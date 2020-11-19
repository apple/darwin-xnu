#include <darwintest.h>
#include <darwintest_utils.h>
#include <darwintest_multiprocess.h>
#include <kern/debug.h>
#include <kern/kern_cdata.h>
#include <kern/block_hint.h>
#include <kdd.h>
#include <libproc.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/dyld_priv.h>
#include <sys/syscall.h>
#include <sys/stackshot.h>
#include <uuid/uuid.h>
#include <servers/bootstrap.h>
#include <pthread/workqueue_private.h>
#import <zlib.h>

T_GLOBAL_META(
		T_META_NAMESPACE("xnu.stackshot"),
		T_META_CHECK_LEAKS(false),
		T_META_ASROOT(true)
		);

static const char *current_process_name(void);
static void verify_stackshot_sharedcache_layout(struct dyld_uuid_info_64 *uuids, uint32_t uuid_count);
static void parse_stackshot(uint64_t stackshot_parsing_flags, void *ssbuf, size_t sslen, NSDictionary *extra);
static void parse_thread_group_stackshot(void **sbuf, size_t sslen);
static uint64_t stackshot_timestamp(void *ssbuf, size_t sslen);
static void initialize_thread(void);

static uint64_t global_flags = 0;

#define DEFAULT_STACKSHOT_BUFFER_SIZE (1024 * 1024)
#define MAX_STACKSHOT_BUFFER_SIZE     (6 * 1024 * 1024)

#define SRP_SERVICE_NAME "com.apple.xnu.test.stackshot.special_reply_port"

/* bit flags for parse_stackshot */
#define PARSE_STACKSHOT_DELTA                0x01
#define PARSE_STACKSHOT_ZOMBIE               0x02
#define PARSE_STACKSHOT_SHAREDCACHE_LAYOUT   0x04
#define PARSE_STACKSHOT_DISPATCH_QUEUE_LABEL 0x08
#define PARSE_STACKSHOT_TURNSTILEINFO        0x10
#define PARSE_STACKSHOT_POSTEXEC             0x20
#define PARSE_STACKSHOT_WAITINFO_CSEG        0x40
#define PARSE_STACKSHOT_WAITINFO_SRP         0x80
#define PARSE_STACKSHOT_TRANSLATED           0x100

/* keys for 'extra' dictionary for parse_stackshot */
static const NSString* zombie_child_pid_key = @"zombie_child_pid"; // -> @(pid), required for PARSE_STACKSHOT_ZOMBIE
static const NSString* postexec_child_unique_pid_key = @"postexec_child_unique_pid";  // -> @(unique_pid), required for PARSE_STACKSHOT_POSTEXEC
static const NSString* cseg_expected_threadid_key = @"cseg_expected_threadid"; // -> @(tid), required for PARSE_STACKSHOT_WAITINFO_CSEG
static const NSString* srp_expected_pid_key = @"srp_expected_pid"; // -> @(pid), required for PARSE_STACKSHOT_WAITINFO_SRP
static const NSString* translated_child_pid_key = @"translated_child_pid"; // -> @(pid), required for PARSE_STACKSHOT_TRANSLATED

#define TEST_STACKSHOT_QUEUE_LABEL        "houston.we.had.a.problem"
#define TEST_STACKSHOT_QUEUE_LABEL_LENGTH sizeof(TEST_STACKSHOT_QUEUE_LABEL)

T_DECL(microstackshots, "test the microstackshot syscall")
{
	void *buf = NULL;
	unsigned int size = DEFAULT_STACKSHOT_BUFFER_SIZE;

	while (1) {
		buf = malloc(size);
		T_QUIET; T_ASSERT_NOTNULL(buf, "allocated stackshot buffer");

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
		int len = syscall(SYS_microstackshot, buf, size,
				(uint32_t) STACKSHOT_GET_MICROSTACKSHOT);
#pragma clang diagnostic pop
		if (len == ENOSYS) {
			T_SKIP("microstackshot syscall failed, likely not compiled with CONFIG_TELEMETRY");
		}
		if (len == -1 && errno == ENOSPC) {
			/* syscall failed because buffer wasn't large enough, try again */
			free(buf);
			buf = NULL;
			size *= 2;
			T_ASSERT_LE(size, (unsigned int)MAX_STACKSHOT_BUFFER_SIZE,
					"growing stackshot buffer to sane size");
			continue;
		}
		T_ASSERT_POSIX_SUCCESS(len, "called microstackshot syscall");
		break;
    }

	T_EXPECT_EQ(*(uint32_t *)buf,
			(uint32_t)STACKSHOT_MICRO_SNAPSHOT_MAGIC,
			"magic value for microstackshot matches");

	free(buf);
}

struct scenario {
	const char *name;
	uint64_t flags;
	bool quiet;
	bool should_fail;
	bool maybe_unsupported;
	pid_t target_pid;
	uint64_t since_timestamp;
	uint32_t size_hint;
	dt_stat_time_t timer;
};

static void
quiet(struct scenario *scenario)
{
	if (scenario->timer || scenario->quiet) {
		T_QUIET;
	}
}

static void
take_stackshot(struct scenario *scenario, bool compress_ok, void (^cb)(void *buf, size_t size))
{
start:
	initialize_thread();

	void *config = stackshot_config_create();
	quiet(scenario);
	T_ASSERT_NOTNULL(config, "created stackshot config");

	int ret = stackshot_config_set_flags(config, scenario->flags | global_flags);
	quiet(scenario);
	T_ASSERT_POSIX_ZERO(ret, "set flags %#llx on stackshot config", scenario->flags);

	if (scenario->size_hint > 0) {
		ret = stackshot_config_set_size_hint(config, scenario->size_hint);
		quiet(scenario);
		T_ASSERT_POSIX_ZERO(ret, "set size hint %" PRIu32 " on stackshot config",
				scenario->size_hint);
	}

	if (scenario->target_pid > 0) {
		ret = stackshot_config_set_pid(config, scenario->target_pid);
		quiet(scenario);
		T_ASSERT_POSIX_ZERO(ret, "set target pid %d on stackshot config",
				scenario->target_pid);
	}

	if (scenario->since_timestamp > 0) {
		ret = stackshot_config_set_delta_timestamp(config, scenario->since_timestamp);
		quiet(scenario);
		T_ASSERT_POSIX_ZERO(ret, "set since timestamp %" PRIu64 " on stackshot config",
				scenario->since_timestamp);
	}

	int retries_remaining = 5;

retry: ;
	uint64_t start_time = mach_absolute_time();
	ret = stackshot_capture_with_config(config);
	uint64_t end_time = mach_absolute_time();

	if (scenario->should_fail) {
		T_EXPECTFAIL;
		T_ASSERT_POSIX_ZERO(ret, "called stackshot_capture_with_config");
		return;
	}

	if (ret == EBUSY || ret == ETIMEDOUT) {
		if (retries_remaining > 0) {
			if (!scenario->timer) {
				T_LOG("stackshot_capture_with_config failed with %s (%d), retrying",
						strerror(ret), ret);
			}

			retries_remaining--;
			goto retry;
		} else {
			T_ASSERT_POSIX_ZERO(ret,
					"called stackshot_capture_with_config (no retries remaining)");
		}
	} else if ((ret == ENOTSUP) && scenario->maybe_unsupported) {
		T_SKIP("kernel indicated this stackshot configuration is not supported");
	} else {
		quiet(scenario);
		T_ASSERT_POSIX_ZERO(ret, "called stackshot_capture_with_config");
	}

	if (scenario->timer) {
		dt_stat_mach_time_add(scenario->timer, end_time - start_time);
	}
	void *buf = stackshot_config_get_stackshot_buffer(config);
	size_t size = stackshot_config_get_stackshot_size(config);
	if (scenario->name) {
		char sspath[MAXPATHLEN];
		strlcpy(sspath, scenario->name, sizeof(sspath));
		strlcat(sspath, ".kcdata", sizeof(sspath));
		T_QUIET; T_ASSERT_POSIX_ZERO(dt_resultfile(sspath, sizeof(sspath)),
				"create result file path");

		if (!scenario->quiet) {
			T_LOG("writing stackshot to %s", sspath);
		}

		FILE *f = fopen(sspath, "w");
		T_WITH_ERRNO; T_QUIET; T_ASSERT_NOTNULL(f,
				"open stackshot output file");

		size_t written = fwrite(buf, size, 1, f);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(written, "wrote stackshot to file");

		fclose(f);
	}
	cb(buf, size);
	if (compress_ok) {
		if (global_flags == 0) {
			T_LOG("Restarting test with compression");
			global_flags |= STACKSHOT_DO_COMPRESS;
			goto start;
		} else {
			global_flags = 0;
		}
	}

	ret = stackshot_config_dealloc(config);
	T_QUIET; T_EXPECT_POSIX_ZERO(ret, "deallocated stackshot config");
}

T_DECL(simple_compressed, "take a simple compressed stackshot")
{
	struct scenario scenario = {
		.name = "kcdata_compressed",
		.flags = (STACKSHOT_DO_COMPRESS | STACKSHOT_SAVE_LOADINFO | STACKSHOT_THREAD_WAITINFO | STACKSHOT_GET_GLOBAL_MEM_STATS |
				STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT),
	};

	T_LOG("taking compressed kcdata stackshot");
	take_stackshot(&scenario, true, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(0, ssbuf, sslen, nil);
	});
}

T_DECL(panic_compressed, "take a compressed stackshot with the same flags as a panic stackshot")
{
	uint64_t stackshot_flags = (STACKSHOT_SAVE_KEXT_LOADINFO |
			STACKSHOT_SAVE_LOADINFO |
			STACKSHOT_KCDATA_FORMAT |
			STACKSHOT_ENABLE_BT_FAULTING |
			STACKSHOT_ENABLE_UUID_FAULTING |
			STACKSHOT_DO_COMPRESS |
			STACKSHOT_NO_IO_STATS |
			STACKSHOT_THREAD_WAITINFO |
#if TARGET_OS_MAC
			STACKSHOT_COLLECT_SHAREDCACHE_LAYOUT |
#endif
			STACKSHOT_DISABLE_LATENCY_INFO);

	struct scenario scenario = {
		.name = "kcdata_panic_compressed",
		.flags = stackshot_flags,
	};

	T_LOG("taking compressed kcdata stackshot with panic flags");
	take_stackshot(&scenario, true, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(0, ssbuf, sslen, nil);
	});
}

T_DECL(kcdata, "test that kcdata stackshots can be taken and parsed")
{
	struct scenario scenario = {
		.name = "kcdata",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS |
				STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT),
	};

	T_LOG("taking kcdata stackshot");
	take_stackshot(&scenario, true, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(0, ssbuf, sslen, nil);
	});
}

T_DECL(kcdata_faulting, "test that kcdata stackshots while faulting can be taken and parsed")
{
	struct scenario scenario = {
		.name = "faulting",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS
				| STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT
				| STACKSHOT_ENABLE_BT_FAULTING | STACKSHOT_ENABLE_UUID_FAULTING),
	};

	T_LOG("taking faulting stackshot");
	take_stackshot(&scenario, true, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(0, ssbuf, sslen, nil);
	});
}

T_DECL(bad_flags, "test a poorly-formed stackshot syscall")
{
	struct scenario scenario = {
		.flags = STACKSHOT_SAVE_IN_KERNEL_BUFFER /* not allowed from user space */,
		.should_fail = true,
	};

	T_LOG("attempting to take stackshot with kernel-only flag");
	take_stackshot(&scenario, true, ^(__unused void *ssbuf, __unused size_t sslen) {
		T_ASSERT_FAIL("stackshot data callback called");
	});
}

T_DECL(delta, "test delta stackshots")
{
	struct scenario scenario = {
		.name = "delta",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS
				| STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT),
	};

	T_LOG("taking full stackshot");
	take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
		uint64_t stackshot_time = stackshot_timestamp(ssbuf, sslen);

		T_LOG("taking delta stackshot since time %" PRIu64, stackshot_time);

		parse_stackshot(0, ssbuf, sslen, nil);

		struct scenario delta_scenario = {
			.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS
					| STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT
					| STACKSHOT_COLLECT_DELTA_SNAPSHOT),
			.since_timestamp = stackshot_time
		};

		take_stackshot(&delta_scenario, false, ^(void *dssbuf, size_t dsslen) {
			parse_stackshot(PARSE_STACKSHOT_DELTA, dssbuf, dsslen, nil);
		});
	});
}

T_DECL(shared_cache_layout, "test stackshot inclusion of shared cache layout")
{
	struct scenario scenario = {
		.name = "shared_cache_layout",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS
				| STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT |
				STACKSHOT_COLLECT_SHAREDCACHE_LAYOUT),
	};

	size_t shared_cache_length;
	const void *cache_header = _dyld_get_shared_cache_range(&shared_cache_length);
	if (cache_header == NULL) {
		T_SKIP("Device not running with shared cache, skipping test...");
	}

	if (shared_cache_length == 0) {
		T_SKIP("dyld reports that currently running shared cache has zero length");
	}

	T_LOG("taking stackshot with STACKSHOT_COLLECT_SHAREDCACHE_LAYOUT set");
	take_stackshot(&scenario, true, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(PARSE_STACKSHOT_SHAREDCACHE_LAYOUT, ssbuf, sslen, nil);
	});
}

T_DECL(stress, "test that taking stackshots for 60 seconds doesn't crash the system")
{
	uint64_t max_diff_time = 60ULL /* seconds */ * 1000000000ULL;
	uint64_t start_time;

	struct scenario scenario = {
		.name = "stress",
		.quiet = true,
		.flags = (STACKSHOT_KCDATA_FORMAT |
				STACKSHOT_THREAD_WAITINFO |
				STACKSHOT_SAVE_LOADINFO |
				STACKSHOT_SAVE_KEXT_LOADINFO |
				STACKSHOT_GET_GLOBAL_MEM_STATS |
				// STACKSHOT_GET_BOOT_PROFILE |
				STACKSHOT_SAVE_IMP_DONATION_PIDS |
				STACKSHOT_COLLECT_SHAREDCACHE_LAYOUT |
				STACKSHOT_THREAD_GROUP |
				STACKSHOT_SAVE_JETSAM_COALITIONS |
				STACKSHOT_ASID |
				// STACKSHOT_PAGE_TABLES |
				0),
	};

	start_time = clock_gettime_nsec_np(CLOCK_MONOTONIC);
	while (clock_gettime_nsec_np(CLOCK_MONOTONIC) - start_time < max_diff_time) {
		take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
			printf(".");
			fflush(stdout);
		});

		/* Leave some time for the testing infrastructure to catch up */
		usleep(10000);

	}
	printf("\n");
}

T_DECL(dispatch_queue_label, "test that kcdata stackshots contain libdispatch queue labels")
{
	struct scenario scenario = {
		.name = "kcdata",
		.flags = (STACKSHOT_GET_DQ | STACKSHOT_KCDATA_FORMAT),
	};
	dispatch_semaphore_t child_ready_sem, parent_done_sem;
	dispatch_queue_t dq;

#if TARGET_OS_WATCH
	T_SKIP("This test is flaky on watches: 51663346");
#endif

	child_ready_sem = dispatch_semaphore_create(0);
	T_QUIET; T_ASSERT_NOTNULL(child_ready_sem, "dqlabel child semaphore");

	parent_done_sem = dispatch_semaphore_create(0);
	T_QUIET; T_ASSERT_NOTNULL(parent_done_sem, "dqlabel parent semaphore");

	dq = dispatch_queue_create(TEST_STACKSHOT_QUEUE_LABEL, NULL);
	T_QUIET; T_ASSERT_NOTNULL(dq, "dispatch queue");

	/* start the helper thread */
	dispatch_async(dq, ^{
			dispatch_semaphore_signal(child_ready_sem);

			dispatch_semaphore_wait(parent_done_sem, DISPATCH_TIME_FOREVER);
	});

	/* block behind the child starting up */
	dispatch_semaphore_wait(child_ready_sem, DISPATCH_TIME_FOREVER);

	T_LOG("taking kcdata stackshot with libdispatch queue labels");
	take_stackshot(&scenario, true, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(PARSE_STACKSHOT_DISPATCH_QUEUE_LABEL, ssbuf, sslen, nil);
	});

	dispatch_semaphore_signal(parent_done_sem);
}

static void *stuck_sysctl_thread(void *arg) {
	int val = 1;
	dispatch_semaphore_t child_thread_started = *(dispatch_semaphore_t *)arg;

	dispatch_semaphore_signal(child_thread_started);
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.wedge_thread", NULL, NULL, &val, sizeof(val)), "wedge child thread");

	return NULL;
}

T_HELPER_DECL(zombie_child, "child process to sample as a zombie")
{
	pthread_t pthread;
	dispatch_semaphore_t child_thread_started = dispatch_semaphore_create(0);
	T_QUIET; T_ASSERT_NOTNULL(child_thread_started, "zombie child thread semaphore");

	/* spawn another thread to get stuck in the kernel, then call exit() to become a zombie */
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_create(&pthread, NULL, stuck_sysctl_thread, &child_thread_started), "pthread_create");

	dispatch_semaphore_wait(child_thread_started, DISPATCH_TIME_FOREVER);

	/* sleep for a bit in the hope of ensuring that the other thread has called the sysctl before we signal the parent */
	usleep(100);
	T_ASSERT_POSIX_SUCCESS(kill(getppid(), SIGUSR1), "signaled parent to take stackshot");

	exit(0);
}

T_DECL(zombie, "tests a stackshot of a zombie task with a thread stuck in the kernel")
{
	char path[PATH_MAX];
	uint32_t path_size = sizeof(path);
	T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");
	char *args[] = { path, "-n", "zombie_child", NULL };

	dispatch_source_t child_sig_src;
	dispatch_semaphore_t child_ready_sem = dispatch_semaphore_create(0);
	T_QUIET; T_ASSERT_NOTNULL(child_ready_sem, "zombie child semaphore");

	dispatch_queue_t signal_processing_q = dispatch_queue_create("signal processing queue", NULL);
	T_QUIET; T_ASSERT_NOTNULL(signal_processing_q, "signal processing queue");

	pid_t pid;

	T_LOG("spawning a child");

	signal(SIGUSR1, SIG_IGN);
	child_sig_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, signal_processing_q);
	T_QUIET; T_ASSERT_NOTNULL(child_sig_src, "dispatch_source_create (child_sig_src)");

	dispatch_source_set_event_handler(child_sig_src, ^{ dispatch_semaphore_signal(child_ready_sem); });
	dispatch_activate(child_sig_src);

	int sp_ret = posix_spawn(&pid, args[0], NULL, NULL, args, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(sp_ret, "spawned process '%s' with PID %d", args[0], pid);

	dispatch_semaphore_wait(child_ready_sem, DISPATCH_TIME_FOREVER);

	T_LOG("received signal from child, capturing stackshot");

	struct proc_bsdshortinfo bsdshortinfo;
	int retval, iterations_to_wait = 10;

	while (iterations_to_wait > 0) {
		retval = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &bsdshortinfo, sizeof(bsdshortinfo));
		if ((retval == 0) && errno == ESRCH) {
			T_LOG("unable to find child using proc_pidinfo, assuming zombie");
			break;
		}

		T_QUIET; T_WITH_ERRNO; T_ASSERT_GT(retval, 0, "proc_pidinfo(PROC_PIDT_SHORTBSDINFO) returned a value > 0");
		T_QUIET; T_ASSERT_EQ(retval, (int)sizeof(bsdshortinfo), "proc_pidinfo call for PROC_PIDT_SHORTBSDINFO returned expected size");

		if (bsdshortinfo.pbsi_flags & PROC_FLAG_INEXIT) {
			T_LOG("child proc info marked as in exit");
			break;
		}

		iterations_to_wait--;
		if (iterations_to_wait == 0) {
			/*
			 * This will mark the test as failed but let it continue so we
			 * don't leave a process stuck in the kernel.
			 */
			T_FAIL("unable to discover that child is marked as exiting");
		}

		/* Give the child a few more seconds to make it to exit */
		sleep(5);
	}

	/* Give the child some more time to make it through exit */
	sleep(10);

	struct scenario scenario = {
		.name = "zombie",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS
				| STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT),
	};

	take_stackshot(&scenario, false, ^( void *ssbuf, size_t sslen) {
		/* First unwedge the child so we can reap it */
		int val = 1, status;
		T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.unwedge_thread", NULL, NULL, &val, sizeof(val)), "unwedge child");

		T_QUIET; T_ASSERT_POSIX_SUCCESS(waitpid(pid, &status, 0), "waitpid on zombie child");

		parse_stackshot(PARSE_STACKSHOT_ZOMBIE, ssbuf, sslen, @{zombie_child_pid_key: @(pid)});
	});
}

T_HELPER_DECL(exec_child_preexec, "child process pre-exec")
{
	dispatch_queue_t signal_processing_q = dispatch_queue_create("signal processing queue", NULL);
	T_QUIET; T_ASSERT_NOTNULL(signal_processing_q, "signal processing queue");
	
	signal(SIGUSR1, SIG_IGN);
	dispatch_source_t parent_sig_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, signal_processing_q);
	T_QUIET; T_ASSERT_NOTNULL(parent_sig_src, "dispatch_source_create (child_sig_src)");
	dispatch_source_set_event_handler(parent_sig_src, ^{
		
		// Parent took a timestamp then signaled us: exec into the next process
		
		char path[PATH_MAX];
		uint32_t path_size = sizeof(path);
		T_QUIET; T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");
		char *args[] = { path, "-n", "exec_child_postexec", NULL };
		
		T_QUIET; T_ASSERT_POSIX_ZERO(execve(args[0], args, NULL), "execing into exec_child_postexec");
	});
	dispatch_activate(parent_sig_src);
	
	T_ASSERT_POSIX_SUCCESS(kill(getppid(), SIGUSR1), "signaled parent to take timestamp");
	
	sleep(100);
	// Should never get here
	T_FAIL("Received signal to exec from parent");
}

T_HELPER_DECL(exec_child_postexec, "child process post-exec to sample")
{
	T_ASSERT_POSIX_SUCCESS(kill(getppid(), SIGUSR1), "signaled parent to take stackshot");
	sleep(100);
	// Should never get here
	T_FAIL("Killed by parent");
}

T_DECL(exec, "test getting full task snapshots for a task that execs")
{
	char path[PATH_MAX];
	uint32_t path_size = sizeof(path);
	T_QUIET; T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");
	char *args[] = { path, "-n", "exec_child_preexec", NULL };
	
	dispatch_source_t child_sig_src;
	dispatch_semaphore_t child_ready_sem = dispatch_semaphore_create(0);
	T_QUIET; T_ASSERT_NOTNULL(child_ready_sem, "exec child semaphore");
	
	dispatch_queue_t signal_processing_q = dispatch_queue_create("signal processing queue", NULL);
	T_QUIET; T_ASSERT_NOTNULL(signal_processing_q, "signal processing queue");
	
	pid_t pid;
	
	T_LOG("spawning a child");
	
	signal(SIGUSR1, SIG_IGN);
	child_sig_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, signal_processing_q);
	T_QUIET; T_ASSERT_NOTNULL(child_sig_src, "dispatch_source_create (child_sig_src)");
	
	dispatch_source_set_event_handler(child_sig_src, ^{ dispatch_semaphore_signal(child_ready_sem); });
	dispatch_activate(child_sig_src);
	
	int sp_ret = posix_spawn(&pid, args[0], NULL, NULL, args, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(sp_ret, "spawned process '%s' with PID %d", args[0], pid);
	
	dispatch_semaphore_wait(child_ready_sem, DISPATCH_TIME_FOREVER);
	
	uint64_t start_time = mach_absolute_time();
	
	struct proc_uniqidentifierinfo proc_info_data = { };
	int retval = proc_pidinfo(getpid(), PROC_PIDUNIQIDENTIFIERINFO, 0, &proc_info_data, sizeof(proc_info_data));
	T_QUIET; T_EXPECT_POSIX_SUCCESS(retval, "proc_pidinfo PROC_PIDUNIQIDENTIFIERINFO");
	T_QUIET; T_ASSERT_EQ_INT(retval, (int) sizeof(proc_info_data), "proc_pidinfo PROC_PIDUNIQIDENTIFIERINFO returned data");
	uint64_t unique_pid = proc_info_data.p_uniqueid;
	
	T_LOG("received signal from pre-exec child, unique_pid is %llu, timestamp is %llu", unique_pid, start_time);
	
	T_ASSERT_POSIX_SUCCESS(kill(pid, SIGUSR1), "signaled pre-exec child to exec");
	
	dispatch_semaphore_wait(child_ready_sem, DISPATCH_TIME_FOREVER);
	
	T_LOG("received signal from post-exec child, capturing stackshot");
	
	struct scenario scenario = {
		.name = "exec",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS
				  | STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT
				  | STACKSHOT_COLLECT_DELTA_SNAPSHOT),
		.since_timestamp = start_time
	};
	
	take_stackshot(&scenario, false, ^( void *ssbuf, size_t sslen) {
		// Kill the child
		int status;
		T_ASSERT_POSIX_SUCCESS(kill(pid, SIGKILL), "kill post-exec child %d", pid);
		T_ASSERT_POSIX_SUCCESS(waitpid(pid, &status, 0), "waitpid on post-exec child");
		
		parse_stackshot(PARSE_STACKSHOT_POSTEXEC | PARSE_STACKSHOT_DELTA, ssbuf, sslen, @{postexec_child_unique_pid_key: @(unique_pid)});
	});
}

static uint32_t
get_user_promotion_basepri(void)
{
	mach_msg_type_number_t count = THREAD_POLICY_STATE_COUNT;
	struct thread_policy_state thread_policy;
	boolean_t get_default = FALSE;
	mach_port_t thread_port = pthread_mach_thread_np(pthread_self());

	kern_return_t kr = thread_policy_get(thread_port, THREAD_POLICY_STATE,
	    (thread_policy_t)&thread_policy, &count, &get_default);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_policy_get");
	return thread_policy.thps_user_promotion_basepri;
}

static int
get_pri(thread_t thread_port)
{
	kern_return_t kr;

	thread_extended_info_data_t extended_info;
	mach_msg_type_number_t count = THREAD_EXTENDED_INFO_COUNT;
	kr = thread_info(thread_port, THREAD_EXTENDED_INFO,
	    (thread_info_t)&extended_info, &count);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_info");

	return extended_info.pth_curpri;
}


T_DECL(turnstile_singlehop, "turnstile single hop test")
{
	dispatch_queue_t dq1, dq2;
	dispatch_semaphore_t sema_x;
	dispatch_queue_attr_t dq1_attr, dq2_attr;
	__block qos_class_t main_qos = 0;
	__block int main_relpri = 0, main_relpri2 = 0, main_afterpri = 0;
	struct scenario scenario = {
		.name = "turnstile_singlehop",
		.flags = (STACKSHOT_THREAD_WAITINFO | STACKSHOT_KCDATA_FORMAT),
	};
	dq1_attr = dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_UTILITY, 0);
	dq2_attr = dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INITIATED, 0);
	pthread_mutex_t lock_a = PTHREAD_MUTEX_INITIALIZER;
	pthread_mutex_t lock_b = PTHREAD_MUTEX_INITIALIZER;

	pthread_mutex_t *lockap = &lock_a, *lockbp = &lock_b;

	dq1 = dispatch_queue_create("q1", dq1_attr);
	dq2 = dispatch_queue_create("q2", dq2_attr);
	sema_x = dispatch_semaphore_create(0);

	pthread_mutex_lock(lockap);
	dispatch_async(dq1, ^{
		pthread_mutex_lock(lockbp);
		T_ASSERT_POSIX_SUCCESS(pthread_get_qos_class_np(pthread_self(), &main_qos, &main_relpri), "get qos class");
		T_LOG("The priority of q1 is %d\n", get_pri(mach_thread_self()));
		dispatch_semaphore_signal(sema_x);
		pthread_mutex_lock(lockap);
	});
	dispatch_semaphore_wait(sema_x, DISPATCH_TIME_FOREVER);

	T_LOG("Async1 completed");

	pthread_set_qos_class_self_np(QOS_CLASS_UTILITY, 0);
	T_ASSERT_POSIX_SUCCESS(pthread_get_qos_class_np(pthread_self(), &main_qos, &main_relpri), "get qos class");
	T_LOG("The priority of main is %d\n", get_pri(mach_thread_self()));
	main_relpri = get_pri(mach_thread_self());

	dispatch_async(dq2, ^{
		T_ASSERT_POSIX_SUCCESS(pthread_get_qos_class_np(pthread_self(), &main_qos, &main_relpri2), "get qos class");
		T_LOG("The priority of q2 is %d\n", get_pri(mach_thread_self()));
		dispatch_semaphore_signal(sema_x);
		pthread_mutex_lock(lockbp);
	});
	dispatch_semaphore_wait(sema_x, DISPATCH_TIME_FOREVER);
	
	T_LOG("Async2 completed");

	while (1) {
		main_afterpri = (int) get_user_promotion_basepri();
		if (main_relpri != main_afterpri) {
			T_LOG("Success with promotion pri is %d", main_afterpri);
			break;
		}

		usleep(100);
	}

	take_stackshot(&scenario, true, ^( void *ssbuf, size_t sslen) {
		parse_stackshot(PARSE_STACKSHOT_TURNSTILEINFO, ssbuf, sslen, nil);
	});
}


static void
expect_instrs_cycles_in_stackshot(void *ssbuf, size_t sslen)
{
	kcdata_iter_t iter = kcdata_iter(ssbuf, sslen);

	bool in_task = false;
	bool in_thread = false;
	bool saw_instrs_cycles = false;
	iter = kcdata_iter_next(iter);

	KCDATA_ITER_FOREACH(iter) {
		switch (kcdata_iter_type(iter)) {
		case KCDATA_TYPE_CONTAINER_BEGIN:
			switch (kcdata_iter_container_type(iter)) {
			case STACKSHOT_KCCONTAINER_TASK:
				in_task = true;
				saw_instrs_cycles = false;
				break;

			case STACKSHOT_KCCONTAINER_THREAD:
				in_thread = true;
				saw_instrs_cycles = false;
				break;

			default:
				break;
			}
			break;

		case STACKSHOT_KCTYPE_INSTRS_CYCLES:
			saw_instrs_cycles = true;
			break;

		case KCDATA_TYPE_CONTAINER_END:
			if (in_thread) {
				T_QUIET; T_EXPECT_TRUE(saw_instrs_cycles,
						"saw instructions and cycles in thread");
				in_thread = false;
			} else if (in_task) {
				T_QUIET; T_EXPECT_TRUE(saw_instrs_cycles,
						"saw instructions and cycles in task");
				in_task = false;
			}

		default:
			break;
		}
	}
}

static void
skip_if_monotonic_unsupported(void)
{
	int supported = 0;
	size_t supported_size = sizeof(supported);
	int ret = sysctlbyname("kern.monotonic.supported", &supported,
			&supported_size, 0, 0);
	if (ret < 0 || !supported) {
		T_SKIP("monotonic is unsupported");
	}
}

T_DECL(instrs_cycles, "test a getting instructions and cycles in stackshot")
{
	skip_if_monotonic_unsupported();

	struct scenario scenario = {
		.name = "instrs-cycles",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_INSTRS_CYCLES
				| STACKSHOT_KCDATA_FORMAT),
	};

	T_LOG("attempting to take stackshot with instructions and cycles");
	take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(0, ssbuf, sslen, nil);
		expect_instrs_cycles_in_stackshot(ssbuf, sslen);
	});
}

T_DECL(delta_instrs_cycles,
		"test delta stackshots with instructions and cycles")
{
	skip_if_monotonic_unsupported();

	struct scenario scenario = {
		.name = "delta-instrs-cycles",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_INSTRS_CYCLES
				| STACKSHOT_KCDATA_FORMAT),
	};

	T_LOG("taking full stackshot");
	take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
		uint64_t stackshot_time = stackshot_timestamp(ssbuf, sslen);

		T_LOG("taking delta stackshot since time %" PRIu64, stackshot_time);

		parse_stackshot(0, ssbuf, sslen, nil);
		expect_instrs_cycles_in_stackshot(ssbuf, sslen);

		struct scenario delta_scenario = {
			.name = "delta-instrs-cycles-next",
			.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_INSTRS_CYCLES
					| STACKSHOT_KCDATA_FORMAT
					| STACKSHOT_COLLECT_DELTA_SNAPSHOT),
			.since_timestamp = stackshot_time,
		};

		take_stackshot(&delta_scenario, false, ^(void *dssbuf, size_t dsslen) {
			parse_stackshot(PARSE_STACKSHOT_DELTA, dssbuf, dsslen, nil);
			expect_instrs_cycles_in_stackshot(dssbuf, dsslen);
		});
	});
}

static void
check_thread_groups_supported()
{
	int err;
	int supported = 0;
	size_t supported_size = sizeof(supported);
	err = sysctlbyname("kern.thread_groups_supported", &supported, &supported_size, NULL, 0);

	if (err || !supported)
		T_SKIP("thread groups not supported on this system");
}

T_DECL(thread_groups, "test getting thread groups in stackshot")
{
	check_thread_groups_supported();

	struct scenario scenario = {
		.name = "thread-groups",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_THREAD_GROUP
				| STACKSHOT_KCDATA_FORMAT),
	};

	T_LOG("attempting to take stackshot with thread group flag");
	take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
		parse_thread_group_stackshot(ssbuf, sslen);
	});
}

static void
parse_page_table_asid_stackshot(void **ssbuf, size_t sslen)
{
	bool seen_asid = false;
	bool seen_page_table_snapshot = false;
	kcdata_iter_t iter = kcdata_iter(ssbuf, sslen);
	T_ASSERT_EQ(kcdata_iter_type(iter), KCDATA_BUFFER_BEGIN_STACKSHOT,
			"buffer provided is a stackshot");

	iter = kcdata_iter_next(iter);
	KCDATA_ITER_FOREACH(iter) {
		switch (kcdata_iter_type(iter)) {
		case KCDATA_TYPE_ARRAY: {
			T_QUIET;
			T_ASSERT_TRUE(kcdata_iter_array_valid(iter),
					"checked that array is valid");

			if (kcdata_iter_array_elem_type(iter) != STACKSHOT_KCTYPE_PAGE_TABLES) {
				continue;
			}

			T_ASSERT_FALSE(seen_page_table_snapshot, "check that we haven't yet seen a page table snapshot");
			seen_page_table_snapshot = true;

			T_ASSERT_EQ((size_t) kcdata_iter_array_elem_size(iter), sizeof(uint64_t),
				"check that each element of the pagetable dump is the expected size");

			uint64_t *pt_array = kcdata_iter_payload(iter);
			uint32_t elem_count = kcdata_iter_array_elem_count(iter);
			uint32_t j;
			bool nonzero_tte = false;
			for (j = 0; j < elem_count;) {
				T_QUIET; T_ASSERT_LE(j + 4, elem_count, "check for valid page table segment header");
				uint64_t pa = pt_array[j];
				uint64_t num_entries = pt_array[j + 1];
				uint64_t start_va = pt_array[j + 2];
				uint64_t end_va = pt_array[j + 3];

				T_QUIET; T_ASSERT_NE(pa, (uint64_t) 0, "check that the pagetable physical address is non-zero");
				T_QUIET; T_ASSERT_EQ(pa % (num_entries * sizeof(uint64_t)), (uint64_t) 0, "check that the pagetable physical address is correctly aligned");
				T_QUIET; T_ASSERT_NE(num_entries, (uint64_t) 0, "check that a pagetable region has more than 0 entries");
				T_QUIET; T_ASSERT_LE(j + 4 + num_entries, (uint64_t) elem_count, "check for sufficient space in page table array");
				T_QUIET; T_ASSERT_GT(end_va, start_va, "check for valid VA bounds in page table segment header");

				for (uint32_t k = j + 4; k < (j + 4 + num_entries); ++k) {
					if (pt_array[k] != 0) {
						nonzero_tte = true;
						T_QUIET; T_ASSERT_EQ((pt_array[k] >> 48) & 0xf, (uint64_t) 0, "check that bits[48:51] of arm64 TTE are clear");
						// L0-L2 table and non-compressed L3 block entries should always have bit 1 set; assumes L0-L2 blocks will not be used outside the kernel
						bool table = ((pt_array[k] & 0x2) != 0);
						if (table) {
							T_QUIET; T_ASSERT_NE(pt_array[k] & ((1ULL << 48) - 1) & ~((1ULL << 12) - 1), (uint64_t) 0, "check that arm64 TTE physical address is non-zero");
						} else { // should be a compressed PTE
							T_QUIET; T_ASSERT_NE(pt_array[k] & 0xC000000000000000ULL, (uint64_t) 0, "check that compressed PTE has at least one of bits [63:62] set");
							T_QUIET; T_ASSERT_EQ(pt_array[k] & ~0xC000000000000000ULL, (uint64_t) 0, "check that compressed PTE has no other bits besides [63:62] set");
						}
					}
				}

				j += (4 + num_entries);
			}
			T_ASSERT_TRUE(nonzero_tte, "check that we saw at least one non-empty TTE");
			T_ASSERT_EQ(j, elem_count, "check that page table dump size matches extent of last header"); 
			break;
		}
		case STACKSHOT_KCTYPE_ASID: {
			T_ASSERT_FALSE(seen_asid, "check that we haven't yet seen an ASID");
			seen_asid = true;
		}
		}
	}
	T_ASSERT_TRUE(seen_page_table_snapshot, "check that we have seen a page table snapshot");
	T_ASSERT_TRUE(seen_asid, "check that we have seen an ASID");
}

T_DECL(dump_page_tables, "test stackshot page table dumping support")
{
	struct scenario scenario = {
		.name = "asid-page-tables",
		.flags = (STACKSHOT_KCDATA_FORMAT | STACKSHOT_ASID | STACKSHOT_PAGE_TABLES),
		.size_hint = (1ULL << 23), // 8 MB
		.target_pid = getpid(),
		.maybe_unsupported = true,
	};

	T_LOG("attempting to take stackshot with ASID and page table flags");
	take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
		parse_page_table_asid_stackshot(ssbuf, sslen);
	});
}

static void stackshot_verify_current_proc_uuid_info(void **ssbuf, size_t sslen, uint64_t expected_offset, const struct proc_uniqidentifierinfo *proc_info_data)
{
	const uuid_t *current_uuid = (const uuid_t *)(&proc_info_data->p_uuid);

	kcdata_iter_t iter = kcdata_iter(ssbuf, sslen);
	T_ASSERT_EQ(kcdata_iter_type(iter), KCDATA_BUFFER_BEGIN_STACKSHOT, "buffer provided is a stackshot");

	iter = kcdata_iter_next(iter);

	KCDATA_ITER_FOREACH(iter) {
		switch (kcdata_iter_type(iter)) {
			case KCDATA_TYPE_ARRAY: {
				T_QUIET; T_ASSERT_TRUE(kcdata_iter_array_valid(iter), "checked that array is valid");
				if (kcdata_iter_array_elem_type(iter) == KCDATA_TYPE_LIBRARY_LOADINFO64) {
					struct user64_dyld_uuid_info *info = (struct user64_dyld_uuid_info *) kcdata_iter_payload(iter);
					if (uuid_compare(*current_uuid, info->imageUUID) == 0) {
						T_ASSERT_EQ(expected_offset, info->imageLoadAddress, "found matching UUID with matching binary offset");
						return;
					}
				} else if (kcdata_iter_array_elem_type(iter) == KCDATA_TYPE_LIBRARY_LOADINFO) {
					struct user32_dyld_uuid_info *info = (struct user32_dyld_uuid_info *) kcdata_iter_payload(iter);
					if (uuid_compare(*current_uuid, info->imageUUID) == 0) {
						T_ASSERT_EQ(expected_offset, ((uint64_t) info->imageLoadAddress),  "found matching UUID with matching binary offset");
						return;
					}
				}
				break;
			}
			default:
				break;
		}
	}

	T_FAIL("failed to find matching UUID in stackshot data");
}

T_DECL(translated, "tests translated bit is set correctly")
{
#if !(TARGET_OS_OSX && TARGET_CPU_ARM64)
	T_SKIP("Not arm mac")
#endif
	// Get path of stackshot_translated_child helper binary
	char path[PATH_MAX];
	uint32_t path_size = sizeof(path);
	T_QUIET; T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");
	char* binary_name = strrchr(path, '/');
	if (binary_name) binary_name++;
	T_QUIET; T_ASSERT_NOTNULL(binary_name, "Find basename in path '%s'", path);
	strlcpy(binary_name, "stackshot_translated_child", path_size - (binary_name - path));
	char *args[] = { path, NULL };
	
	dispatch_source_t child_sig_src;
	dispatch_semaphore_t child_ready_sem = dispatch_semaphore_create(0);
	T_QUIET; T_ASSERT_NOTNULL(child_ready_sem, "exec child semaphore");
	
	dispatch_queue_t signal_processing_q = dispatch_queue_create("signal processing queue", NULL);
	T_QUIET; T_ASSERT_NOTNULL(signal_processing_q, "signal processing queue");
		
	signal(SIGUSR1, SIG_IGN);
	child_sig_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, signal_processing_q);
	T_QUIET; T_ASSERT_NOTNULL(child_sig_src, "dispatch_source_create (child_sig_src)");
	
	dispatch_source_set_event_handler(child_sig_src, ^{ dispatch_semaphore_signal(child_ready_sem); });
	dispatch_activate(child_sig_src);
	
	// Spawn child
	pid_t pid;
	T_LOG("spawning translated child");
	T_QUIET; T_ASSERT_POSIX_ZERO(posix_spawn(&pid, args[0], NULL, NULL, args, NULL), "spawned process '%s' with PID %d", args[0], pid);
	
	// Wait for the the child to spawn up
	dispatch_semaphore_wait(child_ready_sem, DISPATCH_TIME_FOREVER);

	// Make sure the child is running and is translated
	int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
	struct kinfo_proc process_info;
	size_t bufsize = sizeof(process_info);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(sysctl(mib, (unsigned)(sizeof(mib)/sizeof(int)), &process_info, &bufsize, NULL, 0), "get translated child process info");
	T_QUIET; T_ASSERT_GT(bufsize, 0, "process info is not empty");
	T_QUIET; T_ASSERT_TRUE((process_info.kp_proc.p_flag & P_TRANSLATED), "KERN_PROC_PID reports child is translated");
	
	T_LOG("capturing stackshot");
	
	struct scenario scenario = {
		.name = "translated",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS
				  | STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT),
	};
	
	take_stackshot(&scenario, true, ^( void *ssbuf, size_t sslen) {
		// Kill the child
		int status;
		T_QUIET; T_ASSERT_POSIX_SUCCESS(kill(pid, SIGTERM), "kill translated child");
		T_QUIET; T_ASSERT_POSIX_SUCCESS(waitpid(pid, &status, 0), "waitpid on translated child");
		
		parse_stackshot(PARSE_STACKSHOT_TRANSLATED, ssbuf, sslen, @{translated_child_pid_key: @(pid)});
	});
}

T_DECL(proc_uuid_info, "tests that the main binary UUID for a proc is always populated")
{
	struct proc_uniqidentifierinfo proc_info_data = { };
	mach_msg_type_number_t      count;
	kern_return_t               kernel_status;
	task_dyld_info_data_t       task_dyld_info;
	struct dyld_all_image_infos *target_infos;
	int retval;
	bool found_image_in_image_infos = false;
	uint64_t expected_mach_header_offset = 0;

	/* Find the UUID of our main binary */
	retval = proc_pidinfo(getpid(), PROC_PIDUNIQIDENTIFIERINFO, 0, &proc_info_data, sizeof(proc_info_data));
	T_QUIET; T_EXPECT_POSIX_SUCCESS(retval, "proc_pidinfo PROC_PIDUNIQIDENTIFIERINFO");
	T_QUIET; T_ASSERT_EQ_INT(retval, (int) sizeof(proc_info_data), "proc_pidinfo PROC_PIDUNIQIDENTIFIERINFO returned data");

	uuid_string_t str = {};
	uuid_unparse(*(uuid_t*)&proc_info_data.p_uuid, str);
	T_LOG("Found current UUID is %s", str);

	/* Find the location of the dyld image info metadata */
	count = TASK_DYLD_INFO_COUNT;
	kernel_status = task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&task_dyld_info, &count);
	T_QUIET; T_ASSERT_EQ(kernel_status, KERN_SUCCESS, "retrieve task_info for TASK_DYLD_INFO");

	target_infos = (struct dyld_all_image_infos *)task_dyld_info.all_image_info_addr;

	/* Find our binary in the dyld image info array */
	for (int i = 0; i < (int) target_infos->uuidArrayCount; i++) {
		if (uuid_compare(target_infos->uuidArray[i].imageUUID, *(uuid_t*)&proc_info_data.p_uuid) == 0) {
			expected_mach_header_offset = (uint64_t) target_infos->uuidArray[i].imageLoadAddress;
			found_image_in_image_infos = true;
		}
	}

	T_ASSERT_TRUE(found_image_in_image_infos, "found binary image in dyld image info list");

	/* Overwrite the dyld image info data so the kernel has to fallback to the UUID stored in the proc structure */
	target_infos->uuidArrayCount = 0;

	struct scenario scenario = {
		.name = "proc_uuid_info",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_KCDATA_FORMAT),
		.target_pid = getpid(),
	};

	T_LOG("attempting to take stackshot for current PID");
	take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
		stackshot_verify_current_proc_uuid_info(ssbuf, sslen, expected_mach_header_offset, &proc_info_data);
	});
}

T_DECL(cseg_waitinfo, "test that threads stuck in the compressor report correct waitinfo")
{
	int val = 1;
	struct scenario scenario = {
		.name = "cseg_waitinfo",
		.quiet = false,
		.flags = (STACKSHOT_THREAD_WAITINFO | STACKSHOT_KCDATA_FORMAT),
	};
	__block uint64_t thread_id = 0;

	dispatch_queue_t dq = dispatch_queue_create("com.apple.stackshot.cseg_waitinfo", NULL);
	dispatch_semaphore_t child_ok = dispatch_semaphore_create(0);

	dispatch_async(dq, ^{
		pthread_threadid_np(NULL, &thread_id);
		dispatch_semaphore_signal(child_ok);
		T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.cseg_wedge_thread", NULL, NULL, &val, sizeof(val)), "wedge child thread");
	});

	dispatch_semaphore_wait(child_ok, DISPATCH_TIME_FOREVER);
	sleep(1);

	T_LOG("taking stackshot");
	take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
		T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.cseg_unwedge_thread", NULL, NULL, &val, sizeof(val)), "unwedge child thread");
		parse_stackshot(PARSE_STACKSHOT_WAITINFO_CSEG, ssbuf, sslen, @{cseg_expected_threadid_key: @(thread_id)});
	});
}

static void
srp_send(
	mach_port_t send_port,
	mach_port_t reply_port,
	mach_port_t msg_port)
{
	kern_return_t ret = 0;

	struct test_msg {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t port_descriptor;
	};
	struct test_msg send_msg = {
		.header = {
			.msgh_remote_port = send_port,
			.msgh_local_port  = reply_port,
			.msgh_bits        = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND,
	    reply_port ? MACH_MSG_TYPE_MAKE_SEND_ONCE : 0,
	    MACH_MSG_TYPE_MOVE_SEND,
	    MACH_MSGH_BITS_COMPLEX),
			.msgh_id          = 0x100,
			.msgh_size        = sizeof(send_msg),
		},
		.body = {
			.msgh_descriptor_count = 1,
		},
		.port_descriptor = {
			.name        = msg_port,
			.disposition = MACH_MSG_TYPE_MOVE_RECEIVE,
			.type        = MACH_MSG_PORT_DESCRIPTOR,
		},
	};

	if (msg_port == MACH_PORT_NULL) {
		send_msg.body.msgh_descriptor_count = 0;
	}

	ret = mach_msg(&(send_msg.header),
	    MACH_SEND_MSG |
	    MACH_SEND_TIMEOUT |
	    MACH_SEND_OVERRIDE |
	    (reply_port ? MACH_SEND_SYNC_OVERRIDE : 0),
	    send_msg.header.msgh_size,
	    0,
	    MACH_PORT_NULL,
	    10000,
	    0);

	T_ASSERT_MACH_SUCCESS(ret, "client mach_msg");
}

T_HELPER_DECL(srp_client,
    "Client used for the special_reply_port test")
{
	pid_t ppid = getppid();
	dispatch_semaphore_t can_continue  = dispatch_semaphore_create(0);
	dispatch_queue_t dq = dispatch_queue_create("client_signalqueue", NULL);
	dispatch_source_t sig_src;

	mach_msg_return_t mr;
	mach_port_t service_port;
	mach_port_t conn_port;
	mach_port_t special_reply_port;
	mach_port_options_t opts = {
		.flags = MPO_INSERT_SEND_RIGHT,
	};

	signal(SIGUSR1, SIG_IGN);
	sig_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, dq);

	dispatch_source_set_event_handler(sig_src, ^{
			dispatch_semaphore_signal(can_continue);
	});
	dispatch_activate(sig_src);

	/* lookup the mach service port for the parent */
	kern_return_t kr = bootstrap_look_up(bootstrap_port,
	    SRP_SERVICE_NAME, &service_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "client bootstrap_look_up");

	/* create the send-once right (special reply port) and message to send to the server */
	kr = mach_port_construct(mach_task_self(), &opts, 0ull, &conn_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct");

	special_reply_port = thread_get_special_reply_port();
	T_QUIET; T_ASSERT_TRUE(MACH_PORT_VALID(special_reply_port), "get_thread_special_reply_port");

	/* send the message with the special reply port */
	srp_send(service_port, special_reply_port, conn_port);

	/* signal the parent to continue */
	kill(ppid, SIGUSR1);

	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t port_descriptor;
	} rcv_msg = {
		.header =
		{
			.msgh_remote_port = MACH_PORT_NULL,
			.msgh_local_port  = special_reply_port,
			.msgh_size        = sizeof(rcv_msg),
		},
	};

	/* wait on the reply from the parent (that we will never receive) */
	mr = mach_msg(&(rcv_msg.header),
			(MACH_RCV_MSG | MACH_RCV_SYNC_WAIT),
			0,
			rcv_msg.header.msgh_size,
			special_reply_port,
			MACH_MSG_TIMEOUT_NONE,
			service_port);

	/* not expected to execute as parent will SIGKILL client... */
	T_LOG("client process exiting after sending message to parent (server)");
}

/*
 * Tests the stackshot wait info plumbing for synchronous IPC that doesn't use kevent on the server.
 *
 * (part 1): tests the scenario where a client sends a request that includes a special reply port
 *           to a server that doesn't receive the message and doesn't copy the send-once right
 *           into its address space as a result. for this case the special reply port is enqueued
 *           in a port and we check which task has that receive right and use that info. (rdar://60440338)
 * (part 2): tests the scenario where a client sends a request that includes a special reply port
 *           to a server that receives the message and copies in the send-once right, but doesn't
 *           reply to the client. for this case the special reply port is copied out and the kernel
 *           stashes the info about which task copied out the send once right. (rdar://60440592)
 */
T_DECL(special_reply_port, "test that tasks using special reply ports have correct waitinfo")
{
	dispatch_semaphore_t can_continue  = dispatch_semaphore_create(0);
	dispatch_queue_t dq = dispatch_queue_create("signalqueue", NULL);
	dispatch_source_t sig_src;
	char path[PATH_MAX];
	uint32_t path_size = sizeof(path);
	T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");
	char *client_args[] = { path, "-n", "srp_client", NULL };
	pid_t client_pid;
	int sp_ret;
	kern_return_t kr;
	struct scenario scenario = {
		.name = "srp",
		.quiet = false,
		.flags = (STACKSHOT_THREAD_WAITINFO | STACKSHOT_KCDATA_FORMAT),
	};
	mach_port_t port;

	/* setup the signal handler in the parent (server) */
	T_LOG("setup sig handlers");
	signal(SIGUSR1, SIG_IGN);
	sig_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, dq);

	dispatch_source_set_event_handler(sig_src, ^{
			dispatch_semaphore_signal(can_continue);
	});
	dispatch_activate(sig_src);

	/* register with the mach service name so the client can lookup and send a message to the parent (server) */
	T_LOG("Server about to check in");
	kr = bootstrap_check_in(bootstrap_port, SRP_SERVICE_NAME, &port);
	T_ASSERT_MACH_SUCCESS(kr, "server bootstrap_check_in");

	T_LOG("Launching client");
	sp_ret = posix_spawn(&client_pid, client_args[0], NULL, NULL, client_args, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(sp_ret, "spawned process '%s' with PID %d", client_args[0], client_pid);
	T_LOG("Spawned client as PID %d", client_pid);

	dispatch_semaphore_wait(can_continue, DISPATCH_TIME_FOREVER);
	T_LOG("Ready to take stackshot, but waiting 1s for the coast to clear");

	sleep(1);

	/*
	 * take the stackshot without calling receive to verify that the stackshot wait
	 * info shows our (the server) PID for the scenario where the server has yet to
	 * receive the message.
	 */
	T_LOG("Taking stackshot for part 1 coverage");
	take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(PARSE_STACKSHOT_WAITINFO_SRP, ssbuf, sslen,
				@{srp_expected_pid_key: @(getpid())});
	});

	/*
	 * receive the message from the client (which should copy the send once right into
	 * our address space).
	 */
	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t port_descriptor;
	} rcv_msg = {
		.header =
		{
			.msgh_remote_port = MACH_PORT_NULL,
			.msgh_local_port  = port,
			.msgh_size        = sizeof(rcv_msg),
		},
	};

	T_LOG("server: starting sync receive\n");

	mach_msg_return_t mr;
	mr = mach_msg(&(rcv_msg.header),
			(MACH_RCV_MSG | MACH_RCV_TIMEOUT),
			0,
			4096,
			port,
			10000,
			MACH_PORT_NULL);
	T_QUIET; T_ASSERT_MACH_SUCCESS(mr, "mach_msg() recieve of message from client");

	/*
	 * take the stackshot to verify that the stackshot wait info shows our (the server) PID
	 * for the scenario where the server has received the message and copied in the send-once right.
	 */
	T_LOG("Taking stackshot for part 2 coverage");
	take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(PARSE_STACKSHOT_WAITINFO_SRP, ssbuf, sslen,
				@{srp_expected_pid_key: @(getpid())});
	});

	/* cleanup - kill the client */
	T_LOG("killing client");
	kill(client_pid, SIGKILL);

	T_LOG("waiting for the client to exit");
	waitpid(client_pid, NULL, 0);
}

#pragma mark performance tests

#define SHOULD_REUSE_SIZE_HINT 0x01
#define SHOULD_USE_DELTA       0x02
#define SHOULD_TARGET_SELF     0x04

static void
stackshot_perf(unsigned int options)
{
	struct scenario scenario = {
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS
			| STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT),
	};

	dt_stat_t size = dt_stat_create("bytes", "size");
	dt_stat_time_t duration = dt_stat_time_create("duration");
	scenario.timer = duration;

	if (options & SHOULD_TARGET_SELF) {
		scenario.target_pid = getpid();
	}

	while (!dt_stat_stable(duration) || !dt_stat_stable(size)) {
		__block uint64_t last_time = 0;
		__block uint32_t size_hint = 0;
		take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
			dt_stat_add(size, (double)sslen);
			last_time = stackshot_timestamp(ssbuf, sslen);
			size_hint = (uint32_t)sslen;
		});
		if (options & SHOULD_USE_DELTA) {
			scenario.since_timestamp = last_time;
			scenario.flags |= STACKSHOT_COLLECT_DELTA_SNAPSHOT;
		}
		if (options & SHOULD_REUSE_SIZE_HINT) {
			scenario.size_hint = size_hint;
		}
	}

	dt_stat_finalize(duration);
	dt_stat_finalize(size);
}

static void
stackshot_flag_perf_noclobber(uint64_t flag, char *flagname)
{
	struct scenario scenario = {
		.quiet = true,
		.flags = (flag | STACKSHOT_KCDATA_FORMAT),
	};

	dt_stat_t duration = dt_stat_create("nanoseconds per thread", "%s_duration", flagname);
	dt_stat_t size = dt_stat_create("bytes per thread", "%s_size", flagname);
	T_LOG("Testing \"%s\" = 0x%x", flagname, flag);

	while (!dt_stat_stable(duration) || !dt_stat_stable(size)) {
		take_stackshot(&scenario, false, ^(void *ssbuf, size_t sslen) {
			kcdata_iter_t iter = kcdata_iter(ssbuf, sslen);
			unsigned long no_threads = 0;
			mach_timebase_info_data_t timebase = {0, 0};
			uint64_t stackshot_duration = 0;
			int found = 0;
			T_QUIET; T_ASSERT_EQ(kcdata_iter_type(iter), KCDATA_BUFFER_BEGIN_STACKSHOT, "stackshot buffer");

			KCDATA_ITER_FOREACH(iter) {
				switch(kcdata_iter_type(iter)) {
					case STACKSHOT_KCTYPE_THREAD_SNAPSHOT: {
						found |= 1;
						no_threads ++;
						break;
					}
					case STACKSHOT_KCTYPE_STACKSHOT_DURATION: {
						struct stackshot_duration *ssd = kcdata_iter_payload(iter);
						stackshot_duration = ssd->stackshot_duration;
						found |= 2;
						break;
					}
					case KCDATA_TYPE_TIMEBASE: {
						found |= 4;
						mach_timebase_info_data_t *tb = kcdata_iter_payload(iter);
						memcpy(&timebase, tb, sizeof(timebase));
						break;
					}
				}
			}

			T_QUIET; T_ASSERT_EQ(found, 0x7, "found everything needed");

			uint64_t ns = (stackshot_duration * timebase.numer) / timebase.denom;
			uint64_t per_thread_ns = ns / no_threads;
			uint64_t per_thread_size = sslen / no_threads;

			dt_stat_add(duration, per_thread_ns);
			dt_stat_add(size, per_thread_size);
		});
	}

	dt_stat_finalize(duration);
	dt_stat_finalize(size);
}

static void
stackshot_flag_perf(uint64_t flag, char *flagname)
{
	/*
	 * STACKSHOT_NO_IO_STATS disables data collection, so set it for
	 * more accurate perfdata collection.
	 */
	flag |= STACKSHOT_NO_IO_STATS;

	stackshot_flag_perf_noclobber(flag, flagname);
}


T_DECL(flag_perf, "test stackshot performance with different flags set", T_META_TAG_PERF)
{
	stackshot_flag_perf_noclobber(STACKSHOT_NO_IO_STATS, "baseline");
	stackshot_flag_perf_noclobber(0, "io_stats");

	stackshot_flag_perf(STACKSHOT_THREAD_WAITINFO, "thread_waitinfo");
	stackshot_flag_perf(STACKSHOT_GET_DQ, "get_dq");
	stackshot_flag_perf(STACKSHOT_SAVE_LOADINFO, "save_loadinfo");
	stackshot_flag_perf(STACKSHOT_GET_GLOBAL_MEM_STATS, "get_global_mem_stats");
	stackshot_flag_perf(STACKSHOT_SAVE_KEXT_LOADINFO, "save_kext_loadinfo");
	stackshot_flag_perf(STACKSHOT_SAVE_IMP_DONATION_PIDS, "save_imp_donation_pids");
	stackshot_flag_perf(STACKSHOT_ENABLE_BT_FAULTING, "enable_bt_faulting");
	stackshot_flag_perf(STACKSHOT_COLLECT_SHAREDCACHE_LAYOUT, "collect_sharedcache_layout");
	stackshot_flag_perf(STACKSHOT_ENABLE_UUID_FAULTING, "enable_uuid_faulting");
	stackshot_flag_perf(STACKSHOT_THREAD_GROUP, "thread_group");
	stackshot_flag_perf(STACKSHOT_SAVE_JETSAM_COALITIONS, "save_jetsam_coalitions");
	stackshot_flag_perf(STACKSHOT_INSTRS_CYCLES, "instrs_cycles");
	stackshot_flag_perf(STACKSHOT_ASID, "asid");
}

T_DECL(perf_no_size_hint, "test stackshot performance with no size hint",
		T_META_TAG_PERF)
{
	stackshot_perf(0);
}

T_DECL(perf_size_hint, "test stackshot performance with size hint",
		T_META_TAG_PERF)
{
	stackshot_perf(SHOULD_REUSE_SIZE_HINT);
}

T_DECL(perf_process, "test stackshot performance targeted at process",
		T_META_TAG_PERF)
{
	stackshot_perf(SHOULD_REUSE_SIZE_HINT | SHOULD_TARGET_SELF);
}

T_DECL(perf_delta, "test delta stackshot performance",
		T_META_TAG_PERF)
{
	stackshot_perf(SHOULD_REUSE_SIZE_HINT | SHOULD_USE_DELTA);
}

T_DECL(perf_delta_process, "test delta stackshot performance targeted at a process",
		T_META_TAG_PERF)
{
	stackshot_perf(SHOULD_REUSE_SIZE_HINT | SHOULD_USE_DELTA | SHOULD_TARGET_SELF);
}

static uint64_t
stackshot_timestamp(void *ssbuf, size_t sslen)
{
	kcdata_iter_t iter = kcdata_iter(ssbuf, sslen);

	uint32_t type = kcdata_iter_type(iter);
	if (type != KCDATA_BUFFER_BEGIN_STACKSHOT && type != KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT) {
		T_ASSERT_FAIL("invalid kcdata type %u", kcdata_iter_type(iter));
	}

	iter = kcdata_iter_find_type(iter, KCDATA_TYPE_MACH_ABSOLUTE_TIME);
	T_QUIET;
	T_ASSERT_TRUE(kcdata_iter_valid(iter), "timestamp found in stackshot");

	return *(uint64_t *)kcdata_iter_payload(iter);
}

#define TEST_THREAD_NAME "stackshot_test_thread"

static void
parse_thread_group_stackshot(void **ssbuf, size_t sslen)
{
	bool seen_thread_group_snapshot = false;
	kcdata_iter_t iter = kcdata_iter(ssbuf, sslen);
	T_ASSERT_EQ(kcdata_iter_type(iter), KCDATA_BUFFER_BEGIN_STACKSHOT,
			"buffer provided is a stackshot");

	NSMutableSet *thread_groups = [[NSMutableSet alloc] init];

	iter = kcdata_iter_next(iter);
	KCDATA_ITER_FOREACH(iter) {
		switch (kcdata_iter_type(iter)) {
		case KCDATA_TYPE_ARRAY: {
			T_QUIET;
			T_ASSERT_TRUE(kcdata_iter_array_valid(iter),
					"checked that array is valid");

			if (kcdata_iter_array_elem_type(iter) != STACKSHOT_KCTYPE_THREAD_GROUP_SNAPSHOT) {
				continue;
			}

			seen_thread_group_snapshot = true;

			if (kcdata_iter_array_elem_size(iter) >= sizeof(struct thread_group_snapshot_v2)) {
				struct thread_group_snapshot_v2 *tgs_array = kcdata_iter_payload(iter);
				for (uint32_t j = 0; j < kcdata_iter_array_elem_count(iter); j++) {
					struct thread_group_snapshot_v2 *tgs = tgs_array + j;
					[thread_groups addObject:@(tgs->tgs_id)];
				}

			}
			else {
				struct thread_group_snapshot *tgs_array = kcdata_iter_payload(iter);
				for (uint32_t j = 0; j < kcdata_iter_array_elem_count(iter); j++) {
					struct thread_group_snapshot *tgs = tgs_array + j;
					[thread_groups addObject:@(tgs->tgs_id)];
				}
			}
			break;
		}
		}
	}
	KCDATA_ITER_FOREACH(iter) {
		NSError *error = nil;

		switch (kcdata_iter_type(iter)) {

		case KCDATA_TYPE_CONTAINER_BEGIN: {
			T_QUIET;
			T_ASSERT_TRUE(kcdata_iter_container_valid(iter),
					"checked that container is valid");

			if (kcdata_iter_container_type(iter) != STACKSHOT_KCCONTAINER_THREAD) {
				break;
			}

			NSDictionary *container = parseKCDataContainer(&iter, &error);
			T_QUIET; T_ASSERT_NOTNULL(container, "parsed container from stackshot");
			T_QUIET; T_ASSERT_NULL(error, "error unset after parsing container");

			int tg = [container[@"thread_snapshots"][@"thread_group"] intValue];

			T_ASSERT_TRUE([thread_groups containsObject:@(tg)], "check that the thread group the thread is in exists");

			break;
		};

		}
	}
	T_ASSERT_TRUE(seen_thread_group_snapshot, "check that we have seen a thread group snapshot");
}

static void
verify_stackshot_sharedcache_layout(struct dyld_uuid_info_64 *uuids, uint32_t uuid_count)
{
	uuid_t cur_shared_cache_uuid;
	__block uint32_t lib_index = 0, libs_found = 0;

	_dyld_get_shared_cache_uuid(cur_shared_cache_uuid);
	int result = dyld_shared_cache_iterate_text(cur_shared_cache_uuid, ^(const dyld_shared_cache_dylib_text_info* info) {
			T_QUIET; T_ASSERT_LT(lib_index, uuid_count, "dyld_shared_cache_iterate_text exceeded number of libraries returned by kernel");

			libs_found++;
			struct dyld_uuid_info_64 *cur_stackshot_uuid_entry = &uuids[lib_index];
			T_QUIET; T_ASSERT_EQ(memcmp(info->dylibUuid, cur_stackshot_uuid_entry->imageUUID, sizeof(info->dylibUuid)), 0,
					"dyld returned UUID doesn't match kernel returned UUID");
			T_QUIET; T_ASSERT_EQ(info->loadAddressUnslid, cur_stackshot_uuid_entry->imageLoadAddress,
					"dyld returned load address doesn't match kernel returned load address");
			lib_index++;
		});

	T_ASSERT_EQ(result, 0, "iterate shared cache layout");
	T_ASSERT_EQ(libs_found, uuid_count, "dyld iterator returned same number of libraries as kernel");

	T_LOG("verified %d libraries from dyld shared cache", libs_found);
}

static void
check_shared_cache_uuid(uuid_t imageUUID)
{
	static uuid_t shared_cache_uuid;
	static dispatch_once_t read_shared_cache_uuid;

	dispatch_once(&read_shared_cache_uuid, ^{
		T_QUIET;
		T_ASSERT_TRUE(_dyld_get_shared_cache_uuid(shared_cache_uuid), "retrieve current shared cache UUID");
	});
	T_QUIET; T_ASSERT_EQ(uuid_compare(shared_cache_uuid, imageUUID), 0,
			"dyld returned UUID doesn't match kernel returned UUID for system shared cache");
}

/*
 * extra dictionary contains data relevant for the given flags:
 * PARSE_STACKSHOT_ZOMBIE:   zombie_child_pid_key -> @(pid)
 * PARSE_STACKSHOT_POSTEXEC: postexec_child_unique_pid_key -> @(unique_pid)
 */
static void
parse_stackshot(uint64_t stackshot_parsing_flags, void *ssbuf, size_t sslen, NSDictionary *extra)
{
	bool delta = (stackshot_parsing_flags & PARSE_STACKSHOT_DELTA);
	bool expect_zombie_child = (stackshot_parsing_flags & PARSE_STACKSHOT_ZOMBIE);
	bool expect_postexec_child = (stackshot_parsing_flags & PARSE_STACKSHOT_POSTEXEC);
	bool expect_cseg_waitinfo = (stackshot_parsing_flags & PARSE_STACKSHOT_WAITINFO_CSEG);
	bool expect_translated_child = (stackshot_parsing_flags & PARSE_STACKSHOT_TRANSLATED);
	bool expect_shared_cache_layout = false;
	bool expect_shared_cache_uuid = !delta;
	bool expect_dispatch_queue_label = (stackshot_parsing_flags & PARSE_STACKSHOT_DISPATCH_QUEUE_LABEL);
	bool expect_turnstile_lock = (stackshot_parsing_flags & PARSE_STACKSHOT_TURNSTILEINFO);
	bool expect_srp_waitinfo = (stackshot_parsing_flags & PARSE_STACKSHOT_WAITINFO_SRP);
	bool found_zombie_child = false, found_postexec_child = false, found_shared_cache_layout = false, found_shared_cache_uuid = false;
	bool found_translated_child = false;
	bool found_dispatch_queue_label = false, found_turnstile_lock = false;
	bool found_cseg_waitinfo = false, found_srp_waitinfo = false;
	pid_t zombie_child_pid = -1, srp_expected_pid = 0;
	pid_t translated_child_pid = -1;
	uint64_t postexec_child_unique_pid = 0, cseg_expected_threadid = 0;
	char *inflatedBufferBase = NULL;

	if (expect_shared_cache_uuid) {
		uuid_t shared_cache_uuid;
		if (!_dyld_get_shared_cache_uuid(shared_cache_uuid)) {
			T_LOG("Skipping verifying shared cache UUID in stackshot data because not running with a shared cache");
			expect_shared_cache_uuid = false;
		}
	}

	if (stackshot_parsing_flags & PARSE_STACKSHOT_SHAREDCACHE_LAYOUT) {
		size_t shared_cache_length = 0;
		const void *cache_header = _dyld_get_shared_cache_range(&shared_cache_length);
		T_QUIET; T_ASSERT_NOTNULL(cache_header, "current process running with shared cache");
		T_QUIET; T_ASSERT_GT(shared_cache_length, sizeof(struct _dyld_cache_header), "valid shared cache length populated by _dyld_get_shared_cache_range");

		if (_dyld_shared_cache_is_locally_built()) {
			T_LOG("device running with locally built shared cache, expect shared cache layout");
			expect_shared_cache_layout = true;
		} else {
			T_LOG("device running with B&I built shared-cache, no shared cache layout expected");
		}
	}

	if (expect_zombie_child) {
		NSNumber* pid_num = extra[zombie_child_pid_key];
		T_QUIET; T_ASSERT_NOTNULL(pid_num, "zombie child pid provided");
		zombie_child_pid = [pid_num intValue];
		T_QUIET; T_ASSERT_GT(zombie_child_pid, 0, "zombie child pid greater than zero");
	}

	if (expect_postexec_child) {
		NSNumber* unique_pid_num = extra[postexec_child_unique_pid_key];
		T_QUIET; T_ASSERT_NOTNULL(unique_pid_num, "postexec child unique pid provided");
		postexec_child_unique_pid = [unique_pid_num unsignedLongLongValue];
		T_QUIET; T_ASSERT_GT(postexec_child_unique_pid, 0ull, "postexec child unique pid greater than zero");
	}

	if (expect_cseg_waitinfo) {
		NSNumber* tid_num = extra[cseg_expected_threadid_key];
		T_QUIET; T_ASSERT_NOTNULL(tid_num, "cseg's expected thread id provided");
		cseg_expected_threadid = [tid_num intValue];
		T_QUIET; T_ASSERT_GT(cseg_expected_threadid, 0, "cseg_expected_threadid greater than zero");
	}

	if (expect_srp_waitinfo) {
		NSNumber* pid_num = extra[srp_expected_pid_key];
		T_QUIET; T_ASSERT_NOTNULL(pid_num, "expected SRP pid provided");
		srp_expected_pid  = [pid_num intValue];
		T_QUIET; T_ASSERT_GT(srp_expected_pid , 0, "srp_expected_pid greater than zero");
	}

	if (expect_translated_child) {
		NSNumber* pid_num = extra[translated_child_pid_key];
		T_QUIET; T_ASSERT_NOTNULL(pid_num, "translated child pid provided");
		translated_child_pid = [pid_num intValue];
		T_QUIET; T_ASSERT_GT(translated_child_pid, 0, "translated child pid greater than zero");
	}
	
	kcdata_iter_t iter = kcdata_iter(ssbuf, sslen);
	if (delta) {
		T_ASSERT_EQ(kcdata_iter_type(iter), KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT,
				"buffer provided is a delta stackshot");

			iter = kcdata_iter_next(iter);
	} else {
		if (kcdata_iter_type(iter) != KCDATA_BUFFER_BEGIN_COMPRESSED) {
			T_ASSERT_EQ(kcdata_iter_type(iter), KCDATA_BUFFER_BEGIN_STACKSHOT,
					"buffer provided is a stackshot");

			iter = kcdata_iter_next(iter);
		} else {
			/* we are dealing with a compressed buffer */
			iter = kcdata_iter_next(iter);
			uint64_t compression_type = 0, totalout = 0, totalin = 0;

			uint64_t *data;
			char *desc;
			for (int i = 0; i < 3; i ++) {
				kcdata_iter_get_data_with_desc(iter, &desc, &data, NULL);
				if (strcmp(desc, "kcd_c_type") == 0) {
					compression_type = *data;
				} else if (strcmp(desc, "kcd_c_totalout") == 0){
					totalout = *data;
				} else if (strcmp(desc, "kcd_c_totalin") == 0){
					totalin = *data;
				}

				iter = kcdata_iter_next(iter);
			}

			T_ASSERT_EQ(compression_type, 1, "zlib compression is used");
			T_ASSERT_GT(totalout, 0, "successfully gathered how long the compressed buffer is");
			T_ASSERT_GT(totalin, 0, "successfully gathered how long the uncompressed buffer will be at least");

			/* progress to the next kcdata item */
			T_ASSERT_EQ(kcdata_iter_type(iter), KCDATA_BUFFER_BEGIN_STACKSHOT, "compressed stackshot found");

			void *bufferBase = kcdata_iter_payload(iter);

			/*
			 * zlib is used, allocate a buffer based on the metadata, plus
			 * extra scratch space (+12.5%) in case totalin was inconsistent
			 */
			size_t inflatedBufferSize = totalin + (totalin >> 3);
			inflatedBufferBase = malloc(inflatedBufferSize);
			T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(inflatedBufferBase, "allocated temporary output buffer");

			z_stream zs;
			memset(&zs, 0, sizeof(zs));
			T_QUIET; T_ASSERT_EQ(inflateInit(&zs), Z_OK, "inflateInit OK");
			zs.next_in = bufferBase;
			zs.avail_in = totalout;
			zs.next_out = inflatedBufferBase;
			zs.avail_out = inflatedBufferSize;
			T_ASSERT_EQ(inflate(&zs, Z_FINISH), Z_STREAM_END, "inflated buffer");
			inflateEnd(&zs);

			T_ASSERT_EQ(zs.total_out, totalin, "expected number of bytes inflated");
			
			/* copy the data after the compressed area */
			T_QUIET; T_ASSERT_LE(sslen - totalout - (bufferBase - ssbuf),
					inflatedBufferSize - zs.total_out,
					"footer fits in the buffer");
			memcpy(inflatedBufferBase + zs.total_out,
					bufferBase + totalout,
					sslen - totalout - (bufferBase - ssbuf));

			iter = kcdata_iter(inflatedBufferBase, inflatedBufferSize);
		}
	}

	KCDATA_ITER_FOREACH(iter) {
		NSError *error = nil;

		switch (kcdata_iter_type(iter)) {
		case KCDATA_TYPE_ARRAY: {
			T_QUIET;
			T_ASSERT_TRUE(kcdata_iter_array_valid(iter),
					"checked that array is valid");

			NSMutableDictionary *array = parseKCDataArray(iter, &error);
			T_QUIET; T_ASSERT_NOTNULL(array, "parsed array from stackshot");
			T_QUIET; T_ASSERT_NULL(error, "error unset after parsing array");

			if (kcdata_iter_array_elem_type(iter) == STACKSHOT_KCTYPE_SYS_SHAREDCACHE_LAYOUT) {
				struct dyld_uuid_info_64 *shared_cache_uuids = kcdata_iter_payload(iter);
				uint32_t uuid_count = kcdata_iter_array_elem_count(iter);
				T_ASSERT_NOTNULL(shared_cache_uuids, "parsed shared cache layout array");
				T_ASSERT_GT(uuid_count, 0, "returned valid number of UUIDs from shared cache");
				verify_stackshot_sharedcache_layout(shared_cache_uuids, uuid_count);
				found_shared_cache_layout = true;
			}

			break;
		}

		case KCDATA_TYPE_CONTAINER_BEGIN: {
			T_QUIET;
			T_ASSERT_TRUE(kcdata_iter_container_valid(iter),
					"checked that container is valid");

			if (kcdata_iter_container_type(iter) != STACKSHOT_KCCONTAINER_TASK) {
				break;
			}

			NSDictionary *container = parseKCDataContainer(&iter, &error);
			T_QUIET; T_ASSERT_NOTNULL(container, "parsed container from stackshot");
			T_QUIET; T_ASSERT_NULL(error, "error unset after parsing container");

			NSDictionary* task_snapshot = container[@"task_snapshots"][@"task_snapshot"];
			NSDictionary* task_delta_snapshot = container[@"task_snapshots"][@"task_delta_snapshot"];
			
			T_QUIET; T_ASSERT_TRUE(!!task_snapshot != !!task_delta_snapshot, "Either task_snapshot xor task_delta_snapshot provided");

			if (expect_dispatch_queue_label && !found_dispatch_queue_label) {
				for (id thread_key in container[@"task_snapshots"][@"thread_snapshots"]) {
					NSMutableDictionary *thread = container[@"task_snapshots"][@"thread_snapshots"][thread_key];
					NSString *dql = thread[@"dispatch_queue_label"];

					if ([dql isEqualToString:@TEST_STACKSHOT_QUEUE_LABEL]) {
						found_dispatch_queue_label = true;
						break;
					}
				}
			}
			
			if (expect_postexec_child && !found_postexec_child) {
				if (task_snapshot) {
					uint64_t unique_pid = [task_snapshot[@"ts_unique_pid"] unsignedLongLongValue];
					if (unique_pid == postexec_child_unique_pid) {
						found_postexec_child = true;
						
						T_PASS("post-exec child %llu has a task snapshot", postexec_child_unique_pid);
						
						break;
					}
				}
				
				if (task_delta_snapshot) {
					uint64_t unique_pid = [task_delta_snapshot[@"tds_unique_pid"] unsignedLongLongValue];
					if (unique_pid == postexec_child_unique_pid) {
						found_postexec_child = true;
						
						T_FAIL("post-exec child %llu shouldn't have a delta task snapshot", postexec_child_unique_pid);
						
						break;
					}
				}
			}
			
			if (!task_snapshot) {
				break;
			}

			int pid = [task_snapshot[@"ts_pid"] intValue];

			if (pid && expect_shared_cache_uuid && !found_shared_cache_uuid) {
				id ptr = container[@"task_snapshots"][@"shared_cache_dyld_load_info"];
				if (ptr) {
					id uuid = ptr[@"imageUUID"];

					uint8_t uuid_p[16];
					for (int i = 0; i < 16; i ++)
						uuid_p[i] = (uint8_t) ([[uuid objectAtIndex:i] intValue]);

					check_shared_cache_uuid(uuid_p);

					/* 
					 * check_shared_cache_uuid() will assert on failure, so if
					 * we get here, then we have found the shared cache UUID
					 * and it's correct
					 */
					found_shared_cache_uuid =  true;
				}
			}
			
			
			if (expect_zombie_child && (pid == zombie_child_pid)) {
				found_zombie_child = true;
				
				uint64_t task_flags = [task_snapshot[@"ts_ss_flags"] unsignedLongLongValue];
				T_ASSERT_TRUE((task_flags & kTerminatedSnapshot) == kTerminatedSnapshot, "child zombie marked as terminated");
				
				continue;
			}
			
			if (expect_translated_child && (pid == translated_child_pid)) {
				found_translated_child = true;
				
				uint64_t task_flags = [task_snapshot[@"ts_ss_flags"] unsignedLongLongValue];
				T_ASSERT_EQ((task_flags & kTaskIsTranslated), kTaskIsTranslated, "child marked as translated");
				
				continue;
			}

			if (expect_cseg_waitinfo) {
				NSArray *winfos = container[@"task_snapshots"][@"thread_waitinfo"];

				for (id i in winfos) {
					if ([i[@"wait_type"] intValue] == kThreadWaitCompressor && [i[@"owner"] intValue] == cseg_expected_threadid) {
						found_cseg_waitinfo = true;
						break;
					}
				}
			}

			if (expect_srp_waitinfo) {
				NSArray *tinfos = container[@"task_snapshots"][@"thread_turnstileinfo"];
				NSArray *winfos = container[@"task_snapshots"][@"thread_waitinfo"];

				for (id i in tinfos) {
					if (!found_srp_waitinfo) {
						if ([i[@"turnstile_context"] intValue] == srp_expected_pid &&
								([i[@"turnstile_flags"] intValue] & STACKSHOT_TURNSTILE_STATUS_BLOCKED_ON_TASK)) {

							/* we found something that is blocking the correct pid */
							for (id j in winfos) {
								if ([j[@"waiter"] intValue] == [i[@"waiter"] intValue] &&
										[j[@"wait_type"] intValue] == kThreadWaitPortReceive) {
									found_srp_waitinfo = true;
									break;
								}
							}

							if (found_srp_waitinfo) {
								break;
							}
						}
					}
				}
			}

			if (pid != getpid()) {
				break;
			}
			
			T_EXPECT_EQ_STR(current_process_name(),
					[task_snapshot[@"ts_p_comm"] UTF8String],
					"current process name matches in stackshot");

			uint64_t task_flags = [task_snapshot[@"ts_ss_flags"] unsignedLongLongValue];
			T_ASSERT_NE((task_flags & kTerminatedSnapshot), kTerminatedSnapshot, "current process not marked as terminated");
			T_ASSERT_NE((task_flags & kTaskIsTranslated), kTaskIsTranslated, "current process not marked as translated");

			T_QUIET;
			T_EXPECT_LE(pid, [task_snapshot[@"ts_unique_pid"] intValue],
					"unique pid is greater than pid");

			NSDictionary* task_cpu_architecture = container[@"task_snapshots"][@"task_cpu_architecture"];
			T_QUIET; T_ASSERT_NOTNULL(task_cpu_architecture[@"cputype"], "have cputype");
			T_QUIET; T_ASSERT_NOTNULL(task_cpu_architecture[@"cpusubtype"], "have cputype");
			int cputype = [task_cpu_architecture[@"cputype"] intValue];
			int cpusubtype = [task_cpu_architecture[@"cpusubtype"] intValue];

			struct proc_archinfo archinfo;
			int retval = proc_pidinfo(pid, PROC_PIDARCHINFO, 0, &archinfo, sizeof(archinfo));
			T_QUIET; T_WITH_ERRNO; T_ASSERT_GT(retval, 0, "proc_pidinfo(PROC_PIDARCHINFO) returned a value > 0");
			T_QUIET; T_ASSERT_EQ(retval, (int)sizeof(struct proc_archinfo), "proc_pidinfo call for PROC_PIDARCHINFO returned expected size");
			T_QUIET; T_EXPECT_EQ(cputype, archinfo.p_cputype, "cpu type is correct");
			T_QUIET; T_EXPECT_EQ(cpusubtype, archinfo.p_cpusubtype, "cpu subtype is correct");

			bool found_main_thread = false;
			uint64_t main_thread_id = -1ULL;
			for (id thread_key in container[@"task_snapshots"][@"thread_snapshots"]) {
				NSMutableDictionary *thread = container[@"task_snapshots"][@"thread_snapshots"][thread_key];
				NSDictionary *thread_snap = thread[@"thread_snapshot"];

				T_QUIET; T_EXPECT_GT([thread_snap[@"ths_thread_id"] intValue], 0,
						"thread ID of thread in current task is valid");
				T_QUIET; T_EXPECT_GT([thread_snap[@"ths_base_priority"] intValue], 0,
						"base priority of thread in current task is valid");
				T_QUIET; T_EXPECT_GT([thread_snap[@"ths_sched_priority"] intValue], 0,
						"scheduling priority of thread in current task is valid");

				NSString *pth_name = thread[@"pth_name"];
				if (pth_name != nil && [pth_name isEqualToString:@TEST_THREAD_NAME]) {
					found_main_thread = true;
					main_thread_id = [thread_snap[@"ths_thread_id"] unsignedLongLongValue];

					T_QUIET; T_EXPECT_GT([thread_snap[@"ths_total_syscalls"] intValue], 0,
							"total syscalls of current thread is valid");

					NSDictionary *cpu_times = thread[@"cpu_times"];
					T_EXPECT_GE([cpu_times[@"runnable_time"] intValue],
							[cpu_times[@"system_time"] intValue] +
							[cpu_times[@"user_time"] intValue],
							"runnable time of current thread is valid");
				}
			}
			T_EXPECT_TRUE(found_main_thread, "found main thread for current task in stackshot");

			if (expect_turnstile_lock && !found_turnstile_lock) {
				NSArray *tsinfos = container[@"task_snapshots"][@"thread_turnstileinfo"];

				for (id i in tsinfos) {
					if ([i[@"turnstile_context"] unsignedLongLongValue] == main_thread_id) {
						found_turnstile_lock = true;
						break;
					}
				}
			}
			break;
		}
		case STACKSHOT_KCTYPE_SHAREDCACHE_LOADINFO: {
			struct dyld_uuid_info_64_v2 *payload = kcdata_iter_payload(iter);
			T_ASSERT_EQ(kcdata_iter_size(iter), sizeof(*payload), "valid dyld_uuid_info_64_v2 struct");

			check_shared_cache_uuid(payload->imageUUID);

			/* 
			 * check_shared_cache_uuid() asserts on failure, so we must have
			 * found the shared cache UUID to be correct.
			 */
			found_shared_cache_uuid = true;
			break;
		}
		}
	}

	if (expect_zombie_child) {
		T_QUIET; T_ASSERT_TRUE(found_zombie_child, "found zombie child in kcdata");
	}

	if (expect_postexec_child) {
		T_QUIET; T_ASSERT_TRUE(found_postexec_child, "found post-exec child in kcdata");
	}

	if (expect_translated_child) {
		T_QUIET; T_ASSERT_TRUE(found_translated_child, "found translated child in kcdata");
	}

	if (expect_shared_cache_layout) {
		T_QUIET; T_ASSERT_TRUE(found_shared_cache_layout, "shared cache layout found in kcdata");
	}

	if (expect_shared_cache_uuid) {
		T_QUIET; T_ASSERT_TRUE(found_shared_cache_uuid, "shared cache UUID found in kcdata");
	}

	if (expect_dispatch_queue_label) {
		T_QUIET; T_ASSERT_TRUE(found_dispatch_queue_label, "dispatch queue label found in kcdata");
	}

	if (expect_turnstile_lock) {
		T_QUIET; T_ASSERT_TRUE(found_turnstile_lock, "found expected deadlock");
	}

	if (expect_cseg_waitinfo) {
		T_QUIET; T_ASSERT_TRUE(found_cseg_waitinfo, "found c_seg waitinfo");
	}

	if (expect_srp_waitinfo) {
		T_QUIET; T_ASSERT_TRUE(found_srp_waitinfo, "found special reply port waitinfo");
	}

	T_ASSERT_FALSE(KCDATA_ITER_FOREACH_FAILED(iter), "successfully iterated kcdata");

	free(inflatedBufferBase);
}

static const char *
current_process_name(void)
{
	static char name[64];

	if (!name[0]) {
		int ret = proc_name(getpid(), name, sizeof(name));
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(ret, "proc_name failed for current process");
	}

	return name;
}

static void
initialize_thread(void)
{
	int ret = pthread_setname_np(TEST_THREAD_NAME);
	T_QUIET;
	T_ASSERT_POSIX_ZERO(ret, "set thread name to %s", TEST_THREAD_NAME);
}

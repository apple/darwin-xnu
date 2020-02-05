#include <darwintest.h>
#include <darwintest_utils.h>
#include <kern/debug.h>
#include <kern/kern_cdata.h>
#include <kdd.h>
#include <libproc.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/dyld_priv.h>
#include <sys/syscall.h>
#include <sys/stackshot.h>

T_GLOBAL_META(
		T_META_NAMESPACE("xnu.stackshot"),
		T_META_CHECK_LEAKS(false),
		T_META_ASROOT(true)
		);

static const char *current_process_name(void);
static void verify_stackshot_sharedcache_layout(struct dyld_uuid_info_64 *uuids, uint32_t uuid_count);
static void parse_stackshot(uint64_t stackshot_parsing_flags, void *ssbuf, size_t sslen, int child_pid);
static void parse_thread_group_stackshot(void **sbuf, size_t sslen);
static uint64_t stackshot_timestamp(void *ssbuf, size_t sslen);
static void initialize_thread(void);

#define DEFAULT_STACKSHOT_BUFFER_SIZE (1024 * 1024)
#define MAX_STACKSHOT_BUFFER_SIZE     (6 * 1024 * 1024)

/* bit flags for parse_stackshot */
#define PARSE_STACKSHOT_DELTA                0x01
#define PARSE_STACKSHOT_ZOMBIE               0x02
#define PARSE_STACKSHOT_SHAREDCACHE_LAYOUT   0x04
#define PARSE_STACKSHOT_DISPATCH_QUEUE_LABEL 0x08
#define PARSE_STACKSHOT_TURNSTILEINFO        0x10

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
				STACKSHOT_GET_MICROSTACKSHOT);
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
	uint32_t flags;
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
take_stackshot(struct scenario *scenario, void (^cb)(void *buf, size_t size))
{
	initialize_thread();

	void *config = stackshot_config_create();
	quiet(scenario);
	T_ASSERT_NOTNULL(config, "created stackshot config");

	int ret = stackshot_config_set_flags(config, scenario->flags);
	quiet(scenario);
	T_ASSERT_POSIX_ZERO(ret, "set flags %#x on stackshot config", scenario->flags);

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

	ret = stackshot_config_dealloc(config);
	T_QUIET; T_EXPECT_POSIX_ZERO(ret, "deallocated stackshot config");
}

T_DECL(kcdata, "test that kcdata stackshots can be taken and parsed")
{
	struct scenario scenario = {
		.name = "kcdata",
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS |
				STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT),
	};

	T_LOG("taking kcdata stackshot");
	take_stackshot(&scenario, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(0, ssbuf, sslen, -1);
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
	take_stackshot(&scenario, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(0, ssbuf, sslen, -1);
	});
}

T_DECL(bad_flags, "test a poorly-formed stackshot syscall")
{
	struct scenario scenario = {
		.flags = STACKSHOT_SAVE_IN_KERNEL_BUFFER /* not allowed from user space */,
		.should_fail = true,
	};

	T_LOG("attempting to take stackshot with kernel-only flag");
	take_stackshot(&scenario, ^(__unused void *ssbuf, __unused size_t sslen) {
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
	take_stackshot(&scenario, ^(void *ssbuf, size_t sslen) {
		uint64_t stackshot_time = stackshot_timestamp(ssbuf, sslen);

		T_LOG("taking delta stackshot since time %" PRIu64, stackshot_time);

		parse_stackshot(0, ssbuf, sslen, -1);

		struct scenario delta_scenario = {
			.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS
					| STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT
					| STACKSHOT_COLLECT_DELTA_SNAPSHOT),
			.since_timestamp = stackshot_time
		};

		take_stackshot(&delta_scenario, ^(void *dssbuf, size_t dsslen) {
			parse_stackshot(PARSE_STACKSHOT_DELTA, dssbuf, dsslen, -1);
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
	take_stackshot(&scenario, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(PARSE_STACKSHOT_SHAREDCACHE_LAYOUT, ssbuf, sslen, -1);
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
		take_stackshot(&scenario, ^(void *ssbuf, size_t sslen) {
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
	take_stackshot(&scenario, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(PARSE_STACKSHOT_DISPATCH_QUEUE_LABEL, ssbuf, sslen, -1);
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

	take_stackshot(&scenario, ^( void *ssbuf, size_t sslen) {
		/* First unwedge the child so we can reap it */
		int val = 1, status;
		T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.unwedge_thread", NULL, NULL, &val, sizeof(val)), "unwedge child");

		T_QUIET; T_ASSERT_POSIX_SUCCESS(waitpid(pid, &status, 0), "waitpid on zombie child");

		parse_stackshot(PARSE_STACKSHOT_ZOMBIE, ssbuf, sslen, pid);
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
	qos_class_t main_qos = 0;
	int main_relpri = 0, main_relpri2 = 0, main_afterpri = 0;
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
		main_afterpri = get_user_promotion_basepri();
		if (main_relpri != main_afterpri) {
			T_LOG("Success with promotion pri is %d", main_afterpri);
			break;
		}

		usleep(100);
	}

	take_stackshot(&scenario, ^( void *ssbuf, size_t sslen) {
		parse_stackshot(PARSE_STACKSHOT_TURNSTILEINFO, ssbuf, sslen, -1);
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
	take_stackshot(&scenario, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(0, ssbuf, sslen, -1);
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
	take_stackshot(&scenario, ^(void *ssbuf, size_t sslen) {
		uint64_t stackshot_time = stackshot_timestamp(ssbuf, sslen);

		T_LOG("taking delta stackshot since time %" PRIu64, stackshot_time);

		parse_stackshot(0, ssbuf, sslen, -1);
		expect_instrs_cycles_in_stackshot(ssbuf, sslen);

		struct scenario delta_scenario = {
			.name = "delta-instrs-cycles-next",
			.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_INSTRS_CYCLES
					| STACKSHOT_KCDATA_FORMAT
					| STACKSHOT_COLLECT_DELTA_SNAPSHOT),
			.since_timestamp = stackshot_time,
		};

		take_stackshot(&delta_scenario, ^(void *dssbuf, size_t dsslen) {
			parse_stackshot(PARSE_STACKSHOT_DELTA, dssbuf, dsslen, -1);
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
	take_stackshot(&scenario, ^(void *ssbuf, size_t sslen) {
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
	take_stackshot(&scenario, ^(void *ssbuf, size_t sslen) {
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
	take_stackshot(&scenario, ^(void *ssbuf, size_t sslen) {
		stackshot_verify_current_proc_uuid_info(ssbuf, sslen, expected_mach_header_offset, &proc_info_data);
	});
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
		take_stackshot(&scenario, ^(void *ssbuf, size_t sslen) {
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
parse_stackshot(uint64_t stackshot_parsing_flags, void *ssbuf, size_t sslen, int child_pid)
{
	bool delta = (stackshot_parsing_flags & PARSE_STACKSHOT_DELTA);
	bool expect_zombie_child = (stackshot_parsing_flags & PARSE_STACKSHOT_ZOMBIE);
	bool expect_shared_cache_layout = false;
	bool expect_shared_cache_uuid = !delta;
	bool expect_dispatch_queue_label = (stackshot_parsing_flags & PARSE_STACKSHOT_DISPATCH_QUEUE_LABEL);
	bool expect_turnstile_lock = (stackshot_parsing_flags & PARSE_STACKSHOT_TURNSTILEINFO);
	bool found_zombie_child = false, found_shared_cache_layout = false, found_shared_cache_uuid = false;
	bool found_dispatch_queue_label = false, found_turnstile_lock = false;

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
		T_QUIET; T_ASSERT_GT(child_pid, 0, "child pid greater than zero");
	}

	kcdata_iter_t iter = kcdata_iter(ssbuf, sslen);
	if (delta) {
		T_ASSERT_EQ(kcdata_iter_type(iter), KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT,
				"buffer provided is a delta stackshot");
	} else {
		T_ASSERT_EQ(kcdata_iter_type(iter), KCDATA_BUFFER_BEGIN_STACKSHOT,
				"buffer provided is a stackshot");
	}

	iter = kcdata_iter_next(iter);
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

			int pid = [container[@"task_snapshots"][@"task_snapshot"][@"ts_pid"] intValue];
			if (expect_zombie_child && (pid == child_pid)) {
					found_zombie_child = true;

					uint64_t task_flags = [container[@"task_snapshots"][@"task_snapshot"][@"ts_ss_flags"] unsignedLongLongValue];
					T_ASSERT_TRUE((task_flags & kTerminatedSnapshot) == kTerminatedSnapshot, "child zombie marked as terminated");

					continue;
			} else if (pid != getpid()) {
				break;
			}

			T_EXPECT_EQ_STR(current_process_name(),
					[container[@"task_snapshots"][@"task_snapshot"][@"ts_p_comm"] UTF8String],
					"current process name matches in stackshot");

			uint64_t task_flags = [container[@"task_snapshots"][@"task_snapshot"][@"ts_ss_flags"] unsignedLongLongValue];
			T_ASSERT_FALSE((task_flags & kTerminatedSnapshot) == kTerminatedSnapshot, "current process not marked as terminated");

			T_QUIET;
			T_EXPECT_LE(pid, [container[@"task_snapshots"][@"task_snapshot"][@"ts_unique_pid"] intValue],
					"unique pid is greater than pid");

			bool found_main_thread = false;
			uint64_t main_thread_id = -1;
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
					main_thread_id = [thread_snap[@"ths_thread_id"] intValue];

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
					if ([i[@"turnstile_context"] intValue] == main_thread_id) {
						found_turnstile_lock = true;
						break;
					}
				}
			}
			break;
		}
		case STACKSHOT_KCTYPE_SHAREDCACHE_LOADINFO: {
			struct dyld_uuid_info_64_v2 *shared_cache_info = kcdata_iter_payload(iter);
			uuid_t shared_cache_uuid;
			T_QUIET; T_ASSERT_TRUE(_dyld_get_shared_cache_uuid(shared_cache_uuid), "retrieve current shared cache UUID");
			T_QUIET; T_ASSERT_EQ(memcmp(shared_cache_info->imageUUID, shared_cache_uuid, sizeof(shared_cache_uuid)), 0,
					"dyld returned UUID doesn't match kernel returned UUID for system shared cache");
			found_shared_cache_uuid = true;
			break;
		}
		}
	}

	if (expect_zombie_child) {
		T_QUIET; T_ASSERT_TRUE(found_zombie_child, "found zombie child in kcdata");
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

	T_ASSERT_FALSE(KCDATA_ITER_FOREACH_FAILED(iter), "successfully iterated kcdata");
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

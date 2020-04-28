#include <darwintest.h>
#include <darwintest_utils.h>
#include <sys/kern_memorystatus.h>
#include <kern/debug.h>
#include <mach-o/dyld.h>
#include <sys/stackshot.h>
#include <kdd.h>
#include <signal.h>

#define RECURSIONS 25
#define FIRST_RECURSIVE_FRAME 3

T_GLOBAL_META(
		T_META_NAMESPACE("xnu.stackshot.accuracy"),
		T_META_CHECK_LEAKS(false),
		T_META_ASROOT(true)
		);


void child_init(void);
void parent_helper_singleproc(int);

#define CHECK_FOR_FAULT_STATS         (1 << 0)
#define WRITE_STACKSHOT_BUFFER_TO_TMP (1 << 1)
#define CHECK_FOR_KERNEL_THREADS      (1 << 2)
int check_stackshot(void *, int);

/* used for WRITE_STACKSHOT_BUFFER_TO_TMP */
static char const *current_scenario_name;
static pid_t child_pid;

/* helpers */

static void __attribute__((noinline))
child_recurse(int r, int spin, void (^cb)(void))
{
	if (r > 0) {
		child_recurse(r - 1, spin, cb);
	}

	cb();

	/* wait forever */
	if (spin == 0) {
		sleep(100000);
	} else if (spin == 2) {
		int v = 1;
		/* ssh won't let the session die if we still have file handles open to its output. */
		close(STDERR_FILENO);
		close(STDOUT_FILENO);
		T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.wedge_thread", NULL, NULL, &v, sizeof(v)),
					"wedged thread in the kernel");
	} else {
		while (1) {
			__asm__ volatile("" : : : "memory");
		}
	}
}

T_HELPER_DECL(simple_child_process, "child process that will be frozen and others")
{
	child_init();
}

T_HELPER_DECL(sid_child_process, "child process that setsid()s")
{
	pid_t ppid = getppid();

	T_ASSERT_POSIX_SUCCESS(setsid(), "session id set");

	child_recurse(RECURSIONS, 2, ^{
		kill(ppid, SIGUSR1);
	});

	T_ASSERT_FAIL("child_init returned!");
}

static void
kill_children(void)
{
	kill(child_pid, SIGKILL);
}

static void *
take_stackshot(pid_t target_pid, uint32_t extra_flags, uint64_t since_timestamp)
{
	void *stackshot_config;
	int err, retries = 5;
	uint32_t stackshot_flags = STACKSHOT_KCDATA_FORMAT |
								STACKSHOT_THREAD_WAITINFO |
								STACKSHOT_GET_DQ;

	/* we should be able to verify delta stackshots */
	if (since_timestamp != 0) {
		stackshot_flags |= STACKSHOT_COLLECT_DELTA_SNAPSHOT;
	}

	stackshot_flags |= extra_flags;

	stackshot_config = stackshot_config_create();
	T_ASSERT_NOTNULL(stackshot_config, "allocate stackshot config");

	err = stackshot_config_set_flags(stackshot_config, stackshot_flags);
	T_ASSERT_EQ(err, 0, "set flags on stackshot config");

	err = stackshot_config_set_pid(stackshot_config, target_pid);
	T_ASSERT_EQ(err, 0, "set target pid on stackshot config");

	if (since_timestamp != 0) {
		err = stackshot_config_set_delta_timestamp(stackshot_config, since_timestamp);
		T_ASSERT_EQ(err, 0, "set prev snapshot time on stackshot config");
	}

	while (retries > 0) {
		err = stackshot_capture_with_config(stackshot_config);
		if (err == 0) {
			break;
		} else if (err == EBUSY || err == ETIMEDOUT) {
			T_LOG("stackshot capture returned %d (%s)\n", err, strerror(err));
			if (retries == 0) {
				T_ASSERT_FAIL("failed to take stackshot with error after retries: %d: %s\n", err, strerror(err));
			}

			retries--;
			continue;
		} else {
			T_ASSERT_FAIL("failed to take stackshot with error: %d: %s\n", err, strerror(err));
		}
	}

	return stackshot_config;
}

int
check_stackshot(void *stackshot_config, int flags)
{
	void *buf;
	uint32_t buflen, kcdata_type;
	kcdata_iter_t iter;
	NSError *nserror = nil;
	pid_t target_pid;
	int ret = 0;
	uint64_t expected_return_addr = 0;
	bool found_fault_stats = false;
	struct stackshot_fault_stats fault_stats = {0};

	buf = stackshot_config_get_stackshot_buffer(stackshot_config);
	T_ASSERT_NOTNULL(buf, "stackshot buffer is not null");
	buflen = stackshot_config_get_stackshot_size(stackshot_config);
	T_ASSERT_GT(buflen, 0, "valid stackshot buffer length");
	target_pid = ((struct stackshot_config*)stackshot_config)->sc_pid;
	T_ASSERT_GT(target_pid, 0, "valid target_pid");

	/* if need to write it to fs, do it now */
	if (flags & WRITE_STACKSHOT_BUFFER_TO_TMP) {
		char sspath[MAXPATHLEN];
		strlcpy(sspath, current_scenario_name, sizeof(sspath));
		strlcat(sspath, ".kcdata", sizeof(sspath));
		T_QUIET; T_ASSERT_POSIX_ZERO(dt_resultfile(sspath, sizeof(sspath)),
				"create result file path");

		FILE *f = fopen(sspath, "w");
		T_WITH_ERRNO; T_QUIET; T_ASSERT_NOTNULL(f,
				"open stackshot output file");

		size_t written = fwrite(buf, buflen, 1, f);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(written, "wrote stackshot to file");

		fclose(f);
	}

	/* begin iterating */
	iter = kcdata_iter(buf, buflen);
	T_ASSERT_EQ(kcdata_iter_type(iter), KCDATA_BUFFER_BEGIN_STACKSHOT, "buffer is a stackshot");

	/* time to iterate */
	iter = kcdata_iter_next(iter);
	KCDATA_ITER_FOREACH(iter) {
		kcdata_type = kcdata_iter_type(iter);
		NSNumber *parsedPid;
		NSMutableDictionary *parsedContainer, *parsedThreads;

		if ((flags & CHECK_FOR_FAULT_STATS) != 0 &&
				kcdata_type == STACKSHOT_KCTYPE_STACKSHOT_FAULT_STATS) {
			memcpy(&fault_stats, kcdata_iter_payload(iter), sizeof(fault_stats));
			found_fault_stats = true;
		}

		if (kcdata_type != KCDATA_TYPE_CONTAINER_BEGIN) {
			continue;
		}
		
		if (kcdata_iter_container_type(iter) != STACKSHOT_KCCONTAINER_TASK) {
			continue;
		}

		parsedContainer = parseKCDataContainer(&iter, &nserror);
		T_ASSERT_NOTNULL(parsedContainer, "parsedContainer is not null");
		T_ASSERT_NULL(nserror, "no NSError occured while parsing the kcdata container");

		/* 
		 * given that we've targetted the pid, we can be sure that this
		 * ts_pid will be the pid we expect
		 */
		parsedPid = parsedContainer[@"task_snapshots"][@"task_snapshot"][@"ts_pid"];
		T_ASSERT_EQ([parsedPid intValue], target_pid, "found correct pid");

		/* start parsing the threads */
		parsedThreads = parsedContainer[@"task_snapshots"][@"thread_snapshots"];
		for (id th_key in parsedThreads) {
			uint32_t frame_index = 0;

			if ((flags & CHECK_FOR_KERNEL_THREADS) == 0) {
				/* skip threads that don't have enough frames */
				if ([parsedThreads[th_key][@"user_stack_frames"] count] < RECURSIONS) {
					continue;
				}

				for (id frame in parsedThreads[th_key][@"user_stack_frames"]) {
					if ((frame_index >= FIRST_RECURSIVE_FRAME) && (frame_index < (RECURSIONS - FIRST_RECURSIVE_FRAME))) {
						if (expected_return_addr == 0ull) {
							expected_return_addr = [frame[@"lr"] unsignedLongLongValue];
						} else {
							T_QUIET;
							T_ASSERT_EQ(expected_return_addr, [frame[@"lr"] unsignedLongLongValue], "expected return address found");
						}
					}
					frame_index ++;
				}
			} else {
				T_ASSERT_NOTNULL(parsedThreads[th_key][@"kernel_stack_frames"],
						"found kernel stack frames");
			}

		}
	}

	if (found_fault_stats) {
		T_LOG("number of pages faulted in: %d", fault_stats.sfs_pages_faulted_in);
		T_LOG("MATUs spent faulting: %lld", fault_stats.sfs_time_spent_faulting);
		T_LOG("MATUS fault time limit: %lld", fault_stats.sfs_system_max_fault_time);
		T_LOG("did we stop because of the limit?: %s", fault_stats.sfs_stopped_faulting ? "yes" : "no");
		if (expected_return_addr != 0ull) {
			T_ASSERT_GT(fault_stats.sfs_pages_faulted_in, 0, "faulted at least one page in");
			T_LOG("NOTE: successfully faulted in the pages");
		} else {
			T_LOG("NOTE: We were not able to fault the stack's pages back in");

			/* if we couldn't fault the pages back in, then at least verify that we tried */
			T_ASSERT_GT(fault_stats.sfs_time_spent_faulting, 0ull, "spent time trying to fault");
		}
	} else if ((flags & CHECK_FOR_KERNEL_THREADS) == 0) {
		T_ASSERT_NE(expected_return_addr, 0ull, "found child thread with recursions");
	}

	if (flags & CHECK_FOR_FAULT_STATS) {
		T_ASSERT_EQ(found_fault_stats, true, "found fault stats");
	}

	return ret;
}

void
child_init(void)
{
#if !TARGET_OS_OSX
	int freeze_state;
#endif /* !TARGET_OS_OSX */
	pid_t pid = getpid();
	char padding[16 * 1024];
	__asm__ volatile(""::"r"(padding));

	T_LOG("child pid: %d\n", pid);

#if !TARGET_OS_OSX
	/* allow us to be frozen */
	freeze_state = memorystatus_control(MEMORYSTATUS_CMD_GET_PROCESS_IS_FREEZABLE, pid, 0, NULL, 0);
	if (freeze_state == -1) {
		T_SKIP("This device doesn't have CONFIG_FREEZE enabled.");
	} else if (freeze_state == 0) {
		T_LOG("CHILD was found to be UNFREEZABLE, enabling freezing.");
		memorystatus_control(MEMORYSTATUS_CMD_SET_PROCESS_IS_FREEZABLE, pid, 1, NULL, 0);
		freeze_state = memorystatus_control(MEMORYSTATUS_CMD_GET_PROCESS_IS_FREEZABLE, pid, 0, NULL, 0);
		T_ASSERT_EQ(freeze_state, 1, "successfully set freezeability");
	}
#else
	T_LOG("Cannot change freezeability as freezing is only available on embedded devices");
#endif /* !TARGET_OS_OSX */

	/* 
	 * recurse a bunch of times to generate predictable data in the stackshot,
	 * then send SIGUSR1 to the parent to let it know that we are done.
	 */
	child_recurse(RECURSIONS, 0, ^{
		kill(getppid(), SIGUSR1);
	});

	T_ASSERT_FAIL("child_recurse returned, but it must not?");
}

void
parent_helper_singleproc(int spin)
{
	dispatch_semaphore_t child_done_sema = dispatch_semaphore_create(0);
	dispatch_queue_t dq = dispatch_queue_create("com.apple.stackshot_accuracy.basic_sp", NULL);
	void *stackshot_config;

	dispatch_async(dq, ^{
		char padding[16 * 1024];
		__asm__ volatile(""::"r"(padding));

		child_recurse(RECURSIONS, spin, ^{
			dispatch_semaphore_signal(child_done_sema);
		});
	});

	dispatch_semaphore_wait(child_done_sema, DISPATCH_TIME_FOREVER);
	T_LOG("done waiting for child");

	/* take the stackshot and parse it */
	stackshot_config = take_stackshot(getpid(), 0, 0);

	/* check that the stackshot has the stack frames */
	check_stackshot(stackshot_config, 0);

	T_LOG("done!");
}

T_DECL(basic, "test that no-fault stackshot works correctly")
{
	char path[PATH_MAX];
	uint32_t path_size = sizeof(path);
	char *args[] = { path, "-n", "simple_child_process", NULL };
	dispatch_queue_t dq = dispatch_queue_create("com.apple.stackshot_accuracy.basic", NULL);
	dispatch_semaphore_t child_done_sema = dispatch_semaphore_create(0);
	dispatch_source_t child_sig_src;
	void *stackshot_config;

	current_scenario_name = __func__;

	T_LOG("parent pid: %d\n", getpid());
	T_QUIET; T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");

	/* setup signal handling */
	signal(SIGUSR1, SIG_IGN);
	child_sig_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, dq);
	dispatch_source_set_event_handler(child_sig_src, ^{
		dispatch_semaphore_signal(child_done_sema);
	});
	dispatch_activate(child_sig_src);

	/* create the child process */
	T_ASSERT_POSIX_SUCCESS(dt_launch_tool(&child_pid, args, false, NULL, NULL), "child launched");
	T_ATEND(kill_children);

	/* wait until the child has recursed enough */
	dispatch_semaphore_wait(child_done_sema, DISPATCH_TIME_FOREVER);

	T_LOG("child finished, parent executing");

	/* take the stackshot and parse it */
	stackshot_config = take_stackshot(child_pid, 0, 0);

	/* check that the stackshot has the stack frames */
	check_stackshot(stackshot_config, 0);	

	T_LOG("all done, killing child");

	/* tell the child to quit */
	T_ASSERT_POSIX_SUCCESS(kill(child_pid, SIGTERM), "killed child");
}

T_DECL(basic_singleproc, "test that no-fault stackshot works correctly in single process setting")
{
	current_scenario_name = __func__;
	parent_helper_singleproc(0);
}

T_DECL(basic_singleproc_spin, "test that no-fault stackshot works correctly in single process setting with spinning")
{
	current_scenario_name = __func__;
	parent_helper_singleproc(1);
}

T_DECL(fault, "test that faulting stackshots work correctly")
{
	dispatch_queue_t dq = dispatch_queue_create("com.apple.stackshot_fault_accuracy", NULL);
	dispatch_source_t child_sig_src;
	dispatch_semaphore_t child_done_sema = dispatch_semaphore_create(0);
	void *stackshot_config;
	int oldftm, newval = 1, freeze_enabled, oldratio, newratio = 0;
	size_t oldlen = sizeof(oldftm), fe_len = sizeof(freeze_enabled), ratiolen = sizeof(oldratio);
	char path[PATH_MAX];
	uint32_t path_size = sizeof(path);
	char *args[] = { path, "-n", "simple_child_process", NULL };

	current_scenario_name = __func__;
	T_QUIET; T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");

#if TARGET_OS_OSX
	T_SKIP("freezing is not available on macOS");
#endif /* TARGET_OS_OSX */

	/* Try checking if freezing is enabled at all */
	if (sysctlbyname("vm.freeze_enabled", &freeze_enabled, &fe_len, NULL, 0) == -1) {
		if (errno == ENOENT) {
			T_SKIP("This device doesn't have CONFIG_FREEZE enabled.");
		} else {
			T_FAIL("failed to query vm.freeze_enabled, errno: %d", errno);
		}
	}

	if (!freeze_enabled) {
		T_SKIP("Freeze is not enabled, skipping test.");
	}

	/* signal handling */
	signal(SIGUSR1, SIG_IGN);
	child_sig_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, dq);
	dispatch_source_set_event_handler(child_sig_src, ^{
		dispatch_semaphore_signal(child_done_sema);
	});
	dispatch_activate(child_sig_src);

	T_ASSERT_POSIX_SUCCESS(dt_launch_tool(&child_pid, args, false, NULL, NULL), "child launched");
	T_ATEND(kill_children);

	dispatch_semaphore_wait(child_done_sema, DISPATCH_TIME_FOREVER);

	/* keep processes in memory */
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.memorystatus_freeze_to_memory", &oldftm, &oldlen, &newval, sizeof(newval)),
			"disabled freezing to disk");

	/* set the ratio to zero */
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.memorystatus_freeze_private_shared_pages_ratio", &oldratio, &ratiolen, &newratio, sizeof(newratio)), "disabled private:shared ratio checking");

	/* freeze the child */
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.memorystatus_freeze", NULL, 0, &child_pid, sizeof(child_pid)),
			"froze child");

	/* Sleep to allow the compressor to finish compressing the child */
	sleep(5);

	/* take the stackshot and parse it */
	stackshot_config = take_stackshot(child_pid, STACKSHOT_ENABLE_BT_FAULTING | STACKSHOT_ENABLE_UUID_FAULTING, 0);

	/* check that the stackshot has the stack frames */
	check_stackshot(stackshot_config, CHECK_FOR_FAULT_STATS);

	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.memorystatus_freeze_to_memory", NULL, 0, &oldftm, sizeof(oldftm)),
			"reset freezing to disk");

	/* reset the private:shared ratio */
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.memorystatus_freeze_private_shared_pages_ratio", NULL, 0, &oldratio, sizeof(oldratio)), "reset private:shared ratio");

	T_LOG("all done, killing child");

	/* tell the child to quit */
	T_ASSERT_POSIX_SUCCESS(kill(child_pid, SIGTERM), "killed child");
}

T_DECL(fault_singleproc, "test that faulting stackshots work correctly in a single process setting")
{
	dispatch_semaphore_t child_done_sema = dispatch_semaphore_create(0);
	dispatch_queue_t dq = dispatch_queue_create("com.apple.stackshot_accuracy.fault_sp", NULL);
	void *stackshot_config;
	__block pthread_t child_thread;
	char *child_stack;
	size_t child_stacklen;

#if !TARGET_OS_OSX
	T_SKIP("madvise(..., ..., MADV_PAGEOUT) is not available on embedded platforms");
#endif /* !TARGET_OS_OSX */

	dispatch_async(dq, ^{
		char padding[16 * 1024];
		__asm__ volatile(""::"r"(padding));

		child_recurse(RECURSIONS, 0, ^{
			child_thread = pthread_self();
			dispatch_semaphore_signal(child_done_sema);
		});
	});

	dispatch_semaphore_wait(child_done_sema, DISPATCH_TIME_FOREVER);
	T_LOG("done waiting for child");

	child_stack = pthread_get_stackaddr_np(child_thread);
	child_stacklen = pthread_get_stacksize_np(child_thread);
	child_stack -= child_stacklen;
	T_LOG("child stack: [0x%p - 0x%p]: 0x%zu bytes", (void *)child_stack,
			(void *)(child_stack + child_stacklen), child_stacklen);

	/* paging out the child */
	T_ASSERT_POSIX_SUCCESS(madvise(child_stack, child_stacklen, MADV_PAGEOUT), "paged out via madvise(2) the child stack");

	/* take the stackshot and parse it */
	stackshot_config = take_stackshot(getpid(), STACKSHOT_ENABLE_BT_FAULTING | STACKSHOT_ENABLE_UUID_FAULTING, 0);

	/* check that the stackshot has the stack frames */
	check_stackshot(stackshot_config, CHECK_FOR_FAULT_STATS);

	T_LOG("done!");
}

T_DECL(zombie, "test that threads wedged in the kernel can be stackshot'd")
{
	dispatch_queue_t dq = dispatch_queue_create("com.apple.stackshot_accuracy.zombie", NULL);
	dispatch_semaphore_t child_done_sema = dispatch_semaphore_create(0);
	dispatch_source_t child_sig_src;
	void *stackshot_config;
	char path[PATH_MAX];
	uint32_t path_size = sizeof(path);
	char *args[] = { path, "-n", "sid_child_process", NULL };

	current_scenario_name = __func__;
	T_QUIET; T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");

	T_LOG("parent pid: %d\n", getpid());

	/* setup signal handling */
	signal(SIGUSR1, SIG_IGN);
	child_sig_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, dq);
	dispatch_source_set_event_handler(child_sig_src, ^{
		dispatch_semaphore_signal(child_done_sema);
	});
	dispatch_activate(child_sig_src);

	/* create the child process */
	T_ASSERT_POSIX_SUCCESS(dt_launch_tool(&child_pid, args, false, NULL, NULL), "child launched");
	T_ATEND(kill_children);

	/* wait until the child has recursed enough */
	dispatch_semaphore_wait(child_done_sema, DISPATCH_TIME_FOREVER);

	T_LOG("child finished, parent executing. invoking jetsam");

	T_ASSERT_POSIX_SUCCESS(memorystatus_control(MEMORYSTATUS_CMD_TEST_JETSAM, child_pid, 0, 0, 0),
			"jetsam'd the child");

	/* Sleep to allow the target process to become zombified */
	sleep(1);

	/* take the stackshot and parse it */
	stackshot_config = take_stackshot(child_pid, 0, 0);

	/* check that the stackshot has the stack frames */
	check_stackshot(stackshot_config, CHECK_FOR_KERNEL_THREADS);

	T_LOG("all done, unwedging and killing child");

	int v = 1;
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.unwedge_thread", NULL, NULL, &v, sizeof(v)),
			"unwedged child");

	/* tell the child to quit */
	T_ASSERT_POSIX_SUCCESS(kill(child_pid, SIGTERM), "killed child");
}

#include <stdio.h>
#include <stdlib.h>

#include <darwintest.h>
#include <darwintest_utils.h>

#include <dispatch/dispatch.h>
#include <kern/debug.h>
#include <libproc.h>
#include <mach-o/dyld.h>
#include <sys/syscall.h>
#include <sys/stackshot.h>
#include <spawn.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.stackshot"),
	T_META_CHECK_LEAKS(false),
	T_META_ASROOT(true)
	);

#define TEST_DURATION_NS (60 * NSEC_PER_SEC)

#define REAP_INTERVAL 10

static void*
loop(__attribute__ ((unused)) void *arg)
{
	exit(0);
}

T_HELPER_DECL(spawn_children_helper, "spawn_children helper")
{
	pthread_t pthread;

	T_QUIET; T_ASSERT_POSIX_ZERO(pthread_create(&pthread, NULL, loop, NULL), "pthread_create");

	while (1) {
		;
	}
}

static void
take_stackshot(void)
{
	uint32_t stackshot_flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS |
	    STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT);

	void *config = stackshot_config_create();
	T_QUIET; T_ASSERT_NOTNULL(config, "created stackshot config");

	int ret = stackshot_config_set_flags(config, stackshot_flags);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "set flags on stackshot config");

	int retries_remaining = 5;

retry:
	ret = stackshot_capture_with_config(config);

	if (ret == EBUSY || ret == ETIMEDOUT) {
		if (retries_remaining > 0) {
			retries_remaining--;
			goto retry;
		} else {
			T_QUIET; T_ASSERT_POSIX_ZERO(ret,
			    "called stackshot_capture_with_config (no retries remaining)");
		}
	} else {
		T_QUIET; T_ASSERT_POSIX_ZERO(ret, "called stackshot_capture_with_config");
	}

	ret = stackshot_config_dealloc(config);
	T_QUIET; T_EXPECT_POSIX_ZERO(ret, "deallocated stackshot config");
}

T_DECL(stackshot_spawn_exit, "tests taking many stackshots while children processes are spawning+exiting", T_META_TIMEOUT(120))
{
	char path[PATH_MAX];
	uint32_t path_size = sizeof(path);
	T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");
	char *args[] = { path, "-n", "spawn_children_helper", NULL };

	uint64_t stop_time = clock_gettime_nsec_np(CLOCK_UPTIME_RAW) + TEST_DURATION_NS;

	dispatch_queue_t stackshot_queue = dispatch_queue_create("stackshot_queue", NULL);
	dispatch_async(stackshot_queue, ^(void) {
		int num_stackshots = 0;

		while (1) {
		        take_stackshot();
		        num_stackshots++;
		        if ((num_stackshots % 100) == 0) {
		                T_LOG("completed %d stackshots", num_stackshots);
			}

		        // Sleep between each stackshot
		        usleep(100);
		}
	});

	// <rdar://problem/39739547> META option for T_HELPER_DECL to not output test begin on start
	posix_spawn_file_actions_t actions;
	T_QUIET; T_ASSERT_POSIX_SUCCESS(posix_spawn_file_actions_init(&actions), "create spawn actions");
	T_QUIET; T_ASSERT_POSIX_SUCCESS(posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0),
	    "set stdout of child to NULL");

	int children_unreaped = 0, status;
	uint64_t iterations_completed = 0;
	while (clock_gettime_nsec_np(CLOCK_UPTIME_RAW) < stop_time) {
		pid_t pid;

		int sp_ret = posix_spawn(&pid, args[0], &actions, NULL, args, NULL);
		T_QUIET; T_ASSERT_POSIX_ZERO(sp_ret, "spawned process '%s' with PID %d", args[0], pid);

		children_unreaped++;

		if (children_unreaped >= REAP_INTERVAL) {
			while (children_unreaped) {
				T_QUIET; T_ASSERT_POSIX_SUCCESS(waitpid(-1, &status, 0), "waitpid returned child pid");
				children_unreaped--;
			}
		}

		if ((iterations_completed % 100) == 0) {
			T_LOG("spawned %llu children thus far", iterations_completed);
		}
		iterations_completed++;
	}

	while (children_unreaped) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(waitpid(-1, &status, 0), "waitpid returned child pid");
		children_unreaped--;
	}
}

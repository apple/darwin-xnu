#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <spawn.h>
#include <spawn_private.h>

#include <sys/sysctl.h>
#include <sys/errno.h>
#include <sys/kern_memorystatus.h>

#include <crt_externs.h>
#include <mach-o/dyld.h>
#include <darwintest.h>
#include <darwintest_utils.h>

#include "memorystatus_assertion_helpers.h"

#define MAX_TASK_MEM_ENTITLED "kern.entitled_max_task_pmem"
#define MAX_TASK_MEM "kern.max_task_pmem"
#define MAX_TASK_MEM_ENTITLED_VALUE (3 * (1 << 10))

#if ENTITLED
#define TESTNAME entitlement_increased_memory_limit_entitled
#else /* ENTITLED */
#define TESTNAME entitlement_increased_memory_limit_unentitled
#endif /* ENTITLED */

T_GLOBAL_META(T_META_NAMESPACE("xnu.vm"));

static int32_t old_entitled_max_task_pmem = 0;

static void
reset_old_entitled_max_task_mem()
{
	int ret;
	size_t size_old_entitled_max_task_pmem = sizeof(old_entitled_max_task_pmem);
	// Use sysctl to change entitled limit
	ret = sysctlbyname(MAX_TASK_MEM_ENTITLED, NULL, 0, &old_entitled_max_task_pmem, size_old_entitled_max_task_pmem);
}

T_HELPER_DECL(child, "Child") {
	// Doesn't do anything. Will start suspended
	// so that its parent can check its memlimits
	// and then kill it.
	T_PASS("Child exiting");
}

static pid_t
spawn_child_with_memlimit(int32_t memlimit)
{
	posix_spawnattr_t attr;
	int ret;
	char **args;
	char testpath[PATH_MAX];
	uint32_t testpath_buf_size;
	pid_t pid;

	ret = posix_spawnattr_init(&attr);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_init");

	testpath_buf_size = sizeof(testpath);
	ret = _NSGetExecutablePath(testpath, &testpath_buf_size);
	T_ASSERT_POSIX_ZERO(ret, "_NSGetExecutablePath");
	T_LOG("Executable path: %s", testpath);
	args = (char *[]){
		testpath,
		"-n",
		"child",
		NULL
	};

	ret = posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_setflags() failed");
	ret = posix_spawnattr_setjetsam_ext(&attr,
	    0, JETSAM_PRIORITY_FOREGROUND, memlimit, memlimit);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_setjetsam_ext");
	ret = posix_spawn(&pid, testpath, NULL, &attr, args, *_NSGetEnviron());
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "posix_spawn() failed");

	return pid;
}


T_DECL(TESTNAME,
    "Verify that entitled processes can allocate up to the entitled memory limit",
    T_META_CHECK_LEAKS(false))
{
	int32_t entitled_max_task_pmem = MAX_TASK_MEM_ENTITLED_VALUE, max_task_pmem = 0, expected_limit;
	size_t size_entitled_max_task_pmem = sizeof(entitled_max_task_pmem);
	size_t size_old_entitled_max_task_pmem = sizeof(old_entitled_max_task_pmem);
	size_t size_max_task_pmem = sizeof(max_task_pmem);
	int status;
	pid_t pid, rc;
	bool signaled;
	memorystatus_memlimit_properties2_t mmprops;

	int ret = 0;

	// Get the unentitled limit
	ret = sysctlbyname(MAX_TASK_MEM, &max_task_pmem, &size_max_task_pmem, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "call sysctlbyname to get max task physical memory.");
	if (max_task_pmem >= MAX_TASK_MEM_ENTITLED_VALUE) {
		T_SKIP("max_task_pmem (%lld) is larger than entitled value (%lld). Skipping test on this device.", max_task_pmem, MAX_TASK_MEM_ENTITLED_VALUE);
	}

	// Use sysctl to change entitled limit
	ret = sysctlbyname(MAX_TASK_MEM_ENTITLED, &old_entitled_max_task_pmem, &size_old_entitled_max_task_pmem, &entitled_max_task_pmem, size_entitled_max_task_pmem);
	T_ASSERT_POSIX_SUCCESS(ret, "call sysctlbyname to set entitled hardware mem size.");

	T_ATEND(reset_old_entitled_max_task_mem);

	/*
	 * Spawn child with the normal task limit (just as launchd does for an app)
	 * The child will start suspended, so we can check its memlimit.
	 */

	pid = spawn_child_with_memlimit(max_task_pmem);
	T_ASSERT_POSIX_SUCCESS(pid, "spawn child with task limit");

	// Check its memlimt
	ret = memorystatus_control(MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES, pid, 0, &mmprops, sizeof(mmprops));
	T_ASSERT_POSIX_SUCCESS(ret, "memorystatus_control");
#if ENTITLED
	expected_limit = MAX_TASK_MEM_ENTITLED_VALUE;
#else /* ENTITLED */
	expected_limit = max_task_pmem;
#endif /* ENTITLED */
	T_ASSERT_EQ(mmprops.v1.memlimit_active, expected_limit, "active limit");
	T_ASSERT_EQ(mmprops.v1.memlimit_inactive, expected_limit, "inactive limit");

	// Resume the child. It should exit immediately.
	ret = kill(pid, SIGCONT);
	T_ASSERT_POSIX_SUCCESS(ret, "kill child");

	// Check child's exit code.
	while (true) {
		rc = waitpid(pid, &status, 0);
		if (rc == -1 && errno == EINTR) {
			continue;
		}
		T_ASSERT_EQ(rc, pid, "waitpid");
		signaled = WIFSIGNALED(status);
		T_ASSERT_FALSE(signaled, "Child exited cleanly");
		ret = WEXITSTATUS(status);
		T_ASSERT_EQ(ret, 0, "child exited with code 0.");
		break;
	}
}

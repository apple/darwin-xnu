#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>

#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(false));

static int after_regions = 0;

/*
 * No system(3c) on watchOS, so provide our own.
 */
static int
my_system(const char *command)
{
	pid_t pid;
	int status = 0;
	const char *argv[] = {
		"/bin/sh",
		"-c",
		command,
		NULL
	};

	if (dt_launch_tool(&pid, (char **)(void *)argv, FALSE, NULL, NULL)) {
		return -1;
	}
	sleep(2); /* let the child start running */

	size_t size = sizeof(after_regions);
	int ret = sysctlbyname("vm.shared_region_pager_count", &after_regions, &size, NULL, 0);
	T_QUIET; T_EXPECT_POSIX_SUCCESS(ret, "get shared_region_pager_count after");

	if (!dt_waitpid(pid, &status, NULL, 30)) {
		if (status != 0) {
			return status;
		}
		return -1;
	}
	return status;
}

/*
 * If shared regions by entitlement was not originally active, turn it back off.
 */
static int orig_setting = 0;
static void
cleanup(void)
{
	int ret;
	int off = 0;
	size_t size_off = sizeof(off);

	if (orig_setting == 0) {
		ret = sysctlbyname("vm.vm_shared_region_by_entitlement", NULL, NULL, &off, size_off);
		T_QUIET; T_EXPECT_POSIX_SUCCESS(ret, "turning sysctl back off");
	}
}

/*
 * This test:
 * - looks at the number of shared region pagers,
 * - launches a helper app that has entitlement for unique signing
 * - gets the number of shared region pagers again.
 * It expects to see additional shared region pager(s) to exist.
 *
 */
T_DECL(sr_entitlement, "shared region by entitlement test")
{
	int ret;
	size_t size;
	int before_regions = 0;
	int on = 1;
	size_t size_on = sizeof(on);

#if !__arm64e__
	T_SKIP("No pointer authentication support");
#endif

	/*
	 * Check if the sysctl vm_shared_region_by_entitlement exists and if so make
	 * sure it is set.
	 */
	size = sizeof(orig_setting);
	ret = sysctlbyname("vm.vm_shared_region_by_entitlement", &orig_setting, &size, &on, size_on);
	if (ret != 0) {
		T_SKIP("No pointer authentication support");
	}

	T_ATEND(cleanup);

	size = sizeof(before_regions);
	ret = sysctlbyname("vm.shared_region_pager_count", &before_regions, &size, NULL, 0);
	T_QUIET; T_EXPECT_POSIX_SUCCESS(ret, "get shared_region_pager_count before");
	T_QUIET; T_EXPECT_GE_INT(before_regions, 1, "invalid before number of regions");

	ret = my_system("./sr_entitlement_helper");
	if (ret != 0) {
		T_ASSERT_FAIL("Couldn't run helper first time ret = %d", ret);
	}

	T_EXPECT_GT_INT(after_regions, before_regions, "expected additional SR pagers after running helper");
}

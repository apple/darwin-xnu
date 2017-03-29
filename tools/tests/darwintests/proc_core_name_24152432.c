#include <darwintest.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <TargetConditionals.h>
#include <unistd.h>

#define BUFFLEN 2048
#define EVILLEN 19

static const char corefile_ctl[]     = "kern.corefile";
static const char coredump_ctl[]     = "kern.coredump";
/* The default coredump location if the kern.coredump ctl is invalid */
static const char default_dump_fmt[] = "/cores/core.%d";
/* The coredump location when we set kern.coredump ctl to something valid */
static const char valid_dump_fmt[]   = "/cores/test-core.%d";

/* /cores/core.%(null), then BORK immediately after. */
static char evil[] = {'/', 'c', 'o', 'r', 'e', 's', '/', 'c', 'o', 'r', 'e', '.', '%', '\0', 'B', 'O', 'R', 'K', '\0'};
/* A valid coredump location to test. */
static char valid_dump_loc[]   = "/cores/test-core.%P";

static const struct rlimit lim_infty = {
	RLIM_INFINITY,
	RLIM_INFINITY
};

#if TARGET_OS_OSX
static int fork_and_wait_for_segfault(void);

static int fork_and_wait_for_segfault() {
	int pid, ret;
	pid = fork();
	if (pid == 0) {
		unsigned int *ptr = NULL; /* Cause a segfault so that we get a coredump */
		*ptr = 0xdeadd00d;
		T_FAIL("Expected segmentation fault on write to NULL pointer");
	}
	T_ASSERT_TRUE(pid != -1, "Checking fork success in parent");

	ret = wait(NULL);
	T_ASSERT_TRUE(ret != -1, "Waited for child to segfault and dump core");
	return pid;
}
#endif

T_DECL(
    proc_core_name_24152432,
    "Tests behavior of core dump when kern.corefile ends in %, e.g., /cores/core.%",
    T_META_ASROOT(true))
{
#if TARGET_OS_OSX
	int ret, pid;
	int enable_core_dump = 1;
	char buf[BUFFLEN];
	memset(buf, 0, BUFFLEN);
	size_t oldlen = BUFFLEN;

	ret = sysctlbyname(coredump_ctl, buf, &oldlen, &enable_core_dump, sizeof(int));
	T_ASSERT_POSIX_SUCCESS(ret, "sysctl: enable core dumps");
	memset(buf, 0, BUFFLEN);
	oldlen = BUFFLEN;

	ret = setrlimit(RLIMIT_CORE, &lim_infty);
	T_ASSERT_POSIX_SUCCESS(ret, "setrlimit: remove limit on maximum coredump size");

	ret = sysctlbyname(corefile_ctl, buf, &oldlen, evil, EVILLEN);
	T_ASSERT_POSIX_SUCCESS(ret, "sysctl: set bad core dump location, old value was %s", buf);
	memset(buf, 0, BUFFLEN);
	oldlen = BUFFLEN;

	pid = fork_and_wait_for_segfault();

	snprintf(buf, BUFFLEN, default_dump_fmt, pid);
	ret = remove(buf);
	T_ASSERT_TRUE(ret != -1, "Removing coredump file (should be in fallback location)");
	memset(buf, 0, BUFFLEN);

	ret = sysctlbyname(corefile_ctl, buf, &oldlen, valid_dump_loc, strlen(valid_dump_loc));
	T_ASSERT_POSIX_SUCCESS(ret, "sysctl: set valid core dump location, old value was %s", buf);
	memset(buf, 0, BUFFLEN);

	pid = fork_and_wait_for_segfault();

	snprintf(buf, BUFFLEN, valid_dump_fmt, pid);
	ret = remove(buf);
	T_ASSERT_TRUE(ret != -1, "Removing coredump file (should be in valid location)");
#else
	T_LOG("proc_core_name appears in OS X only, skipping test.");
#endif
	T_PASS("proc_core_name_24152432 PASSED");
}

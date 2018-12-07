#include <darwintest.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/sysctl.h>
#include <sys/resource.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <TargetConditionals.h>
#include <unistd.h>
#include <dirent.h>

#define BUFFLEN  2048
#define EVILLEN  19
#define TIMEOUT  420 /* Timeout in seconds to wait for coredumps to appear */

static const char corefile_ctl[]     = "kern.corefile";
static const char coredump_ctl[]     = "kern.coredump";
/* The directory where coredumps will be */
static const char dump_dir[]	     = "/cores";
/* The default coredump location if the kern.coredump ctl is invalid */
static const char default_dump_fmt[] = "/cores/core.%d";
/* The coredump location when we set kern.coredump ctl to something valid */
static const char valid_dump_fmt[]   = "/cores/test-core.%d";
static const char ls_path[]          = "/bin/ls";

/* /cores/core.%(null), then BORK immediately after. */
static char evil[] = "/cores/core.%\0BORK";
/* A valid coredump location to test. */
static char valid_dump_loc[]   = "/cores/test-core.%P";

static const struct rlimit lim_infty = {
	RLIM_INFINITY,
	RLIM_INFINITY
};

static volatile int stop_looking = 0;

static const struct timespec timeout = {
	TIMEOUT,
	0
};

#if TARGET_OS_OSX
static int fork_and_wait_for_segfault(void);

static void sigalrm_handler(int sig)
{
	(void)sig;
	stop_looking = 1;
	return;
}

static void list_coredump_files()
{
	int ret;
	char buf[BUFFLEN] = { 0 };

	T_LOG("Contents of %s:", dump_dir);
	snprintf(buf, BUFFLEN, "%s %s", ls_path, dump_dir);
	ret = system(buf);
	T_ASSERT_POSIX_SUCCESS(ret, "Listing contents of cores directory");
	return;
}

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

static int setup_coredump_kevent(struct kevent *kev, int dir)
{
	int ret;
	int kqfd;

	EV_SET(kev, dir, EVFILT_VNODE, EV_ADD, NOTE_WRITE, 0, NULL);
	kqfd = kqueue();
	T_ASSERT_POSIX_SUCCESS(kqfd, "kqueue: get kqueue for coredump monitoring");

	ret = kevent(kqfd, kev, 1, NULL, 0, NULL);
	T_ASSERT_POSIX_SUCCESS(ret, "kevent: setup directory monitoring for coredump");
	return kqfd;
}

static void look_for_coredump(const char *format, int pid, int kqfd, struct kevent *kev)
{
	int ret = 0;
	int i = 0;
	char buf[BUFFLEN];
	memset(buf, 0, BUFFLEN);
	/*
	 * Something else might touch this directory. If we get notified and don't see
	 * anything, try a few more times before failing.
	 */
	alarm(TIMEOUT);
	while (!stop_looking) {
		/* Wait for kevent to tell us the coredump folder was modified */
		ret = kevent(kqfd, NULL, 0, kev, 1, &timeout);
		T_ASSERT_POSIX_SUCCESS(ret, "kevent: Waiting for coredump to appear");

		snprintf(buf, BUFFLEN, format, pid);
		ret = remove(buf);

		if (ret != -1)
			break;

		T_LOG("Couldn't find coredump file (try #%d).", i+1);
		i++;
	}
	alarm(0);

	if (ret == -1) {
		/* Couldn't find the coredump -- list contents of /cores */
		list_coredump_files();
	}
	T_ASSERT_POSIX_SUCCESS(ret, "Removing coredump file (should be at %s)", buf);
}

static void sysctl_enable_coredumps(void)
{
	int ret;
	int enable_core_dump = 1;
	size_t oldlen = BUFFLEN;
	char buf[BUFFLEN];
	memset(buf, 0, BUFFLEN);

	ret = sysctlbyname(coredump_ctl, buf, &oldlen, &enable_core_dump, sizeof(int));
	T_ASSERT_POSIX_SUCCESS(ret, "sysctl: enable core dumps");

	ret = setrlimit(RLIMIT_CORE, &lim_infty);
	T_ASSERT_POSIX_SUCCESS(ret, "setrlimit: remove limit on maximum coredump size");
}
#endif

T_DECL(
	proc_core_name_24152432,
	"Tests behavior of core dump when kern.corefile ends in %, e.g., /cores/core.%",
	T_META_ASROOT(true),
	T_META_IGNORECRASHES("proc_core_name_24152432.*"))
{
#if TARGET_OS_OSX
	DIR *dirp;
	int ret, pid, dir;
	char buf[BUFFLEN];
	memset(buf, 0, BUFFLEN);
	size_t oldlen = BUFFLEN;
	struct kevent kev;
	sig_t sig;
	int kqfd;

	sig = signal(SIGALRM, sigalrm_handler);
	T_WITH_ERRNO; T_EXPECT_NE(sig, SIG_ERR, "signal: set sigalrm handler");

	dirp = opendir(dump_dir);
	T_ASSERT_NOTNULL(dirp, "opendir: opening coredump directory");
	dir = dirfd(dirp);
	T_ASSERT_POSIX_SUCCESS(dir, "dirfd: getting file descriptor for coredump directory");
	kqfd = setup_coredump_kevent(&kev, dir);

	sysctl_enable_coredumps();

	ret = sysctlbyname(corefile_ctl, buf, &oldlen, evil, EVILLEN);
	T_ASSERT_POSIX_SUCCESS(ret, "sysctl: set bad core dump location, old value was %s", buf);
	memset(buf, 0, BUFFLEN);
	oldlen = BUFFLEN;

	pid = fork_and_wait_for_segfault();
	look_for_coredump(default_dump_fmt, pid, kqfd, &kev);

	ret = sysctlbyname(corefile_ctl, buf, &oldlen, valid_dump_loc, strlen(valid_dump_loc));
	T_ASSERT_POSIX_SUCCESS(ret, "sysctl: set valid core dump location, old value was %s", buf);
	memset(buf, 0, BUFFLEN);

	pid = fork_and_wait_for_segfault();
	look_for_coredump(valid_dump_fmt, pid, kqfd, &kev);

	closedir(dirp);
	close(kqfd);
#else
	T_LOG("proc_core_name appears in OS X only, skipping test.");
#endif
	T_PASS("proc_core_name_24152432 PASSED");
}

#include <darwintest.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syslimits.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

T_GLOBAL_META(T_META_CHECK_LEAKS(false));

T_DECL(settimeofday, "check setting and getting time of day",
    T_META_ASROOT(true))
{
	struct timeval origtime = {};
	struct timezone origtz = {};
	int ret = gettimeofday(&origtime, &origtz);
	T_ASSERT_POSIX_SUCCESS(ret, "get current time with gettimeofday(2)");

#if TARGET_OS_BRIDGE
	/*
	 * bridgeOS is not allowed to set the time -- only the macOS side can.
	 */
	T_SKIP("bridgeOS is not allowed to call settimeofday(2)");
#endif /* TARGET_OS_BRIDGE */

	struct timeval newtime = {};
	newtime = origtime;
	newtime.tv_sec -= 60;
	ret = settimeofday(&newtime, NULL);
	T_ASSERT_POSIX_SUCCESS(ret,
	    "set time back 60 seconds with settimeofday(2)");

	ret = gettimeofday(&newtime, NULL);
	T_ASSERT_POSIX_SUCCESS(ret, "get new time with gettimeofday(2)");

	T_ASSERT_GT(origtime.tv_sec, newtime.tv_sec,
	    "new time should be before original time");

	newtime = origtime;
	newtime.tv_sec += 1;
	ret = settimeofday(&newtime, NULL);
	T_ASSERT_POSIX_SUCCESS(ret,
	    "set time close to original value with gettimeofday(2)");
}

static char tmppath[PATH_MAX] = "";

static void
cleanup_tmpfile(void)
{
	if (tmppath[0] != '\0') {
		unlink(tmppath);
	}
}

static int
create_tmpfile(void)
{
	const char *tmpdir = getenv("TMPDIR");
	strlcat(tmppath, tmpdir ? tmpdir : "/tmp", sizeof(tmppath));
	strlcat(tmppath, "xnu_quick_test.XXXXX", sizeof(tmppath));
	int fd = mkstemp(tmppath);
	T_ASSERT_POSIX_SUCCESS(fd, "created temporary file at %s", tmppath);
	T_ATEND(cleanup_tmpfile);
	return fd;
}

T_DECL(futimes, "check that futimes updates file times",
    T_META_RUN_CONCURRENTLY(true))
{
	int tmpfd = create_tmpfile();

	struct stat stbuf = {};
	int ret = fstat(tmpfd, &stbuf);
	T_ASSERT_POSIX_SUCCESS(ret, "get file metadata with fstat(2)");
	struct timeval amtimes[2] = {};
	TIMESPEC_TO_TIMEVAL(&amtimes[0], &stbuf.st_atimespec);
	TIMESPEC_TO_TIMEVAL(&amtimes[1], &stbuf.st_mtimespec);

	amtimes[0].tv_sec -= 120;
	amtimes[1].tv_sec -= 120;

	ret = futimes(tmpfd, amtimes);
	T_ASSERT_POSIX_SUCCESS(ret, "update file times with utimes(2)");

	ret = fstat(tmpfd, &stbuf);
	T_ASSERT_POSIX_SUCCESS(ret, "get file metadata after update with fstat(2)");
	struct timeval newamtimes[2] = {};
	TIMESPEC_TO_TIMEVAL(&newamtimes[0], &stbuf.st_atimespec);
	TIMESPEC_TO_TIMEVAL(&newamtimes[1], &stbuf.st_mtimespec);

	/*
	 * Reading the metadata shouldn't count as an access.
	 */
	T_ASSERT_EQ(amtimes[0].tv_sec, newamtimes[0].tv_sec,
	    "access time matches what was set");
	T_ASSERT_EQ(amtimes[1].tv_sec, newamtimes[1].tv_sec,
	    "modification time matches what was set");
}

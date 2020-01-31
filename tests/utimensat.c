#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <darwintest.h>
#include <darwintest_utils.h>

#define FILENAME "utimensat"

static const struct timespec tptr[][2] = {
	{ { 0x12345678, 987654321 }, { 0x15263748, 123456789 }, },

	{ { 0, UTIME_NOW }, { 0x15263748, 123456789 }, },
	{ { 0x12345678, 987654321 }, { 0, UTIME_NOW }, },
	{ { 0, UTIME_NOW }, { 0, UTIME_NOW }, },

	{ { 0, UTIME_OMIT }, { 0x15263748, 123456789 }, },
	{ { 0x12345678, 987654321 }, { 0, UTIME_OMIT }, },
	{ { 0, UTIME_OMIT }, { 0, UTIME_OMIT }, },

	{ { 0, UTIME_NOW }, { 0, UTIME_OMIT }, },
	{ { 0, UTIME_OMIT }, { 0, UTIME_NOW }, },
};

T_DECL(utimensat, "Try various versions of utimensat")
{
	T_SETUPBEGIN;
	T_ASSERT_POSIX_ZERO(chdir(dt_tmpdir()), NULL);
	// Skip the test if the current working directory is not on APFS.
	struct statfs sfs = { 0 };
	T_QUIET; T_ASSERT_POSIX_SUCCESS(statfs(".", &sfs), NULL);
	if (memcmp(&sfs.f_fstypename[0], "apfs", strlen("apfs")) != 0) {
		T_SKIP("utimensat is APFS-only, but working directory is non-APFS");
	}
	T_SETUPEND;

	struct stat pre_st, post_st;
	int fd;

	T_ASSERT_POSIX_SUCCESS((fd = open(FILENAME, O_CREAT | O_RDWR, 0644)), NULL);
	T_ASSERT_POSIX_ZERO(close(fd), NULL);

	for (size_t i = 0; i < sizeof(tptr) / sizeof(tptr[0]); i++) {
		T_LOG("=== {%ld, %ld} {%ld, %ld} ===",
		    tptr[i][0].tv_sec, tptr[i][0].tv_nsec,
		    tptr[i][1].tv_sec, tptr[i][1].tv_nsec);

		struct timespec now;
		clock_gettime(CLOCK_REALTIME, &now);

		T_ASSERT_POSIX_ZERO(stat(FILENAME, &pre_st), NULL);
		T_ASSERT_POSIX_ZERO(utimensat(AT_FDCWD, FILENAME, tptr[i], 0), NULL);
		T_ASSERT_POSIX_ZERO(stat(FILENAME, &post_st), NULL);

		if (tptr[i][0].tv_nsec == UTIME_NOW) {
			T_ASSERT_GE(post_st.st_atimespec.tv_sec, now.tv_sec, NULL);
		} else if (tptr[i][0].tv_nsec == UTIME_OMIT) {
			T_ASSERT_EQ(post_st.st_atimespec.tv_sec, pre_st.st_atimespec.tv_sec, NULL);
			T_ASSERT_EQ(post_st.st_atimespec.tv_nsec, pre_st.st_atimespec.tv_nsec, NULL);
		} else {
			T_ASSERT_EQ(post_st.st_atimespec.tv_sec, tptr[i][0].tv_sec, NULL);
			T_ASSERT_EQ(post_st.st_atimespec.tv_nsec, tptr[i][0].tv_nsec, NULL);
		}

		if (tptr[i][1].tv_nsec == UTIME_NOW) {
			T_ASSERT_GE(post_st.st_mtimespec.tv_sec, now.tv_sec, NULL);
		} else if (tptr[i][1].tv_nsec == UTIME_OMIT) {
			T_ASSERT_EQ(post_st.st_mtimespec.tv_sec, pre_st.st_mtimespec.tv_sec, NULL);
			T_ASSERT_EQ(post_st.st_mtimespec.tv_nsec, pre_st.st_mtimespec.tv_nsec, NULL);
		} else {
			T_ASSERT_EQ(post_st.st_mtimespec.tv_sec, tptr[i][1].tv_sec, NULL);
			T_ASSERT_EQ(post_st.st_mtimespec.tv_nsec, tptr[i][1].tv_nsec, NULL);
		}
	}
}

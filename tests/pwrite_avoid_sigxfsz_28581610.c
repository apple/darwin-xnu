/*
 * testname: pwrite_avoid_sigxfsz_28581610
 */

#include <darwintest.h>
#include <fcntl.h>
#include <limits.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#define TMP_FILE_PATH "/tmp/test_pwrite"

static sigjmp_buf xfsz_jmpbuf;

void xfsz_signal(int);

void
xfsz_signal(__unused int signo)
{
	siglongjmp(xfsz_jmpbuf, 1);
}

T_DECL(pwrite, "Tests avoiding SIGXFSZ with pwrite and odd offsets",
    T_META_ASROOT(true))
{
	int fd, x;
	off_t ret;
	struct stat f_stat;
	struct rlimit crl;
	static const int offs[] = { -1, -1 * 1024, -1 * 1024 * 16, -1 * 1024 * 1024 * 16, 0 };
	static unsigned char buffer[1048576];

	T_SETUPBEGIN;
	/* We expect zero SIGXFSZ signals because we have no file size limits */
	crl.rlim_cur = crl.rlim_max = RLIM_INFINITY;
	ret = setrlimit(RLIMIT_FSIZE, &crl);
	T_ASSERT_POSIX_SUCCESS(ret, "setting infinite file size limit");

	/* we just needed root to setup unlimited file size */
	remove(TMP_FILE_PATH);
	setuid(5000);

	/* We just want an empty regular file to test with */
	fd = open(TMP_FILE_PATH, O_RDWR | O_CREAT | O_EXCL, 0777);
	T_ASSERT_POSIX_SUCCESS(fd, "opening fd on temp file %s.", TMP_FILE_PATH);

	/* sanity check that this new file is really zero bytes in size */
	ret = fstat(fd, &f_stat);
	T_ASSERT_POSIX_SUCCESS(ret, "stat() fd on temp file.");
	T_ASSERT_TRUE(0 == f_stat.st_size, "ensure %s is empty", TMP_FILE_PATH);

	/* sanity check that ftruncate() considers negative offsets an error */
	for (x = 0; offs[x] != 0; x++) {
		ret = ftruncate(fd, offs[x]);
		T_ASSERT_TRUE(((ret == -1) && (errno == EINVAL)),
		    "negative offset %d", offs[x]);
	}

	T_SETUPEND;

	/* we want to get the EFBIG errno but without a SIGXFSZ signal */
	T_EXPECTFAIL;
	if (!sigsetjmp(xfsz_jmpbuf, 1)) {
		signal(SIGXFSZ, xfsz_signal);
		ret = pwrite(fd, buffer, sizeof buffer, LONG_MAX);
		T_ASSERT_TRUE(((ret == -1) && (errno == EFBIG)),
		    "large offset %d", 13);
	} else {
		signal(SIGXFSZ, SIG_DFL);
		T_FAIL("%s unexpected SIGXFSZ with offset %lX",
		    "<rdar://problem/28581610>", LONG_MAX);
	}

	/* Negative offsets are invalid, no SIGXFSZ signals required */
	for (x = 0; offs[x] != 0; x++) {
		/* only -1 gives the correct result */
		if (-1 != offs[x]) {
			T_EXPECTFAIL;
		}

		if (!sigsetjmp(xfsz_jmpbuf, 1)) {
			signal(SIGXFSZ, xfsz_signal);
			ret = pwrite(fd, buffer, sizeof buffer, offs[x]);
			T_ASSERT_TRUE(((ret == -1) && (errno == EINVAL)),
			    "negative offset %d", offs[x]);
		} else {
			signal(SIGXFSZ, SIG_DFL);
			T_FAIL("%s unexpected SIGXFSZ with negative offset %d",
			    "<rdar://problem/28581610>", offs[x]);
		}
	}

	remove(TMP_FILE_PATH);
}

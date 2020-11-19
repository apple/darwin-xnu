#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <darwintest.h>

static void
too_long(int ignored)
{
	T_ASSERT_FAIL("child readv is blocked");
}

T_DECL(pipe_read_infloop_55437634, "Infinite loop in pipe_read")
{
	int p[2];
	char c = 0;
	struct iovec iov = {
		.iov_base = &c,
		.iov_len = 0x100000000UL
	};
	pid_t child;
	int status = 0;

	T_SETUPBEGIN;
	/* create a pipe with some data in it: */
	T_ASSERT_POSIX_SUCCESS(pipe(p), NULL);
	T_ASSERT_POSIX_SUCCESS(write(p[1], "A", 1), NULL);
	T_SETUPEND;

	T_ASSERT_POSIX_SUCCESS(child = fork(), NULL);

	if (!child) {
		readv(p[0], &iov, 1);
		exit(0);
	}

	/*
	 * if the waitpid takes too long, the child is probably stuck in the
	 * infinite loop, so fail via too_long.
	 */
	T_ASSERT_NE(signal(SIGALRM, too_long), SIG_ERR, NULL);
	T_ASSERT_POSIX_SUCCESS(alarm(10), NULL);

	/* this will hang if the bug is there: */
	T_ASSERT_POSIX_SUCCESS(waitpid(child, &status, 0), NULL);

	/* expecting a clean, zero exit: */
	T_ASSERT_TRUE(WIFEXITED(status), NULL);
	T_ASSERT_EQ(WEXITSTATUS(status), 0, NULL);
}

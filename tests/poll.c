#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif
#include <darwintest.h>

#include <dispatch/dispatch.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <poll.h>
#include <stdint.h>
#include <unistd.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.poll"));

#define SLEEP_TIME_SECS 1
#define POLL_TIMEOUT_MS 1800
static_assert(POLL_TIMEOUT_MS > (SLEEP_TIME_SECS * 1000),
		"poll timeout should be longer than sleep time");

/*
 * This matches the behavior of other UNIXes, but is under-specified in POSIX.
 *
 * See <rdar://problem/28372390>.
 */
T_DECL(sleep_with_no_fds,
		"poll() called with no fds provided should act like sleep")
{
	uint64_t begin_time, sleep_time, poll_time;
	struct pollfd pfd = { 0 };

	begin_time = mach_absolute_time();
	sleep(SLEEP_TIME_SECS);
	sleep_time = mach_absolute_time() - begin_time;
	T_LOG("sleep(%d) ~= %llu mach absolute time units", SLEEP_TIME_SECS, sleep_time);

	begin_time = mach_absolute_time();
	T_ASSERT_POSIX_SUCCESS(poll(&pfd, 0, POLL_TIMEOUT_MS),
			"poll() with 0 events and timeout %d ms", POLL_TIMEOUT_MS);
	poll_time = mach_absolute_time() - begin_time;

	T_EXPECT_GT(poll_time, sleep_time,
			"poll(... %d) should wait longer than sleep(1)", POLL_TIMEOUT_MS);
}

#define LAUNCHD_PATH "/sbin/launchd"
#define PIPE_DIR_TIMEOUT_SECS 1

/*
 * See <rdar://problem/28539155>.
 */
T_DECL(directories,
		"poll() with directories should return an error")
{
	int file, dir, pipes[2];
	struct pollfd pfd[] = {
		{ .events = POLLIN },
		{ .events = POLLIN },
		{ .events = POLLIN },
	};

	file = open(LAUNCHD_PATH, O_RDONLY | O_NONBLOCK);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(file, "open(%s)", LAUNCHD_PATH);
	dir = open(".", O_RDONLY | O_NONBLOCK);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(dir, "open(\".\")");
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pipe(pipes), NULL);

	/* just directory */
	pfd[0].fd = dir;
	T_EXPECT_POSIX_SUCCESS(poll(pfd, 1, -1), "poll() with a directory");
	T_QUIET; T_EXPECT_TRUE(pfd[0].revents & POLLNVAL,
			"directory should be an invalid event");

	/* file and directory */
	pfd[0].fd = file; pfd[0].revents = 0;
	pfd[1].fd = dir; pfd[1].revents = 0;
	T_EXPECT_POSIX_SUCCESS(poll(pfd, 2, -1),
			"poll() with a file and directory");
	T_QUIET; T_EXPECT_TRUE(pfd[0].revents & POLLIN, "file should be readable");
	T_QUIET; T_EXPECT_TRUE(pfd[1].revents & POLLNVAL,
			"directory should be an invalid event");

	/* directory and file */
	pfd[0].fd = dir; pfd[0].revents = 0;
	pfd[1].fd = file; pfd[1].revents = 0;
	T_EXPECT_POSIX_SUCCESS(poll(pfd, 2, -1),
			"poll() with a directory and a file");
	T_QUIET; T_EXPECT_TRUE(pfd[0].revents & POLLNVAL,
			"directory should be an invalid event");
	T_QUIET; T_EXPECT_TRUE(pfd[1].revents & POLLIN, "file should be readable");

	/* file and pipe */
	pfd[0].fd = file; pfd[0].revents = 0;
	pfd[1].fd = pipes[0]; pfd[0].revents = 0;
	T_EXPECT_POSIX_SUCCESS(poll(pfd, 2, -1),
			"poll() with a file and pipe");
	T_QUIET; T_EXPECT_TRUE(pfd[0].revents & POLLIN, "file should be readable");
	T_QUIET; T_EXPECT_FALSE(pfd[1].revents & POLLIN,
			"pipe should not be readable");

	/* file, directory, and pipe */
	pfd[0].fd = file; pfd[0].revents = 0;
	pfd[1].fd = dir; pfd[1].revents = 0;
	pfd[2].fd = pipes[0]; pfd[2].revents = 0;
	T_EXPECT_POSIX_SUCCESS(poll(pfd, 3, -1),
			"poll() with a file, directory, and pipe");
	T_QUIET; T_EXPECT_TRUE(pfd[0].revents & POLLIN, "file should be readable");
	T_QUIET; T_EXPECT_TRUE(pfd[1].revents & POLLNVAL,
			"directory should be an invalid event");
	T_QUIET; T_EXPECT_FALSE(pfd[2].revents & POLLIN, "pipe should not be readable");

	/* directory and pipe */
	__block bool timed_out = true;
	pfd[0].fd = dir; pfd[0].revents = 0;
	pfd[1].fd = pipes[0]; pfd[1].revents = 0;
	dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
			PIPE_DIR_TIMEOUT_SECS * NSEC_PER_SEC),
			dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
		T_ASSERT_FALSE(timed_out, "poll timed out after %d seconds",
				PIPE_DIR_TIMEOUT_SECS);
	});

	T_EXPECT_POSIX_SUCCESS(poll(pfd, 3, -1),
			"poll() with a directory and pipe");
	timed_out = false;

	T_QUIET; T_EXPECT_TRUE(pfd[0].revents & POLLNVAL,
			"directory should be an invalid event");
	T_QUIET; T_EXPECT_FALSE(pfd[1].revents & POLLIN, "pipe should not be readable");
}

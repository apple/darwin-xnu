#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#include <sys/event.h>

#include <darwintest.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

/*
 * <rdar://problem/30231213> close() of kqueue FD races with kqueue_scan park
 *
 * When close concurrent with poll goes wrong, the close hangs
 * and the kevent never gets any more events.
 */

/* Both events should fire at about the same time */
static uint32_t timeout_ms = 10;

static void *
poll_kqueue(void *arg)
{
	int fd = (int)arg;

	struct kevent kev = {
		.filter = EVFILT_TIMER,
		.flags  = EV_ADD,
		.data   = timeout_ms,
	};

	int rv = kevent(fd, &kev, 1, NULL, 0, NULL);

	if (rv == -1 && errno == EBADF) {
		/* The close may race with this thread spawning */
		T_LOG("kqueue already closed?");
		return NULL;
	} else {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "kevent");
	}

	while ((rv = kevent(fd, NULL, 0, &kev, 1, NULL)) == 1) {
		T_LOG("poll\n");
	}

	if (rv != -1 || errno != EBADF) {
		T_ASSERT_POSIX_SUCCESS(rv, "fd should be closed");
	}

	return NULL;
}

static void
run_test()
{
	int fd = kqueue();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, "kqueue");

	pthread_t thread;
	int rv = pthread_create(&thread, NULL, poll_kqueue,
	    (void *)(uintptr_t)fd);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_create");

	usleep(timeout_ms * 1000);

	rv = close(fd);
	T_ASSERT_POSIX_SUCCESS(rv, "close");

	rv = pthread_join(thread, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_join");
}

T_DECL(kqueue_close_race, "Races kqueue close with kqueue process",
    T_META_LTEPHASE(LTE_POSTINIT), T_META_TIMEOUT(5))
{
	for (uint32_t i = 1; i < 100; i++) {
		run_test();
	}
}

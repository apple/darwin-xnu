#include <darwintest.h>

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/semaphore.h>
#include <sys/select.h>

/* Select parameters */
#define TIMEOUT_CHANCE          17      /* one in this many times, timeout */
#define TIMEOUT_POLLCHANCE      11      /* one in this many is a poll */
#define TIMEOUT_SCALE           5       /* microseconds multiplier */

static semaphore_t g_thread_sem;
static semaphore_t g_sync_sem;

struct endpoint {
	int       fd[4];
	pthread_t pth;
};

typedef void * (*thread_func)(struct endpoint *ep);
typedef void   (*setup_func)(struct endpoint *ep);

struct thread_sync_arg {
	struct endpoint ep;
	setup_func  setup;
	thread_func work;
};

static mach_timebase_info_data_t g_timebase;

static int g_sleep_iterations = 150000;
static int g_sleep_usecs = 30;
static int g_stress_nthreads = 100;
static uint64_t g_stress_duration = 60;

static inline uint64_t
ns_to_abs(uint64_t ns)
{
	return ns * g_timebase.denom / g_timebase.numer;
}

static inline uint64_t
abs_to_ns(uint64_t abs)
{
	return abs * g_timebase.numer / g_timebase.denom;
}



/*
 * Synchronize the startup / initialization of a set of threads
 */
static void *
thread_sync(void *ctx)
{
	struct thread_sync_arg *a = (struct thread_sync_arg *)ctx;
	T_QUIET;
	T_ASSERT_TRUE(((a != NULL) && (a->work != NULL)), "thread setup error");

	if (a->setup) {
		(a->setup)(&a->ep);
	}

	semaphore_wait_signal(g_thread_sem, g_sync_sem);
	return (a->work)(&a->ep);
}

struct select_stress_args {
	struct endpoint *ep;
	int nthreads;
};

static void
setup_stress_event(struct endpoint *ep)
{
	T_QUIET;
	T_WITH_ERRNO;
	T_ASSERT_POSIX_SUCCESS(pipe(&ep->fd[0]), "pipe()");

	T_LOG("th[0x%lx]: fd:{%d,%d}, ep@%p",
	    (uintptr_t)pthread_self(), ep->fd[0], ep->fd[1], (void *)ep);
}

/*
 * Cause file descriptors to be reused/replaced.  We expect that it will at
 * least take the lowest fd as part of the descriptor list.  This may be
 * optimistic, but it shows replacing an fd out from under a select() if it
 * happens.
 *
 * We potentially delay the open for a random amount of time so that another
 * thread can come in and wake up the fd_set with a bad (closed) fd in the set.
 */
static void
recycle_fds(struct endpoint *ep)
{
	/* close endpoint descriptors in random order */
	if (random() % 1) {
		close(ep->fd[0]);
		close(ep->fd[1]);
	} else {
		close(ep->fd[1]);
		close(ep->fd[0]);
	}

	/* randomize a delay */
	if ((random() % ep->fd[0]) == 0) {
		usleep(((random() % ep->fd[1]) + 1) * ep->fd[1]);
	}

	/* reopen the FDs, hopefully in the middle of select() */
	T_QUIET;
	T_WITH_ERRNO;
	T_ASSERT_POSIX_SUCCESS(pipe(&ep->fd[0]), "pipe");
}


/*
 * Send a byte of data down the thread end of a pipe to wake up the select
 * on the other end of it.  Select will wake up normally because of this,
 * and read the byte out. Hopefully, another thread has closed/reopened its FDs.
 */
static void
write_data(struct endpoint *ep)
{
	T_QUIET;
	T_WITH_ERRNO;
	T_ASSERT_POSIX_SUCCESS(write(ep->fd[1], "X", 1), "th[0x%lx] write_data(fd=%d)",
	    (uintptr_t)pthread_self(), ep->fd[1]);
}

static void *
do_stress_events(struct endpoint *ep)
{
	unsigned write_freq = (unsigned)(((uintptr_t)pthread_self() & 0xff0000) >> 16);

	/* some default */
	if (write_freq == 0) {
		write_freq = 31;
	}

	T_LOG("th[0x%lx] write_freq:%d", (uintptr_t)pthread_self(), write_freq);

	for (;;) {
		/* randomized delay between events */
		usleep(((random() % ep->fd[1]) + 1) * ep->fd[1]);

		if ((random() % write_freq) == 0) {
			write_data(ep);
		} else {
			recycle_fds(ep);
		}
	}
}

struct selarg {
	struct thread_sync_arg *th;
	fd_set  def_readfds;
	int max_fd;
	int nthreads;
	int ret;

	pthread_t pth;
};

/*
 * Put the actual call to select in its own thread so we can catch errors that
 * occur only the first time a thread calls select.
 */
static void *
do_select(void *arg)
{
	struct selarg *sarg = (struct selarg *)arg;
	struct timeval timeout;
	struct timeval *tp = NULL;
	fd_set  readfds;
	int nfd;

	sarg->ret = 0;

	FD_COPY(&sarg->def_readfds, &readfds);

	/* Add a timeout probablistically */
	if ((random() % TIMEOUT_CHANCE) == 0) {
		timeout.tv_sec = random() % 1;
		timeout.tv_usec = ((random() % TIMEOUT_POLLCHANCE) * TIMEOUT_SCALE);
		tp = &timeout;
	}

	/* Do the select */
	nfd = select(sarg->max_fd + 1, &readfds, 0, 0, tp);
	if (nfd < 0) {
		/* EBADF: fd_set has changed */
		if (errno == EBADF) {
			sarg->ret = EBADF;
			return NULL;
		}

		/* Other errors are fatal */
		T_QUIET;
		T_WITH_ERRNO;
		T_ASSERT_POSIX_SUCCESS(nfd, "select:stress");
	}

	/* Fast: handle timeouts */
	if (nfd == 0) {
		return NULL;
	}

	/* Slower: discard read input thrown at us from threads */
	for (int i = 0; i < sarg->nthreads; i++) {
		struct endpoint *ep = &sarg->th[i].ep;

		if (FD_ISSET(ep->fd[0], &readfds)) {
			char c;
			(void)read(ep->fd[0], &c, 1);
		}
	}

	return NULL;
}


static void
test_select_stress(int nthreads, uint64_t duration_seconds)
{
	uint64_t deadline;
	uint64_t seconds_remain, last_print_time;

	struct selarg sarg;

	int started_threads = 0;
	struct thread_sync_arg *th;

	if (nthreads < 2) {
		T_LOG("forcing a minimum of 2 threads");
		nthreads = 2;
	}

	/*
	 * Allocate memory for endpoint data
	 */
	th = calloc(nthreads, sizeof(*th));
	T_QUIET;
	T_ASSERT_NOTNULL(th, "select_stress: No memory for thread endpoints");

	T_LOG("Select stress test: %d threads, for %lld seconds", nthreads, duration_seconds);

	/*
	 * Startup all the threads
	 */
	T_LOG("\tcreating threads...");
	for (int i = 0; i < nthreads; i++) {
		struct endpoint *e = &th[i].ep;
		th[i].setup = setup_stress_event;
		th[i].work = do_stress_events;
		T_QUIET;
		T_WITH_ERRNO;
		T_ASSERT_POSIX_ZERO(pthread_create(&e->pth, 0, thread_sync, &th[i]),
		    "pthread_create:do_stress_events");
	}

	/*
	 * Wait for all the threads to start up
	 */
	while (started_threads < nthreads) {
		if (semaphore_wait(g_sync_sem) == KERN_SUCCESS) {
			++started_threads;
		}
	}

	/*
	 * Kick everyone off
	 */
	semaphore_signal_all(g_thread_sem);

	/*
	 * Calculate a stop time
	 */
	deadline = mach_absolute_time() + ns_to_abs(duration_seconds * NSEC_PER_SEC);
	seconds_remain = duration_seconds;
	last_print_time = seconds_remain + 1;

	/*
	 * Perform the select and read any data that comes from the
	 * constituent thread FDs.
	 */

	T_LOG("\ttest running!");
handle_ebadf:
	/* (re) set up the select fd set */
	sarg.max_fd = 0;
	FD_ZERO(&sarg.def_readfds);
	for (int i = 0; i < nthreads; i++) {
		struct endpoint *ep = &th[i].ep;

		FD_SET(ep->fd[0], &sarg.def_readfds);
		if (ep->fd[0] > sarg.max_fd) {
			sarg.max_fd = ep->fd[0];
		}
	}

	sarg.th = th;
	sarg.nthreads = nthreads;

	while (mach_absolute_time() < deadline) {
		void *thret = NULL;

		seconds_remain = abs_to_ns(deadline - mach_absolute_time()) / NSEC_PER_SEC;
		if (last_print_time > seconds_remain) {
			T_LOG(" %6lld...", seconds_remain);
			last_print_time = seconds_remain;
		}

		sarg.ret = 0;
		T_QUIET;
		T_WITH_ERRNO;
		T_ASSERT_POSIX_ZERO(pthread_create(&sarg.pth, 0, do_select, &sarg),
		    "pthread_create:do_select");

		T_QUIET;
		T_WITH_ERRNO;
		T_ASSERT_POSIX_ZERO(pthread_cancel(sarg.pth), "pthread_cancel");
		T_QUIET;
		T_WITH_ERRNO;
		T_ASSERT_POSIX_ZERO(pthread_join(sarg.pth, &thret), "pthread_join");

		if (sarg.ret == EBADF) {
			goto handle_ebadf;
		}
		T_QUIET;
		T_ASSERT_GE(sarg.ret, 0, "threaded do_select returned an \
		    error: %d!", sarg.ret);
	}

	T_PASS("select stress test passed");
}


/*
 * TEST: use select as sleep()
 */
static void
test_select_sleep(uint32_t niterations, unsigned long usecs)
{
	int ret;
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = usecs;

	if (!niterations) {
		T_FAIL("select sleep test skipped");
		return;
	}

	T_LOG("Testing select as sleep (n=%d, us=%ld)...", niterations, usecs);

	while (niterations--) {
		ret = select(0, NULL, NULL, NULL, &tv);
		if (ret < 0 && errno != EINTR) {
			T_QUIET;
			T_WITH_ERRNO;
			T_ASSERT_POSIX_SUCCESS(ret, "select:sleep");
		}
	}

	T_PASS("select sleep test passed");
}

#define get_env_arg(NM, sval, val) \
	do { \
	        sval = getenv(#NM); \
	        if (sval) { \
	                long v = atol(sval); \
	                if (v <= 0) \
	                        v =1 ; \
	                val = (typeof(val))v; \
	        } \
	} while (0)

T_DECL(select_sleep, "select sleep test for rdar://problem/20804876 Gala: select with no FDs leaks waitq table objects (causes asserts/panics)")
{
	char *env_sval = NULL;

	get_env_arg(SELSLEEP_ITERATIONS, env_sval, g_sleep_iterations);
	get_env_arg(SELSLEEP_INTERVAL, env_sval, g_sleep_usecs);

	test_select_sleep((uint32_t)g_sleep_iterations, (unsigned long)g_sleep_usecs);
}

T_DECL(select_stress, "select stress test for rdar://problem/20804876 Gala: select with no FDs leaks waitq table objects (causes asserts/panics)")
{
	char *env_sval = NULL;

	T_QUIET;
	T_ASSERT_MACH_SUCCESS(mach_timebase_info(&g_timebase),
	    "Can't get mach_timebase_info!");

	get_env_arg(SELSTRESS_THREADS, env_sval, g_stress_nthreads);
	get_env_arg(SELSTRESS_DURATION, env_sval, g_stress_duration);

	T_QUIET;
	T_ASSERT_MACH_SUCCESS(semaphore_create(mach_task_self(), &g_sync_sem, SYNC_POLICY_FIFO, 0),
	    "semaphore_create(g_sync_sem)");
	T_QUIET;
	T_ASSERT_MACH_SUCCESS(semaphore_create(mach_task_self(), &g_thread_sem, SYNC_POLICY_FIFO, 0),
	    "semaphore_create(g_thread_sem)");

	test_select_stress(g_stress_nthreads, g_stress_duration);
}

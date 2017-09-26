/*
 * Test to validate that we can schedule threads on all hw.ncpus cores according to _os_cpu_number
 *
 * <rdar://problem/29545645>
 *
xcrun -sdk macosx.internal clang -o cpucount cpucount.c -ldarwintest -g -Weverything
xcrun -sdk iphoneos.internal clang -arch arm64 -o cpucount-ios cpucount.c -ldarwintest -g -Weverything
 */

#include <darwintest.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdalign.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <err.h>
#include <errno.h>
#include <sysexits.h>
#include <sys/sysctl.h>
#include <stdatomic.h>

#include <mach/mach.h>
#include <mach/mach_time.h>

#include <os/tsd.h> /* private header for _os_cpu_number */

/* const variables aren't constants, but enums are */
enum { max_threads = 40 };

#define CACHE_ALIGNED __attribute__((aligned(128)))

static _Atomic CACHE_ALIGNED uint64_t g_ready_threads = 0;

static _Atomic CACHE_ALIGNED bool g_cpu_seen[max_threads];

static _Atomic CACHE_ALIGNED bool g_bail = false;

static uint32_t g_threads; /* set by sysctl hw.ncpu */

static uint64_t g_spin_ms = 50; /* it takes ~50ms of spinning for CLPC to deign to give us all cores */

/*
 * sometimes pageout scan can eat all of CPU 0 long enough to fail the test,
 * so we run the test at RT priority
 */
static uint32_t g_thread_pri = 97;

/*
 * add in some extra low-pri threads to convince the amp scheduler to use E-cores consistently
 * works around <rdar://problem/29636191>
 */
static uint32_t g_spin_threads = 2;
static uint32_t g_spin_threads_pri = 20;

static semaphore_t g_readysem, g_go_sem;

static mach_timebase_info_data_t timebase_info;

static uint64_t nanos_to_abs(uint64_t nanos) { return nanos * timebase_info.denom / timebase_info.numer; }

static void set_realtime(pthread_t thread) {
	kern_return_t kr;
	thread_time_constraint_policy_data_t pol;

	mach_port_t target_thread = pthread_mach_thread_np(thread);
	T_QUIET; T_ASSERT_NOTNULL(target_thread, "pthread_mach_thread_np");

	/* 1s 100ms 10ms */
	pol.period      = (uint32_t)nanos_to_abs(1000000000);
	pol.constraint  = (uint32_t)nanos_to_abs(100000000);
	pol.computation = (uint32_t)nanos_to_abs(10000000);

	pol.preemptible = 0; /* Ignored by OS */
	kr = thread_policy_set(target_thread, THREAD_TIME_CONSTRAINT_POLICY, (thread_policy_t) &pol,
	                       THREAD_TIME_CONSTRAINT_POLICY_COUNT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_policy_set(THREAD_TIME_CONSTRAINT_POLICY)");
}

static pthread_t
create_thread(void *(*start_routine)(void *), uint32_t priority)
{
	int rv;
	pthread_t new_thread;
	pthread_attr_t attr;

	struct sched_param param = { .sched_priority = (int)priority };

	rv = pthread_attr_init(&attr);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_attr_init");

	rv = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_attr_setdetachstate");

	rv = pthread_attr_setschedparam(&attr, &param);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_attr_setschedparam");

	rv = pthread_create(&new_thread, &attr, start_routine, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_create");

	if (priority == 97)
		set_realtime(new_thread);

	rv = pthread_attr_destroy(&attr);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_attr_destroy");

	return new_thread;
}

static void *
thread_fn(__unused void *arg)
{
	T_QUIET; T_EXPECT_TRUE(true, "initialize darwintest on this thread");

	kern_return_t kr;

	kr = semaphore_wait_signal(g_go_sem, g_readysem);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_wait_signal");

	/* atomic inc to say hello */
	g_ready_threads++;

	uint64_t timeout = nanos_to_abs(g_spin_ms * NSEC_PER_MSEC) + mach_absolute_time();

	/*
	 * spin to force the other threads to spread out across the cores
	 * may take some time if cores are masked and CLPC needs to warm up to unmask them
	 */
	while (g_ready_threads < g_threads && mach_absolute_time() < timeout);

	T_QUIET; T_ASSERT_GE(timeout, mach_absolute_time(), "waiting for all threads took too long");

	timeout = nanos_to_abs(g_spin_ms * NSEC_PER_MSEC) + mach_absolute_time();

	int iteration = 0;
	uint32_t cpunum = 0;

	/* search for new CPUs for the duration */
	while (mach_absolute_time() < timeout) {
		cpunum = _os_cpu_number();

		assert(cpunum < max_threads);

		g_cpu_seen[cpunum] = true;

		if (iteration++ % 10000) {
			uint32_t cpus_seen = 0;

			for (uint32_t i = 0 ; i < g_threads; i++) {
				if (g_cpu_seen[i])
					cpus_seen++;
			}

			/* bail out early if we saw all CPUs */
			if (cpus_seen == g_threads)
				break;
		}
	}

	g_bail = true;

	printf("thread cpunum: %d\n", cpunum);

	kr = semaphore_wait_signal(g_go_sem, g_readysem);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_wait_signal");

	return NULL;
}

static void *
spin_fn(__unused void *arg)
{
	T_QUIET; T_EXPECT_TRUE(true, "initialize darwintest on this thread");

	kern_return_t kr;

	kr = semaphore_wait_signal(g_go_sem, g_readysem);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_wait_signal");

	uint64_t timeout = nanos_to_abs(g_spin_ms * NSEC_PER_MSEC * 2) + mach_absolute_time();

	/*
	 * run and sleep a bit to force some scheduler churn to get all the cores active
	 * needed to work around bugs in the amp scheduler
	 */
	while (mach_absolute_time() < timeout && g_bail == false) {
		usleep(500);

		uint64_t inner_timeout = nanos_to_abs(1 * NSEC_PER_MSEC) + mach_absolute_time();

		while (mach_absolute_time() < inner_timeout && g_bail == false);
	}

	kr = semaphore_wait_signal(g_go_sem, g_readysem);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_wait_signal");

	return NULL;
}


#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-flexible-array-initializer"
T_DECL(count_cpus, "Tests we can schedule threads on all hw.ncpus cores according to _os_cpu_number",
       T_META_CHECK_LEAKS(NO))
#pragma clang diagnostic pop
{
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	int rv;
	kern_return_t kr;
	kr = mach_timebase_info(&timebase_info);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_timebase_info");

	kr = semaphore_create(mach_task_self(), &g_readysem, SYNC_POLICY_FIFO, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_create");

	kr = semaphore_create(mach_task_self(), &g_go_sem, SYNC_POLICY_FIFO, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_create");

	size_t ncpu_size = sizeof(g_threads);
	rv = sysctlbyname("hw.ncpu", &g_threads, &ncpu_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "sysctlbyname(hw.ncpu)");

	printf("hw.ncpu: %2d\n", g_threads);

	assert(g_threads < max_threads);

	for (uint32_t i = 0; i < g_threads; i++)
		create_thread(&thread_fn, g_thread_pri);

	for (uint32_t i = 0; i < g_spin_threads; i++)
		create_thread(&spin_fn, g_spin_threads_pri);

	for (uint32_t i = 0 ; i < g_threads + g_spin_threads; i++) {
		kr = semaphore_wait(g_readysem);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_wait");
	}

	uint64_t timeout = nanos_to_abs(g_spin_ms * NSEC_PER_MSEC) + mach_absolute_time();

	/* spin to warm up CLPC :) */
	while (mach_absolute_time() < timeout);

	kr = semaphore_signal_all(g_go_sem);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_signal_all");

	for (uint32_t i = 0 ; i < g_threads + g_spin_threads; i++) {
		kr = semaphore_wait(g_readysem);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "semaphore_wait");
	}

	uint32_t cpus_seen = 0;

	for (uint32_t i = 0 ; i < g_threads; i++) {
		if (g_cpu_seen[i])
			cpus_seen++;

		printf("cpu %2d: %d\n", i, g_cpu_seen[i]);
	}

	T_ASSERT_EQ(cpus_seen, g_threads, "test should have run threads on all CPUS");
}


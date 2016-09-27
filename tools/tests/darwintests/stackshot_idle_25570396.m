/* This program tests that kThreadIdleWorker is being set properly, so
 * that idle and active threads can be appropriately identified.
 */

#include <darwintest.h>
#include <dispatch/dispatch.h>
#include <kdd.h>
#include <kern/kcdata.h>
#include <kern/debug.h>
#include <mach/mach_init.h>
#include <mach/mach_traps.h>
#include <mach/semaphore.h>
#include <mach/task.h>
#include <pthread.h>
#include <sys/stackshot.h>
#include <stdlib.h>
#include <unistd.h>

#include <Foundation/Foundation.h>

#define NUMRETRIES  5  // number of times to retry a stackshot
#define NUMENQUEUES 16 // number of blocking jobs to enqueue
#define NUMTHREADS  (NUMENQUEUES + 2) // total number of threads (including numenqueues)

volatile static int spin_threads = 1;

static void *
take_stackshot(uint32_t extra_flags, uint64_t since_timestamp)
{
	void * stackshot;
	int ret, retries;
	uint32_t stackshot_flags = STACKSHOT_SAVE_LOADINFO |
					STACKSHOT_GET_GLOBAL_MEM_STATS |
					STACKSHOT_SAVE_IMP_DONATION_PIDS |
					STACKSHOT_KCDATA_FORMAT;

	if (since_timestamp != 0)
		stackshot_flags |= STACKSHOT_COLLECT_DELTA_SNAPSHOT;

	stackshot_flags |= extra_flags;

	stackshot = stackshot_config_create();
	T_ASSERT_NOTNULL(stackshot, "Allocating stackshot config");

	ret = stackshot_config_set_flags(stackshot, stackshot_flags);
	T_ASSERT_POSIX_ZERO(ret, "Setting flags on stackshot config");

	ret = stackshot_config_set_pid(stackshot, getpid());
	T_ASSERT_POSIX_ZERO(ret, "Setting target pid on stackshot config");

	if (since_timestamp != 0) {
		ret = stackshot_config_set_delta_timestamp(stackshot, since_timestamp);
		T_ASSERT_POSIX_ZERO(ret, "Setting prev snapshot time on stackshot config");
	}

	for (retries = NUMRETRIES; retries > 0; retries--) {
		ret = stackshot_capture_with_config(stackshot);
		T_ASSERT_TRUE(ret == 0 || ret == EBUSY || ret == ETIMEDOUT, "Attempting to take stackshot (error %d)...", ret);
		if (retries == 0 && (ret == EBUSY || ret == ETIMEDOUT))
			T_ASSERT_FAIL("Failed to take stackshot after %d retries: %s", ret, strerror(ret));
		if (ret == 0)
			break;
	}
	return stackshot;
}

static uint64_t get_stackshot_timestamp(void * stackshot)
{
	kcdata_iter_t iter;
	void * buf;
	uint64_t default_time = 0;
	uint32_t t, buflen;

	buf = stackshot_config_get_stackshot_buffer(stackshot);
	T_ASSERT_NOTNULL(buf, "Getting stackshot buffer");
	buflen = stackshot_config_get_stackshot_size(stackshot);

	iter = kcdata_iter(buf, buflen);
	t    = kcdata_iter_type(iter);

	T_ASSERT_TRUE(t == KCDATA_BUFFER_BEGIN_STACKSHOT || t == KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT,
		"Making sure stackshot data begins with \"begin\" flag");
	T_ASSERT_TRUE(kcdata_iter_valid(iter = kcdata_iter_find_type(iter, KCDATA_TYPE_MACH_ABSOLUTE_TIME)),
		"Getting stackshot timestamp");
	default_time = *(uint64_t *)kcdata_iter_payload(iter);
	return default_time;
}

static void
get_thread_statuses(void * stackshot, int * num_idles, int * num_nonidles)
{
	void *buf;
	uint32_t t, buflen;
	uint64_t thread_snap_flags;
	NSError *error = nil;
	NSMutableDictionary *parsed_container, *parsed_threads;

	*num_idles = 0;
	*num_nonidles = 0;

	buf = stackshot_config_get_stackshot_buffer(stackshot);
	T_ASSERT_NOTNULL(buf, "Getting stackshot buffer");
	buflen = stackshot_config_get_stackshot_size(stackshot);

	kcdata_iter_t iter = kcdata_iter(buf, buflen);
	T_ASSERT_TRUE(kcdata_iter_type(iter) == KCDATA_BUFFER_BEGIN_STACKSHOT ||
			kcdata_iter_type(iter) == KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT,
			"Checking start of stackshot buffer");

	iter = kcdata_iter_next(iter);
	KCDATA_ITER_FOREACH(iter)
	{
		t = kcdata_iter_type(iter);

		if (t != KCDATA_TYPE_CONTAINER_BEGIN) {
			continue;
		}

		if (kcdata_iter_container_type(iter) != STACKSHOT_KCCONTAINER_TASK) {
			continue;
		}

		parsed_container = parseKCDataContainer(&iter, &error);
		T_ASSERT_TRUE(parsed_container && !error, "Parsing container");

		parsed_threads = parsed_container[@"task_snapshots"][@"thread_snapshots"];
		for (id th_key in parsed_threads) {
			/* check to see that tid matches expected idle status */
			thread_snap_flags = [parsed_threads[th_key][@"thread_snapshot"][@"ths_ss_flags"] unsignedLongLongValue];
			(thread_snap_flags & kThreadIdleWorker) ? (*num_idles)++ : (*num_nonidles)++;
		}
		[parsed_container release];
	}

}

/* Dispatch NUMENQUEUES jobs to a concurrent queue that immediately wait on a
 * shared semaphore. This should spin up plenty of threads! */
static void
warm_up_threadpool(dispatch_queue_t q)
{
	int i;
	dispatch_semaphore_t thread_wait = dispatch_semaphore_create(0);
	T_QUIET; T_ASSERT_NOTNULL(thread_wait, "Initializing work queue semaphore");
	dispatch_semaphore_t main_wait = dispatch_semaphore_create(0);
	T_QUIET; T_ASSERT_NOTNULL(main_wait, "Initializing main thread semaphore");

	for (i = 0; i < NUMENQUEUES; i++) {
		dispatch_async(q, ^{
			dispatch_semaphore_wait(thread_wait, DISPATCH_TIME_FOREVER);
			dispatch_semaphore_signal(main_wait);
		});
	}

	sleep(1); // give worker threads enough time to block

	for (i = 0; i < NUMENQUEUES; i++) {
		dispatch_semaphore_signal(thread_wait);
		dispatch_semaphore_wait(main_wait, DISPATCH_TIME_FOREVER);
	}

	dispatch_release(thread_wait);
	dispatch_release(main_wait);

	// Give enough time for worker threads to go idle again
	sleep(1);
}

/* Dispatch NUMENQUEUES jobs to a concurrent queue that spin in a tight loop.
 * Isn't guaranteed to occupy every worker thread, but it's enough so
 * that a thread will go from idle to nonidle.
 */
static void
fill_threadpool_with_spinning(dispatch_queue_t q)
{
	int i;
	for (i = 0; i < NUMENQUEUES; i++) {
		dispatch_async(q, ^{
			while(spin_threads); // should now appear as non-idle in delta shot
		});
	}
	sleep(1); // wait for jobs to enqueue
}

/* Take stackshot, count the number of idle and nonidle threads the stackshot records.
 * Where this is called, there should be NUMENQUEUES idle threads (thanks to warm_up_threadpool)
 * and 2 nonidle threads (the main thread, and the spinning pthread).
 */
static void
take_and_verify_initial_stackshot(uint64_t * since_time)
{
	void *stackshot;
	int num_init_idle_threads, num_init_nonidle_threads;

	stackshot = take_stackshot(0, 0);
	*since_time = get_stackshot_timestamp(stackshot);
	get_thread_statuses(stackshot, &num_init_idle_threads, &num_init_nonidle_threads);

	T_EXPECT_EQ(num_init_idle_threads, NUMENQUEUES,
			"Idle count of %d should match expected value of %d...",
			num_init_idle_threads, NUMENQUEUES);
	T_EXPECT_EQ(num_init_nonidle_threads, NUMTHREADS - NUMENQUEUES,
			"Non-idle count of %d should match expected value of %d...",
			num_init_nonidle_threads, NUMTHREADS - NUMENQUEUES);
	stackshot_config_dealloc(stackshot);
}

/* Take a stackshot and a delta stackshot, measuring what changed since the previous
 * stackshot. Where this is called, the blocking jobs have been cleared from the work queue,
 * and the work queue has NUMENQUEUES tight-spinning jobs on it. Make sure that
 * no new idle threads appear in the delta, and make sure that the delta shot isn't
 * ignoring the worker threads that have become active.
 */
static void
take_and_verify_delta_stackshot(uint64_t since_time)
{
	void *stackshot;
	void *delta_stackshot;

	int num_delta_idles, num_delta_nonidles, num_curr_idles, num_curr_nonidles;

	stackshot = take_stackshot(0, 0);
	delta_stackshot = take_stackshot(0, since_time); /* Threads should appear in delta stackshot as non-idle */

	get_thread_statuses(stackshot, &num_curr_idles, &num_curr_nonidles);
	get_thread_statuses(delta_stackshot, &num_delta_idles, &num_delta_nonidles);

	T_EXPECT_EQ(num_delta_idles, 0, "Making sure there are no idles in delta shot");
	T_EXPECT_EQ(num_delta_nonidles + num_curr_idles, NUMTHREADS,
			"Making sure delta shot isn't ignoring newly active threads");
	stackshot_config_dealloc(stackshot);
	stackshot_config_dealloc(delta_stackshot);
}

static void *
spinning_non_work_queue_thread(void * ignored)
{
	(void)ignored;
	while(spin_threads);
	return NULL;
}

T_DECL(stackshot_idle_25570396, "Tests that stackshot can properly recognize idle and non-idle threads", T_META("owner", "Core Kernel Team"))
{
	int ret;
	uint64_t initial_stackshot_time;
	pthread_t spinning_thread;
	dispatch_queue_t q;

	ret = pthread_create(&spinning_thread, NULL, spinning_non_work_queue_thread, NULL);
	T_ASSERT_POSIX_ZERO(ret, "Spinning up non-work-queue thread");

	q = dispatch_queue_create("com.apple.kernel.test.waiting_semaphores", DISPATCH_QUEUE_CONCURRENT);

	warm_up_threadpool(q);
	take_and_verify_initial_stackshot(&initial_stackshot_time);

	fill_threadpool_with_spinning(q);
	take_and_verify_delta_stackshot(initial_stackshot_time);

	spin_threads = 0; /* pthread-made thread should now exit */
	ret = pthread_join(spinning_thread, NULL);
	T_ASSERT_POSIX_ZERO(ret, "Joining on non-work-queue thread");
}

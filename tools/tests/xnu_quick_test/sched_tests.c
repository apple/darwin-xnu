/*
 *  sched_tests.c
 *  xnu_quick_test
 *
 *  Copyright 2011 Apple Inc. All rights reserved.
 *
 */

#include "tests.h"
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/semaphore.h>
#include <unistd.h>
#include <err.h>
#include <sys/param.h>
#include <pthread.h>

#define DEBUG 0

#if DEBUG
#define dprintf(...) printf(__VA_ARGS__)
#else
#define dprintf(...) do { } while(0)
#endif

static uint64_t
nanos_to_abs(uint64_t ns, uint32_t numer, uint32_t denom)
{
	return (uint64_t)(ns * (((double)denom) / ((double)numer)));
}

static void set_realtime(void) {
	struct mach_timebase_info mti;
	thread_time_constraint_policy_data_t pol;
	kern_return_t kret;

	kret = mach_timebase_info(&mti);
	if (kret != KERN_SUCCESS) {
		warnx("Could not get timebase info %d", kret);
		return;
	}

	/* 1s 100ms 10ms */
	pol.period      = nanos_to_abs(1000000000, mti.numer, mti.denom);
	pol.constraint  = nanos_to_abs(100000000,  mti.numer, mti.denom);
	pol.computation = nanos_to_abs(10000000,   mti.numer, mti.denom);
	pol.preemptible = 0; /* Ignored by OS */

	kret = thread_policy_set(mach_thread_self(), THREAD_TIME_CONSTRAINT_POLICY, (thread_policy_t) &pol, THREAD_TIME_CONSTRAINT_POLICY_COUNT);
	if (kret != KERN_SUCCESS) {
		warnx("Failed to set realtime %d", kret);
	}
}

struct t1_ctx {
	pthread_t __p;
	int currentThread;
	int totalThreads;
	boolean_t useRealtime;
	semaphore_t wait_to_start;
	semaphore_t next_waiter;

	semaphore_t common_sema; /* main thing everyone blocks on */
	uint64_t wakeup_time; /* out parameter */
};

void *t1(void *arg) {
	struct t1_ctx *ctx = (struct t1_ctx *)arg;
	kern_return_t kret;

	dprintf("thread %d (pthread %p) started\n", ctx->currentThread, pthread_self());

	/* Wait to allow previous thread to block on common semaphore */
	kret = semaphore_wait(ctx->wait_to_start);
	if (kret != KERN_SUCCESS) {
		warnx("semaphore_wait(wait_to_start) thread %d failed %d",
			  ctx->currentThread, kret);
	}

	sleep(1);

	if (ctx->useRealtime) {
		dprintf("thread %d going realtime\n", ctx->currentThread);
		set_realtime();
	}

	kret = semaphore_signal(ctx->next_waiter);
	if (kret != KERN_SUCCESS) {
		warnx("semaphore_signal(next_waiter) thread %d failed %d",
			  ctx->currentThread, kret);
	}

	/*
	 * We have 1 second to block on the common semaphore before
	 * the next thread does.
	 */
	dprintf("thread %d blocking on common semaphore\n", ctx->currentThread);

	kret = semaphore_wait(ctx->common_sema);
	if (kret != KERN_SUCCESS) {
		warnx("semaphore_wait(common_sema) thread %d failed %d",
			  ctx->currentThread, kret);
	}

	/* Save our time for analysis */
	ctx->wakeup_time = mach_absolute_time();
	dprintf("thread %d woke up at %llu\n", ctx->currentThread, ctx->wakeup_time);

	kret = semaphore_signal(ctx->common_sema);
	if (kret != KERN_SUCCESS) {
		warnx("semaphore_signal(common_sema) thread %d failed %d",
			  ctx->currentThread, kret);
	}

	return NULL;
}
	   



int sched_tests( void * the_argp )
{
	kern_return_t kret;
	int ret;
	int i;
	semaphore_t common_sema;
	semaphore_t all_checked_in;
	
	struct t1_ctx ctxs[3];
	
	/*
	 * Test 8979062. Ensure that a realtime thread that
	 * blocks on a semaphore after a non-realtime thread
	 * gets woken up first.
	 */

	kret = semaphore_create(mach_task_self(), &common_sema, SYNC_POLICY_FIFO /* not really, in this case */, 0);
	if (kret != KERN_SUCCESS) {
		warnx("semaphore_create failed: %d", kret);
		return -1;
	}

	kret = semaphore_create(mach_task_self(), &all_checked_in, SYNC_POLICY_FIFO, 0);
	if (kret != KERN_SUCCESS) {
		warnx("semaphore_create failed: %d", kret);
		return -1;
	}

	memset(&ctxs, 0x00, sizeof(ctxs));
	for (i=0; i < sizeof(ctxs)/sizeof(ctxs[0]); i++) {
		ctxs[i].__p = NULL; /* set later */
		ctxs[i].currentThread = i;
		ctxs[i].totalThreads = sizeof(ctxs)/sizeof(ctxs[0]);
		ctxs[i].useRealtime = FALSE;

		kret = semaphore_create(mach_task_self(), &ctxs[i].wait_to_start, SYNC_POLICY_FIFO /* not really, in this case */, 0);
		if (kret != KERN_SUCCESS) {
			warnx("semaphore_create failed: %d", kret);
			return -1;
		}
		ctxs[i].next_waiter = MACH_PORT_NULL; /* set later */
		ctxs[i].common_sema = common_sema;
		ctxs[i].wakeup_time = 0;
	}

	ctxs[1].useRealtime = TRUE;

	for (i=1; i < sizeof(ctxs)/sizeof(ctxs[0]); i++) {
		ctxs[i-1].next_waiter = ctxs[i].wait_to_start;
	}
	ctxs[i-1].next_waiter = all_checked_in;


	for (i=0; i < sizeof(ctxs)/sizeof(ctxs[0]); i++) {
		ret = pthread_create(&ctxs[i].__p, NULL, t1, &ctxs[i]);
		if (ret != 0) {
			warn("pthread_create failed");
			return -1;
		}
	}

	/* wake up first thread */
	kret = semaphore_signal(ctxs[0].wait_to_start);
	if (kret != KERN_SUCCESS) {
		warnx("semaphore_signal(initial wait_to_start) failed %d", kret);
		return -1;
	}

	/* Wait for everyone to have blocked */
	kret = semaphore_wait(all_checked_in);
	if (kret != KERN_SUCCESS) {
		warnx("semaphore_wait(all_checked_in) failed %d", kret);
		return -1;
	}

	/* Give some slack for last guy */
	sleep(1);

	kret = semaphore_signal(common_sema);
	if (kret != KERN_SUCCESS) {
		warnx("semaphore_signal(initial common_sema) failed %d", kret);
		return -1;
	}

	for (i=0; i < sizeof(ctxs)/sizeof(ctxs[0]); i++) {
		ret = pthread_join(ctxs[i].__p, NULL);
		if (ret != 0) {
			warn("pthread_join failed");
			return -1;
		}
	}

	dprintf("All threads joined\n");

	/*
	 * Our expectation is that thread 1 was realtime and
	 * finished first, followed by 0 and then 2
	 */
	if ((ctxs[1].wakeup_time < ctxs[0].wakeup_time)
		&& (ctxs[0].wakeup_time < ctxs[2].wakeup_time)) {
		/* success */
	} else {
		warnx("Threads woken out of order %llu %llu %llu",
			  ctxs[0].wakeup_time, ctxs[1].wakeup_time,
			  ctxs[2].wakeup_time);
		return -1;
	}

	return 0;
}


/*
 * Copyright (c) 2018 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <mach/mach_types.h>
#include <mach/machine.h>
#include <machine/machine_routines.h>
#include <machine/sched_param.h>
#include <machine/machine_cpu.h>
#include <kern/kern_types.h>
#include <kern/debug.h>
#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/processor.h>
#include <kern/queue.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/sched_clutch.h>
#include <machine/atomic.h>
#include <kern/sched_clutch.h>
#include <sys/kdebug.h>


#if CONFIG_SCHED_CLUTCH

/* Forward declarations of static routines */

/* Root level hierarchy management */
static void sched_clutch_root_init(sched_clutch_root_t, processor_set_t);
static void sched_clutch_root_bucket_init(sched_clutch_root_bucket_t, sched_bucket_t);
static void sched_clutch_root_pri_update(sched_clutch_root_t);
static sched_clutch_root_bucket_t sched_clutch_root_highest_root_bucket(sched_clutch_root_t, uint64_t);
static void sched_clutch_root_urgency_inc(sched_clutch_root_t, thread_t);
static void sched_clutch_root_urgency_dec(sched_clutch_root_t, thread_t);

/* Root bucket level hierarchy management */
static uint64_t sched_clutch_root_bucket_deadline_calculate(sched_clutch_root_bucket_t, uint64_t);
static void sched_clutch_root_bucket_deadline_update(sched_clutch_root_bucket_t, sched_clutch_root_t, uint64_t);
static int sched_clutch_root_bucket_pri_compare(sched_clutch_root_bucket_t, sched_clutch_root_bucket_t);

/* Clutch bucket level hierarchy management */
static void sched_clutch_bucket_hierarchy_insert(sched_clutch_root_t, sched_clutch_bucket_t, sched_bucket_t, uint64_t);
static void sched_clutch_bucket_hierarchy_remove(sched_clutch_root_t, sched_clutch_bucket_t, sched_bucket_t, uint64_t);
static boolean_t sched_clutch_bucket_runnable(sched_clutch_bucket_t, sched_clutch_root_t, uint64_t);
static boolean_t sched_clutch_bucket_update(sched_clutch_bucket_t, sched_clutch_root_t, uint64_t);
static void sched_clutch_bucket_empty(sched_clutch_bucket_t, sched_clutch_root_t, uint64_t);

static void sched_clutch_bucket_cpu_usage_update(sched_clutch_bucket_t, uint64_t);
static void sched_clutch_bucket_cpu_blocked_update(sched_clutch_bucket_t, uint64_t);
static uint8_t sched_clutch_bucket_pri_calculate(sched_clutch_bucket_t, uint64_t);
static sched_clutch_bucket_t sched_clutch_root_bucket_highest_clutch_bucket(sched_clutch_root_bucket_t);

/* Clutch timeshare properties updates */
static uint32_t sched_clutch_run_bucket_incr(sched_clutch_t, sched_bucket_t);
static uint32_t sched_clutch_run_bucket_decr(sched_clutch_t, sched_bucket_t);
static void sched_clutch_bucket_cpu_adjust(sched_clutch_bucket_t);
static void sched_clutch_bucket_timeshare_update(sched_clutch_bucket_t);
static boolean_t sched_thread_sched_pri_promoted(thread_t);
/* Clutch membership management */
static boolean_t sched_clutch_thread_insert(sched_clutch_root_t, thread_t, integer_t);
static void sched_clutch_thread_remove(sched_clutch_root_t, thread_t, uint64_t);
static thread_t sched_clutch_thread_highest(sched_clutch_root_t);

/* Clutch properties updates */
static uint32_t sched_clutch_root_urgency(sched_clutch_root_t);
static uint32_t sched_clutch_root_count_sum(sched_clutch_root_t);
static int sched_clutch_root_priority(sched_clutch_root_t);


/* Helper debugging routines */
static inline void sched_clutch_hierarchy_locked_assert(sched_clutch_root_t);



/*
 * Global priority queue comparator routine for root buckets. The
 * routine implements the priority queue as a minimum deadline queue
 * to achieve EDF scheduling.
 */
priority_queue_compare_fn_t sched_clutch_root_bucket_compare;


/*
 * Special markers for buckets that have invalid WCELs/quantums etc.
 */
#define SCHED_CLUTCH_INVALID_TIME_32 ((uint32_t)~0)
#define SCHED_CLUTCH_INVALID_TIME_64 ((uint64_t)~0)

/*
 * Root level bucket WCELs
 *
 * The root level bucket selection algorithm is an Earliest Deadline
 * First (EDF) algorithm where the deadline for buckets are defined
 * by the worst-case-execution-latency and the make runnable timestamp
 * for the bucket.
 *
 */
static uint32_t sched_clutch_root_bucket_wcel_us[TH_BUCKET_SCHED_MAX] = {
	SCHED_CLUTCH_INVALID_TIME_32,                   /* FIXPRI */
	0,                                              /* FG */
	37500,                                          /* IN (37.5ms) */
	75000,                                          /* DF (75ms) */
	150000,                                         /* UT (150ms) */
	250000                                          /* BG (250ms) */
};
static uint64_t sched_clutch_root_bucket_wcel[TH_BUCKET_SCHED_MAX] = {0};

/*
 * Root level bucket warp
 *
 * Each root level bucket has a warp value associated with it as well.
 * The warp value allows the root bucket to effectively warp ahead of
 * lower priority buckets for a limited time even if it has a later
 * deadline. The warping behavior provides extra (but limited)
 * opportunity for high priority buckets to remain responsive.
 */

/* Special warp deadline value to indicate that the bucket has not used any warp yet */
#define SCHED_CLUTCH_ROOT_BUCKET_WARP_UNUSED    (SCHED_CLUTCH_INVALID_TIME_64)

/* Warp window durations for various tiers */
static uint32_t sched_clutch_root_bucket_warp_us[TH_BUCKET_SCHED_MAX] = {
	SCHED_CLUTCH_INVALID_TIME_32,                   /* FIXPRI */
	8000,                                           /* FG (8ms)*/
	4000,                                           /* IN (4ms) */
	2000,                                           /* DF (2ms) */
	1000,                                           /* UT (1ms) */
	0                                               /* BG (0ms) */
};
static uint64_t sched_clutch_root_bucket_warp[TH_BUCKET_SCHED_MAX] = {0};

/*
 * Thread level quantum
 *
 * The algorithm defines quantums for threads at various buckets. This
 * (combined with the root level bucket quantums) restricts how much
 * the lower priority levels can preempt the higher priority threads.
 */
static uint32_t sched_clutch_thread_quantum_us[TH_BUCKET_SCHED_MAX] = {
	10000,                                          /* FIXPRI (10ms) */
	10000,                                          /* FG (10ms) */
	8000,                                           /* IN (8ms) */
	6000,                                           /* DF (6ms) */
	4000,                                           /* UT (4ms) */
	2000                                            /* BG (2ms) */
};
static uint64_t sched_clutch_thread_quantum[TH_BUCKET_SCHED_MAX] = {0};

enum sched_clutch_state {
	SCHED_CLUTCH_STATE_EMPTY = 0,
	SCHED_CLUTCH_STATE_RUNNABLE,
};

/*
 * sched_clutch_us_to_abstime()
 *
 * Initializer for converting all durations in usec to abstime
 */
static void
sched_clutch_us_to_abstime(uint32_t *us_vals, uint64_t *abstime_vals)
{
	for (int i = 0; i < TH_BUCKET_SCHED_MAX; i++) {
		if (us_vals[i] == SCHED_CLUTCH_INVALID_TIME_32) {
			abstime_vals[i] = SCHED_CLUTCH_INVALID_TIME_64;
		} else {
			clock_interval_to_absolutetime_interval(us_vals[i],
			    NSEC_PER_USEC, &abstime_vals[i]);
		}
	}
}

#if DEVELOPMENT || DEBUG

/*
 * sched_clutch_hierarchy_locked_assert()
 *
 * Debugging helper routine. Asserts that the hierarchy is locked. The locking
 * for the hierarchy depends on where the hierarchy is hooked. The current
 * implementation hooks the hierarchy at the pset, so the hierarchy is locked
 * using the pset lock.
 */
static inline void
sched_clutch_hierarchy_locked_assert(
	sched_clutch_root_t root_clutch)
{
	pset_assert_locked(root_clutch->scr_pset);
}

#else /* DEVELOPMENT || DEBUG */

static inline void
sched_clutch_hierarchy_locked_assert(
	__unused sched_clutch_root_t root_clutch)
{
}

#endif /* DEVELOPMENT || DEBUG */

/*
 * sched_clutch_thr_count_inc()
 *
 * Increment thread count at a hierarchy level with overflow checks.
 */
static void
sched_clutch_thr_count_inc(
	uint16_t *thr_count)
{
	if (__improbable(os_inc_overflow(thr_count))) {
		panic("sched_clutch thread count overflowed!");
	}
}

/*
 * sched_clutch_thr_count_dec()
 *
 * Decrement thread count at a hierarchy level with underflow checks.
 */
static void
sched_clutch_thr_count_dec(
	uint16_t *thr_count)
{
	if (__improbable(os_dec_overflow(thr_count))) {
		panic("sched_clutch thread count underflowed!");
	}
}


/*
 * sched_clutch_root_init()
 *
 * Routine to initialize the scheduler hierarchy root.
 */
static void
sched_clutch_root_init(
	sched_clutch_root_t root_clutch,
	processor_set_t pset)
{
	root_clutch->scr_thr_count = 0;
	root_clutch->scr_priority = NOPRI;
	root_clutch->scr_urgency = 0;
	root_clutch->scr_pset = pset;

	/* Initialize the queue which maintains all runnable clutch_buckets for timesharing purposes */
	queue_init(&root_clutch->scr_clutch_buckets);

	/* Initialize the queue which maintains all runnable foreign clutch buckets */
	queue_init(&root_clutch->scr_foreign_buckets);

	/* Initialize the bitmap and priority queue of runnable root buckets */
	sched_clutch_root_bucket_compare = priority_heap_make_comparator(a, b, struct sched_clutch_root_bucket, scrb_pqlink, {
		return (a->scrb_deadline < b->scrb_deadline) ? 1 : ((a->scrb_deadline == b->scrb_deadline) ? 0 : -1);
	});
	priority_queue_init(&root_clutch->scr_root_buckets, PRIORITY_QUEUE_GENERIC_KEY | PRIORITY_QUEUE_MIN_HEAP);
	bitmap_zero(root_clutch->scr_runnable_bitmap, TH_BUCKET_SCHED_MAX);
	bitmap_zero(root_clutch->scr_warp_available, TH_BUCKET_SCHED_MAX);

	/* Initialize all the root buckets */
	for (uint32_t i = 0; i < TH_BUCKET_SCHED_MAX; i++) {
		sched_clutch_root_bucket_init(&root_clutch->scr_buckets[i], i);
	}
}

/*
 * sched_clutch_root_bucket_init()
 *
 * Routine to initialize root buckets.
 */
static void
sched_clutch_root_bucket_init(
	sched_clutch_root_bucket_t root_bucket,
	sched_bucket_t bucket)
{
	root_bucket->scrb_bucket = bucket;
	priority_queue_init(&root_bucket->scrb_clutch_buckets, PRIORITY_QUEUE_BUILTIN_KEY | PRIORITY_QUEUE_MAX_HEAP);
	priority_queue_entry_init(&root_bucket->scrb_pqlink);
	root_bucket->scrb_deadline = SCHED_CLUTCH_INVALID_TIME_64;
	root_bucket->scrb_warped_deadline = 0;
	root_bucket->scrb_warp_remaining = sched_clutch_root_bucket_warp[root_bucket->scrb_bucket];
}

/*
 * sched_clutch_root_bucket_pri_compare()
 *
 * Routine to compare root buckets based on the highest runnable clutch
 * bucket priorities in the root buckets.
 */
static int
sched_clutch_root_bucket_pri_compare(
	sched_clutch_root_bucket_t a,
	sched_clutch_root_bucket_t b)
{
	sched_clutch_bucket_t a_highest = sched_clutch_root_bucket_highest_clutch_bucket(a);
	sched_clutch_bucket_t b_highest = sched_clutch_root_bucket_highest_clutch_bucket(b);
	return (a_highest->scb_priority > b_highest->scb_priority) ?
	       1 : ((a_highest->scb_priority == b_highest->scb_priority) ? 0 : -1);
}

/*
 * sched_clutch_root_select_aboveui()
 *
 * Special case scheduling for Above UI bucket.
 *
 * AboveUI threads are typically system critical threads that need low latency
 * which is why they are handled specially.
 *
 * Since the priority range for AboveUI and FG Timeshare buckets overlap, it is
 * important to maintain some native priority order between those buckets. The policy
 * implemented here is to compare the highest clutch buckets of both buckets; if the
 * Above UI bucket is higher, schedule it immediately. Otherwise fall through to the
 * deadline based scheduling which should pickup the timeshare buckets.
 *
 * The implementation allows extremely low latency CPU access for Above UI threads
 * while supporting the use case of high priority timeshare threads contending with
 * lower priority fixed priority threads.
 */
static boolean_t
sched_clutch_root_select_aboveui(
	sched_clutch_root_t root_clutch)
{
	if (bitmap_test(root_clutch->scr_runnable_bitmap, TH_BUCKET_FIXPRI)) {
		sched_clutch_root_bucket_t root_bucket_aboveui = &root_clutch->scr_buckets[TH_BUCKET_FIXPRI];
		sched_clutch_root_bucket_t root_bucket_sharefg = &root_clutch->scr_buckets[TH_BUCKET_SHARE_FG];

		if (!bitmap_test(root_clutch->scr_runnable_bitmap, TH_BUCKET_SHARE_FG)) {
			/* If the timeshare FG bucket is not runnable, pick the aboveUI bucket for scheduling */
			return true;
		}
		if (sched_clutch_root_bucket_pri_compare(root_bucket_aboveui, root_bucket_sharefg) >= 0) {
			/* If the aboveUI bucket has a higher native clutch bucket priority, schedule it */
			return true;
		}
	}
	return false;
}


/*
 * sched_clutch_root_highest_root_bucket()
 *
 * Main routine to find the highest runnable root level bucket.
 * This routine is called from performance sensitive contexts; so it is
 * crucial to keep this O(1).
 *
 */
static sched_clutch_root_bucket_t
sched_clutch_root_highest_root_bucket(
	sched_clutch_root_t root_clutch,
	uint64_t timestamp)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
	if (bitmap_lsb_first(root_clutch->scr_runnable_bitmap, TH_BUCKET_SCHED_MAX) == -1) {
		return NULL;
	}

	if (sched_clutch_root_select_aboveui(root_clutch)) {
		return &root_clutch->scr_buckets[TH_BUCKET_FIXPRI];
	}

	/*
	 * Above UI bucket is not runnable or has a low priority clutch bucket; use the earliest deadline model
	 * to schedule threads. The idea is that as the timeshare buckets use CPU, they will drop their
	 * interactivity score and allow low priority AboveUI clutch buckets to be scheduled.
	 */

	/* Find the earliest deadline bucket */
	sched_clutch_root_bucket_t edf_bucket = priority_queue_min(&root_clutch->scr_root_buckets, struct sched_clutch_root_bucket, scrb_pqlink);

	sched_clutch_root_bucket_t warp_bucket = NULL;
	int warp_bucket_index = -1;
evaluate_warp_buckets:
	/* Check if any higher runnable buckets have warp available */
	warp_bucket_index = bitmap_lsb_first(root_clutch->scr_warp_available, TH_BUCKET_SCHED_MAX);

	if ((warp_bucket_index == -1) || (warp_bucket_index >= edf_bucket->scrb_bucket)) {
		/* No higher buckets have warp available; choose the edf bucket and replenish its warp */
		sched_clutch_root_bucket_deadline_update(edf_bucket, root_clutch, timestamp);
		edf_bucket->scrb_warp_remaining = sched_clutch_root_bucket_warp[edf_bucket->scrb_bucket];
		edf_bucket->scrb_warped_deadline = SCHED_CLUTCH_ROOT_BUCKET_WARP_UNUSED;
		bitmap_set(root_clutch->scr_warp_available, edf_bucket->scrb_bucket);
		return edf_bucket;
	}

	/*
	 * Looks like there is a root bucket which is higher in the natural priority
	 * order than edf_bucket and might have some warp remaining.
	 */
	warp_bucket = &root_clutch->scr_buckets[warp_bucket_index];
	if (warp_bucket->scrb_warped_deadline == SCHED_CLUTCH_ROOT_BUCKET_WARP_UNUSED) {
		/* Root bucket has not used any of its warp; set a deadline to expire its warp and return it */
		warp_bucket->scrb_warped_deadline = timestamp + warp_bucket->scrb_warp_remaining;
		sched_clutch_root_bucket_deadline_update(warp_bucket, root_clutch, timestamp);
		return warp_bucket;
	}
	if (warp_bucket->scrb_warped_deadline > timestamp) {
		/* Root bucket already has a warp window open with some warp remaining */
		sched_clutch_root_bucket_deadline_update(warp_bucket, root_clutch, timestamp);
		return warp_bucket;
	}

	/* For this bucket, warp window was opened sometime in the past but has now
	 * expired. Mark the bucket as not avilable for warp anymore and re-run the
	 * warp bucket selection logic.
	 */
	warp_bucket->scrb_warp_remaining = 0;
	bitmap_clear(root_clutch->scr_warp_available, warp_bucket->scrb_bucket);
	goto evaluate_warp_buckets;
}

/*
 * sched_clutch_root_bucket_deadline_calculate()
 *
 * Calculate the deadline for the bucket based on its WCEL
 */
static uint64_t
sched_clutch_root_bucket_deadline_calculate(
	sched_clutch_root_bucket_t root_bucket,
	uint64_t timestamp)
{
	/* For fixpri AboveUI bucket always return it as the earliest deadline */
	if (root_bucket->scrb_bucket < TH_BUCKET_SHARE_FG) {
		return 0;
	}

	/* For all timeshare buckets set the deadline as current time + worst-case-execution-latency */
	return timestamp + sched_clutch_root_bucket_wcel[root_bucket->scrb_bucket];
}

/*
 * sched_clutch_root_bucket_deadline_update()
 *
 * Routine to update the deadline of the root bucket when it is selected.
 * Updating the deadline also moves the root_bucket in the EDF priority
 * queue.
 */
static void
sched_clutch_root_bucket_deadline_update(
	sched_clutch_root_bucket_t root_bucket,
	sched_clutch_root_t root_clutch,
	uint64_t timestamp)
{
	if (root_bucket->scrb_bucket == TH_BUCKET_FIXPRI) {
		/* The algorithm never uses the deadlines for scheduling TH_BUCKET_FIXPRI bucket */
		return;
	}
	uint64_t old_deadline = root_bucket->scrb_deadline;
	uint64_t new_deadline = sched_clutch_root_bucket_deadline_calculate(root_bucket, timestamp);
	assert(old_deadline <= new_deadline);
	if (old_deadline != new_deadline) {
		root_bucket->scrb_deadline = new_deadline;
		/* Since the priority queue is a min-heap, use the decrease routine even though the deadline has a larger value now */
		priority_queue_entry_decrease(&root_clutch->scr_root_buckets, &root_bucket->scrb_pqlink, PRIORITY_QUEUE_KEY_NONE, sched_clutch_root_bucket_compare);
	}
}

/*
 * sched_clutch_root_bucket_runnable()
 *
 * Routine to insert a newly runnable root bucket into the hierarchy.
 * Also updates the deadline and warp parameters as necessary.
 */
static void
sched_clutch_root_bucket_runnable(
	sched_clutch_root_bucket_t root_bucket,
	sched_clutch_root_t root_clutch,
	uint64_t timestamp)
{
	/* Mark the root bucket as runnable */
	bitmap_set(root_clutch->scr_runnable_bitmap, root_bucket->scrb_bucket);
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_CLUTCH_ROOT_BUCKET_STATE) | DBG_FUNC_NONE,
	    root_bucket->scrb_bucket, SCHED_CLUTCH_STATE_RUNNABLE, 0, 0, 0);

	if (root_bucket->scrb_bucket == TH_BUCKET_FIXPRI) {
		/* Since the TH_BUCKET_FIXPRI bucket is not scheduled based on deadline, nothing more needed here */
		return;
	}

	root_bucket->scrb_deadline = sched_clutch_root_bucket_deadline_calculate(root_bucket, timestamp);
	priority_queue_insert(&root_clutch->scr_root_buckets, &root_bucket->scrb_pqlink, PRIORITY_QUEUE_KEY_NONE, sched_clutch_root_bucket_compare);

	if (root_bucket->scrb_warp_remaining) {
		/* Since the bucket has some warp remaining and its now runnable, mark it as available for warp */
		bitmap_set(root_clutch->scr_warp_available, root_bucket->scrb_bucket);
	}
}

/*
 * sched_clutch_root_bucket_empty()
 *
 * Routine to remove an empty root bucket from the hierarchy.
 * Also updates the deadline and warp parameters as necessary.
 */
static void
sched_clutch_root_bucket_empty(
	sched_clutch_root_bucket_t root_bucket,
	sched_clutch_root_t root_clutch,
	uint64_t timestamp)
{
	bitmap_clear(root_clutch->scr_runnable_bitmap, root_bucket->scrb_bucket);
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_CLUTCH_ROOT_BUCKET_STATE) | DBG_FUNC_NONE,
	    root_bucket->scrb_bucket, SCHED_CLUTCH_STATE_EMPTY, 0, 0, 0);

	if (root_bucket->scrb_bucket == TH_BUCKET_FIXPRI) {
		/* Since the TH_BUCKET_FIXPRI bucket is not scheduled based on deadline, nothing more needed here */
		return;
	}

	priority_queue_remove(&root_clutch->scr_root_buckets, &root_bucket->scrb_pqlink, sched_clutch_root_bucket_compare);

	bitmap_clear(root_clutch->scr_warp_available, root_bucket->scrb_bucket);
	if (root_bucket->scrb_warped_deadline > timestamp) {
		/*
		 * For root buckets that were using the warp, check if the warp
		 * deadline is in the future. If yes, remove the wall time the
		 * warp was active and update the warp remaining. This allows
		 * the root bucket to use the remaining warp the next time it
		 * becomes runnable.
		 */
		root_bucket->scrb_warp_remaining = root_bucket->scrb_warped_deadline - timestamp;
	} else if (root_bucket->scrb_warped_deadline != SCHED_CLUTCH_ROOT_BUCKET_WARP_UNUSED) {
		/*
		 * If the root bucket's warped deadline is in the past, it has used up
		 * all the warp it was assigned. Empty out its warp remaining.
		 */
		root_bucket->scrb_warp_remaining = 0;
	}
}

/*
 * sched_clutch_root_pri_update()
 *
 * The root level priority is used for thread selection and preemption
 * logic.
 */
static void
sched_clutch_root_pri_update(
	sched_clutch_root_t root_clutch)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
	if (bitmap_lsb_first(root_clutch->scr_runnable_bitmap, TH_BUCKET_SCHED_MAX) == -1) {
		/* No runnable root buckets */
		root_clutch->scr_priority = NOPRI;
		assert(root_clutch->scr_urgency == 0);
		return;
	}
	sched_clutch_root_bucket_t root_bucket = NULL;
	/* Special case for AboveUI (uses same logic as thread selection) */
	if (sched_clutch_root_select_aboveui(root_clutch)) {
		root_bucket = &root_clutch->scr_buckets[TH_BUCKET_FIXPRI];
	} else {
		/*
		 * AboveUI bucket is not runnable or has a low clutch bucket priority,
		 * select the next runnable root bucket in natural priority order. This logic
		 * is slightly different from thread selection, because thread selection
		 * considers deadlines, warps etc. to decide the most optimal bucket at a
		 * given timestamp. Since the priority value is used for preemption decisions
		 * only, it needs to be based on the highest runnable thread available in
		 * the timeshare domain.
		 */
		int root_bucket_index = bitmap_lsb_next(root_clutch->scr_runnable_bitmap, TH_BUCKET_SCHED_MAX, TH_BUCKET_FIXPRI);
		assert(root_bucket_index != -1);
		root_bucket = &root_clutch->scr_buckets[root_bucket_index];
	}
	/* For the selected root bucket, find the highest priority clutch bucket */
	sched_clutch_bucket_t clutch_bucket = sched_clutch_root_bucket_highest_clutch_bucket(root_bucket);
	root_clutch->scr_priority = priority_queue_max_key(&clutch_bucket->scb_clutchpri_prioq);
}

/*
 * sched_clutch_root_urgency_inc()
 *
 * Routine to increment the urgency at the root level based on the thread
 * priority that is being inserted into the hierarchy. The root urgency
 * counter is updated based on the urgency of threads in any of the
 * clutch buckets which are part of the hierarchy.
 *
 * Always called with the pset lock held.
 */
static void
sched_clutch_root_urgency_inc(
	sched_clutch_root_t root_clutch,
	thread_t thread)
{
	if (SCHED(priority_is_urgent)(thread->sched_pri)) {
		root_clutch->scr_urgency++;
	}
}

/*
 * sched_clutch_root_urgency_dec()
 *
 * Routine to decrement the urgency at the root level based on the thread
 * priority that is being removed from the hierarchy. The root urgency
 * counter is updated based on the urgency of threads in any of the
 * clutch buckets which are part of the hierarchy.
 *
 * Always called with the pset lock held.
 */
static void
sched_clutch_root_urgency_dec(
	sched_clutch_root_t root_clutch,
	thread_t thread)
{
	if (SCHED(priority_is_urgent)(thread->sched_pri)) {
		root_clutch->scr_urgency--;
	}
}

/*
 * Clutch bucket level scheduling
 *
 * The second level of scheduling is the clutch bucket level scheduling
 * which tries to schedule thread groups within root_buckets. Each
 * clutch represents a thread group and a clutch_bucket represents
 * threads at a particular sched_bucket within that thread group. The
 * goal of this level of scheduling is to allow interactive thread
 * groups low latency access to the CPU. It also provides slight
 * scheduling preference for App and unrestricted thread groups.
 *
 * The clutch bucket scheduling algorithm measures an interactivity
 * score for all clutch buckets. The interactivity score is based
 * on the ratio of the CPU used and the voluntary blocking of threads
 * within the clutch bucket. The algorithm is very close to the ULE
 * scheduler on FreeBSD in terms of calculations. The interactivity
 * score provides an interactivity boost in the range of
 * [0:SCHED_CLUTCH_BUCKET_INTERACTIVE_PRI * 2] which allows interactive
 * thread groups to win over CPU spinners.
 */

/* Priority boost range for interactivity */
#define SCHED_CLUTCH_BUCKET_INTERACTIVE_PRI_DEFAULT     (8)
uint8_t sched_clutch_bucket_interactive_pri = SCHED_CLUTCH_BUCKET_INTERACTIVE_PRI_DEFAULT;

/* window to scale the cpu usage and blocked values (currently 500ms). Its the threshold of used+blocked */
uint64_t sched_clutch_bucket_adjust_threshold = 0;
#define SCHED_CLUTCH_BUCKET_ADJUST_THRESHOLD_USECS      (500000)

/* The ratio to scale the cpu/blocked time per window */
#define SCHED_CLUTCH_BUCKET_ADJUST_RATIO                (10)

/* rate at which interactivity score is recalculated. This keeps the score smooth in terms of extremely bursty behavior */
uint64_t sched_clutch_bucket_interactivity_delta = 0;
#define SCHED_CLUTCH_BUCKET_INTERACTIVITY_DELTA_USECS_DEFAULT   (25000)

/*
 * In order to allow App thread groups some preference over daemon thread
 * groups, the App clutch_buckets get a 8 point boost. The boost value should
 * be chosen such that badly behaved apps are still penalized over well
 * behaved interactive daemon clutch_buckets.
 */
#define SCHED_CLUTCH_BUCKET_PRI_BOOST_DEFAULT           (8)
uint8_t sched_clutch_bucket_pri_boost = SCHED_CLUTCH_BUCKET_PRI_BOOST_DEFAULT;

/* Initial value for voluntary blocking time for the clutch_bucket */
#define SCHED_CLUTCH_BUCKET_BLOCKED_TS_INVALID  (uint32_t)(~0)

/*
 * sched_clutch_bucket_init()
 *
 * Initializer for clutch buckets.
 */
static void
sched_clutch_bucket_init(
	sched_clutch_bucket_t clutch_bucket,
	sched_clutch_t clutch,
	sched_bucket_t bucket)
{
	bzero(clutch_bucket, sizeof(struct sched_clutch_bucket));

	clutch_bucket->scb_bucket = bucket;
	/* scb_priority will be recalculated when a thread is inserted in the clutch bucket */
	clutch_bucket->scb_priority = 0;
	/*
	 * All thread groups should be initialized to be interactive; this allows the newly launched
	 * thread groups to fairly compete with already running thread groups.
	 */
	clutch_bucket->scb_interactivity_score = (sched_clutch_bucket_interactive_pri * 2);
	clutch_bucket->scb_foreign = false;

	os_atomic_store(&clutch_bucket->scb_timeshare_tick, 0, relaxed);
	os_atomic_store(&clutch_bucket->scb_pri_shift, INT8_MAX, relaxed);

	clutch_bucket->scb_interactivity_ts = 0;
	clutch_bucket->scb_blocked_ts = SCHED_CLUTCH_BUCKET_BLOCKED_TS_INVALID;
	priority_queue_entry_init(&clutch_bucket->scb_pqlink);
	clutch_bucket->scb_clutch = clutch;
	clutch_bucket->scb_root = NULL;
	priority_queue_init(&clutch_bucket->scb_clutchpri_prioq, PRIORITY_QUEUE_BUILTIN_KEY | PRIORITY_QUEUE_MAX_HEAP);
	run_queue_init(&clutch_bucket->scb_runq);
}

/*
 * sched_clutch_init_with_thread_group()
 *
 * Initialize the sched_clutch when the thread group is being created
 */
void
sched_clutch_init_with_thread_group(
	sched_clutch_t clutch,
	struct thread_group *tg)
{
	os_atomic_store(&clutch->sc_thr_count, 0, relaxed);

	/* Initialize all the clutch buckets */
	for (uint32_t i = 0; i < TH_BUCKET_SCHED_MAX; i++) {
		sched_clutch_bucket_init(&(clutch->sc_clutch_buckets[i]), clutch, i);
	}

	/* Grouping specific fields */
	clutch->sc_tg = tg;
	os_atomic_store(&clutch->sc_tg_priority, 0, relaxed);
}

/*
 * sched_clutch_destroy()
 *
 * Destructor for clutch; called from thread group release code.
 */
void
sched_clutch_destroy(
	__unused sched_clutch_t clutch)
{
	assert(os_atomic_load(&clutch->sc_thr_count, relaxed) == 0);
}


/*
 * sched_clutch_bucket_hierarchy_insert()
 *
 * Routine to insert a newly runnable clutch_bucket into the root hierarchy.
 */
static void
sched_clutch_bucket_hierarchy_insert(
	sched_clutch_root_t root_clutch,
	sched_clutch_bucket_t clutch_bucket,
	sched_bucket_t bucket,
	uint64_t timestamp)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
	if (bucket > TH_BUCKET_FIXPRI) {
		/* Enqueue the timeshare clutch buckets into the global runnable clutch_bucket list; used for sched tick operations */
		enqueue_tail(&root_clutch->scr_clutch_buckets, &clutch_bucket->scb_listlink);
	}
	sched_clutch_root_bucket_t root_bucket = &root_clutch->scr_buckets[bucket];

	/* If this is the first clutch bucket in the root bucket, insert the root bucket into the root priority queue */
	if (priority_queue_empty(&root_bucket->scrb_clutch_buckets)) {
		sched_clutch_root_bucket_runnable(root_bucket, root_clutch, timestamp);
	}

	/* Insert the clutch bucket into the root bucket priority queue */
	priority_queue_insert(&root_bucket->scrb_clutch_buckets, &clutch_bucket->scb_pqlink, clutch_bucket->scb_priority, PRIORITY_QUEUE_SCHED_PRI_MAX_HEAP_COMPARE);
	os_atomic_store(&clutch_bucket->scb_root, root_clutch, relaxed);
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_CLUTCH_TG_BUCKET_STATE) | DBG_FUNC_NONE,
	    thread_group_get_id(clutch_bucket->scb_clutch->sc_tg), clutch_bucket->scb_bucket, SCHED_CLUTCH_STATE_RUNNABLE, clutch_bucket->scb_priority, 0);
}

/*
 * sched_clutch_bucket_hierarchy_remove()
 *
 * Rotuine to remove a empty clutch bucket from the root hierarchy.
 */
static void
sched_clutch_bucket_hierarchy_remove(
	sched_clutch_root_t root_clutch,
	sched_clutch_bucket_t clutch_bucket,
	sched_bucket_t bucket,
	uint64_t timestamp)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
	if (bucket > TH_BUCKET_FIXPRI) {
		/* Remove the timeshare clutch bucket from the globally runnable clutch_bucket list */
		remqueue(&clutch_bucket->scb_listlink);
	}

	sched_clutch_root_bucket_t root_bucket = &root_clutch->scr_buckets[bucket];

	/* Remove the clutch bucket from the root bucket priority queue */
	priority_queue_remove(&root_bucket->scrb_clutch_buckets, &clutch_bucket->scb_pqlink, PRIORITY_QUEUE_SCHED_PRI_MAX_HEAP_COMPARE);
	os_atomic_store(&clutch_bucket->scb_root, NULL, relaxed);
	clutch_bucket->scb_blocked_ts = timestamp;
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_CLUTCH_TG_BUCKET_STATE) | DBG_FUNC_NONE,
	    thread_group_get_id(clutch_bucket->scb_clutch->sc_tg), clutch_bucket->scb_bucket, SCHED_CLUTCH_STATE_EMPTY, 0, 0);

	/* If the root bucket priority queue is now empty, remove it from the root priority queue */
	if (priority_queue_empty(&root_bucket->scrb_clutch_buckets)) {
		sched_clutch_root_bucket_empty(root_bucket, root_clutch, timestamp);
	}
}

/*
 * sched_clutch_bucket_base_pri()
 *
 * Calculates the "base" priority of the clutch bucket. The base
 * priority of the clutch bucket is the sum of the max of highest
 * base_pri and highest sched_pri in the clutch bucket and any
 * grouping specific (App/Daemon...) boosts applicable to the
 * clutch_bucket.
 */
static uint8_t
sched_clutch_bucket_base_pri(
	sched_clutch_bucket_t clutch_bucket)
{
	uint8_t clutch_boost = 0;
	assert(clutch_bucket->scb_runq.count != 0);

	sched_clutch_t clutch = clutch_bucket->scb_clutch;

	/*
	 * Since the clutch bucket can contain threads that are members of the group due
	 * to the sched_pri being promoted or due to their base pri, the base priority of
	 * the entire clutch bucket should be based on the highest thread (promoted or base)
	 * in the clutch bucket.
	 */
	uint8_t max_pri = priority_queue_empty(&clutch_bucket->scb_clutchpri_prioq) ? 0 : priority_queue_max_key(&clutch_bucket->scb_clutchpri_prioq);

	/*
	 * For all AboveUI clutch buckets and clutch buckets for thread groups that
	 * havent been specified as SCHED_CLUTCH_TG_PRI_LOW, give a priority boost
	 */
	if ((clutch_bucket->scb_bucket == TH_BUCKET_FIXPRI) ||
	    (os_atomic_load(&clutch->sc_tg_priority, relaxed) != SCHED_CLUTCH_TG_PRI_LOW)) {
		clutch_boost = sched_clutch_bucket_pri_boost;
	}
	return max_pri + clutch_boost;
}

/*
 * sched_clutch_bucket_interactivity_score_calculate()
 *
 * Routine to calculate the interactivity score for the clutch bucket. The
 * interactivity score is based on the ratio of CPU used by all threads in
 * the bucket and the blocked time of the bucket as a whole.
 */
static uint8_t
sched_clutch_bucket_interactivity_score_calculate(
	sched_clutch_bucket_t clutch_bucket,
	uint64_t timestamp)
{
	if (clutch_bucket->scb_bucket == TH_BUCKET_FIXPRI) {
		/*
		 * Since the root bucket selection algorithm for Above UI looks at clutch bucket
		 * priorities, make sure all AboveUI buckets are marked interactive.
		 */
		assert(clutch_bucket->scb_interactivity_score == (2 * sched_clutch_bucket_interactive_pri));
		return clutch_bucket->scb_interactivity_score;
	}

	if (clutch_bucket->scb_interactivity_ts == 0) {
		/*
		 * This indicates a newly initialized clutch bucket; return the default interactivity score
		 * and update timestamp.
		 */
		clutch_bucket->scb_interactivity_ts = timestamp;
		return clutch_bucket->scb_interactivity_score;
	}

	if (timestamp < (clutch_bucket->scb_interactivity_ts + sched_clutch_bucket_interactivity_delta)) {
		return clutch_bucket->scb_interactivity_score;
	}

	/* Check if the clutch bucket accounting needs to be scaled */
	sched_clutch_bucket_cpu_adjust(clutch_bucket);
	clutch_bucket->scb_interactivity_ts = timestamp;

	sched_clutch_bucket_cpu_data_t scb_cpu_data;
	scb_cpu_data.scbcd_cpu_data_packed = os_atomic_load_wide(&clutch_bucket->scb_cpu_data.scbcd_cpu_data_packed, relaxed);
	clutch_cpu_data_t cpu_used = scb_cpu_data.cpu_data.scbcd_cpu_used;
	clutch_cpu_data_t cpu_blocked = scb_cpu_data.cpu_data.scbcd_cpu_blocked;

	/*
	 * In extremely CPU contended cases, it is possible that the clutch bucket has been runnable
	 * for a long time but none of its threads have been picked up for execution. In that case, both
	 * the CPU used and blocked would be 0.
	 */
	if ((cpu_blocked == 0) && (cpu_used == 0)) {
		return clutch_bucket->scb_interactivity_score;
	}

	/*
	 * For all timeshare buckets, calculate the interactivity score of the bucket
	 * and add it to the base priority
	 */
	uint8_t interactive_score = 0;
	if (cpu_blocked > cpu_used) {
		/* Interactive clutch_bucket case */
		interactive_score = sched_clutch_bucket_interactive_pri +
		    ((sched_clutch_bucket_interactive_pri * (cpu_blocked - cpu_used)) / cpu_blocked);
	} else {
		/* Non-interactive clutch_bucket case */
		interactive_score = ((sched_clutch_bucket_interactive_pri * cpu_blocked) / cpu_used);
	}
	clutch_bucket->scb_interactivity_score = interactive_score;
	return interactive_score;
}

/*
 * sched_clutch_bucket_pri_calculate()
 *
 * The priority calculation algorithm for the clutch_bucket is a slight
 * modification on the ULE interactivity score. It uses the base priority
 * of the clutch bucket and applies an interactivity score boost to the
 * highly responsive clutch buckets.
 */

static uint8_t
sched_clutch_bucket_pri_calculate(
	sched_clutch_bucket_t clutch_bucket,
	uint64_t timestamp)
{
	/* For empty clutch buckets, return priority 0 */
	if (clutch_bucket->scb_thr_count == 0) {
		return 0;
	}

	uint8_t base_pri = sched_clutch_bucket_base_pri(clutch_bucket);
	uint8_t interactive_score = sched_clutch_bucket_interactivity_score_calculate(clutch_bucket, timestamp);

	assert(((uint64_t)base_pri + interactive_score) <= UINT8_MAX);
	uint8_t pri = base_pri + interactive_score;
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_CLUTCH_TG_BUCKET_PRI) | DBG_FUNC_NONE,
	    thread_group_get_id(clutch_bucket->scb_clutch->sc_tg), clutch_bucket->scb_bucket, pri, interactive_score, 0);
	return pri;
}

/*
 * sched_clutch_root_bucket_highest_clutch_bucket()
 *
 * Routine to find the highest priority clutch bucket
 * within the root bucket.
 */
static sched_clutch_bucket_t
sched_clutch_root_bucket_highest_clutch_bucket(
	sched_clutch_root_bucket_t root_bucket)
{
	if (priority_queue_empty(&root_bucket->scrb_clutch_buckets)) {
		return NULL;
	}
	return priority_queue_max(&root_bucket->scrb_clutch_buckets, struct sched_clutch_bucket, scb_pqlink);
}

/*
 * sched_clutch_bucket_runnable()
 *
 * Perform all operations needed when a new clutch bucket becomes runnable.
 * It involves inserting the clutch_bucket into the hierarchy and updating the
 * root priority appropriately.
 */
static boolean_t
sched_clutch_bucket_runnable(
	sched_clutch_bucket_t clutch_bucket,
	sched_clutch_root_t root_clutch,
	uint64_t timestamp)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
	sched_clutch_bucket_cpu_blocked_update(clutch_bucket, timestamp);
	clutch_bucket->scb_priority = sched_clutch_bucket_pri_calculate(clutch_bucket, timestamp);
	sched_clutch_bucket_hierarchy_insert(root_clutch, clutch_bucket, clutch_bucket->scb_bucket, timestamp);
	/* Update the timesharing properties of this clutch_bucket; also done every sched_tick */
	sched_clutch_bucket_timeshare_update(clutch_bucket);
	int16_t root_old_pri = root_clutch->scr_priority;
	sched_clutch_root_pri_update(root_clutch);
	return root_clutch->scr_priority > root_old_pri;
}

/*
 * sched_clutch_bucket_update()
 *
 * Update the clutch_bucket's position in the hierarchy based on whether
 * the newly runnable thread changes its priority. Also update the root
 * priority accordingly.
 */
static boolean_t
sched_clutch_bucket_update(
	sched_clutch_bucket_t clutch_bucket,
	sched_clutch_root_t root_clutch,
	uint64_t timestamp)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
	uint64_t new_pri = sched_clutch_bucket_pri_calculate(clutch_bucket, timestamp);
	if (new_pri == clutch_bucket->scb_priority) {
		return false;
	}
	struct priority_queue *bucket_prioq = &root_clutch->scr_buckets[clutch_bucket->scb_bucket].scrb_clutch_buckets;

	if (new_pri < clutch_bucket->scb_priority) {
		clutch_bucket->scb_priority = new_pri;
		priority_queue_entry_decrease(bucket_prioq, &clutch_bucket->scb_pqlink,
		    clutch_bucket->scb_priority, PRIORITY_QUEUE_SCHED_PRI_MAX_HEAP_COMPARE);
	} else {
		clutch_bucket->scb_priority = new_pri;
		priority_queue_entry_increase(bucket_prioq, &clutch_bucket->scb_pqlink,
		    clutch_bucket->scb_priority, PRIORITY_QUEUE_SCHED_PRI_MAX_HEAP_COMPARE);
	}

	int16_t root_old_pri = root_clutch->scr_priority;
	sched_clutch_root_pri_update(root_clutch);
	return root_clutch->scr_priority > root_old_pri;
}

/*
 * sched_clutch_bucket_empty()
 *
 * Perform all the operations needed when a clutch_bucket is no longer runnable.
 * It involves removing the clutch bucket from the hierarchy and updaing the root
 * priority appropriately.
 */
static void
sched_clutch_bucket_empty(
	sched_clutch_bucket_t clutch_bucket,
	sched_clutch_root_t root_clutch,
	uint64_t timestamp)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
	sched_clutch_bucket_hierarchy_remove(root_clutch, clutch_bucket, clutch_bucket->scb_bucket, timestamp);
	clutch_bucket->scb_priority = sched_clutch_bucket_pri_calculate(clutch_bucket, timestamp);
	sched_clutch_root_pri_update(root_clutch);
}

/*
 * sched_clutch_cpu_usage_update()
 *
 * Routine to update CPU usage of the thread in the hierarchy.
 */
void
sched_clutch_cpu_usage_update(
	thread_t thread,
	uint64_t delta)
{
	if (!SCHED_CLUTCH_THREAD_ELIGIBLE(thread)) {
		return;
	}
	sched_clutch_t clutch = sched_clutch_for_thread(thread);
	sched_clutch_bucket_t clutch_bucket = &(clutch->sc_clutch_buckets[thread->th_sched_bucket]);
	sched_clutch_bucket_cpu_usage_update(clutch_bucket, delta);
}

/*
 * sched_clutch_bucket_cpu_usage_update()
 *
 * Routine to update the CPU usage of the clutch_bucket.
 */
static void
sched_clutch_bucket_cpu_usage_update(
	sched_clutch_bucket_t clutch_bucket,
	uint64_t delta)
{
	if (clutch_bucket->scb_bucket == TH_BUCKET_FIXPRI) {
		/* Since Above UI bucket has maximum interactivity score always, nothing to do here */
		return;
	}

	/*
	 * The CPU usage should not overflow the clutch_cpu_data_t type. Since the usage is used to
	 * calculate interactivity score, it is safe to restrict it to CLUTCH_CPU_DATA_MAX.
	 */
	delta = MIN(delta, CLUTCH_CPU_DATA_MAX);
	os_atomic_add_orig(&(clutch_bucket->scb_cpu_data.cpu_data.scbcd_cpu_used), (clutch_cpu_data_t)delta, relaxed);
}

/*
 * sched_clutch_bucket_cpu_blocked_update()
 *
 * Routine to update CPU blocked time for clutch_bucket.
 */
static void
sched_clutch_bucket_cpu_blocked_update(
	sched_clutch_bucket_t clutch_bucket,
	uint64_t timestamp)
{
	if ((clutch_bucket->scb_bucket == TH_BUCKET_FIXPRI) ||
	    (clutch_bucket->scb_blocked_ts == SCHED_CLUTCH_BUCKET_BLOCKED_TS_INVALID)) {
		/* For Above UI bucket and a newly initialized clutch bucket, nothing to do here */
		return;
	}

	uint64_t blocked_time = timestamp - clutch_bucket->scb_blocked_ts;
	if (blocked_time > sched_clutch_bucket_adjust_threshold) {
		blocked_time = sched_clutch_bucket_adjust_threshold;
	}

	/*
	 * The CPU blocked should not overflow the clutch_cpu_data_t type. Since the blocked is used to
	 * calculate interactivity score, it is safe to restrict it to CLUTCH_CPU_DATA_MAX.
	 */
	blocked_time = MIN(blocked_time, CLUTCH_CPU_DATA_MAX);
	clutch_cpu_data_t __assert_only cpu_blocked_orig = os_atomic_add_orig(&(clutch_bucket->scb_cpu_data.cpu_data.scbcd_cpu_blocked), (clutch_cpu_data_t)blocked_time, relaxed);
	/* The blocked time is scaled every so often, it should never overflow */
	assert(blocked_time <= (CLUTCH_CPU_DATA_MAX - cpu_blocked_orig));
}

/*
 * sched_clutch_bucket_cpu_adjust()
 *
 * Routine to scale the cpu usage and blocked time once the sum gets bigger
 * than sched_clutch_bucket_adjust_threshold. Allows the values to remain
 * manageable and maintain the same ratio while allowing clutch buckets to
 * adjust behavior and reflect in the interactivity score in a reasonable
 * amount of time.
 */
static void
sched_clutch_bucket_cpu_adjust(
	sched_clutch_bucket_t clutch_bucket)
{
	sched_clutch_bucket_cpu_data_t old_cpu_data = {};
	sched_clutch_bucket_cpu_data_t new_cpu_data = {};
	do {
		old_cpu_data.scbcd_cpu_data_packed = os_atomic_load_wide(&clutch_bucket->scb_cpu_data.scbcd_cpu_data_packed, relaxed);
		clutch_cpu_data_t cpu_used = old_cpu_data.cpu_data.scbcd_cpu_used;
		clutch_cpu_data_t cpu_blocked = old_cpu_data.cpu_data.scbcd_cpu_blocked;
		if ((cpu_used + cpu_blocked) < sched_clutch_bucket_adjust_threshold) {
			return;
		}

		/*
		 * The accumulation of CPU used and blocked is past the threshold; scale it
		 * down to lose old history.
		 */
		new_cpu_data.cpu_data.scbcd_cpu_used = cpu_used / SCHED_CLUTCH_BUCKET_ADJUST_RATIO;
		new_cpu_data.cpu_data.scbcd_cpu_blocked = cpu_blocked / SCHED_CLUTCH_BUCKET_ADJUST_RATIO;
	} while (!os_atomic_cmpxchg(&clutch_bucket->scb_cpu_data.scbcd_cpu_data_packed, old_cpu_data.scbcd_cpu_data_packed, new_cpu_data.scbcd_cpu_data_packed, relaxed));
}

/*
 * Thread level scheduling algorithm
 *
 * The thread level scheduling algorithm uses the mach timeshare
 * decay based algorithm to achieve sharing between threads within the
 * same clutch bucket. The load/priority shifts etc. are all maintained
 * at the clutch bucket level and used for decay calculation of the
 * threads. The load sampling is still driven off the scheduler tick
 * for runnable clutch buckets (it does not use the new higher frequency
 * EWMA based load calculation). The idea is that the contention and load
 * within clutch_buckets should be limited enough to not see heavy decay
 * and timeshare effectively.
 */

/*
 * sched_clutch_thread_run_bucket_incr() / sched_clutch_run_bucket_incr()
 *
 * Increment the run count for the clutch bucket associated with the
 * thread.
 */
uint32_t
sched_clutch_thread_run_bucket_incr(
	thread_t thread,
	sched_bucket_t bucket)
{
	if (!SCHED_CLUTCH_THREAD_ELIGIBLE(thread)) {
		return 0;
	}
	sched_clutch_t clutch = sched_clutch_for_thread(thread);
	return sched_clutch_run_bucket_incr(clutch, bucket);
}

static uint32_t
sched_clutch_run_bucket_incr(
	sched_clutch_t clutch,
	sched_bucket_t bucket)
{
	assert(bucket != TH_BUCKET_RUN);
	sched_clutch_bucket_t clutch_bucket = &(clutch->sc_clutch_buckets[bucket]);
	uint32_t result = os_atomic_inc(&(clutch_bucket->scb_run_count), relaxed);
	return result;
}

/*
 * sched_clutch_thread_run_bucket_decr() / sched_clutch_run_bucket_decr()
 *
 * Decrement the run count for the clutch bucket associated with the
 * thread.
 */
uint32_t
sched_clutch_thread_run_bucket_decr(
	thread_t thread,
	sched_bucket_t bucket)
{
	if (!SCHED_CLUTCH_THREAD_ELIGIBLE(thread)) {
		return 0;
	}
	sched_clutch_t clutch = sched_clutch_for_thread(thread);
	return sched_clutch_run_bucket_decr(clutch, bucket);
}

static uint32_t
sched_clutch_run_bucket_decr(
	sched_clutch_t clutch,
	sched_bucket_t bucket)
{
	assert(bucket != TH_BUCKET_RUN);
	sched_clutch_bucket_t clutch_bucket = &(clutch->sc_clutch_buckets[bucket]);
	uint32_t result = os_atomic_dec(&(clutch_bucket->scb_run_count), relaxed);
	return result;
}

/*
 * sched_clutch_bucket_timeshare_update()
 *
 * Routine to update the load and priority shift for the clutch_bucket every
 * sched_tick. For runnable clutch_buckets, the sched tick handling code
 * iterates the clutch buckets and calls this routine. For all others, the
 * clutch_bucket maintains a "last updated schedtick" parameter. As threads
 * become runnable in the clutch bucket, if this value is outdated, the load
 * and shifts are updated.
 *
 * Possible optimization:
 * - The current algorithm samples the load every sched tick (125ms).
 *   This is prone to spikes in runnable counts; if that turns out to be
 *   a problem, a simple solution would be to do the EWMA trick to sample
 *   load at every load_tick (30ms) and use the averaged value for the pri
 *   shift calculation.
 */
static void
sched_clutch_bucket_timeshare_update(
	sched_clutch_bucket_t clutch_bucket)
{
	if (clutch_bucket->scb_bucket < TH_BUCKET_SHARE_FG) {
		return;
	}

	/*
	 * Update the timeshare parameters for the clutch bucket if they havent been updated
	 * in this tick.
	 */
	uint32_t bucket_sched_ts = os_atomic_load(&clutch_bucket->scb_timeshare_tick, relaxed);
	uint32_t current_sched_ts = sched_tick;
	if (bucket_sched_ts != current_sched_ts) {
		os_atomic_store(&clutch_bucket->scb_timeshare_tick, current_sched_ts, relaxed);
		uint32_t bucket_load = (os_atomic_load(&clutch_bucket->scb_run_count, relaxed) / processor_avail_count);
		bucket_load = MIN(bucket_load, NRQS - 1);
		uint32_t pri_shift = sched_fixed_shift - sched_load_shifts[bucket_load];
		os_atomic_store(&clutch_bucket->scb_pri_shift, pri_shift, relaxed);
	}
}

/*
 * sched_clutch_thread_clutch_update()
 *
 * Routine called when the thread changes its thread group. The current
 * implementation relies on the fact that the thread group is changed only
 * from the context of the thread itself. Due to this fact, the thread
 * group change causes only counter updates in the old & new clutch
 * buckets and no hierarchy changes. The routine also attributes the CPU
 * used so far to the old clutch.
 */
void
sched_clutch_thread_clutch_update(
	thread_t thread,
	sched_clutch_t old_clutch,
	sched_clutch_t new_clutch)
{
	uint32_t cpu_delta;
	assert(current_thread() == thread);

	if (old_clutch) {
		sched_clutch_run_bucket_decr(old_clutch, thread->th_sched_bucket);
		/*
		 * Calculate the CPU used by this thread in the old bucket and
		 * add it to the old clutch bucket. This uses the same CPU usage
		 * logic as update_priority etc.
		 */
		thread_timer_delta(thread, cpu_delta);
		if (thread->pri_shift < INT8_MAX) {
			thread->sched_usage += cpu_delta;
		}
		thread->cpu_delta += cpu_delta;
		sched_clutch_bucket_cpu_usage_update(&(old_clutch->sc_clutch_buckets[thread->th_sched_bucket]), cpu_delta);
	}

	if (new_clutch) {
		sched_clutch_run_bucket_incr(new_clutch, thread->th_sched_bucket);
	}
}

/* Thread Insertion/Removal/Selection routines */

/*
 * sched_clutch_thread_insert()
 *
 * Routine to insert a thread into the sched clutch hierarchy.
 * Update the counts at all levels of the hierarchy and insert the nodes
 * as they become runnable. Always called with the pset lock held.
 */
static boolean_t
sched_clutch_thread_insert(
	sched_clutch_root_t root_clutch,
	thread_t thread,
	integer_t options)
{
	boolean_t result = FALSE;

	sched_clutch_hierarchy_locked_assert(root_clutch);
	sched_clutch_t clutch = sched_clutch_for_thread(thread);
	assert(thread->thread_group == clutch->sc_tg);

	uint64_t current_timestamp = mach_absolute_time();
	sched_clutch_bucket_t clutch_bucket = &(clutch->sc_clutch_buckets[thread->th_sched_bucket]);
	assert((clutch_bucket->scb_root == NULL) || (clutch_bucket->scb_root == root_clutch));

	/* Insert thread into the clutch_bucket runq using sched_pri */
	run_queue_enqueue(&clutch_bucket->scb_runq, thread, options);
	/* Increment the urgency counter for the root if necessary */
	sched_clutch_root_urgency_inc(root_clutch, thread);

	/* Insert thread into clutch_bucket priority queue based on the promoted or base priority */
	priority_queue_insert(&clutch_bucket->scb_clutchpri_prioq, &thread->sched_clutchpri_link,
	    sched_thread_sched_pri_promoted(thread) ? thread->sched_pri : thread->base_pri,
	    PRIORITY_QUEUE_SCHED_PRI_MAX_HEAP_COMPARE);
	os_atomic_inc(&clutch->sc_thr_count, relaxed);
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_CLUTCH_THREAD_STATE) | DBG_FUNC_NONE,
	    thread_group_get_id(clutch_bucket->scb_clutch->sc_tg), clutch_bucket->scb_bucket, thread_tid(thread), SCHED_CLUTCH_STATE_RUNNABLE, 0);

	/* Enqueue the clutch into the hierarchy (if needed) and update properties */
	if (clutch_bucket->scb_thr_count == 0) {
		sched_clutch_thr_count_inc(&clutch_bucket->scb_thr_count);
		sched_clutch_thr_count_inc(&root_clutch->scr_thr_count);
		/* Insert the newly runnable clutch bucket into the hierarchy */
		result = sched_clutch_bucket_runnable(clutch_bucket, root_clutch, current_timestamp);
	} else {
		sched_clutch_thr_count_inc(&clutch_bucket->scb_thr_count);
		sched_clutch_thr_count_inc(&root_clutch->scr_thr_count);
		/* Update the position of the clutch bucket in the hierarchy */
		result = sched_clutch_bucket_update(clutch_bucket, root_clutch, current_timestamp);
	}
	return result;
}

/*
 * sched_clutch_thread_remove()
 *
 * Routine to remove a thread from the sched clutch hierarchy.
 * Update the counts at all levels of the hierarchy and remove the nodes
 * as they become empty. Always called with the pset lock held.
 */
static void
sched_clutch_thread_remove(
	sched_clutch_root_t root_clutch,
	thread_t thread,
	uint64_t current_timestamp)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
	sched_clutch_t clutch = sched_clutch_for_thread(thread);
	assert(thread->thread_group == clutch->sc_tg);
	assert(thread->runq != PROCESSOR_NULL);

	sched_clutch_bucket_t clutch_bucket = &(clutch->sc_clutch_buckets[thread->th_sched_bucket]);
	assert(clutch_bucket->scb_root == root_clutch);

	/* Decrement the urgency counter for the root if necessary */
	sched_clutch_root_urgency_dec(root_clutch, thread);
	/* Remove thread from the clutch_bucket */
	run_queue_remove(&clutch_bucket->scb_runq, thread);

	priority_queue_remove(&clutch_bucket->scb_clutchpri_prioq, &thread->sched_clutchpri_link,
	    PRIORITY_QUEUE_SCHED_PRI_MAX_HEAP_COMPARE);
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_CLUTCH_THREAD_STATE) | DBG_FUNC_NONE,
	    thread_group_get_id(clutch_bucket->scb_clutch->sc_tg), clutch_bucket->scb_bucket, thread_tid(thread), SCHED_CLUTCH_STATE_EMPTY, 0);

	/* Update counts at various levels of the hierarchy */
	os_atomic_dec(&clutch->sc_thr_count, relaxed);
	sched_clutch_thr_count_dec(&root_clutch->scr_thr_count);
	sched_clutch_thr_count_dec(&clutch_bucket->scb_thr_count);

	/* Remove the clutch from hierarchy (if needed) and update properties */
	if (clutch_bucket->scb_thr_count == 0) {
		sched_clutch_bucket_empty(clutch_bucket, root_clutch, current_timestamp);
	} else {
		sched_clutch_bucket_update(clutch_bucket, root_clutch, current_timestamp);
	}
}

/*
 * sched_clutch_thread_highest()
 *
 * Routine to find and remove the highest priority thread
 * from the sched clutch hierarchy. The algorithm looks at the
 * hierarchy for the most eligible runnable thread and calls
 * sched_clutch_thread_remove(). Always called with the
 * pset lock held.
 */
static thread_t
sched_clutch_thread_highest(
	sched_clutch_root_t root_clutch)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
	uint64_t current_timestamp = mach_absolute_time();

	/* Select the highest priority root bucket */
	sched_clutch_root_bucket_t root_bucket = sched_clutch_root_highest_root_bucket(root_clutch, current_timestamp);
	if (root_bucket == NULL) {
		return THREAD_NULL;
	}
	/* Since a thread is being picked from this root bucket, update its deadline */
	sched_clutch_root_bucket_deadline_update(root_bucket, root_clutch, current_timestamp);

	/* Find the highest priority clutch bucket in this root bucket */
	sched_clutch_bucket_t clutch_bucket = sched_clutch_root_bucket_highest_clutch_bucket(root_bucket);
	assert(clutch_bucket != NULL);

	/* Find the highest priority runnable thread in this clutch bucket */
	thread_t thread = run_queue_peek(&clutch_bucket->scb_runq);
	assert(thread != NULL);

	/* Remove and return the thread from the hierarchy */
	sched_clutch_thread_remove(root_clutch, thread, current_timestamp);
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_CLUTCH_THREAD_SELECT) | DBG_FUNC_NONE,
	    thread_tid(thread), thread_group_get_id(clutch_bucket->scb_clutch->sc_tg), clutch_bucket->scb_bucket, 0, 0);
	return thread;
}


/* High level global accessor routines */

/*
 * sched_clutch_root_urgency()
 *
 * Routine to get the urgency of the highest runnable
 * thread in the hierarchy.
 */
static uint32_t
sched_clutch_root_urgency(
	sched_clutch_root_t root_clutch)
{
	return root_clutch->scr_urgency;
}

/*
 * sched_clutch_root_count_sum()
 *
 * The count_sum mechanism is used for scheduler runq
 * statistics calculation. Its only useful for debugging
 * purposes; since it takes a mach_absolute_time() on
 * other scheduler implementations, its better to avoid
 * populating this until absolutely necessary.
 */
static uint32_t
sched_clutch_root_count_sum(
	__unused sched_clutch_root_t root_clutch)
{
	return 0;
}

/*
 * sched_clutch_root_priority()
 *
 * Routine to get the priority of the highest runnable
 * thread in the hierarchy.
 */
static int
sched_clutch_root_priority(
	sched_clutch_root_t root_clutch)
{
	return root_clutch->scr_priority;
}

/*
 * sched_clutch_root_count()
 *
 * Returns total number of runnable threads in the hierarchy.
 */
uint32_t
sched_clutch_root_count(
	sched_clutch_root_t root_clutch)
{
	return root_clutch->scr_thr_count;
}

/*
 * sched_clutch_thread_pri_shift()
 *
 * Routine to get the priority shift value for a thread.
 * Since the timesharing is done at the clutch_bucket level,
 * this routine gets the clutch_bucket and retrieves the
 * values from there.
 */
uint32_t
sched_clutch_thread_pri_shift(
	thread_t thread,
	sched_bucket_t bucket)
{
	if (!SCHED_CLUTCH_THREAD_ELIGIBLE(thread)) {
		return UINT8_MAX;
	}
	assert(bucket != TH_BUCKET_RUN);
	sched_clutch_t clutch = sched_clutch_for_thread(thread);
	sched_clutch_bucket_t clutch_bucket = &(clutch->sc_clutch_buckets[bucket]);
	return os_atomic_load(&clutch_bucket->scb_pri_shift, relaxed);
}

#pragma mark -- Clutch Scheduler Algorithm

static void
sched_clutch_init(void);

static void
sched_clutch_timebase_init(void);

static thread_t
sched_clutch_steal_thread(processor_set_t pset);

static void
sched_clutch_thread_update_scan(sched_update_scan_context_t scan_context);

static boolean_t
sched_clutch_processor_enqueue(processor_t processor, thread_t thread,
    sched_options_t options);

static boolean_t
sched_clutch_processor_queue_remove(processor_t processor, thread_t thread);

static ast_t
sched_clutch_processor_csw_check(processor_t processor);

static boolean_t
sched_clutch_processor_queue_has_priority(processor_t processor, int priority, boolean_t gte);

static int
sched_clutch_runq_count(processor_t processor);

static boolean_t
sched_clutch_processor_queue_empty(processor_t processor);

static uint64_t
sched_clutch_runq_stats_count_sum(processor_t processor);

static int
sched_clutch_processor_bound_count(processor_t processor);

static void
sched_clutch_pset_init(processor_set_t pset);

static void
sched_clutch_processor_init(processor_t processor);

static thread_t
sched_clutch_choose_thread(processor_t processor, int priority, ast_t reason);

static void
sched_clutch_processor_queue_shutdown(processor_t processor);

static sched_mode_t
sched_clutch_initial_thread_sched_mode(task_t parent_task);

static uint32_t
sched_clutch_initial_quantum_size(thread_t thread);

static bool
sched_clutch_thread_avoid_processor(processor_t processor, thread_t thread);

static uint32_t
sched_clutch_run_incr(thread_t thread);

static uint32_t
sched_clutch_run_decr(thread_t thread);

static void
sched_clutch_update_thread_bucket(thread_t thread);

const struct sched_dispatch_table sched_clutch_dispatch = {
	.sched_name                                     = "clutch",
	.init                                           = sched_clutch_init,
	.timebase_init                                  = sched_clutch_timebase_init,
	.processor_init                                 = sched_clutch_processor_init,
	.pset_init                                      = sched_clutch_pset_init,
	.maintenance_continuation                       = sched_timeshare_maintenance_continue,
	.choose_thread                                  = sched_clutch_choose_thread,
	.steal_thread_enabled                           = sched_steal_thread_enabled,
	.steal_thread                                   = sched_clutch_steal_thread,
	.compute_timeshare_priority                     = sched_compute_timeshare_priority,
	.choose_processor                               = choose_processor,
	.processor_enqueue                              = sched_clutch_processor_enqueue,
	.processor_queue_shutdown                       = sched_clutch_processor_queue_shutdown,
	.processor_queue_remove                         = sched_clutch_processor_queue_remove,
	.processor_queue_empty                          = sched_clutch_processor_queue_empty,
	.priority_is_urgent                             = priority_is_urgent,
	.processor_csw_check                            = sched_clutch_processor_csw_check,
	.processor_queue_has_priority                   = sched_clutch_processor_queue_has_priority,
	.initial_quantum_size                           = sched_clutch_initial_quantum_size,
	.initial_thread_sched_mode                      = sched_clutch_initial_thread_sched_mode,
	.can_update_priority                            = can_update_priority,
	.update_priority                                = update_priority,
	.lightweight_update_priority                    = lightweight_update_priority,
	.quantum_expire                                 = sched_default_quantum_expire,
	.processor_runq_count                           = sched_clutch_runq_count,
	.processor_runq_stats_count_sum                 = sched_clutch_runq_stats_count_sum,
	.processor_bound_count                          = sched_clutch_processor_bound_count,
	.thread_update_scan                             = sched_clutch_thread_update_scan,
	.multiple_psets_enabled                         = TRUE,
	.sched_groups_enabled                           = FALSE,
	.avoid_processor_enabled                        = TRUE,
	.thread_avoid_processor                         = sched_clutch_thread_avoid_processor,
	.processor_balance                              = sched_SMT_balance,

	.rt_runq                                        = sched_rtglobal_runq,
	.rt_init                                        = sched_rtglobal_init,
	.rt_queue_shutdown                              = sched_rtglobal_queue_shutdown,
	.rt_runq_scan                                   = sched_rtglobal_runq_scan,
	.rt_runq_count_sum                              = sched_rtglobal_runq_count_sum,

	.qos_max_parallelism                            = sched_qos_max_parallelism,
	.check_spill                                    = sched_check_spill,
	.ipi_policy                                     = sched_ipi_policy,
	.thread_should_yield                            = sched_thread_should_yield,
	.run_count_incr                                 = sched_clutch_run_incr,
	.run_count_decr                                 = sched_clutch_run_decr,
	.update_thread_bucket                           = sched_clutch_update_thread_bucket,
	.pset_made_schedulable                          = sched_pset_made_schedulable,
};

__attribute__((always_inline))
static inline run_queue_t
sched_clutch_bound_runq(processor_t processor)
{
	return &processor->runq;
}

__attribute__((always_inline))
static inline sched_clutch_root_t
sched_clutch_processor_root_clutch(processor_t processor)
{
	return &processor->processor_set->pset_clutch_root;
}

__attribute__((always_inline))
static inline run_queue_t
sched_clutch_thread_bound_runq(processor_t processor, __assert_only thread_t thread)
{
	assert(thread->bound_processor == processor);
	return sched_clutch_bound_runq(processor);
}

static uint32_t
sched_clutch_initial_quantum_size(thread_t thread)
{
	if (thread == THREAD_NULL) {
		return std_quantum;
	}
	assert(sched_clutch_thread_quantum[thread->th_sched_bucket] <= UINT32_MAX);
	return (uint32_t)sched_clutch_thread_quantum[thread->th_sched_bucket];
}

static sched_mode_t
sched_clutch_initial_thread_sched_mode(task_t parent_task)
{
	if (parent_task == kernel_task) {
		return TH_MODE_FIXED;
	} else {
		return TH_MODE_TIMESHARE;
	}
}

static void
sched_clutch_processor_init(processor_t processor)
{
	run_queue_init(&processor->runq);
}

static void
sched_clutch_pset_init(processor_set_t pset)
{
	sched_clutch_root_init(&pset->pset_clutch_root, pset);
}

static void
sched_clutch_init(void)
{
	if (!PE_parse_boot_argn("sched_clutch_bucket_interactive_pri", &sched_clutch_bucket_interactive_pri, sizeof(sched_clutch_bucket_interactive_pri))) {
		sched_clutch_bucket_interactive_pri = SCHED_CLUTCH_BUCKET_INTERACTIVE_PRI_DEFAULT;
	}
	if (!PE_parse_boot_argn("sched_clutch_bucket_pri_boost", &sched_clutch_bucket_pri_boost, sizeof(sched_clutch_bucket_pri_boost))) {
		sched_clutch_bucket_pri_boost = SCHED_CLUTCH_BUCKET_PRI_BOOST_DEFAULT;
	}
	sched_timeshare_init();
}

static void
sched_clutch_timebase_init(void)
{
	sched_timeshare_timebase_init();
	sched_clutch_us_to_abstime(sched_clutch_root_bucket_wcel_us, sched_clutch_root_bucket_wcel);
	sched_clutch_us_to_abstime(sched_clutch_root_bucket_warp_us, sched_clutch_root_bucket_warp);
	sched_clutch_us_to_abstime(sched_clutch_thread_quantum_us, sched_clutch_thread_quantum);
	clock_interval_to_absolutetime_interval(SCHED_CLUTCH_BUCKET_ADJUST_THRESHOLD_USECS,
	    NSEC_PER_USEC, &sched_clutch_bucket_adjust_threshold);

	uint32_t interactivity_delta = 0;
	if (!PE_parse_boot_argn("sched_clutch_bucket_interactivity_delta_usecs", &interactivity_delta, sizeof(interactivity_delta))) {
		interactivity_delta = SCHED_CLUTCH_BUCKET_INTERACTIVITY_DELTA_USECS_DEFAULT;
	}
	clock_interval_to_absolutetime_interval(interactivity_delta, NSEC_PER_USEC, &sched_clutch_bucket_interactivity_delta);
}

static thread_t
sched_clutch_choose_thread(
	processor_t      processor,
	int              priority,
	__unused ast_t            reason)
{
	int clutch_pri = sched_clutch_root_priority(sched_clutch_processor_root_clutch(processor));
	uint32_t clutch_count = sched_clutch_root_count(sched_clutch_processor_root_clutch(processor));
	run_queue_t bound_runq = sched_clutch_bound_runq(processor);
	boolean_t choose_from_boundq = false;

	if (bound_runq->highq < priority &&
	    clutch_pri < priority) {
		return THREAD_NULL;
	}

	if (bound_runq->count && clutch_count) {
		if (bound_runq->highq >= clutch_pri) {
			choose_from_boundq = true;
		}
	} else if (bound_runq->count) {
		choose_from_boundq = true;
	} else if (clutch_count) {
		choose_from_boundq = false;
	} else {
		return THREAD_NULL;
	}

	thread_t thread = THREAD_NULL;
	if (choose_from_boundq == false) {
		sched_clutch_root_t pset_clutch_root = sched_clutch_processor_root_clutch(processor);
		thread = sched_clutch_thread_highest(pset_clutch_root);
	} else {
		thread = run_queue_dequeue(bound_runq, SCHED_HEADQ);
	}
	return thread;
}

static boolean_t
sched_clutch_processor_enqueue(
	processor_t       processor,
	thread_t          thread,
	sched_options_t   options)
{
	boolean_t       result;

	thread->runq = processor;
	if (SCHED_CLUTCH_THREAD_ELIGIBLE(thread)) {
		sched_clutch_root_t pset_clutch_root = sched_clutch_processor_root_clutch(processor);
		result = sched_clutch_thread_insert(pset_clutch_root, thread, options);
	} else {
		run_queue_t rq = sched_clutch_thread_bound_runq(processor, thread);
		result = run_queue_enqueue(rq, thread, options);
	}
	return result;
}

static boolean_t
sched_clutch_processor_queue_empty(processor_t processor)
{
	return sched_clutch_root_count(sched_clutch_processor_root_clutch(processor)) == 0 &&
	       sched_clutch_bound_runq(processor)->count == 0;
}

static ast_t
sched_clutch_processor_csw_check(processor_t processor)
{
	boolean_t       has_higher;
	int             pri;

	if (sched_clutch_thread_avoid_processor(processor, current_thread())) {
		return AST_PREEMPT | AST_URGENT;
	}

	run_queue_t bound_runq = sched_clutch_bound_runq(processor);
	int clutch_pri = sched_clutch_root_priority(sched_clutch_processor_root_clutch(processor));

	assert(processor->active_thread != NULL);

	pri = MAX(clutch_pri, bound_runq->highq);

	if (processor->first_timeslice) {
		has_higher = (pri > processor->current_pri);
	} else {
		has_higher = (pri >= processor->current_pri);
	}

	if (has_higher) {
		if (sched_clutch_root_urgency(sched_clutch_processor_root_clutch(processor)) > 0) {
			return AST_PREEMPT | AST_URGENT;
		}

		if (bound_runq->urgency > 0) {
			return AST_PREEMPT | AST_URGENT;
		}

		return AST_PREEMPT;
	}

	return AST_NONE;
}

static boolean_t
sched_clutch_processor_queue_has_priority(processor_t    processor,
    int            priority,
    boolean_t      gte)
{
	run_queue_t bound_runq = sched_clutch_bound_runq(processor);

	int qpri = MAX(sched_clutch_root_priority(sched_clutch_processor_root_clutch(processor)), bound_runq->highq);

	if (gte) {
		return qpri >= priority;
	} else {
		return qpri > priority;
	}
}

static int
sched_clutch_runq_count(processor_t processor)
{
	return (int)sched_clutch_root_count(sched_clutch_processor_root_clutch(processor)) + sched_clutch_bound_runq(processor)->count;
}

static uint64_t
sched_clutch_runq_stats_count_sum(processor_t processor)
{
	uint64_t bound_sum = sched_clutch_bound_runq(processor)->runq_stats.count_sum;

	if (processor->cpu_id == processor->processor_set->cpu_set_low) {
		return bound_sum + sched_clutch_root_count_sum(sched_clutch_processor_root_clutch(processor));
	} else {
		return bound_sum;
	}
}
static int
sched_clutch_processor_bound_count(processor_t processor)
{
	return sched_clutch_bound_runq(processor)->count;
}

static void
sched_clutch_processor_queue_shutdown(processor_t processor)
{
	processor_set_t pset = processor->processor_set;
	sched_clutch_root_t pset_clutch_root = sched_clutch_processor_root_clutch(processor);
	thread_t        thread;
	queue_head_t    tqueue;

	/* We only need to migrate threads if this is the last active processor in the pset */
	if (pset->online_processor_count > 0) {
		pset_unlock(pset);
		return;
	}

	queue_init(&tqueue);
	while (sched_clutch_root_count(pset_clutch_root) > 0) {
		thread = sched_clutch_thread_highest(pset_clutch_root);
		enqueue_tail(&tqueue, &thread->runq_links);
	}

	pset_unlock(pset);

	qe_foreach_element_safe(thread, &tqueue, runq_links) {
		remqueue(&thread->runq_links);

		thread_lock(thread);

		thread_setrun(thread, SCHED_TAILQ);

		thread_unlock(thread);
	}
}

static boolean_t
sched_clutch_processor_queue_remove(
	processor_t processor,
	thread_t    thread)
{
	run_queue_t             rq;
	processor_set_t         pset = processor->processor_set;

	pset_lock(pset);

	if (processor == thread->runq) {
		/*
		 * Thread is on a run queue and we have a lock on
		 * that run queue.
		 */
		if (SCHED_CLUTCH_THREAD_ELIGIBLE(thread)) {
			sched_clutch_root_t pset_clutch_root = sched_clutch_processor_root_clutch(processor);
			sched_clutch_thread_remove(pset_clutch_root, thread, mach_absolute_time());
		} else {
			rq = sched_clutch_thread_bound_runq(processor, thread);
			run_queue_remove(rq, thread);
		}
	} else {
		/*
		 * The thread left the run queue before we could
		 * lock the run queue.
		 */
		assert(thread->runq == PROCESSOR_NULL);
		processor = PROCESSOR_NULL;
	}

	pset_unlock(pset);

	return processor != PROCESSOR_NULL;
}

static thread_t
sched_clutch_steal_thread(processor_set_t pset)
{
	processor_set_t nset, cset = pset;
	thread_t        thread;

	do {
		sched_clutch_root_t pset_clutch_root = &cset->pset_clutch_root;
		if (sched_clutch_root_count(pset_clutch_root) > 0) {
			thread = sched_clutch_thread_highest(pset_clutch_root);
			pset_unlock(cset);
			return thread;
		}

		nset = next_pset(cset);

		if (nset != pset) {
			pset_unlock(cset);

			cset = nset;
			pset_lock(cset);
		}
	} while (nset != pset);

	pset_unlock(cset);

	return THREAD_NULL;
}

static void
sched_clutch_thread_update_scan(sched_update_scan_context_t scan_context)
{
	boolean_t               restart_needed = FALSE;
	processor_t             processor = processor_list;
	processor_set_t         pset;
	thread_t                thread;
	spl_t                   s;

	/*
	 *  We update the threads associated with each processor (bound and idle threads)
	 *  and then update the threads in each pset runqueue.
	 */

	do {
		do {
			pset = processor->processor_set;

			s = splsched();
			pset_lock(pset);

			restart_needed = runq_scan(sched_clutch_bound_runq(processor), scan_context);

			pset_unlock(pset);
			splx(s);

			if (restart_needed) {
				break;
			}

			thread = processor->idle_thread;
			if (thread != THREAD_NULL && thread->sched_stamp != sched_tick) {
				if (thread_update_add_thread(thread) == FALSE) {
					restart_needed = TRUE;
					break;
				}
			}
		} while ((processor = processor->processor_list) != NULL);

		/* Ok, we now have a collection of candidates -- fix them. */
		thread_update_process_threads();
	} while (restart_needed);

	pset = &pset0;

	do {
		do {
			s = splsched();
			pset_lock(pset);

			if (sched_clutch_root_count(&pset->pset_clutch_root) > 0) {
				queue_t clutch_bucket_list = &pset->pset_clutch_root.scr_clutch_buckets;
				sched_clutch_bucket_t clutch_bucket;
				qe_foreach_element(clutch_bucket, clutch_bucket_list, scb_listlink) {
					sched_clutch_bucket_timeshare_update(clutch_bucket);
					restart_needed = runq_scan(&clutch_bucket->scb_runq, scan_context);
					if (restart_needed) {
						break;
					}
				}
			}

			pset_unlock(pset);
			splx(s);
			if (restart_needed) {
				break;
			}
		} while ((pset = pset->pset_list) != NULL);

		/* Ok, we now have a collection of candidates -- fix them. */
		thread_update_process_threads();
	} while (restart_needed);
}

extern int sched_allow_rt_smt;

/* Return true if this thread should not continue running on this processor */
static bool
sched_clutch_thread_avoid_processor(processor_t processor, thread_t thread)
{
	if (processor->processor_primary != processor) {
		/*
		 * This is a secondary SMT processor.  If the primary is running
		 * a realtime thread, only allow realtime threads on the secondary.
		 */
		if ((processor->processor_primary->current_pri >= BASEPRI_RTQUEUES) && ((thread->sched_pri < BASEPRI_RTQUEUES) || !sched_allow_rt_smt)) {
			return true;
		}
	}

	return false;
}

/*
 * For the clutch scheduler, the run counts are maintained in the clutch
 * buckets (i.e thread group scheduling structure).
 */
static uint32_t
sched_clutch_run_incr(thread_t thread)
{
	assert((thread->state & (TH_RUN | TH_IDLE)) == TH_RUN);
	uint32_t new_count = os_atomic_inc(&sched_run_buckets[TH_BUCKET_RUN], relaxed);
	sched_clutch_thread_run_bucket_incr(thread, thread->th_sched_bucket);
	return new_count;
}

static uint32_t
sched_clutch_run_decr(thread_t thread)
{
	assert((thread->state & (TH_RUN | TH_IDLE)) != TH_RUN);
	uint32_t new_count = os_atomic_dec(&sched_run_buckets[TH_BUCKET_RUN], relaxed);
	sched_clutch_thread_run_bucket_decr(thread, thread->th_sched_bucket);
	return new_count;
}

static sched_bucket_t
sched_convert_pri_to_bucket(uint8_t priority)
{
	sched_bucket_t bucket = TH_BUCKET_RUN;

	if (priority > BASEPRI_USER_INITIATED) {
		bucket = TH_BUCKET_SHARE_FG;
	} else if (priority > BASEPRI_DEFAULT) {
		bucket = TH_BUCKET_SHARE_IN;
	} else if (priority > BASEPRI_UTILITY) {
		bucket = TH_BUCKET_SHARE_DF;
	} else if (priority > MAXPRI_THROTTLE) {
		bucket = TH_BUCKET_SHARE_UT;
	} else {
		bucket = TH_BUCKET_SHARE_BG;
	}
	return bucket;
}

/*
 * For threads that have changed sched_pri without changing the
 * base_pri for any reason other than decay, use the sched_pri
 * as the bucketizing priority instead of base_pri. All such
 * changes are typically due to kernel locking primitives boosts
 * or demotions.
 */
static boolean_t
sched_thread_sched_pri_promoted(thread_t thread)
{
	return (thread->sched_flags & TH_SFLAG_PROMOTED) ||
	       (thread->sched_flags & TH_SFLAG_PROMOTE_REASON_MASK) ||
	       (thread->sched_flags & TH_SFLAG_DEMOTED_MASK) ||
	       (thread->sched_flags & TH_SFLAG_DEPRESSED_MASK) ||
	       (thread->kern_promotion_schedpri != 0);
}

/*
 * Routine to update the scheduling bucket for the thread.
 *
 * In the clutch scheduler implementation, the thread's bucket
 * is based on sched_pri if it was promoted due to a kernel
 * primitive; otherwise its based on the thread base_pri. This
 * enhancement allows promoted threads to reach a higher priority
 * bucket and potentially get selected sooner for scheduling.
 *
 * Also, the clutch scheduler does not honor fixed priority below
 * FG priority. It simply puts those threads in the corresponding
 * timeshare bucket. The reason for to do that is because it is
 * extremely hard to define the scheduling properties of such threads
 * and they typically lead to performance issues.
 */

void
sched_clutch_update_thread_bucket(thread_t thread)
{
	sched_bucket_t old_bucket = thread->th_sched_bucket;
	sched_bucket_t new_bucket = TH_BUCKET_RUN;
	assert(thread->runq == PROCESSOR_NULL);

	int pri = (sched_thread_sched_pri_promoted(thread)) ? thread->sched_pri : thread->base_pri;

	switch (thread->sched_mode) {
	case TH_MODE_FIXED:
		if (pri >= BASEPRI_FOREGROUND) {
			new_bucket = TH_BUCKET_FIXPRI;
		} else {
			new_bucket = sched_convert_pri_to_bucket(pri);
		}
		break;

	case TH_MODE_REALTIME:
		new_bucket = TH_BUCKET_FIXPRI;
		break;

	case TH_MODE_TIMESHARE:
		new_bucket = sched_convert_pri_to_bucket(pri);
		break;

	default:
		panic("unexpected mode: %d", thread->sched_mode);
		break;
	}

	if (old_bucket == new_bucket) {
		return;
	}

	thread->th_sched_bucket = new_bucket;
	thread->pri_shift = sched_clutch_thread_pri_shift(thread, new_bucket);

	/*
	 * Since this is called after the thread has been removed from the runq,
	 * only the run counts need to be updated. The re-insert into the runq
	 * would put the thread into the correct new bucket's runq.
	 */
	if ((thread->state & (TH_RUN | TH_IDLE)) == TH_RUN) {
		sched_clutch_thread_run_bucket_decr(thread, old_bucket);
		sched_clutch_thread_run_bucket_incr(thread, new_bucket);
	}
}


#endif /* CONFIG_SCHED_CLUTCH */

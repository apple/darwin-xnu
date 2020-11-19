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

#if CONFIG_SCHED_EDGE
#include <kern/sched_amp_common.h>
#endif /* CONFIG_SCHED_EDGE */

#if CONFIG_SCHED_CLUTCH

/* Forward declarations of static routines */

/* Root level hierarchy management */
static void sched_clutch_root_init(sched_clutch_root_t, processor_set_t);
static void sched_clutch_root_bucket_init(sched_clutch_root_bucket_t, sched_bucket_t, bool);
static void sched_clutch_root_pri_update(sched_clutch_root_t);
static void sched_clutch_root_urgency_inc(sched_clutch_root_t, thread_t);
static void sched_clutch_root_urgency_dec(sched_clutch_root_t, thread_t);

__enum_decl(sched_clutch_highest_root_bucket_type_t, uint32_t, {
	SCHED_CLUTCH_HIGHEST_ROOT_BUCKET_NONE           = 0,
	SCHED_CLUTCH_HIGHEST_ROOT_BUCKET_UNBOUND_ONLY   = 1,
	SCHED_CLUTCH_HIGHEST_ROOT_BUCKET_ALL            = 2,
});

static sched_clutch_root_bucket_t sched_clutch_root_highest_root_bucket(sched_clutch_root_t, uint64_t, sched_clutch_highest_root_bucket_type_t);

#if CONFIG_SCHED_EDGE
/* Support for foreign threads on AMP platforms */
static boolean_t sched_clutch_root_foreign_empty(sched_clutch_root_t);
static thread_t sched_clutch_root_highest_foreign_thread_remove(sched_clutch_root_t);
#endif /* CONFIG_SCHED_EDGE */

/* Root bucket level hierarchy management */
static uint64_t sched_clutch_root_bucket_deadline_calculate(sched_clutch_root_bucket_t, uint64_t);
static void sched_clutch_root_bucket_deadline_update(sched_clutch_root_bucket_t, sched_clutch_root_t, uint64_t);

/* Options for clutch bucket ordering in the runq */
__options_decl(sched_clutch_bucket_options_t, uint32_t, {
	SCHED_CLUTCH_BUCKET_OPTIONS_NONE        = 0x0,
	/* Round robin clutch bucket on thread removal */
	SCHED_CLUTCH_BUCKET_OPTIONS_SAMEPRI_RR  = 0x1,
	/* Insert clutch bucket at head (for thread preemption) */
	SCHED_CLUTCH_BUCKET_OPTIONS_HEADQ       = 0x2,
	/* Insert clutch bucket at tail (default) */
	SCHED_CLUTCH_BUCKET_OPTIONS_TAILQ       = 0x4,
});

/* Clutch bucket level hierarchy management */
static void sched_clutch_bucket_hierarchy_insert(sched_clutch_root_t, sched_clutch_bucket_t, sched_bucket_t, uint64_t, sched_clutch_bucket_options_t);
static void sched_clutch_bucket_hierarchy_remove(sched_clutch_root_t, sched_clutch_bucket_t, sched_bucket_t, uint64_t, sched_clutch_bucket_options_t);
static boolean_t sched_clutch_bucket_runnable(sched_clutch_bucket_t, sched_clutch_root_t, uint64_t, sched_clutch_bucket_options_t);
static boolean_t sched_clutch_bucket_update(sched_clutch_bucket_t, sched_clutch_root_t, uint64_t, sched_clutch_bucket_options_t);
static void sched_clutch_bucket_empty(sched_clutch_bucket_t, sched_clutch_root_t, uint64_t, sched_clutch_bucket_options_t);
static uint8_t sched_clutch_bucket_pri_calculate(sched_clutch_bucket_t, uint64_t);

/* Clutch bucket group level properties management */
static void sched_clutch_bucket_group_cpu_usage_update(sched_clutch_bucket_group_t, uint64_t);
static void sched_clutch_bucket_group_cpu_adjust(sched_clutch_bucket_group_t, uint8_t);
static void sched_clutch_bucket_group_timeshare_update(sched_clutch_bucket_group_t, sched_clutch_bucket_t, uint64_t);
static uint8_t sched_clutch_bucket_group_pending_ageout(sched_clutch_bucket_group_t, uint64_t);
static uint32_t sched_clutch_bucket_group_run_count_inc(sched_clutch_bucket_group_t);
static uint32_t sched_clutch_bucket_group_run_count_dec(sched_clutch_bucket_group_t);
static uint8_t sched_clutch_bucket_group_interactivity_score_calculate(sched_clutch_bucket_group_t, uint64_t);

/* Clutch timeshare properties updates */
static uint32_t sched_clutch_run_bucket_incr(sched_clutch_t, sched_bucket_t);
static uint32_t sched_clutch_run_bucket_decr(sched_clutch_t, sched_bucket_t);

/* Clutch membership management */
static boolean_t sched_clutch_thread_insert(sched_clutch_root_t, thread_t, integer_t);
static void sched_clutch_thread_remove(sched_clutch_root_t, thread_t, uint64_t, sched_clutch_bucket_options_t);
static thread_t sched_clutch_thread_highest_remove(sched_clutch_root_t);

/* Clutch properties updates */
static uint32_t sched_clutch_root_urgency(sched_clutch_root_t);
static uint32_t sched_clutch_root_count_sum(sched_clutch_root_t);
static int sched_clutch_root_priority(sched_clutch_root_t);
static sched_clutch_bucket_t sched_clutch_root_bucket_highest_clutch_bucket(sched_clutch_root_bucket_t);
static boolean_t sched_thread_sched_pri_promoted(thread_t);

#if CONFIG_SCHED_EDGE
/* System based routines */
static bool sched_edge_pset_available(processor_set_t);
static uint32_t sched_edge_thread_bound_cluster_id(thread_t);
#endif /* CONFIG_SCHED_EDGE */

/* Helper debugging routines */
static inline void sched_clutch_hierarchy_locked_assert(sched_clutch_root_t);

extern processor_set_t pset_array[MAX_PSETS];

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

#if XNU_TARGET_OS_OSX
static uint32_t sched_clutch_thread_quantum_us[TH_BUCKET_SCHED_MAX] = {
	10000,                                          /* FIXPRI (10ms) */
	10000,                                          /* FG (10ms) */
	10000,                                          /* IN (10ms) */
	10000,                                          /* DF (10ms) */
	4000,                                           /* UT (4ms) */
	2000                                            /* BG (2ms) */
};
#else /* XNU_TARGET_OS_OSX */
static uint32_t sched_clutch_thread_quantum_us[TH_BUCKET_SCHED_MAX] = {
	10000,                                          /* FIXPRI (10ms) */
	10000,                                          /* FG (10ms) */
	8000,                                           /* IN (8ms) */
	6000,                                           /* DF (6ms) */
	4000,                                           /* UT (4ms) */
	2000                                            /* BG (2ms) */
};
#endif /* XNU_TARGET_OS_OSX */

static uint64_t sched_clutch_thread_quantum[TH_BUCKET_SCHED_MAX] = {0};

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

/* Clutch/Edge Scheduler Debugging support */
#define SCHED_CLUTCH_DBG_THR_COUNT_PACK(a, b, c)        ((uint64_t)c | ((uint64_t)b << 16) | ((uint64_t)a << 32))

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
 * The clutch scheduler attempts to ageout the CPU usage of clutch bucket groups
 * based on the amount of time they have been pending and the load at that
 * scheduling bucket level. Since the clutch bucket groups are global (i.e. span
 * multiple clusters, its important to keep the load also as a global counter.
 */
static uint32_t _Atomic sched_clutch_global_bucket_load[TH_BUCKET_SCHED_MAX];

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
#if CONFIG_SCHED_EDGE
	root_clutch->scr_cluster_id = pset->pset_cluster_id;
#else /* CONFIG_SCHED_EDGE */
	root_clutch->scr_cluster_id = 0;
#endif /* CONFIG_SCHED_EDGE */

	/* Initialize the queue which maintains all runnable clutch_buckets for timesharing purposes */
	queue_init(&root_clutch->scr_clutch_buckets);

	/* Initialize the priority queue which maintains all runnable foreign clutch buckets */
	priority_queue_init(&root_clutch->scr_foreign_buckets);
	bzero(&root_clutch->scr_cumulative_run_count, sizeof(root_clutch->scr_cumulative_run_count));
	bitmap_zero(root_clutch->scr_bound_runnable_bitmap, TH_BUCKET_SCHED_MAX);
	bitmap_zero(root_clutch->scr_bound_warp_available, TH_BUCKET_SCHED_MAX);
	priority_queue_init(&root_clutch->scr_bound_root_buckets);

	/* Initialize the bitmap and priority queue of runnable root buckets */
	priority_queue_init(&root_clutch->scr_unbound_root_buckets);
	bitmap_zero(root_clutch->scr_unbound_runnable_bitmap, TH_BUCKET_SCHED_MAX);
	bitmap_zero(root_clutch->scr_unbound_warp_available, TH_BUCKET_SCHED_MAX);

	/* Initialize all the root buckets */
	for (uint32_t i = 0; i < TH_BUCKET_SCHED_MAX; i++) {
		sched_clutch_root_bucket_init(&root_clutch->scr_unbound_buckets[i], i, false);
		sched_clutch_root_bucket_init(&root_clutch->scr_bound_buckets[i], i, true);
	}
}

/*
 * Clutch Bucket Runqueues
 *
 * The clutch buckets are maintained in a runq at the root bucket level. The
 * runq organization allows clutch buckets to be ordered based on various
 * factors such as:
 *
 * - Clutch buckets are round robin'ed at the same priority level when a
 *   thread is selected from a clutch bucket. This prevents a clutch bucket
 *   from starving out other clutch buckets at the same priority.
 *
 * - Clutch buckets are inserted at the head when it becomes runnable due to
 *   thread preemption. This allows threads that were preempted to maintain
 *   their order in the queue.
 *
 */

/*
 * sched_clutch_bucket_runq_init()
 *
 * Initialize a clutch bucket runq.
 */
static void
sched_clutch_bucket_runq_init(
	sched_clutch_bucket_runq_t clutch_buckets_rq)
{
	clutch_buckets_rq->scbrq_highq = NOPRI;
	for (uint8_t i = 0; i < BITMAP_LEN(NRQS); i++) {
		clutch_buckets_rq->scbrq_bitmap[i] = 0;
	}
	clutch_buckets_rq->scbrq_count = 0;
	for (int i = 0; i < NRQS; i++) {
		circle_queue_init(&clutch_buckets_rq->scbrq_queues[i]);
	}
}

/*
 * sched_clutch_bucket_runq_empty()
 *
 * Returns if a clutch bucket runq is empty.
 */
static boolean_t
sched_clutch_bucket_runq_empty(
	sched_clutch_bucket_runq_t clutch_buckets_rq)
{
	return clutch_buckets_rq->scbrq_count == 0;
}

/*
 * sched_clutch_bucket_runq_peek()
 *
 * Returns the highest priority clutch bucket in the runq.
 */
static sched_clutch_bucket_t
sched_clutch_bucket_runq_peek(
	sched_clutch_bucket_runq_t clutch_buckets_rq)
{
	if (clutch_buckets_rq->scbrq_count > 0) {
		circle_queue_t queue = &clutch_buckets_rq->scbrq_queues[clutch_buckets_rq->scbrq_highq];
		return cqe_queue_first(queue, struct sched_clutch_bucket, scb_runqlink);
	} else {
		return NULL;
	}
}

/*
 * sched_clutch_bucket_runq_enqueue()
 *
 * Enqueue a clutch bucket into the runq based on the options passed in.
 */
static void
sched_clutch_bucket_runq_enqueue(
	sched_clutch_bucket_runq_t clutch_buckets_rq,
	sched_clutch_bucket_t clutch_bucket,
	sched_clutch_bucket_options_t options)
{
	circle_queue_t queue = &clutch_buckets_rq->scbrq_queues[clutch_bucket->scb_priority];
	if (circle_queue_empty(queue)) {
		circle_enqueue_tail(queue, &clutch_bucket->scb_runqlink);
		bitmap_set(clutch_buckets_rq->scbrq_bitmap, clutch_bucket->scb_priority);
		if (clutch_bucket->scb_priority > clutch_buckets_rq->scbrq_highq) {
			clutch_buckets_rq->scbrq_highq = clutch_bucket->scb_priority;
		}
	} else {
		if (options & SCHED_CLUTCH_BUCKET_OPTIONS_HEADQ) {
			circle_enqueue_head(queue, &clutch_bucket->scb_runqlink);
		} else {
			/*
			 * Default behavior (handles SCHED_CLUTCH_BUCKET_OPTIONS_TAILQ &
			 * SCHED_CLUTCH_BUCKET_OPTIONS_NONE)
			 */
			circle_enqueue_tail(queue, &clutch_bucket->scb_runqlink);
		}
	}
	clutch_buckets_rq->scbrq_count++;
}

/*
 * sched_clutch_bucket_runq_remove()
 *
 * Remove a clutch bucket from the runq.
 */
static void
sched_clutch_bucket_runq_remove(
	sched_clutch_bucket_runq_t clutch_buckets_rq,
	sched_clutch_bucket_t clutch_bucket)
{
	circle_queue_t queue = &clutch_buckets_rq->scbrq_queues[clutch_bucket->scb_priority];
	circle_dequeue(queue, &clutch_bucket->scb_runqlink);
	assert(clutch_buckets_rq->scbrq_count > 0);
	clutch_buckets_rq->scbrq_count--;
	if (circle_queue_empty(queue)) {
		bitmap_clear(clutch_buckets_rq->scbrq_bitmap, clutch_bucket->scb_priority);
		clutch_buckets_rq->scbrq_highq = bitmap_first(clutch_buckets_rq->scbrq_bitmap, NRQS);
	}
}

static void
sched_clutch_bucket_runq_rotate(
	sched_clutch_bucket_runq_t clutch_buckets_rq,
	sched_clutch_bucket_t clutch_bucket)
{
	circle_queue_t queue = &clutch_buckets_rq->scbrq_queues[clutch_bucket->scb_priority];
	assert(clutch_bucket == cqe_queue_first(queue, struct sched_clutch_bucket, scb_runqlink));
	circle_queue_rotate_head_forward(queue);
}

/*
 * sched_clutch_root_bucket_init()
 *
 * Routine to initialize root buckets.
 */
static void
sched_clutch_root_bucket_init(
	sched_clutch_root_bucket_t root_bucket,
	sched_bucket_t bucket,
	bool bound_root_bucket)
{
	root_bucket->scrb_bucket = bucket;
	if (bound_root_bucket) {
		/* For bound root buckets, initialize the bound thread runq. */
		root_bucket->scrb_bound = true;
		run_queue_init(&root_bucket->scrb_bound_thread_runq);
	} else {
		/*
		 * The unbounded root buckets contain a runq of runnable clutch buckets
		 * which then hold the runnable threads.
		 */
		root_bucket->scrb_bound = false;
		sched_clutch_bucket_runq_init(&root_bucket->scrb_clutch_buckets);
	}
	priority_queue_entry_init(&root_bucket->scrb_pqlink);
	root_bucket->scrb_pqlink.deadline = SCHED_CLUTCH_INVALID_TIME_64;
	root_bucket->scrb_warped_deadline = 0;
	root_bucket->scrb_warp_remaining = sched_clutch_root_bucket_warp[root_bucket->scrb_bucket];
	root_bucket->scrb_starvation_avoidance = false;
	root_bucket->scrb_starvation_ts = 0;
}

/*
 * Special case scheduling for Above UI bucket.
 *
 * AboveUI threads are typically system critical threads that need low latency
 * which is why they are handled specially.
 *
 * Since the priority range for AboveUI and FG Timeshare buckets overlap, it is
 * important to maintain some native priority order between those buckets. For unbounded
 * root buckets, the policy is to compare the highest clutch buckets of both buckets; if the
 * Above UI bucket is higher, schedule it immediately. Otherwise fall through to the
 * deadline based scheduling which should pickup the timeshare buckets. For the bound
 * case, the policy simply compares the priority of the highest runnable threads in
 * the above UI and timeshare buckets.
 *
 * The implementation allows extremely low latency CPU access for Above UI threads
 * while supporting the use case of high priority timeshare threads contending with
 * lower priority fixed priority threads.
 */


/*
 * sched_clutch_root_unbound_select_aboveui()
 *
 * Routine to determine if the above UI unbounded bucket should be selected for execution.
 */
static bool
sched_clutch_root_unbound_select_aboveui(
	sched_clutch_root_t root_clutch)
{
	if (bitmap_test(root_clutch->scr_unbound_runnable_bitmap, TH_BUCKET_FIXPRI)) {
		sched_clutch_root_bucket_t root_bucket_aboveui = &root_clutch->scr_unbound_buckets[TH_BUCKET_FIXPRI];
		sched_clutch_root_bucket_t root_bucket_sharefg = &root_clutch->scr_unbound_buckets[TH_BUCKET_SHARE_FG];
		if (!bitmap_test(root_clutch->scr_unbound_runnable_bitmap, TH_BUCKET_SHARE_FG)) {
			/* If the timeshare FG bucket is not runnable, pick the aboveUI bucket for scheduling */
			return true;
		}
		sched_clutch_bucket_t clutch_bucket_aboveui = sched_clutch_root_bucket_highest_clutch_bucket(root_bucket_aboveui);
		sched_clutch_bucket_t clutch_bucket_sharefg = sched_clutch_root_bucket_highest_clutch_bucket(root_bucket_sharefg);
		if (clutch_bucket_aboveui->scb_priority >= clutch_bucket_sharefg->scb_priority) {
			return true;
		}
	}
	return false;
}

/*
 * sched_clutch_root_bound_select_aboveui()
 *
 * Routine to determine if the above UI bounded bucket should be selected for execution.
 */
static bool
sched_clutch_root_bound_select_aboveui(
	sched_clutch_root_t root_clutch)
{
	sched_clutch_root_bucket_t root_bucket_aboveui = &root_clutch->scr_bound_buckets[TH_BUCKET_FIXPRI];
	sched_clutch_root_bucket_t root_bucket_sharefg = &root_clutch->scr_bound_buckets[TH_BUCKET_SHARE_FG];
	if (root_bucket_aboveui->scrb_bound_thread_runq.count == 0) {
		return false;
	}
	return root_bucket_aboveui->scrb_bound_thread_runq.highq >= root_bucket_sharefg->scrb_bound_thread_runq.highq;
}

/*
 * sched_clutch_root_highest_root_bucket()
 *
 * Main routine to find the highest runnable root level bucket.
 * This routine is called from performance sensitive contexts; so it is
 * crucial to keep this O(1). The options parameter determines if
 * the selection logic should look at unbounded threads only (for
 * cross-cluster stealing operations) or both bounded and unbounded
 * threads (for selecting next thread for execution on current cluster).
 */
static sched_clutch_root_bucket_t
sched_clutch_root_highest_root_bucket(
	sched_clutch_root_t root_clutch,
	uint64_t timestamp,
	sched_clutch_highest_root_bucket_type_t type)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
	int highest_runnable_bucket = -1;
	if (type == SCHED_CLUTCH_HIGHEST_ROOT_BUCKET_UNBOUND_ONLY) {
		highest_runnable_bucket = bitmap_lsb_first(root_clutch->scr_unbound_runnable_bitmap, TH_BUCKET_SCHED_MAX);
	} else {
		int highest_unbound_runnable_bucket = bitmap_lsb_first(root_clutch->scr_unbound_runnable_bitmap, TH_BUCKET_SCHED_MAX);
		int highest_bound_runnable_bucket = bitmap_lsb_first(root_clutch->scr_bound_runnable_bitmap, TH_BUCKET_SCHED_MAX);
		highest_runnable_bucket = (highest_bound_runnable_bucket != -1) ? ((highest_unbound_runnable_bucket != -1) ? MIN(highest_bound_runnable_bucket, highest_unbound_runnable_bucket) : highest_bound_runnable_bucket) : highest_unbound_runnable_bucket;
	}

	if (highest_runnable_bucket == -1) {
		return NULL;
	}

	/* Above UI root bucket selection (see comment above for more details on this special case handling) */
	bool unbound_aboveui = sched_clutch_root_unbound_select_aboveui(root_clutch);
	if (type == SCHED_CLUTCH_HIGHEST_ROOT_BUCKET_UNBOUND_ONLY) {
		if (unbound_aboveui) {
			return &root_clutch->scr_unbound_buckets[TH_BUCKET_FIXPRI];
		}
		/* Fall through to selecting a timeshare root bucket */
	} else {
		bool bound_aboveui = sched_clutch_root_bound_select_aboveui(root_clutch);
		sched_clutch_root_bucket_t unbound_aboveui_root_bucket = &root_clutch->scr_unbound_buckets[TH_BUCKET_FIXPRI];
		sched_clutch_root_bucket_t bound_aboveui_root_bucket = &root_clutch->scr_bound_buckets[TH_BUCKET_FIXPRI];

		if (unbound_aboveui && bound_aboveui) {
			/*
			 * In this scenario both the bounded and unbounded above UI buckets are runnable; choose based on the
			 * highest runnable priority in both the buckets.
			 * */
			int bound_aboveui_pri = root_clutch->scr_bound_buckets[TH_BUCKET_FIXPRI].scrb_bound_thread_runq.highq;
			sched_clutch_bucket_t clutch_bucket = sched_clutch_root_bucket_highest_clutch_bucket(unbound_aboveui_root_bucket);
			int unbound_aboveui_pri = priority_queue_max_sched_pri(&clutch_bucket->scb_clutchpri_prioq);
			return (bound_aboveui_pri >= unbound_aboveui_pri) ? bound_aboveui_root_bucket : unbound_aboveui_root_bucket;
		}
		if (unbound_aboveui) {
			return unbound_aboveui_root_bucket;
		}
		if (bound_aboveui) {
			return bound_aboveui_root_bucket;
		}
		/* Fall through to selecting a timeshare root bucket */
	}

	/*
	 * Above UI bucket is not runnable or has a low priority runnable thread; use the
	 * earliest deadline model to schedule threads. The idea is that as the timeshare
	 * buckets use CPU, they will drop their interactivity score/sched priority and
	 * allow the low priority AboveUI buckets to be scheduled.
	 */

	/* Find the earliest deadline bucket */
	sched_clutch_root_bucket_t edf_bucket = NULL;
	sched_clutch_root_bucket_t warp_bucket = NULL;
	int warp_bucket_index = -1;

evaluate_root_buckets:
	if (type == SCHED_CLUTCH_HIGHEST_ROOT_BUCKET_UNBOUND_ONLY) {
		edf_bucket = priority_queue_min(&root_clutch->scr_unbound_root_buckets, struct sched_clutch_root_bucket, scrb_pqlink);
	} else {
		sched_clutch_root_bucket_t unbound_bucket = priority_queue_min(&root_clutch->scr_unbound_root_buckets, struct sched_clutch_root_bucket, scrb_pqlink);
		sched_clutch_root_bucket_t bound_bucket = priority_queue_min(&root_clutch->scr_bound_root_buckets, struct sched_clutch_root_bucket, scrb_pqlink);
		if (bound_bucket && unbound_bucket) {
			/* If bound and unbound root buckets are runnable, select the one with the earlier deadline */
			edf_bucket = (bound_bucket->scrb_pqlink.deadline <= unbound_bucket->scrb_pqlink.deadline) ? bound_bucket : unbound_bucket;
		} else {
			edf_bucket = (bound_bucket) ? bound_bucket : unbound_bucket;
		}
	}
	/*
	 * Check if any of the buckets have warp available. The implementation only allows root buckets to warp ahead of
	 * buckets of the same type (i.e. bound/unbound). The reason for doing that is because warping is a concept that
	 * makes sense between root buckets of the same type since its effectively a scheduling advantage over a lower
	 * QoS root bucket.
	 */
	bitmap_t *warp_available_bitmap = (edf_bucket->scrb_bound) ? (root_clutch->scr_bound_warp_available) : (root_clutch->scr_unbound_warp_available);
	warp_bucket_index = bitmap_lsb_first(warp_available_bitmap, TH_BUCKET_SCHED_MAX);

	if ((warp_bucket_index == -1) || (warp_bucket_index >= edf_bucket->scrb_bucket)) {
		/* No higher buckets have warp left; best choice is the EDF based bucket */
		if (edf_bucket->scrb_starvation_avoidance) {
			/*
			 * Indicates that the earliest deadline bucket is in starvation avoidance mode. Check to see if the
			 * starvation avoidance window is still open and return this bucket if it is.
			 *
			 * The starvation avoidance window is calculated based on the quantum of threads at that bucket and
			 * the number of CPUs in the cluster. The idea is to basically provide one quantum worth of starvation
			 * avoidance across all CPUs.
			 */
			uint64_t starvation_window = sched_clutch_thread_quantum[edf_bucket->scrb_bucket] / root_clutch->scr_pset->online_processor_count;
			if (timestamp < (edf_bucket->scrb_starvation_ts + starvation_window)) {
				return edf_bucket;
			} else {
				/* Starvation avoidance window is over; update deadline and re-evaluate EDF */
				edf_bucket->scrb_starvation_avoidance = false;
				edf_bucket->scrb_starvation_ts = 0;
				sched_clutch_root_bucket_deadline_update(edf_bucket, root_clutch, timestamp);
			}
			goto evaluate_root_buckets;
		}

		/* Looks like the EDF bucket is not in starvation avoidance mode; check if it should be */
		if (highest_runnable_bucket < edf_bucket->scrb_bucket) {
			/* Since a higher bucket is runnable, it indicates that the EDF bucket should be in starvation avoidance */
			edf_bucket->scrb_starvation_avoidance = true;
			edf_bucket->scrb_starvation_ts = timestamp;
		} else {
			/* EDF bucket is being selected in the natural order; update deadline and reset warp */
			sched_clutch_root_bucket_deadline_update(edf_bucket, root_clutch, timestamp);
			edf_bucket->scrb_warp_remaining = sched_clutch_root_bucket_warp[edf_bucket->scrb_bucket];
			edf_bucket->scrb_warped_deadline = SCHED_CLUTCH_ROOT_BUCKET_WARP_UNUSED;
			if (edf_bucket->scrb_bound) {
				bitmap_set(root_clutch->scr_bound_warp_available, edf_bucket->scrb_bucket);
			} else {
				bitmap_set(root_clutch->scr_unbound_warp_available, edf_bucket->scrb_bucket);
			}
		}
		return edf_bucket;
	}

	/*
	 * Looks like there is a root bucket which is higher in the natural priority
	 * order than edf_bucket and might have some warp remaining.
	 */
	warp_bucket = (edf_bucket->scrb_bound) ? &root_clutch->scr_bound_buckets[warp_bucket_index] : &root_clutch->scr_unbound_buckets[warp_bucket_index];
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
	if (warp_bucket->scrb_bound) {
		bitmap_clear(root_clutch->scr_bound_warp_available, warp_bucket->scrb_bucket);
	} else {
		bitmap_clear(root_clutch->scr_unbound_warp_available, warp_bucket->scrb_bucket);
	}
	goto evaluate_root_buckets;
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

	uint64_t old_deadline = root_bucket->scrb_pqlink.deadline;
	uint64_t new_deadline = sched_clutch_root_bucket_deadline_calculate(root_bucket, timestamp);
	if (__improbable(old_deadline > new_deadline)) {
		panic("old_deadline (%llu) > new_deadline (%llu); root_bucket (%d); timestamp (%llu)", old_deadline, new_deadline, root_bucket->scrb_bucket, timestamp);
	}
	if (old_deadline != new_deadline) {
		root_bucket->scrb_pqlink.deadline = new_deadline;
		struct priority_queue_deadline_min *prioq = (root_bucket->scrb_bound) ? &root_clutch->scr_bound_root_buckets : &root_clutch->scr_unbound_root_buckets;
		priority_queue_entry_increased(prioq, &root_bucket->scrb_pqlink);
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
	bitmap_t *runnable_bitmap = (root_bucket->scrb_bound) ? root_clutch->scr_bound_runnable_bitmap : root_clutch->scr_unbound_runnable_bitmap;
	bitmap_set(runnable_bitmap, root_bucket->scrb_bucket);

	if (root_bucket->scrb_bucket == TH_BUCKET_FIXPRI) {
		/* Since the TH_BUCKET_FIXPRI bucket is not scheduled based on deadline, nothing more needed here */
		return;
	}

	if (root_bucket->scrb_starvation_avoidance == false) {
		/*
		 * Only update the deadline if the bucket was not in starvation avoidance mode. If the bucket was in
		 * starvation avoidance and its window has expired, the highest root bucket selection logic will notice
		 * that and fix it up.
		 */
		root_bucket->scrb_pqlink.deadline = sched_clutch_root_bucket_deadline_calculate(root_bucket, timestamp);
	}
	struct priority_queue_deadline_min *prioq = (root_bucket->scrb_bound) ? &root_clutch->scr_bound_root_buckets : &root_clutch->scr_unbound_root_buckets;
	priority_queue_insert(prioq, &root_bucket->scrb_pqlink);
	if (root_bucket->scrb_warp_remaining) {
		/* Since the bucket has some warp remaining and its now runnable, mark it as available for warp */
		bitmap_t *warp_bitmap = (root_bucket->scrb_bound) ? root_clutch->scr_bound_warp_available : root_clutch->scr_unbound_warp_available;
		bitmap_set(warp_bitmap, root_bucket->scrb_bucket);
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
	bitmap_t *runnable_bitmap = (root_bucket->scrb_bound) ? root_clutch->scr_bound_runnable_bitmap : root_clutch->scr_unbound_runnable_bitmap;
	bitmap_clear(runnable_bitmap, root_bucket->scrb_bucket);

	if (root_bucket->scrb_bucket == TH_BUCKET_FIXPRI) {
		/* Since the TH_BUCKET_FIXPRI bucket is not scheduled based on deadline, nothing more needed here */
		return;
	}

	struct priority_queue_deadline_min *prioq = (root_bucket->scrb_bound) ? &root_clutch->scr_bound_root_buckets : &root_clutch->scr_unbound_root_buckets;
	priority_queue_remove(prioq, &root_bucket->scrb_pqlink);

	bitmap_t *warp_bitmap = (root_bucket->scrb_bound) ? root_clutch->scr_bound_warp_available : root_clutch->scr_unbound_warp_available;
	bitmap_clear(warp_bitmap, root_bucket->scrb_bucket);

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

static int
sched_clutch_global_bucket_load_get(
	sched_bucket_t bucket)
{
	return (int)os_atomic_load(&sched_clutch_global_bucket_load[bucket], relaxed);
}

/*
 * sched_clutch_root_pri_update()
 *
 * The root level priority is used for thread selection and preemption
 * logic.
 *
 * The logic uses the same decision as thread selection for deciding between the
 * above UI and timeshare buckets. If one of the timesharing buckets have to be
 * used for priority calculation, the logic is slightly different from thread
 * selection, because thread selection considers deadlines, warps etc. to
 * decide the most optimal bucket at a given timestamp. Since the priority
 * value is used for preemption decisions only, it needs to be based on the
 * highest runnable thread available in the timeshare domain. This logic can
 * be made more sophisticated if there are cases of unnecessary preemption
 * being seen in workloads.
 */
static void
sched_clutch_root_pri_update(
	sched_clutch_root_t root_clutch)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
	int16_t root_bound_pri = NOPRI;
	int16_t root_unbound_pri = NOPRI;

	if (bitmap_lsb_first(root_clutch->scr_bound_runnable_bitmap, TH_BUCKET_SCHED_MAX) == -1) {
		goto root_pri_update_unbound;
	}
	sched_clutch_root_bucket_t root_bucket_bound = NULL;
	if (sched_clutch_root_bound_select_aboveui(root_clutch)) {
		root_bucket_bound = &root_clutch->scr_bound_buckets[TH_BUCKET_FIXPRI];
	} else {
		int root_bucket_index = bitmap_lsb_next(root_clutch->scr_bound_runnable_bitmap, TH_BUCKET_SCHED_MAX, TH_BUCKET_FIXPRI);
		assert(root_bucket_index != -1);
		root_bucket_bound = &root_clutch->scr_bound_buckets[root_bucket_index];
	}
	root_bound_pri = root_bucket_bound->scrb_bound_thread_runq.highq;

root_pri_update_unbound:
	if (bitmap_lsb_first(root_clutch->scr_unbound_runnable_bitmap, TH_BUCKET_SCHED_MAX) == -1) {
		goto root_pri_update_complete;
	}
	sched_clutch_root_bucket_t root_bucket_unbound = NULL;
	if (sched_clutch_root_unbound_select_aboveui(root_clutch)) {
		root_bucket_unbound = &root_clutch->scr_unbound_buckets[TH_BUCKET_FIXPRI];
	} else {
		int root_bucket_index = bitmap_lsb_next(root_clutch->scr_unbound_runnable_bitmap, TH_BUCKET_SCHED_MAX, TH_BUCKET_FIXPRI);
		assert(root_bucket_index != -1);
		root_bucket_unbound = &root_clutch->scr_unbound_buckets[root_bucket_index];
	}
	/* For the selected root bucket, find the highest priority clutch bucket */
	sched_clutch_bucket_t clutch_bucket = sched_clutch_root_bucket_highest_clutch_bucket(root_bucket_unbound);
	root_unbound_pri = priority_queue_max_sched_pri(&clutch_bucket->scb_clutchpri_prioq);

root_pri_update_complete:
	root_clutch->scr_priority = MAX(root_bound_pri, root_unbound_pri);
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
 * clutch represents a thread group and a clutch_bucket_group represents
 * threads at a particular sched_bucket within that thread group. The
 * clutch_bucket_group contains a clutch_bucket per cluster on the system
 * where it holds the runnable threads destined for execution on that
 * cluster.
 *
 * The goal of this level of scheduling is to allow interactive thread
 * groups low latency access to the CPU. It also provides slight
 * scheduling preference for App and unrestricted thread groups.
 *
 * The clutch bucket scheduling algorithm measures an interactivity
 * score for all clutch bucket groups. The interactivity score is based
 * on the ratio of the CPU used and the voluntary blocking of threads
 * within the clutch bucket group. The algorithm is very close to the ULE
 * scheduler on FreeBSD in terms of calculations. The interactivity
 * score provides an interactivity boost in the range of
 * [0:SCHED_CLUTCH_BUCKET_INTERACTIVE_PRI * 2] which allows interactive
 * thread groups to win over CPU spinners.
 *
 * The interactivity score of the clutch bucket group is combined with the
 * highest base/promoted priority of threads in the clutch bucket to form
 * the overall priority of the clutch bucket.
 */

/* Priority boost range for interactivity */
#define SCHED_CLUTCH_BUCKET_GROUP_INTERACTIVE_PRI_DEFAULT     (8)
uint8_t sched_clutch_bucket_group_interactive_pri = SCHED_CLUTCH_BUCKET_GROUP_INTERACTIVE_PRI_DEFAULT;

/* window to scale the cpu usage and blocked values (currently 500ms). Its the threshold of used+blocked */
uint64_t sched_clutch_bucket_group_adjust_threshold = 0;
#define SCHED_CLUTCH_BUCKET_GROUP_ADJUST_THRESHOLD_USECS      (500000)

/* The ratio to scale the cpu/blocked time per window */
#define SCHED_CLUTCH_BUCKET_GROUP_ADJUST_RATIO                (10)

/*
 * In order to allow App thread groups some preference over daemon thread
 * groups, the App clutch_buckets get a priority boost. The boost value should
 * be chosen such that badly behaved apps are still penalized over well
 * behaved interactive daemons.
 */
static uint8_t sched_clutch_bucket_group_pri_boost[SCHED_CLUTCH_TG_PRI_MAX] = {
	[SCHED_CLUTCH_TG_PRI_LOW]  = 0,
	[SCHED_CLUTCH_TG_PRI_MED]  = 2,
	[SCHED_CLUTCH_TG_PRI_HIGH] = 4,
};

/* Initial value for voluntary blocking time for the clutch_bucket */
#define SCHED_CLUTCH_BUCKET_GROUP_BLOCKED_TS_INVALID          (uint64_t)(~0)

/* Value indicating the clutch bucket is not pending execution */
#define SCHED_CLUTCH_BUCKET_GROUP_PENDING_INVALID             ((uint64_t)(~0))

/*
 * Thread group CPU starvation avoidance
 *
 * In heavily CPU contended scenarios, it is possible that some thread groups
 * which have a low interactivity score do not get CPU time at all. In order to
 * resolve that, the scheduler tries to ageout the CPU usage of the clutch
 * bucket group when it has been pending execution for a certain time as defined
 * by the sched_clutch_bucket_group_pending_delta_us values below.
 *
 * The values chosen here are very close to the WCEL values for each sched bucket.
 * These values are multiplied by the load average of the relevant root bucket to
 * provide an estimate of the actual clutch bucket load.
 */
static uint32_t sched_clutch_bucket_group_pending_delta_us[TH_BUCKET_SCHED_MAX] = {
	SCHED_CLUTCH_INVALID_TIME_32,           /* FIXPRI */
	10000,                                  /* FG */
	37500,                                  /* IN */
	75000,                                  /* DF */
	150000,                                 /* UT */
	250000,                                 /* BG */
};
static uint64_t sched_clutch_bucket_group_pending_delta[TH_BUCKET_SCHED_MAX] = {0};

/*
 * sched_clutch_bucket_init()
 *
 * Initializer for clutch buckets.
 */
static void
sched_clutch_bucket_init(
	sched_clutch_bucket_t clutch_bucket,
	sched_clutch_bucket_group_t clutch_bucket_group,
	sched_bucket_t bucket)
{
	bzero(clutch_bucket, sizeof(struct sched_clutch_bucket));

	clutch_bucket->scb_bucket = bucket;
	/* scb_priority will be recalculated when a thread is inserted in the clutch bucket */
	clutch_bucket->scb_priority = 0;
#if CONFIG_SCHED_EDGE
	clutch_bucket->scb_foreign = false;
	priority_queue_entry_init(&clutch_bucket->scb_foreignlink);
#endif /* CONFIG_SCHED_EDGE */
	clutch_bucket->scb_group = clutch_bucket_group;
	clutch_bucket->scb_root = NULL;
	priority_queue_init(&clutch_bucket->scb_clutchpri_prioq);
	priority_queue_init(&clutch_bucket->scb_thread_runq);
	queue_init(&clutch_bucket->scb_thread_timeshare_queue);
}

/*
 * sched_clutch_bucket_group_init()
 *
 * Initializer for clutch bucket groups.
 */
static void
sched_clutch_bucket_group_init(
	sched_clutch_bucket_group_t clutch_bucket_group,
	sched_clutch_t clutch,
	sched_bucket_t bucket)
{
	bzero(clutch_bucket_group, sizeof(struct sched_clutch_bucket_group));
	clutch_bucket_group->scbg_bucket = bucket;
	clutch_bucket_group->scbg_clutch = clutch;
	for (int i = 0; i < MAX_PSETS; i++) {
		sched_clutch_bucket_init(&clutch_bucket_group->scbg_clutch_buckets[i], clutch_bucket_group, bucket);
	}
	os_atomic_store(&clutch_bucket_group->scbg_timeshare_tick, 0, relaxed);
	os_atomic_store(&clutch_bucket_group->scbg_pri_shift, INT8_MAX, relaxed);
	os_atomic_store(&clutch_bucket_group->scbg_preferred_cluster, pset0.pset_cluster_id, relaxed);
	/*
	 * All thread groups should be initialized to be interactive; this allows the newly launched
	 * thread groups to fairly compete with already running thread groups.
	 */
	clutch_bucket_group->scbg_interactivity_data.scct_count = (sched_clutch_bucket_group_interactive_pri * 2);
	clutch_bucket_group->scbg_interactivity_data.scct_timestamp = 0;
	os_atomic_store(&clutch_bucket_group->scbg_cpu_data.cpu_data.scbcd_cpu_blocked, (clutch_cpu_data_t)sched_clutch_bucket_group_adjust_threshold, relaxed);
#if !__LP64__
	lck_spin_init(&clutch_bucket_group->scbg_stats_lock, &pset_lck_grp, NULL);
#endif /* !__LP64__ */
	clutch_bucket_group->scbg_blocked_data.scct_timestamp = SCHED_CLUTCH_BUCKET_GROUP_BLOCKED_TS_INVALID;
	clutch_bucket_group->scbg_pending_data.scct_timestamp = SCHED_CLUTCH_BUCKET_GROUP_PENDING_INVALID;
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
		sched_clutch_bucket_group_init(&(clutch->sc_clutch_groups[i]), clutch, i);
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

#if CONFIG_SCHED_EDGE

/*
 * The current edge scheduler still relies on globals for E & P clusters. It uses these
 * globals for the following operations:
 * - Sysctl support for configuring edges
 * - Edge scheduler initialization
 *
 * These should be removed for multi-cluster platforms once a clear policy for the above
 * operations is defined.
 * <Edge Multi-cluster Support Needed>
 */
static uint32_t ecore_cluster_id = 0;
static uint32_t pcore_cluster_id = 1;

/*
 * Edge Scheduler Preferred Cluster Mechanism
 *
 * In order to have better control over various QoS buckets within a thread group, the Edge
 * scheduler allows CLPC to specify a preferred cluster for each QoS level in a TG. These
 * preferences are stored at the sched_clutch_bucket_group level since that represents all
 * threads at a particular QoS level within a sched_clutch. For any lookup of preferred
 * cluster, the logic always goes back to the preference stored at the clutch_bucket_group.
 */

static uint32_t
sched_edge_clutch_bucket_group_preferred_cluster(sched_clutch_bucket_group_t clutch_bucket_group)
{
	return os_atomic_load(&clutch_bucket_group->scbg_preferred_cluster, relaxed);
}

static uint32_t
sched_clutch_bucket_preferred_cluster(sched_clutch_bucket_t clutch_bucket)
{
	return sched_edge_clutch_bucket_group_preferred_cluster(clutch_bucket->scb_group);
}

uint32_t
sched_edge_thread_preferred_cluster(thread_t thread)
{
	if (SCHED_CLUTCH_THREAD_CLUSTER_BOUND(thread)) {
		/* For threads bound to a specific cluster, return the bound cluster id */
		return sched_edge_thread_bound_cluster_id(thread);
	}

	sched_clutch_t clutch = sched_clutch_for_thread(thread);
	sched_clutch_bucket_group_t clutch_bucket_group = &clutch->sc_clutch_groups[thread->th_sched_bucket];
	return sched_edge_clutch_bucket_group_preferred_cluster(clutch_bucket_group);
}

/*
 * Edge Scheduler Foreign Bucket Support
 *
 * In the Edge Scheduler, each cluster maintains a priority queue of clutch buckets containing
 * threads that are not native to the cluster. A clutch bucket is considered native if its
 * preferred cluster has the same type as the cluster its enqueued in. The foreign clutch
 * bucket priority queue is used for rebalance operations to get threads back to their native
 * cluster quickly.
 *
 * It is possible to make this policy even more aggressive by considering all clusters that
 * are not the preferred cluster as the foreign cluster, but that would mean a lot of thread
 * migrations which might have performance implications.
 */

static void
sched_clutch_bucket_mark_native(sched_clutch_bucket_t clutch_bucket, sched_clutch_root_t root_clutch)
{
	if (clutch_bucket->scb_foreign) {
		clutch_bucket->scb_foreign = false;
		priority_queue_remove(&root_clutch->scr_foreign_buckets, &clutch_bucket->scb_foreignlink);
	}
}

static void
sched_clutch_bucket_mark_foreign(sched_clutch_bucket_t clutch_bucket, sched_clutch_root_t root_clutch)
{
	if (!clutch_bucket->scb_foreign) {
		clutch_bucket->scb_foreign = true;
		priority_queue_entry_set_sched_pri(&root_clutch->scr_foreign_buckets, &clutch_bucket->scb_foreignlink, clutch_bucket->scb_priority, 0);
		priority_queue_insert(&root_clutch->scr_foreign_buckets, &clutch_bucket->scb_foreignlink);
	}
}

/*
 * Edge Scheduler Cumulative Load Average
 *
 * The Edge scheduler maintains a per-QoS/scheduling bucket load average for
 * making thread migration decisions. The per-bucket load is maintained as a
 * cumulative count since higher scheduling buckets impact load on lower buckets
 * for thread migration decisions.
 *
 */

static void
sched_edge_cluster_cumulative_count_incr(sched_clutch_root_t root_clutch, sched_bucket_t bucket)
{
	switch (bucket) {
	case TH_BUCKET_FIXPRI:    os_atomic_inc(&root_clutch->scr_cumulative_run_count[TH_BUCKET_FIXPRI], relaxed); OS_FALLTHROUGH;
	case TH_BUCKET_SHARE_FG:  os_atomic_inc(&root_clutch->scr_cumulative_run_count[TH_BUCKET_SHARE_FG], relaxed); OS_FALLTHROUGH;
	case TH_BUCKET_SHARE_IN:  os_atomic_inc(&root_clutch->scr_cumulative_run_count[TH_BUCKET_SHARE_IN], relaxed); OS_FALLTHROUGH;
	case TH_BUCKET_SHARE_DF:  os_atomic_inc(&root_clutch->scr_cumulative_run_count[TH_BUCKET_SHARE_DF], relaxed); OS_FALLTHROUGH;
	case TH_BUCKET_SHARE_UT:  os_atomic_inc(&root_clutch->scr_cumulative_run_count[TH_BUCKET_SHARE_UT], relaxed); OS_FALLTHROUGH;
	case TH_BUCKET_SHARE_BG:  os_atomic_inc(&root_clutch->scr_cumulative_run_count[TH_BUCKET_SHARE_BG], relaxed); break;
	default:
		panic("Unexpected sched_bucket passed to sched_edge_cluster_cumulative_count_incr()");
	}
}

static void
sched_edge_cluster_cumulative_count_decr(sched_clutch_root_t root_clutch, sched_bucket_t bucket)
{
	switch (bucket) {
	case TH_BUCKET_FIXPRI:    os_atomic_dec(&root_clutch->scr_cumulative_run_count[TH_BUCKET_FIXPRI], relaxed); OS_FALLTHROUGH;
	case TH_BUCKET_SHARE_FG:  os_atomic_dec(&root_clutch->scr_cumulative_run_count[TH_BUCKET_SHARE_FG], relaxed); OS_FALLTHROUGH;
	case TH_BUCKET_SHARE_IN:  os_atomic_dec(&root_clutch->scr_cumulative_run_count[TH_BUCKET_SHARE_IN], relaxed); OS_FALLTHROUGH;
	case TH_BUCKET_SHARE_DF:  os_atomic_dec(&root_clutch->scr_cumulative_run_count[TH_BUCKET_SHARE_DF], relaxed); OS_FALLTHROUGH;
	case TH_BUCKET_SHARE_UT:  os_atomic_dec(&root_clutch->scr_cumulative_run_count[TH_BUCKET_SHARE_UT], relaxed); OS_FALLTHROUGH;
	case TH_BUCKET_SHARE_BG:  os_atomic_dec(&root_clutch->scr_cumulative_run_count[TH_BUCKET_SHARE_BG], relaxed); break;
	default:
		panic("Unexpected sched_bucket passed to sched_edge_cluster_cumulative_count_decr()");
	}
}

uint16_t
sched_edge_cluster_cumulative_count(sched_clutch_root_t root_clutch, sched_bucket_t bucket)
{
	return os_atomic_load(&root_clutch->scr_cumulative_run_count[bucket], relaxed);
}

#endif /* CONFIG_SCHED_EDGE */

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
	uint64_t timestamp,
	sched_clutch_bucket_options_t options)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
	if (bucket > TH_BUCKET_FIXPRI) {
		/* Enqueue the timeshare clutch buckets into the global runnable clutch_bucket list; used for sched tick operations */
		enqueue_tail(&root_clutch->scr_clutch_buckets, &clutch_bucket->scb_listlink);
	}
#if CONFIG_SCHED_EDGE
	/* Check if the bucket is a foreign clutch bucket and add it to the foreign buckets list */
	uint32_t preferred_cluster = sched_clutch_bucket_preferred_cluster(clutch_bucket);
	if (pset_type_for_id(preferred_cluster) != pset_type_for_id(root_clutch->scr_cluster_id)) {
		sched_clutch_bucket_mark_foreign(clutch_bucket, root_clutch);
	}
#endif /* CONFIG_SCHED_EDGE */
	sched_clutch_root_bucket_t root_bucket = &root_clutch->scr_unbound_buckets[bucket];

	/* If this is the first clutch bucket in the root bucket, insert the root bucket into the root priority queue */
	if (sched_clutch_bucket_runq_empty(&root_bucket->scrb_clutch_buckets)) {
		sched_clutch_root_bucket_runnable(root_bucket, root_clutch, timestamp);
	}

	/* Insert the clutch bucket into the root bucket run queue with order based on options */
	sched_clutch_bucket_runq_enqueue(&root_bucket->scrb_clutch_buckets, clutch_bucket, options);
	os_atomic_store(&clutch_bucket->scb_root, root_clutch, relaxed);
	os_atomic_inc(&sched_clutch_global_bucket_load[bucket], relaxed);
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
	uint64_t timestamp,
	__unused sched_clutch_bucket_options_t options)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
	if (bucket > TH_BUCKET_FIXPRI) {
		/* Remove the timeshare clutch bucket from the globally runnable clutch_bucket list */
		remqueue(&clutch_bucket->scb_listlink);
	}
#if CONFIG_SCHED_EDGE
	sched_clutch_bucket_mark_native(clutch_bucket, root_clutch);
#endif /* CONFIG_SCHED_EDGE */

	sched_clutch_root_bucket_t root_bucket = &root_clutch->scr_unbound_buckets[bucket];

	/* Remove the clutch bucket from the root bucket priority queue */
	sched_clutch_bucket_runq_remove(&root_bucket->scrb_clutch_buckets, clutch_bucket);
	os_atomic_store(&clutch_bucket->scb_root, NULL, relaxed);

	/* If the root bucket priority queue is now empty, remove it from the root priority queue */
	if (sched_clutch_bucket_runq_empty(&root_bucket->scrb_clutch_buckets)) {
		sched_clutch_root_bucket_empty(root_bucket, root_clutch, timestamp);
	}
	os_atomic_dec(&sched_clutch_global_bucket_load[bucket], relaxed);
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
	assert(priority_queue_empty(&clutch_bucket->scb_thread_runq) == false);

	sched_clutch_t clutch = clutch_bucket->scb_group->scbg_clutch;

	/*
	 * Since the clutch bucket can contain threads that are members of the group due
	 * to the sched_pri being promoted or due to their base pri, the base priority of
	 * the entire clutch bucket should be based on the highest thread (promoted or base)
	 * in the clutch bucket.
	 */
	uint8_t max_pri = 0;
	if (!priority_queue_empty(&clutch_bucket->scb_clutchpri_prioq)) {
		max_pri = priority_queue_max_sched_pri(&clutch_bucket->scb_clutchpri_prioq);
	}

	sched_clutch_tg_priority_t tg_pri = os_atomic_load(&clutch->sc_tg_priority, relaxed);
	clutch_boost = sched_clutch_bucket_group_pri_boost[tg_pri];
	return max_pri + clutch_boost;
}

/*
 * sched_clutch_interactivity_from_cpu_data()
 *
 * Routine to calculate the interactivity score of a clutch bucket group from its CPU usage
 */
static uint8_t
sched_clutch_interactivity_from_cpu_data(sched_clutch_bucket_group_t clutch_bucket_group)
{
	sched_clutch_bucket_cpu_data_t scb_cpu_data;
	scb_cpu_data.scbcd_cpu_data_packed = os_atomic_load_wide(&clutch_bucket_group->scbg_cpu_data.scbcd_cpu_data_packed, relaxed);
	clutch_cpu_data_t cpu_used = scb_cpu_data.cpu_data.scbcd_cpu_used;
	clutch_cpu_data_t cpu_blocked = scb_cpu_data.cpu_data.scbcd_cpu_blocked;
	uint8_t interactive_score = 0;

	if ((cpu_blocked == 0) && (cpu_used == 0)) {
		return (uint8_t)clutch_bucket_group->scbg_interactivity_data.scct_count;
	}
	/*
	 * For all timeshare buckets, calculate the interactivity score of the bucket
	 * and add it to the base priority
	 */
	if (cpu_blocked > cpu_used) {
		/* Interactive clutch_bucket case */
		interactive_score = sched_clutch_bucket_group_interactive_pri +
		    ((sched_clutch_bucket_group_interactive_pri * (cpu_blocked - cpu_used)) / cpu_blocked);
	} else {
		/* Non-interactive clutch_bucket case */
		interactive_score = ((sched_clutch_bucket_group_interactive_pri * cpu_blocked) / cpu_used);
	}
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
	uint8_t interactive_score = sched_clutch_bucket_group_interactivity_score_calculate(clutch_bucket->scb_group, timestamp);

	assert(((uint64_t)base_pri + interactive_score) <= UINT8_MAX);
	uint8_t pri = base_pri + interactive_score;
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_CLUTCH_TG_BUCKET_PRI) | DBG_FUNC_NONE,
	    thread_group_get_id(clutch_bucket->scb_group->scbg_clutch->sc_tg), clutch_bucket->scb_bucket, pri, interactive_score, 0);
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
	if (sched_clutch_bucket_runq_empty(&root_bucket->scrb_clutch_buckets)) {
		return NULL;
	}
	return sched_clutch_bucket_runq_peek(&root_bucket->scrb_clutch_buckets);
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
	uint64_t timestamp,
	sched_clutch_bucket_options_t options)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
	/* Since the clutch bucket became newly runnable, update its pending timestamp */
	clutch_bucket->scb_priority = sched_clutch_bucket_pri_calculate(clutch_bucket, timestamp);
	sched_clutch_bucket_hierarchy_insert(root_clutch, clutch_bucket, clutch_bucket->scb_bucket, timestamp, options);

	/* Update the timesharing properties of this clutch_bucket; also done every sched_tick */
	sched_clutch_bucket_group_timeshare_update(clutch_bucket->scb_group, clutch_bucket, timestamp);
	int16_t root_old_pri = root_clutch->scr_priority;
	sched_clutch_root_pri_update(root_clutch);
	return root_clutch->scr_priority > root_old_pri;
}

/*
 * sched_clutch_bucket_update()
 *
 * Update the clutch_bucket's position in the hierarchy. This routine is
 * called when a new thread is inserted or removed from a runnable clutch
 * bucket. The options specify some properties about the clutch bucket
 * insertion order into the clutch bucket runq.
 */
static boolean_t
sched_clutch_bucket_update(
	sched_clutch_bucket_t clutch_bucket,
	sched_clutch_root_t root_clutch,
	uint64_t timestamp,
	sched_clutch_bucket_options_t options)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
	uint64_t new_pri = sched_clutch_bucket_pri_calculate(clutch_bucket, timestamp);
	sched_clutch_bucket_runq_t bucket_runq = &root_clutch->scr_unbound_buckets[clutch_bucket->scb_bucket].scrb_clutch_buckets;
	if (new_pri == clutch_bucket->scb_priority) {
		/*
		 * If SCHED_CLUTCH_BUCKET_OPTIONS_SAMEPRI_RR is specified, move the clutch bucket
		 * to the end of the runq. Typically used when a thread is selected for execution
		 * from a clutch bucket.
		 */
		if (options & SCHED_CLUTCH_BUCKET_OPTIONS_SAMEPRI_RR) {
			sched_clutch_bucket_runq_rotate(bucket_runq, clutch_bucket);
		}
		return false;
	}
	sched_clutch_bucket_runq_remove(bucket_runq, clutch_bucket);
#if CONFIG_SCHED_EDGE
	if (clutch_bucket->scb_foreign) {
		priority_queue_remove(&root_clutch->scr_foreign_buckets, &clutch_bucket->scb_foreignlink);
	}
#endif /* CONFIG_SCHED_EDGE */
	clutch_bucket->scb_priority = new_pri;
#if CONFIG_SCHED_EDGE
	if (clutch_bucket->scb_foreign) {
		priority_queue_entry_set_sched_pri(&root_clutch->scr_foreign_buckets, &clutch_bucket->scb_foreignlink, clutch_bucket->scb_priority, 0);
		priority_queue_insert(&root_clutch->scr_foreign_buckets, &clutch_bucket->scb_foreignlink);
	}
#endif /* CONFIG_SCHED_EDGE */
	sched_clutch_bucket_runq_enqueue(bucket_runq, clutch_bucket, options);

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
	uint64_t timestamp,
	sched_clutch_bucket_options_t options)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
	sched_clutch_bucket_hierarchy_remove(root_clutch, clutch_bucket, clutch_bucket->scb_bucket, timestamp, options);
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
	if (!SCHED_CLUTCH_THREAD_ELIGIBLE(thread) || SCHED_CLUTCH_THREAD_CLUSTER_BOUND(thread)) {
		return;
	}

	sched_clutch_t clutch = sched_clutch_for_thread(thread);
	sched_clutch_bucket_group_t clutch_bucket_group = &(clutch->sc_clutch_groups[thread->th_sched_bucket]);
	sched_clutch_bucket_group_cpu_usage_update(clutch_bucket_group, delta);
}

/*
 * sched_clutch_bucket_group_cpu_usage_update()
 *
 * Routine to update the CPU usage of the clutch_bucket.
 */
static void
sched_clutch_bucket_group_cpu_usage_update(
	sched_clutch_bucket_group_t clutch_bucket_group,
	uint64_t delta)
{
	if (clutch_bucket_group->scbg_bucket == TH_BUCKET_FIXPRI) {
		/* Since Above UI bucket has maximum interactivity score always, nothing to do here */
		return;
	}
	delta = MIN(delta, sched_clutch_bucket_group_adjust_threshold);
	os_atomic_add(&(clutch_bucket_group->scbg_cpu_data.cpu_data.scbcd_cpu_used), (clutch_cpu_data_t)delta, relaxed);
}

/*
 * sched_clutch_bucket_group_cpu_pending_adjust()
 *
 * Routine to calculate the adjusted CPU usage value based on the pending intervals. The calculation is done
 * such that one "pending interval" provides one point improvement in interactivity score.
 */
static inline uint64_t
sched_clutch_bucket_group_cpu_pending_adjust(
	uint64_t cpu_used,
	uint64_t cpu_blocked,
	uint8_t pending_intervals)
{
	uint64_t cpu_used_adjusted = 0;
	if (cpu_blocked < cpu_used) {
		cpu_used_adjusted = (sched_clutch_bucket_group_interactive_pri * cpu_blocked * cpu_used);
		cpu_used_adjusted = cpu_used_adjusted / ((sched_clutch_bucket_group_interactive_pri * cpu_blocked) + (cpu_used * pending_intervals));
	} else {
		uint64_t adjust_factor = (cpu_blocked * pending_intervals) / sched_clutch_bucket_group_interactive_pri;
		cpu_used_adjusted = (adjust_factor > cpu_used) ? 0 : (cpu_used - adjust_factor);
	}
	return cpu_used_adjusted;
}

/*
 * sched_clutch_bucket_group_cpu_adjust()
 *
 * Routine to scale the cpu usage and blocked time once the sum gets bigger
 * than sched_clutch_bucket_group_adjust_threshold. Allows the values to remain
 * manageable and maintain the same ratio while allowing clutch buckets to
 * adjust behavior and reflect in the interactivity score in a reasonable
 * amount of time. Also adjusts the CPU usage based on pending_intervals
 * which allows ageout of CPU to avoid starvation in highly contended scenarios.
 */
static void
sched_clutch_bucket_group_cpu_adjust(
	sched_clutch_bucket_group_t clutch_bucket_group,
	uint8_t pending_intervals)
{
	sched_clutch_bucket_cpu_data_t old_cpu_data = {};
	sched_clutch_bucket_cpu_data_t new_cpu_data = {};
	os_atomic_rmw_loop(&clutch_bucket_group->scbg_cpu_data.scbcd_cpu_data_packed, old_cpu_data.scbcd_cpu_data_packed, new_cpu_data.scbcd_cpu_data_packed, relaxed, {
		clutch_cpu_data_t cpu_used = old_cpu_data.cpu_data.scbcd_cpu_used;
		clutch_cpu_data_t cpu_blocked = old_cpu_data.cpu_data.scbcd_cpu_blocked;

		if ((pending_intervals == 0) && (cpu_used + cpu_blocked) < sched_clutch_bucket_group_adjust_threshold) {
		        /* No changes to the CPU used and blocked values */
		        os_atomic_rmw_loop_give_up();
		}
		if ((cpu_used + cpu_blocked) >= sched_clutch_bucket_group_adjust_threshold) {
		        /* Only keep the recent CPU history to better indicate how this TG has been behaving */
		        cpu_used = cpu_used / SCHED_CLUTCH_BUCKET_GROUP_ADJUST_RATIO;
		        cpu_blocked = cpu_blocked / SCHED_CLUTCH_BUCKET_GROUP_ADJUST_RATIO;
		}
		/* Use the shift passed in to ageout the CPU usage */
		cpu_used = (clutch_cpu_data_t)sched_clutch_bucket_group_cpu_pending_adjust(cpu_used, cpu_blocked, pending_intervals);
		new_cpu_data.cpu_data.scbcd_cpu_used = cpu_used;
		new_cpu_data.cpu_data.scbcd_cpu_blocked = cpu_blocked;
	});
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
	sched_clutch_bucket_group_t clutch_bucket_group = &(clutch->sc_clutch_groups[bucket]);
	return sched_clutch_bucket_group_run_count_inc(clutch_bucket_group);
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
	sched_clutch_bucket_group_t clutch_bucket_group = &(clutch->sc_clutch_groups[bucket]);
	return sched_clutch_bucket_group_run_count_dec(clutch_bucket_group);
}

/*
 * sched_clutch_bucket_group_timeshare_update()
 *
 * Routine to update the load and priority shift for the clutch_bucket_group
 * every sched_tick. For multi-cluster platforms, each QoS level will have multiple
 * clutch buckets with runnable threads in them. So it is important to maintain
 * the timesharing information at the clutch_bucket_group level instead of
 * individual clutch buckets (because the algorithm is trying to timeshare all
 * threads at the same QoS irrespective of which hierarchy they are enqueued in).
 *
 * The routine is called from the sched tick handling code to make sure this value
 * is updated at least once every sched tick. For clutch bucket groups which have
 * not been runnable for very long, the clutch_bucket_group maintains a "last
 * updated schedtick" parameter. As threads become runnable in the clutch bucket group,
 * if this value is outdated, the load and shifts are updated.
 *
 * Possible optimization:
 * - The current algorithm samples the load every sched tick (125ms).
 *   This is prone to spikes in runnable counts; if that turns out to be
 *   a problem, a simple solution would be to do the EWMA trick to sample
 *   load at every load_tick (30ms) and use the averaged value for the pri
 *   shift calculation.
 */
static void
sched_clutch_bucket_group_timeshare_update(
	sched_clutch_bucket_group_t clutch_bucket_group,
	sched_clutch_bucket_t clutch_bucket,
	uint64_t ctime)
{
	if (clutch_bucket_group->scbg_bucket < TH_BUCKET_SHARE_FG) {
		/* No timesharing needed for fixed priority Above UI threads */
		return;
	}

	/*
	 * Update the timeshare parameters for the clutch bucket group
	 * if they havent been updated in this tick.
	 */
	uint32_t sched_ts = os_atomic_load(&clutch_bucket_group->scbg_timeshare_tick, relaxed);
	uint32_t current_sched_ts = sched_tick;
	if (sched_ts < current_sched_ts) {
		os_atomic_store(&clutch_bucket_group->scbg_timeshare_tick, current_sched_ts, relaxed);
		/* NCPU wide workloads should not experience decay */
		uint64_t bucket_group_run_count = os_atomic_load_wide(&clutch_bucket_group->scbg_blocked_data.scct_count, relaxed) - 1;
		uint32_t bucket_group_load = (uint32_t)(bucket_group_run_count / processor_avail_count);
		bucket_group_load = MIN(bucket_group_load, NRQS - 1);
		uint32_t pri_shift = sched_fixed_shift - sched_load_shifts[bucket_group_load];
		/* Ensure that the pri_shift value is reasonable */
		pri_shift = (pri_shift > SCHED_PRI_SHIFT_MAX) ? INT8_MAX : pri_shift;
		os_atomic_store(&clutch_bucket_group->scbg_pri_shift, pri_shift, relaxed);
	}

	/*
	 * Update the clutch bucket priority; this allows clutch buckets that have been pending
	 * for a long time to get an updated interactivity score.
	 */
	sched_clutch_bucket_update(clutch_bucket, clutch_bucket->scb_root, ctime, SCHED_CLUTCH_BUCKET_OPTIONS_NONE);
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
		if (!SCHED_CLUTCH_THREAD_CLUSTER_BOUND(thread)) {
			sched_clutch_bucket_group_t clutch_bucket_group = &(old_clutch->sc_clutch_groups[thread->th_sched_bucket]);
			sched_clutch_bucket_group_cpu_usage_update(clutch_bucket_group, cpu_delta);
		}
	}

	if (new_clutch) {
		sched_clutch_run_bucket_incr(new_clutch, thread->th_sched_bucket);
	}
}

/* Thread Insertion/Removal/Selection routines */

#if CONFIG_SCHED_EDGE

/*
 * Edge Scheduler Bound Thread Support
 *
 * The edge scheduler allows threads to be bound to specific clusters. The scheduler
 * maintains a separate runq on the clutch root to hold these bound threads. These
 * bound threads count towards the root priority and thread count, but are ignored
 * for thread migration/steal decisions. Bound threads that are enqueued in the
 * separate runq have the th_bound_cluster_enqueued flag set to allow easy
 * removal.
 *
 * Bound Threads Timesharing
 * The bound threads share the timesharing properties of the clutch bucket group they are
 * part of. They contribute to the load and use priority shifts/decay values from the
 * clutch bucket group.
 */

static boolean_t
sched_edge_bound_thread_insert(
	sched_clutch_root_t root_clutch,
	thread_t thread,
	integer_t options)
{
	/* Update the clutch runnable count and priority */
	sched_clutch_thr_count_inc(&root_clutch->scr_thr_count);
	sched_clutch_root_bucket_t root_bucket = &root_clutch->scr_bound_buckets[thread->th_sched_bucket];
	if (root_bucket->scrb_bound_thread_runq.count == 0) {
		sched_clutch_root_bucket_runnable(root_bucket, root_clutch, mach_absolute_time());
	}

	assert((thread->th_bound_cluster_enqueued) == false);
	run_queue_enqueue(&root_bucket->scrb_bound_thread_runq, thread, options);
	thread->th_bound_cluster_enqueued = true;

	int16_t root_old_pri = root_clutch->scr_priority;
	sched_clutch_root_pri_update(root_clutch);
	return root_clutch->scr_priority > root_old_pri;
}

static void
sched_edge_bound_thread_remove(
	sched_clutch_root_t root_clutch,
	thread_t thread)
{
	sched_clutch_root_bucket_t root_bucket = &root_clutch->scr_bound_buckets[thread->th_sched_bucket];
	assert((thread->th_bound_cluster_enqueued) == true);
	run_queue_remove(&root_bucket->scrb_bound_thread_runq, thread);
	thread->th_bound_cluster_enqueued = false;

	/* Update the clutch runnable count and priority */
	sched_clutch_thr_count_dec(&root_clutch->scr_thr_count);
	if (root_bucket->scrb_bound_thread_runq.count == 0) {
		sched_clutch_root_bucket_empty(root_bucket, root_clutch, mach_absolute_time());
	}
	sched_clutch_root_pri_update(root_clutch);
}

#endif /* CONFIG_SCHED_EDGE */

/*
 * sched_clutch_thread_bound_lookup()
 *
 * Routine to lookup the highest priority runnable thread in a bounded root bucket.
 */
static thread_t
sched_clutch_thread_bound_lookup(
	__unused sched_clutch_root_t root_clutch,
	sched_clutch_root_bucket_t root_bucket)
{
	return run_queue_peek(&root_bucket->scrb_bound_thread_runq);
}

/*
 * Clutch Bucket Group Thread Counts and Pending time calculation
 *
 * The pending time on the clutch_bucket_group allows the scheduler to track if it
 * needs to ageout the CPU usage because the clutch_bucket_group has been pending for
 * a very long time. The pending time is set to the timestamp as soon as a thread becomes
 * runnable. When a thread is picked up for execution from this clutch_bucket_group, the
 * pending time is advanced to the time of thread selection.
 *
 * Since threads for a clutch bucket group can be added or removed from multiple CPUs
 * simulataneously, it is important that the updates to thread counts and pending timestamps
 * happen atomically. The implementation relies on the following aspects to make that work
 * as expected:
 * - The clutch scheduler would be deployed on single cluster platforms where the pset lock
 *   is held when threads are added/removed and pending timestamps are updated
 * - The edge scheduler would have support for double wide 128 bit atomics which allow the
 *   thread count and pending timestamp to be updated atomically.
 *
 * Clutch bucket group interactivity timestamp and score updates also rely on the properties
 * above to atomically update the interactivity score for a clutch bucket group.
 */

#if CONFIG_SCHED_EDGE

static void
sched_clutch_bucket_group_thr_count_inc(
	sched_clutch_bucket_group_t clutch_bucket_group,
	uint64_t timestamp)
{
	sched_clutch_counter_time_t old_pending_data;
	sched_clutch_counter_time_t new_pending_data;
	os_atomic_rmw_loop(&clutch_bucket_group->scbg_pending_data.scct_packed, old_pending_data.scct_packed, new_pending_data.scct_packed, relaxed, {
		new_pending_data.scct_count = old_pending_data.scct_count + 1;
		new_pending_data.scct_timestamp = old_pending_data.scct_timestamp;
		if (old_pending_data.scct_count == 0) {
		        new_pending_data.scct_timestamp = timestamp;
		}
	});
}

static void
sched_clutch_bucket_group_thr_count_dec(
	sched_clutch_bucket_group_t clutch_bucket_group,
	uint64_t timestamp)
{
	sched_clutch_counter_time_t old_pending_data;
	sched_clutch_counter_time_t new_pending_data;
	os_atomic_rmw_loop(&clutch_bucket_group->scbg_pending_data.scct_packed, old_pending_data.scct_packed, new_pending_data.scct_packed, relaxed, {
		new_pending_data.scct_count = old_pending_data.scct_count - 1;
		if (new_pending_data.scct_count == 0) {
		        new_pending_data.scct_timestamp = SCHED_CLUTCH_BUCKET_GROUP_PENDING_INVALID;
		} else {
		        new_pending_data.scct_timestamp = timestamp;
		}
	});
}

static uint8_t
sched_clutch_bucket_group_pending_ageout(
	sched_clutch_bucket_group_t clutch_bucket_group,
	uint64_t timestamp)
{
	int bucket_load = sched_clutch_global_bucket_load_get(clutch_bucket_group->scbg_bucket);
	sched_clutch_counter_time_t old_pending_data;
	sched_clutch_counter_time_t new_pending_data;
	uint8_t cpu_usage_shift = 0;

	os_atomic_rmw_loop(&clutch_bucket_group->scbg_pending_data.scct_packed, old_pending_data.scct_packed, new_pending_data.scct_packed, relaxed, {
		cpu_usage_shift = 0;
		uint64_t old_pending_ts = old_pending_data.scct_timestamp;
		bool old_update = (old_pending_ts >= timestamp);
		bool no_pending_time = (old_pending_ts == SCHED_CLUTCH_BUCKET_GROUP_PENDING_INVALID);
		bool no_bucket_load = (bucket_load == 0);
		if (old_update || no_pending_time || no_bucket_load) {
		        os_atomic_rmw_loop_give_up();
		}

		/* Calculate the time the clutch bucket group has been pending */
		uint64_t pending_delta = timestamp - old_pending_ts;
		uint64_t interactivity_delta = sched_clutch_bucket_group_pending_delta[clutch_bucket_group->scbg_bucket] * bucket_load;
		if (pending_delta < interactivity_delta) {
		        os_atomic_rmw_loop_give_up();
		}
		cpu_usage_shift = (pending_delta / interactivity_delta);
		new_pending_data.scct_timestamp = old_pending_ts + (cpu_usage_shift * interactivity_delta);
		new_pending_data.scct_count = old_pending_data.scct_count;
	});
	return cpu_usage_shift;
}

static uint8_t
sched_clutch_bucket_group_interactivity_score_calculate(
	sched_clutch_bucket_group_t clutch_bucket_group,
	uint64_t timestamp)
{
	if (clutch_bucket_group->scbg_bucket == TH_BUCKET_FIXPRI) {
		/*
		 * Since the root bucket selection algorithm for Above UI looks at clutch bucket
		 * priorities, make sure all AboveUI buckets are marked interactive.
		 */
		assert(clutch_bucket_group->scbg_interactivity_data.scct_count == (2 * sched_clutch_bucket_group_interactive_pri));
		return (uint8_t)clutch_bucket_group->scbg_interactivity_data.scct_count;
	}
	/* Check if the clutch bucket group CPU usage needs to be aged out due to pending time */
	uint8_t pending_intervals = sched_clutch_bucket_group_pending_ageout(clutch_bucket_group, timestamp);
	/* Adjust CPU stats based on the calculated shift and to make sure only recent behavior is used */
	sched_clutch_bucket_group_cpu_adjust(clutch_bucket_group, pending_intervals);
	uint8_t interactivity_score = sched_clutch_interactivity_from_cpu_data(clutch_bucket_group);
	sched_clutch_counter_time_t old_interactivity_data;
	sched_clutch_counter_time_t new_interactivity_data;

	bool score_updated = os_atomic_rmw_loop(&clutch_bucket_group->scbg_interactivity_data.scct_packed, old_interactivity_data.scct_packed, new_interactivity_data.scct_packed, relaxed, {
		if (old_interactivity_data.scct_timestamp >= timestamp) {
		        os_atomic_rmw_loop_give_up();
		}
		new_interactivity_data.scct_timestamp = timestamp;
		if (old_interactivity_data.scct_timestamp != 0) {
		        new_interactivity_data.scct_count = interactivity_score;
		}
	});
	if (score_updated) {
		return (uint8_t)new_interactivity_data.scct_count;
	} else {
		return (uint8_t)old_interactivity_data.scct_count;
	}
}

#else /* CONFIG_SCHED_EDGE */

/*
 * For the clutch scheduler, atomicity is ensured by making sure all operations
 * are happening under the pset lock of the only cluster present on the platform.
 */
static void
sched_clutch_bucket_group_thr_count_inc(
	sched_clutch_bucket_group_t clutch_bucket_group,
	uint64_t timestamp)
{
	sched_clutch_hierarchy_locked_assert(&pset0.pset_clutch_root);
	if (clutch_bucket_group->scbg_pending_data.scct_count == 0) {
		clutch_bucket_group->scbg_pending_data.scct_timestamp = timestamp;
	}
	clutch_bucket_group->scbg_pending_data.scct_count++;
}

static void
sched_clutch_bucket_group_thr_count_dec(
	sched_clutch_bucket_group_t clutch_bucket_group,
	uint64_t timestamp)
{
	sched_clutch_hierarchy_locked_assert(&pset0.pset_clutch_root);
	clutch_bucket_group->scbg_pending_data.scct_count--;
	if (clutch_bucket_group->scbg_pending_data.scct_count == 0) {
		clutch_bucket_group->scbg_pending_data.scct_timestamp = SCHED_CLUTCH_BUCKET_GROUP_PENDING_INVALID;
	} else {
		clutch_bucket_group->scbg_pending_data.scct_timestamp = timestamp;
	}
}

static uint8_t
sched_clutch_bucket_group_pending_ageout(
	sched_clutch_bucket_group_t clutch_bucket_group,
	uint64_t timestamp)
{
	sched_clutch_hierarchy_locked_assert(&pset0.pset_clutch_root);
	int bucket_load = sched_clutch_global_bucket_load_get(clutch_bucket_group->scbg_bucket);
	uint64_t old_pending_ts = clutch_bucket_group->scbg_pending_data.scct_timestamp;
	bool old_update = (old_pending_ts >= timestamp);
	bool no_pending_time = (old_pending_ts == SCHED_CLUTCH_BUCKET_GROUP_PENDING_INVALID);
	bool no_bucket_load = (bucket_load == 0);
	if (old_update || no_pending_time || no_bucket_load) {
		return 0;
	}
	uint64_t pending_delta = timestamp - old_pending_ts;
	uint64_t interactivity_delta = sched_clutch_bucket_group_pending_delta[clutch_bucket_group->scbg_bucket] * bucket_load;
	if (pending_delta < interactivity_delta) {
		return 0;
	}
	uint8_t cpu_usage_shift = (pending_delta / interactivity_delta);
	clutch_bucket_group->scbg_pending_data.scct_timestamp = old_pending_ts + (cpu_usage_shift * interactivity_delta);
	return cpu_usage_shift;
}

static uint8_t
sched_clutch_bucket_group_interactivity_score_calculate(
	sched_clutch_bucket_group_t clutch_bucket_group,
	uint64_t timestamp)
{
	sched_clutch_hierarchy_locked_assert(&pset0.pset_clutch_root);
	if (clutch_bucket_group->scbg_bucket == TH_BUCKET_FIXPRI) {
		/*
		 * Since the root bucket selection algorithm for Above UI looks at clutch bucket
		 * priorities, make sure all AboveUI buckets are marked interactive.
		 */
		assert(clutch_bucket_group->scbg_interactivity_data.scct_count == (2 * sched_clutch_bucket_group_interactive_pri));
		return (uint8_t)clutch_bucket_group->scbg_interactivity_data.scct_count;
	}
	/* Check if the clutch bucket group CPU usage needs to be aged out due to pending time */
	uint8_t pending_intervals = sched_clutch_bucket_group_pending_ageout(clutch_bucket_group, timestamp);
	/* Adjust CPU stats based on the calculated shift and to make sure only recent behavior is used */
	sched_clutch_bucket_group_cpu_adjust(clutch_bucket_group, pending_intervals);
	uint8_t interactivity_score = sched_clutch_interactivity_from_cpu_data(clutch_bucket_group);
	if (timestamp > clutch_bucket_group->scbg_interactivity_data.scct_timestamp) {
		clutch_bucket_group->scbg_interactivity_data.scct_count = interactivity_score;
		clutch_bucket_group->scbg_interactivity_data.scct_timestamp = timestamp;
		return interactivity_score;
	} else {
		return (uint8_t)clutch_bucket_group->scbg_interactivity_data.scct_count;
	}
}

#endif /* CONFIG_SCHED_EDGE */

/*
 * Clutch Bucket Group Run Count and Blocked Time Accounting
 *
 * The clutch bucket group maintains the number of runnable/running threads in the group.
 * Since the blocked time of the clutch bucket group is based on this count, it is
 * important to make sure the blocking timestamp and the run count are updated atomically.
 *
 * Since the run count increments happen without any pset locks held, the scheduler makes
 * these updates atomic in the following way:
 * - On 64-bit platforms, it uses double wide atomics to update the count & timestamp
 * - On 32-bit platforms, it uses a lock to synchronize the count & timestamp update
 */

#if !__LP64__

static uint32_t
sched_clutch_bucket_group_run_count_inc(
	sched_clutch_bucket_group_t clutch_bucket_group)
{
	uint64_t blocked_time = 0;
	uint64_t updated_run_count = 0;

	lck_spin_lock(&clutch_bucket_group->scbg_stats_lock);
	if ((clutch_bucket_group->scbg_blocked_data.scct_timestamp != SCHED_CLUTCH_BUCKET_GROUP_BLOCKED_TS_INVALID) &&
	    (clutch_bucket_group->scbg_blocked_data.scct_count == 0)) {
		/* Run count is transitioning from 0 to 1; calculate blocked time and add it to CPU data */
		blocked_time = mach_absolute_time() - clutch_bucket_group->scbg_blocked_data.scct_timestamp;
		clutch_bucket_group->scbg_blocked_data.scct_timestamp = SCHED_CLUTCH_BUCKET_GROUP_BLOCKED_TS_INVALID;
	}
	clutch_bucket_group->scbg_blocked_data.scct_count = clutch_bucket_group->scbg_blocked_data.scct_count + 1;
	updated_run_count = clutch_bucket_group->scbg_blocked_data.scct_count;
	lck_spin_unlock(&clutch_bucket_group->scbg_stats_lock);

	blocked_time = MIN(blocked_time, sched_clutch_bucket_group_adjust_threshold);
	os_atomic_add(&(clutch_bucket_group->scbg_cpu_data.cpu_data.scbcd_cpu_blocked), (clutch_cpu_data_t)blocked_time, relaxed);
	return (uint32_t)updated_run_count;
}

static uint32_t
sched_clutch_bucket_group_run_count_dec(
	sched_clutch_bucket_group_t clutch_bucket_group)
{
	uint64_t updated_run_count = 0;

	lck_spin_lock(&clutch_bucket_group->scbg_stats_lock);
	clutch_bucket_group->scbg_blocked_data.scct_count = clutch_bucket_group->scbg_blocked_data.scct_count - 1;
	if (clutch_bucket_group->scbg_blocked_data.scct_count == 0) {
		/* Run count is transitioning from 1 to 0; start the blocked timer */
		clutch_bucket_group->scbg_blocked_data.scct_timestamp = mach_absolute_time();
	}
	updated_run_count = clutch_bucket_group->scbg_blocked_data.scct_count;
	lck_spin_unlock(&clutch_bucket_group->scbg_stats_lock);
	return (uint32_t)updated_run_count;
}

#else /* !__LP64__ */

static uint32_t
sched_clutch_bucket_group_run_count_inc(
	sched_clutch_bucket_group_t clutch_bucket_group)
{
	sched_clutch_counter_time_t old_blocked_data;
	sched_clutch_counter_time_t new_blocked_data;

	bool update_blocked_time = false;
	os_atomic_rmw_loop(&clutch_bucket_group->scbg_blocked_data.scct_packed, old_blocked_data.scct_packed, new_blocked_data.scct_packed, relaxed, {
		new_blocked_data.scct_count = old_blocked_data.scct_count + 1;
		new_blocked_data.scct_timestamp = old_blocked_data.scct_timestamp;
		update_blocked_time = false;
		if (old_blocked_data.scct_count == 0) {
		        new_blocked_data.scct_timestamp = SCHED_CLUTCH_BUCKET_GROUP_BLOCKED_TS_INVALID;
		        update_blocked_time = true;
		}
	});
	if (update_blocked_time && (old_blocked_data.scct_timestamp != SCHED_CLUTCH_BUCKET_GROUP_BLOCKED_TS_INVALID)) {
		uint64_t ctime = mach_absolute_time();
		if (ctime > old_blocked_data.scct_timestamp) {
			uint64_t blocked_time = ctime - old_blocked_data.scct_timestamp;
			blocked_time = MIN(blocked_time, sched_clutch_bucket_group_adjust_threshold);
			os_atomic_add(&(clutch_bucket_group->scbg_cpu_data.cpu_data.scbcd_cpu_blocked), (clutch_cpu_data_t)blocked_time, relaxed);
		}
	}
	return (uint32_t)new_blocked_data.scct_count;
}

static uint32_t
sched_clutch_bucket_group_run_count_dec(
	sched_clutch_bucket_group_t clutch_bucket_group)
{
	sched_clutch_counter_time_t old_blocked_data;
	sched_clutch_counter_time_t new_blocked_data;

	uint64_t ctime = mach_absolute_time();
	os_atomic_rmw_loop(&clutch_bucket_group->scbg_blocked_data.scct_packed, old_blocked_data.scct_packed, new_blocked_data.scct_packed, relaxed, {
		new_blocked_data.scct_count = old_blocked_data.scct_count - 1;
		new_blocked_data.scct_timestamp = old_blocked_data.scct_timestamp;
		if (new_blocked_data.scct_count == 0) {
		        new_blocked_data.scct_timestamp = ctime;
		}
	});
	return (uint32_t)new_blocked_data.scct_count;
}

#endif /* !__LP64__ */

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
#if CONFIG_SCHED_EDGE
	sched_edge_cluster_cumulative_count_incr(root_clutch, thread->th_sched_bucket);
	/*
	 * Check if the thread is bound and is being enqueued in its desired bound cluster.
	 * One scenario where a bound thread might not be getting enqueued in the bound cluster
	 * hierarchy would be if the thread is "soft" bound and the bound cluster is
	 * de-recommended. In that case, the thread should be treated as an unbound
	 * thread.
	 */
	if (SCHED_CLUTCH_THREAD_CLUSTER_BOUND(thread) && (sched_edge_thread_bound_cluster_id(thread) == root_clutch->scr_cluster_id)) {
		return sched_edge_bound_thread_insert(root_clutch, thread, options);
	}
#endif /* CONFIG_SCHED_EDGE */
	sched_clutch_t clutch = sched_clutch_for_thread(thread);
	assert(thread->thread_group == clutch->sc_tg);

	uint64_t current_timestamp = mach_absolute_time();
	sched_clutch_bucket_group_t clutch_bucket_group = &(clutch->sc_clutch_groups[thread->th_sched_bucket]);
	sched_clutch_bucket_t clutch_bucket = &(clutch_bucket_group->scbg_clutch_buckets[root_clutch->scr_cluster_id]);
	assert((clutch_bucket->scb_root == NULL) || (clutch_bucket->scb_root == root_clutch));

	/*
	 * Thread linkage in clutch_bucket
	 *
	 * A thread has a few linkages within the clutch bucket:
	 * - A stable priority queue linkage which is the main runqueue (based on sched_pri) for the clutch bucket
	 * - A regular priority queue linkage which is based on thread's base/promoted pri (used for clutch bucket priority calculation)
	 * - A queue linkage used for timesharing operations of threads at the scheduler tick
	 */

	/* Insert thread into the clutch_bucket stable priority runqueue using sched_pri */
	thread->th_clutch_runq_link.stamp = current_timestamp;
	priority_queue_entry_set_sched_pri(&clutch_bucket->scb_thread_runq, &thread->th_clutch_runq_link, thread->sched_pri,
	    (options & SCHED_TAILQ) ? PRIORITY_QUEUE_ENTRY_NONE : PRIORITY_QUEUE_ENTRY_PREEMPTED);
	priority_queue_insert(&clutch_bucket->scb_thread_runq, &thread->th_clutch_runq_link);

	/* Insert thread into clutch_bucket priority queue based on the promoted or base priority */
	priority_queue_entry_set_sched_pri(&clutch_bucket->scb_clutchpri_prioq, &thread->th_clutch_pri_link,
	    sched_thread_sched_pri_promoted(thread) ? thread->sched_pri : thread->base_pri, false);
	priority_queue_insert(&clutch_bucket->scb_clutchpri_prioq, &thread->th_clutch_pri_link);

	/* Insert thread into timesharing queue of the clutch bucket */
	enqueue_tail(&clutch_bucket->scb_thread_timeshare_queue, &thread->th_clutch_timeshare_link);

	/* Increment the urgency counter for the root if necessary */
	sched_clutch_root_urgency_inc(root_clutch, thread);

	os_atomic_inc(&clutch->sc_thr_count, relaxed);
	sched_clutch_bucket_group_thr_count_inc(clutch_bucket->scb_group, current_timestamp);

	/* Enqueue the clutch into the hierarchy (if needed) and update properties; pick the insertion order based on thread options */
	sched_clutch_bucket_options_t scb_options = (options & SCHED_HEADQ) ? SCHED_CLUTCH_BUCKET_OPTIONS_HEADQ : SCHED_CLUTCH_BUCKET_OPTIONS_TAILQ;
	if (clutch_bucket->scb_thr_count == 0) {
		sched_clutch_thr_count_inc(&clutch_bucket->scb_thr_count);
		sched_clutch_thr_count_inc(&root_clutch->scr_thr_count);
		result = sched_clutch_bucket_runnable(clutch_bucket, root_clutch, current_timestamp, scb_options);
	} else {
		sched_clutch_thr_count_inc(&clutch_bucket->scb_thr_count);
		sched_clutch_thr_count_inc(&root_clutch->scr_thr_count);
		result = sched_clutch_bucket_update(clutch_bucket, root_clutch, current_timestamp, scb_options);
	}

	KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_CLUTCH_THR_COUNT) | DBG_FUNC_NONE,
	    root_clutch->scr_cluster_id, thread_group_get_id(clutch_bucket->scb_group->scbg_clutch->sc_tg), clutch_bucket->scb_bucket,
	    SCHED_CLUTCH_DBG_THR_COUNT_PACK(root_clutch->scr_thr_count, os_atomic_load(&clutch->sc_thr_count, relaxed), clutch_bucket->scb_thr_count));
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
	uint64_t current_timestamp,
	sched_clutch_bucket_options_t options)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
#if CONFIG_SCHED_EDGE
	sched_edge_cluster_cumulative_count_decr(root_clutch, thread->th_sched_bucket);
	if (thread->th_bound_cluster_enqueued) {
		sched_edge_bound_thread_remove(root_clutch, thread);
		return;
	}
#endif /* CONFIG_SCHED_EDGE */
	sched_clutch_t clutch = sched_clutch_for_thread(thread);
	assert(thread->thread_group == clutch->sc_tg);
	assert(thread->runq != PROCESSOR_NULL);

	sched_clutch_bucket_group_t clutch_bucket_group = &(clutch->sc_clutch_groups[thread->th_sched_bucket]);
	sched_clutch_bucket_t clutch_bucket = &(clutch_bucket_group->scbg_clutch_buckets[root_clutch->scr_cluster_id]);
	assert(clutch_bucket->scb_root == root_clutch);

	/* Decrement the urgency counter for the root if necessary */
	sched_clutch_root_urgency_dec(root_clutch, thread);
	/* Remove thread from the clutch_bucket */
	priority_queue_remove(&clutch_bucket->scb_thread_runq, &thread->th_clutch_runq_link);
	remqueue(&thread->th_clutch_timeshare_link);
	thread->runq = PROCESSOR_NULL;

	priority_queue_remove(&clutch_bucket->scb_clutchpri_prioq, &thread->th_clutch_pri_link);

	/* Update counts at various levels of the hierarchy */
	os_atomic_dec(&clutch->sc_thr_count, relaxed);
	sched_clutch_bucket_group_thr_count_dec(clutch_bucket->scb_group, current_timestamp);
	sched_clutch_thr_count_dec(&root_clutch->scr_thr_count);
	sched_clutch_thr_count_dec(&clutch_bucket->scb_thr_count);

	/* Remove the clutch from hierarchy (if needed) and update properties */
	if (clutch_bucket->scb_thr_count == 0) {
		sched_clutch_bucket_empty(clutch_bucket, root_clutch, current_timestamp, options);
	} else {
		sched_clutch_bucket_update(clutch_bucket, root_clutch, current_timestamp, options);
	}
	KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_CLUTCH_THR_COUNT) | DBG_FUNC_NONE,
	    root_clutch->scr_cluster_id, thread_group_get_id(clutch_bucket->scb_group->scbg_clutch->sc_tg), clutch_bucket->scb_bucket,
	    SCHED_CLUTCH_DBG_THR_COUNT_PACK(root_clutch->scr_thr_count, os_atomic_load(&clutch->sc_thr_count, relaxed), clutch_bucket->scb_thr_count));
}

/*
 * sched_clutch_thread_unbound_lookup()
 *
 * Routine to find the highest unbound thread in the root clutch.
 * Helps find threads easily for steal/migrate scenarios in the
 * Edge scheduler.
 */
static thread_t
sched_clutch_thread_unbound_lookup(
	sched_clutch_root_t root_clutch,
	sched_clutch_root_bucket_t root_bucket)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);

	/* Find the highest priority clutch bucket in this root bucket */
	sched_clutch_bucket_t clutch_bucket = sched_clutch_root_bucket_highest_clutch_bucket(root_bucket);
	assert(clutch_bucket != NULL);

	/* Find the highest priority runnable thread in this clutch bucket */
	thread_t thread = priority_queue_max(&clutch_bucket->scb_thread_runq, struct thread, th_clutch_runq_link);
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_CLUTCH_THREAD_SELECT) | DBG_FUNC_NONE,
	    thread_tid(thread), thread_group_get_id(clutch_bucket->scb_group->scbg_clutch->sc_tg), clutch_bucket->scb_bucket, 0, 0);
	return thread;
}

/*
 * sched_clutch_thread_highest_remove()
 *
 * Routine to find and remove the highest priority thread
 * from the sched clutch hierarchy. The algorithm looks at the
 * hierarchy for the most eligible runnable thread and calls
 * sched_clutch_thread_remove(). Always called with the
 * pset lock held.
 */
static thread_t
sched_clutch_thread_highest_remove(
	sched_clutch_root_t root_clutch)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
	uint64_t current_timestamp = mach_absolute_time();

	sched_clutch_root_bucket_t root_bucket = sched_clutch_root_highest_root_bucket(root_clutch, current_timestamp, SCHED_CLUTCH_HIGHEST_ROOT_BUCKET_ALL);
	if (root_bucket == NULL) {
		return THREAD_NULL;
	}

	thread_t highest_thread = THREAD_NULL;
	if (root_bucket->scrb_bound) {
		highest_thread = sched_clutch_thread_bound_lookup(root_clutch, root_bucket);
	} else {
		highest_thread = sched_clutch_thread_unbound_lookup(root_clutch, root_bucket);
	}
	sched_clutch_thread_remove(root_clutch, highest_thread, current_timestamp, SCHED_CLUTCH_BUCKET_OPTIONS_SAMEPRI_RR);
	return highest_thread;
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

#if CONFIG_SCHED_EDGE

/*
 * sched_clutch_root_foreign_empty()
 *
 * Routine to check if the foreign clutch bucket priority list is empty for a cluster.
 */
static boolean_t
sched_clutch_root_foreign_empty(
	sched_clutch_root_t root_clutch)
{
	return priority_queue_empty(&root_clutch->scr_foreign_buckets);
}

/*
 * sched_clutch_root_highest_foreign_thread_remove()
 *
 * Routine to return the thread in the highest priority clutch bucket in a cluster.
 * Must be called with the pset for the cluster locked.
 */
static thread_t
sched_clutch_root_highest_foreign_thread_remove(
	sched_clutch_root_t root_clutch)
{
	thread_t thread = THREAD_NULL;
	if (priority_queue_empty(&root_clutch->scr_foreign_buckets)) {
		return thread;
	}
	sched_clutch_bucket_t clutch_bucket = priority_queue_max(&root_clutch->scr_foreign_buckets, struct sched_clutch_bucket, scb_foreignlink);
	thread = priority_queue_max(&clutch_bucket->scb_thread_runq, struct thread, th_clutch_runq_link);
	sched_clutch_thread_remove(root_clutch, thread, mach_absolute_time(), 0);
	return thread;
}

#endif /* CONFIG_SCHED_EDGE */

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
		return INT8_MAX;
	}
	assert(bucket != TH_BUCKET_RUN);
	sched_clutch_t clutch = sched_clutch_for_thread(thread);
	sched_clutch_bucket_group_t clutch_bucket_group = &(clutch->sc_clutch_groups[bucket]);
	return os_atomic_load(&clutch_bucket_group->scbg_pri_shift, relaxed);
}

#pragma mark -- Clutch Scheduler Algorithm

static void
sched_clutch_init(void);

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
	.timebase_init                                  = sched_timeshare_timebase_init,
	.processor_init                                 = sched_clutch_processor_init,
	.pset_init                                      = sched_clutch_pset_init,
	.maintenance_continuation                       = sched_timeshare_maintenance_continue,
	.choose_thread                                  = sched_clutch_choose_thread,
	.steal_thread_enabled                           = sched_steal_thread_enabled,
	.steal_thread                                   = sched_clutch_steal_thread,
	.compute_timeshare_priority                     = sched_compute_timeshare_priority,
	.choose_node                                    = sched_choose_node,
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

	.rt_runq                                        = sched_rtlocal_runq,
	.rt_init                                        = sched_rtlocal_init,
	.rt_queue_shutdown                              = sched_rtlocal_queue_shutdown,
	.rt_runq_scan                                   = sched_rtlocal_runq_scan,
	.rt_runq_count_sum                              = sched_rtlocal_runq_count_sum,

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
sched_clutch_tunables_init(void)
{
	sched_clutch_us_to_abstime(sched_clutch_root_bucket_wcel_us, sched_clutch_root_bucket_wcel);
	sched_clutch_us_to_abstime(sched_clutch_root_bucket_warp_us, sched_clutch_root_bucket_warp);
	sched_clutch_us_to_abstime(sched_clutch_thread_quantum_us, sched_clutch_thread_quantum);
	clock_interval_to_absolutetime_interval(SCHED_CLUTCH_BUCKET_GROUP_ADJUST_THRESHOLD_USECS,
	    NSEC_PER_USEC, &sched_clutch_bucket_group_adjust_threshold);
	assert(sched_clutch_bucket_group_adjust_threshold <= CLUTCH_CPU_DATA_MAX);
	sched_clutch_us_to_abstime(sched_clutch_bucket_group_pending_delta_us, sched_clutch_bucket_group_pending_delta);
}

static void
sched_clutch_init(void)
{
	if (!PE_parse_boot_argn("sched_clutch_bucket_group_interactive_pri", &sched_clutch_bucket_group_interactive_pri, sizeof(sched_clutch_bucket_group_interactive_pri))) {
		sched_clutch_bucket_group_interactive_pri = SCHED_CLUTCH_BUCKET_GROUP_INTERACTIVE_PRI_DEFAULT;
	}
	sched_timeshare_init();
	sched_clutch_tunables_init();
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
		thread = sched_clutch_thread_highest_remove(pset_clutch_root);
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
		thread = sched_clutch_thread_highest_remove(pset_clutch_root);
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
			sched_clutch_thread_remove(pset_clutch_root, thread, mach_absolute_time(), SCHED_CLUTCH_BUCKET_OPTIONS_NONE);
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
sched_clutch_steal_thread(__unused processor_set_t pset)
{
	/* Thread stealing is not enabled for single cluster clutch scheduler platforms */
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

	pset_node_t node = &pset_node0;
	pset = node->psets;

	do {
		do {
			restart_needed = FALSE;
			while (pset != NULL) {
				s = splsched();
				pset_lock(pset);

				if (sched_clutch_root_count(&pset->pset_clutch_root) > 0) {
					for (sched_bucket_t bucket = TH_BUCKET_SHARE_FG; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
						restart_needed = runq_scan(&pset->pset_clutch_root.scr_bound_buckets[bucket].scrb_bound_thread_runq, scan_context);
						if (restart_needed) {
							break;
						}
					}
					queue_t clutch_bucket_list = &pset->pset_clutch_root.scr_clutch_buckets;
					sched_clutch_bucket_t clutch_bucket;
					qe_foreach_element(clutch_bucket, clutch_bucket_list, scb_listlink) {
						sched_clutch_bucket_group_timeshare_update(clutch_bucket->scb_group, clutch_bucket, scan_context->sched_tick_last_abstime);
						restart_needed = sched_clutch_timeshare_scan(&clutch_bucket->scb_thread_timeshare_queue, clutch_bucket->scb_thr_count, scan_context);
					}
				}

				pset_unlock(pset);
				splx(s);

				if (restart_needed) {
					break;
				}
				pset = pset->pset_list;
			}

			if (restart_needed) {
				break;
			}
		} while (((node = node->node_list) != NULL) && ((pset = node->psets) != NULL));

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

#if CONFIG_SCHED_EDGE

/* Implementation of the AMP version of the clutch scheduler */

static void
sched_edge_init(void);

static thread_t
sched_edge_processor_idle(processor_set_t pset);

static ast_t
sched_edge_processor_csw_check(processor_t processor);

static boolean_t
sched_edge_processor_queue_has_priority(processor_t processor, int priority, boolean_t gte);

static boolean_t
sched_edge_processor_queue_empty(processor_t processor);

static thread_t
sched_edge_choose_thread(processor_t processor, int priority, ast_t reason);

static void
sched_edge_processor_queue_shutdown(processor_t processor);

static processor_t
sched_edge_choose_processor(processor_set_t pset, processor_t processor, thread_t thread);

static bool
sched_edge_thread_avoid_processor(processor_t processor, thread_t thread);

static void
sched_edge_balance(processor_t cprocessor, processor_set_t cpset);

static void
sched_edge_check_spill(processor_set_t pset, thread_t thread);

static bool
sched_edge_thread_should_yield(processor_t processor, thread_t thread);

static void
sched_edge_pset_made_schedulable(processor_t processor, processor_set_t dst_pset, boolean_t drop_lock);

static bool
sched_edge_steal_thread_enabled(processor_set_t pset);

static sched_ipi_type_t
sched_edge_ipi_policy(processor_t dst, thread_t thread, boolean_t dst_idle, sched_ipi_event_t event);

static uint32_t
sched_edge_qos_max_parallelism(int qos, uint64_t options);

const struct sched_dispatch_table sched_edge_dispatch = {
	.sched_name                                     = "edge",
	.init                                           = sched_edge_init,
	.timebase_init                                  = sched_timeshare_timebase_init,
	.processor_init                                 = sched_clutch_processor_init,
	.pset_init                                      = sched_clutch_pset_init,
	.maintenance_continuation                       = sched_timeshare_maintenance_continue,
	.choose_thread                                  = sched_edge_choose_thread,
	.steal_thread_enabled                           = sched_edge_steal_thread_enabled,
	.steal_thread                                   = sched_edge_processor_idle,
	.compute_timeshare_priority                     = sched_compute_timeshare_priority,
	.choose_node                                    = sched_choose_node,
	.choose_processor                               = sched_edge_choose_processor,
	.processor_enqueue                              = sched_clutch_processor_enqueue,
	.processor_queue_shutdown                       = sched_edge_processor_queue_shutdown,
	.processor_queue_remove                         = sched_clutch_processor_queue_remove,
	.processor_queue_empty                          = sched_edge_processor_queue_empty,
	.priority_is_urgent                             = priority_is_urgent,
	.processor_csw_check                            = sched_edge_processor_csw_check,
	.processor_queue_has_priority                   = sched_edge_processor_queue_has_priority,
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
	.thread_avoid_processor                         = sched_edge_thread_avoid_processor,
	.processor_balance                              = sched_edge_balance,

	.rt_runq                                        = sched_amp_rt_runq,
	.rt_init                                        = sched_amp_rt_init,
	.rt_queue_shutdown                              = sched_amp_rt_queue_shutdown,
	.rt_runq_scan                                   = sched_amp_rt_runq_scan,
	.rt_runq_count_sum                              = sched_amp_rt_runq_count_sum,

	.qos_max_parallelism                            = sched_edge_qos_max_parallelism,
	.check_spill                                    = sched_edge_check_spill,
	.ipi_policy                                     = sched_edge_ipi_policy,
	.thread_should_yield                            = sched_edge_thread_should_yield,
	.run_count_incr                                 = sched_clutch_run_incr,
	.run_count_decr                                 = sched_clutch_run_decr,
	.update_thread_bucket                           = sched_clutch_update_thread_bucket,
	.pset_made_schedulable                          = sched_edge_pset_made_schedulable,
	.thread_group_recommendation_change             = NULL,
};

static struct processor_set pset1;
static struct pset_node pset_node1;
static bitmap_t sched_edge_available_pset_bitmask[BITMAP_LEN(MAX_PSETS)];

/*
 * sched_edge_pset_available()
 *
 * Routine to determine if a pset is available for scheduling.
 */
static bool
sched_edge_pset_available(processor_set_t pset)
{
	return bitmap_test(sched_edge_available_pset_bitmask, pset->pset_cluster_id);
}

/*
 * sched_edge_thread_bound_cluster_id()
 *
 * Routine to determine which cluster a particular thread is bound to. Uses
 * the sched_flags on the thread to map back to a specific cluster id.
 *
 * <Edge Multi-cluster Support Needed>
 */
static uint32_t
sched_edge_thread_bound_cluster_id(thread_t thread)
{
	assert(SCHED_CLUTCH_THREAD_CLUSTER_BOUND(thread));
	if (thread->sched_flags & TH_SFLAG_ECORE_ONLY) {
		return (pset_array[0]->pset_type == CLUSTER_TYPE_E) ? 0 : 1;
	} else {
		return (pset_array[0]->pset_type == CLUSTER_TYPE_P) ? 0 : 1;
	}
}

/* Forward declaration for some thread migration routines */
static boolean_t sched_edge_foreign_runnable_thread_available(processor_set_t pset);
static boolean_t sched_edge_foreign_running_thread_available(processor_set_t pset);
static processor_set_t sched_edge_steal_candidate(processor_set_t pset);
static processor_set_t sched_edge_migrate_candidate(processor_set_t preferred_pset, thread_t thread, processor_set_t locked_pset, bool switch_pset_locks);

/*
 * sched_edge_config_set()
 *
 * Support to update an edge configuration. Typically used by CLPC to affect thread migration
 * policies in the scheduler.
 */
static void
sched_edge_config_set(uint32_t src_cluster, uint32_t dst_cluster, sched_clutch_edge edge_config)
{
	sched_clutch_edge *edge = &pset_array[src_cluster]->sched_edges[dst_cluster];
	edge->sce_edge_packed = edge_config.sce_edge_packed;
}

/*
 * sched_edge_config_get()
 *
 * Support to get an edge configuration. Typically used by CLPC to query edge configs to decide
 * if it needs to update edges.
 */
static sched_clutch_edge
sched_edge_config_get(uint32_t src_cluster, uint32_t dst_cluster)
{
	return pset_array[src_cluster]->sched_edges[dst_cluster];
}

#if DEVELOPMENT || DEBUG

/*
 * Helper Routines for edge scheduler sysctl configuration
 *
 * The current support is limited to dual cluster AMP platforms.
 * <Edge Multi-cluster Support Needed>
 */

kern_return_t
sched_edge_sysctl_configure_e_to_p(uint64_t edge_config)
{
	pset_array[ecore_cluster_id]->sched_edges[pcore_cluster_id].sce_edge_packed = edge_config;
	return KERN_SUCCESS;
}

kern_return_t
sched_edge_sysctl_configure_p_to_e(uint64_t edge_config)
{
	pset_array[pcore_cluster_id]->sched_edges[ecore_cluster_id].sce_edge_packed = edge_config;
	return KERN_SUCCESS;
}

sched_clutch_edge
sched_edge_e_to_p(void)
{
	return sched_edge_config_get(ecore_cluster_id, pcore_cluster_id);
}

sched_clutch_edge
sched_edge_p_to_e(void)
{
	return sched_edge_config_get(pcore_cluster_id, ecore_cluster_id);
}

#endif /* DEVELOPMENT || DEBUG */

/*
 * sched_edge_matrix_set()
 *
 * Routine to update various edges in the cluster edge matrix. The edge_changes_bitmap
 * indicates which edges need to be updated. Both the edge_matrix & edge_changes_bitmap
 * are MAX_PSETS * MAX_PSETS matrices flattened into a single dimensional array.
 */
void
sched_edge_matrix_set(sched_clutch_edge *edge_matrix, bool *edge_changes_bitmap, __unused uint64_t flags, uint64_t matrix_order)
{
	uint32_t edge_index = 0;
	for (uint32_t src_cluster = 0; src_cluster < matrix_order; src_cluster++) {
		for (uint32_t dst_cluster = 0; dst_cluster < matrix_order; dst_cluster++) {
			if (edge_changes_bitmap[edge_index]) {
				sched_edge_config_set(src_cluster, dst_cluster, edge_matrix[edge_index]);
			}
			edge_index++;
		}
	}
}

/*
 * sched_edge_matrix_get()
 *
 * Routine to retrieve various edges in the cluster edge matrix. The edge_request_bitmap
 * indicates which edges need to be retrieved. Both the edge_matrix & edge_request_bitmap
 * are MAX_PSETS * MAX_PSETS matrices flattened into a single dimensional array.
 */
void
sched_edge_matrix_get(sched_clutch_edge *edge_matrix, bool *edge_request_bitmap, __unused uint64_t flags, uint64_t matrix_order)
{
	uint32_t edge_index = 0;
	for (uint32_t src_cluster = 0; src_cluster < matrix_order; src_cluster++) {
		for (uint32_t dst_cluster = 0; dst_cluster < matrix_order; dst_cluster++) {
			if (edge_request_bitmap[edge_index]) {
				edge_matrix[edge_index] = sched_edge_config_get(src_cluster, dst_cluster);
			}
			edge_index++;
		}
	}
}

/*
 * sched_edge_init()
 *
 * Routine to initialize the data structures for the Edge scheduler. The current implementation
 * relies on this being enabled for a dual cluster AMP system. Once a better design for MAX_PSETS,
 * edge config etc. is defined, it should be made more generic to handle the multi-cluster
 * platorms.
 * <Edge Multi-cluster Support Needed>
 */
static void
sched_edge_init(void)
{
	processor_set_t ecore_set = &pset0;
	processor_set_t pcore_set = &pset1;

	if (ml_get_boot_cluster() == CLUSTER_TYPE_P) {
		/* If the device boots on a P-cluster, fixup the IDs etc. */
		pcore_set = &pset0;
		ecore_set = &pset1;
		bitmap_set(sched_edge_available_pset_bitmask, pcore_cluster_id);
	} else {
		bitmap_set(sched_edge_available_pset_bitmask, ecore_cluster_id);
	}

	ecore_set->pset_cluster_type = PSET_AMP_E;
	ecore_set->pset_cluster_id = ecore_cluster_id;

	pcore_set->pset_cluster_type = PSET_AMP_P;
	pcore_set->pset_cluster_id = pcore_cluster_id;

	pset_init(&pset1, &pset_node1);
	pset_node1.psets = &pset1;
	pset_node0.node_list = &pset_node1;

	pset_array[ecore_cluster_id] = ecore_set;
	pset_array[ecore_cluster_id]->pset_type = CLUSTER_TYPE_E;
	bitmap_set(pset_array[ecore_cluster_id]->foreign_psets, pcore_cluster_id);

	sched_edge_config_set(ecore_cluster_id, ecore_cluster_id, (sched_clutch_edge){.sce_migration_weight = 0, .sce_migration_allowed = 0, .sce_steal_allowed = 0});
	sched_edge_config_set(ecore_cluster_id, pcore_cluster_id, (sched_clutch_edge){.sce_migration_weight = 0, .sce_migration_allowed = 0, .sce_steal_allowed = 0});

	pset_array[pcore_cluster_id] = pcore_set;
	pset_array[pcore_cluster_id]->pset_type = CLUSTER_TYPE_P;
	bitmap_set(pset_array[pcore_cluster_id]->foreign_psets, ecore_cluster_id);

	sched_edge_config_set(pcore_cluster_id, pcore_cluster_id, (sched_clutch_edge){.sce_migration_weight = 0, .sce_migration_allowed = 0, .sce_steal_allowed = 0});
	sched_edge_config_set(pcore_cluster_id, ecore_cluster_id, (sched_clutch_edge){.sce_migration_weight = 64, .sce_migration_allowed = 1, .sce_steal_allowed = 1});

	sched_timeshare_init();
	sched_clutch_tunables_init();
}

static thread_t
sched_edge_choose_thread(
	processor_t      processor,
	int              priority,
	__unused ast_t            reason)
{
	int clutch_pri = sched_clutch_root_priority(sched_clutch_processor_root_clutch(processor));
	run_queue_t bound_runq = sched_clutch_bound_runq(processor);
	boolean_t choose_from_boundq = false;

	if ((bound_runq->highq < priority) &&
	    (clutch_pri < priority)) {
		return THREAD_NULL;
	}

	if (bound_runq->highq >= clutch_pri) {
		choose_from_boundq = true;
	}

	thread_t thread = THREAD_NULL;
	if (choose_from_boundq == false) {
		sched_clutch_root_t pset_clutch_root = sched_clutch_processor_root_clutch(processor);
		thread = sched_clutch_thread_highest_remove(pset_clutch_root);
	} else {
		thread = run_queue_dequeue(bound_runq, SCHED_HEADQ);
	}
	return thread;
}

static boolean_t
sched_edge_processor_queue_empty(processor_t processor)
{
	return (sched_clutch_root_count(sched_clutch_processor_root_clutch(processor)) == 0) &&
	       (sched_clutch_bound_runq(processor)->count == 0);
}

static void
sched_edge_check_spill(__unused processor_set_t pset, __unused thread_t thread)
{
	assert(thread->bound_processor == PROCESSOR_NULL);
}

__options_decl(sched_edge_thread_yield_reason_t, uint32_t, {
	SCHED_EDGE_YIELD_RUNQ_NONEMPTY       = 0x0,
	SCHED_EDGE_YIELD_FOREIGN_RUNNABLE    = 0x1,
	SCHED_EDGE_YIELD_FOREIGN_RUNNING     = 0x2,
	SCHED_EDGE_YIELD_STEAL_POSSIBLE      = 0x3,
	SCHED_EDGE_YIELD_DISALLOW            = 0x4,
});

static bool
sched_edge_thread_should_yield(processor_t processor, __unused thread_t thread)
{
	if (!sched_edge_processor_queue_empty(processor) || (rt_runq_count(processor->processor_set) > 0)) {
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_SHOULD_YIELD) | DBG_FUNC_NONE,
		    thread_tid(thread), processor->processor_set->pset_cluster_id, 0, SCHED_EDGE_YIELD_RUNQ_NONEMPTY);
		return true;
	}

	/*
	 * The yield logic should follow the same logic that steal_thread () does. The
	 * thread_should_yield() is effectively trying to quickly check that if the
	 * current thread gave up CPU, is there any other thread that would execute
	 * on this CPU. So it needs to provide the same answer as the steal_thread()/
	 * processor Idle logic.
	 */
	if (sched_edge_foreign_runnable_thread_available(processor->processor_set)) {
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_SHOULD_YIELD) | DBG_FUNC_NONE,
		    thread_tid(thread), processor->processor_set->pset_cluster_id, 0, SCHED_EDGE_YIELD_FOREIGN_RUNNABLE);
		return true;
	}
	if (sched_edge_foreign_running_thread_available(processor->processor_set)) {
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_SHOULD_YIELD) | DBG_FUNC_NONE,
		    thread_tid(thread), processor->processor_set->pset_cluster_id, 0, SCHED_EDGE_YIELD_FOREIGN_RUNNING);
		return true;
	}

	processor_set_t steal_candidate = sched_edge_steal_candidate(processor->processor_set);
	if (steal_candidate != NULL) {
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_SHOULD_YIELD) | DBG_FUNC_NONE,
		    thread_tid(thread), processor->processor_set->pset_cluster_id, 0, SCHED_EDGE_YIELD_STEAL_POSSIBLE);
		return true;
	}

	KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_SHOULD_YIELD) | DBG_FUNC_NONE, thread_tid(thread), processor->processor_set->pset_cluster_id,
	    0, SCHED_EDGE_YIELD_DISALLOW);
	return false;
}

static ast_t
sched_edge_processor_csw_check(processor_t processor)
{
	boolean_t       has_higher;
	int             pri;

	int clutch_pri = sched_clutch_root_priority(sched_clutch_processor_root_clutch(processor));
	run_queue_t bound_runq = sched_clutch_bound_runq(processor);

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
sched_edge_processor_queue_has_priority(processor_t    processor,
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

static void
sched_edge_processor_queue_shutdown(processor_t processor)
{
	processor_set_t pset = processor->processor_set;
	sched_clutch_root_t pset_clutch_root = sched_clutch_processor_root_clutch(processor);
	thread_t        thread;
	queue_head_t    tqueue;

	/* We only need to migrate threads if this is the last active or last recommended processor in the pset */
	if ((pset->online_processor_count > 0) && pset_is_recommended(pset)) {
		pset_unlock(pset);
		return;
	}

	bitmap_clear(sched_edge_available_pset_bitmask, pset->pset_cluster_id);

	queue_init(&tqueue);
	while (sched_clutch_root_count(pset_clutch_root) > 0) {
		thread = sched_clutch_thread_highest_remove(pset_clutch_root);
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

/*
 * sched_edge_cluster_load_metric()
 *
 * The load metric for a cluster is a measure of the average scheduling latency
 * experienced by threads on that cluster. It is a product of the average number
 * of threads in the runqueue and the average execution time for threads. The metric
 * has special values in the following cases:
 * - UINT32_MAX: If the cluster is not available for scheduling, its load is set to
 *   the maximum value to disallow any threads to migrate to this cluster.
 * - 0: If there are idle CPUs in the cluster or an empty runqueue; this allows threads
 *   to be spread across the platform quickly for ncpu wide workloads.
 */
static uint32_t
sched_edge_cluster_load_metric(processor_set_t pset, sched_bucket_t sched_bucket)
{
	if (sched_edge_pset_available(pset) == false) {
		return UINT32_MAX;
	}
	return (uint32_t)sched_get_pset_load_average(pset, sched_bucket);
}

/*
 *
 * Edge Scheduler Steal/Rebalance logic
 *
 * = Generic scheduler logic =
 *
 * The SCHED(steal_thread) scheduler callout is invoked when the processor does not
 * find any thread for execution in its runqueue. The aim of the steal operation
 * is to find other threads running/runnable in other clusters which should be
 * executed here.
 *
 * If the steal callout does not return a thread, the thread_select() logic calls
 * SCHED(processor_balance) callout which is supposed to IPI other CPUs to rebalance
 * threads and idle out the current CPU.
 *
 * = SCHED(steal_thread) for Edge Scheduler =
 *
 * The edge scheduler hooks into sched_edge_processor_idle() for steal_thread. This
 * routine tries to do the following operations in order:
 * (1) Find foreign runnnable threads in non-native cluster
 *     runqueues (sched_edge_foreign_runnable_thread_remove())
 * (2) Check if foreign threads are running on the non-native
 *     clusters (sched_edge_foreign_running_thread_available())
 *         - If yes, return THREAD_NULL for the steal callout and
 *         perform rebalancing as part of SCHED(processor_balance) i.e. sched_edge_balance()
 * (3) Steal a thread from another cluster based on edge
 *     weights (sched_edge_steal_thread())
 *
 * = SCHED(processor_balance) for Edge Scheduler =
 *
 * If steal_thread did not return a thread for the processor, use
 * sched_edge_balance() to rebalance foreign running threads and idle out this CPU.
 *
 * = Clutch Bucket Preferred Cluster Overrides =
 *
 * Since these operations (just like thread migrations on enqueue)
 * move threads across clusters, they need support for handling clutch
 * bucket group level preferred cluster recommendations.
 * For (1), a clutch bucket will be in the foreign runnable queue based
 * on the clutch bucket group preferred cluster.
 * For (2), the running thread will set the bit on the processor based
 * on its preferred cluster type.
 * For (3), the edge configuration would prevent threads from being stolen
 * in the wrong direction.
 *
 * = SCHED(thread_should_yield) =
 * The thread_should_yield() logic needs to have the same logic as sched_edge_processor_idle()
 * since that is expecting the same answer as if thread_select() was called on a core
 * with an empty runqueue.
 */

static bool
sched_edge_steal_thread_enabled(__unused processor_set_t pset)
{
	/*
	 * For edge scheduler, the gating for steal is being done by sched_edge_steal_candidate()
	 */
	return true;
}

static processor_set_t
sched_edge_steal_candidate(processor_set_t pset)
{
	/*
	 * Edge Scheduler Optimization
	 *
	 * Investigate a better policy for stealing. The current implementation looks
	 * at all the incoming weights for the pset that just became idle and sees which
	 * clusters have loads > edge weights. It is effectively trying to simulate a
	 * overload migration as if a thread had become runnable on the candidate cluster.
	 *
	 * The logic today bails as soon as it finds a cluster where the cluster load is
	 * greater than the edge weight. This helps the check to be quick which is useful
	 * for sched_edge_thread_should_yield() which uses this. Maybe it should have a
	 * more advanced version for the actual steal operation which looks for the
	 * maximum delta etc.
	 */
	processor_set_t target_pset = NULL;
	uint32_t dst_cluster_id = pset->pset_cluster_id;

	for (int cluster_id = 0; cluster_id < MAX_PSETS; cluster_id++) {
		processor_set_t candidate_pset = pset_array[cluster_id];

		if (candidate_pset == pset) {
			continue;
		}

		sched_clutch_edge *incoming_edge = &pset_array[cluster_id]->sched_edges[dst_cluster_id];
		if (incoming_edge->sce_steal_allowed == false) {
			continue;
		}

		uint32_t incoming_weight = incoming_edge->sce_migration_weight;
		int highest_runnable_bucket = bitmap_lsb_first(candidate_pset->pset_clutch_root.scr_unbound_runnable_bitmap, TH_BUCKET_SCHED_MAX);
		if (highest_runnable_bucket == -1) {
			/* Candidate cluster runq is empty */
			continue;
		}
		/* Use the load metrics for highest runnable bucket since that would be stolen next */
		uint32_t candidate_load = sched_edge_cluster_load_metric(candidate_pset, (sched_bucket_t)highest_runnable_bucket);
		if (candidate_load > incoming_weight) {
			/* Only steal from the candidate if its load is higher than the incoming edge and it has runnable threads */
			target_pset = candidate_pset;
			break;
		}
	}

	return target_pset;
}

static boolean_t
sched_edge_foreign_runnable_thread_available(processor_set_t pset)
{
	/* Find all the clusters that are foreign for this cluster */
	bitmap_t *foreign_pset_bitmap = pset->foreign_psets;
	for (int cluster = bitmap_first(foreign_pset_bitmap, MAX_PSETS); cluster >= 0; cluster = bitmap_next(foreign_pset_bitmap, cluster)) {
		/*
		 * For each cluster, see if there are any runnable foreign threads.
		 * This check is currently being done without the pset lock to make it cheap for
		 * the common case.
		 */
		processor_set_t target_pset = pset_array[cluster];
		if (sched_edge_pset_available(target_pset) == false) {
			continue;
		}

		if (!sched_clutch_root_foreign_empty(&target_pset->pset_clutch_root)) {
			return true;
		}
	}
	return false;
}

static thread_t
sched_edge_foreign_runnable_thread_remove(processor_set_t pset, uint64_t ctime)
{
	thread_t thread = THREAD_NULL;

	/* Find all the clusters that are foreign for this cluster */
	bitmap_t *foreign_pset_bitmap = pset->foreign_psets;
	for (int cluster = bitmap_first(foreign_pset_bitmap, MAX_PSETS); cluster >= 0; cluster = bitmap_next(foreign_pset_bitmap, cluster)) {
		/*
		 * For each cluster, see if there are any runnable foreign threads.
		 * This check is currently being done without the pset lock to make it cheap for
		 * the common case.
		 */
		processor_set_t target_pset = pset_array[cluster];
		if (sched_edge_pset_available(target_pset) == false) {
			continue;
		}

		if (sched_clutch_root_foreign_empty(&target_pset->pset_clutch_root)) {
			continue;
		}
		/*
		 * Looks like there are runnable foreign threads in the hierarchy; lock the pset
		 * and get the highest priority thread.
		 */
		pset_lock(target_pset);
		if (sched_edge_pset_available(target_pset)) {
			thread = sched_clutch_root_highest_foreign_thread_remove(&target_pset->pset_clutch_root);
			sched_update_pset_load_average(target_pset, ctime);
		}
		pset_unlock(target_pset);

		/*
		 * Edge Scheduler Optimization
		 *
		 * The current implementation immediately returns as soon as it finds a foreign
		 * runnable thread. This could be enhanced to look at highest priority threads
		 * from all foreign clusters and pick the highest amongst them. That would need
		 * some form of global state across psets to make that kind of a check cheap.
		 */
		if (thread != THREAD_NULL) {
			KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_REBAL_RUNNABLE) | DBG_FUNC_NONE, thread_tid(thread), pset->pset_cluster_id, target_pset->pset_cluster_id, 0);
			break;
		}
		/* Looks like the thread escaped after the check but before the pset lock was taken; continue the search */
	}

	return thread;
}

static boolean_t
sched_edge_foreign_running_thread_available(processor_set_t pset)
{
	bitmap_t *foreign_pset_bitmap = pset->foreign_psets;
	for (int cluster = bitmap_first(foreign_pset_bitmap, MAX_PSETS); cluster >= 0; cluster = bitmap_next(foreign_pset_bitmap, cluster)) {
		/* Skip the pset if its not schedulable */
		processor_set_t target_pset = pset_array[cluster];
		if (sched_edge_pset_available(target_pset) == false) {
			continue;
		}

		uint64_t running_foreign_bitmap = target_pset->cpu_state_map[PROCESSOR_RUNNING] & target_pset->cpu_running_foreign;
		if (lsb_first(running_foreign_bitmap) != -1) {
			/* Found a non-native CPU running a foreign thread; rebalance is needed */
			return true;
		}
	}
	return false;
}

static thread_t
sched_edge_steal_thread(processor_set_t pset)
{
	thread_t thread = THREAD_NULL;
	processor_set_t steal_from_pset = sched_edge_steal_candidate(pset);
	if (steal_from_pset) {
		/*
		 * sched_edge_steal_candidate() has found a pset which is ideal to steal from.
		 * Lock the pset and select the highest thread in that runqueue.
		 */
		pset_lock(steal_from_pset);
		if (bitmap_first(steal_from_pset->pset_clutch_root.scr_unbound_runnable_bitmap, TH_BUCKET_SCHED_MAX) != -1) {
			uint64_t current_timestamp = mach_absolute_time();
			sched_clutch_root_bucket_t root_bucket = sched_clutch_root_highest_root_bucket(&steal_from_pset->pset_clutch_root, current_timestamp, SCHED_CLUTCH_HIGHEST_ROOT_BUCKET_UNBOUND_ONLY);
			thread = sched_clutch_thread_unbound_lookup(&steal_from_pset->pset_clutch_root, root_bucket);
			sched_clutch_thread_remove(&steal_from_pset->pset_clutch_root, thread, current_timestamp, SCHED_CLUTCH_BUCKET_OPTIONS_SAMEPRI_RR);
			KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_STEAL) | DBG_FUNC_NONE, thread_tid(thread), pset->pset_cluster_id, steal_from_pset->pset_cluster_id, 0);
			sched_update_pset_load_average(steal_from_pset, current_timestamp);
		}
		/*
		 * Edge Scheduler Optimization
		 * Maybe this needs to circle around if the steal candidate did not have any threads by
		 * by the time the pset lock was taken.
		 */
		pset_unlock(steal_from_pset);
	}
	return thread;
}

/*
 * sched_edge_processor_idle()
 *
 * The routine is the implementation for steal_thread() for the Edge scheduler.
 */
static thread_t
sched_edge_processor_idle(processor_set_t pset)
{
	thread_t thread = THREAD_NULL;

	uint64_t ctime = mach_absolute_time();

	/* Each of the operations acquire the lock for the pset they target */
	pset_unlock(pset);

	/* Find highest priority runnable thread on all non-native clusters */
	thread = sched_edge_foreign_runnable_thread_remove(pset, ctime);
	if (thread != THREAD_NULL) {
		return thread;
	}

	/* Find foreign running threads to rebalance; the actual rebalance is done in sched_edge_balance() */
	boolean_t rebalance_needed = sched_edge_foreign_running_thread_available(pset);
	if (rebalance_needed) {
		return THREAD_NULL;
	}

	/* No foreign threads found; find a thread to steal from a pset based on weights/loads etc. */
	thread = sched_edge_steal_thread(pset);
	return thread;
}

/* Return true if this thread should not continue running on this processor */
static bool
sched_edge_thread_avoid_processor(processor_t processor, thread_t thread)
{
	processor_set_t preferred_pset = pset_array[sched_edge_thread_preferred_cluster(thread)];
	/*
	 * For long running parallel workloads, it is important to rebalance threads across
	 * E/P clusters so that they make equal forward progress. This is achieved through
	 * threads expiring their quantum on the non-preferred cluster type and explicitly
	 * rebalancing to the preferred cluster runqueue.
	 *
	 * <Edge Multi-Cluster Support Needed>
	 * For multi-cluster platforms, it mignt be useful to move the thread incase its
	 * preferred pset is idle now.
	 */
	if (processor->processor_set->pset_type != preferred_pset->pset_type) {
		return true;
	}
	/* If thread already running on preferred cluster, do not avoid */
	if (processor->processor_set == preferred_pset) {
		return false;
	}
	/*
	 * The thread is running on a processor that is of the same type as the
	 * preferred pset, but is not the actual preferred pset. In that case
	 * look at edge weights to see if this thread should continue execution
	 * here or go back to its preferred cluster.
	 *
	 * <Edge Multi-Cluster Support Needed>
	 * This logic needs to ensure that the current thread is not counted against
	 * the load average for the current pset otherwise it would always end up avoiding
	 * the current cluster.
	 */
	processor_set_t chosen_pset = sched_edge_migrate_candidate(preferred_pset, thread, processor->processor_set, false);
	return chosen_pset != processor->processor_set;
}

static void
sched_edge_balance(__unused processor_t cprocessor, processor_set_t cpset)
{
	assert(cprocessor == current_processor());
	pset_unlock(cpset);

	uint64_t ast_processor_map = 0;
	sched_ipi_type_t ipi_type[MAX_CPUS] = {SCHED_IPI_NONE};

	bitmap_t *foreign_pset_bitmap = cpset->foreign_psets;
	for (int cluster = bitmap_first(foreign_pset_bitmap, MAX_PSETS); cluster >= 0; cluster = bitmap_next(foreign_pset_bitmap, cluster)) {
		/* Skip the pset if its not schedulable */
		processor_set_t target_pset = pset_array[cluster];
		if (sched_edge_pset_available(target_pset) == false) {
			continue;
		}

		pset_lock(target_pset);
		uint64_t cpu_running_foreign_map = (target_pset->cpu_running_foreign & target_pset->cpu_state_map[PROCESSOR_RUNNING]);
		for (int cpuid = lsb_first(cpu_running_foreign_map); cpuid >= 0; cpuid = lsb_next(cpu_running_foreign_map, cpuid)) {
			processor_t target_cpu = processor_array[cpuid];
			ipi_type[target_cpu->cpu_id] = sched_ipi_action(target_cpu, NULL, false, SCHED_IPI_EVENT_REBALANCE);
			if (ipi_type[cpuid] != SCHED_IPI_NONE) {
				bit_set(ast_processor_map, cpuid);
			}
		}
		pset_unlock(target_pset);
	}

	for (int cpuid = lsb_first(ast_processor_map); cpuid >= 0; cpuid = lsb_next(ast_processor_map, cpuid)) {
		processor_t ast_processor = processor_array[cpuid];
		sched_ipi_perform(ast_processor, ipi_type[cpuid]);
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_REBAL_RUNNING) | DBG_FUNC_NONE, 0, cprocessor->cpu_id, cpuid, 0);
	}
}

/*
 * sched_edge_migrate_edges_evaluate()
 *
 * Routine to find the candidate for thread migration based on edge weights.
 *
 * Returns the most ideal cluster for execution of this thread based on outgoing edges of the preferred pset. Can
 * return preferred_pset if its the most ideal destination for this thread.
 */
static processor_set_t
sched_edge_migrate_edges_evaluate(processor_set_t preferred_pset, uint32_t preferred_cluster_load, thread_t thread)
{
	processor_set_t selected_pset = preferred_pset;
	uint32_t preferred_cluster_id = preferred_pset->pset_cluster_id;
	cluster_type_t preferred_cluster_type = pset_type_for_id(preferred_cluster_id);

	/* Look at edge deltas with other clusters to find the ideal migration candidate */
	sched_clutch_edge *edge = preferred_pset->sched_edges;
	uint32_t max_edge_delta = 0;

	/*
	 * Edge Scheduler Optimization
	 *
	 * For really large cluster count systems, it might make sense to optimize the
	 * clusters iterated by using bitmaps and skipping over clusters that are not
	 * available for scheduling or have migration disabled from this cluster.
	 */
	for (uint32_t cluster_id = 0; cluster_id < MAX_PSETS; cluster_id++) {
		processor_set_t dst_pset = pset_array[cluster_id];
		if (cluster_id == preferred_cluster_id) {
			continue;
		}

		if (edge[cluster_id].sce_migration_allowed == false) {
			continue;
		}

		uint32_t dst_load = sched_edge_cluster_load_metric(dst_pset, thread->th_sched_bucket);
		if (dst_load > preferred_cluster_load) {
			continue;
		}

		/*
		 * Fast path for idle dst cluster
		 *
		 * For extremely parallel workloads, it is important to load up
		 * all clusters as quickly as possible. This short-circuit allows
		 * that.
		 * <Edge Multi-cluster Support Needed>
		 *
		 * For multi-cluster platforms, the loop should start with the homogeneous
		 * clusters first.
		 */
		if (dst_load == 0) {
			selected_pset = dst_pset;
			break;
		}

		uint32_t edge_delta = preferred_cluster_load - dst_load;
		if (edge_delta < edge[cluster_id].sce_migration_weight) {
			continue;
		}

		if (edge_delta < max_edge_delta) {
			continue;
		}

		if (edge_delta == max_edge_delta) {
			/* If the edge delta is the same as the max delta, make sure a homogeneous cluster is picked */
			boolean_t selected_homogeneous = (pset_type_for_id(selected_pset->pset_cluster_id) == preferred_cluster_type);
			boolean_t candidate_homogeneous = (pset_type_for_id(dst_pset->pset_cluster_id) == preferred_cluster_type);
			if (selected_homogeneous || !candidate_homogeneous) {
				continue;
			}
		}
		/* dst_pset seems to be the best candidate for migration */
		max_edge_delta = edge_delta;
		selected_pset = dst_pset;
	}
	return selected_pset;
}

/*
 * sched_edge_candidate_alternative()
 *
 * Routine to find an alternative cluster from candidate_cluster_bitmap since the
 * selected_pset is not available for execution. The logic tries to prefer homogeneous
 * clusters over heterogeneous clusters since this is typically used in thread
 * placement decisions.
 */
_Static_assert(MAX_PSETS <= 64, "Unable to fit maximum number of psets in uint64_t bitmask");
static processor_set_t
sched_edge_candidate_alternative(processor_set_t selected_pset, uint64_t candidate_cluster_bitmap)
{
	/*
	 * It looks like the most ideal pset is not available for scheduling currently.
	 * Try to find a homogeneous cluster that is still available.
	 */
	bitmap_t *foreign_clusters = selected_pset->foreign_psets;
	uint64_t available_native_clusters = ~(foreign_clusters[0]) & candidate_cluster_bitmap;
	int available_cluster_id = lsb_first(available_native_clusters);
	if (available_cluster_id == -1) {
		/* Looks like none of the homogeneous clusters are available; pick the first available cluster */
		available_cluster_id = bit_first(candidate_cluster_bitmap);
	}
	assert(available_cluster_id != -1);
	return pset_array[available_cluster_id];
}

/*
 * sched_edge_switch_pset_lock()
 *
 * Helper routine for sched_edge_migrate_candidate() which switches pset locks (if needed) based on
 * switch_pset_locks.
 * Returns the newly locked pset after the switch.
 */
static processor_set_t
sched_edge_switch_pset_lock(processor_set_t selected_pset, processor_set_t locked_pset, bool switch_pset_locks)
{
	if (!switch_pset_locks) {
		return locked_pset;
	}
	if (selected_pset != locked_pset) {
		pset_unlock(locked_pset);
		pset_lock(selected_pset);
		return selected_pset;
	} else {
		return locked_pset;
	}
}

/*
 * sched_edge_migrate_candidate()
 *
 * Routine to find an appropriate cluster for scheduling a thread. The routine looks at the properties of
 * the thread and the preferred cluster to determine the best available pset for scheduling.
 *
 * The switch_pset_locks parameter defines whether the routine should switch pset locks to provide an
 * accurate scheduling decision. This mode is typically used when choosing a pset for scheduling a thread since the
 * decision has to be synchronized with another CPU changing the recommendation of clusters available
 * on the system. If this parameter is set to false, this routine returns the best effort indication of
 * the cluster the thread should be scheduled on. It is typically used in fast path contexts (such as
 * SCHED(thread_avoid_processor) to determine if there is a possibility of scheduling this thread on a
 * more appropriate cluster.
 *
 * Routine returns the most ideal cluster for scheduling. If switch_pset_locks is set, it ensures that the
 * resultant pset lock is held.
 */
static processor_set_t
sched_edge_migrate_candidate(processor_set_t preferred_pset, thread_t thread, processor_set_t locked_pset, bool switch_pset_locks)
{
	__kdebug_only uint32_t preferred_cluster_id = preferred_pset->pset_cluster_id;
	processor_set_t selected_pset = preferred_pset;

	if (SCHED_CLUTCH_THREAD_CLUSTER_BOUND(thread)) {
		/* For bound threads always recommend the cluster its bound to */
		selected_pset = pset_array[sched_edge_thread_bound_cluster_id(thread)];
		locked_pset = sched_edge_switch_pset_lock(selected_pset, locked_pset, switch_pset_locks);
		if (sched_edge_pset_available(selected_pset) || (SCHED_CLUTCH_THREAD_CLUSTER_BOUND_SOFT(thread) == false)) {
			/*
			 * If the bound cluster is not available, check if the thread is soft bound. For soft bound threads,
			 * fall through to the regular cluster selection logic which handles unavailable clusters
			 * appropriately. If the thread is hard bound, then return the bound cluster always.
			 */
			return selected_pset;
		}
	}

	uint64_t candidate_cluster_bitmap = mask(MAX_PSETS);
	if (thread->sched_pri >= BASEPRI_RTQUEUES) {
		/* For realtime threads, try and schedule them on the preferred pset always */
		goto migrate_candidate_available_check;
	}

	/*
	 * If a thread is being rebalanced for achieving equal progress of parallel workloads,
	 * it needs to end up on the preferred runqueue.
	 */
	uint32_t preferred_cluster_load = sched_edge_cluster_load_metric(preferred_pset, thread->th_sched_bucket);
	boolean_t amp_rebalance = (thread->reason & (AST_REBALANCE | AST_QUANTUM)) == (AST_REBALANCE | AST_QUANTUM);
	if ((preferred_cluster_load == 0) || amp_rebalance) {
		goto migrate_candidate_available_check;
	}

	/* Look at edge weights to decide the most ideal migration candidate for this thread */
	selected_pset = sched_edge_migrate_edges_evaluate(preferred_pset, preferred_cluster_load, thread);

migrate_candidate_available_check:
	locked_pset = sched_edge_switch_pset_lock(selected_pset, locked_pset, switch_pset_locks);
	if (sched_edge_pset_available(selected_pset) == true) {
		if (selected_pset != preferred_pset) {
			KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_CLUSTER_OVERLOAD) | DBG_FUNC_NONE, thread_tid(thread), preferred_cluster_id, selected_pset->pset_cluster_id, preferred_cluster_load);
		}
		return selected_pset;
	}
	/* Looks like selected_pset is not available for scheduling; remove it from candidate_cluster_bitmap */
	bitmap_clear(&candidate_cluster_bitmap, selected_pset->pset_cluster_id);
	if (__improbable(bitmap_first(&candidate_cluster_bitmap, MAX_PSETS) == -1)) {
		/*
		 * None of the clusters are available for scheduling; this situation should be rare but if it happens,
		 * simply return the boot cluster.
		 */
		selected_pset = &pset0;
		locked_pset = sched_edge_switch_pset_lock(selected_pset, locked_pset, switch_pset_locks);
		if (selected_pset != preferred_pset) {
			KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_CLUSTER_OVERLOAD) | DBG_FUNC_NONE, thread_tid(thread), preferred_cluster_id, selected_pset->pset_cluster_id, preferred_cluster_load);
		}
		return selected_pset;
	}
	/* Try and find an alternative for the selected pset */
	selected_pset = sched_edge_candidate_alternative(selected_pset, candidate_cluster_bitmap);
	goto migrate_candidate_available_check;
}

static processor_t
sched_edge_choose_processor(processor_set_t pset, processor_t processor, thread_t thread)
{
	/* Bound threads don't call this function */
	assert(thread->bound_processor == PROCESSOR_NULL);
	processor_t chosen_processor = PROCESSOR_NULL;

	/*
	 * sched_edge_preferred_pset() returns the preferred pset for a given thread.
	 * It should take the passed in "pset" as a hint which represents the recency metric for
	 * pset selection logic.
	 */
	processor_set_t preferred_pset = pset_array[sched_edge_thread_preferred_cluster(thread)];
	processor_set_t chosen_pset = preferred_pset;
	/*
	 * If the preferred pset is overloaded, find a pset which is the best candidate to migrate
	 * threads to. sched_edge_migrate_candidate() returns the preferred pset
	 * if it has capacity; otherwise finds the best candidate pset to migrate this thread to.
	 *
	 * <Edge Multi-cluster Support Needed>
	 * It might be useful to build a recency metric for the thread for multiple clusters and
	 * factor that into the migration decisions.
	 */
	chosen_pset = sched_edge_migrate_candidate(preferred_pset, thread, pset, true);
	chosen_processor = choose_processor(chosen_pset, processor, thread);
	assert(chosen_processor->processor_set == chosen_pset);
	return chosen_processor;
}

/*
 * sched_edge_clutch_bucket_threads_drain()
 *
 * Drains all the runnable threads which are not restricted to the root_clutch (due to clutch
 * bucket overrides etc.) into a local thread queue.
 */
static void
sched_edge_clutch_bucket_threads_drain(sched_clutch_bucket_t clutch_bucket, sched_clutch_root_t root_clutch, queue_t clutch_threads)
{
	thread_t thread = THREAD_NULL;
	uint64_t current_timestamp = mach_approximate_time();
	qe_foreach_element_safe(thread, &clutch_bucket->scb_thread_timeshare_queue, th_clutch_timeshare_link) {
		sched_clutch_thread_remove(root_clutch, thread, current_timestamp, SCHED_CLUTCH_BUCKET_OPTIONS_NONE);
		enqueue_tail(clutch_threads, &thread->runq_links);
	}
}

/*
 * sched_edge_run_drained_threads()
 *
 * Makes all drained threads in a local queue runnable.
 */
static void
sched_edge_run_drained_threads(queue_t clutch_threads)
{
	thread_t thread;
	/* Now setrun all the threads in the local queue */
	qe_foreach_element_safe(thread, clutch_threads, runq_links) {
		remqueue(&thread->runq_links);
		thread_lock(thread);
		thread_setrun(thread, SCHED_TAILQ);
		thread_unlock(thread);
	}
}

/*
 * sched_edge_update_preferred_cluster()
 *
 * Routine to update the preferred cluster for QoS buckets within a thread group.
 * The buckets to be updated are specifed as a bitmap (clutch_bucket_modify_bitmap).
 */
static void
sched_edge_update_preferred_cluster(
	sched_clutch_t sched_clutch,
	bitmap_t *clutch_bucket_modify_bitmap,
	uint32_t *tg_bucket_preferred_cluster)
{
	for (int bucket = bitmap_first(clutch_bucket_modify_bitmap, TH_BUCKET_SCHED_MAX); bucket >= 0; bucket = bitmap_next(clutch_bucket_modify_bitmap, bucket)) {
		os_atomic_store(&sched_clutch->sc_clutch_groups[bucket].scbg_preferred_cluster, tg_bucket_preferred_cluster[bucket], relaxed);
	}
}

/*
 * sched_edge_migrate_thread_group_runnable_threads()
 *
 * Routine to implement the migration of threads on a cluster when the thread group
 * recommendation is updated. The migration works using a 2-phase
 * algorithm.
 *
 * Phase 1: With the pset lock held, check the recommendation of the clutch buckets.
 * For each clutch bucket, if it needs to be migrated immediately, drain the threads
 * into a local thread queue. Otherwise mark the clutch bucket as native/foreign as
 * appropriate.
 *
 * Phase 2: After unlocking the pset, drain all the threads from the local thread
 * queue and mark them runnable which should land them in the right hierarchy.
 *
 * The routine assumes that the preferences for the clutch buckets/clutch bucket
 * groups have already been updated by the caller.
 *
 * - Called with the pset locked and interrupts disabled.
 * - Returns with the pset unlocked.
 */
static void
sched_edge_migrate_thread_group_runnable_threads(
	sched_clutch_t sched_clutch,
	sched_clutch_root_t root_clutch,
	bitmap_t *clutch_bucket_modify_bitmap,
	__unused uint32_t *tg_bucket_preferred_cluster,
	bool migrate_immediately)
{
	/* Queue to hold threads that have been drained from clutch buckets to be migrated */
	queue_head_t clutch_threads;
	queue_init(&clutch_threads);

	for (int bucket = bitmap_first(clutch_bucket_modify_bitmap, TH_BUCKET_SCHED_MAX); bucket >= 0; bucket = bitmap_next(clutch_bucket_modify_bitmap, bucket)) {
		/* Get the clutch bucket for this cluster and sched bucket */
		sched_clutch_bucket_group_t clutch_bucket_group = &(sched_clutch->sc_clutch_groups[bucket]);
		sched_clutch_bucket_t clutch_bucket = &(clutch_bucket_group->scbg_clutch_buckets[root_clutch->scr_cluster_id]);
		sched_clutch_root_t scb_root = os_atomic_load(&clutch_bucket->scb_root, relaxed);
		if (scb_root == NULL) {
			/* Clutch bucket not runnable or already in the right hierarchy; nothing to do here */
			assert(clutch_bucket->scb_thr_count == 0);
			continue;
		}
		assert(scb_root == root_clutch);
		uint32_t clutch_bucket_preferred_cluster = sched_clutch_bucket_preferred_cluster(clutch_bucket);

		if (migrate_immediately) {
			/*
			 * For transitions where threads need to be migrated immediately, drain the threads into a
			 * local queue unless we are looking at the clutch buckets for the newly recommended
			 * cluster.
			 */
			if (root_clutch->scr_cluster_id != clutch_bucket_preferred_cluster) {
				sched_edge_clutch_bucket_threads_drain(clutch_bucket, scb_root, &clutch_threads);
			} else {
				sched_clutch_bucket_mark_native(clutch_bucket, root_clutch);
			}
		} else {
			/* Check if this cluster is the same type as the newly recommended cluster */
			boolean_t homogeneous_cluster = (pset_type_for_id(root_clutch->scr_cluster_id) == pset_type_for_id(clutch_bucket_preferred_cluster));
			/*
			 * If threads do not have to be migrated immediately, just change the native/foreign
			 * flag on the clutch bucket.
			 */
			if (homogeneous_cluster) {
				sched_clutch_bucket_mark_native(clutch_bucket, root_clutch);
			} else {
				sched_clutch_bucket_mark_foreign(clutch_bucket, root_clutch);
			}
		}
	}

	pset_unlock(root_clutch->scr_pset);
	sched_edge_run_drained_threads(&clutch_threads);
}

/*
 * sched_edge_migrate_thread_group_running_threads()
 *
 * Routine to find all running threads of a thread group on a specific cluster
 * and IPI them if they need to be moved immediately.
 */
static void
sched_edge_migrate_thread_group_running_threads(
	sched_clutch_t sched_clutch,
	sched_clutch_root_t root_clutch,
	__unused bitmap_t *clutch_bucket_modify_bitmap,
	uint32_t *tg_bucket_preferred_cluster,
	bool migrate_immediately)
{
	if (migrate_immediately == false) {
		/* If CLPC has recommended not to move threads immediately, nothing to do here */
		return;
	}

	/*
	 * Edge Scheduler Optimization
	 *
	 * When the system has a large number of clusters and cores, it might be useful to
	 * narrow down the iteration by using a thread running bitmap per clutch.
	 */
	uint64_t ast_processor_map = 0;
	sched_ipi_type_t ipi_type[MAX_CPUS] = {SCHED_IPI_NONE};

	uint64_t running_map = root_clutch->scr_pset->cpu_state_map[PROCESSOR_RUNNING];
	/*
	 * Iterate all CPUs and look for the ones running threads from this thread group and are
	 * not restricted to the specific cluster (due to overrides etc.)
	 */
	for (int cpuid = lsb_first(running_map); cpuid >= 0; cpuid = lsb_next(running_map, cpuid)) {
		processor_t src_processor = processor_array[cpuid];
		boolean_t expected_tg = (src_processor->current_thread_group == sched_clutch->sc_tg);
		sched_bucket_t processor_sched_bucket = src_processor->processor_set->cpu_running_buckets[cpuid];
		boolean_t non_preferred_cluster = tg_bucket_preferred_cluster[processor_sched_bucket] != root_clutch->scr_cluster_id;

		if (expected_tg && non_preferred_cluster) {
			ipi_type[cpuid] = sched_ipi_action(src_processor, NULL, false, SCHED_IPI_EVENT_REBALANCE);
			if (ipi_type[cpuid] != SCHED_IPI_NONE) {
				bit_set(ast_processor_map, cpuid);
			} else if (src_processor == current_processor()) {
				ast_on(AST_PREEMPT);
				bit_set(root_clutch->scr_pset->pending_AST_PREEMPT_cpu_mask, cpuid);
			}
		}
	}

	/* Perform all the IPIs */
	if (bit_first(ast_processor_map) != -1) {
		for (int cpuid = lsb_first(ast_processor_map); cpuid >= 0; cpuid = lsb_next(ast_processor_map, cpuid)) {
			processor_t ast_processor = processor_array[cpuid];
			sched_ipi_perform(ast_processor, ipi_type[cpuid]);
		}
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_AMP_RECOMMENDATION_CHANGE) | DBG_FUNC_NONE, thread_group_get_id(sched_clutch->sc_tg), ast_processor_map, 0, 0);
	}
}

/*
 * sched_edge_tg_preferred_cluster_change()
 *
 * Routine to handle changes to a thread group's recommendation. In the Edge Scheduler, the preferred cluster
 * is specified on a per-QoS basis within a thread group. The routine updates the preferences and performs
 * thread migrations based on the policy specified by CLPC.
 * tg_bucket_preferred_cluster is an array of size TH_BUCKET_SCHED_MAX which specifies the new preferred cluster
 * for each QoS within the thread group.
 */
void
sched_edge_tg_preferred_cluster_change(struct thread_group *tg, uint32_t *tg_bucket_preferred_cluster, sched_perfcontrol_preferred_cluster_options_t options)
{
	sched_clutch_t clutch = sched_clutch_for_thread_group(tg);
	/*
	 * In order to optimize the processing, create a bitmap which represents all QoS buckets
	 * for which the preferred cluster has changed.
	 */
	bitmap_t clutch_bucket_modify_bitmap[BITMAP_LEN(TH_BUCKET_SCHED_MAX)] = {0};
	for (sched_bucket_t bucket = TH_BUCKET_FIXPRI; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
		uint32_t old_preferred_cluster = sched_edge_clutch_bucket_group_preferred_cluster(&clutch->sc_clutch_groups[bucket]);
		uint32_t new_preferred_cluster = tg_bucket_preferred_cluster[bucket];
		if (old_preferred_cluster != new_preferred_cluster) {
			bitmap_set(clutch_bucket_modify_bitmap, bucket);
		}
	}
	if (bitmap_lsb_first(clutch_bucket_modify_bitmap, TH_BUCKET_SCHED_MAX) == -1) {
		/* No changes in any clutch buckets; nothing to do here */
		return;
	}

	for (uint32_t cluster_id = 0; cluster_id < MAX_PSETS; cluster_id++) {
		processor_set_t pset = pset_array[cluster_id];
		spl_t s = splsched();
		pset_lock(pset);
		/*
		 * The first operation is to update the preferred cluster for all QoS buckets within the
		 * thread group so that any future threads becoming runnable would see the new preferred
		 * cluster value.
		 */
		sched_edge_update_preferred_cluster(clutch, clutch_bucket_modify_bitmap, tg_bucket_preferred_cluster);
		/*
		 * Currently iterates all clusters looking for running threads for a TG to be migrated. Can be optimized
		 * by keeping a per-clutch bitmap of clusters running threads for a particular TG.
		 *
		 * <Edge Multi-cluster Support Needed>
		 */
		/* Migrate all running threads of the TG on this cluster based on options specified by CLPC */
		sched_edge_migrate_thread_group_running_threads(clutch, &pset->pset_clutch_root, clutch_bucket_modify_bitmap,
		    tg_bucket_preferred_cluster, (options & SCHED_PERFCONTROL_PREFERRED_CLUSTER_MIGRATE_RUNNING));
		/* Migrate all runnable threads of the TG in this cluster's hierarchy based on options specified by CLPC */
		sched_edge_migrate_thread_group_runnable_threads(clutch, &pset->pset_clutch_root, clutch_bucket_modify_bitmap,
		    tg_bucket_preferred_cluster, (options & SCHED_PERFCONTROL_PREFERRED_CLUSTER_MIGRATE_RUNNABLE));
		/* sched_edge_migrate_thread_group_runnable_threads() returns with pset unlocked */
		splx(s);
	}
}

/*
 * sched_edge_pset_made_schedulable()
 *
 * Routine to migrate all the clutch buckets which are not in their recommended
 * pset hierarchy now that a new pset has become runnable. Its possible that this
 * routine is called when the pset is already marked schedulable.
 *
 * Invoked with the pset lock held and interrupts disabled.
 */
static void
sched_edge_pset_made_schedulable(__unused processor_t processor, processor_set_t dst_pset, boolean_t drop_lock)
{
	if (bitmap_test(sched_edge_available_pset_bitmask, dst_pset->pset_cluster_id)) {
		/* Nothing to do here since pset is already marked schedulable */
		if (drop_lock) {
			pset_unlock(dst_pset);
		}
		return;
	}

	bitmap_set(sched_edge_available_pset_bitmask, dst_pset->pset_cluster_id);

	thread_t thread = sched_edge_processor_idle(dst_pset);
	if (thread != THREAD_NULL) {
		thread_lock(thread);
		thread_setrun(thread, SCHED_TAILQ);
		thread_unlock(thread);
	}

	if (!drop_lock) {
		pset_lock(dst_pset);
	}
}

extern int sched_amp_spill_deferred_ipi;
extern int sched_amp_pcores_preempt_immediate_ipi;

int sched_edge_migrate_ipi_immediate = 1;

sched_ipi_type_t
sched_edge_ipi_policy(processor_t dst, thread_t thread, boolean_t dst_idle, sched_ipi_event_t event)
{
	processor_set_t pset = dst->processor_set;
	assert(bit_test(pset->pending_AST_URGENT_cpu_mask, dst->cpu_id) == false);
	assert(dst != current_processor());

	boolean_t deferred_ipi_supported = false;
#if defined(CONFIG_SCHED_DEFERRED_AST)
	deferred_ipi_supported = true;
#endif /* CONFIG_SCHED_DEFERRED_AST */

	switch (event) {
	case SCHED_IPI_EVENT_SPILL:
		/* For Spill event, use deferred IPIs if sched_amp_spill_deferred_ipi set */
		if (deferred_ipi_supported && sched_amp_spill_deferred_ipi) {
			return sched_ipi_deferred_policy(pset, dst, event);
		}
		break;
	case SCHED_IPI_EVENT_PREEMPT:
		/* For preemption, the default policy is to use deferred IPIs
		 * for Non-RT P-core preemption. Override that behavior if
		 * sched_amp_pcores_preempt_immediate_ipi is set
		 */
		if (thread && thread->sched_pri < BASEPRI_RTQUEUES) {
			if (sched_edge_migrate_ipi_immediate) {
				/*
				 * For workloads that are going wide, it might be useful use Immediate IPI to
				 * wakeup the idle CPU if the scheduler estimates that the preferred pset will
				 * be busy for the deferred IPI timeout. The Edge Scheduler uses the avg execution
				 * latency on the preferred pset as an estimate of busyness.
				 *
				 * <Edge Multi-cluster Support Needed>
				 */
				processor_set_t preferred_pset = pset_array[sched_edge_thread_preferred_cluster(thread)];
				if ((preferred_pset->pset_execution_time[thread->th_sched_bucket].pset_avg_thread_execution_time * NSEC_PER_USEC) >= ml_cpu_signal_deferred_get_timer()) {
					return dst_idle ? SCHED_IPI_IDLE : SCHED_IPI_IMMEDIATE;
				}
			}
			if (sched_amp_pcores_preempt_immediate_ipi && (pset_type_for_id(pset->pset_cluster_id) == CLUSTER_TYPE_P)) {
				return dst_idle ? SCHED_IPI_IDLE : SCHED_IPI_IMMEDIATE;
			}
		}
		break;
	default:
		break;
	}
	/* Default back to the global policy for all other scenarios */
	return sched_ipi_policy(dst, thread, dst_idle, event);
}

/*
 * sched_edge_qos_max_parallelism()
 */
uint32_t
sched_edge_qos_max_parallelism(int qos, uint64_t options)
{
	uint32_t ecount = 0;
	uint32_t pcount = 0;

	for (int cluster_id = 0; cluster_id < MAX_PSETS; cluster_id++) {
		processor_set_t pset = pset_array[cluster_id];
		if (pset_type_for_id(cluster_id) == CLUSTER_TYPE_P) {
			pcount += pset->cpu_set_count;
		} else {
			ecount += pset->cpu_set_count;
		}
	}

	if (options & QOS_PARALLELISM_REALTIME) {
		/* For realtime threads on AMP, we would want them
		 * to limit the width to just the P-cores since we
		 * do not spill/rebalance for RT threads.
		 */
		return pcount;
	}

	/*
	 * The Edge scheduler supports per-QoS recommendations for thread groups.
	 * This enables lower QoS buckets (such as UT) to be scheduled on all
	 * CPUs on the system.
	 *
	 * The only restriction is for BG/Maintenance QoS classes for which the
	 * performance controller would never recommend execution on the P-cores.
	 * If that policy changes in the future, this value should be changed.
	 */
	switch (qos) {
	case THREAD_QOS_BACKGROUND:
	case THREAD_QOS_MAINTENANCE:
		return ecount;
	default:
		return ecount + pcount;
	}
}



#endif /* CONFIG_SCHED_EDGE */

#endif /* CONFIG_SCHED_CLUTCH */

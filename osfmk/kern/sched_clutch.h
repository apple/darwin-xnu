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

#ifndef _KERN_SCHED_CLUTCH_H_
#define _KERN_SCHED_CLUTCH_H_

#include <kern/sched.h>
#include <machine/atomic.h>
#include <kern/priority_queue.h>
#include <kern/thread_group.h>
#include <kern/bits.h>

#if CONFIG_SCHED_CLUTCH

/*
 * Clutch ordering based on thread group flags (specified
 * by the thread grouping mechanism). These properties
 * define a thread group specific priority boost.
 *
 * The current implementation gives a slight boost to
 * HIGH & MED thread groups which effectively deprioritizes
 * daemon thread groups which are marked "Efficient" on AMP
 * systems.
 */
__enum_decl(sched_clutch_tg_priority_t, uint8_t, {
	SCHED_CLUTCH_TG_PRI_LOW           = 0,
	SCHED_CLUTCH_TG_PRI_MED           = 1,
	SCHED_CLUTCH_TG_PRI_HIGH          = 2,
	SCHED_CLUTCH_TG_PRI_MAX           = 3,
});

/*
 * For the current implementation, bound threads are not managed
 * in the clutch hierarchy. This helper macro is used to indicate
 * if the thread should be in the hierarchy.
 */
#define SCHED_CLUTCH_THREAD_ELIGIBLE(thread)    ((thread->bound_processor) == PROCESSOR_NULL)

#if CONFIG_SCHED_EDGE
#define SCHED_CLUTCH_THREAD_CLUSTER_BOUND(thread)       ((thread->sched_flags & (TH_SFLAG_ECORE_ONLY | TH_SFLAG_PCORE_ONLY)) != 0)
#define SCHED_CLUTCH_THREAD_CLUSTER_BOUND_SOFT(thread)  ((thread->sched_flags & TH_SFLAG_BOUND_SOFT) != 0)

#else /* CONFIG_SCHED_EDGE */
#define SCHED_CLUTCH_THREAD_CLUSTER_BOUND(thread)       (0)
#define SCHED_CLUTCH_THREAD_CLUSTER_BOUND_SOFT(thread)  (0)
#endif /* CONFIG_SCHED_EDGE */

/*
 * Clutch Bucket Runqueue Structure.
 */
struct sched_clutch_bucket_runq {
	int                     scbrq_highq;
	int                     scbrq_count;
	bitmap_t                scbrq_bitmap[BITMAP_LEN(NRQS_MAX)];
	circle_queue_head_t     scbrq_queues[NRQS_MAX];
};
typedef struct sched_clutch_bucket_runq *sched_clutch_bucket_runq_t;

/*
 *
 * Clutch hierarchy locking protocol
 *
 * The scheduler clutch hierarchy is protected by a combination of
 * atomics and pset lock.
 * - All fields protected by the pset lock are annotated with (P)
 * - All fields updated using atomics are annotated with (A)
 * - All fields that are unprotected and are not updated after
 *   initialization are annotated with (I)
 */

/*
 * struct sched_clutch_root_bucket
 *
 * A clutch_root_bucket represents all threads across all thread groups
 * that are in the same scheduler bucket (FG/IN/...). The clutch_root_bucket
 * is selected for execution by the root level bucket selection algorithm
 * which bases the decision on the clutch_root_bucket's deadline (EDF). The
 * deadline for a root bucket is calculated based on its runnable timestamp
 * and the worst-case-execution-latency values specied in sched_clutch_root_bucket_wcel[]
 */
struct sched_clutch_root_bucket {
	/* (I) sched bucket represented by this root bucket */
	uint8_t                         scrb_bucket;
	/* (I) Indicates the root bucket represents cluster bound threads */
	bool                            scrb_bound;
	/* (P) Indicates if the root bucket is in starvation avoidance mode */
	bool                            scrb_starvation_avoidance;

	union {
		/* (P) priority queue for all unbound clutch buckets in this sched bucket */
		struct sched_clutch_bucket_runq scrb_clutch_buckets;
		/* (P) Runqueue for all bound threads part of this root bucket */
		struct run_queue                scrb_bound_thread_runq;
	};
	/* (P) priority queue entry to use for enqueueing root bucket into root prioq */
	struct priority_queue_entry_deadline scrb_pqlink;
	/* (P) warped deadline for root bucket */
	uint64_t                        scrb_warped_deadline;
	/* (P) warp remaining for root bucket */
	uint64_t                        scrb_warp_remaining;
	/* (P) timestamp for the start of the starvation avoidance window */
	uint64_t                        scrb_starvation_ts;
};
typedef struct sched_clutch_root_bucket *sched_clutch_root_bucket_t;

/*
 * struct sched_clutch_root
 *
 * A clutch_root represents the root of the hierarchy. It maintains a
 * priority queue of all runnable root buckets. The clutch_root also
 * maintains the information about the last clutch_root_bucket scheduled
 * in order to implement bucket level quantum. The bucket level quantums
 * allow low priority buckets to get a "fair" chance of using the CPU even
 * if they contain a bunch of short executing threads. The bucket quantums
 * are configured using sched_clutch_root_bucket_quantum[]
 */
struct sched_clutch_root {
	/* (P) root level priority; represents the highest runnable thread in the hierarchy */
	int16_t                         scr_priority;
	/* (P) total number of runnable threads in the hierarchy */
	uint16_t                        scr_thr_count;
	/* (P) root level urgency; represents the urgency of the whole hierarchy for pre-emption purposes */
	int16_t                         scr_urgency;

	uint32_t                        scr_cluster_id;
	/* (I) processor set this hierarchy belongs to */
	processor_set_t                 scr_pset;
	/*
	 * (P) list of all runnable clutch buckets across the system;
	 * allows easy iteration in the sched tick based timesharing code
	 */
	queue_head_t                    scr_clutch_buckets;

	/*
	 * (P) priority queue of all runnable foreign buckets in this hierarchy;
	 * used for tracking thread groups which need to be migrated when
	 * psets are available or rebalancing threads on CPU idle.
	 */
	struct priority_queue_sched_max scr_foreign_buckets;

	/* Root level bucket management */

	/* (P) bitmap of all runnable unbounded root buckets */
	bitmap_t                        scr_unbound_runnable_bitmap[BITMAP_LEN(TH_BUCKET_SCHED_MAX)];
	/* (P) bitmap of all runnable unbounded root buckets which have warps remaining */
	bitmap_t                        scr_unbound_warp_available[BITMAP_LEN(TH_BUCKET_SCHED_MAX)];
	/* (P) bitmap of all runnable bounded root buckets */
	bitmap_t                        scr_bound_runnable_bitmap[BITMAP_LEN(TH_BUCKET_SCHED_MAX)];
	/* (P) bitmap of all runnable bounded root buckets which have warps remaining */
	bitmap_t                        scr_bound_warp_available[BITMAP_LEN(TH_BUCKET_SCHED_MAX)];

	/* (P) priority queue of all runnable unbounded root buckets in deadline order */
	struct priority_queue_deadline_min scr_unbound_root_buckets;
	/* (P) priority queue of all bounded root buckets in deadline order */
	struct priority_queue_deadline_min scr_bound_root_buckets;

	/* (P) cumulative run counts at each bucket for load average calculation */
	uint16_t _Atomic                scr_cumulative_run_count[TH_BUCKET_SCHED_MAX];

	/* (P) storage for all unbound clutch_root_buckets */
	struct sched_clutch_root_bucket scr_unbound_buckets[TH_BUCKET_SCHED_MAX];
	/* (P) storage for all bound clutch_root_buckets */
	struct sched_clutch_root_bucket scr_bound_buckets[TH_BUCKET_SCHED_MAX];
};
typedef struct sched_clutch_root *sched_clutch_root_t;

/* forward declaration for sched_clutch */
struct sched_clutch;

/*
 * sched_clutch_bucket_cpu_data_t
 *
 * Used for maintaining clutch bucket used and blocked time. The
 * values are used for calculating the interactivity score for the
 * clutch bucket.
 *
 * Since the CPU used/blocked calculation uses wide atomics, the data
 * types used are different based on the platform.
 */

#if __LP64__

#define CLUTCH_CPU_DATA_MAX             (UINT64_MAX)
typedef uint64_t                        clutch_cpu_data_t;
typedef unsigned __int128               clutch_cpu_data_wide_t;

#else /* __LP64__ */

#define CLUTCH_CPU_DATA_MAX             (UINT32_MAX)
typedef uint32_t                        clutch_cpu_data_t;
typedef uint64_t                        clutch_cpu_data_wide_t;

#endif /* __LP64__ */

typedef union sched_clutch_bucket_cpu_data {
	struct {
		/* Clutch bucket CPU used across all threads */
		clutch_cpu_data_t       scbcd_cpu_used;
		/* Clutch bucket voluntary blocked time */
		clutch_cpu_data_t       scbcd_cpu_blocked;
	} cpu_data;
	clutch_cpu_data_wide_t          scbcd_cpu_data_packed;
} sched_clutch_bucket_cpu_data_t;

/*
 * struct sched_clutch_bucket
 *
 * A sched_clutch_bucket represents the set of threads for a thread
 * group at a particular scheduling bucket in a specific cluster.
 * It maintains information about the CPU usage & blocking behavior
 * of all threads part of the clutch_bucket. It inherits the timeshare
 * values from the clutch_bucket_group for decay and timesharing among
 * threads in the clutch.
 *
 * Since the clutch bucket is a per thread group per-QoS entity it is
 * important to keep its size small and the structure well aligned.
 */
struct sched_clutch_bucket {
#if CONFIG_SCHED_EDGE
	/* (P) flag to indicate if the bucket is a foreign bucket */
	bool                            scb_foreign;
#endif /* CONFIG_SCHED_EDGE */
	/* (I) bucket for the clutch_bucket */
	uint8_t                         scb_bucket;
	/* (P) priority of the clutch bucket */
	uint8_t                         scb_priority;
	/* (P) number of threads in this clutch_bucket; should match runq.count */
	uint16_t                        scb_thr_count;

	/* Pointer to the clutch bucket group this clutch bucket belongs to */
	struct sched_clutch_bucket_group *scb_group;
	/* (A) pointer to the root of the hierarchy this bucket is in */
	struct sched_clutch_root        *scb_root;
	/* (P) priority queue of threads based on their promoted/base priority */
	struct priority_queue_sched_max scb_clutchpri_prioq;
	/* (P) runq of threads in clutch_bucket */
	struct priority_queue_sched_stable_max scb_thread_runq;

	/* (P) linkage for all clutch_buckets in a root bucket; used for tick operations */
	queue_chain_t                   scb_listlink;
	/* (P) linkage for clutch_bucket in root_bucket runqueue */
	queue_chain_t                   scb_runqlink;
	/* (P) queue of threads for timesharing purposes */
	queue_head_t                    scb_thread_timeshare_queue;
#if CONFIG_SCHED_EDGE
	/* (P) linkage for all "foreign" clutch buckets in the root clutch */
	struct priority_queue_entry_sched     scb_foreignlink;
#endif /* CONFIG_SCHED_EDGE */
};
typedef struct sched_clutch_bucket *sched_clutch_bucket_t;

/*
 * sched_clutch_counter_time_t
 *
 * Holds thread counts and a timestamp (typically for a clutch bucket group).
 * Used to allow atomic updates to these fields.
 */
typedef union sched_clutch_counter_time {
	struct {
		uint64_t                scct_count;
		uint64_t                scct_timestamp;
	};
#if __LP64__
	unsigned __int128               scct_packed;
#endif /* __LP64__ */
} __attribute__((aligned(16))) sched_clutch_counter_time_t;

/*
 * struct sched_clutch_bucket_group
 *
 * It represents all the threads for a thread group at a particular
 * QoS/Scheduling bucket. This structure also maintains the timesharing
 * properties that are used for decay calculation for all threads in the
 * thread group at the specific scheduling bucket.
 */
struct sched_clutch_bucket_group {
	/* (I) bucket for the clutch_bucket_group */
	uint8_t                         scbg_bucket;
	/* (A) sched tick when the clutch bucket group load/shifts were updated */
	uint32_t _Atomic                scbg_timeshare_tick;
	/* (A) priority shifts for threads in the clutch_bucket_group */
	uint32_t _Atomic                scbg_pri_shift;
	/* (A) preferred cluster ID for clutch bucket */
	uint32_t _Atomic                scbg_preferred_cluster;
	/* (I) clutch to which this clutch bucket_group belongs */
	struct sched_clutch             *scbg_clutch;
#if !__LP64__
	/* Lock for synchronizing updates to blocked data (only on platforms without 128-atomics) */
	lck_spin_t                      scbg_stats_lock;
#endif /* !__LP64__ */
	/* (A/L depending on arch) holds blcked timestamp and runnable/running count */
	sched_clutch_counter_time_t     scbg_blocked_data;
	/* (P/A depending on scheduler) holds pending timestamp and thread count */
	sched_clutch_counter_time_t     scbg_pending_data;
	/* (P/A depending on scheduler) holds interactivity timestamp and score */
	sched_clutch_counter_time_t     scbg_interactivity_data;
	/* (A) CPU usage information for the clutch bucket group */
	sched_clutch_bucket_cpu_data_t  scbg_cpu_data;

	/*
	 * Edge Scheduler Optimization
	 *
	 * Currently the array is statically sized based on MAX_PSETS.
	 * If that definition does not exist (or has a large theoretical
	 * max value), this could be a dynamic array based on ml_topology_info*
	 * routines.
	 *
	 * <Edge Multi-cluster Support Needed>
	 */
	/* Storage for all clutch buckets for a thread group at scbg_bucket */
	struct sched_clutch_bucket      scbg_clutch_buckets[MAX_PSETS];
};
typedef struct sched_clutch_bucket_group *sched_clutch_bucket_group_t;


/*
 * struct sched_clutch
 *
 * A sched_clutch is a 1:1 mapping to a thread group. It maintains the
 * storage for all clutch buckets for this thread group and some properties
 * of the thread group (such as flags etc.)
 */
struct sched_clutch {
	/*
	 * (A) number of runnable threads in sched_clutch; needs to be atomic
	 * to support cross cluster sched_clutch migrations.
	 */
	uint16_t _Atomic                sc_thr_count;
	/*
	 * Grouping specific parameters. Currently the implementation only
	 * supports thread_group based grouping.
	 */
	union {
		/* (A) priority specified by the thread grouping mechanism */
		sched_clutch_tg_priority_t _Atomic sc_tg_priority;
	};
	union {
		/* (I) Pointer to thread group */
		struct thread_group     *sc_tg;
	};
	/* (I) storage for all clutch_buckets for this clutch */
	struct sched_clutch_bucket_group sc_clutch_groups[TH_BUCKET_SCHED_MAX];
};
typedef struct sched_clutch *sched_clutch_t;


/* Clutch lifecycle management */
void sched_clutch_init_with_thread_group(sched_clutch_t, struct thread_group *);
void sched_clutch_destroy(sched_clutch_t);

/* Clutch thread membership management */
void sched_clutch_thread_clutch_update(thread_t, sched_clutch_t, sched_clutch_t);
uint32_t sched_edge_thread_preferred_cluster(thread_t);

/* Clutch timesharing stats management */
uint32_t sched_clutch_thread_run_bucket_incr(thread_t, sched_bucket_t);
uint32_t sched_clutch_thread_run_bucket_decr(thread_t, sched_bucket_t);
void sched_clutch_cpu_usage_update(thread_t, uint64_t);
uint32_t sched_clutch_thread_pri_shift(thread_t, sched_bucket_t);

/* Clutch properties accessors */
uint32_t sched_clutch_root_count(sched_clutch_root_t);

/* Grouping specific external routines */
extern sched_clutch_t sched_clutch_for_thread(thread_t);
extern sched_clutch_t sched_clutch_for_thread_group(struct thread_group *);

#if CONFIG_SCHED_EDGE

/*
 * Getter and Setter for Edge configuration. Used by CLPC to affect thread migration behavior.
 */
void sched_edge_matrix_get(sched_clutch_edge *edge_matrix, bool *edge_request_bitmap, uint64_t flags, uint64_t matrix_order);
void sched_edge_matrix_set(sched_clutch_edge *edge_matrix, bool *edge_changes_bitmap, uint64_t flags, uint64_t matrix_order);
void sched_edge_tg_preferred_cluster_change(struct thread_group *tg, uint32_t *tg_bucket_preferred_cluster, sched_perfcontrol_preferred_cluster_options_t options);

uint16_t sched_edge_cluster_cumulative_count(sched_clutch_root_t root_clutch, sched_bucket_t bucket);

#if DEVELOPMENT || DEBUG
/*
 * Sysctl support for dynamically configuring edge properties.
 *
 * <Edge Multi-cluster Support Needed>
 */
kern_return_t sched_edge_sysctl_configure_e_to_p(uint64_t);
kern_return_t sched_edge_sysctl_configure_p_to_e(uint64_t);
sched_clutch_edge sched_edge_e_to_p(void);
sched_clutch_edge sched_edge_p_to_e(void);
#endif /* DEVELOPMENT || DEBUG */

#endif /* CONFIG_SCHED_EDGE */

#endif /* CONFIG_SCHED_CLUTCH */

#endif /* _KERN_SCHED_CLUTCH_H_ */

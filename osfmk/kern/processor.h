/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */

/*
 *	processor.h:	Processor and processor-related definitions.
 */

#ifndef _KERN_PROCESSOR_H_
#define _KERN_PROCESSOR_H_

#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <kern/kern_types.h>

#include <sys/cdefs.h>

#ifdef  MACH_KERNEL_PRIVATE

#include <mach/mach_types.h>
#include <kern/ast.h>
#include <kern/cpu_number.h>
#include <kern/smp.h>
#include <kern/simple_lock.h>
#include <kern/locks.h>
#include <kern/percpu.h>
#include <kern/queue.h>
#include <kern/sched.h>
#include <kern/sched_urgency.h>
#include <kern/timer.h>
#include <mach/sfi_class.h>
#include <kern/sched_clutch.h>
#include <kern/timer_call.h>
#include <kern/assert.h>
#include <machine/limits.h>

/*
 *	Processor state is accessed by locking the scheduling lock
 *	for the assigned processor set.
 *
 *           -------------------- SHUTDOWN
 *          /                     ^     ^
 *        _/                      |      \
 *  OFF_LINE ---> START ---> RUNNING ---> IDLE ---> DISPATCHING
 *         \_________________^   ^ ^______/           /
 *                                \__________________/
 *
 *  Most of these state transitions are externally driven as a
 *  a directive (for instance telling an IDLE processor to start
 *  coming out of the idle state to run a thread). However these
 *  are typically paired with a handshake by the processor itself
 *  to indicate that it has completed a transition of indeterminate
 *  length (for example, the DISPATCHING->RUNNING or START->RUNNING
 *  transitions must occur on the processor itself).
 *
 *  The boot processor has some special cases, and skips the START state,
 *  since it has already bootstrapped and is ready to context switch threads.
 *
 *  When a processor is in DISPATCHING or RUNNING state, the current_pri,
 *  current_thmode, and deadline fields should be set, so that other
 *  processors can evaluate if it is an appropriate candidate for preemption.
 */
#if defined(CONFIG_SCHED_DEFERRED_AST)
/*
 *           -------------------- SHUTDOWN
 *          /                     ^     ^
 *        _/                      |      \
 *  OFF_LINE ---> START ---> RUNNING ---> IDLE ---> DISPATCHING
 *         \_________________^   ^ ^______/ ^_____ /  /
 *                                \__________________/
 *
 *  A DISPATCHING processor may be put back into IDLE, if another
 *  processor determines that the target processor will have nothing to do
 *  upon reaching the RUNNING state.  This is racy, but if the target
 *  responds and becomes RUNNING, it will not break the processor state
 *  machine.
 *
 *  This change allows us to cancel an outstanding signal/AST on a processor
 *  (if such an operation is supported through hardware or software), and
 *  push the processor back into the IDLE state as a power optimization.
 */
#endif

typedef enum {
	PROCESSOR_OFF_LINE      = 0,    /* Not available */
	PROCESSOR_SHUTDOWN      = 1,    /* Going off-line */
	PROCESSOR_START         = 2,    /* Being started */
	PROCESSOR_UNUSED        = 3,    /* Formerly Inactive (unavailable) */
	PROCESSOR_IDLE          = 4,    /* Idle (available) */
	PROCESSOR_DISPATCHING   = 5,    /* Dispatching (idle -> active) */
	PROCESSOR_RUNNING       = 6,    /* Normal execution */
	PROCESSOR_STATE_LEN     = (PROCESSOR_RUNNING + 1)
} processor_state_t;

typedef enum {
	PSET_SMP,
#if __AMP__
	PSET_AMP_E,
	PSET_AMP_P,
#endif
} pset_cluster_type_t;

#if __AMP__

typedef enum {
	SCHED_PERFCTL_POLICY_DEFAULT,           /*  static policy: set at boot */
	SCHED_PERFCTL_POLICY_FOLLOW_GROUP,      /* dynamic policy: perfctl_class follows thread group across amp clusters */
	SCHED_PERFCTL_POLICY_RESTRICT_E,        /* dynamic policy: limits perfctl_class to amp e cluster */
} sched_perfctl_class_policy_t;

extern _Atomic sched_perfctl_class_policy_t sched_perfctl_policy_util;
extern _Atomic sched_perfctl_class_policy_t sched_perfctl_policy_bg;

#endif /* __AMP__ */

typedef bitmap_t cpumap_t;

#if __arm64__

/*
 * pset_execution_time_t
 *
 * The pset_execution_time_t type is used to maintain the average
 * execution time of threads on a pset. Since the avg. execution time is
 * updated from contexts where the pset lock is not held, it uses a
 * double-wide RMW loop to update these values atomically.
 */
typedef union {
	struct {
		uint64_t        pset_avg_thread_execution_time;
		uint64_t        pset_execution_time_last_update;
	};
	unsigned __int128       pset_execution_time_packed;
} pset_execution_time_t;

#endif /* __arm64__ */

struct processor_set {
	int                     pset_id;
	int                     online_processor_count;
	int                     cpu_set_low, cpu_set_hi;
	int                     cpu_set_count;
	int                     last_chosen;

	uint64_t                load_average;
	uint64_t                pset_load_average[TH_BUCKET_SCHED_MAX];
	uint64_t                pset_load_last_update;
	cpumap_t                cpu_bitmask;
	cpumap_t                recommended_bitmask;
	cpumap_t                cpu_state_map[PROCESSOR_STATE_LEN];
	cpumap_t                primary_map;
	cpumap_t                realtime_map;
	cpumap_t                cpu_running_foreign;
	sched_bucket_t          cpu_running_buckets[MAX_CPUS];

#define SCHED_PSET_TLOCK (1)
#if     defined(SCHED_PSET_TLOCK)
/* TODO: reorder struct for temporal cache locality */
	__attribute__((aligned(128))) lck_ticket_t      sched_lock;
#else /* SCHED_PSET_TLOCK*/
	__attribute__((aligned(128))) lck_spin_t        sched_lock;     /* lock for above */
#endif /* SCHED_PSET_TLOCK*/

#if defined(CONFIG_SCHED_TRADITIONAL) || defined(CONFIG_SCHED_MULTIQ)
	struct run_queue        pset_runq;      /* runq for this processor set */
#endif
	struct rt_queue         rt_runq;        /* realtime runq for this processor set */
#if CONFIG_SCHED_CLUTCH
	struct sched_clutch_root pset_clutch_root; /* clutch hierarchy root */
#endif /* CONFIG_SCHED_CLUTCH */

#if defined(CONFIG_SCHED_TRADITIONAL)
	int                     pset_runq_bound_count;
	/* # of threads in runq bound to any processor in pset */
#endif

	/* CPUs that have been sent an unacknowledged remote AST for scheduling purposes */
	cpumap_t                pending_AST_URGENT_cpu_mask;
	cpumap_t                pending_AST_PREEMPT_cpu_mask;
#if defined(CONFIG_SCHED_DEFERRED_AST)
	/*
	 * A separate mask, for ASTs that we may be able to cancel.  This is dependent on
	 * some level of support for requesting an AST on a processor, and then quashing
	 * that request later.
	 *
	 * The purpose of this field (and the associated codepaths) is to infer when we
	 * no longer need a processor that is DISPATCHING to come up, and to prevent it
	 * from coming out of IDLE if possible.  This should serve to decrease the number
	 * of spurious ASTs in the system, and let processors spend longer periods in
	 * IDLE.
	 */
	cpumap_t                pending_deferred_AST_cpu_mask;
#endif
	cpumap_t                pending_spill_cpu_mask;

	struct ipc_port *       pset_self;              /* port for operations */
	struct ipc_port *       pset_name_self; /* port for information */

	processor_set_t         pset_list;              /* chain of associated psets */
	pset_node_t             node;
	uint32_t                pset_cluster_id;

	/*
	 * Currently the scheduler uses a mix of pset_cluster_type_t & cluster_type_t
	 * for recommendations etc. It might be useful to unify these as a single type.
	 */
	pset_cluster_type_t     pset_cluster_type;
	cluster_type_t          pset_type;

#if CONFIG_SCHED_EDGE
	bitmap_t                foreign_psets[BITMAP_LEN(MAX_PSETS)];
	sched_clutch_edge       sched_edges[MAX_PSETS];
	pset_execution_time_t   pset_execution_time[TH_BUCKET_SCHED_MAX];
#endif /* CONFIG_SCHED_EDGE */
	bool                    is_SMT;                 /* pset contains SMT processors */
};

extern struct processor_set     pset0;

typedef bitmap_t pset_map_t;

struct pset_node {
	processor_set_t         psets;                  /* list of associated psets */

	pset_node_t             nodes;                  /* list of associated subnodes */
	pset_node_t             node_list;              /* chain of associated nodes */

	pset_node_t             parent;

	pset_map_t              pset_map;               /* map of associated psets */
	_Atomic pset_map_t      pset_idle_map;          /* psets with at least one IDLE CPU */
	_Atomic pset_map_t      pset_idle_primary_map;  /* psets with at least one IDLE primary CPU */
	_Atomic pset_map_t      pset_non_rt_map;        /* psets with at least one available CPU not running a realtime thread */
	_Atomic pset_map_t      pset_non_rt_primary_map;/* psets with at least one available primary CPU not running a realtime thread */
};

extern struct pset_node pset_node0;

extern queue_head_t tasks, threads, corpse_tasks;
extern int tasks_count, terminated_tasks_count, threads_count;
decl_lck_mtx_data(extern, tasks_threads_lock);
decl_lck_mtx_data(extern, tasks_corpse_lock);

/*
 * The terminated tasks queue should only be inspected elsewhere by stackshot.
 */
extern queue_head_t terminated_tasks;

struct processor {
	processor_state_t       state;                  /* See above */
	bool                    is_SMT;
	bool                    is_recommended;
	bool                    current_is_NO_SMT;      /* cached TH_SFLAG_NO_SMT of current thread */
	bool                    current_is_bound;       /* current thread is bound to this processor */
	bool                    current_is_eagerpreempt;/* current thread is TH_SFLAG_EAGERPREEMPT */
	struct thread          *active_thread;          /* thread running on processor */
	struct thread          *idle_thread;            /* this processor's idle thread. */
	struct thread          *startup_thread;

	processor_set_t         processor_set;  /* assigned set */

	/*
	 * XXX All current_* fields should be grouped together, as they're
	 * updated at the same time.
	 */
	int                     current_pri;            /* priority of current thread */
	sfi_class_id_t          current_sfi_class;      /* SFI class of current thread */
	perfcontrol_class_t     current_perfctl_class;  /* Perfcontrol class for current thread */
	/*
	 * The cluster type recommended for the current thread.
	 */
	pset_cluster_type_t     current_recommended_pset_type;
	thread_urgency_t        current_urgency;        /* cached urgency of current thread */

#if CONFIG_SCHED_TRADITIONAL
	int                     runq_bound_count;       /* # of threads bound to this processor */
#endif /* CONFIG_SCHED_TRADITIONAL */

#if CONFIG_THREAD_GROUPS
	struct thread_group    *current_thread_group;   /* thread_group of current thread */
#endif
	int                     starting_pri;           /* priority of current thread as it was when scheduled */
	int                     cpu_id;                 /* platform numeric id */

	uint64_t                quantum_end;            /* time when current quantum ends */
	uint64_t                last_dispatch;          /* time of last dispatch */

#if KPERF
	uint64_t                kperf_last_sample_time; /* time of last kperf sample */
#endif /* KPERF */

	uint64_t                deadline;               /* for next realtime thread */
	bool                    first_timeslice;        /* has the quantum expired since context switch */

	bool                    processor_offlined;     /* has the processor been explicitly processor_offline'ed */
	bool                    must_idle;              /* Needs to be forced idle as next selected thread is allowed on this processor */

	bool                    running_timers_active;  /* whether the running timers should fire */
	struct timer_call       running_timers[RUNNING_TIMER_MAX];

#if CONFIG_SCHED_TRADITIONAL || CONFIG_SCHED_MULTIQ
	struct run_queue        runq;                   /* runq for this processor */
#endif /* CONFIG_SCHED_TRADITIONAL || CONFIG_SCHED_MULTIQ */

#if CONFIG_SCHED_GRRR
	struct grrr_run_queue   grrr_runq;              /* Group Ratio Round-Robin runq */
#endif /* CONFIG_SCHED_GRRR */

	/*
	 * Pointer to primary processor for secondary SMT processors, or a
	 * pointer to ourselves for primaries or non-SMT.
	 */
	processor_t             processor_primary;
	processor_t             processor_secondary;
	struct ipc_port        *processor_self;         /* port for operations */

	processor_t             processor_list;         /* all existing processors */

	/* Processor state statistics */
	timer_data_t            idle_state;
	timer_data_t            system_state;
	timer_data_t            user_state;

	timer_t                 current_state;          /* points to processor's idle, system, or user state timer */

	/* Thread execution timers */
	timer_t                 thread_timer;           /* points to current thread's user or system timer */
	timer_t                 kernel_timer;           /* points to current thread's system_timer */

	uint64_t                timer_call_ttd;         /* current timer call time-to-deadline */
};

extern processor_t processor_list;
decl_simple_lock_data(extern, processor_list_lock);

/*
 * Maximum number of CPUs supported by the scheduler.  bits.h bitmap macros
 * need to be used to support greater than 64.
 */
#define MAX_SCHED_CPUS          64
extern processor_t              processor_array[MAX_SCHED_CPUS]; /* array indexed by cpuid */
extern processor_set_t          pset_array[MAX_PSETS];           /* array indexed by pset_id */

extern uint32_t                 processor_avail_count;
extern uint32_t                 processor_avail_count_user;
extern uint32_t                 primary_processor_avail_count;
extern uint32_t                 primary_processor_avail_count_user;

#define master_processor PERCPU_GET_MASTER(processor)
PERCPU_DECL(struct processor, processor);

extern processor_t      current_processor(void);

/* Lock macros, always acquired and released with interrupts disabled (splsched()) */

extern lck_grp_t pset_lck_grp;

#if defined(SCHED_PSET_TLOCK)
#define pset_lock_init(p)               lck_ticket_init(&(p)->sched_lock, &pset_lck_grp)
#define pset_lock(p)                    lck_ticket_lock(&(p)->sched_lock, &pset_lck_grp)
#define pset_unlock(p)                  lck_ticket_unlock(&(p)->sched_lock)
#define pset_assert_locked(p)           lck_ticket_assert_owned(&(p)->sched_lock)
#else /* SCHED_PSET_TLOCK*/
#define pset_lock_init(p)               lck_spin_init(&(p)->sched_lock, &pset_lck_grp, NULL)
#define pset_lock(p)                    lck_spin_lock_grp(&(p)->sched_lock, &pset_lck_grp)
#define pset_unlock(p)                  lck_spin_unlock(&(p)->sched_lock)
#define pset_assert_locked(p)           LCK_SPIN_ASSERT(&(p)->sched_lock, LCK_ASSERT_OWNED)
#endif /*!SCHED_PSET_TLOCK*/

extern void             processor_bootstrap(void);

extern void             processor_init(
	processor_t             processor,
	int                     cpu_id,
	processor_set_t         processor_set);

extern void             processor_set_primary(
	processor_t             processor,
	processor_t             primary);

extern kern_return_t    processor_shutdown(
	processor_t             processor);

extern kern_return_t    processor_start_from_user(
	processor_t             processor);
extern kern_return_t    processor_exit_from_user(
	processor_t             processor);

extern kern_return_t    sched_processor_enable(
	processor_t             processor,
	boolean_t               enable);

extern void             processor_queue_shutdown(
	processor_t             processor);

extern void             processor_queue_shutdown(
	processor_t             processor);

extern processor_set_t  processor_pset(
	processor_t             processor);

extern pset_node_t      pset_node_root(void);

extern processor_set_t  pset_create(
	pset_node_t             node);

extern void             pset_init(
	processor_set_t         pset,
	pset_node_t             node);

extern processor_set_t  pset_find(
	uint32_t                cluster_id,
	processor_set_t         default_pset);

#if !defined(RC_HIDE_XNU_FIRESTORM) && (MAX_CPU_CLUSTERS > 2)

/*
 * Find the first processor_set for the given pset_cluster_type.
 * Should be removed with rdar://57340304, as it's only
 * useful for the workaround described in rdar://57306691.
 */

extern processor_set_t  pset_find_first_by_cluster_type(
	pset_cluster_type_t     pset_cluster_type);

#endif /* !defined(RC_HIDE_XNU_FIRESTORM) && (MAX_CPU_CLUSTERS > 2) */

extern kern_return_t    processor_info_count(
	processor_flavor_t      flavor,
	mach_msg_type_number_t  *count);

#define pset_deallocate(x)
#define pset_reference(x)

extern void             machine_run_count(
	uint32_t                count);

extern processor_t      machine_choose_processor(
	processor_set_t         pset,
	processor_t             processor);

#define next_pset(p)    (((p)->pset_list != PROCESSOR_SET_NULL)? (p)->pset_list: (p)->node->psets)

#define PSET_THING_TASK         0
#define PSET_THING_THREAD       1

extern pset_cluster_type_t recommended_pset_type(
	thread_t                thread);
#if CONFIG_THREAD_GROUPS
extern pset_cluster_type_t thread_group_pset_recommendation(
	struct thread_group     *tg,
	cluster_type_t          recommendation);
#endif /* CONFIG_THREAD_GROUPS */

inline static bool
pset_is_recommended(processor_set_t pset)
{
	return (pset->recommended_bitmask & pset->cpu_bitmask) != 0;
}

extern void             processor_state_update_idle(
	processor_t             processor);

extern void             processor_state_update_from_thread(
	processor_t             processor,
	thread_t                thread);

extern void             processor_state_update_explicit(
	processor_t             processor,
	int                     pri,
	sfi_class_id_t          sfi_class,
	pset_cluster_type_t     pset_type,
	perfcontrol_class_t     perfctl_class,
	thread_urgency_t        urgency,
	sched_bucket_t          bucket);

#define PSET_LOAD_NUMERATOR_SHIFT   16
#define PSET_LOAD_FRACTIONAL_SHIFT   4

#if CONFIG_SCHED_EDGE

extern cluster_type_t pset_type_for_id(uint32_t cluster_id);

/*
 * The Edge scheduler uses average scheduling latency as the metric for making
 * thread migration decisions. One component of avg scheduling latency is the load
 * average on the cluster.
 *
 * Load Average Fixed Point Arithmetic
 *
 * The load average is maintained as a 24.8 fixed point arithmetic value for precision.
 * When multiplied by the average execution time, it needs to be rounded up (based on
 * the most significant bit of the fractional part) for better accuracy. After rounding
 * up, the whole number part of the value is used as the actual load value for
 * migrate/steal decisions.
 */
#define SCHED_PSET_LOAD_EWMA_FRACTION_BITS 8
#define SCHED_PSET_LOAD_EWMA_ROUND_BIT     (1 << (SCHED_PSET_LOAD_EWMA_FRACTION_BITS - 1))
#define SCHED_PSET_LOAD_EWMA_FRACTION_MASK ((1 << SCHED_PSET_LOAD_EWMA_FRACTION_BITS) - 1)

inline static int
sched_get_pset_load_average(processor_set_t pset, sched_bucket_t sched_bucket)
{
	return (int)(((pset->pset_load_average[sched_bucket] + SCHED_PSET_LOAD_EWMA_ROUND_BIT) >> SCHED_PSET_LOAD_EWMA_FRACTION_BITS) *
	       pset->pset_execution_time[sched_bucket].pset_avg_thread_execution_time);
}

#else /* CONFIG_SCHED_EDGE */
inline static int
sched_get_pset_load_average(processor_set_t pset, __unused sched_bucket_t sched_bucket)
{
	return (int)pset->load_average >> (PSET_LOAD_NUMERATOR_SHIFT - PSET_LOAD_FRACTIONAL_SHIFT);
}
#endif /* CONFIG_SCHED_EDGE */

extern void sched_update_pset_load_average(processor_set_t pset, uint64_t curtime);
extern void sched_update_pset_avg_execution_time(processor_set_t pset, uint64_t delta, uint64_t curtime, sched_bucket_t sched_bucket);

inline static void
pset_update_processor_state(processor_set_t pset, processor_t processor, uint new_state)
{
	pset_assert_locked(pset);

	uint old_state = processor->state;
	uint cpuid = (uint)processor->cpu_id;

	assert(processor->processor_set == pset);
	assert(bit_test(pset->cpu_bitmask, cpuid));

	assert(old_state < PROCESSOR_STATE_LEN);
	assert(new_state < PROCESSOR_STATE_LEN);

	processor->state = new_state;

	bit_clear(pset->cpu_state_map[old_state], cpuid);
	bit_set(pset->cpu_state_map[new_state], cpuid);

	if ((old_state == PROCESSOR_RUNNING) || (new_state == PROCESSOR_RUNNING)) {
		sched_update_pset_load_average(pset, 0);
		if (new_state == PROCESSOR_RUNNING) {
			assert(processor == current_processor());
		}
	}
	if ((old_state == PROCESSOR_IDLE) || (new_state == PROCESSOR_IDLE)) {
		if (new_state == PROCESSOR_IDLE) {
			bit_clear(pset->realtime_map, cpuid);
		}

		pset_node_t node = pset->node;

		if (bit_count(node->pset_map) == 1) {
			/* Node has only a single pset, so skip node pset map updates */
			return;
		}

		if (new_state == PROCESSOR_IDLE) {
			if (processor->processor_primary == processor) {
				if (!bit_test(atomic_load(&node->pset_non_rt_primary_map), pset->pset_id)) {
					atomic_bit_set(&node->pset_non_rt_primary_map, pset->pset_id, memory_order_relaxed);
				}
				if (!bit_test(atomic_load(&node->pset_idle_primary_map), pset->pset_id)) {
					atomic_bit_set(&node->pset_idle_primary_map, pset->pset_id, memory_order_relaxed);
				}
			}
			if (!bit_test(atomic_load(&node->pset_non_rt_map), pset->pset_id)) {
				atomic_bit_set(&node->pset_non_rt_map, pset->pset_id, memory_order_relaxed);
			}
			if (!bit_test(atomic_load(&node->pset_idle_map), pset->pset_id)) {
				atomic_bit_set(&node->pset_idle_map, pset->pset_id, memory_order_relaxed);
			}
		} else {
			cpumap_t idle_map = pset->cpu_state_map[PROCESSOR_IDLE];
			if (idle_map == 0) {
				/* No more IDLE CPUs */
				if (bit_test(atomic_load(&node->pset_idle_map), pset->pset_id)) {
					atomic_bit_clear(&node->pset_idle_map, pset->pset_id, memory_order_relaxed);
				}
			}
			if (processor->processor_primary == processor) {
				idle_map &= pset->primary_map;
				if (idle_map == 0) {
					/* No more IDLE primary CPUs */
					if (bit_test(atomic_load(&node->pset_idle_primary_map), pset->pset_id)) {
						atomic_bit_clear(&node->pset_idle_primary_map, pset->pset_id, memory_order_relaxed);
					}
				}
			}
		}
	}
}

#else   /* MACH_KERNEL_PRIVATE */

__BEGIN_DECLS

extern void             pset_deallocate(
	processor_set_t         pset);

extern void             pset_reference(
	processor_set_t         pset);

__END_DECLS

#endif  /* MACH_KERNEL_PRIVATE */

#ifdef KERNEL_PRIVATE
__BEGIN_DECLS
extern unsigned int             processor_count;
extern processor_t      cpu_to_processor(int cpu);

extern kern_return_t    enable_smt_processors(bool enable);

__END_DECLS

#endif /* KERNEL_PRIVATE */

#endif  /* _KERN_PROCESSOR_H_ */

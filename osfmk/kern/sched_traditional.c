/*
 * Copyright (c) 2000-2015 Apple Inc. All rights reserved.
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
 * @OSF_FREE_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
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

#include <mach/mach_types.h>

#include <kern/sched.h>
#include <kern/sched_prim.h>

static boolean_t
    sched_traditional_use_pset_runqueue = FALSE;

static void
sched_traditional_init(void);

static bool
sched_traditional_steal_thread_enabled(processor_set_t pset);

static thread_t
sched_traditional_steal_thread(processor_set_t pset);

static thread_t
sched_traditional_steal_processor_thread(processor_t processor);

static void
sched_traditional_thread_update_scan(sched_update_scan_context_t scan_context);

static void
sched_traditional_processor_queue_shutdown(processor_t processor);

static boolean_t
sched_traditional_processor_enqueue(processor_t processor, thread_t thread, integer_t options);

static boolean_t
sched_traditional_processor_queue_remove(processor_t processor, thread_t thread);

static boolean_t
sched_traditional_processor_queue_empty(processor_t processor);

static ast_t
sched_traditional_processor_csw_check(processor_t processor);

static boolean_t
sched_traditional_processor_queue_has_priority(processor_t processor, int priority, boolean_t gte);

static int
sched_traditional_processor_runq_count(processor_t processor);

static boolean_t
sched_traditional_with_pset_runqueue_processor_queue_empty(processor_t processor);

static uint64_t
sched_traditional_processor_runq_stats_count_sum(processor_t processor);

static uint64_t
sched_traditional_with_pset_runqueue_processor_runq_stats_count_sum(processor_t processor);

static int
sched_traditional_processor_bound_count(processor_t processor);

extern void
sched_traditional_quantum_expire(thread_t thread);

static void
sched_traditional_processor_init(processor_t processor);

static void
sched_traditional_pset_init(processor_set_t pset);

static void
sched_traditional_with_pset_runqueue_init(void);

static sched_mode_t
sched_traditional_initial_thread_sched_mode(task_t parent_task);

static thread_t
sched_traditional_choose_thread(processor_t processor, int priority, ast_t reason);

/* Choose a thread from a processor's priority-based runq */
static thread_t sched_traditional_choose_thread_from_runq(processor_t processor, run_queue_t runq, int priority);

const struct sched_dispatch_table sched_traditional_dispatch = {
	.sched_name                                     = "traditional",
	.init                                           = sched_traditional_init,
	.timebase_init                                  = sched_timeshare_timebase_init,
	.processor_init                                 = sched_traditional_processor_init,
	.pset_init                                      = sched_traditional_pset_init,
	.maintenance_continuation                       = sched_timeshare_maintenance_continue,
	.choose_thread                                  = sched_traditional_choose_thread,
	.steal_thread_enabled                           = sched_traditional_steal_thread_enabled,
	.steal_thread                                   = sched_traditional_steal_thread,
	.compute_timeshare_priority                     = sched_compute_timeshare_priority,
	.choose_processor                               = choose_processor,
	.processor_enqueue                              = sched_traditional_processor_enqueue,
	.processor_queue_shutdown                       = sched_traditional_processor_queue_shutdown,
	.processor_queue_remove                         = sched_traditional_processor_queue_remove,
	.processor_queue_empty                          = sched_traditional_processor_queue_empty,
	.priority_is_urgent                             = priority_is_urgent,
	.processor_csw_check                            = sched_traditional_processor_csw_check,
	.processor_queue_has_priority                   = sched_traditional_processor_queue_has_priority,
	.initial_quantum_size                           = sched_timeshare_initial_quantum_size,
	.initial_thread_sched_mode                      = sched_traditional_initial_thread_sched_mode,
	.can_update_priority                            = can_update_priority,
	.update_priority                                = update_priority,
	.lightweight_update_priority                    = lightweight_update_priority,
	.quantum_expire                                 = sched_default_quantum_expire,
	.processor_runq_count                           = sched_traditional_processor_runq_count,
	.processor_runq_stats_count_sum                 = sched_traditional_processor_runq_stats_count_sum,
	.processor_bound_count                          = sched_traditional_processor_bound_count,
	.thread_update_scan                             = sched_traditional_thread_update_scan,
	.direct_dispatch_to_idle_processors             = TRUE,
	.multiple_psets_enabled                         = TRUE,
	.sched_groups_enabled                           = FALSE,
	.avoid_processor_enabled                        = FALSE,
	.thread_avoid_processor                         = NULL,
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
};

const struct sched_dispatch_table sched_traditional_with_pset_runqueue_dispatch = {
	.sched_name                                     = "traditional_with_pset_runqueue",
	.init                                           = sched_traditional_with_pset_runqueue_init,
	.timebase_init                                  = sched_timeshare_timebase_init,
	.processor_init                                 = sched_traditional_processor_init,
	.pset_init                                      = sched_traditional_pset_init,
	.maintenance_continuation                       = sched_timeshare_maintenance_continue,
	.choose_thread                                  = sched_traditional_choose_thread,
	.steal_thread_enabled                           = sched_steal_thread_enabled,
	.steal_thread                                   = sched_traditional_steal_thread,
	.compute_timeshare_priority                     = sched_compute_timeshare_priority,
	.choose_processor                               = choose_processor,
	.processor_enqueue                              = sched_traditional_processor_enqueue,
	.processor_queue_shutdown                       = sched_traditional_processor_queue_shutdown,
	.processor_queue_remove                         = sched_traditional_processor_queue_remove,
	.processor_queue_empty                          = sched_traditional_with_pset_runqueue_processor_queue_empty,
	.priority_is_urgent                             = priority_is_urgent,
	.processor_csw_check                            = sched_traditional_processor_csw_check,
	.processor_queue_has_priority                   = sched_traditional_processor_queue_has_priority,
	.initial_quantum_size                           = sched_timeshare_initial_quantum_size,
	.initial_thread_sched_mode                      = sched_traditional_initial_thread_sched_mode,
	.can_update_priority                            = can_update_priority,
	.update_priority                                = update_priority,
	.lightweight_update_priority                    = lightweight_update_priority,
	.quantum_expire                                 = sched_default_quantum_expire,
	.processor_runq_count                           = sched_traditional_processor_runq_count,
	.processor_runq_stats_count_sum                 = sched_traditional_with_pset_runqueue_processor_runq_stats_count_sum,
	.processor_bound_count                          = sched_traditional_processor_bound_count,
	.thread_update_scan                             = sched_traditional_thread_update_scan,
	.direct_dispatch_to_idle_processors             = FALSE,
	.multiple_psets_enabled                         = TRUE,
	.sched_groups_enabled                           = FALSE,
	.avoid_processor_enabled                        = FALSE,
	.thread_avoid_processor                         = NULL,
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
};

static void
sched_traditional_init(void)
{
	sched_timeshare_init();
}

static void
sched_traditional_with_pset_runqueue_init(void)
{
	sched_timeshare_init();
	sched_traditional_use_pset_runqueue = TRUE;
}

static void
sched_traditional_processor_init(processor_t processor)
{
	if (!sched_traditional_use_pset_runqueue) {
		run_queue_init(&processor->runq);
	}
	processor->runq_bound_count = 0;
}

static void
sched_traditional_pset_init(processor_set_t pset)
{
	if (sched_traditional_use_pset_runqueue) {
		run_queue_init(&pset->pset_runq);
	}
	pset->pset_runq_bound_count = 0;
}

__attribute__((always_inline))
static inline run_queue_t
runq_for_processor(processor_t processor)
{
	if (sched_traditional_use_pset_runqueue) {
		return &processor->processor_set->pset_runq;
	} else {
		return &processor->runq;
	}
}

__attribute__((always_inline))
static inline void
runq_consider_incr_bound_count(processor_t processor,
    thread_t thread)
{
	if (thread->bound_processor == PROCESSOR_NULL) {
		return;
	}

	assert(thread->bound_processor == processor);

	if (sched_traditional_use_pset_runqueue) {
		processor->processor_set->pset_runq_bound_count++;
	}

	processor->runq_bound_count++;
}

__attribute__((always_inline))
static inline void
runq_consider_decr_bound_count(processor_t processor,
    thread_t thread)
{
	if (thread->bound_processor == PROCESSOR_NULL) {
		return;
	}

	assert(thread->bound_processor == processor);

	if (sched_traditional_use_pset_runqueue) {
		processor->processor_set->pset_runq_bound_count--;
	}

	processor->runq_bound_count--;
}

static thread_t
sched_traditional_choose_thread(
	processor_t     processor,
	int             priority,
	__unused ast_t           reason)
{
	thread_t thread;

	thread = sched_traditional_choose_thread_from_runq(processor, runq_for_processor(processor), priority);
	if (thread != THREAD_NULL) {
		runq_consider_decr_bound_count(processor, thread);
	}

	return thread;
}

/*
 *	sched_traditional_choose_thread_from_runq:
 *
 *	Locate a thread to execute from the processor run queue
 *	and return it.  Only choose a thread with greater or equal
 *	priority.
 *
 *	Associated pset must be locked.  Returns THREAD_NULL
 *	on failure.
 */
static thread_t
sched_traditional_choose_thread_from_runq(
	processor_t     processor,
	run_queue_t     rq,
	int             priority)
{
	queue_t         queue   = rq->queues + rq->highq;
	int             pri     = rq->highq;
	int             count   = rq->count;
	thread_t        thread;

	while (count > 0 && pri >= priority) {
		thread = (thread_t)(uintptr_t)queue_first(queue);
		while (!queue_end(queue, (queue_entry_t)thread)) {
			if (thread->bound_processor == PROCESSOR_NULL ||
			    thread->bound_processor == processor) {
				remqueue((queue_entry_t)thread);

				thread->runq = PROCESSOR_NULL;
				SCHED_STATS_RUNQ_CHANGE(&rq->runq_stats, rq->count);
				rq->count--;
				if (SCHED(priority_is_urgent)(pri)) {
					rq->urgency--; assert(rq->urgency >= 0);
				}
				if (queue_empty(queue)) {
					bitmap_clear(rq->bitmap, pri);
					rq->highq = bitmap_first(rq->bitmap, NRQS);
				}

				return thread;
			}
			count--;

			thread = (thread_t)(uintptr_t)queue_next((queue_entry_t)thread);
		}

		queue--; pri--;
	}

	return THREAD_NULL;
}

static sched_mode_t
sched_traditional_initial_thread_sched_mode(task_t parent_task)
{
	if (parent_task == kernel_task) {
		return TH_MODE_FIXED;
	} else {
		return TH_MODE_TIMESHARE;
	}
}

/*
 *	sched_traditional_processor_enqueue:
 *
 *	Enqueue thread on a processor run queue.  Thread must be locked,
 *	and not already be on a run queue.
 *
 *	Returns TRUE if a preemption is indicated based on the state
 *	of the run queue.
 *
 *	The run queue must be locked (see thread_run_queue_remove()
 *	for more info).
 */
static boolean_t
sched_traditional_processor_enqueue(processor_t   processor,
    thread_t      thread,
    integer_t     options)
{
	run_queue_t     rq = runq_for_processor(processor);
	boolean_t       result;

	result = run_queue_enqueue(rq, thread, options);
	thread->runq = processor;
	runq_consider_incr_bound_count(processor, thread);

	return result;
}

static boolean_t
sched_traditional_processor_queue_empty(processor_t processor)
{
	return runq_for_processor(processor)->count == 0;
}

static boolean_t
sched_traditional_with_pset_runqueue_processor_queue_empty(processor_t processor)
{
	processor_set_t pset = processor->processor_set;
	int count = runq_for_processor(processor)->count;

	/*
	 * The pset runq contains the count of all runnable threads
	 * for all processors in the pset. However, for threads that
	 * are bound to another processor, the current "processor"
	 * is not eligible to execute the thread. So we only
	 * include bound threads that our bound to the current
	 * "processor". This allows the processor to idle when the
	 * count of eligible threads drops to 0, even if there's
	 * a runnable thread bound to a different processor in the
	 * shared runq.
	 */

	count -= pset->pset_runq_bound_count;
	count += processor->runq_bound_count;

	return count == 0;
}

static ast_t
sched_traditional_processor_csw_check(processor_t processor)
{
	run_queue_t     runq;
	boolean_t       has_higher;

	assert(processor->active_thread != NULL);

	runq = runq_for_processor(processor);

	if (processor->first_timeslice) {
		has_higher = (runq->highq > processor->current_pri);
	} else {
		has_higher = (runq->highq >= processor->current_pri);
	}

	if (has_higher) {
		if (runq->urgency > 0) {
			return AST_PREEMPT | AST_URGENT;
		}

		return AST_PREEMPT;
	}

	return AST_NONE;
}

static boolean_t
sched_traditional_processor_queue_has_priority(processor_t      processor,
    int              priority,
    boolean_t        gte)
{
	if (gte) {
		return runq_for_processor(processor)->highq >= priority;
	} else {
		return runq_for_processor(processor)->highq > priority;
	}
}

static int
sched_traditional_processor_runq_count(processor_t processor)
{
	return runq_for_processor(processor)->count;
}

static uint64_t
sched_traditional_processor_runq_stats_count_sum(processor_t processor)
{
	return runq_for_processor(processor)->runq_stats.count_sum;
}

static uint64_t
sched_traditional_with_pset_runqueue_processor_runq_stats_count_sum(processor_t processor)
{
	if (processor->cpu_id == processor->processor_set->cpu_set_low) {
		return runq_for_processor(processor)->runq_stats.count_sum;
	} else {
		return 0ULL;
	}
}

static int
sched_traditional_processor_bound_count(processor_t processor)
{
	return processor->runq_bound_count;
}

/*
 *	sched_traditional_processor_queue_shutdown:
 *
 *	Shutdown a processor run queue by
 *	re-dispatching non-bound threads.
 *
 *	Associated pset must be locked, and is
 *	returned unlocked.
 */
static void
sched_traditional_processor_queue_shutdown(processor_t processor)
{
	processor_set_t         pset    = processor->processor_set;
	run_queue_t             rq      = runq_for_processor(processor);
	queue_t                 queue   = rq->queues + rq->highq;
	int                     pri     = rq->highq;
	int                     count   = rq->count;
	thread_t                next, thread;
	queue_head_t            tqueue;

	queue_init(&tqueue);

	while (count > 0) {
		thread = (thread_t)(uintptr_t)queue_first(queue);
		while (!queue_end(queue, (queue_entry_t)thread)) {
			next = (thread_t)(uintptr_t)queue_next((queue_entry_t)thread);

			if (thread->bound_processor == PROCESSOR_NULL) {
				remqueue((queue_entry_t)thread);

				thread->runq = PROCESSOR_NULL;
				SCHED_STATS_RUNQ_CHANGE(&rq->runq_stats, rq->count);
				runq_consider_decr_bound_count(processor, thread);
				rq->count--;
				if (SCHED(priority_is_urgent)(pri)) {
					rq->urgency--; assert(rq->urgency >= 0);
				}
				if (queue_empty(queue)) {
					bitmap_clear(rq->bitmap, pri);
					rq->highq = bitmap_first(rq->bitmap, NRQS);
				}

				enqueue_tail(&tqueue, (queue_entry_t)thread);
			}
			count--;

			thread = next;
		}

		queue--; pri--;
	}

	pset_unlock(pset);

	while ((thread = (thread_t)(uintptr_t)dequeue_head(&tqueue)) != THREAD_NULL) {
		thread_lock(thread);

		thread_setrun(thread, SCHED_TAILQ);

		thread_unlock(thread);
	}
}

#if 0
static void
run_queue_check(
	run_queue_t     rq,
	thread_t        thread)
{
	queue_t         q;
	queue_entry_t   qe;

	if (rq != thread->runq) {
		panic("run_queue_check: thread runq");
	}

	if (thread->sched_pri > MAXPRI || thread->sched_pri < MINPRI) {
		panic("run_queue_check: thread sched_pri");
	}

	q = &rq->queues[thread->sched_pri];
	qe = queue_first(q);
	while (!queue_end(q, qe)) {
		if (qe == (queue_entry_t)thread) {
			return;
		}

		qe = queue_next(qe);
	}

	panic("run_queue_check: end");
}
#endif /* 0 */

/*
 * Locks the runqueue itself.
 *
 * Thread must be locked.
 */
static boolean_t
sched_traditional_processor_queue_remove(processor_t processor,
    thread_t thread)
{
	processor_set_t pset;
	run_queue_t     rq;

	pset = processor->processor_set;
	pset_lock(pset);

	rq = runq_for_processor(processor);

	if (processor == thread->runq) {
		/*
		 * Thread is on a run queue and we have a lock on
		 * that run queue.
		 */
		runq_consider_decr_bound_count(processor, thread);
		run_queue_remove(rq, thread);
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

/*
 *	sched_traditional_steal_processor_thread:
 *
 *	Locate a thread to steal from the processor and
 *	return it.
 *
 *	Associated pset must be locked.  Returns THREAD_NULL
 *	on failure.
 */
static thread_t
sched_traditional_steal_processor_thread(processor_t processor)
{
	run_queue_t     rq      = runq_for_processor(processor);
	queue_t         queue   = rq->queues + rq->highq;
	int             pri     = rq->highq;
	int             count   = rq->count;
	thread_t        thread;

	while (count > 0) {
		thread = (thread_t)(uintptr_t)queue_first(queue);
		while (!queue_end(queue, (queue_entry_t)thread)) {
			if (thread->bound_processor == PROCESSOR_NULL) {
				remqueue((queue_entry_t)thread);

				thread->runq = PROCESSOR_NULL;
				SCHED_STATS_RUNQ_CHANGE(&rq->runq_stats, rq->count);
				runq_consider_decr_bound_count(processor, thread);
				rq->count--;
				if (SCHED(priority_is_urgent)(pri)) {
					rq->urgency--; assert(rq->urgency >= 0);
				}
				if (queue_empty(queue)) {
					bitmap_clear(rq->bitmap, pri);
					rq->highq = bitmap_first(rq->bitmap, NRQS);
				}

				return thread;
			}
			count--;

			thread = (thread_t)(uintptr_t)queue_next((queue_entry_t)thread);
		}

		queue--; pri--;
	}

	return THREAD_NULL;
}

static bool
sched_traditional_steal_thread_enabled(processor_set_t pset)
{
	(void)pset;
	return true;
}

/*
 *	Locate and steal a thread, beginning
 *	at the pset.
 *
 *	The pset must be locked, and is returned
 *	unlocked.
 *
 *	Returns the stolen thread, or THREAD_NULL on
 *	failure.
 */
static thread_t
sched_traditional_steal_thread(processor_set_t pset)
{
	processor_set_t nset, cset = pset;
	processor_t     processor;
	thread_t        thread;

	do {
		uint64_t active_map = (pset->cpu_state_map[PROCESSOR_RUNNING] |
		    pset->cpu_state_map[PROCESSOR_DISPATCHING]);
		for (int cpuid = lsb_first(active_map); cpuid >= 0; cpuid = lsb_next(active_map, cpuid)) {
			processor = processor_array[cpuid];
			if (runq_for_processor(processor)->count > 0) {
				thread = sched_traditional_steal_processor_thread(processor);
				if (thread != THREAD_NULL) {
					pset_unlock(cset);

					return thread;
				}
			}
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
sched_traditional_thread_update_scan(sched_update_scan_context_t scan_context)
{
	boolean_t       restart_needed = FALSE;
	processor_t     processor = processor_list;
	processor_set_t pset;
	thread_t        thread;
	spl_t           s;

	do {
		do {
			/*
			 * TODO: in sched_traditional_use_pset_runqueue case,
			 *  avoid scanning the same runq multiple times
			 */
			pset = processor->processor_set;

			s = splsched();
			pset_lock(pset);

			restart_needed = runq_scan(runq_for_processor(processor), scan_context);

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
}

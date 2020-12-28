/*
 * Copyright (c) 2013 Apple Inc. All rights reserved.
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

#include <sys/kdebug.h>

static void
sched_dualq_init(void);

static thread_t
sched_dualq_steal_thread(processor_set_t pset);

static void
sched_dualq_thread_update_scan(sched_update_scan_context_t scan_context);

static boolean_t
sched_dualq_processor_enqueue(processor_t processor, thread_t thread,
    sched_options_t options);

static boolean_t
sched_dualq_processor_queue_remove(processor_t processor, thread_t thread);

static ast_t
sched_dualq_processor_csw_check(processor_t processor);

static boolean_t
sched_dualq_processor_queue_has_priority(processor_t processor, int priority, boolean_t gte);

static int
sched_dualq_runq_count(processor_t processor);

static boolean_t
sched_dualq_processor_queue_empty(processor_t processor);

static uint64_t
sched_dualq_runq_stats_count_sum(processor_t processor);

static int
sched_dualq_processor_bound_count(processor_t processor);

static void
sched_dualq_pset_init(processor_set_t pset);

static void
sched_dualq_processor_init(processor_t processor);

static thread_t
sched_dualq_choose_thread(processor_t processor, int priority, ast_t reason);

static void
sched_dualq_processor_queue_shutdown(processor_t processor);

static sched_mode_t
sched_dualq_initial_thread_sched_mode(task_t parent_task);

static bool
sched_dualq_thread_avoid_processor(processor_t processor, thread_t thread);

const struct sched_dispatch_table sched_dualq_dispatch = {
	.sched_name                                     = "dualq",
	.init                                           = sched_dualq_init,
	.timebase_init                                  = sched_timeshare_timebase_init,
	.processor_init                                 = sched_dualq_processor_init,
	.pset_init                                      = sched_dualq_pset_init,
	.maintenance_continuation                       = sched_timeshare_maintenance_continue,
	.choose_thread                                  = sched_dualq_choose_thread,
	.steal_thread_enabled                           = sched_steal_thread_enabled,
	.steal_thread                                   = sched_dualq_steal_thread,
	.compute_timeshare_priority                     = sched_compute_timeshare_priority,
	.choose_processor                               = choose_processor,
	.processor_enqueue                              = sched_dualq_processor_enqueue,
	.processor_queue_shutdown                       = sched_dualq_processor_queue_shutdown,
	.processor_queue_remove                         = sched_dualq_processor_queue_remove,
	.processor_queue_empty                          = sched_dualq_processor_queue_empty,
	.priority_is_urgent                             = priority_is_urgent,
	.processor_csw_check                            = sched_dualq_processor_csw_check,
	.processor_queue_has_priority                   = sched_dualq_processor_queue_has_priority,
	.initial_quantum_size                           = sched_timeshare_initial_quantum_size,
	.initial_thread_sched_mode                      = sched_dualq_initial_thread_sched_mode,
	.can_update_priority                            = can_update_priority,
	.update_priority                                = update_priority,
	.lightweight_update_priority                    = lightweight_update_priority,
	.quantum_expire                                 = sched_default_quantum_expire,
	.processor_runq_count                           = sched_dualq_runq_count,
	.processor_runq_stats_count_sum                 = sched_dualq_runq_stats_count_sum,
	.processor_bound_count                          = sched_dualq_processor_bound_count,
	.thread_update_scan                             = sched_dualq_thread_update_scan,
	.multiple_psets_enabled                         = TRUE,
	.sched_groups_enabled                           = FALSE,
	.avoid_processor_enabled                        = TRUE,
	.thread_avoid_processor                         = sched_dualq_thread_avoid_processor,
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
	.run_count_incr                                 = sched_run_incr,
	.run_count_decr                                 = sched_run_decr,
	.update_thread_bucket                           = sched_update_thread_bucket,
	.pset_made_schedulable                          = sched_pset_made_schedulable,
};

__attribute__((always_inline))
static inline run_queue_t
dualq_main_runq(processor_t processor)
{
	return &processor->processor_set->pset_runq;
}

__attribute__((always_inline))
static inline run_queue_t
dualq_bound_runq(processor_t processor)
{
	return &processor->runq;
}

__attribute__((always_inline))
static inline run_queue_t
dualq_runq_for_thread(processor_t processor, thread_t thread)
{
	if (thread->bound_processor == PROCESSOR_NULL) {
		return dualq_main_runq(processor);
	} else {
		assert(thread->bound_processor == processor);
		return dualq_bound_runq(processor);
	}
}

static sched_mode_t
sched_dualq_initial_thread_sched_mode(task_t parent_task)
{
	if (parent_task == kernel_task) {
		return TH_MODE_FIXED;
	} else {
		return TH_MODE_TIMESHARE;
	}
}

static void
sched_dualq_processor_init(processor_t processor)
{
	run_queue_init(&processor->runq);
}

static void
sched_dualq_pset_init(processor_set_t pset)
{
	run_queue_init(&pset->pset_runq);
}

extern int sched_allow_NO_SMT_threads;
static void
sched_dualq_init(void)
{
	sched_timeshare_init();

	if (PE_parse_boot_argn("disable_NO_SMT_threads", NULL, 0)) {
		sched_allow_NO_SMT_threads = 0;
	}
}

static thread_t
sched_dualq_choose_thread(
	processor_t      processor,
	int              priority,
	__unused ast_t            reason)
{
	run_queue_t main_runq  = dualq_main_runq(processor);
	run_queue_t bound_runq = dualq_bound_runq(processor);
	run_queue_t chosen_runq;

	if (bound_runq->highq < priority &&
	    main_runq->highq < priority) {
		return THREAD_NULL;
	}

	if (bound_runq->count && main_runq->count) {
		if (bound_runq->highq >= main_runq->highq) {
			chosen_runq = bound_runq;
		} else {
			chosen_runq = main_runq;
		}
	} else if (bound_runq->count) {
		chosen_runq = bound_runq;
	} else if (main_runq->count) {
		chosen_runq = main_runq;
	} else {
		return THREAD_NULL;
	}

	if (chosen_runq == bound_runq) {
		return run_queue_dequeue(chosen_runq, SCHED_HEADQ);
	}

	if (processor->is_SMT) {
		thread_t potential_thread = run_queue_peek(chosen_runq);
		if (potential_thread == THREAD_NULL) {
			return THREAD_NULL;
		}
		if (processor->processor_primary != processor) {
			/*
			 * Secondary processor may not run a NO_SMT thread,
			 * nor any thread if the primary is running a NO_SMT thread.
			 */
			if (thread_no_smt(potential_thread)) {
				processor->must_idle = true;
				return THREAD_NULL;
			}
			processor_t primary = processor->processor_primary;
			if (primary->state == PROCESSOR_RUNNING) {
				if (processor_active_thread_no_smt(primary)) {
					processor->must_idle = true;
					return THREAD_NULL;
				}
			}
		} else if (processor->processor_secondary != PROCESSOR_NULL) {
			processor_t secondary = processor->processor_secondary;
			/*
			 * Primary processor may not run a NO_SMT thread if
			 * its secondary is running a bound thread.
			 */
			if (secondary->state == PROCESSOR_RUNNING) {
				if (thread_no_smt(potential_thread) && secondary->current_is_bound) {
					processor->must_idle = true;
					return THREAD_NULL;
				}
			}
		}
	}

	return run_queue_dequeue(chosen_runq, SCHED_HEADQ);
}

static boolean_t
sched_dualq_processor_enqueue(
	processor_t       processor,
	thread_t          thread,
	sched_options_t   options)
{
	run_queue_t     rq = dualq_runq_for_thread(processor, thread);
	boolean_t       result;

	result = run_queue_enqueue(rq, thread, options);
	thread->runq = processor;

	return result;
}

static boolean_t
sched_dualq_processor_queue_empty(processor_t processor)
{
	return dualq_main_runq(processor)->count == 0 &&
	       dualq_bound_runq(processor)->count == 0;
}

static ast_t
sched_dualq_processor_csw_check(processor_t processor)
{
	boolean_t       has_higher;
	int             pri;

	if (sched_dualq_thread_avoid_processor(processor, current_thread())) {
		return AST_PREEMPT | AST_URGENT;
	}

	run_queue_t main_runq  = dualq_main_runq(processor);
	run_queue_t bound_runq = dualq_bound_runq(processor);

	assert(processor->active_thread != NULL);

	pri = MAX(main_runq->highq, bound_runq->highq);

	if (processor->first_timeslice) {
		has_higher = (pri > processor->current_pri);
	} else {
		has_higher = (pri >= processor->current_pri);
	}

	if (has_higher) {
		if (main_runq->urgency > 0) {
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
sched_dualq_processor_queue_has_priority(processor_t    processor,
    int            priority,
    boolean_t      gte)
{
	run_queue_t main_runq  = dualq_main_runq(processor);
	run_queue_t bound_runq = dualq_bound_runq(processor);

	int qpri = MAX(main_runq->highq, bound_runq->highq);

	if (gte) {
		return qpri >= priority;
	} else {
		return qpri > priority;
	}
}

static int
sched_dualq_runq_count(processor_t processor)
{
	return dualq_main_runq(processor)->count + dualq_bound_runq(processor)->count;
}

static uint64_t
sched_dualq_runq_stats_count_sum(processor_t processor)
{
	uint64_t bound_sum = dualq_bound_runq(processor)->runq_stats.count_sum;

	if (processor->cpu_id == processor->processor_set->cpu_set_low) {
		return bound_sum + dualq_main_runq(processor)->runq_stats.count_sum;
	} else {
		return bound_sum;
	}
}
static int
sched_dualq_processor_bound_count(processor_t processor)
{
	return dualq_bound_runq(processor)->count;
}

static void
sched_dualq_processor_queue_shutdown(processor_t processor)
{
	processor_set_t pset = processor->processor_set;
	run_queue_t     rq   = dualq_main_runq(processor);
	thread_t        thread;
	queue_head_t    tqueue;

	/* We only need to migrate threads if this is the last active processor in the pset */
	if (pset->online_processor_count > 0) {
		pset_unlock(pset);
		return;
	}

	queue_init(&tqueue);

	while (rq->count > 0) {
		thread = run_queue_dequeue(rq, SCHED_HEADQ);
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
sched_dualq_processor_queue_remove(
	processor_t processor,
	thread_t    thread)
{
	run_queue_t             rq;
	processor_set_t         pset = processor->processor_set;

	pset_lock(pset);

	rq = dualq_runq_for_thread(processor, thread);

	if (processor == thread->runq) {
		/*
		 * Thread is on a run queue and we have a lock on
		 * that run queue.
		 */
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

static thread_t
sched_dualq_steal_thread(processor_set_t pset)
{
	processor_set_t cset = pset;
	processor_set_t nset = next_pset(cset);
	thread_t        thread;

	while (nset != pset) {
		pset_unlock(cset);
		cset = nset;
		pset_lock(cset);

		if (cset->pset_runq.count > 0) {
			/* Need task_restrict logic here */
			thread = run_queue_dequeue(&cset->pset_runq, SCHED_HEADQ);
			pset_unlock(cset);
			return thread;
		}

		nset = next_pset(cset);
	}

	pset_unlock(cset);

	return THREAD_NULL;
}

static void
sched_dualq_thread_update_scan(sched_update_scan_context_t scan_context)
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

			restart_needed = runq_scan(dualq_bound_runq(processor), scan_context);

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

			restart_needed = runq_scan(&pset->pset_runq, scan_context);

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
sched_dualq_thread_avoid_processor(processor_t processor, thread_t thread)
{
	if (thread->bound_processor == processor) {
		/* Thread is bound here */
		return false;
	}

	if (processor->processor_primary != processor) {
		/*
		 * This is a secondary SMT processor.  If the primary is running
		 * a realtime thread, only allow realtime threads on the secondary.
		 */
		processor_t primary = processor->processor_primary;
		if ((primary->current_pri >= BASEPRI_RTQUEUES) && ((thread->sched_pri < BASEPRI_RTQUEUES) || !sched_allow_rt_smt)) {
			return true;
		}

		/* NO_SMT threads are not allowed on secondary processors */
		if (thread_no_smt(thread)) {
			return true;
		}

		if (primary->state == PROCESSOR_RUNNING) {
			if (processor_active_thread_no_smt(primary)) {
				/* No threads allowed on secondary if primary has NO_SMT */
				return true;
			}
		}
	}

	if (processor->processor_secondary != PROCESSOR_NULL) {
		/*
		 * This is a primary SMT processor.  If the secondary is running
		 * a bound thread, the primary may not run a NO_SMT thread.
		 */
		processor_t secondary = processor->processor_secondary;

		if (secondary->state == PROCESSOR_RUNNING) {
			if (secondary->current_is_bound && thread_no_smt(thread)) {
				return true;
			}
		}
	}

	return false;
}

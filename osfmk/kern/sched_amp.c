/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
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
#include <kern/thread_group.h>
#include <kern/sched_amp_common.h>

#include <sys/kdebug.h>

#if __AMP__

static thread_t
sched_amp_steal_thread(processor_set_t pset);

static void
sched_amp_thread_update_scan(sched_update_scan_context_t scan_context);

static boolean_t
sched_amp_processor_enqueue(processor_t processor, thread_t thread,
    sched_options_t options);

static boolean_t
sched_amp_processor_queue_remove(processor_t processor, thread_t thread);

static ast_t
sched_amp_processor_csw_check(processor_t processor);

static boolean_t
sched_amp_processor_queue_has_priority(processor_t processor, int priority, boolean_t gte);

static int
sched_amp_runq_count(processor_t processor);

static boolean_t
sched_amp_processor_queue_empty(processor_t processor);

static uint64_t
sched_amp_runq_stats_count_sum(processor_t processor);

static int
sched_amp_processor_bound_count(processor_t processor);

static void
sched_amp_pset_init(processor_set_t pset);

static void
sched_amp_processor_init(processor_t processor);

static thread_t
sched_amp_choose_thread(processor_t processor, int priority, ast_t reason);

static void
sched_amp_processor_queue_shutdown(processor_t processor);

static sched_mode_t
sched_amp_initial_thread_sched_mode(task_t parent_task);

static processor_t
sched_amp_choose_processor(processor_set_t pset, processor_t processor, thread_t thread);

static bool
sched_amp_thread_avoid_processor(processor_t processor, thread_t thread);

static bool
sched_amp_thread_should_yield(processor_t processor, thread_t thread);

static void
sched_amp_thread_group_recommendation_change(struct thread_group *tg, cluster_type_t new_recommendation);

const struct sched_dispatch_table sched_amp_dispatch = {
	.sched_name                                     = "amp",
	.init                                           = sched_amp_init,
	.timebase_init                                  = sched_timeshare_timebase_init,
	.processor_init                                 = sched_amp_processor_init,
	.pset_init                                      = sched_amp_pset_init,
	.maintenance_continuation                       = sched_timeshare_maintenance_continue,
	.choose_thread                                  = sched_amp_choose_thread,
	.steal_thread_enabled                           = sched_amp_steal_thread_enabled,
	.steal_thread                                   = sched_amp_steal_thread,
	.compute_timeshare_priority                     = sched_compute_timeshare_priority,
	.choose_processor                               = sched_amp_choose_processor,
	.processor_enqueue                              = sched_amp_processor_enqueue,
	.processor_queue_shutdown                       = sched_amp_processor_queue_shutdown,
	.processor_queue_remove                         = sched_amp_processor_queue_remove,
	.processor_queue_empty                          = sched_amp_processor_queue_empty,
	.priority_is_urgent                             = priority_is_urgent,
	.processor_csw_check                            = sched_amp_processor_csw_check,
	.processor_queue_has_priority                   = sched_amp_processor_queue_has_priority,
	.initial_quantum_size                           = sched_timeshare_initial_quantum_size,
	.initial_thread_sched_mode                      = sched_amp_initial_thread_sched_mode,
	.can_update_priority                            = can_update_priority,
	.update_priority                                = update_priority,
	.lightweight_update_priority                    = lightweight_update_priority,
	.quantum_expire                                 = sched_default_quantum_expire,
	.processor_runq_count                           = sched_amp_runq_count,
	.processor_runq_stats_count_sum                 = sched_amp_runq_stats_count_sum,
	.processor_bound_count                          = sched_amp_processor_bound_count,
	.thread_update_scan                             = sched_amp_thread_update_scan,
	.multiple_psets_enabled                         = TRUE,
	.sched_groups_enabled                           = FALSE,
	.avoid_processor_enabled                        = TRUE,
	.thread_avoid_processor                         = sched_amp_thread_avoid_processor,
	.processor_balance                              = sched_amp_balance,

	.rt_runq                                        = sched_amp_rt_runq,
	.rt_init                                        = sched_amp_rt_init,
	.rt_queue_shutdown                              = sched_amp_rt_queue_shutdown,
	.rt_runq_scan                                   = sched_amp_rt_runq_scan,
	.rt_runq_count_sum                              = sched_amp_rt_runq_count_sum,

	.qos_max_parallelism                            = sched_amp_qos_max_parallelism,
	.check_spill                                    = sched_amp_check_spill,
	.ipi_policy                                     = sched_amp_ipi_policy,
	.thread_should_yield                            = sched_amp_thread_should_yield,
	.run_count_incr                                 = sched_run_incr,
	.run_count_decr                                 = sched_run_decr,
	.update_thread_bucket                           = sched_update_thread_bucket,
	.pset_made_schedulable                          = sched_pset_made_schedulable,
	.thread_group_recommendation_change             = sched_amp_thread_group_recommendation_change,
};

extern processor_set_t ecore_set;
extern processor_set_t pcore_set;

__attribute__((always_inline))
static inline run_queue_t
amp_main_runq(processor_t processor)
{
	return &processor->processor_set->pset_runq;
}

__attribute__((always_inline))
static inline run_queue_t
amp_bound_runq(processor_t processor)
{
	return &processor->runq;
}

__attribute__((always_inline))
static inline run_queue_t
amp_runq_for_thread(processor_t processor, thread_t thread)
{
	if (thread->bound_processor == PROCESSOR_NULL) {
		return amp_main_runq(processor);
	} else {
		assert(thread->bound_processor == processor);
		return amp_bound_runq(processor);
	}
}

static sched_mode_t
sched_amp_initial_thread_sched_mode(task_t parent_task)
{
	if (parent_task == kernel_task) {
		return TH_MODE_FIXED;
	} else {
		return TH_MODE_TIMESHARE;
	}
}

static void
sched_amp_processor_init(processor_t processor)
{
	run_queue_init(&processor->runq);
}

static void
sched_amp_pset_init(processor_set_t pset)
{
	run_queue_init(&pset->pset_runq);
}

static thread_t
sched_amp_choose_thread(
	processor_t      processor,
	int              priority,
	__unused ast_t            reason)
{
	processor_set_t pset = processor->processor_set;
	bool spill_pending = false;
	int spill_pri = -1;

	if (pset == ecore_set && bit_test(pset->pending_spill_cpu_mask, processor->cpu_id)) {
		spill_pending = true;
		spill_pri = pcore_set->pset_runq.highq;
	}

	run_queue_t main_runq  = amp_main_runq(processor);
	run_queue_t bound_runq = amp_bound_runq(processor);
	run_queue_t chosen_runq;

	if ((bound_runq->highq < priority) &&
	    (main_runq->highq < priority) &&
	    (spill_pri < priority)) {
		return THREAD_NULL;
	}

	if ((spill_pri > bound_runq->highq) &&
	    (spill_pri > main_runq->highq)) {
		/*
		 * There is a higher priority thread on the P-core runq,
		 * so returning THREAD_NULL here will cause thread_select()
		 * to call sched_amp_steal_thread() to try to get it.
		 */
		return THREAD_NULL;
	}

	if (bound_runq->highq >= main_runq->highq) {
		chosen_runq = bound_runq;
	} else {
		chosen_runq = main_runq;
	}

	return run_queue_dequeue(chosen_runq, SCHED_HEADQ);
}

static boolean_t
sched_amp_processor_enqueue(
	processor_t       processor,
	thread_t          thread,
	sched_options_t   options)
{
	run_queue_t     rq = amp_runq_for_thread(processor, thread);
	boolean_t       result;

	result = run_queue_enqueue(rq, thread, options);
	thread->runq = processor;

	return result;
}

static boolean_t
sched_amp_processor_queue_empty(processor_t processor)
{
	processor_set_t pset = processor->processor_set;
	bool spill_pending = bit_test(pset->pending_spill_cpu_mask, processor->cpu_id);

	return (amp_main_runq(processor)->count == 0) &&
	       (amp_bound_runq(processor)->count == 0) &&
	       !spill_pending;
}

static bool
sched_amp_thread_should_yield(processor_t processor, thread_t thread)
{
	if (!sched_amp_processor_queue_empty(processor) || (rt_runq_count(processor->processor_set) > 0)) {
		return true;
	}

	if ((processor->processor_set->pset_cluster_type == PSET_AMP_E) && (recommended_pset_type(thread) == PSET_AMP_P)) {
		return pcore_set->pset_runq.count > 0;
	}

	return false;
}

static ast_t
sched_amp_processor_csw_check(processor_t processor)
{
	boolean_t       has_higher;
	int             pri;

	run_queue_t main_runq  = amp_main_runq(processor);
	run_queue_t bound_runq = amp_bound_runq(processor);

	assert(processor->active_thread != NULL);

	processor_set_t pset = processor->processor_set;
	bool spill_pending = false;
	int spill_pri = -1;
	int spill_urgency = 0;

	if (pset == ecore_set && bit_test(pset->pending_spill_cpu_mask, processor->cpu_id)) {
		spill_pending = true;
		spill_pri = pcore_set->pset_runq.highq;
		spill_urgency = pcore_set->pset_runq.urgency;
	}

	pri = MAX(main_runq->highq, bound_runq->highq);
	if (spill_pending) {
		pri = MAX(pri, spill_pri);
	}

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

		if (spill_urgency > 0) {
			return AST_PREEMPT | AST_URGENT;
		}

		return AST_PREEMPT;
	}

	return AST_NONE;
}

static boolean_t
sched_amp_processor_queue_has_priority(processor_t    processor,
    int            priority,
    boolean_t      gte)
{
	bool spill_pending = false;
	int spill_pri = -1;
	processor_set_t pset = processor->processor_set;

	if (pset == ecore_set && bit_test(pset->pending_spill_cpu_mask, processor->cpu_id)) {
		spill_pending = true;
		spill_pri = pcore_set->pset_runq.highq;
	}
	run_queue_t main_runq  = amp_main_runq(processor);
	run_queue_t bound_runq = amp_bound_runq(processor);

	int qpri = MAX(main_runq->highq, bound_runq->highq);
	if (spill_pending) {
		qpri = MAX(qpri, spill_pri);
	}

	if (gte) {
		return qpri >= priority;
	} else {
		return qpri > priority;
	}
}

static int
sched_amp_runq_count(processor_t processor)
{
	return amp_main_runq(processor)->count + amp_bound_runq(processor)->count;
}

static uint64_t
sched_amp_runq_stats_count_sum(processor_t processor)
{
	uint64_t bound_sum = amp_bound_runq(processor)->runq_stats.count_sum;

	if (processor->cpu_id == processor->processor_set->cpu_set_low) {
		return bound_sum + amp_main_runq(processor)->runq_stats.count_sum;
	} else {
		return bound_sum;
	}
}
static int
sched_amp_processor_bound_count(processor_t processor)
{
	return amp_bound_runq(processor)->count;
}

static void
sched_amp_processor_queue_shutdown(processor_t processor)
{
	processor_set_t pset = processor->processor_set;
	run_queue_t     rq   = amp_main_runq(processor);
	thread_t        thread;
	queue_head_t    tqueue;

	/* We only need to migrate threads if this is the last active or last recommended processor in the pset */
	if ((pset->online_processor_count > 0) && pset_is_recommended(pset)) {
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
sched_amp_processor_queue_remove(
	processor_t processor,
	thread_t    thread)
{
	run_queue_t             rq;
	processor_set_t         pset = processor->processor_set;

	pset_lock(pset);

	rq = amp_runq_for_thread(processor, thread);

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

/*
 * sched_amp_steal_thread()
 *
 */
thread_t
sched_amp_steal_thread(processor_set_t pset)
{
	thread_t thread = THREAD_NULL;
	processor_set_t nset = pset;

	assert(pset->pset_cluster_type != PSET_AMP_P);

	processor_t processor = current_processor();
	assert(pset == processor->processor_set);

	bool spill_pending = bit_test(pset->pending_spill_cpu_mask, processor->cpu_id);
	bit_clear(pset->pending_spill_cpu_mask, processor->cpu_id);

	nset = pcore_set;

	assert(nset != pset);

	if (sched_get_pset_load_average(nset) >= sched_amp_steal_threshold(nset, spill_pending)) {
		pset_unlock(pset);

		pset = nset;

		pset_lock(pset);

		/* Allow steal if load average still OK, no idle cores, and more threads on runq than active cores DISPATCHING */
		if ((sched_get_pset_load_average(pset) >= sched_amp_steal_threshold(pset, spill_pending)) &&
		    (pset->pset_runq.count > bit_count(pset->cpu_state_map[PROCESSOR_DISPATCHING])) &&
		    (bit_count(pset->recommended_bitmask & pset->cpu_state_map[PROCESSOR_IDLE]) == 0)) {
			thread = run_queue_dequeue(&pset->pset_runq, SCHED_HEADQ);
			KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_AMP_STEAL) | DBG_FUNC_NONE, spill_pending, 0, 0, 0);
			sched_update_pset_load_average(pset);
		}
	}

	pset_unlock(pset);
	return thread;
}



static void
sched_amp_thread_update_scan(sched_update_scan_context_t scan_context)
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

			restart_needed = runq_scan(amp_bound_runq(processor), scan_context);

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

				restart_needed = runq_scan(&pset->pset_runq, scan_context);

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

static bool
pcores_recommended(thread_t thread)
{
	if (pcore_set->online_processor_count == 0) {
		/* No pcores available */
		return false;
	}

	if (!pset_is_recommended(ecore_set)) {
		/* No E cores recommended, must use P cores */
		return true;
	}

	if (recommended_pset_type(thread) == PSET_AMP_E) {
		return false;
	}

	return pset_is_recommended(pcore_set);
}

/* Return true if this thread should not continue running on this processor */
static bool
sched_amp_thread_avoid_processor(processor_t processor, thread_t thread)
{
	if (processor->processor_set->pset_cluster_type == PSET_AMP_E) {
		if (pcores_recommended(thread)) {
			return true;
		}
	} else if (processor->processor_set->pset_cluster_type == PSET_AMP_P) {
		if (!pcores_recommended(thread)) {
			return true;
		}
	}

	return false;
}

static processor_t
sched_amp_choose_processor(processor_set_t pset, processor_t processor, thread_t thread)
{
	/* Bound threads don't call this function */
	assert(thread->bound_processor == PROCESSOR_NULL);

	processor_set_t nset = pset;
	bool choose_pcores;

again:
	choose_pcores = pcores_recommended(thread);

	if (choose_pcores && (pset->pset_cluster_type != PSET_AMP_P)) {
		nset = pcore_set;
		assert(nset != NULL);
	} else if (!choose_pcores && (pset->pset_cluster_type != PSET_AMP_E)) {
		nset = ecore_set;
		assert(nset != NULL);
	}

	if (nset != pset) {
		pset_unlock(pset);
		pset_lock(nset);
	}

	/* Now that the chosen pset is definitely locked, make sure nothing important has changed */
	if (!pset_is_recommended(nset)) {
		pset = nset;
		goto again;
	}

	return choose_processor(nset, processor, thread);
}

void
sched_amp_thread_group_recommendation_change(struct thread_group *tg, cluster_type_t new_recommendation)
{
	thread_group_update_recommendation(tg, new_recommendation);

	if (new_recommendation != CLUSTER_TYPE_P) {
		return;
	}

	sched_amp_bounce_thread_group_from_ecores(ecore_set, tg);
}

#if DEVELOPMENT || DEBUG
extern int32_t sysctl_get_bound_cpuid(void);
int32_t
sysctl_get_bound_cpuid(void)
{
	int32_t cpuid = -1;
	thread_t self = current_thread();

	processor_t processor = self->bound_processor;
	if (processor == NULL) {
		cpuid = -1;
	} else {
		cpuid = processor->cpu_id;
	}

	return cpuid;
}

extern void sysctl_thread_bind_cpuid(int32_t cpuid);
void
sysctl_thread_bind_cpuid(int32_t cpuid)
{
	if (cpuid < 0 || cpuid >= MAX_SCHED_CPUS) {
		return;
	}

	processor_t processor = processor_array[cpuid];
	if (processor == PROCESSOR_NULL) {
		return;
	}

	thread_bind(processor);

	thread_block(THREAD_CONTINUE_NULL);
}

extern char sysctl_get_bound_cluster_type(void);
char
sysctl_get_bound_cluster_type(void)
{
	thread_t self = current_thread();

	if (self->sched_flags & TH_SFLAG_ECORE_ONLY) {
		return 'E';
	} else if (self->sched_flags & TH_SFLAG_PCORE_ONLY) {
		return 'P';
	}

	return '0';
}

extern void sysctl_thread_bind_cluster_type(char cluster_type);
void
sysctl_thread_bind_cluster_type(char cluster_type)
{
	thread_bind_cluster_type(cluster_type);
}

extern char sysctl_get_task_cluster_type(void);
char
sysctl_get_task_cluster_type(void)
{
	thread_t thread = current_thread();
	task_t task = thread->task;

	if (task->pset_hint == ecore_set) {
		return 'E';
	} else if (task->pset_hint == pcore_set) {
		return 'P';
	}

	return '0';
}

extern void sysctl_task_set_cluster_type(char cluster_type);
void
sysctl_task_set_cluster_type(char cluster_type)
{
	thread_t thread = current_thread();
	task_t task = thread->task;

	switch (cluster_type) {
	case 'e':
	case 'E':
		task->pset_hint = ecore_set;
		break;
	case 'p':
	case 'P':
		task->pset_hint = pcore_set;
		break;
	default:
		break;
	}

	thread_block(THREAD_CONTINUE_NULL);
}
#endif

#endif

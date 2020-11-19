/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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
#include <machine/atomic.h>
#include <sys/kdebug.h>
#include <kern/sched_amp_common.h>
#include <stdatomic.h>

#if __AMP__

/* Exported globals */
processor_set_t ecore_set = NULL;
processor_set_t pcore_set = NULL;

static struct processor_set pset1;
static struct pset_node pset_node1;

#if DEVELOPMENT || DEBUG
bool system_ecore_only = false;
#endif /* DEVELOPMENT || DEBUG */

/*
 * sched_amp_init()
 *
 * Initialize the pcore_set and ecore_set globals which describe the
 * P/E processor sets.
 */
void
sched_amp_init(void)
{
	pset_init(&pset1, &pset_node1);
	pset_node1.psets = &pset1;
	pset_node0.node_list = &pset_node1;

	if (ml_get_boot_cluster() == CLUSTER_TYPE_P) {
		pcore_set = &pset0;
		ecore_set = &pset1;
	} else {
		ecore_set = &pset0;
		pcore_set = &pset1;
	}

	ecore_set->pset_cluster_type = PSET_AMP_E;
	ecore_set->pset_cluster_id = 0;

	pcore_set->pset_cluster_type = PSET_AMP_P;
	pcore_set->pset_cluster_id = 1;

#if DEVELOPMENT || DEBUG
	if (PE_parse_boot_argn("enable_skstsct", NULL, 0)) {
		system_ecore_only = true;
	}
#endif /* DEVELOPMENT || DEBUG */

	sched_timeshare_init();
}

/* Spill threshold load average is ncpus in pset + (sched_amp_spill_count/(1 << PSET_LOAD_FRACTIONAL_SHIFT) */
int sched_amp_spill_count = 3;
int sched_amp_idle_steal = 1;
int sched_amp_spill_steal = 1;

/*
 * We see performance gains from doing immediate IPIs to P-cores to run
 * P-eligible threads and lesser P-E migrations from using deferred IPIs
 * for spill.
 */
int sched_amp_spill_deferred_ipi = 1;
int sched_amp_pcores_preempt_immediate_ipi = 1;

/*
 * sched_perfcontrol_inherit_recommendation_from_tg changes amp
 * scheduling policy away from default and allows policy to be
 * modified at run-time.
 *
 * once modified from default, the policy toggles between "follow
 * thread group" and "restrict to e".
 */

_Atomic sched_perfctl_class_policy_t sched_perfctl_policy_util = SCHED_PERFCTL_POLICY_DEFAULT;
_Atomic sched_perfctl_class_policy_t sched_perfctl_policy_bg = SCHED_PERFCTL_POLICY_DEFAULT;

/*
 * sched_amp_spill_threshold()
 *
 * Routine to calulate spill threshold which decides if cluster should spill.
 */
int
sched_amp_spill_threshold(processor_set_t pset)
{
	int recommended_processor_count = bit_count(pset->recommended_bitmask & pset->cpu_bitmask);

	return (recommended_processor_count << PSET_LOAD_FRACTIONAL_SHIFT) + sched_amp_spill_count;
}

/*
 * pset_signal_spill()
 *
 * Routine to signal a running/idle CPU to cause a spill onto that CPU.
 * Called with pset locked, returns unlocked
 */
void
pset_signal_spill(processor_set_t pset, int spilled_thread_priority)
{
	processor_t processor;
	sched_ipi_type_t ipi_type = SCHED_IPI_NONE;

	uint64_t idle_map = pset->recommended_bitmask & pset->cpu_state_map[PROCESSOR_IDLE];
	for (int cpuid = lsb_first(idle_map); cpuid >= 0; cpuid = lsb_next(idle_map, cpuid)) {
		processor = processor_array[cpuid];
		if (bit_set_if_clear(pset->pending_spill_cpu_mask, processor->cpu_id)) {
			KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_AMP_SIGNAL_SPILL) | DBG_FUNC_NONE, processor->cpu_id, 0, 0, 0);

			processor->deadline = UINT64_MAX;
			pset_update_processor_state(pset, processor, PROCESSOR_DISPATCHING);

			if (processor == current_processor()) {
				bit_set(pset->pending_AST_URGENT_cpu_mask, processor->cpu_id);
			} else {
				ipi_type = sched_ipi_action(processor, NULL, true, SCHED_IPI_EVENT_SPILL);
			}
			pset_unlock(pset);
			sched_ipi_perform(processor, ipi_type);
			return;
		}
	}

	processor_t ast_processor = NULL;
	uint64_t running_map = pset->recommended_bitmask & pset->cpu_state_map[PROCESSOR_RUNNING];
	for (int cpuid = lsb_first(running_map); cpuid >= 0; cpuid = lsb_next(running_map, cpuid)) {
		processor = processor_array[cpuid];
		if (processor->current_recommended_pset_type == PSET_AMP_P) {
			/* Already running a spilled P-core recommended thread */
			continue;
		}
		if (bit_test(pset->pending_spill_cpu_mask, processor->cpu_id)) {
			/* Already received a spill signal */
			continue;
		}
		if (processor->current_pri >= spilled_thread_priority) {
			/* Already running a higher or equal priority thread */
			continue;
		}

		/* Found a suitable processor */
		bit_set(pset->pending_spill_cpu_mask, processor->cpu_id);
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_AMP_SIGNAL_SPILL) | DBG_FUNC_NONE, processor->cpu_id, 1, 0, 0);
		if (processor == current_processor()) {
			ast_on(AST_PREEMPT);
		}
		ipi_type = sched_ipi_action(processor, NULL, false, SCHED_IPI_EVENT_SPILL);
		if (ipi_type != SCHED_IPI_NONE) {
			ast_processor = processor;
		}
		break;
	}

	pset_unlock(pset);
	sched_ipi_perform(ast_processor, ipi_type);
}

/*
 * pset_should_accept_spilled_thread()
 *
 * Routine to decide if pset should accept spilled threads.
 * This function must be safe to call (to use as a hint) without holding the pset lock.
 */
bool
pset_should_accept_spilled_thread(processor_set_t pset, int spilled_thread_priority)
{
	if ((pset->recommended_bitmask & pset->cpu_state_map[PROCESSOR_IDLE]) != 0) {
		return true;
	}

	uint64_t cpu_map = (pset->recommended_bitmask & pset->cpu_state_map[PROCESSOR_RUNNING]);

	for (int cpuid = lsb_first(cpu_map); cpuid >= 0; cpuid = lsb_next(cpu_map, cpuid)) {
		processor_t processor = processor_array[cpuid];

		if (processor->current_recommended_pset_type == PSET_AMP_P) {
			/* This processor is already running a spilled thread */
			continue;
		}

		if (processor->current_pri < spilled_thread_priority) {
			return true;
		}
	}

	return false;
}

/*
 * should_spill_to_ecores()
 *
 * Spill policy is implemented here
 */
bool
should_spill_to_ecores(processor_set_t nset, thread_t thread)
{
	if (nset->pset_cluster_type == PSET_AMP_E) {
		/* Not relevant if ecores already preferred */
		return false;
	}

	if (!pset_is_recommended(ecore_set)) {
		/* E cores must be recommended */
		return false;
	}

	if (thread->sched_flags & TH_SFLAG_PCORE_ONLY) {
		return false;
	}

	if (thread->sched_pri >= BASEPRI_RTQUEUES) {
		/* Never spill realtime threads */
		return false;
	}

	if ((nset->recommended_bitmask & nset->cpu_state_map[PROCESSOR_IDLE]) != 0) {
		/* Don't spill if idle cores */
		return false;
	}

	if ((sched_get_pset_load_average(nset, 0) >= sched_amp_spill_threshold(nset)) &&  /* There is already a load on P cores */
	    pset_should_accept_spilled_thread(ecore_set, thread->sched_pri)) { /* There are lower priority E cores */
		return true;
	}

	return false;
}

/*
 * sched_amp_check_spill()
 *
 * Routine to check if the thread should be spilled and signal the pset if needed.
 */
void
sched_amp_check_spill(processor_set_t pset, thread_t thread)
{
	/* pset is unlocked */

	/* Bound threads don't call this function */
	assert(thread->bound_processor == PROCESSOR_NULL);

	if (should_spill_to_ecores(pset, thread)) {
		pset_lock(ecore_set);

		pset_signal_spill(ecore_set, thread->sched_pri);
		/* returns with ecore_set unlocked */
	}
}

/*
 * sched_amp_steal_threshold()
 *
 * Routine to calculate the steal threshold
 */
int
sched_amp_steal_threshold(processor_set_t pset, bool spill_pending)
{
	int recommended_processor_count = bit_count(pset->recommended_bitmask & pset->cpu_bitmask);

	return (recommended_processor_count << PSET_LOAD_FRACTIONAL_SHIFT) + (spill_pending ? sched_amp_spill_steal : sched_amp_idle_steal);
}

/*
 * sched_amp_steal_thread_enabled()
 *
 */
bool
sched_amp_steal_thread_enabled(processor_set_t pset)
{
	return (pset->pset_cluster_type == PSET_AMP_E) && (pcore_set->online_processor_count > 0);
}

/*
 * sched_amp_balance()
 *
 * Invoked with pset locked, returns with pset unlocked
 */
void
sched_amp_balance(processor_t cprocessor, processor_set_t cpset)
{
	assert(cprocessor == current_processor());

	pset_unlock(cpset);

	if (cpset->pset_cluster_type == PSET_AMP_E || !cprocessor->is_recommended) {
		return;
	}

	/*
	 * cprocessor is an idle, recommended P core processor.
	 * Look for P-eligible threads that have spilled to an E core
	 * and coax them to come back.
	 */

	processor_set_t pset = ecore_set;

	pset_lock(pset);

	processor_t eprocessor;
	uint64_t ast_processor_map = 0;

	sched_ipi_type_t ipi_type[MAX_CPUS] = {SCHED_IPI_NONE};
	uint64_t running_map = pset->cpu_state_map[PROCESSOR_RUNNING];
	for (int cpuid = lsb_first(running_map); cpuid >= 0; cpuid = lsb_next(running_map, cpuid)) {
		eprocessor = processor_array[cpuid];
		if ((eprocessor->current_pri < BASEPRI_RTQUEUES) &&
		    (eprocessor->current_recommended_pset_type == PSET_AMP_P)) {
			ipi_type[eprocessor->cpu_id] = sched_ipi_action(eprocessor, NULL, false, SCHED_IPI_EVENT_REBALANCE);
			if (ipi_type[eprocessor->cpu_id] != SCHED_IPI_NONE) {
				bit_set(ast_processor_map, eprocessor->cpu_id);
				assert(eprocessor != cprocessor);
			}
		}
	}

	pset_unlock(pset);

	for (int cpuid = lsb_first(ast_processor_map); cpuid >= 0; cpuid = lsb_next(ast_processor_map, cpuid)) {
		processor_t ast_processor = processor_array[cpuid];
		sched_ipi_perform(ast_processor, ipi_type[cpuid]);
	}
}

/*
 * Helper function for sched_amp_thread_group_recommendation_change()
 * Find all the cores in the pset running threads from the thread_group tg
 * and send them a rebalance interrupt.
 */
void
sched_amp_bounce_thread_group_from_ecores(processor_set_t pset, struct thread_group *tg)
{
	assert(pset->pset_cluster_type == PSET_AMP_E);
	uint64_t ast_processor_map = 0;
	sched_ipi_type_t ipi_type[MAX_CPUS] = {SCHED_IPI_NONE};

	spl_t s = splsched();
	pset_lock(pset);

	uint64_t running_map = pset->cpu_state_map[PROCESSOR_RUNNING];
	for (int cpuid = lsb_first(running_map); cpuid >= 0; cpuid = lsb_next(running_map, cpuid)) {
		processor_t eprocessor = processor_array[cpuid];
		if (eprocessor->current_thread_group == tg) {
			ipi_type[eprocessor->cpu_id] = sched_ipi_action(eprocessor, NULL, false, SCHED_IPI_EVENT_REBALANCE);
			if (ipi_type[eprocessor->cpu_id] != SCHED_IPI_NONE) {
				bit_set(ast_processor_map, eprocessor->cpu_id);
			} else if (eprocessor == current_processor()) {
				ast_on(AST_PREEMPT);
				bit_set(pset->pending_AST_PREEMPT_cpu_mask, eprocessor->cpu_id);
			}
		}
	}

	KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_AMP_RECOMMENDATION_CHANGE) | DBG_FUNC_NONE, tg, ast_processor_map, 0, 0);

	pset_unlock(pset);

	for (int cpuid = lsb_first(ast_processor_map); cpuid >= 0; cpuid = lsb_next(ast_processor_map, cpuid)) {
		processor_t ast_processor = processor_array[cpuid];
		sched_ipi_perform(ast_processor, ipi_type[cpuid]);
	}

	splx(s);
}

/*
 * sched_amp_ipi_policy()
 */
sched_ipi_type_t
sched_amp_ipi_policy(processor_t dst, thread_t thread, boolean_t dst_idle, sched_ipi_event_t event)
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
			if (sched_amp_pcores_preempt_immediate_ipi && (pset == pcore_set)) {
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
 * sched_amp_qos_max_parallelism()
 */
uint32_t
sched_amp_qos_max_parallelism(int qos, uint64_t options)
{
	uint32_t ecount = ecore_set->cpu_set_count;
	uint32_t pcount = pcore_set->cpu_set_count;

	if (options & QOS_PARALLELISM_REALTIME) {
		/* For realtime threads on AMP, we would want them
		 * to limit the width to just the P-cores since we
		 * do not spill/rebalance for RT threads.
		 */
		return pcount;
	}

	/*
	 * The default AMP scheduler policy is to run utility and by
	 * threads on E-Cores only.  Run-time policy adjustment unlocks
	 * ability of utility and bg to threads to be scheduled based on
	 * run-time conditions.
	 */
	switch (qos) {
	case THREAD_QOS_UTILITY:
		return (os_atomic_load(&sched_perfctl_policy_util, relaxed) == SCHED_PERFCTL_POLICY_DEFAULT) ? ecount : (ecount + pcount);
	case THREAD_QOS_BACKGROUND:
	case THREAD_QOS_MAINTENANCE:
		return (os_atomic_load(&sched_perfctl_policy_bg, relaxed) == SCHED_PERFCTL_POLICY_DEFAULT) ? ecount : (ecount + pcount);
	default:
		return ecount + pcount;
	}
}

pset_node_t
sched_amp_choose_node(thread_t thread)
{
	if (recommended_pset_type(thread) == PSET_AMP_P) {
		return pcore_set->node;
	} else {
		return ecore_set->node;
	}
}

/*
 * sched_amp_rt_runq()
 */
rt_queue_t
sched_amp_rt_runq(processor_set_t pset)
{
	return &pset->rt_runq;
}

/*
 * sched_amp_rt_init()
 */
void
sched_amp_rt_init(processor_set_t pset)
{
	pset_rt_init(pset);
}

/*
 * sched_amp_rt_queue_shutdown()
 */
void
sched_amp_rt_queue_shutdown(processor_t processor)
{
	processor_set_t pset = processor->processor_set;
	thread_t        thread;
	queue_head_t    tqueue;

	pset_lock(pset);

	/* We only need to migrate threads if this is the last active or last recommended processor in the pset */
	if ((pset->online_processor_count > 0) && pset_is_recommended(pset)) {
		pset_unlock(pset);
		return;
	}

	queue_init(&tqueue);

	while (rt_runq_count(pset) > 0) {
		thread = qe_dequeue_head(&pset->rt_runq.queue, struct thread, runq_links);
		thread->runq = PROCESSOR_NULL;
		SCHED_STATS_RUNQ_CHANGE(&pset->rt_runq.runq_stats,
		    os_atomic_load(&pset->rt_runq.count, relaxed));
		rt_runq_count_decr(pset);
		enqueue_tail(&tqueue, &thread->runq_links);
	}
	sched_update_pset_load_average(pset, 0);
	pset_unlock(pset);

	qe_foreach_element_safe(thread, &tqueue, runq_links) {
		remqueue(&thread->runq_links);

		thread_lock(thread);

		thread_setrun(thread, SCHED_TAILQ);

		thread_unlock(thread);
	}
}

/*
 * sched_amp_rt_runq_scan()
 *
 * Assumes RT lock is not held, and acquires splsched/rt_lock itself
 */
void
sched_amp_rt_runq_scan(sched_update_scan_context_t scan_context)
{
	thread_t        thread;

	pset_node_t node = &pset_node0;
	processor_set_t pset = node->psets;

	spl_t s = splsched();
	do {
		while (pset != NULL) {
			pset_lock(pset);

			qe_foreach_element_safe(thread, &pset->rt_runq.queue, runq_links) {
				if (thread->last_made_runnable_time < scan_context->earliest_rt_make_runnable_time) {
					scan_context->earliest_rt_make_runnable_time = thread->last_made_runnable_time;
				}
			}

			pset_unlock(pset);

			pset = pset->pset_list;
		}
	} while (((node = node->node_list) != NULL) && ((pset = node->psets) != NULL));
	splx(s);
}

/*
 * sched_amp_rt_runq_count_sum()
 */
int64_t
sched_amp_rt_runq_count_sum(void)
{
	pset_node_t node = &pset_node0;
	processor_set_t pset = node->psets;
	int64_t count = 0;

	do {
		while (pset != NULL) {
			count += pset->rt_runq.runq_stats.count_sum;

			pset = pset->pset_list;
		}
	} while (((node = node->node_list) != NULL) && ((pset = node->psets) != NULL));

	return count;
}

#endif /* __AMP__ */

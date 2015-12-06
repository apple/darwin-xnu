/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
#include <mach/thread_act_server.h>

#include <kern/kern_types.h>
#include <kern/processor.h>
#include <kern/thread.h>
#include <kern/affinity.h>
#include <mach/task_policy.h>
#include <kern/sfi.h>

#include <mach/machine/sdt.h>

#define QOS_EXTRACT(q)        ((q) & 0xff)

/*
 * THREAD_QOS_UNSPECIFIED is assigned the highest tier available, so it does not provide a limit
 * to threads that don't have a QoS class set.
 */
const qos_policy_params_t thread_qos_policy_params = {
	/*
	 * This table defines the starting base priority of the thread,
	 * which will be modified by the thread importance and the task max priority
	 * before being applied.
	 */
	.qos_pri[THREAD_QOS_UNSPECIFIED]                = 0, /* not consulted */
	.qos_pri[THREAD_QOS_USER_INTERACTIVE]           = BASEPRI_BACKGROUND, /* i.e. 46 */
	.qos_pri[THREAD_QOS_USER_INITIATED]             = BASEPRI_USER_INITIATED,
	.qos_pri[THREAD_QOS_LEGACY]                     = BASEPRI_DEFAULT,
	.qos_pri[THREAD_QOS_UTILITY]                    = BASEPRI_UTILITY,
	.qos_pri[THREAD_QOS_BACKGROUND]                 = MAXPRI_THROTTLE,
	.qos_pri[THREAD_QOS_MAINTENANCE]                = MAXPRI_THROTTLE,

	/*
	 * This table defines the highest IO priority that a thread marked with this
	 * QoS class can have.
	 */
	.qos_iotier[THREAD_QOS_UNSPECIFIED]             = THROTTLE_LEVEL_TIER0,
	.qos_iotier[THREAD_QOS_USER_INTERACTIVE]        = THROTTLE_LEVEL_TIER0,
	.qos_iotier[THREAD_QOS_USER_INITIATED]          = THROTTLE_LEVEL_TIER0,
	.qos_iotier[THREAD_QOS_LEGACY]                  = THROTTLE_LEVEL_TIER0,
	.qos_iotier[THREAD_QOS_UTILITY]                 = THROTTLE_LEVEL_TIER1,
	.qos_iotier[THREAD_QOS_BACKGROUND]              = THROTTLE_LEVEL_TIER2, /* possibly overridden by bg_iotier */
	.qos_iotier[THREAD_QOS_MAINTENANCE]             = THROTTLE_LEVEL_TIER3,

	/*
	 * This table defines the highest QoS level that
	 * a thread marked with this QoS class can have.
	 */

	.qos_through_qos[THREAD_QOS_UNSPECIFIED]        = QOS_EXTRACT(THROUGHPUT_QOS_TIER_UNSPECIFIED),
	.qos_through_qos[THREAD_QOS_USER_INTERACTIVE]   = QOS_EXTRACT(THROUGHPUT_QOS_TIER_0),
	.qos_through_qos[THREAD_QOS_USER_INITIATED]     = QOS_EXTRACT(THROUGHPUT_QOS_TIER_1),
	.qos_through_qos[THREAD_QOS_LEGACY]             = QOS_EXTRACT(THROUGHPUT_QOS_TIER_1),
	.qos_through_qos[THREAD_QOS_UTILITY]            = QOS_EXTRACT(THROUGHPUT_QOS_TIER_2),
	.qos_through_qos[THREAD_QOS_BACKGROUND]         = QOS_EXTRACT(THROUGHPUT_QOS_TIER_5),
	.qos_through_qos[THREAD_QOS_MAINTENANCE]        = QOS_EXTRACT(THROUGHPUT_QOS_TIER_5),

	.qos_latency_qos[THREAD_QOS_UNSPECIFIED]        = QOS_EXTRACT(LATENCY_QOS_TIER_UNSPECIFIED),
	.qos_latency_qos[THREAD_QOS_USER_INTERACTIVE]   = QOS_EXTRACT(LATENCY_QOS_TIER_0),
	.qos_latency_qos[THREAD_QOS_USER_INITIATED]     = QOS_EXTRACT(LATENCY_QOS_TIER_1),
	.qos_latency_qos[THREAD_QOS_LEGACY]             = QOS_EXTRACT(LATENCY_QOS_TIER_1),
	.qos_latency_qos[THREAD_QOS_UTILITY]            = QOS_EXTRACT(LATENCY_QOS_TIER_3),
	.qos_latency_qos[THREAD_QOS_BACKGROUND]         = QOS_EXTRACT(LATENCY_QOS_TIER_3),
	.qos_latency_qos[THREAD_QOS_MAINTENANCE]        = QOS_EXTRACT(LATENCY_QOS_TIER_3),
};

static void
thread_set_user_sched_mode_and_recompute_pri(thread_t thread, sched_mode_t mode);

static int
thread_qos_scaled_relative_priority(int qos, int qos_relprio);


extern void proc_get_thread_policy(thread_t thread, thread_policy_state_t info);

boolean_t
thread_has_qos_policy(thread_t thread) {
	return (proc_get_task_policy(thread->task, thread, TASK_POLICY_ATTRIBUTE, TASK_POLICY_QOS) != THREAD_QOS_UNSPECIFIED) ? TRUE : FALSE;
}

kern_return_t
thread_remove_qos_policy(thread_t thread) 
{
	thread_qos_policy_data_t unspec_qos;
	unspec_qos.qos_tier = THREAD_QOS_UNSPECIFIED;
	unspec_qos.tier_importance = 0;

	__unused int prev_qos = thread->requested_policy.thrp_qos;

	DTRACE_PROC2(qos__remove, thread_t, thread, int, prev_qos);

	return thread_policy_set_internal(thread, THREAD_QOS_POLICY, (thread_policy_t)&unspec_qos, THREAD_QOS_POLICY_COUNT);
}

boolean_t
thread_is_static_param(thread_t thread)
{
	if (thread->static_param) {
		DTRACE_PROC1(qos__legacy__denied, thread_t, thread);
		return TRUE;
	}
	return FALSE;
}

/*
 * Relative priorities can range between 0REL and -15REL. These
 * map to QoS-specific ranges, to create non-overlapping priority
 * ranges.
 */
static int
thread_qos_scaled_relative_priority(int qos, int qos_relprio)
{
	int next_lower_qos;

	/* Fast path, since no validation or scaling is needed */
	if (qos_relprio == 0) return 0;

	switch (qos) {
		case THREAD_QOS_USER_INTERACTIVE:
			next_lower_qos = THREAD_QOS_USER_INITIATED;
			break;
		case THREAD_QOS_USER_INITIATED:
			next_lower_qos = THREAD_QOS_LEGACY;
			break;
		case THREAD_QOS_LEGACY:
			next_lower_qos = THREAD_QOS_UTILITY;
			break;
		case THREAD_QOS_UTILITY:
			next_lower_qos = THREAD_QOS_BACKGROUND;
			break;
		case THREAD_QOS_MAINTENANCE:
		case THREAD_QOS_BACKGROUND:
			next_lower_qos = 0;
			break;
		default:
			panic("Unrecognized QoS %d", qos);
			return 0;
	}

	int prio_range_max = thread_qos_policy_params.qos_pri[qos];
	int prio_range_min = next_lower_qos ? thread_qos_policy_params.qos_pri[next_lower_qos] : 0;

	/*
	 * We now have the valid range that the scaled relative priority can map to. Note
	 * that the lower bound is exclusive, but the upper bound is inclusive. If the
	 * range is (21,31], 0REL should map to 31 and -15REL should map to 22. We use the
	 * fact that the max relative priority is -15 and use ">>4" to divide by 16 and discard
	 * remainder.
	 */
	int scaled_relprio = -(((prio_range_max - prio_range_min) * (-qos_relprio)) >> 4);

	return scaled_relprio;
}

/*
 * flag set by -qos-policy-allow boot-arg to allow
 * testing thread qos policy from userspace
 */
boolean_t allow_qos_policy_set = FALSE;

kern_return_t
thread_policy_set(
	thread_t				thread,
	thread_policy_flavor_t	flavor,
	thread_policy_t			policy_info,
	mach_msg_type_number_t	count)
{
	thread_qos_policy_data_t req_qos;
	kern_return_t kr;
	
	req_qos.qos_tier = THREAD_QOS_UNSPECIFIED;

	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	if (allow_qos_policy_set == FALSE) {
		if (thread_is_static_param(thread))
			return (KERN_POLICY_STATIC);

		if (flavor == THREAD_QOS_POLICY || flavor == THREAD_QOS_POLICY_OVERRIDE)
			return (KERN_INVALID_ARGUMENT);
	}

	/* Threads without static_param set reset their QoS when other policies are applied. */
	if (thread->requested_policy.thrp_qos != THREAD_QOS_UNSPECIFIED) {
		/* Store the existing tier, if we fail this call it is used to reset back. */
		req_qos.qos_tier = thread->requested_policy.thrp_qos;
		req_qos.tier_importance = thread->requested_policy.thrp_qos_relprio;

		kr = thread_remove_qos_policy(thread);
		if (kr != KERN_SUCCESS) {
			return kr;
		}
	}

	kr = thread_policy_set_internal(thread, flavor, policy_info, count);

	/* Return KERN_QOS_REMOVED instead of KERN_SUCCESS if we succeeded. */
	if (req_qos.qos_tier != THREAD_QOS_UNSPECIFIED) {
		if (kr != KERN_SUCCESS) {
			/* Reset back to our original tier as the set failed. */
			(void)thread_policy_set_internal(thread, THREAD_QOS_POLICY, (thread_policy_t)&req_qos, THREAD_QOS_POLICY_COUNT);
		}
	}

	return kr;
}

kern_return_t
thread_policy_set_internal(
	thread_t				thread,
	thread_policy_flavor_t	flavor,
	thread_policy_t			policy_info,
	mach_msg_type_number_t	count)
{
	kern_return_t			result = KERN_SUCCESS;
	spl_t					s;

	thread_mtx_lock(thread);
	if (!thread->active) {
		thread_mtx_unlock(thread);

		return (KERN_TERMINATED);
	}

	switch (flavor) {

	case THREAD_EXTENDED_POLICY:
	{
		boolean_t				timeshare = TRUE;

		if (count >= THREAD_EXTENDED_POLICY_COUNT) {
			thread_extended_policy_t	info;

			info = (thread_extended_policy_t)policy_info;
			timeshare = info->timeshare;
		}

		sched_mode_t mode = (timeshare == TRUE) ? TH_MODE_TIMESHARE : TH_MODE_FIXED;

		s = splsched();
		thread_lock(thread);

		thread_set_user_sched_mode_and_recompute_pri(thread, mode);

		thread_unlock(thread);
		splx(s);

		sfi_reevaluate(thread);

		break;
	}

	case THREAD_TIME_CONSTRAINT_POLICY:
	{
		thread_time_constraint_policy_t		info;

		if (count < THREAD_TIME_CONSTRAINT_POLICY_COUNT) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		info = (thread_time_constraint_policy_t)policy_info;
		if (	info->constraint < info->computation	||
				info->computation > max_rt_quantum		||
				info->computation < min_rt_quantum		) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		s = splsched();
		thread_lock(thread);

		thread->realtime.period = info->period;
		thread->realtime.computation = info->computation;
		thread->realtime.constraint = info->constraint;
		thread->realtime.preemptible = info->preemptible;

		thread_set_user_sched_mode_and_recompute_pri(thread, TH_MODE_REALTIME);

		thread_unlock(thread);
		splx(s);

		sfi_reevaluate(thread);

		break;
	}

	case THREAD_PRECEDENCE_POLICY:
	{
		thread_precedence_policy_t		info;

		if (count < THREAD_PRECEDENCE_POLICY_COUNT) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}
		info = (thread_precedence_policy_t)policy_info;

		s = splsched();
		thread_lock(thread);

		thread->importance = info->importance;

		thread_recompute_priority(thread);

		thread_unlock(thread);
		splx(s);

		break;
	}

	case THREAD_AFFINITY_POLICY:
	{
		thread_affinity_policy_t	info;

		if (!thread_affinity_is_supported()) {
			result = KERN_NOT_SUPPORTED;
			break;
		}
		if (count < THREAD_AFFINITY_POLICY_COUNT) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		info = (thread_affinity_policy_t) policy_info;
		/*
		 * Unlock the thread mutex here and
		 * return directly after calling thread_affinity_set().
		 * This is necessary for correct lock ordering because
		 * thread_affinity_set() takes the task lock.
		 */
		thread_mtx_unlock(thread);
		return thread_affinity_set(thread, info->affinity_tag);
	}

	case THREAD_THROUGHPUT_QOS_POLICY:
	{
		thread_throughput_qos_policy_t info = (thread_throughput_qos_policy_t) policy_info;
		int tqos;
		
		if (count < THREAD_LATENCY_QOS_POLICY_COUNT) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		if ((result = qos_throughput_policy_validate(info->thread_throughput_qos_tier)) !=
		    KERN_SUCCESS) {
			break;
		}

		tqos = qos_extract(info->thread_throughput_qos_tier);
		thread->effective_policy.t_through_qos = tqos;
	}
		break;

	case THREAD_LATENCY_QOS_POLICY:
	{
		thread_latency_qos_policy_t info = (thread_latency_qos_policy_t) policy_info;
		int lqos;
		
		if (count < THREAD_THROUGHPUT_QOS_POLICY_COUNT) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		if ((result = qos_latency_policy_validate(info->thread_latency_qos_tier)) !=
		    KERN_SUCCESS) {
			break;
		}

		lqos = qos_extract(info->thread_latency_qos_tier);
/* The expected use cases (opt-in) of per-thread latency QoS would seem to
 * preclude any requirement at present to re-evaluate timers on a thread level
 * latency QoS change.
 */
		thread->effective_policy.t_latency_qos = lqos;

	}
		break;

	case THREAD_QOS_POLICY:
	case THREAD_QOS_POLICY_OVERRIDE:
	{
		thread_qos_policy_t info = (thread_qos_policy_t)policy_info;

		if (count < THREAD_QOS_POLICY_COUNT) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		if (info->qos_tier < 0 || info->qos_tier >= THREAD_QOS_LAST) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		if (info->tier_importance > 0 || info->tier_importance < THREAD_QOS_MIN_TIER_IMPORTANCE) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		if (info->qos_tier == THREAD_QOS_UNSPECIFIED && info->tier_importance != 0) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		/*
		 * Going into task policy requires the task mutex,
		 * because of the way synchronization against the IO policy
		 * subsystem works.
		 *
		 * We need to move thread policy to the thread mutex instead.
		 * <rdar://problem/15831652> separate thread policy from task policy
		 */

		if (flavor == THREAD_QOS_POLICY_OVERRIDE) {
			int strongest_override = info->qos_tier;

			if (info->qos_tier != THREAD_QOS_UNSPECIFIED &&
			    thread->requested_policy.thrp_qos_override != THREAD_QOS_UNSPECIFIED)
				strongest_override = MAX(thread->requested_policy.thrp_qos_override, info->qos_tier);

			thread_mtx_unlock(thread);

			/* There is a race here. To be closed in <rdar://problem/15831652> separate thread policy from task policy */

			proc_set_task_policy(thread->task, thread, TASK_POLICY_ATTRIBUTE, TASK_POLICY_QOS_OVERRIDE, strongest_override);

			return (result);
		}

		thread_mtx_unlock(thread);

		proc_set_task_policy2(thread->task, thread, TASK_POLICY_ATTRIBUTE, TASK_POLICY_QOS_AND_RELPRIO, info->qos_tier, -info->tier_importance);

		thread_mtx_lock(thread);
		if (!thread->active) {
			thread_mtx_unlock(thread);
			return (KERN_TERMINATED);
		}
		
		break;
	}

	default:
		result = KERN_INVALID_ARGUMENT;
		break;
	}

	thread_mtx_unlock(thread);
	return (result);
}

/*
 * thread_set_mode_and_absolute_pri:
 *
 * Set scheduling policy & absolute priority for thread, for deprecated
 * thread_set_policy and thread_policy interfaces.
 *
 * Note that there is no implemented difference between POLICY_RR and POLICY_FIFO.
 * Both result in FIXED mode scheduling.
 *
 * Called with thread mutex locked.
 */
kern_return_t
thread_set_mode_and_absolute_pri(
	thread_t		thread,
	integer_t		policy,
	integer_t		priority)
{
	spl_t s;
	sched_mode_t mode;
	kern_return_t kr = KERN_SUCCESS;

	if (thread_is_static_param(thread))
		return (KERN_POLICY_STATIC);

	if (thread->policy_reset)
		return (KERN_SUCCESS);

	/* Setting legacy policies on threads kills the current QoS */
	if (thread->requested_policy.thrp_qos != THREAD_QOS_UNSPECIFIED) {
		thread_mtx_unlock(thread);

		kr = thread_remove_qos_policy(thread);

		thread_mtx_lock(thread);
		if (!thread->active) {
			return (KERN_TERMINATED);
		}
	}

	switch (policy) {
		case POLICY_TIMESHARE:
			mode = TH_MODE_TIMESHARE;
			break;
		case POLICY_RR:
		case POLICY_FIFO:
			mode = TH_MODE_FIXED;
			break;
		default:
			panic("unexpected sched policy: %d", policy);
			break;
	}

	s = splsched();
	thread_lock(thread);

	/* This path isn't allowed to change a thread out of realtime. */
	if ((thread->sched_mode != TH_MODE_REALTIME) &&
	    (thread->saved_mode != TH_MODE_REALTIME)) {

		/*
		 * Reverse engineer and apply the correct importance value
		 * from the requested absolute priority value.
		 */

		if (priority >= thread->max_priority)
			priority = thread->max_priority - thread->task_priority;
		else if (priority >= MINPRI_KERNEL)
			priority -=  MINPRI_KERNEL;
		else if (priority >= MINPRI_RESERVED)
			priority -=  MINPRI_RESERVED;
		else
			priority -= BASEPRI_DEFAULT;

		priority += thread->task_priority;

		if (priority > thread->max_priority)
			priority = thread->max_priority;
		else if (priority < MINPRI)
			priority = MINPRI;

		thread->importance = priority - thread->task_priority;

		thread_set_user_sched_mode_and_recompute_pri(thread, mode);
	}

	thread_unlock(thread);
	splx(s);

	sfi_reevaluate(thread);

	return (kr);
}

/*
 * Set the thread's requested mode and recompute priority
 * Called with thread mutex and thread locked
 *
 * TODO: Mitigate potential problems caused by moving thread to end of runq
 * whenever its priority is recomputed
 *      Only remove when it actually changes? Attempt to re-insert at appropriate location?
 */
static void
thread_set_user_sched_mode_and_recompute_pri(thread_t thread, sched_mode_t mode)
{
	if (thread->policy_reset)
		return;

	boolean_t removed = thread_run_queue_remove(thread);

	/*
	 * TODO: Instead of having saved mode, have 'user mode' and 'true mode'.
	 * That way there's zero confusion over which the user wants
	 * and which the kernel wants.
	 */
	if (thread->sched_flags & TH_SFLAG_DEMOTED_MASK)
		thread->saved_mode = mode;
	else
		sched_set_thread_mode(thread, mode);

	thread_recompute_priority(thread);

	if (removed)
		thread_run_queue_reinsert(thread, SCHED_TAILQ);
}

/* called with task lock locked */
void
thread_recompute_qos(thread_t thread) {
	spl_t s;

	thread_mtx_lock(thread);

	if (!thread->active) {
		thread_mtx_unlock(thread);
		return;
	}

	s = splsched();
	thread_lock(thread);

	thread_recompute_priority(thread);

	thread_unlock(thread);
	splx(s);

	thread_mtx_unlock(thread);
}

/* called with task lock locked and thread_mtx_lock locked */
void
thread_update_qos_cpu_time(thread_t thread, boolean_t lock_needed)
{
	uint64_t last_qos_change_balance;
	ledger_amount_t thread_balance_credit;
	ledger_amount_t thread_balance_debit;
	ledger_amount_t effective_qos_time;
	uint64_t ctime;
	uint64_t remainder = 0, consumed = 0;
	processor_t		processor;
	spl_t s;
	kern_return_t kr;

	if (lock_needed) {
		s = splsched();
		thread_lock(thread);
	}
	
	/*
	 * Calculation of time elapsed by the thread in the current qos.
	 * Following is the timeline which shows all the variables used in the calculation below.
	 *
	 *       thread ledger      thread ledger
	 *      cpu_time_last_qos     cpu_time
	 *              |                |<-   consumed  ->|<- remainder  ->|
	 * timeline  ----------------------------------------------------------->
	 *                               |                 |                |
	 *                            thread_dispatch    ctime           quantum end
	 *
	 *              |<-----  effective qos time  ----->|
	 */
	
	/* 
	 * Calculate time elapsed since last qos change on this thread.
	 * For cpu time on thread ledger, do not use ledger_get_balance,
	 * only use credit field of ledger, since
	 * debit is used by per thread cpu limits and is not zero.
	 */
	kr = ledger_get_entries(thread->t_threadledger, thread_ledgers.cpu_time, &thread_balance_credit, &thread_balance_debit);
	if (kr != KERN_SUCCESS)
		goto out;
	last_qos_change_balance = thread->cpu_time_last_qos;

	/*
	 * If thread running on CPU, calculate time elapsed since this thread was last dispatched on cpu.
	 * The thread ledger is only updated at context switch, the time since last context swicth is not 
	 * updated in the thread ledger cpu time.
	 */
	processor = thread->last_processor;
	if ((processor != PROCESSOR_NULL) && (processor->state == PROCESSOR_RUNNING) &&
		   (processor->active_thread == thread)) {
		ctime = mach_absolute_time();
	
		if (processor->quantum_end > ctime)
			remainder = processor->quantum_end - ctime;

		consumed = thread->quantum_remaining - remainder;
	}
	/*
	 * There can be multiple qos change in a quantum and in that case the cpu_time_last_qos will
	 * lie between cpu_time marker and ctime marker shown below. The output of 
	 * thread_balance - last_qos_change_balance will be negative in such case, but overall outcome
	 * when consumed is added to it would be positive.
	 *
	 *          thread ledger
	 *            cpu_time
	 *               |<------------  consumed    --------->|<- remainder  ->|
	 * timeline  ----------------------------------------------------------->
	 *               |              |                      |                |
	 *         thread_dispatch  thread ledger            ctime           quantum end
	 *                          cpu_time_last_qos
	 *
	 *                              |<-effective qos time->|
	 */
	effective_qos_time = (ledger_amount_t) consumed;
	effective_qos_time += thread_balance_credit - last_qos_change_balance;

	if (lock_needed) {
		thread_unlock(thread);
		splx(s);
	}

	if (effective_qos_time < 0)
		return;

	thread->cpu_time_last_qos += (uint64_t)effective_qos_time;

	/*
	 * Update the task-level qos stats. Its safe to perform operations on these fields, since we 
	 * hold the task lock.
	 */
	switch (thread->effective_policy.thep_qos) {
	
	case THREAD_QOS_DEFAULT:
		thread->task->cpu_time_qos_stats.cpu_time_qos_default += effective_qos_time;
		break;

	case THREAD_QOS_MAINTENANCE:
		thread->task->cpu_time_qos_stats.cpu_time_qos_maintenance += effective_qos_time;
		break;

	case THREAD_QOS_BACKGROUND:
		thread->task->cpu_time_qos_stats.cpu_time_qos_background += effective_qos_time;
		break;

	case THREAD_QOS_UTILITY:
		thread->task->cpu_time_qos_stats.cpu_time_qos_utility += effective_qos_time;
		break;

	case THREAD_QOS_LEGACY:
		thread->task->cpu_time_qos_stats.cpu_time_qos_legacy += effective_qos_time;
		break;
	
	case THREAD_QOS_USER_INITIATED:
		thread->task->cpu_time_qos_stats.cpu_time_qos_user_initiated += effective_qos_time;
		break;

	case THREAD_QOS_USER_INTERACTIVE:
		thread->task->cpu_time_qos_stats.cpu_time_qos_user_interactive += effective_qos_time;
		break;
	}

	return;

out:
	if (lock_needed) {
		thread_unlock(thread);
		splx(s);
	}
}

/*
 * Calculate base priority from thread attributes, and set it on the thread
 *
 * Called with thread_lock and thread mutex held.
 */
void
thread_recompute_priority(
	thread_t		thread)
{
	integer_t		priority;

	if (thread->policy_reset)
		return;

	if (thread->sched_mode == TH_MODE_REALTIME) {
		sched_set_thread_base_priority(thread, BASEPRI_RTQUEUES);
		return;
	} else if (thread->effective_policy.thep_qos != THREAD_QOS_UNSPECIFIED) {
		int qos = thread->effective_policy.thep_qos;
		int qos_ui_is_urgent = thread->effective_policy.qos_ui_is_urgent;
		int qos_relprio = -(thread->effective_policy.thep_qos_relprio); /* stored in task policy inverted */
		int qos_scaled_relprio;

		assert(qos >= 0 && qos < THREAD_QOS_LAST);
		assert(qos_relprio <= 0 && qos_relprio >= THREAD_QOS_MIN_TIER_IMPORTANCE);

		priority = thread_qos_policy_params.qos_pri[qos];
		qos_scaled_relprio = thread_qos_scaled_relative_priority(qos, qos_relprio);

		if (qos == THREAD_QOS_USER_INTERACTIVE && qos_ui_is_urgent == 1) {
			/* Bump priority 46 to 47 when in a frontmost app */
			qos_scaled_relprio += 1;
		}

		priority += qos_scaled_relprio;
	} else {
		if (thread->importance > MAXPRI)
			priority = MAXPRI;
		else if (thread->importance < -MAXPRI)
			priority = -MAXPRI;
		else
			priority = thread->importance;

		priority += thread->task_priority;
	}

	if (thread->saved_mode == TH_MODE_REALTIME &&
	    thread->sched_flags & TH_SFLAG_FAILSAFE)
		priority = DEPRESSPRI;

	if (thread->effective_policy.terminated == TRUE && priority < thread->task_priority) {
		priority = thread->task_priority;
	}

	if (priority > thread->max_priority)
		priority = thread->max_priority;
	else if (priority < MINPRI)
		priority = MINPRI;


	sched_set_thread_base_priority(thread, priority);
}

/* Called with the thread mutex held */
void
thread_task_priority(
	thread_t		thread,
	integer_t		priority,
	integer_t		max_priority)
{
	spl_t s;

	assert(thread != THREAD_NULL);

	if (!thread->active || thread->policy_reset)
		return;

	s = splsched();
	thread_lock(thread);

	integer_t old_max_priority = thread->max_priority;

	thread->task_priority = priority;
	thread->max_priority = max_priority;

	/* A thread is 'throttled' when its max priority is below MAXPRI_THROTTLE */
	if ((max_priority > MAXPRI_THROTTLE) && (old_max_priority <= MAXPRI_THROTTLE)) {
		sched_set_thread_throttled(thread, FALSE);
	} else if ((max_priority <= MAXPRI_THROTTLE) && (old_max_priority > MAXPRI_THROTTLE)) {
		sched_set_thread_throttled(thread, TRUE);
	}

	thread_recompute_priority(thread);

	thread_unlock(thread);
	splx(s);
}

/*
 * Reset thread to default state in preparation for termination
 * Called with thread mutex locked
 *
 * Always called on current thread, so we don't need a run queue remove
 */
void
thread_policy_reset(
	thread_t		thread)
{
	spl_t		s;

	assert(thread == current_thread());

	s = splsched();
	thread_lock(thread);

	assert_thread_sched_count(thread);

	if (thread->sched_flags & TH_SFLAG_FAILSAFE)
		sched_thread_mode_undemote(thread, TH_SFLAG_FAILSAFE);

	assert_thread_sched_count(thread);

	if (thread->sched_flags & TH_SFLAG_THROTTLED)
		sched_set_thread_throttled(thread, FALSE);

	assert_thread_sched_count(thread);

	assert(thread->BG_COUNT == 0);

	/* At this point, the various demotions should be inactive */
	assert(!(thread->sched_flags & TH_SFLAG_DEMOTED_MASK));
	assert(!(thread->sched_flags & TH_SFLAG_THROTTLED));
	assert(!(thread->sched_flags & TH_SFLAG_DEPRESSED_MASK));

	/* Reset thread back to task-default basepri and mode  */
	sched_mode_t newmode = SCHED(initial_thread_sched_mode)(thread->task);

	sched_set_thread_mode(thread, newmode);

	thread->importance = 0;

	sched_set_thread_base_priority(thread, thread->task_priority);

	/* Prevent further changes to thread base priority or mode */
	thread->policy_reset = 1;

	assert(thread->BG_COUNT == 0);
	assert_thread_sched_count(thread);

	thread_unlock(thread);
	splx(s);
}

kern_return_t
thread_policy_get(
	thread_t				thread,
	thread_policy_flavor_t	flavor,
	thread_policy_t			policy_info,
	mach_msg_type_number_t	*count,
	boolean_t				*get_default)
{
	kern_return_t			result = KERN_SUCCESS;
	spl_t					s;

	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	thread_mtx_lock(thread);
	if (!thread->active) {
		thread_mtx_unlock(thread);

		return (KERN_TERMINATED);
	}

	switch (flavor) {

	case THREAD_EXTENDED_POLICY:
	{
		boolean_t		timeshare = TRUE;

		if (!(*get_default)) {
			s = splsched();
			thread_lock(thread);

			if (	 (thread->sched_mode != TH_MODE_REALTIME)	&&
					 (thread->saved_mode != TH_MODE_REALTIME)			) {
				if (!(thread->sched_flags & TH_SFLAG_DEMOTED_MASK))
					timeshare = (thread->sched_mode == TH_MODE_TIMESHARE) != 0;
				else
					timeshare = (thread->saved_mode == TH_MODE_TIMESHARE) != 0;
			}
			else
				*get_default = TRUE;

			thread_unlock(thread);
			splx(s);
		}

		if (*count >= THREAD_EXTENDED_POLICY_COUNT) {
			thread_extended_policy_t	info;

			info = (thread_extended_policy_t)policy_info;
			info->timeshare = timeshare;
		}

		break;
	}

	case THREAD_TIME_CONSTRAINT_POLICY:
	{
		thread_time_constraint_policy_t		info;

		if (*count < THREAD_TIME_CONSTRAINT_POLICY_COUNT) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		info = (thread_time_constraint_policy_t)policy_info;

		if (!(*get_default)) {
			s = splsched();
			thread_lock(thread);

			if (	(thread->sched_mode == TH_MODE_REALTIME)	||
					(thread->saved_mode == TH_MODE_REALTIME)		) {
				info->period = thread->realtime.period;
				info->computation = thread->realtime.computation;
				info->constraint = thread->realtime.constraint;
				info->preemptible = thread->realtime.preemptible;
			}
			else
				*get_default = TRUE;

			thread_unlock(thread);
			splx(s);
		}

		if (*get_default) {
			info->period = 0;
			info->computation = default_timeshare_computation;
			info->constraint = default_timeshare_constraint;
			info->preemptible = TRUE;
		}

		break;
	}

	case THREAD_PRECEDENCE_POLICY:
	{
		thread_precedence_policy_t		info;

		if (*count < THREAD_PRECEDENCE_POLICY_COUNT) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		info = (thread_precedence_policy_t)policy_info;

		if (!(*get_default)) {
			s = splsched();
			thread_lock(thread);

			info->importance = thread->importance;

			thread_unlock(thread);
			splx(s);
		}
		else
			info->importance = 0;

		break;
	}

	case THREAD_AFFINITY_POLICY:
	{
		thread_affinity_policy_t		info;

		if (!thread_affinity_is_supported()) {
			result = KERN_NOT_SUPPORTED;
			break;
		}
		if (*count < THREAD_AFFINITY_POLICY_COUNT) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		info = (thread_affinity_policy_t)policy_info;

		if (!(*get_default))
			info->affinity_tag = thread_affinity_get(thread);
		else
			info->affinity_tag = THREAD_AFFINITY_TAG_NULL;

		break;
	}

	case THREAD_POLICY_STATE:
	{
		thread_policy_state_t		info;

		if (*count < THREAD_POLICY_STATE_COUNT) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		/* Only root can get this info */
		if (current_task()->sec_token.val[0] != 0) {
			result = KERN_PROTECTION_FAILURE;
			break;
		}

		info = (thread_policy_state_t)policy_info;

		if (!(*get_default)) {
			info->flags = 0;

			info->flags |= (thread->static_param ? THREAD_POLICY_STATE_FLAG_STATIC_PARAM : 0);

			/*
			 * Unlock the thread mutex and directly return.
			 * This is necessary because proc_get_thread_policy()
			 * takes the task lock.
			 */
			thread_mtx_unlock(thread);
			proc_get_thread_policy(thread, info);
			return (result);
		} else {
			info->requested = 0;
			info->effective = 0;
			info->pending = 0;
		}

		break;
	}
	
	case THREAD_LATENCY_QOS_POLICY:
	{
		thread_latency_qos_policy_t info = (thread_latency_qos_policy_t) policy_info;
		uint32_t plqos;

		if (*count < THREAD_LATENCY_QOS_POLICY_COUNT) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		if (*get_default) {
			plqos = 0;
		} else {
			plqos = thread->effective_policy.t_latency_qos;
		}

		info->thread_latency_qos_tier = qos_latency_policy_package(plqos);
	}
	break;

	case THREAD_THROUGHPUT_QOS_POLICY:
	{
		thread_throughput_qos_policy_t info = (thread_throughput_qos_policy_t) policy_info;
		uint32_t ptqos;

		if (*count < THREAD_THROUGHPUT_QOS_POLICY_COUNT) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		if (*get_default) {
			ptqos = 0;
		} else {
			ptqos = thread->effective_policy.t_through_qos;
		}

		info->thread_throughput_qos_tier = qos_throughput_policy_package(ptqos);
	}
	break;

	case THREAD_QOS_POLICY:
	case THREAD_QOS_POLICY_OVERRIDE:
	{
		thread_qos_policy_t info = (thread_qos_policy_t)policy_info;

		if (*count < THREAD_QOS_POLICY_COUNT) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		if (!(*get_default)) {
			if (flavor == THREAD_QOS_POLICY_OVERRIDE) {
				info->qos_tier = thread->requested_policy.thrp_qos_override;
				/* TODO: handle importance overrides */
				info->tier_importance = 0;
			} else {
				info->qos_tier = thread->requested_policy.thrp_qos;
				info->tier_importance = thread->importance;
			}
		} else {
			info->qos_tier = THREAD_QOS_UNSPECIFIED;
			info->tier_importance = 0;
		}

		break;
	}

	default:
		result = KERN_INVALID_ARGUMENT;
		break;
	}

	thread_mtx_unlock(thread);

	return (result);
}

static volatile uint64_t unique_work_interval_id = 1; /* Start at 1, 0 is not a valid work interval ID */

kern_return_t
thread_policy_create_work_interval(
	thread_t		thread,
	uint64_t		*work_interval_id)
{
	thread_mtx_lock(thread);
	if (thread->work_interval_id) {
		/* already assigned a work interval ID */
		thread_mtx_unlock(thread);
		return (KERN_INVALID_VALUE);
	}

	thread->work_interval_id = OSIncrementAtomic64((volatile int64_t *)&unique_work_interval_id);
	*work_interval_id = thread->work_interval_id;

	thread_mtx_unlock(thread);
	return KERN_SUCCESS;
}

kern_return_t
thread_policy_destroy_work_interval(
	thread_t		thread,
	uint64_t		work_interval_id)
{
	thread_mtx_lock(thread);
	if (work_interval_id == 0 || thread->work_interval_id == 0 || thread->work_interval_id != work_interval_id) {
		/* work ID isn't valid or doesn't match previously assigned work interval ID */
		thread_mtx_unlock(thread);
		return (KERN_INVALID_ARGUMENT);
	}

	thread->work_interval_id = 0;

	thread_mtx_unlock(thread);
	return KERN_SUCCESS;
}

/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
#include <mach/task_server.h>

#include <kern/sched.h>
#include <kern/task.h>
#include <mach/thread_policy.h>
#include <sys/errno.h>
#include <sys/resource.h>
#include <machine/limits.h>
#include <kern/ledger.h>
#include <kern/thread_call.h>
#if CONFIG_TELEMETRY
#include <kern/telemetry.h>
#endif

#if IMPORTANCE_DEBUG
#include <mach/machine/sdt.h>
#endif /* IMPORTANCE_DEBUG */

#include <sys/kdebug.h>

/*
 *  Task Policy
 *
 *  This subsystem manages task and thread IO priority and backgrounding,
 *  as well as importance inheritance, process suppression, task QoS, and apptype.
 *  These properties have a suprising number of complex interactions, so they are
 *  centralized here in one state machine to simplify the implementation of those interactions.
 *
 *  Architecture:
 *  Threads and tasks have three policy fields: requested, effective, and pending.
 *  Requested represents the wishes of each interface that influences task policy.
 *  Effective represents the distillation of that policy into a set of behaviors.
 *  Pending represents updates that haven't been applied yet.
 *
 *  Each interface that has an input into the task policy state machine controls a field in requested.
 *  If the interface has a getter, it returns what is in the field in requested, but that is
 *  not necessarily what is actually in effect.
 *
 *  All kernel subsystems that behave differently based on task policy call into
 *  the get_effective_policy function, which returns the decision of the task policy state machine
 *  for that subsystem by querying only the 'effective' field.
 *
 *  Policy change operations:
 *  Here are the steps to change a policy on a task or thread:
 *  1) Lock task
 *  2) Change requested field for the relevant policy
 *  3) Run a task policy update, which recalculates effective based on requested,
 *     then takes a diff between the old and new versions of requested and calls the relevant
 *     other subsystems to apply these changes, and updates the pending field.
 *  4) Unlock task
 *  5) Run task policy update complete, which looks at the pending field to update
 *     subsystems which cannot be touched while holding the task lock.
 *
 *  To add a new requested policy, add the field in the requested struct, the flavor in task.h,
 *  the setter and getter in proc_(set|get)_task_policy*, and dump the state in task_requested_bitfield,
 *  then set up the effects of that behavior in task_policy_update*.
 *
 *  Most policies are set via proc_set_task_policy, but policies that don't fit that interface
 *  roll their own lock/set/update/unlock/complete code inside this file.
 *
 *
 *  Suppression policy
 *
 *  These are a set of behaviors that can be requested for a task.  They currently have specific
 *  implied actions when they're enabled, but they may be made customizable in the future.
 *
 *  When the affected task is boosted, we temporarily disable the suppression behaviors
 *  so that the affected process has a chance to run so it can call the API to permanently
 *  disable the suppression behaviors.
 *
 *  Locking
 *
 *  Changing task policy on a task or thread takes the task lock, and not the thread lock.
 *  TODO: Should changing policy on a thread take the thread lock instead?
 *
 *  Querying the effective policy does not take the task lock, to prevent deadlocks or slowdown in sensitive code.
 *  This means that any notification of state change needs to be externally synchronized.
 *
 */

/* for task holds without dropping the lock */
extern void task_hold_locked(task_t task);
extern void task_release_locked(task_t task);
extern void task_wait_locked(task_t task, boolean_t until_not_runnable);

/* Task policy related helper functions */
static void proc_set_task_policy_locked(task_t task, thread_t thread, int category, int flavor, int value);

static void task_policy_update_locked(task_t task, thread_t thread);
static void task_policy_update_internal_locked(task_t task, thread_t thread, boolean_t in_create);
static void task_policy_update_task_locked(task_t task, boolean_t update_throttle, boolean_t update_bg_throttle);
static void task_policy_update_thread_locked(thread_t thread, int update_cpu, boolean_t update_throttle);

static void task_policy_update_complete_unlocked(task_t task, thread_t thread);

static int proc_get_effective_policy(task_t task, thread_t thread, int policy);

static void proc_iopol_to_tier(int iopolicy, int *tier, int *passive);
static int proc_tier_to_iopol(int tier, int passive);

static uintptr_t trequested(task_t task, thread_t thread);
static uintptr_t teffective(task_t task, thread_t thread);
static uintptr_t tpending(task_t task, thread_t thread);
static uint64_t task_requested_bitfield(task_t task, thread_t thread);
static uint64_t task_effective_bitfield(task_t task, thread_t thread);
static uint64_t task_pending_bitfield(task_t task, thread_t thread);

void proc_get_thread_policy(thread_t thread, thread_policy_state_t info);

/* CPU Limits related helper functions */
static int task_get_cpuusage(task_t task, uint8_t *percentagep, uint64_t *intervalp, uint64_t *deadlinep, int *scope);
int task_set_cpuusage(task_t task, uint8_t percentage, uint64_t interval, uint64_t deadline, int scope, int entitled);
static int task_clear_cpuusage_locked(task_t task, int cpumon_entitled);
int task_disable_cpumon(task_t task);
static int task_apply_resource_actions(task_t task, int type);
void task_action_cpuusage(thread_call_param_t param0, thread_call_param_t param1);
void proc_init_cpumon_params(void);

#ifdef MACH_BSD
int             proc_pid(void *proc);
extern int      proc_selfpid(void);
extern char *   proc_name_address(void *p);
extern void     rethrottle_thread(void * uthread);
extern void     proc_apply_task_networkbg(void * bsd_info, thread_t thread, int bg);
#endif /* MACH_BSD */


/* Importance Inheritance related helper functions */

void task_importance_mark_receiver(task_t task, boolean_t receiving);

#if IMPORTANCE_INHERITANCE
static void task_update_boost_locked(task_t task, boolean_t boost_active);

static int task_importance_hold_assertion_locked(task_t target_task, int external, uint32_t count);
static int task_importance_drop_assertion_locked(task_t target_task, int external, uint32_t count);
#endif /* IMPORTANCE_INHERITANCE */

#if IMPORTANCE_DEBUG
#define __impdebug_only
#else
#define __impdebug_only __unused
#endif

#if IMPORTANCE_INHERITANCE
#define __imp_only
#else
#define __imp_only __unused
#endif

#define TASK_LOCKED   1
#define TASK_UNLOCKED 0

#define DO_LOWPRI_CPU   1
#define UNDO_LOWPRI_CPU 2

/* Macros for making tracing simpler */

#define tpriority(task, thread)  ((uintptr_t)(thread == THREAD_NULL ? (task->priority)  : (thread->priority)))
#define tisthread(thread) (thread == THREAD_NULL ? TASK_POLICY_TASK  : TASK_POLICY_THREAD)
#define targetid(task, thread)   ((uintptr_t)(thread == THREAD_NULL ? (audit_token_pid_from_task(task)) : (thread->thread_id)))

/*
 * Default parameters for certain policies
 */

int proc_standard_daemon_tier = THROTTLE_LEVEL_TIER1;
int proc_suppressed_disk_tier = THROTTLE_LEVEL_TIER1;
int proc_tal_disk_tier        = THROTTLE_LEVEL_TIER1;

int proc_graphics_timer_qos   = (LATENCY_QOS_TIER_0 & 0xFF);

const int proc_default_bg_iotier  = THROTTLE_LEVEL_TIER2;


const struct task_requested_policy default_task_requested_policy = {
	.bg_iotier = proc_default_bg_iotier
};
const struct task_effective_policy default_task_effective_policy = {};
const struct task_pended_policy default_task_pended_policy = {};

/*
 * Default parameters for CPU usage monitor.
 *
 * Default setting is 50% over 3 minutes.
 */
#define         DEFAULT_CPUMON_PERCENTAGE 50
#define         DEFAULT_CPUMON_INTERVAL   (3 * 60)

uint8_t         proc_max_cpumon_percentage;
uint64_t	proc_max_cpumon_interval;

static kern_return_t
task_qos_policy_validate(task_qos_policy_t qosinfo, mach_msg_type_number_t count) {
	if (count < TASK_QOS_POLICY_COUNT)
		return KERN_INVALID_ARGUMENT;

	task_latency_qos_t ltier = qosinfo->task_latency_qos_tier;
	task_throughput_qos_t ttier = qosinfo->task_throughput_qos_tier;

	if ((ltier != LATENCY_QOS_TIER_UNSPECIFIED) &&
	    ((ltier > LATENCY_QOS_TIER_5) || (ltier < LATENCY_QOS_TIER_0)))
		return KERN_INVALID_ARGUMENT;

	if ((ttier != THROUGHPUT_QOS_TIER_UNSPECIFIED) &&
	    ((ttier > THROUGHPUT_QOS_TIER_5) || (ttier < THROUGHPUT_QOS_TIER_0)))
		return KERN_INVALID_ARGUMENT;

	return KERN_SUCCESS;
}

static uint32_t
task_qos_extract(uint32_t qv) {
	return (qv & 0xFF);
}

static uint32_t
task_qos_latency_package(uint32_t qv) {
	return (qv == LATENCY_QOS_TIER_UNSPECIFIED) ? LATENCY_QOS_TIER_UNSPECIFIED : ((0xFF << 16) | qv);
}

static uint32_t
task_qos_throughput_package(uint32_t qv) {
	return (qv == THROUGHPUT_QOS_TIER_UNSPECIFIED) ? THROUGHPUT_QOS_TIER_UNSPECIFIED : ((0xFE << 16) | qv);
}

kern_return_t
task_policy_set(
	task_t					task,
	task_policy_flavor_t	flavor,
	task_policy_t			policy_info,
	mach_msg_type_number_t	count)
{
	kern_return_t		result = KERN_SUCCESS;

	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	switch (flavor) {

	case TASK_CATEGORY_POLICY: {
		task_category_policy_t info = (task_category_policy_t)policy_info;

		if (count < TASK_CATEGORY_POLICY_COUNT)
			return (KERN_INVALID_ARGUMENT);


		switch(info->role) {
			case TASK_FOREGROUND_APPLICATION:
			case TASK_BACKGROUND_APPLICATION:
			case TASK_DEFAULT_APPLICATION:
				proc_set_task_policy(task, THREAD_NULL,
				                     TASK_POLICY_ATTRIBUTE, TASK_POLICY_ROLE,
				                     info->role);
				break;

			case TASK_CONTROL_APPLICATION:
				if (task != current_task() || task->sec_token.val[0] != 0)
					result = KERN_INVALID_ARGUMENT;
				else
					proc_set_task_policy(task, THREAD_NULL,
					                     TASK_POLICY_ATTRIBUTE, TASK_POLICY_ROLE,
					                     info->role);
				break;

			case TASK_GRAPHICS_SERVER:
				/* TODO: Restrict this role to FCFS <rdar://problem/12552788> */
				if (task != current_task() || task->sec_token.val[0] != 0)
					result = KERN_INVALID_ARGUMENT;
				else
					proc_set_task_policy(task, THREAD_NULL,
					                     TASK_POLICY_ATTRIBUTE, TASK_POLICY_ROLE,
					                     info->role);
				break;
			default:
				result = KERN_INVALID_ARGUMENT;
				break;
		} /* switch (info->role) */

		break;
	}

/* Desired energy-efficiency/performance "quality-of-service" */
	case TASK_BASE_QOS_POLICY:
	{
		task_qos_policy_t qosinfo = (task_qos_policy_t)policy_info;
		kern_return_t kr = task_qos_policy_validate(qosinfo, count);

		if (kr != KERN_SUCCESS)
			return kr;

		task_lock(task);

		/* This uses the latency QoS tracepoint, even though we might be changing both */
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		                          (IMPORTANCE_CODE(TASK_POLICY_LATENCY_QOS, (TASK_POLICY_ATTRIBUTE | TASK_POLICY_TASK))) | DBG_FUNC_START,
		                          proc_selfpid(), targetid(task, THREAD_NULL), trequested(task, THREAD_NULL), 0, 0);

		task->requested_policy.t_base_latency_qos = task_qos_extract(qosinfo->task_latency_qos_tier);
		task->requested_policy.t_base_through_qos = task_qos_extract(qosinfo->task_throughput_qos_tier);

		task_policy_update_locked(task, THREAD_NULL);

		task_unlock(task);

		task_policy_update_complete_unlocked(task, THREAD_NULL);

		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		                          (IMPORTANCE_CODE(TASK_POLICY_LATENCY_QOS, (TASK_POLICY_ATTRIBUTE | TASK_POLICY_TASK))) | DBG_FUNC_END,
		                          proc_selfpid(), targetid(task, THREAD_NULL), trequested(task, THREAD_NULL), 0, 0);
	}
		break;

	case TASK_OVERRIDE_QOS_POLICY:
	{
		task_qos_policy_t qosinfo = (task_qos_policy_t)policy_info;
		kern_return_t kr = task_qos_policy_validate(qosinfo, count);

		if (kr != KERN_SUCCESS)
			return kr;

		task_lock(task);

		/* This uses the latency QoS tracepoint, even though we might be changing both */
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		                          (IMPORTANCE_CODE(TASK_POLICY_LATENCY_QOS, (TASK_POLICY_ATTRIBUTE | TASK_POLICY_TASK))) | DBG_FUNC_START,
		                          proc_selfpid(), targetid(task, THREAD_NULL), trequested(task, THREAD_NULL), 0, 0);

		task->requested_policy.t_over_latency_qos = task_qos_extract(qosinfo->task_latency_qos_tier);
		task->requested_policy.t_over_through_qos = task_qos_extract(qosinfo->task_throughput_qos_tier);

		task_policy_update_locked(task, THREAD_NULL);

		task_unlock(task);

		task_policy_update_complete_unlocked(task, THREAD_NULL);

		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		                          (IMPORTANCE_CODE(TASK_POLICY_LATENCY_QOS, (TASK_POLICY_ATTRIBUTE | TASK_POLICY_TASK))) | DBG_FUNC_END,
		                          proc_selfpid(), targetid(task, THREAD_NULL), trequested(task, THREAD_NULL), 0, 0);		
	}
		break;

	case TASK_SUPPRESSION_POLICY:
	{

		task_suppression_policy_t info = (task_suppression_policy_t)policy_info;

		if (count < TASK_SUPPRESSION_POLICY_COUNT)
			return (KERN_INVALID_ARGUMENT);

		struct task_qos_policy qosinfo;

		qosinfo.task_latency_qos_tier = info->timer_throttle;
		qosinfo.task_throughput_qos_tier = info->throughput_qos;

		kern_return_t kr = task_qos_policy_validate(&qosinfo, TASK_QOS_POLICY_COUNT);

		if (kr != KERN_SUCCESS)
			return kr;

		task_lock(task);

		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		                          (IMPORTANCE_CODE(IMP_TASK_SUPPRESSION, info->active)) | DBG_FUNC_START,
		                          proc_selfpid(), audit_token_pid_from_task(task), trequested(task, THREAD_NULL),
		                          0, 0);

		task->requested_policy.t_sup_active      = (info->active)         ? 1 : 0;
		task->requested_policy.t_sup_lowpri_cpu  = (info->lowpri_cpu)     ? 1 : 0;
		task->requested_policy.t_sup_timer       = task_qos_extract(info->timer_throttle);
		task->requested_policy.t_sup_disk        = (info->disk_throttle)  ? 1 : 0;
		task->requested_policy.t_sup_cpu_limit   = (info->cpu_limit)      ? 1 : 0;
		task->requested_policy.t_sup_suspend     = (info->suspend)        ? 1 : 0;
		task->requested_policy.t_sup_throughput  = task_qos_extract(info->throughput_qos);
		task->requested_policy.t_sup_cpu         = (info->suppressed_cpu) ? 1 : 0;

		task_policy_update_locked(task, THREAD_NULL);

		task_unlock(task);

		task_policy_update_complete_unlocked(task, THREAD_NULL);

		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		                          (IMPORTANCE_CODE(IMP_TASK_SUPPRESSION, info->active)) | DBG_FUNC_END,
		                          proc_selfpid(), audit_token_pid_from_task(task), trequested(task, THREAD_NULL),
		                          0, 0);

		break;

	}

	default:
		result = KERN_INVALID_ARGUMENT;
		break;
	}

	return (result);
}

/* Sets BSD 'nice' value on the task */
kern_return_t
task_importance(
	task_t				task,
	integer_t			importance)
{
	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);

	if (!task->active) {
		task_unlock(task);

		return (KERN_TERMINATED);
	}

	if (proc_get_effective_task_policy(task, TASK_POLICY_ROLE) >= TASK_CONTROL_APPLICATION) {
		task_unlock(task);

		return (KERN_INVALID_ARGUMENT);
	}

	task->importance = importance;

	/* TODO: tracepoint? */

	/* Redrive only the task priority calculation */
	task_policy_update_task_locked(task, FALSE, FALSE);

	task_unlock(task);

	return (KERN_SUCCESS);
}

kern_return_t
task_policy_get(
	task_t					task,
	task_policy_flavor_t	flavor,
	task_policy_t			policy_info,
	mach_msg_type_number_t	*count,
	boolean_t				*get_default)
{
	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	switch (flavor) {

	case TASK_CATEGORY_POLICY:
	{
		task_category_policy_t		info = (task_category_policy_t)policy_info;

		if (*count < TASK_CATEGORY_POLICY_COUNT)
			return (KERN_INVALID_ARGUMENT);

		if (*get_default)
			info->role = TASK_UNSPECIFIED;
		else
			info->role = proc_get_task_policy(task, THREAD_NULL, TASK_POLICY_ATTRIBUTE, TASK_POLICY_ROLE);
		break;
	}

	case TASK_BASE_QOS_POLICY: /* FALLTHRU */
	case TASK_OVERRIDE_QOS_POLICY:
	{
		task_qos_policy_t info = (task_qos_policy_t)policy_info;

		if (*count < TASK_QOS_POLICY_COUNT)
			return (KERN_INVALID_ARGUMENT);

		if (*get_default) {
			info->task_latency_qos_tier = LATENCY_QOS_TIER_UNSPECIFIED;
			info->task_throughput_qos_tier = THROUGHPUT_QOS_TIER_UNSPECIFIED;
		} else if (flavor == TASK_BASE_QOS_POLICY) {
			task_lock(task);

			info->task_latency_qos_tier    = task_qos_latency_package(task->requested_policy.t_base_latency_qos);
			info->task_throughput_qos_tier = task_qos_throughput_package(task->requested_policy.t_base_through_qos);

			task_unlock(task);
		} else if (flavor == TASK_OVERRIDE_QOS_POLICY) {
			task_lock(task);

			info->task_latency_qos_tier    = task_qos_latency_package(task->requested_policy.t_over_latency_qos);
			info->task_throughput_qos_tier = task_qos_throughput_package(task->requested_policy.t_over_through_qos);

			task_unlock(task);
		}

		break;
	}

	case TASK_POLICY_STATE:
	{
		task_policy_state_t info = (task_policy_state_t)policy_info;

		if (*count < TASK_POLICY_STATE_COUNT)
			return (KERN_INVALID_ARGUMENT);

		/* Only root can get this info */
		if (current_task()->sec_token.val[0] != 0)
			return KERN_PROTECTION_FAILURE;

		task_lock(task);

		if (*get_default) {
			info->requested = 0;
			info->effective = 0;
			info->pending = 0;
			info->imp_assertcnt = 0;
			info->imp_externcnt = 0;
			info->flags = 0;
		} else {
			info->requested = task_requested_bitfield(task, THREAD_NULL);
			info->effective = task_effective_bitfield(task, THREAD_NULL);
			info->pending   = task_pending_bitfield(task, THREAD_NULL);
			info->imp_assertcnt = task->task_imp_assertcnt;
			info->imp_externcnt = task->task_imp_externcnt;
			
			info->flags = 0;
			info->flags |= (task->imp_receiver      ? TASK_IMP_RECEIVER : 0);
			info->flags |= (task->imp_donor         ? TASK_IMP_DONOR    : 0);
		}

		task_unlock(task);

		break;
	}

	case TASK_SUPPRESSION_POLICY:
	{
		task_suppression_policy_t info = (task_suppression_policy_t)policy_info;

		if (*count < TASK_SUPPRESSION_POLICY_COUNT)
			return (KERN_INVALID_ARGUMENT);

		task_lock(task);

		if (*get_default) {
			info->active            = 0;
			info->lowpri_cpu        = 0;
			info->timer_throttle    = LATENCY_QOS_TIER_UNSPECIFIED;
			info->disk_throttle     = 0;
			info->cpu_limit         = 0;
			info->suspend           = 0;
			info->throughput_qos    = 0;
			info->suppressed_cpu    = 0;
		} else {
			info->active            = task->requested_policy.t_sup_active;
			info->lowpri_cpu        = task->requested_policy.t_sup_lowpri_cpu;
			info->timer_throttle    = task_qos_latency_package(task->requested_policy.t_sup_timer);
			info->disk_throttle     = task->requested_policy.t_sup_disk;
			info->cpu_limit         = task->requested_policy.t_sup_cpu_limit;
			info->suspend           = task->requested_policy.t_sup_suspend;
			info->throughput_qos    = task_qos_throughput_package(task->requested_policy.t_sup_throughput);
			info->suppressed_cpu    = task->requested_policy.t_sup_cpu;
		}

		task_unlock(task);
		break;
	}

	default:
		return (KERN_INVALID_ARGUMENT);
	}

	return (KERN_SUCCESS);
}

/*
 * Called at task creation
 * We calculate the correct effective but don't apply it to anything yet.
 * The threads, etc will inherit from the task as they get created.
 */
void
task_policy_create(task_t task, int parent_boosted)
{
	if (task->requested_policy.t_apptype == TASK_APPTYPE_DAEMON_ADAPTIVE) {
		if (parent_boosted) {
			task->requested_policy.t_apptype = TASK_APPTYPE_DAEMON_INTERACTIVE;
			task_importance_mark_donor(task, TRUE);
		} else {
			task->requested_policy.t_apptype = TASK_APPTYPE_DAEMON_BACKGROUND;
			task_importance_mark_receiver(task, FALSE);
		}
	}

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	                          (IMPORTANCE_CODE(IMP_UPDATE, (IMP_UPDATE_TASK_CREATE | TASK_POLICY_TASK))) | DBG_FUNC_START,
	                          proc_selfpid(), audit_token_pid_from_task(task),
	                          teffective(task, THREAD_NULL), tpriority(task, THREAD_NULL), 0);

	task_policy_update_internal_locked(task, THREAD_NULL, TRUE);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	                          (IMPORTANCE_CODE(IMP_UPDATE, (IMP_UPDATE_TASK_CREATE | TASK_POLICY_TASK))) | DBG_FUNC_END,
	                          proc_selfpid(), audit_token_pid_from_task(task),
	                          teffective(task, THREAD_NULL), tpriority(task, THREAD_NULL), 0);
}

static void
task_policy_update_locked(task_t task, thread_t thread)
{
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	                          (IMPORTANCE_CODE(IMP_UPDATE, tisthread(thread)) | DBG_FUNC_START),
	                          proc_selfpid(), targetid(task, thread),
	                          teffective(task, thread), tpriority(task, thread), 0);

	task_policy_update_internal_locked(task, thread, FALSE);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	                          (IMPORTANCE_CODE(IMP_UPDATE, tisthread(thread))) | DBG_FUNC_END,
	                          proc_selfpid(), targetid(task, thread),
	                          teffective(task, thread), tpriority(task, thread), 0);
}

/*
 * One state update function TO RULE THEM ALL
 *
 * This function updates the task or thread effective policy fields
 * and pushes the results to the relevant subsystems.
 *
 * Must call update_complete after unlocking the task,
 * as some subsystems cannot be updated while holding the task lock.
 *
 * Called with task locked, not thread
 */
static void
task_policy_update_internal_locked(task_t task, thread_t thread, boolean_t in_create)
{
	boolean_t on_task = (thread == THREAD_NULL) ? TRUE : FALSE;

	/*
	 * Step 1:
	 *  Gather requested policy
	 */

	struct task_requested_policy requested =
	        (on_task) ? task->requested_policy : thread->requested_policy;

	/*
	 * Step 2:
	 *  Calculate new effective policies from requested policy and task state
	 *  Rules:
	 *      If in an 'on_task' block, must only look at and set fields starting with t_
	 *      If operating on a task, don't touch anything starting with th_
	 *      If operating on a thread, don't touch anything starting with t_
	 *      Don't change requested, it won't take effect
	 */

	struct task_effective_policy next = {};

	/* Calculate DARWIN_BG */
	boolean_t wants_darwinbg        = FALSE;
	boolean_t wants_all_sockets_bg  = FALSE; /* Do I want my existing sockets to be bg */
	boolean_t wants_watchersbg      = FALSE; /* Do I want my pidbound threads to be bg */
	boolean_t wants_tal             = FALSE; /* Do I want the effects of TAL mode */
	/*
	 * If DARWIN_BG has been requested at either level, it's engaged.
	 * Only true DARWIN_BG changes cause watchers to transition.
	 */
	if (requested.int_darwinbg || requested.ext_darwinbg)
		wants_watchersbg = wants_all_sockets_bg = wants_darwinbg = TRUE;

	if (on_task) {
		/* Background TAL apps are throttled when TAL is enabled */
		if (requested.t_apptype      == TASK_APPTYPE_APP_TAL &&
		    requested.t_role         == TASK_BACKGROUND_APPLICATION &&
		    requested.t_tal_enabled  == 1) {
			wants_tal = TRUE;
			next.t_tal_engaged = 1;
		}

		/* Adaptive daemons are DARWIN_BG unless boosted, and don't get network throttled. */
		if (requested.t_apptype == TASK_APPTYPE_DAEMON_ADAPTIVE &&
		    requested.t_boosted == 0)
			wants_darwinbg = TRUE;

		/* Background daemons are always DARWIN_BG, no exceptions, and don't get network throttled. */
		if (requested.t_apptype == TASK_APPTYPE_DAEMON_BACKGROUND)
			wants_darwinbg = TRUE;
	} else {
		if (requested.th_pidbind_bg)
			wants_all_sockets_bg = wants_darwinbg = TRUE;

		if (requested.th_workq_bg)
			wants_darwinbg = TRUE;
	}

	/* Calculate side effects of DARWIN_BG */

	if (wants_darwinbg) {
		next.darwinbg = 1;
		/* darwinbg threads/tasks always create bg sockets, but we don't always loop over all sockets */
		next.new_sockets_bg = 1;
		next.lowpri_cpu = 1;
	}

	if (wants_all_sockets_bg)
		next.all_sockets_bg = 1;

	if (on_task && wants_watchersbg)
		next.t_watchers_bg = 1;

	/* Calculate low CPU priority */

	boolean_t wants_lowpri_cpu = FALSE;

	if (wants_darwinbg || wants_tal)
		wants_lowpri_cpu = TRUE;

	if (on_task && requested.t_sup_lowpri_cpu && requested.t_boosted == 0)
		wants_lowpri_cpu = TRUE;

	if (wants_lowpri_cpu)
		next.lowpri_cpu = 1;

	/* Calculate IO policy */

	/* Update BG IO policy (so we can see if it has changed) */
	next.bg_iotier = requested.bg_iotier;

	int iopol = THROTTLE_LEVEL_TIER0;

	if (wants_darwinbg)
		iopol = MAX(iopol, requested.bg_iotier);

	if (on_task) {
		if (requested.t_apptype == TASK_APPTYPE_DAEMON_STANDARD)
			iopol = MAX(iopol, proc_standard_daemon_tier);

		if (requested.t_sup_disk && requested.t_boosted == 0)
			iopol = MAX(iopol, proc_suppressed_disk_tier);

		if (wants_tal)
			iopol = MAX(iopol, proc_tal_disk_tier);
	}

	iopol = MAX(iopol, requested.int_iotier);
	iopol = MAX(iopol, requested.ext_iotier);

	next.io_tier = iopol;

	/* Calculate Passive IO policy */

	if (requested.ext_iopassive || requested.int_iopassive)
		next.io_passive = 1;

	/* Calculate miscellaneous policy */

	if (on_task) {
		/* Update role */
		next.t_role = requested.t_role;

		/* Calculate suppression-active flag */
		if (requested.t_sup_active && requested.t_boosted == 0)
			next.t_sup_active = 1;

		/* Calculate suspend policy */
		if (requested.t_sup_suspend && requested.t_boosted == 0)
			next.t_suspended = 1;

		/* Calculate GPU Access policy */
		if (requested.t_int_gpu_deny || requested.t_ext_gpu_deny)
			next.t_gpu_deny = 1;


		/* Calculate timer QOS */
		int latency_qos = requested.t_base_latency_qos;

		if (requested.t_sup_timer && requested.t_boosted == 0)
			latency_qos = requested.t_sup_timer;

		if (requested.t_over_latency_qos != 0)
			latency_qos = requested.t_over_latency_qos;

		/* Treat the windowserver special */
		if (requested.t_role == TASK_GRAPHICS_SERVER)
			latency_qos = proc_graphics_timer_qos;

		next.t_latency_qos = latency_qos;

		/* Calculate throughput QOS */
		int through_qos = requested.t_base_through_qos;

		if (requested.t_sup_throughput && requested.t_boosted == 0)
			through_qos = requested.t_sup_throughput;

		if (requested.t_over_through_qos != 0)
			through_qos = requested.t_over_through_qos;

		next.t_through_qos = through_qos;

		/* Calculate suppressed CPU priority */
		if (requested.t_sup_cpu && requested.t_boosted == 0)
			next.t_suppressed_cpu = 1;
	}

	if (requested.terminated) {
		/*
		 * Shoot down the throttles that slow down exit or response to SIGTERM
		 * We don't need to shoot down:
		 * passive        (don't want to cause others to throttle)
		 * all_sockets_bg (don't need to iterate FDs on every exit)
		 * new_sockets_bg (doesn't matter for exiting process)
		 * gpu deny       (doesn't matter for exiting process)
		 * pidsuspend     (jetsam-ed BG process shouldn't run again)
		 * watchers_bg    (watcher threads don't need to be unthrottled)
		 * t_latency_qos  (affects userspace timers only)
		 */

		next.terminated         = 1;
		next.darwinbg           = 0;
		next.lowpri_cpu         = 0;
		next.io_tier            = THROTTLE_LEVEL_TIER0;
		if (on_task) {
			next.t_tal_engaged = 0;
			next.t_role = TASK_UNSPECIFIED;
			next.t_suppressed_cpu = 0;

			/* TODO: This should only be shot down on SIGTERM, not exit */
			next.t_suspended   = 0;
		}
	}

	/*
	 * Step 3:
	 *  Swap out old policy for new policy
	 */

	struct task_effective_policy prev =
	        (on_task) ? task->effective_policy : thread->effective_policy;

	/*
	 * Check for invalid transitions here for easier debugging
	 * TODO: dump the structs as hex in the panic string
	 */
	if (task == kernel_task && prev.all_sockets_bg != next.all_sockets_bg)
		panic("unexpected network change for kernel task");

	/* This is the point where the new values become visible to other threads */
	if (on_task)
		task->effective_policy = next;
	else
		thread->effective_policy = next;

	/* Don't do anything further to a half-formed task or thread */
	if (in_create)
		return;

	/*
	 * Step 4:
	 *  Pend updates that can't be done while holding the task lock
	 *  Preserve pending updates that may still be waiting to be applied
	 */

	struct task_pended_policy pended =
		(on_task) ? task->pended_policy : thread->pended_policy;

	if (prev.all_sockets_bg != next.all_sockets_bg)
		pended.update_sockets = 1;

	if (on_task) {
		/* Only re-scan the timer list if the qos level is getting less strong */
		if (prev.t_latency_qos > next.t_latency_qos)
			pended.t_update_timers = 1;

	}

	if (on_task)
		task->pended_policy = pended;
	else
		thread->pended_policy = pended;

	/*
	 * Step 5:
	 *  Update other subsystems as necessary if something has changed
	 */

	boolean_t update_throttle = (prev.io_tier != next.io_tier) ? TRUE : FALSE;

	if (on_task) {
		if (prev.t_suspended == 0 && next.t_suspended == 1 && task->active) {
			task_hold_locked(task);
			task_wait_locked(task, FALSE);
		}
		if (prev.t_suspended == 1 && next.t_suspended == 0 && task->active) {
			task_release_locked(task);
		}

		boolean_t update_threads = FALSE;

		if (prev.bg_iotier != next.bg_iotier)
			update_threads = TRUE;

		if (prev.terminated != next.terminated)
			update_threads = TRUE;

		task_policy_update_task_locked(task, update_throttle, update_threads);
	} else {
		int update_cpu = 0;

		if (prev.lowpri_cpu != next.lowpri_cpu)
			update_cpu = (next.lowpri_cpu ? DO_LOWPRI_CPU : UNDO_LOWPRI_CPU);

		task_policy_update_thread_locked(thread, update_cpu, update_throttle);
	}
}

/* Despite the name, the thread's task is locked, the thread is not */
static void
task_policy_update_thread_locked(thread_t thread,
                                 int update_cpu,
                                 boolean_t update_throttle)
{
	thread_precedence_policy_data_t policy;

	if (update_throttle) {
		rethrottle_thread(thread->uthread);
	}

	/*
	 * TODO: pidbind needs to stuff remembered importance into saved_importance
	 * properly deal with bg'ed threads being pidbound and unbging while pidbound
	 *
	 * TODO: A BG thread's priority is 0 on desktop and 4 on embedded.  Need to reconcile this.
	 * */
	if (update_cpu == DO_LOWPRI_CPU) {
		thread->saved_importance = thread->importance;
		policy.importance = INT_MIN;
	} else if (update_cpu == UNDO_LOWPRI_CPU) {
		policy.importance = thread->saved_importance;
		thread->saved_importance = 0;
	}

	/* Takes thread lock and thread mtx lock */
	if (update_cpu)
		thread_policy_set_internal(thread, THREAD_PRECEDENCE_POLICY,
                                           (thread_policy_t)&policy,
                                           THREAD_PRECEDENCE_POLICY_COUNT);
}

/*
 * Calculate priority on a task, loop through its threads, and tell them about
 * priority changes and throttle changes.
 */
static void
task_policy_update_task_locked(task_t    task,
                               boolean_t update_throttle,
                               boolean_t update_threads)
{
	boolean_t update_priority = FALSE;

	if (task == kernel_task)
		panic("Attempting to set task policy on kernel_task");

	int priority     = BASEPRI_DEFAULT;
	int max_priority = MAXPRI_USER;

	if (proc_get_effective_task_policy(task, TASK_POLICY_LOWPRI_CPU)) {
		priority = MAXPRI_THROTTLE;
		max_priority = MAXPRI_THROTTLE;
	} else if (proc_get_effective_task_policy(task, TASK_POLICY_SUPPRESSED_CPU)) {
		priority = MAXPRI_SUPPRESSED;
		max_priority = MAXPRI_SUPPRESSED;
	} else {
		switch (proc_get_effective_task_policy(task, TASK_POLICY_ROLE)) {
			case TASK_FOREGROUND_APPLICATION:
				priority = BASEPRI_FOREGROUND;
				break;
			case TASK_BACKGROUND_APPLICATION:
				priority = BASEPRI_BACKGROUND;
				break;
			case TASK_CONTROL_APPLICATION:
				priority = BASEPRI_CONTROL;
				break;
			case TASK_GRAPHICS_SERVER:
				priority = BASEPRI_GRAPHICS;
				max_priority = MAXPRI_RESERVED;
				break;
			default:
				break;
		}

		/* factor in 'nice' value */
		priority += task->importance;
	}

	/* avoid extra work if priority isn't changing */
	if (task->priority != priority || task->max_priority != max_priority) {
		update_priority = TRUE;

		/* update the scheduling priority for the task */
		task->max_priority = max_priority;

		if (priority > task->max_priority)
			priority = task->max_priority;
		else if (priority < MINPRI)
			priority = MINPRI;

		task->priority = priority;
	}

	/* Loop over the threads in the task only once, and only if necessary */
	if (update_threads || update_throttle || update_priority ) {
		thread_t thread;

		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			if (update_priority) {
				thread_mtx_lock(thread);

				if (thread->active)
					thread_task_priority(thread, priority, max_priority);

				thread_mtx_unlock(thread);
			}

			if (update_throttle) {
				rethrottle_thread(thread->uthread);
			}

			if (update_threads) {
				thread->requested_policy.bg_iotier  = task->effective_policy.bg_iotier;
				thread->requested_policy.terminated = task->effective_policy.terminated;

				task_policy_update_internal_locked(task, thread, FALSE);
				/*  The thread policy must not emit any completion actions due to this change. */
			}
		}
	}
}

/*
 * Called with task unlocked to do things that can't be done while holding the task lock
 * To keep things consistent, only one thread can make progress through here at a time for any one task.
 *
 * TODO: tracepoints
 */
static void
task_policy_update_complete_unlocked(task_t task, thread_t thread)
{
	boolean_t on_task = (thread == THREAD_NULL) ? TRUE : FALSE;

	task_lock(task);

	while (task->pended_policy.t_updating_policy != 0) {
		assert_wait((event_t)&task->pended_policy, THREAD_UNINT);
		task_unlock(task);
		thread_block(THREAD_CONTINUE_NULL);
		task_lock(task);
	}

	/* Take a snapshot of the current state */

	struct task_pended_policy pended =
		(on_task) ? task->pended_policy : thread->pended_policy;

	struct task_effective_policy effective =
		(on_task) ? task->effective_policy : thread->effective_policy;
	
	/* Mark the pended operations as being handled */
	if (on_task)
		task->pended_policy = default_task_pended_policy;
	else
		thread->pended_policy = default_task_pended_policy;

	task->pended_policy.t_updating_policy = 1;

	task_unlock(task);

	/* Update the other subsystems with the new state */

#ifdef MACH_BSD
	if (pended.update_sockets)
		proc_apply_task_networkbg(task->bsd_info, thread, effective.all_sockets_bg);
#endif /* MACH_BSD */

	if (on_task) {
		/* The timer throttle has been removed, we need to look for expired timers and fire them */
		if (pended.t_update_timers)
			ml_timer_evaluate();

	}

	/* Wake up anyone waiting to make another update */
	task_lock(task);
	task->pended_policy.t_updating_policy = 0;
	thread_wakeup(&task->pended_policy);
	task_unlock(task);
}

/*
 * Initiate a task policy state transition
 *
 * Everything that modifies requested except functions that need to hold the task lock
 * should use this function
 *
 * Argument validation should be performed before reaching this point.
 *
 * TODO: Do we need to check task->active or thread->active?
 */
void
proc_set_task_policy(task_t     task,
                     thread_t   thread,
                     int        category,
                     int        flavor,
                     int        value)
{
	task_lock(task);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	                          (IMPORTANCE_CODE(flavor, (category | tisthread(thread)))) | DBG_FUNC_START,
	                          proc_selfpid(), targetid(task, thread), trequested(task, thread), value, 0);

	proc_set_task_policy_locked(task, thread, category, flavor, value);

	task_policy_update_locked(task, thread);

	task_unlock(task);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	                          (IMPORTANCE_CODE(flavor, (category | tisthread(thread)))) | DBG_FUNC_END,
	                          proc_selfpid(), targetid(task, thread), trequested(task, thread), tpending(task, thread), 0);

	task_policy_update_complete_unlocked(task, thread);
}

/*
 * Initiate a task policy state transition on a thread with its TID
 * Useful if you cannot guarantee the thread won't get terminated
 */
void
proc_set_task_policy_thread(task_t     task,
                            uint64_t   tid,
                            int        category,
                            int        flavor,
                            int        value)
{
	thread_t thread;
	thread_t self = current_thread();

	task_lock(task);

	if (tid == TID_NULL || tid == self->thread_id)
		thread = self;
	else
		thread = task_findtid(task, tid);

	if (thread == THREAD_NULL) {
		task_unlock(task);
		return;
	}

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	                          (IMPORTANCE_CODE(flavor, (category | TASK_POLICY_THREAD))) | DBG_FUNC_START,
	                          proc_selfpid(), targetid(task, thread), trequested(task, thread), value, 0);

	proc_set_task_policy_locked(task, thread, category, flavor, value);

	task_policy_update_locked(task, thread);

	task_unlock(task);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	                          (IMPORTANCE_CODE(flavor, (category | TASK_POLICY_THREAD))) | DBG_FUNC_END,
	                          proc_selfpid(), targetid(task, thread), trequested(task, thread), tpending(task, thread), 0);

	task_policy_update_complete_unlocked(task, thread);
}


/*
 * Set the requested state for a specific flavor to a specific value.
 *
 *  TODO:
 *  Verify that arguments to non iopol things are 1 or 0
 */
static void
proc_set_task_policy_locked(task_t      task,
                            thread_t    thread,
                            int         category,
                            int         flavor,
                            int         value)
{
	boolean_t on_task = (thread == THREAD_NULL) ? TRUE : FALSE;

	int tier, passive;

	struct task_requested_policy requested =
	        (on_task) ? task->requested_policy : thread->requested_policy;

	switch (flavor) {

	/* Category: EXTERNAL and INTERNAL, thread and task */

		case TASK_POLICY_DARWIN_BG:
			if (category == TASK_POLICY_EXTERNAL)
				requested.ext_darwinbg = value;
			else
				requested.int_darwinbg = value;
			break;

		case TASK_POLICY_IOPOL:
			proc_iopol_to_tier(value, &tier, &passive);
			if (category == TASK_POLICY_EXTERNAL) {
				requested.ext_iotier  = tier;
				requested.ext_iopassive = passive;
			} else {
				requested.int_iotier  = tier;
				requested.int_iopassive = passive;
			}
			break;

		case TASK_POLICY_IO:
			if (category == TASK_POLICY_EXTERNAL)
				requested.ext_iotier = value;
			else
				requested.int_iotier = value;
			break;

		case TASK_POLICY_PASSIVE_IO:
			if (category == TASK_POLICY_EXTERNAL)
				requested.ext_iopassive = value;
			else
				requested.int_iopassive = value;
			break;

	/* Category: EXTERNAL and INTERNAL, task only */

		case TASK_POLICY_GPU_DENY:
			assert(on_task);
			if (category == TASK_POLICY_EXTERNAL)
				requested.t_ext_gpu_deny = value;
			else
				requested.t_int_gpu_deny = value;
			break;

		case TASK_POLICY_DARWIN_BG_AND_GPU:
			assert(on_task);
			if (category == TASK_POLICY_EXTERNAL) {
				requested.ext_darwinbg = value;
				requested.t_ext_gpu_deny = value;
			} else {
				requested.int_darwinbg = value;
				requested.t_int_gpu_deny = value;
			}
			break;

	/* Category: INTERNAL, task only */			

		case TASK_POLICY_DARWIN_BG_IOPOL:
			assert(on_task && category == TASK_POLICY_INTERNAL);
			proc_iopol_to_tier(value, &tier, &passive);
			requested.bg_iotier = tier;
			break;

	/* Category: ATTRIBUTE, task only */

		case TASK_POLICY_TAL:
			assert(on_task && category == TASK_POLICY_ATTRIBUTE);
			requested.t_tal_enabled = value;
			break;

		case TASK_POLICY_BOOST:
			assert(on_task && category == TASK_POLICY_ATTRIBUTE);
			requested.t_boosted = value;
			break;

		case TASK_POLICY_ROLE:
			assert(on_task && category == TASK_POLICY_ATTRIBUTE);
			requested.t_role = value;
			break;

		case TASK_POLICY_TERMINATED:
			assert(on_task && category == TASK_POLICY_ATTRIBUTE);
			requested.terminated = value;
			break;

	/* Category: ATTRIBUTE, thread only */

		case TASK_POLICY_PIDBIND_BG:
			assert(!on_task && category == TASK_POLICY_ATTRIBUTE);
			requested.th_pidbind_bg = value;
			break;

		case TASK_POLICY_WORKQ_BG:
			assert(!on_task && category == TASK_POLICY_ATTRIBUTE);
			requested.th_workq_bg = value;
			break;

		default:
			panic("unknown task policy: %d %d %d", category, flavor, value);
			break;
	}

	if (on_task)
		task->requested_policy = requested;
	else
		thread->requested_policy = requested;
}


/*
 * Gets what you set. Effective values may be different.
 */
int
proc_get_task_policy(task_t     task,
                     thread_t   thread,
                     int        category,
                     int        flavor)
{
	boolean_t on_task = (thread == THREAD_NULL) ? TRUE : FALSE;

	int value = 0;

	task_lock(task);

	struct task_requested_policy requested =
	        (on_task) ? task->requested_policy : thread->requested_policy;

	switch (flavor) {
		case TASK_POLICY_DARWIN_BG:
			if (category == TASK_POLICY_EXTERNAL)
				value = requested.ext_darwinbg;
			else
				value = requested.int_darwinbg;
			break;
		case TASK_POLICY_IOPOL:
			if (category == TASK_POLICY_EXTERNAL)
				value = proc_tier_to_iopol(requested.ext_iotier,
				                            requested.ext_iopassive);
			else
				value = proc_tier_to_iopol(requested.int_iotier,
				                            requested.int_iopassive);
			break;
		case TASK_POLICY_IO:
			if (category == TASK_POLICY_EXTERNAL)
				value = requested.ext_iotier;
			else
				value = requested.int_iotier;
			break;
		case TASK_POLICY_PASSIVE_IO:
			if (category == TASK_POLICY_EXTERNAL)
				value = requested.ext_iopassive;
			else
				value = requested.int_iopassive;
			break;
		case TASK_POLICY_GPU_DENY:
			assert(on_task);
			if (category == TASK_POLICY_EXTERNAL)
				value = requested.t_ext_gpu_deny;
			else
				value = requested.t_int_gpu_deny;
			break;
		case TASK_POLICY_DARWIN_BG_IOPOL:
			assert(on_task && category == TASK_POLICY_ATTRIBUTE);
			value = proc_tier_to_iopol(requested.bg_iotier, 0);
			break;
		case TASK_POLICY_ROLE:
			assert(on_task && category == TASK_POLICY_ATTRIBUTE);
			value = requested.t_role;
			break;
		default:
			panic("unknown policy_flavor %d", flavor);
			break;
	}

	task_unlock(task);

	return value;
}


/*
 * Functions for querying effective state for relevant subsystems
 * ONLY the relevant subsystem should query these.
 * NEVER take a value from one of the 'effective' functions and stuff it into a setter.
 */

int
proc_get_effective_task_policy(task_t task, int flavor)
{
	return proc_get_effective_policy(task, THREAD_NULL, flavor);
}

int
proc_get_effective_thread_policy(thread_t thread, int flavor)
{
	return proc_get_effective_policy(thread->task, thread, flavor);
}

/*
 * Gets what is actually in effect, for subsystems which pull policy instead of receive updates.
 *
 * NOTE: This accessor does not take the task lock.
 * Notifications of state updates need to be externally synchronized with state queries.
 * This routine *MUST* remain interrupt safe, as it is potentially invoked
 * within the context of a timer interrupt.
 */
static int
proc_get_effective_policy(task_t   task,
                          thread_t thread,
                          int      flavor)
{
	boolean_t on_task = (thread == THREAD_NULL) ? TRUE : FALSE;
	int value = 0;

	switch (flavor) {
		case TASK_POLICY_DARWIN_BG:
			/*
			 * This backs the KPI call proc_pidbackgrounded to find
			 * out if a pid is backgrounded,
			 * as well as proc_get_effective_thread_policy. 
			 * Its main use is within the timer layer, as well as
			 * prioritizing requests to the graphics system.
			 * Returns 1 for background mode, 0 for normal mode
			 */
			if (on_task)
				value = task->effective_policy.darwinbg;
			else
				value = (task->effective_policy.darwinbg ||
				          thread->effective_policy.darwinbg) ? 1 : 0;
			break;
		case TASK_POLICY_IO:
			/*
			 * The I/O system calls here to find out what throttling tier to apply to an operation.
			 * Returns THROTTLE_LEVEL_* values
			 */
			if (on_task)
				value = task->effective_policy.io_tier;
			else {
				value = MAX(task->effective_policy.io_tier,
				             thread->effective_policy.io_tier);
				if (thread->iotier_override != THROTTLE_LEVEL_NONE)
					value = MIN(value, thread->iotier_override);
			}
			break;
		case TASK_POLICY_PASSIVE_IO:
			/*
			 * The I/O system calls here to find out whether an operation should be passive.
			 * (i.e. not cause operations with lower throttle tiers to be throttled)
			 * Returns 1 for passive mode, 0 for normal mode
			 */
			if (on_task)
				value = task->effective_policy.io_passive;
			else
				value = (task->effective_policy.io_passive ||
				          thread->effective_policy.io_passive) ? 1 : 0;
			break;
		case TASK_POLICY_NEW_SOCKETS_BG:
			/*
			 * socreate() calls this to determine if it should mark a new socket as background
			 * Returns 1 for background mode, 0 for normal mode
			 */
			if (on_task)
				value = task->effective_policy.new_sockets_bg;
			else
				value = (task->effective_policy.new_sockets_bg ||
				          thread->effective_policy.new_sockets_bg) ? 1 : 0;
			break;
		case TASK_POLICY_LOWPRI_CPU:
			/*
			 * Returns 1 for low priority cpu mode, 0 for normal mode
			 */
			if (on_task)
				value = task->effective_policy.lowpri_cpu;
			else
				value = (task->effective_policy.lowpri_cpu ||
				          thread->effective_policy.lowpri_cpu) ? 1 : 0;
			break;
		case TASK_POLICY_SUPPRESSED_CPU:
			/*
			 * Returns 1 for suppressed cpu mode, 0 for normal mode
			 */
			assert(on_task);
			value = task->effective_policy.t_suppressed_cpu;
			break;
		case TASK_POLICY_LATENCY_QOS:
			/*
			 * timer arming calls into here to find out the timer coalescing level
			 * Returns a QoS tier (0-6)
			 */
			assert(on_task);
			value = task->effective_policy.t_latency_qos;
			break;
		case TASK_POLICY_THROUGH_QOS:
			/*
			 * Returns a QoS tier (0-6)
			 */
			assert(on_task);
			value = task->effective_policy.t_through_qos;
			break;
		case TASK_POLICY_GPU_DENY:
			/*
			 * This is where IOKit calls into task_policy to find out whether
			 * it should allow access to the GPU.
			 * Returns 1 for NOT allowed, returns 0 for allowed
			 */
			assert(on_task);
			value = task->effective_policy.t_gpu_deny;
			break;
		case TASK_POLICY_ROLE:
			assert(on_task);
			value = task->effective_policy.t_role;
			break;
		case TASK_POLICY_WATCHERS_BG:
			assert(on_task);
			value = task->effective_policy.t_watchers_bg;
			break;
		default:
			panic("unknown policy_flavor %d", flavor);
			break;
	}

	return value;
}

/*
 * Convert from IOPOL_* values to throttle tiers.
 *
 * TODO: Can this be made more compact, like an array lookup
 * Note that it is possible to support e.g. IOPOL_PASSIVE_STANDARD in the future
 */

static void
proc_iopol_to_tier(int iopolicy, int *tier, int *passive)
{
	*passive = 0;
	*tier = 0;
	switch (iopolicy) {
		case IOPOL_IMPORTANT:
			*tier = THROTTLE_LEVEL_TIER0;
			break;
		case IOPOL_PASSIVE:
			*tier = THROTTLE_LEVEL_TIER0;
			*passive = 1;
			break;
		case IOPOL_STANDARD:
			*tier = THROTTLE_LEVEL_TIER1;
			break;
		case IOPOL_UTILITY:
			*tier = THROTTLE_LEVEL_TIER2;
			break;
		case IOPOL_THROTTLE:
			*tier = THROTTLE_LEVEL_TIER3;
			break;
		default:
			panic("unknown I/O policy %d", iopolicy);
			break;
	}
}

static int
proc_tier_to_iopol(int tier, int passive)
{
	if (passive == 1) {
		switch (tier) {
			case THROTTLE_LEVEL_TIER0:
				return IOPOL_PASSIVE;
				break;
			default:
				panic("unknown passive tier %d", tier);
				return IOPOL_DEFAULT;
				break;
		}
	} else {
		switch (tier) {
			case THROTTLE_LEVEL_NONE:
				return IOPOL_DEFAULT;
				break;
			case THROTTLE_LEVEL_TIER0:
				return IOPOL_IMPORTANT;
				break;
			case THROTTLE_LEVEL_TIER1:
				return IOPOL_STANDARD;
				break;
			case THROTTLE_LEVEL_TIER2:
				return IOPOL_UTILITY;
				break;
			case THROTTLE_LEVEL_TIER3:
				return IOPOL_THROTTLE;
				break;
			default:
				panic("unknown tier %d", tier);
				return IOPOL_DEFAULT;
				break;
		}
	}
}

/* apply internal backgrounding for workqueue threads */
int
proc_apply_workq_bgthreadpolicy(thread_t thread)
{
	if (thread == THREAD_NULL)
		return ESRCH;

	proc_set_task_policy(thread->task, thread, TASK_POLICY_ATTRIBUTE,
	                     TASK_POLICY_WORKQ_BG, TASK_POLICY_ENABLE);

	return(0);
}

/*
 * remove internal backgrounding for workqueue threads
 * does NOT go find sockets created while BG and unbackground them
 */
int
proc_restore_workq_bgthreadpolicy(thread_t thread)
{
	if (thread == THREAD_NULL)
		return ESRCH;

	proc_set_task_policy(thread->task, thread, TASK_POLICY_ATTRIBUTE,
	                     TASK_POLICY_WORKQ_BG, TASK_POLICY_DISABLE);

	return(0);
}

/* here for temporary compatibility */
int
proc_setthread_saved_importance(__unused thread_t thread, __unused int importance)
{
	return(0);
}

/*
 * Set an override on the thread which is consulted with a
 * higher priority than the task/thread policy. This should
 * only be set for temporary grants until the thread
 * returns to the userspace boundary
 *
 * We use atomic operations to swap in the override, with
 * the assumption that the thread itself can
 * read the override and clear it on return to userspace.
 *
 * No locking is performed, since it is acceptable to see
 * a stale override for one loop through throttle_lowpri_io().
 * However a thread reference must be held on the thread.
 */

void set_thread_iotier_override(thread_t thread, int policy)
{
	int current_override;

	/* Let most aggressive I/O policy win until user boundary */
	do {
		current_override = thread->iotier_override;

		if (current_override != THROTTLE_LEVEL_NONE)
			policy = MIN(current_override, policy);

		if (current_override == policy) {
			/* no effective change */
			return;
		}
	} while (!OSCompareAndSwap(current_override, policy, &thread->iotier_override));

	/*
	 * Since the thread may be currently throttled,
	 * re-evaluate tiers and potentially break out
	 * of an msleep
	 */
	rethrottle_thread(thread->uthread);
}

/*
 * Called at process exec to initialize the apptype of a process
 */
void
proc_set_task_apptype(task_t task, int apptype)
{
	task_lock(task);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	                          (IMPORTANCE_CODE(IMP_TASK_APPTYPE, apptype)) | DBG_FUNC_START,
	                          proc_selfpid(), audit_token_pid_from_task(task), trequested(task, THREAD_NULL),
	                          apptype, 0);

	switch (apptype) {
		case TASK_APPTYPE_APP_TAL:
			/* TAL starts off enabled by default */
			task->requested_policy.t_tal_enabled = 1;
			/* fall through */

		case TASK_APPTYPE_APP_DEFAULT:
		case TASK_APPTYPE_DAEMON_INTERACTIVE:
			task->requested_policy.t_apptype = apptype;

			task_importance_mark_donor(task, TRUE);
			/* Apps (and interactive daemons) are boost recievers on desktop for suppression behaviors */
			task_importance_mark_receiver(task, TRUE);
			break;

		case TASK_APPTYPE_DAEMON_STANDARD:
			task->requested_policy.t_apptype = apptype;

			task_importance_mark_donor(task, TRUE);
			task_importance_mark_receiver(task, FALSE);
			break;

		case TASK_APPTYPE_DAEMON_ADAPTIVE:
			task->requested_policy.t_apptype = apptype;

			task_importance_mark_donor(task, FALSE);
			task_importance_mark_receiver(task, TRUE);
			break;

		case TASK_APPTYPE_DAEMON_BACKGROUND:
			task->requested_policy.t_apptype = apptype;

			task_importance_mark_donor(task, FALSE);
			task_importance_mark_receiver(task, FALSE);
			break;

		default:
			panic("invalid apptype %d", apptype);
			break;
	}

	task_policy_update_locked(task, THREAD_NULL);

	task_unlock(task);

	task_policy_update_complete_unlocked(task, THREAD_NULL);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	                          (IMPORTANCE_CODE(IMP_TASK_APPTYPE, apptype)) | DBG_FUNC_END,
	                          proc_selfpid(), audit_token_pid_from_task(task), trequested(task, THREAD_NULL),
	                          task->imp_receiver, 0);
}

/* for process_policy to check before attempting to set */
boolean_t
proc_task_is_tal(task_t task)
{
	return (task->requested_policy.t_apptype == TASK_APPTYPE_APP_TAL) ? TRUE : FALSE;
}

/* for telemetry */
integer_t
task_grab_latency_qos(task_t task)
{
	return task_qos_latency_package(proc_get_effective_task_policy(task, TASK_POLICY_LATENCY_QOS));
}

/* update the darwin background action state in the flags field for libproc */
int
proc_get_darwinbgstate(task_t task, uint32_t * flagsp)
{
	if (task->requested_policy.ext_darwinbg)
		*flagsp |= PROC_FLAG_EXT_DARWINBG;

	if (task->requested_policy.int_darwinbg)
		*flagsp |= PROC_FLAG_DARWINBG;


	if (task->requested_policy.t_apptype == TASK_APPTYPE_DAEMON_ADAPTIVE)
		*flagsp |= PROC_FLAG_ADAPTIVE;

	if (task->requested_policy.t_apptype == TASK_APPTYPE_DAEMON_ADAPTIVE && task->requested_policy.t_boosted == 1)
		*flagsp |= PROC_FLAG_ADAPTIVE_IMPORTANT;

	if (task->imp_donor)
		*flagsp |= PROC_FLAG_IMPORTANCE_DONOR;

	if (task->effective_policy.t_sup_active)
		*flagsp |= PROC_FLAG_SUPPRESSED;

	return(0);
}

/* All per-thread state is in the first 32-bits of the bitfield */
void
proc_get_thread_policy(thread_t thread, thread_policy_state_t info)
{
	task_t task = thread->task;
	task_lock(task);
	info->requested = (integer_t)task_requested_bitfield(task, thread);
	info->effective = (integer_t)task_effective_bitfield(task, thread);
	info->pending   = (integer_t)task_pending_bitfield(task, thread);
	task_unlock(task);
}


/* dump requested for tracepoint */
static uintptr_t
trequested(task_t task, thread_t thread)
{
	return (uintptr_t) task_requested_bitfield(task, thread);
}

/* dump effective for tracepoint */
static uintptr_t
teffective(task_t task, thread_t thread)
{
	return (uintptr_t) task_effective_bitfield(task, thread);
}

/* dump pending for tracepoint */
static uintptr_t
tpending(task_t task, thread_t thread)
{
	return (uintptr_t) task_pending_bitfield(task, thread);
}

uint64_t
task_requested_bitfield(task_t task, thread_t thread)
{
	uint64_t bits = 0;
	struct task_requested_policy requested =
	        (thread == THREAD_NULL) ? task->requested_policy : thread->requested_policy;

	bits |= (requested.int_darwinbg         ? POLICY_REQ_INT_DARWIN_BG  : 0);
	bits |= (requested.ext_darwinbg         ? POLICY_REQ_EXT_DARWIN_BG  : 0);
	bits |= (requested.int_iotier           ? (((uint64_t)requested.int_iotier) << POLICY_REQ_INT_IO_TIER_SHIFT) : 0);
	bits |= (requested.ext_iotier           ? (((uint64_t)requested.ext_iotier) << POLICY_REQ_EXT_IO_TIER_SHIFT) : 0);
	bits |= (requested.int_iopassive        ? POLICY_REQ_INT_PASSIVE_IO : 0);
	bits |= (requested.ext_iopassive        ? POLICY_REQ_EXT_PASSIVE_IO : 0);
	bits |= (requested.bg_iotier            ? (((uint64_t)requested.bg_iotier)  << POLICY_REQ_BG_IOTIER_SHIFT)   : 0);
	bits |= (requested.terminated           ? POLICY_REQ_TERMINATED     : 0);

	bits |= (requested.th_pidbind_bg        ? POLICY_REQ_PIDBIND_BG     : 0);
	bits |= (requested.th_workq_bg          ? POLICY_REQ_WORKQ_BG       : 0);

	bits |= (requested.t_boosted            ? POLICY_REQ_BOOSTED        : 0);
	bits |= (requested.t_tal_enabled        ? POLICY_REQ_TAL_ENABLED    : 0);
	bits |= (requested.t_int_gpu_deny       ? POLICY_REQ_INT_GPU_DENY   : 0);
	bits |= (requested.t_ext_gpu_deny       ? POLICY_REQ_EXT_GPU_DENY   : 0);
	bits |= (requested.t_apptype            ? (((uint64_t)requested.t_apptype)    << POLICY_REQ_APPTYPE_SHIFT)  : 0);
	bits |= (requested.t_role               ? (((uint64_t)requested.t_role)       << POLICY_REQ_ROLE_SHIFT)     : 0);

	bits |= (requested.t_sup_active         ? POLICY_REQ_SUP_ACTIVE         : 0);
	bits |= (requested.t_sup_lowpri_cpu     ? POLICY_REQ_SUP_LOWPRI_CPU     : 0);
	bits |= (requested.t_sup_cpu            ? POLICY_REQ_SUP_CPU            : 0);
	bits |= (requested.t_sup_timer          ? (((uint64_t)requested.t_sup_timer)  << POLICY_REQ_SUP_TIMER_THROTTLE_SHIFT) : 0);
	bits |= (requested.t_sup_throughput     ? (((uint64_t)requested.t_sup_throughput)   << POLICY_REQ_SUP_THROUGHPUT_SHIFT)   : 0);
	bits |= (requested.t_sup_disk           ? POLICY_REQ_SUP_DISK_THROTTLE  : 0);
	bits |= (requested.t_sup_cpu_limit      ? POLICY_REQ_SUP_CPU_LIMIT      : 0);
	bits |= (requested.t_sup_suspend        ? POLICY_REQ_SUP_SUSPEND        : 0);
	bits |= (requested.t_base_latency_qos   ? (((uint64_t)requested.t_base_latency_qos) << POLICY_REQ_BASE_LATENCY_QOS_SHIFT) : 0);
	bits |= (requested.t_over_latency_qos   ? (((uint64_t)requested.t_over_latency_qos) << POLICY_REQ_OVER_LATENCY_QOS_SHIFT) : 0);
	bits |= (requested.t_base_through_qos   ? (((uint64_t)requested.t_base_through_qos) << POLICY_REQ_BASE_THROUGH_QOS_SHIFT) : 0);
	bits |= (requested.t_over_through_qos   ? (((uint64_t)requested.t_over_through_qos) << POLICY_REQ_OVER_THROUGH_QOS_SHIFT) : 0);

	return bits;
}

uint64_t
task_effective_bitfield(task_t task, thread_t thread)
{
	uint64_t bits = 0;
	struct task_effective_policy effective =
	        (thread == THREAD_NULL) ? task->effective_policy : thread->effective_policy;

	bits |= (effective.io_tier              ? (((uint64_t)effective.io_tier) << POLICY_EFF_IO_TIER_SHIFT) : 0);
	bits |= (effective.io_passive           ? POLICY_EFF_IO_PASSIVE     : 0);
	bits |= (effective.darwinbg             ? POLICY_EFF_DARWIN_BG      : 0);
	bits |= (effective.lowpri_cpu           ? POLICY_EFF_LOWPRI_CPU     : 0);
	bits |= (effective.terminated           ? POLICY_EFF_TERMINATED     : 0);
	bits |= (effective.all_sockets_bg       ? POLICY_EFF_ALL_SOCKETS_BG : 0);
	bits |= (effective.new_sockets_bg       ? POLICY_EFF_NEW_SOCKETS_BG : 0);
	bits |= (effective.bg_iotier            ? (((uint64_t)effective.bg_iotier) << POLICY_EFF_BG_IOTIER_SHIFT) : 0);

	bits |= (effective.t_gpu_deny           ? POLICY_EFF_GPU_DENY       : 0);
	bits |= (effective.t_tal_engaged        ? POLICY_EFF_TAL_ENGAGED    : 0);
	bits |= (effective.t_suspended          ? POLICY_EFF_SUSPENDED      : 0);
	bits |= (effective.t_watchers_bg        ? POLICY_EFF_WATCHERS_BG    : 0);
	bits |= (effective.t_sup_active         ? POLICY_EFF_SUP_ACTIVE     : 0);
	bits |= (effective.t_suppressed_cpu     ? POLICY_EFF_SUP_CPU        : 0);
	bits |= (effective.t_role               ? (((uint64_t)effective.t_role)        << POLICY_EFF_ROLE_SHIFT)        : 0);
	bits |= (effective.t_latency_qos        ? (((uint64_t)effective.t_latency_qos) << POLICY_EFF_LATENCY_QOS_SHIFT) : 0);
	bits |= (effective.t_through_qos        ? (((uint64_t)effective.t_through_qos) << POLICY_EFF_THROUGH_QOS_SHIFT) : 0);

	return bits;
}

uint64_t
task_pending_bitfield(task_t task, thread_t thread)
{
	uint64_t bits = 0;
	struct task_pended_policy pended =
	        (thread == THREAD_NULL) ? task->pended_policy : thread->pended_policy;

	bits |= (pended.t_updating_policy    ? POLICY_PEND_UPDATING   : 0);
	bits |= (pended.update_sockets       ? POLICY_PEND_SOCKETS    : 0);

	bits |= (pended.t_update_timers      ? POLICY_PEND_TIMERS     : 0);
	bits |= (pended.t_update_watchers    ? POLICY_PEND_WATCHERS   : 0);

	return bits;
}


/*
 * Resource usage and CPU related routines
 */

int 
proc_get_task_ruse_cpu(task_t task, uint32_t *policyp, uint8_t *percentagep, uint64_t *intervalp, uint64_t *deadlinep)
{
	
	int error = 0;
	int scope;

	task_lock(task);

	
	error = task_get_cpuusage(task, percentagep, intervalp, deadlinep, &scope);
	task_unlock(task);

	/*
	 * Reverse-map from CPU resource limit scopes back to policies (see comment below).
	 */
	if (scope == TASK_RUSECPU_FLAGS_PERTHR_LIMIT) {
		*policyp = TASK_POLICY_RESOURCE_ATTRIBUTE_NOTIFY_EXC;
	} else if (scope == TASK_RUSECPU_FLAGS_PROC_LIMIT) {
		*policyp = TASK_POLICY_RESOURCE_ATTRIBUTE_THROTTLE;
	} else if (scope == TASK_RUSECPU_FLAGS_DEADLINE) {
		*policyp = TASK_POLICY_RESOURCE_ATTRIBUTE_NONE;
	}

	return(error);
}

/*
 * Configure the default CPU usage monitor parameters.
 *
 * For tasks which have this mechanism activated: if any thread in the
 * process consumes more CPU than this, an EXC_RESOURCE exception will be generated.
 */
void
proc_init_cpumon_params(void)
{
	if (!PE_parse_boot_argn("max_cpumon_percentage", &proc_max_cpumon_percentage,
		sizeof (proc_max_cpumon_percentage))) {
	 	proc_max_cpumon_percentage = DEFAULT_CPUMON_PERCENTAGE;
	}

	if (proc_max_cpumon_percentage > 100) {
		proc_max_cpumon_percentage = 100;
	}

	/* The interval should be specified in seconds. */ 
	if (!PE_parse_boot_argn("max_cpumon_interval", &proc_max_cpumon_interval,
	 	sizeof (proc_max_cpumon_interval))) {
	 	proc_max_cpumon_interval = DEFAULT_CPUMON_INTERVAL;
	}

	proc_max_cpumon_interval *= NSEC_PER_SEC;
}

/*
 * Currently supported configurations for CPU limits.
 *
 * Policy				| Deadline-based CPU limit | Percentage-based CPU limit
 * -------------------------------------+--------------------------+------------------------------
 * PROC_POLICY_RSRCACT_THROTTLE		| ENOTSUP		   | Task-wide scope only
 * PROC_POLICY_RSRCACT_SUSPEND		| Task-wide scope only	   | ENOTSUP
 * PROC_POLICY_RSRCACT_TERMINATE	| Task-wide scope only	   | ENOTSUP
 * PROC_POLICY_RSRCACT_NOTIFY_KQ	| Task-wide scope only	   | ENOTSUP
 * PROC_POLICY_RSRCACT_NOTIFY_EXC	| ENOTSUP		   | Per-thread scope only
 *
 * A deadline-based CPU limit is actually a simple wallclock timer - the requested action is performed
 * after the specified amount of wallclock time has elapsed.
 *
 * A percentage-based CPU limit performs the requested action after the specified amount of actual CPU time
 * has been consumed -- regardless of how much wallclock time has elapsed -- by either the task as an
 * aggregate entity (so-called "Task-wide" or "Proc-wide" scope, whereby the CPU time consumed by all threads
 * in the task are added together), or by any one thread in the task (so-called "per-thread" scope).
 *
 * We support either deadline != 0 OR percentage != 0, but not both. The original intention in having them
 * share an API was to use actual CPU time as the basis of the deadline-based limit (as in: perform an action
 * after I have used some amount of CPU time; this is different than the recurring percentage/interval model)
 * but the potential consumer of the API at the time was insisting on wallclock time instead.
 *
 * Currently, requesting notification via an exception is the only way to get per-thread scope for a
 * CPU limit. All other types of notifications force task-wide scope for the limit.
 */
int 
proc_set_task_ruse_cpu(task_t task, uint32_t policy, uint8_t percentage, uint64_t interval, uint64_t deadline,
	int cpumon_entitled)
{
	int error = 0;
	int scope;

 	/*
 	 * Enforce the matrix of supported configurations for policy, percentage, and deadline.
 	 */
 	switch (policy) {
 	// If no policy is explicitly given, the default is to throttle.
 	case TASK_POLICY_RESOURCE_ATTRIBUTE_NONE:
	case TASK_POLICY_RESOURCE_ATTRIBUTE_THROTTLE:
		if (deadline != 0)
			return (ENOTSUP);
		scope = TASK_RUSECPU_FLAGS_PROC_LIMIT;
		break;
	case TASK_POLICY_RESOURCE_ATTRIBUTE_SUSPEND:
	case TASK_POLICY_RESOURCE_ATTRIBUTE_TERMINATE:
	case TASK_POLICY_RESOURCE_ATTRIBUTE_NOTIFY_KQ:
		if (percentage != 0)
			return (ENOTSUP);
		scope = TASK_RUSECPU_FLAGS_DEADLINE;
		break;
 	case TASK_POLICY_RESOURCE_ATTRIBUTE_NOTIFY_EXC:
		if (deadline != 0)
			return (ENOTSUP);
		scope = TASK_RUSECPU_FLAGS_PERTHR_LIMIT;
#ifdef CONFIG_NOMONITORS
		return (error);
#endif /* CONFIG_NOMONITORS */
		break;
	default:
		return (EINVAL);
	}

	task_lock(task);
	if (task != current_task()) {
		task->policy_ru_cpu_ext = policy;
	} else {
		task->policy_ru_cpu = policy;
	}
	error = task_set_cpuusage(task, percentage, interval, deadline, scope, cpumon_entitled);
	task_unlock(task);
	return(error);
}

int 
proc_clear_task_ruse_cpu(task_t task, int cpumon_entitled)
{
	int error = 0;
	int action;
	void * bsdinfo = NULL;

	task_lock(task);
	if (task != current_task()) {
		task->policy_ru_cpu_ext = TASK_POLICY_RESOURCE_ATTRIBUTE_DEFAULT;
	} else {
		task->policy_ru_cpu = TASK_POLICY_RESOURCE_ATTRIBUTE_DEFAULT;
	}

	error = task_clear_cpuusage_locked(task, cpumon_entitled);
	if (error != 0)
		goto out;	

	action = task->applied_ru_cpu;
	if (task->applied_ru_cpu_ext != TASK_POLICY_RESOURCE_ATTRIBUTE_NONE) {
		/* reset action */
		task->applied_ru_cpu_ext = TASK_POLICY_RESOURCE_ATTRIBUTE_NONE;
	}
	if (action != TASK_POLICY_RESOURCE_ATTRIBUTE_NONE) {
		bsdinfo = task->bsd_info;
		task_unlock(task);
		proc_restore_resource_actions(bsdinfo, TASK_POLICY_CPU_RESOURCE_USAGE, action);
		goto out1;
	}

out:
	task_unlock(task);
out1:
	return(error);

}

/* used to apply resource limit related actions */
static int
task_apply_resource_actions(task_t task, int type)
{
	int action = TASK_POLICY_RESOURCE_ATTRIBUTE_NONE;
	void * bsdinfo = NULL;
	
	switch (type) {
		case TASK_POLICY_CPU_RESOURCE_USAGE:
			break;
		case TASK_POLICY_WIREDMEM_RESOURCE_USAGE:
		case TASK_POLICY_VIRTUALMEM_RESOURCE_USAGE:
		case TASK_POLICY_DISK_RESOURCE_USAGE:
		case TASK_POLICY_NETWORK_RESOURCE_USAGE:
		case TASK_POLICY_POWER_RESOURCE_USAGE:
			return(0);

		default:
			return(1);
	};

	/* only cpu actions for now */
	task_lock(task);
	
	if (task->applied_ru_cpu_ext == TASK_POLICY_RESOURCE_ATTRIBUTE_NONE) {
		/* apply action */
		task->applied_ru_cpu_ext = task->policy_ru_cpu_ext;
		action = task->applied_ru_cpu_ext;
	} else {
		action = task->applied_ru_cpu_ext;
	}

	if (action != TASK_POLICY_RESOURCE_ATTRIBUTE_NONE) {
		bsdinfo = task->bsd_info;
		task_unlock(task);
		proc_apply_resource_actions(bsdinfo, TASK_POLICY_CPU_RESOURCE_USAGE, action);
	} else
		task_unlock(task);

	return(0);
}

/*
 * XXX This API is somewhat broken; we support multiple simultaneous CPU limits, but the get/set API
 * only allows for one at a time. This means that if there is a per-thread limit active, the other
 * "scopes" will not be accessible via this API. We could change it to pass in the scope of interest
 * to the caller, and prefer that, but there's no need for that at the moment.
 */
int
task_get_cpuusage(task_t task, uint8_t *percentagep, uint64_t *intervalp, uint64_t *deadlinep, int *scope)
{
	*percentagep = 0;
	*intervalp = 0;
	*deadlinep = 0;

	if ((task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_PERTHR_LIMIT) != 0) {
		*scope = TASK_RUSECPU_FLAGS_PERTHR_LIMIT;
		*percentagep = task->rusage_cpu_perthr_percentage;
		*intervalp = task->rusage_cpu_perthr_interval;
	} else if ((task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_PROC_LIMIT) != 0) {
		*scope = TASK_RUSECPU_FLAGS_PROC_LIMIT;
		*percentagep = task->rusage_cpu_percentage;
		*intervalp = task->rusage_cpu_interval;
	} else if ((task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_DEADLINE) != 0) {
		*scope = TASK_RUSECPU_FLAGS_DEADLINE;
		*deadlinep = task->rusage_cpu_deadline;
	} else {
		*scope = 0;
	}

	return(0);
}

/*
 * Disable the CPU usage monitor for the task. Return value indicates
 * if the mechanism was actually enabled.
 */
int
task_disable_cpumon(task_t task) {
	thread_t thread;
	
	task_lock_assert_owned(task);

	if ((task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_PERTHR_LIMIT) == 0) {
		return (KERN_INVALID_ARGUMENT);
	}

#if CONFIG_TELEMETRY
	/*
	 * Disable task-wide telemetry if it was ever enabled by the CPU usage
	 * monitor's warning zone.
	 */
	telemetry_task_ctl_locked(current_task(), TF_CPUMON_WARNING, 0);
#endif

	/*
	 * Disable the monitor for the task, and propagate that change to each thread.
	 */
	task->rusage_cpu_flags &= ~(TASK_RUSECPU_FLAGS_PERTHR_LIMIT | TASK_RUSECPU_FLAGS_FATAL_CPUMON);		
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		set_astledger(thread);
	}
	task->rusage_cpu_perthr_percentage = 0;
	task->rusage_cpu_perthr_interval = 0;

	return (KERN_SUCCESS);
}

int
task_set_cpuusage(task_t task, uint8_t percentage, uint64_t interval, uint64_t deadline, int scope, int cpumon_entitled)
{
	thread_t thread;	
	uint64_t abstime = 0;
	uint64_t limittime = 0;

	lck_mtx_assert(&task->lock, LCK_MTX_ASSERT_OWNED);

	/* By default, refill once per second */
	if (interval == 0)
		interval = NSEC_PER_SEC;

	if (percentage != 0) {
		if (scope == TASK_RUSECPU_FLAGS_PERTHR_LIMIT) {
			boolean_t warn = FALSE;

			/*
			 * A per-thread CPU limit on a task generates an exception
			 * (LEDGER_ACTION_EXCEPTION) if any one thread in the task
			 * exceeds the limit.
			 */

			if (percentage == TASK_POLICY_CPUMON_DISABLE) {
				if (cpumon_entitled) {
					task_disable_cpumon(task);
					return (0);
				}

				/*
				 * This task wishes to disable the CPU usage monitor, but it's
				 * missing the required entitlement:
				 *     com.apple.private.kernel.override-cpumon
				 *
				 * Instead, treat this as a request to reset its params 
				 * back to the defaults.
				 */
				warn = TRUE;
				percentage = TASK_POLICY_CPUMON_DEFAULTS;
			}

			if (percentage == TASK_POLICY_CPUMON_DEFAULTS) {
				percentage = proc_max_cpumon_percentage;
				interval   = proc_max_cpumon_interval;
			}

			if (percentage > 100) {
				percentage = 100;
			}

			/*
			 * Passing in an interval of -1 means either:
			 * - Leave the interval as-is, if there's already a per-thread
			 *   limit configured
			 * - Use the system default.
		  	 */
			if (interval == -1ULL) {
				if (task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_PERTHR_LIMIT) {
			 		interval = task->rusage_cpu_perthr_interval;
				} else {
					interval = proc_max_cpumon_interval;
				}
			}

			/*
			 * Enforce global caps on CPU usage monitor here if the process is not
			 * entitled to escape the global caps.
			 */
			 if ((percentage > proc_max_cpumon_percentage) && (cpumon_entitled == 0)) {
				warn = TRUE;
			 	percentage = proc_max_cpumon_percentage;
			 }

			 if ((interval > proc_max_cpumon_interval) && (cpumon_entitled == 0)) {
				warn = TRUE;
			 	interval = proc_max_cpumon_interval;
			 }

			if (warn) {
				int 	  pid = 0;
				char 	  *procname = (char *)"unknown";

#ifdef MACH_BSD
				pid = proc_selfpid();
				if (current_task()->bsd_info != NULL) {
					procname = proc_name_address(current_task()->bsd_info);
				}
#endif

				printf("process %s[%d] denied attempt to escape CPU monitor"
					" (missing required entitlement).\n", procname, pid);
			}

			task->rusage_cpu_flags |= TASK_RUSECPU_FLAGS_PERTHR_LIMIT;
			task->rusage_cpu_perthr_percentage = percentage;
			task->rusage_cpu_perthr_interval = interval;
			queue_iterate(&task->threads, thread, thread_t, task_threads) {
				set_astledger(thread);
			}
		} else if (scope == TASK_RUSECPU_FLAGS_PROC_LIMIT) {
			/*
			 * Currently, a proc-wide CPU limit always blocks if the limit is
			 * exceeded (LEDGER_ACTION_BLOCK).
			 */
			task->rusage_cpu_flags |= TASK_RUSECPU_FLAGS_PROC_LIMIT;
			task->rusage_cpu_percentage = percentage;
			task->rusage_cpu_interval = interval;

			limittime = (interval * percentage) / 100;
			nanoseconds_to_absolutetime(limittime, &abstime);

			ledger_set_limit(task->ledger, task_ledgers.cpu_time, abstime, 0);
			ledger_set_period(task->ledger, task_ledgers.cpu_time, interval);
			ledger_set_action(task->ledger, task_ledgers.cpu_time, LEDGER_ACTION_BLOCK);
		}
	}

	if (deadline != 0) {
		assert(scope == TASK_RUSECPU_FLAGS_DEADLINE);

		/* if already in use, cancel and wait for it to cleanout */
		if (task->rusage_cpu_callt != NULL) {
			task_unlock(task);
			thread_call_cancel_wait(task->rusage_cpu_callt);
			task_lock(task);
		}
		if (task->rusage_cpu_callt == NULL) {
			task->rusage_cpu_callt = thread_call_allocate_with_priority(task_action_cpuusage, (thread_call_param_t)task, THREAD_CALL_PRIORITY_KERNEL);
		}
		/* setup callout */
		if (task->rusage_cpu_callt != 0) {
			uint64_t save_abstime = 0;

			task->rusage_cpu_flags |= TASK_RUSECPU_FLAGS_DEADLINE;
			task->rusage_cpu_deadline = deadline;

			nanoseconds_to_absolutetime(deadline, &abstime);
			save_abstime = abstime;
			clock_absolutetime_interval_to_deadline(save_abstime, &abstime);
			thread_call_enter_delayed(task->rusage_cpu_callt, abstime);
		}
	}

	return(0);
}

int
task_clear_cpuusage(task_t task, int cpumon_entitled)
{
	int retval = 0;

	task_lock(task);
	retval = task_clear_cpuusage_locked(task, cpumon_entitled);
	task_unlock(task);

	return(retval);
}

int
task_clear_cpuusage_locked(task_t task, int cpumon_entitled)
{
	thread_call_t savecallt;

	/* cancel percentage handling if set */
	if (task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_PROC_LIMIT) {
		task->rusage_cpu_flags &= ~TASK_RUSECPU_FLAGS_PROC_LIMIT;		
		ledger_set_limit(task->ledger, task_ledgers.cpu_time, LEDGER_LIMIT_INFINITY, 0);
		task->rusage_cpu_percentage = 0;
		task->rusage_cpu_interval = 0;
	}

	/*
	 * Disable the CPU usage monitor.
	 */
	if (cpumon_entitled) {
		task_disable_cpumon(task);
	}

	/* cancel deadline handling if set */
	if (task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_DEADLINE) {
		task->rusage_cpu_flags &= ~TASK_RUSECPU_FLAGS_DEADLINE;
		if (task->rusage_cpu_callt != 0) {
			savecallt = task->rusage_cpu_callt;
			task->rusage_cpu_callt = NULL;
			task->rusage_cpu_deadline = 0;
			task_unlock(task);
			thread_call_cancel_wait(savecallt);
			thread_call_free(savecallt);
			task_lock(task);
		}
	}
	return(0);
}

/* called by ledger unit to enforce action due to  resource usage criteria being met */
void
task_action_cpuusage(thread_call_param_t param0, __unused thread_call_param_t param1)
{
	task_t task = (task_t)param0;
	(void)task_apply_resource_actions(task, TASK_POLICY_CPU_RESOURCE_USAGE);
	return;
}


/*
 * Routines for taskwatch and pidbind
 */


/*
 * Routines for importance donation/inheritance/boosting
 */

void
task_importance_mark_donor(task_t task, boolean_t donating)
{
#if IMPORTANCE_INHERITANCE
	task->imp_donor = (donating ? 1 : 0);
#endif /* IMPORTANCE_INHERITANCE */
}

void
task_importance_mark_receiver(task_t task, boolean_t receiving)
{
#if IMPORTANCE_INHERITANCE
	if (receiving) {
		assert(task->task_imp_assertcnt == 0);
		task->imp_receiver       = 1;  /* task can receive importance boost */
		task->task_imp_assertcnt = 0;
		task->task_imp_externcnt = 0;
	} else {
		if (task->task_imp_assertcnt != 0 || task->task_imp_externcnt != 0)
			panic("disabling imp_receiver on task with pending boosts!");

		task->imp_receiver       = 0;
		task->task_imp_assertcnt = 0;
		task->task_imp_externcnt = 0;
	}
#endif /* IMPORTANCE_INHERITANCE */
}


#if IMPORTANCE_INHERITANCE

static void
task_update_boost_locked(task_t task, boolean_t boost_active)
{
#if IMPORTANCE_DEBUG
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_BOOST, (boost_active ? IMP_BOOSTED : IMP_UNBOOSTED)) | DBG_FUNC_START),
	                          proc_selfpid(), audit_token_pid_from_task(task), trequested(task, THREAD_NULL), 0, 0);
#endif

	/* assert(boost_active ? task->requested_policy.t_boosted == 0 : task->requested_policy.t_boosted == 1); */

	proc_set_task_policy_locked(task, THREAD_NULL, TASK_POLICY_ATTRIBUTE, TASK_POLICY_BOOST, boost_active);

	task_policy_update_locked(task, THREAD_NULL);

#if IMPORTANCE_DEBUG
	if (boost_active == TRUE){
		DTRACE_BOOST2(boost, task_t, task, int, audit_token_pid_from_task(task));
	} else {
		DTRACE_BOOST2(unboost, task_t, task, int, audit_token_pid_from_task(task));
	}
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_BOOST, (boost_active ? IMP_BOOSTED : IMP_UNBOOSTED)) | DBG_FUNC_END),
	                          proc_selfpid(), audit_token_pid_from_task(task),
	                          trequested(task, THREAD_NULL), tpending(task, THREAD_NULL), 0);
#endif
}

/*
 * Check if this task should donate importance.
 *
 * May be called without taking the task lock. In that case, donor status can change
 * so you must check only once for each donation event.
 */
boolean_t
task_is_importance_donor(task_t task)
{
	return (task->imp_donor == 1 || task->task_imp_assertcnt > 0) ? TRUE : FALSE;
}

/*
 * This routine may be called without holding task lock
 * since the value of imp_receiver can never be unset.
 */
boolean_t
task_is_importance_receiver(task_t task)
{
	return (task->imp_receiver) ? TRUE : FALSE;
}

/*
 * External importance assertions are managed by the process in userspace
 * Internal importance assertions are the responsibility of the kernel
 * Assertions are changed from internal to external via task_importance_externalize_assertion
 */

int
task_importance_hold_internal_assertion(task_t target_task, uint32_t count)
{
	int rval = 0;

	task_lock(target_task);
	rval = task_importance_hold_assertion_locked(target_task, TASK_POLICY_INTERNAL, count);
	task_unlock(target_task);

	task_policy_update_complete_unlocked(target_task, THREAD_NULL);

	return(rval);
}

int
task_importance_hold_external_assertion(task_t target_task, uint32_t count)
{
	int rval = 0;

	task_lock(target_task);
	rval = task_importance_hold_assertion_locked(target_task, TASK_POLICY_EXTERNAL, count);
	task_unlock(target_task);

	task_policy_update_complete_unlocked(target_task, THREAD_NULL);

	return(rval);
}

int
task_importance_drop_internal_assertion(task_t target_task, uint32_t count)
{
	int rval = 0;

	task_lock(target_task);
	rval = task_importance_drop_assertion_locked(target_task, TASK_POLICY_INTERNAL, count);
	task_unlock(target_task);

	task_policy_update_complete_unlocked(target_task, THREAD_NULL);

	return(rval);
}

int
task_importance_drop_external_assertion(task_t target_task, uint32_t count)
{
	int rval = 0;

	task_lock(target_task);
	rval = task_importance_drop_assertion_locked(target_task, TASK_POLICY_EXTERNAL, count);
	task_unlock(target_task);

	task_policy_update_complete_unlocked(target_task, THREAD_NULL);

	return(rval);
}

/*
 * Returns EOVERFLOW if an external assertion is taken when not holding an external boost.
 */
static int
task_importance_hold_assertion_locked(task_t target_task, int external, uint32_t count)
{
	boolean_t apply_boost = FALSE;
	int ret = 0;

	assert(target_task->imp_receiver != 0);

#if IMPORTANCE_DEBUG
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_ASSERTION, (IMP_HOLD | external))) | DBG_FUNC_START,
	        proc_selfpid(), audit_token_pid_from_task(target_task), target_task->task_imp_assertcnt, target_task->task_imp_externcnt, 0);
#endif

	/* assert(target_task->task_imp_assertcnt >= target_task->task_imp_externcnt); */

	if (external == TASK_POLICY_EXTERNAL) {
		if (target_task->task_imp_externcnt == 0) {
			/* Only allowed to take a new boost assertion when holding an external boost */
			printf("BUG in process %s[%d]: it attempted to acquire a new boost assertion without holding an existing external assertion. "
			       "(%d total, %d external)\n",
			       proc_name_address(target_task->bsd_info), audit_token_pid_from_task(target_task),
			       target_task->task_imp_assertcnt, target_task->task_imp_externcnt);
			ret = EOVERFLOW;
			count = 0;
		} else {
			target_task->task_imp_assertcnt += count;
			target_task->task_imp_externcnt += count;
		}
	} else {
		if (target_task->task_imp_assertcnt == 0)
			apply_boost = TRUE;
		target_task->task_imp_assertcnt += count;
	}

	if (apply_boost == TRUE)
		task_update_boost_locked(target_task, TRUE);

#if IMPORTANCE_DEBUG
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_ASSERTION, (IMP_HOLD | external))) | DBG_FUNC_END,
	        proc_selfpid(), audit_token_pid_from_task(target_task), target_task->task_imp_assertcnt, target_task->task_imp_externcnt, 0);
	DTRACE_BOOST6(receive_internal_boost, task_t, target_task, int, audit_token_pid_from_task(target_task), task_t, current_task(), int, proc_selfpid(), int, count, int, target_task->task_imp_assertcnt);
	if (external == TASK_POLICY_EXTERNAL){
		DTRACE_BOOST5(receive_boost, task_t, target_task, int, audit_token_pid_from_task(target_task), int, proc_selfpid(), int, count, int, target_task->task_imp_externcnt);
	}
#endif
	return(ret);
}


/*
 * Returns EOVERFLOW if an external assertion is over-released.
 * Panics if an internal assertion is over-released.
 */
static int
task_importance_drop_assertion_locked(task_t target_task, int external, uint32_t count)
{
	int ret = 0;

	assert(target_task->imp_receiver != 0);

#if IMPORTANCE_DEBUG
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_ASSERTION, (IMP_DROP | external))) | DBG_FUNC_START,
	        proc_selfpid(), audit_token_pid_from_task(target_task), target_task->task_imp_assertcnt, target_task->task_imp_externcnt, 0);
#endif

	/* assert(target_task->task_imp_assertcnt >= target_task->task_imp_externcnt); */

	if (external == TASK_POLICY_EXTERNAL) {
		assert(count == 1);
		if (count <= target_task->task_imp_externcnt) {
			target_task->task_imp_externcnt -= count;
			if (count <= target_task->task_imp_assertcnt)
				target_task->task_imp_assertcnt -= count;
		} else {
			/* Process over-released its boost count */
			printf("BUG in process %s[%d]: over-released external boost assertions (%d total, %d external)\n",
			       proc_name_address(target_task->bsd_info), audit_token_pid_from_task(target_task),
			       target_task->task_imp_assertcnt, target_task->task_imp_externcnt);
			
			/* TODO: If count > 1, we should clear out as many external assertions as there are left. */
			ret = EOVERFLOW;
			count = 0;
		}
	} else {
		if (count <= target_task->task_imp_assertcnt) {
			target_task->task_imp_assertcnt -= count;
		} else {
			/* TODO: Turn this back into a panic <rdar://problem/12592649> */
			printf("Over-release of kernel-internal importance assertions for task %p (%s), dropping %d assertion(s) but task only has %d remaining (%d external).\n",
			      target_task,
			      (target_task->bsd_info == NULL) ? "" : proc_name_address(target_task->bsd_info),
			      count,
			      target_task->task_imp_assertcnt,
			      target_task->task_imp_externcnt);
			count = 0;
		}
	}

	/* assert(target_task->task_imp_assertcnt >= target_task->task_imp_externcnt); */

	if (target_task->task_imp_assertcnt == 0 && ret == 0)
		task_update_boost_locked(target_task, FALSE);

#if IMPORTANCE_DEBUG
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_ASSERTION, (IMP_DROP | external))) | DBG_FUNC_END,
	        proc_selfpid(), audit_token_pid_from_task(target_task), target_task->task_imp_assertcnt, target_task->task_imp_externcnt, 0);
	if (external == TASK_POLICY_EXTERNAL) {
		DTRACE_BOOST4(drop_boost, task_t, target_task, int, audit_token_pid_from_task(target_task), int, count, int, target_task->task_imp_externcnt);
	}
	DTRACE_BOOST4(drop_internal_boost, task_t, target_task, int, audit_token_pid_from_task(target_task), int, count, int, target_task->task_imp_assertcnt);
#endif

	return(ret);
}

/* Transfer an assertion to userspace responsibility */
int
task_importance_externalize_assertion(task_t target_task, uint32_t count, __unused int sender_pid)
{
	assert(target_task != TASK_NULL);
	assert(target_task->imp_receiver != 0);

	task_lock(target_task);

#if IMPORTANCE_DEBUG
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_ASSERTION, IMP_EXTERN)) | DBG_FUNC_START,
	        proc_selfpid(), audit_token_pid_from_task(target_task), target_task->task_imp_assertcnt, target_task->task_imp_externcnt, 0);
#endif

	/* assert(target_task->task_imp_assertcnt >= target_task->task_imp_externcnt + count); */

	target_task->task_imp_externcnt += count;

#if IMPORTANCE_DEBUG
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_ASSERTION, IMP_EXTERN)) | DBG_FUNC_END,
	        proc_selfpid(), audit_token_pid_from_task(target_task), target_task->task_imp_assertcnt, target_task->task_imp_externcnt, 0);
	DTRACE_BOOST5(receive_boost, task_t, target_task, int, audit_token_pid_from_task(target_task),
		int, sender_pid, int, count, int, target_task->task_imp_externcnt);
#endif /* IMPORTANCE_DEBUG */

	task_unlock(target_task);

	return(0);
}


#endif /* IMPORTANCE_INHERITANCE */

void
task_hold_multiple_assertion(__imp_only task_t task, __imp_only uint32_t count)
{
#if IMPORTANCE_INHERITANCE
	assert(task->imp_receiver != 0);

	task_importance_hold_internal_assertion(task, count);
#endif /* IMPORTANCE_INHERITANCE */
}

void
task_add_importance_watchport(__imp_only task_t task, __imp_only __impdebug_only int pid, __imp_only mach_port_t port, int *boostp)
{
	int boost = 0;

	__impdebug_only int released_pid = 0;

#if IMPORTANCE_INHERITANCE
	task_t release_imp_task = TASK_NULL;

	if (task->imp_receiver == 0) {
		*boostp = boost;
		return;
	}

	if (IP_VALID(port) != 0) {
		ip_lock(port);

		/*
		 * The port must have been marked tempowner already.
		 * This also filters out ports whose receive rights
		 * are already enqueued in a message, as you can't
		 * change the right's destination once it's already
		 * on its way.
		 */
		if (port->ip_tempowner != 0) {
			assert(port->ip_impdonation != 0);

			boost = port->ip_impcount;
			if (port->ip_taskptr != 0) {
				/*
				 * if this port is already bound to a task,
				 * release the task reference and drop any
				 * watchport-forwarded boosts
				 */
				release_imp_task = port->ip_imp_task;
			}

			/* mark the port is watching another task */
			port->ip_taskptr = 1;
			port->ip_imp_task = task;
			task_reference(task);
		}
		ip_unlock(port);

		if (release_imp_task != TASK_NULL) {
			if (boost > 0)
				task_importance_drop_internal_assertion(release_imp_task, boost);
			released_pid = audit_token_pid_from_task(release_imp_task);
			task_deallocate(release_imp_task);
		}
#if IMPORTANCE_DEBUG
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_WATCHPORT, 0)) | DBG_FUNC_NONE,
		        proc_selfpid(), pid, boost, released_pid, 0);
#endif /* IMPORTANCE_DEBUG */
	}
#endif /* IMPORTANCE_INHERITANCE */

	*boostp = boost;
	return;
}


/*
 * Routines for VM to query task importance
 */


/*
 * Order to be considered while estimating importance
 * for low memory notification and purging purgeable memory.
 */
#define TASK_IMPORTANCE_FOREGROUND     4
#define TASK_IMPORTANCE_NOTDARWINBG    1


/*
 * Checks if the task is already notified.
 *
 * Condition: task lock should be held while calling this function.
 */
boolean_t
task_has_been_notified(task_t task, int pressurelevel)
{
	if (task == NULL) {
		return FALSE;
	}
	
	if (pressurelevel == kVMPressureWarning) 
		return (task->low_mem_notified_warn ? TRUE : FALSE);
	else if (pressurelevel == kVMPressureCritical) 
		return (task->low_mem_notified_critical ? TRUE : FALSE);
	else 
		return TRUE;
}


/*
 * Checks if the task is used for purging.
 *
 * Condition: task lock should be held while calling this function.
 */
boolean_t
task_used_for_purging(task_t task, int pressurelevel)
{
	if (task == NULL) {
		return FALSE;
	}
	
	if (pressurelevel == kVMPressureWarning)
		return (task->purged_memory_warn ? TRUE : FALSE);
	else if (pressurelevel == kVMPressureCritical)
		return (task->purged_memory_critical ? TRUE : FALSE);
	else
		return TRUE;
}


/*
 * Mark the task as notified with memory notification.
 * 
 * Condition: task lock should be held while calling this function.
 */
void
task_mark_has_been_notified(task_t task, int pressurelevel)
{
	if (task == NULL) {
		return;
	}
	
	if (pressurelevel == kVMPressureWarning)
		task->low_mem_notified_warn = 1;
	else if (pressurelevel == kVMPressureCritical)
		task->low_mem_notified_critical = 1;
}


/*
 * Mark the task as purged.
 *
 * Condition: task lock should be held while calling this function.
 */
void
task_mark_used_for_purging(task_t task, int pressurelevel)
{
	if (task == NULL) {
		return;
	}
	
	if (pressurelevel == kVMPressureWarning)
		task->purged_memory_warn = 1;
	else if (pressurelevel == kVMPressureCritical)
		task->purged_memory_critical = 1;
}


/*
 * Mark the task eligible for low memory notification.
 * 
 * Condition: task lock should be held while calling this function.
 */
void
task_clear_has_been_notified(task_t task, int pressurelevel)
{
	if (task == NULL) {
		return;
	}
	
	if (pressurelevel == kVMPressureWarning)
		task->low_mem_notified_warn = 0;
	else if (pressurelevel == kVMPressureCritical)
		task->low_mem_notified_critical = 0;
}


/*
 * Mark the task eligible for purging its purgeable memory.
 *
 * Condition: task lock should be held while calling this function.
 */
void
task_clear_used_for_purging(task_t task)
{
	if (task == NULL) {
		return;
	}
	
	task->purged_memory_warn = 0;
	task->purged_memory_critical = 0;
}


/*
 * Estimate task importance for purging its purgeable memory 
 * and low memory notification.
 * 
 * Importance is calculated in the following order of criteria:
 * -Task role : Background vs Foreground
 * -Boost status: Not boosted vs Boosted
 * -Darwin BG status.
 *
 * Returns: Estimated task importance. Less important task will have lower 
 *          estimated importance.
 */
int
task_importance_estimate(task_t task)
{
	int task_importance = 0;

	if (task == NULL) {
		return 0;
	}

	if (proc_get_effective_task_policy(task, TASK_POLICY_ROLE) == TASK_FOREGROUND_APPLICATION)
			task_importance += TASK_IMPORTANCE_FOREGROUND;

	if (proc_get_effective_task_policy(task, TASK_POLICY_DARWIN_BG) == 0)
			task_importance += TASK_IMPORTANCE_NOTDARWINBG;
	
	return task_importance;
}


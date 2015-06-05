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
#include <kern/sfi.h>
#include <kern/coalition.h>
#if CONFIG_TELEMETRY
#include <kern/telemetry.h>
#endif

#if IMPORTANCE_INHERITANCE
#include <ipc/ipc_importance.h>
#if IMPORTANCE_DEBUG
#include <mach/machine/sdt.h>
#endif /* IMPORTANCE_DEBUG */
#endif /* IMPORTANCE_INHERITACE */

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
 *  then set up the effects of that behavior in task_policy_update*. If the policy manifests
 *  itself as a distinct effective policy, add it to the effective struct and add it to the
 *  proc_get_effective_policy accessor.
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

extern const qos_policy_params_t thread_qos_policy_params;

/* for task holds without dropping the lock */
extern void task_hold_locked(task_t task);
extern void task_release_locked(task_t task);
extern void task_wait_locked(task_t task, boolean_t until_not_runnable);

extern void thread_recompute_qos(thread_t thread);

/* Task policy related helper functions */
static void proc_set_task_policy_locked(task_t task, thread_t thread, int category, int flavor, int value);
static void proc_set_task_policy2_locked(task_t task, thread_t thread, int category, int flavor, int value1, int value2);

static void task_policy_update_locked(task_t task, thread_t thread, task_pend_token_t pend_token);
static void task_policy_update_internal_locked(task_t task, thread_t thread, boolean_t in_create, task_pend_token_t pend_token);
static void task_policy_update_task_locked(task_t task, boolean_t update_throttle, boolean_t update_bg_throttle, boolean_t update_sfi);
static void task_policy_update_thread_locked(thread_t thread, int update_cpu, boolean_t update_throttle, boolean_t update_sfi, boolean_t update_qos);
static boolean_t task_policy_update_coalition_focal_tasks(task_t task, int prev_role, int next_role);

static int proc_get_effective_policy(task_t task, thread_t thread, int policy);

static void proc_iopol_to_tier(int iopolicy, int *tier, int *passive);
static int proc_tier_to_iopol(int tier, int passive);

static uintptr_t trequested_0(task_t task, thread_t thread);
static uintptr_t trequested_1(task_t task, thread_t thread);
static uintptr_t teffective_0(task_t task, thread_t thread);
static uintptr_t teffective_1(task_t task, thread_t thread);
static uint32_t tpending(task_pend_token_t pend_token);
static uint64_t task_requested_bitfield(task_t task, thread_t thread);
static uint64_t task_effective_bitfield(task_t task, thread_t thread);

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
extern void     proc_apply_task_networkbg(void * bsd_info, thread_t thread);
#endif /* MACH_BSD */

extern zone_t thread_qos_override_zone;
static boolean_t _proc_thread_qos_remove_override_internal(task_t task, thread_t thread, uint64_t tid, user_addr_t resource, int resource_type, boolean_t reset);


/* Importance Inheritance related helper functions */

#if IMPORTANCE_INHERITANCE

static void task_add_importance_watchport(task_t task, mach_port_t port, int *boostp);
static void task_importance_update_live_donor(task_t target_task);

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

/* Latency/throughput QoS fields remain zeroed, i.e. TIER_UNSPECIFIED at creation */
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

kern_return_t
qos_latency_policy_validate(task_latency_qos_t ltier) {
	if ((ltier != LATENCY_QOS_TIER_UNSPECIFIED) &&
	    ((ltier > LATENCY_QOS_TIER_5) || (ltier < LATENCY_QOS_TIER_0)))
		return KERN_INVALID_ARGUMENT;

	return KERN_SUCCESS;
}

kern_return_t
qos_throughput_policy_validate(task_throughput_qos_t ttier) {
	if ((ttier != THROUGHPUT_QOS_TIER_UNSPECIFIED) &&
	    ((ttier > THROUGHPUT_QOS_TIER_5) || (ttier < THROUGHPUT_QOS_TIER_0)))
		return KERN_INVALID_ARGUMENT;

	return KERN_SUCCESS;
}

static kern_return_t
task_qos_policy_validate(task_qos_policy_t qosinfo, mach_msg_type_number_t count) {
	if (count < TASK_QOS_POLICY_COUNT)
		return KERN_INVALID_ARGUMENT;

	task_latency_qos_t ltier = qosinfo->task_latency_qos_tier;
	task_throughput_qos_t ttier = qosinfo->task_throughput_qos_tier;

	kern_return_t kr = qos_latency_policy_validate(ltier);

	if (kr != KERN_SUCCESS)
		return kr;

	kr = qos_throughput_policy_validate(ttier);

	return kr;
}

uint32_t
qos_extract(uint32_t qv) {
	return (qv & 0xFF);
}

uint32_t
qos_latency_policy_package(uint32_t qv) {
	return (qv == LATENCY_QOS_TIER_UNSPECIFIED) ? LATENCY_QOS_TIER_UNSPECIFIED : ((0xFF << 16) | qv);
}

uint32_t
qos_throughput_policy_package(uint32_t qv) {
	return (qv == THROUGHPUT_QOS_TIER_UNSPECIFIED) ? THROUGHPUT_QOS_TIER_UNSPECIFIED : ((0xFE << 16) | qv);
}

/* TEMPORARY boot-arg controlling task_policy suppression (App Nap) */
static boolean_t task_policy_suppression_disable = FALSE;

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
	case TASK_OVERRIDE_QOS_POLICY:
	{
		task_qos_policy_t qosinfo = (task_qos_policy_t)policy_info;
		kern_return_t kr = task_qos_policy_validate(qosinfo, count);

		if (kr != KERN_SUCCESS)
			return kr;


		uint32_t lqos = qos_extract(qosinfo->task_latency_qos_tier);
		uint32_t tqos = qos_extract(qosinfo->task_throughput_qos_tier);

		proc_set_task_policy2(task, THREAD_NULL, TASK_POLICY_ATTRIBUTE,
							  flavor == TASK_BASE_QOS_POLICY ? TASK_POLICY_BASE_LATENCY_AND_THROUGHPUT_QOS : TASK_POLICY_OVERRIDE_LATENCY_AND_THROUGHPUT_QOS,
							  lqos, tqos);
	}
	break;

	case TASK_BASE_LATENCY_QOS_POLICY:
	{
		task_qos_policy_t qosinfo = (task_qos_policy_t)policy_info;
		kern_return_t kr = task_qos_policy_validate(qosinfo, count);

		if (kr != KERN_SUCCESS)
			return kr;

		uint32_t lqos = qos_extract(qosinfo->task_latency_qos_tier);

		proc_set_task_policy(task, NULL, TASK_POLICY_ATTRIBUTE, TASK_BASE_LATENCY_QOS_POLICY, lqos);
	}
	break;

	case TASK_BASE_THROUGHPUT_QOS_POLICY:
	{
		task_qos_policy_t qosinfo = (task_qos_policy_t)policy_info;
		kern_return_t kr = task_qos_policy_validate(qosinfo, count);

		if (kr != KERN_SUCCESS)
			return kr;

		uint32_t tqos = qos_extract(qosinfo->task_throughput_qos_tier);

		proc_set_task_policy(task, NULL, TASK_POLICY_ATTRIBUTE, TASK_BASE_THROUGHPUT_QOS_POLICY, tqos);
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

		/* TEMPORARY disablement of task suppression */
		if (task_policy_suppression_disable && info->active)
			return KERN_SUCCESS;

		struct task_pend_token pend_token = {};

		task_lock(task);

		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		                          (IMPORTANCE_CODE(IMP_TASK_SUPPRESSION, info->active)) | DBG_FUNC_START,
		                          proc_selfpid(), audit_token_pid_from_task(task), trequested_0(task, THREAD_NULL),
		                          trequested_1(task, THREAD_NULL), 0);

		task->requested_policy.t_sup_active      = (info->active)         ? 1 : 0;
		task->requested_policy.t_sup_lowpri_cpu  = (info->lowpri_cpu)     ? 1 : 0;
		task->requested_policy.t_sup_timer       = qos_extract(info->timer_throttle);
		task->requested_policy.t_sup_disk        = (info->disk_throttle)  ? 1 : 0;
		task->requested_policy.t_sup_cpu_limit   = (info->cpu_limit)      ? 1 : 0;
		task->requested_policy.t_sup_suspend     = (info->suspend)        ? 1 : 0;
		task->requested_policy.t_sup_throughput  = qos_extract(info->throughput_qos);
		task->requested_policy.t_sup_cpu         = (info->suppressed_cpu) ? 1 : 0;
		task->requested_policy.t_sup_bg_sockets  = (info->background_sockets) ? 1 : 0;

		task_policy_update_locked(task, THREAD_NULL, &pend_token);

		task_unlock(task);

		task_policy_update_complete_unlocked(task, THREAD_NULL, &pend_token);

		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		                          (IMPORTANCE_CODE(IMP_TASK_SUPPRESSION, info->active)) | DBG_FUNC_END,
		                          proc_selfpid(), audit_token_pid_from_task(task), trequested_0(task, THREAD_NULL),
		                          trequested_1(task, THREAD_NULL), 0);

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
	task_policy_update_task_locked(task, FALSE, FALSE, FALSE);

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
			int value1, value2;

			proc_get_task_policy2(task, THREAD_NULL, TASK_POLICY_ATTRIBUTE, TASK_POLICY_BASE_LATENCY_AND_THROUGHPUT_QOS, &value1, &value2);

			info->task_latency_qos_tier = qos_latency_policy_package(value1);
			info->task_throughput_qos_tier = qos_throughput_policy_package(value2);

		} else if (flavor == TASK_OVERRIDE_QOS_POLICY) {
			int value1, value2;

			proc_get_task_policy2(task, THREAD_NULL, TASK_POLICY_ATTRIBUTE, TASK_POLICY_OVERRIDE_LATENCY_AND_THROUGHPUT_QOS, &value1, &value2);

			info->task_latency_qos_tier = qos_latency_policy_package(value1);
			info->task_throughput_qos_tier = qos_throughput_policy_package(value2);
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

		if (*get_default) {
			info->requested = 0;
			info->effective = 0;
			info->pending = 0;
			info->imp_assertcnt = 0;
			info->imp_externcnt = 0;
			info->flags = 0;
			info->imp_transitions = 0;
		} else {
			task_lock(task);

			info->requested = task_requested_bitfield(task, THREAD_NULL);
			info->effective = task_effective_bitfield(task, THREAD_NULL);
			info->pending   = 0;
			
			info->flags = 0;
			if (task->task_imp_base != NULL) {
				info->imp_assertcnt = task->task_imp_base->iit_assertcnt;
				info->imp_externcnt = IIT_EXTERN(task->task_imp_base);
				info->flags |= (task_is_marked_importance_receiver(task) ? TASK_IMP_RECEIVER : 0);
				info->flags |= (task_is_marked_importance_denap_receiver(task) ? TASK_DENAP_RECEIVER : 0);
				info->flags |= (task_is_marked_importance_donor(task) ? TASK_IMP_DONOR : 0);
				info->flags |= (task_is_marked_live_importance_donor(task) ? TASK_IMP_LIVE_DONOR : 0);
				info->imp_transitions = task->task_imp_base->iit_transitions;
			} else {
				info->imp_assertcnt = 0;
				info->imp_externcnt = 0;
				info->imp_transitions = 0;
			}
			task_unlock(task);
		}

		info->reserved[0] = 0;
		info->reserved[1] = 0;

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
			info->timer_throttle    = qos_latency_policy_package(task->requested_policy.t_sup_timer);
			info->disk_throttle     = task->requested_policy.t_sup_disk;
			info->cpu_limit         = task->requested_policy.t_sup_cpu_limit;
			info->suspend           = task->requested_policy.t_sup_suspend;
			info->throughput_qos    = qos_throughput_policy_package(task->requested_policy.t_sup_throughput);
			info->suppressed_cpu    = task->requested_policy.t_sup_cpu;
			info->background_sockets = task->requested_policy.t_sup_bg_sockets;
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
				  audit_token_pid_from_task(task), teffective_0(task, THREAD_NULL),
				  teffective_1(task, THREAD_NULL), tpriority(task, THREAD_NULL), 0);

	task_policy_update_internal_locked(task, THREAD_NULL, TRUE, NULL);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				  (IMPORTANCE_CODE(IMP_UPDATE, (IMP_UPDATE_TASK_CREATE | TASK_POLICY_TASK))) | DBG_FUNC_END,
				  audit_token_pid_from_task(task), teffective_0(task, THREAD_NULL),
				  teffective_1(task, THREAD_NULL), tpriority(task, THREAD_NULL), 0);

	task_importance_update_live_donor(task);
	task_policy_update_task_locked(task, FALSE, FALSE, FALSE);
}

void
thread_policy_create(thread_t thread)
{
	task_t task = thread->task;

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				  (IMPORTANCE_CODE(IMP_UPDATE, (IMP_UPDATE_TASK_CREATE | TASK_POLICY_THREAD))) | DBG_FUNC_START,
				  targetid(task, thread), teffective_0(task, thread),
				  teffective_1(task, thread), tpriority(task, thread), 0);

	task_policy_update_internal_locked(task, thread, TRUE, NULL);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				  (IMPORTANCE_CODE(IMP_UPDATE, (IMP_UPDATE_TASK_CREATE | TASK_POLICY_THREAD))) | DBG_FUNC_END,
				  targetid(task, thread), teffective_0(task, thread),
				  teffective_1(task, thread), tpriority(task, thread), 0);
}

static void
task_policy_update_locked(task_t task, thread_t thread, task_pend_token_t pend_token)
{
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	                          (IMPORTANCE_CODE(IMP_UPDATE, tisthread(thread)) | DBG_FUNC_START),
	                          targetid(task, thread), teffective_0(task, thread),
	                          teffective_1(task, thread), tpriority(task, thread), 0);

	task_policy_update_internal_locked(task, thread, FALSE, pend_token);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				  (IMPORTANCE_CODE(IMP_UPDATE, tisthread(thread))) | DBG_FUNC_END,
				  targetid(task, thread), teffective_0(task, thread),
				  teffective_1(task, thread), tpriority(task, thread), 0);
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
task_policy_update_internal_locked(task_t task, thread_t thread, boolean_t in_create, task_pend_token_t pend_token)
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
	struct task_effective_policy task_effective;

	/* Calculate QoS policies */

	if (on_task) {
		/* Update task role */
		next.t_role = requested.t_role;

		/* Set task qos clamp and ceiling */
		next.t_qos_clamp = requested.t_qos_clamp;

		if (requested.t_apptype == TASK_APPTYPE_APP_DEFAULT ||
		    requested.t_apptype == TASK_APPTYPE_APP_TAL) {

			switch (next.t_role) {
				case TASK_FOREGROUND_APPLICATION:
					/* Foreground apps get urgent scheduler priority */
					next.qos_ui_is_urgent = 1;
					next.t_qos_ceiling = THREAD_QOS_UNSPECIFIED;
					break;

				case TASK_BACKGROUND_APPLICATION:
					/* This is really 'non-focal but on-screen' */
					next.t_qos_ceiling = THREAD_QOS_UNSPECIFIED;
					break;

				case TASK_DEFAULT_APPLICATION:
					/* This is 'may render UI but we don't know if it's focal/nonfocal' */
					next.t_qos_ceiling = THREAD_QOS_UNSPECIFIED;
					break;					

				case TASK_NONUI_APPLICATION:
					/* i.e. 'off-screen' */
					next.t_qos_ceiling = THREAD_QOS_LEGACY;
					break;

				case TASK_CONTROL_APPLICATION:
				case TASK_GRAPHICS_SERVER:
					next.qos_ui_is_urgent = 1;
					next.t_qos_ceiling = THREAD_QOS_UNSPECIFIED;
					break;

				case TASK_UNSPECIFIED:
				default:
					/* Apps that don't have an application role get
					 * USER_INTERACTIVE and USER_INITIATED squashed to LEGACY */
					next.t_qos_ceiling = THREAD_QOS_LEGACY;
					break;
			}
		} else {
			/* Daemons get USER_INTERACTIVE squashed to USER_INITIATED */
			next.t_qos_ceiling = THREAD_QOS_USER_INITIATED;
		}
	} else {
		/*
		 * Set thread qos tier
		 * Note that an override only overrides the QoS field, not other policy settings.
		 * A thread must already be participating in QoS for override to take effect
		 */

		/* Snapshot the task's effective policy */
		task_effective = task->effective_policy;

		next.qos_ui_is_urgent = task_effective.qos_ui_is_urgent;

		if ((requested.thrp_qos_override != THREAD_QOS_UNSPECIFIED) && (requested.thrp_qos != THREAD_QOS_UNSPECIFIED))
			next.thep_qos = MAX(requested.thrp_qos_override, requested.thrp_qos);
		else
			next.thep_qos = requested.thrp_qos;

		/* A task clamp will result in an effective QoS even when requested is UNSPECIFIED */
		if (task_effective.t_qos_clamp != THREAD_QOS_UNSPECIFIED) {
			if (next.thep_qos != THREAD_QOS_UNSPECIFIED)
				next.thep_qos = MIN(task_effective.t_qos_clamp, next.thep_qos);
			else
				next.thep_qos = task_effective.t_qos_clamp;
		}

		/* The ceiling only applies to threads that are in the QoS world */
		if (task_effective.t_qos_ceiling != THREAD_QOS_UNSPECIFIED &&
		    next.thep_qos                != THREAD_QOS_UNSPECIFIED) {
			next.thep_qos = MIN(task_effective.t_qos_ceiling, next.thep_qos);
		}

		/*
		 * The QoS relative priority is only applicable when the original programmer's
		 * intended (requested) QoS is in effect. When the QoS is clamped (e.g.
		 * USER_INITIATED-13REL clamped to UTILITY), the relative priority is not honored,
		 * since otherwise it would be lower than unclamped threads. Similarly, in the
		 * presence of boosting, the programmer doesn't know what other actors
		 * are boosting the thread.
		 */
		if ((requested.thrp_qos != THREAD_QOS_UNSPECIFIED) &&
		    (requested.thrp_qos == next.thep_qos) &&
		    (requested.thrp_qos_override == THREAD_QOS_UNSPECIFIED)) {
			next.thep_qos_relprio = requested.thrp_qos_relprio;
		} else {
			next.thep_qos_relprio = 0;
		}
	}

	/* Calculate DARWIN_BG */
	boolean_t wants_darwinbg        = FALSE;
	boolean_t wants_all_sockets_bg  = FALSE; /* Do I want my existing sockets to be bg */
	boolean_t wants_watchersbg      = FALSE; /* Do I want my pidbound threads to be bg */
	boolean_t wants_tal             = FALSE; /* Do I want the effects of TAL mode */

	/*
	 * If DARWIN_BG has been requested at either level, it's engaged.
	 * Only true DARWIN_BG changes cause watchers to transition.
	 *
	 * Backgrounding due to apptype does.
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

		if (next.t_qos_clamp == THREAD_QOS_BACKGROUND || next.t_qos_clamp == THREAD_QOS_MAINTENANCE)
			wants_darwinbg = TRUE;
	} else {
		if (requested.th_pidbind_bg)
			wants_all_sockets_bg = wants_darwinbg = TRUE;

		if (requested.th_workq_bg)
			wants_darwinbg = TRUE;

		if (next.thep_qos == THREAD_QOS_BACKGROUND || next.thep_qos == THREAD_QOS_MAINTENANCE)
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

	/* darwinbg on either task or thread implies background QOS (or lower) */
	if (!on_task &&
		(wants_darwinbg || task_effective.darwinbg) &&
		(next.thep_qos > THREAD_QOS_BACKGROUND || next.thep_qos == THREAD_QOS_UNSPECIFIED)){
		next.thep_qos = THREAD_QOS_BACKGROUND;
		next.thep_qos_relprio = 0;
	}

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

		if (next.t_qos_clamp != THREAD_QOS_UNSPECIFIED)
			iopol = MAX(iopol, thread_qos_policy_params.qos_iotier[next.t_qos_clamp]);

	} else {
		/* Look up the associated IO tier value for the QoS class */
		iopol = MAX(iopol, thread_qos_policy_params.qos_iotier[next.thep_qos]);
	}

	iopol = MAX(iopol, requested.int_iotier);
	iopol = MAX(iopol, requested.ext_iotier);

	next.io_tier = iopol;

	/* Calculate Passive IO policy */

	if (requested.ext_iopassive || requested.int_iopassive)
		next.io_passive = 1;

	/* Calculate miscellaneous policy */

	if (on_task) {
		/* Calculate suppression-active flag */
		if (requested.t_sup_active && requested.t_boosted == 0)
			next.t_sup_active = 1;

		/* Calculate suspend policy */
		if (requested.t_sup_suspend && requested.t_boosted == 0)
			next.t_suspended = 1;

		/* Calculate timer QOS */
		int latency_qos = requested.t_base_latency_qos;

		if (requested.t_sup_timer && requested.t_boosted == 0)
			latency_qos = requested.t_sup_timer;

		if (next.t_qos_clamp != THREAD_QOS_UNSPECIFIED)
			latency_qos = MAX(latency_qos, (int)thread_qos_policy_params.qos_latency_qos[next.t_qos_clamp]);

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

		if (next.t_qos_clamp != THREAD_QOS_UNSPECIFIED)
			through_qos = MAX(through_qos, (int)thread_qos_policy_params.qos_through_qos[next.t_qos_clamp]);

		if (requested.t_over_through_qos != 0)
			through_qos = requested.t_over_through_qos;

		next.t_through_qos = through_qos;

		/* Calculate suppressed CPU priority */
		if (requested.t_sup_cpu && requested.t_boosted == 0)
			next.t_suppressed_cpu = 1;

		/*
		 * Calculate background sockets
		 * Don't take into account boosting to limit transition frequency.
		 */
		if (requested.t_sup_bg_sockets){
			next.all_sockets_bg = 1;
			next.new_sockets_bg = 1;
		}

		/* Apply SFI Managed class bit */
		next.t_sfi_managed = requested.t_sfi_managed;

		/* Calculate 'live donor' status for live importance */
		switch (requested.t_apptype) {
			case TASK_APPTYPE_APP_TAL:
			case TASK_APPTYPE_APP_DEFAULT:
				if (requested.ext_darwinbg == 0)
					next.t_live_donor = 1;
				else
					next.t_live_donor = 0;
				break;

			case TASK_APPTYPE_DAEMON_INTERACTIVE:
			case TASK_APPTYPE_DAEMON_STANDARD:
			case TASK_APPTYPE_DAEMON_ADAPTIVE:
			case TASK_APPTYPE_DAEMON_BACKGROUND:
			default:
				next.t_live_donor = 0;
				break;
		}
	}

	if (requested.terminated) {
		/*
		 * Shoot down the throttles that slow down exit or response to SIGTERM
		 * We don't need to shoot down:
		 * passive        (don't want to cause others to throttle)
		 * all_sockets_bg (don't need to iterate FDs on every exit)
		 * new_sockets_bg (doesn't matter for exiting process)
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
		} else {
			next.thep_qos = 0;
		}
	}

	/*
	 * Step 3:
	 *  Swap out old policy for new policy
	 */

	if (!on_task) {
		/* Acquire thread mutex to synchronize against
		 * thread_policy_set(). Consider reworking to separate qos
		 * fields, or locking the task in thread_policy_set.
		 * A more efficient model would be to make the thread bits
		 * authoritative.
		 */
		thread_mtx_lock(thread);
	}

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
	else {
		/* Preserve thread specific latency/throughput QoS modified via
		 * thread_policy_set(). Inelegant in the extreme, to be reworked.
		 *
		 * If thread QoS class is set, we don't need to preserve the previously set values.
		 * We should ensure to not accidentally preserve previous thread QoS values if you set a thread
		 * back to default QoS.
		 */
		uint32_t lqos = thread->effective_policy.t_latency_qos, tqos = thread->effective_policy.t_through_qos;

		if (prev.thep_qos == THREAD_QOS_UNSPECIFIED && next.thep_qos == THREAD_QOS_UNSPECIFIED) {
			next.t_latency_qos = lqos;
			next.t_through_qos = tqos;
		} else if (prev.thep_qos != THREAD_QOS_UNSPECIFIED && next.thep_qos == THREAD_QOS_UNSPECIFIED) {
			next.t_latency_qos = 0;
			next.t_through_qos = 0;
		} else {
			next.t_latency_qos = thread_qos_policy_params.qos_latency_qos[next.thep_qos];
			next.t_through_qos = thread_qos_policy_params.qos_through_qos[next.thep_qos];
		}

		thread_update_qos_cpu_time(thread, TRUE);
		thread->effective_policy = next;
		thread_mtx_unlock(thread);
	}

	/* Don't do anything further to a half-formed task or thread */
	if (in_create)
		return;

	/*
	 * Step 4:
	 *  Pend updates that can't be done while holding the task lock
	 */

	if (prev.all_sockets_bg != next.all_sockets_bg)
		pend_token->tpt_update_sockets = 1;

	if (on_task) {
		/* Only re-scan the timer list if the qos level is getting less strong */
		if (prev.t_latency_qos > next.t_latency_qos)
			pend_token->tpt_update_timers = 1;


		if (prev.t_live_donor != next.t_live_donor)
			pend_token->tpt_update_live_donor = 1;
	}

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
		boolean_t update_sfi = FALSE;

		if (prev.bg_iotier          != next.bg_iotier        ||
		    prev.terminated         != next.terminated       ||
		    prev.t_qos_clamp        != next.t_qos_clamp      ||
		    prev.t_qos_ceiling      != next.t_qos_ceiling    ||
		    prev.qos_ui_is_urgent   != next.qos_ui_is_urgent ||
		    prev.darwinbg           != next.darwinbg)
			update_threads = TRUE;

		/*
		 * A bit of a layering violation. We know what task policy attributes
		 * sfi_thread_classify() consults, so if they change, trigger SFI
		 * re-evaluation.
		 */
		if ((prev.t_latency_qos != next.t_latency_qos) ||
			(prev.t_role != next.t_role) ||
			(prev.darwinbg != next.darwinbg) ||
			(prev.t_sfi_managed != next.t_sfi_managed))
			update_sfi = TRUE;

/* TODO: if CONFIG_SFI */
		if (prev.t_role != next.t_role && task_policy_update_coalition_focal_tasks(task, prev.t_role, next.t_role)) {
			update_sfi = TRUE;
			pend_token->tpt_update_coal_sfi = 1;
		}

		task_policy_update_task_locked(task, update_throttle, update_threads, update_sfi);
	} else {
		int update_cpu = 0;
		boolean_t update_sfi = FALSE;
		boolean_t update_qos = FALSE;

		if (prev.lowpri_cpu != next.lowpri_cpu)
			update_cpu = (next.lowpri_cpu ? DO_LOWPRI_CPU : UNDO_LOWPRI_CPU);

		if (prev.darwinbg != next.darwinbg ||
		    prev.thep_qos != next.thep_qos)
			update_sfi = TRUE;

		if (prev.thep_qos           != next.thep_qos          ||
		    prev.thep_qos_relprio   != next.thep_qos_relprio  ||
		    prev.qos_ui_is_urgent   != next.qos_ui_is_urgent) {
			update_qos = TRUE;
		}

		task_policy_update_thread_locked(thread, update_cpu, update_throttle, update_sfi, update_qos);
	}
}

/*
 * Yet another layering violation. We reach out and bang on the coalition directly.
 */
static boolean_t
task_policy_update_coalition_focal_tasks(task_t     task,
                                         int        prev_role,
                                         int        next_role)
{
	boolean_t sfi_transition = FALSE;

	if (prev_role != TASK_FOREGROUND_APPLICATION && next_role == TASK_FOREGROUND_APPLICATION) {
		if (coalition_adjust_focal_task_count(task->coalition, 1) == 1)
			sfi_transition = TRUE;
	} else if (prev_role == TASK_FOREGROUND_APPLICATION && next_role != TASK_FOREGROUND_APPLICATION) {
		if (coalition_adjust_focal_task_count(task->coalition, -1) == 0)
			sfi_transition = TRUE;
	}

	if (prev_role != TASK_BACKGROUND_APPLICATION && next_role == TASK_BACKGROUND_APPLICATION) {
		if (coalition_adjust_non_focal_task_count(task->coalition, 1) == 1)
			sfi_transition = TRUE;
	} else if (prev_role == TASK_BACKGROUND_APPLICATION && next_role != TASK_BACKGROUND_APPLICATION) {
		if (coalition_adjust_non_focal_task_count(task->coalition, -1) == 0)
			sfi_transition = TRUE;
	}

	return sfi_transition;
}

/* Despite the name, the thread's task is locked, the thread is not */
void
task_policy_update_thread_locked(thread_t thread,
                                 int update_cpu,
                                 boolean_t update_throttle,
                                 boolean_t update_sfi,
                                 boolean_t update_qos)
{
	thread_precedence_policy_data_t policy;

	if (update_throttle) {
		rethrottle_thread(thread->uthread);
	}

	if (update_sfi) {
		sfi_reevaluate(thread);
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

	if (update_qos)
		thread_recompute_qos(thread);
}

/*
 * Calculate priority on a task, loop through its threads, and tell them about
 * priority changes and throttle changes.
 */
void
task_policy_update_task_locked(task_t    task,
                               boolean_t update_throttle,
                               boolean_t update_threads,
                               boolean_t update_sfi)
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

		if (task->effective_policy.t_qos_clamp != THREAD_QOS_UNSPECIFIED) {
			int qos_clamp_priority = thread_qos_policy_params.qos_pri[task->effective_policy.t_qos_clamp];

			priority        = MIN(priority, qos_clamp_priority);
			max_priority    = MIN(max_priority, qos_clamp_priority);
		}
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
	if (update_threads || update_throttle || update_priority || update_sfi ) {
		thread_t thread;

		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			if (update_priority) {
				thread_mtx_lock(thread);

				thread_task_priority(thread, priority, max_priority);

				thread_mtx_unlock(thread);
			}

			if (update_throttle) {
				rethrottle_thread(thread->uthread);
			}

			if (update_sfi) {
				sfi_reevaluate(thread);
			}

			if (update_threads) {
				thread->requested_policy.bg_iotier  = task->effective_policy.bg_iotier;
				thread->requested_policy.terminated = task->effective_policy.terminated;

				task_policy_update_internal_locked(task, thread, FALSE, NULL);
				/*  The thread policy must not emit any completion actions due to this change. */
			}
		}
	}
}

/*
 * Called with task unlocked to do things that can't be done while holding the task lock
 */
void
task_policy_update_complete_unlocked(task_t task, thread_t thread, task_pend_token_t pend_token)
{
	boolean_t on_task = (thread == THREAD_NULL) ? TRUE : FALSE;

#ifdef MACH_BSD
	if (pend_token->tpt_update_sockets)
		proc_apply_task_networkbg(task->bsd_info, thread);
#endif /* MACH_BSD */

	if (on_task) {
		/* The timer throttle has been removed or reduced, we need to look for expired timers and fire them */
		if (pend_token->tpt_update_timers)
			ml_timer_evaluate();


		if (pend_token->tpt_update_live_donor)
			task_importance_update_live_donor(task);

		if (pend_token->tpt_update_coal_sfi)
			coalition_sfi_reevaluate(task->coalition, task);
	}
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
	struct task_pend_token pend_token = {};
	
	task_lock(task);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				  (IMPORTANCE_CODE(flavor, (category | tisthread(thread)))) | DBG_FUNC_START,
				  targetid(task, thread), trequested_0(task, thread), trequested_1(task, thread), value, 0);

	proc_set_task_policy_locked(task, thread, category, flavor, value);

	task_policy_update_locked(task, thread, &pend_token);

	task_unlock(task);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				  (IMPORTANCE_CODE(flavor, (category | tisthread(thread)))) | DBG_FUNC_END,
				  targetid(task, thread), trequested_0(task, thread), trequested_1(task, thread), tpending(&pend_token), 0);

	task_policy_update_complete_unlocked(task, thread, &pend_token);
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
	struct task_pend_token pend_token = {};

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
				  targetid(task, thread), trequested_0(task, thread), trequested_1(task, thread), value, 0);

	proc_set_task_policy_locked(task, thread, category, flavor, value);

	task_policy_update_locked(task, thread, &pend_token);

	task_unlock(task);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				  (IMPORTANCE_CODE(flavor, (category | TASK_POLICY_THREAD))) | DBG_FUNC_END,
				  targetid(task, thread), trequested_0(task, thread), trequested_1(task, thread), tpending(&pend_token), 0);

	task_policy_update_complete_unlocked(task, thread, &pend_token);
}

/*
 * Variant of proc_set_task_policy() that sets two scalars in the requested policy structure.
 * Same locking rules apply.
 */
void
proc_set_task_policy2(task_t task, thread_t thread, int category, int flavor, int value1, int value2)
{
	struct task_pend_token pend_token = {};
	
	task_lock(task);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				  (IMPORTANCE_CODE(flavor, (category | tisthread(thread)))) | DBG_FUNC_START,
				  targetid(task, thread), trequested_0(task, thread), trequested_1(task, thread), value1, 0);

	proc_set_task_policy2_locked(task, thread, category, flavor, value1, value2);

	task_policy_update_locked(task, thread, &pend_token);

	task_unlock(task);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				  (IMPORTANCE_CODE(flavor, (category | tisthread(thread)))) | DBG_FUNC_END,
				  targetid(task, thread), trequested_0(task, thread), trequested_0(task, thread), tpending(&pend_token), 0);

	task_policy_update_complete_unlocked(task, thread, &pend_token);
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
		case TASK_BASE_LATENCY_QOS_POLICY:
			assert(on_task && category == TASK_POLICY_ATTRIBUTE);
			requested.t_base_latency_qos = value;
			break;
		case TASK_BASE_THROUGHPUT_QOS_POLICY:
			assert(on_task && category == TASK_POLICY_ATTRIBUTE);
			requested.t_base_through_qos = value;
			break;
		case TASK_POLICY_SFI_MANAGED:
			assert(on_task && category == TASK_POLICY_ATTRIBUTE);
			requested.t_sfi_managed = value;
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

		case TASK_POLICY_QOS:
			assert(!on_task && category == TASK_POLICY_ATTRIBUTE);
			requested.thrp_qos = value;
			break;

		case TASK_POLICY_QOS_OVERRIDE:
			assert(!on_task && category == TASK_POLICY_ATTRIBUTE);
			requested.thrp_qos_override = value;
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
 * Variant of proc_set_task_policy_locked() that sets two scalars in the requested policy structure.
 */
static void
proc_set_task_policy2_locked(task_t      task,
                             thread_t    thread,
                             int         category,
                             int         flavor,
                             int         value1,
                             int         value2)
{
	boolean_t on_task = (thread == THREAD_NULL) ? TRUE : FALSE;

	struct task_requested_policy requested =
	        (on_task) ? task->requested_policy : thread->requested_policy;

	switch (flavor) {

	/* Category: ATTRIBUTE, task only */

		case TASK_POLICY_BASE_LATENCY_AND_THROUGHPUT_QOS:
			assert(on_task && category == TASK_POLICY_ATTRIBUTE);
			requested.t_base_latency_qos = value1;
			requested.t_base_through_qos = value2;
			break;

		case TASK_POLICY_OVERRIDE_LATENCY_AND_THROUGHPUT_QOS:
			assert(on_task && category == TASK_POLICY_ATTRIBUTE);
			requested.t_over_latency_qos = value1;
			requested.t_over_through_qos = value2;
			break;

	/* Category: ATTRIBUTE, thread only */

		case TASK_POLICY_QOS_AND_RELPRIO:

			assert(!on_task && category == TASK_POLICY_ATTRIBUTE);
			requested.thrp_qos = value1;
			requested.thrp_qos_relprio = value2;
			DTRACE_BOOST3(qos_set, uint64_t, thread->thread_id, int, requested.thrp_qos, int, requested.thrp_qos_relprio);
			break;

		default:
			panic("unknown task policy: %d %d %d %d", category, flavor, value1, value2);
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
		case TASK_POLICY_DARWIN_BG_IOPOL:
			assert(on_task && category == TASK_POLICY_ATTRIBUTE);
			value = proc_tier_to_iopol(requested.bg_iotier, 0);
			break;
		case TASK_POLICY_ROLE:
			assert(on_task && category == TASK_POLICY_ATTRIBUTE);
			value = requested.t_role;
			break;
		case TASK_POLICY_SFI_MANAGED:
			assert(on_task && category == TASK_POLICY_ATTRIBUTE);
			value = requested.t_sfi_managed;
			break;
		case TASK_POLICY_QOS:
			assert(!on_task && category == TASK_POLICY_ATTRIBUTE);
			value = requested.thrp_qos;
			break;
		case TASK_POLICY_QOS_OVERRIDE:
			assert(!on_task && category == TASK_POLICY_ATTRIBUTE);
			value = requested.thrp_qos_override;
			break;
		default:
			panic("unknown policy_flavor %d", flavor);
			break;
	}

	task_unlock(task);

	return value;
}

/*
 * Variant of proc_get_task_policy() that returns two scalar outputs.
 */
void
proc_get_task_policy2(task_t task, thread_t thread, int category __unused, int flavor, int *value1, int *value2)
{
	boolean_t on_task = (thread == THREAD_NULL) ? TRUE : FALSE;

	task_lock(task);

	struct task_requested_policy requested =
	        (on_task) ? task->requested_policy : thread->requested_policy;

	switch (flavor) {
		/* TASK attributes */
		case TASK_POLICY_BASE_LATENCY_AND_THROUGHPUT_QOS:
			assert(on_task && category == TASK_POLICY_ATTRIBUTE);
			*value1 = requested.t_base_latency_qos;
			*value2 = requested.t_base_through_qos;
			break;

		case TASK_POLICY_OVERRIDE_LATENCY_AND_THROUGHPUT_QOS:
			assert(on_task && category == TASK_POLICY_ATTRIBUTE);
			*value1 = requested.t_over_latency_qos;
			*value2 = requested.t_over_through_qos;
			break;

		/* THREAD attributes */
		case TASK_POLICY_QOS_AND_RELPRIO:
			assert(!on_task && category == TASK_POLICY_ATTRIBUTE);
			*value1 = requested.thrp_qos;
			*value2 = requested.thrp_qos_relprio;
			break;

		default:
			panic("unknown policy_flavor %d", flavor);
			break;
	}

	task_unlock(task);
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
 * within the context of a timer interrupt.  It is also called in KDP context for stackshot.
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
			 * Returns THROTTLE_LEVEL_* values. Some userspace spinlock operations can apply
			 * a temporary iotier override to make the I/O more aggressive to get the lock
			 * owner to release the spinlock.
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
			 * Returns 1 for passive mode, 0 for normal mode.
			 * If a userspace spinlock has applied an override, that I/O should always
			 * be passive to avoid self-throttling when the override is removed and lower
			 * iotier I/Os are issued.
			 */
			if (on_task)
				value = task->effective_policy.io_passive;
			else {
				int io_tier = MAX(task->effective_policy.io_tier, thread->effective_policy.io_tier);
				boolean_t override_in_effect = (thread->iotier_override != THROTTLE_LEVEL_NONE) && (thread->iotier_override < io_tier);

				value = (task->effective_policy.io_passive ||
				          thread->effective_policy.io_passive || override_in_effect) ? 1 : 0;
			}
			break;
		case TASK_POLICY_ALL_SOCKETS_BG:
			/*
			 * do_background_socket() calls this to determine what it should do to the proc's sockets
			 * Returns 1 for background mode, 0 for normal mode
			 *
			 * This consults both thread and task so un-DBGing a thread while the task is BG
			 * doesn't get you out of the network throttle.
			 */
			if (on_task)
				value = task->effective_policy.all_sockets_bg;
			else
				value = (task->effective_policy.all_sockets_bg ||
				         thread->effective_policy.all_sockets_bg) ? 1 : 0;
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
			if (on_task) {
				value = task->effective_policy.t_latency_qos;
			} else {
				value = MAX(task->effective_policy.t_latency_qos, thread->effective_policy.t_latency_qos);
			}
			break;
		case TASK_POLICY_THROUGH_QOS:
			/*
			 * Returns a QoS tier (0-6)
			 */
			assert(on_task);
			value = task->effective_policy.t_through_qos;
			break;
		case TASK_POLICY_ROLE:
			assert(on_task);
			value = task->effective_policy.t_role;
			break;
		case TASK_POLICY_WATCHERS_BG:
			assert(on_task);
			value = task->effective_policy.t_watchers_bg;
			break;
		case TASK_POLICY_SFI_MANAGED:
			assert(on_task);
			value = task->effective_policy.t_sfi_managed;
			break;
		case TASK_POLICY_QOS:
			assert(!on_task);
			value = thread->effective_policy.thep_qos;
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
			case THROTTLE_LEVEL_TIER0:
				return IOPOL_DEFAULT;
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
 * Userspace synchronization routines (like pthread mutexes, pthread reader-writer locks,
 * semaphores, dispatch_sync) may result in priority inversions where a higher priority
 * (i.e. scheduler priority, I/O tier, QoS tier) is waiting on a resource owned by a lower
 * priority thread. In these cases, we attempt to propagate the priority token, as long
 * as the subsystem informs us of the relationships between the threads. The userspace
 * synchronization subsystem should maintain the information of owner->resource and
 * resource->waiters itself.
 */

/*
 * This helper canonicalizes the resource/resource_type given the current qos_override_mode
 * in effect. Note that wildcards (THREAD_QOS_OVERRIDE_RESOURCE_WILDCARD) may need
 * to be handled specially in the future, but for now it's fine to slam
 * *resource to USER_ADDR_NULL even if it was previously a wildcard.
 */
static void _canonicalize_resource_and_type(user_addr_t *resource, int *resource_type) {
	if (qos_override_mode == QOS_OVERRIDE_MODE_OVERHANG_PEAK || qos_override_mode == QOS_OVERRIDE_MODE_IGNORE_OVERRIDE) {
		/* Map all input resource/type to a single one */
		*resource = USER_ADDR_NULL;
		*resource_type = THREAD_QOS_OVERRIDE_TYPE_UNKNOWN;
	} else if (qos_override_mode == QOS_OVERRIDE_MODE_FINE_GRAINED_OVERRIDE) {
		/* no transform */
	} else if (qos_override_mode == QOS_OVERRIDE_MODE_FINE_GRAINED_OVERRIDE_BUT_IGNORE_DISPATCH) {
		/* Map all dispatch overrides to a single one, to avoid memory overhead */
		if (*resource_type == THREAD_QOS_OVERRIDE_TYPE_DISPATCH_ASYNCHRONOUS_OVERRIDE) {
			*resource = USER_ADDR_NULL;
		}
	} else if (qos_override_mode == QOS_OVERRIDE_MODE_FINE_GRAINED_OVERRIDE_BUT_SINGLE_MUTEX_OVERRIDE) {
		/* Map all mutex overrides to a single one, to avoid memory overhead */
		if (*resource_type == THREAD_QOS_OVERRIDE_TYPE_PTHREAD_MUTEX) {
			*resource = USER_ADDR_NULL;
		}
	}
}

/* This helper routine finds an existing override if known. Locking should be done by caller */
static struct thread_qos_override *_find_qos_override(thread_t thread, user_addr_t resource, int resource_type) {
	struct thread_qos_override *override;

	override = thread->overrides;
	while (override) {
		if (override->override_resource == resource &&
			override->override_resource_type == resource_type) {
			return override;
		}
		
		override = override->override_next;
	}

	return NULL;
}

static void _find_and_decrement_qos_override(thread_t thread, user_addr_t resource, int resource_type, boolean_t reset, struct thread_qos_override **free_override_list) {
	struct thread_qos_override *override, *override_prev;

	override_prev = NULL;
	override = thread->overrides;
	while (override) {
		struct thread_qos_override *override_next = override->override_next;

		if ((THREAD_QOS_OVERRIDE_RESOURCE_WILDCARD == resource || override->override_resource == resource) &&
			override->override_resource_type == resource_type) {
			if (reset) {
				override->override_contended_resource_count = 0;
			} else {
				override->override_contended_resource_count--;
			}

			if (override->override_contended_resource_count == 0) {
				if (override_prev == NULL) {
					thread->overrides = override_next;
				} else {
					override_prev->override_next = override_next;
				}
				
				/* Add to out-param for later zfree */
				override->override_next = *free_override_list;
				*free_override_list = override;
			} else {
				override_prev = override;
			}

			if (THREAD_QOS_OVERRIDE_RESOURCE_WILDCARD != resource) {
				return;
			}
		} else {
			override_prev = override;
		}
		
		override = override_next;
	}
}

/* This helper recalculates the current requested override using the policy selected at boot */
static int _calculate_requested_qos_override(thread_t thread)
{
	if (qos_override_mode == QOS_OVERRIDE_MODE_IGNORE_OVERRIDE) {
		return THREAD_QOS_UNSPECIFIED;
	}

	/* iterate over all overrides and calculate MAX */
	struct thread_qos_override *override;
	int qos_override = THREAD_QOS_UNSPECIFIED;

	override = thread->overrides;
	while (override) {
		if (qos_override_mode != QOS_OVERRIDE_MODE_FINE_GRAINED_OVERRIDE_BUT_IGNORE_DISPATCH ||
			override->override_resource_type != THREAD_QOS_OVERRIDE_TYPE_DISPATCH_ASYNCHRONOUS_OVERRIDE) {
			qos_override = MAX(qos_override, override->override_qos);
		}
		
		override = override->override_next;
	}

	return qos_override;
}

boolean_t proc_thread_qos_add_override(task_t task, thread_t thread, uint64_t tid, int override_qos, boolean_t first_override_for_resource, user_addr_t resource, int resource_type)
{
	thread_t	self = current_thread();
	struct task_pend_token pend_token = {};

	/* XXX move to thread mutex when thread policy does */
	task_lock(task);

	/*
	 * If thread is passed, it is assumed to be most accurate, since the caller must have an explicit (or implicit) reference
	 * to the thread
	 */
	
	if (thread != THREAD_NULL) {
		assert(task == thread->task);
	} else {
		if (tid == self->thread_id) {
			thread = self;
		} else {
			thread = task_findtid(task, tid);

			if (thread == THREAD_NULL) {
				KERNEL_DEBUG_CONSTANT((IMPORTANCE_CODE(IMP_USYNCH_QOS_OVERRIDE, IMP_USYNCH_ADD_OVERRIDE)) | DBG_FUNC_NONE,
									  tid, 0, 0xdead, 0, 0);
				task_unlock(task);
				return FALSE;
			}
		}
	}

	KERNEL_DEBUG_CONSTANT((IMPORTANCE_CODE(IMP_USYNCH_QOS_OVERRIDE, IMP_USYNCH_ADD_OVERRIDE)) | DBG_FUNC_START,
						  thread_tid(thread), override_qos, first_override_for_resource ? 1 : 0, 0, 0);

	DTRACE_BOOST5(qos_add_override_pre, uint64_t, tid, uint64_t, thread->requested_policy.thrp_qos,
		uint64_t, thread->effective_policy.thep_qos, int, override_qos, boolean_t, first_override_for_resource);

	struct task_requested_policy requested = thread->requested_policy;
	struct thread_qos_override *override;
	struct thread_qos_override *deferred_free_override = NULL;
	int new_qos_override, prev_qos_override;
	int new_effective_qos;
	boolean_t has_thread_reference = FALSE;

	_canonicalize_resource_and_type(&resource, &resource_type);

	if (first_override_for_resource) {
		override = _find_qos_override(thread, resource, resource_type);
		if (override) {
			override->override_contended_resource_count++;
		} else {
			struct thread_qos_override *override_new;

			/* We need to allocate a new object. Drop the task lock and recheck afterwards in case someone else added the override */
			thread_reference(thread);
			has_thread_reference = TRUE;
			task_unlock(task);
			override_new = zalloc(thread_qos_override_zone);
			task_lock(task);

			override = _find_qos_override(thread, resource, resource_type);
			if (override) {
				/* Someone else already allocated while the task lock was dropped */
				deferred_free_override = override_new;
				override->override_contended_resource_count++;
			} else {
				override = override_new;
				override->override_next = thread->overrides;
				override->override_contended_resource_count = 1 /* since first_override_for_resource was TRUE */;
				override->override_resource = resource;
				override->override_resource_type = resource_type;
				override->override_qos = THREAD_QOS_UNSPECIFIED;
				thread->overrides = override;
			}
		}
	} else {
		override = _find_qos_override(thread, resource, resource_type);
	}

	if (override) {
		if (override->override_qos == THREAD_QOS_UNSPECIFIED)
			override->override_qos = override_qos;
		else
			override->override_qos = MAX(override->override_qos, override_qos);
	}

	/* Determine how to combine the various overrides into a single current requested override */
	prev_qos_override = requested.thrp_qos_override;
	new_qos_override = _calculate_requested_qos_override(thread);

	if (new_qos_override != prev_qos_override) {
		requested.thrp_qos_override = new_qos_override;

		thread->requested_policy = requested;

		task_policy_update_locked(task, thread, &pend_token);
		
		if (!has_thread_reference) {
			thread_reference(thread);
		}
		
		task_unlock(task);
		
		task_policy_update_complete_unlocked(task, thread, &pend_token);

		new_effective_qos = thread->effective_policy.thep_qos;
		
		thread_deallocate(thread);
	} else {
		new_effective_qos = thread->effective_policy.thep_qos;

		task_unlock(task);

		if (has_thread_reference) {
			thread_deallocate(thread);
		}
	}

	if (deferred_free_override) {
		zfree(thread_qos_override_zone, deferred_free_override);
	}

	DTRACE_BOOST3(qos_add_override_post, int, prev_qos_override, int, new_qos_override,
				  int, new_effective_qos);

	KERNEL_DEBUG_CONSTANT((IMPORTANCE_CODE(IMP_USYNCH_QOS_OVERRIDE, IMP_USYNCH_ADD_OVERRIDE)) | DBG_FUNC_END,
						  new_qos_override, resource, resource_type, 0, 0);

	return TRUE;
}


static boolean_t _proc_thread_qos_remove_override_internal(task_t task, thread_t thread, uint64_t tid, user_addr_t resource, int resource_type, boolean_t reset)
{
	thread_t	self = current_thread();
	struct task_pend_token pend_token = {};

	/* XXX move to thread mutex when thread policy does */
	task_lock(task);

	/*
	 * If thread is passed, it is assumed to be most accurate, since the caller must have an explicit (or implicit) reference
	 * to the thread
	 */
	if (thread != THREAD_NULL) {
		assert(task == thread->task);
	} else {
		if (tid == self->thread_id) {
			thread = self;
		} else {
			thread = task_findtid(task, tid);

			if (thread == THREAD_NULL) {
				KERNEL_DEBUG_CONSTANT((IMPORTANCE_CODE(IMP_USYNCH_QOS_OVERRIDE, IMP_USYNCH_REMOVE_OVERRIDE)) | DBG_FUNC_NONE,
									  tid, 0, 0xdead, 0, 0);
				task_unlock(task);
				return FALSE;
			}
		}
	}

	struct task_requested_policy requested = thread->requested_policy;
	struct thread_qos_override *deferred_free_override_list = NULL;
	int new_qos_override, prev_qos_override;

	_canonicalize_resource_and_type(&resource, &resource_type);

	_find_and_decrement_qos_override(thread, resource, resource_type, reset, &deferred_free_override_list);

	KERNEL_DEBUG_CONSTANT((IMPORTANCE_CODE(IMP_USYNCH_QOS_OVERRIDE, IMP_USYNCH_REMOVE_OVERRIDE)) | DBG_FUNC_START,
						  thread_tid(thread), resource, reset, 0, 0);

	/* Determine how to combine the various overrides into a single current requested override */
	prev_qos_override = requested.thrp_qos_override;
	new_qos_override = _calculate_requested_qos_override(thread);

	if (new_qos_override != prev_qos_override) {
		requested.thrp_qos_override = new_qos_override;

		thread->requested_policy = requested;

		task_policy_update_locked(task, thread, &pend_token);
		
		thread_reference(thread);
			
		task_unlock(task);
		
		task_policy_update_complete_unlocked(task, thread, &pend_token);
		
		thread_deallocate(thread);
	} else {
		task_unlock(task);
	}

	while (deferred_free_override_list) {
		struct thread_qos_override *override_next = deferred_free_override_list->override_next;
		
		zfree(thread_qos_override_zone, deferred_free_override_list);
		deferred_free_override_list = override_next;
	}

	KERNEL_DEBUG_CONSTANT((IMPORTANCE_CODE(IMP_USYNCH_QOS_OVERRIDE, IMP_USYNCH_REMOVE_OVERRIDE)) | DBG_FUNC_END,
						  0, 0, 0, 0, 0);

	return TRUE;
}

boolean_t proc_thread_qos_remove_override(task_t task, thread_t thread, uint64_t tid, user_addr_t resource, int resource_type)
{
	return _proc_thread_qos_remove_override_internal(task, thread, tid, resource, resource_type, FALSE);

}

boolean_t proc_thread_qos_reset_override(task_t task, thread_t thread, uint64_t tid, user_addr_t resource, int resource_type)
{
	return _proc_thread_qos_remove_override_internal(task, thread, tid, resource, resource_type, TRUE);
}

/* Deallocate before thread termination */
void proc_thread_qos_deallocate(thread_t thread)
{
	task_t task = thread->task;
	struct thread_qos_override *override;

	/* XXX move to thread mutex when thread policy does */
	task_lock(task);
	override = thread->overrides;
	thread->overrides = NULL; 		/* task policy re-evaluation needed? */
	thread->requested_policy.thrp_qos_override = THREAD_QOS_UNSPECIFIED;
	task_unlock(task);

	while (override) {
		struct thread_qos_override *override_next = override->override_next;
		
		zfree(thread_qos_override_zone, override);
		override = override_next;
	}
}

/* TODO: remove this variable when interactive daemon audit period is over */
extern boolean_t ipc_importance_interactive_receiver;

/*
 * Called at process exec to initialize the apptype, qos clamp, and qos seed of a process
 *
 * TODO: Make this function more table-driven instead of ad-hoc
 */
void
proc_set_task_spawnpolicy(task_t task, int apptype, int qos_clamp,
                          ipc_port_t * portwatch_ports, int portwatch_count)
{
	struct task_pend_token pend_token = {};

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				  (IMPORTANCE_CODE(IMP_TASK_APPTYPE, apptype)) | DBG_FUNC_START,
				  audit_token_pid_from_task(task), trequested_0(task, THREAD_NULL), trequested_1(task, THREAD_NULL),
				  apptype, 0);

	switch (apptype) {
		case TASK_APPTYPE_APP_TAL:
		case TASK_APPTYPE_APP_DEFAULT:
			/* Apps become donors via the 'live-donor' flag instead of the static donor flag */
			task_importance_mark_donor(task, FALSE);
			task_importance_mark_live_donor(task, TRUE);
			task_importance_mark_receiver(task, FALSE);
			/* Apps are de-nap recievers on desktop for suppression behaviors */
			task_importance_mark_denap_receiver(task, TRUE);
			break;

		case TASK_APPTYPE_DAEMON_INTERACTIVE:
			task_importance_mark_donor(task, TRUE);
			task_importance_mark_live_donor(task, FALSE);

			/* 
			 * A boot arg controls whether interactive daemons are importance receivers.
			 * Normally, they are not.  But for testing their behavior as an adaptive
			 * daemon, the boot-arg can be set.
			 *
			 * TODO: remove this when the interactive daemon audit period is over.
			 */
			task_importance_mark_receiver(task, /* FALSE */ ipc_importance_interactive_receiver);
			task_importance_mark_denap_receiver(task, FALSE);
			break;

		case TASK_APPTYPE_DAEMON_STANDARD:
			task_importance_mark_donor(task, TRUE);
			task_importance_mark_live_donor(task, FALSE);
			task_importance_mark_receiver(task, FALSE);
			task_importance_mark_denap_receiver(task, FALSE);
			break;

		case TASK_APPTYPE_DAEMON_ADAPTIVE:
			task_importance_mark_donor(task, FALSE);
			task_importance_mark_live_donor(task, FALSE);
			task_importance_mark_receiver(task, TRUE);
			task_importance_mark_denap_receiver(task, FALSE);
			break;

		case TASK_APPTYPE_DAEMON_BACKGROUND:
			task_importance_mark_donor(task, FALSE);
			task_importance_mark_live_donor(task, FALSE);
			task_importance_mark_receiver(task, FALSE);
			task_importance_mark_denap_receiver(task, FALSE);
			break;

		case TASK_APPTYPE_NONE:
			break;
	}

	if (portwatch_ports != NULL && apptype == TASK_APPTYPE_DAEMON_ADAPTIVE) {
		int portwatch_boosts = 0;

		for (int i = 0; i < portwatch_count; i++) {
			ipc_port_t port = NULL;

			if ((port = portwatch_ports[i]) != NULL) {
				int boost = 0;
				task_add_importance_watchport(task, port, &boost);
				portwatch_boosts += boost;
			}
		}

		if (portwatch_boosts > 0) {
			task_importance_hold_internal_assertion(task, portwatch_boosts);
		}
	}

	task_lock(task);

	if (apptype == TASK_APPTYPE_APP_TAL) {
		/* TAL starts off enabled by default */
		task->requested_policy.t_tal_enabled = 1;
	}

	if (apptype != TASK_APPTYPE_NONE) {
		task->requested_policy.t_apptype = apptype;

	}

	if (qos_clamp != THREAD_QOS_UNSPECIFIED) {
		task->requested_policy.t_qos_clamp = qos_clamp;
	}

	task_policy_update_locked(task, THREAD_NULL, &pend_token);

	task_unlock(task);

	/* Ensure the donor bit is updated to be in sync with the new live donor status */
	pend_token.tpt_update_live_donor = 1;

	task_policy_update_complete_unlocked(task, THREAD_NULL, &pend_token);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				  (IMPORTANCE_CODE(IMP_TASK_APPTYPE, apptype)) | DBG_FUNC_END,
				  audit_token_pid_from_task(task), trequested_0(task, THREAD_NULL), trequested_1(task, THREAD_NULL),
				  task_is_importance_receiver(task), 0);
}

/* Set up the primordial thread's QoS */
void
task_set_main_thread_qos(task_t task, thread_t main_thread) {
	struct task_pend_token pend_token = {};

	assert(main_thread->task == task);

	task_lock(task);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	                          (IMPORTANCE_CODE(IMP_MAIN_THREAD_QOS, 0)) | DBG_FUNC_START,
	                          audit_token_pid_from_task(task), trequested_0(task, THREAD_NULL), trequested_1(task, THREAD_NULL),
	                          main_thread->requested_policy.thrp_qos, 0);

	int primordial_qos = THREAD_QOS_UNSPECIFIED;

	int qos_clamp = task->requested_policy.t_qos_clamp;

	switch (task->requested_policy.t_apptype) {
		case TASK_APPTYPE_APP_TAL:
		case TASK_APPTYPE_APP_DEFAULT:
			primordial_qos = THREAD_QOS_USER_INTERACTIVE;
			break;

		case TASK_APPTYPE_DAEMON_INTERACTIVE:
		case TASK_APPTYPE_DAEMON_STANDARD:
		case TASK_APPTYPE_DAEMON_ADAPTIVE:
			primordial_qos = THREAD_QOS_LEGACY;
			break;

		case TASK_APPTYPE_DAEMON_BACKGROUND:
			primordial_qos = THREAD_QOS_BACKGROUND;
			break;
	}

	if (qos_clamp != THREAD_QOS_UNSPECIFIED) {
		if (primordial_qos != THREAD_QOS_UNSPECIFIED) {
			primordial_qos = MIN(qos_clamp, primordial_qos);
		} else {
			primordial_qos = qos_clamp;
		}
	}

	main_thread->requested_policy.thrp_qos = primordial_qos;

	task_policy_update_locked(task, main_thread, &pend_token);

	task_unlock(task);

	task_policy_update_complete_unlocked(task, main_thread, &pend_token);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	                          (IMPORTANCE_CODE(IMP_MAIN_THREAD_QOS, 0)) | DBG_FUNC_END,
	                          audit_token_pid_from_task(task), trequested_0(task, THREAD_NULL), trequested_1(task, THREAD_NULL),
	                          primordial_qos, 0);
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
	return qos_latency_policy_package(proc_get_effective_task_policy(task, TASK_POLICY_LATENCY_QOS));
}

/* update the darwin background action state in the flags field for libproc */
int
proc_get_darwinbgstate(task_t task, uint32_t * flagsp)
{
	if (task->requested_policy.ext_darwinbg)
		*flagsp |= PROC_FLAG_EXT_DARWINBG;

	if (task->requested_policy.int_darwinbg)
		*flagsp |= PROC_FLAG_DARWINBG;


	if (task->requested_policy.t_apptype == TASK_APPTYPE_APP_DEFAULT ||
	    task->requested_policy.t_apptype == TASK_APPTYPE_APP_TAL)
		*flagsp |= PROC_FLAG_APPLICATION;

	if (task->requested_policy.t_apptype == TASK_APPTYPE_DAEMON_ADAPTIVE)
		*flagsp |= PROC_FLAG_ADAPTIVE;

	if (task->requested_policy.t_apptype == TASK_APPTYPE_DAEMON_ADAPTIVE && task->requested_policy.t_boosted == 1)
		*flagsp |= PROC_FLAG_ADAPTIVE_IMPORTANT;

	if (task_is_importance_donor(task))
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
	info->pending   = 0;
	task_unlock(task);
}

/*
 * Tracepoint data... Reading the tracepoint data can be somewhat complicated.
 * The current scheme packs as much data into a single tracepoint as it can.
 *
 * Each task/thread requested/effective structure is 64 bits in size. Any
 * given tracepoint will emit either requested or effective data, but not both.
 *
 * A tracepoint may emit any of task, thread, or task & thread data.
 * 
 * The type of data emitted varies with pointer size. Where possible, both
 * task and thread data are emitted. In LP32 systems, the first and second
 * halves of either the task or thread data is emitted.
 *
 * The code uses uintptr_t array indexes instead of high/low to avoid
 * confusion WRT big vs little endian.
 *
 * The truth table for the tracepoint data functions is below, and has the
 * following invariants:
 *
 * 1) task and thread are uintptr_t*
 * 2) task may never be NULL
 *
 *
 *                                     LP32            LP64
 * trequested_0(task, NULL)            task[0]         task[0]
 * trequested_1(task, NULL)            task[1]         NULL
 * trequested_0(task, thread)          thread[0]       task[0]
 * trequested_1(task, thread)          thread[1]       thread[0]
 *
 * Basically, you get a full task or thread on LP32, and both on LP64.
 *
 * The uintptr_t munging here is squicky enough to deserve a comment.
 *
 * The variables we are accessing are laid out in memory like this:
 *
 * [            LP64 uintptr_t  0          ]
 * [ LP32 uintptr_t 0 ] [ LP32 uintptr_t 1 ]
 *
 *      1   2   3   4     5   6   7   8
 *
 */

static uintptr_t
trequested_0(task_t task, thread_t thread)
{
	assert(task);
	_Static_assert(sizeof(struct task_requested_policy) == sizeof(uint64_t), "size invariant violated");
	_Static_assert(sizeof(task->requested_policy) == sizeof(thread->requested_policy), "size invariant violated");

	uintptr_t* raw = (uintptr_t*)((thread == THREAD_NULL) ? &task->requested_policy : &thread->requested_policy);
	return raw[0];
}

static uintptr_t
trequested_1(task_t task, thread_t thread)
{
	assert(task);
	_Static_assert(sizeof(struct task_requested_policy) == sizeof(uint64_t), "size invariant violated");
	_Static_assert(sizeof(task->requested_policy) == sizeof(thread->requested_policy), "size invariant violated");

#if defined __LP64__
	return (thread == NULL) ? 0 : *(uintptr_t*)&thread->requested_policy;
#else
	uintptr_t* raw = (uintptr_t*)((thread == THREAD_NULL) ? &task->requested_policy : &thread->requested_policy);
	return raw[1];
#endif
}

static uintptr_t
teffective_0(task_t task, thread_t thread)
{
	assert(task);
	_Static_assert(sizeof(struct task_effective_policy) == sizeof(uint64_t), "size invariant violated");
	_Static_assert(sizeof(task->effective_policy) == sizeof(thread->effective_policy), "size invariant violated");

	uintptr_t* raw = (uintptr_t*)((thread == THREAD_NULL) ? &task->effective_policy : &thread->effective_policy);
	return raw[0];
}

static uintptr_t
teffective_1(task_t task, thread_t thread)
{
	assert(task);
	_Static_assert(sizeof(struct task_effective_policy) == sizeof(uint64_t), "size invariant violated");
	_Static_assert(sizeof(task->effective_policy) == sizeof(thread->effective_policy), "size invariant violated");

#if defined __LP64__
	return (thread == NULL) ? 0 : *(uintptr_t*)&thread->effective_policy;
#else
	uintptr_t* raw = (uintptr_t*)((thread == THREAD_NULL) ? &task->effective_policy : &thread->effective_policy);
	return raw[1];
#endif
}

/* dump pending for tracepoint */
static uint32_t tpending(task_pend_token_t pend_token) { return *(uint32_t*)(void*)(pend_token); }

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

	if (thread != THREAD_NULL) {
		bits |= (requested.thrp_qos     ? (((uint64_t)requested.thrp_qos)   << POLICY_REQ_TH_QOS_SHIFT)  : 0);
		bits |= (requested.thrp_qos_override     ? (((uint64_t)requested.thrp_qos_override)   << POLICY_REQ_TH_QOS_OVER_SHIFT)  : 0);
	}

	bits |= (requested.t_boosted            ? POLICY_REQ_BOOSTED        : 0);
	bits |= (requested.t_tal_enabled        ? POLICY_REQ_TAL_ENABLED    : 0);
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
	bits |= (requested.t_sup_bg_sockets     ? POLICY_REQ_SUP_BG_SOCKETS     : 0);
	bits |= (requested.t_base_latency_qos   ? (((uint64_t)requested.t_base_latency_qos) << POLICY_REQ_BASE_LATENCY_QOS_SHIFT) : 0);
	bits |= (requested.t_over_latency_qos   ? (((uint64_t)requested.t_over_latency_qos) << POLICY_REQ_OVER_LATENCY_QOS_SHIFT) : 0);
	bits |= (requested.t_base_through_qos   ? (((uint64_t)requested.t_base_through_qos) << POLICY_REQ_BASE_THROUGH_QOS_SHIFT) : 0);
	bits |= (requested.t_over_through_qos   ? (((uint64_t)requested.t_over_through_qos) << POLICY_REQ_OVER_THROUGH_QOS_SHIFT) : 0);
	bits |= (requested.t_sfi_managed        ? POLICY_REQ_SFI_MANAGED        : 0);
	bits |= (requested.t_qos_clamp          ? (((uint64_t)requested.t_qos_clamp)        << POLICY_REQ_QOS_CLAMP_SHIFT)        : 0);

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
	bits |= (effective.qos_ui_is_urgent     ? POLICY_EFF_QOS_UI_IS_URGENT : 0);

	if (thread != THREAD_NULL)
		bits |= (effective.thep_qos     ? (((uint64_t)effective.thep_qos)   << POLICY_EFF_TH_QOS_SHIFT)  : 0);

	bits |= (effective.t_tal_engaged        ? POLICY_EFF_TAL_ENGAGED    : 0);
	bits |= (effective.t_suspended          ? POLICY_EFF_SUSPENDED      : 0);
	bits |= (effective.t_watchers_bg        ? POLICY_EFF_WATCHERS_BG    : 0);
	bits |= (effective.t_sup_active         ? POLICY_EFF_SUP_ACTIVE     : 0);
	bits |= (effective.t_suppressed_cpu     ? POLICY_EFF_SUP_CPU        : 0);
	bits |= (effective.t_role               ? (((uint64_t)effective.t_role)        << POLICY_EFF_ROLE_SHIFT)        : 0);
	bits |= (effective.t_latency_qos        ? (((uint64_t)effective.t_latency_qos) << POLICY_EFF_LATENCY_QOS_SHIFT) : 0);
	bits |= (effective.t_through_qos        ? (((uint64_t)effective.t_through_qos) << POLICY_EFF_THROUGH_QOS_SHIFT) : 0);
	bits |= (effective.t_sfi_managed        ? POLICY_EFF_SFI_MANAGED    : 0);
	bits |= (effective.t_qos_ceiling        ? (((uint64_t)effective.t_qos_ceiling) << POLICY_EFF_QOS_CEILING_SHIFT) : 0);

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

	/* TEMPORARY boot arg to control App suppression */
	PE_parse_boot_argn("task_policy_suppression_disable",
			   &task_policy_suppression_disable,
			   sizeof(task_policy_suppression_disable));
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
	telemetry_task_ctl_locked(task, TF_CPUMON_WARNING, 0);
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

static void
task_importance_update_live_donor(task_t target_task)
{
#if IMPORTANCE_INHERITANCE

	ipc_importance_task_t task_imp;

	task_imp = ipc_importance_for_task(target_task, FALSE);
	if (IIT_NULL != task_imp) {
		ipc_importance_task_update_live_donor(task_imp);
		ipc_importance_task_release(task_imp);
	}
#endif /* IMPORTANCE_INHERITANCE */
}

void
task_importance_mark_donor(task_t task, boolean_t donating)
{
#if IMPORTANCE_INHERITANCE
	ipc_importance_task_t task_imp;

	task_imp = ipc_importance_for_task(task, FALSE);
	if (IIT_NULL != task_imp) {
		ipc_importance_task_mark_donor(task_imp, donating);
		ipc_importance_task_release(task_imp);
	}
#endif /* IMPORTANCE_INHERITANCE */
}

void
task_importance_mark_live_donor(task_t task, boolean_t live_donating)
{
#if IMPORTANCE_INHERITANCE
	ipc_importance_task_t task_imp;

	task_imp = ipc_importance_for_task(task, FALSE);
	if (IIT_NULL != task_imp) {
		ipc_importance_task_mark_live_donor(task_imp, live_donating);
		ipc_importance_task_release(task_imp);
	}
#endif /* IMPORTANCE_INHERITANCE */
}

void
task_importance_mark_receiver(task_t task, boolean_t receiving)
{
#if IMPORTANCE_INHERITANCE
	ipc_importance_task_t task_imp;

	task_imp = ipc_importance_for_task(task, FALSE);
	if (IIT_NULL != task_imp) {
		ipc_importance_task_mark_receiver(task_imp, receiving);
		ipc_importance_task_release(task_imp);
	}
#endif /* IMPORTANCE_INHERITANCE */
}

void
task_importance_mark_denap_receiver(task_t task, boolean_t denap)
{
#if IMPORTANCE_INHERITANCE
	ipc_importance_task_t task_imp;

	task_imp = ipc_importance_for_task(task, FALSE);
	if (IIT_NULL != task_imp) {
		ipc_importance_task_mark_denap_receiver(task_imp, denap);
		ipc_importance_task_release(task_imp);
	}
#endif /* IMPORTANCE_INHERITANCE */
}

void
task_importance_reset(__imp_only task_t task)
{
#if IMPORTANCE_INHERITANCE
	ipc_importance_task_t task_imp;

	/* TODO: Lower importance downstream before disconnect */
	task_imp = task->task_imp_base;
	ipc_importance_reset(task_imp, FALSE);
	task_importance_update_live_donor(task);
#endif /* IMPORTANCE_INHERITANCE */
}

#if IMPORTANCE_INHERITANCE

/*
 * Sets the task boost bit to the provided value.  Does NOT run the update function.
 *
 * Task lock must be held.
 */
void
task_set_boost_locked(task_t task, boolean_t boost_active)
{
#if IMPORTANCE_DEBUG
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_BOOST, (boost_active ? IMP_BOOSTED : IMP_UNBOOSTED)) | DBG_FUNC_START),
	                          proc_selfpid(), audit_token_pid_from_task(task), trequested_0(task, THREAD_NULL), trequested_1(task, THREAD_NULL), 0);
#endif

	task->requested_policy.t_boosted = boost_active;

#if IMPORTANCE_DEBUG
	if (boost_active == TRUE){
		DTRACE_BOOST2(boost, task_t, task, int, audit_token_pid_from_task(task));
	} else {
		DTRACE_BOOST2(unboost, task_t, task, int, audit_token_pid_from_task(task));
	}
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_BOOST, (boost_active ? IMP_BOOSTED : IMP_UNBOOSTED)) | DBG_FUNC_END),
	                          proc_selfpid(), audit_token_pid_from_task(task),
	                          trequested_0(task, THREAD_NULL), trequested_1(task, THREAD_NULL), 0);
#endif
}

/*
 * Sets the task boost bit to the provided value and applies the update.
 *
 * Task lock must be held.  Must call update complete after unlocking the task.
 */
void
task_update_boost_locked(task_t task, boolean_t boost_active, task_pend_token_t pend_token)
{
	task_set_boost_locked(task, boost_active);

	task_policy_update_locked(task, THREAD_NULL, pend_token);
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
	if (task->task_imp_base == IIT_NULL)
		return FALSE;
	return ipc_importance_task_is_donor(task->task_imp_base);
}

/*
 * Query the status of the task's donor mark.
 */
boolean_t
task_is_marked_importance_donor(task_t task)
{
	if (task->task_imp_base == IIT_NULL)
		return FALSE;
	return ipc_importance_task_is_marked_donor(task->task_imp_base);
}

/*
 * Query the status of the task's live donor and donor mark.
 */
boolean_t
task_is_marked_live_importance_donor(task_t task)
{
	if (task->task_imp_base == IIT_NULL)
		return FALSE;
	return ipc_importance_task_is_marked_live_donor(task->task_imp_base);
}


/*
 * This routine may be called without holding task lock
 * since the value of imp_receiver can never be unset.
 */
boolean_t
task_is_importance_receiver(task_t task)
{
	if (task->task_imp_base == IIT_NULL)
		return FALSE;
	return ipc_importance_task_is_marked_receiver(task->task_imp_base);
}

/*
 * Query the task's receiver mark.
 */
boolean_t
task_is_marked_importance_receiver(task_t task)
{
	if (task->task_imp_base == IIT_NULL)
		return FALSE;
	return ipc_importance_task_is_marked_receiver(task->task_imp_base);
}

/*
 * This routine may be called without holding task lock
 * since the value of de-nap receiver can never be unset.
 */
boolean_t
task_is_importance_denap_receiver(task_t task)
{
	if (task->task_imp_base == IIT_NULL)
		return FALSE;
	return ipc_importance_task_is_denap_receiver(task->task_imp_base);
}

/*
 * Query the task's de-nap receiver mark.
 */
boolean_t
task_is_marked_importance_denap_receiver(task_t task)
{
	if (task->task_imp_base == IIT_NULL)
		return FALSE;
	return ipc_importance_task_is_marked_denap_receiver(task->task_imp_base);
}

/*
 * This routine may be called without holding task lock
 * since the value of imp_receiver can never be unset.
 */
boolean_t
task_is_importance_receiver_type(task_t task)
{
	if (task->task_imp_base == IIT_NULL)
		return FALSE;
	return (task_is_importance_receiver(task) ||
		task_is_importance_denap_receiver(task));
}

/*
 * External importance assertions are managed by the process in userspace
 * Internal importance assertions are the responsibility of the kernel
 * Assertions are changed from internal to external via task_importance_externalize_assertion
 */

int
task_importance_hold_watchport_assertion(task_t target_task, uint32_t count)
{
	ipc_importance_task_t task_imp;
	kern_return_t ret;

	/* must already have set up an importance */
	task_imp = target_task->task_imp_base;
	assert(IIT_NULL != task_imp);

	ret = ipc_importance_task_hold_internal_assertion(task_imp, count);
	return (KERN_SUCCESS != ret) ? ENOTSUP : 0;
}

int
task_importance_hold_internal_assertion(task_t target_task, uint32_t count)
{
	ipc_importance_task_t task_imp;
	kern_return_t ret;

	/* may be first time, so allow for possible importance setup */
	task_imp = ipc_importance_for_task(target_task, FALSE);
	if (IIT_NULL == task_imp) {
		return EOVERFLOW;
	}
	ret = ipc_importance_task_hold_internal_assertion(task_imp, count);
	ipc_importance_task_release(task_imp);

	return (KERN_SUCCESS != ret) ? ENOTSUP : 0;
}

int
task_importance_hold_file_lock_assertion(task_t target_task, uint32_t count)
{
	ipc_importance_task_t task_imp;
	kern_return_t ret;

	/* may be first time, so allow for possible importance setup */
	task_imp = ipc_importance_for_task(target_task, FALSE);
	if (IIT_NULL == task_imp) {
		return EOVERFLOW;
	}
	ret = ipc_importance_task_hold_file_lock_assertion(task_imp, count);
	ipc_importance_task_release(task_imp);

	return (KERN_SUCCESS != ret) ? ENOTSUP : 0;
}

int
task_importance_hold_legacy_external_assertion(task_t target_task, uint32_t count)
{
	ipc_importance_task_t task_imp;
	kern_return_t ret;
 
	/* must already have set up an importance */
	task_imp = target_task->task_imp_base;
	if (IIT_NULL == task_imp) {
		return EOVERFLOW;
	}	  
	ret = ipc_importance_task_hold_legacy_external_assertion(task_imp, count);
	return (KERN_SUCCESS != ret) ? ENOTSUP : 0;
}

int
task_importance_drop_internal_assertion(task_t target_task, uint32_t count)
{
	ipc_importance_task_t task_imp;
	kern_return_t ret;
 
	/* must already have set up an importance */
	task_imp = target_task->task_imp_base;
	if (IIT_NULL == task_imp) {
		return EOVERFLOW;
	}
	ret = ipc_importance_task_drop_internal_assertion(target_task->task_imp_base, count);
	return (KERN_SUCCESS != ret) ? ENOTSUP : 0;
}

int
task_importance_drop_file_lock_assertion(task_t target_task, uint32_t count)
{
	ipc_importance_task_t task_imp;
	kern_return_t ret;
 
	/* must already have set up an importance */
	task_imp = target_task->task_imp_base;
	if (IIT_NULL == task_imp) {
		return EOVERFLOW;
	}
	ret = ipc_importance_task_drop_file_lock_assertion(target_task->task_imp_base, count);
	return (KERN_SUCCESS != ret) ? EOVERFLOW : 0;
}

int
task_importance_drop_legacy_external_assertion(task_t target_task, uint32_t count)
{
	ipc_importance_task_t task_imp;
	kern_return_t ret;
 
	/* must already have set up an importance */
	task_imp = target_task->task_imp_base;
	if (IIT_NULL == task_imp) {
		return EOVERFLOW;
	}
	ret = ipc_importance_task_drop_legacy_external_assertion(task_imp, count);
	return (KERN_SUCCESS != ret) ? EOVERFLOW : 0;
}

static void
task_add_importance_watchport(task_t task, mach_port_t port, int *boostp)
{
	int boost = 0;

	__impdebug_only int released_pid = 0;
	__impdebug_only int pid = audit_token_pid_from_task(task);

	ipc_importance_task_t release_imp_task = IIT_NULL;

	if (IP_VALID(port) != 0) {
		ipc_importance_task_t new_imp_task = ipc_importance_for_task(task, FALSE);

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
			if (IIT_NULL != port->ip_imp_task) {
				/*
				 * if this port is already bound to a task,
				 * release the task reference and drop any
				 * watchport-forwarded boosts
				 */
				release_imp_task = port->ip_imp_task;
				port->ip_imp_task = IIT_NULL;
			}

			/* mark the port is watching another task (reference held in port->ip_imp_task) */
			if (ipc_importance_task_is_marked_receiver(new_imp_task)) {
				port->ip_imp_task = new_imp_task;
				new_imp_task = IIT_NULL;
			}
		}
		ip_unlock(port);

		if (IIT_NULL != new_imp_task) {
			ipc_importance_task_release(new_imp_task);
		}

		if (IIT_NULL != release_imp_task) {
			if (boost > 0)
				ipc_importance_task_drop_internal_assertion(release_imp_task, boost);

			// released_pid = audit_token_pid_from_task(release_imp_task); /* TODO: Need ref-safe way to get pid */
			ipc_importance_task_release(release_imp_task);
		}
#if IMPORTANCE_DEBUG
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_WATCHPORT, 0)) | DBG_FUNC_NONE,
		        proc_selfpid(), pid, boost, released_pid, 0);
#endif /* IMPORTANCE_DEBUG */
	}

	*boostp = boost;
	return;
}

#endif /* IMPORTANCE_INHERITANCE */

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


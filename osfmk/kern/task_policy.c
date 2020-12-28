/*
 * Copyright (c) 2000-2016 Apple Computer, Inc. All rights reserved.
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

#include <kern/policy_internal.h>
#include <mach/task_policy.h>

#include <mach/mach_types.h>
#include <mach/task_server.h>

#include <kern/host.h>                  /* host_priv_self()        */
#include <mach/host_priv.h>             /* host_get_special_port() */
#include <mach/host_special_ports.h>    /* RESOURCE_NOTIFY_PORT    */
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
#if CONFIG_EMBEDDED
#include <kern/kalloc.h>
#include <sys/errno.h>
#endif /* CONFIG_EMBEDDED */

#if IMPORTANCE_INHERITANCE
#include <ipc/ipc_importance.h>
#if IMPORTANCE_TRACE
#include <mach/machine/sdt.h>
#endif /* IMPORTANCE_TRACE */
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
 *  Threads and tasks have two policy fields: requested, effective.
 *  Requested represents the wishes of each interface that influences task policy.
 *  Effective represents the distillation of that policy into a set of behaviors.
 *
 *  Each thread making a modification in the policy system passes a 'pending' struct,
 *  which tracks updates that will be applied after dropping the policy engine lock.
 *
 *  Each interface that has an input into the task policy state machine controls a field in requested.
 *  If the interface has a getter, it returns what is in the field in requested, but that is
 *  not necessarily what is actually in effect.
 *
 *  All kernel subsystems that behave differently based on task policy call into
 *  the proc_get_effective_(task|thread)_policy functions, which return the decision of the task policy state machine
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
 *  the setter and getter in proc_(set|get)_task_policy*,
 *  then set up the effects of that behavior in task_policy_update*. If the policy manifests
 *  itself as a distinct effective policy, add it to the effective struct and add it to the
 *  proc_get_effective_task_policy accessor.
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
 *  Changing task policy on a task takes the task lock.
 *  Changing task policy on a thread takes the thread mutex.
 *  Task policy changes that affect threads will take each thread's mutex to update it if necessary.
 *
 *  Querying the effective policy does not take a lock, because callers
 *  may run in interrupt context or other place where locks are not OK.
 *
 *  This means that any notification of state change needs to be externally synchronized.
 *  We do this by idempotent callouts after the state has changed to ask
 *  other subsystems to update their view of the world.
 *
 * TODO: Move all cpu/wakes/io monitor code into a separate file
 * TODO: Move all importance code over to importance subsystem
 * TODO: Move all taskwatch code into a separate file
 * TODO: Move all VM importance code into a separate file
 */

/* Task policy related helper functions */
static void proc_set_task_policy_locked(task_t task, int category, int flavor, int value, int value2);

static void task_policy_update_locked(task_t task, task_pend_token_t pend_token);
static void task_policy_update_internal_locked(task_t task, boolean_t in_create, task_pend_token_t pend_token);

/* For attributes that have two scalars as input/output */
static void proc_set_task_policy2(task_t task, int category, int flavor, int value1, int value2);
static void proc_get_task_policy2(task_t task, int category, int flavor, int *value1, int *value2);

static boolean_t task_policy_update_coalition_focal_tasks(task_t task, int prev_role, int next_role, task_pend_token_t pend_token);

static uint64_t task_requested_bitfield(task_t task);
static uint64_t task_effective_bitfield(task_t task);

/* Convenience functions for munging a policy bitfield into a tracepoint */
static uintptr_t trequested_0(task_t task);
static uintptr_t trequested_1(task_t task);
static uintptr_t teffective_0(task_t task);
static uintptr_t teffective_1(task_t task);

/* CPU limits helper functions */
static int task_set_cpuusage(task_t task, uint8_t percentage, uint64_t interval, uint64_t deadline, int scope, int entitled);
static int task_get_cpuusage(task_t task, uint8_t *percentagep, uint64_t *intervalp, uint64_t *deadlinep, int *scope);
static int task_enable_cpumon_locked(task_t task);
static int task_disable_cpumon(task_t task);
static int task_clear_cpuusage_locked(task_t task, int cpumon_entitled);
static int task_apply_resource_actions(task_t task, int type);
static void task_action_cpuusage(thread_call_param_t param0, thread_call_param_t param1);

#ifdef MACH_BSD
typedef struct proc *   proc_t;
int                     proc_pid(void *proc);
extern int              proc_selfpid(void);
extern char *           proc_name_address(void *p);
extern char *           proc_best_name(proc_t proc);

extern int proc_pidpathinfo_internal(proc_t p, uint64_t arg,
    char *buffer, uint32_t buffersize,
    int32_t *retval);
#endif /* MACH_BSD */


#if CONFIG_EMBEDDED
/* TODO: make CONFIG_TASKWATCH */
/* Taskwatch related helper functions */
static void set_thread_appbg(thread_t thread, int setbg, int importance);
static void add_taskwatch_locked(task_t task, task_watch_t * twp);
static void remove_taskwatch_locked(task_t task, task_watch_t * twp);
static void task_watch_lock(void);
static void task_watch_unlock(void);
static void apply_appstate_watchers(task_t task);

typedef struct task_watcher {
	queue_chain_t   tw_links;       /* queueing of threads */
	task_t          tw_task;        /* task that is being watched */
	thread_t        tw_thread;      /* thread that is watching the watch_task */
	int             tw_state;       /* the current app state of the thread */
	int             tw_importance;  /* importance prior to backgrounding */
} task_watch_t;

typedef struct thread_watchlist {
	thread_t        thread;         /* thread being worked on for taskwatch action */
	int             importance;     /* importance to be restored if thread is being made active */
} thread_watchlist_t;

#endif /* CONFIG_EMBEDDED */

extern int memorystatus_update_priority_for_appnap(proc_t p, boolean_t is_appnap);

/* Importance Inheritance related helper functions */

#if IMPORTANCE_INHERITANCE

static void task_importance_mark_live_donor(task_t task, boolean_t donating);
static void task_importance_mark_receiver(task_t task, boolean_t receiving);
static void task_importance_mark_denap_receiver(task_t task, boolean_t denap);

static boolean_t task_is_marked_live_importance_donor(task_t task);
static boolean_t task_is_importance_receiver(task_t task);
static boolean_t task_is_importance_denap_receiver(task_t task);

static int task_importance_hold_internal_assertion(task_t target_task, uint32_t count);

static void task_add_importance_watchport(task_t task, mach_port_t port, int *boostp);
static void task_importance_update_live_donor(task_t target_task);

static void task_set_boost_locked(task_t task, boolean_t boost_active);

#endif /* IMPORTANCE_INHERITANCE */

#if IMPORTANCE_TRACE
#define __imptrace_only
#else /* IMPORTANCE_TRACE */
#define __imptrace_only __unused
#endif /* !IMPORTANCE_TRACE */

#if IMPORTANCE_INHERITANCE
#define __imp_only
#else
#define __imp_only __unused
#endif

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
	.trp_bg_iotier = proc_default_bg_iotier
};
const struct task_effective_policy default_task_effective_policy = {};

/*
 * Default parameters for CPU usage monitor.
 *
 * Default setting is 50% over 3 minutes.
 */
#define         DEFAULT_CPUMON_PERCENTAGE 50
#define         DEFAULT_CPUMON_INTERVAL   (3 * 60)

uint8_t         proc_max_cpumon_percentage;
uint64_t        proc_max_cpumon_interval;


kern_return_t
qos_latency_policy_validate(task_latency_qos_t ltier)
{
	if ((ltier != LATENCY_QOS_TIER_UNSPECIFIED) &&
	    ((ltier > LATENCY_QOS_TIER_5) || (ltier < LATENCY_QOS_TIER_0))) {
		return KERN_INVALID_ARGUMENT;
	}

	return KERN_SUCCESS;
}

kern_return_t
qos_throughput_policy_validate(task_throughput_qos_t ttier)
{
	if ((ttier != THROUGHPUT_QOS_TIER_UNSPECIFIED) &&
	    ((ttier > THROUGHPUT_QOS_TIER_5) || (ttier < THROUGHPUT_QOS_TIER_0))) {
		return KERN_INVALID_ARGUMENT;
	}

	return KERN_SUCCESS;
}

static kern_return_t
task_qos_policy_validate(task_qos_policy_t qosinfo, mach_msg_type_number_t count)
{
	if (count < TASK_QOS_POLICY_COUNT) {
		return KERN_INVALID_ARGUMENT;
	}

	task_latency_qos_t ltier = qosinfo->task_latency_qos_tier;
	task_throughput_qos_t ttier = qosinfo->task_throughput_qos_tier;

	kern_return_t kr = qos_latency_policy_validate(ltier);

	if (kr != KERN_SUCCESS) {
		return kr;
	}

	kr = qos_throughput_policy_validate(ttier);

	return kr;
}

uint32_t
qos_extract(uint32_t qv)
{
	return qv & 0xFF;
}

uint32_t
qos_latency_policy_package(uint32_t qv)
{
	return (qv == LATENCY_QOS_TIER_UNSPECIFIED) ? LATENCY_QOS_TIER_UNSPECIFIED : ((0xFF << 16) | qv);
}

uint32_t
qos_throughput_policy_package(uint32_t qv)
{
	return (qv == THROUGHPUT_QOS_TIER_UNSPECIFIED) ? THROUGHPUT_QOS_TIER_UNSPECIFIED : ((0xFE << 16) | qv);
}

#define TASK_POLICY_SUPPRESSION_DISABLE  0x1
#define TASK_POLICY_SUPPRESSION_IOTIER2  0x2
#define TASK_POLICY_SUPPRESSION_NONDONOR 0x4
/* TEMPORARY boot-arg controlling task_policy suppression (App Nap) */
static boolean_t task_policy_suppression_flags = TASK_POLICY_SUPPRESSION_IOTIER2 |
    TASK_POLICY_SUPPRESSION_NONDONOR;

kern_return_t
task_policy_set(
	task_t                                  task,
	task_policy_flavor_t    flavor,
	task_policy_t                   policy_info,
	mach_msg_type_number_t  count)
{
	kern_return_t           result = KERN_SUCCESS;

	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	switch (flavor) {
	case TASK_CATEGORY_POLICY: {
		task_category_policy_t info = (task_category_policy_t)policy_info;

		if (count < TASK_CATEGORY_POLICY_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

#if CONFIG_EMBEDDED
		/* On embedded, you can't modify your own role. */
		if (current_task() == task) {
			return KERN_INVALID_ARGUMENT;
		}
#endif

		switch (info->role) {
		case TASK_FOREGROUND_APPLICATION:
		case TASK_BACKGROUND_APPLICATION:
		case TASK_DEFAULT_APPLICATION:
			proc_set_task_policy(task,
			    TASK_POLICY_ATTRIBUTE, TASK_POLICY_ROLE,
			    info->role);
			break;

		case TASK_CONTROL_APPLICATION:
			if (task != current_task() || task->sec_token.val[0] != 0) {
				result = KERN_INVALID_ARGUMENT;
			} else {
				proc_set_task_policy(task,
				    TASK_POLICY_ATTRIBUTE, TASK_POLICY_ROLE,
				    info->role);
			}
			break;

		case TASK_GRAPHICS_SERVER:
			/* TODO: Restrict this role to FCFS <rdar://problem/12552788> */
			if (task != current_task() || task->sec_token.val[0] != 0) {
				result = KERN_INVALID_ARGUMENT;
			} else {
				proc_set_task_policy(task,
				    TASK_POLICY_ATTRIBUTE, TASK_POLICY_ROLE,
				    info->role);
			}
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

		if (kr != KERN_SUCCESS) {
			return kr;
		}


		uint32_t lqos = qos_extract(qosinfo->task_latency_qos_tier);
		uint32_t tqos = qos_extract(qosinfo->task_throughput_qos_tier);

		proc_set_task_policy2(task, TASK_POLICY_ATTRIBUTE,
		    flavor == TASK_BASE_QOS_POLICY ? TASK_POLICY_BASE_LATENCY_AND_THROUGHPUT_QOS : TASK_POLICY_OVERRIDE_LATENCY_AND_THROUGHPUT_QOS,
		    lqos, tqos);
	}
	break;

	case TASK_BASE_LATENCY_QOS_POLICY:
	{
		task_qos_policy_t qosinfo = (task_qos_policy_t)policy_info;
		kern_return_t kr = task_qos_policy_validate(qosinfo, count);

		if (kr != KERN_SUCCESS) {
			return kr;
		}

		uint32_t lqos = qos_extract(qosinfo->task_latency_qos_tier);

		proc_set_task_policy(task, TASK_POLICY_ATTRIBUTE, TASK_BASE_LATENCY_QOS_POLICY, lqos);
	}
	break;

	case TASK_BASE_THROUGHPUT_QOS_POLICY:
	{
		task_qos_policy_t qosinfo = (task_qos_policy_t)policy_info;
		kern_return_t kr = task_qos_policy_validate(qosinfo, count);

		if (kr != KERN_SUCCESS) {
			return kr;
		}

		uint32_t tqos = qos_extract(qosinfo->task_throughput_qos_tier);

		proc_set_task_policy(task, TASK_POLICY_ATTRIBUTE, TASK_BASE_THROUGHPUT_QOS_POLICY, tqos);
	}
	break;

	case TASK_SUPPRESSION_POLICY:
	{
#if CONFIG_EMBEDDED
		/*
		 * Suppression policy is not enabled for embedded
		 * because apps aren't marked as denap receivers
		 */
		result = KERN_INVALID_ARGUMENT;
		break;
#else /* CONFIG_EMBEDDED */

		task_suppression_policy_t info = (task_suppression_policy_t)policy_info;

		if (count < TASK_SUPPRESSION_POLICY_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		struct task_qos_policy qosinfo;

		qosinfo.task_latency_qos_tier = info->timer_throttle;
		qosinfo.task_throughput_qos_tier = info->throughput_qos;

		kern_return_t kr = task_qos_policy_validate(&qosinfo, TASK_QOS_POLICY_COUNT);

		if (kr != KERN_SUCCESS) {
			return kr;
		}

		/* TEMPORARY disablement of task suppression */
		if (info->active &&
		    (task_policy_suppression_flags & TASK_POLICY_SUPPRESSION_DISABLE)) {
			return KERN_SUCCESS;
		}

		struct task_pend_token pend_token = {};

		task_lock(task);

		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		    (IMPORTANCE_CODE(IMP_TASK_SUPPRESSION, info->active)) | DBG_FUNC_START,
		    proc_selfpid(), task_pid(task), trequested_0(task),
		    trequested_1(task), 0);

		task->requested_policy.trp_sup_active      = (info->active)         ? 1 : 0;
		task->requested_policy.trp_sup_lowpri_cpu  = (info->lowpri_cpu)     ? 1 : 0;
		task->requested_policy.trp_sup_timer       = qos_extract(info->timer_throttle);
		task->requested_policy.trp_sup_disk        = (info->disk_throttle)  ? 1 : 0;
		task->requested_policy.trp_sup_throughput  = qos_extract(info->throughput_qos);
		task->requested_policy.trp_sup_cpu         = (info->suppressed_cpu) ? 1 : 0;
		task->requested_policy.trp_sup_bg_sockets  = (info->background_sockets) ? 1 : 0;

		task_policy_update_locked(task, &pend_token);

		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		    (IMPORTANCE_CODE(IMP_TASK_SUPPRESSION, info->active)) | DBG_FUNC_END,
		    proc_selfpid(), task_pid(task), trequested_0(task),
		    trequested_1(task), 0);

		task_unlock(task);

		task_policy_update_complete_unlocked(task, &pend_token);

		break;

#endif /* CONFIG_EMBEDDED */
	}

	default:
		result = KERN_INVALID_ARGUMENT;
		break;
	}

	return result;
}

/* Sets BSD 'nice' value on the task */
kern_return_t
task_importance(
	task_t                          task,
	integer_t                       importance)
{
	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	task_lock(task);

	if (!task->active) {
		task_unlock(task);

		return KERN_TERMINATED;
	}

	if (proc_get_effective_task_policy(task, TASK_POLICY_ROLE) >= TASK_CONTROL_APPLICATION) {
		task_unlock(task);

		return KERN_INVALID_ARGUMENT;
	}

	task->importance = importance;

	struct task_pend_token pend_token = {};

	task_policy_update_locked(task, &pend_token);

	task_unlock(task);

	task_policy_update_complete_unlocked(task, &pend_token);

	return KERN_SUCCESS;
}

kern_return_t
task_policy_get(
	task_t                                  task,
	task_policy_flavor_t    flavor,
	task_policy_t                   policy_info,
	mach_msg_type_number_t  *count,
	boolean_t                               *get_default)
{
	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	switch (flavor) {
	case TASK_CATEGORY_POLICY:
	{
		task_category_policy_t          info = (task_category_policy_t)policy_info;

		if (*count < TASK_CATEGORY_POLICY_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (*get_default) {
			info->role = TASK_UNSPECIFIED;
		} else {
			info->role = proc_get_task_policy(task, TASK_POLICY_ATTRIBUTE, TASK_POLICY_ROLE);
		}
		break;
	}

	case TASK_BASE_QOS_POLICY: /* FALLTHRU */
	case TASK_OVERRIDE_QOS_POLICY:
	{
		task_qos_policy_t info = (task_qos_policy_t)policy_info;

		if (*count < TASK_QOS_POLICY_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (*get_default) {
			info->task_latency_qos_tier = LATENCY_QOS_TIER_UNSPECIFIED;
			info->task_throughput_qos_tier = THROUGHPUT_QOS_TIER_UNSPECIFIED;
		} else if (flavor == TASK_BASE_QOS_POLICY) {
			int value1, value2;

			proc_get_task_policy2(task, TASK_POLICY_ATTRIBUTE, TASK_POLICY_BASE_LATENCY_AND_THROUGHPUT_QOS, &value1, &value2);

			info->task_latency_qos_tier = qos_latency_policy_package(value1);
			info->task_throughput_qos_tier = qos_throughput_policy_package(value2);
		} else if (flavor == TASK_OVERRIDE_QOS_POLICY) {
			int value1, value2;

			proc_get_task_policy2(task, TASK_POLICY_ATTRIBUTE, TASK_POLICY_OVERRIDE_LATENCY_AND_THROUGHPUT_QOS, &value1, &value2);

			info->task_latency_qos_tier = qos_latency_policy_package(value1);
			info->task_throughput_qos_tier = qos_throughput_policy_package(value2);
		}

		break;
	}

	case TASK_POLICY_STATE:
	{
		task_policy_state_t info = (task_policy_state_t)policy_info;

		if (*count < TASK_POLICY_STATE_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		/* Only root can get this info */
		if (current_task()->sec_token.val[0] != 0) {
			return KERN_PROTECTION_FAILURE;
		}

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

			info->requested = task_requested_bitfield(task);
			info->effective = task_effective_bitfield(task);
			info->pending   = 0;

			info->tps_requested_policy = *(uint64_t*)(&task->requested_policy);
			info->tps_effective_policy = *(uint64_t*)(&task->effective_policy);

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

		break;
	}

	case TASK_SUPPRESSION_POLICY:
	{
		task_suppression_policy_t info = (task_suppression_policy_t)policy_info;

		if (*count < TASK_SUPPRESSION_POLICY_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

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
			info->active            = task->requested_policy.trp_sup_active;
			info->lowpri_cpu        = task->requested_policy.trp_sup_lowpri_cpu;
			info->timer_throttle    = qos_latency_policy_package(task->requested_policy.trp_sup_timer);
			info->disk_throttle     = task->requested_policy.trp_sup_disk;
			info->cpu_limit         = 0;
			info->suspend           = 0;
			info->throughput_qos    = qos_throughput_policy_package(task->requested_policy.trp_sup_throughput);
			info->suppressed_cpu    = task->requested_policy.trp_sup_cpu;
			info->background_sockets = task->requested_policy.trp_sup_bg_sockets;
		}

		task_unlock(task);
		break;
	}

	default:
		return KERN_INVALID_ARGUMENT;
	}

	return KERN_SUCCESS;
}

/*
 * Called at task creation
 * We calculate the correct effective but don't apply it to anything yet.
 * The threads, etc will inherit from the task as they get created.
 */
void
task_policy_create(task_t task, task_t parent_task)
{
	task->requested_policy.trp_apptype          = parent_task->requested_policy.trp_apptype;

	task->requested_policy.trp_int_darwinbg     = parent_task->requested_policy.trp_int_darwinbg;
	task->requested_policy.trp_ext_darwinbg     = parent_task->requested_policy.trp_ext_darwinbg;
	task->requested_policy.trp_int_iotier       = parent_task->requested_policy.trp_int_iotier;
	task->requested_policy.trp_ext_iotier       = parent_task->requested_policy.trp_ext_iotier;
	task->requested_policy.trp_int_iopassive    = parent_task->requested_policy.trp_int_iopassive;
	task->requested_policy.trp_ext_iopassive    = parent_task->requested_policy.trp_ext_iopassive;
	task->requested_policy.trp_bg_iotier        = parent_task->requested_policy.trp_bg_iotier;
	task->requested_policy.trp_terminated       = parent_task->requested_policy.trp_terminated;
	task->requested_policy.trp_qos_clamp        = parent_task->requested_policy.trp_qos_clamp;

	if (task->requested_policy.trp_apptype == TASK_APPTYPE_DAEMON_ADAPTIVE && !task_is_exec_copy(task)) {
		/* Do not update the apptype for exec copy task */
		if (parent_task->requested_policy.trp_boosted) {
			task->requested_policy.trp_apptype = TASK_APPTYPE_DAEMON_INTERACTIVE;
			task_importance_mark_donor(task, TRUE);
		} else {
			task->requested_policy.trp_apptype = TASK_APPTYPE_DAEMON_BACKGROUND;
			task_importance_mark_receiver(task, FALSE);
		}
	}

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    (IMPORTANCE_CODE(IMP_UPDATE, (IMP_UPDATE_TASK_CREATE | TASK_POLICY_TASK))) | DBG_FUNC_START,
	    task_pid(task), teffective_0(task),
	    teffective_1(task), task->priority, 0);

	task_policy_update_internal_locked(task, TRUE, NULL);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    (IMPORTANCE_CODE(IMP_UPDATE, (IMP_UPDATE_TASK_CREATE | TASK_POLICY_TASK))) | DBG_FUNC_END,
	    task_pid(task), teffective_0(task),
	    teffective_1(task), task->priority, 0);

	task_importance_update_live_donor(task);
}


static void
task_policy_update_locked(task_t task, task_pend_token_t pend_token)
{
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    (IMPORTANCE_CODE(IMP_UPDATE, TASK_POLICY_TASK) | DBG_FUNC_START),
	    task_pid(task), teffective_0(task),
	    teffective_1(task), task->priority, 0);

	task_policy_update_internal_locked(task, FALSE, pend_token);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    (IMPORTANCE_CODE(IMP_UPDATE, TASK_POLICY_TASK)) | DBG_FUNC_END,
	    task_pid(task), teffective_0(task),
	    teffective_1(task), task->priority, 0);
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
task_policy_update_internal_locked(task_t task, boolean_t in_create, task_pend_token_t pend_token)
{
	/*
	 * Step 1:
	 *  Gather requested policy
	 */

	struct task_requested_policy requested = task->requested_policy;

	/*
	 * Step 2:
	 *  Calculate new effective policies from requested policy and task state
	 *  Rules:
	 *      Don't change requested, it won't take effect
	 */

	struct task_effective_policy next = {};

	/* Update task role */
	next.tep_role = requested.trp_role;

	/* Set task qos clamp and ceiling */
	next.tep_qos_clamp = requested.trp_qos_clamp;

	if (requested.trp_apptype == TASK_APPTYPE_APP_DEFAULT ||
	    requested.trp_apptype == TASK_APPTYPE_APP_TAL) {
		switch (next.tep_role) {
		case TASK_FOREGROUND_APPLICATION:
			/* Foreground apps get urgent scheduler priority */
			next.tep_qos_ui_is_urgent = 1;
			next.tep_qos_ceiling = THREAD_QOS_UNSPECIFIED;
			break;

		case TASK_BACKGROUND_APPLICATION:
			/* This is really 'non-focal but on-screen' */
			next.tep_qos_ceiling = THREAD_QOS_UNSPECIFIED;
			break;

		case TASK_DEFAULT_APPLICATION:
			/* This is 'may render UI but we don't know if it's focal/nonfocal' */
			next.tep_qos_ceiling = THREAD_QOS_UNSPECIFIED;
			break;

		case TASK_NONUI_APPLICATION:
			/* i.e. 'off-screen' */
			next.tep_qos_ceiling = THREAD_QOS_LEGACY;
			break;

		case TASK_CONTROL_APPLICATION:
		case TASK_GRAPHICS_SERVER:
			next.tep_qos_ui_is_urgent = 1;
			next.tep_qos_ceiling = THREAD_QOS_UNSPECIFIED;
			break;

		case TASK_THROTTLE_APPLICATION:
			/* i.e. 'TAL launch' */
			next.tep_qos_ceiling = THREAD_QOS_UTILITY;
			break;

		case TASK_DARWINBG_APPLICATION:
			/* i.e. 'DARWIN_BG throttled background application' */
			next.tep_qos_ceiling = THREAD_QOS_BACKGROUND;
			break;

		case TASK_UNSPECIFIED:
		default:
			/* Apps that don't have an application role get
			 * USER_INTERACTIVE and USER_INITIATED squashed to LEGACY */
			next.tep_qos_ceiling = THREAD_QOS_LEGACY;
			break;
		}
	} else {
		/* Daemons and dext get USER_INTERACTIVE squashed to USER_INITIATED */
		next.tep_qos_ceiling = THREAD_QOS_USER_INITIATED;
	}

	/* Calculate DARWIN_BG */
	boolean_t wants_darwinbg        = FALSE;
	boolean_t wants_all_sockets_bg  = FALSE; /* Do I want my existing sockets to be bg */
	boolean_t wants_watchersbg      = FALSE; /* Do I want my pidbound threads to be bg */

	/*
	 * If DARWIN_BG has been requested at either level, it's engaged.
	 * Only true DARWIN_BG changes cause watchers to transition.
	 *
	 * Backgrounding due to apptype does.
	 */
	if (requested.trp_int_darwinbg || requested.trp_ext_darwinbg ||
	    next.tep_role == TASK_DARWINBG_APPLICATION) {
		wants_watchersbg = wants_all_sockets_bg = wants_darwinbg = TRUE;
	}

	/*
	 * Deprecated TAL implementation for TAL apptype
	 * Background TAL apps are throttled when TAL is enabled
	 */
	if (requested.trp_apptype == TASK_APPTYPE_APP_TAL &&
	    requested.trp_role == TASK_BACKGROUND_APPLICATION &&
	    requested.trp_tal_enabled == 1) {
		next.tep_tal_engaged = 1;
	}

	/* New TAL implementation based on TAL role alone, works for all apps */
	if ((requested.trp_apptype == TASK_APPTYPE_APP_DEFAULT ||
	    requested.trp_apptype == TASK_APPTYPE_APP_TAL) &&
	    requested.trp_role == TASK_THROTTLE_APPLICATION) {
		next.tep_tal_engaged = 1;
	}

	/* Adaptive daemons are DARWIN_BG unless boosted, and don't get network throttled. */
	if (requested.trp_apptype == TASK_APPTYPE_DAEMON_ADAPTIVE &&
	    requested.trp_boosted == 0) {
		wants_darwinbg = TRUE;
	}

	/* Background daemons are always DARWIN_BG, no exceptions, and don't get network throttled. */
	if (requested.trp_apptype == TASK_APPTYPE_DAEMON_BACKGROUND) {
		wants_darwinbg = TRUE;
	}

	if (next.tep_qos_clamp == THREAD_QOS_BACKGROUND || next.tep_qos_clamp == THREAD_QOS_MAINTENANCE) {
		wants_darwinbg = TRUE;
	}

	/* Calculate side effects of DARWIN_BG */

	if (wants_darwinbg) {
		next.tep_darwinbg = 1;
		/* darwinbg tasks always create bg sockets, but we don't always loop over all sockets */
		next.tep_new_sockets_bg = 1;
		next.tep_lowpri_cpu = 1;
	}

	if (wants_all_sockets_bg) {
		next.tep_all_sockets_bg = 1;
	}

	if (wants_watchersbg) {
		next.tep_watchers_bg = 1;
	}

	/* Calculate low CPU priority */

	boolean_t wants_lowpri_cpu = FALSE;

	if (wants_darwinbg) {
		wants_lowpri_cpu = TRUE;
	}

	if (next.tep_tal_engaged) {
		wants_lowpri_cpu = TRUE;
	}

	if (requested.trp_sup_lowpri_cpu && requested.trp_boosted == 0) {
		wants_lowpri_cpu = TRUE;
	}

	if (wants_lowpri_cpu) {
		next.tep_lowpri_cpu = 1;
	}

	/* Calculate IO policy */

	/* Update BG IO policy (so we can see if it has changed) */
	next.tep_bg_iotier = requested.trp_bg_iotier;

	int iopol = THROTTLE_LEVEL_TIER0;

	if (wants_darwinbg) {
		iopol = MAX(iopol, requested.trp_bg_iotier);
	}

	if (requested.trp_apptype == TASK_APPTYPE_DAEMON_STANDARD) {
		iopol = MAX(iopol, proc_standard_daemon_tier);
	}

	if (requested.trp_sup_disk && requested.trp_boosted == 0) {
		iopol = MAX(iopol, proc_suppressed_disk_tier);
	}

	if (next.tep_tal_engaged) {
		iopol = MAX(iopol, proc_tal_disk_tier);
	}

	if (next.tep_qos_clamp != THREAD_QOS_UNSPECIFIED) {
		iopol = MAX(iopol, thread_qos_policy_params.qos_iotier[next.tep_qos_clamp]);
	}

	iopol = MAX(iopol, requested.trp_int_iotier);
	iopol = MAX(iopol, requested.trp_ext_iotier);

	next.tep_io_tier = iopol;

	/* Calculate Passive IO policy */

	if (requested.trp_ext_iopassive || requested.trp_int_iopassive) {
		next.tep_io_passive = 1;
	}

	/* Calculate suppression-active flag */
	boolean_t appnap_transition = FALSE;

	if (requested.trp_sup_active && requested.trp_boosted == 0) {
		next.tep_sup_active = 1;
	}

	if (task->effective_policy.tep_sup_active != next.tep_sup_active) {
		appnap_transition = TRUE;
	}

	/* Calculate timer QOS */
	int latency_qos = requested.trp_base_latency_qos;

	if (requested.trp_sup_timer && requested.trp_boosted == 0) {
		latency_qos = requested.trp_sup_timer;
	}

	if (next.tep_qos_clamp != THREAD_QOS_UNSPECIFIED) {
		latency_qos = MAX(latency_qos, (int)thread_qos_policy_params.qos_latency_qos[next.tep_qos_clamp]);
	}

	if (requested.trp_over_latency_qos != 0) {
		latency_qos = requested.trp_over_latency_qos;
	}

	/* Treat the windowserver special */
	if (requested.trp_role == TASK_GRAPHICS_SERVER) {
		latency_qos = proc_graphics_timer_qos;
	}

	next.tep_latency_qos = latency_qos;

	/* Calculate throughput QOS */
	int through_qos = requested.trp_base_through_qos;

	if (requested.trp_sup_throughput && requested.trp_boosted == 0) {
		through_qos = requested.trp_sup_throughput;
	}

	if (next.tep_qos_clamp != THREAD_QOS_UNSPECIFIED) {
		through_qos = MAX(through_qos, (int)thread_qos_policy_params.qos_through_qos[next.tep_qos_clamp]);
	}

	if (requested.trp_over_through_qos != 0) {
		through_qos = requested.trp_over_through_qos;
	}

	next.tep_through_qos = through_qos;

	/* Calculate suppressed CPU priority */
	if (requested.trp_sup_cpu && requested.trp_boosted == 0) {
		next.tep_suppressed_cpu = 1;
	}

	/*
	 * Calculate background sockets
	 * Don't take into account boosting to limit transition frequency.
	 */
	if (requested.trp_sup_bg_sockets) {
		next.tep_all_sockets_bg = 1;
		next.tep_new_sockets_bg = 1;
	}

	/* Apply SFI Managed class bit */
	next.tep_sfi_managed = requested.trp_sfi_managed;

	/* Calculate 'live donor' status for live importance */
	switch (requested.trp_apptype) {
	case TASK_APPTYPE_APP_TAL:
	case TASK_APPTYPE_APP_DEFAULT:
		if (requested.trp_ext_darwinbg == 1 ||
		    (next.tep_sup_active == 1 &&
		    (task_policy_suppression_flags & TASK_POLICY_SUPPRESSION_NONDONOR)) ||
		    next.tep_role == TASK_DARWINBG_APPLICATION) {
			next.tep_live_donor = 0;
		} else {
			next.tep_live_donor = 1;
		}
		break;

	case TASK_APPTYPE_DAEMON_INTERACTIVE:
	case TASK_APPTYPE_DAEMON_STANDARD:
	case TASK_APPTYPE_DAEMON_ADAPTIVE:
	case TASK_APPTYPE_DAEMON_BACKGROUND:
	case TASK_APPTYPE_DRIVER:
	default:
		next.tep_live_donor = 0;
		break;
	}

	if (requested.trp_terminated) {
		/*
		 * Shoot down the throttles that slow down exit or response to SIGTERM
		 * We don't need to shoot down:
		 * passive        (don't want to cause others to throttle)
		 * all_sockets_bg (don't need to iterate FDs on every exit)
		 * new_sockets_bg (doesn't matter for exiting process)
		 * pidsuspend     (jetsam-ed BG process shouldn't run again)
		 * watchers_bg    (watcher threads don't need to be unthrottled)
		 * latency_qos    (affects userspace timers only)
		 */

		next.tep_terminated     = 1;
		next.tep_darwinbg       = 0;
		next.tep_lowpri_cpu     = 0;
		next.tep_io_tier        = THROTTLE_LEVEL_TIER0;
		next.tep_tal_engaged    = 0;
		next.tep_role           = TASK_UNSPECIFIED;
		next.tep_suppressed_cpu = 0;
	}

	/*
	 * Step 3:
	 *  Swap out old policy for new policy
	 */

	struct task_effective_policy prev = task->effective_policy;

	/* This is the point where the new values become visible to other threads */
	task->effective_policy = next;

	/* Don't do anything further to a half-formed task */
	if (in_create) {
		return;
	}

	if (task == kernel_task) {
		panic("Attempting to set task policy on kernel_task");
	}

	/*
	 * Step 4:
	 *  Pend updates that can't be done while holding the task lock
	 */

	if (prev.tep_all_sockets_bg != next.tep_all_sockets_bg) {
		pend_token->tpt_update_sockets = 1;
	}

	/* Only re-scan the timer list if the qos level is getting less strong */
	if (prev.tep_latency_qos > next.tep_latency_qos) {
		pend_token->tpt_update_timers = 1;
	}

#if CONFIG_EMBEDDED
	if (prev.tep_watchers_bg != next.tep_watchers_bg) {
		pend_token->tpt_update_watchers = 1;
	}
#endif /* CONFIG_EMBEDDED */

	if (prev.tep_live_donor != next.tep_live_donor) {
		pend_token->tpt_update_live_donor = 1;
	}

	/*
	 * Step 5:
	 *  Update other subsystems as necessary if something has changed
	 */

	boolean_t update_threads = FALSE, update_sfi = FALSE;

	/*
	 * Check for the attributes that thread_policy_update_internal_locked() consults,
	 *  and trigger thread policy re-evaluation.
	 */
	if (prev.tep_io_tier != next.tep_io_tier ||
	    prev.tep_bg_iotier != next.tep_bg_iotier ||
	    prev.tep_io_passive != next.tep_io_passive ||
	    prev.tep_darwinbg != next.tep_darwinbg ||
	    prev.tep_qos_clamp != next.tep_qos_clamp ||
	    prev.tep_qos_ceiling != next.tep_qos_ceiling ||
	    prev.tep_qos_ui_is_urgent != next.tep_qos_ui_is_urgent ||
	    prev.tep_latency_qos != next.tep_latency_qos ||
	    prev.tep_through_qos != next.tep_through_qos ||
	    prev.tep_lowpri_cpu != next.tep_lowpri_cpu ||
	    prev.tep_new_sockets_bg != next.tep_new_sockets_bg ||
	    prev.tep_terminated != next.tep_terminated) {
		update_threads = TRUE;
	}

	/*
	 * Check for the attributes that sfi_thread_classify() consults,
	 *  and trigger SFI re-evaluation.
	 */
	if (prev.tep_latency_qos != next.tep_latency_qos ||
	    prev.tep_role != next.tep_role ||
	    prev.tep_sfi_managed != next.tep_sfi_managed) {
		update_sfi = TRUE;
	}

	/* Reflect task role transitions into the coalition role counters */
	if (prev.tep_role != next.tep_role) {
		if (task_policy_update_coalition_focal_tasks(task, prev.tep_role, next.tep_role, pend_token)) {
			update_sfi = TRUE;
		}
	}

	boolean_t update_priority = FALSE;

	int priority     = BASEPRI_DEFAULT;
	int max_priority = MAXPRI_USER;

	if (next.tep_lowpri_cpu) {
		priority = MAXPRI_THROTTLE;
		max_priority = MAXPRI_THROTTLE;
	} else if (next.tep_suppressed_cpu) {
		priority = MAXPRI_SUPPRESSED;
		max_priority = MAXPRI_SUPPRESSED;
	} else {
		switch (next.tep_role) {
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

		if (task->effective_policy.tep_qos_clamp != THREAD_QOS_UNSPECIFIED) {
			int qos_clamp_priority = thread_qos_policy_params.qos_pri[task->effective_policy.tep_qos_clamp];

			priority        = MIN(priority, qos_clamp_priority);
			max_priority    = MIN(max_priority, qos_clamp_priority);
		}

		if (priority > max_priority) {
			priority = max_priority;
		} else if (priority < MINPRI) {
			priority = MINPRI;
		}
	}

	assert(priority <= max_priority);

	/* avoid extra work if priority isn't changing */
	if (priority != task->priority ||
	    max_priority != task->max_priority) {
		/* update the scheduling priority for the task */
		task->max_priority  = max_priority;
		task->priority      = priority;
		update_priority     = TRUE;
	}

	/* Loop over the threads in the task:
	 * only once
	 * only if necessary
	 * with one thread mutex hold per thread
	 */
	if (update_threads || update_priority || update_sfi) {
		thread_t thread;

		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			struct task_pend_token thread_pend_token = {};

			if (update_sfi) {
				thread_pend_token.tpt_update_thread_sfi = 1;
			}

			if (update_priority || update_threads) {
				thread_policy_update_tasklocked(thread,
				    task->priority, task->max_priority,
				    &thread_pend_token);
			}

			assert(!thread_pend_token.tpt_update_sockets);

			// Slightly risky, as we still hold the task lock...
			thread_policy_update_complete_unlocked(thread, &thread_pend_token);
		}
	}

	/*
	 * Use the app-nap transitions to influence the
	 * transition of the process within the jetsam band
	 * [and optionally its live-donor status]
	 * On macOS only.
	 */
	if (appnap_transition == TRUE) {
		if (task->effective_policy.tep_sup_active == 1) {
			memorystatus_update_priority_for_appnap(((proc_t) task->bsd_info), TRUE);
		} else {
			memorystatus_update_priority_for_appnap(((proc_t) task->bsd_info), FALSE);
		}
	}
}


/*
 * Yet another layering violation. We reach out and bang on the coalition directly.
 */
static boolean_t
task_policy_update_coalition_focal_tasks(task_t            task,
    int               prev_role,
    int               next_role,
    task_pend_token_t pend_token)
{
	boolean_t sfi_transition = FALSE;
	uint32_t new_count = 0;

	/* task moving into/out-of the foreground */
	if (prev_role != TASK_FOREGROUND_APPLICATION && next_role == TASK_FOREGROUND_APPLICATION) {
		if (task_coalition_adjust_focal_count(task, 1, &new_count) && (new_count == 1)) {
			sfi_transition = TRUE;
			pend_token->tpt_update_tg_ui_flag = TRUE;
		}
	} else if (prev_role == TASK_FOREGROUND_APPLICATION && next_role != TASK_FOREGROUND_APPLICATION) {
		if (task_coalition_adjust_focal_count(task, -1, &new_count) && (new_count == 0)) {
			sfi_transition = TRUE;
			pend_token->tpt_update_tg_ui_flag = TRUE;
		}
	}

	/* task moving into/out-of background */
	if (prev_role != TASK_BACKGROUND_APPLICATION && next_role == TASK_BACKGROUND_APPLICATION) {
		if (task_coalition_adjust_nonfocal_count(task, 1, &new_count) && (new_count == 1)) {
			sfi_transition = TRUE;
		}
	} else if (prev_role == TASK_BACKGROUND_APPLICATION && next_role != TASK_BACKGROUND_APPLICATION) {
		if (task_coalition_adjust_nonfocal_count(task, -1, &new_count) && (new_count == 0)) {
			sfi_transition = TRUE;
		}
	}

	if (sfi_transition) {
		pend_token->tpt_update_coal_sfi = 1;
	}
	return sfi_transition;
}

#if CONFIG_SCHED_SFI

/* coalition object is locked */
static void
task_sfi_reevaluate_cb(coalition_t coal, void *ctx, task_t task)
{
	thread_t thread;

	/* unused for now */
	(void)coal;

	/* skip the task we're re-evaluating on behalf of: it's already updated */
	if (task == (task_t)ctx) {
		return;
	}

	task_lock(task);

	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		sfi_reevaluate(thread);
	}

	task_unlock(task);
}
#endif /* CONFIG_SCHED_SFI */

/*
 * Called with task unlocked to do things that can't be done while holding the task lock
 */
void
task_policy_update_complete_unlocked(task_t task, task_pend_token_t pend_token)
{
#ifdef MACH_BSD
	if (pend_token->tpt_update_sockets) {
		proc_apply_task_networkbg(task->bsd_info, THREAD_NULL);
	}
#endif /* MACH_BSD */

	/* The timer throttle has been removed or reduced, we need to look for expired timers and fire them */
	if (pend_token->tpt_update_timers) {
		ml_timer_evaluate();
	}

#if CONFIG_EMBEDDED
	if (pend_token->tpt_update_watchers) {
		apply_appstate_watchers(task);
	}
#endif /* CONFIG_EMBEDDED */

	if (pend_token->tpt_update_live_donor) {
		task_importance_update_live_donor(task);
	}

#if CONFIG_SCHED_SFI
	/* use the resource coalition for SFI re-evaluation */
	if (pend_token->tpt_update_coal_sfi) {
		coalition_for_each_task(task->coalition[COALITION_TYPE_RESOURCE],
		    (void *)task, task_sfi_reevaluate_cb);
	}
#endif /* CONFIG_SCHED_SFI */

}

/*
 * Initiate a task policy state transition
 *
 * Everything that modifies requested except functions that need to hold the task lock
 * should use this function
 *
 * Argument validation should be performed before reaching this point.
 *
 * TODO: Do we need to check task->active?
 */
void
proc_set_task_policy(task_t     task,
    int        category,
    int        flavor,
    int        value)
{
	struct task_pend_token pend_token = {};

	task_lock(task);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    (IMPORTANCE_CODE(flavor, (category | TASK_POLICY_TASK))) | DBG_FUNC_START,
	    task_pid(task), trequested_0(task),
	    trequested_1(task), value, 0);

	proc_set_task_policy_locked(task, category, flavor, value, 0);

	task_policy_update_locked(task, &pend_token);


	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    (IMPORTANCE_CODE(flavor, (category | TASK_POLICY_TASK))) | DBG_FUNC_END,
	    task_pid(task), trequested_0(task),
	    trequested_1(task), tpending(&pend_token), 0);

	task_unlock(task);

	task_policy_update_complete_unlocked(task, &pend_token);
}

/*
 * Variant of proc_set_task_policy() that sets two scalars in the requested policy structure.
 * Same locking rules apply.
 */
void
proc_set_task_policy2(task_t    task,
    int       category,
    int       flavor,
    int       value,
    int       value2)
{
	struct task_pend_token pend_token = {};

	task_lock(task);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    (IMPORTANCE_CODE(flavor, (category | TASK_POLICY_TASK))) | DBG_FUNC_START,
	    task_pid(task), trequested_0(task),
	    trequested_1(task), value, 0);

	proc_set_task_policy_locked(task, category, flavor, value, value2);

	task_policy_update_locked(task, &pend_token);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    (IMPORTANCE_CODE(flavor, (category | TASK_POLICY_TASK))) | DBG_FUNC_END,
	    task_pid(task), trequested_0(task),
	    trequested_1(task), tpending(&pend_token), 0);

	task_unlock(task);

	task_policy_update_complete_unlocked(task, &pend_token);
}

/*
 * Set the requested state for a specific flavor to a specific value.
 *
 *  TODO:
 *  Verify that arguments to non iopol things are 1 or 0
 */
static void
proc_set_task_policy_locked(task_t      task,
    int         category,
    int         flavor,
    int         value,
    int         value2)
{
	int tier, passive;

	struct task_requested_policy requested = task->requested_policy;

	switch (flavor) {
	/* Category: EXTERNAL and INTERNAL */

	case TASK_POLICY_DARWIN_BG:
		if (category == TASK_POLICY_EXTERNAL) {
			requested.trp_ext_darwinbg = value;
		} else {
			requested.trp_int_darwinbg = value;
		}
		break;

	case TASK_POLICY_IOPOL:
		proc_iopol_to_tier(value, &tier, &passive);
		if (category == TASK_POLICY_EXTERNAL) {
			requested.trp_ext_iotier  = tier;
			requested.trp_ext_iopassive = passive;
		} else {
			requested.trp_int_iotier  = tier;
			requested.trp_int_iopassive = passive;
		}
		break;

	case TASK_POLICY_IO:
		if (category == TASK_POLICY_EXTERNAL) {
			requested.trp_ext_iotier = value;
		} else {
			requested.trp_int_iotier = value;
		}
		break;

	case TASK_POLICY_PASSIVE_IO:
		if (category == TASK_POLICY_EXTERNAL) {
			requested.trp_ext_iopassive = value;
		} else {
			requested.trp_int_iopassive = value;
		}
		break;

	/* Category: INTERNAL */

	case TASK_POLICY_DARWIN_BG_IOPOL:
		assert(category == TASK_POLICY_INTERNAL);
		proc_iopol_to_tier(value, &tier, &passive);
		requested.trp_bg_iotier = tier;
		break;

	/* Category: ATTRIBUTE */

	case TASK_POLICY_TAL:
		assert(category == TASK_POLICY_ATTRIBUTE);
		requested.trp_tal_enabled = value;
		break;

	case TASK_POLICY_BOOST:
		assert(category == TASK_POLICY_ATTRIBUTE);
		requested.trp_boosted = value;
		break;

	case TASK_POLICY_ROLE:
		assert(category == TASK_POLICY_ATTRIBUTE);
		requested.trp_role = value;
		break;

	case TASK_POLICY_TERMINATED:
		assert(category == TASK_POLICY_ATTRIBUTE);
		requested.trp_terminated = value;
		break;

	case TASK_BASE_LATENCY_QOS_POLICY:
		assert(category == TASK_POLICY_ATTRIBUTE);
		requested.trp_base_latency_qos = value;
		break;

	case TASK_BASE_THROUGHPUT_QOS_POLICY:
		assert(category == TASK_POLICY_ATTRIBUTE);
		requested.trp_base_through_qos = value;
		break;

	case TASK_POLICY_SFI_MANAGED:
		assert(category == TASK_POLICY_ATTRIBUTE);
		requested.trp_sfi_managed = value;
		break;

	case TASK_POLICY_BASE_LATENCY_AND_THROUGHPUT_QOS:
		assert(category == TASK_POLICY_ATTRIBUTE);
		requested.trp_base_latency_qos = value;
		requested.trp_base_through_qos = value2;
		break;

	case TASK_POLICY_OVERRIDE_LATENCY_AND_THROUGHPUT_QOS:
		assert(category == TASK_POLICY_ATTRIBUTE);
		requested.trp_over_latency_qos = value;
		requested.trp_over_through_qos = value2;
		break;

	default:
		panic("unknown task policy: %d %d %d %d", category, flavor, value, value2);
		break;
	}

	task->requested_policy = requested;
}

/*
 * Gets what you set. Effective values may be different.
 */
int
proc_get_task_policy(task_t     task,
    int        category,
    int        flavor)
{
	int value = 0;

	task_lock(task);

	struct task_requested_policy requested = task->requested_policy;

	switch (flavor) {
	case TASK_POLICY_DARWIN_BG:
		if (category == TASK_POLICY_EXTERNAL) {
			value = requested.trp_ext_darwinbg;
		} else {
			value = requested.trp_int_darwinbg;
		}
		break;
	case TASK_POLICY_IOPOL:
		if (category == TASK_POLICY_EXTERNAL) {
			value = proc_tier_to_iopol(requested.trp_ext_iotier,
			    requested.trp_ext_iopassive);
		} else {
			value = proc_tier_to_iopol(requested.trp_int_iotier,
			    requested.trp_int_iopassive);
		}
		break;
	case TASK_POLICY_IO:
		if (category == TASK_POLICY_EXTERNAL) {
			value = requested.trp_ext_iotier;
		} else {
			value = requested.trp_int_iotier;
		}
		break;
	case TASK_POLICY_PASSIVE_IO:
		if (category == TASK_POLICY_EXTERNAL) {
			value = requested.trp_ext_iopassive;
		} else {
			value = requested.trp_int_iopassive;
		}
		break;
	case TASK_POLICY_DARWIN_BG_IOPOL:
		assert(category == TASK_POLICY_ATTRIBUTE);
		value = proc_tier_to_iopol(requested.trp_bg_iotier, 0);
		break;
	case TASK_POLICY_ROLE:
		assert(category == TASK_POLICY_ATTRIBUTE);
		value = requested.trp_role;
		break;
	case TASK_POLICY_SFI_MANAGED:
		assert(category == TASK_POLICY_ATTRIBUTE);
		value = requested.trp_sfi_managed;
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
proc_get_task_policy2(task_t task,
    __assert_only int category,
    int flavor,
    int *value1,
    int *value2)
{
	task_lock(task);

	struct task_requested_policy requested = task->requested_policy;

	switch (flavor) {
	case TASK_POLICY_BASE_LATENCY_AND_THROUGHPUT_QOS:
		assert(category == TASK_POLICY_ATTRIBUTE);
		*value1 = requested.trp_base_latency_qos;
		*value2 = requested.trp_base_through_qos;
		break;

	case TASK_POLICY_OVERRIDE_LATENCY_AND_THROUGHPUT_QOS:
		assert(category == TASK_POLICY_ATTRIBUTE);
		*value1 = requested.trp_over_latency_qos;
		*value2 = requested.trp_over_through_qos;
		break;

	default:
		panic("unknown policy_flavor %d", flavor);
		break;
	}

	task_unlock(task);
}

/*
 * Function for querying effective state for relevant subsystems
 * Gets what is actually in effect, for subsystems which pull policy instead of receive updates.
 *
 * ONLY the relevant subsystem should query this.
 * NEVER take a value from the 'effective' function and stuff it into a setter.
 *
 * NOTE: This accessor does not take the task lock.
 * Notifications of state updates need to be externally synchronized with state queries.
 * This routine *MUST* remain interrupt safe, as it is potentially invoked
 * within the context of a timer interrupt.  It is also called in KDP context for stackshot.
 */
int
proc_get_effective_task_policy(task_t   task,
    int      flavor)
{
	int value = 0;

	switch (flavor) {
	case TASK_POLICY_DARWIN_BG:
		/*
		 * This backs the KPI call proc_pidbackgrounded to find
		 * out if a pid is backgrounded.
		 * It is used to communicate state to the VM system, as well as
		 * prioritizing requests to the graphics system.
		 * Returns 1 for background mode, 0 for normal mode
		 */
		value = task->effective_policy.tep_darwinbg;
		break;
	case TASK_POLICY_ALL_SOCKETS_BG:
		/*
		 * do_background_socket() calls this to determine what it should do to the proc's sockets
		 * Returns 1 for background mode, 0 for normal mode
		 *
		 * This consults both thread and task so un-DBGing a thread while the task is BG
		 * doesn't get you out of the network throttle.
		 */
		value = task->effective_policy.tep_all_sockets_bg;
		break;
	case TASK_POLICY_SUP_ACTIVE:
		/*
		 * Is the task in AppNap? This is used to determine the urgency
		 * that's passed to the performance management subsystem for threads
		 * that are running at a priority <= MAXPRI_THROTTLE.
		 */
		value = task->effective_policy.tep_sup_active;
		break;
	case TASK_POLICY_LATENCY_QOS:
		/*
		 * timer arming calls into here to find out the timer coalescing level
		 * Returns a QoS tier (0-6)
		 */
		value = task->effective_policy.tep_latency_qos;
		break;
	case TASK_POLICY_THROUGH_QOS:
		/*
		 * This value is passed into the urgency callout from the scheduler
		 * to the performance management subsystem.
		 * Returns a QoS tier (0-6)
		 */
		value = task->effective_policy.tep_through_qos;
		break;
	case TASK_POLICY_ROLE:
		/*
		 * This controls various things that ask whether a process is foreground,
		 * like SFI, VM, access to GPU, etc
		 */
		value = task->effective_policy.tep_role;
		break;
	case TASK_POLICY_WATCHERS_BG:
		/*
		 * This controls whether or not a thread watching this process should be BG.
		 */
		value = task->effective_policy.tep_watchers_bg;
		break;
	case TASK_POLICY_SFI_MANAGED:
		/*
		 * This controls whether or not a process is targeted for specific control by thermald.
		 */
		value = task->effective_policy.tep_sfi_managed;
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

void
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

int
proc_tier_to_iopol(int tier, int passive)
{
	if (passive == 1) {
		switch (tier) {
		case THROTTLE_LEVEL_TIER0:
			return IOPOL_PASSIVE;
		default:
			panic("unknown passive tier %d", tier);
			return IOPOL_DEFAULT;
		}
	} else {
		switch (tier) {
		case THROTTLE_LEVEL_NONE:
		case THROTTLE_LEVEL_TIER0:
			return IOPOL_DEFAULT;
		case THROTTLE_LEVEL_TIER1:
			return IOPOL_STANDARD;
		case THROTTLE_LEVEL_TIER2:
			return IOPOL_UTILITY;
		case THROTTLE_LEVEL_TIER3:
			return IOPOL_THROTTLE;
		default:
			panic("unknown tier %d", tier);
			return IOPOL_DEFAULT;
		}
	}
}

int
proc_darwin_role_to_task_role(int darwin_role, int* task_role)
{
	integer_t role = TASK_UNSPECIFIED;

	switch (darwin_role) {
	case PRIO_DARWIN_ROLE_DEFAULT:
		role = TASK_UNSPECIFIED;
		break;
	case PRIO_DARWIN_ROLE_UI_FOCAL:
		role = TASK_FOREGROUND_APPLICATION;
		break;
	case PRIO_DARWIN_ROLE_UI:
		role = TASK_DEFAULT_APPLICATION;
		break;
	case PRIO_DARWIN_ROLE_NON_UI:
		role = TASK_NONUI_APPLICATION;
		break;
	case PRIO_DARWIN_ROLE_UI_NON_FOCAL:
		role = TASK_BACKGROUND_APPLICATION;
		break;
	case PRIO_DARWIN_ROLE_TAL_LAUNCH:
		role = TASK_THROTTLE_APPLICATION;
		break;
	case PRIO_DARWIN_ROLE_DARWIN_BG:
		role = TASK_DARWINBG_APPLICATION;
		break;
	default:
		return EINVAL;
	}

	*task_role = role;

	return 0;
}

int
proc_task_role_to_darwin_role(int task_role)
{
	switch (task_role) {
	case TASK_FOREGROUND_APPLICATION:
		return PRIO_DARWIN_ROLE_UI_FOCAL;
	case TASK_BACKGROUND_APPLICATION:
		return PRIO_DARWIN_ROLE_UI_NON_FOCAL;
	case TASK_NONUI_APPLICATION:
		return PRIO_DARWIN_ROLE_NON_UI;
	case TASK_DEFAULT_APPLICATION:
		return PRIO_DARWIN_ROLE_UI;
	case TASK_THROTTLE_APPLICATION:
		return PRIO_DARWIN_ROLE_TAL_LAUNCH;
	case TASK_DARWINBG_APPLICATION:
		return PRIO_DARWIN_ROLE_DARWIN_BG;
	case TASK_UNSPECIFIED:
	default:
		return PRIO_DARWIN_ROLE_DEFAULT;
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
proc_set_task_spawnpolicy(task_t task, thread_t thread, int apptype, int qos_clamp, int role,
    ipc_port_t * portwatch_ports, uint32_t portwatch_count)
{
	struct task_pend_token pend_token = {};

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    (IMPORTANCE_CODE(IMP_TASK_APPTYPE, apptype)) | DBG_FUNC_START,
	    task_pid(task), trequested_0(task), trequested_1(task),
	    apptype, 0);

	switch (apptype) {
	case TASK_APPTYPE_APP_TAL:
	case TASK_APPTYPE_APP_DEFAULT:
		/* Apps become donors via the 'live-donor' flag instead of the static donor flag */
		task_importance_mark_donor(task, FALSE);
		task_importance_mark_live_donor(task, TRUE);
		task_importance_mark_receiver(task, FALSE);
#if CONFIG_EMBEDDED
		task_importance_mark_denap_receiver(task, FALSE);
#else
		/* Apps are de-nap recievers on desktop for suppression behaviors */
		task_importance_mark_denap_receiver(task, TRUE);
#endif /* CONFIG_EMBEDDED */
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

	case TASK_APPTYPE_DRIVER:
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

		for (uint32_t i = 0; i < portwatch_count; i++) {
			ipc_port_t port = NULL;

			if (IP_VALID(port = portwatch_ports[i])) {
				int boost = 0;
				task_add_importance_watchport(task, port, &boost);
				portwatch_boosts += boost;
			}
		}

		if (portwatch_boosts > 0) {
			task_importance_hold_internal_assertion(task, portwatch_boosts);
		}
	}

	/* Redirect the turnstile push of watchports to task */
	if (portwatch_count && portwatch_ports != NULL) {
		task_add_turnstile_watchports(task, thread, portwatch_ports, portwatch_count);
	}

	task_lock(task);

	if (apptype == TASK_APPTYPE_APP_TAL) {
		/* TAL starts off enabled by default */
		task->requested_policy.trp_tal_enabled = 1;
	}

	if (apptype != TASK_APPTYPE_NONE) {
		task->requested_policy.trp_apptype = apptype;
	}

#if CONFIG_EMBEDDED
	/* Remove this after launchd starts setting it properly */
	if (apptype == TASK_APPTYPE_APP_DEFAULT && role == TASK_UNSPECIFIED) {
		task->requested_policy.trp_role = TASK_FOREGROUND_APPLICATION;
	} else
#endif
	if (role != TASK_UNSPECIFIED) {
		task->requested_policy.trp_role = role;
	}

	if (qos_clamp != THREAD_QOS_UNSPECIFIED) {
		task->requested_policy.trp_qos_clamp = qos_clamp;
	}

	task_policy_update_locked(task, &pend_token);

	task_unlock(task);

	/* Ensure the donor bit is updated to be in sync with the new live donor status */
	pend_token.tpt_update_live_donor = 1;

	task_policy_update_complete_unlocked(task, &pend_token);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    (IMPORTANCE_CODE(IMP_TASK_APPTYPE, apptype)) | DBG_FUNC_END,
	    task_pid(task), trequested_0(task), trequested_1(task),
	    task_is_importance_receiver(task), 0);
}

/*
 * Inherit task role across exec
 */
void
proc_inherit_task_role(task_t new_task,
    task_t old_task)
{
	int role;

	/* inherit the role from old task to new task */
	role = proc_get_task_policy(old_task, TASK_POLICY_ATTRIBUTE, TASK_POLICY_ROLE);
	proc_set_task_policy(new_task, TASK_POLICY_ATTRIBUTE, TASK_POLICY_ROLE, role);
}

extern void *initproc;

/*
 * Compute the default main thread qos for a task
 */
int
task_compute_main_thread_qos(task_t task)
{
	int primordial_qos = THREAD_QOS_UNSPECIFIED;

	int qos_clamp = task->requested_policy.trp_qos_clamp;

	switch (task->requested_policy.trp_apptype) {
	case TASK_APPTYPE_APP_TAL:
	case TASK_APPTYPE_APP_DEFAULT:
		primordial_qos = THREAD_QOS_USER_INTERACTIVE;
		break;

	case TASK_APPTYPE_DAEMON_INTERACTIVE:
	case TASK_APPTYPE_DAEMON_STANDARD:
	case TASK_APPTYPE_DAEMON_ADAPTIVE:
	case TASK_APPTYPE_DRIVER:
		primordial_qos = THREAD_QOS_LEGACY;
		break;

	case TASK_APPTYPE_DAEMON_BACKGROUND:
		primordial_qos = THREAD_QOS_BACKGROUND;
		break;
	}

	if (task->bsd_info == initproc) {
		/* PID 1 gets a special case */
		primordial_qos = MAX(primordial_qos, THREAD_QOS_USER_INITIATED);
	}

	if (qos_clamp != THREAD_QOS_UNSPECIFIED) {
		if (primordial_qos != THREAD_QOS_UNSPECIFIED) {
			primordial_qos = MIN(qos_clamp, primordial_qos);
		} else {
			primordial_qos = qos_clamp;
		}
	}

	return primordial_qos;
}


/* for process_policy to check before attempting to set */
boolean_t
proc_task_is_tal(task_t task)
{
	return (task->requested_policy.trp_apptype == TASK_APPTYPE_APP_TAL) ? TRUE : FALSE;
}

int
task_get_apptype(task_t task)
{
	return task->requested_policy.trp_apptype;
}

boolean_t
task_is_daemon(task_t task)
{
	switch (task->requested_policy.trp_apptype) {
	case TASK_APPTYPE_DAEMON_INTERACTIVE:
	case TASK_APPTYPE_DAEMON_STANDARD:
	case TASK_APPTYPE_DAEMON_ADAPTIVE:
	case TASK_APPTYPE_DAEMON_BACKGROUND:
		return TRUE;
	default:
		return FALSE;
	}
}

bool
task_is_driver(task_t task)
{
	if (!task) {
		return FALSE;
	}
	return task->requested_policy.trp_apptype == TASK_APPTYPE_DRIVER;
}

boolean_t
task_is_app(task_t task)
{
	switch (task->requested_policy.trp_apptype) {
	case TASK_APPTYPE_APP_DEFAULT:
	case TASK_APPTYPE_APP_TAL:
		return TRUE;
	default:
		return FALSE;
	}
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
	if (task->requested_policy.trp_ext_darwinbg) {
		*flagsp |= PROC_FLAG_EXT_DARWINBG;
	}

	if (task->requested_policy.trp_int_darwinbg) {
		*flagsp |= PROC_FLAG_DARWINBG;
	}

#if CONFIG_EMBEDDED
	if (task->requested_policy.trp_apptype == TASK_APPTYPE_DAEMON_BACKGROUND) {
		*flagsp |= PROC_FLAG_IOS_APPLEDAEMON;
	}

	if (task->requested_policy.trp_apptype == TASK_APPTYPE_DAEMON_ADAPTIVE) {
		*flagsp |= PROC_FLAG_IOS_IMPPROMOTION;
	}
#endif /* CONFIG_EMBEDDED */

	if (task->requested_policy.trp_apptype == TASK_APPTYPE_APP_DEFAULT ||
	    task->requested_policy.trp_apptype == TASK_APPTYPE_APP_TAL) {
		*flagsp |= PROC_FLAG_APPLICATION;
	}

	if (task->requested_policy.trp_apptype == TASK_APPTYPE_DAEMON_ADAPTIVE) {
		*flagsp |= PROC_FLAG_ADAPTIVE;
	}

	if (task->requested_policy.trp_apptype == TASK_APPTYPE_DAEMON_ADAPTIVE &&
	    task->requested_policy.trp_boosted == 1) {
		*flagsp |= PROC_FLAG_ADAPTIVE_IMPORTANT;
	}

	if (task_is_importance_donor(task)) {
		*flagsp |= PROC_FLAG_IMPORTANCE_DONOR;
	}

	if (task->effective_policy.tep_sup_active) {
		*flagsp |= PROC_FLAG_SUPPRESSED;
	}

	return 0;
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
trequested_0(task_t task)
{
	static_assert(sizeof(struct task_requested_policy) == sizeof(uint64_t), "size invariant violated");

	uintptr_t* raw = (uintptr_t*)&task->requested_policy;

	return raw[0];
}

static uintptr_t
trequested_1(task_t task)
{
#if defined __LP64__
	(void)task;
	return 0;
#else
	uintptr_t* raw = (uintptr_t*)(&task->requested_policy);
	return raw[1];
#endif
}

static uintptr_t
teffective_0(task_t task)
{
	uintptr_t* raw = (uintptr_t*)&task->effective_policy;

	return raw[0];
}

static uintptr_t
teffective_1(task_t task)
{
#if defined __LP64__
	(void)task;
	return 0;
#else
	uintptr_t* raw = (uintptr_t*)(&task->effective_policy);
	return raw[1];
#endif
}

/* dump pending for tracepoint */
uint32_t
tpending(task_pend_token_t pend_token)
{
	return *(uint32_t*)(void*)(pend_token);
}

uint64_t
task_requested_bitfield(task_t task)
{
	uint64_t bits = 0;
	struct task_requested_policy requested = task->requested_policy;

	bits |= (requested.trp_int_darwinbg     ? POLICY_REQ_INT_DARWIN_BG  : 0);
	bits |= (requested.trp_ext_darwinbg     ? POLICY_REQ_EXT_DARWIN_BG  : 0);
	bits |= (requested.trp_int_iotier       ? (((uint64_t)requested.trp_int_iotier) << POLICY_REQ_INT_IO_TIER_SHIFT) : 0);
	bits |= (requested.trp_ext_iotier       ? (((uint64_t)requested.trp_ext_iotier) << POLICY_REQ_EXT_IO_TIER_SHIFT) : 0);
	bits |= (requested.trp_int_iopassive    ? POLICY_REQ_INT_PASSIVE_IO : 0);
	bits |= (requested.trp_ext_iopassive    ? POLICY_REQ_EXT_PASSIVE_IO : 0);
	bits |= (requested.trp_bg_iotier        ? (((uint64_t)requested.trp_bg_iotier) << POLICY_REQ_BG_IOTIER_SHIFT)   : 0);
	bits |= (requested.trp_terminated       ? POLICY_REQ_TERMINATED     : 0);

	bits |= (requested.trp_boosted          ? POLICY_REQ_BOOSTED        : 0);
	bits |= (requested.trp_tal_enabled      ? POLICY_REQ_TAL_ENABLED    : 0);
	bits |= (requested.trp_apptype          ? (((uint64_t)requested.trp_apptype) << POLICY_REQ_APPTYPE_SHIFT)  : 0);
	bits |= (requested.trp_role             ? (((uint64_t)requested.trp_role) << POLICY_REQ_ROLE_SHIFT)     : 0);

	bits |= (requested.trp_sup_active       ? POLICY_REQ_SUP_ACTIVE         : 0);
	bits |= (requested.trp_sup_lowpri_cpu   ? POLICY_REQ_SUP_LOWPRI_CPU     : 0);
	bits |= (requested.trp_sup_cpu          ? POLICY_REQ_SUP_CPU            : 0);
	bits |= (requested.trp_sup_timer        ? (((uint64_t)requested.trp_sup_timer) << POLICY_REQ_SUP_TIMER_THROTTLE_SHIFT) : 0);
	bits |= (requested.trp_sup_throughput   ? (((uint64_t)requested.trp_sup_throughput) << POLICY_REQ_SUP_THROUGHPUT_SHIFT)     : 0);
	bits |= (requested.trp_sup_disk         ? POLICY_REQ_SUP_DISK_THROTTLE  : 0);
	bits |= (requested.trp_sup_bg_sockets   ? POLICY_REQ_SUP_BG_SOCKETS     : 0);

	bits |= (requested.trp_base_latency_qos ? (((uint64_t)requested.trp_base_latency_qos) << POLICY_REQ_BASE_LATENCY_QOS_SHIFT) : 0);
	bits |= (requested.trp_over_latency_qos ? (((uint64_t)requested.trp_over_latency_qos) << POLICY_REQ_OVER_LATENCY_QOS_SHIFT) : 0);
	bits |= (requested.trp_base_through_qos ? (((uint64_t)requested.trp_base_through_qos) << POLICY_REQ_BASE_THROUGH_QOS_SHIFT) : 0);
	bits |= (requested.trp_over_through_qos ? (((uint64_t)requested.trp_over_through_qos) << POLICY_REQ_OVER_THROUGH_QOS_SHIFT) : 0);
	bits |= (requested.trp_sfi_managed      ? POLICY_REQ_SFI_MANAGED        : 0);
	bits |= (requested.trp_qos_clamp        ? (((uint64_t)requested.trp_qos_clamp) << POLICY_REQ_QOS_CLAMP_SHIFT)        : 0);

	return bits;
}

uint64_t
task_effective_bitfield(task_t task)
{
	uint64_t bits = 0;
	struct task_effective_policy effective = task->effective_policy;

	bits |= (effective.tep_io_tier          ? (((uint64_t)effective.tep_io_tier) << POLICY_EFF_IO_TIER_SHIFT) : 0);
	bits |= (effective.tep_io_passive       ? POLICY_EFF_IO_PASSIVE     : 0);
	bits |= (effective.tep_darwinbg         ? POLICY_EFF_DARWIN_BG      : 0);
	bits |= (effective.tep_lowpri_cpu       ? POLICY_EFF_LOWPRI_CPU     : 0);
	bits |= (effective.tep_terminated       ? POLICY_EFF_TERMINATED     : 0);
	bits |= (effective.tep_all_sockets_bg   ? POLICY_EFF_ALL_SOCKETS_BG : 0);
	bits |= (effective.tep_new_sockets_bg   ? POLICY_EFF_NEW_SOCKETS_BG : 0);
	bits |= (effective.tep_bg_iotier        ? (((uint64_t)effective.tep_bg_iotier) << POLICY_EFF_BG_IOTIER_SHIFT) : 0);
	bits |= (effective.tep_qos_ui_is_urgent ? POLICY_EFF_QOS_UI_IS_URGENT : 0);

	bits |= (effective.tep_tal_engaged      ? POLICY_EFF_TAL_ENGAGED    : 0);
	bits |= (effective.tep_watchers_bg      ? POLICY_EFF_WATCHERS_BG    : 0);
	bits |= (effective.tep_sup_active       ? POLICY_EFF_SUP_ACTIVE     : 0);
	bits |= (effective.tep_suppressed_cpu   ? POLICY_EFF_SUP_CPU        : 0);
	bits |= (effective.tep_role             ? (((uint64_t)effective.tep_role) << POLICY_EFF_ROLE_SHIFT)        : 0);
	bits |= (effective.tep_latency_qos      ? (((uint64_t)effective.tep_latency_qos) << POLICY_EFF_LATENCY_QOS_SHIFT) : 0);
	bits |= (effective.tep_through_qos      ? (((uint64_t)effective.tep_through_qos) << POLICY_EFF_THROUGH_QOS_SHIFT) : 0);
	bits |= (effective.tep_sfi_managed      ? POLICY_EFF_SFI_MANAGED    : 0);
	bits |= (effective.tep_qos_ceiling      ? (((uint64_t)effective.tep_qos_ceiling) << POLICY_EFF_QOS_CEILING_SHIFT) : 0);

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

	return error;
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
	/*
	 * The max CPU percentage can be configured via the boot-args and
	 * a key in the device tree. The boot-args are honored first, then the
	 * device tree.
	 */
	if (!PE_parse_boot_argn("max_cpumon_percentage", &proc_max_cpumon_percentage,
	    sizeof(proc_max_cpumon_percentage))) {
		uint64_t max_percentage = 0ULL;

		if (!PE_get_default("kern.max_cpumon_percentage", &max_percentage,
		    sizeof(max_percentage))) {
			max_percentage = DEFAULT_CPUMON_PERCENTAGE;
		}

		assert(max_percentage <= UINT8_MAX);
		proc_max_cpumon_percentage = (uint8_t) max_percentage;
	}

	if (proc_max_cpumon_percentage > 100) {
		proc_max_cpumon_percentage = 100;
	}

	/*
	 * The interval should be specified in seconds.
	 *
	 * Like the max CPU percentage, the max CPU interval can be configured
	 * via boot-args and the device tree.
	 */
	if (!PE_parse_boot_argn("max_cpumon_interval", &proc_max_cpumon_interval,
	    sizeof(proc_max_cpumon_interval))) {
		if (!PE_get_default("kern.max_cpumon_interval", &proc_max_cpumon_interval,
		    sizeof(proc_max_cpumon_interval))) {
			proc_max_cpumon_interval = DEFAULT_CPUMON_INTERVAL;
		}
	}

	proc_max_cpumon_interval *= NSEC_PER_SEC;

	/* TEMPORARY boot arg to control App suppression */
	PE_parse_boot_argn("task_policy_suppression_flags",
	    &task_policy_suppression_flags,
	    sizeof(task_policy_suppression_flags));

	/* adjust suppression disk policy if called for in boot arg */
	if (task_policy_suppression_flags & TASK_POLICY_SUPPRESSION_IOTIER2) {
		proc_suppressed_disk_tier = THROTTLE_LEVEL_TIER2;
	}
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
		if (deadline != 0) {
			return ENOTSUP;
		}
		scope = TASK_RUSECPU_FLAGS_PROC_LIMIT;
		break;
	case TASK_POLICY_RESOURCE_ATTRIBUTE_SUSPEND:
	case TASK_POLICY_RESOURCE_ATTRIBUTE_TERMINATE:
	case TASK_POLICY_RESOURCE_ATTRIBUTE_NOTIFY_KQ:
		if (percentage != 0) {
			return ENOTSUP;
		}
		scope = TASK_RUSECPU_FLAGS_DEADLINE;
		break;
	case TASK_POLICY_RESOURCE_ATTRIBUTE_NOTIFY_EXC:
		if (deadline != 0) {
			return ENOTSUP;
		}
		scope = TASK_RUSECPU_FLAGS_PERTHR_LIMIT;
#ifdef CONFIG_NOMONITORS
		return error;
#endif /* CONFIG_NOMONITORS */
		break;
	default:
		return EINVAL;
	}

	task_lock(task);
	if (task != current_task()) {
		task->policy_ru_cpu_ext = policy;
	} else {
		task->policy_ru_cpu = policy;
	}
	error = task_set_cpuusage(task, percentage, interval, deadline, scope, cpumon_entitled);
	task_unlock(task);
	return error;
}

/* TODO: get rid of these */
#define TASK_POLICY_CPU_RESOURCE_USAGE          0
#define TASK_POLICY_WIREDMEM_RESOURCE_USAGE     1
#define TASK_POLICY_VIRTUALMEM_RESOURCE_USAGE   2
#define TASK_POLICY_DISK_RESOURCE_USAGE         3
#define TASK_POLICY_NETWORK_RESOURCE_USAGE      4
#define TASK_POLICY_POWER_RESOURCE_USAGE        5

#define TASK_POLICY_RESOURCE_USAGE_COUNT        6

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
	if (error != 0) {
		goto out;
	}

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
	return error;
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
		return 0;

	default:
		return 1;
	}
	;

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
	} else {
		task_unlock(task);
	}

	return 0;
}

/*
 * XXX This API is somewhat broken; we support multiple simultaneous CPU limits, but the get/set API
 * only allows for one at a time. This means that if there is a per-thread limit active, the other
 * "scopes" will not be accessible via this API. We could change it to pass in the scope of interest
 * to the caller, and prefer that, but there's no need for that at the moment.
 */
static int
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

	return 0;
}

/*
 * Suspend the CPU usage monitor for the task.  Return value indicates
 * if the mechanism was actually enabled.
 */
int
task_suspend_cpumon(task_t task)
{
	thread_t thread;

	task_lock_assert_owned(task);

	if ((task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_PERTHR_LIMIT) == 0) {
		return KERN_INVALID_ARGUMENT;
	}

#if CONFIG_TELEMETRY
	/*
	 * Disable task-wide telemetry if it was ever enabled by the CPU usage
	 * monitor's warning zone.
	 */
	telemetry_task_ctl_locked(task, TF_CPUMON_WARNING, 0);
#endif

	/*
	 * Suspend monitoring for the task, and propagate that change to each thread.
	 */
	task->rusage_cpu_flags &= ~(TASK_RUSECPU_FLAGS_PERTHR_LIMIT | TASK_RUSECPU_FLAGS_FATAL_CPUMON);
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		act_set_astledger(thread);
	}

	return KERN_SUCCESS;
}

/*
 * Remove all traces of the CPU monitor.
 */
int
task_disable_cpumon(task_t task)
{
	int kret;

	task_lock_assert_owned(task);

	kret = task_suspend_cpumon(task);
	if (kret) {
		return kret;
	}

	/* Once we clear these values, the monitor can't be resumed */
	task->rusage_cpu_perthr_percentage = 0;
	task->rusage_cpu_perthr_interval = 0;

	return KERN_SUCCESS;
}


static int
task_enable_cpumon_locked(task_t task)
{
	thread_t thread;
	task_lock_assert_owned(task);

	if (task->rusage_cpu_perthr_percentage == 0 ||
	    task->rusage_cpu_perthr_interval == 0) {
		return KERN_INVALID_ARGUMENT;
	}

	task->rusage_cpu_flags |= TASK_RUSECPU_FLAGS_PERTHR_LIMIT;
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		act_set_astledger(thread);
	}

	return KERN_SUCCESS;
}

int
task_resume_cpumon(task_t task)
{
	kern_return_t kret;

	if (!task) {
		return EINVAL;
	}

	task_lock(task);
	kret = task_enable_cpumon_locked(task);
	task_unlock(task);

	return kret;
}


/* duplicate values from bsd/sys/process_policy.h */
#define PROC_POLICY_CPUMON_DISABLE      0xFF
#define PROC_POLICY_CPUMON_DEFAULTS     0xFE

static int
task_set_cpuusage(task_t task, uint8_t percentage, uint64_t interval, uint64_t deadline, int scope, int cpumon_entitled)
{
	uint64_t abstime = 0;
	uint64_t limittime = 0;

	lck_mtx_assert(&task->lock, LCK_MTX_ASSERT_OWNED);

	/* By default, refill once per second */
	if (interval == 0) {
		interval = NSEC_PER_SEC;
	}

	if (percentage != 0) {
		if (scope == TASK_RUSECPU_FLAGS_PERTHR_LIMIT) {
			boolean_t warn = FALSE;

			/*
			 * A per-thread CPU limit on a task generates an exception
			 * (LEDGER_ACTION_EXCEPTION) if any one thread in the task
			 * exceeds the limit.
			 */

			if (percentage == PROC_POLICY_CPUMON_DISABLE) {
				if (cpumon_entitled) {
					/* 25095698 - task_disable_cpumon() should be reliable */
					task_disable_cpumon(task);
					return 0;
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
				percentage = PROC_POLICY_CPUMON_DEFAULTS;
			}

			if (percentage == PROC_POLICY_CPUMON_DEFAULTS) {
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
				int       pid = 0;
				const char *procname = "unknown";

#ifdef MACH_BSD
				pid = proc_selfpid();
				if (current_task()->bsd_info != NULL) {
					procname = proc_name_address(current_task()->bsd_info);
				}
#endif

				printf("process %s[%d] denied attempt to escape CPU monitor"
				    " (missing required entitlement).\n", procname, pid);
			}

			/* configure the limit values */
			task->rusage_cpu_perthr_percentage = percentage;
			task->rusage_cpu_perthr_interval = interval;

			/* and enable the CPU monitor */
			(void)task_enable_cpumon_locked(task);
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

	return 0;
}

int
task_clear_cpuusage(task_t task, int cpumon_entitled)
{
	int retval = 0;

	task_lock(task);
	retval = task_clear_cpuusage_locked(task, cpumon_entitled);
	task_unlock(task);

	return retval;
}

static int
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
	return 0;
}

/* called by ledger unit to enforce action due to resource usage criteria being met */
static void
task_action_cpuusage(thread_call_param_t param0, __unused thread_call_param_t param1)
{
	task_t task = (task_t)param0;
	(void)task_apply_resource_actions(task, TASK_POLICY_CPU_RESOURCE_USAGE);
	return;
}


/*
 * Routines for taskwatch and pidbind
 */

#if CONFIG_EMBEDDED

lck_mtx_t       task_watch_mtx;

void
task_watch_init(void)
{
	lck_mtx_init(&task_watch_mtx, &task_lck_grp, &task_lck_attr);
}

static void
task_watch_lock(void)
{
	lck_mtx_lock(&task_watch_mtx);
}

static void
task_watch_unlock(void)
{
	lck_mtx_unlock(&task_watch_mtx);
}

static void
add_taskwatch_locked(task_t task, task_watch_t * twp)
{
	queue_enter(&task->task_watchers, twp, task_watch_t *, tw_links);
	task->num_taskwatchers++;
}

static void
remove_taskwatch_locked(task_t task, task_watch_t * twp)
{
	queue_remove(&task->task_watchers, twp, task_watch_t *, tw_links);
	task->num_taskwatchers--;
}


int
proc_lf_pidbind(task_t curtask, uint64_t tid, task_t target_task, int bind)
{
	thread_t target_thread = NULL;
	int ret = 0, setbg = 0;
	task_watch_t *twp = NULL;
	task_t task = TASK_NULL;

	target_thread = task_findtid(curtask, tid);
	if (target_thread == NULL) {
		return ESRCH;
	}
	/* holds thread reference */

	if (bind != 0) {
		/* task is still active ? */
		task_lock(target_task);
		if (target_task->active == 0) {
			task_unlock(target_task);
			ret = ESRCH;
			goto out;
		}
		task_unlock(target_task);

		twp = (task_watch_t *)kalloc(sizeof(task_watch_t));
		if (twp == NULL) {
			task_watch_unlock();
			ret = ENOMEM;
			goto out;
		}

		bzero(twp, sizeof(task_watch_t));

		task_watch_lock();

		if (target_thread->taskwatch != NULL) {
			/* already bound to another task */
			task_watch_unlock();

			kfree(twp, sizeof(task_watch_t));
			ret = EBUSY;
			goto out;
		}

		task_reference(target_task);

		setbg = proc_get_effective_task_policy(target_task, TASK_POLICY_WATCHERS_BG);

		twp->tw_task = target_task;             /* holds the task reference */
		twp->tw_thread = target_thread;         /* holds the thread reference */
		twp->tw_state = setbg;
		twp->tw_importance = target_thread->importance;

		add_taskwatch_locked(target_task, twp);

		target_thread->taskwatch = twp;

		task_watch_unlock();

		if (setbg) {
			set_thread_appbg(target_thread, setbg, INT_MIN);
		}

		/* retain the thread reference as it is in twp */
		target_thread = NULL;
	} else {
		/* unbind */
		task_watch_lock();
		if ((twp = target_thread->taskwatch) != NULL) {
			task = twp->tw_task;
			target_thread->taskwatch = NULL;
			remove_taskwatch_locked(task, twp);

			task_watch_unlock();

			task_deallocate(task);                  /* drop task ref in twp */
			set_thread_appbg(target_thread, 0, twp->tw_importance);
			thread_deallocate(target_thread);       /* drop thread ref in twp */
			kfree(twp, sizeof(task_watch_t));
		} else {
			task_watch_unlock();
			ret = 0;                /* return success if it not alredy bound */
			goto out;
		}
	}
out:
	thread_deallocate(target_thread);       /* drop thread ref acquired in this routine */
	return ret;
}

static void
set_thread_appbg(thread_t thread, int setbg, __unused int importance)
{
	int enable = (setbg ? TASK_POLICY_ENABLE : TASK_POLICY_DISABLE);

	proc_set_thread_policy(thread, TASK_POLICY_ATTRIBUTE, TASK_POLICY_PIDBIND_BG, enable);
}

static void
apply_appstate_watchers(task_t task)
{
	int numwatchers = 0, i, j, setbg;
	thread_watchlist_t * threadlist;
	task_watch_t * twp;

retry:
	/* if no watchers on the list return */
	if ((numwatchers = task->num_taskwatchers) == 0) {
		return;
	}

	threadlist = (thread_watchlist_t *)kalloc(numwatchers * sizeof(thread_watchlist_t));
	if (threadlist == NULL) {
		return;
	}

	bzero(threadlist, numwatchers * sizeof(thread_watchlist_t));

	task_watch_lock();
	/*serialize application of app state changes */

	if (task->watchapplying != 0) {
		lck_mtx_sleep(&task_watch_mtx, LCK_SLEEP_DEFAULT, &task->watchapplying, THREAD_UNINT);
		task_watch_unlock();
		kfree(threadlist, numwatchers * sizeof(thread_watchlist_t));
		goto retry;
	}

	if (numwatchers != task->num_taskwatchers) {
		task_watch_unlock();
		kfree(threadlist, numwatchers * sizeof(thread_watchlist_t));
		goto retry;
	}

	setbg = proc_get_effective_task_policy(task, TASK_POLICY_WATCHERS_BG);

	task->watchapplying = 1;
	i = 0;
	queue_iterate(&task->task_watchers, twp, task_watch_t *, tw_links) {
		threadlist[i].thread = twp->tw_thread;
		thread_reference(threadlist[i].thread);
		if (setbg != 0) {
			twp->tw_importance = twp->tw_thread->importance;
			threadlist[i].importance = INT_MIN;
		} else {
			threadlist[i].importance = twp->tw_importance;
		}
		i++;
		if (i > numwatchers) {
			break;
		}
	}

	task_watch_unlock();

	for (j = 0; j < i; j++) {
		set_thread_appbg(threadlist[j].thread, setbg, threadlist[j].importance);
		thread_deallocate(threadlist[j].thread);
	}
	kfree(threadlist, numwatchers * sizeof(thread_watchlist_t));


	task_watch_lock();
	task->watchapplying = 0;
	thread_wakeup_one(&task->watchapplying);
	task_watch_unlock();
}

void
thead_remove_taskwatch(thread_t thread)
{
	task_watch_t * twp;
	int importance = 0;

	task_watch_lock();
	if ((twp = thread->taskwatch) != NULL) {
		thread->taskwatch = NULL;
		remove_taskwatch_locked(twp->tw_task, twp);
	}
	task_watch_unlock();
	if (twp != NULL) {
		thread_deallocate(twp->tw_thread);
		task_deallocate(twp->tw_task);
		importance = twp->tw_importance;
		kfree(twp, sizeof(task_watch_t));
		/* remove the thread and networkbg */
		set_thread_appbg(thread, 0, importance);
	}
}

void
task_removewatchers(task_t task)
{
	int numwatchers = 0, i, j;
	task_watch_t ** twplist = NULL;
	task_watch_t * twp = NULL;

retry:
	if ((numwatchers = task->num_taskwatchers) == 0) {
		return;
	}

	twplist = (task_watch_t **)kalloc(numwatchers * sizeof(task_watch_t *));
	if (twplist == NULL) {
		return;
	}

	bzero(twplist, numwatchers * sizeof(task_watch_t *));

	task_watch_lock();
	if (task->num_taskwatchers == 0) {
		task_watch_unlock();
		goto out;
	}

	if (numwatchers != task->num_taskwatchers) {
		task_watch_unlock();
		kfree(twplist, numwatchers * sizeof(task_watch_t *));
		numwatchers = 0;
		goto retry;
	}

	i = 0;
	while ((twp = (task_watch_t *)dequeue_head(&task->task_watchers)) != NULL) {
		twplist[i] = twp;
		task->num_taskwatchers--;

		/*
		 * Since the linkage is removed and thead state cleanup is already set up,
		 * remove the refernce from the thread.
		 */
		twp->tw_thread->taskwatch = NULL;       /* removed linkage, clear thread holding ref */
		i++;
		if ((task->num_taskwatchers == 0) || (i > numwatchers)) {
			break;
		}
	}

	task_watch_unlock();

	for (j = 0; j < i; j++) {
		twp = twplist[j];
		/* remove thread and network bg */
		set_thread_appbg(twp->tw_thread, 0, twp->tw_importance);
		thread_deallocate(twp->tw_thread);
		task_deallocate(twp->tw_task);
		kfree(twp, sizeof(task_watch_t));
	}

out:
	kfree(twplist, numwatchers * sizeof(task_watch_t *));
}
#endif /* CONFIG_EMBEDDED */

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

void
task_importance_init_from_parent(__imp_only task_t new_task, __imp_only task_t parent_task)
{
#if IMPORTANCE_INHERITANCE
	ipc_importance_task_t new_task_imp = IIT_NULL;

	new_task->task_imp_base = NULL;
	if (!parent_task) {
		return;
	}

	if (task_is_marked_importance_donor(parent_task)) {
		new_task_imp = ipc_importance_for_task(new_task, FALSE);
		assert(IIT_NULL != new_task_imp);
		ipc_importance_task_mark_donor(new_task_imp, TRUE);
	}
	if (task_is_marked_live_importance_donor(parent_task)) {
		if (IIT_NULL == new_task_imp) {
			new_task_imp = ipc_importance_for_task(new_task, FALSE);
		}
		assert(IIT_NULL != new_task_imp);
		ipc_importance_task_mark_live_donor(new_task_imp, TRUE);
	}
	/* Do not inherit 'receiver' on fork, vfexec or true spawn */
	if (task_is_exec_copy(new_task) &&
	    task_is_marked_importance_receiver(parent_task)) {
		if (IIT_NULL == new_task_imp) {
			new_task_imp = ipc_importance_for_task(new_task, FALSE);
		}
		assert(IIT_NULL != new_task_imp);
		ipc_importance_task_mark_receiver(new_task_imp, TRUE);
	}
	if (task_is_marked_importance_denap_receiver(parent_task)) {
		if (IIT_NULL == new_task_imp) {
			new_task_imp = ipc_importance_for_task(new_task, FALSE);
		}
		assert(IIT_NULL != new_task_imp);
		ipc_importance_task_mark_denap_receiver(new_task_imp, TRUE);
	}
	if (IIT_NULL != new_task_imp) {
		assert(new_task->task_imp_base == new_task_imp);
		ipc_importance_task_release(new_task_imp);
	}
#endif /* IMPORTANCE_INHERITANCE */
}

#if IMPORTANCE_INHERITANCE
/*
 * Sets the task boost bit to the provided value.  Does NOT run the update function.
 *
 * Task lock must be held.
 */
static void
task_set_boost_locked(task_t task, boolean_t boost_active)
{
#if IMPORTANCE_TRACE
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_BOOST, (boost_active ? IMP_BOOSTED : IMP_UNBOOSTED)) | DBG_FUNC_START),
	    proc_selfpid(), task_pid(task), trequested_0(task), trequested_1(task), 0);
#endif /* IMPORTANCE_TRACE */

	task->requested_policy.trp_boosted = boost_active;

#if IMPORTANCE_TRACE
	if (boost_active == TRUE) {
		DTRACE_BOOST2(boost, task_t, task, int, task_pid(task));
	} else {
		DTRACE_BOOST2(unboost, task_t, task, int, task_pid(task));
	}
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_BOOST, (boost_active ? IMP_BOOSTED : IMP_UNBOOSTED)) | DBG_FUNC_END),
	    proc_selfpid(), task_pid(task),
	    trequested_0(task), trequested_1(task), 0);
#endif /* IMPORTANCE_TRACE */
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

	task_policy_update_locked(task, pend_token);
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
	if (task->task_imp_base == IIT_NULL) {
		return FALSE;
	}
	return ipc_importance_task_is_donor(task->task_imp_base);
}

/*
 * Query the status of the task's donor mark.
 */
boolean_t
task_is_marked_importance_donor(task_t task)
{
	if (task->task_imp_base == IIT_NULL) {
		return FALSE;
	}
	return ipc_importance_task_is_marked_donor(task->task_imp_base);
}

/*
 * Query the status of the task's live donor and donor mark.
 */
boolean_t
task_is_marked_live_importance_donor(task_t task)
{
	if (task->task_imp_base == IIT_NULL) {
		return FALSE;
	}
	return ipc_importance_task_is_marked_live_donor(task->task_imp_base);
}


/*
 * This routine may be called without holding task lock
 * since the value of imp_receiver can never be unset.
 */
boolean_t
task_is_importance_receiver(task_t task)
{
	if (task->task_imp_base == IIT_NULL) {
		return FALSE;
	}
	return ipc_importance_task_is_marked_receiver(task->task_imp_base);
}

/*
 * Query the task's receiver mark.
 */
boolean_t
task_is_marked_importance_receiver(task_t task)
{
	if (task->task_imp_base == IIT_NULL) {
		return FALSE;
	}
	return ipc_importance_task_is_marked_receiver(task->task_imp_base);
}

/*
 * This routine may be called without holding task lock
 * since the value of de-nap receiver can never be unset.
 */
boolean_t
task_is_importance_denap_receiver(task_t task)
{
	if (task->task_imp_base == IIT_NULL) {
		return FALSE;
	}
	return ipc_importance_task_is_denap_receiver(task->task_imp_base);
}

/*
 * Query the task's de-nap receiver mark.
 */
boolean_t
task_is_marked_importance_denap_receiver(task_t task)
{
	if (task->task_imp_base == IIT_NULL) {
		return FALSE;
	}
	return ipc_importance_task_is_marked_denap_receiver(task->task_imp_base);
}

/*
 * This routine may be called without holding task lock
 * since the value of imp_receiver can never be unset.
 */
boolean_t
task_is_importance_receiver_type(task_t task)
{
	if (task->task_imp_base == IIT_NULL) {
		return FALSE;
	}
	return task_is_importance_receiver(task) ||
	       task_is_importance_denap_receiver(task);
}

/*
 * External importance assertions are managed by the process in userspace
 * Internal importance assertions are the responsibility of the kernel
 * Assertions are changed from internal to external via task_importance_externalize_assertion
 */

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

	__imptrace_only int released_pid = 0;
	__imptrace_only int pid = task_pid(task);

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
			if (boost > 0) {
				ipc_importance_task_drop_internal_assertion(release_imp_task, boost);
			}

			// released_pid = task_pid(release_imp_task); /* TODO: Need ref-safe way to get pid */
			ipc_importance_task_release(release_imp_task);
		}
#if IMPORTANCE_TRACE
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_WATCHPORT, 0)) | DBG_FUNC_NONE,
		    proc_selfpid(), pid, boost, released_pid, 0);
#endif /* IMPORTANCE_TRACE */
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
 * (Un)Mark the task as a privileged listener for memory notifications.
 * if marked, this task will be among the first to be notified amongst
 * the bulk of all other tasks when the system enters a pressure level
 * of interest to this task.
 */
int
task_low_mem_privileged_listener(task_t task, boolean_t new_value, boolean_t *old_value)
{
	if (old_value != NULL) {
		*old_value = (boolean_t)task->low_mem_privileged_listener;
	} else {
		task_lock(task);
		task->low_mem_privileged_listener = (uint32_t)new_value;
		task_unlock(task);
	}

	return 0;
}

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

	if (pressurelevel == kVMPressureWarning) {
		return task->low_mem_notified_warn ? TRUE : FALSE;
	} else if (pressurelevel == kVMPressureCritical) {
		return task->low_mem_notified_critical ? TRUE : FALSE;
	} else {
		return TRUE;
	}
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

	if (pressurelevel == kVMPressureWarning) {
		return task->purged_memory_warn ? TRUE : FALSE;
	} else if (pressurelevel == kVMPressureCritical) {
		return task->purged_memory_critical ? TRUE : FALSE;
	} else {
		return TRUE;
	}
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

	if (pressurelevel == kVMPressureWarning) {
		task->low_mem_notified_warn = 1;
	} else if (pressurelevel == kVMPressureCritical) {
		task->low_mem_notified_critical = 1;
	}
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

	if (pressurelevel == kVMPressureWarning) {
		task->purged_memory_warn = 1;
	} else if (pressurelevel == kVMPressureCritical) {
		task->purged_memory_critical = 1;
	}
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

	if (pressurelevel == kVMPressureWarning) {
		task->low_mem_notified_warn = 0;
	} else if (pressurelevel == kVMPressureCritical) {
		task->low_mem_notified_critical = 0;
	}
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

	if (proc_get_effective_task_policy(task, TASK_POLICY_ROLE) == TASK_FOREGROUND_APPLICATION) {
		task_importance += TASK_IMPORTANCE_FOREGROUND;
	}

	if (proc_get_effective_task_policy(task, TASK_POLICY_DARWIN_BG) == 0) {
		task_importance += TASK_IMPORTANCE_NOTDARWINBG;
	}

	return task_importance;
}

boolean_t
task_has_assertions(task_t task)
{
	return task->task_imp_base->iit_assertcnt? TRUE : FALSE;
}


kern_return_t
send_resource_violation(typeof(send_cpu_usage_violation) sendfunc,
    task_t violator,
    struct ledger_entry_info *linfo,
    resource_notify_flags_t flags)
{
#ifndef MACH_BSD
	return KERN_NOT_SUPPORTED;
#else
	kern_return_t   kr = KERN_SUCCESS;
	proc_t          proc = NULL;
	posix_path_t    proc_path = "";
	proc_name_t     procname = "<unknown>";
	int             pid = -1;
	clock_sec_t     secs;
	clock_nsec_t    nsecs;
	mach_timespec_t timestamp;
	thread_t        curthread = current_thread();
	ipc_port_t      dstport = MACH_PORT_NULL;

	if (!violator) {
		kr = KERN_INVALID_ARGUMENT; goto finish;
	}

	/* extract violator information */
	task_lock(violator);
	if (!(proc = get_bsdtask_info(violator))) {
		task_unlock(violator);
		kr = KERN_INVALID_ARGUMENT; goto finish;
	}
	(void)mig_strncpy(procname, proc_best_name(proc), sizeof(procname));
	pid = task_pid(violator);
	if (flags & kRNFatalLimitFlag) {
		kr = proc_pidpathinfo_internal(proc, 0, proc_path,
		    sizeof(proc_path), NULL);
	}
	task_unlock(violator);
	if (kr) {
		goto finish;
	}

	/* violation time ~ now */
	clock_get_calendar_nanotime(&secs, &nsecs);
	timestamp.tv_sec = (int32_t)secs;
	timestamp.tv_nsec = (int32_t)nsecs;
	/* 25567702 tracks widening mach_timespec_t */

	/* send message */
	kr = host_get_special_port(host_priv_self(), HOST_LOCAL_NODE,
	    HOST_RESOURCE_NOTIFY_PORT, &dstport);
	if (kr) {
		goto finish;
	}

	thread_set_honor_qlimit(curthread);
	kr = sendfunc(dstport,
	    procname, pid, proc_path, timestamp,
	    linfo->lei_balance, linfo->lei_last_refill,
	    linfo->lei_limit, linfo->lei_refill_period,
	    flags);
	thread_clear_honor_qlimit(curthread);

	ipc_port_release_send(dstport);

finish:
	return kr;
#endif      /* MACH_BSD */
}


/*
 * Resource violations trace four 64-bit integers.  For K32, two additional
 * codes are allocated, the first with the low nibble doubled.  So if the K64
 * code is 0x042, the K32 codes would be 0x044 and 0x45.
 */
#ifdef __LP64__
void
trace_resource_violation(uint16_t code,
    struct ledger_entry_info *linfo)
{
	KERNEL_DBG_IST_SANE(KDBG_CODE(DBG_MACH, DBG_MACH_RESOURCE, code),
	    linfo->lei_balance, linfo->lei_last_refill,
	    linfo->lei_limit, linfo->lei_refill_period);
}
#else /* K32 */
/* TODO: create/find a trace_two_LLs() for K32 systems */
#define MASK32 0xffffffff
void
trace_resource_violation(uint16_t code,
    struct ledger_entry_info *linfo)
{
	int8_t lownibble = (code & 0x3) * 2;
	int16_t codeA = (code & 0xffc) | lownibble;
	int16_t codeB = codeA + 1;

	int32_t balance_high = (linfo->lei_balance >> 32) & MASK32;
	int32_t balance_low = linfo->lei_balance & MASK32;
	int32_t last_refill_high = (linfo->lei_last_refill >> 32) & MASK32;
	int32_t last_refill_low = linfo->lei_last_refill & MASK32;

	int32_t limit_high = (linfo->lei_limit >> 32) & MASK32;
	int32_t limit_low = linfo->lei_limit & MASK32;
	int32_t refill_period_high = (linfo->lei_refill_period >> 32) & MASK32;
	int32_t refill_period_low = linfo->lei_refill_period & MASK32;

	KERNEL_DBG_IST_SANE(KDBG_CODE(DBG_MACH, DBG_MACH_RESOURCE, codeA),
	    balance_high, balance_low,
	    last_refill_high, last_refill_low);
	KERNEL_DBG_IST_SANE(KDBG_CODE(DBG_MACH, DBG_MACH_RESOURCE, codeB),
	    limit_high, limit_low,
	    refill_period_high, refill_period_low);
}
#endif /* K64/K32 */

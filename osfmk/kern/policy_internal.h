/*
 * Copyright (c) 2015-2016 Apple Inc. All rights reserved.
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

#ifndef _KERN_POLICY_INTERNAL_H_
#define _KERN_POLICY_INTERNAL_H_

/*
 * Interfaces for functionality implemented in task_ or thread_policy subsystem
 */

#ifdef XNU_KERNEL_PRIVATE

#include <sys/cdefs.h>
#include <mach/kern_return.h>
#include <kern/kern_types.h>
#include <mach/task_policy.h>
#include <kern/task.h>
#include <kern/ledger.h>

/*
 ******************************
 * XNU-internal functionality
 ******************************
 */

/*
 * Get effective policy
 * Only for use by relevant subsystem, should never be passed into a setter!
 */
extern int proc_get_effective_task_policy(task_t task, int flavor);
extern int proc_get_effective_thread_policy(thread_t thread, int flavor);

/* Set task 'nice' value */
extern kern_return_t task_importance(task_t task, integer_t importance);

/* value */
#define TASK_POLICY_DISABLE             0x0
#define TASK_POLICY_ENABLE              0x1

/* category */
#define TASK_POLICY_INTERNAL            0x0
#define TASK_POLICY_EXTERNAL            0x1
#define TASK_POLICY_ATTRIBUTE           0x2

/* for tracing */
#define TASK_POLICY_TASK                0x4
#define TASK_POLICY_THREAD              0x8

/* flavors (also DBG_IMPORTANCE subclasses  0x20 - 0x3F) */

/* internal or external, thread or task */
#define TASK_POLICY_DARWIN_BG           0x21
#define TASK_POLICY_IOPOL               0x22
#define TASK_POLICY_IO                  0x23
#define TASK_POLICY_PASSIVE_IO          0x24

/* internal, task only */
#define TASK_POLICY_DARWIN_BG_IOPOL     0x27

/* task-only attributes */
#define TASK_POLICY_TAL                 0x28
#define TASK_POLICY_BOOST               0x29
#define TASK_POLICY_ROLE                0x2A
/* unused                               0x2B */
#define TASK_POLICY_TERMINATED          0x2C
#define TASK_POLICY_NEW_SOCKETS_BG      0x2D
/* unused                               0x2E */
#define TASK_POLICY_LATENCY_QOS         0x2F
#define TASK_POLICY_THROUGH_QOS         0x30
#define TASK_POLICY_WATCHERS_BG         0x31

#define TASK_POLICY_SFI_MANAGED         0x34
#define TASK_POLICY_ALL_SOCKETS_BG      0x37

#define TASK_POLICY_BASE_LATENCY_AND_THROUGHPUT_QOS  0x39 /* latency as value1, throughput as value2 */
#define TASK_POLICY_OVERRIDE_LATENCY_AND_THROUGHPUT_QOS  0x3A /* latency as value1, throughput as value2 */

/* thread-only attributes */
#define TASK_POLICY_PIDBIND_BG          0x32
/* unused                               0x33 */
#define TASK_POLICY_QOS                 0x35
#define TASK_POLICY_QOS_OVERRIDE        0x36
#define TASK_POLICY_QOS_AND_RELPRIO     0x38 /* QoS as value1, relative priority as value2 */
#define TASK_POLICY_QOS_PROMOTE         0x3C
#define TASK_POLICY_QOS_IPC_OVERRIDE    0x3D

#define TASK_POLICY_MAX                 0x3F

/* The main entrance to task policy is this function */
extern void proc_set_task_policy(task_t task, int category, int flavor, int value);
extern int  proc_get_task_policy(task_t task, int category, int flavor);

extern void proc_set_thread_policy(thread_t thread, int category, int flavor, int value);
extern int  proc_get_thread_policy(thread_t thread, int category, int flavor);

/* For use when you don't already hold a reference on the target thread */
extern void proc_set_thread_policy_with_tid(task_t task, uint64_t tid, int category, int flavor, int value);


/* Functions used by kern_resource.c */
extern boolean_t thread_has_qos_policy(thread_t thread);
extern kern_return_t thread_remove_qos_policy(thread_t thread);

extern int  proc_darwin_role_to_task_role(int darwin_role, int* task_role);
extern int  proc_task_role_to_darwin_role(int task_role);

/* Functions used by kern_exec.c */
extern void task_set_main_thread_qos(task_t task, thread_t main_thread);
extern void proc_set_task_spawnpolicy(task_t task, int apptype, int qos_clamp, int role,
                                      ipc_port_t * portwatch_ports, int portwatch_count);

/* IO Throttle tiers */
#define THROTTLE_LEVEL_NONE     -1
#define	THROTTLE_LEVEL_TIER0     0      /* IOPOL_NORMAL, IOPOL_DEFAULT, IOPOL_PASSIVE */

#define THROTTLE_LEVEL_THROTTLED 1
#define THROTTLE_LEVEL_TIER1     1      /* IOPOL_STANDARD */
#define THROTTLE_LEVEL_TIER2     2      /* IOPOL_UTILITY */
#define THROTTLE_LEVEL_TIER3     3      /* IOPOL_THROTTLE */

#define THROTTLE_LEVEL_START     0
#define THROTTLE_LEVEL_END       3

#define THROTTLE_LEVEL_COMPRESSOR_TIER0         THROTTLE_LEVEL_TIER0
#define THROTTLE_LEVEL_COMPRESSOR_TIER1         THROTTLE_LEVEL_TIER1
#define THROTTLE_LEVEL_COMPRESSOR_TIER2         THROTTLE_LEVEL_TIER2

#define THROTTLE_LEVEL_PAGEOUT_THROTTLED        THROTTLE_LEVEL_TIER2
#define THROTTLE_LEVEL_PAGEOUT_UNTHROTTLED      THROTTLE_LEVEL_TIER1

#if CONFIG_IOSCHED
#define IOSCHED_METADATA_TIER                   THROTTLE_LEVEL_TIER1
#endif /* CONFIG_IOSCHED */

extern int proc_get_darwinbgstate(task_t task, uint32_t *flagsp);
extern int task_get_apptype(task_t);

#ifdef MACH_BSD
extern void proc_apply_task_networkbg(void * bsd_info, thread_t thread);
#endif /* MACH_BSD */

/* Functions used by pthread_shims.c */
extern boolean_t proc_thread_qos_add_override(task_t task, thread_t thread, uint64_t tid,
                                              int override_qos, boolean_t first_override_for_resource,
                                              user_addr_t resource, int resource_type);
extern int proc_thread_qos_add_override_check_owner(thread_t thread, int override_qos,
		boolean_t first_override_for_resource, user_addr_t resource, int resource_type,
		user_addr_t user_lock_addr, mach_port_name_t user_lock_owner);
extern boolean_t proc_thread_qos_remove_override(task_t task, thread_t thread, uint64_t tid,
                                                 user_addr_t resource, int resource_type);
extern boolean_t proc_thread_qos_reset_override(task_t task, thread_t thread, uint64_t tid,
                                                 user_addr_t resource, int resource_type);
extern int proc_thread_qos_squash_override(thread_t thread, user_addr_t resource, int resource_type);

extern kern_return_t
thread_set_workq_qos(thread_t thread, int qos_tier, int relprio);
extern kern_return_t
thread_set_workq_pri(thread_t thread, integer_t priority, integer_t policy);

extern int
task_get_default_manager_qos(task_t task);

extern void proc_thread_qos_deallocate(thread_t thread);

extern int task_clear_cpuusage(task_t task, int cpumon_entitled);


/* Importance inheritance functions not under IMPORTANCE_INHERITANCE */
extern void task_importance_mark_donor(task_t task, boolean_t donating);
extern void task_importance_reset(task_t task);

#if IMPORTANCE_INHERITANCE
extern boolean_t task_is_importance_donor(task_t task);
extern boolean_t task_is_importance_receiver_type(task_t task);

extern int task_importance_hold_file_lock_assertion(task_t target_task, uint32_t count);
extern int task_importance_drop_file_lock_assertion(task_t target_task, uint32_t count);

extern int task_importance_hold_legacy_external_assertion(task_t target_task, uint32_t count);
extern int task_importance_drop_legacy_external_assertion(task_t target_task, uint32_t count);
#endif /* IMPORTANCE_INHERITANCE */

/* Functions used by process_policy.c */
extern boolean_t proc_task_is_tal(task_t task);

/* Arguments to proc_set_task_ruse_cpu */
#define TASK_POLICY_RESOURCE_ATTRIBUTE_NONE             0x00
#define TASK_POLICY_RESOURCE_ATTRIBUTE_THROTTLE         0x01
#define TASK_POLICY_RESOURCE_ATTRIBUTE_SUSPEND          0x02
#define TASK_POLICY_RESOURCE_ATTRIBUTE_TERMINATE        0x03
#define TASK_POLICY_RESOURCE_ATTRIBUTE_NOTIFY_KQ        0x04
#define TASK_POLICY_RESOURCE_ATTRIBUTE_NOTIFY_EXC       0x05
#define TASK_POLICY_RESOURCE_ATTRIBUTE_DEFAULT          TASK_POLICY_RESOURCE_ATTRIBUTE_NONE

extern int proc_get_task_ruse_cpu(task_t task, uint32_t *policyp, uint8_t *percentagep,
                                  uint64_t *intervalp, uint64_t *deadlinep);
extern int proc_set_task_ruse_cpu(task_t task, uint32_t policy, uint8_t percentage,
                                  uint64_t interval, uint64_t deadline, int cpumon_entitled);
extern int task_suspend_cpumon(task_t task);
extern int task_resume_cpumon(task_t task);
extern int proc_clear_task_ruse_cpu(task_t task, int cpumon_entitled);

extern int proc_apply_resource_actions(void * p, int type, int action);
extern int proc_restore_resource_actions(void * p, int type, int action);

/* VM/Jetsam importance callouts */
extern int task_low_mem_privileged_listener(task_t task, boolean_t new_value, boolean_t *old_value);
extern boolean_t task_has_been_notified(task_t task, int pressurelevel);
extern boolean_t task_used_for_purging(task_t task, int pressurelevel);
extern void task_mark_has_been_notified(task_t task, int pressurelevel);
extern void task_mark_used_for_purging(task_t task, int pressurelevel);
extern void task_clear_has_been_notified(task_t task, int pressurelevel);
extern void task_clear_used_for_purging(task_t task);
extern int task_importance_estimate(task_t task);

/*
 * Allocate/assign a single work interval ID for a thread,
 * and support deallocating it.
 */
extern kern_return_t thread_policy_create_work_interval(thread_t thread, uint64_t *work_interval_id);
extern kern_return_t thread_policy_destroy_work_interval(thread_t thread, uint64_t work_interval_id);

extern kern_return_t thread_policy_set_internal(thread_t thread, thread_policy_flavor_t flavor,
                                                thread_policy_t policy_info, mach_msg_type_number_t count);

struct promote_token {
	uint16_t        pt_basepri;
	uint16_t        pt_qos;
};

#define PROMOTE_TOKEN_INIT ((struct promote_token){.pt_basepri = 0, .pt_qos = 0})

extern void thread_user_promotion_add(thread_t thread, thread_t promoter, struct promote_token* promote_token);
extern void thread_user_promotion_update(thread_t thread, thread_t promoter, struct promote_token* promote_token);
extern void thread_user_promotion_drop(thread_t thread);

/* for IPC override management */
extern void thread_add_ipc_override(thread_t thread, uint32_t qos_override);
extern void thread_update_ipc_override(thread_t thread, uint32_t qos_override);
extern void thread_drop_ipc_override(thread_t thread);
extern uint32_t thread_get_ipc_override(thread_t thread);

/*
 ******************************
 * Mach-internal functionality
 ******************************
 */

#ifdef MACH_KERNEL_PRIVATE

/*
 * this exports the internal policy update calls
 * for IPC importance hooks into task policy
 */

typedef struct task_pend_token {
	uint32_t        tpt_update_sockets      :1,
	                tpt_update_timers       :1,
	                tpt_update_watchers     :1,
	                tpt_update_live_donor   :1,
	                tpt_update_coal_sfi     :1,
	                tpt_update_throttle     :1,
	                tpt_update_thread_sfi   :1,
	                tpt_force_recompute_pri :1;
} *task_pend_token_t;

extern void task_policy_update_complete_unlocked(task_t task, task_pend_token_t pend_token);
extern void task_update_boost_locked(task_t task, boolean_t boost_active, task_pend_token_t pend_token);

extern void thread_policy_update_locked(thread_t thread, task_pend_token_t pend_token);
extern void thread_policy_update_complete_unlocked(thread_t task, task_pend_token_t pend_token);

typedef struct {
	int             qos_pri[THREAD_QOS_LAST];
	int             qos_iotier[THREAD_QOS_LAST];
	uint32_t        qos_through_qos[THREAD_QOS_LAST];
	uint32_t        qos_latency_qos[THREAD_QOS_LAST];
} qos_policy_params_t;

extern const qos_policy_params_t thread_qos_policy_params;

/* for task policy tracepoints */
/* Convenience functions for munging a policy bitfield into a tracepoint */
uintptr_t threquested_0(thread_t thread);
uintptr_t threquested_1(thread_t thread);
uintptr_t theffective_0(thread_t thread);
uintptr_t theffective_1(thread_t thread);
extern uint32_t  tpending(task_pend_token_t pend_token);

extern void proc_iopol_to_tier(int iopolicy, int *tier, int *passive);
extern int  proc_tier_to_iopol(int tier, int passive);

extern void set_thread_iotier_override(thread_t, int policy);

extern integer_t task_grab_latency_qos(task_t task);
extern void task_policy_create(task_t task, task_t parent_task);
extern void thread_policy_create(thread_t thread);

extern boolean_t task_is_daemon(task_t task);
extern boolean_t task_is_app(task_t task);


#if IMPORTANCE_INHERITANCE
extern boolean_t task_is_marked_importance_donor(task_t task);
extern boolean_t task_is_marked_importance_receiver(task_t task);

extern boolean_t task_is_marked_importance_denap_receiver(task_t task);
#endif /* IMPORTANCE_INHERITANCE */

/* flags for rusage_cpu_flags */
#define TASK_RUSECPU_FLAGS_PROC_LIMIT                   0x01
#define TASK_RUSECPU_FLAGS_PERTHR_LIMIT                 0x02
#define TASK_RUSECPU_FLAGS_DEADLINE                     0x04
#define TASK_RUSECPU_FLAGS_FATAL_CPUMON                 0x08    /* CPU usage monitor violations are fatal */
#define TASK_RUSECPU_FLAGS_FATAL_WAKEUPSMON             0x10    /* wakeups monitor violations are fatal */
#define TASK_RUSECPU_FLAGS_PHYS_FOOTPRINT_EXCEPTION     0x20    /* exceeding physical footprint generates EXC_RESOURCE */

extern void proc_init_cpumon_params(void);
extern void thread_policy_init(void);

int task_compute_main_thread_qos(task_t task);

/* thread policy internals */
extern void thread_policy_reset(thread_t thread);
extern kern_return_t thread_set_mode_and_absolute_pri(thread_t thread, integer_t policy, integer_t priority);

extern void thread_policy_update_tasklocked(thread_t thread, integer_t priority, integer_t max_priority, task_pend_token_t pend_token);

#include "mach/resource_notify.h"       /* from MIG */

/*! @function   send_resource_violation
    @abstract   send usage monitor violation notification

    @param  violator  the task (process) violating its CPU budget
    @param  ledger_info   the entry tracking the resource limit
    @param  flags   see constants for type in sys/reason.h

    @result KERN_SUCCESS if the message was sent

    @discussion
        send_resource_violation() calls the corresponding MIG routine
        over the host special RESOURCE_NOTIFY port.
*/
kern_return_t send_resource_violation(typeof(send_cpu_usage_violation),
                                      task_t violator,
                                      struct ledger_entry_info *ledger_info,
                                      resource_notify_flags_t flags);

/*! @function	trace_resource_violation
    @abstract	trace violations on K32/64

    @param  code   the (K64) DBG_MACH_RESOURCE trace code
    @param  ledger_info   the entry tracking the resource limit

    @discussion
        Trace observed usage and corresponding limit on K32 or K64.  On
        K32, a pair of trace points are used.  The low nibble of the K32
        trace points must start at double the low nibble of the provided
        K64 trace point.  For example:
		#define LOGWRITES_VIOLATED              0x022
		...
		#define LOGWRITES_VIOLATED_K32A         0x024
		#define LOGWRITES_VIOLATED_K32B         0x025
*/
void trace_resource_violation(uint16_t code,
                              struct ledger_entry_info *ledger_info);

#endif /* MACH_KERNEL_PRIVATE */

#endif /* XNU_KERNEL_PRIVATE */

#endif /* _KERN_POLICY_INTERNAL_H_ */

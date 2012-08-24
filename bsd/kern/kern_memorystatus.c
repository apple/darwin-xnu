/*
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
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
 *
 */

#include <kern/sched_prim.h>
#include <kern/kalloc.h>
#include <kern/assert.h>
#include <kern/debug.h>
#include <kern/lock.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/host.h>
#include <libkern/libkern.h>
#include <mach/mach_time.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/host_priv.h>
#include <sys/kern_event.h>
#include <sys/proc.h>
#include <sys/signal.h>
#include <sys/signalvar.h>
#include <sys/sysctl.h>
#include <sys/sysproto.h>
#include <sys/wait.h>
#include <sys/tree.h>
#include <sys/priv.h>
#include <pexpert/pexpert.h>

#if CONFIG_FREEZE
#include <vm/vm_protos.h>
#include <vm/vm_map.h>
#endif

#include <sys/kern_memorystatus.h> 

/* These are very verbose printfs(), enable with
 * MEMORYSTATUS_DEBUG_LOG
 */
#if MEMORYSTATUS_DEBUG_LOG
#define MEMORYSTATUS_DEBUG(cond, format, ...)      \
do {                                              \
	if (cond) { printf(format, ##__VA_ARGS__); } \
} while(0)
#else
#define MEMORYSTATUS_DEBUG(cond, format, ...)
#endif

/* General memorystatus stuff */

static void memorystatus_add_node(memorystatus_node *node);
static void memorystatus_remove_node(memorystatus_node *node);
static memorystatus_node *memorystatus_get_node(pid_t pid);
static void memorystatus_release_node(memorystatus_node *node);

int memorystatus_wakeup = 0;

static void memorystatus_thread(void *param __unused, wait_result_t wr __unused);

static memorystatus_node *next_memorystatus_node = NULL;

static int memorystatus_list_count = 0;

static lck_mtx_t * memorystatus_list_mlock;
static lck_attr_t * memorystatus_lck_attr;
static lck_grp_t * memorystatus_lck_grp;
static lck_grp_attr_t * memorystatus_lck_grp_attr;

static TAILQ_HEAD(memorystatus_list_head, memorystatus_node) memorystatus_list;

static uint64_t memorystatus_idle_delay_time = 0;

static unsigned int memorystatus_dirty_count = 0;

extern void proc_dirty_start(struct proc *p);
extern void proc_dirty_end(struct proc *p);

/* Jetsam */

#if CONFIG_JETSAM

extern unsigned int    vm_page_free_count;
extern unsigned int    vm_page_active_count;
extern unsigned int    vm_page_inactive_count;
extern unsigned int    vm_page_throttled_count;
extern unsigned int    vm_page_purgeable_count;
extern unsigned int    vm_page_wire_count;

static lck_mtx_t * exit_list_mlock;

static TAILQ_HEAD(exit_list_head, memorystatus_node) exit_list;

static unsigned int memorystatus_kev_failure_count = 0;

/* Counted in pages... */
unsigned int memorystatus_delta = 0;

unsigned int memorystatus_available_pages = (unsigned int)-1;
unsigned int memorystatus_available_pages_critical = 0;
unsigned int memorystatus_available_pages_highwater = 0;

/* ...with the exception of the legacy level in percent. */
unsigned int memorystatus_level = 0;

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_kev_failure_count, CTLFLAG_RD, &memorystatus_kev_failure_count, 0, "");
SYSCTL_INT(_kern, OID_AUTO, memorystatus_level, CTLFLAG_RD, &memorystatus_level, 0, "");

unsigned int memorystatus_jetsam_policy = kPolicyDefault;

unsigned int memorystatus_jetsam_policy_offset_pages_more_free = 0;
#if DEVELOPMENT || DEBUG
unsigned int memorystatus_jetsam_policy_offset_pages_diagnostic = 0;
#endif

static memorystatus_jetsam_snapshot_t memorystatus_jetsam_snapshot;
#define memorystatus_jetsam_snapshot_list memorystatus_jetsam_snapshot.entries

static int memorystatus_jetsam_snapshot_list_count = 0;

int memorystatus_jetsam_wakeup = 0;
unsigned int memorystatus_jetsam_running = 1;

static uint32_t memorystatus_task_page_count(task_t task);

static void memorystatus_move_node_to_exit_list(memorystatus_node *node);

static void memorystatus_update_levels_locked(void);

static void memorystatus_jetsam_thread_block(void);
static void memorystatus_jetsam_thread(void *param __unused, wait_result_t wr __unused);

static int memorystatus_send_note(int event_code, void *data, size_t data_length);

static uint32_t memorystatus_build_flags_from_state(uint32_t state);

/* VM pressure */

#if VM_PRESSURE_EVENTS

typedef enum vm_pressure_level {
        kVMPressureNormal   = 0,
        kVMPressureWarning  = 1,
        kVMPressureUrgent   = 2,
        kVMPressureCritical = 3,
} vm_pressure_level_t;

static vm_pressure_level_t memorystatus_vm_pressure_level = kVMPressureNormal;

unsigned int memorystatus_available_pages_pressure = 0;

static inline boolean_t memorystatus_get_pressure_locked(void);
static void memorystatus_check_pressure_reset(void);

#endif /* VM_PRESSURE_EVENTS */

#endif /* CONFIG_JETSAM */

/* Freeze */

#if CONFIG_FREEZE

static unsigned int memorystatus_suspended_resident_count = 0;
static unsigned int memorystatus_suspended_count = 0;

boolean_t memorystatus_freeze_enabled = FALSE;
int memorystatus_freeze_wakeup = 0;

static inline boolean_t memorystatus_can_freeze_processes(void);
static boolean_t memorystatus_can_freeze(boolean_t *memorystatus_freeze_swap_low);

static void memorystatus_freeze_thread(void *param __unused, wait_result_t wr __unused);

/* Thresholds */
static unsigned int memorystatus_freeze_threshold = 0;

static unsigned int memorystatus_freeze_pages_min = FREEZE_PAGES_MIN;
static unsigned int memorystatus_freeze_pages_max = FREEZE_PAGES_MAX;

static unsigned int memorystatus_frozen_count = 0;

static unsigned int memorystatus_freeze_suspended_threshold = FREEZE_SUSPENDED_THRESHOLD_DEFAULT;

/* Stats */
static uint64_t memorystatus_freeze_count = 0;
static uint64_t memorystatus_freeze_pageouts = 0;

/* Throttling */
static throttle_interval_t throttle_intervals[] = {
	{      60,  8, 0, 0, { 0, 0 }, FALSE }, /* 1 hour intermediate interval, 8x burst */
	{ 24 * 60,  1, 0, 0, { 0, 0 }, FALSE }, /* 24 hour long interval, no burst */
};

static uint64_t memorystatus_freeze_throttle_count = 0;

#endif /* CONFIG_FREEZE */

#if CONFIG_JETSAM

/* Debug */

#if DEVELOPMENT || DEBUG

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages, CTLFLAG_RD, &memorystatus_available_pages, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages_critical, CTLFLAG_RW, &memorystatus_available_pages_critical, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages_highwater, CTLFLAG_RW, &memorystatus_available_pages_highwater, 0, "");
#if VM_PRESSURE_EVENTS
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages_pressure, CTLFLAG_RW, &memorystatus_available_pages_pressure, 0, "");
#endif /* VM_PRESSURE_EVENTS */

/* Diagnostic code */
enum {
	kJetsamDiagnosticModeNone =              0, 
	kJetsamDiagnosticModeAll  =              1,
	kJetsamDiagnosticModeStopAtFirstActive = 2,
	kJetsamDiagnosticModeCount
} jetsam_diagnostic_mode = kJetsamDiagnosticModeNone;

static int jetsam_diagnostic_suspended_one_active_proc = 0;

static int
sysctl_jetsam_diagnostic_mode SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)

	const char *diagnosticStrings[] = {
		"jetsam: diagnostic mode: resetting critical level.",
		"jetsam: diagnostic mode: will examine all processes",
		"jetsam: diagnostic mode: will stop at first active process"                
	};
        
	int error, val = jetsam_diagnostic_mode;
	boolean_t changed = FALSE;

	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || !req->newptr)
 		return (error);
	if ((val < 0) || (val >= kJetsamDiagnosticModeCount)) {
		printf("jetsam: diagnostic mode: invalid value - %d\n", val);
		return EINVAL;
	}
	
	lck_mtx_lock(memorystatus_list_mlock);
	
	if ((unsigned int) val != jetsam_diagnostic_mode) {
		jetsam_diagnostic_mode = val;

		memorystatus_jetsam_policy &= ~kPolicyDiagnoseActive;
                
		switch (jetsam_diagnostic_mode) {
		case kJetsamDiagnosticModeNone:
			/* Already cleared */
			break;
		case kJetsamDiagnosticModeAll:
			memorystatus_jetsam_policy |= kPolicyDiagnoseAll;
			break;
		case kJetsamDiagnosticModeStopAtFirstActive:
			memorystatus_jetsam_policy |= kPolicyDiagnoseFirst;
			break;
		default:
			/* Already validated */
			break;
		}
        	
       	memorystatus_update_levels_locked();
		changed = TRUE;
	}
        
	lck_mtx_unlock(memorystatus_list_mlock);
	
	if (changed) {
		printf("%s\n", diagnosticStrings[val]);
	}
	
	return (0);
}

SYSCTL_PROC(_debug, OID_AUTO, jetsam_diagnostic_mode, CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_ANYBODY,
  		&jetsam_diagnostic_mode, 0, sysctl_jetsam_diagnostic_mode, "I", "Jetsam Diagnostic Mode");

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_jetsam_policy_offset_pages_more_free, CTLFLAG_RW, &memorystatus_jetsam_policy_offset_pages_more_free, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_jetsam_policy_offset_pages_diagnostic, CTLFLAG_RW, &memorystatus_jetsam_policy_offset_pages_diagnostic, 0, "");

#if VM_PRESSURE_EVENTS

#include "vm_pressure.h"

static int
sysctl_memorystatus_vm_pressure_level SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	int error = 0;

	error = priv_check_cred(kauth_cred_get(), PRIV_VM_PRESSURE, 0);
	if (error)
		return (error);

	return SYSCTL_OUT(req, &memorystatus_vm_pressure_level, sizeof(memorystatus_vm_pressure_level));
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_vm_pressure_level, CTLTYPE_INT|CTLFLAG_RD|CTLFLAG_LOCKED|CTLFLAG_MASKED,
    0, 0, &sysctl_memorystatus_vm_pressure_level, "I", "");

static int
sysctl_memorystatus_vm_pressure_send SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)

	int error, pid = 0;

	error = sysctl_handle_int(oidp, &pid, 0, req);
	if (error || !req->newptr)
		return (error);

	if (vm_dispatch_pressure_note_to_pid(pid)) {
		return 0;
	}

	return EINVAL;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_vm_pressure_send, CTLTYPE_INT|CTLFLAG_WR|CTLFLAG_LOCKED|CTLFLAG_MASKED,
    0, 0, &sysctl_memorystatus_vm_pressure_send, "I", "");

#endif /* VM_PRESSURE_EVENTS */

#endif /* CONFIG_JETSAM */

#if CONFIG_FREEZE

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_threshold, CTLFLAG_RW, &memorystatus_freeze_threshold, 0, "");

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_pages_min, CTLFLAG_RW, &memorystatus_freeze_pages_min, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_pages_max, CTLFLAG_RW, &memorystatus_freeze_pages_max, 0, "");

SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freeze_count, CTLFLAG_RD, &memorystatus_freeze_count, "");
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freeze_pageouts, CTLFLAG_RD, &memorystatus_freeze_pageouts, "");
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freeze_throttle_count, CTLFLAG_RD, &memorystatus_freeze_throttle_count, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_min_processes, CTLFLAG_RW, &memorystatus_freeze_suspended_threshold, 0, "");

boolean_t memorystatus_freeze_throttle_enabled = TRUE;
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_throttle_enabled, CTLFLAG_RW, &memorystatus_freeze_throttle_enabled, 0, "");

/* 
 * Manual trigger of freeze and thaw for dev / debug kernels only.
 */
static int
sysctl_memorystatus_freeze SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)

	int error, pid = 0;
	proc_t p;

	error = sysctl_handle_int(oidp, &pid, 0, req);
	if (error || !req->newptr)
		return (error);

	p = proc_find(pid);
	if (p != NULL) {
		uint32_t purgeable, wired, clean, dirty;
		boolean_t shared;
		uint32_t max_pages = MIN(default_pager_swap_pages_free(), memorystatus_freeze_pages_max);
		task_freeze(p->task, &purgeable, &wired, &clean, &dirty, max_pages, &shared, FALSE);
		proc_rele(p);
        return 0;
	}

	return EINVAL;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_freeze, CTLTYPE_INT|CTLFLAG_WR|CTLFLAG_LOCKED|CTLFLAG_MASKED,
    0, 0, &sysctl_memorystatus_freeze, "I", "");

static int
sysctl_memorystatus_available_pages_thaw SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)

	int error, pid = 0;
	proc_t p;

	error = sysctl_handle_int(oidp, &pid, 0, req);
	if (error || !req->newptr)
		return (error);

	p = proc_find(pid);
	if (p != NULL) {
		task_thaw(p->task);
		proc_rele(p);
		return 0;
	}

	return EINVAL;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_thaw, CTLTYPE_INT|CTLFLAG_WR|CTLFLAG_LOCKED|CTLFLAG_MASKED,
    0, 0, &sysctl_memorystatus_available_pages_thaw, "I", "");

#endif /* CONFIG_FREEZE */

#endif /* DEVELOPMENT || DEBUG */

__private_extern__ void
memorystatus_init(void)
{
	thread_t thread = THREAD_NULL;
	kern_return_t result;
	
	memorystatus_lck_attr = lck_attr_alloc_init();
	memorystatus_lck_grp_attr = lck_grp_attr_alloc_init();
	memorystatus_lck_grp = lck_grp_alloc_init("memorystatus",  memorystatus_lck_grp_attr);
	memorystatus_list_mlock = lck_mtx_alloc_init(memorystatus_lck_grp, memorystatus_lck_attr);
	TAILQ_INIT(&memorystatus_list);

#if CONFIG_JETSAM
	exit_list_mlock = lck_mtx_alloc_init(memorystatus_lck_grp, memorystatus_lck_attr);
	TAILQ_INIT(&exit_list);
	
	memorystatus_delta = DELTA_PERCENT * atop_64(max_mem) / 100;
#endif

#if CONFIG_FREEZE
	memorystatus_freeze_threshold = (FREEZE_PERCENT / DELTA_PERCENT) * memorystatus_delta;
#endif

	nanoseconds_to_absolutetime((uint64_t)IDLE_EXIT_TIME_SECS * NSEC_PER_SEC, &memorystatus_idle_delay_time);

	result = kernel_thread_start(memorystatus_thread, NULL, &thread);
	if (result == KERN_SUCCESS) {
		thread_deallocate(thread);
	} else {
		panic("Could not create memorystatus_thread");
	}

#if CONFIG_JETSAM
	memorystatus_jetsam_policy_offset_pages_more_free = (POLICY_MORE_FREE_OFFSET_PERCENT / DELTA_PERCENT) * memorystatus_delta;
#if DEVELOPMENT || DEBUG
	memorystatus_jetsam_policy_offset_pages_diagnostic = (POLICY_DIAGNOSTIC_OFFSET_PERCENT / DELTA_PERCENT) * memorystatus_delta;
#endif

	/* No contention at this point */
	memorystatus_update_levels_locked();
	
	result = kernel_thread_start(memorystatus_jetsam_thread, NULL, &thread);
	if (result == KERN_SUCCESS) {
		thread_deallocate(thread);
	} else {
		panic("Could not create memorystatus_jetsam_thread");
	}
#endif
}

/*
 * Node manipulation
 */

static void
memorystatus_add_node(memorystatus_node *new_node)
{
	memorystatus_node *node;

 	/* Make sure we're called with the list lock held */
	lck_mtx_assert(memorystatus_list_mlock, LCK_MTX_ASSERT_OWNED);

	TAILQ_FOREACH(node, &memorystatus_list, link) {
		if (node->priority <= new_node->priority) {
			break;
		}
	}

	if (node) {
		TAILQ_INSERT_BEFORE(node, new_node, link);
	} else {
		TAILQ_INSERT_TAIL(&memorystatus_list, new_node, link);
	}

	next_memorystatus_node = TAILQ_FIRST(&memorystatus_list);

	memorystatus_list_count++;
}

static void
memorystatus_remove_node(memorystatus_node *node) 
{
	/* Make sure we're called with the list lock held */
	lck_mtx_assert(memorystatus_list_mlock, LCK_MTX_ASSERT_OWNED);

	TAILQ_REMOVE(&memorystatus_list, node, link);
 	next_memorystatus_node = TAILQ_FIRST(&memorystatus_list);

#if CONFIG_FREEZE    
	if (node->state & (kProcessFrozen)) {
		memorystatus_frozen_count--;
	}

	if (node->state & kProcessSuspended) {
		memorystatus_suspended_resident_count -= node->resident_pages;
		memorystatus_suspended_count--;
	}
#endif

	memorystatus_list_count--;
}

/* Returns with the lock taken if found */
static memorystatus_node *
memorystatus_get_node(pid_t pid) 
{
	memorystatus_node *node;

	lck_mtx_lock(memorystatus_list_mlock);

	TAILQ_FOREACH(node, &memorystatus_list, link) {
		if (node->pid == pid) {
			break;
		}
	}

	if (!node) {
		lck_mtx_unlock(memorystatus_list_mlock);		
	}

	return node;
}

static void
memorystatus_release_node(memorystatus_node *node) 
{
#pragma unused(node)
	lck_mtx_unlock(memorystatus_list_mlock);	
}

/* 
 * List manipulation
 */
 
kern_return_t 
memorystatus_list_add(pid_t pid, int priority, int high_water_mark)
{

#if !CONFIG_JETSAM
#pragma unused(high_water_mark)
#endif

	memorystatus_node *new_node;

	new_node = (memorystatus_node*)kalloc(sizeof(memorystatus_node));
	if (!new_node) {
		assert(FALSE);
	}
	memset(new_node, 0, sizeof(memorystatus_node));
    
	MEMORYSTATUS_DEBUG(1, "memorystatus_list_add: adding process %d with priority %d, high water mark %d.\n", pid, priority, high_water_mark);
    
	new_node->pid = pid;
	new_node->priority = priority;
#if CONFIG_JETSAM
	new_node->hiwat_pages = high_water_mark;
#endif    

	lck_mtx_lock(memorystatus_list_mlock);
    
	memorystatus_add_node(new_node);
        
	lck_mtx_unlock(memorystatus_list_mlock);
	
	return KERN_SUCCESS;
}

kern_return_t
memorystatus_list_change(boolean_t effective, pid_t pid, int priority, int state_flags, int high_water_mark)
{

#if !CONFIG_JETSAM
#pragma unused(high_water_mark)
#endif
	
	kern_return_t ret;
	memorystatus_node *node, *search;

	MEMORYSTATUS_DEBUG(1, "memorystatus_list_change: changing process %d to priority %d with flags %d\n", pid, priority, state_flags);

	lck_mtx_lock(memorystatus_list_mlock);

	TAILQ_FOREACH(node, &memorystatus_list, link) {
		if (node->pid == pid) {
			break;
		}
	}
    
	if (!node) {
		ret = KERN_FAILURE;
		goto out;             
	}

	if (effective && (node->state & kProcessPriorityUpdated)) {
		MEMORYSTATUS_DEBUG(1, "memorystatus_list_change: effective change specified for pid %d, but change already occurred.\n", pid);
		ret = KERN_FAILURE;
		goto out;             
	}

	node->state |= kProcessPriorityUpdated;
 
	if (state_flags != -1) {
		node->state &= ~(kProcessActive|kProcessForeground);
		if (state_flags & kMemorystatusFlagsFrontmost) {
			node->state |= kProcessForeground;
		}
		if (state_flags & kMemorystatusFlagsActive) {
			node->state |= kProcessActive;
		}
	}

#if CONFIG_JETSAM        
	if (high_water_mark != -1) {
		node->hiwat_pages = high_water_mark;
	}
#endif

	if (node->priority == priority) {
		/* Priority unchanged */
		MEMORYSTATUS_DEBUG(1, "memorystatus_list_change: same priority set for pid %d\n", pid);
		ret = KERN_SUCCESS;
		goto out;
	}

	if (node->priority < priority) {
		/* Higher priority value (ie less important) - search backwards */
		search = TAILQ_PREV(node, memorystatus_list_head, link);
		TAILQ_REMOVE(&memorystatus_list, node, link);

		node->priority = priority;
		while (search && (search->priority <= node->priority)) {
			search = TAILQ_PREV(search, memorystatus_list_head, link);
		}
		if (search) {
			TAILQ_INSERT_AFTER(&memorystatus_list, search, node, link);
		} else {
			TAILQ_INSERT_HEAD(&memorystatus_list, node, link);
		}
	} else {
		/* Lower priority value (ie more important) - search forwards */
		search = TAILQ_NEXT(node, link);
		TAILQ_REMOVE(&memorystatus_list, node, link);

		node->priority = priority;
		while (search && (search->priority >= node->priority)) {
			search = TAILQ_NEXT(search, link);
		}
		if (search) {
			TAILQ_INSERT_BEFORE(search, node, link);
		} else {
			TAILQ_INSERT_TAIL(&memorystatus_list, node, link);
		}
	}

	next_memorystatus_node = TAILQ_FIRST(&memorystatus_list);
	ret = KERN_SUCCESS;

out:
	lck_mtx_unlock(memorystatus_list_mlock);
	return ret;
}

kern_return_t memorystatus_list_remove(pid_t pid)
{
	kern_return_t ret;
	memorystatus_node *node = NULL;

	MEMORYSTATUS_DEBUG(1, "memorystatus_list_remove: removing process %d\n", pid);

#if CONFIG_JETSAM
	/* Did we mark this as a exited process? */
	lck_mtx_lock(exit_list_mlock);

	TAILQ_FOREACH(node, &exit_list, link) {
		if (node->pid == pid) {
			/* We did, so remove it from the list. The stats were updated when the queues were shifted. */
			TAILQ_REMOVE(&exit_list, node, link);
			break;
		}
	}

	lck_mtx_unlock(exit_list_mlock);
#endif

	/* If not, search the main list */
	if (!node) {
		lck_mtx_lock(memorystatus_list_mlock);

		TAILQ_FOREACH(node, &memorystatus_list, link) {
			if (node->pid == pid) {
				/* Remove from the list, and update accounting accordingly */
				memorystatus_remove_node(node);
				break;
			}
		}

		lck_mtx_unlock(memorystatus_list_mlock);
	}

	if (node) {
		kfree(node, sizeof(memorystatus_node));
		ret = KERN_SUCCESS; 
	} else {
		ret = KERN_FAILURE;
	}

	return ret;
}

kern_return_t 
memorystatus_on_track_dirty(int pid, boolean_t track)
{
	kern_return_t ret = KERN_FAILURE;
	memorystatus_node *node;
	
	node = memorystatus_get_node((pid_t)pid);
	if (!node) {
		return KERN_FAILURE;
	}
	
	if (track & !(node->state & kProcessSupportsIdleExit)) {
		node->state |= kProcessSupportsIdleExit;
		node->clean_time = mach_absolute_time() + memorystatus_idle_delay_time;
		ret = KERN_SUCCESS;
	} else	if (!track & (node->state & kProcessSupportsIdleExit)) {
		node->state &= ~kProcessSupportsIdleExit;
		node->clean_time = 0;
		ret = KERN_SUCCESS;		
	}
	
	memorystatus_release_node(node);
		
	return ret;	
}

kern_return_t 
memorystatus_on_dirty(int pid, boolean_t dirty)
{
	kern_return_t ret = KERN_FAILURE;
	memorystatus_node *node;
	
	node = memorystatus_get_node((pid_t)pid);
	if (!node) {
		return KERN_FAILURE;
	}
	
	if (dirty) {
		if (!(node->state & kProcessDirty)) {
			node->state |= kProcessDirty;
			node->clean_time = 0;
			memorystatus_dirty_count++;
			ret = KERN_SUCCESS;
		}
	} else {
		if (node->state & kProcessDirty) {
			node->state &= ~kProcessDirty;
			node->clean_time = mach_absolute_time() + memorystatus_idle_delay_time;
			memorystatus_dirty_count--;
			ret = KERN_SUCCESS;
		}
	}
	
	memorystatus_release_node(node);
	
	return ret;
}

void 
memorystatus_on_suspend(int pid)
{	
	memorystatus_node *node = memorystatus_get_node((pid_t)pid);

	if (node) {
#if CONFIG_FREEZE
		proc_t p;

		p = proc_find(pid);
		if (p != NULL) {
			uint32_t pages = memorystatus_task_page_count(p->task);
			proc_rele(p);
			node->resident_pages = pages;
			memorystatus_suspended_resident_count += pages;
		}
		memorystatus_suspended_count++;
#endif

		node->state |= kProcessSuspended;

		memorystatus_release_node(node);
	}
}

void
memorystatus_on_resume(int pid)
{	
	memorystatus_node *node = memorystatus_get_node((pid_t)pid);

	if (node) {
#if CONFIG_FREEZE
		boolean_t frozen = (node->state & kProcessFrozen);
		if (node->state & (kProcessFrozen)) {
			memorystatus_frozen_count--;
		}
		memorystatus_suspended_resident_count -= node->resident_pages;
		memorystatus_suspended_count--;
#endif

		node->state &= ~(kProcessSuspended | kProcessFrozen | kProcessIgnored);

		memorystatus_release_node(node);

#if CONFIG_FREEZE
		if (frozen) {
			memorystatus_freeze_entry_t data = { pid, kMemorystatusFlagsThawed, 0 };
			memorystatus_send_note(kMemorystatusFreezeNote, &data, sizeof(data));
		}
#endif
	}
}

void
memorystatus_on_inactivity(int pid)
{
#pragma unused(pid)
#if CONFIG_FREEZE
	/* Wake the freeze thread */
	thread_wakeup((event_t)&memorystatus_freeze_wakeup);
#endif	
}

static void
memorystatus_thread(void *param __unused, wait_result_t wr __unused)
{
	static boolean_t initialized = FALSE;
	memorystatus_node *node;
	uint64_t current_time;
	pid_t victim_pid = -1;

	if (initialized == FALSE) {
		initialized = TRUE;
	 	assert_wait(&memorystatus_wakeup, THREAD_UNINT);
		(void)thread_block((thread_continue_t)memorystatus_thread);
	}

	/*  Pick next idle exit victim. For now, just iterate through; ideally, this would be be more intelligent. */
	current_time = mach_absolute_time();
	
	/* Set a cutoff so that we don't idle exit processes that went recently clean */
	
	lck_mtx_lock(memorystatus_list_mlock);
	
	if (memorystatus_dirty_count) {
		TAILQ_FOREACH(node, &memorystatus_list, link) {
			if ((node->state & kProcessSupportsIdleExit) && !(node->state & (kProcessDirty|kProcessIgnoreIdleExit))) {				
				if (current_time >= node->clean_time) {
					victim_pid = node->pid;
					break;
				}
			}
		}
	}

	lck_mtx_unlock(memorystatus_list_mlock);
	
	if (-1 != victim_pid) {		
		proc_t p = proc_find(victim_pid);
		if (p != NULL) {
			boolean_t kill = FALSE;
			proc_dirty_start(p);
			/* Ensure process is still marked for idle exit and is clean */
			if ((p->p_dirty & (P_DIRTY_ALLOW_IDLE_EXIT|P_DIRTY_IS_DIRTY|P_DIRTY_TERMINATED)) == (P_DIRTY_ALLOW_IDLE_EXIT)) {
				/* Clean; issue SIGKILL */
				p->p_dirty |= P_DIRTY_TERMINATED;
				kill = TRUE;
			}
			proc_dirty_end(p);
			if (TRUE == kill) {
				printf("memorystatus_thread: idle exiting pid %d [%s]\n", victim_pid, (p->p_comm ? p->p_comm : "(unknown)"));
				psignal(p, SIGKILL);
			}
			proc_rele(p);
		}
	}

 	assert_wait(&memorystatus_wakeup, THREAD_UNINT);
	(void)thread_block((thread_continue_t)memorystatus_thread);
}

#if CONFIG_JETSAM

static uint32_t
memorystatus_task_page_count(task_t task)
{
	kern_return_t ret;
	static task_info_data_t data;
	static struct task_basic_info *info = (struct task_basic_info *)&data;
	static mach_msg_type_number_t count = TASK_BASIC_INFO_COUNT;

	ret = task_info(task, TASK_BASIC_INFO, (task_info_t)&data, &count);
	if (ret == KERN_SUCCESS) {
		return info->resident_size / PAGE_SIZE;
	}
	return 0;
}

static int
memorystatus_send_note(int event_code, void *data, size_t data_length) {
	int ret;
	struct kev_msg ev_msg;
	
	ev_msg.vendor_code    = KEV_VENDOR_APPLE;
	ev_msg.kev_class      = KEV_SYSTEM_CLASS;
	ev_msg.kev_subclass   = KEV_MEMORYSTATUS_SUBCLASS;

	ev_msg.event_code     = event_code;

	ev_msg.dv[0].data_length = data_length;
	ev_msg.dv[0].data_ptr = data;
	ev_msg.dv[1].data_length = 0;

	ret = kev_post_msg(&ev_msg);
	if (ret) {
		memorystatus_kev_failure_count++;
		printf("%s: kev_post_msg() failed, err %d\n", __func__, ret);
	}
	
    return ret;
}

static uint32_t
memorystatus_build_flags_from_state(uint32_t state) {
    uint32_t flags = 0;
    
    if (state & kProcessForeground) {
        flags |= kMemorystatusFlagsFrontmost;
    }
    if (state & kProcessActive) {
        flags |= kMemorystatusFlagsActive;
    }
    if (state & kProcessSupportsIdleExit) {
        flags |= kMemorystatusFlagsSupportsIdleExit;
    }
    if (state & kProcessDirty) {
        flags |= kMemorystatusFlagsDirty;
    }
    
    return flags;
}

static void 
memorystatus_move_node_to_exit_list(memorystatus_node *node) 
{
	/* Make sure we're called with the list lock held */
	lck_mtx_assert(memorystatus_list_mlock, LCK_MTX_ASSERT_OWNED);
    
	/* Now, acquire the exit list lock... */
	lck_mtx_lock(exit_list_mlock);
	
	/* Remove from list + update accounting... */
	memorystatus_remove_node(node);
	
	/* ...then insert at the end of the exit queue */
	TAILQ_INSERT_TAIL(&exit_list, node, link);
	
	/* And relax */
	lck_mtx_unlock(exit_list_mlock);
}

void memorystatus_update(unsigned int pages_avail)
{        
	if (!memorystatus_delta) {
	    return;
	}
	    	      
	if ((pages_avail < memorystatus_available_pages_critical) ||
	     (pages_avail >= (memorystatus_available_pages + memorystatus_delta)) ||
	     (memorystatus_available_pages >= (pages_avail + memorystatus_delta))) {
		memorystatus_available_pages = pages_avail;
		memorystatus_level = memorystatus_available_pages * 100 / atop_64(max_mem);
		/* Only wake the thread if currently blocked */
		if (OSCompareAndSwap(0, 1, &memorystatus_jetsam_running)) {
			thread_wakeup((event_t)&memorystatus_jetsam_wakeup);
		}
	}
}

static boolean_t
memorystatus_get_snapshot_properties_for_proc_locked(proc_t p, memorystatus_jetsam_snapshot_entry_t *entry)
{	
	memorystatus_node *node;
    
	TAILQ_FOREACH(node, &memorystatus_list, link) {
		if (node->pid == p->p_pid) {
			break;
		}
	}
	
	if (!node) {
		return FALSE;
	}
	
	entry->pid = p->p_pid;
	strlcpy(&entry->name[0], p->p_comm, MAXCOMLEN+1);
	entry->priority = node->priority;
	entry->pages = memorystatus_task_page_count(p->task);
	entry->flags = memorystatus_build_flags_from_state(node->state);
	memcpy(&entry->uuid[0], &p->p_uuid[0], sizeof(p->p_uuid));

	return TRUE;	
}

static void
memorystatus_jetsam_snapshot_procs_locked(void)
{
	proc_t p;
	int i = 0;

	memorystatus_jetsam_snapshot.stats.free_pages = vm_page_free_count;
	memorystatus_jetsam_snapshot.stats.active_pages = vm_page_active_count;
	memorystatus_jetsam_snapshot.stats.inactive_pages = vm_page_inactive_count;
	memorystatus_jetsam_snapshot.stats.throttled_pages = vm_page_throttled_count;
	memorystatus_jetsam_snapshot.stats.purgeable_pages = vm_page_purgeable_count;
	memorystatus_jetsam_snapshot.stats.wired_pages = vm_page_wire_count;
	proc_list_lock();
	LIST_FOREACH(p, &allproc, p_list) {
		if (FALSE == memorystatus_get_snapshot_properties_for_proc_locked(p, &memorystatus_jetsam_snapshot_list[i])) {
			continue;
		}
		
		MEMORYSTATUS_DEBUG(0, "jetsam snapshot pid = %d, uuid = %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			p->p_pid, 
			p->p_uuid[0], p->p_uuid[1], p->p_uuid[2], p->p_uuid[3], p->p_uuid[4], p->p_uuid[5], p->p_uuid[6], p->p_uuid[7],
			p->p_uuid[8], p->p_uuid[9], p->p_uuid[10], p->p_uuid[11], p->p_uuid[12], p->p_uuid[13], p->p_uuid[14], p->p_uuid[15]);

		if (++i == kMaxSnapshotEntries) {
			break;
		} 	
	}
	proc_list_unlock();	
	memorystatus_jetsam_snapshot.snapshot_time = mach_absolute_time();
	memorystatus_jetsam_snapshot.entry_count = memorystatus_jetsam_snapshot_list_count = i - 1;
}

static void
memorystatus_mark_pid_in_snapshot(pid_t pid, int flags)
{
	int i = 0;

	for (i = 0; i < memorystatus_jetsam_snapshot_list_count; i++) {
		if (memorystatus_jetsam_snapshot_list[i].pid == pid) {
			memorystatus_jetsam_snapshot_list[i].flags |= flags;
			return;
		}
	}
}

int
memorystatus_kill_top_proc(boolean_t any, uint32_t cause)
{
	proc_t p;
	int pending_snapshot = 0;

#ifndef CONFIG_FREEZE
#pragma unused(any)
#endif
	
	lck_mtx_lock(memorystatus_list_mlock);

	if (memorystatus_jetsam_snapshot_list_count == 0) {
		memorystatus_jetsam_snapshot_procs_locked();
	} else {
		pending_snapshot = 1;
	}

	while (next_memorystatus_node) {
		memorystatus_node *node;
		pid_t aPid;
#if DEVELOPMENT || DEBUG
		int activeProcess;
		int procSuspendedForDiagnosis;
#endif /* DEVELOPMENT || DEBUG */

		node = next_memorystatus_node;
		next_memorystatus_node = TAILQ_NEXT(next_memorystatus_node, link);

#if DEVELOPMENT || DEBUG
		activeProcess = node->state & kProcessForeground;
		procSuspendedForDiagnosis = node->state & kProcessSuspendedForDiag;
#endif /* DEVELOPMENT || DEBUG */
		
		aPid = node->pid;

		/* skip empty slots in the list */
		if (aPid == 0  || (node->state & kProcessKilled)) {
			continue; // with lock held
		}

		p = proc_find(aPid);
		if (p != NULL) {
			int flags = cause;
			
#if DEVELOPMENT || DEBUG
			if ((memorystatus_jetsam_policy & kPolicyDiagnoseActive) && procSuspendedForDiagnosis) {
				printf("jetsam: continuing after ignoring proc suspended already for diagnosis - %d\n", aPid);
				proc_rele(p);
				continue;
			}
#endif /* DEVELOPMENT || DEBUG */

#if CONFIG_FREEZE
			boolean_t skip;
			boolean_t reclaim_proc = !(node->state & (kProcessLocked | kProcessNoReclaimWorth));
			if (any || reclaim_proc) {
				if (node->state & kProcessFrozen) {
					flags |= kMemorystatusFlagsFrozen;
				}
				skip = FALSE;
			} else {
				skip = TRUE;
			}
			
			if (skip) {
				proc_rele(p);			
			} else
#endif
			{
#if DEVELOPMENT || DEBUG
				if ((memorystatus_jetsam_policy & kPolicyDiagnoseActive) && activeProcess) {
					MEMORYSTATUS_DEBUG(1, "jetsam: suspending pid %d [%s] (active) for diagnosis - memory_status_level: %d\n",
						aPid, (p->p_comm ? p->p_comm: "(unknown)"), memorystatus_level);
					memorystatus_mark_pid_in_snapshot(aPid, kMemorystatusFlagsSuspForDiagnosis);
					node->state |= kProcessSuspendedForDiag;
					if (memorystatus_jetsam_policy & kPolicyDiagnoseFirst) {
						jetsam_diagnostic_suspended_one_active_proc = 1;
						printf("jetsam: returning after suspending first active proc - %d\n", aPid);
					}
					lck_mtx_unlock(memorystatus_list_mlock);
					task_suspend(p->task);
					proc_rele(p);
					return 0;
				} else
#endif /* DEVELOPMENT || DEBUG */
				{
					printf("memorystatus: jetsam killing pid %d [%s] - memorystatus_available_pages: %d\n", 
						aPid, (p->p_comm ? p->p_comm : "(unknown)"), memorystatus_available_pages);
					/* Shift queue, update stats */
					memorystatus_move_node_to_exit_list(node);
					memorystatus_mark_pid_in_snapshot(aPid, flags);
					lck_mtx_unlock(memorystatus_list_mlock);
					exit1_internal(p, W_EXITCODE(0, SIGKILL), (int *)NULL, FALSE, FALSE);
					proc_rele(p);
					return 0;
				}
			}
		}
	}
	
	lck_mtx_unlock(memorystatus_list_mlock);
	
	// If we didn't kill anything, toss any newly-created snapshot
	if (!pending_snapshot) {
	    memorystatus_jetsam_snapshot.entry_count = memorystatus_jetsam_snapshot_list_count = 0;
	}
	
	return -1;
}

int memorystatus_kill_top_proc_from_VM(void) {
	return memorystatus_kill_top_proc(TRUE, kMemorystatusFlagsKilledVM);
}

static int
memorystatus_kill_hiwat_proc(void)
{
	proc_t p;
	int pending_snapshot = 0;
	memorystatus_node *next_hiwat_node;
	
	lck_mtx_lock(memorystatus_list_mlock);
	
	if (memorystatus_jetsam_snapshot_list_count == 0) {
		memorystatus_jetsam_snapshot_procs_locked();
	} else {
		pending_snapshot = 1;
	}
	
	next_hiwat_node = next_memorystatus_node;
	
	while (next_hiwat_node) {
		pid_t aPid;
		int32_t hiwat;
		memorystatus_node *node;
        
		node = next_hiwat_node;
		next_hiwat_node = TAILQ_NEXT(next_hiwat_node, link);
		
		aPid = node->pid;
		hiwat = node->hiwat_pages;
		
		/* skip empty or non-hiwat slots in the list */
		if (aPid == 0 || (hiwat < 0) || (node->state & kProcessKilled)) {
			continue; // with lock held
		}
		
		p = proc_find(aPid);
		if (p != NULL) {
			int32_t pages = (int32_t)memorystatus_task_page_count(p->task);
			boolean_t skip = (pages <= hiwat);
#if DEVELOPMENT || DEBUG
			if (!skip && (memorystatus_jetsam_policy & kPolicyDiagnoseActive)) {
				if (node->state & kProcessSuspendedForDiag) {
					proc_rele(p);
					continue;
				}
			}
#endif /* DEVELOPMENT || DEBUG */

#if CONFIG_FREEZE
			if (!skip) {
				if (node->state & kProcessLocked) {
					skip = TRUE;
				} else {
					skip = FALSE;
				}				
			}
#endif

			if (!skip) {
				MEMORYSTATUS_DEBUG(1, "jetsam: %s pid %d [%s] - %d pages > 1 (%d)\n",
					(memorystatus_jetsam_policy & kPolicyDiagnoseActive) ? "suspending": "killing", aPid, p->p_comm, pages, hiwat);
#if DEVELOPMENT || DEBUG
				if (memorystatus_jetsam_policy & kPolicyDiagnoseActive) {
				    memorystatus_mark_pid_in_snapshot(aPid, kMemorystatusFlagsSuspForDiagnosis);
					node->state |= kProcessSuspendedForDiag;
					lck_mtx_unlock(memorystatus_list_mlock);
					task_suspend(p->task);
					proc_rele(p);
					MEMORYSTATUS_DEBUG(1, "jetsam: pid %d suspended for diagnosis - memorystatus_available_pages: %d\n", aPid, memorystatus_available_pages);
				} else
#endif /* DEVELOPMENT || DEBUG */
				{	
					printf("memorystatus: jetsam killing pid %d [%s] (highwater) - memorystatus_available_pages: %d\n", 
						aPid, (p->p_comm ? p->p_comm : "(unknown)"), memorystatus_available_pages);
					/* Shift queue, update stats */
					memorystatus_move_node_to_exit_list(node);
					memorystatus_mark_pid_in_snapshot(aPid, kMemorystatusFlagsKilledHiwat);
					lck_mtx_unlock(memorystatus_list_mlock);		    
					exit1(p, W_EXITCODE(0, SIGKILL), (int *)NULL);
					proc_rele(p);
				}
				return 0;
			} else {
				proc_rele(p);
			}

		}
	}
	
	lck_mtx_unlock(memorystatus_list_mlock);
	
	// If we didn't kill anything, toss any newly-created snapshot
	if (!pending_snapshot) {
		memorystatus_jetsam_snapshot.entry_count = memorystatus_jetsam_snapshot_list_count = 0;
	}
	
	return -1;
}

static void
memorystatus_jetsam_thread_block(void)
{
 	assert_wait(&memorystatus_jetsam_wakeup, THREAD_UNINT);
	assert(memorystatus_jetsam_running == 1);
	OSDecrementAtomic(&memorystatus_jetsam_running);
	(void)thread_block((thread_continue_t)memorystatus_jetsam_thread);   
}

static void
memorystatus_jetsam_thread(void *param __unused, wait_result_t wr __unused)
{
	boolean_t post_snapshot = FALSE; 
	static boolean_t is_vm_privileged = FALSE;

	if (is_vm_privileged == FALSE) {
		/* 
		 * It's the first time the thread has run, so just mark the thread as privileged and block.
		 * This avoids a spurious pass with unset variables, as set out in <rdar://problem/9609402>.
		 */
		thread_wire(host_priv_self(), current_thread(), TRUE);
		is_vm_privileged = TRUE;
		memorystatus_jetsam_thread_block();
	}
	
	assert(memorystatus_available_pages != (unsigned)-1);
	
	while(1) {
		unsigned int last_available_pages;

#if DEVELOPMENT || DEBUG
		jetsam_diagnostic_suspended_one_active_proc = 0;
#endif /* DEVELOPMENT || DEBUG */
	    
		while (memorystatus_available_pages <= memorystatus_available_pages_highwater) {
			if (memorystatus_kill_hiwat_proc() < 0) {
				break;
			}
			post_snapshot = TRUE;
		}

		while (memorystatus_available_pages <= memorystatus_available_pages_critical) {
			if (memorystatus_kill_top_proc(FALSE, kMemorystatusFlagsKilled) < 0) {
				/* No victim was found - panic */
				panic("memorystatus_jetsam_thread: no victim! available pages:%d, critical page level: %d\n",
                                        memorystatus_available_pages, memorystatus_available_pages_critical);
			}
			post_snapshot = TRUE;
#if DEVELOPMENT || DEBUG
			if ((memorystatus_jetsam_policy & kPolicyDiagnoseFirst) && jetsam_diagnostic_suspended_one_active_proc) {
				printf("jetsam: stopping killing since 1 active proc suspended already for diagnosis\n");
				break; // we found first active proc, let's not kill any more
			}
#endif /* DEVELOPMENT || DEBUG */
		}
		
		last_available_pages = memorystatus_available_pages;

		if (post_snapshot) {
			size_t snapshot_size = sizeof(memorystatus_jetsam_snapshot_t) + sizeof(memorystatus_jetsam_snapshot_entry_t) * (memorystatus_jetsam_snapshot_list_count - 1);
			memorystatus_jetsam_snapshot.notification_time = mach_absolute_time();
			memorystatus_send_note(kMemorystatusSnapshotNote, &snapshot_size, sizeof(snapshot_size));
		}

		if (memorystatus_available_pages >= (last_available_pages + memorystatus_delta) ||
		    last_available_pages >= (memorystatus_available_pages + memorystatus_delta)) {
			continue;
		}

#if VM_PRESSURE_EVENTS
		memorystatus_check_pressure_reset();
#endif

		memorystatus_jetsam_thread_block();
	}
}

#endif /* CONFIG_JETSAM */

#if CONFIG_FREEZE

__private_extern__ void
memorystatus_freeze_init(void)
{
	kern_return_t result;
	thread_t thread;
	
	result = kernel_thread_start(memorystatus_freeze_thread, NULL, &thread);
	if (result == KERN_SUCCESS) {
		thread_deallocate(thread);
	} else {
		panic("Could not create memorystatus_freeze_thread");
	}
}

static int
memorystatus_freeze_top_proc(boolean_t *memorystatus_freeze_swap_low)
{
	proc_t p;
	uint32_t i;
	memorystatus_node *next_freeze_node;

	lck_mtx_lock(memorystatus_list_mlock);
	
	next_freeze_node = next_memorystatus_node;
	
	while (next_freeze_node) {
		memorystatus_node *node;
		pid_t aPid;
		uint32_t state;
		
		node = next_freeze_node;
		next_freeze_node = TAILQ_NEXT(next_freeze_node, link);

		aPid = node->pid;
		state = node->state;

		/* skip empty slots in the list */
		if (aPid == 0) {
			continue; // with lock held
		}

		/* Ensure the process is eligible for freezing */
		if ((state & (kProcessKilled | kProcessLocked | kProcessFrozen)) || !(state & kProcessSuspended)) {
			continue; // with lock held
		}

		p = proc_find(aPid);
		if (p != NULL) {
			kern_return_t kr;
			uint32_t purgeable, wired, clean, dirty;
			boolean_t shared;
			uint32_t max_pages = 0;
					
			/* Only freeze processes meeting our minimum resident page criteria */
			if (memorystatus_task_page_count(p->task) < memorystatus_freeze_pages_min) {
				proc_rele(p);
				continue;
			} 

			/* Ensure there's enough free space to freeze this process. */			
			max_pages = MIN(default_pager_swap_pages_free(), memorystatus_freeze_pages_max);
			if (max_pages < memorystatus_freeze_pages_min) {
				*memorystatus_freeze_swap_low = TRUE;
				proc_rele(p);
				lck_mtx_unlock(memorystatus_list_mlock);
				return 0;
			}
			
			/* Mark as locked temporarily to avoid kill */
			node->state |= kProcessLocked;
			
			kr = task_freeze(p->task, &purgeable, &wired, &clean, &dirty, max_pages, &shared, FALSE);
			
			MEMORYSTATUS_DEBUG(1, "memorystatus_freeze_top_proc: task_freeze %s for pid %d [%s] - "
     			"memorystatus_pages: %d, purgeable: %d, wired: %d, clean: %d, dirty: %d, shared %d, free swap: %d\n", 
        		(kr == KERN_SUCCESS) ? "SUCCEEDED" : "FAILED", aPid, (p->p_comm ? p->p_comm : "(unknown)"), 
        		memorystatus_available_pages, purgeable, wired, clean, dirty, shared, default_pager_swap_pages_free());
        		
			proc_rele(p);
     		
			node->state &= ~kProcessLocked;
			
			if (KERN_SUCCESS == kr) {
				memorystatus_freeze_entry_t data = { aPid, kMemorystatusFlagsFrozen, dirty };
				
				memorystatus_frozen_count++;
				
				node->state |= (kProcessFrozen | (shared ? 0: kProcessNoReclaimWorth));
			
				/* Update stats */
				for (i = 0; i < sizeof(throttle_intervals) / sizeof(struct throttle_interval_t); i++) {
        			throttle_intervals[i].pageouts += dirty;
				}
			
				memorystatus_freeze_pageouts += dirty;
				memorystatus_freeze_count++;

				lck_mtx_unlock(memorystatus_list_mlock);

				memorystatus_send_note(kMemorystatusFreezeNote, &data, sizeof(data));

				return dirty;
			}
        		
			/* Failed; go round again */
		}
	}
	
	lck_mtx_unlock(memorystatus_list_mlock);
	
	return -1;
}

static inline boolean_t 
memorystatus_can_freeze_processes(void) 
{
	boolean_t ret;
	
	lck_mtx_lock(memorystatus_list_mlock);
	
	if (memorystatus_suspended_count) {
		uint32_t average_resident_pages, estimated_processes;
        
		/* Estimate the number of suspended processes we can fit */
		average_resident_pages = memorystatus_suspended_resident_count / memorystatus_suspended_count;
		estimated_processes = memorystatus_suspended_count +
			((memorystatus_available_pages - memorystatus_available_pages_critical) / average_resident_pages);

		/* If it's predicted that no freeze will occur, lower the threshold temporarily */
		if (estimated_processes <= FREEZE_SUSPENDED_THRESHOLD_DEFAULT) {
			memorystatus_freeze_suspended_threshold = FREEZE_SUSPENDED_THRESHOLD_LOW;
		} else {
			memorystatus_freeze_suspended_threshold = FREEZE_SUSPENDED_THRESHOLD_DEFAULT;        
		}

		MEMORYSTATUS_DEBUG(1, "memorystatus_can_freeze_processes: %d suspended processes, %d average resident pages / process, %d suspended processes estimated\n", 
			memorystatus_suspended_count, average_resident_pages, estimated_processes);
	
		if ((memorystatus_suspended_count - memorystatus_frozen_count) > memorystatus_freeze_suspended_threshold) {
			ret = TRUE;
		} else {
			ret = FALSE;
		}
	} else {
		ret = FALSE;
	}
				
	lck_mtx_unlock(memorystatus_list_mlock);
	
	return ret;
}

static boolean_t 
memorystatus_can_freeze(boolean_t *memorystatus_freeze_swap_low)
{
	/* Only freeze if we're sufficiently low on memory; this holds off freeze right
	   after boot,  and is generally is a no-op once we've reached steady state. */
	if (memorystatus_available_pages > memorystatus_freeze_threshold) {
		return FALSE;
	}
	
	/* Check minimum suspended process threshold. */
	if (!memorystatus_can_freeze_processes()) {
		return FALSE;
	}

	/* Is swap running low? */
	if (*memorystatus_freeze_swap_low) {
		/* If there's been no movement in free swap pages since we last attempted freeze, return. */
		if (default_pager_swap_pages_free() < memorystatus_freeze_pages_min) {
			return FALSE;
		}
		
		/* Pages have been freed - we can retry. */
		*memorystatus_freeze_swap_low = FALSE;	
	}
	
	/* OK */
	return TRUE;
}

static void
memorystatus_freeze_update_throttle_interval(mach_timespec_t *ts, struct throttle_interval_t *interval)
{
	if (CMP_MACH_TIMESPEC(ts, &interval->ts) >= 0) {
		if (!interval->max_pageouts) {
			interval->max_pageouts = (interval->burst_multiple * (((uint64_t)interval->mins * FREEZE_DAILY_PAGEOUTS_MAX) / (24 * 60)));
		} else {
			printf("memorystatus_freeze_update_throttle_interval: %d minute throttle timeout, resetting\n", interval->mins);
		}
		interval->ts.tv_sec = interval->mins * 60;
		interval->ts.tv_nsec = 0;
		ADD_MACH_TIMESPEC(&interval->ts, ts);
		/* Since we update the throttle stats pre-freeze, adjust for overshoot here */
		if (interval->pageouts > interval->max_pageouts) {
			interval->pageouts -= interval->max_pageouts;
		} else {
			interval->pageouts = 0;
		}
		interval->throttle = FALSE;
	} else if (!interval->throttle && interval->pageouts >= interval->max_pageouts) {
		printf("memorystatus_freeze_update_throttle_interval: %d minute pageout limit exceeded; enabling throttle\n", interval->mins);
		interval->throttle = TRUE;
	}	

	MEMORYSTATUS_DEBUG(1, "memorystatus_freeze_update_throttle_interval: throttle updated - %d frozen (%d max) within %dm; %dm remaining; throttle %s\n", 
		interval->pageouts, interval->max_pageouts, interval->mins, (interval->ts.tv_sec - ts->tv_sec) / 60, 
		interval->throttle ? "on" : "off");
}

static boolean_t
memorystatus_freeze_update_throttle(void) 
{
	clock_sec_t sec;
	clock_nsec_t nsec;
	mach_timespec_t ts;
	uint32_t i;
	boolean_t throttled = FALSE;

#if DEVELOPMENT || DEBUG
	if (!memorystatus_freeze_throttle_enabled)
		return FALSE;
#endif

	clock_get_system_nanotime(&sec, &nsec);
	ts.tv_sec = sec;
	ts.tv_nsec = nsec;
	
	/* Check freeze pageouts over multiple intervals and throttle if we've exceeded our budget.
	 *
	 * This ensures that periods of inactivity can't be used as 'credit' towards freeze if the device has
	 * remained dormant for a long period. We do, however, allow increased thresholds for shorter intervals in
	 * order to allow for bursts of activity.
	 */
	for (i = 0; i < sizeof(throttle_intervals) / sizeof(struct throttle_interval_t); i++) {
		memorystatus_freeze_update_throttle_interval(&ts, &throttle_intervals[i]);
		if (throttle_intervals[i].throttle == TRUE)
			throttled = TRUE;
	}								

	return throttled;
}

static void
memorystatus_freeze_thread(void *param __unused, wait_result_t wr __unused)
{
	static boolean_t memorystatus_freeze_swap_low = FALSE;
	
	if (memorystatus_freeze_enabled) {
		if (memorystatus_can_freeze(&memorystatus_freeze_swap_low)) {
			/* Only freeze if we've not exceeded our pageout budgets */
			if (!memorystatus_freeze_update_throttle()) {
				memorystatus_freeze_top_proc(&memorystatus_freeze_swap_low);
			} else {
				printf("memorystatus_freeze_thread: in throttle, ignoring freeze\n");
				memorystatus_freeze_throttle_count++; /* Throttled, update stats */
			}
		}
	}

	assert_wait((event_t) &memorystatus_freeze_wakeup, THREAD_UNINT);
	thread_block((thread_continue_t) memorystatus_freeze_thread);	
}

#endif /* CONFIG_FREEZE */

#if CONFIG_JETSAM

#if VM_PRESSURE_EVENTS

static inline boolean_t
memorystatus_get_pressure_locked(void) {
	if (memorystatus_available_pages > memorystatus_available_pages_pressure) {
                /* Too many free pages */
                return kVMPressureNormal;
	}
	
#if CONFIG_FREEZE
	if (memorystatus_frozen_count > 0) {
                /* Frozen processes exist */
                return kVMPressureNormal;	        
	}
#endif

	if (memorystatus_suspended_count > MEMORYSTATUS_SUSPENDED_THRESHOLD) {
	        /* Too many supended processes */
		return kVMPressureNormal;
	}
	
	if (memorystatus_suspended_count > 0) {
	        /* Some suspended processes - warn */
		return kVMPressureWarning;
	}
    
	/* Otherwise, pressure level is urgent */
	return kVMPressureUrgent;
}

pid_t
memorystatus_request_vm_pressure_candidate(void) {
	memorystatus_node *node;
	pid_t pid = -1;

	lck_mtx_lock(memorystatus_list_mlock);

	/* Are we in a low memory state? */
	memorystatus_vm_pressure_level = memorystatus_get_pressure_locked();
	if (kVMPressureNormal != memorystatus_vm_pressure_level) {
		TAILQ_FOREACH(node, &memorystatus_list, link) {
			/* Skip ineligible processes */
			if (node->state & (kProcessKilled | kProcessLocked | kProcessSuspended | kProcessFrozen | kProcessNotifiedForPressure)) {
				continue;
			}
			node->state |= kProcessNotifiedForPressure;
			pid = node->pid;
			break;
		}
	}
    
	lck_mtx_unlock(memorystatus_list_mlock);

	return pid;
}

void
memorystatus_send_pressure_note(pid_t pid) {
    memorystatus_send_note(kMemorystatusPressureNote, &pid, sizeof(pid));
}

static void
memorystatus_check_pressure_reset() {        
	lck_mtx_lock(memorystatus_list_mlock);
	
	if (kVMPressureNormal != memorystatus_vm_pressure_level) {
		memorystatus_vm_pressure_level = memorystatus_get_pressure_locked();
		if (kVMPressureNormal == memorystatus_vm_pressure_level) {
			memorystatus_node *node;
			TAILQ_FOREACH(node, &memorystatus_list, link) {
				node->state &= ~kProcessNotifiedForPressure;
			}
		}
	}
    
	lck_mtx_unlock(memorystatus_list_mlock);
}

#endif /* VM_PRESSURE_EVENTS */

/* Sysctls... */

static int
sysctl_memorystatus_list_change SYSCTL_HANDLER_ARGS
{
	int ret;
	memorystatus_priority_entry_t entry;

#pragma unused(oidp, arg1, arg2)

	if (!req->newptr || req->newlen > sizeof(entry)) {
		return EINVAL;
	}

	ret = SYSCTL_IN(req, &entry, req->newlen);
	if (ret) {
		return ret;
	}

	memorystatus_list_change(FALSE, entry.pid, entry.priority, entry.flags, -1);

	return ret;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_jetsam_change, CTLTYPE_INT|CTLFLAG_WR|CTLFLAG_LOCKED|CTLFLAG_MASKED,
    0, 0, &sysctl_memorystatus_list_change, "I", "");
    
static int
sysctl_memorystatus_priority_list(__unused struct sysctl_oid *oid, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int ret;
	size_t allocated_size, list_size = 0;
 	memorystatus_priority_entry_t *list;
 	uint32_t list_count, i = 0;
 	memorystatus_node *node;
        
 	/* Races, but this is only for diagnostic purposes */
 	list_count = memorystatus_list_count;
	allocated_size = sizeof(memorystatus_priority_entry_t) * list_count;
 	list = kalloc(allocated_size);
	if (!list) {
		return ENOMEM;
	}

	memset(list, 0, allocated_size);
        
	lck_mtx_lock(memorystatus_list_mlock);

	TAILQ_FOREACH(node, &memorystatus_list, link) {
		list[i].pid = node->pid;
		list[i].priority = node->priority; 
		list[i].flags = memorystatus_build_flags_from_state(node->state);
		list[i].hiwat_pages = node->hiwat_pages;
		list_size += sizeof(memorystatus_priority_entry_t);
		if (++i >= list_count) {
			break;
		}       
	}
	
	lck_mtx_unlock(memorystatus_list_mlock);
	
	if (!list_size) {
		if (req->oldptr) {
			MEMORYSTATUS_DEBUG(1, "kern.memorystatus_priority_list returning EINVAL\n");
			return EINVAL;
		}
		else {
			MEMORYSTATUS_DEBUG(1, "kern.memorystatus_priority_list returning 0 for size\n");
		}
	} else {
		MEMORYSTATUS_DEBUG(1, "kern.memorystatus_priority_list returning %ld for size\n", (long)list_size);
	}
	
	ret = SYSCTL_OUT(req, list, list_size);

	kfree(list, allocated_size);
	
	return ret;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_priority_list, CTLTYPE_OPAQUE|CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0, sysctl_memorystatus_priority_list, "S,jetsam_priorities", "");

static void
memorystatus_update_levels_locked(void) {
	/* Set the baseline levels in pages */
	memorystatus_available_pages_critical = (CRITICAL_PERCENT / DELTA_PERCENT) * memorystatus_delta;
	memorystatus_available_pages_highwater = (HIGHWATER_PERCENT / DELTA_PERCENT) * memorystatus_delta;
#if VM_PRESSURE_EVENTS
	memorystatus_available_pages_pressure = (PRESSURE_PERCENT / DELTA_PERCENT) * memorystatus_delta;
#endif
	
#if DEBUG || DEVELOPMENT
	if (memorystatus_jetsam_policy & kPolicyDiagnoseActive) {
		memorystatus_available_pages_critical += memorystatus_jetsam_policy_offset_pages_diagnostic;
		memorystatus_available_pages_highwater += memorystatus_jetsam_policy_offset_pages_diagnostic;
#if VM_PRESSURE_EVENTS
		memorystatus_available_pages_pressure += memorystatus_jetsam_policy_offset_pages_diagnostic;
#endif
	}
#endif
	
	/* Only boost the critical level - it's more important to kill right away than issue warnings */
	if (memorystatus_jetsam_policy & kPolicyMoreFree) {
		memorystatus_available_pages_critical += memorystatus_jetsam_policy_offset_pages_more_free;
	}
}

static int
sysctl_memorystatus_jetsam_policy_more_free SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	int error, more_free = 0;

	error = priv_check_cred(kauth_cred_get(), PRIV_VM_JETSAM, 0);
	if (error)
		return (error);

	error = sysctl_handle_int(oidp, &more_free, 0, req);
	if (error || !req->newptr)
		return (error);

	lck_mtx_lock(memorystatus_list_mlock);
	
	if (more_free) {
		memorystatus_jetsam_policy |= kPolicyMoreFree;
	} else {
 		memorystatus_jetsam_policy &= ~kPolicyMoreFree;               
	}
        
	memorystatus_update_levels_locked();
		
	lck_mtx_unlock(memorystatus_list_mlock);
	
	return 0;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_jetsam_policy_more_free, CTLTYPE_INT|CTLFLAG_WR|CTLFLAG_LOCKED|CTLFLAG_MASKED|CTLFLAG_ANYBODY,
    0, 0, &sysctl_memorystatus_jetsam_policy_more_free, "I", "");

static int
sysctl_handle_memorystatus_snapshot(__unused struct sysctl_oid *oid, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int ret;
	size_t currentsize = 0;

	if (memorystatus_jetsam_snapshot_list_count > 0) {
		currentsize = sizeof(memorystatus_jetsam_snapshot_t) + sizeof(memorystatus_jetsam_snapshot_entry_t) * (memorystatus_jetsam_snapshot_list_count - 1);
	}
	if (!currentsize) {
		if (req->oldptr) {
			MEMORYSTATUS_DEBUG(1, "kern.memorystatus_snapshot returning EINVAL\n");
			return EINVAL;
		}
		else {
			MEMORYSTATUS_DEBUG(1, "kern.memorystatus_snapshot returning 0 for size\n");
		}
	} else {
		MEMORYSTATUS_DEBUG(1, "kern.memorystatus_snapshot returning %ld for size\n", (long)currentsize);
	}	
	ret = SYSCTL_OUT(req, &memorystatus_jetsam_snapshot, currentsize);
	if (!ret && req->oldptr) {
		memorystatus_jetsam_snapshot.entry_count = memorystatus_jetsam_snapshot_list_count = 0;
	}
	return ret;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_snapshot, CTLTYPE_OPAQUE|CTLFLAG_RD, 0, 0, sysctl_handle_memorystatus_snapshot, "S,memorystatus_snapshot", "");

#endif /* CONFIG_JETSAM */

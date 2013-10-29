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
#include <mach/host_priv.h>
#include <mach/mach_host.h>
#include <pexpert/pexpert.h>
#include <sys/kern_event.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <sys/signal.h>
#include <sys/signalvar.h>
#include <sys/sysctl.h>
#include <sys/sysproto.h>
#include <sys/wait.h>
#include <sys/tree.h>
#include <sys/priv.h>
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>

#if CONFIG_FREEZE
#include <vm/vm_map.h>
#endif /* CONFIG_FREEZE */

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

/* General tunables */

unsigned long delta_percentage = 5;
unsigned long critical_threshold_percentage = 5;
unsigned long idle_offset_percentage = 5;
unsigned long pressure_threshold_percentage = 15;
unsigned long freeze_threshold_percentage = 50;

/* General memorystatus stuff */

struct klist memorystatus_klist;
static lck_mtx_t memorystatus_klist_mutex;

static void memorystatus_klist_lock(void);
static void memorystatus_klist_unlock(void);

static uint64_t memorystatus_idle_delay_time = 0;

/*
 * Memorystatus kevents
 */

static int filt_memorystatusattach(struct knote *kn);
static void filt_memorystatusdetach(struct knote *kn);
static int filt_memorystatus(struct knote *kn, long hint);

struct filterops memorystatus_filtops = {
	.f_attach = filt_memorystatusattach,
	.f_detach = filt_memorystatusdetach,
	.f_event = filt_memorystatus,
};

enum {
	kMemorystatusNoPressure = 1,
	kMemorystatusPressure = 2
};

/* Idle guard handling */

static int32_t memorystatus_scheduled_idle_demotions = 0;

static thread_call_t memorystatus_idle_demotion_call;

static void memorystatus_perform_idle_demotion(__unused void *spare1, __unused void *spare2);
static void memorystatus_schedule_idle_demotion_locked(proc_t p, boolean_t set_state);
static void memorystatus_invalidate_idle_demotion_locked(proc_t p, boolean_t clean_state);
static void memorystatus_reschedule_idle_demotion_locked(void);

static void memorystatus_update_priority_locked(proc_t p, int priority);

int memorystatus_wakeup = 0;

unsigned int memorystatus_level = 0;

static int memorystatus_list_count = 0;

#define MEMSTAT_BUCKET_COUNT (JETSAM_PRIORITY_MAX + 1)

typedef struct memstat_bucket {
    TAILQ_HEAD(, proc) list;
    int count;
} memstat_bucket_t;

memstat_bucket_t memstat_bucket[MEMSTAT_BUCKET_COUNT];

uint64_t memstat_idle_demotion_deadline = 0;

static unsigned int memorystatus_dirty_count = 0;

#if !CONFIG_JETSAM
static boolean_t kill_idle_exit = FALSE;
#endif


int
memorystatus_get_level(__unused struct proc *p, struct memorystatus_get_level_args *args, __unused int *ret)
{
	user_addr_t	level = 0;
	
	level = args->level;
	
	if (copyout(&memorystatus_level, level, sizeof(memorystatus_level)) != 0) {
		return EFAULT;
	}
	
	return 0;
}

static proc_t memorystatus_get_first_proc_locked(unsigned int *bucket_index, boolean_t search);
static proc_t memorystatus_get_next_proc_locked(unsigned int *bucket_index, proc_t p, boolean_t search);

static void memorystatus_thread(void *param __unused, wait_result_t wr __unused);

/* Jetsam */

#if CONFIG_JETSAM

/* Kill processes exceeding their limit either under memory pressure (1), or as soon as possible (0) */
#define LEGACY_HIWATER 1

static int memorystatus_highwater_enabled = 1;

extern unsigned int    vm_page_free_count;
extern unsigned int    vm_page_active_count;
extern unsigned int    vm_page_inactive_count;
extern unsigned int    vm_page_throttled_count;
extern unsigned int    vm_page_purgeable_count;
extern unsigned int    vm_page_wire_count;

unsigned int memorystatus_delta = 0;

static unsigned int memorystatus_available_pages = (unsigned int)-1;
static unsigned int memorystatus_available_pages_pressure = 0;
static unsigned int memorystatus_available_pages_critical = 0;
static unsigned int memorystatus_available_pages_critical_base = 0;
static unsigned int memorystatus_last_foreground_pressure_pages = (unsigned int)-1;
#if !LATENCY_JETSAM
static unsigned int memorystatus_available_pages_critical_idle_offset = 0;
#endif

#if DEVELOPMENT || DEBUG
static unsigned int memorystatus_jetsam_panic_debug = 0;

static unsigned int memorystatus_jetsam_policy = kPolicyDefault;
static unsigned int memorystatus_jetsam_policy_offset_pages_diagnostic = 0;
#endif

static boolean_t kill_under_pressure = FALSE;

static memorystatus_jetsam_snapshot_t *memorystatus_jetsam_snapshot;
#define memorystatus_jetsam_snapshot_list memorystatus_jetsam_snapshot->entries

static unsigned int memorystatus_jetsam_snapshot_count = 0;
static unsigned int memorystatus_jetsam_snapshot_max = 0;

static void memorystatus_clear_errors(void);
static void memorystatus_get_task_page_counts(task_t task, uint32_t *footprint, uint32_t *max_footprint);
static int memorystatus_send_note(int event_code, void *data, size_t data_length);
static uint32_t memorystatus_build_state(proc_t p);
static void memorystatus_update_levels_locked(boolean_t critical_only);
static boolean_t memorystatus_issue_pressure_kevent(boolean_t pressured);

static boolean_t memorystatus_kill_specific_process(pid_t victim_pid, uint32_t cause);
static boolean_t memorystatus_kill_top_process(boolean_t any, uint32_t cause, int32_t *priority, uint32_t *errors);
#if LEGACY_HIWATER
static boolean_t memorystatus_kill_hiwat_proc(uint32_t *errors);
#endif

static boolean_t memorystatus_kill_process_async(pid_t victim_pid, uint32_t cause);
static boolean_t memorystatus_kill_process_sync(pid_t victim_pid, uint32_t cause);

#endif /* CONFIG_JETSAM */

/* VM pressure */

#if VM_PRESSURE_EVENTS

#include "vm_pressure.h"

extern boolean_t memorystatus_warn_process(pid_t pid);

vm_pressure_level_t memorystatus_vm_pressure_level = kVMPressureNormal;

#endif /* VM_PRESSURE_EVENTS */

/* Freeze */

#if CONFIG_FREEZE

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

static unsigned int memorystatus_suspended_count = 0;
static unsigned int memorystatus_suspended_footprint_total = 0;

#endif /* CONFIG_FREEZE */

/* Debug */

#if DEVELOPMENT || DEBUG

#if CONFIG_JETSAM

/* Debug aid to aid determination of limit */

static int
sysctl_memorystatus_highwater_enable SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2)
	proc_t p;
	unsigned int b = 0;
	int error, enable = 0;
	int32_t memlimit;

	error = SYSCTL_OUT(req, arg1, sizeof(int));
	if (error || !req->newptr) {
		return (error);
	}

	error = SYSCTL_IN(req, &enable, sizeof(int));
	if (error || !req->newptr) {
		return (error);
	}

	if (!(enable == 0 || enable == 1)) {
		return EINVAL;
	}

	proc_list_lock();

	p = memorystatus_get_first_proc_locked(&b, TRUE);
	while (p) {
		if (enable) {
			if ((p->p_memstat_state & P_MEMSTAT_MEMLIMIT_BACKGROUND) && (p->p_memstat_effectivepriority >= JETSAM_PRIORITY_FOREGROUND)) {          
				memlimit = -1;
			} else {
				memlimit = p->p_memstat_memlimit;                	        
			}
		} else {
			memlimit = -1;
		}
		task_set_phys_footprint_limit_internal(p->task, (memlimit  > 0) ? memlimit : -1, NULL, TRUE);
	        
		p = memorystatus_get_next_proc_locked(&b, p, TRUE);
	}
	
	memorystatus_highwater_enabled = enable;

	proc_list_unlock();

	return 0;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_highwater_enabled, CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_highwater_enabled, 0, sysctl_memorystatus_highwater_enable, "I", "");

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages, CTLFLAG_RD|CTLFLAG_LOCKED, &memorystatus_available_pages, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages_critical, CTLFLAG_RD|CTLFLAG_LOCKED, &memorystatus_available_pages_critical, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages_critical_base, CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_available_pages_critical_base, 0, "");
#if !LATENCY_JETSAM
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages_critical_idle_offset, CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_available_pages_critical_idle_offset, 0, "");
#endif

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
	
	proc_list_lock();
	
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
        	
		memorystatus_update_levels_locked(FALSE);
		changed = TRUE;
	}
        
	proc_list_unlock();
	
	if (changed) {
		printf("%s\n", diagnosticStrings[val]);
	}
	
	return (0);
}

SYSCTL_PROC(_debug, OID_AUTO, jetsam_diagnostic_mode, CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_LOCKED|CTLFLAG_ANYBODY,
  		&jetsam_diagnostic_mode, 0, sysctl_jetsam_diagnostic_mode, "I", "Jetsam Diagnostic Mode");

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_jetsam_policy_offset_pages_diagnostic, CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_jetsam_policy_offset_pages_diagnostic, 0, "");

#if VM_PRESSURE_EVENTS

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages_pressure, CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_available_pages_pressure, 0, "");

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

	return vm_dispatch_pressure_note_to_pid(pid, FALSE);
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_vm_pressure_send, CTLTYPE_INT|CTLFLAG_WR|CTLFLAG_LOCKED|CTLFLAG_MASKED,
    0, 0, &sysctl_memorystatus_vm_pressure_send, "I", "");

#endif /* VM_PRESSURE_EVENTS */

#endif /* CONFIG_JETSAM */

#endif /* DEVELOPMENT || DEBUG */

#if CONFIG_FREEZE

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_threshold, CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_freeze_threshold, 0, "");

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_pages_min, CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_freeze_pages_min, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_pages_max, CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_freeze_pages_max, 0, "");

SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freeze_count, CTLFLAG_RD|CTLFLAG_LOCKED, &memorystatus_freeze_count, "");
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freeze_pageouts, CTLFLAG_RD|CTLFLAG_LOCKED, &memorystatus_freeze_pageouts, "");
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freeze_throttle_count, CTLFLAG_RD|CTLFLAG_LOCKED, &memorystatus_freeze_throttle_count, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_min_processes, CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_freeze_suspended_threshold, 0, "");

boolean_t memorystatus_freeze_throttle_enabled = TRUE;
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_throttle_enabled, CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_freeze_throttle_enabled, 0, "");

/* 
 * Enabled via: <rdar://problem/13248767> Enable the sysctl_memorystatus_freeze/thaw sysctls on Release KC
 * 
 * TODO: Manual trigger of freeze and thaw for dev / debug kernels only.
 * <rdar://problem/13248795> Disable/restrict the sysctl_memorystatus_freeze/thaw sysctls on Release KC
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
		uint32_t max_pages = 0;

		if (DEFAULT_FREEZER_IS_ACTIVE || DEFAULT_FREEZER_COMPRESSED_PAGER_IS_ACTIVE) {
			max_pages = MIN(default_pager_swap_pages_free(), memorystatus_freeze_pages_max);
		} else {
			max_pages = UINT32_MAX - 1;
		}
		error = task_freeze(p->task, &purgeable, &wired, &clean, &dirty, max_pages, &shared, FALSE);
		proc_rele(p);

		if (error)
			error = EIO;
		return error;
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
		error = task_thaw(p->task);
		proc_rele(p);
		
		if (error)
			error = EIO;
		return error;
	}

	return EINVAL;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_thaw, CTLTYPE_INT|CTLFLAG_WR|CTLFLAG_LOCKED|CTLFLAG_MASKED,
    0, 0, &sysctl_memorystatus_available_pages_thaw, "I", "");

#endif /* CONFIG_FREEZE */

extern kern_return_t kernel_thread_start_priority(thread_continue_t continuation,
                                                  void *parameter,
                                                  integer_t priority,
                                                  thread_t *new_thread);

static proc_t memorystatus_get_first_proc_locked(unsigned int *bucket_index, boolean_t search) {
	memstat_bucket_t *current_bucket;
	proc_t next_p;

	if ((*bucket_index) >= MEMSTAT_BUCKET_COUNT) {
		return NULL;
	}

	current_bucket = &memstat_bucket[*bucket_index];
	next_p = TAILQ_FIRST(&current_bucket->list);
	if (!next_p && search) {
		while (!next_p && (++(*bucket_index) < MEMSTAT_BUCKET_COUNT)) {
			current_bucket = &memstat_bucket[*bucket_index];
			next_p = TAILQ_FIRST(&current_bucket->list);
		}
	}
	
	return next_p;
}

static proc_t memorystatus_get_next_proc_locked(unsigned int *bucket_index, proc_t p, boolean_t search) {
	memstat_bucket_t *current_bucket;
	proc_t next_p;
        
	if (!p || ((*bucket_index) >= MEMSTAT_BUCKET_COUNT)) {
		return NULL;
	}

	next_p = TAILQ_NEXT(p, p_memstat_list);
	while (!next_p && search && (++(*bucket_index) < MEMSTAT_BUCKET_COUNT)) {
		current_bucket = &memstat_bucket[*bucket_index];
		next_p = TAILQ_FIRST(&current_bucket->list);
	}

	return next_p;
}

__private_extern__ void
memorystatus_init(void)
{
	thread_t thread = THREAD_NULL;
	kern_return_t result;
	int i;

	nanoseconds_to_absolutetime((uint64_t)DEFERRED_IDLE_EXIT_TIME_SECS * NSEC_PER_SEC, &memorystatus_idle_delay_time);
	
	/* Init buckets */
	for (i = 0; i < MEMSTAT_BUCKET_COUNT; i++) {
		TAILQ_INIT(&memstat_bucket[i].list);
		memstat_bucket[i].count = 0;
	}
	
	memorystatus_idle_demotion_call = thread_call_allocate((thread_call_func_t)memorystatus_perform_idle_demotion, NULL);

	/* Apply overrides */
	PE_get_default("kern.jetsam_delta", &delta_percentage, sizeof(delta_percentage));
	assert(delta_percentage < 100);
	PE_get_default("kern.jetsam_critical_threshold", &critical_threshold_percentage, sizeof(critical_threshold_percentage));
	assert(critical_threshold_percentage < 100);
	PE_get_default("kern.jetsam_idle_offset", &idle_offset_percentage, sizeof(idle_offset_percentage));
	assert(idle_offset_percentage < 100);
	PE_get_default("kern.jetsam_pressure_threshold", &pressure_threshold_percentage, sizeof(pressure_threshold_percentage));
	assert(pressure_threshold_percentage < 100);
	PE_get_default("kern.jetsam_freeze_threshold", &freeze_threshold_percentage, sizeof(freeze_threshold_percentage));
	assert(freeze_threshold_percentage < 100);
	
#if CONFIG_JETSAM
	memorystatus_delta = delta_percentage * atop_64(max_mem) / 100;
#if !LATENCY_JETSAM
	memorystatus_available_pages_critical_idle_offset = idle_offset_percentage * atop_64(max_mem) / 100;
#endif

	memorystatus_available_pages_critical_base = (critical_threshold_percentage / delta_percentage) * memorystatus_delta;
	
	memorystatus_jetsam_snapshot_max = maxproc;
	memorystatus_jetsam_snapshot = 
		(memorystatus_jetsam_snapshot_t*)kalloc(sizeof(memorystatus_jetsam_snapshot_t) +
		sizeof(memorystatus_jetsam_snapshot_entry_t) * memorystatus_jetsam_snapshot_max);
	if (!memorystatus_jetsam_snapshot) {
		panic("Could not allocate memorystatus_jetsam_snapshot");
	}

	/* No contention at this point */
	memorystatus_update_levels_locked(FALSE);
#endif
	
#if CONFIG_FREEZE
	memorystatus_freeze_threshold = (freeze_threshold_percentage / delta_percentage) * memorystatus_delta;
#endif
	
	result = kernel_thread_start_priority(memorystatus_thread, NULL, 95 /* MAXPRI_KERNEL */, &thread);
	if (result == KERN_SUCCESS) {
		thread_deallocate(thread);
	} else {
		panic("Could not create memorystatus_thread");
	}
}

/* Centralised for the purposes of allowing panic-on-jetsam */
extern void
vm_wake_compactor_swapper(void);

static boolean_t
memorystatus_do_kill(proc_t p, uint32_t cause) {

	int retval = 0;

#if CONFIG_JETSAM && (DEVELOPMENT || DEBUG)
	if (memorystatus_jetsam_panic_debug & (1 << cause)) {
		panic("memorystatus_do_kill(): jetsam debug panic (cause: %d)", cause);
	}
#else
#pragma unused(cause)
#endif
	int jetsam_flags = P_LTERM_JETSAM;
	switch (cause) {
		case kMemorystatusKilledHiwat:			jetsam_flags |= P_JETSAM_HIWAT; break;
		case kMemorystatusKilledVnodes:			jetsam_flags |= P_JETSAM_VNODE; break;
		case kMemorystatusKilledVMPageShortage:		jetsam_flags |= P_JETSAM_VMPAGESHORTAGE; break;
		case kMemorystatusKilledVMThrashing:		jetsam_flags |= P_JETSAM_VMTHRASHING; break;
		case kMemorystatusKilledPerProcessLimit:	jetsam_flags |= P_JETSAM_PID; break;
		case kMemorystatusKilledIdleExit:		jetsam_flags |= P_JETSAM_IDLEEXIT; break;
	}
	retval = exit1_internal(p, W_EXITCODE(0, SIGKILL), (int *)NULL, FALSE, FALSE, jetsam_flags);

	if (COMPRESSED_PAGER_IS_ACTIVE || DEFAULT_FREEZER_COMPRESSED_PAGER_IS_ACTIVE) {
 		vm_wake_compactor_swapper();
 	}
	
	return (retval == 0);
}

/*
 * Node manipulation
 */

static void
memorystatus_check_levels_locked(void) {
#if CONFIG_JETSAM
	/* Update levels */
	memorystatus_update_levels_locked(TRUE);
#endif
}

static void
memorystatus_perform_idle_demotion(__unused void *spare1, __unused void *spare2) 
{
	proc_t p;
	uint64_t current_time;
	memstat_bucket_t *demotion_bucket;
   
	MEMORYSTATUS_DEBUG(1, "memorystatus_perform_idle_demotion()\n");
   
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_IDLE_DEMOTE) | DBG_FUNC_START, 0, 0, 0, 0, 0);
 
 	current_time = mach_absolute_time();
 
	proc_list_lock();

	demotion_bucket = &memstat_bucket[JETSAM_PRIORITY_IDLE_DEFERRED];
	p = TAILQ_FIRST(&demotion_bucket->list);
	    
	while (p) {
		MEMORYSTATUS_DEBUG(1, "memorystatus_perform_idle_demotion() found %d\n", p->p_pid);
	        
		assert(p->p_memstat_idledeadline);
		assert(p->p_memstat_dirty & P_DIRTY_DEFER_IN_PROGRESS);
		assert((p->p_memstat_dirty & (P_DIRTY_IDLE_EXIT_ENABLED|P_DIRTY_IS_DIRTY)) == P_DIRTY_IDLE_EXIT_ENABLED);
        
		if (current_time >= p->p_memstat_idledeadline) {
#if DEBUG || DEVELOPMENT
			if (!(p->p_memstat_dirty & P_DIRTY_MARKED)) {
				printf("memorystatus_perform_idle_demotion: moving process %d to idle band, but never dirtied (0x%x)!\n", p->p_pid, p->p_memstat_dirty);
			}
#endif
			memorystatus_invalidate_idle_demotion_locked(p, TRUE);
			memorystatus_update_priority_locked(p, JETSAM_PRIORITY_IDLE);
			
			// The prior process has moved out of the demotion bucket, so grab the new head and continue
			p = TAILQ_FIRST(&demotion_bucket->list);
			continue;
		}
		
		// No further candidates
		break;
	}
	
	memorystatus_reschedule_idle_demotion_locked();
	
	proc_list_unlock();

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_IDLE_DEMOTE) | DBG_FUNC_END, 0, 0, 0, 0, 0);
}

static void
memorystatus_schedule_idle_demotion_locked(proc_t p, boolean_t set_state) 
{	
	MEMORYSTATUS_DEBUG(1, "memorystatus_schedule_idle_demotion_locked: scheduling demotion to idle band for process %d (dirty:0x%x, set_state %d, demotions %d).\n", 
	    p->p_pid, p->p_memstat_dirty, set_state, memorystatus_scheduled_idle_demotions);

	assert((p->p_memstat_dirty & (P_DIRTY_IDLE_EXIT_ENABLED|P_DIRTY_DEFER_IN_PROGRESS)) == (P_DIRTY_IDLE_EXIT_ENABLED|P_DIRTY_DEFER_IN_PROGRESS));

	if (set_state) {
		assert(p->p_memstat_idledeadline == 0);
		p->p_memstat_idledeadline = mach_absolute_time() + memorystatus_idle_delay_time;
	}
	
 	assert(p->p_memstat_idledeadline);
	
 	memorystatus_scheduled_idle_demotions++;
}

static void
memorystatus_invalidate_idle_demotion_locked(proc_t p, boolean_t clear_state) 
{
	MEMORYSTATUS_DEBUG(1, "memorystatus_invalidate_idle_demotion(): invalidating demotion to idle band for process %d (clear_state %d, demotions %d).\n", 
	    p->p_pid, clear_state, memorystatus_scheduled_idle_demotions);
    
	assert(p->p_memstat_idledeadline);
 
	if (clear_state) {
 		p->p_memstat_idledeadline = 0;
 		p->p_memstat_dirty &= ~P_DIRTY_DEFER_IN_PROGRESS;
	}
 	
 	memorystatus_scheduled_idle_demotions--;
 	assert(memorystatus_scheduled_idle_demotions >= 0);
}

static void
memorystatus_reschedule_idle_demotion_locked(void) {
 	if (0 == memorystatus_scheduled_idle_demotions) {
 	 	if (memstat_idle_demotion_deadline) {
 	 	 	/* Transitioned 1->0, so cancel next call */
 	 	 	thread_call_cancel(memorystatus_idle_demotion_call);
 	 	 	memstat_idle_demotion_deadline = 0;
 		}
 	} else {
 		memstat_bucket_t *demotion_bucket;
 		proc_t p;
 		demotion_bucket = &memstat_bucket[JETSAM_PRIORITY_IDLE_DEFERRED];
 		p = TAILQ_FIRST(&demotion_bucket->list);
 		assert(p && p->p_memstat_idledeadline);
 		
 		if (memstat_idle_demotion_deadline != p->p_memstat_idledeadline){
 	 	 	thread_call_enter_delayed(memorystatus_idle_demotion_call, p->p_memstat_idledeadline);
 	 	 	memstat_idle_demotion_deadline = p->p_memstat_idledeadline;
		}
 	}
}

/* 
 * List manipulation
 */
 
int 
memorystatus_add(proc_t p, boolean_t locked)
{
	memstat_bucket_t *bucket;
	
	MEMORYSTATUS_DEBUG(1, "memorystatus_list_add(): adding process %d with priority %d.\n", p->pid, priority);
   
	if (!locked) {
   	   	proc_list_lock();
   	}
	
	/* Processes marked internal do not have priority tracked */
	if (p->p_memstat_state & P_MEMSTAT_INTERNAL) {
                goto exit;
	}
	
	bucket = &memstat_bucket[p->p_memstat_effectivepriority];
	
	TAILQ_INSERT_TAIL(&bucket->list, p, p_memstat_list);
	bucket->count++;

	memorystatus_list_count++;

	memorystatus_check_levels_locked();
	
exit:
   	if (!locked) {
   	   	proc_list_unlock();
   	}
	
	return 0;
}

static void
memorystatus_update_priority_locked(proc_t p, int priority)
{
	memstat_bucket_t *old_bucket, *new_bucket;
	
	assert(priority < MEMSTAT_BUCKET_COUNT);
	
	/* Ensure that exit isn't underway, leaving the proc retained but removed from its bucket */
	if ((p->p_listflag & P_LIST_EXITED) != 0) {
		return;
	}
	
	MEMORYSTATUS_DEBUG(1, "memorystatus_update_priority_locked(): setting process %d to priority %d\n", p->p_pid, priority);	

	old_bucket = &memstat_bucket[p->p_memstat_effectivepriority];
	TAILQ_REMOVE(&old_bucket->list, p, p_memstat_list);
	old_bucket->count--;
	
	new_bucket = &memstat_bucket[priority];	
	TAILQ_INSERT_TAIL(&new_bucket->list, p, p_memstat_list);
	new_bucket->count++;
	
#if CONFIG_JETSAM
	if (memorystatus_highwater_enabled && (p->p_memstat_state & P_MEMSTAT_MEMLIMIT_BACKGROUND)) {        
		if (((priority >= JETSAM_PRIORITY_FOREGROUND) && (p->p_memstat_effectivepriority < JETSAM_PRIORITY_FOREGROUND)) ||
			((priority < JETSAM_PRIORITY_FOREGROUND) && (p->p_memstat_effectivepriority >= JETSAM_PRIORITY_FOREGROUND))) {            
			int32_t memlimit = (priority >= JETSAM_PRIORITY_FOREGROUND) ? -1 : p->p_memstat_memlimit;
			task_set_phys_footprint_limit_internal(p->task, (memlimit  > 0) ? memlimit : -1, NULL, TRUE);
		}
	}
#endif
	
	p->p_memstat_effectivepriority = priority;
	
	memorystatus_check_levels_locked();
}

int
memorystatus_update(proc_t p, int priority, uint64_t user_data, boolean_t effective, boolean_t update_memlimit, int32_t memlimit, boolean_t memlimit_background)
{
	int ret;
	
#if !CONFIG_JETSAM
#pragma unused(update_memlimit, memlimit, memlimit_background)
#endif

	MEMORYSTATUS_DEBUG(1, "memorystatus_update: changing process %d: priority %d, user_data 0x%llx\n", p->p_pid, priority, user_data);
    
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_UPDATE) | DBG_FUNC_START, p->p_pid, priority, user_data, effective, 0);
	
	if (priority == -1) {
		/* Use as shorthand for default priority */
		priority = JETSAM_PRIORITY_DEFAULT;
	} else if (priority == JETSAM_PRIORITY_IDLE_DEFERRED) {
		/* JETSAM_PRIORITY_IDLE_DEFERRED is reserved for internal use; if requested, adjust to JETSAM_PRIORITY_IDLE. */
		priority = JETSAM_PRIORITY_IDLE;	        
	} else if ((priority < 0) || (priority >= MEMSTAT_BUCKET_COUNT)) {
		/* Sanity check */
		ret = EINVAL;
		goto out;
	}
	
	proc_list_lock();
	
	assert(!(p->p_memstat_state & P_MEMSTAT_INTERNAL));

	if (effective && (p->p_memstat_state & P_MEMSTAT_PRIORITYUPDATED)) {
		ret = EALREADY;
		proc_list_unlock();
		MEMORYSTATUS_DEBUG(1, "memorystatus_update: effective change specified for pid %d, but change already occurred.\n", pid);
		goto out;             
	}

	p->p_memstat_state |= P_MEMSTAT_PRIORITYUPDATED;
	p->p_memstat_userdata = user_data;
	p->p_memstat_requestedpriority = priority;
	
#if CONFIG_JETSAM
	if (update_memlimit) {
		p->p_memstat_memlimit = memlimit;
		if (memlimit_background) {
			/* Will be set as priority is updated */
			p->p_memstat_state |= P_MEMSTAT_MEMLIMIT_BACKGROUND;
		} else {
			/* Otherwise, apply now */
			if (memorystatus_highwater_enabled) {
				task_set_phys_footprint_limit_internal(p->task, (memlimit  > 0) ? memlimit : -1, NULL, TRUE);
			}
		}
	}
#endif

	memorystatus_update_priority_locked(p, priority);
	
	proc_list_unlock();
	ret = 0;

out:
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_UPDATE) | DBG_FUNC_END, ret, 0, 0, 0, 0);

	return ret;
}

int
memorystatus_remove(proc_t p, boolean_t locked)
{
	int ret;
	memstat_bucket_t *bucket;

	MEMORYSTATUS_DEBUG(1, "memorystatus_list_remove: removing process %d\n", pid);

   	if (!locked) {
   	   	proc_list_lock();
   	}

	assert(!(p->p_memstat_state & P_MEMSTAT_INTERNAL));

	bucket = &memstat_bucket[p->p_memstat_effectivepriority];
	TAILQ_REMOVE(&bucket->list, p, p_memstat_list);
	bucket->count--;

	memorystatus_list_count--;

	/* If awaiting demotion to the idle band, clean up */
	if (p->p_memstat_effectivepriority == JETSAM_PRIORITY_IDLE_DEFERRED) {
		memorystatus_invalidate_idle_demotion_locked(p, TRUE);
 		memorystatus_reschedule_idle_demotion_locked();
	}

	memorystatus_check_levels_locked();

#if CONFIG_FREEZE    
	if (p->p_memstat_state & (P_MEMSTAT_FROZEN)) {
		memorystatus_frozen_count--;
	}

	if (p->p_memstat_state & P_MEMSTAT_SUSPENDED) {
		memorystatus_suspended_footprint_total -= p->p_memstat_suspendedfootprint;
		memorystatus_suspended_count--;
	}
#endif

   	if (!locked) {
   	   	proc_list_unlock();
   	}

	if (p) {
		ret = 0; 
	} else {
		ret = ESRCH;
	}

	return ret;
}

static boolean_t
memorystatus_validate_track_flags(struct proc *target_p, uint32_t pcontrol) {
	/* See that the process isn't marked for termination */
	if (target_p->p_memstat_dirty & P_DIRTY_TERMINATED) {
		return FALSE;
	}
	
	/* Idle exit requires that process be tracked */
	if ((pcontrol & PROC_DIRTY_ALLOW_IDLE_EXIT) &&
	   !(pcontrol & PROC_DIRTY_TRACK)) {
		return FALSE;		
	}

	/* Deferral is only relevant if idle exit is specified */
	if ((pcontrol & PROC_DIRTY_DEFER) && 
	   !(pcontrol & PROC_DIRTY_ALLOWS_IDLE_EXIT)) {
		return FALSE;		
	}
	
	return TRUE;
}

static void
memorystatus_update_idle_priority_locked(proc_t p) {
	int32_t priority;
	
	MEMORYSTATUS_DEBUG(1, "memorystatus_update_idle_priority_locked(): pid %d dirty 0x%X\n", p->p_pid, p->p_memstat_dirty);
	
	if ((p->p_memstat_dirty & (P_DIRTY_IDLE_EXIT_ENABLED|P_DIRTY_IS_DIRTY)) == P_DIRTY_IDLE_EXIT_ENABLED) {
		priority = (p->p_memstat_dirty & P_DIRTY_DEFER_IN_PROGRESS) ? JETSAM_PRIORITY_IDLE_DEFERRED : JETSAM_PRIORITY_IDLE;
	} else {
		priority = p->p_memstat_requestedpriority;
	}
	
	memorystatus_update_priority_locked(p, priority);
} 

/*
 * Processes can opt to have their state tracked by the kernel, indicating  when they are busy (dirty) or idle
 * (clean). They may also indicate that they support termination when idle, with the result that they are promoted
 * to their desired, higher, jetsam priority when dirty (and are therefore killed later), and demoted to the low
 * priority idle band when clean (and killed earlier, protecting higher priority procesess).
 *
 * If the deferral flag is set, then newly tracked processes will be protected for an initial period (as determined by
 * memorystatus_idle_delay_time); if they go clean during this time, then they will be moved to a deferred-idle band
 * with a slightly higher priority, guarding against immediate termination under memory pressure and being unable to
 * make forward progress. Finally, when the guard expires, they will be moved to the standard, lowest-priority, idle
 * band. The deferral can be cleared early by clearing the appropriate flag.
 *
 * The deferral timer is active only for the duration that the process is marked as guarded and clean; if the process
 * is marked dirty, the timer will be cancelled. Upon being subsequently marked clean, the deferment will either be
 * re-enabled or the guard state cleared, depending on whether the guard deadline has passed.
 */

int
memorystatus_dirty_track(proc_t p, uint32_t pcontrol) {
	unsigned int old_dirty;
	boolean_t reschedule = FALSE;
	int ret;
    
	proc_list_lock();
	
	if (p->p_memstat_state & P_MEMSTAT_INTERNAL) {
		ret = EPERM;
		goto exit;
	}
	
	if (!memorystatus_validate_track_flags(p, pcontrol)) {
		ret = EINVAL;
		goto exit;
        }

        old_dirty = p->p_memstat_dirty;

	/* These bits are cumulative, as per <rdar://problem/11159924> */
	if (pcontrol & PROC_DIRTY_TRACK) {
		p->p_memstat_dirty |= P_DIRTY_TRACK;
	}

	if (pcontrol & PROC_DIRTY_ALLOW_IDLE_EXIT) {
		p->p_memstat_dirty |= P_DIRTY_ALLOW_IDLE_EXIT;					
	}

	/* This can be set and cleared exactly once. */
	if ((pcontrol & PROC_DIRTY_DEFER) && !(old_dirty & P_DIRTY_DEFER)) {
		p->p_memstat_dirty |= (P_DIRTY_DEFER|P_DIRTY_DEFER_IN_PROGRESS);				
	} else {
		p->p_memstat_dirty &= ~P_DIRTY_DEFER_IN_PROGRESS;					
	}

	MEMORYSTATUS_DEBUG(1, "memorystatus_on_track_dirty(): set idle-exit %s / deferred %s / dirty %s for process %d\n",
		((p->p_memstat_dirty & P_DIRTY_IDLE_EXIT_ENABLED) == P_DIRTY_IDLE_EXIT_ENABLED) ? "Y" : "N",
		p->p_memstat_dirty & P_DIRTY_DEFER_IN_PROGRESS ? "Y" : "N",
		p->p_memstat_dirty & P_DIRTY ? "Y" : "N",
		p->p_pid);

	/* Kick off or invalidate the idle exit deferment if there's a state transition. */
	if (!(p->p_memstat_dirty & P_DIRTY_IS_DIRTY)) {
		if (((p->p_memstat_dirty & P_DIRTY_IDLE_EXIT_ENABLED) == P_DIRTY_IDLE_EXIT_ENABLED) && 
			(p->p_memstat_dirty & P_DIRTY_DEFER_IN_PROGRESS) && !(old_dirty & P_DIRTY_DEFER_IN_PROGRESS)) {
			memorystatus_schedule_idle_demotion_locked(p, TRUE);
			reschedule = TRUE;
		} else if (!(p->p_memstat_dirty & P_DIRTY_DEFER_IN_PROGRESS) && (old_dirty & P_DIRTY_DEFER_IN_PROGRESS)) {
			memorystatus_invalidate_idle_demotion_locked(p, TRUE);
			reschedule = TRUE;
		}
	}

	memorystatus_update_idle_priority_locked(p);
	
	if (reschedule) {
		memorystatus_reschedule_idle_demotion_locked();
	}
		
	ret = 0;
	
exit:		
	proc_list_unlock();
	
	return ret;
}

int
memorystatus_dirty_set(proc_t p, boolean_t self, uint32_t pcontrol) {
	int ret;
	boolean_t kill = false;
	boolean_t reschedule = FALSE;
	boolean_t was_dirty = FALSE;
	boolean_t now_dirty = FALSE;

	MEMORYSTATUS_DEBUG(1, "memorystatus_dirty_set(): %d %d 0x%x 0x%x\n", self, p->p_pid, pcontrol, p->p_memstat_dirty);

	proc_list_lock();

	if (p->p_memstat_state & P_MEMSTAT_INTERNAL) {
		ret = EPERM;
		goto exit;
	}

	if (p->p_memstat_dirty & P_DIRTY_IS_DIRTY)
		was_dirty = TRUE;

	if (!(p->p_memstat_dirty & P_DIRTY_TRACK)) {
		/* Dirty tracking not enabled */
		ret = EINVAL;			
	} else if (pcontrol && (p->p_memstat_dirty & P_DIRTY_TERMINATED)) {
		/* 
		 * Process is set to be terminated and we're attempting to mark it dirty.
		 * Set for termination and marking as clean is OK - see <rdar://problem/10594349>.
		 */
		ret = EBUSY;		
	} else {
		int flag = (self == TRUE) ? P_DIRTY : P_DIRTY_SHUTDOWN;
		if (pcontrol && !(p->p_memstat_dirty & flag)) {
			/* Mark the process as having been dirtied at some point */
			p->p_memstat_dirty |= (flag | P_DIRTY_MARKED);
			memorystatus_dirty_count++;
			ret = 0;
		} else if ((pcontrol == 0) && (p->p_memstat_dirty & flag)) {
			if ((flag == P_DIRTY_SHUTDOWN) && (!p->p_memstat_dirty & P_DIRTY)) {
				/* Clearing the dirty shutdown flag, and the process is otherwise clean - kill */
				p->p_memstat_dirty |= P_DIRTY_TERMINATED;
				kill = true;
			} else if ((flag == P_DIRTY) && (p->p_memstat_dirty & P_DIRTY_TERMINATED)) {
				/* Kill previously terminated processes if set clean */
				kill = true;						
			}
			p->p_memstat_dirty &= ~flag;
			memorystatus_dirty_count--;
			ret = 0;
		} else {
			/* Already set */
			ret = EALREADY;
		}
	}

	if (ret != 0) {
		goto exit;
	}
	    
	if (p->p_memstat_dirty & P_DIRTY_IS_DIRTY)
		now_dirty = TRUE;

	if ((was_dirty == TRUE && now_dirty == FALSE) ||
	    (was_dirty == FALSE && now_dirty == TRUE)) {

		/* Manage idle exit deferral, if applied */
		if ((p->p_memstat_dirty & (P_DIRTY_IDLE_EXIT_ENABLED|P_DIRTY_DEFER_IN_PROGRESS)) ==
		    (P_DIRTY_IDLE_EXIT_ENABLED|P_DIRTY_DEFER_IN_PROGRESS)) {
			if (p->p_memstat_dirty & P_DIRTY_IS_DIRTY) {
				memorystatus_invalidate_idle_demotion_locked(p, FALSE);
				reschedule = TRUE;
			} else {
				/* We evaluate lazily, so reset the idle-deadline if it's expired by the time the process becomes clean. */
				if (mach_absolute_time() >= p->p_memstat_idledeadline) {
					p->p_memstat_idledeadline = 0;
					p->p_memstat_dirty &= ~P_DIRTY_DEFER_IN_PROGRESS;
				} else {
					memorystatus_schedule_idle_demotion_locked(p, FALSE);
					reschedule = TRUE;
				}
			}
		}
    
		memorystatus_update_idle_priority_locked(p);
	
		/* If the deferral state changed, reschedule the demotion timer */
		if (reschedule) {
			memorystatus_reschedule_idle_demotion_locked();
		}
	}
		
	if (kill) {
		psignal(p, SIGKILL);
	}
	
exit:
	proc_list_unlock();

	return ret;
}

int
memorystatus_dirty_get(proc_t p) {
	int ret = 0;
    
	proc_list_lock();
	
	if (p->p_memstat_dirty & P_DIRTY_TRACK) {
		ret |= PROC_DIRTY_TRACKED;
		if (p->p_memstat_dirty & P_DIRTY_ALLOW_IDLE_EXIT) {
			ret |= PROC_DIRTY_ALLOWS_IDLE_EXIT;
		}
		if (p->p_memstat_dirty & P_DIRTY) {
			ret |= PROC_DIRTY_IS_DIRTY;
		}
	}
	
	proc_list_unlock();
    
	return ret;
}

int
memorystatus_on_terminate(proc_t p) {
	int sig;
    
	proc_list_lock();
	
	p->p_memstat_dirty |= P_DIRTY_TERMINATED;
	
	if ((p->p_memstat_dirty & (P_DIRTY_TRACK|P_DIRTY_IS_DIRTY)) == P_DIRTY_TRACK) {
		/* Clean; mark as terminated and issue SIGKILL */
		sig = SIGKILL;
	} else {
		/* Dirty, terminated, or state tracking is unsupported; issue SIGTERM to allow cleanup */
		sig = SIGTERM;
	}

	proc_list_unlock();
	
	return sig;
}

void
memorystatus_on_suspend(proc_t p)
{
#if CONFIG_FREEZE
	uint32_t pages;
	memorystatus_get_task_page_counts(p->task, &pages, NULL);
#endif
	proc_list_lock();
#if CONFIG_FREEZE
	p->p_memstat_suspendedfootprint = pages;
	memorystatus_suspended_footprint_total += pages;
	memorystatus_suspended_count++;
#endif
	p->p_memstat_state |= P_MEMSTAT_SUSPENDED;
	proc_list_unlock();
}

void
memorystatus_on_resume(proc_t p)
{
#if CONFIG_FREEZE
	boolean_t frozen;
	pid_t pid;
#endif

	proc_list_lock();

#if CONFIG_FREEZE
	frozen = (p->p_memstat_state & P_MEMSTAT_FROZEN);
	if (frozen) {
		memorystatus_frozen_count--;
		p->p_memstat_state |= P_MEMSTAT_PRIOR_THAW;
	}

	memorystatus_suspended_footprint_total -= p->p_memstat_suspendedfootprint;
	memorystatus_suspended_count--;
	
	pid = p->p_pid;
#endif

	p->p_memstat_state &= ~(P_MEMSTAT_SUSPENDED | P_MEMSTAT_FROZEN);

	proc_list_unlock();
    
#if CONFIG_FREEZE
	if (frozen) {
		memorystatus_freeze_entry_t data = { pid, FALSE, 0 };
		memorystatus_send_note(kMemorystatusFreezeNote, &data, sizeof(data));
	}
#endif
}

void
memorystatus_on_inactivity(proc_t p)
{
#pragma unused(p)
#if CONFIG_FREEZE
	/* Wake the freeze thread */
	thread_wakeup((event_t)&memorystatus_freeze_wakeup);
#endif	
}

static uint32_t
memorystatus_build_state(proc_t p) {
	uint32_t snapshot_state = 0;
    
	/* General */
	if (p->p_memstat_state & P_MEMSTAT_SUSPENDED) {
		snapshot_state |= kMemorystatusSuspended;
	}
	if (p->p_memstat_state & P_MEMSTAT_FROZEN) {
		snapshot_state |= kMemorystatusFrozen;
	}
	if (p->p_memstat_state & P_MEMSTAT_PRIOR_THAW) {
 		snapshot_state |= kMemorystatusWasThawed;
	}
	
	/* Tracking */
	if (p->p_memstat_dirty & P_DIRTY_TRACK) {
		snapshot_state |= kMemorystatusTracked;
	}
	if ((p->p_memstat_dirty & P_DIRTY_IDLE_EXIT_ENABLED) == P_DIRTY_IDLE_EXIT_ENABLED) {
		snapshot_state |= kMemorystatusSupportsIdleExit;
	}
	if (p->p_memstat_dirty & P_DIRTY_IS_DIRTY) {
		snapshot_state |= kMemorystatusDirty;
	}

	return snapshot_state;
}

#if !CONFIG_JETSAM

static boolean_t
kill_idle_exit_proc(void)
{
	proc_t p, victim_p = PROC_NULL;
	uint64_t current_time;
	boolean_t killed = FALSE;
	unsigned int i = 0;

	/* Pick next idle exit victim. */
	current_time = mach_absolute_time();
	
	proc_list_lock();
	
	p = memorystatus_get_first_proc_locked(&i, FALSE);
	while (p) {
		/* No need to look beyond the idle band */
		if (p->p_memstat_effectivepriority != JETSAM_PRIORITY_IDLE) {
			break;
		}
		
		if ((p->p_memstat_dirty & (P_DIRTY_ALLOW_IDLE_EXIT|P_DIRTY_IS_DIRTY|P_DIRTY_TERMINATED)) == (P_DIRTY_ALLOW_IDLE_EXIT)) {				
			if (current_time >= p->p_memstat_idledeadline) {
				p->p_memstat_dirty |= P_DIRTY_TERMINATED;
				victim_p = proc_ref_locked(p);
				break;
			}
		}
		
		p = memorystatus_get_next_proc_locked(&i, p, FALSE);
	}
	
	proc_list_unlock();
	
	if (victim_p) {
		printf("memorystatus_thread: idle exiting pid %d [%s]\n", victim_p->p_pid, (victim_p->p_comm ? victim_p->p_comm : "(unknown)"));
		killed = memorystatus_do_kill(victim_p, kMemorystatusKilledIdleExit);
		proc_rele(victim_p);
	}

	return killed;
}
#endif

static void
memorystatus_thread_wake(void) {
	thread_wakeup((event_t)&memorystatus_wakeup);
}

static int
memorystatus_thread_block(uint32_t interval_ms, thread_continue_t continuation)
{
	if (interval_ms) {
		assert_wait_timeout(&memorystatus_wakeup, THREAD_UNINT, interval_ms, 1000 * NSEC_PER_USEC);
	} else {
		assert_wait(&memorystatus_wakeup, THREAD_UNINT);
	}
	
	return thread_block(continuation);   
}

extern boolean_t vm_compressor_thrashing_detected;
extern uint64_t vm_compressor_total_compressions(void);

static void
memorystatus_thread(void *param __unused, wait_result_t wr __unused)
{
	static boolean_t is_vm_privileged = FALSE;
#if CONFIG_JETSAM
	boolean_t post_snapshot = FALSE;
	uint32_t errors = 0;
#endif

	if (is_vm_privileged == FALSE) {
		/* 
		 * It's the first time the thread has run, so just mark the thread as privileged and block.
		 * This avoids a spurious pass with unset variables, as set out in <rdar://problem/9609402>.
		 */
		thread_wire(host_priv_self(), current_thread(), TRUE);
		is_vm_privileged = TRUE;
		
		memorystatus_thread_block(0, memorystatus_thread);
	}
	
#if CONFIG_JETSAM
	
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_SCAN) | DBG_FUNC_START,
		memorystatus_available_pages, 0, 0, 0, 0);

	uint32_t cause = vm_compressor_thrashing_detected ? kMemorystatusKilledVMThrashing : kMemorystatusKilledVMPageShortage;

	/* Jetsam aware version.
	 *
	 * If woken under pressure, go down the path of killing:
	 *
	 * - processes exceeding their highwater mark if no clean victims available
	 * - the least recently used process if no highwater mark victims available
	 */
#if !LATENCY_JETSAM	   
	while (vm_compressor_thrashing_detected || memorystatus_available_pages <= memorystatus_available_pages_critical) {
#else
	while (kill_under_pressure) {
		const uint32_t SNAPSHOT_WAIT_TIMEOUT_MS = 100;
		wait_result_t wait_result;
#endif
		boolean_t killed;
		int32_t priority;

#if LEGACY_HIWATER
		/* Highwater */
		killed = memorystatus_kill_hiwat_proc(&errors);
		if (killed) {
			post_snapshot = TRUE;
			goto done;
		}
#endif
		
		/* LRU */
		killed = memorystatus_kill_top_process(TRUE, cause, &priority, &errors);
		if (killed) {
			if (!kill_under_pressure && (priority != JETSAM_PRIORITY_IDLE)) {
			        /* Don't generate logs for steady-state idle-exit kills */
        			post_snapshot = TRUE;
			}
			goto done;
		}
			
		/* Under pressure and unable to kill a process - panic */
		panic("memorystatus_jetsam_thread: no victim! available pages:%d\n", memorystatus_available_pages);
			
done:		
		kill_under_pressure = FALSE;
		vm_compressor_thrashing_detected = FALSE;
				
#if LATENCY_JETSAM
		KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_LATENCY_COALESCE) | DBG_FUNC_START,
			memorystatus_available_pages, 0, 0, 0, 0);
		thread_wakeup((event_t)&latency_jetsam_wakeup);
		/* 
		 * Coalesce snapshot reports in the face of repeated jetsams by blocking here with a timeout. 
		 * If the wait expires, issue the note.
		 */
		wait_result = memorystatus_thread_block(SNAPSHOT_WAIT_TIMEOUT_MS, THREAD_CONTINUE_NULL);	
		KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_LATENCY_COALESCE) | DBG_FUNC_END,
			memorystatus_available_pages, 0, 0, 0, 0);
		if (wait_result != THREAD_AWAKENED) {
			/* Catch-all */
			break;
		}
#endif
	}
		
	if (errors) {
		memorystatus_clear_errors();
	}

#if VM_PRESSURE_EVENTS
	memorystatus_update_vm_pressure(TRUE);
#endif

	if (post_snapshot) {
		size_t snapshot_size = sizeof(memorystatus_jetsam_snapshot_t) +
			sizeof(memorystatus_jetsam_snapshot_entry_t) * (memorystatus_jetsam_snapshot_count);
		memorystatus_jetsam_snapshot->notification_time = mach_absolute_time();
		memorystatus_send_note(kMemorystatusSnapshotNote, &snapshot_size, sizeof(snapshot_size));
	}
	
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_SCAN) | DBG_FUNC_END,
		memorystatus_available_pages, 0, 0, 0, 0);

#else /* CONFIG_JETSAM */

	/* Simple version.
	 *
	 * Jetsam not enabled, so just kill the first suitable clean process
	 * and sleep.
	 */

	if (kill_idle_exit) {
		kill_idle_exit_proc();
		kill_idle_exit = FALSE;
	}
	
#endif /* CONFIG_JETSAM */

	memorystatus_thread_block(0, memorystatus_thread);
}

#if !CONFIG_JETSAM
boolean_t memorystatus_idle_exit_from_VM(void) {
	kill_idle_exit = TRUE;	
	memorystatus_thread_wake();
	return TRUE;
}
#endif

#if CONFIG_JETSAM

/*
 * Callback invoked when allowable physical memory footprint exceeded
 * (dirty pages + IOKit mappings)
 *
 * This is invoked for both advisory, non-fatal per-task high watermarks,
 * as well as the fatal system-wide task memory limit.
 */
void
memorystatus_on_ledger_footprint_exceeded(boolean_t warning, const int max_footprint_mb)
{
	proc_t p = current_proc();
    
	printf("process %d (%s) %s physical memory footprint limit of %d MB\n",
		p->p_pid, p->p_comm,
		warning ? "approaching" : "exceeded",
		max_footprint_mb);

#if VM_PRESSURE_EVENTS
	if (warning == TRUE) {
		if (memorystatus_warn_process(p->p_pid) != TRUE) {
			/* Print warning, since it's possible that task has not registered for pressure notifications */
			printf("task_exceeded_footprint: failed to warn the current task (exiting?).\n");			
		}
		return;
	}
#endif /* VM_PRESSURE_EVENTS */

	if (p->p_memstat_memlimit <= 0) {
		/*
		 * If this process has no high watermark, then we have been invoked because the task
		 * has violated the system-wide per-task memory limit.
		 */
		if (memorystatus_kill_process_sync(p->p_pid, kMemorystatusKilledPerProcessLimit) != TRUE) {
			printf("task_exceeded_footprint: failed to kill the current task (exiting?).\n");
		}
	}
}

static void
memorystatus_get_task_page_counts(task_t task, uint32_t *footprint, uint32_t *max_footprint)
{
	assert(task);
	assert(footprint);
    
	*footprint = (uint32_t)(get_task_phys_footprint(task) / PAGE_SIZE_64);
	if (max_footprint) {
		*max_footprint = (uint32_t)(get_task_phys_footprint_max(task) / PAGE_SIZE_64);
	}
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
		printf("%s: kev_post_msg() failed, err %d\n", __func__, ret);
	}
	
	return ret;
}

static void
memorystatus_update_snapshot_locked(proc_t p, uint32_t kill_cause)
{
	unsigned int i;

	for (i = 0; i < memorystatus_jetsam_snapshot_count; i++) {
		if (memorystatus_jetsam_snapshot_list[i].pid == p->p_pid) {
			/* Update if the priority has changed since the snapshot was taken */
			if (memorystatus_jetsam_snapshot_list[i].priority != p->p_memstat_effectivepriority) {
				memorystatus_jetsam_snapshot_list[i].priority = p->p_memstat_effectivepriority;
				strlcpy(memorystatus_jetsam_snapshot_list[i].name, p->p_comm, MAXCOMLEN+1);
				memorystatus_jetsam_snapshot_list[i].state = memorystatus_build_state(p);
				memorystatus_jetsam_snapshot_list[i].user_data = p->p_memstat_userdata;
				memorystatus_jetsam_snapshot_list[i].fds = p->p_fd->fd_nfiles;
			}
			memorystatus_jetsam_snapshot_list[i].killed = kill_cause;
			return;
		}
	}
}

void memorystatus_pages_update(unsigned int pages_avail)
{
	boolean_t critical, delta;
        
	if (!memorystatus_delta) {
	    return;
	}
	
	critical = (pages_avail < memorystatus_available_pages_critical) ? TRUE : FALSE;
	delta = ((pages_avail >= (memorystatus_available_pages + memorystatus_delta)) 
                || (memorystatus_available_pages >= (pages_avail + memorystatus_delta))) ? TRUE : FALSE;
        
	if (critical || delta) {
		memorystatus_available_pages = pages_avail;
  		memorystatus_level = memorystatus_available_pages * 100 / atop_64(max_mem);

#if LATENCY_JETSAM
		/* Bail early to avoid excessive wake-ups */
		if (critical) {
			return;
		}
#endif

		memorystatus_thread_wake();
	}
}

static boolean_t
memorystatus_get_snapshot_properties_for_proc_locked(proc_t p, memorystatus_jetsam_snapshot_entry_t *entry)
{	
	memset(entry, 0, sizeof(memorystatus_jetsam_snapshot_entry_t));
	
	entry->pid = p->p_pid;
	strlcpy(&entry->name[0], p->p_comm, MAXCOMLEN+1);
	entry->priority = p->p_memstat_effectivepriority;
	memorystatus_get_task_page_counts(p->task, &entry->pages, &entry->max_pages);
	entry->state = memorystatus_build_state(p);
	entry->user_data = p->p_memstat_userdata;
	memcpy(&entry->uuid[0], &p->p_uuid[0], sizeof(p->p_uuid));

	return TRUE;	
}

static void
memorystatus_jetsam_snapshot_procs_locked(void)
{
	proc_t p, next_p;
	unsigned int b = 0, i = 0;
	kern_return_t kr = KERN_SUCCESS;

	mach_msg_type_number_t	count = HOST_VM_INFO64_COUNT;
	vm_statistics64_data_t	vm_stat;

	if ((kr = host_statistics64(host_self(), HOST_VM_INFO64, (host_info64_t)&vm_stat, &count) != KERN_SUCCESS)) {
		printf("memorystatus_jetsam_snapshot_procs_locked: host_statistics64 failed with %d\n", kr);
		memset(&memorystatus_jetsam_snapshot->stats, 0, sizeof(memorystatus_jetsam_snapshot->stats));
	} else {
		memorystatus_jetsam_snapshot->stats.free_pages = vm_stat.free_count;
		memorystatus_jetsam_snapshot->stats.active_pages = vm_stat.active_count;
		memorystatus_jetsam_snapshot->stats.inactive_pages = vm_stat.inactive_count;
		memorystatus_jetsam_snapshot->stats.throttled_pages = vm_stat.throttled_count;
		memorystatus_jetsam_snapshot->stats.purgeable_pages = vm_stat.purgeable_count;
		memorystatus_jetsam_snapshot->stats.wired_pages = vm_stat.wire_count;
		
		memorystatus_jetsam_snapshot->stats.speculative_pages = vm_stat.speculative_count;
		memorystatus_jetsam_snapshot->stats.filebacked_pages = vm_stat.external_page_count;
		memorystatus_jetsam_snapshot->stats.anonymous_pages = vm_stat.internal_page_count;
		memorystatus_jetsam_snapshot->stats.compressions = vm_stat.compressions;
		memorystatus_jetsam_snapshot->stats.decompressions = vm_stat.decompressions;
		memorystatus_jetsam_snapshot->stats.compressor_pages = vm_stat.compressor_page_count;
		memorystatus_jetsam_snapshot->stats.total_uncompressed_pages_in_compressor = vm_stat.total_uncompressed_pages_in_compressor;
	}

	next_p = memorystatus_get_first_proc_locked(&b, TRUE);
	while (next_p) {
		p = next_p;
		next_p = memorystatus_get_next_proc_locked(&b, p, TRUE);
	        
		if (FALSE == memorystatus_get_snapshot_properties_for_proc_locked(p, &memorystatus_jetsam_snapshot_list[i])) {
			continue;
		}
		
		MEMORYSTATUS_DEBUG(0, "jetsam snapshot pid = %d, uuid = %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			p->p_pid, 
			p->p_uuid[0], p->p_uuid[1], p->p_uuid[2], p->p_uuid[3], p->p_uuid[4], p->p_uuid[5], p->p_uuid[6], p->p_uuid[7],
			p->p_uuid[8], p->p_uuid[9], p->p_uuid[10], p->p_uuid[11], p->p_uuid[12], p->p_uuid[13], p->p_uuid[14], p->p_uuid[15]);

		if (++i == memorystatus_jetsam_snapshot_max) {
			break;
		} 	
	}

	memorystatus_jetsam_snapshot->snapshot_time = mach_absolute_time();
	memorystatus_jetsam_snapshot->entry_count = memorystatus_jetsam_snapshot_count = i;
}

#if DEVELOPMENT || DEBUG

static int
memorystatus_cmd_set_panic_bits(user_addr_t buffer, uint32_t buffer_size) {
	int ret;
	memorystatus_jetsam_panic_options_t debug;
	
	if (buffer_size != sizeof(memorystatus_jetsam_panic_options_t)) {
		return EINVAL;
	}

	ret = copyin(buffer, &debug, buffer_size);
	if (ret) {
		return ret;
	}
	
	/* Panic bits match kMemorystatusKilled* enum */
	memorystatus_jetsam_panic_debug = (memorystatus_jetsam_panic_debug & ~debug.mask) | (debug.data & debug.mask);
	
	/* Copyout new value */
	debug.data = memorystatus_jetsam_panic_debug;
	ret = copyout(&debug, buffer, sizeof(memorystatus_jetsam_panic_options_t));
	
	return ret;
}

#endif

/*
 * Jetsam a specific process.
 */
static boolean_t 
memorystatus_kill_specific_process(pid_t victim_pid, uint32_t cause) {
	boolean_t killed;
	proc_t p;

	/* TODO - add a victim queue and push this into the main jetsam thread */

	p = proc_find(victim_pid);
	if (!p) {
		return FALSE;
	}

	printf("memorystatus: specifically killing pid %d [%s] - memorystatus_available_pages: %d\n", 
		victim_pid, (p->p_comm ? p->p_comm : "(unknown)"), memorystatus_available_pages);

	proc_list_lock();

	if (memorystatus_jetsam_snapshot_count == 0) {
		memorystatus_jetsam_snapshot_procs_locked();
	}

	memorystatus_update_snapshot_locked(p, cause);
	proc_list_unlock();
	
	killed = memorystatus_do_kill(p, cause);
	proc_rele(p);
	
	return killed;
}

/*
 * Jetsam the first process in the queue.
 */
static boolean_t
memorystatus_kill_top_process(boolean_t any, uint32_t cause, int32_t *priority, uint32_t *errors)
{
	pid_t aPid;
	proc_t p = PROC_NULL, next_p = PROC_NULL;
	boolean_t new_snapshot = FALSE, killed = FALSE;
	unsigned int i = 0;

#ifndef CONFIG_FREEZE
#pragma unused(any)
#endif
	
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_JETSAM) | DBG_FUNC_START,
		memorystatus_available_pages, 0, 0, 0, 0);

	proc_list_lock();

	next_p = memorystatus_get_first_proc_locked(&i, TRUE);
	while (next_p) {
#if DEVELOPMENT || DEBUG
		int activeProcess;
		int procSuspendedForDiagnosis;
#endif /* DEVELOPMENT || DEBUG */
        
		p = next_p;
		next_p = memorystatus_get_next_proc_locked(&i, p, TRUE);
		
#if DEVELOPMENT || DEBUG
		activeProcess = p->p_memstat_state & P_MEMSTAT_FOREGROUND;
		procSuspendedForDiagnosis = p->p_memstat_state & P_MEMSTAT_DIAG_SUSPENDED;
#endif /* DEVELOPMENT || DEBUG */
		
		aPid = p->p_pid;

		if (p->p_memstat_state & (P_MEMSTAT_ERROR | P_MEMSTAT_TERMINATED)) {
			continue;
		}
		    
#if DEVELOPMENT || DEBUG
		if ((memorystatus_jetsam_policy & kPolicyDiagnoseActive) && procSuspendedForDiagnosis) {
			printf("jetsam: continuing after ignoring proc suspended already for diagnosis - %d\n", aPid);
			continue;
		}
#endif /* DEVELOPMENT || DEBUG */

#if CONFIG_FREEZE
		boolean_t skip;
		boolean_t reclaim_proc = !(p->p_memstat_state & (P_MEMSTAT_LOCKED | P_MEMSTAT_NORECLAIM));
		if (any || reclaim_proc) {
			skip = FALSE;
		} else {
			skip = TRUE;
		}
			
		if (skip) {
			continue;
		} else
#endif
		{
			if (priority) {
				*priority = p->p_memstat_effectivepriority;
			}
		        
		        /*
		         * Capture a snapshot if none exists and:
		         * - priority was not requested (this is something other than an ambient kill)
		         * - the priority was requested *and* the targeted process is not at idle priority
		         */
                	if ((memorystatus_jetsam_snapshot_count == 0) && 
                	    ((!priority) || (priority && (*priority != JETSAM_PRIORITY_IDLE)))) {
                		memorystatus_jetsam_snapshot_procs_locked();
                		new_snapshot = TRUE;
                	}
		        
			/* 
			 * Mark as terminated so that if exit1() indicates success, but the process (for example)
			 * is blocked in task_exception_notify(), it'll be skipped if encountered again - see 
			 * <rdar://problem/13553476>. This is cheaper than examining P_LEXIT, which requires the 
			 * acquisition of the proc lock.
			 */
			p->p_memstat_state |= P_MEMSTAT_TERMINATED;
		        
#if DEVELOPMENT || DEBUG
			if ((memorystatus_jetsam_policy & kPolicyDiagnoseActive) && activeProcess) {
				MEMORYSTATUS_DEBUG(1, "jetsam: suspending pid %d [%s] (active) for diagnosis - memory_status_level: %d\n",
					aPid, (p->p_comm ? p->p_comm: "(unknown)"), memorystatus_level);
				memorystatus_update_snapshot_locked(p, kMemorystatusKilledDiagnostic);
				p->p_memstat_state |= P_MEMSTAT_DIAG_SUSPENDED;
				if (memorystatus_jetsam_policy & kPolicyDiagnoseFirst) {
					jetsam_diagnostic_suspended_one_active_proc = 1;
					printf("jetsam: returning after suspending first active proc - %d\n", aPid);
				}
				
				p = proc_ref_locked(p);
				proc_list_unlock();
				if (p) {
					task_suspend(p->task);
					proc_rele(p);
					killed = TRUE;
				}
				
				goto exit;
			} else
#endif /* DEVELOPMENT || DEBUG */
			{
				/* Shift queue, update stats */
				memorystatus_update_snapshot_locked(p, cause);
				
				p = proc_ref_locked(p);
				proc_list_unlock();
				if (p) {
					printf("memorystatus: jetsam killing pid %d [%s] - memorystatus_available_pages: %d\n", 
    						aPid, (p->p_comm ? p->p_comm : "(unknown)"), memorystatus_available_pages);
					killed = memorystatus_do_kill(p, cause);
				}
				
				/* Success? */
				if (killed) {
					proc_rele(p);
					goto exit;
				}
				
				/* Failure - unwind and restart. */
				proc_list_lock();
				proc_rele_locked(p);
				p->p_memstat_state &= ~P_MEMSTAT_TERMINATED;
				p->p_memstat_state |= P_MEMSTAT_ERROR;
				*errors += 1;
				i = 0;
				next_p = memorystatus_get_first_proc_locked(&i, TRUE);
			}
		}
	}
	
	proc_list_unlock();
	
exit:
	/* Clear snapshot if freshly captured and no target was found */
	if (new_snapshot && !killed) {
	    memorystatus_jetsam_snapshot->entry_count = memorystatus_jetsam_snapshot_count = 0;
	}
	
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_JETSAM) | DBG_FUNC_END,
	    memorystatus_available_pages, killed ? aPid : 0, 0, 0, 0);

	return killed;
}

#if LEGACY_HIWATER

static boolean_t
memorystatus_kill_hiwat_proc(uint32_t *errors)
{
	pid_t aPid = 0;
	proc_t p = PROC_NULL, next_p = PROC_NULL;
	boolean_t new_snapshot = FALSE, killed = FALSE;
	unsigned int i = 0;
	
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_JETSAM_HIWAT) | DBG_FUNC_START,
		memorystatus_available_pages, 0, 0, 0, 0);
	
	proc_list_lock();
	
	next_p = memorystatus_get_first_proc_locked(&i, TRUE);
	while (next_p) {
		uint32_t footprint;
		boolean_t skip;

		p = next_p;
		next_p = memorystatus_get_next_proc_locked(&i, p, TRUE);
		
		aPid = p->p_pid;
		
		if (p->p_memstat_state  & (P_MEMSTAT_ERROR | P_MEMSTAT_TERMINATED)) {
			continue;
		}
		
		/* skip if no limit set */
		if (p->p_memstat_memlimit <= 0) {
			continue;
		}
		
		/* skip if a currently inapplicable limit is encountered */
		if ((p->p_memstat_state & P_MEMSTAT_MEMLIMIT_BACKGROUND) && (p->p_memstat_effectivepriority >= JETSAM_PRIORITY_FOREGROUND)) {          
			continue;
		}

		footprint = (uint32_t)(get_task_phys_footprint(p->task) / (1024 * 1024));
		skip = (((int32_t)footprint) <= p->p_memstat_memlimit);
#if DEVELOPMENT || DEBUG
		if (!skip && (memorystatus_jetsam_policy & kPolicyDiagnoseActive)) {
			if (p->p_memstat_state & P_MEMSTAT_DIAG_SUSPENDED) {
				continue;
			}
		}
#endif /* DEVELOPMENT || DEBUG */

#if CONFIG_FREEZE
		if (!skip) {
			if (p->p_memstat_state & P_MEMSTAT_LOCKED) {
				skip = TRUE;
			} else {
				skip = FALSE;
			}				
		}
#endif

		if (skip) {
			continue;
		} else {
			MEMORYSTATUS_DEBUG(1, "jetsam: %s pid %d [%s] - %d pages > 1 (%d)\n",
				(memorystatus_jetsam_policy & kPolicyDiagnoseActive) ? "suspending": "killing", aPid, p->p_comm, pages, hiwat);
				
			if (memorystatus_jetsam_snapshot_count == 0) {
                		memorystatus_jetsam_snapshot_procs_locked();
                		new_snapshot = TRUE;
                	}
                	
			p->p_memstat_state |= P_MEMSTAT_TERMINATED;
				
#if DEVELOPMENT || DEBUG
			if (memorystatus_jetsam_policy & kPolicyDiagnoseActive) {
			        MEMORYSTATUS_DEBUG(1, "jetsam: pid %d suspended for diagnosis - memorystatus_available_pages: %d\n", aPid, memorystatus_available_pages);
				memorystatus_update_snapshot_locked(p, kMemorystatusKilledDiagnostic);
				p->p_memstat_state |= P_MEMSTAT_DIAG_SUSPENDED;
				
				p = proc_ref_locked(p);
				proc_list_unlock();
				if (p) {
					task_suspend(p->task);
					proc_rele(p);
					killed = TRUE;
				}
				
				goto exit;
			} else
#endif /* DEVELOPMENT || DEBUG */
			{
				memorystatus_update_snapshot_locked(p, kMemorystatusKilledHiwat);
			        
				p = proc_ref_locked(p);
				proc_list_unlock();
				if (p) {
				    printf("memorystatus: jetsam killing pid %d [%s] (highwater) - memorystatus_available_pages: %d\n", 
        					aPid, (p->p_comm ? p->p_comm : "(unknown)"), memorystatus_available_pages);
				    killed = memorystatus_do_kill(p, kMemorystatusKilledHiwat);
				}
				
				/* Success? */
				if (killed) {
					proc_rele(p);
					goto exit;
				}

				/* Failure - unwind and restart. */
				proc_list_lock();
				proc_rele_locked(p);
				p->p_memstat_state &= ~P_MEMSTAT_TERMINATED;
				p->p_memstat_state |= P_MEMSTAT_ERROR;
				*errors += 1;
				i = 0;
				next_p = memorystatus_get_first_proc_locked(&i, TRUE);
			}
		}
	}
	
	proc_list_unlock();
	
exit:
	/* Clear snapshot if freshly captured and no target was found */
	if (new_snapshot && !killed) {
		memorystatus_jetsam_snapshot->entry_count = memorystatus_jetsam_snapshot_count = 0;
	}
	
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_JETSAM_HIWAT) | DBG_FUNC_END, 
	    memorystatus_available_pages, killed ? aPid : 0, 0, 0, 0);

	return killed;
}

#endif /* LEGACY_HIWATER */

static boolean_t 
memorystatus_kill_process_async(pid_t victim_pid, uint32_t cause) {
	/* TODO: allow a general async path */
	if ((victim_pid != -1) || (cause != kMemorystatusKilledVMPageShortage || cause != kMemorystatusKilledVMThrashing)) {
		return FALSE;
	}
    
	kill_under_pressure = TRUE;
	memorystatus_thread_wake();
	return TRUE;
}

static boolean_t 
memorystatus_kill_process_sync(pid_t victim_pid, uint32_t cause) {
	boolean_t res;
	uint32_t errors = 0;
    
	if (victim_pid == -1) {
		/* No pid, so kill first process */
		res = memorystatus_kill_top_process(TRUE, cause, NULL, &errors);
	} else {
		res = memorystatus_kill_specific_process(victim_pid, cause);
	}
	
	if (errors) {
		memorystatus_clear_errors();
	}
    
	if (res == TRUE) {
		/* Fire off snapshot notification */
		size_t snapshot_size = sizeof(memorystatus_jetsam_snapshot_t) + 
			sizeof(memorystatus_jetsam_snapshot_entry_t) * memorystatus_jetsam_snapshot_count;
		memorystatus_jetsam_snapshot->notification_time = mach_absolute_time();
		memorystatus_send_note(kMemorystatusSnapshotNote, &snapshot_size, sizeof(snapshot_size));
	}
    
	return res;
}

boolean_t 
memorystatus_kill_on_VM_page_shortage(boolean_t async) {
	if (async) {
		return memorystatus_kill_process_async(-1, kMemorystatusKilledVMPageShortage);
	} else {
		return memorystatus_kill_process_sync(-1, kMemorystatusKilledVMPageShortage);
	}
}

boolean_t
memorystatus_kill_on_VM_thrashing(boolean_t async) {
	if (async) {
		return memorystatus_kill_process_async(-1, kMemorystatusKilledVMThrashing);
	} else {
		return memorystatus_kill_process_sync(-1, kMemorystatusKilledVMThrashing);
	}
}

boolean_t 
memorystatus_kill_on_vnode_limit(void) {
	return memorystatus_kill_process_sync(-1, kMemorystatusKilledVnodes);
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
memorystatus_freeze_top_process(boolean_t *memorystatus_freeze_swap_low)
{
	pid_t aPid = 0;
	int ret = -1;
	proc_t p = PROC_NULL, next_p = PROC_NULL;
	unsigned int i = 0;

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_FREEZE) | DBG_FUNC_START,
		memorystatus_available_pages, 0, 0, 0, 0);

	proc_list_lock();
	
	next_p = memorystatus_get_first_proc_locked(&i, TRUE);
	while (next_p) {
		kern_return_t kr;
		uint32_t purgeable, wired, clean, dirty;
		boolean_t shared;
		uint32_t pages;
		uint32_t max_pages = 0;
		uint32_t state;
		
		p = next_p;
		next_p = memorystatus_get_next_proc_locked(&i, p, TRUE);

		aPid = p->p_pid;
		state = p->p_memstat_state;

		/* Ensure the process is eligible for freezing */
		if ((state & (P_MEMSTAT_TERMINATED | P_MEMSTAT_LOCKED | P_MEMSTAT_FROZEN)) || !(state & P_MEMSTAT_SUSPENDED)) {
			continue; // with lock held
		}
					
		/* Only freeze processes meeting our minimum resident page criteria */
		memorystatus_get_task_page_counts(p->task, &pages, NULL);
		if (pages < memorystatus_freeze_pages_min) {
			continue; // with lock held
		} 

		if (DEFAULT_FREEZER_IS_ACTIVE || DEFAULT_FREEZER_COMPRESSED_PAGER_IS_ACTIVE) {
			/* Ensure there's enough free space to freeze this process. */			
			max_pages = MIN(default_pager_swap_pages_free(), memorystatus_freeze_pages_max);
			if (max_pages < memorystatus_freeze_pages_min) {
				*memorystatus_freeze_swap_low = TRUE;
				proc_list_unlock();
				goto exit;
			}
		} else {
			max_pages = UINT32_MAX - 1;
		}
		
		/* Mark as locked temporarily to avoid kill */
		p->p_memstat_state |= P_MEMSTAT_LOCKED;

		p = proc_ref_locked(p);
		proc_list_unlock();        
		if (!p) {
			goto exit;
		}
        
		kr = task_freeze(p->task, &purgeable, &wired, &clean, &dirty, max_pages, &shared, FALSE);
		
		MEMORYSTATUS_DEBUG(1, "memorystatus_freeze_top_process: task_freeze %s for pid %d [%s] - "
    			"memorystatus_pages: %d, purgeable: %d, wired: %d, clean: %d, dirty: %d, shared %d, free swap: %d\n", 
       		(kr == KERN_SUCCESS) ? "SUCCEEDED" : "FAILED", aPid, (p->p_comm ? p->p_comm : "(unknown)"), 
       		memorystatus_available_pages, purgeable, wired, clean, dirty, shared, default_pager_swap_pages_free());
     
		proc_list_lock();
		p->p_memstat_state &= ~P_MEMSTAT_LOCKED;
		
		/* Success? */
		if (KERN_SUCCESS == kr) {
			memorystatus_freeze_entry_t data = { aPid, TRUE, dirty };
			
			memorystatus_frozen_count++;
			
			p->p_memstat_state |= (P_MEMSTAT_FROZEN | (shared ? 0: P_MEMSTAT_NORECLAIM));
		
			/* Update stats */
			for (i = 0; i < sizeof(throttle_intervals) / sizeof(struct throttle_interval_t); i++) {
       				throttle_intervals[i].pageouts += dirty;
			}
		
			memorystatus_freeze_pageouts += dirty;
			memorystatus_freeze_count++;

			proc_list_unlock();

			memorystatus_send_note(kMemorystatusFreezeNote, &data, sizeof(data));

			/* Return the number of reclaimed pages */
			ret = dirty;

		} else {
			proc_list_unlock();
		}
        
		proc_rele(p);
		goto exit;
	}
	
	proc_list_unlock();
	
exit:
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_FREEZE) | DBG_FUNC_END,
		memorystatus_available_pages, aPid, 0, 0, 0);
	
	return ret;
}

static inline boolean_t 
memorystatus_can_freeze_processes(void) 
{
	boolean_t ret;
	
	proc_list_lock();
	
	if (memorystatus_suspended_count) {
		uint32_t average_resident_pages, estimated_processes;
        
		/* Estimate the number of suspended processes we can fit */
		average_resident_pages = memorystatus_suspended_footprint_total / memorystatus_suspended_count;
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
				
	proc_list_unlock();
	
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
				memorystatus_freeze_top_process(&memorystatus_freeze_swap_low);
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

#if CONFIG_JETSAM && VM_PRESSURE_EVENTS

boolean_t
memorystatus_warn_process(pid_t pid) {
	return (vm_dispatch_pressure_note_to_pid(pid, FALSE) == 0);
}

static inline boolean_t
memorystatus_update_pressure_locked(boolean_t *pressured) {
	vm_pressure_level_t old_level, new_level;
	
	old_level = memorystatus_vm_pressure_level;
	
	if (memorystatus_available_pages > memorystatus_available_pages_pressure) {
		/* Too many free pages */
		new_level = kVMPressureNormal;
	}	
#if CONFIG_FREEZE
	else if (memorystatus_frozen_count > 0) {
		/* Frozen processes exist */
		new_level = kVMPressureNormal;	        
	}
#endif
	else if (memorystatus_suspended_count > MEMORYSTATUS_SUSPENDED_THRESHOLD) {
		/* Too many supended processes */
		new_level = kVMPressureNormal;
	}
	else if (memorystatus_suspended_count > 0) {
		/* Some suspended processes - warn */
		new_level = kVMPressureWarning;
	}
    else {
		/* Otherwise, pressure level is urgent */
		new_level = kVMPressureUrgent;
	}
	
	*pressured = (new_level != kVMPressureNormal);
	
	/* Did the pressure level change? */
	if (old_level != new_level) {
		MEMORYSTATUS_DEBUG(1, "memorystatus_update_pressure_locked(): memory pressure changed %d -> %d; memorystatus_available_pages: %d\n ", 
		    old_level, new_level, memorystatus_available_pages);
		memorystatus_vm_pressure_level = new_level;
		return TRUE;
	}
	
	return FALSE;
}

kern_return_t
memorystatus_update_vm_pressure(boolean_t target_foreground) {
	boolean_t pressure_changed, pressured;
	boolean_t warn = FALSE;

	/* 
	 * Centralised pressure handling routine. Called from:
	 * - The main jetsam thread. In this case, we update the pressure level and dispatch warnings to the foreground 
	 *   process *only*, each time the available page % drops.
	 * - The pageout scan path. In this scenario, every other registered process is targeted in footprint order.
	 *
	 * This scheme guarantees delivery to the foreground app, while providing for warnings to the remaining processes
	 * driven by the pageout scan.
	 */

	MEMORYSTATUS_DEBUG(1, "memorystatus_update_vm_pressure(): foreground %d; available %d, critical %d, pressure %d\n", 
        	target_foreground, memorystatus_available_pages, memorystatus_available_pages_critical, memorystatus_available_pages_pressure);

	proc_list_lock();

	pressure_changed = memorystatus_update_pressure_locked(&pressured);
	
	if (pressured) {
		if (target_foreground) {
			if (memorystatus_available_pages != memorystatus_last_foreground_pressure_pages) {
				if (memorystatus_available_pages < memorystatus_last_foreground_pressure_pages) {
					warn = TRUE;
				}
				memorystatus_last_foreground_pressure_pages = memorystatus_available_pages;
			}
		} else {
			warn = TRUE;
		}
	} else if (pressure_changed) {
		memorystatus_last_foreground_pressure_pages =  (unsigned int)-1;
	}
	
	proc_list_unlock();

	/* Target foreground processes if specified */
	if (warn) {
		if (target_foreground) {
			MEMORYSTATUS_DEBUG(1, "memorystatus_update_vm_pressure(): invoking vm_find_pressure_foreground_candidates()\n");
			vm_find_pressure_foreground_candidates();
		} else {
			MEMORYSTATUS_DEBUG(1, "memorystatus_update_vm_pressure(): invoking vm_find_pressure_candidate()\n");
			/* Defer to VM code. This can race with the foreground priority, but
			 * it's preferable to holding onto locks for an extended period. */
			vm_find_pressure_candidate();
		}
	}
    
	/* Dispatch the global kevent to privileged listeners */
	if (pressure_changed) {
		memorystatus_issue_pressure_kevent(pressured);
	}

 	return KERN_SUCCESS;
}

int
memorystatus_send_pressure_note(pid_t pid) {
 	MEMORYSTATUS_DEBUG(1, "memorystatus_send_pressure_note(): pid %d\n", pid);      
 	return memorystatus_send_note(kMemorystatusPressureNote, &pid, sizeof(pid));
}

boolean_t
memorystatus_bg_pressure_eligible(proc_t p) {
 	boolean_t eligible = FALSE;
        
	proc_list_lock();
	
	MEMORYSTATUS_DEBUG(1, "memorystatus_bg_pressure_eligible: pid %d, state 0x%x\n", p->p_pid, p->p_memstat_state);
        
 	/* Foreground processes have already been dealt with at this point, so just test for eligibility */
 	if (!(p->p_memstat_state & (P_MEMSTAT_TERMINATED | P_MEMSTAT_LOCKED | P_MEMSTAT_SUSPENDED | P_MEMSTAT_FROZEN))) {
                eligible = TRUE;
	}
        
	proc_list_unlock();
	
 	return eligible;
}

boolean_t
memorystatus_is_foreground_locked(proc_t p) {
        return ((p->p_memstat_effectivepriority == JETSAM_PRIORITY_FOREGROUND) || 
                (p->p_memstat_effectivepriority == JETSAM_PRIORITY_FOREGROUND_SUPPORT));
}

#else /* CONFIG_JETSAM && VM_PRESSURE_EVENTS */

/*
 * Trigger levels to test the mechanism.
 * Can be used via a sysctl.
 */
#define TEST_LOW_MEMORY_TRIGGER_ONE		1
#define TEST_LOW_MEMORY_TRIGGER_ALL		2
#define TEST_PURGEABLE_TRIGGER_ONE		3
#define TEST_PURGEABLE_TRIGGER_ALL		4
#define TEST_LOW_MEMORY_PURGEABLE_TRIGGER_ONE	5
#define TEST_LOW_MEMORY_PURGEABLE_TRIGGER_ALL	6

boolean_t		memorystatus_manual_testing_on = FALSE;
vm_pressure_level_t	memorystatus_manual_testing_level = kVMPressureNormal;

extern struct knote *
vm_pressure_select_optimal_candidate_to_notify(struct klist *, int);

extern
kern_return_t vm_pressure_notification_without_levels(void);

extern void vm_pressure_klist_lock(void);
extern void vm_pressure_klist_unlock(void);

extern void vm_reset_active_list(void);

extern void delay(int);

#define INTER_NOTIFICATION_DELAY	(250000)	/* .25 second */

void memorystatus_on_pageout_scan_end(void) {
	/* No-op */
}

/*
 * kn_max - knote
 *
 * knote_pressure_level - to check if the knote is registered for this notification level.
 *
 * task	- task whose bits we'll be modifying
 *
 * pressure_level_to_clear - if the task has been notified of this past level, clear that notification bit so that if/when we revert to that level, the task will be notified again.
 *
 * pressure_level_to_set - the task is about to be notified of this new level. Update the task's bit notification information appropriately.
 *
 */
boolean_t
is_knote_registered_modify_task_pressure_bits(struct knote*, int, task_t, vm_pressure_level_t, vm_pressure_level_t);

boolean_t
is_knote_registered_modify_task_pressure_bits(struct knote *kn_max, int knote_pressure_level, task_t task, vm_pressure_level_t pressure_level_to_clear, vm_pressure_level_t pressure_level_to_set)
{
	if (kn_max->kn_sfflags & knote_pressure_level) {

		if (task_has_been_notified(task, pressure_level_to_clear) == TRUE) {

			task_clear_has_been_notified(task, pressure_level_to_clear);
		}

		task_mark_has_been_notified(task, pressure_level_to_set);
		return TRUE;
	}

	return FALSE;
}

extern kern_return_t vm_pressure_notify_dispatch_vm_clients(void);

kern_return_t
memorystatus_update_vm_pressure(boolean_t target_best_process) 
{
	struct knote			*kn_max = NULL;
        pid_t				target_pid = -1;
        struct klist			dispatch_klist = { NULL };
	proc_t				target_proc = PROC_NULL;
	static vm_pressure_level_t 	level_snapshot = kVMPressureNormal;
	struct task			*task = NULL;
	boolean_t			found_candidate = FALSE;

	while (1) {
	
		/*
		 * There is a race window here. But it's not clear
		 * how much we benefit from having extra synchronization.
		 */
		level_snapshot = memorystatus_vm_pressure_level;

		memorystatus_klist_lock();
		kn_max = vm_pressure_select_optimal_candidate_to_notify(&memorystatus_klist, level_snapshot);

        	if (kn_max == NULL) {
			memorystatus_klist_unlock();

			/*
			 * No more level-based clients to notify.
			 * Try the non-level based notification clients.
			 *	
			 * However, these non-level clients don't understand
			 * the "return-to-normal" notification.
			 *
			 * So don't consider them for those notifications. Just
			 * return instead.
			 *
			 */

			if (level_snapshot != kVMPressureNormal) {
				goto try_dispatch_vm_clients;
			} else {
				return KERN_FAILURE;
			}	
		}
		
		target_proc = kn_max->kn_kq->kq_p;
		
		proc_list_lock();
		if (target_proc != proc_ref_locked(target_proc)) {
			target_proc = PROC_NULL;
			proc_list_unlock();
			memorystatus_klist_unlock();
			continue;
		}
		proc_list_unlock();
		memorystatus_klist_unlock();
		
		target_pid = target_proc->p_pid;

		task = (struct task *)(target_proc->task);
	
		if (level_snapshot != kVMPressureNormal) {

			if (level_snapshot == kVMPressureWarning || level_snapshot == kVMPressureUrgent) {

				if (is_knote_registered_modify_task_pressure_bits(kn_max, NOTE_MEMORYSTATUS_PRESSURE_WARN, task, kVMPressureCritical, kVMPressureWarning) == TRUE) {
					found_candidate = TRUE;
				}
			} else {
				if (level_snapshot == kVMPressureCritical) {
				
					if (is_knote_registered_modify_task_pressure_bits(kn_max, NOTE_MEMORYSTATUS_PRESSURE_CRITICAL, task, kVMPressureWarning, kVMPressureCritical) == TRUE) {
						found_candidate = TRUE;
					}
				}
			}
		} else {
			if (kn_max->kn_sfflags & NOTE_MEMORYSTATUS_PRESSURE_NORMAL) {

				task_clear_has_been_notified(task, kVMPressureWarning);
				task_clear_has_been_notified(task, kVMPressureCritical);

				found_candidate = TRUE;
			}
		}

		if (found_candidate == FALSE) {
			continue;
		}

		memorystatus_klist_lock();
		KNOTE_DETACH(&memorystatus_klist, kn_max);
		KNOTE_ATTACH(&dispatch_klist, kn_max);
		memorystatus_klist_unlock();

		KNOTE(&dispatch_klist, (level_snapshot != kVMPressureNormal) ? kMemorystatusPressure : kMemorystatusNoPressure);

		memorystatus_klist_lock();
		KNOTE_DETACH(&dispatch_klist, kn_max);
		KNOTE_ATTACH(&memorystatus_klist, kn_max);
		memorystatus_klist_unlock();

		microuptime(&target_proc->vm_pressure_last_notify_tstamp);
		proc_rele(target_proc);

		if (target_best_process == TRUE) {
			break;
		}

try_dispatch_vm_clients:
		if (level_snapshot != kVMPressureNormal) {
			/* 
			 * Wake up idle-exit thread.
			 * Targets one process per invocation.
			 *
			 * TODO: memorystatus_idle_exit_from_VM should return FALSE once it's
			 * done with all idle-exitable processes. Currently, we will exit this
			 * loop when we are done with notification clients (level and non-level based)
			 * but we may still have some idle-exitable processes around.
			 *
			 */
			memorystatus_idle_exit_from_VM();

			if ((vm_pressure_notify_dispatch_vm_clients() == KERN_FAILURE) && (kn_max == NULL)) {
				/*
				 * kn_max == NULL i.e. we didn't find any eligible clients for the level-based notifications
				 * AND
				 * we have failed to find any eligible clients for the non-level based notifications too.
				 * So, we are done.
				 */

				return KERN_FAILURE;
			}
		}

		if (memorystatus_manual_testing_on == FALSE) {
			delay(INTER_NOTIFICATION_DELAY);
		}
	}

	return KERN_SUCCESS;
}

vm_pressure_level_t
convert_internal_pressure_level_to_dispatch_level(vm_pressure_level_t);

vm_pressure_level_t
convert_internal_pressure_level_to_dispatch_level(vm_pressure_level_t internal_pressure_level)
{
	vm_pressure_level_t	dispatch_level = NOTE_MEMORYSTATUS_PRESSURE_NORMAL;
	
	switch (internal_pressure_level) {

		case kVMPressureNormal:
		{
			dispatch_level = NOTE_MEMORYSTATUS_PRESSURE_NORMAL;
			break;
		}

		case kVMPressureWarning:
		case kVMPressureUrgent:
		{
			dispatch_level = NOTE_MEMORYSTATUS_PRESSURE_WARN;
			break;
		}

		case kVMPressureCritical:
		{
			dispatch_level = NOTE_MEMORYSTATUS_PRESSURE_CRITICAL;
			break;
		}

		default:
			break;
	}

	return dispatch_level;
}

static int
sysctl_memorystatus_vm_pressure_level SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	
	vm_pressure_level_t dispatch_level = convert_internal_pressure_level_to_dispatch_level(memorystatus_vm_pressure_level);

	return SYSCTL_OUT(req, &dispatch_level, sizeof(dispatch_level));
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_vm_pressure_level, CTLTYPE_INT|CTLFLAG_RD|CTLFLAG_LOCKED,
    0, 0, &sysctl_memorystatus_vm_pressure_level, "I", "");


extern int memorystatus_purge_on_warning;
extern int memorystatus_purge_on_critical;

static int
sysctl_memorypressure_manual_trigger SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)

	int level = 0;
	int error = 0;
	int pressure_level = 0;
	int trigger_request = 0;
	int force_purge;

	error = sysctl_handle_int(oidp, &level, 0, req);
	if (error || !req->newptr) {
		return (error);
	}

	memorystatus_manual_testing_on = TRUE;

	trigger_request = (level >> 16) & 0xFFFF;
	pressure_level = (level & 0xFFFF); 

	if (trigger_request < TEST_LOW_MEMORY_TRIGGER_ONE ||
	    trigger_request > TEST_LOW_MEMORY_PURGEABLE_TRIGGER_ALL) {
		return EINVAL;
	}
	switch (pressure_level) {
	case NOTE_MEMORYSTATUS_PRESSURE_NORMAL:
	case NOTE_MEMORYSTATUS_PRESSURE_WARN:
	case NOTE_MEMORYSTATUS_PRESSURE_CRITICAL:
		break;
	default:
		return EINVAL;
	}

	/*
	 * The pressure level is being set from user-space.
	 * And user-space uses the constants in sys/event.h
	 * So we translate those events to our internal levels here.
	 */
	if (pressure_level == NOTE_MEMORYSTATUS_PRESSURE_NORMAL) {

		memorystatus_manual_testing_level = kVMPressureNormal;
		force_purge = 0;

	} else if (pressure_level == NOTE_MEMORYSTATUS_PRESSURE_WARN) {

		memorystatus_manual_testing_level = kVMPressureWarning;
		force_purge = memorystatus_purge_on_warning;

	} else if (pressure_level == NOTE_MEMORYSTATUS_PRESSURE_CRITICAL) {

		memorystatus_manual_testing_level = kVMPressureCritical;
		force_purge = memorystatus_purge_on_critical;
	}

	memorystatus_vm_pressure_level = memorystatus_manual_testing_level;

	/* purge according to the new pressure level */
	switch (trigger_request) {
	case TEST_PURGEABLE_TRIGGER_ONE:
	case TEST_LOW_MEMORY_PURGEABLE_TRIGGER_ONE:
		if (force_purge == 0) {
			/* no purging requested */
			break;
		}
		vm_purgeable_object_purge_one_unlocked(force_purge);
		break;
	case TEST_PURGEABLE_TRIGGER_ALL:
	case TEST_LOW_MEMORY_PURGEABLE_TRIGGER_ALL:
		if (force_purge == 0) {
			/* no purging requested */
			break;
		}
		while (vm_purgeable_object_purge_one_unlocked(force_purge));
		break;
	}

	if ((trigger_request == TEST_LOW_MEMORY_TRIGGER_ONE) ||
	    (trigger_request == TEST_LOW_MEMORY_PURGEABLE_TRIGGER_ONE)) {

		memorystatus_update_vm_pressure(TRUE);
	}

	if ((trigger_request == TEST_LOW_MEMORY_TRIGGER_ALL) ||
	    (trigger_request == TEST_LOW_MEMORY_PURGEABLE_TRIGGER_ALL)) {

		while (memorystatus_update_vm_pressure(FALSE) == KERN_SUCCESS) {
			continue;
		}
	}
		
	if (pressure_level == NOTE_MEMORYSTATUS_PRESSURE_NORMAL) {
		memorystatus_manual_testing_on = FALSE;
				
		vm_pressure_klist_lock();
		vm_reset_active_list();
		vm_pressure_klist_unlock();
	} else {

		vm_pressure_klist_lock();
		vm_pressure_notification_without_levels();
		vm_pressure_klist_unlock();
	}

	return 0;
}

SYSCTL_PROC(_kern, OID_AUTO, memorypressure_manual_trigger, CTLTYPE_INT|CTLFLAG_WR|CTLFLAG_LOCKED|CTLFLAG_MASKED,
    0, 0, &sysctl_memorypressure_manual_trigger, "I", "");


extern int memorystatus_purge_on_warning;
extern int memorystatus_purge_on_urgent;
extern int memorystatus_purge_on_critical;

SYSCTL_INT(_kern, OID_AUTO, memorystatus_purge_on_warning, CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_purge_on_warning, 0, "");
SYSCTL_INT(_kern, OID_AUTO, memorystatus_purge_on_urgent, CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_purge_on_urgent, 0, "");
SYSCTL_INT(_kern, OID_AUTO, memorystatus_purge_on_critical, CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_purge_on_critical, 0, "");


#endif /* CONFIG_JETSAM && VM_PRESSURE_EVENTS */

/* Return both allocated and actual size, since there's a race between allocation and list compilation */
static int
memorystatus_get_priority_list(memorystatus_priority_entry_t **list_ptr, size_t *buffer_size, size_t *list_size, boolean_t size_only) 
{
 	uint32_t list_count, i = 0;
	memorystatus_priority_entry_t *list_entry;
	proc_t p;

 	list_count = memorystatus_list_count;
	*list_size = sizeof(memorystatus_priority_entry_t) * list_count;

	/* Just a size check? */
	if (size_only) {
		return 0;
	}
	
	/* Otherwise, validate the size of the buffer */
	if (*buffer_size < *list_size) {
		return EINVAL;
	}

 	*list_ptr = (memorystatus_priority_entry_t*)kalloc(*list_size);
	if (!list_ptr) {
		return ENOMEM;
	}

	memset(*list_ptr, 0, *list_size);

	*buffer_size = *list_size;
	*list_size = 0;

	list_entry = *list_ptr;

	proc_list_lock();

	p = memorystatus_get_first_proc_locked(&i, TRUE);
	while (p && (*list_size < *buffer_size)) {
		list_entry->pid = p->p_pid;
		list_entry->priority = p->p_memstat_effectivepriority;
		list_entry->user_data = p->p_memstat_userdata;
#if LEGACY_HIWATER
		if (((p->p_memstat_state & P_MEMSTAT_MEMLIMIT_BACKGROUND) && (p->p_memstat_effectivepriority >= JETSAM_PRIORITY_FOREGROUND)) ||
		     (p->p_memstat_memlimit <= 0)) {
			task_get_phys_footprint_limit(p->task, &list_entry->limit);  
		} else {
			list_entry->limit = p->p_memstat_memlimit;
		}
#else
		task_get_phys_footprint_limit(p->task, &list_entry->limit);
#endif
		list_entry->state = memorystatus_build_state(p);
		list_entry++;

		*list_size += sizeof(memorystatus_priority_entry_t);
		
		p = memorystatus_get_next_proc_locked(&i, p, TRUE);
	}
	
	proc_list_unlock();
	
	MEMORYSTATUS_DEBUG(1, "memorystatus_get_priority_list: returning %lu for size\n", (unsigned long)*list_size);
	
	return 0;
}

static int
memorystatus_cmd_get_priority_list(user_addr_t buffer, size_t buffer_size, int32_t *retval) {
	int error = EINVAL;
	boolean_t size_only;
	memorystatus_priority_entry_t *list = NULL;
	size_t list_size;
	
	size_only = ((buffer == USER_ADDR_NULL) ? TRUE: FALSE);
		
	error = memorystatus_get_priority_list(&list, &buffer_size, &list_size, size_only);
	if (error) {
		goto out;
	}

	if (!size_only) {
		error = copyout(list, buffer, list_size);
	}
	
	if (error == 0) {
		*retval = list_size;
	}
out:

	if (list) {
		kfree(list, buffer_size);
	}

	return error;
}

#if CONFIG_JETSAM

static void 
memorystatus_clear_errors(void)
{
	proc_t p;
	unsigned int i = 0;

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_CLEAR_ERRORS) | DBG_FUNC_START, 0, 0, 0, 0, 0);
    
	proc_list_lock();
    
	p = memorystatus_get_first_proc_locked(&i, TRUE);
	while (p) {
		if (p->p_memstat_state & P_MEMSTAT_ERROR) {
			p->p_memstat_state &= ~P_MEMSTAT_ERROR;
		}
		p = memorystatus_get_next_proc_locked(&i, p, TRUE);
	}
	
	proc_list_unlock();

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_CLEAR_ERRORS) | DBG_FUNC_END, 0, 0, 0, 0, 0);
}

static void
memorystatus_update_levels_locked(boolean_t critical_only) {
	memorystatus_available_pages_critical = memorystatus_available_pages_critical_base;
#if !LATENCY_JETSAM
	{
		// If there's an entry in the first bucket, we have idle processes
		memstat_bucket_t *first_bucket = &memstat_bucket[JETSAM_PRIORITY_IDLE];
		if (first_bucket->count) {
			memorystatus_available_pages_critical += memorystatus_available_pages_critical_idle_offset;
		}
	}
#endif
#if DEBUG || DEVELOPMENT
	if (memorystatus_jetsam_policy & kPolicyDiagnoseActive) {
		memorystatus_available_pages_critical += memorystatus_jetsam_policy_offset_pages_diagnostic;
	}
#endif
        
	if (critical_only) {
		return;
	}
	
#if VM_PRESSURE_EVENTS
	memorystatus_available_pages_pressure = (pressure_threshold_percentage / delta_percentage) * memorystatus_delta;
#if DEBUG || DEVELOPMENT
	if (memorystatus_jetsam_policy & kPolicyDiagnoseActive) {
		memorystatus_available_pages_pressure += memorystatus_jetsam_policy_offset_pages_diagnostic;
	}
#endif
#endif
}

static int
memorystatus_get_snapshot(memorystatus_jetsam_snapshot_t **snapshot, size_t *snapshot_size, boolean_t size_only) {
	size_t input_size = *snapshot_size;
	
	if (memorystatus_jetsam_snapshot_count > 0) {
		*snapshot_size = sizeof(memorystatus_jetsam_snapshot_t) + (sizeof(memorystatus_jetsam_snapshot_entry_t) * (memorystatus_jetsam_snapshot_count));
	} else {
		*snapshot_size = 0;
	}

	if (size_only) {
		return 0;
	}

	if (input_size < *snapshot_size) {
		return EINVAL;
	}

	*snapshot = memorystatus_jetsam_snapshot;
	
	MEMORYSTATUS_DEBUG(1, "memorystatus_snapshot: returning %ld for size\n", (long)*snapshot_size);
	
	return 0;
}

static int
memorystatus_cmd_get_jetsam_snapshot(user_addr_t buffer, size_t buffer_size, int32_t *retval) {
	int error = EINVAL;
	boolean_t size_only;
	memorystatus_jetsam_snapshot_t *snapshot;
	
	size_only = ((buffer == USER_ADDR_NULL) ? TRUE : FALSE);
	
	error = memorystatus_get_snapshot(&snapshot, &buffer_size, size_only);
	if (error) {
		goto out;
	}

	/* Copy out and reset */
	if (!size_only) {
		if ((error = copyout(snapshot, buffer, buffer_size)) == 0) {
			snapshot->entry_count = memorystatus_jetsam_snapshot_count = 0;
		}
	}

	if (error == 0) {
		*retval = buffer_size;
	}
out:
	return error;
}

static int
memorystatus_cmd_set_priority_properties(pid_t pid, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval) {
	const uint32_t MAX_ENTRY_COUNT = 2; /* Cap the entry count */
	
	int error;
	uint32_t i;
	uint32_t entry_count;
	memorystatus_priority_properties_t *entries;
	
	/* Validate inputs */
	if ((pid == 0) || (buffer == USER_ADDR_NULL) || (buffer_size == 0)) {
		return EINVAL;
	}
	
	/* Make sure the buffer is a multiple of the entry size, and that an excessive size isn't specified */
	entry_count = (buffer_size / sizeof(memorystatus_priority_properties_t));
	if (((buffer_size % sizeof(memorystatus_priority_properties_t)) != 0) || (entry_count > MAX_ENTRY_COUNT)) {
		return EINVAL;
	}
		
	entries = (memorystatus_priority_properties_t *)kalloc(buffer_size);
		
	error = copyin(buffer, entries, buffer_size);
	
	for (i = 0; i < entry_count; i++) {
		proc_t p;
                
		if (error) {
			break;
		}
		
		p = proc_find(pid);
		if (!p) {
			error = ESRCH;
			break;         
		}
		
		if (p->p_memstat_state & P_MEMSTAT_INTERNAL) {
			error = EPERM;
			proc_rele(p);
			break;	        
		}
		
		error = memorystatus_update(p, entries[i].priority, entries[i].user_data, FALSE, FALSE, 0, 0);
		proc_rele(p);
	}
	
	kfree(entries, buffer_size);
	
	return error;
}

static int
memorystatus_cmd_get_pressure_status(int32_t *retval) {	
	int error;
	
	/* Need privilege for check */
	error = priv_check_cred(kauth_cred_get(), PRIV_VM_PRESSURE, 0);
	if (error) {
		return (error);
	}
	
	/* Inherently racy, so it's not worth taking a lock here */
	*retval = (kVMPressureNormal != memorystatus_vm_pressure_level) ? 1 : 0;
	
	return error;
}

static int
memorystatus_cmd_set_jetsam_high_water_mark(pid_t pid, int32_t high_water_mark, __unused int32_t *retval) {
	int error = 0;
        
	proc_t p = proc_find(pid);
	if (!p) {
		return ESRCH;
	}
        
	if (high_water_mark <= 0) {
		high_water_mark = -1; /* Disable */
	}
    
	proc_list_lock();
    
	if (p->p_memstat_state & P_MEMSTAT_INTERNAL) {
		error = EPERM;
		goto exit;	        
	}
    
	p->p_memstat_memlimit = high_water_mark;
	if (memorystatus_highwater_enabled) {
        	if (p->p_memstat_state & P_MEMSTAT_MEMLIMIT_BACKGROUND) {
        		memorystatus_update_priority_locked(p, p->p_memstat_effectivepriority);
        	} else {
        		error = (task_set_phys_footprint_limit_internal(p->task, high_water_mark, NULL, TRUE) == 0) ? 0 : EINVAL;
        	}
	}

exit:
	proc_list_unlock();
	proc_rele(p);
	
	return error;
}

#endif /* CONFIG_JETSAM */

int
memorystatus_control(struct proc *p __unused, struct memorystatus_control_args *args, int *ret) {
	int error = EINVAL;

#if !CONFIG_JETSAM
	#pragma unused(ret)
#endif

	/* Root only for now */
	if (!kauth_cred_issuser(kauth_cred_get())) {
		error = EPERM;
		goto out;
	}
	
	/* Sanity check */
	if (args->buffersize > MEMORYSTATUS_BUFFERSIZE_MAX) {
		error = EINVAL;
		goto out;
	}

	switch (args->command) {
	case MEMORYSTATUS_CMD_GET_PRIORITY_LIST:
		error = memorystatus_cmd_get_priority_list(args->buffer, args->buffersize, ret);
		break;
#if CONFIG_JETSAM
	case MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES:
		error = memorystatus_cmd_set_priority_properties(args->pid, args->buffer, args->buffersize, ret);
		break;
	case MEMORYSTATUS_CMD_GET_JETSAM_SNAPSHOT:
		error = memorystatus_cmd_get_jetsam_snapshot(args->buffer, args->buffersize, ret);
		break;
	case MEMORYSTATUS_CMD_GET_PRESSURE_STATUS:
		error = memorystatus_cmd_get_pressure_status(ret);
		break;
	case MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK:
		/* TODO: deprecate. Keeping it in as there's no pid based way to set the ledger limit right now. */
		error = memorystatus_cmd_set_jetsam_high_water_mark(args->pid, (int32_t)args->flags, ret);
		break;
	/* Test commands */
#if DEVELOPMENT || DEBUG
	case MEMORYSTATUS_CMD_TEST_JETSAM:
		error = memorystatus_kill_process_sync(args->pid, kMemorystatusKilled) ? 0 : EINVAL;
		break;
	case MEMORYSTATUS_CMD_SET_JETSAM_PANIC_BITS:
		error = memorystatus_cmd_set_panic_bits(args->buffer, args->buffersize);
		break;
#endif /* DEVELOPMENT || DEBUG */
#endif /* CONFIG_JETSAM */
	default:
		break;
	}

out:
	return error;
}


static int
filt_memorystatusattach(struct knote *kn)
{	
	kn->kn_flags |= EV_CLEAR;
	return memorystatus_knote_register(kn);
}

static void
filt_memorystatusdetach(struct knote *kn)
{
	memorystatus_knote_unregister(kn);
}

static int
filt_memorystatus(struct knote *kn __unused, long hint)
{
	if (hint) {
		switch (hint) {
		case kMemorystatusNoPressure:
			if (kn->kn_sfflags & NOTE_MEMORYSTATUS_PRESSURE_NORMAL) {
				kn->kn_fflags |= NOTE_MEMORYSTATUS_PRESSURE_NORMAL;
			}
			break;
		case kMemorystatusPressure:
			if (memorystatus_vm_pressure_level == kVMPressureWarning || memorystatus_vm_pressure_level == kVMPressureUrgent) {
				if (kn->kn_sfflags & NOTE_MEMORYSTATUS_PRESSURE_WARN) {
					kn->kn_fflags |= NOTE_MEMORYSTATUS_PRESSURE_WARN;
				}
			} else if (memorystatus_vm_pressure_level == kVMPressureCritical) {

				if (kn->kn_sfflags & NOTE_MEMORYSTATUS_PRESSURE_CRITICAL) {
					kn->kn_fflags |= NOTE_MEMORYSTATUS_PRESSURE_CRITICAL;
				}
			}
			break;
		default:
			break;
		}
	}
	
	return (kn->kn_fflags != 0);
}

static void
memorystatus_klist_lock(void) {
	lck_mtx_lock(&memorystatus_klist_mutex);
}

static void
memorystatus_klist_unlock(void) {
	lck_mtx_unlock(&memorystatus_klist_mutex);
}

void 
memorystatus_kevent_init(lck_grp_t *grp, lck_attr_t *attr) {
	lck_mtx_init(&memorystatus_klist_mutex, grp, attr);
	klist_init(&memorystatus_klist);
}

int
memorystatus_knote_register(struct knote *kn) {
	int error = 0;
	
	memorystatus_klist_lock();
	
	if (kn->kn_sfflags & (NOTE_MEMORYSTATUS_PRESSURE_NORMAL | NOTE_MEMORYSTATUS_PRESSURE_WARN | NOTE_MEMORYSTATUS_PRESSURE_CRITICAL)) {

#if CONFIG_JETSAM && VM_PRESSURE_EVENTS
		/* Need a privilege to register */
		error = priv_check_cred(kauth_cred_get(), PRIV_VM_PRESSURE, 0);
#endif /* CONFIG_JETSAM && VM_PRESSURE_EVENTS */

		if (!error) {
			KNOTE_ATTACH(&memorystatus_klist, kn);
		}
	} else {	  
		error = ENOTSUP;
	}
	
	memorystatus_klist_unlock();
	
	return error;
}

void
memorystatus_knote_unregister(struct knote *kn __unused) {	
	memorystatus_klist_lock();
	KNOTE_DETACH(&memorystatus_klist, kn);
	memorystatus_klist_unlock();
}

#if CONFIG_JETSAM && VM_PRESSURE_EVENTS
static boolean_t
memorystatus_issue_pressure_kevent(boolean_t pressured) {
	memorystatus_klist_lock();
	KNOTE(&memorystatus_klist, pressured ? kMemorystatusPressure : kMemorystatusNoPressure);
	memorystatus_klist_unlock();
	return TRUE;
}

#endif /* CONFIG_JETSAM && VM_PRESSURE_EVENTS */

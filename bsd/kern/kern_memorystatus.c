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
#include <kern/locks.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/host.h>
#include <kern/policy_internal.h>

#include <IOKit/IOBSD.h>

#include <libkern/libkern.h>
#include <mach/coalition.h>
#include <mach/mach_time.h>
#include <mach/task.h>
#include <mach/host_priv.h>
#include <mach/mach_host.h>
#include <pexpert/pexpert.h>
#include <sys/coalition.h>
#include <sys/kern_event.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <sys/reason.h>
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

#include <mach/machine/sdt.h>

/* For logging clarity */
static const char *jetsam_kill_cause_name[] = {
	""                      ,
	"jettisoned"		,       /* kMemorystatusKilled			*/
	"highwater"             ,       /* kMemorystatusKilledHiwat		*/
	"vnode-limit"           ,       /* kMemorystatusKilledVnodes		*/
	"vm-pageshortage"       ,       /* kMemorystatusKilledVMPageShortage	*/
	"vm-thrashing"          ,       /* kMemorystatusKilledVMThrashing	*/
	"fc-thrashing"          ,       /* kMemorystatusKilledFCThrashing	*/
	"per-process-limit"     ,       /* kMemorystatusKilledPerProcessLimit	*/
	"diagnostic"            ,       /* kMemorystatusKilledDiagnostic	*/
	"idle-exit"             ,       /* kMemorystatusKilledIdleExit		*/
};

#if CONFIG_JETSAM
/* Does cause indicate vm or fc thrashing? */
static boolean_t
is_thrashing(unsigned cause)
{
	switch (cause) {
	case kMemorystatusKilledVMThrashing:
	case kMemorystatusKilledFCThrashing:
		return TRUE;
	default:
		return FALSE;
	}
}

/* Callback into vm_compressor.c to signal that thrashing has been mitigated. */
extern void vm_thrashing_jetsam_done(void);
#endif /* CONFIG_JETSAM */

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

/*
 * Active / Inactive limit support
 * proc list must be locked
 *
 * The SET_*** macros are used to initialize a limit
 * for the first time.
 *
 * The CACHE_*** macros are use to cache the limit that will
 * soon be in effect down in the ledgers.
 */

#define SET_ACTIVE_LIMITS_LOCKED(p, limit, is_fatal)			\
MACRO_BEGIN								\
(p)->p_memstat_memlimit_active = (limit);				\
   (p)->p_memstat_state &= ~P_MEMSTAT_MEMLIMIT_ACTIVE_EXC_TRIGGERED;	\
   if (is_fatal) {							\
	   (p)->p_memstat_state |= P_MEMSTAT_MEMLIMIT_ACTIVE_FATAL;	\
   } else {								\
	   (p)->p_memstat_state &= ~P_MEMSTAT_MEMLIMIT_ACTIVE_FATAL;	\
   }									\
MACRO_END

#define SET_INACTIVE_LIMITS_LOCKED(p, limit, is_fatal)			\
MACRO_BEGIN								\
(p)->p_memstat_memlimit_inactive = (limit);				\
   (p)->p_memstat_state &= ~P_MEMSTAT_MEMLIMIT_INACTIVE_EXC_TRIGGERED;	\
   if (is_fatal) {							\
	   (p)->p_memstat_state |= P_MEMSTAT_MEMLIMIT_INACTIVE_FATAL;	\
   } else {								\
	   (p)->p_memstat_state &= ~P_MEMSTAT_MEMLIMIT_INACTIVE_FATAL;	\
   }									\
MACRO_END

#define CACHE_ACTIVE_LIMITS_LOCKED(p, trigger_exception)		\
MACRO_BEGIN								\
(p)->p_memstat_memlimit = (p)->p_memstat_memlimit_active;		\
   if ((p)->p_memstat_state & P_MEMSTAT_MEMLIMIT_ACTIVE_FATAL) {	\
	   (p)->p_memstat_state |= P_MEMSTAT_FATAL_MEMLIMIT;		\
   } else {								\
	   (p)->p_memstat_state &= ~P_MEMSTAT_FATAL_MEMLIMIT;		\
   }									\
   if ((p)->p_memstat_state & P_MEMSTAT_MEMLIMIT_ACTIVE_EXC_TRIGGERED) { \
	   trigger_exception = FALSE;					\
   } else {								\
	   trigger_exception = TRUE;					\
   }									\
MACRO_END

#define CACHE_INACTIVE_LIMITS_LOCKED(p, trigger_exception)		\
MACRO_BEGIN								\
(p)->p_memstat_memlimit = (p)->p_memstat_memlimit_inactive;		\
   if ((p)->p_memstat_state & P_MEMSTAT_MEMLIMIT_INACTIVE_FATAL) {	\
	   (p)->p_memstat_state |= P_MEMSTAT_FATAL_MEMLIMIT;		\
   } else {								\
	   (p)->p_memstat_state &= ~P_MEMSTAT_FATAL_MEMLIMIT;		\
   }									\
   if ((p)->p_memstat_state & P_MEMSTAT_MEMLIMIT_INACTIVE_EXC_TRIGGERED) { \
	   trigger_exception = FALSE;					\
   } else {								\
	   trigger_exception = TRUE;					\
   }									\
MACRO_END


/* General tunables */

unsigned long delta_percentage = 5;
unsigned long critical_threshold_percentage = 5;
unsigned long idle_offset_percentage = 5;
unsigned long pressure_threshold_percentage = 15;
unsigned long freeze_threshold_percentage = 50;
unsigned long policy_more_free_offset_percentage = 5;

/* General memorystatus stuff */

struct klist memorystatus_klist;
static lck_mtx_t memorystatus_klist_mutex;

static void memorystatus_klist_lock(void);
static void memorystatus_klist_unlock(void);

static uint64_t memorystatus_sysprocs_idle_delay_time = 0;
static uint64_t memorystatus_apps_idle_delay_time = 0;

/*
 * Memorystatus kevents
 */

static int filt_memorystatusattach(struct knote *kn);
static void filt_memorystatusdetach(struct knote *kn);
static int filt_memorystatus(struct knote *kn, long hint);
static int filt_memorystatustouch(struct knote *kn, struct kevent_internal_s *kev);
static int filt_memorystatusprocess(struct knote *kn, struct filt_process_s *data, struct kevent_internal_s *kev);

struct filterops memorystatus_filtops = {
	.f_attach = filt_memorystatusattach,
	.f_detach = filt_memorystatusdetach,
	.f_event = filt_memorystatus,
	.f_touch = filt_memorystatustouch,
	.f_process = filt_memorystatusprocess,
};

enum {
	kMemorystatusNoPressure = 0x1,
	kMemorystatusPressure = 0x2,
	kMemorystatusLowSwap = 0x4,
	kMemorystatusProcLimitWarn = 0x8,
	kMemorystatusProcLimitCritical = 0x10
};

/* Idle guard handling */

static int32_t memorystatus_scheduled_idle_demotions_sysprocs = 0;
static int32_t memorystatus_scheduled_idle_demotions_apps = 0;

static thread_call_t memorystatus_idle_demotion_call;

static void memorystatus_perform_idle_demotion(__unused void *spare1, __unused void *spare2);
static void memorystatus_schedule_idle_demotion_locked(proc_t p, boolean_t set_state);
static void memorystatus_invalidate_idle_demotion_locked(proc_t p, boolean_t clean_state);
static void memorystatus_reschedule_idle_demotion_locked(void);

static void memorystatus_update_priority_locked(proc_t p, int priority, boolean_t head_insert, boolean_t skip_demotion_check);

vm_pressure_level_t convert_internal_pressure_level_to_dispatch_level(vm_pressure_level_t);

boolean_t is_knote_registered_modify_task_pressure_bits(struct knote*, int, task_t, vm_pressure_level_t, vm_pressure_level_t);
void memorystatus_klist_reset_all_for_level(vm_pressure_level_t pressure_level_to_clear);
void memorystatus_send_low_swap_note(void);

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

int system_procs_aging_band = JETSAM_PRIORITY_AGING_BAND1;
int applications_aging_band = JETSAM_PRIORITY_IDLE;

#define isProcessInAgingBands(p)	((isSysProc(p) && system_procs_aging_band && (p->p_memstat_effectivepriority == system_procs_aging_band)) || (isApp(p) && applications_aging_band && (p->p_memstat_effectivepriority == applications_aging_band)))
#define isApp(p)			(! (p->p_memstat_dirty & P_DIRTY_TRACK))
#define isSysProc(p)			((p->p_memstat_dirty & P_DIRTY_TRACK))

#define	kJetsamAgingPolicyNone				(0)
#define kJetsamAgingPolicyLegacy			(1)
#define	kJetsamAgingPolicySysProcsReclaimedFirst	(2)
#define	kJetsamAgingPolicyAppsReclaimedFirst		(3)
#define kJetsamAgingPolicyMax				kJetsamAgingPolicyAppsReclaimedFirst

unsigned int jetsam_aging_policy = kJetsamAgingPolicyLegacy;

extern int corpse_for_fatal_memkill;
extern unsigned long total_corpses_count;
extern void task_purge_all_corpses(void);

#if 0

/* Keeping around for future use if we need a utility that can do this OR an app that needs a dynamic adjustment. */

static int
sysctl_set_jetsam_aging_policy SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)

	int error = 0, val = 0;
	memstat_bucket_t *old_bucket = 0;
	int old_system_procs_aging_band = 0, new_system_procs_aging_band = 0;
	int old_applications_aging_band = 0, new_applications_aging_band = 0;
	proc_t p = NULL, next_proc = NULL;


	error = sysctl_io_number(req, jetsam_aging_policy, sizeof(int), &val, NULL);
	if (error || !req->newptr) {
 		return (error);
	}

	if ((val < 0) || (val > kJetsamAgingPolicyMax)) {
		printf("jetsam: ordering policy sysctl has invalid value - %d\n", val);
		return EINVAL;
	}

	/*
	 * We need to synchronize with any potential adding/removal from aging bands
	 * that might be in progress currently. We use the proc_list_lock() just for
	 * consistency with all the routines dealing with 'aging' processes. We need
	 * a lighterweight lock.
	 */ 
	proc_list_lock();

	old_system_procs_aging_band = system_procs_aging_band;
	old_applications_aging_band = applications_aging_band;
	
	switch (val) {

		case kJetsamAgingPolicyNone:
			new_system_procs_aging_band = JETSAM_PRIORITY_IDLE;
			new_applications_aging_band = JETSAM_PRIORITY_IDLE; 
			break;

		case kJetsamAgingPolicyLegacy:
			/*
			 * Legacy behavior where some daemons get a 10s protection once and only before the first clean->dirty->clean transition before going into IDLE band.
			 */
			new_system_procs_aging_band = JETSAM_PRIORITY_AGING_BAND1;
			new_applications_aging_band = JETSAM_PRIORITY_IDLE; 
			break;

		case kJetsamAgingPolicySysProcsReclaimedFirst:
			new_system_procs_aging_band = JETSAM_PRIORITY_AGING_BAND1;
			new_applications_aging_band = JETSAM_PRIORITY_AGING_BAND2;
			break;

		case kJetsamAgingPolicyAppsReclaimedFirst:
			new_system_procs_aging_band = JETSAM_PRIORITY_AGING_BAND2;
			new_applications_aging_band = JETSAM_PRIORITY_AGING_BAND1; 
			break;

		default:
			break;
	}

	if (old_system_procs_aging_band && (old_system_procs_aging_band != new_system_procs_aging_band)) {

		old_bucket = &memstat_bucket[old_system_procs_aging_band];
		p = TAILQ_FIRST(&old_bucket->list);
		    
		while (p) {
			
			next_proc = TAILQ_NEXT(p, p_memstat_list);

			if (isSysProc(p)) {
				if (new_system_procs_aging_band == JETSAM_PRIORITY_IDLE) {
					memorystatus_invalidate_idle_demotion_locked(p, TRUE);
				}

				memorystatus_update_priority_locked(p, new_system_procs_aging_band, false, true);
			}

			p = next_proc;
			continue;
		}
	}

	if (old_applications_aging_band && (old_applications_aging_band != new_applications_aging_band)) {

		old_bucket = &memstat_bucket[old_applications_aging_band];
		p = TAILQ_FIRST(&old_bucket->list);
		    
		while (p) {

			next_proc = TAILQ_NEXT(p, p_memstat_list);

			if (isApp(p)) {
				if (new_applications_aging_band == JETSAM_PRIORITY_IDLE) {
					memorystatus_invalidate_idle_demotion_locked(p, TRUE);
				}

				memorystatus_update_priority_locked(p, new_applications_aging_band, false, true);
			}

			p = next_proc;
			continue;
		}
	}

	jetsam_aging_policy = val;
	system_procs_aging_band = new_system_procs_aging_band;
	applications_aging_band = new_applications_aging_band;

	proc_list_unlock();

	return (0);
}

SYSCTL_PROC(_kern, OID_AUTO, set_jetsam_aging_policy, CTLTYPE_INT|CTLFLAG_RW,
  	    0, 0, sysctl_set_jetsam_aging_policy, "I", "Jetsam Aging Policy");
#endif /*0*/

static int
sysctl_jetsam_set_sysprocs_idle_delay_time SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)

	int error = 0, val = 0, old_time_in_secs = 0;
	uint64_t old_time_in_ns = 0;

	absolutetime_to_nanoseconds(memorystatus_sysprocs_idle_delay_time, &old_time_in_ns);
	old_time_in_secs = old_time_in_ns / NSEC_PER_SEC;

	error = sysctl_io_number(req, old_time_in_secs, sizeof(int), &val, NULL);
	if (error || !req->newptr) {
 		return (error);
	}

	if ((val < 0) || (val > INT32_MAX)) {
		printf("jetsam: new idle delay interval has invalid value.\n");
		return EINVAL;
	}

	nanoseconds_to_absolutetime((uint64_t)val * NSEC_PER_SEC, &memorystatus_sysprocs_idle_delay_time);
	
	return(0);
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_sysprocs_idle_delay_time, CTLTYPE_INT|CTLFLAG_RW,
  	    0, 0, sysctl_jetsam_set_sysprocs_idle_delay_time, "I", "Aging window for system processes");


static int
sysctl_jetsam_set_apps_idle_delay_time SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)

	int error = 0, val = 0, old_time_in_secs = 0;
	uint64_t old_time_in_ns = 0;

	absolutetime_to_nanoseconds(memorystatus_apps_idle_delay_time, &old_time_in_ns);
	old_time_in_secs = old_time_in_ns / NSEC_PER_SEC;

	error = sysctl_io_number(req, old_time_in_secs, sizeof(int), &val, NULL);
	if (error || !req->newptr) {
 		return (error);
	}

	if ((val < 0) || (val > INT32_MAX)) {
		printf("jetsam: new idle delay interval has invalid value.\n");
		return EINVAL;
	}

	nanoseconds_to_absolutetime((uint64_t)val * NSEC_PER_SEC, &memorystatus_apps_idle_delay_time);
	
	return(0);
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_apps_idle_delay_time, CTLTYPE_INT|CTLFLAG_RW,
  	    0, 0, sysctl_jetsam_set_apps_idle_delay_time, "I", "Aging window for applications");

SYSCTL_INT(_kern, OID_AUTO, jetsam_aging_policy, CTLTYPE_INT|CTLFLAG_RD, &jetsam_aging_policy, 0, "");

static unsigned int memorystatus_dirty_count = 0;

SYSCTL_INT(_kern, OID_AUTO, max_task_pmem, CTLFLAG_RD|CTLFLAG_LOCKED|CTLFLAG_MASKED, &max_task_footprint_mb, 0, "");


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

/* Memory Limits */

static int memorystatus_highwater_enabled = 1;  /* Update the cached memlimit data. */

static boolean_t proc_jetsam_state_is_active_locked(proc_t);
static boolean_t memorystatus_kill_specific_process(pid_t victim_pid, uint32_t cause, os_reason_t jetsam_reason);
static boolean_t memorystatus_kill_process_sync(pid_t victim_pid, uint32_t cause, os_reason_t jetsam_reason);


/* Jetsam */

#if CONFIG_JETSAM

static int memorystatus_cmd_set_jetsam_memory_limit(pid_t pid, int32_t high_water_mark, __unused int32_t *retval, boolean_t is_fatal_limit);

static int memorystatus_cmd_set_memlimit_properties(pid_t pid, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval);

static int memorystatus_set_memlimit_properties(pid_t pid, memorystatus_memlimit_properties_t *entry);

static int memorystatus_cmd_get_memlimit_properties(pid_t pid, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval);

static int memorystatus_cmd_get_memlimit_excess_np(pid_t pid, uint32_t flags, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval);

int proc_get_memstat_priority(proc_t, boolean_t);

static boolean_t memorystatus_idle_snapshot = 0;

unsigned int memorystatus_delta = 0;

static unsigned int memorystatus_available_pages_critical_base = 0;
//static unsigned int memorystatus_last_foreground_pressure_pages = (unsigned int)-1;
static unsigned int memorystatus_available_pages_critical_idle_offset = 0;

/* Jetsam Loop Detection */
static boolean_t memorystatus_jld_enabled = TRUE;		/* Enables jetsam loop detection on all devices */
static uint32_t memorystatus_jld_eval_period_msecs = 0;		/* Init pass sets this based on device memory size */
static int      memorystatus_jld_eval_aggressive_count = 3;	/* Raise the priority max after 'n' aggressive loops */
static int      memorystatus_jld_eval_aggressive_priority_band_max = 15;  /* Kill aggressively up through this band */

/*
 * A FG app can request that the aggressive jetsam mechanism display some leniency in the FG band. This 'lenient' mode is described as:
 * --- if aggressive jetsam kills an app in the FG band and gets back >=AGGRESSIVE_JETSAM_LENIENT_MODE_THRESHOLD memory, it will stop the aggressive march further into and up the jetsam bands.
 *
 * RESTRICTIONS:
 * - Such a request is respected/acknowledged only once while that 'requesting' app is in the FG band i.e. if aggressive jetsam was
 * needed and the 'lenient' mode was deployed then that's it for this special mode while the app is in the FG band. 
 *
 * - If the app is still in the FG band and aggressive jetsam is needed again, there will be no stop-and-check the next time around.
 *
 * - Also, the transition of the 'requesting' app away from the FG band will void this special behavior.
 */

#define AGGRESSIVE_JETSAM_LENIENT_MODE_THRESHOLD	25
boolean_t 	memorystatus_aggressive_jetsam_lenient_allowed = FALSE;
boolean_t 	memorystatus_aggressive_jetsam_lenient = FALSE;

#if DEVELOPMENT || DEBUG
/* 
 * Jetsam Loop Detection tunables.
 */

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_jld_eval_period_msecs, CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_jld_eval_period_msecs, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_jld_eval_aggressive_count, CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_jld_eval_aggressive_count, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_jld_eval_aggressive_priority_band_max, CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_jld_eval_aggressive_priority_band_max, 0, "");
#endif /* DEVELOPMENT || DEBUG */

#if DEVELOPMENT || DEBUG
static unsigned int memorystatus_jetsam_panic_debug = 0;
static unsigned int memorystatus_jetsam_policy_offset_pages_diagnostic = 0;
#endif

static unsigned int memorystatus_jetsam_policy = kPolicyDefault;
static unsigned int memorystatus_thread_wasted_wakeup = 0;

static uint32_t kill_under_pressure_cause = 0;

/*
 * default jetsam snapshot support
 */
static memorystatus_jetsam_snapshot_t *memorystatus_jetsam_snapshot;
#define memorystatus_jetsam_snapshot_list memorystatus_jetsam_snapshot->entries
static unsigned int memorystatus_jetsam_snapshot_count = 0;
static unsigned int memorystatus_jetsam_snapshot_max = 0;
static uint64_t memorystatus_jetsam_snapshot_last_timestamp = 0;
static uint64_t memorystatus_jetsam_snapshot_timeout = 0;
#define JETSAM_SNAPSHOT_TIMEOUT_SECS 30

/*
 * snapshot support for memstats collected at boot.
 */
static memorystatus_jetsam_snapshot_t memorystatus_at_boot_snapshot;

static void memorystatus_init_jetsam_snapshot_locked(memorystatus_jetsam_snapshot_t *od_snapshot, uint32_t ods_list_count);
static boolean_t memorystatus_init_jetsam_snapshot_entry_locked(proc_t p, memorystatus_jetsam_snapshot_entry_t *entry, uint64_t gencount);
static void memorystatus_update_jetsam_snapshot_entry_locked(proc_t p, uint32_t kill_cause, uint64_t killtime);

static void memorystatus_clear_errors(void);
static void memorystatus_get_task_page_counts(task_t task, uint32_t *footprint, uint32_t *max_footprint, uint32_t *max_footprint_lifetime, uint32_t *purgeable_pages);
static void memorystatus_get_task_phys_footprint_page_counts(task_t task,
							     uint64_t *internal_pages, uint64_t *internal_compressed_pages,
							     uint64_t *purgeable_nonvolatile_pages, uint64_t *purgeable_nonvolatile_compressed_pages,
							     uint64_t *alternate_accounting_pages, uint64_t *alternate_accounting_compressed_pages,
							     uint64_t *iokit_mapped_pages, uint64_t *page_table_pages);

static void memorystatus_get_task_memory_region_count(task_t task, uint64_t *count);

static uint32_t memorystatus_build_state(proc_t p);
static void memorystatus_update_levels_locked(boolean_t critical_only);
//static boolean_t memorystatus_issue_pressure_kevent(boolean_t pressured);

static boolean_t memorystatus_kill_top_process(boolean_t any, boolean_t sort_flag, uint32_t cause, os_reason_t jetsam_reason, int32_t *priority, uint32_t *errors);
static boolean_t memorystatus_kill_top_process_aggressive(boolean_t any, uint32_t cause, os_reason_t jetsam_reason, int aggr_count, int32_t priority_max, uint32_t *errors);
static boolean_t memorystatus_kill_elevated_process(uint32_t cause, os_reason_t jetsam_reason, int aggr_count, uint32_t *errors);
static boolean_t memorystatus_kill_hiwat_proc(uint32_t *errors);

static boolean_t memorystatus_kill_process_async(pid_t victim_pid, uint32_t cause);

/* Priority Band Sorting Routines */
static int  memorystatus_sort_bucket(unsigned int bucket_index, int sort_order);
static int  memorystatus_sort_by_largest_coalition_locked(unsigned int bucket_index, int coal_sort_order);
static void memorystatus_sort_by_largest_process_locked(unsigned int bucket_index);
static int  memorystatus_move_list_locked(unsigned int bucket_index, pid_t *pid_list, int list_sz);

/* qsort routines */
typedef int (*cmpfunc_t)(const void *a, const void *b);
extern void qsort(void *a, size_t n, size_t es, cmpfunc_t cmp);
static int memstat_asc_cmp(const void *a, const void *b);

#endif /* CONFIG_JETSAM */

/* VM pressure */

extern unsigned int    vm_page_free_count;
extern unsigned int    vm_page_active_count;
extern unsigned int    vm_page_inactive_count;
extern unsigned int    vm_page_throttled_count;
extern unsigned int    vm_page_purgeable_count;
extern unsigned int    vm_page_wire_count;
#if CONFIG_SECLUDED_MEMORY
extern unsigned int	vm_page_secluded_count;
#endif /* CONFIG_SECLUDED_MEMORY */

#if VM_PRESSURE_EVENTS

boolean_t memorystatus_warn_process(pid_t pid, boolean_t exceeded);

vm_pressure_level_t memorystatus_vm_pressure_level = kVMPressureNormal;

#if CONFIG_MEMORYSTATUS
unsigned int memorystatus_available_pages = (unsigned int)-1;
unsigned int memorystatus_available_pages_pressure = 0;
unsigned int memorystatus_available_pages_critical = 0;
unsigned int memorystatus_frozen_count = 0;
unsigned int memorystatus_suspended_count = 0;
unsigned int memorystatus_policy_more_free_offset_pages = 0;

/*
 * We use this flag to signal if we have any HWM offenders
 * on the system. This way we can reduce the number of wakeups
 * of the memorystatus_thread when the system is between the
 * "pressure" and "critical" threshold.
 *
 * The (re-)setting of this variable is done without any locks
 * or synchronization simply because it is not possible (currently)
 * to keep track of HWM offenders that drop down below their memory
 * limit and/or exit. So, we choose to burn a couple of wasted wakeups
 * by allowing the unguarded modification of this variable.
 */
boolean_t memorystatus_hwm_candidates = 0;

static int memorystatus_send_note(int event_code, void *data, size_t data_length);
#endif /* CONFIG_MEMORYSTATUS */

#endif /* VM_PRESSURE_EVENTS */


#if DEVELOPMENT || DEBUG

lck_grp_attr_t *disconnect_page_mappings_lck_grp_attr;
lck_grp_t *disconnect_page_mappings_lck_grp;
static lck_mtx_t disconnect_page_mappings_mutex;

#endif


/* Freeze */

#if CONFIG_FREEZE

boolean_t memorystatus_freeze_enabled = FALSE;
int memorystatus_freeze_wakeup = 0;

lck_grp_attr_t *freezer_lck_grp_attr;
lck_grp_t *freezer_lck_grp;
static lck_mtx_t freezer_mutex;

static inline boolean_t memorystatus_can_freeze_processes(void);
static boolean_t memorystatus_can_freeze(boolean_t *memorystatus_freeze_swap_low);

static void memorystatus_freeze_thread(void *param __unused, wait_result_t wr __unused);

/* Thresholds */
static unsigned int memorystatus_freeze_threshold = 0;

static unsigned int memorystatus_freeze_pages_min = 0;
static unsigned int memorystatus_freeze_pages_max = 0;

static unsigned int memorystatus_freeze_suspended_threshold = FREEZE_SUSPENDED_THRESHOLD_DEFAULT;

static unsigned int memorystatus_freeze_daily_mb_max = FREEZE_DAILY_MB_MAX_DEFAULT;

/* Stats */
static uint64_t memorystatus_freeze_count = 0;
static uint64_t memorystatus_freeze_pageouts = 0;

/* Throttling */
static throttle_interval_t throttle_intervals[] = {
	{      60,  8, 0, 0, { 0, 0 }, FALSE }, /* 1 hour intermediate interval, 8x burst */
	{ 24 * 60,  1, 0, 0, { 0, 0 }, FALSE }, /* 24 hour long interval, no burst */
};

static uint64_t memorystatus_freeze_throttle_count = 0;

static unsigned int memorystatus_suspended_footprint_total = 0;	/* pages */

extern uint64_t vm_swap_get_free_space(void);

static boolean_t memorystatus_freeze_update_throttle();

#endif /* CONFIG_FREEZE */

/* Debug */

extern struct knote *vm_find_knote_from_pid(pid_t, struct klist *);

#if DEVELOPMENT || DEBUG

static unsigned int memorystatus_debug_dump_this_bucket = 0;

static void
memorystatus_debug_dump_bucket_locked (unsigned int bucket_index)
{
	proc_t p = NULL;
	uint64_t bytes = 0;
	int ledger_limit = 0;
	unsigned int b = bucket_index;
	boolean_t traverse_all_buckets = FALSE;

        if (bucket_index >= MEMSTAT_BUCKET_COUNT) {
		traverse_all_buckets = TRUE;
		b = 0;
        } else {
		traverse_all_buckets = FALSE;
		b = bucket_index;
	}

	/*
	 * footprint reported in [pages / MB ]
	 * limits reported as:
	 *      L-limit  proc's Ledger limit
	 *      C-limit  proc's Cached limit, should match Ledger
	 *      A-limit  proc's Active limit
	 *     IA-limit  proc's Inactive limit
	 *	F==Fatal,  NF==NonFatal
	 */

        printf("memorystatus_debug_dump ***START*(PAGE_SIZE_64=%llu)**\n", PAGE_SIZE_64);
	printf("bucket [pid]       [pages / MB]     [state]      [EP / RP]   dirty     deadline [L-limit / C-limit / A-limit / IA-limit] name\n");
	p = memorystatus_get_first_proc_locked(&b, traverse_all_buckets);
	while (p) {
		bytes = get_task_phys_footprint(p->task);
		task_get_phys_footprint_limit(p->task, &ledger_limit);
		printf("%2d     [%5d]     [%5lld /%3lldMB]   0x%-8x   [%2d / %2d]   0x%-3x   %10lld    [%3d / %3d%s / %3d%s / %3d%s]   %s\n",
		       b, p->p_pid,
		       (bytes / PAGE_SIZE_64),    	/* task's footprint converted from bytes to pages     */
		       (bytes / (1024ULL * 1024ULL)),	/* task's footprint converted from bytes to MB */
		       p->p_memstat_state, p->p_memstat_effectivepriority, p->p_memstat_requestedpriority, p->p_memstat_dirty, p->p_memstat_idledeadline,
		       ledger_limit,
		       p->p_memstat_memlimit,
		       (p->p_memstat_state & P_MEMSTAT_FATAL_MEMLIMIT ? "F " : "NF"),
		       p->p_memstat_memlimit_active, 
		       (p->p_memstat_state & P_MEMSTAT_MEMLIMIT_ACTIVE_FATAL ? "F " : "NF"),
		       p->p_memstat_memlimit_inactive, 
		       (p->p_memstat_state & P_MEMSTAT_MEMLIMIT_INACTIVE_FATAL ? "F " : "NF"),
		       (*p->p_name ? p->p_name : "unknown"));
		p = memorystatus_get_next_proc_locked(&b, p, traverse_all_buckets);
        }
        printf("memorystatus_debug_dump ***END***\n");
}

static int
sysctl_memorystatus_debug_dump_bucket SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2)
        int bucket_index = 0;
        int error;
	error = SYSCTL_OUT(req, arg1, sizeof(int));
	if (error || !req->newptr) {
		return (error);
	}
        error = SYSCTL_IN(req, &bucket_index, sizeof(int));
        if (error || !req->newptr) {
                return (error);
        }
	if (bucket_index >= MEMSTAT_BUCKET_COUNT) {
		/*
		 * All jetsam buckets will be dumped.
		 */
        } else {
		/*
		 * Only a single bucket will be dumped.
		 */
	}

	proc_list_lock();
	memorystatus_debug_dump_bucket_locked(bucket_index);
	proc_list_unlock();
	memorystatus_debug_dump_this_bucket = bucket_index;
	return (error);
}

/*
 * Debug aid to look at jetsam buckets and proc jetsam fields.
 *	Use this sysctl to act on a particular jetsam bucket.
 *	Writing the sysctl triggers the dump.
 *   	Usage: sysctl kern.memorystatus_debug_dump_this_bucket=<bucket_index>
 */

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_debug_dump_this_bucket, CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_debug_dump_this_bucket, 0, sysctl_memorystatus_debug_dump_bucket, "I", "");


/* Debug aid to aid determination of limit */

static int
sysctl_memorystatus_highwater_enable SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2)
	proc_t p;
	unsigned int b = 0;
	int error, enable = 0;

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
		boolean_t trigger_exception;

		if (enable) {
			/*
			 * No need to consider P_MEMSTAT_MEMLIMIT_BACKGROUND anymore.
			 * Background limits are described via the inactive limit slots.
			 */

			if (proc_jetsam_state_is_active_locked(p) == TRUE) {
				CACHE_ACTIVE_LIMITS_LOCKED(p, trigger_exception);
			} else {
				CACHE_INACTIVE_LIMITS_LOCKED(p, trigger_exception);
			}

		} else {
			/*
			 * Disabling limits does not touch the stored variants.
			 * Set the cached limit fields to system_wide defaults.
			 */
			p->p_memstat_memlimit = -1;
			p->p_memstat_state |= P_MEMSTAT_FATAL_MEMLIMIT;
			trigger_exception = TRUE;
		}

		/*
		 * Enforce the cached limit by writing to the ledger.
		 */
		task_set_phys_footprint_limit_internal(p->task, (p->p_memstat_memlimit > 0) ? p->p_memstat_memlimit: -1, NULL, trigger_exception);

		p = memorystatus_get_next_proc_locked(&b, p, TRUE);
	}
	
	memorystatus_highwater_enabled = enable;

	proc_list_unlock();

	return 0;

}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_highwater_enabled, CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_highwater_enabled, 0, sysctl_memorystatus_highwater_enable, "I", "");

#if VM_PRESSURE_EVENTS

/*
 * This routine is used for targeted notifications
 * regardless of system memory pressure.
 * "memnote" is the current user.
 */

static int
sysctl_memorystatus_vm_pressure_send SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)

	int error = 0, pid = 0;
	struct knote *kn = NULL;
	boolean_t found_knote = FALSE;
	int fflags = 0;		/* filter flags for EVFILT_MEMORYSTATUS */
	uint64_t value = 0;

	error = sysctl_handle_quad(oidp, &value, 0, req);
	if (error || !req->newptr)
		return (error);

	/*
	 * Find the pid in the low 32 bits of value passed in.
	 */
	pid = (int)(value & 0xFFFFFFFF);

	/*
	 * Find notification in the high 32 bits of the value passed in.
	 */
	fflags = (int)((value >> 32) & 0xFFFFFFFF);

	/*
	 * For backwards compatibility, when no notification is
	 * passed in, default to the NOTE_MEMORYSTATUS_PRESSURE_WARN
	 */
	if (fflags == 0) {
		fflags = NOTE_MEMORYSTATUS_PRESSURE_WARN;
		// printf("memorystatus_vm_pressure_send: using default notification [0x%x]\n", fflags);
	}

	/*
	 * See event.h ... fflags for EVFILT_MEMORYSTATUS
	 */
	if (!((fflags == NOTE_MEMORYSTATUS_PRESSURE_NORMAL)||
	      (fflags == NOTE_MEMORYSTATUS_PRESSURE_WARN) ||
	      (fflags == NOTE_MEMORYSTATUS_PRESSURE_CRITICAL) ||
	      (fflags == NOTE_MEMORYSTATUS_LOW_SWAP) ||
	      (fflags == NOTE_MEMORYSTATUS_PROC_LIMIT_WARN) ||
	      (fflags == NOTE_MEMORYSTATUS_PROC_LIMIT_CRITICAL))) {

		printf("memorystatus_vm_pressure_send: notification [0x%x] not supported \n", fflags);
		error = 1;
		return (error);
	}

	/*
	 * Forcibly send pid a memorystatus notification.
	 */

	memorystatus_klist_lock();

	SLIST_FOREACH(kn, &memorystatus_klist, kn_selnext) {
		proc_t knote_proc = knote_get_kq(kn)->kq_p;
		pid_t knote_pid = knote_proc->p_pid;

		if (knote_pid == pid) {
			/*
			 * Forcibly send this pid a memorystatus notification.
			 */
			kn->kn_fflags = fflags;
			found_knote = TRUE;
		}
	}

	if (found_knote) {
		KNOTE(&memorystatus_klist, 0);
		printf("memorystatus_vm_pressure_send: (value 0x%llx) notification [0x%x] sent to process [%d] \n", value, fflags, pid);
		error = 0;
	} else {
		printf("memorystatus_vm_pressure_send: (value 0x%llx) notification [0x%x] not sent to process [%d] (none registered?)\n", value, fflags, pid);
		error = 1;
	}

	memorystatus_klist_unlock();

	return (error);
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_vm_pressure_send, CTLTYPE_QUAD|CTLFLAG_WR|CTLFLAG_LOCKED|CTLFLAG_MASKED,
    0, 0, &sysctl_memorystatus_vm_pressure_send, "Q", "");

#endif /* VM_PRESSURE_EVENTS */

#if CONFIG_JETSAM

SYSCTL_INT(_kern, OID_AUTO, memorystatus_idle_snapshot, CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_idle_snapshot, 0, "");

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages, CTLFLAG_RD|CTLFLAG_LOCKED, &memorystatus_available_pages, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages_critical, CTLFLAG_RD|CTLFLAG_LOCKED, &memorystatus_available_pages_critical, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages_critical_base, CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_available_pages_critical_base, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages_critical_idle_offset, CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_available_pages_critical_idle_offset, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_policy_more_free_offset_pages, CTLFLAG_RW, &memorystatus_policy_more_free_offset_pages, 0, "");

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

#endif /* VM_PRESSURE_EVENTS */

#endif /* CONFIG_JETSAM */

#if CONFIG_FREEZE

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_daily_mb_max, CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_freeze_daily_mb_max, 0, "");

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_threshold, CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_freeze_threshold, 0, "");

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_pages_min, CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_freeze_pages_min, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_pages_max, CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_freeze_pages_max, 0, "");

SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freeze_count, CTLFLAG_RD|CTLFLAG_LOCKED, &memorystatus_freeze_count, "");
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freeze_pageouts, CTLFLAG_RD|CTLFLAG_LOCKED, &memorystatus_freeze_pageouts, "");
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freeze_throttle_count, CTLFLAG_RD|CTLFLAG_LOCKED, &memorystatus_freeze_throttle_count, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_min_processes, CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_freeze_suspended_threshold, 0, "");

boolean_t memorystatus_freeze_throttle_enabled = TRUE;
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_throttle_enabled, CTLFLAG_RW|CTLFLAG_LOCKED, &memorystatus_freeze_throttle_enabled, 0, "");

#define VM_PAGES_FOR_ALL_PROCS	(2)
/* 
 * Manual trigger of freeze and thaw for dev / debug kernels only.
 */
static int
sysctl_memorystatus_freeze SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error, pid = 0;
	proc_t p;

	if (memorystatus_freeze_enabled == FALSE) {
		return ENOTSUP;
	}

	error = sysctl_handle_int(oidp, &pid, 0, req);
	if (error || !req->newptr)
		return (error);

	if (pid == VM_PAGES_FOR_ALL_PROCS) {
		vm_pageout_anonymous_pages();

		return 0;
	}

	lck_mtx_lock(&freezer_mutex);

	p = proc_find(pid);
	if (p != NULL) {
		uint32_t purgeable, wired, clean, dirty;
		boolean_t shared;
		uint32_t max_pages = 0;

		if (VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {

			unsigned int avail_swap_space = 0; /* in pages. */

			/*
			 * Freezer backed by the compressor and swap file(s)
			 * while will hold compressed data.
			 */
			avail_swap_space = vm_swap_get_free_space() / PAGE_SIZE_64;

			max_pages = MIN(avail_swap_space, memorystatus_freeze_pages_max);

		} else {
			/*
			 * We only have the compressor without any swap.
			 */
			max_pages = UINT32_MAX - 1;
		}

		error = task_freeze(p->task, &purgeable, &wired, &clean, &dirty, max_pages, &shared, FALSE);
		proc_rele(p);

		if (error)
			error = EIO;

		lck_mtx_unlock(&freezer_mutex);
		return error;
	}

	lck_mtx_unlock(&freezer_mutex);
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

	if (memorystatus_freeze_enabled == FALSE) {
		return ENOTSUP;
	}

	error = sysctl_handle_int(oidp, &pid, 0, req);
	if (error || !req->newptr)
		return (error);

	if (pid == VM_PAGES_FOR_ALL_PROCS) {
		do_fastwake_warmup_all();
		return 0;
	} else {
		p = proc_find(pid);
		if (p != NULL) {
			error = task_thaw(p->task);
			proc_rele(p);

			if (error)
				error = EIO;
			return error;
		}
	}

	return EINVAL;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_thaw, CTLTYPE_INT|CTLFLAG_WR|CTLFLAG_LOCKED|CTLFLAG_MASKED,
    0, 0, &sysctl_memorystatus_available_pages_thaw, "I", "");

#endif /* CONFIG_FREEZE */

#endif /* DEVELOPMENT || DEBUG */

extern kern_return_t kernel_thread_start_priority(thread_continue_t continuation,
                                                  void *parameter,
                                                  integer_t priority,
                                                  thread_t *new_thread);

#if DEVELOPMENT || DEBUG

static int
sysctl_memorystatus_disconnect_page_mappings SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int	error = 0, pid = 0;
	proc_t	p;

	error = sysctl_handle_int(oidp, &pid, 0, req);
	if (error || !req->newptr)
		return (error);

	lck_mtx_lock(&disconnect_page_mappings_mutex);

	if (pid == -1) {
		vm_pageout_disconnect_all_pages();
	} else {
		p = proc_find(pid);

		if (p != NULL) {
			error = task_disconnect_page_mappings(p->task);

			proc_rele(p);

			if (error)
				error = EIO;
		} else
			error = EINVAL;
	}
	lck_mtx_unlock(&disconnect_page_mappings_mutex);

	return error;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_disconnect_page_mappings, CTLTYPE_INT|CTLFLAG_WR|CTLFLAG_LOCKED|CTLFLAG_MASKED,
    0, 0, &sysctl_memorystatus_disconnect_page_mappings, "I", "");

#endif /* DEVELOPMENT || DEBUG */



#if CONFIG_JETSAM
/*
 * Picks the sorting routine for a given jetsam priority band.
 *
 * Input:
 *	bucket_index - jetsam priority band to be sorted.
 *	sort_order - JETSAM_SORT_xxx from kern_memorystatus.h
 *		Currently sort_order is only meaningful when handling
 *		coalitions.
 *
 * Return: 
 *	0     on success
 * 	non-0 on failure
 */
static int memorystatus_sort_bucket(unsigned int bucket_index, int sort_order)
{
	int coal_sort_order;

	/*
	 * Verify the jetsam priority
	 */
        if (bucket_index >= MEMSTAT_BUCKET_COUNT) {
		return(EINVAL);
        }

#if DEVELOPMENT || DEBUG
        if (sort_order == JETSAM_SORT_DEFAULT) {
		coal_sort_order = COALITION_SORT_DEFAULT;
	} else {
		coal_sort_order = sort_order;		/* only used for testing scenarios */
	}
#else
	/* Verify default */
        if (sort_order == JETSAM_SORT_DEFAULT) {
		coal_sort_order = COALITION_SORT_DEFAULT;
	} else {
		return(EINVAL);
	}
#endif

	proc_list_lock();
	switch (bucket_index) {
	case JETSAM_PRIORITY_FOREGROUND:
		if (memorystatus_sort_by_largest_coalition_locked(bucket_index, coal_sort_order) == 0) {
			/*
			 * Fall back to per process sorting when zero coalitions are found.
			 */
			memorystatus_sort_by_largest_process_locked(bucket_index);
		}
		break;
	default:
		memorystatus_sort_by_largest_process_locked(bucket_index);
		break;
	}
	proc_list_unlock();
	
        return(0);
}

/*
 * Sort processes by size for a single jetsam bucket.
 */

static void memorystatus_sort_by_largest_process_locked(unsigned int bucket_index)
{
	proc_t p = NULL, insert_after_proc = NULL, max_proc = NULL;
	proc_t next_p = NULL, prev_max_proc = NULL;
	uint32_t pages = 0, max_pages = 0;
	memstat_bucket_t *current_bucket;
		
	if (bucket_index >= MEMSTAT_BUCKET_COUNT) {
		return;
	}
		
	current_bucket = &memstat_bucket[bucket_index];

	p = TAILQ_FIRST(&current_bucket->list);

	while (p) {
		memorystatus_get_task_page_counts(p->task, &pages, NULL, NULL, NULL);
		max_pages = pages;
		max_proc = p;
		prev_max_proc = p;
		
		while ((next_p = TAILQ_NEXT(p, p_memstat_list)) != NULL) {
			/* traversing list until we find next largest process */
			p=next_p;
			memorystatus_get_task_page_counts(p->task, &pages, NULL, NULL, NULL);
			if (pages > max_pages) {
				max_pages = pages;
				max_proc = p;
			}
		}

		if (prev_max_proc != max_proc) {
			/* found a larger process, place it in the list */
			TAILQ_REMOVE(&current_bucket->list, max_proc, p_memstat_list);
			if (insert_after_proc == NULL) {
				TAILQ_INSERT_HEAD(&current_bucket->list, max_proc, p_memstat_list);
			} else {
				TAILQ_INSERT_AFTER(&current_bucket->list, insert_after_proc, max_proc, p_memstat_list);
			}
			prev_max_proc = max_proc;
		}

		insert_after_proc = max_proc;

		p = TAILQ_NEXT(max_proc, p_memstat_list);
	}
}

#endif /* CONFIG_JETSAM */

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

#if CONFIG_FREEZE
	memorystatus_freeze_pages_min = FREEZE_PAGES_MIN;
	memorystatus_freeze_pages_max = FREEZE_PAGES_MAX;
#endif

#if DEVELOPMENT || DEBUG
	disconnect_page_mappings_lck_grp_attr = lck_grp_attr_alloc_init();
	disconnect_page_mappings_lck_grp = lck_grp_alloc_init("disconnect_page_mappings", disconnect_page_mappings_lck_grp_attr);

	lck_mtx_init(&disconnect_page_mappings_mutex, disconnect_page_mappings_lck_grp, NULL);
#endif		

	nanoseconds_to_absolutetime((uint64_t)DEFERRED_IDLE_EXIT_TIME_SECS * NSEC_PER_SEC, &memorystatus_sysprocs_idle_delay_time);
	nanoseconds_to_absolutetime((uint64_t)DEFERRED_IDLE_EXIT_TIME_SECS * NSEC_PER_SEC, &memorystatus_apps_idle_delay_time);
	
	/* Init buckets */
	for (i = 0; i < MEMSTAT_BUCKET_COUNT; i++) {
		TAILQ_INIT(&memstat_bucket[i].list);
		memstat_bucket[i].count = 0;
	}
	
	memorystatus_idle_demotion_call = thread_call_allocate((thread_call_func_t)memorystatus_perform_idle_demotion, NULL);

	/* Apply overrides */
	PE_get_default("kern.jetsam_delta", &delta_percentage, sizeof(delta_percentage));
	if (delta_percentage == 0) {
		delta_percentage = 5;
	}
	assert(delta_percentage < 100);
	PE_get_default("kern.jetsam_critical_threshold", &critical_threshold_percentage, sizeof(critical_threshold_percentage));
	assert(critical_threshold_percentage < 100);
	PE_get_default("kern.jetsam_idle_offset", &idle_offset_percentage, sizeof(idle_offset_percentage));
	assert(idle_offset_percentage < 100);
	PE_get_default("kern.jetsam_pressure_threshold", &pressure_threshold_percentage, sizeof(pressure_threshold_percentage));
	assert(pressure_threshold_percentage < 100);
	PE_get_default("kern.jetsam_freeze_threshold", &freeze_threshold_percentage, sizeof(freeze_threshold_percentage));
	assert(freeze_threshold_percentage < 100);
	
	if (!PE_parse_boot_argn("jetsam_aging_policy", &jetsam_aging_policy,
			sizeof (jetsam_aging_policy))) {

		if (!PE_get_default("kern.jetsam_aging_policy", &jetsam_aging_policy,
				sizeof(jetsam_aging_policy))) {

			jetsam_aging_policy = kJetsamAgingPolicyLegacy;
		}
	}

	if (jetsam_aging_policy > kJetsamAgingPolicyMax) {
		jetsam_aging_policy = kJetsamAgingPolicyLegacy;
	}

	switch (jetsam_aging_policy) {

		case kJetsamAgingPolicyNone:
			system_procs_aging_band = JETSAM_PRIORITY_IDLE;
			applications_aging_band = JETSAM_PRIORITY_IDLE;
			break;

		case kJetsamAgingPolicyLegacy:
			/*
			 * Legacy behavior where some daemons get a 10s protection once
			 * AND only before the first clean->dirty->clean transition before
			 * going into IDLE band.
			 */
			system_procs_aging_band = JETSAM_PRIORITY_AGING_BAND1;
			applications_aging_band = JETSAM_PRIORITY_IDLE;
			break;

		case kJetsamAgingPolicySysProcsReclaimedFirst:
			system_procs_aging_band = JETSAM_PRIORITY_AGING_BAND1;
			applications_aging_band = JETSAM_PRIORITY_AGING_BAND2;
			break;

		case kJetsamAgingPolicyAppsReclaimedFirst:
			system_procs_aging_band = JETSAM_PRIORITY_AGING_BAND2;
			applications_aging_band = JETSAM_PRIORITY_AGING_BAND1;
			break;

		default:
			break;
	}

	/*
	 * The aging bands cannot overlap with the JETSAM_PRIORITY_ELEVATED_INACTIVE
	 * band and must be below it in priority. This is so that we don't have to make
	 * our 'aging' code worry about a mix of processes, some of which need to age
	 * and some others that need to stay elevated in the jetsam bands.
	 */
	assert(JETSAM_PRIORITY_ELEVATED_INACTIVE > system_procs_aging_band);
	assert(JETSAM_PRIORITY_ELEVATED_INACTIVE > applications_aging_band);

#if CONFIG_JETSAM
	/* Take snapshots for idle-exit kills by default? First check the boot-arg... */
	if (!PE_parse_boot_argn("jetsam_idle_snapshot", &memorystatus_idle_snapshot, sizeof (memorystatus_idle_snapshot))) {
	        /* ...no boot-arg, so check the device tree */
	        PE_get_default("kern.jetsam_idle_snapshot", &memorystatus_idle_snapshot, sizeof(memorystatus_idle_snapshot));
	}

	memorystatus_delta = delta_percentage * atop_64(max_mem) / 100;
	memorystatus_available_pages_critical_idle_offset = idle_offset_percentage * atop_64(max_mem) / 100;
	memorystatus_available_pages_critical_base = (critical_threshold_percentage / delta_percentage) * memorystatus_delta;
	memorystatus_policy_more_free_offset_pages = (policy_more_free_offset_percentage / delta_percentage) * memorystatus_delta;
	
	memorystatus_jetsam_snapshot_max = maxproc;
	memorystatus_jetsam_snapshot = 
		(memorystatus_jetsam_snapshot_t*)kalloc(sizeof(memorystatus_jetsam_snapshot_t) +
		sizeof(memorystatus_jetsam_snapshot_entry_t) * memorystatus_jetsam_snapshot_max);
	if (!memorystatus_jetsam_snapshot) {
		panic("Could not allocate memorystatus_jetsam_snapshot");
	}

	nanoseconds_to_absolutetime((uint64_t)JETSAM_SNAPSHOT_TIMEOUT_SECS * NSEC_PER_SEC, &memorystatus_jetsam_snapshot_timeout);

	memset(&memorystatus_at_boot_snapshot, 0, sizeof(memorystatus_jetsam_snapshot_t));

	/* No contention at this point */
	memorystatus_update_levels_locked(FALSE);

	/* Jetsam Loop Detection */
	if (max_mem <= (512 * 1024 * 1024)) {
		/* 512 MB devices */
		memorystatus_jld_eval_period_msecs = 8000;	/* 8000 msecs == 8 second window */
	} else {
		/* 1GB and larger devices */
		memorystatus_jld_eval_period_msecs = 6000;	/* 6000 msecs == 6 second window */
	}
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
vm_run_compactor(void);

/*
 * The jetsam no frills kill call
 * 	Return: 0 on success
 *		error code on failure (EINVAL...)
 */
static int
jetsam_do_kill(proc_t p, int jetsam_flags, os_reason_t jetsam_reason) {
	int error = 0;
	error = exit_with_reason(p, W_EXITCODE(0, SIGKILL), (int *)NULL, FALSE, FALSE, jetsam_flags, jetsam_reason);
	return(error);
}

/*
 * Wrapper for processes exiting with memorystatus details
 */
static boolean_t
memorystatus_do_kill(proc_t p, uint32_t cause, os_reason_t jetsam_reason) {

	int error = 0;
	__unused pid_t victim_pid = p->p_pid;

	KERNEL_DEBUG_CONSTANT( (BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_DO_KILL)) | DBG_FUNC_START,
			       victim_pid, cause, vm_page_free_count, 0, 0);

	DTRACE_MEMORYSTATUS3(memorystatus_do_kill, proc_t, p, os_reason_t, jetsam_reason, uint32_t, cause);
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
		case kMemorystatusKilledFCThrashing:		jetsam_flags |= P_JETSAM_FCTHRASHING; break;
		case kMemorystatusKilledPerProcessLimit:	jetsam_flags |= P_JETSAM_PID; break;
		case kMemorystatusKilledIdleExit:		jetsam_flags |= P_JETSAM_IDLEEXIT; break;
	}
	error = jetsam_do_kill(p, jetsam_flags, jetsam_reason);

	KERNEL_DEBUG_CONSTANT( (BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_DO_KILL)) | DBG_FUNC_END, 
			       victim_pid, cause, vm_page_free_count, error, 0);

	vm_run_compactor();

	return (error == 0);
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

/* 
 * Pin a process to a particular jetsam band when it is in the background i.e. not doing active work.
 * For an application: that means no longer in the FG band
 * For a daemon: that means no longer in its 'requested' jetsam priority band
 */

int
memorystatus_update_inactive_jetsam_priority_band(pid_t pid, uint32_t op_flags, boolean_t effective_now)
{
	int error = 0;	
	boolean_t enable = FALSE;
	proc_t	p = NULL;

	if (op_flags == MEMORYSTATUS_CMD_ELEVATED_INACTIVEJETSAMPRIORITY_ENABLE) {
		enable = TRUE;
	} else if (op_flags == MEMORYSTATUS_CMD_ELEVATED_INACTIVEJETSAMPRIORITY_DISABLE) {
		enable = FALSE;
	} else {
		return EINVAL;
	}

	p = proc_find(pid);
	if (p != NULL) {

		if ((enable && ((p->p_memstat_state & P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND) == P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND)) ||
		    (!enable && ((p->p_memstat_state & P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND) == 0))) {
			/*
			 * No change in state.
			 */

		} else {

			proc_list_lock();

			if (enable) {
				p->p_memstat_state |= P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND;
				memorystatus_invalidate_idle_demotion_locked(p, TRUE);

				if (effective_now) {
					if (p->p_memstat_effectivepriority < JETSAM_PRIORITY_ELEVATED_INACTIVE) {
						boolean_t trigger_exception;
						CACHE_ACTIVE_LIMITS_LOCKED(p, trigger_exception);
						task_set_phys_footprint_limit_internal(p->task, (p->p_memstat_memlimit > 0) ? p->p_memstat_memlimit : -1, NULL, trigger_exception);
						memorystatus_update_priority_locked(p, JETSAM_PRIORITY_ELEVATED_INACTIVE, FALSE, FALSE);
					}
				} else {
					if (isProcessInAgingBands(p)) {
						memorystatus_update_priority_locked(p, JETSAM_PRIORITY_IDLE, FALSE, TRUE);
					}
				}
			} else {

				p->p_memstat_state &= ~P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND;
				memorystatus_invalidate_idle_demotion_locked(p, TRUE);

				if (effective_now) {
					if (p->p_memstat_effectivepriority == JETSAM_PRIORITY_ELEVATED_INACTIVE) {
						memorystatus_update_priority_locked(p, JETSAM_PRIORITY_IDLE, FALSE, TRUE);
					}
				} else {
					if (isProcessInAgingBands(p)) {
						memorystatus_update_priority_locked(p, JETSAM_PRIORITY_IDLE, FALSE, TRUE);
					}
				}
			}

			proc_list_unlock();
		}
		proc_rele(p);
		error = 0;

	} else {
		error = ESRCH;
	}

	return error;
}

static void
memorystatus_perform_idle_demotion(__unused void *spare1, __unused void *spare2) 
{
	proc_t p;
	uint64_t current_time = 0, idle_delay_time = 0;
	int demote_prio_band = 0;
	memstat_bucket_t *demotion_bucket;
   
	MEMORYSTATUS_DEBUG(1, "memorystatus_perform_idle_demotion()\n");
   
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_IDLE_DEMOTE) | DBG_FUNC_START, 0, 0, 0, 0, 0);
 
 	current_time = mach_absolute_time();
 
	proc_list_lock();

	demote_prio_band = JETSAM_PRIORITY_IDLE + 1;

	for (; demote_prio_band < JETSAM_PRIORITY_MAX; demote_prio_band++) {

		if (demote_prio_band != system_procs_aging_band && demote_prio_band != applications_aging_band)
			continue;

		demotion_bucket = &memstat_bucket[demote_prio_band];
		p = TAILQ_FIRST(&demotion_bucket->list);
		    
		while (p) {
			MEMORYSTATUS_DEBUG(1, "memorystatus_perform_idle_demotion() found %d\n", p->p_pid);
			
			assert(p->p_memstat_idledeadline);

			assert(p->p_memstat_dirty & P_DIRTY_AGING_IN_PROGRESS);

			if (current_time >= p->p_memstat_idledeadline) {

				if ((isSysProc(p) &&
				    ((p->p_memstat_dirty & (P_DIRTY_IDLE_EXIT_ENABLED|P_DIRTY_IS_DIRTY)) != P_DIRTY_IDLE_EXIT_ENABLED)) || /* system proc marked dirty*/
					task_has_assertions((struct task *)(p->task))) { /* has outstanding assertions which might indicate outstanding work too */
					idle_delay_time = (isSysProc(p)) ? memorystatus_sysprocs_idle_delay_time : memorystatus_apps_idle_delay_time;

					p->p_memstat_idledeadline += idle_delay_time;
					p = TAILQ_NEXT(p, p_memstat_list);

				} else {
			
					proc_t next_proc = NULL;

					next_proc = TAILQ_NEXT(p, p_memstat_list);
					memorystatus_invalidate_idle_demotion_locked(p, TRUE);

					memorystatus_update_priority_locked(p, JETSAM_PRIORITY_IDLE, false, true);
					
					p = next_proc;
					continue;
					
				}
			} else {
				// No further candidates
				break;
			}
		}

	}

	memorystatus_reschedule_idle_demotion_locked();
	
	proc_list_unlock();

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_IDLE_DEMOTE) | DBG_FUNC_END, 0, 0, 0, 0, 0);
}

static void
memorystatus_schedule_idle_demotion_locked(proc_t p, boolean_t set_state) 
{	
	boolean_t present_in_sysprocs_aging_bucket = FALSE;
	boolean_t present_in_apps_aging_bucket = FALSE;
	uint64_t  idle_delay_time = 0;

	if (jetsam_aging_policy == kJetsamAgingPolicyNone) {
		return;
	}

	if (p->p_memstat_state & P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND) {
		/*
		 * This process isn't going to be making the trip to the lower bands.
		 */
		return;
	}

	if (isProcessInAgingBands(p)){
		
		if (jetsam_aging_policy != kJetsamAgingPolicyLegacy) {
			assert((p->p_memstat_dirty & P_DIRTY_AGING_IN_PROGRESS) != P_DIRTY_AGING_IN_PROGRESS);
		}

		if (isSysProc(p) && system_procs_aging_band) {
			present_in_sysprocs_aging_bucket = TRUE;

		} else if (isApp(p) && applications_aging_band) {
			present_in_apps_aging_bucket = TRUE;
		}
	}

	assert(!present_in_sysprocs_aging_bucket);
	assert(!present_in_apps_aging_bucket);

	MEMORYSTATUS_DEBUG(1, "memorystatus_schedule_idle_demotion_locked: scheduling demotion to idle band for pid %d (dirty:0x%x, set_state %d, demotions %d).\n", 
	    p->p_pid, p->p_memstat_dirty, set_state, (memorystatus_scheduled_idle_demotions_sysprocs + memorystatus_scheduled_idle_demotions_apps));

	if(isSysProc(p)) {
		assert((p->p_memstat_dirty & P_DIRTY_IDLE_EXIT_ENABLED) == P_DIRTY_IDLE_EXIT_ENABLED);
	}

	idle_delay_time = (isSysProc(p)) ? memorystatus_sysprocs_idle_delay_time : memorystatus_apps_idle_delay_time;

	if (set_state) {
		p->p_memstat_dirty |= P_DIRTY_AGING_IN_PROGRESS;
		p->p_memstat_idledeadline = mach_absolute_time() + idle_delay_time;
	}
	
	assert(p->p_memstat_idledeadline);
	
 	if (isSysProc(p) && present_in_sysprocs_aging_bucket == FALSE) {
		memorystatus_scheduled_idle_demotions_sysprocs++;

	} else if (isApp(p) && present_in_apps_aging_bucket == FALSE) {
		memorystatus_scheduled_idle_demotions_apps++;
	}
}

static void
memorystatus_invalidate_idle_demotion_locked(proc_t p, boolean_t clear_state) 
{
	boolean_t present_in_sysprocs_aging_bucket = FALSE;
	boolean_t present_in_apps_aging_bucket = FALSE;

	if (!system_procs_aging_band && !applications_aging_band) {
		return;
	}

	if ((p->p_memstat_dirty & P_DIRTY_AGING_IN_PROGRESS) == 0) {
		return;
	}

	if (isProcessInAgingBands(p)) {
		
		if (jetsam_aging_policy != kJetsamAgingPolicyLegacy) {
			assert((p->p_memstat_dirty & P_DIRTY_AGING_IN_PROGRESS) == P_DIRTY_AGING_IN_PROGRESS);
		}

		if (isSysProc(p) && system_procs_aging_band) {
			assert(p->p_memstat_effectivepriority == system_procs_aging_band);
			assert(p->p_memstat_idledeadline);
			present_in_sysprocs_aging_bucket = TRUE;

		} else if (isApp(p) && applications_aging_band) {
			assert(p->p_memstat_effectivepriority == applications_aging_band);
			assert(p->p_memstat_idledeadline);
			present_in_apps_aging_bucket = TRUE;
		}
	}

	MEMORYSTATUS_DEBUG(1, "memorystatus_invalidate_idle_demotion(): invalidating demotion to idle band for pid %d (clear_state %d, demotions %d).\n", 
	    p->p_pid, clear_state, (memorystatus_scheduled_idle_demotions_sysprocs + memorystatus_scheduled_idle_demotions_apps));
    
 
	if (clear_state) {
 		p->p_memstat_idledeadline = 0;
 		p->p_memstat_dirty &= ~P_DIRTY_AGING_IN_PROGRESS;
	}
 	
 	if (isSysProc(p) &&present_in_sysprocs_aging_bucket == TRUE) {
		memorystatus_scheduled_idle_demotions_sysprocs--;
		assert(memorystatus_scheduled_idle_demotions_sysprocs >= 0);

	} else if (isApp(p) && present_in_apps_aging_bucket == TRUE) {
		memorystatus_scheduled_idle_demotions_apps--;
		assert(memorystatus_scheduled_idle_demotions_apps >= 0);
	}

 	assert((memorystatus_scheduled_idle_demotions_sysprocs + memorystatus_scheduled_idle_demotions_apps) >= 0);
}

static void
memorystatus_reschedule_idle_demotion_locked(void) {
 	if (0 == (memorystatus_scheduled_idle_demotions_sysprocs + memorystatus_scheduled_idle_demotions_apps)) {
 	 	if (memstat_idle_demotion_deadline) {
 	 	 	/* Transitioned 1->0, so cancel next call */
 	 	 	thread_call_cancel(memorystatus_idle_demotion_call);
 	 	 	memstat_idle_demotion_deadline = 0;
 		}
 	} else {
 		memstat_bucket_t *demotion_bucket;
 		proc_t p = NULL, p1 = NULL, p2 = NULL;

 		if (system_procs_aging_band) {
			
			demotion_bucket = &memstat_bucket[system_procs_aging_band];
			p1 = TAILQ_FIRST(&demotion_bucket->list);

			p = p1;
		}

 		if (applications_aging_band) {
			
			demotion_bucket = &memstat_bucket[applications_aging_band];
			p2 = TAILQ_FIRST(&demotion_bucket->list);

			if (p1 && p2) {
				p = (p1->p_memstat_idledeadline > p2->p_memstat_idledeadline) ? p2 : p1;
			} else {
				p = (p1 == NULL) ? p2 : p1;
			}

		}

		assert(p);

		if (p != NULL) {
			assert(p && p->p_memstat_idledeadline);
			if (memstat_idle_demotion_deadline != p->p_memstat_idledeadline){
				thread_call_enter_delayed(memorystatus_idle_demotion_call, p->p_memstat_idledeadline);
				memstat_idle_demotion_deadline = p->p_memstat_idledeadline;
			}
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
	
	MEMORYSTATUS_DEBUG(1, "memorystatus_list_add(): adding pid %d with priority %d.\n", p->p_pid, p->p_memstat_effectivepriority);

	if (!locked) {
   	   	proc_list_lock();
   	}

	DTRACE_MEMORYSTATUS2(memorystatus_add, proc_t, p, int32_t, p->p_memstat_effectivepriority);

	/* Processes marked internal do not have priority tracked */
	if (p->p_memstat_state & P_MEMSTAT_INTERNAL) {
                goto exit;
	}
	
	bucket = &memstat_bucket[p->p_memstat_effectivepriority];
	
	if (isSysProc(p) && system_procs_aging_band && (p->p_memstat_effectivepriority == system_procs_aging_band)) {
		assert(bucket->count == memorystatus_scheduled_idle_demotions_sysprocs - 1);

	} else if (isApp(p) && applications_aging_band && (p->p_memstat_effectivepriority == applications_aging_band)) {
		assert(bucket->count == memorystatus_scheduled_idle_demotions_apps - 1);

	} else if (p->p_memstat_effectivepriority == JETSAM_PRIORITY_IDLE) {
		/*
		 * Entering the idle band.
		 * Record idle start time.
		 */
		p->p_memstat_idle_start = mach_absolute_time();
	}

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

/*
 * Description:
 *	Moves a process from one jetsam bucket to another.
 *	which changes the LRU position of the process.
 *
 *	Monitors transition between buckets and if necessary
 *	will update cached memory limits accordingly.
 *
 *	skip_demotion_check:
 *	- if the 'jetsam aging policy' is NOT 'legacy':
 *		When this flag is TRUE, it means we are going
 *		to age the ripe processes out of the aging bands and into the
 *		IDLE band and apply their inactive memory limits.
 *
 *	- if the 'jetsam aging policy' is 'legacy':
 *		When this flag is TRUE, it might mean the above aging mechanism
 *		OR
 *		It might be that we have a process that has used up its 'idle deferral'
 *		stay that is given to it once per lifetime. And in this case, the process
 *		won't be going through any aging codepaths. But we still need to apply
 *		the right inactive limits and so we explicitly set this to TRUE if the
 *		new priority for the process is the IDLE band.
 */
void
memorystatus_update_priority_locked(proc_t p, int priority, boolean_t head_insert, boolean_t skip_demotion_check)
{
	memstat_bucket_t *old_bucket, *new_bucket;
	
	assert(priority < MEMSTAT_BUCKET_COUNT);
	
	/* Ensure that exit isn't underway, leaving the proc retained but removed from its bucket */
	if ((p->p_listflag & P_LIST_EXITED) != 0) {
		return;
	}

	MEMORYSTATUS_DEBUG(1, "memorystatus_update_priority_locked(): setting %s(%d) to priority %d, inserting at %s\n",
			   (*p->p_name ? p->p_name : "unknown"), p->p_pid, priority, head_insert ? "head" : "tail");

	DTRACE_MEMORYSTATUS3(memorystatus_update_priority, proc_t, p, int32_t, p->p_memstat_effectivepriority, int, priority);

#if DEVELOPMENT || DEBUG
	if (priority == JETSAM_PRIORITY_IDLE && /* if the process is on its way into the IDLE band */
	    skip_demotion_check == FALSE &&	/* and it isn't via the path that will set the INACTIVE memlimits */
	    (p->p_memstat_dirty & P_DIRTY_TRACK) && /* and it has 'DIRTY' tracking enabled */
	    ((p->p_memstat_memlimit != p->p_memstat_memlimit_inactive) || /* and we notice that the current limit isn't the right value (inactive) */
	    ((p->p_memstat_state & P_MEMSTAT_MEMLIMIT_INACTIVE_FATAL) ? ( ! (p->p_memstat_state & P_MEMSTAT_FATAL_MEMLIMIT)) : (p->p_memstat_state & P_MEMSTAT_FATAL_MEMLIMIT)))) /* OR type (fatal vs non-fatal) */
		panic("memorystatus_update_priority_locked: on %s with 0x%x, prio: %d and %d\n", p->p_name, p->p_memstat_state, priority, p->p_memstat_memlimit); /* then we must catch this */
#endif /* DEVELOPMENT || DEBUG */

	old_bucket = &memstat_bucket[p->p_memstat_effectivepriority];

	if (skip_demotion_check == FALSE) {

		if (isSysProc(p)) {
			/*
			 * For system processes, the memorystatus_dirty_* routines take care of adding/removing
			 * the processes from the aging bands and balancing the demotion counts.
			 * We can, however, override that if the process has an 'elevated inactive jetsam band' attribute.
			 */

			if (priority <= JETSAM_PRIORITY_ELEVATED_INACTIVE && (p->p_memstat_state & P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND)) {
				priority = JETSAM_PRIORITY_ELEVATED_INACTIVE;

				assert(! (p->p_memstat_dirty & P_DIRTY_AGING_IN_PROGRESS));
			}
		} else if (isApp(p)) {
		
			/*
			 * Check to see if the application is being lowered in jetsam priority. If so, and:
			 * - it has an 'elevated inactive jetsam band' attribute, then put it in the JETSAM_PRIORITY_ELEVATED_INACTIVE band.
			 * - it is a normal application, then let it age in the aging band if that policy is in effect.
			 */
	
			if (priority <= JETSAM_PRIORITY_ELEVATED_INACTIVE && (p->p_memstat_state & P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND)) {
				priority = JETSAM_PRIORITY_ELEVATED_INACTIVE;
			} else {

				if (applications_aging_band) {
			       		if (p->p_memstat_effectivepriority == applications_aging_band) {
						assert(old_bucket->count == (memorystatus_scheduled_idle_demotions_apps + 1));
					}

					if ((jetsam_aging_policy != kJetsamAgingPolicyLegacy) && (priority <= applications_aging_band)) {
						assert(! (p->p_memstat_dirty & P_DIRTY_AGING_IN_PROGRESS));
						priority = applications_aging_band;
						memorystatus_schedule_idle_demotion_locked(p, TRUE);
					}
				}
			}
		}
	}

	if ((system_procs_aging_band && (priority == system_procs_aging_band)) || (applications_aging_band && (priority == applications_aging_band))) {
		assert(p->p_memstat_dirty & P_DIRTY_AGING_IN_PROGRESS);
	}

	TAILQ_REMOVE(&old_bucket->list, p, p_memstat_list);
	old_bucket->count--;

	new_bucket = &memstat_bucket[priority];	
	if (head_insert)
		TAILQ_INSERT_HEAD(&new_bucket->list, p, p_memstat_list);
	else
		TAILQ_INSERT_TAIL(&new_bucket->list, p, p_memstat_list);
	new_bucket->count++;

	if (memorystatus_highwater_enabled) {
		boolean_t trigger_exception;

		/* 
		 * If cached limit data is updated, then the limits
		 * will be enforced by writing to the ledgers.
		 */
		boolean_t ledger_update_needed = TRUE;

		/*
		 * No need to consider P_MEMSTAT_MEMLIMIT_BACKGROUND anymore.
		 * Background limits are described via the inactive limit slots.
		 *
		 * Here, we must update the cached memory limit if the task 
		 * is transitioning between:
		 * 	active <--> inactive
		 *	FG     <-->       BG
		 * but:
		 *	dirty  <-->    clean   is ignored
		 *
		 * We bypass non-idle processes that have opted into dirty tracking because
		 * a move between buckets does not imply a transition between the
		 * dirty <--> clean state.
		 */

		if (p->p_memstat_dirty & P_DIRTY_TRACK) {

			if (skip_demotion_check == TRUE && priority == JETSAM_PRIORITY_IDLE) {
				CACHE_INACTIVE_LIMITS_LOCKED(p, trigger_exception);
			} else {
				ledger_update_needed = FALSE;
			}

		} else if ((priority >= JETSAM_PRIORITY_FOREGROUND) && (p->p_memstat_effectivepriority < JETSAM_PRIORITY_FOREGROUND)) {
			/*
			 * 	inactive --> active
			 *	BG       -->     FG
			 *      assign active state
			 */
			CACHE_ACTIVE_LIMITS_LOCKED(p, trigger_exception);

		} else if ((priority < JETSAM_PRIORITY_FOREGROUND) && (p->p_memstat_effectivepriority >= JETSAM_PRIORITY_FOREGROUND)) {
			/*
			 * 	active --> inactive
			 *	FG     -->       BG
			 *      assign inactive state
			 */
			CACHE_INACTIVE_LIMITS_LOCKED(p, trigger_exception);
		} else {
			/*
			 * The transition between jetsam priority buckets apparently did
			 * not affect active/inactive state.
			 * This is not unusual... especially during startup when
			 * processes are getting established in their respective bands.
			 */
			ledger_update_needed = FALSE;
		}

		/*
		 * Enforce the new limits by writing to the ledger
		 */
		if (ledger_update_needed) {
			task_set_phys_footprint_limit_internal(p->task, (p->p_memstat_memlimit > 0) ? p->p_memstat_memlimit : -1, NULL, trigger_exception);

			MEMORYSTATUS_DEBUG(3, "memorystatus_update_priority_locked: new limit on pid %d (%dMB %s) priority old --> new (%d --> %d) dirty?=0x%x %s\n",
					   p->p_pid, (p->p_memstat_memlimit > 0 ? p->p_memstat_memlimit : -1),
					   (p->p_memstat_state & P_MEMSTAT_FATAL_MEMLIMIT ? "F " : "NF"), p->p_memstat_effectivepriority, priority, p->p_memstat_dirty,
					   (p->p_memstat_dirty ? ((p->p_memstat_dirty & P_DIRTY) ? "isdirty" : "isclean") : ""));
		}
	}

	/*
	 * Record idle start or idle delta.
	 */
	if (p->p_memstat_effectivepriority == priority) {
		/*	
		 * This process is not transitioning between
		 * jetsam priority buckets.  Do nothing.
		 */
	} else if (p->p_memstat_effectivepriority == JETSAM_PRIORITY_IDLE) {
		uint64_t now;
		/*
		 * Transitioning out of the idle priority bucket.
		 * Record idle delta.
		 */
		assert(p->p_memstat_idle_start != 0);
		now = mach_absolute_time();
		if (now > p->p_memstat_idle_start) {
			p->p_memstat_idle_delta = now - p->p_memstat_idle_start;
		}
	} else if (priority == JETSAM_PRIORITY_IDLE) {
		/*
		 * Transitioning into the idle priority bucket.
		 * Record idle start.
		 */
		p->p_memstat_idle_start = mach_absolute_time();
	}

	p->p_memstat_effectivepriority = priority;

#if CONFIG_SECLUDED_MEMORY
	if (secluded_for_apps &&
	    task_could_use_secluded_mem(p->task)) {
		task_set_can_use_secluded_mem(
			p->task,
			(priority >= JETSAM_PRIORITY_FOREGROUND));
	}
#endif /* CONFIG_SECLUDED_MEMORY */
	
	memorystatus_check_levels_locked();
}

/*
 *
 * Description: Update the jetsam priority and memory limit attributes for a given process.
 *
 * Parameters:
 *	p	init this process's jetsam information.
 *	priority          The jetsam priority band
 *	user_data	  user specific data, unused by the kernel
 *	effective	  guards against race if process's update already occurred
 *	update_memlimit   When true we know this is the init step via the posix_spawn path.
 *
 *	memlimit_active	  Value in megabytes; The monitored footprint level while the
 *			  process is active.  Exceeding it may result in termination
 *			  based on it's associated fatal flag.
 *
 *	memlimit_active_is_fatal  When a process is active and exceeds its memory footprint,
 *				  this describes whether or not it should be immediately fatal.
 *
 *	memlimit_inactive Value in megabytes; The monitored footprint level while the
 *			  process is inactive.  Exceeding it may result in termination
 *			  based on it's associated fatal flag.
 *
 *	memlimit_inactive_is_fatal  When a process is inactive and exceeds its memory footprint,
 *				    this describes whether or not it should be immediatly fatal.
 *
 *	memlimit_background	This process has a high-water-mark while in the background.
 *				No longer meaningful.  Background limits are described via
 *				the inactive slots.  Flag is ignored.
 *
 *
 * Returns:     0	Success
 *		non-0	Failure
 */

int
memorystatus_update(proc_t p, int priority, uint64_t user_data, boolean_t effective, boolean_t update_memlimit,
		    int32_t memlimit_active,   boolean_t memlimit_active_is_fatal,
                    int32_t memlimit_inactive, boolean_t memlimit_inactive_is_fatal,
                    __unused boolean_t memlimit_background)
{
	int ret;
	boolean_t head_insert = false;

	MEMORYSTATUS_DEBUG(1, "memorystatus_update: changing (%s) pid %d: priority %d, user_data 0x%llx\n", (*p->p_name ? p->p_name : "unknown"), p->p_pid, priority, user_data);

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_UPDATE) | DBG_FUNC_START, p->p_pid, priority, user_data, effective, 0);
	
	if (priority == -1) {
		/* Use as shorthand for default priority */
		priority = JETSAM_PRIORITY_DEFAULT;
	} else if ((priority == system_procs_aging_band) || (priority == applications_aging_band)) {
		/* Both the aging bands are reserved for internal use; if requested, adjust to JETSAM_PRIORITY_IDLE. */
		priority = JETSAM_PRIORITY_IDLE;	        
	} else if (priority == JETSAM_PRIORITY_IDLE_HEAD) {
		/* JETSAM_PRIORITY_IDLE_HEAD inserts at the head of the idle queue */
		priority = JETSAM_PRIORITY_IDLE;
		head_insert = TRUE;
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
		MEMORYSTATUS_DEBUG(1, "memorystatus_update: effective change specified for pid %d, but change already occurred.\n", p->p_pid);
		goto out;             
	}

	if ((p->p_memstat_state & P_MEMSTAT_TERMINATED) || ((p->p_listflag & P_LIST_EXITED) != 0)) {
		/*
		 * This could happen when a process calling posix_spawn() is exiting on the jetsam thread.
		 */
		ret = EBUSY;
		proc_list_unlock();
		goto out;             
	}

	p->p_memstat_state |= P_MEMSTAT_PRIORITYUPDATED;
	p->p_memstat_userdata = user_data;
	p->p_memstat_requestedpriority = priority;

	if (update_memlimit) {
		boolean_t trigger_exception;

		/*
		 * Posix_spawn'd processes come through this path to instantiate ledger limits.
		 * Forked processes do not come through this path, so no ledger limits exist.
		 * (That's why forked processes can consume unlimited memory.)
		 */

		MEMORYSTATUS_DEBUG(3, "memorystatus_update(enter): pid %d, priority %d, dirty=0x%x, Active(%dMB %s), Inactive(%dMB, %s)\n",
				   p->p_pid, priority, p->p_memstat_dirty,
				   memlimit_active,   (memlimit_active_is_fatal ? "F " : "NF"),
				   memlimit_inactive, (memlimit_inactive_is_fatal ? "F " : "NF"));

		if (memlimit_background) {

			/*
			 * With 2-level HWM support, we no longer honor P_MEMSTAT_MEMLIMIT_BACKGROUND.
			 * Background limits are described via the inactive limit slots.
			 */

			// p->p_memstat_state |= P_MEMSTAT_MEMLIMIT_BACKGROUND;

#if DEVELOPMENT || DEBUG
			printf("memorystatus_update: WARNING %s[%d] set unused flag P_MEMSTAT_MEMLIMIT_BACKGROUND [A==%dMB %s] [IA==%dMB %s]\n",
			       (*p->p_name ? p->p_name : "unknown"), p->p_pid,
			       memlimit_active, (memlimit_active_is_fatal ? "F " : "NF"),
			       memlimit_inactive, (memlimit_inactive_is_fatal ? "F " : "NF"));
#endif /* DEVELOPMENT || DEBUG */
		}

		if (memlimit_active <= 0) {
			/*
			 * This process will have a system_wide task limit when active.
			 * System_wide task limit is always fatal.
			 * It's quite common to see non-fatal flag passed in here.
			 * It's not an error, we just ignore it.
			 */

			/*
			 * For backward compatibility with some unexplained launchd behavior,
			 * we allow a zero sized limit.  But we still enforce system_wide limit
			 * when written to the ledgers.  
			 */

			if (memlimit_active < 0) {
				memlimit_active = -1;  /* enforces system_wide task limit */
			}
			memlimit_active_is_fatal = TRUE;
		}

		if (memlimit_inactive <= 0) {
			/*
			 * This process will have a system_wide task limit when inactive.
			 * System_wide task limit is always fatal.
			 */

			memlimit_inactive = -1;
			memlimit_inactive_is_fatal = TRUE;
		}

		/*
		 * Initialize the active limit variants for this process.
		 */
		SET_ACTIVE_LIMITS_LOCKED(p, memlimit_active, memlimit_active_is_fatal);

		/*
		 * Initialize the inactive limit variants for this process.
		 */
		SET_INACTIVE_LIMITS_LOCKED(p, memlimit_inactive, memlimit_inactive_is_fatal);

		/*
		 * Initialize the cached limits for target process.
		 * When the target process is dirty tracked, it's typically
		 * in a clean state.  Non dirty tracked processes are
		 * typically active (Foreground or above).
		 * But just in case, we don't make assumptions...
		 */

		if (proc_jetsam_state_is_active_locked(p) == TRUE) {
			CACHE_ACTIVE_LIMITS_LOCKED(p, trigger_exception);
		} else {
			CACHE_INACTIVE_LIMITS_LOCKED(p, trigger_exception);
		}

		/*
		 * Enforce the cached limit by writing to the ledger.
		 */
		if (memorystatus_highwater_enabled) {
			/* apply now */
			assert(trigger_exception == TRUE);
			task_set_phys_footprint_limit_internal(p->task, ((p->p_memstat_memlimit > 0) ? p->p_memstat_memlimit : -1), NULL, trigger_exception);

			MEMORYSTATUS_DEBUG(3, "memorystatus_update: init: limit on pid %d (%dMB %s) targeting priority(%d) dirty?=0x%x %s\n",
					   p->p_pid, (p->p_memstat_memlimit > 0 ? p->p_memstat_memlimit : -1),
					   (p->p_memstat_state & P_MEMSTAT_FATAL_MEMLIMIT ? "F " : "NF"), priority, p->p_memstat_dirty,
					   (p->p_memstat_dirty ? ((p->p_memstat_dirty & P_DIRTY) ? "isdirty" : "isclean") : ""));
		}
	}

	/*
	 * We can't add to the aging bands buckets here.
	 * But, we could be removing it from those buckets.
	 * Check and take appropriate steps if so.
	 */
	
	if (isProcessInAgingBands(p)) {
		
		memorystatus_invalidate_idle_demotion_locked(p, TRUE);
		memorystatus_update_priority_locked(p, JETSAM_PRIORITY_IDLE, FALSE, TRUE);
	} else {
		if (jetsam_aging_policy == kJetsamAgingPolicyLegacy &&  priority == JETSAM_PRIORITY_IDLE) {
			/*
			 * Daemons with 'inactive' limits will go through the dirty tracking codepath.
			 * This path deals with apps that may have 'inactive' limits e.g. WebContent processes.
			 * If this is the legacy aging policy we explicitly need to apply those limits. If it
			 * is any other aging policy, then we don't need to worry because all processes
			 * will go through the aging bands and then the demotion thread will take care to
			 * move them into the IDLE band and apply the required limits.
			 */
			memorystatus_update_priority_locked(p, priority, head_insert, TRUE);
		}
	}

	memorystatus_update_priority_locked(p, priority, head_insert, FALSE);

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
	boolean_t	reschedule = FALSE;

	MEMORYSTATUS_DEBUG(1, "memorystatus_list_remove: removing pid %d\n", p->p_pid);

   	if (!locked) {
   	   	proc_list_lock();
   	}

	assert(!(p->p_memstat_state & P_MEMSTAT_INTERNAL));
	
	bucket = &memstat_bucket[p->p_memstat_effectivepriority];

	if (isSysProc(p) && system_procs_aging_band && (p->p_memstat_effectivepriority == system_procs_aging_band)) {

		assert(bucket->count == memorystatus_scheduled_idle_demotions_sysprocs);
		reschedule = TRUE;

	} else if (isApp(p) && applications_aging_band && (p->p_memstat_effectivepriority == applications_aging_band)) {

		assert(bucket->count == memorystatus_scheduled_idle_demotions_apps);
		reschedule = TRUE;
	}

	/*
	 * Record idle delta
	 */

	if (p->p_memstat_effectivepriority == JETSAM_PRIORITY_IDLE) {
		uint64_t now = mach_absolute_time();
		if (now > p->p_memstat_idle_start) {
			p->p_memstat_idle_delta = now - p->p_memstat_idle_start;
		}
	}

	TAILQ_REMOVE(&bucket->list, p, p_memstat_list);
	bucket->count--;

	memorystatus_list_count--;

	/* If awaiting demotion to the idle band, clean up */
	if (reschedule) {
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

/*
 * Validate dirty tracking flags with process state.
 *
 * Return:
 *	0     on success
 * 	non-0 on failure
 *
 * The proc_list_lock is held by the caller.
 */

static int
memorystatus_validate_track_flags(struct proc *target_p, uint32_t pcontrol) {
	/* See that the process isn't marked for termination */
	if (target_p->p_memstat_dirty & P_DIRTY_TERMINATED) {
		return EBUSY;
	}
	
	/* Idle exit requires that process be tracked */
	if ((pcontrol & PROC_DIRTY_ALLOW_IDLE_EXIT) &&
	   !(pcontrol & PROC_DIRTY_TRACK)) {
		return EINVAL;
	}

	/* 'Launch in progress' tracking requires that process have enabled dirty tracking too. */
	if ((pcontrol & PROC_DIRTY_LAUNCH_IN_PROGRESS) &&
	   !(pcontrol & PROC_DIRTY_TRACK)) {
		return EINVAL;
	}

	/* Deferral is only relevant if idle exit is specified */
	if ((pcontrol & PROC_DIRTY_DEFER) && 
	   !(pcontrol & PROC_DIRTY_ALLOWS_IDLE_EXIT)) {
		return EINVAL;
	}
	
	return(0);
}

static void
memorystatus_update_idle_priority_locked(proc_t p) {
	int32_t priority;

	MEMORYSTATUS_DEBUG(1, "memorystatus_update_idle_priority_locked(): pid %d dirty 0x%X\n", p->p_pid, p->p_memstat_dirty);

	assert(isSysProc(p));	

	if ((p->p_memstat_dirty & (P_DIRTY_IDLE_EXIT_ENABLED|P_DIRTY_IS_DIRTY)) == P_DIRTY_IDLE_EXIT_ENABLED) {

		priority = (p->p_memstat_dirty & P_DIRTY_AGING_IN_PROGRESS) ? system_procs_aging_band : JETSAM_PRIORITY_IDLE;
	} else {
		priority = p->p_memstat_requestedpriority;
	}
	
	if (priority != p->p_memstat_effectivepriority) {

		if ((jetsam_aging_policy == kJetsamAgingPolicyLegacy) &&
		    (priority == JETSAM_PRIORITY_IDLE)) {

			/*
			 * This process is on its way into the IDLE band. The system is
			 * using 'legacy' jetsam aging policy. That means, this process
			 * has already used up its idle-deferral aging time that is given
			 * once per its lifetime. So we need to set the INACTIVE limits
			 * explicitly because it won't be going through the demotion paths
			 * that take care to apply the limits appropriately.
			 */
			memorystatus_update_priority_locked(p, priority, false, true);

		} else {
			memorystatus_update_priority_locked(p, priority, false, false);
		}
	}
} 

/*
 * Processes can opt to have their state tracked by the kernel, indicating  when they are busy (dirty) or idle
 * (clean). They may also indicate that they support termination when idle, with the result that they are promoted
 * to their desired, higher, jetsam priority when dirty (and are therefore killed later), and demoted to the low
 * priority idle band when clean (and killed earlier, protecting higher priority procesess).
 *
 * If the deferral flag is set, then newly tracked processes will be protected for an initial period (as determined by
 * memorystatus_sysprocs_idle_delay_time); if they go clean during this time, then they will be moved to a deferred-idle band
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
	boolean_t already_deferred = FALSE;
	boolean_t defer_now = FALSE;
	int ret = 0;
    
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_DIRTY_TRACK),
		p->p_pid, p->p_memstat_dirty, pcontrol, 0, 0);
	
	proc_list_lock();
	
	if ((p->p_listflag & P_LIST_EXITED) != 0) {
		/*
		 * Process is on its way out.
		 */
		ret = EBUSY;
		goto exit;
	}

	if (p->p_memstat_state & P_MEMSTAT_INTERNAL) {
		ret = EPERM;
		goto exit;
	}
	
	if ((ret = memorystatus_validate_track_flags(p, pcontrol)) != 0) {
		/* error  */
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

	if (pcontrol & PROC_DIRTY_LAUNCH_IN_PROGRESS) {
		p->p_memstat_dirty |= P_DIRTY_LAUNCH_IN_PROGRESS;
	}

	if (old_dirty & P_DIRTY_AGING_IN_PROGRESS) {
		already_deferred = TRUE;
	}


	/* This can be set and cleared exactly once. */
	if (pcontrol & PROC_DIRTY_DEFER) {

	       	if ( !(old_dirty & P_DIRTY_DEFER)) {
			p->p_memstat_dirty |= P_DIRTY_DEFER;
		}

		defer_now = TRUE;
	}

	MEMORYSTATUS_DEBUG(1, "memorystatus_on_track_dirty(): set idle-exit %s / defer %s / dirty %s for pid %d\n",
		((p->p_memstat_dirty & P_DIRTY_IDLE_EXIT_ENABLED) == P_DIRTY_IDLE_EXIT_ENABLED) ? "Y" : "N",
		defer_now ? "Y" : "N",
		p->p_memstat_dirty & P_DIRTY ? "Y" : "N",
		p->p_pid);

	/* Kick off or invalidate the idle exit deferment if there's a state transition. */
	if (!(p->p_memstat_dirty & P_DIRTY_IS_DIRTY)) {
		if ((p->p_memstat_dirty & P_DIRTY_IDLE_EXIT_ENABLED) == P_DIRTY_IDLE_EXIT_ENABLED) {

			if (defer_now && !already_deferred) {
				
				/*
				 * Request to defer a clean process that's idle-exit enabled 
				 * and not already in the jetsam deferred band. Most likely a
				 * new launch.
				 */
				memorystatus_schedule_idle_demotion_locked(p, TRUE);
				reschedule = TRUE;

			} else if (!defer_now) {

				/*
				 * The process isn't asking for the 'aging' facility.
				 * Could be that it is:
				 */

				if (already_deferred) {
					/*
					 * already in the aging bands. Traditionally,
					 * some processes have tried to use this to
					 * opt out of the 'aging' facility.
					 */
				
					memorystatus_invalidate_idle_demotion_locked(p, TRUE);
				} else {
					/*
					 * agnostic to the 'aging' facility. In that case,
					 * we'll go ahead and opt it in because this is likely
					 * a new launch (clean process, dirty tracking enabled)
					 */
				
					memorystatus_schedule_idle_demotion_locked(p, TRUE);
				}

				reschedule = TRUE;
			}
		}
	} else {

		/*
		 * We are trying to operate on a dirty process. Dirty processes have to
		 * be removed from the deferred band. The question is do we reset the 
		 * deferred state or not?
		 *
		 * This could be a legal request like:
		 * - this process had opted into the 'aging' band
		 * - but it's now dirty and requests to opt out.
		 * In this case, we remove the process from the band and reset its
		 * state too. It'll opt back in properly when needed.
		 *
		 * OR, this request could be a user-space bug. E.g.:
		 * - this process had opted into the 'aging' band when clean
		 * - and, then issues another request to again put it into the band except
		 *   this time the process is dirty.
		 * The process going dirty, as a transition in memorystatus_dirty_set(), will pull the process out of
		 * the deferred band with its state intact. So our request below is no-op.
		 * But we do it here anyways for coverage.
		 *
		 * memorystatus_update_idle_priority_locked()
		 * single-mindedly treats a dirty process as "cannot be in the aging band".
		 */

		if (!defer_now && already_deferred) {
			memorystatus_invalidate_idle_demotion_locked(p, TRUE);
			reschedule = TRUE;
		} else {

			boolean_t reset_state = (jetsam_aging_policy != kJetsamAgingPolicyLegacy) ? TRUE : FALSE;

			memorystatus_invalidate_idle_demotion_locked(p, reset_state);
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
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_DIRTY_SET), p->p_pid, self, pcontrol, 0, 0);

	proc_list_lock();

	if ((p->p_listflag & P_LIST_EXITED) != 0) {
		/*
		 * Process is on its way out.
		 */
		ret = EBUSY;
		goto exit;
	}

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
			if ((flag == P_DIRTY_SHUTDOWN) && (!(p->p_memstat_dirty & P_DIRTY))) {
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
		if ((p->p_memstat_dirty & P_DIRTY_IDLE_EXIT_ENABLED) == P_DIRTY_IDLE_EXIT_ENABLED) {

			/*
			 * Legacy mode: P_DIRTY_AGING_IN_PROGRESS means the process is in the aging band OR it might be heading back
			 * there once it's clean again. For the legacy case, this only applies if it has some protection window left.
			 *
			 * Non-Legacy mode: P_DIRTY_AGING_IN_PROGRESS means the process is in the aging band. It will always stop over
			 * in that band on it's way to IDLE.
			 */

			if (p->p_memstat_dirty & P_DIRTY_IS_DIRTY) {
				/*
				 * New dirty process i.e. "was_dirty == FALSE && now_dirty == TRUE"
				 *
				 * The process will move from its aging band to its higher requested
				 * jetsam band. 
				 */
				boolean_t reset_state = (jetsam_aging_policy != kJetsamAgingPolicyLegacy) ? TRUE : FALSE;

				memorystatus_invalidate_idle_demotion_locked(p, reset_state);
				reschedule = TRUE;
			} else {

				/*
				 * Process is back from "dirty" to "clean".
				 */

				if (jetsam_aging_policy == kJetsamAgingPolicyLegacy) {
					if (mach_absolute_time() >= p->p_memstat_idledeadline) {
						/*
						 * The process' deadline has expired. It currently
						 * does not reside in any of the aging buckets.
						 * 
						 * It's on its way to the JETSAM_PRIORITY_IDLE 
						 * bucket via memorystatus_update_idle_priority_locked()
						 * below.
						 
						 * So all we need to do is reset all the state on the
						 * process that's related to the aging bucket i.e.
						 * the AGING_IN_PROGRESS flag and the timer deadline.
						 */

						memorystatus_invalidate_idle_demotion_locked(p, TRUE);
						reschedule = TRUE;
					} else {
						/*
						 * It still has some protection window left and so
						 * we just re-arm the timer without modifying any
						 * state on the process iff it still wants into that band.
						 */

						if (p->p_memstat_dirty & P_DIRTY_AGING_IN_PROGRESS) {
							memorystatus_schedule_idle_demotion_locked(p, FALSE);
							reschedule = TRUE;
						}
					}
				} else {

					memorystatus_schedule_idle_demotion_locked(p, TRUE);
					reschedule = TRUE;
				}
			}
		}

		memorystatus_update_idle_priority_locked(p);

		if (memorystatus_highwater_enabled) {
			boolean_t trigger_exception = FALSE, ledger_update_needed = TRUE;
			/* 
			 * We are in this path because this process transitioned between 
			 * dirty <--> clean state.  Update the cached memory limits.
			 */

			if (proc_jetsam_state_is_active_locked(p) == TRUE) {
				/*
				 * process is dirty
				 */
				CACHE_ACTIVE_LIMITS_LOCKED(p, trigger_exception);
				ledger_update_needed = TRUE;
			} else {
				/*
				 * process is clean...but if it has opted into pressured-exit
				 * we don't apply the INACTIVE limit till the process has aged
				 * out and is entering the IDLE band.
				 * See memorystatus_update_priority_locked() for that.
				 */
			
				if (p->p_memstat_dirty & P_DIRTY_ALLOW_IDLE_EXIT) {
					ledger_update_needed = FALSE;
				} else {
					CACHE_INACTIVE_LIMITS_LOCKED(p, trigger_exception);
					ledger_update_needed = TRUE;
				}
			}

			/*
			 * Enforce the new limits by writing to the ledger.
			 *
			 * This is a hot path and holding the proc_list_lock while writing to the ledgers,
			 * (where the task lock is taken) is bad.  So, we temporarily drop the proc_list_lock.
			 * We aren't traversing the jetsam bucket list here, so we should be safe.
			 * See rdar://21394491.
			 */

			if (ledger_update_needed && proc_ref_locked(p) == p) {
				int ledger_limit;
				if (p->p_memstat_memlimit > 0) {
					ledger_limit = p->p_memstat_memlimit;
				} else {
					ledger_limit = -1;
				}
				proc_list_unlock();
				task_set_phys_footprint_limit_internal(p->task, ledger_limit, NULL, trigger_exception);
				proc_list_lock();
				proc_rele_locked(p);

				MEMORYSTATUS_DEBUG(3, "memorystatus_dirty_set: new limit on pid %d (%dMB %s) priority(%d) dirty?=0x%x %s\n",
					   p->p_pid, (p->p_memstat_memlimit > 0 ? p->p_memstat_memlimit : -1),
					   (p->p_memstat_state & P_MEMSTAT_FATAL_MEMLIMIT ? "F " : "NF"), p->p_memstat_effectivepriority, p->p_memstat_dirty,
					   (p->p_memstat_dirty ? ((p->p_memstat_dirty & P_DIRTY) ? "isdirty" : "isclean") : ""));
			}

		}
	
		/* If the deferral state changed, reschedule the demotion timer */
		if (reschedule) {
			memorystatus_reschedule_idle_demotion_locked();
		}
	}

	if (kill) {
		if (proc_ref_locked(p) == p) {
			proc_list_unlock();
			psignal(p, SIGKILL);
			proc_list_lock();
			proc_rele_locked(p);
		}
	}
	
exit:
	proc_list_unlock();

	return ret;
}

int
memorystatus_dirty_clear(proc_t p, uint32_t pcontrol) {

	int ret = 0;

	MEMORYSTATUS_DEBUG(1, "memorystatus_dirty_clear(): %d 0x%x 0x%x\n", p->p_pid, pcontrol, p->p_memstat_dirty);
	
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_DIRTY_CLEAR), p->p_pid, pcontrol, 0, 0, 0);

	proc_list_lock();

	if ((p->p_listflag & P_LIST_EXITED) != 0) {
		/*
		 * Process is on its way out.
		 */
		ret = EBUSY;
		goto exit;
	}

	if (p->p_memstat_state & P_MEMSTAT_INTERNAL) {
		ret = EPERM;
		goto exit;
	}

	if (!(p->p_memstat_dirty & P_DIRTY_TRACK)) {
		/* Dirty tracking not enabled */
		ret = EINVAL;			
		goto exit;
	} 

	if (!pcontrol || (pcontrol & (PROC_DIRTY_LAUNCH_IN_PROGRESS | PROC_DIRTY_DEFER)) == 0) {
		ret = EINVAL;
		goto exit;
	}

	if (pcontrol & PROC_DIRTY_LAUNCH_IN_PROGRESS) {
		p->p_memstat_dirty &= ~P_DIRTY_LAUNCH_IN_PROGRESS;
	}

	/* This can be set and cleared exactly once. */
	if (pcontrol & PROC_DIRTY_DEFER) {

	       	if (p->p_memstat_dirty & P_DIRTY_DEFER) {

			p->p_memstat_dirty &= ~P_DIRTY_DEFER;

			memorystatus_invalidate_idle_demotion_locked(p, TRUE);
			memorystatus_update_idle_priority_locked(p);
			memorystatus_reschedule_idle_demotion_locked();
		}
	}

	ret = 0;
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
		if (p->p_memstat_dirty & P_DIRTY_LAUNCH_IN_PROGRESS) {
			ret |= PROC_DIRTY_LAUNCH_IS_IN_PROGRESS;
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
	memorystatus_get_task_page_counts(p->task, &pages, NULL, NULL, NULL);
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

/*
 * The proc_list_lock is held by the caller.
*/
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
	os_reason_t jetsam_reason = OS_REASON_NULL;

	/* Pick next idle exit victim. */
	current_time = mach_absolute_time();
	
	jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_MEMORY_IDLE_EXIT);
	if (jetsam_reason == OS_REASON_NULL) {
		printf("kill_idle_exit_proc: failed to allocate jetsam reason\n");
	}

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
		printf("memorystatus_thread: idle exiting pid %d [%s]\n", victim_p->p_pid, (*victim_p->p_name ? victim_p->p_name : "(unknown)"));
		killed = memorystatus_do_kill(victim_p, kMemorystatusKilledIdleExit, jetsam_reason);
		proc_rele(victim_p);
	} else {
		os_reason_free(jetsam_reason);
	}

	return killed;
}
#endif

#if CONFIG_JETSAM
static void
memorystatus_thread_wake(void) {
	thread_wakeup((event_t)&memorystatus_wakeup);
}
#endif /* CONFIG_JETSAM */

extern void vm_pressure_response(void);

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

static void
memorystatus_thread(void *param __unused, wait_result_t wr __unused)
{
	static boolean_t is_vm_privileged = FALSE;

#if CONFIG_JETSAM
	boolean_t post_snapshot = FALSE;
	uint32_t errors = 0;
	uint32_t hwm_kill = 0;
	boolean_t sort_flag = TRUE;
	boolean_t corpse_list_purged = FALSE;

        /* Jetsam Loop Detection - locals */
	memstat_bucket_t *bucket;
	int		jld_bucket_count = 0;
	struct timeval	jld_now_tstamp = {0,0};
	uint64_t 	jld_now_msecs = 0;
	int		elevated_bucket_count = 0;

	/* Jetsam Loop Detection - statics */
	static uint64_t  jld_timestamp_msecs = 0;
	static int	 jld_idle_kill_candidates = 0;	/* Number of available processes in band 0,1 at start */
	static int	 jld_idle_kills = 0;		/* Number of procs killed during eval period  */
	static int	 jld_eval_aggressive_count = 0;		/* Bumps the max priority in aggressive loop */
	static int32_t   jld_priority_band_max = JETSAM_PRIORITY_UI_SUPPORT;
#endif

	if (is_vm_privileged == FALSE) {
		/* 
		 * It's the first time the thread has run, so just mark the thread as privileged and block.
		 * This avoids a spurious pass with unset variables, as set out in <rdar://problem/9609402>.
		 */
		thread_wire(host_priv_self(), current_thread(), TRUE);
		is_vm_privileged = TRUE;
		
		if (vm_restricted_to_single_processor == TRUE)
			thread_vm_bind_group_add();

		memorystatus_thread_block(0, memorystatus_thread);
	}
	
#if CONFIG_JETSAM
	
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_SCAN) | DBG_FUNC_START,
			      memorystatus_available_pages, memorystatus_jld_enabled, memorystatus_jld_eval_period_msecs, memorystatus_jld_eval_aggressive_count,0);

	/*
	 * Jetsam aware version.
	 *
	 * The VM pressure notification thread is working it's way through clients in parallel.
	 *
	 * So, while the pressure notification thread is targeting processes in order of 
	 * increasing jetsam priority, we can hopefully reduce / stop it's work by killing 
	 * any processes that have exceeded their highwater mark.
	 *
	 * If we run out of HWM processes and our available pages drops below the critical threshold, then,
	 * we target the least recently used process in order of increasing jetsam priority (exception: the FG band).
	 */
	while (is_thrashing(kill_under_pressure_cause) ||
	       memorystatus_available_pages <= memorystatus_available_pages_pressure) {
		boolean_t killed;
		int32_t priority;
		uint32_t cause;
		uint64_t jetsam_reason_code = JETSAM_REASON_INVALID;
		os_reason_t jetsam_reason = OS_REASON_NULL;

		cause = kill_under_pressure_cause;
		switch (cause) {
			case kMemorystatusKilledFCThrashing:
				jetsam_reason_code = JETSAM_REASON_MEMORY_FCTHRASHING;
				break;
			case kMemorystatusKilledVMThrashing:
				jetsam_reason_code = JETSAM_REASON_MEMORY_VMTHRASHING;
				break;
			case kMemorystatusKilledVMPageShortage:
				/* falls through */
			default:
				jetsam_reason_code = JETSAM_REASON_MEMORY_VMPAGESHORTAGE;
				cause = kMemorystatusKilledVMPageShortage;
				break;
		}

		/* Highwater */
		killed = memorystatus_kill_hiwat_proc(&errors);
		if (killed) {
			hwm_kill++;
			post_snapshot = TRUE;
			goto done;
		} else {
			memorystatus_hwm_candidates = FALSE;
		}

		/* No highwater processes to kill. Continue or stop for now? */
		if (!is_thrashing(kill_under_pressure_cause) &&
		    (memorystatus_available_pages > memorystatus_available_pages_critical)) {
			/*
			 * We are _not_ out of pressure but we are above the critical threshold and there's:
			 * - no compressor thrashing
			 * - no more HWM processes left.
			 * For now, don't kill any other processes.
			 */
		
			if (hwm_kill == 0) {
 				memorystatus_thread_wasted_wakeup++;
			}

			break;
		}

		jetsam_reason = os_reason_create(OS_REASON_JETSAM, jetsam_reason_code);
		if (jetsam_reason == OS_REASON_NULL) {
			printf("memorystatus_thread: failed to allocate jetsam reason\n");
		}

		if (memorystatus_jld_enabled == TRUE) {

			/*
			 * Jetsam Loop Detection: attempt to detect
			 * rapid daemon relaunches in the lower bands.
			 */
			
			microuptime(&jld_now_tstamp);

			/*
			 * Ignore usecs in this calculation.
			 * msecs granularity is close enough.
			 */
			jld_now_msecs = (jld_now_tstamp.tv_sec * 1000);

			proc_list_lock();
			switch (jetsam_aging_policy) {
			case kJetsamAgingPolicyLegacy:
				bucket = &memstat_bucket[JETSAM_PRIORITY_IDLE];
				jld_bucket_count = bucket->count;
				bucket = &memstat_bucket[JETSAM_PRIORITY_AGING_BAND1];
				jld_bucket_count += bucket->count;
				break;
			case kJetsamAgingPolicySysProcsReclaimedFirst:
			case kJetsamAgingPolicyAppsReclaimedFirst:
				bucket = &memstat_bucket[JETSAM_PRIORITY_IDLE];
				jld_bucket_count = bucket->count;
				bucket = &memstat_bucket[system_procs_aging_band];
				jld_bucket_count += bucket->count;
				bucket = &memstat_bucket[applications_aging_band];
				jld_bucket_count += bucket->count;
				break;
			case kJetsamAgingPolicyNone:
			default:
				bucket = &memstat_bucket[JETSAM_PRIORITY_IDLE];
				jld_bucket_count = bucket->count;
				break;
			}

			bucket = &memstat_bucket[JETSAM_PRIORITY_ELEVATED_INACTIVE];
			elevated_bucket_count = bucket->count;

			proc_list_unlock();

			/*
			 * memorystatus_jld_eval_period_msecs is a tunable
			 * memorystatus_jld_eval_aggressive_count is a tunable
			 * memorystatus_jld_eval_aggressive_priority_band_max is a tunable
			 */
			if ( (jld_bucket_count == 0) || 
			     (jld_now_msecs > (jld_timestamp_msecs + memorystatus_jld_eval_period_msecs))) {

				/* 
				 * Refresh evaluation parameters 
				 */
				jld_timestamp_msecs	 = jld_now_msecs;
				jld_idle_kill_candidates = jld_bucket_count;
				jld_idle_kills		 = 0;
				jld_eval_aggressive_count = 0;
				jld_priority_band_max	= JETSAM_PRIORITY_UI_SUPPORT;
			}

			if (jld_idle_kills > jld_idle_kill_candidates) {
				jld_eval_aggressive_count++;

#if DEVELOPMENT || DEBUG
				printf("memorystatus: aggressive%d: beginning of window: %lld ms, : timestamp now: %lld ms\n",
						jld_eval_aggressive_count,
						jld_timestamp_msecs,
						jld_now_msecs);
				printf("memorystatus: aggressive%d: idle candidates: %d, idle kills: %d\n",
						jld_eval_aggressive_count,
						jld_idle_kill_candidates,
						jld_idle_kills);
#endif /* DEVELOPMENT || DEBUG */

				if ((jld_eval_aggressive_count == memorystatus_jld_eval_aggressive_count) &&
				    (total_corpses_count > 0) && (corpse_list_purged == FALSE)) {
					/*
					 * If we reach this aggressive cycle, corpses might be causing memory pressure.
					 * So, in an effort to avoid jetsams in the FG band, we will attempt to purge
					 * corpse memory prior to this final march through JETSAM_PRIORITY_UI_SUPPORT.
					 */
					task_purge_all_corpses();
					corpse_list_purged = TRUE;
				}
				else if (jld_eval_aggressive_count > memorystatus_jld_eval_aggressive_count) {
					/* 
					 * Bump up the jetsam priority limit (eg: the bucket index)
					 * Enforce bucket index sanity.
					 */
					if ((memorystatus_jld_eval_aggressive_priority_band_max < 0) || 
					    (memorystatus_jld_eval_aggressive_priority_band_max >= MEMSTAT_BUCKET_COUNT)) {
						/*
						 * Do nothing.  Stick with the default level.
						 */
					} else {
						jld_priority_band_max = memorystatus_jld_eval_aggressive_priority_band_max;
					}
				}

				/* Visit elevated processes first */
				while (elevated_bucket_count) {

					elevated_bucket_count--;

					/*
					 * memorystatus_kill_elevated_process() drops a reference,
					 * so take another one so we can continue to use this exit reason
					 * even after it returns.
					 */

					os_reason_ref(jetsam_reason);
					killed = memorystatus_kill_elevated_process(
						kMemorystatusKilledVMThrashing,
						jetsam_reason,
						jld_eval_aggressive_count,
						&errors);

					if (killed) {
						post_snapshot = TRUE;
						if (memorystatus_available_pages <= memorystatus_available_pages_pressure) {
							/*
							 * Still under pressure.
							 * Find another pinned processes.
							 */
							continue;
						} else {
							goto done;
						}
					} else {
						/*
						 * No pinned processes left to kill.
						 * Abandon elevated band.
						 */
						break;
					}
				}

				/*
				 * memorystatus_kill_top_process_aggressive() drops a reference,
				 * so take another one so we can continue to use this exit reason
				 * even after it returns
				 */
				os_reason_ref(jetsam_reason);
				killed = memorystatus_kill_top_process_aggressive(
					TRUE, 
					kMemorystatusKilledVMThrashing,
					jetsam_reason,
					jld_eval_aggressive_count, 
					jld_priority_band_max, 
					&errors);
					
				if (killed) {
					/* Always generate logs after aggressive kill */
					post_snapshot = TRUE;
					jld_idle_kills = 0;
					goto done;
				} 
			} 
		}

		/*
		 * memorystatus_kill_top_process() drops a reference,
		 * so take another one so we can continue to use this exit reason
		 * even after it returns
		 */
		os_reason_ref(jetsam_reason);

		/* LRU */
		killed = memorystatus_kill_top_process(TRUE, sort_flag, cause, jetsam_reason, &priority, &errors);
		sort_flag = FALSE;

		if (killed) {
			/*
			 * Don't generate logs for steady-state idle-exit kills,
			 * unless it is overridden for debug or by the device
			 * tree.
			 */
			if ((priority != JETSAM_PRIORITY_IDLE) || memorystatus_idle_snapshot) {
        			post_snapshot = TRUE;
			}

			/* Jetsam Loop Detection */
			if (memorystatus_jld_enabled == TRUE) {
				if ((priority == JETSAM_PRIORITY_IDLE) || (priority == system_procs_aging_band) || (priority == applications_aging_band)) {
					jld_idle_kills++;
				} else {
					/*
					 * We've reached into bands beyond idle deferred.
					 * We make no attempt to monitor them
					 */
				}
			}

			if ((priority >= JETSAM_PRIORITY_UI_SUPPORT) && (total_corpses_count > 0) && (corpse_list_purged == FALSE)) {
				/*
				 * If we have jetsammed a process in or above JETSAM_PRIORITY_UI_SUPPORT
				 * then we attempt to relieve pressure by purging corpse memory.
				 */
				task_purge_all_corpses();
				corpse_list_purged = TRUE;
			}
			goto done;
		}
		
		if (memorystatus_available_pages <= memorystatus_available_pages_critical) {
			/*
			 * Still under pressure and unable to kill a process - purge corpse memory
			 */
			if (total_corpses_count > 0) {
				task_purge_all_corpses();
				corpse_list_purged = TRUE;
			}

			if (memorystatus_available_pages <= memorystatus_available_pages_critical) {
				/*
				 * Still under pressure and unable to kill a process - panic
				 */
				panic("memorystatus_jetsam_thread: no victim! available pages:%d\n", memorystatus_available_pages);
			}
		}
			
done:		

		/*
		 * We do not want to over-kill when thrashing has been detected.
		 * To avoid that, we reset the flag here and notify the
		 * compressor.
		 */
		if (is_thrashing(kill_under_pressure_cause)) {
			kill_under_pressure_cause = 0;
			vm_thrashing_jetsam_done();
		}

		os_reason_free(jetsam_reason);
	}

	kill_under_pressure_cause = 0;
	
	if (errors) {
		memorystatus_clear_errors();
	}

#if VM_PRESSURE_EVENTS
	/*
	 * LD: We used to target the foreground process first and foremost here.
	 * Now, we target all processes, starting from the non-suspended, background
	 * processes first. We will target foreground too.
	 *
	 * memorystatus_update_vm_pressure(TRUE);
	 */
	//vm_pressure_response();
#endif

	if (post_snapshot) {
		proc_list_lock();
		size_t snapshot_size = sizeof(memorystatus_jetsam_snapshot_t) +
			sizeof(memorystatus_jetsam_snapshot_entry_t) * (memorystatus_jetsam_snapshot_count);
		uint64_t timestamp_now = mach_absolute_time();
		memorystatus_jetsam_snapshot->notification_time = timestamp_now;
		memorystatus_jetsam_snapshot->js_gencount++;
		if (memorystatus_jetsam_snapshot_count > 0 && (memorystatus_jetsam_snapshot_last_timestamp == 0 ||
				timestamp_now > memorystatus_jetsam_snapshot_last_timestamp + memorystatus_jetsam_snapshot_timeout)) {
			proc_list_unlock();
			int ret = memorystatus_send_note(kMemorystatusSnapshotNote, &snapshot_size, sizeof(snapshot_size));
			if (!ret) {
				proc_list_lock();
				memorystatus_jetsam_snapshot_last_timestamp = timestamp_now;
				proc_list_unlock();
			}
		} else {
			proc_list_unlock();
		}
	}

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_SCAN) | DBG_FUNC_END,
		memorystatus_available_pages, 0, 0, 0, 0);

#else /* CONFIG_JETSAM */

	/*
	 * Jetsam not enabled
	 */

#endif /* CONFIG_JETSAM */

	memorystatus_thread_block(0, memorystatus_thread);
}

#if !CONFIG_JETSAM
/*
 * Returns TRUE:
 * 	when an idle-exitable proc was killed
 * Returns FALSE:
 *	when there are no more idle-exitable procs found
 * 	when the attempt to kill an idle-exitable proc failed
 */
boolean_t memorystatus_idle_exit_from_VM(void) {
	return(kill_idle_exit_proc());
}
#endif /* !CONFIG_JETSAM */

/*
 * Returns TRUE:
 *	when exceeding ledger footprint is fatal.
 * Returns FALSE:
 *	when exceeding ledger footprint is non fatal.
 */
boolean_t
memorystatus_turnoff_exception_and_get_fatalness(boolean_t warning, const int max_footprint_mb)
{
	proc_t p = current_proc();
	boolean_t is_fatal;

	proc_list_lock();

	is_fatal = (p->p_memstat_state & P_MEMSTAT_FATAL_MEMLIMIT);

	if (warning == FALSE) {
		boolean_t is_active;
		boolean_t state_changed = FALSE;

		/*
		 * We are here because a process has exceeded its ledger limit.
		 * That is, the process is no longer in the limit warning range.
		 *
		 * When a process exceeds its ledger limit, we want an EXC_RESOURCE
		 * to trigger, but only once per process per limit.  We enforce that
		 * here, by identifying the active/inactive limit type. We then turn
		 * off the exception state by marking the limit as exception triggered.
		 */

		is_active = proc_jetsam_state_is_active_locked(p);

		if (is_active == TRUE) {
			/*
			 * turn off exceptions for active state
			 */
			if (!(p->p_memstat_state & P_MEMSTAT_MEMLIMIT_ACTIVE_EXC_TRIGGERED)) {
				p->p_memstat_state |= P_MEMSTAT_MEMLIMIT_ACTIVE_EXC_TRIGGERED;
				state_changed = TRUE;
			}
		} else {
			/*
			 * turn off exceptions for inactive state
			 */
			if (!(p->p_memstat_state & P_MEMSTAT_MEMLIMIT_INACTIVE_EXC_TRIGGERED)) {
				p->p_memstat_state |= P_MEMSTAT_MEMLIMIT_INACTIVE_EXC_TRIGGERED;
				state_changed = TRUE;
			}
		}

		/*
		 * The limit violation is logged here, but only once per process per limit.
		 * This avoids excessive logging when a process consistently exceeds a soft limit.
		 * Soft memory limit is a non-fatal high-water-mark
		 * Hard memory limit is a fatal custom-task-limit or system-wide per-task memory limit.
		 */
		if(state_changed) {
			printf("process %d (%s) exceeded physical memory footprint, the %s%sMemoryLimit of %d MB\n",
			       p->p_pid, (*p->p_name ? p->p_name : "unknown"), (is_active ? "Active" : "Inactive"),
			       (is_fatal  ? "Hard" : "Soft"), max_footprint_mb);
		}

	}
	proc_list_unlock();

	return is_fatal;
}

/*
 * Callback invoked when allowable physical memory footprint exceeded
 * (dirty pages + IOKit mappings)
 *
 * This is invoked for both advisory, non-fatal per-task high watermarks,
 * as well as the fatal task memory limits.
 */
void
memorystatus_on_ledger_footprint_exceeded(boolean_t warning, boolean_t is_fatal)
{
	os_reason_t jetsam_reason = OS_REASON_NULL;

	proc_t p = current_proc();

#if VM_PRESSURE_EVENTS
	if (warning == TRUE) {
		/*
		 * This is a warning path which implies that the current process is close, but has
		 * not yet exceeded its per-process memory limit.
		 */
		if (memorystatus_warn_process(p->p_pid, FALSE /* not exceeded */) != TRUE) {
			/* Print warning, since it's possible that task has not registered for pressure notifications */
			printf("task_exceeded_footprint: failed to warn the current task (%d exiting, or no handler registered?).\n", p->p_pid);
		}
		return;
	}
#endif /* VM_PRESSURE_EVENTS */

	if (is_fatal) {
		/*
		 * If this process has no high watermark or has a fatal task limit, then we have been invoked because the task
		 * has violated either the system-wide per-task memory limit OR its own task limit.
		 */
		jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_MEMORY_PERPROCESSLIMIT);
		if (jetsam_reason == NULL) {
			printf("task_exceeded footprint: failed to allocate jetsam reason\n");
		} else if (corpse_for_fatal_memkill != 0) {
			/* Set OS_REASON_FLAG_GENERATE_CRASH_REPORT to generate corpse */
			jetsam_reason->osr_flags |= OS_REASON_FLAG_GENERATE_CRASH_REPORT;
		}

		if (memorystatus_kill_process_sync(p->p_pid, kMemorystatusKilledPerProcessLimit, jetsam_reason) != TRUE) {
			printf("task_exceeded_footprint: failed to kill the current task (exiting?).\n");
		}
	} else {
		/*
		 * HWM offender exists. Done without locks or synchronization.
		 * See comment near its declaration for more details.
		 */
		memorystatus_hwm_candidates = TRUE;

#if VM_PRESSURE_EVENTS
		/*
		 * The current process is not in the warning path.
		 * This path implies the current process has exceeded a non-fatal (soft) memory limit.
		 * Failure to send note is ignored here.
		 */
		(void)memorystatus_warn_process(p->p_pid, TRUE /* exceeded */);

#endif /* VM_PRESSURE_EVENTS */
	}
}

/*
 * Description:
 *	Evaluates active vs. inactive process state.
 *	Processes that opt into dirty tracking are evaluated
 *	based on clean vs dirty state.
 *	dirty ==> active
 *	clean ==> inactive
 *
 *	Process that do not opt into dirty tracking are
 *	evalulated based on priority level.
 *	Foreground or above ==> active
 *	Below Foreground    ==> inactive
 *
 *	Return: TRUE if active
 *		False if inactive
 */

static boolean_t
proc_jetsam_state_is_active_locked(proc_t p) {

	if (p->p_memstat_dirty & P_DIRTY_TRACK) {
		/*
		 * process has opted into dirty tracking
		 * active state is based on dirty vs. clean
		 */
		if (p->p_memstat_dirty & P_DIRTY_IS_DIRTY) {
			/*
			 * process is dirty
			 * implies active state
			 */
			return TRUE;
		} else {
			/*
			 * process is clean
			 * implies inactive state
			 */
			return FALSE;
		}
	} else if (p->p_memstat_effectivepriority >= JETSAM_PRIORITY_FOREGROUND) {
		/*
		 * process is Foreground or higher
		 * implies active state
		 */
		return TRUE;
	} else {
		/*
		 * process found below Foreground
		 * implies inactive state
		 */
		return FALSE;
	}
}

static boolean_t 
memorystatus_kill_process_sync(pid_t victim_pid, uint32_t cause, os_reason_t jetsam_reason) {
	boolean_t res;

#if CONFIG_JETSAM
	uint32_t errors = 0;

	if (victim_pid == -1) {
		/* No pid, so kill first process */
		res = memorystatus_kill_top_process(TRUE, TRUE, cause, jetsam_reason, NULL, &errors);
	} else {
		res = memorystatus_kill_specific_process(victim_pid, cause, jetsam_reason);
	}
	
	if (errors) {
		memorystatus_clear_errors();
	}

	if (res == TRUE) {
		/* Fire off snapshot notification */
		proc_list_lock();
		size_t snapshot_size = sizeof(memorystatus_jetsam_snapshot_t) + 
			sizeof(memorystatus_jetsam_snapshot_entry_t) * memorystatus_jetsam_snapshot_count;
		uint64_t timestamp_now = mach_absolute_time();
		memorystatus_jetsam_snapshot->notification_time = timestamp_now;
		if (memorystatus_jetsam_snapshot_count > 0 && (memorystatus_jetsam_snapshot_last_timestamp == 0 ||
				timestamp_now > memorystatus_jetsam_snapshot_last_timestamp + memorystatus_jetsam_snapshot_timeout)) {
			proc_list_unlock();
			int ret = memorystatus_send_note(kMemorystatusSnapshotNote, &snapshot_size, sizeof(snapshot_size));
			if (!ret) {
				proc_list_lock();
				memorystatus_jetsam_snapshot_last_timestamp = timestamp_now;
				proc_list_unlock();
			}
		} else {
			proc_list_unlock();
		}
	}
#else /* !CONFIG_JETSAM */

	res = memorystatus_kill_specific_process(victim_pid, cause, jetsam_reason);

#endif /* CONFIG_JETSAM */
    
	return res;
}

/*
 * Jetsam a specific process.
 */
static boolean_t 
memorystatus_kill_specific_process(pid_t victim_pid, uint32_t cause, os_reason_t jetsam_reason) {
	boolean_t killed;
	proc_t p;
	uint64_t killtime = 0;
        clock_sec_t     tv_sec;
        clock_usec_t    tv_usec;
        uint32_t        tv_msec;

	/* TODO - add a victim queue and push this into the main jetsam thread */

	p = proc_find(victim_pid);
	if (!p) {
		os_reason_free(jetsam_reason);
		return FALSE;
	}

	proc_list_lock();

#if CONFIG_JETSAM
	if (memorystatus_jetsam_snapshot_count == 0) {
		memorystatus_init_jetsam_snapshot_locked(NULL,0);
	}

	killtime = mach_absolute_time();
        absolutetime_to_microtime(killtime, &tv_sec, &tv_usec);
        tv_msec = tv_usec / 1000;

	memorystatus_update_jetsam_snapshot_entry_locked(p, cause, killtime);

	proc_list_unlock();

	printf("%lu.%02d memorystatus: specifically killing pid %d [%s] (%s %d) - memorystatus_available_pages: %d\n",
	       (unsigned long)tv_sec, tv_msec, victim_pid, (*p->p_name ? p->p_name : "(unknown)"),
	       jetsam_kill_cause_name[cause], p->p_memstat_effectivepriority, memorystatus_available_pages);
#else /* !CONFIG_JETSAM */
	proc_list_unlock();

	killtime = mach_absolute_time();
        absolutetime_to_microtime(killtime, &tv_sec, &tv_usec);
        tv_msec = tv_usec / 1000;
	printf("%lu.%02d memorystatus: specifically killing pid %d [%s] (%s %d)\n",
	       (unsigned long)tv_sec, tv_msec, victim_pid, (*p->p_name ? p->p_name : "(unknown)"),
	       jetsam_kill_cause_name[cause], p->p_memstat_effectivepriority);
#endif /* CONFIG_JETSAM */
	
	killed = memorystatus_do_kill(p, cause, jetsam_reason);
	proc_rele(p);
	
	return killed;
}


/*
 * Toggle the P_MEMSTAT_TERMINATED state.
 * Takes the proc_list_lock.
 */
void
proc_memstat_terminated(proc_t p, boolean_t set)
{
#if DEVELOPMENT || DEBUG
	if (p) {
		proc_list_lock();
		if (set == TRUE) {
			p->p_memstat_state |= P_MEMSTAT_TERMINATED;
		} else {
			p->p_memstat_state &= ~P_MEMSTAT_TERMINATED;
		}
		proc_list_unlock();
	}
#else
#pragma unused(p, set)
	/*
	 * do nothing
	 */
#endif /* DEVELOPMENT || DEBUG */
	return;
}


#if CONFIG_JETSAM
/*
 * This is invoked when cpulimits have been exceeded while in fatal mode.
 * The jetsam_flags do not apply as those are for memory related kills.
 * We call this routine so that the offending process is killed with 
 * a non-zero exit status.
 */
void
jetsam_on_ledger_cpulimit_exceeded(void)
{
	int retval = 0;
	int jetsam_flags = 0;  /* make it obvious */
	proc_t p = current_proc();
	os_reason_t jetsam_reason = OS_REASON_NULL;

	printf("task_exceeded_cpulimit: killing pid %d [%s]\n",
	       p->p_pid, (*p->p_name ? p->p_name : "(unknown)"));

	jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_CPULIMIT);
	if (jetsam_reason == OS_REASON_NULL) {
		printf("task_exceeded_cpulimit: unable to allocate memory for jetsam reason\n");
	}

	retval = jetsam_do_kill(p, jetsam_flags, jetsam_reason);
	
	if (retval) {
		printf("task_exceeded_cpulimit: failed to kill current task (exiting?).\n");
	}
}

static void
memorystatus_get_task_memory_region_count(task_t task, uint64_t *count)
{
	assert(task);
	assert(count);

	*count = get_task_memory_region_count(task);
}

static void
memorystatus_get_task_page_counts(task_t task, uint32_t *footprint, uint32_t *max_footprint, uint32_t *max_footprint_lifetime, uint32_t *purgeable_pages)
{
	assert(task);
	assert(footprint);

	uint64_t pages;

	pages = (get_task_phys_footprint(task) / PAGE_SIZE_64);
	assert(((uint32_t)pages) == pages);
	*footprint = (uint32_t)pages;

	if (max_footprint) {
		pages = (get_task_phys_footprint_max(task) / PAGE_SIZE_64);
		assert(((uint32_t)pages) == pages);
		*max_footprint = (uint32_t)pages;
	}
	if (max_footprint_lifetime) {
		pages = (get_task_resident_max(task) / PAGE_SIZE_64);
		assert(((uint32_t)pages) == pages);
		*max_footprint_lifetime = (uint32_t)pages;
	}
	if (purgeable_pages) {
		pages = (get_task_purgeable_size(task) / PAGE_SIZE_64);
		assert(((uint32_t)pages) == pages);
		*purgeable_pages = (uint32_t)pages;
	}
}

static void
memorystatus_get_task_phys_footprint_page_counts(task_t task,
						 uint64_t *internal_pages, uint64_t *internal_compressed_pages,
						 uint64_t *purgeable_nonvolatile_pages, uint64_t *purgeable_nonvolatile_compressed_pages,
						 uint64_t *alternate_accounting_pages, uint64_t *alternate_accounting_compressed_pages,
						 uint64_t *iokit_mapped_pages, uint64_t *page_table_pages)
{
	assert(task);

	if (internal_pages) {
		*internal_pages = (get_task_internal(task) / PAGE_SIZE_64);
	}

	if (internal_compressed_pages) {
		*internal_compressed_pages = (get_task_internal_compressed(task) / PAGE_SIZE_64);
	}

	if (purgeable_nonvolatile_pages) {
		*purgeable_nonvolatile_pages = (get_task_purgeable_nonvolatile(task) / PAGE_SIZE_64);
	}

	if (purgeable_nonvolatile_compressed_pages) {
		*purgeable_nonvolatile_compressed_pages = (get_task_purgeable_nonvolatile_compressed(task) / PAGE_SIZE_64);
	}

	if (alternate_accounting_pages) {
		*alternate_accounting_pages = (get_task_alternate_accounting(task) / PAGE_SIZE_64);
	}

	if (alternate_accounting_compressed_pages) {
		*alternate_accounting_compressed_pages = (get_task_alternate_accounting_compressed(task) / PAGE_SIZE_64);
	}

	if (iokit_mapped_pages) {
		*iokit_mapped_pages = (get_task_iokit_mapped(task) / PAGE_SIZE_64);
	}

	if (page_table_pages) {
		*page_table_pages = (get_task_page_table(task) / PAGE_SIZE_64);
	}
}

/*
 * This routine only acts on the global jetsam event snapshot.
 * Updating the process's entry can race when the memorystatus_thread
 * has chosen to kill a process that is racing to exit on another core.
 */
static void
memorystatus_update_jetsam_snapshot_entry_locked(proc_t p, uint32_t kill_cause, uint64_t killtime)
{
	memorystatus_jetsam_snapshot_entry_t *entry = NULL;
	memorystatus_jetsam_snapshot_t *snapshot    = NULL;
	memorystatus_jetsam_snapshot_entry_t *snapshot_list = NULL;

	unsigned int i;

	if (memorystatus_jetsam_snapshot_count == 0) {
		/*
		 * No active snapshot.
		 * Nothing to do.
		 */
		return;
	}

	/*
	 * Sanity check as this routine should only be called
	 * from a jetsam kill path.
	 */
	assert(kill_cause != 0 && killtime != 0);

	snapshot       = memorystatus_jetsam_snapshot;
	snapshot_list  = memorystatus_jetsam_snapshot->entries;

	for (i = 0; i < memorystatus_jetsam_snapshot_count; i++) {
		if (snapshot_list[i].pid == p->p_pid) {

			entry = &snapshot_list[i];

			if (entry->killed || entry->jse_killtime) {
				/*
				 * We apparently raced on the exit path
				 * for this process, as it's snapshot entry
				 * has already recorded a kill.
				 */
				assert(entry->killed && entry->jse_killtime);
				break;
			}

			/*
			 * Update the entry we just found in the snapshot.
			 */

			entry->killed       = kill_cause;
			entry->jse_killtime = killtime;
			entry->jse_gencount = snapshot->js_gencount;
			entry->jse_idle_delta = p->p_memstat_idle_delta;

			/*
			 * If a process has moved between bands since snapshot was
			 * initialized, then likely these fields changed too.
			 */
			 if (entry->priority != p->p_memstat_effectivepriority) {

				strlcpy(entry->name, p->p_name, sizeof(entry->name));
				entry->priority  = p->p_memstat_effectivepriority;
				entry->state     = memorystatus_build_state(p);
				entry->user_data = p->p_memstat_userdata;
				entry->fds       = p->p_fd->fd_nfiles;
			 }

			 /*
			  * Always update the page counts on a kill.
			  */

			 uint32_t pages              = 0;
			 uint32_t max_pages          = 0;
			 uint32_t max_pages_lifetime = 0;
			 uint32_t purgeable_pages    = 0;

			 memorystatus_get_task_page_counts(p->task, &pages, &max_pages, &max_pages_lifetime, &purgeable_pages);
			 entry->pages              = (uint64_t)pages;
			 entry->max_pages          = (uint64_t)max_pages;
			 entry->max_pages_lifetime = (uint64_t)max_pages_lifetime;
			 entry->purgeable_pages    = (uint64_t)purgeable_pages;

			 uint64_t internal_pages			= 0;
			 uint64_t internal_compressed_pages		= 0;
			 uint64_t purgeable_nonvolatile_pages		= 0;
			 uint64_t purgeable_nonvolatile_compressed_pages = 0;
			 uint64_t alternate_accounting_pages		= 0;
			 uint64_t alternate_accounting_compressed_pages = 0;
			 uint64_t iokit_mapped_pages			= 0;
			 uint64_t page_table_pages			= 0;

			 memorystatus_get_task_phys_footprint_page_counts(p->task, &internal_pages, &internal_compressed_pages,
									  &purgeable_nonvolatile_pages, &purgeable_nonvolatile_compressed_pages,
									  &alternate_accounting_pages, &alternate_accounting_compressed_pages,
									  &iokit_mapped_pages, &page_table_pages);

			 entry->jse_internal_pages = internal_pages;
			 entry->jse_internal_compressed_pages = internal_compressed_pages;
			 entry->jse_purgeable_nonvolatile_pages = purgeable_nonvolatile_pages;
			 entry->jse_purgeable_nonvolatile_compressed_pages = purgeable_nonvolatile_compressed_pages;
			 entry->jse_alternate_accounting_pages = alternate_accounting_pages;
			 entry->jse_alternate_accounting_compressed_pages = alternate_accounting_compressed_pages;
			 entry->jse_iokit_mapped_pages = iokit_mapped_pages;
			 entry->jse_page_table_pages = page_table_pages;

			 uint64_t region_count = 0;
			 memorystatus_get_task_memory_region_count(p->task, &region_count);
			 entry->jse_memory_region_count = region_count;

			 goto exit;
		}
	}

	if (entry == NULL) {
		/*
		 * The entry was not found in the snapshot, so the process must have
		 * launched after the snapshot was initialized.
		 * Let's try to append the new entry.
		 */
		if (memorystatus_jetsam_snapshot_count < memorystatus_jetsam_snapshot_max) {
			/*
			 * A populated snapshot buffer exists
			 * and there is room to init a new entry.
			 */
			assert(memorystatus_jetsam_snapshot_count == snapshot->entry_count);

			unsigned int next = memorystatus_jetsam_snapshot_count;

			if(memorystatus_init_jetsam_snapshot_entry_locked(p, &snapshot_list[next], (snapshot->js_gencount)) == TRUE) {

				entry = &snapshot_list[next];
				entry->killed       = kill_cause;
				entry->jse_killtime = killtime;

				snapshot->entry_count = ++next;
				memorystatus_jetsam_snapshot_count = next;

				if (memorystatus_jetsam_snapshot_count >= memorystatus_jetsam_snapshot_max) {
					/*
					 * We just used the last slot in the snapshot buffer.
					 * We only want to log it once... so we do it here
					 * when we notice we've hit the max.
					 */
					printf("memorystatus: WARNING snapshot buffer is full, count %d\n",
					       memorystatus_jetsam_snapshot_count);
				}
			}
		}
	}

exit:
	if (entry == NULL) {
		/*
		 * If we reach here, the snapshot buffer could not be updated.
		 * Most likely, the buffer is full, in which case we would have
		 * logged a warning in the previous call.
		 *
		 * For now, we will stop appending snapshot entries.
		 * When the buffer is consumed, the snapshot state will reset.
		 */

		MEMORYSTATUS_DEBUG(4, "memorystatus_update_jetsam_snapshot_entry_locked: failed to update pid %d, priority %d, count %d\n",
				   p->p_pid, p->p_memstat_effectivepriority,  memorystatus_jetsam_snapshot_count);
	}

	return;
}

void memorystatus_pages_update(unsigned int pages_avail)
{
	memorystatus_available_pages = pages_avail;

#if VM_PRESSURE_EVENTS
	/*
	 * Since memorystatus_available_pages changes, we should
	 * re-evaluate the pressure levels on the system and 
	 * check if we need to wake the pressure thread.
	 * We also update memorystatus_level in that routine.
	 */ 
	vm_pressure_response();

	if (memorystatus_available_pages <= memorystatus_available_pages_pressure) {

		if (memorystatus_hwm_candidates || (memorystatus_available_pages <= memorystatus_available_pages_critical)) {
			memorystatus_thread_wake();
		}
	}
#else /* VM_PRESSURE_EVENTS */

	boolean_t critical, delta;
        
	if (!memorystatus_delta) {
	    return;
	}
	
	critical = (pages_avail < memorystatus_available_pages_critical) ? TRUE : FALSE;
	delta = ((pages_avail >= (memorystatus_available_pages + memorystatus_delta)) 
                || (memorystatus_available_pages >= (pages_avail + memorystatus_delta))) ? TRUE : FALSE;
        
	if (critical || delta) {
		unsigned int total_pages;

		total_pages = (unsigned int) atop_64(max_mem);
#if CONFIG_SECLUDED_MEMORY
		total_pages -= vm_page_secluded_count;
#endif /* CONFIG_SECLUDED_MEMORY */
		memorystatus_level = memorystatus_available_pages * 100 / total_pages;
		memorystatus_thread_wake();
	}
#endif /* VM_PRESSURE_EVENTS */
}

static boolean_t
memorystatus_init_jetsam_snapshot_entry_locked(proc_t p, memorystatus_jetsam_snapshot_entry_t *entry, uint64_t gencount)
{	
	clock_sec_t                     tv_sec;
	clock_usec_t                    tv_usec;
	uint32_t pages = 0;
	uint32_t max_pages = 0;
	uint32_t max_pages_lifetime = 0;
	uint32_t purgeable_pages = 0;
	uint64_t internal_pages				= 0;
	uint64_t internal_compressed_pages		= 0;
	uint64_t purgeable_nonvolatile_pages		= 0;
	uint64_t purgeable_nonvolatile_compressed_pages	= 0;
	uint64_t alternate_accounting_pages		= 0;
	uint64_t alternate_accounting_compressed_pages	= 0;
	uint64_t iokit_mapped_pages			= 0;
	uint64_t page_table_pages			=0;
	uint64_t region_count				= 0;
	uint64_t cids[COALITION_NUM_TYPES];

	memset(entry, 0, sizeof(memorystatus_jetsam_snapshot_entry_t));

	entry->pid = p->p_pid;
	strlcpy(&entry->name[0], p->p_name, sizeof(entry->name));
	entry->priority = p->p_memstat_effectivepriority;

	memorystatus_get_task_page_counts(p->task, &pages, &max_pages, &max_pages_lifetime, &purgeable_pages);
	entry->pages              = (uint64_t)pages;
	entry->max_pages          = (uint64_t)max_pages;
	entry->max_pages_lifetime = (uint64_t)max_pages_lifetime;
	entry->purgeable_pages    = (uint64_t)purgeable_pages;

	memorystatus_get_task_phys_footprint_page_counts(p->task, &internal_pages, &internal_compressed_pages,
							 &purgeable_nonvolatile_pages, &purgeable_nonvolatile_compressed_pages,
							 &alternate_accounting_pages, &alternate_accounting_compressed_pages,
							 &iokit_mapped_pages, &page_table_pages);

	entry->jse_internal_pages = internal_pages;
	entry->jse_internal_compressed_pages = internal_compressed_pages;
	entry->jse_purgeable_nonvolatile_pages = purgeable_nonvolatile_pages;
	entry->jse_purgeable_nonvolatile_compressed_pages = purgeable_nonvolatile_compressed_pages;
	entry->jse_alternate_accounting_pages = alternate_accounting_pages;
	entry->jse_alternate_accounting_compressed_pages = alternate_accounting_compressed_pages;
	entry->jse_iokit_mapped_pages = iokit_mapped_pages;
	entry->jse_page_table_pages = page_table_pages;

	memorystatus_get_task_memory_region_count(p->task, &region_count);
	entry->jse_memory_region_count = region_count;

	entry->state     = memorystatus_build_state(p);
	entry->user_data = p->p_memstat_userdata;
	memcpy(&entry->uuid[0], &p->p_uuid[0], sizeof(p->p_uuid));
	entry->fds       = p->p_fd->fd_nfiles;

	absolutetime_to_microtime(get_task_cpu_time(p->task), &tv_sec, &tv_usec);
	entry->cpu_time.tv_sec = tv_sec;
	entry->cpu_time.tv_usec = tv_usec;

	assert(p->p_stats != NULL);
	entry->jse_starttime =  p->p_stats->ps_start;	/* abstime process started */
	entry->jse_killtime = 0;			/* abstime jetsam chose to kill process */
	entry->killed       = 0;			/* the jetsam kill cause */
	entry->jse_gencount = gencount;			/* indicates a pass through jetsam thread, when process was targeted to be killed */

	entry->jse_idle_delta = p->p_memstat_idle_delta; /* Most recent timespan spent in idle-band */

	proc_coalitionids(p, cids);
	entry->jse_coalition_jetsam_id = cids[COALITION_TYPE_JETSAM];

	return TRUE;	
}

static void
memorystatus_init_snapshot_vmstats(memorystatus_jetsam_snapshot_t *snapshot)
{
	kern_return_t kr = KERN_SUCCESS;
	mach_msg_type_number_t	count = HOST_VM_INFO64_COUNT;
	vm_statistics64_data_t	vm_stat;

	if ((kr = host_statistics64(host_self(), HOST_VM_INFO64, (host_info64_t)&vm_stat, &count) != KERN_SUCCESS)) {
		printf("memorystatus_init_jetsam_snapshot_stats: host_statistics64 failed with %d\n", kr);
		memset(&snapshot->stats, 0, sizeof(snapshot->stats));
	} else {
		snapshot->stats.free_pages	= vm_stat.free_count;
		snapshot->stats.active_pages	= vm_stat.active_count;
		snapshot->stats.inactive_pages	= vm_stat.inactive_count;
		snapshot->stats.throttled_pages	= vm_stat.throttled_count;
		snapshot->stats.purgeable_pages	= vm_stat.purgeable_count;
		snapshot->stats.wired_pages	= vm_stat.wire_count;

		snapshot->stats.speculative_pages = vm_stat.speculative_count;
		snapshot->stats.filebacked_pages  = vm_stat.external_page_count;
		snapshot->stats.anonymous_pages   = vm_stat.internal_page_count;
		snapshot->stats.compressions      = vm_stat.compressions;
		snapshot->stats.decompressions    = vm_stat.decompressions;
		snapshot->stats.compressor_pages  = vm_stat.compressor_page_count;
		snapshot->stats.total_uncompressed_pages_in_compressor = vm_stat.total_uncompressed_pages_in_compressor;
	}
}

/*
 * Collect vm statistics at boot.
 * Called only once (see kern_exec.c)
 * Data can be consumed at any time.
 */
void
memorystatus_init_at_boot_snapshot() {
	memorystatus_init_snapshot_vmstats(&memorystatus_at_boot_snapshot);
	memorystatus_at_boot_snapshot.entry_count = 0;
	memorystatus_at_boot_snapshot.notification_time = 0;   /* updated when consumed */
	memorystatus_at_boot_snapshot.snapshot_time = mach_absolute_time();
}

static void
memorystatus_init_jetsam_snapshot_locked(memorystatus_jetsam_snapshot_t *od_snapshot, uint32_t ods_list_count )
{
	proc_t p, next_p;
	unsigned int b = 0, i = 0;

	memorystatus_jetsam_snapshot_t *snapshot = NULL;
	memorystatus_jetsam_snapshot_entry_t *snapshot_list = NULL;
	unsigned int snapshot_max = 0;

	if (od_snapshot) {
		/*
		 * This is an on_demand snapshot
		 */
		snapshot      = od_snapshot;
		snapshot_list = od_snapshot->entries;
		snapshot_max  = ods_list_count;
	} else {
		/*
		 * This is a jetsam event snapshot
		 */
		snapshot      = memorystatus_jetsam_snapshot;
		snapshot_list = memorystatus_jetsam_snapshot->entries;
		snapshot_max  = memorystatus_jetsam_snapshot_max;
	}

	/*
	 * Init the snapshot header information
	 */
	memorystatus_init_snapshot_vmstats(snapshot);
	snapshot->snapshot_time = mach_absolute_time();
	snapshot->notification_time = 0;
	snapshot->js_gencount = 0;

	next_p = memorystatus_get_first_proc_locked(&b, TRUE);
	while (next_p) {
		p = next_p;
		next_p = memorystatus_get_next_proc_locked(&b, p, TRUE);
	        
		if (FALSE == memorystatus_init_jetsam_snapshot_entry_locked(p, &snapshot_list[i], snapshot->js_gencount)) {
			continue;
		}
		
		MEMORYSTATUS_DEBUG(0, "jetsam snapshot pid %d, uuid = %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			p->p_pid, 
			p->p_uuid[0], p->p_uuid[1], p->p_uuid[2], p->p_uuid[3], p->p_uuid[4], p->p_uuid[5], p->p_uuid[6], p->p_uuid[7],
			p->p_uuid[8], p->p_uuid[9], p->p_uuid[10], p->p_uuid[11], p->p_uuid[12], p->p_uuid[13], p->p_uuid[14], p->p_uuid[15]);

		if (++i == snapshot_max) {
			break;
		} 	
	}

	snapshot->entry_count = i;

	if (!od_snapshot) {
		/* update the system buffer count */
		memorystatus_jetsam_snapshot_count = i;
	}
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

/*
 * Triggers a sort_order on a specified jetsam priority band.
 * This is for testing only, used to force a path through the sort
 * function.
 */
static int
memorystatus_cmd_test_jetsam_sort(int priority, int sort_order) {

	int error = 0;

	unsigned int bucket_index = 0;

	if (priority == -1) {
		/* Use as shorthand for default priority */
		bucket_index = JETSAM_PRIORITY_DEFAULT;
	} else {
		bucket_index = (unsigned int)priority;
	}

	error = memorystatus_sort_bucket(bucket_index, sort_order);

	return (error);
}

#endif /* DEVELOPMENT || DEBUG */

/*
 * Jetsam the first process in the queue.
 */
static boolean_t
memorystatus_kill_top_process(boolean_t any, boolean_t sort_flag, uint32_t cause, os_reason_t jetsam_reason,
			      int32_t *priority, uint32_t *errors)
{
	pid_t aPid;
	proc_t p = PROC_NULL, next_p = PROC_NULL;
	boolean_t new_snapshot = FALSE, killed = FALSE;
	int kill_count = 0;
	unsigned int i = 0;
	uint32_t aPid_ep;
	uint64_t killtime = 0;
        clock_sec_t     tv_sec;
        clock_usec_t    tv_usec;
        uint32_t        tv_msec;

#ifndef CONFIG_FREEZE
#pragma unused(any)
#endif
	
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_JETSAM) | DBG_FUNC_START,
		memorystatus_available_pages, 0, 0, 0, 0);


	if (sort_flag == TRUE) {
		(void)memorystatus_sort_bucket(JETSAM_PRIORITY_FOREGROUND, JETSAM_SORT_DEFAULT);
	}

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
		aPid_ep = p->p_memstat_effectivepriority;

		if (p->p_memstat_state & (P_MEMSTAT_ERROR | P_MEMSTAT_TERMINATED)) {
			continue;   /* with lock held */
		}
		    
#if DEVELOPMENT || DEBUG
		if ((memorystatus_jetsam_policy & kPolicyDiagnoseActive) && procSuspendedForDiagnosis) {
			printf("jetsam: continuing after ignoring proc suspended already for diagnosis - %d\n", aPid);
			continue;
		}
#endif /* DEVELOPMENT || DEBUG */

		if (cause == kMemorystatusKilledVnodes)
		{
			/*
			 * If the system runs out of vnodes, we systematically jetsam
			 * processes in hopes of stumbling onto a vnode gain that helps
			 * the system recover.  The process that happens to trigger
			 * this path has no known relationship to the vnode consumption.
			 * We attempt to safeguard that process e.g: do not jetsam it.
			 */

			if (p == current_proc()) {
				/* do not jetsam the current process */
				continue;
			}
		}

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
		        /*
		         * Capture a snapshot if none exists and:
		         * - priority was not requested (this is something other than an ambient kill)
		         * - the priority was requested *and* the targeted process is not at idle priority
		         */
                	if ((memorystatus_jetsam_snapshot_count == 0) && 
			    (memorystatus_idle_snapshot || ((!priority) || (priority && (aPid_ep != JETSAM_PRIORITY_IDLE))))) {
				memorystatus_init_jetsam_snapshot_locked(NULL,0);
                		new_snapshot = TRUE;
                	}
		        
			/* 
			 * Mark as terminated so that if exit1() indicates success, but the process (for example)
			 * is blocked in task_exception_notify(), it'll be skipped if encountered again - see 
			 * <rdar://problem/13553476>. This is cheaper than examining P_LEXIT, which requires the 
			 * acquisition of the proc lock.
			 */
			p->p_memstat_state |= P_MEMSTAT_TERMINATED;

			killtime = mach_absolute_time();
			absolutetime_to_microtime(killtime, &tv_sec, &tv_usec);
			tv_msec = tv_usec / 1000;
		        
#if DEVELOPMENT || DEBUG
			if ((memorystatus_jetsam_policy & kPolicyDiagnoseActive) && activeProcess) {
				MEMORYSTATUS_DEBUG(1, "jetsam: suspending pid %d [%s] (active) for diagnosis - memory_status_level: %d\n",
					aPid, (*p->p_name ? p->p_name: "(unknown)"), memorystatus_level);
				memorystatus_update_jetsam_snapshot_entry_locked(p, kMemorystatusKilledDiagnostic, killtime);
				p->p_memstat_state |= P_MEMSTAT_DIAG_SUSPENDED;
				if (memorystatus_jetsam_policy & kPolicyDiagnoseFirst) {
					jetsam_diagnostic_suspended_one_active_proc = 1;
					printf("jetsam: returning after suspending first active proc - %d\n", aPid);
				}
				
				p = proc_ref_locked(p);
				proc_list_unlock();
				if (p) {
					task_suspend(p->task);
					if (priority) {
						*priority = aPid_ep;
					}
					proc_rele(p);
					killed = TRUE;
				}
				
				goto exit;
			} else
#endif /* DEVELOPMENT || DEBUG */
			{
				/* Shift queue, update stats */
				memorystatus_update_jetsam_snapshot_entry_locked(p, cause, killtime);

				if (proc_ref_locked(p) == p) {
					proc_list_unlock();
					printf("%lu.%02d memorystatus: %s %d [%s] (%s %d) - memorystatus_available_pages: %d\n",
					       (unsigned long)tv_sec, tv_msec,
					       ((aPid_ep == JETSAM_PRIORITY_IDLE) ? "idle exiting pid" : "jetsam killing top process pid"),
					       aPid, (*p->p_name ? p->p_name : "(unknown)"),
					       jetsam_kill_cause_name[cause], aPid_ep, memorystatus_available_pages);

					/*
					 * memorystatus_do_kill() drops a reference, so take another one so we can
					 * continue to use this exit reason even after memorystatus_do_kill()
					 * returns.
					 */
					os_reason_ref(jetsam_reason);

					killed = memorystatus_do_kill(p, cause, jetsam_reason);

					/* Success? */
					if (killed) {
						if (priority) {
							*priority = aPid_ep;
						}
						proc_rele(p);
						kill_count++;
						goto exit;
					}
				
					/*
					 * Failure - first unwind the state,
					 * then fall through to restart the search.
					 */
					proc_list_lock();
					proc_rele_locked(p);
					p->p_memstat_state &= ~P_MEMSTAT_TERMINATED;
					p->p_memstat_state |= P_MEMSTAT_ERROR;
					*errors += 1;
				}
				
				/*
				 * Failure - restart the search.
				 *
				 * We might have raced with "p" exiting on another core, resulting in no
				 * ref on "p".  Or, we may have failed to kill "p".
				 *
				 * Either way, we fall thru to here, leaving the proc in the
				 * P_MEMSTAT_TERMINATED state.
				 *
				 * And, we hold the the proc_list_lock at this point.
				 */

				i = 0;
				next_p = memorystatus_get_first_proc_locked(&i, TRUE);
			}
		}
	}
	
	proc_list_unlock();
	
exit:
	os_reason_free(jetsam_reason);

	/* Clear snapshot if freshly captured and no target was found */
	if (new_snapshot && !killed) {
		proc_list_lock();
		memorystatus_jetsam_snapshot->entry_count = memorystatus_jetsam_snapshot_count = 0;
		proc_list_unlock();
	}
	
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_JETSAM) | DBG_FUNC_END,
			      memorystatus_available_pages, killed ? aPid : 0, kill_count, 0, 0);

	return killed;
}

/*
 * Jetsam aggressively 
 */
static boolean_t
memorystatus_kill_top_process_aggressive(boolean_t any, uint32_t cause, os_reason_t jetsam_reason, int aggr_count,
					 int32_t priority_max, uint32_t *errors)
{
	pid_t aPid;
	proc_t p = PROC_NULL, next_p = PROC_NULL;
	boolean_t new_snapshot = FALSE, killed = FALSE;
	int kill_count = 0;
	unsigned int i = 0;
	int32_t aPid_ep = 0;
	unsigned int memorystatus_level_snapshot = 0;
	uint64_t killtime = 0;
        clock_sec_t     tv_sec;
        clock_usec_t    tv_usec;
        uint32_t        tv_msec;

#pragma unused(any)

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_JETSAM) | DBG_FUNC_START,
		memorystatus_available_pages, priority_max, 0, 0, 0);

	memorystatus_sort_bucket(JETSAM_PRIORITY_FOREGROUND, JETSAM_SORT_DEFAULT);

	proc_list_lock();

	next_p = memorystatus_get_first_proc_locked(&i, TRUE);
	while (next_p) {
#if DEVELOPMENT || DEBUG
		int activeProcess;
		int procSuspendedForDiagnosis;
#endif /* DEVELOPMENT || DEBUG */

		if ((unsigned int)(next_p->p_memstat_effectivepriority) != i) {

			/*
			 * We have raced with next_p running on another core, as it has
			 * moved to a different jetsam priority band.  This means we have
			 * lost our place in line while traversing the jetsam list.  We
			 * attempt to recover by rewinding to the beginning of the band
			 * we were already traversing.  By doing this, we do not guarantee
			 * that no process escapes this aggressive march, but we can make
			 * skipping an entire range of processes less likely. (PR-21069019)
			 */

			MEMORYSTATUS_DEBUG(1, "memorystatus: aggressive%d: rewinding %s moved from band %d --> %d\n",
					   aggr_count, (*next_p->p_name ? next_p->p_name : "unknown"), i, next_p->p_memstat_effectivepriority);

			next_p = memorystatus_get_first_proc_locked(&i, TRUE);
			continue;
		}

		p = next_p;
		next_p = memorystatus_get_next_proc_locked(&i, p, TRUE);

		if (p->p_memstat_effectivepriority > priority_max) {
			/* 
			 * Bail out of this killing spree if we have
			 * reached beyond the priority_max jetsam band.
 			 * That is, we kill up to and through the 
			 * priority_max jetsam band.
			 */
			proc_list_unlock();
			goto exit;
		}
		
#if DEVELOPMENT || DEBUG
		activeProcess = p->p_memstat_state & P_MEMSTAT_FOREGROUND;
		procSuspendedForDiagnosis = p->p_memstat_state & P_MEMSTAT_DIAG_SUSPENDED;
#endif /* DEVELOPMENT || DEBUG */
		
		aPid = p->p_pid;
		aPid_ep = p->p_memstat_effectivepriority;

		if (p->p_memstat_state & (P_MEMSTAT_ERROR | P_MEMSTAT_TERMINATED)) {
			continue;
		}
		    
#if DEVELOPMENT || DEBUG
		if ((memorystatus_jetsam_policy & kPolicyDiagnoseActive) && procSuspendedForDiagnosis) {
			printf("jetsam: continuing after ignoring proc suspended already for diagnosis - %d\n", aPid);
			continue;
		}
#endif /* DEVELOPMENT || DEBUG */

		/*
		 * Capture a snapshot if none exists.
		 */
		if (memorystatus_jetsam_snapshot_count == 0) {
			memorystatus_init_jetsam_snapshot_locked(NULL,0);
			new_snapshot = TRUE;
		}
		        
		/* 
		 * Mark as terminated so that if exit1() indicates success, but the process (for example)
		 * is blocked in task_exception_notify(), it'll be skipped if encountered again - see 
		 * <rdar://problem/13553476>. This is cheaper than examining P_LEXIT, which requires the 
		 * acquisition of the proc lock.
		 */
		p->p_memstat_state |= P_MEMSTAT_TERMINATED;

		killtime = mach_absolute_time();
		absolutetime_to_microtime(killtime, &tv_sec, &tv_usec);
		tv_msec = tv_usec / 1000;
		        
		/* Shift queue, update stats */
		memorystatus_update_jetsam_snapshot_entry_locked(p, cause, killtime);

		/*
		 * In order to kill the target process, we will drop the proc_list_lock.
		 * To guaranteee that p and next_p don't disappear out from under the lock,
		 * we must take a ref on both.
		 * If we cannot get a reference, then it's likely we've raced with
		 * that process exiting on another core.
		 */
		if (proc_ref_locked(p) == p) {
			if (next_p) {
				while (next_p && (proc_ref_locked(next_p) != next_p)) {
					proc_t temp_p;

					 /*
					  * We must have raced with next_p exiting on another core.
					  * Recover by getting the next eligible process in the band.
					  */

					MEMORYSTATUS_DEBUG(1, "memorystatus: aggressive%d: skipping %d [%s] (exiting?)\n",
					       aggr_count, next_p->p_pid, (*next_p->p_name ? next_p->p_name : "(unknown)"));

					temp_p = next_p;
					next_p = memorystatus_get_next_proc_locked(&i, temp_p, TRUE);
				 }
			}
			proc_list_unlock();

			printf("%lu.%01d memorystatus: aggressive%d: %s %d [%s] (%s %d) - memorystatus_available_pages: %d\n",
			       (unsigned long)tv_sec, tv_msec, aggr_count,
			       ((aPid_ep == JETSAM_PRIORITY_IDLE) ? "idle exiting pid" : "jetsam killing pid"),
			       aPid, (*p->p_name ? p->p_name : "(unknown)"),
			       jetsam_kill_cause_name[cause], aPid_ep, memorystatus_available_pages);

			memorystatus_level_snapshot = memorystatus_level;

			/*
			 * memorystatus_do_kill() drops a reference, so take another one so we can
			 * continue to use this exit reason even after memorystatus_do_kill()
			 * returns.
			 */
			os_reason_ref(jetsam_reason);
			killed = memorystatus_do_kill(p, cause, jetsam_reason);

			/* Success? */
			if (killed) {
				proc_rele(p);
				kill_count++;
				p = NULL;
				killed = FALSE;

				/* 
				 * Continue the killing spree.
				 */
				proc_list_lock();
				if (next_p) {
					proc_rele_locked(next_p);
				}

				if (aPid_ep == JETSAM_PRIORITY_FOREGROUND && memorystatus_aggressive_jetsam_lenient == TRUE) {
					if (memorystatus_level > memorystatus_level_snapshot && ((memorystatus_level - memorystatus_level_snapshot) >= AGGRESSIVE_JETSAM_LENIENT_MODE_THRESHOLD)) {
#if DEVELOPMENT || DEBUG
						printf("Disabling Lenient mode after one-time deployment.\n");
#endif /* DEVELOPMENT || DEBUG */
						memorystatus_aggressive_jetsam_lenient = FALSE;
						break;
					}
				}

				continue;
			}
					
			/*
			 * Failure - first unwind the state,
			 * then fall through to restart the search.
			 */
			proc_list_lock();
			proc_rele_locked(p);
			if (next_p) {
				proc_rele_locked(next_p);
			}
			p->p_memstat_state &= ~P_MEMSTAT_TERMINATED;
			p->p_memstat_state |= P_MEMSTAT_ERROR;
			*errors += 1;
			p = NULL;
		}

		/*
		 * Failure - restart the search at the beginning of
		 * the band we were already traversing.
		 *
		 * We might have raced with "p" exiting on another core, resulting in no
		 * ref on "p".  Or, we may have failed to kill "p".
		 *
		 * Either way, we fall thru to here, leaving the proc in the 
		 * P_MEMSTAT_TERMINATED or P_MEMSTAT_ERROR state.
		 *
		 * And, we hold the the proc_list_lock at this point.
		 */

		next_p = memorystatus_get_first_proc_locked(&i, TRUE);
	}
	
	proc_list_unlock();
	
exit:
	os_reason_free(jetsam_reason);

	/* Clear snapshot if freshly captured and no target was found */
	if (new_snapshot && (kill_count == 0)) {
	    memorystatus_jetsam_snapshot->entry_count = memorystatus_jetsam_snapshot_count = 0;
	}
	
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_JETSAM) | DBG_FUNC_END,
			      memorystatus_available_pages, killed ? aPid : 0, kill_count, 0, 0);

	if (kill_count > 0) {
		return(TRUE);
	}
	else {
		return(FALSE);
	}
}

static boolean_t
memorystatus_kill_hiwat_proc(uint32_t *errors)
{
	pid_t aPid = 0;
	proc_t p = PROC_NULL, next_p = PROC_NULL;
	boolean_t new_snapshot = FALSE, killed = FALSE;
	int kill_count = 0;
	unsigned int i = 0;
	uint32_t aPid_ep;
	uint64_t killtime = 0;
        clock_sec_t     tv_sec;
        clock_usec_t    tv_usec;
        uint32_t        tv_msec;
	os_reason_t jetsam_reason = OS_REASON_NULL;
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_JETSAM_HIWAT) | DBG_FUNC_START,
		memorystatus_available_pages, 0, 0, 0, 0);
	
	jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_MEMORY_HIGHWATER);
	if (jetsam_reason == OS_REASON_NULL) {
		printf("memorystatus_kill_hiwat_proc: failed to allocate exit reason\n");
	}

	proc_list_lock();
	
	next_p = memorystatus_get_first_proc_locked(&i, TRUE);
	while (next_p) {
		uint64_t footprint_in_bytes = 0;
		uint64_t memlimit_in_bytes  = 0;
		boolean_t skip = 0;

		p = next_p;
		next_p = memorystatus_get_next_proc_locked(&i, p, TRUE);
		
		aPid = p->p_pid;
		aPid_ep = p->p_memstat_effectivepriority;
		
		if (p->p_memstat_state  & (P_MEMSTAT_ERROR | P_MEMSTAT_TERMINATED)) {
			continue;
		}
		
		/* skip if no limit set */
		if (p->p_memstat_memlimit <= 0) {
			continue;
		}

#if 0
		/*
		 * No need to consider P_MEMSTAT_MEMLIMIT_BACKGROUND anymore.
		 * Background limits are described via the inactive limit slots.
		 * Their fatal/non-fatal setting will drive whether or not to be
		 * considered in this kill path.
		 */

		/* skip if a currently inapplicable limit is encountered */
		if ((p->p_memstat_state & P_MEMSTAT_MEMLIMIT_BACKGROUND) && (p->p_memstat_effectivepriority >= JETSAM_PRIORITY_FOREGROUND)) {          
			continue;
		}
#endif
		footprint_in_bytes = get_task_phys_footprint(p->task);
		memlimit_in_bytes  = (((uint64_t)p->p_memstat_memlimit) * 1024ULL * 1024ULL);	/* convert MB to bytes */
		skip = (footprint_in_bytes <= memlimit_in_bytes);

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
#if DEVELOPMENT || DEBUG
			MEMORYSTATUS_DEBUG(1, "jetsam: %s pid %d [%s] - %lld Mb > 1 (%d Mb)\n",
					   (memorystatus_jetsam_policy & kPolicyDiagnoseActive) ? "suspending": "killing",
					   aPid, (*p->p_name ? p->p_name : "unknown"),
					   (footprint_in_bytes / (1024ULL * 1024ULL)), 	/* converted bytes to MB */
					   p->p_memstat_memlimit);
#endif /* DEVELOPMENT || DEBUG */
				
			if (memorystatus_jetsam_snapshot_count == 0) {
				memorystatus_init_jetsam_snapshot_locked(NULL,0);
                		new_snapshot = TRUE;
                	}
                	
			p->p_memstat_state |= P_MEMSTAT_TERMINATED;

			killtime = mach_absolute_time();
			absolutetime_to_microtime(killtime, &tv_sec, &tv_usec);
			tv_msec = tv_usec / 1000;
				
#if DEVELOPMENT || DEBUG
			if (memorystatus_jetsam_policy & kPolicyDiagnoseActive) {
			        MEMORYSTATUS_DEBUG(1, "jetsam: pid %d suspended for diagnosis - memorystatus_available_pages: %d\n", aPid, memorystatus_available_pages);
				memorystatus_update_jetsam_snapshot_entry_locked(p, kMemorystatusKilledDiagnostic, killtime);
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
				memorystatus_update_jetsam_snapshot_entry_locked(p, kMemorystatusKilledHiwat, killtime);
			        
				if (proc_ref_locked(p) == p) {
					proc_list_unlock();

					printf("%lu.%02d memorystatus: jetsam killing pid %d [%s] (highwater %d) - memorystatus_available_pages: %d\n",
					       (unsigned long)tv_sec, tv_msec, aPid, (*p->p_name ? p->p_name : "(unknown)"), aPid_ep, memorystatus_available_pages);

					/*
					 * memorystatus_do_kill drops a reference, so take another one so we can
					 * continue to use this exit reason even after memorystatus_do_kill()
					 * returns
					 */
					os_reason_ref(jetsam_reason);

					killed = memorystatus_do_kill(p, kMemorystatusKilledHiwat, jetsam_reason);

					/* Success? */
					if (killed) {
						proc_rele(p);
						kill_count++;
						goto exit;
					}

					/*
					 * Failure - first unwind the state,
					 * then fall through to restart the search.
					 */
					proc_list_lock();
					proc_rele_locked(p);
					p->p_memstat_state &= ~P_MEMSTAT_TERMINATED;
					p->p_memstat_state |= P_MEMSTAT_ERROR;
					*errors += 1;
				}

				/*
				 * Failure - restart the search.
				 *
				 * We might have raced with "p" exiting on another core, resulting in no
				 * ref on "p".  Or, we may have failed to kill "p".
				 *
				 * Either way, we fall thru to here, leaving the proc in the 
				 * P_MEMSTAT_TERMINATED state.
				 *
				 * And, we hold the the proc_list_lock at this point.
				 */

				i = 0;
				next_p = memorystatus_get_first_proc_locked(&i, TRUE);
			}
		}
	}
	
	proc_list_unlock();
	
exit:
	os_reason_free(jetsam_reason);

	/* Clear snapshot if freshly captured and no target was found */
	if (new_snapshot && !killed) {
		proc_list_lock();
		memorystatus_jetsam_snapshot->entry_count = memorystatus_jetsam_snapshot_count = 0;
		proc_list_unlock();
	}
	
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_JETSAM_HIWAT) | DBG_FUNC_END, 
			      memorystatus_available_pages, killed ? aPid : 0, kill_count, 0, 0);

	return killed;
}

/*
 * Jetsam a process pinned in the elevated band.
 *
 * Return:  true -- at least one pinned process was jetsammed
 *	    false -- no pinned process was jetsammed
 */
static boolean_t
memorystatus_kill_elevated_process(uint32_t cause, os_reason_t jetsam_reason, int aggr_count, uint32_t *errors)
{
	pid_t aPid = 0;
	proc_t p = PROC_NULL, next_p = PROC_NULL;
	boolean_t new_snapshot = FALSE, killed = FALSE;
	int kill_count = 0;
	unsigned int i = JETSAM_PRIORITY_ELEVATED_INACTIVE;
	uint32_t aPid_ep;
	uint64_t killtime = 0;
        clock_sec_t     tv_sec;
        clock_usec_t    tv_usec;
        uint32_t        tv_msec;


	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_JETSAM) | DBG_FUNC_START,
		memorystatus_available_pages, 0, 0, 0, 0);

	proc_list_lock();

	next_p = memorystatus_get_first_proc_locked(&i, FALSE);
	while (next_p) {

		p = next_p;
		next_p = memorystatus_get_next_proc_locked(&i, p, FALSE);

		aPid = p->p_pid;
		aPid_ep = p->p_memstat_effectivepriority;

		/*
		 * Only pick a process pinned in this elevated band
		 */
		if (!(p->p_memstat_state & P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND)) {
			continue;
		}

		if (p->p_memstat_state  & (P_MEMSTAT_ERROR | P_MEMSTAT_TERMINATED)) {
			continue;
		}

#if CONFIG_FREEZE
		if (p->p_memstat_state & P_MEMSTAT_LOCKED) {
			continue;
		}
#endif

#if DEVELOPMENT || DEBUG
		MEMORYSTATUS_DEBUG(1, "jetsam: elevated%d process pid %d [%s] - memorystatus_available_pages: %d\n",
				   aggr_count,
				   aPid, (*p->p_name ? p->p_name : "unknown"),
				   memorystatus_available_pages);
#endif /* DEVELOPMENT || DEBUG */

		if (memorystatus_jetsam_snapshot_count == 0) {
			memorystatus_init_jetsam_snapshot_locked(NULL,0);
			new_snapshot = TRUE;
		}

		p->p_memstat_state |= P_MEMSTAT_TERMINATED;

		killtime = mach_absolute_time();
		absolutetime_to_microtime(killtime, &tv_sec, &tv_usec);
		tv_msec = tv_usec / 1000;

		memorystatus_update_jetsam_snapshot_entry_locked(p, cause, killtime);

		if (proc_ref_locked(p) == p) {

			proc_list_unlock();

                        printf("%lu.%01d memorystatus: elevated%d: jetsam killing pid %d [%s] (%s %d) - memorystatus_available_pages: %d\n",
                               (unsigned long)tv_sec, tv_msec,
			       aggr_count,
                               aPid, (*p->p_name ? p->p_name : "(unknown)"),
                               jetsam_kill_cause_name[cause], aPid_ep, memorystatus_available_pages);

			/*
			 * memorystatus_do_kill drops a reference, so take another one so we can
			 * continue to use this exit reason even after memorystatus_do_kill()
			 * returns
			 */
			os_reason_ref(jetsam_reason);
			killed = memorystatus_do_kill(p, cause, jetsam_reason);

			/* Success? */
			if (killed) {
				proc_rele(p);
				kill_count++;
				goto exit;
			}

			/*
			 * Failure - first unwind the state,
			 * then fall through to restart the search.
			 */
			proc_list_lock();
			proc_rele_locked(p);
			p->p_memstat_state &= ~P_MEMSTAT_TERMINATED;
			p->p_memstat_state |= P_MEMSTAT_ERROR;
			*errors += 1;
		}

		/*
		 * Failure - restart the search.
		 *
		 * We might have raced with "p" exiting on another core, resulting in no
		 * ref on "p".  Or, we may have failed to kill "p".
		 *
		 * Either way, we fall thru to here, leaving the proc in the
		 * P_MEMSTAT_TERMINATED state or P_MEMSTAT_ERROR state.
		 *
		 * And, we hold the the proc_list_lock at this point.
		 */

		next_p = memorystatus_get_first_proc_locked(&i, FALSE);
	}

	proc_list_unlock();

exit:
	os_reason_free(jetsam_reason);

	/* Clear snapshot if freshly captured and no target was found */
	if (new_snapshot && (kill_count == 0)) {
		proc_list_lock();
		memorystatus_jetsam_snapshot->entry_count = memorystatus_jetsam_snapshot_count = 0;
		proc_list_unlock();
	}

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_JETSAM) | DBG_FUNC_END,
			      memorystatus_available_pages, killed ? aPid : 0, kill_count, 0, 0);

	return (killed);
}

static boolean_t 
memorystatus_kill_process_async(pid_t victim_pid, uint32_t cause) {
	/*
	 * TODO: allow a general async path
	 *
	 * NOTE: If a new async kill cause is added, make sure to update memorystatus_thread() to
	 * add the appropriate exit reason code mapping.
	 */
	if ((victim_pid != -1) || (cause != kMemorystatusKilledVMPageShortage && cause != kMemorystatusKilledVMThrashing &&
				   cause != kMemorystatusKilledFCThrashing)) {
		return FALSE;
	}
    
	kill_under_pressure_cause = cause;
	memorystatus_thread_wake();
	return TRUE;
}

boolean_t 
memorystatus_kill_on_VM_page_shortage(boolean_t async) {
	if (async) {
		return memorystatus_kill_process_async(-1, kMemorystatusKilledVMPageShortage);
	} else {
		os_reason_t jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_MEMORY_VMPAGESHORTAGE);
		if (jetsam_reason == OS_REASON_NULL) {
			printf("memorystatus_kill_on_VM_page_shortage -- sync: failed to allocate jetsam reason\n");
		}

		return memorystatus_kill_process_sync(-1, kMemorystatusKilledVMPageShortage, jetsam_reason);
	}
}

boolean_t
memorystatus_kill_on_VM_thrashing(boolean_t async) {
	if (async) {
		return memorystatus_kill_process_async(-1, kMemorystatusKilledVMThrashing);
	} else {
		os_reason_t jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_MEMORY_VMTHRASHING);
		if (jetsam_reason == OS_REASON_NULL) {
			printf("memorystatus_kill_on_VM_thrashing -- sync: failed to allocate jetsam reason\n");
		}

		return memorystatus_kill_process_sync(-1, kMemorystatusKilledVMThrashing, jetsam_reason);
	}
}

boolean_t
memorystatus_kill_on_FC_thrashing(boolean_t async) {


	if (async) {
		return memorystatus_kill_process_async(-1, kMemorystatusKilledFCThrashing);
	} else {
		os_reason_t jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_MEMORY_FCTHRASHING);
		if (jetsam_reason == OS_REASON_NULL) {
			printf("memorystatus_kill_on_FC_thrashing -- sync: failed to allocate jetsam reason\n");
		}

		return memorystatus_kill_process_sync(-1, kMemorystatusKilledFCThrashing, jetsam_reason);
	}
}

boolean_t 
memorystatus_kill_on_vnode_limit(void) {
	os_reason_t jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_VNODE);
	if (jetsam_reason == OS_REASON_NULL) {
		printf("memorystatus_kill_on_vnode_limit: failed to allocate jetsam reason\n");
	}

	return memorystatus_kill_process_sync(-1, kMemorystatusKilledVnodes, jetsam_reason);
}

#endif /* CONFIG_JETSAM */

#if CONFIG_FREEZE

__private_extern__ void
memorystatus_freeze_init(void)
{
	kern_return_t result;
	thread_t thread;

	freezer_lck_grp_attr = lck_grp_attr_alloc_init();
	freezer_lck_grp = lck_grp_alloc_init("freezer", freezer_lck_grp_attr);

	lck_mtx_init(&freezer_mutex, freezer_lck_grp, NULL);
		
	result = kernel_thread_start(memorystatus_freeze_thread, NULL, &thread);
	if (result == KERN_SUCCESS) {
		thread_deallocate(thread);
	} else {
		panic("Could not create memorystatus_freeze_thread");
	}
}

/*
 * Synchronously freeze the passed proc. Called with a reference to the proc held.
 *
 * Returns EINVAL or the value returned by task_freeze().
 */
int
memorystatus_freeze_process_sync(proc_t p)
{
	int ret = EINVAL;
	pid_t aPid = 0;
	boolean_t memorystatus_freeze_swap_low = FALSE;

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_FREEZE) | DBG_FUNC_START,
		memorystatus_available_pages, 0, 0, 0, 0);

	lck_mtx_lock(&freezer_mutex);

	if (p == NULL) {
		goto exit;
	}

	if (memorystatus_freeze_enabled == FALSE) {
		goto exit;
	}

	if (!memorystatus_can_freeze(&memorystatus_freeze_swap_low)) {
		goto exit;
	}

	if (memorystatus_freeze_update_throttle()) {
		printf("memorystatus_freeze_process_sync: in throttle, ignorning freeze\n");
		memorystatus_freeze_throttle_count++;
		goto exit;
	}

	proc_list_lock();

	if (p != NULL) {
		uint32_t purgeable, wired, clean, dirty, state;
		uint32_t max_pages, pages, i;
		boolean_t shared;

		aPid = p->p_pid;
		state = p->p_memstat_state;

		/* Ensure the process is eligible for freezing */
		if ((state & (P_MEMSTAT_TERMINATED | P_MEMSTAT_LOCKED | P_MEMSTAT_FROZEN)) || !(state & P_MEMSTAT_SUSPENDED)) {
			proc_list_unlock();
			goto exit;
		}

		/* Only freeze processes meeting our minimum resident page criteria */
		memorystatus_get_task_page_counts(p->task, &pages, NULL, NULL, NULL);
		if (pages < memorystatus_freeze_pages_min) {
			proc_list_unlock();
			goto exit;
		}

		if (VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {

			unsigned int avail_swap_space = 0; /* in pages. */

			/*
			 * Freezer backed by the compressor and swap file(s)
			 * while will hold compressed data.
			 */
			avail_swap_space = vm_swap_get_free_space() / PAGE_SIZE_64;

			max_pages = MIN(avail_swap_space, memorystatus_freeze_pages_max);

			if (max_pages < memorystatus_freeze_pages_min) {
				proc_list_unlock();
				goto exit;
			}
		} else {
			/*
			 * We only have the compressor without any swap.
			 */
			max_pages = UINT32_MAX - 1;
		}

		/* Mark as locked temporarily to avoid kill */
		p->p_memstat_state |= P_MEMSTAT_LOCKED;
		proc_list_unlock();

		ret = task_freeze(p->task, &purgeable, &wired, &clean, &dirty, max_pages, &shared, FALSE);

		DTRACE_MEMORYSTATUS6(memorystatus_freeze, proc_t, p, unsigned int, memorystatus_available_pages, boolean_t, purgeable, unsigned int, wired, uint32_t, clean, uint32_t, dirty);

		MEMORYSTATUS_DEBUG(1, "memorystatus_freeze_process_sync: task_freeze %s for pid %d [%s] - "
			"memorystatus_pages: %d, purgeable: %d, wired: %d, clean: %d, dirty: %d, max_pages %d, shared %d\n",
			(ret == KERN_SUCCESS) ? "SUCCEEDED" : "FAILED", aPid, (*p->p_name ? p->p_name : "(unknown)"),
				   memorystatus_available_pages, purgeable, wired, clean, dirty, max_pages, shared);

		proc_list_lock();
		p->p_memstat_state &= ~P_MEMSTAT_LOCKED;

		if (ret == KERN_SUCCESS) {
			memorystatus_freeze_entry_t data = { aPid, TRUE, dirty };

			memorystatus_frozen_count++;

			p->p_memstat_state |= (P_MEMSTAT_FROZEN | (shared ? 0: P_MEMSTAT_NORECLAIM));

			if (VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
				/* Update stats */
				for (i = 0; i < sizeof(throttle_intervals) / sizeof(struct throttle_interval_t); i++) {
					throttle_intervals[i].pageouts += dirty;
				}
			}

			memorystatus_freeze_pageouts += dirty;
			memorystatus_freeze_count++;

			proc_list_unlock();

			memorystatus_send_note(kMemorystatusFreezeNote, &data, sizeof(data));
		} else {
			proc_list_unlock();
		}
	}

exit:
	lck_mtx_unlock(&freezer_mutex);
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_FREEZE) | DBG_FUNC_END,
		memorystatus_available_pages, aPid, 0, 0, 0);

	return ret;
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
		memorystatus_get_task_page_counts(p->task, &pages, NULL, NULL, NULL);
		if (pages < memorystatus_freeze_pages_min) {
			continue; // with lock held
		} 

		if (VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {

			/* Ensure there's enough free space to freeze this process. */

			unsigned int avail_swap_space = 0; /* in pages. */

			/*
			 * Freezer backed by the compressor and swap file(s)
			 * while will hold compressed data.
			 */
			avail_swap_space = vm_swap_get_free_space() / PAGE_SIZE_64;

			max_pages = MIN(avail_swap_space, memorystatus_freeze_pages_max);

			if (max_pages < memorystatus_freeze_pages_min) {
				*memorystatus_freeze_swap_low = TRUE;
				proc_list_unlock();
				goto exit;
			}
		} else {
			/*
			 * We only have the compressor pool.
			 */
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
    			"memorystatus_pages: %d, purgeable: %d, wired: %d, clean: %d, dirty: %d, max_pages %d, shared %d\n", 
				   (kr == KERN_SUCCESS) ? "SUCCEEDED" : "FAILED", aPid, (*p->p_name ? p->p_name : "(unknown)"),
				   memorystatus_available_pages, purgeable, wired, clean, dirty, max_pages, shared);
     
		proc_list_lock();
		p->p_memstat_state &= ~P_MEMSTAT_LOCKED;
		
		/* Success? */
		if (KERN_SUCCESS == kr) {
			memorystatus_freeze_entry_t data = { aPid, TRUE, dirty };
			
			memorystatus_frozen_count++;
			
			p->p_memstat_state |= (P_MEMSTAT_FROZEN | (shared ? 0: P_MEMSTAT_NORECLAIM));

			if (VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
				/* Update stats */
				for (i = 0; i < sizeof(throttle_intervals) / sizeof(struct throttle_interval_t); i++) {
					throttle_intervals[i].pageouts += dirty;
				}
			}

			memorystatus_freeze_pageouts += dirty;
			memorystatus_freeze_count++;

			proc_list_unlock();

			memorystatus_send_note(kMemorystatusFreezeNote, &data, sizeof(data));

			/* Return KERN_SUCESS */
			ret = kr;

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
	boolean_t can_freeze = TRUE;

	/* Only freeze if we're sufficiently low on memory; this holds off freeze right
	   after boot,  and is generally is a no-op once we've reached steady state. */
	if (memorystatus_available_pages > memorystatus_freeze_threshold) {
		return FALSE;
	}
	
	/* Check minimum suspended process threshold. */
	if (!memorystatus_can_freeze_processes()) {
		return FALSE;
	}
	assert(VM_CONFIG_COMPRESSOR_IS_PRESENT);

	if ( !VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
		/*
		 * In-core compressor used for freezing WITHOUT on-disk swap support.
		 */
		if (vm_compressor_low_on_space()) {
			if (*memorystatus_freeze_swap_low) {
				*memorystatus_freeze_swap_low = TRUE;
			}

			can_freeze = FALSE;

		} else {
			if (*memorystatus_freeze_swap_low) {
				*memorystatus_freeze_swap_low = FALSE;
			}

			can_freeze = TRUE;
		}
	} else {
		/*
		 * Freezing WITH on-disk swap support.
		 *
		 * In-core compressor fronts the swap.
		 */
		if (vm_swap_low_on_space()) {
			if (*memorystatus_freeze_swap_low) {
				*memorystatus_freeze_swap_low = TRUE;
			}

			can_freeze = FALSE;
		}

	}
	
	return can_freeze;
}

static void
memorystatus_freeze_update_throttle_interval(mach_timespec_t *ts, struct throttle_interval_t *interval)
{
	unsigned int freeze_daily_pageouts_max = memorystatus_freeze_daily_mb_max * (1024 * 1024 / PAGE_SIZE);
	if (CMP_MACH_TIMESPEC(ts, &interval->ts) >= 0) {
		if (!interval->max_pageouts) {
			interval->max_pageouts = (interval->burst_multiple * (((uint64_t)interval->mins * freeze_daily_pageouts_max) / (24 * 60)));
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

	lck_mtx_lock(&freezer_mutex);
	if (memorystatus_freeze_enabled) {
		if (memorystatus_can_freeze(&memorystatus_freeze_swap_low)) {
			/* Only freeze if we've not exceeded our pageout budgets.*/
			if (!memorystatus_freeze_update_throttle()) {
				memorystatus_freeze_top_process(&memorystatus_freeze_swap_low);
			} else {
				printf("memorystatus_freeze_thread: in throttle, ignoring freeze\n");
				memorystatus_freeze_throttle_count++; /* Throttled, update stats */
			}
		}
	}
	lck_mtx_unlock(&freezer_mutex);

	assert_wait((event_t) &memorystatus_freeze_wakeup, THREAD_UNINT);
	thread_block((thread_continue_t) memorystatus_freeze_thread);	
}

static int
sysctl_memorystatus_do_fastwake_warmup_all  SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, req, arg1, arg2)

	/* Need to be root or have entitlement */
	if (!kauth_cred_issuser(kauth_cred_get()) && !IOTaskHasEntitlement(current_task(), MEMORYSTATUS_ENTITLEMENT)) {
		return EPERM;
	}

	if (memorystatus_freeze_enabled == FALSE) {
		return ENOTSUP;
	}

	do_fastwake_warmup_all();

	return 0;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_do_fastwake_warmup_all, CTLTYPE_INT|CTLFLAG_WR|CTLFLAG_LOCKED|CTLFLAG_MASKED,
    0, 0, &sysctl_memorystatus_do_fastwake_warmup_all, "I", "");

#endif /* CONFIG_FREEZE */

#if VM_PRESSURE_EVENTS

#if CONFIG_MEMORYSTATUS

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

boolean_t
memorystatus_warn_process(pid_t pid, boolean_t limit_exceeded) {

	boolean_t ret = FALSE;
	boolean_t found_knote = FALSE;
	struct knote *kn = NULL;

	/*
	 * See comment in sysctl_memorystatus_vm_pressure_send.
	 */

	memorystatus_klist_lock();

	SLIST_FOREACH(kn, &memorystatus_klist, kn_selnext) {
		proc_t knote_proc = knote_get_kq(kn)->kq_p;
		pid_t knote_pid = knote_proc->p_pid;

		if (knote_pid == pid) {
			/*
			 * By setting the "fflags" here, we are forcing
			 * a process to deal with the case where it's
			 * bumping up into its memory limits. If we don't
			 * do this here, we will end up depending on the
			 * system pressure snapshot evaluation in
			 * filt_memorystatus().
			 */

			if (!limit_exceeded) {

				/*
				 * Processes on desktop are not expecting to handle a system-wide
				 * critical or system-wide warning notification from this path.
				 * Intentionally set only the unambiguous limit warning here.
				 */

				if (kn->kn_sfflags & NOTE_MEMORYSTATUS_PROC_LIMIT_WARN) {
					kn->kn_fflags = NOTE_MEMORYSTATUS_PROC_LIMIT_WARN;
					found_knote = TRUE;
				}

			} else {
				/*
				 * Send this notification when a process has exceeded a soft limit.
				 */
				if (kn->kn_sfflags & NOTE_MEMORYSTATUS_PROC_LIMIT_CRITICAL) {
					kn->kn_fflags = NOTE_MEMORYSTATUS_PROC_LIMIT_CRITICAL;
					found_knote = TRUE;
				}
			}
		}
	}

	if (found_knote) {
		KNOTE(&memorystatus_klist, 0);
		ret = TRUE;
	}

	memorystatus_klist_unlock();

	return ret;
}

/*
 * Can only be set by the current task on itself.
 */
int
memorystatus_low_mem_privileged_listener(uint32_t op_flags)
{
	boolean_t set_privilege = FALSE;
	/*
	 * Need an entitlement check here?
	 */
	if (op_flags == MEMORYSTATUS_CMD_PRIVILEGED_LISTENER_ENABLE) {
		set_privilege = TRUE;
	} else if (op_flags == MEMORYSTATUS_CMD_PRIVILEGED_LISTENER_DISABLE) {
		set_privilege = FALSE;
	} else {
		return EINVAL;
	}

	return (task_low_mem_privileged_listener(current_task(), set_privilege, NULL));
}

int
memorystatus_send_pressure_note(pid_t pid) {
 	MEMORYSTATUS_DEBUG(1, "memorystatus_send_pressure_note(): pid %d\n", pid);      
 	return memorystatus_send_note(kMemorystatusPressureNote, &pid, sizeof(pid));
}

void
memorystatus_send_low_swap_note(void) {
	
	struct knote *kn = NULL;

	memorystatus_klist_lock();
	SLIST_FOREACH(kn, &memorystatus_klist, kn_selnext) {
		/* We call is_knote_registered_modify_task_pressure_bits to check if the sfflags for the
		 * current note contain NOTE_MEMORYSTATUS_LOW_SWAP. Once we find one note in the memorystatus_klist
		 * that has the NOTE_MEMORYSTATUS_LOW_SWAP flags in its sfflags set, we call KNOTE with
		 * kMemoryStatusLowSwap as the hint to process and update all knotes on the memorystatus_klist accordingly. */
		if (is_knote_registered_modify_task_pressure_bits(kn, NOTE_MEMORYSTATUS_LOW_SWAP, NULL, 0, 0) == TRUE) {
			KNOTE(&memorystatus_klist, kMemorystatusLowSwap);
			break;
		}
	}

	memorystatus_klist_unlock();
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

/*
 * This is meant for stackshot and kperf -- it does not take the proc_list_lock
 * to access the p_memstat_dirty field.
 */
boolean_t
memorystatus_proc_is_dirty_unsafe(void *v)
{
	if (!v) {
		return FALSE;
	}
	proc_t p = (proc_t)v;
	return (p->p_memstat_dirty & P_DIRTY_IS_DIRTY) != 0;
}

#endif /* CONFIG_MEMORYSTATUS */

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
vm_pressure_select_optimal_candidate_to_notify(struct klist *, int, boolean_t);

/*
 * This value is the threshold that a process must meet to be considered for scavenging.
 */
#define VM_PRESSURE_MINIMUM_RSIZE		10	/* MB */

#define VM_PRESSURE_NOTIFY_WAIT_PERIOD		10000	/* milliseconds */

#if DEBUG
#define VM_PRESSURE_DEBUG(cond, format, ...)      \
do {                                              \
	if (cond) { printf(format, ##__VA_ARGS__); } \
} while(0)
#else
#define VM_PRESSURE_DEBUG(cond, format, ...)
#endif

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
is_knote_registered_modify_task_pressure_bits(struct knote *kn_max, int knote_pressure_level, task_t task, vm_pressure_level_t pressure_level_to_clear, vm_pressure_level_t pressure_level_to_set)
{
	if (kn_max->kn_sfflags & knote_pressure_level) {

		if (pressure_level_to_clear && task_has_been_notified(task, pressure_level_to_clear) == TRUE) {

			task_clear_has_been_notified(task, pressure_level_to_clear);
		}

		task_mark_has_been_notified(task, pressure_level_to_set);
		return TRUE;
	}

	return FALSE;
}

void
memorystatus_klist_reset_all_for_level(vm_pressure_level_t pressure_level_to_clear)
{
	struct knote *kn = NULL;

	memorystatus_klist_lock();
        SLIST_FOREACH(kn, &memorystatus_klist, kn_selnext) {

		proc_t			p = PROC_NULL;
		struct task*		t = TASK_NULL;

		p = knote_get_kq(kn)->kq_p;
		proc_list_lock();
		if (p != proc_ref_locked(p)) {
			p = PROC_NULL;
			proc_list_unlock();
			continue;
		}
		proc_list_unlock();

		t = (struct task *)(p->task);

		task_clear_has_been_notified(t, pressure_level_to_clear);

		proc_rele(p);
	}

	memorystatus_klist_unlock();
}

extern kern_return_t vm_pressure_notify_dispatch_vm_clients(boolean_t target_foreground_process);

struct knote *
vm_pressure_select_optimal_candidate_to_notify(struct klist *candidate_list, int level, boolean_t target_foreground_process);

/*
 * Used by the vm_pressure_thread which is
 * signalled from within vm_pageout_scan().
 */
static void vm_dispatch_memory_pressure(void);
void consider_vm_pressure_events(void);

void consider_vm_pressure_events(void)
{
	vm_dispatch_memory_pressure();
}
static void vm_dispatch_memory_pressure(void)
{
	memorystatus_update_vm_pressure(FALSE);
}

extern vm_pressure_level_t
convert_internal_pressure_level_to_dispatch_level(vm_pressure_level_t);

struct knote *
vm_pressure_select_optimal_candidate_to_notify(struct klist *candidate_list, int level, boolean_t target_foreground_process)
{
	struct knote	*kn = NULL, *kn_max = NULL;
        uint64_t	resident_max = 0;	/* MB */
	struct timeval	curr_tstamp = {0, 0};
	int		elapsed_msecs = 0;
	int		selected_task_importance = 0;
	static int	pressure_snapshot = -1;
	boolean_t	pressure_increase = FALSE;

	if (pressure_snapshot == -1) {
		/*
		 * Initial snapshot.
		 */
		pressure_snapshot = level;
		pressure_increase = TRUE;
	} else {

		if (level >= pressure_snapshot) {
			pressure_increase = TRUE;
		} else {
			pressure_increase = FALSE;
		}

		pressure_snapshot = level;
	}

	if (pressure_increase == TRUE) {
		/*
		 * We'll start by considering the largest
		 * unimportant task in our list.
		 */
		selected_task_importance = INT_MAX;
	} else {
		/*
		 * We'll start by considering the largest
		 * important task in our list.
		 */
		selected_task_importance = 0;
	}

	microuptime(&curr_tstamp);

        SLIST_FOREACH(kn, candidate_list, kn_selnext) {

                uint64_t		resident_size = 0;	/* MB */
		proc_t			p = PROC_NULL;
		struct task*		t = TASK_NULL;
		int			curr_task_importance = 0;
		boolean_t		consider_knote = FALSE;
		boolean_t		privileged_listener = FALSE;

		p = knote_get_kq(kn)->kq_p;
		proc_list_lock();
		if (p != proc_ref_locked(p)) {
			p = PROC_NULL;
			proc_list_unlock();
			continue;
		}
		proc_list_unlock();

#if CONFIG_MEMORYSTATUS
		if (target_foreground_process == TRUE && !memorystatus_is_foreground_locked(p)) {
			/*
			 * Skip process not marked foreground.
			 */
			proc_rele(p);
			continue;
		}
#endif /* CONFIG_MEMORYSTATUS */

		t = (struct task *)(p->task);

		timevalsub(&curr_tstamp, &p->vm_pressure_last_notify_tstamp);
		elapsed_msecs = curr_tstamp.tv_sec * 1000 + curr_tstamp.tv_usec / 1000;

		vm_pressure_level_t dispatch_level = convert_internal_pressure_level_to_dispatch_level(level);

		if ((kn->kn_sfflags & dispatch_level) == 0) {
			proc_rele(p);
			continue;
		}

#if CONFIG_MEMORYSTATUS
		if (target_foreground_process == FALSE && !memorystatus_bg_pressure_eligible(p)) {
			VM_PRESSURE_DEBUG(1, "[vm_pressure] skipping process %d\n", p->p_pid);
			proc_rele(p);
			continue;
		}
#endif /* CONFIG_MEMORYSTATUS */

		curr_task_importance = task_importance_estimate(t);

		/*
		 * Privileged listeners are only considered in the multi-level pressure scheme
		 * AND only if the pressure is increasing.
		 */
		if (level > 0) {

			if (task_has_been_notified(t, level) == FALSE) {

				/*
				 * Is this a privileged listener?
				 */
				if (task_low_mem_privileged_listener(t, FALSE, &privileged_listener) == 0) {

					if (privileged_listener) {
						kn_max = kn;
						proc_rele(p);
						goto done_scanning;
					}
				}
			} else {
				proc_rele(p);
				continue;
			}
		} else if (level == 0) {

			/*
			 * Task wasn't notified when the pressure was increasing and so
			 * no need to notify it that the pressure is decreasing.
			 */
			if ((task_has_been_notified(t, kVMPressureWarning) == FALSE) && (task_has_been_notified(t, kVMPressureCritical) == FALSE)) {
				proc_rele(p);
				continue;
			}
		}

		/*
                 * We don't want a small process to block large processes from
                 * being notified again. <rdar://problem/7955532>
                 */
                resident_size = (get_task_phys_footprint(t))/(1024*1024ULL);  /* MB */

                if (resident_size >= VM_PRESSURE_MINIMUM_RSIZE) {

			if (level > 0) {
				/*
				 * Warning or Critical Pressure.
				 */
				 if (pressure_increase) {
					if ((curr_task_importance < selected_task_importance) ||
					    ((curr_task_importance == selected_task_importance) && (resident_size > resident_max))) {

						/*
						 * We have found a candidate process which is:
						 * a) at a lower importance than the current selected process
						 * OR
						 * b) has importance equal to that of the current selected process but is larger
						 */

						consider_knote = TRUE;
					}
				} else {
					if ((curr_task_importance > selected_task_importance) ||
					    ((curr_task_importance == selected_task_importance) && (resident_size > resident_max))) {

						/*
						 * We have found a candidate process which is:
						 * a) at a higher importance than the current selected process
						 * OR
						 * b) has importance equal to that of the current selected process but is larger
						 */

						consider_knote = TRUE;
					}
				}
			} else if (level == 0) {
				/*
				 * Pressure back to normal.
				 */
				if ((curr_task_importance > selected_task_importance) ||
				    ((curr_task_importance == selected_task_importance) && (resident_size > resident_max))) {

					consider_knote = TRUE;
				}
			}

			if (consider_knote) {
				resident_max = resident_size;
				kn_max = kn;
				selected_task_importance = curr_task_importance;
				consider_knote = FALSE; /* reset for the next candidate */
			}
                } else {
                        /* There was no candidate with enough resident memory to scavenge */
                        VM_PRESSURE_DEBUG(0, "[vm_pressure] threshold failed for pid %d with %llu resident...\n", p->p_pid, resident_size);
                }
		proc_rele(p);
        }

done_scanning:
	if (kn_max) {
		VM_DEBUG_CONSTANT_EVENT(vm_pressure_event, VM_PRESSURE_EVENT, DBG_FUNC_NONE, knote_get_kq(kn_max)->kq_p->p_pid, resident_max, 0, 0);
		VM_PRESSURE_DEBUG(1, "[vm_pressure] sending event to pid %d with %llu resident\n", knote_get_kq(kn_max)->kq_p->p_pid, resident_max);
	}

	return kn_max;
}

#define VM_PRESSURE_DECREASED_SMOOTHING_PERIOD		5000	/* milliseconds */
#define WARNING_NOTIFICATION_RESTING_PERIOD		25	/* seconds */
#define CRITICAL_NOTIFICATION_RESTING_PERIOD		25	/* seconds */

uint64_t next_warning_notification_sent_at_ts = 0;
uint64_t next_critical_notification_sent_at_ts = 0;

kern_return_t
memorystatus_update_vm_pressure(boolean_t target_foreground_process) 
{
	struct knote			*kn_max = NULL;
	struct knote			*kn_cur = NULL, *kn_temp = NULL;  /* for safe list traversal */
        pid_t				target_pid = -1;
        struct klist			dispatch_klist = { NULL };
	proc_t				target_proc = PROC_NULL;
	struct task			*task = NULL;
	boolean_t			found_candidate = FALSE;

	static vm_pressure_level_t 	level_snapshot = kVMPressureNormal;
	static vm_pressure_level_t	prev_level_snapshot = kVMPressureNormal;
	boolean_t			smoothing_window_started = FALSE;
	struct timeval			smoothing_window_start_tstamp = {0, 0};
	struct timeval			curr_tstamp = {0, 0};
	int				elapsed_msecs = 0;
	uint64_t 			curr_ts = mach_absolute_time();

#if !CONFIG_JETSAM
#define MAX_IDLE_KILLS 100	/* limit the number of idle kills allowed */

	int	idle_kill_counter = 0;

	/*
	 * On desktop we take this opportunity to free up memory pressure
	 * by immediately killing idle exitable processes. We use a delay
	 * to avoid overkill.  And we impose a max counter as a fail safe
	 * in case daemons re-launch too fast.
	 */
	while ((memorystatus_vm_pressure_level != kVMPressureNormal) && (idle_kill_counter < MAX_IDLE_KILLS)) {
		if (memorystatus_idle_exit_from_VM() == FALSE) {
			/* No idle exitable processes left to kill */
			break;
		}
		idle_kill_counter++;

		if (memorystatus_manual_testing_on == TRUE) {
			/*
			 * Skip the delay when testing
			 * the pressure notification scheme.
			 */
		} else {
			delay(1000000);    /* 1 second */
		}
	}
#endif /* !CONFIG_JETSAM */

	if (level_snapshot != kVMPressureNormal) {

		/*
		 * Check to see if we are still in the 'resting' period
		 * after having notified all clients interested in
		 * a particular pressure level.
		 */

		level_snapshot = memorystatus_vm_pressure_level;

		if (level_snapshot == kVMPressureWarning || level_snapshot == kVMPressureUrgent) {

			if (curr_ts < next_warning_notification_sent_at_ts) {
				delay(INTER_NOTIFICATION_DELAY * 4 /* 1 sec */);
				return KERN_SUCCESS;
			}
		} else if (level_snapshot == kVMPressureCritical) {

			if (curr_ts < next_critical_notification_sent_at_ts) {
				delay(INTER_NOTIFICATION_DELAY * 4 /* 1 sec */);
				return KERN_SUCCESS;
			}
		}
	}

	while (1) {
	
		/*
		 * There is a race window here. But it's not clear
		 * how much we benefit from having extra synchronization.
		 */
		level_snapshot = memorystatus_vm_pressure_level;

		if (prev_level_snapshot > level_snapshot) {
			/*
			 * Pressure decreased? Let's take a little breather
			 * and see if this condition stays.
			 */
			if (smoothing_window_started == FALSE) {

				smoothing_window_started = TRUE;
				microuptime(&smoothing_window_start_tstamp);
			}

			microuptime(&curr_tstamp);
			timevalsub(&curr_tstamp, &smoothing_window_start_tstamp);
			elapsed_msecs = curr_tstamp.tv_sec * 1000 + curr_tstamp.tv_usec / 1000;

			if (elapsed_msecs < VM_PRESSURE_DECREASED_SMOOTHING_PERIOD) {
			
				delay(INTER_NOTIFICATION_DELAY);
				continue;
			}
		}

		prev_level_snapshot = level_snapshot;
		smoothing_window_started = FALSE;

		memorystatus_klist_lock();
		kn_max = vm_pressure_select_optimal_candidate_to_notify(&memorystatus_klist, level_snapshot, target_foreground_process);

        	if (kn_max == NULL) {
			memorystatus_klist_unlock();

			/*
			 * No more level-based clients to notify.
			 *
			 * Start the 'resting' window within which clients will not be re-notified.
			 */

			if (level_snapshot != kVMPressureNormal) {
				if (level_snapshot == kVMPressureWarning || level_snapshot == kVMPressureUrgent) {
					nanoseconds_to_absolutetime(WARNING_NOTIFICATION_RESTING_PERIOD * NSEC_PER_SEC, &curr_ts);
					next_warning_notification_sent_at_ts = mach_absolute_time() + curr_ts;

					memorystatus_klist_reset_all_for_level(kVMPressureWarning);
				}

				if (level_snapshot == kVMPressureCritical) {
					nanoseconds_to_absolutetime(CRITICAL_NOTIFICATION_RESTING_PERIOD * NSEC_PER_SEC, &curr_ts);
					next_critical_notification_sent_at_ts = mach_absolute_time() + curr_ts; 

					memorystatus_klist_reset_all_for_level(kVMPressureCritical);
				}
			}
			return KERN_FAILURE;
		}
		
		target_proc = knote_get_kq(kn_max)->kq_p;
		
		proc_list_lock();
		if (target_proc != proc_ref_locked(target_proc)) {
			target_proc = PROC_NULL;
			proc_list_unlock();
			memorystatus_klist_unlock();
			continue;
		}
		proc_list_unlock();
		
		target_pid = target_proc->p_pid;

		task = (struct task *)(target_proc->task);
	
		if (level_snapshot != kVMPressureNormal) {

			if (level_snapshot == kVMPressureWarning || level_snapshot == kVMPressureUrgent) {

				if (is_knote_registered_modify_task_pressure_bits(kn_max, NOTE_MEMORYSTATUS_PRESSURE_WARN, task, 0, kVMPressureWarning) == TRUE) {
					found_candidate = TRUE;
				}
			} else {
				if (level_snapshot == kVMPressureCritical) {
				
					if (is_knote_registered_modify_task_pressure_bits(kn_max, NOTE_MEMORYSTATUS_PRESSURE_CRITICAL, task, 0, kVMPressureCritical) == TRUE) {
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
			proc_rele(target_proc);
			memorystatus_klist_unlock();
			continue;
		}

		SLIST_FOREACH_SAFE(kn_cur, &memorystatus_klist, kn_selnext, kn_temp) {

			int knote_pressure_level = convert_internal_pressure_level_to_dispatch_level(level_snapshot);

			if (is_knote_registered_modify_task_pressure_bits(kn_cur, knote_pressure_level, task, 0, level_snapshot) == TRUE) {
				proc_t knote_proc = knote_get_kq(kn_cur)->kq_p;
				pid_t knote_pid = knote_proc->p_pid;
				if (knote_pid == target_pid) {
					KNOTE_DETACH(&memorystatus_klist, kn_cur);
					KNOTE_ATTACH(&dispatch_klist, kn_cur);
				}
			}
		}

		KNOTE(&dispatch_klist, (level_snapshot != kVMPressureNormal) ? kMemorystatusPressure : kMemorystatusNoPressure);

		SLIST_FOREACH_SAFE(kn_cur, &dispatch_klist, kn_selnext, kn_temp) {
			KNOTE_DETACH(&dispatch_klist, kn_cur);
			KNOTE_ATTACH(&memorystatus_klist, kn_cur);
		}

		memorystatus_klist_unlock();

		microuptime(&target_proc->vm_pressure_last_notify_tstamp);
		proc_rele(target_proc);

		if (memorystatus_manual_testing_on == TRUE && target_foreground_process == TRUE) {
			break;
		}

		if (memorystatus_manual_testing_on == TRUE) {
			/*
			 * Testing out the pressure notification scheme.
			 * No need for delays etc.
			 */
		} else {

			uint32_t sleep_interval = INTER_NOTIFICATION_DELAY;
#if CONFIG_JETSAM
			unsigned int page_delta = 0;
			unsigned int skip_delay_page_threshold = 0;

			assert(memorystatus_available_pages_pressure >= memorystatus_available_pages_critical_base);
			
			page_delta = (memorystatus_available_pages_pressure - memorystatus_available_pages_critical_base) / 2;
			skip_delay_page_threshold = memorystatus_available_pages_pressure - page_delta;

			if (memorystatus_available_pages <= skip_delay_page_threshold) {
				/*
				 * We are nearing the critcal mark fast and can't afford to wait between
				 * notifications.
				 */
				sleep_interval = 0;
			}
#endif /* CONFIG_JETSAM */
				
			if (sleep_interval) {
				delay(sleep_interval);
			}
		}
	}

	return KERN_SUCCESS;
}

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

#if DEBUG || DEVELOPMENT

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_vm_pressure_level, CTLTYPE_INT|CTLFLAG_RD|CTLFLAG_LOCKED,
    0, 0, &sysctl_memorystatus_vm_pressure_level, "I", "");

#else /* DEBUG || DEVELOPMENT */

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_vm_pressure_level, CTLTYPE_INT|CTLFLAG_RD|CTLFLAG_LOCKED|CTLFLAG_MASKED,
    0, 0, &sysctl_memorystatus_vm_pressure_level, "I", "");

#endif /* DEBUG || DEVELOPMENT */

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


#endif /* VM_PRESSURE_EVENTS */

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

		/*
		 * No need to consider P_MEMSTAT_MEMLIMIT_BACKGROUND anymore.
		 * Background limits are described via the inactive limit slots.
		 * So, here, the cached limit should always be valid.
		 */

		if (p->p_memstat_memlimit <= 0) {
                        task_get_phys_footprint_limit(p->task, &list_entry->limit);
                } else {
                        list_entry->limit = p->p_memstat_memlimit;
                }

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

	/*
	 * If there's an entry in the first bucket, we have idle processes.
	 */

	memstat_bucket_t *first_bucket = &memstat_bucket[JETSAM_PRIORITY_IDLE];
	if (first_bucket->count) {
		memorystatus_available_pages_critical += memorystatus_available_pages_critical_idle_offset;

		if (memorystatus_available_pages_critical  > memorystatus_available_pages_pressure ) {
			/* 
			 * The critical threshold must never exceed the pressure threshold
			 */
			memorystatus_available_pages_critical = memorystatus_available_pages_pressure;
		}
	}

#if DEBUG || DEVELOPMENT
	if (memorystatus_jetsam_policy & kPolicyDiagnoseActive) {
		memorystatus_available_pages_critical += memorystatus_jetsam_policy_offset_pages_diagnostic;

		if (memorystatus_available_pages_critical > memorystatus_available_pages_pressure ) {
			/* 
			 * The critical threshold must never exceed the pressure threshold
			 */
			memorystatus_available_pages_critical = memorystatus_available_pages_pressure;
		}
	}
#endif

	if (memorystatus_jetsam_policy & kPolicyMoreFree) {
		memorystatus_available_pages_critical += memorystatus_policy_more_free_offset_pages;
	}

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
sysctl_kern_memorystatus_policy_more_free SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	int error = 0, more_free = 0;

	/*
	 * TODO: Enable this privilege check?
	 *
	 * error = priv_check_cred(kauth_cred_get(), PRIV_VM_JETSAM, 0);
	 * if (error)
	 *	return (error);
	 */

	error = sysctl_handle_int(oidp, &more_free, 0, req);
	if (error || !req->newptr)
		return (error);

	if ((more_free && ((memorystatus_jetsam_policy & kPolicyMoreFree) == kPolicyMoreFree)) ||
	    (!more_free && ((memorystatus_jetsam_policy & kPolicyMoreFree) == 0))) {

		/*
		 * No change in state.
		 */
		return 0;
	}

	proc_list_lock();

	if (more_free) {
		memorystatus_jetsam_policy |= kPolicyMoreFree;
	} else {
		memorystatus_jetsam_policy &= ~kPolicyMoreFree;
	}

	memorystatus_update_levels_locked(TRUE);

	proc_list_unlock();

	return 0;
}
SYSCTL_PROC(_kern, OID_AUTO, memorystatus_policy_more_free, CTLTYPE_INT|CTLFLAG_WR|CTLFLAG_LOCKED|CTLFLAG_MASKED,
    0, 0, &sysctl_kern_memorystatus_policy_more_free, "I", "");

/*
 * Get the at_boot snapshot
 */
static int
memorystatus_get_at_boot_snapshot(memorystatus_jetsam_snapshot_t **snapshot, size_t *snapshot_size, boolean_t size_only) {
	size_t input_size = *snapshot_size;

	/*
	 * The at_boot snapshot has no entry list.
	 */
	*snapshot_size = sizeof(memorystatus_jetsam_snapshot_t);

	if (size_only) {
		return 0;
	}

	/*
	 * Validate the size of the snapshot buffer
	 */
	if (input_size < *snapshot_size) {
		return EINVAL;
	}

	/*
	 * Update the notification_time only
	 */
	memorystatus_at_boot_snapshot.notification_time = mach_absolute_time();
	*snapshot = &memorystatus_at_boot_snapshot;

	MEMORYSTATUS_DEBUG(7, "memorystatus_get_at_boot_snapshot: returned inputsize (%ld), snapshot_size(%ld), listcount(%d)\n",
			   (long)input_size, (long)*snapshot_size, 0);
	return 0;
}

static int
memorystatus_get_on_demand_snapshot(memorystatus_jetsam_snapshot_t **snapshot, size_t *snapshot_size, boolean_t size_only) {
	size_t input_size = *snapshot_size;
	uint32_t ods_list_count = memorystatus_list_count;
	memorystatus_jetsam_snapshot_t *ods = NULL;	/* The on_demand snapshot buffer */

	*snapshot_size = sizeof(memorystatus_jetsam_snapshot_t) + (sizeof(memorystatus_jetsam_snapshot_entry_t) * (ods_list_count));

	if (size_only) {
		return 0;
	}

	/*
	 * Validate the size of the snapshot buffer.
	 * This is inherently racey. May want to revisit
	 * this error condition and trim the output when
	 * it doesn't fit.
	 */
	if (input_size < *snapshot_size) {
		return EINVAL;
	}

	/*
	 * Allocate and initialize a snapshot buffer.
	 */
	ods = (memorystatus_jetsam_snapshot_t *)kalloc(*snapshot_size);
	if (!ods) {
		return (ENOMEM);
	}

	memset(ods, 0, *snapshot_size);

	proc_list_lock();
	memorystatus_init_jetsam_snapshot_locked(ods, ods_list_count);
	proc_list_unlock();

	/*
	 * Return the kernel allocated, on_demand buffer.
	 * The caller of this routine will copy the data out
	 * to user space and then free the kernel allocated
	 * buffer.
	 */
	*snapshot = ods;

	MEMORYSTATUS_DEBUG(7, "memorystatus_get_on_demand_snapshot: returned inputsize (%ld), snapshot_size(%ld), listcount(%ld)\n",
				   (long)input_size, (long)*snapshot_size, (long)ods_list_count);
	
	return 0;
}

static int
memorystatus_get_jetsam_snapshot(memorystatus_jetsam_snapshot_t **snapshot, size_t *snapshot_size, boolean_t size_only) {
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

	MEMORYSTATUS_DEBUG(7, "memorystatus_get_jetsam_snapshot: returned inputsize (%ld), snapshot_size(%ld), listcount(%ld)\n",
				   (long)input_size, (long)*snapshot_size, (long)memorystatus_jetsam_snapshot_count);

	return 0;
}


static int
memorystatus_cmd_get_jetsam_snapshot(int32_t flags, user_addr_t buffer, size_t buffer_size, int32_t *retval) {
	int error = EINVAL;
	boolean_t size_only;
	boolean_t is_default_snapshot = FALSE;
	boolean_t is_on_demand_snapshot = FALSE;
	boolean_t is_at_boot_snapshot = FALSE;
	memorystatus_jetsam_snapshot_t *snapshot;

	size_only = ((buffer == USER_ADDR_NULL) ? TRUE : FALSE);

	if (flags == 0) {
		/* Default */
		is_default_snapshot = TRUE;
		error = memorystatus_get_jetsam_snapshot(&snapshot, &buffer_size, size_only);
	} else {
		if (flags & ~(MEMORYSTATUS_SNAPSHOT_ON_DEMAND | MEMORYSTATUS_SNAPSHOT_AT_BOOT)) {
			/*
			 * Unsupported bit set in flag.
			 */
			return EINVAL;
		}

		if ((flags & (MEMORYSTATUS_SNAPSHOT_ON_DEMAND | MEMORYSTATUS_SNAPSHOT_AT_BOOT)) ==
		    (MEMORYSTATUS_SNAPSHOT_ON_DEMAND |	MEMORYSTATUS_SNAPSHOT_AT_BOOT)) {
			/*
			 * Can't have both set at the same time.
			 */
			return EINVAL;
		}

		if (flags & MEMORYSTATUS_SNAPSHOT_ON_DEMAND) {
			is_on_demand_snapshot = TRUE;
			/*
			 * When not requesting the size only, the following call will allocate
			 * an on_demand snapshot buffer, which is freed below.
			 */
			error = memorystatus_get_on_demand_snapshot(&snapshot, &buffer_size, size_only);

		} else if (flags & MEMORYSTATUS_SNAPSHOT_AT_BOOT) {
			is_at_boot_snapshot = TRUE;
			error = memorystatus_get_at_boot_snapshot(&snapshot, &buffer_size, size_only);
		} else {
			/*
			 * Invalid flag setting.
			 */
			return EINVAL;
		}
	}

	if (error) {
		goto out;
	}

	/*
	 * Copy the data out to user space and clear the snapshot buffer.
	 * If working with the jetsam snapshot,
	 *	clearing the buffer means, reset the count.
	 * If working with an on_demand snapshot
	 *	clearing the buffer means, free it.
	 * If working with the at_boot snapshot
	 *	there is nothing to clear or update.
	 */
	if (!size_only) {
		if ((error = copyout(snapshot, buffer, buffer_size)) == 0) {
			if (is_default_snapshot) {
				/*
				 * The jetsam snapshot is never freed, its count is simply reset.
				 */
				proc_list_lock();
				snapshot->entry_count = memorystatus_jetsam_snapshot_count = 0;
				memorystatus_jetsam_snapshot_last_timestamp = 0;
				proc_list_unlock();
			}
		}

		if (is_on_demand_snapshot) {
			/*
			 * The on_demand snapshot is always freed,
			 * even if the copyout failed.
			 */
			if(snapshot) {
				kfree(snapshot, buffer_size);
			}
		}
	}

	if (error == 0) {
		*retval = buffer_size;
	}
out:
	return error;
}

/*
 * 	Routine:	memorystatus_cmd_grp_set_properties
 *	Purpose:	Update properties for a group of processes.
 *
 *	Supported Properties:
 *	[priority]
 *		Move each process out of its effective priority
 *		band and into a new priority band.
 *		Maintains relative order from lowest to highest priority.
 *		In single band, maintains relative order from head to tail.
 *
 *		eg: before	[effectivepriority | pid]
 *				[18 | p101              ]
 *				[17 | p55, p67, p19     ]
 *				[12 | p103 p10          ]
 *				[ 7 | p25               ]
 *			 	[ 0 | p71, p82,         ]
 *
 *		after	[ new band | pid]
 *			[ xxx | p71, p82, p25, p103, p10, p55, p67, p19, p101]
 *
 *	Returns:  0 on success, else non-zero.
 *
 *	Caveat:   We know there is a race window regarding recycled pids.
 *		  A process could be killed before the kernel can act on it here.
 *		  If a pid cannot be found in any of the jetsam priority bands,
 *		  then we simply ignore it.  No harm.
 *		  But, if the pid has been recycled then it could be an issue.
 *		  In that scenario, we might move an unsuspecting process to the new
 *		  priority band. It's not clear how the kernel can safeguard
 *		  against this, but it would be an extremely rare case anyway.
 *		  The caller of this api might avoid such race conditions by
 *		  ensuring that the processes passed in the pid list are suspended.
 */


/* This internal structure can expand when we add support for more properties */
typedef	struct memorystatus_internal_properties
{
	proc_t proc;
	int32_t priority;  /* see memorytstatus_priority_entry_t : priority */
} memorystatus_internal_properties_t;
	

static int
memorystatus_cmd_grp_set_properties(int32_t flags, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval) {

#pragma unused (flags)

	/*
	 * We only handle setting priority
	 * per process
	 */

	int error = 0;
	memorystatus_priority_entry_t *entries = NULL;
	uint32_t entry_count = 0;

	/* This will be the ordered proc list */
	memorystatus_internal_properties_t *table = NULL;
	size_t table_size = 0;
	uint32_t table_count = 0;

	uint32_t i = 0;
	uint32_t bucket_index = 0;
	boolean_t head_insert;
	int32_t new_priority;
	
	proc_t p;

	/* Verify inputs */
	if ((buffer == USER_ADDR_NULL) || (buffer_size == 0) || ((buffer_size % sizeof(memorystatus_priority_entry_t)) != 0)) {
		error = EINVAL;
		goto out;
	}

	entry_count = (buffer_size / sizeof(memorystatus_priority_entry_t));
	if ((entries = (memorystatus_priority_entry_t *)kalloc(buffer_size)) == NULL) {
		error = ENOMEM;
		goto out;
	}

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_GRP_SET_PROP) | DBG_FUNC_START, entry_count, 0, 0, 0, 0);

	if ((error = copyin(buffer, entries, buffer_size)) != 0) {
		goto out;
	}

	/* Verify sanity of input priorities */
	for (i=0; i < entry_count; i++) {
		if (entries[i].priority == -1) {
			/* Use as shorthand for default priority */
			entries[i].priority = JETSAM_PRIORITY_DEFAULT;
		} else if ((entries[i].priority == system_procs_aging_band) || (entries[i].priority == applications_aging_band)) {
			/* Both the aging bands are reserved for internal use;
			 * if requested, adjust to JETSAM_PRIORITY_IDLE. */
			entries[i].priority = JETSAM_PRIORITY_IDLE;
	        } else if (entries[i].priority == JETSAM_PRIORITY_IDLE_HEAD) {
			/* JETSAM_PRIORITY_IDLE_HEAD inserts at the head of the idle
			 * queue */
			/* Deal with this later */
		} else if ((entries[i].priority < 0) || (entries[i].priority >= MEMSTAT_BUCKET_COUNT)) {
			/* Sanity check */
			error = EINVAL;
			goto out;
		}
	}

	table_size = sizeof(memorystatus_internal_properties_t) * entry_count;
	if ( (table = (memorystatus_internal_properties_t *)kalloc(table_size)) == NULL) {
		error = ENOMEM;
		goto out;
	}
	memset(table, 0, table_size);


	/*
	 * For each jetsam bucket entry, spin through the input property list.
	 * When a matching pid is found, populate an adjacent table with the
	 * appropriate proc pointer and new property values.
	 * This traversal automatically preserves order from lowest
	 * to highest priority.
	 */

	bucket_index=0;
	
	proc_list_lock();

	/* Create the ordered table */
	p = memorystatus_get_first_proc_locked(&bucket_index, TRUE);	
	while (p && (table_count < entry_count)) {
		for (i=0; i < entry_count; i++ ) {
			if (p->p_pid == entries[i].pid) {
				/* Build the table data  */
				table[table_count].proc = p;
				table[table_count].priority = entries[i].priority;
				table_count++;
				break;
			}
		}
		p = memorystatus_get_next_proc_locked(&bucket_index, p, TRUE);
	}
	
	/* We now have ordered list of procs ready to move */
	for (i=0; i < table_count; i++) {
		p = table[i].proc;
		assert(p != NULL);

		/* Allow head inserts -- but relative order is now  */
		if (table[i].priority == JETSAM_PRIORITY_IDLE_HEAD) {
			new_priority = JETSAM_PRIORITY_IDLE;
			head_insert = true;
		} else {
			new_priority = table[i].priority;
			head_insert = false;
		}
		
		/* Not allowed */
		if (p->p_memstat_state & P_MEMSTAT_INTERNAL) {
			continue;
		}

		/*
		 * Take appropriate steps if moving proc out of
		 * either of the aging bands.
		 */
		if ((p->p_memstat_effectivepriority == system_procs_aging_band) || (p->p_memstat_effectivepriority == applications_aging_band)) {
			memorystatus_invalidate_idle_demotion_locked(p, TRUE);
		}

		memorystatus_update_priority_locked(p, new_priority, head_insert, false);
	}

	proc_list_unlock();

	/*
	 * if (table_count != entry_count)
	 * then some pids were not found in a jetsam band.
	 * harmless but interesting...
	 */
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_GRP_SET_PROP) | DBG_FUNC_END, entry_count, table_count, 0, 0, 0);
	
out:
	if (entries)
		kfree(entries, buffer_size);
	if (table)
		kfree(table, table_size);

	return (error);
}


/*
 * This routine is used to update a process's jetsam priority position and stored user_data.
 * It is not used for the setting of memory limits, which is why the last 6 args to the
 * memorystatus_update() call are 0 or FALSE.
 */
	
static int
memorystatus_cmd_set_priority_properties(pid_t pid, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval) {
	int error = 0;
	memorystatus_priority_properties_t mpp_entry;

	/* Validate inputs */
	if ((pid == 0) || (buffer == USER_ADDR_NULL) || (buffer_size != sizeof(memorystatus_priority_properties_t))) {
		return EINVAL;
	}
	
	error = copyin(buffer, &mpp_entry, buffer_size);

	if (error == 0) {
		proc_t p;
                
		p = proc_find(pid);
		if (!p) {
			return ESRCH;
		}
		
		if (p->p_memstat_state & P_MEMSTAT_INTERNAL) {
			proc_rele(p);
			return EPERM;
		}
	
		error = memorystatus_update(p, mpp_entry.priority, mpp_entry.user_data, FALSE, FALSE, 0, 0, FALSE, FALSE, FALSE);
		proc_rele(p);
	}
	
	return(error);
}

static int
memorystatus_cmd_set_memlimit_properties(pid_t pid, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval) {
	int error = 0;
	memorystatus_memlimit_properties_t mmp_entry;

	/* Validate inputs */
	if ((pid == 0) || (buffer == USER_ADDR_NULL) || (buffer_size != sizeof(memorystatus_memlimit_properties_t))) {
		return EINVAL;
	}

	error = copyin(buffer, &mmp_entry, buffer_size);

	if (error == 0) {
		error = memorystatus_set_memlimit_properties(pid, &mmp_entry);
	}

	return(error);
}

/*
 * When getting the memlimit settings, we can't simply call task_get_phys_footprint_limit().
 * That gets the proc's cached memlimit and there is no guarantee that the active/inactive
 * limits will be the same in the no-limit case.  Instead we convert limits <= 0 using
 * task_convert_phys_footprint_limit(). It computes the same limit value that would be written
 * to the task's ledgers via task_set_phys_footprint_limit().
 */
static int
memorystatus_cmd_get_memlimit_properties(pid_t pid, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval) {
	int error = 0;
	memorystatus_memlimit_properties_t mmp_entry;

	/* Validate inputs */
	if ((pid == 0) || (buffer == USER_ADDR_NULL) || (buffer_size != sizeof(memorystatus_memlimit_properties_t))) {
		return EINVAL;
	}

	memset (&mmp_entry, 0, sizeof(memorystatus_memlimit_properties_t));

	proc_t p = proc_find(pid);
	if (!p) {
		return ESRCH;
	}

	/*
	 * Get the active limit and attributes.
	 * No locks taken since we hold a reference to the proc.
	 */

	if (p->p_memstat_memlimit_active > 0 ) {
		mmp_entry.memlimit_active = p->p_memstat_memlimit_active;
	} else {
		task_convert_phys_footprint_limit(-1, &mmp_entry.memlimit_active);
	}

	if (p->p_memstat_state & P_MEMSTAT_MEMLIMIT_ACTIVE_FATAL) {
		mmp_entry.memlimit_active_attr |= MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;
	}

	/*
	 * Get the inactive limit and attributes
	 */
	if (p->p_memstat_memlimit_inactive <= 0) {
		task_convert_phys_footprint_limit(-1, &mmp_entry.memlimit_inactive);
	} else {
		mmp_entry.memlimit_inactive = p->p_memstat_memlimit_inactive;
	}
	if (p->p_memstat_state & P_MEMSTAT_MEMLIMIT_INACTIVE_FATAL) {
		mmp_entry.memlimit_inactive_attr |= MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;
	}
	proc_rele(p);

	error = copyout(&mmp_entry, buffer, buffer_size);

	return(error);
}


/*
 * SPI for kbd - pr24956468
 * This is a very simple snapshot that calculates how much a
 * process's phys_footprint exceeds a specific memory limit.
 * Only the inactive memory limit is supported for now.
 * The delta is returned as bytes in excess or zero.
 */
static int
memorystatus_cmd_get_memlimit_excess_np(pid_t pid, uint32_t flags, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval) {
	int error = 0;
	uint64_t footprint_in_bytes = 0;
	uint64_t delta_in_bytes = 0;
	int32_t  memlimit_mb = 0;
	uint64_t memlimit_bytes = 0;

	/* Validate inputs */
	if ((pid == 0) || (buffer == USER_ADDR_NULL) || (buffer_size != sizeof(uint64_t)) || (flags != 0)) {
		    return EINVAL;
	}

	proc_t p = proc_find(pid);
	if (!p) {
		return ESRCH;
	}

	/*
	 * Get the inactive limit.
	 * No locks taken since we hold a reference to the proc.
	 */

	if (p->p_memstat_memlimit_inactive <= 0) {
		task_convert_phys_footprint_limit(-1, &memlimit_mb);
	} else {
		memlimit_mb = p->p_memstat_memlimit_inactive;
	}

	footprint_in_bytes = get_task_phys_footprint(p->task);

	proc_rele(p);

	memlimit_bytes = memlimit_mb * 1024 * 1024;	/* MB to bytes */

	/*
	 * Computed delta always returns >= 0 bytes
	 */
	if (footprint_in_bytes > memlimit_bytes) {
		delta_in_bytes = footprint_in_bytes - memlimit_bytes;
	}

	error = copyout(&delta_in_bytes, buffer, sizeof(delta_in_bytes));

	return(error);
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

int
memorystatus_get_pressure_status_kdp() {
	return (kVMPressureNormal != memorystatus_vm_pressure_level) ? 1 : 0;
}

/*
 * Every process, including a P_MEMSTAT_INTERNAL process (currently only pid 1), is allowed to set a HWM.
 *
 * This call is inflexible -- it does not distinguish between active/inactive, fatal/non-fatal
 * So, with 2-level HWM preserving previous behavior will map as follows.
 *      - treat the limit passed in as both an active and inactive limit.
 *      - treat the is_fatal_limit flag as though it applies to both active and inactive limits.
 *
 * When invoked via MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK
 *      - the is_fatal_limit is FALSE, meaning the active and inactive limits are non-fatal/soft
 *      - so mapping is (active/non-fatal, inactive/non-fatal)
 *
 * When invoked via MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT
 *      - the is_fatal_limit is TRUE, meaning the process's active and inactive limits are fatal/hard
 *      - so mapping is (active/fatal, inactive/fatal)
 */

static int
memorystatus_cmd_set_jetsam_memory_limit(pid_t pid, int32_t high_water_mark, __unused int32_t *retval, boolean_t is_fatal_limit) {
	int error = 0;
	memorystatus_memlimit_properties_t entry;

	entry.memlimit_active = high_water_mark;
	entry.memlimit_active_attr = 0;
	entry.memlimit_inactive = high_water_mark;
	entry.memlimit_inactive_attr = 0;

	if (is_fatal_limit == TRUE) {
		entry.memlimit_active_attr   |= MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;
		entry.memlimit_inactive_attr |= MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;
	}

	error = memorystatus_set_memlimit_properties(pid, &entry);
	return (error);
}

static int
memorystatus_set_memlimit_properties(pid_t pid, memorystatus_memlimit_properties_t *entry) {

	int32_t  memlimit_active;
	boolean_t memlimit_active_is_fatal;
	int32_t  memlimit_inactive;
	boolean_t memlimit_inactive_is_fatal;
	uint32_t valid_attrs = 0;
	int       error = 0;
        
	proc_t p = proc_find(pid);
	if (!p) {
		return ESRCH;
	}

	/*
	 * Check for valid attribute flags.
	 */
	valid_attrs |= (MEMORYSTATUS_MEMLIMIT_ATTR_FATAL);
	if ((entry->memlimit_active_attr & (~valid_attrs)) != 0) {
		proc_rele(p);
		return EINVAL;
	}
	if ((entry->memlimit_inactive_attr & (~valid_attrs)) != 0) {
		proc_rele(p);
		return EINVAL;
	}

	/*
	 * Setup the active memlimit properties
	 */
	memlimit_active = entry->memlimit_active;
	if (entry->memlimit_active_attr & MEMORYSTATUS_MEMLIMIT_ATTR_FATAL) {
		memlimit_active_is_fatal = TRUE;
	} else {
		memlimit_active_is_fatal = FALSE;
	}

	/*
	 * Setup the inactive memlimit properties
	 */
	memlimit_inactive = entry->memlimit_inactive;
	if (entry->memlimit_inactive_attr & MEMORYSTATUS_MEMLIMIT_ATTR_FATAL) {
		memlimit_inactive_is_fatal = TRUE;
	} else {
		memlimit_inactive_is_fatal = FALSE;
	}

	/*
	 * Setting a limit of <= 0 implies that the process has no
	 * high-water-mark and has no per-task-limit.  That means
	 * the system_wide task limit is in place, which by the way,
	 * is always fatal.
	 */

	if (memlimit_active <= 0) {
		/*
		 * Enforce the fatal system_wide task limit while process is active.
		 */
		memlimit_active = -1;
		memlimit_active_is_fatal = TRUE;
	}

	if (memlimit_inactive <= 0) {
		/*
		 * Enforce the fatal system_wide task limit while process is inactive.
		 */
		memlimit_inactive = -1;
		memlimit_inactive_is_fatal = TRUE;
	}

	proc_list_lock();

	/*
	 * Store the active limit variants in the proc.
	 */
	SET_ACTIVE_LIMITS_LOCKED(p, memlimit_active, memlimit_active_is_fatal);

	/*
	 * Store the inactive limit variants in the proc.
	 */
	SET_INACTIVE_LIMITS_LOCKED(p, memlimit_inactive, memlimit_inactive_is_fatal);

	/*
	 * Enforce appropriate limit variant by updating the cached values
	 * and writing the ledger.
	 * Limit choice is based on process active/inactive state.
	 */

	if (memorystatus_highwater_enabled) {
		boolean_t trigger_exception;
		/*
		 * No need to consider P_MEMSTAT_MEMLIMIT_BACKGROUND anymore.
		 * Background limits are described via the inactive limit slots.
		 */

		if (proc_jetsam_state_is_active_locked(p) == TRUE) {
			CACHE_ACTIVE_LIMITS_LOCKED(p, trigger_exception);
		} else {
			CACHE_INACTIVE_LIMITS_LOCKED(p, trigger_exception);
		}

		/* Enforce the limit by writing to the ledgers */
		assert(trigger_exception == TRUE);
		error = (task_set_phys_footprint_limit_internal(p->task, ((p->p_memstat_memlimit > 0) ? p->p_memstat_memlimit : -1), NULL, trigger_exception) == 0) ? 0 : EINVAL;

		MEMORYSTATUS_DEBUG(3, "memorystatus_set_memlimit_properties: new limit on pid %d (%dMB %s) current priority (%d) dirty_state?=0x%x %s\n",
				   p->p_pid, (p->p_memstat_memlimit > 0 ? p->p_memstat_memlimit : -1),
				   (p->p_memstat_state & P_MEMSTAT_FATAL_MEMLIMIT ? "F " : "NF"), p->p_memstat_effectivepriority, p->p_memstat_dirty,
				   (p->p_memstat_dirty ? ((p->p_memstat_dirty & P_DIRTY) ? "isdirty" : "isclean") : ""));
		DTRACE_MEMORYSTATUS2(memorystatus_set_memlimit, proc_t, p, int32_t, (p->p_memstat_memlimit > 0 ? p->p_memstat_memlimit : -1));
	}

	proc_list_unlock();
	proc_rele(p);
	
	return error;
}

/*
 * Returns the jetsam priority (effective or requested) of the process
 * associated with this task.
 */
int
proc_get_memstat_priority(proc_t p, boolean_t effective_priority)
{
	if (p) {
		if (effective_priority) {
			return p->p_memstat_effectivepriority;
		} else {
			return p->p_memstat_requestedpriority;
		}
	}
	return 0;
}

#endif /* CONFIG_JETSAM */

int
memorystatus_control(struct proc *p __unused, struct memorystatus_control_args *args, int *ret) {
	int error = EINVAL;
	os_reason_t jetsam_reason = OS_REASON_NULL;

#if !CONFIG_JETSAM
	#pragma unused(ret)
	#pragma unused(jetsam_reason)
#endif

	/* Need to be root or have entitlement */
	if (!kauth_cred_issuser(kauth_cred_get()) && !IOTaskHasEntitlement(current_task(), MEMORYSTATUS_ENTITLEMENT)) {
		error = EPERM;
		goto out;
	}

	/*
	 * Sanity check.
	 * Do not enforce it for snapshots.
	 */
	if (args->command != MEMORYSTATUS_CMD_GET_JETSAM_SNAPSHOT) {
		if (args->buffersize > MEMORYSTATUS_BUFFERSIZE_MAX) {
			error = EINVAL;
			goto out;
		}
	}

	switch (args->command) {
	case MEMORYSTATUS_CMD_GET_PRIORITY_LIST:
		error = memorystatus_cmd_get_priority_list(args->buffer, args->buffersize, ret);
		break;
#if CONFIG_JETSAM
	case MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES:
		error = memorystatus_cmd_set_priority_properties(args->pid, args->buffer, args->buffersize, ret);
		break;
	case MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES:
		error = memorystatus_cmd_set_memlimit_properties(args->pid, args->buffer, args->buffersize, ret);
		break;
	case MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES:
		error = memorystatus_cmd_get_memlimit_properties(args->pid, args->buffer, args->buffersize, ret);
		break;
	case MEMORYSTATUS_CMD_GET_MEMLIMIT_EXCESS:
		error = memorystatus_cmd_get_memlimit_excess_np(args->pid, args->flags, args->buffer, args->buffersize, ret);
		break;
	case MEMORYSTATUS_CMD_GRP_SET_PROPERTIES:
		error = memorystatus_cmd_grp_set_properties((int32_t)args->flags, args->buffer, args->buffersize, ret);
		break;		
	case MEMORYSTATUS_CMD_GET_JETSAM_SNAPSHOT:
		error = memorystatus_cmd_get_jetsam_snapshot((int32_t)args->flags, args->buffer, args->buffersize, ret);
		break;
	case MEMORYSTATUS_CMD_GET_PRESSURE_STATUS:
		error = memorystatus_cmd_get_pressure_status(ret);
		break;
	case MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK:
		/*
		 * This call does not distinguish between active and inactive limits.
		 * Default behavior in 2-level HWM world is to set both.
		 * Non-fatal limit is also assumed for both.
		 */
		error = memorystatus_cmd_set_jetsam_memory_limit(args->pid, (int32_t)args->flags, ret, FALSE);
		break;
	case MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT:
		/*
		 * This call does not distinguish between active and inactive limits.
		 * Default behavior in 2-level HWM world is to set both.
		 * Fatal limit is also assumed for both.
		 */
		error = memorystatus_cmd_set_jetsam_memory_limit(args->pid, (int32_t)args->flags, ret, TRUE);
		break;
	/* Test commands */
#if DEVELOPMENT || DEBUG
	case MEMORYSTATUS_CMD_TEST_JETSAM:
		jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_GENERIC);
		if (jetsam_reason == OS_REASON_NULL) {
			printf("memorystatus_control: failed to allocate jetsam reason\n");
		}

		error = memorystatus_kill_process_sync(args->pid, kMemorystatusKilled, jetsam_reason) ? 0 : EINVAL;
		break;
	case MEMORYSTATUS_CMD_TEST_JETSAM_SORT:
		error = memorystatus_cmd_test_jetsam_sort(args->pid, (int32_t)args->flags);
		break;
	case MEMORYSTATUS_CMD_SET_JETSAM_PANIC_BITS:
		error = memorystatus_cmd_set_panic_bits(args->buffer, args->buffersize);
		break;
#else /* DEVELOPMENT || DEBUG */
	#pragma unused(jetsam_reason)
#endif /* DEVELOPMENT || DEBUG */
	case MEMORYSTATUS_CMD_AGGRESSIVE_JETSAM_LENIENT_MODE_ENABLE:
		if (memorystatus_aggressive_jetsam_lenient_allowed == FALSE) {
#if DEVELOPMENT || DEBUG
			printf("Enabling Lenient Mode\n");
#endif /* DEVELOPMENT || DEBUG */

			memorystatus_aggressive_jetsam_lenient_allowed = TRUE;
			memorystatus_aggressive_jetsam_lenient = TRUE;
			error = 0;
		}
		break;
	case MEMORYSTATUS_CMD_AGGRESSIVE_JETSAM_LENIENT_MODE_DISABLE:
#if DEVELOPMENT || DEBUG
		printf("Disabling Lenient mode\n");
#endif /* DEVELOPMENT || DEBUG */
		memorystatus_aggressive_jetsam_lenient_allowed = FALSE;
		memorystatus_aggressive_jetsam_lenient = FALSE;
		error = 0;
		break;
#endif /* CONFIG_JETSAM */
	case MEMORYSTATUS_CMD_PRIVILEGED_LISTENER_ENABLE:
	case MEMORYSTATUS_CMD_PRIVILEGED_LISTENER_DISABLE:
		error = memorystatus_low_mem_privileged_listener(args->command);
		break;

#if CONFIG_JETSAM
	case MEMORYSTATUS_CMD_ELEVATED_INACTIVEJETSAMPRIORITY_ENABLE:
	case MEMORYSTATUS_CMD_ELEVATED_INACTIVEJETSAMPRIORITY_DISABLE:
		error = memorystatus_update_inactive_jetsam_priority_band(args->pid, args->command, args->flags ? TRUE : FALSE);
		break;
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
	int error;

	kn->kn_flags |= EV_CLEAR;
	error = memorystatus_knote_register(kn);
	if (error) {
		kn->kn_flags = EV_ERROR;
		kn->kn_data = error;
	}
	return 0;
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
				kn->kn_fflags = NOTE_MEMORYSTATUS_PRESSURE_NORMAL;
			}
			break;
		case kMemorystatusPressure:
			if (memorystatus_vm_pressure_level == kVMPressureWarning || memorystatus_vm_pressure_level == kVMPressureUrgent) {
				if (kn->kn_sfflags & NOTE_MEMORYSTATUS_PRESSURE_WARN) {
					kn->kn_fflags = NOTE_MEMORYSTATUS_PRESSURE_WARN;
				}
			} else if (memorystatus_vm_pressure_level == kVMPressureCritical) {

				if (kn->kn_sfflags & NOTE_MEMORYSTATUS_PRESSURE_CRITICAL) {
					kn->kn_fflags = NOTE_MEMORYSTATUS_PRESSURE_CRITICAL;
				}
			}
			break;
		case kMemorystatusLowSwap:
			if (kn->kn_sfflags & NOTE_MEMORYSTATUS_LOW_SWAP) {
				kn->kn_fflags = NOTE_MEMORYSTATUS_LOW_SWAP;
			}
			break;

		case kMemorystatusProcLimitWarn:
			if (kn->kn_sfflags & NOTE_MEMORYSTATUS_PROC_LIMIT_WARN) {
                                kn->kn_fflags = NOTE_MEMORYSTATUS_PROC_LIMIT_WARN;
                        }
                        break;

		case kMemorystatusProcLimitCritical:
			if (kn->kn_sfflags & NOTE_MEMORYSTATUS_PROC_LIMIT_CRITICAL) {
                                kn->kn_fflags = NOTE_MEMORYSTATUS_PROC_LIMIT_CRITICAL;
                        }
                        break;

		default:
			break;
		}
	}
	
	return (kn->kn_fflags != 0);
}

static int
filt_memorystatustouch(struct knote *kn, struct kevent_internal_s *kev)
{
	int res;

	memorystatus_klist_lock();

	/*
	 * copy in new kevent settings
	 * (saving the "desired" data and fflags).
	 */
	kn->kn_sfflags = kev->fflags;

	if ((kn->kn_status & KN_UDATA_SPECIFIC) == 0)
		kn->kn_udata = kev->udata;

	/*
	 * reset the output flags based on a
	 * combination of the old events and
	 * the new desired event list.
	 */
	//kn->kn_fflags &= kn->kn_sfflags;

	res = (kn->kn_fflags != 0);

	memorystatus_klist_unlock();

	return res;
}

static int
filt_memorystatusprocess(struct knote *kn, struct filt_process_s *data, struct kevent_internal_s *kev)
{
#pragma unused(data)
	int res;

	memorystatus_klist_lock();
	res = (kn->kn_fflags != 0);
	if (res) {
		*kev = kn->kn_kevent;
		kn->kn_flags |= EV_CLEAR; /* automatic */
		kn->kn_fflags = 0;
		kn->kn_data = 0;
	}
	memorystatus_klist_unlock();

	return res;
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
	
	if (kn->kn_sfflags & (NOTE_MEMORYSTATUS_PRESSURE_NORMAL | NOTE_MEMORYSTATUS_PRESSURE_WARN |
			      NOTE_MEMORYSTATUS_PRESSURE_CRITICAL | NOTE_MEMORYSTATUS_LOW_SWAP |
			      NOTE_MEMORYSTATUS_PROC_LIMIT_WARN | NOTE_MEMORYSTATUS_PROC_LIMIT_CRITICAL)) {

		KNOTE_ATTACH(&memorystatus_klist, kn);

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


#if 0
#if CONFIG_JETSAM && VM_PRESSURE_EVENTS
static boolean_t
memorystatus_issue_pressure_kevent(boolean_t pressured) {
	memorystatus_klist_lock();
	KNOTE(&memorystatus_klist, pressured ? kMemorystatusPressure : kMemorystatusNoPressure);
	memorystatus_klist_unlock();
	return TRUE;
}
#endif /* CONFIG_JETSAM && VM_PRESSURE_EVENTS */
#endif /* 0 */

#if CONFIG_JETSAM
/* Coalition support */

/* sorting info for a particular priority bucket */
typedef struct memstat_sort_info {
	coalition_t	msi_coal;
	uint64_t	msi_page_count;
	pid_t		msi_pid;
	int		msi_ntasks;
} memstat_sort_info_t;

/* 
 * qsort from smallest page count to largest page count
 *
 * return < 0 for a < b
 *          0 for a == b
 *        > 0 for a > b
 */
static int memstat_asc_cmp(const void *a, const void *b)
{
        const memstat_sort_info_t *msA = (const memstat_sort_info_t *)a;
        const memstat_sort_info_t *msB = (const memstat_sort_info_t *)b;

        return (int)((uint64_t)msA->msi_page_count - (uint64_t)msB->msi_page_count);
}

/*
 * Return the number of pids rearranged during this sort.
 */
static int
memorystatus_sort_by_largest_coalition_locked(unsigned int bucket_index, int coal_sort_order)
{
#define MAX_SORT_PIDS		80
#define MAX_COAL_LEADERS 	10

	unsigned int b = bucket_index;
	int nleaders = 0;
	int ntasks = 0;
	proc_t p = NULL;
	coalition_t coal = COALITION_NULL;
	int pids_moved = 0;
	int total_pids_moved = 0;
	int i;

	/* 
	 * The system is typically under memory pressure when in this
	 * path, hence, we want to avoid dynamic memory allocation.
	 */
	memstat_sort_info_t leaders[MAX_COAL_LEADERS];
	pid_t pid_list[MAX_SORT_PIDS];

	if (bucket_index >= MEMSTAT_BUCKET_COUNT) {
                return(0);
        }

	/*
	 * Clear the array that holds coalition leader information
	 */
	for (i=0; i < MAX_COAL_LEADERS; i++) {
		leaders[i].msi_coal = COALITION_NULL;
		leaders[i].msi_page_count = 0;		/* will hold total coalition page count */
		leaders[i].msi_pid = 0;			/* will hold coalition leader pid */
		leaders[i].msi_ntasks = 0;		/* will hold the number of tasks in a coalition */
	}

        p = memorystatus_get_first_proc_locked(&b, FALSE);
        while (p) {
                if (coalition_is_leader(p->task, COALITION_TYPE_JETSAM, &coal)) {
			if (nleaders < MAX_COAL_LEADERS) {
				int coal_ntasks = 0;
				uint64_t coal_page_count = coalition_get_page_count(coal, &coal_ntasks);
				leaders[nleaders].msi_coal = coal;
				leaders[nleaders].msi_page_count = coal_page_count;
				leaders[nleaders].msi_pid = p->p_pid;    	/* the coalition leader */
				leaders[nleaders].msi_ntasks = coal_ntasks;
				nleaders++;
			} else {
				/* 
				 * We've hit MAX_COAL_LEADERS meaning we can handle no more coalitions.
				 * Abandoned coalitions will linger at the tail of the priority band 
				 * when this sort session ends.
				 * TODO:  should this be an assert?
				 */
				printf("%s: WARNING: more than %d leaders in priority band [%d]\n",
				       __FUNCTION__, MAX_COAL_LEADERS, bucket_index);
				break;
			}
                }
                p=memorystatus_get_next_proc_locked(&b, p, FALSE);
        }

	if (nleaders == 0) {
		/* Nothing to sort */
		return(0);
	}

	/* 
	 * Sort the coalition leader array, from smallest coalition page count
	 * to largest coalition page count.  When inserted in the priority bucket,
	 * smallest coalition is handled first, resulting in the last to be jetsammed.
	 */
	if (nleaders > 1) {
		qsort(leaders, nleaders, sizeof(memstat_sort_info_t), memstat_asc_cmp);
	}

#if 0
	for (i = 0; i < nleaders; i++) {
		printf("%s: coal_leader[%d of %d] pid[%d] pages[%llu] ntasks[%d]\n",
		       __FUNCTION__, i, nleaders, leaders[i].msi_pid, leaders[i].msi_page_count,
			leaders[i].msi_ntasks);
	}
#endif

	/*
	 * During coalition sorting, processes in a priority band are rearranged
	 * by being re-inserted at the head of the queue.  So, when handling a
	 * list, the first process that gets moved to the head of the queue,
	 * ultimately gets pushed toward the queue tail, and hence, jetsams last.
	 *
	 * So, for example, the coalition leader is expected to jetsam last,
	 * after its coalition members.  Therefore, the coalition leader is
	 * inserted at the head of the queue first.
	 *
	 * After processing a coalition, the jetsam order is as follows:
	 *   undefs(jetsam first), extensions, xpc services, leader(jetsam last)
	 */

	/*
	 * Coalition members are rearranged in the priority bucket here,
	 * based on their coalition role.
	 */
	total_pids_moved = 0;
	for (i=0; i < nleaders; i++) {
		
		/* a bit of bookkeeping */
		pids_moved = 0;

		/* Coalition leaders are jetsammed last, so move into place first */
		pid_list[0] = leaders[i].msi_pid;
		pids_moved += memorystatus_move_list_locked(bucket_index, pid_list, 1);

		/* xpc services should jetsam after extensions */
		ntasks = coalition_get_pid_list (leaders[i].msi_coal, COALITION_ROLEMASK_XPC,
						 coal_sort_order, pid_list, MAX_SORT_PIDS);

		if (ntasks > 0) {
			pids_moved += memorystatus_move_list_locked(bucket_index, pid_list, 
								    (ntasks <= MAX_SORT_PIDS ? ntasks : MAX_SORT_PIDS));
		}

		/* extensions should jetsam after unmarked processes */
		ntasks = coalition_get_pid_list (leaders[i].msi_coal, COALITION_ROLEMASK_EXT,
						 coal_sort_order, pid_list, MAX_SORT_PIDS);

		if (ntasks > 0) {
			pids_moved += memorystatus_move_list_locked(bucket_index, pid_list,
								    (ntasks <= MAX_SORT_PIDS ? ntasks : MAX_SORT_PIDS));
		}

		/* undefined coalition members should be the first to jetsam */
		ntasks = coalition_get_pid_list (leaders[i].msi_coal, COALITION_ROLEMASK_UNDEF,
						 coal_sort_order, pid_list, MAX_SORT_PIDS);

		if (ntasks > 0) {
			pids_moved += memorystatus_move_list_locked(bucket_index, pid_list, 
								    (ntasks <= MAX_SORT_PIDS ? ntasks : MAX_SORT_PIDS));
		}

#if 0
		if (pids_moved == leaders[i].msi_ntasks) {
			/*
			 * All the pids in the coalition were found in this band.
			 */
			printf("%s: pids_moved[%d]  equal  total coalition ntasks[%d] \n", __FUNCTION__,
			       pids_moved, leaders[i].msi_ntasks);
		} else if (pids_moved > leaders[i].msi_ntasks) {
			/*
			 * Apparently new coalition members showed up during the sort?
			 */
			printf("%s: pids_moved[%d] were greater than expected coalition ntasks[%d] \n", __FUNCTION__,
			       pids_moved, leaders[i].msi_ntasks);
		} else {
			/*
			 * Apparently not all the pids in the coalition were found in this band?
			 */
			printf("%s: pids_moved[%d] were less than  expected coalition ntasks[%d] \n", __FUNCTION__,
			       pids_moved, leaders[i].msi_ntasks);
		}
#endif

		total_pids_moved += pids_moved;

	} /* end for */

	return(total_pids_moved);
}


/*
 * Traverse a list of pids, searching for each within the priority band provided.
 * If pid is found, move it to the front of the priority band.
 * Never searches outside the priority band provided.
 * 
 * Input:
 *	bucket_index - jetsam priority band.
 *	pid_list - pointer to a list of pids.
 *	list_sz  - number of pids in the list.
 *
 * Pid list ordering is important in that, 
 * pid_list[n] is expected to jetsam ahead of pid_list[n+1].
 * The sort_order is set by the coalition default.
 *
 * Return: 
 *	the number of pids found and hence moved within the priority band.
 */
static int
memorystatus_move_list_locked(unsigned int bucket_index, pid_t *pid_list, int list_sz)
{
	memstat_bucket_t *current_bucket;
	int i;
	int found_pids = 0;

	if ((pid_list == NULL) || (list_sz <= 0)) {
		return(0);
	}

	if (bucket_index >= MEMSTAT_BUCKET_COUNT) {
                return(0);
        }

	current_bucket = &memstat_bucket[bucket_index];
	for (i=0; i < list_sz; i++) {
		unsigned int b = bucket_index;
		proc_t p = NULL;
		proc_t aProc = NULL;
		pid_t  aPid;
		int list_index;

		list_index = ((list_sz - 1) - i);
                aPid = pid_list[list_index];

                /* never search beyond bucket_index provided */
                p = memorystatus_get_first_proc_locked(&b, FALSE);
                while (p) {
                        if (p->p_pid == aPid) {
                                aProc = p;
                                break;
                        }
                        p = memorystatus_get_next_proc_locked(&b, p, FALSE);
                }

                if (aProc == NULL) {
			/* pid not found in this band, just skip it */
                        continue;
                } else {
                        TAILQ_REMOVE(&current_bucket->list, aProc, p_memstat_list);
                        TAILQ_INSERT_HEAD(&current_bucket->list, aProc, p_memstat_list);
			found_pids++;
                }
        }
	return(found_pids);
}
#endif  /* CONFIG_JETSAM */

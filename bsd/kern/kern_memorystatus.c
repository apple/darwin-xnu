/*
 * Copyright (c) 2006-2019 Apple Inc. All rights reserved.
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
#include <kern/thread_group.h>

#include <IOKit/IOBSD.h>

#include <corpses/task_corpse.h>
#include <libkern/libkern.h>
#include <mach/coalition.h>
#include <mach/mach_time.h>
#include <mach/task.h>
#include <mach/host_priv.h>
#include <mach/mach_host.h>
#include <os/log.h>
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
#include <mach/machine/sdt.h>
#include <libkern/section_keywords.h>
#include <stdatomic.h>

#if CONFIG_FREEZE
#include <vm/vm_map.h>
#endif /* CONFIG_FREEZE */

#include <sys/kern_memorystatus.h>
#include <sys/kern_memorystatus_freeze.h>
#include <sys/kern_memorystatus_notify.h>

/* For logging clarity */
static const char *memorystatus_kill_cause_name[] = {
	"",                                                                             /* kMemorystatusInvalid							*/
	"jettisoned",                                                   /* kMemorystatusKilled							*/
	"highwater",                                                            /* kMemorystatusKilledHiwat						*/
	"vnode-limit",                                                  /* kMemorystatusKilledVnodes					*/
	"vm-pageshortage",                                              /* kMemorystatusKilledVMPageShortage			*/
	"proc-thrashing",                                               /* kMemorystatusKilledProcThrashing				*/
	"fc-thrashing",                                                 /* kMemorystatusKilledFCThrashing				*/
	"per-process-limit",                                            /* kMemorystatusKilledPerProcessLimit			*/
	"disk-space-shortage",                                  /* kMemorystatusKilledDiskSpaceShortage			*/
	"idle-exit",                                                            /* kMemorystatusKilledIdleExit					*/
	"zone-map-exhaustion",                                  /* kMemorystatusKilledZoneMapExhaustion			*/
	"vm-compressor-thrashing",                              /* kMemorystatusKilledVMCompressorThrashing		*/
	"vm-compressor-space-shortage",                 /* kMemorystatusKilledVMCompressorSpaceShortage	*/
};

static const char *
memorystatus_priority_band_name(int32_t priority)
{
	switch (priority) {
	case JETSAM_PRIORITY_FOREGROUND:
		return "FOREGROUND";
	case JETSAM_PRIORITY_AUDIO_AND_ACCESSORY:
		return "AUDIO_AND_ACCESSORY";
	case JETSAM_PRIORITY_CONDUCTOR:
		return "CONDUCTOR";
	case JETSAM_PRIORITY_DRIVER_APPLE:
		return "DRIVER_APPLE";
	case JETSAM_PRIORITY_HOME:
		return "HOME";
	case JETSAM_PRIORITY_EXECUTIVE:
		return "EXECUTIVE";
	case JETSAM_PRIORITY_IMPORTANT:
		return "IMPORTANT";
	case JETSAM_PRIORITY_CRITICAL:
		return "CRITICAL";
	}

	return "?";
}

/* Does cause indicate vm or fc thrashing? */
static boolean_t
is_reason_thrashing(unsigned cause)
{
	switch (cause) {
	case kMemorystatusKilledFCThrashing:
	case kMemorystatusKilledVMCompressorThrashing:
	case kMemorystatusKilledVMCompressorSpaceShortage:
		return TRUE;
	default:
		return FALSE;
	}
}

/* Is the zone map almost full? */
static boolean_t
is_reason_zone_map_exhaustion(unsigned cause)
{
	if (cause == kMemorystatusKilledZoneMapExhaustion) {
		return TRUE;
	}
	return FALSE;
}

/*
 * Returns the current zone map size and capacity to include in the jetsam snapshot.
 * Defined in zalloc.c
 */
extern void get_zone_map_size(uint64_t *current_size, uint64_t *capacity);

/*
 * Returns the name of the largest zone and its size to include in the jetsam snapshot.
 * Defined in zalloc.c
 */
extern void get_largest_zone_info(char *zone_name, size_t zone_name_len, uint64_t *zone_size);

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

#define SET_ACTIVE_LIMITS_LOCKED(p, limit, is_fatal)                    \
MACRO_BEGIN                                                             \
(p)->p_memstat_memlimit_active = (limit);                               \
   if (is_fatal) {                                                      \
	   (p)->p_memstat_state |= P_MEMSTAT_MEMLIMIT_ACTIVE_FATAL;     \
   } else {                                                             \
	   (p)->p_memstat_state &= ~P_MEMSTAT_MEMLIMIT_ACTIVE_FATAL;    \
   }                                                                    \
MACRO_END

#define SET_INACTIVE_LIMITS_LOCKED(p, limit, is_fatal)                  \
MACRO_BEGIN                                                             \
(p)->p_memstat_memlimit_inactive = (limit);                             \
   if (is_fatal) {                                                      \
	   (p)->p_memstat_state |= P_MEMSTAT_MEMLIMIT_INACTIVE_FATAL;   \
   } else {                                                             \
	   (p)->p_memstat_state &= ~P_MEMSTAT_MEMLIMIT_INACTIVE_FATAL;  \
   }                                                                    \
MACRO_END

#define CACHE_ACTIVE_LIMITS_LOCKED(p, is_fatal)                         \
MACRO_BEGIN                                                             \
(p)->p_memstat_memlimit = (p)->p_memstat_memlimit_active;               \
   if ((p)->p_memstat_state & P_MEMSTAT_MEMLIMIT_ACTIVE_FATAL) {        \
	   (p)->p_memstat_state |= P_MEMSTAT_FATAL_MEMLIMIT;            \
	   is_fatal = TRUE;                                             \
   } else {                                                             \
	   (p)->p_memstat_state &= ~P_MEMSTAT_FATAL_MEMLIMIT;           \
	   is_fatal = FALSE;                                            \
   }                                                                    \
MACRO_END

#define CACHE_INACTIVE_LIMITS_LOCKED(p, is_fatal)                       \
MACRO_BEGIN                                                             \
(p)->p_memstat_memlimit = (p)->p_memstat_memlimit_inactive;             \
   if ((p)->p_memstat_state & P_MEMSTAT_MEMLIMIT_INACTIVE_FATAL) {      \
	   (p)->p_memstat_state |= P_MEMSTAT_FATAL_MEMLIMIT;            \
	   is_fatal = TRUE;                                             \
   } else {                                                             \
	   (p)->p_memstat_state &= ~P_MEMSTAT_FATAL_MEMLIMIT;           \
	   is_fatal = FALSE;                                            \
   }                                                                    \
MACRO_END


/* General tunables */

unsigned long delta_percentage = 5;
unsigned long critical_threshold_percentage = 5;
// On embedded devices with more than 3GB of memory we lower the critical percentage.
uint64_t config_jetsam_large_memory_cutoff = 3UL * (1UL << 30);
unsigned long critical_threshold_percentage_larger_devices = 4;
unsigned long delta_percentage_larger_devices = 4;
unsigned long idle_offset_percentage = 5;
unsigned long pressure_threshold_percentage = 15;
unsigned long policy_more_free_offset_percentage = 5;
unsigned long sysproc_aging_aggr_threshold_percentage = 7;

/*
 * default jetsam snapshot support
 */
memorystatus_jetsam_snapshot_t *memorystatus_jetsam_snapshot;
memorystatus_jetsam_snapshot_t *memorystatus_jetsam_snapshot_copy;
unsigned int memorystatus_jetsam_snapshot_count = 0;
unsigned int memorystatus_jetsam_snapshot_copy_count = 0;
unsigned int memorystatus_jetsam_snapshot_max = 0;
unsigned int memorystatus_jetsam_snapshot_size = 0;
uint64_t memorystatus_jetsam_snapshot_last_timestamp = 0;
uint64_t memorystatus_jetsam_snapshot_timeout = 0;

/* General memorystatus stuff */

uint64_t memorystatus_sysprocs_idle_delay_time = 0;
uint64_t memorystatus_apps_idle_delay_time = 0;

static lck_grp_attr_t *memorystatus_jetsam_fg_band_lock_grp_attr;
static lck_grp_t *memorystatus_jetsam_fg_band_lock_grp;
lck_mtx_t memorystatus_jetsam_fg_band_lock;

/* Idle guard handling */

static int32_t memorystatus_scheduled_idle_demotions_sysprocs = 0;
static int32_t memorystatus_scheduled_idle_demotions_apps = 0;

static void memorystatus_perform_idle_demotion(__unused void *spare1, __unused void *spare2);
static void memorystatus_schedule_idle_demotion_locked(proc_t p, boolean_t set_state);
static void memorystatus_reschedule_idle_demotion_locked(void);
int memorystatus_update_priority_for_appnap(proc_t p, boolean_t is_appnap);
vm_pressure_level_t convert_internal_pressure_level_to_dispatch_level(vm_pressure_level_t);
boolean_t is_knote_registered_modify_task_pressure_bits(struct knote*, int, task_t, vm_pressure_level_t, vm_pressure_level_t);
void memorystatus_klist_reset_all_for_level(vm_pressure_level_t pressure_level_to_clear);
void memorystatus_send_low_swap_note(void);
int memorystatus_get_proccnt_upto_priority(int32_t max_bucket_index);
boolean_t memorystatus_kill_elevated_process(uint32_t cause, os_reason_t jetsam_reason, unsigned int band, int aggr_count,
    uint32_t *errors, uint64_t *memory_reclaimed);
uint64_t memorystatus_available_memory_internal(proc_t p);

unsigned int memorystatus_level = 0;
static int memorystatus_list_count = 0;
memstat_bucket_t memstat_bucket[MEMSTAT_BUCKET_COUNT];
static thread_call_t memorystatus_idle_demotion_call;
uint64_t memstat_idle_demotion_deadline = 0;
int system_procs_aging_band = JETSAM_PRIORITY_AGING_BAND1;
int applications_aging_band = JETSAM_PRIORITY_IDLE;

#define isProcessInAgingBands(p)        ((isSysProc(p) && system_procs_aging_band && (p->p_memstat_effectivepriority == system_procs_aging_band)) || (isApp(p) && applications_aging_band && (p->p_memstat_effectivepriority == applications_aging_band)))

#define kJetsamAgingPolicyNone                          (0)
#define kJetsamAgingPolicyLegacy                        (1)
#define kJetsamAgingPolicySysProcsReclaimedFirst        (2)
#define kJetsamAgingPolicyAppsReclaimedFirst            (3)
#define kJetsamAgingPolicyMax                           kJetsamAgingPolicyAppsReclaimedFirst

unsigned int jetsam_aging_policy = kJetsamAgingPolicySysProcsReclaimedFirst;

extern int corpse_for_fatal_memkill;
extern uint64_t vm_purgeable_purge_task_owned(task_t task);
boolean_t memorystatus_allowed_vm_map_fork(task_t);
#if DEVELOPMENT || DEBUG
void memorystatus_abort_vm_map_fork(task_t);
#endif

/*
 * Idle delay timeout factors for daemons based on relaunch behavior. Only used in
 * kJetsamAgingPolicySysProcsReclaimedFirst aging policy.
 */
#define kJetsamSysProcsIdleDelayTimeLowRatio    (5)
#define kJetsamSysProcsIdleDelayTimeMedRatio    (2)
#define kJetsamSysProcsIdleDelayTimeHighRatio   (1)
static_assert(kJetsamSysProcsIdleDelayTimeLowRatio <= DEFERRED_IDLE_EXIT_TIME_SECS, "sysproc idle delay time for low relaunch daemons would be 0");

/*
 * For the kJetsamAgingPolicySysProcsReclaimedFirst aging policy, treat apps as well
 * behaved daemons for aging purposes.
 */
#define kJetsamAppsIdleDelayTimeRatio   (kJetsamSysProcsIdleDelayTimeLowRatio)

static uint64_t
memorystatus_sysprocs_idle_time(proc_t p)
{
	/*
	 * The kJetsamAgingPolicySysProcsReclaimedFirst aging policy uses the relaunch behavior to
	 * determine the exact idle deferred time provided to the daemons. For all other aging
	 * policies, simply return the default aging idle time.
	 */
	if (jetsam_aging_policy != kJetsamAgingPolicySysProcsReclaimedFirst) {
		return memorystatus_sysprocs_idle_delay_time;
	}

	uint64_t idle_delay_time = 0;
	/*
	 * For system processes, base the idle delay time on the
	 * jetsam relaunch behavior specified by launchd. The idea
	 * is to provide extra protection to the daemons which would
	 * relaunch immediately after jetsam.
	 */
	switch (p->p_memstat_relaunch_flags) {
	case P_MEMSTAT_RELAUNCH_UNKNOWN:
	case P_MEMSTAT_RELAUNCH_LOW:
		idle_delay_time = memorystatus_sysprocs_idle_delay_time / kJetsamSysProcsIdleDelayTimeLowRatio;
		break;
	case P_MEMSTAT_RELAUNCH_MED:
		idle_delay_time = memorystatus_sysprocs_idle_delay_time / kJetsamSysProcsIdleDelayTimeMedRatio;
		break;
	case P_MEMSTAT_RELAUNCH_HIGH:
		idle_delay_time = memorystatus_sysprocs_idle_delay_time / kJetsamSysProcsIdleDelayTimeHighRatio;
		break;
	default:
		panic("Unknown relaunch flags on process!");
		break;
	}
	return idle_delay_time;
}

static uint64_t
memorystatus_apps_idle_time(__unused proc_t p)
{
	/*
	 * For kJetsamAgingPolicySysProcsReclaimedFirst, the Apps are considered as low
	 * relaunch candidates. So only provide limited protection to them. In the other
	 * aging policies, return the default aging idle time.
	 */
	if (jetsam_aging_policy != kJetsamAgingPolicySysProcsReclaimedFirst) {
		return memorystatus_apps_idle_delay_time;
	}

	return memorystatus_apps_idle_delay_time / kJetsamAppsIdleDelayTimeRatio;
}


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
		return error;
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

	return 0;
}

SYSCTL_PROC(_kern, OID_AUTO, set_jetsam_aging_policy, CTLTYPE_INT | CTLFLAG_RW,
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
		return error;
	}

	if ((val < 0) || (val > INT32_MAX)) {
		printf("jetsam: new idle delay interval has invalid value.\n");
		return EINVAL;
	}

	nanoseconds_to_absolutetime((uint64_t)val * NSEC_PER_SEC, &memorystatus_sysprocs_idle_delay_time);

	return 0;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_sysprocs_idle_delay_time, CTLTYPE_INT | CTLFLAG_RW,
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
		return error;
	}

	if ((val < 0) || (val > INT32_MAX)) {
		printf("jetsam: new idle delay interval has invalid value.\n");
		return EINVAL;
	}

	nanoseconds_to_absolutetime((uint64_t)val * NSEC_PER_SEC, &memorystatus_apps_idle_delay_time);

	return 0;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_apps_idle_delay_time, CTLTYPE_INT | CTLFLAG_RW,
    0, 0, sysctl_jetsam_set_apps_idle_delay_time, "I", "Aging window for applications");

SYSCTL_INT(_kern, OID_AUTO, jetsam_aging_policy, CTLTYPE_INT | CTLFLAG_RD, &jetsam_aging_policy, 0, "");

static unsigned int memorystatus_dirty_count = 0;

SYSCTL_INT(_kern, OID_AUTO, max_task_pmem, CTLFLAG_RD | CTLFLAG_LOCKED | CTLFLAG_MASKED, &max_task_footprint_mb, 0, "");

static int memorystatus_highwater_enabled = 1;  /* Update the cached memlimit data. */
static boolean_t proc_jetsam_state_is_active_locked(proc_t);

#if __arm64__
#if CONFIG_MEMORYSTATUS
int legacy_footprint_bonus_mb = 50; /* This value was chosen after looking at the top 30 apps
                                     * that needed the additional room in their footprint when
                                     * the 'correct' accounting methods were applied to them.
                                     */

#if DEVELOPMENT || DEBUG
SYSCTL_INT(_kern, OID_AUTO, legacy_footprint_bonus_mb, CTLFLAG_RW | CTLFLAG_LOCKED, &legacy_footprint_bonus_mb, 0, "");
#endif /* DEVELOPMENT || DEBUG */

void
memorystatus_act_on_legacy_footprint_entitlement(proc_t p, boolean_t footprint_increase)
{
	int memlimit_mb_active = 0, memlimit_mb_inactive = 0;
	boolean_t memlimit_active_is_fatal = FALSE, memlimit_inactive_is_fatal = 0, use_active_limit = FALSE;

	if (p == NULL) {
		return;
	}

	proc_list_lock();

	if (p->p_memstat_memlimit_active > 0) {
		memlimit_mb_active = p->p_memstat_memlimit_active;
	} else if (p->p_memstat_memlimit_active == -1) {
		memlimit_mb_active = max_task_footprint_mb;
	} else {
		/*
		 * Nothing to do for '0' which is
		 * a special value only used internally
		 * to test 'no limits'.
		 */
		proc_list_unlock();
		return;
	}

	if (p->p_memstat_memlimit_inactive > 0) {
		memlimit_mb_inactive = p->p_memstat_memlimit_inactive;
	} else if (p->p_memstat_memlimit_inactive == -1) {
		memlimit_mb_inactive = max_task_footprint_mb;
	} else {
		/*
		 * Nothing to do for '0' which is
		 * a special value only used internally
		 * to test 'no limits'.
		 */
		proc_list_unlock();
		return;
	}

	if (footprint_increase) {
		memlimit_mb_active += legacy_footprint_bonus_mb;
		memlimit_mb_inactive += legacy_footprint_bonus_mb;
	} else {
		memlimit_mb_active -= legacy_footprint_bonus_mb;
		if (memlimit_mb_active == max_task_footprint_mb) {
			memlimit_mb_active = -1; /* reverting back to default system limit */
		}

		memlimit_mb_inactive -= legacy_footprint_bonus_mb;
		if (memlimit_mb_inactive == max_task_footprint_mb) {
			memlimit_mb_inactive = -1; /* reverting back to default system limit */
		}
	}

	memlimit_active_is_fatal = (p->p_memstat_state & P_MEMSTAT_MEMLIMIT_ACTIVE_FATAL);
	memlimit_inactive_is_fatal = (p->p_memstat_state & P_MEMSTAT_MEMLIMIT_INACTIVE_FATAL);

	SET_ACTIVE_LIMITS_LOCKED(p, memlimit_mb_active, memlimit_active_is_fatal);
	SET_INACTIVE_LIMITS_LOCKED(p, memlimit_mb_inactive, memlimit_inactive_is_fatal);

	if (proc_jetsam_state_is_active_locked(p) == TRUE) {
		use_active_limit = TRUE;
		CACHE_ACTIVE_LIMITS_LOCKED(p, memlimit_active_is_fatal);
	} else {
		CACHE_INACTIVE_LIMITS_LOCKED(p, memlimit_inactive_is_fatal);
	}


	if (memorystatus_highwater_enabled) {
		task_set_phys_footprint_limit_internal(p->task,
		    (p->p_memstat_memlimit > 0) ? p->p_memstat_memlimit : -1,
		    NULL,                                    /*return old value */
		    use_active_limit,                                    /*active limit?*/
		    (use_active_limit ? memlimit_active_is_fatal : memlimit_inactive_is_fatal));
	}

	proc_list_unlock();
}

#endif /* CONFIG_MEMORYSTATUS */
#endif /* __arm64__ */

#if CONFIG_EMBEDDED

SYSCTL_INT(_kern, OID_AUTO, memorystatus_level, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_level, 0, "");

#endif /* CONFIG_EMBEDDED */

int
memorystatus_get_level(__unused struct proc *p, struct memorystatus_get_level_args *args, __unused int *ret)
{
	user_addr_t     level = 0;

	level = args->level;

	if (copyout(&memorystatus_level, level, sizeof(memorystatus_level)) != 0) {
		return EFAULT;
	}

	return 0;
}

static void memorystatus_thread(void *param __unused, wait_result_t wr __unused);

/* Memory Limits */

static boolean_t memorystatus_kill_specific_process(pid_t victim_pid, uint32_t cause, os_reason_t jetsam_reason);
static boolean_t memorystatus_kill_process_sync(pid_t victim_pid, uint32_t cause, os_reason_t jetsam_reason);


static int memorystatus_cmd_set_memlimit_properties(pid_t pid, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval);

static int memorystatus_set_memlimit_properties(pid_t pid, memorystatus_memlimit_properties_t *entry);

static int memorystatus_cmd_get_memlimit_properties(pid_t pid, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval);

static int memorystatus_cmd_get_memlimit_excess_np(pid_t pid, uint32_t flags, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval);

static void memorystatus_get_memlimit_properties_internal(proc_t p, memorystatus_memlimit_properties_t *p_entry);
static int memorystatus_set_memlimit_properties_internal(proc_t p, memorystatus_memlimit_properties_t *p_entry);

int proc_get_memstat_priority(proc_t, boolean_t);

static boolean_t memorystatus_idle_snapshot = 0;

unsigned int memorystatus_delta = 0;

/* Jetsam Loop Detection */
static boolean_t memorystatus_jld_enabled = FALSE;              /* Enable jetsam loop detection */
static uint32_t memorystatus_jld_eval_period_msecs = 0;         /* Init pass sets this based on device memory size */
static int      memorystatus_jld_eval_aggressive_count = 3;     /* Raise the priority max after 'n' aggressive loops */
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

#define AGGRESSIVE_JETSAM_LENIENT_MODE_THRESHOLD        25
boolean_t       memorystatus_aggressive_jetsam_lenient_allowed = FALSE;
boolean_t       memorystatus_aggressive_jetsam_lenient = FALSE;

#if DEVELOPMENT || DEBUG
/*
 * Jetsam Loop Detection tunables.
 */

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_jld_eval_period_msecs, CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_jld_eval_period_msecs, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_jld_eval_aggressive_count, CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_jld_eval_aggressive_count, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_jld_eval_aggressive_priority_band_max, CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_jld_eval_aggressive_priority_band_max, 0, "");
#endif /* DEVELOPMENT || DEBUG */

static uint32_t kill_under_pressure_cause = 0;

/*
 * snapshot support for memstats collected at boot.
 */
static memorystatus_jetsam_snapshot_t memorystatus_at_boot_snapshot;

static void memorystatus_init_jetsam_snapshot_locked(memorystatus_jetsam_snapshot_t *od_snapshot, uint32_t ods_list_count);
static boolean_t memorystatus_init_jetsam_snapshot_entry_locked(proc_t p, memorystatus_jetsam_snapshot_entry_t *entry, uint64_t gencount);
static void memorystatus_update_jetsam_snapshot_entry_locked(proc_t p, uint32_t kill_cause, uint64_t killtime);

static void memorystatus_clear_errors(void);
static void memorystatus_get_task_phys_footprint_page_counts(task_t task,
    uint64_t *internal_pages, uint64_t *internal_compressed_pages,
    uint64_t *purgeable_nonvolatile_pages, uint64_t *purgeable_nonvolatile_compressed_pages,
    uint64_t *alternate_accounting_pages, uint64_t *alternate_accounting_compressed_pages,
    uint64_t *iokit_mapped_pages, uint64_t *page_table_pages);

static void memorystatus_get_task_memory_region_count(task_t task, uint64_t *count);

static uint32_t memorystatus_build_state(proc_t p);
//static boolean_t memorystatus_issue_pressure_kevent(boolean_t pressured);

static boolean_t memorystatus_kill_top_process(boolean_t any, boolean_t sort_flag, uint32_t cause, os_reason_t jetsam_reason, int32_t *priority,
    uint32_t *errors, uint64_t *memory_reclaimed);
static boolean_t memorystatus_kill_processes_aggressive(uint32_t cause, int aggr_count, int32_t priority_max, uint32_t *errors, uint64_t *memory_reclaimed);
static boolean_t memorystatus_kill_hiwat_proc(uint32_t *errors, boolean_t *purged, uint64_t *memory_reclaimed);

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

/* VM pressure */

extern unsigned int    vm_page_free_count;
extern unsigned int    vm_page_active_count;
extern unsigned int    vm_page_inactive_count;
extern unsigned int    vm_page_throttled_count;
extern unsigned int    vm_page_purgeable_count;
extern unsigned int    vm_page_wire_count;
#if CONFIG_SECLUDED_MEMORY
extern unsigned int     vm_page_secluded_count;
extern unsigned int     vm_page_secluded_count_over_target;
#endif /* CONFIG_SECLUDED_MEMORY */

/* Aggressive jetsam pages threshold for sysproc aging policy */
unsigned int memorystatus_sysproc_aging_aggr_pages = 0;

#if CONFIG_JETSAM
unsigned int memorystatus_available_pages = (unsigned int)-1;
unsigned int memorystatus_available_pages_pressure = 0;
unsigned int memorystatus_available_pages_critical = 0;
unsigned int memorystatus_available_pages_critical_base = 0;
unsigned int memorystatus_available_pages_critical_idle_offset = 0;

#if DEVELOPMENT || DEBUG
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_available_pages, 0, "");
#else
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages, CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED, &memorystatus_available_pages, 0, "");
#endif /* DEVELOPMENT || DEBUG */

static unsigned int memorystatus_jetsam_policy = kPolicyDefault;
unsigned int memorystatus_policy_more_free_offset_pages = 0;
static void memorystatus_update_levels_locked(boolean_t critical_only);
static unsigned int memorystatus_thread_wasted_wakeup = 0;

/* Callback into vm_compressor.c to signal that thrashing has been mitigated. */
extern void vm_thrashing_jetsam_done(void);
static int memorystatus_cmd_set_jetsam_memory_limit(pid_t pid, int32_t high_water_mark, __unused int32_t *retval, boolean_t is_fatal_limit);
#if DEVELOPMENT || DEBUG
static inline uint32_t
roundToNearestMB(uint32_t in)
{
	return (in + ((1 << 20) - 1)) >> 20;
}

static int memorystatus_cmd_increase_jetsam_task_limit(pid_t pid, uint32_t byte_increase);
#endif

int32_t max_kill_priority = JETSAM_PRIORITY_MAX;

#else /* CONFIG_JETSAM */

uint64_t memorystatus_available_pages = (uint64_t)-1;
uint64_t memorystatus_available_pages_pressure = (uint64_t)-1;
uint64_t memorystatus_available_pages_critical = (uint64_t)-1;

int32_t max_kill_priority = JETSAM_PRIORITY_IDLE;
#endif /* CONFIG_JETSAM */

#if DEVELOPMENT || DEBUG

lck_grp_attr_t *disconnect_page_mappings_lck_grp_attr;
lck_grp_t *disconnect_page_mappings_lck_grp;
static lck_mtx_t disconnect_page_mappings_mutex;

extern boolean_t kill_on_no_paging_space;
#endif /* DEVELOPMENT || DEBUG */


/* Debug */

extern struct knote *vm_find_knote_from_pid(pid_t, struct klist *);

#if DEVELOPMENT || DEBUG

static unsigned int memorystatus_debug_dump_this_bucket = 0;

static void
memorystatus_debug_dump_bucket_locked(unsigned int bucket_index)
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
	printf("bucket [pid]       [pages / MB]     [state]      [EP / RP / AP]   dirty     deadline [L-limit / C-limit / A-limit / IA-limit] name\n");
	p = memorystatus_get_first_proc_locked(&b, traverse_all_buckets);
	while (p) {
		bytes = get_task_phys_footprint(p->task);
		task_get_phys_footprint_limit(p->task, &ledger_limit);
		printf("%2d     [%5d]     [%5lld /%3lldMB]   0x%-8x   [%2d / %2d / %2d]   0x%-3x   %10lld    [%3d / %3d%s / %3d%s / %3d%s]   %s\n",
		    b, p->p_pid,
		    (bytes / PAGE_SIZE_64),             /* task's footprint converted from bytes to pages     */
		    (bytes / (1024ULL * 1024ULL)),      /* task's footprint converted from bytes to MB */
		    p->p_memstat_state, p->p_memstat_effectivepriority, p->p_memstat_requestedpriority, p->p_memstat_assertionpriority,
		    p->p_memstat_dirty, p->p_memstat_idledeadline,
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
		return error;
	}
	error = SYSCTL_IN(req, &bucket_index, sizeof(int));
	if (error || !req->newptr) {
		return error;
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
	return error;
}

/*
 * Debug aid to look at jetsam buckets and proc jetsam fields.
 *	Use this sysctl to act on a particular jetsam bucket.
 *	Writing the sysctl triggers the dump.
 *      Usage: sysctl kern.memorystatus_debug_dump_this_bucket=<bucket_index>
 */

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_debug_dump_this_bucket, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_debug_dump_this_bucket, 0, sysctl_memorystatus_debug_dump_bucket, "I", "");


/* Debug aid to aid determination of limit */

static int
sysctl_memorystatus_highwater_enable SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2)
	proc_t p;
	unsigned int b = 0;
	int error, enable = 0;
	boolean_t use_active;   /* use the active limit and active limit attributes */
	boolean_t is_fatal;

	error = SYSCTL_OUT(req, arg1, sizeof(int));
	if (error || !req->newptr) {
		return error;
	}

	error = SYSCTL_IN(req, &enable, sizeof(int));
	if (error || !req->newptr) {
		return error;
	}

	if (!(enable == 0 || enable == 1)) {
		return EINVAL;
	}

	proc_list_lock();

	p = memorystatus_get_first_proc_locked(&b, TRUE);
	while (p) {
		use_active = proc_jetsam_state_is_active_locked(p);

		if (enable) {
			if (use_active == TRUE) {
				CACHE_ACTIVE_LIMITS_LOCKED(p, is_fatal);
			} else {
				CACHE_INACTIVE_LIMITS_LOCKED(p, is_fatal);
			}
		} else {
			/*
			 * Disabling limits does not touch the stored variants.
			 * Set the cached limit fields to system_wide defaults.
			 */
			p->p_memstat_memlimit = -1;
			p->p_memstat_state |= P_MEMSTAT_FATAL_MEMLIMIT;
			is_fatal = TRUE;
		}

		/*
		 * Enforce the cached limit by writing to the ledger.
		 */
		task_set_phys_footprint_limit_internal(p->task, (p->p_memstat_memlimit > 0) ? p->p_memstat_memlimit: -1, NULL, use_active, is_fatal);

		p = memorystatus_get_next_proc_locked(&b, p, TRUE);
	}

	memorystatus_highwater_enabled = enable;

	proc_list_unlock();

	return 0;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_highwater_enabled, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_highwater_enabled, 0, sysctl_memorystatus_highwater_enable, "I", "");

SYSCTL_INT(_kern, OID_AUTO, memorystatus_idle_snapshot, CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_idle_snapshot, 0, "");

#if CONFIG_JETSAM
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages_critical, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_available_pages_critical, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages_critical_base, CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_available_pages_critical_base, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages_critical_idle_offset, CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_available_pages_critical_idle_offset, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_policy_more_free_offset_pages, CTLFLAG_RW, &memorystatus_policy_more_free_offset_pages, 0, "");

static unsigned int memorystatus_jetsam_panic_debug = 0;

#if VM_PRESSURE_EVENTS

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages_pressure, CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_available_pages_pressure, 0, "");

#endif /* VM_PRESSURE_EVENTS */

#endif /* CONFIG_JETSAM */

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
	int     error = 0, pid = 0;
	proc_t  p;

	error = sysctl_handle_int(oidp, &pid, 0, req);
	if (error || !req->newptr) {
		return error;
	}

	lck_mtx_lock(&disconnect_page_mappings_mutex);

	if (pid == -1) {
		vm_pageout_disconnect_all_pages();
	} else {
		p = proc_find(pid);

		if (p != NULL) {
			error = task_disconnect_page_mappings(p->task);

			proc_rele(p);

			if (error) {
				error = EIO;
			}
		} else {
			error = EINVAL;
		}
	}
	lck_mtx_unlock(&disconnect_page_mappings_mutex);

	return error;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_disconnect_page_mappings, CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_LOCKED | CTLFLAG_MASKED,
    0, 0, &sysctl_memorystatus_disconnect_page_mappings, "I", "");

#endif /* DEVELOPMENT || DEBUG */


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
 *      non-0 on failure
 */
static int
memorystatus_sort_bucket(unsigned int bucket_index, int sort_order)
{
	int coal_sort_order;

	/*
	 * Verify the jetsam priority
	 */
	if (bucket_index >= MEMSTAT_BUCKET_COUNT) {
		return EINVAL;
	}

#if DEVELOPMENT || DEBUG
	if (sort_order == JETSAM_SORT_DEFAULT) {
		coal_sort_order = COALITION_SORT_DEFAULT;
	} else {
		coal_sort_order = sort_order;           /* only used for testing scenarios */
	}
#else
	/* Verify default */
	if (sort_order == JETSAM_SORT_DEFAULT) {
		coal_sort_order = COALITION_SORT_DEFAULT;
	} else {
		return EINVAL;
	}
#endif

	proc_list_lock();

	if (memstat_bucket[bucket_index].count == 0) {
		proc_list_unlock();
		return 0;
	}

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

	return 0;
}

/*
 * Sort processes by size for a single jetsam bucket.
 */

static void
memorystatus_sort_by_largest_process_locked(unsigned int bucket_index)
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
		memorystatus_get_task_page_counts(p->task, &pages, NULL, NULL);
		max_pages = pages;
		max_proc = p;
		prev_max_proc = p;

		while ((next_p = TAILQ_NEXT(p, p_memstat_list)) != NULL) {
			/* traversing list until we find next largest process */
			p = next_p;
			memorystatus_get_task_page_counts(p->task, &pages, NULL, NULL);
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

proc_t
memorystatus_get_first_proc_locked(unsigned int *bucket_index, boolean_t search)
{
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

proc_t
memorystatus_get_next_proc_locked(unsigned int *bucket_index, proc_t p, boolean_t search)
{
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

/*
 * Structure to hold state for a jetsam thread.
 * Typically there should be a single jetsam thread
 * unless parallel jetsam is enabled.
 */
struct jetsam_thread_state {
	uint8_t       inited; /* boolean - if the thread is initialized */
	uint8_t       limit_to_low_bands; /* boolean */
	int           memorystatus_wakeup; /* wake channel */
	int           index; /* jetsam thread index */
	thread_t      thread; /* jetsam thread pointer */
} *jetsam_threads;

/* Maximum number of jetsam threads allowed */
#define JETSAM_THREADS_LIMIT   3

/* Number of active jetsam threads */
_Atomic int active_jetsam_threads = 1;

/* Number of maximum jetsam threads configured */
int max_jetsam_threads = JETSAM_THREADS_LIMIT;

/*
 * Global switch for enabling fast jetsam. Fast jetsam is
 * hooked up via the system_override() system call. It has the
 * following effects:
 * - Raise the jetsam threshold ("clear-the-deck")
 * - Enabled parallel jetsam on eligible devices
 */
int fast_jetsam_enabled = 0;

/* Routine to find the jetsam state structure for the current jetsam thread */
static inline struct jetsam_thread_state *
jetsam_current_thread(void)
{
	for (int thr_id = 0; thr_id < max_jetsam_threads; thr_id++) {
		if (jetsam_threads[thr_id].thread == current_thread()) {
			return &(jetsam_threads[thr_id]);
		}
	}
	return NULL;
}


__private_extern__ void
memorystatus_init(void)
{
	kern_return_t result;
	int i;

#if CONFIG_FREEZE
	memorystatus_freeze_jetsam_band = JETSAM_PRIORITY_UI_SUPPORT;
	memorystatus_frozen_processes_max = FREEZE_PROCESSES_MAX;
	memorystatus_frozen_shared_mb_max = ((MAX_FROZEN_SHARED_MB_PERCENT * max_task_footprint_mb) / 100); /* 10% of the system wide task limit */
	memorystatus_freeze_shared_mb_per_process_max = (memorystatus_frozen_shared_mb_max / 4);
	memorystatus_freeze_pages_min = FREEZE_PAGES_MIN;
	memorystatus_freeze_pages_max = FREEZE_PAGES_MAX;
	memorystatus_max_frozen_demotions_daily = MAX_FROZEN_PROCESS_DEMOTIONS;
	memorystatus_thaw_count_demotion_threshold = MIN_THAW_DEMOTION_THRESHOLD;
#endif

#if DEVELOPMENT || DEBUG
	disconnect_page_mappings_lck_grp_attr = lck_grp_attr_alloc_init();
	disconnect_page_mappings_lck_grp = lck_grp_alloc_init("disconnect_page_mappings", disconnect_page_mappings_lck_grp_attr);

	lck_mtx_init(&disconnect_page_mappings_mutex, disconnect_page_mappings_lck_grp, NULL);

	if (kill_on_no_paging_space == TRUE) {
		max_kill_priority = JETSAM_PRIORITY_MAX;
	}
#endif

	memorystatus_jetsam_fg_band_lock_grp_attr = lck_grp_attr_alloc_init();
	memorystatus_jetsam_fg_band_lock_grp =
	    lck_grp_alloc_init("memorystatus_jetsam_fg_band", memorystatus_jetsam_fg_band_lock_grp_attr);
	lck_mtx_init(&memorystatus_jetsam_fg_band_lock, memorystatus_jetsam_fg_band_lock_grp, NULL);

	/* Init buckets */
	for (i = 0; i < MEMSTAT_BUCKET_COUNT; i++) {
		TAILQ_INIT(&memstat_bucket[i].list);
		memstat_bucket[i].count = 0;
		memstat_bucket[i].relaunch_high_count = 0;
	}
	memorystatus_idle_demotion_call = thread_call_allocate((thread_call_func_t)memorystatus_perform_idle_demotion, NULL);

	nanoseconds_to_absolutetime((uint64_t)DEFERRED_IDLE_EXIT_TIME_SECS * NSEC_PER_SEC, &memorystatus_sysprocs_idle_delay_time);
	nanoseconds_to_absolutetime((uint64_t)DEFERRED_IDLE_EXIT_TIME_SECS * NSEC_PER_SEC, &memorystatus_apps_idle_delay_time);

#if CONFIG_JETSAM
	/* Apply overrides */
	if (!PE_parse_boot_argn("kern.jetsam_delta", &delta_percentage, sizeof(delta_percentage))) {
		PE_get_default("kern.jetsam_delta", &delta_percentage, sizeof(delta_percentage));
	}
	if (delta_percentage == 0) {
		delta_percentage = 5;
	}
	if (max_mem > config_jetsam_large_memory_cutoff) {
		critical_threshold_percentage = critical_threshold_percentage_larger_devices;
		delta_percentage = delta_percentage_larger_devices;
	}
	assert(delta_percentage < 100);
	if (!PE_parse_boot_argn("kern.jetsam_critical_threshold", &critical_threshold_percentage, sizeof(critical_threshold_percentage))) {
		PE_get_default("kern.jetsam_critical_threshold", &critical_threshold_percentage, sizeof(critical_threshold_percentage));
	}
	assert(critical_threshold_percentage < 100);
	PE_get_default("kern.jetsam_idle_offset", &idle_offset_percentage, sizeof(idle_offset_percentage));
	assert(idle_offset_percentage < 100);
	PE_get_default("kern.jetsam_pressure_threshold", &pressure_threshold_percentage, sizeof(pressure_threshold_percentage));
	assert(pressure_threshold_percentage < 100);
	PE_get_default("kern.jetsam_freeze_threshold", &freeze_threshold_percentage, sizeof(freeze_threshold_percentage));
	assert(freeze_threshold_percentage < 100);


	if (!PE_parse_boot_argn("jetsam_aging_policy", &jetsam_aging_policy,
	    sizeof(jetsam_aging_policy))) {
		if (!PE_get_default("kern.jetsam_aging_policy", &jetsam_aging_policy,
		    sizeof(jetsam_aging_policy))) {
			jetsam_aging_policy = kJetsamAgingPolicySysProcsReclaimedFirst;
		}
	}

	if (jetsam_aging_policy > kJetsamAgingPolicyMax) {
		jetsam_aging_policy = kJetsamAgingPolicySysProcsReclaimedFirst;
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

	/* Take snapshots for idle-exit kills by default? First check the boot-arg... */
	if (!PE_parse_boot_argn("jetsam_idle_snapshot", &memorystatus_idle_snapshot, sizeof(memorystatus_idle_snapshot))) {
		/* ...no boot-arg, so check the device tree */
		PE_get_default("kern.jetsam_idle_snapshot", &memorystatus_idle_snapshot, sizeof(memorystatus_idle_snapshot));
	}

	memorystatus_delta = delta_percentage * atop_64(max_mem) / 100;
	memorystatus_available_pages_critical_idle_offset = idle_offset_percentage * atop_64(max_mem) / 100;
	memorystatus_available_pages_critical_base = (critical_threshold_percentage / delta_percentage) * memorystatus_delta;
	memorystatus_policy_more_free_offset_pages = (policy_more_free_offset_percentage / delta_percentage) * memorystatus_delta;
	memorystatus_sysproc_aging_aggr_pages = sysproc_aging_aggr_threshold_percentage * atop_64(max_mem) / 100;

	/* Jetsam Loop Detection */
	if (max_mem <= (512 * 1024 * 1024)) {
		/* 512 MB devices */
		memorystatus_jld_eval_period_msecs = 8000;      /* 8000 msecs == 8 second window */
	} else {
		/* 1GB and larger devices */
		memorystatus_jld_eval_period_msecs = 6000;      /* 6000 msecs == 6 second window */
	}

	memorystatus_jld_enabled = TRUE;

	/* No contention at this point */
	memorystatus_update_levels_locked(FALSE);

#endif /* CONFIG_JETSAM */

	memorystatus_jetsam_snapshot_max = maxproc;

	memorystatus_jetsam_snapshot_size = sizeof(memorystatus_jetsam_snapshot_t) +
	    (sizeof(memorystatus_jetsam_snapshot_entry_t) * memorystatus_jetsam_snapshot_max);

	memorystatus_jetsam_snapshot =
	    (memorystatus_jetsam_snapshot_t*)kalloc(memorystatus_jetsam_snapshot_size);
	if (!memorystatus_jetsam_snapshot) {
		panic("Could not allocate memorystatus_jetsam_snapshot");
	}

	memorystatus_jetsam_snapshot_copy =
	    (memorystatus_jetsam_snapshot_t*)kalloc(memorystatus_jetsam_snapshot_size);
	if (!memorystatus_jetsam_snapshot_copy) {
		panic("Could not allocate memorystatus_jetsam_snapshot_copy");
	}

	nanoseconds_to_absolutetime((uint64_t)JETSAM_SNAPSHOT_TIMEOUT_SECS * NSEC_PER_SEC, &memorystatus_jetsam_snapshot_timeout);

	memset(&memorystatus_at_boot_snapshot, 0, sizeof(memorystatus_jetsam_snapshot_t));

#if CONFIG_FREEZE
	memorystatus_freeze_threshold = (freeze_threshold_percentage / delta_percentage) * memorystatus_delta;
#endif

	/* Check the boot-arg to see if fast jetsam is allowed */
	if (!PE_parse_boot_argn("fast_jetsam_enabled", &fast_jetsam_enabled, sizeof(fast_jetsam_enabled))) {
		fast_jetsam_enabled = 0;
	}

	/* Check the boot-arg to configure the maximum number of jetsam threads */
	if (!PE_parse_boot_argn("max_jetsam_threads", &max_jetsam_threads, sizeof(max_jetsam_threads))) {
		max_jetsam_threads = JETSAM_THREADS_LIMIT;
	}

	/* Restrict the maximum number of jetsam threads to JETSAM_THREADS_LIMIT */
	if (max_jetsam_threads > JETSAM_THREADS_LIMIT) {
		max_jetsam_threads = JETSAM_THREADS_LIMIT;
	}

	/* For low CPU systems disable fast jetsam mechanism */
	if (vm_pageout_state.vm_restricted_to_single_processor == TRUE) {
		max_jetsam_threads = 1;
		fast_jetsam_enabled = 0;
	}

	/* Initialize the jetsam_threads state array */
	jetsam_threads = kalloc(sizeof(struct jetsam_thread_state) * max_jetsam_threads);

	/* Initialize all the jetsam threads */
	for (i = 0; i < max_jetsam_threads; i++) {
		jetsam_threads[i].inited = FALSE;
		jetsam_threads[i].index = i;
		result = kernel_thread_start_priority(memorystatus_thread, NULL, 95 /* MAXPRI_KERNEL */, &jetsam_threads[i].thread);
		if (result != KERN_SUCCESS) {
			panic("Could not create memorystatus_thread %d", i);
		}
		thread_deallocate(jetsam_threads[i].thread);
	}
}

/* Centralised for the purposes of allowing panic-on-jetsam */
extern void
vm_run_compactor(void);

/*
 * The jetsam no frills kill call
 *      Return: 0 on success
 *		error code on failure (EINVAL...)
 */
static int
jetsam_do_kill(proc_t p, int jetsam_flags, os_reason_t jetsam_reason)
{
	int error = 0;
	error = exit_with_reason(p, W_EXITCODE(0, SIGKILL), (int *)NULL, FALSE, FALSE, jetsam_flags, jetsam_reason);
	return error;
}

/*
 * Wrapper for processes exiting with memorystatus details
 */
static boolean_t
memorystatus_do_kill(proc_t p, uint32_t cause, os_reason_t jetsam_reason, uint64_t *footprint_of_killed_proc)
{
	int error = 0;
	__unused pid_t victim_pid = p->p_pid;
	uint64_t footprint = get_task_phys_footprint(p->task);
#if (KDEBUG_LEVEL >= KDEBUG_LEVEL_STANDARD)
	int32_t memstat_effectivepriority = p->p_memstat_effectivepriority;
#endif /* (KDEBUG_LEVEL >= KDEBUG_LEVEL_STANDARD) */

	KERNEL_DEBUG_CONSTANT((BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_DO_KILL)) | DBG_FUNC_START,
	    victim_pid, cause, vm_page_free_count, footprint, 0);
	DTRACE_MEMORYSTATUS4(memorystatus_do_kill, proc_t, p, os_reason_t, jetsam_reason, uint32_t, cause, uint64_t, footprint);
#if CONFIG_JETSAM && (DEVELOPMENT || DEBUG)
	if (memorystatus_jetsam_panic_debug & (1 << cause)) {
		panic("memorystatus_do_kill(): jetsam debug panic (cause: %d)", cause);
	}
#else
#pragma unused(cause)
#endif

	if (p->p_memstat_effectivepriority >= JETSAM_PRIORITY_FOREGROUND) {
		printf("memorystatus: killing process %d [%s] in high band %s (%d) - memorystatus_available_pages: %llu\n", p->p_pid,
		    (*p->p_name ? p->p_name : "unknown"),
		    memorystatus_priority_band_name(p->p_memstat_effectivepriority), p->p_memstat_effectivepriority,
		    (uint64_t)memorystatus_available_pages);
	}

	/*
	 * The jetsam_reason (os_reason_t) has enough information about the kill cause.
	 * We don't really need jetsam_flags anymore, so it's okay that not all possible kill causes have been mapped.
	 */
	int jetsam_flags = P_LTERM_JETSAM;
	switch (cause) {
	case kMemorystatusKilledHiwat:                                          jetsam_flags |= P_JETSAM_HIWAT; break;
	case kMemorystatusKilledVnodes:                                         jetsam_flags |= P_JETSAM_VNODE; break;
	case kMemorystatusKilledVMPageShortage:                         jetsam_flags |= P_JETSAM_VMPAGESHORTAGE; break;
	case kMemorystatusKilledVMCompressorThrashing:
	case kMemorystatusKilledVMCompressorSpaceShortage:      jetsam_flags |= P_JETSAM_VMTHRASHING; break;
	case kMemorystatusKilledFCThrashing:                            jetsam_flags |= P_JETSAM_FCTHRASHING; break;
	case kMemorystatusKilledPerProcessLimit:                        jetsam_flags |= P_JETSAM_PID; break;
	case kMemorystatusKilledIdleExit:                                       jetsam_flags |= P_JETSAM_IDLEEXIT; break;
	}
	error = jetsam_do_kill(p, jetsam_flags, jetsam_reason);
	*footprint_of_killed_proc = ((error == 0) ? footprint : 0);

	KERNEL_DEBUG_CONSTANT((BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_DO_KILL)) | DBG_FUNC_END,
	    victim_pid, memstat_effectivepriority, vm_page_free_count, error, 0);

	KERNEL_DEBUG_CONSTANT((BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_COMPACTOR_RUN)) | DBG_FUNC_START,
	    victim_pid, cause, vm_page_free_count, *footprint_of_killed_proc, 0);

	vm_run_compactor();

	KERNEL_DEBUG_CONSTANT((BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_COMPACTOR_RUN)) | DBG_FUNC_END,
	    victim_pid, cause, vm_page_free_count, 0, 0);

	return error == 0;
}

/*
 * Node manipulation
 */

static void
memorystatus_check_levels_locked(void)
{
#if CONFIG_JETSAM
	/* Update levels */
	memorystatus_update_levels_locked(TRUE);
#else /* CONFIG_JETSAM */
	/*
	 * Nothing to do here currently since we update
	 * memorystatus_available_pages in vm_pressure_response.
	 */
#endif /* CONFIG_JETSAM */
}

/*
 * Pin a process to a particular jetsam band when it is in the background i.e. not doing active work.
 * For an application: that means no longer in the FG band
 * For a daemon: that means no longer in its 'requested' jetsam priority band
 */

int
memorystatus_update_inactive_jetsam_priority_band(pid_t pid, uint32_t op_flags, int jetsam_prio, boolean_t effective_now)
{
	int error = 0;
	boolean_t enable = FALSE;
	proc_t  p = NULL;

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
					if (p->p_memstat_effectivepriority < jetsam_prio) {
						if (memorystatus_highwater_enabled) {
							/*
							 * Process is about to transition from
							 * inactive --> active
							 * assign active state
							 */
							boolean_t is_fatal;
							boolean_t use_active = TRUE;
							CACHE_ACTIVE_LIMITS_LOCKED(p, is_fatal);
							task_set_phys_footprint_limit_internal(p->task, (p->p_memstat_memlimit > 0) ? p->p_memstat_memlimit : -1, NULL, use_active, is_fatal);
						}
						memorystatus_update_priority_locked(p, jetsam_prio, FALSE, FALSE);
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
					if (p->p_memstat_effectivepriority == jetsam_prio) {
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
		if (demote_prio_band != system_procs_aging_band && demote_prio_band != applications_aging_band) {
			continue;
		}

		demotion_bucket = &memstat_bucket[demote_prio_band];
		p = TAILQ_FIRST(&demotion_bucket->list);

		while (p) {
			MEMORYSTATUS_DEBUG(1, "memorystatus_perform_idle_demotion() found %d\n", p->p_pid);

			assert(p->p_memstat_idledeadline);

			assert(p->p_memstat_dirty & P_DIRTY_AGING_IN_PROGRESS);

			if (current_time >= p->p_memstat_idledeadline) {
				if ((isSysProc(p) &&
				    ((p->p_memstat_dirty & (P_DIRTY_IDLE_EXIT_ENABLED | P_DIRTY_IS_DIRTY)) != P_DIRTY_IDLE_EXIT_ENABLED)) || /* system proc marked dirty*/
				    task_has_assertions((struct task *)(p->task))) {     /* has outstanding assertions which might indicate outstanding work too */
					idle_delay_time = (isSysProc(p)) ? memorystatus_sysprocs_idle_time(p) : memorystatus_apps_idle_time(p);

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

	if ((p->p_memstat_state & P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND) ||
	    (p->p_memstat_state & P_MEMSTAT_PRIORITY_ASSERTION)) {
		/*
		 * This process isn't going to be making the trip to the lower bands.
		 */
		return;
	}

	if (isProcessInAgingBands(p)) {
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

	if (isSysProc(p)) {
		assert((p->p_memstat_dirty & P_DIRTY_IDLE_EXIT_ENABLED) == P_DIRTY_IDLE_EXIT_ENABLED);
	}

	idle_delay_time = (isSysProc(p)) ? memorystatus_sysprocs_idle_time(p) : memorystatus_apps_idle_time(p);
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

void
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

	if (isSysProc(p) && present_in_sysprocs_aging_bucket == TRUE) {
		memorystatus_scheduled_idle_demotions_sysprocs--;
		assert(memorystatus_scheduled_idle_demotions_sysprocs >= 0);
	} else if (isApp(p) && present_in_apps_aging_bucket == TRUE) {
		memorystatus_scheduled_idle_demotions_apps--;
		assert(memorystatus_scheduled_idle_demotions_apps >= 0);
	}

	assert((memorystatus_scheduled_idle_demotions_sysprocs + memorystatus_scheduled_idle_demotions_apps) >= 0);
}

static void
memorystatus_reschedule_idle_demotion_locked(void)
{
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
			if (memstat_idle_demotion_deadline != p->p_memstat_idledeadline) {
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

	/*
	 * Opt out system processes from being frozen by default.
	 * For coalition-based freezing, we only want to freeze sysprocs that have specifically opted in.
	 */
	if (isSysProc(p)) {
		p->p_memstat_state |= P_MEMSTAT_FREEZE_DISABLED;
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
	if (p->p_memstat_relaunch_flags & (P_MEMSTAT_RELAUNCH_HIGH)) {
		bucket->relaunch_high_count++;
	}

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

	old_bucket = &memstat_bucket[p->p_memstat_effectivepriority];

	if (skip_demotion_check == FALSE) {
		if (isSysProc(p)) {
			/*
			 * For system processes, the memorystatus_dirty_* routines take care of adding/removing
			 * the processes from the aging bands and balancing the demotion counts.
			 * We can, however, override that if the process has an 'elevated inactive jetsam band' attribute.
			 */

			if (p->p_memstat_state & P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND) {
				/*
				 * 2 types of processes can use the non-standard elevated inactive band:
				 * - Frozen processes that always land in memorystatus_freeze_jetsam_band
				 * OR
				 * - processes that specifically opt-in to the elevated inactive support e.g. docked processes.
				 */
#if CONFIG_FREEZE
				if (p->p_memstat_state & P_MEMSTAT_FROZEN) {
					if (priority <= memorystatus_freeze_jetsam_band) {
						priority = memorystatus_freeze_jetsam_band;
					}
				} else
#endif /* CONFIG_FREEZE */
				{
					if (priority <= JETSAM_PRIORITY_ELEVATED_INACTIVE) {
						priority = JETSAM_PRIORITY_ELEVATED_INACTIVE;
					}
				}
				assert(!(p->p_memstat_dirty & P_DIRTY_AGING_IN_PROGRESS));
			}
		} else if (isApp(p)) {
			/*
			 * Check to see if the application is being lowered in jetsam priority. If so, and:
			 * - it has an 'elevated inactive jetsam band' attribute, then put it in the appropriate band.
			 * - it is a normal application, then let it age in the aging band if that policy is in effect.
			 */

			if (p->p_memstat_state & P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND) {
#if CONFIG_FREEZE
				if (p->p_memstat_state & P_MEMSTAT_FROZEN) {
					if (priority <= memorystatus_freeze_jetsam_band) {
						priority = memorystatus_freeze_jetsam_band;
					}
				} else
#endif /* CONFIG_FREEZE */
				{
					if (priority <= JETSAM_PRIORITY_ELEVATED_INACTIVE) {
						priority = JETSAM_PRIORITY_ELEVATED_INACTIVE;
					}
				}
			} else {
				if (applications_aging_band) {
					if (p->p_memstat_effectivepriority == applications_aging_band) {
						assert(old_bucket->count == (memorystatus_scheduled_idle_demotions_apps + 1));
					}

					if ((jetsam_aging_policy != kJetsamAgingPolicyLegacy) && (priority <= applications_aging_band)) {
						assert(!(p->p_memstat_dirty & P_DIRTY_AGING_IN_PROGRESS));
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

#if DEVELOPMENT || DEBUG
	if (priority == JETSAM_PRIORITY_IDLE && /* if the process is on its way into the IDLE band */
	    skip_demotion_check == FALSE &&     /* and it isn't via the path that will set the INACTIVE memlimits */
	    (p->p_memstat_dirty & P_DIRTY_TRACK) && /* and it has 'DIRTY' tracking enabled */
	    ((p->p_memstat_memlimit != p->p_memstat_memlimit_inactive) || /* and we notice that the current limit isn't the right value (inactive) */
	    ((p->p_memstat_state & P_MEMSTAT_MEMLIMIT_INACTIVE_FATAL) ? (!(p->p_memstat_state & P_MEMSTAT_FATAL_MEMLIMIT)) : (p->p_memstat_state & P_MEMSTAT_FATAL_MEMLIMIT)))) { /* OR type (fatal vs non-fatal) */
		printf("memorystatus_update_priority_locked: on %s with 0x%x, prio: %d and %d\n", p->p_name, p->p_memstat_state, priority, p->p_memstat_memlimit); /* then we must catch this */
	}
#endif /* DEVELOPMENT || DEBUG */

	TAILQ_REMOVE(&old_bucket->list, p, p_memstat_list);
	old_bucket->count--;
	if (p->p_memstat_relaunch_flags & (P_MEMSTAT_RELAUNCH_HIGH)) {
		old_bucket->relaunch_high_count--;
	}

	new_bucket = &memstat_bucket[priority];
	if (head_insert) {
		TAILQ_INSERT_HEAD(&new_bucket->list, p, p_memstat_list);
	} else {
		TAILQ_INSERT_TAIL(&new_bucket->list, p, p_memstat_list);
	}
	new_bucket->count++;
	if (p->p_memstat_relaunch_flags & (P_MEMSTAT_RELAUNCH_HIGH)) {
		new_bucket->relaunch_high_count++;
	}

	if (memorystatus_highwater_enabled) {
		boolean_t is_fatal;
		boolean_t use_active;

		/*
		 * If cached limit data is updated, then the limits
		 * will be enforced by writing to the ledgers.
		 */
		boolean_t ledger_update_needed = TRUE;

		/*
		 * Here, we must update the cached memory limit if the task
		 * is transitioning between:
		 *      active <--> inactive
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
				CACHE_INACTIVE_LIMITS_LOCKED(p, is_fatal);
				use_active = FALSE;
			} else {
				ledger_update_needed = FALSE;
			}
		} else if ((priority >= JETSAM_PRIORITY_FOREGROUND) && (p->p_memstat_effectivepriority < JETSAM_PRIORITY_FOREGROUND)) {
			/*
			 *      inactive --> active
			 *	BG       -->     FG
			 *      assign active state
			 */
			CACHE_ACTIVE_LIMITS_LOCKED(p, is_fatal);
			use_active = TRUE;
		} else if ((priority < JETSAM_PRIORITY_FOREGROUND) && (p->p_memstat_effectivepriority >= JETSAM_PRIORITY_FOREGROUND)) {
			/*
			 *      active --> inactive
			 *	FG     -->       BG
			 *      assign inactive state
			 */
			CACHE_INACTIVE_LIMITS_LOCKED(p, is_fatal);
			use_active = FALSE;
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
			task_set_phys_footprint_limit_internal(p->task, (p->p_memstat_memlimit > 0) ? p->p_memstat_memlimit : -1, NULL, use_active, is_fatal);

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

		/*
		 * About to become active and so memory footprint could change.
		 * So mark it eligible for freeze-considerations next time around.
		 */
		if (p->p_memstat_state & P_MEMSTAT_FREEZE_IGNORE) {
			p->p_memstat_state &= ~P_MEMSTAT_FREEZE_IGNORE;
		}
	} else if (priority == JETSAM_PRIORITY_IDLE) {
		/*
		 * Transitioning into the idle priority bucket.
		 * Record idle start.
		 */
		p->p_memstat_idle_start = mach_absolute_time();
	}

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_CHANGE_PRIORITY), p->p_pid, priority, p->p_memstat_effectivepriority, 0, 0);

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

int
memorystatus_relaunch_flags_update(proc_t p, int relaunch_flags)
{
	p->p_memstat_relaunch_flags = relaunch_flags;
	KDBG(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_RELAUNCH_FLAGS), p->p_pid, relaunch_flags, 0, 0, 0);
	return 0;
}

/*
 *
 * Description: Update the jetsam priority and memory limit attributes for a given process.
 *
 * Parameters:
 *	p	init this process's jetsam information.
 *	priority          The jetsam priority band
 *	user_data	  user specific data, unused by the kernel
 *	is_assertion	  When true, a priority update is driven by an assertion.
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
 * Returns:     0	Success
 *		non-0	Failure
 */

int
memorystatus_update(proc_t p, int priority, uint64_t user_data, boolean_t is_assertion, boolean_t effective, boolean_t update_memlimit,
    int32_t memlimit_active, boolean_t memlimit_active_is_fatal,
    int32_t memlimit_inactive, boolean_t memlimit_inactive_is_fatal)
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

	if (is_assertion) {
		if (priority == JETSAM_PRIORITY_IDLE) {
			/*
			 * Assertions relinquish control when the process is heading to IDLE.
			 */
			if (p->p_memstat_state & P_MEMSTAT_PRIORITY_ASSERTION) {
				/*
				 * Mark the process as no longer being managed by assertions.
				 */
				p->p_memstat_state &= ~P_MEMSTAT_PRIORITY_ASSERTION;
			} else {
				/*
				 * Ignore an idle priority transition if the process is not
				 * already managed by assertions.  We won't treat this as
				 * an error, but we will log the unexpected behavior and bail.
				 */
				os_log(OS_LOG_DEFAULT, "memorystatus: Ignore assertion driven idle priority. Process not previously controlled %s:%d\n",
				    (*p->p_name ? p->p_name : "unknown"), p->p_pid);

				ret = 0;
				proc_list_unlock();
				goto out;
			}
		} else {
			/*
			 * Process is now being managed by assertions,
			 */
			p->p_memstat_state |= P_MEMSTAT_PRIORITY_ASSERTION;
		}

		/* Always update the assertion priority in this path */

		p->p_memstat_assertionpriority = priority;

		int memstat_dirty_flags = memorystatus_dirty_get(p, TRUE);  /* proc_list_lock is held */

		if (memstat_dirty_flags != 0) {
			/*
			 * Calculate maximum priority only when dirty tracking processes are involved.
			 */
			int maxpriority;
			if (memstat_dirty_flags & PROC_DIRTY_IS_DIRTY) {
				maxpriority = MAX(p->p_memstat_assertionpriority, p->p_memstat_requestedpriority);
			} else {
				/* clean */

				if (memstat_dirty_flags & PROC_DIRTY_ALLOWS_IDLE_EXIT) {
					/*
					 * The aging policy must be evaluated and applied here because runnningboardd
					 * has relinquished its hold on the jetsam priority by attempting to move a
					 * clean process to the idle band.
					 */

					int newpriority = JETSAM_PRIORITY_IDLE;
					if ((p->p_memstat_dirty & (P_DIRTY_IDLE_EXIT_ENABLED | P_DIRTY_IS_DIRTY)) == P_DIRTY_IDLE_EXIT_ENABLED) {
						newpriority = (p->p_memstat_dirty & P_DIRTY_AGING_IN_PROGRESS) ? system_procs_aging_band : JETSAM_PRIORITY_IDLE;
					}

					maxpriority = MAX(p->p_memstat_assertionpriority, newpriority );

					if (newpriority == system_procs_aging_band) {
						memorystatus_schedule_idle_demotion_locked(p, FALSE);
					}
				} else {
					/*
					 * Preserves requestedpriority when the process does not support pressured exit.
					 */
					maxpriority = MAX(p->p_memstat_assertionpriority, p->p_memstat_requestedpriority);
				}
			}
			priority = maxpriority;
		}
	} else {
		p->p_memstat_requestedpriority = priority;
	}

	if (update_memlimit) {
		boolean_t is_fatal;
		boolean_t use_active;

		/*
		 * Posix_spawn'd processes come through this path to instantiate ledger limits.
		 * Forked processes do not come through this path, so no ledger limits exist.
		 * (That's why forked processes can consume unlimited memory.)
		 */

		MEMORYSTATUS_DEBUG(3, "memorystatus_update(enter): pid %d, priority %d, dirty=0x%x, Active(%dMB %s), Inactive(%dMB, %s)\n",
		    p->p_pid, priority, p->p_memstat_dirty,
		    memlimit_active, (memlimit_active_is_fatal ? "F " : "NF"),
		    memlimit_inactive, (memlimit_inactive_is_fatal ? "F " : "NF"));

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
			CACHE_ACTIVE_LIMITS_LOCKED(p, is_fatal);
			use_active = TRUE;
		} else {
			CACHE_INACTIVE_LIMITS_LOCKED(p, is_fatal);
			use_active = FALSE;
		}

		/*
		 * Enforce the cached limit by writing to the ledger.
		 */
		if (memorystatus_highwater_enabled) {
			/* apply now */
			task_set_phys_footprint_limit_internal(p->task, ((p->p_memstat_memlimit > 0) ? p->p_memstat_memlimit : -1), NULL, use_active, is_fatal);

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
		if ((jetsam_aging_policy != kJetsamAgingPolicyLegacy) && isApp(p) && (priority > applications_aging_band)) {
			/*
			 * Runningboardd is pulling up an application that is in the aging band.
			 * We reset the app's state here so that it'll get a fresh stay in the
			 * aging band on the way back.
			 *
			 * We always handled the app 'aging' in the memorystatus_update_priority_locked()
			 * function. Daemons used to be handled via the dirty 'set/clear/track' path.
			 * But with extensions (daemon-app hybrid), runningboardd is now going through
			 * this routine for daemons too and things have gotten a bit tangled. This should
			 * be simplified/untangled at some point and might require some assistance from
			 * runningboardd.
			 */
			memorystatus_invalidate_idle_demotion_locked(p, TRUE);
		} else {
			memorystatus_invalidate_idle_demotion_locked(p, FALSE);
		}
		memorystatus_update_priority_locked(p, JETSAM_PRIORITY_IDLE, FALSE, TRUE);
	} else {
		if (jetsam_aging_policy == kJetsamAgingPolicyLegacy && priority == JETSAM_PRIORITY_IDLE) {
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
memorystatus_remove(proc_t p)
{
	int ret;
	memstat_bucket_t *bucket;
	boolean_t       reschedule = FALSE;

	MEMORYSTATUS_DEBUG(1, "memorystatus_list_remove: removing pid %d\n", p->p_pid);

	/*
	 * Check if this proc is locked (because we're performing a freeze).
	 * If so, we fail and instruct the caller to try again later.
	 */
	if (p->p_memstat_state & P_MEMSTAT_LOCKED) {
		return EAGAIN;
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
	if (p->p_memstat_relaunch_flags & (P_MEMSTAT_RELAUNCH_HIGH)) {
		bucket->relaunch_high_count--;
	}

	memorystatus_list_count--;

	/* If awaiting demotion to the idle band, clean up */
	if (reschedule) {
		memorystatus_invalidate_idle_demotion_locked(p, TRUE);
		memorystatus_reschedule_idle_demotion_locked();
	}

	memorystatus_check_levels_locked();

#if CONFIG_FREEZE
	if (p->p_memstat_state & (P_MEMSTAT_FROZEN)) {
		if (p->p_memstat_state & P_MEMSTAT_REFREEZE_ELIGIBLE) {
			p->p_memstat_state &= ~P_MEMSTAT_REFREEZE_ELIGIBLE;
			memorystatus_refreeze_eligible_count--;
		}

		memorystatus_frozen_count--;
		memorystatus_frozen_shared_mb -= p->p_memstat_freeze_sharedanon_pages;
		p->p_memstat_freeze_sharedanon_pages = 0;
	}

	if (p->p_memstat_state & P_MEMSTAT_SUSPENDED) {
		memorystatus_suspended_count--;
	}
#endif

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
 *      non-0 on failure
 *
 * The proc_list_lock is held by the caller.
 */

static int
memorystatus_validate_track_flags(struct proc *target_p, uint32_t pcontrol)
{
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

	/* Only one type of DEFER behavior is allowed.*/
	if ((pcontrol & PROC_DIRTY_DEFER) &&
	    (pcontrol & PROC_DIRTY_DEFER_ALWAYS)) {
		return EINVAL;
	}

	/* Deferral is only relevant if idle exit is specified */
	if (((pcontrol & PROC_DIRTY_DEFER) ||
	    (pcontrol & PROC_DIRTY_DEFER_ALWAYS)) &&
	    !(pcontrol & PROC_DIRTY_ALLOWS_IDLE_EXIT)) {
		return EINVAL;
	}

	return 0;
}

static void
memorystatus_update_idle_priority_locked(proc_t p)
{
	int32_t priority;

	MEMORYSTATUS_DEBUG(1, "memorystatus_update_idle_priority_locked(): pid %d dirty 0x%X\n", p->p_pid, p->p_memstat_dirty);

	assert(isSysProc(p));

	if ((p->p_memstat_dirty & (P_DIRTY_IDLE_EXIT_ENABLED | P_DIRTY_IS_DIRTY)) == P_DIRTY_IDLE_EXIT_ENABLED) {
		priority = (p->p_memstat_dirty & P_DIRTY_AGING_IN_PROGRESS) ? system_procs_aging_band : JETSAM_PRIORITY_IDLE;
	} else {
		priority = p->p_memstat_requestedpriority;
	}

	if (p->p_memstat_state & P_MEMSTAT_PRIORITY_ASSERTION) {
		/*
		 * This process has a jetsam priority managed by an assertion.
		 * Policy is to choose the max priority.
		 */
		if (p->p_memstat_assertionpriority > priority) {
			os_log(OS_LOG_DEFAULT, "memorystatus: assertion priority %d overrides priority %d for %s:%d\n",
			    p->p_memstat_assertionpriority, priority,
			    (*p->p_name ? p->p_name : "unknown"), p->p_pid);
			priority = p->p_memstat_assertionpriority;
		}
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

			if (p->p_memstat_state & P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND) {
				/*
				 * This process has the 'elevated inactive jetsam band' attribute.
				 * So, there will be no trip to IDLE after all.
				 * Instead, we pin the process in the elevated band,
				 * where its ACTIVE limits will apply.
				 */

				priority = JETSAM_PRIORITY_ELEVATED_INACTIVE;
			}

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
memorystatus_dirty_track(proc_t p, uint32_t pcontrol)
{
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
	if (pcontrol & (PROC_DIRTY_DEFER | PROC_DIRTY_DEFER_ALWAYS)) {
		if ((pcontrol & (PROC_DIRTY_DEFER)) &&
		    !(old_dirty & P_DIRTY_DEFER)) {
			p->p_memstat_dirty |= P_DIRTY_DEFER;
		}

		if ((pcontrol & (PROC_DIRTY_DEFER_ALWAYS)) &&
		    !(old_dirty & P_DIRTY_DEFER_ALWAYS)) {
			p->p_memstat_dirty |= P_DIRTY_DEFER_ALWAYS;
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
memorystatus_dirty_set(proc_t p, boolean_t self, uint32_t pcontrol)
{
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

	if (p->p_memstat_dirty & P_DIRTY_IS_DIRTY) {
		was_dirty = TRUE;
	}

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

	if (p->p_memstat_dirty & P_DIRTY_IS_DIRTY) {
		now_dirty = TRUE;
	}

	if ((was_dirty == TRUE && now_dirty == FALSE) ||
	    (was_dirty == FALSE && now_dirty == TRUE)) {
		/* Manage idle exit deferral, if applied */
		if ((p->p_memstat_dirty & P_DIRTY_IDLE_EXIT_ENABLED) == P_DIRTY_IDLE_EXIT_ENABLED) {
			/*
			 * Legacy mode: P_DIRTY_AGING_IN_PROGRESS means the process is in the aging band OR it might be heading back
			 * there once it's clean again. For the legacy case, this only applies if it has some protection window left.
			 * P_DIRTY_DEFER: one-time protection window given at launch
			 * P_DIRTY_DEFER_ALWAYS: protection window given for every dirty->clean transition. Like non-legacy mode.
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
					if (((p->p_memstat_dirty & P_DIRTY_DEFER_ALWAYS) == FALSE) &&
					    (mach_absolute_time() >= p->p_memstat_idledeadline)) {
						/*
						 * The process' hasn't enrolled in the "always defer after dirty"
						 * mode and its deadline has expired. It currently
						 * does not reside in any of the aging buckets.
						 *
						 * It's on its way to the JETSAM_PRIORITY_IDLE
						 * bucket via memorystatus_update_idle_priority_locked()
						 * below.
						 *
						 * So all we need to do is reset all the state on the
						 * process that's related to the aging bucket i.e.
						 * the AGING_IN_PROGRESS flag and the timer deadline.
						 */

						memorystatus_invalidate_idle_demotion_locked(p, TRUE);
						reschedule = TRUE;
					} else {
						/*
						 * Process enrolled in "always stop in deferral band after dirty" OR
						 * it still has some protection window left and so
						 * we just re-arm the timer without modifying any
						 * state on the process iff it still wants into that band.
						 */

						if (p->p_memstat_dirty & P_DIRTY_DEFER_ALWAYS) {
							memorystatus_schedule_idle_demotion_locked(p, TRUE);
							reschedule = TRUE;
						} else if (p->p_memstat_dirty & P_DIRTY_AGING_IN_PROGRESS) {
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
			boolean_t ledger_update_needed = TRUE;
			boolean_t use_active;
			boolean_t is_fatal;
			/*
			 * We are in this path because this process transitioned between
			 * dirty <--> clean state.  Update the cached memory limits.
			 */

			if (proc_jetsam_state_is_active_locked(p) == TRUE) {
				/*
				 * process is pinned in elevated band
				 * or
				 * process is dirty
				 */
				CACHE_ACTIVE_LIMITS_LOCKED(p, is_fatal);
				use_active = TRUE;
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
					CACHE_INACTIVE_LIMITS_LOCKED(p, is_fatal);
					use_active = FALSE;
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
				task_set_phys_footprint_limit_internal(p->task, ledger_limit, NULL, use_active, is_fatal);
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
memorystatus_dirty_clear(proc_t p, uint32_t pcontrol)
{
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

	if (!pcontrol || (pcontrol & (PROC_DIRTY_LAUNCH_IN_PROGRESS | PROC_DIRTY_DEFER | PROC_DIRTY_DEFER_ALWAYS)) == 0) {
		ret = EINVAL;
		goto exit;
	}

	if (pcontrol & PROC_DIRTY_LAUNCH_IN_PROGRESS) {
		p->p_memstat_dirty &= ~P_DIRTY_LAUNCH_IN_PROGRESS;
	}

	/* This can be set and cleared exactly once. */
	if (pcontrol & (PROC_DIRTY_DEFER | PROC_DIRTY_DEFER_ALWAYS)) {
		if (p->p_memstat_dirty & P_DIRTY_DEFER) {
			p->p_memstat_dirty &= ~(P_DIRTY_DEFER);
		}

		if (p->p_memstat_dirty & P_DIRTY_DEFER_ALWAYS) {
			p->p_memstat_dirty &= ~(P_DIRTY_DEFER_ALWAYS);
		}

		memorystatus_invalidate_idle_demotion_locked(p, TRUE);
		memorystatus_update_idle_priority_locked(p);
		memorystatus_reschedule_idle_demotion_locked();
	}

	ret = 0;
exit:
	proc_list_unlock();

	return ret;
}

int
memorystatus_dirty_get(proc_t p, boolean_t locked)
{
	int ret = 0;

	if (!locked) {
		proc_list_lock();
	}

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

	if (!locked) {
		proc_list_unlock();
	}

	return ret;
}

int
memorystatus_on_terminate(proc_t p)
{
	int sig;

	proc_list_lock();

	p->p_memstat_dirty |= P_DIRTY_TERMINATED;

	if ((p->p_memstat_dirty & (P_DIRTY_TRACK | P_DIRTY_IS_DIRTY)) == P_DIRTY_TRACK) {
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
	memorystatus_get_task_page_counts(p->task, &pages, NULL, NULL);
#endif
	proc_list_lock();
#if CONFIG_FREEZE
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
		/*
		 * Now that we don't _thaw_ a process completely,
		 * resuming it (and having some on-demand swapins)
		 * shouldn't preclude it from being counted as frozen.
		 *
		 * memorystatus_frozen_count--;
		 *
		 * We preserve the P_MEMSTAT_FROZEN state since the process
		 * could have state on disk AND so will deserve some protection
		 * in the jetsam bands.
		 */
		if ((p->p_memstat_state & P_MEMSTAT_REFREEZE_ELIGIBLE) == 0) {
			p->p_memstat_state |= P_MEMSTAT_REFREEZE_ELIGIBLE;
			memorystatus_refreeze_eligible_count++;
		}
		p->p_memstat_thaw_count++;

		memorystatus_thaw_count++;
	}

	memorystatus_suspended_count--;

	pid = p->p_pid;
#endif

	/*
	 * P_MEMSTAT_FROZEN will remain unchanged. This used to be:
	 * p->p_memstat_state &= ~(P_MEMSTAT_SUSPENDED | P_MEMSTAT_FROZEN);
	 */
	p->p_memstat_state &= ~P_MEMSTAT_SUSPENDED;

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
memorystatus_build_state(proc_t p)
{
	uint32_t snapshot_state = 0;

	/* General */
	if (p->p_memstat_state & P_MEMSTAT_SUSPENDED) {
		snapshot_state |= kMemorystatusSuspended;
	}
	if (p->p_memstat_state & P_MEMSTAT_FROZEN) {
		snapshot_state |= kMemorystatusFrozen;
	}
	if (p->p_memstat_state & P_MEMSTAT_REFREEZE_ELIGIBLE) {
		snapshot_state |= kMemorystatusWasThawed;
	}
	if (p->p_memstat_state & P_MEMSTAT_PRIORITY_ASSERTION) {
		snapshot_state |= kMemorystatusAssertion;
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

static boolean_t
kill_idle_exit_proc(void)
{
	proc_t p, victim_p = PROC_NULL;
	uint64_t current_time, footprint_of_killed_proc;
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

		if ((p->p_memstat_dirty & (P_DIRTY_ALLOW_IDLE_EXIT | P_DIRTY_IS_DIRTY | P_DIRTY_TERMINATED)) == (P_DIRTY_ALLOW_IDLE_EXIT)) {
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
		printf("memorystatus: killing_idle_process pid %d [%s] jetsam_reason->osr_code: %llu\n", victim_p->p_pid, (*victim_p->p_name ? victim_p->p_name : "unknown"), jetsam_reason->osr_code);
		killed = memorystatus_do_kill(victim_p, kMemorystatusKilledIdleExit, jetsam_reason, &footprint_of_killed_proc);
		proc_rele(victim_p);
	} else {
		os_reason_free(jetsam_reason);
	}

	return killed;
}

static void
memorystatus_thread_wake(void)
{
	int thr_id = 0;
	int active_thr = atomic_load(&active_jetsam_threads);

	/* Wakeup all the jetsam threads */
	for (thr_id = 0; thr_id < active_thr; thr_id++) {
		thread_wakeup((event_t)&jetsam_threads[thr_id].memorystatus_wakeup);
	}
}

#if CONFIG_JETSAM

static void
memorystatus_thread_pool_max()
{
	/* Increase the jetsam thread pool to max_jetsam_threads */
	int max_threads = max_jetsam_threads;
	printf("Expanding memorystatus pool to %d!\n", max_threads);
	atomic_store(&active_jetsam_threads, max_threads);
}

static void
memorystatus_thread_pool_default()
{
	/* Restore the jetsam thread pool to a single thread */
	printf("Reverting memorystatus pool back to 1\n");
	atomic_store(&active_jetsam_threads, 1);
}

#endif /* CONFIG_JETSAM */

extern void vm_pressure_response(void);

static int
memorystatus_thread_block(uint32_t interval_ms, thread_continue_t continuation)
{
	struct jetsam_thread_state *jetsam_thread = jetsam_current_thread();

	assert(jetsam_thread != NULL);
	if (interval_ms) {
		assert_wait_timeout(&jetsam_thread->memorystatus_wakeup, THREAD_UNINT, interval_ms, NSEC_PER_MSEC);
	} else {
		assert_wait(&jetsam_thread->memorystatus_wakeup, THREAD_UNINT);
	}

	return thread_block(continuation);
}

static boolean_t
memorystatus_avail_pages_below_pressure(void)
{
#if CONFIG_EMBEDDED
/*
 * Instead of CONFIG_EMBEDDED for these *avail_pages* routines, we should
 * key off of the system having dynamic swap support. With full swap support,
 * the system shouldn't really need to worry about various page thresholds.
 */
	return memorystatus_available_pages <= memorystatus_available_pages_pressure;
#else /* CONFIG_EMBEDDED */
	return FALSE;
#endif /* CONFIG_EMBEDDED */
}

static boolean_t
memorystatus_avail_pages_below_critical(void)
{
#if CONFIG_EMBEDDED
	return memorystatus_available_pages <= memorystatus_available_pages_critical;
#else /* CONFIG_EMBEDDED */
	return FALSE;
#endif /* CONFIG_EMBEDDED */
}

static boolean_t
memorystatus_post_snapshot(int32_t priority, uint32_t cause)
{
	boolean_t is_idle_priority;

	if (jetsam_aging_policy == kJetsamAgingPolicyLegacy) {
		is_idle_priority = (priority == JETSAM_PRIORITY_IDLE);
	} else {
		is_idle_priority = (priority == JETSAM_PRIORITY_IDLE || priority == JETSAM_PRIORITY_IDLE_DEFERRED);
	}
#if CONFIG_EMBEDDED
#pragma unused(cause)
	/*
	 * Don't generate logs for steady-state idle-exit kills,
	 * unless it is overridden for debug or by the device
	 * tree.
	 */

	return !is_idle_priority || memorystatus_idle_snapshot;

#else /* CONFIG_EMBEDDED */
	/*
	 * Don't generate logs for steady-state idle-exit kills,
	 * unless
	 * - it is overridden for debug or by the device
	 * tree.
	 * OR
	 * - the kill causes are important i.e. not kMemorystatusKilledIdleExit
	 */

	boolean_t snapshot_eligible_kill_cause = (is_reason_thrashing(cause) || is_reason_zone_map_exhaustion(cause));
	return !is_idle_priority || memorystatus_idle_snapshot || snapshot_eligible_kill_cause;
#endif /* CONFIG_EMBEDDED */
}

static boolean_t
memorystatus_action_needed(void)
{
#if CONFIG_EMBEDDED
	return is_reason_thrashing(kill_under_pressure_cause) ||
	       is_reason_zone_map_exhaustion(kill_under_pressure_cause) ||
	       memorystatus_available_pages <= memorystatus_available_pages_pressure;
#else /* CONFIG_EMBEDDED */
	return is_reason_thrashing(kill_under_pressure_cause) ||
	       is_reason_zone_map_exhaustion(kill_under_pressure_cause);
#endif /* CONFIG_EMBEDDED */
}

static boolean_t
memorystatus_act_on_hiwat_processes(uint32_t *errors, uint32_t *hwm_kill, boolean_t *post_snapshot, __unused boolean_t *is_critical, uint64_t *memory_reclaimed)
{
	boolean_t purged = FALSE, killed = FALSE;

	*memory_reclaimed = 0;
	killed = memorystatus_kill_hiwat_proc(errors, &purged, memory_reclaimed);

	if (killed) {
		*hwm_kill = *hwm_kill + 1;
		*post_snapshot = TRUE;
		return TRUE;
	} else {
		if (purged == FALSE) {
			/* couldn't purge and couldn't kill */
			memorystatus_hwm_candidates = FALSE;
		}
	}

#if CONFIG_JETSAM
	/* No highwater processes to kill. Continue or stop for now? */
	if (!is_reason_thrashing(kill_under_pressure_cause) &&
	    !is_reason_zone_map_exhaustion(kill_under_pressure_cause) &&
	    (memorystatus_available_pages > memorystatus_available_pages_critical)) {
		/*
		 * We are _not_ out of pressure but we are above the critical threshold and there's:
		 * - no compressor thrashing
		 * - enough zone memory
		 * - no more HWM processes left.
		 * For now, don't kill any other processes.
		 */

		if (*hwm_kill == 0) {
			memorystatus_thread_wasted_wakeup++;
		}

		*is_critical = FALSE;

		return TRUE;
	}
#endif /* CONFIG_JETSAM */

	return FALSE;
}

/*
 * kJetsamHighRelaunchCandidatesThreshold defines the percentage of candidates
 * in the idle & deferred bands that need to be bad candidates in order to trigger
 * aggressive jetsam.
 */
#define kJetsamHighRelaunchCandidatesThreshold  (100)

/* kJetsamMinCandidatesThreshold defines the minimum number of candidates in the
 * idle/deferred bands to trigger aggressive jetsam. This value basically decides
 * how much memory the system is ready to hold in the lower bands without triggering
 * aggressive jetsam. This number should ideally be tuned based on the memory config
 * of the device.
 */
#define kJetsamMinCandidatesThreshold           (5)

static boolean_t
memorystatus_aggressive_jetsam_needed_sysproc_aging(__unused int jld_eval_aggressive_count, __unused int *jld_idle_kills, __unused int jld_idle_kill_candidates, int *total_candidates, int *elevated_bucket_count)
{
	boolean_t aggressive_jetsam_needed = false;

	/*
	 * For the kJetsamAgingPolicySysProcsReclaimedFirst aging policy, we maintain the jetsam
	 * relaunch behavior for all daemons. Also, daemons and apps are aged in deferred bands on
	 * every dirty->clean transition. For this aging policy, the best way to determine if
	 * aggressive jetsam is needed, is to see if the kill candidates are mostly bad candidates.
	 * If yes, then we need to go to higher bands to reclaim memory.
	 */
	proc_list_lock();
	/* Get total candidate counts for idle and idle deferred bands */
	*total_candidates = memstat_bucket[JETSAM_PRIORITY_IDLE].count + memstat_bucket[system_procs_aging_band].count;
	/* Get counts of bad kill candidates in idle and idle deferred bands */
	int bad_candidates = memstat_bucket[JETSAM_PRIORITY_IDLE].relaunch_high_count + memstat_bucket[system_procs_aging_band].relaunch_high_count;

	*elevated_bucket_count = memstat_bucket[JETSAM_PRIORITY_ELEVATED_INACTIVE].count;

	proc_list_unlock();

	/* Check if the number of bad candidates is greater than kJetsamHighRelaunchCandidatesThreshold % */
	aggressive_jetsam_needed = (((bad_candidates * 100) / *total_candidates) >= kJetsamHighRelaunchCandidatesThreshold);

	/*
	 * Since the new aging policy bases the aggressive jetsam trigger on percentage of
	 * bad candidates, it is prone to being overly aggressive. In order to mitigate that,
	 * make sure the system is really under memory pressure before triggering aggressive
	 * jetsam.
	 */
	if (memorystatus_available_pages > memorystatus_sysproc_aging_aggr_pages) {
		aggressive_jetsam_needed = false;
	}

#if DEVELOPMENT || DEBUG
	printf("memorystatus: aggressive%d: [%s] Bad Candidate Threshold Check (total: %d, bad: %d, threshold: %d %%); Memory Pressure Check (available_pgs: %llu, threshold_pgs: %llu)\n",
	    jld_eval_aggressive_count, aggressive_jetsam_needed ? "PASSED" : "FAILED", *total_candidates, bad_candidates,
	    kJetsamHighRelaunchCandidatesThreshold, (uint64_t)memorystatus_available_pages, (uint64_t)memorystatus_sysproc_aging_aggr_pages);
#endif /* DEVELOPMENT || DEBUG */
	return aggressive_jetsam_needed;
}

static boolean_t
memorystatus_aggressive_jetsam_needed_default(__unused int jld_eval_aggressive_count, int *jld_idle_kills, int jld_idle_kill_candidates, int *total_candidates, int *elevated_bucket_count)
{
	boolean_t aggressive_jetsam_needed = false;
	/* Jetsam Loop Detection - locals */
	memstat_bucket_t *bucket;
	int             jld_bucket_count = 0;

	proc_list_lock();
	switch (jetsam_aging_policy) {
	case kJetsamAgingPolicyLegacy:
		bucket = &memstat_bucket[JETSAM_PRIORITY_IDLE];
		jld_bucket_count = bucket->count;
		bucket = &memstat_bucket[JETSAM_PRIORITY_AGING_BAND1];
		jld_bucket_count += bucket->count;
		break;
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
	*elevated_bucket_count = bucket->count;
	*total_candidates = jld_bucket_count;
	proc_list_unlock();

	aggressive_jetsam_needed = (*jld_idle_kills > jld_idle_kill_candidates);

#if DEVELOPMENT || DEBUG
	if (aggressive_jetsam_needed) {
		printf("memorystatus: aggressive%d: idle candidates: %d, idle kills: %d\n",
		    jld_eval_aggressive_count,
		    jld_idle_kill_candidates,
		    *jld_idle_kills);
	}
#endif /* DEVELOPMENT || DEBUG */
	return aggressive_jetsam_needed;
}

static boolean_t
memorystatus_act_aggressive(uint32_t cause, os_reason_t jetsam_reason, int *jld_idle_kills, boolean_t *corpse_list_purged, boolean_t *post_snapshot, uint64_t *memory_reclaimed)
{
	boolean_t aggressive_jetsam_needed = false;
	boolean_t killed;
	uint32_t errors = 0;
	uint64_t footprint_of_killed_proc = 0;
	int elevated_bucket_count = 0;
	int total_candidates = 0;
	*memory_reclaimed = 0;

	/*
	 * The aggressive jetsam logic looks at the number of times it has been in the
	 * aggressive loop to determine the max priority band it should kill upto. The
	 * static variables below are used to track that property.
	 *
	 * To reset those values, the implementation checks if it has been
	 * memorystatus_jld_eval_period_msecs since the parameters were reset.
	 */
	static int       jld_eval_aggressive_count = 0;
	static int32_t   jld_priority_band_max = JETSAM_PRIORITY_UI_SUPPORT;
	static uint64_t  jld_timestamp_msecs = 0;
	static int       jld_idle_kill_candidates = 0;

	if (memorystatus_jld_enabled == FALSE) {
		/* If aggressive jetsam is disabled, nothing to do here */
		return FALSE;
	}

	/* Get current timestamp (msecs only) */
	struct timeval  jld_now_tstamp = {0, 0};
	uint64_t        jld_now_msecs = 0;
	microuptime(&jld_now_tstamp);
	jld_now_msecs = (jld_now_tstamp.tv_sec * 1000);

	/*
	 * The aggressive jetsam logic looks at the number of candidates and their
	 * properties to decide if aggressive jetsam should be engaged.
	 */
	if (jetsam_aging_policy == kJetsamAgingPolicySysProcsReclaimedFirst) {
		/*
		 * For the kJetsamAgingPolicySysProcsReclaimedFirst aging policy, the logic looks at the number of
		 * candidates in the idle and deferred band and how many out of them are marked as high relaunch
		 * probability.
		 */
		aggressive_jetsam_needed = memorystatus_aggressive_jetsam_needed_sysproc_aging(jld_eval_aggressive_count,
		    jld_idle_kills, jld_idle_kill_candidates, &total_candidates, &elevated_bucket_count);
	} else {
		/*
		 * The other aging policies look at number of candidate processes over a specific time window and
		 * evaluate if the system is in a jetsam loop. If yes, aggressive jetsam is triggered.
		 */
		aggressive_jetsam_needed = memorystatus_aggressive_jetsam_needed_default(jld_eval_aggressive_count,
		    jld_idle_kills, jld_idle_kill_candidates, &total_candidates, &elevated_bucket_count);
	}

	/*
	 * Check if its been really long since the aggressive jetsam evaluation
	 * parameters have been refreshed. This logic also resets the jld_eval_aggressive_count
	 * counter to make sure we reset the aggressive jetsam severity.
	 */
	boolean_t param_reval = false;

	if ((total_candidates == 0) ||
	    (jld_now_msecs > (jld_timestamp_msecs + memorystatus_jld_eval_period_msecs))) {
		jld_timestamp_msecs      = jld_now_msecs;
		jld_idle_kill_candidates = total_candidates;
		*jld_idle_kills          = 0;
		jld_eval_aggressive_count = 0;
		jld_priority_band_max   = JETSAM_PRIORITY_UI_SUPPORT;
		param_reval = true;
	}

	/*
	 * If the parameters have been updated, re-evaluate the aggressive_jetsam_needed condition for
	 * the non kJetsamAgingPolicySysProcsReclaimedFirst policy since its based on jld_idle_kill_candidates etc.
	 */
	if ((param_reval == true) && (jetsam_aging_policy != kJetsamAgingPolicySysProcsReclaimedFirst)) {
		aggressive_jetsam_needed = (*jld_idle_kills > jld_idle_kill_candidates);
	}

	/*
	 * It is also possible that the system is down to a very small number of processes in the candidate
	 * bands. In that case, the decisions made by the memorystatus_aggressive_jetsam_needed_* routines
	 * would not be useful. In that case, do not trigger aggressive jetsam.
	 */
	if (total_candidates < kJetsamMinCandidatesThreshold) {
#if DEVELOPMENT || DEBUG
		printf("memorystatus: aggressive: [FAILED] Low Candidate Count (current: %d, threshold: %d)\n", total_candidates, kJetsamMinCandidatesThreshold);
#endif /* DEVELOPMENT || DEBUG */
		aggressive_jetsam_needed = false;
	}

	if (aggressive_jetsam_needed == false) {
		/* Either the aging policy or the candidate count decided that aggressive jetsam is not needed. Nothing more to do here. */
		return FALSE;
	}

	/* Looks like aggressive jetsam is needed */
	jld_eval_aggressive_count++;

	if (jld_eval_aggressive_count == memorystatus_jld_eval_aggressive_count) {
		memorystatus_issue_fg_band_notify();

		/*
		 * If we reach this aggressive cycle, corpses might be causing memory pressure.
		 * So, in an effort to avoid jetsams in the FG band, we will attempt to purge
		 * corpse memory prior to this final march through JETSAM_PRIORITY_UI_SUPPORT.
		 */
		if (total_corpses_count() > 0 && !*corpse_list_purged) {
			task_purge_all_corpses();
			*corpse_list_purged = TRUE;
		}
	} else if (jld_eval_aggressive_count > memorystatus_jld_eval_aggressive_count) {
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
			cause,
			jetsam_reason,
			JETSAM_PRIORITY_ELEVATED_INACTIVE,
			jld_eval_aggressive_count,
			&errors, &footprint_of_killed_proc);
		if (killed) {
			*post_snapshot = TRUE;
			*memory_reclaimed += footprint_of_killed_proc;
			if (memorystatus_avail_pages_below_pressure()) {
				/*
				 * Still under pressure.
				 * Find another pinned processes.
				 */
				continue;
			} else {
				return TRUE;
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
	 * memorystatus_kill_processes_aggressive() allocates its own
	 * jetsam_reason so the kMemorystatusKilledProcThrashing cause
	 * is consistent throughout the aggressive march.
	 */
	killed = memorystatus_kill_processes_aggressive(
		kMemorystatusKilledProcThrashing,
		jld_eval_aggressive_count,
		jld_priority_band_max,
		&errors, &footprint_of_killed_proc);

	if (killed) {
		/* Always generate logs after aggressive kill */
		*post_snapshot = TRUE;
		*memory_reclaimed += footprint_of_killed_proc;
		*jld_idle_kills = 0;
		return TRUE;
	}

	return FALSE;
}


static void
memorystatus_thread(void *param __unused, wait_result_t wr __unused)
{
	boolean_t post_snapshot = FALSE;
	uint32_t errors = 0;
	uint32_t hwm_kill = 0;
	boolean_t sort_flag = TRUE;
	boolean_t corpse_list_purged = FALSE;
	int     jld_idle_kills = 0;
	struct jetsam_thread_state *jetsam_thread = jetsam_current_thread();
	uint64_t total_memory_reclaimed = 0;

	assert(jetsam_thread != NULL);
	if (jetsam_thread->inited == FALSE) {
		/*
		 * It's the first time the thread has run, so just mark the thread as privileged and block.
		 * This avoids a spurious pass with unset variables, as set out in <rdar://problem/9609402>.
		 */

		char name[32];
		thread_wire(host_priv_self(), current_thread(), TRUE);
		snprintf(name, 32, "VM_memorystatus_%d", jetsam_thread->index + 1);

		/* Limit all but one thread to the lower jetsam bands, as that's where most of the victims are. */
		if (jetsam_thread->index == 0) {
			if (vm_pageout_state.vm_restricted_to_single_processor == TRUE) {
				thread_vm_bind_group_add();
			}
			jetsam_thread->limit_to_low_bands = FALSE;
		} else {
			jetsam_thread->limit_to_low_bands = TRUE;
		}
		thread_set_thread_name(current_thread(), name);
		jetsam_thread->inited = TRUE;
		memorystatus_thread_block(0, memorystatus_thread);
	}

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_SCAN) | DBG_FUNC_START,
	    memorystatus_available_pages, memorystatus_jld_enabled, memorystatus_jld_eval_period_msecs, memorystatus_jld_eval_aggressive_count, 0);

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
	while (memorystatus_action_needed()) {
		boolean_t killed;
		int32_t priority;
		uint32_t cause;
		uint64_t memory_reclaimed = 0;
		uint64_t jetsam_reason_code = JETSAM_REASON_INVALID;
		os_reason_t jetsam_reason = OS_REASON_NULL;

		cause = kill_under_pressure_cause;
		switch (cause) {
		case kMemorystatusKilledFCThrashing:
			jetsam_reason_code = JETSAM_REASON_MEMORY_FCTHRASHING;
			break;
		case kMemorystatusKilledVMCompressorThrashing:
			jetsam_reason_code = JETSAM_REASON_MEMORY_VMCOMPRESSOR_THRASHING;
			break;
		case kMemorystatusKilledVMCompressorSpaceShortage:
			jetsam_reason_code = JETSAM_REASON_MEMORY_VMCOMPRESSOR_SPACE_SHORTAGE;
			break;
		case kMemorystatusKilledZoneMapExhaustion:
			jetsam_reason_code = JETSAM_REASON_ZONE_MAP_EXHAUSTION;
			break;
		case kMemorystatusKilledVMPageShortage:
		/* falls through */
		default:
			jetsam_reason_code = JETSAM_REASON_MEMORY_VMPAGESHORTAGE;
			cause = kMemorystatusKilledVMPageShortage;
			break;
		}

		/* Highwater */
		boolean_t is_critical = TRUE;
		if (memorystatus_act_on_hiwat_processes(&errors, &hwm_kill, &post_snapshot, &is_critical, &memory_reclaimed)) {
			total_memory_reclaimed += memory_reclaimed;
			if (is_critical == FALSE) {
				/*
				 * For now, don't kill any other processes.
				 */
				break;
			} else {
				goto done;
			}
		}

		jetsam_reason = os_reason_create(OS_REASON_JETSAM, jetsam_reason_code);
		if (jetsam_reason == OS_REASON_NULL) {
			printf("memorystatus_thread: failed to allocate jetsam reason\n");
		}

		/* Only unlimited jetsam threads should act aggressive */
		if (!jetsam_thread->limit_to_low_bands &&
		    memorystatus_act_aggressive(cause, jetsam_reason, &jld_idle_kills, &corpse_list_purged, &post_snapshot, &memory_reclaimed)) {
			total_memory_reclaimed += memory_reclaimed;
			goto done;
		}

		/*
		 * memorystatus_kill_top_process() drops a reference,
		 * so take another one so we can continue to use this exit reason
		 * even after it returns
		 */
		os_reason_ref(jetsam_reason);

		/* LRU */
		killed = memorystatus_kill_top_process(TRUE, sort_flag, cause, jetsam_reason, &priority, &errors, &memory_reclaimed);
		sort_flag = FALSE;

		if (killed) {
			total_memory_reclaimed += memory_reclaimed;
			if (memorystatus_post_snapshot(priority, cause) == TRUE) {
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

			/*
			 * If we have jetsammed a process in or above JETSAM_PRIORITY_UI_SUPPORT
			 * then we attempt to relieve pressure by purging corpse memory and notifying
			 * anybody wanting to know this.
			 */
			if (priority >= JETSAM_PRIORITY_UI_SUPPORT) {
				memorystatus_issue_fg_band_notify();
				if (total_corpses_count() > 0 && !corpse_list_purged) {
					task_purge_all_corpses();
					corpse_list_purged = TRUE;
				}
			}
			goto done;
		}

		if (memorystatus_avail_pages_below_critical()) {
			/*
			 * Still under pressure and unable to kill a process - purge corpse memory
			 */
			if (total_corpses_count() > 0) {
				task_purge_all_corpses();
				corpse_list_purged = TRUE;
			}

			if (!jetsam_thread->limit_to_low_bands && memorystatus_avail_pages_below_critical()) {
				/*
				 * Still under pressure and unable to kill a process - panic
				 */
				panic("memorystatus_jetsam_thread: no victim! available pages:%llu\n", (uint64_t)memorystatus_available_pages);
			}
		}

done:

		/*
		 * We do not want to over-kill when thrashing has been detected.
		 * To avoid that, we reset the flag here and notify the
		 * compressor.
		 */
		if (is_reason_thrashing(kill_under_pressure_cause)) {
			kill_under_pressure_cause = 0;
#if CONFIG_JETSAM
			vm_thrashing_jetsam_done();
#endif /* CONFIG_JETSAM */
		} else if (is_reason_zone_map_exhaustion(kill_under_pressure_cause)) {
			kill_under_pressure_cause = 0;
		}

		os_reason_free(jetsam_reason);
	}

	kill_under_pressure_cause = 0;

	if (errors) {
		memorystatus_clear_errors();
	}

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
	    memorystatus_available_pages, total_memory_reclaimed, 0, 0, 0);

	memorystatus_thread_block(0, memorystatus_thread);
}

/*
 * Returns TRUE:
 *      when an idle-exitable proc was killed
 * Returns FALSE:
 *	when there are no more idle-exitable procs found
 *      when the attempt to kill an idle-exitable proc failed
 */
boolean_t
memorystatus_idle_exit_from_VM(void)
{
	/*
	 * This routine should no longer be needed since we are
	 * now using jetsam bands on all platforms and so will deal
	 * with IDLE processes within the memorystatus thread itself.
	 *
	 * But we still use it because we observed that macos systems
	 * started heavy compression/swapping with a bunch of
	 * idle-exitable processes alive and doing nothing. We decided
	 * to rather kill those processes than start swapping earlier.
	 */

	return kill_idle_exit_proc();
}

/*
 * Callback invoked when allowable physical memory footprint exceeded
 * (dirty pages + IOKit mappings)
 *
 * This is invoked for both advisory, non-fatal per-task high watermarks,
 * as well as the fatal task memory limits.
 */
void
memorystatus_on_ledger_footprint_exceeded(boolean_t warning, boolean_t memlimit_is_active, boolean_t memlimit_is_fatal)
{
	os_reason_t jetsam_reason = OS_REASON_NULL;

	proc_t p = current_proc();

#if VM_PRESSURE_EVENTS
	if (warning == TRUE) {
		/*
		 * This is a warning path which implies that the current process is close, but has
		 * not yet exceeded its per-process memory limit.
		 */
		if (memorystatus_warn_process(p->p_pid, memlimit_is_active, memlimit_is_fatal, FALSE /* not exceeded */) != TRUE) {
			/* Print warning, since it's possible that task has not registered for pressure notifications */
			os_log(OS_LOG_DEFAULT, "memorystatus_on_ledger_footprint_exceeded: failed to warn the current task (%d exiting, or no handler registered?).\n", p->p_pid);
		}
		return;
	}
#endif /* VM_PRESSURE_EVENTS */

	if (memlimit_is_fatal) {
		/*
		 * If this process has no high watermark or has a fatal task limit, then we have been invoked because the task
		 * has violated either the system-wide per-task memory limit OR its own task limit.
		 */
		jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_MEMORY_PERPROCESSLIMIT);
		if (jetsam_reason == NULL) {
			printf("task_exceeded footprint: failed to allocate jetsam reason\n");
		} else if (corpse_for_fatal_memkill != 0 && proc_send_synchronous_EXC_RESOURCE(p) == FALSE) {
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
		(void)memorystatus_warn_process(p->p_pid, memlimit_is_active, memlimit_is_fatal, TRUE /* exceeded */);

#endif /* VM_PRESSURE_EVENTS */
	}
}

void
memorystatus_log_exception(const int max_footprint_mb, boolean_t memlimit_is_active, boolean_t memlimit_is_fatal)
{
	proc_t p = current_proc();

	/*
	 * The limit violation is logged here, but only once per process per limit.
	 * Soft memory limit is a non-fatal high-water-mark
	 * Hard memory limit is a fatal custom-task-limit or system-wide per-task memory limit.
	 */

	os_log_with_startup_serial(OS_LOG_DEFAULT, "EXC_RESOURCE -> %s[%d] exceeded mem limit: %s%s %d MB (%s)\n",
	    ((p && *p->p_name) ? p->p_name : "unknown"), (p ? p->p_pid : -1), (memlimit_is_active ? "Active" : "Inactive"),
	    (memlimit_is_fatal  ? "Hard" : "Soft"), max_footprint_mb,
	    (memlimit_is_fatal  ? "fatal" : "non-fatal"));

	return;
}


/*
 * Description:
 *	Evaluates process state to determine which limit
 *	should be applied (active vs. inactive limit).
 *
 *	Processes that have the 'elevated inactive jetsam band' attribute
 *	are first evaluated based on their current priority band.
 *	presently elevated ==> active
 *
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
proc_jetsam_state_is_active_locked(proc_t p)
{
	if ((p->p_memstat_state & P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND) &&
	    (p->p_memstat_effectivepriority == JETSAM_PRIORITY_ELEVATED_INACTIVE)) {
		/*
		 * process has the 'elevated inactive jetsam band' attribute
		 * and process is present in the elevated band
		 * implies active state
		 */
		return TRUE;
	} else if (p->p_memstat_dirty & P_DIRTY_TRACK) {
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
memorystatus_kill_process_sync(pid_t victim_pid, uint32_t cause, os_reason_t jetsam_reason)
{
	boolean_t res;

	uint32_t errors = 0;
	uint64_t memory_reclaimed = 0;

	if (victim_pid == -1) {
		/* No pid, so kill first process */
		res = memorystatus_kill_top_process(TRUE, TRUE, cause, jetsam_reason, NULL, &errors, &memory_reclaimed);
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

	return res;
}

/*
 * Jetsam a specific process.
 */
static boolean_t
memorystatus_kill_specific_process(pid_t victim_pid, uint32_t cause, os_reason_t jetsam_reason)
{
	boolean_t killed;
	proc_t p;
	uint64_t killtime = 0;
	uint64_t footprint_of_killed_proc;
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

	if (memorystatus_jetsam_snapshot_count == 0) {
		memorystatus_init_jetsam_snapshot_locked(NULL, 0);
	}

	killtime = mach_absolute_time();
	absolutetime_to_microtime(killtime, &tv_sec, &tv_usec);
	tv_msec = tv_usec / 1000;

	memorystatus_update_jetsam_snapshot_entry_locked(p, cause, killtime);

	proc_list_unlock();

	killed = memorystatus_do_kill(p, cause, jetsam_reason, &footprint_of_killed_proc);

	os_log_with_startup_serial(OS_LOG_DEFAULT, "%lu.%03d memorystatus: killing_specific_process pid %d [%s] (%s %d) %lluKB - memorystatus_available_pages: %llu\n",
	    (unsigned long)tv_sec, tv_msec, victim_pid, ((p && *p->p_name) ? p->p_name : "unknown"),
	    memorystatus_kill_cause_name[cause], (p ? p->p_memstat_effectivepriority: -1),
	    footprint_of_killed_proc >> 10, (uint64_t)memorystatus_available_pages);

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

#endif /* CONFIG_JETSAM */

static void
memorystatus_get_task_memory_region_count(task_t task, uint64_t *count)
{
	assert(task);
	assert(count);

	*count = get_task_memory_region_count(task);
}


#define MEMORYSTATUS_VM_MAP_FORK_ALLOWED     0x100000000
#define MEMORYSTATUS_VM_MAP_FORK_NOT_ALLOWED 0x200000000

#if DEVELOPMENT || DEBUG

/*
 * Sysctl only used to test memorystatus_allowed_vm_map_fork() path.
 *   set a new pidwatch value
 *	or
 *   get the current pidwatch value
 *
 * The pidwatch_val starts out with a PID to watch for in the map_fork path.
 * Its value is:
 * - OR'd with MEMORYSTATUS_VM_MAP_FORK_ALLOWED if we allow the map_fork.
 * - OR'd with MEMORYSTATUS_VM_MAP_FORK_NOT_ALLOWED if we disallow the map_fork.
 * - set to -1ull if the map_fork() is aborted for other reasons.
 */

uint64_t memorystatus_vm_map_fork_pidwatch_val = 0;

static int sysctl_memorystatus_vm_map_fork_pidwatch SYSCTL_HANDLER_ARGS {
#pragma unused(oidp, arg1, arg2)

	uint64_t new_value = 0;
	uint64_t old_value = 0;
	int error = 0;

	/*
	 * The pid is held in the low 32 bits.
	 * The 'allowed' flags are in the upper 32 bits.
	 */
	old_value = memorystatus_vm_map_fork_pidwatch_val;

	error = sysctl_io_number(req, old_value, sizeof(old_value), &new_value, NULL);

	if (error || !req->newptr) {
		/*
		 * No new value passed in.
		 */
		return error;
	}

	/*
	 * A new pid was passed in via req->newptr.
	 * Ignore any attempt to set the higher order bits.
	 */
	memorystatus_vm_map_fork_pidwatch_val = new_value & 0xFFFFFFFF;
	printf("memorystatus: pidwatch old_value = 0x%llx, new_value = 0x%llx \n", old_value, new_value);

	return error;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_vm_map_fork_pidwatch, CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_MASKED,
    0, 0, sysctl_memorystatus_vm_map_fork_pidwatch, "Q", "get/set pid watched for in vm_map_fork");


/*
 * Record if a watched process fails to qualify for a vm_map_fork().
 */
void
memorystatus_abort_vm_map_fork(task_t task)
{
	if (memorystatus_vm_map_fork_pidwatch_val != 0) {
		proc_t p = get_bsdtask_info(task);
		if (p != NULL && memorystatus_vm_map_fork_pidwatch_val == (uint64_t)p->p_pid) {
			memorystatus_vm_map_fork_pidwatch_val = -1ull;
		}
	}
}

static void
set_vm_map_fork_pidwatch(task_t task, uint64_t x)
{
	if (memorystatus_vm_map_fork_pidwatch_val != 0) {
		proc_t p = get_bsdtask_info(task);
		if (p && (memorystatus_vm_map_fork_pidwatch_val == (uint64_t)p->p_pid)) {
			memorystatus_vm_map_fork_pidwatch_val |= x;
		}
	}
}

#else /* DEVELOPMENT || DEBUG */


static void
set_vm_map_fork_pidwatch(task_t task, uint64_t x)
{
#pragma unused(task)
#pragma unused(x)
}

#endif /* DEVELOPMENT || DEBUG */

/*
 * Called during EXC_RESOURCE handling when a process exceeds a soft
 * memory limit.  This is the corpse fork path and here we decide if
 * vm_map_fork will be allowed when creating the corpse.
 * The task being considered is suspended.
 *
 * By default, a vm_map_fork is allowed to proceed.
 *
 * A few simple policy assumptions:
 *	Desktop platform is not considered in this path.
 *	The vm_map_fork is always allowed.
 *
 *	If the device has a zero system-wide task limit,
 *	then the vm_map_fork is allowed.
 *
 *	And if a process's memory footprint calculates less
 *	than or equal to half of the system-wide task limit,
 *	then the vm_map_fork is allowed.  This calculation
 *	is based on the assumption that a process can
 *	munch memory up to the system-wide task limit.
 */
boolean_t
memorystatus_allowed_vm_map_fork(task_t task)
{
	boolean_t is_allowed = TRUE;   /* default */

#if CONFIG_EMBEDDED

	uint64_t footprint_in_bytes;
	uint64_t max_allowed_bytes;

	if (max_task_footprint_mb == 0) {
		set_vm_map_fork_pidwatch(task, MEMORYSTATUS_VM_MAP_FORK_ALLOWED);
		return is_allowed;
	}

	footprint_in_bytes = get_task_phys_footprint(task);

	/*
	 * Maximum is 1/4 of the system-wide task limit.
	 */
	max_allowed_bytes = ((uint64_t)max_task_footprint_mb * 1024 * 1024) >> 2;

	if (footprint_in_bytes > max_allowed_bytes) {
		printf("memorystatus disallowed vm_map_fork %lld  %lld\n", footprint_in_bytes, max_allowed_bytes);
		set_vm_map_fork_pidwatch(task, MEMORYSTATUS_VM_MAP_FORK_NOT_ALLOWED);
		return !is_allowed;
	}
#endif /* CONFIG_EMBEDDED */

	set_vm_map_fork_pidwatch(task, MEMORYSTATUS_VM_MAP_FORK_ALLOWED);
	return is_allowed;
}

void
memorystatus_get_task_page_counts(task_t task, uint32_t *footprint, uint32_t *max_footprint_lifetime, uint32_t *purgeable_pages)
{
	assert(task);
	assert(footprint);

	uint64_t pages;

	pages = (get_task_phys_footprint(task) / PAGE_SIZE_64);
	assert(((uint32_t)pages) == pages);
	*footprint = (uint32_t)pages;

	if (max_footprint_lifetime) {
		pages = (get_task_phys_footprint_lifetime_max(task) / PAGE_SIZE_64);
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

	LCK_MTX_ASSERT(proc_list_mlock, LCK_MTX_ASSERT_OWNED);

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
#if CONFIG_FREEZE
			entry->jse_thaw_count = p->p_memstat_thaw_count;
#else /* CONFIG_FREEZE */
			entry->jse_thaw_count = 0;
#endif /* CONFIG_FREEZE */

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
			uint32_t max_pages_lifetime = 0;
			uint32_t purgeable_pages    = 0;

			memorystatus_get_task_page_counts(p->task, &pages, &max_pages_lifetime, &purgeable_pages);
			entry->pages              = (uint64_t)pages;
			entry->max_pages_lifetime = (uint64_t)max_pages_lifetime;
			entry->purgeable_pages    = (uint64_t)purgeable_pages;

			uint64_t internal_pages                        = 0;
			uint64_t internal_compressed_pages             = 0;
			uint64_t purgeable_nonvolatile_pages           = 0;
			uint64_t purgeable_nonvolatile_compressed_pages = 0;
			uint64_t alternate_accounting_pages            = 0;
			uint64_t alternate_accounting_compressed_pages = 0;
			uint64_t iokit_mapped_pages                    = 0;
			uint64_t page_table_pages                      = 0;

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

			if (memorystatus_init_jetsam_snapshot_entry_locked(p, &snapshot_list[next], (snapshot->js_gencount)) == TRUE) {
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
		    p->p_pid, p->p_memstat_effectivepriority, memorystatus_jetsam_snapshot_count);
	}

	return;
}

#if CONFIG_JETSAM
void
memorystatus_pages_update(unsigned int pages_avail)
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
#if CONFIG_FREEZE
	/*
	 * We can't grab the freezer_mutex here even though that synchronization would be correct to inspect
	 * the # of frozen processes and wakeup the freezer thread. Reason being that we come here into this
	 * code with (possibly) the page-queue locks held and preemption disabled. So trying to grab a mutex here
	 * will result in the "mutex with preemption disabled" panic.
	 */

	if (memorystatus_freeze_thread_should_run() == TRUE) {
		/*
		 * The freezer thread is usually woken up by some user-space call i.e. pid_hibernate(any process).
		 * That trigger isn't invoked often enough and so we are enabling this explicit wakeup here.
		 */
		if (VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
			thread_wakeup((event_t)&memorystatus_freeze_wakeup);
		}
	}
#endif /* CONFIG_FREEZE */

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
#endif /* CONFIG_JETSAM */

static boolean_t
memorystatus_init_jetsam_snapshot_entry_locked(proc_t p, memorystatus_jetsam_snapshot_entry_t *entry, uint64_t gencount)
{
	clock_sec_t                     tv_sec;
	clock_usec_t                    tv_usec;
	uint32_t pages = 0;
	uint32_t max_pages_lifetime = 0;
	uint32_t purgeable_pages = 0;
	uint64_t internal_pages                         = 0;
	uint64_t internal_compressed_pages              = 0;
	uint64_t purgeable_nonvolatile_pages            = 0;
	uint64_t purgeable_nonvolatile_compressed_pages = 0;
	uint64_t alternate_accounting_pages             = 0;
	uint64_t alternate_accounting_compressed_pages  = 0;
	uint64_t iokit_mapped_pages                     = 0;
	uint64_t page_table_pages                       = 0;
	uint64_t region_count                           = 0;
	uint64_t cids[COALITION_NUM_TYPES];

	memset(entry, 0, sizeof(memorystatus_jetsam_snapshot_entry_t));

	entry->pid = p->p_pid;
	strlcpy(&entry->name[0], p->p_name, sizeof(entry->name));
	entry->priority = p->p_memstat_effectivepriority;

	memorystatus_get_task_page_counts(p->task, &pages, &max_pages_lifetime, &purgeable_pages);
	entry->pages              = (uint64_t)pages;
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
	entry->cpu_time.tv_sec = (int64_t)tv_sec;
	entry->cpu_time.tv_usec = (int64_t)tv_usec;

	assert(p->p_stats != NULL);
	entry->jse_starttime =  p->p_stats->ps_start;   /* abstime process started */
	entry->jse_killtime = 0;                        /* abstime jetsam chose to kill process */
	entry->killed       = 0;                        /* the jetsam kill cause */
	entry->jse_gencount = gencount;                 /* indicates a pass through jetsam thread, when process was targeted to be killed */

	entry->jse_idle_delta = p->p_memstat_idle_delta; /* Most recent timespan spent in idle-band */

#if CONFIG_FREEZE
	entry->jse_thaw_count = p->p_memstat_thaw_count;
#else /* CONFIG_FREEZE */
	entry->jse_thaw_count = 0;
#endif /* CONFIG_FREEZE */

	proc_coalitionids(p, cids);
	entry->jse_coalition_jetsam_id = cids[COALITION_TYPE_JETSAM];

	return TRUE;
}

static void
memorystatus_init_snapshot_vmstats(memorystatus_jetsam_snapshot_t *snapshot)
{
	kern_return_t kr = KERN_SUCCESS;
	mach_msg_type_number_t  count = HOST_VM_INFO64_COUNT;
	vm_statistics64_data_t  vm_stat;

	if ((kr = host_statistics64(host_self(), HOST_VM_INFO64, (host_info64_t)&vm_stat, &count)) != KERN_SUCCESS) {
		printf("memorystatus_init_jetsam_snapshot_stats: host_statistics64 failed with %d\n", kr);
		memset(&snapshot->stats, 0, sizeof(snapshot->stats));
	} else {
		snapshot->stats.free_pages      = vm_stat.free_count;
		snapshot->stats.active_pages    = vm_stat.active_count;
		snapshot->stats.inactive_pages  = vm_stat.inactive_count;
		snapshot->stats.throttled_pages = vm_stat.throttled_count;
		snapshot->stats.purgeable_pages = vm_stat.purgeable_count;
		snapshot->stats.wired_pages     = vm_stat.wire_count;

		snapshot->stats.speculative_pages = vm_stat.speculative_count;
		snapshot->stats.filebacked_pages  = vm_stat.external_page_count;
		snapshot->stats.anonymous_pages   = vm_stat.internal_page_count;
		snapshot->stats.compressions      = vm_stat.compressions;
		snapshot->stats.decompressions    = vm_stat.decompressions;
		snapshot->stats.compressor_pages  = vm_stat.compressor_page_count;
		snapshot->stats.total_uncompressed_pages_in_compressor = vm_stat.total_uncompressed_pages_in_compressor;
	}

	get_zone_map_size(&snapshot->stats.zone_map_size, &snapshot->stats.zone_map_capacity);

	bzero(snapshot->stats.largest_zone_name, sizeof(snapshot->stats.largest_zone_name));
	get_largest_zone_info(snapshot->stats.largest_zone_name, sizeof(snapshot->stats.largest_zone_name),
	    &snapshot->stats.largest_zone_size);
}

/*
 * Collect vm statistics at boot.
 * Called only once (see kern_exec.c)
 * Data can be consumed at any time.
 */
void
memorystatus_init_at_boot_snapshot()
{
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

	LCK_MTX_ASSERT(proc_list_mlock, LCK_MTX_ASSERT_OWNED);

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

#if CONFIG_JETSAM
static int
memorystatus_cmd_set_panic_bits(user_addr_t buffer, uint32_t buffer_size)
{
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
#endif /* CONFIG_JETSAM */

/*
 * Triggers a sort_order on a specified jetsam priority band.
 * This is for testing only, used to force a path through the sort
 * function.
 */
static int
memorystatus_cmd_test_jetsam_sort(int priority, int sort_order)
{
	int error = 0;

	unsigned int bucket_index = 0;

	if (priority == -1) {
		/* Use as shorthand for default priority */
		bucket_index = JETSAM_PRIORITY_DEFAULT;
	} else {
		bucket_index = (unsigned int)priority;
	}

	error = memorystatus_sort_bucket(bucket_index, sort_order);

	return error;
}

#endif /* DEVELOPMENT || DEBUG */

/*
 * Prepare the process to be killed (set state, update snapshot) and kill it.
 */
static uint64_t memorystatus_purge_before_jetsam_success = 0;

static boolean_t
memorystatus_kill_proc(proc_t p, uint32_t cause, os_reason_t jetsam_reason, boolean_t *killed, uint64_t *footprint_of_killed_proc)
{
	pid_t aPid = 0;
	uint32_t aPid_ep = 0;

	uint64_t        killtime = 0;
	clock_sec_t     tv_sec;
	clock_usec_t    tv_usec;
	uint32_t        tv_msec;
	boolean_t       retval = FALSE;

	aPid = p->p_pid;
	aPid_ep = p->p_memstat_effectivepriority;

	if (cause != kMemorystatusKilledVnodes && cause != kMemorystatusKilledZoneMapExhaustion) {
		/*
		 * Genuine memory pressure and not other (vnode/zone) resource exhaustion.
		 */
		boolean_t success = FALSE;
		uint64_t num_pages_purged;
		uint64_t num_pages_reclaimed = 0;
		uint64_t num_pages_unsecluded = 0;

		networking_memstatus_callout(p, cause);
		num_pages_purged = vm_purgeable_purge_task_owned(p->task);
		num_pages_reclaimed += num_pages_purged;
#if CONFIG_SECLUDED_MEMORY
		if (cause == kMemorystatusKilledVMPageShortage &&
		    vm_page_secluded_count > 0 &&
		    task_can_use_secluded_mem(p->task, FALSE)) {
			/*
			 * We're about to kill a process that has access
			 * to the secluded pool.  Drain that pool into the
			 * free or active queues to make these pages re-appear
			 * as "available", which might make us no longer need
			 * to kill that process.
			 * Since the secluded pool does not get refilled while
			 * a process has access to it, it should remain
			 * drained.
			 */
			num_pages_unsecluded = vm_page_secluded_drain();
			num_pages_reclaimed += num_pages_unsecluded;
		}
#endif /* CONFIG_SECLUDED_MEMORY */

		if (num_pages_reclaimed) {
			/*
			 * We actually reclaimed something and so let's
			 * check if we need to continue with the kill.
			 */
			if (cause == kMemorystatusKilledHiwat) {
				uint64_t footprint_in_bytes = get_task_phys_footprint(p->task);
				uint64_t memlimit_in_bytes  = (((uint64_t)p->p_memstat_memlimit) * 1024ULL * 1024ULL);  /* convert MB to bytes */
				success = (footprint_in_bytes <= memlimit_in_bytes);
			} else {
				success = (memorystatus_avail_pages_below_pressure() == FALSE);
#if CONFIG_SECLUDED_MEMORY
				if (!success && num_pages_unsecluded) {
					/*
					 * We just drained the secluded pool
					 * because we're about to kill a
					 * process that has access to it.
					 * This is an important process and
					 * we'd rather not kill it unless
					 * absolutely necessary, so declare
					 * success even if draining the pool
					 * did not quite get us out of the
					 * "pressure" level but still got
					 * us out of the "critical" level.
					 */
					success = (memorystatus_avail_pages_below_critical() == FALSE);
				}
#endif /* CONFIG_SECLUDED_MEMORY */
			}

			if (success) {
				memorystatus_purge_before_jetsam_success++;

				os_log_with_startup_serial(OS_LOG_DEFAULT, "memorystatus: reclaimed %llu pages (%llu purged, %llu unsecluded) from pid %d [%s] and avoided %s\n",
				    num_pages_reclaimed, num_pages_purged, num_pages_unsecluded, aPid, ((p && *p->p_name) ? p->p_name : "unknown"), memorystatus_kill_cause_name[cause]);

				*killed = FALSE;

				return TRUE;
			}
		}
	}

#if CONFIG_JETSAM && (DEVELOPMENT || DEBUG)
	MEMORYSTATUS_DEBUG(1, "jetsam: killing pid %d [%s] - %lld Mb > 1 (%d Mb)\n",
	    aPid, (*p->p_name ? p->p_name : "unknown"),
	    (footprint_in_bytes / (1024ULL * 1024ULL)),                 /* converted bytes to MB */
	    p->p_memstat_memlimit);
#endif /* CONFIG_JETSAM && (DEVELOPMENT || DEBUG) */

	killtime = mach_absolute_time();
	absolutetime_to_microtime(killtime, &tv_sec, &tv_usec);
	tv_msec = tv_usec / 1000;

	proc_list_lock();
	memorystatus_update_jetsam_snapshot_entry_locked(p, cause, killtime);
	proc_list_unlock();

	char kill_reason_string[128];

	if (cause == kMemorystatusKilledHiwat) {
		strlcpy(kill_reason_string, "killing_highwater_process", 128);
	} else {
		if (aPid_ep == JETSAM_PRIORITY_IDLE) {
			strlcpy(kill_reason_string, "killing_idle_process", 128);
		} else {
			strlcpy(kill_reason_string, "killing_top_process", 128);
		}
	}

	/*
	 * memorystatus_do_kill drops a reference, so take another one so we can
	 * continue to use this exit reason even after memorystatus_do_kill()
	 * returns
	 */
	os_reason_ref(jetsam_reason);

	retval = memorystatus_do_kill(p, cause, jetsam_reason, footprint_of_killed_proc);
	*killed = retval;

	os_log_with_startup_serial(OS_LOG_DEFAULT, "%lu.%03d memorystatus: %s pid %d [%s] (%s %d) %lluKB - memorystatus_available_pages: %llu",
	    (unsigned long)tv_sec, tv_msec, kill_reason_string,
	    aPid, ((p && *p->p_name) ? p->p_name : "unknown"),
	    memorystatus_kill_cause_name[cause], aPid_ep,
	    (*footprint_of_killed_proc) >> 10, (uint64_t)memorystatus_available_pages);

	return retval;
}

/*
 * Jetsam the first process in the queue.
 */
static boolean_t
memorystatus_kill_top_process(boolean_t any, boolean_t sort_flag, uint32_t cause, os_reason_t jetsam_reason,
    int32_t *priority, uint32_t *errors, uint64_t *memory_reclaimed)
{
	pid_t aPid;
	proc_t p = PROC_NULL, next_p = PROC_NULL;
	boolean_t new_snapshot = FALSE, force_new_snapshot = FALSE, killed = FALSE, freed_mem = FALSE;
	unsigned int i = 0;
	uint32_t aPid_ep;
	int32_t local_max_kill_prio = JETSAM_PRIORITY_IDLE;
	uint64_t footprint_of_killed_proc = 0;

#ifndef CONFIG_FREEZE
#pragma unused(any)
#endif

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_JETSAM) | DBG_FUNC_START,
	    memorystatus_available_pages, 0, 0, 0, 0);


#if CONFIG_JETSAM
	if (sort_flag == TRUE) {
		(void)memorystatus_sort_bucket(JETSAM_PRIORITY_FOREGROUND, JETSAM_SORT_DEFAULT);
	}

	local_max_kill_prio = max_kill_priority;

	force_new_snapshot = FALSE;

#else /* CONFIG_JETSAM */

	if (sort_flag == TRUE) {
		(void)memorystatus_sort_bucket(JETSAM_PRIORITY_IDLE, JETSAM_SORT_DEFAULT);
	}

	/*
	 * On macos, we currently only have 2 reasons to be here:
	 *
	 * kMemorystatusKilledZoneMapExhaustion
	 * AND
	 * kMemorystatusKilledVMCompressorSpaceShortage
	 *
	 * If we are here because of kMemorystatusKilledZoneMapExhaustion, we will consider
	 * any and all processes as eligible kill candidates since we need to avoid a panic.
	 *
	 * Since this function can be called async. it is harder to toggle the max_kill_priority
	 * value before and after a call. And so we use this local variable to set the upper band
	 * on the eligible kill bands.
	 */
	if (cause == kMemorystatusKilledZoneMapExhaustion) {
		local_max_kill_prio = JETSAM_PRIORITY_MAX;
	} else {
		local_max_kill_prio = max_kill_priority;
	}

	/*
	 * And, because we are here under extreme circumstances, we force a snapshot even for
	 * IDLE kills.
	 */
	force_new_snapshot = TRUE;

#endif /* CONFIG_JETSAM */

	if (cause != kMemorystatusKilledZoneMapExhaustion &&
	    jetsam_current_thread() != NULL &&
	    jetsam_current_thread()->limit_to_low_bands &&
	    local_max_kill_prio > JETSAM_PRIORITY_BACKGROUND) {
		local_max_kill_prio = JETSAM_PRIORITY_BACKGROUND;
	}

	proc_list_lock();

	next_p = memorystatus_get_first_proc_locked(&i, TRUE);
	while (next_p && (next_p->p_memstat_effectivepriority <= local_max_kill_prio)) {
		p = next_p;
		next_p = memorystatus_get_next_proc_locked(&i, p, TRUE);


		aPid = p->p_pid;
		aPid_ep = p->p_memstat_effectivepriority;

		if (p->p_memstat_state & (P_MEMSTAT_ERROR | P_MEMSTAT_TERMINATED)) {
			continue;   /* with lock held */
		}

		if (cause == kMemorystatusKilledVnodes) {
			/*
			 * If the system runs out of vnodes, we systematically jetsam
			 * processes in hopes of stumbling onto a vnode gain that helps
			 * the system recover.  The process that happens to trigger
			 * this path has no known relationship to the vnode shortage.
			 * Deadlock avoidance: attempt to safeguard the caller.
			 */

			if (p == current_proc()) {
				/* do not jetsam the current process */
				continue;
			}
		}

#if CONFIG_FREEZE
		boolean_t skip;
		boolean_t reclaim_proc = !(p->p_memstat_state & P_MEMSTAT_LOCKED);
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
			if (proc_ref_locked(p) == p) {
				/*
				 * Mark as terminated so that if exit1() indicates success, but the process (for example)
				 * is blocked in task_exception_notify(), it'll be skipped if encountered again - see
				 * <rdar://problem/13553476>. This is cheaper than examining P_LEXIT, which requires the
				 * acquisition of the proc lock.
				 */
				p->p_memstat_state |= P_MEMSTAT_TERMINATED;
			} else {
				/*
				 * We need to restart the search again because
				 * proc_ref_locked _can_ drop the proc_list lock
				 * and we could have lost our stored next_p via
				 * an exit() on another core.
				 */
				i = 0;
				next_p = memorystatus_get_first_proc_locked(&i, TRUE);
				continue;
			}

			/*
			 * Capture a snapshot if none exists and:
			 * - we are forcing a new snapshot creation, either because:
			 *      - on a particular platform we need these snapshots every time, OR
			 *	- a boot-arg/embedded device tree property has been set.
			 * - priority was not requested (this is something other than an ambient kill)
			 * - the priority was requested *and* the targeted process is not at idle priority
			 */
			if ((memorystatus_jetsam_snapshot_count == 0) &&
			    (force_new_snapshot || memorystatus_idle_snapshot || ((!priority) || (priority && (aPid_ep != JETSAM_PRIORITY_IDLE))))) {
				memorystatus_init_jetsam_snapshot_locked(NULL, 0);
				new_snapshot = TRUE;
			}

			proc_list_unlock();

			freed_mem = memorystatus_kill_proc(p, cause, jetsam_reason, &killed, &footprint_of_killed_proc); /* purged and/or killed 'p' */
			/* Success? */
			if (freed_mem) {
				if (killed) {
					*memory_reclaimed = footprint_of_killed_proc;
					if (priority) {
						*priority = aPid_ep;
					}
				} else {
					/* purged */
					proc_list_lock();
					p->p_memstat_state &= ~P_MEMSTAT_TERMINATED;
					proc_list_unlock();
				}
				proc_rele(p);
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

			i = 0;
			next_p = memorystatus_get_first_proc_locked(&i, TRUE);
		}
	}

	proc_list_unlock();

exit:
	os_reason_free(jetsam_reason);

	if (!killed) {
		*memory_reclaimed = 0;

		/* Clear snapshot if freshly captured and no target was found */
		if (new_snapshot) {
			proc_list_lock();
			memorystatus_jetsam_snapshot->entry_count = memorystatus_jetsam_snapshot_count = 0;
			proc_list_unlock();
		}
	}

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_JETSAM) | DBG_FUNC_END,
	    memorystatus_available_pages, killed ? aPid : 0, killed, *memory_reclaimed, 0);

	return killed;
}

/*
 * Jetsam aggressively
 */
static boolean_t
memorystatus_kill_processes_aggressive(uint32_t cause, int aggr_count,
    int32_t priority_max, uint32_t *errors, uint64_t *memory_reclaimed)
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
	os_reason_t jetsam_reason = OS_REASON_NULL;
	uint64_t footprint_of_killed_proc = 0;

	*memory_reclaimed = 0;

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_JETSAM) | DBG_FUNC_START,
	    memorystatus_available_pages, priority_max, 0, 0, 0);

	if (priority_max >= JETSAM_PRIORITY_FOREGROUND) {
		/*
		 * Check if aggressive jetsam has been asked to kill upto or beyond the
		 * JETSAM_PRIORITY_FOREGROUND bucket. If yes, sort the FG band based on
		 * coalition footprint.
		 */
		memorystatus_sort_bucket(JETSAM_PRIORITY_FOREGROUND, JETSAM_SORT_DEFAULT);
	}

	jetsam_reason = os_reason_create(OS_REASON_JETSAM, cause);
	if (jetsam_reason == OS_REASON_NULL) {
		printf("memorystatus_kill_processes_aggressive: failed to allocate exit reason\n");
	}

	proc_list_lock();

	next_p = memorystatus_get_first_proc_locked(&i, TRUE);
	while (next_p) {
		if (((next_p->p_listflag & P_LIST_EXITED) != 0) ||
		    ((unsigned int)(next_p->p_memstat_effectivepriority) != i)) {
			/*
			 * We have raced with next_p running on another core.
			 * It may be exiting or it may have moved to a different
			 * jetsam priority band.  This means we have lost our
			 * place in line while traversing the jetsam list.  We
			 * attempt to recover by rewinding to the beginning of the band
			 * we were already traversing.  By doing this, we do not guarantee
			 * that no process escapes this aggressive march, but we can make
			 * skipping an entire range of processes less likely. (PR-21069019)
			 */

			MEMORYSTATUS_DEBUG(1, "memorystatus: aggressive%d: rewinding band %d, %s(%d) moved or exiting.\n",
			    aggr_count, i, (*next_p->p_name ? next_p->p_name : "unknown"), next_p->p_pid);

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

		aPid = p->p_pid;
		aPid_ep = p->p_memstat_effectivepriority;

		if (p->p_memstat_state & (P_MEMSTAT_ERROR | P_MEMSTAT_TERMINATED)) {
			continue;
		}

		/*
		 * Capture a snapshot if none exists.
		 */
		if (memorystatus_jetsam_snapshot_count == 0) {
			memorystatus_init_jetsam_snapshot_locked(NULL, 0);
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

			printf("%lu.%03d memorystatus: %s%d pid %d [%s] (%s %d) - memorystatus_available_pages: %llu\n",
			    (unsigned long)tv_sec, tv_msec,
			    ((aPid_ep == JETSAM_PRIORITY_IDLE) ? "killing_idle_process_aggressive" : "killing_top_process_aggressive"),
			    aggr_count, aPid, (*p->p_name ? p->p_name : "unknown"),
			    memorystatus_kill_cause_name[cause], aPid_ep, (uint64_t)memorystatus_available_pages);

			memorystatus_level_snapshot = memorystatus_level;

			/*
			 * memorystatus_do_kill() drops a reference, so take another one so we can
			 * continue to use this exit reason even after memorystatus_do_kill()
			 * returns.
			 */
			os_reason_ref(jetsam_reason);
			killed = memorystatus_do_kill(p, cause, jetsam_reason, &footprint_of_killed_proc);

			/* Success? */
			if (killed) {
				*memory_reclaimed += footprint_of_killed_proc;
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
		proc_list_lock();
		memorystatus_jetsam_snapshot->entry_count = memorystatus_jetsam_snapshot_count = 0;
		proc_list_unlock();
	}

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_JETSAM) | DBG_FUNC_END,
	    memorystatus_available_pages, 0, kill_count, *memory_reclaimed, 0);

	if (kill_count > 0) {
		return TRUE;
	} else {
		return FALSE;
	}
}

static boolean_t
memorystatus_kill_hiwat_proc(uint32_t *errors, boolean_t *purged, uint64_t *memory_reclaimed)
{
	pid_t aPid = 0;
	proc_t p = PROC_NULL, next_p = PROC_NULL;
	boolean_t new_snapshot = FALSE, killed = FALSE, freed_mem = FALSE;
	unsigned int i = 0;
	uint32_t aPid_ep;
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

		footprint_in_bytes = get_task_phys_footprint(p->task);
		memlimit_in_bytes  = (((uint64_t)p->p_memstat_memlimit) * 1024ULL * 1024ULL);   /* convert MB to bytes */
		skip = (footprint_in_bytes <= memlimit_in_bytes);

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
			if (memorystatus_jetsam_snapshot_count == 0) {
				memorystatus_init_jetsam_snapshot_locked(NULL, 0);
				new_snapshot = TRUE;
			}

			if (proc_ref_locked(p) == p) {
				/*
				 * Mark as terminated so that if exit1() indicates success, but the process (for example)
				 * is blocked in task_exception_notify(), it'll be skipped if encountered again - see
				 * <rdar://problem/13553476>. This is cheaper than examining P_LEXIT, which requires the
				 * acquisition of the proc lock.
				 */
				p->p_memstat_state |= P_MEMSTAT_TERMINATED;

				proc_list_unlock();
			} else {
				/*
				 * We need to restart the search again because
				 * proc_ref_locked _can_ drop the proc_list lock
				 * and we could have lost our stored next_p via
				 * an exit() on another core.
				 */
				i = 0;
				next_p = memorystatus_get_first_proc_locked(&i, TRUE);
				continue;
			}

			footprint_in_bytes = 0;
			freed_mem = memorystatus_kill_proc(p, kMemorystatusKilledHiwat, jetsam_reason, &killed, &footprint_in_bytes); /* purged and/or killed 'p' */

			/* Success? */
			if (freed_mem) {
				if (killed == FALSE) {
					/* purged 'p'..don't reset HWM candidate count */
					*purged = TRUE;

					proc_list_lock();
					p->p_memstat_state &= ~P_MEMSTAT_TERMINATED;
					proc_list_unlock();
				} else {
					*memory_reclaimed = footprint_in_bytes;
				}
				proc_rele(p);
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

			i = 0;
			next_p = memorystatus_get_first_proc_locked(&i, TRUE);
		}
	}

	proc_list_unlock();

exit:
	os_reason_free(jetsam_reason);

	if (!killed) {
		*memory_reclaimed = 0;

		/* Clear snapshot if freshly captured and no target was found */
		if (new_snapshot) {
			proc_list_lock();
			memorystatus_jetsam_snapshot->entry_count = memorystatus_jetsam_snapshot_count = 0;
			proc_list_unlock();
		}
	}

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_JETSAM_HIWAT) | DBG_FUNC_END,
	    memorystatus_available_pages, killed ? aPid : 0, killed, *memory_reclaimed, 0);

	return killed;
}

/*
 * Jetsam a process pinned in the elevated band.
 *
 * Return:  true -- a pinned process was jetsammed
 *	    false -- no pinned process was jetsammed
 */
boolean_t
memorystatus_kill_elevated_process(uint32_t cause, os_reason_t jetsam_reason, unsigned int band, int aggr_count, uint32_t *errors, uint64_t *memory_reclaimed)
{
	pid_t aPid = 0;
	proc_t p = PROC_NULL, next_p = PROC_NULL;
	boolean_t new_snapshot = FALSE, killed = FALSE;
	int kill_count = 0;
	uint32_t aPid_ep;
	uint64_t killtime = 0;
	clock_sec_t     tv_sec;
	clock_usec_t    tv_usec;
	uint32_t        tv_msec;
	uint64_t footprint_of_killed_proc = 0;


	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_JETSAM) | DBG_FUNC_START,
	    memorystatus_available_pages, 0, 0, 0, 0);

#if CONFIG_FREEZE
	boolean_t consider_frozen_only = FALSE;

	if (band == (unsigned int) memorystatus_freeze_jetsam_band) {
		consider_frozen_only = TRUE;
	}
#endif /* CONFIG_FREEZE */

	proc_list_lock();

	next_p = memorystatus_get_first_proc_locked(&band, FALSE);
	while (next_p) {
		p = next_p;
		next_p = memorystatus_get_next_proc_locked(&band, p, FALSE);

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
		if (consider_frozen_only && !(p->p_memstat_state & P_MEMSTAT_FROZEN)) {
			continue;
		}

		if (p->p_memstat_state & P_MEMSTAT_LOCKED) {
			continue;
		}
#endif /* CONFIG_FREEZE */

#if DEVELOPMENT || DEBUG
		MEMORYSTATUS_DEBUG(1, "jetsam: elevated%d process pid %d [%s] - memorystatus_available_pages: %d\n",
		    aggr_count,
		    aPid, (*p->p_name ? p->p_name : "unknown"),
		    memorystatus_available_pages);
#endif /* DEVELOPMENT || DEBUG */

		if (memorystatus_jetsam_snapshot_count == 0) {
			memorystatus_init_jetsam_snapshot_locked(NULL, 0);
			new_snapshot = TRUE;
		}

		p->p_memstat_state |= P_MEMSTAT_TERMINATED;

		killtime = mach_absolute_time();
		absolutetime_to_microtime(killtime, &tv_sec, &tv_usec);
		tv_msec = tv_usec / 1000;

		memorystatus_update_jetsam_snapshot_entry_locked(p, cause, killtime);

		if (proc_ref_locked(p) == p) {
			proc_list_unlock();

			/*
			 * memorystatus_do_kill drops a reference, so take another one so we can
			 * continue to use this exit reason even after memorystatus_do_kill()
			 * returns
			 */
			os_reason_ref(jetsam_reason);
			killed = memorystatus_do_kill(p, cause, jetsam_reason, &footprint_of_killed_proc);

			os_log_with_startup_serial(OS_LOG_DEFAULT, "%lu.%03d memorystatus: killing_top_process_elevated%d pid %d [%s] (%s %d) %lluKB - memorystatus_available_pages: %llu\n",
			    (unsigned long)tv_sec, tv_msec,
			    aggr_count,
			    aPid, ((p && *p->p_name) ? p->p_name : "unknown"),
			    memorystatus_kill_cause_name[cause], aPid_ep,
			    footprint_of_killed_proc >> 10, (uint64_t)memorystatus_available_pages);

			/* Success? */
			if (killed) {
				*memory_reclaimed = footprint_of_killed_proc;
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

		next_p = memorystatus_get_first_proc_locked(&band, FALSE);
	}

	proc_list_unlock();

exit:
	os_reason_free(jetsam_reason);

	if (kill_count == 0) {
		*memory_reclaimed = 0;

		/* Clear snapshot if freshly captured and no target was found */
		if (new_snapshot) {
			proc_list_lock();
			memorystatus_jetsam_snapshot->entry_count = memorystatus_jetsam_snapshot_count = 0;
			proc_list_unlock();
		}
	}

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_JETSAM) | DBG_FUNC_END,
	    memorystatus_available_pages, killed ? aPid : 0, kill_count, *memory_reclaimed, 0);

	return killed;
}

static boolean_t
memorystatus_kill_process_async(pid_t victim_pid, uint32_t cause)
{
	/*
	 * TODO: allow a general async path
	 *
	 * NOTE: If a new async kill cause is added, make sure to update memorystatus_thread() to
	 * add the appropriate exit reason code mapping.
	 */
	if ((victim_pid != -1) ||
	    (cause != kMemorystatusKilledVMPageShortage &&
	    cause != kMemorystatusKilledVMCompressorThrashing &&
	    cause != kMemorystatusKilledVMCompressorSpaceShortage &&
	    cause != kMemorystatusKilledFCThrashing &&
	    cause != kMemorystatusKilledZoneMapExhaustion)) {
		return FALSE;
	}

	kill_under_pressure_cause = cause;
	memorystatus_thread_wake();
	return TRUE;
}

boolean_t
memorystatus_kill_on_VM_compressor_space_shortage(boolean_t async)
{
	if (async) {
		return memorystatus_kill_process_async(-1, kMemorystatusKilledVMCompressorSpaceShortage);
	} else {
		os_reason_t jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_MEMORY_VMCOMPRESSOR_SPACE_SHORTAGE);
		if (jetsam_reason == OS_REASON_NULL) {
			printf("memorystatus_kill_on_VM_compressor_space_shortage -- sync: failed to allocate jetsam reason\n");
		}

		return memorystatus_kill_process_sync(-1, kMemorystatusKilledVMCompressorSpaceShortage, jetsam_reason);
	}
}

#if CONFIG_JETSAM
boolean_t
memorystatus_kill_on_VM_compressor_thrashing(boolean_t async)
{
	if (async) {
		return memorystatus_kill_process_async(-1, kMemorystatusKilledVMCompressorThrashing);
	} else {
		os_reason_t jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_MEMORY_VMCOMPRESSOR_THRASHING);
		if (jetsam_reason == OS_REASON_NULL) {
			printf("memorystatus_kill_on_VM_compressor_thrashing -- sync: failed to allocate jetsam reason\n");
		}

		return memorystatus_kill_process_sync(-1, kMemorystatusKilledVMCompressorThrashing, jetsam_reason);
	}
}

boolean_t
memorystatus_kill_on_VM_page_shortage(boolean_t async)
{
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
memorystatus_kill_on_FC_thrashing(boolean_t async)
{
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
memorystatus_kill_on_vnode_limit(void)
{
	os_reason_t jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_VNODE);
	if (jetsam_reason == OS_REASON_NULL) {
		printf("memorystatus_kill_on_vnode_limit: failed to allocate jetsam reason\n");
	}

	return memorystatus_kill_process_sync(-1, kMemorystatusKilledVnodes, jetsam_reason);
}

#endif /* CONFIG_JETSAM */

boolean_t
memorystatus_kill_on_zone_map_exhaustion(pid_t pid)
{
	boolean_t res = FALSE;
	if (pid == -1) {
		res = memorystatus_kill_process_async(-1, kMemorystatusKilledZoneMapExhaustion);
	} else {
		os_reason_t jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_ZONE_MAP_EXHAUSTION);
		if (jetsam_reason == OS_REASON_NULL) {
			printf("memorystatus_kill_on_zone_map_exhaustion: failed to allocate jetsam reason\n");
		}

		res = memorystatus_kill_process_sync(pid, kMemorystatusKilledZoneMapExhaustion, jetsam_reason);
	}
	return res;
}

void
memorystatus_on_pageout_scan_end(void)
{
	/* No-op */
}

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
	if (!*list_ptr) {
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
memorystatus_get_priority_pid(pid_t pid, user_addr_t buffer, size_t buffer_size)
{
	int error = 0;
	memorystatus_priority_entry_t mp_entry;
	kern_return_t ret;

	/* Validate inputs */
	if ((pid == 0) || (buffer == USER_ADDR_NULL) || (buffer_size != sizeof(memorystatus_priority_entry_t))) {
		return EINVAL;
	}

	proc_t p = proc_find(pid);
	if (!p) {
		return ESRCH;
	}

	memset(&mp_entry, 0, sizeof(memorystatus_priority_entry_t));

	mp_entry.pid = p->p_pid;
	mp_entry.priority = p->p_memstat_effectivepriority;
	mp_entry.user_data = p->p_memstat_userdata;
	if (p->p_memstat_memlimit <= 0) {
		ret = task_get_phys_footprint_limit(p->task, &mp_entry.limit);
		if (ret != KERN_SUCCESS) {
			proc_rele(p);
			return EINVAL;
		}
	} else {
		mp_entry.limit = p->p_memstat_memlimit;
	}
	mp_entry.state = memorystatus_build_state(p);

	proc_rele(p);

	error = copyout(&mp_entry, buffer, buffer_size);

	return error;
}

static int
memorystatus_cmd_get_priority_list(pid_t pid, user_addr_t buffer, size_t buffer_size, int32_t *retval)
{
	int error = 0;
	boolean_t size_only;
	size_t list_size;

	/*
	 * When a non-zero pid is provided, the 'list' has only one entry.
	 */

	size_only = ((buffer == USER_ADDR_NULL) ? TRUE: FALSE);

	if (pid != 0) {
		list_size = sizeof(memorystatus_priority_entry_t) * 1;
		if (!size_only) {
			error = memorystatus_get_priority_pid(pid, buffer, buffer_size);
		}
	} else {
		memorystatus_priority_entry_t *list = NULL;
		error = memorystatus_get_priority_list(&list, &buffer_size, &list_size, size_only);

		if (error == 0) {
			if (!size_only) {
				error = copyout(list, buffer, list_size);
			}
		}

		if (list) {
			kfree(list, buffer_size);
		}
	}

	if (error == 0) {
		*retval = list_size;
	}

	return error;
}

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

#if CONFIG_JETSAM
static void
memorystatus_update_levels_locked(boolean_t critical_only)
{
	memorystatus_available_pages_critical = memorystatus_available_pages_critical_base;

	/*
	 * If there's an entry in the first bucket, we have idle processes.
	 */

	memstat_bucket_t *first_bucket = &memstat_bucket[JETSAM_PRIORITY_IDLE];
	if (first_bucket->count) {
		memorystatus_available_pages_critical += memorystatus_available_pages_critical_idle_offset;

		if (memorystatus_available_pages_critical > memorystatus_available_pages_pressure) {
			/*
			 * The critical threshold must never exceed the pressure threshold
			 */
			memorystatus_available_pages_critical = memorystatus_available_pages_pressure;
		}
	}

	if (memorystatus_jetsam_policy & kPolicyMoreFree) {
		memorystatus_available_pages_critical += memorystatus_policy_more_free_offset_pages;
	}

	if (critical_only) {
		return;
	}

#if VM_PRESSURE_EVENTS
	memorystatus_available_pages_pressure = (pressure_threshold_percentage / delta_percentage) * memorystatus_delta;
#endif
}

void
memorystatus_fast_jetsam_override(boolean_t enable_override)
{
	/* If fast jetsam is not enabled, simply return */
	if (!fast_jetsam_enabled) {
		return;
	}

	if (enable_override) {
		if ((memorystatus_jetsam_policy & kPolicyMoreFree) == kPolicyMoreFree) {
			return;
		}
		proc_list_lock();
		memorystatus_jetsam_policy |= kPolicyMoreFree;
		memorystatus_thread_pool_max();
		memorystatus_update_levels_locked(TRUE);
		proc_list_unlock();
	} else {
		if ((memorystatus_jetsam_policy & kPolicyMoreFree) == 0) {
			return;
		}
		proc_list_lock();
		memorystatus_jetsam_policy &= ~kPolicyMoreFree;
		memorystatus_thread_pool_default();
		memorystatus_update_levels_locked(TRUE);
		proc_list_unlock();
	}
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
	if (error || !req->newptr) {
		return error;
	}

	if (more_free) {
		memorystatus_fast_jetsam_override(true);
	} else {
		memorystatus_fast_jetsam_override(false);
	}

	return 0;
}
SYSCTL_PROC(_kern, OID_AUTO, memorystatus_policy_more_free, CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_LOCKED | CTLFLAG_MASKED,
    0, 0, &sysctl_kern_memorystatus_policy_more_free, "I", "");

#endif /* CONFIG_JETSAM */

/*
 * Get the at_boot snapshot
 */
static int
memorystatus_get_at_boot_snapshot(memorystatus_jetsam_snapshot_t **snapshot, size_t *snapshot_size, boolean_t size_only)
{
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

/*
 * Get the previous fully populated snapshot
 */
static int
memorystatus_get_jetsam_snapshot_copy(memorystatus_jetsam_snapshot_t **snapshot, size_t *snapshot_size, boolean_t size_only)
{
	size_t input_size = *snapshot_size;

	if (memorystatus_jetsam_snapshot_copy_count > 0) {
		*snapshot_size = sizeof(memorystatus_jetsam_snapshot_t) + (sizeof(memorystatus_jetsam_snapshot_entry_t) * (memorystatus_jetsam_snapshot_copy_count));
	} else {
		*snapshot_size = 0;
	}

	if (size_only) {
		return 0;
	}

	if (input_size < *snapshot_size) {
		return EINVAL;
	}

	*snapshot = memorystatus_jetsam_snapshot_copy;

	MEMORYSTATUS_DEBUG(7, "memorystatus_get_jetsam_snapshot_copy: returned inputsize (%ld), snapshot_size(%ld), listcount(%ld)\n",
	    (long)input_size, (long)*snapshot_size, (long)memorystatus_jetsam_snapshot_copy_count);

	return 0;
}

static int
memorystatus_get_on_demand_snapshot(memorystatus_jetsam_snapshot_t **snapshot, size_t *snapshot_size, boolean_t size_only)
{
	size_t input_size = *snapshot_size;
	uint32_t ods_list_count = memorystatus_list_count;
	memorystatus_jetsam_snapshot_t *ods = NULL;     /* The on_demand snapshot buffer */

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
		return ENOMEM;
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
memorystatus_get_jetsam_snapshot(memorystatus_jetsam_snapshot_t **snapshot, size_t *snapshot_size, boolean_t size_only)
{
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
memorystatus_cmd_get_jetsam_snapshot(int32_t flags, user_addr_t buffer, size_t buffer_size, int32_t *retval)
{
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
		if (flags & ~(MEMORYSTATUS_SNAPSHOT_ON_DEMAND | MEMORYSTATUS_SNAPSHOT_AT_BOOT | MEMORYSTATUS_SNAPSHOT_COPY)) {
			/*
			 * Unsupported bit set in flag.
			 */
			return EINVAL;
		}

		if (flags & (flags - 0x1)) {
			/*
			 * Can't have multiple flags set at the same time.
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
		} else if (flags & MEMORYSTATUS_SNAPSHOT_COPY) {
			error = memorystatus_get_jetsam_snapshot_copy(&snapshot, &buffer_size, size_only);
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
	 * If working with a copy of the snapshot
	 *	there is nothing to clear or update.
	 */
	if (!size_only) {
		if ((error = copyout(snapshot, buffer, buffer_size)) == 0) {
			if (is_default_snapshot) {
				/*
				 * The jetsam snapshot is never freed, its count is simply reset.
				 * However, we make a copy for any parties that might be interested
				 * in the previous fully populated snapshot.
				 */
				proc_list_lock();
				memcpy(memorystatus_jetsam_snapshot_copy, memorystatus_jetsam_snapshot, memorystatus_jetsam_snapshot_size);
				memorystatus_jetsam_snapshot_copy_count = memorystatus_jetsam_snapshot_count;
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
			if (snapshot) {
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
 *      Routine:	memorystatus_cmd_grp_set_priorities
 *	Purpose:	Update priorities for a group of processes.
 *
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
 *			        [ 0 | p71, p82,         ]
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


static int
memorystatus_cmd_grp_set_priorities(user_addr_t buffer, size_t buffer_size)
{
	/*
	 * We only handle setting priority
	 * per process
	 */

	int error = 0;
	memorystatus_properties_entry_v1_t *entries = NULL;
	uint32_t entry_count = 0;

	/* This will be the ordered proc list */
	typedef struct memorystatus_internal_properties {
		proc_t proc;
		int32_t priority;
	} memorystatus_internal_properties_t;

	memorystatus_internal_properties_t *table = NULL;
	size_t table_size = 0;
	uint32_t table_count = 0;

	uint32_t i = 0;
	uint32_t bucket_index = 0;
	boolean_t head_insert;
	int32_t new_priority;

	proc_t p;

	/* Verify inputs */
	if ((buffer == USER_ADDR_NULL) || (buffer_size == 0)) {
		error = EINVAL;
		goto out;
	}

	entry_count = (buffer_size / sizeof(memorystatus_properties_entry_v1_t));
	if ((entries = (memorystatus_properties_entry_v1_t *)kalloc(buffer_size)) == NULL) {
		error = ENOMEM;
		goto out;
	}

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_GRP_SET_PROP) | DBG_FUNC_START, MEMORYSTATUS_FLAGS_GRP_SET_PRIORITY, entry_count, 0, 0, 0);

	if ((error = copyin(buffer, entries, buffer_size)) != 0) {
		goto out;
	}

	/* Verify sanity of input priorities */
	if (entries[0].version == MEMORYSTATUS_MPE_VERSION_1) {
		if ((buffer_size % MEMORYSTATUS_MPE_VERSION_1_SIZE) != 0) {
			error = EINVAL;
			goto out;
		}
	} else {
		error = EINVAL;
		goto out;
	}

	for (i = 0; i < entry_count; i++) {
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
	if ((table = (memorystatus_internal_properties_t *)kalloc(table_size)) == NULL) {
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

	bucket_index = 0;

	proc_list_lock();

	/* Create the ordered table */
	p = memorystatus_get_first_proc_locked(&bucket_index, TRUE);
	while (p && (table_count < entry_count)) {
		for (i = 0; i < entry_count; i++) {
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
	for (i = 0; i < table_count; i++) {
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
out:
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_GRP_SET_PROP) | DBG_FUNC_END, MEMORYSTATUS_FLAGS_GRP_SET_PRIORITY, entry_count, table_count, 0, 0);

	if (entries) {
		kfree(entries, buffer_size);
	}
	if (table) {
		kfree(table, table_size);
	}

	return error;
}

memorystatus_internal_probabilities_t *memorystatus_global_probabilities_table = NULL;
size_t memorystatus_global_probabilities_size = 0;

static int
memorystatus_cmd_grp_set_probabilities(user_addr_t buffer, size_t buffer_size)
{
	int error = 0;
	memorystatus_properties_entry_v1_t *entries = NULL;
	uint32_t entry_count = 0, i = 0;
	memorystatus_internal_probabilities_t *tmp_table_new = NULL, *tmp_table_old = NULL;
	size_t tmp_table_new_size = 0, tmp_table_old_size = 0;

	/* Verify inputs */
	if ((buffer == USER_ADDR_NULL) || (buffer_size == 0)) {
		error = EINVAL;
		goto out;
	}

	entry_count = (buffer_size / sizeof(memorystatus_properties_entry_v1_t));

	if ((entries = (memorystatus_properties_entry_v1_t *) kalloc(buffer_size)) == NULL) {
		error = ENOMEM;
		goto out;
	}

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_GRP_SET_PROP) | DBG_FUNC_START, MEMORYSTATUS_FLAGS_GRP_SET_PROBABILITY, entry_count, 0, 0, 0);

	if ((error = copyin(buffer, entries, buffer_size)) != 0) {
		goto out;
	}

	if (entries[0].version == MEMORYSTATUS_MPE_VERSION_1) {
		if ((buffer_size % MEMORYSTATUS_MPE_VERSION_1_SIZE) != 0) {
			error = EINVAL;
			goto out;
		}
	} else {
		error = EINVAL;
		goto out;
	}

	/* Verify sanity of input priorities */
	for (i = 0; i < entry_count; i++) {
		/*
		 * 0 - low probability of use.
		 * 1 - high probability of use.
		 *
		 * Keeping this field an int (& not a bool) to allow
		 * us to experiment with different values/approaches
		 * later on.
		 */
		if (entries[i].use_probability > 1) {
			error = EINVAL;
			goto out;
		}
	}

	tmp_table_new_size = sizeof(memorystatus_internal_probabilities_t) * entry_count;

	if ((tmp_table_new = (memorystatus_internal_probabilities_t *) kalloc(tmp_table_new_size)) == NULL) {
		error = ENOMEM;
		goto out;
	}
	memset(tmp_table_new, 0, tmp_table_new_size);

	proc_list_lock();

	if (memorystatus_global_probabilities_table) {
		tmp_table_old = memorystatus_global_probabilities_table;
		tmp_table_old_size = memorystatus_global_probabilities_size;
	}

	memorystatus_global_probabilities_table = tmp_table_new;
	memorystatus_global_probabilities_size = tmp_table_new_size;
	tmp_table_new = NULL;

	for (i = 0; i < entry_count; i++) {
		/* Build the table data  */
		strlcpy(memorystatus_global_probabilities_table[i].proc_name, entries[i].proc_name, MAXCOMLEN + 1);
		memorystatus_global_probabilities_table[i].use_probability = entries[i].use_probability;
	}

	proc_list_unlock();

out:
	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_GRP_SET_PROP) | DBG_FUNC_END, MEMORYSTATUS_FLAGS_GRP_SET_PROBABILITY, entry_count, tmp_table_new_size, 0, 0);

	if (entries) {
		kfree(entries, buffer_size);
		entries = NULL;
	}

	if (tmp_table_old) {
		kfree(tmp_table_old, tmp_table_old_size);
		tmp_table_old = NULL;
	}

	return error;
}

static int
memorystatus_cmd_grp_set_properties(int32_t flags, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval)
{
	int error = 0;

	if ((flags & MEMORYSTATUS_FLAGS_GRP_SET_PRIORITY) == MEMORYSTATUS_FLAGS_GRP_SET_PRIORITY) {
		error = memorystatus_cmd_grp_set_priorities(buffer, buffer_size);
	} else if ((flags & MEMORYSTATUS_FLAGS_GRP_SET_PROBABILITY) == MEMORYSTATUS_FLAGS_GRP_SET_PROBABILITY) {
		error = memorystatus_cmd_grp_set_probabilities(buffer, buffer_size);
	} else {
		error = EINVAL;
	}

	return error;
}

/*
 * This routine is used to update a process's jetsam priority position and stored user_data.
 * It is not used for the setting of memory limits, which is why the last 6 args to the
 * memorystatus_update() call are 0 or FALSE.
 *
 * Flags passed into this call are used to distinguish the motivation behind a jetsam priority
 * transition.  By default, the kernel updates the process's original requested priority when
 * no flag is passed.  But when the MEMORYSTATUS_SET_PRIORITY_ASSERTION flag is used, the kernel
 * updates the process's assertion driven priority.
 *
 * The assertion flag was introduced for use by the device's assertion mediator (eg: runningboardd).
 * When an assertion is controlling a process's jetsam priority, it may conflict with that process's
 * dirty/clean (active/inactive) jetsam state.  The kernel attempts to resolve a priority transition
 * conflict by reviewing the process state and then choosing the maximum jetsam band at play,
 * eg: requested priority versus assertion priority.
 */

static int
memorystatus_cmd_set_priority_properties(pid_t pid, uint32_t flags, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval)
{
	int error = 0;
	boolean_t is_assertion = FALSE;         /* priority is driven by an assertion */
	memorystatus_priority_properties_t mpp_entry;

	/* Validate inputs */
	if ((pid == 0) || (buffer == USER_ADDR_NULL) || (buffer_size != sizeof(memorystatus_priority_properties_t))) {
		return EINVAL;
	}

	/* Validate flags */
	if (flags == 0) {
		/*
		 * Default. This path updates requestedpriority.
		 */
	} else {
		if (flags & ~(MEMORYSTATUS_SET_PRIORITY_ASSERTION)) {
			/*
			 * Unsupported bit set in flag.
			 */
			return EINVAL;
		} else if (flags & MEMORYSTATUS_SET_PRIORITY_ASSERTION) {
			is_assertion = TRUE;
		}
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

		if (is_assertion) {
			os_log(OS_LOG_DEFAULT, "memorystatus: set assertion priority(%d) target %s:%d\n",
			    mpp_entry.priority, (*p->p_name ? p->p_name : "unknown"), p->p_pid);
		}

		error = memorystatus_update(p, mpp_entry.priority, mpp_entry.user_data, is_assertion, FALSE, FALSE, 0, 0, FALSE, FALSE);
		proc_rele(p);
	}

	return error;
}

static int
memorystatus_cmd_set_memlimit_properties(pid_t pid, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval)
{
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

	return error;
}

static void
memorystatus_get_memlimit_properties_internal(proc_t p, memorystatus_memlimit_properties_t* p_entry)
{
	memset(p_entry, 0, sizeof(memorystatus_memlimit_properties_t));

	if (p->p_memstat_memlimit_active > 0) {
		p_entry->memlimit_active = p->p_memstat_memlimit_active;
	} else {
		task_convert_phys_footprint_limit(-1, &p_entry->memlimit_active);
	}

	if (p->p_memstat_state & P_MEMSTAT_MEMLIMIT_ACTIVE_FATAL) {
		p_entry->memlimit_active_attr |= MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;
	}

	/*
	 * Get the inactive limit and attributes
	 */
	if (p->p_memstat_memlimit_inactive <= 0) {
		task_convert_phys_footprint_limit(-1, &p_entry->memlimit_inactive);
	} else {
		p_entry->memlimit_inactive = p->p_memstat_memlimit_inactive;
	}
	if (p->p_memstat_state & P_MEMSTAT_MEMLIMIT_INACTIVE_FATAL) {
		p_entry->memlimit_inactive_attr |= MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;
	}
}

/*
 * When getting the memlimit settings, we can't simply call task_get_phys_footprint_limit().
 * That gets the proc's cached memlimit and there is no guarantee that the active/inactive
 * limits will be the same in the no-limit case.  Instead we convert limits <= 0 using
 * task_convert_phys_footprint_limit(). It computes the same limit value that would be written
 * to the task's ledgers via task_set_phys_footprint_limit().
 */
static int
memorystatus_cmd_get_memlimit_properties(pid_t pid, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval)
{
	memorystatus_memlimit_properties2_t mmp_entry;

	/* Validate inputs */
	if ((pid == 0) || (buffer == USER_ADDR_NULL) ||
	    ((buffer_size != sizeof(memorystatus_memlimit_properties_t)) &&
	    (buffer_size != sizeof(memorystatus_memlimit_properties2_t)))) {
		return EINVAL;
	}

	memset(&mmp_entry, 0, sizeof(memorystatus_memlimit_properties2_t));

	proc_t p = proc_find(pid);
	if (!p) {
		return ESRCH;
	}

	/*
	 * Get the active limit and attributes.
	 * No locks taken since we hold a reference to the proc.
	 */

	memorystatus_get_memlimit_properties_internal(p, &mmp_entry.v1);

#if CONFIG_JETSAM
#if DEVELOPMENT || DEBUG
	/*
	 * Get the limit increased via SPI
	 */
	mmp_entry.memlimit_increase = roundToNearestMB(p->p_memlimit_increase);
	mmp_entry.memlimit_increase_bytes = p->p_memlimit_increase;
#endif /* DEVELOPMENT || DEBUG */
#endif /* CONFIG_JETSAM */

	proc_rele(p);

	int error = copyout(&mmp_entry, buffer, buffer_size);

	return error;
}


/*
 * SPI for kbd - pr24956468
 * This is a very simple snapshot that calculates how much a
 * process's phys_footprint exceeds a specific memory limit.
 * Only the inactive memory limit is supported for now.
 * The delta is returned as bytes in excess or zero.
 */
static int
memorystatus_cmd_get_memlimit_excess_np(pid_t pid, uint32_t flags, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval)
{
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

	memlimit_bytes = memlimit_mb * 1024 * 1024;     /* MB to bytes */

	/*
	 * Computed delta always returns >= 0 bytes
	 */
	if (footprint_in_bytes > memlimit_bytes) {
		delta_in_bytes = footprint_in_bytes - memlimit_bytes;
	}

	error = copyout(&delta_in_bytes, buffer, sizeof(delta_in_bytes));

	return error;
}


static int
memorystatus_cmd_get_pressure_status(int32_t *retval)
{
	int error;

	/* Need privilege for check */
	error = priv_check_cred(kauth_cred_get(), PRIV_VM_PRESSURE, 0);
	if (error) {
		return error;
	}

	/* Inherently racy, so it's not worth taking a lock here */
	*retval = (kVMPressureNormal != memorystatus_vm_pressure_level) ? 1 : 0;

	return error;
}

int
memorystatus_get_pressure_status_kdp()
{
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

#if CONFIG_JETSAM
static int
memorystatus_cmd_set_jetsam_memory_limit(pid_t pid, int32_t high_water_mark, __unused int32_t *retval, boolean_t is_fatal_limit)
{
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
	return error;
}
#endif /* CONFIG_JETSAM */

static int
memorystatus_set_memlimit_properties_internal(proc_t p, memorystatus_memlimit_properties_t *p_entry)
{
	int error = 0;

	LCK_MTX_ASSERT(proc_list_mlock, LCK_MTX_ASSERT_OWNED);

	/*
	 * Store the active limit variants in the proc.
	 */
	SET_ACTIVE_LIMITS_LOCKED(p, p_entry->memlimit_active, p_entry->memlimit_active_attr);

	/*
	 * Store the inactive limit variants in the proc.
	 */
	SET_INACTIVE_LIMITS_LOCKED(p, p_entry->memlimit_inactive, p_entry->memlimit_inactive_attr);

	/*
	 * Enforce appropriate limit variant by updating the cached values
	 * and writing the ledger.
	 * Limit choice is based on process active/inactive state.
	 */

	if (memorystatus_highwater_enabled) {
		boolean_t is_fatal;
		boolean_t use_active;

		if (proc_jetsam_state_is_active_locked(p) == TRUE) {
			CACHE_ACTIVE_LIMITS_LOCKED(p, is_fatal);
			use_active = TRUE;
		} else {
			CACHE_INACTIVE_LIMITS_LOCKED(p, is_fatal);
			use_active = FALSE;
		}

		/* Enforce the limit by writing to the ledgers */
		error = (task_set_phys_footprint_limit_internal(p->task, ((p->p_memstat_memlimit > 0) ? p->p_memstat_memlimit : -1), NULL, use_active, is_fatal) == 0) ? 0 : EINVAL;

		MEMORYSTATUS_DEBUG(3, "memorystatus_set_memlimit_properties: new limit on pid %d (%dMB %s) current priority (%d) dirty_state?=0x%x %s\n",
		    p->p_pid, (p->p_memstat_memlimit > 0 ? p->p_memstat_memlimit : -1),
		    (p->p_memstat_state & P_MEMSTAT_FATAL_MEMLIMIT ? "F " : "NF"), p->p_memstat_effectivepriority, p->p_memstat_dirty,
		    (p->p_memstat_dirty ? ((p->p_memstat_dirty & P_DIRTY) ? "isdirty" : "isclean") : ""));
		DTRACE_MEMORYSTATUS2(memorystatus_set_memlimit, proc_t, p, int32_t, (p->p_memstat_memlimit > 0 ? p->p_memstat_memlimit : -1));
	}

	return error;
}

static int
memorystatus_set_memlimit_properties(pid_t pid, memorystatus_memlimit_properties_t *entry)
{
	memorystatus_memlimit_properties_t set_entry;

	proc_t p = proc_find(pid);
	if (!p) {
		return ESRCH;
	}

	/*
	 * Check for valid attribute flags.
	 */
	const uint32_t valid_attrs = MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;
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
	set_entry.memlimit_active = entry->memlimit_active;
	set_entry.memlimit_active_attr = entry->memlimit_active_attr & MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;

	/*
	 * Setup the inactive memlimit properties
	 */
	set_entry.memlimit_inactive = entry->memlimit_inactive;
	set_entry.memlimit_inactive_attr = entry->memlimit_inactive_attr & MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;

	/*
	 * Setting a limit of <= 0 implies that the process has no
	 * high-water-mark and has no per-task-limit.  That means
	 * the system_wide task limit is in place, which by the way,
	 * is always fatal.
	 */

	if (set_entry.memlimit_active <= 0) {
		/*
		 * Enforce the fatal system_wide task limit while process is active.
		 */
		set_entry.memlimit_active = -1;
		set_entry.memlimit_active_attr = MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;
	}
#if CONFIG_JETSAM
#if DEVELOPMENT || DEBUG
	else {
		/* add the current increase to it, for roots */
		set_entry.memlimit_active += roundToNearestMB(p->p_memlimit_increase);
	}
#endif /* DEVELOPMENT || DEBUG */
#endif /* CONFIG_JETSAM */

	if (set_entry.memlimit_inactive <= 0) {
		/*
		 * Enforce the fatal system_wide task limit while process is inactive.
		 */
		set_entry.memlimit_inactive = -1;
		set_entry.memlimit_inactive_attr = MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;
	}
#if CONFIG_JETSAM
#if DEVELOPMENT || DEBUG
	else {
		/* add the current increase to it, for roots */
		set_entry.memlimit_inactive += roundToNearestMB(p->p_memlimit_increase);
	}
#endif /* DEVELOPMENT || DEBUG */
#endif /* CONFIG_JETSAM */

	proc_list_lock();

	int error = memorystatus_set_memlimit_properties_internal(p, &set_entry);

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

static int
memorystatus_get_process_is_managed(pid_t pid, int *is_managed)
{
	proc_t p = NULL;

	/* Validate inputs */
	if (pid == 0) {
		return EINVAL;
	}

	p = proc_find(pid);
	if (!p) {
		return ESRCH;
	}

	proc_list_lock();
	*is_managed = ((p->p_memstat_state & P_MEMSTAT_MANAGED) ? 1 : 0);
	proc_rele_locked(p);
	proc_list_unlock();

	return 0;
}

static int
memorystatus_set_process_is_managed(pid_t pid, boolean_t set_managed)
{
	proc_t p = NULL;

	/* Validate inputs */
	if (pid == 0) {
		return EINVAL;
	}

	p = proc_find(pid);
	if (!p) {
		return ESRCH;
	}

	proc_list_lock();
	if (set_managed == TRUE) {
		p->p_memstat_state |= P_MEMSTAT_MANAGED;
		/*
		 * The P_MEMSTAT_MANAGED bit is set by assertiond for Apps.
		 * Also opt them in to being frozen (they might have started
		 * off with the P_MEMSTAT_FREEZE_DISABLED bit set.)
		 */
		p->p_memstat_state &= ~P_MEMSTAT_FREEZE_DISABLED;
	} else {
		p->p_memstat_state &= ~P_MEMSTAT_MANAGED;
	}
	proc_rele_locked(p);
	proc_list_unlock();

	return 0;
}

int
memorystatus_control(struct proc *p __unused, struct memorystatus_control_args *args, int *ret)
{
	int error = EINVAL;
	boolean_t skip_auth_check = FALSE;
	os_reason_t jetsam_reason = OS_REASON_NULL;

#if !CONFIG_JETSAM
    #pragma unused(ret)
    #pragma unused(jetsam_reason)
#endif

	/* We don't need entitlements if we're setting/ querying the freeze preference for a process. Skip the check below. */
	if (args->command == MEMORYSTATUS_CMD_SET_PROCESS_IS_FREEZABLE || args->command == MEMORYSTATUS_CMD_GET_PROCESS_IS_FREEZABLE) {
		skip_auth_check = TRUE;
	}

	/* Need to be root or have entitlement. */
	if (!kauth_cred_issuser(kauth_cred_get()) && !IOTaskHasEntitlement(current_task(), MEMORYSTATUS_ENTITLEMENT) && !skip_auth_check) {
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
		error = memorystatus_cmd_get_priority_list(args->pid, args->buffer, args->buffersize, ret);
		break;
	case MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES:
		error = memorystatus_cmd_set_priority_properties(args->pid, args->flags, args->buffer, args->buffersize, ret);
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
#if CONFIG_JETSAM
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
#endif /* CONFIG_JETSAM */
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
#if CONFIG_JETSAM
	case MEMORYSTATUS_CMD_SET_JETSAM_PANIC_BITS:
		error = memorystatus_cmd_set_panic_bits(args->buffer, args->buffersize);
		break;
#endif /* CONFIG_JETSAM */
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
	case MEMORYSTATUS_CMD_GET_AGGRESSIVE_JETSAM_LENIENT_MODE:
		*ret = (memorystatus_aggressive_jetsam_lenient ? 1 : 0);
		error = 0;
		break;
	case MEMORYSTATUS_CMD_PRIVILEGED_LISTENER_ENABLE:
	case MEMORYSTATUS_CMD_PRIVILEGED_LISTENER_DISABLE:
		error = memorystatus_low_mem_privileged_listener(args->command);
		break;

	case MEMORYSTATUS_CMD_ELEVATED_INACTIVEJETSAMPRIORITY_ENABLE:
	case MEMORYSTATUS_CMD_ELEVATED_INACTIVEJETSAMPRIORITY_DISABLE:
		error = memorystatus_update_inactive_jetsam_priority_band(args->pid, args->command, JETSAM_PRIORITY_ELEVATED_INACTIVE, args->flags ? TRUE : FALSE);
		break;
	case MEMORYSTATUS_CMD_SET_PROCESS_IS_MANAGED:
		error = memorystatus_set_process_is_managed(args->pid, args->flags);
		break;

	case MEMORYSTATUS_CMD_GET_PROCESS_IS_MANAGED:
		error = memorystatus_get_process_is_managed(args->pid, ret);
		break;

#if CONFIG_FREEZE
	case MEMORYSTATUS_CMD_SET_PROCESS_IS_FREEZABLE:
		error = memorystatus_set_process_is_freezable(args->pid, args->flags ? TRUE : FALSE);
		break;

	case MEMORYSTATUS_CMD_GET_PROCESS_IS_FREEZABLE:
		error = memorystatus_get_process_is_freezable(args->pid, ret);
		break;

#if DEVELOPMENT || DEBUG
	case MEMORYSTATUS_CMD_FREEZER_CONTROL:
		error = memorystatus_freezer_control(args->flags, args->buffer, args->buffersize, ret);
		break;
#endif /* DEVELOPMENT || DEBUG */
#endif /* CONFIG_FREEZE */

#if CONFIG_JETSAM
#if DEVELOPMENT || DEBUG
	case MEMORYSTATUS_CMD_INCREASE_JETSAM_TASK_LIMIT:
		error = memorystatus_cmd_increase_jetsam_task_limit(args->pid, args->flags);
		break;
#endif /* DEVELOPMENT */
#endif /* CONFIG_JETSAM */

	default:
		break;
	}

out:
	return error;
}

/* Coalition support */

/* sorting info for a particular priority bucket */
typedef struct memstat_sort_info {
	coalition_t     msi_coal;
	uint64_t        msi_page_count;
	pid_t           msi_pid;
	int             msi_ntasks;
} memstat_sort_info_t;

/*
 * qsort from smallest page count to largest page count
 *
 * return < 0 for a < b
 *          0 for a == b
 *        > 0 for a > b
 */
static int
memstat_asc_cmp(const void *a, const void *b)
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
#define MAX_SORT_PIDS           80
#define MAX_COAL_LEADERS        10

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
		return 0;
	}

	/*
	 * Clear the array that holds coalition leader information
	 */
	for (i = 0; i < MAX_COAL_LEADERS; i++) {
		leaders[i].msi_coal = COALITION_NULL;
		leaders[i].msi_page_count = 0;          /* will hold total coalition page count */
		leaders[i].msi_pid = 0;                 /* will hold coalition leader pid */
		leaders[i].msi_ntasks = 0;              /* will hold the number of tasks in a coalition */
	}

	p = memorystatus_get_first_proc_locked(&b, FALSE);
	while (p) {
		coal = task_get_coalition(p->task, COALITION_TYPE_JETSAM);
		if (coalition_is_leader(p->task, coal)) {
			if (nleaders < MAX_COAL_LEADERS) {
				int coal_ntasks = 0;
				uint64_t coal_page_count = coalition_get_page_count(coal, &coal_ntasks);
				leaders[nleaders].msi_coal = coal;
				leaders[nleaders].msi_page_count = coal_page_count;
				leaders[nleaders].msi_pid = p->p_pid;           /* the coalition leader */
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
		p = memorystatus_get_next_proc_locked(&b, p, FALSE);
	}

	if (nleaders == 0) {
		/* Nothing to sort */
		return 0;
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
	for (i = 0; i < nleaders; i++) {
		/* a bit of bookkeeping */
		pids_moved = 0;

		/* Coalition leaders are jetsammed last, so move into place first */
		pid_list[0] = leaders[i].msi_pid;
		pids_moved += memorystatus_move_list_locked(bucket_index, pid_list, 1);

		/* xpc services should jetsam after extensions */
		ntasks = coalition_get_pid_list(leaders[i].msi_coal, COALITION_ROLEMASK_XPC,
		    coal_sort_order, pid_list, MAX_SORT_PIDS);

		if (ntasks > 0) {
			pids_moved += memorystatus_move_list_locked(bucket_index, pid_list,
			    (ntasks <= MAX_SORT_PIDS ? ntasks : MAX_SORT_PIDS));
		}

		/* extensions should jetsam after unmarked processes */
		ntasks = coalition_get_pid_list(leaders[i].msi_coal, COALITION_ROLEMASK_EXT,
		    coal_sort_order, pid_list, MAX_SORT_PIDS);

		if (ntasks > 0) {
			pids_moved += memorystatus_move_list_locked(bucket_index, pid_list,
			    (ntasks <= MAX_SORT_PIDS ? ntasks : MAX_SORT_PIDS));
		}

		/* undefined coalition members should be the first to jetsam */
		ntasks = coalition_get_pid_list(leaders[i].msi_coal, COALITION_ROLEMASK_UNDEF,
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

	return total_pids_moved;
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
		return 0;
	}

	if (bucket_index >= MEMSTAT_BUCKET_COUNT) {
		return 0;
	}

	current_bucket = &memstat_bucket[bucket_index];
	for (i = 0; i < list_sz; i++) {
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
	return found_pids;
}

int
memorystatus_get_proccnt_upto_priority(int32_t max_bucket_index)
{
	int32_t i = JETSAM_PRIORITY_IDLE;
	int count = 0;

	if (max_bucket_index >= MEMSTAT_BUCKET_COUNT) {
		return -1;
	}

	while (i <= max_bucket_index) {
		count += memstat_bucket[i++].count;
	}

	return count;
}

int
memorystatus_update_priority_for_appnap(proc_t p, boolean_t is_appnap)
{
#if !CONFIG_JETSAM
	if (!p || (!isApp(p)) || (p->p_memstat_state & (P_MEMSTAT_INTERNAL | P_MEMSTAT_MANAGED))) {
		/*
		 * Ineligible processes OR system processes e.g. launchd.
		 *
		 * We also skip processes that have the P_MEMSTAT_MANAGED bit set, i.e.
		 * they're managed by assertiond. These are iOS apps that have been ported
		 * to macOS. assertiond might be in the process of modifying the app's
		 * priority / memory limit - so it might have the proc_list lock, and then try
		 * to take the task lock. Meanwhile we've entered this function with the task lock
		 * held, and we need the proc_list lock below. So we'll deadlock with assertiond.
		 *
		 * It should be fine to read the P_MEMSTAT_MANAGED bit without the proc_list
		 * lock here, since assertiond only sets this bit on process launch.
		 */
		return -1;
	}

	/*
	 * For macOS only:
	 * We would like to use memorystatus_update() here to move the processes
	 * within the bands. Unfortunately memorystatus_update() calls
	 * memorystatus_update_priority_locked() which uses any band transitions
	 * as an indication to modify ledgers. For that it needs the task lock
	 * and since we came into this function with the task lock held, we'll deadlock.
	 *
	 * Unfortunately we can't completely disable ledger updates  because we still
	 * need the ledger updates for a subset of processes i.e. daemons.
	 * When all processes on all platforms support memory limits, we can simply call
	 * memorystatus_update().
	 *
	 * It also has some logic to deal with 'aging' which, currently, is only applicable
	 * on CONFIG_JETSAM configs. So, till every platform has CONFIG_JETSAM we'll need
	 * to do this explicit band transition.
	 */

	memstat_bucket_t *current_bucket, *new_bucket;
	int32_t priority = 0;

	proc_list_lock();

	if (((p->p_listflag & P_LIST_EXITED) != 0) ||
	    (p->p_memstat_state & (P_MEMSTAT_ERROR | P_MEMSTAT_TERMINATED))) {
		/*
		 * If the process is on its way out OR
		 * jetsam has alread tried and failed to kill this process,
		 * let's skip the whole jetsam band transition.
		 */
		proc_list_unlock();
		return 0;
	}

	if (is_appnap) {
		current_bucket = &memstat_bucket[p->p_memstat_effectivepriority];
		new_bucket = &memstat_bucket[JETSAM_PRIORITY_IDLE];
		priority = JETSAM_PRIORITY_IDLE;
	} else {
		if (p->p_memstat_effectivepriority != JETSAM_PRIORITY_IDLE) {
			/*
			 * It is possible that someone pulled this process
			 * out of the IDLE band without updating its app-nap
			 * parameters.
			 */
			proc_list_unlock();
			return 0;
		}

		current_bucket = &memstat_bucket[JETSAM_PRIORITY_IDLE];
		new_bucket = &memstat_bucket[p->p_memstat_requestedpriority];
		priority = p->p_memstat_requestedpriority;
	}

	TAILQ_REMOVE(&current_bucket->list, p, p_memstat_list);
	current_bucket->count--;
	if (p->p_memstat_relaunch_flags & (P_MEMSTAT_RELAUNCH_HIGH)) {
		current_bucket->relaunch_high_count--;
	}
	TAILQ_INSERT_TAIL(&new_bucket->list, p, p_memstat_list);
	new_bucket->count++;
	if (p->p_memstat_relaunch_flags & (P_MEMSTAT_RELAUNCH_HIGH)) {
		new_bucket->relaunch_high_count++;
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

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_CHANGE_PRIORITY), p->p_pid, priority, p->p_memstat_effectivepriority, 0, 0);

	p->p_memstat_effectivepriority = priority;

	proc_list_unlock();

	return 0;

#else /* !CONFIG_JETSAM */
	#pragma unused(p)
	#pragma unused(is_appnap)
	return -1;
#endif /* !CONFIG_JETSAM */
}

uint64_t
memorystatus_available_memory_internal(proc_t p)
{
#ifdef XNU_TARGET_OS_OSX
	#pragma unused(p)
	return 0;
#else
	const uint64_t footprint_in_bytes = get_task_phys_footprint(p->task);
	int32_t memlimit_mb;
	int64_t memlimit_bytes;
	int64_t rc;

	if (isApp(p) == FALSE) {
		return 0;
	}

	if (p->p_memstat_memlimit > 0) {
		memlimit_mb = p->p_memstat_memlimit;
	} else if (task_convert_phys_footprint_limit(-1, &memlimit_mb) != KERN_SUCCESS) {
		return 0;
	}

	if (memlimit_mb <= 0) {
		memlimit_bytes = INT_MAX & ~((1 << 20) - 1);
	} else {
		memlimit_bytes = ((int64_t) memlimit_mb) << 20;
	}

	rc = memlimit_bytes - footprint_in_bytes;

	return (rc >= 0) ? rc : 0;
#endif
}

int
memorystatus_available_memory(struct proc *p, __unused struct memorystatus_available_memory_args *args, uint64_t *ret)
{
	*ret = memorystatus_available_memory_internal(p);

	return 0;
}

#if CONFIG_JETSAM
#if DEVELOPMENT || DEBUG
static int
memorystatus_cmd_increase_jetsam_task_limit(pid_t pid, uint32_t byte_increase)
{
	memorystatus_memlimit_properties_t mmp_entry;

	/* Validate inputs */
	if ((pid == 0) || (byte_increase == 0)) {
		return EINVAL;
	}

	proc_t p = proc_find(pid);

	if (!p) {
		return ESRCH;
	}

	const uint32_t current_memlimit_increase = roundToNearestMB(p->p_memlimit_increase);
	const uint32_t page_aligned_increase = round_page(p->p_memlimit_increase + byte_increase); /* round to page */

	proc_list_lock();

	memorystatus_get_memlimit_properties_internal(p, &mmp_entry);

	if (mmp_entry.memlimit_active > 0) {
		mmp_entry.memlimit_active -= current_memlimit_increase;
		mmp_entry.memlimit_active += roundToNearestMB(page_aligned_increase);
	}

	if (mmp_entry.memlimit_inactive > 0) {
		mmp_entry.memlimit_inactive -= current_memlimit_increase;
		mmp_entry.memlimit_inactive += roundToNearestMB(page_aligned_increase);
	}

	/*
	 * Store the updated delta limit in the proc.
	 */
	p->p_memlimit_increase = page_aligned_increase;

	int error = memorystatus_set_memlimit_properties_internal(p, &mmp_entry);

	proc_list_unlock();
	proc_rele(p);

	return error;
}
#endif /* DEVELOPMENT */
#endif /* CONFIG_JETSAM */

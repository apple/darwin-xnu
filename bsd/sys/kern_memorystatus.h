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
 */

#ifndef SYS_MEMORYSTATUS_H
#define SYS_MEMORYSTATUS_H

#include <stdint.h>
#include <sys/time.h>
#include <sys/proc.h>
#include <sys/param.h>

#define MEMORYSTATUS_ENTITLEMENT "com.apple.private.memorystatus"

#define JETSAM_PRIORITY_REVISION                  2

#define JETSAM_PRIORITY_IDLE_HEAD                -2
/* The value -1 is an alias to JETSAM_PRIORITY_DEFAULT */
#define JETSAM_PRIORITY_IDLE                      0
#define JETSAM_PRIORITY_IDLE_DEFERRED		  1 /* Keeping this around till all xnu_quick_tests can be moved away from it.*/
#define JETSAM_PRIORITY_AGING_BAND1		  JETSAM_PRIORITY_IDLE_DEFERRED
#define JETSAM_PRIORITY_BACKGROUND_OPPORTUNISTIC  2
#define JETSAM_PRIORITY_AGING_BAND2		  JETSAM_PRIORITY_BACKGROUND_OPPORTUNISTIC
#define JETSAM_PRIORITY_BACKGROUND                3
#define JETSAM_PRIORITY_ELEVATED_INACTIVE	  JETSAM_PRIORITY_BACKGROUND
#define JETSAM_PRIORITY_MAIL                      4
#define JETSAM_PRIORITY_PHONE                     5
#define JETSAM_PRIORITY_UI_SUPPORT                8
#define JETSAM_PRIORITY_FOREGROUND_SUPPORT        9
#define JETSAM_PRIORITY_FOREGROUND               10
#define JETSAM_PRIORITY_AUDIO_AND_ACCESSORY      12
#define JETSAM_PRIORITY_CONDUCTOR                13
#define JETSAM_PRIORITY_HOME                     16
#define JETSAM_PRIORITY_EXECUTIVE                17
#define JETSAM_PRIORITY_IMPORTANT                18
#define JETSAM_PRIORITY_CRITICAL                 19

#define JETSAM_PRIORITY_MAX                      21

/* TODO - tune. This should probably be lower priority */
#define JETSAM_PRIORITY_DEFAULT                  18
#define JETSAM_PRIORITY_TELEPHONY                19

/* Compatibility */
#define DEFAULT_JETSAM_PRIORITY                  18

#define DEFERRED_IDLE_EXIT_TIME_SECS             10

#define KEV_MEMORYSTATUS_SUBCLASS                 3

enum {
	kMemorystatusLevelNote = 1,
	kMemorystatusSnapshotNote = 2,
	kMemorystatusFreezeNote = 3,
	kMemorystatusPressureNote = 4
};

enum {
	kMemorystatusLevelAny = -1,
	kMemorystatusLevelNormal = 0,
	kMemorystatusLevelWarning = 1,
	kMemorystatusLevelUrgent = 2,
	kMemorystatusLevelCritical = 3
};

typedef struct memorystatus_priority_entry {
	pid_t pid;
	int32_t priority;
	uint64_t user_data;
	int32_t limit;	/* MB */
	uint32_t state;
} memorystatus_priority_entry_t;

typedef struct memorystatus_kernel_stats {
	uint32_t free_pages;
	uint32_t active_pages;
	uint32_t inactive_pages;
	uint32_t throttled_pages;
	uint32_t purgeable_pages;
	uint32_t wired_pages;
	uint32_t speculative_pages;
	uint32_t filebacked_pages;
	uint32_t anonymous_pages;
	uint32_t compressor_pages;
	uint64_t compressions;
	uint64_t decompressions;
	uint64_t total_uncompressed_pages_in_compressor;
} memorystatus_kernel_stats_t;

/*
** This is a variable-length struct.
** Allocate a buffer of the size returned by the sysctl, cast to a memorystatus_snapshot_t *
*/

typedef struct jetsam_snapshot_entry {
	pid_t    pid;
	char     name[(2*MAXCOMLEN)+1];
	int32_t  priority;
	uint32_t state;
	uint32_t fds;
	uint8_t  uuid[16];
	uint64_t user_data;
	uint64_t killed;
	uint64_t pages;
	uint64_t max_pages;
	uint64_t max_pages_lifetime;
	uint64_t purgeable_pages;
	uint64_t jse_internal_pages;
	uint64_t jse_internal_compressed_pages;
	uint64_t jse_purgeable_nonvolatile_pages;
	uint64_t jse_purgeable_nonvolatile_compressed_pages;
	uint64_t jse_alternate_accounting_pages;
	uint64_t jse_alternate_accounting_compressed_pages;
	uint64_t jse_iokit_mapped_pages;
	uint64_t jse_page_table_pages;
	uint64_t jse_memory_region_count;
	uint64_t jse_gencount;			/* memorystatus_thread generation counter */
	uint64_t jse_starttime;			/* absolute time when process starts */
	uint64_t jse_killtime;			/* absolute time when jetsam chooses to kill a process */
	uint64_t jse_idle_delta;		/* time spent in idle band */
	uint64_t jse_coalition_jetsam_id;	/* we only expose coalition id for COALITION_TYPE_JETSAM */
	struct timeval cpu_time;
} memorystatus_jetsam_snapshot_entry_t;

typedef struct jetsam_snapshot {
	uint64_t snapshot_time;			/* absolute time snapshot was initialized */
	uint64_t notification_time;		/* absolute time snapshot was consumed */
	uint64_t js_gencount;			/* memorystatus_thread generation counter */
	memorystatus_kernel_stats_t stats;	/* system stat when snapshot is initialized */
	size_t entry_count;
	memorystatus_jetsam_snapshot_entry_t entries[];
} memorystatus_jetsam_snapshot_t;

typedef struct memorystatus_freeze_entry {
 	int32_t pid;
 	uint32_t flags;
 	uint32_t pages;
} memorystatus_freeze_entry_t;

/* TODO - deprecate; see <rdar://problem/12969599> */
#define kMaxSnapshotEntries 192

/* State */
#define kMemorystatusSuspended        0x01
#define kMemorystatusFrozen           0x02
#define kMemorystatusWasThawed        0x04
#define kMemorystatusTracked          0x08
#define kMemorystatusSupportsIdleExit 0x10
#define kMemorystatusDirty            0x20

/* Cause */
enum {
	kMemorystatusKilled = 1,
	kMemorystatusKilledHiwat,
 	kMemorystatusKilledVnodes,
  	kMemorystatusKilledVMPageShortage,
  	kMemorystatusKilledVMThrashing,
  	kMemorystatusKilledFCThrashing,
  	kMemorystatusKilledPerProcessLimit,
	kMemorystatusKilledDiagnostic,
	kMemorystatusKilledIdleExit
};

/* Jetsam exit reason definitions */
#define JETSAM_REASON_INVALID			0
#define JETSAM_REASON_GENERIC			1
#define JETSAM_REASON_MEMORY_HIGHWATER		2
#define JETSAM_REASON_VNODE			3
#define JETSAM_REASON_MEMORY_VMPAGESHORTAGE	4
#define JETSAM_REASON_MEMORY_VMTHRASHING	5
#define JETSAM_REASON_MEMORY_FCTHRASHING	6
#define JETSAM_REASON_MEMORY_PERPROCESSLIMIT	7
#define JETSAM_REASON_MEMORY_DIAGNOSTIC		8
#define JETSAM_REASON_MEMORY_IDLE_EXIT		9
#define JETSAM_REASON_CPULIMIT			10

/* Temporary, to prevent the need for a linked submission of ReportCrash */
/* Remove when <rdar://problem/13210532> has been integrated */
enum {
	kMemorystatusKilledVM = kMemorystatusKilledVMPageShortage
};

/* Memorystatus control */
#define MEMORYSTATUS_BUFFERSIZE_MAX 65536

#ifndef KERNEL
int memorystatus_get_level(user_addr_t level);
int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);
#endif

/* Commands */
#define MEMORYSTATUS_CMD_GET_PRIORITY_LIST            1
#define MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES      2
#define MEMORYSTATUS_CMD_GET_JETSAM_SNAPSHOT          3
#define MEMORYSTATUS_CMD_GET_PRESSURE_STATUS          4
#define MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK   5    /* Set active memory limit = inactive memory limit, both non-fatal	*/
#define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT	      6    /* Set active memory limit = inactive memory limit, both fatal	*/
#define MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES      7    /* Set memory limits plus attributes independently			*/
#define MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES      8    /* Get memory limits plus attributes					*/
#define MEMORYSTATUS_CMD_PRIVILEGED_LISTENER_ENABLE   9    /* Set the task's status as a privileged listener w.r.t memory notifications  */
#define MEMORYSTATUS_CMD_PRIVILEGED_LISTENER_DISABLE  10   /* Reset the task's status as a privileged listener w.r.t memory notifications  */
#define MEMORYSTATUS_CMD_AGGRESSIVE_JETSAM_LENIENT_MODE_ENABLE  11   /* Enable the 'lenient' mode for aggressive jetsam. See comments in kern_memorystatus.c near the top. */
#define MEMORYSTATUS_CMD_AGGRESSIVE_JETSAM_LENIENT_MODE_DISABLE 12   /* Disable the 'lenient' mode for aggressive jetsam. */
#define MEMORYSTATUS_CMD_GET_MEMLIMIT_EXCESS          13   /* Compute how much a process's phys_footprint exceeds inactive memory limit */
#define MEMORYSTATUS_CMD_ELEVATED_INACTIVEJETSAMPRIORITY_ENABLE 	14
#define MEMORYSTATUS_CMD_ELEVATED_INACTIVEJETSAMPRIORITY_DISABLE 	15

/* Commands that act on a group of processes */
#define MEMORYSTATUS_CMD_GRP_SET_PROPERTIES           100

#if PRIVATE
/* Test commands */

/* Trigger forced jetsam */
#define MEMORYSTATUS_CMD_TEST_JETSAM		1000
#define MEMORYSTATUS_CMD_TEST_JETSAM_SORT	1001

/* Panic on jetsam options */
typedef struct memorystatus_jetsam_panic_options {
	uint32_t data;
	uint32_t mask;
} memorystatus_jetsam_panic_options_t;

#define MEMORYSTATUS_CMD_SET_JETSAM_PANIC_BITS        1002

/* Select priority band sort order */
#define JETSAM_SORT_NOSORT	0
#define JETSAM_SORT_DEFAULT	1

#endif /* PRIVATE */

/*
 * For use with memorystatus_control:
 * MEMORYSTATUS_CMD_GET_JETSAM_SNAPSHOT
 *
 * A jetsam snapshot is initialized when a non-idle
 * jetsam event occurs.  The data is held in the
 * buffer until it is reaped. This is the default
 * behavior.
 *
 * Flags change the default behavior:
 *	Demand mode - this is an on_demand snapshot,
 *	meaning data is populated upon request.
 *
 *	Boot mode - this is a snapshot of
 *	memstats collected before loading the
 *	init program.  Once collected, these
 *	stats do not change.  In this mode,
 *	the snapshot entry_count is always 0.
 *
 * Snapshots are inherently racey between request
 * for buffer size and actual data compilation.
*/

/* Flags */
#define MEMORYSTATUS_SNAPSHOT_ON_DEMAND		0x1	/* A populated snapshot buffer is returned on demand */
#define MEMORYSTATUS_SNAPSHOT_AT_BOOT		0x2	/* Returns a snapshot with memstats collected at boot */


/*
 * For use with memorystatus_control:
 * MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES
 */
typedef struct memorystatus_priority_properties {
	int32_t  priority;
	uint64_t user_data;
} memorystatus_priority_properties_t;

/*
 * For use with memorystatus_control:
 * MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES
 * MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES
 */
typedef struct memorystatus_memlimit_properties {
	int32_t memlimit_active;		/* jetsam memory limit (in MB) when process is active */
	uint32_t memlimit_active_attr;
	int32_t memlimit_inactive;		/* jetsam memory limit (in MB) when process is inactive */
	uint32_t memlimit_inactive_attr;
} memorystatus_memlimit_properties_t;

#define MEMORYSTATUS_MEMLIMIT_ATTR_FATAL	0x1	/* if set, exceeding the memlimit is fatal */

#ifdef XNU_KERNEL_PRIVATE

/*
 * A process will be killed immediately if it crosses a memory limit marked as fatal.
 * Fatal limit types are the
 *	- default system-wide task limit
 *	- per-task custom memory limit
 *
 * A process with a non-fatal memory limit can exceed that limit, but becomes an early
 * candidate for jetsam when the device is under memory pressure.
 * Non-fatal limit types are the
 *	- high-water-mark limit
 *
 * P_MEMSTAT_MEMLIMIT_BACKGROUND is translated in posix_spawn as
 *	the fatal system_wide task limit when active
 * 	non-fatal inactive limit based on limit provided.
 *	This is necessary for backward compatibility until the
 * 	the flag can be considered obsolete.
 *
 * Processes that opt into dirty tracking are evaluated
 * based on clean vs dirty state.
 *      dirty ==> active
 *      clean ==> inactive
 *
 * Processes that do not opt into dirty tracking are
 * evalulated based on priority level.
 *      Foreground or above ==> active
 *      Below Foreground    ==> inactive
 */

/*
 * p_memstat_state flag holds
 *	- in kernel process state and memlimit state
 */

#define P_MEMSTAT_SUSPENDED            0x00000001
#define P_MEMSTAT_FROZEN               0x00000002
#define P_MEMSTAT_NORECLAIM            0x00000004
#define P_MEMSTAT_ERROR                0x00000008
#define P_MEMSTAT_LOCKED               0x00000010
#define P_MEMSTAT_TERMINATED           0x00000020
#define P_MEMSTAT_NOTFIED              0x00000040
#define P_MEMSTAT_PRIORITYUPDATED      0x00000080
#define P_MEMSTAT_FOREGROUND           0x00000100
#define P_MEMSTAT_DIAG_SUSPENDED       0x00000200
#define P_MEMSTAT_PRIOR_THAW           0x00000400
#define P_MEMSTAT_MEMLIMIT_BACKGROUND  0x00000800 /* Task has a memory limit for when it's in the background. Used for a process' "high water mark".*/
#define P_MEMSTAT_INTERNAL             0x00001000
#define P_MEMSTAT_FATAL_MEMLIMIT                  0x00002000   /* current fatal state of the process's memlimit */
#define P_MEMSTAT_MEMLIMIT_ACTIVE_FATAL           0x00004000   /* if set, exceeding limit is fatal when the process is active   */
#define P_MEMSTAT_MEMLIMIT_INACTIVE_FATAL         0x00008000   /* if set, exceeding limit is fatal when the process is inactive */
#define P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND 	  0x00010000   /* if set, the process will go into this band & stay there when in the background instead
								  of the aging bands and/or the IDLE band. */

extern void memorystatus_init(void) __attribute__((section("__TEXT, initcode")));

extern void memorystatus_init_at_boot_snapshot(void);

extern int memorystatus_add(proc_t p, boolean_t locked);
extern int memorystatus_update(proc_t p, int priority, uint64_t user_data, boolean_t effective,
			       boolean_t update_memlimit, int32_t memlimit_active, boolean_t memlimit_active_is_fatal,
			       int32_t memlimit_inactive, boolean_t memlimit_inactive_is_fatal, boolean_t memlimit_background);

extern int memorystatus_remove(proc_t p, boolean_t locked);

int memorystatus_update_inactive_jetsam_priority_band(pid_t pid, uint32_t opflags, boolean_t effective_now);


extern int memorystatus_dirty_track(proc_t p, uint32_t pcontrol);
extern int memorystatus_dirty_set(proc_t p, boolean_t self, uint32_t pcontrol);
extern int memorystatus_dirty_get(proc_t p);
extern int memorystatus_dirty_clear(proc_t p, uint32_t pcontrol);

extern int memorystatus_on_terminate(proc_t p);

extern void memorystatus_on_suspend(proc_t p);
extern void memorystatus_on_resume(proc_t p);
extern void memorystatus_on_inactivity(proc_t p);

extern void memorystatus_on_pageout_scan_end(void);

/* Memorystatus kevent */

void memorystatus_kevent_init(lck_grp_t *grp, lck_attr_t *attr);

int memorystatus_knote_register(struct knote *kn);
void memorystatus_knote_unregister(struct knote *kn);

#if CONFIG_MEMORYSTATUS
void memorystatus_log_exception(const int max_footprint_mb, boolean_t memlimit_is_active, boolean_t memlimit_is_fatal);
void memorystatus_on_ledger_footprint_exceeded(int warning, boolean_t memlimit_is_active, boolean_t memlimit_is_fatal);
void proc_memstat_terminated(proc_t p, boolean_t set);
boolean_t memorystatus_proc_is_dirty_unsafe(void *v);
#endif /* CONFIG_MEMORYSTATUS */

#if CONFIG_JETSAM

int memorystatus_get_pressure_status_kdp(void);

typedef enum memorystatus_policy {
	kPolicyDefault        = 0x0, 
	kPolicyMoreFree       = 0x1,
	kPolicyDiagnoseAll    = 0x2,
	kPolicyDiagnoseFirst  = 0x4,
	kPolicyDiagnoseActive = (kPolicyDiagnoseAll | kPolicyDiagnoseFirst),
} memorystatus_policy_t;

extern int memorystatus_jetsam_wakeup;
extern unsigned int memorystatus_jetsam_running;

boolean_t memorystatus_kill_on_VM_page_shortage(boolean_t async);
boolean_t memorystatus_kill_on_VM_thrashing(boolean_t async);
boolean_t memorystatus_kill_on_FC_thrashing(boolean_t async);
boolean_t memorystatus_kill_on_vnode_limit(void);

void jetsam_on_ledger_cpulimit_exceeded(void);

void memorystatus_pages_update(unsigned int pages_avail);

#else /* CONFIG_JETSAM */

boolean_t memorystatus_idle_exit_from_VM(void);

#endif /* !CONFIG_JETSAM */

#ifdef CONFIG_FREEZE

#define FREEZE_PAGES_MIN   ( 1 * 1024 * 1024 / PAGE_SIZE)
#define FREEZE_PAGES_MAX   (16 * 1024 * 1024 / PAGE_SIZE)

#define FREEZE_SUSPENDED_THRESHOLD_LOW     2
#define FREEZE_SUSPENDED_THRESHOLD_DEFAULT 4

#define FREEZE_DAILY_MB_MAX_DEFAULT 	  1024

typedef struct throttle_interval_t {
	uint32_t mins;
	uint32_t burst_multiple;
	uint32_t pageouts;
	uint32_t max_pageouts;
	mach_timespec_t ts;
	boolean_t throttle;
} throttle_interval_t;

extern boolean_t memorystatus_freeze_enabled;
extern int memorystatus_freeze_wakeup;

extern void memorystatus_freeze_init(void) __attribute__((section("__TEXT, initcode")));
extern int  memorystatus_freeze_process_sync(proc_t p);
#endif /* CONFIG_FREEZE */

#if VM_PRESSURE_EVENTS

extern kern_return_t memorystatus_update_vm_pressure(boolean_t);

#if CONFIG_MEMORYSTATUS
/* Flags */
extern int memorystatus_low_mem_privileged_listener(uint32_t op_flags);
extern int memorystatus_send_pressure_note(int pid);
extern boolean_t memorystatus_is_foreground_locked(proc_t p);
extern boolean_t memorystatus_bg_pressure_eligible(proc_t p);
#endif /* CONFIG_MEMORYSTATUS */

#endif /* VM_PRESSURE_EVENTS */

#endif /* XNU_KERNEL_PRIVATE */

#endif /* SYS_MEMORYSTATUS_H */

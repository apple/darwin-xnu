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

#define JETSAM_PRIORITY_REVISION                  2

#define JETSAM_PRIORITY_IDLE                      0
#define JETSAM_PRIORITY_IDLE_DEFERRED             1
#define JETSAM_PRIORITY_BACKGROUND_OPPORTUNISTIC  2
#define JETSAM_PRIORITY_BACKGROUND                3
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
	int32_t limit;
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
	char     name[MAXCOMLEN+1];
	int32_t  priority;
	uint32_t pages;
	uint32_t max_pages;
	uint32_t state;
	uint32_t killed;
	uint64_t user_data;
	uint8_t  uuid[16];
	uint32_t fds;
} memorystatus_jetsam_snapshot_entry_t;

typedef struct jetsam_snapshot {
	uint64_t snapshot_time;
	uint64_t notification_time;
	memorystatus_kernel_stats_t stats;
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
  	kMemorystatusKilledPerProcessLimit,
	kMemorystatusKilledDiagnostic,
	kMemorystatusKilledIdleExit
};

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
#define MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK   5 /* TODO: deprecate */

#if PRIVATE
/* Test commands */

/* Trigger forced jetsam */
#define MEMORYSTATUS_CMD_TEST_JETSAM                  1000

/* Panic on jetsam options */
typedef struct memorystatus_jetsam_panic_options {
	uint32_t data;
	uint32_t mask;
} memorystatus_jetsam_panic_options_t;

#define MEMORYSTATUS_CMD_SET_JETSAM_PANIC_BITS        1001
#endif /* PRIVATE */

typedef struct memorystatus_priority_properties {
	int32_t  priority;
	uint64_t user_data;
} memorystatus_priority_properties_t;

#ifdef XNU_KERNEL_PRIVATE

/* p_memstat_state flags */

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
#define P_MEMSTAT_MEMLIMIT_BACKGROUND  0x00000800
#define P_MEMSTAT_INTERNAL             0x00001000

extern void memorystatus_init(void) __attribute__((section("__TEXT, initcode")));

extern int memorystatus_add(proc_t p, boolean_t locked);
extern int memorystatus_update(proc_t p, int priority, uint64_t user_data, boolean_t effective, boolean_t update_memlimit, int32_t memlimit, boolean_t memlimit_background);
extern int memorystatus_remove(proc_t p, boolean_t locked);

extern int memorystatus_dirty_track(proc_t p, uint32_t pcontrol);
extern int memorystatus_dirty_set(proc_t p, boolean_t self, uint32_t pcontrol);
extern int memorystatus_dirty_get(proc_t p);

extern int memorystatus_on_terminate(proc_t p);

extern void memorystatus_on_suspend(proc_t p);
extern void memorystatus_on_resume(proc_t p);
extern void memorystatus_on_inactivity(proc_t p);

extern void memorystatus_on_pageout_scan_end(void);

/* Memorystatus kevent */

void memorystatus_kevent_init(lck_grp_t *grp, lck_attr_t *attr);

int memorystatus_knote_register(struct knote *kn);
void memorystatus_knote_unregister(struct knote *kn);

#if CONFIG_JETSAM

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
boolean_t memorystatus_kill_on_vnode_limit(void);

void memorystatus_on_ledger_footprint_exceeded(int warning, const int max_footprint_mb);

void memorystatus_pages_update(unsigned int pages_avail);

extern boolean_t memorystatus_is_foreground_locked(proc_t p);

#else /* CONFIG_JETSAM */

boolean_t memorystatus_idle_exit_from_VM(void);

#endif /* !CONFIG_JETSAM */

#ifdef CONFIG_FREEZE

#define FREEZE_PAGES_MIN   ( 1 * 1024 * 1024 / PAGE_SIZE)
#define FREEZE_PAGES_MAX   (16 * 1024 * 1024 / PAGE_SIZE)

#define FREEZE_SUSPENDED_THRESHOLD_LOW     2
#define FREEZE_SUSPENDED_THRESHOLD_DEFAULT 4

#define FREEZE_DAILY_MB_MAX 	  1024
#define FREEZE_DAILY_PAGEOUTS_MAX (FREEZE_DAILY_MB_MAX * (1024 * 1024 / PAGE_SIZE))

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

#endif /* CONFIG_FREEZE */

#if VM_PRESSURE_EVENTS

#define MEMORYSTATUS_SUSPENDED_THRESHOLD  4

extern kern_return_t memorystatus_update_vm_pressure(boolean_t);

#if CONFIG_JETSAM
extern int memorystatus_send_pressure_note(int pid);
extern boolean_t memorystatus_bg_pressure_eligible(proc_t p);
#endif

#endif /* VM_PRESSURE_EVENTS */

#endif /* XNU_KERNEL_PRIVATE */

#endif /* SYS_MEMORYSTATUS_H */

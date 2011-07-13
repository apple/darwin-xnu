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

#include <sys/kern_event.h>
#include <sys/kern_memorystatus.h>

#include <kern/sched_prim.h>
#include <kern/kalloc.h>
#include <kern/debug.h>
#include <kern/lock.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <libkern/libkern.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <sys/proc.h>
#include <sys/signal.h>
#include <sys/signalvar.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <sys/tree.h>
#include <pexpert/pexpert.h>

#if CONFIG_FREEZE
#include <vm/vm_protos.h>
#include <vm/vm_map.h>

enum {
	kProcessSuspended =        (1 << 0), 
	kProcessHibernated =       (1 << 1),
	kProcessNoReclaimWorth =   (1 << 2),
	kProcessIgnored =          (1 << 3),
	kProcessBusy =             (1 << 4)
};

static lck_mtx_t * hibernation_mlock;
static lck_attr_t * hibernation_lck_attr;
static lck_grp_t * hibernation_lck_grp;
static lck_grp_attr_t * hibernation_lck_grp_attr;

typedef struct hibernation_node {
	RB_ENTRY(hibernation_node) link;
	pid_t pid;
	uint32_t state;
	mach_timespec_t hibernation_ts;
} hibernation_node;

static int hibernation_tree_compare(hibernation_node *n1, hibernation_node *n2) {
	if (n1->pid < n2->pid)
		return -1;
	else if (n1->pid > n2->pid)
		return 1;
	else
		return 0;
}

static RB_HEAD(hibernation_tree, hibernation_node) hibernation_tree_head;
RB_PROTOTYPE_SC(static, hibernation_tree, hibernation_node, link, hibernation_tree_compare);

RB_GENERATE(hibernation_tree, hibernation_node, link, hibernation_tree_compare);

static inline boolean_t kern_hibernation_can_hibernate_processes(void);
static boolean_t kern_hibernation_can_hibernate(void);

static void kern_hibernation_add_node(hibernation_node *node);
static hibernation_node *kern_hibernation_get_node(pid_t pid);
static void kern_hibernation_release_node(hibernation_node *node);
static void kern_hibernation_free_node(hibernation_node *node, boolean_t unlock);

static void kern_hibernation_register_pid(pid_t pid);
static void kern_hibernation_unregister_pid(pid_t pid);

static int kern_hibernation_get_process_state(pid_t pid, uint32_t *state, mach_timespec_t *ts);
static int kern_hibernation_set_process_state(pid_t pid, uint32_t state);

static void kern_hibernation_cull(void);

static void kern_hibernation_thread(void);

extern boolean_t vm_freeze_enabled;

int kern_hibernation_wakeup = 0;

static int jetsam_priority_list_hibernation_index = 0;

/* Thresholds */
static int kern_memorystatus_level_hibernate = 50;

#define HIBERNATION_PAGES_MIN   ( 1 * 1024 * 1024 / PAGE_SIZE)
#define HIBERNATION_PAGES_MAX   (16 * 1024 * 1024 / PAGE_SIZE)

static unsigned int kern_memorystatus_hibernation_pages_min   = HIBERNATION_PAGES_MIN;
static unsigned int kern_memorystatus_hibernation_pages_max   = HIBERNATION_PAGES_MAX;

static unsigned int kern_memorystatus_suspended_count = 0;
static unsigned int kern_memorystatus_hibernated_count = 0;

static unsigned int kern_memorystatus_hibernation_suspended_minimum = 4;

static unsigned int kern_memorystatus_low_swap_pages = 0;

/* Throttling */
#define HIBERNATION_DAILY_MB_MAX 	  1024
#define HIBERNATION_DAILY_PAGEOUTS_MAX (HIBERNATION_DAILY_MB_MAX * (1024 * 1024 / PAGE_SIZE))

static struct throttle_interval_t {
	uint32_t mins;
	uint32_t burst_multiple;
	uint32_t pageouts;
	uint32_t max_pageouts;
	mach_timespec_t ts;
	boolean_t throttle;
} throttle_intervals[] = {
	{ 	   60,  8, 0, 0, { 0, 0 }, FALSE }, /* 1 hour intermediate interval, 8x burst */
	{ 24 * 60,  1, 0, 0, { 0, 0 }, FALSE }, /* 24 hour long interval, no burst */
};

/* Stats */
static uint64_t kern_memorystatus_hibernation_count = 0;
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_hibernation_count, CTLFLAG_RD, &kern_memorystatus_hibernation_count, "");

static uint64_t kern_memorystatus_hibernation_pageouts = 0;
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_hibernation_pageouts, CTLFLAG_RD, &kern_memorystatus_hibernation_pageouts, "");

static uint64_t kern_memorystatus_hibernation_throttle_count = 0;
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_hibernation_throttle_count, CTLFLAG_RD, &kern_memorystatus_hibernation_throttle_count, "");

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_hibernation_min_processes, CTLFLAG_RW, &kern_memorystatus_hibernation_suspended_minimum, 0, "");

#if DEVELOPMENT || DEBUG
/* Allow parameter tweaking in these builds */
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_level_hibernate, CTLFLAG_RW, &kern_memorystatus_level_hibernate, 0, "");

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_hibernation_pages_min, CTLFLAG_RW, &kern_memorystatus_hibernation_pages_min, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_hibernation_pages_max, CTLFLAG_RW, &kern_memorystatus_hibernation_pages_max, 0, "");

boolean_t kern_memorystatus_hibernation_throttle_enabled = TRUE;
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_hibernation_throttle_enabled, CTLFLAG_RW, &kern_memorystatus_hibernation_throttle_enabled, 0, "");
#endif /* DEVELOPMENT || DEBUG */
#endif /* CONFIG_FREEZE */

extern unsigned int    vm_page_free_count;
extern unsigned int    vm_page_active_count;
extern unsigned int    vm_page_inactive_count;
extern unsigned int    vm_page_purgeable_count;
extern unsigned int    vm_page_wire_count;

static void kern_memorystatus_thread(void);

int kern_memorystatus_wakeup = 0;
int kern_memorystatus_level = 0;
int kern_memorystatus_last_level = 0;
unsigned int kern_memorystatus_delta;

unsigned int kern_memorystatus_kev_failure_count = 0;
int kern_memorystatus_level_critical = 5;
#define kern_memorystatus_level_highwater (kern_memorystatus_level_critical + 5)

static struct {
	jetsam_kernel_stats_t stats;
	size_t entry_count;
	jetsam_snapshot_entry_t entries[kMaxSnapshotEntries];
} jetsam_snapshot;

static jetsam_priority_entry_t jetsam_priority_list[kMaxPriorityEntries];
#define jetsam_snapshot_list jetsam_snapshot.entries

static int jetsam_priority_list_index = 0;
static int jetsam_priority_list_count = 0;
static int jetsam_snapshot_list_count = 0;

static lck_mtx_t * jetsam_list_mlock;
static lck_attr_t * jetsam_lck_attr;
static lck_grp_t * jetsam_lck_grp;
static lck_grp_attr_t * jetsam_lck_grp_attr;

SYSCTL_INT(_kern, OID_AUTO, memorystatus_level, CTLFLAG_RD | CTLFLAG_LOCKED, &kern_memorystatus_level, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_kev_failure_count, CTLFLAG_RD | CTLFLAG_LOCKED, &kern_memorystatus_kev_failure_count, 0, "");

#if DEVELOPMENT || DEBUG

enum {
	kJetsamDiagnosticModeNone =              0, 
	kJetsamDiagnosticModeAll  =              1,
	kJetsamDiagnosticModeStopAtFirstActive = 2
} jetsam_diagnostic_mode = kJetsamDiagnosticModeNone;

static int jetsam_diagnostic_suspended_one_active_proc = 0;

static int
sysctl_jetsam_diagnostic_mode SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error, val = jetsam_diagnostic_mode;
	boolean_t disabled;

	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || !req->newptr)
 		return (error);
	if ((val < 0) || (val > 2)) {
		printf("jetsam: diagnostic mode: invalid value - %d\n", val);
		return (0);
	}
	
	/* 
	 * If jetsam_diagnostic_mode is set, we need to lower memory threshold for jetsam
	 */
	disabled = (val == 0) && (jetsam_diagnostic_mode != kJetsamDiagnosticModeNone);
	
	jetsam_diagnostic_mode = val;
	
	if (disabled) {
		kern_memorystatus_level_critical = 5;
		printf("jetsam: diagnostic mode: resetting critical level to %d\n", kern_memorystatus_level_critical);
	} else {
		kern_memorystatus_level_critical = 10;
		printf("jetsam: diagnostic mode: %d: increasing critical level to %d\n", (int) jetsam_diagnostic_mode, kern_memorystatus_level_critical);
		if (jetsam_diagnostic_mode == kJetsamDiagnosticModeStopAtFirstActive)
			printf("jetsam: diagnostic mode: will stop at first active app\n");
	}
	
	return (0);
}

SYSCTL_PROC(_debug, OID_AUTO, jetsam_diagnostic_mode, CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_ANYBODY,
  		&jetsam_diagnostic_mode, 0, sysctl_jetsam_diagnostic_mode, "I", "Jetsam Diagnostic Mode");
#endif /* DEVELOPMENT || DEBUG */

__private_extern__ void
kern_memorystatus_init(void)
{
	jetsam_lck_attr = lck_attr_alloc_init();
	jetsam_lck_grp_attr= lck_grp_attr_alloc_init();
	jetsam_lck_grp = lck_grp_alloc_init("jetsam",  jetsam_lck_grp_attr);
	jetsam_list_mlock = lck_mtx_alloc_init(jetsam_lck_grp, jetsam_lck_attr);
	kern_memorystatus_delta = 5 * atop_64(max_mem) / 100;

	(void)kernel_thread(kernel_task, kern_memorystatus_thread);
}

static uint32_t
jetsam_task_page_count(task_t task)
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

static uint32_t
jetsam_flags_for_pid(pid_t pid)
{
	int i;

	for (i = 0; i < jetsam_priority_list_count; i++) {
		if (pid == jetsam_priority_list[i].pid) {
			return jetsam_priority_list[i].flags;
		}
	}
	return 0;
}

static void
jetsam_snapshot_procs(void)
{
	proc_t p;
	int i = 0;

	jetsam_snapshot.stats.free_pages = vm_page_free_count;
	jetsam_snapshot.stats.active_pages = vm_page_active_count;
	jetsam_snapshot.stats.inactive_pages = vm_page_inactive_count;
	jetsam_snapshot.stats.purgeable_pages = vm_page_purgeable_count;
	jetsam_snapshot.stats.wired_pages = vm_page_wire_count;
	proc_list_lock();
	LIST_FOREACH(p, &allproc, p_list) {
		task_t task = p->task;
		jetsam_snapshot_list[i].pid = p->p_pid;
		jetsam_snapshot_list[i].pages = jetsam_task_page_count(task);
		jetsam_snapshot_list[i].flags = jetsam_flags_for_pid(p->p_pid);
		strlcpy(&jetsam_snapshot_list[i].name[0], p->p_comm, MAXCOMLEN+1);
#ifdef DEBUG
		printf("jetsam snapshot pid = %d, uuid = %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			p->p_pid, 
			p->p_uuid[0], p->p_uuid[1], p->p_uuid[2], p->p_uuid[3], p->p_uuid[4], p->p_uuid[5], p->p_uuid[6], p->p_uuid[7],
			p->p_uuid[8], p->p_uuid[9], p->p_uuid[10], p->p_uuid[11], p->p_uuid[12], p->p_uuid[13], p->p_uuid[14], p->p_uuid[15]);
#endif
		memcpy(&jetsam_snapshot_list[i].uuid[0], &p->p_uuid[0], sizeof(p->p_uuid));
		i++;
		if (i == kMaxSnapshotEntries) {
			break;
		} 	
	}
	proc_list_unlock();	
	jetsam_snapshot.entry_count = jetsam_snapshot_list_count = i - 1;
}

static void
jetsam_mark_pid_in_snapshot(pid_t pid, int flags)
{

	int i = 0;

	for (i = 0; i < jetsam_snapshot_list_count; i++) {
		if (jetsam_snapshot_list[i].pid == pid) {
			jetsam_snapshot_list[i].flags |= flags;
			return;
		}
	}
}

int
jetsam_kill_top_proc(boolean_t any, uint32_t cause)
{
	proc_t p;

#ifndef CONFIG_FREEZE
#pragma unused(any)
#endif

	if (jetsam_snapshot_list_count == 0) {
		jetsam_snapshot_procs();
	}
	lck_mtx_lock(jetsam_list_mlock);
	while (jetsam_priority_list_index < jetsam_priority_list_count) {
		jetsam_priority_entry_t* jetsam_priority_entry = &jetsam_priority_list[jetsam_priority_list_index];
		pid_t aPid = jetsam_priority_entry->pid;
#if DEVELOPMENT || DEBUG
		int activeProcess = jetsam_priority_entry->flags & kJetsamFlagsFrontmost;
		int procSuspendedForDiagnosis = jetsam_priority_entry->flags & kJetsamFlagsSuspForDiagnosis;
#endif /* DEVELOPMENT || DEBUG */
		jetsam_priority_list_index++;
		/* skip empty slots in the list */
		if (aPid == 0) {
			continue; // with lock held
		}
		lck_mtx_unlock(jetsam_list_mlock);
		p = proc_find(aPid);
		if (p != NULL) {
			int flags = cause;
#if DEVELOPMENT || DEBUG
			if ((jetsam_diagnostic_mode != kJetsamDiagnosticModeNone) && procSuspendedForDiagnosis) {
				printf("jetsam: continuing after ignoring proc suspended already for diagnosis - %d\n", aPid);
				proc_rele(p);
				lck_mtx_lock(jetsam_list_mlock);
				continue;
			}
#endif /* DEVELOPMENT || DEBUG */
#if CONFIG_FREEZE
			hibernation_node *node;
			boolean_t skip;
			if ((node = kern_hibernation_get_node(aPid))) {
				boolean_t reclaim_proc = !(node->state & (kProcessBusy | kProcessNoReclaimWorth));
				if (any || reclaim_proc) {
					if (node->state & kProcessHibernated) {
						flags |= kJetsamFlagsHibernated;
					}
					skip = FALSE;
				} else {
					skip = TRUE;
				}
				kern_hibernation_release_node(node);
			} else {
				skip = FALSE;
			}
			if (skip) {
				proc_rele(p);			
			} else
#endif
			{
#if DEVELOPMENT || DEBUG
				if ((jetsam_diagnostic_mode != kJetsamDiagnosticModeNone) && activeProcess) {
#if DEBUG
					printf("jetsam: suspending pid %d [%s] (active) for diagnosis - memory_status_level: %d\n",
						aPid, (p->p_comm ? p->p_comm: "(unknown)"), kern_memorystatus_level);
#endif /* DEBUG */
					jetsam_mark_pid_in_snapshot(aPid, kJetsamFlagsSuspForDiagnosis);
					jetsam_priority_entry->flags |= kJetsamFlagsSuspForDiagnosis;
					task_suspend(p->task);
					proc_rele(p);
					if (jetsam_diagnostic_mode == kJetsamDiagnosticModeStopAtFirstActive) {
						jetsam_diagnostic_suspended_one_active_proc = 1;
						printf("jetsam: returning after suspending first active proc - %d\n", aPid);
					}
					return 0;
				} else
#endif /* DEVELOPMENT || DEBUG */
				{
					printf("jetsam: killing pid %d [%s] - memory_status_level: %d\n", 
						aPid, (p->p_comm ? p->p_comm : "(unknown)"), kern_memorystatus_level);
					jetsam_mark_pid_in_snapshot(aPid, flags);
					exit1(p, W_EXITCODE(0, SIGKILL), (int *)NULL);
					proc_rele(p);
#if DEBUG
					printf("jetsam: pid %d killed - memory_status_level: %d\n", aPid, kern_memorystatus_level);
#endif /* DEBUG */
					return 0;
				}
			}
		}
	    lck_mtx_lock(jetsam_list_mlock);
	}
	lck_mtx_unlock(jetsam_list_mlock);
	return -1;
}

static int
jetsam_kill_hiwat_proc(void)
{
	proc_t p;
	int i;
	if (jetsam_snapshot_list_count == 0) {
		jetsam_snapshot_procs();
	}
	lck_mtx_lock(jetsam_list_mlock);
	for (i = jetsam_priority_list_index; i < jetsam_priority_list_count; i++) {
		pid_t aPid;
		int32_t hiwat;
		aPid = jetsam_priority_list[i].pid;
		hiwat = jetsam_priority_list[i].hiwat_pages;	
		/* skip empty or non-hiwat slots in the list */
		if (aPid == 0 || (hiwat < 0)) {
			continue; // with lock held
		}
		p = proc_find(aPid);
		if (p != NULL) {
			int32_t pages = (int32_t)jetsam_task_page_count(p->task);
			boolean_t skip = (pages <= hiwat);
#if DEVELOPMENT || DEBUG
			if (!skip && (jetsam_diagnostic_mode != kJetsamDiagnosticModeNone)) {
				if (jetsam_priority_list[i].flags & kJetsamFlagsSuspForDiagnosis) {
					proc_rele(p);
					continue;
				}
			}
#endif /* DEVELOPMENT || DEBUG */
#if CONFIG_FREEZE
			if (!skip) {
				hibernation_node *node;
				if ((node = kern_hibernation_get_node(aPid))) {
					if (node->state & kProcessBusy) {
						kern_hibernation_release_node(node);
						skip = TRUE;
					} else {
						kern_hibernation_free_node(node, TRUE);
						skip = FALSE;
					}
				}				
			}
#endif
			if (!skip) {
#if DEBUG
				printf("jetsam: %s pid %d [%s] - %d pages > hiwat (%d)\n",
					(jetsam_diagnostic_mode != kJetsamDiagnosticModeNone)?"suspending": "killing", aPid, p->p_comm, pages, hiwat);
#endif /* DEBUG */
#if DEVELOPMENT || DEBUG
				if (jetsam_diagnostic_mode != kJetsamDiagnosticModeNone) {
					lck_mtx_unlock(jetsam_list_mlock);
					task_suspend(p->task);
					proc_rele(p);
#if DEBUG
					printf("jetsam: pid %d suspended for diagnosis - memory_status_level: %d\n", aPid, kern_memorystatus_level);
#endif /* DEBUG */
					jetsam_mark_pid_in_snapshot(aPid, kJetsamFlagsSuspForDiagnosis);
					jetsam_priority_list[i].flags |= kJetsamFlagsSuspForDiagnosis;
				} else
#endif /* DEVELOPMENT || DEBUG */
				{
					jetsam_priority_list[i].pid = 0;
					lck_mtx_unlock(jetsam_list_mlock);
					exit1(p, W_EXITCODE(0, SIGKILL), (int *)NULL);
					proc_rele(p);
#if DEBUG
					printf("jetsam: pid %d killed - memory_status_level: %d\n", aPid, kern_memorystatus_level);
#endif /* DEBUG */
					jetsam_mark_pid_in_snapshot(aPid, kJetsamFlagsKilledHiwat);
				}
				return 0;
			} else {
				proc_rele(p);
			}

		}
	}
	lck_mtx_unlock(jetsam_list_mlock);
	return -1;
}

#if CONFIG_FREEZE
static void
jetsam_send_hibernation_note(uint32_t flags, pid_t pid, uint32_t pages) {
	int ret;
	struct kev_msg ev_msg;
	jetsam_hibernation_entry_t data;
	
	ev_msg.vendor_code    = KEV_VENDOR_APPLE;
	ev_msg.kev_class      = KEV_SYSTEM_CLASS;
	ev_msg.kev_subclass   = KEV_MEMORYSTATUS_SUBCLASS;

	ev_msg.event_code     = kMemoryStatusHibernationNote;

	ev_msg.dv[0].data_length = sizeof data;
	ev_msg.dv[0].data_ptr = &data;
	ev_msg.dv[1].data_length = 0;

	data.pid = pid;
	data.flags = flags;
	data.pages = pages;

	ret = kev_post_msg(&ev_msg);
	if (ret) {
		kern_memorystatus_kev_failure_count++;
		printf("%s: kev_post_msg() failed, err %d\n", __func__, ret);
	}
}

static int
jetsam_hibernate_top_proc(void)
{
	int hibernate_index;
	proc_t p;
	uint32_t i;

	lck_mtx_lock(jetsam_list_mlock);
	
	for (hibernate_index = jetsam_priority_list_index; hibernate_index < jetsam_priority_list_count; hibernate_index++) {
		pid_t aPid;
		uint32_t state = 0;

		aPid = jetsam_priority_list[hibernate_index].pid;

		/* skip empty slots in the list */
		if (aPid == 0) {
			continue; // with lock held
		}

		if (kern_hibernation_get_process_state(aPid, &state, NULL) != 0) {
			continue; // with lock held
		}

		/* ensure the process isn't marked as busy and is suspended */
		if ((state & kProcessBusy) || !(state & kProcessSuspended)) {
			continue; // with lock held
		}

		p = proc_find(aPid);
		if (p != NULL) {
			hibernation_node *node;
			boolean_t skip;
			uint32_t purgeable, wired, clean, dirty;
			boolean_t shared;
			
			lck_mtx_unlock(jetsam_list_mlock);
			
			if ((node = kern_hibernation_get_node(aPid))) {
				if (node->state & kProcessBusy) {
					skip = TRUE;
				} else {
					node->state |= kProcessBusy;
					/* Whether we hibernate or not, increase the count so can we maintain the gap between hibernated and suspended processes. */
					kern_memorystatus_hibernated_count++;
					skip = FALSE;
				}
				kern_hibernation_release_node(node);
			} else {
				skip = TRUE;
			}
			
			if (!skip) {
				/* Only hibernate processes meeting our size criteria. If not met, mark it as such and return. */
				task_freeze(p->task, &purgeable, &wired, &clean, &dirty, &shared, TRUE);
				skip = (dirty < kern_memorystatus_hibernation_pages_min) || (dirty > kern_memorystatus_hibernation_pages_max);		
			}
			
			if (!skip) {
				unsigned int swap_pages_free = default_pager_swap_pages_free();
				
				/* Ensure there's actually enough space free to hibernate this process. */
				if (dirty > swap_pages_free) {
					kern_memorystatus_low_swap_pages = swap_pages_free;
					skip = TRUE;
				}
			}

			if (skip) {
				kern_hibernation_set_process_state(aPid, kProcessIgnored);
				proc_rele(p);
				return 0;
			}

#if DEBUG
			printf("jetsam: pid %d [%s] hibernating - memory_status_level: %d, purgeable: %d, wired: %d, clean: %d, dirty: %d, shared %d, free swap: %d\n", 
				aPid, (p->p_comm ? p->p_comm : "(unknown)"), kern_memorystatus_level, purgeable, wired, clean, dirty, shared, default_pager_swap_pages_free());
#endif

			task_freeze(p->task, &purgeable, &wired, &clean, &dirty, &shared, FALSE);
			proc_rele(p);
			
			kern_hibernation_set_process_state(aPid, kProcessHibernated | (shared ? 0: kProcessNoReclaimWorth));
			
			/* Update stats */
			for (i = 0; i < sizeof(throttle_intervals) / sizeof(struct throttle_interval_t); i++) {
				throttle_intervals[i].pageouts += dirty;
			}
			kern_memorystatus_hibernation_pageouts += dirty;
			kern_memorystatus_hibernation_count++;
			
			jetsam_send_hibernation_note(kJetsamFlagsHibernated, aPid, dirty);

			return dirty;
		}
	}
	lck_mtx_unlock(jetsam_list_mlock);
	return -1;
}
#endif /* CONFIG_FREEZE */

static void
kern_memorystatus_thread(void)
{
	struct kev_msg ev_msg;
	jetsam_kernel_stats_t data;
	boolean_t post_memorystatus_snapshot = FALSE; 
	int ret;

	bzero(&data, sizeof(jetsam_kernel_stats_t));
	bzero(&ev_msg, sizeof(struct kev_msg));
	while(1) {

#if DEVELOPMENT || DEBUG
		jetsam_diagnostic_suspended_one_active_proc = 0;
#endif /* DEVELOPMENT || DEBUG */

		while (kern_memorystatus_level <= kern_memorystatus_level_highwater) {
			if (jetsam_kill_hiwat_proc() < 0) {
				break;
			}
			post_memorystatus_snapshot = TRUE;
		}

		while (kern_memorystatus_level <= kern_memorystatus_level_critical) {
			if (jetsam_kill_top_proc(FALSE, kJetsamFlagsKilled) < 0) {
				break;
			}
			post_memorystatus_snapshot = TRUE;
#if DEVELOPMENT || DEBUG
			if ((jetsam_diagnostic_mode == kJetsamDiagnosticModeStopAtFirstActive) && jetsam_diagnostic_suspended_one_active_proc) {
				printf("jetsam: stopping killing since 1 active proc suspended already for diagnosis\n");
				break; // we found first active proc, let's not kill any more
			}
#endif /* DEVELOPMENT || DEBUG */
		}

		kern_memorystatus_last_level = kern_memorystatus_level;

		ev_msg.vendor_code    = KEV_VENDOR_APPLE;
		ev_msg.kev_class      = KEV_SYSTEM_CLASS;
		ev_msg.kev_subclass   = KEV_MEMORYSTATUS_SUBCLASS;

		/* pass the memory status level (percent free) */
		ev_msg.event_code     = kMemoryStatusLevelNote;

		ev_msg.dv[0].data_length = sizeof kern_memorystatus_last_level;
		ev_msg.dv[0].data_ptr = &kern_memorystatus_last_level;
		ev_msg.dv[1].data_length = sizeof data;
		ev_msg.dv[1].data_ptr = &data;
		ev_msg.dv[2].data_length = 0;

		data.free_pages = vm_page_free_count;
		data.active_pages = vm_page_active_count;
		data.inactive_pages = vm_page_inactive_count;
		data.purgeable_pages = vm_page_purgeable_count;
		data.wired_pages = vm_page_wire_count;

		ret = kev_post_msg(&ev_msg);
		if (ret) {
			kern_memorystatus_kev_failure_count++;
			printf("%s: kev_post_msg() failed, err %d\n", __func__, ret);
		}

		if (post_memorystatus_snapshot) {
			size_t snapshot_size =  sizeof(jetsam_kernel_stats_t) + sizeof(size_t) + sizeof(jetsam_snapshot_entry_t) * jetsam_snapshot_list_count;
			ev_msg.event_code = kMemoryStatusSnapshotNote;
			ev_msg.dv[0].data_length = sizeof snapshot_size;
			ev_msg.dv[0].data_ptr = &snapshot_size;
			ev_msg.dv[1].data_length = 0;

			ret = kev_post_msg(&ev_msg);
			if (ret) {
				kern_memorystatus_kev_failure_count++;
				printf("%s: kev_post_msg() failed, err %d\n", __func__, ret);
			}
		}

		if (kern_memorystatus_level >= kern_memorystatus_last_level + 5 ||
		    kern_memorystatus_level <= kern_memorystatus_last_level - 5)
			continue;

		assert_wait(&kern_memorystatus_wakeup, THREAD_UNINT);
		(void)thread_block((thread_continue_t)kern_memorystatus_thread);
	}
}

#if CONFIG_FREEZE

__private_extern__ void
kern_hibernation_init(void)
{
    hibernation_lck_attr = lck_attr_alloc_init();
    hibernation_lck_grp_attr = lck_grp_attr_alloc_init();
    hibernation_lck_grp = lck_grp_alloc_init("hibernation",  hibernation_lck_grp_attr);
    hibernation_mlock = lck_mtx_alloc_init(hibernation_lck_grp, hibernation_lck_attr);
	
	RB_INIT(&hibernation_tree_head);

	(void)kernel_thread(kernel_task, kern_hibernation_thread);
}

static inline boolean_t 
kern_hibernation_can_hibernate_processes(void) 
{
	boolean_t ret;
	
	lck_mtx_lock_spin(hibernation_mlock);
	ret = (kern_memorystatus_suspended_count - kern_memorystatus_hibernated_count) > 
				kern_memorystatus_hibernation_suspended_minimum ? TRUE : FALSE;
	lck_mtx_unlock(hibernation_mlock);
	
	return ret;
}

static boolean_t 
kern_hibernation_can_hibernate(void)
{
	/* Only hibernate if we're sufficiently low on memory; this holds off hibernation right after boot, 
	   and is generally is a no-op once we've reached steady state. */
	if (kern_memorystatus_level > kern_memorystatus_level_hibernate) {
		return FALSE;
	}
	
	/* Check minimum suspended process threshold. */
	if (!kern_hibernation_can_hibernate_processes()) {
		return FALSE;
	}

	/* Is swap running low? */
	if (kern_memorystatus_low_swap_pages) {
		/* If there's been no movement in free swap pages since we last attempted hibernation, return. */
		if (default_pager_swap_pages_free() <= kern_memorystatus_low_swap_pages) {
			return FALSE;
		}
		
		/* Pages have been freed, so we can retry. */
		kern_memorystatus_low_swap_pages = 0;
	}
	
	/* OK */
	return TRUE;
}

static void
kern_hibernation_add_node(hibernation_node *node)
{
	lck_mtx_lock_spin(hibernation_mlock);

	RB_INSERT(hibernation_tree, &hibernation_tree_head, node);
	kern_memorystatus_suspended_count++;

	lck_mtx_unlock(hibernation_mlock);	
}

/* Returns with the hibernation lock taken */
static hibernation_node *
kern_hibernation_get_node(pid_t pid) 
{
	hibernation_node sought, *found;
	sought.pid = pid;
	lck_mtx_lock_spin(hibernation_mlock);
	found = RB_FIND(hibernation_tree, &hibernation_tree_head, &sought);
	if (!found) {
		lck_mtx_unlock(hibernation_mlock);		
	}
	return found;
}

static void
kern_hibernation_release_node(hibernation_node *node) 
{
#pragma unused(node)
	lck_mtx_unlock(hibernation_mlock);	
}

static void 
kern_hibernation_free_node(hibernation_node *node, boolean_t unlock) 
{
	/* make sure we're called with the hibernation_mlock held */
	lck_mtx_assert(hibernation_mlock, LCK_MTX_ASSERT_OWNED);

	if (node->state & (kProcessHibernated | kProcessIgnored)) {
		kern_memorystatus_hibernated_count--;
	} 

	kern_memorystatus_suspended_count--;
	
	RB_REMOVE(hibernation_tree, &hibernation_tree_head, node);
	kfree(node, sizeof(hibernation_node));

	if (unlock) {
		lck_mtx_unlock(hibernation_mlock);
	}	
}

static void 
kern_hibernation_register_pid(pid_t pid)
{
	hibernation_node *node;

#if DEVELOPMENT || DEBUG
	node = kern_hibernation_get_node(pid);
	if (node) {
		printf("kern_hibernation_register_pid: pid %d already registered!\n", pid);
		kern_hibernation_release_node(node);
		return;
	}
#endif

	/* Register as a candiate for hibernation */
	node = (hibernation_node *)kalloc(sizeof(hibernation_node));
	if (node) {	
		clock_sec_t sec;
		clock_nsec_t nsec;
		mach_timespec_t ts;
		
		memset(node, 0, sizeof(hibernation_node));

		node->pid = pid;
		node->state = kProcessSuspended;

		clock_get_system_nanotime(&sec, &nsec);
		ts.tv_sec = sec;
		ts.tv_nsec = nsec;
		
		node->hibernation_ts = ts;

		kern_hibernation_add_node(node);
	}
}

static void 
kern_hibernation_unregister_pid(pid_t pid)
{
	hibernation_node *node;
	
	node = kern_hibernation_get_node(pid);
	if (node) {
		kern_hibernation_free_node(node, TRUE);
	}
}

void 
kern_hibernation_on_pid_suspend(pid_t pid)
{	
	kern_hibernation_register_pid(pid);
}

/* If enabled, we bring all the hibernated pages back prior to resumption; otherwise, they're faulted back in on demand */
#define THAW_ON_RESUME 1

void
kern_hibernation_on_pid_resume(pid_t pid, task_t task)
{	
#if THAW_ON_RESUME
	hibernation_node *node;
	if ((node = kern_hibernation_get_node(pid))) {
		if (node->state & kProcessHibernated) {
			node->state |= kProcessBusy;
			kern_hibernation_release_node(node);
			task_thaw(task);
			jetsam_send_hibernation_note(kJetsamFlagsThawed, pid, 0);
		} else {
			kern_hibernation_release_node(node);
		}
	}
#else
#pragma unused(task)
#endif
	kern_hibernation_unregister_pid(pid);
}

void
kern_hibernation_on_pid_hibernate(pid_t pid)
{
#pragma unused(pid)

	/* Wake the hibernation thread */
	thread_wakeup((event_t)&kern_hibernation_wakeup);	
}

static int 
kern_hibernation_get_process_state(pid_t pid, uint32_t *state, mach_timespec_t *ts) 
{
	hibernation_node *found;
	int err = ESRCH;
	
	*state = 0;

	found = kern_hibernation_get_node(pid);
	if (found) {
		*state = found->state;
		if (ts) {
			*ts = found->hibernation_ts;
		}
		err = 0;
		kern_hibernation_release_node(found);
	}
	
	return err;
}

static int 
kern_hibernation_set_process_state(pid_t pid, uint32_t state) 
{
	hibernation_node *found;
	int err = ESRCH;

	found = kern_hibernation_get_node(pid);
	if (found) {
		found->state = state;
		err = 0;
		kern_hibernation_release_node(found);
	}
	
	return err;
}

static void
kern_hibernation_update_throttle_interval(mach_timespec_t *ts, struct throttle_interval_t *interval)
{
	if (CMP_MACH_TIMESPEC(ts, &interval->ts) >= 0) {
		if (!interval->max_pageouts) {
			interval->max_pageouts = (interval->burst_multiple * (((uint64_t)interval->mins * HIBERNATION_DAILY_PAGEOUTS_MAX) / (24 * 60)));
		} else {
			printf("jetsam: %d minute throttle timeout, resetting\n", interval->mins);
		}
		interval->ts.tv_sec = interval->mins * 60;
		interval->ts.tv_nsec = 0;
		ADD_MACH_TIMESPEC(&interval->ts, ts);
		/* Since we update the throttle stats pre-hibernation, adjust for overshoot here */
		if (interval->pageouts > interval->max_pageouts) {
			interval->pageouts -= interval->max_pageouts;
		} else {
			interval->pageouts = 0;
		}
		interval->throttle = FALSE;
	} else if (!interval->throttle && interval->pageouts >= interval->max_pageouts) {
		printf("jetsam: %d minute pageout limit exceeded; enabling throttle\n", interval->mins);
		interval->throttle = TRUE;
	}	
#ifdef DEBUG
	printf("jetsam: throttle updated - %d frozen (%d max) within %dm; %dm remaining; throttle %s\n", 
		interval->pageouts, interval->max_pageouts, interval->mins, (interval->ts.tv_sec - ts->tv_sec) / 60, 
		interval->throttle ? "on" : "off");
#endif
}

static boolean_t
kern_hibernation_throttle_update(void) 
{
	clock_sec_t sec;
	clock_nsec_t nsec;
	mach_timespec_t ts;
	uint32_t i;
	boolean_t throttled = FALSE;

#if DEVELOPMENT || DEBUG
	if (!kern_memorystatus_hibernation_throttle_enabled)
		return FALSE;
#endif

	clock_get_system_nanotime(&sec, &nsec);
	ts.tv_sec = sec;
	ts.tv_nsec = nsec;
	
	/* Check hibernation pageouts over multiple intervals and throttle if we've exceeded our budget.
	 *
	 * This ensures that periods of inactivity can't be used as 'credit' towards hibernation if the device has
	 * remained dormant for a long period. We do, however, allow increased thresholds for shorter intervals in
	 * order to allow for bursts of activity.
	 */
	for (i = 0; i < sizeof(throttle_intervals) / sizeof(struct throttle_interval_t); i++) {
		kern_hibernation_update_throttle_interval(&ts, &throttle_intervals[i]);
		if (throttle_intervals[i].throttle == TRUE)
			throttled = TRUE;
	}								

	return throttled;
}

static void
kern_hibernation_cull(void)
{
	hibernation_node *node, *next;
	lck_mtx_lock(hibernation_mlock);

	for (node = RB_MIN(hibernation_tree, &hibernation_tree_head); node != NULL; node = next) {
		proc_t p;

		next = RB_NEXT(hibernation_tree, &hibernation_tree_head, node);

		/* TODO: probably suboptimal, so revisit should it cause a performance issue */
		p = proc_find(node->pid);
		if (p) {
			proc_rele(p);
		} else {
			kern_hibernation_free_node(node, FALSE);				
		}
	}

	lck_mtx_unlock(hibernation_mlock);	
}

static void
kern_hibernation_thread(void)
{
	if (vm_freeze_enabled) {
		if (kern_hibernation_can_hibernate()) {
			
			/* Cull dead processes */
			kern_hibernation_cull();
			
			/* Only hibernate if we've not exceeded our pageout budgets */
			if (!kern_hibernation_throttle_update()) {
				jetsam_hibernate_top_proc();
			} else {
				printf("kern_hibernation_thread: in throttle, ignoring hibernation\n");
				kern_memorystatus_hibernation_throttle_count++; /* Throttled, update stats */
			}
		}
	}

	assert_wait((event_t) &kern_hibernation_wakeup, THREAD_UNINT);
	thread_block((thread_continue_t) kern_hibernation_thread);	
}

#endif /* CONFIG_FREEZE */

static int
sysctl_io_variable(struct sysctl_req *req, void *pValue, size_t currentsize, size_t maxsize, size_t *newsize)
{
    int error;

    /* Copy blob out */
    error = SYSCTL_OUT(req, pValue, currentsize);

    /* error or nothing to set */
    if (error || !req->newptr)
        return(error);

    if (req->newlen > maxsize) {
		return EINVAL;
	}
	error = SYSCTL_IN(req, pValue, req->newlen);

	if (!error) {
		*newsize = req->newlen;
	}

    return(error);
}

static int
sysctl_handle_kern_memorystatus_priority_list(__unused struct sysctl_oid *oid, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int i, ret;
	jetsam_priority_entry_t temp_list[kMaxPriorityEntries];
	size_t newsize, currentsize;

	if (req->oldptr) {
		lck_mtx_lock(jetsam_list_mlock);
		for (i = 0; i < jetsam_priority_list_count; i++) {
			temp_list[i] = jetsam_priority_list[i];
		}
		lck_mtx_unlock(jetsam_list_mlock);
	}

	currentsize = sizeof(jetsam_priority_list[0]) * jetsam_priority_list_count;

	ret = sysctl_io_variable(req, &temp_list[0], currentsize, sizeof(temp_list), &newsize);

	if (!ret && req->newptr) {
		int temp_list_count = newsize / sizeof(jetsam_priority_list[0]);
#if DEBUG 
		printf("set jetsam priority pids = { ");
		for (i = 0; i < temp_list_count; i++) {
			printf("(%d, 0x%08x, %d) ", temp_list[i].pid, temp_list[i].flags, temp_list[i].hiwat_pages);
		}
		printf("}\n");
#endif /* DEBUG */
		lck_mtx_lock(jetsam_list_mlock);
#if CONFIG_FREEZE
		jetsam_priority_list_hibernation_index = 0;
#endif
		jetsam_priority_list_index = 0;
		jetsam_priority_list_count = temp_list_count;
		for (i = 0; i < temp_list_count; i++) {
			jetsam_priority_list[i] = temp_list[i];
		}
		for (i = temp_list_count; i < kMaxPriorityEntries; i++) {
			jetsam_priority_list[i].pid = 0;
			jetsam_priority_list[i].flags = 0;
			jetsam_priority_list[i].hiwat_pages = -1;
			jetsam_priority_list[i].hiwat_reserved1 = -1;
			jetsam_priority_list[i].hiwat_reserved2 = -1;
			jetsam_priority_list[i].hiwat_reserved3 = -1;
		}
		lck_mtx_unlock(jetsam_list_mlock);
	}	
	return ret;
}

static int
sysctl_handle_kern_memorystatus_snapshot(__unused struct sysctl_oid *oid, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int ret;
	size_t currentsize = 0;

	if (jetsam_snapshot_list_count > 0) {
		currentsize = sizeof(jetsam_kernel_stats_t) + sizeof(size_t) + sizeof(jetsam_snapshot_entry_t) * jetsam_snapshot_list_count;
	}
	if (!currentsize) {
		if (req->oldptr) {
#ifdef DEBUG
			printf("kern.memorystatus_snapshot returning EINVAL\n");
#endif
			return EINVAL;
		}
		else {
#ifdef DEBUG
			printf("kern.memorystatus_snapshot returning 0 for size\n");
#endif
		}
	} else {
#ifdef DEBUG
			printf("kern.memorystatus_snapshot returning %ld for size\n", (long)currentsize);
#endif
	}	
	ret = sysctl_io_variable(req, &jetsam_snapshot, currentsize, 0, NULL);
	if (!ret && req->oldptr) {
		jetsam_snapshot.entry_count = jetsam_snapshot_list_count = 0;
	}
	return ret;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_priority_list, CTLTYPE_OPAQUE|CTLFLAG_RW | CTLFLAG_LOCKED, 0, 0, sysctl_handle_kern_memorystatus_priority_list, "S,jetsam_priorities", "");
SYSCTL_PROC(_kern, OID_AUTO, memorystatus_snapshot, CTLTYPE_OPAQUE|CTLFLAG_RD, 0, 0, sysctl_handle_kern_memorystatus_snapshot, "S,jetsam_snapshot", "");

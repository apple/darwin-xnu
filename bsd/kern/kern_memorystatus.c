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

extern unsigned int    vm_page_free_count;
extern unsigned int    vm_page_active_count;
extern unsigned int    vm_page_inactive_count;
extern unsigned int    vm_page_purgeable_count;
extern unsigned int    vm_page_wire_count;

static void kern_memorystatus_thread(void);

int kern_memorystatus_wakeup = 0;
int kern_memorystatus_level = 0;
int kern_memorystatus_last_level = 0;
unsigned int kern_memorystatus_kev_failure_count = 0;
int kern_memorystatus_level_critical = 5;

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

SYSCTL_INT(_kern, OID_AUTO, memorystatus_level, CTLFLAG_RD, &kern_memorystatus_level, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_kev_failure_count, CTLFLAG_RD, &kern_memorystatus_kev_failure_count, 0, "");

__private_extern__ void
kern_memorystatus_init(void)
{
    jetsam_lck_attr = lck_attr_alloc_init();
    jetsam_lck_grp_attr= lck_grp_attr_alloc_init();
    jetsam_lck_grp = lck_grp_alloc_init("jetsam",  jetsam_lck_grp_attr);
    jetsam_list_mlock = lck_mtx_alloc_init(jetsam_lck_grp, jetsam_lck_attr);

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
jetsam_mark_pid_in_snapshot(pid_t pid)
{

	int i = 0;

	for (i = 0; i < jetsam_snapshot_list_count; i++) {
		if (jetsam_snapshot_list[i].pid == pid) {
			jetsam_snapshot_list[i].flags |= kJetsamFlagsKilled;
			return;
		}
	}
}

static int
jetsam_kill_top_proc(void)
{
	proc_t p;

	if (jetsam_snapshot_list_count == 0) {
		jetsam_snapshot_procs();
	}
	lck_mtx_lock(jetsam_list_mlock);
	while (jetsam_priority_list_index < jetsam_priority_list_count) {
		pid_t aPid;
		aPid = jetsam_priority_list[jetsam_priority_list_index].pid;
		jetsam_priority_list_index++;
		/* skip empty slots in the list */
		if (aPid == 0) {
			continue; // with lock held
		}
		lck_mtx_unlock(jetsam_list_mlock);
		jetsam_mark_pid_in_snapshot(aPid);
		p = proc_find(aPid);
		if (p != NULL) {
#if DEBUG
			printf("jetsam: killing pid %d [%s] - memory_status_level: %d - ", aPid, p->p_comm, kern_memorystatus_level);
#endif /* DEBUG */
			exit1(p, W_EXITCODE(0, SIGKILL), (int *)NULL);
			proc_rele(p);
#if DEBUG
			printf("jetsam: pid %d killed - memory_status_level: %d\n", aPid, kern_memorystatus_level);
#endif /* DEBUG */
			return 0;
		}
	    lck_mtx_lock(jetsam_list_mlock);
	}
	lck_mtx_unlock(jetsam_list_mlock);
	return -1;
}

static void
kern_memorystatus_thread(void)
{
	struct kev_msg ev_msg;
	jetsam_kernel_stats_t data;
	int ret;

	while(1) {

		while (kern_memorystatus_level <= kern_memorystatus_level_critical) {
			if (jetsam_kill_top_proc() < 0) {
				break;
			}
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

		if (jetsam_snapshot_list_count) {
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
		jetsam_priority_list_count = newsize / sizeof(jetsam_priority_list[0]);
#if DEBUG 
		printf("set jetsam priority pids = { ");
		for (i = 0; i < jetsam_priority_list_count; i++) {
			printf("%d ", temp_list[i].pid);
		}
		printf("}\n");
#endif /* DEBUG */
		lck_mtx_lock(jetsam_list_mlock);
		for (i = 0; i < jetsam_priority_list_count; i++) {
			jetsam_priority_list[i] = temp_list[i];
		}
		for (i = jetsam_priority_list_count; i < kMaxPriorityEntries; i++) {
			jetsam_priority_list[i].pid = 0;
			jetsam_priority_list[i].flags = 0;
		}
		jetsam_priority_list_index = 0;
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

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_priority_list, CTLTYPE_OPAQUE|CTLFLAG_RW, 0, 0, sysctl_handle_kern_memorystatus_priority_list, "S,jetsam_priorities", "");
SYSCTL_PROC(_kern, OID_AUTO, memorystatus_snapshot, CTLTYPE_OPAQUE|CTLFLAG_RD, 0, 0, sysctl_handle_kern_memorystatus_snapshot, "S,jetsam_snapshot", "");

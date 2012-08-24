/*
 * Copyright (c) 2009-2010 Apple Inc. All rights reserved.
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

#include <libkern/libkern.h>
#include <mach/mach_types.h>
#include <mach/task.h>
#include <sys/proc_internal.h>
#include <sys/event.h>
#include <sys/eventvar.h>
#include <kern/locks.h>
#include <sys/queue.h>
#include <kern/vm_pressure.h>
#include <sys/malloc.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <kern/assert.h>
#include <vm/vm_pageout.h>

#if CONFIG_MEMORYSTATUS
#include <sys/kern_memorystatus.h>
#endif

/* 
 * This value is the threshold that a process must meet to be considered for scavenging.
 */
#define VM_PRESSURE_MINIMUM_RSIZE		10	/* MB */
#define VM_PRESSURE_NOTIFY_WAIT_PERIOD		10000	/* milliseconds */

static void vm_pressure_klist_lock(void);
static void vm_pressure_klist_unlock(void);

static void vm_dispatch_memory_pressure(void);
static kern_return_t vm_try_pressure_candidates(void);
static void vm_reset_active_list(void);

static lck_mtx_t vm_pressure_klist_mutex;

struct klist vm_pressure_klist;
struct klist vm_pressure_klist_dormant;

#if DEBUG
#define VM_PRESSURE_DEBUG(cond, format, ...)      \
do {                                              \
	if (cond) { printf(format, ##__VA_ARGS__); } \
} while(0)
#else
#define VM_PRESSURE_DEBUG(cond, format, ...)
#endif

void vm_pressure_init(lck_grp_t *grp, lck_attr_t *attr) {
	lck_mtx_init(&vm_pressure_klist_mutex, grp, attr);
}

static void vm_pressure_klist_lock(void) {
	lck_mtx_lock(&vm_pressure_klist_mutex);
}

static void vm_pressure_klist_unlock(void) {
	lck_mtx_unlock(&vm_pressure_klist_mutex);
}

int vm_knote_register(struct knote *kn) {
	int rv = 0;
	
	vm_pressure_klist_lock();
	
	if ((kn->kn_sfflags) & (NOTE_VM_PRESSURE)) {
		KNOTE_ATTACH(&vm_pressure_klist, kn);
	} else {	  
		rv = ENOTSUP;
	}
	
	vm_pressure_klist_unlock();
	
	return rv;
}

void vm_knote_unregister(struct knote *kn) {
	struct knote *kn_temp;
	
	vm_pressure_klist_lock();
	
	VM_PRESSURE_DEBUG(0, "[vm_pressure] process %d cancelling pressure notification\n", kn->kn_kq->kq_p->p_pid);
	
	SLIST_FOREACH(kn_temp, &vm_pressure_klist, kn_selnext) {
		if (kn_temp == kn) {
			KNOTE_DETACH(&vm_pressure_klist, kn);
			vm_pressure_klist_unlock();
			return;
		}
	}

	SLIST_FOREACH(kn_temp, &vm_pressure_klist_dormant, kn_selnext) {
		if (kn_temp == kn) {
			KNOTE_DETACH(&vm_pressure_klist_dormant, kn);
			vm_pressure_klist_unlock();
			return;
		}
	}
	
	vm_pressure_klist_unlock();
}

void vm_pressure_proc_cleanup(proc_t p)
{
	struct knote *kn = NULL;

	vm_pressure_klist_lock();
	
	VM_PRESSURE_DEBUG(0, "[vm_pressure] process %d exiting pressure notification\n", p->p_pid);
	
	SLIST_FOREACH(kn, &vm_pressure_klist, kn_selnext) {
		if (kn->kn_kq->kq_p == p) {
			KNOTE_DETACH(&vm_pressure_klist, kn);
			vm_pressure_klist_unlock();
			return;
		}
	}
	
	SLIST_FOREACH(kn, &vm_pressure_klist_dormant, kn_selnext) {
		if (kn->kn_kq->kq_p == p) {
			KNOTE_DETACH(&vm_pressure_klist_dormant, kn);
			vm_pressure_klist_unlock();
			return;
		}
	}
	
	vm_pressure_klist_unlock();
}

void consider_vm_pressure_events(void)
{
	vm_dispatch_memory_pressure();
}

static void vm_dispatch_memory_pressure(void)
{
	vm_pressure_klist_lock();
	
	if (!SLIST_EMPTY(&vm_pressure_klist)) {
		
		VM_PRESSURE_DEBUG(1, "[vm_pressure] vm_dispatch_memory_pressure\n");
		
		if (vm_try_pressure_candidates() == KERN_SUCCESS) {
			vm_pressure_klist_unlock();
			return;
		}
		
	}
	
	VM_PRESSURE_DEBUG(1, "[vm_pressure] could not find suitable event candidate\n");
	
	vm_reset_active_list();
	
	vm_pressure_klist_unlock();
}

#if CONFIG_JETSAM

/* Jetsam aware version. Called with lock held */

static struct knote * vm_find_knote_from_pid(pid_t pid) {
	struct knote *kn = NULL;
    
	SLIST_FOREACH(kn, &vm_pressure_klist, kn_selnext) {
		struct proc *p;
		pid_t current_pid;

		p = kn->kn_kq->kq_p;
		current_pid = p->p_pid;

		if (current_pid == pid) {
			break;
		}
	}
    
	return kn;
}

static kern_return_t vm_try_pressure_candidates(void)
{
        struct knote *kn = NULL;
        pid_t target_pid = (pid_t)-1;

        /* If memory is low, and there's a pid to target... */
        target_pid = memorystatus_request_vm_pressure_candidate();
        while (target_pid != -1) {
                /* ...look it up in the list, and break if found... */
                if ((kn = vm_find_knote_from_pid(target_pid))) {
                        break;
                }

                /* ...otherwise, go round again. */
                target_pid = memorystatus_request_vm_pressure_candidate();
        }

        if (NULL == kn) {
                VM_PRESSURE_DEBUG(0, "[vm_pressure] can't find candidate pid\n");
                return KERN_FAILURE;
        }

        /* ...and dispatch the note */
        VM_PRESSURE_DEBUG(1, "[vm_pressure] sending event to pid %d, free pages %d\n", kn->kn_kq->kq_p->p_pid, memorystatus_available_pages);

        KNOTE(&vm_pressure_klist, target_pid);
        
        memorystatus_send_pressure_note(target_pid);

        return KERN_SUCCESS;
}

static void vm_reset_active_list(void) {
        /* No-op */
}

#if DEVELOPMENT || DEBUG

/* Test purposes only */
boolean_t vm_dispatch_pressure_note_to_pid(pid_t pid) {
	struct knote *kn;
    
	vm_pressure_klist_lock();
    
	kn = vm_find_knote_from_pid(pid);
	if (kn) {
		KNOTE(&vm_pressure_klist, pid);
	}
    
	vm_pressure_klist_unlock();
    
	return kn ? TRUE : FALSE;
}

#endif /* DEVELOPMENT || DEBUG */

#else /* CONFIG_MEMORYSTATUS */

static kern_return_t vm_try_pressure_candidates(void)
{
	struct knote *kn = NULL, *kn_max = NULL;
        unsigned int resident_max = 0;
        pid_t target_pid = -1;
        struct klist dispatch_klist = { NULL };
	kern_return_t kr = KERN_SUCCESS;
	struct timeval curr_tstamp = {0, 0};
	int elapsed_msecs = 0;
	proc_t	target_proc = PROC_NULL;

	microuptime(&curr_tstamp);
	
        SLIST_FOREACH(kn, &vm_pressure_klist, kn_selnext) {
                struct mach_task_basic_info basic_info;
                mach_msg_type_number_t  size = MACH_TASK_BASIC_INFO_COUNT;
                unsigned int		resident_size = 0;
		proc_t			p = PROC_NULL;
		struct task*		t = TASK_NULL;

		p = kn->kn_kq->kq_p;
		proc_list_lock();
		if (p != proc_ref_locked(p)) {
			p = PROC_NULL;
			proc_list_unlock();
			continue;
		}
		proc_list_unlock();

		t = (struct task *)(p->task);
		
		timevalsub(&curr_tstamp, &p->vm_pressure_last_notify_tstamp);
		elapsed_msecs = curr_tstamp.tv_sec * 1000 + curr_tstamp.tv_usec / 1000;
							
		if (elapsed_msecs < VM_PRESSURE_NOTIFY_WAIT_PERIOD) {
			proc_rele(p);
			continue;
		}

                if( ( kr = task_info(t, MACH_TASK_BASIC_INFO, (task_info_t)(&basic_info), &size)) != KERN_SUCCESS ) {
                        VM_PRESSURE_DEBUG(1, "[vm_pressure] task_info for pid %d failed with %d\n", p->p_pid, kr);
			proc_rele(p);
                        continue;
                }

                /* 
                * We don't want a small process to block large processes from 
                * being notified again. <rdar://problem/7955532>
                */
                resident_size = (basic_info.resident_size)/(MB);
                if (resident_size >= VM_PRESSURE_MINIMUM_RSIZE) {
                        if (resident_size > resident_max) {
                                resident_max = resident_size;
                                kn_max = kn;
                                target_pid = p->p_pid;
				target_proc = p;
                        }
                } else {
                        /* There was no candidate with enough resident memory to scavenge */
                        VM_PRESSURE_DEBUG(0, "[vm_pressure] threshold failed for pid %d with %u resident...\n", p->p_pid, resident_size);
                }
		proc_rele(p);
        }

        if (kn_max == NULL || target_pid == -1) {
		return KERN_FAILURE;
	}

	VM_DEBUG_EVENT(vm_pageout_scan, VM_PRESSURE_EVENT, DBG_FUNC_NONE, target_pid, resident_max, 0, 0);
        VM_PRESSURE_DEBUG(1, "[vm_pressure] sending event to pid %d with %u resident\n", kn_max->kn_kq->kq_p->p_pid, resident_max);

        KNOTE_DETACH(&vm_pressure_klist, kn_max);

	target_proc = proc_find(target_pid);
	if (target_proc != PROC_NULL) {
        	KNOTE_ATTACH(&dispatch_klist, kn_max);
        	KNOTE(&dispatch_klist, target_pid);
        	KNOTE_ATTACH(&vm_pressure_klist_dormant, kn_max);

		microuptime(&target_proc->vm_pressure_last_notify_tstamp);
		proc_rele(target_proc);
	}

        return KERN_SUCCESS;
}

/*
 * Remove all elements from the dormant list and place them on the active list.
 * Called with klist lock held.
 */
static void vm_reset_active_list(void) {
	/* Re-charge the main list from the dormant list if possible */
	if (!SLIST_EMPTY(&vm_pressure_klist_dormant)) {
		struct knote *kn;

		VM_PRESSURE_DEBUG(1, "[vm_pressure] recharging main list from dormant list\n");
        
		while (!SLIST_EMPTY(&vm_pressure_klist_dormant)) {
			kn = SLIST_FIRST(&vm_pressure_klist_dormant);
			SLIST_REMOVE_HEAD(&vm_pressure_klist_dormant, kn_selnext);
			SLIST_INSERT_HEAD(&vm_pressure_klist, kn, kn_selnext);
		}
	}
}

#endif /* CONFIG_MEMORYSTATUS */

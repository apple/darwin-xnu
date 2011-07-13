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

void vm_pressure_klist_lock(void);
void vm_pressure_klist_unlock(void);

void vm_dispatch_memory_pressure(void);
int vm_try_terminate_candidates(void);
int vm_try_pressure_candidates(void);
void vm_recharge_active_list(void);

struct klist vm_pressure_klist;
struct klist vm_pressure_klist_dormant;

void vm_pressure_klist_lock(void) {
	lck_mtx_lock(&vm_pressure_klist_mutex);
}

void vm_pressure_klist_unlock(void) {
	lck_mtx_unlock(&vm_pressure_klist_mutex);
}

int vm_knote_register(struct knote *kn) {
	int rv = 0;
	
	vm_pressure_klist_lock();
	
	if ((kn->kn_sfflags & (NOTE_VM_PRESSURE))) {
#if DEBUG
		printf("[vm_pressure] process %d registering pressure notification\n", kn->kn_kq->kq_p->p_pid);
#endif
		KNOTE_ATTACH(&vm_pressure_klist, kn);
	} else
		rv = ENOTSUP;
	
	vm_pressure_klist_unlock();
	
	return rv;
}

void vm_knote_unregister(struct knote *kn) {
	struct knote *kn_temp;
	
	vm_pressure_klist_lock();
	
#if DEBUG
	printf("[vm_pressure] process %d cancelling pressure notification\n", kn->kn_kq->kq_p->p_pid);
#endif
	
	SLIST_FOREACH(kn_temp, &vm_pressure_klist, kn_selnext) {
		if (kn_temp == kn) {
			KNOTE_DETACH(&vm_pressure_klist, kn);
			vm_pressure_klist_unlock();
			return;
		}
	}
	KNOTE_DETACH(&vm_pressure_klist_dormant, kn);
	
	vm_pressure_klist_unlock();
}

/* Interface for event dispatch from vm_pageout_garbage_collect thread */
void consider_pressure_events(void) {
	vm_dispatch_memory_pressure();
}

void vm_dispatch_memory_pressure(void) {	
	vm_pressure_klist_lock();
	
	if (!SLIST_EMPTY(&vm_pressure_klist)) {
		
#if DEBUG
		printf("[vm_pressure] vm_dispatch_memory_pressure\n");
#endif
		
		if (vm_try_pressure_candidates()) {
			vm_pressure_klist_unlock();
			return;
		}
		
	}
	
	/* Else... */
	
#if DEBUG
	printf("[vm_pressure] could not find suitable event candidate\n");
#endif
	
	vm_recharge_active_list();
	
	vm_pressure_klist_unlock();
}

/*
 * Try standard pressure event candidates.  Called with klist lock held.
 */
int vm_try_pressure_candidates(void) {
	/* 
	 * This value is the threshold that a process must meet to be considered for scavenging.
	 * If a process has sufficiently little resident memory, there is probably no use scavenging it.
	 * At best, we'll scavenge very little memory.  At worst, we'll page in code pages or malloc metadata.
	 */
	
#define VM_PRESSURE_MINIMUM_RSIZE	(10 * 1024 * 1024)
	
	struct proc *p_max = NULL;
	unsigned int resident_max = 0;
	struct knote *kn_max = NULL;
	struct knote *kn;
	
	SLIST_FOREACH(kn, &vm_pressure_klist, kn_selnext) {
		if ( (kn != NULL ) && ( kn->kn_kq != NULL ) && ( kn->kn_kq->kq_p != NULL ) ) {
			if (kn->kn_sfflags & NOTE_VM_PRESSURE) {
				struct proc *p = kn->kn_kq->kq_p;
				if (!(kn->kn_status & KN_DISABLED)) {
					kern_return_t kr = KERN_SUCCESS;
					struct task *t = (struct task *)(p->task);
					struct task_basic_info basic_info;
					mach_msg_type_number_t size = TASK_BASIC_INFO_COUNT;
					if( ( kr = task_info(t, TASK_BASIC_INFO, (task_info_t)(&basic_info), &size)) == KERN_SUCCESS ) {
						unsigned int resident_size = basic_info.resident_size;
						/* 
						 * We don't want a small process to block large processes from 
						 * being notified again.  <rdar://problem/7955532>
						 */						
						if (resident_size >= VM_PRESSURE_MINIMUM_RSIZE) {
							if (resident_size > resident_max) {
								p_max = p;
								resident_max = resident_size;
								kn_max = kn;
							}
						} else {
#if DEBUG
							/* There was no candidate with enough resident memory to scavenge */
							/* This debug print makes too much noise now */
							//printf("[vm_pressure] threshold failed for pid %d with %u resident, skipping...\n", p->p_pid, resident_size);
#endif
						}
					} else {
#if DEBUG
						printf("[vm_pressure] task_info for pid %d failed with %d\n", p->p_pid, kr);
#endif
					}
				} else {
#if DEBUG
					printf("[vm_pressure] pid %d currently disabled, skipping...\n", p->p_pid);
#endif
				}
			}
		} else {
#if DEBUG
			if (kn == NULL) {
				printf("[vm_pressure] kn is NULL\n");
			} else if (kn->kn_kq == NULL) {
				printf("[vm_pressure] kn->kn_kq is NULL\n");
			} else if (kn->kn_kq->kq_p == NULL) {
				printf("[vm_pressure] kn->kn_kq->kq_p is NULL\n");
			}
#endif
		}
	}
	
	if (kn_max == NULL) return 0;

#if DEBUG
	printf("[vm_pressure] sending event to pid %d with %u resident\n", kn_max->kn_kq->kq_p->p_pid, resident_max);
#endif

	KNOTE_DETACH(&vm_pressure_klist, kn_max);
	struct klist dispatch_klist = { NULL };
	KNOTE_ATTACH(&dispatch_klist, kn_max);
	KNOTE(&dispatch_klist, NOTE_VM_PRESSURE);
	KNOTE_ATTACH(&vm_pressure_klist_dormant, kn_max);
	
	return 1;
}


/*
 * Remove all elements from the dormant list and place them on the active list.
 * Called with klist lock held.
 */
void vm_recharge_active_list(void) {
	/* Re-charge the main list from the dormant list if possible */
	if (!SLIST_EMPTY(&vm_pressure_klist_dormant)) {
#if DEBUG
		printf("[vm_pressure] recharging main list from dormant list\n");
#endif	
		struct knote *kn;
		while (!SLIST_EMPTY(&vm_pressure_klist_dormant)) {
			kn = SLIST_FIRST(&vm_pressure_klist_dormant);
			SLIST_REMOVE_HEAD(&vm_pressure_klist_dormant, kn_selnext);
			SLIST_INSERT_HEAD(&vm_pressure_klist, kn, kn_selnext);
		}
	}
}

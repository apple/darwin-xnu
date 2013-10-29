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
#include <kern/task.h>
#include <vm/vm_pageout.h>

#include <kern/task.h>

#if CONFIG_MEMORYSTATUS
#include <sys/kern_memorystatus.h>
#endif

/* 
 * This value is the threshold that a process must meet to be considered for scavenging.
 */
#define VM_PRESSURE_MINIMUM_RSIZE		10	/* MB */
#define VM_PRESSURE_NOTIFY_WAIT_PERIOD		10000	/* milliseconds */

void vm_pressure_klist_lock(void);
void vm_pressure_klist_unlock(void);

static void vm_dispatch_memory_pressure(void);
void vm_reset_active_list(void);

#if !(CONFIG_MEMORYSTATUS && CONFIG_JETSAM)
static kern_return_t vm_try_pressure_candidates(void);
#endif

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

void vm_pressure_klist_lock(void) {
	lck_mtx_lock(&vm_pressure_klist_mutex);
}

void vm_pressure_klist_unlock(void) {
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

/*
 * Used by the vm_pressure_thread which is
 * signalled from within vm_pageout_scan().
 */
void consider_vm_pressure_events(void)
{
	vm_dispatch_memory_pressure();
}

#if CONFIG_MEMORYSTATUS && CONFIG_JETSAM

static void vm_dispatch_memory_pressure(void)
{
	/* Update the pressure level and target the foreground or next-largest process as appropriate */
	memorystatus_update_vm_pressure(FALSE);
}

/* Jetsam aware version. Called with lock held */

static struct knote *vm_find_knote_from_pid(pid_t pid, struct klist *list) {
	struct knote *kn = NULL;
    
	SLIST_FOREACH(kn, list, kn_selnext) {
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

int vm_dispatch_pressure_note_to_pid(pid_t pid, boolean_t locked) {
	int ret = EINVAL;
	struct knote *kn;
    
	VM_PRESSURE_DEBUG(1, "vm_dispatch_pressure_note_to_pid(): pid %d\n", pid);
	
	if (!locked) {
		vm_pressure_klist_lock();	    
	}
    
	/* 
	 * Because we're specifically targeting a process here, we don't care
	 * if a warning has already been sent and it's moved to the dormant
	 * list; check that too.
	 */
	kn = vm_find_knote_from_pid(pid, &vm_pressure_klist);
	if (kn) {
    		KNOTE(&vm_pressure_klist, pid);
    		ret = 0;
	} else {	
	        kn = vm_find_knote_from_pid(pid, &vm_pressure_klist_dormant);
	        if (!kn) {
        		KNOTE(&vm_pressure_klist_dormant, pid);
	        }
	}

	if (!locked) {
		vm_pressure_klist_unlock();	    
	}

	return ret;
}

void vm_find_pressure_foreground_candidates(void)
{
	struct knote *kn, *kn_tmp;
	struct klist dispatch_klist = { NULL };

	vm_pressure_klist_lock();
	proc_list_lock();
	
	/* Find the foreground processes. */
	SLIST_FOREACH_SAFE(kn, &vm_pressure_klist, kn_selnext, kn_tmp) {
		proc_t p = kn->kn_kq->kq_p;

		if (memorystatus_is_foreground_locked(p)) {
			KNOTE_DETACH(&vm_pressure_klist, kn);  
			KNOTE_ATTACH(&dispatch_klist, kn);          
		}
	}

	SLIST_FOREACH_SAFE(kn, &vm_pressure_klist_dormant, kn_selnext, kn_tmp) {
		proc_t p = kn->kn_kq->kq_p;

		if (memorystatus_is_foreground_locked(p)) {
			KNOTE_DETACH(&vm_pressure_klist_dormant, kn);  
			KNOTE_ATTACH(&dispatch_klist, kn);          
		}
	}

	proc_list_unlock();

	/* Dispatch pressure notifications accordingly */
	SLIST_FOREACH_SAFE(kn, &dispatch_klist, kn_selnext, kn_tmp) {
		proc_t p = kn->kn_kq->kq_p;

		proc_list_lock();
		if (p != proc_ref_locked(p)) {
			proc_list_unlock();
			KNOTE_DETACH(&dispatch_klist, kn);
			KNOTE_ATTACH(&vm_pressure_klist_dormant, kn);
			continue;
		}
		proc_list_unlock();
  
		VM_PRESSURE_DEBUG(1, "[vm_pressure] sending event to pid %d\n", kn->kn_kq->kq_p->p_pid);
		KNOTE(&dispatch_klist, p->p_pid);
		KNOTE_DETACH(&dispatch_klist, kn);
		KNOTE_ATTACH(&vm_pressure_klist_dormant, kn);
		microuptime(&p->vm_pressure_last_notify_tstamp);
		memorystatus_send_pressure_note(p->p_pid);
		proc_rele(p);
	}

	vm_pressure_klist_unlock();
}

void vm_find_pressure_candidate(void)
{
	struct knote *kn = NULL, *kn_max = NULL;
	unsigned int resident_max = 0;
	pid_t target_pid = -1;
	struct klist dispatch_klist = { NULL };
	struct timeval curr_tstamp = {0, 0};
	int elapsed_msecs = 0;
	proc_t target_proc = PROC_NULL;
	kern_return_t kr = KERN_SUCCESS;

	microuptime(&curr_tstamp);
	
	vm_pressure_klist_lock();
	
	SLIST_FOREACH(kn, &vm_pressure_klist, kn_selnext) {\
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
		
		if (!memorystatus_bg_pressure_eligible(p)) {
			VM_PRESSURE_DEBUG(1, "[vm_pressure] skipping process %d\n", p->p_pid);
			proc_rele(p);
			continue;			
		}

		if( ( kr = task_info(t, MACH_TASK_BASIC_INFO, (task_info_t)(&basic_info), &size)) != KERN_SUCCESS ) {
			VM_PRESSURE_DEBUG(1, "[vm_pressure] task_info for pid %d failed\n", p->p_pid);
			proc_rele(p);
			continue;
		}

		/* 
		 * We don't want a small process to block large processes from 
		 * being notified again. <rdar://problem/7955532>
		 */
		resident_size = (basic_info.resident_size)/(1024 * 1024);
		if (resident_size >= VM_PRESSURE_MINIMUM_RSIZE) {
			if (resident_size > resident_max) {
				resident_max = resident_size;
				kn_max = kn;
				target_pid = p->p_pid;
				target_proc = p;
			}
		} else {
			/* There was no candidate with enough resident memory to scavenge */
			VM_PRESSURE_DEBUG(1, "[vm_pressure] threshold failed for pid %d with %u resident...\n", p->p_pid, resident_size);
		}
		proc_rele(p);
	}

	if (kn_max == NULL || target_pid == -1) {
		VM_PRESSURE_DEBUG(1, "[vm_pressure] - no target found!\n");
		goto exit;
	}

	VM_DEBUG_EVENT(vm_pageout_scan, VM_PRESSURE_EVENT, DBG_FUNC_NONE, target_pid, resident_max, 0, 0);
	VM_PRESSURE_DEBUG(1, "[vm_pressure] sending event to pid %d with %u resident\n", kn_max->kn_kq->kq_p->p_pid, resident_max);

	KNOTE_DETACH(&vm_pressure_klist, kn_max);

	target_proc = proc_find(target_pid);
	if (target_proc != PROC_NULL) {
		KNOTE_ATTACH(&dispatch_klist, kn_max);
		KNOTE(&dispatch_klist, target_pid);
		KNOTE_ATTACH(&vm_pressure_klist_dormant, kn_max);
		memorystatus_send_pressure_note(target_pid);
		microuptime(&target_proc->vm_pressure_last_notify_tstamp);
		proc_rele(target_proc);
	}

exit:
	vm_pressure_klist_unlock();
}

#else /* CONFIG_MEMORYSTATUS && CONFIG_JETSAM */

struct knote *
vm_pressure_select_optimal_candidate_to_notify(struct klist *candidate_list, int level);

kern_return_t vm_pressure_notification_without_levels(void);
kern_return_t vm_pressure_notify_dispatch_vm_clients(void);

kern_return_t
vm_pressure_notify_dispatch_vm_clients(void)
{
	vm_pressure_klist_lock();
	
	if (SLIST_EMPTY(&vm_pressure_klist)) {
		vm_reset_active_list();
	}
	
	if (!SLIST_EMPTY(&vm_pressure_klist)) {
		
		VM_PRESSURE_DEBUG(1, "[vm_pressure] vm_dispatch_memory_pressure\n");
		
		if (KERN_SUCCESS == vm_try_pressure_candidates()) {
			vm_pressure_klist_unlock();
			return KERN_SUCCESS;
		}
	}
	
	VM_PRESSURE_DEBUG(1, "[vm_pressure] could not find suitable event candidate\n");
	
	vm_pressure_klist_unlock();

	return KERN_FAILURE;
}

static void vm_dispatch_memory_pressure(void)
{
	memorystatus_update_vm_pressure(FALSE);
}

extern vm_pressure_level_t
convert_internal_pressure_level_to_dispatch_level(vm_pressure_level_t);

struct knote *
vm_pressure_select_optimal_candidate_to_notify(struct klist *candidate_list, int level)
{
	struct knote	*kn = NULL, *kn_max = NULL;
        unsigned int	resident_max = 0;
	kern_return_t	kr = KERN_SUCCESS;
	struct timeval	curr_tstamp = {0, 0};
	int		elapsed_msecs = 0;
	int		selected_task_importance = 0;
	static int	pressure_snapshot = -1;
	boolean_t	pressure_increase = FALSE;

	if (level != -1) {
	
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
	}

	if ((level > 0) && (pressure_increase) == TRUE) {
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

                struct mach_task_basic_info basic_info;
                mach_msg_type_number_t  size = MACH_TASK_BASIC_INFO_COUNT;
                unsigned int		resident_size = 0;
		proc_t			p = PROC_NULL;
		struct task*		t = TASK_NULL;
		int			curr_task_importance = 0;
		boolean_t		consider_knote = FALSE;

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
							
		if ((level == -1) && (elapsed_msecs < VM_PRESSURE_NOTIFY_WAIT_PERIOD)) { 
			proc_rele(p);
			continue;
		}

		if (level != -1) {
			/*
			 * For the level based notifications, check and see if this knote is
			 * registered for the current level.
			 */
			vm_pressure_level_t dispatch_level = convert_internal_pressure_level_to_dispatch_level(level);
	
			if ((kn->kn_sfflags & dispatch_level) == 0) {
				proc_rele(p);
				continue;
			}
		}
	
                if( ( kr = task_info(t, MACH_TASK_BASIC_INFO, (task_info_t)(&basic_info), &size)) != KERN_SUCCESS ) {
                        VM_PRESSURE_DEBUG(1, "[vm_pressure] task_info for pid %d failed with %d\n", p->p_pid, kr);
			proc_rele(p);
                        continue;
                }

		curr_task_importance = task_importance_estimate(t);

                /* 
                * We don't want a small process to block large processes from 
                * being notified again. <rdar://problem/7955532>
                */
                resident_size = (basic_info.resident_size)/(MB);

                if (resident_size >= VM_PRESSURE_MINIMUM_RSIZE) {

			if (level > 0) {
				/*
				 * Warning or Critical Pressure.
				 */
                        	if (pressure_increase) {
					if ((curr_task_importance <= selected_task_importance) && (resident_size > resident_max)) {
						if (task_has_been_notified(t, level) == FALSE) {
							consider_knote = TRUE;
						}
					}
				} else {
					if ((curr_task_importance >= selected_task_importance) && (resident_size > resident_max)) {
						if (task_has_been_notified(t, level) == FALSE) {
							consider_knote = TRUE;
						}
					}
				}
			} else if (level == 0) {
                        	/*
				 * Pressure back to normal.
				 */
				if ((curr_task_importance >= selected_task_importance) && (resident_size > resident_max)) {

					if ((task_has_been_notified(t, kVMPressureWarning) == TRUE) || (task_has_been_notified(t, kVMPressureCritical) == TRUE)) {
						consider_knote = TRUE;
					}
				}
			} else if (level == -1) {

				/*
				 * Simple (importance and level)-free behavior based solely on RSIZE.
				 */
				if (resident_size > resident_max) {
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
                        VM_PRESSURE_DEBUG(0, "[vm_pressure] threshold failed for pid %d with %u resident...\n", p->p_pid, resident_size);
                }
		proc_rele(p);
        }

	if (kn_max) {
        	VM_PRESSURE_DEBUG(1, "[vm_pressure] sending event to pid %d with %u resident\n", kn_max->kn_kq->kq_p->p_pid, resident_max);
	}

	return kn_max;
}

/*
 * vm_pressure_klist_lock is held for this routine.
 */
kern_return_t vm_pressure_notification_without_levels(void)
{
	struct knote *kn_max = NULL;
        pid_t target_pid = -1;
        struct klist dispatch_klist = { NULL };
	proc_t	target_proc = PROC_NULL;

	kn_max = vm_pressure_select_optimal_candidate_to_notify(&vm_pressure_klist, -1);

        if (kn_max == NULL) {
		return KERN_FAILURE;
	}
		
	target_proc = kn_max->kn_kq->kq_p;
	
        KNOTE_DETACH(&vm_pressure_klist, kn_max);

	if (target_proc != PROC_NULL) {
	
		target_pid = target_proc->p_pid;
	    
		memoryshot(VM_PRESSURE_EVENT, DBG_FUNC_NONE);

        	KNOTE_ATTACH(&dispatch_klist, kn_max);
        	KNOTE(&dispatch_klist, target_pid);
        	KNOTE_ATTACH(&vm_pressure_klist_dormant, kn_max);

		microuptime(&target_proc->vm_pressure_last_notify_tstamp);
	}

        return KERN_SUCCESS;
}

static kern_return_t vm_try_pressure_candidates(void)
{
	/*
	 * This takes care of candidates that use NOTE_VM_PRESSURE.
	 * It's a notification without indication of the level
	 * of memory pressure.
	 */
	return (vm_pressure_notification_without_levels());
}

#endif /* !(CONFIG_MEMORYSTATUS && CONFIG_JETSAM) */

/*
 * Remove all elements from the dormant list and place them on the active list.
 * Called with klist lock held.
 */
void vm_reset_active_list(void) {
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

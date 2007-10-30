/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
/*
 	File:		PseudoKernel.c

 	Contains:	BlueBox PseudoKernel calls
	Written by:	Mark Gorlinsky
				Bill Angell

 	Copyright:	1997 by Apple Computer, Inc., all rights reserved

*/

#include <mach/mach_types.h>
#include <mach/mach_host.h>
#include <mach/kern_return.h>

#include <kern/kalloc.h>
#include <kern/kern_types.h>
#include <kern/host.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <ppc/PseudoKernel.h>
#include <ppc/exception.h>
#include <ppc/misc_protos.h>
#include <ppc/proc_reg.h>

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>

extern int is_suser(void);
extern void tbeproc(void *proc);

void bbSetRupt(ReturnHandler *rh, thread_t ct);

/*
** Function:	NotifyInterruption
**
** Inputs:
**		ppcInterrupHandler	- interrupt handler to execute
**		interruptStatePtr	- current interrupt state
**
** Outputs:
**
** Notes:
**
*/
kern_return_t
syscall_notify_interrupt(void)
{
	task_t			task;
	thread_t 		act, fact;
	bbRupt			*bbr;
	BTTD_t			*bttd;
	int				i;

	task = current_task();							/* Figure out who our task is */

	task_lock(task);						/* Lock our task */
	
	fact = (thread_t)task->threads.next;		/* Get the first activation on task */
	act = NULL;										/* Pretend we didn't find it yet */
	
	for(i = 0; i < task->thread_count; i++) {		/* Scan the whole list */
		if(fact->machine.bbDescAddr) {					/* Is this a Blue thread? */
			bttd = (BTTD_t *)(fact->machine.bbDescAddr & -PAGE_SIZE);
			if(bttd->InterruptVector) {				/* Is this the Blue interrupt thread? */
				act = fact;							/* Yeah... */
				break;								/* Found it, Bail the loop... */
			}
		}
		fact = (thread_t)fact->task_threads.next;	/* Go to the next one */
	}

	if(!act) {								/* Couldn't find a bluebox */
		task_unlock(task);					/* Release task lock */
		return KERN_FAILURE;				/* No tickie, no shirtee... */
	}

	thread_reference(act);
	
	task_unlock(task);								/* Safe to release now */

	thread_mtx_lock(act);

	/* if the calling thread is the BlueBox thread that handles interrupts
	 * we know that we are in the PsuedoKernel and we can short circuit 
	 * setting up the asynchronous task by setting a pending interrupt.
	 */
	
	if (act == current_thread()) {		
		bttd->InterruptControlWord = bttd->InterruptControlWord | 
			((bttd->postIntMask >> kCR2ToBackupShift) & kBackupCR2Mask);
				
		thread_mtx_unlock(act);						/* Unlock the activation */
		thread_deallocate(act);
		return KERN_SUCCESS;
	}

	if(act->machine.emPendRupts >= 16) {				/* Have we hit the arbitrary maximum? */
		thread_mtx_unlock(act);						/* Unlock the activation */
		thread_deallocate(act);
		return KERN_RESOURCE_SHORTAGE;				/* Too many pending right now */
	}
	
	if(!(bbr = (bbRupt *)kalloc(sizeof(bbRupt)))) {	/* Get a return handler control block */
		thread_mtx_unlock(act);						/* Unlock the activation */
		thread_deallocate(act);
		return KERN_RESOURCE_SHORTAGE;				/* No storage... */
	}
	
	(void)hw_atomic_add(&act->machine.emPendRupts, 1);	/* Count this 'rupt */
	bbr->rh.handler = bbSetRupt;					/* Set interruption routine */

	bbr->rh.next = act->handlers;					/* Put our interrupt at the start of the list */
	act->handlers = &bbr->rh;

	act_set_apc(act);								/* Set an APC AST */

	thread_mtx_unlock(act);							/* Unlock the activation */
	thread_deallocate(act);
	return KERN_SUCCESS;							/* We're done... */
}

/* 
 *	This guy is fired off asynchronously to actually do the 'rupt.
 *	We will find the user state savearea and modify it.  If we can't,
 *	we just leave after releasing our work area
 */

void bbSetRupt(ReturnHandler *rh, thread_t act) {

	struct savearea	*sv;
	BTTD_t		*bttd;
	bbRupt		*bbr;
	UInt32		interruptState;
	
	bbr = (bbRupt *)rh;								/* Make our area convenient */

	if(!(act->machine.bbDescAddr)) {					/* Is BlueBox still enabled? */
		kfree(bbr, sizeof(bbRupt));	/* No, release the control block */
		return;
	}

	(void)hw_atomic_sub(&act->machine.emPendRupts, 1);	/* Uncount this 'rupt */

	if(!(sv = find_user_regs(act))) {				/* Find the user state registers */
		kfree(bbr, sizeof(bbRupt));	/* Couldn't find 'em, release the control block */
		return;
	}

	bttd = (BTTD_t *)(act->machine.bbDescAddr & -PAGE_SIZE);
		
    interruptState = (bttd->InterruptControlWord & kInterruptStateMask) >> kInterruptStateShift; 

    switch (interruptState) {
		
		case kInSystemContext:
			sv->save_cr |= bttd->postIntMask;		/* post int in CR2 */
			break;
			
		case kInAlternateContext:
			bttd->InterruptControlWord = (bttd->InterruptControlWord & ~kInterruptStateMask) | 
				(kInPseudoKernel << kInterruptStateShift);
				
			bttd->exceptionInfo.srr0 = (unsigned int)sv->save_srr0;		/* Save the current PC */
			sv->save_srr0 = (uint64_t)act->machine.bbInterrupt;	/* Set the new PC */
			bttd->exceptionInfo.sprg1 = (unsigned int)sv->save_r1;		/* Save the original R1 */
			sv->save_r1 = (uint64_t)bttd->exceptionInfo.sprg0;	/* Set the new R1 */
			bttd->exceptionInfo.srr1 = (unsigned int)sv->save_srr1;		/* Save the original MSR */
			sv->save_srr1 &= ~(MASK(MSR_BE)|MASK(MSR_SE));	/* Clear SE|BE bits in MSR */
			act->machine.specFlags &= ~bbNoMachSC;				/* reactivate Mach SCs */ 
			disable_preemption();							/* Don't move us around */
			getPerProc()->spcFlags = act->machine.specFlags;	/* Copy the flags */
			enable_preemption();							/* Ok to move us around */
			/* drop through to post int in backup CR2 in ICW */

		case kInExceptionHandler:
		case kInPseudoKernel:
		case kOutsideBlue:
			bttd->InterruptControlWord = bttd->InterruptControlWord | 
				((bttd->postIntMask >> kCR2ToBackupShift) & kBackupCR2Mask);
			break;
				
		default:
			break;
	}

	kfree(bbr, sizeof(bbRupt));	/* Release the control block */
	return;

}

/*
 * This function is used to enable the firmware assist code for bluebox traps, system calls
 * and interrupts.
 *
 * The assist code can be called from two types of threads.  The blue thread, which handles 
 * traps, system calls and interrupts and preemptive threads that only issue system calls.
 *
 * Parameters:	host			.
 * 		_taskID			opaque task ID
 * 		_TWI_TableStart		Start of TWI table
 * 		_Desc_TableStart	Start of descriptor table
 */ 

kern_return_t
enable_bluebox(host_t host, unsigned _taskID, unsigned _TWI_TableStart,
	       unsigned _Desc_TableStart)
{
	/* XXX mig funness */
	void *taskID = (void *)_taskID;
	void *TWI_TableStart = (void *)_TWI_TableStart;
	char *Desc_TableStart = (char *)_Desc_TableStart;
	
	thread_t 		th;
	vm_offset_t		kerndescaddr, origdescoffset;
	kern_return_t 	ret;
	ppnum_t			physdescpage;
	BTTD_t			*bttd;
	
	th = current_thread();									/* Get our thread */					

	if ( host == HOST_NULL ) return KERN_INVALID_HOST;
	if ( ! is_suser() ) return KERN_FAILURE;						/* We will only do this for the superuser */
	if ( th->machine.bbDescAddr ) return KERN_FAILURE;		/* Bail if already authorized... */
	if ( ! (unsigned int) Desc_TableStart ) return KERN_FAILURE;	/* There has to be a descriptor page */ 
	if ( ! TWI_TableStart ) return KERN_FAILURE;					/* There has to be a TWI table */ 

	/* Get the page offset of the descriptor */
	origdescoffset = (vm_offset_t)Desc_TableStart & (PAGE_SIZE - 1);

	/* Align the descriptor to a page */
	Desc_TableStart = (char *)((vm_offset_t)Desc_TableStart & -PAGE_SIZE);

	ret = vm_map_wire(th->map, 					/* Kernel wire the descriptor in the user's map */
		(vm_offset_t)Desc_TableStart,
		(vm_offset_t)Desc_TableStart + PAGE_SIZE,
		VM_PROT_READ | VM_PROT_WRITE,
		FALSE);															
		
	if(ret != KERN_SUCCESS) {								/* Couldn't wire it, spit on 'em... */
		return KERN_FAILURE;	
	}
		
	physdescpage = 											/* Get the physical page number of the page */
		pmap_find_phys(th->map->pmap, CAST_USER_ADDR_T(Desc_TableStart));

	ret =  kmem_alloc_pageable(kernel_map, &kerndescaddr, PAGE_SIZE);	/* Find a virtual address to use */
	if(ret != KERN_SUCCESS) {								/* Could we get an address? */
		(void) vm_map_unwire(th->map,				/* No, unwire the descriptor */
			(vm_offset_t)Desc_TableStart,
			(vm_offset_t)Desc_TableStart + PAGE_SIZE,
			TRUE);
		return KERN_FAILURE;								/* Split... */
	}
	
	(void) pmap_enter(kernel_pmap, 							/* Map this into the kernel */
		kerndescaddr, physdescpage, VM_PROT_READ|VM_PROT_WRITE, 
		VM_WIMG_USE_DEFAULT, TRUE);
	
	bttd = (BTTD_t *)kerndescaddr;							/* Get the address in a convienient spot */ 
	
	th->machine.bbDescAddr = (unsigned int)kerndescaddr+origdescoffset;	/* Set kernel address of the table */
	th->machine.bbUserDA = (unsigned int)Desc_TableStart;	/* Set user address of the table */
	th->machine.bbTableStart = (unsigned int)TWI_TableStart;	/* Set address of the trap table */
	th->machine.bbTaskID = (unsigned int)taskID;		/* Assign opaque task ID */
	th->machine.bbTaskEnv = 0;						/* Clean task environment data */
	th->machine.emPendRupts = 0;						/* Clean pending 'rupt count */
	th->machine.bbTrap = bttd->TrapVector;			/* Remember trap vector */
	th->machine.bbSysCall = bttd->SysCallVector;		/* Remember syscall vector */
	th->machine.bbInterrupt = bttd->InterruptVector;	/* Remember interrupt vector */
	th->machine.bbPending = bttd->PendingIntVector;	/* Remember pending vector */
	th->machine.specFlags &= ~(bbNoMachSC | bbPreemptive);	/* Make sure mach SCs are enabled and we are not marked preemptive */
	th->machine.specFlags |= bbThread;				/* Set that we are Classic thread */
		
	if(!(bttd->InterruptVector)) {							/* See if this is a preemptive (MP) BlueBox thread */
		th->machine.specFlags |= bbPreemptive;		/* Yes, remember it */
	}
		
	disable_preemption();									/* Don't move us around */
	getPerProc()->spcFlags = th->machine.specFlags;	/* Copy the flags */
	enable_preemption();									/* Ok to move us around */
		
	{
		/* mark the proc to indicate that this is a TBE proc */

		tbeproc(th->task->bsd_info);
	}

	return KERN_SUCCESS;
}

kern_return_t disable_bluebox( host_t host ) {				/* User call to terminate bluebox */
	
	thread_t 	act;
	
	act = current_thread();									/* Get our thread */					

	if (host == HOST_NULL) return KERN_INVALID_HOST;
	
	if(!is_suser()) return KERN_FAILURE;					/* We will only do this for the superuser */
	if(!act->machine.bbDescAddr) return KERN_FAILURE;			/* Bail if not authorized... */

	disable_bluebox_internal(act);							/* Clean it all up */
	return KERN_SUCCESS;									/* Leave */
}

void disable_bluebox_internal(thread_t act) {			/* Terminate bluebox */
		
	(void) vm_map_unwire(act->map,							/* Unwire the descriptor in user's address space */
		(vm_offset_t)act->machine.bbUserDA,
		(vm_offset_t)act->machine.bbUserDA + PAGE_SIZE,
		FALSE);
		
	kmem_free(kernel_map, (vm_offset_t)act->machine.bbDescAddr & -PAGE_SIZE, PAGE_SIZE);	/* Release the page */
	
	act->machine.bbDescAddr = 0;								/* Clear kernel pointer to it */
	act->machine.bbUserDA = 0;									/* Clear user pointer to it */
	act->machine.bbTableStart = 0;								/* Clear user pointer to TWI table */
	act->machine.bbTaskID = 0;									/* Clear opaque task ID */
	act->machine.bbTaskEnv = 0;								/* Clean task environment data */
	act->machine.emPendRupts = 0;								/* Clean pending 'rupt count */
	act->machine.specFlags &= ~(bbNoMachSC | bbPreemptive | bbThread);	/* Clean up Blue Box enables */
	disable_preemption();								/* Don't move us around */
	getPerProc()->spcFlags = act->machine.specFlags;		/* Copy the flags */
	enable_preemption();								/* Ok to move us around */
	return;
}

/*
 * Use the new PPCcall method to enable blue box threads
 *
 *	save->r3 = taskID
 *	save->r4 = TWI_TableStart
 *	save->r5 = Desc_TableStart
 *
 */
int bb_enable_bluebox( struct savearea *save )
{
	kern_return_t rc;

	rc = enable_bluebox((host_t)0xFFFFFFFF,
			    CAST_DOWN(unsigned, save->save_r3),
			    CAST_DOWN(unsigned, save->save_r4),
			    CAST_DOWN(unsigned, save->save_r5));
	save->save_r3 = rc;
	return 1;										/* Return with normal AST checking */
}

/*
 * Use the new PPCcall method to disable blue box threads
 *
 */
int bb_disable_bluebox( struct savearea *save )
{
	kern_return_t rc;

	rc = disable_bluebox( (host_t)0xFFFFFFFF );
	save->save_r3 = rc;
	return 1;										/* Return with normal AST checking */
}

/*
 * Search through the list of threads to find the matching taskIDs, then
 * set the task environment pointer.  A task in this case is a preemptive thread
 * in MacOS 9.
 *
 *	save->r3 = taskID
 *	save->r4 = taskEnv
 */

int bb_settaskenv( struct savearea *save )
{
	int				i;
    task_t			task;
	thread_t	act, fact;


	task = current_task();							/* Figure out who our task is */

	task_lock(task);								/* Lock our task */
	fact = (thread_t)task->threads.next;		/* Get the first activation on task */
	act = NULL;										/* Pretend we didn't find it yet */
	
	for(i = 0; i < task->thread_count; i++) {		/* Scan the whole list */
		if(fact->machine.bbDescAddr) {					/* Is this a Blue thread? */
			if ( fact->machine.bbTaskID == save->save_r3 ) {	/* Is this the task we are looking for? */
				act = fact;							/* Yeah... */
				break;								/* Found it, Bail the loop... */
			}
		}
		fact = (thread_t)fact->task_threads.next;	/* Go to the next one */
	}

	if ( !act || !act->active) {
		task_unlock(task);							/* Release task lock */
		save->save_r3 = -1;							/* we failed to find the taskID */
		return 1;
	}

	thread_reference(act);

	task_unlock(task);								/* Safe to release now */

	thread_mtx_lock(act);							/* Make sure this stays 'round */

	act->machine.bbTaskEnv = save->save_r4;
	if(act == current_thread()) {						/* Are we setting our own? */
		disable_preemption();						/* Don't move us around */
		getPerProc()->ppbbTaskEnv = act->machine.bbTaskEnv;	/* Remember the environment */
		enable_preemption();						/* Ok to move us around */
	}

	thread_mtx_unlock(act);							/* Unlock the activation */
	thread_deallocate(act);
	save->save_r3 = 0;
	return 1;
}

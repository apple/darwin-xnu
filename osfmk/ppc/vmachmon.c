/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*-----------------------------------------------------------------------
** vmachmon.c
**
** C routines that we are adding to the MacOS X kernel.
**
-----------------------------------------------------------------------*/

#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <mach/host_info.h>
#include <kern/kern_types.h>
#include <kern/host.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/thread_act.h>
#include <ppc/exception.h>
#include <ppc/mappings.h>
#include <ppc/thread_act.h>
#include <vm/vm_kern.h>

#include <ppc/vmachmon.h>

extern struct	Saveanchor saveanchor;			/* Aligned savearea anchor */
extern double FloatInit;
extern unsigned long QNaNbarbarian[4];

/*************************************************************************************
	Virtual Machine Monitor Internal Routines
**************************************************************************************/

/*-----------------------------------------------------------------------
** vmm_get_entry
**
** This function verifies and return a vmm context entry index
**
** Inputs:
**		act - pointer to current thread activation
**		index - index into vmm control table (this is a "one based" value)
**
** Outputs:
**		address of a vmmCntrlEntry or 0 if not found
-----------------------------------------------------------------------*/

vmmCntrlEntry *vmm_get_entry(
	thread_act_t		act,
	vmm_thread_index_t 	index)
{
	vmmCntrlTable *CTable;
	vmmCntrlEntry *CEntry;

	index = index & vmmTInum;								/* Clean up the index */

	if (act->mact.vmmControl == 0) return NULL;				/* No control table means no vmm */
	if ((index - 1) >= kVmmMaxContexts) return NULL;		/* Index not in range */	

	CTable = act->mact.vmmControl;							/* Make the address a bit more convienient */
	CEntry = &CTable->vmmc[index - 1];						/* Point to the entry */
	
	if (!(CEntry->vmmFlags & vmmInUse)) return NULL;		/* See if the slot is actually in use */
	
	return CEntry;
}

/*-----------------------------------------------------------------------
** vmm_get_adsp
**
** This function verifies and returns the pmap for an address space.
** If there is none and the request is valid, a pmap will be created.
**
** Inputs:
**		act - pointer to current thread activation
**		index - index into vmm control table (this is a "one based" value)
**
** Outputs:
**		address of a pmap or 0 if not found or could no be created
**		Note that if there is no pmap for the address space it will be created.
-----------------------------------------------------------------------*/

pmap_t vmm_get_adsp(thread_act_t act, vmm_thread_index_t index)
{
	pmap_t pmap;

	if (act->mact.vmmControl == 0) return NULL;				/* No control table means no vmm */
	if ((index - 1) >= kVmmMaxContexts) return NULL;		/* Index not in range */	

	pmap = act->mact.vmmControl->vmmAdsp[index - 1];		/* Get the pmap */
	if(pmap) return pmap;									/* We've got it... */

	pmap = pmap_create(0);									/* Make a fresh one */
	act->mact.vmmControl->vmmAdsp[index - 1] = pmap;		/* Remember it */
/*
 *	Note that if the create fails, we will return a null.
 */
	return pmap;											/* Return it... */
}



/*************************************************************************************
	Virtual Machine Monitor Exported Functionality
	
	The following routines are used to implement a quick-switch mechanism for
	virtual machines that need to execute within their own processor envinroment
	(including register and MMU state).
**************************************************************************************/

/*-----------------------------------------------------------------------
** vmm_get_version
**
** This function returns the current version of the virtual machine
** interface. It is divided into two portions. The top 16 bits
** represent the major version number, and the bottom 16 bits
** represent the minor version number. Clients using the Vmm
** functionality should make sure they are using a verison new
** enough for them.
**
** Inputs:
**		none
**
** Outputs:
**		32-bit number representing major/minor version of 
**				the Vmm module
-----------------------------------------------------------------------*/

int vmm_get_version(struct savearea *save)
{
	save->save_r3 = kVmmCurrentVersion;		/* Return the version */
	return 1;
}


/*-----------------------------------------------------------------------
** Vmm_get_features
**
** This function returns a set of flags that represents the functionality
** supported by the current verison of the Vmm interface. Clients should
** use this to determine whether they can run on this system.
**
** Inputs:
**		none
**
** Outputs:
**		32-bit number representing functionality supported by this
**				version of the Vmm module
-----------------------------------------------------------------------*/

int vmm_get_features(struct savearea *save)
{
	save->save_r3 = kVmmCurrentFeatures;		/* Return the features */
	if(per_proc_info->pf.Available & pf64Bit) {
		save->save_r3 &= ~kVmmFeature_LittleEndian;	/* No little endian here */
		save->save_r3 |= kVmmFeature_SixtyFourBit;	/* Set that we can do 64-bit */
	}
	return 1;
}


/*-----------------------------------------------------------------------
** vmm_max_addr
**
** This function returns the maximum addressable virtual address sported
**
** Outputs:
**		Returns max address
-----------------------------------------------------------------------*/

addr64_t vmm_max_addr(thread_act_t act) 
{
	return vm_max_address;							/* Return the maximum address */
}

/*-----------------------------------------------------------------------
** vmm_get_XA
**
** This function retrieves the eXtended Architecture flags for the specifed VM.
** 
** We need to return the result in the return code rather than in the return parameters
** because we need an architecture independent format so the results are actually 
** usable by the host. For example, the return parameters for 64-bit are 8 bytes wide vs.
** 4 for 32-bit. 
** 
**
** Inputs:
**		act - pointer to current thread activation structure
**		index - index returned by vmm_init_context
**
** Outputs:
**		Return code is set to the XA flags.  If the index is invalid or the
**		context has not been created, we return 0.
-----------------------------------------------------------------------*/

unsigned int vmm_get_XA(
	thread_act_t 		act,
	vmm_thread_index_t 	index)
{
	vmmCntrlEntry 		*CEntry;

	CEntry = vmm_get_entry(act, index);				/* Convert index to entry */		
	if (CEntry == NULL) return 0;					/* Either this isn't a vmm or the index is bogus */
	
	return CEntry->vmmXAFlgs;						/* Return the flags */
}

/*-----------------------------------------------------------------------
** vmm_init_context
**
** This function initializes an  emulation context. It allocates
** a new pmap (address space) and fills in the initial processor
** state within the specified structure. The structure, mapped
** into the client's logical address space, must be page-aligned.
**
** Inputs:
**		act - pointer to current thread activation
**		version - requested version of the Vmm interface (allowing
**			future versions of the interface to change, but still
**			support older clients)
**		vmm_user_state - pointer to a logical page within the
**			client's address space
**
** Outputs:
**		kernel return code indicating success or failure
-----------------------------------------------------------------------*/

int vmm_init_context(struct savearea *save)
{

	thread_act_t		act;
	vmm_version_t 		version;
	vmm_state_page_t *	vmm_user_state;
	vmmCntrlTable		*CTable;
	vm_offset_t			conkern;
	vmm_state_page_t *	vks;
	ppnum_t				conphys;
	kern_return_t 		ret;
	pmap_t				new_pmap;	
	int					cvi, i;
    task_t				task;
    thread_act_t		fact, gact;

	vmm_user_state = CAST_DOWN(vmm_state_page_t *, save->save_r4);  /* Get the user address of the comm area */
	if ((unsigned int)vmm_user_state & (PAGE_SIZE - 1)) {	/* Make sure the comm area is page aligned */
		save->save_r3 = KERN_FAILURE;			/* Return failure */
		return 1;
	}

	/* Make sure that the version requested is supported */
	version = save->save_r3;					/* Pick up passed in version */
	if (((version >> 16) < kVmmMinMajorVersion) || ((version >> 16) > (kVmmCurrentVersion >> 16))) {
		save->save_r3 = KERN_FAILURE;			/* Return failure */
		return 1;
	}

	if((version & 0xFFFF) > kVmmCurMinorVersion) {	/* Check for valid minor */
		save->save_r3 = KERN_FAILURE;			/* Return failure */
		return 1;
	}

	act = current_act();						/* Pick up our activation */
	
	ml_set_interrupts_enabled(TRUE);			/* This can take a bit of time so pass interruptions */
	
	task = current_task();						/* Figure out who we are */

	task_lock(task);							/* Lock our task */

	fact = (thread_act_t)task->threads.next;	/* Get the first activation on task */
	gact = 0;									/* Pretend we didn't find it yet */

	for(i = 0; i < task->thread_count; i++) {	/* All of the activations */
		if(fact->mact.vmmControl) {				/* Is this a virtual machine monitor? */
			gact = fact;						/* Yeah... */
			break;								/* Bail the loop... */
		}
		fact = (thread_act_t)fact->task_threads.next;	/* Go to the next one */
	}
	

/*
 *	We only allow one thread per task to be a virtual machine monitor right now.  This solves
 *	a number of potential problems that I can't put my finger on right now.
 *
 *	Utlimately, I think we want to move the controls and make all this task based instead of
 *	thread based.  That would allow an emulator architecture to spawn a kernel thread for each
 *	VM (if they want) rather than hand dispatch contexts.
 */

	if(gact && (gact != act)) {					/* Check if another thread is a vmm or trying to be */
		task_unlock(task);						/* Release task lock */
		ml_set_interrupts_enabled(FALSE);		/* Set back interruptions */
		save->save_r3 = KERN_FAILURE;			/* We must play alone... */
		return 1;
	}
	
	if(!gact) act->mact.vmmControl = (vmmCntrlTable *)1;	/* Temporarily mark that we are the vmm thread */

	task_unlock(task);							/* Safe to release now (because we've marked ourselves) */

	CTable = act->mact.vmmControl;				/* Get the control table address */
	if ((unsigned int)CTable == 1) {			/* If we are marked, try to allocate a new table, otherwise we have one */
		if(!(CTable = (vmmCntrlTable *)kalloc(sizeof(vmmCntrlTable)))) {	/* Get a fresh emulation control table */
			act->mact.vmmControl = 0;			/* Unmark us as vmm 'cause we failed */
			ml_set_interrupts_enabled(FALSE);	/* Set back interruptions */
			save->save_r3 = KERN_RESOURCE_SHORTAGE;		/* No storage... */
			return 1;
		}
		
		bzero((void *)CTable, sizeof(vmmCntrlTable));	/* Clean it up */
		act->mact.vmmControl = CTable;			/* Initialize the table anchor */
	}

	for(cvi = 0; cvi < kVmmMaxContexts; cvi++) {	/* Search to find a free slot */
		if(!(CTable->vmmc[cvi].vmmFlags & vmmInUse)) break;	/* Bail if we find an unused slot */
	}
	
	if(cvi >= kVmmMaxContexts) {				/* Did we find one? */
		ml_set_interrupts_enabled(FALSE);		/* Set back interruptions */
		save->save_r3 = KERN_RESOURCE_SHORTAGE;	/* No empty slots... */	
		return 1;
	}

	ret = vm_map_wire(							/* Wire the virtual machine monitor's context area */
		act->map,
		(vm_offset_t)vmm_user_state,
		(vm_offset_t)vmm_user_state + PAGE_SIZE,
		VM_PROT_READ | VM_PROT_WRITE,
		FALSE);															
		
	if (ret != KERN_SUCCESS) 					/* The wire failed, return the code */
		goto return_in_shame;

	/* Map the vmm state into the kernel's address space. */
	conphys = pmap_find_phys(act->map->pmap, (addr64_t)((uintptr_t)vmm_user_state));

	/* Find a virtual address to use. */
	ret = kmem_alloc_pageable(kernel_map, &conkern, PAGE_SIZE);
	if (ret != KERN_SUCCESS) {					/* Did we find an address? */
		(void) vm_map_unwire(act->map,			/* No, unwire the context area */
			(vm_offset_t)vmm_user_state,
			(vm_offset_t)vmm_user_state + PAGE_SIZE,
			TRUE);
		goto return_in_shame;
	}
	
	/* Map it into the kernel's address space. */

	pmap_enter(kernel_pmap, conkern, conphys, 
		VM_PROT_READ | VM_PROT_WRITE, 
		VM_WIMG_USE_DEFAULT, TRUE);
	
	/* Clear the vmm state structure. */
	vks = (vmm_state_page_t *)conkern;
	bzero((char *)vks, PAGE_SIZE);
	
	
	/* We're home free now. Simply fill in the necessary info and return. */
	
	vks->interface_version = version;			/* Set our version code */
	vks->thread_index = cvi + 1;				/* Tell the user the index for this virtual machine */
	
	CTable->vmmc[cvi].vmmFlags = vmmInUse;		/* Mark the slot in use and make sure the rest are clear */
	CTable->vmmc[cvi].vmmContextKern = vks;		/* Remember the kernel address of comm area */
	CTable->vmmc[cvi].vmmContextPhys = (vmm_state_page_t *)conphys;	/* Remember the state page physical addr */
	CTable->vmmc[cvi].vmmContextUser = vmm_user_state;		/* Remember user address of comm area */
	
	CTable->vmmc[cvi].vmmFacCtx.FPUsave = 0;	/* Clear facility context control */
	CTable->vmmc[cvi].vmmFacCtx.FPUlevel = 0;	/* Clear facility context control */
	CTable->vmmc[cvi].vmmFacCtx.FPUcpu = 0;		/* Clear facility context control */
	CTable->vmmc[cvi].vmmFacCtx.VMXsave = 0;	/* Clear facility context control */
	CTable->vmmc[cvi].vmmFacCtx.VMXlevel = 0;	/* Clear facility context control */
	CTable->vmmc[cvi].vmmFacCtx.VMXcpu = 0;		/* Clear facility context control */
	CTable->vmmc[cvi].vmmFacCtx.facAct = act;	/* Point back to the activation */

	hw_atomic_add((int *)&saveanchor.savetarget, 2);	/* Account for the number of extra saveareas we think we might "need" */

	if (!(act->map->pmap->pmapFlags & pmapVMhost)) {
		simple_lock(&(act->map->pmap->lock));
		act->map->pmap->pmapFlags |= pmapVMhost;
		simple_unlock(&(act->map->pmap->lock));
	}
	
	ml_set_interrupts_enabled(FALSE);			/* Set back interruptions */
	save->save_r3 = KERN_SUCCESS;				/* Hip, hip, horay... */	
	return 1;

return_in_shame:
	if(!gact) kfree((vm_offset_t)CTable, sizeof(vmmCntrlTable));	/* Toss the table if we just allocated it */
	act->mact.vmmControl = 0;					/* Unmark us as vmm 'cause we failed */
	ml_set_interrupts_enabled(FALSE);			/* Set back interruptions */
	save->save_r3 = ret;						/* Pass back return code... */	
	return 1;

}


/*-----------------------------------------------------------------------
** vmm_tear_down_context
**
** This function uninitializes an emulation context. It deallocates
** internal resources associated with the context block.
**
** Inputs:
**		act - pointer to current thread activation structure
**		index - index returned by vmm_init_context
**
** Outputs:
**		kernel return code indicating success or failure
**
** Strangeness note:
**		This call will also trash the address space with the same ID.  While this 
**		is really not too cool, we have to do it because we need to make
**		sure that old VMM users (not that we really have any) who depend upon 
**		the address space going away with the context still work the same.
-----------------------------------------------------------------------*/

kern_return_t vmm_tear_down_context(
	thread_act_t 		act,
	vmm_thread_index_t 	index)
{
	vmmCntrlEntry 		*CEntry;
	vmmCntrlTable		*CTable;
	int					cvi;
	register savearea 	*sv;

	CEntry = vmm_get_entry(act, index);				/* Convert index to entry */		
	if (CEntry == NULL) return KERN_FAILURE;		/* Either this isn't vmm thread or the index is bogus */

	ml_set_interrupts_enabled(TRUE);				/* This can take a bit of time so pass interruptions */

	hw_atomic_sub((int *)&saveanchor.savetarget, 2);	/* We don't need these extra saveareas anymore */

	if(CEntry->vmmFacCtx.FPUsave) {					/* Is there any floating point context? */
		toss_live_fpu(&CEntry->vmmFacCtx);			/* Get rid of any live context here */
		save_release((savearea *)CEntry->vmmFacCtx.FPUsave);	/* Release it */
	}

	if(CEntry->vmmFacCtx.VMXsave) {					/* Is there any vector context? */
		toss_live_vec(&CEntry->vmmFacCtx);			/* Get rid of any live context here */
		save_release((savearea *)CEntry->vmmFacCtx.VMXsave);	/* Release it */
	}
	
	CEntry->vmmPmap = 0;							/* Remove this trace */
	if(act->mact.vmmControl->vmmAdsp[index - 1]) {	/* Check if there is an address space assigned here */
		mapping_remove(act->mact.vmmControl->vmmAdsp[index - 1], 0xFFFFFFFFFFFFF000LL);	/* Remove final page explicitly because we might have mapped it */	
		pmap_remove(act->mact.vmmControl->vmmAdsp[index - 1], 0, 0xFFFFFFFFFFFFF000LL);	/* Remove all entries from this map */
		pmap_destroy(act->mact.vmmControl->vmmAdsp[index - 1]);	/* Toss the pmap for this context */
		act->mact.vmmControl->vmmAdsp[index - 1] = NULL;	/* Clean it up */
	}
	
	(void) vm_map_unwire(							/* Unwire the user comm page */
		act->map,
		(vm_offset_t)CEntry->vmmContextUser,
		(vm_offset_t)CEntry->vmmContextUser + PAGE_SIZE,
		FALSE);
	
	kmem_free(kernel_map, (vm_offset_t)CEntry->vmmContextKern, PAGE_SIZE);	/* Remove kernel's view of the comm page */
	
	CTable = act->mact.vmmControl;					/* Get the control table address */
	CTable->vmmGFlags = CTable->vmmGFlags & ~vmmLastAdSp;	/* Make sure we don't try to automap into this */

	CEntry->vmmFlags = 0;							/* Clear out all of the flags for this entry including in use */
	CEntry->vmmContextKern = 0;						/* Clear the kernel address of comm area */
	CEntry->vmmContextUser = 0;						/* Clear the user address of comm area */
	
	CEntry->vmmFacCtx.FPUsave = 0;					/* Clear facility context control */
	CEntry->vmmFacCtx.FPUlevel = 0;					/* Clear facility context control */
	CEntry->vmmFacCtx.FPUcpu = 0;					/* Clear facility context control */
	CEntry->vmmFacCtx.VMXsave = 0;					/* Clear facility context control */
	CEntry->vmmFacCtx.VMXlevel = 0;					/* Clear facility context control */
	CEntry->vmmFacCtx.VMXcpu = 0;					/* Clear facility context control */
	CEntry->vmmFacCtx.facAct = 0;					/* Clear facility context control */
	
	for(cvi = 0; cvi < kVmmMaxContexts; cvi++) {	/* Search to find a free slot */
		if(CTable->vmmc[cvi].vmmFlags & vmmInUse) {	/* Return if there are still some in use */
			ml_set_interrupts_enabled(FALSE);		/* No more interruptions */
			return KERN_SUCCESS;					/* Leave... */
		}
	}

/*
 *	When we have tossed the last context, toss any address spaces left over before releasing
 *	the VMM control block 
 */

	for(cvi = 1; cvi <= kVmmMaxContexts; cvi++) {	/* Look at all slots */
		if(!act->mact.vmmControl->vmmAdsp[index - 1]) continue;	/* Nothing to remove here */
		mapping_remove(act->mact.vmmControl->vmmAdsp[index - 1], 0xFFFFFFFFFFFFF000LL);	/* Remove final page explicitly because we might have mapped it */	
		pmap_remove(act->mact.vmmControl->vmmAdsp[index - 1], 0, 0xFFFFFFFFFFFFF000LL);	/* Remove all entries from this map */
		pmap_destroy(act->mact.vmmControl->vmmAdsp[index - 1]);	/* Toss the pmap for this context */
		act->mact.vmmControl->vmmAdsp[index - 1] = 0;	/* Clear just in case */
	}		

	kfree((vm_offset_t)CTable, sizeof(vmmCntrlTable));	/* Toss the table because to tossed the last context */
	act->mact.vmmControl = 0;						/* Unmark us as vmm */

	ml_set_interrupts_enabled(FALSE);				/* No more interruptions */
	
	return KERN_SUCCESS;
}


/*-----------------------------------------------------------------------
** vmm_set_XA
**
** This function sets the eXtended Architecture flags for the specifed VM.
** 
** We need to return the result in the return code rather than in the return parameters
** because we need an architecture independent format so the results are actually 
** usable by the host. For example, the return parameters for 64-bit are 8 bytes wide vs.
** 4 for 32-bit. 
** 
** Note that this function does a lot of the same stuff as vmm_tear_down_context
** and vmm_init_context.
**
** Inputs:
**		act - pointer to current thread activation structure
**		index - index returned by vmm_init_context
**		flags - the extended architecture flags
**		
**
** Outputs:
**		KERN_SUCCESS if vm is valid and initialized. KERN_FAILURE if not.
**		Also, the internal flags are set and, additionally, the VM is completely reset.
-----------------------------------------------------------------------*/

kern_return_t vmm_set_XA(
	thread_act_t 		act,
	vmm_thread_index_t 	index,
	unsigned int xaflags)
{
	vmmCntrlEntry 		*CEntry;
	vmmCntrlTable		*CTable;
	vmm_state_page_t 	*vks;
	vmm_version_t 		version;

	if(xaflags & ~vmm64Bit) return KERN_FAILURE;	/* We only support this one kind now */

	CEntry = vmm_get_entry(act, index);				/* Convert index to entry */		
	if (CEntry == NULL) return KERN_FAILURE;		/* Either this isn't a vmm or the index is bogus */

	ml_set_interrupts_enabled(TRUE);				/* This can take a bit of time so pass interruptions */
	
	if(CEntry->vmmFacCtx.FPUsave) {					/* Is there any floating point context? */
		toss_live_fpu(&CEntry->vmmFacCtx);			/* Get rid of any live context here */
		save_release((savearea *)CEntry->vmmFacCtx.FPUsave);	/* Release it */
	}

	if(CEntry->vmmFacCtx.VMXsave) {					/* Is there any vector context? */
		toss_live_vec(&CEntry->vmmFacCtx);			/* Get rid of any live context here */
		save_release((savearea *)CEntry->vmmFacCtx.VMXsave);	/* Release it */
	}

	CTable = act->mact.vmmControl;					/* Get the control table address */
	CTable->vmmGFlags = CTable->vmmGFlags & ~vmmLastAdSp;	/* Make sure we don't try to automap into this */
	
	CEntry->vmmFlags &= vmmInUse;					/* Clear out all of the flags for this entry except in use */
	CEntry->vmmXAFlgs = (xaflags & vmm64Bit) | (CEntry->vmmXAFlgs & ~vmm64Bit);	/* Set the XA flags */
	CEntry->vmmFacCtx.FPUsave = 0;					/* Clear facility context control */
	CEntry->vmmFacCtx.FPUlevel = 0;					/* Clear facility context control */
	CEntry->vmmFacCtx.FPUcpu = 0;					/* Clear facility context control */
	CEntry->vmmFacCtx.VMXsave = 0;					/* Clear facility context control */
	CEntry->vmmFacCtx.VMXlevel = 0;					/* Clear facility context control */
	CEntry->vmmFacCtx.VMXcpu = 0;					/* Clear facility context control */
	
	vks = CEntry->vmmContextKern;					/* Get address of the context page */
	version = vks->interface_version;				/* Save the version code */
	bzero((char *)vks, 4096);						/* Clear all */

	vks->interface_version = version;				/* Set our version code */
	vks->thread_index = index % vmmTInum;			/* Tell the user the index for this virtual machine */
	
	ml_set_interrupts_enabled(FALSE);				/* No more interruptions */
	
	return KERN_SUCCESS;							/* Return the flags */
}


/*-----------------------------------------------------------------------
** vmm_tear_down_all
**
** This function uninitializes all emulation contexts. If there are
** any vmm contexts, it calls vmm_tear_down_context for each one.
**
** Note: this can also be called from normal thread termination.  Because of
** that, we will context switch out of an alternate if we are currenty in it.
** It will be terminated with no valid return code set because we don't expect 
** the activation to ever run again.
**
** Inputs:
**		activation to tear down
**
** Outputs:
**		All vmm contexts released and VMM shut down
-----------------------------------------------------------------------*/
void vmm_tear_down_all(thread_act_t act) {

	vmmCntrlTable		*CTable;
	int					cvi;
	kern_return_t		ret;
	savearea			*save;
	spl_t				s;
	
	if(act->mact.specFlags & runningVM) {			/* Are we actually in a context right now? */
		save = find_user_regs(act);					/* Find the user state context */
		if(!save) {									/* Did we find it? */
			panic("vmm_tear_down_all: runningVM marked but no user state context\n");
			return;
		}
		
		save->save_exception = kVmmBogusContext*4;	/* Indicate that this context is bogus now */
		s = splhigh();								/* Make sure interrupts are off */
		vmm_force_exit(act, save);					/* Force and exit from VM state */
		splx(s);									/* Restore interrupts */
	}
	
	if(CTable = act->mact.vmmControl) {				/* Do we have a vmm control block? */


		for(cvi = 1; cvi <= kVmmMaxContexts; cvi++) {	/* Look at all slots */
			if(CTable->vmmc[cvi - 1].vmmFlags & vmmInUse) {	/* Is this one in use */
				ret = vmm_tear_down_context(act, cvi);	/* Take down the found context */
				if(ret != KERN_SUCCESS) {			/* Did it go away? */
					panic("vmm_tear_down_all: vmm_tear_down_context failed; ret=%08X, act = %08X, cvi = %d\n",
					  ret, act, cvi);
				}
			}
		}		

/*
 *		Note that all address apces should be gone here.
 */
		if(act->mact.vmmControl) {						/* Did we find one? */
			panic("vmm_tear_down_all: control table did not get deallocated\n");	/* Table did not go away */
		}
	}

	return;
}

/*-----------------------------------------------------------------------
** vmm_map_page
**
** This function maps a page from within the client's logical
** address space into the alternate address space.
**
** The page need not be locked or resident.  If not resident, it will be faulted
** in by this code, which may take some time.   Also, if the page is not locked,
** it, and this mapping may disappear at any time, even before it gets used.  Note also
** that reference and change information is NOT preserved when a page is unmapped, either
** explicitly or implicitly (e.g., a pageout, being unmapped in the non-alternate address
** space).  This means that if RC is needed, the page MUST be wired.
**
** Note that if there is already a mapping at the address, it is removed and all 
** information (including RC) is lost BEFORE an attempt is made to map it. Also,
** if the map call fails, the old address is still unmapped..
**
** Inputs:
**		act   - pointer to current thread activation
**		index - index of address space to map into
**		va    - virtual address within the client's address
**			    space
**		ava   - virtual address within the alternate address
**			    space
**		prot - protection flags
**
**	Note that attempted mapping of areas in nested pmaps (shared libraries) or block mapped
**  areas are not allowed and will fail. Same with directly mapped I/O areas.
**
** Input conditions:
**      Interrupts disabled (from fast trap)
**
** Outputs:
**		kernel return code indicating success or failure
**      if success, va resident and alternate mapping made
-----------------------------------------------------------------------*/

kern_return_t vmm_map_page(
	thread_act_t 		act,
	vmm_adsp_id_t	 	index,
	addr64_t	 		cva,
	addr64_t	 		ava,
	vm_prot_t 			prot)
{
	kern_return_t		ret;
	vmmCntrlEntry 		*CEntry;
	register mapping 	*mp;
	struct phys_entry 	*pp;
	vm_map_t 			map;
	addr64_t			ova, nextva;
	pmap_t				pmap;

	pmap = vmm_get_adsp(act, index);			/* Get the pmap for this address space */
	if(!pmap) return KERN_FAILURE;				/* Bogus address space, no VMs, or we can't make a pmap, failure... */

	if(ava > vm_max_address) return kVmmInvalidAddress;	/* Does the machine support an address of this size? */

	map = current_act()->map;					/* Get the current map */
	
	while(1) {									/* Keep trying until we get it or until we fail */

		mp = mapping_find(map->pmap, cva, &nextva, 0);	/* Find the mapping for this address */
		
		if(mp) break;							/* We found it */

		ml_set_interrupts_enabled(TRUE);		/* Enable interruptions */
		ret = vm_fault(map, trunc_page_32((vm_offset_t)cva), VM_PROT_READ | VM_PROT_WRITE, FALSE);	/* Didn't find it, try to fault it in read/write... */
		ml_set_interrupts_enabled(FALSE);		/* Disable interruptions */
		if (ret != KERN_SUCCESS) return KERN_FAILURE;	/* There isn't a page there, return... */
	}

	if(mp->mpFlags & (mpBlock | mpNest | mpSpecial)) {	/* If this is a block, a nest, or some other special thing, we can't map it */
		mapping_drop_busy(mp);					/* We have everything we need from the mapping */
		return KERN_FAILURE;					/* Leave in shame */
	}
	
	while(1) {										/* Keep trying the enter until it goes in */
		ova = mapping_make(pmap, ava, mp->mpPAddr, 0, 1, prot);	/* Enter the mapping into the pmap */
		if(!ova) break;							/* If there were no collisions, we are done... */
		mapping_remove(pmap, ova);				/* Remove the mapping that collided */
	}

	mapping_drop_busy(mp);						/* We have everything we need from the mapping */

	if (!((per_proc_info[cpu_number()].spcFlags) & FamVMmode)) {
		act->mact.vmmControl->vmmLastMap = ava & 0xFFFFFFFFFFFFF000ULL;	/* Remember the last mapping we made */
		act->mact.vmmControl->vmmGFlags = (act->mact.vmmControl->vmmGFlags & ~vmmLastAdSp) | index;	/* Remember last address space */
	}

	return KERN_SUCCESS;
}


/*-----------------------------------------------------------------------
** vmm_map_execute
**
** This function maps a page from within the client's logical
** address space into the alternate address space of the
** Virtual Machine Monitor context and then directly starts executing.
**
**	See description of vmm_map_page for details. 
**
** Inputs:
**		Index is used for both the context and the address space ID.
**		index[24:31] is the context id and index[16:23] is the address space.
**		if the address space ID is 0, the context ID is used for it.
**
** Outputs:
**		Normal exit is to run the VM.  Abnormal exit is triggered via a 
**		non-KERN_SUCCESS return from vmm_map_page or later during the 
**		attempt to transition into the VM. 
-----------------------------------------------------------------------*/

vmm_return_code_t vmm_map_execute(
	thread_act_t 		act,
	vmm_thread_index_t 	index,
	addr64_t	 		cva,
	addr64_t	 		ava,
	vm_prot_t 			prot)
{
	kern_return_t		ret;
	vmmCntrlEntry 		*CEntry;
	unsigned int		adsp;
	vmm_thread_index_t	cndx;

	cndx = index & 0xFF;							/* Clean it up */

	CEntry = vmm_get_entry(act, cndx);				/* Get and validate the index */
	if (CEntry == NULL) return kVmmBogusContext;	/* Return bogus context */
	
	if (((per_proc_info[cpu_number()].spcFlags) & FamVMmode) && (CEntry != act->mact.vmmCEntry))
		return kVmmBogusContext;			/* Yes, invalid index in Fam */
	
	adsp = (index >> 8) & 0xFF;						/* Get any requested address space */
	if(!adsp) adsp = (index & 0xFF);				/* If 0, use context ID as address space ID */
	
	ret = vmm_map_page(act, adsp, cva, ava, prot);	/* Go try to map the page on in */
	
	
	if(ret == KERN_SUCCESS) {
		act->mact.vmmControl->vmmLastMap = ava & 0xFFFFFFFFFFFFF000ULL;	/* Remember the last mapping we made */
		act->mact.vmmControl->vmmGFlags = (act->mact.vmmControl->vmmGFlags & ~vmmLastAdSp) | cndx;	/* Remember last address space */
		vmm_execute_vm(act, cndx);				/* Return was ok, launch the VM */
	}
	
	return ret;										/* We had trouble mapping in the page */	
	
}

/*-----------------------------------------------------------------------
** vmm_map_list
**
** This function maps a list of pages into various address spaces
**
** Inputs:
**		act   - pointer to current thread activation
**		index - index of default address space (used if not specifed in list entry
**		count - number of pages to release
**		flavor - 0 if 32-bit version, 1 if 64-bit
**		vmcpComm in the comm page contains up to kVmmMaxMapPages to map
**
** Outputs:
**		kernel return code indicating success or failure
**		KERN_FAILURE is returned if kVmmMaxUnmapPages is exceeded
**		or the vmm_map_page call fails.
**		We return kVmmInvalidAddress if virtual address size is not supported
-----------------------------------------------------------------------*/

kern_return_t vmm_map_list(
	thread_act_t 		act,
	vmm_adsp_id_t 		index,
	unsigned int		cnt,
	unsigned int		flavor)
{
	vmmCntrlEntry 		*CEntry;
	boolean_t			ret;
	unsigned int 		i;
	vmmMList			*lst;
	vmmMList64			*lstx;
	addr64_t	 		cva;
	addr64_t	 		ava;
	vm_prot_t 			prot;
	vmm_adsp_id_t 		adsp;

	CEntry = vmm_get_entry(act, index);				/* Convert index to entry */		
	if (CEntry == NULL) return KERN_FAILURE;		/* Either this isn't a vmm or the index is bogus */
	
	if(cnt > kVmmMaxMapPages) return KERN_FAILURE;	/* They tried to map too many */
	if(!cnt) return KERN_SUCCESS;					/* If they said none, we're done... */
	
	lst = (vmmMList *)&((vmm_comm_page_t *)CEntry->vmmContextKern)->vmcpComm[0];	/* Point to the first entry */
	lstx = (vmmMList64 *)&((vmm_comm_page_t *)CEntry->vmmContextKern)->vmcpComm[0];	/* Point to the first entry */
	
	for(i = 0; i < cnt; i++) {						/* Step and release all pages in list */
		if(flavor) {								/* Check if 32- or 64-bit addresses */
			cva = lstx[i].vmlva;					/* Get the 64-bit actual address */	
			ava = lstx[i].vmlava;					/* Get the 64-bit guest address */	
		}
		else {
			cva = lst[i].vmlva;						/* Get the 32-bit actual address */	
			ava = lst[i].vmlava;					/* Get the 32-bit guest address */	
		}

		prot = ava & vmmlProt;						/* Extract the protection bits */	
		adsp = (ava & vmmlAdID) >> 4;				/* Extract an explicit address space request */	
		if(!adsp) adsp = index - 1;					/* If no explicit, use supplied default */
		ava = ava &= 0xFFFFFFFFFFFFF000ULL;			/* Clean up the address */
		
		ret = vmm_map_page(act, index, cva, ava, prot);	/* Go try to map the page on in */
		if(ret != KERN_SUCCESS) return ret;			/* Bail if any error */
	}
	
	return KERN_SUCCESS	;							/* Return... */
}

/*-----------------------------------------------------------------------
** vmm_get_page_mapping
**
** This function determines whether the specified VMM
** virtual address is mapped.
**
** Inputs:
**		act   - pointer to current thread activation
**		index - index of vmm state for this page
**		va    - virtual address within the alternate's address
**			    space
**
** Outputs:
**		Non-alternate's virtual address (page aligned) or -1 if not mapped or any failure
**
** Note:
**      If there are aliases to the page in the non-alternate address space,
**	    this call could return the wrong one.  Moral of the story: no aliases.
-----------------------------------------------------------------------*/

addr64_t vmm_get_page_mapping(
	thread_act_t 		act,
	vmm_adsp_id_t	 	index,
	addr64_t	 		va)
{
	vmmCntrlEntry 		*CEntry;
	register mapping 	*mp;
	pmap_t				pmap;
	addr64_t			nextva, sva;
	ppnum_t				pa;

	pmap = vmm_get_adsp(act, index);						/* Get and validate the index */
	if (!pmap)return -1;									/* No good, failure... */

	mp = mapping_find(pmap, va, &nextva, 0);				/* Find our page */
	
	if(!mp) return -1;										/* Not mapped, return -1 */

	pa = mp->mpPAddr;										/* Remember the page address */

	mapping_drop_busy(mp);									/* Go ahead and relase the mapping now */
	
	pmap = current_act()->map->pmap;						/* Get the current pmap */
	sva = mapping_p2v(pmap, pa);							/* Now find the source virtual */

	if(sva != 0) return sva;								/* We found it... */
	
	panic("vmm_get_page_mapping: could not back-map alternate va (%016llX)\n", va);	/* We are bad wrong if we can't find it */

	return -1;
}

/*-----------------------------------------------------------------------
** vmm_unmap_page
**
** This function unmaps a page from the alternate's logical
** address space.
**
** Inputs:
**		act   - pointer to current thread activation
**		index - index of vmm state for this page
**		va    - virtual address within the vmm's address
**			    space
**
** Outputs:
**		kernel return code indicating success or failure
-----------------------------------------------------------------------*/

kern_return_t vmm_unmap_page(
	thread_act_t 		act,
	vmm_adsp_id_t	 	index,
	addr64_t	 		va)
{
	vmmCntrlEntry 		*CEntry;
	addr64_t			nadd;
	pmap_t				pmap;
	kern_return_t		kern_result = KERN_SUCCESS;

	pmap = vmm_get_adsp(act, index);						/* Get and validate the index */
	if (!pmap)return -1;									/* No good, failure... */
	
	nadd = mapping_remove(pmap, va);						/* Toss the mapping */
	
	return ((nadd & 1) ? KERN_FAILURE : KERN_SUCCESS);		/* Return... */
}

/*-----------------------------------------------------------------------
** vmm_unmap_list
**
** This function unmaps a list of pages from the alternate's logical
** address space.
**
** Inputs:
**		act   - pointer to current thread activation
**		index - index of vmm state for this page
**		count - number of pages to release
**		flavor - 0 if 32-bit, 1 if 64-bit
**		vmcpComm in the comm page contains up to kVmmMaxUnmapPages to unmap
**
** Outputs:
**		kernel return code indicating success or failure
**		KERN_FAILURE is returned if kVmmMaxUnmapPages is exceeded
-----------------------------------------------------------------------*/

kern_return_t vmm_unmap_list(
	thread_act_t 		act,
	vmm_adsp_id_t	 	index,
	unsigned int 		cnt,
	unsigned int		flavor)
{
	vmmCntrlEntry 		*CEntry;
	boolean_t			ret;
	kern_return_t		kern_result = KERN_SUCCESS;
	unsigned int		*pgaddr, i;
	addr64_t			gva;
	vmmUMList			*lst;
	vmmUMList64			*lstx;
	pmap_t				pmap;
	int					adsp;

	CEntry = vmm_get_entry(act, index);				/* Convert index to entry */		
	if (CEntry == NULL) return KERN_FAILURE;		/* Either this isn't a vmm or the index is bogus */
	
	if(cnt > kVmmMaxUnmapPages) return KERN_FAILURE;	/* They tried to unmap too many */
	if(!cnt) return KERN_SUCCESS;					/* If they said none, we're done... */
	
	lst = (vmmUMList *)lstx = (vmmUMList64 *) &((vmm_comm_page_t *)CEntry->vmmContextKern)->vmcpComm[0];	/* Point to the first entry */
	
	for(i = 0; i < cnt; i++) {						/* Step and release all pages in list */
		if(flavor) {								/* Check if 32- or 64-bit addresses */
			gva = lstx[i].vmlava;					/* Get the 64-bit guest address */	
		}
		else {
			gva = lst[i].vmlava;					/* Get the 32-bit guest address */	
		}

		adsp = (gva & vmmlAdID) >> 4;				/* Extract an explicit address space request */	
		if(!adsp) adsp = index - 1;					/* If no explicit, use supplied default */
		pmap = act->mact.vmmControl->vmmAdsp[adsp];	/* Get the pmap for this request */
		if(!pmap) continue;							/* Ain't nuthin' mapped here, no durn map... */

		gva = gva &= 0xFFFFFFFFFFFFF000ULL;			/* Clean up the address */		
		(void)mapping_remove(pmap, gva);			/* Toss the mapping */
	}
	
	return KERN_SUCCESS	;							/* Return... */
}

/*-----------------------------------------------------------------------
** vmm_unmap_all_pages
**
** This function unmaps all pages from the alternates's logical
** address space.
**
** Inputs:
**		act   - pointer to current thread activation
**		index - index of context state
**
** Outputs:
**		none
**
** Note:
**      All pages are unmapped, but the address space (i.e., pmap) is still alive
-----------------------------------------------------------------------*/

void vmm_unmap_all_pages(
	thread_act_t 		act,
	vmm_adsp_id_t	 	index)
{
	vmmCntrlEntry 		*CEntry;
	pmap_t				pmap;

	pmap = vmm_get_adsp(act, index);						/* Convert index to entry */		
	if (!pmap) return;										/* Either this isn't vmm thread or the index is bogus */
	
/*
 *	Note: the pmap code won't deal with the last page in the address space, so handle it explicitly
 */
	mapping_remove(pmap, 0xFFFFFFFFFFFFF000LL);				/* Remove final page explicitly because we might have mapped it */	
	pmap_remove(pmap, 0, 0xFFFFFFFFFFFFF000LL);				/* Remove all entries from this map */
	return;
}


/*-----------------------------------------------------------------------
** vmm_get_page_dirty_flag
**
** This function returns the changed flag of the page
** and optionally clears clears the flag.
**
** Inputs:
**		act   - pointer to current thread activation
**		index - index of vmm state for this page
**		va    - virtual address within the vmm's address
**			    space
**		reset - Clears dirty if true, untouched if not
**
** Outputs:
**		the dirty bit
**		clears the dirty bit in the pte if requested
**
**	Note:
**		The RC bits are merged into the global physical entry
-----------------------------------------------------------------------*/

boolean_t vmm_get_page_dirty_flag(
	thread_act_t 				act,
	vmm_adsp_id_t	 	index,
	addr64_t	 		va,
	unsigned int		reset)
{
	vmmCntrlEntry 		*CEntry;
	register mapping 	*mpv, *mp;
	unsigned int		RC;
	pmap_t				pmap;

	pmap = vmm_get_adsp(act, index);						/* Convert index to entry */		
	if (!pmap) return 1;									/* Either this isn't vmm thread or the index is bogus */
	
	RC = hw_test_rc(pmap, (addr64_t)va, reset);				/* Fetch the RC bits and clear if requested */	

	switch (RC & mapRetCode) {								/* Decode return code */
	
		case mapRtOK:										/* Changed */
			return ((RC & (unsigned int)mpC) == (unsigned int)mpC);	/* Return if dirty or not */
			break;
	
		case mapRtNotFnd:									/* Didn't find it */
			return 1;										/* Return dirty */
			break;
			
		default:
			panic("vmm_get_page_dirty_flag: hw_test_rc failed - rc = %d, pmap = %08X, va = %016llX\n", RC, pmap, va);
		
	}

	return 1;												/* Return the change bit */
}


/*-----------------------------------------------------------------------
** vmm_protect_page
**
** This function sets the protection bits of a mapped page
**
** Inputs:
**		act   - pointer to current thread activation
**		index - index of vmm state for this page
**		va    - virtual address within the vmm's address
**			    space
**		prot  - Protection flags
**
** Outputs:
**		none
**		Protection bits of the mapping are modifed
**
-----------------------------------------------------------------------*/

kern_return_t vmm_protect_page(
	thread_act_t 		act,
	vmm_adsp_id_t	 	index,
	addr64_t	 		va,
	vm_prot_t			prot)
{
	vmmCntrlEntry 		*CEntry;
	addr64_t			nextva;
	int	ret;
	pmap_t				pmap;

	pmap = vmm_get_adsp(act, index);						/* Convert index to entry */		
	if (!pmap) return KERN_FAILURE;							/* Either this isn't vmm thread or the index is bogus */
	
	ret = hw_protect(pmap, va, prot, &nextva);				/* Try to change the protect here */

	switch (ret) {											/* Decode return code */
	
		case mapRtOK:										/* All ok... */
			break;											/* Outta here */
			
		case mapRtNotFnd:									/* Didn't find it */
			return KERN_SUCCESS;							/* Ok, return... */
			break;
			
		default:
			panic("vmm_protect_page: hw_protect failed - rc = %d, pmap = %08X, va = %016llX\n", ret, pmap, (addr64_t)va);
		
	}

	if (!((per_proc_info[cpu_number()].spcFlags) & FamVMmode)) {
		act->mact.vmmControl->vmmLastMap = va & 0xFFFFFFFFFFFFF000ULL;	/* Remember the last mapping we made */
		act->mact.vmmControl->vmmGFlags = (act->mact.vmmControl->vmmGFlags & ~vmmLastAdSp) | index;	/* Remember last address space */
	}

	return KERN_SUCCESS;									/* Return */
}


/*-----------------------------------------------------------------------
** vmm_protect_execute
**
** This function sets the protection bits of a mapped page
** and then directly starts executing.
**
**	See description of vmm_protect_page for details
**
** Inputs:
**		See vmm_protect_page and vmm_map_execute
**
** Outputs:
**		Normal exit is to run the VM.  Abnormal exit is triggered via a 
**		non-KERN_SUCCESS return from vmm_map_page or later during the 
**		attempt to transition into the VM. 
-----------------------------------------------------------------------*/

vmm_return_code_t vmm_protect_execute(
	thread_act_t 		act,
	vmm_thread_index_t 	index,
	addr64_t	 		va,
	vm_prot_t			prot)
{
	kern_return_t		ret;
	vmmCntrlEntry 		*CEntry;
	unsigned int		adsp;
	vmm_thread_index_t	cndx;

	cndx = index & 0xFF;							/* Clean it up */
	CEntry = vmm_get_entry(act, cndx);				/* Get and validate the index */
	if (CEntry == NULL) return kVmmBogusContext;	/* Return bogus context */
	
	adsp = (index >> 8) & 0xFF;						/* Get any requested address space */
	if(!adsp) adsp = (index & 0xFF);				/* If 0, use context ID as address space ID */
	
	if (((per_proc_info[cpu_number()].spcFlags) & FamVMmode) && (CEntry != act->mact.vmmCEntry))
		return kVmmBogusContext;			/* Yes, invalid index in Fam */
	
	ret = vmm_protect_page(act, adsp, va, prot);	/* Go try to change access */
	
	if(ret == KERN_SUCCESS) {
		act->mact.vmmControl->vmmLastMap = va & 0xFFFFFFFFFFFFF000ULL;	/* Remember the last mapping we made */
		act->mact.vmmControl->vmmGFlags = (act->mact.vmmControl->vmmGFlags & ~vmmLastAdSp) | cndx;	/* Remember last address space */
		vmm_execute_vm(act, cndx);	/* Return was ok, launch the VM */
	}
	
	return ret;										/* We had trouble of some kind (shouldn't happen) */	
	
}


/*-----------------------------------------------------------------------
** vmm_get_float_state
**
** This function causes the current floating point state to 
** be saved into the shared context area.  It also clears the
** vmmFloatCngd changed flag.
**
** Inputs:
**		act - pointer to current thread activation structure
**		index - index returned by vmm_init_context
**
** Outputs:
**		context saved
-----------------------------------------------------------------------*/

kern_return_t vmm_get_float_state(
	thread_act_t 		act,
	vmm_thread_index_t 	index)
{
	vmmCntrlEntry 		*CEntry;
	vmmCntrlTable		*CTable;
	int					i;
	register struct savearea_fpu *sv;

	CEntry = vmm_get_entry(act, index);				/* Convert index to entry */		
	if (CEntry == NULL) return KERN_FAILURE;		/* Either this isn't vmm thread or the index is bogus */
	
	act->mact.specFlags &= ~floatCng;				/* Clear the special flag */
	CEntry->vmmContextKern->vmmStat &= ~vmmFloatCngd;	/* Clear the change indication */

	fpu_save(&CEntry->vmmFacCtx);					/* Save context if live */

	if(sv = CEntry->vmmFacCtx.FPUsave) {			/* Is there context yet? */
		bcopy((char *)&sv->save_fp0, (char *)&(CEntry->vmmContextKern->vmm_proc_state.ppcFPRs), 32 * 8); /* 32 registers */
		return KERN_SUCCESS;
	}


	for(i = 0; i < 32; i++) {						/* Initialize floating points */
		CEntry->vmmContextKern->vmm_proc_state.ppcFPRs[i].d = FloatInit;	/* Initial value */
	}

	return KERN_SUCCESS;
}

/*-----------------------------------------------------------------------
** vmm_get_vector_state
**
** This function causes the current vector state to 
** be saved into the shared context area.  It also clears the
** vmmVectorCngd changed flag.
**
** Inputs:
**		act - pointer to current thread activation structure
**		index - index returned by vmm_init_context
**
** Outputs:
**		context saved
-----------------------------------------------------------------------*/

kern_return_t vmm_get_vector_state(
	thread_act_t 		act,
	vmm_thread_index_t 	index)
{
	vmmCntrlEntry 		*CEntry;
	vmmCntrlTable		*CTable;
	int					i, j;
	unsigned int 		vrvalidwrk;
	register struct savearea_vec *sv;

	CEntry = vmm_get_entry(act, index);				/* Convert index to entry */		
	if (CEntry == NULL) return KERN_FAILURE;		/* Either this isn't vmm thread or the index is bogus */

	vec_save(&CEntry->vmmFacCtx);					/* Save context if live */
	
	act->mact.specFlags &= ~vectorCng;				/* Clear the special flag */
	CEntry->vmmContextKern->vmmStat &= ~vmmVectCngd;	/* Clear the change indication */
	
	if(sv = CEntry->vmmFacCtx.VMXsave) {			/* Is there context yet? */

		vrvalidwrk = sv->save_vrvalid;				/* Get the valid flags */

		for(i = 0; i < 32; i++) {					/* Copy the saved registers and invalidate the others */
			if(vrvalidwrk & 0x80000000) {			/* Do we have a valid value here? */
				for(j = 0; j < 4; j++) {			/* If so, copy it over */
					CEntry->vmmContextKern->vmm_proc_state.ppcVRs[i].i[j] = ((unsigned int *)&(sv->save_vr0))[(i * 4) + j];
				}
			}
			else {
				for(j = 0; j < 4; j++) {			/* Otherwise set to empty value */
					CEntry->vmmContextKern->vmm_proc_state.ppcVRs[i].i[j] = QNaNbarbarian[j];
				}
			}
			
			vrvalidwrk = vrvalidwrk << 1;			/* Shift over to the next */
			
		}

		return KERN_SUCCESS;
	}

	for(i = 0; i < 32; i++) {						/* Initialize vector registers */
		for(j=0; j < 4; j++) {						/* Do words */
			CEntry->vmmContextKern->vmm_proc_state.ppcVRs[i].i[j] = QNaNbarbarian[j];		/* Initial value */
		}
	}

	return KERN_SUCCESS;
}

/*-----------------------------------------------------------------------
** vmm_set_timer
**
** This function causes a timer (in AbsoluteTime) for a specific time
** to be set  It also clears the vmmTimerPop flag if the timer is actually 
** set, it is cleared otherwise.
**
** A timer is cleared by setting setting the time to 0. This will clear
** the vmmTimerPop bit. Simply setting the timer to earlier than the
** current time clears the internal timer request, but leaves the
** vmmTimerPop flag set.
** 
**
** Inputs:
**		act - pointer to current thread activation structure
**		index - index returned by vmm_init_context
**		timerhi - high order word of AbsoluteTime to pop
**		timerlo - low order word of AbsoluteTime to pop
**
** Outputs:
**		timer set, vmmTimerPop cleared
-----------------------------------------------------------------------*/

kern_return_t vmm_set_timer(
	thread_act_t 		act,
	vmm_thread_index_t 	index,
	unsigned int 		timerhi, 
	unsigned int 		timerlo)
{
	vmmCntrlEntry 		*CEntry;
		
	CEntry = vmm_get_entry(act, index);				/* Convert index to entry */		
	if (CEntry == NULL) return KERN_FAILURE;		/* Either this isn't vmm thread or the index is bogus */
	
	CEntry->vmmTimer = ((uint64_t)timerhi << 32) | timerlo;
	
	vmm_timer_pop(act);								/* Go adjust all of the timer stuff */
	return KERN_SUCCESS;							/* Leave now... */
}


/*-----------------------------------------------------------------------
** vmm_get_timer
**
** This function causes the timer for a specified VM to be
** returned in return_params[0] and return_params[1].
** Note that this is kind of funky for 64-bit VMs because we
** split the timer into two parts so that we still set parms 0 and 1.
** Obviously, we don't need to do this because the parms are 8 bytes
** wide.
** 
**
** Inputs:
**		act - pointer to current thread activation structure
**		index - index returned by vmm_init_context
**
** Outputs:
**		Timer value set in return_params[0] and return_params[1].
**		Set to 0 if timer is not set.
-----------------------------------------------------------------------*/

kern_return_t vmm_get_timer(
	thread_act_t 		act,
	vmm_thread_index_t 	index)
{
	vmmCntrlEntry 		*CEntry;
	vmmCntrlTable		*CTable;

	CEntry = vmm_get_entry(act, index);				/* Convert index to entry */		
	if (CEntry == NULL) return KERN_FAILURE;		/* Either this isn't vmm thread or the index is bogus */

	if(CEntry->vmmXAFlgs & vmm64Bit) {				/* A 64-bit virtual machine? */
		CEntry->vmmContextKern->vmmRet.vmmrp64.return_params[0] = (uint32_t)(CEntry->vmmTimer >> 32);	/* Return the last timer value */
		CEntry->vmmContextKern->vmmRet.vmmrp64.return_params[1] = (uint32_t)CEntry->vmmTimer;	/* Return the last timer value */
	}
	else {
		CEntry->vmmContextKern->vmmRet.vmmrp32.return_params[0] = (CEntry->vmmTimer >> 32);	/* Return the last timer value */
		CEntry->vmmContextKern->vmmRet.vmmrp32.return_params[1] = (uint32_t)CEntry->vmmTimer;	/* Return the last timer value */
	}
	return KERN_SUCCESS;
}


/*-----------------------------------------------------------------------
** vmm_timer_pop
**
** This function causes all timers in the array of VMs to be updated.
** All appropriate flags are set or reset.  If a VM is currently
** running and its timer expired, it is intercepted.
**
** The qactTimer value is set to the lowest unexpired timer.  It is
** zeroed if all timers are expired or have been reset.
**
** Inputs:
**		act - pointer to current thread activation structure
**
** Outputs:
**		timers set, vmmTimerPop cleared or set
-----------------------------------------------------------------------*/

void vmm_timer_pop(
	thread_act_t 		act)
{
	vmmCntrlEntry 		*CEntry;
	vmmCntrlTable		*CTable;
	int					cvi, any;
	uint64_t			now, soonest;
	savearea			*sv;
		
	if(!((unsigned int)act->mact.vmmControl & 0xFFFFFFFE)) {	/* Are there any virtual machines? */
		panic("vmm_timer_pop: No virtual machines defined; act = %08X\n", act);
	}

	soonest = 0xFFFFFFFFFFFFFFFFULL;				/* Max time */

	clock_get_uptime(&now);							/* What time is it? */
	
	CTable = act->mact.vmmControl;					/* Make this easier */	
	any = 0;										/* Haven't found a running unexpired timer yet */
	
	for(cvi = 0; cvi < kVmmMaxContexts; cvi++) {	/* Cycle through all and check time now */

		if(!(CTable->vmmc[cvi].vmmFlags & vmmInUse)) continue;	/* Do not check if the entry is empty */
		
		if(CTable->vmmc[cvi].vmmTimer == 0) {		/* Is the timer reset? */
			CTable->vmmc[cvi].vmmFlags &= ~vmmTimerPop;			/* Clear timer popped */
			CTable->vmmc[cvi].vmmContextKern->vmmStat &= ~vmmTimerPop;	/* Clear timer popped */
			continue;								/* Check next */
		}

		if (CTable->vmmc[cvi].vmmTimer <= now) {
			CTable->vmmc[cvi].vmmFlags |= vmmTimerPop;	/* Set timer popped here */
			CTable->vmmc[cvi].vmmContextKern->vmmStat |= vmmTimerPop;	/* Set timer popped here */
			if((unsigned int)&CTable->vmmc[cvi] == (unsigned int)act->mact.vmmCEntry) {	/* Is this the running VM? */
				sv = find_user_regs(act);			/* Get the user state registers */
				if(!sv) {							/* Did we find something? */
					panic("vmm_timer_pop: no user context; act = %08X\n", act);
				}
				sv->save_exception = kVmmReturnNull*4;	/* Indicate that this is a null exception */
				vmm_force_exit(act, sv);			/* Intercept a running VM */
			}
			continue;								/* Check the rest */
		}
		else {										/* It hasn't popped yet */
			CTable->vmmc[cvi].vmmFlags &= ~vmmTimerPop;	/* Set timer not popped here */
			CTable->vmmc[cvi].vmmContextKern->vmmStat &= ~vmmTimerPop;	/* Set timer not popped here */
		}
		
		any = 1;									/* Show we found an active unexpired timer */
		
		if (CTable->vmmc[cvi].vmmTimer < soonest)
			soonest = CTable->vmmc[cvi].vmmTimer;
	}
	
	if(any) {
		if (act->mact.qactTimer == 0 || soonest <= act->mact.qactTimer)
			act->mact.qactTimer = soonest;	/* Set lowest timer */
	}

	return;
}



/*-----------------------------------------------------------------------
** vmm_stop_vm
**
** This function prevents the specified VM(s) to from running.
** If any is currently executing, the execution is intercepted
** with a code of kVmmStopped.  Note that execution of the VM is
** blocked until a vmmExecuteVM is called with the start flag set to 1.
** This provides the ability for a thread to stop execution of a VM and
** insure that it will not be run until the emulator has processed the
** "virtual" interruption.
**
** Inputs:
**		vmmask - 32 bit mask corresponding to the VMs to put in stop state
**				 NOTE: if this mask is all 0s, any executing VM is intercepted with
*     			 a kVmmStopped (but not marked stopped), otherwise this is a no-op. Also note that there
**				 note that there is a potential race here and the VM may not stop.
**
** Outputs:
**		kernel return code indicating success
**      or if no VMs are enabled, an invalid syscall exception.
-----------------------------------------------------------------------*/

int vmm_stop_vm(struct savearea *save)
{

	thread_act_t		act;
	vmmCntrlTable		*CTable;
	int					cvi, i;
    task_t				task;
    thread_act_t		fact;
    unsigned int		vmmask;
    ReturnHandler		*stopapc;

	ml_set_interrupts_enabled(TRUE);			/* This can take a bit of time so pass interruptions */
	
	task = current_task();						/* Figure out who we are */

	task_lock(task);							/* Lock our task */

	fact = (thread_act_t)task->threads.next;	/* Get the first activation on task */
	act = 0;									/* Pretend we didn't find it yet */

	for(i = 0; i < task->thread_count; i++) {	/* All of the activations */
		if(fact->mact.vmmControl) {				/* Is this a virtual machine monitor? */
			act = fact;							/* Yeah... */
			break;								/* Bail the loop... */
		}
		fact = (thread_act_t)fact->task_threads.next;	/* Go to the next one */
	}

	if(!((unsigned int)act)) {					/* See if we have VMMs yet */
		task_unlock(task);						/* No, unlock the task */
		ml_set_interrupts_enabled(FALSE);		/* Set back interruptions */
		return 0;								/* Go generate a syscall exception */
	}

	act_lock_thread(act);						/* Make sure this stays 'round */
	task_unlock(task);							/* Safe to release now */

	CTable = act->mact.vmmControl;				/* Get the pointer to the table */
	
	if(!((unsigned int)CTable & -2)) {			/* Are there any all the way up yet? */
		act_unlock_thread(act);					/* Unlock the activation */
		ml_set_interrupts_enabled(FALSE);		/* Set back interruptions */
		return 0;								/* Go generate a syscall exception */
	}
	
	if(!(vmmask = save->save_r3)) {				/* Get the stop mask and check if all zeros */
		act_unlock_thread(act);					/* Unlock the activation */
		ml_set_interrupts_enabled(FALSE);		/* Set back interruptions */
		save->save_r3 = KERN_SUCCESS;			/* Set success */	
		return 1;								/* Return... */
	}

	for(cvi = 0; cvi < kVmmMaxContexts; cvi++) {	/* Search slots */
		if((0x80000000 & vmmask) && (CTable->vmmc[cvi].vmmFlags & vmmInUse)) {	/* See if we need to stop and if it is in use */
			hw_atomic_or(&CTable->vmmc[cvi].vmmFlags, vmmXStop);	/* Set this one to stop */
		}
		vmmask = vmmask << 1;					/* Slide mask over */
	}
	
	if(hw_compare_and_store(0, 1, &act->mact.emPendRupts)) {	/* See if there is already a stop pending and lock out others if not */
		act_unlock_thread(act);					/* Already one pending, unlock the activation */
		ml_set_interrupts_enabled(FALSE);		/* Set back interruptions */
		save->save_r3 = KERN_SUCCESS;			/* Say we did it... */	
		return 1;								/* Leave */
	}

	if(!(stopapc = (ReturnHandler *)kalloc(sizeof(ReturnHandler)))) {	/* Get a return handler control block */
		act->mact.emPendRupts = 0;				/* No memory, say we have given up request */
		act_unlock_thread(act);					/* Unlock the activation */
		ml_set_interrupts_enabled(FALSE);		/* Set back interruptions */
		save->save_r3 = KERN_RESOURCE_SHORTAGE;	/* No storage... */
		return 1;								/* Return... */
	}

	ml_set_interrupts_enabled(FALSE);			/* Disable interruptions for now */

	stopapc->handler = vmm_interrupt;			/* Set interruption routine */

	stopapc->next = act->handlers;				/* Put our interrupt at the start of the list */
	act->handlers = stopapc;					/* Point to us */

	act_set_apc(act);							/* Set an APC AST */
	ml_set_interrupts_enabled(TRUE);			/* Enable interruptions now */

	act_unlock_thread(act);						/* Unlock the activation */
	
	ml_set_interrupts_enabled(FALSE);			/* Set back interruptions */
	save->save_r3 = KERN_SUCCESS;				/* Hip, hip, horay... */	
	return 1;
}

/*-----------------------------------------------------------------------
** vmm_interrupt
**
** This function is executed asynchronously from an APC AST.
** It is to be used for anything that needs to interrupt a running VM.
** This include any kind of interruption generation (other than timer pop)
** or entering the stopped state.
**
** Inputs:
**		ReturnHandler *rh - the return handler control block as required by the APC.
**		thread_act_t act  - the activation
**
** Outputs:
**		Whatever needed to be done is done.
-----------------------------------------------------------------------*/

void vmm_interrupt(ReturnHandler *rh, thread_act_t act) {

	vmmCntrlTable		*CTable;
	savearea			*sv;
	boolean_t			inter;



	kfree((vm_offset_t)rh, sizeof(ReturnHandler));	/* Release the return handler block */
	
	inter  = ml_set_interrupts_enabled(FALSE);	/* Disable interruptions for now */

	act->mact.emPendRupts = 0;					/* Say that there are no more interrupts pending */
	CTable = act->mact.vmmControl;				/* Get the pointer to the table */
	
	if(!((unsigned int)CTable & -2)) return;	/* Leave if we aren't doing VMs any more... */

	if(act->mact.vmmCEntry && (act->mact.vmmCEntry->vmmFlags & vmmXStop)) {	/* Do we need to stop the running guy? */
		sv = find_user_regs(act);				/* Get the user state registers */
		if(!sv) {								/* Did we find something? */
			panic("vmm_interrupt: no user context; act = %08X\n", act);
		}
		sv->save_exception = kVmmStopped*4;		/* Set a "stopped" exception */
		vmm_force_exit(act, sv);				/* Intercept a running VM */
	}
	ml_set_interrupts_enabled(inter);			/* Put interrupts back to what they were */

	return;
}

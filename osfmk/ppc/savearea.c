/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 *	This file is used to maintain the exception save areas
 *
 */

#include <cpus.h>
#include <debug.h>
#include <mach_kgdb.h>
#include <mach_vm_debug.h>

#include <kern/thread.h>
#include <mach/vm_attributes.h>
#include <mach/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <mach/ppc/thread_status.h>
#include <kern/spl.h>
#include <kern/simple_lock.h>

#include <kern/misc_protos.h>
#include <ppc/misc_protos.h>
#include <ppc/proc_reg.h>
#include <ppc/mem.h>
#include <ppc/pmap.h>
#include <ppc/pmap_internals.h>
#include <ppc/Firmware.h>
#include <ppc/mappings.h>
#include <ppc/exception.h>
#include <ppc/savearea.h>
#include <ddb/db_output.h>


extern struct	Saveanchor saveanchor;							/* Aliged savearea anchor */
struct Saveanchor backpocket;									/* Emergency saveareas */
unsigned int	debsave0 = 0;									/* Debug flag */
unsigned int	backchain = 0;									/* Debug flag */

/*
 *		These routines keep track of exception save areas and keeps the count within specific limits.  If there are
 *		too few, more are allocated, too many, and they are released. This savearea is where the PCBs are
 *		stored.  They never span a page boundary and are referenced by both virtual and real addresses.
 *		Within the interrupt vectors, the real address is used because at that level, no exceptions
 *		can be tolerated.  Save areas can be dynamic or permanent.  Permanant saveareas are allocated
 *		at boot time and must be in place before any type of exception occurs.  These are never released,
 *		and the number is based upon some arbitrary (yet to be determined) amount times the number of
 *		processors.  This represents the minimum number required to process a total system failure without
 *		destroying valuable and ever-so-handy system debugging information.
 *
 *		We keep two global free lists (the savearea free pool and the savearea free list) and one local
 *		list per processor.
 *
 *		The local lists are small and require no locked access.  They are chained using physical addresses
 *		and no interruptions are allowed when adding to or removing from the list. Also known as the 
 *		qfret list. This list is local to a processor and is intended for use only by very low level
 *		context handling code. 
 *
 *		The savearea free list is a medium size list that is globally accessible.  It is updated
 *		while holding a simple lock. The length of time that the lock is held is kept short.  The
 *		longest period of time is when the list is trimmed. Like the qfret lists, this is chained physically
 *		and must be accessed with translation and interruptions disabled. This is where the bulk
 *		of the free entries are located.
 *
 *		The saveareas are allocated from full pages.  A pool element is marked
 *		with an allocation map that shows which "slots" are free.  These pages are allocated via the
 *		normal kernel memory allocation functions. Queueing is with physical addresses.  The enqueue,
 *		dequeue, and search for free blocks is done under free list lock.  
 *		only if there are empty slots in it.
 *
 *		Saveareas that are counted as "in use" once they are removed from the savearea free list.
 *		This means that all areas on the local qfret list are considered in use.
 *
 *		There are two methods of obtaining a savearea.  The save_get function (which is also inlined
 *		in the low-level exception handler) attempts to get an area from the local qfret list.  This is
 *		done completely without locks.  If qfret is exahusted (or maybe just too low) an area is allocated
 *		from the savearea free list. If the free list is empty, we install the back pocket areas and
 *		panic.
 *
 *		The save_alloc function is designed to be called by high level routines, e.g., thread creation,
 *		etc.  It will allocate from the free list.  After allocation, it will compare the free count
 *		to the target value.  If outside of the range, it will adjust the size either upwards or
 *		downwards.
 *
 *		If we need to shrink the list, it will be trimmed to the target size and unlocked.  The code
 *		will walk the chain and return each savearea to its pool page.  If a pool page becomes
 *		completely empty, it is dequeued from the free pool list and enqueued (atomic queue
 *		function) to be released.
 *
 *		Once the trim list is finished, the pool release queue is checked to see if there are pages
 *		waiting to be released. If so, they are released one at a time.
 *
 *		If the free list needed to be grown rather than shrunken, we will first attempt to recover
 *		a page from the pending release queue (built when we trim the free list).  If we find one,
 *		it is allocated, otherwise, a page of kernel memory is allocated.  This loops until there are
 *		enough free saveareas.
 *		
 */



/*
 *		Allocate our initial context save areas.  As soon as we do this,
 *		we can take an interrupt. We do the saveareas here, 'cause they're guaranteed
 *		to be at least page aligned.
 */


void savearea_init(vm_offset_t *addrx) {

	savearea_comm	*savec, *savec2, *saveprev;
	vm_offset_t		save, save2, addr;
	int i;

	
	saveanchor.savetarget	= InitialSaveTarget;		/* Initial target value */
	saveanchor.saveinuse	= 0;						/* Number of areas in use */

	saveanchor.savefree = 0;							/* Remember the start of the free chain */
	saveanchor.savefreecnt = 0;							/* Remember the length */
	saveanchor.savepoolfwd = (unsigned int *)&saveanchor;	/* Remember pool forward */
	saveanchor.savepoolbwd = (unsigned int *)&saveanchor;	/* Remember pool backward */

	addr = *addrx;										/* Make this easier for ourselves */

	save = 	addr;										/* Point to the whole block of blocks */	

/*
 *	First we allocate the back pocket in case of emergencies
 */


	for(i=0; i < 8; i++) {								/* Initialize the back pocket saveareas */

		savec = (savearea_comm *)save;					/* Get the control area for this one */

		savec->sac_alloc = 0;							/* Mark it allocated */
		savec->sac_vrswap = 0;							/* V=R, so the translation factor is 0 */
		savec->sac_flags = sac_perm;					/* Mark it permanent */
		savec->sac_flags |= 0x0000EE00;					/* Debug eyecatcher */
		save_queue((savearea *)savec);					/* Add page to savearea lists */
		save += PAGE_SIZE;								/* Jump up to the next one now */
	
	}

	backpocket = saveanchor;							/* Save this for emergencies */


/*
 *	We've saved away the back pocket savearea info, so reset it all and
 *	now allocate for real
 */


	saveanchor.savefree = 0;							/* Remember the start of the free chain */
	saveanchor.savefreecnt = 0;							/* Remember the length */
	saveanchor.saveadjust = 0;							/* Set none needed yet */
	saveanchor.savepoolfwd = (unsigned int *)&saveanchor;	/* Remember pool forward */
	saveanchor.savepoolbwd = (unsigned int *)&saveanchor;	/* Remember pool backward */

	for(i=0; i < InitialSaveBloks; i++) {				/* Initialize the saveareas */

		savec = (savearea_comm *)save;					/* Get the control area for this one */

		savec->sac_alloc = 0;							/* Mark it allocated */
		savec->sac_vrswap = 0;							/* V=R, so the translation factor is 0 */
		savec->sac_flags = sac_perm;					/* Mark it permanent */
		savec->sac_flags |= 0x0000EE00;					/* Debug eyecatcher */
		save_queue((savearea *)savec);					/* Add page to savearea lists */
		save += PAGE_SIZE;								/* Jump up to the next one now */
	
	}

	*addrx = save;										/* Move the free storage lowwater mark */

/*
 *	We now have a free list that has our initial number of entries  
 *	The local qfret lists is empty.  When we call save_get below it will see that
 *	the local list is empty and fill it for us.
 *
 *	It is ok to call save_get_phys here because even though if we are translation on, we are still V=R and
 *	running with BAT registers so no interruptions.  Regular interruptions will be off.  Using save_get
 *	would be wrong if the tracing was enabled--it would cause an exception.
 */

	save2 = (vm_offset_t)save_get_phys();				/* This will populate the local list  
														   and get the first one for the system */
	per_proc_info[0].next_savearea = (unsigned int)save2; /* Tell the exception handler about it */
	
/*
 *	The system is now able to take interruptions
 */
	
	return;

}




/*
 *		Returns a savearea.  If the free list needs size adjustment it happens here.
 *		Don't actually allocate the savearea until after the adjustment is done.
 */

struct savearea	*save_alloc(void) {						/* Reserve a save area */
	
	
	if(saveanchor.saveadjust) save_adjust();			/* If size need adjustment, do it now */
	
	return save_get();									/* Pass the baby... */
}


/*
 *		This routine releases a save area to the free queue.  If after that, we have more than our maximum target,
 *		we start releasing what we can until we hit the normal target. 
 */



void save_release(struct savearea *save) {				/* Release a save area */
	
	save_ret(save);										/* Return a savearea to the free list */
	
	if(saveanchor.saveadjust) save_adjust();			/* Adjust the savearea free list and pool size if needed */
	
	return;
	
}


/*
 *		Adjusts the size of the free list.  Can either release or allocate full pages
 *		of kernel memory.  This can block.
 *
 *		Note that we will only run one adjustment and the amount needed may change
 *		while we are executing.
 *
 *		Calling this routine is triggered by saveanchor.saveadjust.  This value is always calculated just before
 *		we unlock the saveanchor lock (this keeps it pretty accurate).  If the total of savefreecnt and saveinuse
 *		is within the hysteresis range, it is set to 0.  If outside, it is set to the number needed to bring
 *		the total to the target value.  Note that there is a minimum size to the free list (FreeListMin) and if
 *		savefreecnt falls below that, saveadjust is set to the number needed to bring it to that.
 */


void save_adjust(void) {
	
	savearea_comm	*sctl, *sctlnext, *freepool, *freepage, *realpage;
	kern_return_t ret;

	if(saveanchor.saveadjust < 0) 					{	/* Do we need to adjust down? */
			
		sctl = (savearea_comm *)save_trim_free();		/* Trim list to the need count, return start of trim list */
				
		while(sctl) {									/* Release the free pages back to the kernel */
			sctlnext = (savearea_comm *)sctl->save_prev;	/* Get next in list */
			kmem_free(kernel_map, (vm_offset_t) sctl, PAGE_SIZE);	/* Release the page */
			sctl = sctlnext;							/* Chain onwards */
		}
	}
	else {												/* We need more... */

		if(save_recover()) return;						/* If we can recover enough from the pool, return */
		
		while(saveanchor.saveadjust > 0) {				/* Keep going until we have enough */

			ret = kmem_alloc_wired(kernel_map, (vm_offset_t *)&freepage, PAGE_SIZE);	/* Get a page for free pool */
			if(ret != KERN_SUCCESS) {					/* Did we get some memory? */
				panic("Whoops...  Not a bit of wired memory left for saveareas\n");
			}
			
			realpage = (savearea_comm *)pmap_extract(kernel_pmap, (vm_offset_t)freepage);	/* Get the physical */
			
			bzero((void *)freepage, PAGE_SIZE);			/* Clear it all to zeros */
			freepage->sac_alloc = 0;					/* Mark all entries taken */
			freepage->sac_vrswap = (unsigned int)freepage ^ (unsigned int)realpage;		/* Form mask to convert V to R and vice versa */
	
			freepage->sac_flags |= 0x0000EE00;			/* Set debug eyecatcher */
						
			save_queue((savearea *)realpage);			/* Add all saveareas on page to free list */
		}
	}
}

/*
 *		Fake up information to make the saveareas look like a zone
 */

save_fake_zone_info(int *count, vm_size_t *cur_size, vm_size_t *max_size, vm_size_t *elem_size,
		    vm_size_t *alloc_size, int *collectable, int *exhaustable)
{
	*count      = saveanchor.saveinuse;
	*cur_size   = (saveanchor.savefreecnt + saveanchor.saveinuse) * (PAGE_SIZE / sac_cnt);
	*max_size   = saveanchor.savemaxcount * (PAGE_SIZE / sac_cnt);
	*elem_size  = sizeof(savearea);
	*alloc_size = PAGE_SIZE;
	*collectable = 1;
	*exhaustable = 0;
}



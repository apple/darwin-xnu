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
 *
 */

/*
 *		This routine allocates a save area.  It checks if enough are available.
 *		If not, it allocates upward to the target free count.
 *		Then, it allocates one and returns it.
 */



struct savearea	*save_alloc(void) {						/* Reserve a save area */
	
	kern_return_t	retr;
	savectl			*sctl;								/* Previous and current save pages */
	vm_offset_t		vaddr, paddr;
	struct savearea	*newbaby;
	
	if(saveanchor.savecount <= (saveanchor.saveneed - saveanchor.saveneghyst)) {	/* Start allocating if we drop too far */
		while(saveanchor.savecount < saveanchor.saveneed) {	/* Keep adding until the adjustment is done */		
			
			
			retr = kmem_alloc_wired(kernel_map, &vaddr, PAGE_SIZE);	/* Find a virtual address to use */
			
			if(retr != KERN_SUCCESS) {					/* Did we get some memory? */
				panic("Whoops...  Not a bit of wired memory left for saveareas\n");
			}
			
			paddr = pmap_extract(kernel_pmap, vaddr);	/* Get the physical */
			
			bzero((void *)vaddr, PAGE_SIZE);			/* Clear it all to zeros */
			sctl = (savectl *)(vaddr+PAGE_SIZE-sizeof(savectl));	/* Point to the control area of the new page */
			sctl->sac_alloc = sac_empty;				/* Mark all entries free */
			sctl->sac_vrswap = (unsigned int)vaddr ^ (unsigned int)paddr;		/* Form mask to convert V to R and vice versa */

			sctl->sac_flags |= 0x0000EE00;				/* (TEST/DEBUG) */
				
			if(!save_queue(paddr)) {					/* Add the new ones to the free savearea list */
				panic("Arrgghhhh, time out trying to lock the savearea anchor during upward adjustment\n");
			}
		}
	}
	if (saveanchor.savecount > saveanchor.savemaxcount)
	        saveanchor.savemaxcount = saveanchor.savecount;

	newbaby = save_get();								/* Get a savearea and return it */
	if(!((unsigned int)newbaby & 0xFFFFF000)) {			/* Whoa... None left??? No, way, no can do... */
		panic("No saveareas?!?!?! No way! Can't happen! Nuh-uh... I'm dead, done for, kaput...\n");
	}

	return newbaby;										/* Bye-bye baby... */
	
}


/*
 *		This routine releases a save area to the free queue.  If after that, we have more than our maximum target,
 *		we start releasing what we can until we hit the normal target. 
 */



void save_release(struct savearea *save) {				/* Release a save area */

	savectl	*csave;										/* The just released savearea block */

	save_ret(save);										/* Return a savearea to the free list */
	
	if(saveanchor.savecount > (saveanchor.saveneed + saveanchor.saveposhyst)) {	/* Start releasing if we have to many */
		csave = (savectl *)42;							/* Start with some nonzero garbage */
		while((unsigned int)csave && (saveanchor.savecount > saveanchor.saveneed)) {	/* Keep removing until the adjustment is done */
	
			csave = save_dequeue();						/* Find and dequeue one that is all empty */
				
			if((unsigned int)csave & 1) {				/* Did we timeout trying to get the lock? */
				panic("Arrgghhhh, time out trying to lock the savearea anchor during downward adjustment\n");
				return;
			}
			
			if((unsigned int)csave) kmem_free(kernel_map, (vm_offset_t) csave, PAGE_SIZE);	/* Release the page if we found one */
		}
	}
	return;
	
}


save_fake_zone_info(int *count, vm_size_t *cur_size, vm_size_t *max_size, vm_size_t *elem_size,
		    vm_size_t *alloc_size, int *collectable, int *exhaustable)
{
        *count      = saveanchor.saveinuse;
	*cur_size   = saveanchor.savecount * (PAGE_SIZE / 2);
	*max_size   = saveanchor.savemaxcount * (PAGE_SIZE / 2);
	*elem_size  = PAGE_SIZE / 2;
	*alloc_size = PAGE_SIZE;
	*collectable = 1;
	*exhaustable = 0;
}



/*
 *		This routine prints the free savearea block chain for debugging.
 */



void save_free_dump(void) {						/* Dump the free chain */

	unsigned int 			*dsv, omsr;
	savectl					*dsc;				
	
	dsv = save_deb(&omsr);						/* Get the virtual of the first and disable interrupts */

	while(dsv) {								/* Do 'em all */
		dsc=(savectl *)((unsigned int)dsv+4096-sizeof(savectl));	/* Point to the control area */
//		printf("%08X %08X: nxt=%08X; alloc=%08X; flags=%08X\n", dsv,	/* Print it all out */
//			((unsigned int)dsv)^(dsc->sac_vrswap), dsc->sac_next, dsc->sac_alloc, dsc->sac_flags);
		dsv=(unsigned int *)(((unsigned int) dsc->sac_next)^(dsc->sac_vrswap));	/* On to the next, virtually */
	
	}
	__asm__ volatile ("mtmsr %0" : : "r" (omsr));	/* Restore the interruption mask */	
	return;
}

/*
 *		This routine prints the free savearea block chain for debugging.
 */



void DumpTheSave(struct savearea *save) {						/* Dump the free chain */

	unsigned int 	*r;
	
	printf("savearea at %08X\n", save);
	printf("           srrs: %08X %08X\n", save->save_srr0, save->save_srr1);
	printf("    cr, xer, lr: %08X %08X %08X\n", save->save_cr, save->save_xer, save->save_lr); 
	printf("ctr, dar, dsisr: %08X %08X %08X\n", save->save_ctr, save->save_dar, save->save_dsisr); 
	printf("  space, copyin: %08X %08X\n", save->save_space, save->save_sr_copyin); 
	r=&save->save_r0;
	printf("           regs: %08X %08X %08X %08X %08X %08X %08X %08X\n", r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]);
	printf("                 %08X %08X %08X %08X %08X %08X %08X %08X\n", r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15]);
	printf("                 %08X %08X %08X %08X %08X %08X %08X %08X\n", r[16], r[17], r[18], r[19], r[20], r[21], r[22], r[23]);
	printf("                 %08X %08X %08X %08X %08X %08X %08X %08X\n", r[24], r[25], r[29], r[27], r[28], r[29], r[30], r[31]);
	r=(unsigned int *)&save->save_fp0;
	printf("         floats: %08X%08X %08X%08X %08X%08X %08X%08X\n", r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]);
	printf("                 %08X%08X %08X%08X %08X%08X %08X%08X\n", r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15]);
	printf("                 %08X%08X %08X%08X %08X%08X %08X%08X\n", r[16], r[17], r[18], r[19], r[20], r[21], r[22], r[23]);
	printf("                 %08X%08X %08X%08X %08X%08X %08X%08X\n", r[24], r[25], r[29], r[27], r[28], r[29], r[30], r[31]);
	printf("                 %08X%08X %08X%08X %08X%08X %08X%08X\n", r[32], r[33], r[34], r[35], r[36], r[37], r[38], r[39]);
	printf("                 %08X%08X %08X%08X %08X%08X %08X%08X\n", r[40], r[41], r[42], r[43], r[44], r[45], r[46], r[47]);
	printf("                 %08X%08X %08X%08X %08X%08X %08X%08X\n", r[48], r[49], r[50], r[51], r[52], r[53], r[54], r[55]);
	printf("                 %08X%08X %08X%08X %08X%08X %08X%08X\n", r[56], r[57], r[58], r[59], r[60], r[61], r[62], r[63]);
	r=&save->save_sr0;
	printf("            srs: %08X %08X %08X %08X %08X %08X %08X %08X\n", r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]);
	printf("                 %08X %08X %08X %08X %08X %08X %08X %08X\n", r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15]);
	printf("prev, phys, act: %08X %08X %08X\n", save->save_prev, save->save_phys, save->save_act); 
	printf("          flags: %08X\n", save->save_flags); 
	return;
}




/*
 *		Dumps out savearea and stack backchains
 */
 
void DumpBackChain(struct savearea *save) {			/* Prints out back chains */

	unsigned int 	*r;
	savearea		*sv;
	
	if(!backchain) return;
	printf("Proceeding back from savearea at %08X:\n", save);
	sv=save;
	while(sv) {
		printf("   curr=%08X; prev=%08X; stack=%08X\n", sv, sv->save_prev, sv->save_r1);
		sv=sv->save_prev;
	}
	return;
}





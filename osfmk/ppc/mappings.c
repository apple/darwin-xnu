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
 *	This file is used to maintain the virtual to real mappings for a PowerPC machine.
 *	The code herein is primarily used to bridge between the pmap layer and the hardware layer.
 *	Currently, some of the function of this module is contained within pmap.c.  We may want to move
 *	all of this into it (or most anyway) for the sake of performance.  We shall see as we write it.
 *
 *	We also depend upon the structure of the phys_entry control block.  We do put some processor 
 *	specific stuff in there.
 *
 */

#include <cpus.h>
#include <debug.h>
#include <mach_kgdb.h>
#include <mach_vm_debug.h>
#include <db_machine_commands.h>

#include <kern/thread.h>
#include <kern/thread_act.h>
#include <mach/vm_attributes.h>
#include <mach/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <kern/spl.h>

#include <kern/misc_protos.h>
#include <ppc/misc_protos.h>
#include <ppc/proc_reg.h>

#include <vm/pmap.h>
#include <ppc/pmap.h>
#include <ppc/pmap_internals.h>
#include <ppc/mem.h>

#include <ppc/new_screen.h>
#include <ppc/Firmware.h>
#include <ppc/mappings.h>
#include <ddb/db_output.h>

#include <ppc/POWERMAC/video_console.h>		/* (TEST/DEBUG) */

#define PERFTIMES 0

#if PERFTIMES && DEBUG
#define debugLog2(a, b, c) dbgLog2(a, b, c)
#else
#define debugLog2(a, b, c)
#endif

vm_map_t        mapping_map = VM_MAP_NULL;
#define		MAPPING_MAP_SIZE	33554432	/* 32MB address space */

unsigned int	incrVSID = 0;									/* VSID increment value */
unsigned int	mappingdeb0 = 0;						
unsigned int	mappingdeb1 = 0;						
extern unsigned int	hash_table_size;						
extern vm_offset_t mem_size;
/*
 *	ppc_prot translates from the mach representation of protections to the PPC version.
 *  We also allow for a direct setting of the protection bits. This extends the mach
 *	concepts to allow the greater control we need for Virtual Machines (VMM).
 *	Calculation of it like this saves a memory reference - and maybe a couple of microseconds.
 *	It eliminates the used of this table.
 *	unsigned char ppc_prot[16] = { 0, 3, 2, 2, 3, 3, 2, 2, 0, 1, 2, 3, 0, 1, 2, 3 };
 */

#define ppc_prot(p) ((0xE4E4AFAC >> (p << 1)) & 3)

/*
 *			About PPC VSID generation:
 *
 *			This function is called to generate an address space ID. This space ID must be unique within
 *			the system.  For the PowerPC, it is used to build the VSID.  We build a VSID in the following
 *			way:  space ID << 4 | segment.  Since a VSID is 24 bits, and out of that, we reserve the last
 *			4, so, we can have 2^20 (2M) unique IDs.  Each pmap has a unique space ID, so we should be able
 *			to have 2M pmaps at a time, which we couldn't, we'd run out of memory way before then.  The 
 *			problem is that only a certain number of pmaps are kept in a free list and if that is full,
 *			they are release.  This causes us to lose track of what space IDs are free to be reused.
 *			We can do 4 things: 1) not worry about it, 2) keep all free pmaps, 3) rebuild all mappings
 *			when the space ID wraps, or 4) scan the list of pmaps and find a free one.
 *
 *			Yet another consideration is the hardware use of the VSID.  It is used as part of the hash
 *			calculation for virtual address lookup.  An improperly chosen value could potentially cause
 *			too many hashes to hit the same bucket, causing PTEG overflows.  The actual hash function
 *			is (page index XOR vsid) mod number of ptegs. For a 32MB machine, using the suggested
 *			hash table size, there are 2^12 (8192) PTEGs.  Remember, though, that the bottom 4 bits
 *			are reserved for the segment number, which means that we really have 2^(12-4) 512 space IDs
 *			before we start hashing to the same buckets with the same vaddrs. Also, within a space ID,
 *			every 8192 pages (32MB) within a segment will hash to the same bucket.  That's 8 collisions
 *			per segment.  So, a scan of every page for 256MB would fill 32 PTEGs completely, but
 *			with no overflow.  I don't think that this is a problem.
 *
 *			There may be a problem with the space ID, though. A new space ID is generate (mainly) 
 *			whenever there is a fork.  There shouldn't really be any problem because (for a 32MB
 *			machine) we can have 512 pmaps and still not have hash collisions for the same address.
 *			The potential problem, though, is if we get long-term pmaps that have space IDs that are
 *			the same modulo 512.  We can reduce this problem by having the segment number be bits
 *			0-3 of the space ID rather than 20-23.  Doing this means that, in effect, corresponding
 *			vaddrs in different segments hash to the same PTEG. While this is somewhat of a problem,
 *			I don't think that it is as signifigant as the other, so, I'll make the space ID
 *			with segment first.
 *
 *			The final, and biggest problem is the wrap, which will happen every 2^20 space IDs.
 *			While this is a problem that should only happen in periods counted in weeks, it can and
 *			will happen.  This is assuming a monotonically increasing space ID. If we were to search
 *			for an inactive space ID, there could not be a wrap until there was 2^20 concurrent space IDs.
 *			That's pretty unlikely to happen.  There couldn't be enough storage to support a million tasks.
 *
 *			So, what we do is to keep all active pmaps in a chain (anchored from kernel_pmap and
 *			locked by free_pmap_lock) that is sorted in VSID sequence order.
 *
 *			Whenever we need a VSID, we walk the list looking for the next in the sequence from
 *			the last that was freed.  The we allocate that.
 *
 *			NOTE: We must be called with interruptions off and free_pmap_lock held.
 *
 */

/*
 *		mapping_init();
 *			Do anything that needs to be done before the mapping system can be used.
 *			Hash table must be initialized before we call this.
 *
 *			Calculate the SID increment.  Currently we use size^(1/2) + size^(1/4) + 1;
 */

void mapping_init(void) {

	unsigned int tmp;
	
	__asm__ volatile("cntlzw %0, %1" : "=r" (tmp) : "r" (hash_table_size));	/* Get number of leading 0s */

	incrVSID = 1 << ((32 - tmp + 1) >> 1);						/* Get ceiling of sqrt of table size */
	incrVSID |= 1 << ((32 - tmp + 1) >> 2);						/* Get ceiling of quadroot of table size */
	incrVSID |= 1;												/* Set bit and add 1 */
	return;

}


/*
 *		mapping_remove(pmap_t pmap, vm_offset_t va);
 *			Given a pmap and virtual address, this routine finds the mapping and removes it from
 *			both its PTEG hash list and the physical entry list.  The mapping block will be added to
 *			the free list.  If the free list threshold is reached, garbage collection will happen.
 *			We also kick back a return code to say whether or not we had one to remove.
 *
 *			We have a strict ordering here:  the mapping must be removed from the PTEG hash list before
 *			it can be removed from the physical entry list.  This allows us to get by with only the PTEG
 *			hash lock at page fault time. The physical entry lock must be held while we remove the mapping 
 *			from both lists. The PTEG lock is one of the lowest level locks.  No PTE fault, interruptions,
 *			losing control, getting other locks, etc., are allowed when you hold it. You do, and you die.
 *			It's just that simple!
 *
 *			When the phys_entry lock is held, the mappings chained to that one are guaranteed to stay around.
 *			However, a mapping's order on the PTEG hash chain is not.  The interrupt handler uses the PTEG
 *			lock to control the hash cahin and may move the position of the mapping for MRU calculations.
 *
 *			Note that mappings do not need to point to a physical entry. When they don't, it indicates 
 *			the mapping is outside of physical memory and usually refers to a memory mapped device of
 *			some sort.  Naturally, we can't lock what we don't have, so the phys entry lock and unlock
 *			routines return normally, but don't do anything.
 */

boolean_t mapping_remove(pmap_t pmap, vm_offset_t va) {			/* Remove a single mapping for this VADDR 
																   Returns TRUE if a mapping was found to remove */

	mapping		*mp, *mpv;
	register blokmap *blm;
	spl_t 		s;
	unsigned int *useadd, *useaddr;
	int i;
	
	debugLog2(1, va, pmap->space);								/* start mapping_remove */

	s=splhigh();												/* Don't bother me */
	
	mp = hw_lock_phys_vir(pmap->space, va);						/* Lock the physical entry for this mapping */

	if(!mp) {													/* Did we find one? */
		splx(s);											/* Allow 'rupts now */
		if(mp = (mapping *)hw_rem_blk(pmap, va, va)) {			/* No normal pages, try to remove an odd-sized one */
			
			if((unsigned int)mp & 1) {							/* Make sure we don't unmap a permanent one */
				blm = (blokmap *)hw_cpv((mapping *)((unsigned int)mp & 0xFFFFFFFC));		/* Get virtual address */
				panic("mapping_remove: attempt to unmap a permanent mapping - pmap = %08X, va = %08X, mapping = %08X\n",
					pmap, va, blm);
			}
			while ((unsigned int)mp & 2)
				mp = (mapping *)hw_rem_blk(pmap, va, va);
#if 0
			blm = (blokmap *)hw_cpv(mp);						/* (TEST/DEBUG) */
			kprintf("mapping_remove: removed block map - bm=%08X; start=%08X; end=%08X; PTEr=%08X\n",	/* (TEST/DEBUG) */
			 blm, blm->start, blm->end, blm->PTEr);
#endif
			mapping_free(hw_cpv(mp));							/* Release it */
			debugLog2(2, 1, 0);									/* End mapping_remove */
			return TRUE;										/* Tell them we did it */
		}
		debugLog2(2, 0, 0);										/* end mapping_remove */
		return FALSE;											/* Didn't find any, return FALSE... */
	}
	if((unsigned int)mp&1) {									/* Did we timeout? */
		panic("mapping_remove: timeout locking physical entry\n");	/* Yeah, scream about it! */
		splx(s);												/* Restore the interrupt level */
		return FALSE;											/* Bad hair day, return FALSE... */
	}
	
	mpv = hw_cpv(mp);											/* Get virtual address of mapping */
#if DEBUG
	if(hw_atomic_sub(&mpv->pmap->stats.resident_count, 1) < 0) panic("pmap resident count went negative\n");
#else
	(void)hw_atomic_sub(&mpv->pmap->stats.resident_count, 1);	/* Decrement the resident page count */
#endif
	useadd = (unsigned int *)&pmap->pmapUsage[(va >> pmapUsageShft) & pmapUsageMask];	/* Point to slot to bump */
	useaddr = (unsigned int *)((unsigned int)useadd & -4);		/* Round down to word */
	(void)hw_atomic_sub(useaddr, (useaddr == useadd) ? 0x00010000 : 1);	/* Increment the even or odd slot */

#if 0
	for(i = 0; i < (pmapUsageMask + 1); i++) {					/* (TEST/DEBUG) */
		if((mpv->pmap->pmapUsage[i]) > 8192) {					/* (TEST/DEBUG) */
			panic("mapping_remove: pmapUsage slot for %08X has invalid count (%d) for pmap %08X\n",
				i * pmapUsageSize, mpv->pmap->pmapUsage[i], mpv->pmap);
		}
	}
#endif
	
	hw_rem_map(mp);												/* Remove the corresponding mapping */
	
	if(mpv->physent)hw_unlock_bit((unsigned int *)&mpv->physent->phys_link, PHYS_LOCK);	/* Unlock physical entry associated with mapping */
	
	splx(s);													/* Was there something you needed? */
		
	mapping_free(mpv);											/* Add mapping to the free list */
	debugLog2(2, 1, 0);											/* end mapping_remove */
	return TRUE;												/* Tell them we did it */
}

/*
 *		mapping_purge_pmap(struct phys_entry *pp, pmap_t pmap) - release all mappings for this physent for the specified map
 *
 *		This guy releases any mappings that exist for a physical page on a specified map.
 *		We get the lock on the phys_entry, and hold it through out this whole routine.
 *		That way, no one can change the queue out from underneath us.  We keep fetching
 *		the physents mapping anchor until it is null, then we're done.  
 *
 *		For each mapping, we call the remove routine to remove it from the PTEG hash list and 
 *		decriment the pmap's residency count.  Then we release the mapping back to the free list.
 *
 */
 

void mapping_purge_pmap(struct phys_entry *pp, pmap_t pmap) {		/* Remove all mappings from specified pmap for this physent */

	mapping		*mp, *mp_next, *mpv;
	spl_t 		s;
	unsigned int *useadd, *useaddr, uindx;
	int i;
		
	s=splhigh();									/* Don't bother me */
	
	if(!hw_lock_bit((unsigned int *)&pp->phys_link, PHYS_LOCK, LockTimeOut)) {	/* Lock the physical entry */
		panic("\nmapping_purge_pmap: Timeout attempting to lock physical entry at %08X: %08X %08X\n", 
			pp, pp->phys_link, pp->pte1);	/* Complain about timeout */
	}

	mp = (mapping *)((unsigned int)pp->phys_link & ~PHYS_FLAGS);
	
	while(mp) {	/* Keep going so long as there's another */

		mpv = hw_cpv(mp);					/* Get the virtual address */
		if(mpv->pmap != pmap) {
			mp = (mapping *)((unsigned int)mpv->next & ~PHYS_FLAGS);
			continue;
		}
#if DEBUG
		if(hw_atomic_sub(&mpv->pmap->stats.resident_count, 1) < 0) panic("pmap resident count went negative\n");
#else
		(void)hw_atomic_sub(&mpv->pmap->stats.resident_count, 1);	/* Decrement the resident page count */
#endif

		uindx = ((mpv->PTEv >> 24) & 0x78) | ((mpv->PTEv >> 3) & 7);	/* Join seg # and top 2 bits of API */
		useadd = (unsigned int *)&mpv->pmap->pmapUsage[uindx];	/* Point to slot to bump */
		useaddr = (unsigned int *)((unsigned int)useadd & -4);	/* Round down to word */
		(void)hw_atomic_sub(useaddr, (useaddr == useadd) ? 0x00010000 : 1); /* Incr the even or odd slot */

	
	
		mp_next = (mapping *)((unsigned int)mpv->next & ~PHYS_FLAGS);
		hw_rem_map(mp);						/* Remove the mapping */
		mapping_free(mpv);					/* Add mapping to the free list */
		mp = mp_next;
	}
		
	hw_unlock_bit((unsigned int *)&pp->phys_link, PHYS_LOCK);	/* We're done, unlock the physical entry */
	splx(s);
	return;
}
/*
 *		mapping_purge(struct phys_entry *pp) - release all mappings for this physent to the free list 
 *
 *		This guy releases any mappings that exist for a physical page.
 *		We get the lock on the phys_entry, and hold it through out this whole routine.
 *		That way, no one can change the queue out from underneath us.  We keep fetching
 *		the physents mapping anchor until it is null, then we're done.  
 *
 *		For each mapping, we call the remove routine to remove it from the PTEG hash list and 
 *		decriment the pmap's residency count.  Then we release the mapping back to the free list.
 *
 */
 
void mapping_purge(struct phys_entry *pp) {						/* Remove all mappings for this physent */

	mapping		*mp, *mpv;
	spl_t 		s;
	unsigned int *useadd, *useaddr, uindx;
	int i;
		
	s=splhigh();												/* Don't bother me */
	debugLog2(3, pp->pte1, 0);									/* start mapping_purge */
	
	if(!hw_lock_bit((unsigned int *)&pp->phys_link, PHYS_LOCK, LockTimeOut)) {		/* Lock the physical entry */
		panic("\nmapping_purge: Timeout attempting to lock physical entry at %08X: %08X %08X\n", 
			pp, pp->phys_link, pp->pte1);	/* Complain about timeout */
	}
	
	while(mp = (mapping *)((unsigned int)pp->phys_link & ~PHYS_FLAGS)) {	/* Keep going so long as there's another */

		mpv = hw_cpv(mp);										/* Get the virtual address */
#if DEBUG
		if(hw_atomic_sub(&mpv->pmap->stats.resident_count, 1) < 0) panic("pmap resident count went negative\n");
#else
		(void)hw_atomic_sub(&mpv->pmap->stats.resident_count, 1);	/* Decrement the resident page count */
#endif

		uindx = ((mpv->PTEv >> 24) & 0x78) | ((mpv->PTEv >> 3) & 7);	/* Join segment number and top 2 bits of the API */
		useadd = (unsigned int *)&mpv->pmap->pmapUsage[uindx];	/* Point to slot to bump */
		useaddr = (unsigned int *)((unsigned int)useadd & -4);	/* Round down to word */
		(void)hw_atomic_sub(useaddr, (useaddr == useadd) ? 0x00010000 : 1);	/* Increment the even or odd slot */

#if 0
	for(i = 0; i < (pmapUsageMask + 1); i++) {					/* (TEST/DEBUG) */
		if((mpv->pmap->pmapUsage[i]) > 8192) {					/* (TEST/DEBUG) */
			panic("mapping_remove: pmapUsage slot for %08X has invalid count (%d) for pmap %08X\n",
				i * pmapUsageSize, mpv->pmap->pmapUsage[i], mpv->pmap);
		}
	}
#endif
	
	
		hw_rem_map(mp);											/* Remove the mapping */
		mapping_free(mpv);										/* Add mapping to the free list */
	}
		
	hw_unlock_bit((unsigned int *)&pp->phys_link, PHYS_LOCK);	/* We're done, unlock the physical entry */
	
	debugLog2(4, pp->pte1, 0);									/* end mapping_purge */
	splx(s);													/* Was there something you needed? */
	return;														/* Tell them we did it */
}


/*
 *		mapping_make(pmap, pp, va, spa, prot, attr, locked) - map a virtual address to a real one 
 *
 *		This routine takes the given parameters, builds a mapping block, and queues it into the 
 *		correct lists.
 *		
 *		The pp parameter can be null.  This allows us to make a mapping that is not
 *		associated with any physical page.  We may need this for certain I/O areas.
 *
 *		If the phys_entry address is null, we neither lock or chain into it.
 *		If locked is 1, we already hold the lock on the phys_entry and won't get nor release it.
 */
 
mapping *mapping_make(pmap_t pmap, struct phys_entry *pp, vm_offset_t va, vm_offset_t pa, vm_prot_t prot, int attr, boolean_t locked) {	/* Make an address mapping */

	register mapping *mp, *mpv;
	unsigned int *useadd, *useaddr;
	spl_t 		s;
	int i;

	debugLog2(5, va, pa);										/* start mapping_purge */
	mpv = mapping_alloc();										/* Get a spare mapping block */
	
	mpv->pmap = pmap;											/* Initialize the pmap pointer */
	mpv->physent = pp;											/* Initialize the pointer to the physical entry */
	mpv->PTEr = ((unsigned int)pa & ~(PAGE_SIZE - 1)) | attr<<3 | ppc_prot(prot);	/* Build the real portion of the PTE */
	mpv->PTEv = (((unsigned int)va >> 1) & 0x78000000) | (pmap->space << 7) | (((unsigned int)va >> 22) & 0x0000003F);	/* Build the VSID */

	s=splhigh();												/* Don't bother from now on */
	
	mp = hw_cvp(mpv);											/* Get the physical address of this */

	if(pp && !locked) {											/* Is there a physical entry? Or do we already hold the lock? */
		if(!hw_lock_bit((unsigned int *)&pp->phys_link, PHYS_LOCK, LockTimeOut)) {	/* Lock the physical entry */
			panic("\nmapping_make: Timeout attempting to lock physical entry at %08X: %08X %08X\n", 
				pp, pp->phys_link, pp->pte1);					/* Complain about timeout */
		}
	}
		
	if(pp) {													/* See of there is a physcial entry */
		mpv->next = (mapping *)((unsigned int)pp->phys_link & ~PHYS_FLAGS);		/* Move the old anchor to the new mappings forward */
		pp->phys_link = (mapping *)((unsigned int)mp | (unsigned int)pp->phys_link & PHYS_FLAGS);	/* Point the anchor at us.  Now we're on the list (keep the flags) */
	}
	
	hw_add_map(mp, pmap->space, va);							/* Stick it on the PTEG hash list */
	
	(void)hw_atomic_add(&mpv->pmap->stats.resident_count, 1);	/* Increment the resident page count */
	useadd = (unsigned int *)&pmap->pmapUsage[(va >> pmapUsageShft) & pmapUsageMask];	/* Point to slot to bump */
	useaddr = (unsigned int *)((unsigned int)useadd & -4);		/* Round down to word */
	(void)hw_atomic_add(useaddr, (useaddr == useadd) ? 0x00010000 : 1);	/* Increment the even or odd slot */
#if 0
	for(i = 0; i < (pmapUsageMask + 1); i++) {					/* (TEST/DEBUG) */
		if((mpv->pmap->pmapUsage[i]) > 8192) {					/* (TEST/DEBUG) */
			panic("mapping_remove: pmapUsage slot for %08X has invalid count (%d) for pmap %08X\n",
				i * pmapUsageSize, mpv->pmap->pmapUsage[i], mpv->pmap);
		}
	}
#endif

	if(pp && !locked)hw_unlock_bit((unsigned int *)&pp->phys_link, PHYS_LOCK);	/* If we have one and we didn't hold on entry, unlock the physical entry */
		
	splx(s);													/* Ok for interruptions now */
	debugLog2(6, pmap->space, prot);							/* end mapping_purge */
	return mpv;													/* Leave... */
}


/*
 *		Enters optimal translations for odd-sized V=F blocks.
 *
 *		Builds a block map for each power-of-two hunk o' address
 *		that exists.  This is specific to the processor type.  
 *		PPC uses BAT register size stuff.  Future PPC might have
 *		something else.
 *
 *		The supplied va is expected to be maxoptimal vs the supplied boundary. We're too
 *		stupid to know otherwise so we only look at the va anyhow, so there...
 *
 */
 
void mapping_block_map_opt(pmap_t pmap, vm_offset_t va, vm_offset_t pa, vm_offset_t bnd, vm_size_t size, vm_prot_t prot, int attr) {	/* Maps optimal autogenned blocks */

	register blokmap *blm, *oblm;
	unsigned int	pg;
	unsigned int	maxsize, boundary, leading, trailing, cbsize, minsize, tomin;
	int				i, maxshft, nummax, minshft;

#if 1
	kprintf("mapping_block_map_opt: pmap=%08X; va=%08X; pa=%08X; ; bnd=%08X; size=%08X; prot=%08X; attr=%08X\n",	/* (TEST/DEBUG) */
	 pmap, va, pa, bnd, size, prot, attr);
#endif
	
	minsize = blokValid ^ (blokValid & (blokValid - 1));	/* Set minimum subblock size */
	maxsize = 0x80000000 >> cntlzw(blokValid);		/* Set maximum subblock size */
	
	minshft = 31 - cntlzw(minsize);					/* Shift to position minimum size */
	maxshft = 31 - cntlzw(blokValid);				/* Shift to position maximum size */
	
	leading = ((va + bnd - 1) & -bnd) - va;			/* Get size of leading area */
	trailing = size - leading;						/* Get size of trailing area */
	tomin = ((va + minsize - 1) & -minsize) - va;	/* Get size needed to round up to the minimum block size */
	
#if 1
	kprintf("mapping_block_map_opt: bnd=%08X; leading=%08X; trailing=%08X; tomin=%08X\n", bnd, leading, trailing, tomin);		/* (TEST/DEBUG) */
#endif

	if(tomin)pmap_map_block(pmap, va, pa, tomin, prot, attr, 0); /* Map up to minimum block size */
	
	va = va + tomin;								/* Adjust virtual start */
	pa = pa + tomin;								/* Adjust physical start */
	leading = leading - tomin;						/* Adjust leading size */
	
/*
 *	Some of this code is very classic PPC.  We need to fix this up.
 */
 
	leading = leading >> minshft;					/* Position for bit testing */
	cbsize = minsize;								/* Set the minimum size */
	
	for(i = 0; i < (maxshft - minshft + 1); i ++) {	/* Cycle through all block sizes, small to large */
		
		if(leading & 1) {		
			pmap_map_block(pmap, va, pa, cbsize, prot, attr, 0); /* Map up to next boundary */
			pa = pa + cbsize;						/* Bump up physical address */
			va = va + cbsize;						/* Bump up virtual address */
		}
	
		leading = leading >> 1;						/* Shift up to next size */
		cbsize = cbsize << 1;						/* Here too */

	}
	
	nummax = trailing >> maxshft;					/* Get number of max size blocks left */
	for(i=0; i < nummax - 1; i++) {					/* Account for all max size block left but 1 */
		pmap_map_block(pmap, va, pa, maxsize, prot, attr, 0); /* Map up to next boundary */

		pa = pa + maxsize;							/* Bump up physical address */
		va = va + maxsize;							/* Bump up virtual address */
		trailing -= maxsize;						/* Back off what we just did */
	}
	
	cbsize = maxsize;								/* Start at maximum size */
	
	for(i = 0; i < (maxshft - minshft + 1); i ++) {	/* Cycle through all block sizes, high to low */
		
		if(trailing & cbsize) {	
			trailing &= ~cbsize;					/* Remove the block we are allocating */						
			pmap_map_block(pmap, va, pa, cbsize, prot, attr, 0); /* Map up to next boundary */
			pa = pa + cbsize;						/* Bump up physical address */
			va = va + cbsize;						/* Bump up virtual address */
		}	
		cbsize = cbsize >> 1;						/* Next size down */
	}
	
	if(trailing) pmap_map_block(pmap, va, pa, trailing, prot, attr, 0); /* Map up to end */
	
	return;													/* Return */
}


/*
 *		Enters translations for odd-sized V=F blocks.
 *
 *		Checks to insure that the request is at least ODDBLKMIN in size.  If smaller, the request
 *		will be split into normal-sized page mappings.
 *
 *		The higher level VM map should be locked to insure that we don't have a
 *		double diddle here.
 *
 *		We panic if we get a block that overlaps with another. We do not merge adjacent
 *		blocks because removing any address within a block removes the entire block and if
 *		would really mess things up if we trashed too much.
 *
 *		Once a block is mapped, it is unmutable, that is, protection, catch mode, etc. can
 *		not be changed.  The block must be unmapped and then remapped with the new stuff.
 *		We also do not keep track of reference or change flags.
 *
 *		Blocks are kept in MRU order anchored from the pmap. The chain is traversed only
 *		with interruptions and translation disabled and under the control of the lock located
 *		in the first block map. MRU is used because it is expected that the same entry 
 *		will be accessed repeatedly while PTEs are being generated to cover those addresses.
 *
 */
 
void pmap_map_block(pmap_t pmap, vm_offset_t va, vm_offset_t pa, vm_size_t size, vm_prot_t prot, int attr, unsigned int flags) {	/* Map an autogenned block */

	register blokmap *blm, *oblm, *oblm_virt;;
	unsigned int pg;

#if 0
	kprintf("pmap_map_block: pmap=%08X; va=%08X; pa=%08X; size=%08X; prot=%08X; attr=%08X\n",	/* (TEST/DEBUG) */
	 pmap, va, pa, size, prot, attr);
#endif

	if(size < ODDBLKMIN) {									/* Is this below the minimum size? */
		for(pg = 0; pg < size; pg += PAGE_SIZE) {			/* Add all pages in this block */
			mapping_make(pmap, 0, va + pg, pa + pg, prot, attr, 0);	/* Map this page on in */
#if 0
			kprintf("pmap_map_block: mm: va=%08X; pa=%08X\n",	/* (TEST/DEBUG) */
				va + pg, pa + pg);
#endif
		}
		return;												/* All done */
	}
	
	blm = (blokmap *)mapping_alloc();						/* Get a block mapping */
	
	blm->start = (unsigned int)va & -PAGE_SIZE;				/* Get virtual block start */
	blm->end = (blm->start + size - 1) | (PAGE_SIZE - 1);	/* Get virtual block end */
	blm->current = 0;
	blm->PTEr = ((unsigned int)pa & -PAGE_SIZE) | attr<<3 | ppc_prot(prot);	/* Build the real portion of the base PTE */
	blm->space = pmap->space;								/* Set the space (only needed for remove) */
	blm->blkFlags = flags;									/* Set the block's flags */
	
#if 0
	kprintf("pmap_map_block: bm=%08X; start=%08X; end=%08X; PTEr=%08X\n",	/* (TEST/DEBUG) */
	 blm, blm->start, blm->end, blm->PTEr);
#endif

	blm = (blokmap *)hw_cvp((mapping *)blm);				/* Get the physical address of this */

#if 0
	kprintf("pmap_map_block: bm (real)=%08X; pmap->bmaps=%08X\n",	/* (TEST/DEBUG) */
	 blm, pmap->bmaps);
#endif

	do {
		oblm = hw_add_blk(pmap, blm); 
		if ((unsigned int)oblm & 2) {
			oblm_virt = (blokmap *)hw_cpv((mapping *)((unsigned int)oblm & 0xFFFFFFFC));
			mapping_remove(pmap, oblm_virt->start);
		};
	} while ((unsigned int)oblm & 2);

	if (oblm) {
		oblm = (blokmap *)hw_cpv((mapping *) oblm);				/* Get the old block virtual address */
		blm = (blokmap *)hw_cpv((mapping *)blm);				/* Back to the virtual address of this */
		if((oblm->start != blm->start) ||					/* If we have a match, then this is a fault race and */
				(oblm->end != blm->end) ||				/* is acceptable */
				(oblm->PTEr != blm->PTEr))
			panic("pmap_map_block: block map overlap - blm = %08X\n", oblm);/* Otherwise, Squeak loudly and carry a big stick */
		mapping_free((struct mapping *)blm);
	}

#if 0
	kprintf("pmap_map_block: pmap->bmaps=%08X\n",			/* (TEST/DEBUG) */
	 blm, pmap->bmaps);
#endif

	return;													/* Return */
}


/*
 *		Optimally enters translations for odd-sized V=F blocks.
 *
 *		Checks to insure that the request is at least ODDBLKMIN in size.  If smaller, the request
 *		will be split into normal-sized page mappings.
 *
 *		This one is different than pmap_map_block in that it will allocate it's own virtual
 *		target address. Rather than allocating a single block,
 *		it will also allocate multiple blocks that are power-of-two aligned/sized.  This allows
 *		hardware-level mapping that takes advantage of BAT maps or large page sizes.
 *
 *		Most considerations for pmap_map_block apply.
 *
 *
 */
 
kern_return_t pmap_map_block_opt(vm_map_t map, vm_offset_t *va, 
	vm_offset_t pa, vm_size_t size, vm_prot_t prot, int attr) {	/* Map an optimal autogenned block */

	register blokmap *blm, *oblm;
	unsigned int 	pg;
    kern_return_t	err;
	unsigned int	bnd;

#if 1
	kprintf("pmap_map_block_opt: map=%08X; pa=%08X; size=%08X; prot=%08X; attr=%08X\n",	/* (TEST/DEBUG) */
		map, pa, size, prot, attr);
#endif

	if(size < ODDBLKMIN) {									/* Is this below the minimum size? */
		err = vm_allocate(map, va, size, VM_FLAGS_ANYWHERE);	/* Make us some memories */
		if(err) {
#if DEBUG
			kprintf("pmap_map_block_opt: vm_allocate() returned %d\n", err);	/* Say we died */
#endif
			return(err);									/* Pass back the error */
		}
#if 1
		kprintf("pmap_map_block_opt: small; vaddr = %08X\n", *va);	/* (TEST/DEBUG) */
#endif

		for(pg = 0; pg < size; pg += PAGE_SIZE) {			/* Add all pages in this block */
			mapping_make(map->pmap, 0, *va + pg, pa + pg, prot, attr, 0);	/* Map this page on in */
		}
		return(KERN_SUCCESS);								/* All done */
	}
	
	err = vm_map_block(map, va, &bnd, pa, size, prot);		/* Go get an optimal allocation */

	if(err == KERN_INVALID_ADDRESS) {						/* Can we try a brute force block mapping? */
		err = vm_allocate(map, va, size, VM_FLAGS_ANYWHERE);	/* Make us some memories */
		if(err) {
#if DEBUG
			kprintf("pmap_map_block_opt: non-optimal vm_allocate() returned %d\n", err);	/* Say we died */
#endif
			return(err);									/* Pass back the error */
		}
#if 1
		kprintf("pmap_map_block_opt: non-optimal - vaddr = %08X\n", *va);	/* (TEST/DEBUG) */
#endif
		pmap_map_block(map->pmap, *va, pa, size, prot, attr, 0);	/* Set up a block mapped area */
		return KERN_SUCCESS;								/* All done now */
	}

	if(err != KERN_SUCCESS) {								/* We couldn't get any address range to map this... */
#if DEBUG
		kprintf("pmap_map_block_opt: vm_allocate() returned %d\n", err);	/* Say we couldn' do it */
#endif
		return(err);
	}

#if 1
	kprintf("pmap_map_block_opt: optimal - vaddr=%08X; bnd=%08X\n", *va, bnd);	/* (TEST/DEBUG) */
#endif
	mapping_block_map_opt(map->pmap, *va, pa, bnd, size, prot, attr);	/* Go build the maps */
	return(KERN_SUCCESS);									/* All done */
}


#if 0

/*
 *		Enters translations for odd-sized V=F blocks and merges adjacent or overlapping
 *		areas.
 *
 *		Once blocks are merged, they act like one block, i.e., if you remove it,
 *		it all goes...
 *
 *		This can only be used during boot.  Ain't no way we can handle SMP
 *		or preemption easily, so we restrict it.  We don't check either. We
 *		assume only skilled professional programmers will attempt using this
 *		function. We assume no responsibility, either real or imagined, for
 *		injury or death resulting from unauthorized use of this function.
 *
 *		No user servicable parts inside. Notice to be removed by end-user only,
 *		under penalty of applicable federal and state laws.
 *
 *		See descriptions of pmap_map_block. Ignore the part where we say we panic for
 *		overlapping areas.  Note that we do panic if we can't merge.
 *
 */
 
void pmap_map_block_merge(pmap_t pmap, vm_offset_t va, vm_offset_t pa, vm_size_t size, vm_prot_t prot, int attr) {	/* Map an autogenned block */

	register blokmap *blm, *oblm;
	unsigned int pg;
	spl_t 		s;

#if 1
	kprintf("pmap_map_block_merge: pmap=%08X; va=%08X; pa=%08X; size=%08X; prot=%08X; attr=%08X\n",	/* (TEST/DEBUG) */
	 pmap, va, pa, size, prot, attr);
#endif

	s=splhigh();												/* Don't bother from now on */
	if(size < ODDBLKMIN) {										/* Is this below the minimum size? */
		for(pg = 0; pg < size; pg += PAGE_SIZE) {				/* Add all pages in this block */
			mapping_make(pmap, 0, va + pg, pa + pg, prot, attr, 0);	/* Map this page on in */
		}
		return;													/* All done */
	}
	
	blm = (blokmap *)mapping_alloc();							/* Get a block mapping */
	
	blm->start = (unsigned int)va & -PAGE_SIZE;					/* Get virtual block start */
	blm->end = (blm->start + size - 1) | (PAGE_SIZE - 1);		/* Get virtual block end */
	blm->PTEr = ((unsigned int)pa & -PAGE_SIZE) | attr<<3 | ppc_prot(prot);	/* Build the real portion of the base PTE */
	
#if 1
	kprintf("pmap_map_block_merge: bm=%08X; start=%08X; end=%08X; PTEr=%08X\n",	/* (TEST/DEBUG) */
	 blm, blm->start, blm->end, blm->PTEr);
#endif

	blm = (blokmap *)hw_cvp((mapping *)blm);					/* Get the physical address of this */

#if 1
	kprintf("pmap_map_block_merge: bm (real)=%08X; pmap->bmaps=%08X\n",	/* (TEST/DEBUG) */
	 blm, pmap->bmaps);
#endif

	if(oblm = hw_add_blk(pmap, blm)) {							/* Add to list and make sure we don't overlap anything */
		panic("pmap_map_block_merge: block map overlap - blm = %08X\n", oblm);	/* Squeak loudly and carry a big stick */
	}

#if 1
	kprintf("pmap_map_block_merge: pmap->bmaps=%08X\n",			/* (TEST/DEBUG) */
	 blm, pmap->bmaps);
#endif
	splx(s);													/* Ok for interruptions now */

	return;														/* Return */
}
#endif

/*
 *		void mapping_protect_phys(phys_entry *pp, vm_prot_t prot) - change the protection of a physical page
 *
 *		This routine takes a physical entry and runs through all mappings attached to it and changes
 *		the protection.  If there are PTEs associated with the mappings, they will be invalidated before
 *		the protection is changed.  We don't try to save the PTE.  We won't worry about the LRU calculations
 *		either (I don't think, maybe I'll change my mind later).  There is no limitation on changes, e.g., 
 *		higher to lower, lower to higher.
 *
 *		Phys_entry is unlocked.
 */

void mapping_protect_phys(struct phys_entry *pp, vm_prot_t prot, boolean_t locked) {	/* Change protection of all mappings to page */

	spl_t				spl;
	
	debugLog2(9, pp->pte1, prot);								/* end remap */
	spl=splhigh();												/* No interruptions during this */
	if(!locked) {												/* Do we need to lock the physent? */
		if(!hw_lock_bit((unsigned int *)&pp->phys_link, PHYS_LOCK, LockTimeOut)) {	/* Lock the physical entry */
			panic("\nmapping_protect: Timeout attempting to lock physical entry at %08X: %08X %08X\n", 
				pp, pp->phys_link, pp->pte1);						/* Complain about timeout */
		}
	}	

	hw_prot(pp, ppc_prot(prot));								/* Go set the protection on this physical page */

	if(!locked) hw_unlock_bit((unsigned int *)&pp->phys_link, PHYS_LOCK);	/* We're done, unlock the physical entry */
	splx(spl);													/* Restore interrupt state */
	debugLog2(10, pp->pte1, 0);									/* end remap */
	
	return;														/* Leave... */
}

/*
 *		void mapping_protect(pmap_t pmap, vm_offset_t vaddr, vm_prot_t prot) - change the protection of a virtual page
 *
 *		This routine takes a pmap and virtual address and changes
 *		the protection.  If there are PTEs associated with the mappings, they will be invalidated before
 *		the protection is changed.  We don't try to save the PTE.  We won't worry about the LRU calculations
 *		either (I don't think, maybe I'll change my mind later).  There is no limitation on changes, e.g., 
 *		higher to lower, lower to higher.
 *
 */

void mapping_protect(pmap_t pmap, vm_offset_t vaddr, vm_prot_t prot) {	/* Change protection of a virtual page */

	mapping		*mp, *mpv;
	spl_t 		s;

	debugLog2(9, vaddr, pmap);					/* start mapping_protect */
	s = splhigh();								/* Don't bother me */
		
	mp = hw_lock_phys_vir(pmap->space, vaddr);	/* Lock the physical entry for this mapping */

	if(!mp) {									/* Did we find one? */
		splx(s);								/* Restore the interrupt level */
		debugLog2(10, 0, 0);						/* end mapping_pmap */
		return;									/* Didn't find any... */
	}
	if((unsigned int)mp & 1) {					/* Did we timeout? */
		panic("mapping_protect: timeout locking physical entry\n");	/* Yeah, scream about it! */
		splx(s);								/* Restore the interrupt level */
		return;									/* Bad hair day... */
	}
		
	hw_prot_virt(mp, ppc_prot(prot));			/* Go set the protection on this virtual mapping */

	mpv = hw_cpv(mp);							/* Get virtual address of mapping */
	if(mpv->physent) {							/* If there is a physical page, */
		hw_unlock_bit((unsigned int *)&mpv->physent->phys_link, PHYS_LOCK);	/* Unlock the physical entry */
	}
	splx(s);									/* Restore interrupt state */
	debugLog2(10, mpv->PTEr, 0);				/* end remap */
	
	return;										/* Leave... */
}

/*
 *		mapping_phys_attr(struct phys_entry *pp, vm_prot_t prot, unsigned int wimg) Sets the default physical page attributes
 *
 *		This routine takes a physical entry and sets the physical attributes.  There can be no mappings
 *		associated with this page when we do it.
 */

void mapping_phys_attr(struct phys_entry *pp, vm_prot_t prot, unsigned int wimg) {	/* Sets the default physical page attributes */

	debugLog2(11, pp->pte1, prot);								/* end remap */

	if(!hw_lock_bit((unsigned int *)&pp->phys_link, PHYS_LOCK, LockTimeOut)) {	/* Lock the physical entry */
		panic("\nmapping_phys_attr: Timeout attempting to lock physical entry at %08X: %08X %08X\n", 
			pp, pp->phys_link, pp->pte1);						/* Complain about timeout */
	}

	hw_phys_attr(pp, ppc_prot(prot), wimg);						/* Go set the default WIMG and protection */

	hw_unlock_bit((unsigned int *)&pp->phys_link, PHYS_LOCK);	/* We're done, unlock the physical entry */
	debugLog2(12, pp->pte1, wimg);								/* end remap */
	
	return;														/* Leave... */
}

/*
 *		void mapping_invall(phys_entry *pp) - invalidates all ptes associated with a page
 *
 *		This routine takes a physical entry and runs through all mappings attached to it and invalidates
 *		any PTEs it finds.
 *
 *		Interruptions must be disabled and the physical entry locked at entry.
 */

void mapping_invall(struct phys_entry *pp) {					/* Clear all PTEs pointing to a physical page */

	hw_inv_all(pp);												/* Go set the change bit of a physical page */
	
	return;														/* Leave... */
}


/*
 *		void mapping_clr_mod(phys_entry *pp) - clears the change bit of a physical page
 *
 *		This routine takes a physical entry and runs through all mappings attached to it and turns
 *		off the change bit.  If there are PTEs associated with the mappings, they will be invalidated before
 *		the change bit is changed.  We don't try to save the PTE.  We won't worry about the LRU calculations
 *		either (I don't think, maybe I'll change my mind later).
 *
 *		Interruptions must be disabled and the physical entry locked at entry.
 */

void mapping_clr_mod(struct phys_entry *pp) {					/* Clears the change bit of a physical page */

	hw_clr_mod(pp);												/* Go clear the change bit of a physical page */
	return;														/* Leave... */
}


/*
 *		void mapping_set_mod(phys_entry *pp) - set the change bit of a physical page
 *
 *		This routine takes a physical entry and runs through all mappings attached to it and turns
 *		on the change bit.  If there are PTEs associated with the mappings, they will be invalidated before
 *		the change bit is changed.  We don't try to save the PTE.  We won't worry about the LRU calculations
 *		either (I don't think, maybe I'll change my mind later).
 *
 *		Interruptions must be disabled and the physical entry locked at entry.
 */

void mapping_set_mod(struct phys_entry *pp) {					/* Sets the change bit of a physical page */

	hw_set_mod(pp);												/* Go set the change bit of a physical page */
	return;														/* Leave... */
}


/*
 *		void mapping_clr_ref(struct phys_entry *pp) - clears the reference bit of a physical page
 *
 *		This routine takes a physical entry and runs through all mappings attached to it and turns
 *		off the reference bit.  If there are PTEs associated with the mappings, they will be invalidated before
 *		the reference bit is changed.  We don't try to save the PTE.  We won't worry about the LRU calculations
 *		either (I don't think, maybe I'll change my mind later).
 *
 *		Interruptions must be disabled at entry.
 */

void mapping_clr_ref(struct phys_entry *pp) {					/* Clears the reference bit of a physical page */

	mapping	*mp;

	debugLog2(13, pp->pte1, 0);									/* end remap */
	if(!hw_lock_bit((unsigned int *)&pp->phys_link, PHYS_LOCK, LockTimeOut)) {	/* Lock the physical entry for this mapping */
		panic("Lock timeout getting lock on physical entry\n");	/* Just die... */
	}
	hw_clr_ref(pp);												/* Go clear the reference bit of a physical page */
	hw_unlock_bit((unsigned int *)&pp->phys_link, PHYS_LOCK);	/* Unlock physical entry */
	debugLog2(14, pp->pte1, 0);									/* end remap */
	return;														/* Leave... */
}


/*
 *		void mapping_set_ref(phys_entry *pp) - set the reference bit of a physical page
 *
 *		This routine takes a physical entry and runs through all mappings attached to it and turns
 *		on the reference bit.  If there are PTEs associated with the mappings, they will be invalidated before
 *		the reference bit is changed.  We don't try to save the PTE.  We won't worry about the LRU calculations
 *		either (I don't think, maybe I'll change my mind later).
 *
 *		Interruptions must be disabled and the physical entry locked at entry.
 */

void mapping_set_ref(struct phys_entry *pp) {					/* Sets the reference bit of a physical page */

	hw_set_ref(pp);												/* Go set the reference bit of a physical page */
	return;														/* Leave... */
}


/*
 *		void mapping_tst_mod(phys_entry *pp) - test the change bit of a physical page
 *
 *		This routine takes a physical entry and runs through all mappings attached to it and tests
 *		the changed bit.  If there are PTEs associated with the mappings, they will be invalidated before
 *		the changed bit is tested.  We don't try to save the PTE.  We won't worry about the LRU calculations
 *		either (I don't think, maybe I'll change my mind later).
 *
 *		Interruptions must be disabled and the physical entry locked at entry.
 */

boolean_t mapping_tst_mod(struct phys_entry *pp) {				/* Tests the change bit of a physical page */

	return(hw_tst_mod(pp));										/* Go test the change bit of a physical page */
}


/*
 *		void mapping_tst_ref(phys_entry *pp) - tests the reference bit of a physical page
 *
 *		This routine takes a physical entry and runs through all mappings attached to it and tests
 *		the reference bit.  If there are PTEs associated with the mappings, they will be invalidated before
 *		the reference bit is changed.  We don't try to save the PTE.  We won't worry about the LRU calculations
 *		either (I don't think, maybe I'll change my mind later).
 *
 *		Interruptions must be disabled and the physical entry locked at entry.
 */

boolean_t mapping_tst_ref(struct phys_entry *pp) {				/* Tests the reference bit of a physical page */

	return(hw_tst_ref(pp));										/* Go test the reference bit of a physical page */
}


/*
 *		void mapping_phys_init(physent, wimg) - fills in the default processor dependent areas of the phys ent
 *
 *		Currently, this sets the default word 1 of the PTE.  The only bits set are the WIMG bits
 */

void mapping_phys_init(struct phys_entry *pp, unsigned int pa, unsigned int wimg) {		/* Initializes hw specific storage attributes */

	pp->pte1 = (pa & -PAGE_SIZE) | ((wimg << 3) & 0x00000078);	/* Set the WIMG and phys addr in the default PTE1 */

	return;														/* Leave... */
}


/*
 *		mapping_adjust(void) - Releases free mapping blocks and/or allocates new ones 
 *
 *		This routine frees any mapping blocks queued to mapCtl.mapcrel. It also checks
 *		the number of free mappings remaining, and if below a threshold, replenishes them.
 *		The list will be replenshed from mapCtl.mapcrel if there are enough.  Otherwise,
 *		a new one is allocated.
 *
 *		This routine allocates and/or memory and must be called from a safe place. 
 *		Currently, vm_pageout_scan is the safest place. We insure that the 
 */

thread_call_t				mapping_adjust_call;
static thread_call_data_t	mapping_adjust_call_data;

void mapping_adjust(void) {										/* Adjust free mappings */

	kern_return_t	retr;
	mappingblok	*mb, *mbn;
	spl_t			s;
	int				allocsize, i;
	extern int vm_page_free_count;

	if(mapCtl.mapcmin <= MAPPERBLOK) {
	        mapCtl.mapcmin = (mem_size / PAGE_SIZE) / 16;

#if DEBUG
		kprintf("mapping_adjust: minimum entries rqrd = %08X\n", mapCtl.mapcmin);
		kprintf("mapping_adjust: free = %08X; in use = %08X; release = %08X\n",
		  mapCtl.mapcfree, mapCtl.mapcinuse, mapCtl.mapcreln);
#endif
	}

	s = splhigh();												/* Don't bother from now on */
	if(!hw_lock_to((hw_lock_t)&mapCtl.mapclock, LockTimeOut)) {	/* Lock the control header */ 
		panic("mapping_adjust - timeout getting control lock (1)\n");	/* Tell all and die */
	}
	
	if (mapping_adjust_call == NULL) {
		thread_call_setup(&mapping_adjust_call_data, 
		                  (thread_call_func_t)mapping_adjust, 
		                  (thread_call_param_t)NULL);
		mapping_adjust_call = &mapping_adjust_call_data;
	}

	while(1) {													/* Keep going until we've got enough */
		
		allocsize = mapCtl.mapcmin - mapCtl.mapcfree;			/* Figure out how much we need */
		if(allocsize < 1) break;								/* Leave if we have all we need */
		
		if((unsigned int)(mbn = mapCtl.mapcrel)) {				/* Can we rescue a free one? */
			mapCtl.mapcrel = mbn->nextblok;						/* Dequeue it */
			mapCtl.mapcreln--;									/* Back off the count */
			allocsize = MAPPERBLOK;								/* Show we allocated one block */			
		}
		else {													/* No free ones, try to get it */
			
			allocsize = (allocsize + MAPPERBLOK - 1) / MAPPERBLOK;	/* Get the number of pages we need */

			hw_lock_unlock((hw_lock_t)&mapCtl.mapclock);		/* Unlock our stuff */
			splx(s);											/* Restore 'rupts */

			for(; allocsize > 0; allocsize >>= 1) {				/* Try allocating in descending halves */ 
				retr = kmem_alloc_wired(mapping_map, (vm_offset_t *)&mbn, PAGE_SIZE * allocsize);	/* Find a virtual address to use */
				if((retr != KERN_SUCCESS) && (allocsize == 1)) {	/* Did we find any memory at all? */
					break;
				}
				if(retr == KERN_SUCCESS) break;					/* We got some memory, bail out... */
			}
			allocsize = allocsize * MAPPERBLOK;					/* Convert pages to number of maps allocated */
			s = splhigh();										/* Don't bother from now on */
			if(!hw_lock_to((hw_lock_t)&mapCtl.mapclock, LockTimeOut)) {	/* Lock the control header */ 
				panic("mapping_adjust - timeout getting control lock (2)\n");	/* Tell all and die */
			}
		}
		if (retr != KERN_SUCCESS)
			break;												/* Fail to alocate, bail out... */
		for(; allocsize > 0; allocsize -= MAPPERBLOK) {			/* Release one block at a time */
			mapping_free_init((vm_offset_t)mbn, 0, 1);			/* Initialize a non-permanent block */
			mbn = (mappingblok *)((unsigned int)mbn + PAGE_SIZE);	/* Point to the next slot */
		}
		if ((mapCtl.mapcinuse + mapCtl.mapcfree + (mapCtl.mapcreln * (MAPPERBLOK + 1))) > mapCtl.mapcmaxalloc)
		        mapCtl.mapcmaxalloc = mapCtl.mapcinuse + mapCtl.mapcfree + (mapCtl.mapcreln * (MAPPERBLOK + 1));
	}

	if(mapCtl.mapcholdoff) {									/* Should we hold off this release? */
		mapCtl.mapcrecurse = 0;									/* We are done now */
		hw_lock_unlock((hw_lock_t)&mapCtl.mapclock);			/* Unlock our stuff */
		splx(s);												/* Restore 'rupts */
		return;													/* Return... */
	}

	mbn = mapCtl.mapcrel;										/* Get first pending release block */
	mapCtl.mapcrel = 0;											/* Dequeue them */
	mapCtl.mapcreln = 0;										/* Set count to 0 */

	hw_lock_unlock((hw_lock_t)&mapCtl.mapclock);				/* Unlock our stuff */
	splx(s);													/* Restore 'rupts */

	while((unsigned int)mbn) {									/* Toss 'em all */
		mb = mbn->nextblok;										/* Get the next */
		kmem_free(mapping_map, (vm_offset_t) mbn, PAGE_SIZE);	/* Release this mapping block */
		mbn = mb;												/* Chain to the next */
	}

	__asm__ volatile("sync");									/* Make sure all is well */
	mapCtl.mapcrecurse = 0;										/* We are done now */
	return;
}

/*
 *		mapping_free(mapping *mp) - release a mapping to the free list 
 *
 *		This routine takes a mapping and adds it to the free list.
 *		If this mapping make the block non-empty, we queue it to the free block list.
 *		NOTE: we might want to queue it to the end to keep quelch the pathalogical
 *		case when we get a mapping and free it repeatedly causing the block to chain and unchain.
 *		If this release fills a block and we are above the threshold, we release the block
 */

void mapping_free(struct mapping *mp) {							/* Release a mapping */

	mappingblok	*mb, *mbn;
	spl_t			s;
	unsigned int	full, mindx;

	mindx = ((unsigned int)mp & (PAGE_SIZE - 1)) >> 5;			/* Get index to mapping */
	mb = (mappingblok *)((unsigned int)mp & -PAGE_SIZE);		/* Point to the mapping block */

	s = splhigh();												/* Don't bother from now on */
	if(!hw_lock_to((hw_lock_t)&mapCtl.mapclock, LockTimeOut)) {	/* Lock the control header */ 
		panic("mapping_free - timeout getting control lock\n");	/* Tell all and die */
	}
	
	full = !(mb->mapblokfree[0] | mb->mapblokfree[1] | mb->mapblokfree[2] | mb->mapblokfree[3]);	/* See if full now */ 
	mb->mapblokfree[mindx >> 5] |= (0x80000000 >> (mindx & 31));	/* Flip on the free bit */
	
	if(full) {													/* If it was full before this: */
		mb->nextblok = mapCtl.mapcnext;							/* Move head of list to us */
		mapCtl.mapcnext = mb;									/* Chain us to the head of the list */
		if(!((unsigned int)mapCtl.mapclast))
			mapCtl.mapclast = mb;
	}

	mapCtl.mapcfree++;											/* Bump free count */
	mapCtl.mapcinuse--;											/* Decriment in use count */
	
	mapCtl.mapcfreec++;											/* Count total calls */

	if(mapCtl.mapcfree > mapCtl.mapcmin) {						/* Should we consider releasing this? */
		if(((mb->mapblokfree[0] | 0x80000000) & mb->mapblokfree[1] & mb->mapblokfree[2] & mb->mapblokfree[3]) 
		   == 0xFFFFFFFF) {										/* See if empty now */ 

			if(mapCtl.mapcnext == mb) {							/* Are we first on the list? */
				mapCtl.mapcnext = mb->nextblok;					/* Unchain us */
				if(!((unsigned int)mapCtl.mapcnext)) mapCtl.mapclast = 0;	/* If last, remove last */
			}
			else {												/* We're not first */
				for(mbn = mapCtl.mapcnext; mbn != 0; mbn = mbn->nextblok) {	/* Search for our block */
					if(mbn->nextblok == mb) break;				/* Is the next one our's? */
				}
				if(!mbn) panic("mapping_free: attempt to release mapping block (%08X) not on list\n", mp);
				mbn->nextblok = mb->nextblok;					/* Dequeue us */
				if(mapCtl.mapclast == mb) mapCtl.mapclast = mbn;	/* If last, make our predecessor last */
			}
			
			if(mb->mapblokflags & mbPerm) {						/* Is this permanently assigned? */
				mb->nextblok = mapCtl.mapcnext;					/* Move chain head to us */
				mapCtl.mapcnext = mb;							/* Chain us to the head */
				if(!((unsigned int)mb->nextblok)) mapCtl.mapclast = mb;	/* If last, make us so */
			}
			else {
				mapCtl.mapcfree -= MAPPERBLOK;					/* Remove the block from the free count */
				mapCtl.mapcreln++;								/* Count on release list */
				mb->nextblok = mapCtl.mapcrel;					/* Move pointer */
				mapCtl.mapcrel = mb;							/* Chain us in front */
			}
		}
	}

	if(mapCtl.mapcreln > MAPFRTHRSH) {							/* Do we have way too many releasable mappings? */
		if(hw_compare_and_store(0, 1, &mapCtl.mapcrecurse)) {	/* Make sure we aren't recursing */
			thread_call_enter(mapping_adjust_call);				/* Go toss some */
		}
	}
	hw_lock_unlock((hw_lock_t)&mapCtl.mapclock);				/* Unlock our stuff */
	splx(s);													/* Restore 'rupts */

	return;														/* Bye, dude... */
}


/*
 *		mapping_alloc(void) - obtain a mapping from the free list 
 *
 *		This routine takes a mapping off of the free list and returns it's address.
 *
 *		We do this by finding a free entry in the first block and allocating it.
 *		If this allocation empties the block, we remove it from the free list.
 *		If this allocation drops the total number of free entries below a threshold,
 *		we allocate a new block.
 *
 */

mapping *mapping_alloc(void) {									/* Obtain a mapping */

	register mapping *mp;
	mappingblok	*mb, *mbn;
	spl_t			s;
	int				mindx;
	kern_return_t	retr;

	s = splhigh();												/* Don't bother from now on */
	if(!hw_lock_to((hw_lock_t)&mapCtl.mapclock, LockTimeOut)) {	/* Lock the control header */ 
		panic("mapping_alloc - timeout getting control lock\n");	/* Tell all and die */
	}

	if(!(mb = mapCtl.mapcnext)) {								/* Get the first block entry */
		unsigned int			i;
		struct mappingflush		mappingflush;
		PCA						*pca_min, *pca_max;
		PCA						*pca_base;

		pca_min = (PCA *)(hash_table_base+hash_table_size);
		pca_max = (PCA *)(hash_table_base+hash_table_size+hash_table_size);

		while (mapCtl.mapcfree <= (MAPPERBLOK*2)) {
			mapCtl.mapcflush.mappingcnt = 0;
			pca_base = mapCtl.mapcflush.pcaptr;
			do {
				hw_select_mappings(&mapCtl.mapcflush);
				mapCtl.mapcflush.pcaptr++;
				if (mapCtl.mapcflush.pcaptr >= pca_max)
					mapCtl.mapcflush.pcaptr = pca_min;
			} while ((mapCtl.mapcflush.mappingcnt == 0) && (mapCtl.mapcflush.pcaptr != pca_base));

			if ((mapCtl.mapcflush.mappingcnt == 0) && (mapCtl.mapcflush.pcaptr == pca_base)) {
				hw_lock_unlock((hw_lock_t)&mapCtl.mapclock);
				panic("mapping_alloc - all mappings are wired\n");
			}
			mappingflush = mapCtl.mapcflush;
			hw_lock_unlock((hw_lock_t)&mapCtl.mapclock);
			splx(s);
			for (i=0;i<mappingflush.mappingcnt;i++)
				mapping_remove(mappingflush.mapping[i].pmap, 
				               mappingflush.mapping[i].offset);
			s = splhigh();
			if(!hw_lock_to((hw_lock_t)&mapCtl.mapclock, LockTimeOut)) {
				panic("mapping_alloc - timeout getting control lock\n");
			}
		}
		mb = mapCtl.mapcnext;
	}
	
	if(!(mindx = mapalc(mb))) {									/* Allocate a slot */
		panic("mapping_alloc - empty mapping block detected at %08X\n", mb);	/* Not allowed to find none */
	}
	
	if(mindx < 0) {												/* Did we just take the last one */
		mindx = -mindx;											/* Make positive */
		mapCtl.mapcnext = mb->nextblok;							/* Remove us from the list */
		if(!((unsigned int)mapCtl.mapcnext)) mapCtl.mapclast = 0;	/* Removed the last one */
	}
	
	mapCtl.mapcfree--;											/* Decrement free count */
	mapCtl.mapcinuse++;											/* Bump in use count */
	
	mapCtl.mapcallocc++;										/* Count total calls */

/*
 *	Note: in the following code, we will attempt to rescue blocks only one at a time.
 *	Eventually, after a few more mapping_alloc calls, we will catch up.  If there are none
 *	rescueable, we will kick the misc scan who will allocate some for us.  We only do this
 *	if we haven't already done it.
 *	For early boot, we are set up to only rescue one block at a time.  This is because we prime
 *	the release list with as much as we need until threads start.
 */
	if(mapCtl.mapcfree < mapCtl.mapcmin) {						/* See if we need to replenish */
		if(mbn = mapCtl.mapcrel) {								/* Try to rescue a block from impending doom */
			mapCtl.mapcrel = mbn->nextblok;						/* Pop the queue */
			mapCtl.mapcreln--;									/* Back off the count */
			mapping_free_init((vm_offset_t)mbn, 0, 1);			/* Initialize a non-permanent block */
		}
		else {													/* We need to replenish */
		        if (mapCtl.mapcfree < (mapCtl.mapcmin / 4)) {
			        if(hw_compare_and_store(0, 1, &mapCtl.mapcrecurse)) {	/* Make sure we aren't recursing */
				        thread_call_enter(mapping_adjust_call);			/* Go allocate some more */
				}
			}
		}
	}

	hw_lock_unlock((hw_lock_t)&mapCtl.mapclock);				/* Unlock our stuff */
	splx(s);													/* Restore 'rupts */
	
	mp = &((mapping *)mb)[mindx];								/* Point to the allocated mapping */
    __asm__ volatile("dcbz 0,%0" : : "r" (mp));					/* Clean it up */
	return mp;													/* Send it back... */
}


void
consider_mapping_adjust()
{
	spl_t			s;

	s = splhigh();												/* Don't bother from now on */
	if(!hw_lock_to((hw_lock_t)&mapCtl.mapclock, LockTimeOut)) {	/* Lock the control header */ 
		panic("mapping_alloc - timeout getting control lock\n");	/* Tell all and die */
	}

        if (mapCtl.mapcfree < (mapCtl.mapcmin / 4)) {
	        if(hw_compare_and_store(0, 1, &mapCtl.mapcrecurse)) {	/* Make sure we aren't recursing */
		        thread_call_enter(mapping_adjust_call);			/* Go allocate some more */
		}
	}

	hw_lock_unlock((hw_lock_t)&mapCtl.mapclock);				/* Unlock our stuff */
	splx(s);													/* Restore 'rupts */
	
}



/*
 *		void mapping_free_init(mb, perm) - Adds a block of storage to the free mapping list
 *
 *		The mapping block is a page size area on a page boundary.  It contains 1 header and 127
 *		mappings.  This call adds and initializes a block for use.
 *	
 *		The header contains a chain link, bit maps, a virtual to real translation mask, and
 *		some statistics. Bit maps map each slot on the page (bit 0 is not used because it 
 *		corresponds to the header).  The translation mask is the XOR of the virtual and real
 *		addresses (needless to say, the block must be wired).
 *
 *		We handle these mappings the same way as saveareas: the block is only on the chain so
 *		long as there are free entries in it.
 *
 *		Empty blocks are garbage collected when there are at least mapCtl.mapcmin pages worth of free 
 *		mappings. Blocks marked PERM won't ever be released.
 *
 *		If perm is negative, the mapping is initialized, but immediately queued to the mapCtl.mapcrel
 *		list.  We do this only at start up time. This is done because we only allocate blocks 
 *		in the pageout scan and it doesn't start up until after we run out of the initial mappings.
 *		Therefore, we need to preallocate a bunch, but we don't want them to be permanent.  If we put
 *		them on the release queue, the allocate routine will rescue them.  Then when the
 *		pageout scan starts, all extra ones will be released.
 *
 */


void mapping_free_init(vm_offset_t mbl, int perm, boolean_t locked) {		
															/* Set's start and end of a block of mappings
															   perm indicates if the block can be released 
															   or goes straight to the release queue .
															   locked indicates if the lock is held already */
														   
	mappingblok	*mb;
	spl_t		s;
	int			i;
	unsigned int	raddr;

	mb = (mappingblok *)mbl;								/* Start of area */
	
	
	if(perm >= 0) {											/* See if we need to initialize the block */
		if(perm) {
			raddr = (unsigned int)mbl;						/* Perm means V=R */
			mb->mapblokflags = mbPerm;						/* Set perm */
		}
		else {
			raddr = kvtophys(mbl);							/* Get real address */
			mb->mapblokflags = 0;							/* Set not perm */
		}
		
		mb->mapblokvrswap = raddr ^ (unsigned int)mbl;		/* Form translation mask */
		
		mb->mapblokfree[0] = 0x7FFFFFFF;					/* Set first 32 (minus 1) free */
		mb->mapblokfree[1] = 0xFFFFFFFF;					/* Set next 32 free */
		mb->mapblokfree[2] = 0xFFFFFFFF;					/* Set next 32 free */
		mb->mapblokfree[3] = 0xFFFFFFFF;					/* Set next 32 free */
	}
	
	s = splhigh();											/* Don't bother from now on */
	if(!locked) {											/* Do we need the lock? */
		if(!hw_lock_to((hw_lock_t)&mapCtl.mapclock, LockTimeOut)) {		/* Lock the control header */ 
			panic("mapping_free_init - timeout getting control lock\n");	/* Tell all and die */
		}
	}
	
	if(perm < 0) {											/* Direct to release queue? */
		mb->nextblok = mapCtl.mapcrel;						/* Move forward pointer */
		mapCtl.mapcrel = mb;								/* Queue us on in */
		mapCtl.mapcreln++;									/* Count the free block */
	}
	else {													/* Add to the free list */
		
		mb->nextblok = 0;									/* We always add to the end */
		mapCtl.mapcfree += MAPPERBLOK;						/* Bump count */
		
		if(!((unsigned int)mapCtl.mapcnext)) {				/* First entry on list? */
			mapCtl.mapcnext = mapCtl.mapclast = mb;			/* Chain to us */
		}
		else {												/* We are not the first */
			mapCtl.mapclast->nextblok = mb;					/* Point the last to us */
			mapCtl.mapclast = mb;							/* We are now last */
		}
	}
		
	if(!locked) {											/* Do we need to unlock? */
		hw_lock_unlock((hw_lock_t)&mapCtl.mapclock);		/* Unlock our stuff */
	}
		splx(s);											/* Restore 'rupts */
	return;													/* All done, leave... */
}


/*
 *		void mapping_prealloc(unsigned int) - Preallocates mapppings for large request
 *	
 *		No locks can be held, because we allocate memory here.
 *		This routine needs a corresponding mapping_relpre call to remove the
 *		hold off flag so that the adjust routine will free the extra mapping
 *		blocks on the release list.  I don't like this, but I don't know
 *		how else to do this for now...
 *
 */

void mapping_prealloc(unsigned int size) {					/* Preallocates mapppings for large request */

	int	nmapb, i;
	kern_return_t	retr;
	mappingblok	*mbn;
	spl_t		s;

	s = splhigh();											/* Don't bother from now on */
	if(!hw_lock_to((hw_lock_t)&mapCtl.mapclock, LockTimeOut)) {		/* Lock the control header */ 
		panic("mapping_prealloc - timeout getting control lock\n");	/* Tell all and die */
	}

	nmapb = (size >> 12) + mapCtl.mapcmin;					/* Get number of entries needed for this and the minimum */
	
	mapCtl.mapcholdoff++;									/* Bump the hold off count */
	
	if((nmapb = (nmapb - mapCtl.mapcfree)) <= 0) {			/* Do we already have enough? */
		hw_lock_unlock((hw_lock_t)&mapCtl.mapclock);		/* Unlock our stuff */
		splx(s);											/* Restore 'rupts */
		return;
	}
	if (!hw_compare_and_store(0, 1, &mapCtl.mapcrecurse)) {	                /* Make sure we aren't recursing */
		hw_lock_unlock((hw_lock_t)&mapCtl.mapclock);			/* Unlock our stuff */
		splx(s);							/* Restore 'rupts */
		return;
	}
	nmapb = (nmapb + MAPPERBLOK - 1) / MAPPERBLOK;			/* Get number of blocks to get */
	
	hw_lock_unlock((hw_lock_t)&mapCtl.mapclock);			/* Unlock our stuff */
	splx(s);												/* Restore 'rupts */
	
	for(i = 0; i < nmapb; i++) {							/* Allocate 'em all */
		retr = kmem_alloc_wired(mapping_map, (vm_offset_t *)&mbn, PAGE_SIZE);	/* Find a virtual address to use */
		if(retr != KERN_SUCCESS) {							/* Did we get some memory? */
			panic("Whoops...  Not a bit of wired memory left for anyone\n");
		}
		mapping_free_init((vm_offset_t)mbn, -1, 0);			/* Initialize on to the release queue */
	}
	if ((mapCtl.mapcinuse + mapCtl.mapcfree + (mapCtl.mapcreln * (MAPPERBLOK + 1))) > mapCtl.mapcmaxalloc)
	        mapCtl.mapcmaxalloc = mapCtl.mapcinuse + mapCtl.mapcfree + (mapCtl.mapcreln * (MAPPERBLOK + 1));

	mapCtl.mapcrecurse = 0;										/* We are done now */
}

/*
 *		void mapping_relpre(void) - Releases preallocation release hold off
 *	
 *		This routine removes the
 *		hold off flag so that the adjust routine will free the extra mapping
 *		blocks on the release list.  I don't like this, but I don't know
 *		how else to do this for now...
 *
 */

void mapping_relpre(void) {									/* Releases release hold off */

	spl_t		s;

	s = splhigh();											/* Don't bother from now on */
	if(!hw_lock_to((hw_lock_t)&mapCtl.mapclock, LockTimeOut)) {		/* Lock the control header */ 
		panic("mapping_relpre - timeout getting control lock\n");	/* Tell all and die */
	}
	if(--mapCtl.mapcholdoff < 0) {							/* Back down the hold off count */
		panic("mapping_relpre: hold-off count went negative\n");
	}

	hw_lock_unlock((hw_lock_t)&mapCtl.mapclock);			/* Unlock our stuff */
	splx(s);												/* Restore 'rupts */
}

/*
 *		void mapping_free_prime(void) - Primes the mapping block release list
 *
 *		See mapping_free_init.
 *		No locks can be held, because we allocate memory here.
 *		One processor running only.
 *
 */

void mapping_free_prime(void) {									/* Primes the mapping block release list */

	int	nmapb, i;
	kern_return_t	retr;
	mappingblok	*mbn;
	vm_offset_t     mapping_min;
	
	retr = kmem_suballoc(kernel_map, &mapping_min, MAPPING_MAP_SIZE,
			     FALSE, TRUE, &mapping_map);

	if (retr != KERN_SUCCESS)
	        panic("mapping_free_prime: kmem_suballoc failed");


	nmapb = (mapCtl.mapcfree + mapCtl.mapcinuse + MAPPERBLOK - 1) / MAPPERBLOK;	/* Get permanent allocation */
	nmapb = nmapb * 4;											/* Get 4 times our initial allocation */

#if DEBUG
	kprintf("mapping_free_prime: free = %08X; in use = %08X; priming = %08X\n", 
	  mapCtl.mapcfree, mapCtl.mapcinuse, nmapb);
#endif
	
	for(i = 0; i < nmapb; i++) {								/* Allocate 'em all */
		retr = kmem_alloc_wired(mapping_map, (vm_offset_t *)&mbn, PAGE_SIZE);	/* Find a virtual address to use */
		if(retr != KERN_SUCCESS) {								/* Did we get some memory? */
			panic("Whoops...  Not a bit of wired memory left for anyone\n");
		}
		mapping_free_init((vm_offset_t)mbn, -1, 0);				/* Initialize onto release queue */
	}
	if ((mapCtl.mapcinuse + mapCtl.mapcfree + (mapCtl.mapcreln * (MAPPERBLOK + 1))) > mapCtl.mapcmaxalloc)
	        mapCtl.mapcmaxalloc = mapCtl.mapcinuse + mapCtl.mapcfree + (mapCtl.mapcreln * (MAPPERBLOK + 1));
}



mapping_fake_zone_info(int *count, vm_size_t *cur_size, vm_size_t *max_size, vm_size_t *elem_size,
  		       vm_size_t *alloc_size, int *collectable, int *exhaustable)
{
        *count      = mapCtl.mapcinuse;
	*cur_size   = ((PAGE_SIZE / (MAPPERBLOK + 1)) * (mapCtl.mapcinuse + mapCtl.mapcfree)) + (PAGE_SIZE * mapCtl.mapcreln);
	*max_size   = (PAGE_SIZE / (MAPPERBLOK + 1)) * mapCtl.mapcmaxalloc;
	*elem_size  = (PAGE_SIZE / (MAPPERBLOK + 1));
	*alloc_size = PAGE_SIZE;

	*collectable = 1;
	*exhaustable = 0;
}


/*
 *		vm_offset_t	mapping_p2v(pmap_t pmap, phys_entry *pp) - Finds first virtual mapping of a physical page in a space
 *
 *		Gets a lock on the physical entry.  Then it searches the list of attached mappings for one with
 *		the same space.  If it finds it, it returns the virtual address.
 *
 *		Note that this will fail if the pmap has nested pmaps in it.  Fact is, I'll check
 *		for it and fail it myself...
 */

vm_offset_t	mapping_p2v(pmap_t pmap, struct phys_entry *pp) {		/* Finds first virtual mapping of a physical page in a space */

	spl_t				s;
	register mapping	*mp, *mpv;
	vm_offset_t			va;

	if(pmap->vflags & pmapAltSeg) return 0;					/* If there are nested pmaps, fail immediately */

	s = splhigh();
	if(!hw_lock_bit((unsigned int *)&pp->phys_link, PHYS_LOCK, LockTimeOut)) {	/* Try to get the lock on the physical entry */
		splx(s);											/* Restore 'rupts */
		panic("mapping_p2v: timeout getting lock on physent\n");			/* Arrrgghhhh! */
		return(0);											/* Should die before here */
	}
	
	va = 0;													/* Assume failure */
	
	for(mpv = hw_cpv(pp->phys_link); mpv; mpv = hw_cpv(mpv->next)) {	/* Scan 'em all */
		
		if(!(((mpv->PTEv >> 7) & 0x000FFFFF) == pmap->space)) continue;	/* Skip all the rest if this is not the right space... */ 
		
		va = ((((unsigned int)mpv->PTEhash & -64) << 6) ^ (pmap->space  << 12)) & 0x003FF000;	/* Backward hash to the wrapped VADDR */
		va = va | ((mpv->PTEv << 1) & 0xF0000000);			/* Move in the segment number */
		va = va | ((mpv->PTEv << 22) & 0x0FC00000);			/* Add in the API for the top of the address */
		break;												/* We're done now, pass virtual address back */
	}
	
	hw_unlock_bit((unsigned int *)&pp->phys_link, PHYS_LOCK);				/* Unlock the physical entry */
	splx(s);												/* Restore 'rupts */
	return(va);												/* Return the result or 0... */
}

/*
 *	kvtophys(addr)
 *
 *	Convert a kernel virtual address to a physical address
 */
vm_offset_t kvtophys(vm_offset_t va) {

	register mapping		*mp, *mpv;
	register blokmap		*bmp;
	register vm_offset_t 	pa;
	spl_t				s;
	
	s=splhigh();											/* Don't bother from now on */
	mp = hw_lock_phys_vir(PPC_SID_KERNEL, va);				/* Find mapping and lock the physical entry for this mapping */

	if((unsigned int)mp&1) {								/* Did the lock on the phys entry time out? */
		splx(s);											/* Restore 'rupts */
		panic("kvtophys: timeout obtaining lock on physical entry (vaddr=%08X)\n", va);	/* Scream bloody murder! */
		return 0;
	}

	if(!mp) {												/* If it was not a normal page */
		pa = hw_cvp_blk(kernel_pmap, va);					/* Try to convert odd-sized page (returns 0 if not found) */
		splx(s);											/* Restore 'rupts */
		return pa;											/* Return physical address */
	}

	mpv = hw_cpv(mp);										/* Convert to virtual addressing */
	
	if(!mpv->physent) {										/* Was there a physical entry? */
		pa = (vm_offset_t)((mpv->PTEr & -PAGE_SIZE) | ((unsigned int)va & (PAGE_SIZE-1)));	/* Get physical address from physent */
	}
	else {
		pa = (vm_offset_t)((mpv->physent->pte1 & -PAGE_SIZE) | ((unsigned int)va & (PAGE_SIZE-1)));	/* Get physical address from physent */
		hw_unlock_bit((unsigned int *)&mpv->physent->phys_link, PHYS_LOCK);	/* Unlock the physical entry */
	}
	
	splx(s);												/* Restore 'rupts */
	return pa;												/* Return the physical address... */
}

/*
 *	phystokv(addr)
 *
 *	Convert a physical address to a kernel virtual address if
 *	there is a mapping, otherwise return NULL
 */

vm_offset_t phystokv(vm_offset_t pa) {

	struct phys_entry	*pp;
	vm_offset_t			va;

	pp = pmap_find_physentry(pa);							/* Find the physical entry */
	if (PHYS_NULL == pp) {
		return (vm_offset_t)NULL;							/* If none, return null */
	}
	if(!(va=mapping_p2v(kernel_pmap, pp))) {
		return 0;											/* Can't find it, return 0... */
	}
	return (va | (pa & (PAGE_SIZE-1)));						/* Build and return VADDR... */

}

/*
 *		void ignore_zero_fault(boolean_t) - Sets up to ignore or honor any fault on 
 *		page 0 access for the current thread.
 *
 *		If parameter is TRUE, faults are ignored
 *		If parameter is FALSE, faults are honored
 *
 */

void ignore_zero_fault(boolean_t type) {				/* Sets up to ignore or honor any fault on page 0 access for the current thread */

	if(type) current_act()->mact.specFlags |= ignoreZeroFault;	/* Ignore faults on page 0 */
	else     current_act()->mact.specFlags &= ~ignoreZeroFault;	/* Honor faults on page 0 */
	
	return;												/* Return the result or 0... */
}


/*
 *	Allocates a range of virtual addresses in a map as optimally as
 *	possible for block mapping.  The start address is aligned such
 *	that a minimum number of power-of-two sized/aligned blocks is
 *	required to cover the entire range. 
 *
 *	We also use a mask of valid block sizes to determine optimality.
 *
 *	Note that the passed in pa is not actually mapped to the selected va,
 *	rather, it is used to figure the optimal boundary.  The actual 
 *	V to R mapping is done externally.
 *
 *	This function will return KERN_INVALID_ADDRESS if an optimal address 
 *	can not be found.  It is not necessarily a fatal error, the caller may still be
 *	still be able to do a non-optimal assignment.
 */

kern_return_t vm_map_block(vm_map_t map, vm_offset_t *va, vm_offset_t *bnd, vm_offset_t pa, 
	vm_size_t size, vm_prot_t prot) {

	vm_map_entry_t	entry, next, tmp_entry, new_entry;
	vm_offset_t		start, end, algnpa, endadr, strtadr, curradr;
	vm_offset_t		boundary;
	
	unsigned int	maxsize, minsize, leading, trailing;
	
	assert(page_aligned(pa));
	assert(page_aligned(size));

	if (map == VM_MAP_NULL) return(KERN_INVALID_ARGUMENT);	/* Dude, like we need a target map */
	
	minsize = blokValid ^ (blokValid & (blokValid - 1));	/* Set minimum subblock size */
	maxsize = 0x80000000 >> cntlzw(blokValid);	/* Set maximum subblock size */
	
	boundary = 0x80000000 >> cntlzw(size);		/* Get optimal boundary */
	if(boundary > maxsize) boundary = maxsize;	/* Pin this at maximum supported hardware size */
	
	vm_map_lock(map);							/* No touchee no mapee */

 	for(; boundary > minsize; boundary >>= 1) {	/* Try all optimizations until we find one */
		if(!(boundary & blokValid)) continue;	/* Skip unavailable block sizes */
		algnpa = (pa + boundary - 1) & -boundary;	/* Round physical up */
		leading = algnpa - pa;					/* Get leading size */
		
		curradr = 0;							/* Start low */
		
		while(1) {								/* Try all possible values for this opt level */

			curradr = curradr + boundary;		/* Get the next optimal address */
			strtadr = curradr - leading;		/* Calculate start of optimal range */
			endadr = strtadr + size;			/* And now the end */
			
			if((curradr < boundary) ||			/* Did address wrap here? */
				(strtadr > curradr) ||			/* How about this way? */
				(endadr < strtadr)) break;		/* We wrapped, try next lower optimization... */
		
			if(strtadr < map->min_offset) continue;	/* Jump to the next higher slot... */
			if(endadr > map->max_offset) break;	/* No room right now... */
			
			if(vm_map_lookup_entry(map, strtadr, &entry)) continue;	/* Find slot, continue if allocated... */
		
			next = entry->vme_next;				/* Get the next entry */
			if((next == vm_map_to_entry(map)) ||	/* Are we the last entry? */
				(next->vme_start >= endadr)) {	/* or do we end before the next entry? */
			
				new_entry = vm_map_entry_insert(map, entry, strtadr, endadr, /* Yes, carve out our entry */
					VM_OBJECT_NULL,
					0,							/* Offset into object of 0 */
					FALSE, 						/* No copy needed */
					FALSE, 						/* Not shared */
					FALSE,						/* Not in transition */
					prot, 						/* Set the protection to requested */
					prot,						/* We can't change protection */
					VM_BEHAVIOR_DEFAULT, 		/* Use default behavior, but makes no never mind,
												   'cause we don't page in this area */
					VM_INHERIT_DEFAULT, 		/* Default inheritance */
					0);							/* Nothing is wired */
			
				vm_map_unlock(map);				/* Let the world see it all */
				*va = strtadr;					/* Tell everyone */
				*bnd = boundary;				/* Say what boundary we are aligned to */
				return(KERN_SUCCESS);			/* Leave, all is right with the world... */
			}
		}		
	}	

	vm_map_unlock(map);							/* Couldn't find a slot */
	return(KERN_INVALID_ADDRESS);
}

/* 
 *		Copies data from a physical page to a virtual page.  This is used to 
 *		move data from the kernel to user state.
 *
 *		Note that it is invalid to have a source that spans a page boundry.
 *		This can block.
 *		We don't check protection either.
 *		And we don't handle a block mapped sink address either.
 *
 */
 
kern_return_t copyp2v(vm_offset_t source, vm_offset_t sink, unsigned int size) {
 
	vm_map_t map;
	kern_return_t ret;
	unsigned int spaceid;
	int left, csize;
	vm_offset_t pa;
	register mapping *mpv, *mp;
	spl_t s;

	if((size == 0) || ((source ^ (source + size - 1)) & -PAGE_SIZE)) return KERN_FAILURE;	/* We don't allow a source page crosser */
	map = current_act()->map;						/* Get the current map */

	while(size) {
		s=splhigh();								/* Don't bother me */
	
		spaceid = map->pmap->pmapSegs[(unsigned int)sink >> 28];	/* Get space ID. Don't bother to clean top bits */

		mp = hw_lock_phys_vir(spaceid, sink);		/* Lock the physical entry for the sink */
		if(!mp) {									/* Was it there? */
			splx(s);								/* Restore the interrupt level */
			ret = vm_fault(map, trunc_page(sink), VM_PROT_READ | VM_PROT_WRITE, FALSE, NULL, 0);	/* Didn't find it, try to fault it in... */
			if (ret == KERN_SUCCESS) continue;		/* We got it in, try again to find it... */

			return KERN_FAILURE;					/* Didn't find any, return no good... */
		}
		if((unsigned int)mp&1) {					/* Did we timeout? */
			panic("dumpaddr: timeout locking physical entry for virtual address (%08X)\n", sink);	/* Yeah, scream about it! */
			splx(s);								/* Restore the interrupt level */
			return KERN_FAILURE;					/* Bad hair day, return FALSE... */
		}

		mpv = hw_cpv(mp);							/* Convert mapping block to virtual */

		if(mpv->PTEr & 1) {							/* Are we write protected? yes, could indicate COW */
			hw_unlock_bit((unsigned int *)&mpv->physent->phys_link, PHYS_LOCK);	/* Unlock the sink */
			splx(s);								/* Restore the interrupt level */
			ret = vm_fault(map, trunc_page(sink), VM_PROT_READ | VM_PROT_WRITE, FALSE, NULL, 0);	/* check for a COW area */
			if (ret == KERN_SUCCESS) continue;		/* We got it in, try again to find it... */
			return KERN_FAILURE;					/* Didn't find any, return no good... */
		}
	 	left = PAGE_SIZE - (sink & PAGE_MASK);		/* Get amount left on sink page */

		csize = size < left ? size : left;              /* Set amount to copy this pass */

		pa = (vm_offset_t)((mpv->physent->pte1 & ~PAGE_MASK) | ((unsigned int)sink & PAGE_MASK));	/* Get physical address of sink */

	 	bcopy_physvir((char *)source, (char *)pa, csize);	/* Do a physical copy, virtually */

		hw_set_mod(mpv->physent);					/* Go set the change of the sink */

		hw_unlock_bit((unsigned int *)&mpv->physent->phys_link, PHYS_LOCK);	/* Unlock the sink */
	 	splx(s);									/* Open up for interrupts */

	 	sink += csize;								/* Move up to start of next page */
	 	source += csize;							/* Move up source */
	 	size -= csize;								/* Set amount for next pass */
	}
	return KERN_SUCCESS;
}


/*
 * copy 'size' bytes from physical to physical address
 * the caller must validate the physical ranges 
 *
 * if flush_action == 0, no cache flush necessary
 * if flush_action == 1, flush the source
 * if flush_action == 2, flush the dest
 * if flush_action == 3, flush both source and dest
 */

kern_return_t copyp2p(vm_offset_t source, vm_offset_t dest, unsigned int size, unsigned int flush_action) {

        switch(flush_action) {
	case 1:
	        flush_dcache(source, size, 1);
		break;
	case 2:
	        flush_dcache(dest, size, 1);
		break;
	case 3:
	        flush_dcache(source, size, 1);
	        flush_dcache(dest, size, 1);
		break;

	}
        bcopy_phys((char *)source, (char *)dest, size);	/* Do a physical copy */

        switch(flush_action) {
	case 1:
	        flush_dcache(source, size, 1);
		break;
	case 2:
	        flush_dcache(dest, size, 1);
		break;
	case 3:
	        flush_dcache(source, size, 1);
	        flush_dcache(dest, size, 1);
		break;

	}
}



#if DEBUG
/*
 *		Dumps out the mapping stuff associated with a virtual address
 */
void dumpaddr(space_t space, vm_offset_t va) {

	mapping		*mp, *mpv;
	vm_offset_t	pa;
	spl_t 		s;

	s=splhigh();											/* Don't bother me */

	mp = hw_lock_phys_vir(space, va);						/* Lock the physical entry for this mapping */
	if(!mp) {												/* Did we find one? */
		splx(s);											/* Restore the interrupt level */
		printf("dumpaddr: virtual address (%08X) not mapped\n", va);	
		return;												/* Didn't find any, return FALSE... */
	}
	if((unsigned int)mp&1) {								/* Did we timeout? */
		panic("dumpaddr: timeout locking physical entry for virtual address (%08X)\n", va);	/* Yeah, scream about it! */
		splx(s);											/* Restore the interrupt level */
		return;												/* Bad hair day, return FALSE... */
	}
	printf("dumpaddr: space=%08X; vaddr=%08X\n", space, va);	/* Say what address were dumping */
	mpv = hw_cpv(mp);										/* Get virtual address of mapping */
	dumpmapping(mpv);
	if(mpv->physent) {
		dumppca(mpv);
		hw_unlock_bit((unsigned int *)&mpv->physent->phys_link, PHYS_LOCK);	/* Unlock physical entry associated with mapping */
	}
	splx(s);												/* Was there something you needed? */
	return;													/* Tell them we did it */
}



/*
 *		Prints out a mapping control block
 *
 */
 
void dumpmapping(struct mapping *mp) { 						/* Dump out a mapping */

	printf("Dump of mapping block: %08X\n", mp);			/* Header */
	printf("                 next: %08X\n", mp->next);                 
	printf("             hashnext: %08X\n", mp->hashnext);                 
	printf("              PTEhash: %08X\n", mp->PTEhash);                 
	printf("               PTEent: %08X\n", mp->PTEent);                 
	printf("              physent: %08X\n", mp->physent);                 
	printf("                 PTEv: %08X\n", mp->PTEv);                 
	printf("                 PTEr: %08X\n", mp->PTEr);                 
	printf("                 pmap: %08X\n", mp->pmap);
	
	if(mp->physent) {									/* Print physent if it exists */
		printf("Associated physical entry: %08X %08X\n", mp->physent->phys_link, mp->physent->pte1);
	}
	else {
		printf("Associated physical entry: none\n");
	}
	
	dumppca(mp);										/* Dump out the PCA information */
	
	return;
}

/*
 *		Prints out a PTEG control area
 *
 */
 
void dumppca(struct mapping *mp) { 						/* PCA */

	PCA				*pca;
	unsigned int	*pteg;
	
	pca = (PCA *)((unsigned int)mp->PTEhash&-64);		/* Back up to the start of the PCA */
	pteg=(unsigned int *)((unsigned int)pca-(((hash_table_base&0x0000FFFF)+1)<<16));
	printf(" Dump of PCA: %08X\n", pca);		/* Header */
	printf("     PCAlock: %08X\n", pca->PCAlock);                 
	printf("     PCAallo: %08X\n", pca->flgs.PCAallo);                 
	printf("     PCAhash: %08X %08X %08X %08X\n", pca->PCAhash[0], pca->PCAhash[1], pca->PCAhash[2], pca->PCAhash[3]);                 
	printf("              %08X %08X %08X %08X\n", pca->PCAhash[4], pca->PCAhash[5], pca->PCAhash[6], pca->PCAhash[7]);                 
	printf("Dump of PTEG: %08X\n", pteg);		/* Header */
	printf("              %08X %08X %08X %08X\n", pteg[0], pteg[1], pteg[2], pteg[3]);                 
	printf("              %08X %08X %08X %08X\n", pteg[4], pteg[5], pteg[6], pteg[7]);                 
	printf("              %08X %08X %08X %08X\n", pteg[8], pteg[9], pteg[10], pteg[11]);                 
	printf("              %08X %08X %08X %08X\n", pteg[12], pteg[13], pteg[14], pteg[15]);                 
	return;
}

/*
 *		Dumps starting with a physical entry
 */
 
void dumpphys(struct phys_entry *pp) { 						/* Dump from physent */

	mapping			*mp;
	PCA				*pca;
	unsigned int	*pteg;

	printf("Dump from physical entry %08X: %08X %08X\n", pp, pp->phys_link, pp->pte1);
	mp = hw_cpv(pp->phys_link);
	while(mp) {
		dumpmapping(mp);
		dumppca(mp);
		mp = hw_cpv(mp->next);
	}
	
	return;
}

#endif


kern_return_t bmapvideo(vm_offset_t *info);
kern_return_t bmapvideo(vm_offset_t *info) {

	extern struct vc_info vinfo;
	
	(void)copyout((char *)&vinfo, (char *)info, sizeof(struct vc_info));	/* Copy out the video info */
	return KERN_SUCCESS;
}

kern_return_t bmapmap(vm_offset_t va, vm_offset_t pa, vm_size_t size, vm_prot_t prot, int attr);
kern_return_t bmapmap(vm_offset_t va, vm_offset_t pa, vm_size_t size, vm_prot_t prot, int attr) {
	
	pmap_map_block(current_act()->task->map->pmap, va, pa, size, prot, attr, 0);	/* Map it in */
	return KERN_SUCCESS;
}

kern_return_t bmapmapr(vm_offset_t va);
kern_return_t bmapmapr(vm_offset_t va) {
	
	mapping_remove(current_act()->task->map->pmap, va);	/* Remove map */
	return KERN_SUCCESS;
}

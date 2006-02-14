/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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

#include <debug.h>
#include <mach_kgdb.h>
#include <mach_vm_debug.h>
#include <db_machine_commands.h>

#include <mach/mach_types.h>
#include <mach/vm_attributes.h>
#include <mach/vm_param.h>

#include <kern/kern_types.h>
#include <kern/thread.h>
#include <kern/spl.h>
#include <kern/misc_protos.h>

#include <vm/vm_fault.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/pmap.h>

#include <ppc/exception.h>
#include <ppc/misc_protos.h>
#include <ppc/proc_reg.h>
#include <ppc/pmap.h>
#include <ppc/mem.h>
#include <ppc/new_screen.h>
#include <ppc/Firmware.h>
#include <ppc/mappings.h>
#include <ddb/db_output.h>

#include <console/video_console.h>		/* (TEST/DEBUG) */

#define PERFTIMES 0

vm_map_t        mapping_map = VM_MAP_NULL;

unsigned int	incrVSID = 0;						/* VSID increment value */
unsigned int	mappingdeb0 = 0;						
unsigned int	mappingdeb1 = 0;
int ppc_max_adrsp;									/* Maximum address spaces */			
				
addr64_t		*mapdebug;							/* (BRINGUP) */
extern unsigned int DebugWork;						/* (BRINGUP) */
						
void mapping_verify(void);
void mapping_phys_unused(ppnum_t pa);

/*
 *  ppc_prot translates Mach's representation of protections to that of the PPC hardware.
 *  For Virtual Machines (VMM), we also provide translation entries where the output is
 *  the same as the input, allowing direct specification of PPC protections. Mach's 
 *	representations are always in the range 0..7, so they always fall into the first
 *	8 table entries; direct translations are placed in the range 8..16, so they fall into
 *  the second half of the table.
 *
 *  ***NOTE*** I've commented out the Mach->PPC translations that would set page-level
 *             no-execute, pending updates to the VM layer that will properly enable its
 *             use.  Bob Abeles 08.02.04
 */
 
//unsigned char ppc_prot[16] = { 4, 7, 6, 6, 3, 3, 2, 2,		/* Mach -> PPC translations */
unsigned char ppc_prot[16] = { 0, 3, 2, 2, 3, 3, 2, 2,		/* Mach -> PPC translations */
                               0, 1, 2, 3, 4, 5, 6, 7 };	/* VMM direct  translations */

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

	unsigned int tmp, maxeff, rwidth;
	
	ppc_max_adrsp = maxAdrSp;									/* Set maximum address spaces */			
	
	maxeff = 32;												/* Assume 32-bit */
	if(PerProcTable[0].ppe_vaddr->pf.Available & pf64Bit) maxeff = 64;	/* Is this a 64-bit machine? */
	
	rwidth = PerProcTable[0].ppe_vaddr->pf.pfMaxVAddr - maxAdrSpb;		/* Reduce address width by width of address space ID */
	if(rwidth > maxeff) rwidth = maxeff;						/* If we still have more virtual than effective, clamp at effective */
	
	vm_max_address = 0xFFFFFFFFFFFFFFFFULL >> (64 - rwidth);		/* Get maximum effective address supported */
	vm_max_physical = 0xFFFFFFFFFFFFFFFFULL >> (64 - PerProcTable[0].ppe_vaddr->pf.pfMaxPAddr);	/* Get maximum physical address supported */
	
	if(PerProcTable[0].ppe_vaddr->pf.Available & pf64Bit) {				/* Are we 64 bit? */
		tmp = 12;												/* Size of hash space */
	}
	else {
		__asm__ volatile("cntlzw %0, %1" : "=r" (tmp) : "r" (hash_table_size));	/* Get number of leading 0s */
		tmp = 32 - tmp;											/* Size of hash space */
	}

	incrVSID = 1 << ((tmp + 1) >> 1);							/* Get ceiling of sqrt of table size */
	incrVSID |= 1 << ((tmp + 1) >> 2);							/* Get ceiling of quadroot of table size */
	incrVSID |= 1;												/* Set bit and add 1 */

	return;

}


/*
 *		mapping_remove(pmap_t pmap, addr64_t va);
 *			Given a pmap and virtual address, this routine finds the mapping and unmaps it.
 *			The mapping block will be added to
 *			the free list.  If the free list threshold is reached, garbage collection will happen.
 *
 *			We also pass back the next higher mapped address. This is done so that the higher level
 *			pmap_remove function can release a range of addresses simply by calling mapping_remove
 *			in a loop until it finishes the range or is returned a vaddr of 0.
 *
 *			Note that if the mapping is not found, we return the next VA ORed with 1
 *
 */

addr64_t mapping_remove(pmap_t pmap, addr64_t va) {		/* Remove a single mapping for this VADDR 
														   Returns TRUE if a mapping was found to remove */

	mapping_t	*mp;
	addr64_t	nextva;
	ppnum_t		pgaddr;
	
	va &= ~PAGE_MASK;									/* Scrub noise bits */
	
	do {												/* Keep trying until we truely fail */
		mp = hw_rem_map(pmap, va, &nextva);				/* Remove a mapping from this pmap */
	} while (mapRtRemove == ((unsigned int)mp & mapRetCode));
	
	switch ((unsigned int)mp & mapRetCode) {
		case mapRtOK:
			break;										/* Mapping removed */
		case mapRtNotFnd:
			return (nextva | 1);						/* Nothing found to unmap */
		default:
			panic("mapping_remove: hw_rem_map failed - pmap = %08X, va = %016llX, code = %08X\n",
				pmap, va, mp);
			break;
	}

	pgaddr = mp->mpPAddr;								/* Get page number from mapping */
	
	mapping_free(mp);									/* Add mapping to the free list */
	
	if ((pmap->pmapFlags & pmapVMhost) && pmap->pmapVmmExt) {
														/* If this is an assisted host, scrub any guest mappings */
		unsigned int  idx;
		phys_entry_t *physent = mapping_phys_lookup(pgaddr, &idx);
														/* Get physent for our physical page */
		if (!physent) {									/* No physent, could be in I/O area, so exit */
			return (nextva);
		}
		
		do {											/* Iterate 'till all guest mappings are gone */
			mp = hw_scrub_guest(physent, pmap);			/* Attempt to scrub a guest mapping */
			switch ((unsigned int)mp & mapRetCode) {
				case mapRtGuest:						/* Found a guest mapping */
				case mapRtNotFnd:						/* Mapping was there, but disappeared, must retry */
				case mapRtEmpty:						/* No guest mappings left to scrub */
					break;
				default:
					panic("mapping_remove: hw_scrub_guest failed - physent = %08X, code = %08X\n",
						physent, mp);					/* Cry havoc, cry wrack,
															at least we die with harness on our backs */
					break;
			}
		} while (mapRtEmpty != ((unsigned int)mp & mapRetCode));
	}

	return nextva;										/* Tell them we did it */
}

/*
 *		mapping_make(pmap, va, pa, flags, size, prot) - map a virtual address to a real one 
 *
 *		This routine takes the given parameters, builds a mapping block, and queues it into the 
 *		correct lists.
 *		
 *		pmap (virtual address)		is the pmap to map into
 *		va   (virtual address)		is the 64-bit virtual address that is being mapped
 *		pa	(physical page number)	is the physical page number (i.e., physcial address >> 12). This is
 *									a 32-bit quantity.
 *		Flags:
 *			block					if 1, mapping is a block, size parameter is used. Note: we do not keep 
 *									reference and change information or allow protection changes of blocks.
 *									any changes must first unmap and then remap the area.
 *			use attribute			Use specified attributes for map, not defaults for physical page
 *			perm					Mapping is permanent
 *			cache inhibited			Cache inhibited (used if use attribute or block set )
 *			guarded					Guarded access (used if use attribute or block set )
 *		size						size of block in pages - 1 (not used if not block)
 *		prot						VM protection bits
 *		attr						Cachability/Guardedness    
 *
 *		Returns 0 if mapping was successful.  Returns vaddr that overlaps/collides.
 *		Returns 1 for any other failure.
 *
 *		Note that we make an assumption that all memory in the range 0f 0x0000000080000000 to 0x00000000FFFFFFFF is reserved
 *		for I/O and default the cache attrubutes appropriately.  The caller is free to set whatever they want however.
 *
 *		If there is any physical page that is not found in the physent table, the mapping is forced to be a
 *		block mapping of length 1.  This keeps us from trying to update a physent during later mapping use,
 *		e.g., fault handling.
 *
 *
 */
 
addr64_t mapping_make(pmap_t pmap, addr64_t va, ppnum_t pa, unsigned int flags, unsigned int size, vm_prot_t prot) {	/* Make an address mapping */

	register mapping_t *mp;
	addr64_t colladdr, psmask;
	unsigned int pindex, mflags, pattr, wimg, rc;
	phys_entry_t *physent;
	int nlists, pcf;

	pindex = 0;
	
	mflags = 0x01000000;										/* Start building mpFlags field (busy count = 1) */

	pcf = (flags & mmFlgPcfg) >> 24;							/* Get the physical page config index */
	if(!(pPcfg[pcf].pcfFlags)) {								/* Validate requested physical page configuration */
		panic("mapping_make: invalid physical page configuration request - pmap = %08X, va = %016llX, cfg = %d\n",
			pmap, va, pcf);
	}
	
	psmask = (1ULL << pPcfg[pcf].pcfPSize) - 1;					/* Mask to isolate any offset into a page */
	if(va & psmask) {											/* Make sure we are page aligned on virtual */
		panic("mapping_make: attempt to map unaligned vaddr - pmap = %08X, va = %016llX, cfg = %d\n",
			pmap, va, pcf);
	}
	if(((addr64_t)pa << 12) & psmask) {							/* Make sure we are page aligned on physical */
		panic("mapping_make: attempt to map unaligned paddr - pmap = %08X, pa = %016llX, cfg = %d\n",
			pmap, pa, pcf);
	}
	
	mflags |= (pcf << (31-mpPcfgb));							/* Insert physical page configuration index */

	if(!(flags & mmFlgBlock)) {									/* Is this a block map? */

		size = 1;												/* Set size to 1 page if not block */
	 
		physent = mapping_phys_lookup(pa, &pindex);				/* Get physical entry */
		if(!physent) {											/* Did we find the physical page? */
			mflags |= mpBlock;									/* Force this to a block if no physent */
			pattr = 0;											/* Assume normal, non-I/O memory */
			if((pa & 0xFFF80000) == 0x00080000) pattr = mmFlgCInhib | mmFlgGuarded;	/* If this page is in I/O range, set I/O attributes */
		}
		else pattr = ((physent->ppLink & (ppI | ppG)) >> 60);	/* Get the default attributes from physent */
		
		if(flags & mmFlgUseAttr) pattr = flags & (mmFlgCInhib | mmFlgGuarded);	/* Use requested attributes */
	}
	else {														/* This is a block */
		 
		pattr = flags & (mmFlgCInhib | mmFlgGuarded);			/* Use requested attributes */
		mflags |= mpBlock;										/* Show that this is a block */
	
		if(size > pmapSmallBlock) {								/* Is it one? */
			if(size & 0x00001FFF) return mapRtBadSz;			/* Fail if bigger than 256MB and not a 32MB multiple */
			size = size >> 13;									/* Convert to 32MB chunks */
			mflags = mflags | mpBSu;							/* Show 32MB basic size unit */
		}
	}
	
	wimg = 0x2;													/* Set basic PPC wimg to 0b0010 - Coherent */
	if(pattr & mmFlgCInhib) wimg |= 0x4;						/* Add cache inhibited if we need to */
	if(pattr & mmFlgGuarded) wimg |= 0x1;						/* Add guarded if we need to */
	
	mflags = mflags | (pindex << 16);							/* Stick in the physical entry table index */
	
	if(flags & mmFlgPerm) mflags |= mpPerm;						/* Set permanent mapping */
	
	size = size - 1;											/* Change size to offset */
	if(size > 0xFFFF) return mapRtBadSz;						/* Leave if size is too big */
	
	nlists = mapSetLists(pmap);									/* Set number of lists this will be on */
	
	mp = mapping_alloc(nlists);									/* Get a spare mapping block with this many lists */

                                                                /* the mapping is zero except that the mpLists field is set */
	mp->mpFlags |= mflags;										/* Add in the rest of the flags to mpLists */
	mp->mpSpace = pmap->space;									/* Set the address space/pmap lookup ID */
	mp->u.mpBSize = size;										/* Set the size */
	mp->mpPte = 0;												/* Set the PTE invalid */
	mp->mpPAddr = pa;											/* Set the physical page number */
	mp->mpVAddr = (va & ~mpHWFlags) | (wimg << 3)				/* Add the protection and attributes to the field */
		| ((PerProcTable[0].ppe_vaddr->pf.Available & pf64Bit)?
			getProtPPC(prot) : (getProtPPC(prot) & 0x3));		/* Mask off no-execute control for 32-bit machines */			
	
	while(1) {													/* Keep trying... */
		colladdr = hw_add_map(pmap, mp);						/* Go add the mapping to the pmap */
		rc = colladdr & mapRetCode;								/* Separate return code */
		colladdr &= ~mapRetCode;								/* Clean up collision effective address */
		
		switch (rc) {
			case mapRtOK:
				return mapRtOK;									/* Mapping added successfully */
				
			case mapRtRemove:									/* Remove in progress */
				(void)mapping_remove(pmap, colladdr);			/* Lend a helping hand to another CPU doing block removal */
				continue;										/* Retry mapping add */
				
			case mapRtMapDup:									/* Identical mapping already present */
				mapping_free(mp);								/* Free duplicate mapping */
				return mapRtOK;										/* Return success */
				
			case mapRtSmash:									/* Mapping already present but does not match new mapping */
				mapping_free(mp);								/* Free duplicate mapping */
				return (colladdr | mapRtSmash);					/* Return colliding address, with some dirt added to avoid
																   confusion if effective address is 0 */
			default:
				panic("mapping_make: hw_add_map failed - collision addr = %016llX, code = %02X, pmap = %08X, va = %016llX, mapping = %08X\n",
					colladdr, rc, pmap, va, mp);				/* Die dead */
		}
		
	}
	
	return 1;													/* Unreachable, but pleases compiler */
}


/*
 *		mapping *mapping_find(pmap, va, *nextva, full) - Finds a mapping 
 *
 *		Looks up the vaddr and returns the mapping and the next mapped va
 *		If full is true, it will descend through all nested pmaps to find actual mapping
 *
 *		Must be called with interruptions disabled or we can hang trying to remove found mapping.
 *
 *		Returns 0 if not found and the virtual address of the mapping if it is
 *		Note that the mappings busy count is bumped. It is the responsibility of the caller
 *		to drop the count.  If this is not done, any attempt to remove the mapping will hang.
 *
 *		NOTE: The nextva field is not valid when full is TRUE.
 *
 *
 */
 
mapping_t *mapping_find(pmap_t pmap, addr64_t va, addr64_t *nextva, int full) {	/* Make an address mapping */

	register mapping_t *mp;
	addr64_t	curva;
	pmap_t	curpmap;
	int	nestdepth;

	curpmap = pmap;												/* Remember entry */
	nestdepth = 0;												/* Set nest depth */
	curva = (addr64_t)va;										/* Set current va */

	while(1) {

		mp = hw_find_map(curpmap, curva, nextva);				/* Find the mapping for this address */
		if((unsigned int)mp == mapRtBadLk) {					/* Did we lock up ok? */
			panic("mapping_find: pmap lock failure - rc = %08X, pmap = %08X\n", mp, curpmap);	/* Die... */
		}
		
		if(!mp || ((mp->mpFlags & mpType) < mpMinSpecial) || !full) break;		/* Are we done looking? */

		if((mp->mpFlags & mpType) != mpNest) {					/* Don't chain through anything other than a nested pmap */
			mapping_drop_busy(mp);								/* We have everything we need from the mapping */
			mp = 0;												/* Set not found */
			break;
		}

		if(nestdepth++ > 64) {									/* Have we nested too far down? */
			panic("mapping_find: too many nested pmaps - va = %016llX, curva = %016llX, pmap = %08X, curpmap = %08X\n",
				va, curva, pmap, curpmap);
		}
		
		curva = curva + mp->mpNestReloc;						/* Relocate va to new pmap */
		curpmap = (pmap_t) pmapTrans[mp->mpSpace].pmapVAddr;	/* Get the address of the nested pmap */
		mapping_drop_busy(mp);									/* We have everything we need from the mapping */
		
	}

	return mp;													/* Return the mapping if we found one */
}

/*
 *		void mapping_protect(pmap_t pmap, addt_t va, vm_prot_t prot, addr64_t *nextva) - change the protection of a virtual page
 *
 *		This routine takes a pmap and virtual address and changes
 *		the protection.  If there are PTEs associated with the mappings, they will be invalidated before
 *		the protection is changed. 
 *
 *		We return success if we change the protection or if there is no page mapped at va.  We return failure if
 *		the va corresponds to a block mapped area or the mapping is permanant.
 *
 *
 */

void
mapping_protect(pmap_t pmap, addr64_t va, vm_prot_t prot, addr64_t *nextva) {	/* Change protection of a virtual page */

	int	ret;
	
	ret = hw_protect(pmap, va, getProtPPC(prot), nextva);	/* Try to change the protect here */

	switch (ret) {								/* Decode return code */
	
		case mapRtOK:							/* Changed */
		case mapRtNotFnd:						/* Didn't find it */
		case mapRtBlock:						/* Block map, just ignore request */
		case mapRtNest:							/* Nested pmap, just ignore request */
			break;
			
		default:
			panic("mapping_protect: hw_protect failed - rc = %d, pmap = %08X, va = %016llX\n", ret, pmap, va);
		
	}

}

/*
 *		void mapping_protect_phys(ppnum_t pa, vm_prot_t prot) - change the protection of a physical page
 *
 *		This routine takes a physical entry and runs through all mappings attached to it and changes
 *		the protection.  If there are PTEs associated with the mappings, they will be invalidated before
 *		the protection is changed.  There is no limitation on changes, e.g., 
 *		higher to lower, lower to higher.
 *
 *		Any mapping that is marked permanent is not changed
 *
 *		Phys_entry is unlocked.
 */

void mapping_protect_phys(ppnum_t pa, vm_prot_t prot) {	/* Change protection of all mappings to page */
	
	unsigned int pindex;
	phys_entry_t *physent;
	
	physent = mapping_phys_lookup(pa, &pindex);					/* Get physical entry */
	if(!physent) {												/* Did we find the physical page? */
		panic("mapping_protect_phys: invalid physical page %08X\n", pa);
	}

	hw_walk_phys(physent, hwpNoop, hwpSPrtMap, hwpNoop,
	             getProtPPC(prot), hwpPurgePTE);				/* Set the new protection for page and mappings */

	return;														/* Leave... */
}


/*
 *		void mapping_clr_mod(ppnum_t pa) - clears the change bit of a physical page
 *
 *		This routine takes a physical entry and runs through all mappings attached to it and turns
 *		off the change bit. 
 */

void mapping_clr_mod(ppnum_t pa) {								/* Clears the change bit of a physical page */

	unsigned int pindex;
	phys_entry_t *physent;
	
	physent = mapping_phys_lookup(pa, &pindex);					/* Get physical entry */
	if(!physent) {												/* Did we find the physical page? */
		panic("mapping_clr_mod: invalid physical page %08X\n", pa);
	}

	hw_walk_phys(physent, hwpNoop, hwpCCngMap, hwpCCngPhy,
				 0, hwpPurgePTE);								/* Clear change for page and mappings */
	return;														/* Leave... */
}


/*
 *		void mapping_set_mod(ppnum_t pa) - set the change bit of a physical page
 *
 *		This routine takes a physical entry and runs through all mappings attached to it and turns
 *		on the change bit.  
 */

void mapping_set_mod(ppnum_t pa) {								/* Sets the change bit of a physical page */

	unsigned int pindex;
	phys_entry_t *physent;
	
	physent = mapping_phys_lookup(pa, &pindex);					/* Get physical entry */
	if(!physent) {												/* Did we find the physical page? */
		panic("mapping_set_mod: invalid physical page %08X\n", pa);
	}

	hw_walk_phys(physent, hwpNoop, hwpSCngMap, hwpSCngPhy,
				 0, hwpNoopPTE);								/* Set change for page and mappings */
	return;														/* Leave... */
}


/*
 *		void mapping_clr_ref(ppnum_t pa) - clears the reference bit of a physical page
 *
 *		This routine takes a physical entry and runs through all mappings attached to it and turns
 *		off the reference bit.  
 */

void mapping_clr_ref(ppnum_t pa) {								/* Clears the reference bit of a physical page */

	unsigned int pindex;
	phys_entry_t *physent;
	
	physent = mapping_phys_lookup(pa, &pindex);					/* Get physical entry */
	if(!physent) {												/* Did we find the physical page? */
		panic("mapping_clr_ref: invalid physical page %08X\n", pa);
	}

	hw_walk_phys(physent, hwpNoop, hwpCRefMap, hwpCRefPhy,
				 0, hwpPurgePTE);								/* Clear reference for page and mappings */
	return;														/* Leave... */
}


/*
 *		void mapping_set_ref(ppnum_t pa) - set the reference bit of a physical page
 *
 *		This routine takes a physical entry and runs through all mappings attached to it and turns
 *		on the reference bit. 
 */

void mapping_set_ref(ppnum_t pa) {								/* Sets the reference bit of a physical page */

	unsigned int pindex;
	phys_entry_t *physent;
	
	physent = mapping_phys_lookup(pa, &pindex);					/* Get physical entry */
	if(!physent) {												/* Did we find the physical page? */
		panic("mapping_set_ref: invalid physical page %08X\n", pa);
	}

	hw_walk_phys(physent, hwpNoop, hwpSRefMap, hwpSRefPhy,
				 0, hwpNoopPTE);								/* Set reference for page and mappings */
	return;														/* Leave... */
}


/*
 *		boolean_t mapping_tst_mod(ppnum_t pa) - test the change bit of a physical page
 *
 *		This routine takes a physical entry and runs through all mappings attached to it and tests
 *		the changed bit. 
 */

boolean_t mapping_tst_mod(ppnum_t pa) {							/* Tests the change bit of a physical page */

	unsigned int pindex, rc;
	phys_entry_t *physent;
	
	physent = mapping_phys_lookup(pa, &pindex);					/* Get physical entry */
	if(!physent) {												/* Did we find the physical page? */
		panic("mapping_tst_mod: invalid physical page %08X\n", pa);
	}

	rc = hw_walk_phys(physent, hwpTCngPhy, hwpTCngMap, hwpNoop,
					  0, hwpMergePTE);							/* Set change for page and mappings */
	return ((rc & (unsigned long)ppC) != 0);					/* Leave with change bit */
}


/*
 *		boolean_t mapping_tst_ref(ppnum_t pa) - tests the reference bit of a physical page
 *
 *		This routine takes a physical entry and runs through all mappings attached to it and tests
 *		the reference bit. 
 */

boolean_t mapping_tst_ref(ppnum_t pa) {							/* Tests the reference bit of a physical page */

	unsigned int pindex, rc;
	phys_entry_t *physent;
	
	physent = mapping_phys_lookup(pa, &pindex);					/* Get physical entry */
	if(!physent) {												/* Did we find the physical page? */
		panic("mapping_tst_ref: invalid physical page %08X\n", pa);
	}

	rc = hw_walk_phys(physent, hwpTRefPhy, hwpTRefMap, hwpNoop,
	                  0, hwpMergePTE);							/* Test reference for page and mappings */
	return ((rc & (unsigned long)ppR) != 0);					/* Leave with reference bit */
}


/*
 *		unsigned int mapping_tst_refmod(ppnum_t pa) - tests the reference and change bits of a physical page
 *
 *		This routine takes a physical entry and runs through all mappings attached to it and tests
 *		their reference and changed bits. 
 */

unsigned int mapping_tst_refmod(ppnum_t pa) {					/* Tests the reference and change bits of a physical page */
	
	unsigned int  pindex, rc;
	phys_entry_t *physent;
	
	physent = mapping_phys_lookup(pa, &pindex);					/* Get physical entry */
	if (!physent) {												/* Did we find the physical page? */
		panic("mapping_tst_refmod: invalid physical page %08X\n", pa);
	}

	rc = hw_walk_phys(physent, hwpTRefCngPhy, hwpTRefCngMap, hwpNoop,
					  0, hwpMergePTE);							/* Test reference and change bits in page and mappings */
	return (((rc & ppC)? VM_MEM_MODIFIED : 0) | ((rc & ppR)? VM_MEM_REFERENCED : 0));
																/* Convert bits to generic format and return */
	
}


/*
 *		void mapping_clr_refmod(ppnum_t pa, unsigned int mask) - clears the reference and change bits specified
 *        by mask of a physical page
 *
 *		This routine takes a physical entry and runs through all mappings attached to it and turns
 *		off all the reference and change bits.  
 */

void mapping_clr_refmod(ppnum_t pa, unsigned int mask) {		/* Clears the reference and change bits of a physical page */

	unsigned int  pindex;
	phys_entry_t *physent;
	unsigned int  ppcMask;
	
	physent = mapping_phys_lookup(pa, &pindex);					/* Get physical entry */
	if(!physent) {												/* Did we find the physical page? */
		panic("mapping_clr_refmod: invalid physical page %08X\n", pa);
	}

	ppcMask = (((mask & VM_MEM_MODIFIED)? ppC : 0) | ((mask & VM_MEM_REFERENCED)? ppR : 0));
																/* Convert mask bits to PPC-specific format */
	hw_walk_phys(physent, hwpNoop, hwpCRefCngMap, hwpCRefCngPhy,
	             ppcMask, hwpPurgePTE);							/* Clear reference and change bits for page and mappings */
	return;														/* Leave... */
}



/*
 *		phys_ent  *mapping_phys_lookup(ppnum_t pp, unsigned int *pindex) - tests the reference bit of a physical page
 *
 *		This routine takes a physical page number and returns the phys_entry associated with it.  It also
 *		calculates the bank address associated with the entry
 *		the reference bit. 
 */

phys_entry_t *mapping_phys_lookup(ppnum_t pp, unsigned int *pindex) {	/* Finds the physical entry for the page */

	int i;
	
	for(i = 0; i < pmap_mem_regions_count; i++) {				/* Walk through the list */
		if(!(unsigned int)pmap_mem_regions[i].mrPhysTab) continue;	/* Skip any empty lists */
		if((pp < pmap_mem_regions[i].mrStart) || (pp > pmap_mem_regions[i].mrEnd)) continue;	/* This isn't ours */
		
		*pindex = (i * sizeof(mem_region_t)) / 4;				/* Make the word index to this list */
		
		return &pmap_mem_regions[i].mrPhysTab[pp - pmap_mem_regions[i].mrStart];	/* Return the physent pointer */
	}
	
	return (phys_entry_t *)0;										/* Shucks, can't find it... */
	
}




/*
 *		mapping_adjust(void) - Releases free mapping blocks and/or allocates new ones 
 *
 *		This routine frees any mapping blocks queued to mapCtl.mapcrel. It also checks
 *		the number of free mappings remaining, and if below a threshold, replenishes them.
 *		The list will be replenshed from mapCtl.mapcrel if there are enough.  Otherwise,
 *		a new one is allocated.
 *
 *		This routine allocates and/or frees memory and must be called from a safe place. 
 *		Currently, vm_pageout_scan is the safest place. 
 */

thread_call_t				mapping_adjust_call;
static thread_call_data_t	mapping_adjust_call_data;

void mapping_adjust(void) {										/* Adjust free mappings */

	kern_return_t	retr = KERN_SUCCESS;
	mappingblok_t	*mb, *mbn;
	spl_t			s;
	int				allocsize;

	if(mapCtl.mapcmin <= MAPPERBLOK) {
		mapCtl.mapcmin = (sane_size / PAGE_SIZE) / 16;

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
			mbn = (mappingblok_t *)((unsigned int)mbn + PAGE_SIZE);	/* Point to the next slot */
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

	__asm__ volatile("eieio");									/* Make sure all is well */
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

	mappingblok_t	*mb, *mbn;
	spl_t			s;
	unsigned int	full, mindx, lists;

	mindx = ((unsigned int)mp & (PAGE_SIZE - 1)) >> 6;			/* Get index to mapping */
	mb = (mappingblok_t *)((unsigned int)mp & -PAGE_SIZE);		/* Point to the mapping block */
    lists = (mp->mpFlags & mpLists);							/* get #lists */
    if ((lists == 0) || (lists > kSkipListMaxLists)) 			/* panic if out of range */
        panic("mapping_free: mpLists invalid\n");

#if 0
	mp->mpFlags = 0x99999999;									/* (BRINGUP) */	
	mp->mpSpace = 0x9999;										/* (BRINGUP) */	
	mp->u.mpBSize = 0x9999;										/* (BRINGUP) */	
	mp->mpPte   = 0x99999998;									/* (BRINGUP) */	
	mp->mpPAddr = 0x99999999;									/* (BRINGUP) */	
	mp->mpVAddr = 0x9999999999999999ULL;						/* (BRINGUP) */	
	mp->mpAlias = 0x9999999999999999ULL;						/* (BRINGUP) */	
	mp->mpList0 = 0x9999999999999999ULL;						/* (BRINGUP) */	
	mp->mpList[0] = 0x9999999999999999ULL;						/* (BRINGUP) */	
	mp->mpList[1] = 0x9999999999999999ULL;						/* (BRINGUP) */	
	mp->mpList[2] = 0x9999999999999999ULL;						/* (BRINGUP) */	

	if(lists > mpBasicLists) {									/* (BRINGUP) */	
		mp->mpList[3] = 0x9999999999999999ULL;					/* (BRINGUP) */	
		mp->mpList[4] = 0x9999999999999999ULL;					/* (BRINGUP) */	
		mp->mpList[5] = 0x9999999999999999ULL;					/* (BRINGUP) */	
		mp->mpList[6] = 0x9999999999999999ULL;					/* (BRINGUP) */	
		mp->mpList[7] = 0x9999999999999999ULL;					/* (BRINGUP) */	
		mp->mpList[8] = 0x9999999999999999ULL;					/* (BRINGUP) */	
		mp->mpList[9] = 0x9999999999999999ULL;					/* (BRINGUP) */	
		mp->mpList[10] = 0x9999999999999999ULL;					/* (BRINGUP) */	
	}
#endif	
	

	s = splhigh();												/* Don't bother from now on */
	if(!hw_lock_to((hw_lock_t)&mapCtl.mapclock, LockTimeOut)) {	/* Lock the control header */ 
		panic("mapping_free - timeout getting control lock\n");	/* Tell all and die */
	}
	
	full = !(mb->mapblokfree[0] | mb->mapblokfree[1]);			/* See if full now */ 
	mb->mapblokfree[mindx >> 5] |= (0x80000000 >> (mindx & 31));	/* Flip on the free bit */
    if ( lists > mpBasicLists ) {								/* if big block, lite the 2nd bit too */
        mindx++;
        mb->mapblokfree[mindx >> 5] |= (0x80000000 >> (mindx & 31));
        mapCtl.mapcfree++;
        mapCtl.mapcinuse--;
    }
	
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
		if(((mb->mapblokfree[0] | 0x80000000) & mb->mapblokfree[1]) == 0xFFFFFFFF) {	/* See if empty now */ 

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
 *		mapping_alloc(lists) - obtain a mapping from the free list 
 *
 *		This routine takes a mapping off of the free list and returns its address.
 *		The mapping is zeroed, and its mpLists count is set.  The caller passes in
 *		the number of skiplists it would prefer; if this number is greater than 
 *		mpBasicLists (ie, 4) then we need to allocate a 128-byte mapping, which is
 *		just two consequtive free entries coallesced into one.  If we cannot find
 *		two consequtive free entries, we clamp the list count down to mpBasicLists
 *		and return a basic 64-byte node.  Our caller never knows the difference.
 *
 *		If this allocation empties a block, we remove it from the free list.
 *		If this allocation drops the total number of free entries below a threshold,
 *		we allocate a new block.
 *
 */
decl_simple_lock_data(extern,free_pmap_lock)

mapping_t *
mapping_alloc(int lists) {								/* Obtain a mapping */

	register mapping_t *mp;
	mappingblok_t	*mb, *mbn;
	spl_t			s;
	int				mindx;
    int				big = (lists > mpBasicLists);				/* set flag if big block req'd */
	pmap_t			refpmap, ckpmap;
	unsigned int	space, i;
	addr64_t		va, nextva;
	boolean_t		found_mapping;
	boolean_t		do_rescan;
    
	s = splhigh();												/* Don't bother from now on */
	if(!hw_lock_to((hw_lock_t)&mapCtl.mapclock, LockTimeOut)) {	/* Lock the control header */ 
		panic("mapping_alloc - timeout getting control lock\n");	/* Tell all and die */
	}

	if(!((unsigned int)mapCtl.mapcnext)) {						/* Are there any free mappings? */
	
/*
 *		No free mappings.  First, there may be some mapping blocks on the "to be released"
 *		list.  If so, rescue one.  Otherwise, try to steal a couple blocks worth.
 */

		if((mbn = mapCtl.mapcrel) != 0) {						/* Try to rescue a block from impending doom */
			mapCtl.mapcrel = mbn->nextblok;						/* Pop the queue */
			mapCtl.mapcreln--;									/* Back off the count */
			mapping_free_init((vm_offset_t)mbn, 0, 1);			/* Initialize a non-permanent block */
			goto rescued;
		}

		hw_lock_unlock((hw_lock_t)&mapCtl.mapclock);

		simple_lock(&free_pmap_lock);

		if(!hw_lock_to((hw_lock_t)&mapCtl.mapclock, LockTimeOut)) {	/* Lock the control header */ 
			panic("mapping_alloc - timeout getting control lock\n");	/* Tell all and die */
		}

		if (!((unsigned int)mapCtl.mapcnext)) {

			refpmap = (pmap_t)cursor_pmap->pmap_link.next;
			space = mapCtl.mapcflush.spacenum;
			while (refpmap != cursor_pmap) {
				if(((pmap_t)(refpmap->pmap_link.next))->spaceNum > space) break;
				refpmap = (pmap_t)refpmap->pmap_link.next;
			}

			ckpmap = refpmap;
			va = mapCtl.mapcflush.addr;
			found_mapping = FALSE;

			while (mapCtl.mapcfree <= (MAPPERBLOK*2)) {

				hw_lock_unlock((hw_lock_t)&mapCtl.mapclock);

				ckpmap = (pmap_t)ckpmap->pmap_link.next;

				/* We don't steal mappings from the kernel pmap, a VMM host pmap, or a VMM guest pmap with guest
				   shadow assist active.
				 */
				if ((ckpmap->stats.resident_count != 0) && (ckpmap != kernel_pmap)
														&& !(ckpmap->pmapFlags & (pmapVMgsaa|pmapVMhost))) {
					do_rescan = TRUE;
					for (i=0;i<8;i++) {
						mp = hw_purge_map(ckpmap, va, &nextva);

						switch ((unsigned int)mp & mapRetCode) {
							case mapRtOK:
								mapping_free(mp);
								found_mapping = TRUE;
								break;
							case mapRtNotFnd:
								break;
							default:
								panic("mapping_alloc: hw_purge_map failed - pmap = %08X, va = %16llX, code = %08X\n", ckpmap, va, mp);
								break;
						}

						if (mapRtNotFnd == ((unsigned int)mp & mapRetCode)) 
							if (do_rescan)
								do_rescan = FALSE;
							else
								break;

						va = nextva;
					}
				}

				if (ckpmap == refpmap) {
					if (found_mapping == FALSE)
						panic("no valid pmap to purge mappings\n");
					else
						found_mapping = FALSE;
				}

				if(!hw_lock_to((hw_lock_t)&mapCtl.mapclock, LockTimeOut)) {	/* Lock the control header */ 
					panic("mapping_alloc - timeout getting control lock\n");	/* Tell all and die */
				}

			}

			mapCtl.mapcflush.spacenum = ckpmap->spaceNum;
			mapCtl.mapcflush.addr = nextva;
		}

		simple_unlock(&free_pmap_lock);
	}

rescued:

	mb = mapCtl.mapcnext;
    
    if ( big ) {												/* if we need a big (128-byte) mapping */
        mapCtl.mapcbig++;										/* count attempts to allocate a big mapping */
        mbn = NULL;												/* this will be prev ptr */
        mindx = 0;
        while( mb ) {											/* loop over mapping blocks with free entries */
            mindx = mapalc2(mb);								/* try for 2 consequtive free bits in this block */

           if ( mindx )	break;									/* exit loop if we found them */
            mbn = mb;											/* remember previous block */
            mb = mb->nextblok;									/* move on to next block */
        }
        if ( mindx == 0 ) {										/* if we couldn't find 2 consequtive bits... */
            mapCtl.mapcbigfails++;								/* count failures */
            big = 0;											/* forget that we needed a big mapping */
            lists = mpBasicLists;								/* clamp list count down to the max in a 64-byte mapping */
            mb = mapCtl.mapcnext;								/* back to the first block with a free entry */
        }
        else {													/* if we did find a big mapping */
            mapCtl.mapcfree--;									/* Decrement free count twice */
            mapCtl.mapcinuse++;									/* Bump in use count twice */
            if ( mindx < 0 ) {									/* if we just used the last 2 free bits in this block */
                if (mbn) {										/* if this wasn't the first block */
                    mindx = -mindx;								/* make positive */
                    mbn->nextblok = mb->nextblok;				/* unlink this one from the middle of block list */
                    if (mb ==  mapCtl.mapclast)	{				/* if we emptied last block */
                        mapCtl.mapclast = mbn;					/* then prev block is now last */
                    }
                }
            }
        }
    }
    
    if ( !big ) {												/* if we need a small (64-byte) mapping */
        if(!(mindx = mapalc1(mb))) 								/* Allocate a 1-bit slot */
            panic("mapping_alloc - empty mapping block detected at %08X\n", mb);
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
		if((mbn = mapCtl.mapcrel) != 0) {						/* Try to rescue a block from impending doom */
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
	
	mp = &((mapping_t *)mb)[mindx];								/* Point to the allocated mapping */
    mp->mpFlags = lists;										/* set the list count */


	return mp;													/* Send it back... */
}


void
consider_mapping_adjust(void)
{
	spl_t			s;

	s = splhigh();												/* Don't bother from now on */
	if(!hw_lock_to((hw_lock_t)&mapCtl.mapclock, LockTimeOut)) {	/* Lock the control header */ 
		panic("consider_mapping_adjust -- lock timeout\n");
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
 *		The mapping block is a page size area on a page boundary.  It contains 1 header and 63
 *		mappings.  This call adds and initializes a block for use.  Mappings come in two sizes,
 *		64 and 128 bytes (the only difference is the number of skip-lists.)  When we allocate a
 *		128-byte mapping we just look for two consequtive free 64-byte mappings, so most of the
 *		code only deals with "basic" 64-byte mappings.  This works for two reasons:
 *			- Only one in 256 mappings is big, so they are rare.
 *			- If we cannot find two consequtive free mappings, we just return a small one.
 *			  There is no problem with doing this, except a minor performance degredation.
 *		Therefore, all counts etc in the mapping control structure are in units of small blocks.
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
														   
	mappingblok_t	*mb;
	spl_t		s;
	addr64_t	raddr;
	ppnum_t		pp;

	mb = (mappingblok_t *)mbl;								/* Start of area */	
	
	if(perm >= 0) {											/* See if we need to initialize the block */
		if(perm) {
			raddr = (addr64_t)((unsigned int)mbl);			/* Perm means V=R */
			mb->mapblokflags = mbPerm;						/* Set perm */
//			mb->mapblokflags |= (unsigned int)mb;			/* (BRINGUP) */
		}
		else {
			pp = pmap_find_phys(kernel_pmap, (addr64_t)mbl);	/* Get the physical page */
			if(!pp) {										/* What gives?  Where's the page? */
				panic("mapping_free_init: could not find translation for vaddr %016llX\n", (addr64_t)mbl);
			}
			
			raddr = (addr64_t)pp << 12;						/* Convert physical page to physical address */
			mb->mapblokflags = 0;							/* Set not perm */
//			mb->mapblokflags |= (unsigned int)mb;			/* (BRINGUP) */
		}
		
		mb->mapblokvrswap = raddr ^ (addr64_t)((unsigned int)mbl);		/* Form translation mask */
		
		mb->mapblokfree[0] = 0x7FFFFFFF;					/* Set first 32 (minus 1) free */
		mb->mapblokfree[1] = 0xFFFFFFFF;					/* Set next 32 free */
	}
	
	s = splhigh();											/* Don't bother from now on */
	if(!locked) {											/* Do we need the lock? */
		if(!hw_lock_to((hw_lock_t)&mapCtl.mapclock, LockTimeOut)) {		/* Lock the control header */ 
			panic("mapping_free_init: timeout getting control lock\n");	/* Tell all and die */
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

	splx(s);												/* Restore 'rupts */
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
	mappingblok_t	*mbn;
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
	if (!hw_compare_and_store(0, 1, &mapCtl.mapcrecurse)) {	    /* Make sure we aren't recursing */
		hw_lock_unlock((hw_lock_t)&mapCtl.mapclock);			/* Unlock our stuff */
		splx(s);											/* Restore 'rupts */
		return;
	}
	nmapb = (nmapb + MAPPERBLOK - 1) / MAPPERBLOK;			/* Get number of blocks to get */
	
	hw_lock_unlock((hw_lock_t)&mapCtl.mapclock);			/* Unlock our stuff */
	splx(s);												/* Restore 'rupts */
	
	for(i = 0; i < nmapb; i++) {							/* Allocate 'em all */
		retr = kmem_alloc_wired(mapping_map, (vm_offset_t *)&mbn, PAGE_SIZE);	/* Find a virtual address to use */
		if(retr != KERN_SUCCESS) 							/* Did we get some memory? */
			break;
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
	mappingblok_t	*mbn;
	vm_offset_t     mapping_min;
	
	retr = kmem_suballoc(kernel_map, &mapping_min, sane_size / 16,
			     FALSE, VM_FLAGS_ANYWHERE, &mapping_map);

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


void
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
 *		addr64_t	mapping_p2v(pmap_t pmap, ppnum_t pa) - Finds first virtual mapping of a physical page in a space
 *
 *		First looks up  the physical entry associated witht the physical page.  Then searches the alias
 *		list for a matching pmap.  It grabs the virtual address from the mapping, drops busy, and returns 
 *		that.
 *
 */

addr64_t	mapping_p2v(pmap_t pmap, ppnum_t pa) {				/* Finds first virtual mapping of a physical page in a space */

	spl_t s;
	mapping_t *mp;
	unsigned int pindex;
	phys_entry_t *physent;
	addr64_t va;

	physent = mapping_phys_lookup(pa, &pindex);					/* Get physical entry */
	if(!physent) {												/* Did we find the physical page? */
		panic("mapping_p2v: invalid physical page %08X\n", pa);
	}

	s = splhigh();											/* Make sure interruptions are disabled */

	mp = hw_find_space(physent, pmap->space);				/* Go find the first mapping to the page from the requested pmap */

	if(mp) {												/* Did we find one? */
		va = mp->mpVAddr & -4096;							/* If so, get the cleaned up vaddr */
		mapping_drop_busy(mp);								/* Go ahead and relase the mapping now */
	}
	else va = 0;											/* Return failure */

	splx(s);												/* Restore 'rupts */
	
	return va;												/* Bye, bye... */
	
}

/*
 *	phystokv(addr)
 *
 *	Convert a physical address to a kernel virtual address if
 *	there is a mapping, otherwise return NULL
 */

vm_offset_t phystokv(vm_offset_t pa) {

	addr64_t	va;
	ppnum_t pp;

	pp = pa >> 12;											/* Convert to a page number */
	
	if(!(va = mapping_p2v(kernel_pmap, pp))) {
		return 0;											/* Can't find it, return 0... */
	}
	
	return (va | (pa & (PAGE_SIZE - 1)));					/* Build and return VADDR... */

}

/*
 *	kvtophys(addr)
 *
 *	Convert a kernel virtual address to a physical address
 */
vm_offset_t kvtophys(vm_offset_t va) {

	return pmap_extract(kernel_pmap, va);					/* Find mapping and lock the physical entry for this mapping */

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

	if(type) current_thread()->machine.specFlags |= ignoreZeroFault;	/* Ignore faults on page 0 */
	else     current_thread()->machine.specFlags &= ~ignoreZeroFault;	/* Honor faults on page 0 */
	
	return;												/* Return the result or 0... */
}


/* 
 *		Copies data between a physical page and a virtual page, or 2 physical.  This is used to 
 *		move data from the kernel to user state. Note that the "which" parm
 *		says which of the parameters is physical and if we need to flush sink/source.  
 *		Note that both addresses may be physical, but only one may be virtual.
 *
 *		The rules are that the size can be anything.  Either address can be on any boundary
 *		and span pages.  The physical data must be contiguous as must the virtual.
 *
 *		We can block when we try to resolve the virtual address at each page boundary.
 *		We don't check protection on the physical page.
 *
 *		Note that we will not check the entire range and if a page translation fails,
 *		we will stop with partial contents copied.
 *
 */
 
kern_return_t hw_copypv_32(addr64_t source, addr64_t sink, unsigned int size, int which) {
 
	vm_map_t map;
	kern_return_t ret;
	addr64_t nextva, vaddr, paddr;
	register mapping_t *mp;
	spl_t s;
	unsigned int lop, csize;
	int needtran, bothphys;
	unsigned int pindex;
	phys_entry_t *physent;
	vm_prot_t prot;
	int orig_which;

	orig_which = which;

	map = (which & cppvKmap) ? kernel_map : current_map_fast();

	if((which & (cppvPsrc | cppvPsnk)) == 0 ) {		/* Make sure that only one is virtual */
		panic("copypv: no more than 1 parameter may be virtual\n");	/* Not allowed */
	}
	
	bothphys = 1;									/* Assume both are physical */
	
	if(!(which & cppvPsnk)) {						/* Is sink page virtual? */
		vaddr = sink;								/* Sink side is virtual */
		bothphys = 0;								/* Show both aren't physical */
		prot = VM_PROT_READ | VM_PROT_WRITE;		/* Sink always must be read/write */
	} else if (!(which & cppvPsrc)) {				/* Is source page virtual? */
		vaddr = source;								/* Source side is virtual */
		bothphys = 0;								/* Show both aren't physical */
		prot = VM_PROT_READ; 						/* Virtual source is always read only */
	}

	needtran = 1;									/* Show we need to map the virtual the first time */
	s = splhigh();									/* Don't bother me */

	while(size) {

		if(!bothphys && (needtran || !(vaddr & 4095LL))) {	/* If first time or we stepped onto a new page, we need to translate */
			if(!needtran) {							/* If this is not the first translation, we need to drop the old busy */
				mapping_drop_busy(mp);				/* Release the old mapping now */
			}
			needtran = 0;
			
			while(1) {
				mp = mapping_find(map->pmap, vaddr, &nextva, 1);	/* Find and busy the mapping */
				if(!mp) {							/* Was it there? */
					if(getPerProc()->istackptr == 0)
						panic("copypv: No vaild mapping on memory %s %x", "RD", vaddr);

					splx(s);						/* Restore the interrupt level */
					ret = vm_fault(map, vm_map_trunc_page(vaddr), prot, FALSE, THREAD_UNINT, NULL, 0);	/* Didn't find it, try to fault it in... */
				
					if(ret != KERN_SUCCESS)return KERN_FAILURE;	/* Didn't find any, return no good... */
					
					s = splhigh();					/* Don't bother me */
					continue;						/* Go try for the map again... */
	
				}
				if (mp->mpVAddr & mpI) {                 /* cache inhibited, so force the appropriate page to be flushed before */
				        if (which & cppvPsrc)            /* and after the copy to avoid cache paradoxes */
					        which |= cppvFsnk;
					else
					        which |= cppvFsrc;
				} else
				        which = orig_which;

				/* Note that we have to have the destination writable.  So, if we already have it, or we are mapping the source,
					we can just leave.
				*/		
				if((which & cppvPsnk) || !(mp->mpVAddr & 1)) break;		/* We got it mapped R/W or the source is not virtual, leave... */
			
				mapping_drop_busy(mp);				/* Go ahead and release the mapping for now */
				if(getPerProc()->istackptr == 0)
					panic("copypv: No vaild mapping on memory %s %x", "RDWR", vaddr);
				splx(s);							/* Restore the interrupt level */
				
				ret = vm_fault(map, vm_map_trunc_page(vaddr), VM_PROT_READ | VM_PROT_WRITE, FALSE, THREAD_UNINT, NULL, 0);	/* check for a COW area */
				if (ret != KERN_SUCCESS) return KERN_FAILURE;	/* We couldn't get it R/W, leave in disgrace... */
				s = splhigh();						/* Don't bother me */
			}
			paddr = ((addr64_t)mp->mpPAddr << 12) + (vaddr - (mp->mpVAddr & -4096LL));        /* construct the physical address... this calculation works */
			                                                                                  /* properly on both single page and block mappings */
			if(which & cppvPsrc) sink = paddr;		/* If source is physical, then the sink is virtual */
			else source = paddr;					/* Otherwise the source is */
		}
			
		lop = (unsigned int)(4096LL - (sink & 4095LL));		/* Assume sink smallest */
		if(lop > (unsigned int)(4096LL - (source & 4095LL))) lop = (unsigned int)(4096LL - (source & 4095LL));	/* No, source is smaller */
		
		csize = size;								/* Assume we can copy it all */
		if(lop < size) csize = lop;					/* Nope, we can't do it all */
		
		if(which & cppvFsrc) flush_dcache64(source, csize, 1);	/* If requested, flush source before move */
		if(which & cppvFsnk) flush_dcache64(sink, csize, 1);	/* If requested, flush sink before move */

		bcopy_physvir_32(source, sink, csize);			/* Do a physical copy, virtually */
		
		if(which & cppvFsrc) flush_dcache64(source, csize, 1);	/* If requested, flush source after move */
		if(which & cppvFsnk) flush_dcache64(sink, csize, 1);	/* If requested, flush sink after move */

/*
 *		Note that for certain ram disk flavors, we may be copying outside of known memory.
 *		Therefore, before we try to mark it modifed, we check if it exists.
 */

		if( !(which & cppvNoModSnk)) {
		        physent = mapping_phys_lookup(sink >> 12, &pindex);	/* Get physical entry for sink */
			if(physent) mapping_set_mod((ppnum_t)(sink >> 12));		/* Make sure we know that it is modified */
		}
		if( !(which & cppvNoRefSrc)) {
		        physent = mapping_phys_lookup(source >> 12, &pindex);	/* Get physical entry for source */
			if(physent) mapping_set_ref((ppnum_t)(source >> 12));		/* Make sure we know that it is modified */
		}
		size = size - csize;						/* Calculate what is left */
		vaddr = vaddr + csize;						/* Move to next sink address */
		source = source + csize;					/* Bump source to next physical address */
		sink = sink + csize;						/* Bump sink to next physical address */
	}
	
	if(!bothphys) mapping_drop_busy(mp);			/* Go ahead and release the mapping of the virtual page if any */
	splx(s);										/* Open up for interrupts */

	return KERN_SUCCESS;
}


/*
 *	Debug code 
 */

void mapping_verify(void) {

	spl_t		s;
	mappingblok_t	*mb, *mbn;
	unsigned int	relncnt;
	unsigned int	dumbodude;

	dumbodude = 0;
	
	s = splhigh();											/* Don't bother from now on */

	mbn = 0;												/* Start with none */
	for(mb = mapCtl.mapcnext; mb; mb = mb->nextblok) {		/* Walk the free chain */
		if((mappingblok_t *)(mb->mapblokflags & 0x7FFFFFFF) != mb) {	/* Is tag ok? */
			panic("mapping_verify: flags tag bad, free chain; mb = %08X, tag = %08X\n", mb, mb->mapblokflags);
		}
		mbn = mb;											/* Remember the last one */
	}
	
	if(mapCtl.mapcnext && (mapCtl.mapclast != mbn)) {		/* Do we point to the last one? */
		panic("mapping_verify: last pointer bad; mb = %08X, mapclast = %08X\n", mb, mapCtl.mapclast);
	}
	
	relncnt = 0;											/* Clear count */
	for(mb = mapCtl.mapcrel; mb; mb = mb->nextblok) {		/* Walk the release chain */
		dumbodude |= mb->mapblokflags;						/* Just touch it to make sure it is mapped */
		relncnt++;											/* Count this one */
	}
	
	if(mapCtl.mapcreln != relncnt) {							/* Is the count on release queue ok? */
		panic("mapping_verify: bad release queue count; mapcreln = %d, cnt = %d, ignore this = %08X\n", mapCtl.mapcreln, relncnt, dumbodude);
	}

	splx(s);												/* Restore 'rupts */

	return;
}

void mapping_phys_unused(ppnum_t pa) {

	unsigned int pindex;
	phys_entry_t *physent;

	physent = mapping_phys_lookup(pa, &pindex);				/* Get physical entry */
	if(!physent) return;									/* Did we find the physical page? */

	if(!(physent->ppLink & ~(ppLock | ppFlags))) return;	/* No one else is here */
	
	panic("mapping_phys_unused: physical page (%08X) in use, physent = %08X\n", pa, physent);
	
}
	
void mapping_hibernate_flush(void)
{
    int bank;
    unsigned int page;
    struct phys_entry * entry;

    for (bank = 0; bank < pmap_mem_regions_count; bank++)
    {
	entry = (struct phys_entry *) pmap_mem_regions[bank].mrPhysTab;
	for (page = pmap_mem_regions[bank].mrStart; page <= pmap_mem_regions[bank].mrEnd; page++)
	{
	    hw_walk_phys(entry, hwpNoop, hwpNoop, hwpNoop, 0, hwpPurgePTE);
	    entry++;
	}
    }
}







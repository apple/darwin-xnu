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
/*
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1990,1991,1992 The University of Utah and
 * the Center for Software Science (CSS).
 * Copyright (c) 1991,1987 Carnegie Mellon University.
 * All rights reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation,
 * and that all advertising materials mentioning features or use of
 * this software display the following acknowledgement: ``This product
 * includes software developed by the Center for Software Science at
 * the University of Utah.''
 *
 * CARNEGIE MELLON, THE UNIVERSITY OF UTAH AND CSS ALLOW FREE USE OF
 * THIS SOFTWARE IN ITS "AS IS" CONDITION, AND DISCLAIM ANY LIABILITY
 * OF ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF
 * THIS SOFTWARE.
 *
 * CSS requests users of this software to return to css-dist@cs.utah.edu any
 * improvements that they make and grant CSS redistribution rights.
 *
 * Carnegie Mellon requests users of this software to return to
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 *
 * 	Utah $Hdr: pmap.c 1.28 92/06/23$
 *	Author: Mike Hibler, Bob Wheeler, University of Utah CSS, 10/90
 */
 
/*
 *	Manages physical address maps for powerpc.
 *
 *	In addition to hardware address maps, this
 *	module is called upon to provide software-use-only
 *	maps which may or may not be stored in the same
 *	form as hardware maps.  These pseudo-maps are
 *	used to store intermediate results from copy
 *	operations to and from address spaces.
 *
 *	Since the information managed by this module is
 *	also stored by the logical address mapping module,
 *	this module may throw away valid virtual-to-physical
 *	mappings at almost any time.  However, invalidations
 *	of virtual-to-physical mappings must be done as
 *	requested.
 *
 *	In order to cope with hardware architectures which
 *	make virtual-to-physical map invalidates expensive,
 *	this module may delay invalidate or reduced protection
 *	operations until such time as they are actually
 *	necessary.  This module is given full information to
 *	when physical maps must be made correct.
 *	
 */

#include <zone_debug.h>
#include <cpus.h>
#include <debug.h>
#include <mach_kgdb.h>
#include <mach_vm_debug.h>
#include <db_machine_commands.h>

#include <kern/thread.h>
#include <kern/simple_lock.h>
#include <mach/vm_attributes.h>
#include <mach/vm_param.h>
#include <vm/vm_kern.h>
#include <kern/spl.h>

#include <kern/misc_protos.h>
#include <ppc/misc_protos.h>
#include <ppc/proc_reg.h>

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>

#include <ppc/pmap.h>
#include <ppc/mem.h>
#include <ppc/mappings.h>

#include <ppc/new_screen.h>
#include <ppc/Firmware.h>
#include <ppc/savearea.h>
#include <ppc/exception.h>
#include <ppc/low_trace.h>
#include <ddb/db_output.h>

extern unsigned int	avail_remaining;
extern unsigned int	mappingdeb0;
extern	struct 	Saveanchor saveanchor;						/* Aliged savearea anchor */
extern int 		real_ncpus;									/* Number of actual CPUs */
unsigned int 	debugbackpocket;							/* (TEST/DEBUG) */

vm_offset_t		first_free_virt;
int          	current_free_region;						/* Used in pmap_next_page */

pmapTransTab *pmapTrans;									/* Point to the hash to pmap translations */
struct phys_entry *phys_table;

/* forward */
void pmap_activate(pmap_t pmap, thread_t th, int which_cpu);
void pmap_deactivate(pmap_t pmap, thread_t th, int which_cpu);
void copy_to_phys(vm_offset_t sva, vm_offset_t dpa, int bytecount);

#if MACH_VM_DEBUG
int pmap_list_resident_pages(pmap_t pmap, vm_offset_t *listp, int space);
#endif

/*  NOTE:  kernel_pmap_store must be in V=R storage and aligned!!!!!!!!!!!!!! */

extern struct pmap	kernel_pmap_store;
pmap_t		kernel_pmap;			/* Pointer to kernel pmap and anchor for in-use pmaps */		
addr64_t	kernel_pmap_phys;		/* Pointer to kernel pmap and anchor for in-use pmaps, physical address */		
pmap_t		cursor_pmap;			/* Pointer to last pmap allocated or previous if removed from in-use list */
pmap_t		sharedPmap;				/* Pointer to common pmap for 64-bit address spaces */
struct zone	*pmap_zone;				/* zone of pmap structures */
boolean_t	pmap_initialized = FALSE;

int ppc_max_pmaps;					/* Maximum number of concurrent address spaces allowed. This is machine dependent */	
addr64_t vm_max_address;			/* Maximum effective address supported */
addr64_t vm_max_physical;			/* Maximum physical address supported */

/*
 * Physical-to-virtual translations are handled by inverted page table
 * structures, phys_tables.  Multiple mappings of a single page are handled
 * by linking the affected mapping structures. We initialise one region
 * for phys_tables of the physical memory we know about, but more may be
 * added as it is discovered (eg. by drivers).
 */

/*
 *	free pmap list. caches the first free_pmap_max pmaps that are freed up
 */
int		free_pmap_max = 32;
int		free_pmap_count;
pmap_t	free_pmap_list;
decl_simple_lock_data(,free_pmap_lock)

/*
 * Function to get index into phys_table for a given physical address
 */

struct phys_entry *pmap_find_physentry(ppnum_t pa)
{
	int i;
	unsigned int entry;

	for (i = pmap_mem_regions_count - 1; i >= 0; i--) {
		if (pa < pmap_mem_regions[i].mrStart) continue;	/* See if we fit in this region */
		if (pa > pmap_mem_regions[i].mrEnd) continue;	/* Check the end too */
		
		entry = (unsigned int)pmap_mem_regions[i].mrPhysTab + ((pa - pmap_mem_regions[i].mrStart) * sizeof(phys_entry));
		return (struct phys_entry *)entry;
	}
//	kprintf("DEBUG - pmap_find_physentry: page 0x%08X not found\n", pa);
	return 0;
}

/*
 * kern_return_t
 * pmap_add_physical_memory(vm_offset_t spa, vm_offset_t epa,
 *                          boolean_t available, unsigned int attr)
 *
 *	THIS IS NOT SUPPORTED
 */
kern_return_t pmap_add_physical_memory(vm_offset_t spa, vm_offset_t epa,
				       boolean_t available, unsigned int attr)
{
	
	panic("Forget it! You can't map no more memory, you greedy puke!\n");
	return KERN_SUCCESS;
}

/*
 * pmap_map(va, spa, epa, prot)
 *	is called during boot to map memory in the kernel's address map.
 *	A virtual address range starting at "va" is mapped to the physical
 *	address range "spa" to "epa" with machine independent protection
 *	"prot".
 *
 *	"va", "spa", and "epa" are byte addresses and must be on machine
 *	independent page boundaries.
 *
 *	Pages with a contiguous virtual address range, the same protection, and attributes.
 *	therefore, we map it with a single block.
 *
 *	Note that this call will only map into 32-bit space
 *
 */

vm_offset_t
pmap_map(
	vm_offset_t va,
	vm_offset_t spa,
	vm_offset_t epa,
	vm_prot_t prot)
{

	addr64_t colladr;
	
	if (spa == epa) return(va);

	assert(epa > spa);

	colladr = mapping_make(kernel_pmap, (addr64_t)va, (ppnum_t)(spa >> 12), (mmFlgBlock | mmFlgPerm), (epa - spa) >> 12, prot & VM_PROT_ALL);

	if(colladr) {											/* Was something already mapped in the range? */
		panic("pmap_map: attempt to map previously mapped range - va = %08X, pa = %08X, epa = %08X, collision = %016llX\n",
			va, spa, epa, colladr);
	}				
	return(va);
}

/*
 *	Bootstrap the system enough to run with virtual memory.
 *	Map the kernel's code and data, and allocate the system page table.
 *	Called with mapping done by BATs. Page_size must already be set.
 *
 *	Parameters:
 *	msize:	Total memory present
 *	first_avail:	First virtual address available
 *	kmapsize:	Size of kernel text and data
 */
void
pmap_bootstrap(uint64_t msize, vm_offset_t *first_avail, unsigned int kmapsize)
{
	register struct mapping *mp;
	vm_offset_t 	addr;
	vm_size_t 		size;
	int 			i, num, j, rsize, mapsize, vmpagesz, vmmapsz, bank, nbits;
	uint64_t		tmemsize;
	uint_t			htslop;
	vm_offset_t		first_used_addr, PCAsize;
	struct phys_entry *phys_table;

	*first_avail = round_page_32(*first_avail);				/* Make sure we start out on a page boundary */
	vm_last_addr = VM_MAX_KERNEL_ADDRESS;					/* Set the highest address know to VM */

	/*
	 * Initialize kernel pmap
	 */
	kernel_pmap = &kernel_pmap_store;
	kernel_pmap_phys = (addr64_t)&kernel_pmap_store;
	cursor_pmap = &kernel_pmap_store;

	simple_lock_init(&kernel_pmap->lock, ETAP_VM_PMAP_KERNEL);

	kernel_pmap->pmap_link.next = (queue_t)kernel_pmap;		/* Set up anchor forward */
	kernel_pmap->pmap_link.prev = (queue_t)kernel_pmap;		/* Set up anchor reverse */
	kernel_pmap->ref_count = 1;
	kernel_pmap->pmapFlags = pmapKeyDef;					/* Set the default keys */
	kernel_pmap->pmapCCtl = pmapCCtlVal;					/* Initialize cache control */
	kernel_pmap->space = PPC_SID_KERNEL;
	kernel_pmap->pmapvr = 0;								/* Virtual = Real  */

/*
 *	The hash table wants to have one pteg for every 2 physical pages.
 *	We will allocate this in physical RAM, outside of kernel virtual memory,
 *	at the top of the highest bank that will contain it.
 *	Note that "bank" doesn't refer to a physical memory slot here, it is a range of
 *	physically contiguous memory.
 *
 *	The PCA will go there as well, immediately before the hash table.
 */
 
	nbits = cntlzw(((msize << 1) - 1) >> 32);				/* Get first bit in upper half */
	if(nbits == 32) nbits = nbits + cntlzw((uint_t)((msize << 1) - 1));	/* If upper half was empty, find bit in bottom half */
 	tmemsize = 0x8000000000000000ULL >> nbits;					/* Get memory size rounded up to power of 2 */
 	
 	if(tmemsize > 0x0000002000000000ULL) tmemsize = 0x0000002000000000ULL;	/* Make sure we don't make an unsupported hash table size */

 	hash_table_size = (uint_t)(tmemsize >> 13) * per_proc_info[0].pf.pfPTEG;	/* Get provisional hash_table_size */
 	if(hash_table_size < (256 * 1024)) hash_table_size = (256 * 1024);	/* Make sure we are at least minimum size */	

	while(1) {												/* Try to fit hash table in PCA into contiguous memory */

		if(hash_table_size < (256 * 1024)) {				/* Have we dropped too short? This should never, ever happen */
			panic("pmap_bootstrap: Can't find space for hash table\n");	/* This will never print, system isn't up far enough... */
		}

		PCAsize = (hash_table_size / per_proc_info[0].pf.pfPTEG) * sizeof(PCA);	/* Get total size of PCA table */
		PCAsize = round_page_32(PCAsize);					/* Make sure it is at least a page long */
	
		for(bank = pmap_mem_regions_count - 1; bank >= 0; bank--) {	/* Search backwards through banks */
			
			hash_table_base = ((addr64_t)pmap_mem_regions[bank].mrEnd << 12) - hash_table_size + PAGE_SIZE;	/* Get tenative address */
			
			htslop = hash_table_base & (hash_table_size - 1);	/* Get the extra that we will round down when we align */
			hash_table_base = hash_table_base & -(addr64_t)hash_table_size;	/* Round down to correct boundary */
			
			if((hash_table_base - round_page_32(PCAsize)) >= ((addr64_t)pmap_mem_regions[bank].mrStart << 12)) break;	/* Leave if we fit */
		}
		
		if(bank >= 0) break;								/* We are done if we found a suitable bank */
		
		hash_table_size = hash_table_size >> 1;				/* Try the next size down */
	}

	if(htslop) {											/* If there was slop (i.e., wasted pages for alignment) add a new region */
		for(i = pmap_mem_regions_count - 1; i >= bank; i--) {	/* Copy from end to our bank, including our bank */
			pmap_mem_regions[i + 1].mrStart  = pmap_mem_regions[i].mrStart;	/* Set the start of the bank */
			pmap_mem_regions[i + 1].mrAStart = pmap_mem_regions[i].mrAStart;	/* Set the start of allocatable area */
			pmap_mem_regions[i + 1].mrEnd    = pmap_mem_regions[i].mrEnd;	/* Set the end address of bank */
			pmap_mem_regions[i + 1].mrAEnd   = pmap_mem_regions[i].mrAEnd;	/* Set the end address of allocatable area */
		}
		
		pmap_mem_regions[i + 1].mrStart  = (hash_table_base + hash_table_size) >> 12;	/* Set the start of the next bank to the start of the slop area */
		pmap_mem_regions[i + 1].mrAStart = (hash_table_base + hash_table_size) >> 12;	/* Set the start of allocatable area to the start of the slop area */
		pmap_mem_regions[i].mrEnd        = (hash_table_base + hash_table_size - 4096) >> 12;	/* Set the end of our bank to the end of the hash table */
		
	}		
	
	pmap_mem_regions[bank].mrAEnd = (hash_table_base - PCAsize - 4096) >> 12;	/* Set the maximum allocatable in this bank */
	
	hw_hash_init();											/* Initiaize the hash table and PCA */
	hw_setup_trans();										/* Set up hardware registers needed for translation */
	
/*
 *	The hash table is now all initialized and so is the PCA.  Go on to do the rest of it.
 *	This allocation is from the bottom up.
 */	
	
	num = atop_64(msize);										/* Get number of pages in all of memory */

/* Figure out how much we need to allocate */

	size = (vm_size_t) (
		(InitialSaveBloks * PAGE_SIZE) +					/* Allow space for the initial context saveareas */
		(BackPocketSaveBloks * PAGE_SIZE) +					/* For backpocket saveareas */
		trcWork.traceSize +								/* Size of trace table */
		((((1 << maxAdrSpb) * sizeof(pmapTransTab)) + 4095) & -4096) +	/* Size of pmap translate table */
		(((num * sizeof(struct phys_entry)) + 4095) & -4096) 	/* For the physical entries */
	);

	mapsize = size = round_page_32(size);						/* Get size of area to map that we just calculated */
	mapsize = mapsize + kmapsize;							/* Account for the kernel text size */

	vmpagesz = round_page_32(num * sizeof(struct vm_page));	/* Allow for all vm_pages needed to map physical mem */
	vmmapsz = round_page_32((num / 8) * sizeof(struct vm_map_entry));	/* Allow for vm_maps */
	
	mapsize = mapsize + vmpagesz + vmmapsz;					/* Add the VM system estimates into the grand total */

	mapsize = mapsize + (4 * 1024 * 1024);					/* Allow for 4 meg of extra mappings */
	mapsize = ((mapsize / PAGE_SIZE) + MAPPERBLOK - 1) / MAPPERBLOK;	/* Get number of blocks of mappings we need */
	mapsize = mapsize + ((mapsize  + MAPPERBLOK - 1) / MAPPERBLOK);	/* Account for the mappings themselves */

	size = size + (mapsize * PAGE_SIZE);					/* Get the true size we need */

	/* hash table must be aligned to its size */

	addr = *first_avail;									/* Set the address to start allocations */
	first_used_addr = addr;									/* Remember where we started */

	bzero((char *)addr, size);								/* Clear everything that we are allocating */

 	savearea_init(addr);									/* Initialize the savearea chains and data */

	addr = (vm_offset_t)((unsigned int)addr + ((InitialSaveBloks + BackPocketSaveBloks) * PAGE_SIZE));	/* Point past saveareas */

	trcWork.traceCurr = (unsigned int)addr;					/* Set first trace slot to use */
	trcWork.traceStart = (unsigned int)addr;				/* Set start of trace table */
	trcWork.traceEnd = (unsigned int)addr + trcWork.traceSize;		/* Set end of trace table */

	addr = (vm_offset_t)trcWork.traceEnd;					/* Set next allocatable location */
		
	pmapTrans = (pmapTransTab *)addr;						/* Point to the pmap to hash translation table */
		
	pmapTrans[PPC_SID_KERNEL].pmapPAddr = (addr64_t)kernel_pmap;	/* Initialize the kernel pmap in the translate table */
	pmapTrans[PPC_SID_KERNEL].pmapVAddr = kernel_pmap;		/* Initialize the kernel pmap in the translate table */
		
	addr += ((((1 << maxAdrSpb) * sizeof(pmapTransTab)) + 4095) & -4096);	/* Point past pmap translate table */

/*	NOTE: the phys_table must be within the first 2GB of physical RAM. This makes sure we only need to do 32-bit arithmetic */

	phys_table = (struct phys_entry *) addr;				/* Get pointer to physical table */

	for (bank = 0; bank < pmap_mem_regions_count; bank++) {	/* Set pointer and initialize all banks of ram */
		
		pmap_mem_regions[bank].mrPhysTab = phys_table;		/* Set pointer to the physical table for this bank */
		
		phys_table = phys_table + (pmap_mem_regions[bank].mrEnd - pmap_mem_regions[bank].mrStart + 1);	/* Point to the next */
	}

	addr += (((num * sizeof(struct phys_entry)) + 4095) & -4096);	/* Step on past the physical entries */
	
/*
 * 		Remaining space is for mapping entries.  Tell the initializer routine that
 * 		the mapping system can't release this block because it's permanently assigned
 */

	mapping_init();											/* Initialize the mapping tables */

	for(i = addr; i < first_used_addr + size; i += PAGE_SIZE) {	/* Add initial mapping blocks */
		mapping_free_init(i, 1, 0);							/* Pass block address and say that this one is not releasable */
	}
	mapCtl.mapcmin = MAPPERBLOK;							/* Make sure we only adjust one at a time */

	/* Map V=R the page tables */
	pmap_map(first_used_addr, first_used_addr,
		 round_page_32(first_used_addr + size), VM_PROT_READ | VM_PROT_WRITE);

	*first_avail = round_page_32(first_used_addr + size);		/* Set next available page */
	first_free_virt = *first_avail;							/* Ditto */

	/* All the rest of memory is free - add it to the free
	 * regions so that it can be allocated by pmap_steal
	 */

	pmap_mem_regions[0].mrAStart = (*first_avail >> 12);	/* Set up the free area to start allocations (always in the first bank) */

	current_free_region = 0;								/* Set that we will start allocating in bank 0 */
	avail_remaining = 0;									/* Clear free page count */
	for(bank = 0; bank < pmap_mem_regions_count; bank++) {	/* Total up all of the pages in the system that are available */
		avail_remaining += (pmap_mem_regions[bank].mrAEnd - pmap_mem_regions[bank].mrAStart) + 1;	/* Add in allocatable pages in this bank */
	}


}

/*
 * pmap_init(spa, epa)
 *	finishes the initialization of the pmap module.
 *	This procedure is called from vm_mem_init() in vm/vm_init.c
 *	to initialize any remaining data structures that the pmap module
 *	needs to map virtual memory (VM is already ON).
 *
 *	Note that the pmap needs to be sized and aligned to
 *	a power of two.  This is because it is used both in virtual and
 *	real so it can't span a page boundary.
 */

void
pmap_init(void)
{

	addr64_t cva;

	pmap_zone = zinit(pmapSize, 400 * pmapSize, 4096, "pmap");
#if	ZONE_DEBUG
	zone_debug_disable(pmap_zone);		/* Can't debug this one 'cause it messes with size and alignment */
#endif	/* ZONE_DEBUG */

	pmap_initialized = TRUE;

	/*
	 *	Initialize list of freed up pmaps
	 */
	free_pmap_list = 0;					/* Set that there are no free pmaps */
	free_pmap_count = 0;
	simple_lock_init(&free_pmap_lock, ETAP_VM_PMAP_CACHE);
	
}

unsigned int pmap_free_pages(void)
{
	return avail_remaining;
}

/*
 *	This function allocates physical pages.
 */

/* Non-optimal, but only used for virtual memory startup.
 * Allocate memory from a table of free physical addresses
 * If there are no more free entries, too bad. 
 */

boolean_t pmap_next_page(ppnum_t *addrp)
{
		int i;

	if(current_free_region >= pmap_mem_regions_count) return FALSE;	/* Return failure if we have used everything... */
	
	for(i = current_free_region; i < pmap_mem_regions_count; i++) {	/* Find the next bank with free pages */
		if(pmap_mem_regions[i].mrAStart <= pmap_mem_regions[i].mrAEnd) break;	/* Found one */
	}
	
	current_free_region = i;										/* Set our current bank */
	if(i >= pmap_mem_regions_count) return FALSE;					/* Couldn't find a free page */

	*addrp = pmap_mem_regions[i].mrAStart;					/* Allocate the page */
	pmap_mem_regions[i].mrAStart = pmap_mem_regions[i].mrAStart + 1;	/* Set the next one to go */
	avail_remaining--;												/* Drop free count */

	return TRUE;
}

void pmap_virtual_space(
	vm_offset_t *startp,
	vm_offset_t *endp)
{
	*startp = round_page_32(first_free_virt);
	*endp   = vm_last_addr;
}

/*
 * pmap_create
 *
 * Create and return a physical map.
 *
 * If the size specified for the map is zero, the map is an actual physical
 * map, and may be referenced by the hardware.
 *
 * A pmap is either in the free list or in the in-use list.  The only use
 * of the in-use list (aside from debugging) is to handle the VSID wrap situation.
 * Whenever a new pmap is allocated (i.e., not recovered from the free list). The
 * in-use list is matched until a hole in the VSID sequence is found. (Note
 * that the in-use pmaps are queued in VSID sequence order.) This is all done
 * while free_pmap_lock is held.
 *
 * If the size specified is non-zero, the map will be used in software 
 * only, and is bounded by that size.
 */
pmap_t
pmap_create(vm_size_t size)
{
	pmap_t pmap, ckpmap, fore, aft;
	int s, i;
	unsigned int currSID, hspace;
	addr64_t physpmap;

	/*
	 * A software use-only map doesn't even need a pmap structure.
	 */
	if (size)
		return(PMAP_NULL);

	/* 
	 * If there is a pmap in the pmap free list, reuse it. 
	 * Note that we use free_pmap_list for all chaining of pmaps, both to
	 * the free list and the in use chain (anchored from kernel_pmap).
	 */
	s = splhigh();
	simple_lock(&free_pmap_lock);
	
	if(free_pmap_list) {							/* Any free? */
		pmap = free_pmap_list;						/* Yes, allocate it */
		free_pmap_list = (pmap_t)pmap->freepmap;	/* Dequeue this one (we chain free ones through freepmap) */
		free_pmap_count--;
	}
	else {
		simple_unlock(&free_pmap_lock);				/* Unlock just in case */
		splx(s);

		pmap = (pmap_t) zalloc(pmap_zone);			/* Get one */
		if (pmap == PMAP_NULL) return(PMAP_NULL);	/* Handle out-of-memory condition */
		
		bzero((char *)pmap, pmapSize);				/* Clean up the pmap */
		
		s = splhigh();
		simple_lock(&free_pmap_lock);				/* Lock it back up	*/
		
		ckpmap = cursor_pmap;						/* Get starting point for free ID search */
		currSID = ckpmap->spaceNum;					/* Get the actual space ID number */

		while(1) {									/* Keep trying until something happens */
		
			currSID = (currSID + 1) & (maxAdrSp - 1);	/* Get the next in the sequence */
			if(((currSID * incrVSID) & (maxAdrSp - 1)) == invalSpace) continue;	/* Skip the space we have reserved */
			ckpmap = (pmap_t)ckpmap->pmap_link.next;	/* On to the next in-use pmap */
	
			if(ckpmap->spaceNum != currSID) break;	/* If we are out of sequence, this is free */
			
			if(ckpmap == cursor_pmap) {				/* See if we have 2^20 already allocated */
				panic("pmap_create: Maximum number (%d) active address spaces reached\n", maxAdrSp);	/* Die pig dog */
			}
		}

		pmap->space = (currSID * incrVSID) & (maxAdrSp - 1);	/* Calculate the actual VSID */
		pmap->spaceNum = currSID;					/* Set the space ID number */
/*
 *		Now we link into the chain just before the out of sequence guy.
 */

		fore = (pmap_t)ckpmap->pmap_link.prev;		/* Get the current's previous */
		pmap->pmap_link.next = (queue_t)ckpmap;		/* My next points to the current */
		fore->pmap_link.next = (queue_t)pmap;		/* Current's previous's next points to me */
		pmap->pmap_link.prev = (queue_t)fore;		/* My prev points to what the current pointed to */
		ckpmap->pmap_link.prev = (queue_t)pmap;		/* Current's prev points to me */

		simple_lock_init(&pmap->lock, ETAP_VM_PMAP);
		
		physpmap = ((addr64_t)pmap_find_phys(kernel_pmap, (addr64_t)pmap) << 12) | (addr64_t)((unsigned int)pmap & 0xFFF);	/* Get the physical address of the pmap */
		
		pmap->pmapvr = (addr64_t)((unsigned int)pmap) ^ physpmap;	/* Make V to R translation mask */
		
		pmapTrans[pmap->space].pmapPAddr = physpmap;	/* Set translate table physical to point to us */
		pmapTrans[pmap->space].pmapVAddr = pmap;	/* Set translate table virtual to point to us */
		
	}

	pmap->pmapFlags = pmapKeyDef;					/* Set default key */
	pmap->pmapCCtl = pmapCCtlVal;					/* Initialize cache control */
	pmap->ref_count = 1;
	pmap->stats.resident_count = 0;
	pmap->stats.wired_count = 0;
	pmap->pmapSCSubTag = 0x0000000000000000ULL;		/* Make sure this is clean an tidy */
	simple_unlock(&free_pmap_lock);

	splx(s);
	return(pmap);
}

/* 
 * pmap_destroy
 * 
 * Gives up a reference to the specified pmap.  When the reference count 
 * reaches zero the pmap structure is added to the pmap free list.
 *
 * Should only be called if the map contains no valid mappings.
 */
void
pmap_destroy(pmap_t pmap)
{
	int ref_count;
	spl_t s;
	pmap_t fore, aft;

	if (pmap == PMAP_NULL)
		return;

	ref_count=hw_atomic_sub(&pmap->ref_count, 1);			/* Back off the count */
	if(ref_count>0) return;									/* Still more users, leave now... */

	if(ref_count < 0)										/* Did we go too far? */
		panic("pmap_destroy(): ref_count < 0");
	
#ifdef notdef
	if(pmap->stats.resident_count != 0)
		panic("PMAP_DESTROY: pmap not empty");
#else
	if(pmap->stats.resident_count != 0) {
		pmap_remove(pmap, 0, 0xFFFFFFFFFFFFF000ULL);
	}
#endif

	/* 
	 * Add the pmap to the pmap free list. 
	 */

	s = splhigh();
	/* 
	 * Add the pmap to the pmap free list. 
	 */
	simple_lock(&free_pmap_lock);
	
	if (free_pmap_count <= free_pmap_max) {		/* Do we have enough spares? */
		
		pmap->freepmap = (struct blokmap *)free_pmap_list;	/* Queue in front */
		free_pmap_list = pmap;
		free_pmap_count++;
		simple_unlock(&free_pmap_lock);

	} else {
		if(cursor_pmap == pmap) cursor_pmap = (pmap_t)pmap->pmap_link.prev;	/* If we are releasing the cursor, back up */
		fore = (pmap_t)pmap->pmap_link.prev;
		aft  = (pmap_t)pmap->pmap_link.next;
		fore->pmap_link.next = pmap->pmap_link.next;	/* My previous's next is my next */
		aft->pmap_link.prev = pmap->pmap_link.prev;		/* My next's previous is my previous */	
		simple_unlock(&free_pmap_lock);
		pmapTrans[pmap->space].pmapPAddr = -1;			/* Invalidate the translate table physical */
		pmapTrans[pmap->space].pmapVAddr = -1;			/* Invalidate the translate table virtual */
		zfree(pmap_zone, (vm_offset_t) pmap);
	}
	splx(s);
}

/*
 * pmap_reference(pmap)
 *	gains a reference to the specified pmap.
 */
void
pmap_reference(pmap_t pmap)
{
	spl_t s;

	if (pmap != PMAP_NULL) hw_atomic_add(&pmap->ref_count, 1);	/* Bump the count */
}

/*
 * pmap_remove_some_phys
 *
 *	Removes mappings of the associated page from the specified pmap
 *
 */
void pmap_remove_some_phys(
	     pmap_t pmap,
	     vm_offset_t pa)
{
	register struct phys_entry 	*pp;
	register struct mapping 	*mp;
	unsigned int pindex;

	if (pmap == PMAP_NULL) {					/* This should never be called with a null pmap */
		panic("pmap_remove_some_phys: null pmap\n");
	}

	pp = mapping_phys_lookup(pa, &pindex);		/* Get physical entry */
	if (pp == 0) return;						/* Leave if not in physical RAM */

	while(1) {									/* Keep going until we toss all pages from this pmap */
		if (pmap->pmapFlags & pmapVMhost) {
			mp = hw_purge_phys(pp);				/* Toss a map */
			if(!mp ) return;					
			if((unsigned int)mp & mapRetCode) {		/* Was there a failure? */
				panic("pmap_remove_some_phys: hw_purge_phys failed - pp = %08X, pmap = %08X, code = %08X\n",
					pp, pmap, mp);
			}
		} else { 
			mp = hw_purge_space(pp, pmap);			/* Toss a map */
			if(!mp ) return;					
			if((unsigned int)mp & mapRetCode) {		/* Was there a failure? */
				panic("pmap_remove_some_phys: hw_purge_pmap failed - pp = %08X, pmap = %08X, code = %08X\n",
					pp, pmap, mp);
			}
		}
		mapping_free(mp);						/* Toss the mapping */
	}

	return;										/* Leave... */
}

/*
 * pmap_remove(pmap, s, e)
 *	unmaps all virtual addresses v in the virtual address
 *	range determined by [s, e) and pmap.
 *	s and e must be on machine independent page boundaries and
 *	s must be less than or equal to e.
 *
 *	Note that pmap_remove does not remove any mappings in nested pmaps. We just 
 *	skip those segments.
 */
void
pmap_remove(
	    pmap_t pmap,
	    addr64_t sva,
	    addr64_t eva)
{
	addr64_t		va, endva;

	if (pmap == PMAP_NULL) return;					/* Leave if software pmap */


	/* It is just possible that eva might have wrapped around to zero,
	 * and sometimes we get asked to liberate something of size zero
	 * even though it's dumb (eg. after zero length read_overwrites)
	 */
	assert(eva >= sva);

	/* If these are not page aligned the loop might not terminate */
	assert((sva == trunc_page_64(sva)) && (eva == trunc_page_64(eva)));

	va = sva & -4096LL;							/* Round start down to a page */
	endva = eva & -4096LL;						/* Round end down to a page */

	while(1) {									/* Go until we finish the range */
		va = mapping_remove(pmap, va);			/* Remove the mapping and see what's next */
		va = va & -4096LL;						/* Make sure the "not found" indication is clear */
		if((va == 0) || (va >= endva)) break;	/* End loop if we finish range or run off the end */
	}

}

/*
 *	Routine:
 *		pmap_page_protect
 *
 *	Function:
 *		Lower the permission for all mappings to a given page.
 */
void
pmap_page_protect(
	ppnum_t pa,
	vm_prot_t prot)
{
	register struct phys_entry 	*pp;
	boolean_t 			remove;
	unsigned int		pindex;
	mapping				*mp;


	switch (prot) {
		case VM_PROT_READ:
		case VM_PROT_READ|VM_PROT_EXECUTE:
			remove = FALSE;
			break;
		case VM_PROT_ALL:
			return;
		default:
			remove = TRUE;
			break;
	}


	pp = mapping_phys_lookup(pa, &pindex);	/* Get physical entry */
	if (pp == 0) return;						/* Leave if not in physical RAM */

	if (remove) {								/* If the protection was set to none, we'll remove all mappings */
		
		while(1) {								/* Keep going until we toss all pages from this physical page */
			mp = hw_purge_phys(pp);				/* Toss a map */
			if(!mp ) return;					
			if((unsigned int)mp & mapRetCode) {	/* Was there a failure? */
				panic("pmap_page_protect: hw_purge_phys failed - pp = %08X, code = %08X\n",
					pp, mp);
			}
			mapping_free(mp);					/* Toss the mapping */
		}

		return;									/* Leave... */
	}

/*	When we get here, it means that we are to change the protection for a 
 *	physical page.  
 */
 
	mapping_protect_phys(pa, prot & VM_PROT_ALL);	/* Change protection of all mappings to page. */

}

/*
 * pmap_protect(pmap, s, e, prot)
 *	changes the protection on all virtual addresses v in the 
 *	virtual address range determined by [s, e] and pmap to prot.
 *	s and e must be on machine independent page boundaries and
 *	s must be less than or equal to e.
 *
 *	Note that any requests to change the protection of a nested pmap are
 *	ignored. Those changes MUST be done by calling this with the correct pmap.
 */
void pmap_protect(
	     pmap_t pmap,
	     vm_offset_t sva, 
	     vm_offset_t eva,
	     vm_prot_t prot)
{

	addr64_t va, endva, nextva;

	if (pmap == PMAP_NULL) return;				/* Do nothing if no pmap */

	if (prot == VM_PROT_NONE) {					/* Should we kill the address range?? */
		pmap_remove(pmap, (addr64_t)sva, (addr64_t)eva);	/* Yeah, dump 'em */
		return;									/* Leave... */
	}

	va = sva & -4096LL;							/* Round start down to a page */
	endva = eva & -4096LL;						/* Round end down to a page */

	while(1) {									/* Go until we finish the range */
		(void)mapping_protect(pmap, va, prot & VM_PROT_ALL, &va);	/* Change the protection and see what's next */
		if((va == 0) || (va >= endva)) break;	/* End loop if we finish range or run off the end */
	}

}



/*
 * pmap_enter
 *
 * Create a translation for the virtual address (virt) to the physical
 * address (phys) in the pmap with the protection requested. If the
 * translation is wired then we can not allow a full page fault, i.e., 
 * the mapping control block is not eligible to be stolen in a low memory
 * condition.
 *
 * NB: This is the only routine which MAY NOT lazy-evaluate
 *     or lose information.  That is, this routine must actually
 *     insert this page into the given map NOW.
 */
void
pmap_enter(pmap_t pmap, vm_offset_t va, ppnum_t pa, vm_prot_t prot, 
		unsigned int flags, boolean_t wired)
{
	int					memattr;
	pmap_t				opmap;
	unsigned int		mflags;
	addr64_t			colva;
	
	if (pmap == PMAP_NULL) return;					/* Leave if software pmap */

	disable_preemption();							/* Don't change threads */

	mflags = 0;										/* Make sure this is initialized to nothing special */
	if(!(flags & VM_WIMG_USE_DEFAULT)) {			/* Are they supplying the attributes? */
		mflags = mmFlgUseAttr | (flags & VM_MEM_GUARDED) | ((flags & VM_MEM_NOT_CACHEABLE) >> 1);	/* Convert to our mapping_make flags */
	}
	
/*
 *	It is possible to hang here if another processor is remapping any pages we collide with and are removing
 */ 

	while(1) {										/* Keep trying the enter until it goes in */
	
		colva = mapping_make(pmap, va, pa, mflags, 1, prot & VM_PROT_ALL);	/* Enter the mapping into the pmap */
		
		if(!colva) break;							/* If there were no collisions, we are done... */
		
		mapping_remove(pmap, colva);				/* Remove the mapping that collided */
	}

	enable_preemption();							/* Thread change ok */

}

/*
 *		Enters translations for odd-sized V=F blocks.
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
 *		Note that pmap_map_block_rc is the same but doesn't panic if collision.
 *
 */
 
void pmap_map_block(pmap_t pmap, addr64_t va, ppnum_t pa, vm_size_t size, vm_prot_t prot, int attr, unsigned int flags) {	/* Map an autogenned block */

	int					memattr;
	unsigned int		mflags;
	addr64_t			colva;

	
	if (pmap == PMAP_NULL) {						/* Did they give us a pmap? */
		panic("pmap_map_block: null pmap\n");		/* No, like that's dumb... */
	}

//	kprintf("pmap_map_block: (%08X) va = %016llX, pa = %08X, size = %08X, prot = %08X, attr = %08X, flags = %08X\n", 	/* (BRINGUP) */
//		current_act(), va, pa, size, prot, attr, flags);	/* (BRINGUP) */


	mflags = mmFlgBlock | mmFlgUseAttr | (attr & VM_MEM_GUARDED) | ((attr & VM_MEM_NOT_CACHEABLE) >> 1);	/* Convert to our mapping_make flags */
	if(flags) mflags |= mmFlgPerm;					/* Mark permanent if requested */
	
	colva = mapping_make(pmap, va, pa, mflags, (size >> 12), prot);	/* Enter the mapping into the pmap */
	
	if(colva) {										/* If there was a collision, panic */
		panic("pmap_map_block: collision at %016llX, pmap = %08X\n", colva, pmap);
	}
	
	return;											/* Return */
}

int pmap_map_block_rc(pmap_t pmap, addr64_t va, ppnum_t pa, vm_size_t size, vm_prot_t prot, int attr, unsigned int flags) {	/* Map an autogenned block */

	int					memattr;
	unsigned int		mflags;
	addr64_t			colva;

	
	if (pmap == PMAP_NULL) {						/* Did they give us a pmap? */
		panic("pmap_map_block_rc: null pmap\n");	/* No, like that's dumb... */
	}

	mflags = mmFlgBlock | mmFlgUseAttr | (attr & VM_MEM_GUARDED) | ((attr & VM_MEM_NOT_CACHEABLE) >> 1);	/* Convert to our mapping_make flags */
	if(flags) mflags |= mmFlgPerm;					/* Mark permanent if requested */
	
	colva = mapping_make(pmap, va, pa, mflags, (size >> 12), prot);	/* Enter the mapping into the pmap */
	
	if(colva) return 0;								/* If there was a collision, fail */
	
	return 1;										/* Return true of we worked */
}

/*
 * pmap_extract(pmap, va)
 *	returns the physical address corrsponding to the 
 *	virtual address specified by pmap and va if the
 *	virtual address is mapped and 0 if it is not.
 *	Note: we assume nothing is ever mapped to phys 0.
 *
 *	NOTE: This call always will fail for physical addresses greater than 0xFFFFF000.
 */
vm_offset_t pmap_extract(pmap_t pmap, vm_offset_t va) {

	spl_t					spl;
	register struct mapping	*mp;
	register vm_offset_t	pa;
	addr64_t				nextva;
	ppnum_t					ppoffset;
	unsigned int			gva;

#ifdef BOGUSCOMPAT
	panic("pmap_extract: THIS CALL IS BOGUS. NEVER USE IT EVER. So there...\n");	/* Don't use this */
#else

	gva = (unsigned int)va;							/* Make sure we don't have a sign */

	spl = splhigh();								/* We can't allow any loss of control here */
	
	mp = mapping_find(pmap, (addr64_t)gva, &nextva,1);	/* Find the mapping for this address */
	
	if(!mp) {										/* Is the page mapped? */
		splx(spl);									/* Enable interrupts */
		return 0;									/* Pass back 0 if not found */
	}

	ppoffset = (ppnum_t)(((gva & -4096LL) - (mp->mpVAddr & -4096LL)) >> 12);	/* Get offset from va to base va */
	
	
	pa = mp->mpPAddr + ppoffset;					/* Remember ppage because mapping may vanish after drop call */
			
	mapping_drop_busy(mp);							/* We have everything we need from the mapping */
	splx(spl);										/* Restore 'rupts */

	if(pa > maxPPage32) return 0;					/* Force large addresses to fail */
	
	pa = (pa << 12) | (va & 0xFFF);					/* Convert physical page number to address */
	
#endif
	return pa;										/* Return physical address or 0 */
}

/*
 * ppnum_t pmap_find_phys(pmap, addr64_t va)
 *	returns the physical page corrsponding to the 
 *	virtual address specified by pmap and va if the
 *	virtual address is mapped and 0 if it is not.
 *	Note: we assume nothing is ever mapped to phys 0.
 *
 */
ppnum_t pmap_find_phys(pmap_t pmap, addr64_t va) {

	spl_t					spl;
	register struct mapping	*mp;
	ppnum_t					pa, ppoffset;
	addr64_t				nextva, curva;

	spl = splhigh();								/* We can't allow any loss of control here */
	
	mp = mapping_find(pmap, va, &nextva, 1);		/* Find the mapping for this address */
	
	if(!mp) {										/* Is the page mapped? */
		splx(spl);									/* Enable interrupts */
		return 0;									/* Pass back 0 if not found */
	}
		
	
	ppoffset = (ppnum_t)(((va & -4096LL) - (mp->mpVAddr & -4096LL)) >> 12);	/* Get offset from va to base va */
	
	pa = mp->mpPAddr + ppoffset;					/* Get the actual physical address */

	mapping_drop_busy(mp);							/* We have everything we need from the mapping */

	splx(spl);										/* Restore 'rupts */
	return pa;										/* Return physical address or 0 */
}


/*
 *	pmap_attributes:
 *
 *	Set/Get special memory attributes; not implemented.
 *
 *	Note: 'VAL_GET_INFO' is used to return info about a page.
 *	  If less than 1 page is specified, return the physical page
 *	  mapping and a count of the number of mappings to that page.
 *	  If more than one page is specified, return the number
 *	  of resident pages and the number of shared (more than
 *	  one mapping) pages in the range;
 *
 *
 */
kern_return_t
pmap_attribute(pmap, address, size, attribute, value)
	pmap_t			pmap;
	vm_offset_t		address;
	vm_size_t		size;
	vm_machine_attribute_t	attribute;
	vm_machine_attribute_val_t* value;	
{
	
	return KERN_INVALID_ARGUMENT;

}

/*
 * pmap_attribute_cache_sync(vm_offset_t pa)
 * 
 * Invalidates all of the instruction cache on a physical page and
 * pushes any dirty data from the data cache for the same physical page
 */
 
kern_return_t pmap_attribute_cache_sync(ppnum_t pp, vm_size_t size,
				vm_machine_attribute_t  attribute,
				vm_machine_attribute_val_t* value) {
	
	spl_t s;
	unsigned int i, npages;
	
	npages = round_page_32(size) >> 12;			/* Get the number of pages to do */
	
	for(i = 0; i < npages; i++) {				/* Do all requested pages */
		s = splhigh();							/* No interruptions here */
		sync_ppage(pp + i);						/* Go flush data cache and invalidate icache */
		splx(s);								/* Allow interruptions */
	}
	
	return KERN_SUCCESS;
}

/*
 * pmap_sync_caches_phys(ppnum_t pa)
 * 
 * Invalidates all of the instruction cache on a physical page and
 * pushes any dirty data from the data cache for the same physical page
 */
 
void pmap_sync_caches_phys(ppnum_t pa) {
	
	spl_t s;
	
	s = splhigh();								/* No interruptions here */
	sync_ppage(pa);								/* Sync up dem caches */
	splx(s);									/* Allow interruptions */
	return;
}

/*
 * pmap_collect
 * 
 * Garbage collects the physical map system for pages that are no longer used.
 * It isn't implemented or needed or wanted.
 */
void
pmap_collect(pmap_t pmap)
{
	return;
}

/*
 *	Routine:	pmap_activate
 *	Function:
 *		Binds the given physical map to the given
 *		processor, and returns a hardware map description.
 *		It isn't implemented or needed or wanted.
 */
void
pmap_activate(
	pmap_t pmap,
	thread_t th,
	int which_cpu)
{
	return;
}
/*
 * pmap_deactivate:
 * It isn't implemented or needed or wanted.
 */
void
pmap_deactivate(
	pmap_t pmap,
	thread_t th,
	int which_cpu)
{
	return;
}


/*
 * pmap_pageable(pmap, s, e, pageable)
 *	Make the specified pages (by pmap, offset)
 *	pageable (or not) as requested.
 *
 *	A page which is not pageable may not take
 *	a fault; therefore, its page table entry
 *	must remain valid for the duration.
 *
 *	This routine is merely advisory; pmap_enter()
 *	will specify that these pages are to be wired
 *	down (or not) as appropriate.
 *
 *	(called from vm/vm_fault.c).
 */
void
pmap_pageable(
	pmap_t		pmap,
	vm_offset_t	start,
	vm_offset_t	end,
	boolean_t	pageable)
{

	return;												/* This is not used... */

}
/*
 *	Routine:	pmap_change_wiring
 *	NOT USED ANYMORE.
 */
void
pmap_change_wiring(
	register pmap_t	pmap,
	vm_offset_t	va,
	boolean_t	wired)
{
	return;												/* This is not used... */
}

/*
 * pmap_modify_pages(pmap, s, e)
 *	sets the modified bit on all virtual addresses v in the 
 *	virtual address range determined by [s, e] and pmap,
 *	s and e must be on machine independent page boundaries and
 *	s must be less than or equal to e.
 *
 *  Note that this function will not descend nested pmaps.
 */
void
pmap_modify_pages(
	     pmap_t pmap,
	     vm_offset_t sva, 
	     vm_offset_t eva)
{
	spl_t		spl;
	mapping		*mp;
	ppnum_t		pa;
	addr64_t		va, endva, nextva;
	unsigned int	saveflags;

	if (pmap == PMAP_NULL) return;					/* If no pmap, can't do it... */
	
	va = sva & -4096;								/* Round to page */
	endva = eva & -4096;							/* Round to page */

	while (va < endva) {							/* Walk through all pages */

		spl = splhigh();							/* We can't allow any loss of control here */
	
		mp = mapping_find(pmap, (addr64_t)va, &va, 0);	/* Find the mapping for this address */
		
		if(!mp) {									/* Is the page mapped? */
			splx(spl);								/* Page not mapped, restore interruptions */
			if((va == 0) || (va >= endva)) break;	/* We are done if there are no more or we hit the end... */
			continue;								/* We are not done and there is more to check... */
		}
		
		saveflags = mp->mpFlags;					/* Remember the flags */
		pa = mp->mpPAddr;							/* Remember ppage because mapping may vanish after drop call */
	
		mapping_drop_busy(mp);						/* We have everything we need from the mapping */
	
		splx(spl);									/* Restore 'rupts */
	
		if(saveflags & (mpNest | mpBlock)) continue;	/* Can't mess around with these guys... */	
		
		mapping_set_mod(pa);						/* Set the modfied bit for this page */
		
		if(va == 0) break;							/* We hit the end of the pmap, might as well leave now... */
	}
	return;											/* Leave... */
}

/*
 * pmap_clear_modify(phys)
 *	clears the hardware modified ("dirty") bit for one
 *	machine independant page starting at the given
 *	physical address.  phys must be aligned on a machine
 *	independant page boundary.
 */
void
pmap_clear_modify(vm_offset_t pa)
{

	mapping_clr_mod((ppnum_t)pa);				/* Clear all change bits for physical page */

}

/*
 * pmap_is_modified(phys)
 *	returns TRUE if the given physical page has been modified 
 *	since the last call to pmap_clear_modify().
 */
boolean_t
pmap_is_modified(register vm_offset_t pa)
{
	return mapping_tst_mod((ppnum_t)pa);	/* Check for modified */
	
}

/*
 * pmap_clear_reference(phys)
 *	clears the hardware referenced bit in the given machine
 *	independant physical page.  
 *
 */
void
pmap_clear_reference(vm_offset_t pa)
{
	mapping_clr_ref((ppnum_t)pa);			/* Check for modified */
}

/*
 * pmap_is_referenced(phys)
 *	returns TRUE if the given physical page has been referenced 
 *	since the last call to pmap_clear_reference().
 */
boolean_t
pmap_is_referenced(vm_offset_t pa)
{
	return mapping_tst_ref((ppnum_t)pa);	/* Check for referenced */
}

/*
 * pmap_canExecute(ppnum_t pa)
 *  returns 1 if instructions can execute
 *  returns 0 if know not (i.e. guarded and/or non-executable set)
 *  returns -1 if we don't know (i.e., the page is no RAM)
 */
int
pmap_canExecute(ppnum_t pa)
{		
	phys_entry *physent;
	unsigned int pindex;

	physent = mapping_phys_lookup(pa, &pindex);				/* Get physical entry */

	if(!physent) return -1;									/* If there is no physical entry, we don't know... */

	if((physent->ppLink & (ppN | ppG))) return 0;			/* If we are marked non-executable or guarded, say we can not execute */
	return 1;												/* Good to go... */
}

#if	MACH_VM_DEBUG
int
pmap_list_resident_pages(
	register pmap_t		pmap,
	register vm_offset_t	*listp,
	register int		space)
{
	return 0;
}
#endif	/* MACH_VM_DEBUG */

/*
 * Locking:
 *	spl: VM
 */
void
pmap_copy_part_page(
	vm_offset_t	src,
	vm_offset_t	src_offset,
	vm_offset_t	dst,
	vm_offset_t	dst_offset,
	vm_size_t	len)
{
	register struct phys_entry *pp_src, *pp_dst;
	spl_t	s;
	addr64_t fsrc, fdst;

	assert(((dst <<12) & PAGE_MASK+dst_offset+len) <= PAGE_SIZE);
	assert(((src <<12) & PAGE_MASK+src_offset+len) <= PAGE_SIZE);

	fsrc = ((addr64_t)src << 12) + src_offset;
	fdst = ((addr64_t)dst << 12) + dst_offset;

	phys_copy(fsrc, fdst, len);								/* Copy the stuff physically */
}

void
pmap_zero_part_page(
	vm_offset_t	p,
	vm_offset_t     offset,
	vm_size_t       len)
{
    panic("pmap_zero_part_page");
}

boolean_t pmap_verify_free(ppnum_t pa) {

	struct phys_entry	*pp;
	unsigned int pindex;

	pp = mapping_phys_lookup(pa, &pindex);	/* Get physical entry */
	if (pp == 0) return FALSE;					/* If there isn't one, show no mapping... */

	if(pp->ppLink & ~(ppLock | ppN | ppFlags)) return TRUE;	/* We have at least one mapping */
	return FALSE;								/* No mappings */
}


/* Determine if we need to switch space and set up for it if so */

void pmap_switch(pmap_t map)
{
	unsigned int i;


	hw_blow_seg(copyIOaddr);					/* Blow off the first segment */
	hw_blow_seg(copyIOaddr + 0x10000000ULL);	/* Blow off the second segment */

/* when changing to kernel space, don't bother
 * doing anything, the kernel is mapped from here already.
 */
	if (map->space == PPC_SID_KERNEL) {			/* Are we switching into kernel space? */
		return;									/* If so, we don't do anything... */
	}
	
	hw_set_user_space(map);						/* Indicate if we need to load the SRs or not */
	return;										/* Bye, bye, butterfly... */
}

/*
 *	kern_return_t pmap_nest(grand, subord, vstart, size)
 *
 *	grand  = the pmap that we will nest subord into
 *	subord = the pmap that goes into the grand
 *	vstart  = start of range in pmap to be inserted
 *	nstart  = start of range in pmap nested pmap
 *	size   = Size of nest area (up to 16TB)
 *
 *	Inserts a pmap into another.  This is used to implement shared segments.
 *	On the current PPC processors, this is limited to segment (256MB) aligned
 *	segment sized ranges.
 *
 *	We actually kinda allow recursive nests.  The gating factor is that we do not allow 
 *	nesting on top of something that is already mapped, i.e., the range must be empty.
 *
 *	
 *
 *	Note that we depend upon higher level VM locks to insure that things don't change while
 *	we are doing this.  For example, VM should not be doing any pmap enters while it is nesting
 *	or do 2 nests at once.
 */

kern_return_t pmap_nest(pmap_t grand, pmap_t subord, addr64_t vstart, addr64_t nstart, uint64_t size) {
		
	addr64_t nextva, vend, colladdr;
	unsigned int msize;
	int i, nlists, asize;
	spl_t	s;
	mapping *mp;
	
	
	if(size & 0x0FFFFFFFULL) return KERN_INVALID_VALUE;	/* We can only do this for multiples of 256MB */
	if((size >> 28) > 65536)  return KERN_INVALID_VALUE;	/* Max size we can nest is 16TB */
	if(vstart & 0x0FFFFFFFULL) return KERN_INVALID_VALUE;	/* We can only do this aligned to 256MB */
	if(nstart & 0x0FFFFFFFULL) return KERN_INVALID_VALUE;	/* We can only do this aligned to 256MB */
	
	if(size == 0) {								/*	Is the size valid? */
		panic("pmap_nest: size is invalid - %016llX\n", size);
	}
	
	msize = (size >> 28) - 1;							/* Change size to blocks of 256MB */
	
	nlists = mapSetLists(grand);						/* Set number of lists this will be on */

	mp = mapping_alloc(nlists);							/* Get a spare mapping block */
	
	mp->mpFlags = 0x01000000 | mpNest | nlists;			/* Set the flags. Make sure busy count is 1 */
	mp->mpSpace = subord->space;						/* Set the address space/pmap lookup ID */
	mp->mpBSize = msize;								/* Set the size */
	mp->mpPte = 0;										/* Set the PTE invalid */
	mp->mpPAddr = 0;									/* Set the physical page number */
	mp->mpVAddr = vstart;								/* Set the address */
	mp->mpNestReloc = nstart - vstart;					/* Set grand to nested vaddr relocation value */
	
	colladdr = hw_add_map(grand, mp);					/* Go add the mapping to the pmap */
	
	if(colladdr) {										/* Did it collide? */
		vend = vstart + size - 4096;					/* Point to the last page we would cover in nest */	
		panic("pmap_nest: attempt to nest into a non-empty range - pmap = %08X, start = %016llX, end = %016llX\n",
			grand, vstart, vend);
	}
	
	return KERN_SUCCESS;
}

/*
 *	kern_return_t pmap_unnest(grand, vaddr)
 *
 *	grand  = the pmap that we will nest subord into
 *	vaddr  = start of range in pmap to be unnested
 *
 *	Removes a pmap from another.  This is used to implement shared segments.
 *	On the current PPC processors, this is limited to segment (256MB) aligned
 *	segment sized ranges.
 */

kern_return_t pmap_unnest(pmap_t grand, addr64_t vaddr) {
			
	unsigned int oflags, seg, grandr, tstamp;
	int i, tcpu, mycpu;
	addr64_t nextva;
	spl_t s;
	mapping *mp;
		
	s = splhigh();										/* Make sure interruptions are disabled */

	mp = mapping_find(grand, vaddr, &nextva, 0);		/* Find the nested map */

	if(((unsigned int)mp & mapRetCode) != mapRtOK) {	/* See if it was even nested */
		panic("pmap_unnest: Attempt to unnest an unnested segment - va = %016llX\n", vaddr);
	}

	if(!(mp->mpFlags & mpNest)) {						/* Did we find something other than a nest? */
		panic("pmap_unnest: Attempt to unnest something that is not a nest - va = %016llX\n", vaddr);
	}
	
	if(mp->mpVAddr != vaddr) {							/* Make sure the address is the same */
		panic("pmap_unnest: Attempt to unnest something that is not at start of nest - va = %016llX\n", vaddr);
	}

	(void)hw_atomic_or(&mp->mpFlags, mpRemovable);		/* Show that this mapping is now removable */
	
	mapping_drop_busy(mp);								/* Go ahead and relase the mapping now */

	disable_preemption();								/* It's all for me! */
	splx(s);											/* Restore 'rupts */
		
	(void)mapping_remove(grand, vaddr);					/* Toss the nested pmap mapping */
	
	invalidateSegs(grand);								/* Invalidate the pmap segment cache */
	
/*
 *	Note that the following will force the segment registers to be reloaded 
 *	on all processors (if they are using the pmap we just changed) before returning.
 *
 *	This is needed.  The reason is that until the segment register is 
 *	reloaded, another thread in the same task on a different processor will
 *	be able to access memory that it isn't allowed to anymore.  That can happen
 *	because access to the subordinate pmap is being removed, but the pmap is still
 *	valid.
 *
 *	Note that we only kick the other processor if we see that it was using the pmap while we
 *	were changing it.
 */


	mycpu = cpu_number();								/* Who am I? Am I just a dream? */
	for(i=0; i < real_ncpus; i++) {						/* Cycle through processors */
		if((unsigned int)grand == per_proc_info[i].ppUserPmapVirt) {	/* Is this guy using the changed pmap? */
			
			per_proc_info[i].ppInvSeg = 1;				/* Show that we need to invalidate the segments */
			
			if(i == mycpu) continue;					/* Don't diddle ourselves */
		
			tstamp = per_proc_info[i].ruptStamp[1];		/* Save the processor's last interrupt time stamp */
			if(cpu_signal(i, SIGPwake, 0, 0) != KERN_SUCCESS) {	/* Make sure we see the pmap change */
				continue;
			}
			
			if(!hw_cpu_wcng(&per_proc_info[i].ruptStamp[1], tstamp, LockTimeOut)) {	/* Wait for the other processors to enter debug */
				panic("pmap_unnest: Other processor (%d) did not see interruption request\n", i);
			}
		}
	}

	enable_preemption();								/* Others can run now */
	return KERN_SUCCESS;								/* Bye, bye, butterfly... */
}


/*
 *	void MapUserAddressSpaceInit(void)
 *
 *	Initialized anything we need to in order to map user address space slices into
 *	the kernel.  Primarily used for copy in/out.
 *
 *	Currently we only support one 512MB slot for this purpose.  There are two special
 *	mappings defined for the purpose: the special pmap nest, and linkage mapping.
 *
 *	The special pmap nest (which is allocated in this function) is used as a place holder
 *	in the kernel's pmap search list. It is 512MB long and covers the address range
 *	starting at copyIOaddr.  It points to no actual memory and when the fault handler 
 *	hits in it, it knows to look in the per_proc and start using the linkage
 *	mapping contained therin.
 *
 *	The linkage mapping is used to glue the user address space slice into the 
 *	kernel.  It contains the relocation information used to transform the faulting
 *	kernel address into the user address space.  It also provides the link to the
 *	user's pmap.  This is pointed to by the per_proc and is switched in and out
 *	whenever there is a context switch.
 *
 */

void MapUserAddressSpaceInit(void) {
		
	addr64_t colladdr;
	int nlists, asize;
	mapping *mp;
	
	nlists = mapSetLists(kernel_pmap);					/* Set number of lists this will be on */
	
	mp = mapping_alloc(nlists);							/* Get a spare mapping block */
	
	mp->mpFlags = 0x01000000 |mpNest | mpSpecial | nlists;	/* Set the flags. Make sure busy count is 1 */
	mp->mpSpace = kernel_pmap->space;					/* Set the address space/pmap lookup ID */
	mp->mpBSize = 1;									/* Set the size to 2 segments */
	mp->mpPte = 0;										/* Means nothing */
	mp->mpPAddr = 0;									/* Means nothing */
	mp->mpVAddr = copyIOaddr;							/* Set the address range we cover */
	mp->mpNestReloc = 0;								/* Means nothing */
	
	colladdr = hw_add_map(kernel_pmap, mp);				/* Go add the mapping to the pmap */
	
	if(colladdr) {										/* Did it collide? */
		panic("MapUserAddressSpaceInit: MapUserAddressSpace range already mapped\n");
	}
	
	return;
}

/*
 *	addr64_t MapUserAddressSpace(vm_map_t map, vm_offset_t va, size)
 *
 *	map  = the vm_map that we are mapping into the kernel
 *	va = start of the address range we are mapping
 *	size  = size of the range.  No greater than 256MB and not 0.
 *	Note that we do not test validty, we chose to trust our fellows...
 *
 *	Maps a slice of a user address space into a predefined kernel range
 *	on a per-thread basis.  In the future, the restriction of a predefined
 *	range will be loosened.
 *
 *	Builds the proper linkage map to map the user range
 *  We will round this down to the previous segment boundary and calculate
 *	the relocation to the kernel slot
 *
 *	We always make a segment table entry here if we need to.  This is mainly because of
 *	copyin/out and if we don't, there will be multiple segment faults for
 *	each system call.  I have seen upwards of 30000 per second.
 *
 *	We do check, however, to see if the slice is already mapped and if so,
 *	we just exit.  This is done for performance reasons.  It was found that 
 *	there was a considerable boost in copyin/out performance if we did not
 *	invalidate the segment at ReleaseUserAddressSpace time, so we dumped the
 *	restriction that you had to bracket MapUserAddressSpace.  Further, there 
 *	is a yet further boost if you didn't need to map it each time.  The theory
 *	behind this is that many times copies are to or from the same segment and
 *	done multiple times within the same system call.  To take advantage of that,
 *	we check cioSpace and cioRelo to see if we've already got it.  
 *
 *	We also need to half-invalidate the slice when we context switch or go
 *	back to user state.  A half-invalidate does not clear the actual mapping,
 *	but it does force the MapUserAddressSpace function to reload the segment
 *	register/SLBE.  If this is not done, we can end up some pretty severe
 *	performance penalties. If we map a slice, and the cached space/relocation is
 *	the same, we won't reload the segment registers.  Howver, since we ran someone else,
 *	our SR is cleared and we will take a fault.  This is reasonable if we block
 *	while copying (e.g., we took a page fault), but it is not reasonable when we 
 *	just start.  For this reason, we half-invalidate to make sure that the SR is
 *	explicitly reloaded.
 *	 
 *	Note that we do not go to the trouble of making a pmap segment cache
 *	entry for these guys because they are very short term -- 99.99% of the time
 *	they will be unmapped before the next context switch.
 *
 */

addr64_t MapUserAddressSpace(vm_map_t map, addr64_t va, unsigned int size) {
		
	addr64_t baddrs, reladd;
	thread_act_t act;
	mapping *mp;
	struct per_proc_info *perproc;
	
	baddrs = va & 0xFFFFFFFFF0000000ULL;				/* Isolate the segment */
	act = current_act();								/* Remember our activation */

	reladd = baddrs - copyIOaddr;						/* Get the relocation from user to kernel */
	
	if((act->mact.cioSpace == map->pmap->space) && (act->mact.cioRelo == reladd)) {	/* Already mapped? */
		return ((va & 0x0FFFFFFFULL) | copyIOaddr);		/* Pass back the kernel address we are to use */
	}

	disable_preemption();								/* Don't move... */	
	perproc = getPerProc();								/* Get our per_proc_block */
	
	mp = (mapping *)&perproc->ppCIOmp;					/* Make up for C */
	act->mact.cioRelo = reladd;							/* Relocation from user to kernel */
	mp->mpNestReloc = reladd;							/* Relocation from user to kernel */
	
	act->mact.cioSpace = map->pmap->space;				/* Set the address space/pmap lookup ID */
	mp->mpSpace = map->pmap->space;						/* Set the address space/pmap lookup ID */
	
/*
 *	Here we make an assumption that we are going to be using the base pmap's address space.
 *	If we are wrong, and that would be very, very, very rare, the fault handler will fix us up.
 */ 

	hw_map_seg(map->pmap,  copyIOaddr, baddrs);			/* Make the entry for the first segment */

	enable_preemption();								/* Let's move */
	return ((va & 0x0FFFFFFFULL) | copyIOaddr);			/* Pass back the kernel address we are to use */
}

/*
 *	void ReleaseUserAddressMapping(addr64_t kva)
 *
 *	kva = kernel address of the user copy in/out slice
 *
 */

void ReleaseUserAddressSpace(addr64_t kva) {
		
	int i;
	addr64_t nextva, vend, kaddr, baddrs;
	unsigned int msize;
	thread_act_t act;
	mapping *mp;
	
	if(kva == 0) return;								/* Handle a 0 */
		
	disable_preemption();								/* Don't move... */
	
	act = current_act();								/* Remember our activation */

	if(act->mact.cioSpace == invalSpace) {				/* We only support one at a time */
		panic("ReleaseUserAddressMapping: attempt release undefined copy in/out user address space slice\n");
	}

	act->mact.cioSpace = invalSpace;					/* Invalidate space */
	mp = (mapping *)&per_proc_info[cpu_number()].ppCIOmp;	/* Make up for C */
	mp->mpSpace = invalSpace;							/* Trash it in the per_proc as well */
	
	hw_blow_seg(copyIOaddr);							/* Blow off the first segment */
	hw_blow_seg(copyIOaddr + 0x10000000ULL);			/* Blow off the second segment */
	
	enable_preemption();								/* Let's move */
	
	return;												/* Let's leave */
}



/*
 *	kern_return_t pmap_boot_map(size)
 *
 *	size   = size of virtual address range to be mapped
 *
 *	This function is used to assign a range of virtual addresses before VM in 
 *	initialized.  It starts at VM_MAX_KERNEL_ADDRESS and works downward.
 *	The variable vm_last_addr contains the current highest possible VM
 *	assignable address.  It is a panic to attempt to call this after VM has
 *	started up.  The only problem is, is that we may not have the serial or
 *	framebuffer mapped, so we'll never know we died.........
 */

vm_offset_t pmap_boot_map(vm_size_t size) {
			
	if(kernel_map != VM_MAP_NULL) {				/* Has VM already started? */
		panic("pmap_boot_map: VM started\n");
	}
	
	size = round_page_32(size);					/* Make sure this is in pages */
	vm_last_addr = vm_last_addr - size;			/* Allocate the memory */
	return (vm_last_addr + 1);					/* Return the vaddr we just allocated */

}



/* temporary workaround */
boolean_t
coredumpok(vm_map_t map, vm_offset_t va)
{
  return TRUE;
}

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
#include <kern/spl.h>

#include <kern/misc_protos.h>
#include <ppc/misc_protos.h>
#include <ppc/proc_reg.h>

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>

#include <ppc/pmap.h>
#include <ppc/pmap_internals.h>
#include <ppc/mem.h>
#include <ppc/mappings.h>

#include <ppc/new_screen.h>
#include <ppc/Firmware.h>
#include <ppc/savearea.h>
#include <ppc/exception.h>
#include <ddb/db_output.h>

#if	DB_MACHINE_COMMANDS
/* optionally enable traces of pmap operations in post-mortem trace table */
/* #define PMAP_LOWTRACE 1 */
#define PMAP_LOWTRACE 0
#else	/* DB_MACHINE_COMMANDS */
/* Can not trace even if we wanted to */
#define PMAP_LOWTRACE 0
#endif	/* DB_MACHINE_COMMANDS */

#define PERFTIMES 0

#if PERFTIMES && DEBUG
#define debugLog2(a, b, c) dbgLog2(a, b, c)
#else
#define debugLog2(a, b, c)
#endif

extern unsigned int	avail_remaining;
extern unsigned int	mappingdeb0;
extern	struct 	Saveanchor saveanchor;						/* Aliged savearea anchor */
extern int 		real_ncpus;									/* Number of actual CPUs */
unsigned int debugbackpocket;								/* (TEST/DEBUG) */

vm_offset_t		avail_next;
vm_offset_t		first_free_virt;
int          	current_free_region;						/* Used in pmap_next_page */

/* forward */
void pmap_activate(pmap_t pmap, thread_t th, int which_cpu);
void pmap_deactivate(pmap_t pmap, thread_t th, int which_cpu);
void copy_to_phys(vm_offset_t sva, vm_offset_t dpa, int bytecount);

#if MACH_VM_DEBUG
int pmap_list_resident_pages(pmap_t pmap, vm_offset_t *listp, int space);
#endif

#if DEBUG
#define PDB_USER	0x01	/* exported functions */
#define PDB_MAPPING	0x02	/* low-level mapping routines */
#define PDB_ENTER	0x04	/* pmap_enter specifics */
#define PDB_COPY	0x08	/* copy page debugging */
#define PDB_ZERO	0x10	/* zero page debugging */
#define PDB_WIRED	0x20	/* things concerning wired entries */
#define PDB_PTEG	0x40	/* PTEG overflows */
#define PDB_LOCK	0x100	/* locks */
#define PDB_IO		0x200	/* Improper use of WIMG_IO checks - PCI machines */

int pmdebug=0;
#endif

/*  NOTE:  kernel_pmap_store must be in V=R storage and aligned!!!!!!!!!!!!!! */

extern struct pmap	kernel_pmap_store;
pmap_t		kernel_pmap;			/* Pointer to kernel pmap and anchor for in-use pmaps */		
pmap_t		cursor_pmap;			/* Pointer to last pmap allocated or previous if removed from in-use list */
struct zone	*pmap_zone;				/* zone of pmap structures */
boolean_t	pmap_initialized = FALSE;

/*
 * Physical-to-virtual translations are handled by inverted page table
 * structures, phys_tables.  Multiple mappings of a single page are handled
 * by linking the affected mapping structures. We initialise one region
 * for phys_tables of the physical memory we know about, but more may be
 * added as it is discovered (eg. by drivers).
 */
struct phys_entry *phys_table;		/* For debugging */

lock_t	pmap_system_lock;

decl_simple_lock_data(,tlb_system_lock)

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

struct phys_entry *pmap_find_physentry(vm_offset_t pa)
{
	int i;
	struct phys_entry *entry;

	for (i = pmap_mem_regions_count-1; i >= 0; i--) {
		if (pa < pmap_mem_regions[i].start)
			continue;
		if (pa >= pmap_mem_regions[i].end)
			return PHYS_NULL;
		
		entry = &pmap_mem_regions[i].phys_table[(pa - pmap_mem_regions[i].start) >> PPC_PGSHIFT];
		__asm__ volatile("dcbt 0,%0" : : "r" (entry));	/* We will use this in a little bit */
		return entry;
	}
	kprintf("DEBUG : pmap_find_physentry 0x%08x out of range\n",pa);
	return PHYS_NULL;
}

/*
 * kern_return_t
 * pmap_add_physical_memory(vm_offset_t spa, vm_offset_t epa,
 *                          boolean_t available, unsigned int attr)
 *	Allocate some extra physentries for the physical addresses given,
 *	specifying some default attribute that on the powerpc specifies
 *      the default cachability for any mappings using these addresses
 *	If the memory is marked as available, it is added to the general
 *	VM pool, otherwise it is not (it is reserved for card IO etc).
 */
kern_return_t pmap_add_physical_memory(vm_offset_t spa, vm_offset_t epa,
				       boolean_t available, unsigned int attr)
{
	int i,j;
	spl_t s;

	/* Only map whole pages */
	
	panic("Forget it! You can't map no more memory, you greedy puke!\n");

	spa = trunc_page(spa);
	epa = round_page(epa);

	/* First check that the region doesn't already exist */

	assert (epa >= spa);
	for (i = 0; i < pmap_mem_regions_count; i++) {
		/* If we're below the next region, then no conflict */
		if (epa < pmap_mem_regions[i].start)
			break;
		if (spa < pmap_mem_regions[i].end) {
#if DEBUG
			kprintf("pmap_add_physical_memory(0x%08x,0x%08x,0x%08x) - memory already present\n",spa,epa,attr);
#endif /* DEBUG */
			return KERN_NO_SPACE;
		}
	}

#if DEBUG
	kprintf("pmap_add_physical_memory; region insert spot: %d out of %d\n", i, pmap_mem_regions_count);	/* (TEST/DEBUG) */
#endif

	/* Check that we've got enough space for another region */
	if (pmap_mem_regions_count == PMAP_MEM_REGION_MAX)
		return KERN_RESOURCE_SHORTAGE;

	/* Once here, i points to the mem_region above ours in physical mem */

	/* allocate a new phys_table for this new region */
#if DEBUG
	kprintf("pmap_add_physical_memory; kalloc\n");	/* (TEST/DEBUG) */
#endif

	phys_table =  (struct phys_entry *)
		kalloc(sizeof(struct phys_entry) * atop(epa-spa));
#if DEBUG
	kprintf("pmap_add_physical_memory; new phys_table: %08X\n", phys_table);	/* (TEST/DEBUG) */
#endif

	/* Initialise the new phys_table entries */
	for (j = 0; j < atop(epa-spa); j++) {
		
		phys_table[j].phys_link = MAPPING_NULL;
		
		mapping_phys_init(&phys_table[j], spa+(j*PAGE_SIZE), attr);	/* Initialize the hardware specific portions */

	}
	s = splhigh();
	
	/* Move all the phys_table entries up some to make room in
	 * the ordered list.
	 */
	for (j = pmap_mem_regions_count; j > i ; j--)
		pmap_mem_regions[j] = pmap_mem_regions[j-1];

	/* Insert a new entry with some memory to back it */

	pmap_mem_regions[i].start 	     = spa;
	pmap_mem_regions[i].end           = epa;
	pmap_mem_regions[i].phys_table    = phys_table;

	pmap_mem_regions_count++;
	splx(s);
	
#if DEBUG
	for(i=0; i<pmap_mem_regions_count; i++) {			/* (TEST/DEBUG) */
		kprintf("region %d: %08X %08X %08X\n", i, pmap_mem_regions[i].start,
			pmap_mem_regions[i].end, pmap_mem_regions[i].phys_table);	/* (TEST/DEBUG) */
	}
#endif

	if (available) {
		kprintf("warning : pmap_add_physical_mem() "
		       "available not yet supported\n");
	}

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
 */
vm_offset_t
pmap_map(
	vm_offset_t va,
	vm_offset_t spa,
	vm_offset_t epa,
	vm_prot_t prot)
{


	if (spa == epa)
		return(va);

	assert(epa > spa);
	debugLog2(40, va, spa);								/* Log pmap_map call */

	pmap_map_block(kernel_pmap, va, spa, epa - spa, prot, PTE_WIMG_DEFAULT, blkPerm);	/* Set up a permanent block mapped area */

	debugLog2(41, epa, prot);							/* Log pmap_map call */

	return(va);
}

/*
 * pmap_map_bd(va, spa, epa, prot)
 *	Back-door routine for mapping kernel VM at initialisation.
 *	Used for mapping memory outside the known physical memory
 *      space, with caching disabled. Designed for use by device probes.
 * 
 *	A virtual address range starting at "va" is mapped to the physical
 *	address range "spa" to "epa" with machine independent protection
 *	"prot".
 *
 *	"va", "spa", and "epa" are byte addresses and must be on machine
 *	independent page boundaries.
 *
 * WARNING: The current version of memcpy() can use the dcbz instruction
 * on the destination addresses.  This will cause an alignment exception
 * and consequent overhead if the destination is caching-disabled.  So
 * avoid memcpy()ing into the memory mapped by this function.
 *
 * also, many other pmap_ routines will misbehave if you try and change
 * protections or remove these mappings, they are designed to be permanent.
 *
 * These areas will be added to the autogen list, if possible.  Existing translations
 * are overridden and their mapping stuctures are released.  This takes place in
 * the autogen_map function.
 *
 * Locking:
 *	this routine is called only during system initialization when only
 *	one processor is active, so no need to take locks...
 */
vm_offset_t
pmap_map_bd(
	vm_offset_t va,
	vm_offset_t spa,
	vm_offset_t epa,
	vm_prot_t prot)
{
	register struct mapping *mp;
	register struct phys_entry 	*pp;
	

	if (spa == epa)
		return(va);

	assert(epa > spa);

	debugLog2(42, va, epa);								/* Log pmap_map_bd call */

	pmap_map_block(kernel_pmap, va, spa, epa - spa, prot, PTE_WIMG_IO, blkPerm);	/* Set up autogen area */

	debugLog2(43, epa, prot);							/* Log pmap_map_bd exit */

	return(va);
}

/*
 *	Bootstrap the system enough to run with virtual memory.
 *	Map the kernel's code and data, and allocate the system page table.
 *	Called with mapping done by BATs. Page_size must already be set.
 *
 *	Parameters:
 *	mem_size:	Total memory present
 *	first_avail:	First virtual address available
 *	first_phys_avail:	First physical address available
 */
void
pmap_bootstrap(unsigned int mem_size, vm_offset_t *first_avail, vm_offset_t *first_phys_avail, unsigned int kmapsize)
{
	register struct mapping *mp;
	vm_offset_t 	addr;
	vm_size_t 		size;
	int 			i, num, j, rsize, mapsize, vmpagesz, vmmapsz;
	unsigned int	 mask;
	vm_offset_t		first_used_addr;
	PCA				*pcaptr;

	*first_avail = round_page(*first_avail);
	
#if DEBUG
	kprintf("first_avail=%08X; first_phys_avail=%08X; avail_remaining=%d\n", 
		*first_avail, *first_phys_avail, avail_remaining);
#endif

	assert(PAGE_SIZE == PPC_PGBYTES);

	/*
	 * Initialize kernel pmap
	 */
	kernel_pmap = &kernel_pmap_store;
	cursor_pmap = &kernel_pmap_store;

	lock_init(&pmap_system_lock,
		  FALSE,		/* NOT a sleep lock */
		  ETAP_VM_PMAP_SYS,
		  ETAP_VM_PMAP_SYS_I);

	simple_lock_init(&kernel_pmap->lock, ETAP_VM_PMAP_KERNEL);

	kernel_pmap->pmap_link.next = (queue_t)kernel_pmap;		/* Set up anchor forward */
	kernel_pmap->pmap_link.prev = (queue_t)kernel_pmap;		/* Set up anchor reverse */
	kernel_pmap->ref_count = 1;
	kernel_pmap->space = PPC_SID_KERNEL;
	kernel_pmap->pmapvr = 0;						/* Virtual = Real  */
	kernel_pmap->bmaps = 0;							/* No block pages just yet */
	for(i=0; i < 128; i++) {						/* Clear usage slots */
		kernel_pmap->pmapUsage[i] = 0;
	}
	for(i=0; i < 16; i++) {							/* Initialize for laughs */
		kernel_pmap->pmapSegs[i] = SEG_REG_PROT | (i << 20) | PPC_SID_KERNEL;
	}

	/*
	 * Allocate: (from first_avail up)
	 *      Aligned to its own size:
     	 *       hash table (for mem size 2**x, allocate 2**(x-10) entries)
	 *	 mapping table (same size and immediatly following hash table)
	 */
	/* hash_table_size must be a power of 2, recommended sizes are
	 * taken from PPC601 User Manual, table 6-19. We take the next
	 * highest size if mem_size is not a power of two.
	 * TODO NMGS make this configurable at boot time.
	 */

	num = sizeof(pte_t) * (mem_size >> 10);

	for (hash_table_size = 64 * 1024;	/* minimum size = 64Kbytes */
	     hash_table_size < num; 
	     hash_table_size *= 2)
		continue;

	/* Scale to within any physical memory layout constraints */
	do {
		num = atop(mem_size);	/* num now holds mem_size in pages */

		/* size of all structures that we're going to allocate */

		size = (vm_size_t) (
			(InitialSaveBloks * PAGE_SIZE) +	/* Allow space for the initial context saveareas */
			((InitialSaveBloks / 2) * PAGE_SIZE) +	/* For backpocket saveareas */
			hash_table_size +					/* For hash table */
			hash_table_size +					/* For PTEG allocation table */
			(num * sizeof(struct phys_entry))	/* For the physical entries */
			);

		mapsize = size = round_page(size);		/* Get size of area to map that we just calculated */
		mapsize = mapsize + kmapsize;			/* Account for the kernel text size */

		vmpagesz = round_page(num * sizeof(struct vm_page));	/* Allow for all vm_pages needed to map physical mem */
		vmmapsz = round_page((num / 8) * sizeof(struct vm_map_entry));	/* Allow for vm_maps */
		
		mapsize = mapsize + vmpagesz + vmmapsz;	/* Add the VM system estimates into the grand total */

		mapsize = mapsize + (4 * 1024 * 1024);	/* Allow for 4 meg of extra mappings */
		mapsize = ((mapsize / PAGE_SIZE) + MAPPERBLOK - 1) / MAPPERBLOK;	/* Get number of blocks of mappings we need */
		mapsize = mapsize + ((mapsize  + MAPPERBLOK - 1) / MAPPERBLOK);	/* Account for the mappings themselves */

#if DEBUG
		kprintf("pmap_bootstrap: initial vm_pages     = %08X\n", vmpagesz);
		kprintf("pmap_bootstrap: initial vm_maps      = %08X\n", vmmapsz);
		kprintf("pmap_bootstrap: size before mappings = %08X\n", size);
		kprintf("pmap_bootstrap: kernel map size      = %08X\n", kmapsize);
		kprintf("pmap_bootstrap: mapping blocks rqrd  = %08X\n", mapsize);
#endif
		
		size = size + (mapsize * PAGE_SIZE);	/* Get the true size we need */

		/* hash table must be aligned to its size */

		addr = (*first_avail +
			(hash_table_size-1)) & ~(hash_table_size-1);

		if (addr + size > pmap_mem_regions[0].end) {
			hash_table_size /= 2;
		} else {
			break;
		}
		/* If we have had to shrink hash table to too small, panic */
		if (hash_table_size == 32 * 1024)
			panic("cannot lay out pmap memory map correctly");
	} while (1);
	
#if DEBUG
	kprintf("hash table size=%08X, total size of area=%08X, addr=%08X\n", 
		hash_table_size, size, addr);
#endif
	if (round_page(*first_phys_avail) < trunc_page(addr)) {
		/* We are stepping over at least one page here, so
		 * add this region to the free regions so that it can
		 * be allocated by pmap_steal
		 */
		free_regions[free_regions_count].start = round_page(*first_phys_avail);
		free_regions[free_regions_count].end = trunc_page(addr);

		avail_remaining += (free_regions[free_regions_count].end -
				    free_regions[free_regions_count].start) /
					    PPC_PGBYTES;
#if DEBUG
		kprintf("ADDED FREE REGION from 0x%08x to 0x%08x, avail_remaining = %d\n",
			free_regions[free_regions_count].start,free_regions[free_regions_count].end, 
			avail_remaining);
#endif /* DEBUG */
		free_regions_count++;
	}

	/* Zero everything - this also invalidates the hash table entries */
	bzero((char *)addr, size);

	/* Set up some pointers to our new structures */

	/* from here,  addr points to the next free address */
	
	first_used_addr = addr;	/* remember where we started */

	/* Set up hash table address and dma buffer address, keeping
	 * alignment. These mappings are all 1-1,  so dma_r == dma_v
	 * 
	 * If hash_table_size == dma_buffer_alignment, then put hash_table
	 * first, since dma_buffer_size may be smaller than alignment, but
	 * hash table alignment==hash_table_size.
	 */
	hash_table_base = addr;
		
	addr += hash_table_size;
	addr += hash_table_size;							/* Add another for the PTEG Control Area */
	assert((hash_table_base & (hash_table_size-1)) == 0);

	pcaptr = (PCA *)(hash_table_base+hash_table_size);	/* Point to the PCA table */
	mapCtl.mapcflush.pcaptr = pcaptr;
	
	for(i=0; i < (hash_table_size/64) ; i++) {			/* For all of PTEG control areas: */
		pcaptr[i].flgs.PCAalflgs.PCAfree=0xFF;			/* Mark all slots free */
		pcaptr[i].flgs.PCAalflgs.PCAsteal=0x01;			/* Initialize steal position */
	}
	
 	savearea_init(&addr);								/* Initialize the savearea chains and data */
 
	/* phys_table is static to help debugging,
	 * this variable is no longer actually used
	 * outside of this scope
	 */

	phys_table = (struct phys_entry *) addr;

#if DEBUG
	kprintf("hash_table_base                 =%08X\n", hash_table_base);
	kprintf("phys_table                      =%08X\n", phys_table);
	kprintf("pmap_mem_regions_count          =%08X\n", pmap_mem_regions_count);
#endif

	for (i = 0; i < pmap_mem_regions_count; i++) {
		
		pmap_mem_regions[i].phys_table = phys_table;
		rsize = (pmap_mem_regions[i].end - (unsigned int)pmap_mem_regions[i].start)/PAGE_SIZE;
		
#if DEBUG
		kprintf("Initializing physical table for region %d\n", i);
		kprintf("   table=%08X, size=%08X, start=%08X, end=%08X\n",
			phys_table, rsize, pmap_mem_regions[i].start, 
			(unsigned int)pmap_mem_regions[i].end);
#endif		
		
		for (j = 0; j < rsize; j++) {
			phys_table[j].phys_link = MAPPING_NULL;
			mapping_phys_init(&phys_table[j], (unsigned int)pmap_mem_regions[i].start+(j*PAGE_SIZE), 
				PTE_WIMG_DEFAULT);						/* Initializes hw specific storage attributes */
		}
		phys_table = phys_table +
			atop(pmap_mem_regions[i].end - pmap_mem_regions[i].start);
	}

	/* restore phys_table for debug */
	phys_table = (struct phys_entry *) addr;

	addr += sizeof(struct phys_entry) * num;
	
	simple_lock_init(&tlb_system_lock, ETAP_VM_PMAP_TLB);

	/* Initialise the registers necessary for supporting the hashtable */
#if DEBUG
	kprintf("*** hash_table_init: base=%08X, size=%08X\n", hash_table_base, hash_table_size);
#endif

	hash_table_init(hash_table_base, hash_table_size);
			
/*
 * 		Remaining space is for mapping entries.  Tell the initializer routine that
 * 		the mapping system can't release this block because it's permanently assigned
 */

	mapping_init();									/* Initialize the mapping tables */

	for(i = addr; i < first_used_addr + size; i += PAGE_SIZE) {	/* Add initial mapping blocks */
		mapping_free_init(i, 1, 0);					/* Pass block address and say that this one is not releasable */
	}
	mapCtl.mapcmin = MAPPERBLOK;					/* Make sure we only adjust one at a time */

#if DEBUG

	kprintf("mapping kernel memory from 0x%08x to 0x%08x, to address 0x%08x\n",
		 first_used_addr, round_page(first_used_addr+size),
		 first_used_addr);
#endif /* DEBUG */

	/* Map V=R the page tables */
	pmap_map(first_used_addr, first_used_addr,
		 round_page(first_used_addr+size), VM_PROT_READ | VM_PROT_WRITE);

#if DEBUG

	for(i=first_used_addr; i < round_page(first_used_addr+size); i+=PAGE_SIZE) {	/* Step through all these mappings */
		if(i != (j = kvtophys(i))) {							/* Verify that the mapping was made V=R */
			kprintf("*** V=R mapping failed to verify: V=%08X; R=%08X\n", i, j);
		}
	}
#endif

	*first_avail = round_page(first_used_addr + size);
	first_free_virt = round_page(first_used_addr + size);

	/* All the rest of memory is free - add it to the free
	 * regions so that it can be allocated by pmap_steal
	 */
	free_regions[free_regions_count].start = *first_avail;
	free_regions[free_regions_count].end = pmap_mem_regions[0].end;

	avail_remaining += (free_regions[free_regions_count].end -
			    free_regions[free_regions_count].start) /
				    PPC_PGBYTES;

#if DEBUG
	kprintf("ADDED FREE REGION from 0x%08x to 0x%08x, avail_remaining = %d\n",
		free_regions[free_regions_count].start,free_regions[free_regions_count].end, 
		avail_remaining);
#endif /* DEBUG */

	free_regions_count++;

	current_free_region = 0;

	avail_next = free_regions[current_free_region].start;
	
#if DEBUG
	kprintf("Number of free regions=%d\n",free_regions_count);	/* (TEST/DEBUG) */
	kprintf("Current free region=%d\n",current_free_region);	/* (TEST/DEBUG) */
	for(i=0;i<free_regions_count; i++) {					/* (TEST/DEBUG) */
		kprintf("Free region %3d - from %08X to %08X\n", i, free_regions[i].start,
			free_regions[i].end);							/* (TEST/DEBUG) */
	}
	for (i = 0; i < pmap_mem_regions_count; i++) {			/* (TEST/DEBUG) */
		kprintf("PMAP region %3d - from %08X to %08X; phys=%08X\n", i,	/* (TEST/DEBUG) */
			pmap_mem_regions[i].start,						/* (TEST/DEBUG) */
			pmap_mem_regions[i].end,						/* (TEST/DEBUG) */
			pmap_mem_regions[i].phys_table);				/* (TEST/DEBUG) */
	}
#endif

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

boolean_t pmap_next_page(vm_offset_t *addrp)
{
	/* Non optimal, but only used for virtual memory startup.
     * Allocate memory from a table of free physical addresses
	 * If there are no more free entries, too bad. We have two
	 * tables to look through, free_regions[] which holds free
	 * regions from inside pmap_mem_regions[0], and the others...
	 * pmap_mem_regions[1..]
     */
	 
	/* current_free_region indicates the next free entry,
	 * if it's less than free_regions_count, then we're still
	 * in free_regions, otherwise we're in pmap_mem_regions
	 */

	if (current_free_region >= free_regions_count) {
		/* We're into the pmap_mem_regions, handle this
		 * separately to free_regions
		 */

		int current_pmap_mem_region = current_free_region -
					 free_regions_count + 1;
		if (current_pmap_mem_region > pmap_mem_regions_count)
			return FALSE;
		*addrp = avail_next;
		avail_next += PAGE_SIZE;
		avail_remaining--;
		if (avail_next >= pmap_mem_regions[current_pmap_mem_region].end) {
			current_free_region++;
			current_pmap_mem_region++;
			avail_next = pmap_mem_regions[current_pmap_mem_region].start;
#if DEBUG
			kprintf("pmap_next_page : next region start=0x%08x\n",avail_next);
#endif /* DEBUG */
		}
		return TRUE;
	}
	
	/* We're in the free_regions, allocate next page and increment
	 * counters
	 */
	*addrp = avail_next;

	avail_next += PAGE_SIZE;
	avail_remaining--;

	if (avail_next >= free_regions[current_free_region].end) {
		current_free_region++;
		if (current_free_region < free_regions_count)
			avail_next = free_regions[current_free_region].start;
		else
			avail_next = pmap_mem_regions[current_free_region -
						 free_regions_count + 1].start;
#if DEBUG
		kprintf("pmap_next_page : next region start=0x%08x\n",avail_next);
#endif 
	}
	return TRUE;
}

void pmap_virtual_space(
	vm_offset_t *startp,
	vm_offset_t *endp)
{
	*startp = round_page(first_free_virt);
	*endp   = VM_MAX_KERNEL_ADDRESS;
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
	space_t sid;
	unsigned int currSID;

#if PMAP_LOWTRACE
	dbgTrace(0xF1D00001, size, 0);			/* (TEST/DEBUG) */
#endif

#if DEBUG
	if (pmdebug & PDB_USER)
		kprintf("pmap_create(size=%x)%c", size, size ? '\n' : ' ');
#endif

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
	
	if(free_pmap_list) {					/* Any free? */
		pmap = free_pmap_list;				/* Yes, allocate it */
		free_pmap_list = (pmap_t)pmap->bmaps;	/* Dequeue this one (we chain free ones through bmaps) */
		free_pmap_count--;
	}
	else {
		simple_unlock(&free_pmap_lock);		/* Unlock just in case */
		splx(s);

		pmap = (pmap_t) zalloc(pmap_zone);	/* Get one */
		if (pmap == PMAP_NULL) return(PMAP_NULL);	/* Handle out-of-memory condition */
		
		bzero((char *)pmap, pmapSize);		/* Clean up the pmap */
		
		s = splhigh();
		simple_lock(&free_pmap_lock);		/* Lock it back up	*/
		
		ckpmap = cursor_pmap;				/* Get starting point for free ID search */
		currSID = ckpmap->spaceNum;			/* Get the actual space ID number */

		while(1) {							/* Keep trying until something happens */
		
			currSID = (currSID + 1) & SID_MAX;	/* Get the next in the sequence */
			ckpmap = (pmap_t)ckpmap->pmap_link.next;	/* On to the next in-use pmap */
	
			if(ckpmap->spaceNum != currSID) break;	/* If we are out of sequence, this is free */
			
			if(ckpmap == cursor_pmap) {		/* See if we have 2^20 already allocated */
				panic("pmap_create: Maximum number (2^20) active address spaces reached\n");	/* Die pig dog */
			}
		}

		pmap->space = (currSID * incrVSID) & SID_MAX;	/* Calculate the actual VSID */
		pmap->spaceNum = currSID;			/* Set the space ID number */

/*
 *		Now we link into the chain just before the out of sequence guy.
 */

		fore = (pmap_t)ckpmap->pmap_link.prev;	/* Get the current's previous */
		pmap->pmap_link.next = (queue_t)ckpmap;	/* My next points to the current */
		fore->pmap_link.next = (queue_t)pmap;	/* Current's previous's next points to me */
		pmap->pmap_link.prev = (queue_t)fore;	/* My prev points to what the current pointed to */
		ckpmap->pmap_link.prev = (queue_t)pmap;	/* Current's prev points to me */

		simple_lock_init(&pmap->lock, ETAP_VM_PMAP);
		pmap->pmapvr = (unsigned int)pmap ^ (unsigned int)pmap_extract(kernel_pmap, (vm_offset_t)pmap);	/* Get physical pointer to the pmap and make mask */
	}
	pmap->ref_count = 1;
	pmap->stats.resident_count = 0;
	pmap->stats.wired_count = 0;
	pmap->bmaps = 0;						/* Clear block map pointer to 0 */
	pmap->vflags = 0;						/* Mark all alternates invalid for now */
	for(i=0; i < 128; i++) {				/* Clean out usage slots */
		pmap->pmapUsage[i] = 0;
	}
	for(i=0; i < 16; i++) {					/* Initialize for laughs */
		pmap->pmapSegs[i] = SEG_REG_PROT | (i << 20) | pmap->space;
	}
	
#if PMAP_LOWTRACE
	dbgTrace(0xF1D00002, (unsigned int)pmap, (unsigned int)pmap->space);	/* (TEST/DEBUG) */
#endif

#if DEBUG
	if (pmdebug & PDB_USER)
		kprintf("-> %x, space id = %d\n", pmap, pmap->space);
#endif

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

#if PMAP_LOWTRACE
	dbgTrace(0xF1D00003, (unsigned int)pmap, 0);			/* (TEST/DEBUG) */
#endif

#if DEBUG
	if (pmdebug & PDB_USER)
		kprintf("pmap_destroy(pmap=%x)\n", pmap);
#endif

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
		pmap_remove(pmap, 0, 0xFFFFF000);
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
	
	if (free_pmap_count <= free_pmap_max) {					/* Do we have enough spares? */
		
		pmap->bmaps = (struct blokmap *)free_pmap_list;		/* Queue in front */
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

#if PMAP_LOWTRACE
	dbgTrace(0xF1D00004, (unsigned int)pmap, 0);			/* (TEST/DEBUG) */
#endif

#if DEBUG
	if (pmdebug & PDB_USER)
		kprintf("pmap_reference(pmap=%x)\n", pmap);
#endif

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
	register struct mapping 	*mp, *mpv;


	if (pmap == PMAP_NULL) return;				/* Do nothing if no pmap */

	pp = pmap_find_physentry(pa);				/* Get the physent for this page */
	if (pp == PHYS_NULL) return;				/* Leave if not in physical RAM */

	mapping_purge_pmap(pp, pmap);	

	return;							/* Leave... */
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
	    vm_offset_t sva,
	    vm_offset_t eva)
{
	spl_t			spl;
	struct mapping	*mp, *blm;
	vm_offset_t		lpage;

#if PMAP_LOWTRACE
	dbgTrace(0xF1D00005, (unsigned int)pmap, sva|((eva-sva)>>12));	/* (TEST/DEBUG) */
#endif

#if DEBUG
	if (pmdebug & PDB_USER)
		kprintf("pmap_remove(pmap=%x, sva=%x, eva=%x)\n",
		       pmap, sva, eva);
#endif

	if (pmap == PMAP_NULL)
		return;

	/* It is just possible that eva might have wrapped around to zero,
	 * and sometimes we get asked to liberate something of size zero
	 * even though it's dumb (eg. after zero length read_overwrites)
	 */
	assert(eva >= sva);

	/* If these are not page aligned the loop might not terminate */
	assert((sva == trunc_page(sva)) && (eva == trunc_page(eva)));

	/* We liberate addresses from high to low, since the stack grows
	 * down. This means that we won't need to test addresses below
	 * the limit of stack growth
	 */

	debugLog2(44, sva, eva);					/* Log pmap_map call */
	
	sva = trunc_page(sva);						/* Make it clean */
	lpage = trunc_page(eva) - PAGE_SIZE;		/* Point to the last page contained in the range */

/*
 *	Here we will remove all of the block mappings that overlap this range.
 *	hw_rem_blk removes one mapping in the range and returns.  If it returns
 *	0, there are no blocks in the range.
 */

	while(mp = (mapping *)hw_rem_blk(pmap, sva, lpage)) {	/* Keep going until no more */
		if((unsigned int)mp & 1) {							/* Make sure we don't unmap a permanent one */
			blm = (struct mapping  *)hw_cpv((mapping *)((unsigned int)mp & 0xFFFFFFFC));		/* Get virtual address */
			panic("mapping_remove: attempt to unmap a permanent mapping - pmap = %08X, va = %08X, mapping = %08X\n",
				pmap, sva, blm);
		}
		if (!((unsigned int)mp & 2))
			mapping_free(hw_cpv(mp));							/* Release it */
	}
	while (pmap->stats.resident_count && (eva > sva)) {

		eva -= PAGE_SIZE;						/* Back up a page */

#if 1
		if((0x00008000 >> (sva >> 28)) & pmap->vflags)
		   panic("pmap_remove: attempt to remove nested vaddr; pmap = %08X, vaddr = %08X\n", pmap, sva);	/* (TEST/DEBUG) panic */
#endif
		if(!(pmap->pmapUsage[(eva >> pmapUsageShft) & pmapUsageMask])) {	/* See if this chunk has anything in it */
			eva = eva & (-pmapUsageSize);		/* Back up into the previous slot */
			continue;							/* Check the next... */
		}
		mapping_remove(pmap, eva);				/* Remove the mapping for this address */
	}

	debugLog2(45, 0, 0);						/* Log pmap_map call */
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
	vm_offset_t pa,
	vm_prot_t prot)
{
	register struct phys_entry 	*pp;
	boolean_t 			remove;


#if PMAP_LOWTRACE
	dbgTrace(0xF1D00006, (unsigned int)pa, (unsigned int)prot);	/* (TEST/DEBUG) */
#endif

#if DEBUG
	if (pmdebug & PDB_USER)
		kprintf("pmap_page_protect(pa=%x, prot=%x)\n", pa, prot);
#endif

	debugLog2(46, pa, prot);					/* Log pmap_page_protect call */

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

	pp = pmap_find_physentry(pa);				/* Get the physent for this page */
	if (pp == PHYS_NULL) return;				/* Leave if not in physical RAM */

	if (remove) {								/* If the protection was set to none, we'll remove all mappings */
		mapping_purge(pp);						/* Get rid of them all */

		debugLog2(47, 0, 0);					/* Log pmap_map call */
		return;									/* Leave... */
	}
	
	/*	When we get here, it means that we are to change the protection for a 
	 *	physical page.  
	 */
	 
	mapping_protect_phys(pp, prot, 0);			/* Change protection of all mappings to page. */

	debugLog2(47, 1, 0);						/* Log pmap_map call */
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
	spl_t						spl;
	register struct phys_entry 	*pp;
	register struct mapping 	*mp, *mpv;

#if PMAP_LOWTRACE
	dbgTrace(0xF1D00008, (unsigned int)pmap, (unsigned int)(sva|((eva-sva)>>12)));	/* (TEST/DEBUG) */
#endif

#if DEBUG
	if (pmdebug & PDB_USER)
		kprintf("pmap_protect(pmap=%x, sva=%x, eva=%x, prot=%x)\n", pmap, sva, eva, prot);
	
	assert(sva < eva);
#endif

	if (pmap == PMAP_NULL) return;				/* Do nothing if no pmap */

	debugLog2(48, sva, eva);					/* Log pmap_map call */

	if (prot == VM_PROT_NONE) {					/* Should we kill the address range?? */
		pmap_remove(pmap, sva, eva);			/* Yeah, dump 'em */

		debugLog2(49, prot, 0);								/* Log pmap_map call */

		return;									/* Leave... */
	}

	sva = trunc_page(sva);						/* Start up a page boundary */
	
	while(sva < eva) {							/* Step through */

		if(!(pmap->pmapUsage[(sva >> pmapUsageShft) & pmapUsageMask])) {	/* See if this chunk has anything in it */
			sva = (sva + pmapUsageSize) &(-pmapUsageSize);	/* Jump up into the next slot if nothing here */
			if(!sva) break;						/* We tried to wrap, kill loop... */
			continue;							/* Check the next... */
		}

#if 1
		if((0x00008000 >> (sva >> 28)) & pmap->vflags)
		   panic("pmap_protect: attempt to protect nested vaddr; pmap = %08X, vaddr = %08X\n", pmap, sva);	/* (TEST/DEBUG) panic */
#endif

		mapping_protect(pmap, sva, prot);		/* Change the protection on the page */
		sva += PAGE_SIZE;						/* On to the next page */
	}

	debugLog2(49, prot, 1);						/* Log pmap_map call */
	return;										/* Leave... */
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
pmap_enter(pmap_t pmap, vm_offset_t va, vm_offset_t pa, vm_prot_t prot, 
		unsigned int flags, boolean_t wired)
{
	spl_t				spl;
	struct mapping		*mp;
	struct phys_entry	*pp;
	int					memattr;
	
#if PMAP_LOWTRACE
	dbgTrace(0xF1D00009, (unsigned int)pmap, (unsigned int)va);	/* (TEST/DEBUG) */
	dbgTrace(0xF1D04009, (unsigned int)pa, (unsigned int)prot);	/* (TEST/DEBUG) */
#endif		
	
	if (pmap == PMAP_NULL) return;					/* If they gave us no pmap, just leave... */

	debugLog2(50, va, pa);							/* Log pmap_map call */

	pp = pmap_find_physentry(pa);					/* Get the physent for this physical page */

	if((0x00008000 >> (va >> 28)) & pmap->vflags)
	   panic("pmap_enter: attempt to map into nested vaddr; pmap = %08X, vaddr = %08X\n", pmap, va);	/* (TEST/DEBUG) panic */

	spl=splhigh();									/* Have to disallow interrupts between the
													   time we possibly clear a mapping and the time
													   we get it remapped again.  An I/O SLIH could
													   try to drive an IOR using the page before
													   we get it mapped (Dude! This was a tough 
													   bug!!!!) */

	mapping_remove(pmap, va);						/* Remove any other mapping at this address */

	if(flags & VM_WIMG_USE_DEFAULT) {
	    if(pp) {
			/* Set attr to the phys default */
			memattr = ((pp->pte1&0x00000078) >> 3);	
		} else {
			memattr = PTE_WIMG_UNCACHED_COHERENT_GUARDED;
		}
	} else {
		memattr = flags & VM_WIMG_MASK;
	}
	

	/* Make the address mapping */
	mp=mapping_make(pmap, pp, va, pa, prot, memattr, 0);	

	splx(spl);										/* I'm not busy no more - come what may */

	debugLog2(51, prot, 0);							/* Log pmap_map call */

#if	DEBUG
	if (pmdebug & (PDB_USER|PDB_ENTER))
		kprintf("leaving pmap_enter\n");
#endif

}

/*
 * pmap_extract(pmap, va)
 *	returns the physical address corrsponding to the 
 *	virtual address specified by pmap and va if the
 *	virtual address is mapped and 0 if it is not.
 */
vm_offset_t pmap_extract(pmap_t pmap, vm_offset_t va) {

	spl_t					spl;
	register struct mapping	*mp, *mpv;
	register vm_offset_t	pa;
	unsigned int			seg;
	pmap_t					actpmap;


#if PMAP_LOWTRACE
	dbgTrace(0xF1D0000B, (unsigned int)pmap, (unsigned int)va);	/* (TEST/DEBUG) */
#endif
#if DEBUG
	if (pmdebug & PDB_USER)
		kprintf("pmap_extract(pmap=%x, va=%x)\n", pmap, va);
#endif

	seg = va >> 28;									/* Isolate segment */
	if((0x00008000 >> seg) & pmap->vflags) actpmap = pmap->pmapPmaps[seg];	/* Set nested pmap if there is one */
	else actpmap = pmap;							/* Otherwise use the one passed in */

	pa = (vm_offset_t) 0;							/* Clear this to 0 */ 

	debugLog2(52, actpmap->space, va);					/* Log pmap_map call */

	spl = splhigh();								/* We can't allow any loss of control here */

	if(mp=hw_lock_phys_vir(actpmap->space, va)) {	/* Find the mapping for this vaddr and lock physent */	
		if((unsigned int)mp&1) {					/* Did the lock on the phys entry time out? */
			panic("pmap_extract: timeout obtaining lock on physical entry\n");	/* Scream bloody murder! */
			splx(spl);								/* Interruptions are cool now */
			return 0;
		}

		mpv = hw_cpv(mp);							/* Get virtual address of mapping */
		pa = (vm_offset_t)((mpv->PTEr & -PAGE_SIZE) | ((unsigned int)va & (PAGE_SIZE-1)));	/* Build the physical address */
		if(mpv->physent) hw_unlock_bit((unsigned int *)&mpv->physent->phys_link, PHYS_LOCK);	/* Unlock the physical entry */
		splx(spl);									/* Interruptions are cool now */

		debugLog2(53, pa, 0);						/* Log pmap_map call */

		return pa;									/* Return the physical address... */
	}

	pa = hw_cvp_blk(pmap, va);						/* Try to convert odd-sized page (returns 0 if not found) */
													/* Note no nested pmaps here */
	splx(spl);										/* Restore 'rupts */
	debugLog2(53, pa, 0);							/* Log pmap_map call */
	return pa;										/* Return physical address or 0 */
}

/*
 *	pmap_attribute_cache_sync
 *	Handle the machine attribute calls which involve sync the prcessor
 *	cache.
 */
kern_return_t
pmap_attribute_cache_sync(address, size, attribute, value)
	vm_offset_t	address;
	vm_size_t	size;
	vm_machine_attribute_t	attribute;
	vm_machine_attribute_val_t* value;	
{
	while(size) {
		switch (*value) {					/* What type was that again? */
			case MATTR_VAL_CACHE_SYNC:			/* It is sync I+D caches */
				sync_cache(address, PAGE_SIZE);		/* Sync up dem caches */
				break;					/* Done with this one here... */
						
			case MATTR_VAL_CACHE_FLUSH:			/* It is flush from all caches */
				flush_dcache(address, PAGE_SIZE, TRUE);	/* Flush out the data cache */
				invalidate_icache(address, 
						PAGE_SIZE, TRUE);	/* Flush out the instruction cache */
				break;					/* Done with this one here... */
				
			case MATTR_VAL_DCACHE_FLUSH:			/* It is flush from data cache(s) */
				flush_dcache(address, PAGE_SIZE, TRUE);	/* Flush out the data cache */
				break;					/* Done with this one here... */

			case MATTR_VAL_ICACHE_FLUSH:			/* It is flush from instr cache(s) */
				invalidate_icache(address, 
						PAGE_SIZE, TRUE);	/* Flush out the instruction cache */
				break;					/* Done with this one here... */
		}
		size -= PAGE_SIZE;
	}
	return KERN_SUCCESS;;
}
	

/*
 *	pmap_attributes:
 *
 *	Set/Get special memory attributes; Set is not implemented.
 *
 *	Note: 'VAL_GET_INFO' is used to return info about a page.
 *	  If less than 1 page is specified, return the physical page
 *	  mapping and a count of the number of mappings to that page.
 *	  If more than one page is specified, return the number
 *	  of resident pages and the number of shared (more than
 *	  one mapping) pages in the range;
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
	spl_t			s;
	vm_offset_t 	sva, eva;
	vm_offset_t		pa;
	kern_return_t	ret;
	register struct mapping	*mp, *mpv;
	register struct phys_entry *pp;
	int 			total, seg;
	pmap_t			actpmap;

	if (attribute != MATTR_CACHE)
		return KERN_INVALID_ARGUMENT;

	/* We can't get the caching attribute for more than one page
	 * at a time
	 */
	if ((*value == MATTR_VAL_GET) &&
	    (trunc_page(address) != trunc_page(address+size-1)))
		return KERN_INVALID_ARGUMENT;

	if (pmap == PMAP_NULL)
		return KERN_SUCCESS;

	sva = trunc_page(address);
	eva = round_page(address + size);
	ret = KERN_SUCCESS;

	debugLog2(54, address, attribute);						/* Log pmap_map call */

	switch (*value) {
		case MATTR_VAL_CACHE_SYNC:							/* sync I+D caches */
		case MATTR_VAL_CACHE_FLUSH:							/* flush from all caches */
		case MATTR_VAL_DCACHE_FLUSH:						/* flush from data cache(s) */
		case MATTR_VAL_ICACHE_FLUSH:						/* flush from instr cache(s) */
			sva = trunc_page(sva);
			s = splhigh();

			while (sva < eva) {	
				seg = sva >> 28;							/* Isolate segment */
				if((0x00008000 >> seg) & pmap->vflags) actpmap = pmap->pmapPmaps[seg];	/* Set nested pmap if there is one */
				else actpmap = pmap;						/* Otherwise use the one passed in */
			
/*
 *				Note: the following should work ok with nested pmaps because there are not overlayed mappings 
 */
				if(!(actpmap->pmapUsage[(sva >> pmapUsageShft) & pmapUsageMask])) {	/* See if this chunk has anything in it */
					sva = (sva + pmapUsageSize) & (-pmapUsageSize);	/* Jump up into the next slot if nothing here */
					if(!sva) break;							/* We tried to wrap, kill loop... */
					continue;								/* Check the next... */
				}

				if(!(mp = hw_lock_phys_vir(actpmap->space, sva))) {	/* Find the mapping for this vaddr and lock physent */
 					sva += PAGE_SIZE;						/* Point to the next page */
					continue;								/* Skip if the page is not mapped... */
				}

				if((unsigned int)mp&1) {					/* Did the lock on the phys entry time out? */
					panic("pmap_attribute: timeout obtaining lock on physical entry\n");	/* Scream bloody murder! */
					continue;
				}
				
				mpv = hw_cpv(mp);							/* Get virtual address of mapping */
				if((unsigned int)mpv->physent) {			/* Is there a physical entry? */
					pa = (vm_offset_t)mpv->physent->pte1 & -PAGE_SIZE;	/* Yes, get the physical address from there */
				} 
				else {
					pa = (vm_offset_t)(mpv->PTEr & PAGE_SIZE);	/* Otherwise from the mapping */
				}

				switch (*value) {							/* What type was that again? */
					case MATTR_VAL_CACHE_SYNC:				/* It is sync I+D caches */
						sync_cache(pa, PAGE_SIZE);			/* Sync up dem caches */
						break;								/* Done with this one here... */
					
					case MATTR_VAL_CACHE_FLUSH:				/* It is flush from all caches */
						flush_dcache(pa, PAGE_SIZE, TRUE);	/* Flush out the data cache */
						invalidate_icache(pa, PAGE_SIZE, TRUE);	/* Flush out the instruction cache */
						break;								/* Done with this one here... */
					
					case MATTR_VAL_DCACHE_FLUSH:			/* It is flush from data cache(s) */
						flush_dcache(pa, PAGE_SIZE, TRUE);	/* Flush out the data cache */
						break;								/* Done with this one here... */

					case MATTR_VAL_ICACHE_FLUSH:			/* It is flush from instr cache(s) */
						invalidate_icache(pa, PAGE_SIZE, TRUE);	/* Flush out the instruction cache */
						break;								/* Done with this one here... */
				}
				if(mpv->physent) hw_unlock_bit((unsigned int *)&mpv->physent->phys_link, PHYS_LOCK);	/* Unlock the physical entry if it exists*/
 				
 				sva += PAGE_SIZE;							/* Point to the next page */
			}
			splx(s);
			break;

		case MATTR_VAL_GET_INFO:							/* Get info */
			total = 0;
			s = splhigh();									/* Lock 'em out */
		
			if (size <= PAGE_SIZE) {						/* Do they want just one page */
				seg = sva >> 28;							/* Isolate segment */
				if((0x00008000 >> seg) & pmap->vflags) actpmap = pmap->pmapPmaps[seg];	/* Set nested pmap if there is one */
				else actpmap = pmap;						/* Otherwise use the one passed in */
				if(!(mp = hw_lock_phys_vir(actpmap->space, sva))) {	/* Find the mapping for this vaddr and lock physent */
					*value = 0;								/* Return nothing if no mapping */
				}
				else {
					if((unsigned int)mp&1) {				/* Did the lock on the phys entry time out? */
						panic("pmap_attribute: timeout obtaining lock on physical entry\n");	/* Scream bloody murder! */
					}
					mpv = hw_cpv(mp);						/* Get virtual address of mapping */
					if(pp = mpv->physent) {					/* Check for a physical entry */
						total = 0;							/* Clear the count */
						for (mpv = (mapping *)hw_cpv((mapping *)((unsigned int)pp->phys_link & ~PHYS_FLAGS)); mpv != NULL; mpv = hw_cpv(mp->next)) total++;	/* Count the mapping */
						*value = (vm_machine_attribute_val_t) ((pp->pte1 & -PAGE_SIZE) | total);	/* Pass back the physical address and the count of mappings */
						hw_unlock_bit((unsigned int *)&pp->phys_link, PHYS_LOCK);	/* Clear the physical entry lock */
					}
					else {									/* This is the case for an I/O mapped area */
						*value = (vm_machine_attribute_val_t) ((mpv->PTEr & -PAGE_SIZE) | 1);	/* Pass back the physical address and the count of mappings */
					}
				}
			}
			else {
				total = 0;
				while (sva < eva) {
					seg = sva >> 28;						/* Isolate segment */
					if((0x00008000 >> seg) & pmap->vflags) actpmap = pmap->pmapPmaps[seg];	/* Set nested pmap if there is one */
					else actpmap = pmap;					/* Otherwise use the one passed in */
					
					if(!(actpmap->pmapUsage[(sva >> pmapUsageShft) & pmapUsageMask])) {	/* See if this chunk has anything in it */
						sva = (sva + pmapUsageSize) & (-pmapUsageSize);	/* Jump up into the next slot if nothing here */
						if(!sva) break;						/* We tried to wrap, kill loop... */
						continue;							/* Check the next... */
					}
					if(mp = hw_lock_phys_vir(actpmap->space, sva)) {	/* Find the mapping for this vaddr and lock physent */
						if((unsigned int)mp&1) {			/* Did the lock on the phys entry time out? */
							panic("pmap_attribute: timeout obtaining lock on physical entry\n");	/* Scream bloody murder! */
							continue;
						}
						mpv = hw_cpv(mp);					/* Get virtual address of mapping */
						total += 65536 + (mpv->physent && ((mapping *)((unsigned int)mpv->physent->phys_link & -32))->next);	/* Count the "resident" and shared pages */
						hw_unlock_bit((unsigned int *)&mpv->physent->phys_link, PHYS_LOCK);	/* Clear the physical entry lock */
					}
					sva += PAGE_SIZE;
				}
				*value = total;
			}
			splx(s);
			break;
	
		case MATTR_VAL_GET:		/* return current value */
		case MATTR_VAL_OFF:		/* turn attribute off */
		case MATTR_VAL_ON:		/* turn attribute on */
		default:
			ret = KERN_INVALID_ARGUMENT;
			break;
	}

	debugLog2(55, 0, 0);					/* Log pmap_map call */

	return ret;
}

/*
 * pmap_sync_caches_phys(vm_offset_t pa)
 * 
 * Invalidates all of the instruction cache on a physical page and
 * pushes any dirty data from the data cache for the same physical page
 */
 
void pmap_sync_caches_phys(vm_offset_t pa) {
	
	spl_t s;

	s = splhigh();						/* No interruptions here */
	sync_cache(trunc_page(pa), PAGE_SIZE);			/* Sync up dem caches */
	splx(s);							/* Allow interruptions */
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

#if DEBUG

/*
 * pmap_zero_page
 * pmap_copy page
 * 
 * are implemented in movc.s, these
 * are just wrappers to help debugging
 */

extern void pmap_zero_page_assembler(vm_offset_t p);
extern void pmap_copy_page_assembler(vm_offset_t src, vm_offset_t dst);

/*
 * pmap_zero_page(pa)
 *
 * pmap_zero_page zeros the specified (machine independent) page pa.
 */
void
pmap_zero_page(
	vm_offset_t p)
{
	register struct mapping *mp;
	register struct phys_entry *pp;

	if (pmdebug & (PDB_USER|PDB_ZERO))
		kprintf("pmap_zero_page(pa=%x)\n", p);

	/*
	 * XXX can these happen?
	 */
	if (pmap_find_physentry(p) == PHYS_NULL)
		panic("zero_page: physaddr out of range");

	pmap_zero_page_assembler(p);
}

/*
 * pmap_copy_page(src, dst)
 *
 * pmap_copy_page copies the specified (machine independent)
 * page from physical address src to physical address dst.
 *
 * We need to invalidate the cache for address dst before
 * we do the copy. Apparently there won't be any mappings
 * to the dst address normally.
 */
void
pmap_copy_page(
	vm_offset_t src,
	vm_offset_t dst)
{
	register struct phys_entry *pp;

	if (pmdebug & (PDB_USER|PDB_COPY))
		kprintf("pmap_copy_page(spa=%x, dpa=%x)\n", src, dst);
	if (pmdebug & PDB_COPY)
		kprintf("pmap_copy_page: phys_copy(%x, %x, %x)\n",
		       src, dst, PAGE_SIZE);

	pmap_copy_page_assembler(src, dst);
}
#endif /* DEBUG */

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
 *	NOTE USED ANYMORE.
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
 */
void
pmap_modify_pages(
	     pmap_t pmap,
	     vm_offset_t sva, 
	     vm_offset_t eva)
{
	spl_t		spl;
	mapping		*mp;

#if PMAP_LOWTRACE
	dbgTrace(0xF1D00010, (unsigned int)pmap, (unsigned int)(sva|((eva-sva)>>12)));	/* (TEST/DEBUG) */
#endif

#if DEBUG
	if (pmdebug & PDB_USER) kprintf("pmap_modify_pages(pmap=%x, sva=%x, eva=%x)\n", pmap, sva, eva);
#endif

	if (pmap == PMAP_NULL) return;						/* If no pmap, can't do it... */

	debugLog2(56, sva, eva);							/* Log pmap_map call */

	spl=splhigh();										/* Don't bother me */

	for ( ; sva < eva; sva += PAGE_SIZE) {				/* Cycle through the whole range */	
		mp = hw_lock_phys_vir(pmap->space, sva);		/* Lock the physical entry for this mapping */
		if(mp) {										/* Did we find one? */
			if((unsigned int)mp&1) {					/* Did the lock on the phys entry time out? */
				panic("pmap_modify_pages: timeout obtaining lock on physical entry\n");	/* Scream bloody murder! */
				continue;
			}
			mp = hw_cpv(mp);							/* Convert to virtual addressing */				
			if(!mp->physent) continue;					/* No physical entry means an I/O page, we can't set attributes */
			mapping_set_mod(mp->physent);				/* Set the modfied bit for this page */
			hw_unlock_bit((unsigned int *)&mp->physent->phys_link, PHYS_LOCK);	/* Unlock the physical entry */
		}
	}
	splx(spl);											/* Restore the interrupt level */

	debugLog2(57, 0, 0);								/* Log pmap_map call */
	return;												/* Leave... */
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
	register struct phys_entry	*pp;
	spl_t		spl;

#if PMAP_LOWTRACE
	dbgTrace(0xF1D00011, (unsigned int)pa, 0);			/* (TEST/DEBUG) */
#endif
#if DEBUG
	if (pmdebug & PDB_USER)
		kprintf("pmap_clear_modify(pa=%x)\n", pa);
#endif

	pp = pmap_find_physentry(pa);						/* Find the physent for this page */
	if (pp == PHYS_NULL) return;						/* If there isn't one, just leave... */

	debugLog2(58, pa, 0);					/* Log pmap_map call */

	spl=splhigh();										/* Don't bother me */

	if(!hw_lock_bit((unsigned int *)&pp->phys_link, PHYS_LOCK, LockTimeOut)) {	/* Try to get the lock on the physical entry */
		panic("pmap_clear_modify: Timeout getting lock on physent at %08X\n", pp);	/* Arrrgghhhh! */
		splx(spl);										/* Restore 'rupts */
		return;											/* Should die before here */
	}

	mapping_clr_mod(pp);								/* Clear all change bits for physical page */

	hw_unlock_bit((unsigned int *)&pp->phys_link, PHYS_LOCK);	/* Unlock the physical entry */
 	splx(spl);											/* Restore the interrupt level */

	debugLog2(59, 0, 0);					/* Log pmap_map call */
}

/*
 * pmap_is_modified(phys)
 *	returns TRUE if the given physical page has been modified 
 *	since the last call to pmap_clear_modify().
 */
boolean_t
pmap_is_modified(register vm_offset_t pa)
{
	register struct phys_entry	*pp;
	spl_t		spl;
	boolean_t	ret;


#if PMAP_LOWTRACE
	dbgTrace(0xF1D00012, (unsigned int)pa, 0);			/* (TEST/DEBUG) */
#endif
#if DEBUG
	if (pmdebug & PDB_USER)
		kprintf("pmap_is_modified(pa=%x)\n", pa);
#endif

	pp = pmap_find_physentry(pa);						/* Find the physent for this page */
	if (pp == PHYS_NULL) return(FALSE);					/* Just indicate not set... */
	
	debugLog2(60, pa, 0);					/* Log pmap_map call */

	spl=splhigh();										/* Don't bother me */

	if(!hw_lock_bit((unsigned int *)&pp->phys_link, PHYS_LOCK, LockTimeOut)) {	/* Try to get the lock on the physical entry */
		panic("pmap_is_modified: Timeout getting lock on physent at %08X\n", pp);	/* Arrrgghhhh! */
		splx(spl);										/* Restore 'rupts */
		return 0;										/* Should die before here */
	}
	
	ret = mapping_tst_mod(pp);							/* Check for modified */
	
	hw_unlock_bit((unsigned int *)&pp->phys_link, PHYS_LOCK);	/* Unlock the physical entry */
 	splx(spl);											/* Restore the interrupt level */
	
	debugLog2(61, ret, 0);					/* Log pmap_map call */

	return ret;										
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
	register struct phys_entry	*pp;
	spl_t		spl;


#if PMAP_LOWTRACE
	dbgTrace(0xF1D00013, (unsigned int)pa, 0);				/* (TEST/DEBUG) */
#endif
#if DEBUG
	if (pmdebug & PDB_USER)
		kprintf("pmap_clear_reference(pa=%x)\n", pa);
#endif

	pp = pmap_find_physentry(pa);							/* Find the physent for this page */
	if (pp == PHYS_NULL) return;							/* If there isn't one, just leave... */

	debugLog2(62, pa, 0);					/* Log pmap_map call */

	spl=splhigh();											/* Don't bother me */
	mapping_clr_ref(pp);									/* Clear all reference bits for physical page */
 	splx(spl);												/* Restore the interrupt level */

	debugLog2(63, 0, 0);					/* Log pmap_map call */

}

/*
 * pmap_is_referenced(phys)
 *	returns TRUE if the given physical page has been referenced 
 *	since the last call to pmap_clear_reference().
 */
boolean_t
pmap_is_referenced(vm_offset_t pa)
{
	register struct phys_entry 	*pp;
	spl_t		spl;
	boolean_t	ret;


#if PMAP_LOWTRACE
	dbgTrace(0xF1D00014, (unsigned int)pa, 0);			/* (TEST/DEBUG) */
#endif
#if DEBUG
	if (pmdebug & PDB_USER)
		kprintf("pmap_is_referenced(pa=%x)\n", pa);
#endif

	pp = pmap_find_physentry(pa);						/* Find the physent for this page */
	if (pp == PHYS_NULL) return(FALSE);					/* Just indicate not set... */
	
	debugLog2(64, pa, 0);					/* Log pmap_map call */

	spl=splhigh();										/* Don't bother me */

	if(!hw_lock_bit((unsigned int *)&pp->phys_link, PHYS_LOCK, LockTimeOut)) {	/* Try to get the lock on the physical entry */
		panic("pmap_is_referenced: Timeout getting lock on physent at %08X\n", pp);	/* Arrrgghhhh! */
		splx(spl);										/* Restore 'rupts */
		return 0;										/* Should die before here */
	}
	
	ret = mapping_tst_ref(pp);							/* Check for referenced */
	
	hw_unlock_bit((unsigned int *)&pp->phys_link, PHYS_LOCK);	/* Unlock the physical entry */
 	splx(spl);											/* Restore the interrupt level */
	
	debugLog2(65, ret, 0);					/* Log pmap_map call */

	return ret;										
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


#if PMAP_LOWTRACE
	dbgTrace(0xF1D00019, (unsigned int)src+src_offset, (unsigned int)dst+dst_offset);	/* (TEST/DEBUG) */
	dbgTrace(0xF1D04019, (unsigned int)len, 0);			/* (TEST/DEBUG) */
#endif
	s = splhigh();

        assert(((dst & PAGE_MASK)+dst_offset+len) <= PAGE_SIZE);
        assert(((src & PAGE_MASK)+src_offset+len) <= PAGE_SIZE);

	/*
	 * Since the source and destination are physical addresses, 
	 * turn off data translation to perform a  bcopy() in bcopy_phys().
	 */
	phys_copy((vm_offset_t) src+src_offset,
		  (vm_offset_t) dst+dst_offset, len);

	splx(s);
}

void
pmap_zero_part_page(
	vm_offset_t	p,
	vm_offset_t     offset,
	vm_size_t       len)
{
    panic("pmap_zero_part_page");
}

boolean_t pmap_verify_free(vm_offset_t pa) {

	struct phys_entry	*pp;

#if PMAP_LOWTRACE
	dbgTrace(0xF1D00007, (unsigned int)pa, 0);				/* (TEST/DEBUG) */
#endif

#if DEBUG
	if (pmdebug & PDB_USER)
		kprintf("pmap_verify_free(pa=%x)\n", pa);
#endif

	if (!pmap_initialized) return(TRUE);

	pp = pmap_find_physentry(pa);							/* Look up the physical entry */
	if (pp == PHYS_NULL) return FALSE;						/* If there isn't one, show no mapping... */
	return ((mapping *)((unsigned int)pp->phys_link & ~PHYS_FLAGS) == MAPPING_NULL);	/* Otherwise, return TRUE if mapping exists... */
}


/* Determine if we need to switch space and set up for it if so */

void pmap_switch(pmap_t map)
{
	unsigned int i;

#if DEBUG
	if (watchacts & WA_PCB) {
		kprintf("Switching to map at 0x%08x, space=%d\n",
		       map,map->space);
	}
#endif /* DEBUG */


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
 *	kern_return_t pmap_nest(grand, subord, vaddr, size)
 *
 *	grand  = the pmap that we will nest subord into
 *	subord = the pmap that goes into the grand
 *	vaddr  = start of range in pmap to be inserted
 *	size   = size of range in pmap to be inserted
 *
 *	Inserts a pmap into another.  This is used to implement shared segments.
 *	On the current PPC processors, this is limited to segment (256MB) aligned
 *	segment sized ranges.
 */

kern_return_t pmap_nest(pmap_t grand, pmap_t subord, vm_offset_t vaddr, vm_size_t size) {
			
	unsigned int oflags, seg, grandr;
	int i;
	
	if(size != 0x10000000) return KERN_INVALID_VALUE;	/* We can only do this for 256MB for now */
	if(vaddr & 0x0FFFFFFF) return KERN_INVALID_VALUE;	/* We can only do this aligned to 256MB */

	while(1) {									/* Test and set the subordinate flag */
		oflags = subord->vflags & ~pmapAltSeg;	/* Get old unset value */
		if(subord->vflags & pmapAltSeg) {		/* Are trying to nest one already nested? */
			panic("pmap_nest: Attempt to nest an already nested pmap\n");
		}
		if(hw_compare_and_store(oflags, oflags | pmapSubord, &subord->vflags)) break;	/* Done if we got it set */
	}
	
	simple_lock(&grand->lock);					/* Lock the superior pmap */

	if(grand->vflags & pmapSubord) {			/* Are we only one level deep? */
		simple_unlock(&grand->lock);			/* Unlock the superior pmap */
		panic("pmap_nest: Attempt to nest into subordinate pmap\n");
		return KERN_FAILURE;					/* Shame on you */
	}

	seg = vaddr >> 28;							/* Isolate the segment number */
	if((0x00008000 >> seg) & grand->vflags) {	/* See if it is already in use */
		simple_unlock(&grand->lock);			/* Unlock the superior pmap */
		panic("pmap_nest: Attempt to nest into already nested segment\n");
		return KERN_FAILURE;					/* Shame on you */
	}
	
	grand->pmapPmaps[seg] = subord;				/* Set the pointer to the subordinate */
	grand->pmapSegs[seg] = SEG_REG_PROT | (seg << 20) | subord->space;		/* Set the vsid to the subordinate's vsid */
	grand->vflags |= (0x00008000 >> seg);		/* Set in-use bit */

	grandr = (unsigned int)grand ^ grand->pmapvr;	/* Get real address of the grand pmap */
	
	simple_unlock(&grand->lock);				/* Unlock the grand pmap */
	

/*
 *	Note that the following will force the segment registers to be reloaded following
 *	the next interrupt on all processors if they are using the pmap we just changed.
 *
 */


	for(i=0; i < real_ncpus; i++) {							/* Cycle through processors */
		(void)hw_compare_and_store((unsigned int)grandr, 0, &per_proc_info[i].Lastpmap);	/* Clear if ours */
	}
		
	return KERN_SUCCESS;						/* Bye, bye, butterfly... */
}


/*
 *	kern_return_t pmap_unnest(grand, vaddr, size)
 *
 *	grand  = the pmap that we will nest subord into
 *	vaddr  = start of range in pmap to be inserted
 *	size   = size of range in pmap to be inserted
 *
 *	Removes a pmap from another.  This is used to implement shared segments.
 *	On the current PPC processors, this is limited to segment (256MB) aligned
 *	segment sized ranges.
 */

kern_return_t pmap_unnest(pmap_t grand, vm_offset_t vaddr, vm_size_t size) {
			
	unsigned int oflags, seg, grandr, tstamp;
	int i, tcpu, mycpu;
		
	if(size != 0x10000000) return KERN_INVALID_VALUE;	/* We can only do this for 256MB for now */
	if(vaddr & 0x0FFFFFFF) return KERN_INVALID_VALUE;	/* We can only do this aligned to 256MB */

	simple_lock(&grand->lock);					/* Lock the superior pmap */
	disable_preemption();						/* It's all for me! */

	seg = vaddr >> 28;							/* Isolate the segment number */
	if(!((0x00008000 >> seg) & grand->vflags)) {	/* See if it is already in use */
		enable_preemption();					/* Ok, your turn */
		simple_unlock(&grand->lock);			/* Unlock the superior pmap */
		panic("pmap_unnest: Attempt to unnest an unnested segment\n");
		return KERN_FAILURE;					/* Shame on you */
	}
	
	grand->pmapPmaps[seg] = (pmap_t)0;			/* Clear the pointer to the subordinate */
	grand->pmapSegs[seg] = grand->space;		/* Set the pointer to the subordinate's vsid */
	grand->pmapSegs[seg] = SEG_REG_PROT | (seg << 20) | grand->space;		/* Set the vsid to the grand's vsid */
	grand->vflags &= ~(0x00008000 >> seg);		/* Clear in-use bit */

	grandr = (unsigned int)grand ^ grand->pmapvr;	/* Get real address of the grand pmap */
	
	simple_unlock(&grand->lock);				/* Unlock the superior pmap */

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


	mycpu = cpu_number();						/* Who am I? Am I just a dream? */
	for(i=0; i < real_ncpus; i++) {				/* Cycle through processors */
		if(hw_compare_and_store((unsigned int)grandr, 0, &per_proc_info[i].Lastpmap)) {	/* Clear if ours and kick the other guy if he was using it */
			if(i == mycpu) continue;				/* Don't diddle ourselves */
			tstamp = per_proc_info[i].ruptStamp[1];	/* Save the processor's last interrupt time stamp */
			if(cpu_signal(i, SIGPwake, 0, 0) != KERN_SUCCESS) {	/* Make sure we see the pmap change */
				continue;
			}
			if(!hw_cpu_wcng(&per_proc_info[i].ruptStamp[1], tstamp, LockTimeOut)) {	/* Wait for the other processors to enter debug */
				panic("pmap_unnest: Other processor (%d) did not see interruption request\n", i);
			}
		}
	}

	enable_preemption();						/* Others can run now */
	return KERN_SUCCESS;						/* Bye, bye, butterfly... */
}


void pmap_ver(pmap_t pmap, vm_offset_t sva, vm_offset_t eva) {

	int cnt, i, j, k;
	vm_offset_t xx;
	
	if(!pmap) return;

	sva = trunc_page(sva);
	eva = trunc_page(eva);
	
	for(i = 0; i < (pmapUsageMask + 1); i++) {	/* Step through them all */
		if((pmap->pmapUsage[i]) > 8192) {		/* See if this is a sane number */
			panic("pmap_ver: pmapUsage slot for %08X has invalid count (%d) for pmap %08X\n",
				i * pmapUsageSize, pmap->pmapUsage[i], pmap);
		}
	}
	j = 0;
	while(1) {									/* Try multiple times */
		cnt = 0;
		for(i = 0; i < (pmapUsageMask + 1); i++) {	/* Step through them all */
			cnt = cnt + pmap->pmapUsage[i];			/* Sum all slots */
		}
		if(cnt == pmap->stats.resident_count) break;	/* We're ok if we match... */
		
		j++;
		for(i = 0; i < 100000; i++) {
			k = j + i;
		}
		if(j >= 10) {
			panic("pmap_ver: pmapUsage total (%d) does not match resident count (%d) for pmap %08X\n",
				cnt, pmap->stats.resident_count, pmap);
		}
	}
	
	for(xx = sva; xx < eva; xx += PAGE_SIZE) {	/* See if any slots not clear */
		if(pmap_extract(pmap, xx)) {
			panic("pmap_ver: range (%08X to %08X) not empty at %08X for pmap %08X\n",
				sva, eva, xx, pmap);
		}
	}
}


/* temporary workaround */
boolean_t
coredumpok(vm_map_t map, vm_offset_t va)
{
  return TRUE;
}


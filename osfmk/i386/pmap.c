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
 * Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */

/*
 *	File:	pmap.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	(These guys wrote the Vax version)
 *
 *	Physical Map management code for Intel i386, i486, and i860.
 *
 *	Manages physical address maps.
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
 *	necessary.  This module is given full information as
 *	to which processors are currently using which maps,
 *	and to when physical maps must be made correct.
 */

#include <cpus.h>

#include <string.h>
#include <norma_vm.h>
#include <mach_kdb.h>
#include <mach_ldebug.h>

#include <mach/machine/vm_types.h>

#include <mach/boolean.h>
#include <kern/thread.h>
#include <kern/zalloc.h>

#include <kern/lock.h>
#include <kern/spl.h>

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <mach/vm_param.h>
#include <mach/vm_prot.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>

#include <mach/machine/vm_param.h>
#include <machine/thread.h>

#include <kern/misc_protos.h>			/* prototyping */
#include <i386/misc_protos.h>

#include <i386/cpuid.h>

#if	MACH_KDB
#include <ddb/db_command.h>
#include <ddb/db_output.h>
#include <ddb/db_sym.h>
#include <ddb/db_print.h>
#endif	/* MACH_KDB */

#include <kern/xpr.h>

#if NCPUS > 1
#include <i386/AT386/mp/mp_events.h>
#endif

/*
 * Forward declarations for internal functions.
 */
void	pmap_expand(
			pmap_t		map,
			vm_offset_t	v);

extern void	pmap_remove_range(
			pmap_t		pmap,
			vm_offset_t	va,
			pt_entry_t	*spte,
			pt_entry_t	*epte);

void	phys_attribute_clear(
			vm_offset_t	phys,
			int		bits);

boolean_t phys_attribute_test(
			vm_offset_t	phys,
			int		bits);

void pmap_set_modify(vm_offset_t	phys);

void phys_attribute_set(
			vm_offset_t	phys,
			int		bits);


#ifndef	set_dirbase
void	set_dirbase(vm_offset_t	dirbase);
#endif	/* set_dirbase */

#define	PA_TO_PTE(pa)	(pa_to_pte((pa) - VM_MIN_KERNEL_ADDRESS))
#define	iswired(pte)	((pte) & INTEL_PTE_WIRED)

pmap_t	real_pmap[NCPUS];

#define	WRITE_PTE(pte_p, pte_entry)		*(pte_p) = (pte_entry);
#define	WRITE_PTE_FAST(pte_p, pte_entry)	*(pte_p) = (pte_entry);

/*
 *	Private data structures.
 */

/*
 *	For each vm_page_t, there is a list of all currently
 *	valid virtual mappings of that page.  An entry is
 *	a pv_entry_t; the list is the pv_table.
 */

typedef struct pv_entry {
	struct pv_entry	*next;		/* next pv_entry */
	pmap_t		pmap;		/* pmap where mapping lies */
	vm_offset_t	va;		/* virtual address for mapping */
} *pv_entry_t;

#define PV_ENTRY_NULL	((pv_entry_t) 0)

pv_entry_t	pv_head_table;		/* array of entries, one per page */

/*
 *	pv_list entries are kept on a list that can only be accessed
 *	with the pmap system locked (at SPLVM, not in the cpus_active set).
 *	The list is refilled from the pv_list_zone if it becomes empty.
 */
pv_entry_t	pv_free_list;		/* free list at SPLVM */
decl_simple_lock_data(,pv_free_list_lock)

#define	PV_ALLOC(pv_e) { \
	simple_lock(&pv_free_list_lock); \
	if ((pv_e = pv_free_list) != 0) { \
	    pv_free_list = pv_e->next; \
	} \
	simple_unlock(&pv_free_list_lock); \
}

#define	PV_FREE(pv_e) { \
	simple_lock(&pv_free_list_lock); \
	pv_e->next = pv_free_list; \
	pv_free_list = pv_e; \
	simple_unlock(&pv_free_list_lock); \
}

zone_t		pv_list_zone;		/* zone of pv_entry structures */

/*
 *	Each entry in the pv_head_table is locked by a bit in the
 *	pv_lock_table.  The lock bits are accessed by the physical
 *	address of the page they lock.
 */

char	*pv_lock_table;		/* pointer to array of bits */
#define pv_lock_table_size(n)	(((n)+BYTE_SIZE-1)/BYTE_SIZE)

/*
 *	First and last physical addresses that we maintain any information
 *	for.  Initialized to zero so that pmap operations done before
 *	pmap_init won't touch any non-existent structures.
 */
vm_offset_t	vm_first_phys = (vm_offset_t) 0;
vm_offset_t	vm_last_phys  = (vm_offset_t) 0;
boolean_t	pmap_initialized = FALSE;/* Has pmap_init completed? */

/*
 *	Index into pv_head table, its lock bits, and the modify/reference
 *	bits starting at vm_first_phys.
 */

#define pa_index(pa)	(atop(pa - vm_first_phys))

#define pai_to_pvh(pai)		(&pv_head_table[pai])
#define lock_pvh_pai(pai)	bit_lock(pai, (void *)pv_lock_table)
#define unlock_pvh_pai(pai)	bit_unlock(pai, (void *)pv_lock_table)

/*
 *	Array of physical page attribites for managed pages.
 *	One byte per physical page.
 */
char	*pmap_phys_attributes;

/*
 *	Physical page attributes.  Copy bits from PTE definition.
 */
#define	PHYS_MODIFIED	INTEL_PTE_MOD	/* page modified */
#define	PHYS_REFERENCED	INTEL_PTE_REF	/* page referenced */
#define PHYS_NCACHE	INTEL_PTE_NCACHE

/*
 *	Amount of virtual memory mapped by one
 *	page-directory entry.
 */
#define	PDE_MAPPED_SIZE		(pdetova(1))

/*
 *	We allocate page table pages directly from the VM system
 *	through this object.  It maps physical memory.
 */
vm_object_t	pmap_object = VM_OBJECT_NULL;

/*
 *	Locking and TLB invalidation
 */

/*
 *	Locking Protocols:
 *
 *	There are two structures in the pmap module that need locking:
 *	the pmaps themselves, and the per-page pv_lists (which are locked
 *	by locking the pv_lock_table entry that corresponds to the pv_head
 *	for the list in question.)  Most routines want to lock a pmap and
 *	then do operations in it that require pv_list locking -- however
 *	pmap_remove_all and pmap_copy_on_write operate on a physical page
 *	basis and want to do the locking in the reverse order, i.e. lock
 *	a pv_list and then go through all the pmaps referenced by that list.
 *	To protect against deadlock between these two cases, the pmap_lock
 *	is used.  There are three different locking protocols as a result:
 *
 *  1.  pmap operations only (pmap_extract, pmap_access, ...)  Lock only
 *		the pmap.
 *
 *  2.  pmap-based operations (pmap_enter, pmap_remove, ...)  Get a read
 *		lock on the pmap_lock (shared read), then lock the pmap
 *		and finally the pv_lists as needed [i.e. pmap lock before
 *		pv_list lock.]
 *
 *  3.  pv_list-based operations (pmap_remove_all, pmap_copy_on_write, ...)
 *		Get a write lock on the pmap_lock (exclusive write); this
 *		also guaranteees exclusive access to the pv_lists.  Lock the
 *		pmaps as needed.
 *
 *	At no time may any routine hold more than one pmap lock or more than
 *	one pv_list lock.  Because interrupt level routines can allocate
 *	mbufs and cause pmap_enter's, the pmap_lock and the lock on the
 *	kernel_pmap can only be held at splhigh.
 */

#if	NCPUS > 1
/*
 *	We raise the interrupt level to splhigh, to block interprocessor
 *	interrupts during pmap operations.  We must take the CPU out of
 *	the cpus_active set while interrupts are blocked.
 */
#define SPLVM(spl)	{ \
	spl = splhigh(); \
	mp_disable_preemption(); \
	i_bit_clear(cpu_number(), &cpus_active); \
	mp_enable_preemption(); \
}

#define SPLX(spl)	{ \
	mp_disable_preemption(); \
	i_bit_set(cpu_number(), &cpus_active); \
	mp_enable_preemption(); \
	splx(spl); \
}

/*
 *	Lock on pmap system
 */
lock_t	pmap_system_lock;

#define PMAP_READ_LOCK(pmap, spl) {	\
	SPLVM(spl);			\
	lock_read(&pmap_system_lock);	\
	simple_lock(&(pmap)->lock);	\
}

#define PMAP_WRITE_LOCK(spl) {		\
	SPLVM(spl);			\
	lock_write(&pmap_system_lock);	\
}

#define PMAP_READ_UNLOCK(pmap, spl) {		\
	simple_unlock(&(pmap)->lock);		\
	lock_read_done(&pmap_system_lock);	\
	SPLX(spl);				\
}

#define PMAP_WRITE_UNLOCK(spl) {		\
	lock_write_done(&pmap_system_lock);	\
	SPLX(spl);				\
}

#define PMAP_WRITE_TO_READ_LOCK(pmap) {		\
	simple_lock(&(pmap)->lock);		\
	lock_write_to_read(&pmap_system_lock);	\
}

#define LOCK_PVH(index)		lock_pvh_pai(index)

#define UNLOCK_PVH(index)	unlock_pvh_pai(index)

#define PMAP_FLUSH_TLBS()						\
{									\
	flush_tlb();							\
	i386_signal_cpus(MP_TLB_FLUSH);					\
}

#define	PMAP_RELOAD_TLBS()	{ 		\
	i386_signal_cpus(MP_TLB_RELOAD);	\
	set_cr3(kernel_pmap->pdirbase);		\
}

#define PMAP_INVALIDATE_PAGE(map, addr) {	\
	if (map == kernel_pmap)			\
		invlpg((vm_offset_t) addr);	\
	else					\
		flush_tlb();			\
	i386_signal_cpus(MP_TLB_FLUSH);		\
}

#else	/* NCPUS > 1 */

#if	MACH_RT
#define SPLVM(spl)			{ (spl) = splhigh(); }
#define SPLX(spl)			splx (spl)
#else	/* MACH_RT */
#define SPLVM(spl)
#define SPLX(spl)
#endif	/* MACH_RT */

#define PMAP_READ_LOCK(pmap, spl)	SPLVM(spl)
#define PMAP_WRITE_LOCK(spl)		SPLVM(spl)
#define PMAP_READ_UNLOCK(pmap, spl)	SPLX(spl)
#define PMAP_WRITE_UNLOCK(spl)		SPLX(spl)
#define PMAP_WRITE_TO_READ_LOCK(pmap)

#if	MACH_RT
#define LOCK_PVH(index)			disable_preemption()
#define UNLOCK_PVH(index)		enable_preemption()
#else	/* MACH_RT */
#define LOCK_PVH(index)
#define UNLOCK_PVH(index)
#endif	/* MACH_RT */

#define	PMAP_FLUSH_TLBS()	flush_tlb()
#define	PMAP_RELOAD_TLBS()	set_cr3(kernel_pmap->pdirbase)
#define	PMAP_INVALIDATE_PAGE(map, addr) {	\
		if (map == kernel_pmap)		\
			invlpg((vm_offset_t) addr);	\
		else				\
			flush_tlb();		\
}

#endif	/* NCPUS > 1 */

#define MAX_TBIS_SIZE	32		/* > this -> TBIA */ /* XXX */

#if	NCPUS > 1
/*
 *	Structures to keep track of pending TLB invalidations
 */
cpu_set			cpus_active;
cpu_set			cpus_idle;
volatile boolean_t	cpu_update_needed[NCPUS];


#endif	/* NCPUS > 1 */

/*
 *	Other useful macros.
 */
#define current_pmap()		(vm_map_pmap(current_act()->map))
#define pmap_in_use(pmap, cpu)	(((pmap)->cpus_using & (1 << (cpu))) != 0)

struct pmap	kernel_pmap_store;
pmap_t		kernel_pmap;

struct zone	*pmap_zone;		/* zone of pmap structures */

int		pmap_debug = 0;		/* flag for debugging prints */
int		ptes_per_vm_page;	/* number of hardware ptes needed
					   to map one VM page. */
unsigned int	inuse_ptepages_count = 0;	/* debugging */

/*
 *	Pmap cache.  Cache is threaded through ref_count field of pmap.
 *	Max will eventually be constant -- variable for experimentation.
 */
int		pmap_cache_max = 32;
int		pmap_alloc_chunk = 8;
pmap_t		pmap_cache_list;
int		pmap_cache_count;
decl_simple_lock_data(,pmap_cache_lock)

extern	vm_offset_t	hole_start, hole_end;

extern char end;

/*
 * Page directory for kernel.
 */
pt_entry_t	*kpde = 0;	/* set by start.s - keep out of bss */

#if  DEBUG_ALIAS
#define PMAP_ALIAS_MAX 32
struct pmap_alias {
        vm_offset_t rpc;
        pmap_t pmap;
        vm_offset_t va;
        int cookie;
#define PMAP_ALIAS_COOKIE 0xdeadbeef
} pmap_aliasbuf[PMAP_ALIAS_MAX];
int pmap_alias_index = 0;
extern vm_offset_t get_rpc();

#endif  /* DEBUG_ALIAS */

/*
 *	Given an offset and a map, compute the address of the
 *	pte.  If the address is invalid with respect to the map
 *	then PT_ENTRY_NULL is returned (and the map may need to grow).
 *
 *	This is only used in machine-dependent code.
 */

pt_entry_t *
pmap_pte(
	register pmap_t		pmap,
	register vm_offset_t	addr)
{
	register pt_entry_t	*ptp;
	register pt_entry_t	pte;

	pte = pmap->dirbase[pdenum(pmap, addr)];
	if ((pte & INTEL_PTE_VALID) == 0)
		return(PT_ENTRY_NULL);
	ptp = (pt_entry_t *)ptetokv(pte);
	return(&ptp[ptenum(addr)]);

}

#define	pmap_pde(pmap, addr) (&(pmap)->dirbase[pdenum(pmap, addr)])

#define DEBUG_PTE_PAGE	0

#if	DEBUG_PTE_PAGE
void
ptep_check(
	ptep_t	ptep)
{
	register pt_entry_t	*pte, *epte;
	int			ctu, ctw;

	/* check the use and wired counts */
	if (ptep == PTE_PAGE_NULL)
		return;
	pte = pmap_pte(ptep->pmap, ptep->va);
	epte = pte + INTEL_PGBYTES/sizeof(pt_entry_t);
	ctu = 0;
	ctw = 0;
	while (pte < epte) {
		if (pte->pfn != 0) {
			ctu++;
			if (pte->wired)
				ctw++;
		}
		pte += ptes_per_vm_page;
	}

	if (ctu != ptep->use_count || ctw != ptep->wired_count) {
		printf("use %d wired %d - actual use %d wired %d\n",
		    	ptep->use_count, ptep->wired_count, ctu, ctw);
		panic("pte count");
	}
}
#endif	/* DEBUG_PTE_PAGE */

/*
 *	Map memory at initialization.  The physical addresses being
 *	mapped are not managed and are never unmapped.
 *
 *	For now, VM is already on, we only need to map the
 *	specified memory.
 */
vm_offset_t
pmap_map(
	register vm_offset_t	virt,
	register vm_offset_t	start,
	register vm_offset_t	end,
	register vm_prot_t	prot)
{
	register int		ps;

	ps = PAGE_SIZE;
	while (start < end) {
		pmap_enter(kernel_pmap, virt, start, prot, 0, FALSE);
		virt += ps;
		start += ps;
	}
	return(virt);
}

/*
 *	Back-door routine for mapping kernel VM at initialization.  
 * 	Useful for mapping memory outside the range
 *      Sets no-cache, A, D.
 *	[vm_first_phys, vm_last_phys) (i.e., devices).
 *	Otherwise like pmap_map.
 */
vm_offset_t
pmap_map_bd(
	register vm_offset_t	virt,
	register vm_offset_t	start,
	register vm_offset_t	end,
	vm_prot_t		prot)
{
	register pt_entry_t	template;
	register pt_entry_t	*pte;

	template = pa_to_pte(start)
		| INTEL_PTE_NCACHE
		| INTEL_PTE_REF
		| INTEL_PTE_MOD
		| INTEL_PTE_WIRED
		| INTEL_PTE_VALID;
	if (prot & VM_PROT_WRITE)
	    template |= INTEL_PTE_WRITE;

	while (start < end) {
		pte = pmap_pte(kernel_pmap, virt);
		if (pte == PT_ENTRY_NULL)
			panic("pmap_map_bd: Invalid kernel address\n");
		WRITE_PTE_FAST(pte, template)
		pte_increment_pa(template);
		virt += PAGE_SIZE;
		start += PAGE_SIZE;
	}

	PMAP_FLUSH_TLBS();

	return(virt);
}

extern int		cnvmem;
extern	char		*first_avail;
extern	vm_offset_t	virtual_avail, virtual_end;
extern	vm_offset_t	avail_start, avail_end, avail_next;

/*
 *	Bootstrap the system enough to run with virtual memory.
 *	Map the kernel's code and data, and allocate the system page table.
 *	Called with mapping OFF.  Page_size must already be set.
 *
 *	Parameters:
 *	load_start:	PA where kernel was loaded
 *	avail_start	PA of first available physical page -
 *			   after kernel page tables
 *	avail_end	PA of last available physical page
 *	virtual_avail	VA of first available page -
 *			   after kernel page tables
 *	virtual_end	VA of last available page -
 *			   end of kernel address space
 *
 *	&start_text	start of kernel text
 *	&etext		end of kernel text
 */

void
pmap_bootstrap(
	vm_offset_t	load_start)
{
	vm_offset_t	va, tva, paddr;
	pt_entry_t	template;
	pt_entry_t	*pde, *pte, *ptend;
	vm_size_t	morevm;		/* VM space for kernel map */

	/*
	 *	Set ptes_per_vm_page for general use.
	 */
	ptes_per_vm_page = PAGE_SIZE / INTEL_PGBYTES;

	/*
	 *	The kernel's pmap is statically allocated so we don't
	 *	have to use pmap_create, which is unlikely to work
	 *	correctly at this part of the boot sequence.
	 */

	kernel_pmap = &kernel_pmap_store;

#if	NCPUS > 1
	lock_init(&pmap_system_lock,
		  FALSE,		/* NOT a sleep lock */
		  ETAP_VM_PMAP_SYS,
		  ETAP_VM_PMAP_SYS_I);
#endif	/* NCPUS > 1 */

	simple_lock_init(&kernel_pmap->lock, ETAP_VM_PMAP_KERNEL);
	simple_lock_init(&pv_free_list_lock, ETAP_VM_PMAP_FREE);

	kernel_pmap->ref_count = 1;

	/*
	 *	The kernel page directory has been allocated;
	 *	its virtual address is in kpde.
	 *
	 *	Enough kernel page table pages have been allocated
	 *	to map low system memory, kernel text, kernel data/bss,
	 *	kdb's symbols, and the page directory and page tables.
	 *
	 *	No other physical memory has been allocated.
	 */

	/*
	 * Start mapping virtual memory to physical memory, 1-1,
	 * at end of mapped memory.
	 */

	virtual_avail = phystokv(avail_start);
	virtual_end = phystokv(avail_end);

	pde = kpde;
	pde += pdenum(kernel_pmap, virtual_avail);

	if (pte_to_pa(*pde) == 0) {
	    /* This pte has not been allocated */
	    pte = 0; ptend = 0;
	}
	else {
	    pte = (pt_entry_t *)ptetokv(*pde);
						/* first pte of page */
	    ptend = pte+NPTES;			/* last pte of page */
	    pte += ptenum(virtual_avail);	/* point to pte that
						   maps first avail VA */
	    pde++;	/* point pde to first empty slot */
	}

	template = pa_to_pte(avail_start)
		| INTEL_PTE_VALID
		| INTEL_PTE_WRITE;

	for (va = virtual_avail; va < virtual_end; va += INTEL_PGBYTES) {
	    if (pte >= ptend) {
		pte = (pt_entry_t *)phystokv(virtual_avail);
		ptend = pte + NPTES;
		virtual_avail = (vm_offset_t)ptend;
		if (virtual_avail == hole_start)
		  virtual_avail = hole_end;
		*pde = PA_TO_PTE((vm_offset_t) pte)
			| INTEL_PTE_VALID
			| INTEL_PTE_WRITE;
		pde++;
	    }
	    WRITE_PTE_FAST(pte, template)
	    pte++;
	    pte_increment_pa(template);
	}

	avail_start = virtual_avail - VM_MIN_KERNEL_ADDRESS;
	avail_next = avail_start;

	/*
	 *	Figure out maximum kernel address.
	 *	Kernel virtual space is:
	 *		- at least three times physical memory
	 *		- at least VM_MIN_KERNEL_ADDRESS
	 *		- limited by VM_MAX_KERNEL_ADDRESS
	 */

	morevm = 3*avail_end;
	if (virtual_end + morevm > VM_MAX_KERNEL_ADDRESS)
	  morevm = VM_MAX_KERNEL_ADDRESS - virtual_end + 1;

/*
 *	startup requires additional virtual memory (for tables, buffers, 
 *	etc.).  The kd driver may also require some of that memory to
 *	access the graphics board.
 *
 */
	*(int *)&template = 0;

	/*
	 * Leave room for kernel-loaded servers, which have been linked at
	 * addresses from VM_MIN_KERNEL_LOADED_ADDRESS to
	 * VM_MAX_KERNEL_LOADED_ADDRESS.
	 */
	if (virtual_end + morevm < VM_MAX_KERNEL_LOADED_ADDRESS + 1)
		morevm = VM_MAX_KERNEL_LOADED_ADDRESS + 1 - virtual_end;


	virtual_end += morevm;
	for (tva = va; tva < virtual_end; tva += INTEL_PGBYTES) {
	    if (pte >= ptend) {
		pmap_next_page(&paddr);
		pte = (pt_entry_t *)phystokv(paddr);
		ptend = pte + NPTES;
		*pde = PA_TO_PTE((vm_offset_t) pte)
			| INTEL_PTE_VALID
			| INTEL_PTE_WRITE;
		pde++;
	    }
	    WRITE_PTE_FAST(pte, template)
	    pte++;
	}

	virtual_avail = va;

	/* Push the virtual avail address above hole_end */
	if (virtual_avail < hole_end)
		virtual_avail = hole_end;

	/*
	 *	c.f. comment above
	 *
	 */
	virtual_end = va + morevm;
	while (pte < ptend)
	    *pte++ = 0;

	/*
	 *	invalidate user virtual addresses 
	 */
	memset((char *)kpde,
	       0,
	       pdenum(kernel_pmap,VM_MIN_KERNEL_ADDRESS)*sizeof(pt_entry_t));
	kernel_pmap->dirbase = kpde;
	printf("Kernel virtual space from 0x%x to 0x%x.\n",
			VM_MIN_KERNEL_ADDRESS, virtual_end);

	avail_start = avail_next;
	printf("Available physical space from 0x%x to 0x%x\n",
			avail_start, avail_end);

	kernel_pmap->pdirbase = kvtophys((vm_offset_t)kernel_pmap->dirbase);

	if (cpuid_features() & CPUID_FEATURE_PAT)
	{
		uint64_t pat;
		uint32_t msr;
	    
		msr = 0x277;
		asm volatile("rdmsr" : "=A" (pat) : "c" (msr));
	    
		pat &= ~(0xfULL << 48);
		pat |= 0x01ULL << 48;
	    
		asm volatile("wrmsr" :: "A" (pat), "c" (msr));
	}
}

void
pmap_virtual_space(
	vm_offset_t *startp,
	vm_offset_t *endp)
{
	*startp = virtual_avail;
	*endp = virtual_end;
}

/*
 *	Initialize the pmap module.
 *	Called by vm_init, to initialize any structures that the pmap
 *	system needs to map virtual memory.
 */
void
pmap_init(void)
{
	register long		npages;
	vm_offset_t		addr;
	register vm_size_t	s;
	int			i;

	/*
	 *	Allocate memory for the pv_head_table and its lock bits,
	 *	the modify bit array, and the pte_page table.
	 */

	npages = atop(avail_end - avail_start);
	s = (vm_size_t) (sizeof(struct pv_entry) * npages
				+ pv_lock_table_size(npages)
				+ npages);

	s = round_page(s);
	if (kmem_alloc_wired(kernel_map, &addr, s) != KERN_SUCCESS)
		panic("pmap_init");

	memset((char *)addr, 0, s);

	/*
	 *	Allocate the structures first to preserve word-alignment.
	 */
	pv_head_table = (pv_entry_t) addr;
	addr = (vm_offset_t) (pv_head_table + npages);

	pv_lock_table = (char *) addr;
	addr = (vm_offset_t) (pv_lock_table + pv_lock_table_size(npages));

	pmap_phys_attributes = (char *) addr;

	/*
	 *	Create the zone of physical maps,
	 *	and of the physical-to-virtual entries.
	 */
	s = (vm_size_t) sizeof(struct pmap);
	pmap_zone = zinit(s, 400*s, 4096, "pmap"); /* XXX */
	s = (vm_size_t) sizeof(struct pv_entry);
	pv_list_zone = zinit(s, 10000*s, 4096, "pv_list"); /* XXX */

	/*
	 *	Only now, when all of the data structures are allocated,
	 *	can we set vm_first_phys and vm_last_phys.  If we set them
	 *	too soon, the kmem_alloc_wired above will try to use these
	 *	data structures and blow up.
	 */

	vm_first_phys = avail_start;
	vm_last_phys = avail_end;
	pmap_initialized = TRUE;

	/*
	 *	Initializie pmap cache.
	 */
	pmap_cache_list = PMAP_NULL;
	pmap_cache_count = 0;
	simple_lock_init(&pmap_cache_lock, ETAP_VM_PMAP_CACHE);
}


#define	pmap_valid_page(x)	((avail_start <= x) && (x < avail_end))


#define valid_page(x) (pmap_initialized && pmap_valid_page(x))

boolean_t
pmap_verify_free(
	vm_offset_t	phys)
{
	pv_entry_t	pv_h;
	int		pai;
	spl_t		spl;
	boolean_t	result;

	assert(phys != vm_page_fictitious_addr);
	if (!pmap_initialized)
		return(TRUE);

	if (!pmap_valid_page(phys))
		return(FALSE);

	PMAP_WRITE_LOCK(spl);

	pai = pa_index(phys);
	pv_h = pai_to_pvh(pai);

	result = (pv_h->pmap == PMAP_NULL);
	PMAP_WRITE_UNLOCK(spl);

	return(result);
}

/*
 *	Create and return a physical map.
 *
 *	If the size specified for the map
 *	is zero, the map is an actual physical
 *	map, and may be referenced by the
 *	hardware.
 *
 *	If the size specified is non-zero,
 *	the map will be used in software only, and
 *	is bounded by that size.
 */
pmap_t
pmap_create(
	vm_size_t	size)
{
	register pmap_t			p;
	register pmap_statistics_t	stats;

	/*
	 *	A software use-only map doesn't even need a map.
	 */

	if (size != 0) {
		return(PMAP_NULL);
	}

	/*
	 *	Try to get cached pmap, if this fails,
	 *	allocate a pmap struct from the pmap_zone.  Then allocate
	 *	the page descriptor table from the pd_zone.
	 */

	simple_lock(&pmap_cache_lock);
	while ((p = pmap_cache_list) == PMAP_NULL) {

		vm_offset_t		dirbases;
		register int		i;

		simple_unlock(&pmap_cache_lock);

#if	NCPUS > 1
	/*
	 * XXX	NEEDS MP DOING ALLOC logic so that if multiple processors
	 * XXX	get here, only one allocates a chunk of pmaps.
	 * (for now we'll just let it go - safe but wasteful)
	 */
#endif

		/*
		 *	Allocate a chunck of pmaps.  Single kmem_alloc_wired
		 *	operation reduces kernel map fragmentation.
		 */

		if (kmem_alloc_wired(kernel_map, &dirbases,
				     pmap_alloc_chunk * INTEL_PGBYTES)
							!= KERN_SUCCESS)
			panic("pmap_create.1");

		for (i = pmap_alloc_chunk; i > 0 ; i--) {
			p = (pmap_t) zalloc(pmap_zone);
			if (p == PMAP_NULL)
				panic("pmap_create.2");

			/*
			 *	Initialize pmap.  Don't bother with
			 *	ref count as cache list is threaded
			 *	through it.  It'll be set on cache removal.
			 */
			p->dirbase = (pt_entry_t *) dirbases;
			dirbases += INTEL_PGBYTES;
			memcpy(p->dirbase, kpde, INTEL_PGBYTES);
			p->pdirbase = kvtophys((vm_offset_t)p->dirbase);

			simple_lock_init(&p->lock, ETAP_VM_PMAP);
			p->cpus_using = 0;

			/*
			 *	Initialize statistics.
			 */
			stats = &p->stats;
			stats->resident_count = 0;
			stats->wired_count = 0;
			
			/*
			 *	Insert into cache
			 */
			simple_lock(&pmap_cache_lock);
			p->ref_count = (int) pmap_cache_list;
			pmap_cache_list = p;
			pmap_cache_count++;
			simple_unlock(&pmap_cache_lock);
		}
		simple_lock(&pmap_cache_lock);
	}

	assert(p->stats.resident_count == 0);
	assert(p->stats.wired_count == 0);
	p->stats.resident_count = 0;
	p->stats.wired_count = 0;

	pmap_cache_list = (pmap_t) p->ref_count;
	p->ref_count = 1;
	pmap_cache_count--;
	simple_unlock(&pmap_cache_lock);

	return(p);
}

/*
 *	Retire the given physical map from service.
 *	Should only be called if the map contains
 *	no valid mappings.
 */

void
pmap_destroy(
	register pmap_t	p)
{
	register pt_entry_t	*pdep;
	register vm_offset_t	pa;
	register int		c;
	spl_t                   s;
	register vm_page_t	m;

	if (p == PMAP_NULL)
		return;

	SPLVM(s);
	simple_lock(&p->lock);
	c = --p->ref_count;
	if (c == 0) {
		register int    my_cpu;

		mp_disable_preemption();
		my_cpu = cpu_number();

		/* 
		 * If some cpu is not using the physical pmap pointer that it
		 * is supposed to be (see set_dirbase), we might be using the
		 * pmap that is being destroyed! Make sure we are
		 * physically on the right pmap:
		 */


		if (real_pmap[my_cpu] == p) {
			PMAP_CPU_CLR(p, my_cpu);
			real_pmap[my_cpu] = kernel_pmap;
			PMAP_RELOAD_TLBS();
		}
		mp_enable_preemption();
	}
	simple_unlock(&p->lock);
	SPLX(s);

	if (c != 0) {
	    return;	/* still in use */
	}

	/*
	 *	Free the memory maps, then the
	 *	pmap structure.
	 */
	pdep = p->dirbase;
	while (pdep < &p->dirbase[pdenum(p, LINEAR_KERNEL_ADDRESS)]) {
	    if (*pdep & INTEL_PTE_VALID) {
		pa = pte_to_pa(*pdep);
		vm_object_lock(pmap_object);
		m = vm_page_lookup(pmap_object, pa);
		if (m == VM_PAGE_NULL)
		    panic("pmap_destroy: pte page not in object");
		vm_page_lock_queues();
		vm_page_free(m);
		inuse_ptepages_count--;
		vm_object_unlock(pmap_object);
		vm_page_unlock_queues();

		/*
		 *	Clear pdes, this might be headed for the cache.
		 */
		c = ptes_per_vm_page;
		do {
		    *pdep = 0;
		    pdep++;
		} while (--c > 0);
	    }
	    else {
		pdep += ptes_per_vm_page;
	    }
	
	}
	assert(p->stats.resident_count == 0);
	assert(p->stats.wired_count == 0);

	/*
	 *	Add to cache if not already full
	 */
	simple_lock(&pmap_cache_lock);
	if (pmap_cache_count <= pmap_cache_max) {
		p->ref_count = (int) pmap_cache_list;
		pmap_cache_list = p;
		pmap_cache_count++;
		simple_unlock(&pmap_cache_lock);
	}
	else {
		simple_unlock(&pmap_cache_lock);
		kmem_free(kernel_map, (vm_offset_t)p->dirbase, INTEL_PGBYTES);
		zfree(pmap_zone, (vm_offset_t) p);
	}
}

/*
 *	Add a reference to the specified pmap.
 */

void
pmap_reference(
	register pmap_t	p)
{
	spl_t	s;

	if (p != PMAP_NULL) {
		SPLVM(s);
		simple_lock(&p->lock);
		p->ref_count++;
		simple_unlock(&p->lock);
		SPLX(s);
	}
}

/*
 *	Remove a range of hardware page-table entries.
 *	The entries given are the first (inclusive)
 *	and last (exclusive) entries for the VM pages.
 *	The virtual address is the va for the first pte.
 *
 *	The pmap must be locked.
 *	If the pmap is not the kernel pmap, the range must lie
 *	entirely within one pte-page.  This is NOT checked.
 *	Assumes that the pte-page exists.
 */

/* static */
void
pmap_remove_range(
	pmap_t			pmap,
	vm_offset_t		va,
	pt_entry_t		*spte,
	pt_entry_t		*epte)
{
	register pt_entry_t	*cpte;
	int			num_removed, num_unwired;
	int			pai;
	vm_offset_t		pa;

#if	DEBUG_PTE_PAGE
	if (pmap != kernel_pmap)
		ptep_check(get_pte_page(spte));
#endif	/* DEBUG_PTE_PAGE */
	num_removed = 0;
	num_unwired = 0;

	for (cpte = spte; cpte < epte;
	     cpte += ptes_per_vm_page, va += PAGE_SIZE) {

	    pa = pte_to_pa(*cpte);
	    if (pa == 0)
		continue;

	    num_removed++;
	    if (iswired(*cpte))
		num_unwired++;

	    if (!valid_page(pa)) {

		/*
		 *	Outside range of managed physical memory.
		 *	Just remove the mappings.
		 */
		register int	i = ptes_per_vm_page;
		register pt_entry_t	*lpte = cpte;
		do {
		    *lpte = 0;
		    lpte++;
		} while (--i > 0);
		continue;
	    }

	    pai = pa_index(pa);
	    LOCK_PVH(pai);

	    /*
	     *	Get the modify and reference bits.
	     */
	    {
		register int		i;
		register pt_entry_t	*lpte;

		i = ptes_per_vm_page;
		lpte = cpte;
		do {
		    pmap_phys_attributes[pai] |=
			*lpte & (PHYS_MODIFIED|PHYS_REFERENCED);
		    *lpte = 0;
		    lpte++;
		} while (--i > 0);
	    }

	    /*
	     *	Remove the mapping from the pvlist for
	     *	this physical page.
	     */
	    {
		register pv_entry_t	pv_h, prev, cur;

		pv_h = pai_to_pvh(pai);
		if (pv_h->pmap == PMAP_NULL) {
		    panic("pmap_remove: null pv_list!");
		}
		if (pv_h->va == va && pv_h->pmap == pmap) {
		    /*
		     * Header is the pv_entry.  Copy the next one
		     * to header and free the next one (we cannot
		     * free the header)
		     */
		    cur = pv_h->next;
		    if (cur != PV_ENTRY_NULL) {
			*pv_h = *cur;
			PV_FREE(cur);
		    }
		    else {
			pv_h->pmap = PMAP_NULL;
		    }
		}
		else {
		    cur = pv_h;
		    do {
			prev = cur;
			if ((cur = prev->next) == PV_ENTRY_NULL) {
			    panic("pmap-remove: mapping not in pv_list!");
			}
		    } while (cur->va != va || cur->pmap != pmap);
		    prev->next = cur->next;
		    PV_FREE(cur);
		}
		UNLOCK_PVH(pai);
	    }
	}

	/*
	 *	Update the counts
	 */
	assert(pmap->stats.resident_count >= num_removed);
	pmap->stats.resident_count -= num_removed;
	assert(pmap->stats.wired_count >= num_unwired);
	pmap->stats.wired_count -= num_unwired;
}

/*
 *	Remove phys addr if mapped in specified map
 *
 */
void
pmap_remove_some_phys(
	pmap_t		map,
	vm_offset_t	phys_addr)
{

/* Implement to support working set code */

}


/*
 *	Remove the given range of addresses
 *	from the specified map.
 *
 *	It is assumed that the start and end are properly
 *	rounded to the hardware page size.
 */


/* FIXMEx86 */
void
pmap_remove(
	pmap_t		map,
	addr64_t	s,
	addr64_t	e)
{
	spl_t			spl;
	register pt_entry_t	*pde;
	register pt_entry_t	*spte, *epte;
	vm_offset_t		l;

	if (map == PMAP_NULL)
		return;

	PMAP_READ_LOCK(map, spl);

	pde = pmap_pde(map, s);

	while (s < e) {
	    l = (s + PDE_MAPPED_SIZE) & ~(PDE_MAPPED_SIZE-1);
	    if (l > e)
		l = e;
	    if (*pde & INTEL_PTE_VALID) {
		spte = (pt_entry_t *)ptetokv(*pde);
		spte = &spte[ptenum(s)];
		epte = &spte[intel_btop(l-s)];
		pmap_remove_range(map, s, spte, epte);
	    }
	    s = l;
	    pde++;
	}

	PMAP_FLUSH_TLBS();

	PMAP_READ_UNLOCK(map, spl);
}

/*
 *	Routine:	pmap_page_protect
 *
 *	Function:
 *		Lower the permission for all mappings to a given
 *		page.
 */
void
pmap_page_protect(
	vm_offset_t	phys,
	vm_prot_t	prot)
{
	pv_entry_t		pv_h, prev;
	register pv_entry_t	pv_e;
	register pt_entry_t	*pte;
	int			pai;
	register pmap_t		pmap;
	spl_t			spl;
	boolean_t		remove;

	assert(phys != vm_page_fictitious_addr);
	if (!valid_page(phys)) {
	    /*
	     *	Not a managed page.
	     */
	    return;
	}

	/*
	 * Determine the new protection.
	 */
	switch (prot) {
	    case VM_PROT_READ:
	    case VM_PROT_READ|VM_PROT_EXECUTE:
		remove = FALSE;
		break;
	    case VM_PROT_ALL:
		return;	/* nothing to do */
	    default:
		remove = TRUE;
		break;
	}

	/*
	 *	Lock the pmap system first, since we will be changing
	 *	several pmaps.
	 */

	PMAP_WRITE_LOCK(spl);

	pai = pa_index(phys);
	pv_h = pai_to_pvh(pai);

	/*
	 * Walk down PV list, changing or removing all mappings.
	 * We do not have to lock the pv_list because we have
	 * the entire pmap system locked.
	 */
	if (pv_h->pmap != PMAP_NULL) {

	    prev = pv_e = pv_h;
	    do {
		pmap = pv_e->pmap;
		/*
		 * Lock the pmap to block pmap_extract and similar routines.
		 */
		simple_lock(&pmap->lock);

		{
		    register vm_offset_t va;

		    va = pv_e->va;
		    pte = pmap_pte(pmap, va);

		    /*
		     * Consistency checks.
		     */
		    /* assert(*pte & INTEL_PTE_VALID); XXX */
		    /* assert(pte_to_phys(*pte) == phys); */

		    /*
		     * Invalidate TLBs for all CPUs using this mapping.
		     */
		    PMAP_INVALIDATE_PAGE(pmap, va);
		}

		/*
		 * Remove the mapping if new protection is NONE
		 * or if write-protecting a kernel mapping.
		 */
		if (remove || pmap == kernel_pmap) {
		    /*
		     * Remove the mapping, collecting any modify bits.
		     */
		    {
			register int	i = ptes_per_vm_page;

			do {
			    pmap_phys_attributes[pai] |=
				*pte & (PHYS_MODIFIED|PHYS_REFERENCED);
			    *pte++ = 0;
			} while (--i > 0);
		    }

		    assert(pmap->stats.resident_count >= 1);
		    pmap->stats.resident_count--;

		    /*
		     * Remove the pv_entry.
		     */
		    if (pv_e == pv_h) {
			/*
			 * Fix up head later.
			 */
			pv_h->pmap = PMAP_NULL;
		    }
		    else {
			/*
			 * Delete this entry.
			 */
			prev->next = pv_e->next;
			PV_FREE(pv_e);
		    }
		}
		else {
		    /*
		     * Write-protect.
		     */
		    register int i = ptes_per_vm_page;

		    do {
			*pte &= ~INTEL_PTE_WRITE;
			pte++;
		    } while (--i > 0);

		    /*
		     * Advance prev.
		     */
		    prev = pv_e;
		}

		simple_unlock(&pmap->lock);

	    } while ((pv_e = prev->next) != PV_ENTRY_NULL);

	    /*
	     * If pv_head mapping was removed, fix it up.
	     */
	    if (pv_h->pmap == PMAP_NULL) {
		pv_e = pv_h->next;
		if (pv_e != PV_ENTRY_NULL) {
		    *pv_h = *pv_e;
		    PV_FREE(pv_e);
		}
	    }
	}

	PMAP_WRITE_UNLOCK(spl);
}

/*
 *	Set the physical protection on the
 *	specified range of this map as requested.
 *	Will not increase permissions.
 */
void
pmap_protect(
	pmap_t		map,
	vm_offset_t	s,
	vm_offset_t	e,
	vm_prot_t	prot)
{
	register pt_entry_t	*pde;
	register pt_entry_t	*spte, *epte;
	vm_offset_t		l;
	spl_t		spl;


	if (map == PMAP_NULL)
		return;

	/*
	 * Determine the new protection.
	 */
	switch (prot) {
	    case VM_PROT_READ:
	    case VM_PROT_READ|VM_PROT_EXECUTE:
		break;
	    case VM_PROT_READ|VM_PROT_WRITE:
	    case VM_PROT_ALL:
		return;	/* nothing to do */
	    default:
		pmap_remove(map, s, e);
		return;
	}

	/*
	 * If write-protecting in the kernel pmap,
	 * remove the mappings; the i386 ignores
	 * the write-permission bit in kernel mode.
	 *
	 * XXX should be #if'd for i386
	 */

	if (cpuid_family == CPUID_FAMILY_386)
	    if (map == kernel_pmap) {
		    pmap_remove(map, s, e);
		    return;
	    }

	SPLVM(spl);
	simple_lock(&map->lock);


	pde = pmap_pde(map, s);
	while (s < e) {
	    l = (s + PDE_MAPPED_SIZE) & ~(PDE_MAPPED_SIZE-1);
	    if (l > e)
		l = e;
	    if (*pde & INTEL_PTE_VALID) {
		spte = (pt_entry_t *)ptetokv(*pde);
		spte = &spte[ptenum(s)];
		epte = &spte[intel_btop(l-s)];

		while (spte < epte) {
		    if (*spte & INTEL_PTE_VALID)
			*spte &= ~INTEL_PTE_WRITE;
		    spte++;
		}
	    }
	    s = l;
	    pde++;
	}

	PMAP_FLUSH_TLBS();

	simple_unlock(&map->lock);
	SPLX(spl);
}



/*
 *	Insert the given physical page (p) at
 *	the specified virtual address (v) in the
 *	target physical map with the protection requested.
 *
 *	If specified, the page will be wired down, meaning
 *	that the related pte cannot be reclaimed.
 *
 *	NB:  This is the only routine which MAY NOT lazy-evaluate
 *	or lose information.  That is, this routine must actually
 *	insert this page into the given map NOW.
 */
void
pmap_enter(
	register pmap_t		pmap,
	vm_offset_t		v,
	register vm_offset_t	pa,
	vm_prot_t		prot,
	unsigned int 		flags,
	boolean_t		wired)
{
	register pt_entry_t	*pte;
	register pv_entry_t	pv_h;
	register int		i, pai;
	pv_entry_t		pv_e;
	pt_entry_t		template;
	spl_t			spl;
	vm_offset_t		old_pa;

	XPR(0x80000000, "%x/%x: pmap_enter %x/%x/%x\n",
	    current_thread()->top_act,
	    current_thread(), 
	    pmap, v, pa);

	assert(pa != vm_page_fictitious_addr);
	if (pmap_debug)
		printf("pmap(%x, %x)\n", v, pa);
	if (pmap == PMAP_NULL)
		return;

	if (cpuid_family == CPUID_FAMILY_386)
	if (pmap == kernel_pmap && (prot & VM_PROT_WRITE) == 0
	    && !wired /* hack for io_wire */ ) {
	    /*
	     *	Because the 386 ignores write protection in kernel mode,
	     *	we cannot enter a read-only kernel mapping, and must
	     *	remove an existing mapping if changing it.
	     *
	     *  XXX should be #if'd for i386
	     */
	    PMAP_READ_LOCK(pmap, spl);

	    pte = pmap_pte(pmap, v);
	    if (pte != PT_ENTRY_NULL && pte_to_pa(*pte) != 0) {
		/*
		 *	Invalidate the translation buffer,
		 *	then remove the mapping.
		 */
		PMAP_INVALIDATE_PAGE(pmap, v);
		pmap_remove_range(pmap, v, pte,
				  pte + ptes_per_vm_page);
	    }
	    PMAP_READ_UNLOCK(pmap, spl);
	    return;
	}

	/*
	 *	Must allocate a new pvlist entry while we're unlocked;
	 *	zalloc may cause pageout (which will lock the pmap system).
	 *	If we determine we need a pvlist entry, we will unlock
	 *	and allocate one.  Then we will retry, throughing away
	 *	the allocated entry later (if we no longer need it).
	 */
	pv_e = PV_ENTRY_NULL;
Retry:
	PMAP_READ_LOCK(pmap, spl);

	/*
	 *	Expand pmap to include this pte.  Assume that
	 *	pmap is always expanded to include enough hardware
	 *	pages to map one VM page.
	 */

	while ((pte = pmap_pte(pmap, v)) == PT_ENTRY_NULL) {
		/*
		 *	Must unlock to expand the pmap.
		 */
		PMAP_READ_UNLOCK(pmap, spl);

		pmap_expand(pmap, v);

		PMAP_READ_LOCK(pmap, spl);
	}
	/*
	 *	Special case if the physical page is already mapped
	 *	at this address.
	 */
	old_pa = pte_to_pa(*pte);
	if (old_pa == pa) {
	    /*
	     *	May be changing its wired attribute or protection
	     */
	
	    template = pa_to_pte(pa) | INTEL_PTE_VALID;

	    if(flags & VM_MEM_NOT_CACHEABLE) {
		if(!(flags & VM_MEM_GUARDED))
			template |= INTEL_PTE_PTA;
		template |= INTEL_PTE_NCACHE;
	    }

	    if (pmap != kernel_pmap)
		template |= INTEL_PTE_USER;
	    if (prot & VM_PROT_WRITE)
		template |= INTEL_PTE_WRITE;
	    if (wired) {
		template |= INTEL_PTE_WIRED;
		if (!iswired(*pte))
		    pmap->stats.wired_count++;
	    }
	    else {
		if (iswired(*pte)) {
		    assert(pmap->stats.wired_count >= 1);
		    pmap->stats.wired_count--;
		}
	    }

	    PMAP_INVALIDATE_PAGE(pmap, v);

	    i = ptes_per_vm_page;
	    do {
		if (*pte & INTEL_PTE_MOD)
		    template |= INTEL_PTE_MOD;
		WRITE_PTE(pte, template)
		pte++;
		pte_increment_pa(template);
	    } while (--i > 0);

	    goto Done;
	}

	/*
	 *	Outline of code from here:
	 *	   1) If va was mapped, update TLBs, remove the mapping
	 *	      and remove old pvlist entry.
	 *	   2) Add pvlist entry for new mapping
	 *	   3) Enter new mapping.
	 *
	 *	SHARING_FAULTS complicates this slightly in that it cannot
	 *	replace the mapping, but must remove it (because adding the
	 *	pvlist entry for the new mapping may remove others), and
	 *	hence always enters the new mapping at step 3)
	 *
	 *	If the old physical page is not managed step 1) is skipped
	 *	(except for updating the TLBs), and the mapping is
	 *	overwritten at step 3).  If the new physical page is not
	 *	managed, step 2) is skipped.
	 */

	if (old_pa != (vm_offset_t) 0) {

	    PMAP_INVALIDATE_PAGE(pmap, v);

#if	DEBUG_PTE_PAGE
	    if (pmap != kernel_pmap)
		ptep_check(get_pte_page(pte));
#endif	/* DEBUG_PTE_PAGE */

	    /*
	     *	Don't do anything to pages outside valid memory here.
	     *	Instead convince the code that enters a new mapping
	     *	to overwrite the old one.
	     */

	    if (valid_page(old_pa)) {

		pai = pa_index(old_pa);
		LOCK_PVH(pai);

		assert(pmap->stats.resident_count >= 1);
		pmap->stats.resident_count--;
	    	if (iswired(*pte)) {
		    assert(pmap->stats.wired_count >= 1);
		    pmap->stats.wired_count--;
		}
		i = ptes_per_vm_page;
		do {
		    pmap_phys_attributes[pai] |=
			*pte & (PHYS_MODIFIED|PHYS_REFERENCED);
		    WRITE_PTE(pte, 0)
		    pte++;
		    pte_increment_pa(template);
		} while (--i > 0);

		/*
		 * Put pte back to beginning of page since it'll be
		 * used later to enter the new page.
		 */
		pte -= ptes_per_vm_page;

		/*
		 *	Remove the mapping from the pvlist for
		 *	this physical page.
		 */
		{
		    register pv_entry_t	prev, cur;

		    pv_h = pai_to_pvh(pai);
		    if (pv_h->pmap == PMAP_NULL) {
			panic("pmap_enter: null pv_list!");
		    }
		    if (pv_h->va == v && pv_h->pmap == pmap) {
			/*
			 * Header is the pv_entry.  Copy the next one
			 * to header and free the next one (we cannot
			 * free the header)
			 */
			cur = pv_h->next;
			if (cur != PV_ENTRY_NULL) {
			    *pv_h = *cur;
			    pv_e = cur;
			}
			else {
			    pv_h->pmap = PMAP_NULL;
			}
		    }
		    else {
			cur = pv_h;
			do {
			    prev = cur;
			    if ((cur = prev->next) == PV_ENTRY_NULL) {
			        panic("pmap_enter: mapping not in pv_list!");
			    }
			} while (cur->va != v || cur->pmap != pmap);
			prev->next = cur->next;
			pv_e = cur;
		    }
		}
		UNLOCK_PVH(pai);
	    }
	    else {

		/*
		 *	old_pa is not managed.  Pretend it's zero so code
		 *	at Step 3) will enter new mapping (overwriting old
		 *	one).  Do removal part of accounting.
		 */
		old_pa = (vm_offset_t) 0;
		assert(pmap->stats.resident_count >= 1);
		pmap->stats.resident_count--;
		if (iswired(*pte)) {
		    assert(pmap->stats.wired_count >= 1);
		    pmap->stats.wired_count--;
		}
	    }
	}

	if (valid_page(pa)) {

	    /*
	     *	Step 2) Enter the mapping in the PV list for this
	     *	physical page.
	     */

	    pai = pa_index(pa);


#if SHARING_FAULTS
RetryPvList:
	    /*
	     * We can return here from the sharing fault code below
	     * in case we removed the only entry on the pv list and thus
	     * must enter the new one in the list header.
	     */
#endif /* SHARING_FAULTS */
	    LOCK_PVH(pai);
	    pv_h = pai_to_pvh(pai);

	    if (pv_h->pmap == PMAP_NULL) {
		/*
		 *	No mappings yet
		 */
		pv_h->va = v;
		pv_h->pmap = pmap;
		pv_h->next = PV_ENTRY_NULL;
	    }
	    else {
#if	DEBUG
		{
		    /*
		     * check that this mapping is not already there
		     * or there is no alias for this mapping in the same map
		     */
		    pv_entry_t	e = pv_h;
		    while (e != PV_ENTRY_NULL) {
			if (e->pmap == pmap && e->va == v)
                            panic("pmap_enter: already in pv_list");
			e = e->next;
		    }
		}
#endif	/* DEBUG */
#if SHARING_FAULTS
                {
                    /*
                     * do sharing faults.
                     * if we find an entry on this pv list in the same address
		     * space, remove it.  we know there will not be more
		     * than one. 
		     */
		    pv_entry_t	e = pv_h;
                    pt_entry_t      *opte;

		    while (e != PV_ENTRY_NULL) {
			if (e->pmap == pmap) {
                            /*
			     *	Remove it, drop pv list lock first.
			     */
                            UNLOCK_PVH(pai);

                            opte = pmap_pte(pmap, e->va);
                            assert(opte != PT_ENTRY_NULL);
                            /*
			     *	Invalidate the translation buffer,
			     *	then remove the mapping.
			     */
			     PMAP_INVALIDATE_PAGE(pmap, e->va);
                             pmap_remove_range(pmap, e->va, opte,
                                                      opte + ptes_per_vm_page);
			     /*
			      * We could have remove the head entry,
			      * so there could be no more entries
			      * and so we have to use the pv head entry.
			      * so, go back to the top and try the entry
			      * again.
			      */
			     goto RetryPvList;
			}
                        e = e->next;
		    }

		    /*
                     * check that this mapping is not already there
                     */
		    e = pv_h;
		    while (e != PV_ENTRY_NULL) {
			if (e->pmap == pmap)
                            panic("pmap_enter: alias in pv_list");
			e = e->next;
		    }
		}
#endif /* SHARING_FAULTS */
#if DEBUG_ALIAS
                {
                    /*
                     * check for aliases within the same address space.
                     */
		    pv_entry_t	e = pv_h;
                    vm_offset_t     rpc = get_rpc();

		    while (e != PV_ENTRY_NULL) {
			if (e->pmap == pmap) {
                            /*
                             * log this entry in the alias ring buffer
			     * if it's not there already.
                             */
                            struct pmap_alias *pma;
                            int ii, logit;

                            logit = TRUE;
                            for (ii = 0; ii < pmap_alias_index; ii++) {
                                if (pmap_aliasbuf[ii].rpc == rpc) {
                                    /* found it in the log already */
                                    logit = FALSE;
                                    break;
				}
			    }
                            if (logit) {
                                pma = &pmap_aliasbuf[pmap_alias_index];
                                pma->pmap = pmap;
                                pma->va = v;
                                pma->rpc = rpc;
                                pma->cookie = PMAP_ALIAS_COOKIE;
                                if (++pmap_alias_index >= PMAP_ALIAS_MAX)
                                    panic("pmap_enter: exhausted alias log");
			    }
			}
                        e = e->next;
		    }
		}
#endif /* DEBUG_ALIAS */
		/*
		 *	Add new pv_entry after header.
		 */
		if (pv_e == PV_ENTRY_NULL) {
		    PV_ALLOC(pv_e);
		    if (pv_e == PV_ENTRY_NULL) {
			UNLOCK_PVH(pai);
			PMAP_READ_UNLOCK(pmap, spl);

			/*
			 * Refill from zone.
			 */
			pv_e = (pv_entry_t) zalloc(pv_list_zone);
			goto Retry;
		    }
		}
		pv_e->va = v;
		pv_e->pmap = pmap;
		pv_e->next = pv_h->next;
		pv_h->next = pv_e;
		/*
		 *	Remember that we used the pvlist entry.
		 */
		pv_e = PV_ENTRY_NULL;
	    }
	    UNLOCK_PVH(pai);
	}

	/*
	 * Step 3) Enter and count the mapping.
	 */

	pmap->stats.resident_count++;

	/*
	 *	Build a template to speed up entering -
	 *	only the pfn changes.
	 */
	template = pa_to_pte(pa) | INTEL_PTE_VALID;

	if(flags & VM_MEM_NOT_CACHEABLE) {
		if(!(flags & VM_MEM_GUARDED))
			template |= INTEL_PTE_PTA;
		template |= INTEL_PTE_NCACHE;
	}

	if (pmap != kernel_pmap)
		template |= INTEL_PTE_USER;
	if (prot & VM_PROT_WRITE)
		template |= INTEL_PTE_WRITE;
	if (wired) {
		template |= INTEL_PTE_WIRED;
		pmap->stats.wired_count++;
	}
	i = ptes_per_vm_page;
	do {
		WRITE_PTE(pte, template)
		pte++;
		pte_increment_pa(template);
	} while (--i > 0);
Done:
	if (pv_e != PV_ENTRY_NULL) {
	    PV_FREE(pv_e);
	}

	PMAP_READ_UNLOCK(pmap, spl);
}

/*
 *	Routine:	pmap_change_wiring
 *	Function:	Change the wiring attribute for a map/virtual-address
 *			pair.
 *	In/out conditions:
 *			The mapping must already exist in the pmap.
 */
void
pmap_change_wiring(
	register pmap_t	map,
	vm_offset_t	v,
	boolean_t	wired)
{
	register pt_entry_t	*pte;
	register int		i;
	spl_t			spl;

#if 0
	/*
	 *	We must grab the pmap system lock because we may
	 *	change a pte_page queue.
	 */
	PMAP_READ_LOCK(map, spl);

	if ((pte = pmap_pte(map, v)) == PT_ENTRY_NULL)
		panic("pmap_change_wiring: pte missing");

	if (wired && !iswired(*pte)) {
	    /*
	     *	wiring down mapping
	     */
	    map->stats.wired_count++;
	    i = ptes_per_vm_page;
	    do {
		*pte++ |= INTEL_PTE_WIRED;
	    } while (--i > 0);
	}
	else if (!wired && iswired(*pte)) {
	    /*
	     *	unwiring mapping
	     */
	    assert(map->stats.wired_count >= 1);
	    map->stats.wired_count--;
	    i = ptes_per_vm_page;
	    do {
		*pte++ &= ~INTEL_PTE_WIRED;
	    } while (--i > 0);
	}

	PMAP_READ_UNLOCK(map, spl);

#else
	return;
#endif

}

/*
 *	Routine:	pmap_extract
 *	Function:
 *		Extract the physical page address associated
 *		with the given map/virtual_address pair.
 */

vm_offset_t
pmap_extract(
	register pmap_t	pmap,
	vm_offset_t	va)
{
	register pt_entry_t	*pte;
	register vm_offset_t	pa;
	spl_t			spl;

	SPLVM(spl);
	simple_lock(&pmap->lock);
	if ((pte = pmap_pte(pmap, va)) == PT_ENTRY_NULL)
	    pa = (vm_offset_t) 0;
	else if (!(*pte & INTEL_PTE_VALID))
	    pa = (vm_offset_t) 0;
	else
	    pa = pte_to_pa(*pte) + (va & INTEL_OFFMASK);
	simple_unlock(&pmap->lock);
	SPLX(spl);
	return(pa);
}

/*
 *	Routine:	pmap_expand
 *
 *	Expands a pmap to be able to map the specified virtual address.
 *
 *	Allocates new virtual memory for the P0 or P1 portion of the
 *	pmap, then re-maps the physical pages that were in the old
 *	pmap to be in the new pmap.
 *
 *	Must be called with the pmap system and the pmap unlocked,
 *	since these must be unlocked to use vm_allocate or vm_deallocate.
 *	Thus it must be called in a loop that checks whether the map
 *	has been expanded enough.
 *	(We won't loop forever, since page tables aren't shrunk.)
 */
void
pmap_expand(
	register pmap_t		map,
	register vm_offset_t	v)
{
	pt_entry_t		*pdp;
	register vm_page_t	m;
	register vm_offset_t	pa;
	register int		i;
	spl_t			spl;

	if (map == kernel_pmap)
	    panic("pmap_expand");

	/*
	 *	We cannot allocate the pmap_object in pmap_init,
	 *	because it is called before the zone package is up.
	 *	Allocate it now if it is missing.
	 */
	if (pmap_object == VM_OBJECT_NULL)
	    pmap_object = vm_object_allocate(avail_end);

	/*
	 *	Allocate a VM page for the level 2 page table entries.
	 */
	while ((m = vm_page_grab()) == VM_PAGE_NULL)
		VM_PAGE_WAIT();

	/*
	 *	Map the page to its physical address so that it
	 *	can be found later.
	 */
	pa = m->phys_page;
	vm_object_lock(pmap_object);
	vm_page_insert(m, pmap_object, pa);
	vm_page_lock_queues();
	vm_page_wire(m);
	inuse_ptepages_count++;
	vm_object_unlock(pmap_object);
	vm_page_unlock_queues();

	/*
	 *	Zero the page.
	 */
	memset((void *)phystokv(pa), 0, PAGE_SIZE);

	PMAP_READ_LOCK(map, spl);
	/*
	 *	See if someone else expanded us first
	 */
	if (pmap_pte(map, v) != PT_ENTRY_NULL) {
		PMAP_READ_UNLOCK(map, spl);
		vm_object_lock(pmap_object);
		vm_page_lock_queues();
		vm_page_free(m);
		inuse_ptepages_count--;
		vm_page_unlock_queues();
		vm_object_unlock(pmap_object);
		return;
	}

	/*
	 *	Set the page directory entry for this page table.
	 *	If we have allocated more than one hardware page,
	 *	set several page directory entries.
	 */

	i = ptes_per_vm_page;
	pdp = &map->dirbase[pdenum(map, v) & ~(i-1)];
	do {
	    *pdp = pa_to_pte(pa)
		| INTEL_PTE_VALID
		| INTEL_PTE_USER
		| INTEL_PTE_WRITE;
	    pdp++;
	    pa += INTEL_PGBYTES;
	} while (--i > 0);

	PMAP_READ_UNLOCK(map, spl);
	return;
}

/*
 *	Copy the range specified by src_addr/len
 *	from the source map to the range dst_addr/len
 *	in the destination map.
 *
 *	This routine is only advisory and need not do anything.
 */
#if	0
void
pmap_copy(
	pmap_t		dst_pmap,
	pmap_t		src_pmap,
	vm_offset_t	dst_addr,
	vm_size_t	len,
	vm_offset_t	src_addr)
{
#ifdef	lint
	dst_pmap++; src_pmap++; dst_addr++; len++; src_addr++;
#endif	/* lint */
}
#endif/* 	0 */

/*
 * pmap_sync_caches_phys(ppnum_t pa)
 * 
 * Invalidates all of the instruction cache on a physical page and
 * pushes any dirty data from the data cache for the same physical page
 */
 
void pmap_sync_caches_phys(ppnum_t pa)
{
	if (!(cpuid_features() & CPUID_FEATURE_SS))
	{
		__asm__ volatile("wbinvd");	
	}
	return;
}

int	collect_ref;
int	collect_unref;

/*
 *	Routine:	pmap_collect
 *	Function:
 *		Garbage collects the physical map system for
 *		pages which are no longer used.
 *		Success need not be guaranteed -- that is, there
 *		may well be pages which are not referenced, but
 *		others may be collected.
 *	Usage:
 *		Called by the pageout daemon when pages are scarce.
 */
void
pmap_collect(
	pmap_t 		p)
{
	register pt_entry_t	*pdp, *ptp;
	pt_entry_t		*eptp;
	vm_offset_t		pa;
	int			wired;
	spl_t                   spl;

	if (p == PMAP_NULL)
		return;

	if (p == kernel_pmap)
		return;

	/*
	 *	Garbage collect map.
	 */
	PMAP_READ_LOCK(p, spl);
	PMAP_FLUSH_TLBS();

	for (pdp = p->dirbase;
	     pdp < &p->dirbase[pdenum(p, LINEAR_KERNEL_ADDRESS)];
	     pdp += ptes_per_vm_page)
	{
	    if (*pdp & INTEL_PTE_VALID) 
	      if(*pdp & INTEL_PTE_REF) {
		*pdp &= ~INTEL_PTE_REF;
		collect_ref++;
	      } else {
		collect_unref++;
		pa = pte_to_pa(*pdp);
		ptp = (pt_entry_t *)phystokv(pa);
		eptp = ptp + NPTES*ptes_per_vm_page;

		/*
		 * If the pte page has any wired mappings, we cannot
		 * free it.
		 */
		wired = 0;
		{
		    register pt_entry_t *ptep;
		    for (ptep = ptp; ptep < eptp; ptep++) {
			if (iswired(*ptep)) {
			    wired = 1;
			    break;
			}
		    }
		}
		if (!wired) {
		    /*
		     * Remove the virtual addresses mapped by this pte page.
		     */
		    pmap_remove_range(p,
				pdetova(pdp - p->dirbase),
				ptp,
				eptp);

		    /*
		     * Invalidate the page directory pointer.
		     */
		    {
			register int i = ptes_per_vm_page;
			register pt_entry_t *pdep = pdp;
			do {
			    *pdep++ = 0;
			} while (--i > 0);
		    }

		    PMAP_READ_UNLOCK(p, spl);

		    /*
		     * And free the pte page itself.
		     */
		    {
			register vm_page_t m;

			vm_object_lock(pmap_object);
			m = vm_page_lookup(pmap_object, pa);
			if (m == VM_PAGE_NULL)
			    panic("pmap_collect: pte page not in object");
			vm_page_lock_queues();
			vm_page_free(m);
			inuse_ptepages_count--;
			vm_page_unlock_queues();
			vm_object_unlock(pmap_object);
		    }

		    PMAP_READ_LOCK(p, spl);
		}
	    }
	}
	PMAP_READ_UNLOCK(p, spl);
	return;

}

/*
 *	Routine:	pmap_kernel
 *	Function:
 *		Returns the physical map handle for the kernel.
 */
#if	0
pmap_t
pmap_kernel(void)
{
    	return (kernel_pmap);
}
#endif/* 	0 */

/*
 *	pmap_zero_page zeros the specified (machine independent) page.
 *	See machine/phys.c or machine/phys.s for implementation.
 */
#if	0
void
pmap_zero_page(
	register vm_offset_t	phys)
{
	register int	i;

	assert(phys != vm_page_fictitious_addr);
	i = PAGE_SIZE / INTEL_PGBYTES;
	phys = intel_pfn(phys);

	while (i--)
		zero_phys(phys++);
}
#endif/* 	0 */

/*
 *	pmap_copy_page copies the specified (machine independent) page.
 *	See machine/phys.c or machine/phys.s for implementation.
 */
#if	0
void
pmap_copy_page(
	vm_offset_t	src,
	vm_offset_t	dst)
{
	int	i;

	assert(src != vm_page_fictitious_addr);
	assert(dst != vm_page_fictitious_addr);
	i = PAGE_SIZE / INTEL_PGBYTES;

	while (i--) {
		copy_phys(intel_pfn(src), intel_pfn(dst));
		src += INTEL_PGBYTES;
		dst += INTEL_PGBYTES;
	}
}
#endif/* 	0 */

/*
 *	Routine:	pmap_pageable
 *	Function:
 *		Make the specified pages (by pmap, offset)
 *		pageable (or not) as requested.
 *
 *		A page which is not pageable may not take
 *		a fault; therefore, its page table entry
 *		must remain valid for the duration.
 *
 *		This routine is merely advisory; pmap_enter
 *		will specify that these pages are to be wired
 *		down (or not) as appropriate.
 */
void
pmap_pageable(
	pmap_t		pmap,
	vm_offset_t	start,
	vm_offset_t	end,
	boolean_t	pageable)
{
#ifdef	lint
	pmap++; start++; end++; pageable++;
#endif	/* lint */
}

/*
 *	Clear specified attribute bits.
 */
void
phys_attribute_clear(
	vm_offset_t	phys,
	int		bits)
{
	pv_entry_t		pv_h;
	register pv_entry_t	pv_e;
	register pt_entry_t	*pte;
	int			pai;
	register pmap_t		pmap;
	spl_t			spl;

	assert(phys != vm_page_fictitious_addr);
	if (!valid_page(phys)) {
	    /*
	     *	Not a managed page.
	     */
	    return;
	}

	/*
	 *	Lock the pmap system first, since we will be changing
	 *	several pmaps.
	 */

	PMAP_WRITE_LOCK(spl);

	pai = pa_index(phys);
	pv_h = pai_to_pvh(pai);

	/*
	 * Walk down PV list, clearing all modify or reference bits.
	 * We do not have to lock the pv_list because we have
	 * the entire pmap system locked.
	 */
	if (pv_h->pmap != PMAP_NULL) {
	    /*
	     * There are some mappings.
	     */
	    for (pv_e = pv_h; pv_e != PV_ENTRY_NULL; pv_e = pv_e->next) {

		pmap = pv_e->pmap;
		/*
		 * Lock the pmap to block pmap_extract and similar routines.
		 */
		simple_lock(&pmap->lock);

		{
		    register vm_offset_t va;

		    va = pv_e->va;
		    pte = pmap_pte(pmap, va);

#if	0
		    /*
		     * Consistency checks.
		     */
		    assert(*pte & INTEL_PTE_VALID);
		    /* assert(pte_to_phys(*pte) == phys); */
#endif

		    /*
		     * Invalidate TLBs for all CPUs using this mapping.
		     */
		    PMAP_INVALIDATE_PAGE(pmap, va);
		}

		/*
		 * Clear modify or reference bits.
		 */
		{
		    register int	i = ptes_per_vm_page;
		    do {
			*pte++ &= ~bits;
		    } while (--i > 0);
		}
		simple_unlock(&pmap->lock);
	    }
	}

	pmap_phys_attributes[pai] &= ~bits;

	PMAP_WRITE_UNLOCK(spl);
}

/*
 *	Check specified attribute bits.
 */
boolean_t
phys_attribute_test(
	vm_offset_t	phys,
	int		bits)
{
	pv_entry_t		pv_h;
	register pv_entry_t	pv_e;
	register pt_entry_t	*pte;
	int			pai;
	register pmap_t		pmap;
	spl_t			spl;

	assert(phys != vm_page_fictitious_addr);
	if (!valid_page(phys)) {
	    /*
	     *	Not a managed page.
	     */
	    return (FALSE);
	}

	/*
	 *	Lock the pmap system first, since we will be checking
	 *	several pmaps.
	 */

	PMAP_WRITE_LOCK(spl);

	pai = pa_index(phys);
	pv_h = pai_to_pvh(pai);

	if (pmap_phys_attributes[pai] & bits) {
	    PMAP_WRITE_UNLOCK(spl);
	    return (TRUE);
	}

	/*
	 * Walk down PV list, checking all mappings.
	 * We do not have to lock the pv_list because we have
	 * the entire pmap system locked.
	 */
	if (pv_h->pmap != PMAP_NULL) {
	    /*
	     * There are some mappings.
	     */
	    for (pv_e = pv_h; pv_e != PV_ENTRY_NULL; pv_e = pv_e->next) {

		pmap = pv_e->pmap;
		/*
		 * Lock the pmap to block pmap_extract and similar routines.
		 */
		simple_lock(&pmap->lock);

		{
		    register vm_offset_t va;

		    va = pv_e->va;
		    pte = pmap_pte(pmap, va);

#if	0
		    /*
		     * Consistency checks.
		     */
		    assert(*pte & INTEL_PTE_VALID);
		    /* assert(pte_to_phys(*pte) == phys); */
#endif
		}

		/*
		 * Check modify or reference bits.
		 */
		{
		    register int	i = ptes_per_vm_page;

		    do {
			if (*pte++ & bits) {
			    simple_unlock(&pmap->lock);
			    PMAP_WRITE_UNLOCK(spl);
			    return (TRUE);
			}
		    } while (--i > 0);
		}
		simple_unlock(&pmap->lock);
	    }
	}
	PMAP_WRITE_UNLOCK(spl);
	return (FALSE);
}

/*
 *	Set specified attribute bits.
 */
void
phys_attribute_set(
	vm_offset_t	phys,
	int		bits)
{
	int			spl;

	assert(phys != vm_page_fictitious_addr);
	if (!valid_page(phys)) {
	    /*
	     *	Not a managed page.
	     */
	    return;
	}

	/*
	 *	Lock the pmap system and set the requested bits in
	 *	the phys attributes array.  Don't need to bother with
	 *	ptes because the test routine looks here first.
	 */

	PMAP_WRITE_LOCK(spl);
	pmap_phys_attributes[pa_index(phys)] |= bits;
	PMAP_WRITE_UNLOCK(spl);
}

/*
 *	Set the modify bit on the specified physical page.
 */

void pmap_set_modify(
	register vm_offset_t	phys)
{
	phys_attribute_set(phys, PHYS_MODIFIED);
}

/*
 *	Clear the modify bits on the specified physical page.
 */

void
pmap_clear_modify(
	register vm_offset_t	phys)
{
	phys_attribute_clear(phys, PHYS_MODIFIED);
}

/*
 *	pmap_is_modified:
 *
 *	Return whether or not the specified physical page is modified
 *	by any physical maps.
 */

boolean_t
pmap_is_modified(
	register vm_offset_t	phys)
{
	return (phys_attribute_test(phys, PHYS_MODIFIED));
}

/*
 *	pmap_clear_reference:
 *
 *	Clear the reference bit on the specified physical page.
 */

void
pmap_clear_reference(
	vm_offset_t	phys)
{
	phys_attribute_clear(phys, PHYS_REFERENCED);
}

/*
 *	pmap_is_referenced:
 *
 *	Return whether or not the specified physical page is referenced
 *	by any physical maps.
 */

boolean_t
pmap_is_referenced(
	vm_offset_t	phys)
{
	return (phys_attribute_test(phys, PHYS_REFERENCED));
}

/*
 *	Set the modify bit on the specified range
 *	of this map as requested.
 *
 *	This optimization stands only if each time the dirty bit
 *	in vm_page_t is tested, it is also tested in the pmap.
 */
void
pmap_modify_pages(
	pmap_t		map,
	vm_offset_t	s,
	vm_offset_t	e)
{
	spl_t			spl;
	register pt_entry_t	*pde;
	register pt_entry_t	*spte, *epte;
	vm_offset_t		l;

	if (map == PMAP_NULL)
		return;

	PMAP_READ_LOCK(map, spl);

	pde = pmap_pde(map, s);
	while (s && s < e) {
	    l = (s + PDE_MAPPED_SIZE) & ~(PDE_MAPPED_SIZE-1);
	    if (l > e)
		l = e;
	    if (*pde & INTEL_PTE_VALID) {
		spte = (pt_entry_t *)ptetokv(*pde);
		if (l) {
		   spte = &spte[ptenum(s)];
		   epte = &spte[intel_btop(l-s)];
	        } else {
		   epte = &spte[intel_btop(PDE_MAPPED_SIZE)];
		   spte = &spte[ptenum(s)];
	        }
		while (spte < epte) {
		    if (*spte & INTEL_PTE_VALID) {
			*spte |= (INTEL_PTE_MOD | INTEL_PTE_WRITE);
		    }
		    spte++;
		}
	    }
	    s = l;
	    pde++;
	}
	PMAP_FLUSH_TLBS();
	PMAP_READ_UNLOCK(map, spl);
}


void 
invalidate_icache(vm_offset_t addr, unsigned cnt, int phys)
{
	return;
}
void 
flush_dcache(vm_offset_t addr, unsigned count, int phys)
{
	return;
}

#if	NCPUS > 1

void inline
pmap_wait_for_clear()
{
	register int		my_cpu;
	spl_t			s;
	register pmap_t		my_pmap;

	mp_disable_preemption();
	my_cpu = cpu_number();
	

	my_pmap = real_pmap[my_cpu];

	if (!(my_pmap && pmap_in_use(my_pmap, my_cpu)))
		my_pmap = kernel_pmap;

	/*
	 *	Raise spl to splhigh (above splip) to block out pmap_extract
	 *	from IO code (which would put this cpu back in the active
	 *	set).
	 */
	s = splhigh();

	/*
	 *	Wait for any pmap updates in progress, on either user
	 *	or kernel pmap.
	 */
	 while (*(volatile hw_lock_t)&my_pmap->lock.interlock ||
	  *(volatile hw_lock_t)&kernel_pmap->lock.interlock) {
		continue;
	}

	splx(s);
	mp_enable_preemption();
}

void
pmap_flush_tlb_interrupt(void) {
	pmap_wait_for_clear();

	flush_tlb();
}

void
pmap_reload_tlb_interrupt(void) {
	pmap_wait_for_clear();

	set_cr3(kernel_pmap->pdirbase);
}

	
#endif	/* NCPUS > 1 */

#if	MACH_KDB

/* show phys page mappings and attributes */

extern void	db_show_page(vm_offset_t pa);

void
db_show_page(vm_offset_t pa)
{
	pv_entry_t	pv_h;
	int		pai;
	char 		attr;
	
	pai = pa_index(pa);
	pv_h = pai_to_pvh(pai);

	attr = pmap_phys_attributes[pai];
	printf("phys page %x ", pa);
	if (attr & PHYS_MODIFIED)
		printf("modified, ");
	if (attr & PHYS_REFERENCED)
		printf("referenced, ");
	if (pv_h->pmap || pv_h->next)
		printf(" mapped at\n");
	else
		printf(" not mapped\n");
	for (; pv_h; pv_h = pv_h->next)
		if (pv_h->pmap)
			printf("%x in pmap %x\n", pv_h->va, pv_h->pmap);
}

#endif /* MACH_KDB */

#if	MACH_KDB
void db_kvtophys(vm_offset_t);
void db_show_vaddrs(pt_entry_t  *);

/*
 *	print out the results of kvtophys(arg)
 */
void
db_kvtophys(
	vm_offset_t	vaddr)
{
	db_printf("0x%x", kvtophys(vaddr));
}

/*
 *	Walk the pages tables.
 */
void
db_show_vaddrs(
	pt_entry_t	*dirbase)
{
	pt_entry_t	*ptep, *pdep, tmp;
	int		x, y, pdecnt, ptecnt;

	if (dirbase == 0) {
		dirbase = kernel_pmap->dirbase;
	}
	if (dirbase == 0) {
		db_printf("need a dirbase...\n");
		return;
	}
	dirbase = (pt_entry_t *) ((unsigned long) dirbase & ~INTEL_OFFMASK);

	db_printf("dirbase: 0x%x\n", dirbase);

	pdecnt = ptecnt = 0;
	pdep = &dirbase[0];
	for (y = 0; y < NPDES; y++, pdep++) {
		if (((tmp = *pdep) & INTEL_PTE_VALID) == 0) {
			continue;
		}
		pdecnt++;
		ptep = (pt_entry_t *) ((*pdep) & ~INTEL_OFFMASK);
		db_printf("dir[%4d]: 0x%x\n", y, *pdep);
		for (x = 0; x < NPTES; x++, ptep++) {
			if (((tmp = *ptep) & INTEL_PTE_VALID) == 0) {
				continue;
			}
			ptecnt++;
			db_printf("   tab[%4d]: 0x%x, va=0x%x, pa=0x%x\n",
				x,
				*ptep,
				(y << 22) | (x << 12),
				*ptep & ~INTEL_OFFMASK);
		}
	}

	db_printf("total: %d tables, %d page table entries.\n", pdecnt, ptecnt);

}
#endif	/* MACH_KDB */

#include <mach_vm_debug.h>
#if	MACH_VM_DEBUG
#include <vm/vm_debug.h>

int
pmap_list_resident_pages(
	register pmap_t		pmap,
	register vm_offset_t	*listp,
	register int		space)
{
	return 0;
}
#endif	/* MACH_VM_DEBUG */

#ifdef MACH_BSD
/*
 * pmap_pagemove
 *
 * BSD support routine to reassign virtual addresses.
 */

void
pmap_movepage(unsigned long from, unsigned long to, vm_size_t size)
{
	spl_t	spl;
	pt_entry_t	*pte, saved_pte;
	/* Lock the kernel map */


	while (size > 0) {
		PMAP_READ_LOCK(kernel_pmap, spl);
		pte = pmap_pte(kernel_pmap, from);
		if (pte == NULL)
			panic("pmap_pagemove from pte NULL");
		saved_pte = *pte;
		PMAP_READ_UNLOCK(kernel_pmap, spl);

		pmap_enter(kernel_pmap, to, i386_trunc_page(*pte),
			VM_PROT_READ|VM_PROT_WRITE, 0, *pte & INTEL_PTE_WIRED);

		pmap_remove(kernel_pmap, from, from+PAGE_SIZE);

		PMAP_READ_LOCK(kernel_pmap, spl);
		pte = pmap_pte(kernel_pmap, to);
		if (pte == NULL)
			panic("pmap_pagemove 'to' pte NULL");

		*pte = saved_pte;
		PMAP_READ_UNLOCK(kernel_pmap, spl);

		from += PAGE_SIZE;
		to += PAGE_SIZE;
		size -= PAGE_SIZE;
	}

	/* Get the processors to update the TLBs */
	PMAP_FLUSH_TLBS();

}

kern_return_t bmapvideo(vm_offset_t *info);
kern_return_t bmapvideo(vm_offset_t *info) {

	extern struct vc_info vinfo;
#ifdef NOTIMPLEMENTED
	(void)copyout((char *)&vinfo, (char *)info, sizeof(struct vc_info));	/* Copy out the video info */
#endif
	return KERN_SUCCESS;
}

kern_return_t bmapmap(vm_offset_t va, vm_offset_t pa, vm_size_t size, vm_prot_t prot, int attr);
kern_return_t bmapmap(vm_offset_t va, vm_offset_t pa, vm_size_t size, vm_prot_t prot, int attr) {
	
#ifdef NOTIMPLEMENTED
	pmap_map_block(current_act()->task->map->pmap, va, pa, size, prot, attr);	/* Map it in */
#endif
	return KERN_SUCCESS;
}

kern_return_t bmapmapr(vm_offset_t va);
kern_return_t bmapmapr(vm_offset_t va) {
	
#ifdef NOTIMPLEMENTED
	mapping_remove(current_act()->task->map->pmap, va);	/* Remove map */
#endif
	return KERN_SUCCESS;
}
#endif

/* temporary workaround */
boolean_t
coredumpok(vm_map_t map, vm_offset_t va)
{
  pt_entry_t *ptep;
  ptep = pmap_pte(map->pmap, va);
  if (0 == ptep) return FALSE;
  return ((*ptep & (INTEL_PTE_NCACHE|INTEL_PTE_WIRED)) != (INTEL_PTE_NCACHE|INTEL_PTE_WIRED));
}

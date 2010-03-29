/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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

#include <string.h>
#include <mach_kdb.h>
#include <mach_ldebug.h>

#include <libkern/OSAtomic.h>

#include <mach/machine/vm_types.h>

#include <mach/boolean.h>
#include <kern/thread.h>
#include <kern/zalloc.h>
#include <kern/queue.h>

#include <kern/lock.h>
#include <kern/kalloc.h>
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
#include <i386/cpu_data.h>
#include <i386/cpu_number.h>
#include <i386/machine_cpu.h>
#include <i386/seg.h>
#include <i386/serial_io.h>
#include <i386/cpu_capabilities.h>
#include <i386/machine_routines.h>
#include <i386/proc_reg.h>
#include <i386/tsc.h>
#include <i386/acpi.h>
#include <i386/pmap_internal.h>

#if	MACH_KDB
#include <ddb/db_command.h>
#include <ddb/db_output.h>
#include <ddb/db_sym.h>
#include <ddb/db_print.h>
#endif	/* MACH_KDB */

#include <vm/vm_protos.h>

#include <i386/mp.h>
#include <i386/mp_desc.h>
#include <i386/i386_lowmem.h>


/* #define DEBUGINTERRUPTS 1  uncomment to ensure pmap callers have interrupts enabled */
#ifdef DEBUGINTERRUPTS
#define pmap_intr_assert() {if (processor_avail_count > 1 && !ml_get_interrupts_enabled()) panic("pmap interrupt assert %s, %d",__FILE__, __LINE__);}
#else
#define pmap_intr_assert()
#endif

#ifdef IWANTTODEBUG
#undef	DEBUG
#define DEBUG 1
#define POSTCODE_DELAY 1
#include <i386/postcode.h>
#endif /* IWANTTODEBUG */

/*
 * Forward declarations for internal functions.
 */

void		pmap_remove_range(
			pmap_t		pmap,
			vm_map_offset_t	va,
			pt_entry_t	*spte,
			pt_entry_t	*epte);

void		phys_attribute_clear(
			ppnum_t		phys,
			int		bits);

int		phys_attribute_test(
			ppnum_t		phys,
			int		bits);

void		phys_attribute_set(
			ppnum_t		phys,
			int		bits);

void		pmap_set_reference(
			ppnum_t pn);

boolean_t	phys_page_exists(
			ppnum_t pn);


#ifdef PMAP_DEBUG
void dump_pmap(pmap_t);
void dump_4GB_pdpt(pmap_t p);
void dump_4GB_pdpt_thread(thread_t tp);
#endif

int nx_enabled = 1;			/* enable no-execute protection */
#ifdef CONFIG_EMBEDDED
int allow_data_exec  = 0;	/* no exec from data, embedded is hardcore like that */
#else
int allow_data_exec  = VM_ABI_32;	/* 32-bit apps may execute data by default, 64-bit apps may not */
#endif
int allow_stack_exec = 0;		/* No apps may execute from the stack by default */

boolean_t cpu_64bit  = FALSE;
boolean_t pmap_trace = FALSE;

/*
 * when spinning through pmap_remove
 * ensure that we don't spend too much
 * time with preemption disabled.
 * I'm setting the current threshold
 * to 20us
 */
#define MAX_PREEMPTION_LATENCY_NS 20000

uint64_t max_preemption_latency_tsc = 0;


pv_hashed_entry_t     *pv_hash_table;  /* hash lists */

uint32_t npvhash = 0;


/*
 *	pv_list entries are kept on a list that can only be accessed
 *	with the pmap system locked (at SPLVM, not in the cpus_active set).
 *	The list is refilled from the pv_hashed_list_zone if it becomes empty.
 */
pv_rooted_entry_t	pv_free_list = PV_ROOTED_ENTRY_NULL;		/* free list at SPLVM */
pv_hashed_entry_t	pv_hashed_free_list = PV_HASHED_ENTRY_NULL;
pv_hashed_entry_t      pv_hashed_kern_free_list = PV_HASHED_ENTRY_NULL;
decl_simple_lock_data(,pv_hashed_free_list_lock)
decl_simple_lock_data(,pv_hashed_kern_free_list_lock)
decl_simple_lock_data(,pv_hash_table_lock)

int pv_free_count = 0;
int pv_hashed_free_count = 0;
int pv_kern_free_count = 0;
int pv_hashed_kern_free_count = 0;

zone_t		pv_hashed_list_zone;	/* zone of pv_hashed_entry structures */

static zone_t pdpt_zone;

/*
 *	Each entry in the pv_head_table is locked by a bit in the
 *	pv_lock_table.  The lock bits are accessed by the physical
 *	address of the page they lock.
 */

char	*pv_lock_table;		/* pointer to array of bits */
#define pv_lock_table_size(n)	(((n)+BYTE_SIZE-1)/BYTE_SIZE)

char    *pv_hash_lock_table;
#define pv_hash_lock_table_size(n)  (((n)+BYTE_SIZE-1)/BYTE_SIZE)

/*
 *	First and last physical addresses that we maintain any information
 *	for.  Initialized to zero so that pmap operations done before
 *	pmap_init won't touch any non-existent structures.
 */
boolean_t	pmap_initialized = FALSE;/* Has pmap_init completed? */

static struct vm_object kptobj_object_store;
static vm_object_t kptobj;

/*
 *	Array of physical page attribites for managed pages.
 *	One byte per physical page.
 */
char	*pmap_phys_attributes;
unsigned int	last_managed_page = 0;

/*
 *	Physical page attributes.  Copy bits from PTE definition.
 */
#define	PHYS_MODIFIED	INTEL_PTE_MOD	/* page modified */
#define	PHYS_REFERENCED	INTEL_PTE_REF	/* page referenced */
#define PHYS_MANAGED	INTEL_PTE_VALID /* page is managed */

/*
 *	Amount of virtual memory mapped by one
 *	page-directory entry.
 */
#define	PDE_MAPPED_SIZE		(pdetova(1))
uint64_t pde_mapped_size;

/*
 *	Locking and TLB invalidation
 */

/*
 *	Locking Protocols: (changed 2/2007 JK)
 *
 *	There are two structures in the pmap module that need locking:
 *	the pmaps themselves, and the per-page pv_lists (which are locked
 *	by locking the pv_lock_table entry that corresponds to the pv_head
 *	for the list in question.)  Most routines want to lock a pmap and
 *	then do operations in it that require pv_list locking -- however
 *	pmap_remove_all and pmap_copy_on_write operate on a physical page
 *	basis and want to do the locking in the reverse order, i.e. lock
 *	a pv_list and then go through all the pmaps referenced by that list.
 *
 *      The system wide pmap lock has been removed. Now, paths take a lock
 *      on the pmap before changing its 'shape' and the reverse order lockers
 *      (coming in by phys ppn) take a lock on the corresponding pv and then
 *      retest to be sure nothing changed during the window before they locked
 *      and can then run up/down the pv lists holding the list lock. This also
 *      lets the pmap layer run (nearly completely) interrupt enabled, unlike
 *      previously.
 */


/*
 * PV locking
 */

#define LOCK_PVH(index)		{       \
    mp_disable_preemption();           \
    lock_pvh_pai(index);               \
}

#define UNLOCK_PVH(index)  {      \
    unlock_pvh_pai(index);        \
    mp_enable_preemption();       \
}

/*
 * PV hash locking
 */

#define LOCK_PV_HASH(hash)         lock_hash_hash(hash)

#define UNLOCK_PV_HASH(hash)       unlock_hash_hash(hash)

#if	USLOCK_DEBUG
extern int	max_lock_loops;
#define LOOP_VAR							\
	unsigned int	loop_count;					\
	loop_count = disable_serial_output ? max_lock_loops		\
					: max_lock_loops*100
#define LOOP_CHECK(msg, pmap)						\
	if (--loop_count == 0) {					\
		mp_disable_preemption();				\
	    	kprintf("%s: cpu %d pmap %x\n",				\
			  msg, cpu_number(), pmap);			\
            	Debugger("deadlock detection");				\
		mp_enable_preemption();					\
		loop_count = max_lock_loops;				\
	}
#else	/* USLOCK_DEBUG */
#define LOOP_VAR
#define LOOP_CHECK(msg, pmap)
#endif	/* USLOCK_DEBUG */

unsigned pmap_memory_region_count;
unsigned pmap_memory_region_current;

pmap_memory_region_t pmap_memory_regions[PMAP_MEMORY_REGIONS_SIZE];

/*
 *	Other useful macros.
 */
#define current_pmap()		(vm_map_pmap(current_thread()->map))

struct pmap	kernel_pmap_store;
pmap_t		kernel_pmap;

pd_entry_t    high_shared_pde;
pd_entry_t    commpage64_pde;

struct zone	*pmap_zone;		/* zone of pmap structures */

int		pmap_debug = 0;		/* flag for debugging prints */

unsigned int	inuse_ptepages_count = 0;

addr64_t	kernel64_cr3;
boolean_t	no_shared_cr3 = FALSE;	/* -no_shared_cr3 boot arg */


/*
 *	Pmap cache.  Cache is threaded through ref_count field of pmap.
 *	Max will eventually be constant -- variable for experimentation.
 */
int		pmap_cache_max = 32;
int		pmap_alloc_chunk = 8;
pmap_t		pmap_cache_list;
int		pmap_cache_count;
decl_simple_lock_data(,pmap_cache_lock)

extern char end;

static int nkpt;

pt_entry_t     *DMAP1, *DMAP2;
caddr_t         DADDR1;
caddr_t         DADDR2;
/*
 * for legacy, returns the address of the pde entry.
 * for 64 bit, causes the pdpt page containing the pde entry to be mapped,
 * then returns the mapped address of the pde entry in that page
 */
pd_entry_t *
pmap_pde(pmap_t m, vm_map_offset_t v)
{
  pd_entry_t *pde;
	if (!cpu_64bit || (m == kernel_pmap)) {
	  pde = (&((m)->dirbase[(vm_offset_t)(v) >> PDESHIFT]));
	} else {
	  assert(m);
	  assert(ml_get_interrupts_enabled() == 0 || get_preemption_level() != 0);
	  pde = pmap64_pde(m, v);
	}
	return pde;
}


/*
 * the single pml4 page per pmap is allocated at pmap create time and exists
 * for the duration of the pmap. we allocate this page in kernel vm (to save us one
 * level of page table dynamic mapping.
 * this returns the address of the requested pml4 entry in the top level page.
 */
static inline
pml4_entry_t *
pmap64_pml4(pmap_t pmap, vm_map_offset_t vaddr)
{
  return ((pml4_entry_t *)pmap->pm_hold + ((vm_offset_t)((vaddr>>PML4SHIFT)&(NPML4PG-1))));
}

/*
 * maps in the pml4 page, if any, containing the pdpt entry requested
 * and returns the address of the pdpt entry in that mapped page
 */
pdpt_entry_t *
pmap64_pdpt(pmap_t pmap, vm_map_offset_t vaddr)
{
  pml4_entry_t newpf;
  pml4_entry_t *pml4;
  int i;

  assert(pmap);
  assert(ml_get_interrupts_enabled() == 0 || get_preemption_level() != 0);
  if ((vaddr > 0x00007FFFFFFFFFFFULL) && (vaddr < 0xFFFF800000000000ULL)) {
    return(0);
  }

  pml4 = pmap64_pml4(pmap, vaddr);

	if (pml4 && ((*pml4 & INTEL_PTE_VALID))) {

		newpf = *pml4 & PG_FRAME;


		for (i=PMAP_PDPT_FIRST_WINDOW; i < PMAP_PDPT_FIRST_WINDOW+PMAP_PDPT_NWINDOWS; i++) {
		  if (((*(current_cpu_datap()->cpu_pmap->mapwindow[i].prv_CMAP)) & PG_FRAME) == newpf) {
		  return((pdpt_entry_t *)(current_cpu_datap()->cpu_pmap->mapwindow[i].prv_CADDR) + 
			 ((vm_offset_t)((vaddr>>PDPTSHIFT)&(NPDPTPG-1))));
		  }
		}

		  current_cpu_datap()->cpu_pmap->pdpt_window_index++;
		  if (current_cpu_datap()->cpu_pmap->pdpt_window_index > (PMAP_PDPT_FIRST_WINDOW+PMAP_PDPT_NWINDOWS-1))
		    current_cpu_datap()->cpu_pmap->pdpt_window_index = PMAP_PDPT_FIRST_WINDOW;
		  pmap_store_pte(
				 (current_cpu_datap()->cpu_pmap->mapwindow[current_cpu_datap()->cpu_pmap->pdpt_window_index].prv_CMAP),
				 newpf | INTEL_PTE_RW | INTEL_PTE_VALID);
		  invlpg((u_int)(current_cpu_datap()->cpu_pmap->mapwindow[current_cpu_datap()->cpu_pmap->pdpt_window_index].prv_CADDR));
		  return ((pdpt_entry_t *)(current_cpu_datap()->cpu_pmap->mapwindow[current_cpu_datap()->cpu_pmap->pdpt_window_index].prv_CADDR) +
			  ((vm_offset_t)((vaddr>>PDPTSHIFT)&(NPDPTPG-1))));
	}

	return (NULL);
}

/*
 * maps in the pdpt page, if any, containing the pde entry requested
 * and returns the address of the pde entry in that mapped page
 */
pd_entry_t *
pmap64_pde(pmap_t pmap, vm_map_offset_t vaddr)
{
  pdpt_entry_t newpf;
  pdpt_entry_t *pdpt;
  int i;

  assert(pmap);
  assert(ml_get_interrupts_enabled() == 0 || get_preemption_level() != 0);
  if ((vaddr > 0x00007FFFFFFFFFFFULL) && (vaddr < 0xFFFF800000000000ULL)) {
    return(0);
  }

  /*  if (vaddr & (1ULL << 63)) panic("neg addr");*/
  pdpt = pmap64_pdpt(pmap, vaddr);

	  if (pdpt && ((*pdpt & INTEL_PTE_VALID))) {

		newpf = *pdpt & PG_FRAME;

		for (i=PMAP_PDE_FIRST_WINDOW; i < PMAP_PDE_FIRST_WINDOW+PMAP_PDE_NWINDOWS; i++) {
		  if (((*(current_cpu_datap()->cpu_pmap->mapwindow[i].prv_CMAP)) & PG_FRAME) == newpf) {
		  return((pd_entry_t *)(current_cpu_datap()->cpu_pmap->mapwindow[i].prv_CADDR) + 
			 ((vm_offset_t)((vaddr>>PDSHIFT)&(NPDPG-1))));
		  }
		}

		  current_cpu_datap()->cpu_pmap->pde_window_index++;
		  if (current_cpu_datap()->cpu_pmap->pde_window_index > (PMAP_PDE_FIRST_WINDOW+PMAP_PDE_NWINDOWS-1))
		    current_cpu_datap()->cpu_pmap->pde_window_index = PMAP_PDE_FIRST_WINDOW;
		  pmap_store_pte(
				 (current_cpu_datap()->cpu_pmap->mapwindow[current_cpu_datap()->cpu_pmap->pde_window_index].prv_CMAP),
				 newpf | INTEL_PTE_RW | INTEL_PTE_VALID);
		  invlpg((u_int)(current_cpu_datap()->cpu_pmap->mapwindow[current_cpu_datap()->cpu_pmap->pde_window_index].prv_CADDR));
		  return ((pd_entry_t *)(current_cpu_datap()->cpu_pmap->mapwindow[current_cpu_datap()->cpu_pmap->pde_window_index].prv_CADDR) +
			  ((vm_offset_t)((vaddr>>PDSHIFT)&(NPDPG-1))));
	}

	return (NULL);
}

/*
 * Because the page tables (top 3 levels) are mapped into per cpu windows,
 * callers must either disable interrupts or disable preemption before calling
 * one of the pte mapping routines (e.g. pmap_pte()) as the returned vaddr
 * is in one of those mapped windows and that cannot be allowed to change until
 * the caller is done using the returned pte pointer. When done, the caller
 * restores interrupts or preemption to its previous state after which point the
 * vaddr for the returned pte can no longer be used
 */


/*
 * return address of mapped pte for vaddr va in pmap pmap.
 * must be called with pre-emption or interrupts disabled
 * if targeted pmap is not the kernel pmap
 * since we may be passing back a virtual address that is
 * associated with this cpu... pre-emption or interrupts
 * must remain disabled until the caller is done using
 * the pointer that was passed back .
 *
 * maps the pde page, if any, containing the pte in and returns
 * the address of the pte in that mapped page
 */
pt_entry_t     *
pmap_pte(pmap_t pmap, vm_map_offset_t vaddr)
{
        pd_entry_t     *pde;
	pd_entry_t     newpf;
	int i;

	assert(pmap);
	pde = pmap_pde(pmap,vaddr);

	if (pde && ((*pde & INTEL_PTE_VALID))) {
           if (*pde & INTEL_PTE_PS)
                return pde;
	    if (pmap == kernel_pmap)
	        return (vtopte(vaddr)); /* compat kernel still has pte's mapped */
#if TESTING
	    if (ml_get_interrupts_enabled() && get_preemption_level() == 0)
	        panic("pmap_pte: unsafe call");
#endif
	        assert(ml_get_interrupts_enabled() == 0 || get_preemption_level() != 0);

		newpf = *pde & PG_FRAME;

		for (i=PMAP_PTE_FIRST_WINDOW; i < PMAP_PTE_FIRST_WINDOW+PMAP_PTE_NWINDOWS; i++) {
		  if (((*(current_cpu_datap()->cpu_pmap->mapwindow[i].prv_CMAP)) & PG_FRAME) == newpf) {
		  return((pt_entry_t *)(current_cpu_datap()->cpu_pmap->mapwindow[i].prv_CADDR) + 
			 ((vm_offset_t)i386_btop(vaddr) & (NPTEPG-1)));
		  }
		}

		  current_cpu_datap()->cpu_pmap->pte_window_index++;
		  if (current_cpu_datap()->cpu_pmap->pte_window_index > (PMAP_PTE_FIRST_WINDOW+PMAP_PTE_NWINDOWS-1))
		    current_cpu_datap()->cpu_pmap->pte_window_index = PMAP_PTE_FIRST_WINDOW;
		  pmap_store_pte(
				 (current_cpu_datap()->cpu_pmap->mapwindow[current_cpu_datap()->cpu_pmap->pte_window_index].prv_CMAP),
				 newpf | INTEL_PTE_RW | INTEL_PTE_VALID);
		  invlpg((u_int)(current_cpu_datap()->cpu_pmap->mapwindow[current_cpu_datap()->cpu_pmap->pte_window_index].prv_CADDR));
		  return ((pt_entry_t *)(current_cpu_datap()->cpu_pmap->mapwindow[current_cpu_datap()->cpu_pmap->pte_window_index].prv_CADDR) +
			  ((vm_offset_t)i386_btop(vaddr) & (NPTEPG-1)));
	}

	return(NULL);
}
	

/*
 *	Map memory at initialization.  The physical addresses being
 *	mapped are not managed and are never unmapped.
 *
 *	For now, VM is already on, we only need to map the
 *	specified memory.
 */
vm_offset_t
pmap_map(
	vm_offset_t	virt,
	vm_map_offset_t	start_addr,
	vm_map_offset_t	end_addr,
	vm_prot_t	prot,
	unsigned int	flags)
{
	int		ps;

	ps = PAGE_SIZE;
	while (start_addr < end_addr) {
		pmap_enter(kernel_pmap, (vm_map_offset_t)virt,
			   (ppnum_t) i386_btop(start_addr), prot, flags, FALSE);
		virt += ps;
		start_addr += ps;
	}
	return(virt);
}

/*
 *	Back-door routine for mapping kernel VM at initialization.  
 * 	Useful for mapping memory outside the range
 *      Sets no-cache, A, D.
 *	Otherwise like pmap_map.
 */
vm_offset_t
pmap_map_bd(
	vm_offset_t	virt,
	vm_map_offset_t	start_addr,
	vm_map_offset_t	end_addr,
	vm_prot_t	prot,
	unsigned int	flags)
{
	pt_entry_t	template;
	pt_entry_t      *pte;
	spl_t           spl;

	template = pa_to_pte(start_addr)
		| INTEL_PTE_REF
		| INTEL_PTE_MOD
		| INTEL_PTE_WIRED
		| INTEL_PTE_VALID;

	if(flags & (VM_MEM_NOT_CACHEABLE | VM_WIMG_USE_DEFAULT)) {
	    template |= INTEL_PTE_NCACHE;
	    if(!(flags & (VM_MEM_GUARDED | VM_WIMG_USE_DEFAULT)))
		    template |= INTEL_PTE_PTA;
	}

	if (prot & VM_PROT_WRITE)
	    template |= INTEL_PTE_WRITE;


	while (start_addr < end_addr) {
	        spl = splhigh();
		pte = pmap_pte(kernel_pmap, (vm_map_offset_t)virt);
		if (pte == PT_ENTRY_NULL) {
			panic("pmap_map_bd: Invalid kernel address\n");
		}
		pmap_store_pte(pte, template);
		splx(spl);
		pte_increment_pa(template);
		virt += PAGE_SIZE;
		start_addr += PAGE_SIZE;
	} 


	flush_tlb();
	return(virt);
}

extern	char			*first_avail;
extern	vm_offset_t		virtual_avail, virtual_end;
extern	pmap_paddr_t		avail_start, avail_end;

void
pmap_cpu_init(void)
{
	/*
	 * Here early in the life of a processor (from cpu_mode_init()).
	 * If we're not in 64-bit mode, enable the global TLB feature.
	 * Note: regardless of mode we continue to set the global attribute
	 * bit in ptes for all (32-bit) global pages such as the commpage.
	 */
	if (!cpu_64bit) {
		set_cr4(get_cr4() | CR4_PGE);
	}

	/*
	 * Initialize the per-cpu, TLB-related fields.
	 */
	current_cpu_datap()->cpu_active_cr3 = kernel_pmap->pm_cr3;
	current_cpu_datap()->cpu_tlb_invalid = FALSE;
}

vm_offset_t
pmap_high_shared_remap(enum high_fixed_addresses e, vm_offset_t va, int sz)
{
  vm_offset_t ve = pmap_index_to_virt(e);
  pt_entry_t *ptep;
  pmap_paddr_t pa;
  int i;
  spl_t s;

  assert(0 == (va & PAGE_MASK));  /* expecting page aligned */
  s = splhigh();
  ptep = pmap_pte(kernel_pmap, (vm_map_offset_t)ve);

  for (i=0; i< sz; i++) {
    pa = (pmap_paddr_t) kvtophys(va);
    pmap_store_pte(ptep, (pa & PG_FRAME)
				| INTEL_PTE_VALID
		                | INTEL_PTE_GLOBAL
				| INTEL_PTE_RW
				| INTEL_PTE_REF
				| INTEL_PTE_MOD);
    va+= PAGE_SIZE;
    ptep++;
  }
  splx(s);
  return ve;
}

vm_offset_t
pmap_cpu_high_shared_remap(int cpu, enum high_cpu_types e, vm_offset_t va, int sz)
{ 
  enum high_fixed_addresses	a = e + HIGH_CPU_END * cpu;
  return pmap_high_shared_remap(HIGH_FIXED_CPUS_BEGIN + a, va, sz);
}

void pmap_init_high_shared(void);

extern vm_offset_t gdtptr, idtptr;

extern uint32_t low_intstack;

extern struct fake_descriptor ldt_desc_pattern;
extern struct fake_descriptor tss_desc_pattern;

extern char hi_remap_text, hi_remap_etext;
extern char t_zero_div;

pt_entry_t *pte_unique_base;

void
pmap_init_high_shared(void)
{

	vm_offset_t haddr;
	spl_t s;
#if MACH_KDB
	struct i386_tss *ttss;
#endif

	cpu_desc_index_t * cdi = &cpu_data_master.cpu_desc_index;

	kprintf("HIGH_MEM_BASE 0x%x fixed per-cpu begin 0x%x\n", 
		HIGH_MEM_BASE,pmap_index_to_virt(HIGH_FIXED_CPUS_BEGIN));
	s = splhigh();
	pte_unique_base = pmap_pte(kernel_pmap, (vm_map_offset_t)pmap_index_to_virt(HIGH_FIXED_CPUS_BEGIN));
	splx(s);

	if (i386_btop(&hi_remap_etext - &hi_remap_text + 1) >
				HIGH_FIXED_TRAMPS_END - HIGH_FIXED_TRAMPS + 1)
		panic("tramps too large");
	haddr = pmap_high_shared_remap(HIGH_FIXED_TRAMPS,
					(vm_offset_t) &hi_remap_text, 3);
	kprintf("tramp: 0x%x, ",haddr);
	/* map gdt up high and update ptr for reload */
	haddr = pmap_high_shared_remap(HIGH_FIXED_GDT,
					(vm_offset_t) master_gdt, 1);
	cdi->cdi_gdt.ptr = (void *)haddr;
	kprintf("GDT: 0x%x, ",haddr);
	/* map ldt up high */
	haddr = pmap_high_shared_remap(HIGH_FIXED_LDT_BEGIN,
					(vm_offset_t) master_ldt,
					HIGH_FIXED_LDT_END - HIGH_FIXED_LDT_BEGIN + 1);
	cdi->cdi_ldt = (struct fake_descriptor *)haddr;
	kprintf("LDT: 0x%x, ",haddr);
	/* put new ldt addr into gdt */
	struct fake_descriptor temp_fake_desc;
	temp_fake_desc = ldt_desc_pattern;
	temp_fake_desc.offset = (vm_offset_t) haddr;
	fix_desc(&temp_fake_desc, 1);
	
	*(struct fake_descriptor *) &master_gdt[sel_idx(KERNEL_LDT)] = temp_fake_desc;
	*(struct fake_descriptor *) &master_gdt[sel_idx(USER_LDT)] = temp_fake_desc;

	/* map idt up high */
	haddr = pmap_high_shared_remap(HIGH_FIXED_IDT,
					(vm_offset_t) master_idt, 1);
	cdi->cdi_idt.ptr = (void *)haddr;
	kprintf("IDT: 0x%x, ", haddr);
	/* remap ktss up high and put new high addr into gdt */
	haddr = pmap_high_shared_remap(HIGH_FIXED_KTSS,
					(vm_offset_t) &master_ktss, 1);

	temp_fake_desc = tss_desc_pattern;
	temp_fake_desc.offset = (vm_offset_t) haddr;
	fix_desc(&temp_fake_desc, 1);
	*(struct fake_descriptor *) &master_gdt[sel_idx(KERNEL_TSS)] = temp_fake_desc;
	kprintf("KTSS: 0x%x, ",haddr);
#if MACH_KDB
	/* remap dbtss up high and put new high addr into gdt */
	haddr = pmap_high_shared_remap(HIGH_FIXED_DBTSS,
					(vm_offset_t) &master_dbtss, 1);
	temp_fake_desc = tss_desc_pattern;
	temp_fake_desc.offset = (vm_offset_t) haddr;
	fix_desc(&temp_fake_desc, 1);
	*(struct fake_descriptor *)&master_gdt[sel_idx(DEBUG_TSS)] = temp_fake_desc;
	ttss = (struct i386_tss *)haddr;
	kprintf("DBTSS: 0x%x, ",haddr);
#endif	/* MACH_KDB */

	/* remap dftss up high and put new high addr into gdt */
	haddr = pmap_high_shared_remap(HIGH_FIXED_DFTSS,
					(vm_offset_t) &master_dftss, 1);
	temp_fake_desc = tss_desc_pattern;
	temp_fake_desc.offset = (vm_offset_t) haddr;
	fix_desc(&temp_fake_desc, 1);
	*(struct fake_descriptor *) &master_gdt[sel_idx(DF_TSS)] = temp_fake_desc;
	kprintf("DFTSS: 0x%x\n",haddr);

	/* remap mctss up high and put new high addr into gdt */
	haddr = pmap_high_shared_remap(HIGH_FIXED_DFTSS,
					(vm_offset_t) &master_mctss, 1);
	temp_fake_desc = tss_desc_pattern;
	temp_fake_desc.offset = (vm_offset_t) haddr;
	fix_desc(&temp_fake_desc, 1);
	*(struct fake_descriptor *) &master_gdt[sel_idx(MC_TSS)] = temp_fake_desc;
	kprintf("MCTSS: 0x%x\n",haddr);

	cpu_desc_load(&cpu_data_master);
}


/*
 *	Bootstrap the system enough to run with virtual memory.
 *	Map the kernel's code and data, and allocate the system page table.
 *	Called with mapping OFF.  Page_size must already be set.
 */

void
pmap_bootstrap(
	__unused vm_offset_t	load_start,
	boolean_t		IA32e)
{
	vm_offset_t	va;
	pt_entry_t	*pte;
	int i;
	pdpt_entry_t *pdpt;
	spl_t s;

	vm_last_addr = VM_MAX_KERNEL_ADDRESS;	/* Set the highest address
						 * known to VM */
	/*
	 *	The kernel's pmap is statically allocated so we don't
	 *	have to use pmap_create, which is unlikely to work
	 *	correctly at this part of the boot sequence.
	 */


	kernel_pmap = &kernel_pmap_store;
	kernel_pmap->ref_count = 1;
	kernel_pmap->nx_enabled = FALSE;
	kernel_pmap->pm_task_map = TASK_MAP_32BIT;
	kernel_pmap->pm_obj = (vm_object_t) NULL;
	kernel_pmap->dirbase = (pd_entry_t *)((unsigned int)IdlePTD | KERNBASE);
	kernel_pmap->pdirbase = (pmap_paddr_t)((int)IdlePTD);
	pdpt = (pd_entry_t *)((unsigned int)IdlePDPT | KERNBASE );
	kernel_pmap->pm_pdpt = pdpt;
	kernel_pmap->pm_cr3 = (pmap_paddr_t)((int)IdlePDPT);


	va = (vm_offset_t)kernel_pmap->dirbase;
	/* setup self referential mapping(s) */
	for (i = 0; i< NPGPTD; i++, pdpt++) {
	  pmap_paddr_t pa;
	  pa = (pmap_paddr_t) kvtophys((vm_offset_t)(va + i386_ptob(i)));
	  pmap_store_pte(
	    (pd_entry_t *) (kernel_pmap->dirbase + PTDPTDI + i),
	    (pa & PG_FRAME) | INTEL_PTE_VALID | INTEL_PTE_RW | INTEL_PTE_REF |
	      INTEL_PTE_MOD | INTEL_PTE_WIRED) ;
	  pmap_store_pte(pdpt, pa | INTEL_PTE_VALID);
	}

	cpu_64bit = IA32e;
	
	lo_kernel_cr3 = kernel_pmap->pm_cr3;
	current_cpu_datap()->cpu_kernel_cr3 = (addr64_t) kernel_pmap->pm_cr3;

	/* save the value we stuff into created pmaps to share the gdts etc */
	high_shared_pde = *pmap_pde(kernel_pmap, HIGH_MEM_BASE);
	/* make sure G bit is on for high shared pde entry */
	high_shared_pde |= INTEL_PTE_GLOBAL;
	s = splhigh();
	pmap_store_pte(pmap_pde(kernel_pmap, HIGH_MEM_BASE), high_shared_pde);
	splx(s);

	nkpt = NKPT;
	OSAddAtomic(NKPT, &inuse_ptepages_count);

	virtual_avail = (vm_offset_t)VADDR(KPTDI,0) + (vm_offset_t)first_avail;
	virtual_end = (vm_offset_t)(VM_MAX_KERNEL_ADDRESS);

	/*
	 * Reserve some special page table entries/VA space for temporary
	 * mapping of pages.
	 */
#define	SYSMAP(c, p, v, n)	\
	v = (c)va; va += ((n)*INTEL_PGBYTES); p = pte; pte += (n)

	va = virtual_avail;
	pte = vtopte(va);

        for (i=0; i<PMAP_NWINDOWS; i++) {
            SYSMAP(caddr_t,
		   (current_cpu_datap()->cpu_pmap->mapwindow[i].prv_CMAP),
                   (current_cpu_datap()->cpu_pmap->mapwindow[i].prv_CADDR),
		   1);
            *current_cpu_datap()->cpu_pmap->mapwindow[i].prv_CMAP = 0;
        }

	/* DMAP user for debugger */
	SYSMAP(caddr_t, DMAP1, DADDR1, 1);
	SYSMAP(caddr_t, DMAP2, DADDR2, 1);  /* XXX temporary - can remove */

	virtual_avail = va;

	if (PE_parse_boot_argn("npvhash", &npvhash, sizeof (npvhash))) {
	  if (0 != ((npvhash+1) & npvhash)) {
	    kprintf("invalid hash %d, must be ((2^N)-1), using default %d\n",npvhash,NPVHASH);
	    npvhash = NPVHASH;
	  }
	} else {
	  npvhash = NPVHASH;
	}
	printf("npvhash=%d\n",npvhash);

	simple_lock_init(&kernel_pmap->lock, 0);
	simple_lock_init(&pv_hashed_free_list_lock, 0);
	simple_lock_init(&pv_hashed_kern_free_list_lock, 0);
	simple_lock_init(&pv_hash_table_lock,0);

	pmap_init_high_shared();

	pde_mapped_size = PDE_MAPPED_SIZE;

	if (cpu_64bit) {
	  pdpt_entry_t *ppdpt   = IdlePDPT;
	  pdpt_entry_t *ppdpt64 = (pdpt_entry_t *)IdlePDPT64;
	  pdpt_entry_t *ppml4   = (pdpt_entry_t *)IdlePML4;
	  int istate = ml_set_interrupts_enabled(FALSE);

	  /*
	   * Clone a new 64-bit 3rd-level page table directory, IdlePML4,
	   * with page bits set for the correct IA-32e operation and so that
	   * the legacy-mode IdlePDPT is retained for slave processor start-up.
	   * This is necessary due to the incompatible use of page bits between
	   * 64-bit and legacy modes.
	   */
	  kernel_pmap->pm_cr3 = (pmap_paddr_t)((int)IdlePML4); /* setup in start.s for us */
	  kernel_pmap->pm_pml4 = IdlePML4;
	  kernel_pmap->pm_pdpt = (pd_entry_t *)
					((unsigned int)IdlePDPT64 | KERNBASE );
#define PAGE_BITS INTEL_PTE_VALID|INTEL_PTE_RW|INTEL_PTE_USER|INTEL_PTE_REF
	  pmap_store_pte(kernel_pmap->pm_pml4,
		 	 (uint32_t)IdlePDPT64 | PAGE_BITS);
	  pmap_store_pte((ppdpt64+0), *(ppdpt+0) | PAGE_BITS);
	  pmap_store_pte((ppdpt64+1), *(ppdpt+1) | PAGE_BITS);
	  pmap_store_pte((ppdpt64+2), *(ppdpt+2) | PAGE_BITS);
	  pmap_store_pte((ppdpt64+3), *(ppdpt+3) | PAGE_BITS);

	  /*
	   * The kernel is also mapped in the uber-sapce at the 4GB starting
	   * 0xFFFFFF80:00000000. This is the highest entry in the 4th-level.
	   */
	  pmap_store_pte((ppml4+KERNEL_UBER_PML4_INDEX), *(ppml4+0));

	  kernel64_cr3 = (addr64_t) kernel_pmap->pm_cr3;

	  /* Re-initialize descriptors and prepare to switch modes */
	  cpu_desc_init64(&cpu_data_master);
	  current_cpu_datap()->cpu_is64bit = TRUE;
	  current_cpu_datap()->cpu_active_cr3 = kernel64_cr3;

	  pde_mapped_size = 512*4096 ; 

	  ml_set_interrupts_enabled(istate);
	}

	/* Sets 64-bit mode if required. */
	cpu_mode_init(&cpu_data_master);
	/* Update in-kernel CPUID information if we're now in 64-bit mode */
	if (IA32e)
		cpuid_set_info();

	kernel_pmap->pm_hold = (vm_offset_t)kernel_pmap->pm_pml4;

	kprintf("Kernel virtual space from 0x%x to 0x%x.\n",
			VADDR(KPTDI,0), virtual_end);
	printf("PAE enabled\n");
	if (cpu_64bit){
	  printf("64 bit mode enabled\n");kprintf("64 bit mode enabled\n"); }

	kprintf("Available physical space from 0x%llx to 0x%llx\n",
			avail_start, avail_end);

	/*
	 * By default for 64-bit users loaded at 4GB, share kernel mapping.
	 * But this may be overridden by the -no_shared_cr3 boot-arg.
	 */
	if (PE_parse_boot_argn("-no_shared_cr3", &no_shared_cr3, sizeof (no_shared_cr3))) {
		kprintf("Shared kernel address space disabled\n");
	}	

#ifdef	PMAP_TRACES
	if (PE_parse_boot_argn("-pmap_trace", &pmap_trace, sizeof (pmap_trace))) {
		kprintf("Kernel traces for pmap operations enabled\n");
	}	
#endif	/* PMAP_TRACES */
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
	vm_map_offset_t		vaddr;
	ppnum_t ppn;

	/*
	 *	Allocate memory for the pv_head_table and its lock bits,
	 *	the modify bit array, and the pte_page table.
	 */

	/*
	 * zero bias all these arrays now instead of off avail_start
	 * so we cover all memory
	 */

	npages = (long)i386_btop(avail_end);
	s = (vm_size_t) (sizeof(struct pv_rooted_entry) * npages
			 + (sizeof (struct pv_hashed_entry_t *) * (npvhash+1))
			 + pv_lock_table_size(npages)
			 + pv_hash_lock_table_size((npvhash+1))
				+ npages);

	s = round_page(s);
	if (kernel_memory_allocate(kernel_map, &addr, s, 0,
				   KMA_KOBJECT | KMA_PERMANENT)
	    != KERN_SUCCESS)
		panic("pmap_init");

	memset((char *)addr, 0, s);

#if PV_DEBUG
	if (0 == npvhash) panic("npvhash not initialized");
#endif

	/*
	 *	Allocate the structures first to preserve word-alignment.
	 */
	pv_head_table = (pv_rooted_entry_t) addr;
	addr = (vm_offset_t) (pv_head_table + npages);

	pv_hash_table = (pv_hashed_entry_t *)addr;
	addr = (vm_offset_t) (pv_hash_table + (npvhash + 1));

	pv_lock_table = (char *) addr;
	addr = (vm_offset_t) (pv_lock_table + pv_lock_table_size(npages));

	pv_hash_lock_table = (char *) addr;
	addr = (vm_offset_t) (pv_hash_lock_table + pv_hash_lock_table_size((npvhash+1)));

	pmap_phys_attributes = (char *) addr;
	{
	        unsigned int i;
		unsigned int pn;
		ppnum_t  last_pn;
		pmap_memory_region_t *pmptr = pmap_memory_regions;

		last_pn = (ppnum_t)i386_btop(avail_end);

		for (i = 0; i < pmap_memory_region_count; i++, pmptr++) {
		        if (pmptr->type == kEfiConventionalMemory) {

			        for (pn = pmptr->base; pn <= pmptr->end; pn++) {
				        if (pn < last_pn) {
					        pmap_phys_attributes[pn] |= PHYS_MANAGED;

						if (pn > last_managed_page)
						        last_managed_page = pn;
					}
				}
			}
		}
	}

	/*
	 *	Create the zone of physical maps,
	 *	and of the physical-to-virtual entries.
	 */
	s = (vm_size_t) sizeof(struct pmap);
	pmap_zone = zinit(s, 400*s, 4096, "pmap"); /* XXX */
	s = (vm_size_t) sizeof(struct pv_hashed_entry);
	pv_hashed_list_zone = zinit(s, 10000*s, 4096, "pv_list"); /* XXX */
	s = 63;
	pdpt_zone = zinit(s, 400*s, 4096, "pdpt"); /* XXX */

	kptobj = &kptobj_object_store;
	_vm_object_allocate((vm_object_size_t)(NPGPTD*NPTDPG), kptobj);
	kernel_pmap->pm_obj = kptobj;

	/* create pv entries for kernel pages mapped by low level
	   startup code.  these have to exist so we can pmap_remove()
	   e.g. kext pages from the middle of our addr space */

	vaddr = (vm_map_offset_t)0;
	for (ppn = 0; ppn < i386_btop(avail_start) ; ppn++ ) {
	  pv_rooted_entry_t	pv_e;

	  pv_e = pai_to_pvh(ppn);
	  pv_e->va = vaddr;
	  vaddr += PAGE_SIZE;
	  pv_e->pmap = kernel_pmap;
	  queue_init(&pv_e->qlink);
	}

	pmap_initialized = TRUE;

	/*
	 *	Initialize pmap cache.
	 */
	pmap_cache_list = PMAP_NULL;
	pmap_cache_count = 0;
	simple_lock_init(&pmap_cache_lock, 0);

	max_preemption_latency_tsc = tmrCvt((uint64_t)MAX_PREEMPTION_LATENCY_NS, tscFCvtn2t);

}


#define managed_page(x) ( (unsigned int)x <= last_managed_page && (pmap_phys_attributes[x] & PHYS_MANAGED) )

/*
 * this function is only used for debugging fron the vm layer
 */
boolean_t
pmap_verify_free(
		 ppnum_t pn)
{
	pv_rooted_entry_t	pv_h;
	int		pai;
	boolean_t	result;

	assert(pn != vm_page_fictitious_addr);

	if (!pmap_initialized)
		return(TRUE);

	if (pn == vm_page_guard_addr)
		return TRUE;

	pai = ppn_to_pai(pn);
	if (!managed_page(pai))
		return(FALSE);
	pv_h = pai_to_pvh(pn);
	result = (pv_h->pmap == PMAP_NULL);
	return(result);
}

boolean_t
pmap_is_empty(
       pmap_t          pmap,
       vm_map_offset_t va_start,
       vm_map_offset_t va_end)
{
	vm_map_offset_t offset;
	ppnum_t         phys_page;

	if (pmap == PMAP_NULL) {
		return TRUE;
	}

	/*
	 * Check the resident page count
	 * - if it's zero, the pmap is completely empty.
	 * This short-circuit test prevents a virtual address scan which is
	 * painfully slow for 64-bit spaces.
	 * This assumes the count is correct
	 * .. the debug kernel ought to be checking perhaps by page table walk.
	 */
	if (pmap->stats.resident_count == 0)
		return TRUE;

	for (offset = va_start;
	     offset < va_end;
	     offset += PAGE_SIZE_64) {
		phys_page = pmap_find_phys(pmap, offset);
		if (phys_page) {
			if (pmap != kernel_pmap &&
			    pmap->pm_task_map == TASK_MAP_32BIT &&
			    offset >= HIGH_MEM_BASE) {
				/*
				 * The "high_shared_pde" is used to share
				 * the entire top-most 2MB of address space
				 * between the kernel and all 32-bit tasks.
				 * So none of this can be removed from 32-bit
				 * tasks.
				 * Let's pretend there's nothing up
				 * there...
				 */
				return TRUE;
			}
			kprintf("pmap_is_empty(%p,0x%llx,0x%llx): "
				"page %d at 0x%llx\n",
				pmap, va_start, va_end, phys_page, offset);
			return FALSE;
		}
	}

	return TRUE;
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
	    vm_map_size_t	sz,
	    boolean_t		is_64bit)
{
	pmap_t			p;
	int		i;
	vm_offset_t	va;
	vm_size_t	size;
	pdpt_entry_t    *pdpt;
	pml4_entry_t    *pml4p;
	pd_entry_t      *pdp;
	int template;
	spl_t s;

	PMAP_TRACE(PMAP_CODE(PMAP__CREATE) | DBG_FUNC_START,
		   (int) (sz>>32), (int) sz, (int) is_64bit, 0, 0);

	size = (vm_size_t) sz;

	/*
	 *	A software use-only map doesn't even need a map.
	 */

	if (size != 0) {
		return(PMAP_NULL);
	}

	p = (pmap_t) zalloc(pmap_zone);
	if (PMAP_NULL == p)
		panic("pmap_create zalloc");

	/* init counts now since we'll be bumping some */
	simple_lock_init(&p->lock, 0);
	p->stats.resident_count = 0;
	p->stats.resident_max = 0;
	p->stats.wired_count = 0;
	p->ref_count = 1;
	p->nx_enabled = 1;
	p->pm_shared = FALSE;

	assert(!is_64bit || cpu_64bit);
	p->pm_task_map = is_64bit ? TASK_MAP_64BIT : TASK_MAP_32BIT;;

	if (!cpu_64bit) {
		/* legacy 32 bit setup */
		/* in the legacy case the pdpt layer is hardwired to 4 entries and each
		 * entry covers 1GB of addr space */
		if (KERN_SUCCESS != kmem_alloc_kobject(kernel_map, (vm_offset_t *)(&p->dirbase), NBPTD))
			panic("pmap_create kmem_alloc_kobject");
		p->pm_hold = (vm_offset_t)zalloc(pdpt_zone);
		if ((vm_offset_t)NULL == p->pm_hold) {
			panic("pdpt zalloc");
		}
		pdpt = (pdpt_entry_t *) (( p->pm_hold + 31) & ~31);
		p->pm_cr3 = (pmap_paddr_t)kvtophys((vm_offset_t)pdpt);
		if (NULL == (p->pm_obj = vm_object_allocate((vm_object_size_t)(NPGPTD*NPTDPG))))
			panic("pmap_create vm_object_allocate");

		memset((char *)p->dirbase, 0, NBPTD);

		va = (vm_offset_t)p->dirbase;
		p->pdirbase = kvtophys(va);

		template = INTEL_PTE_VALID;
		for (i = 0; i< NPGPTD; i++, pdpt++ ) {
			pmap_paddr_t pa;
			pa = (pmap_paddr_t) kvtophys((vm_offset_t)(va + i386_ptob(i)));
			pmap_store_pte(pdpt, pa | template);
		}

		/* map the high shared pde */
		s = splhigh();
		pmap_store_pte(pmap_pde(p, HIGH_MEM_BASE), high_shared_pde);
		splx(s);

	} else {
	        /* 64 bit setup  */

	        /* alloc the pml4 page in kernel vm */
	        if (KERN_SUCCESS != kmem_alloc_kobject(kernel_map, (vm_offset_t *)(&p->pm_hold), PAGE_SIZE))
		        panic("pmap_create kmem_alloc_kobject pml4");

	        memset((char *)p->pm_hold, 0, PAGE_SIZE);
		p->pm_cr3 = (pmap_paddr_t)kvtophys((vm_offset_t)p->pm_hold);

		OSAddAtomic(1,  &inuse_ptepages_count);

		/* allocate the vm_objs to hold the pdpt, pde and pte pages */

		if (NULL == (p->pm_obj_pml4 = vm_object_allocate((vm_object_size_t)(NPML4PGS))))
			panic("pmap_create pdpt obj");

		if (NULL == (p->pm_obj_pdpt = vm_object_allocate((vm_object_size_t)(NPDPTPGS))))
			panic("pmap_create pdpt obj");

		if (NULL == (p->pm_obj = vm_object_allocate((vm_object_size_t)(NPDEPGS))))
			panic("pmap_create pte obj");

		/* uber space points to uber mapped kernel */
		s = splhigh();
		pml4p = pmap64_pml4(p, 0ULL);
		pmap_store_pte((pml4p+KERNEL_UBER_PML4_INDEX), *kernel_pmap->pm_pml4);


		if (!is_64bit) {
			while ((pdp = pmap64_pde(p, (uint64_t)HIGH_MEM_BASE)) == PD_ENTRY_NULL) {
				splx(s);
				pmap_expand_pdpt(p, (uint64_t)HIGH_MEM_BASE); /* need room for another pde entry */
				s = splhigh();
			}
			pmap_store_pte(pdp, high_shared_pde);
		}
		splx(s);
	}

	PMAP_TRACE(PMAP_CODE(PMAP__CREATE) | DBG_FUNC_START,
		   (int) p, is_64bit, 0, 0, 0);

	return(p);
}

/*
 * The following routines implement the shared address optmization for 64-bit
 * users with a 4GB page zero.
 *
 * pmap_set_4GB_pagezero()
 *	is called in the exec and fork paths to mirror the kernel's
 *	mapping in the bottom 4G of the user's pmap. The task mapping changes
 *	from TASK_MAP_64BIT to TASK_MAP_64BIT_SHARED. This routine returns
 *	without doing anything if the -no_shared_cr3 boot-arg is set.
 *
 * pmap_clear_4GB_pagezero()
 *	is called in the exec/exit paths to undo this mirror. The task mapping
 *	reverts to TASK_MAP_64BIT. In addition, we switch to the kernel's
 *	CR3 by calling pmap_load_kernel_cr3(). 
 *
 * pmap_load_kernel_cr3()
 *	loads cr3 with the kernel's page table. In addition to being called
 * 	by pmap_clear_4GB_pagezero(), it is used both prior to teardown and
 *	when we go idle in the context of a shared map.
 *
 * Further notes on per-cpu data used:
 *
 *	cpu_kernel_cr3	is the cr3 for the kernel's pmap.
 *			This is loaded in a trampoline on entering the kernel
 *			from a 32-bit user (or non-shared-cr3 64-bit user).
 *	cpu_task_cr3	is the cr3 for the current thread.
 *			This is loaded in a trampoline as we exit the kernel.
 *	cpu_active_cr3	reflects the cr3 currently loaded.
 *			However, the low order bit is set when the
 *			processor is idle or interrupts are disabled
 *			while the system pmap lock is held. It is used by
 *			tlb shoot-down.
 *	cpu_task_map	indicates whether the task cr3 belongs to
 *			a 32-bit, a 64-bit or a 64-bit shared map.
 *			The latter allows the avoidance of the cr3 load
 *			on kernel entry and exit.
 *	cpu_tlb_invalid	set TRUE when a tlb flush is requested.
 *			If the cr3 is "inactive" (the cpu is idle or the
 *			system-wide pmap lock is held) this not serviced by
 *			an IPI but at time when the cr3 becomes "active".
 */ 

void
pmap_set_4GB_pagezero(pmap_t p)
{
	pdpt_entry_t	*user_pdptp;
	pdpt_entry_t	*kern_pdptp;

	assert(p->pm_task_map != TASK_MAP_32BIT);

	/* Kernel-shared cr3 may be disabled by boot arg. */
	if (no_shared_cr3)
		return;

	/*
	 * Set the bottom 4 3rd-level pte's to be the kernel's.
	 */
	PMAP_LOCK(p);
	while ((user_pdptp = pmap64_pdpt(p, 0x0)) == PDPT_ENTRY_NULL) {
		PMAP_UNLOCK(p);
		pmap_expand_pml4(p, 0x0);
		PMAP_LOCK(p);
	}
	kern_pdptp = kernel_pmap->pm_pdpt;
	pmap_store_pte(user_pdptp+0, *(kern_pdptp+0));
	pmap_store_pte(user_pdptp+1, *(kern_pdptp+1));
	pmap_store_pte(user_pdptp+2, *(kern_pdptp+2));
	pmap_store_pte(user_pdptp+3, *(kern_pdptp+3));
	p->pm_task_map = TASK_MAP_64BIT_SHARED;
	PMAP_UNLOCK(p);
}

void
pmap_clear_4GB_pagezero(pmap_t p)
{
	pdpt_entry_t	*user_pdptp;

	if (p->pm_task_map != TASK_MAP_64BIT_SHARED)
		return;

	PMAP_LOCK(p);

	p->pm_task_map = TASK_MAP_64BIT;

	pmap_load_kernel_cr3();

	user_pdptp = pmap64_pdpt(p, 0x0);
	pmap_store_pte(user_pdptp+0, 0);
	pmap_store_pte(user_pdptp+1, 0);
	pmap_store_pte(user_pdptp+2, 0);
	pmap_store_pte(user_pdptp+3, 0);

	PMAP_UNLOCK(p);
}

void
pmap_load_kernel_cr3(void)
{
	uint64_t	kernel_cr3;

	assert(ml_get_interrupts_enabled() == 0 || get_preemption_level() != 0);

	/*
	 * Reload cr3 with the true kernel cr3.
	 */
	kernel_cr3 = current_cpu_datap()->cpu_kernel_cr3;
	set64_cr3(kernel_cr3);
	current_cpu_datap()->cpu_active_cr3 = kernel_cr3;
	current_cpu_datap()->cpu_tlb_invalid = FALSE;
	__asm__ volatile("mfence");
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
	register int		c;

	if (p == PMAP_NULL)
		return;

	PMAP_TRACE(PMAP_CODE(PMAP__DESTROY) | DBG_FUNC_START,
		   (int) p, 0, 0, 0, 0);

	PMAP_LOCK(p);

	c = --p->ref_count;

	if (c == 0) {
		/* 
		 * If some cpu is not using the physical pmap pointer that it
		 * is supposed to be (see set_dirbase), we might be using the
		 * pmap that is being destroyed! Make sure we are
		 * physically on the right pmap:
		 */
		PMAP_UPDATE_TLBS(p,
				 0x0ULL,
				 0xFFFFFFFFFFFFF000ULL);
	}

	PMAP_UNLOCK(p);

	if (c != 0) {
		PMAP_TRACE(PMAP_CODE(PMAP__DESTROY) | DBG_FUNC_END,
			   (int) p, 1, 0, 0, 0);
	        return;	/* still in use */
	}

	/*
	 *	Free the memory maps, then the
	 *	pmap structure.
	 */
	if (!cpu_64bit) {
		OSAddAtomic(-p->pm_obj->resident_page_count,  &inuse_ptepages_count);

		kmem_free(kernel_map, (vm_offset_t)p->dirbase, NBPTD);
		zfree(pdpt_zone, (void *)p->pm_hold);

		vm_object_deallocate(p->pm_obj);
	} else {
	        /* 64 bit */
	        int inuse_ptepages = 0;

		/* free 64 bit mode structs */
		inuse_ptepages++;
		kmem_free(kernel_map, (vm_offset_t)p->pm_hold, PAGE_SIZE);

		inuse_ptepages += p->pm_obj_pml4->resident_page_count;
		vm_object_deallocate(p->pm_obj_pml4);

		inuse_ptepages += p->pm_obj_pdpt->resident_page_count;
		vm_object_deallocate(p->pm_obj_pdpt);

		inuse_ptepages += p->pm_obj->resident_page_count;
		vm_object_deallocate(p->pm_obj);

		OSAddAtomic(-inuse_ptepages,  &inuse_ptepages_count);
	}
	zfree(pmap_zone, p);

	PMAP_TRACE(PMAP_CODE(PMAP__DESTROY) | DBG_FUNC_END,
		   0, 0, 0, 0, 0);

}

/*
 *	Add a reference to the specified pmap.
 */

void
pmap_reference(
	register pmap_t	p)
{

	if (p != PMAP_NULL) {
	        PMAP_LOCK(p);
		p->ref_count++;
		PMAP_UNLOCK(p);;
	}
}


/*
 *	Remove phys addr if mapped in specified map
 *
 */
void
pmap_remove_some_phys(
	__unused pmap_t		map,
	__unused ppnum_t         pn)
{

/* Implement to support working set code */

}

/*
 *	Routine:
 *		pmap_disconnect
 *
 *	Function:
 *		Disconnect all mappings for this page and return reference and change status
 *		in generic format.
 *
 */
unsigned int pmap_disconnect(
	ppnum_t pa)
{
	pmap_page_protect(pa, 0);			/* disconnect the page */
	return (pmap_get_refmod(pa));			/* return ref/chg status */
}

/*
 *	Set the physical protection on the
 *	specified range of this map as requested.
 *	Will not increase permissions.
 */
void
pmap_protect(
	pmap_t		map,
	vm_map_offset_t	sva,
	vm_map_offset_t	eva,
	vm_prot_t	prot)
{
	register pt_entry_t	*pde;
	register pt_entry_t	*spte, *epte;
	vm_map_offset_t		lva;
	vm_map_offset_t		orig_sva;
	boolean_t	set_NX;
	int		num_found = 0;

	pmap_intr_assert();

	if (map == PMAP_NULL)
		return;

	if (prot == VM_PROT_NONE) {
		pmap_remove(map, sva, eva);
		return;
	}

	PMAP_TRACE(PMAP_CODE(PMAP__PROTECT) | DBG_FUNC_START,
		   (int) map,
		   (int) (sva>>32), (int) sva,
		   (int) (eva>>32), (int) eva);

	if ( (prot & VM_PROT_EXECUTE) || !nx_enabled || !map->nx_enabled )
	        set_NX = FALSE;
	else
	        set_NX = TRUE;

	PMAP_LOCK(map);

	orig_sva = sva;
	while (sva < eva) {
	    lva = (sva + pde_mapped_size) & ~(pde_mapped_size-1);
	    if (lva > eva)
		lva = eva;
	    pde = pmap_pde(map, sva);
	    if (pde && (*pde & INTEL_PTE_VALID)) {
	        spte = (pt_entry_t *)pmap_pte(map, (sva & ~(pde_mapped_size-1)));
		spte = &spte[ptenum(sva)];
		epte = &spte[intel_btop(lva-sva)];

		while (spte < epte) {

		    if (*spte & INTEL_PTE_VALID) {
		      
		        if (prot & VM_PROT_WRITE)
			    pmap_update_pte(spte, *spte, (*spte | INTEL_PTE_WRITE));
			else
			    pmap_update_pte(spte, *spte, (*spte & ~INTEL_PTE_WRITE));

			if (set_NX == TRUE)
			    pmap_update_pte(spte, *spte, (*spte | INTEL_PTE_NX));
			else
			    pmap_update_pte(spte, *spte, (*spte & ~INTEL_PTE_NX));

			num_found++;
		    }
		    spte++;
		}
	    }
	    sva = lva;
	}
	if (num_found)
	    PMAP_UPDATE_TLBS(map, orig_sva, eva);

	PMAP_UNLOCK(map);

	PMAP_TRACE(PMAP_CODE(PMAP__PROTECT) | DBG_FUNC_END,
		   0, 0, 0, 0, 0);

}

/* Map a (possibly) autogenned block */
void
pmap_map_block(
	pmap_t		pmap, 
	addr64_t	va,
	ppnum_t 	pa,
	uint32_t	size,
	vm_prot_t	prot,
	int		attr,
	__unused unsigned int	flags)
{
    uint32_t page;

    for (page = 0; page < size; page++) {
	pmap_enter(pmap, va, pa, prot, attr, TRUE);
	va += PAGE_SIZE;
	pa++;
    }
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
	vm_map_offset_t	vaddr,
	boolean_t	wired)
{
	register pt_entry_t	*pte;

	/*
	 *	We must grab the pmap system lock because we may
	 *	change a pte_page queue.
	 */
	PMAP_LOCK(map);

	if ((pte = pmap_pte(map, vaddr)) == PT_ENTRY_NULL)
		panic("pmap_change_wiring: pte missing");

	if (wired && !iswired(*pte)) {
	    /*
	     *	wiring down mapping
	     */
	    OSAddAtomic(+1,  &map->stats.wired_count);
	    pmap_update_pte(pte, *pte, (*pte | INTEL_PTE_WIRED));
	}
	else if (!wired && iswired(*pte)) {
	    /*
	     *	unwiring mapping
	     */
	    assert(map->stats.wired_count >= 1);
	    OSAddAtomic(-1,  &map->stats.wired_count);
	    pmap_update_pte(pte, *pte, (*pte & ~INTEL_PTE_WIRED));
	}

	PMAP_UNLOCK(map);
}


/*
 *	Routine:	pmap_extract
 *	Function:
 *		Extract the physical page address associated
 *		with the given map/virtual_address pair.
 *     Change to shim for backwards compatibility but will not
 *     work for 64 bit systems.  Some old drivers that we cannot
 *     change need this.
 */

vm_offset_t
pmap_extract(
	register pmap_t	pmap,
	vm_map_offset_t	vaddr)
{
        ppnum_t ppn;
	vm_offset_t paddr;

	paddr = (vm_offset_t)0;
	ppn = pmap_find_phys(pmap, vaddr);

	if (ppn) {
	        paddr = ((vm_offset_t)i386_ptob(ppn)) | ((vm_offset_t)vaddr & INTEL_OFFMASK);
	}
	return (paddr);
}

void
pmap_expand_pml4(
		 pmap_t map,
		 vm_map_offset_t vaddr)
{
	register vm_page_t	m;
	register pmap_paddr_t	pa;
	uint64_t                i;
	spl_t			spl;
	ppnum_t                 pn;
	pml4_entry_t            *pml4p;

	if (kernel_pmap == map) panic("expand kernel pml4");

	spl = splhigh();
	pml4p = pmap64_pml4(map, vaddr);
	splx(spl);
	if (PML4_ENTRY_NULL == pml4p) panic("pmap_expand_pml4 no pml4p");

	/*
	 *	Allocate a VM page for the pml4 page
	 */
	while ((m = vm_page_grab()) == VM_PAGE_NULL)
		VM_PAGE_WAIT();

	/*
	 *	put the page into the pmap's obj list so it
	 *	can be found later.
	 */
	pn = m->phys_page;
	pa = i386_ptob(pn);
	i = pml4idx(map, vaddr);

	/*
	 *	Zero the page.
	 */
	pmap_zero_page(pn);

	vm_page_lockspin_queues();
	vm_page_wire(m);
	vm_page_unlock_queues();

	OSAddAtomic(1,  &inuse_ptepages_count);

	/* Take the oject lock (mutex) before the PMAP_LOCK (spinlock) */
	vm_object_lock(map->pm_obj_pml4);

	PMAP_LOCK(map);
	/*
	 *	See if someone else expanded us first
	 */
	if (pmap64_pdpt(map, vaddr) != PDPT_ENTRY_NULL) {
	        PMAP_UNLOCK(map);
		vm_object_unlock(map->pm_obj_pml4);

		VM_PAGE_FREE(m);

		OSAddAtomic(-1,  &inuse_ptepages_count);
		return;
	}

#if 0 /* DEBUG */
       if (0 != vm_page_lookup(map->pm_obj_pml4, (vm_object_offset_t)i)) {
	       panic("pmap_expand_pml4: obj not empty, pmap %p pm_obj %p vaddr 0x%llx i 0x%llx\n",
		     map, map->pm_obj_pml4, vaddr, i);
       }
#endif
	vm_page_insert(m, map->pm_obj_pml4, (vm_object_offset_t)i);
	vm_object_unlock(map->pm_obj_pml4);

	/*
	 *	Set the page directory entry for this page table.
	 */
	pml4p = pmap64_pml4(map, vaddr); /* refetch under lock */

	pmap_store_pte(pml4p, pa_to_pte(pa)
				| INTEL_PTE_VALID
				| INTEL_PTE_USER
				| INTEL_PTE_WRITE);

	PMAP_UNLOCK(map);

	return;

}

void
pmap_expand_pdpt(
		 pmap_t map,
		 vm_map_offset_t vaddr)
{
	register vm_page_t	m;
	register pmap_paddr_t	pa;
	uint64_t                i;
	spl_t			spl;
	ppnum_t                 pn;
	pdpt_entry_t            *pdptp;

	if (kernel_pmap == map) panic("expand kernel pdpt");

	spl = splhigh();
	while ((pdptp = pmap64_pdpt(map, vaddr)) == PDPT_ENTRY_NULL) {
	        splx(spl);
		pmap_expand_pml4(map, vaddr); /* need room for another pdpt entry */
		spl = splhigh();
	}
	splx(spl);

	/*
	 *	Allocate a VM page for the pdpt page
	 */
	while ((m = vm_page_grab()) == VM_PAGE_NULL)
		VM_PAGE_WAIT();

	/*
	 *	put the page into the pmap's obj list so it
	 *	can be found later.
	 */
	pn = m->phys_page;
	pa = i386_ptob(pn);
	i = pdptidx(map, vaddr);

	/*
	 *	Zero the page.
	 */
	pmap_zero_page(pn);

	vm_page_lockspin_queues();
	vm_page_wire(m);
	vm_page_unlock_queues();

	OSAddAtomic(1,  &inuse_ptepages_count);

	/* Take the oject lock (mutex) before the PMAP_LOCK (spinlock) */
	vm_object_lock(map->pm_obj_pdpt);

	PMAP_LOCK(map);
	/*
	 *	See if someone else expanded us first
	 */
	if (pmap64_pde(map, vaddr) != PD_ENTRY_NULL) {
		PMAP_UNLOCK(map);
		vm_object_unlock(map->pm_obj_pdpt);

		VM_PAGE_FREE(m);

		OSAddAtomic(-1,  &inuse_ptepages_count);
		return;
	}

#if 0 /* DEBUG */
       if (0 != vm_page_lookup(map->pm_obj_pdpt, (vm_object_offset_t)i)) {
	       panic("pmap_expand_pdpt: obj not empty, pmap %p pm_obj %p vaddr 0x%llx i 0x%llx\n",
		     map, map->pm_obj_pdpt, vaddr, i);
       }
#endif
	vm_page_insert(m, map->pm_obj_pdpt, (vm_object_offset_t)i);
	vm_object_unlock(map->pm_obj_pdpt);

	/*
	 *	Set the page directory entry for this page table.
	 */
	pdptp = pmap64_pdpt(map, vaddr); /* refetch under lock */

	pmap_store_pte(pdptp, pa_to_pte(pa)
				| INTEL_PTE_VALID
				| INTEL_PTE_USER
				| INTEL_PTE_WRITE);

	PMAP_UNLOCK(map);

	return;

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
	pmap_t		map,
	vm_map_offset_t	vaddr)
{
	pt_entry_t		*pdp;
	register vm_page_t	m;
	register pmap_paddr_t	pa;
	uint64_t                 i;
	spl_t			spl;
	ppnum_t                 pn;

	/*
	 * if not the kernel map (while we are still compat kernel mode)
	 * and we are 64 bit, propagate expand upwards
	 */

	if (cpu_64bit && (map != kernel_pmap)) {
	        spl = splhigh();
		while ((pdp = pmap64_pde(map, vaddr)) == PD_ENTRY_NULL) {
		        splx(spl);
			pmap_expand_pdpt(map, vaddr); /* need room for another pde entry */
			spl = splhigh();
		}
		splx(spl);
	}

	/*
	 *	Allocate a VM page for the pde entries.
	 */
	while ((m = vm_page_grab()) == VM_PAGE_NULL)
		VM_PAGE_WAIT();

	/*
	 *	put the page into the pmap's obj list so it
	 *	can be found later.
	 */
	pn = m->phys_page;
	pa = i386_ptob(pn);
	i = pdeidx(map, vaddr);

	/*
	 *	Zero the page.
	 */
	pmap_zero_page(pn);

	vm_page_lockspin_queues();
	vm_page_wire(m);
	vm_page_unlock_queues();

	OSAddAtomic(1,  &inuse_ptepages_count);

	/* Take the oject lock (mutex) before the PMAP_LOCK (spinlock) */
	vm_object_lock(map->pm_obj);

	PMAP_LOCK(map);
	/*
	 *	See if someone else expanded us first
	 */

	if (pmap_pte(map, vaddr) != PT_ENTRY_NULL) {
		PMAP_UNLOCK(map);
		vm_object_unlock(map->pm_obj);

		VM_PAGE_FREE(m);

		OSAddAtomic(-1,  &inuse_ptepages_count);
		return;
	}

#if 0 /* DEBUG */
       if (0 != vm_page_lookup(map->pm_obj, (vm_object_offset_t)i)) {
	       panic("pmap_expand: obj not empty, pmap 0x%x pm_obj 0x%x vaddr 0x%llx i 0x%llx\n",
		     map, map->pm_obj, vaddr, i);
       }
#endif
	vm_page_insert(m, map->pm_obj, (vm_object_offset_t)i);
	vm_object_unlock(map->pm_obj);

	/*
	 * refetch while locked 
	 */

	pdp = pmap_pde(map, vaddr);

	/*
	 *	Set the page directory entry for this page table.
	 */
	pmap_store_pte(pdp, pa_to_pte(pa)
				| INTEL_PTE_VALID
				| INTEL_PTE_USER
				| INTEL_PTE_WRITE);

	PMAP_UNLOCK(map);

	return;
}


/*
 * pmap_sync_page_data_phys(ppnum_t pa)
 * 
 * Invalidates all of the instruction cache on a physical page and
 * pushes any dirty data from the data cache for the same physical page
 * Not required in i386.
 */
void
pmap_sync_page_data_phys(__unused ppnum_t pa)
{
	return;
}

/*
 * pmap_sync_page_attributes_phys(ppnum_t pa)
 * 
 * Write back and invalidate all cachelines on a physical page.
 */
void
pmap_sync_page_attributes_phys(ppnum_t pa)
{
	cache_flush_page_phys(pa);
}



#ifdef CURRENTLY_UNUSED_AND_UNTESTED

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
	int			wired;

	if (p == PMAP_NULL)
		return;

	if (p == kernel_pmap)
		return;

	/*
	 *	Garbage collect map.
	 */
	PMAP_LOCK(p);

	for (pdp = (pt_entry_t *)p->dirbase;
	     pdp < (pt_entry_t *)&p->dirbase[(UMAXPTDI+1)];
	     pdp++)
	{
	   if (*pdp & INTEL_PTE_VALID) {
	      if(*pdp & INTEL_PTE_REF) {
		pmap_store_pte(pdp, *pdp & ~INTEL_PTE_REF);
		collect_ref++;
	      } else {
		collect_unref++;
		ptp = pmap_pte(p, pdetova(pdp - (pt_entry_t *)p->dirbase));
		eptp = ptp + NPTEPG;

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
				pdetova(pdp - (pt_entry_t *)p->dirbase),
				ptp,
				eptp);

		    /*
		     * Invalidate the page directory pointer.
		     */
		    pmap_store_pte(pdp, 0x0);
		 
		    PMAP_UNLOCK(p);

		    /*
		     * And free the pte page itself.
		     */
		    {
			register vm_page_t m;

			vm_object_lock(p->pm_obj);

			m = vm_page_lookup(p->pm_obj,(vm_object_offset_t)(pdp - (pt_entry_t *)&p->dirbase[0]));
			if (m == VM_PAGE_NULL)
			    panic("pmap_collect: pte page not in object");

			VM_PAGE_FREE(m);

			OSAddAtomic(-1,  &inuse_ptepages_count);

			vm_object_unlock(p->pm_obj);
		    }

		    PMAP_LOCK(p);
		}
	      }
	   }
	}

	PMAP_UPDATE_TLBS(p, 0x0, 0xFFFFFFFFFFFFF000ULL);
	PMAP_UNLOCK(p);
	return;

}
#endif


void
pmap_copy_page(ppnum_t src, ppnum_t dst)
{
  bcopy_phys((addr64_t)i386_ptob(src),
	     (addr64_t)i386_ptob(dst),
	     PAGE_SIZE);
}


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
	__unused pmap_t		pmap,
	__unused vm_map_offset_t	start_addr,
	__unused vm_map_offset_t	end_addr,
	__unused boolean_t	pageable)
{
#ifdef	lint
	pmap++; start_addr++; end_addr++; pageable++;
#endif	/* lint */
}

/*
 *	Clear specified attribute bits.
 */
void
phys_attribute_clear(
	ppnum_t		pn,
	int		bits)
{
	pv_rooted_entry_t		pv_h;
	register pv_hashed_entry_t	pv_e;
	register pt_entry_t	*pte;
	int			pai;
	register pmap_t		pmap;

	pmap_intr_assert();
	assert(pn != vm_page_fictitious_addr);
	if (pn == vm_page_guard_addr)
		return;

	pai = ppn_to_pai(pn);

	if (!managed_page(pai)) {
	    /*
	     *	Not a managed page.
	     */
	    return;
	}


	PMAP_TRACE(PMAP_CODE(PMAP__ATTRIBUTE_CLEAR) | DBG_FUNC_START,
		   (int) pn, bits, 0, 0, 0);

	pv_h = pai_to_pvh(pai);

	LOCK_PVH(pai);

	/*
	 * Walk down PV list, clearing all modify or reference bits.
	 * We do not have to lock the pv_list because we have
	 * the entire pmap system locked.
	 */
	if (pv_h->pmap != PMAP_NULL) {
	    /*
	     * There are some mappings.
	     */

	  pv_e = (pv_hashed_entry_t)pv_h;

	  do {
		pmap = pv_e->pmap;

		{
		    vm_map_offset_t va;

		    va = pv_e->va;

		    /*
		     * Clear modify and/or reference bits.
		     */

		    pte = pmap_pte(pmap, va);
		    pmap_update_pte(pte, *pte, (*pte & ~bits));
		    /* Ensure all processors using this translation
		     * invalidate this TLB entry. The invalidation *must* follow
		     * the PTE update, to ensure that the TLB shadow of the
		     * 'D' bit (in particular) is synchronized with the
		     * updated PTE.
		     */
		    PMAP_UPDATE_TLBS(pmap, va, va + PAGE_SIZE);
		}

		pv_e = (pv_hashed_entry_t)queue_next(&pv_e->qlink);

	  } while (pv_e != (pv_hashed_entry_t)pv_h);
	}
	pmap_phys_attributes[pai] &= ~bits;

	UNLOCK_PVH(pai);

	PMAP_TRACE(PMAP_CODE(PMAP__ATTRIBUTE_CLEAR) | DBG_FUNC_END,
		   0, 0, 0, 0, 0);

}

/*
 *	Check specified attribute bits.
 */
int
phys_attribute_test(
	ppnum_t		pn,
	int		bits)
{
	pv_rooted_entry_t		pv_h;
	register pv_hashed_entry_t	pv_e;
	register pt_entry_t	*pte;
	int			pai;
	register pmap_t		pmap;
	int			attributes = 0;

	pmap_intr_assert();
	assert(pn != vm_page_fictitious_addr);
	if (pn == vm_page_guard_addr)
		return 0;

	pai = ppn_to_pai(pn);

	if (!managed_page(pai)) {
	    /*
	     *	Not a managed page.
	     */
	    return (0);
	}

	/*
	 * super fast check...  if bits already collected
	 * no need to take any locks...
	 * if not set, we need to recheck after taking
	 * the lock in case they got pulled in while
	 * we were waiting for the lock
	 */
	if ( (pmap_phys_attributes[pai] & bits) == bits)
	    return (bits);

	pv_h = pai_to_pvh(pai);

	LOCK_PVH(pai);

	attributes = pmap_phys_attributes[pai] & bits;


	/*
	 * Walk down PV list, checking the mappings until we
	 * reach the end or we've found the attributes we've asked for
	 * We do not have to lock the pv_list because we have
	 * the entire pmap system locked.
	 */
	if (pv_h->pmap != PMAP_NULL) {
	    /*
	     * There are some mappings.
	     */
	  pv_e = (pv_hashed_entry_t)pv_h;
	  if (attributes != bits) do {

	        pmap = pv_e->pmap;

		{
		    vm_map_offset_t va;

		    va = pv_e->va;
		    /*
		     * first make sure any processor actively
		     * using this pmap, flushes its TLB state
		     */
		    PMAP_UPDATE_TLBS(pmap, va, va + PAGE_SIZE);

		    /*
		     * pick up modify and/or reference bits from this mapping
		     */
		    pte = pmap_pte(pmap, va);
		    attributes |= (int)(*pte & bits);

		}

		pv_e = (pv_hashed_entry_t)queue_next(&pv_e->qlink);

	    } while ((attributes != bits) && (pv_e != (pv_hashed_entry_t)pv_h));
	}

	UNLOCK_PVH(pai);
	return (attributes);
}

/*
 *	Set specified attribute bits.
 */
void
phys_attribute_set(
	ppnum_t		pn,
	int		bits)
{
	int		pai;

	pmap_intr_assert();
	assert(pn != vm_page_fictitious_addr);
	if (pn == vm_page_guard_addr)
		return;

	pai = ppn_to_pai(pn);

	if (!managed_page(pai)) {
	    /*
	     *	Not a managed page.
	     */
	    return;
	}

	LOCK_PVH(pai);

	pmap_phys_attributes[pai] |= bits;

	UNLOCK_PVH(pai);
}

/*
 *	Set the modify bit on the specified physical page.
 */

void pmap_set_modify(
		     ppnum_t pn)
{
	phys_attribute_set(pn, PHYS_MODIFIED);
}

/*
 *	Clear the modify bits on the specified physical page.
 */

void
pmap_clear_modify(
		  ppnum_t pn)
{
	phys_attribute_clear(pn, PHYS_MODIFIED);
}

/*
 *	pmap_is_modified:
 *
 *	Return whether or not the specified physical page is modified
 *	by any physical maps.
 */

boolean_t
pmap_is_modified(
		 ppnum_t pn)
{
        if (phys_attribute_test(pn, PHYS_MODIFIED))
	        return TRUE;

	return FALSE;
}

/*
 *	pmap_clear_reference:
 *
 *	Clear the reference bit on the specified physical page.
 */

void
pmap_clear_reference(
		     ppnum_t pn)
{
	phys_attribute_clear(pn, PHYS_REFERENCED);
}

void
pmap_set_reference(ppnum_t pn)
{
	phys_attribute_set(pn, PHYS_REFERENCED);
}

/*
 *	pmap_is_referenced:
 *
 *	Return whether or not the specified physical page is referenced
 *	by any physical maps.
 */

boolean_t
pmap_is_referenced(
		   ppnum_t pn)
{
        if (phys_attribute_test(pn, PHYS_REFERENCED))
	        return TRUE;

	return FALSE;
}

/*
 * pmap_get_refmod(phys)
 *  returns the referenced and modified bits of the specified
 *  physical page.
 */
unsigned int
pmap_get_refmod(ppnum_t pa)
{
        int	refmod;
	unsigned int retval = 0;

	refmod = phys_attribute_test(pa, PHYS_MODIFIED | PHYS_REFERENCED);

	if (refmod & PHYS_MODIFIED)
	        retval |= VM_MEM_MODIFIED;
	if (refmod & PHYS_REFERENCED)
	        retval |= VM_MEM_REFERENCED;

	return (retval);
}

/*
 * pmap_clear_refmod(phys, mask)
 *  clears the referenced and modified bits as specified by the mask
 *  of the specified physical page.
 */
void
pmap_clear_refmod(ppnum_t pa, unsigned int mask)
{
	unsigned int  x86Mask;

	x86Mask = (   ((mask &   VM_MEM_MODIFIED)?   PHYS_MODIFIED : 0)
	            | ((mask & VM_MEM_REFERENCED)? PHYS_REFERENCED : 0));
	phys_attribute_clear(pa, x86Mask);
}

void 
invalidate_icache(__unused vm_offset_t	addr,
		  __unused unsigned	cnt,
		  __unused int		phys)
{
	return;
}
void 
flush_dcache(__unused vm_offset_t	addr,
	     __unused unsigned		count,
	     __unused int		phys)
{
	return;
}

#if CONFIG_DTRACE
/*
 * Constrain DTrace copyin/copyout actions
 */
extern kern_return_t dtrace_copyio_preflight(addr64_t);
extern kern_return_t dtrace_copyio_postflight(addr64_t);

kern_return_t dtrace_copyio_preflight(__unused addr64_t va)
{
	thread_t thread = current_thread();

	if (current_map() == kernel_map)
		return KERN_FAILURE;
	else if (thread->machine.specFlags & CopyIOActive)
		return KERN_FAILURE;
	else
		return KERN_SUCCESS;
}
 
kern_return_t dtrace_copyio_postflight(__unused addr64_t va)
{
	return KERN_SUCCESS;
}
#endif /* CONFIG_DTRACE */

#if	MACH_KDB

/* show phys page mappings and attributes */

extern void	db_show_page(pmap_paddr_t pa);

#if 0
void
db_show_page(pmap_paddr_t pa)
{
	pv_entry_t	pv_h;
	int		pai;
	char 		attr;
	
	pai = pa_index(pa);
	pv_h = pai_to_pvh(pai);

	attr = pmap_phys_attributes[pai];
	printf("phys page %llx ", pa);
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
			printf("%llx in pmap %p\n", pv_h->va, pv_h->pmap);
}
#endif

#endif /* MACH_KDB */

#if	MACH_KDB
#if 0
void db_kvtophys(vm_offset_t);
void db_show_vaddrs(pt_entry_t  *);

/*
 *	print out the results of kvtophys(arg)
 */
void
db_kvtophys(
	vm_offset_t	vaddr)
{
	db_printf("0x%qx", kvtophys(vaddr));
}

/*
 *	Walk the pages tables.
 */
void
db_show_vaddrs(
	pt_entry_t	*dirbase)
{
	pt_entry_t	*ptep, *pdep, tmp;
	unsigned int	x, y, pdecnt, ptecnt;

	if (dirbase == 0) {
		dirbase = kernel_pmap->dirbase;
	}
	if (dirbase == 0) {
		db_printf("need a dirbase...\n");
		return;
	}
	dirbase = (pt_entry_t *) (int) ((unsigned long) dirbase & ~INTEL_OFFMASK);

	db_printf("dirbase: 0x%x\n", dirbase);

	pdecnt = ptecnt = 0;
	pdep = &dirbase[0];
	for (y = 0; y < NPDEPG; y++, pdep++) {
		if (((tmp = *pdep) & INTEL_PTE_VALID) == 0) {
			continue;
		}
		pdecnt++;
		ptep = (pt_entry_t *) ((unsigned long)(*pdep) & ~INTEL_OFFMASK);
		db_printf("dir[%4d]: 0x%x\n", y, *pdep);
		for (x = 0; x < NPTEPG; x++, ptep++) {
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
#endif
#endif	/* MACH_KDB */

#include <mach_vm_debug.h>
#if	MACH_VM_DEBUG
#include <vm/vm_debug.h>

int
pmap_list_resident_pages(
	__unused pmap_t		pmap,
	__unused vm_offset_t	*listp,
	__unused int		space)
{
	return 0;
}
#endif	/* MACH_VM_DEBUG */



/* temporary workaround */
boolean_t
coredumpok(__unused vm_map_t map, __unused vm_offset_t va)
{
#if 0
	pt_entry_t     *ptep;

	ptep = pmap_pte(map->pmap, va);
	if (0 == ptep)
		return FALSE;
	return ((*ptep & (INTEL_PTE_NCACHE | INTEL_PTE_WIRED)) != (INTEL_PTE_NCACHE | INTEL_PTE_WIRED));
#else
	return TRUE;
#endif
}


boolean_t
phys_page_exists(
		 ppnum_t pn)
{
	assert(pn != vm_page_fictitious_addr);

	if (!pmap_initialized)
		return (TRUE);

	if (pn == vm_page_guard_addr)
		return FALSE;

	if (!managed_page(ppn_to_pai(pn)))
		return (FALSE);

	return TRUE;
}

void
pmap_commpage32_init(vm_offset_t kernel_commpage, vm_offset_t user_commpage, int cnt)
{
	int i;
	pt_entry_t *opte, *npte;
	pt_entry_t pte;
	spl_t s;

	for (i = 0; i < cnt; i++) {
	        s = splhigh();
		opte = pmap_pte(kernel_pmap, (vm_map_offset_t)kernel_commpage);
		if (0 == opte)
			panic("kernel_commpage");
		pte = *opte | INTEL_PTE_USER|INTEL_PTE_GLOBAL;
		pte &= ~INTEL_PTE_WRITE; // ensure read only
		npte = pmap_pte(kernel_pmap, (vm_map_offset_t)user_commpage);
		if (0 == npte)
			panic("user_commpage");
		pmap_store_pte(npte, pte);
		splx(s);
		kernel_commpage += INTEL_PGBYTES;
		user_commpage += INTEL_PGBYTES;
	}
}


#define PMAP_COMMPAGE64_CNT  (_COMM_PAGE64_AREA_USED/PAGE_SIZE)
pt_entry_t pmap_commpage64_ptes[PMAP_COMMPAGE64_CNT];

void
pmap_commpage64_init(vm_offset_t kernel_commpage, __unused vm_map_offset_t user_commpage, int cnt)
{
    int i;
    pt_entry_t *kptep;

    PMAP_LOCK(kernel_pmap);

    for (i = 0; i < cnt; i++) {
        kptep = pmap_pte(kernel_pmap, (uint64_t)kernel_commpage + (i*PAGE_SIZE));
	if ((0 == kptep) || (0 == (*kptep & INTEL_PTE_VALID)))
	    panic("pmap_commpage64_init pte");
	pmap_commpage64_ptes[i] = ((*kptep & ~INTEL_PTE_WRITE) | INTEL_PTE_USER);
    }
    PMAP_UNLOCK(kernel_pmap);
}


static cpu_pmap_t		cpu_pmap_master;

struct cpu_pmap *
pmap_cpu_alloc(boolean_t is_boot_cpu)
{
	int			ret;
	int			i;
	cpu_pmap_t		*cp;
	vm_offset_t		address;
	vm_map_address_t	mapaddr;
	vm_map_entry_t		entry;
	pt_entry_t		*pte;
	
	if (is_boot_cpu) {
		cp = &cpu_pmap_master;
	} else {
		/*
		 * The per-cpu pmap data structure itself.
		 */
		ret = kmem_alloc(kernel_map,
				 (vm_offset_t *) &cp, sizeof(cpu_pmap_t));
		if (ret != KERN_SUCCESS) {
			printf("pmap_cpu_alloc() failed ret=%d\n", ret);
			return NULL;
		}
		bzero((void *)cp, sizeof(cpu_pmap_t));

		/*
		 * The temporary windows used for copy/zero - see loose_ends.c
		 */
		ret = vm_map_find_space(kernel_map,
		    &mapaddr, PMAP_NWINDOWS*PAGE_SIZE, (vm_map_offset_t)0, 0, &entry);
		if (ret != KERN_SUCCESS) {
			printf("pmap_cpu_alloc() "
				"vm_map_find_space ret=%d\n", ret);
			pmap_cpu_free(cp);
			return NULL;
		}
		address = (vm_offset_t)mapaddr;

		for (i = 0; i < PMAP_NWINDOWS; i++, address += PAGE_SIZE) {
		  spl_t s;
		        s = splhigh();
			while ((pte = pmap_pte(kernel_pmap, (vm_map_offset_t)address)) == 0)
				pmap_expand(kernel_pmap, (vm_map_offset_t)address);
			* (int *) pte = 0; 
			cp->mapwindow[i].prv_CADDR = (caddr_t) address;
			cp->mapwindow[i].prv_CMAP = pte;
			splx(s);
		}
		vm_map_unlock(kernel_map);
	}

	cp->pdpt_window_index = PMAP_PDPT_FIRST_WINDOW;
	cp->pde_window_index = PMAP_PDE_FIRST_WINDOW;
	cp->pte_window_index = PMAP_PTE_FIRST_WINDOW;

	return cp;
}

void
pmap_cpu_free(struct cpu_pmap *cp)
{
	if (cp != NULL && cp != &cpu_pmap_master) {
		kfree((void *) cp, sizeof(cpu_pmap_t));
	}
}


mapwindow_t *
pmap_get_mapwindow(pt_entry_t pentry)
{
    mapwindow_t *mp;
    int i;

    assert(ml_get_interrupts_enabled() == 0 || get_preemption_level() != 0);

    /*
     * Note: 0th map reserved for pmap_pte()
     */
    for (i = PMAP_NWINDOWS_FIRSTFREE; i < PMAP_NWINDOWS; i++) {
            mp = &current_cpu_datap()->cpu_pmap->mapwindow[i];

	    if (*mp->prv_CMAP == 0) {
	            pmap_store_pte(mp->prv_CMAP, pentry);

		    invlpg((uintptr_t)mp->prv_CADDR);

		    return (mp);
	    }
    }
    panic("pmap_get_mapwindow: no windows available");

    return NULL;
}


void
pmap_put_mapwindow(mapwindow_t *mp)
{
    pmap_store_pte(mp->prv_CMAP, 0);
}

void
pmap_switch(pmap_t tpmap)
{
        spl_t	s;

	s = splhigh();		/* Make sure interruptions are disabled */

	set_dirbase(tpmap, current_thread());

	splx(s);
}


/*
 * disable no-execute capability on
 * the specified pmap
 */
void pmap_disable_NX(pmap_t pmap) {
  
        pmap->nx_enabled = 0;
}

void
pt_fake_zone_info(int *count, vm_size_t *cur_size, vm_size_t *max_size, vm_size_t *elem_size,
		  vm_size_t *alloc_size, int *collectable, int *exhaustable)
{
        *count      = inuse_ptepages_count;
	*cur_size   = PAGE_SIZE * inuse_ptepages_count;
	*max_size   = PAGE_SIZE * (inuse_ptepages_count + vm_page_inactive_count + vm_page_active_count + vm_page_free_count);
	*elem_size  = PAGE_SIZE;
	*alloc_size = PAGE_SIZE;

	*collectable = 1;
	*exhaustable = 0;
}

vm_offset_t pmap_cpu_high_map_vaddr(int cpu, enum high_cpu_types e)
{
  enum high_fixed_addresses a;
  a = e + HIGH_CPU_END * cpu;
  return pmap_index_to_virt(HIGH_FIXED_CPUS_BEGIN + a);
}

vm_offset_t pmap_high_map_vaddr(enum high_cpu_types e)
{
  return pmap_cpu_high_map_vaddr(cpu_number(), e);
}

vm_offset_t pmap_high_map(pt_entry_t pte, enum high_cpu_types e)
{
  enum high_fixed_addresses a;
  vm_offset_t vaddr;

  a = e + HIGH_CPU_END * cpu_number();
  vaddr = (vm_offset_t)pmap_index_to_virt(HIGH_FIXED_CPUS_BEGIN + a);
  pmap_store_pte(pte_unique_base + a, pte);

  /* TLB flush for this page for this  cpu */
  invlpg((uintptr_t)vaddr);

  return  vaddr;
}

static inline void
pmap_cpuset_NMIPI(cpu_set cpu_mask) {
	unsigned int cpu, cpu_bit;
	uint64_t deadline;

	for (cpu = 0, cpu_bit = 1; cpu < real_ncpus; cpu++, cpu_bit <<= 1) {
		if (cpu_mask & cpu_bit)
			cpu_NMI_interrupt(cpu);
	}
	deadline = mach_absolute_time() + (LockTimeOut);
	while (mach_absolute_time() < deadline)
		cpu_pause();
}

/*
 * Called with pmap locked, we:
 *  - scan through per-cpu data to see which other cpus need to flush
 *  - send an IPI to each non-idle cpu to be flushed
 *  - wait for all to signal back that they are inactive or we see that
 *    they are in an interrupt handler or at a safe point
 *  - flush the local tlb is active for this pmap
 *  - return ... the caller will unlock the pmap
 */
void
pmap_flush_tlbs(pmap_t	pmap)
{
	unsigned int	cpu;
	unsigned int	cpu_bit;
	cpu_set		cpus_to_signal;
	unsigned int	my_cpu = cpu_number();
	pmap_paddr_t	pmap_cr3 = pmap->pm_cr3;
	boolean_t	flush_self = FALSE;
	uint64_t	deadline;

	assert((processor_avail_count < 2) ||
	       (ml_get_interrupts_enabled() && get_preemption_level() != 0));

	/*
	 * Scan other cpus for matching active or task CR3.
	 * For idle cpus (with no active map) we mark them invalid but
	 * don't signal -- they'll check as they go busy.
	 * Note: for the kernel pmap we look for 64-bit shared address maps.
	 */
	cpus_to_signal = 0;
	for (cpu = 0, cpu_bit = 1; cpu < real_ncpus; cpu++, cpu_bit <<= 1) {
		if (!cpu_datap(cpu)->cpu_running)
			continue;
		if ((cpu_datap(cpu)->cpu_task_cr3 == pmap_cr3) ||
		    (CPU_GET_ACTIVE_CR3(cpu)      == pmap_cr3) ||
		    (pmap->pm_shared) ||
		    ((pmap == kernel_pmap) &&
		     (!CPU_CR3_IS_ACTIVE(cpu) ||
		      cpu_datap(cpu)->cpu_task_map == TASK_MAP_64BIT_SHARED))) {
			if (cpu == my_cpu) {
				flush_self = TRUE;
				continue;
			}
			cpu_datap(cpu)->cpu_tlb_invalid = TRUE;
			__asm__ volatile("mfence");

			if (CPU_CR3_IS_ACTIVE(cpu)) {
				cpus_to_signal |= cpu_bit;
				i386_signal_cpu(cpu, MP_TLB_FLUSH, ASYNC);
			}
		}
	}

	PMAP_TRACE(PMAP_CODE(PMAP__FLUSH_TLBS) | DBG_FUNC_START,
		   (int) pmap, cpus_to_signal, flush_self, 0, 0);

	if (cpus_to_signal) {
		cpu_set	cpus_to_respond = cpus_to_signal;

		deadline = mach_absolute_time() + LockTimeOut;
		/*
		 * Wait for those other cpus to acknowledge
		 */
		while (cpus_to_respond != 0) {
			if (mach_absolute_time() > deadline) {
				if (mp_recent_debugger_activity())
					continue;
				if (!panic_active()) {
					pmap_tlb_flush_timeout = TRUE;
					pmap_cpuset_NMIPI(cpus_to_respond);
				}
				panic("pmap_flush_tlbs() timeout: "
				    "cpu(s) failing to respond to interrupts, pmap=%p cpus_to_respond=0x%lx",
				    pmap, cpus_to_respond);
			}

			for (cpu = 0, cpu_bit = 1; cpu < real_ncpus; cpu++, cpu_bit <<= 1) {
				if ((cpus_to_respond & cpu_bit) != 0) {
					if (!cpu_datap(cpu)->cpu_running ||
					    cpu_datap(cpu)->cpu_tlb_invalid == FALSE ||
					    !CPU_CR3_IS_ACTIVE(cpu)) {
						cpus_to_respond &= ~cpu_bit;
					}
					cpu_pause();
				}
				if (cpus_to_respond == 0)
					break;
			}
		}
	}
	/*
	 * Flush local tlb if required.
	 * We need this flush even if the pmap being changed
	 * is the user map... in case we do a copyin/out
	 * before returning to user mode.
	 */
	if (flush_self)
		flush_tlb();

	if ((pmap == kernel_pmap) && (flush_self != TRUE)) {
		panic("pmap_flush_tlbs: pmap == kernel_pmap && flush_self != TRUE; kernel CR3: 0x%llX, CPU active CR3: 0x%llX, CPU Task Map: %d", kernel_pmap->pm_cr3, current_cpu_datap()->cpu_active_cr3, current_cpu_datap()->cpu_task_map);
	}

	PMAP_TRACE(PMAP_CODE(PMAP__FLUSH_TLBS) | DBG_FUNC_END,
		   (int) pmap, cpus_to_signal, flush_self, 0, 0);
}

void
process_pmap_updates(void)
{
	assert(ml_get_interrupts_enabled() == 0 || get_preemption_level() != 0);

	flush_tlb();

	current_cpu_datap()->cpu_tlb_invalid = FALSE;
	__asm__ volatile("mfence");
}

void
pmap_update_interrupt(void)
{
        PMAP_TRACE(PMAP_CODE(PMAP__UPDATE_INTERRUPT) | DBG_FUNC_START,
		   0, 0, 0, 0, 0);

	process_pmap_updates();

        PMAP_TRACE(PMAP_CODE(PMAP__UPDATE_INTERRUPT) | DBG_FUNC_END,
		   0, 0, 0, 0, 0);
}


unsigned int pmap_cache_attributes(ppnum_t pn) {

	if (!managed_page(ppn_to_pai(pn)))
	        return (VM_WIMG_IO);

	return (VM_WIMG_COPYBACK);
}

#ifdef PMAP_DEBUG
void
pmap_dump(pmap_t p)
{
  int i;

  kprintf("pmap 0x%x\n",p);

  kprintf("  pm_cr3 0x%llx\n",p->pm_cr3);
  kprintf("  pm_pml4 0x%x\n",p->pm_pml4);
  kprintf("  pm_pdpt 0x%x\n",p->pm_pdpt);

  kprintf("    pml4[0] 0x%llx\n",*p->pm_pml4);
  for (i=0;i<8;i++)
    kprintf("    pdpt[%d] 0x%llx\n",i, p->pm_pdpt[i]);
}

void pmap_dump_wrap(void)
{
  pmap_dump(current_cpu_datap()->cpu_active_thread->task->map->pmap);
}

void
dump_4GB_pdpt(pmap_t p)
{
	int		spl;
	pdpt_entry_t	*user_pdptp;
	pdpt_entry_t	*kern_pdptp;
	pdpt_entry_t	*pml4p;

	spl = splhigh();
	while ((user_pdptp = pmap64_pdpt(p, 0x0)) == PDPT_ENTRY_NULL) {
		splx(spl);
		pmap_expand_pml4(p, 0x0);
		spl = splhigh();
	}
	kern_pdptp = kernel_pmap->pm_pdpt;
	if (kern_pdptp == NULL)
		panic("kern_pdptp == NULL");
	kprintf("dump_4GB_pdpt(%p)\n"
		"kern_pdptp=%p (phys=0x%016llx)\n"
		"\t 0x%08x: 0x%016llx\n"
		"\t 0x%08x: 0x%016llx\n"
		"\t 0x%08x: 0x%016llx\n"
		"\t 0x%08x: 0x%016llx\n"
		"\t 0x%08x: 0x%016llx\n"
		"user_pdptp=%p (phys=0x%016llx)\n"
		"\t 0x%08x: 0x%016llx\n"
		"\t 0x%08x: 0x%016llx\n"
		"\t 0x%08x: 0x%016llx\n"
		"\t 0x%08x: 0x%016llx\n"
		"\t 0x%08x: 0x%016llx\n",
		p, kern_pdptp, kvtophys(kern_pdptp),
		kern_pdptp+0, *(kern_pdptp+0),
		kern_pdptp+1, *(kern_pdptp+1),
		kern_pdptp+2, *(kern_pdptp+2),
		kern_pdptp+3, *(kern_pdptp+3),
		kern_pdptp+4, *(kern_pdptp+4),
		user_pdptp, kvtophys(user_pdptp),
		user_pdptp+0, *(user_pdptp+0),
		user_pdptp+1, *(user_pdptp+1),
		user_pdptp+2, *(user_pdptp+2),
		user_pdptp+3, *(user_pdptp+3),
		user_pdptp+4, *(user_pdptp+4));
	kprintf("user pm_cr3=0x%016llx pm_hold=0x%08x pm_pml4=0x%08x\n",
		p->pm_cr3, p->pm_hold, p->pm_pml4);
	pml4p = (pdpt_entry_t *)p->pm_hold;
	if (pml4p == NULL)
		panic("user pml4p == NULL");
	kprintf("\t 0x%08x: 0x%016llx\n"
		"\t 0x%08x: 0x%016llx\n",
		pml4p+0, *(pml4p),
		pml4p+KERNEL_UBER_PML4_INDEX, *(pml4p+KERNEL_UBER_PML4_INDEX));
	kprintf("kern pm_cr3=0x%016llx pm_hold=0x%08x pm_pml4=0x%08x\n",
		kernel_pmap->pm_cr3, kernel_pmap->pm_hold, kernel_pmap->pm_pml4);
	pml4p = (pdpt_entry_t *)kernel_pmap->pm_hold;
	if (pml4p == NULL)
		panic("kern pml4p == NULL");
	kprintf("\t 0x%08x: 0x%016llx\n"
		"\t 0x%08x: 0x%016llx\n",
		pml4p+0, *(pml4p),
		pml4p+511, *(pml4p+511));
	splx(spl);
}

void dump_4GB_pdpt_thread(thread_t tp)
{
	dump_4GB_pdpt(tp->map->pmap);
}


#endif


/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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
#include <norma_vm.h>
#include <mach_kdb.h>
#include <mach_ldebug.h>

#include <mach/machine/vm_types.h>

#include <mach/boolean.h>
#include <kern/thread.h>
#include <kern/zalloc.h>

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
#include <i386/mp_slave_boot.h>
#include <i386/seg.h>
#include <i386/cpu_capabilities.h>

#if	MACH_KDB
#include <ddb/db_command.h>
#include <ddb/db_output.h>
#include <ddb/db_sym.h>
#include <ddb/db_print.h>
#endif	/* MACH_KDB */

#include <kern/xpr.h>

#include <vm/vm_protos.h>

#include <i386/mp.h>
#include <i386/mp_desc.h>

#include <sys/kdebug.h>

#ifdef IWANTTODEBUG
#undef	DEBUG
#define DEBUG 1
#define POSTCODE_DELAY 1
#include <i386/postcode.h>
#endif /* IWANTTODEBUG */

/*
 * Forward declarations for internal functions.
 */
void		pmap_expand_pml4(
			pmap_t		map,
			vm_map_offset_t	v);

void		pmap_expand_pdpt(
			pmap_t		map,
			vm_map_offset_t	v);

void		pmap_expand(
			pmap_t		map,
			vm_map_offset_t	v);

static void	pmap_remove_range(
			pmap_t		pmap,
			vm_map_offset_t	va,
			pt_entry_t	*spte,
			pt_entry_t	*epte);

void		phys_attribute_clear(
			ppnum_t	phys,
			int		bits);

boolean_t	phys_attribute_test(
			ppnum_t	phys,
			int		bits);

void		phys_attribute_set(
			ppnum_t	phys,
			int		bits);

void		pmap_set_reference(
			ppnum_t pn);

void		pmap_movepage(
			unsigned long	from,
			unsigned long	to,
			vm_size_t	size);

boolean_t	phys_page_exists(
			ppnum_t pn);

#ifdef PMAP_DEBUG
void dump_pmap(pmap_t);
void dump_4GB_pdpt(pmap_t p);
void dump_4GB_pdpt_thread(thread_t tp);
#endif

#define	iswired(pte)	((pte) & INTEL_PTE_WIRED)

int nx_enabled = 1;			/* enable no-execute protection */

int cpu_64bit  = 0;


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
	vm_map_offset_t	va;		/* virtual address for mapping */
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
int pv_free_count = 0;
#define PV_LOW_WATER_MARK 5000
#define PV_ALLOC_CHUNK 2000
thread_call_t  mapping_adjust_call;
static thread_call_data_t  mapping_adjust_call_data;
int mappingrecurse = 0;

#define	PV_ALLOC(pv_e) { \
	simple_lock(&pv_free_list_lock); \
	if ((pv_e = pv_free_list) != 0) { \
	    pv_free_list = pv_e->next; \
            pv_free_count--; \
            if (pv_free_count < PV_LOW_WATER_MARK) \
              if (hw_compare_and_store(0,1,(u_int *)&mappingrecurse)) \
                thread_call_enter(mapping_adjust_call); \
	} \
	simple_unlock(&pv_free_list_lock); \
}

#define	PV_FREE(pv_e) { \
	simple_lock(&pv_free_list_lock); \
	pv_e->next = pv_free_list; \
	pv_free_list = pv_e; \
        pv_free_count++; \
	simple_unlock(&pv_free_list_lock); \
}

zone_t		pv_list_zone;		/* zone of pv_entry structures */

static zone_t pdpt_zone;

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
pmap_paddr_t	vm_first_phys = (pmap_paddr_t) 0;
pmap_paddr_t	vm_last_phys  = (pmap_paddr_t) 0;
boolean_t	pmap_initialized = FALSE;/* Has pmap_init completed? */

static struct vm_object kptobj_object_store;
static vm_object_t kptobj;

/*
 *	Index into pv_head table, its lock bits, and the modify/reference
 *	bits starting at vm_first_phys.
 */

#define pa_index(pa)	(i386_btop(pa - vm_first_phys))

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
uint64_t pde_mapped_size;

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

/*
 *	We raise the interrupt level to splvm, to block interprocessor
 *	interrupts during pmap operations.  We mark the cpu's cr3 inactive
 *	while interrupts are blocked.
 */
#define SPLVM(spl)	{						\
	spl = splhigh();						\
	CPU_CR3_MARK_INACTIVE();					\
}

#define SPLX(spl)	{						\
	if (current_cpu_datap()->cpu_tlb_invalid)			\
	    process_pmap_updates();					\
	CPU_CR3_MARK_ACTIVE();						\
	splx(spl);							\
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

#if	USLOCK_DEBUG
extern int	max_lock_loops;
extern int	disableSerialOuput;
#define LOOP_VAR							\
	unsigned int	loop_count;					\
	loop_count = disableSerialOuput ? max_lock_loops		\
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


static void pmap_flush_tlbs(pmap_t pmap);

#define PMAP_UPDATE_TLBS(pmap, s, e)					\
	pmap_flush_tlbs(pmap)


#define MAX_TBIS_SIZE	32		/* > this -> TBIA */ /* XXX */


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

unsigned int	inuse_ptepages_count = 0;	/* debugging */

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
extern uint32_t lowGlo;
extern void *version;

pt_entry_t     *DMAP1, *DMAP2;
caddr_t         DADDR1;
caddr_t         DADDR2;

#if  DEBUG_ALIAS
#define PMAP_ALIAS_MAX 32
struct pmap_alias {
        vm_offset_t rpc;
        pmap_t pmap;
        vm_map_offset_t va;
        int cookie;
#define PMAP_ALIAS_COOKIE 0xdeadbeef
} pmap_aliasbuf[PMAP_ALIAS_MAX];
int pmap_alias_index = 0;
extern vm_offset_t get_rpc();

#endif  /* DEBUG_ALIAS */

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

	return (0);
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

	return (0);
}



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
	  if (pmap == kernel_pmap) {
	    return (vtopte(vaddr)); /* compat kernel still has pte's mapped */
	  }

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

	return(0);
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
 *	[vm_first_phys, vm_last_phys) (i.e., devices).
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
	pt_entry_t	*pte;

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
		pte = pmap_pte(kernel_pmap, (vm_map_offset_t)virt);
		if (pte == PT_ENTRY_NULL) {
			panic("pmap_map_bd: Invalid kernel address\n");
		}
		pmap_store_pte(pte, template);
		pte_increment_pa(template);
		virt += PAGE_SIZE;
		start_addr += PAGE_SIZE;
	}

	flush_tlb();
	return(virt);
}

extern	char		*first_avail;
extern	vm_offset_t	virtual_avail, virtual_end;
extern	pmap_paddr_t	avail_start, avail_end;
extern  vm_offset_t     etext;
extern  void            *sectHIBB;
extern  int             sectSizeHIB;


vm_offset_t
pmap_high_shared_remap(enum high_fixed_addresses e, vm_offset_t va, int sz)
{
  vm_offset_t ve = pmap_index_to_virt(e);
  pt_entry_t *ptep;
  pmap_paddr_t pa;
  int i;

  assert(0 == (va & PAGE_MASK));  /* expecting page aligned */
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
        struct __gdt_desc_struct gdt_desc = {0,0,0};
	struct __idt_desc_struct idt_desc = {0,0,0};
#if MACH_KDB
	struct i386_tss *ttss;
#endif

	kprintf("HIGH_MEM_BASE 0x%x fixed per-cpu begin 0x%x\n", 
		HIGH_MEM_BASE,pmap_index_to_virt(HIGH_FIXED_CPUS_BEGIN));
	pte_unique_base = pmap_pte(kernel_pmap, (vm_map_offset_t)pmap_index_to_virt(HIGH_FIXED_CPUS_BEGIN));

	if (i386_btop(&hi_remap_etext - &hi_remap_text + 1) >
				HIGH_FIXED_TRAMPS_END - HIGH_FIXED_TRAMPS + 1)
		panic("tramps too large");
	haddr = pmap_high_shared_remap(HIGH_FIXED_TRAMPS,
					(vm_offset_t) &hi_remap_text, 3);
	kprintf("tramp: 0x%x, ",haddr);
	printf("hi mem tramps at 0x%x\n",haddr);
	/* map gdt up high and update ptr for reload */
	haddr = pmap_high_shared_remap(HIGH_FIXED_GDT,
					(vm_offset_t) master_gdt, 1);
	__asm__ __volatile__("sgdt %0": "=m" (gdt_desc): :"memory");
	gdt_desc.address = haddr;
	kprintf("GDT: 0x%x, ",haddr);
	/* map ldt up high */
	haddr = pmap_high_shared_remap(HIGH_FIXED_LDT_BEGIN,
					(vm_offset_t) master_ldt,
					HIGH_FIXED_LDT_END - HIGH_FIXED_LDT_BEGIN + 1);
	kprintf("LDT: 0x%x, ",haddr);
	/* put new ldt addr into gdt */
	master_gdt[sel_idx(KERNEL_LDT)] = ldt_desc_pattern;
	master_gdt[sel_idx(KERNEL_LDT)].offset = (vm_offset_t) haddr;
	fix_desc(&master_gdt[sel_idx(KERNEL_LDT)], 1);
	master_gdt[sel_idx(USER_LDT)] = ldt_desc_pattern;
	master_gdt[sel_idx(USER_LDT)].offset = (vm_offset_t) haddr;
	fix_desc(&master_gdt[sel_idx(USER_LDT)], 1);

	/* map idt up high */
	haddr = pmap_high_shared_remap(HIGH_FIXED_IDT,
					(vm_offset_t) master_idt, 1);
	__asm__ __volatile__("sidt %0" : "=m" (idt_desc));
	idt_desc.address = haddr;
	kprintf("IDT: 0x%x, ", haddr);
	/* remap ktss up high and put new high addr into gdt */
	haddr = pmap_high_shared_remap(HIGH_FIXED_KTSS,
					(vm_offset_t) &master_ktss, 1);
	master_gdt[sel_idx(KERNEL_TSS)] = tss_desc_pattern;
	master_gdt[sel_idx(KERNEL_TSS)].offset = (vm_offset_t) haddr;
	fix_desc(&master_gdt[sel_idx(KERNEL_TSS)], 1);
	kprintf("KTSS: 0x%x, ",haddr);
#if MACH_KDB
	/* remap dbtss up high and put new high addr into gdt */
	haddr = pmap_high_shared_remap(HIGH_FIXED_DBTSS,
					(vm_offset_t) &master_dbtss, 1);
	master_gdt[sel_idx(DEBUG_TSS)] = tss_desc_pattern;
	master_gdt[sel_idx(DEBUG_TSS)].offset = (vm_offset_t) haddr;
	fix_desc(&master_gdt[sel_idx(DEBUG_TSS)], 1);
	ttss = (struct i386_tss *)haddr;
	kprintf("DBTSS: 0x%x, ",haddr);
#endif	/* MACH_KDB */

	/* remap dftss up high and put new high addr into gdt */
	haddr = pmap_high_shared_remap(HIGH_FIXED_DFTSS,
					(vm_offset_t) &master_dftss, 1);
	master_gdt[sel_idx(DF_TSS)] = tss_desc_pattern;
	master_gdt[sel_idx(DF_TSS)].offset = (vm_offset_t) haddr;
	fix_desc(&master_gdt[sel_idx(DF_TSS)], 1);
	kprintf("DFTSS: 0x%x\n",haddr);

	/* remap mctss up high and put new high addr into gdt */
	haddr = pmap_high_shared_remap(HIGH_FIXED_DFTSS,
					(vm_offset_t) &master_mctss, 1);
	master_gdt[sel_idx(MC_TSS)] = tss_desc_pattern;
	master_gdt[sel_idx(MC_TSS)].offset = (vm_offset_t) haddr;
	fix_desc(&master_gdt[sel_idx(MC_TSS)], 1);
	kprintf("MCTSS: 0x%x\n",haddr);

	__asm__ __volatile__("lgdt %0": "=m" (gdt_desc));
	__asm__ __volatile__("lidt %0": "=m" (idt_desc));
	kprintf("gdt/idt reloaded, ");
	set_tr(KERNEL_TSS);
	kprintf("tr reset to KERNEL_TSS\n");
}


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
	__unused vm_offset_t	load_start,
	boolean_t		IA32e)
{
	vm_offset_t	va;
	pt_entry_t	*pte;
	int i;
	int wpkernel, boot_arg;
	pdpt_entry_t *pdpt;

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
	kernel_pmap->pm_64bit = 0;
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
	  pa = (pmap_paddr_t) kvtophys(va + i386_ptob(i));
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
	pmap_store_pte(pmap_pde(kernel_pmap, HIGH_MEM_BASE), high_shared_pde);

	nkpt = NKPT;
	inuse_ptepages_count += NKPT;

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


	lock_init(&pmap_system_lock,
		  FALSE,		/* NOT a sleep lock */
		  0, 0);

	virtual_avail = va;

	wpkernel = 1;
	if (PE_parse_boot_arg("wpkernel", &boot_arg)) {
		if (boot_arg == 0)
			wpkernel = 0;
	}

	/* Remap kernel text readonly unless the "wpkernel" boot-arg is present
	 * and set to 0.
	 */
	if (wpkernel)
	{
		vm_offset_t     myva;
		pt_entry_t     *ptep;

		for (myva = i386_round_page(MP_BOOT + MP_BOOTSTACK); myva < etext; myva += PAGE_SIZE) {
                        if (myva >= (vm_offset_t)sectHIBB && myva < ((vm_offset_t)sectHIBB + sectSizeHIB))
                                continue;
			ptep = pmap_pte(kernel_pmap, (vm_map_offset_t)myva);
			if (ptep)
				pmap_store_pte(ptep, *ptep & ~INTEL_PTE_RW);
		}
	}

	/* no matter what,  kernel page zero is not accessible */
	pte = pmap_pte(kernel_pmap, 0);
	pmap_store_pte(pte, INTEL_PTE_INVALID);

	/* map lowmem global page into fixed addr 0x2000 */
	if (0 == (pte = pmap_pte(kernel_pmap,0x2000))) panic("lowmem pte");

	pmap_store_pte(pte, kvtophys((vm_offset_t)&lowGlo)|INTEL_PTE_VALID|INTEL_PTE_REF|INTEL_PTE_MOD|INTEL_PTE_WIRED|INTEL_PTE_RW);
	flush_tlb();

	simple_lock_init(&kernel_pmap->lock, 0);
	simple_lock_init(&pv_free_list_lock, 0);

        pmap_init_high_shared();

	pde_mapped_size = PDE_MAPPED_SIZE;

	if (cpu_64bit) {
	  pdpt_entry_t *ppdpt   = (pdpt_entry_t *)IdlePDPT;
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
	  cpu_IA32e_enable(current_cpu_datap());
	  current_cpu_datap()->cpu_is64bit = TRUE;
	  /* welcome to a 64 bit world */

	  /* Re-initialize and load descriptors */
	  cpu_desc_init64(&cpu_data_master, TRUE);
	  cpu_desc_load64(&cpu_data_master);
	  fast_syscall_init64();

	  pde_mapped_size = 512*4096 ; 

	  ml_set_interrupts_enabled(istate);

	}
	kernel_pmap->pm_hold = kernel_pmap->pm_pml4;

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
	if (PE_parse_boot_arg("-no_shared_cr3", &no_shared_cr3)) {
		kprintf("Shared kernel address space disabled\n");
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
	vm_map_offset_t		vaddr;
	ppnum_t			ppn;

	/*
	 *	Allocate memory for the pv_head_table and its lock bits,
	 *	the modify bit array, and the pte_page table.
	 */

	/* zero bias all these arrays now instead of off avail_start
	   so we cover all memory */
	npages = i386_btop(avail_end);
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
	s = 63;
	pdpt_zone = zinit(s, 400*s, 4096, "pdpt"); /* XXX */

	/*
	 *	Only now, when all of the data structures are allocated,
	 *	can we set vm_first_phys and vm_last_phys.  If we set them
	 *	too soon, the kmem_alloc_wired above will try to use these
	 *	data structures and blow up.
	 */

	/* zero bias this now so we cover all memory */
	vm_first_phys = 0;
	vm_last_phys = avail_end;

	kptobj = &kptobj_object_store;
	_vm_object_allocate((vm_object_size_t)NKPDE, kptobj);
	kernel_pmap->pm_obj = kptobj;

	/* create pv entries for kernel pages mapped by low level
	   startup code.  these have to exist so we can pmap_remove()
	   e.g. kext pages from the middle of our addr space */

	vaddr = (vm_map_offset_t)0;
	for (ppn = 0; ppn < i386_btop(avail_start) ; ppn++ ) {
	  pv_entry_t	pv_e;

	  pv_e = pai_to_pvh(ppn);
	  pv_e->va = vaddr;
	  vaddr += PAGE_SIZE;
	  kernel_pmap->stats.resident_count++;
	  pv_e->pmap = kernel_pmap;
	  pv_e->next = PV_ENTRY_NULL;
	}

	pmap_initialized = TRUE;

	/*
	 *	Initializie pmap cache.
	 */
	pmap_cache_list = PMAP_NULL;
	pmap_cache_count = 0;
	simple_lock_init(&pmap_cache_lock, 0);
}

void
x86_lowmem_free(void)
{
	/* free lowmem pages back to the vm system. we had to defer doing this
	   until the vm system was fully up.
	   the actual pages that are released are determined by which
	   pages the memory sizing code puts into the region table */

	ml_static_mfree((vm_offset_t) i386_ptob(pmap_memory_regions[0].base),
			(vm_size_t) i386_ptob(pmap_memory_regions[0].end - pmap_memory_regions[0].base));
}


#define valid_page(x) (pmap_initialized && pmap_valid_page(x))

boolean_t
pmap_verify_free(
		 ppnum_t pn)
{
        pmap_paddr_t	phys;
	pv_entry_t	pv_h;
	int		pai;
	spl_t		spl;
	boolean_t	result;

	assert(pn != vm_page_fictitious_addr);
	phys = (pmap_paddr_t)i386_ptob(pn);
	if (!pmap_initialized)
		return(TRUE);

	if (!pmap_valid_page(pn))
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
	    vm_map_size_t	sz,
	    boolean_t  		is_64bit)
{
        register pmap_t			p;
	int		i;
	vm_offset_t	va;
	vm_size_t	size;
	pdpt_entry_t    *pdpt;
	pml4_entry_t    *pml4p;
	vm_page_t       m;
	int template;
	pd_entry_t      *pdp;
	spl_t s;

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
	p->stats.wired_count = 0;
	p->ref_count = 1;
	p->nx_enabled = 1;
	p->pm_64bit = is_64bit;
	p->pm_kernel_cr3 = FALSE;

	if (!cpu_64bit) {
	  /* legacy 32 bit setup */
	  /* in the legacy case the pdpt layer is hardwired to 4 entries and each
	   * entry covers 1GB of addr space */
	  if (KERN_SUCCESS != kmem_alloc_wired(kernel_map, (vm_offset_t *)(&p->dirbase), NBPTD))
	    panic("pmap_create kmem_alloc_wired");
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

	  template = cpu_64bit ? INTEL_PTE_VALID|INTEL_PTE_RW|INTEL_PTE_USER|INTEL_PTE_REF : INTEL_PTE_VALID;
	  for (i = 0; i< NPGPTD; i++, pdpt++) {
	    pmap_paddr_t pa;
	    pa = (pmap_paddr_t) kvtophys(va + i386_ptob(i));
	    pmap_store_pte(pdpt, pa | template);
	  }

	  /* map the high shared pde */
	  pmap_store_pte(pmap_pde(p, HIGH_MEM_BASE), high_shared_pde);

	} else {

	  /* 64 bit setup  */

	  /* alloc the pml4 page in kernel vm */
	  if (KERN_SUCCESS != kmem_alloc_wired(kernel_map, (vm_offset_t *)(&p->pm_hold), PAGE_SIZE))
	    panic("pmap_create kmem_alloc_wired pml4");

	  memset((char *)p->pm_hold, 0, PAGE_SIZE);
	  p->pm_cr3 = (pmap_paddr_t)kvtophys((vm_offset_t)p->pm_hold);

	  inuse_ptepages_count++;
	  p->stats.resident_count++;
	  p->stats.wired_count++;

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
	pmap_store_pte((pml4p+KERNEL_UBER_PML4_INDEX),*kernel_pmap->pm_pml4);
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

	return(p);
}

void
pmap_set_4GB_pagezero(pmap_t p)
{
	int		spl;
	pdpt_entry_t	*user_pdptp;
	pdpt_entry_t	*kern_pdptp;

	assert(p->pm_64bit);

	/* Kernel-shared cr3 may be disabled by boot arg. */
	if (no_shared_cr3)
		return;

	/*
	 * Set the bottom 4 3rd-level pte's to be the kernel's.
	 */
	spl = splhigh();
	while ((user_pdptp = pmap64_pdpt(p, 0x0)) == PDPT_ENTRY_NULL) {
		splx(spl);
		pmap_expand_pml4(p, 0x0);
		spl = splhigh();
	}
	kern_pdptp = kernel_pmap->pm_pdpt;
	pmap_store_pte(user_pdptp+0, *(kern_pdptp+0));
	pmap_store_pte(user_pdptp+1, *(kern_pdptp+1));
	pmap_store_pte(user_pdptp+2, *(kern_pdptp+2));
	pmap_store_pte(user_pdptp+3, *(kern_pdptp+3));

	p->pm_kernel_cr3 = TRUE;

	splx(spl);

}

void
pmap_load_kernel_cr3(void)
{
	uint32_t	kernel_cr3;

	assert(!ml_get_interrupts_enabled());

	/*
	 * Reload cr3 with the true kernel cr3.
	 * Note: kernel's pml4 resides below 4GB physical.
	 */
	kernel_cr3 = current_cpu_datap()->cpu_kernel_cr3;
	set_cr3(kernel_cr3);
	current_cpu_datap()->cpu_active_cr3 = kernel_cr3;
	current_cpu_datap()->cpu_task_map = TASK_MAP_32BIT;
	current_cpu_datap()->cpu_tlb_invalid = FALSE;
	__asm__ volatile("mfence");
}

void
pmap_clear_4GB_pagezero(pmap_t p)
{
	int		spl;
	pdpt_entry_t	*user_pdptp;
	uint32_t	cr3;

	if (!p->pm_kernel_cr3)
		return;

	spl = splhigh();
	user_pdptp = pmap64_pdpt(p, 0x0);
	pmap_store_pte(user_pdptp+0, 0);
	pmap_store_pte(user_pdptp+1, 0);
	pmap_store_pte(user_pdptp+2, 0);
	pmap_store_pte(user_pdptp+3, 0);

	p->pm_kernel_cr3 = FALSE;

	pmap_load_kernel_cr3();

	splx(spl);
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
	spl_t                   s;
#if 0
	register pt_entry_t	*pdep;
	register vm_page_t	m;
#endif

	if (p == PMAP_NULL)
		return;
	SPLVM(s);
	simple_lock(&p->lock);
	c = --p->ref_count;
	if (c == 0) {
		/* 
		 * If some cpu is not using the physical pmap pointer that it
		 * is supposed to be (see set_dirbase), we might be using the
		 * pmap that is being destroyed! Make sure we are
		 * physically on the right pmap:
		 */
		PMAP_UPDATE_TLBS(p,
				 VM_MIN_ADDRESS,
				 VM_MAX_KERNEL_ADDRESS);

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

	if (!cpu_64bit) {
#if 0
	pdep = (pt_entry_t *)p->dirbase;

	while (pdep < (pt_entry_t *)&p->dirbase[(UMAXPTDI+1)]) {
	    int ind;

	    if (*pdep & INTEL_PTE_VALID) {
	        ind = pdep - (pt_entry_t *)&p->dirbase[0];

		vm_object_lock(p->pm_obj);
		m = vm_page_lookup(p->pm_obj, (vm_object_offset_t)ind);
		if (m == VM_PAGE_NULL) {
		    panic("pmap_destroy: pte page not in object");
		}
		vm_page_lock_queues();
		vm_page_free(m);
		inuse_ptepages_count--;

		vm_object_unlock(p->pm_obj);
		vm_page_unlock_queues();

		/*
		 *	Clear pdes, this might be headed for the cache.
		 */
		pmap_store_pte(pdep, 0);
		pdep++;
	    }
	    else {
	      pmap_store_pte(pdep, 0);
	      pdep++;
	    }
	
	}
#else
	inuse_ptepages_count -= p->pm_obj->resident_page_count;
#endif
	vm_object_deallocate(p->pm_obj);
	  kmem_free(kernel_map, (vm_offset_t)p->dirbase, NBPTD);
	  zfree(pdpt_zone, (void *)p->pm_hold);
	} else {

	  /* 64 bit */

	  pmap_unmap_sharedpage(p);

	  /* free 64 bit mode structs */
	  inuse_ptepages_count--;
	  kmem_free(kernel_map, (vm_offset_t)p->pm_hold, PAGE_SIZE);

	  inuse_ptepages_count -= p->pm_obj_pml4->resident_page_count;
	  vm_object_deallocate(p->pm_obj_pml4);

	  inuse_ptepages_count -= p->pm_obj_pdpt->resident_page_count;
	  vm_object_deallocate(p->pm_obj_pdpt);

	  inuse_ptepages_count -= p->pm_obj->resident_page_count;
	  vm_object_deallocate(p->pm_obj);

	}

	zfree(pmap_zone, p);
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

static void
pmap_remove_range(
	pmap_t			pmap,
	vm_map_offset_t		vaddr,
	pt_entry_t		*spte,
	pt_entry_t		*epte)
{
	register pt_entry_t	*cpte;
	int			num_removed, num_unwired;
	int			pai;
	pmap_paddr_t		pa;

	num_removed = 0;
	num_unwired = 0;

	for (cpte = spte; cpte < epte;
	     cpte++, vaddr += PAGE_SIZE) {

	    pa = pte_to_pa(*cpte);
	    if (pa == 0)
		continue;

	    if (iswired(*cpte))
		num_unwired++;

	    if (!valid_page(i386_btop(pa))) {

		/*
		 *	Outside range of managed physical memory.
		 *	Just remove the mappings.
		 */
		register pt_entry_t	*lpte = cpte;

		pmap_store_pte(lpte, 0);
		continue;
	    }
	    num_removed++;

	    pai = pa_index(pa);
	    LOCK_PVH(pai);

	    /*
	     *	Get the modify and reference bits.
	     */
	    {
		register pt_entry_t	*lpte;

		lpte = cpte;
		pmap_phys_attributes[pai] |=
			*lpte & (PHYS_MODIFIED|PHYS_REFERENCED);
		pmap_store_pte(lpte, 0);

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
		if (pv_h->va == vaddr && pv_h->pmap == pmap) {
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
		    } while (cur->va != vaddr || cur->pmap != pmap);
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
	__unused pmap_t		map,
	__unused ppnum_t         pn)
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


void
pmap_remove(
	pmap_t		map,
	addr64_t	s64,
	addr64_t	e64)
{
	spl_t			spl;
	register pt_entry_t	*pde;
	register pt_entry_t	*spte, *epte;
	addr64_t		l64;
	addr64_t    		orig_s64;

	if (map == PMAP_NULL || s64 == e64)
		return;

	PMAP_READ_LOCK(map, spl);

	orig_s64 = s64;

	while (s64 < e64) {
	    l64 = (s64 + pde_mapped_size) & ~(pde_mapped_size-1);
	    if (l64 > e64)
		l64 = e64;
	    pde = pmap_pde(map, s64);
	    if (pde && (*pde & INTEL_PTE_VALID)) {
	        spte = (pt_entry_t *)pmap_pte(map, (s64 & ~(pde_mapped_size-1)));
		spte = &spte[ptenum(s64)];
		epte = &spte[intel_btop(l64-s64)];
		pmap_remove_range(map, s64, spte, epte);
	    }
	    s64 = l64;
	    pde++;
	}
	PMAP_UPDATE_TLBS(map, orig_s64, e64);

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
        ppnum_t         pn,
	vm_prot_t	prot)
{
	pv_entry_t		pv_h, prev;
	register pv_entry_t	pv_e;
	register pt_entry_t	*pte;
	int			pai;
	register pmap_t		pmap;
	spl_t			spl;
	boolean_t		remove;
	pmap_paddr_t            phys;

	assert(pn != vm_page_fictitious_addr);

	if (!valid_page(pn)) {
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
	phys = (pmap_paddr_t)i386_ptob(pn);
	pai = pa_index(phys);
	pv_h = pai_to_pvh(pai);


	/*
	 *	Lock the pmap system first, since we will be changing
	 *	several pmaps.
	 */
	PMAP_WRITE_LOCK(spl);

	/*
	 * Walk down PV list, changing or removing all mappings.
	 * We do not have to lock the pv_list because we have
	 * the entire pmap system locked.
	 */
	if (pv_h->pmap != PMAP_NULL) {

	        prev = pv_e = pv_h;

		do {
		        register vm_map_offset_t vaddr;

			pmap = pv_e->pmap;
			/*
			 * Lock the pmap to block pmap_extract and similar routines.
			 */
			simple_lock(&pmap->lock);

			vaddr = pv_e->va;
			pte = pmap_pte(pmap, vaddr);
			if(0 == pte) {
			  kprintf("pmap_page_protect pmap 0x%x pn 0x%x vaddr 0x%llx\n",pmap, pn, vaddr);
			  panic("pmap_page_protect");
			}
			/*
			 * Consistency checks.
			 */
			/* assert(*pte & INTEL_PTE_VALID); XXX */
			/* assert(pte_to_phys(*pte) == phys); */


			/*
			 * Remove the mapping if new protection is NONE
			 * or if write-protecting a kernel mapping.
			 */
			if (remove || pmap == kernel_pmap) {
			        /*
				 * Remove the mapping, collecting any modify bits.
				 */
			        pmap_store_pte(pte, *pte & ~INTEL_PTE_VALID);

				PMAP_UPDATE_TLBS(pmap, vaddr, vaddr + PAGE_SIZE);

			        pmap_phys_attributes[pai] |= *pte & (PHYS_MODIFIED|PHYS_REFERENCED);

				pmap_store_pte(pte, 0);


				//XXX breaks DEBUG build		    assert(pmap->stats.resident_count >= 1);
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
			} else {
			        /*
				 * Write-protect.
				 */
			        pmap_store_pte(pte, *pte & ~INTEL_PTE_WRITE);

				PMAP_UPDATE_TLBS(pmap, vaddr, vaddr + PAGE_SIZE);
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
	pmap_page_protect(pa, 0);				/* disconnect the page */
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
	spl_t		spl;
	boolean_t	set_NX;

	if (map == PMAP_NULL)
		return;

	if (prot == VM_PROT_NONE) {
		pmap_remove(map, sva, eva);
		return;
	}

	if ( (prot & VM_PROT_EXECUTE) || !nx_enabled || !map->nx_enabled )
	        set_NX = FALSE;
	else
	        set_NX = TRUE;

	SPLVM(spl);
	simple_lock(&map->lock);

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
			    pmap_store_pte(spte, *spte | INTEL_PTE_WRITE);
			else
			    pmap_store_pte(spte, *spte & ~INTEL_PTE_WRITE);

			if (set_NX == TRUE)
			    pmap_store_pte(spte, *spte | INTEL_PTE_NX);
			else
			    pmap_store_pte(spte, *spte & ~INTEL_PTE_NX);

		    }
		    spte++;
		}
	    }
	    sva = lva;
	    pde++;
	}
	PMAP_UPDATE_TLBS(map, orig_sva, eva);

	simple_unlock(&map->lock);
	SPLX(spl);
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
	vm_map_offset_t		vaddr,
	ppnum_t                 pn,
	vm_prot_t		prot,
	unsigned int 		flags,
	boolean_t		wired)
{
	register pt_entry_t	*pte;
	register pv_entry_t	pv_h;
	register int		pai;
	pv_entry_t		pv_e;
	pt_entry_t		template;
	spl_t			spl;
	pmap_paddr_t		old_pa;
	pmap_paddr_t            pa = (pmap_paddr_t)i386_ptob(pn);
	boolean_t		need_tlbflush = FALSE;
	boolean_t		set_NX;

	XPR(0x80000000, "%x/%x: pmap_enter %x/%qx/%x\n",
	    current_thread(),
	    current_thread(), 
	    pmap, vaddr, pn);

	assert(pn != vm_page_fictitious_addr);
	if (pmap_debug)
		printf("pmap(%qx, %x)\n", vaddr, pn);
	if (pmap == PMAP_NULL)
		return;

	if ( (prot & VM_PROT_EXECUTE) || !nx_enabled || !pmap->nx_enabled )
	        set_NX = FALSE;
	else
	        set_NX = TRUE;
	
	/*
	 *	Must allocate a new pvlist entry while we're unlocked;
	 *	zalloc may cause pageout (which will lock the pmap system).
	 *	If we determine we need a pvlist entry, we will unlock
	 *	and allocate one.  Then we will retry, throughing away
	 *	the allocated entry later (if we no longer need it).
	 */
	pv_e = PV_ENTRY_NULL;

	PMAP_READ_LOCK(pmap, spl);

	/*
	 *	Expand pmap to include this pte.  Assume that
	 *	pmap is always expanded to include enough hardware
	 *	pages to map one VM page.
	 */

	while ((pte = pmap_pte(pmap, vaddr)) == PT_ENTRY_NULL) {
		/*
		 *	Must unlock to expand the pmap.
		 */
		PMAP_READ_UNLOCK(pmap, spl);

		pmap_expand(pmap, vaddr); /* going to grow pde level page(s) */

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

	    if(VM_MEM_NOT_CACHEABLE == (flags & (VM_MEM_NOT_CACHEABLE | VM_WIMG_USE_DEFAULT))) {
		if(!(flags & VM_MEM_GUARDED))
			template |= INTEL_PTE_PTA;
		template |= INTEL_PTE_NCACHE;
	    }

	    if (pmap != kernel_pmap)
		template |= INTEL_PTE_USER;
	    if (prot & VM_PROT_WRITE)
		template |= INTEL_PTE_WRITE;

	    if (set_NX == TRUE)
		template |= INTEL_PTE_NX;

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

		if (*pte & INTEL_PTE_MOD)
		    template |= INTEL_PTE_MOD;

		pmap_store_pte(pte, template);
		pte++;

		need_tlbflush = TRUE;
	    goto Done;
	}

	/*
	 *	Outline of code from here:
	 *	   1) If va was mapped, update TLBs, remove the mapping
	 *	      and remove old pvlist entry.
	 *	   2) Add pvlist entry for new mapping
	 *	   3) Enter new mapping.
	 *
	 *      SHARING FAULTS IS HORRIBLY BROKEN
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

	if (old_pa != (pmap_paddr_t) 0) {

	    /*
	     *	Don't do anything to pages outside valid memory here.
	     *	Instead convince the code that enters a new mapping
	     *	to overwrite the old one.
	     */

	    if (valid_page(i386_btop(old_pa))) {

		pai = pa_index(old_pa);
		LOCK_PVH(pai);

		assert(pmap->stats.resident_count >= 1);
		pmap->stats.resident_count--;
	    	if (iswired(*pte)) {
		    assert(pmap->stats.wired_count >= 1);
		    pmap->stats.wired_count--;
		}

		    pmap_phys_attributes[pai] |=
			*pte & (PHYS_MODIFIED|PHYS_REFERENCED);

		pmap_store_pte(pte, 0);
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
		    if (pv_h->va == vaddr && pv_h->pmap == pmap) {
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
			} while (cur->va != vaddr || cur->pmap != pmap);
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
		old_pa = (pmap_paddr_t) 0;

		if (iswired(*pte)) {
		    assert(pmap->stats.wired_count >= 1);
		    pmap->stats.wired_count--;
		}
	    }
	    need_tlbflush = TRUE;
        
	}

	if (valid_page(i386_btop(pa))) {

	    /*
	     *	Step 2) Enter the mapping in the PV list for this
	     *	physical page.
	     */

	    pai = pa_index(pa);


#if SHARING_FAULTS /* this is horribly broken , do not enable */
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
		pv_h->va = vaddr;
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
			if (e->pmap == pmap && e->va == vaddr)
                            panic("pmap_enter: already in pv_list");
			e = e->next;
		    }
		}
#endif	/* DEBUG */
#if SHARING_FAULTS /* broken, do not enable */
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
                             pmap_remove_range(pmap, e->va, opte,
                                                      opte + 1);

			     PMAP_UPDATE_TLBS(pmap, e->va, e->va + PAGE_SIZE);

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
                                pma->va = vaddr;
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
		      panic("pmap no pv_e's");
		    }
		}
		pv_e->va = vaddr;
		pv_e->pmap = pmap;
		pv_e->next = pv_h->next;
		pv_h->next = pv_e;
		/*
		 *	Remember that we used the pvlist entry.
		 */
		pv_e = PV_ENTRY_NULL;
	    }
	    UNLOCK_PVH(pai);

	    /*
	     * only count the mapping
	     * for 'managed memory'
	     */
	    pmap->stats.resident_count++;
	}

	/*
	 * Step 3) Enter the mapping.
	 */


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

	if (set_NX == TRUE)
		template |= INTEL_PTE_NX;

	if (wired) {
		template |= INTEL_PTE_WIRED;
		pmap->stats.wired_count++;
	}
	pmap_store_pte(pte, template);

Done:
	if (need_tlbflush == TRUE)
	        PMAP_UPDATE_TLBS(pmap, vaddr, vaddr + PAGE_SIZE);

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
	vm_map_offset_t	vaddr,
	boolean_t	wired)
{
	register pt_entry_t	*pte;
	spl_t			spl;

#if 1
	/*
	 *	We must grab the pmap system lock because we may
	 *	change a pte_page queue.
	 */
	PMAP_READ_LOCK(map, spl);

	if ((pte = pmap_pte(map, vaddr)) == PT_ENTRY_NULL)
		panic("pmap_change_wiring: pte missing");

	if (wired && !iswired(*pte)) {
	    /*
	     *	wiring down mapping
	     */
	    map->stats.wired_count++;
	    pmap_store_pte(pte, *pte | INTEL_PTE_WIRED);
	    pte++;
	}
	else if (!wired && iswired(*pte)) {
	    /*
	     *	unwiring mapping
	     */
	    assert(map->stats.wired_count >= 1);
	    map->stats.wired_count--;
	    pmap_store_pte(pte, *pte & ~INTEL_PTE_WIRED);
	    pte++;
	}

	PMAP_READ_UNLOCK(map, spl);

#else
	return;
#endif

}

ppnum_t
pmap_find_phys(pmap_t pmap, addr64_t va)
{
	pt_entry_t     *ptp;
	ppnum_t         ppn;

	mp_disable_preemption();

	ptp = pmap_pte(pmap, va);
	if (PT_ENTRY_NULL == ptp) {
		ppn = 0;
	} else {
		ppn = (ppnum_t) i386_btop(pte_to_pa(*ptp));
	}
	mp_enable_preemption();

	return ppn;
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
	        paddr = ((vm_offset_t)i386_ptob(ppn)) | (vaddr & INTEL_OFFMASK);
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

	vm_object_lock(map->pm_obj_pml4);
#if 0 /* DEBUG */
	if (0 != vm_page_lookup(map->pm_obj_pml4, (vm_object_offset_t)i)) {
	  kprintf("pmap_expand_pml4: obj_pml4 not empty, pmap 0x%x pm_obj_pml4 0x%x vaddr 0x%llx i 0x%llx\n",
		  map, map->pm_obj_pml4, vaddr, i);
	}
#endif
	vm_page_insert(m, map->pm_obj_pml4, (vm_object_offset_t)i);

	vm_page_lock_queues();
	vm_page_wire(m);

	vm_page_unlock_queues();
	vm_object_unlock(map->pm_obj_pml4);
	inuse_ptepages_count++;
	map->stats.resident_count++;
	map->stats.wired_count++;

	/*
	 *	Zero the page.
	 */
	pmap_zero_page(pn);

	PMAP_READ_LOCK(map, spl);
	/*
	 *	See if someone else expanded us first
	 */
	if (pmap64_pdpt(map, vaddr) != PDPT_ENTRY_NULL) {
		PMAP_READ_UNLOCK(map, spl);
		vm_object_lock(map->pm_obj_pml4);
		vm_page_lock_queues();
		vm_page_free(m);
		inuse_ptepages_count--;
		map->stats.resident_count--;
		map->stats.wired_count--;

		vm_page_unlock_queues();
		vm_object_unlock(map->pm_obj_pml4);
		return;
	}

	/*
	 *	Set the page directory entry for this page table.
	 *	If we have allocated more than one hardware page,
	 *	set several page directory entries.
	 */

	pml4p = pmap64_pml4(map, vaddr); /* refetch under lock */

	pmap_store_pte(pml4p, pa_to_pte(pa)
				| INTEL_PTE_VALID
				| INTEL_PTE_USER
				| INTEL_PTE_WRITE);

	PMAP_READ_UNLOCK(map, spl);

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

	vm_object_lock(map->pm_obj_pdpt);
#if 0 /* DEBUG */
	if (0 != vm_page_lookup(map->pm_obj_pdpt, (vm_object_offset_t)i)) {
	  kprintf("pmap_expand_pdpt: obj_pdpt not empty, pmap 0x%x pm_obj_pdpt 0x%x vaddr 0x%llx i 0x%llx\n",
		  map, map->pm_obj_pdpt, vaddr, i);
	}
#endif
	vm_page_insert(m, map->pm_obj_pdpt, (vm_object_offset_t)i);

	vm_page_lock_queues();
	vm_page_wire(m);

	vm_page_unlock_queues();
	vm_object_unlock(map->pm_obj_pdpt);
	inuse_ptepages_count++;
	map->stats.resident_count++;
	map->stats.wired_count++;

	/*
	 *	Zero the page.
	 */
	pmap_zero_page(pn);

	PMAP_READ_LOCK(map, spl);
	/*
	 *	See if someone else expanded us first
	 */
	if (pmap64_pde(map, vaddr) != PD_ENTRY_NULL) {
		PMAP_READ_UNLOCK(map, spl);
		vm_object_lock(map->pm_obj_pdpt);
		vm_page_lock_queues();
		vm_page_free(m);
		inuse_ptepages_count--;
		map->stats.resident_count--;
		map->stats.wired_count--;

		vm_page_unlock_queues();
		vm_object_unlock(map->pm_obj_pdpt);
		return;
	}

	/*
	 *	Set the page directory entry for this page table.
	 *	If we have allocated more than one hardware page,
	 *	set several page directory entries.
	 */

	pdptp = pmap64_pdpt(map, vaddr); /* refetch under lock */

	pmap_store_pte(pdptp, pa_to_pte(pa)
				| INTEL_PTE_VALID
				| INTEL_PTE_USER
				| INTEL_PTE_WRITE);

	PMAP_READ_UNLOCK(map, spl);

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
	} else {
	  pdp = pmap_pde(map, vaddr);
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

	vm_object_lock(map->pm_obj);
#if 0 /* DEBUG */
	if (0 != vm_page_lookup(map->pm_obj, (vm_object_offset_t)i)) {
	  kprintf("pmap_expand: obj not empty, pmap 0x%x pm_obj 0x%x vaddr 0x%llx i 0x%llx\n",
		  map, map->pm_obj, vaddr, i);
	}
#endif
	vm_page_insert(m, map->pm_obj, (vm_object_offset_t)i);

	vm_page_lock_queues();
	vm_page_wire(m);
	inuse_ptepages_count++;

	vm_page_unlock_queues();
	vm_object_unlock(map->pm_obj);

	/*
	 *	Zero the page.
	 */
	pmap_zero_page(pn);

	PMAP_READ_LOCK(map, spl);
	/*
	 *	See if someone else expanded us first
	 */
	if (pmap_pte(map, vaddr) != PT_ENTRY_NULL) {
		PMAP_READ_UNLOCK(map, spl);
		vm_object_lock(map->pm_obj);

		vm_page_lock_queues();
		vm_page_free(m);
		inuse_ptepages_count--;

		vm_page_unlock_queues();
		vm_object_unlock(map->pm_obj);
		return;
	}

	pdp = pmap_pde(map, vaddr); /* refetch while locked */

	/*
	 *	Set the page directory entry for this page table.
	 *	If we have allocated more than one hardware page,
	 *	set several page directory entries.
	 */

	pmap_store_pte(pdp, pa_to_pte(pa)
				| INTEL_PTE_VALID
				| INTEL_PTE_USER
				| INTEL_PTE_WRITE);
	    

	PMAP_READ_UNLOCK(map, spl);

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
	spl_t                   spl;

	if (p == PMAP_NULL)
		return;

	if (p == kernel_pmap)
		return;

	/*
	 *	Garbage collect map.
	 */
	PMAP_READ_LOCK(p, spl);

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
		 
		    PMAP_READ_UNLOCK(p, spl);

		    /*
		     * And free the pte page itself.
		     */
		    {
			register vm_page_t m;

			vm_object_lock(p->pm_obj);
			m = vm_page_lookup(p->pm_obj,(vm_object_offset_t)(pdp - (pt_entry_t *)&p->dirbase[0]));
			if (m == VM_PAGE_NULL)
			    panic("pmap_collect: pte page not in object");
			vm_page_lock_queues();
			vm_page_free(m);
			inuse_ptepages_count--;
			vm_page_unlock_queues();
			vm_object_unlock(p->pm_obj);
		    }

		    PMAP_READ_LOCK(p, spl);
		}
	      }
	   }
	}
	PMAP_UPDATE_TLBS(p, VM_MIN_ADDRESS, VM_MAX_ADDRESS);

	PMAP_READ_UNLOCK(p, spl);
	return;

}


void
pmap_copy_page(src, dst)
	ppnum_t src;
	ppnum_t dst;
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
	ppnum_t	pn,
	int		bits)
{
	pv_entry_t		pv_h;
	register pv_entry_t	pv_e;
	register pt_entry_t	*pte;
	int			pai;
	register pmap_t		pmap;
	spl_t			spl;
	pmap_paddr_t            phys;

	assert(pn != vm_page_fictitious_addr);
	if (!valid_page(pn)) {
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
	phys = i386_ptob(pn);
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
		    register vm_map_offset_t va;

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
		 * Clear modify or reference bits.
		 */

			pmap_store_pte(pte, *pte & ~bits);
			pte++;
			PMAP_UPDATE_TLBS(pmap, va, va + PAGE_SIZE);
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
	ppnum_t	pn,
	int		bits)
{
	pv_entry_t		pv_h;
	register pv_entry_t	pv_e;
	register pt_entry_t	*pte;
	int			pai;
	register pmap_t		pmap;
	spl_t			spl;
	pmap_paddr_t            phys;

	assert(pn != vm_page_fictitious_addr);
	if (!valid_page(pn)) {
	    /*
	     *	Not a managed page.
	     */
	    return (FALSE);
	}

	phys = i386_ptob(pn);
	pai = pa_index(phys);
	/*
	 * super fast check...  if bits already collected
	 * no need to take any locks...
	 * if not set, we need to recheck after taking
	 * the lock in case they got pulled in while
	 * we were waiting for the lock
	 */
	if (pmap_phys_attributes[pai] & bits)
	    return (TRUE);
	pv_h = pai_to_pvh(pai);

	/*
	 *	Lock the pmap system first, since we will be checking
	 *	several pmaps.
	 */
	PMAP_WRITE_LOCK(spl);

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
		    register vm_map_offset_t va;

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
			if (*pte++ & bits) {
			    simple_unlock(&pmap->lock);
			    PMAP_WRITE_UNLOCK(spl);
			    return (TRUE);
			}
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
	ppnum_t	pn,
	int		bits)
{
	int			spl;
	pmap_paddr_t   phys;

	assert(pn != vm_page_fictitious_addr);
	if (!valid_page(pn)) {
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
	phys = i386_ptob(pn);
	PMAP_WRITE_LOCK(spl);
	pmap_phys_attributes[pa_index(phys)] |= bits;
	PMAP_WRITE_UNLOCK(spl);
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
	return (phys_attribute_test(pn, PHYS_MODIFIED));
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
	return (phys_attribute_test(pn, PHYS_REFERENCED));
}

/*
 * pmap_get_refmod(phys)
 *  returns the referenced and modified bits of the specified
 *  physical page.
 */
unsigned int
pmap_get_refmod(ppnum_t pa)
{
	return (   ((phys_attribute_test(pa,   PHYS_MODIFIED))?   VM_MEM_MODIFIED : 0)
			 | ((phys_attribute_test(pa, PHYS_REFERENCED))? VM_MEM_REFERENCED : 0));
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
	vm_map_offset_t	sva,
	vm_map_offset_t	eva)
{
	spl_t			spl;
	register pt_entry_t	*pde;
	register pt_entry_t	*spte, *epte;
	vm_map_offset_t		lva;
	vm_map_offset_t		orig_sva;

	if (map == PMAP_NULL)
		return;

	PMAP_READ_LOCK(map, spl);

	orig_sva = sva;
	while (sva && sva < eva) {
	    lva = (sva + pde_mapped_size) & ~(pde_mapped_size-1);
	    if (lva > eva)
		lva = eva;
	    pde = pmap_pde(map, sva);
	    if (pde && (*pde & INTEL_PTE_VALID)) {
	      spte = (pt_entry_t *)pmap_pte(map, (sva & ~(pde_mapped_size-1)));
		if (lva) {
		   spte = &spte[ptenum(sva)];
		   epte = &spte[intel_btop(lva-sva)];
	        } else {
		   epte = &spte[intel_btop(pde_mapped_size)];
		   spte = &spte[ptenum(sva)];
	        }
		while (spte < epte) {
		    if (*spte & INTEL_PTE_VALID) {
			pmap_store_pte(spte, *spte
						| INTEL_PTE_MOD
						| INTEL_PTE_WRITE);
		    }
		    spte++;
		}
	    }
	    sva = lva;
	    pde++;
	}
	PMAP_UPDATE_TLBS(map, orig_sva, eva);

	PMAP_READ_UNLOCK(map, spl);
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

#if	MACH_KDB

/* show phys page mappings and attributes */

extern void	db_show_page(pmap_paddr_t pa);

void
db_show_page(pmap_paddr_t pa)
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
		ptep = (pt_entry_t *) ((*pdep) & ~INTEL_OFFMASK);
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
	pmap_paddr_t     phys;

	assert(pn != vm_page_fictitious_addr);

	if (!pmap_initialized)
		return (TRUE);
	phys = (pmap_paddr_t) i386_ptob(pn);
	if (!pmap_valid_page(pn))
		return (FALSE);

	return TRUE;
}

void
mapping_free_prime()
{
	int             i;
	pv_entry_t      pv_e;

	for (i = 0; i < (5 * PV_ALLOC_CHUNK); i++) {
		pv_e = (pv_entry_t) zalloc(pv_list_zone);
		PV_FREE(pv_e);
	}
}

void
mapping_adjust()
{
	pv_entry_t      pv_e;
	int             i;
	int             spl;

	if (mapping_adjust_call == NULL) {
		thread_call_setup(&mapping_adjust_call_data,
				  (thread_call_func_t) mapping_adjust,
				  (thread_call_param_t) NULL);
		mapping_adjust_call = &mapping_adjust_call_data;
	}
	/* XXX  rethink best way to do locking here */
	if (pv_free_count < PV_LOW_WATER_MARK) {
		for (i = 0; i < PV_ALLOC_CHUNK; i++) {
			pv_e = (pv_entry_t) zalloc(pv_list_zone);
			SPLVM(spl);
			PV_FREE(pv_e);
			SPLX(spl);
		}
	}
	mappingrecurse = 0;
}

void
pmap_commpage32_init(vm_offset_t kernel_commpage, vm_offset_t user_commpage, int cnt)
{
  int i;
  pt_entry_t *opte, *npte;
  pt_entry_t pte;


  for (i = 0; i < cnt; i++) {
    opte = pmap_pte(kernel_pmap, (vm_map_offset_t)kernel_commpage);
    if (0 == opte) panic("kernel_commpage");
    pte = *opte | INTEL_PTE_USER|INTEL_PTE_GLOBAL;
    pte &= ~INTEL_PTE_WRITE; // ensure read only
    npte = pmap_pte(kernel_pmap, (vm_map_offset_t)user_commpage);
    if (0 == npte) panic("user_commpage");
    pmap_store_pte(npte, pte);
    kernel_commpage += INTEL_PGBYTES;
    user_commpage += INTEL_PGBYTES;
  }
}

#define PMAP_COMMPAGE64_CNT  (_COMM_PAGE64_AREA_USED/PAGE_SIZE)
pt_entry_t pmap_commpage64_ptes[PMAP_COMMPAGE64_CNT];

void
pmap_commpage64_init(vm_offset_t kernel_commpage, __unused vm_map_offset_t user_commpage, int cnt)
{
  spl_t s;
  int i;
  pt_entry_t *kptep;

  s = splhigh();
  for (i = 0; i< cnt; i++) {
    kptep = pmap_pte(kernel_pmap, (uint64_t)kernel_commpage + (i*PAGE_SIZE));
    if ((0 == kptep) || (0 == (*kptep & INTEL_PTE_VALID))) panic("pmap_commpage64_init pte");
    pmap_commpage64_ptes[i] = ((*kptep & ~INTEL_PTE_WRITE) | INTEL_PTE_USER);
  }
  splx(s);

}

void
pmap_map_sharedpage(__unused task_t task, pmap_t p)
{
  pt_entry_t *ptep;
  spl_t s;
  int i;

  if (!p->pm_64bit) return;
  /* setup high 64 bit commpage */
  s = splhigh();  
  while ((ptep = pmap_pte(p, (uint64_t)_COMM_PAGE64_BASE_ADDRESS)) == PD_ENTRY_NULL) {
    splx(s);
    pmap_expand(p, (uint64_t)_COMM_PAGE64_BASE_ADDRESS);
    s = splhigh();
  }

  for (i = 0; i< PMAP_COMMPAGE64_CNT; i++) {
    ptep = pmap_pte(p, (uint64_t)_COMM_PAGE64_BASE_ADDRESS + (i*PAGE_SIZE));
    if (0 == ptep) panic("pmap_map_sharedpage");
    pmap_store_pte(ptep, pmap_commpage64_ptes[i]);
  }
  splx(s);

}

void
pmap_unmap_sharedpage(pmap_t pmap)
{
  spl_t s;
  pt_entry_t *ptep;
  int i;

  if (!pmap->pm_64bit) return;
  s = splhigh();
  for (i = 0; i< PMAP_COMMPAGE64_CNT; i++) {
    ptep = pmap_pte(pmap, (uint64_t)_COMM_PAGE64_BASE_ADDRESS + (i*PAGE_SIZE));
  if (ptep) pmap_store_pte(ptep, 0);
  }
  splx(s);
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
			while ((pte = pmap_pte(kernel_pmap, (vm_map_offset_t)address)) == 0)
				pmap_expand(kernel_pmap, (vm_map_offset_t)address);
			* (int *) pte = 0; 
			cp->mapwindow[i].prv_CADDR = (caddr_t) address;
			cp->mapwindow[i].prv_CMAP = pte;
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
    boolean_t	istate;

    /*
     * can be called from hardware interrupt context
     * so we need to protect the lookup process
     */
    istate = ml_set_interrupts_enabled(FALSE);

    /*
     * Note: 0th map reserved for pmap_pte()
     */
    for (i = PMAP_NWINDOWS_FIRSTFREE; i < PMAP_NWINDOWS; i++) {
            mp = &current_cpu_datap()->cpu_pmap->mapwindow[i];

	    if (*mp->prv_CMAP == 0) {
	            *mp->prv_CMAP = pentry;
		    break;
	    }
    }
    if (i >= PMAP_NWINDOWS)
            mp = NULL;
    (void) ml_set_interrupts_enabled(istate);
    
    return (mp);
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
 *
 *      on x86 this is very limited right now.  must be exactly 1 segment.
 *
 *	Note that we depend upon higher level VM locks to insure that things don't change while
 *	we are doing this.  For example, VM should not be doing any pmap enters while it is nesting
 *	or do 2 nests at once.
 */


kern_return_t pmap_nest(pmap_t grand, pmap_t subord, addr64_t vstart, addr64_t nstart, uint64_t size) {
		
        vm_map_offset_t	vaddr, nvaddr;
	pd_entry_t	*pde,*npde;
	unsigned int	i, need_flush;
	unsigned int	num_pde;
	spl_t		s;

	// do validity tests

	if(size & 0x0FFFFFFFULL) return KERN_INVALID_VALUE;	/* We can only do this for multiples of 256MB */
	if((size >> 28) > 65536)  return KERN_INVALID_VALUE;	/* Max size we can nest is 16TB */
	if(vstart & 0x0FFFFFFFULL) return KERN_INVALID_VALUE;	/* We can only do this aligned to 256MB */
	if(nstart & 0x0FFFFFFFULL) return KERN_INVALID_VALUE;	/* We can only do this aligned to 256MB */
	if(size == 0) {	   
		panic("pmap_nest: size is invalid - %016llX\n", size);
	}
	if ((size >> 28) != 1) panic("pmap_nest: size 0x%llx must be 0x%x", size, NBPDE);

	// prepopulate subord pmap pde's if necessary

	if (cpu_64bit) {
	  s = splhigh();
	  while (PD_ENTRY_NULL == (npde = pmap_pde(subord, nstart))) {
	    splx(s);
	    pmap_expand(subord, nstart);
	    s = splhigh();
	  }
	  splx(s);
	}

	PMAP_READ_LOCK(subord,s);
	nvaddr = (vm_map_offset_t)nstart;
	need_flush = 0;
	num_pde = size >> PDESHIFT;

	for (i=0;i<num_pde;i++) {
	  npde = pmap_pde(subord, nvaddr);
	  if ((0 == npde) || (*npde++ & INTEL_PTE_VALID) == 0) {
	    PMAP_READ_UNLOCK(subord,s);
	    pmap_expand(subord, nvaddr); // pmap_expand handles races
	    PMAP_READ_LOCK(subord,s);
	    need_flush++;
	  }
	  nvaddr += NBPDE;
	}

	if (need_flush) {
	  nvaddr = (vm_map_offset_t)nstart;
	  PMAP_UPDATE_TLBS(subord, nvaddr, nvaddr + (1 << 28) -1 );
	}
	PMAP_READ_UNLOCK(subord,s);

	// copy pde's from subord pmap into grand pmap

	if (cpu_64bit) {
	  s = splhigh();
	  while (PD_ENTRY_NULL == (pde = pmap_pde(grand, vstart))) {
	    splx(s);
	    pmap_expand(grand, vstart);
	    s = splhigh();
	  }
	  splx(s);
	}

	PMAP_READ_LOCK(grand,s);
	vaddr = (vm_map_offset_t)vstart;
	for (i=0;i<num_pde;i++,pde++) {
	  pd_entry_t tpde;
	  npde = pmap_pde(subord, nstart);
	  if (npde == 0) panic("pmap_nest: no npde, subord 0x%x nstart 0x%llx", subord, nstart);
	  tpde = *npde;
	  nstart += NBPDE;
	  pde = pmap_pde(grand, vaddr);
	  if (pde == 0) panic("pmap_nest: no pde, grand  0x%x vaddr 0x%llx", grand, vaddr);
	  vaddr += NBPDE;
	  pmap_store_pte(pde, tpde);
	}
	PMAP_UPDATE_TLBS(grand, vaddr, vaddr + (1 << 28) -1 );

	PMAP_READ_UNLOCK(grand,s);

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
			
	spl_t s;
	pd_entry_t *pde;
	unsigned int i;
	unsigned int num_pde;

	PMAP_READ_LOCK(grand,s);

	// invalidate all pdes for segment at vaddr in pmap grand

	num_pde = (1<<28) >> PDESHIFT;

	for (i=0;i<num_pde;i++,pde++) {
	  pde = pmap_pde(grand, (vm_map_offset_t)vaddr);
	  if (pde == 0) panic("pmap_unnest: no pde, grand 0x%x vaddr 0x%llx\n", grand, vaddr);
	  pmap_store_pte(pde, (pd_entry_t)0);
	  vaddr += NBPDE;
	}
	PMAP_UPDATE_TLBS(grand, vaddr, vaddr + (1<<28) -1 );

	PMAP_READ_UNLOCK(grand,s);
		
	return KERN_SUCCESS;								/* Bye, bye, butterfly... */
}

void
pmap_switch(pmap_t tpmap)
{
        spl_t	s;
  	int	my_cpu;

	s = splhigh();		/* Make sure interruptions are disabled */
	my_cpu = cpu_number();

	set_dirbase(tpmap, my_cpu);

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
  *(pte_unique_base + a) = pte;

  /* TLB flush for this page for this  cpu */
  invlpg((uintptr_t)vaddr);

  return  vaddr;
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

	assert(!ml_get_interrupts_enabled());

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
		if ((cpu_datap(cpu)->cpu_task_cr3   == pmap_cr3) ||
		    (cpu_datap(cpu)->cpu_active_cr3 == pmap_cr3) ||
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

	if (cpus_to_signal) {
	        KERNEL_DEBUG(0xef800024 | DBG_FUNC_START, cpus_to_signal, 0, 0, 0, 0);

		deadline = mach_absolute_time() + LockTimeOut;
		/*
		 * Wait for those other cpus to acknowledge
		 */
		for (cpu = 0, cpu_bit = 1; cpu < real_ncpus; cpu++, cpu_bit <<= 1) {
			while ((cpus_to_signal & cpu_bit) != 0) {
			        if (!cpu_datap(cpu)->cpu_running ||
				    cpu_datap(cpu)->cpu_tlb_invalid == FALSE ||
				    !CPU_CR3_IS_ACTIVE(cpu)) {
				        cpus_to_signal &= ~cpu_bit;
					break;
				}
				if (mach_absolute_time() > deadline)
				        panic("pmap_flush_tlbs() "
					      "timeout pmap=%p cpus_to_signal=%p",
					      pmap, cpus_to_signal);
				cpu_pause();
			}
		        if (cpus_to_signal == 0)
			        break;
		}
	        KERNEL_DEBUG(0xef800024 | DBG_FUNC_END, cpus_to_signal, 0, 0, 0, 0);
	}

	/*
	 * Flush local tlb if required.
	 * We need this flush even if the pmap being changed
	 * is the user map... in case we do a copyin/out
	 * before returning to user mode.
	 */
	if (flush_self)
		flush_tlb();

}

void
process_pmap_updates(void)
{
	flush_tlb();

	current_cpu_datap()->cpu_tlb_invalid = FALSE;
	__asm__ volatile("mfence");
}

void
pmap_update_interrupt(void)
{
        KERNEL_DEBUG(0xef800028 | DBG_FUNC_START, 0, 0, 0, 0, 0);

	assert(!ml_get_interrupts_enabled());

	process_pmap_updates();

        KERNEL_DEBUG(0xef800028 | DBG_FUNC_END, 0, 0, 0, 0, 0);
}


unsigned int pmap_cache_attributes(ppnum_t pn) {

	if (!pmap_valid_page(pn))
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

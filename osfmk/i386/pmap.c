/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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

#if	MACH_KDB
#include <ddb/db_command.h>
#include <ddb/db_output.h>
#include <ddb/db_sym.h>
#include <ddb/db_print.h>
#endif	/* MACH_KDB */

#include <kern/xpr.h>

#include <vm/vm_protos.h>

#include <i386/mp.h>

/*
 * Forward declarations for internal functions.
 */
void		pmap_expand(
			pmap_t		map,
			vm_offset_t	v);

extern void	pmap_remove_range(
			pmap_t		pmap,
			vm_offset_t	va,
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

void		pmap_growkernel(
			vm_offset_t addr);

void		pmap_set_reference(
			ppnum_t pn);

void		pmap_movepage(
			unsigned long	from,
			unsigned long	to,
			vm_size_t	size);

pt_entry_t *	pmap_mapgetpte(
			vm_map_t	map,
			vm_offset_t	v);

boolean_t	phys_page_exists(
			ppnum_t pn);

#ifndef	set_dirbase
void		set_dirbase(vm_offset_t	dirbase);
#endif	/* set_dirbase */

#define	iswired(pte)	((pte) & INTEL_PTE_WIRED)

#define	WRITE_PTE(pte_p, pte_entry)		*(pte_p) = (pte_entry);
#define	WRITE_PTE_FAST(pte_p, pte_entry)	*(pte_p) = (pte_entry);

#define value_64bit(value)  ((value) & 0xFFFFFFFF00000000LL)
#define low32(x) ((unsigned int)((x) & 0x00000000ffffffffLL))

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
              if (hw_compare_and_store(0,1,&mappingrecurse)) \
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

#ifdef PAE
static zone_t pdpt_zone;
#endif


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

pmap_paddr_t    kernel_vm_end = (pmap_paddr_t)0;

#define GROW_KERNEL_FUNCTION_IMPLEMENTED 1
#if GROW_KERNEL_FUNCTION_IMPLEMENTED  /* not needed until growing kernel pmap */
static struct vm_object kptobj_object_store;
static vm_object_t kptobj;
#endif


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
	    	kprintf("%s: cpu %d pmap %x, cpus_active 0x%x\n",	\
			  msg, cpu_number(), pmap, cpus_active);	\
            	Debugger("deadlock detection");				\
		mp_enable_preemption();					\
		loop_count = max_lock_loops;				\
	}
#else	/* USLOCK_DEBUG */
#define LOOP_VAR
#define LOOP_CHECK(msg, pmap)
#endif	/* USLOCK_DEBUG */

#define PMAP_UPDATE_TLBS(pmap, s, e)					\
{									\
	cpu_set	cpu_mask;						\
	cpu_set	users;							\
									\
	mp_disable_preemption();					\
	cpu_mask = 1 << cpu_number();					\
									\
	/* Since the pmap is locked, other updates are locked */ 	\
	/* out, and any pmap_activate has finished. */ 			\
 									\
	/* find other cpus using the pmap */ 				\
	users = (pmap)->cpus_using & ~cpu_mask;        			\
	if (users) { 							\
            LOOP_VAR;							\
	    /* signal them, and wait for them to finish */ 		\
	    /* using the pmap */ 					\
	    signal_cpus(users, (pmap), (s), (e));      			\
	    while (((pmap)->cpus_using & cpus_active & ~cpu_mask)) {	\
		LOOP_CHECK("PMAP_UPDATE_TLBS", pmap);			\
		cpu_pause(); 						\
	    }								\
	} 								\
	/* invalidate our own TLB if pmap is in use */ 			\
 									\
	if ((pmap)->cpus_using & cpu_mask) {   				\
	    INVALIDATE_TLB((pmap), (s), (e));				\
	} 								\
									\
	mp_enable_preemption();						\
}

#define MAX_TBIS_SIZE	32		/* > this -> TBIA */ /* XXX */

#define INVALIDATE_TLB(m, s, e) {	\
	flush_tlb(); 			\
}

/*
 *	Structures to keep track of pending TLB invalidations
 */
cpu_set			cpus_active;
cpu_set			cpus_idle;

#define UPDATE_LIST_SIZE	4

struct pmap_update_item {
	pmap_t		pmap;		/* pmap to invalidate */
	vm_offset_t	start;		/* start address to invalidate */
	vm_offset_t	end;		/* end address to invalidate */
};

typedef	struct pmap_update_item	*pmap_update_item_t;

/*
 *	List of pmap updates.  If the list overflows,
 *	the last entry is changed to invalidate all.
 */
struct pmap_update_list {
	decl_simple_lock_data(,lock)
	int			count;
	struct pmap_update_item	item[UPDATE_LIST_SIZE];
} ;
typedef	struct pmap_update_list	*pmap_update_list_t;

extern void signal_cpus(
			cpu_set		use_list,
			pmap_t		pmap,
			vm_offset_t	start,
			vm_offset_t	end);

pmap_memory_region_t pmap_memory_regions[PMAP_MEMORY_REGIONS_SIZE];

/*
 *	Other useful macros.
 */
#define current_pmap()		(vm_map_pmap(current_thread()->map))
#define pmap_in_use(pmap, cpu)	(((pmap)->cpus_using & (1 << (cpu))) != 0)

struct pmap	kernel_pmap_store;
pmap_t		kernel_pmap;

#ifdef PMAP_QUEUE
decl_simple_lock_data(,free_pmap_lock)
#endif

struct zone	*pmap_zone;		/* zone of pmap structures */

int		pmap_debug = 0;		/* flag for debugging prints */

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

static int nkpt;

pt_entry_t     *DMAP1, *DMAP2;
caddr_t         DADDR1;
caddr_t         DADDR2;

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

#define	pmap_pde(m, v)	(&((m)->dirbase[(vm_offset_t)(v) >> PDESHIFT]))
#define pdir_pde(d, v) (d[(vm_offset_t)(v) >> PDESHIFT])

static __inline int
pmap_is_current(pmap_t pmap)
{
  return (pmap == kernel_pmap ||
	  (pmap->dirbase[PTDPTDI] & PG_FRAME) == (PTDpde[0] & PG_FRAME));
}


/*
 * return address of mapped pte for vaddr va in pmap pmap.
 */
pt_entry_t     *
pmap_pte(pmap_t pmap, vm_offset_t va)
{
  pd_entry_t     *pde;
  pd_entry_t     newpf;

  pde = pmap_pde(pmap, va);
  if (*pde != 0) {
    if (pmap_is_current(pmap))
      return( vtopte(va));
    newpf = *pde & PG_FRAME;
    if (((*CM4) & PG_FRAME) != newpf) {
      *CM4 = newpf | INTEL_PTE_RW | INTEL_PTE_VALID;
      invlpg((u_int)CA4);
    }
    return (pt_entry_t *)CA4 + (i386_btop(va) & (NPTEPG-1));
  }
  return(0);
}
	
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
		pte++;
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
	register vm_offset_t	start_addr,
	register vm_offset_t	end_addr,
	register vm_prot_t	prot)
{
	register int		ps;

	ps = PAGE_SIZE;
	while (start_addr < end_addr) {
		pmap_enter(kernel_pmap,
			virt, (ppnum_t) i386_btop(start_addr), prot, 0, FALSE);
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
	register vm_offset_t	virt,
	register vm_offset_t	start_addr,
	register vm_offset_t	end_addr,
	vm_prot_t		prot)
{
	register pt_entry_t	template;
	register pt_entry_t	*pte;

	template = pa_to_pte(start_addr)
		| INTEL_PTE_NCACHE
		| INTEL_PTE_REF
		| INTEL_PTE_MOD
		| INTEL_PTE_WIRED
		| INTEL_PTE_VALID;
	if (prot & VM_PROT_WRITE)
	    template |= INTEL_PTE_WRITE;

	/* XXX move pmap_pte out of loop, once one pte mapped, all are */
	while (start_addr < end_addr) {
		pte = pmap_pte(kernel_pmap, virt);
		if (pte == PT_ENTRY_NULL) {
			panic("pmap_map_bd: Invalid kernel address\n");
		}
		WRITE_PTE_FAST(pte, template)
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
	__unused vm_offset_t	load_start)
{
	vm_offset_t	va;
	pt_entry_t	*pte;
	int i;
	int wpkernel, boot_arg;

	vm_last_addr = VM_MAX_KERNEL_ADDRESS;	/* Set the highest address
						 * known to VM */

	/*
	 *	The kernel's pmap is statically allocated so we don't
	 *	have to use pmap_create, which is unlikely to work
	 *	correctly at this part of the boot sequence.
	 */

	kernel_pmap = &kernel_pmap_store;
#ifdef PMAP_QUEUE
	kernel_pmap->pmap_link.next = (queue_t)kernel_pmap;		/* Set up anchor forward */
	kernel_pmap->pmap_link.prev = (queue_t)kernel_pmap;		/* Set up anchor reverse */
#endif
	kernel_pmap->ref_count = 1;
	kernel_pmap->pm_obj = (vm_object_t) NULL;
	kernel_pmap->dirbase = (pd_entry_t *)((unsigned int)IdlePTD | KERNBASE);
	kernel_pmap->pdirbase = (pd_entry_t *)IdlePTD;
#ifdef PAE
	kernel_pmap->pm_pdpt = (pd_entry_t *)((unsigned int)IdlePDPT | KERNBASE );
	kernel_pmap->pm_ppdpt = (vm_offset_t)IdlePDPT;
#endif

	va = (vm_offset_t)kernel_pmap->dirbase;
	/* setup self referential mapping(s) */
	for (i = 0; i< NPGPTD; i++ ) {
	  pmap_paddr_t pa;
	  pa = (pmap_paddr_t) kvtophys(va + i386_ptob(i));
	  * (pd_entry_t *) (kernel_pmap->dirbase + PTDPTDI + i) = 
	    (pa & PG_FRAME) | INTEL_PTE_VALID | INTEL_PTE_RW | INTEL_PTE_REF |
	    INTEL_PTE_MOD | INTEL_PTE_WIRED ;
#ifdef PAE
	  kernel_pmap->pm_pdpt[i] = pa | INTEL_PTE_VALID;
#endif
	}

	nkpt = NKPT;

	virtual_avail = (vm_offset_t)VADDR(KPTDI,0) + (vm_offset_t)first_avail;
	virtual_end = (vm_offset_t)(VM_MAX_KERNEL_ADDRESS);

	/*
	 * Reserve some special page table entries/VA space for temporary
	 * mapping of pages.
	 */
#define	SYSMAP(c, p, v, n)	\
	v = (c)va; va += ((n)*INTEL_PGBYTES); p = pte; pte += (n);

	va = virtual_avail;
	pte = (pt_entry_t *) pmap_pte(kernel_pmap, va);

	/*
	 * CMAP1/CMAP2 are used for zeroing and copying pages.
         * CMAP3 is used for ml_phys_read/write.
	 */
	SYSMAP(caddr_t, CM1, CA1, 1)
	* (pt_entry_t *) CM1 = 0;
	SYSMAP(caddr_t, CM2, CA2, 1)
	* (pt_entry_t *) CM2 = 0;
	SYSMAP(caddr_t, CM3, CA3, 1)
	* (pt_entry_t *) CM3 = 0;

	/* used by pmap_pte */
	SYSMAP(caddr_t, CM4, CA4, 1)
	  * (pt_entry_t *) CM4 = 0;

	/* DMAP user for debugger */
	SYSMAP(caddr_t, DMAP1, DADDR1, 1);
	SYSMAP(caddr_t, DMAP2, DADDR2, 1);  /* XXX temporary - can remove */


	lock_init(&pmap_system_lock,
		  FALSE,		/* NOT a sleep lock */
		  0, 0);

	virtual_avail = va;

	wpkernel = 1;
	if (PE_parse_boot_arg("debug", &boot_arg)) {
	  if (boot_arg & DB_PRT) wpkernel = 0;
	  if (boot_arg & DB_NMI) wpkernel = 0;
	}

	/* remap kernel text readonly if not debugging or kprintfing */
	if (wpkernel)
	{
		vm_offset_t     myva;
		pt_entry_t     *ptep;

		for (myva = i386_round_page(VM_MIN_KERNEL_ADDRESS + MP_BOOT + MP_BOOTSTACK); myva < etext; myva += PAGE_SIZE) {
                        if (myva >= (vm_offset_t)sectHIBB && myva < ((vm_offset_t)sectHIBB + sectSizeHIB))
                                continue;
			ptep = pmap_pte(kernel_pmap, myva);
			if (ptep)
				*ptep &= ~INTEL_PTE_RW;
		}
		flush_tlb();
	}

	simple_lock_init(&kernel_pmap->lock, 0);
	simple_lock_init(&pv_free_list_lock, 0);

	/* invalidate user virtual addresses */
	memset((char *)kernel_pmap->dirbase,
	       0,
	       (KPTDI) * sizeof(pd_entry_t));

	kprintf("Kernel virtual space from 0x%x to 0x%x.\n",
			VADDR(KPTDI,0), virtual_end);
#ifdef PAE
	kprintf("Available physical space from 0x%llx to 0x%llx\n",
			avail_start, avail_end);
	printf("PAE enabled\n");
#else
	kprintf("Available physical space from 0x%x to 0x%x\n",
			avail_start, avail_end);
#endif
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
	vm_offset_t vaddr;
	ppnum_t ppn;

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
#ifdef PAE
	//	s = (vm_size_t) (sizeof(pdpt_entry_t) * NPGPTD);
	s = 63;
	pdpt_zone = zinit(s, 400*s, 4096, "pdpt"); /* XXX */
#endif

	/*
	 *	Only now, when all of the data structures are allocated,
	 *	can we set vm_first_phys and vm_last_phys.  If we set them
	 *	too soon, the kmem_alloc_wired above will try to use these
	 *	data structures and blow up.
	 */

	/* zero bias this now so we cover all memory */
	vm_first_phys = 0;
	vm_last_phys = avail_end;

#if GROW_KERNEL_FUNCTION_IMPLEMENTED
	kptobj = &kptobj_object_store;
	_vm_object_allocate((vm_object_size_t)NKPDE, kptobj);
	kernel_pmap->pm_obj = kptobj;
#endif

	/* create pv entries for kernel pages mapped by low level
	   startup code.  these have to exist so we can pmap_remove()
	   e.g. kext pages from the middle of our addr space */

	vaddr = (vm_offset_t)VM_MIN_KERNEL_ADDRESS;
	for (ppn = 0; ppn < i386_btop(avail_start) ; ppn++ ) {
	  pv_entry_t	pv_e;

	  pv_e = pai_to_pvh(ppn);
	  pv_e->va = vaddr;
	  vaddr += PAGE_SIZE;
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
#ifdef PMAP_QUEUE
	simple_lock_init(&free_pmap_lock, 0);
#endif

}

void
x86_lowmem_free(void)
{
	/* free lowmem pages back to the vm system. we had to defer doing this
	   until the vm system was fully up.
	   the actual pages that are released are determined by which
	   pages the memory sizing code puts into the region table */

	ml_static_mfree((vm_offset_t) i386_ptob(pmap_memory_regions[0].base)|VM_MIN_KERNEL_ADDRESS,
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
	vm_size_t	size)
{
  register pmap_t			p;
#ifdef PMAP_QUEUE
  register pmap_t pro;
  spl_t s;
#endif
	register int i;
	register vm_offset_t va;

	/*
	 *	A software use-only map doesn't even need a map.
	 */

	if (size != 0) {
		return(PMAP_NULL);
	}

	p = (pmap_t) zalloc(pmap_zone);
	if (PMAP_NULL == p)
	  panic("pmap_create zalloc");
	if (KERN_SUCCESS != kmem_alloc_wired(kernel_map, (vm_offset_t *)(&p->dirbase), NBPTD))
	  panic("pmap_create kmem_alloc_wired");
#ifdef PAE
	p->pm_hold = (vm_offset_t)zalloc(pdpt_zone);
	if ((vm_offset_t)NULL == p->pm_hold) {
	  panic("pdpt zalloc");
	}
	p->pm_pdpt = (pdpt_entry_t *) (( p->pm_hold + 31) & ~31);
	p->pm_ppdpt = kvtophys((vm_offset_t)p->pm_pdpt);  /* XXX */
#endif
	if (NULL == (p->pm_obj = vm_object_allocate((vm_object_size_t)(NPGPTD*NPDEPG))))
	  panic("pmap_create vm_object_allocate");
	memcpy(p->dirbase, 
	       (void *)((unsigned int)IdlePTD | KERNBASE),
	       NBPTD);
	va = (vm_offset_t)p->dirbase;
	p->pdirbase = (pd_entry_t *)(kvtophys(va));
	simple_lock_init(&p->lock, 0);

	/* setup self referential mapping(s) */
	for (i = 0; i< NPGPTD; i++ ) {
	  pmap_paddr_t pa;
	  pa = (pmap_paddr_t) kvtophys(va + i386_ptob(i));
	  * (pd_entry_t *) (p->dirbase + PTDPTDI + i) = 
	    (pa & PG_FRAME) | INTEL_PTE_VALID | INTEL_PTE_RW | INTEL_PTE_REF |
	    INTEL_PTE_MOD | INTEL_PTE_WIRED ;
#ifdef PAE
	  p->pm_pdpt[i] = pa | INTEL_PTE_VALID;
#endif
	}

	p->cpus_using = 0;
	p->stats.resident_count = 0;
	p->stats.wired_count = 0;
	p->ref_count = 1;

#ifdef PMAP_QUEUE
	/* insert new pmap at head of queue hanging off kernel_pmap */
	SPLVM(s);
	simple_lock(&free_pmap_lock);
	p->pmap_link.next = (queue_t)kernel_pmap->pmap_link.next;
	kernel_pmap->pmap_link.next = (queue_t)p;

	pro = (pmap_t) p->pmap_link.next;
	p->pmap_link.prev = (queue_t)pro->pmap_link.prev;
	pro->pmap_link.prev = (queue_t)p;

	
	simple_unlock(&free_pmap_lock);
	SPLX(s);
#endif

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
	register int		c;
	spl_t                   s;
	register vm_page_t	m;
#ifdef PMAP_QUEUE
	register pmap_t        pre,pro;
#endif

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
		/* force pmap/cr3 update */
		PMAP_UPDATE_TLBS(p,
				 VM_MIN_ADDRESS,
				 VM_MAX_KERNEL_ADDRESS);

		if (PMAP_REAL(my_cpu) == p) {
			PMAP_CPU_CLR(p, my_cpu);
			PMAP_REAL(my_cpu) = kernel_pmap;
#ifdef PAE
			set_cr3((unsigned int)kernel_pmap->pm_ppdpt);
#else
			set_cr3((unsigned int)kernel_pmap->pdirbase);
#endif
		}
		mp_enable_preemption();
	}
	simple_unlock(&p->lock);
	SPLX(s);

	if (c != 0) {
	    return;	/* still in use */
	}

#ifdef PMAP_QUEUE
	/* remove from pmap queue */
	SPLVM(s);
	simple_lock(&free_pmap_lock);

	pre = (pmap_t)p->pmap_link.prev;
	pre->pmap_link.next = (queue_t)p->pmap_link.next;
	pro = (pmap_t)p->pmap_link.next;
	pro->pmap_link.prev = (queue_t)p->pmap_link.prev;

	simple_unlock(&free_pmap_lock);
	SPLX(s);
#endif

	/*
	 *	Free the memory maps, then the
	 *	pmap structure.
	 */

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
		*pdep++ = 0;
	    }
	    else {
	      *pdep++ = 0;
	    }
	
	}

	vm_object_deallocate(p->pm_obj);
	kmem_free(kernel_map, (vm_offset_t)p->dirbase, NBPTD);
#ifdef PAE
	zfree(pdpt_zone, (void *)p->pm_hold);
#endif
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
	pmap_paddr_t		pa;

#if	DEBUG_PTE_PAGE
	if (pmap != kernel_pmap)
		ptep_check(get_pte_page(spte));
#endif	/* DEBUG_PTE_PAGE */
	num_removed = 0;
	num_unwired = 0;

	for (cpte = spte; cpte < epte;
	     cpte++, va += PAGE_SIZE) {

	    pa = pte_to_pa(*cpte);
	    if (pa == 0)
		continue;

	    num_removed++;
	    if (iswired(*cpte))
		num_unwired++;

	    if (!valid_page(i386_btop(pa))) {

		/*
		 *	Outside range of managed physical memory.
		 *	Just remove the mappings.
		 */
		register pt_entry_t	*lpte = cpte;

		*lpte = 0;
		continue;
	    }

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
		    *lpte = 0;

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
	vm_offset_t		l;
	vm_offset_t    s, e;
	vm_offset_t    orig_s;

	if (map == PMAP_NULL)
		return;

	PMAP_READ_LOCK(map, spl);

	if (value_64bit(s64) || value_64bit(e64)) {
	  panic("pmap_remove addr overflow");
	}

	orig_s = s = (vm_offset_t)low32(s64);
	e = (vm_offset_t)low32(e64);

	pde = pmap_pde(map, s);

	while (s < e) {
	    l = (s + PDE_MAPPED_SIZE) & ~(PDE_MAPPED_SIZE-1);
	    if (l > e)
		l = e;
	    if (*pde & INTEL_PTE_VALID) {
	      spte = (pt_entry_t *)pmap_pte(map, (s & ~(PDE_MAPPED_SIZE-1)));
		spte = &spte[ptenum(s)];
		epte = &spte[intel_btop(l-s)];
		pmap_remove_range(map, s, spte, epte);
	    }
	    s = l;
	    pde++;
	}

	PMAP_UPDATE_TLBS(map, orig_s, e);

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
	pmap_paddr_t             phys;

	assert(pn != vm_page_fictitious_addr);
	phys = (pmap_paddr_t)i386_ptob(pn);
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
	      register vm_offset_t va;
		pmap = pv_e->pmap;
		/*
		 * Lock the pmap to block pmap_extract and similar routines.
		 */
		simple_lock(&pmap->lock);

		{

		    va = pv_e->va;
		    pte = pmap_pte(pmap, va);

		    /*
		     * Consistency checks.
		     */
		    /* assert(*pte & INTEL_PTE_VALID); XXX */
		    /* assert(pte_to_phys(*pte) == phys); */

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
			    pmap_phys_attributes[pai] |=
				*pte & (PHYS_MODIFIED|PHYS_REFERENCED);
			    *pte++ = 0;
			    PMAP_UPDATE_TLBS(pmap, va, va + PAGE_SIZE);
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

			*pte &= ~INTEL_PTE_WRITE;
			pte++;
			PMAP_UPDATE_TLBS(pmap, va, va + PAGE_SIZE);
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
	vm_offset_t	s,
	vm_offset_t	e,
	vm_prot_t	prot)
{
	register pt_entry_t	*pde;
	register pt_entry_t	*spte, *epte;
	vm_offset_t		l;
	spl_t		spl;
	vm_offset_t    orig_s = s;


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
		pmap_remove(map, (addr64_t)s, (addr64_t)e);
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
	      spte = (pt_entry_t *)pmap_pte(map, (s & ~(PDE_MAPPED_SIZE-1)));
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

	PMAP_UPDATE_TLBS(map, orig_s, e);

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
	pmap_paddr_t             pa = (pmap_paddr_t)i386_ptob(pn);

	XPR(0x80000000, "%x/%x: pmap_enter %x/%x/%x\n",
	    current_thread(),
	    current_thread(), 
	    pmap, v, pn);

	assert(pn != vm_page_fictitious_addr);
	if (pmap_debug)
		printf("pmap(%x, %x)\n", v, pn);
	if (pmap == PMAP_NULL)
		return;

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

		if (*pte & INTEL_PTE_MOD)
		    template |= INTEL_PTE_MOD;
		WRITE_PTE(pte, template)
		  pte++;

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

	if (old_pa != (pmap_paddr_t) 0) {


#if	DEBUG_PTE_PAGE
	    if (pmap != kernel_pmap)
		ptep_check(get_pte_page(pte));
#endif	/* DEBUG_PTE_PAGE */

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
		    WRITE_PTE(pte, 0)

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
		old_pa = (pmap_paddr_t) 0;
		assert(pmap->stats.resident_count >= 1);
		pmap->stats.resident_count--;
		if (iswired(*pte)) {
		    assert(pmap->stats.wired_count >= 1);
		    pmap->stats.wired_count--;
		}
	    }
        
	}

	if (valid_page(i386_btop(pa))) {

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
		      panic("pmap no pv_e's");
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

	 WRITE_PTE(pte, template)

Done:
	 PMAP_UPDATE_TLBS(pmap, v, v + PAGE_SIZE);

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
	spl_t			spl;

#if 1
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
	    *pte++ |= INTEL_PTE_WIRED;
	}
	else if (!wired && iswired(*pte)) {
	    /*
	     *	unwiring mapping
	     */
	    assert(map->stats.wired_count >= 1);
	    map->stats.wired_count--;
	    *pte++ &= ~INTEL_PTE_WIRED;
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
	vm_offset_t     a32;
	ppnum_t         ppn;

	if (value_64bit(va))
		panic("pmap_find_phys 64 bit value");
	a32 = (vm_offset_t) low32(va);
	ptp = pmap_pte(pmap, a32);
	if (PT_ENTRY_NULL == ptp) {
		ppn = 0;
	} else {
		ppn = (ppnum_t) i386_btop(pte_to_pa(*ptp));
	}
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
	vm_offset_t	va)
{
  ppnum_t ppn;
  vm_offset_t vaddr;

  vaddr = (vm_offset_t)0;
  ppn = pmap_find_phys(pmap, (addr64_t)va);
  if (ppn) {
    vaddr = ((vm_offset_t)i386_ptob(ppn)) | (va & INTEL_OFFMASK);
  }
  return (vaddr);
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
	register pmap_paddr_t	pa;
	register int		i;
	spl_t			spl;
	ppnum_t                 pn;

	if (map == kernel_pmap) {
	  pmap_growkernel(v);
	  return;
	}

	/*
	 *	Allocate a VM page for the level 2 page table entries.
	 */
	while ((m = vm_page_grab()) == VM_PAGE_NULL)
		VM_PAGE_WAIT();

	/*
	 *	put the page into the pmap's obj list so it
	 *	can be found later.
	 */
	pn = m->phys_page;
	pa = i386_ptob(pn);
	i = pdenum(map, v);
	vm_object_lock(map->pm_obj);
	vm_page_insert(m, map->pm_obj, (vm_object_offset_t)i);
	vm_page_lock_queues();
	vm_page_wire(m);
	inuse_ptepages_count++;
	vm_object_unlock(map->pm_obj);
	vm_page_unlock_queues();

	/*
	 *	Zero the page.
	 */
	pmap_zero_page(pn);

	PMAP_READ_LOCK(map, spl);
	/*
	 *	See if someone else expanded us first
	 */
	if (pmap_pte(map, v) != PT_ENTRY_NULL) {
		PMAP_READ_UNLOCK(map, spl);
		vm_object_lock(map->pm_obj);
		vm_page_lock_queues();
		vm_page_free(m);
		inuse_ptepages_count--;
		vm_page_unlock_queues();
		vm_object_unlock(map->pm_obj);
		return;
	}

	/*
	 *	Set the page directory entry for this page table.
	 *	If we have allocated more than one hardware page,
	 *	set several page directory entries.
	 */

	pdp = &map->dirbase[pdenum(map, v)];
	    *pdp = pa_to_pte(pa)
		| INTEL_PTE_VALID
		| INTEL_PTE_USER
		| INTEL_PTE_WRITE;

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
		*pdp &= ~INTEL_PTE_REF;
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
		    *pdp = 0x0;
		 
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
	__unused vm_offset_t	start_addr,
	__unused vm_offset_t	end_addr,
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
		 * Clear modify or reference bits.
		 */

			*pte++ &= ~bits;
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

	/*
	 *	Lock the pmap system first, since we will be checking
	 *	several pmaps.
	 */

	PMAP_WRITE_LOCK(spl);
	phys = i386_ptob(pn);
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
	vm_offset_t	s,
	vm_offset_t	e)
{
	spl_t			spl;
	register pt_entry_t	*pde;
	register pt_entry_t	*spte, *epte;
	vm_offset_t		l;
	vm_offset_t             orig_s = s;

	if (map == PMAP_NULL)
		return;

	PMAP_READ_LOCK(map, spl);

	pde = pmap_pde(map, s);
	while (s && s < e) {
	    l = (s + PDE_MAPPED_SIZE) & ~(PDE_MAPPED_SIZE-1);
	    if (l > e)
		l = e;
	    if (*pde & INTEL_PTE_VALID) {
	      spte = (pt_entry_t *)pmap_pte(map, (s & ~(PDE_MAPPED_SIZE-1)));
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
	PMAP_UPDATE_TLBS(map, orig_s, e);
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

/*
*	    TLB Coherence Code (TLB "shootdown" code)
* 
* Threads that belong to the same task share the same address space and
* hence share a pmap.  However, they  may run on distinct cpus and thus
* have distinct TLBs that cache page table entries. In order to guarantee
* the TLBs are consistent, whenever a pmap is changed, all threads that
* are active in that pmap must have their TLB updated. To keep track of
* this information, the set of cpus that are currently using a pmap is
* maintained within each pmap structure (cpus_using). Pmap_activate() and
* pmap_deactivate add and remove, respectively, a cpu from this set.
* Since the TLBs are not addressable over the bus, each processor must
* flush its own TLB; a processor that needs to invalidate another TLB
* needs to interrupt the processor that owns that TLB to signal the
* update.
* 
* Whenever a pmap is updated, the lock on that pmap is locked, and all
* cpus using the pmap are signaled to invalidate. All threads that need
* to activate a pmap must wait for the lock to clear to await any updates
* in progress before using the pmap. They must ACQUIRE the lock to add
* their cpu to the cpus_using set. An implicit assumption made
* throughout the TLB code is that all kernel code that runs at or higher
* than splvm blocks out update interrupts, and that such code does not
* touch pageable pages.
* 
* A shootdown interrupt serves another function besides signaling a
* processor to invalidate. The interrupt routine (pmap_update_interrupt)
* waits for the both the pmap lock (and the kernel pmap lock) to clear,
* preventing user code from making implicit pmap updates while the
* sending processor is performing its update. (This could happen via a
* user data write reference that turns on the modify bit in the page
* table). It must wait for any kernel updates that may have started
* concurrently with a user pmap update because the IPC code
* changes mappings.
* Spinning on the VALUES of the locks is sufficient (rather than
* having to acquire the locks) because any updates that occur subsequent
* to finding the lock unlocked will be signaled via another interrupt.
* (This assumes the interrupt is cleared before the low level interrupt code 
* calls pmap_update_interrupt()). 
* 
* The signaling processor must wait for any implicit updates in progress
* to terminate before continuing with its update. Thus it must wait for an
* acknowledgement of the interrupt from each processor for which such
* references could be made. For maintaining this information, a set
* cpus_active is used. A cpu is in this set if and only if it can 
* use a pmap. When pmap_update_interrupt() is entered, a cpu is removed from
* this set; when all such cpus are removed, it is safe to update.
* 
* Before attempting to acquire the update lock on a pmap, a cpu (A) must
* be at least at the priority of the interprocessor interrupt
* (splip<=splvm). Otherwise, A could grab a lock and be interrupted by a
* kernel update; it would spin forever in pmap_update_interrupt() trying
* to acquire the user pmap lock it had already acquired. Furthermore A
* must remove itself from cpus_active.  Otherwise, another cpu holding
* the lock (B) could be in the process of sending an update signal to A,
* and thus be waiting for A to remove itself from cpus_active. If A is
* spinning on the lock at priority this will never happen and a deadlock
* will result.
*/

/*
 *	Signal another CPU that it must flush its TLB
 */
void
signal_cpus(
	cpu_set		use_list,
	pmap_t		pmap,
	vm_offset_t	start_addr,
	vm_offset_t	end_addr)
{
	register int		which_cpu, j;
	register pmap_update_list_t	update_list_p;

	while ((which_cpu = ffs((unsigned long)use_list)) != 0) {
	    which_cpu -= 1;	/* convert to 0 origin */

	    update_list_p = cpu_update_list(which_cpu);
	    simple_lock(&update_list_p->lock);

	    j = update_list_p->count;
	    if (j >= UPDATE_LIST_SIZE) {
		/*
		 *	list overflowed.  Change last item to
		 *	indicate overflow.
		 */
		update_list_p->item[UPDATE_LIST_SIZE-1].pmap  = kernel_pmap;
		update_list_p->item[UPDATE_LIST_SIZE-1].start = VM_MIN_ADDRESS;
		update_list_p->item[UPDATE_LIST_SIZE-1].end   = VM_MAX_KERNEL_ADDRESS;
	    }
	    else {
		update_list_p->item[j].pmap  = pmap;
		update_list_p->item[j].start = start_addr;
		update_list_p->item[j].end   = end_addr;
		update_list_p->count = j+1;
	    }
	    cpu_update_needed(which_cpu) = TRUE;
	    simple_unlock(&update_list_p->lock);

	    /* if its the kernel pmap, ignore cpus_idle */
	    if (((cpus_idle & (1 << which_cpu)) == 0) ||
		(pmap == kernel_pmap) || PMAP_REAL(which_cpu) == pmap)
	      {
		i386_signal_cpu(which_cpu, MP_TLB_FLUSH, ASYNC);
	      }
	    use_list &= ~(1 << which_cpu);
	}
}

void
process_pmap_updates(
	register pmap_t		my_pmap)
{
	register int		my_cpu;
	register pmap_update_list_t	update_list_p;
	register int		j;
	register pmap_t		pmap;

	mp_disable_preemption();
	my_cpu = cpu_number();
	update_list_p = cpu_update_list(my_cpu);
	simple_lock(&update_list_p->lock);

	for (j = 0; j < update_list_p->count; j++) {
	    pmap = update_list_p->item[j].pmap;
	    if (pmap == my_pmap ||
		pmap == kernel_pmap) {

	      	if (pmap->ref_count <= 0) {
			PMAP_CPU_CLR(pmap, my_cpu);
			PMAP_REAL(my_cpu) = kernel_pmap;
#ifdef PAE
			set_cr3((unsigned int)kernel_pmap->pm_ppdpt);
#else
			set_cr3((unsigned int)kernel_pmap->pdirbase);
#endif
		} else
			INVALIDATE_TLB(pmap,
				       update_list_p->item[j].start,
				       update_list_p->item[j].end);
	    }
	} 	
	update_list_p->count = 0;
	cpu_update_needed(my_cpu) = FALSE;
	simple_unlock(&update_list_p->lock);
	mp_enable_preemption();
}

/*
 *	Interrupt routine for TBIA requested from other processor.
 *	This routine can also be called at all interrupts time if
 *	the cpu was idle. Some driver interrupt routines might access
 *	newly allocated vm. (This is the case for hd)
 */
void
pmap_update_interrupt(void)
{
	register int		my_cpu;
	spl_t			s;
	register pmap_t		my_pmap;

	mp_disable_preemption();
	my_cpu = cpu_number();

	/*
	 *	Raise spl to splvm (above splip) to block out pmap_extract
	 *	from IO code (which would put this cpu back in the active
	 *	set).
	 */
	s = splhigh();
	
	my_pmap = PMAP_REAL(my_cpu);

	if (!(my_pmap && pmap_in_use(my_pmap, my_cpu)))
		my_pmap = kernel_pmap;

	do {
	    LOOP_VAR;

	    /*
	     *	Indicate that we're not using either user or kernel
	     *	pmap.
	     */
	    i_bit_clear(my_cpu, &cpus_active);

	    /*
	     *	Wait for any pmap updates in progress, on either user
	     *	or kernel pmap.
	     */
	    while (*(volatile int *)(&my_pmap->lock.interlock.lock_data) ||
		   *(volatile int *)(&kernel_pmap->lock.interlock.lock_data)) {
	    	LOOP_CHECK("pmap_update_interrupt", my_pmap);
		cpu_pause();
	    }

	    process_pmap_updates(my_pmap);

	    i_bit_set(my_cpu, &cpus_active);

	} while (cpu_update_needed(my_cpu));
	
	splx(s);
	mp_enable_preemption();
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
	PMAP_READ_LOCK(kernel_pmap, spl);


	while (size > 0) {
		pte = pmap_pte(kernel_pmap, from);
		if (pte == NULL)
			panic("pmap_pagemove from pte NULL");
		saved_pte = *pte;
		PMAP_READ_UNLOCK(kernel_pmap, spl);

		pmap_enter(kernel_pmap, to, (ppnum_t)i386_btop(i386_trunc_page(*pte)),
			VM_PROT_READ|VM_PROT_WRITE, 0, *pte & INTEL_PTE_WIRED);

		pmap_remove(kernel_pmap, (addr64_t)from, (addr64_t)(from+PAGE_SIZE));

		PMAP_READ_LOCK(kernel_pmap, spl);
		pte = pmap_pte(kernel_pmap, to);
		if (pte == NULL)
			panic("pmap_pagemove 'to' pte NULL");

		*pte = saved_pte;

		from += PAGE_SIZE;
		to += PAGE_SIZE;
		size -= PAGE_SIZE;
	}

	/* Get the processors to update the TLBs */
	PMAP_UPDATE_TLBS(kernel_pmap, from, from+size);
	PMAP_UPDATE_TLBS(kernel_pmap, to, to+size);

	PMAP_READ_UNLOCK(kernel_pmap, spl);

}
#endif /* MACH_BSD */

/* temporary workaround */
boolean_t
coredumpok(vm_map_t map, vm_offset_t va)
{
	pt_entry_t     *ptep;

	ptep = pmap_pte(map->pmap, va);
	if (0 == ptep)
		return FALSE;
	return ((*ptep & (INTEL_PTE_NCACHE | INTEL_PTE_WIRED)) != (INTEL_PTE_NCACHE | INTEL_PTE_WIRED));
}

/*
 * grow the number of kernel page table entries, if needed
 */
void
pmap_growkernel(vm_offset_t addr)
{
#if GROW_KERNEL_FUNCTION_IMPLEMENTED
	struct pmap *pmap;
	int s;
	vm_offset_t ptppaddr;
	ppnum_t  ppn;
	vm_page_t nkpg;
	pd_entry_t newpdir = 0;

	/*
	 * Serialize.
	 * Losers return to try again until the winner completes the work.
	 */
	if (kptobj == 0) panic("growkernel 0");
	if (!vm_object_lock_try(kptobj)) {
	    return;
	}

	vm_page_lock_queues();

	s = splhigh();

	/*
	 * If this is the first time thru, locate the end of the
	 * kernel page table entries and set nkpt to the current
	 * number of kernel page table pages
	 */
 
	if (kernel_vm_end == 0) {
		kernel_vm_end = KERNBASE;
		nkpt = 0;

		while (pdir_pde(kernel_pmap->dirbase, kernel_vm_end)) {
			kernel_vm_end = (kernel_vm_end + PAGE_SIZE * NPTEPG) & ~(PAGE_SIZE * NPTEPG - 1);
			nkpt++;
		}
	}

	/*
	 * Now allocate and map the required number of page tables
	 */
	addr = (addr + PAGE_SIZE * NPTEPG) & ~(PAGE_SIZE * NPTEPG - 1);
	while (kernel_vm_end < addr) {
		if (pdir_pde(kernel_pmap->dirbase, kernel_vm_end)) {
			kernel_vm_end = (kernel_vm_end + PAGE_SIZE * NPTEPG) & ~(PAGE_SIZE * NPTEPG - 1);
			continue; /* someone already filled this one */
		}

		nkpg = vm_page_alloc(kptobj, nkpt);
		if (!nkpg)
			panic("pmap_growkernel: no memory to grow kernel");

		nkpt++;
		vm_page_wire(nkpg);
		ppn  = nkpg->phys_page;
		pmap_zero_page(ppn);
		ptppaddr = i386_ptob(ppn);
		newpdir = (pd_entry_t) (ptppaddr | INTEL_PTE_VALID | 
					INTEL_PTE_RW | INTEL_PTE_REF | INTEL_PTE_MOD);
		pdir_pde(kernel_pmap->dirbase, kernel_vm_end) = newpdir;

		simple_lock(&free_pmap_lock);
		for (pmap = (struct pmap *)kernel_pmap->pmap_link.next;
		     pmap != kernel_pmap ;
		     pmap = (struct pmap *)pmap->pmap_link.next ) {
				*pmap_pde(pmap, kernel_vm_end) = newpdir;
		}
		simple_unlock(&free_pmap_lock);
	}
	splx(s);
	vm_page_unlock_queues();
	vm_object_unlock(kptobj);
#endif
}

pt_entry_t *
pmap_mapgetpte(vm_map_t map, vm_offset_t v)
{
	return pmap_pte(map->pmap, v);
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
pmap_commpage_init(vm_offset_t kernel_commpage, vm_offset_t user_commpage, int cnt)
{
  int i;
  pt_entry_t *opte, *npte;
  pt_entry_t pte;

  for (i = 0; i < cnt; i++) {
    opte = pmap_pte(kernel_pmap, kernel_commpage);
    if (0 == opte) panic("kernel_commpage");
    npte = pmap_pte(kernel_pmap, user_commpage);
    if (0 == npte) panic("user_commpage");
    pte = *opte | INTEL_PTE_USER|INTEL_PTE_GLOBAL;
    pte &= ~INTEL_PTE_WRITE; // ensure read only
    WRITE_PTE_FAST(npte, pte);
    kernel_commpage += INTEL_PGBYTES;
    user_commpage += INTEL_PGBYTES;
  }
}

static cpu_pmap_t		cpu_pmap_master;
static struct pmap_update_list	cpu_update_list_master;

struct cpu_pmap *
pmap_cpu_alloc(boolean_t is_boot_cpu)
{
	int			ret;
	int			i;
	cpu_pmap_t		*cp;
	pmap_update_list_t	up;
	vm_offset_t		address;
	vm_map_entry_t		entry;
	
	if (is_boot_cpu) {
		cp = &cpu_pmap_master;
		up = &cpu_update_list_master;
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
		 * The tlb flush update list.
		 */
		ret = kmem_alloc(kernel_map,
				 (vm_offset_t *) &up, sizeof(*up));
		if (ret != KERN_SUCCESS) {
			printf("pmap_cpu_alloc() failed ret=%d\n", ret);
			pmap_cpu_free(cp);
			return NULL;
		}

		/*
		 * The temporary windows used for copy/zero - see loose_ends.c
		 */
		for (i = 0; i < PMAP_NWINDOWS; i++) {
			ret = vm_map_find_space(kernel_map,
					&address, PAGE_SIZE, 0, &entry);
			if (ret != KERN_SUCCESS) {
				printf("pmap_cpu_alloc() "
					"vm_map_find_space ret=%d\n", ret);
				pmap_cpu_free(cp);
				return NULL;
			}
			vm_map_unlock(kernel_map);

			cp->mapwindow[i].prv_CADDR = (caddr_t) address;
			cp->mapwindow[i].prv_CMAP = vtopte(address);
			* (int *) cp->mapwindow[i].prv_CMAP = 0; 

			kprintf("pmap_cpu_alloc() "
				"window=%d CADDR=0x%x CMAP=0x%x\n",
				i, address, vtopte(address));
		}
	}

	/*
	 *	Set up the pmap request list
	 */
	cp->update_list = up;
	simple_lock_init(&up->lock, 0);
	up->count = 0;

	return cp;
}

void
pmap_cpu_free(struct cpu_pmap *cp)
{
	if (cp != NULL && cp != &cpu_pmap_master) {
		if (cp->update_list != NULL)
			kfree((void *) cp->update_list,
				sizeof(*cp->update_list));
		kfree((void *) cp, sizeof(cpu_pmap_t));
	}
}

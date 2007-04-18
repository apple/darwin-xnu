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
 *	File:	pmap.h
 *
 *	Authors:  Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Machine-dependent structures for the physical map module.
 */

#ifndef	_PMAP_MACHINE_
#define _PMAP_MACHINE_	1

#ifndef	ASSEMBLER

#include <platforms.h>

#include <mach/kern_return.h>
#include <mach/machine/vm_types.h>
#include <mach/vm_prot.h>
#include <mach/vm_statistics.h>
#include <mach/machine/vm_param.h>
#include <kern/kern_types.h>
#include <kern/thread.h>
#include <kern/lock.h>
#define PMAP_QUEUE 1
#ifdef PMAP_QUEUE
#include <kern/queue.h>
#endif

/*
 *	Define the generic in terms of the specific
 */

#define	INTEL_PGBYTES		I386_PGBYTES
#define INTEL_PGSHIFT		I386_PGSHIFT
#define	intel_btop(x)		i386_btop(x)
#define	intel_ptob(x)		i386_ptob(x)
#define	intel_round_page(x)	i386_round_page(x)
#define	intel_trunc_page(x)	i386_trunc_page(x)
#define trunc_intel_to_vm(x)	trunc_i386_to_vm(x)
#define round_intel_to_vm(x)	round_i386_to_vm(x)
#define vm_to_intel(x)		vm_to_i386(x)

/*
 *	i386/i486/i860 Page Table Entry
 */

#ifdef PAE
typedef uint64_t        pdpt_entry_t;
typedef uint64_t 	pt_entry_t;
typedef uint64_t        pd_entry_t;
typedef uint64_t        pmap_paddr_t;
#else
typedef uint32_t 	pt_entry_t;
typedef uint32_t        pd_entry_t;
typedef uint32_t        pmap_paddr_t;
#endif

#define PT_ENTRY_NULL	((pt_entry_t *) 0)
#define PD_ENTRY_NULL	((pt_entry_t *) 0)

#endif	/* ASSEMBLER */

#ifdef PAE
#define NPGPTD          4
#define PDESHIFT        21
#define PTEMASK         0x1ff
#define PTEINDX         3
#else
#define NPGPTD          1
#define PDESHIFT        22
#define PTEMASK         0x3ff
#define PTEINDX         2
#endif
#define PTESHIFT        12

#define PDESIZE		sizeof(pd_entry_t) /* for assembly files */
#define PTESIZE		sizeof(pt_entry_t) /* for assembly files */

#define INTEL_OFFMASK	(I386_PGBYTES - 1)
#define PG_FRAME        (~((pmap_paddr_t)PAGE_MASK))
#define NPTEPG          (PAGE_SIZE/(sizeof (pt_entry_t)))

#define NBPTD           (NPGPTD << PAGE_SHIFT)
#define NPDEPTD         (NBPTD / (sizeof (pd_entry_t)))
#define NPDEPG          (PAGE_SIZE/(sizeof (pd_entry_t)))
#define NBPDE           (1 << PDESHIFT)
#define PDEMASK         (NBPDE - 1)

#define	VM_WIMG_COPYBACK	VM_MEM_COHERENT
#define	VM_WIMG_DEFAULT		VM_MEM_COHERENT
/* ?? intel ?? */
#define VM_WIMG_IO		(VM_MEM_COHERENT | 	\
				VM_MEM_NOT_CACHEABLE | VM_MEM_GUARDED)
#define VM_WIMG_WTHRU		(VM_MEM_WRITE_THROUGH | VM_MEM_COHERENT | VM_MEM_GUARDED)
/* write combining mode, aka store gather */
#define VM_WIMG_WCOMB		(VM_MEM_NOT_CACHEABLE | VM_MEM_COHERENT) 

/*
 * Size of Kernel address space.  This is the number of page table pages
 * (4MB each) to use for the kernel.  256 pages == 1 Gigabyte.
 * This **MUST** be a multiple of 4 (eg: 252, 256, 260, etc).
 */
#ifndef KVA_PAGES
#define KVA_PAGES	256
#endif

/*
 * Pte related macros
 */
#define VADDR(pdi, pti) ((vm_offset_t)(((pdi)<<PDESHIFT)|((pti)<<PTESHIFT)))

#ifndef NKPT
#ifdef PAE
#define	NKPT		500	/* actual number of kernel page tables */
#else
#define	NKPT	        32	/* initial number of kernel page tables */
#endif
#endif
#ifndef NKPDE
#define NKPDE	(KVA_PAGES - 1)	/* addressable number of page tables/pde's */
#endif

/*
 * The *PTDI values control the layout of virtual memory
 *
 */
#ifdef PAE
#define        KPTDI           (0x600)/* start of kernel virtual pde's */
#define        PTDPTDI         (0x7F4) /* ptd entry that points to ptd! */
#define        APTDPTDI        (0x7F8) /* alt ptd entry that points to APTD */
#define        UMAXPTDI        (0x5FC) /* ptd entry for user space end */
#define	UMAXPTEOFF	(NPTEPG)	/* pte entry for user space end */
#else
#define        KPTDI           (0x300)/* start of kernel virtual pde's */
#define        PTDPTDI         (0x3FD) /* ptd entry that points to ptd! */
#define        APTDPTDI        (0x3FE) /* alt ptd entry that points to APTD */
#define        UMAXPTDI        (0x2FF) /* ptd entry for user space end */
#define	UMAXPTEOFF	(NPTEPG)	/* pte entry for user space end */
#endif

#define KERNBASE       VADDR(KPTDI,0)

/*
 *	Convert address offset to page descriptor index
 */
#define pdenum(pmap, a) (((a) >> PDESHIFT) & PDEMASK)


/*
 *	Convert page descriptor index to user virtual address
 */
#define pdetova(a)	((vm_offset_t)(a) << PDESHIFT)

/*
 *	Convert address offset to page table index
 */
#define ptenum(a)	(((a) >> PTESHIFT) & PTEMASK)

/*
 *	Hardware pte bit definitions (to be used directly on the ptes
 *	without using the bit fields).
 */

#define INTEL_PTE_VALID		0x00000001
#define INTEL_PTE_WRITE		0x00000002
#define INTEL_PTE_RW		0x00000002
#define INTEL_PTE_USER		0x00000004
#define INTEL_PTE_WTHRU		0x00000008
#define INTEL_PTE_NCACHE 	0x00000010
#define INTEL_PTE_REF		0x00000020
#define INTEL_PTE_MOD		0x00000040
#define INTEL_PTE_PS            0x00000080
#define INTEL_PTE_GLOBAL        0x00000100
#define INTEL_PTE_WIRED		0x00000200
#define INTEL_PTE_PFN		/*0xFFFFF000*/ (~0xFFF)
#define INTEL_PTE_PTA		0x00000080

#define	pa_to_pte(a)		((a) & INTEL_PTE_PFN) /* XXX */
#define	pte_to_pa(p)		((p) & INTEL_PTE_PFN) /* XXX */
#define	pte_increment_pa(p)	((p) += INTEL_OFFMASK+1)

#define PMAP_DEFAULT_CACHE	0
#define PMAP_INHIBIT_CACHE	1
#define PMAP_GUARDED_CACHE	2
#define PMAP_ACTIVATE_CACHE	4
#define PMAP_NO_GUARD_CACHE	8


#ifndef	ASSEMBLER

#include <sys/queue.h>

/*
 * Address of current and alternate address space page table maps
 * and directories.
 */

extern pt_entry_t PTmap[], APTmap[], Upte;
extern pd_entry_t PTD[], APTD[], PTDpde[], APTDpde[], Upde;

extern pd_entry_t *IdlePTD;	/* physical address of "Idle" state directory */
#ifdef PAE
extern pdpt_entry_t *IdlePDPT;
#endif

/*
 * virtual address to page table entry and
 * to physical address. Likewise for alternate address space.
 * Note: these work recursively, thus vtopte of a pte will give
 * the corresponding pde that in turn maps it.
 */
#define	vtopte(va)	(PTmap + i386_btop(va))


typedef	volatile long	cpu_set;	/* set of CPUs - must be <= 32 */
					/* changed by other processors */
struct md_page {
  int pv_list_count;
  TAILQ_HEAD(,pv_entry)  pv_list;
};

#include <vm/vm_page.h>

/*
 *	For each vm_page_t, there is a list of all currently
 *	valid virtual mappings of that page.  An entry is
 *	a pv_entry_t; the list is the pv_table.
 */

struct pmap {
#ifdef PMAP_QUEUE
  queue_head_t     pmap_link;   /* unordered queue of in use pmaps */
#endif
	pd_entry_t	*dirbase;	/* page directory pointer register */
	pd_entry_t	*pdirbase;	/* phys. address of dirbase */
        vm_object_t     pm_obj;         /* object to hold pte's */
	int		ref_count;	/* reference count */
	decl_simple_lock_data(,lock)	/* lock on map */
	struct pmap_statistics	stats;	/* map statistics */
	cpu_set		cpus_using;	/* bitmap of cpus using pmap */
#ifdef PAE
	vm_offset_t     pm_hold;        /* true pdpt zalloc addr */
	pdpt_entry_t    *pm_pdpt;       /* KVA of pg dir ptr table */
	vm_offset_t     pm_ppdpt;       /* phy addr pdpt
					   should really be 32/64 bit */
#endif
};

#define PMAP_NWINDOWS	4
typedef struct {
	pt_entry_t	*prv_CMAP;
	caddr_t		prv_CADDR;
} mapwindow_t;

typedef struct cpu_pmap {
	mapwindow_t		mapwindow[PMAP_NWINDOWS];
	struct pmap		*real_pmap;
	struct pmap_update_list	*update_list;
	volatile boolean_t	update_needed;
} cpu_pmap_t;

/*
 * Should be rewritten in asm anyway.
 */
#define CM1 (current_cpu_datap()->cpu_pmap->mapwindow[0].prv_CMAP)
#define CM2 (current_cpu_datap()->cpu_pmap->mapwindow[1].prv_CMAP)
#define CM3 (current_cpu_datap()->cpu_pmap->mapwindow[2].prv_CMAP)
#define CM4 (current_cpu_datap()->cpu_pmap->mapwindow[3].prv_CMAP)
#define CA1 (current_cpu_datap()->cpu_pmap->mapwindow[0].prv_CADDR)
#define CA2 (current_cpu_datap()->cpu_pmap->mapwindow[1].prv_CADDR)
#define CA3 (current_cpu_datap()->cpu_pmap->mapwindow[2].prv_CADDR)
#define CA4 (current_cpu_datap()->cpu_pmap->mapwindow[3].prv_CADDR)

typedef struct pmap_memory_regions {
  ppnum_t base;
  ppnum_t end;
  ppnum_t alloc;
  uint32_t type;
} pmap_memory_region_t;

unsigned pmap_memory_region_count;
unsigned pmap_memory_region_current;

#define PMAP_MEMORY_REGIONS_SIZE 32

extern pmap_memory_region_t pmap_memory_regions[];

/* 
 * Optimization avoiding some TLB flushes when switching to
 * kernel-loaded threads.  This is effective only for i386:
 * Since user task, kernel task and kernel loaded tasks share the
 * same virtual space (with appropriate protections), any pmap
 * allows mapping kernel and kernel loaded tasks. 
 *
 * The idea is to avoid switching to another pmap unnecessarily when
 * switching to a kernel-loaded task, or when switching to the kernel
 * itself.
 *
 * We store the pmap we are really using (from which we fetched the
 * dirbase value) in current_cpu_datap()->cpu_pmap.real_pmap.
 *
 * Invariant:
 * current_pmap() == current_cpu_datap()->cpu_pmap.real_pmap ||
 *			current_pmap() == kernel_pmap.
 */
#define	PMAP_REAL(my_cpu)	(cpu_datap(my_cpu)->cpu_pmap->real_pmap)

#include <i386/proc_reg.h>
/*
 * If switching to the kernel pmap, don't incur the TLB cost of switching
 * to its page tables, since all maps include the kernel map as a subset.
 * Simply record that this CPU is logically on the kernel pmap (see
 * pmap_destroy).
 * 
 * Similarly, if switching to a pmap (other than kernel_pmap that is already
 * in use, don't do anything to the hardware, to avoid a TLB flush.
 */

#define	PMAP_CPU_SET(pmap, my_cpu) i_bit_set(my_cpu, &((pmap)->cpus_using))
#define	PMAP_CPU_CLR(pmap, my_cpu) i_bit_clear(my_cpu, &((pmap)->cpus_using))

#ifdef PAE
#define PDIRBASE pm_ppdpt
#else
#define PDIRBASE pdirbase
#endif
#define	set_dirbase(mypmap, my_cpu) {					\
	struct pmap	**ppmap = &PMAP_REAL(my_cpu);			\
	pmap_paddr_t	pdirbase = (pmap_paddr_t)((mypmap)->PDIRBASE);  	\
									\
	if (*ppmap == (pmap_paddr_t)NULL) {				\
		*ppmap = (mypmap);					\
		PMAP_CPU_SET((mypmap), my_cpu);				\
		set_cr3(pdirbase);					\
	} else if ((mypmap) != kernel_pmap && (mypmap) != *ppmap ) {	\
		if (*ppmap != kernel_pmap)				\
			PMAP_CPU_CLR(*ppmap, my_cpu);			\
		*ppmap = (mypmap);					\
		PMAP_CPU_SET((mypmap), my_cpu);				\
		set_cr3(pdirbase);					\
	}								\
	assert((mypmap) == *ppmap || (mypmap) == kernel_pmap);		\
}

/*
 *	List of cpus that are actively using mapped memory.  Any
 *	pmap update operation must wait for all cpus in this list.
 *	Update operations must still be queued to cpus not in this
 *	list.
 */
extern cpu_set		cpus_active;

/*
 *	List of cpus that are idle, but still operating, and will want
 *	to see any kernel pmap updates when they become active.
 */
extern cpu_set		cpus_idle;


#define cpu_update_needed(cpu)	cpu_datap(cpu)->cpu_pmap->update_needed
#define cpu_update_list(cpu)	cpu_datap(cpu)->cpu_pmap->update_list

/*
 *	External declarations for PMAP_ACTIVATE.
 */

extern void		process_pmap_updates(struct pmap *pmap);
extern void		pmap_update_interrupt(void);

/*
 *	Machine dependent routines that are used only for i386/i486/i860.
 */

extern vm_offset_t	(kvtophys)(
				vm_offset_t	addr);

extern pt_entry_t	*pmap_pte(
				struct pmap	*pmap,
				vm_offset_t	addr);

extern vm_offset_t	pmap_map(
				vm_offset_t	virt,
				vm_offset_t	start,
				vm_offset_t	end,
				vm_prot_t	prot);

extern vm_offset_t	pmap_map_bd(
				vm_offset_t	virt,
				vm_offset_t	start,
				vm_offset_t	end,
				vm_prot_t	prot);

extern void		pmap_bootstrap(
				vm_offset_t	load_start);

extern boolean_t	pmap_valid_page(
				ppnum_t	pn);

extern int		pmap_list_resident_pages(
				struct pmap	*pmap,
				vm_offset_t	*listp,
				int		space);

extern void             pmap_commpage_init(
					   vm_offset_t kernel,
					   vm_offset_t user,
					   int count);
extern struct cpu_pmap	*pmap_cpu_alloc(
				boolean_t	is_boot_cpu);
extern void		pmap_cpu_free(
				struct cpu_pmap	*cp);
				
extern void invalidate_icache(vm_offset_t addr, unsigned cnt, int phys);
extern void flush_dcache(vm_offset_t addr, unsigned count, int phys);
extern ppnum_t          pmap_find_phys(pmap_t map, addr64_t va);
extern void pmap_sync_page_data_phys(ppnum_t pa);
extern void pmap_sync_page_attributes_phys(ppnum_t pa);

/*
 *	Macros for speed.
 */


#include <kern/spl.h>

#if defined(PMAP_ACTIVATE_KERNEL)
#undef PMAP_ACTIVATE_KERNEL
#undef PMAP_DEACTIVATE_KERNEL
#undef PMAP_ACTIVATE_USER
#undef PMAP_DEACTIVATE_USER
#endif

/*
 *	For multiple CPUS, PMAP_ACTIVATE and PMAP_DEACTIVATE must manage
 *	fields to control TLB invalidation on other CPUS.
 */

#define	PMAP_ACTIVATE_KERNEL(my_cpu)	{				\
									\
	/*								\
	 *	Let pmap updates proceed while we wait for this pmap.	\
	 */								\
	i_bit_clear((my_cpu), &cpus_active);				\
									\
	/*								\
	 *	Lock the pmap to put this cpu in its active set.	\
	 *	Wait for updates here.					\
	 */								\
	simple_lock(&kernel_pmap->lock);				\
									\
	/*								\
	 *	Process invalidate requests for the kernel pmap.	\
	 */								\
	if (cpu_update_needed(my_cpu))					\
	    process_pmap_updates(kernel_pmap);				\
									\
	/*								\
	 *	Mark that this cpu is using the pmap.			\
	 */								\
	i_bit_set((my_cpu), &kernel_pmap->cpus_using);			\
									\
	/*								\
	 *	Mark this cpu active - IPL will be lowered by		\
	 *	load_context().						\
	 */								\
	i_bit_set((my_cpu), &cpus_active);				\
									\
	simple_unlock(&kernel_pmap->lock);				\
}

#define	PMAP_DEACTIVATE_KERNEL(my_cpu)	{				\
	/*								\
	 *	Mark pmap no longer in use by this cpu even if		\
	 *	pmap is locked against updates.				\
	 */								\
	i_bit_clear((my_cpu), &kernel_pmap->cpus_using);		\
	i_bit_clear((my_cpu), &cpus_active);				\
	PMAP_REAL(my_cpu) = NULL;					\
}

#define PMAP_ACTIVATE_MAP(map, my_cpu)	{				\
	register pmap_t		tpmap;					\
									\
	tpmap = vm_map_pmap(map);					\
	if (tpmap == kernel_pmap) {					\
	    /*								\
	     *	If this is the kernel pmap, switch to its page tables.	\
	     */								\
	    set_dirbase(kernel_pmap, my_cpu);				\
	}								\
	else {								\
	    /*								\
	     *	Let pmap updates proceed while we wait for this pmap.	\
	     */								\
	    i_bit_clear((my_cpu), &cpus_active);			\
									\
	    /*								\
	     *	Lock the pmap to put this cpu in its active set.	\
	     *	Wait for updates here.					\
	     */								\
	    simple_lock(&tpmap->lock);					\
									\
	    /*								\
	     *	No need to invalidate the TLB - the entire user pmap	\
	     *	will be invalidated by reloading dirbase.		\
	     */								\
	    set_dirbase(tpmap, my_cpu);					\
									\
	    /*								\
	     *	Mark this cpu active - IPL will be lowered by		\
	     *	load_context().						\
	     */								\
	    i_bit_set((my_cpu), &cpus_active);				\
									\
	    simple_unlock(&tpmap->lock);				\
	}								\
}

#define PMAP_DEACTIVATE_MAP(map, my_cpu)

#define PMAP_ACTIVATE_USER(th, my_cpu)	{				\
	spl_t		spl;						\
									\
	spl = splhigh();							\
	PMAP_ACTIVATE_MAP(th->map, my_cpu)				\
	splx(spl);							\
}

#define PMAP_DEACTIVATE_USER(th, my_cpu)

#define	PMAP_SWITCH_CONTEXT(old_th, new_th, my_cpu) {			\
	spl_t		spl;						\
									\
	if (old_th->map != new_th->map) {				\
		spl = splhigh();						\
		PMAP_DEACTIVATE_MAP(old_th->map, my_cpu);		\
		PMAP_ACTIVATE_MAP(new_th->map, my_cpu);			\
		splx(spl);						\
	}								\
}

#define	PMAP_SWITCH_USER(th, new_map, my_cpu) {				\
	spl_t		spl;						\
									\
	spl = splhigh();							\
	PMAP_DEACTIVATE_MAP(th->map, my_cpu);				\
	th->map = new_map;						\
	PMAP_ACTIVATE_MAP(th->map, my_cpu);				\
	splx(spl);							\
}

#define MARK_CPU_IDLE(my_cpu)	{					\
	/*								\
	 *	Mark this cpu idle, and remove it from the active set,	\
	 *	since it is not actively using any pmap.  Signal_cpus	\
	 *	will notice that it is idle, and avoid signaling it,	\
	 *	but will queue the update request for when the cpu	\
	 *	becomes active.						\
	 */								\
	int	s = splhigh();						\
	i_bit_set((my_cpu), &cpus_idle);				\
	i_bit_clear((my_cpu), &cpus_active);				\
	splx(s);							\
	set_led(my_cpu); 						\
}

#define MARK_CPU_ACTIVE(my_cpu)	{					\
									\
	int	s = splhigh();						\
	/*								\
	 *	If a kernel_pmap update was requested while this cpu	\
	 *	was idle, process it as if we got the interrupt.	\
	 *	Before doing so, remove this cpu from the idle set.	\
	 *	Since we do not grab any pmap locks while we flush	\
	 *	our TLB, another cpu may start an update operation	\
	 *	before we finish.  Removing this cpu from the idle	\
	 *	set assures that we will receive another update		\
	 *	interrupt if this happens.				\
	 */								\
	i_bit_clear((my_cpu), &cpus_idle);				\
									\
	if (cpu_update_needed(my_cpu))					\
	    pmap_update_interrupt();					\
									\
	/*								\
	 *	Mark that this cpu is now active.			\
	 */								\
	i_bit_set((my_cpu), &cpus_active);				\
	splx(s);							\
	clear_led(my_cpu); 						\
}

#define PMAP_CONTEXT(pmap, thread)

#define pmap_kernel_va(VA)	\
	(((VA) >= VM_MIN_KERNEL_ADDRESS) && ((VA) <= VM_MAX_KERNEL_ADDRESS))

#define pmap_resident_count(pmap)	((pmap)->stats.resident_count)
#define	pmap_copy(dst_pmap,src_pmap,dst_addr,len,src_addr)
#define	pmap_attribute(pmap,addr,size,attr,value) \
					(KERN_INVALID_ADDRESS)
#define	pmap_attribute_cache_sync(addr,size,attr,value) \
					(KERN_INVALID_ADDRESS)

#endif	/* ASSEMBLER */

#endif	/* _PMAP_MACHINE_ */

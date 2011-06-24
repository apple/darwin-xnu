/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
#ifdef KERNEL_PRIVATE
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

#include <i386/mp.h>
#include <i386/proc_reg.h>

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

#endif	/* ASSEMBLER */

#define NPGPTD          4
#define PDESHIFT        21
#define PTEMASK         0x1ff
#define PTEINDX         3

#define PTESHIFT        12


#define INITPT_SEG_BASE  0x100000
#define INITGDT_SEG_BASE 0x106000
#define SLEEP_SEG_BASE   0x107000

#ifdef __x86_64__
#define LOW_4GB_MASK	((vm_offset_t)0x00000000FFFFFFFFUL)
#endif

#define PDESIZE		sizeof(pd_entry_t) /* for assembly files */
#define PTESIZE		sizeof(pt_entry_t) /* for assembly files */

#define INTEL_OFFMASK	(I386_PGBYTES - 1)
#define INTEL_LOFFMASK	(I386_LPGBYTES - 1)
#define PG_FRAME        0x000FFFFFFFFFF000ULL
#define NPTEPG          (PAGE_SIZE/(sizeof (pt_entry_t)))
#define NPTDPG          (PAGE_SIZE/(sizeof (pd_entry_t)))

#define NBPTD           (NPGPTD << PAGE_SHIFT)
#define NPDEPTD         (NBPTD / (sizeof (pd_entry_t)))
#define NPDEPG          (PAGE_SIZE/(sizeof (pd_entry_t)))
#define NBPDE           (1 << PDESHIFT)
#define PDEMASK         (NBPDE - 1)

#define PTE_PER_PAGE	512 /* number of PTE's per page on any level */

 /* cleanly define parameters for all the page table levels */
typedef uint64_t        pml4_entry_t;
#define NPML4PG         (PAGE_SIZE/(sizeof (pml4_entry_t)))
#define PML4SHIFT       39
#define PML4PGSHIFT     9
#define NBPML4          (1ULL << PML4SHIFT)
#define PML4MASK        (NBPML4-1)
#define PML4_ENTRY_NULL ((pml4_entry_t *) 0)

typedef uint64_t        pdpt_entry_t;
#define NPDPTPG         (PAGE_SIZE/(sizeof (pdpt_entry_t)))
#define PDPTSHIFT       30
#define PDPTPGSHIFT     9
#define NBPDPT          (1 << PDPTSHIFT)
#define PDPTMASK        (NBPDPT-1)
#define PDPT_ENTRY_NULL ((pdpt_entry_t *) 0)

typedef uint64_t        pd_entry_t;
#define NPDPG           (PAGE_SIZE/(sizeof (pd_entry_t)))
#define PDSHIFT         21
#define PDPGSHIFT       9
#define NBPD            (1 << PDSHIFT)
#define PDMASK          (NBPD-1)
#define PD_ENTRY_NULL   ((pd_entry_t *) 0)

typedef uint64_t        pt_entry_t;
#define NPTPG           (PAGE_SIZE/(sizeof (pt_entry_t)))
#define PTSHIFT         12
#define PTPGSHIFT       9
#define NBPT            (1 << PTSHIFT)
#define PTMASK          (NBPT-1)
#define PT_ENTRY_NULL	((pt_entry_t *) 0)

typedef uint64_t  pmap_paddr_t;

/* superpages */
#ifdef __x86_64__
#define SUPERPAGE_NBASEPAGES 512
#else
#define SUPERPAGE_NBASEPAGES 1	/* we don't support superpages on i386 */
#endif

/*
 * Atomic 64-bit store of a page table entry.
 */
static inline void
pmap_store_pte(pt_entry_t *entryp, pt_entry_t value)
{
#ifdef __i386__
	/*
	 * Load the new value into %ecx:%ebx
	 * Load the old value into %edx:%eax
	 * Compare-exchange-8bytes at address entryp (loaded in %edi)
	 * If the compare succeeds, the new value will have been stored.
	 * Otherwise, the old value changed and reloaded, so try again.
	 */
	__asm__ volatile(
		"	movl	(%0), %%eax	\n\t"
		"	movl	4(%0), %%edx	\n\t"
		"1:				\n\t"
		"	cmpxchg8b (%0)		\n\t"
		"	jnz 1b"
		:
		: "D" (entryp),
		  "b" ((uint32_t)value),
		  "c" ((uint32_t)(value >> 32))
		: "eax", "edx", "memory");
#else
	/*
	 * In the 32-bit kernel a compare-and-exchange loop was
	 * required to provide atomicity. For K64, life is easier:
	 */
	*entryp = value;
#endif
}

/*
 * Atomic 64-bit compare and exchange of a page table entry.
 */
static inline boolean_t
pmap_cmpx_pte(pt_entry_t *entryp, pt_entry_t old, pt_entry_t new)
{
	boolean_t		ret;

#ifdef __i386__
	/*
	 * Load the old value into %edx:%eax
	 * Load the new value into %ecx:%ebx
	 * Compare-exchange-8bytes at address entryp (loaded in %edi)
	 * If the compare succeeds, the new value is stored, return TRUE.
	 * Otherwise, no swap is made, return FALSE.
	 */
	asm volatile(
		"	lock; cmpxchg8b (%1)	\n\t"
		"	setz	%%al		\n\t"
		"	movzbl	%%al,%0"
		: "=a" (ret)
		: "D" (entryp),
		  "a" ((uint32_t)old),
		  "d" ((uint32_t)(old >> 32)),
		  "b" ((uint32_t)new),
		  "c" ((uint32_t)(new >> 32))
		: "memory");
#else
	/*
	 * Load the old value into %rax
	 * Load the new value into another register
	 * Compare-exchange-quad at address entryp
	 * If the compare succeeds, the new value is stored, return TRUE.
	 * Otherwise, no swap is made, return FALSE.
	 */
	asm volatile(
		"	lock; cmpxchgq %2,(%3)	\n\t"
		"	setz	%%al		\n\t"
		"	movzbl	%%al,%0"
		: "=a" (ret)
		: "a" (old),
		  "r" (new),
		  "r" (entryp)
		: "memory");
#endif
	return ret;
}

#define pmap_update_pte(entryp, old, new) \
	while (!pmap_cmpx_pte((entryp), (old), (new)))


/* in 64 bit spaces, the number of each type of page in the page tables */
#define NPML4PGS        (1ULL * (PAGE_SIZE/(sizeof (pml4_entry_t))))
#define NPDPTPGS        (NPML4PGS * (PAGE_SIZE/(sizeof (pdpt_entry_t))))
#define NPDEPGS         (NPDPTPGS * (PAGE_SIZE/(sizeof (pd_entry_t))))
#define NPTEPGS         (NPDEPGS * (PAGE_SIZE/(sizeof (pt_entry_t))))

#ifdef __i386__
/*
 * The 64-bit kernel is remapped in uber-space which is at the base
 * the highest 4th-level directory (KERNEL_UBER_PML4_INDEX). That is,
 * 512GB from the top of virtual space (or zero).
 */
#define KERNEL_UBER_PML4_INDEX	511
#define KERNEL_UBER_BASE	(0ULL - NBPML4)
#define KERNEL_UBER_BASE_HI32	((uint32_t)(KERNEL_UBER_BASE >> 32))
#else
#define KERNEL_PML4_INDEX	511
#define KERNEL_KEXTS_INDEX	510	/* Home of KEXTs - the basement */
#define KERNEL_PHYSMAP_INDEX	509	/* virtual to physical map */ 
#define KERNEL_BASE		(0ULL - NBPML4)
#define KERNEL_BASEMENT		(KERNEL_BASE - NBPML4)
#endif

#define	VM_WIMG_COPYBACK	VM_MEM_COHERENT
#define	VM_WIMG_DEFAULT		VM_MEM_COHERENT
/* ?? intel ?? */
#define VM_WIMG_IO		(VM_MEM_COHERENT | 	\
				VM_MEM_NOT_CACHEABLE | VM_MEM_GUARDED)
#define VM_WIMG_WTHRU		(VM_MEM_WRITE_THROUGH | VM_MEM_COHERENT | VM_MEM_GUARDED)
/* write combining mode, aka store gather */
#define VM_WIMG_WCOMB		(VM_MEM_NOT_CACHEABLE | VM_MEM_COHERENT) 

/*
 * Pte related macros
 */
#ifdef __i386__
#define VADDR(pdi, pti) ((vm_offset_t)(((pdi)<<PDESHIFT)|((pti)<<PTESHIFT)))
#define VADDR64(pmi, pdi, pti) ((vm_offset_t)(((pmi)<<PLM4SHIFT))((pdi)<<PDESHIFT)|((pti)<<PTESHIFT))
#else
#define KVADDR(pmi, pdpi, pdi, pti)		  \
	 ((vm_offset_t)			  \
		((uint64_t) -1    << 47)        | \
		((uint64_t)(pmi)  << PML4SHIFT) | \
		((uint64_t)(pdpi) << PDPTSHIFT) | \
		((uint64_t)(pdi)  << PDESHIFT)  | \
		((uint64_t)(pti)  << PTESHIFT))
#endif

/*
 * Size of Kernel address space.  This is the number of page table pages
 * (4MB each) to use for the kernel.  256 pages == 1 Gigabyte.
 * This **MUST** be a multiple of 4 (eg: 252, 256, 260, etc).
 */
#ifndef KVA_PAGES
#define KVA_PAGES	1024
#endif

#ifndef NKPT
#define	NKPT		500	/* actual number of kernel page tables */
#endif
#ifndef NKPDE
#define NKPDE	(KVA_PAGES - 1)	/* addressable number of page tables/pde's */
#endif


#ifdef __i386__
enum high_cpu_types {
  HIGH_CPU_ISS0,
  HIGH_CPU_ISS1,
  HIGH_CPU_DESC,
  HIGH_CPU_LDT_BEGIN,
  HIGH_CPU_LDT_END = HIGH_CPU_LDT_BEGIN + (LDTSZ / 512) - 1,
  HIGH_CPU_END
};

enum  high_fixed_addresses {
  HIGH_FIXED_TRAMPS,  /* must be first */
  HIGH_FIXED_TRAMPS_END,
  HIGH_FIXED_GDT,
  HIGH_FIXED_IDT,
  HIGH_FIXED_LDT_BEGIN,
  HIGH_FIXED_LDT_END = HIGH_FIXED_LDT_BEGIN + (LDTSZ / 512) - 1,
  HIGH_FIXED_KTSS,
  HIGH_FIXED_DFTSS,
  HIGH_FIXED_DBTSS,
  HIGH_FIXED_CPUS_BEGIN,
  HIGH_FIXED_CPUS_END = HIGH_FIXED_CPUS_BEGIN + (HIGH_CPU_END * MAX_CPUS) - 1,
};


/* XXX64  below PTDI values need cleanup */
/*
 * The *PTDI values control the layout of virtual memory
 *
 */
#define        KPTDI           (0x000)/* start of kernel virtual pde's */
#define        PTDPTDI         (0x7F4) /* ptd entry that points to ptd! */
#define        APTDPTDI        (0x7F8) /* alt ptd entry that points to APTD */
#define        UMAXPTDI        (0x7F8) /* ptd entry for user space end */
#define	UMAXPTEOFF	(NPTEPG)	/* pte entry for user space end */

#define KERNBASE       VADDR(KPTDI,0)

/*
 *	Convert address offset to directory address
 *	containing the page table pointer - legacy
 */
/*#define pmap_pde(m,v) (&((m)->dirbase[(vm_offset_t)(v) >> PDESHIFT]))*/

#define HIGH_MEM_BASE  ((uint32_t)( -NBPDE) )  /* shared gdt etc seg addr */ /* XXX64 ?? */
#define pmap_index_to_virt(x)  (HIGH_MEM_BASE | ((unsigned)(x) << PAGE_SHIFT))
#endif

/*
 *	Convert address offset to page descriptor index
 */
#define pdptnum(pmap, a) (((vm_offset_t)(a) >> PDPTSHIFT) & PDPTMASK)
#define pdenum(pmap, a)	(((vm_offset_t)(a) >> PDESHIFT) & PDEMASK)
#define PMAP_INVALID_PDPTNUM (~0ULL)

#ifdef __i386__
#define pdeidx(pmap, a)    (((a) >> PDSHIFT)   & ((1ULL<<(48 - PDSHIFT)) -1))
#define pdptidx(pmap, a)   (((a) >> PDPTSHIFT) & ((1ULL<<(48 - PDPTSHIFT)) -1))
#define pml4idx(pmap, a)   (((a) >> PML4SHIFT) & ((1ULL<<(48 - PML4SHIFT)) -1))
#else
#define VAMASK		   ((1ULL<<48)-1)
#define pml4idx(pmap, a)   ((((a) & VAMASK) >> PML4SHIFT) &	\
				((1ULL<<(48 - PML4SHIFT))-1))
#define pdptidx(pmap, a)   ((((a) & PML4MASK) >> PDPTSHIFT) &	\
				((1ULL<<(48 - PDPTSHIFT))-1))
#define pdeidx(pmap, a)    ((((a) & PML4MASK) >> PDSHIFT) &	\
				((1ULL<<(48 - PDSHIFT)) - 1))
#endif

/*
 *	Convert page descriptor index to user virtual address
 */
#define pdetova(a)	((vm_offset_t)(a) << PDESHIFT)

/*
 *	Convert address offset to page table index
 */
#define ptenum(a)	(((vm_offset_t)(a) >> PTESHIFT) & PTEMASK)

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
#define INTEL_PTE_PS		0x00000080
#define INTEL_PTE_PTA		0x00000080
#define INTEL_PTE_GLOBAL	0x00000100
#define INTEL_PTE_WIRED		0x00000200
#define INTEL_PDPTE_NESTED	0x00000400
#define INTEL_PTE_PFN		PG_FRAME

#define INTEL_PTE_NX		(1ULL << 63)

#define INTEL_PTE_INVALID       0
/* This is conservative, but suffices */
#define INTEL_PTE_RSVD		((1ULL << 8) | (1ULL << 9) | (1ULL << 10) | (1ULL << 11) | (0x1FFULL << 54))
#define	pa_to_pte(a)		((a) & INTEL_PTE_PFN) /* XXX */
#define	pte_to_pa(p)		((p) & INTEL_PTE_PFN) /* XXX */
#define	pte_increment_pa(p)	((p) += INTEL_OFFMASK+1)

#define pte_kernel_rw(p)          ((pt_entry_t)(pa_to_pte(p) | INTEL_PTE_VALID|INTEL_PTE_RW))
#define pte_kernel_ro(p)          ((pt_entry_t)(pa_to_pte(p) | INTEL_PTE_VALID))
#define pte_user_rw(p)            ((pt_entry)t)(pa_to_pte(p) | INTEL_PTE_VALID|INTEL_PTE_USER|INTEL_PTE_RW))
#define pte_user_ro(p)            ((pt_entry_t)(pa_to_pte(p) | INTEL_PTE_VALID|INTEL_PTE_USER))

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

#ifdef __i386__
extern pt_entry_t	PTmap[], APTmap[], Upte;
extern pd_entry_t	PTD[], APTD[], PTDpde[], APTDpde[], Upde;
extern pmap_paddr_t	lo_kernel_cr3;
extern pdpt_entry_t	*IdlePDPT64;
#else
extern pt_entry_t	*PTmap;
#endif
extern boolean_t	no_shared_cr3;
extern addr64_t		kernel64_cr3;
extern pd_entry_t	*IdlePTD;	/* physical addr of "Idle" state PTD */
extern pdpt_entry_t	IdlePDPT[];
extern pml4_entry_t	IdlePML4[];

extern uint64_t		pmap_pv_hashlist_walks;
extern uint64_t		pmap_pv_hashlist_cnts;
extern uint32_t		pmap_pv_hashlist_max;
extern uint32_t		pmap_kernel_text_ps;

#ifdef __i386__
/*
 * ** i386 **
 * virtual address to page table entry and
 * to physical address. Likewise for alternate address space.
 * Note: these work recursively, thus vtopte of a pte will give
 * the corresponding pde that in turn maps it.
 */

#define	vtopte(va)	(PTmap + i386_btop((vm_offset_t)va))
#endif

#ifdef __x86_64__
#define ID_MAP_VTOP(x)	((void *)(((uint64_t)(x)) & LOW_4GB_MASK))

#define PHYSMAP_BASE	KVADDR(KERNEL_PHYSMAP_INDEX,0,0,0)
#define PHYSMAP_PTOV(x)	((void *)(((uint64_t)(x)) + PHYSMAP_BASE))
#endif

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
        pd_entry_t      *dirbase;        /* page directory pointer */
#ifdef __i386__
	pmap_paddr_t    pdirbase;        /* phys. address of dirbase */
#endif
        vm_object_t     pm_obj;         /* object to hold pde's */
	int		ref_count;	/* reference count */
        int		nx_enabled;
        task_map_t      pm_task_map;
	decl_simple_lock_data(,lock)	/* lock on map */
	struct pmap_statistics	stats;	/* map statistics */
#ifdef __i386__
	vm_offset_t     pm_hold;        /* true pdpt zalloc addr */
#endif
	pmap_paddr_t    pm_cr3;         /* physical addr */
        pdpt_entry_t    *pm_pdpt;       /* KVA of 3rd level page */
	pml4_entry_t    *pm_pml4;       /* VKA of top level */
	vm_object_t     pm_obj_pdpt;    /* holds pdpt pages */
	vm_object_t     pm_obj_pml4;    /* holds pml4 pages */
	vm_object_t     pm_obj_top;     /* holds single top level page */
        boolean_t       pm_shared;
};


#if NCOPY_WINDOWS > 0
#define PMAP_PDPT_FIRST_WINDOW 0
#define PMAP_PDPT_NWINDOWS 4
#define PMAP_PDE_FIRST_WINDOW (PMAP_PDPT_NWINDOWS)
#define PMAP_PDE_NWINDOWS 4
#define PMAP_PTE_FIRST_WINDOW (PMAP_PDE_FIRST_WINDOW + PMAP_PDE_NWINDOWS)
#define PMAP_PTE_NWINDOWS 4

#define PMAP_NWINDOWS_FIRSTFREE (PMAP_PTE_FIRST_WINDOW + PMAP_PTE_NWINDOWS)
#define PMAP_WINDOW_SIZE 8
#define PMAP_NWINDOWS (PMAP_NWINDOWS_FIRSTFREE + PMAP_WINDOW_SIZE)

typedef struct {
	pt_entry_t	*prv_CMAP;
	caddr_t		prv_CADDR;
} mapwindow_t;

typedef struct cpu_pmap {
        int                     pdpt_window_index;
        int                     pde_window_index;
        int                     pte_window_index;
	mapwindow_t		mapwindow[PMAP_NWINDOWS];
} cpu_pmap_t;


extern mapwindow_t *pmap_get_mapwindow(pt_entry_t pentry);
extern void         pmap_put_mapwindow(mapwindow_t *map);
#endif

typedef struct pmap_memory_regions {
  ppnum_t base;
  ppnum_t end;
  ppnum_t alloc;
  uint32_t type;
} pmap_memory_region_t;

extern unsigned pmap_memory_region_count;
extern unsigned pmap_memory_region_current;

#define PMAP_MEMORY_REGIONS_SIZE 128

extern pmap_memory_region_t pmap_memory_regions[];

static inline void
set_dirbase(pmap_t tpmap, __unused thread_t thread) {
	current_cpu_datap()->cpu_task_cr3 = tpmap->pm_cr3;
	current_cpu_datap()->cpu_task_map = tpmap->pm_task_map;
#ifndef __i386__
	/*
	 * Switch cr3 if necessary
	 * - unless running with no_shared_cr3 debugging mode
	 *   and we're not on the kernel's cr3 (after pre-empted copyio)
	 */
	if (!no_shared_cr3) {
		if (get_cr3() != tpmap->pm_cr3)
			set_cr3(tpmap->pm_cr3);
	} else {
		if (get_cr3() != current_cpu_datap()->cpu_kernel_cr3)
			set_cr3(current_cpu_datap()->cpu_kernel_cr3);
	}
#endif
}

/*
 *	External declarations for PMAP_ACTIVATE.
 */

extern void		process_pmap_updates(void);
extern void		pmap_update_interrupt(void);

/*
 *	Machine dependent routines that are used only for i386/i486/i860.
 */

extern addr64_t		(kvtophys)(
				vm_offset_t	addr);

extern void		pmap_expand(
				pmap_t		pmap,
				vm_map_offset_t	addr);

extern pt_entry_t	*pmap_pte(
				struct pmap	*pmap,
				vm_map_offset_t	addr);

extern pd_entry_t	*pmap_pde(
				struct pmap	*pmap,
				vm_map_offset_t	addr);

extern pd_entry_t	*pmap64_pde(
				struct pmap	*pmap,
				vm_map_offset_t	addr);

extern pdpt_entry_t	*pmap64_pdpt(
				struct pmap	*pmap,
				vm_map_offset_t	addr);

extern vm_offset_t	pmap_map(
				vm_offset_t	virt,
				vm_map_offset_t	start,
				vm_map_offset_t	end,
				vm_prot_t	prot,
				unsigned int	flags);

extern vm_offset_t	pmap_map_bd(
				vm_offset_t	virt,
				vm_map_offset_t	start,
				vm_map_offset_t	end,
				vm_prot_t	prot,
				unsigned int	flags);

extern void		pmap_bootstrap(
				vm_offset_t	load_start,
				boolean_t	IA32e);

extern boolean_t	pmap_valid_page(
				ppnum_t	pn);

extern int		pmap_list_resident_pages(
				struct pmap	*pmap,
				vm_offset_t	*listp,
				int		space);
extern void		x86_filter_TLB_coherency_interrupts(boolean_t);
#ifdef __i386__
extern void             pmap_commpage32_init(
					   vm_offset_t kernel,
					   vm_offset_t user,
					   int count);
extern void             pmap_commpage64_init(
					   vm_offset_t	kernel,
					   vm_map_offset_t user,
					   int count);

#endif

#if NCOPY_WINDOWS > 0
extern struct cpu_pmap	*pmap_cpu_alloc(
				boolean_t	is_boot_cpu);
extern void		pmap_cpu_free(
				struct cpu_pmap	*cp);
#endif

extern void		pmap_map_block(
				pmap_t pmap, 
				addr64_t va,
				ppnum_t pa,
				uint32_t size,
				vm_prot_t prot,
				int attr,
				unsigned int flags);
				
extern void invalidate_icache(vm_offset_t addr, unsigned cnt, int phys);
extern void flush_dcache(vm_offset_t addr, unsigned count, int phys);
extern ppnum_t          pmap_find_phys(pmap_t map, addr64_t va);

extern void pmap_cpu_init(void);
extern void pmap_disable_NX(pmap_t pmap);
#ifdef __i386__
extern void pmap_set_4GB_pagezero(pmap_t pmap);
extern void pmap_clear_4GB_pagezero(pmap_t pmap);
extern void pmap_load_kernel_cr3(void);
extern vm_offset_t pmap_cpu_high_map_vaddr(int, enum high_cpu_types);
extern vm_offset_t pmap_high_map_vaddr(enum high_cpu_types);
extern vm_offset_t pmap_high_map(pt_entry_t, enum high_cpu_types);
extern vm_offset_t pmap_cpu_high_shared_remap(int, enum high_cpu_types, vm_offset_t, int);
extern vm_offset_t pmap_high_shared_remap(enum high_fixed_addresses, vm_offset_t, int);
#endif

extern void pt_fake_zone_info(int *, vm_size_t *, vm_size_t *, vm_size_t *, vm_size_t *, int *, int *);
extern void pmap_pagetable_corruption_msg_log(int (*)(const char * fmt, ...)__printflike(1,2));


/*
 *	Macros for speed.
 */


#include <kern/spl.h>

				  
#define PMAP_ACTIVATE_MAP(map, thread)	{				\
	register pmap_t		tpmap;					\
                                                                        \
        tpmap = vm_map_pmap(map);					\
        set_dirbase(tpmap, thread);					\
}

#ifdef __i386__
#define PMAP_DEACTIVATE_MAP(map, thread)				\
	if (vm_map_pmap(map)->pm_task_map == TASK_MAP_64BIT_SHARED)	\
		pmap_load_kernel_cr3();
#else
#define PMAP_DEACTIVATE_MAP(map, my_cpu)
#endif

#if   defined(__i386__)

#define	PMAP_SWITCH_CONTEXT(old_th, new_th, my_cpu) {			\
	spl_t		spl;						\
	pt_entry_t	*kpdp;						\
	pt_entry_t	*updp;						\
        int		i;						\
        int		need_flush;					\
                                                                        \
        need_flush = 0;							\
        spl = splhigh();						\
	if ((old_th->map != new_th->map) || (new_th->task != old_th->task)) {	\
		PMAP_DEACTIVATE_MAP(old_th->map, old_th);		\
		PMAP_ACTIVATE_MAP(new_th->map, new_th);			\
	}								\
        kpdp = current_cpu_datap()->cpu_copywindow_pdp;			\
        for (i = 0; i < NCOPY_WINDOWS; i++) {				\
                if (new_th->machine.copy_window[i].user_base != (user_addr_t)-1) {	\
	                updp = pmap_pde(new_th->map->pmap,		\
                              new_th->machine.copy_window[i].user_base);\
                        pmap_store_pte(kpdp, updp ? *updp : 0);		\
                }							\
                kpdp++;							\
        }								\
	splx(spl);							\
        if (new_th->machine.copyio_state == WINDOWS_OPENED)		\
                need_flush = 1;						\
        else								\
                new_th->machine.copyio_state = WINDOWS_DIRTY;		\
        if (new_th->machine.physwindow_pte) {				\
	  pmap_store_pte((current_cpu_datap()->cpu_physwindow_ptep),	\
			       new_th->machine.physwindow_pte);	        \
                if (need_flush == 0)					\
                        invlpg((uintptr_t)current_cpu_datap()->cpu_physwindow_base);\
        }								\
        if (need_flush)							\
                flush_tlb();						\
}

#else /* __x86_64__ */
#define	PMAP_SWITCH_CONTEXT(old_th, new_th, my_cpu) {			\
	spl_t		spl;						\
                                                                        \
        spl = splhigh();						\
	if (old_th->map != new_th->map) {				\
		PMAP_DEACTIVATE_MAP(old_th->map, old_th);		\
		PMAP_ACTIVATE_MAP(new_th->map, new_th);			\
	}								\
	splx(spl);							\
}
#endif /* __i386__ */

#ifdef __i386__
#define	PMAP_SWITCH_USER(th, new_map, my_cpu) {				\
	spl_t		spl;						\
									\
	spl = splhigh();						\
	PMAP_DEACTIVATE_MAP(th->map, th);				\
	th->map = new_map;						\
	PMAP_ACTIVATE_MAP(th->map, th);					\
	splx(spl);							\
        inval_copy_windows(th);						\
}
#else
#define	PMAP_SWITCH_USER(th, new_map, my_cpu) {				\
	spl_t		spl;						\
									\
	spl = splhigh();						\
	PMAP_DEACTIVATE_MAP(th->map, th);				\
	th->map = new_map;						\
	PMAP_ACTIVATE_MAP(th->map, th);					\
	splx(spl);							\
}
#endif

/*
 * Marking the current cpu's cr3 inactive is achieved by setting its lsb.
 * Marking the current cpu's cr3 active once more involves clearng this bit.
 * Note that valid page tables are page-aligned and so the bottom 12 bits
 * are noramlly zero.
 * We can only mark the current cpu active/inactive but we can test any cpu.
 */
#define CPU_CR3_MARK_INACTIVE()						\
	current_cpu_datap()->cpu_active_cr3 |= 1

#define CPU_CR3_MARK_ACTIVE()	 					\
	current_cpu_datap()->cpu_active_cr3 &= ~1

#define CPU_CR3_IS_ACTIVE(cpu)						\
	((cpu_datap(cpu)->cpu_active_cr3 & 1) == 0)

#define CPU_GET_ACTIVE_CR3(cpu)						\
	(cpu_datap(cpu)->cpu_active_cr3 & ~1)

#define CPU_GET_TASK_CR3(cpu)						\
	(cpu_datap(cpu)->cpu_task_cr3)

/*
 *	Mark this cpu idle, and remove it from the active set,
 *	since it is not actively using any pmap.  Signal_cpus
 *	will notice that it is idle, and avoid signaling it,
 *	but will queue the update request for when the cpu
 *	becomes active.
 */
#if   defined(__x86_64__)
#define MARK_CPU_IDLE(my_cpu)	{					\
	int	s = splhigh();						\
	CPU_CR3_MARK_INACTIVE();					\
	__asm__ volatile("mfence");					\
	splx(s);							\
}
#else /* __i386__ native */
#define MARK_CPU_IDLE(my_cpu)	{					\
	/*								\
	 *	Mark this cpu idle, and remove it from the active set,	\
	 *	since it is not actively using any pmap.  Signal_cpus	\
	 *	will notice that it is idle, and avoid signaling it,	\
	 *	but will queue the update request for when the cpu	\
	 *	becomes active.						\
	 */								\
	int	s = splhigh();						\
	if (!cpu_mode_is64bit() || no_shared_cr3)			\
		process_pmap_updates();					\
	else								\
		pmap_load_kernel_cr3();					\
	CPU_CR3_MARK_INACTIVE();					\
	__asm__ volatile("mfence");					\
	splx(s);							\
}
#endif /* __i386__ */

#define MARK_CPU_ACTIVE(my_cpu) {					\
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
	CPU_CR3_MARK_ACTIVE();						\
	__asm__ volatile("mfence");					\
									\
	if (current_cpu_datap()->cpu_tlb_invalid)			\
	    process_pmap_updates();					\
	splx(s);							\
}

#define PMAP_CONTEXT(pmap, thread)

#define pmap_kernel_va(VA)	\
	((((vm_offset_t) (VA)) >= vm_min_kernel_address) &&	\
	 (((vm_offset_t) (VA)) <= vm_max_kernel_address))


#define pmap_resident_count(pmap)	((pmap)->stats.resident_count)
#define pmap_resident_max(pmap)		((pmap)->stats.resident_max)
#define	pmap_copy(dst_pmap,src_pmap,dst_addr,len,src_addr)
#define	pmap_attribute(pmap,addr,size,attr,value) \
					(KERN_INVALID_ADDRESS)
#define	pmap_attribute_cache_sync(addr,size,attr,value) \
					(KERN_INVALID_ADDRESS)

#define MACHINE_PMAP_IS_EMPTY 1
extern boolean_t pmap_is_empty(pmap_t		pmap,
			       vm_map_offset_t	start,
			       vm_map_offset_t	end);


#endif	/* ASSEMBLER */


#endif	/* _PMAP_MACHINE_ */


#endif  /* KERNEL_PRIVATE */

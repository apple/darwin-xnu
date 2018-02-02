/*
 *
 * Copyright (c) 2007-2016 Apple Inc. All rights reserved.
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
#ifndef _ARM_PMAP_H_
#define _ARM_PMAP_H_	1

#include <mach_assert.h>

#include <arm/proc_reg.h>
#if defined(__arm64__)
#include <arm64/proc_reg.h>
#endif

/*
 *	Machine-dependent structures for the physical map module.
 */

#ifndef ASSEMBLER

#include <mach/kern_return.h>
#include <mach/machine/vm_types.h>
#include <mach/vm_prot.h>
#include <mach/vm_statistics.h>
#include <mach/machine/vm_param.h>
#include <kern/kern_types.h>
#include <kern/thread.h>
#include <kern/queue.h>

/* Base address for low globals. */
#define LOW_GLOBAL_BASE_ADDRESS 0xfffffff000000000ULL

/*
 * This indicates (roughly) where there is free space for the VM
 * to use for the heap; this does not need to be precise.
 */
#if __ARM64_PMAP_SUBPAGE_L1__ && __ARM_16K_PG__
#define KERNEL_PMAP_HEAP_RANGE_START VM_MIN_KERNEL_AND_KEXT_ADDRESS
#else
#define KERNEL_PMAP_HEAP_RANGE_START LOW_GLOBAL_BASE_ADDRESS
#endif

#if defined(__arm64__)

typedef uint64_t	tt_entry_t;					/* translation table entry type */
#define TT_ENTRY_NULL	 ((tt_entry_t *) 0)

typedef uint64_t	pt_entry_t;					/* page table entry type */
#define PT_ENTRY_NULL	 ((pt_entry_t *) 0)

typedef	uint64_t	pmap_paddr_t;				/* physical address (not ppnum_t) */

#elif defined(__arm__)

typedef uint32_t	 tt_entry_t;				/* translation table entry type */
#define PT_ENTRY_NULL	 ((pt_entry_t *) 0)

typedef uint32_t	pt_entry_t;					/* page table entry type */
#define TT_ENTRY_NULL	 ((tt_entry_t *) 0)

typedef  uint32_t       pmap_paddr_t;			/* physical address (not ppnum_t) */

#else
#error unknown arch
#endif


/* superpages */
#define SUPERPAGE_NBASEPAGES 1	/* No superpages support */

/*
 *      Convert addresses to pages and vice versa.
 *      No rounding is used.
 */
#define arm_atop(x)         (((vm_map_address_t)(x)) >> ARM_PGSHIFT)
#define arm_ptoa(x)         (((vm_map_address_t)(x)) << ARM_PGSHIFT)

/*
 *      Round off or truncate to the nearest page.  These will work
 *      for either addresses or counts.  (i.e. 1 byte rounds to 1 page
 *      bytes.
 */
#define arm_round_page(x)   \
	((((vm_map_address_t)(x)) + ARM_PGMASK) & ~ARM_PGMASK)
#define arm_trunc_page(x)   (((vm_map_address_t)(x)) & ~ARM_PGMASK)

/* Convert address offset to page table index */
#define ptenum(a) ((((a) & ARM_TT_LEAF_INDEX_MASK) >> ARM_TT_LEAF_SHIFT))

/*
 * For setups where the kernel page size does not match the hardware
 * page size (assumably, the kernel page size must be a multiple of
 * the hardware page size), we will need to determine what the page
 * ratio is.
 */
#define PAGE_RATIO			((1 << PAGE_SHIFT) >> ARM_PGSHIFT)
#define TEST_PAGE_RATIO_4	(PAGE_RATIO == 4)

#if (__ARM_VMSA__ <= 7)
#define NTTES	(ARM_PGBYTES / sizeof(tt_entry_t))
#define NPTES	((ARM_PGBYTES/4) /sizeof(pt_entry_t))
#else
#define NTTES	(ARM_PGBYTES / sizeof(tt_entry_t))
#define NPTES	(ARM_PGBYTES / sizeof(pt_entry_t))
#endif

extern void flush_mmu_tlb(void);
extern void flush_core_tlb(void);
#if defined(__arm64__)
extern void flush_mmu_tlb_allentries(uint64_t, uint64_t);
extern void flush_mmu_tlb_entry(uint64_t);
extern void flush_mmu_tlb_entries(uint64_t, uint64_t);
extern void flush_mmu_tlb_asid(uint64_t);
extern void flush_core_tlb_asid(uint64_t);
/*
 * TLBI appers to only deal in 4KB page addresses, so give
 * it an explicit shift of 12.
 */
#define TLBI_ADDR_SIZE 44
#define TLBI_ADDR_MASK ((1ULL << TLBI_ADDR_SIZE) - 1)
#define TLBI_ADDR_SHIFT (12)
#define tlbi_addr(x) (((x) >> TLBI_ADDR_SHIFT) & TLBI_ADDR_MASK)

#define	TLBI_ASID_SHIFT	48
#define TLBI_ASID_SIZE 16
#define TLBI_ASID_MASK (((1ULL << TLBI_ASID_SIZE) - 1) << TLBI_ASID_SHIFT)
#define tlbi_asid(x) (((uint64_t)x << TLBI_ASID_SHIFT) & TLBI_ASID_MASK)
#else
extern void flush_mmu_tlb_entry(uint32_t);
extern void flush_mmu_tlb_entries(uint32_t, uint32_t);
extern void flush_mmu_tlb_mva_entries(uint32_t);
extern void flush_mmu_tlb_asid(uint32_t);
extern void flush_core_tlb_asid(uint32_t);
#endif
extern void flush_mmu_tlb_region(vm_offset_t va, unsigned length);

#if defined(__arm64__)
extern uint64_t get_mmu_control(void);
extern uint64_t get_aux_control(void);
extern void set_aux_control(uint64_t);
extern void set_mmu_ttb(uint64_t);
extern void set_mmu_ttb_alternate(uint64_t);
extern uint64_t get_tcr(void);
extern void set_tcr(uint64_t);
#else
extern uint32_t get_mmu_control(void);
extern void set_mmu_control(uint32_t);
extern uint32_t get_aux_control(void);
extern void set_aux_control(uint32_t);
extern void set_mmu_ttb(pmap_paddr_t);
extern void set_mmu_ttb_alternate(pmap_paddr_t);
extern void set_context_id(uint32_t);
#endif

extern pmap_paddr_t get_mmu_ttb(void);
extern pmap_paddr_t mmu_kvtop(vm_offset_t va); 
extern pmap_paddr_t mmu_kvtop_wpreflight(vm_offset_t va); 
extern pmap_paddr_t mmu_uvtop(vm_offset_t va); 

#if (__ARM_VMSA__ <= 7)
/* Convert address offset to translation table index */
#define ttenum(a)		((a) >>	ARM_TT_L1_SHIFT)

/* Convert translation table index to user virtual address */
#define tteitova(a)		((a) << ARM_TT_L1_SHIFT)

#define pa_to_suptte(a)		((a) & ARM_TTE_SUPER_L1_MASK)
#define suptte_to_pa(p)		((p) & ARM_TTE_SUPER_L1_MASK)

#define pa_to_sectte(a)		((a) & ARM_TTE_BLOCK_L1_MASK)
#define sectte_to_pa(p)		((p) & ARM_TTE_BLOCK_L1_MASK)

#define pa_to_tte(a)		((a) & ARM_TTE_TABLE_MASK)
#define tte_to_pa(p)		((p) & ARM_TTE_TABLE_MASK)

#define pa_to_pte(a)		((a) & ARM_PTE_PAGE_MASK)
#define pte_to_pa(p)		((p) & ARM_PTE_PAGE_MASK)
#define pte_increment_pa(p)	((p) += ptoa(1))

#define	ARM_NESTING_SIZE_MIN	((PAGE_SIZE/0x1000)*4*ARM_TT_L1_SIZE)
#define	ARM_NESTING_SIZE_MAX	((256*ARM_TT_L1_SIZE))

#else

/* Convert address offset to translation table index */
#define ttel0num(a)	((a & ARM_TTE_L0_MASK) >> ARM_TT_L0_SHIFT)
#define ttel1num(a)	((a & ARM_TTE_L1_MASK) >> ARM_TT_L1_SHIFT)
#define ttel2num(a)	((a & ARM_TTE_L2_MASK) >> ARM_TT_L2_SHIFT)

#define pa_to_tte(a)		((a) & ARM_TTE_TABLE_MASK)
#define tte_to_pa(p)		((p) & ARM_TTE_TABLE_MASK)

#define pa_to_pte(a)		((a) & ARM_PTE_MASK)
#define pte_to_pa(p)		((p) & ARM_PTE_MASK)
#define pte_to_ap(p)		(((p) & ARM_PTE_APMASK) >> ARM_PTE_APSHIFT)
#define pte_increment_pa(p)	((p) += ptoa(1))

#define	ARM_NESTING_SIZE_MIN	((PAGE_SIZE/ARM_PGBYTES)*ARM_TT_L2_SIZE)
#define	ARM_NESTING_SIZE_MAX	(0x0000000010000000ULL)

#define TLBFLUSH_SIZE	(ARM_TTE_MAX/((sizeof(unsigned int))*BYTE_SIZE))

#endif	/* __ARM_VMSA__ <= 7 */

#define	PMAP_GC_INFLIGHT	1
#define	PMAP_GC_WAIT		2

/*
 *	Convert translation/page table entry to kernel virtual address
 */
#define ttetokv(a)      (phystokv(tte_to_pa(a)))
#define ptetokv(a)      (phystokv(pte_to_pa(a)))

struct pmap {
	tt_entry_t			*tte;			/* translation table entries */
	pmap_paddr_t		ttep;			/* translation table physical */
	vm_map_address_t	min;			/* min address in pmap */
	vm_map_address_t	max;			/* max address in pmap */
	unsigned int		asid;			/* address space id */
	unsigned int		vasid;			/* Virtual address space id */
	unsigned int		stamp;			/* creation stamp */
	unsigned int		wired;			/* wired bits */
	volatile uint32_t	ref_count;		/* pmap reference count */
	unsigned int		cpu_ref;		/* number of cpus using pmap */
	unsigned int		gc_status;		/* gc status */
	ledger_t			ledger;			/* ledger tracking phys mappings */
	decl_simple_lock_data(,lock)		/* lock on map */
	struct pmap_statistics	stats;		/* map statistics */
	queue_chain_t		pmaps;			/* global list of pmaps */
	tt_entry_t			*tt_entry_free;	/* free translation table entries */
	tt_entry_t			*prev_tte;		/* previous translation table */
	unsigned int		tte_index_max;	/* max tte index in translation table entries */
	boolean_t			nx_enabled;		/* no execute */
	boolean_t			nested;			/* is nested */
	boolean_t			is_64bit;		/* is 64bit */
	struct pmap			*nested_pmap;	/* nested pmap */
	vm_map_address_t	nested_region_grand_addr;
	vm_map_address_t	nested_region_subord_addr;
	vm_map_offset_t		nested_region_size;
	unsigned int		*nested_region_asid_bitmap;
	unsigned int		nested_region_asid_bitmap_size;

#if (__ARM_VMSA__ <= 7)
	decl_simple_lock_data(,tt1_lock)	/* lock on tt1 */
#endif
#if MACH_ASSERT
	int					pmap_pid;
	char				pmap_procname[17];
#endif /* MACH_ASSERT */
#if DEVELOPMENT || DEBUG
	boolean_t		footprint_suspended;
	boolean_t		footprint_was_suspended;
#endif /* DEVELOPMENT || DEBUG */
};

/* typedef struct pmap *pmap_t; */
#define PMAP_NULL       ((pmap_t) 0)


/*
 * WIMG control
 */
#define	VM_MEM_INNER		0x10
#define VM_MEM_EARLY_ACK	0x20

#define	VM_WIMG_DEFAULT		(VM_MEM_COHERENT)
#define	VM_WIMG_COPYBACK	(VM_MEM_COHERENT)
#define	VM_WIMG_INNERWBACK	(VM_MEM_COHERENT | VM_MEM_INNER)
#define VM_WIMG_IO		(VM_MEM_COHERENT | VM_MEM_NOT_CACHEABLE | VM_MEM_GUARDED)
#define VM_WIMG_POSTED		(VM_MEM_COHERENT | VM_MEM_NOT_CACHEABLE | VM_MEM_GUARDED | VM_MEM_EARLY_ACK)
#define VM_WIMG_WTHRU		(VM_MEM_WRITE_THROUGH | VM_MEM_COHERENT | VM_MEM_GUARDED)
#define VM_WIMG_WCOMB		(VM_MEM_NOT_CACHEABLE | VM_MEM_COHERENT) 


#if VM_DEBUG
extern int      pmap_list_resident_pages(
                        pmap_t          pmap,
                        vm_offset_t  *listp,
                        int             space
                );
#else /* #if VM_DEBUG */
#define pmap_list_resident_pages(pmap, listp, space) (0)
#endif /* #if VM_DEBUG */

extern int copysafe(vm_map_address_t from, vm_map_address_t to, uint32_t cnt, int type, uint32_t *bytes_copied);

/* globals shared between arm_vm_init and pmap */
extern tt_entry_t *cpu_tte;	/* first CPUs translation table (shared with kernel pmap) */
extern pmap_paddr_t cpu_ttep;  /* physical translation table addr */

#if __arm64__
extern void *ropagetable_begin;
extern void *ropagetable_end;
#endif

#if __arm64__
extern tt_entry_t *invalid_tte;	/* global invalid translation table  */
extern pmap_paddr_t invalid_ttep;  /* physical invalid translation table addr */
#endif

#define PMAP_CONTEXT(pmap, thread)

/*
 * platform dependent Prototypes
 */
extern void pmap_switch_user_ttb(pmap_t pmap);
extern void pmap_bootstrap(vm_offset_t);
extern vm_map_address_t	pmap_ptov(pmap_t, ppnum_t);
extern ppnum_t pmap_find_phys(pmap_t map, addr64_t va);
extern void pmap_set_pmap(pmap_t pmap, thread_t thread);
extern void pmap_collect(pmap_t pmap);
extern	void pmap_gc(void);
#if defined(__arm64__)
extern vm_offset_t	pmap_extract(pmap_t pmap, vm_map_offset_t va);
#endif

/*
 * Interfaces implemented as macros.
 */

#define	PMAP_SWITCH_USER(th, new_map, my_cpu) {				\
	th->map = new_map;										\
	pmap_set_pmap(vm_map_pmap(new_map), th);				\
}

#define pmap_kernel()										\
	(kernel_pmap)

#define pmap_compressed(pmap)								\
	((pmap)->stats.compressed)

#define pmap_resident_count(pmap)							\
	((pmap)->stats.resident_count)

#define pmap_resident_max(pmap)								\
	((pmap)->stats.resident_max)

#define MACRO_NOOP

#define pmap_copy(dst_pmap, src_pmap, dst_addr, len, src_addr)		\
	MACRO_NOOP

#define pmap_pageable(pmap, start, end, pageable)			\
	MACRO_NOOP

#define pmap_kernel_va(VA)						\
	(((VA) >= VM_MIN_KERNEL_ADDRESS) && ((VA) <= VM_MAX_KERNEL_ADDRESS))

#define	pmap_attribute(pmap,addr,size,attr,value)			\
	(KERN_INVALID_ADDRESS)

#define copyinmsg(from, to, cnt)							\
	copyin(from, to, cnt)

#define copyoutmsg(from, to, cnt)							\
	copyout(from, to, cnt)

extern pmap_paddr_t kvtophys(vm_offset_t va); 

extern vm_map_address_t pmap_map(vm_map_address_t va, vm_offset_t sa, vm_offset_t ea, vm_prot_t prot, unsigned int flags);
extern vm_map_address_t pmap_map_high_window_bd( vm_offset_t pa, vm_size_t len, vm_prot_t prot);
extern kern_return_t pmap_map_block(pmap_t pmap, addr64_t va, ppnum_t pa, uint32_t size, vm_prot_t prot, int attr, unsigned int flags);
extern void pmap_map_globals(void);

#define PMAP_MAP_BD_DEVICE	0x1
#define PMAP_MAP_BD_WCOMB	0x2
#define PMAP_MAP_BD_POSTED	0x3
#define PMAP_MAP_BD_MASK	0x3

extern vm_map_address_t pmap_map_bd_with_options(vm_map_address_t va, vm_offset_t sa, vm_offset_t ea, vm_prot_t prot, int32_t options);
extern vm_map_address_t pmap_map_bd(vm_map_address_t va, vm_offset_t sa, vm_offset_t ea, vm_prot_t prot);

extern void pmap_init_pte_page(pmap_t, pt_entry_t *, vm_offset_t, unsigned int ttlevel, boolean_t alloc_ptd);
extern void pmap_init_pte_static_page(pmap_t, pt_entry_t *, pmap_paddr_t);

extern boolean_t pmap_valid_address(pmap_paddr_t addr);
extern void pmap_disable_NX(pmap_t pmap);
extern void pmap_set_nested(pmap_t pmap);
extern vm_map_address_t pmap_create_sharedpage(void);
extern void pmap_insert_sharedpage(pmap_t pmap);
extern void pmap_protect_sharedpage(void);

extern vm_offset_t pmap_cpu_windows_copy_addr(int cpu_num, unsigned int index);
extern unsigned int pmap_map_cpu_windows_copy(ppnum_t pn, vm_prot_t prot, unsigned int wimg_bits);
extern void pmap_unmap_cpu_windows_copy(unsigned int index);

extern void pt_fake_zone_init(int);
extern void pt_fake_zone_info(int *, vm_size_t *, vm_size_t *, vm_size_t *, vm_size_t *, 
			      uint64_t *, int *, int *, int *);

extern boolean_t pmap_valid_page(ppnum_t pn);

#define MACHINE_PMAP_IS_EMPTY 1
extern boolean_t pmap_is_empty(pmap_t pmap, vm_map_offset_t start, vm_map_offset_t end);

#define ARM_PMAP_MAX_OFFSET_DEFAULT	0x01
#define ARM_PMAP_MAX_OFFSET_MIN		0x02
#define ARM_PMAP_MAX_OFFSET_MAX		0x04
#define ARM_PMAP_MAX_OFFSET_DEVICE	0x08
#define ARM_PMAP_MAX_OFFSET_JUMBO	0x10

#define ASID_SHIFT			(11)				/* Shift for the maximum virtual ASID value (2048) */
#define MAX_ASID			(1 << ASID_SHIFT)		/* Max supported ASIDs (can be virtual) */
#define ARM_ASID_SHIFT			(8)				/* Shift for the maximum ARM ASID value (256) */
#define ARM_MAX_ASID			(1 << ARM_ASID_SHIFT)		/* Max ASIDs supported by the hardware */
#define ASID_VIRT_BITS			(ASID_SHIFT - ARM_ASID_SHIFT)	/* The number of virtual bits in a virtaul ASID */
#define NBBY				8

extern vm_map_offset_t pmap_max_offset(boolean_t is64, unsigned int option);

boolean_t pmap_virtual_region(unsigned int region_select, vm_map_offset_t *startp, vm_map_size_t *size);

boolean_t pmap_enforces_execute_only(pmap_t pmap);

/* pmap dispatch indices */
#define ARM_FAST_FAULT_INDEX 0
#define ARM_FORCE_FAST_FAULT_INDEX 1
#define MAPPING_FREE_PRIME_INDEX 2
#define MAPPING_REPLENISH_INDEX 3
#define PHYS_ATTRIBUTE_CLEAR_INDEX 4
#define PHYS_ATTRIBUTE_SET_INDEX 5
#define PMAP_BATCH_SET_CACHE_ATTRIBUTES_INDEX 6
#define PMAP_CHANGE_WIRING_INDEX 7
#define PMAP_CREATE_INDEX 8
#define PMAP_DESTROY_INDEX 9
#define PMAP_ENTER_OPTIONS_INDEX 10
#define PMAP_EXTRACT_INDEX 11
#define PMAP_FIND_PHYS_INDEX 12
#define PMAP_INSERT_SHAREDPAGE_INDEX 13
#define PMAP_IS_EMPTY_INDEX 14
#define PMAP_MAP_CPU_WINDOWS_COPY_INDEX 15
#define PMAP_MARK_PAGE_AS_PMAP_PAGE_INDEX 16
#define PMAP_NEST_INDEX 17
#define PMAP_PAGE_PROTECT_OPTIONS_INDEX 18
#define PMAP_PROTECT_OPTIONS_INDEX 19
#define PMAP_QUERY_PAGE_INFO_INDEX 20
#define PMAP_QUERY_RESIDENT_INDEX 21
#define PMAP_REFERENCE_INDEX 22
#define PMAP_REMOVE_OPTIONS_INDEX 23
#define PMAP_RETURN_INDEX 24
#define PMAP_SET_CACHE_ATTRIBUTES_INDEX 25
#define PMAP_SET_NESTED_INDEX 26
#define PMAP_SET_PROCESS_INDEX 27
#define PMAP_SWITCH_INDEX 28
#define PMAP_SWITCH_USER_TTB_INDEX 29
#define PMAP_UNHINT_KV_ADDR_INDEX 30
#define PMAP_UNMAP_CPU_WINDOWS_COPY_INDEX 31
#define PMAP_UNNEST_OPTIONS_INDEX 32
#define PMAP_FOOTPRINT_SUSPEND_INDEX 33
#define PMAP_CPU_DATA_INIT_INDEX 34
#define PMAP_RELEASE_PAGES_TO_KERNEL_INDEX 35

#define MAX_PMAP_INDEX 36

#define PMAP_INVALID_CPU_NUM (~0U)

struct pmap_cpu_data {
	pmap_t cpu_user_pmap;
	unsigned int cpu_number;
	unsigned int cpu_user_pmap_stamp;

	/*
	 * This supports overloading of ARM ASIDs by the pmap.  The field needs
	 * to be wide enough to cover all the virtual bits in a virtual ASID.
	 * With 256 physical ASIDs, 8-bit fields let us support up to 65536
	 * Virtual ASIDs, minus all that would map on to 0 (as 0 is a global
	 * ASID).
	 *
	 * If we were to use bitfield shenanigans here, we could save a bit of
	 * memory by only having enough bits to support MAX_ASID.  However, such
	 * an implementation would be more error prone.
	 */
	uint8_t cpu_asid_high_bits[ARM_MAX_ASID];
};

typedef struct pmap_cpu_data pmap_cpu_data_t;

/* Initialize the pmap per-CPU data for the current CPU. */
extern void pmap_cpu_data_init(void);

/* Get the pmap per-CPU data for the current CPU. */
extern pmap_cpu_data_t * pmap_get_cpu_data(void);

#define MARK_AS_PMAP_TEXT
#define MARK_AS_PMAP_DATA

extern kern_return_t pmap_return(boolean_t do_panic, boolean_t do_recurse);

#endif /* #ifndef ASSEMBLER */

#endif /* #ifndef _ARM_PMAP_H_ */

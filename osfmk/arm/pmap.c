/*
 * Copyright (c) 2011-2016 Apple Inc. All rights reserved.
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
#include <string.h>
#include <mach_assert.h>
#include <mach_ldebug.h>

#include <mach/shared_region.h>
#include <mach/vm_param.h>
#include <mach/vm_prot.h>
#include <mach/vm_map.h>
#include <mach/machine/vm_param.h>
#include <mach/machine/vm_types.h>

#include <mach/boolean.h>
#include <kern/thread.h>
#include <kern/sched.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <kern/ledger.h>
#include <kern/misc_protos.h>
#include <kern/spl.h>
#include <kern/xpr.h>

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_protos.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/cpm.h>

#include <libkern/section_keywords.h>

#include <machine/atomic.h>
#include <machine/thread.h>
#include <machine/lowglobals.h>

#include <arm/caches_internal.h>
#include <arm/cpu_data.h>
#include <arm/cpu_data_internal.h>
#include <arm/cpu_capabilities.h>
#include <arm/cpu_number.h>
#include <arm/machine_cpu.h>
#include <arm/misc_protos.h>
#include <arm/trap.h>

#include <libkern/section_keywords.h>

#if	(__ARM_VMSA__ > 7)
#include <arm64/proc_reg.h>
#include <pexpert/arm64/boot.h>
#if CONFIG_PGTRACE
#include <stdint.h>
#include <arm64/pgtrace.h>
#if CONFIG_PGTRACE_NONKEXT
#include <arm64/pgtrace_decoder.h>
#endif // CONFIG_PGTRACE_NONKEXT
#endif
#endif

#include <pexpert/device_tree.h>

#include <san/kasan.h>

#if MACH_ASSERT
int pmap_stats_assert = 1;
#define PMAP_STATS_ASSERTF(cond, pmap, fmt, ...)		    \
	MACRO_BEGIN					    \
	if (pmap_stats_assert && (pmap)->pmap_stats_assert) \
		assertf(cond, fmt, ##__VA_ARGS__);		    \
	MACRO_END
#else /* MACH_ASSERT */
#define PMAP_STATS_ASSERTF(cond, pmap, fmt, ...)
#endif /* MACH_ASSERT */

#if DEVELOPMENT || DEBUG
#define PMAP_FOOTPRINT_SUSPENDED(pmap) ((pmap)->footprint_suspended)
#else /* DEVELOPMENT || DEBUG */
#define PMAP_FOOTPRINT_SUSPENDED(pmap) (FALSE)
#endif /* DEVELOPMENT || DEBUG */



#if DEVELOPMENT || DEBUG
int panic_on_unsigned_execute = 0;
#endif /* DEVELOPMENT || DEBUG */


/* Virtual memory region for early allocation */
#if	(__ARM_VMSA__ == 7)
#define VREGION1_START		(VM_HIGH_KERNEL_WINDOW & ~ARM_TT_L1_PT_OFFMASK)
#else
#define VREGION1_HIGH_WINDOW	(PE_EARLY_BOOT_VA)
#define VREGION1_START		((VM_MAX_KERNEL_ADDRESS & CPUWINDOWS_BASE_MASK) - VREGION1_HIGH_WINDOW)
#endif
#define VREGION1_SIZE		(trunc_page(VM_MAX_KERNEL_ADDRESS - (VREGION1_START)))

extern unsigned int not_in_kdp;

extern vm_offset_t first_avail;

extern pmap_paddr_t avail_start;
extern pmap_paddr_t avail_end;

extern vm_offset_t     virtual_space_start;	/* Next available kernel VA */
extern vm_offset_t     virtual_space_end;	/* End of kernel address space */

extern int hard_maxproc;

#if (__ARM_VMSA__ > 7)
/* The number of address bits one TTBR can cover. */
#define PGTABLE_ADDR_BITS (64ULL - T0SZ_BOOT)

/*
 * The bounds on our TTBRs.  These are for sanity checking that
 * an address is accessible by a TTBR before we attempt to map it.
 */
#define ARM64_TTBR0_MIN_ADDR (0ULL)
#define ARM64_TTBR0_MAX_ADDR (0ULL + (1ULL << PGTABLE_ADDR_BITS) - 1)
#define ARM64_TTBR1_MIN_ADDR (0ULL - (1ULL << PGTABLE_ADDR_BITS))
#define ARM64_TTBR1_MAX_ADDR (~0ULL)

/* The level of the root of a page table. */
const uint64_t arm64_root_pgtable_level = (3 - ((PGTABLE_ADDR_BITS - 1 - ARM_PGSHIFT) / (ARM_PGSHIFT - TTE_SHIFT)));

/* The number of entries in the root TT of a page table. */
const uint64_t arm64_root_pgtable_num_ttes = (2 << ((PGTABLE_ADDR_BITS - 1 - ARM_PGSHIFT) % (ARM_PGSHIFT - TTE_SHIFT)));
#else
const uint64_t arm64_root_pgtable_level = 0;
const uint64_t arm64_root_pgtable_num_ttes = 0;
#endif

struct pmap                     kernel_pmap_store MARK_AS_PMAP_DATA;
SECURITY_READ_ONLY_LATE(pmap_t) kernel_pmap = &kernel_pmap_store;

struct vm_object pmap_object_store __attribute__((aligned(VM_PACKED_POINTER_ALIGNMENT)));	/* store pt pages */
vm_object_t     pmap_object = &pmap_object_store;

static struct zone *pmap_zone;	/* zone of pmap structures */

decl_simple_lock_data(, pmaps_lock MARK_AS_PMAP_DATA)
unsigned int	pmap_stamp MARK_AS_PMAP_DATA;
queue_head_t	map_pmap_list MARK_AS_PMAP_DATA;

queue_head_t	tt_pmap_list MARK_AS_PMAP_DATA;
unsigned int	tt_pmap_count MARK_AS_PMAP_DATA;
unsigned int	tt_pmap_max MARK_AS_PMAP_DATA;

decl_simple_lock_data(, pt_pages_lock MARK_AS_PMAP_DATA)
queue_head_t	pt_page_list MARK_AS_PMAP_DATA;	/* pt page ptd entries list */

decl_simple_lock_data(, pmap_pages_lock MARK_AS_PMAP_DATA)

typedef struct page_free_entry {
	struct page_free_entry	*next;
} page_free_entry_t;

#define PAGE_FREE_ENTRY_NULL	((page_free_entry_t *) 0)

page_free_entry_t	*pmap_pages_reclaim_list MARK_AS_PMAP_DATA;	/* Reclaimed pt page list */
unsigned int		pmap_pages_request_count MARK_AS_PMAP_DATA;	/* Pending requests to reclaim pt page */
unsigned long long	pmap_pages_request_acum MARK_AS_PMAP_DATA;


typedef struct tt_free_entry {
	struct tt_free_entry	*next;
} tt_free_entry_t;

#define TT_FREE_ENTRY_NULL	((tt_free_entry_t *) 0)

tt_free_entry_t	*free_page_size_tt_list MARK_AS_PMAP_DATA;
unsigned int	free_page_size_tt_count MARK_AS_PMAP_DATA;
unsigned int	free_page_size_tt_max MARK_AS_PMAP_DATA;
#define	FREE_PAGE_SIZE_TT_MAX	4
tt_free_entry_t	*free_two_page_size_tt_list MARK_AS_PMAP_DATA;
unsigned int	free_two_page_size_tt_count MARK_AS_PMAP_DATA;
unsigned int	free_two_page_size_tt_max MARK_AS_PMAP_DATA;
#define	FREE_TWO_PAGE_SIZE_TT_MAX	4
tt_free_entry_t	*free_tt_list MARK_AS_PMAP_DATA;
unsigned int	free_tt_count MARK_AS_PMAP_DATA;
unsigned int	free_tt_max MARK_AS_PMAP_DATA;

#define TT_FREE_ENTRY_NULL	((tt_free_entry_t *) 0)

boolean_t pmap_gc_allowed MARK_AS_PMAP_DATA = TRUE;
boolean_t pmap_gc_forced MARK_AS_PMAP_DATA = FALSE;
boolean_t pmap_gc_allowed_by_time_throttle = TRUE;

unsigned int    inuse_user_ttepages_count MARK_AS_PMAP_DATA = 0;	/* non-root, non-leaf user pagetable pages, in units of PAGE_SIZE */
unsigned int    inuse_user_ptepages_count MARK_AS_PMAP_DATA = 0;	/* leaf user pagetable pages, in units of PAGE_SIZE */
unsigned int	inuse_user_tteroot_count MARK_AS_PMAP_DATA = 0;  /* root user pagetables, in units of PMAP_ROOT_ALLOC_SIZE */
unsigned int    inuse_kernel_ttepages_count MARK_AS_PMAP_DATA = 0; /* non-root, non-leaf kernel pagetable pages, in units of PAGE_SIZE */
unsigned int    inuse_kernel_ptepages_count MARK_AS_PMAP_DATA = 0; /* leaf kernel pagetable pages, in units of PAGE_SIZE */
unsigned int	inuse_kernel_tteroot_count MARK_AS_PMAP_DATA = 0; /* root kernel pagetables, in units of PMAP_ROOT_ALLOC_SIZE */
unsigned int    inuse_pmap_pages_count = 0;	/* debugging */

SECURITY_READ_ONLY_LATE(tt_entry_t *) invalid_tte  = 0;
SECURITY_READ_ONLY_LATE(pmap_paddr_t) invalid_ttep = 0;

SECURITY_READ_ONLY_LATE(tt_entry_t *) cpu_tte  = 0;			/* set by arm_vm_init() - keep out of bss */
SECURITY_READ_ONLY_LATE(pmap_paddr_t) cpu_ttep = 0;			/* set by arm_vm_init() - phys tte addr */

#if DEVELOPMENT || DEBUG
int nx_enabled = 1;					/* enable no-execute protection */
int allow_data_exec  = 0;				/* No apps may execute data */
int allow_stack_exec = 0;				/* No apps may execute from the stack */
#else /* DEVELOPMENT || DEBUG */
const int nx_enabled = 1;					/* enable no-execute protection */
const int allow_data_exec  = 0;				/* No apps may execute data */
const int allow_stack_exec = 0;				/* No apps may execute from the stack */
#endif /* DEVELOPMENT || DEBUG */

/*
 *      pv_entry_t - structure to track the active mappings for a given page
 */
typedef struct pv_entry {
		struct pv_entry	*pve_next;	/* next alias */
		pt_entry_t	*pve_ptep;	/* page table entry */
#if __arm__ && (__BIGGEST_ALIGNMENT__ > 4)
/* For the newer ARMv7k ABI where 64-bit types are 64-bit aligned, but pointers
 * are 32-bit:
 * Since pt_desc is 64-bit aligned and we cast often from pv_entry to
 * pt_desc.
 */
} __attribute__ ((aligned(8))) pv_entry_t;
#else
} pv_entry_t;
#endif

#define PV_ENTRY_NULL	((pv_entry_t *) 0)

/*
 * PMAP LEDGERS:
 * We use the least significant bit of the "pve_next" pointer in a "pv_entry"
 * as a marker for pages mapped through an "alternate accounting" mapping.
 * These macros set, clear and test for this marker and extract the actual
 * value of the "pve_next" pointer.
 */
#define PVE_NEXT_ALTACCT	((uintptr_t) 0x1)
#define PVE_NEXT_SET_ALTACCT(pve_next_p) \
	*(pve_next_p) = (struct pv_entry *) (((uintptr_t) *(pve_next_p)) | \
					     PVE_NEXT_ALTACCT)
#define PVE_NEXT_CLR_ALTACCT(pve_next_p) \
	*(pve_next_p) = (struct pv_entry *) (((uintptr_t) *(pve_next_p)) & \
					     ~PVE_NEXT_ALTACCT)
#define PVE_NEXT_IS_ALTACCT(pve_next)	\
	((((uintptr_t) (pve_next)) & PVE_NEXT_ALTACCT) ? TRUE : FALSE)
#define PVE_NEXT_PTR(pve_next) \
	((struct pv_entry *)(((uintptr_t) (pve_next)) & \
			     ~PVE_NEXT_ALTACCT))
#if MACH_ASSERT
static void pmap_check_ledgers(pmap_t pmap);
#else
static inline void pmap_check_ledgers(__unused pmap_t pmap) {}
#endif /* MACH_ASSERT */

SECURITY_READ_ONLY_LATE(pv_entry_t **) pv_head_table;		/* array of pv entry pointers */

pv_entry_t		*pv_free_list MARK_AS_PMAP_DATA;
pv_entry_t		*pv_kern_free_list MARK_AS_PMAP_DATA;
decl_simple_lock_data(,pv_free_list_lock MARK_AS_PMAP_DATA)
decl_simple_lock_data(,pv_kern_free_list_lock MARK_AS_PMAP_DATA)

decl_simple_lock_data(,phys_backup_lock)

/*
 *		pt_desc - structure to keep info on page assigned to page tables
 */
#if (__ARM_VMSA__ == 7)
#define	PT_INDEX_MAX	1
#else
#if (ARM_PGSHIFT == 14)
#define	PT_INDEX_MAX	1
#else
#define	PT_INDEX_MAX	4
#endif
#endif

#define	PT_DESC_REFCOUNT	0x4000U

typedef struct pt_desc {
	queue_chain_t		pt_page;
	struct {
		unsigned short	refcnt;
		unsigned short	wiredcnt;
	} pt_cnt[PT_INDEX_MAX];
	struct pmap			*pmap;
	struct {
		vm_offset_t		va;
	} pt_map[PT_INDEX_MAX];
} pt_desc_t;


#define PTD_ENTRY_NULL	((pt_desc_t *) 0)

SECURITY_READ_ONLY_LATE(pt_desc_t *) ptd_root_table;

pt_desc_t		*ptd_free_list MARK_AS_PMAP_DATA = PTD_ENTRY_NULL;
SECURITY_READ_ONLY_LATE(boolean_t) ptd_preboot = TRUE;
unsigned int	ptd_free_count MARK_AS_PMAP_DATA = 0;
decl_simple_lock_data(,ptd_free_list_lock MARK_AS_PMAP_DATA)

/*
 *	physical page attribute
 */
typedef	u_int16_t pp_attr_t;

#define	PP_ATTR_WIMG_MASK		0x003F
#define	PP_ATTR_WIMG(x)			((x) & PP_ATTR_WIMG_MASK)

#define PP_ATTR_REFERENCED		0x0040
#define PP_ATTR_MODIFIED		0x0080

#define PP_ATTR_INTERNAL		0x0100
#define PP_ATTR_REUSABLE		0x0200
#define	PP_ATTR_ALTACCT			0x0400
#define	PP_ATTR_NOENCRYPT		0x0800

#define PP_ATTR_REFFAULT		0x1000
#define PP_ATTR_MODFAULT		0x2000


SECURITY_READ_ONLY_LATE(pp_attr_t*)	pp_attr_table;


typedef uint8_t io_attr_t;

#define IO_ATTR_WIMG_MASK		0x3F
#define IO_ATTR_WIMG(x)			((x) & IO_ATTR_WIMG_MASK)

SECURITY_READ_ONLY_LATE(io_attr_t*)	io_attr_table;

SECURITY_READ_ONLY_LATE(pmap_paddr_t)	vm_first_phys = (pmap_paddr_t) 0;
SECURITY_READ_ONLY_LATE(pmap_paddr_t)	vm_last_phys = (pmap_paddr_t) 0;

SECURITY_READ_ONLY_LATE(pmap_paddr_t)	io_rgn_start = 0;
SECURITY_READ_ONLY_LATE(pmap_paddr_t)	io_rgn_end = 0;
SECURITY_READ_ONLY_LATE(uint32_t)	io_rgn_granule = 0;

SECURITY_READ_ONLY_LATE(boolean_t)	pmap_initialized = FALSE;	/* Has pmap_init completed? */

SECURITY_READ_ONLY_LATE(uint64_t) pmap_nesting_size_min;
SECURITY_READ_ONLY_LATE(uint64_t) pmap_nesting_size_max;

SECURITY_READ_ONLY_LATE(vm_map_offset_t) arm_pmap_max_offset_default  = 0x0;
#if defined(__arm64__)
SECURITY_READ_ONLY_LATE(vm_map_offset_t) arm64_pmap_max_offset_default = 0x0;
#endif

/* free address spaces (1 means free) */
static uint32_t asid_bitmap[MAX_ASID / (sizeof(uint32_t) * NBBY)] MARK_AS_PMAP_DATA;

#if	(__ARM_VMSA__ > 7)
SECURITY_READ_ONLY_LATE(pmap_t) sharedpage_pmap;
#endif


#define pa_index(pa)										\
	(atop((pa) - vm_first_phys))

#define pai_to_pvh(pai)										\
	(&pv_head_table[pai])

#define pa_valid(x) 										\
	((x) >= vm_first_phys && (x) < vm_last_phys)

/* PTE Define Macros */

#define	pte_is_wired(pte)									\
	(((pte) & ARM_PTE_WIRED_MASK) == ARM_PTE_WIRED)

#define	pte_set_wired(ptep, wired)							\
	do {													\
		SInt16	*ptd_wiredcnt_ptr;							\
		ptd_wiredcnt_ptr = (SInt16 *)&(ptep_get_ptd(ptep)->pt_cnt[ARM_PT_DESC_INDEX(ptep)].wiredcnt);	\
		if (wired) {										\
				*ptep |= ARM_PTE_WIRED;						\
				OSAddAtomic16(1, ptd_wiredcnt_ptr);			\
		} else {											\
				*ptep &= ~ARM_PTE_WIRED;					\
				OSAddAtomic16(-1, ptd_wiredcnt_ptr);		\
		}												\
	} while(0)

#define	pte_is_ffr(pte)										\
	(((pte) & ARM_PTE_WRITEABLE) == ARM_PTE_WRITEABLE)

#define	pte_set_ffr(pte, ffr)								\
	do {													\
		if (ffr) {											\
			pte |= ARM_PTE_WRITEABLE;						\
		} else {											\
			pte &= ~ARM_PTE_WRITEABLE;						\
		}													\
	} while(0)

/* PVE Define Macros */

#define pve_next(pve)										\
	((pve)->pve_next)

#define pve_link_field(pve)									\
	(&pve_next(pve))

#define pve_link(pp, e)										\
	((pve_next(e) = pve_next(pp)),	(pve_next(pp) = (e)))

#define pve_unlink(pp, e)									\
	(pve_next(pp) = pve_next(e))

/* bits held in the ptep pointer field */

#define pve_get_ptep(pve)									\
	((pve)->pve_ptep)

#define pve_set_ptep(pve, ptep_new)								\
	do {											\
		(pve)->pve_ptep = (ptep_new);							\
	} while (0)

/* PTEP Define Macros */

#if	(__ARM_VMSA__ == 7)

#define	ARM_PT_DESC_INDEX_MASK		0x00000
#define	ARM_PT_DESC_INDEX_SHIFT		0

	/*
	 * mask for page descriptor index:  4MB per page table
	 */
#define ARM_TT_PT_INDEX_MASK		0xfffU		/* mask for page descriptor index: 4MB per page table  */

	/*
	 * Shift value used for reconstructing the virtual address for a PTE.
	 */
#define ARM_TT_PT_ADDR_SHIFT		(10U)

#define	ARM_PT_DESC_INDEX(ptep)									\
	(((unsigned)(ptep) & ARM_PT_DESC_INDEX_MASK) >> ARM_PT_DESC_INDEX_SHIFT)

#define ptep_get_ptd(ptep)										\
	((struct pt_desc *)((*((vm_offset_t *)(pai_to_pvh(pa_index((vm_offset_t)(ptep) - gVirtBase + gPhysBase))))) & PVH_LIST_MASK))

#define ptep_get_va(ptep)										\
	((((pt_desc_t *) (pvh_list(pai_to_pvh(pa_index((((vm_offset_t)(ptep) & ~0xFFF) - gVirtBase + gPhysBase))))))->pt_map[ARM_PT_DESC_INDEX(ptep)].va)+ ((((unsigned)(ptep)) & ARM_TT_PT_INDEX_MASK)<<ARM_TT_PT_ADDR_SHIFT))

#define ptep_get_pmap(ptep)										\
        ((((pt_desc_t *) (pvh_list(pai_to_pvh(pa_index((((vm_offset_t)(ptep) & ~0xFFF) - gVirtBase + gPhysBase))))))->pmap))


#else

#if (ARM_PGSHIFT == 12)
#define	ARM_PT_DESC_INDEX_MASK		((PAGE_SHIFT_CONST == ARM_PGSHIFT )? 0x00000ULL : 0x03000ULL)
#define	ARM_PT_DESC_INDEX_SHIFT		((PAGE_SHIFT_CONST == ARM_PGSHIFT )? 0 : 12)
	/*
	 * mask for page descriptor index:  2MB per page table
	 */
#define ARM_TT_PT_INDEX_MASK		(0x0fffULL)
	/*
	 * Shift value used for reconstructing the virtual address for a PTE.
	 */
#define ARM_TT_PT_ADDR_SHIFT		(9ULL)

	/* TODO: Give this a better name/documentation than "other" */
#define ARM_TT_PT_OTHER_MASK		(0x0fffULL)

#else

#define	ARM_PT_DESC_INDEX_MASK		(0x00000)
#define	ARM_PT_DESC_INDEX_SHIFT		(0)
	/*
	 * mask for page descriptor index:  32MB per page table
	 */
#define ARM_TT_PT_INDEX_MASK		(0x3fffULL)
	/*
	 * Shift value used for reconstructing the virtual address for a PTE.
	 */
#define ARM_TT_PT_ADDR_SHIFT		(11ULL)

	/* TODO: Give this a better name/documentation than "other" */
#define ARM_TT_PT_OTHER_MASK		(0x3fffULL)
#endif

#define	ARM_PT_DESC_INDEX(ptep)									\
	(((unsigned)(ptep) & ARM_PT_DESC_INDEX_MASK) >> ARM_PT_DESC_INDEX_SHIFT)


#define ptep_get_ptd(ptep)										\
	((struct pt_desc *)((*((vm_offset_t *)(pai_to_pvh(pa_index((vm_offset_t)(ptep) - gVirtBase + gPhysBase))))) & PVH_LIST_MASK))

#define ptep_get_va(ptep)										\
        ((((pt_desc_t *) (pvh_list(pai_to_pvh(pa_index((((vm_offset_t)(ptep) & ~ARM_TT_PT_OTHER_MASK) - gVirtBase + gPhysBase))))))->pt_map[ARM_PT_DESC_INDEX(ptep)].va)+ ((((unsigned)(ptep)) & ARM_TT_PT_INDEX_MASK)<<ARM_TT_PT_ADDR_SHIFT))

#define ptep_get_pmap(ptep)										\
        ((((pt_desc_t *) (pvh_list(pai_to_pvh(pa_index((((vm_offset_t)(ptep) & ~ARM_TT_PT_OTHER_MASK) - gVirtBase + gPhysBase))))))->pmap))

#endif


/* PVH Define Macros */

/* pvhead type */
#define	PVH_TYPE_NULL	0x0UL
#define	PVH_TYPE_PVEP	0x1UL
#define	PVH_TYPE_PTEP	0x2UL
#define	PVH_TYPE_PTDP	0x3UL

#define PVH_TYPE_MASK	(0x3UL)
#define PVH_LIST_MASK	(~PVH_TYPE_MASK)

#if	(__ARM_VMSA__ == 7)
#define pvh_set_bits(h, b)										\
	do {														\
		while (!OSCompareAndSwap(*(vm_offset_t *)(h), *(vm_offset_t *)(h) | (b), (vm_offset_t *)(h)));	\
	} while (0)

#define pvh_clear_bits(h, b)									\
	do {														\
		while (!OSCompareAndSwap(*(vm_offset_t *)(h), *(vm_offset_t *)(h) & ~(b), (vm_offset_t *)(h)));	\
	} while (0)
#else
#define pvh_set_bits(h, b)										\
	do {														\
		while (!OSCompareAndSwap64(*(vm_offset_t *)(h), *(vm_offset_t *)(h) | ((int64_t)b), (vm_offset_t *)(h)));	\
	} while (0)

#define pvh_clear_bits(h, b)									\
	do {														\
		while (!OSCompareAndSwap64(*(vm_offset_t *)(h), *(vm_offset_t *)(h) & ~((int64_t)b), (vm_offset_t *)(h)));	\
	} while (0)
#endif

#define pvh_test_type(h, b)										\
	((*(vm_offset_t *)(h) & (PVH_TYPE_MASK)) == (b))

#define pvh_ptep(h)												\
		((pt_entry_t *)(*(vm_offset_t *)(h) & PVH_LIST_MASK))

#define pvh_list(h)												\
		((pv_entry_t *)(*(vm_offset_t *)(h) & PVH_LIST_MASK))

#define pvh_bits(h)												\
	(*(vm_offset_t *)(h) & PVH_TYPE_MASK)

#if	(__ARM_VMSA__ == 7)
#define pvh_update_head(h, e, t)									\
	do {														\
		while (!OSCompareAndSwap(*(vm_offset_t *)(h), (vm_offset_t)(e) | (t), (vm_offset_t *)(h)));	\
	} while (0)
#else
#define pvh_update_head(h, e, t)									\
	do {														\
		while (!OSCompareAndSwap64(*(vm_offset_t *)(h), (vm_offset_t)(e) | (t), (vm_offset_t *)(h)));	\
	} while (0)
#endif

#define pvh_add(h, e)							\
	do {								\
		assert(!pvh_test_type((h), PVH_TYPE_PTEP));		\
		pve_next(e) = pvh_list(h);				\
		pvh_update_head((h), (e), PVH_TYPE_PVEP);		\
	} while (0)

#define pvh_remove(h, p, e)						\
	do {								\
		assert(!PVE_NEXT_IS_ALTACCT(pve_next((e))));		\
		if ((p) == (h)) {					\
			if (PVE_NEXT_PTR(pve_next((e))) == PV_ENTRY_NULL) { \
				pvh_update_head((h), PV_ENTRY_NULL, PVH_TYPE_NULL); \
			} else {					\
				pvh_update_head((h), PVE_NEXT_PTR(pve_next((e))), PVH_TYPE_PVEP); \
			}						\
		} else {						\
			/*						\
			 * PMAP LEDGERS:				\
			 * preserve the "alternate accounting" bit	\
			 * when updating "p" (the previous entry's	\
			 * "pve_next").					\
			 */						\
			boolean_t	__is_altacct;			\
			__is_altacct = PVE_NEXT_IS_ALTACCT(*(p));	\
			*(p) = PVE_NEXT_PTR(pve_next((e)));		\
			if (__is_altacct) {				\
				PVE_NEXT_SET_ALTACCT((p));		\
			} else {					\
				PVE_NEXT_CLR_ALTACCT((p));		\
			}						\
		}							\
	} while (0)


/* PPATTR Define Macros */

#define ppattr_set_bits(h, b)										\
	do {														\
		while (!OSCompareAndSwap16(*(pp_attr_t *)(h), *(pp_attr_t *)(h) | (b), (pp_attr_t *)(h)));	\
	} while (0)

#define ppattr_clear_bits(h, b)									\
	do {														\
		while (!OSCompareAndSwap16(*(pp_attr_t *)(h), *(pp_attr_t *)(h) & ~(b), (pp_attr_t *)(h)));	\
	} while (0)

#define ppattr_test_bits(h, b)										\
	((*(pp_attr_t *)(h) & (b)) == (b))

#define pa_set_bits(x, b)										\
	do {														\
		if (pa_valid(x))										\
			ppattr_set_bits(&pp_attr_table[pa_index(x)], 		\
				     (b));										\
	} while (0)

#define pa_test_bits(x, b)										\
	(pa_valid(x) ? ppattr_test_bits(&pp_attr_table[pa_index(x)],\
				     (b)) : FALSE)

#define pa_clear_bits(x, b)										\
	do {														\
		if (pa_valid(x))										\
			ppattr_clear_bits(&pp_attr_table[pa_index(x)],		\
				       (b));									\
	} while (0)

#define pa_set_modify(x)										\
	pa_set_bits(x, PP_ATTR_MODIFIED)

#define pa_clear_modify(x)										\
	pa_clear_bits(x, PP_ATTR_MODIFIED)

#define pa_set_reference(x)										\
	pa_set_bits(x, PP_ATTR_REFERENCED)

#define pa_clear_reference(x)									\
	pa_clear_bits(x, PP_ATTR_REFERENCED)


#define IS_INTERNAL_PAGE(pai) \
	ppattr_test_bits(&pp_attr_table[pai], PP_ATTR_INTERNAL)
#define SET_INTERNAL_PAGE(pai) \
	ppattr_set_bits(&pp_attr_table[pai], PP_ATTR_INTERNAL)
#define CLR_INTERNAL_PAGE(pai) \
	ppattr_clear_bits(&pp_attr_table[pai], PP_ATTR_INTERNAL)

#define IS_REUSABLE_PAGE(pai) \
	ppattr_test_bits(&pp_attr_table[pai], PP_ATTR_REUSABLE)
#define SET_REUSABLE_PAGE(pai) \
	ppattr_set_bits(&pp_attr_table[pai], PP_ATTR_REUSABLE)
#define CLR_REUSABLE_PAGE(pai) \
	ppattr_clear_bits(&pp_attr_table[pai], PP_ATTR_REUSABLE)

#define IS_ALTACCT_PAGE(pai, pve_p)				\
	(((pve_p) == NULL)					  \
	 ? ppattr_test_bits(&pp_attr_table[pai], PP_ATTR_ALTACCT)  \
	 : PVE_NEXT_IS_ALTACCT(pve_next((pve_p))))
#define SET_ALTACCT_PAGE(pai, pve_p)					\
	if ((pve_p) == NULL) {						\
		ppattr_set_bits(&pp_attr_table[pai], PP_ATTR_ALTACCT);	\
	} else {							\
		PVE_NEXT_SET_ALTACCT(&pve_next((pve_p)));		\
	}
#define CLR_ALTACCT_PAGE(pai, pve_p)					\
	if ((pve_p) == NULL) {						\
		ppattr_clear_bits(&pp_attr_table[pai], PP_ATTR_ALTACCT);\
	} else {							\
		PVE_NEXT_CLR_ALTACCT(&pve_next((pve_p)));		\
	}

#define IS_REFFAULT_PAGE(pai) \
	ppattr_test_bits(&pp_attr_table[pai], PP_ATTR_REFFAULT)
#define SET_REFFAULT_PAGE(pai) \
	ppattr_set_bits(&pp_attr_table[pai], PP_ATTR_REFFAULT)
#define CLR_REFFAULT_PAGE(pai) \
	ppattr_clear_bits(&pp_attr_table[pai], PP_ATTR_REFFAULT)

#define IS_MODFAULT_PAGE(pai) \
	ppattr_test_bits(&pp_attr_table[pai], PP_ATTR_MODFAULT)
#define SET_MODFAULT_PAGE(pai) \
	ppattr_set_bits(&pp_attr_table[pai], PP_ATTR_MODFAULT)
#define CLR_MODFAULT_PAGE(pai) \
	ppattr_clear_bits(&pp_attr_table[pai], PP_ATTR_MODFAULT)


#if	(__ARM_VMSA__ == 7)

#define tte_index(pmap, addr)									\
	ttenum((addr))

#define tte_get_ptd(tte)										\
	((struct pt_desc *)((*((vm_offset_t *)(pai_to_pvh(pa_index((vm_offset_t)((tte) & ~PAGE_MASK)))))) & PVH_LIST_MASK))

#else

#define tt0_index(pmap, addr)									\
	(((addr) & ARM_TT_L0_INDEX_MASK) >> ARM_TT_L0_SHIFT)

#define tt1_index(pmap, addr)									\
	(((addr) & ARM_TT_L1_INDEX_MASK) >> ARM_TT_L1_SHIFT)

#define tt2_index(pmap, addr)									\
	(((addr) & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT)

#define tt3_index(pmap, addr)									\
	(((addr) & ARM_TT_L3_INDEX_MASK) >> ARM_TT_L3_SHIFT)

#define tte_index(pmap, addr)									\
	(((addr) & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT)

#define tte_get_ptd(tte)										\
	((struct pt_desc *)((*((vm_offset_t *)(pai_to_pvh(pa_index((vm_offset_t)((tte) & ~PAGE_MASK)))))) & PVH_LIST_MASK))

#endif

/*
 *	Lock on pmap system
 */

#define PMAP_LOCK_INIT(pmap) {									\
	simple_lock_init(&(pmap)->lock, 0);							\
			}

#define PMAP_LOCK(pmap) {										\
	simple_lock(&(pmap)->lock);									\
}

#define PMAP_UNLOCK(pmap) {										\
	simple_unlock(&(pmap)->lock);								\
}

#if MACH_ASSERT
#define PMAP_ASSERT_LOCKED(pmap) {								\
	simple_lock_assert(&(pmap)->lock, LCK_ASSERT_OWNED);					\
}
#else
#define PMAP_ASSERT_LOCKED(pmap)
#endif

/*
 *	Each entry in the pv_head_table is locked by a bit in the
 *	pv lock array, which is stored in the region preceding pv_head_table.
 *	The lock bits are accessed by the physical address of the page they lock.
 */
#define LOCK_PVH(index)	{										\
	hw_lock_bit((hw_lock_bit_t *)										\
		((unsigned int*)pv_head_table)-1-(index>>5),			\
		(index&0x1F));											\
	}

#define UNLOCK_PVH(index)	{									\
	hw_unlock_bit((hw_lock_bit_t *)									\
		((unsigned int*)pv_head_table)-1-(index>>5),			\
		(index&0x1F));											\
	}

#define ASSERT_PVH_LOCKED(index) {								\
	assert(*(((unsigned int*)pv_head_table)-1-(index>>5)) & (1 << (index & 0x1F)));		\
}

#define PMAP_UPDATE_TLBS(pmap, s, e) {							\
	flush_mmu_tlb_region_asid(s, (unsigned)(e - s), pmap);					\
}

#ifdef	__ARM_L1_PTW__

#define FLUSH_PTE_RANGE(spte, epte)								\
	__asm__	volatile("dsb ish");

#define FLUSH_PTE(pte_p)										\
	__asm__	volatile("dsb ish");

#else

#define FLUSH_PTE_RANGE(spte, epte)								\
		CleanPoU_DcacheRegion((vm_offset_t)spte,				\
			(vm_offset_t)epte - (vm_offset_t)spte);

#define FLUSH_PTE(pte_p)										\
	CleanPoU_DcacheRegion((vm_offset_t)pte_p, sizeof(pt_entry_t));
#endif

#define WRITE_PTE(pte_p, pte_entry)								\
    __unreachable_ok_push										\
	if (TEST_PAGE_RATIO_4) {									\
	do {														\
		if (((unsigned)(pte_p)) & 0x1f) panic("WRITE_PTE\n");		\
		if (((pte_entry) & ~ARM_PTE_COMPRESSED_MASK) == ARM_PTE_EMPTY) {	\
		*(pte_p) = (pte_entry);									\
		*((pte_p)+1) = (pte_entry);								\
		*((pte_p)+2) = (pte_entry);								\
		*((pte_p)+3) = (pte_entry);								\
		} else {												\
		*(pte_p) = (pte_entry);									\
		*((pte_p)+1) = (pte_entry) | 0x1000;						\
		*((pte_p)+2) = (pte_entry) | 0x2000;						\
		*((pte_p)+3) = (pte_entry) | 0x3000;						\
		}														\
		FLUSH_PTE_RANGE((pte_p),((pte_p)+4));						\
	} while(0);													\
	} else {													\
	do {														\
		*(pte_p) = (pte_entry);									\
		FLUSH_PTE(pte_p);										\
	} while(0);													\
	}															\
    __unreachable_ok_pop

#define WRITE_PTE_FAST(pte_p, pte_entry)						\
    __unreachable_ok_push										\
	if (TEST_PAGE_RATIO_4) {									\
	if (((unsigned)(pte_p)) & 0x1f) panic("WRITE_PTE\n");			\
	if (((pte_entry) & ~ARM_PTE_COMPRESSED_MASK) == ARM_PTE_EMPTY) {	\
	*(pte_p) = (pte_entry);										\
	*((pte_p)+1) = (pte_entry);									\
	*((pte_p)+2) = (pte_entry);									\
	*((pte_p)+3) = (pte_entry);									\
	} else {													\
	*(pte_p) = (pte_entry);										\
	*((pte_p)+1) = (pte_entry) | 0x1000;							\
	*((pte_p)+2) = (pte_entry) | 0x2000;							\
	*((pte_p)+3) = (pte_entry) | 0x3000;							\
	}															\
	} else {													\
	*(pte_p) = (pte_entry);										\
	}															\
    __unreachable_ok_pop


/*
 * Other useful macros.
 */
#define current_pmap()											\
	(vm_map_pmap(current_thread()->map))

#define PMAP_IS_VALID(x) (TRUE)

#ifdef PMAP_TRACES
unsigned int pmap_trace = 0;

#define PMAP_TRACE(...) \
	if (pmap_trace) { \
		KDBG_RELEASE(__VA_ARGS__); \
	}
#else
#define PMAP_TRACE(...) KDBG_DEBUG(__VA_ARGS__)
#endif

#define PMAP_TRACE_CONSTANT(...) KDBG_RELEASE(__VA_ARGS__)

/*
 * Internal function prototypes (forward declarations).
 */

static void pv_init(
				void);

static boolean_t pv_alloc(
				pmap_t pmap,
				unsigned int pai,
				pv_entry_t **pvepp);

static void pv_free(
				pv_entry_t *pvep);

static void pv_list_free(
				pv_entry_t *pvehp,
				pv_entry_t *pvetp,
				unsigned int cnt);

static void ptd_bootstrap(
				pt_desc_t *ptdp, unsigned int ptd_cnt);

static pt_desc_t *ptd_alloc(
				pmap_t pmap);

static void ptd_deallocate(
				pt_desc_t *ptdp);

static void ptd_init(
				pt_desc_t *ptdp, pmap_t pmap, vm_map_address_t va, unsigned int ttlevel, pt_entry_t * pte_p);

static void		pmap_zone_init(
				void);

static void		pmap_set_reference(
				ppnum_t pn);

ppnum_t			pmap_vtophys(
				pmap_t pmap, addr64_t va);

void pmap_switch_user_ttb(
				pmap_t pmap);

static void	flush_mmu_tlb_region_asid(
				vm_offset_t va, unsigned length, pmap_t pmap);

static kern_return_t pmap_expand(
				pmap_t, vm_map_address_t, unsigned int options, unsigned int level);

static int pmap_remove_range(
				pmap_t, vm_map_address_t, pt_entry_t *, pt_entry_t *, uint32_t *);

static int pmap_remove_range_options(
				pmap_t, vm_map_address_t, pt_entry_t *, pt_entry_t *, uint32_t *, int);

static tt_entry_t *pmap_tt1_allocate(
				pmap_t, vm_size_t, unsigned int);

#define	PMAP_TT_ALLOCATE_NOWAIT		0x1

static void pmap_tt1_deallocate(
				pmap_t, tt_entry_t *, vm_size_t, unsigned int);

#define	PMAP_TT_DEALLOCATE_NOBLOCK	0x1

static kern_return_t pmap_tt_allocate(
				pmap_t, tt_entry_t **, unsigned int, unsigned int);

#define	PMAP_TT_ALLOCATE_NOWAIT		0x1

static void pmap_tte_deallocate(
				pmap_t, tt_entry_t *, unsigned int);

#define	PMAP_TT_L1_LEVEL	0x1
#define	PMAP_TT_L2_LEVEL	0x2
#define	PMAP_TT_L3_LEVEL	0x3
#if (__ARM_VMSA__ == 7)
#define	PMAP_TT_MAX_LEVEL	PMAP_TT_L2_LEVEL
#else
#define	PMAP_TT_MAX_LEVEL	PMAP_TT_L3_LEVEL
#endif

#ifdef __ARM64_PMAP_SUBPAGE_L1__
#if (__ARM_VMSA__ <= 7)
#error This is not supported for old-style page tables
#endif
#define PMAP_ROOT_ALLOC_SIZE (((ARM_TT_L1_INDEX_MASK >> ARM_TT_L1_SHIFT) + 1) * sizeof(tt_entry_t))
#else
#define PMAP_ROOT_ALLOC_SIZE (ARM_PGBYTES)
#endif

const unsigned int arm_hardware_page_size = ARM_PGBYTES;
const unsigned int arm_pt_desc_size = sizeof(pt_desc_t);
const unsigned int arm_pt_root_size = PMAP_ROOT_ALLOC_SIZE;

#define	PMAP_TT_DEALLOCATE_NOBLOCK	0x1

void pmap_init_pte_page_internal(
				pmap_t, pt_entry_t *, vm_offset_t, unsigned int , pt_desc_t **);


#if	(__ARM_VMSA__ > 7)

static inline tt_entry_t *pmap_tt1e(
				pmap_t, vm_map_address_t);

static inline tt_entry_t *pmap_tt2e(
				pmap_t, vm_map_address_t);

static inline pt_entry_t *pmap_tt3e(
				pmap_t, vm_map_address_t);

static void pmap_unmap_sharedpage(
				pmap_t pmap);

static void pmap_sharedpage_flush_32_to_64(
				void);

static boolean_t
			pmap_is_64bit(pmap_t);


#endif
static inline tt_entry_t *pmap_tte(
				pmap_t, vm_map_address_t);

static inline pt_entry_t *pmap_pte(
				pmap_t, vm_map_address_t);

static void pmap_update_cache_attributes_locked(
				ppnum_t, unsigned);

boolean_t arm_clear_fast_fault(
				ppnum_t ppnum,
				vm_prot_t fault_type);

static pmap_paddr_t	pmap_pages_reclaim(
				void);

static kern_return_t pmap_pages_alloc(
				pmap_paddr_t    *pa,
				unsigned    size,
				unsigned    option);

#define	PMAP_PAGES_ALLOCATE_NOWAIT		0x1
#define	PMAP_PAGES_RECLAIM_NOWAIT		0x2

static void pmap_pages_free(
				pmap_paddr_t	pa,
				unsigned	size);


#define PMAP_SUPPORT_PROTOTYPES(__return_type, __function_name, __function_args, __function_index) \
	static __return_type __function_name##_internal __function_args;

PMAP_SUPPORT_PROTOTYPES(
kern_return_t,
arm_fast_fault, (pmap_t pmap,
                 vm_map_address_t va,
                 vm_prot_t fault_type,
                 boolean_t from_user), ARM_FAST_FAULT_INDEX);


PMAP_SUPPORT_PROTOTYPES(
boolean_t,
arm_force_fast_fault, (ppnum_t ppnum,
                       vm_prot_t allow_mode,
                       int options), ARM_FORCE_FAST_FAULT_INDEX);

PMAP_SUPPORT_PROTOTYPES(
kern_return_t,
mapping_free_prime, (void), MAPPING_FREE_PRIME_INDEX);

PMAP_SUPPORT_PROTOTYPES(
kern_return_t,
mapping_replenish, (void), MAPPING_REPLENISH_INDEX);

PMAP_SUPPORT_PROTOTYPES(
boolean_t,
pmap_batch_set_cache_attributes, (ppnum_t pn,
                                  unsigned int cacheattr,
                                  unsigned int page_cnt,
                                  unsigned int page_index,
                                  boolean_t doit,
                                  unsigned int *res), PMAP_BATCH_SET_CACHE_ATTRIBUTES_INDEX);

PMAP_SUPPORT_PROTOTYPES(
void,
pmap_change_wiring, (pmap_t pmap,
                     vm_map_address_t v,
                     boolean_t wired), PMAP_CHANGE_WIRING_INDEX);

PMAP_SUPPORT_PROTOTYPES(
pmap_t,
pmap_create, (ledger_t ledger,
              vm_map_size_t size,
              boolean_t is_64bit), PMAP_CREATE_INDEX);

PMAP_SUPPORT_PROTOTYPES(
void,
pmap_destroy, (pmap_t pmap), PMAP_DESTROY_INDEX);



PMAP_SUPPORT_PROTOTYPES(
kern_return_t,
pmap_enter_options, (pmap_t pmap,
                     vm_map_address_t v,
                     ppnum_t pn,
                     vm_prot_t prot,
                     vm_prot_t fault_type,
                     unsigned int flags,
                     boolean_t wired,
                     unsigned int options), PMAP_ENTER_OPTIONS_INDEX);

PMAP_SUPPORT_PROTOTYPES(
vm_offset_t,
pmap_extract, (pmap_t pmap,
               vm_map_address_t va), PMAP_EXTRACT_INDEX);

PMAP_SUPPORT_PROTOTYPES(
ppnum_t,
pmap_find_phys, (pmap_t pmap,
                 addr64_t va), PMAP_FIND_PHYS_INDEX);

#if (__ARM_VMSA__ > 7)
PMAP_SUPPORT_PROTOTYPES(
void,
pmap_insert_sharedpage, (pmap_t pmap), PMAP_INSERT_SHAREDPAGE_INDEX);
#endif


PMAP_SUPPORT_PROTOTYPES(
boolean_t,
pmap_is_empty, (pmap_t pmap,
                vm_map_offset_t va_start,
                vm_map_offset_t va_end), PMAP_IS_EMPTY_INDEX);


PMAP_SUPPORT_PROTOTYPES(
unsigned int,
pmap_map_cpu_windows_copy, (ppnum_t pn,
                            vm_prot_t prot,
                            unsigned int wimg_bits), PMAP_MAP_CPU_WINDOWS_COPY_INDEX);

PMAP_SUPPORT_PROTOTYPES(
kern_return_t,
pmap_nest, (pmap_t grand,
            pmap_t subord,
            addr64_t vstart,
            addr64_t nstart,
            uint64_t size), PMAP_NEST_INDEX);

PMAP_SUPPORT_PROTOTYPES(
void,
pmap_page_protect_options, (ppnum_t ppnum,
                            vm_prot_t prot,
                            unsigned int options), PMAP_PAGE_PROTECT_OPTIONS_INDEX);

PMAP_SUPPORT_PROTOTYPES(
void,
pmap_protect_options, (pmap_t pmap,
                       vm_map_address_t start,
                       vm_map_address_t end,
                       vm_prot_t prot,
                       unsigned int options,
                       void *args), PMAP_PROTECT_OPTIONS_INDEX);

PMAP_SUPPORT_PROTOTYPES(
kern_return_t,
pmap_query_page_info, (pmap_t pmap,
                       vm_map_offset_t va,
                       int *disp_p), PMAP_QUERY_PAGE_INFO_INDEX);

PMAP_SUPPORT_PROTOTYPES(
boolean_t,
pmap_query_resident, (pmap_t pmap,
                      vm_map_address_t start,
                      vm_map_address_t end,
                      mach_vm_size_t *resident_bytes_p,
                      mach_vm_size_t *compressed_bytes_p), PMAP_QUERY_RESIDENT_INDEX);

PMAP_SUPPORT_PROTOTYPES(
void,
pmap_reference, (pmap_t pmap), PMAP_REFERENCE_INDEX);

PMAP_SUPPORT_PROTOTYPES(
int,
pmap_remove_options, (pmap_t pmap,
                      vm_map_address_t start,
                      vm_map_address_t end,
                      int options), PMAP_REMOVE_OPTIONS_INDEX);

PMAP_SUPPORT_PROTOTYPES(
kern_return_t,
pmap_return, (boolean_t do_panic,
              boolean_t do_recurse), PMAP_RETURN_INDEX);

PMAP_SUPPORT_PROTOTYPES(
void,
pmap_set_cache_attributes, (ppnum_t pn,
                            unsigned int cacheattr), PMAP_SET_CACHE_ATTRIBUTES_INDEX);

PMAP_SUPPORT_PROTOTYPES(
void,
pmap_set_nested, (pmap_t pmap), PMAP_SET_NESTED_INDEX);

#if MACH_ASSERT
PMAP_SUPPORT_PROTOTYPES(
void,
pmap_set_process, (pmap_t pmap,
                   int pid,
                   char *procname), PMAP_SET_PROCESS_INDEX);
#endif


PMAP_SUPPORT_PROTOTYPES(
void,
pmap_unmap_cpu_windows_copy, (unsigned int index), PMAP_UNMAP_CPU_WINDOWS_COPY_INDEX);

PMAP_SUPPORT_PROTOTYPES(
kern_return_t,
pmap_unnest_options, (pmap_t grand,
                      addr64_t vaddr,
                      uint64_t size,
                      unsigned int option), PMAP_UNNEST_OPTIONS_INDEX);


PMAP_SUPPORT_PROTOTYPES(
void,
phys_attribute_set, (ppnum_t pn,
                     unsigned int bits), PHYS_ATTRIBUTE_SET_INDEX);


PMAP_SUPPORT_PROTOTYPES(
void,
phys_attribute_clear, (ppnum_t pn,
                       unsigned int bits,
                       int options,
                       void *arg), PHYS_ATTRIBUTE_CLEAR_INDEX);

PMAP_SUPPORT_PROTOTYPES(
void,
pmap_switch, (pmap_t pmap), PMAP_SWITCH_INDEX);

PMAP_SUPPORT_PROTOTYPES(
void,
pmap_switch_user_ttb, (pmap_t pmap), PMAP_SWITCH_USER_TTB_INDEX);



void pmap_footprint_suspend(vm_map_t	map,
			    boolean_t	suspend);
PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_footprint_suspend, (vm_map_t map,
				 boolean_t suspend),
	PMAP_FOOTPRINT_SUSPEND_INDEX);

#if CONFIG_PGTRACE
boolean_t pgtrace_enabled = 0;

typedef struct {
    queue_chain_t   chain;

    /*
        pmap        - pmap for below addresses
        ova         - original va page address
        cva         - clone va addresses for pre, target and post pages
        cva_spte    - clone saved ptes
        range       - trace range in this map
        cloned      - has been cloned or not
    */
    pmap_t          pmap;
    vm_map_offset_t ova;
    vm_map_offset_t cva[3];
    pt_entry_t      cva_spte[3];
    struct {
        pmap_paddr_t    start;
        pmap_paddr_t    end;
    } range;
    bool            cloned;
} pmap_pgtrace_map_t;

static void pmap_pgtrace_init(void);
static bool pmap_pgtrace_enter_clone(pmap_t pmap, vm_map_offset_t va_page, vm_map_offset_t start, vm_map_offset_t end);
static void pmap_pgtrace_remove_clone(pmap_t pmap, pmap_paddr_t pa_page, vm_map_offset_t va_page);
static void pmap_pgtrace_remove_all_clone(pmap_paddr_t pa);
#endif

#if	(__ARM_VMSA__ > 7)
/*
 * The low global vector page is mapped at a fixed alias.
 * Since the page size is 16k for H8 and newer we map the globals to a 16k
 * aligned address. Readers of the globals (e.g. lldb, panic server) need
 * to check both addresses anyway for backward compatibility. So for now
 * we leave H6 and H7 where they were.
 */
#if (ARM_PGSHIFT == 14)
#define LOWGLOBAL_ALIAS		(LOW_GLOBAL_BASE_ADDRESS + 0x4000)
#else
#define LOWGLOBAL_ALIAS		(LOW_GLOBAL_BASE_ADDRESS + 0x2000)
#endif

#else
#define LOWGLOBAL_ALIAS		(0xFFFF1000)	
#endif

long long alloc_tteroot_count __attribute__((aligned(8))) MARK_AS_PMAP_DATA = 0LL;
long long alloc_ttepages_count __attribute__((aligned(8))) MARK_AS_PMAP_DATA = 0LL;
long long alloc_ptepages_count __attribute__((aligned(8))) MARK_AS_PMAP_DATA = 0LL;
long long alloc_pmap_pages_count __attribute__((aligned(8))) = 0LL;

int pt_fake_zone_index = -1;		/* index of pmap fake zone */



/*
 * Allocates and initializes a per-CPU data structure for the pmap.
 */
static void
pmap_cpu_data_init_internal(unsigned int cpu_number)
{
	pmap_cpu_data_t * pmap_cpu_data = NULL;

	pmap_cpu_data = pmap_get_cpu_data();
	pmap_cpu_data->cpu_number = cpu_number;
}

void
pmap_cpu_data_init(void)
{
	pmap_cpu_data_init_internal(cpu_number());
}

static void
pmap_cpu_data_array_init(void)
{

	pmap_cpu_data_init();
}

pmap_cpu_data_t *
pmap_get_cpu_data(void)
{
	pmap_cpu_data_t * pmap_cpu_data = NULL;

	pmap_cpu_data = &getCpuDatap()->cpu_pmap_cpu_data;

	return pmap_cpu_data;
}


/* TODO */
pmap_paddr_t
pmap_pages_reclaim(
	void)
{
	boolean_t		found_page;
	unsigned		i;
	pt_desc_t		*ptdp;


	/*
	 * pmap_pages_reclaim() is returning a page by freeing an active pt page.
	 * To be eligible, a pt page is assigned to a user pmap. It doesn't have any wired pte
	 * entry and it  contains at least one valid pte entry.
	 *
	 * In a loop, check for a page in the reclaimed pt page list.
	 * if one is present, unlink that page and return the physical page address.
	 * Otherwise, scan the pt page list for an eligible pt page to reclaim.
	 * If found, invoke pmap_remove_range() on its pmap and address range then
	 * deallocates that pt page. This will end up adding the pt page to the
	 * reclaimed pt page list.
	 * If no eligible page were found in the pt page list, panic.
	 */

	simple_lock(&pmap_pages_lock);
	pmap_pages_request_count++;
	pmap_pages_request_acum++;

	while (1) {

		if (pmap_pages_reclaim_list != (page_free_entry_t *)NULL) {
			page_free_entry_t	*page_entry;

			page_entry = pmap_pages_reclaim_list;
			pmap_pages_reclaim_list = pmap_pages_reclaim_list->next;
			simple_unlock(&pmap_pages_lock);

			return((pmap_paddr_t)ml_static_vtop((vm_offset_t)page_entry));
		}

		simple_unlock(&pmap_pages_lock);

		simple_lock(&pt_pages_lock);
		ptdp = (pt_desc_t *)queue_first(&pt_page_list);
		found_page = FALSE;

		while (!queue_end(&pt_page_list, (queue_entry_t)ptdp)) {
			if ((ptdp->pmap != kernel_pmap)
			    && (ptdp->pmap->nested == FALSE)
			    && (simple_lock_try(&ptdp->pmap->lock))) {

				unsigned refcnt_acc = 0;
				unsigned wiredcnt_acc = 0;

				for (i = 0 ; i < PT_INDEX_MAX ; i++) {
					if (ptdp->pt_cnt[i].refcnt & PT_DESC_REFCOUNT) {
						/* Do not attempt to free a page that contains an L2 table
						 * or is currently being operated on by pmap_enter(), 
						 * which can drop the pmap lock. */
						refcnt_acc = 0;
						break;
					}
					refcnt_acc += ptdp->pt_cnt[i].refcnt;
					wiredcnt_acc += ptdp->pt_cnt[i].wiredcnt;
				}
				if ((wiredcnt_acc == 0) && (refcnt_acc != 0)) {
					found_page = TRUE;
					/* Leave ptdp->pmap locked here.  We're about to reclaim
					 * a tt page from it, so we don't want anyone else messing
					 * with it while we do that. */
					break;
				}
				simple_unlock(&ptdp->pmap->lock);
			}
			ptdp = (pt_desc_t *)queue_next((queue_t)ptdp);
		}
		if (!found_page) {
			panic("pmap_pages_reclaim(): No eligible page in pt_page_list\n");
		} else {
			int					remove_count = 0;
			vm_map_address_t	va;
			pmap_t				pmap;
			pt_entry_t			*bpte, *epte;
			pt_entry_t			*pte_p;
			tt_entry_t			*tte_p;
			uint32_t			rmv_spte=0;

			simple_unlock(&pt_pages_lock);
			pmap = ptdp->pmap;
			PMAP_ASSERT_LOCKED(pmap); // pmap lock should be held from loop above
			for (i = 0 ; i < PT_INDEX_MAX ; i++) {
				va = ptdp->pt_map[i].va;

				tte_p = pmap_tte(pmap, va);
				if ((tte_p != (tt_entry_t *) NULL)
				    && ((*tte_p & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE)) {

#if	(__ARM_VMSA__ == 7)
					pte_p = (pt_entry_t *) ttetokv(*tte_p);
					bpte = &pte_p[ptenum(va)];
					epte = bpte + PAGE_SIZE/sizeof(pt_entry_t);
#else
					pte_p = (pt_entry_t *) ttetokv(*tte_p);
					bpte = &pte_p[tt3_index(pmap, va)];
					epte = bpte + PAGE_SIZE/sizeof(pt_entry_t);
#endif
					/*
					 * Use PMAP_OPTIONS_REMOVE to clear any
					 * "compressed" markers and update the
					 * "compressed" counter in pmap->stats.
					 * This means that we lose accounting for
					 * any compressed pages in this range
					 * but the alternative is to not be able
					 * to account for their future decompression,
					 * which could cause the counter to drift
					 * more and more.
					 */
					remove_count += pmap_remove_range_options(
						pmap, va, bpte, epte,
						&rmv_spte, PMAP_OPTIONS_REMOVE);
					if (ptdp->pt_cnt[ARM_PT_DESC_INDEX(pte_p)].refcnt != 0)
						panic("pmap_pages_reclaim(): ptdp %p, count %d\n", ptdp, ptdp->pt_cnt[ARM_PT_DESC_INDEX(pte_p)].refcnt);
#if	(__ARM_VMSA__ == 7)
					pmap_tte_deallocate(pmap, tte_p, PMAP_TT_L1_LEVEL);
					flush_mmu_tlb_entry((va & ~ARM_TT_L1_PT_OFFMASK) | (pmap->asid & 0xff));
					flush_mmu_tlb_entry(((va & ~ARM_TT_L1_PT_OFFMASK) + ARM_TT_L1_SIZE) | (pmap->asid & 0xff));
					flush_mmu_tlb_entry(((va & ~ARM_TT_L1_PT_OFFMASK) + 2*ARM_TT_L1_SIZE)| (pmap->asid & 0xff));
					flush_mmu_tlb_entry(((va & ~ARM_TT_L1_PT_OFFMASK) + 3*ARM_TT_L1_SIZE)| (pmap->asid & 0xff));
#else
					pmap_tte_deallocate(pmap, tte_p, PMAP_TT_L2_LEVEL);
					flush_mmu_tlb_entry(tlbi_addr(va & ~ARM_TT_L2_OFFMASK) | tlbi_asid(pmap->asid));
#endif

					if (remove_count > 0) {
#if	(__ARM_VMSA__ == 7)
						PMAP_UPDATE_TLBS(pmap, va, va+4*ARM_TT_L1_SIZE);
#else
						PMAP_UPDATE_TLBS(pmap, va, va+ARM_TT_L2_SIZE);
#endif
					}
				}
			}
			// Undo the lock we grabbed when we found ptdp above
			PMAP_UNLOCK(pmap);
		}
		simple_lock(&pmap_pages_lock);
	}
}


static kern_return_t
pmap_pages_alloc(
	pmap_paddr_t	*pa,
	unsigned		size,
	unsigned		option)
{
	vm_page_t       m = VM_PAGE_NULL, m_prev;

	if(option & PMAP_PAGES_RECLAIM_NOWAIT) {
		assert(size == PAGE_SIZE);
		*pa = pmap_pages_reclaim();
		return KERN_SUCCESS;
	}
	if (size == PAGE_SIZE) {
		while ((m = vm_page_grab()) == VM_PAGE_NULL) {
			if(option & PMAP_PAGES_ALLOCATE_NOWAIT) {
				return KERN_RESOURCE_SHORTAGE;
			}

			VM_PAGE_WAIT();
		}
		vm_page_lock_queues();
		vm_page_wire(m, VM_KERN_MEMORY_PTE, TRUE);
		vm_page_unlock_queues();
	}
	if (size == 2*PAGE_SIZE) {
		while (cpm_allocate(size, &m, 0, 1, TRUE, 0) != KERN_SUCCESS) {
			if(option & PMAP_PAGES_ALLOCATE_NOWAIT)
				return KERN_RESOURCE_SHORTAGE;

			VM_PAGE_WAIT();
		}
	}

	*pa = (pmap_paddr_t)ptoa(VM_PAGE_GET_PHYS_PAGE(m));

	vm_object_lock(pmap_object);
	while (m != VM_PAGE_NULL) {
		vm_page_insert_wired(m, pmap_object, (vm_object_offset_t) ((ptoa(VM_PAGE_GET_PHYS_PAGE(m))) - gPhysBase), VM_KERN_MEMORY_PTE);
		m_prev = m;
		m = NEXT_PAGE(m_prev);
		*(NEXT_PAGE_PTR(m_prev)) = VM_PAGE_NULL;
	}
	vm_object_unlock(pmap_object);

	OSAddAtomic(size>>PAGE_SHIFT, &inuse_pmap_pages_count);
	OSAddAtomic64(size>>PAGE_SHIFT, &alloc_pmap_pages_count);

	return KERN_SUCCESS;
}


static void
pmap_pages_free(
	pmap_paddr_t	pa,
	unsigned	size)
{
	simple_lock(&pmap_pages_lock);

	if (pmap_pages_request_count != 0) {
		page_free_entry_t	*page_entry;

		pmap_pages_request_count--;
		page_entry = (page_free_entry_t *)phystokv(pa);
		page_entry->next = pmap_pages_reclaim_list;
		pmap_pages_reclaim_list = page_entry;
		simple_unlock(&pmap_pages_lock);

		return;
	}

	simple_unlock(&pmap_pages_lock);

	vm_page_t       m;
	pmap_paddr_t	pa_max;

	OSAddAtomic(-(size>>PAGE_SHIFT), &inuse_pmap_pages_count);

	for (pa_max = pa + size; pa < pa_max; pa = pa + PAGE_SIZE) {
		vm_object_lock(pmap_object);
		m = vm_page_lookup(pmap_object, (pa - gPhysBase));
		assert(m != VM_PAGE_NULL);
		assert(VM_PAGE_WIRED(m));
		vm_page_lock_queues();
		vm_page_free(m);
		vm_page_unlock_queues();
		vm_object_unlock(pmap_object);
	}
}

static inline void
PMAP_ZINFO_PALLOC(
	pmap_t pmap, int bytes)
{
	pmap_ledger_credit(pmap, task_ledgers.tkm_private, bytes);
}

static inline void
PMAP_ZINFO_PFREE(
	pmap_t pmap,
	int bytes)
{
	pmap_ledger_debit(pmap, task_ledgers.tkm_private, bytes);
}

static inline void
pmap_tt_ledger_credit(
	pmap_t		pmap,
	vm_size_t	size)
{
	if (pmap != kernel_pmap) {
		pmap_ledger_credit(pmap, task_ledgers.phys_footprint, size);
		pmap_ledger_credit(pmap, task_ledgers.page_table, size);
	}
}

static inline void
pmap_tt_ledger_debit(
	pmap_t		pmap,
	vm_size_t	size)
{
	if (pmap != kernel_pmap) {
		pmap_ledger_debit(pmap, task_ledgers.phys_footprint, size);
		pmap_ledger_debit(pmap, task_ledgers.page_table, size);
	}
}

static unsigned int
alloc_asid(
	void)
{
	unsigned int    asid_bitmap_index;

	simple_lock(&pmaps_lock);
	for (asid_bitmap_index = 0; asid_bitmap_index < (MAX_ASID / (sizeof(uint32_t) * NBBY)); asid_bitmap_index++) {
		unsigned int    temp = ffs(asid_bitmap[asid_bitmap_index]);
		if (temp > 0) {
			temp -= 1;
			asid_bitmap[asid_bitmap_index] &= ~(1 << temp);
#if __ARM_KERNEL_PROTECT__
			/*
			 * We need two ASIDs: n and (n | 1).  n is used for EL0,
			 * (n | 1) for EL1.
			 */
			unsigned int temp2 = temp | 1;
			assert(temp2 < MAX_ASID);
			assert(temp2 < 32);
			assert(temp2 != temp);
			assert(asid_bitmap[asid_bitmap_index] & (1 << temp2));

			/* Grab the second ASID. */
			asid_bitmap[asid_bitmap_index] &= ~(1 << temp2);
#endif /* __ARM_KERNEL_PROTECT__ */
			simple_unlock(&pmaps_lock);

			/*
			 * We should never vend out physical ASID 0 through this
			 * method, as it belongs to the kernel.
			 */
			assert(((asid_bitmap_index * sizeof(uint32_t) * NBBY + temp) % ARM_MAX_ASID) != 0);

#if __ARM_KERNEL_PROTECT__
			/* Or the kernel EL1 ASID. */
			assert(((asid_bitmap_index * sizeof(uint32_t) * NBBY + temp) % ARM_MAX_ASID) != 1);
#endif /* __ARM_KERNEL_PROTECT__ */

			return (asid_bitmap_index * sizeof(uint32_t) * NBBY + temp);
		}
	}
	simple_unlock(&pmaps_lock);
	/*
	 * ToDo: Add code to deal with pmap with no asid panic for now. Not
	 * an issue with the small config  process hard limit
	 */
	panic("alloc_asid(): out of ASID number");
	return MAX_ASID;
}

static void
free_asid(
	int asid)
{
	/* Don't free up any alias of physical ASID 0. */
	assert((asid % ARM_MAX_ASID) != 0);

	simple_lock(&pmaps_lock);
	setbit(asid, (int *) asid_bitmap);

#if __ARM_KERNEL_PROTECT__
	assert((asid | 1) < MAX_ASID);
	assert((asid | 1) != asid);
	setbit(asid | 1, (int *) asid_bitmap);
#endif /* __ARM_KERNEL_PROTECT__ */

	simple_unlock(&pmaps_lock);
}

#define PV_LOW_WATER_MARK_DEFAULT      0x200
#define PV_KERN_LOW_WATER_MARK_DEFAULT 0x200
#define PV_ALLOC_CHUNK_INITIAL         0x200
#define PV_KERN_ALLOC_CHUNK_INITIAL    0x200
#define PV_ALLOC_INITIAL_TARGET        (PV_ALLOC_CHUNK_INITIAL * 5)
#define PV_KERN_ALLOC_INITIAL_TARGET   (PV_KERN_ALLOC_CHUNK_INITIAL)


uint32_t pv_free_count MARK_AS_PMAP_DATA = 0;
uint32_t pv_page_count MARK_AS_PMAP_DATA = 0;
uint32_t pv_kern_free_count MARK_AS_PMAP_DATA = 0;

uint32_t pv_low_water_mark MARK_AS_PMAP_DATA;
uint32_t pv_kern_low_water_mark MARK_AS_PMAP_DATA;
uint32_t pv_alloc_chunk MARK_AS_PMAP_DATA;
uint32_t pv_kern_alloc_chunk MARK_AS_PMAP_DATA;

thread_t mapping_replenish_thread;
event_t	mapping_replenish_event;
event_t pmap_user_pv_throttle_event;
volatile uint32_t mappingrecurse = 0;

uint64_t pmap_pv_throttle_stat;
uint64_t pmap_pv_throttled_waiters;

unsigned pmap_mapping_thread_wakeups;
unsigned pmap_kernel_reserve_replenish_stat MARK_AS_PMAP_DATA;
unsigned pmap_user_reserve_replenish_stat MARK_AS_PMAP_DATA;
unsigned pmap_kern_reserve_alloc_stat MARK_AS_PMAP_DATA;


static void
pv_init(
	void)
{
	simple_lock_init(&pv_free_list_lock, 0);
	simple_lock_init(&pv_kern_free_list_lock, 0);
	pv_free_list = PV_ENTRY_NULL;
	pv_free_count = 0x0U;
	pv_kern_free_list = PV_ENTRY_NULL;
	pv_kern_free_count = 0x0U;
}

static inline void	PV_ALLOC(pv_entry_t **pv_ep);
static inline void	PV_KERN_ALLOC(pv_entry_t **pv_e);
static inline void	PV_FREE_LIST(pv_entry_t *pv_eh, pv_entry_t *pv_et, int pv_cnt);
static inline void	PV_KERN_FREE_LIST(pv_entry_t *pv_eh, pv_entry_t *pv_et, int pv_cnt);

static inline void	pmap_pv_throttle(pmap_t p);

static boolean_t
pv_alloc(
	pmap_t pmap,
	unsigned int pai,
	pv_entry_t **pvepp)
{
	PMAP_ASSERT_LOCKED(pmap);
	ASSERT_PVH_LOCKED(pai);
	PV_ALLOC(pvepp);
	if (PV_ENTRY_NULL == *pvepp) {

		if (kernel_pmap == pmap) {

			PV_KERN_ALLOC(pvepp);

			if (PV_ENTRY_NULL == *pvepp) {
				pv_entry_t		*pv_e;
				pv_entry_t		*pv_eh;
				pv_entry_t		*pv_et;
				int				pv_cnt;
				unsigned		j;
				pmap_paddr_t    pa;
				kern_return_t	ret;

				UNLOCK_PVH(pai);
				PMAP_UNLOCK(pmap);

				ret = pmap_pages_alloc(&pa, PAGE_SIZE, PMAP_PAGES_ALLOCATE_NOWAIT);

				if (ret == KERN_RESOURCE_SHORTAGE) {
					ret = pmap_pages_alloc(&pa, PAGE_SIZE, PMAP_PAGES_RECLAIM_NOWAIT);
				}

				if (ret != KERN_SUCCESS) {
					panic("%s: failed to alloc page for kernel, ret=%d, "
					      "pmap=%p, pai=%u, pvepp=%p",
					      __FUNCTION__, ret,
					      pmap, pai, pvepp);
				}

				pv_page_count++;

				pv_e = (pv_entry_t *)phystokv(pa);
				pv_cnt = 0;
				pv_eh = pv_et = PV_ENTRY_NULL;
				*pvepp = pv_e;
				pv_e++;

				for (j = 1; j < (PAGE_SIZE/sizeof(pv_entry_t)) ; j++) {
					pv_e->pve_next = pv_eh;
					pv_eh = pv_e;

					if (pv_et == PV_ENTRY_NULL)
						pv_et = pv_e;
					pv_cnt++;
					pv_e++;
				}
				PV_KERN_FREE_LIST(pv_eh, pv_et, pv_cnt);
				PMAP_LOCK(pmap);
				LOCK_PVH(pai);
				return FALSE;
			}
		} else {
			UNLOCK_PVH(pai);
			PMAP_UNLOCK(pmap);
			pmap_pv_throttle(pmap);
			{
				pv_entry_t		*pv_e;
				pv_entry_t		*pv_eh;
				pv_entry_t		*pv_et;
				int				pv_cnt;
				unsigned		j;
				pmap_paddr_t    pa;
				kern_return_t	ret;

				ret = pmap_pages_alloc(&pa, PAGE_SIZE, 0);

				if (ret != KERN_SUCCESS) {
					panic("%s: failed to alloc page, ret=%d, "
					      "pmap=%p, pai=%u, pvepp=%p",
					      __FUNCTION__, ret,
					      pmap, pai, pvepp);
				}

				pv_page_count++;

				pv_e = (pv_entry_t *)phystokv(pa);
				pv_cnt = 0;
				pv_eh = pv_et = PV_ENTRY_NULL;
				*pvepp = pv_e;
				pv_e++;

				for (j = 1; j < (PAGE_SIZE/sizeof(pv_entry_t)) ; j++) {
					pv_e->pve_next = pv_eh;
					pv_eh = pv_e;

					if (pv_et == PV_ENTRY_NULL)
						pv_et = pv_e;
					pv_cnt++;
					pv_e++;
				}
				PV_FREE_LIST(pv_eh, pv_et, pv_cnt);
			}
			PMAP_LOCK(pmap);
			LOCK_PVH(pai);
			return FALSE;
		}
	}
	assert(PV_ENTRY_NULL != *pvepp);
	return TRUE;
}

static void
pv_free(
	pv_entry_t *pvep)
{
	PV_FREE_LIST(pvep, pvep, 1);
}

static void
pv_list_free(
	pv_entry_t *pvehp,
	pv_entry_t *pvetp,
	unsigned int cnt)
{
	PV_FREE_LIST(pvehp, pvetp, cnt);
}



static inline void	PV_ALLOC(pv_entry_t **pv_ep) {
	assert(*pv_ep == PV_ENTRY_NULL);
	simple_lock(&pv_free_list_lock);
	/*
	 * If the kernel reserved pool is low, let non-kernel mappings allocate
	 * synchronously, possibly subject to a throttle.
	 */
	if ((pv_kern_free_count >= pv_kern_low_water_mark) && ((*pv_ep = pv_free_list) != 0)) {
		pv_free_list = (pv_entry_t *)(*pv_ep)->pve_next;
		(*pv_ep)->pve_next = PV_ENTRY_NULL;
		pv_free_count--;
	}

	simple_unlock(&pv_free_list_lock);

	if ((pv_free_count < pv_low_water_mark) || (pv_kern_free_count < pv_kern_low_water_mark)) {
		if (!mappingrecurse && hw_compare_and_store(0,1, &mappingrecurse))
			thread_wakeup(&mapping_replenish_event);
	}
}

static inline void	PV_FREE_LIST(pv_entry_t *pv_eh, pv_entry_t *pv_et, int pv_cnt) {
	simple_lock(&pv_free_list_lock);
	pv_et->pve_next = (pv_entry_t *)pv_free_list;
	pv_free_list = pv_eh;
	pv_free_count += pv_cnt;
	simple_unlock(&pv_free_list_lock);
}

static inline void	PV_KERN_ALLOC(pv_entry_t **pv_e) {
	assert(*pv_e == PV_ENTRY_NULL);
	simple_lock(&pv_kern_free_list_lock);

	if ((*pv_e = pv_kern_free_list) != 0) {
		pv_kern_free_list = (pv_entry_t *)(*pv_e)->pve_next;
		(*pv_e)->pve_next = PV_ENTRY_NULL;
		pv_kern_free_count--;
		pmap_kern_reserve_alloc_stat++;
	}

	simple_unlock(&pv_kern_free_list_lock);

	if (pv_kern_free_count < pv_kern_low_water_mark) {
		if (!mappingrecurse && hw_compare_and_store(0,1, &mappingrecurse)) {
			thread_wakeup(&mapping_replenish_event);
		}
	}
}

static inline void	PV_KERN_FREE_LIST(pv_entry_t *pv_eh, pv_entry_t *pv_et, int pv_cnt) {
	simple_lock(&pv_kern_free_list_lock);
	pv_et->pve_next = pv_kern_free_list;
	pv_kern_free_list = pv_eh;
	pv_kern_free_count += pv_cnt;
	simple_unlock(&pv_kern_free_list_lock);
}

static inline void pmap_pv_throttle(__unused pmap_t p) {
	assert(p != kernel_pmap);
	/* Apply throttle on non-kernel mappings */
	if (pv_kern_free_count < (pv_kern_low_water_mark / 2)) {
		pmap_pv_throttle_stat++;
		/* This doesn't need to be strictly accurate, merely a hint
		 * to eliminate the timeout when the reserve is replenished.
		 */
		pmap_pv_throttled_waiters++;
		assert_wait_timeout(&pmap_user_pv_throttle_event, THREAD_UNINT, 1, 1000 * NSEC_PER_USEC);
		thread_block(THREAD_CONTINUE_NULL);
	}
}

/*
 * Creates a target number of free pv_entry_t objects for the kernel free list
 * and the general free list.
 */
static kern_return_t
mapping_free_prime_internal(void)
{
	unsigned       j;
	pmap_paddr_t   pa;
	kern_return_t  ret;
	pv_entry_t    *pv_e;
	pv_entry_t    *pv_eh;
	pv_entry_t    *pv_et;
	int            pv_cnt;
	int            alloc_options = 0;
	int            needed_pv_cnt = 0;
	int            target_pv_free_cnt = 0;

	SECURITY_READ_ONLY_LATE(static boolean_t) mapping_free_prime_internal_called = FALSE;
	SECURITY_READ_ONLY_LATE(static boolean_t) mapping_free_prime_internal_done = FALSE;

	if (mapping_free_prime_internal_done) {
		return KERN_FAILURE;
	}

	if (!mapping_free_prime_internal_called) {
		mapping_free_prime_internal_called = TRUE;

		pv_low_water_mark = PV_LOW_WATER_MARK_DEFAULT;

		/* Alterable via sysctl */
		pv_kern_low_water_mark = PV_KERN_LOW_WATER_MARK_DEFAULT;

		pv_kern_alloc_chunk = PV_KERN_ALLOC_CHUNK_INITIAL;
		pv_alloc_chunk = PV_ALLOC_CHUNK_INITIAL;
	}

	pv_cnt = 0;
	pv_eh = pv_et = PV_ENTRY_NULL;
	target_pv_free_cnt = PV_ALLOC_INITIAL_TARGET;

	/*
	 * We don't take the lock to read pv_free_count, as we should not be
	 * invoking this from a multithreaded context.
	 */
	needed_pv_cnt = target_pv_free_cnt - pv_free_count;

	if (needed_pv_cnt > target_pv_free_cnt) {
		needed_pv_cnt = 0;
	}

	while (pv_cnt < needed_pv_cnt) {
		ret = pmap_pages_alloc(&pa, PAGE_SIZE, alloc_options);

		assert(ret == KERN_SUCCESS);

		pv_page_count++;

		pv_e = (pv_entry_t *)phystokv(pa);

		for (j = 0; j < (PAGE_SIZE/sizeof(pv_entry_t)) ; j++) {
			pv_e->pve_next = pv_eh;
			pv_eh = pv_e;

			if (pv_et == PV_ENTRY_NULL)
				pv_et = pv_e;
			pv_cnt++;
			pv_e++;
		}
	}

	if (pv_cnt) {
		PV_FREE_LIST(pv_eh, pv_et, pv_cnt);
	}

	pv_cnt = 0;
	pv_eh = pv_et = PV_ENTRY_NULL;
	target_pv_free_cnt = PV_KERN_ALLOC_INITIAL_TARGET;

	/*
	 * We don't take the lock to read pv_kern_free_count, as we should not
	 * be invoking this from a multithreaded context.
	 */
	needed_pv_cnt = target_pv_free_cnt - pv_kern_free_count;

	if (needed_pv_cnt > target_pv_free_cnt) {
		needed_pv_cnt = 0;
	}

	while (pv_cnt < needed_pv_cnt) {

		ret = pmap_pages_alloc(&pa, PAGE_SIZE, alloc_options);

		assert(ret == KERN_SUCCESS);
		pv_page_count++;

		pv_e = (pv_entry_t *)phystokv(pa);

		for (j = 0; j < (PAGE_SIZE/sizeof(pv_entry_t)) ; j++) {
			pv_e->pve_next = pv_eh;
			pv_eh = pv_e;

			if (pv_et == PV_ENTRY_NULL)
				pv_et = pv_e;
			pv_cnt++;
			pv_e++;
		}
	}

	if (pv_cnt) {
		PV_KERN_FREE_LIST(pv_eh, pv_et, pv_cnt);
	}

	mapping_free_prime_internal_done = TRUE;
	return KERN_SUCCESS;
}

void
mapping_free_prime(void)
{
	kern_return_t kr = KERN_FAILURE;

	kr = mapping_free_prime_internal();

	if (kr != KERN_SUCCESS) {
		panic("%s: failed, kr=%d", __FUNCTION__, kr);
	}
}

void mapping_replenish(void);

void mapping_adjust(void) {
	kern_return_t mres;

	mres = kernel_thread_start_priority((thread_continue_t)mapping_replenish, NULL, MAXPRI_KERNEL, &mapping_replenish_thread);
	if (mres != KERN_SUCCESS) {
		panic("pmap: mapping_replenish thread creation failed");
	}
	thread_deallocate(mapping_replenish_thread);
}

/*
 * Fills the kernel and general PV free lists back up to their low watermarks.
 */
static kern_return_t
mapping_replenish_internal(void)
{
	pv_entry_t    *pv_e;
	pv_entry_t    *pv_eh;
	pv_entry_t    *pv_et;
	int            pv_cnt;
	unsigned       j;
	pmap_paddr_t   pa;
	kern_return_t  ret = KERN_SUCCESS;

	while (pv_kern_free_count < pv_kern_low_water_mark) {
		pv_cnt = 0;
		pv_eh = pv_et = PV_ENTRY_NULL;

		ret = pmap_pages_alloc(&pa, PAGE_SIZE, 0);
		assert(ret == KERN_SUCCESS);

		pv_page_count++;

		pv_e = (pv_entry_t *)phystokv(pa);

		for (j = 0; j < (PAGE_SIZE/sizeof(pv_entry_t)) ; j++) {
			pv_e->pve_next = pv_eh;
			pv_eh = pv_e;

			if (pv_et == PV_ENTRY_NULL)
				pv_et = pv_e;
			pv_cnt++;
			pv_e++;
		}
		pmap_kernel_reserve_replenish_stat += pv_cnt;
		PV_KERN_FREE_LIST(pv_eh, pv_et, pv_cnt);
	}

	while (pv_free_count < pv_low_water_mark) {
		pv_cnt = 0;
		pv_eh = pv_et = PV_ENTRY_NULL;

		ret = pmap_pages_alloc(&pa, PAGE_SIZE, 0);
		assert(ret == KERN_SUCCESS);

		pv_page_count++;

		pv_e = (pv_entry_t *)phystokv(pa);

		for (j = 0; j < (PAGE_SIZE/sizeof(pv_entry_t)) ; j++) {
			pv_e->pve_next = pv_eh;
			pv_eh = pv_e;

			if (pv_et == PV_ENTRY_NULL)
				pv_et = pv_e;
			pv_cnt++;
			pv_e++;
		}
		pmap_user_reserve_replenish_stat += pv_cnt;
		PV_FREE_LIST(pv_eh, pv_et, pv_cnt);
	}

	return ret;
}

/*
 * Continuation function that keeps the PV free lists from running out of free
 * elements.
 */
__attribute__((noreturn))
void
mapping_replenish(void)
{
	kern_return_t kr;

	/* We qualify for VM privileges...*/
	current_thread()->options |= TH_OPT_VMPRIV;

	for (;;) {
		kr = mapping_replenish_internal();

		if (kr != KERN_SUCCESS) {
			panic("%s: failed, kr=%d", __FUNCTION__, kr);
		}

		/*
		 * Wake threads throttled while the kernel reserve was being replenished.
		 */
		if (pmap_pv_throttled_waiters) {
			pmap_pv_throttled_waiters = 0;
			thread_wakeup(&pmap_user_pv_throttle_event);
		}

		/* Check if the kernel pool has been depleted since the
		 * first pass, to reduce refill latency.
		 */
		if (pv_kern_free_count < pv_kern_low_water_mark)
			continue;
		/* Block sans continuation to avoid yielding kernel stack */
		assert_wait(&mapping_replenish_event, THREAD_UNINT);
		mappingrecurse = 0;
		thread_block(THREAD_CONTINUE_NULL);
		pmap_mapping_thread_wakeups++;
	}
}


static void
ptd_bootstrap(
	pt_desc_t *ptdp,
	unsigned int ptd_cnt)
{
	simple_lock_init(&ptd_free_list_lock, 0);
	while (ptd_cnt != 0) {
		(*(void **)ptdp) = (void *)ptd_free_list;
		ptd_free_list = ptdp;
		ptdp++;
		ptd_cnt--;
		ptd_free_count++;
	}
	ptd_preboot = FALSE;
}

static pt_desc_t
*ptd_alloc(
	pmap_t pmap)
{
	pt_desc_t	*ptdp;
	unsigned	i;

	if (!ptd_preboot)
		simple_lock(&ptd_free_list_lock);

	if (ptd_free_count == 0) {
		unsigned int    ptd_cnt;
		pt_desc_t		*ptdp_next;

		if (ptd_preboot) {
			ptdp = (pt_desc_t *)avail_start;
			avail_start += ARM_PGBYTES;
			ptdp_next = ptdp;
			ptd_cnt = ARM_PGBYTES/sizeof(pt_desc_t);
		} else {
			pmap_paddr_t    pa;
			kern_return_t	ret;

			simple_unlock(&ptd_free_list_lock);

			if (pmap_pages_alloc(&pa, PAGE_SIZE, PMAP_PAGES_ALLOCATE_NOWAIT) != KERN_SUCCESS) {
				ret =  pmap_pages_alloc(&pa, PAGE_SIZE, PMAP_PAGES_RECLAIM_NOWAIT);
	  			assert(ret == KERN_SUCCESS);
			}
			ptdp = (pt_desc_t *)phystokv(pa);

			simple_lock(&ptd_free_list_lock);
			ptdp_next = ptdp;
			ptd_cnt = PAGE_SIZE/sizeof(pt_desc_t);
		}

		while (ptd_cnt != 0) {
			(*(void **)ptdp_next) = (void *)ptd_free_list;
			ptd_free_list = ptdp_next;
			ptdp_next++;
			ptd_cnt--;
			ptd_free_count++;
		}
	}

	if ((ptdp = ptd_free_list) != PTD_ENTRY_NULL) {
		ptd_free_list = (pt_desc_t *)(*(void **)ptdp);
		ptd_free_count--;
	} else {
		panic("out of ptd entry\n");
	}

	if (!ptd_preboot)
		simple_unlock(&ptd_free_list_lock);

	ptdp->pt_page.next = NULL;
	ptdp->pt_page.prev = NULL;
	ptdp->pmap = pmap;

	for (i = 0 ; i < PT_INDEX_MAX ; i++) {
		ptdp->pt_map[i].va = 0;
		ptdp->pt_cnt[i].refcnt = 0;
		ptdp->pt_cnt[i].wiredcnt = 0;
	}
	simple_lock(&pt_pages_lock);
	queue_enter(&pt_page_list, ptdp, pt_desc_t *, pt_page);
	simple_unlock(&pt_pages_lock);

	pmap_tt_ledger_credit(pmap, sizeof(*ptdp));

	return(ptdp);
}

static void
ptd_deallocate(
	pt_desc_t *ptdp)
{
	unsigned	i;
	pmap_t		pmap = ptdp->pmap;

	if (ptd_preboot) {
		panic("ptd_deallocate(): early boot\n");
	}
	for (i = 0 ; i < PT_INDEX_MAX ; i++) {
		if (ptdp->pt_cnt[i].refcnt != 0)
			panic("ptd_deallocate(): ptdp=%p refcnt=0x%x \n", ptdp, ptdp->pt_cnt[i].refcnt);
	}

	if (ptdp->pt_page.next != NULL) {
		simple_lock(&pt_pages_lock);
		queue_remove(&pt_page_list, ptdp, pt_desc_t *, pt_page);
		simple_unlock(&pt_pages_lock);
	}
	simple_lock(&ptd_free_list_lock);
	(*(void **)ptdp) = (void *)ptd_free_list;
	ptd_free_list = (pt_desc_t *)ptdp;
	ptd_free_count++;
	simple_unlock(&ptd_free_list_lock);
	pmap_tt_ledger_debit(pmap, sizeof(*ptdp));
}

static void
ptd_init(
	pt_desc_t *ptdp,
	pmap_t pmap,
	vm_map_address_t va,
	unsigned int level,
	pt_entry_t *pte_p)
{
	if (ptdp->pmap != pmap)
		panic("ptd_init(): pmap mismatch\n");

#if	(__ARM_VMSA__ == 7)
	assert(level == 2);
	ptdp->pt_map[ARM_PT_DESC_INDEX(pte_p)].va = (vm_offset_t) va & ~(ARM_TT_L1_PT_OFFMASK);
#else
	if (level == 3) {
		ptdp->pt_map[ARM_PT_DESC_INDEX(pte_p)].va = (vm_offset_t) va & ~ARM_TT_L2_OFFMASK ;
	} else if (level == 2)
		ptdp->pt_map[ARM_PT_DESC_INDEX(pte_p)].va = (vm_offset_t) va & ~ARM_TT_L1_OFFMASK ;
#endif
	if (level < PMAP_TT_MAX_LEVEL)
		ptdp->pt_cnt[ARM_PT_DESC_INDEX(pte_p)].refcnt = PT_DESC_REFCOUNT;

}


boolean_t
pmap_valid_address(
	pmap_paddr_t addr)
{
	return pa_valid(addr);
}

#if	(__ARM_VMSA__ == 7)

/*
 *      Given an offset and a map, compute the address of the
 *      corresponding translation table entry.
 */
static inline tt_entry_t *
pmap_tte(pmap_t pmap,
	 vm_map_address_t addr)
{
	if (!(tte_index(pmap, addr) < pmap->tte_index_max))
		return (tt_entry_t *)NULL;
	return (&pmap->tte[tte_index(pmap, addr)]);
}


/*
 *	Given an offset and a map, compute the address of the
 *	pte.  If the address is invalid with respect to the map
 *	then PT_ENTRY_NULL is returned (and the map may need to grow).
 *
 *	This is only used internally.
 */
static inline pt_entry_t *
pmap_pte(
	 pmap_t pmap,
	 vm_map_address_t addr)
{
	pt_entry_t     *ptp;
	tt_entry_t     *ttp;
	tt_entry_t      tte;

	ttp = pmap_tte(pmap, addr);
	if (ttp == (tt_entry_t *)NULL)
		return (PT_ENTRY_NULL);
	tte = *ttp;
	#if MACH_ASSERT
	if ((tte & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_BLOCK)
		panic("Attempt to demote L1 block: pmap=%p, va=0x%llx, tte=0x%llx\n", pmap, (uint64_t)addr, (uint64_t)tte);
	#endif
	if ((tte & ARM_TTE_TYPE_MASK) != ARM_TTE_TYPE_TABLE)
		return (PT_ENTRY_NULL);
	ptp = (pt_entry_t *) ttetokv(tte) + ptenum(addr);
	return (ptp);
}

#else

/*
 *	Given an offset and a map, compute the address of level 1 translation table entry.
 *	If the tranlation is invalid then PT_ENTRY_NULL is returned.
 */
static inline tt_entry_t *
pmap_tt1e(pmap_t pmap,
	 vm_map_address_t addr)
{
#if __ARM64_TWO_LEVEL_PMAP__
#pragma unused(pmap, addr)
	panic("pmap_tt1e called on a two level pmap");
	return (NULL);
#else
	return (&pmap->tte[tt1_index(pmap, addr)]);
#endif
}

/*
 *	Given an offset and a map, compute the address of level 2 translation table entry.
 *	If the tranlation is invalid then PT_ENTRY_NULL is returned.
 */
static inline tt_entry_t *
pmap_tt2e(pmap_t pmap,
	 vm_map_address_t addr)
{
#if __ARM64_TWO_LEVEL_PMAP__
	return (&pmap->tte[tt2_index(pmap, addr)]);
#else
	tt_entry_t     *ttp;
	tt_entry_t      tte;

	ttp = pmap_tt1e(pmap, addr);
	tte = *ttp;
	#if MACH_ASSERT
	if ((tte & (ARM_TTE_TYPE_MASK | ARM_TTE_VALID)) == (ARM_TTE_TYPE_BLOCK | ARM_TTE_VALID))
		panic("Attempt to demote L1 block (?!): pmap=%p, va=0x%llx, tte=0x%llx\n", pmap, (uint64_t)addr, (uint64_t)tte);
	#endif
	if ((tte & (ARM_TTE_TYPE_MASK | ARM_TTE_VALID)) != (ARM_TTE_TYPE_TABLE | ARM_TTE_VALID))
		return (PT_ENTRY_NULL);

	ttp = &((tt_entry_t*) phystokv(tte & ARM_TTE_TABLE_MASK))[tt2_index(pmap, addr)];
	return ((tt_entry_t *)ttp);
#endif
}


/*
 *	Given an offset and a map, compute the address of level 3 translation table entry.
 *	If the tranlation is invalid then PT_ENTRY_NULL is returned.
 */
static inline pt_entry_t *
pmap_tt3e(
	 pmap_t pmap,
	 vm_map_address_t addr)
{
	pt_entry_t     *ptp;
	tt_entry_t     *ttp;
	tt_entry_t      tte;

	/* Level 0 currently unused */
#if __ARM64_TWO_LEVEL_PMAP__
	ttp = pmap_tt2e(pmap, addr);
	tte = *ttp;
#else
	/* Get first-level (1GB) entry */
	ttp = pmap_tt1e(pmap, addr);
	tte = *ttp;
	#if MACH_ASSERT
	if ((tte & (ARM_TTE_TYPE_MASK | ARM_TTE_VALID)) == (ARM_TTE_TYPE_BLOCK | ARM_TTE_VALID))
		panic("Attempt to demote L1 block (?!): pmap=%p, va=0x%llx, tte=0x%llx\n", pmap, (uint64_t)addr, (uint64_t)tte);
	#endif
	if ((tte & (ARM_TTE_TYPE_MASK | ARM_TTE_VALID)) != (ARM_TTE_TYPE_TABLE | ARM_TTE_VALID))
		return (PT_ENTRY_NULL);

	tte = ((tt_entry_t*) phystokv(tte & ARM_TTE_TABLE_MASK))[tt2_index(pmap, addr)];
#endif
#if MACH_ASSERT
	if ((tte & (ARM_TTE_TYPE_MASK | ARM_TTE_VALID)) == (ARM_TTE_TYPE_BLOCK | ARM_TTE_VALID))
		panic("Attempt to demote L2 block: pmap=%p, va=0x%llx, tte=0x%llx\n", pmap, (uint64_t)addr, (uint64_t)tte);
#endif
	if ((tte & (ARM_TTE_TYPE_MASK | ARM_TTE_VALID)) != (ARM_TTE_TYPE_TABLE | ARM_TTE_VALID)) {
		return (PT_ENTRY_NULL);
	}

	/* Get third-level (4KB) entry */
	ptp = &(((pt_entry_t*) phystokv(tte & ARM_TTE_TABLE_MASK))[tt3_index(pmap, addr)]);
	return (ptp);
}


static inline tt_entry_t *
pmap_tte(
	pmap_t pmap,
	vm_map_address_t addr)
{
	return(pmap_tt2e(pmap, addr));
}


static inline pt_entry_t *
pmap_pte(
	 pmap_t pmap,
	 vm_map_address_t addr)
{
	return(pmap_tt3e(pmap, addr));
}

#endif


/*
 *      Map memory at initialization.  The physical addresses being
 *      mapped are not managed and are never unmapped.
 *
 *      For now, VM is already on, we only need to map the
 *      specified memory.
 */
vm_map_address_t
pmap_map(
	 vm_map_address_t virt,
	 vm_offset_t start,
	 vm_offset_t end,
	 vm_prot_t prot,
	 unsigned int flags)
{
	kern_return_t   kr;
	vm_size_t       ps;

	ps = PAGE_SIZE;
	while (start < end) {
		kr = pmap_enter(kernel_pmap, virt, (ppnum_t)atop(start),
		                prot, VM_PROT_NONE, flags, FALSE);

		if (kr != KERN_SUCCESS) {
			panic("%s: failed pmap_enter, "
			      "virt=%p, start_addr=%p, end_addr=%p, prot=%#x, flags=%#x",
			      __FUNCTION__,
			      (void *) virt, (void *) start, (void *) end, prot, flags);
		}

		virt += ps;
		start += ps;
	}
	return (virt);
}

vm_map_address_t
pmap_map_bd_with_options(
	    vm_map_address_t virt,
	    vm_offset_t start,
	    vm_offset_t end,
	    vm_prot_t prot,
	    int32_t options)
{
	pt_entry_t      tmplate;
	pt_entry_t     *ptep;
	vm_map_address_t vaddr;
	vm_offset_t     paddr;
	pt_entry_t	mem_attr;

	switch (options & PMAP_MAP_BD_MASK) {
	case PMAP_MAP_BD_WCOMB:
		mem_attr = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_WRITECOMB);
#if	(__ARM_VMSA__ > 7)
		mem_attr |= ARM_PTE_SH(SH_OUTER_MEMORY);
#else
		mem_attr |= ARM_PTE_SH;
#endif
		break;
	case PMAP_MAP_BD_POSTED:
		mem_attr = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_POSTED);
		break;
	default:
		mem_attr = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DISABLE);
		break;
	}

	tmplate = pa_to_pte(start) | ARM_PTE_AP((prot & VM_PROT_WRITE) ? AP_RWNA : AP_RONA) |
	          mem_attr | ARM_PTE_TYPE | ARM_PTE_NX | ARM_PTE_PNX | ARM_PTE_AF;
#if __ARM_KERNEL_PROTECT__
	tmplate |= ARM_PTE_NG;
#endif /* __ARM_KERNEL_PROTECT__ */

	vaddr = virt;
	paddr = start;
	while (paddr < end) {

		ptep = pmap_pte(kernel_pmap, vaddr);
		if (ptep == PT_ENTRY_NULL) {
			panic("pmap_map_bd");
		}
		assert(!ARM_PTE_IS_COMPRESSED(*ptep));
		WRITE_PTE(ptep, tmplate);

		pte_increment_pa(tmplate);
		vaddr += PAGE_SIZE;
		paddr += PAGE_SIZE;
	}

	if (end >= start)
		flush_mmu_tlb_region(virt, (unsigned)(end - start));

	return (vaddr);
}

/*
 *      Back-door routine for mapping kernel VM at initialization.
 *      Useful for mapping memory outside the range
 *      [vm_first_phys, vm_last_phys] (i.e., devices).
 *      Otherwise like pmap_map.
 */
vm_map_address_t
pmap_map_bd(
	vm_map_address_t virt,
	vm_offset_t start,
	vm_offset_t end,
	vm_prot_t prot)
{
	pt_entry_t      tmplate;
	pt_entry_t		*ptep;
	vm_map_address_t vaddr;
	vm_offset_t		paddr;

	/* not cacheable and not buffered */
	tmplate = pa_to_pte(start)
	          | ARM_PTE_TYPE | ARM_PTE_AF | ARM_PTE_NX | ARM_PTE_PNX
	          | ARM_PTE_AP((prot & VM_PROT_WRITE) ? AP_RWNA : AP_RONA)
	          | ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DISABLE);
#if __ARM_KERNEL_PROTECT__
	tmplate |= ARM_PTE_NG;
#endif /* __ARM_KERNEL_PROTECT__ */

	vaddr = virt;
	paddr = start;
	while (paddr < end) {

		ptep = pmap_pte(kernel_pmap, vaddr);
		if (ptep == PT_ENTRY_NULL) {
			panic("pmap_map_bd");
		}
		assert(!ARM_PTE_IS_COMPRESSED(*ptep));
		WRITE_PTE(ptep, tmplate);

		pte_increment_pa(tmplate);
		vaddr += PAGE_SIZE;
		paddr += PAGE_SIZE;
	}

	if (end >= start)
		flush_mmu_tlb_region(virt, (unsigned)(end - start));

	return (vaddr);
}

/*
 *      Back-door routine for mapping kernel VM at initialization.
 *      Useful for mapping memory specific physical addresses in early
 *      boot (i.e., before kernel_map is initialized).
 *
 *      Maps are in the VM_HIGH_KERNEL_WINDOW area.
 */

vm_map_address_t
pmap_map_high_window_bd(
	vm_offset_t pa_start,
	vm_size_t len,
	vm_prot_t prot)
{
	pt_entry_t		*ptep, pte;
#if (__ARM_VMSA__ == 7)
	vm_map_address_t	va_start = VM_HIGH_KERNEL_WINDOW;
	vm_map_address_t	va_max = VM_MAX_KERNEL_ADDRESS;
#else
	vm_map_address_t	va_start = VREGION1_START;
	vm_map_address_t	va_max = VREGION1_START + VREGION1_SIZE;
#endif
	vm_map_address_t	va_end;
	vm_map_address_t	va;
	vm_size_t		offset;

	offset = pa_start & PAGE_MASK;
	pa_start -= offset;
	len += offset;

	if (len > (va_max - va_start)) {
		panic("pmap_map_high_window_bd: area too large\n");
	}

scan:
	for ( ; va_start < va_max; va_start += PAGE_SIZE) {
		ptep = pmap_pte(kernel_pmap, va_start);
		assert(!ARM_PTE_IS_COMPRESSED(*ptep));
		if (*ptep == ARM_PTE_TYPE_FAULT)
			break;
	}
	if (va_start > va_max) {
		panic("pmap_map_high_window_bd: insufficient pages\n");
	}

	for (va_end = va_start + PAGE_SIZE; va_end < va_start + len; va_end += PAGE_SIZE) {
		ptep = pmap_pte(kernel_pmap, va_end);
		assert(!ARM_PTE_IS_COMPRESSED(*ptep));
		if (*ptep != ARM_PTE_TYPE_FAULT) {
			va_start = va_end + PAGE_SIZE;
			goto scan;
		}
	}

	for (va = va_start; va < va_end; va += PAGE_SIZE, pa_start += PAGE_SIZE) {
		ptep = pmap_pte(kernel_pmap, va);
		pte = pa_to_pte(pa_start)
	          | ARM_PTE_TYPE | ARM_PTE_AF | ARM_PTE_NX | ARM_PTE_PNX
		      | ARM_PTE_AP((prot & VM_PROT_WRITE) ? AP_RWNA : AP_RONA)
	          | ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DEFAULT);
#if	(__ARM_VMSA__ > 7)
		pte |= ARM_PTE_SH(SH_OUTER_MEMORY);
#else
		pte |= ARM_PTE_SH;
#endif
#if __ARM_KERNEL_PROTECT__
		pte |= ARM_PTE_NG;
#endif /* __ARM_KERNEL_PROTECT__ */
		WRITE_PTE(ptep, pte);
	}
	PMAP_UPDATE_TLBS(kernel_pmap, va_start, va_start + len);
#if KASAN
	kasan_notify_address(va_start, len);
#endif
	return va_start;
}

#define PMAP_ALIGN(addr, align) ((addr) + ((align) - 1) & ~((align) - 1))

typedef struct pmap_io_range
{
	uint64_t addr;
	uint32_t len;
	uint32_t wimg;
} __attribute__((packed))  pmap_io_range_t;

static unsigned int 
pmap_compute_io_rgns(void)
{
	DTEntry entry;
	pmap_io_range_t *ranges;
	void *prop = NULL;
        int err;
	unsigned int prop_size;

        err = DTLookupEntry(NULL, "/defaults", &entry);
        assert(err == kSuccess);

	if (kSuccess != DTGetProperty(entry, "pmap-io-granule", &prop, &prop_size))
		return 0;

	io_rgn_granule = *((uint32_t*)prop);

	if (kSuccess != DTGetProperty(entry, "pmap-io-ranges", &prop, &prop_size))
		return 0;

	if ((io_rgn_granule == 0) || (io_rgn_granule & PAGE_MASK))
		panic("pmap I/O region granularity is not page-aligned!\n");

	ranges = prop;
	for (unsigned int i = 0; i < (prop_size / sizeof(*ranges)); ++i) {
		if ((i == 0) || (ranges[i].addr < io_rgn_start))
			io_rgn_start = ranges[i].addr;
		if ((i == 0) || ((ranges[i].addr + ranges[i].len) > io_rgn_end))
			io_rgn_end = ranges[i].addr + ranges[i].len;
	}

	if (io_rgn_start & PAGE_MASK)
		panic("pmap I/O region start is not page-aligned!\n");

	if (io_rgn_end & PAGE_MASK)
		panic("pmap I/O region end is not page-aligned!\n");

	if (((io_rgn_start < gPhysBase) && (io_rgn_end >= gPhysBase)) ||
	    ((io_rgn_start < avail_end) && (io_rgn_end >= avail_end)))
		panic("pmap I/O region overlaps physical memory!\n");

	return (unsigned int)((io_rgn_end - io_rgn_start) / io_rgn_granule);
}

static void
pmap_load_io_rgns(void)
{
	DTEntry entry;
	pmap_io_range_t *ranges;
	void *prop = NULL;
        int err;
	unsigned int prop_size;

	if (io_rgn_granule == 0)
		return;

        err = DTLookupEntry(NULL, "/defaults", &entry);
        assert(err == kSuccess);

	err = DTGetProperty(entry, "pmap-io-ranges", &prop, &prop_size);
        assert(err == kSuccess);

	ranges = prop;
	for (unsigned int i = 0; i < (prop_size / sizeof(*ranges)); ++i) {
		if ((ranges[i].addr - io_rgn_start) % io_rgn_granule)
			panic("pmap I/O region %d is not aligned to I/O granularity!\n", i);
		if (ranges[i].len % io_rgn_granule)
			panic("pmap I/O region %d size is not a multiple of I/O granularity!\n", i);
		for (uint32_t offs = 0; offs < ranges[i].len; offs += io_rgn_granule) {
			io_attr_table[(ranges[i].addr + offs - io_rgn_start) / io_rgn_granule] =
			    IO_ATTR_WIMG(ranges[i].wimg);
		}
	}
}


/*
 *	Bootstrap the system enough to run with virtual memory.
 *
 *	The early VM initialization code has already allocated
 *	the first CPU's translation table and made entries for
 *	all the one-to-one mappings to be found there.
 *
 *	We must set up the kernel pmap structures, the
 *	physical-to-virtual translation lookup tables for the
 *	physical memory to be managed (between avail_start and
 *	avail_end).

 *	Map the kernel's code and data, and allocate the system page table.
 *	Page_size must already be set.
 *
 *	Parameters:
 *	first_avail	first available physical page -
 *			   after kernel page tables
 *	avail_start	PA of first managed physical page
 *	avail_end	PA of last managed physical page
 */

void
pmap_bootstrap(
	vm_offset_t vstart)
{
	pmap_paddr_t	pmap_struct_start;
	vm_size_t       pv_head_size;
	vm_size_t       pv_lock_table_size;
	vm_size_t	ptd_root_table_size;
	vm_size_t       pp_attr_table_size;
	vm_size_t	io_attr_table_size;
	unsigned int	niorgns;
	unsigned int    npages;
	unsigned int    i;
	vm_map_offset_t	maxoffset;


#ifdef PMAP_TRACES
	if (PE_parse_boot_argn("-pmap_trace", &pmap_trace, sizeof (pmap_trace))) {
		kprintf("Kernel traces for pmap operations enabled\n");
	}
#endif

	/*
	 *	Initialize the kernel pmap.
	 */
	pmap_stamp = 1;
	kernel_pmap->tte = cpu_tte;
	kernel_pmap->ttep = cpu_ttep;
#if (__ARM_VMSA__ > 7)
	kernel_pmap->min = ARM64_TTBR1_MIN_ADDR;
#else
	kernel_pmap->min = VM_MIN_KERNEL_AND_KEXT_ADDRESS;
#endif
	kernel_pmap->max = VM_MAX_KERNEL_ADDRESS;
	kernel_pmap->wired = 0;
	kernel_pmap->ref_count = 1;
	kernel_pmap->gc_status = 0;
	kernel_pmap->nx_enabled = TRUE;
#ifdef	__arm64__
	kernel_pmap->is_64bit = TRUE;
#else
	kernel_pmap->is_64bit = FALSE;
#endif
	kernel_pmap->stamp = hw_atomic_add(&pmap_stamp, 1);

	kernel_pmap->nested_region_grand_addr = 0x0ULL;
	kernel_pmap->nested_region_subord_addr = 0x0ULL;
	kernel_pmap->nested_region_size = 0x0ULL;
	kernel_pmap->nested_region_asid_bitmap = NULL;
	kernel_pmap->nested_region_asid_bitmap_size = 0x0UL;

#if (__ARM_VMSA__ == 7)
	kernel_pmap->tte_index_max = 4*NTTES;
#else
	kernel_pmap->tte_index_max = (ARM_PGBYTES / sizeof(tt_entry_t));
#endif
	kernel_pmap->prev_tte = (tt_entry_t *) NULL;
	kernel_pmap->cpu_ref = 0;

	PMAP_LOCK_INIT(kernel_pmap);
#if	(__ARM_VMSA__ == 7)
	simple_lock_init(&kernel_pmap->tt1_lock, 0);
#endif
	memset((void *) &kernel_pmap->stats, 0, sizeof(kernel_pmap->stats));

	/* allocate space for and initialize the bookkeeping structures */
	niorgns = pmap_compute_io_rgns();
	npages = (unsigned int)atop(mem_size);
	pp_attr_table_size = npages * sizeof(pp_attr_t);
	io_attr_table_size = niorgns * sizeof(io_attr_t);
	pv_lock_table_size = npages;
	pv_head_size = round_page(sizeof(pv_entry_t *) * npages);
#if	(__ARM_VMSA__ == 7)
	ptd_root_table_size = sizeof(pt_desc_t) * (1<<((mem_size>>30)+12));
#else
	ptd_root_table_size = sizeof(pt_desc_t) * (1<<((mem_size>>30)+13));
#endif

	pmap_struct_start = avail_start;

	pp_attr_table = (pp_attr_t *) phystokv(avail_start);
	avail_start = PMAP_ALIGN(avail_start + pp_attr_table_size, __alignof(pp_attr_t));
	io_attr_table = (io_attr_t *) phystokv(avail_start);
	avail_start = PMAP_ALIGN(avail_start + io_attr_table_size + pv_lock_table_size, __alignof(pv_entry_t*));
	pv_head_table = (pv_entry_t **) phystokv(avail_start);
	avail_start = PMAP_ALIGN(avail_start + pv_head_size, __alignof(pt_desc_t));
	ptd_root_table = (pt_desc_t *)phystokv(avail_start);
	avail_start = round_page(avail_start + ptd_root_table_size);

	memset((char *)phystokv(pmap_struct_start), 0, avail_start - pmap_struct_start);

	pmap_load_io_rgns();
	ptd_bootstrap(ptd_root_table, (unsigned int)(ptd_root_table_size/sizeof(pt_desc_t)));

	pmap_cpu_data_array_init();

	vm_first_phys = gPhysBase;
	vm_last_phys = trunc_page(avail_end);

	simple_lock_init(&pmaps_lock, 0);
	queue_init(&map_pmap_list);
	queue_enter(&map_pmap_list, kernel_pmap, pmap_t, pmaps);
	queue_init(&tt_pmap_list);
	tt_pmap_count = 0;
	tt_pmap_max = 0;
	free_page_size_tt_list = TT_FREE_ENTRY_NULL;
	free_page_size_tt_count = 0;
	free_page_size_tt_max = 0;
	free_two_page_size_tt_list = TT_FREE_ENTRY_NULL;
	free_two_page_size_tt_count = 0;
	free_two_page_size_tt_max = 0;
	free_tt_list = TT_FREE_ENTRY_NULL;
	free_tt_count = 0;
	free_tt_max = 0;

	simple_lock_init(&pt_pages_lock, 0);
	queue_init(&pt_page_list);

	simple_lock_init(&pmap_pages_lock, 0);
	pmap_pages_request_count = 0;
	pmap_pages_request_acum = 0;
	pmap_pages_reclaim_list = PAGE_FREE_ENTRY_NULL;

	virtual_space_start = vstart;
	virtual_space_end = VM_MAX_KERNEL_ADDRESS;

	/* mark all the address spaces in use */
	for (i = 0; i < MAX_ASID / (sizeof(uint32_t) * NBBY); i++)
		asid_bitmap[i] = 0xffffffff;

	/*
	 * The kernel gets ASID 0, and all aliases of it.  This is
	 * important because ASID 0 is global; if we vend ASID 0
	 * out to a user pmap, those translations will show up in
	 * other processes through the TLB.
	 */
	for (i = 0; i < MAX_ASID; i += ARM_MAX_ASID) {
		asid_bitmap[i / (sizeof(uint32_t) * NBBY)] &= ~(1 << (i % (sizeof(uint32_t) * NBBY)));

#if __ARM_KERNEL_PROTECT__
		assert((i + 1) < MAX_ASID);
		asid_bitmap[(i + 1) / (sizeof(uint32_t) * NBBY)] &= ~(1 << ((i + 1) % (sizeof(uint32_t) * NBBY)));
#endif /* __ARM_KERNEL_PROTECT__ */
	}

	kernel_pmap->asid = 0;
	kernel_pmap->vasid = 0;

	if (PE_parse_boot_argn("arm_maxoffset", &maxoffset, sizeof (maxoffset))) {
		maxoffset = trunc_page(maxoffset);
		if ((maxoffset >= pmap_max_offset(FALSE, ARM_PMAP_MAX_OFFSET_MIN))
		    && (maxoffset <= pmap_max_offset(FALSE, ARM_PMAP_MAX_OFFSET_MAX))) {
                	arm_pmap_max_offset_default = maxoffset;
		}
	}
#if defined(__arm64__)
	if (PE_parse_boot_argn("arm64_maxoffset", &maxoffset, sizeof (maxoffset))) {
		maxoffset = trunc_page(maxoffset);
		if ((maxoffset >= pmap_max_offset(TRUE, ARM_PMAP_MAX_OFFSET_MIN))
		    && (maxoffset <= pmap_max_offset(TRUE, ARM_PMAP_MAX_OFFSET_MAX))) {
                	arm64_pmap_max_offset_default = maxoffset;
		}
	}
#endif

#if DEVELOPMENT || DEBUG
	PE_parse_boot_argn("panic_on_unsigned_execute", &panic_on_unsigned_execute, sizeof (panic_on_unsigned_execute));
#endif /* DEVELOPMENT || DEBUG */

	pmap_nesting_size_min = ARM_NESTING_SIZE_MIN;
	pmap_nesting_size_max = ARM_NESTING_SIZE_MAX;

	simple_lock_init(&phys_backup_lock, 0);

#if MACH_ASSERT
	PE_parse_boot_argn("pmap_stats_assert",
			   &pmap_stats_assert,
			   sizeof (pmap_stats_assert));
#endif /* MACH_ASSERT */

#if KASAN
	/* Shadow the CPU copy windows, as they fall outside of the physical aperture */
	kasan_map_shadow(CPUWINDOWS_BASE, CPUWINDOWS_TOP - CPUWINDOWS_BASE, true);
#endif /* KASAN */
}


void
pmap_virtual_space(
   vm_offset_t *startp,
   vm_offset_t *endp
)
{
	*startp = virtual_space_start;
	*endp = virtual_space_end;
}


boolean_t
pmap_virtual_region(
	unsigned int region_select,
	vm_map_offset_t *startp,
	vm_map_size_t *size
)
{
	boolean_t	ret = FALSE;
#if	__ARM64_PMAP_SUBPAGE_L1__ && __ARM_16K_PG__
	if (region_select == 0) {
		/*
		 * In this config, the bootstrap mappings should occupy their own L2
		 * TTs, as they should be immutable after boot.  Having the associated
		 * TTEs and PTEs in their own pages allows us to lock down those pages,
		 * while allowing the rest of the kernel address range to be remapped.
		 */
#if	(__ARM_VMSA__ > 7)
		*startp = LOW_GLOBAL_BASE_ADDRESS & ~ARM_TT_L2_OFFMASK;
#else
#error Unsupported configuration
#endif
		*size = ((VM_MAX_KERNEL_ADDRESS - *startp) & ~PAGE_MASK);
		ret = TRUE;
	}
#else
#if     (__ARM_VMSA__ > 7)
	unsigned long low_global_vr_mask = 0;
	vm_map_size_t low_global_vr_size = 0;
#endif

	if (region_select == 0) {
#if	(__ARM_VMSA__ == 7)
		*startp = gVirtBase & 0xFFC00000;
		*size = ((virtual_space_start-(gVirtBase & 0xFFC00000)) + ~0xFFC00000) & 0xFFC00000;
#else
		/* Round to avoid overlapping with the V=P area; round to at least the L2 block size. */
		if (!TEST_PAGE_SIZE_4K) {
			*startp = gVirtBase & 0xFFFFFFFFFE000000;
			*size = ((virtual_space_start-(gVirtBase & 0xFFFFFFFFFE000000)) + ~0xFFFFFFFFFE000000) & 0xFFFFFFFFFE000000;
		} else {
			*startp = gVirtBase & 0xFFFFFFFFFF800000;
			*size = ((virtual_space_start-(gVirtBase & 0xFFFFFFFFFF800000)) + ~0xFFFFFFFFFF800000) & 0xFFFFFFFFFF800000;
		}
#endif
		ret = TRUE;
	}
	if (region_select == 1) {
		*startp = VREGION1_START;
		*size = VREGION1_SIZE;
		ret = TRUE;
	}
#if	(__ARM_VMSA__ > 7)
	/* We need to reserve a range that is at least the size of an L2 block mapping for the low globals */
	if (!TEST_PAGE_SIZE_4K) {
		low_global_vr_mask = 0xFFFFFFFFFE000000;
		low_global_vr_size = 0x2000000;
	} else {
		low_global_vr_mask = 0xFFFFFFFFFF800000;
		low_global_vr_size = 0x800000;
	}

	if (((gVirtBase & low_global_vr_mask) != LOW_GLOBAL_BASE_ADDRESS)  && (region_select == 2)) {
		*startp = LOW_GLOBAL_BASE_ADDRESS;
		*size = low_global_vr_size;
		ret = TRUE;
	}

	if (region_select == 3) {
		/* In this config, we allow the bootstrap mappings to occupy the same
		 * page table pages as the heap.
		 */
		*startp = VM_MIN_KERNEL_ADDRESS;
		*size = LOW_GLOBAL_BASE_ADDRESS - *startp;
		ret = TRUE;
	}
#endif
#endif
	return ret;
}

unsigned int
pmap_free_pages(
	void)
{
	return (unsigned int)atop(avail_end - first_avail);
}


boolean_t
pmap_next_page_hi(
	ppnum_t * pnum)
{
	return pmap_next_page(pnum);
}


boolean_t
pmap_next_page(
	ppnum_t *pnum)
{
	if (first_avail != avail_end) {
		*pnum = (ppnum_t)atop(first_avail);
		first_avail += PAGE_SIZE;
		return TRUE;
	}
	return FALSE;
}


/*
 *	Initialize the pmap module.
 *	Called by vm_init, to initialize any structures that the pmap
 *	system needs to map virtual memory.
 */
void
pmap_init(
	void)
{
	/*
	 *	Protect page zero in the kernel map.
	 *	(can be overruled by permanent transltion
	 *	table entries at page zero - see arm_vm_init).
	 */
	vm_protect(kernel_map, 0, PAGE_SIZE, TRUE, VM_PROT_NONE);

	pmap_initialized = TRUE;

	pmap_zone_init();


	/*
	 *	Initialize the pmap object (for tracking the vm_page_t
	 *	structures for pages we allocate to be page tables in
	 *	pmap_expand().
	 */
	_vm_object_allocate(mem_size, pmap_object);
	pmap_object->copy_strategy = MEMORY_OBJECT_COPY_NONE;

	pv_init();

	/*
	 * The value of hard_maxproc may have been scaled, make sure
	 * it is still less than the value of MAX_ASID.
	 */
	assert(hard_maxproc < MAX_ASID);

#if CONFIG_PGTRACE
    pmap_pgtrace_init();
#endif
}

boolean_t
pmap_verify_free(
	ppnum_t ppnum)
{
	pv_entry_t		**pv_h;
	int             pai;
	boolean_t       result = TRUE;
	pmap_paddr_t    phys = ptoa(ppnum);

	assert(phys != vm_page_fictitious_addr);

	if (!pa_valid(phys))
		return (FALSE);

	pai = (int)pa_index(phys);
	pv_h = pai_to_pvh(pai);

	result = (pvh_list(pv_h) == PV_ENTRY_NULL);

	return (result);
}


/*
 *    Initialize zones used by pmap.
 */
static void
pmap_zone_init(
	void)
{
	/*
	 *	Create the zone of physical maps
	 *	and the physical-to-virtual entries.
	 */
	pmap_zone = zinit((vm_size_t) sizeof(struct pmap), (vm_size_t) sizeof(struct pmap)*256,
	                  PAGE_SIZE, "pmap");
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
static pmap_t
pmap_create_internal(
	ledger_t ledger,
	vm_map_size_t size,
	boolean_t is_64bit)
{
	unsigned        i;
	pmap_t          p;

	/*
	 *	A software use-only map doesn't even need a pmap.
	 */
	if (size != 0) {
		return (PMAP_NULL);
	}


	/*
	 *	Allocate a pmap struct from the pmap_zone.  Then allocate
	 *	the translation table of the right size for the pmap.
	 */
	if ((p = (pmap_t) zalloc(pmap_zone)) == PMAP_NULL)
		return (PMAP_NULL);

	if (is_64bit) {
		p->min = MACH_VM_MIN_ADDRESS;
		p->max = MACH_VM_MAX_ADDRESS;
	} else {
		p->min = VM_MIN_ADDRESS;
		p->max = VM_MAX_ADDRESS;
	}

	p->wired = 0;
	p->ref_count = 1;
	p->gc_status = 0;
	p->stamp = hw_atomic_add(&pmap_stamp, 1);
	p->nx_enabled = TRUE;
	p->is_64bit = is_64bit;
	p->nested = FALSE;
	p->nested_pmap = PMAP_NULL;


	ledger_reference(ledger);
	p->ledger = ledger;

	PMAP_LOCK_INIT(p);
#if	(__ARM_VMSA__ == 7)
	simple_lock_init(&p->tt1_lock, 0);
#endif
	memset((void *) &p->stats, 0, sizeof(p->stats));

	p->tt_entry_free = (tt_entry_t *)0;

	p->tte = pmap_tt1_allocate(p, PMAP_ROOT_ALLOC_SIZE, 0);
	p->ttep = ml_static_vtop((vm_offset_t)p->tte);

#if (__ARM_VMSA__ == 7)
	p->tte_index_max = NTTES;
#else
	p->tte_index_max = (PMAP_ROOT_ALLOC_SIZE / sizeof(tt_entry_t));
#endif
	p->prev_tte = (tt_entry_t *) NULL;
	p->cpu_ref = 0;

	/* nullify the translation table */
	for (i = 0; i < p->tte_index_max; i++)
		p->tte[i] = ARM_TTE_TYPE_FAULT;

#ifndef  __ARM_L1_PTW__
	CleanPoU_DcacheRegion((vm_offset_t) (p->tte), PMAP_ROOT_ALLOC_SIZE);
#else
	__asm__ volatile("dsb ish");
#endif
	/* assign a asid */
	p->vasid = alloc_asid();
	p->asid = p->vasid % ARM_MAX_ASID;

	/*
	 *  initialize the rest of the structure
	 */
	p->nested_region_grand_addr = 0x0ULL;
	p->nested_region_subord_addr = 0x0ULL;
	p->nested_region_size = 0x0ULL;
	p->nested_region_asid_bitmap = NULL;
	p->nested_region_asid_bitmap_size = 0x0UL;

#if MACH_ASSERT
	p->pmap_stats_assert = TRUE;
	p->pmap_pid = 0;
	strlcpy(p->pmap_procname, "<nil>", sizeof (p->pmap_procname));
#endif /* MACH_ASSERT */
#if DEVELOPMENT || DEBUG
	p->footprint_suspended = FALSE;
	p->footprint_was_suspended = FALSE;
#endif /* DEVELOPMENT || DEBUG */

	simple_lock(&pmaps_lock);
	queue_enter(&map_pmap_list, p, pmap_t, pmaps);
	simple_unlock(&pmaps_lock);

	return (p);
}

pmap_t
pmap_create(
	ledger_t ledger,
	vm_map_size_t size,
	boolean_t is_64bit)
{
	pmap_t pmap;

	PMAP_TRACE(PMAP_CODE(PMAP__CREATE) | DBG_FUNC_START, size, is_64bit);

	pmap = pmap_create_internal(ledger, size, is_64bit);

	PMAP_TRACE(PMAP_CODE(PMAP__CREATE) | DBG_FUNC_END,
	           VM_KERNEL_ADDRHIDE(pmap));

	return pmap;
}

#if MACH_ASSERT
static void
pmap_set_process_internal(
	__unused pmap_t pmap,
	__unused int pid,
	__unused char *procname)
{
#if MACH_ASSERT
	if (pmap == NULL) {
		return;
	}

	pmap->pmap_pid = pid;
	strlcpy(pmap->pmap_procname, procname, sizeof (pmap->pmap_procname));
	if (!strncmp(procname, "corecaptured", sizeof (pmap->pmap_procname))) {
		/*
		 * XXX FBDP
		 * "corecaptured" somehow triggers some issues that make
		 * the pmap stats and ledgers to go off track, causing
		 * some assertion failures and ledger panics.
		 * Turn that off if the terminating process is "corecaptured".
		 */
		pmap->pmap_stats_assert = FALSE;
		ledger_disable_panic_on_negative(pmap->ledger,
						 task_ledgers.phys_footprint);
		ledger_disable_panic_on_negative(pmap->ledger,
						 task_ledgers.internal);
		ledger_disable_panic_on_negative(pmap->ledger,
						 task_ledgers.internal_compressed);
		ledger_disable_panic_on_negative(pmap->ledger,
						 task_ledgers.iokit_mapped);
		ledger_disable_panic_on_negative(pmap->ledger,
						 task_ledgers.alternate_accounting);
		ledger_disable_panic_on_negative(pmap->ledger,
						 task_ledgers.alternate_accounting_compressed);
	}
#endif /* MACH_ASSERT */
}
#endif /* MACH_ASSERT*/

#if MACH_ASSERT
void
pmap_set_process(
	pmap_t pmap,
	int pid,
	char *procname)
{
	pmap_set_process_internal(pmap, pid, procname);
}

/*
 * We maintain stats and ledgers so that a task's physical footprint is:
 * phys_footprint = ((internal - alternate_accounting)
 *                   + (internal_compressed - alternate_accounting_compressed)
 *                   + iokit_mapped
 *                   + purgeable_nonvolatile
 *                   + purgeable_nonvolatile_compressed
 *                   + page_table)
 * where "alternate_accounting" includes "iokit" and "purgeable" memory.
 */

struct {
	uint64_t	num_pmaps_checked;

	int		phys_footprint_over;
	ledger_amount_t	phys_footprint_over_total;
	ledger_amount_t	phys_footprint_over_max;
	int		phys_footprint_under;
	ledger_amount_t	phys_footprint_under_total;
	ledger_amount_t	phys_footprint_under_max;

	int		internal_over;
	ledger_amount_t	internal_over_total;
	ledger_amount_t	internal_over_max;
	int		internal_under;
	ledger_amount_t	internal_under_total;
	ledger_amount_t	internal_under_max;

	int		internal_compressed_over;
	ledger_amount_t	internal_compressed_over_total;
	ledger_amount_t	internal_compressed_over_max;
	int		internal_compressed_under;
	ledger_amount_t	internal_compressed_under_total;
	ledger_amount_t	internal_compressed_under_max;

	int		iokit_mapped_over;
	ledger_amount_t	iokit_mapped_over_total;
	ledger_amount_t	iokit_mapped_over_max;
	int		iokit_mapped_under;
	ledger_amount_t	iokit_mapped_under_total;
	ledger_amount_t	iokit_mapped_under_max;

	int		alternate_accounting_over;
	ledger_amount_t	alternate_accounting_over_total;
	ledger_amount_t	alternate_accounting_over_max;
	int		alternate_accounting_under;
	ledger_amount_t	alternate_accounting_under_total;
	ledger_amount_t	alternate_accounting_under_max;

	int		alternate_accounting_compressed_over;
	ledger_amount_t	alternate_accounting_compressed_over_total;
	ledger_amount_t	alternate_accounting_compressed_over_max;
	int		alternate_accounting_compressed_under;
	ledger_amount_t	alternate_accounting_compressed_under_total;
	ledger_amount_t	alternate_accounting_compressed_under_max;

	int		page_table_over;
	ledger_amount_t	page_table_over_total;
	ledger_amount_t	page_table_over_max;
	int		page_table_under;
	ledger_amount_t	page_table_under_total;
	ledger_amount_t	page_table_under_max;

	int		purgeable_volatile_over;
	ledger_amount_t	purgeable_volatile_over_total;
	ledger_amount_t	purgeable_volatile_over_max;
	int		purgeable_volatile_under;
	ledger_amount_t	purgeable_volatile_under_total;
	ledger_amount_t	purgeable_volatile_under_max;

	int		purgeable_nonvolatile_over;
	ledger_amount_t	purgeable_nonvolatile_over_total;
	ledger_amount_t	purgeable_nonvolatile_over_max;
	int		purgeable_nonvolatile_under;
	ledger_amount_t	purgeable_nonvolatile_under_total;
	ledger_amount_t	purgeable_nonvolatile_under_max;

	int		purgeable_volatile_compressed_over;
	ledger_amount_t	purgeable_volatile_compressed_over_total;
	ledger_amount_t	purgeable_volatile_compressed_over_max;
	int		purgeable_volatile_compressed_under;
	ledger_amount_t	purgeable_volatile_compressed_under_total;
	ledger_amount_t	purgeable_volatile_compressed_under_max;

	int		purgeable_nonvolatile_compressed_over;
	ledger_amount_t	purgeable_nonvolatile_compressed_over_total;
	ledger_amount_t	purgeable_nonvolatile_compressed_over_max;
	int		purgeable_nonvolatile_compressed_under;
	ledger_amount_t	purgeable_nonvolatile_compressed_under_total;
	ledger_amount_t	purgeable_nonvolatile_compressed_under_max;
} pmap_ledgers_drift;
#endif /* MACH_ASSERT */

/*
 *	Retire the given physical map from service.
 *	Should only be called if the map contains
 *	no valid mappings.
 */
static void
pmap_destroy_internal(
	pmap_t pmap)
{
#if (__ARM_VMSA__ == 7)
	pt_entry_t     *ttep;
	unsigned int	i;
	pmap_t		tmp_pmap, tt_pmap;
	queue_head_t	tmp_pmap_list;

	queue_init(&tmp_pmap_list);
	simple_lock(&pmaps_lock);
	tt_pmap = CAST_DOWN_EXPLICIT(pmap_t, queue_first(&tt_pmap_list));
	while (!queue_end(&tt_pmap_list, (queue_entry_t)tt_pmap)) {
		if (tt_pmap->cpu_ref == 0 ) {
			tmp_pmap = tt_pmap;
			tt_pmap = CAST_DOWN_EXPLICIT(pmap_t, queue_next(&tmp_pmap->pmaps));
			queue_remove(&tt_pmap_list, tmp_pmap, pmap_t, pmaps);
			tt_pmap_count--;
			queue_enter(&tmp_pmap_list, tmp_pmap, pmap_t, pmaps);
		} else {
			tmp_pmap = tt_pmap;
			tt_pmap = CAST_DOWN_EXPLICIT(pmap_t, queue_next(&tmp_pmap->pmaps));
        	}
	}
	simple_unlock(&pmaps_lock);

	tmp_pmap = CAST_DOWN_EXPLICIT(pmap_t, queue_first(&tmp_pmap_list));
	while (!queue_end(&tmp_pmap_list, (queue_entry_t)tmp_pmap)) {
			tt_pmap = tmp_pmap;
			tmp_pmap = CAST_DOWN_EXPLICIT(pmap_t, queue_next(&tt_pmap->pmaps));
			queue_remove(&tmp_pmap_list, tt_pmap, pmap_t, pmaps);
			if (tt_pmap->tte) {
				pmap_tt1_deallocate(pmap, tt_pmap->tte, tt_pmap->tte_index_max*sizeof(tt_entry_t), 0);
				tt_pmap->tte = (tt_entry_t *) NULL;
				tt_pmap->ttep = 0;
				tt_pmap->tte_index_max = 0;
			}
			if (tt_pmap->prev_tte) {
				pmap_tt1_deallocate(pmap, tt_pmap->prev_tte, PMAP_ROOT_ALLOC_SIZE, 0);
				tt_pmap->prev_tte = (tt_entry_t *) NULL;
			}
			assert((tt_free_entry_t*)pmap->tt_entry_free == NULL);
			free_asid(tt_pmap->vasid);

			pmap_check_ledgers(tt_pmap);
			ledger_dereference(tt_pmap->ledger);

			zfree(pmap_zone, tt_pmap);
	}

	if (pmap == PMAP_NULL)
		return;

	if (hw_atomic_sub(&pmap->ref_count, 1) != 0)
		return;

	simple_lock(&pmaps_lock);

	while (pmap->gc_status & PMAP_GC_INFLIGHT) {
		pmap->gc_status |= PMAP_GC_WAIT;
                assert_wait((event_t) & pmap->gc_status, THREAD_UNINT);
		simple_unlock(&pmaps_lock);
                (void) thread_block(THREAD_CONTINUE_NULL);
		simple_lock(&pmaps_lock);

	}

	queue_remove(&map_pmap_list, pmap, pmap_t, pmaps);
	simple_unlock(&pmaps_lock);

	/*
	 *	Free the memory maps, then the
	 *	pmap structure.
	 */
	PMAP_LOCK(pmap);
	for (i = 0; i < pmap->tte_index_max; i++) {
		ttep = &pmap->tte[i];
		if ((*ttep & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE) {
			pmap_tte_deallocate(pmap, ttep, PMAP_TT_L1_LEVEL);
			flush_mmu_tlb_entry((i<<ARM_TT_L1_SHIFT) | (pmap->asid & 0xff));
		}
	}
	PMAP_UNLOCK(pmap);

	if (pmap->cpu_ref == 0) {
		if (pmap->tte) {
			pmap_tt1_deallocate(pmap, pmap->tte, pmap->tte_index_max*sizeof(tt_entry_t), 0);
			pmap->tte = (tt_entry_t *) NULL;
			pmap->ttep = 0;
			pmap->tte_index_max = 0;
		}
		if (pmap->prev_tte) {
			pmap_tt1_deallocate(pmap, pmap->prev_tte, PMAP_ROOT_ALLOC_SIZE, 0);
			pmap->prev_tte = (tt_entry_t *) NULL;
		}
		assert((tt_free_entry_t*)pmap->tt_entry_free == NULL);

		/* return its asid to the pool */
		free_asid(pmap->vasid);
		pmap_check_ledgers(pmap);

		ledger_dereference(pmap->ledger);
		if (pmap->nested_region_asid_bitmap)
			kfree(pmap->nested_region_asid_bitmap, pmap->nested_region_asid_bitmap_size*sizeof(unsigned int));
		zfree(pmap_zone, pmap);
	} else {
		simple_lock(&pmaps_lock);
		queue_enter(&tt_pmap_list, pmap, pmap_t, pmaps);
		tt_pmap_count++;
		if (tt_pmap_count > tt_pmap_max)
			tt_pmap_max = tt_pmap_count;
		simple_unlock(&pmaps_lock);
	}
#else
	pt_entry_t     *ttep;
	pmap_paddr_t	pa;
	vm_map_address_t c;

	if (pmap == PMAP_NULL) {
		return;
	}

	pmap_unmap_sharedpage(pmap);

	if (hw_atomic_sub(&pmap->ref_count, 1) == 0) {

		simple_lock(&pmaps_lock);
		while (pmap->gc_status & PMAP_GC_INFLIGHT) {
			pmap->gc_status |= PMAP_GC_WAIT;
			assert_wait((event_t) & pmap->gc_status, THREAD_UNINT);
			simple_unlock(&pmaps_lock);
			(void) thread_block(THREAD_CONTINUE_NULL);
			simple_lock(&pmaps_lock);
		}
		queue_remove(&map_pmap_list, pmap, pmap_t, pmaps);
		simple_unlock(&pmaps_lock);

		/*
		 *	Free the memory maps, then the
		 *	pmap structure.
		 */
		for (c = pmap->min; c < pmap->max; c += ARM_TT_L2_SIZE) {
			ttep = pmap_tt2e(pmap, c);
			if ((ttep != PT_ENTRY_NULL) && (*ttep & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE) {
				PMAP_LOCK(pmap);
				pmap_tte_deallocate(pmap, ttep, PMAP_TT_L2_LEVEL);
				PMAP_UNLOCK(pmap);
				flush_mmu_tlb_entry(tlbi_addr(c) | tlbi_asid(pmap->asid));
			}
		}
#if !__ARM64_TWO_LEVEL_PMAP__
		for (c = pmap->min; c < pmap->max; c += ARM_TT_L1_SIZE) {
			ttep = pmap_tt1e(pmap, c);
			if ((ttep != PT_ENTRY_NULL) && (*ttep & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE) {
				PMAP_LOCK(pmap);
				pmap_tte_deallocate(pmap, ttep, PMAP_TT_L1_LEVEL);
				PMAP_UNLOCK(pmap);
			}
		}
#endif

		if (pmap->tte) {
			pa = pmap->ttep;
			pmap_tt1_deallocate(pmap, (tt_entry_t *)phystokv(pa), PMAP_ROOT_ALLOC_SIZE, 0);
		}


		assert((tt_free_entry_t*)pmap->tt_entry_free == NULL);
		flush_mmu_tlb_asid((uint64_t)(pmap->asid) << TLBI_ASID_SHIFT);
		free_asid(pmap->vasid);

		if (pmap->nested_region_asid_bitmap) {
			kfree(pmap->nested_region_asid_bitmap, pmap->nested_region_asid_bitmap_size*sizeof(unsigned int));
		}

		pmap_check_ledgers(pmap);
		ledger_dereference(pmap->ledger);

		zfree(pmap_zone, pmap);
	}

#endif
}

void
pmap_destroy(
	pmap_t pmap)
{
	PMAP_TRACE(PMAP_CODE(PMAP__DESTROY) | DBG_FUNC_START,
	           VM_KERNEL_ADDRHIDE(pmap));

	pmap_destroy_internal(pmap);

	PMAP_TRACE(PMAP_CODE(PMAP__DESTROY) | DBG_FUNC_END);
}


/*
 *	Add a reference to the specified pmap.
 */
static void
pmap_reference_internal(
	pmap_t pmap)
{
	if (pmap != PMAP_NULL) {
		(void) hw_atomic_add(&pmap->ref_count, 1);
	}
}

void
pmap_reference(
	pmap_t pmap)
{
	pmap_reference_internal(pmap);
}

static tt_entry_t *
pmap_tt1_allocate(
	pmap_t		pmap,
	vm_size_t	size,
	unsigned	option)
{
	tt_entry_t		*tt1;
	tt_free_entry_t	*tt1_free;
	pmap_paddr_t	pa;
	vm_address_t	va;
	vm_address_t	va_end;
	kern_return_t	ret;

	simple_lock(&pmaps_lock);
	if ((size == PAGE_SIZE) && (free_page_size_tt_count != 0)) {
			free_page_size_tt_count--;
			tt1 = (tt_entry_t *)free_page_size_tt_list;
			free_page_size_tt_list = ((tt_free_entry_t *)tt1)->next;
			simple_unlock(&pmaps_lock);
			pmap_tt_ledger_credit(pmap, size);
			return (tt_entry_t *)tt1;
	};
	if ((size == 2*PAGE_SIZE) && (free_two_page_size_tt_count != 0)) {
			free_two_page_size_tt_count--;
			tt1 = (tt_entry_t *)free_two_page_size_tt_list;
			free_two_page_size_tt_list = ((tt_free_entry_t *)tt1)->next;
			simple_unlock(&pmaps_lock);
			pmap_tt_ledger_credit(pmap, size);
			return (tt_entry_t *)tt1;
	};
	if (free_tt_count != 0) {
			free_tt_count--;
			tt1 = (tt_entry_t *)free_tt_list;
			free_tt_list = (tt_free_entry_t *)((tt_free_entry_t *)tt1)->next;
			simple_unlock(&pmaps_lock);
			pmap_tt_ledger_credit(pmap, size);
			return (tt_entry_t *)tt1;
	}

	simple_unlock(&pmaps_lock);

	ret = pmap_pages_alloc(&pa, (unsigned)((size < PAGE_SIZE)? PAGE_SIZE : size), ((option & PMAP_TT_ALLOCATE_NOWAIT)? PMAP_PAGES_ALLOCATE_NOWAIT : 0));

	if(ret ==  KERN_RESOURCE_SHORTAGE)
		return (tt_entry_t *)0;


	if (size < PAGE_SIZE) {
		simple_lock(&pmaps_lock);

		for (va_end = phystokv(pa) + PAGE_SIZE, va = phystokv(pa) + size; va < va_end; va = va+size) {
			tt1_free = (tt_free_entry_t *)va;
			tt1_free->next = free_tt_list;
			free_tt_list = tt1_free;
			free_tt_count++;
		}
		if (free_tt_count > free_tt_max)
			free_tt_max = free_tt_count;

		simple_unlock(&pmaps_lock);
	}

	/* Always report root allocations in units of PMAP_ROOT_ALLOC_SIZE, which can be obtained by sysctl arm_pt_root_size.
	 * Depending on the device, this can vary between 512b and 16K. */
	OSAddAtomic((uint32_t)(size / PMAP_ROOT_ALLOC_SIZE), (pmap == kernel_pmap ? &inuse_kernel_tteroot_count : &inuse_user_tteroot_count));
	OSAddAtomic64(size / PMAP_ROOT_ALLOC_SIZE, &alloc_tteroot_count);
	pmap_tt_ledger_credit(pmap, size);

	return (tt_entry_t *) phystokv(pa);
}

static void
pmap_tt1_deallocate(
	pmap_t pmap,
	tt_entry_t *tt,
	vm_size_t size,
	unsigned option)
{
	tt_free_entry_t	*tt_entry;

	tt_entry = (tt_free_entry_t *)tt;
	if (not_in_kdp)
		simple_lock(&pmaps_lock);

	if (size <  PAGE_SIZE) {
		free_tt_count++;
		if (free_tt_count > free_tt_max)
			free_tt_max = free_tt_count;
		tt_entry->next = free_tt_list;
		free_tt_list = tt_entry;
	}

	if (size == PAGE_SIZE) {
		free_page_size_tt_count++;
		if (free_page_size_tt_count > free_page_size_tt_max)
			free_page_size_tt_max = free_page_size_tt_count;
		tt_entry->next = free_page_size_tt_list;
		free_page_size_tt_list = tt_entry;
	}

	if (size == 2*PAGE_SIZE) {
		free_two_page_size_tt_count++;
		if (free_two_page_size_tt_count > free_two_page_size_tt_max)
			free_two_page_size_tt_max = free_two_page_size_tt_count;
		tt_entry->next = free_two_page_size_tt_list;
		free_two_page_size_tt_list = tt_entry;
	}

	if ((option & PMAP_TT_DEALLOCATE_NOBLOCK) || (!not_in_kdp)) {
		if (not_in_kdp)
			simple_unlock(&pmaps_lock);
		pmap_tt_ledger_debit(pmap, size);
		return;
	}

	while (free_page_size_tt_count > FREE_PAGE_SIZE_TT_MAX) {

		free_page_size_tt_count--;
		tt = (tt_entry_t *)free_page_size_tt_list;
		free_page_size_tt_list = ((tt_free_entry_t *)tt)->next;

		simple_unlock(&pmaps_lock);

		pmap_pages_free(ml_static_vtop((vm_offset_t)tt), PAGE_SIZE);

		OSAddAtomic(-(int32_t)(PAGE_SIZE / PMAP_ROOT_ALLOC_SIZE), (pmap == kernel_pmap ? &inuse_kernel_tteroot_count : &inuse_user_tteroot_count));

		simple_lock(&pmaps_lock);
	}

	while (free_two_page_size_tt_count > FREE_TWO_PAGE_SIZE_TT_MAX) {
		free_two_page_size_tt_count--;
		tt = (tt_entry_t *)free_two_page_size_tt_list;
		free_two_page_size_tt_list = ((tt_free_entry_t *)tt)->next;

		simple_unlock(&pmaps_lock);

		pmap_pages_free(ml_static_vtop((vm_offset_t)tt), 2*PAGE_SIZE);

		OSAddAtomic(-2 * (int32_t)(PAGE_SIZE / PMAP_ROOT_ALLOC_SIZE), (pmap == kernel_pmap ? &inuse_kernel_tteroot_count : &inuse_user_tteroot_count));

		simple_lock(&pmaps_lock);
	}
	simple_unlock(&pmaps_lock);
	pmap_tt_ledger_debit(pmap, size);
}

static kern_return_t
pmap_tt_allocate(
	pmap_t pmap,
	tt_entry_t **ttp,
	unsigned int level,
	unsigned int options)
{
	pmap_paddr_t pa;
	*ttp = NULL;

	PMAP_LOCK(pmap);
	if  ((tt_free_entry_t *)pmap->tt_entry_free != NULL) {
		tt_free_entry_t *tt_free_next;

		tt_free_next = ((tt_free_entry_t *)pmap->tt_entry_free)->next;
		*ttp = (tt_entry_t *)pmap->tt_entry_free;
		pmap->tt_entry_free = (tt_entry_t *)tt_free_next;
	}
	PMAP_UNLOCK(pmap);

	if (*ttp == NULL) {
		pt_desc_t	*ptdp;

		/*
		 *  Allocate a VM page for the level x page table entries.
		 */
		while (pmap_pages_alloc(&pa, PAGE_SIZE, ((options & PMAP_TT_ALLOCATE_NOWAIT)? PMAP_PAGES_ALLOCATE_NOWAIT : 0)) != KERN_SUCCESS) {
			if(options & PMAP_OPTIONS_NOWAIT) {
				return KERN_RESOURCE_SHORTAGE;
			}
			VM_PAGE_WAIT();
		}

		if (level < PMAP_TT_MAX_LEVEL) {
			OSAddAtomic64(1, &alloc_ttepages_count);
			OSAddAtomic(1, (pmap == kernel_pmap ? &inuse_kernel_ttepages_count : &inuse_user_ttepages_count));
		} else {
			OSAddAtomic64(1, &alloc_ptepages_count);
			OSAddAtomic(1, (pmap == kernel_pmap ? &inuse_kernel_ptepages_count : &inuse_user_ptepages_count));
		}

		pmap_tt_ledger_credit(pmap, PAGE_SIZE);

		PMAP_ZINFO_PALLOC(pmap, PAGE_SIZE);

		ptdp = ptd_alloc(pmap);
		*(pt_desc_t **)pai_to_pvh(pa_index(pa)) = ptdp;

		__unreachable_ok_push
		if (TEST_PAGE_RATIO_4) {
			vm_address_t	va;
			vm_address_t	va_end;

			PMAP_LOCK(pmap);

			for (va_end = phystokv(pa) + PAGE_SIZE, va = phystokv(pa) + ARM_PGBYTES; va < va_end; va = va+ARM_PGBYTES) {
				((tt_free_entry_t *)va)->next = (tt_free_entry_t *)pmap->tt_entry_free;
				pmap->tt_entry_free = (tt_entry_t *)va;
			}
			PMAP_UNLOCK(pmap);
		}
		__unreachable_ok_pop

		*ttp = (tt_entry_t *)phystokv(pa);
	}


	return KERN_SUCCESS;
}


static void
pmap_tt_deallocate(
	pmap_t pmap,
	tt_entry_t *ttp,
	unsigned int level)
{
	pt_desc_t *ptdp;
	unsigned pt_acc_cnt;
	unsigned i, max_pt_index = PAGE_RATIO;
	vm_offset_t	free_page=0;

	PMAP_LOCK(pmap);

	ptdp = ptep_get_ptd((vm_offset_t)ttp);

	if (level < PMAP_TT_MAX_LEVEL) {

		if (ptdp->pt_cnt[ARM_PT_DESC_INDEX(ttp)].refcnt == PT_DESC_REFCOUNT)
			ptdp->pt_cnt[ARM_PT_DESC_INDEX(ttp)].refcnt = 0;
	}

	ptdp->pt_map[ARM_PT_DESC_INDEX(ttp)].va = 0;

	if (ptdp->pt_cnt[ARM_PT_DESC_INDEX(ttp)].refcnt != 0)
		panic("pmap_tt_deallocate(): ptdp %p, count %d\n", ptdp, ptdp->pt_cnt[ARM_PT_DESC_INDEX(ttp)].refcnt);

	for (i = 0, pt_acc_cnt = 0 ; i < max_pt_index ; i++)
		pt_acc_cnt += ptdp->pt_cnt[i].refcnt;

	if (pt_acc_cnt == 0) {
		tt_free_entry_t *tt_free_list = (tt_free_entry_t *)&pmap->tt_entry_free;
		unsigned pt_free_entry_cnt = 1;

		while (pt_free_entry_cnt < max_pt_index && tt_free_list) {
			tt_free_entry_t *tt_free_list_next;

			tt_free_list_next = tt_free_list->next;
			if ((((vm_offset_t)tt_free_list_next) - ((vm_offset_t)ttp & ~PAGE_MASK)) < PAGE_SIZE) {
				pt_free_entry_cnt++;
			}
			tt_free_list = tt_free_list_next;
		}
		if (pt_free_entry_cnt == max_pt_index) {
			tt_free_entry_t *tt_free_list_cur;

			free_page = (vm_offset_t)ttp & ~PAGE_MASK;
			tt_free_list = (tt_free_entry_t *)&pmap->tt_entry_free;
			tt_free_list_cur = (tt_free_entry_t *)&pmap->tt_entry_free;

			while (tt_free_list_cur) {
				tt_free_entry_t *tt_free_list_next;

				tt_free_list_next = tt_free_list_cur->next;
				if ((((vm_offset_t)tt_free_list_next) - free_page) < PAGE_SIZE) {
					tt_free_list->next = tt_free_list_next->next;
				} else {
					tt_free_list = tt_free_list_next;
				}
				tt_free_list_cur = tt_free_list_next;
			}
		} else {
			((tt_free_entry_t *)ttp)->next = (tt_free_entry_t *)pmap->tt_entry_free;
			pmap->tt_entry_free = ttp;
		}
	} else {
		((tt_free_entry_t *)ttp)->next = (tt_free_entry_t *)pmap->tt_entry_free;
		pmap->tt_entry_free = ttp;
	}

	PMAP_UNLOCK(pmap);

	if (free_page != 0) {

		ptd_deallocate(ptep_get_ptd((vm_offset_t)free_page));
		*(pt_desc_t **)pai_to_pvh(pa_index(ml_static_vtop(free_page))) = NULL;
		pmap_pages_free(ml_static_vtop(free_page), PAGE_SIZE);
		if (level < PMAP_TT_MAX_LEVEL)
			OSAddAtomic(-1, (pmap == kernel_pmap ? &inuse_kernel_ttepages_count : &inuse_user_ttepages_count));
		else
			OSAddAtomic(-1, (pmap == kernel_pmap ? &inuse_kernel_ptepages_count : &inuse_user_ptepages_count));
		PMAP_ZINFO_PFREE(pmap, PAGE_SIZE);
		pmap_tt_ledger_debit(pmap, PAGE_SIZE);
	}
}

static void
pmap_tte_deallocate(
	pmap_t pmap,
	tt_entry_t *ttep,
	unsigned int level)
{
	pmap_paddr_t pa;
	tt_entry_t tte;

	PMAP_ASSERT_LOCKED(pmap);

	tte = *ttep;

	if (tte == 0) {
		panic("pmap_tte_deallocate(): null tt_entry ttep==%p\n", ttep);
	}

#if     MACH_ASSERT
	if (tte_get_ptd(tte)->pmap != pmap) {
		panic("pmap_tte_deallocate(): ptd=%p ptd->pmap=%p pmap=%p \n",
		      tte_get_ptd(tte), tte_get_ptd(tte)->pmap, pmap);
	}
#endif
	if (((level+1) == PMAP_TT_MAX_LEVEL) && (tte_get_ptd(tte)->pt_cnt[ARM_PT_DESC_INDEX(ttetokv(*ttep))].refcnt != 0)) {
		panic("pmap_tte_deallocate(): pmap=%p ttep=%p ptd=%p refcnt=0x%x \n", pmap, ttep,
		       tte_get_ptd(tte), (tte_get_ptd(tte)->pt_cnt[ARM_PT_DESC_INDEX(ttetokv(*ttep))].refcnt));
	}

#if	(__ARM_VMSA__ == 7)
	{
		tt_entry_t *ttep_4M = (tt_entry_t *) ((vm_offset_t)ttep & 0xFFFFFFF0);
		unsigned i;

		for (i = 0; i<4; i++, ttep_4M++)
			*ttep_4M = (tt_entry_t) 0;
	}
#else
	*ttep = (tt_entry_t) 0;
#endif

#ifndef  __ARM_L1_PTW__
	CleanPoU_DcacheRegion((vm_offset_t) ttep, sizeof(tt_entry_t));
#else
	__asm__ volatile("dsb ish");
#endif
	if ((tte & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE) {
#if	MACH_ASSERT
		{
			pt_entry_t	*pte_p = ((pt_entry_t *) (ttetokv(tte) & ~ARM_PGMASK));
			unsigned	i;

			for (i = 0; i < (ARM_PGBYTES / sizeof(*pte_p)); i++,pte_p++) {
				if (ARM_PTE_IS_COMPRESSED(*pte_p)) {
					panic("pmap_tte_deallocate: tte=0x%llx pmap=%p, pte_p=%p, pte=0x%llx compressed\n",
					      (uint64_t)tte, pmap, pte_p, (uint64_t)(*pte_p));
				} else if (((*pte_p) & ARM_PTE_TYPE_MASK) != ARM_PTE_TYPE_FAULT) {
					panic("pmap_tte_deallocate: tte=0x%llx pmap=%p, pte_p=%p, pte=0x%llx\n",
					      (uint64_t)tte, pmap, pte_p, (uint64_t)(*pte_p));
				}
			}
		}
#endif
		PMAP_UNLOCK(pmap);

		/* Clear any page offset: we mean to free the whole page, but armv7 TTEs may only be
		 * aligned on 1K boundaries.  We clear the surrounding "chunk" of 4 TTEs above. */
		pa = tte_to_pa(tte) & ~ARM_PGMASK;
		pmap_tt_deallocate(pmap, (tt_entry_t *) phystokv(pa), level+1);
		PMAP_LOCK(pmap);
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
 *
 *	Returns the number of PTE changed, and sets *rmv_cnt
 *	to the number of SPTE changed.
 */
static int
pmap_remove_range(
	pmap_t pmap,
	vm_map_address_t va,
	pt_entry_t *bpte,
	pt_entry_t *epte,
	uint32_t *rmv_cnt)
{
	return pmap_remove_range_options(pmap, va, bpte, epte, rmv_cnt,
					 PMAP_OPTIONS_REMOVE);
}

#if MACH_ASSERT
int num_reusable_mismatch = 0;
#endif /* MACH_ASSERT */

static int
pmap_remove_range_options(
	pmap_t pmap,
	vm_map_address_t va,
	pt_entry_t *bpte,
	pt_entry_t *epte,
	uint32_t *rmv_cnt,
	int options)
{
	pt_entry_t     *cpte;
	int             num_removed, num_unwired;
	int             num_pte_changed;
	int             pai = 0;
	pmap_paddr_t    pa;
	int		num_external, num_internal, num_reusable;
	int		num_alt_internal;
	uint64_t	num_compressed, num_alt_compressed;

	PMAP_ASSERT_LOCKED(pmap);

	num_removed = 0;
	num_unwired = 0;
	num_pte_changed = 0;
	num_external = 0;
	num_internal = 0;
	num_reusable = 0;
	num_compressed = 0;
	num_alt_internal = 0;
	num_alt_compressed = 0;

	for (cpte = bpte; cpte < epte;
	     cpte += PAGE_SIZE/ARM_PGBYTES, va += PAGE_SIZE) {
		pv_entry_t    **pv_h, **pve_pp;
		pv_entry_t     *pve_p;
		pt_entry_t      spte;
		boolean_t	managed=FALSE;

		spte = *cpte;

#if CONFIG_PGTRACE
        if (pgtrace_enabled) {
            pmap_pgtrace_remove_clone(pmap, pte_to_pa(spte), va);
        }
#endif

		while (!managed) {
			if (pmap != kernel_pmap &&
			    (options & PMAP_OPTIONS_REMOVE) &&
			    (ARM_PTE_IS_COMPRESSED(spte))) {
				/*
				 * "pmap" must be locked at this point,
				 * so this should not race with another
				 * pmap_remove_range() or pmap_enter().
				 */

				/* one less "compressed"... */
				num_compressed++;
				if (spte & ARM_PTE_COMPRESSED_ALT) {
					/* ... but it used to be "ALTACCT" */
					num_alt_compressed++;
				}

				/* clear marker */
				WRITE_PTE_FAST(cpte, ARM_PTE_TYPE_FAULT);
				/*
				 * "refcnt" also accounts for
				 * our "compressed" markers,
				 * so let's update it here.
				 */
				if (OSAddAtomic16(-1, (SInt16 *) &(ptep_get_ptd(cpte)->pt_cnt[ARM_PT_DESC_INDEX(cpte)].refcnt)) <= 0)
					panic("pmap_remove_range_options: over-release of ptdp %p for pte %p\n", ptep_get_ptd(cpte), cpte);
				spte = *cpte;
			}
			/*
			 * It may be possible for the pte to transition from managed
			 * to unmanaged in this timeframe; for now, elide the assert.
			 * We should break out as a consequence of checking pa_valid.
			 */
			//assert(!ARM_PTE_IS_COMPRESSED(spte));
			pa = pte_to_pa(spte);
			if (!pa_valid(pa)) {
				break;
			}
			pai = (int)pa_index(pa);
			LOCK_PVH(pai);
			spte = *cpte;
			pa = pte_to_pa(spte);
			if (pai == (int)pa_index(pa)) {
				managed =TRUE;
				break; // Leave pai locked as we will unlock it after we free the PV entry
			}
			UNLOCK_PVH(pai);
		}

		if (ARM_PTE_IS_COMPRESSED(*cpte)) {
			/*
			 * There used to be a valid mapping here but it
			 * has already been removed when the page was
			 * sent to the VM compressor, so nothing left to
			 * remove now...
			 */
			continue;
		}

		/* remove the translation, do not flush the TLB */
		if (*cpte != ARM_PTE_TYPE_FAULT) {
			assert(!ARM_PTE_IS_COMPRESSED(*cpte));
#if MACH_ASSERT
			if (managed && (pmap != kernel_pmap) && (ptep_get_va(cpte) != va)) {
				panic("pmap_remove_range_options(): cpte=%p ptd=%p pte=0x%llx va=0x%llx\n",
				      cpte, ptep_get_ptd(cpte), (uint64_t)*cpte, (uint64_t)va);
			}
#endif
			WRITE_PTE_FAST(cpte, ARM_PTE_TYPE_FAULT);
			num_pte_changed++;
		}

		if ((spte != ARM_PTE_TYPE_FAULT) &&
		    (pmap != kernel_pmap)) {
			assert(!ARM_PTE_IS_COMPRESSED(spte));
			if (OSAddAtomic16(-1, (SInt16 *) &(ptep_get_ptd(cpte)->pt_cnt[ARM_PT_DESC_INDEX(cpte)].refcnt)) <= 0)
				panic("pmap_remove_range_options: over-release of ptdp %p for pte %p\n", ptep_get_ptd(cpte), cpte);
			if(rmv_cnt) (*rmv_cnt)++;
		}

		if (pte_is_wired(spte)) {
			pte_set_wired(cpte, 0);
			num_unwired++;
		}
		/*
		 * if not managed, we're done
		 */
		if (!managed)
			continue;
		/*
		 * find and remove the mapping from the chain for this
		 * physical address.
		 */
		ASSERT_PVH_LOCKED(pai); // Should have been locked when we found the managed PTE above
		pv_h = pai_to_pvh(pai);

		if (pvh_test_type(pv_h, PVH_TYPE_PTEP)) {
			if (__builtin_expect((cpte != pvh_ptep(pv_h)), 0))
				panic("pmap_remove_range(): cpte=%p (0x%llx) does not match pv_h=%p (%p)\n", cpte, (uint64_t)spte, pv_h, pvh_ptep(pv_h));
			if (IS_ALTACCT_PAGE(pai, PV_ENTRY_NULL)) {
				assert(IS_INTERNAL_PAGE(pai));
				num_internal++;
				num_alt_internal++;
				CLR_ALTACCT_PAGE(pai, PV_ENTRY_NULL);
			} else if (IS_INTERNAL_PAGE(pai)) {
				if (IS_REUSABLE_PAGE(pai)) {
					num_reusable++;
				} else {
					num_internal++;
				}
			} else {
				num_external++;
			}
			pvh_update_head(pv_h, PV_ENTRY_NULL, PVH_TYPE_NULL);
		} else if (pvh_test_type(pv_h, PVH_TYPE_PVEP)) {

			pve_pp = pv_h;
			pve_p = pvh_list(pv_h);

			while (pve_p != PV_ENTRY_NULL &&
			       (pve_get_ptep(pve_p) != cpte)) {
				pve_pp = pve_link_field(pve_p);
				pve_p = PVE_NEXT_PTR(pve_next(pve_p));
			}

			if (__builtin_expect((pve_p == PV_ENTRY_NULL), 0)) {
				UNLOCK_PVH(pai);
				panic("pmap_remove_range(): cpte=%p (0x%llx) not in pv_h=%p\n", cpte, (uint64_t)spte, pv_h);
			}

#if MACH_ASSERT
			if (kern_feature_override(KF_PMAPV_OVRD) == FALSE) {
				pv_entry_t *check_pve_p = PVE_NEXT_PTR(pve_next(pve_p));
				while (check_pve_p != PV_ENTRY_NULL) {
					if (pve_get_ptep(check_pve_p) == cpte) {
						panic("pmap_remove_range(): duplicate pve entry cpte=%p pmap=%p, pv_h=%p, pve_p=%p, pte=0x%llx, va=0x%llx\n",
						    cpte, pmap, pv_h, pve_p, (uint64_t)spte, (uint64_t)va);
					}
					check_pve_p = PVE_NEXT_PTR(pve_next(check_pve_p));
				}
			}
#endif

			if (IS_ALTACCT_PAGE(pai, pve_p)) {
				assert(IS_INTERNAL_PAGE(pai));
				num_internal++;
				num_alt_internal++;
				CLR_ALTACCT_PAGE(pai, pve_p);
			} else if (IS_INTERNAL_PAGE(pai)) {
				if (IS_REUSABLE_PAGE(pai)) {
					num_reusable++;
				} else {
					num_internal++;
				}
			} else {
				num_external++;
			}

			pvh_remove(pv_h, pve_pp, pve_p)	;
			pv_free(pve_p);
		} else {
			panic("pmap_remove_range(): unexpected PV head %p, cpte=%p pmap=%p pv_h=%p pte=0x%llx va=0x%llx\n",
			      *pv_h, cpte, pmap, pv_h, (uint64_t)spte, (uint64_t)va);
		}

		UNLOCK_PVH(pai);
		num_removed++;
	}

	/*
	 *	Update the counts
	 */
	OSAddAtomic(-num_removed, (SInt32 *) &pmap->stats.resident_count);
	pmap_ledger_debit(pmap, task_ledgers.phys_mem, machine_ptob(num_removed));

	if (pmap != kernel_pmap) {
		/* sanity checks... */
#if MACH_ASSERT
		if (pmap->stats.internal < num_internal) {
			if ((! pmap_stats_assert ||
			     ! pmap->pmap_stats_assert) ||
			    (pmap->stats.internal + pmap->stats.reusable) ==
			    (num_internal + num_reusable)) {
				num_reusable_mismatch++;
				printf("pmap_remove_range_options(%p,0x%llx,%p,%p,0x%x): num_internal=%d num_removed=%d num_unwired=%d num_external=%d num_reusable=%d num_compressed=%lld num_alt_internal=%d num_alt_compressed=%lld num_pte_changed=%d stats.internal=%d stats.reusable=%d\n",
				       pmap,
				       (uint64_t) va,
				       bpte,
				       epte,
				       options,
				       num_internal,
				       num_removed,
				       num_unwired,
				       num_external,
				       num_reusable,
				       num_compressed,
				       num_alt_internal,
				       num_alt_compressed,
				       num_pte_changed,
				       pmap->stats.internal,
				       pmap->stats.reusable);
				/* slight mismatch: fix it... */
				num_internal = pmap->stats.internal;
				num_reusable = pmap->stats.reusable;
			} else {
				panic("pmap_remove_range_options(%p,0x%llx,%p,%p,0x%x): num_internal=%d num_removed=%d num_unwired=%d num_external=%d num_reusable=%d num_compressed=%lld num_alt_internal=%d num_alt_compressed=%lld num_pte_changed=%d stats.internal=%d stats.reusable=%d",
				      pmap,
				      (uint64_t) va,
				      bpte,
				      epte,
				      options,
				      num_internal,
				      num_removed,
				      num_unwired,
				      num_external,
				      num_reusable,
				      num_compressed,
				      num_alt_internal,
				      num_alt_compressed,
				      num_pte_changed,
				      pmap->stats.internal,
				      pmap->stats.reusable);
			}
		}
#endif /* MACH_ASSERT */
		PMAP_STATS_ASSERTF(pmap->stats.external >= num_external,
				   pmap,
				   "pmap=%p num_external=%d stats.external=%d",
				   pmap, num_external, pmap->stats.external);
		PMAP_STATS_ASSERTF(pmap->stats.internal >= num_internal,
				   pmap,
				   "pmap=%p num_internal=%d stats.internal=%d num_reusable=%d stats.reusable=%d",
				   pmap,
				   num_internal, pmap->stats.internal,
				   num_reusable, pmap->stats.reusable);
		PMAP_STATS_ASSERTF(pmap->stats.reusable >= num_reusable,
				   pmap,
				   "pmap=%p num_internal=%d stats.internal=%d num_reusable=%d stats.reusable=%d",
				   pmap,
				   num_internal, pmap->stats.internal,
				   num_reusable, pmap->stats.reusable);
		PMAP_STATS_ASSERTF(pmap->stats.compressed >= num_compressed,
				   pmap,
				   "pmap=%p num_compressed=%lld num_alt_compressed=%lld stats.compressed=%lld",
				   pmap, num_compressed, num_alt_compressed,
				   pmap->stats.compressed);

		/* update pmap stats... */
		OSAddAtomic(-num_unwired, (SInt32 *) &pmap->stats.wired_count);
		if (num_external)
			OSAddAtomic(-num_external, &pmap->stats.external);
		if (num_internal)
			OSAddAtomic(-num_internal, &pmap->stats.internal);
		if (num_reusable)
			OSAddAtomic(-num_reusable, &pmap->stats.reusable);
		if (num_compressed)
			OSAddAtomic64(-num_compressed, &pmap->stats.compressed);
		/* ... and ledgers */
		pmap_ledger_debit(pmap, task_ledgers.wired_mem, machine_ptob(num_unwired));
		pmap_ledger_debit(pmap, task_ledgers.internal, machine_ptob(num_internal));
		pmap_ledger_debit(pmap, task_ledgers.alternate_accounting, machine_ptob(num_alt_internal));
		pmap_ledger_debit(pmap, task_ledgers.alternate_accounting_compressed, machine_ptob(num_alt_compressed));
		pmap_ledger_debit(pmap, task_ledgers.internal_compressed, machine_ptob(num_compressed));
		/* make needed adjustments to phys_footprint */
		pmap_ledger_debit(pmap, task_ledgers.phys_footprint,
				  machine_ptob((num_internal -
						num_alt_internal) +
					       (num_compressed -
						num_alt_compressed)));
	}

	/* flush the ptable entries we have written */
	if (num_pte_changed > 0)
		FLUSH_PTE_RANGE(bpte, epte);

	return num_pte_changed;
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
	pmap_t pmap,
	vm_map_address_t start,
	vm_map_address_t end)
{
	pmap_remove_options(pmap, start, end, PMAP_OPTIONS_REMOVE);
}

static int
pmap_remove_options_internal(pmap_t pmap,
vm_map_address_t start,
vm_map_address_t end,
int options)
{
	int remove_count = 0;
	pt_entry_t     *bpte, *epte;
	pt_entry_t     *pte_p;
	tt_entry_t     *tte_p;
	uint32_t	rmv_spte=0;

	PMAP_LOCK(pmap);

	tte_p = pmap_tte(pmap, start);

	if (tte_p == (tt_entry_t *) NULL) {
		goto done;
	}

	if ((*tte_p & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE) {
		pte_p = (pt_entry_t *) ttetokv(*tte_p);
		bpte = &pte_p[ptenum(start)];
		epte = bpte + ((end - start) >> ARM_TT_LEAF_SHIFT);

		remove_count += pmap_remove_range_options(pmap, start, bpte, epte,
							  &rmv_spte, options);

#if	(__ARM_VMSA__ == 7)
		if (rmv_spte && (ptep_get_ptd(pte_p)->pt_cnt[ARM_PT_DESC_INDEX(pte_p)].refcnt == 0) &&
		    (pmap != kernel_pmap) && (pmap->nested == FALSE)) {
			pmap_tte_deallocate(pmap, tte_p, PMAP_TT_L1_LEVEL);
			flush_mmu_tlb_entry((start & ~ARM_TT_L1_OFFMASK) | (pmap->asid & 0xff));
		}
#else
		if (rmv_spte && (ptep_get_ptd(pte_p)->pt_cnt[ARM_PT_DESC_INDEX(pte_p)].refcnt == 0) &&
		   (pmap != kernel_pmap) && (pmap->nested == FALSE)) {
			pmap_tte_deallocate(pmap, tte_p, PMAP_TT_L2_LEVEL);
			flush_mmu_tlb_entry(tlbi_addr(start & ~ARM_TT_L2_OFFMASK) | tlbi_asid(pmap->asid));
		}
#endif
	}

done:
	PMAP_UNLOCK(pmap);

	return remove_count;
}

void
pmap_remove_options(
	pmap_t pmap,
	vm_map_address_t start,
	vm_map_address_t end,
	int options)
{
	int             remove_count = 0;
	vm_map_address_t va;

	if (pmap == PMAP_NULL)
		return;

	PMAP_TRACE(PMAP_CODE(PMAP__REMOVE) | DBG_FUNC_START,
	           VM_KERNEL_ADDRHIDE(pmap), VM_KERNEL_ADDRHIDE(start),
	           VM_KERNEL_ADDRHIDE(end));

#if MACH_ASSERT
	if ((start|end) & PAGE_MASK) {
		panic("pmap_remove_options() pmap %p start 0x%llx end 0x%llx\n",
		      pmap, (uint64_t)start, (uint64_t)end);
	}
	if ((end < start) || (start < pmap->min) || (end > pmap->max)) {
		panic("pmap_remove_options(): invalid address range, pmap=%p, start=0x%llx, end=0x%llx\n",
		      pmap, (uint64_t)start, (uint64_t)end);
	}
#endif

	/*
	 *      Invalidate the translation buffer first
	 */
	va = start;
	while (va < end) {
		vm_map_address_t l;

#if	(__ARM_VMSA__ == 7)
		l = ((va + ARM_TT_L1_SIZE) & ~ARM_TT_L1_OFFMASK);
#else
		l = ((va + ARM_TT_L2_SIZE) & ~ARM_TT_L2_OFFMASK);
#endif
		if (l > end)
			l = end;

		remove_count += pmap_remove_options_internal(pmap, va, l, options);

		va = l;
	}


	if (remove_count > 0)
		PMAP_UPDATE_TLBS(pmap, start, end);

	PMAP_TRACE(PMAP_CODE(PMAP__REMOVE) | DBG_FUNC_END);
}


/*
 *	Remove phys addr if mapped in specified map
 */
void
pmap_remove_some_phys(
	__unused pmap_t map,
	__unused ppnum_t pn)
{
	/* Implement to support working set code */
}


void
pmap_set_pmap(
	pmap_t pmap,
#if	!__ARM_USER_PROTECT__
	__unused
#endif
	thread_t	thread)
{
	pmap_switch(pmap);
#if __ARM_USER_PROTECT__
	if (pmap->tte_index_max == NTTES) {
		thread->machine.uptw_ttc = 2;
		thread->machine.uptw_ttb = ((unsigned int) pmap->ttep) | TTBR_SETUP;
	} else {
		thread->machine.uptw_ttc = 1;       \
		thread->machine.uptw_ttb = ((unsigned int) pmap->ttep ) | TTBR_SETUP;
	}
	thread->machine.asid = pmap->asid;
#endif
}

static void
pmap_flush_core_tlb_asid(pmap_t pmap)
{
#if (__ARM_VMSA__ == 7)
	flush_core_tlb_asid(pmap->asid);
#else
	flush_core_tlb_asid(((uint64_t) pmap->asid) << TLBI_ASID_SHIFT);
#if __ARM_KERNEL_PROTECT__
	flush_core_tlb_asid(((uint64_t) pmap->asid + 1) << TLBI_ASID_SHIFT);
#endif /* __ARM_KERNEL_PROTECT__ */
#endif
}

static void
pmap_switch_internal(
	pmap_t pmap)
{
	pmap_cpu_data_t *cpu_data_ptr = pmap_get_cpu_data();
	uint32_t 	last_asid_high_bits, asid_high_bits;
	pmap_t          cur_pmap;
	pmap_t          cur_user_pmap;
	boolean_t       do_asid_flush = FALSE;

#if	(__ARM_VMSA__ == 7)
	if (not_in_kdp)
		simple_lock(&pmap->tt1_lock);
#endif

	cur_pmap = current_pmap();
	cur_user_pmap = cpu_data_ptr->cpu_user_pmap;

	/* Paranoia. */
	assert(pmap->asid < (sizeof(cpu_data_ptr->cpu_asid_high_bits) / sizeof(*cpu_data_ptr->cpu_asid_high_bits)));

	/* Extract the "virtual" bits of the ASIDs (which could cause us to alias). */
	asid_high_bits = pmap->vasid >> ARM_ASID_SHIFT;
	last_asid_high_bits = (uint32_t) cpu_data_ptr->cpu_asid_high_bits[pmap->asid];

	if (asid_high_bits != last_asid_high_bits) {
		/*
		 * If the virtual ASID of the new pmap does not match the virtual ASID
		 * last seen on this CPU for the physical ASID (that was a mouthful),
		 * then this switch runs the risk of aliasing.  We need to flush the
		 * TLB for this phyiscal ASID in this case.
		 */
		cpu_data_ptr->cpu_asid_high_bits[pmap->asid] = (uint8_t) asid_high_bits;
		do_asid_flush = TRUE;
	}

	if ((cur_user_pmap == cur_pmap) && (cur_pmap == pmap)) {
		if (cpu_data_ptr->cpu_user_pmap_stamp == pmap->stamp) {
			pmap_switch_user_ttb_internal(pmap);

#if	(__ARM_VMSA__ == 7)
			if (not_in_kdp)
				simple_unlock(&pmap->tt1_lock);
#endif

			if (do_asid_flush) {
				pmap_flush_core_tlb_asid(pmap);
			}

			return;
		} else
			cur_user_pmap = NULL;
	} else if ((cur_user_pmap == pmap) && (cpu_data_ptr->cpu_user_pmap_stamp != pmap->stamp))
			cur_user_pmap = NULL;

	pmap_switch_user_ttb_internal(pmap);

	if (do_asid_flush) {
		pmap_flush_core_tlb_asid(pmap);
	}

#if	(__ARM_VMSA__ == 7)
	if (not_in_kdp)
		simple_unlock(&pmap->tt1_lock);
#else
	if (pmap != kernel_pmap) {

		if (cur_user_pmap != PMAP_NULL) {
			/*
			 * We have a low-address global mapping for the commpage
			 * for 32-bit processes; flush it if we switch to a 64-bot
			 * process.
			 */
			if (pmap_is_64bit(pmap) && !pmap_is_64bit(cur_user_pmap)) {
				pmap_sharedpage_flush_32_to_64();
			}

		} else
			flush_core_tlb();
	}
#endif
}

void
pmap_switch(
	pmap_t pmap)
{
	pmap_switch_internal(pmap);
}

void
pmap_page_protect(
	ppnum_t ppnum,
	vm_prot_t prot)
{
	pmap_page_protect_options(ppnum, prot, 0, NULL);
}

/*
 *	Routine:	pmap_page_protect_options
 *
 *	Function:
 *		Lower the permission for all mappings to a given
 *		page.
 */
static void
pmap_page_protect_options_internal(
	ppnum_t ppnum,
	vm_prot_t prot,
	unsigned int options)
{
	pmap_paddr_t    phys = ptoa(ppnum);
	pv_entry_t    **pv_h;
	pv_entry_t     *pve_p;
	pv_entry_t     *pveh_p;
	pv_entry_t     *pvet_p;
	pt_entry_t     *pte_p;
	int             pai;
	boolean_t       remove;
	boolean_t       set_NX;
	unsigned int	pvh_cnt = 0;

	assert(ppnum != vm_page_fictitious_addr);

	/* Only work with managed pages. */
	if (!pa_valid(phys)) {
		return;
	}

	/*
	 * Determine the new protection.
	 */
	switch (prot) {
	case VM_PROT_ALL:
		return;		/* nothing to do */
	case VM_PROT_READ:
	case VM_PROT_READ | VM_PROT_EXECUTE:
		remove = FALSE;
		break;
	default:
		remove = TRUE;
		break;
	}

	pai = (int)pa_index(phys);
	LOCK_PVH(pai);
	pv_h = pai_to_pvh(pai);

	pte_p = PT_ENTRY_NULL;
	pve_p = PV_ENTRY_NULL;
	pveh_p = PV_ENTRY_NULL;
	pvet_p = PV_ENTRY_NULL;
	if (pvh_test_type(pv_h, PVH_TYPE_PTEP)) {
		pte_p = pvh_ptep(pv_h);
	} else if  (pvh_test_type(pv_h, PVH_TYPE_PVEP)) {
		pve_p = pvh_list(pv_h);
		pveh_p = pve_p;
	}

	while ((pve_p != PV_ENTRY_NULL) || (pte_p != PT_ENTRY_NULL)) {
		vm_map_address_t va;
		pmap_t          pmap;
		pt_entry_t      tmplate;
		boolean_t       update = FALSE;

		if (pve_p != PV_ENTRY_NULL)
			pte_p = pve_get_ptep(pve_p);

		pmap = ptep_get_pmap(pte_p);
		va = ptep_get_va(pte_p);

		if (pte_p == PT_ENTRY_NULL) {
			panic("pmap_page_protect: pmap=%p prot=%d options=%u, pv_h=%p, pveh_p=%p, pve_p=%p, va=0x%llx ppnum: 0x%x\n",
			      pmap, prot, options, pv_h, pveh_p, pve_p, (uint64_t)va, ppnum);
		} else if ((pmap == NULL) || (atop(pte_to_pa(*pte_p)) != ppnum)) {
#if MACH_ASSERT
			if (kern_feature_override(KF_PMAPV_OVRD) == FALSE) {

				pv_entry_t *check_pve_p = pveh_p;
				while (check_pve_p != PV_ENTRY_NULL) {
					if ((check_pve_p != pve_p) && (pve_get_ptep(check_pve_p) == pte_p)) {
						panic("pmap_page_protect: duplicate pve entry pte_p=%p pmap=%p prot=%d options=%u, pv_h=%p, pveh_p=%p, pve_p=%p, pte=0x%llx, va=0x%llx ppnum: 0x%x\n",
						    pte_p, pmap, prot, options, pv_h, pveh_p, pve_p, (uint64_t)*pte_p, (uint64_t)va, ppnum);
					}
					check_pve_p = PVE_NEXT_PTR(pve_next(check_pve_p));
				}
			}
#endif
			panic("pmap_page_protect: bad pve entry pte_p=%p pmap=%p prot=%d options=%u, pv_h=%p, pveh_p=%p, pve_p=%p, pte=0x%llx, va=0x%llx ppnum: 0x%x\n",
			    pte_p, pmap, prot, options, pv_h, pveh_p, pve_p, (uint64_t)*pte_p, (uint64_t)va, ppnum);
		}

#if DEVELOPMENT || DEBUG
		if ((prot & VM_PROT_EXECUTE) || !nx_enabled || !pmap->nx_enabled)
#else
		if ((prot & VM_PROT_EXECUTE))
#endif
			set_NX = FALSE;
		else
			set_NX = TRUE;

		/* Remove the mapping if new protection is NONE */
		if (remove) {
			boolean_t is_altacct = FALSE;

			if (IS_ALTACCT_PAGE(pai, pve_p)) {
				is_altacct = TRUE;
			} else {
				is_altacct = FALSE;
			}

			if (pte_is_wired(*pte_p)) {
				pte_set_wired(pte_p, 0);
				if (pmap != kernel_pmap) {
					pmap_ledger_debit(pmap, task_ledgers.wired_mem, PAGE_SIZE);
					OSAddAtomic(-1, (SInt32 *) &pmap->stats.wired_count);
				}
			}

			if (*pte_p != ARM_PTE_TYPE_FAULT &&
			    pmap != kernel_pmap &&
			    (options & PMAP_OPTIONS_COMPRESSOR) &&
			    IS_INTERNAL_PAGE(pai)) {
				assert(!ARM_PTE_IS_COMPRESSED(*pte_p));
				/* mark this PTE as having been "compressed" */
				tmplate = ARM_PTE_COMPRESSED;
				if (is_altacct) {
					tmplate |= ARM_PTE_COMPRESSED_ALT;
					is_altacct = TRUE;
				}
			} else {
				tmplate = ARM_PTE_TYPE_FAULT;
			}

			if ((*pte_p != ARM_PTE_TYPE_FAULT) &&
			    tmplate == ARM_PTE_TYPE_FAULT &&
			    (pmap != kernel_pmap)) {
				if (OSAddAtomic16(-1, (SInt16 *) &(ptep_get_ptd(pte_p)->pt_cnt[ARM_PT_DESC_INDEX(pte_p)].refcnt)) <= 0)
					panic("pmap_page_protect_options(): over-release of ptdp %p for pte %p\n", ptep_get_ptd(pte_p), pte_p);
			}

			if (*pte_p != tmplate) {
				WRITE_PTE(pte_p, tmplate);
				update = TRUE;
			}
			pvh_cnt++;
			pmap_ledger_debit(pmap, task_ledgers.phys_mem, PAGE_SIZE);
			OSAddAtomic(-1, (SInt32 *) &pmap->stats.resident_count);

#if MACH_ASSERT
			/*
			 * We only ever compress internal pages.
			 */
			if (options & PMAP_OPTIONS_COMPRESSOR) {
				assert(IS_INTERNAL_PAGE(pai));
			}
#endif

			if (pmap != kernel_pmap) {
				if (IS_REUSABLE_PAGE(pai) &&
				    IS_INTERNAL_PAGE(pai) &&
				    !is_altacct) {
					PMAP_STATS_ASSERTF(pmap->stats.reusable > 0, pmap, "stats.reusable %d", pmap->stats.reusable);
					OSAddAtomic(-1, &pmap->stats.reusable);
				} else if (IS_INTERNAL_PAGE(pai)) {
					PMAP_STATS_ASSERTF(pmap->stats.internal > 0, pmap, "stats.internal %d", pmap->stats.internal);
					OSAddAtomic(-1, &pmap->stats.internal);
				} else {
					PMAP_STATS_ASSERTF(pmap->stats.external > 0, pmap, "stats.external %d", pmap->stats.external);
					OSAddAtomic(-1, &pmap->stats.external);
				}
				if ((options & PMAP_OPTIONS_COMPRESSOR) &&
				    IS_INTERNAL_PAGE(pai)) {
					/* adjust "compressed" stats */
					OSAddAtomic64(+1, &pmap->stats.compressed);
					PMAP_STATS_PEAK(pmap->stats.compressed);
					pmap->stats.compressed_lifetime++;
				}

				if (IS_ALTACCT_PAGE(pai, pve_p)) {
					assert(IS_INTERNAL_PAGE(pai));
					pmap_ledger_debit(pmap, task_ledgers.internal, PAGE_SIZE);
					pmap_ledger_debit(pmap, task_ledgers.alternate_accounting, PAGE_SIZE);
					if (options & PMAP_OPTIONS_COMPRESSOR) {
						pmap_ledger_credit(pmap, task_ledgers.internal_compressed, PAGE_SIZE);
						pmap_ledger_credit(pmap, task_ledgers.alternate_accounting_compressed, PAGE_SIZE);
					}

					/*
					 * Cleanup our marker before
					 * we free this pv_entry.
					 */
					CLR_ALTACCT_PAGE(pai, pve_p);

				} else if (IS_REUSABLE_PAGE(pai)) {
					assert(IS_INTERNAL_PAGE(pai));
					if (options & PMAP_OPTIONS_COMPRESSOR) {
						pmap_ledger_credit(pmap, task_ledgers.internal_compressed, PAGE_SIZE);
						/* was not in footprint, but is now */
						pmap_ledger_credit(pmap, task_ledgers.phys_footprint, PAGE_SIZE);
					}

				} else if (IS_INTERNAL_PAGE(pai)) {
					pmap_ledger_debit(pmap, task_ledgers.internal, PAGE_SIZE);

					/*
					 * Update all stats related to physical footprint, which only
					 * deals with internal pages.
					 */
					if (options & PMAP_OPTIONS_COMPRESSOR) {
						/*
						 * This removal is only being done so we can send this page to
						 * the compressor; therefore it mustn't affect total task footprint.
						 */
						pmap_ledger_credit(pmap, task_ledgers.internal_compressed, PAGE_SIZE);
					} else {
						/*
						 * This internal page isn't going to the compressor, so adjust stats to keep
						 * phys_footprint up to date.
						 */
						pmap_ledger_debit(pmap, task_ledgers.phys_footprint, PAGE_SIZE);
					}
				} else {
					/* external page: no impact on ledgers */
				}
			}

			if (pve_p != PV_ENTRY_NULL) {
				assert(pve_next(pve_p) == PVE_NEXT_PTR(pve_next(pve_p)));
			}

		} else {
			pt_entry_t      spte;

			spte = *pte_p;

			if (pmap == kernel_pmap)
				tmplate = ((spte & ~ARM_PTE_APMASK) | ARM_PTE_AP(AP_RONA));
			else
				tmplate = ((spte & ~ARM_PTE_APMASK) | ARM_PTE_AP(AP_RORO));

			pte_set_ffr(tmplate, 0);

#if	(__ARM_VMSA__ == 7)
			if (set_NX) {
				tmplate |= ARM_PTE_NX;
			} else {
				/*
				 * While the naive implementation of this would serve to add execute
				 * permission, this is not how the VM uses this interface, or how
				 * x86_64 implements it.  So ignore requests to add execute permissions.
				 */
#if 0
				tmplate &= ~ARM_PTE_NX;
#else
				;
#endif
			}
#else
			if (set_NX)
				tmplate |= ARM_PTE_NX | ARM_PTE_PNX;
			else {
				/*
				 * While the naive implementation of this would serve to add execute
				 * permission, this is not how the VM uses this interface, or how
				 * x86_64 implements it.  So ignore requests to add execute permissions.
				 */
#if 0
				if (pmap == kernel_pmap) {
					tmplate &= ~ARM_PTE_PNX;
					tmplate |= ARM_PTE_NX;
				} else {
					tmplate &= ~ARM_PTE_NX;
					tmplate |= ARM_PTE_PNX;
				}
#else
				;
#endif
			}
#endif


			if (*pte_p != ARM_PTE_TYPE_FAULT &&
			    !ARM_PTE_IS_COMPRESSED(*pte_p) &&
			    *pte_p != tmplate) {
				WRITE_PTE(pte_p, tmplate);
				update = TRUE;
			}
		}

		/* Invalidate TLBs for all CPUs using it */
		if (update)
			PMAP_UPDATE_TLBS(pmap, va, va + PAGE_SIZE);

		pte_p = PT_ENTRY_NULL;
		pvet_p = pve_p;
		if (pve_p != PV_ENTRY_NULL) {
			pvet_p = pve_p;
			if (remove) {
				assert(pve_next(pve_p) == PVE_NEXT_PTR(pve_next(pve_p)));
			}
			pve_p = PVE_NEXT_PTR(pve_next(pve_p));
		}
	}

	/* if we removed a bunch of entries, take care of them now */
	if (remove) {
		pvh_update_head(pv_h, PV_ENTRY_NULL, PVH_TYPE_NULL);
	}

	UNLOCK_PVH(pai);

	if (remove && (pveh_p != PV_ENTRY_NULL)) {
		pv_list_free(pveh_p, pvet_p, pvh_cnt);
	}
}

void
pmap_page_protect_options(
	ppnum_t ppnum,
	vm_prot_t prot,
	unsigned int options,
	__unused void *arg)
{
	pmap_paddr_t    phys = ptoa(ppnum);

	assert(ppnum != vm_page_fictitious_addr);

	/* Only work with managed pages. */
	if (!pa_valid(phys))
		return;

	/*
	 * Determine the new protection.
	 */
	if (prot == VM_PROT_ALL) {
		return;		/* nothing to do */
	}

	PMAP_TRACE(PMAP_CODE(PMAP__PAGE_PROTECT) | DBG_FUNC_START, ppnum, prot);

	pmap_page_protect_options_internal(ppnum, prot, options);

	PMAP_TRACE(PMAP_CODE(PMAP__PAGE_PROTECT) | DBG_FUNC_END);
}

/*
 * Indicates if the pmap layer enforces some additional restrictions on the
 * given set of protections.
 */
bool pmap_has_prot_policy(__unused vm_prot_t prot)
{
	return FALSE;
}

/*
 *	Set the physical protection on the
 *	specified range of this map as requested.
 *	VERY IMPORTANT: Will not increase permissions.
 *	VERY IMPORTANT: Only pmap_enter() is allowed to grant permissions.
 */
void
pmap_protect(
	pmap_t pmap,
	vm_map_address_t b,
	vm_map_address_t e,
	vm_prot_t prot)
{
	pmap_protect_options(pmap, b, e, prot, 0, NULL);
}

static void
pmap_protect_options_internal(pmap_t pmap,
	vm_map_address_t start,
	vm_map_address_t end,
	vm_prot_t prot,
	unsigned int options,
	__unused void *args)
{
	tt_entry_t     *tte_p;
	pt_entry_t     *bpte_p, *epte_p;
	pt_entry_t     *pte_p;
	boolean_t       set_NX = TRUE;
#if (__ARM_VMSA__ > 7)
	boolean_t       set_XO = FALSE;
#endif
	boolean_t	should_have_removed = FALSE;

#ifndef	__ARM_IC_NOALIAS_ICACHE__
	boolean_t	InvalidatePoU_Icache_Done = FALSE;
#endif

#if DEVELOPMENT || DEBUG
	if (options & PMAP_OPTIONS_PROTECT_IMMEDIATE) {
		if ((prot & VM_PROT_ALL) == VM_PROT_NONE) {
			should_have_removed = TRUE;
		}
	} else
#endif
	{
		/* Determine the new protection. */
		switch (prot) {
#if (__ARM_VMSA__ > 7)
		case VM_PROT_EXECUTE:
			set_XO = TRUE;
			/* fall through */
#endif
		case VM_PROT_READ:
		case VM_PROT_READ | VM_PROT_EXECUTE:
			break;
		case VM_PROT_READ | VM_PROT_WRITE:
		case VM_PROT_ALL:
			return;		/* nothing to do */
		default:
			should_have_removed = TRUE;
		}
	}

	if (should_have_removed) {
		panic("%s: should have been a remove operation, "
		      "pmap=%p, start=%p, end=%p, prot=%#x, options=%#x, args=%p",
		      __FUNCTION__,
		      pmap, (void *)start, (void *)end, prot, options, args);
	}

#if DEVELOPMENT || DEBUG
	if ((prot & VM_PROT_EXECUTE) || !nx_enabled || !pmap->nx_enabled)
#else
	if ((prot & VM_PROT_EXECUTE))
#endif
	{
		set_NX = FALSE;
	} else {
		set_NX = TRUE;
	}

	PMAP_LOCK(pmap);
	tte_p = pmap_tte(pmap, start);

	if ((tte_p != (tt_entry_t *) NULL) && (*tte_p & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE) {
		bpte_p = (pt_entry_t *) ttetokv(*tte_p);
		bpte_p = &bpte_p[ptenum(start)];
		epte_p = bpte_p + arm_atop(end - start);
		pte_p = bpte_p;

		for (pte_p = bpte_p;
		     pte_p < epte_p;
		     pte_p += PAGE_SIZE/ARM_PGBYTES) {
			pt_entry_t spte;
#if DEVELOPMENT || DEBUG
			boolean_t  force_write = FALSE;
#endif

			spte = *pte_p;

			if ((spte == ARM_PTE_TYPE_FAULT) ||
			    ARM_PTE_IS_COMPRESSED(spte)) {
				continue;
			}

			pmap_paddr_t	pa;
			int		pai=0;
			boolean_t	managed=FALSE;

			while (!managed) {
				/*
				 * It may be possible for the pte to transition from managed
				 * to unmanaged in this timeframe; for now, elide the assert.
				 * We should break out as a consequence of checking pa_valid.
				 */
				// assert(!ARM_PTE_IS_COMPRESSED(spte));
				pa = pte_to_pa(spte);
				if (!pa_valid(pa))
					break;
				pai = (int)pa_index(pa);
				LOCK_PVH(pai);
				spte = *pte_p;
				pa = pte_to_pa(spte);
				if (pai == (int)pa_index(pa)) {
					managed =TRUE;
					break; // Leave the PVH locked as we will unlock it after we free the PTE
				}
				UNLOCK_PVH(pai);
			}

			if ((spte == ARM_PTE_TYPE_FAULT) ||
			    ARM_PTE_IS_COMPRESSED(spte)) {
				continue;
			}

			pt_entry_t      tmplate;

			if (pmap == kernel_pmap) {
#if DEVELOPMENT || DEBUG
				if ((options & PMAP_OPTIONS_PROTECT_IMMEDIATE) && (prot & VM_PROT_WRITE)) {
					force_write = TRUE;
					tmplate = ((spte & ~ARM_PTE_APMASK) | ARM_PTE_AP(AP_RWNA));
				} else
#endif
				{
					tmplate = ((spte & ~ARM_PTE_APMASK) | ARM_PTE_AP(AP_RONA));
				}
			} else {
#if DEVELOPMENT || DEBUG
				if ((options & PMAP_OPTIONS_PROTECT_IMMEDIATE) && (prot & VM_PROT_WRITE)) {
					force_write = TRUE;
					tmplate = ((spte & ~ARM_PTE_APMASK) | ARM_PTE_AP(AP_RWRW));
				} else
#endif
				{
					tmplate = ((spte & ~ARM_PTE_APMASK) | ARM_PTE_AP(AP_RORO));
				}
			}

			/*
			 * XXX Removing "NX" would
			 * grant "execute" access
			 * immediately, bypassing any
			 * checks VM might want to do
			 * in its soft fault path.
			 * pmap_protect() and co. are
			 * not allowed to increase
			 * access permissions.
			 */
#if	(__ARM_VMSA__ == 7)
			if (set_NX)
				tmplate |= ARM_PTE_NX;
			else {
				/* do NOT clear "NX"! */
			}
#else
			if (set_NX)
				tmplate |= ARM_PTE_NX | ARM_PTE_PNX;
			else {
				if (pmap == kernel_pmap) {
					/*
					 * TODO: Run CS/Monitor checks here;
					 * should we be clearing PNX here?  Is
					 * this just for dtrace?
					 */
					tmplate &= ~ARM_PTE_PNX;
					tmplate |= ARM_PTE_NX;
				} else {
					/* do NOT clear "NX"! */
					tmplate |= ARM_PTE_PNX;
					if (set_XO) {
						tmplate &= ~ARM_PTE_APMASK;
						tmplate |= ARM_PTE_AP(AP_RONA);
					}
				}
			}
#endif

#if DEVELOPMENT || DEBUG
			if (force_write) {
				/*
				 * TODO: Run CS/Monitor checks here.
				 */
				if (managed) {
					/*
					 * We are marking the page as writable,
					 * so we consider it to be modified and
					 * referenced.
					 */
					pa_set_bits(pa, PP_ATTR_REFERENCED | PP_ATTR_MODIFIED);
					tmplate |= ARM_PTE_AF;

					if (IS_REFFAULT_PAGE(pai)) {
						CLR_REFFAULT_PAGE(pai);
					}

					if (IS_MODFAULT_PAGE(pai)) {
						CLR_MODFAULT_PAGE(pai);
					}
				}
			} else if (options & PMAP_OPTIONS_PROTECT_IMMEDIATE) {
				/*
				 * An immediate request for anything other than
				 * write should still mark the page as
				 * referenced if managed.
				 */
				if (managed) {
					pa_set_bits(pa, PP_ATTR_REFERENCED);
					tmplate |= ARM_PTE_AF;

					if (IS_REFFAULT_PAGE(pai)) {
						CLR_REFFAULT_PAGE(pai);
					}
				}
			}
#endif

			/* We do not expect to write fast fault the entry. */
			pte_set_ffr(tmplate, 0);

			/* TODO: Doesn't this need to worry about PNX? */
			if (((spte & ARM_PTE_NX) == ARM_PTE_NX) && (prot & VM_PROT_EXECUTE)) {
				CleanPoU_DcacheRegion((vm_offset_t) phystokv(pa), PAGE_SIZE);
#ifdef	__ARM_IC_NOALIAS_ICACHE__
				InvalidatePoU_IcacheRegion((vm_offset_t) phystokv(pa), PAGE_SIZE);
#else
				if (!InvalidatePoU_Icache_Done) {
					InvalidatePoU_Icache();
					InvalidatePoU_Icache_Done = TRUE;
				}
#endif
			}

			WRITE_PTE_FAST(pte_p, tmplate);

			if (managed) {
				ASSERT_PVH_LOCKED(pai);
				UNLOCK_PVH(pai);
			}
		}

		FLUSH_PTE_RANGE(bpte_p, epte_p);
		PMAP_UPDATE_TLBS(pmap, start, end);
	}

	PMAP_UNLOCK(pmap);
}

void
pmap_protect_options(
	pmap_t pmap,
	vm_map_address_t b,
	vm_map_address_t e,
	vm_prot_t prot,
	unsigned int options,
	__unused void *args)
{
	vm_map_address_t l, beg;

	if ((b|e) & PAGE_MASK) {
		panic("pmap_protect_options() pmap %p start 0x%llx end 0x%llx\n",
		      pmap, (uint64_t)b, (uint64_t)e);
	}

#if DEVELOPMENT || DEBUG
	if (options & PMAP_OPTIONS_PROTECT_IMMEDIATE) {
		if ((prot & VM_PROT_ALL) == VM_PROT_NONE) {
			pmap_remove_options(pmap, b, e, options);
			return;
		}
	} else
#endif
	{
		/* Determine the new protection. */
		switch (prot) {
		case VM_PROT_EXECUTE:
		case VM_PROT_READ:
		case VM_PROT_READ | VM_PROT_EXECUTE:
			break;
		case VM_PROT_READ | VM_PROT_WRITE:
		case VM_PROT_ALL:
			return;		/* nothing to do */
		default:
			pmap_remove_options(pmap, b, e, options);
			return;
		}
	}

	PMAP_TRACE(PMAP_CODE(PMAP__PROTECT) | DBG_FUNC_START,
	           VM_KERNEL_ADDRHIDE(pmap), VM_KERNEL_ADDRHIDE(b),
	           VM_KERNEL_ADDRHIDE(e));

	beg = b;

	while (beg < e) {
		l = ((beg + ARM_TT_TWIG_SIZE) & ~ARM_TT_TWIG_OFFMASK);

		if (l > e)
			l = e;

		pmap_protect_options_internal(pmap, beg, l, prot, options, args);

		beg = l;
	}

	PMAP_TRACE(PMAP_CODE(PMAP__PROTECT) | DBG_FUNC_END);
}

/* Map a (possibly) autogenned block */
kern_return_t
pmap_map_block(
	pmap_t pmap,
	addr64_t va,
	ppnum_t pa,
	uint32_t size,
	vm_prot_t prot,
	int attr,
	__unused unsigned int flags)
{
	kern_return_t   kr;
	addr64_t        original_va = va;
	uint32_t        page;

	for (page = 0; page < size; page++) {
		kr = pmap_enter(pmap, va, pa, prot, VM_PROT_NONE, attr, TRUE);

		if (kr != KERN_SUCCESS) {
			/*
			 * This will panic for now, as it is unclear that
			 * removing the mappings is correct.
			 */
			panic("%s: failed pmap_enter, "
			      "pmap=%p, va=%#llx, pa=%u, size=%u, prot=%#x, flags=%#x",
			      __FUNCTION__,
			      pmap, va, pa, size, prot, flags);

			pmap_remove(pmap, original_va, va - original_va);
			return kr;
		}

		va += PAGE_SIZE;
		pa++;
	}

	return KERN_SUCCESS;
}

/*
 *	Insert the given physical page (p) at
 *	the specified virtual address (v) in the
 *	target physical map with the protection requested.
 *
 *	If specified, the page will be wired down, meaning
 *	that the related pte can not be reclaimed.
 *
 *	NB:  This is the only routine which MAY NOT lazy-evaluate
 *	or lose information.  That is, this routine must actually
 *	insert this page into the given map eventually (must make
 *	forward progress eventually.
 */
kern_return_t
pmap_enter(
	pmap_t pmap,
	vm_map_address_t v,
	ppnum_t pn,
	vm_prot_t prot,
	vm_prot_t fault_type,
	unsigned int flags,
	boolean_t wired)
{
	return pmap_enter_options(pmap, v, pn, prot, fault_type, flags, wired, 0, NULL);
}


static inline void pmap_enter_pte(pmap_t pmap, pt_entry_t *pte_p, pt_entry_t pte, vm_map_address_t v)
{
	if (pmap != kernel_pmap && ((pte & ARM_PTE_WIRED) != (*pte_p & ARM_PTE_WIRED)))
	{
		SInt16	*ptd_wiredcnt_ptr = (SInt16 *)&(ptep_get_ptd(pte_p)->pt_cnt[ARM_PT_DESC_INDEX(pte_p)].wiredcnt);
		if (pte & ARM_PTE_WIRED) {
			OSAddAtomic16(1, ptd_wiredcnt_ptr);
			pmap_ledger_credit(pmap, task_ledgers.wired_mem, PAGE_SIZE);
			OSAddAtomic(1, (SInt32 *) &pmap->stats.wired_count);
		} else {
			OSAddAtomic16(-1, ptd_wiredcnt_ptr);
			pmap_ledger_debit(pmap, task_ledgers.wired_mem, PAGE_SIZE);
			OSAddAtomic(-1, (SInt32 *) &pmap->stats.wired_count);
		}
	}
	if (*pte_p != ARM_PTE_TYPE_FAULT &&
	    !ARM_PTE_IS_COMPRESSED(*pte_p)) {
		WRITE_PTE(pte_p, pte);
		PMAP_UPDATE_TLBS(pmap, v, v + PAGE_SIZE);
	} else {
		WRITE_PTE(pte_p, pte);
		__asm__ volatile("isb");
	}
}

static pt_entry_t
wimg_to_pte(unsigned int wimg)
{
	pt_entry_t pte;

	switch (wimg & (VM_WIMG_MASK)) {
		case VM_WIMG_IO:
			pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DISABLE);
			pte |= ARM_PTE_NX | ARM_PTE_PNX;
			break;
		case VM_WIMG_POSTED:
			pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_POSTED);
			pte |= ARM_PTE_NX | ARM_PTE_PNX;
			break;
		case VM_WIMG_WCOMB:
			pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_WRITECOMB);
			pte |= ARM_PTE_NX | ARM_PTE_PNX;
			break;
		case VM_WIMG_WTHRU:
			pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_WRITETHRU);
#if	(__ARM_VMSA__ > 7)
			pte |= ARM_PTE_SH(SH_OUTER_MEMORY);
#else
			pte |= ARM_PTE_SH;
#endif
			break;
		case VM_WIMG_COPYBACK:
			pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_WRITEBACK);
#if	(__ARM_VMSA__ > 7)
			pte |= ARM_PTE_SH(SH_OUTER_MEMORY);
#else
			pte |= ARM_PTE_SH;
#endif
			break;
		case VM_WIMG_INNERWBACK:
			pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_INNERWRITEBACK);
#if	(__ARM_VMSA__ > 7)
			pte |= ARM_PTE_SH(SH_INNER_MEMORY);
#else
			pte |= ARM_PTE_SH;
#endif
			break;
		default:
			pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DEFAULT);
#if	(__ARM_VMSA__ > 7)
			pte |= ARM_PTE_SH(SH_OUTER_MEMORY);
#else
			pte |= ARM_PTE_SH;
#endif
	}

	return pte;
}

static kern_return_t
pmap_enter_options_internal(
	pmap_t pmap,
	vm_map_address_t v,
	ppnum_t pn,
	vm_prot_t prot,
	vm_prot_t fault_type,
	unsigned int flags,
	boolean_t wired,
	unsigned int options)
{
	pmap_paddr_t    pa = ptoa(pn);
	pt_entry_t      pte;
	pt_entry_t      spte;
	pt_entry_t      *pte_p;
	pv_entry_t      *pve_p;
	boolean_t       set_NX;
	boolean_t       set_XO = FALSE;
	boolean_t       refcnt_updated;
	boolean_t       wiredcnt_updated;
	unsigned int    wimg_bits;
	boolean_t       was_compressed, was_alt_compressed;

	if ((v) & PAGE_MASK) {
		panic("pmap_enter_options() pmap %p v 0x%llx\n",
		      pmap, (uint64_t)v);
	}

	if ((prot & VM_PROT_EXECUTE) && (prot & VM_PROT_WRITE) && (pmap == kernel_pmap)) {
		panic("pmap_enter_options(): WX request on kernel_pmap");
	}

#if DEVELOPMENT || DEBUG
	if ((prot & VM_PROT_EXECUTE) || !nx_enabled || !pmap->nx_enabled)
#else
	if ((prot & VM_PROT_EXECUTE))
#endif
		set_NX = FALSE;
	else
		set_NX = TRUE;

#if (__ARM_VMSA__ > 7)
	if (prot == VM_PROT_EXECUTE) {
		set_XO = TRUE;
	}
#endif

	assert(pn != vm_page_fictitious_addr);

	refcnt_updated = FALSE;
	wiredcnt_updated = FALSE;
	pve_p = PV_ENTRY_NULL;
	was_compressed = FALSE;
	was_alt_compressed = FALSE;

	PMAP_LOCK(pmap);

	/*
	 *	Expand pmap to include this pte.  Assume that
	 *	pmap is always expanded to include enough hardware
	 *	pages to map one VM page.
	 */
	while ((pte_p = pmap_pte(pmap, v)) == PT_ENTRY_NULL) {
		/* Must unlock to expand the pmap. */
		PMAP_UNLOCK(pmap);

		kern_return_t kr=pmap_expand(pmap, v, options, PMAP_TT_MAX_LEVEL);

		if(kr) {
			return kr;
		}

		PMAP_LOCK(pmap);
	}

	if (options & PMAP_OPTIONS_NOENTER) {
		PMAP_UNLOCK(pmap);
		return KERN_SUCCESS;
	}

Pmap_enter_retry:

	spte = *pte_p;

	if (ARM_PTE_IS_COMPRESSED(spte)) {
		/*
		 * "pmap" should be locked at this point, so this should
		 * not race with another pmap_enter() or pmap_remove_range().
		 */
		assert(pmap != kernel_pmap);

		/* one less "compressed" */
		OSAddAtomic64(-1, &pmap->stats.compressed);
		pmap_ledger_debit(pmap, task_ledgers.internal_compressed,
				  PAGE_SIZE);

		was_compressed = TRUE;
		if (spte & ARM_PTE_COMPRESSED_ALT) {
			was_alt_compressed = TRUE;
			pmap_ledger_debit(
				pmap,
				task_ledgers.alternate_accounting_compressed,
				PAGE_SIZE);
		} else {
			/* was part of the footprint */
			pmap_ledger_debit(pmap, task_ledgers.phys_footprint, PAGE_SIZE);
		}

		/* clear "compressed" marker */
		/* XXX is it necessary since we're about to overwrite it ? */
		WRITE_PTE_FAST(pte_p, ARM_PTE_TYPE_FAULT);
		spte = ARM_PTE_TYPE_FAULT;

		/*
		 * We're replacing a "compressed" marker with a valid PTE,
		 * so no change for "refcnt".
		 */
		refcnt_updated = TRUE;
	}

	if ((spte != ARM_PTE_TYPE_FAULT) && (pte_to_pa(spte) != pa)) {
		pmap_remove_range(pmap, v, pte_p, pte_p + 1, 0);
		PMAP_UPDATE_TLBS(pmap, v, v + PAGE_SIZE);
	}

	pte = pa_to_pte(pa) | ARM_PTE_TYPE;

	/* Don't bother tracking wiring for kernel PTEs.  We use ARM_PTE_WIRED to track
	 * wired memory statistics for user pmaps, but kernel PTEs are assumed
	 * to be wired in nearly all cases.  For VM layer functionality, the wired
	 * count in vm_page_t is sufficient. */
	if (wired && pmap != kernel_pmap)
		pte |= ARM_PTE_WIRED;

#if	(__ARM_VMSA__ == 7)
	if (set_NX)
		pte |= ARM_PTE_NX;
#else
	if (set_NX)
		pte |= ARM_PTE_NX | ARM_PTE_PNX;
	else {
		if (pmap == kernel_pmap) {
			pte |= ARM_PTE_NX;
		} else {
			pte |= ARM_PTE_PNX;
		}
	}
#endif

	if ((flags & (VM_WIMG_MASK | VM_WIMG_USE_DEFAULT)))
		wimg_bits = (flags & (VM_WIMG_MASK | VM_WIMG_USE_DEFAULT));
	else
		wimg_bits = pmap_cache_attributes(pn);

	pte |= wimg_to_pte(wimg_bits);

	if (pmap == kernel_pmap) {
#if __ARM_KERNEL_PROTECT__
		pte |= ARM_PTE_NG;
#endif /* __ARM_KERNEL_PROTECT__ */
		if (prot & VM_PROT_WRITE) {
			pte |= ARM_PTE_AP(AP_RWNA);
			pa_set_bits(pa, PP_ATTR_MODIFIED | PP_ATTR_REFERENCED);
		} else {
			pte |= ARM_PTE_AP(AP_RONA);
			pa_set_bits(pa, PP_ATTR_REFERENCED);
		}
#if	(__ARM_VMSA__ == 7)
		if ((_COMM_PAGE_BASE_ADDRESS <= v) && (v < _COMM_PAGE_BASE_ADDRESS + _COMM_PAGE_AREA_LENGTH))
			pte = (pte & ~(ARM_PTE_APMASK)) | ARM_PTE_AP(AP_RORO);
#endif
	} else {
		if (!(pmap->nested)) {
			pte |= ARM_PTE_NG;
		} else if ((pmap->nested_region_asid_bitmap)
			    && (v >= pmap->nested_region_subord_addr)
			    && (v < (pmap->nested_region_subord_addr+pmap->nested_region_size))) {

			unsigned int index = (unsigned int)((v - pmap->nested_region_subord_addr)  >> ARM_TT_TWIG_SHIFT);

			if ((pmap->nested_region_asid_bitmap)
			     && testbit(index, (int *)pmap->nested_region_asid_bitmap))
				pte |= ARM_PTE_NG;
		}
#if MACH_ASSERT
		if (pmap->nested_pmap != NULL) {
			vm_map_address_t nest_vaddr;
			pt_entry_t		*nest_pte_p;

			nest_vaddr = v - pmap->nested_region_grand_addr + pmap->nested_region_subord_addr;

			if ((nest_vaddr >= pmap->nested_region_subord_addr)
				&& (nest_vaddr < (pmap->nested_region_subord_addr+pmap->nested_region_size))
				&& ((nest_pte_p = pmap_pte(pmap->nested_pmap, nest_vaddr)) != PT_ENTRY_NULL)
				&& (*nest_pte_p != ARM_PTE_TYPE_FAULT)
				&& (!ARM_PTE_IS_COMPRESSED(*nest_pte_p))
				&& (((*nest_pte_p) & ARM_PTE_NG) != ARM_PTE_NG)) {
				unsigned int index = (unsigned int)((v - pmap->nested_region_subord_addr)  >> ARM_TT_TWIG_SHIFT);

				if ((pmap->nested_pmap->nested_region_asid_bitmap)
					&& !testbit(index, (int *)pmap->nested_pmap->nested_region_asid_bitmap)) {

					panic("pmap_enter(): Global attribute conflict nest_pte_p=%p pmap=%p v=0x%llx spte=0x%llx \n",
					      nest_pte_p, pmap, (uint64_t)v, (uint64_t)*nest_pte_p);
				}
			}

		}
#endif
		if (prot & VM_PROT_WRITE) {

			if (pa_valid(pa) && (!pa_test_bits(pa, PP_ATTR_MODIFIED))) {
				if (fault_type & VM_PROT_WRITE) {
					if (set_XO)
						pte |= ARM_PTE_AP(AP_RWNA);
					else
						pte |= ARM_PTE_AP(AP_RWRW);
					pa_set_bits(pa, PP_ATTR_REFERENCED | PP_ATTR_MODIFIED);
				} else {
					if (set_XO)
						pte |= ARM_PTE_AP(AP_RONA);
					else
						pte |= ARM_PTE_AP(AP_RORO);
					pa_set_bits(pa, PP_ATTR_REFERENCED);
					pte_set_ffr(pte, 1);
				}
			} else {
				if (set_XO)
					pte |= ARM_PTE_AP(AP_RWNA);
				else
					pte |= ARM_PTE_AP(AP_RWRW);
				pa_set_bits(pa, PP_ATTR_REFERENCED);
			}
		} else {

			if (set_XO)
				pte |= ARM_PTE_AP(AP_RONA);
			else
				pte |= ARM_PTE_AP(AP_RORO);
			pa_set_bits(pa, PP_ATTR_REFERENCED);
		}
	}

	pte |= ARM_PTE_AF;

	volatile uint16_t *refcnt = NULL;
	volatile uint16_t *wiredcnt = NULL;
	if (pmap != kernel_pmap) {
		refcnt = &(ptep_get_ptd(pte_p)->pt_cnt[ARM_PT_DESC_INDEX(pte_p)].refcnt);
		wiredcnt = &(ptep_get_ptd(pte_p)->pt_cnt[ARM_PT_DESC_INDEX(pte_p)].wiredcnt);
		/* Bump the wired count to keep the PTE page from being reclaimed.  We need this because
		 * we may drop the PVH and pmap locks later in pmap_enter() if we need to allocate
		 * a new PV entry. */
		if (!wiredcnt_updated) {
			OSAddAtomic16(1, (volatile int16_t*)wiredcnt);
			wiredcnt_updated = TRUE;
		}
		if (!refcnt_updated) {
			OSAddAtomic16(1, (volatile int16_t*)refcnt);
			refcnt_updated = TRUE;
		}
	}

	if (pa_valid(pa)) {
		pv_entry_t    **pv_h;
		int             pai;
		boolean_t	is_altacct, is_internal;

		is_internal = FALSE;
		is_altacct = FALSE;

		pai = (int)pa_index(pa);
		pv_h = pai_to_pvh(pai);

		LOCK_PVH(pai);
Pmap_enter_loop:

		if (pte == *pte_p) {
			/*
			 * This pmap_enter operation has been completed by another thread
			 * undo refcnt on pt and return
			 */
			if (refcnt != NULL) {
				assert(refcnt_updated);
				if (OSAddAtomic16(-1, (volatile int16_t*)refcnt) <= 0)
					panic("pmap_enter(): over-release of ptdp %p for pte %p\n", ptep_get_ptd(pte_p), pte_p);
			}
			UNLOCK_PVH(pai);
			goto Pmap_enter_return;
		} else if (pte_to_pa(*pte_p) == pa) {
			if (refcnt != NULL) {
				assert(refcnt_updated);
				if (OSAddAtomic16(-1, (volatile int16_t*)refcnt) <= 0)
					panic("pmap_enter(): over-release of ptdp %p for pte %p\n", ptep_get_ptd(pte_p), pte_p);
			}
			pmap_enter_pte(pmap, pte_p, pte, v);
			UNLOCK_PVH(pai);
			goto Pmap_enter_return;
		} else if (*pte_p != ARM_PTE_TYPE_FAULT) {
			/*
			 * pte has been modified by another thread
			 * hold refcnt on pt and retry pmap_enter operation
			 */
			UNLOCK_PVH(pai);
			goto Pmap_enter_retry;
		}
		if (pvh_test_type(pv_h, PVH_TYPE_NULL))	{
			pvh_update_head(pv_h, pte_p, PVH_TYPE_PTEP);
			/* 1st mapping: see what kind of page it is */
			if (options & PMAP_OPTIONS_INTERNAL) {
				SET_INTERNAL_PAGE(pai);
			} else {
				CLR_INTERNAL_PAGE(pai);
			}
			if ((options & PMAP_OPTIONS_INTERNAL) &&
			    (options & PMAP_OPTIONS_REUSABLE)) {
				SET_REUSABLE_PAGE(pai);
			} else {
				CLR_REUSABLE_PAGE(pai);
			}
			if (pmap != kernel_pmap &&
			    ((options & PMAP_OPTIONS_ALT_ACCT) ||
			     PMAP_FOOTPRINT_SUSPENDED(pmap)) &&
			    IS_INTERNAL_PAGE(pai)) {
				/*
				 * Make a note to ourselves that this mapping is using alternative
				 * accounting. We'll need this in order to know which ledger to
				 * debit when the mapping is removed.
				 *
				 * The altacct bit must be set while the pv head is locked. Defer
				 * the ledger accounting until after we've dropped the lock.
				 */
				SET_ALTACCT_PAGE(pai, PV_ENTRY_NULL);
				is_altacct = TRUE;
			} else {
				CLR_ALTACCT_PAGE(pai, PV_ENTRY_NULL);
			}
		} else {
			if (pvh_test_type(pv_h, PVH_TYPE_PTEP)) {
				pt_entry_t	*pte1_p;

				/*
				 * convert pvh list from PVH_TYPE_PTEP to PVH_TYPE_PVEP
				 */
				pte1_p = pvh_ptep(pv_h);
				if((pve_p == PV_ENTRY_NULL) && (!pv_alloc(pmap, pai, &pve_p))) {
					goto Pmap_enter_loop;
				}
				pve_set_ptep(pve_p, pte1_p);
				pve_p->pve_next = PV_ENTRY_NULL;

				if (IS_ALTACCT_PAGE(pai, PV_ENTRY_NULL)) {
					/*
					 * transfer "altacct" from
					 * pp_attr to this pve
					 */
					CLR_ALTACCT_PAGE(pai, PV_ENTRY_NULL);
					SET_ALTACCT_PAGE(pai, pve_p);
				}
				pvh_update_head(pv_h, pve_p, PVH_TYPE_PVEP);
				pve_p = PV_ENTRY_NULL;
			}
			/*
			 * Set up pv_entry for this new mapping and then
			 * add it to the list for this physical page.
			 */
			if((pve_p == PV_ENTRY_NULL) && (!pv_alloc(pmap, pai, &pve_p))) {
				goto Pmap_enter_loop;
			}
			pve_set_ptep(pve_p, pte_p);
			pve_p->pve_next = PV_ENTRY_NULL;

			pvh_add(pv_h, pve_p);

			if (pmap != kernel_pmap &&
			    ((options & PMAP_OPTIONS_ALT_ACCT) ||
			     PMAP_FOOTPRINT_SUSPENDED(pmap)) &&
			    IS_INTERNAL_PAGE(pai)) {
				/*
				 * Make a note to ourselves that this
				 * mapping is using alternative
				 * accounting. We'll need this in order
				 * to know which ledger to debit when
				 * the mapping is removed.
				 *
				 * The altacct bit must be set while
				 * the pv head is locked. Defer the
				 * ledger accounting until after we've
				 * dropped the lock.
				 */
				SET_ALTACCT_PAGE(pai, pve_p);
				is_altacct = TRUE;
			}

			pve_p = PV_ENTRY_NULL;
		}

		pmap_enter_pte(pmap, pte_p, pte, v);

		if (pmap != kernel_pmap) {
			if (IS_REUSABLE_PAGE(pai) &&
			    !is_altacct) {
				assert(IS_INTERNAL_PAGE(pai));
				OSAddAtomic(+1, &pmap->stats.reusable);
				PMAP_STATS_PEAK(pmap->stats.reusable);
			} else if (IS_INTERNAL_PAGE(pai)) {
				OSAddAtomic(+1, &pmap->stats.internal);
				PMAP_STATS_PEAK(pmap->stats.internal);
				is_internal = TRUE;
			} else {
				OSAddAtomic(+1, &pmap->stats.external);
				PMAP_STATS_PEAK(pmap->stats.external);
			}
		}

		UNLOCK_PVH(pai);

		if (pmap != kernel_pmap) {
			pmap_ledger_credit(pmap, task_ledgers.phys_mem, PAGE_SIZE);

			if (is_internal) {
				/*
				 * Make corresponding adjustments to
				 * phys_footprint statistics.
				 */
				pmap_ledger_credit(pmap, task_ledgers.internal, PAGE_SIZE);
				if (is_altacct) {
					/*
					 * If this page is internal and
					 * in an IOKit region, credit
					 * the task's total count of
					 * dirty, internal IOKit pages.
					 * It should *not* count towards
					 * the task's total physical
					 * memory footprint, because
					 * this entire region was
					 * already billed to the task
					 * at the time the mapping was
					 * created.
					 *
					 * Put another way, this is
					 * internal++ and
					 * alternate_accounting++, so
					 * net effect on phys_footprint
					 * is 0. That means: don't
					 * touch phys_footprint here.
					 */
					pmap_ledger_credit(pmap, task_ledgers.alternate_accounting, PAGE_SIZE);
				}  else {
					pmap_ledger_credit(pmap, task_ledgers.phys_footprint, PAGE_SIZE);
				}
			}
		}

		OSAddAtomic(1, (SInt32 *) &pmap->stats.resident_count);
		if (pmap->stats.resident_count > pmap->stats.resident_max)
			pmap->stats.resident_max = pmap->stats.resident_count;
	} else {
		pmap_enter_pte(pmap, pte_p, pte, v);
	}

Pmap_enter_return:

#if CONFIG_PGTRACE
	if (pgtrace_enabled) {
		// Clone and invalidate original mapping if eligible
		for (int i = 0; i < PAGE_RATIO; i++) {
			pmap_pgtrace_enter_clone(pmap, v + ARM_PGBYTES*i, 0, 0);
		}
	}
#endif

	if (pve_p != PV_ENTRY_NULL)
		pv_free(pve_p);

	if (wiredcnt_updated && (OSAddAtomic16(-1, (volatile int16_t*)wiredcnt) <= 0))
		panic("pmap_enter(): over-unwire of ptdp %p for pte %p\n", ptep_get_ptd(pte_p), pte_p);

	PMAP_UNLOCK(pmap);

	return KERN_SUCCESS;
}

kern_return_t
pmap_enter_options(
	pmap_t pmap,
	vm_map_address_t v,
	ppnum_t pn,
	vm_prot_t prot,
	vm_prot_t fault_type,
	unsigned int flags,
	boolean_t wired,
	unsigned int options,
	__unused void	*arg)
{
	kern_return_t kr = KERN_FAILURE;

	PMAP_TRACE(PMAP_CODE(PMAP__ENTER) | DBG_FUNC_START,
	           VM_KERNEL_ADDRHIDE(pmap), VM_KERNEL_ADDRHIDE(v), pn, prot);

	kr = pmap_enter_options_internal(pmap, v, pn, prot, fault_type, flags, wired, options);

	PMAP_TRACE(PMAP_CODE(PMAP__ENTER) | DBG_FUNC_END, kr);

	return kr;
}

/*
 *	Routine:	pmap_change_wiring
 *	Function:	Change the wiring attribute for a map/virtual-address
 *			pair.
 *	In/out conditions:
 *			The mapping must already exist in the pmap.
 */
static void
pmap_change_wiring_internal(
	pmap_t pmap,
	vm_map_address_t v,
	boolean_t wired)
{
	pt_entry_t     *pte_p;
	pmap_paddr_t    pa;

	/* Don't bother tracking wiring for kernel PTEs.  We use ARM_PTE_WIRED to track
	 * wired memory statistics for user pmaps, but kernel PTEs are assumed
	 * to be wired in nearly all cases.  For VM layer functionality, the wired
	 * count in vm_page_t is sufficient. */
	if (pmap == kernel_pmap) {
		return;
	}

	PMAP_LOCK(pmap);
	pte_p = pmap_pte(pmap, v);
	assert(pte_p != PT_ENTRY_NULL);
	pa = pte_to_pa(*pte_p);
	if (pa_valid(pa))
		LOCK_PVH((int)pa_index(pa));

	if (wired && !pte_is_wired(*pte_p)) {
		pte_set_wired(pte_p, wired);
		OSAddAtomic(+1, (SInt32 *) &pmap->stats.wired_count);
		pmap_ledger_credit(pmap, task_ledgers.wired_mem, PAGE_SIZE);
	} else if (!wired && pte_is_wired(*pte_p)) {
                PMAP_STATS_ASSERTF(pmap->stats.wired_count >= 1, pmap, "stats.wired_count %d", pmap->stats.wired_count);
		pte_set_wired(pte_p, wired);
		OSAddAtomic(-1, (SInt32 *) &pmap->stats.wired_count);
		pmap_ledger_debit(pmap, task_ledgers.wired_mem, PAGE_SIZE);
	}

	if (pa_valid(pa))
		UNLOCK_PVH((int)pa_index(pa));

	PMAP_UNLOCK(pmap);
}

void
pmap_change_wiring(
	pmap_t pmap,
	vm_map_address_t v,
	boolean_t wired)
{
	pmap_change_wiring_internal(pmap, v, wired);
}

static ppnum_t
pmap_find_phys_internal(
	pmap_t pmap,
	addr64_t va)
{
	ppnum_t		ppn=0;

	if (pmap != kernel_pmap) {
		PMAP_LOCK(pmap);
	}

	ppn = pmap_vtophys(pmap, va);

	if (pmap != kernel_pmap) {
		PMAP_UNLOCK(pmap);
	}

	return ppn;
}

ppnum_t
pmap_find_phys(
	pmap_t pmap,
	addr64_t va)
{
	pmap_paddr_t	pa=0;

	if (pmap == kernel_pmap)
		pa = mmu_kvtop(va);
	else if ((current_thread()->map) && (pmap == vm_map_pmap(current_thread()->map)))
		pa = mmu_uvtop(va);

	if (pa) return (ppnum_t)(pa >> PAGE_SHIFT);

	if (not_in_kdp) {
		return pmap_find_phys_internal(pmap, va);
	} else {
		return pmap_vtophys(pmap, va);
	}
}

pmap_paddr_t
kvtophys(
	vm_offset_t va)
{
	pmap_paddr_t pa;

	pa = mmu_kvtop(va);
	if (pa) return pa;
	pa = ((pmap_paddr_t)pmap_vtophys(kernel_pmap, va)) << PAGE_SHIFT;
	if (pa)
		pa |= (va & PAGE_MASK);

	return ((pmap_paddr_t)pa);
}

ppnum_t
pmap_vtophys(
	pmap_t pmap,
	addr64_t va)
{
	if ((va < pmap->min) || (va >= pmap->max)) {
		return 0;
	}

#if	(__ARM_VMSA__ == 7)
	tt_entry_t     *tte_p, tte;
	pt_entry_t     *pte_p;
	ppnum_t         ppn;

	tte_p = pmap_tte(pmap, va);
	if (tte_p == (tt_entry_t *) NULL)
		return (ppnum_t) 0;

	tte = *tte_p;
	if ((tte & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE) {
		pte_p = (pt_entry_t *) ttetokv(tte) + ptenum(va);
		ppn = (ppnum_t) atop(pte_to_pa(*pte_p) | (va & ARM_PGMASK));
#if DEVELOPMENT || DEBUG
		if (ppn != 0 &&
		    ARM_PTE_IS_COMPRESSED(*pte_p)) {
			panic("pmap_vtophys(%p,0x%llx): compressed pte_p=%p 0x%llx with ppn=0x%x\n",
			      pmap, va, pte_p, (uint64_t) (*pte_p), ppn);
		}
#endif /* DEVELOPMENT || DEBUG */
	} else if ((tte & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_BLOCK)
		if ((tte & ARM_TTE_BLOCK_SUPER) == ARM_TTE_BLOCK_SUPER)
			ppn = (ppnum_t) atop(suptte_to_pa(tte) | (va & ARM_TT_L1_SUPER_OFFMASK));
		else
			ppn = (ppnum_t) atop(sectte_to_pa(tte) | (va & ARM_TT_L1_BLOCK_OFFMASK));
	else
		ppn = 0;
#else
	tt_entry_t		*ttp;
	tt_entry_t		tte;
	ppnum_t			ppn=0;

	/* Level 0 currently unused */

#if __ARM64_TWO_LEVEL_PMAP__
	/* We have no L1 entry; go straight to the L2 entry */
	ttp = pmap_tt2e(pmap, va);
	tte = *ttp;
#else
	/* Get first-level (1GB) entry */
	ttp = pmap_tt1e(pmap, va);
	tte = *ttp;
	if ((tte & (ARM_TTE_TYPE_MASK | ARM_TTE_VALID)) != (ARM_TTE_TYPE_TABLE | ARM_TTE_VALID))
		return (ppn);

	tte = ((tt_entry_t*) phystokv(tte & ARM_TTE_TABLE_MASK))[tt2_index(pmap, va)];
#endif
	if ((tte & ARM_TTE_VALID) != (ARM_TTE_VALID))
		return (ppn);

	if ((tte & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_BLOCK) {
		ppn = (ppnum_t) atop((tte & ARM_TTE_BLOCK_L2_MASK)| (va & ARM_TT_L2_OFFMASK));
		return(ppn);
	}
	tte = ((tt_entry_t*) phystokv(tte & ARM_TTE_TABLE_MASK))[tt3_index(pmap, va)];
	ppn = (ppnum_t) atop((tte & ARM_PTE_MASK)| (va & ARM_TT_L3_OFFMASK));
#endif

	return ppn;
}

static vm_offset_t
pmap_extract_internal(
	pmap_t pmap,
	vm_map_address_t va)
{
	pmap_paddr_t    pa=0;
	ppnum_t         ppn=0;

	if (pmap == NULL) {
		return 0;
	}

	PMAP_LOCK(pmap);

	ppn = pmap_vtophys(pmap, va);

	if (ppn != 0)
		pa = ptoa(ppn)| ((va) & PAGE_MASK);

	PMAP_UNLOCK(pmap);

	return pa;
}

/*
 *	Routine:	pmap_extract
 *	Function:
 *		Extract the physical page address associated
 *		with the given map/virtual_address pair.
 *
 */
vm_offset_t
pmap_extract(
	pmap_t pmap,
	vm_map_address_t va)
{
	pmap_paddr_t    pa=0;

	if (pmap == kernel_pmap)
		pa = mmu_kvtop(va);
	else if (pmap == vm_map_pmap(current_thread()->map))
		pa = mmu_uvtop(va);

	if (pa) return pa;

	return pmap_extract_internal(pmap, va);
}

/*
 *	pmap_init_pte_page - Initialize a page table page.
 */
void
pmap_init_pte_page(
	pmap_t pmap,
	pt_entry_t *pte_p,
	vm_offset_t va,
	unsigned int ttlevel,
	boolean_t alloc_ptd)
{
	pt_desc_t	*ptdp;

	ptdp = *(pt_desc_t **)pai_to_pvh(pa_index((((vm_offset_t)pte_p) - gVirtBase + gPhysBase)));

	if (ptdp == NULL) {
		if (alloc_ptd) {
			/*
			 * This path should only be invoked from arm_vm_init.  If we are emulating 16KB pages
			 * on 4KB hardware, we may already have allocated a page table descriptor for a
			 * bootstrap request, so we check for an existing PTD here.
			 */
			ptdp = ptd_alloc(pmap);
			*(pt_desc_t **)pai_to_pvh(pa_index((((vm_offset_t)pte_p) - gVirtBase + gPhysBase))) = ptdp;
		} else {
			panic("pmap_init_pte_page(): pte_p %p\n", pte_p);
		}
	}

	pmap_init_pte_page_internal(pmap, pte_p, va, ttlevel, &ptdp);
}

/*
 *	pmap_init_pte_page_internal - Initialize page table page and page table descriptor
 */
void
pmap_init_pte_page_internal(
	pmap_t pmap,
	pt_entry_t *pte_p,
	vm_offset_t va,
	unsigned int ttlevel,
	pt_desc_t **ptdp)
{
	bzero(pte_p, ARM_PGBYTES);
	// below barrier ensures the page zeroing is visible to PTW before
	// it is linked to the PTE of previous level
	__asm__ volatile("DMB ST" : : : "memory");
	ptd_init(*ptdp, pmap, va, ttlevel, pte_p);
}

/*
 * pmap_init_pte_static_page - for static mappings to a known contiguous range of pa's
 * Called from arm_vm_init().
 */
void
pmap_init_pte_static_page(
	__unused pmap_t pmap,
	pt_entry_t * pte_p,
	pmap_paddr_t pa)
{
#if	(__ARM_VMSA__ == 7)
	unsigned int	i;
	pt_entry_t	*pte_cur;

	for (i = 0, pte_cur = pte_p;
	     i < (ARM_PGBYTES / sizeof(*pte_p));
	     i++, pa += PAGE_SIZE) {
		if (pa >= avail_end) {
			/* We don't want to map memory xnu does not own through this routine. */
			break;
		}

		*pte_cur = pa_to_pte(pa)
		           | ARM_PTE_TYPE | ARM_PTE_AF | ARM_PTE_SH | ARM_PTE_AP(AP_RONA)
		           | ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DEFAULT);
		pte_cur++;
	}
#else
	unsigned int	i;
	pt_entry_t	*pte_cur;
	pt_entry_t	template;

	template = ARM_PTE_TYPE | ARM_PTE_AF | ARM_PTE_SH(SH_OUTER_MEMORY) | ARM_PTE_AP(AP_RONA) | ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DEFAULT) | ARM_PTE_NX;

	for (i = 0, pte_cur = pte_p;
	     i < (ARM_PGBYTES / sizeof(*pte_p));
	     i++, pa += PAGE_SIZE) {
		if (pa >= avail_end) {
			/* We don't want to map memory xnu does not own through this routine. */
			break;
		}

		/* TEST_PAGE_RATIO_4 may be pre-processor defined to 0 */
		__unreachable_ok_push
		if (TEST_PAGE_RATIO_4) {
			*pte_cur = pa_to_pte(pa) | template;
			*(pte_cur+1) = pa_to_pte(pa+0x1000) | template;
			*(pte_cur+2) = pa_to_pte(pa+0x2000) | template;
			*(pte_cur+3) = pa_to_pte(pa+0x3000) | template;
			pte_cur += 4;
		} else {
			*pte_cur = pa_to_pte(pa) | template;
			pte_cur++;
		}
		__unreachable_ok_pop
	}
#endif
	bzero(pte_cur, ARM_PGBYTES - ((vm_offset_t)pte_cur - (vm_offset_t)pte_p));
}


/*
 *	Routine:	pmap_expand
 *
 *	Expands a pmap to be able to map the specified virtual address.
 *
 *	Allocates new memory for the default (COARSE) translation table
 *	entry, initializes all the pte entries to ARM_PTE_TYPE_FAULT and
 *	also allocates space for the corresponding pv entries.
 *
 *	Nothing should be locked.
 */
static kern_return_t
pmap_expand(
	pmap_t pmap,
	vm_map_address_t v,
	unsigned int options,
	unsigned int level)
{
#if	(__ARM_VMSA__ == 7)
	vm_offset_t     pa;
	tt_entry_t		*tte_p;
	tt_entry_t		*tt_p;
	unsigned int	i;


	while (tte_index(pmap, v) >= pmap->tte_index_max) {
		tte_p = pmap_tt1_allocate(pmap, 2*ARM_PGBYTES, ((options & PMAP_OPTIONS_NOWAIT)? PMAP_TT_ALLOCATE_NOWAIT : 0));
		if (tte_p == (tt_entry_t *)0)
			return KERN_RESOURCE_SHORTAGE;

		PMAP_LOCK(pmap);
		if (pmap->tte_index_max >  NTTES) {
			pmap_tt1_deallocate(pmap, tte_p, 2*ARM_PGBYTES, PMAP_TT_DEALLOCATE_NOBLOCK);
			PMAP_UNLOCK(pmap);
			break;
		}

		simple_lock(&pmap->tt1_lock);
		for (i = 0; i < pmap->tte_index_max; i++)
			tte_p[i] = pmap->tte[i];
		for (i = NTTES; i < 2*NTTES; i++)
			tte_p[i] = ARM_TTE_TYPE_FAULT;

		pmap->prev_tte = pmap->tte;
		pmap->tte = tte_p;
		pmap->ttep = ml_static_vtop((vm_offset_t)pmap->tte);
#ifndef  __ARM_L1_PTW__
		CleanPoU_DcacheRegion((vm_offset_t) pmap->tte, 2*NTTES * sizeof(tt_entry_t));
#else
		__builtin_arm_dsb(DSB_ISH);
#endif
		pmap->tte_index_max = 2*NTTES;
		pmap->stamp = hw_atomic_add(&pmap_stamp, 1);

		for (i = 0; i < NTTES; i++)
			pmap->prev_tte[i] = ARM_TTE_TYPE_FAULT;
#ifndef  __ARM_L1_PTW__
		CleanPoU_DcacheRegion((vm_offset_t) pmap->prev_tte, NTTES * sizeof(tt_entry_t));
#else
		__builtin_arm_dsb(DSB_ISH);
#endif

		simple_unlock(&pmap->tt1_lock);
		PMAP_UNLOCK(pmap);
		pmap_set_pmap(pmap, current_thread());

	}

	if (level == 1)
		return (KERN_SUCCESS);

	{
		tt_entry_t     *tte_next_p;

		PMAP_LOCK(pmap);
		pa = 0;
		if (pmap_pte(pmap, v) != PT_ENTRY_NULL) {
			PMAP_UNLOCK(pmap);
			return (KERN_SUCCESS);
		}
		tte_p = &pmap->tte[ttenum(v & ~ARM_TT_L1_PT_OFFMASK)];
		for (i = 0, tte_next_p = tte_p; i<4; i++) {
			if (tte_to_pa(*tte_next_p)) {
				pa = tte_to_pa(*tte_next_p);
				break;
			}
			tte_next_p++;
		}
		pa = pa & ~PAGE_MASK;
		if (pa) {
			tte_p =  &pmap->tte[ttenum(v)];
			*tte_p =  pa_to_tte(pa) | (((v >> ARM_TT_L1_SHIFT) & 0x3) << 10) | ARM_TTE_TYPE_TABLE;
#ifndef  __ARM_L1_PTW__
			CleanPoU_DcacheRegion((vm_offset_t) tte_p, sizeof(tt_entry_t));
#endif
			PMAP_UNLOCK(pmap);
			return (KERN_SUCCESS);
		}
		PMAP_UNLOCK(pmap);
	}
	v = v & ~ARM_TT_L1_PT_OFFMASK;


	while (pmap_pte(pmap, v) == PT_ENTRY_NULL) {
		/*
		 *	Allocate a VM page for the level 2 page table entries.
		 */
		while (pmap_tt_allocate(pmap, &tt_p, PMAP_TT_L2_LEVEL, ((options & PMAP_TT_ALLOCATE_NOWAIT)? PMAP_PAGES_ALLOCATE_NOWAIT : 0)) != KERN_SUCCESS) {
			if(options & PMAP_OPTIONS_NOWAIT) {
				return KERN_RESOURCE_SHORTAGE;
			}
			VM_PAGE_WAIT();
		}

		PMAP_LOCK(pmap);
		/*
		 *	See if someone else expanded us first
		 */
		if (pmap_pte(pmap, v) == PT_ENTRY_NULL) {
			tt_entry_t     *tte_next_p;

			pmap_init_pte_page(pmap,  (pt_entry_t *) tt_p, v, PMAP_TT_L2_LEVEL, FALSE);
			pa = kvtophys((vm_offset_t)tt_p);
#ifndef  __ARM_L1_PTW__
			CleanPoU_DcacheRegion((vm_offset_t) phystokv(pa), PAGE_SIZE);
#endif
			tte_p = &pmap->tte[ttenum(v)];
			for (i = 0, tte_next_p = tte_p; i<4; i++) {
				*tte_next_p = pa_to_tte(pa) | ARM_TTE_TYPE_TABLE;
				tte_next_p++;
				pa = pa +0x400;
			}
#ifndef  __ARM_L1_PTW__
			CleanPoU_DcacheRegion((vm_offset_t) tte_p, 4*sizeof(tt_entry_t));
#endif
			pa = 0x0ULL;
			tt_p = (tt_entry_t *)NULL;
		}
		PMAP_UNLOCK(pmap);
		if (tt_p != (tt_entry_t *)NULL) {
			pmap_tt_deallocate(pmap, tt_p, PMAP_TT_L2_LEVEL);
			tt_p = (tt_entry_t *)NULL;
		}
	}
	return (KERN_SUCCESS);
#else
	pmap_paddr_t	pa;
#if __ARM64_TWO_LEVEL_PMAP__
	/* If we are using a two level page table, we'll start at L2. */
	unsigned int	ttlevel = 2;
#else
	/* Otherwise, we start at L1 (we use 3 levels by default). */
	unsigned int	ttlevel = 1;
#endif
	tt_entry_t		*tte_p;
	tt_entry_t		*tt_p;

	pa = 0x0ULL;
	tt_p =  (tt_entry_t *)NULL;

	for (; ttlevel < level; ttlevel++) {

		PMAP_LOCK(pmap);

		if (ttlevel == 1) {
			if ((pmap_tt2e(pmap, v) == PT_ENTRY_NULL)) {
				PMAP_UNLOCK(pmap);
				while (pmap_tt_allocate(pmap, &tt_p, PMAP_TT_L2_LEVEL, ((options & PMAP_TT_ALLOCATE_NOWAIT)? PMAP_PAGES_ALLOCATE_NOWAIT : 0)) != KERN_SUCCESS) {
					if(options & PMAP_OPTIONS_NOWAIT) {
						return KERN_RESOURCE_SHORTAGE;
					}
					VM_PAGE_WAIT();
				}
				PMAP_LOCK(pmap);
				if ((pmap_tt2e(pmap, v) == PT_ENTRY_NULL)) {
					pmap_init_pte_page(pmap, (pt_entry_t *) tt_p, v, PMAP_TT_L2_LEVEL, FALSE);
					pa = kvtophys((vm_offset_t)tt_p);
					tte_p = pmap_tt1e( pmap, v);
					*tte_p = (pa & ARM_TTE_TABLE_MASK) | ARM_TTE_TYPE_TABLE | ARM_TTE_VALID;
					pa = 0x0ULL;
					tt_p = (tt_entry_t *)NULL;
					if ((pmap == kernel_pmap) && (VM_MIN_KERNEL_ADDRESS < 0x00000000FFFFFFFFULL))
						current_pmap()->tte[v>>ARM_TT_L1_SHIFT] = kernel_pmap->tte[v>>ARM_TT_L1_SHIFT];
				}

			}
		} else if (ttlevel == 2) {
			if (pmap_tt3e(pmap, v) == PT_ENTRY_NULL) {
				PMAP_UNLOCK(pmap);
				while (pmap_tt_allocate(pmap, &tt_p, PMAP_TT_L3_LEVEL, ((options & PMAP_TT_ALLOCATE_NOWAIT)? PMAP_PAGES_ALLOCATE_NOWAIT : 0)) != KERN_SUCCESS) {
					if(options & PMAP_OPTIONS_NOWAIT) {
						return KERN_RESOURCE_SHORTAGE;
					}
					VM_PAGE_WAIT();
				}
				PMAP_LOCK(pmap);
				if ((pmap_tt3e(pmap, v) == PT_ENTRY_NULL)) {
					pmap_init_pte_page(pmap, (pt_entry_t *) tt_p, v ,  PMAP_TT_L3_LEVEL, FALSE);
					pa = kvtophys((vm_offset_t)tt_p);
					tte_p = pmap_tt2e( pmap, v);
					*tte_p = (pa & ARM_TTE_TABLE_MASK) | ARM_TTE_TYPE_TABLE | ARM_TTE_VALID;
					pa = 0x0ULL;
					tt_p = (tt_entry_t *)NULL;
				}
			}
		}

		PMAP_UNLOCK(pmap);

		if (tt_p != (tt_entry_t *)NULL) {
			pmap_tt_deallocate(pmap, tt_p, ttlevel+1);
			tt_p = (tt_entry_t *)NULL;
		}
	}

	return (KERN_SUCCESS);
#endif
}

/*
 *	Routine:	pmap_collect
 *	Function:
 *		Garbage collects the physical map system for
 *		pages which are no longer used.
 *		Success need not be guaranteed -- that is, there
 *		may well be pages which are not referenced, but
 *		others may be collected.
 */
void
pmap_collect(pmap_t pmap)
{
	if (pmap == PMAP_NULL)
		return;

#if 0
	PMAP_LOCK(pmap);
	if ((pmap->nested == FALSE) && (pmap != kernel_pmap)) {
		/* TODO: Scan for vm page assigned to top level page tables with no reference */
	}
	PMAP_UNLOCK(pmap);
#endif

	return;
}

/*
 *	Routine:	pmap_gc
 *	Function:
 *      	Pmap garbage collection
 *		Called by the pageout daemon when pages are scarce.
 *
 */
void
pmap_gc(
	void)
{
	pmap_t	pmap, pmap_next;
	boolean_t	gc_wait;

	if (pmap_gc_allowed &&
	    (pmap_gc_allowed_by_time_throttle ||
	     pmap_gc_forced)) {
		pmap_gc_forced = FALSE;
		pmap_gc_allowed_by_time_throttle = FALSE;
		simple_lock(&pmaps_lock);
		pmap = CAST_DOWN_EXPLICIT(pmap_t, queue_first(&map_pmap_list));
		while (!queue_end(&map_pmap_list, (queue_entry_t)pmap)) {
			if (!(pmap->gc_status & PMAP_GC_INFLIGHT))
				pmap->gc_status |= PMAP_GC_INFLIGHT;
			simple_unlock(&pmaps_lock);

			pmap_collect(pmap);

			simple_lock(&pmaps_lock);
			gc_wait = (pmap->gc_status & PMAP_GC_WAIT);
			pmap->gc_status &= ~(PMAP_GC_INFLIGHT|PMAP_GC_WAIT);
			pmap_next = CAST_DOWN_EXPLICIT(pmap_t, queue_next(&pmap->pmaps));
			if (gc_wait) {
				if (!queue_end(&map_pmap_list, (queue_entry_t)pmap_next))
					pmap_next->gc_status |= PMAP_GC_INFLIGHT;
				simple_unlock(&pmaps_lock);
				thread_wakeup((event_t) & pmap->gc_status);
				simple_lock(&pmaps_lock);
			}
			pmap = pmap_next;
		}
		simple_unlock(&pmaps_lock);
	}
}

/*
 * Called by the VM to reclaim pages that we can reclaim quickly and cheaply.
 */
void
pmap_release_pages_fast(void)
{
}

/*
 *      By default, don't attempt pmap GC more frequently
 *      than once / 1 minutes.
 */

void
compute_pmap_gc_throttle(
	void *arg __unused)
{
	pmap_gc_allowed_by_time_throttle = TRUE;
}

/*
 * pmap_attribute_cache_sync(vm_offset_t pa)
 *
 * Invalidates all of the instruction cache on a physical page and
 * pushes any dirty data from the data cache for the same physical page
 */

kern_return_t
pmap_attribute_cache_sync(
	ppnum_t pp,
	vm_size_t size,
	__unused vm_machine_attribute_t attribute,
	__unused vm_machine_attribute_val_t * value)
{
	if (size > PAGE_SIZE) {
		panic("pmap_attribute_cache_sync size: 0x%llx\n", (uint64_t)size);
	} else
		cache_sync_page(pp);

	return KERN_SUCCESS;
}

/*
 * pmap_sync_page_data_phys(ppnum_t pp)
 *
 * Invalidates all of the instruction cache on a physical page and
 * pushes any dirty data from the data cache for the same physical page
 */
void
pmap_sync_page_data_phys(
	ppnum_t pp)
{
	cache_sync_page(pp);
}

/*
 * pmap_sync_page_attributes_phys(ppnum_t pp)
 *
 * Write back and invalidate all cachelines on a physical page.
 */
void
pmap_sync_page_attributes_phys(
	ppnum_t pp)
{
	flush_dcache((vm_offset_t) (pp << PAGE_SHIFT), PAGE_SIZE, TRUE);
}

#if CONFIG_COREDUMP
/* temporary workaround */
boolean_t
coredumpok(
	vm_map_t map,
	vm_offset_t va)
{
	pt_entry_t     *pte_p;
	pt_entry_t      spte;

	pte_p = pmap_pte(map->pmap, va);
	if (0 == pte_p)
		return FALSE;
	spte = *pte_p;
	return ((spte & ARM_PTE_ATTRINDXMASK) == ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DEFAULT));
}
#endif

void
fillPage(
	ppnum_t pn,
	unsigned int fill)
{
	unsigned int   *addr;
	int             count;

	addr = (unsigned int *) phystokv(ptoa(pn));
	count = PAGE_SIZE / sizeof(unsigned int);
	while (count--)
		*addr++ = fill;
}

extern void     mapping_set_mod(ppnum_t pn);

void
mapping_set_mod(
	ppnum_t pn)
{
	pmap_set_modify(pn);
}

extern void     mapping_set_ref(ppnum_t pn);

void
mapping_set_ref(
	ppnum_t pn)
{
	pmap_set_reference(pn);
}

/*
 *	Clear specified attribute bits.
 *
 *     	Try to force an arm_fast_fault() for all mappings of
 *	the page - to force attributes to be set again at fault time.
 *  If the forcing succeeds, clear the cached bits at the head.
 *  Otherwise, something must have been wired, so leave the cached
 *  attributes alone.
 */
static void
phys_attribute_clear_internal(
	ppnum_t		pn,
	unsigned int	bits,
	int		options,
	void		*arg)
{
	pmap_paddr_t    pa = ptoa(pn);
	vm_prot_t       allow_mode = VM_PROT_ALL;


	if ((bits & PP_ATTR_MODIFIED) &&
	    (options & PMAP_OPTIONS_NOFLUSH) &&
	    (arg == NULL)) {
		panic("phys_attribute_clear(0x%x,0x%x,0x%x,%p): "
		      "should not clear 'modified' without flushing TLBs\n",
		      pn, bits, options, arg);
	}

	assert(pn != vm_page_fictitious_addr);
	if (bits & PP_ATTR_REFERENCED)
		allow_mode &= ~(VM_PROT_READ | VM_PROT_EXECUTE);
	if (bits & PP_ATTR_MODIFIED)
		allow_mode &= ~VM_PROT_WRITE;

	if (bits == PP_ATTR_NOENCRYPT) {
		/*
		 * We short circuit this case; it should not need to
		 * invoke arm_force_fast_fault, so just clear and
		 * return.  On ARM, this bit is just a debugging aid.
		 */
		pa_clear_bits(pa, bits);
		return;
	}

	if (arm_force_fast_fault_internal(pn, allow_mode, options))
		pa_clear_bits(pa, bits);
	return;
}

static void
phys_attribute_clear(
	ppnum_t		pn,
	unsigned int	bits,
	int		options,
	void		*arg)
{
	/*
	 * Do we really want this tracepoint?  It will be extremely chatty.
	 * Also, should we have a corresponding trace point for the set path?
	 */
	PMAP_TRACE(PMAP_CODE(PMAP__ATTRIBUTE_CLEAR) | DBG_FUNC_START, pn, bits);

	phys_attribute_clear_internal(pn, bits, options, arg);

	PMAP_TRACE(PMAP_CODE(PMAP__ATTRIBUTE_CLEAR) | DBG_FUNC_END);
}

/*
 *	Set specified attribute bits.
 *
 *	Set cached value in the pv head because we have
 *	no per-mapping hardware support for referenced and
 *	modify bits.
 */
static void
phys_attribute_set_internal(
	ppnum_t pn,
	unsigned int bits)
{
	pmap_paddr_t    pa = ptoa(pn);
	assert(pn != vm_page_fictitious_addr);


	pa_set_bits(pa, bits);

	return;
}

static void
phys_attribute_set(
	ppnum_t pn,
	unsigned int bits)
{
	phys_attribute_set_internal(pn, bits);
}


/*
 *	Check specified attribute bits.
 *
 *	use the software cached bits (since no hw support).
 */
static boolean_t
phys_attribute_test(
	ppnum_t pn,
	unsigned int bits)
{
	pmap_paddr_t    pa = ptoa(pn);
	assert(pn != vm_page_fictitious_addr);
	return pa_test_bits(pa, bits);
}


/*
 *	Set the modify/reference bits on the specified physical page.
 */
void
pmap_set_modify(ppnum_t pn)
{
	phys_attribute_set(pn, PP_ATTR_MODIFIED);
}


/*
 *	Clear the modify bits on the specified physical page.
 */
void
pmap_clear_modify(
	ppnum_t pn)
{
	phys_attribute_clear(pn, PP_ATTR_MODIFIED, 0, NULL);
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
	return phys_attribute_test(pn, PP_ATTR_MODIFIED);
}


/*
 *	Set the reference bit on the specified physical page.
 */
static void
pmap_set_reference(
	ppnum_t pn)
{
	phys_attribute_set(pn, PP_ATTR_REFERENCED);
}

/*
 *	Clear the reference bits on the specified physical page.
 */
void
pmap_clear_reference(
	ppnum_t pn)
{
	phys_attribute_clear(pn, PP_ATTR_REFERENCED, 0, NULL);
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
	return phys_attribute_test(pn, PP_ATTR_REFERENCED);
}

/*
 * pmap_get_refmod(phys)
 *  returns the referenced and modified bits of the specified
 *  physical page.
 */
unsigned int
pmap_get_refmod(
	ppnum_t pn)
{
	return (((phys_attribute_test(pn, PP_ATTR_MODIFIED)) ? VM_MEM_MODIFIED : 0)
		| ((phys_attribute_test(pn, PP_ATTR_REFERENCED)) ? VM_MEM_REFERENCED : 0));
}

/*
 * pmap_clear_refmod(phys, mask)
 *  clears the referenced and modified bits as specified by the mask
 *  of the specified physical page.
 */
void
pmap_clear_refmod_options(
	ppnum_t		pn,
	unsigned int	mask,
	unsigned int	options,
	void		*arg)
{
	unsigned int    bits;

	bits = ((mask & VM_MEM_MODIFIED) ? PP_ATTR_MODIFIED : 0) |
		((mask & VM_MEM_REFERENCED) ? PP_ATTR_REFERENCED : 0);
	phys_attribute_clear(pn, bits, options, arg);
}

void
pmap_clear_refmod(
	ppnum_t pn,
	unsigned int mask)
{
	pmap_clear_refmod_options(pn, mask, 0, NULL);
}

unsigned int
pmap_disconnect_options(
	ppnum_t pn,
	unsigned int options,
	void *arg)
{
	if ((options & PMAP_OPTIONS_COMPRESSOR_IFF_MODIFIED)) {
		/*
		 * On ARM, the "modified" bit is managed by software, so
		 * we know up-front if the physical page is "modified",
		 * without having to scan all the PTEs pointing to it.
		 * The caller should have made the VM page "busy" so noone
		 * should be able to establish any new mapping and "modify"
		 * the page behind us.
		 */
		if (pmap_is_modified(pn)) {
			/*
			 * The page has been modified and will be sent to
			 * the VM compressor.
			 */
			options |= PMAP_OPTIONS_COMPRESSOR;
		} else {
			/*
			 * The page hasn't been modified and will be freed
			 * instead of compressed.
			 */
		}
	}

	/* disconnect the page */
	pmap_page_protect_options(pn, 0, options, arg);

	/* return ref/chg status */
	return (pmap_get_refmod(pn));
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
unsigned int
pmap_disconnect(
	ppnum_t pn)
{
	pmap_page_protect(pn, 0);	/* disconnect the page */
	return (pmap_get_refmod(pn));	/* return ref/chg status */
}

boolean_t
pmap_has_managed_page(ppnum_t first, ppnum_t last)
{
    if (ptoa(first) >= vm_last_phys)  return (FALSE);
    if (ptoa(last)  <  vm_first_phys) return (FALSE);

	return (TRUE);
}

/*
 * The state maintained by the noencrypt functions is used as a
 * debugging aid on ARM.  This incurs some overhead on the part
 * of the caller.  A special case check in phys_attribute_clear
 * (the most expensive path) currently minimizes this overhead,
 * but stubbing these functions out on RELEASE kernels yields
 * further wins.
 */
boolean_t
pmap_is_noencrypt(
	ppnum_t pn)
{
#if DEVELOPMENT || DEBUG
	boolean_t result = FALSE;

	if (!pa_valid(ptoa(pn))) return FALSE;

	result = (phys_attribute_test(pn, PP_ATTR_NOENCRYPT));

	return result;
#else
#pragma unused(pn)
	return FALSE;
#endif
}

void
pmap_set_noencrypt(
	ppnum_t pn)
{
#if DEVELOPMENT || DEBUG
	if (!pa_valid(ptoa(pn))) return;

	phys_attribute_set(pn, PP_ATTR_NOENCRYPT);
#else
#pragma unused(pn)
#endif
}

void
pmap_clear_noencrypt(
	ppnum_t pn)
{
#if DEVELOPMENT || DEBUG
	if (!pa_valid(ptoa(pn))) return;

	phys_attribute_clear(pn, PP_ATTR_NOENCRYPT, 0, NULL);
#else
#pragma unused(pn)
#endif
}


void
pmap_lock_phys_page(ppnum_t pn)
{
	int             pai;
	pmap_paddr_t	phys = ptoa(pn);

	if (pa_valid(phys)) {
		pai = (int)pa_index(phys);
		LOCK_PVH(pai);
	} else
		simple_lock(&phys_backup_lock);
}


void
pmap_unlock_phys_page(ppnum_t pn)
{
	int             pai;
	pmap_paddr_t	phys = ptoa(pn);

	if (pa_valid(phys)) {
		pai = (int)pa_index(phys);
		UNLOCK_PVH(pai);
	} else
		simple_unlock(&phys_backup_lock);
}

static void
pmap_switch_user_ttb_internal(
	pmap_t pmap)
{
#if	(__ARM_VMSA__ == 7)
	pmap_cpu_data_t	*cpu_data_ptr;

	cpu_data_ptr = pmap_get_cpu_data();

	if ((cpu_data_ptr->cpu_user_pmap != PMAP_NULL)
	    && (cpu_data_ptr->cpu_user_pmap != kernel_pmap)) {
		unsigned int	c;

		c = hw_atomic_sub((volatile uint32_t *)&cpu_data_ptr->cpu_user_pmap->cpu_ref, 1);
		if ((c == 0) && (cpu_data_ptr->cpu_user_pmap->prev_tte != 0)) {
			/* We saved off the old 1-page tt1 in pmap_expand() in case other cores were still using it.
			 * Now that the user pmap's cpu_ref is 0, we should be able to safely free it.*/
			tt_entry_t	*tt_entry;

			tt_entry = cpu_data_ptr->cpu_user_pmap->prev_tte;
			cpu_data_ptr->cpu_user_pmap->prev_tte = (tt_entry_t *) NULL;
			pmap_tt1_deallocate(cpu_data_ptr->cpu_user_pmap, tt_entry, ARM_PGBYTES, PMAP_TT_DEALLOCATE_NOBLOCK);
		}
	}
	cpu_data_ptr->cpu_user_pmap = pmap;
	cpu_data_ptr->cpu_user_pmap_stamp = pmap->stamp;
	(void) hw_atomic_add((volatile uint32_t *)&pmap->cpu_ref, 1);

#if	MACH_ASSERT && __ARM_USER_PROTECT__
	{
		unsigned int ttbr0_val, ttbr1_val;
		__asm__ volatile("mrc p15,0,%0,c2,c0,0\n" : "=r"(ttbr0_val));
		__asm__ volatile("mrc p15,0,%0,c2,c0,1\n" : "=r"(ttbr1_val));
		if (ttbr0_val != ttbr1_val) {
			panic("Misaligned ttbr0  %08X\n", ttbr0_val);
		}
	}
#endif
	if (pmap->tte_index_max == NTTES) {
		/* Setting TTBCR.N for TTBR0 TTBR1 boundary at  0x40000000 */
		__asm__ volatile("mcr	p15,0,%0,c2,c0,2" : : "r"(2));
		__asm__ volatile("isb");
#if !__ARM_USER_PROTECT__
		set_mmu_ttb(pmap->ttep);
#endif
	} else {
#if !__ARM_USER_PROTECT__
		set_mmu_ttb(pmap->ttep);
#endif
		/* Setting TTBCR.N for TTBR0 TTBR1 boundary at  0x80000000 */
		__asm__ volatile("mcr	p15,0,%0,c2,c0,2" : : "r"(1));
		__asm__ volatile("isb");
#if	MACH_ASSERT && __ARM_USER_PROTECT__
		if (pmap->ttep & 0x1000) {
			panic("Misaligned ttbr0  %08X\n", pmap->ttep);
		}
#endif
	}

#if !__ARM_USER_PROTECT__
	set_context_id(pmap->asid);
#endif
#else

	pmap_get_cpu_data()->cpu_user_pmap = pmap;
	pmap_get_cpu_data()->cpu_user_pmap_stamp = pmap->stamp;

#if !__arm64__
	set_context_id(pmap->asid); /* Not required */
#endif
	if (pmap == kernel_pmap) {
		set_mmu_ttb(invalid_ttep & TTBR_BADDR_MASK);
	} else {
		set_mmu_ttb((pmap->ttep & TTBR_BADDR_MASK)|(((uint64_t)pmap->asid) << TTBR_ASID_SHIFT));
	}
#endif
}

void
pmap_switch_user_ttb(
	pmap_t pmap)
{
	pmap_switch_user_ttb_internal(pmap);
}

/*
 * Try to "intuit" whether we need to raise a VM_PROT_WRITE fault
 * for the given address when a "swp" instruction raised the fault.
 * We have to look at the existing pte for the address to see
 * if it needs to get bumped, or just added. If just added, do it
 * as a read-only mapping first (this could result in extra faults -
 * but better that than extra copy-on-write evaluations).
 */

#if	(__ARM_VMSA__ == 7)
boolean_t
arm_swap_readable_type(
	vm_map_address_t addr,
	unsigned int spsr)
{
	int             ap;
	pt_entry_t      spte;
	pt_entry_t     *ptep;

	ptep = pmap_pte(current_pmap(), addr);
	if (ptep == PT_ENTRY_NULL)
		return (FALSE);

	spte = *ptep;
	if (spte == ARM_PTE_TYPE_FAULT ||
	    ARM_PTE_IS_COMPRESSED(spte))
		return (FALSE);

	/* get the access permission bitmaps */
	/* (all subpages should be the same) */
	ap = (spte & ARM_PTE_APMASK);

	if (spsr & 0xf) {	/* Supervisor mode */
		panic("arm_swap_readable_type supv");
		return TRUE;
	} else {		/* User mode */
		if ((ap == ARM_PTE_AP(AP_RWRW)) || (ap == ARM_PTE_AP(AP_RORO)))
			return (FALSE);
		else
			return (TRUE);
	}
}
#endif

/*
 *	Routine:	arm_force_fast_fault
 *
 *	Function:
 *		Force all mappings for this page to fault according
 *		to the access modes allowed, so we can gather ref/modify
 *		bits again.
 */
static boolean_t
arm_force_fast_fault_internal(
	ppnum_t		ppnum,
	vm_prot_t	allow_mode,
	int		options)
{
	pmap_paddr_t    phys = ptoa(ppnum);
	pv_entry_t     *pve_p;
	pt_entry_t     *pte_p;
	int             pai;
	boolean_t       result;
	pv_entry_t    **pv_h;
	boolean_t       is_reusable, is_internal;
	boolean_t       ref_fault;
	boolean_t       mod_fault;

	assert(ppnum != vm_page_fictitious_addr);

	if (!pa_valid(phys)) {
		return FALSE;	/* Not a managed page. */
	}

	result = TRUE;
	ref_fault = FALSE;
	mod_fault = FALSE;
	pai = (int)pa_index(phys);
	LOCK_PVH(pai);
	pv_h = pai_to_pvh(pai);

	pte_p = PT_ENTRY_NULL;
	pve_p = PV_ENTRY_NULL;
	if (pvh_test_type(pv_h, PVH_TYPE_PTEP))	{
		pte_p = pvh_ptep(pv_h);
	} else if  (pvh_test_type(pv_h, PVH_TYPE_PVEP)) {
		pve_p = pvh_list(pv_h);
	}

	is_reusable = IS_REUSABLE_PAGE(pai);
	is_internal = IS_INTERNAL_PAGE(pai);

	while ((pve_p != PV_ENTRY_NULL) || (pte_p != PT_ENTRY_NULL)) {
		vm_map_address_t va;
		pt_entry_t		spte;
		pt_entry_t      tmplate;
		pmap_t          pmap;
		boolean_t	update_pte;

		if (pve_p != PV_ENTRY_NULL)
			pte_p = pve_get_ptep(pve_p);

		if (pte_p == PT_ENTRY_NULL) {
			panic("pte_p is NULL: pve_p=%p ppnum=0x%x\n", pve_p, ppnum);
		}
		if (*pte_p == ARM_PTE_EMPTY) {
			panic("pte is NULL: pte_p=%p ppnum=0x%x\n", pte_p, ppnum);
		}
		if (ARM_PTE_IS_COMPRESSED(*pte_p)) {
			panic("pte is COMPRESSED: pte_p=%p ppnum=0x%x\n", pte_p, ppnum);
		}

		pmap = ptep_get_pmap(pte_p);
		va = ptep_get_va(pte_p);

		assert(va >= pmap->min && va < pmap->max);

		if (pte_is_wired(*pte_p) || pmap == kernel_pmap) {
			result = FALSE;
			break;
		}

		spte = *pte_p;
		tmplate = spte;
		update_pte = FALSE;

		if ((allow_mode & VM_PROT_READ) != VM_PROT_READ) {
			/* read protection sets the pte to fault */
			tmplate =  tmplate & ~ARM_PTE_AF;
			update_pte = TRUE;
			ref_fault = TRUE;
		}
		if ((allow_mode & VM_PROT_WRITE) != VM_PROT_WRITE) {
			/* take away write permission if set */
			if (pmap == kernel_pmap) {
				if ((tmplate & ARM_PTE_APMASK) == ARM_PTE_AP(AP_RWNA)) {
					tmplate = ((tmplate & ~ARM_PTE_APMASK) | ARM_PTE_AP(AP_RONA));
				}
			} else {
				if ((tmplate & ARM_PTE_APMASK) == ARM_PTE_AP(AP_RWRW)) {
					tmplate = ((tmplate & ~ARM_PTE_APMASK) | ARM_PTE_AP(AP_RORO));
				}
			}

			pte_set_ffr(tmplate, 1);
			update_pte = TRUE;
			mod_fault = TRUE;
		}


		if (update_pte) {
			if (*pte_p != ARM_PTE_TYPE_FAULT &&
			    !ARM_PTE_IS_COMPRESSED(*pte_p)) {
				WRITE_PTE(pte_p, tmplate);
				PMAP_UPDATE_TLBS(pmap, va, va + PAGE_SIZE);
			} else {
				WRITE_PTE(pte_p, tmplate);
				__asm__ volatile("isb");
			}
		}

		/* update pmap stats and ledgers */
		if (IS_ALTACCT_PAGE(pai, pve_p)) {
			/*
			 * We do not track "reusable" status for
			 * "alternate accounting" mappings.
			 */
		} else if ((options & PMAP_OPTIONS_CLEAR_REUSABLE) &&
			   is_reusable &&
			   is_internal &&
			   pmap != kernel_pmap) {
			/* one less "reusable" */
			PMAP_STATS_ASSERTF(pmap->stats.reusable > 0, pmap, "stats.reusable %d", pmap->stats.reusable);
			OSAddAtomic(-1, &pmap->stats.reusable);
			/* one more "internal" */
			OSAddAtomic(+1, &pmap->stats.internal);
			PMAP_STATS_PEAK(pmap->stats.internal);
			PMAP_STATS_ASSERTF(pmap->stats.internal > 0, pmap, "stats.internal %d", pmap->stats.internal);
			pmap_ledger_credit(pmap,
					   task_ledgers.internal,
					   machine_ptob(1));
			assert(!IS_ALTACCT_PAGE(pai, pve_p));
			assert(IS_INTERNAL_PAGE(pai));
			pmap_ledger_credit(pmap,
					   task_ledgers.phys_footprint,
					   machine_ptob(1));

			/*
			 * Avoid the cost of another trap to handle the fast
			 * fault when we next write to this page:  let's just
			 * handle that now since we already have all the
			 * necessary information.
			 */
			{
				arm_clear_fast_fault(ppnum, VM_PROT_WRITE);
			}
		} else if ((options & PMAP_OPTIONS_SET_REUSABLE) &&
			   !is_reusable &&
			   is_internal &&
			   pmap != kernel_pmap) {
			/* one more "reusable" */
			OSAddAtomic(+1, &pmap->stats.reusable);
			PMAP_STATS_PEAK(pmap->stats.reusable);
			PMAP_STATS_ASSERTF(pmap->stats.reusable > 0, pmap, "stats.reusable %d", pmap->stats.reusable);
			/* one less "internal" */
			PMAP_STATS_ASSERTF(pmap->stats.internal > 0, pmap, "stats.internal %d", pmap->stats.internal);
			OSAddAtomic(-1, &pmap->stats.internal);
			pmap_ledger_debit(pmap,
					  task_ledgers.internal,
					  machine_ptob(1));
			assert(!IS_ALTACCT_PAGE(pai, pve_p));
			assert(IS_INTERNAL_PAGE(pai));
			pmap_ledger_debit(pmap,
					  task_ledgers.phys_footprint,
					  machine_ptob(1));
		}

		pte_p = PT_ENTRY_NULL;
		if (pve_p != PV_ENTRY_NULL)
			pve_p = PVE_NEXT_PTR(pve_next(pve_p));
	}

	/* update global "reusable" status for this page */
	if (is_internal) {
		if ((options & PMAP_OPTIONS_CLEAR_REUSABLE) &&
		    is_reusable) {
			CLR_REUSABLE_PAGE(pai);
		} else if ((options & PMAP_OPTIONS_SET_REUSABLE) &&
			   !is_reusable) {
			SET_REUSABLE_PAGE(pai);
		}
	}

	if (mod_fault) {
		SET_MODFAULT_PAGE(pai);
	}
	if (ref_fault) {
		SET_REFFAULT_PAGE(pai);
	}

	UNLOCK_PVH(pai);
	return result;
}

boolean_t
arm_force_fast_fault(
	ppnum_t		ppnum,
	vm_prot_t	allow_mode,
	int		options,
	__unused void	*arg)
{
	pmap_paddr_t    phys = ptoa(ppnum);

	assert(ppnum != vm_page_fictitious_addr);

	if (!pa_valid(phys)) {
		return FALSE;	/* Not a managed page. */
	}

	return arm_force_fast_fault_internal(ppnum, allow_mode, options);
}

/*
 *	Routine:	arm_clear_fast_fault
 *
 *	Function:
 *		Clear pending force fault for all mappings for this page based on
 *		the observed fault type, update ref/modify bits.
 */
boolean_t
arm_clear_fast_fault(
	ppnum_t ppnum,
	vm_prot_t fault_type)
{
	pmap_paddr_t    pa = ptoa(ppnum);
	pv_entry_t     *pve_p;
	pt_entry_t     *pte_p;
	int             pai;
	boolean_t       result;
	pv_entry_t    **pv_h;

	assert(ppnum != vm_page_fictitious_addr);

	if (!pa_valid(pa)) {
		return FALSE;	/* Not a managed page. */
	}

	result = FALSE;
	pai = (int)pa_index(pa);
	ASSERT_PVH_LOCKED(pai);
	pv_h = pai_to_pvh(pai);

	pte_p = PT_ENTRY_NULL;
	pve_p = PV_ENTRY_NULL;
	if (pvh_test_type(pv_h, PVH_TYPE_PTEP))	{
		pte_p = pvh_ptep(pv_h);
	} else if  (pvh_test_type(pv_h, PVH_TYPE_PVEP)) {
		pve_p = pvh_list(pv_h);
	}

	while ((pve_p != PV_ENTRY_NULL) || (pte_p != PT_ENTRY_NULL)) {
		vm_map_address_t va;
		pt_entry_t		spte;
		pt_entry_t      tmplate;
		pmap_t          pmap;

		if (pve_p != PV_ENTRY_NULL)
			pte_p = pve_get_ptep(pve_p);

		if (pte_p == PT_ENTRY_NULL) {
			panic("pte_p is NULL: pve_p=%p ppnum=0x%x\n", pve_p, ppnum);
		}
		if (*pte_p == ARM_PTE_EMPTY) {
			panic("pte is NULL: pte_p=%p ppnum=0x%x\n", pte_p, ppnum);
		}

		pmap = ptep_get_pmap(pte_p);
		va = ptep_get_va(pte_p);

		assert(va >= pmap->min && va < pmap->max);

		spte = *pte_p;
		tmplate = spte;

		if ((fault_type & VM_PROT_WRITE) && (pte_is_ffr(spte))) {
			{
				if (pmap == kernel_pmap)
					tmplate = ((spte & ~ARM_PTE_APMASK) | ARM_PTE_AP(AP_RWNA));
				else
					tmplate = ((spte & ~ARM_PTE_APMASK) | ARM_PTE_AP(AP_RWRW));
			}

			tmplate |= ARM_PTE_AF;

			pte_set_ffr(tmplate, 0);
			pa_set_bits(pa, PP_ATTR_REFERENCED | PP_ATTR_MODIFIED);

		} else if ((fault_type & VM_PROT_READ) && ((spte & ARM_PTE_AF) != ARM_PTE_AF)) {
			tmplate = spte | ARM_PTE_AF;

			{
				pa_set_bits(pa, PP_ATTR_REFERENCED);
			}
		}


		if (spte != tmplate) {
			if (spte != ARM_PTE_TYPE_FAULT) {
				WRITE_PTE(pte_p, tmplate);
				PMAP_UPDATE_TLBS(pmap, va, va + PAGE_SIZE);
			} else {
				WRITE_PTE(pte_p, tmplate);
				__asm__ volatile("isb");
			}
			result = TRUE;
		}

		pte_p = PT_ENTRY_NULL;
		if (pve_p != PV_ENTRY_NULL)
			pve_p = PVE_NEXT_PTR(pve_next(pve_p));
	}
	return result;
}

/*
 * Determine if the fault was induced by software tracking of
 * modify/reference bits.  If so, re-enable the mapping (and set
 * the appropriate bits).
 *
 * Returns KERN_SUCCESS if the fault was induced and was
 * successfully handled.
 *
 * Returns KERN_FAILURE if the fault was not induced and
 * the function was unable to deal with it.
 *
 * Returns KERN_PROTECTION_FAILURE if the pmap layer explictly
 * disallows this type of access.
 */
static kern_return_t
arm_fast_fault_internal(
	pmap_t pmap,
	vm_map_address_t va,
	vm_prot_t fault_type,
	__unused boolean_t from_user)
{
	kern_return_t   result = KERN_FAILURE;
	pt_entry_t     *ptep;
	pt_entry_t      spte = ARM_PTE_TYPE_FAULT;
	int             pai;
	pmap_paddr_t    pa;

	PMAP_LOCK(pmap);

	/*
	 * If the entry doesn't exist, is completely invalid, or is already
	 * valid, we can't fix it here.
	 */

	ptep = pmap_pte(pmap, va);
	if (ptep != PT_ENTRY_NULL) {
		spte = *ptep;

		pa = pte_to_pa(spte);

		if ((spte == ARM_PTE_TYPE_FAULT) ||
		    ARM_PTE_IS_COMPRESSED(spte) ||
		    (!pa_valid(pa))) {
				PMAP_UNLOCK(pmap);
				return result;
		}

		pai = (int)pa_index(pa);
		LOCK_PVH(pai);
	} else {
		PMAP_UNLOCK(pmap);
		return result;
	}


	if ((IS_REFFAULT_PAGE(pai)) ||
	    ((fault_type & VM_PROT_WRITE) && IS_MODFAULT_PAGE(pai))) {
		/*
		 * An attempted access will always clear ref/mod fault state, as
		 * appropriate for the fault type.  arm_clear_fast_fault will
		 * update the associated PTEs for the page as appropriate; if
		 * any PTEs are updated, we redrive the access.  If the mapping
		 * does not actually allow for the attempted access, the
		 * following fault will (hopefully) fail to update any PTEs, and
		 * thus cause arm_fast_fault to decide that it failed to handle
		 * the fault.
		 */
		if (IS_REFFAULT_PAGE(pai)) {
			CLR_REFFAULT_PAGE(pai);
		}
		if ( (fault_type & VM_PROT_WRITE) && IS_MODFAULT_PAGE(pai)) {
			CLR_MODFAULT_PAGE(pai);
		}

		if (arm_clear_fast_fault((ppnum_t)atop(pa),fault_type)) {
			/*
			 * Should this preserve KERN_PROTECTION_FAILURE?  The
			 * cost of not doing so is a another fault in a case
			 * that should already result in an exception.
			 */
			result = KERN_SUCCESS;
		}
	}

	UNLOCK_PVH(pai);
	PMAP_UNLOCK(pmap);
	return result;
}

kern_return_t
arm_fast_fault(
	pmap_t pmap,
	vm_map_address_t va,
	vm_prot_t fault_type,
	__unused boolean_t from_user)
{
	kern_return_t   result = KERN_FAILURE;

	if (va < pmap->min || va >= pmap->max)
		return result;

	PMAP_TRACE(PMAP_CODE(PMAP__FAST_FAULT) | DBG_FUNC_START,
	           VM_KERNEL_ADDRHIDE(pmap), VM_KERNEL_ADDRHIDE(va), fault_type,
	           from_user);

#if	(__ARM_VMSA__ == 7)
	if (pmap != kernel_pmap) {
		pmap_cpu_data_t *cpu_data_ptr = pmap_get_cpu_data();
		pmap_t          cur_pmap;
		pmap_t          cur_user_pmap;

		cur_pmap = current_pmap();
		cur_user_pmap = cpu_data_ptr->cpu_user_pmap;

		if ((cur_user_pmap == cur_pmap) && (cur_pmap == pmap)) {
			if (cpu_data_ptr->cpu_user_pmap_stamp != pmap->stamp) {
				pmap_set_pmap(pmap, current_thread());
				result = KERN_SUCCESS;
				goto done;
			}
		}
	}
#endif

	result = arm_fast_fault_internal(pmap, va, fault_type, from_user);

#if (__ARM_VMSA__ == 7)
done:
#endif

	PMAP_TRACE(PMAP_CODE(PMAP__FAST_FAULT) | DBG_FUNC_END, result);

	return result;
}

void
pmap_copy_page(
	ppnum_t psrc,
	ppnum_t pdst)
{
	bcopy_phys((addr64_t) (ptoa(psrc)),
	      (addr64_t) (ptoa(pdst)),
	      PAGE_SIZE);
}


/*
 *	pmap_copy_page copies the specified (machine independent) pages.
 */
void
pmap_copy_part_page(
	ppnum_t psrc,
	vm_offset_t src_offset,
	ppnum_t pdst,
	vm_offset_t dst_offset,
	vm_size_t len)
{
	bcopy_phys((addr64_t) (ptoa(psrc) + src_offset),
	      (addr64_t) (ptoa(pdst) + dst_offset),
	      len);
}


/*
 *	pmap_zero_page zeros the specified (machine independent) page.
 */
void
pmap_zero_page(
	ppnum_t pn)
{
	assert(pn != vm_page_fictitious_addr);
	bzero_phys((addr64_t) ptoa(pn), PAGE_SIZE);
}

/*
 *	pmap_zero_part_page
 *	zeros the specified (machine independent) part of a page.
 */
void
pmap_zero_part_page(
	ppnum_t pn,
	vm_offset_t offset,
	vm_size_t len)
{
	assert(pn != vm_page_fictitious_addr);
	assert(offset + len <= PAGE_SIZE);
	bzero_phys((addr64_t) (ptoa(pn) + offset), len);
}


/*
 * nop in current arm implementation
 */
void
inval_copy_windows(
	__unused thread_t t)
{
}

void
pmap_map_globals(
	void)
{
	pt_entry_t	*ptep, pte;

	ptep = pmap_pte(kernel_pmap, LOWGLOBAL_ALIAS);
	assert(ptep != PT_ENTRY_NULL);
	assert(*ptep == ARM_PTE_EMPTY);

	pte = pa_to_pte(ml_static_vtop((vm_offset_t)&lowGlo)) | AP_RONA | ARM_PTE_NX | ARM_PTE_PNX | ARM_PTE_AF | ARM_PTE_TYPE;
#if __ARM_KERNEL_PROTECT__
	pte |= ARM_PTE_NG;
#endif /* __ARM_KERNEL_PROTECT__ */
	pte |= ARM_PTE_ATTRINDX(CACHE_ATTRINDX_WRITEBACK);
#if	(__ARM_VMSA__ > 7)
	pte |= ARM_PTE_SH(SH_OUTER_MEMORY);
#else
	pte |= ARM_PTE_SH;
#endif
	*ptep = pte;
	FLUSH_PTE_RANGE(ptep,(ptep+1));
	PMAP_UPDATE_TLBS(kernel_pmap, LOWGLOBAL_ALIAS, LOWGLOBAL_ALIAS + PAGE_SIZE);
}

vm_offset_t
pmap_cpu_windows_copy_addr(int cpu_num, unsigned int index)
{
	return (vm_offset_t)(CPUWINDOWS_BASE + (PAGE_SIZE * ((CPUWINDOWS_MAX * cpu_num) + index)));
}

static unsigned int
pmap_map_cpu_windows_copy_internal(
	ppnum_t	pn,
	vm_prot_t prot,
	unsigned int wimg_bits)
{
	pt_entry_t	*ptep = NULL, pte;
	unsigned int	cpu_num;
	unsigned int	i;
	vm_offset_t	cpu_copywindow_vaddr = 0;

	cpu_num = pmap_get_cpu_data()->cpu_number;

	for (i = 0; i<CPUWINDOWS_MAX; i++) {
		cpu_copywindow_vaddr = pmap_cpu_windows_copy_addr(cpu_num, i);
		ptep = pmap_pte(kernel_pmap, cpu_copywindow_vaddr);
		assert(!ARM_PTE_IS_COMPRESSED(*ptep));
		if (*ptep == ARM_PTE_TYPE_FAULT)
			break;
	}
	if (i == CPUWINDOWS_MAX) {
		panic("pmap_map_cpu_windows_copy: out of window\n");
	}

	pte = pa_to_pte(ptoa(pn)) | ARM_PTE_TYPE | ARM_PTE_AF | ARM_PTE_NX | ARM_PTE_PNX;
#if __ARM_KERNEL_PROTECT__
	pte |= ARM_PTE_NG;
#endif /* __ARM_KERNEL_PROTECT__ */

	pte |= wimg_to_pte(wimg_bits);

	if (prot & VM_PROT_WRITE) {
		pte |= ARM_PTE_AP(AP_RWNA);
	} else {
		pte |= ARM_PTE_AP(AP_RONA);
	}

	WRITE_PTE(ptep, pte);
	/*
	 * Invalidate tlb. Cover nested cpu_copywindow_vaddr usage with the interrupted context
	 * in pmap_unmap_cpu_windows_copy() after clearing the pte and before tlb invalidate.
	 */
	PMAP_UPDATE_TLBS(kernel_pmap, cpu_copywindow_vaddr, cpu_copywindow_vaddr + PAGE_SIZE);

	return(i);
}

unsigned int
pmap_map_cpu_windows_copy(
	ppnum_t	pn,
	vm_prot_t prot,
	unsigned int wimg_bits)
{
	return pmap_map_cpu_windows_copy_internal(pn, prot, wimg_bits);
}

static void
pmap_unmap_cpu_windows_copy_internal(
	unsigned int index)
{
	pt_entry_t	*ptep;
	unsigned int	cpu_num;
	vm_offset_t	cpu_copywindow_vaddr = 0;

	cpu_num = pmap_get_cpu_data()->cpu_number;

	cpu_copywindow_vaddr = pmap_cpu_windows_copy_addr(cpu_num, index);
	__asm__	volatile("dsb sy");
	ptep = pmap_pte(kernel_pmap, cpu_copywindow_vaddr);
	WRITE_PTE(ptep, ARM_PTE_TYPE_FAULT);
	PMAP_UPDATE_TLBS(kernel_pmap, cpu_copywindow_vaddr, cpu_copywindow_vaddr + PAGE_SIZE);
}

void
pmap_unmap_cpu_windows_copy(
	unsigned int index)
{
	return pmap_unmap_cpu_windows_copy_internal(index);
}

/*
 * Marked a pmap has nested
 */
static void
pmap_set_nested_internal(
	pmap_t pmap)
{
	pmap->nested = TRUE;
}

void
pmap_set_nested(
	pmap_t pmap)
{
	pmap_set_nested_internal(pmap);
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
 */

static kern_return_t
pmap_nest_internal(
	pmap_t grand,
	pmap_t subord,
	addr64_t vstart,
	addr64_t nstart,
	uint64_t size)
{
	kern_return_t kr = KERN_FAILURE;
	vm_map_offset_t vaddr, nvaddr;
	tt_entry_t     *stte_p;
	tt_entry_t     *gtte_p;
	unsigned int    i;
	unsigned int    num_tte;
	unsigned int	nested_region_asid_bitmap_size;
	unsigned int*	nested_region_asid_bitmap;
	int expand_options = 0;


#if	(__ARM_VMSA__ == 7)
	if (((size|vstart|nstart) & ARM_TT_L1_PT_OFFMASK) != 0x0ULL) {
		return KERN_INVALID_VALUE;	/* Nest 4MB region */
	}
#else
	if (((size|vstart|nstart) & (ARM_TT_L2_OFFMASK)) != 0x0ULL) {
		panic("pmap_nest() pmap %p has a nested pmap 0x%llx, 0x%llx, 0x%llx\n", grand, vstart, nstart, size);
	}
#endif

	if ((grand->nested_pmap != PMAP_NULL) && (grand->nested_pmap != subord)) {
		panic("pmap_nest() pmap %p has a nested pmap\n", grand);
	}

	if (subord->nested_region_asid_bitmap == NULL) {
		nested_region_asid_bitmap_size  = (unsigned int)(size>>ARM_TT_TWIG_SHIFT)/(sizeof(unsigned int)*NBBY);

		nested_region_asid_bitmap = kalloc(nested_region_asid_bitmap_size*sizeof(unsigned int));
		bzero(nested_region_asid_bitmap, nested_region_asid_bitmap_size*sizeof(unsigned int));

		PMAP_LOCK(subord);
		if (subord->nested_region_asid_bitmap == NULL) {
			subord->nested_region_asid_bitmap = nested_region_asid_bitmap;
			subord->nested_region_asid_bitmap_size = nested_region_asid_bitmap_size;
			subord->nested_region_subord_addr = nstart;
			subord->nested_region_size = (mach_vm_offset_t) size;
			nested_region_asid_bitmap = NULL;
		}
		PMAP_UNLOCK(subord);
		if (nested_region_asid_bitmap != NULL) {
			kfree(nested_region_asid_bitmap, nested_region_asid_bitmap_size*sizeof(unsigned int));
		}
	}
	if ((subord->nested_region_subord_addr + subord->nested_region_size) < (nstart+size)) {
		uint64_t	new_size;
		unsigned int	new_nested_region_asid_bitmap_size;
		unsigned int*	new_nested_region_asid_bitmap;

		nested_region_asid_bitmap = NULL;
		nested_region_asid_bitmap_size = 0;
		new_size =  nstart + size - subord->nested_region_subord_addr;

		/* We explicitly add 1 to the bitmap allocation size in order to avoid issues with truncation. */
		new_nested_region_asid_bitmap_size  = (unsigned int)((new_size>>ARM_TT_TWIG_SHIFT)/(sizeof(unsigned int)*NBBY)) + 1;

		new_nested_region_asid_bitmap = kalloc(new_nested_region_asid_bitmap_size*sizeof(unsigned int));
		PMAP_LOCK(subord);
		if (subord->nested_region_size < new_size) {
			bzero(new_nested_region_asid_bitmap, new_nested_region_asid_bitmap_size*sizeof(unsigned int));
			bcopy(subord->nested_region_asid_bitmap, new_nested_region_asid_bitmap, subord->nested_region_asid_bitmap_size);
			nested_region_asid_bitmap_size  = subord->nested_region_asid_bitmap_size;
			nested_region_asid_bitmap = subord->nested_region_asid_bitmap;
			subord->nested_region_asid_bitmap = new_nested_region_asid_bitmap;
			subord->nested_region_asid_bitmap_size = new_nested_region_asid_bitmap_size;
			subord->nested_region_size = new_size;
			new_nested_region_asid_bitmap = NULL;
		}
		PMAP_UNLOCK(subord);
		if (nested_region_asid_bitmap != NULL)
			kfree(nested_region_asid_bitmap, nested_region_asid_bitmap_size*sizeof(unsigned int));
		if (new_nested_region_asid_bitmap != NULL)
			kfree(new_nested_region_asid_bitmap, new_nested_region_asid_bitmap_size*sizeof(unsigned int));
	}

	PMAP_LOCK(subord);
	if (grand->nested_pmap == PMAP_NULL) {
		grand->nested_pmap = subord;
		grand->nested_region_grand_addr = vstart;
		grand->nested_region_subord_addr = nstart;
		grand->nested_region_size = (mach_vm_offset_t) size;
	} else {
		if ((grand->nested_region_grand_addr > vstart)) {
			panic("pmap_nest() pmap %p : attempt to nest outside the nested region\n", grand);
		}
		else if ((grand->nested_region_grand_addr + grand->nested_region_size) < (vstart+size)) {
			grand->nested_region_size = (mach_vm_offset_t)(vstart - grand->nested_region_grand_addr + size);
		}
	}

#if	(__ARM_VMSA__ == 7)
	nvaddr = (vm_map_offset_t) nstart;
	vaddr = (vm_map_offset_t) vstart;
	num_tte = size >> ARM_TT_L1_SHIFT;

	for (i = 0; i < num_tte; i++) {
		stte_p = pmap_tte(subord, nvaddr);
		if ((stte_p == (tt_entry_t *)NULL) || (((*stte_p) & ARM_TTE_TYPE_MASK) != ARM_TTE_TYPE_TABLE)) {
			PMAP_UNLOCK(subord);
			kr = pmap_expand(subord, nvaddr, expand_options, PMAP_TT_L2_LEVEL);

			if (kr != KERN_SUCCESS) {
				PMAP_LOCK(grand);
				goto done;
			}

			PMAP_LOCK(subord);
		}
		PMAP_UNLOCK(subord);
		PMAP_LOCK(grand);
		stte_p = pmap_tte(grand, vaddr);
		if (stte_p == (tt_entry_t *)NULL) {
			PMAP_UNLOCK(grand);
			kr = pmap_expand(grand, vaddr, expand_options, PMAP_TT_L1_LEVEL);

			if (kr != KERN_SUCCESS) {
				PMAP_LOCK(grand);
				goto done;
			}
		} else {
			PMAP_UNLOCK(grand);
			kr = KERN_SUCCESS;
		}
		PMAP_LOCK(subord);


		nvaddr += ARM_TT_L1_SIZE;
		vaddr += ARM_TT_L1_SIZE;
	}

#else
	nvaddr = (vm_map_offset_t) nstart;
	num_tte = (unsigned int)(size >> ARM_TT_L2_SHIFT);

	for (i = 0; i < num_tte; i++) {
		stte_p = pmap_tt2e(subord, nvaddr);
		if (stte_p == PT_ENTRY_NULL || *stte_p == ARM_TTE_EMPTY) {
			PMAP_UNLOCK(subord);
			kr = pmap_expand(subord, nvaddr, expand_options, PMAP_TT_L3_LEVEL);

			if (kr != KERN_SUCCESS) {
				PMAP_LOCK(grand);
				goto done;
			}

			PMAP_LOCK(subord);
		}
		nvaddr += ARM_TT_L2_SIZE;
	}
#endif
	PMAP_UNLOCK(subord);

	/*
	 * copy tte's from subord pmap into grand pmap
	 */

	PMAP_LOCK(grand);
	nvaddr = (vm_map_offset_t) nstart;
	vaddr = (vm_map_offset_t) vstart;


#if	(__ARM_VMSA__ == 7)
	for (i = 0; i < num_tte; i++) {

		stte_p = pmap_tte(subord, nvaddr);
		gtte_p = pmap_tte(grand, vaddr);
		*gtte_p = *stte_p;

		nvaddr += ARM_TT_L1_SIZE;
		vaddr += ARM_TT_L1_SIZE;
	}
#else
	for (i = 0; i < num_tte; i++) {

		stte_p = pmap_tt2e(subord, nstart);
		gtte_p = pmap_tt2e(grand, vaddr);
		if (gtte_p == PT_ENTRY_NULL) {
			PMAP_UNLOCK(grand);
			kr = pmap_expand(grand, vaddr, expand_options, PMAP_TT_L2_LEVEL);
			PMAP_LOCK(grand);

			if (kr != KERN_SUCCESS) {
				goto done;
			}

			gtte_p = pmap_tt2e(grand, vaddr);
		}
		*gtte_p = *stte_p;
		vaddr += ARM_TT_L2_SIZE;
		nstart += ARM_TT_L2_SIZE;
	}
#endif

	kr = KERN_SUCCESS;
done:

#ifndef	__ARM_L1_PTW__
	CleanPoU_DcacheRegion((vm_offset_t) pmap_tte(grand, vstart), num_tte * sizeof(tt_entry_t));
#endif

#if 	(__ARM_VMSA__ > 7)
	/*
	 * check for overflow on LP64 arch
	 */
	assert((size & 0xFFFFFFFF00000000ULL) == 0);
#endif
	PMAP_UPDATE_TLBS(grand, vstart, vstart + size);

	PMAP_UNLOCK(grand);
	return kr;
}

kern_return_t pmap_nest(
	pmap_t grand,
	pmap_t subord,
	addr64_t vstart,
	addr64_t nstart,
	uint64_t size)
{
	kern_return_t kr = KERN_FAILURE;

	PMAP_TRACE(PMAP_CODE(PMAP__NEST) | DBG_FUNC_START,
	           VM_KERNEL_ADDRHIDE(grand), VM_KERNEL_ADDRHIDE(subord),
	           VM_KERNEL_ADDRHIDE(vstart));

	kr = pmap_nest_internal(grand, subord, vstart, nstart, size);

	PMAP_TRACE(PMAP_CODE(PMAP__NEST) | DBG_FUNC_END, kr);

	return kr;
}

/*
 *	kern_return_t pmap_unnest(grand, vaddr)
 *
 *	grand  = the pmap that we will nest subord into
 *	vaddr  = start of range in pmap to be unnested
 *	size   = size of range in pmap to be unnested
 *
 */

kern_return_t
pmap_unnest(
	pmap_t grand,
	addr64_t vaddr,
	uint64_t size)
{
	return(pmap_unnest_options(grand, vaddr, size, 0));
}

static kern_return_t
pmap_unnest_options_internal(
	pmap_t grand,
	addr64_t vaddr,
	uint64_t size,
	unsigned int option)
{
	vm_map_offset_t start;
	vm_map_offset_t addr;
	tt_entry_t     *tte_p;
	unsigned int    current_index;
	unsigned int    start_index;
	unsigned int    max_index;
	unsigned int    num_tte;
	unsigned int    i;

#if	(__ARM_VMSA__ == 7)
	if (((size|vaddr) & ARM_TT_L1_PT_OFFMASK) != 0x0ULL) {
		panic("pmap_unnest(): unaligned request\n");
	}
#else
	if (((size|vaddr) & ARM_TT_L2_OFFMASK) != 0x0ULL) {
			panic("pmap_unnest(): unaligned request\n");
	}
#endif

	if ((option & PMAP_UNNEST_CLEAN) == 0)
	{
		PMAP_LOCK(grand->nested_pmap);

		start = vaddr - grand->nested_region_grand_addr + grand->nested_region_subord_addr ;
		start_index = (unsigned int)((vaddr - grand->nested_region_grand_addr)  >> ARM_TT_TWIG_SHIFT);
		max_index = (unsigned int)(start_index + (size >> ARM_TT_TWIG_SHIFT));
		num_tte = (unsigned int)(size >> ARM_TT_TWIG_SHIFT);

		if (size > grand->nested_region_size) {
			panic("pmap_unnest() pmap %p %llu, %llu\n", grand, size,  (uint64_t)grand->nested_region_size);
		}

		for (current_index = start_index,  addr = start; current_index < max_index; current_index++) {
			pt_entry_t  *bpte, *epte, *cpte;


			if(!testbit(current_index, (int *)grand->nested_pmap->nested_region_asid_bitmap)) {

				setbit(current_index, (int *)grand->nested_pmap->nested_region_asid_bitmap);
				bpte = pmap_pte(grand->nested_pmap, addr);
				epte = bpte + (ARM_TT_LEAF_INDEX_MASK>>ARM_TT_LEAF_SHIFT);

				for (cpte = bpte; cpte <= epte; cpte++) {
					pmap_paddr_t	pa;
					int				pai=0;
					boolean_t		managed=FALSE;
					pt_entry_t  spte;

					if ((*cpte != ARM_PTE_TYPE_FAULT)
					    && (!ARM_PTE_IS_COMPRESSED(*cpte))) {

						spte = *cpte;
						while (!managed) {
							pa = pte_to_pa(spte);
							if (!pa_valid(pa))
								break;
							pai = (int)pa_index(pa);
							LOCK_PVH(pai);
							spte = *cpte;
							pa = pte_to_pa(spte);
							if (pai == (int)pa_index(pa)) {
								managed =TRUE;
								break; // Leave the PVH locked as we'll unlock it after we update the PTE
							}
							UNLOCK_PVH(pai);
						}

						if (((spte & ARM_PTE_NG) != ARM_PTE_NG)) {

							WRITE_PTE(cpte, (spte | ARM_PTE_NG));
						}

						if (managed)
						{
							ASSERT_PVH_LOCKED(pai);
							UNLOCK_PVH(pai);
						}
					}
				}
			}

			addr += ARM_TT_TWIG_SIZE;

#ifndef	__ARM_L1_PTW__
			CleanPoU_DcacheRegion((vm_offset_t) pmap_pte(grand->nested_pmap, start), num_tte * sizeof(tt_entry_t));
#endif
			PMAP_UPDATE_TLBS(grand->nested_pmap, start, start + size);
		}

		PMAP_UNLOCK(grand->nested_pmap);
	}

	PMAP_LOCK(grand);

	/*
	 * invalidate all pdes for segment at vaddr in pmap grand
	 */
	start = vaddr;
	addr = vaddr;

	num_tte = (unsigned int)(size >> ARM_TT_TWIG_SHIFT);

	for (i = 0; i < num_tte; i++) {
		tte_p = pmap_tte(grand, addr);
		*tte_p = ARM_TTE_TYPE_FAULT;

		addr += ARM_TT_TWIG_SIZE;
	}

#ifndef	__ARM_L1_PTW__
	CleanPoU_DcacheRegion((vm_offset_t) pmap_tte(grand, start), num_tte * sizeof(tt_entry_t));
#endif
	PMAP_UPDATE_TLBS(grand, start, start + size);

	PMAP_UNLOCK(grand);

	return KERN_SUCCESS;
}

kern_return_t
pmap_unnest_options(
	pmap_t grand,
	addr64_t vaddr,
	uint64_t size,
	unsigned int option)
{
	kern_return_t kr = KERN_FAILURE;

	PMAP_TRACE(PMAP_CODE(PMAP__UNNEST) | DBG_FUNC_START,
	           VM_KERNEL_ADDRHIDE(grand), VM_KERNEL_ADDRHIDE(vaddr));

	kr = pmap_unnest_options_internal(grand, vaddr, size, option);

	PMAP_TRACE(PMAP_CODE(PMAP__UNNEST) | DBG_FUNC_END, kr);

	return kr;
}

boolean_t
pmap_adjust_unnest_parameters(
	__unused pmap_t p,
	__unused vm_map_offset_t *s,
	__unused vm_map_offset_t *e)
{
	return TRUE; /* to get to log_unnest_badness()... */
}

/*
 * disable no-execute capability on
 * the specified pmap
 */
#if DEVELOPMENT || DEBUG
void
pmap_disable_NX(
	pmap_t pmap)
{
	pmap->nx_enabled = FALSE;
}
#else
void
pmap_disable_NX(
	__unused pmap_t pmap)
{
}
#endif

void
pt_fake_zone_init(
	int zone_index)
{
	pt_fake_zone_index = zone_index;
}

void
pt_fake_zone_info(
	int *count,
	vm_size_t *cur_size, vm_size_t *max_size, vm_size_t *elem_size, vm_size_t *alloc_size,
	uint64_t *sum_size, int *collectable, int *exhaustable, int *caller_acct)
{
	*count      = inuse_pmap_pages_count;
	*cur_size   = PAGE_SIZE * (inuse_pmap_pages_count);
	*max_size   = PAGE_SIZE * (inuse_pmap_pages_count + vm_page_inactive_count + vm_page_active_count + vm_page_free_count);
	*elem_size  = PAGE_SIZE;
	*alloc_size = PAGE_SIZE;
	*sum_size   = (alloc_pmap_pages_count) * PAGE_SIZE;

	*collectable = 1;
	*exhaustable = 0;
	*caller_acct = 1;
}

/*
 * flush a range of hardware TLB entries.
 * NOTE: assumes the smallest TLB entry in use will be for
 * an ARM small page (4K).
 */

#define ARM_FULL_TLB_FLUSH_THRESHOLD	 64
#define ARM64_FULL_TLB_FLUSH_THRESHOLD	256

static void
flush_mmu_tlb_region_asid(
	vm_offset_t va,
	unsigned length,
	pmap_t pmap)
{
#if	(__ARM_VMSA__ == 7)
	vm_offset_t     end = va + length;
	uint32_t	asid;

	asid = pmap->asid;

	if (length / ARM_SMALL_PAGE_SIZE > ARM_FULL_TLB_FLUSH_THRESHOLD) {
		boolean_t	flush_all = FALSE;

		if ((asid == 0) || (pmap->nested == TRUE))
			flush_all = TRUE;
		if (flush_all)
			flush_mmu_tlb();
		else
			flush_mmu_tlb_asid(asid);

		return;
	}
	if (pmap->nested == TRUE) {
#if	!__ARM_MP_EXT__
		flush_mmu_tlb();
#else
		va = arm_trunc_page(va);
		while (va < end) {
			flush_mmu_tlb_mva_entries(va);
			va += ARM_SMALL_PAGE_SIZE;
		}
#endif
		return;
	}
	va = arm_trunc_page(va) | (asid & 0xff);
	flush_mmu_tlb_entries(va, end);

#else
	vm_offset_t		end = va + length;
	uint32_t		asid;

	asid = pmap->asid;

	if ((length >> ARM_TT_L3_SHIFT) > ARM64_FULL_TLB_FLUSH_THRESHOLD) {
		boolean_t       flush_all = FALSE;

		if ((asid == 0) || (pmap->nested == TRUE))
			flush_all = TRUE;
		if (flush_all)
			flush_mmu_tlb();
		else
			flush_mmu_tlb_asid((uint64_t)asid << TLBI_ASID_SHIFT);
		return;
	}
	va = tlbi_asid(asid) | tlbi_addr(va);
	end = tlbi_asid(asid) | tlbi_addr(end);
	if (pmap->nested == TRUE) {
		flush_mmu_tlb_allentries(va, end);
	} else {
		flush_mmu_tlb_entries(va, end);
	}

#endif
}

void
flush_mmu_tlb_region(
	vm_offset_t va,
	unsigned length)
{
	flush_mmu_tlb_region_asid(va, length, kernel_pmap);
}

unsigned int
pmap_cache_attributes(
	ppnum_t pn)
{
	pmap_paddr_t    paddr;
	int		pai;
	unsigned int	result;
	pp_attr_t	pp_attr_current;

	paddr = ptoa(pn);

	if ((paddr >= io_rgn_start) && (paddr < io_rgn_end)) {
		unsigned int attr = IO_ATTR_WIMG(io_attr_table[(paddr - io_rgn_start) / io_rgn_granule]);
		if (attr)
			return attr;
		else
			return (VM_WIMG_IO);
	}


	if (!pmap_initialized) {
		if  ((paddr >= gPhysBase) && (paddr < gPhysBase+gPhysSize))
			return (VM_WIMG_DEFAULT);
		else
			return (VM_WIMG_IO);
	}


	if (!pa_valid(paddr))
		return (VM_WIMG_IO);

	result = VM_WIMG_DEFAULT;

	pai = (int)pa_index(paddr);

	pp_attr_current = pp_attr_table[pai];
	if (pp_attr_current & PP_ATTR_WIMG_MASK)
		result = pp_attr_current & PP_ATTR_WIMG_MASK;
	return result;
}

static boolean_t
pmap_batch_set_cache_attributes_internal(
	ppnum_t	pn,
	unsigned int cacheattr,
	unsigned int page_cnt,
	unsigned int page_index,
	boolean_t doit,
	unsigned int *res)
{
	pmap_paddr_t    paddr;
	int		pai;
	pp_attr_t	pp_attr_current;
	pp_attr_t	pp_attr_template;
	unsigned int	wimg_bits_prev, wimg_bits_new;

	if (cacheattr & VM_WIMG_USE_DEFAULT)
		cacheattr = VM_WIMG_DEFAULT;

	if ((doit == FALSE) &&  (*res == 0)) {
		*res = page_cnt;
		if (platform_cache_batch_wimg(cacheattr & (VM_WIMG_MASK), page_cnt<<PAGE_SHIFT) == FALSE) {
			return FALSE;
		}
	}

	paddr = ptoa(pn);

	if (!pa_valid(paddr)) {
		panic("pmap_batch_set_cache_attributes(): pn 0x%08x not managed\n", pn);
	}

	pai = (int)pa_index(paddr);

	if (doit)
		LOCK_PVH(pai);

	pp_attr_current = pp_attr_table[pai];
	wimg_bits_prev = VM_WIMG_DEFAULT;
	if (pp_attr_current & PP_ATTR_WIMG_MASK)
		wimg_bits_prev = pp_attr_current & PP_ATTR_WIMG_MASK;

	pp_attr_template = (pp_attr_current & ~PP_ATTR_WIMG_MASK) | PP_ATTR_WIMG(cacheattr & (VM_WIMG_MASK));

	if (doit)
		pp_attr_table[pai] = pp_attr_template;

	wimg_bits_new = VM_WIMG_DEFAULT;
	if (pp_attr_template & PP_ATTR_WIMG_MASK)
		wimg_bits_new = pp_attr_template & PP_ATTR_WIMG_MASK;

	if (doit) {
		if (wimg_bits_new != wimg_bits_prev)
			pmap_update_cache_attributes_locked(pn, cacheattr);
		UNLOCK_PVH(pai);
	} else {
		if (wimg_bits_new == VM_WIMG_COPYBACK) {
			return FALSE;
		}
		if (wimg_bits_prev == wimg_bits_new) {
			*res = *res-1;
			if (!platform_cache_batch_wimg(wimg_bits_new, (*res)<<PAGE_SHIFT)) {
				return FALSE;
			}
		}
		return TRUE;
	}

	if (page_cnt ==  (page_index+1)) {
		wimg_bits_prev = VM_WIMG_COPYBACK;
		if (((page_cnt ==  (page_index+1)) && (wimg_bits_prev != wimg_bits_new))
		    && ((wimg_bits_prev == VM_WIMG_COPYBACK)
       	         || ((wimg_bits_prev == VM_WIMG_INNERWBACK)
			    && (wimg_bits_new != VM_WIMG_COPYBACK))
			|| ((wimg_bits_prev == VM_WIMG_WTHRU)
			    && ((wimg_bits_new != VM_WIMG_COPYBACK) || (wimg_bits_new != VM_WIMG_INNERWBACK))))) {
			platform_cache_flush_wimg(wimg_bits_new);
		}
	}

	return TRUE;
};

boolean_t
pmap_batch_set_cache_attributes(
	ppnum_t	pn,
	unsigned int cacheattr,
	unsigned int page_cnt,
	unsigned int page_index,
	boolean_t doit,
	unsigned int *res)
{
	return pmap_batch_set_cache_attributes_internal(pn, cacheattr, page_cnt, page_index, doit, res);
}

static void
pmap_set_cache_attributes_internal(
	ppnum_t pn,
	unsigned int cacheattr)
{
	pmap_paddr_t    paddr;
	int		pai;
	pp_attr_t	pp_attr_current;
	pp_attr_t	pp_attr_template;
	unsigned int	wimg_bits_prev, wimg_bits_new;

	paddr = ptoa(pn);

	if (!pa_valid(paddr)) {
		return;				/* Not a managed page. */
	}

	if (cacheattr & VM_WIMG_USE_DEFAULT)
		cacheattr = VM_WIMG_DEFAULT;

	pai = (int)pa_index(paddr);

	LOCK_PVH(pai);

	pp_attr_current = pp_attr_table[pai];
	wimg_bits_prev = VM_WIMG_DEFAULT;
	if (pp_attr_current & PP_ATTR_WIMG_MASK)
		wimg_bits_prev = pp_attr_current & PP_ATTR_WIMG_MASK;

	pp_attr_template = (pp_attr_current & ~PP_ATTR_WIMG_MASK) | PP_ATTR_WIMG(cacheattr & (VM_WIMG_MASK)) ;

	pp_attr_table[pai] = pp_attr_template;
	wimg_bits_new = VM_WIMG_DEFAULT;
	if (pp_attr_template & PP_ATTR_WIMG_MASK)
		wimg_bits_new = pp_attr_template & PP_ATTR_WIMG_MASK;

	if (wimg_bits_new != wimg_bits_prev)
		pmap_update_cache_attributes_locked(pn, cacheattr);

	UNLOCK_PVH(pai);

	if ((wimg_bits_prev != wimg_bits_new)
	    && ((wimg_bits_prev == VM_WIMG_COPYBACK)
                || ((wimg_bits_prev == VM_WIMG_INNERWBACK)
		    && (wimg_bits_new != VM_WIMG_COPYBACK))
		|| ((wimg_bits_prev == VM_WIMG_WTHRU)
		    && ((wimg_bits_new != VM_WIMG_COPYBACK) || (wimg_bits_new != VM_WIMG_INNERWBACK)))))
		pmap_sync_page_attributes_phys(pn);

}

void
pmap_set_cache_attributes(
	ppnum_t pn,
	unsigned int cacheattr)
{
	pmap_set_cache_attributes_internal(pn, cacheattr);
}

void
pmap_update_cache_attributes_locked(
	ppnum_t ppnum,
	unsigned attributes)
{
	pmap_paddr_t	phys = ptoa(ppnum);
	pv_entry_t	*pve_p;
	pt_entry_t	*pte_p;
	pv_entry_t	**pv_h;
	pt_entry_t      tmplate;
	unsigned int	pai;

#if (__ARM_VMSA__ == 7)
	#define ARM_PTE_SHMASK ARM_PTE_SH
#endif

#if __ARM_PTE_PHYSMAP__
	vm_offset_t kva = phystokv(phys);
	pte_p = pmap_pte(kernel_pmap, kva);

	tmplate = *pte_p;
	tmplate &= ~(ARM_PTE_ATTRINDXMASK | ARM_PTE_SHMASK);
	tmplate |= wimg_to_pte(attributes);

	WRITE_PTE(pte_p, tmplate);
	PMAP_UPDATE_TLBS(kernel_pmap, kva, kva + PAGE_SIZE);
#endif

	pai = (unsigned int)pa_index(phys);

	pv_h = pai_to_pvh(pai);

	pte_p = PT_ENTRY_NULL;
	pve_p = PV_ENTRY_NULL;
	if (pvh_test_type(pv_h, PVH_TYPE_PTEP)) {
		pte_p = pvh_ptep(pv_h);
	} else if  (pvh_test_type(pv_h, PVH_TYPE_PVEP)) {
		pve_p = pvh_list(pv_h);
		pte_p = PT_ENTRY_NULL;
	}

	while ((pve_p != PV_ENTRY_NULL) || (pte_p != PT_ENTRY_NULL)) {
		vm_map_address_t va;
		pmap_t          pmap;

		if (pve_p != PV_ENTRY_NULL)
			pte_p = pve_get_ptep(pve_p);

		pmap = ptep_get_pmap(pte_p);
		va = ptep_get_va(pte_p);

		tmplate = *pte_p;
		tmplate &= ~(ARM_PTE_ATTRINDXMASK | ARM_PTE_SHMASK);
		tmplate |= wimg_to_pte(attributes);

		WRITE_PTE(pte_p, tmplate);
		PMAP_UPDATE_TLBS(pmap, va, va + PAGE_SIZE);

		pte_p = PT_ENTRY_NULL;
		if (pve_p != PV_ENTRY_NULL)
			pve_p = PVE_NEXT_PTR(pve_next(pve_p));

	}
}

#if	(__ARM_VMSA__ == 7)
vm_map_address_t
pmap_create_sharedpage(
	void)
{
	pmap_paddr_t    pa;
	kern_return_t   kr;

	(void) pmap_pages_alloc(&pa, PAGE_SIZE, 0);
	memset((char *) phystokv(pa), 0, PAGE_SIZE);

	kr = pmap_enter(kernel_pmap, _COMM_PAGE_BASE_ADDRESS, atop(pa), VM_PROT_READ | VM_PROT_WRITE, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, TRUE);
	assert(kr == KERN_SUCCESS);

	return((vm_map_address_t)phystokv(pa));

}
#else
static void
pmap_update_tt3e(
	pmap_t pmap,
	vm_address_t address,
	tt_entry_t template)
{
	tt_entry_t *ptep, pte;

	ptep = pmap_tt3e(pmap, address);
	if (ptep == NULL) {
		panic("%s: no ptep?\n", __FUNCTION__);
	}

	pte = *ptep;
	pte = tte_to_pa(pte) | template;
	WRITE_PTE(ptep, pte);
}

/* Note absence of non-global bit */
#define PMAP_COMM_PAGE_PTE_TEMPLATE (ARM_PTE_TYPE_VALID \
		| ARM_PTE_ATTRINDX(CACHE_ATTRINDX_WRITEBACK) \
		| ARM_PTE_SH(SH_INNER_MEMORY) | ARM_PTE_NX \
		| ARM_PTE_PNX | ARM_PTE_AP(AP_RORO) | ARM_PTE_AF)

vm_map_address_t
pmap_create_sharedpage(
		       void
)
{
	kern_return_t   kr;
	pmap_paddr_t    pa = 0;


	(void) pmap_pages_alloc(&pa, PAGE_SIZE, 0);

	memset((char *) phystokv(pa), 0, PAGE_SIZE);

	/*
	 * The kernel pmap maintains a user accessible mapping of the commpage
	 * to test PAN.
	 */
	kr = pmap_expand(kernel_pmap, _COMM_HIGH_PAGE64_BASE_ADDRESS, 0, PMAP_TT_L3_LEVEL);
	assert(kr == KERN_SUCCESS);
	kr = pmap_enter(kernel_pmap, _COMM_HIGH_PAGE64_BASE_ADDRESS, (ppnum_t)atop(pa), VM_PROT_READ, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, TRUE);
	assert(kr == KERN_SUCCESS);

	/*
	 * This mapping should not be global (as we only expect to reference it
	 * during testing).
	 */
	pmap_update_tt3e(kernel_pmap, _COMM_HIGH_PAGE64_BASE_ADDRESS, PMAP_COMM_PAGE_PTE_TEMPLATE | ARM_PTE_NG);

	/*
	 * With PAN enabled kernel drivers can no longer use the previous mapping which is user readable
	 * They should use the following mapping instead
	 */
	kr = pmap_expand(kernel_pmap, _COMM_PRIV_PAGE64_BASE_ADDRESS, 0, PMAP_TT_L3_LEVEL);
	assert(kr == KERN_SUCCESS);
	kr = pmap_enter(kernel_pmap, _COMM_PRIV_PAGE64_BASE_ADDRESS, (ppnum_t)atop(pa), VM_PROT_READ, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, TRUE);
	assert(kr == KERN_SUCCESS);

	/*
	 * In order to avoid burning extra pages on mapping the shared page, we
	 * create a dedicated pmap for the shared page.  We forcibly nest the
	 * translation tables from this pmap into other pmaps.  The level we
	 * will nest at depends on the MMU configuration (page size, TTBR range,
	 * etc).
	 *
	 * Note that this is NOT "the nested pmap" (which is used to nest the
	 * shared cache).
	 *
	 * Note that we update parameters of the entry for our unique needs (NG
	 * entry, etc.).
	 */
	sharedpage_pmap = pmap_create(NULL, 0x0, FALSE);
	assert(sharedpage_pmap != NULL);

	/* The user 64-bit mapping... */
	kr = pmap_enter(sharedpage_pmap, _COMM_PAGE64_BASE_ADDRESS, (ppnum_t)atop(pa), VM_PROT_READ, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, TRUE);
	assert(kr == KERN_SUCCESS);
	pmap_update_tt3e(sharedpage_pmap, _COMM_PAGE64_BASE_ADDRESS, PMAP_COMM_PAGE_PTE_TEMPLATE);

	/* ...and the user 32-bit mapping. */
	kr = pmap_enter(sharedpage_pmap, _COMM_PAGE32_BASE_ADDRESS, (ppnum_t)atop(pa), VM_PROT_READ, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, TRUE);
	assert(kr == KERN_SUCCESS);
	pmap_update_tt3e(sharedpage_pmap, _COMM_PAGE32_BASE_ADDRESS, PMAP_COMM_PAGE_PTE_TEMPLATE);

	/* For manipulation in kernel, go straight to physical page */
	sharedpage_rw_addr = phystokv(pa);
	return((vm_map_address_t)sharedpage_rw_addr);
}

/*
 * Asserts to ensure that the TTEs we nest to map the shared page do not overlap
 * with user controlled TTEs.
 */
#if (ARM_PGSHIFT == 14) || __ARM64_TWO_LEVEL_PMAP__
static_assert((_COMM_PAGE64_BASE_ADDRESS & ~ARM_TT_L2_OFFMASK) >= MACH_VM_MAX_ADDRESS);
static_assert((_COMM_PAGE32_BASE_ADDRESS & ~ARM_TT_L2_OFFMASK) >= VM_MAX_ADDRESS);
#elif (ARM_PGSHIFT == 12)
static_assert((_COMM_PAGE64_BASE_ADDRESS & ~ARM_TT_L1_OFFMASK) >= MACH_VM_MAX_ADDRESS);
static_assert((_COMM_PAGE32_BASE_ADDRESS & ~ARM_TT_L1_OFFMASK) >= VM_MAX_ADDRESS);
#else
#error Nested shared page mapping is unsupported on this config
#endif

static void
pmap_insert_sharedpage_internal(
	pmap_t pmap)
{
#if (ARM_PGSHIFT == 14) && !__ARM64_TWO_LEVEL_PMAP__
	kern_return_t kr;
#endif
	vm_offset_t sharedpage_vaddr;
	pt_entry_t *ttep, *src_ttep;
#if _COMM_PAGE_AREA_LENGTH != PAGE_SIZE
#error We assume a single page.
#endif

	if (pmap_is_64bit(pmap)) {
		sharedpage_vaddr = _COMM_PAGE64_BASE_ADDRESS;
	} else {
		sharedpage_vaddr = _COMM_PAGE32_BASE_ADDRESS;
	}

	PMAP_LOCK(pmap);

	/*
	 * For 4KB pages, we can force the commpage to nest at the level one
	 * page table, as each entry is 1GB (i.e, there will be no overlap
	 * with regular userspace mappings).  For 16KB pages, each level one
	 * entry is 64GB, so we must go to the second level entry (32MB) in
	 * order to nest.
	 */
#if (ARM_PGSHIFT == 12)
#if __ARM64_TWO_LEVEL_PMAP__
#error A two level page table with a page shift of 12 is not currently supported
#endif
	/* Just slam in the L1 entry.  */
	ttep = pmap_tt1e(pmap, sharedpage_vaddr);

	if (*ttep != ARM_PTE_EMPTY) {
		panic("%s: Found something mapped at the commpage address?!", __FUNCTION__);
	}

	src_ttep = pmap_tt1e(sharedpage_pmap, sharedpage_vaddr);
#elif (ARM_PGSHIFT == 14)
#if !__ARM64_TWO_LEVEL_PMAP__
	/* Allocate for the L2 entry if necessary, and slam it into place. */
	/*
	 * As long as we are use a three level page table, the first level
	 * should always exist, so we don't need to check for it.
	 */
	while (*pmap_tt1e(pmap, sharedpage_vaddr) == ARM_PTE_EMPTY) {
		PMAP_UNLOCK(pmap);

		kr = pmap_expand(pmap, _COMM_PAGE32_BASE_ADDRESS, 0, PMAP_TT_L2_LEVEL);

		if (kr != KERN_SUCCESS) {
			panic("Failed to pmap_expand for 32-bit commpage, pmap=%p", pmap);
		}

		PMAP_LOCK(pmap);
	}
#endif

	ttep = pmap_tt2e(pmap, sharedpage_vaddr);

	if (*ttep != ARM_PTE_EMPTY) {
		panic("%s: Found something mapped at the commpage address?!", __FUNCTION__);
	}

	src_ttep = pmap_tt2e(sharedpage_pmap, sharedpage_vaddr);
#endif

	*ttep =  *src_ttep;
#ifndef __ARM_L1_PTW__
	CleanPoU_DcacheRegion((vm_offset_t) ttep, sizeof(tt_entry_t));
#endif
	/* TODO: Should we flush in the 64-bit case? */
	flush_mmu_tlb_region(sharedpage_vaddr, PAGE_SIZE);

#if (ARM_PGSHIFT == 12) && !__ARM64_TWO_LEVEL_PMAP__
	flush_mmu_tlb_entry(tlbi_addr(sharedpage_vaddr & ~ARM_TT_L1_OFFMASK) | tlbi_asid(pmap->asid));
#elif (ARM_PGSHIFT == 14)
	flush_mmu_tlb_entry(tlbi_addr(sharedpage_vaddr & ~ARM_TT_L2_OFFMASK) | tlbi_asid(pmap->asid));
#endif

	PMAP_UNLOCK(pmap);
}

static void
pmap_sharedpage_flush_32_to_64(
	void)
{
	flush_mmu_tlb_region(_COMM_PAGE32_BASE_ADDRESS, PAGE_SIZE);
}

static void
pmap_unmap_sharedpage(
	pmap_t pmap)
{
	pt_entry_t *ttep;
	vm_offset_t sharedpage_vaddr;

#if _COMM_PAGE_AREA_LENGTH != PAGE_SIZE
#error We assume a single page.
#endif

	if (pmap_is_64bit(pmap)) {
		sharedpage_vaddr = _COMM_PAGE64_BASE_ADDRESS;
	} else {
		sharedpage_vaddr = _COMM_PAGE32_BASE_ADDRESS;
	}

#if (ARM_PGSHIFT == 12)
#if __ARM64_TWO_LEVEL_PMAP__
#error A two level page table with a page shift of 12 is not currently supported
#endif
	ttep = pmap_tt1e(pmap, sharedpage_vaddr);

	if (ttep == NULL) {
		return;
	}

	/* It had better be mapped to the shared page */
	if (*ttep != ARM_TTE_EMPTY && *ttep != *pmap_tt1e(sharedpage_pmap, sharedpage_vaddr)) {
		panic("%s: Something other than commpage mapped in shared page slot?", __FUNCTION__);
	}
#elif (ARM_PGSHIFT == 14)
	ttep = pmap_tt2e(pmap, sharedpage_vaddr);

	if (ttep == NULL) {
		return;
	}

	/* It had better be mapped to the shared page */
	if (*ttep != ARM_TTE_EMPTY && *ttep != *pmap_tt2e(sharedpage_pmap, sharedpage_vaddr)) {
		panic("%s: Something other than commpage mapped in shared page slot?", __FUNCTION__);
	}
#endif

	*ttep = ARM_TTE_EMPTY;
	flush_mmu_tlb_region(sharedpage_vaddr, PAGE_SIZE);

#if (ARM_PGSHIFT == 12)
#if __ARM64_TWO_LEVEL_PMAP__
#error A two level page table with a page shift of 12 is not currently supported
#endif
	flush_mmu_tlb_entry(tlbi_addr(sharedpage_vaddr & ~ARM_TT_L1_OFFMASK) | tlbi_asid(pmap->asid));
#elif (ARM_PGSHIFT == 14)
	flush_mmu_tlb_entry(tlbi_addr(sharedpage_vaddr & ~ARM_TT_L2_OFFMASK) | tlbi_asid(pmap->asid));
#endif
}

void
pmap_insert_sharedpage(
	pmap_t pmap)
{
	pmap_insert_sharedpage_internal(pmap);
}

static boolean_t
pmap_is_64bit(
	pmap_t pmap)
{
	return (pmap->is_64bit);
}

#endif

/* ARMTODO -- an implementation that accounts for
 * holes in the physical map, if any.
 */
boolean_t
pmap_valid_page(
	ppnum_t pn) {
	return pa_valid(ptoa(pn));
}

static boolean_t
pmap_is_empty_internal(
	pmap_t pmap,
	vm_map_offset_t va_start,
	vm_map_offset_t va_end)
{
	vm_map_offset_t block_start, block_end;
	tt_entry_t *tte_p;

	if (pmap == NULL) {
		return TRUE;
	}

	if ((pmap != kernel_pmap) && (not_in_kdp)) {
		PMAP_LOCK(pmap);
	}

#if	(__ARM_VMSA__ ==  7)
	if (tte_index(pmap, va_end) >= pmap->tte_index_max) {
		if ((pmap != kernel_pmap) && (not_in_kdp)) {
			PMAP_UNLOCK(pmap);
		}
		return TRUE;
	}

	block_start = va_start;
	tte_p = pmap_tte(pmap, block_start);
	while (block_start < va_end) {
		block_end = (block_start + ARM_TT_L1_SIZE) & ~(ARM_TT_L1_OFFMASK);
		if (block_end > va_end)
			block_end = va_end;

		if ((*tte_p & ARM_TTE_TYPE_MASK) != 0) {
			vm_map_offset_t	offset;
			ppnum_t phys_page = 0;

			for (offset = block_start;
			     offset < block_end;
			     offset += ARM_PGBYTES) {
				// This does a pmap_find_phys() lookup but assumes lock is held
				phys_page = pmap_vtophys(pmap, offset);
				if (phys_page) {
					if ((pmap != kernel_pmap) && (not_in_kdp)) {
						PMAP_UNLOCK(pmap);
					}
					return FALSE;
				}
			}
		}

		block_start = block_end;
		tte_p++;
	}
#else
	block_start = va_start;

	while (block_start < va_end) {
		pt_entry_t     *bpte_p, *epte_p;
		pt_entry_t     *pte_p;

		block_end = (block_start + ARM_TT_L2_SIZE) & ~ARM_TT_L2_OFFMASK;
		if (block_end > va_end)
			block_end = va_end;

		tte_p = pmap_tt2e(pmap, block_start);
		if ((tte_p != PT_ENTRY_NULL)
		     && ((*tte_p & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE)) {

			pte_p = (pt_entry_t *) ttetokv(*tte_p);
			bpte_p = &pte_p[tt3_index(pmap, block_start)];
			epte_p = bpte_p + (((block_end - block_start) & ARM_TT_L3_INDEX_MASK) >> ARM_TT_L3_SHIFT);

			for (pte_p = bpte_p; pte_p < epte_p; pte_p++) {
				if (*pte_p != ARM_PTE_EMPTY) {
					if ((pmap != kernel_pmap) && (not_in_kdp)) {
						PMAP_UNLOCK(pmap);
					}
					return FALSE;
				}
			}
        }
		block_start = block_end;
	}
#endif

	if ((pmap != kernel_pmap) && (not_in_kdp)) {
		PMAP_UNLOCK(pmap);
	}

	return TRUE;
}

boolean_t
pmap_is_empty(
	pmap_t pmap,
	vm_map_offset_t va_start,
	vm_map_offset_t va_end)
{
	return pmap_is_empty_internal(pmap, va_start, va_end);
}

vm_map_offset_t pmap_max_offset(
	boolean_t	is64 __unused,
	unsigned int	option)
{
	vm_map_offset_t	max_offset_ret = 0;

#if defined(__arm64__)
	assert (is64);
	vm_map_offset_t min_max_offset = SHARED_REGION_BASE_ARM64 + SHARED_REGION_SIZE_ARM64 + 0x20000000; // end of shared region + 512MB for various purposes
	if (option == ARM_PMAP_MAX_OFFSET_DEFAULT) {
		max_offset_ret = arm64_pmap_max_offset_default;
	} else if (option == ARM_PMAP_MAX_OFFSET_MIN) {
		max_offset_ret = min_max_offset;
	} else if (option == ARM_PMAP_MAX_OFFSET_MAX) {
		max_offset_ret = MACH_VM_MAX_ADDRESS;
	} else if (option == ARM_PMAP_MAX_OFFSET_DEVICE) {
		if (arm64_pmap_max_offset_default) {
			max_offset_ret = arm64_pmap_max_offset_default;
		} else if (max_mem > 0xC0000000) {
			max_offset_ret = 0x0000000318000000ULL;     // Max offset is 12.375GB for devices with > 3GB of memory
		} else if (max_mem > 0x40000000) {
			max_offset_ret = 0x0000000218000000ULL;     // Max offset is 8.375GB for devices with > 1GB and <= 3GB of memory
		} else {
			max_offset_ret = min_max_offset;
		}
	} else if (option == ARM_PMAP_MAX_OFFSET_JUMBO) {
		if (arm64_pmap_max_offset_default) {
			// Allow the boot-arg to override jumbo size
			max_offset_ret = arm64_pmap_max_offset_default;
		} else {
			max_offset_ret = MACH_VM_MAX_ADDRESS;     // Max offset is MACH_VM_MAX_ADDRESS for pmaps with special "jumbo" blessing
		}
	} else {
		panic("pmap_max_offset illegal option 0x%x\n", option);
	}

	assert(max_offset_ret >= min_max_offset);
	assert(max_offset_ret <= MACH_VM_MAX_ADDRESS);
	return max_offset_ret;
#else
	if (option == ARM_PMAP_MAX_OFFSET_DEFAULT) {
		max_offset_ret = arm_pmap_max_offset_default;
	} else if (option == ARM_PMAP_MAX_OFFSET_MIN) {
		max_offset_ret = 0x66000000;
	} else if (option == ARM_PMAP_MAX_OFFSET_MAX) {
		max_offset_ret = VM_MAX_ADDRESS;
	} else if (option == ARM_PMAP_MAX_OFFSET_DEVICE) {
		if (arm_pmap_max_offset_default) {
			max_offset_ret = arm_pmap_max_offset_default;
		} else if (max_mem > 0x20000000) {
			max_offset_ret = 0x80000000;
		} else {
			max_offset_ret = 0x66000000;
		}
	} else {
		panic("pmap_max_offset illegal option 0x%x\n", option);
	}

	assert(max_offset_ret <= VM_MAX_ADDRESS);
	return max_offset_ret;
#endif
}

#if CONFIG_DTRACE
/*
 * Constrain DTrace copyin/copyout actions
 */
extern kern_return_t dtrace_copyio_preflight(addr64_t);
extern kern_return_t dtrace_copyio_postflight(addr64_t);

kern_return_t dtrace_copyio_preflight(
	__unused addr64_t va)
{
	if (current_map() == kernel_map)
		return KERN_FAILURE;
	else
		return KERN_SUCCESS;
}

kern_return_t dtrace_copyio_postflight(
	__unused addr64_t va)
{
	return KERN_SUCCESS;
}
#endif /* CONFIG_DTRACE */


void
pmap_flush_context_init(__unused pmap_flush_context *pfc)
{
}


void
pmap_flush(
	__unused pmap_flush_context *cpus_to_flush)
{
	/* not implemented yet */
	return;
}

static boolean_t
pmap_query_resident_internal(
	pmap_t			pmap,
	vm_map_address_t	start,
	vm_map_address_t	end,
	mach_vm_size_t		*resident_bytes_p,
	mach_vm_size_t		*compressed_bytes_p)
{
	mach_vm_size_t	resident_bytes = 0;
	mach_vm_size_t	compressed_bytes = 0;

	pt_entry_t     *bpte, *epte;
	pt_entry_t     *pte_p;
	tt_entry_t     *tte_p;

	if (pmap == NULL) {
		return FALSE;
	}

	/* Ensure that this request is valid, and addresses exactly one TTE. */
	assert(!(start % ARM_PGBYTES));
	assert(!(end % ARM_PGBYTES));
	assert(end >= start);
	assert((end - start) <= (PTE_PGENTRIES * ARM_PGBYTES));

	PMAP_LOCK(pmap);
	tte_p = pmap_tte(pmap, start);
	if (tte_p == (tt_entry_t *) NULL) {
		PMAP_UNLOCK(pmap);
		return FALSE;
	}
	if ((*tte_p & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE) {

#if	(__ARM_VMSA__ == 7)
		pte_p = (pt_entry_t *) ttetokv(*tte_p);
		bpte = &pte_p[ptenum(start)];
		epte = bpte + atop(end - start);
#else
		pte_p = (pt_entry_t *) ttetokv(*tte_p);
		bpte = &pte_p[tt3_index(pmap, start)];
		epte = bpte + ((end - start) >> ARM_TT_L3_SHIFT);
#endif

		for (; bpte < epte; bpte++) {
			if (ARM_PTE_IS_COMPRESSED(*bpte)) {
				compressed_bytes += ARM_PGBYTES;
			} else if (pa_valid(pte_to_pa(*bpte))) {
				resident_bytes += ARM_PGBYTES;
			}
		}
	}
	PMAP_UNLOCK(pmap);

	if (compressed_bytes_p) {
		*compressed_bytes_p += compressed_bytes;
	}

	if (resident_bytes_p) {
		*resident_bytes_p += resident_bytes;
	}

	return TRUE;
}

mach_vm_size_t
pmap_query_resident(
	pmap_t			pmap,
	vm_map_address_t	start,
	vm_map_address_t	end,
	mach_vm_size_t		*compressed_bytes_p)
{
	mach_vm_size_t		resident_bytes;
	mach_vm_size_t		compressed_bytes;
	vm_map_address_t	va;


	if (pmap == PMAP_NULL) {
		if (compressed_bytes_p) {
			*compressed_bytes_p = 0;
		}
		return 0;
	}

	resident_bytes = 0;
	compressed_bytes = 0;

	PMAP_TRACE(PMAP_CODE(PMAP__QUERY_RESIDENT) | DBG_FUNC_START,
	           VM_KERNEL_ADDRHIDE(pmap), VM_KERNEL_ADDRHIDE(start),
	           VM_KERNEL_ADDRHIDE(end));

	va = start;
	while (va < end) {
		vm_map_address_t l;

		l = ((va + ARM_TT_TWIG_SIZE) & ~ARM_TT_TWIG_OFFMASK);

		if (l > end)
			l = end;
		if (!pmap_query_resident_internal(pmap, va, l, &resident_bytes, compressed_bytes_p)) {
			break;
		}

		va = l;
	}

	if (compressed_bytes_p) {
		*compressed_bytes_p = compressed_bytes;
	}

	PMAP_TRACE(PMAP_CODE(PMAP__QUERY_RESIDENT) | DBG_FUNC_END,
	           resident_bytes);

	return resident_bytes;
}

#if MACH_ASSERT
extern int pmap_ledgers_panic;
static void
pmap_check_ledgers(
	pmap_t pmap)
{
	ledger_amount_t	bal;
	int		pid;
	char		*procname;
	boolean_t	do_panic;

	if (pmap->pmap_pid == 0) {
		/*
		 * This pmap was not or is no longer fully associated
		 * with a task (e.g. the old pmap after a fork()/exec() or
		 * spawn()).  Its "ledger" still points at a task that is
		 * now using a different (and active) address space, so
		 * we can't check that all the pmap ledgers are balanced here.
		 *
		 * If the "pid" is set, that means that we went through
		 * pmap_set_process() in task_terminate_internal(), so
		 * this task's ledger should not have been re-used and
		 * all the pmap ledgers should be back to 0.
		 */
		return;
	}

	do_panic = FALSE;
	pid = pmap->pmap_pid;
	procname = pmap->pmap_procname;

	pmap_ledgers_drift.num_pmaps_checked++;

	ledger_get_balance(pmap->ledger,
			   task_ledgers.phys_footprint,
			   &bal);
	if (bal != 0) {
#if DEVELOPMENT || DEBUG
//		if (!pmap->footprint_was_suspended)
#endif /* DEVELOPMENT || DEBUG */
		do_panic = TRUE;
		printf("LEDGER BALANCE proc %d (%s) "
		       "\"phys_footprint\" = %lld\n",
		       pid, procname, bal);
		if (bal > 0) {
			pmap_ledgers_drift.phys_footprint_over++;
			pmap_ledgers_drift.phys_footprint_over_total += bal;
			if (bal > pmap_ledgers_drift.phys_footprint_over_max) {
				pmap_ledgers_drift.phys_footprint_over_max = bal;
			}
		} else {
			pmap_ledgers_drift.phys_footprint_under++;
			pmap_ledgers_drift.phys_footprint_under_total += bal;
			if (bal < pmap_ledgers_drift.phys_footprint_under_max) {
				pmap_ledgers_drift.phys_footprint_under_max = bal;
			}
		}
	}
	ledger_get_balance(pmap->ledger,
			   task_ledgers.internal,
			   &bal);
	if (bal != 0) {
		do_panic = TRUE;
		printf("LEDGER BALANCE proc %d (%s) "
		       "\"internal\" = %lld\n",
		       pid, procname, bal);
		if (bal > 0) {
			pmap_ledgers_drift.internal_over++;
			pmap_ledgers_drift.internal_over_total += bal;
			if (bal > pmap_ledgers_drift.internal_over_max) {
				pmap_ledgers_drift.internal_over_max = bal;
			}
		} else {
			pmap_ledgers_drift.internal_under++;
			pmap_ledgers_drift.internal_under_total += bal;
			if (bal < pmap_ledgers_drift.internal_under_max) {
				pmap_ledgers_drift.internal_under_max = bal;
			}
		}
	}
	ledger_get_balance(pmap->ledger,
			   task_ledgers.internal_compressed,
			   &bal);
	if (bal != 0) {
		do_panic = TRUE;
		printf("LEDGER BALANCE proc %d (%s) "
		       "\"internal_compressed\" = %lld\n",
		       pid, procname, bal);
		if (bal > 0) {
			pmap_ledgers_drift.internal_compressed_over++;
			pmap_ledgers_drift.internal_compressed_over_total += bal;
			if (bal > pmap_ledgers_drift.internal_compressed_over_max) {
				pmap_ledgers_drift.internal_compressed_over_max = bal;
			}
		} else {
			pmap_ledgers_drift.internal_compressed_under++;
			pmap_ledgers_drift.internal_compressed_under_total += bal;
			if (bal < pmap_ledgers_drift.internal_compressed_under_max) {
				pmap_ledgers_drift.internal_compressed_under_max = bal;
			}
		}
	}
	ledger_get_balance(pmap->ledger,
			   task_ledgers.iokit_mapped,
			   &bal);
	if (bal != 0) {
		do_panic = TRUE;
		printf("LEDGER BALANCE proc %d (%s) "
		       "\"iokit_mapped\" = %lld\n",
		       pid, procname, bal);
		if (bal > 0) {
			pmap_ledgers_drift.iokit_mapped_over++;
			pmap_ledgers_drift.iokit_mapped_over_total += bal;
			if (bal > pmap_ledgers_drift.iokit_mapped_over_max) {
				pmap_ledgers_drift.iokit_mapped_over_max = bal;
			}
		} else {
			pmap_ledgers_drift.iokit_mapped_under++;
			pmap_ledgers_drift.iokit_mapped_under_total += bal;
			if (bal < pmap_ledgers_drift.iokit_mapped_under_max) {
				pmap_ledgers_drift.iokit_mapped_under_max = bal;
			}
		}
	}
	ledger_get_balance(pmap->ledger,
			   task_ledgers.alternate_accounting,
			   &bal);
	if (bal != 0) {
		do_panic = TRUE;
		printf("LEDGER BALANCE proc %d (%s) "
		       "\"alternate_accounting\" = %lld\n",
		       pid, procname, bal);
		if (bal > 0) {
			pmap_ledgers_drift.alternate_accounting_over++;
			pmap_ledgers_drift.alternate_accounting_over_total += bal;
			if (bal > pmap_ledgers_drift.alternate_accounting_over_max) {
				pmap_ledgers_drift.alternate_accounting_over_max = bal;
			}
		} else {
			pmap_ledgers_drift.alternate_accounting_under++;
			pmap_ledgers_drift.alternate_accounting_under_total += bal;
			if (bal < pmap_ledgers_drift.alternate_accounting_under_max) {
				pmap_ledgers_drift.alternate_accounting_under_max = bal;
			}
		}
	}
	ledger_get_balance(pmap->ledger,
			   task_ledgers.alternate_accounting_compressed,
			   &bal);
	if (bal != 0) {
		do_panic = TRUE;
		printf("LEDGER BALANCE proc %d (%s) "
		       "\"alternate_accounting_compressed\" = %lld\n",
		       pid, procname, bal);
		if (bal > 0) {
			pmap_ledgers_drift.alternate_accounting_compressed_over++;
			pmap_ledgers_drift.alternate_accounting_compressed_over_total += bal;
			if (bal > pmap_ledgers_drift.alternate_accounting_compressed_over_max) {
				pmap_ledgers_drift.alternate_accounting_compressed_over_max = bal;
			}
		} else {
			pmap_ledgers_drift.alternate_accounting_compressed_under++;
			pmap_ledgers_drift.alternate_accounting_compressed_under_total += bal;
			if (bal < pmap_ledgers_drift.alternate_accounting_compressed_under_max) {
				pmap_ledgers_drift.alternate_accounting_compressed_under_max = bal;
			}
		}
	}
	ledger_get_balance(pmap->ledger,
			   task_ledgers.page_table,
			   &bal);
	if (bal != 0) {
		do_panic = TRUE;
		printf("LEDGER BALANCE proc %d (%s) "
		       "\"page_table\" = %lld\n",
		       pid, procname, bal);
		if (bal > 0) {
			pmap_ledgers_drift.page_table_over++;
			pmap_ledgers_drift.page_table_over_total += bal;
			if (bal > pmap_ledgers_drift.page_table_over_max) {
				pmap_ledgers_drift.page_table_over_max = bal;
			}
		} else {
			pmap_ledgers_drift.page_table_under++;
			pmap_ledgers_drift.page_table_under_total += bal;
			if (bal < pmap_ledgers_drift.page_table_under_max) {
				pmap_ledgers_drift.page_table_under_max = bal;
			}
		}
	}
	ledger_get_balance(pmap->ledger,
			   task_ledgers.purgeable_volatile,
			   &bal);
	if (bal != 0) {
		do_panic = TRUE;
		printf("LEDGER BALANCE proc %d (%s) "
		       "\"purgeable_volatile\" = %lld\n",
		       pid, procname, bal);
		if (bal > 0) {
			pmap_ledgers_drift.purgeable_volatile_over++;
			pmap_ledgers_drift.purgeable_volatile_over_total += bal;
			if (bal > pmap_ledgers_drift.purgeable_volatile_over_max) {
				pmap_ledgers_drift.purgeable_volatile_over_max = bal;
			}
		} else {
			pmap_ledgers_drift.purgeable_volatile_under++;
			pmap_ledgers_drift.purgeable_volatile_under_total += bal;
			if (bal < pmap_ledgers_drift.purgeable_volatile_under_max) {
				pmap_ledgers_drift.purgeable_volatile_under_max = bal;
			}
		}
	}
	ledger_get_balance(pmap->ledger,
			   task_ledgers.purgeable_nonvolatile,
			   &bal);
	if (bal != 0) {
		do_panic = TRUE;
		printf("LEDGER BALANCE proc %d (%s) "
		       "\"purgeable_nonvolatile\" = %lld\n",
		       pid, procname, bal);
		if (bal > 0) {
			pmap_ledgers_drift.purgeable_nonvolatile_over++;
			pmap_ledgers_drift.purgeable_nonvolatile_over_total += bal;
			if (bal > pmap_ledgers_drift.purgeable_nonvolatile_over_max) {
				pmap_ledgers_drift.purgeable_nonvolatile_over_max = bal;
			}
		} else {
			pmap_ledgers_drift.purgeable_nonvolatile_under++;
			pmap_ledgers_drift.purgeable_nonvolatile_under_total += bal;
			if (bal < pmap_ledgers_drift.purgeable_nonvolatile_under_max) {
				pmap_ledgers_drift.purgeable_nonvolatile_under_max = bal;
			}
		}
	}
	ledger_get_balance(pmap->ledger,
			   task_ledgers.purgeable_volatile_compressed,
			   &bal);
	if (bal != 0) {
		do_panic = TRUE;
		printf("LEDGER BALANCE proc %d (%s) "
		       "\"purgeable_volatile_compressed\" = %lld\n",
		       pid, procname, bal);
		if (bal > 0) {
			pmap_ledgers_drift.purgeable_volatile_compressed_over++;
			pmap_ledgers_drift.purgeable_volatile_compressed_over_total += bal;
			if (bal > pmap_ledgers_drift.purgeable_volatile_compressed_over_max) {
				pmap_ledgers_drift.purgeable_volatile_compressed_over_max = bal;
			}
		} else {
			pmap_ledgers_drift.purgeable_volatile_compressed_under++;
			pmap_ledgers_drift.purgeable_volatile_compressed_under_total += bal;
			if (bal < pmap_ledgers_drift.purgeable_volatile_compressed_under_max) {
				pmap_ledgers_drift.purgeable_volatile_compressed_under_max = bal;
			}
		}
	}
	ledger_get_balance(pmap->ledger,
			   task_ledgers.purgeable_nonvolatile_compressed,
			   &bal);
	if (bal != 0) {
		do_panic = TRUE;
		printf("LEDGER BALANCE proc %d (%s) "
		       "\"purgeable_nonvolatile_compressed\" = %lld\n",
		       pid, procname, bal);
		if (bal > 0) {
			pmap_ledgers_drift.purgeable_nonvolatile_compressed_over++;
			pmap_ledgers_drift.purgeable_nonvolatile_compressed_over_total += bal;
			if (bal > pmap_ledgers_drift.purgeable_nonvolatile_compressed_over_max) {
				pmap_ledgers_drift.purgeable_nonvolatile_compressed_over_max = bal;
			}
		} else {
			pmap_ledgers_drift.purgeable_nonvolatile_compressed_under++;
			pmap_ledgers_drift.purgeable_nonvolatile_compressed_under_total += bal;
			if (bal < pmap_ledgers_drift.purgeable_nonvolatile_compressed_under_max) {
				pmap_ledgers_drift.purgeable_nonvolatile_compressed_under_max = bal;
			}
		}
	}

	if (do_panic) {
		if (pmap_ledgers_panic &&
		    pmap->pmap_stats_assert) {
			panic("pmap_destroy(%p) %d[%s] has imbalanced ledgers\n",
			      pmap, pid, procname);
		} else {
			printf("pmap_destroy(%p) %d[%s] has imbalanced ledgers\n",
			       pmap, pid, procname);
		}
	}

	PMAP_STATS_ASSERTF(pmap->stats.resident_count == 0, pmap, "stats.resident_count %d", pmap->stats.resident_count);
#if 00
	PMAP_STATS_ASSERTF(pmap->stats.wired_count == 0, pmap, "stats.wired_count %d", pmap->stats.wired_count);
#endif
	PMAP_STATS_ASSERTF(pmap->stats.device == 0, pmap, "stats.device %d", pmap->stats.device);
	PMAP_STATS_ASSERTF(pmap->stats.internal == 0, pmap, "stats.internal %d", pmap->stats.internal);
	PMAP_STATS_ASSERTF(pmap->stats.external == 0, pmap, "stats.external %d", pmap->stats.external);
	PMAP_STATS_ASSERTF(pmap->stats.reusable == 0, pmap, "stats.reusable %d", pmap->stats.reusable);
	PMAP_STATS_ASSERTF(pmap->stats.compressed == 0, pmap, "stats.compressed %lld", pmap->stats.compressed);
}
#endif /* MACH_ASSERT */

void	pmap_advise_pagezero_range(__unused pmap_t p, __unused uint64_t a) {
}


#if CONFIG_PGTRACE
#define PROF_START  uint64_t t, nanot;\
                    t = mach_absolute_time();

#define PROF_END    absolutetime_to_nanoseconds(mach_absolute_time()-t, &nanot);\
                    kprintf("%s: took %llu ns\n", __func__, nanot);

#define PMAP_PGTRACE_LOCK(p)                                \
    do {                                                    \
        *(p) = ml_set_interrupts_enabled(false);            \
        if (simple_lock_try(&(pmap_pgtrace.lock))) break;   \
        ml_set_interrupts_enabled(*(p));                    \
    } while (true)

#define PMAP_PGTRACE_UNLOCK(p)                  \
    do {                                        \
        simple_unlock(&(pmap_pgtrace.lock));    \
        ml_set_interrupts_enabled(*(p));        \
    } while (0)

#define PGTRACE_WRITE_PTE(pte_p, pte_entry) \
    do {                                    \
        *(pte_p) = (pte_entry);             \
        FLUSH_PTE(pte_p);                   \
    } while (0)

#define PGTRACE_MAX_MAP 16      // maximum supported va to same pa

typedef enum {
    UNDEFINED,
    PA_UNDEFINED,
    VA_UNDEFINED,
    DEFINED
} pmap_pgtrace_page_state_t;

typedef struct {
    queue_chain_t   chain;

    /*
        pa              - pa
        maps            - list of va maps to upper pa
        map_pool        - map pool
        map_waste       - waste can
        state           - state
    */
    pmap_paddr_t    pa;
    queue_head_t    maps;
    queue_head_t    map_pool;
    queue_head_t    map_waste;
    pmap_pgtrace_page_state_t    state;
} pmap_pgtrace_page_t;

static struct {
    /*
        pages       - list of tracing page info
    */
    queue_head_t    pages;
    decl_simple_lock_data(, lock);
} pmap_pgtrace = {};

static void pmap_pgtrace_init(void)
{
    queue_init(&(pmap_pgtrace.pages));
    simple_lock_init(&(pmap_pgtrace.lock), 0);

    boolean_t enabled;

    if (PE_parse_boot_argn("pgtrace", &enabled, sizeof(enabled))) {
        pgtrace_enabled = enabled;
    }
}

// find a page with given pa - pmap_pgtrace should be locked
inline static pmap_pgtrace_page_t *pmap_pgtrace_find_page(pmap_paddr_t pa)
{
    queue_head_t *q = &(pmap_pgtrace.pages);
    pmap_pgtrace_page_t *p;

    queue_iterate(q, p, pmap_pgtrace_page_t *, chain) {
        if (p->state == UNDEFINED) {
            continue;
        }
        if (p->state == PA_UNDEFINED) {
            continue;
        }
        if (p->pa == pa) {
            return p;
        }
    }

    return NULL;
}

// enter clone of given pmap, va page and range - pmap should be locked
static bool pmap_pgtrace_enter_clone(pmap_t pmap, vm_map_offset_t va_page, vm_map_offset_t start, vm_map_offset_t end)
{
    bool ints;
    queue_head_t *q = &(pmap_pgtrace.pages);
    pmap_paddr_t pa_page;
    pt_entry_t *ptep, *cptep;
    pmap_pgtrace_page_t *p;
    bool found = false;

    PMAP_ASSERT_LOCKED(pmap);
    assert(va_page == arm_trunc_page(va_page));

    PMAP_PGTRACE_LOCK(&ints);

    ptep = pmap_pte(pmap, va_page);

    // target pte should exist
    if (!ptep || !(*ptep & ARM_PTE_TYPE_VALID)) {
        PMAP_PGTRACE_UNLOCK(&ints);
        return false;
    }

    queue_head_t *mapq;
    queue_head_t *mappool;
    pmap_pgtrace_map_t *map = NULL;

    pa_page = pte_to_pa(*ptep);

    // find if we have a page info defined for this
    queue_iterate(q, p, pmap_pgtrace_page_t *, chain) {
        mapq = &(p->maps);
        mappool = &(p->map_pool);

        switch (p->state) {
        case PA_UNDEFINED:
            queue_iterate(mapq, map, pmap_pgtrace_map_t *, chain) {
                if (map->cloned == false && map->pmap == pmap && map->ova == va_page) {
                    p->pa = pa_page;
                    map->range.start = start;
                    map->range.end = end;
                    found = true;
                    break;
                }
            }
            break;

        case VA_UNDEFINED:
            if (p->pa != pa_page) {
                break;
            }
            queue_iterate(mapq, map, pmap_pgtrace_map_t *, chain) {
                if (map->cloned == false) {
                    map->pmap = pmap;
                    map->ova = va_page;
                    map->range.start = start;
                    map->range.end = end;
                    found = true;
                    break;
                }
            }
            break;

        case DEFINED:
            if (p->pa != pa_page) {
                break;
            }
            queue_iterate(mapq, map, pmap_pgtrace_map_t *, chain) {
                if (map->cloned == true && map->pmap == pmap && map->ova == va_page) {
                    kprintf("%s: skip existing mapping at va=%llx\n", __func__, va_page);
                    break;
                } else if (map->cloned == true && map->pmap == kernel_pmap && map->cva[1] == va_page) {
                    kprintf("%s: skip clone mapping at va=%llx\n", __func__, va_page);
                    break;
                } else if (map->cloned == false && map->pmap == pmap && map->ova == va_page) {
                    // range should be already defined as well
                    found = true;
                    break;
                }
            }
            break;

        default:
            panic("invalid state p->state=%x\n", p->state);
        }

        if (found == true) {
            break;
        }
    }

    // do not clone if no page info found
    if (found == false) {
        PMAP_PGTRACE_UNLOCK(&ints);
        return false;
    }

    // copy pre, target and post ptes to clone ptes
    for (int i = 0; i < 3; i++) {
        ptep = pmap_pte(pmap, va_page + (i-1)*ARM_PGBYTES);
        cptep = pmap_pte(kernel_pmap, map->cva[i]);
        assert(cptep != NULL);
        if (ptep == NULL) {
            PGTRACE_WRITE_PTE(cptep, (pt_entry_t)NULL);
        } else {
            PGTRACE_WRITE_PTE(cptep, *ptep);
        }
        PMAP_UPDATE_TLBS(kernel_pmap, map->cva[i], map->cva[i]+ARM_PGBYTES);
    }

    // get ptes for original and clone
    ptep = pmap_pte(pmap, va_page);
    cptep = pmap_pte(kernel_pmap, map->cva[1]);

    // invalidate original pte and mark it as a pgtrace page
    PGTRACE_WRITE_PTE(ptep, (*ptep | ARM_PTE_PGTRACE) & ~ARM_PTE_TYPE_VALID);
    PMAP_UPDATE_TLBS(pmap, map->ova, map->ova+ARM_PGBYTES);

    map->cloned = true;
    p->state = DEFINED;

    kprintf("%s: pa_page=%llx va_page=%llx cva[1]=%llx pmap=%p ptep=%p cptep=%p\n", __func__, pa_page, va_page, map->cva[1], pmap, ptep, cptep);

    PMAP_PGTRACE_UNLOCK(&ints);

    return true;
}

// This function removes trace bit and validate pte if applicable. Pmap must be locked.
static void pmap_pgtrace_remove_clone(pmap_t pmap, pmap_paddr_t pa, vm_map_offset_t va)
{
    bool ints, found = false;
    pmap_pgtrace_page_t *p;
    pt_entry_t *ptep;

    PMAP_PGTRACE_LOCK(&ints);

    // we must have this page info
    p = pmap_pgtrace_find_page(pa);
    if (p == NULL) {
        goto unlock_exit;
    }

    // find matching map
    queue_head_t *mapq = &(p->maps);
    queue_head_t *mappool = &(p->map_pool);
    pmap_pgtrace_map_t *map;

    queue_iterate(mapq, map, pmap_pgtrace_map_t *, chain) {
        if (map->pmap == pmap && map->ova == va) {
            found = true;
            break;
        }
    }

    if (!found) {
        goto unlock_exit;
    }

    if (map->cloned == true) {
        // Restore back the pte to original state
        ptep = pmap_pte(pmap, map->ova);
        assert(ptep);
        PGTRACE_WRITE_PTE(ptep, *ptep | ARM_PTE_TYPE_VALID);
        PMAP_UPDATE_TLBS(pmap, va, va+ARM_PGBYTES);

        // revert clone pages
        for (int i = 0; i < 3; i++) {
            ptep = pmap_pte(kernel_pmap, map->cva[i]);
            assert(ptep != NULL);
            PGTRACE_WRITE_PTE(ptep, map->cva_spte[i]);
            PMAP_UPDATE_TLBS(kernel_pmap, map->cva[i], map->cva[i]+ARM_PGBYTES);
        }
    }

    queue_remove(mapq, map, pmap_pgtrace_map_t *, chain);
    map->pmap = NULL;
    map->ova = (vm_map_offset_t)NULL;
    map->cloned = false;
    queue_enter_first(mappool, map, pmap_pgtrace_map_t *, chain);

    kprintf("%s: p=%p pa=%llx va=%llx\n", __func__, p, pa, va);

unlock_exit:
    PMAP_PGTRACE_UNLOCK(&ints);
}

// remove all clones of given pa - pmap must be locked
static void pmap_pgtrace_remove_all_clone(pmap_paddr_t pa)
{
    bool ints;
    pmap_pgtrace_page_t *p;
    pt_entry_t *ptep;

    PMAP_PGTRACE_LOCK(&ints);

    // we must have this page info
    p = pmap_pgtrace_find_page(pa);
    if (p == NULL) {
        PMAP_PGTRACE_UNLOCK(&ints);
        return;
    }

    queue_head_t *mapq = &(p->maps);
    queue_head_t *mappool = &(p->map_pool);
    queue_head_t *mapwaste = &(p->map_waste);
    pmap_pgtrace_map_t *map;

    // move maps to waste
    while (!queue_empty(mapq)) {
        queue_remove_first(mapq, map, pmap_pgtrace_map_t *, chain);
        queue_enter_first(mapwaste, map, pmap_pgtrace_map_t*, chain);
    }

    PMAP_PGTRACE_UNLOCK(&ints);

    // sanitize maps in waste
    queue_iterate(mapwaste, map, pmap_pgtrace_map_t *, chain) {
        if (map->cloned == true) {
            PMAP_LOCK(map->pmap);

            // restore back original pte
            ptep = pmap_pte(map->pmap, map->ova);
            assert(ptep);
            PGTRACE_WRITE_PTE(ptep, *ptep | ARM_PTE_TYPE_VALID);
            PMAP_UPDATE_TLBS(map->pmap, map->ova, map->ova+ARM_PGBYTES);

            // revert clone ptes
            for (int i = 0; i < 3; i++) {
                ptep = pmap_pte(kernel_pmap, map->cva[i]);
                assert(ptep != NULL);
                PGTRACE_WRITE_PTE(ptep, map->cva_spte[i]);
                PMAP_UPDATE_TLBS(kernel_pmap, map->cva[i], map->cva[i]+ARM_PGBYTES);
            }

            PMAP_UNLOCK(map->pmap);
        }

        map->pmap = NULL;
        map->ova = (vm_map_offset_t)NULL;
        map->cloned = false;
    }

    PMAP_PGTRACE_LOCK(&ints);

    // recycle maps back to map_pool
    while (!queue_empty(mapwaste)) {
        queue_remove_first(mapwaste, map, pmap_pgtrace_map_t *, chain);
        queue_enter_first(mappool, map, pmap_pgtrace_map_t*, chain);
    }

    PMAP_PGTRACE_UNLOCK(&ints);
}

inline static void pmap_pgtrace_get_search_space(pmap_t pmap, vm_map_offset_t *startp, vm_map_offset_t *endp)
{
    uint64_t tsz;
    vm_map_offset_t end;

    if (pmap == kernel_pmap) {
        tsz = (get_tcr() >> TCR_T1SZ_SHIFT) & TCR_TSZ_MASK;
        *startp = MAX(VM_MIN_KERNEL_ADDRESS, (UINT64_MAX >> (64-tsz)) << (64-tsz));
        *endp = VM_MAX_KERNEL_ADDRESS;
    } else {
        tsz = (get_tcr() >> TCR_T0SZ_SHIFT) & TCR_TSZ_MASK;
        if (tsz == 64) {
            end = 0;
        } else {
            end = ((uint64_t)1 << (64-tsz)) - 1;
        }

        *startp = 0;
        *endp = end;
    }

    assert(*endp > *startp);

    return;
}

// has pa mapped in given pmap? then clone it
static uint64_t pmap_pgtrace_clone_from_pa(pmap_t pmap, pmap_paddr_t pa, vm_map_offset_t start_offset, vm_map_offset_t end_offset) {
    uint64_t ret = 0;
    vm_map_offset_t min, max;
    vm_map_offset_t cur_page, end_page;
    pt_entry_t *ptep;
    tt_entry_t *ttep;
    tt_entry_t tte;

    pmap_pgtrace_get_search_space(pmap, &min, &max);

    cur_page = arm_trunc_page(min);
    end_page = arm_trunc_page(max);
    while (cur_page <= end_page) {
        vm_map_offset_t add = 0;

        PMAP_LOCK(pmap);

        // skip uninterested space
        if (pmap == kernel_pmap &&
            ((vm_kernel_base <= cur_page && cur_page < vm_kernel_top) ||
             (vm_kext_base <= cur_page && cur_page < vm_kext_top))) {
            add = ARM_PGBYTES;
            goto unlock_continue;
        }

#if __ARM64_TWO_LEVEL_PMAP__
        // check whether we can skip l2
        ttep = pmap_tt2e(pmap, cur_page);
        assert(ttep);
        tte = *ttep;
#else
        // check whether we can skip l1
        ttep = pmap_tt1e(pmap, cur_page);
        assert(ttep);
        tte = *ttep;
        if ((tte & (ARM_TTE_TYPE_MASK | ARM_TTE_VALID)) != (ARM_TTE_TYPE_TABLE | ARM_TTE_VALID)) {
            add = ARM_TT_L1_SIZE;
            goto unlock_continue;
        }

        // how about l2
        tte = ((tt_entry_t*) phystokv(tte & ARM_TTE_TABLE_MASK))[tt2_index(pmap, cur_page)];
#endif
        if ((tte & (ARM_TTE_TYPE_MASK | ARM_TTE_VALID)) != (ARM_TTE_TYPE_TABLE | ARM_TTE_VALID)) {
            add = ARM_TT_L2_SIZE;
            goto unlock_continue;
        }

        // ptep finally
        ptep = &(((pt_entry_t*) phystokv(tte & ARM_TTE_TABLE_MASK))[tt3_index(pmap, cur_page)]);
        if (ptep == PT_ENTRY_NULL) {
            add = ARM_TT_L3_SIZE;
            goto unlock_continue;
        }

        if (arm_trunc_page(pa) == pte_to_pa(*ptep)) {
            if (pmap_pgtrace_enter_clone(pmap, cur_page, start_offset, end_offset) == true) {
                ret++;
            }
        }

        add = ARM_PGBYTES;

unlock_continue:
        PMAP_UNLOCK(pmap);

        //overflow
        if (cur_page + add < cur_page) {
            break;
        }

        cur_page += add;
    }


    return ret;
}

// search pv table and clone vas of given pa
static uint64_t pmap_pgtrace_clone_from_pvtable(pmap_paddr_t pa, vm_map_offset_t start_offset, vm_map_offset_t end_offset)
{
    uint64_t ret = 0;
    unsigned long pai;
    pv_entry_t **pvh;
    pt_entry_t *ptep;
    pmap_t pmap;

    typedef struct {
        queue_chain_t chain;
        pmap_t pmap;
        vm_map_offset_t va;
    } pmap_va_t;

    queue_head_t pmapvaq;
    pmap_va_t *pmapva;

    queue_init(&pmapvaq);

    pai = pa_index(pa);
    LOCK_PVH(pai);
    pvh = pai_to_pvh(pai);

    // collect pmap/va pair from pvh
    if (pvh_test_type(pvh, PVH_TYPE_PTEP)) {
        ptep = pvh_ptep(pvh);
        pmap = ptep_get_pmap(ptep);

        pmapva = (pmap_va_t *)kalloc(sizeof(pmap_va_t));
        pmapva->pmap = pmap;
        pmapva->va = ptep_get_va(ptep);

        queue_enter_first(&pmapvaq, pmapva, pmap_va_t *, chain);

    } else if  (pvh_test_type(pvh, PVH_TYPE_PVEP)) {
        pv_entry_t *pvep;

        pvep = pvh_list(pvh);
        while (pvep) {
            ptep = pve_get_ptep(pvep);
            pmap = ptep_get_pmap(ptep);

            pmapva = (pmap_va_t *)kalloc(sizeof(pmap_va_t));
            pmapva->pmap = pmap;
            pmapva->va = ptep_get_va(ptep);

            queue_enter_first(&pmapvaq, pmapva, pmap_va_t *, chain);

            pvep = PVE_NEXT_PTR(pve_next(pvep));
        }
    }

    UNLOCK_PVH(pai);

    // clone them while making sure mapping still exists
    queue_iterate(&pmapvaq, pmapva, pmap_va_t *, chain) {
        PMAP_LOCK(pmapva->pmap);
        ptep = pmap_pte(pmapva->pmap, pmapva->va);
        if (pte_to_pa(*ptep) == pa) {
            if (pmap_pgtrace_enter_clone(pmapva->pmap, pmapva->va, start_offset, end_offset) == true) {
                ret++;
            }
        }
        PMAP_UNLOCK(pmapva->pmap);

        kfree(pmapva, sizeof(pmap_va_t));
    }

    return ret;
}

// allocate a page info
static pmap_pgtrace_page_t *pmap_pgtrace_alloc_page(void)
{
    pmap_pgtrace_page_t *p;
    queue_head_t *mapq;
    queue_head_t *mappool;
    queue_head_t *mapwaste;
    pmap_pgtrace_map_t *map;

    p = kalloc(sizeof(pmap_pgtrace_page_t));
    assert(p);

    p->state = UNDEFINED;

    mapq = &(p->maps);
    mappool = &(p->map_pool);
    mapwaste = &(p->map_waste);
    queue_init(mapq);
    queue_init(mappool);
    queue_init(mapwaste);

    for (int i = 0; i < PGTRACE_MAX_MAP; i++) {
        vm_map_offset_t newcva;
        pt_entry_t *cptep;
        kern_return_t kr;
        vm_map_entry_t entry;

        // get a clone va
        vm_object_reference(kernel_object);
        kr = vm_map_find_space(kernel_map, &newcva, vm_map_round_page(3*ARM_PGBYTES, PAGE_MASK), 0, 0, VM_MAP_KERNEL_FLAGS_NONE, VM_KERN_MEMORY_DIAG, &entry);
        if (kr != KERN_SUCCESS) {
            panic("%s VM couldn't find any space kr=%d\n", __func__, kr);
        }
        VME_OBJECT_SET(entry, kernel_object);
        VME_OFFSET_SET(entry, newcva);
        vm_map_unlock(kernel_map);

        // fill default clone page info and add to pool
        map = kalloc(sizeof(pmap_pgtrace_map_t));
        for (int j = 0; j < 3; j ++) {
            vm_map_offset_t addr = newcva + j * ARM_PGBYTES;

            // pre-expand pmap while preemption enabled
            kr = pmap_expand(kernel_pmap, addr, 0, PMAP_TT_MAX_LEVEL);
            if (kr != KERN_SUCCESS) {
                panic("%s: pmap_expand(kernel_pmap, addr=%llx) returns kr=%d\n", __func__, addr, kr);
            }

            cptep = pmap_pte(kernel_pmap, addr);
            assert(cptep != NULL);

            map->cva[j] = addr;
            map->cva_spte[j] = *cptep;
        }
        map->range.start = map->range.end = 0;
        map->cloned = false;
        queue_enter_first(mappool, map, pmap_pgtrace_map_t *, chain);
    }

    return p;
}

// free a page info
static void pmap_pgtrace_free_page(pmap_pgtrace_page_t *p)
{
    queue_head_t *mapq;
    queue_head_t *mappool;
    queue_head_t *mapwaste;
    pmap_pgtrace_map_t *map;

    assert(p);

    mapq = &(p->maps);
    mappool = &(p->map_pool);
    mapwaste = &(p->map_waste);

    while (!queue_empty(mapq)) {
        queue_remove_first(mapq, map, pmap_pgtrace_map_t *, chain);
        kfree(map, sizeof(pmap_pgtrace_map_t));
    }

    while (!queue_empty(mappool)) {
        queue_remove_first(mappool, map, pmap_pgtrace_map_t *, chain);
        kfree(map, sizeof(pmap_pgtrace_map_t));
    }

    while (!queue_empty(mapwaste)) {
        queue_remove_first(mapwaste, map, pmap_pgtrace_map_t *, chain);
        kfree(map, sizeof(pmap_pgtrace_map_t));
    }

    kfree(p, sizeof(pmap_pgtrace_page_t));
}

// construct page infos with the given address range
int pmap_pgtrace_add_page(pmap_t pmap, vm_map_offset_t start, vm_map_offset_t end)
{
    int ret = 0;
    pt_entry_t *ptep;
    queue_head_t *q = &(pmap_pgtrace.pages);
    bool ints;
    vm_map_offset_t cur_page, end_page;

    if (start > end) {
        kprintf("%s: invalid start=%llx > end=%llx\n", __func__, start, end);
        return -1;
    }

    PROF_START

    // add each page in given range
    cur_page = arm_trunc_page(start);
    end_page = arm_trunc_page(end);
    while (cur_page <= end_page) {
        pmap_paddr_t pa_page = 0;
        uint64_t num_cloned = 0;
        pmap_pgtrace_page_t *p = NULL, *newp;
        bool free_newp = true;
        pmap_pgtrace_page_state_t state;

        // do all allocations outside of spinlocks
        newp = pmap_pgtrace_alloc_page();

        // keep lock orders in pmap, kernel_pmap and pgtrace lock
        if (pmap != NULL) {
            PMAP_LOCK(pmap);
        }
        if (pmap != kernel_pmap) {
            PMAP_LOCK(kernel_pmap);
        }

        // addresses are physical if pmap is null
        if (pmap == NULL) {
            ptep = NULL;
            pa_page = cur_page;
            state = VA_UNDEFINED;
        } else {
            ptep = pmap_pte(pmap, cur_page);
            if (ptep != NULL) {
                pa_page = pte_to_pa(*ptep);
                state = DEFINED;
            } else {
                state = PA_UNDEFINED;
            }
        }

        // search if we have a page info already
        PMAP_PGTRACE_LOCK(&ints);
        if (state != PA_UNDEFINED) {
            p = pmap_pgtrace_find_page(pa_page);
        }

        // add pre-allocated page info if nothing found
        if (p == NULL) {
            queue_enter_first(q, newp, pmap_pgtrace_page_t *, chain);
            p = newp;
            free_newp = false;
        }

        // now p points what we want
        p->state = state;

        queue_head_t *mapq = &(p->maps);
        queue_head_t *mappool = &(p->map_pool);
        pmap_pgtrace_map_t *map;
        vm_map_offset_t start_offset, end_offset;

        // calculate trace offsets in the page
        if (cur_page > start) {
            start_offset = 0;
        } else {
            start_offset = start-cur_page;
        }
        if (cur_page == end_page) {
            end_offset = end-end_page;
        } else {
            end_offset = ARM_PGBYTES-1;
        }

        kprintf("%s: pmap=%p cur_page=%llx ptep=%p state=%d start_offset=%llx end_offset=%llx\n", __func__, pmap, cur_page, ptep, state, start_offset, end_offset);

        // fill map info
        assert(!queue_empty(mappool));
        queue_remove_first(mappool, map, pmap_pgtrace_map_t *, chain);
        if (p->state == PA_UNDEFINED) {
            map->pmap = pmap;
            map->ova = cur_page;
            map->range.start = start_offset;
            map->range.end = end_offset;
        } else if (p->state == VA_UNDEFINED) {
            p->pa = pa_page;
            map->range.start = start_offset;
            map->range.end = end_offset;
        } else if (p->state == DEFINED) {
            p->pa = pa_page;
            map->pmap = pmap;
            map->ova = cur_page;
            map->range.start = start_offset;
            map->range.end = end_offset;
        } else {
            panic("invalid p->state=%d\n", p->state);
        }

        // not cloned yet
        map->cloned = false;
        queue_enter(mapq, map, pmap_pgtrace_map_t *, chain);

        // unlock locks
        PMAP_PGTRACE_UNLOCK(&ints);
        if (pmap != kernel_pmap) {
            PMAP_UNLOCK(kernel_pmap);
        }
        if (pmap != NULL) {
            PMAP_UNLOCK(pmap);
        }

        // now clone it
        if (pa_valid(pa_page)) {
            num_cloned = pmap_pgtrace_clone_from_pvtable(pa_page, start_offset, end_offset);
        }
        if (pmap == NULL) {
            num_cloned += pmap_pgtrace_clone_from_pa(kernel_pmap, pa_page, start_offset, end_offset);
        } else {
            num_cloned += pmap_pgtrace_clone_from_pa(pmap, pa_page, start_offset, end_offset);
        }

        // free pre-allocations if we didn't add it to the q
        if (free_newp) {
            pmap_pgtrace_free_page(newp);
        }

        if (num_cloned == 0) {
            kprintf("%s: no mapping found for pa_page=%llx but will be added when a page entered\n", __func__, pa_page);
        }

        ret += num_cloned;

        // overflow
        if (cur_page + ARM_PGBYTES < cur_page) {
            break;
        } else {
            cur_page += ARM_PGBYTES;
        }
    }

    PROF_END

    return ret;
}

// delete page infos for given address range
int pmap_pgtrace_delete_page(pmap_t pmap, vm_map_offset_t start, vm_map_offset_t end)
{
    int ret = 0;
    bool ints;
    queue_head_t *q = &(pmap_pgtrace.pages);
    pmap_pgtrace_page_t *p;
    vm_map_offset_t cur_page, end_page;

    kprintf("%s start=%llx end=%llx\n", __func__, start, end);

    PROF_START

    pt_entry_t *ptep;
    pmap_paddr_t pa_page;

    // remove page info from start to end
    cur_page = arm_trunc_page(start);
    end_page = arm_trunc_page(end);
    while (cur_page <= end_page) {
        p = NULL;

        if (pmap == NULL) {
            pa_page = cur_page;
        } else {
            PMAP_LOCK(pmap);
            ptep = pmap_pte(pmap, cur_page);
            if (ptep == NULL) {
                PMAP_UNLOCK(pmap);
                goto cont;
            }
            pa_page = pte_to_pa(*ptep);
            PMAP_UNLOCK(pmap);
        }

        // remove all clones and validate
        pmap_pgtrace_remove_all_clone(pa_page);

        // find page info and delete
        PMAP_PGTRACE_LOCK(&ints);
        p = pmap_pgtrace_find_page(pa_page);
        if (p != NULL) {
            queue_remove(q, p, pmap_pgtrace_page_t *, chain);
            ret++;
        }
        PMAP_PGTRACE_UNLOCK(&ints);

        // free outside of locks
        if (p != NULL) {
            pmap_pgtrace_free_page(p);
        }

cont:
        // overflow
        if (cur_page + ARM_PGBYTES < cur_page) {
            break;
        } else {
            cur_page += ARM_PGBYTES;
        }
    }

    PROF_END

    return ret;
}

kern_return_t pmap_pgtrace_fault(pmap_t pmap, vm_map_offset_t va, arm_saved_state_t *ss)
{
    pt_entry_t *ptep;
    pgtrace_run_result_t res;
    pmap_pgtrace_page_t *p;
    bool ints, found = false;
    pmap_paddr_t pa;

    // Quick check if we are interested
    ptep = pmap_pte(pmap, va);
    if (!ptep || !(*ptep & ARM_PTE_PGTRACE)) {
        return KERN_FAILURE;
    }

    PMAP_PGTRACE_LOCK(&ints);

    // Check again since access is serialized
    ptep = pmap_pte(pmap, va);
    if (!ptep || !(*ptep & ARM_PTE_PGTRACE)) {
        PMAP_PGTRACE_UNLOCK(&ints);
        return KERN_FAILURE;

    } else if ((*ptep & ARM_PTE_TYPE_VALID) == ARM_PTE_TYPE_VALID) {
        // Somehow this cpu's tlb has not updated
        kprintf("%s Somehow this cpu's tlb has not updated?\n", __func__);
        PMAP_UPDATE_TLBS(pmap, va, va+ARM_PGBYTES);

        PMAP_PGTRACE_UNLOCK(&ints);
        return KERN_SUCCESS;
    }

    // Find if this pa is what we are tracing
    pa = pte_to_pa(*ptep);

    p = pmap_pgtrace_find_page(arm_trunc_page(pa));
    if (p == NULL) {
        panic("%s Can't find va=%llx pa=%llx from tracing pages\n", __func__, va, pa);
    }

    // find if pmap and va are also matching
    queue_head_t *mapq = &(p->maps);
    queue_head_t *mapwaste = &(p->map_waste);
    pmap_pgtrace_map_t *map;

    queue_iterate(mapq, map, pmap_pgtrace_map_t *, chain) {
        if (map->pmap == pmap && map->ova == arm_trunc_page(va)) {
            found = true;
            break;
        }
    }

    // if not found, search map waste as they are still valid
    if (!found) {
        queue_iterate(mapwaste, map, pmap_pgtrace_map_t *, chain) {
            if (map->pmap == pmap && map->ova == arm_trunc_page(va)) {
                found = true;
                break;
            }
        }
    }

    if (!found) {
        panic("%s Can't find va=%llx pa=%llx from tracing pages\n", __func__, va, pa);
    }

    // Decode and run it on the clone map
    bzero(&res, sizeof(res));
    pgtrace_decode_and_run(*(uint32_t *)get_saved_state_pc(ss), // instruction
                           va, map->cva,                        // fault va and clone page vas
                           ss, &res);

    // write a log if in range
    vm_map_offset_t offset = va - map->ova;
    if (map->range.start <= offset && offset <= map->range.end) {
        pgtrace_write_log(res);
    }

    PMAP_PGTRACE_UNLOCK(&ints);

    // Return to next instruction
    set_saved_state_pc(ss, get_saved_state_pc(ss) + sizeof(uint32_t));

    return KERN_SUCCESS;
}
#endif

boolean_t
pmap_enforces_execute_only(
#if (__ARM_VMSA__ == 7)
	__unused
#endif
	pmap_t pmap)
{
#if (__ARM_VMSA__ > 7)
	return (pmap != kernel_pmap);
#else
	return FALSE;
#endif
}

void
pmap_set_jit_entitled(
	__unused pmap_t pmap)
{
	return;
}

static kern_return_t
pmap_query_page_info_internal(
	pmap_t		pmap,
	vm_map_offset_t	va,
	int		*disp_p)
{
	int		disp;
	pmap_paddr_t	pa;
	int		pai;
	pt_entry_t	*pte;
	pv_entry_t	**pv_h, *pve_p;

	if (pmap == PMAP_NULL || pmap == kernel_pmap) {
		*disp_p = 0;
		return KERN_INVALID_ARGUMENT;
	}

	disp = 0;

	PMAP_LOCK(pmap);

	pte = pmap_pte(pmap, va);
	if (pte == PT_ENTRY_NULL) {
		goto done;
	}

	pa = pte_to_pa(*pte);
	if (pa == 0) {
		if (ARM_PTE_IS_COMPRESSED(*pte)) {
			disp |= PMAP_QUERY_PAGE_COMPRESSED;
			if (*pte & ARM_PTE_COMPRESSED_ALT) {
				disp |= PMAP_QUERY_PAGE_COMPRESSED_ALTACCT;
			}
		}
	} else {
		disp |= PMAP_QUERY_PAGE_PRESENT;
		pai = (int) pa_index(pa);
		if (!pa_valid(pa)) {
			goto done;
		}
		LOCK_PVH(pai);
		pv_h = pai_to_pvh(pai);
		pve_p = PV_ENTRY_NULL;
		if (pvh_test_type(pv_h, PVH_TYPE_PVEP)) {
			pve_p = pvh_list(pv_h);
			while (pve_p != PV_ENTRY_NULL &&
			       pve_get_ptep(pve_p) != pte) {
				pve_p = PVE_NEXT_PTR(pve_next(pve_p));
			}
		}
		if (IS_ALTACCT_PAGE(pai, pve_p)) {
			disp |= PMAP_QUERY_PAGE_ALTACCT;
		} else if (IS_REUSABLE_PAGE(pai)) {
			disp |= PMAP_QUERY_PAGE_REUSABLE;
		} else if (IS_INTERNAL_PAGE(pai)) {
			disp |= PMAP_QUERY_PAGE_INTERNAL;
		}
		UNLOCK_PVH(pai);
	}

done:
	PMAP_UNLOCK(pmap);
	*disp_p = disp;
	return KERN_SUCCESS;
}

kern_return_t
pmap_query_page_info(
	pmap_t		pmap,
	vm_map_offset_t	va,
	int		*disp_p)
{
	return pmap_query_page_info_internal(pmap, va, disp_p);
}

kern_return_t
pmap_return_internal(__unused boolean_t do_panic, __unused boolean_t do_recurse)
{

	return KERN_SUCCESS;
}

kern_return_t
pmap_return(boolean_t do_panic, boolean_t do_recurse)
{
	return pmap_return_internal(do_panic, do_recurse);
}

static void
pmap_footprint_suspend_internal(
	vm_map_t	map,
	boolean_t	suspend)
{
#if DEVELOPMENT || DEBUG
	if (suspend) {
		map->pmap->footprint_suspended = TRUE;
		map->pmap->footprint_was_suspended = TRUE;
	} else {
		map->pmap->footprint_suspended = FALSE;
	}
#else /* DEVELOPMENT || DEBUG */
	(void) map;
	(void) suspend;
#endif /* DEVELOPMENT || DEBUG */
}
void
pmap_footprint_suspend(
	vm_map_t map,
	boolean_t suspend)
{
	pmap_footprint_suspend_internal(map, suspend);
}

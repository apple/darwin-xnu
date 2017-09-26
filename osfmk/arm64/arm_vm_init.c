/*
 * Copyright (c) 2007-2011 Apple Inc. All rights reserved.
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

#include <mach_debug.h>
#include <mach_kdp.h>
#include <debug.h>

#include <mach/vm_types.h>
#include <mach/vm_param.h>
#include <kern/misc_protos.h>
#include <kern/assert.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/pmap.h>

#include <arm64/proc_reg.h>
#include <arm64/lowglobals.h>
#include <arm/cpu_data_internal.h>
#include <arm/misc_protos.h>
#include <pexpert/arm64/boot.h>

#include <libkern/kernel_mach_header.h>
#include <libkern/section_keywords.h>

#if KASAN
extern vm_offset_t shadow_pbase;
extern vm_offset_t shadow_ptop;
extern vm_offset_t physmap_vbase;
extern vm_offset_t physmap_vtop;
#endif

/*
 * Denotes the end of xnu.
 */
extern void *last_kernel_symbol;

/*
 * KASLR parameters
 */
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_kernel_base;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_kernel_top;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_kext_base;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_kext_top;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_kernel_stext;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_kernel_etext;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_kernel_slide;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_kernel_slid_base;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_kernel_slid_top;

SECURITY_READ_ONLY_LATE(vm_offset_t) vm_prelink_stext;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_prelink_etext;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_prelink_sdata;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_prelink_edata;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_prelink_sinfo;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_prelink_einfo;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_slinkedit;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_elinkedit;

/* Used by <mach/arm/vm_param.h> */
SECURITY_READ_ONLY_LATE(unsigned long) gVirtBase;
SECURITY_READ_ONLY_LATE(unsigned long) gPhysBase;
SECURITY_READ_ONLY_LATE(unsigned long) gPhysSize;


/*
 * NOTE: mem_size is bogus on large memory machines. 
 *       We will pin it to 0x80000000 if there is more than 2 GB
 *       This is left only for compatibility and max_mem should be used.
 */
vm_offset_t mem_size;                             /* Size of actual physical memory present
                                                   * minus any performance buffer and possibly
                                                   * limited by mem_limit in bytes */
uint64_t    mem_actual;                           /* The "One True" physical memory size
                                                   * actually, it's the highest physical
                                                   * address + 1 */
uint64_t    max_mem;                              /* Size of physical memory (bytes), adjusted
                                                   * by maxmem */
uint64_t    sane_size;                            /* Memory size to use for defaults
                                                   * calculations */
/* This no longer appears to be used; kill it? */
addr64_t    vm_last_addr = VM_MAX_KERNEL_ADDRESS; /* Highest kernel
                                                   * virtual address known
                                                   * to the VM system */

SECURITY_READ_ONLY_LATE(static vm_offset_t)   segTEXTB;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizeTEXT;


SECURITY_READ_ONLY_LATE(static vm_offset_t)   segDATACONSTB;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizeDATACONST;

SECURITY_READ_ONLY_LATE(static vm_offset_t)   segTEXTEXECB;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizeTEXTEXEC;

SECURITY_READ_ONLY_LATE(static vm_offset_t)   segDATAB;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizeDATA;


SECURITY_READ_ONLY_LATE(static vm_offset_t)   segLINKB;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizeLINK;

SECURITY_READ_ONLY_LATE(static vm_offset_t)   segKLDB;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizeKLD;
SECURITY_READ_ONLY_LATE(static vm_offset_t)   segLASTB;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizeLAST;

SECURITY_READ_ONLY_LATE(vm_offset_t)          segPRELINKTEXTB;
SECURITY_READ_ONLY_LATE(unsigned long)        segSizePRELINKTEXT;

SECURITY_READ_ONLY_LATE(static vm_offset_t)   segPLKTEXTEXECB;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizePLKTEXTEXEC;

SECURITY_READ_ONLY_LATE(static vm_offset_t)   segPLKDATACONSTB;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizePLKDATACONST;

SECURITY_READ_ONLY_LATE(static vm_offset_t)   segPRELINKDATAB;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizePRELINKDATA;

SECURITY_READ_ONLY_LATE(static vm_offset_t)   segPLKLLVMCOVB = 0;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizePLKLLVMCOV = 0;

SECURITY_READ_ONLY_LATE(static vm_offset_t)   segPLKLINKEDITB;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizePLKLINKEDIT;

SECURITY_READ_ONLY_LATE(static vm_offset_t)   segPRELINKINFOB;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizePRELINKINFO;

SECURITY_READ_ONLY_LATE(static boolean_t) use_contiguous_hint = TRUE;

SECURITY_READ_ONLY_LATE(unsigned) PAGE_SHIFT_CONST;

SECURITY_READ_ONLY_LATE(vm_offset_t) end_kern;
SECURITY_READ_ONLY_LATE(vm_offset_t) etext;
SECURITY_READ_ONLY_LATE(vm_offset_t) sdata;
SECURITY_READ_ONLY_LATE(vm_offset_t) edata;

vm_offset_t alloc_ptpage(boolean_t map_static);
SECURITY_READ_ONLY_LATE(vm_offset_t) ropage_next;

/*
 * Bootstrap the system enough to run with virtual memory.
 * Map the kernel's code and data, and allocate the system page table.
 * Page_size must already be set.
 *
 * Parameters:
 * first_avail: first available physical page -
 *              after kernel page tables
 * avail_start: PA of first physical page
 * avail_end:   PA of last physical page
 */
SECURITY_READ_ONLY_LATE(vm_offset_t)     first_avail;
SECURITY_READ_ONLY_LATE(vm_offset_t)     static_memory_end;
SECURITY_READ_ONLY_LATE(pmap_paddr_t)    avail_start;
SECURITY_READ_ONLY_LATE(pmap_paddr_t)    avail_end;

#define	MEM_SIZE_MAX		0x100000000ULL

#if defined(KERNEL_INTEGRITY_KTRR)
#if __ARM64_TWO_LEVEL_PMAP__
/* We could support this configuration, but it adds memory overhead. */
#error This configuration is not supported
#endif
#endif

/*
 * This rounds the given address up to the nearest boundary for a PTE contiguous
 * hint.
 */
static vm_offset_t
round_up_pte_hint_address(vm_offset_t address)
{
	vm_offset_t hint_size = ARM_PTE_SIZE << ARM_PTE_HINT_ENTRIES_SHIFT;
	return ((address + (hint_size - 1)) & ~(hint_size - 1));
}

/* allocate a page for a page table: we support static and dynamic mappings.
 *
 * returns a virtual address for the allocated page
 *
 * for static mappings, we allocate from the region ropagetable_begin to ro_pagetable_end-1,
 * which is defined in the DATA_CONST segment and will be protected RNX when vm_prot_finalize runs.
 *
 * for dynamic mappings, we allocate from avail_start, which should remain RWNX.
 */

vm_offset_t alloc_ptpage(boolean_t map_static) {
	vm_offset_t vaddr;

#if !(defined(KERNEL_INTEGRITY_KTRR))
	map_static = FALSE;
#endif

	if (!ropage_next) {
		ropage_next = (vm_offset_t)&ropagetable_begin;
	}

	if (map_static) {
		assert(ropage_next < (vm_offset_t)&ropagetable_end);

		vaddr = ropage_next;
		ropage_next += ARM_PGBYTES;

		return vaddr;
	} else {
		vaddr = phystokv(avail_start);
		avail_start += ARM_PGBYTES;

		return vaddr;
	}
}

#if DEBUG

void dump_kva_l2(vm_offset_t tt_base, tt_entry_t *tt, int indent, uint64_t *rosz_out, uint64_t *rwsz_out);

void dump_kva_l2(vm_offset_t tt_base, tt_entry_t *tt, int indent, uint64_t *rosz_out, uint64_t *rwsz_out) {
	unsigned int i;
	boolean_t cur_ro, prev_ro = 0;
	int start_entry = -1;
	tt_entry_t cur, prev = 0;
	pmap_paddr_t robegin = kvtophys((vm_offset_t)&ropagetable_begin);
	pmap_paddr_t roend = kvtophys((vm_offset_t)&ropagetable_end);
	boolean_t tt_static = kvtophys((vm_offset_t)tt) >= robegin &&
	                      kvtophys((vm_offset_t)tt) < roend;

	for(i=0; i<TTE_PGENTRIES; i++) {
		int tte_type = tt[i] & ARM_TTE_TYPE_MASK;
		cur = tt[i] & ARM_TTE_TABLE_MASK;

		if (tt_static) {
			/* addresses mapped by this entry are static if it is a block mapping,
			 * or the table was allocated from the RO page table region */
			cur_ro = (tte_type == ARM_TTE_TYPE_BLOCK) || (cur >= robegin && cur < roend);
		} else {
			cur_ro = 0;
		}

		if ((cur == 0 && prev != 0) || (cur_ro != prev_ro && prev != 0)) { // falling edge
			uintptr_t start,end,sz;

			start = (uintptr_t)start_entry << ARM_TT_L2_SHIFT;
			start += tt_base;
			end = ((uintptr_t)i << ARM_TT_L2_SHIFT) - 1;
			end += tt_base;

			sz = end - start + 1;
			printf("%*s0x%08x_%08x-0x%08x_%08x %s (%luMB)\n",
			       indent*4, "",
				   (uint32_t)(start >> 32),(uint32_t)start,
				   (uint32_t)(end >> 32),(uint32_t)end,
				   prev_ro ? "Static " : "Dynamic",
				   (sz >> 20));

			if (prev_ro) {
				*rosz_out += sz;
			} else {
				*rwsz_out += sz;
			}
		}

		if ((prev == 0 && cur != 0) || cur_ro != prev_ro) { // rising edge: set start
			start_entry = i;
		}

		prev = cur;
		prev_ro = cur_ro;
	}
}

void dump_kva_space() {
	uint64_t tot_rosz=0, tot_rwsz=0;
	int ro_ptpages, rw_ptpages;
	pmap_paddr_t robegin = kvtophys((vm_offset_t)&ropagetable_begin);
	pmap_paddr_t roend = kvtophys((vm_offset_t)&ropagetable_end);
	boolean_t root_static = kvtophys((vm_offset_t)cpu_tte) >= robegin &&
	                        kvtophys((vm_offset_t)cpu_tte) < roend;
	uint64_t kva_base = ~((1ULL << (64 - T1SZ_BOOT)) - 1);

	printf("Root page table: %s\n", root_static ? "Static" : "Dynamic");

#if !__ARM64_TWO_LEVEL_PMAP__
	for(unsigned int i=0; i<TTE_PGENTRIES; i++) {
		pmap_paddr_t cur;
		boolean_t cur_ro;
		uintptr_t start,end;
		uint64_t rosz = 0, rwsz = 0;

		if ((cpu_tte[i] & ARM_TTE_VALID) == 0)
			continue;

		cur = cpu_tte[i] & ARM_TTE_TABLE_MASK;
		start = (uint64_t)i << ARM_TT_L1_SHIFT;
		start = start + kva_base;
		end = start + (ARM_TT_L1_SIZE - 1);
		cur_ro = cur >= robegin && cur < roend;

		printf("0x%08x_%08x-0x%08x_%08x %s\n",
		       (uint32_t)(start >> 32),(uint32_t)start,
			   (uint32_t)(end >> 32),(uint32_t)end,
			   cur_ro ? "Static " : "Dynamic");

		dump_kva_l2(start, (tt_entry_t*)phystokv(cur), 1, &rosz, &rwsz);
		tot_rosz += rosz;
		tot_rwsz += rwsz;
	}
#else
	dump_kva_l2(kva_base, cpu_tte, 0, &tot_rosz, &tot_rwsz);
#endif /* !_ARM64_TWO_LEVEL_PMAP__ */

	printf("L2 Address space mapped: Static %lluMB Dynamic %lluMB Total %lluMB\n",
	  tot_rosz >> 20,
	  tot_rwsz >> 20,
	  (tot_rosz >> 20) + (tot_rwsz >> 20));

	ro_ptpages = (int)((ropage_next - (vm_offset_t)&ropagetable_begin) >> ARM_PGSHIFT);
	rw_ptpages = (int)(lowGlo.lgStaticSize  >> ARM_PGSHIFT);
	printf("Pages used: static %d dynamic %d\n", ro_ptpages, rw_ptpages);
}

#endif /* DEBUG */

#if defined(KERNEL_INTEGRITY_KTRR)
extern void bootstrap_instructions;

/*
 * arm_replace_identity_map takes the V=P map that we construct in start.s
 * and repurposes it in order to have it map only the page we need in order
 * to turn on the MMU.  This prevents us from running into issues where
 * KTRR will cause us to fault on executable block mappings that cross the
 * KTRR boundary.
 */
static void arm_replace_identity_map(boot_args * args)
{
	vm_offset_t addr;
	pmap_paddr_t paddr;

#if !__ARM64_TWO_LEVEL_PMAP__
	pmap_paddr_t l1_ptp_phys = 0;
	tt_entry_t *l1_ptp_virt = NULL;
	tt_entry_t *tte1 = NULL;
#endif
	pmap_paddr_t l2_ptp_phys = 0;
	tt_entry_t *l2_ptp_virt = NULL;
	tt_entry_t *tte2 = NULL;
	pmap_paddr_t l3_ptp_phys = 0;
	pt_entry_t *l3_ptp_virt = NULL;
	pt_entry_t *ptep = NULL;

	addr = ((vm_offset_t)&bootstrap_instructions) & ~ARM_PGMASK;
	paddr = kvtophys(addr);

	/*
	 * The V=P page tables (at the time this comment was written) start
	 * after the last bit of kernel data, and consist of 1 to 2 pages.
	 * Grab references to those pages, and allocate an L3 page.
	 */
#if !__ARM64_TWO_LEVEL_PMAP__
	l1_ptp_phys = args->topOfKernelData;
	l1_ptp_virt = (tt_entry_t *)phystokv(l1_ptp_phys);
	tte1 = &l1_ptp_virt[(((paddr) & ARM_TT_L1_INDEX_MASK) >> ARM_TT_L1_SHIFT)];

	l2_ptp_phys = l1_ptp_phys + ARM_PGBYTES;
#else
	l2_ptp_phys = args->topOfKernelData;
#endif
	l2_ptp_virt = (tt_entry_t *)phystokv(l2_ptp_phys);
	tte2 = &l2_ptp_virt[(((paddr) & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT)];

	l3_ptp_virt = (pt_entry_t *)alloc_ptpage(FALSE);
	l3_ptp_phys = kvtophys((vm_offset_t)l3_ptp_virt);
	ptep = &l3_ptp_virt[(((paddr) & ARM_TT_L3_INDEX_MASK) >> ARM_TT_L3_SHIFT)];

	/*
	 * Replace the large V=P mapping with a mapping that provides only the
	 * mappings needed to turn on the MMU.
	 */
#if !__ARM64_TWO_LEVEL_PMAP__
	bzero(l1_ptp_virt, ARM_PGBYTES);
	*tte1 = ARM_TTE_BOOT_TABLE | (l2_ptp_phys & ARM_TTE_TABLE_MASK);
#endif
	bzero(l2_ptp_virt, ARM_PGBYTES);
	*tte2 = ARM_TTE_BOOT_TABLE | (l3_ptp_phys & ARM_TTE_TABLE_MASK);

	*ptep = (paddr & ARM_PTE_MASK) |
	        ARM_PTE_TYPE_VALID |
	        ARM_PTE_SH(SH_OUTER_MEMORY) |
	        ARM_PTE_ATTRINDX(CACHE_ATTRINDX_WRITEBACK) |
	        ARM_PTE_AF |
	        ARM_PTE_AP(AP_RONA) |
	        ARM_PTE_NX;
}
#endif /* defined(KERNEL_INTEGRITY_KTRR)*/

/*
 * arm_vm_page_granular_helper updates protections at the L3 level.  It will (if
 * neccessary) allocate a page for the L3 table and update the corresponding L2
 * entry.  Then, it will iterate over the L3 table, updating protections as necessary.
 * This expects to be invoked on a L2 entry or sub L2 entry granularity, so this should
 * not be invoked from a context that does not do L2 iteration separately (basically,
 * don't call this except from arm_vm_page_granular_prot).
 */
static void
arm_vm_page_granular_helper(vm_offset_t start, vm_offset_t _end, vm_offset_t va,
                            int pte_prot_APX, int pte_prot_XN, int forceCoarse,
                            pt_entry_t **deferred_pte, pt_entry_t *deferred_ptmp)
{
	if (va & ARM_TT_L2_OFFMASK) { /* ragged edge hanging over a ARM_TT_L2_SIZE  boundary */
#if __ARM64_TWO_LEVEL_PMAP__
		tt_entry_t *tte2;
#else
		tt_entry_t *tte1, *tte2;
#endif
		tt_entry_t tmplate;
		pmap_paddr_t pa;
		pt_entry_t *ppte, *recursive_pte = NULL, ptmp, recursive_ptmp = 0;
		addr64_t ppte_phys;
		unsigned i;

		va &= ~ARM_TT_L2_OFFMASK;
		pa = va - gVirtBase + gPhysBase;

#if __ARM64_TWO_LEVEL_PMAP__
		tte2 = &cpu_tte[(((va) & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT)];
#else
		tte1 = &cpu_tte[(((va) & ARM_TT_L1_INDEX_MASK) >> ARM_TT_L1_SHIFT)];
		tte2 = &((tt_entry_t*) phystokv((*tte1) & ARM_TTE_TABLE_MASK))[(((va) & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT)];
#endif

		tmplate = *tte2;

		if (ARM_TTE_TYPE_TABLE == (tmplate & ARM_TTE_TYPE_MASK)) {
			/* pick up the existing page table. */
			ppte = (pt_entry_t *)phystokv((tmplate & ARM_TTE_TABLE_MASK));
		} else {
			// TTE must be reincarnated COARSE.
			ppte = (pt_entry_t*)alloc_ptpage(TRUE);
			ppte_phys = kvtophys((vm_offset_t)ppte);

			pmap_init_pte_static_page(kernel_pmap, ppte, pa);

			*tte2 = pa_to_tte(ppte_phys) | ARM_TTE_TYPE_TABLE  | ARM_TTE_VALID;
		}

		/* Apply the desired protections to the specified page range */
		for (i = 0; i <= (ARM_TT_L3_INDEX_MASK>>ARM_TT_L3_SHIFT); i++) {
			if ((start <= va) && (va < _end)) {

				ptmp = pa | ARM_PTE_AF | ARM_PTE_SH(SH_OUTER_MEMORY) | ARM_PTE_TYPE;
				ptmp = ptmp | ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DEFAULT);
				ptmp = ptmp | ARM_PTE_AP(pte_prot_APX);
				ptmp = ptmp | ARM_PTE_NX;

				if (pte_prot_XN) {
					ptmp = ptmp | ARM_PTE_PNX;
				}

				/*
				 * If we can, apply the contiguous hint to this range.  The hint is
				 * applicable if we are not trying to create per-page mappings and
				 * if the current address falls within a hint-sized range that will
				 * be fully covered by this mapping request.
				 */
				if ((va >= round_up_pte_hint_address(start)) && (round_up_pte_hint_address(va + 1) < _end) &&
				    !forceCoarse && use_contiguous_hint) {
					ptmp |= ARM_PTE_HINT;
				}

				if ((pt_entry_t*)(phystokv(pa)) == ppte) {
					assert(recursive_pte == NULL);	
					/* This assert should be reenabled as part of rdar://problem/30149465 */
					assert(!forceCoarse);
					recursive_pte = &ppte[i];
					recursive_ptmp = ptmp;
				} else if ((deferred_pte != NULL) && (&ppte[i] == &recursive_pte[1])) {
					assert(*deferred_pte == NULL);
					assert(deferred_ptmp != NULL);
					*deferred_pte = &ppte[i];
					*deferred_ptmp = ptmp;
				} else {
					ppte[i] = ptmp;
				}
			}

			va += ARM_PGBYTES;
			pa += ARM_PGBYTES;
		}
		if (recursive_pte != NULL)
			*recursive_pte = recursive_ptmp;
	}
}

/*
 * arm_vm_page_granular_prot updates protections by iterating over the L2 entries and
 * changing them.  If a particular chunk necessitates L3 entries (for reasons of
 * alignment or length, or an explicit request that the entry be fully expanded), we
 * hand off to arm_vm_page_granular_helper to deal with the L3 chunk of the logic.
 *
 * Note that counterintuitively a forceCoarse request is a request to expand the entries
 * out to L3, i.e. to make *finer* grained mappings. That comes from historical arm32
 * nomenclature in which the 4K granule is "coarse" vs. the 1K "fine" granule (which we
 * don't use). 
 */
static void
arm_vm_page_granular_prot(vm_offset_t start, unsigned long size,
                          int tte_prot_XN, int pte_prot_APX, int pte_prot_XN, int forceCoarse)
{
	pt_entry_t *deferred_pte = NULL, deferred_ptmp = 0;
	vm_offset_t _end = start + size;
	vm_offset_t align_start = (start + ARM_TT_L2_OFFMASK) & ~ARM_TT_L2_OFFMASK;

	if (size == 0x0UL)
		return;

	if (align_start > _end) {
		arm_vm_page_granular_helper(start, _end, start, pte_prot_APX, pte_prot_XN, forceCoarse, NULL, NULL);
		return;
	}

	arm_vm_page_granular_helper(start, align_start, start, pte_prot_APX, pte_prot_XN, forceCoarse, &deferred_pte, &deferred_ptmp);

	while ((_end - align_start)  >= ARM_TT_L2_SIZE) {
		if (forceCoarse)
			arm_vm_page_granular_helper(align_start, align_start+ARM_TT_L2_SIZE, align_start + 1,
			                            pte_prot_APX, pte_prot_XN, forceCoarse, NULL, NULL);
		else {
#if __ARM64_TWO_LEVEL_PMAP__
			tt_entry_t *tte2;
#else
			tt_entry_t *tte1, *tte2;
#endif
			tt_entry_t tmplate;

#if __ARM64_TWO_LEVEL_PMAP__
			tte2 = &cpu_tte[((align_start & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT)];
#else
			tte1 = &cpu_tte[((align_start & ARM_TT_L1_INDEX_MASK) >> ARM_TT_L1_SHIFT)];
			tte2 = &((tt_entry_t*) phystokv((*tte1) & ARM_TTE_TABLE_MASK))[((align_start & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT)];
#endif

			tmplate = *tte2;

			tmplate = (tmplate & ~ARM_TTE_BLOCK_APMASK) | ARM_TTE_BLOCK_AP(pte_prot_APX);
			tmplate = tmplate | ARM_TTE_BLOCK_NX;
			if (tte_prot_XN)
				tmplate = tmplate | ARM_TTE_BLOCK_PNX;

			*tte2 = tmplate;
		}
		align_start += ARM_TT_L2_SIZE;
	}

	if (align_start < _end)
		arm_vm_page_granular_helper(align_start, _end, _end, pte_prot_APX, pte_prot_XN, forceCoarse, &deferred_pte, &deferred_ptmp);

	if (deferred_pte != NULL)
		*deferred_pte = deferred_ptmp;
}

static inline void
arm_vm_page_granular_RNX(vm_offset_t start, unsigned long size, int forceCoarse)
{
	arm_vm_page_granular_prot(start, size, 1, AP_RONA, 1, forceCoarse);
}

static inline void
arm_vm_page_granular_ROX(vm_offset_t start, unsigned long size, int forceCoarse)
{
	arm_vm_page_granular_prot(start, size, 0, AP_RONA, 0, forceCoarse);
}

static inline void
arm_vm_page_granular_RWNX(vm_offset_t start, unsigned long size, int forceCoarse)
{
	arm_vm_page_granular_prot(start, size, 1, AP_RWNA, 1, forceCoarse);
}

static inline void
arm_vm_page_granular_RWX(vm_offset_t start, unsigned long size, int forceCoarse)
{
	arm_vm_page_granular_prot(start, size, 0, AP_RWNA, 0, forceCoarse);
}

void
arm_vm_prot_init(boot_args * args)
{
	/*
	 * Enforce W^X protections on sections that have been identified so far. This will be
	 * further refined for each KEXT's TEXT and DATA segments in readPrelinkedExtensions()
	 */
	bool use_small_page_mappings = FALSE;

	/*
	 * First off, we'll create mappings for any physical memory preceeding the kernel TEXT.
	 * This is memory that we want to give to the VM; this will be accomplished through an
	 * ml_static_mfree call in arm_vm_prot_finalize.  This allows the pmap/vm bootstrap
	 * routines to assume they will have a physically contiguous chunk of memory to deal
	 * with during bootstrap, while reclaiming this memory later.
	 */
	arm_vm_page_granular_RWNX(gVirtBase, segPRELINKTEXTB - gVirtBase, use_small_page_mappings); // Memory for the VM

	/* Map coalesced kext TEXT segment RWNX for now */
	arm_vm_page_granular_RWNX(segPRELINKTEXTB, segSizePRELINKTEXT, FALSE); // Refined in OSKext::readPrelinkedExtensions

	/* Map coalesced kext DATA_CONST segment RWNX (could be empty) */
	arm_vm_page_granular_RWNX(segPLKDATACONSTB, segSizePLKDATACONST, FALSE); // Refined in OSKext::readPrelinkedExtensions

	/* Map coalesced kext TEXT_EXEC segment RWX (could be empty) */
	arm_vm_page_granular_ROX(segPLKTEXTEXECB, segSizePLKTEXTEXEC, FALSE); // Refined in OSKext::readPrelinkedExtensions

	/* if new segments not present, set space between PRELINK_TEXT and xnu TEXT to RWNX
	 * otherwise we no longer expecting any space between the coalesced kext read only segments and xnu rosegments
	 */
	if (!segSizePLKDATACONST && !segSizePLKTEXTEXEC) {
		arm_vm_page_granular_RWNX(segPRELINKTEXTB + segSizePRELINKTEXT, segTEXTB - (segPRELINKTEXTB + segSizePRELINKTEXT), FALSE);
	} else {
		/*
		 * If we have the new segments, we should still protect the gap between kext
		 * read-only pages and kernel read-only pages, in the event that this gap
		 * exists.
		 */
		if ((segPLKDATACONSTB + segSizePLKDATACONST) < segTEXTB) {
			arm_vm_page_granular_RWNX(segPLKDATACONSTB + segSizePLKDATACONST, segTEXTB - (segPLKDATACONSTB + segSizePLKDATACONST), FALSE);
		}
	}

	/*
	 * Protection on kernel text is loose here to allow shenanigans early on.  These
	 * protections are tightened in arm_vm_prot_finalize().  This is necessary because
	 * we currently patch LowResetVectorBase in cpu.c.
	 *
	 * TEXT segment contains mach headers and other non-executable data. This will become RONX later.
	 */
	arm_vm_page_granular_RNX(segTEXTB, segSizeTEXT, FALSE);

	/* Can DATACONST start out and stay RNX?
	 * NO, stuff in this segment gets modified during startup (viz. mac_policy_init()/mac_policy_list)
	 * Make RNX in prot_finalize
	 */
	arm_vm_page_granular_RWNX(segDATACONSTB, segSizeDATACONST, FALSE);

	/* TEXTEXEC contains read only executable code: becomes ROX in prot_finalize */
	arm_vm_page_granular_RWX(segTEXTEXECB, segSizeTEXTEXEC, FALSE);


	/* DATA segment will remain RWNX */
	arm_vm_page_granular_RWNX(segDATAB, segSizeDATA, FALSE);

	arm_vm_page_granular_ROX(segKLDB, segSizeKLD, FALSE);
	arm_vm_page_granular_RWNX(segLINKB, segSizeLINK, FALSE);
	arm_vm_page_granular_ROX(segLASTB, segSizeLAST, FALSE); // __LAST may be empty, but we cannot assume this

	arm_vm_page_granular_RWNX(segPRELINKDATAB, segSizePRELINKDATA, FALSE); // Prelink __DATA for kexts (RW data)

	if (segSizePLKLLVMCOV > 0)
		arm_vm_page_granular_RWNX(segPLKLLVMCOVB, segSizePLKLLVMCOV, FALSE); // LLVM code coverage data

	arm_vm_page_granular_RWNX(segPLKLINKEDITB, segSizePLKLINKEDIT, use_small_page_mappings); // Coalesced kext LINKEDIT segment

	arm_vm_page_granular_RWNX(segPRELINKINFOB, segSizePRELINKINFO, FALSE); /* PreLinkInfoDictionary */
	arm_vm_page_granular_RWNX(end_kern, phystokv(args->topOfKernelData) - end_kern, use_small_page_mappings); /* Device Tree, RAM Disk (if present), bootArgs */

	/*
	 * This is offset by 4 pages to make room for the boot page tables; we could probably
	 * include them in the overall mapping, but we'll be paranoid for now.
	 */
	vm_offset_t extra = 0;
#if KASAN
	/* add the KASAN stolen memory to the physmap */
	extra = shadow_ptop - shadow_pbase;

	/* record the extent of the physmap */
	physmap_vbase = phystokv(args->topOfKernelData) + ARM_PGBYTES * 4;
	physmap_vtop = static_memory_end;
#endif
	arm_vm_page_granular_RNX(phystokv(args->topOfKernelData), ARM_PGBYTES * 4, FALSE); // Boot page tables; they should not be mutable.
	arm_vm_page_granular_RWNX(phystokv(args->topOfKernelData) + ARM_PGBYTES * 4,
	                          extra + static_memory_end - ((phystokv(args->topOfKernelData) + ARM_PGBYTES * 4)), use_small_page_mappings); // rest of physmem
}

void
arm_vm_prot_finalize(boot_args * args)
{
#pragma unused(args)
	/*
	 * At this point, we are far enough along in the boot process that it will be
	 * safe to free up all of the memory preceeding the kernel.  It may in fact
	 * be safe to do this earlier.
	 *
	 * This keeps the memory in the V-to-P mapping, but advertises it to the VM
	 * as usable.
	 */

	/*
	 * if old style PRELINK segment exists, free memory before it, and after it before XNU text
	 * otherwise we're dealing with a new style kernel cache, so we should just free the
	 * memory before PRELINK_TEXT segment, since the rest of the KEXT read only data segments
	 * should be immediately followed by XNU's TEXT segment
	 */

	ml_static_mfree(gVirtBase, segPRELINKTEXTB - gVirtBase);

	if (!segSizePLKDATACONST && !segSizePLKTEXTEXEC) {
		/* If new segments not present, PRELINK_TEXT is not dynamically sized, free DRAM between it and xnu TEXT */
		ml_static_mfree(segPRELINKTEXTB + segSizePRELINKTEXT, segTEXTB - (segPRELINKTEXTB + segSizePRELINKTEXT));
	}

	/*
	 * LowResetVectorBase patching should be done by now, so tighten executable
	 * protections.
	 */
	arm_vm_page_granular_ROX(segTEXTEXECB, segSizeTEXTEXEC, FALSE);

	/* tighten permissions on kext read only data and code */
	if (segSizePLKDATACONST && segSizePLKTEXTEXEC) {
		arm_vm_page_granular_RNX(segPRELINKTEXTB, segSizePRELINKTEXT, FALSE);
		arm_vm_page_granular_ROX(segPLKTEXTEXECB, segSizePLKTEXTEXEC, FALSE);
		arm_vm_page_granular_RNX(segPLKDATACONSTB, segSizePLKDATACONST, FALSE);
	}

#if defined(KERNEL_INTEGRITY_KTRR)
	/*
	 * __LAST,__pinst should no longer be executable.
	 */
	arm_vm_page_granular_RNX(segLASTB, segSizeLAST, FALSE);

	/*
	 * Must wait until all other region permissions are set before locking down DATA_CONST
	 * as the kernel static page tables live in DATA_CONST on KTRR enabled systems
	 * and will become immutable.
	 */
#endif
	arm_vm_page_granular_RNX(segDATACONSTB, segSizeDATACONST, FALSE);

#ifndef __ARM_L1_PTW__
	FlushPoC_Dcache();
#endif
	flush_mmu_tlb();
}

#define TBI_USER 0x1
#define TBI_KERNEL 0x2

boolean_t user_tbi = TRUE;

/*
 * TBI (top-byte ignore) is an ARMv8 feature for ignoring the top 8 bits of
 * address accesses. It can be enabled separately for TTBR0 (user) and
 * TTBR1 (kernel). We enable it by default for user only, but allow both
 * to be controlled by the 'tbi' boot-arg.
 */
static void
set_tbi(void)
{
	uint64_t old_tcr, new_tcr;
	int tbi = 0;

	if (PE_parse_boot_argn("tbi", &tbi, sizeof(tbi)))
		user_tbi = ((tbi & TBI_USER) == TBI_USER);
	old_tcr = new_tcr = get_tcr();
	new_tcr |= (user_tbi) ? TCR_TBI0_TOPBYTE_IGNORED : 0;
	new_tcr |= (tbi & TBI_KERNEL) ? TCR_TBI1_TOPBYTE_IGNORED : 0;

	if (old_tcr != new_tcr) {
		set_tcr(new_tcr);
		sysreg_restore.tcr_el1 = new_tcr;
	}
}

void
arm_vm_init(uint64_t memory_size, boot_args * args)
{
#if !__ARM64_TWO_LEVEL_PMAP__
	vm_map_address_t va_l1, va_l1_end;
	pmap_paddr_t     pa_l1;
	tt_entry_t       *cpu_l1_tte;
#else
	/*
	 * If we are using two level page tables, rather than the
	 * 3 level page tables that xnu defaults to for ARM64,
	 * then a great deal of the code in this path becomes
	 * redundant.  As a result, most of the logic having to
	 * do with L1 pages will be excluded from such
	 * configurations in this function.
	 */
#endif
	vm_map_address_t va_l2, va_l2_end;
	pmap_paddr_t     pa_l2;
	tt_entry_t       *cpu_l2_tte;
	pmap_paddr_t     boot_ttep;
	tt_entry_t       *boot_tte;
	uint64_t         mem_segments;
	vm_offset_t      ptpage_vaddr;


	/*
	 * Get the virtual and physical memory base from boot_args.
	 */
	gVirtBase = args->virtBase;
	gPhysBase = args->physBase;
	gPhysSize = args->memSize;
	mem_size = args->memSize;
	if ((memory_size != 0) && (mem_size > memory_size))
		mem_size = memory_size;
	if (mem_size > MEM_SIZE_MAX )
		mem_size = MEM_SIZE_MAX;
	static_memory_end = gVirtBase + mem_size;

	boot_ttep = args->topOfKernelData;
	boot_tte = (tt_entry_t *) phystokv(boot_ttep);

	/* 
	 * Four pages: 
	 *  TTBR0 L1, TTBR0 L2 - 1:1 bootstrap mapping.
	 *  TTBR1 L1, TTBR1 L2 - kernel mapping
	 */
	avail_start = boot_ttep + 4*ARM_PGBYTES; 

#if defined(KERNEL_INTEGRITY_KTRR)
	arm_replace_identity_map(args);
#endif

	/* Initialize invalid tte page */
	invalid_tte = (tt_entry_t *)alloc_ptpage(TRUE);
	invalid_ttep = kvtophys((vm_offset_t)invalid_tte);
	bzero(invalid_tte, ARM_PGBYTES);

	/*
	 * Initialize l1 page table page
	 */
#if __ARM64_TWO_LEVEL_PMAP__
	/*
	 * If we're using a two level page table, we still need to
	 * set the cpu_ttep to avail_start, as this will be the root
	 * of our page table regardless of how many levels we are
	 * using.
	 */
#endif
	cpu_tte = (tt_entry_t *)alloc_ptpage(TRUE);
	cpu_ttep = kvtophys((vm_offset_t)cpu_tte);
	bzero(cpu_tte, ARM_PGBYTES);

	avail_end = gPhysBase + mem_size;

	/*
	 * Initialize l1 and l2 page table pages :
	 *   map physical memory at the kernel base virtual address
	 *   cover the kernel dynamic address range section
	 *
	 *   the so called physical aperture should be statically mapped
	 */

#if !__ARM64_TWO_LEVEL_PMAP__
	pa_l1 = gPhysBase;
	va_l1 = gVirtBase;
	va_l1_end = gVirtBase + mem_size;
#if KASAN
	/* add the KASAN stolen memory to the physmap */
	va_l1_end = gVirtBase + (shadow_ptop - gPhysBase);
#endif
	cpu_l1_tte = cpu_tte + ((va_l1 & ARM_TT_L1_INDEX_MASK) >> ARM_TT_L1_SHIFT);

	while (va_l1 < va_l1_end) {
		tt_entry_t *new_tte = (tt_entry_t *)alloc_ptpage(TRUE);
		/* Allocate a page and setup L1 Table TTE in L1 */
		*cpu_l1_tte = (kvtophys((vm_offset_t)new_tte) & ARM_TTE_TABLE_MASK)  | ARM_TTE_TYPE_TABLE | ARM_TTE_VALID;
		bzero((void *)new_tte, ARM_PGBYTES);

		va_l2 = va_l1;

		if (((va_l1 & ~ARM_TT_L1_OFFMASK)+ARM_TT_L1_SIZE) < va_l1) {
			/* If this is the last L1 entry, it must cover the last mapping. */
			va_l2_end = va_l1_end;
		} else {
			va_l2_end = MIN((va_l1 & ~ARM_TT_L1_OFFMASK)+ARM_TT_L1_SIZE, va_l1_end);
		}

		pa_l2 = pa_l1;
		cpu_l2_tte = ((tt_entry_t *) phystokv(((*cpu_l1_tte) & ARM_TTE_TABLE_MASK))) + ((va_l1 & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT);
#else
		va_l2 = gVirtBase;
		va_l2_end = gVirtBase + mem_size;
		pa_l2 = gPhysBase;
		cpu_l2_tte = cpu_tte + ((va_l2 & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT);

#if KASAN
		/* add the KASAN stolen memory to the physmap */
		va_l2_end = gVirtBase + (shadow_ptop - gPhysBase);
#endif

#endif

		while (va_l2 < va_l2_end) {
			/* Set up L2 Block TTE in L2 */
			*cpu_l2_tte = (pa_l2 & ARM_TTE_BLOCK_L2_MASK) | ARM_TTE_TYPE_BLOCK
			              | ARM_TTE_VALID | ARM_TTE_BLOCK_AF
			              | ARM_TTE_BLOCK_AP(AP_RWNA) | ARM_TTE_BLOCK_SH(SH_OUTER_MEMORY)
			              | ARM_TTE_BLOCK_ATTRINDX(CACHE_ATTRINDX_WRITEBACK);
			va_l2 += ARM_TT_L2_SIZE;
			pa_l2 += ARM_TT_L2_SIZE;
			cpu_l2_tte++;
		}
#if !__ARM64_TWO_LEVEL_PMAP__
		cpu_l1_tte++;
		va_l1 = va_l2;
		pa_l1 = pa_l2;
	}
#endif

	/*
	 * Now retrieve addresses for end, edata, and etext from MACH-O headers
	 */
	segPRELINKTEXTB  = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__PRELINK_TEXT", &segSizePRELINKTEXT);
	segPLKDATACONSTB = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__PLK_DATA_CONST", &segSizePLKDATACONST);
	segPLKTEXTEXECB  = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__PLK_TEXT_EXEC", &segSizePLKTEXTEXEC);
	segTEXTB         = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__TEXT", &segSizeTEXT);
	segDATACONSTB    = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__DATA_CONST", &segSizeDATACONST);
	segTEXTEXECB     = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__TEXT_EXEC", &segSizeTEXTEXEC);
	segDATAB         = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__DATA", &segSizeDATA);
	segLINKB         = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__LINKEDIT", &segSizeLINK);
	segKLDB          = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__KLD", &segSizeKLD);
	segPRELINKDATAB  = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__PRELINK_DATA", &segSizePRELINKDATA);
	segPRELINKINFOB  = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__PRELINK_INFO", &segSizePRELINKINFO);
	segPLKLLVMCOVB   = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__PLK_LLVM_COV", &segSizePLKLLVMCOV);
	segPLKLINKEDITB  = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__PLK_LINKEDIT", &segSizePLKLINKEDIT);
	segLASTB         = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__LAST", &segSizeLAST);

	(void) PE_parse_boot_argn("use_contiguous_hint", &use_contiguous_hint, sizeof(use_contiguous_hint));
	assert(segSizePRELINKTEXT < 0x03000000); /* 23355738 */

	/* if one of the new segments is present, the other one better be as well */
	if (segSizePLKDATACONST || segSizePLKTEXTEXEC) {
		assert(segSizePLKDATACONST && segSizePLKTEXTEXEC);
	}

	etext = (vm_offset_t) segTEXTB + segSizeTEXT;
	sdata = (vm_offset_t) segDATAB;
	edata = (vm_offset_t) segDATAB + segSizeDATA;
	end_kern = round_page(getlastaddr());      /* Force end to next page */

	vm_set_page_size();

	vm_kernel_base = segTEXTB;
	vm_kernel_top = (vm_offset_t) &last_kernel_symbol;
	vm_kext_base = segPRELINKTEXTB;
	vm_kext_top = vm_kext_base + segSizePRELINKTEXT;

	vm_prelink_stext = segPRELINKTEXTB;
	if (!segSizePLKTEXTEXEC && !segSizePLKDATACONST) {
		vm_prelink_etext = segPRELINKTEXTB + segSizePRELINKTEXT;
	} else {
		vm_prelink_etext = segPRELINKTEXTB + segSizePRELINKTEXT + segSizePLKDATACONST + segSizePLKTEXTEXEC;
	}
	vm_prelink_sinfo = segPRELINKINFOB;
	vm_prelink_einfo = segPRELINKINFOB + segSizePRELINKINFO;
	vm_slinkedit = segLINKB;
	vm_elinkedit = segLINKB + segSizeLINK;

	vm_prelink_sdata = segPRELINKDATAB;
	vm_prelink_edata = segPRELINKDATAB + segSizePRELINKDATA;

	arm_vm_prot_init(args);


	/*
	 * Initialize the page tables for the low globals:
	 *   cover this address range:
	 *     LOW_GLOBAL_BASE_ADDRESS + 2MB
	 */
#if __ARM64_TWO_LEVEL_PMAP__
	va_l2 = LOW_GLOBAL_BASE_ADDRESS;
	cpu_l2_tte = cpu_tte + ((va_l2 & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT);
#else
	va_l1 = va_l2 = LOW_GLOBAL_BASE_ADDRESS;
	cpu_l1_tte = cpu_tte + ((va_l1 & ARM_TT_L1_INDEX_MASK) >> ARM_TT_L1_SHIFT);
	cpu_l2_tte = ((tt_entry_t *) phystokv(((*cpu_l1_tte) & ARM_TTE_TABLE_MASK))) + ((va_l2 & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT);
#endif
	ptpage_vaddr = alloc_ptpage(TRUE);
	*cpu_l2_tte = (kvtophys(ptpage_vaddr) & ARM_TTE_TABLE_MASK) | ARM_TTE_TYPE_TABLE | ARM_TTE_VALID | ARM_TTE_TABLE_PXN | ARM_TTE_TABLE_XN;
	bzero((void *)ptpage_vaddr, ARM_PGBYTES);

	/*
	 * Initialize l2 page table pages :
	 *   cover this address range:
	 *    KERNEL_DYNAMIC_ADDR - VM_MAX_KERNEL_ADDRESS
	 */
#if !__ARM64_TWO_LEVEL_PMAP__
	va_l1 = (gVirtBase+MEM_SIZE_MAX+ ~0xFFFFFFFFFF800000ULL) & 0xFFFFFFFFFF800000ULL;
	va_l1_end = VM_MAX_KERNEL_ADDRESS; 
	cpu_l1_tte = cpu_tte + ((va_l1 & ARM_TT_L1_INDEX_MASK) >> ARM_TT_L1_SHIFT);

	while (va_l1 < va_l1_end) {
		if (*cpu_l1_tte == ARM_TTE_EMPTY) {
			/* Allocate a page and setup L1 Table TTE in L1 */
			ptpage_vaddr = alloc_ptpage(TRUE);
			*cpu_l1_tte = (kvtophys(ptpage_vaddr) & ARM_TTE_TABLE_MASK) | ARM_TTE_TYPE_TABLE | ARM_TTE_VALID | ARM_TTE_TABLE_PXN | ARM_TTE_TABLE_XN;
			bzero((void *)ptpage_vaddr, ARM_PGBYTES);
		}

		if ((va_l1 + ARM_TT_L1_SIZE) < va_l1) {
			/* If this is the last L1 entry, it must cover the last mapping. */
			break;
		}

		va_l1 += ARM_TT_L1_SIZE;
		cpu_l1_tte++;
	}
#endif

#if KASAN
	kasan_init();
#endif

	set_mmu_ttb(invalid_ttep & TTBR_BADDR_MASK);
	set_mmu_ttb_alternate(cpu_ttep & TTBR_BADDR_MASK);
	set_tbi();
	flush_mmu_tlb();

	/*
	 * TODO: We're hardcoding the expected virtual TEXT base here;
	 * that gives us an ugly dependency on a linker argument in
	 * the make files.  Clean this up, so we don't hardcode it
	 * twice; this is nothing but trouble.
	 */
	sane_size = mem_size - (avail_start - gPhysBase);
	max_mem = mem_size;
	vm_kernel_slid_base = segPRELINKTEXTB;
	vm_kernel_slid_top = vm_prelink_einfo;
	vm_kernel_slide = segTEXTB-0xfffffff007004000;
	vm_kernel_stext = segTEXTB;
	assert(segDATACONSTB == segTEXTB + segSizeTEXT);
	 assert(segTEXTEXECB == segDATACONSTB + segSizeDATACONST);
	vm_kernel_etext = segTEXTB + segSizeTEXT + segSizeDATACONST + segSizeTEXTEXEC;

	pmap_bootstrap((gVirtBase+MEM_SIZE_MAX+ ~0xFFFFFFFFFF800000ULL) & 0xFFFFFFFFFF800000ULL);

	/*
	 * Initialize l3 page table pages :
	 *   cover this address range:
	 *    2MB + FrameBuffer size + 10MB for each 256MB segment
	 */

	mem_segments = (mem_size + 0x0FFFFFFF) >> 28;

#if !__ARM64_TWO_LEVEL_PMAP__
	va_l1 = (gVirtBase+MEM_SIZE_MAX+ ~0xFFFFFFFFFF800000ULL) & 0xFFFFFFFFFF800000ULL;
	va_l1_end = va_l1 + ((2 + (mem_segments * 10)) << 20);
	va_l1_end += round_page(args->Video.v_height * args->Video.v_rowBytes);
	va_l1_end = (va_l1_end + 0x00000000007FFFFFULL) & 0xFFFFFFFFFF800000ULL;

	cpu_l1_tte = cpu_tte + ((va_l1 & ARM_TT_L1_INDEX_MASK) >> ARM_TT_L1_SHIFT);

	while (va_l1 < va_l1_end) {

		va_l2 = va_l1;

		if (((va_l1 & ~ARM_TT_L1_OFFMASK)+ARM_TT_L1_SIZE) < va_l1) {
			/* If this is the last L1 entry, it must cover the last mapping. */
			va_l2_end = va_l1_end;
		} else {
			va_l2_end = MIN((va_l1 & ~ARM_TT_L1_OFFMASK)+ARM_TT_L1_SIZE, va_l1_end);
		}

		cpu_l2_tte = ((tt_entry_t *) phystokv(((*cpu_l1_tte) & ARM_TTE_TABLE_MASK))) + ((va_l2 & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT);
#else
		va_l2 = (gVirtBase+MEM_SIZE_MAX+ ~0xFFFFFFFFFF800000ULL) & 0xFFFFFFFFFF800000ULL;
		va_l2_end = va_l2 + ((2 + (mem_segments * 10)) << 20);
		va_l2_end += round_page(args->Video.v_height * args->Video.v_rowBytes);
		va_l2_end = (va_l2_end + 0x00000000007FFFFFULL) & 0xFFFFFFFFFF800000ULL;
		cpu_l2_tte = cpu_tte + ((va_l2 & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT);
#endif

		while (va_l2 < va_l2_end) {
			pt_entry_t *    ptp;
			pmap_paddr_t    ptp_phys;

			/* Allocate a page and setup L3 Table TTE in L2 */
			ptp = (pt_entry_t *) alloc_ptpage(FALSE);
			ptp_phys = (pmap_paddr_t)kvtophys((vm_offset_t)ptp);

			pmap_init_pte_page(kernel_pmap, ptp, va_l2, 3, TRUE);

			*cpu_l2_tte = (pa_to_tte (ptp_phys)) | ARM_TTE_TYPE_TABLE | ARM_TTE_VALID | ARM_TTE_TABLE_PXN | ARM_TTE_TABLE_XN;

			va_l2 += ARM_TT_L2_SIZE;
			cpu_l2_tte++;
		};
#if !__ARM64_TWO_LEVEL_PMAP__
		va_l1 = va_l2_end;
		cpu_l1_tte++;
	}
#endif

	/*
	 * Initialize l3 page table pages :
	 *   cover this address range:
	 *   (VM_MAX_KERNEL_ADDRESS & CPUWINDOWS_BASE_MASK) - VM_MAX_KERNEL_ADDRESS
	 */
#if !__ARM64_TWO_LEVEL_PMAP__
	va_l1 = VM_MAX_KERNEL_ADDRESS & CPUWINDOWS_BASE_MASK;
	va_l1_end = VM_MAX_KERNEL_ADDRESS;

	cpu_l1_tte = cpu_tte + ((va_l1 & ARM_TT_L1_INDEX_MASK) >> ARM_TT_L1_SHIFT);

	while (va_l1 < va_l1_end) {

		va_l2 = va_l1;

		if (((va_l1 & ~ARM_TT_L1_OFFMASK)+ARM_TT_L1_SIZE) < va_l1) {
			/* If this is the last L1 entry, it must cover the last mapping. */
			va_l2_end = va_l1_end;
		} else {
			va_l2_end = MIN((va_l1 & ~ARM_TT_L1_OFFMASK)+ARM_TT_L1_SIZE, va_l1_end);
		}

		cpu_l2_tte = ((tt_entry_t *) phystokv(((*cpu_l1_tte) & ARM_TTE_TABLE_MASK))) + ((va_l2 & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT);
#else
		va_l2 = VM_MAX_KERNEL_ADDRESS & CPUWINDOWS_BASE_MASK;
		va_l2_end = VM_MAX_KERNEL_ADDRESS;
		cpu_l2_tte = cpu_tte + ((va_l2 & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT);
#endif

		while (va_l2 < va_l2_end) {
			pt_entry_t *    ptp;
			pmap_paddr_t    ptp_phys;

			/* Allocate a page and setup L3 Table TTE in L2 */
			ptp = (pt_entry_t *) alloc_ptpage(FALSE);
			ptp_phys = (pmap_paddr_t)kvtophys((vm_offset_t)ptp);

			pmap_init_pte_page(kernel_pmap, ptp, va_l2, 3, TRUE);

			*cpu_l2_tte = (pa_to_tte (ptp_phys)) | ARM_TTE_TYPE_TABLE | ARM_TTE_VALID | ARM_TTE_TABLE_PXN | ARM_TTE_TABLE_XN;

			va_l2 += ARM_TT_L2_SIZE;
			cpu_l2_tte++;
		};
#if !__ARM64_TWO_LEVEL_PMAP__
		va_l1 = va_l2_end;
		cpu_l1_tte++;
	}
#endif

#if __ARM64_PMAP_SUBPAGE_L1__ && __ARM_16K_PG__
	/*
	 * In this configuration, the bootstrap mappings (arm_vm_init) and
	 * the heap mappings occupy separate L1 regions.  Explicitly set up
	 * the heap L1 allocations here.
	 */
	va_l1 = VM_MIN_KERNEL_ADDRESS & ~ARM_TT_L1_OFFMASK;
	cpu_l1_tte = cpu_tte + ((va_l1 & ARM_TT_L1_INDEX_MASK) >> ARM_TT_L1_SHIFT);

	while ((va_l1 >= (VM_MIN_KERNEL_ADDRESS & ~ARM_TT_L1_OFFMASK)) && (va_l1 < VM_MAX_KERNEL_ADDRESS)) {
		/*
		 * If the L1 entry has not yet been allocated, allocate it
		 * now and treat it as a heap table.
		 */
		if (*cpu_l1_tte == ARM_TTE_EMPTY) {
			tt_entry_t *new_tte = (tt_entry_t*)alloc_ptpage(FALSE);
			bzero(new_tte, ARM_PGBYTES);
			*cpu_l1_tte = (kvtophys((vm_offset_t)new_tte) & ARM_TTE_TABLE_MASK)  | ARM_TTE_TYPE_TABLE | ARM_TTE_VALID | ARM_TTE_TABLE_PXN | ARM_TTE_TABLE_XN;
		}

		cpu_l1_tte++;
		va_l1 += ARM_TT_L1_SIZE;
	}
#endif

	/*
	 * Adjust avail_start so that the range that the VM owns
	 * starts on a PAGE_SIZE aligned boundary.
	 */
	avail_start = (avail_start + PAGE_MASK) & ~PAGE_MASK;


	first_avail = avail_start;
	patch_low_glo_static_region(args->topOfKernelData, avail_start - args->topOfKernelData);
}


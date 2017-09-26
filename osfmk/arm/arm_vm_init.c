/*
 * Copyright (c) 2007-2008 Apple Inc. All rights reserved.
 * Copyright (c) 2005-2006 Apple Computer, Inc. All rights reserved.
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
#include <mach/thread_status.h>
#include <kern/misc_protos.h>
#include <kern/assert.h>
#include <kern/cpu_number.h>
#include <kern/thread.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/pmap.h>

#include <arm/proc_reg.h>
#include <arm/caches_internal.h>
#include <arm/pmap.h>
#include <arm/misc_protos.h>
#include <arm/lowglobals.h>

#include <pexpert/arm/boot.h>

#include <libkern/kernel_mach_header.h>

/*
 * Denotes the end of xnu.
 */
extern void *last_kernel_symbol;

/*
 * KASLR parameters
 */
vm_offset_t vm_kernel_base;
vm_offset_t vm_kernel_top;
vm_offset_t vm_kernel_stext;
vm_offset_t vm_kernel_etext;
vm_offset_t vm_kernel_slide;
vm_offset_t vm_kernel_slid_base;
vm_offset_t vm_kernel_slid_top;
vm_offset_t vm_kext_base;
vm_offset_t vm_kext_top;
vm_offset_t vm_prelink_stext;
vm_offset_t vm_prelink_etext;
vm_offset_t vm_prelink_sinfo;
vm_offset_t vm_prelink_einfo;
vm_offset_t vm_slinkedit;
vm_offset_t vm_elinkedit;
vm_offset_t vm_prelink_sdata;
vm_offset_t vm_prelink_edata;

unsigned long gVirtBase, gPhysBase, gPhysSize;	    /* Used by <mach/arm/vm_param.h> */

vm_offset_t   mem_size;                             /* Size of actual physical memory present
                                                     * minus any performance buffer and possibly
                                                     * limited by mem_limit in bytes */
uint64_t      mem_actual;                           /* The "One True" physical memory size
                                                     * actually, it's the highest physical
                                                     * address + 1 */
uint64_t      max_mem;                              /* Size of physical memory (bytes), adjusted
                                                     * by maxmem */
uint64_t      sane_size;                            /* Memory size to use for defaults
                                                     * calculations */
addr64_t      vm_last_addr = VM_MAX_KERNEL_ADDRESS; /* Highest kernel
                                                     * virtual address known
                                                     * to the VM system */

static vm_offset_t     segTEXTB;
static unsigned long   segSizeTEXT;
static vm_offset_t     segDATAB;
static unsigned long   segSizeDATA;
static vm_offset_t     segLINKB;
static unsigned long   segSizeLINK;
static vm_offset_t     segKLDB;
static unsigned long   segSizeKLD;
static vm_offset_t     segLASTB;
static unsigned long   segSizeLAST;
static vm_offset_t     sectCONSTB;
static unsigned long   sectSizeCONST;

vm_offset_t     segPRELINKTEXTB;
unsigned long   segSizePRELINKTEXT;
vm_offset_t     segPRELINKINFOB;
unsigned long   segSizePRELINKINFO;

static kernel_segment_command_t *segDATA;
static boolean_t doconstro = TRUE;

vm_offset_t end_kern, etext, sdata, edata;

/*
 * Bootstrap the system enough to run with virtual memory.
 * Map the kernel's code and data, and allocate the system page table.
 * Page_size must already be set.
 *
 * Parameters:
 * first_avail: first available physical page -
 *              after kernel page tables
 * avail_start: PA of first physical page
 * avail_end  : PA of last physical page
 */
vm_offset_t     first_avail;
vm_offset_t     static_memory_end;
pmap_paddr_t    avail_start, avail_end;

#define MEM_SIZE_MAX 0x40000000

extern vm_offset_t ExceptionVectorsBase; /* the code we want to load there */

/* The translation tables have to be 16KB aligned */
#define round_x_table(x) \
	(((pmap_paddr_t)(x) + (ARM_PGBYTES<<2) - 1) & ~((ARM_PGBYTES<<2) - 1))


static void
arm_vm_page_granular_helper(vm_offset_t start, vm_offset_t _end, vm_offset_t va, 
                            int pte_prot_APX, int pte_prot_XN)
{
	if (va & ARM_TT_L1_PT_OFFMASK) { /* ragged edge hanging over a ARM_TT_L1_PT_SIZE  boundary */
		va &= (~ARM_TT_L1_PT_OFFMASK);
		tt_entry_t *tte = &cpu_tte[ttenum(va)];
		tt_entry_t tmplate = *tte;
		pmap_paddr_t pa;
		pt_entry_t *ppte, ptmp;
		unsigned int i;

		pa = va - gVirtBase + gPhysBase;

		if (ARM_TTE_TYPE_TABLE == (tmplate & ARM_TTE_TYPE_MASK)) {
			/* pick up the existing page table. */
			ppte = (pt_entry_t *)phystokv((tmplate & ARM_TTE_TABLE_MASK));
		} else {
			/* TTE must be reincarnated COARSE. */
			ppte = (pt_entry_t *)phystokv(avail_start);
			avail_start += ARM_PGBYTES;

			pmap_init_pte_static_page(kernel_pmap, ppte, pa);

			for (i = 0; i < 4; ++i)
				tte[i] = pa_to_tte(kvtophys((vm_offset_t)ppte) + (i * 0x400)) | ARM_TTE_TYPE_TABLE;
		}

		/* Apply the desired protections to the specified page range */
		for (i = 0; i < (ARM_PGBYTES / sizeof(*ppte)); i++) {
			if (start <= va && va < _end) {

				ptmp = pa | ARM_PTE_AF | ARM_PTE_SH | ARM_PTE_TYPE;
				ptmp = ptmp | ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DEFAULT);
				ptmp = ptmp | ARM_PTE_AP(pte_prot_APX);
				if (pte_prot_XN)
					ptmp = ptmp | ARM_PTE_NX;

				ppte[i] = ptmp;
			}

			va += ARM_PGBYTES;
			pa += ARM_PGBYTES;
		}
	}
}

static void
arm_vm_page_granular_prot(vm_offset_t start, unsigned long size, 
                          int tte_prot_XN, int pte_prot_APX, int pte_prot_XN, int forceCoarse)
{
	vm_offset_t _end = start + size;
	vm_offset_t align_start = (start + ARM_TT_L1_PT_OFFMASK) & ~ARM_TT_L1_PT_OFFMASK;
	vm_offset_t align_end = _end & ~ARM_TT_L1_PT_OFFMASK;

	arm_vm_page_granular_helper(start, _end, start, pte_prot_APX, pte_prot_XN);

	while (align_start < align_end) {
		if (forceCoarse) {
			arm_vm_page_granular_helper(align_start, align_end, align_start + 1, 
			                            pte_prot_APX, pte_prot_XN);
		} else {
			tt_entry_t *tte = &cpu_tte[ttenum(align_start)];
			for (int i = 0; i < 4; ++i) {
				tt_entry_t tmplate = tte[i];

				tmplate = (tmplate & ~ARM_TTE_BLOCK_APMASK) | ARM_TTE_BLOCK_AP(pte_prot_APX);
				tmplate = (tmplate & ~ARM_TTE_BLOCK_NX_MASK);
				if (tte_prot_XN)
					tmplate = tmplate | ARM_TTE_BLOCK_NX;

				tte[i] = tmplate;
			}
		}
		align_start += ARM_TT_L1_PT_SIZE;
	}

	arm_vm_page_granular_helper(start, _end, _end, pte_prot_APX, pte_prot_XN);
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
#if __ARM_PTE_PHYSMAP__
	boolean_t force_coarse_physmap = TRUE;
#else
	boolean_t force_coarse_physmap = FALSE;
#endif
	/*
	 * Enforce W^X protections on segments that have been identified so far. This will be
	 * further refined for each KEXT's TEXT and DATA segments in readPrelinkedExtensions() 
	 */
	
	/*
	 * Protection on kernel text is loose here to allow shenanigans early on (e.g. copying exception vectors)
	 * and storing an address into "error_buffer" (see arm_init.c) !?!
	 * These protections are tightened in arm_vm_prot_finalize()
	 */
	arm_vm_page_granular_RWX(gVirtBase, segSizeTEXT + (segTEXTB - gVirtBase), FALSE);

	if (doconstro) {
		/*
		 * We map __DATA with 3 calls, so that the __const section can have its
		 * protections changed independently of the rest of the __DATA segment.
		 */
		arm_vm_page_granular_RWNX(segDATAB, sectCONSTB - segDATAB, FALSE);
		arm_vm_page_granular_RNX(sectCONSTB, sectSizeCONST, FALSE);
		arm_vm_page_granular_RWNX(sectCONSTB + sectSizeCONST, (segDATAB + segSizeDATA) - (sectCONSTB + sectSizeCONST), FALSE);
	} else {
		/* If we aren't protecting const, just map DATA as a single blob. */
		arm_vm_page_granular_RWNX(segDATAB, segSizeDATA, FALSE);
	}

	arm_vm_page_granular_ROX(segKLDB, segSizeKLD, force_coarse_physmap);
	arm_vm_page_granular_RWNX(segLINKB, segSizeLINK, force_coarse_physmap);
	arm_vm_page_granular_RWNX(segLASTB, segSizeLAST, FALSE); // __LAST may be empty, but we cannot assume this
	arm_vm_page_granular_RWNX(segPRELINKTEXTB, segSizePRELINKTEXT, TRUE); // Refined in OSKext::readPrelinkedExtensions
	arm_vm_page_granular_RWNX(segPRELINKTEXTB + segSizePRELINKTEXT,
	                             end_kern - (segPRELINKTEXTB + segSizePRELINKTEXT), force_coarse_physmap); // PreLinkInfoDictionary
	arm_vm_page_granular_RWNX(end_kern, phystokv(args->topOfKernelData) - end_kern, force_coarse_physmap); // Device Tree, RAM Disk (if present), bootArgs
	arm_vm_page_granular_RWNX(phystokv(args->topOfKernelData), ARM_PGBYTES * 8, FALSE); // boot_tte, cpu_tte

	/*
	 * FIXME: Any page table pages that arm_vm_page_granular_* created with ROX entries in the range
	 * phystokv(args->topOfKernelData) to phystokv(prot_avail_start) should themselves be
	 * write protected in the static mapping of that range.
	 * [Page table pages whose page table entries grant execute (X) privileges should themselves be
	 * marked read-only. This aims to thwart attacks that replace the X entries with vectors to evil code
	 * (relying on some thread of execution to eventually arrive at what previously was a trusted routine).]
	 */
	arm_vm_page_granular_RWNX(phystokv(args->topOfKernelData) + ARM_PGBYTES * 8, ARM_PGBYTES, FALSE); /* Excess physMem over 1MB */
	arm_vm_page_granular_RWX(phystokv(args->topOfKernelData) + ARM_PGBYTES * 9, ARM_PGBYTES, FALSE); /* refined in finalize */

	/* Map the remainder of xnu owned memory. */
	arm_vm_page_granular_RWNX(phystokv(args->topOfKernelData) + ARM_PGBYTES * 10,
	                          static_memory_end - (phystokv(args->topOfKernelData) + ARM_PGBYTES * 10), force_coarse_physmap); /* rest of physmem */

	/*
	 * Special case write protection for the mapping of ExceptionVectorsBase (EVB) at 0xFFFF0000.
	 * Recall that start.s handcrafted a page table page for EVB mapping
	 */
	pmap_paddr_t p = (pmap_paddr_t)(args->topOfKernelData) + (ARM_PGBYTES * 9);
	pt_entry_t *ppte = (pt_entry_t *)phystokv(p);

	int idx = (HIGH_EXC_VECTORS & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT;
	pt_entry_t ptmp = ppte[idx];

	ptmp = (ptmp & ~ARM_PTE_APMASK) | ARM_PTE_AP(AP_RONA);

	ppte[idx] = ptmp;
}

void
arm_vm_prot_finalize(boot_args * args)
{
	/*
	 * Naively we could have:
	 * arm_vm_page_granular_ROX(segTEXTB, segSizeTEXT, FALSE);
	 * but, at present, that would miss a 1Mb boundary at the beginning of the segment and
	 * so would force a (wasteful) coarse page (e.g. when gVirtBase is 0x80000000, segTEXTB is 0x80001000).
	 */
	arm_vm_page_granular_ROX(gVirtBase, segSizeTEXT + (segTEXTB - gVirtBase), FALSE);

	arm_vm_page_granular_RWNX(phystokv(args->topOfKernelData) + ARM_PGBYTES * 9, ARM_PGBYTES, FALSE); /* commpage, EVB */

#ifndef  __ARM_L1_PTW__
	FlushPoC_Dcache();
#endif
	flush_mmu_tlb();
}

void
arm_vm_init(uint64_t memory_size, boot_args * args)
{
	vm_map_address_t va, off, off_end;
	tt_entry_t       *tte, *tte_limit;
	pmap_paddr_t     boot_ttep;
	tt_entry_t       *boot_tte;
	uint32_t         mem_segments;
	kernel_section_t *sectDCONST;

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

	/* Calculate the nubmer of ~256MB segments of memory */
	mem_segments = (mem_size + 0x0FFFFFFF) >> 28;

	/*
	 * Copy the boot mmu tt to create system mmu tt.
	 * System mmu tt start after the boot mmu tt.
	 * Determine translation table base virtual address: - aligned at end
	 * of executable.
	 */
	boot_ttep = args->topOfKernelData;
	boot_tte = (tt_entry_t *) phystokv(boot_ttep);

	cpu_ttep = boot_ttep + ARM_PGBYTES * 4;
	cpu_tte = (tt_entry_t *) phystokv(cpu_ttep);

	bcopy(boot_tte, cpu_tte, ARM_PGBYTES * 4);

	/*
	 * Clear out any V==P mappings that may have been established in e.g. start.s
	 */
	tte = &cpu_tte[ttenum(gPhysBase)];
	tte_limit = &cpu_tte[ttenum(gPhysBase + gPhysSize)];

	/* Hands off [gVirtBase, gVirtBase + gPhysSize) please. */
	if (gPhysBase < gVirtBase) {
		if (gPhysBase + gPhysSize > gVirtBase)
			tte_limit = &cpu_tte[ttenum(gVirtBase)];
	} else {
		if (gPhysBase < gVirtBase + gPhysSize)
			tte = &cpu_tte[ttenum(gVirtBase + gPhysSize)];
	}

	while (tte < tte_limit) {
			*tte = ARM_TTE_TYPE_FAULT; 
			tte++;
		}
		
	/* Skip 6 pages (four L1 + two L2 entries) */
	avail_start = cpu_ttep + ARM_PGBYTES * 6;
	avail_end = gPhysBase + mem_size;

	/*
	 * Now retrieve addresses for end, edata, and etext
	 * from MACH-O headers for the currently running 32 bit kernel.
	 */
	segTEXTB = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__TEXT", &segSizeTEXT);
	segDATAB = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__DATA", &segSizeDATA);
	segLINKB = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__LINKEDIT", &segSizeLINK);
	segKLDB = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__KLD", &segSizeKLD);
	segLASTB = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__LAST", &segSizeLAST);
	segPRELINKTEXTB = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__PRELINK_TEXT", &segSizePRELINKTEXT);
	segPRELINKINFOB = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__PRELINK_INFO", &segSizePRELINKINFO);

	etext = (vm_offset_t) segTEXTB + segSizeTEXT;
	sdata = (vm_offset_t) segDATAB;
	edata = (vm_offset_t) segDATAB + segSizeDATA;
	end_kern = round_page(getlastaddr());   /* Force end to next page */

	/*
	 * Special handling for the __DATA,__const *section*.
	 * A page of padding named lastkerneldataconst is at the end of the __DATA,__const
	 * so we can safely truncate the size. __DATA,__const is also aligned, but
	 * just in case we will round that to a page, too. 
	 */
	segDATA = getsegbynamefromheader(&_mh_execute_header, "__DATA");
	sectDCONST = getsectbynamefromheader(&_mh_execute_header, "__DATA", "__const");
	sectCONSTB = sectDCONST->addr;
	sectSizeCONST = sectDCONST->size;

#if !SECURE_KERNEL
	/* doconstro is true by default, but we allow a boot-arg to disable it */
	(void) PE_parse_boot_argn("dataconstro", &doconstro, sizeof(doconstro));
#endif

	if (doconstro) {
		extern vm_offset_t _lastkerneldataconst;
		extern vm_size_t _lastkerneldataconst_padsize;
		vm_offset_t sdataconst = sectCONSTB;

		/* this should already be aligned, but so that we can protect we round */
		sectCONSTB = round_page(sectCONSTB);

		/* make sure lastkerneldataconst is really last and the right size */
		if ((_lastkerneldataconst == sdataconst + sectSizeCONST - _lastkerneldataconst_padsize) &&
		    (_lastkerneldataconst_padsize >= PAGE_SIZE)) {
			sectSizeCONST = trunc_page(sectSizeCONST);
		} else {
			/* otherwise see if next section is aligned then protect up to it */
			kernel_section_t *next_sect = nextsect(segDATA, sectDCONST);

			if (next_sect && ((next_sect->addr & PAGE_MASK) == 0)) {
				sectSizeCONST = next_sect->addr - sectCONSTB;
			} else {
				/* lastly just go ahead and truncate so we try to protect something */
				sectSizeCONST = trunc_page(sectSizeCONST);
			}
		}

		/* sanity check */
		if ((sectSizeCONST == 0) || (sectCONSTB < sdata) || (sectCONSTB + sectSizeCONST) >= edata) {
			doconstro = FALSE;
		}
	}

	vm_set_page_size();

#ifndef __ARM_L1_PTW__
	FlushPoC_Dcache();
#endif
	set_mmu_ttb(cpu_ttep);
	set_mmu_ttb_alternate(cpu_ttep);
	flush_mmu_tlb();
#if __arm__ && __ARM_USER_PROTECT__
	{
		unsigned int ttbr0_val, ttbr1_val, ttbcr_val;
		thread_t thread = current_thread();

		__asm__ volatile("mrc p15,0,%0,c2,c0,0\n" : "=r"(ttbr0_val));
		__asm__ volatile("mrc p15,0,%0,c2,c0,1\n" : "=r"(ttbr1_val));
		__asm__ volatile("mrc p15,0,%0,c2,c0,2\n" : "=r"(ttbcr_val));
		thread->machine.uptw_ttb = ttbr0_val;
		thread->machine.kptw_ttb = ttbr1_val;
		thread->machine.uptw_ttc = ttbcr_val;
	}
#endif
	vm_prelink_stext = segPRELINKTEXTB;
	vm_prelink_etext = segPRELINKTEXTB + segSizePRELINKTEXT;
	vm_prelink_sinfo = segPRELINKINFOB;
	vm_prelink_einfo = segPRELINKINFOB + segSizePRELINKINFO;
	vm_slinkedit = segLINKB;
	vm_elinkedit = segLINKB + segSizeLINK;

	sane_size = mem_size - (avail_start - gPhysBase);
	max_mem = mem_size;
	vm_kernel_slide = gVirtBase-0x80000000;
	vm_kernel_stext = segTEXTB;
	vm_kernel_etext = segTEXTB + segSizeTEXT;
	vm_kernel_base = gVirtBase;
	vm_kernel_top = (vm_offset_t) &last_kernel_symbol;
	vm_kext_base = segPRELINKTEXTB;
	vm_kext_top = vm_kext_base + segSizePRELINKTEXT;
	vm_kernel_slid_base = segTEXTB;
	vm_kernel_slid_top = vm_kext_top;

	pmap_bootstrap((gVirtBase+MEM_SIZE_MAX+0x3FFFFF) & 0xFFC00000);

	arm_vm_prot_init(args);

	/*
	 * To avoid recursing while trying to init the vm_page and object * mechanisms,
	 * pre-initialize kernel pmap page table pages to cover this address range:
	 *    2MB + FrameBuffer size + 3MB for each 256MB segment
	 */
	off_end = (2 + (mem_segments * 3)) << 20;
	off_end += (unsigned int) round_page(args->Video.v_height * args->Video.v_rowBytes);

	for (off = 0, va = (gVirtBase+MEM_SIZE_MAX+0x3FFFFF) & 0xFFC00000; off < off_end; off += ARM_TT_L1_PT_SIZE) {
		pt_entry_t   *ptp;
		pmap_paddr_t ptp_phys;

		ptp = (pt_entry_t *) phystokv(avail_start);
		ptp_phys = (pmap_paddr_t)avail_start;
		avail_start += ARM_PGBYTES;
		pmap_init_pte_page(kernel_pmap, ptp, va + off, 2, TRUE);
		tte = &cpu_tte[ttenum(va + off)];
		*tte     = pa_to_tte((ptp_phys        )) | ARM_TTE_TYPE_TABLE;;
		*(tte+1) = pa_to_tte((ptp_phys + 0x400)) | ARM_TTE_TYPE_TABLE;;
		*(tte+2) = pa_to_tte((ptp_phys + 0x800)) | ARM_TTE_TYPE_TABLE;;
		*(tte+3) = pa_to_tte((ptp_phys + 0xC00)) | ARM_TTE_TYPE_TABLE;;
	}

	avail_start = (avail_start + PAGE_MASK) & ~PAGE_MASK;

	first_avail = avail_start;
	patch_low_glo_static_region(args->topOfKernelData, avail_start - args->topOfKernelData);
}


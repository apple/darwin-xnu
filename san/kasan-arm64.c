/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
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

#include <stdint.h>
#include <string.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <kern/assert.h>
#include <machine/machine_routines.h>
#include <kern/locks.h>
#include <kern/simple_lock.h>
#include <kern/debug.h>
#include <mach/mach_vm.h>
#include <mach/vm_param.h>
#include <libkern/libkern.h>
#include <sys/queue.h>
#include <vm/pmap.h>
#include <kasan.h>
#include <kasan_internal.h>
#include <memintrinsics.h>

#include <pexpert/arm64/boot.h>
#include <arm64/proc_reg.h>

#include <libkern/kernel_mach_header.h>

extern uint64_t *cpu_tte;
extern unsigned long gVirtBase, gPhysBase;

typedef uint64_t pmap_paddr_t;
extern vm_map_address_t phystokv(pmap_paddr_t pa);

vm_offset_t physmap_vbase;
vm_offset_t physmap_vtop;

vm_offset_t shadow_pbase;
vm_offset_t shadow_ptop;
static vm_offset_t shadow_pnext;

static vm_offset_t zero_page_phys;
static vm_offset_t bootstrap_pgtable_phys;

extern vm_offset_t intstack, intstack_top;
extern vm_offset_t excepstack, excepstack_top;

void kasan_bootstrap(boot_args *, vm_offset_t pgtable);
void flush_mmu_tlb(void);

#define KASAN_SHIFT_ARM64 0xdffffff800000000ULL /* Defined in makedefs/MakeInc.def */
#define KASAN_SHADOW_MIN  0xfffffff400000000ULL
#define KASAN_SHADOW_MAX  0xfffffff680000000ULL

_Static_assert(KASAN_SHIFT == KASAN_SHIFT_ARM64, "KASan inconsistent shadow shift");
_Static_assert(VM_MAX_KERNEL_ADDRESS < KASAN_SHADOW_MIN, "KASan shadow overlaps with kernel VM");
_Static_assert((VM_MIN_KERNEL_ADDRESS >> 3) + KASAN_SHIFT_ARM64 >= KASAN_SHADOW_MIN, "KASan shadow does not cover kernel VM");
_Static_assert((VM_MAX_KERNEL_ADDRESS >> 3) + KASAN_SHIFT_ARM64 < KASAN_SHADOW_MAX,  "KASan shadow does not cover kernel VM");

static uintptr_t
alloc_page(void)
{
	if (shadow_pnext + ARM_PGBYTES >= shadow_ptop) {
		panic("KASAN: OOM");
	}

	uintptr_t mem = shadow_pnext;
	shadow_pnext += ARM_PGBYTES;
	shadow_pages_used++;

	return mem;
}

static uintptr_t
alloc_zero_page(void)
{
	uintptr_t mem = alloc_page();
	__nosan_bzero((void *)phystokv(mem), ARM_PGBYTES);
	return mem;
}

static void
align_to_page(vm_offset_t *addrp, vm_offset_t *sizep)
{
	vm_offset_t addr_aligned = vm_map_trunc_page(*addrp, ARM_PGMASK);
	*sizep = vm_map_round_page(*sizep + (*addrp - addr_aligned), ARM_PGMASK);
	*addrp = addr_aligned;
}

static void
kasan_map_shadow_internal(vm_offset_t address, vm_size_t size, bool is_zero, bool back_page)
{
	size = (size + 0x7UL) & ~0x7UL;
	vm_offset_t shadow_base = vm_map_trunc_page(SHADOW_FOR_ADDRESS(address), ARM_PGMASK);
	vm_offset_t shadow_top = vm_map_round_page(SHADOW_FOR_ADDRESS(address + size), ARM_PGMASK);

	assert(shadow_base >= KASAN_SHADOW_MIN && shadow_top <= KASAN_SHADOW_MAX);
	assert((size & 0x7) == 0);

	for (; shadow_base < shadow_top; shadow_base += ARM_PGBYTES) {
		uint64_t *base = cpu_tte;
		uint64_t *pte;

#if !__ARM64_TWO_LEVEL_PMAP__
		/* lookup L1 entry */
		pte = base + ((shadow_base & ARM_TT_L1_INDEX_MASK) >> ARM_TT_L1_SHIFT);
		if (*pte & ARM_TTE_VALID) {
			assert((*pte & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE);
		} else {
			/* create new L1 table */
			*pte = ((uint64_t)alloc_zero_page() & ARM_TTE_TABLE_MASK) | ARM_TTE_VALID | ARM_TTE_TYPE_TABLE;
		}
		base = (uint64_t *)phystokv(*pte & ARM_TTE_TABLE_MASK);
#endif

		/* lookup L2 entry */
		pte = base + ((shadow_base & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT);
		if (*pte & ARM_TTE_VALID) {
			assert((*pte & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE);
		} else {
			/* create new L3 table */
			*pte = ((uint64_t)alloc_zero_page() & ARM_TTE_TABLE_MASK) | ARM_TTE_VALID | ARM_TTE_TYPE_TABLE;
		}
		base = (uint64_t *)phystokv(*pte & ARM_TTE_TABLE_MASK);

		if (!back_page) {
			continue;
		}

		/* lookup L3 entry */
		pte = base + ((shadow_base & ARM_TT_L3_INDEX_MASK) >> ARM_TT_L3_SHIFT);
		if ((*pte & ARM_PTE_TYPE_VALID) &&
		    ((((*pte) & ARM_PTE_APMASK) != ARM_PTE_AP(AP_RONA)) || is_zero)) {
			/* nothing to do - page already mapped and we are not
			 * upgrading */
		} else {
			/* create new L3 entry */
			uint64_t newpte;
			if (is_zero) {
				/* map the zero page RO */
				newpte = (uint64_t)zero_page_phys | ARM_PTE_AP(AP_RONA);
			} else {
				/* map a fresh page RW */
				newpte = (uint64_t)alloc_zero_page() | ARM_PTE_AP(AP_RWNA);
			}
			newpte |= ARM_PTE_TYPE_VALID
				| ARM_PTE_AF
				| ARM_PTE_SH(SH_OUTER_MEMORY)
				| ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DEFAULT)
				| ARM_PTE_NX
				| ARM_PTE_PNX;
			*pte = newpte;
		}
	}

	flush_mmu_tlb();
}

void
kasan_map_shadow(vm_offset_t address, vm_size_t size, bool is_zero)
{
	kasan_map_shadow_internal(address, size, is_zero, true);
}

/*
 * TODO: mappings here can be reclaimed after kasan_init()
 */
static void
kasan_map_shadow_early(vm_offset_t address, vm_size_t size, bool is_zero)
{
	align_to_page(&address, &size);

	vm_size_t j;
	uint64_t *pte;

	for (j = 0; j < size; j += ARM_PGBYTES) {
		vm_offset_t virt_shadow_target = (vm_offset_t)SHADOW_FOR_ADDRESS(address + j);

		assert(virt_shadow_target >= KASAN_SHADOW_MIN);
		assert(virt_shadow_target < KASAN_SHADOW_MAX);

		uint64_t *base = (uint64_t *)bootstrap_pgtable_phys;

#if !__ARM64_TWO_LEVEL_PMAP__
		/* lookup L1 entry */
		pte = base + ((virt_shadow_target & ARM_TT_L1_INDEX_MASK) >> ARM_TT_L1_SHIFT);
		if (*pte & ARM_TTE_VALID) {
			assert((*pte & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE);
		} else {
			/* create new L1 table */
			vm_address_t pg = alloc_page();
			__nosan_bzero((void *)pg, ARM_PGBYTES);
			*pte = ((uint64_t)pg & ARM_TTE_TABLE_MASK) | ARM_TTE_VALID | ARM_TTE_TYPE_TABLE;
		}
		base = (uint64_t *)(*pte & ARM_TTE_TABLE_MASK);
#endif

		/* lookup L2 entry */
		pte = base + ((virt_shadow_target & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT);
		if (*pte & ARM_TTE_VALID) {
			assert((*pte & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE);
		} else {
			/* create new L3 table */
			vm_address_t pg = alloc_page();
			__nosan_bzero((void *)pg, ARM_PGBYTES);
			*pte = ((uint64_t)pg & ARM_TTE_TABLE_MASK) | ARM_TTE_VALID | ARM_TTE_TYPE_TABLE;
		}
		base = (uint64_t *)(*pte & ARM_TTE_TABLE_MASK);

		/* lookup L3 entry */
		pte = base + ((virt_shadow_target & ARM_TT_L3_INDEX_MASK) >> ARM_TT_L3_SHIFT);

		if ((*pte & (ARM_PTE_TYPE|ARM_PTE_APMASK)) == (ARM_PTE_TYPE_VALID|ARM_PTE_AP(AP_RWNA))) {
			/* L3 entry valid and mapped RW - do nothing */
		} else {
			/* Not mapped, or mapped RO - create new L3 entry or upgrade to RW */

			uint64_t newpte;
			if (is_zero) {
				/* map the zero page RO */
				newpte = (uint64_t)zero_page_phys | ARM_PTE_AP(AP_RONA);
			} else {
				/* map a fresh page RW */
				vm_address_t pg = alloc_page();
				__nosan_bzero((void *)pg, ARM_PGBYTES);
				newpte = pg | ARM_PTE_AP(AP_RWNA);
			}

			/* add the default attributes */
			newpte |= ARM_PTE_TYPE_VALID
				| ARM_PTE_AF
				| ARM_PTE_SH(SH_OUTER_MEMORY)
				| ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DEFAULT)
				| ARM_PTE_NX
				| ARM_PTE_PNX;

			*pte = newpte;
		}
	}

	flush_mmu_tlb();
}

void
kasan_arch_init(void)
{
	/* Map the physical aperture */
	kasan_map_shadow(kernel_vtop, physmap_vtop - kernel_vtop, true);

#if defined(KERNEL_INTEGRITY_KTRR)
	/* Pre-allocate all the L3 page table pages to avoid triggering KTRR */
	kasan_map_shadow_internal(VM_MIN_KERNEL_ADDRESS, VM_MAX_KERNEL_ADDRESS - VM_MIN_KERNEL_ADDRESS + 1, false, false);
#endif
}

/*
 * Steal memory for the shadow, and shadow map the bootstrap page tables so we can
 * run until kasan_init(). Called while running with identity (V=P) map active.
 */
void
kasan_bootstrap(boot_args *args, vm_offset_t pgtable)
{
	uintptr_t tosteal;

	vm_address_t pbase = args->physBase;
	vm_address_t ptop = args->topOfKernelData;
	vm_offset_t extra = (vm_offset_t)&_mh_execute_header - pbase;

	kernel_vbase = args->virtBase;
	kernel_vtop = args->virtBase + ptop - pbase;

	tosteal = (args->memSize * STOLEN_MEM_PERCENT) / 100 + STOLEN_MEM_BYTES;
	tosteal = vm_map_trunc_page(tosteal, ARM_PGMASK);

	args->memSize -= tosteal;

	/* Initialize the page allocator */
	shadow_pbase = vm_map_round_page(pbase + args->memSize, ARM_PGMASK);
	shadow_ptop = shadow_pbase + tosteal;
	shadow_pnext = shadow_pbase;
	shadow_pages_total = (long)((shadow_ptop - shadow_pbase) / ARM_PGBYTES);

	/* Set aside a page of zeros we can use for dummy shadow mappings */
	zero_page_phys = alloc_page();
	__nosan_bzero((void *)zero_page_phys, ARM_PGBYTES);

	/* Shadow the KVA bootstrap mapping: start of kernel Mach-O to end of physical */
	bootstrap_pgtable_phys = pgtable;
	kasan_map_shadow_early(kernel_vbase + extra, args->memSize - extra, true);

	/* Shadow the early stacks */
	vm_offset_t p2v = args->virtBase - args->physBase;

	vm_offset_t intstack_virt = (vm_offset_t)&intstack + p2v;
	vm_offset_t excepstack_virt = (vm_offset_t)&excepstack + p2v;
	vm_offset_t intstack_size = (vm_offset_t)&intstack_top - (vm_offset_t)&intstack;
	vm_offset_t excepstack_size = (vm_offset_t)&excepstack_top - (vm_offset_t)&excepstack;

	kasan_map_shadow_early(intstack_virt, intstack_size, false);
	kasan_map_shadow_early(excepstack_virt, excepstack_size, false);
}

bool
kasan_is_shadow_mapped(uintptr_t shadowp)
{
	uint64_t *pte;
	uint64_t *base = cpu_tte;

	assert(shadowp >= KASAN_SHADOW_MIN);
	assert(shadowp < KASAN_SHADOW_MAX);

#if !__ARM64_TWO_LEVEL_PMAP__
	/* lookup L1 entry */
	pte = base + ((shadowp & ARM_TT_L1_INDEX_MASK) >> ARM_TT_L1_SHIFT);
	if (!(*pte & ARM_TTE_VALID)) {
		return false;
	}
	base = (uint64_t *)phystokv(*pte & ARM_TTE_TABLE_MASK);
#endif

	/* lookup L2 entry */
	pte = base + ((shadowp & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT);
	if (!(*pte & ARM_TTE_VALID)) {
		return false;
	}
	base = (uint64_t *)phystokv(*pte & ARM_TTE_TABLE_MASK);

	/* lookup L3 entry */
	pte = base + ((shadowp & ARM_TT_L3_INDEX_MASK) >> ARM_TT_L3_SHIFT);
	if (!(*pte & ARM_PTE_TYPE_VALID)) {
		return false;
	}

	return true;
}

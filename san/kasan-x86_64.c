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
#include <i386/proc_reg.h>
#include <i386/machine_routines.h>
#include <kern/debug.h>
#include <mach/mach_vm.h>
#include <mach/vm_param.h>
#include <libkern/libkern.h>
#include <pexpert/i386/efi.h>
#include <pexpert/i386/boot.h>
#include <sys/queue.h>
#include <kasan.h>
#include <kasan_internal.h>
#include <vm/pmap.h>
#include <pexpert/i386/efi.h>
#include <pexpert/i386/boot.h>
#include <memintrinsics.h>

extern uint64_t *IdlePML4;
extern uintptr_t physmap_base;
extern uintptr_t physmap_max;
#define phys2virt(x) ((uintptr_t)(x) + physmap_base)

#define INTEL_PTE_VALID         0x00000001ULL
#define INTEL_PTE_WRITE         0x00000002ULL
#define INTEL_PTE_RW            0x00000002ULL
#define INTEL_PTE_USER          0x00000004ULL
#define INTEL_PTE_WTHRU         0x00000008ULL
#define INTEL_PTE_NCACHE        0x00000010ULL
#define INTEL_PTE_REF           0x00000020ULL
#define INTEL_PTE_MOD           0x00000040ULL
#define INTEL_PTE_PS            0x00000080ULL
#define INTEL_PTE_PTA           0x00000080ULL
#define INTEL_PTE_GLOBAL        0x00000100ULL
#define INTEL_PTE_WIRED         0x00000200ULL
#define INTEL_PDPTE_NESTED      0x00000400ULL
#define INTEL_PTE_PFN           PG_FRAME
#define INTEL_PTE_NX            (1ULL << 63)
#define INTEL_PTE_INVALID       0

vm_offset_t shadow_pbase;
vm_offset_t shadow_ptop;
vm_offset_t shadow_pnext;
unsigned shadow_stolen_idx;

static vm_offset_t zero_superpage_phys;

typedef struct {
  unsigned int pml4   : 9;
  unsigned int pdpt   : 9;
  unsigned int pd     : 9;
  unsigned int pt     : 9;
  unsigned int offset : 12;
} split_addr_t;

static split_addr_t
split_address(vm_offset_t address)
{
	split_addr_t addr;

	addr.pml4   = (address >> 39) & 0x1ff;
	addr.pdpt   = (address >> 30) & 0x1ff;
	addr.pd     = (address >> 21) & 0x1ff;
	addr.pt     = (address >> 12) & 0x1ff;
	// addr.offset = address & PAGE_MASK;

	return addr;
}

static uintptr_t
alloc_page(void)
{
	if (shadow_pnext + I386_PGBYTES >= shadow_ptop) {
		panic("KASAN: OOM");
	}

	uintptr_t mem = shadow_pnext;
	shadow_pnext += I386_PGBYTES;
	shadow_pages_used++;

	return mem;
}

#define ROUND_SUPERPAGE(x) ((((uintptr_t)(x)) + I386_LPGBYTES - 1) & ~(I386_LPGMASK))

static uintptr_t
alloc_superpage(void)
{
	uintptr_t mem;
	shadow_pnext = ROUND_SUPERPAGE(shadow_pnext);
	assert((shadow_pnext & I386_LPGMASK) == 0);
	mem = shadow_pnext;
	shadow_pnext += I386_LPGBYTES;
	shadow_pages_used += I386_LPGBYTES / I386_PGBYTES;
	/* XXX: not accounting for superpage rounding */
	return mem;
}

static uintptr_t
alloc_page_zero(void)
{
	uintptr_t mem = alloc_page();
	bzero_phys(mem, I386_PGBYTES);
	return mem;
}

static void
kasan_map_shadow_superpage_zero(vm_offset_t address, vm_size_t size)
{
	address = vm_map_trunc_page(address, I386_LPGMASK);
	size = vm_map_round_page(size, I386_LPGMASK);

	vm_size_t j;
	for (j = 0; j < size; j += I386_LPGBYTES * 8) {

		vm_offset_t virt_shadow_target = (vm_offset_t)SHADOW_FOR_ADDRESS(address + j);

		split_addr_t addr = split_address(virt_shadow_target);
		assert(addr.pml4 == 507 || addr.pml4 == 508);

		uint64_t *L3;
		uint64_t *L2;
		uint64_t *L1;

		L3 = (uint64_t *)(IdlePML4[addr.pml4] & ~PAGE_MASK);
		if (L3 == NULL) {
			uintptr_t pmem = alloc_page_zero();
			L3 = (uint64_t *)phys2virt(pmem);
			IdlePML4[addr.pml4] = pmem
				| INTEL_PTE_VALID
				| INTEL_PTE_WRITE;
		} else {
			L3 = (uint64_t *)phys2virt(L3);
		}

		L2 = (uint64_t *)(L3[addr.pdpt] & ~PAGE_MASK);
		if (L2 == NULL) {
			uintptr_t pmem = alloc_page_zero();
			L2 = (uint64_t *)phys2virt(pmem);
			L3[addr.pdpt] = pmem
				| INTEL_PTE_VALID
				| INTEL_PTE_WRITE;
		} else {
			L2 = (uint64_t *)phys2virt(L2);
		}

		L1 = (uint64_t *)(L2[addr.pd] & ~PAGE_MASK);
		if (L1 == NULL) {
			L2[addr.pd] = (uint64_t)zero_superpage_phys
				| INTEL_PTE_VALID
				| INTEL_PTE_PS
				| INTEL_PTE_NX;
		} else {
			panic("Unexpected shadow mapping, addr =  %lx, sz = %lu\n",
					address, size);
		}

		/* adding a new entry, this is not strictly required */
		invlpg(virt_shadow_target);
	}
}

void
kasan_map_shadow(vm_offset_t address, vm_size_t size, bool is_zero)
{
	vm_offset_t shadow_base = vm_map_trunc_page(SHADOW_FOR_ADDRESS(address), PAGE_MASK);
	vm_offset_t shadow_top = vm_map_round_page(SHADOW_FOR_ADDRESS(address + size), PAGE_MASK);

	for (; shadow_base < shadow_top; shadow_base += I386_PGBYTES) {

		split_addr_t addr = split_address(shadow_base);
		assert(addr.pml4 == 507 || addr.pml4 == 508);

		uint64_t *L3;
		uint64_t *L2;
		uint64_t *L1;
		uint64_t *pte;

		L3 = (uint64_t *)(IdlePML4[addr.pml4] & ~PAGE_MASK);
		if (L3 == NULL) {
			uintptr_t pmem = alloc_page_zero();
			L3 = (uint64_t *)phys2virt(pmem);
			IdlePML4[addr.pml4] = pmem
				| INTEL_PTE_VALID
				| INTEL_PTE_WRITE;
		} else {
			L3 = (uint64_t *)phys2virt(L3);
		}

		L2 = (uint64_t *)(L3[addr.pdpt] & ~PAGE_MASK);
		if (L2 == NULL) {
			uintptr_t pmem = alloc_page_zero();
			L2 = (uint64_t *)phys2virt(pmem);
			L3[addr.pdpt] = pmem
				| INTEL_PTE_VALID
				| INTEL_PTE_WRITE;
		} else {
			L2 = (uint64_t *)phys2virt(L2);
		}

		uint64_t pde = L2[addr.pd];
		if ((pde & (INTEL_PTE_VALID|INTEL_PTE_PS)) == (INTEL_PTE_VALID|INTEL_PTE_PS)) {
			/* Already mapped as a superpage */
			continue;
		}

		L1 = (uint64_t *)(pde & ~PAGE_MASK);
		if (L1 == NULL) {
			uintptr_t pmem = alloc_page_zero();
			L1 = (uint64_t *)phys2virt(pmem);
			L2[addr.pd] = pmem
				| INTEL_PTE_VALID
				| INTEL_PTE_WRITE;
		} else {
			L1 = (uint64_t *)phys2virt(L1);
		}

		pte = (uint64_t *)(L1[addr.pt] & ~PAGE_MASK);
		if (pte == NULL) {
			uint64_t newpte;
			if (is_zero) {
				newpte = (uint64_t)zero_superpage_phys;
			} else {
				newpte = (vm_offset_t)alloc_page_zero()
					| INTEL_PTE_WRITE;
			}
			L1[addr.pt] = newpte
				| INTEL_PTE_VALID
				| INTEL_PTE_NX;

			/* adding a new entry, this is not strictly required */
			invlpg(shadow_base);
		}
	}
}

void
kasan_arch_init(void)
{
	__nosan_bzero((void *)phys2virt(zero_superpage_phys), I386_LPGBYTES);

	/* Map the physical aperture */
	kasan_map_shadow_superpage_zero(physmap_base, physmap_max - physmap_base);
}

/*
 * Steal some memory from EFI for the shadow map.
 */
void
kasan_reserve_memory(void *_args)
{
	boot_args *args = (boot_args *)_args;
	vm_address_t pbase = args->kaddr;
	vm_address_t ptop = args->kaddr + args->ksize;

	kernel_vbase = ml_static_ptovirt(pbase);
	kernel_vtop = ml_static_ptovirt(ptop);

	EfiMemoryRange *mptr, *mptr_tmp;
	unsigned int mcount;
	unsigned int msize;
	unsigned int i;
	unsigned long total_pages;
	unsigned long to_steal;

	mptr = (EfiMemoryRange *)ml_static_ptovirt((vm_offset_t)args->MemoryMap);
	msize = args->MemoryMapDescriptorSize;
	mcount = args->MemoryMapSize / msize;

	/* sum total physical memory */
	total_pages = 0;
	for (i = 0, mptr_tmp = mptr; i < mcount; i++, mptr_tmp = (EfiMemoryRange *)(((vm_offset_t)mptr_tmp) + msize)) {
		total_pages += mptr_tmp->NumberOfPages;
	}

	to_steal = (total_pages * STOLEN_MEM_PERCENT) / 100 + (STOLEN_MEM_BYTES / I386_PGBYTES);

	/* Search for a range large enough to steal from */
	for (i = 0, mptr_tmp = mptr; i < mcount; i++, mptr_tmp = (EfiMemoryRange *)(((vm_offset_t)mptr_tmp) + msize)) {
		ppnum_t base, top;
		base = (ppnum_t)(mptr_tmp->PhysicalStart >> I386_PGSHIFT);
		top = (ppnum_t)((mptr_tmp->PhysicalStart >> I386_PGSHIFT) + mptr_tmp->NumberOfPages - 1);

		if ((mptr_tmp->Type == kEfiConventionalMemory) && (mptr_tmp->NumberOfPages > to_steal)) {
			/* Found a region with sufficient space - steal from the end */
			mptr_tmp->NumberOfPages -= to_steal;

			shadow_pbase = mptr_tmp->PhysicalStart + (mptr_tmp->NumberOfPages << I386_PGSHIFT);
			shadow_ptop = shadow_pbase + (to_steal << I386_PGSHIFT);
			shadow_pnext = shadow_pbase;
			shadow_pages_total = to_steal;
			shadow_stolen_idx = i;

			/* Set aside a page of zeros we can use for dummy shadow mappings */
			zero_superpage_phys = alloc_superpage();

			return;
		}
	}

	panic("KASAN: could not reserve memory");
}

bool
kasan_is_shadow_mapped(uintptr_t shadowp)
{
	split_addr_t addr = split_address(shadowp);
	assert(addr.pml4 == 507 || addr.pml4 == 508);

	uint64_t *L3;
	uint64_t *L2;
	uint64_t *L1;

	L3 = (uint64_t *)(IdlePML4[addr.pml4] & ~PAGE_MASK);
	if (L3 == NULL) {
		return false;
	}
	L3 = (uint64_t *)phys2virt(L3);

	L2 = (uint64_t *)(L3[addr.pdpt] & ~PAGE_MASK);
	if (L2 == NULL) {
		return false;
	}
	L2 = (uint64_t *)phys2virt(L2);

	uint64_t pde = L2[addr.pd];
	if ((pde & (INTEL_PTE_VALID|INTEL_PTE_PS)) == (INTEL_PTE_VALID|INTEL_PTE_PS)) {
		/* mapped as superpage */
		return true;
	}
	L1 = (uint64_t *)(pde & ~PAGE_MASK);
	if (L1 == NULL) {
		return false;
	}
	L1 = (uint64_t *)phys2virt(L1);

	if (L1[addr.pt] & INTEL_PTE_VALID) {
		return true;
	}

	return false;
}

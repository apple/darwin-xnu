/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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
/*!
 * ARM64-specific functions required to support hibernation entry, and also to
 * support hibernation exit after wired pages have already been restored.
 */

#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/kalloc.h>
#include <mach/machine.h>
#include <mach/processor_info.h>
#include <mach/mach_types.h>
#include <kern/cpu_data.h>
#include <kern/startup.h>
#include <IOKit/IOPlatformExpert.h>
#include <pexpert/device_tree.h>

#include <IOKit/IOHibernatePrivate.h>
#include <vm/vm_page.h>
#include <san/kasan.h>
#include <arm/cpu_internal.h>
#include <arm/cpu_data_internal.h>
#include <machine/pal_hibernate.h>

#if HIBERNATE_HMAC_IMAGE
#include <arm64/hibernate_ppl_hmac.h>
#include <arm64/ppl/ppl_hib.h>
#endif /* HIBERNATE_HMAC_IMAGE */

extern void
qsort(void *a, size_t n, size_t es, int (*cmp)(const void *, const void *));

void
pal_hib_teardown_pmap_structs(__unused addr64_t *unneeded_start, __unused addr64_t *unneeded_end)
{
}

void
pal_hib_rebuild_pmap_structs(void)
{
}

static void
set_dram_range(hibernate_bitmap_t *range, uint64_t start_addr, uint64_t size)
{
	uint64_t first_page = atop_64(start_addr);
	uint64_t page_count = atop_64(size);
	uint64_t last_page = first_page + page_count - 1;

	range->first_page = (uint32_t)first_page;
	assert(range->first_page == first_page); // make sure the truncation wasn't lossy

	range->last_page = (uint32_t)last_page;
	assert(range->last_page == last_page); // make sure the truncation wasn't lossy
}

// Comparison function used to sort the DRAM ranges list.
static int
dram_range_compare(const void *a, const void *b)
{
	return ((const hibernate_bitmap_t *)a)->first_page - ((const hibernate_bitmap_t *)b)->first_page;
}

hibernate_page_list_t *
hibernate_page_list_allocate(boolean_t log)
{
	vm_size_t               size;
	uint32_t                bank;
	uint32_t                pages, page_count;
	hibernate_page_list_t * list;
	hibernate_bitmap_t *    bitmap;

#if HIBERNATE_HMAC_IMAGE
	// Determine if any PPL-owned I/O ranges need to be hibernated, and if so,
	// allocate bitmaps to represent those pages.
	const ppl_hib_io_range *io_ranges = NULL;
	uint16_t                num_io_ranges = 0;
	hibernate_bitmap_t *    dram_ranges = NULL;
	uint32_t                num_banks = 1;

	ppl_hmac_get_io_ranges(&io_ranges, &num_io_ranges);

	// Allocate a single DRAM range to cover kernel-managed memory and one range
	// per PPL-owned I/O range that needs to be hibernated.
	if (io_ranges != NULL && num_io_ranges > 0) {
		num_banks += num_io_ranges;
	}

	dram_ranges = kheap_alloc(KHEAP_TEMP,
	    num_banks * sizeof(hibernate_bitmap_t), Z_WAITOK);
	if (!dram_ranges) {
		return NULL;
	}

	// The 0th dram range is used to represent kernel-managed memory, so skip it
	// when adding I/O ranges.
	for (unsigned int i = 1; i < num_banks; ++i) {
		dram_ranges[i].first_page = io_ranges[i - 1].first_page;
		dram_ranges[i].last_page = (io_ranges[i - 1].first_page + io_ranges[i - 1].page_count) - 1;
	}
#else
	// Allocate a single DRAM range to cover the kernel-managed memory.
	hibernate_bitmap_t      dram_ranges[1];
	uint32_t                num_banks = sizeof(dram_ranges) / sizeof(dram_ranges[0]);
#endif /* HIBERNATE_HMAC_IMAGE */

	// All of kernel-managed memory can be described by one DRAM range
	set_dram_range(&dram_ranges[0], gPhysBase, gPhysSize);

	// Sort the DRAM ranges based on the first page. Other parts of the hibernation
	// flow expect these ranges to be in order.
	qsort((void*)dram_ranges, num_banks, sizeof(dram_ranges[0]), dram_range_compare);

	// size the hibernation bitmap

	size = sizeof(hibernate_page_list_t);
	page_count = 0;
	for (bank = 0; bank < num_banks; bank++) {
		pages = dram_ranges[bank].last_page + 1 - dram_ranges[bank].first_page;
		page_count += pages;
		size += sizeof(hibernate_bitmap_t) + ((pages + 31) >> 5) * sizeof(uint32_t);
	}

	list = (hibernate_page_list_t *)kalloc(size);
	if (!list) {
		goto out;
	}

	list->list_size  = (uint32_t)size;
	list->page_count = page_count;
	list->bank_count = num_banks;

	// convert to hibernation bitmap.

	bitmap = &list->bank_bitmap[0];
	for (bank = 0; bank < num_banks; bank++) {
		bitmap->first_page = dram_ranges[bank].first_page;
		bitmap->last_page  = dram_ranges[bank].last_page;
		bitmap->bitmapwords = (bitmap->last_page + 1
		    - bitmap->first_page + 31) >> 5;
		if (log) {
			HIBLOG("hib bank[%d]: 0x%llx (%d) end 0x%llx (%d)\n",
			    bank,
			    ptoa_64(bitmap->first_page), bitmap->first_page,
			    ptoa_64(bitmap->last_page), bitmap->last_page);
		}
		bitmap = (hibernate_bitmap_t *) &bitmap->bitmap[bitmap->bitmapwords];
	}

out:
#if HIBERNATE_HMAC_IMAGE
	kheap_free(KHEAP_TEMP, dram_ranges,
	    num_banks * sizeof(hibernate_bitmap_t));
#endif /* HIBERNATE_HMAC_IMAGE */

	return list;
}

void
pal_hib_get_stack_pages(vm_offset_t *first_page, vm_offset_t *page_count)
{
	vm_offset_t stack_end = BootCpuData.intstack_top;
	vm_offset_t stack_begin = stack_end - INTSTACK_SIZE;
	*first_page = atop_64(kvtophys(stack_begin));
	*page_count = atop_64(round_page(stack_end) - trunc_page(stack_begin));
}

// mark pages not to be saved, but available for scratch usage during restore
void
hibernate_page_list_setall_machine(hibernate_page_list_t * page_list,
    hibernate_page_list_t * page_list_wired,
    boolean_t preflight,
    uint32_t * pagesOut)
{
	vm_offset_t stack_first_page, stack_page_count;
	pal_hib_get_stack_pages(&stack_first_page, &stack_page_count);

	extern pmap_paddr_t pmap_stacks_start_pa, pmap_stacks_end_pa;
	vm_offset_t pmap_stack_page_count = atop_64(pmap_stacks_end_pa - pmap_stacks_start_pa);

	if (!preflight) {
		// mark the stack as unavailable for clobbering during restore;
		// we won't actually save it because we mark these pages as free
		// in hibernate_page_list_set_volatile
		hibernate_set_page_state(page_list, page_list_wired,
		    stack_first_page, stack_page_count,
		    kIOHibernatePageStateWiredSave);

		// Mark the PPL stack as not needing to be saved. Any PPL memory that is
		// excluded from the image will need to be explicitly checked for in
		// pmap_check_ppl_hashed_flag_all(). That function ensures that all
		// PPL pages are contained within the image (so any memory explicitly
		// not being saved, needs to be removed from the check).
		hibernate_set_page_state(page_list, page_list_wired,
		    atop_64(pmap_stacks_start_pa), pmap_stack_page_count,
		    kIOHibernatePageStateFree);
	}
	*pagesOut += stack_page_count;
	*pagesOut -= pmap_stack_page_count;
}

// mark pages not to be saved and not for scratch usage during restore
void
hibernate_page_list_set_volatile(hibernate_page_list_t * page_list,
    hibernate_page_list_t * page_list_wired,
    uint32_t * pagesOut)
{
	vm_offset_t page, count;

	// hibernation restore runs on the interrupt stack,
	// so we need to make sure we don't save it
	pal_hib_get_stack_pages(&page, &count);
	hibernate_set_page_state(page_list, page_list_wired,
	    page, count,
	    kIOHibernatePageStateFree);
	*pagesOut -= count;
}

kern_return_t
hibernate_processor_setup(IOHibernateImageHeader * header)
{
	cpu_datap(master_cpu)->cpu_hibernate = 1;
	header->processorFlags = 0;
	return KERN_SUCCESS;
}

static boolean_t hibernate_vm_locks_safe;

void
hibernate_vm_lock(void)
{
	if (kIOHibernateStateHibernating == gIOHibernateState) {
		hibernate_vm_lock_queues();
		hibernate_vm_locks_safe = TRUE;
	}
}

void
hibernate_vm_unlock(void)
{
	assert(FALSE == ml_get_interrupts_enabled());
	if (kIOHibernateStateHibernating == gIOHibernateState) {
		hibernate_vm_unlock_queues();
	}
	ml_set_is_quiescing(TRUE);
}

// processor_doshutdown() calls hibernate_vm_lock() and hibernate_vm_unlock() on sleep with interrupts disabled.
// ml_hibernate_active_post() calls hibernate_vm_lock_end() on wake before interrupts are enabled.
// VM locks are safely single threaded between hibernate_vm_lock() and hibernate_vm_lock_end().

void
hibernate_vm_lock_end(void)
{
	assert(FALSE == ml_get_interrupts_enabled());
	hibernate_vm_locks_safe = FALSE;
}

boolean_t
hibernate_vm_locks_are_safe(void)
{
	assert(FALSE == ml_get_interrupts_enabled());
	return hibernate_vm_locks_safe;
}

void
pal_hib_init(void)
{
#if HIBERNATE_HMAC_IMAGE
	gHibernateGlobals.hmacRegBase = ppl_hmac_get_reg_base();
#endif /* HIBERNATE_HMAC_IMAGE */
}

void
pal_hib_write_hook(void)
{
}

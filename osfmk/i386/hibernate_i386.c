/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/kalloc.h>
#include <mach/machine.h>
#include <mach/processor_info.h>
#include <mach/mach_types.h>
#include <i386/pmap.h>
#include <kern/cpu_data.h>
#include <IOKit/IOPlatformExpert.h>
#define KERNEL

#include <IOKit/IOHibernatePrivate.h>
#include <vm/vm_page.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* This assumes that
 * - we never will want to read or write memory below the start of kernel text
 * - kernel text and data isn't included in pmap memory regions
 */

extern void *sectTEXTB;
extern char		*first_avail;

hibernate_page_list_t *
hibernate_page_list_allocate(void)
{
    vm_offset_t             base;
    vm_size_t               size;
    uint32_t                bank;
    uint32_t		    pages, page_count;
    hibernate_page_list_t * list;
    hibernate_bitmap_t *    bitmap;
    pmap_memory_region_t *  regions;
    pmap_memory_region_t *  rp;
    uint32_t                num_regions, num_alloc_regions;

    page_count = 0;

    /* Make a list of the maximum number of regions needed */
    num_alloc_regions = 1 + pmap_memory_region_count;

    /* Allocate our own list of memory regions so we can sort them in order. */
    regions = (pmap_memory_region_t *)kalloc(sizeof(pmap_memory_region_t) * num_alloc_regions);
    if (!regions)
        return (0);

    /* Fill in the actual regions we will be returning. */
    rp = regions;

    /* XXX should check for non-volatile memory region below kernel space. */
    /* Kernel region is first. */
    base = (vm_offset_t)(sectTEXTB) & 0x3FFFFFFF;
    rp->base = atop_32(base);
    rp->end = atop_32((vm_offset_t)first_avail) - 1;
    rp->alloc = 0;
    num_regions = 1;

    /* Remaining memory regions.  Consolidate adjacent regions. */
    for (bank = 0; bank < (uint32_t) pmap_memory_region_count; bank++)
    {
        if ((rp->end + 1) == pmap_memory_regions[bank].base) {
            rp->end = pmap_memory_regions[bank].end;
        } else {
            ++rp;
            ++num_regions;
            rp->base = pmap_memory_regions[bank].base;
            rp->end = pmap_memory_regions[bank].end;
            rp->alloc = 0;
        }
    }

    /* Size the hibernation bitmap */
    size = sizeof(hibernate_page_list_t);
    page_count = 0;
    for (bank = 0, rp = regions; bank < num_regions; bank++, rp++) {
	pages = rp->end + 1 - rp->base;
	page_count += pages;
        size += sizeof(hibernate_bitmap_t) + ((pages + 31) >> 5) * sizeof(uint32_t);
    }

    list = (hibernate_page_list_t *)kalloc(size);
    if (!list)
	return (list);
	
    list->list_size  = size;
    list->page_count = page_count;
    list->bank_count = num_regions;

    /* Convert to hibernation bitmap. */
    /* This assumes that ranges are in order and do not overlap. */
    bitmap = &list->bank_bitmap[0];
    for (bank = 0, rp = regions; bank < num_regions; bank++, rp++) {
        bitmap->first_page = rp->base;
        bitmap->last_page = rp->end;
        bitmap->bitmapwords = (bitmap->last_page + 1
                               - bitmap->first_page + 31) >> 5;
        kprintf("HIB: Bank %d: 0x%x end 0x%x\n", bank,
                ptoa_32(bitmap->first_page),
                ptoa_32(bitmap->last_page));
	bitmap = (hibernate_bitmap_t *) &bitmap->bitmap[bitmap->bitmapwords];
    }

    kfree((void *)regions, sizeof(pmap_memory_region_t) * num_alloc_regions);
    return (list);
}

void
hibernate_page_list_setall_machine(hibernate_page_list_t * page_list,
                                   hibernate_page_list_t * page_list_wired,
                                   uint32_t * pagesOut)
{
    KernelBootArgs_t *      bootArgs = (KernelBootArgs_t *)PE_state.bootArgs;
    MemoryRange *           mptr;
    uint32_t                bank;
    uint32_t                page, count;

    for (bank = 0, mptr = bootArgs->memoryMap; bank < bootArgs->memoryMapCount; bank++, mptr++) {

        if (kMemoryRangeNVS != mptr->type) continue;
        kprintf("Base NVS region 0x%x + 0x%x\n", (vm_offset_t)mptr->base, (vm_size_t)mptr->length);
        /* Round to page size.  Hopefully this does not overlap any reserved areas. */
        page = atop_32(trunc_page((vm_offset_t)mptr->base));
        count = atop_32(round_page((vm_offset_t)mptr->base + (vm_size_t)mptr->length)) - page;
        kprintf("Rounded NVS region 0x%x size 0x%x\n", page, count);

        hibernate_set_page_state(page_list, page_list_wired, page, count, 1);
        pagesOut -= count;
    }
}

kern_return_t 
hibernate_processor_setup(IOHibernateImageHeader * header)
{
    current_cpu_datap()->cpu_hibernate = 1;
    header->processorFlags = 0;
    return (KERN_SUCCESS);
}

void
hibernate_vm_lock(void)
{
    if (FALSE /* getPerProc()->hibernate */)
    {
        vm_page_lock_queues();
        mutex_lock(&vm_page_queue_free_lock);
    }
}

void
hibernate_vm_unlock(void)
{
    if (FALSE /* getPerProc()->hibernate */)
    {
        mutex_unlock(&vm_page_queue_free_lock);
        vm_page_unlock_queues();
    }
}

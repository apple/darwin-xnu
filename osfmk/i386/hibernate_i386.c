/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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

#include <pexpert/i386/efi.h>

#include <IOKit/IOHibernatePrivate.h>
#include <vm/vm_page.h>
#include "i386_lowmem.h"

#define MAX_BANKS	32

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

hibernate_page_list_t *
hibernate_page_list_allocate(void)
{
    ppnum_t		    base, num;
    vm_size_t               size;
    uint32_t                bank, num_banks;
    uint32_t		    pages, page_count;
    hibernate_page_list_t * list;
    hibernate_bitmap_t *    bitmap;

    EfiMemoryRange *	    mptr;
    uint32_t		    mcount, msize, i;
    hibernate_bitmap_t	    dram_ranges[MAX_BANKS];
    boot_args *		    args = (boot_args *) PE_state.bootArgs;

    mptr = (EfiMemoryRange *)args->MemoryMap;
    if (args->MemoryMapDescriptorSize == 0)
	panic("Invalid memory map descriptor size");
    msize = args->MemoryMapDescriptorSize;
    mcount = args->MemoryMapSize / msize;

    num_banks = 0;
    for (i = 0; i < mcount; i++, mptr = (EfiMemoryRange *)(((vm_offset_t)mptr) + msize))
    {
	base = (ppnum_t) (mptr->PhysicalStart >> I386_PGSHIFT);
	num = (ppnum_t) mptr->NumberOfPages;
	if (!num)
	    continue;

	switch (mptr->Type)
	{
	    // any kind of dram
	    case kEfiLoaderCode:
	    case kEfiLoaderData:
	    case kEfiBootServicesCode:
	    case kEfiBootServicesData:
	    case kEfiConventionalMemory:
	    case kEfiACPIReclaimMemory:
	    case kEfiACPIMemoryNVS:
	    case kEfiPalCode:

		if (!num_banks || (base != (1 + dram_ranges[num_banks - 1].last_page)))
		{
		    num_banks++;
		    if (num_banks >= MAX_BANKS)
			break;
		    dram_ranges[num_banks - 1].first_page = base;
		}
		dram_ranges[num_banks - 1].last_page = base + num - 1;
		break;

	    // runtime services will be restarted, so no save
	    case kEfiRuntimeServicesCode:
	    case kEfiRuntimeServicesData:
	    // non dram
	    case kEfiReservedMemoryType:
	    case kEfiUnusableMemory:
	    case kEfiMemoryMappedIO:
	    case kEfiMemoryMappedIOPortSpace:
	    default:
		break;
	}
    }

    if (num_banks >= MAX_BANKS)
	return (NULL);

    // size the hibernation bitmap

    size = sizeof(hibernate_page_list_t);
    page_count = 0;
    for (bank = 0; bank < num_banks; bank++) {
	pages = dram_ranges[bank].last_page + 1 - dram_ranges[bank].first_page;
	page_count += pages;
        size += sizeof(hibernate_bitmap_t) + ((pages + 31) >> 5) * sizeof(uint32_t);
    }

    list = (hibernate_page_list_t *)kalloc(size);
    if (!list)
	return (list);
	
    list->list_size  = size;
    list->page_count = page_count;
    list->bank_count = num_banks;

    // convert to hibernation bitmap.

    bitmap = &list->bank_bitmap[0];
    for (bank = 0; bank < num_banks; bank++)
    {
        bitmap->first_page = dram_ranges[bank].first_page;
        bitmap->last_page  = dram_ranges[bank].last_page;
        bitmap->bitmapwords = (bitmap->last_page + 1
                               - bitmap->first_page + 31) >> 5;
        kprintf("hib bank[%d]: 0x%x000 end 0x%xfff\n", bank,
                bitmap->first_page,
                bitmap->last_page);
	bitmap = (hibernate_bitmap_t *) &bitmap->bitmap[bitmap->bitmapwords];
    }

    return (list);
}

// mark pages not to be saved, but available for scratch usage during restore

void
hibernate_page_list_setall_machine( __unused hibernate_page_list_t * page_list,
                                    __unused hibernate_page_list_t * page_list_wired,
                                    __unused uint32_t * pagesOut)
{
}

// mark pages not to be saved and not for scratch usage during restore
void
hibernate_page_list_set_volatile( hibernate_page_list_t * page_list,
				  hibernate_page_list_t * page_list_wired,
				  uint32_t * pagesOut)
{
    boot_args * args = (boot_args *) PE_state.bootArgs;

    hibernate_set_page_state(page_list, page_list_wired, 
		I386_HIB_PAGETABLE, I386_HIB_PAGETABLE_COUNT, 
		kIOHibernatePageStateFree);
    *pagesOut -= I386_HIB_PAGETABLE_COUNT;

    if (args->efiRuntimeServicesPageStart)
    {
	hibernate_set_page_state(page_list, page_list_wired, 
		    args->efiRuntimeServicesPageStart, args->efiRuntimeServicesPageCount, 
		    kIOHibernatePageStateFree);
	*pagesOut -= args->efiRuntimeServicesPageCount;
    }
}

kern_return_t 
hibernate_processor_setup(IOHibernateImageHeader * header)
{
    boot_args * args = (boot_args *) PE_state.bootArgs;

    cpu_datap(0)->cpu_hibernate = 1;
    header->processorFlags = 0;

    header->runtimePages     = args->efiRuntimeServicesPageStart;
    header->runtimePageCount = args->efiRuntimeServicesPageCount;

    return (KERN_SUCCESS);
}

void
hibernate_vm_lock(void)
{
    if (current_cpu_datap()->cpu_hibernate)
    {
        vm_page_lock_queues();
        mutex_lock(&vm_page_queue_free_lock);
    }
}

void
hibernate_vm_unlock(void)
{
    if (current_cpu_datap()->cpu_hibernate)
    {
        mutex_unlock(&vm_page_queue_free_lock);
        vm_page_unlock_queues();
    }
}

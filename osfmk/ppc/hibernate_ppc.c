/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */

#include <kern/kern_types.h>
#include <kern/kalloc.h>
#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <mach/machine.h>
#include <mach/processor_info.h>
#include <mach/mach_types.h>
#include <ppc/proc_reg.h>
#include <ppc/misc_protos.h>
#include <ppc/machine_routines.h>
#include <ppc/machine_cpu.h>
#include <ppc/exception.h>
#include <ppc/asm.h>
#include <ppc/hw_perfmon.h>
#include <pexpert/pexpert.h>
#include <kern/cpu_data.h>
#include <ppc/mappings.h>
#include <ppc/Diagnostics.h>
#include <ppc/trap.h>
#include <ppc/mem.h>
#include <IOKit/IOPlatformExpert.h>
#define KERNEL

#include <IOKit/IOHibernatePrivate.h>
#include <vm/vm_page.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

hibernate_page_list_t *
hibernate_page_list_allocate(void)
{
    vm_size_t               size;
    uint32_t                bank;
    uint32_t	            pages, page_count;
    hibernate_page_list_t * list;
    hibernate_bitmap_t *    bitmap;

    page_count = 0;
    size = sizeof(hibernate_page_list_t);

    for (bank = 0; bank < (uint32_t) pmap_mem_regions_count; bank++)
    {
	size += sizeof(hibernate_bitmap_t);
	pages = pmap_mem_regions[bank].mrEnd + 1 - pmap_mem_regions[bank].mrStart;
	page_count += pages;
	size += ((pages + 31) >> 5) * sizeof(uint32_t);
    }

    list = kalloc(size);
    if (!list)
	return (list);
	
    list->list_size  = size;
    list->page_count = page_count;
    list->bank_count = pmap_mem_regions_count;

    bitmap = &list->bank_bitmap[0];
    for (bank = 0; bank < list->bank_count; bank++)
    {
	bitmap->first_page  =  pmap_mem_regions[bank].mrStart;
	bitmap->last_page   =  pmap_mem_regions[bank].mrEnd;
	bitmap->bitmapwords = (pmap_mem_regions[bank].mrEnd + 1
			     - pmap_mem_regions[bank].mrStart + 31) >> 5;

	bitmap = (hibernate_bitmap_t *) &bitmap->bitmap[bitmap->bitmapwords];
    }
    return (list);
}

void
hibernate_page_list_setall_machine(hibernate_page_list_t * page_list,
                                    hibernate_page_list_t * page_list_wired,
                                    uint32_t * pagesOut)
{
    uint32_t page, count, PCAsize;

    /* Get total size of PCA table */
    PCAsize = round_page((hash_table_size / PerProcTable[0].ppe_vaddr->pf.pfPTEG) 
                          * sizeof(PCA_t));

    page = atop_64(hash_table_base - PCAsize);
    count = atop_64(hash_table_size + PCAsize);

    hibernate_set_page_state(page_list, page_list_wired, page, count, 0);
    pagesOut -= count;

    HIBLOG("removed hash, pca: %d pages\n", count);

    save_snapshot();
}

kern_return_t 
hibernate_processor_setup(IOHibernateImageHeader * header)
{
    header->processorFlags = PerProcTable[0].ppe_vaddr->pf.Available;

    PerProcTable[0].ppe_vaddr->hibernate = 1;

    return (KERN_SUCCESS);
}

void
hibernate_vm_lock(void)
{
    if (getPerProc()->hibernate)
    {
        vm_page_lock_queues();
        mutex_lock(&vm_page_queue_free_lock);
    }
}

void
hibernate_vm_unlock(void)
{
    if (getPerProc()->hibernate)
    {
        mutex_unlock(&vm_page_queue_free_lock);
        vm_page_unlock_queues();
    }
}

void ml_ppc_sleep(void)
{
    struct per_proc_info *proc_info;
    boolean_t dohalt;

    proc_info = getPerProc();
    if (!proc_info->hibernate)
    {
	ml_ppc_do_sleep();
	return;
    }

    {
        uint64_t start, end, nsec;

	HIBLOG("mapping_hibernate_flush start\n");
	clock_get_uptime(&start);

	mapping_hibernate_flush();

	clock_get_uptime(&end);
	absolutetime_to_nanoseconds(end - start, &nsec);
	HIBLOG("mapping_hibernate_flush time: %qd ms\n", nsec / 1000000ULL);
    }

    dohalt = hibernate_write_image();

    if (dohalt)
    {
	// off
	HIBLOG("power off\n");
	if (PE_halt_restart) 
	    (*PE_halt_restart)(kPEHaltCPU);
    }
    else
    {
	// sleep
	HIBLOG("sleep\n");

	// should we come back via regular wake, set the state in memory.
	PerProcTable[0].ppe_vaddr->hibernate = 0;

	PE_cpu_machine_quiesce(proc_info->cpu_id);
	return;
    }
}


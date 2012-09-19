/*
 * Copyright (c) 2004-2005 Apple Computer, Inc. All rights reserved.
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

#include <kern/kalloc.h>
#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <mach/machine.h>
#include <mach/processor_info.h>
#include <mach/mach_types.h>
#include <default_pager/default_pager_internal.h>
#include <IOKit/IOPlatformExpert.h>

#include <IOKit/IOHibernatePrivate.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_purgeable_internal.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

kern_return_t 
hibernate_setup(IOHibernateImageHeader * header,
                        uint32_t  free_page_ratio,
                        uint32_t  free_page_time,
                        boolean_t vmflush,
			hibernate_page_list_t ** page_list_ret,
			hibernate_page_list_t ** page_list_wired_ret,
			hibernate_page_list_t ** page_list_pal_ret,
                        boolean_t * encryptedswap)
{
    hibernate_page_list_t * page_list = NULL;
    hibernate_page_list_t * page_list_wired = NULL;
    hibernate_page_list_t * page_list_pal = NULL;
    uint32_t    	    gobble_count;

    *page_list_ret       = NULL;
    *page_list_wired_ret = NULL;
	*page_list_pal_ret    = NULL;
    
    if (vmflush)
        hibernate_flush_memory();

    page_list = hibernate_page_list_allocate();
    if (!page_list)
        return (KERN_RESOURCE_SHORTAGE);
    page_list_wired = hibernate_page_list_allocate();
    if (!page_list_wired)
    {
        kfree(page_list, page_list->list_size);
        return (KERN_RESOURCE_SHORTAGE);
    }
    page_list_pal = hibernate_page_list_allocate();
    if (!page_list_pal)
    {
        kfree(page_list, page_list->list_size);
        kfree(page_list_wired, page_list_wired->list_size);
        return (KERN_RESOURCE_SHORTAGE);
    }

    *encryptedswap = dp_encryption;

    // pages we could force out to reduce hibernate image size
    gobble_count = (uint32_t)((((uint64_t) page_list->page_count) * ((uint64_t) free_page_ratio)) / 100);

    // no failures hereafter

    hibernate_processor_setup(header);

    HIBLOG("hibernate_alloc_pages flags %08x, gobbling %d pages\n", 
	    header->processorFlags, gobble_count);

    if (gobble_count)
	hibernate_gobble_pages(gobble_count, free_page_time);

    *page_list_ret       = page_list;
    *page_list_wired_ret = page_list_wired;
    *page_list_pal_ret    = page_list_pal;

    return (KERN_SUCCESS);
}

kern_return_t 
hibernate_teardown(hibernate_page_list_t * page_list,
                    hibernate_page_list_t * page_list_wired,
		    hibernate_page_list_t * page_list_pal)
{
    hibernate_free_gobble_pages();

    if (page_list)
        kfree(page_list, page_list->list_size);
    if (page_list_wired)
        kfree(page_list_wired, page_list_wired->list_size);
    if (page_list_pal)
        kfree(page_list_pal, page_list_pal->list_size);

    return (KERN_SUCCESS);
}


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

static vm_page_t hibernate_gobble_queue;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static void
hibernate_page_list_zero(hibernate_page_list_t *list)
{
    uint32_t             bank;
    hibernate_bitmap_t * bitmap;

    bitmap = &list->bank_bitmap[0];
    for (bank = 0; bank < list->bank_count; bank++)
    {
        uint32_t last_bit;

	bzero((void *) &bitmap->bitmap[0], bitmap->bitmapwords << 2); 
        // set out-of-bound bits at end of bitmap.
        last_bit = ((bitmap->last_page - bitmap->first_page + 1) & 31);
	if (last_bit)
	    bitmap->bitmap[bitmap->bitmapwords - 1] = (0xFFFFFFFF >> last_bit);

	bitmap = (hibernate_bitmap_t *) &bitmap->bitmap[bitmap->bitmapwords];
    }
}


static boolean_t 
consider_discard(vm_page_t m)
{
    vm_object_t object = NULL;
    int                  refmod_state;
    boolean_t            discard = FALSE;

    do
    {
        if(m->private)
            panic("consider_discard: private");

        if (!vm_object_lock_try(m->object))
            break;

        object = m->object;

	if (m->wire_count != 0)
            break;
        if (m->precious)
            break;

        if (m->busy || !object->alive)
           /*
            *	Somebody is playing with this page.
            */
            break;

        if (m->absent || m->unusual || m->error)
           /*
            * If it's unusual in anyway, ignore it
            */
            break;
    
        if (m->cleaning)
            break;

	if (m->laundry || m->list_req_pending)
            break;

        if (!m->dirty)
        {
            refmod_state = pmap_get_refmod(m->phys_page);
        
            if (refmod_state & VM_MEM_REFERENCED)
                m->reference = TRUE;
            if (refmod_state & VM_MEM_MODIFIED)
                m->dirty = TRUE;
        }
   
        /*
         * If it's clean or purgeable we can discard the page on wakeup.
	 * JMM - consider purgeable (volatile or empty) objects here as well.
         */
        discard = (!m->dirty) 
		    || (VM_PURGABLE_VOLATILE == object->purgable)
		    || (VM_PURGABLE_EMPTY    == m->object->purgable);
    }
    while (FALSE);

    if (object)
        vm_object_unlock(object);

    return (discard);
}


static void
discard_page(vm_page_t m)
{
    if (m->absent || m->unusual || m->error)
       /*
        * If it's unusual in anyway, ignore
        */
        return;

    if (m->pmapped == TRUE) 
    {
        __unused int refmod_state = pmap_disconnect(m->phys_page);
    }

    if (m->laundry)
        panic("discard_page(%p) laundry", m);
    if (m->private)
        panic("discard_page(%p) private", m);
    if (m->fictitious)
        panic("discard_page(%p) fictitious", m);

    if (VM_PURGABLE_VOLATILE == m->object->purgable)
	{
		assert(m->object->objq.next != NULL && m->object->objq.prev != NULL); /* object should be on a queue */
		purgeable_q_t old_queue=vm_purgeable_object_remove(m->object);
		assert(old_queue);
		/* No need to lock page queue for token delete, hibernate_vm_unlock() 
			makes sure these locks are uncontended before sleep */
		vm_purgeable_token_delete_first(old_queue);
		m->object->purgable = VM_PURGABLE_EMPTY;
	}
	
    if (m->tabled)
	vm_page_remove(m);

    vm_page_free(m);
}

/*
 Bits zero in the bitmaps => needs to be saved. All pages default to be saved,
 pages known to VM to not need saving are subtracted.
 Wired pages to be saved are present in page_list_wired, pageable in page_list.
*/

void
hibernate_page_list_setall(hibernate_page_list_t * page_list,
			   hibernate_page_list_t * page_list_wired,
			   uint32_t * pagesOut)
{
    uint64_t start, end, nsec;
    vm_page_t m;
    uint32_t pages = page_list->page_count;
    uint32_t count_zf = 0, count_throttled = 0, count_inactive = 0, count_active = 0;
    uint32_t count_wire = pages;
    uint32_t count_discard_active    = 0;
    uint32_t count_discard_inactive  = 0;
    uint32_t count_discard_purgeable = 0;
    uint32_t i;
    uint32_t             bank;
    hibernate_bitmap_t * bitmap;
    hibernate_bitmap_t * bitmap_wired;


    HIBLOG("hibernate_page_list_setall start\n");

    clock_get_uptime(&start);

    hibernate_page_list_zero(page_list);
    hibernate_page_list_zero(page_list_wired);

    m = (vm_page_t) hibernate_gobble_queue;
    while(m)
    {
	pages--;
	count_wire--;
	hibernate_page_bitset(page_list,       TRUE, m->phys_page);
	hibernate_page_bitset(page_list_wired, TRUE, m->phys_page);
	m = (vm_page_t) m->pageq.next;
    }

    for( i = 0; i < vm_colors; i++ )
    {
	queue_iterate(&vm_page_queue_free[i],
		      m,
		      vm_page_t,
		      pageq)
	{
	    pages--;
	    count_wire--;
	    hibernate_page_bitset(page_list,       TRUE, m->phys_page);
	    hibernate_page_bitset(page_list_wired, TRUE, m->phys_page);
	}
    }

    queue_iterate(&vm_lopage_queue_free,
		  m,
		  vm_page_t,
		  pageq)
    {
	pages--;
	count_wire--;
	hibernate_page_bitset(page_list,       TRUE, m->phys_page);
	hibernate_page_bitset(page_list_wired, TRUE, m->phys_page);
    }

    queue_iterate( &vm_page_queue_throttled,
                    m,
                    vm_page_t,
                    pageq )
    {
        if ((kIOHibernateModeDiscardCleanInactive & gIOHibernateMode) 
         && consider_discard(m))
        {
            hibernate_page_bitset(page_list, TRUE, m->phys_page);
            count_discard_inactive++;
        }
        else
            count_throttled++;
	count_wire--;
	hibernate_page_bitset(page_list_wired, TRUE, m->phys_page);
    }

    queue_iterate( &vm_page_queue_zf,
                    m,
                    vm_page_t,
                    pageq )
    {
        if ((kIOHibernateModeDiscardCleanInactive & gIOHibernateMode) 
         && consider_discard(m))
        {
            hibernate_page_bitset(page_list, TRUE, m->phys_page);
	    if (m->dirty)
		count_discard_purgeable++;
	    else
		count_discard_inactive++;
        }
        else
            count_zf++;
	count_wire--;
	hibernate_page_bitset(page_list_wired, TRUE, m->phys_page);
    }

    queue_iterate( &vm_page_queue_inactive,
                    m,
                    vm_page_t,
                    pageq )
    {
        if ((kIOHibernateModeDiscardCleanInactive & gIOHibernateMode) 
         && consider_discard(m))
        {
            hibernate_page_bitset(page_list, TRUE, m->phys_page);
	    if (m->dirty)
		count_discard_purgeable++;
	    else
		count_discard_inactive++;
        }
        else
            count_inactive++;
	count_wire--;
	hibernate_page_bitset(page_list_wired, TRUE, m->phys_page);
    }

    queue_iterate( &vm_page_queue_active,
                    m,
                    vm_page_t,
                    pageq )
    {
        if ((kIOHibernateModeDiscardCleanActive & gIOHibernateMode) 
         && consider_discard(m))
        {
            hibernate_page_bitset(page_list, TRUE, m->phys_page);
	    if (m->dirty)
		count_discard_purgeable++;
	    else
		count_discard_active++;
        }
        else
            count_active++;
	count_wire--;
	hibernate_page_bitset(page_list_wired, TRUE, m->phys_page);
    }

    // pull wired from hibernate_bitmap

    bitmap = &page_list->bank_bitmap[0];
    bitmap_wired = &page_list_wired->bank_bitmap[0];
    for (bank = 0; bank < page_list->bank_count; bank++)
    {
	for (i = 0; i < bitmap->bitmapwords; i++)
	    bitmap->bitmap[i] = bitmap->bitmap[i] | ~bitmap_wired->bitmap[i];
	bitmap       = (hibernate_bitmap_t *) &bitmap->bitmap      [bitmap->bitmapwords];
	bitmap_wired = (hibernate_bitmap_t *) &bitmap_wired->bitmap[bitmap_wired->bitmapwords];
    }

    // machine dependent adjustments
    hibernate_page_list_setall_machine(page_list, page_list_wired, &pages);

    clock_get_uptime(&end);
    absolutetime_to_nanoseconds(end - start, &nsec);
    HIBLOG("hibernate_page_list_setall time: %qd ms\n", nsec / 1000000ULL);

    HIBLOG("pages %d, wire %d, act %d, inact %d, zf %d, throt %d, could discard act %d inact %d purgeable %d\n", 
                pages, count_wire, count_active, count_inactive, count_zf, count_throttled,
                count_discard_active, count_discard_inactive, count_discard_purgeable);

    *pagesOut = pages - count_discard_active - count_discard_inactive - count_discard_purgeable;
}

void
hibernate_page_list_discard(hibernate_page_list_t * page_list)
{
    uint64_t  start, end, nsec;
    vm_page_t m;
    vm_page_t next;
    uint32_t  count_discard_active    = 0;
    uint32_t  count_discard_inactive  = 0;
    uint32_t  count_discard_purgeable = 0;

    clock_get_uptime(&start);

    m = (vm_page_t) queue_first(&vm_page_queue_zf);
    while (m && !queue_end(&vm_page_queue_zf, (queue_entry_t)m))
    {
        next = (vm_page_t) m->pageq.next;
        if (hibernate_page_bittst(page_list, m->phys_page))
        {
	    if (m->dirty)
		count_discard_purgeable++;
	    else
		count_discard_inactive++;
            discard_page(m);
        }
        m = next;
    }

    m = (vm_page_t) queue_first(&vm_page_queue_inactive);
    while (m && !queue_end(&vm_page_queue_inactive, (queue_entry_t)m))
    {
        next = (vm_page_t) m->pageq.next;
        if (hibernate_page_bittst(page_list, m->phys_page))
        {
	    if (m->dirty)
		count_discard_purgeable++;
	    else
		count_discard_inactive++;
            discard_page(m);
        }
        m = next;
    }

    m = (vm_page_t) queue_first(&vm_page_queue_active);
    while (m && !queue_end(&vm_page_queue_active, (queue_entry_t)m))
    {
        next = (vm_page_t) m->pageq.next;
        if (hibernate_page_bittst(page_list, m->phys_page))
        {
	    if (m->dirty)
		count_discard_purgeable++;
	    else
		count_discard_active++;
            discard_page(m);
        }
        m = next;
    }

    clock_get_uptime(&end);
    absolutetime_to_nanoseconds(end - start, &nsec);
    HIBLOG("hibernate_page_list_discard time: %qd ms, discarded act %d inact %d purgeable %d\n",
                nsec / 1000000ULL,
                count_discard_active, count_discard_inactive, count_discard_purgeable);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

kern_return_t 
hibernate_setup(IOHibernateImageHeader * header,
                        uint32_t free_page_ratio,
                        uint32_t free_page_time,
			hibernate_page_list_t ** page_list_ret,
			hibernate_page_list_t ** page_list_wired_ret,
                        boolean_t * encryptedswap)
{
    hibernate_page_list_t * page_list = NULL;
    hibernate_page_list_t * page_list_wired = NULL;
    vm_page_t		    m;
    uint32_t    	    i, gobble_count;

    *page_list_ret       = NULL;
    *page_list_wired_ret = NULL;


    page_list = hibernate_page_list_allocate();
    if (!page_list)
        return (KERN_RESOURCE_SHORTAGE);
    page_list_wired = hibernate_page_list_allocate();
    if (!page_list_wired)
    {
        kfree(page_list, page_list->list_size);
        return (KERN_RESOURCE_SHORTAGE);
    }

    *encryptedswap = dp_encryption;

    // pages we could force out to reduce hibernate image size
    gobble_count = (((uint64_t) page_list->page_count) * ((uint64_t) free_page_ratio)) / 100;

    // no failures hereafter

    hibernate_processor_setup(header);

    HIBLOG("hibernate_alloc_pages flags %08x, gobbling %d pages\n", 
	    header->processorFlags, gobble_count);

    if (gobble_count)
    {
        uint64_t start, end, timeout, nsec;
        clock_interval_to_deadline(free_page_time, 1000 * 1000 /*ms*/, &timeout);
        clock_get_uptime(&start);
    
        for (i = 0; i < gobble_count; i++)
        {
            while (VM_PAGE_NULL == (m = vm_page_grab()))
            {
                clock_get_uptime(&end);
                if (end >= timeout)
                    break;
                VM_PAGE_WAIT();
            }
            if (!m)
                break;
            m->busy = FALSE;
            vm_page_gobble(m);
    
            m->pageq.next = (queue_entry_t) hibernate_gobble_queue;
            hibernate_gobble_queue = m;
        }
    
        clock_get_uptime(&end);
        absolutetime_to_nanoseconds(end - start, &nsec);
        HIBLOG("Gobbled %d pages, time: %qd ms\n", i, nsec / 1000000ULL);
    }

    *page_list_ret       = page_list;
    *page_list_wired_ret = page_list_wired;

    return (KERN_SUCCESS);
}

kern_return_t 
hibernate_teardown(hibernate_page_list_t * page_list,
                    hibernate_page_list_t * page_list_wired)
{
    vm_page_t m, next;
    uint32_t  count = 0;

    m = (vm_page_t) hibernate_gobble_queue;
    while(m)
    {
        next = (vm_page_t) m->pageq.next;
        vm_page_free(m);
        count++;
        m = next;
    }
    hibernate_gobble_queue = VM_PAGE_NULL;
    
    if (count)
        HIBLOG("Freed %d pages\n", count);

    if (page_list)
        kfree(page_list, page_list->list_size);
    if (page_list_wired)
        kfree(page_list_wired, page_list_wired->list_size);

    return (KERN_SUCCESS);
}


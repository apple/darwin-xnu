/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */

#include <kern/thread.h>
#include <vm/vm_fault.h>
#include <mach/kern_return.h>
#include <mach/vm_behavior.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/pmap.h>

#include <i386/intel_read_fault.h>

#include <kern/macro_help.h>

/*
 *	Expansion of vm_fault for read fault in kernel mode.
 *	Must enter the mapping as writable, since the i386
 *	(and i860 in i386 compatability mode) ignores write
 *	protection in kernel mode.
 *
 *	Note that this routine can be called for pmap's other
 *	than the kernel_pmap, in which case it just enters
 *	a read-only mapping.  (See e.g. kernel_trap().)
 */
kern_return_t
intel_read_fault(
	vm_map_t	map,
	vm_offset_t	vaddr)
{
	vm_map_version_t	version;	/* Map version for
						   verification */
	vm_object_t		object;		/* Top-level object */
	vm_object_offset_t	offset;		/* Top-level offset */
	vm_prot_t		prot;		/* Protection for mapping */
	vm_behavior_t		behavior;	/* Expected paging behavior */
	vm_map_offset_t		lo_offset, hi_offset;
	vm_page_t		result_page;	/* Result of vm_fault_page */
	vm_page_t		top_page;	/* Placeholder page */
	boolean_t		wired;		/* Is map region wired? */
	kern_return_t		result;
	register vm_page_t	m;
	vm_map_t		map_pmap;
	vm_map_t                original_map = map;
	thread_t                cur_thread;
	boolean_t               funnel_set;
	funnel_t                *curflock = NULL;

	cur_thread = current_thread();
	if ((cur_thread->funnel_state & TH_FN_OWNED) == TH_FN_OWNED) {
		funnel_set = TRUE;
		curflock = cur_thread->funnel_lock;
		thread_funnel_set( curflock , FALSE);
	} else {
		funnel_set = FALSE;
	}

    RetryFault:

	map = original_map;

	/*
	 *	Find the backing store object and offset into it
	 *	to begin search.
	 */
	vm_map_lock_read(map);
	result = vm_map_lookup_locked(&map, vaddr, VM_PROT_READ, &version,
				      &object, &offset, &prot, &wired,
				      &behavior, &lo_offset, 
				      &hi_offset, &map_pmap);
	
	vm_map_unlock_read(map);

	if (result != KERN_SUCCESS) {
		if (funnel_set)
			thread_funnel_set( curflock, TRUE);
		return (result);
	}

	if(map_pmap != map) {
		vm_map_reference(map_pmap);
		vm_map_unlock_read(map_pmap);
	}

	/*
	 *	Make a reference to this object to prevent its
	 *	disposal while we are playing with it.
	 */
	assert(object->ref_count > 0);
	object->ref_count++;
	vm_object_res_reference(object);
	vm_object_paging_begin(object);

	result = vm_fault_page(object, offset, VM_PROT_READ, FALSE,
			       THREAD_ABORTSAFE,
			       lo_offset, hi_offset, behavior,
			       &prot, &result_page, &top_page, (int *)0,
			       0, map->no_zero_fill, FALSE, map, vaddr);

	if (result != VM_FAULT_SUCCESS) {
	    vm_object_deallocate(object);
	    if(map_pmap != map) {
			vm_map_deallocate(map_pmap);
	   }

	    switch (result) {
		case VM_FAULT_RETRY:
		    goto RetryFault;
		case VM_FAULT_INTERRUPTED:
			if (funnel_set)
				thread_funnel_set( curflock, TRUE);
		    return (KERN_SUCCESS);
		case VM_FAULT_MEMORY_SHORTAGE:
		    VM_PAGE_WAIT();
		    goto RetryFault;
		case VM_FAULT_FICTITIOUS_SHORTAGE:
		    vm_page_more_fictitious();
		    goto RetryFault;
		case VM_FAULT_MEMORY_ERROR:
		    return (KERN_MEMORY_ERROR);
	    }
	}

	m = result_page;

	/*
	 *	How to clean up the result of vm_fault_page.  This
	 *	happens whether the mapping is entered or not.
	 */

#define UNLOCK_AND_DEALLOCATE				\
	MACRO_BEGIN					\
	vm_fault_cleanup(m->object, top_page);		\
	vm_object_deallocate(object);			\
	MACRO_END

	/*
	 *	What to do with the resulting page from vm_fault_page
	 *	if it doesn't get entered into the physical map:
	 */

#define RELEASE_PAGE(m)					\
	MACRO_BEGIN					\
	PAGE_WAKEUP_DONE(m);				\
	vm_page_lock_queues();				\
	if (!m->active && !m->inactive)			\
		vm_page_activate(m);			\
	vm_page_unlock_queues();			\
	MACRO_END

	/*
	 *	We must verify that the maps have not changed.
	 */
	vm_object_unlock(m->object);

	if ((map != original_map) || !vm_map_verify(map, &version)) {
	    vm_object_t		retry_object;
	    vm_object_offset_t	retry_offset;
	    vm_prot_t		retry_prot;

		if (map != map_pmap) {
			vm_map_deallocate(map_pmap);
		}
	    
		map = original_map;
		vm_map_lock_read(map);

	    result = vm_map_lookup_locked(&map, vaddr, VM_PROT_READ, &version,
				&retry_object, &retry_offset, &retry_prot,
				&wired, &behavior, &lo_offset, 
				&hi_offset, &map_pmap);

	    if (result != KERN_SUCCESS) {
	        vm_map_unlock_read(map);
			vm_object_lock(m->object);
			RELEASE_PAGE(m);
			UNLOCK_AND_DEALLOCATE;
			if (funnel_set)
				thread_funnel_set( curflock, TRUE);
			return (result);
	    }

		if (map != map_pmap) {
			vm_map_reference(map_pmap);
		}

	    vm_object_unlock(retry_object);

	    if (retry_object != object || retry_offset != offset) {
			vm_object_lock(m->object);
			RELEASE_PAGE(m);
	        vm_map_unlock_read(map);
	        if(map_pmap != map) {
		   		vm_map_unlock_read(map_pmap);
		   		vm_map_deallocate(map_pmap);
			}
			UNLOCK_AND_DEALLOCATE;
			goto RetryFault;
	    }
	}

	/*
	 *	Put the page in the physical map.
	 */

	PMAP_ENTER(map_pmap->pmap, vaddr, m, VM_PROT_READ, PMAP_DEFAULT_CACHE, wired);

	if(map_pmap != map) {
		vm_map_unlock_read(map_pmap);
		vm_map_deallocate(map_pmap);
	}
	
	vm_object_lock(m->object);
	vm_page_lock_queues();
	if (!m->active && !m->inactive)
		vm_page_activate(m);
	m->reference = TRUE;
	vm_page_unlock_queues();

	vm_map_verify_done(map, &version);
	PAGE_WAKEUP_DONE(m);

	UNLOCK_AND_DEALLOCATE;

#undef	UNLOCK_AND_DEALLOCATE
#undef	RELEASE_PAGE
	if (funnel_set)
		thread_funnel_set( curflock, TRUE);
	return (KERN_SUCCESS);
}


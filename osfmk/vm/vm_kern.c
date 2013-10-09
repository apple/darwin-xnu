/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
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
/*
 *	File:	vm/vm_kern.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Kernel memory management.
 */

#include <mach/kern_return.h>
#include <mach/vm_param.h>
#include <kern/assert.h>
#include <kern/lock.h>
#include <kern/thread.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <kern/misc_protos.h>
#include <vm/cpm.h>

#include <string.h>

#include <libkern/OSDebug.h>
#include <sys/kdebug.h>

/*
 *	Variables exported by this module.
 */

vm_map_t	kernel_map;
vm_map_t	kernel_pageable_map;

extern boolean_t vm_kernel_ready;

/*
 * Forward declarations for internal functions.
 */
extern kern_return_t kmem_alloc_pages(
	register vm_object_t		object,
	register vm_object_offset_t	offset,
	register vm_object_size_t	size);

extern void kmem_remap_pages(
	register vm_object_t		object,
	register vm_object_offset_t	offset,
	register vm_offset_t		start,
	register vm_offset_t		end,
	vm_prot_t			protection);

kern_return_t
kmem_alloc_contig(
	vm_map_t		map,
	vm_offset_t		*addrp,
	vm_size_t		size,
	vm_offset_t 		mask,
	ppnum_t			max_pnum,
	ppnum_t			pnum_mask,
	int 			flags)
{
	vm_object_t		object;
	vm_object_offset_t	offset;
	vm_map_offset_t		map_addr; 
	vm_map_offset_t		map_mask;
	vm_map_size_t		map_size, i;
	vm_map_entry_t		entry;
	vm_page_t		m, pages;
	kern_return_t		kr;

	if (map == VM_MAP_NULL || (flags & ~(KMA_KOBJECT | KMA_LOMEM | KMA_NOPAGEWAIT))) 
		return KERN_INVALID_ARGUMENT;

	map_size = vm_map_round_page(size);
	map_mask = (vm_map_offset_t)mask;
	
	/* Check for zero allocation size (either directly or via overflow) */
	if (map_size == 0) {
		*addrp = 0;
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 *	Allocate a new object (if necessary) and the reference we
	 *	will be donating to the map entry.  We must do this before
	 *	locking the map, or risk deadlock with the default pager.
	 */
	if ((flags & KMA_KOBJECT) != 0) {
		object = kernel_object;
		vm_object_reference(object);
	} else {
		object = vm_object_allocate(map_size);
	}

	kr = vm_map_find_space(map, &map_addr, map_size, map_mask, 0, &entry);
	if (KERN_SUCCESS != kr) {
		vm_object_deallocate(object);
		return kr;
	}

	entry->object.vm_object = object;
	entry->offset = offset = (object == kernel_object) ? 
		        map_addr : 0;

	/* Take an extra object ref in case the map entry gets deleted */
	vm_object_reference(object);
	vm_map_unlock(map);

	kr = cpm_allocate(CAST_DOWN(vm_size_t, map_size), &pages, max_pnum, pnum_mask, FALSE, flags);

	if (kr != KERN_SUCCESS) {
		vm_map_remove(map, vm_map_trunc_page(map_addr),
			      vm_map_round_page(map_addr + map_size), 0);
		vm_object_deallocate(object);
		*addrp = 0;
		return kr;
	}

	vm_object_lock(object);
	for (i = 0; i < map_size; i += PAGE_SIZE) {
		m = pages;
		pages = NEXT_PAGE(m);
		*(NEXT_PAGE_PTR(m)) = VM_PAGE_NULL;
		m->busy = FALSE;
		vm_page_insert(m, object, offset + i);
	}
	vm_object_unlock(object);

	if ((kr = vm_map_wire(map, vm_map_trunc_page(map_addr),
			      vm_map_round_page(map_addr + map_size), VM_PROT_DEFAULT, FALSE)) 
		!= KERN_SUCCESS) {
		if (object == kernel_object) {
			vm_object_lock(object);
			vm_object_page_remove(object, offset, offset + map_size);
			vm_object_unlock(object);
		}
		vm_map_remove(map, vm_map_trunc_page(map_addr), 
			      vm_map_round_page(map_addr + map_size), 0);
		vm_object_deallocate(object);
		return kr;
	}
	vm_object_deallocate(object);

	if (object == kernel_object)
		vm_map_simplify(map, map_addr);

	*addrp = (vm_offset_t) map_addr;
	assert((vm_map_offset_t) *addrp == map_addr);
	return KERN_SUCCESS;
}

/*
 * Master entry point for allocating kernel memory.
 * NOTE: this routine is _never_ interrupt safe.
 *
 * map		: map to allocate into
 * addrp	: pointer to start address of new memory
 * size		: size of memory requested
 * flags	: options
 *		  KMA_HERE		*addrp is base address, else "anywhere"
 *		  KMA_NOPAGEWAIT	don't wait for pages if unavailable
 *		  KMA_KOBJECT		use kernel_object
 *		  KMA_LOMEM		support for 32 bit devices in a 64 bit world
 *					if set and a lomemory pool is available
 *					grab pages from it... this also implies
 *					KMA_NOPAGEWAIT
 */

kern_return_t
kernel_memory_allocate(
	register vm_map_t	map,
	register vm_offset_t	*addrp,
	register vm_size_t	size,
	register vm_offset_t	mask,
	int			flags)
{
	vm_object_t 		object;
	vm_object_offset_t 	offset;
	vm_object_offset_t 	pg_offset;
	vm_map_entry_t 		entry = NULL;
	vm_map_offset_t 	map_addr, fill_start;
	vm_map_offset_t		map_mask;
	vm_map_size_t		map_size, fill_size;
	kern_return_t 		kr;
	vm_page_t		mem;
	vm_page_t		guard_page_list = NULL;
	vm_page_t		wired_page_list = NULL;
	int			guard_page_count = 0;
	int			wired_page_count = 0;
	int			i;
	int			vm_alloc_flags;
	vm_prot_t		kma_prot;

	if (! vm_kernel_ready) {
		panic("kernel_memory_allocate: VM is not ready");
	}

	map_size = vm_map_round_page(size);
	map_mask = (vm_map_offset_t) mask;
	vm_alloc_flags = 0;

	/* Check for zero allocation size (either directly or via overflow) */
	if (map_size == 0) {
		*addrp = 0;
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * limit the size of a single extent of wired memory
	 * to try and limit the damage to the system if
	 * too many pages get wired down
	 */
        if (map_size > (1 << 30)) {
                return KERN_RESOURCE_SHORTAGE;
        }

	/*
	 * Guard pages:
	 *
	 * Guard pages are implemented as ficticious pages.  By placing guard pages
	 * on either end of a stack, they can help detect cases where a thread walks
	 * off either end of its stack.  They are allocated and set up here and attempts
	 * to access those pages are trapped in vm_fault_page().
	 *
	 * The map_size we were passed may include extra space for
	 * guard pages.  If those were requested, then back it out of fill_size
	 * since vm_map_find_space() takes just the actual size not including
	 * guard pages.  Similarly, fill_start indicates where the actual pages
	 * will begin in the range.
	 */

	fill_start = 0;
	fill_size = map_size;

	if (flags & KMA_GUARD_FIRST) {
		vm_alloc_flags |= VM_FLAGS_GUARD_BEFORE;
		fill_start += PAGE_SIZE_64;
		fill_size -= PAGE_SIZE_64;
		if (map_size < fill_start + fill_size) {
			/* no space for a guard page */
			*addrp = 0;
			return KERN_INVALID_ARGUMENT;
		}
		guard_page_count++;
	}
	if (flags & KMA_GUARD_LAST) {
		vm_alloc_flags |= VM_FLAGS_GUARD_AFTER;
		fill_size -= PAGE_SIZE_64;
		if (map_size <= fill_start + fill_size) {
			/* no space for a guard page */
			*addrp = 0;
			return KERN_INVALID_ARGUMENT;
		}
		guard_page_count++;
	}
	wired_page_count = (int) (fill_size / PAGE_SIZE_64);
	assert(wired_page_count * PAGE_SIZE_64 == fill_size);

	for (i = 0; i < guard_page_count; i++) {
		for (;;) {
			mem = vm_page_grab_guard();

			if (mem != VM_PAGE_NULL)
				break;
			if (flags & KMA_NOPAGEWAIT) {
				kr = KERN_RESOURCE_SHORTAGE;
				goto out;
			}
			vm_page_more_fictitious();
		}
		mem->pageq.next = (queue_entry_t)guard_page_list;
		guard_page_list = mem;
	}

	for (i = 0; i < wired_page_count; i++) {
		uint64_t	unavailable;
		
		for (;;) {
		        if (flags & KMA_LOMEM)
			        mem = vm_page_grablo();
			else
			        mem = vm_page_grab();

		        if (mem != VM_PAGE_NULL)
			        break;

			if (flags & KMA_NOPAGEWAIT) {
				kr = KERN_RESOURCE_SHORTAGE;
				goto out;
			}
			if ((flags & KMA_LOMEM) && (vm_lopage_needed == TRUE)) {
				kr = KERN_RESOURCE_SHORTAGE;
				goto out;
			}
			unavailable = (vm_page_wire_count + vm_page_free_target) * PAGE_SIZE;

			if (unavailable > max_mem || map_size > (max_mem - unavailable)) {
				kr = KERN_RESOURCE_SHORTAGE;
				goto out;
			}
			VM_PAGE_WAIT();
		}
		mem->pageq.next = (queue_entry_t)wired_page_list;
		wired_page_list = mem;
	}

	/*
	 *	Allocate a new object (if necessary).  We must do this before
	 *	locking the map, or risk deadlock with the default pager.
	 */
	if ((flags & KMA_KOBJECT) != 0) {
		object = kernel_object;
		vm_object_reference(object);
	} else {
		object = vm_object_allocate(map_size);
	}

	kr = vm_map_find_space(map, &map_addr,
			       fill_size, map_mask,
			       vm_alloc_flags, &entry);
	if (KERN_SUCCESS != kr) {
		vm_object_deallocate(object);
		goto out;
	}

	entry->object.vm_object = object;
	entry->offset = offset = (object == kernel_object) ? 
		        map_addr : 0;

	entry->wired_count++;

	if (flags & KMA_PERMANENT)
		entry->permanent = TRUE;

	if (object != kernel_object)
		vm_object_reference(object);

	vm_object_lock(object);
	vm_map_unlock(map);

	pg_offset = 0;

	if (fill_start) {
		if (guard_page_list == NULL)
			panic("kernel_memory_allocate: guard_page_list == NULL");

		mem = guard_page_list;
		guard_page_list = (vm_page_t)mem->pageq.next;
		mem->pageq.next = NULL;

		vm_page_insert(mem, object, offset + pg_offset);

		mem->busy = FALSE;
		pg_offset += PAGE_SIZE_64;
	}

	kma_prot = VM_PROT_READ | VM_PROT_WRITE;

	for (pg_offset = fill_start; pg_offset < fill_start + fill_size; pg_offset += PAGE_SIZE_64) {
		if (wired_page_list == NULL)
			panic("kernel_memory_allocate: wired_page_list == NULL");

		mem = wired_page_list;
		wired_page_list = (vm_page_t)mem->pageq.next;
		mem->pageq.next = NULL;
		mem->wire_count++;

		vm_page_insert(mem, object, offset + pg_offset);

		mem->busy = FALSE;
		mem->pmapped = TRUE;
		mem->wpmapped = TRUE;

		PMAP_ENTER(kernel_pmap, map_addr + pg_offset, mem, 
			   kma_prot, VM_PROT_NONE, ((flags & KMA_KSTACK) ? VM_MEM_STACK : 0), TRUE);

		if (flags & KMA_NOENCRYPT) {
			bzero(CAST_DOWN(void *, (map_addr + pg_offset)), PAGE_SIZE);

			pmap_set_noencrypt(mem->phys_page);
		}
	}
	if ((fill_start + fill_size) < map_size) {
		if (guard_page_list == NULL)
			panic("kernel_memory_allocate: guard_page_list == NULL");

		mem = guard_page_list;
		guard_page_list = (vm_page_t)mem->pageq.next;
		mem->pageq.next = NULL;

		vm_page_insert(mem, object, offset + pg_offset);

		mem->busy = FALSE;
	}
	if (guard_page_list || wired_page_list)
		panic("kernel_memory_allocate: non empty list\n");

	vm_page_lockspin_queues();
	vm_page_wire_count += wired_page_count;
	vm_page_unlock_queues();

	vm_object_unlock(object);

	/*
	 * now that the pages are wired, we no longer have to fear coalesce
	 */
	if (object == kernel_object)
		vm_map_simplify(map, map_addr);
	else
		vm_object_deallocate(object);

	/*
	 *	Return the memory, not zeroed.
	 */
	*addrp = CAST_DOWN(vm_offset_t, map_addr);
	return KERN_SUCCESS;

out:
	if (guard_page_list)
		vm_page_free_list(guard_page_list, FALSE);

	if (wired_page_list)
		vm_page_free_list(wired_page_list, FALSE);

	return kr;
}

/*
 *	kmem_alloc:
 *
 *	Allocate wired-down memory in the kernel's address map
 *	or a submap.  The memory is not zero-filled.
 */

kern_return_t
kmem_alloc(
	vm_map_t	map,
	vm_offset_t	*addrp,
	vm_size_t	size)
{
	kern_return_t kr = kernel_memory_allocate(map, addrp, size, 0, 0);
	TRACE_MACHLEAKS(KMEM_ALLOC_CODE, KMEM_ALLOC_CODE_2, size, *addrp);
	return kr;
}

/*
 *	kmem_realloc:
 *
 *	Reallocate wired-down memory in the kernel's address map
 *	or a submap.  Newly allocated pages are not zeroed.
 *	This can only be used on regions allocated with kmem_alloc.
 *
 *	If successful, the pages in the old region are mapped twice.
 *	The old region is unchanged.  Use kmem_free to get rid of it.
 */
kern_return_t
kmem_realloc(
	vm_map_t		map,
	vm_offset_t		oldaddr,
	vm_size_t		oldsize,
	vm_offset_t		*newaddrp,
	vm_size_t		newsize)
{
	vm_object_t		object;
	vm_object_offset_t	offset;
	vm_map_offset_t		oldmapmin;
	vm_map_offset_t		oldmapmax;
	vm_map_offset_t		newmapaddr;
	vm_map_size_t		oldmapsize;
	vm_map_size_t		newmapsize;
	vm_map_entry_t		oldentry;
	vm_map_entry_t		newentry;
	vm_page_t		mem;
	kern_return_t		kr;

	oldmapmin = vm_map_trunc_page(oldaddr);
	oldmapmax = vm_map_round_page(oldaddr + oldsize);
	oldmapsize = oldmapmax - oldmapmin;
	newmapsize = vm_map_round_page(newsize);


	/*
	 *	Find the VM object backing the old region.
	 */

	vm_map_lock(map);

	if (!vm_map_lookup_entry(map, oldmapmin, &oldentry))
		panic("kmem_realloc");
	object = oldentry->object.vm_object;

	/*
	 *	Increase the size of the object and
	 *	fill in the new region.
	 */

	vm_object_reference(object);
	/* by grabbing the object lock before unlocking the map */
	/* we guarantee that we will panic if more than one     */
	/* attempt is made to realloc a kmem_alloc'd area       */
	vm_object_lock(object);
	vm_map_unlock(map);
	if (object->vo_size != oldmapsize)
		panic("kmem_realloc");
	object->vo_size = newmapsize;
	vm_object_unlock(object);

	/* allocate the new pages while expanded portion of the */
	/* object is still not mapped */
	kmem_alloc_pages(object, vm_object_round_page(oldmapsize),
			 vm_object_round_page(newmapsize-oldmapsize));

	/*
	 *	Find space for the new region.
	 */

	kr = vm_map_find_space(map, &newmapaddr, newmapsize,
			       (vm_map_offset_t) 0, 0, &newentry);
	if (kr != KERN_SUCCESS) {
		vm_object_lock(object);
		for(offset = oldmapsize; 
		    offset < newmapsize; offset += PAGE_SIZE) {
	    		if ((mem = vm_page_lookup(object, offset)) != VM_PAGE_NULL) {
				VM_PAGE_FREE(mem);
			}
		}
		object->vo_size = oldmapsize;
		vm_object_unlock(object);
		vm_object_deallocate(object);
		return kr;
	}
	newentry->object.vm_object = object;
	newentry->offset = 0;
	assert (newentry->wired_count == 0);

	
	/* add an extra reference in case we have someone doing an */
	/* unexpected deallocate */
	vm_object_reference(object);
	vm_map_unlock(map);

	kr = vm_map_wire(map, newmapaddr, newmapaddr + newmapsize, VM_PROT_DEFAULT, FALSE);
	if (KERN_SUCCESS != kr) {
		vm_map_remove(map, newmapaddr, newmapaddr + newmapsize, 0);
		vm_object_lock(object);
		for(offset = oldsize; offset < newmapsize; offset += PAGE_SIZE) {
	    		if ((mem = vm_page_lookup(object, offset)) != VM_PAGE_NULL) {
				VM_PAGE_FREE(mem);
			}
		}
		object->vo_size = oldmapsize;
		vm_object_unlock(object);
		vm_object_deallocate(object);
		return (kr);
	}
	vm_object_deallocate(object);

	*newaddrp = CAST_DOWN(vm_offset_t, newmapaddr);
	return KERN_SUCCESS;
}

/*
 *	kmem_alloc_kobject:
 *
 *	Allocate wired-down memory in the kernel's address map
 *	or a submap.  The memory is not zero-filled.
 *
 *	The memory is allocated in the kernel_object.
 *	It may not be copied with vm_map_copy, and
 *	it may not be reallocated with kmem_realloc.
 */

kern_return_t
kmem_alloc_kobject(
	vm_map_t	map,
	vm_offset_t	*addrp,
	vm_size_t	size)
{
	return kernel_memory_allocate(map, addrp, size, 0, KMA_KOBJECT);
}

/*
 *	kmem_alloc_aligned:
 *
 *	Like kmem_alloc_kobject, except that the memory is aligned.
 *	The size should be a power-of-2.
 */

kern_return_t
kmem_alloc_aligned(
	vm_map_t	map,
	vm_offset_t	*addrp,
	vm_size_t	size)
{
	if ((size & (size - 1)) != 0)
		panic("kmem_alloc_aligned: size not aligned");
	return kernel_memory_allocate(map, addrp, size, size - 1, KMA_KOBJECT);
}

/*
 *	kmem_alloc_pageable:
 *
 *	Allocate pageable memory in the kernel's address map.
 */

kern_return_t
kmem_alloc_pageable(
	vm_map_t	map,
	vm_offset_t	*addrp,
	vm_size_t	size)
{
	vm_map_offset_t map_addr;
	vm_map_size_t	map_size;
	kern_return_t kr;

#ifndef normal
	map_addr = (vm_map_min(map)) + 0x1000;
#else
	map_addr = vm_map_min(map);
#endif
	map_size = vm_map_round_page(size);

	kr = vm_map_enter(map, &map_addr, map_size,
			  (vm_map_offset_t) 0, VM_FLAGS_ANYWHERE,
			  VM_OBJECT_NULL, (vm_object_offset_t) 0, FALSE,
			  VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);

	if (kr != KERN_SUCCESS)
		return kr;

	*addrp = CAST_DOWN(vm_offset_t, map_addr);
	return KERN_SUCCESS;
}

/*
 *	kmem_free:
 *
 *	Release a region of kernel virtual memory allocated
 *	with kmem_alloc, kmem_alloc_kobject, or kmem_alloc_pageable,
 *	and return the physical pages associated with that region.
 */

void
kmem_free(
	vm_map_t	map,
	vm_offset_t	addr,
	vm_size_t	size)
{
	kern_return_t kr;

	assert(addr >= VM_MIN_KERNEL_AND_KEXT_ADDRESS);

	TRACE_MACHLEAKS(KMEM_FREE_CODE, KMEM_FREE_CODE_2, size, addr);

	if(size == 0) {
#if MACH_ASSERT
		printf("kmem_free called with size==0 for map: %p with addr: 0x%llx\n",map,(uint64_t)addr);
#endif
		return;
	}

	kr = vm_map_remove(map, vm_map_trunc_page(addr),
				vm_map_round_page(addr + size), 
				VM_MAP_REMOVE_KUNWIRE);
	if (kr != KERN_SUCCESS)
		panic("kmem_free");
}

/*
 *	Allocate new pages in an object.
 */

kern_return_t
kmem_alloc_pages(
	register vm_object_t		object,
	register vm_object_offset_t	offset,
	register vm_object_size_t	size)
{
	vm_object_size_t		alloc_size;

	alloc_size = vm_object_round_page(size);
        vm_object_lock(object);
	while (alloc_size) {
	    register vm_page_t	mem;


	    /*
	     *	Allocate a page
	     */
	    while (VM_PAGE_NULL == 
		  (mem = vm_page_alloc(object, offset))) {
		vm_object_unlock(object);
		VM_PAGE_WAIT();
		vm_object_lock(object);
	    }
	    mem->busy = FALSE;

	    alloc_size -= PAGE_SIZE;
	    offset += PAGE_SIZE;
	}
	vm_object_unlock(object);
	return KERN_SUCCESS;
}

/*
 *	Remap wired pages in an object into a new region.
 *	The object is assumed to be mapped into the kernel map or
 *	a submap.
 */
void
kmem_remap_pages(
	register vm_object_t		object,
	register vm_object_offset_t	offset,
	register vm_offset_t		start,
	register vm_offset_t		end,
	vm_prot_t			protection)
{

	vm_map_offset_t			map_start;
	vm_map_offset_t			map_end;

	/*
	 *	Mark the pmap region as not pageable.
	 */
	map_start = vm_map_trunc_page(start);
	map_end = vm_map_round_page(end);

	pmap_pageable(kernel_pmap, map_start, map_end, FALSE);

	while (map_start < map_end) {
	    register vm_page_t	mem;

	    vm_object_lock(object);

	    /*
	     *	Find a page
	     */
	    if ((mem = vm_page_lookup(object, offset)) == VM_PAGE_NULL)
		panic("kmem_remap_pages");

	    /*
	     *	Wire it down (again)
	     */
	    vm_page_lockspin_queues();
	    vm_page_wire(mem);
	    vm_page_unlock_queues();
	    vm_object_unlock(object);

	    /*
	     * ENCRYPTED SWAP:
	     * The page is supposed to be wired now, so it
	     * shouldn't be encrypted at this point.  It can
	     * safely be entered in the page table.
	     */
	    ASSERT_PAGE_DECRYPTED(mem);

	    /*
	     *	Enter it in the kernel pmap.  The page isn't busy,
	     *	but this shouldn't be a problem because it is wired.
	     */

	    mem->pmapped = TRUE;
	    mem->wpmapped = TRUE;

	    PMAP_ENTER(kernel_pmap, map_start, mem, protection, VM_PROT_NONE, 0, TRUE);

	    map_start += PAGE_SIZE;
	    offset += PAGE_SIZE;
	}
}

/*
 *	kmem_suballoc:
 *
 *	Allocates a map to manage a subrange
 *	of the kernel virtual address space.
 *
 *	Arguments are as follows:
 *
 *	parent		Map to take range from
 *	addr		Address of start of range (IN/OUT)
 *	size		Size of range to find
 *	pageable	Can region be paged
 *	anywhere	Can region be located anywhere in map
 *	new_map		Pointer to new submap
 */
kern_return_t
kmem_suballoc(
	vm_map_t	parent,
	vm_offset_t	*addr,
	vm_size_t	size,
	boolean_t	pageable,
	int		flags,
	vm_map_t	*new_map)
{
	vm_map_t	map;
	vm_map_offset_t	map_addr;
	vm_map_size_t	map_size;
	kern_return_t	kr;

	map_size = vm_map_round_page(size);

	/*
	 *	Need reference on submap object because it is internal
	 *	to the vm_system.  vm_object_enter will never be called
	 *	on it (usual source of reference for vm_map_enter).
	 */
	vm_object_reference(vm_submap_object);

	map_addr = (flags & VM_FLAGS_ANYWHERE) ?
	           vm_map_min(parent) : vm_map_trunc_page(*addr);

	kr = vm_map_enter(parent, &map_addr, map_size,
			  (vm_map_offset_t) 0, flags,
			  vm_submap_object, (vm_object_offset_t) 0, FALSE,
			  VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);
	if (kr != KERN_SUCCESS) {
		vm_object_deallocate(vm_submap_object);
		return (kr);
	}

	pmap_reference(vm_map_pmap(parent));
	map = vm_map_create(vm_map_pmap(parent), map_addr, map_addr + map_size, pageable);
	if (map == VM_MAP_NULL)
		panic("kmem_suballoc: vm_map_create failed");	/* "can't happen" */

	kr = vm_map_submap(parent, map_addr, map_addr + map_size, map, map_addr, FALSE);
	if (kr != KERN_SUCCESS) {
		/*
		 * See comment preceding vm_map_submap().
		 */
		vm_map_remove(parent, map_addr, map_addr + map_size, VM_MAP_NO_FLAGS);
		vm_map_deallocate(map);	/* also removes ref to pmap */
		vm_object_deallocate(vm_submap_object);
		return (kr);
	}
	*addr = CAST_DOWN(vm_offset_t, map_addr);
	*new_map = map;
	return (KERN_SUCCESS);
}

/*
 *	kmem_init:
 *
 *	Initialize the kernel's virtual memory map, taking
 *	into account all memory allocated up to this time.
 */
void
kmem_init(
	vm_offset_t	start,
	vm_offset_t	end)
{
	vm_map_offset_t map_start;
	vm_map_offset_t map_end;

	map_start = vm_map_trunc_page(start);
	map_end = vm_map_round_page(end);

	kernel_map = vm_map_create(pmap_kernel(),VM_MIN_KERNEL_AND_KEXT_ADDRESS,
			    map_end, FALSE);
	/*
	 *	Reserve virtual memory allocated up to this time.
	 */
	if (start != VM_MIN_KERNEL_AND_KEXT_ADDRESS) {
		vm_map_offset_t map_addr;
		kern_return_t kr;
 
		map_addr = VM_MIN_KERNEL_AND_KEXT_ADDRESS;
		kr = vm_map_enter(kernel_map,
			&map_addr, 
		    	(vm_map_size_t)(map_start - VM_MIN_KERNEL_AND_KEXT_ADDRESS),
			(vm_map_offset_t) 0,
			VM_FLAGS_FIXED | VM_FLAGS_NO_PMAP_CHECK,
			VM_OBJECT_NULL, 
			(vm_object_offset_t) 0, FALSE,
			VM_PROT_NONE, VM_PROT_NONE,
			VM_INHERIT_DEFAULT);
		
		if (kr != KERN_SUCCESS) {
			panic("kmem_init(0x%llx,0x%llx): vm_map_enter(0x%llx,0x%llx) error 0x%x\n",
			      (uint64_t) start, (uint64_t) end,
			      (uint64_t) VM_MIN_KERNEL_AND_KEXT_ADDRESS,
			      (uint64_t) (map_start - VM_MIN_KERNEL_AND_KEXT_ADDRESS),
			      kr);
		}	
	}

	/*
	 * Set the default global user wire limit which limits the amount of
	 * memory that can be locked via mlock().  We set this to the total
	 * amount of memory that are potentially usable by a user app (max_mem)
	 * minus a certain amount.  This can be overridden via a sysctl.
	 */
	vm_global_no_user_wire_amount = MIN(max_mem*20/100,
					    VM_NOT_USER_WIREABLE);
	vm_global_user_wire_limit = max_mem - vm_global_no_user_wire_amount;
	
	/* the default per user limit is the same as the global limit */
	vm_user_wire_limit = vm_global_user_wire_limit;
}


/*
 *	Routine:	copyinmap
 *	Purpose:
 *		Like copyin, except that fromaddr is an address
 *		in the specified VM map.  This implementation
 *		is incomplete; it handles the current user map
 *		and the kernel map/submaps.
 */
kern_return_t
copyinmap(
	vm_map_t		map,
	vm_map_offset_t		fromaddr,
	void			*todata,
	vm_size_t		length)
{
	kern_return_t	kr = KERN_SUCCESS;
	vm_map_t oldmap;

	if (vm_map_pmap(map) == pmap_kernel())
	{
		/* assume a correct copy */
		memcpy(todata, CAST_DOWN(void *, fromaddr), length);
	} 
	else if (current_map() == map)
	{
		if (copyin(fromaddr, todata, length) != 0)
			kr = KERN_INVALID_ADDRESS;
	}
	else
	{
		vm_map_reference(map);
		oldmap = vm_map_switch(map);
		if (copyin(fromaddr, todata, length) != 0)
			kr = KERN_INVALID_ADDRESS;
		vm_map_switch(oldmap);
		vm_map_deallocate(map);
	}
	return kr;
}

/*
 *	Routine:	copyoutmap
 *	Purpose:
 *		Like copyout, except that toaddr is an address
 *		in the specified VM map.  This implementation
 *		is incomplete; it handles the current user map
 *		and the kernel map/submaps.
 */
kern_return_t
copyoutmap(
	vm_map_t		map,
	void			*fromdata,
	vm_map_address_t	toaddr,
	vm_size_t		length)
{
	if (vm_map_pmap(map) == pmap_kernel()) {
		/* assume a correct copy */
		memcpy(CAST_DOWN(void *, toaddr), fromdata, length);
		return KERN_SUCCESS;
	}

	if (current_map() != map)
		return KERN_NOT_SUPPORTED;

	if (copyout(fromdata, toaddr, length) != 0)
		return KERN_INVALID_ADDRESS;

	return KERN_SUCCESS;
}


kern_return_t
vm_conflict_check(
	vm_map_t		map,
	vm_map_offset_t	off,
	vm_map_size_t		len,
	memory_object_t	pager,
	vm_object_offset_t	file_off)
{
	vm_map_entry_t		entry;
	vm_object_t		obj;
	vm_object_offset_t	obj_off;
	vm_map_t		base_map;
	vm_map_offset_t		base_offset;
	vm_map_offset_t		original_offset;
	kern_return_t		kr;
	vm_map_size_t		local_len;

	base_map = map;
	base_offset = off;
	original_offset = off;
	kr = KERN_SUCCESS;
	vm_map_lock(map);
	while(vm_map_lookup_entry(map, off, &entry)) {
		local_len = len;

		if (entry->object.vm_object == VM_OBJECT_NULL) {
			vm_map_unlock(map);
			return KERN_SUCCESS;
		}
		if (entry->is_sub_map) {
			vm_map_t	old_map;

			old_map = map;
			vm_map_lock(entry->object.sub_map);
			map = entry->object.sub_map;
			off = entry->offset + (off - entry->vme_start);
			vm_map_unlock(old_map);
			continue;
		}
		obj = entry->object.vm_object;
		obj_off = (off - entry->vme_start) + entry->offset;
		while(obj->shadow) {
			obj_off += obj->vo_shadow_offset;
			obj = obj->shadow;
		}
		if((obj->pager_created) && (obj->pager == pager)) {
			if(((obj->paging_offset) + obj_off) == file_off) {
				if(off != base_offset) {
					vm_map_unlock(map);
					return KERN_FAILURE;
				}
				kr = KERN_ALREADY_WAITING;
			} else {
			       	vm_object_offset_t	obj_off_aligned;
				vm_object_offset_t	file_off_aligned;

				obj_off_aligned = obj_off & ~PAGE_MASK;
				file_off_aligned = file_off & ~PAGE_MASK;

				if (file_off_aligned == (obj->paging_offset + obj_off_aligned)) {
				        /*
					 * the target map and the file offset start in the same page
					 * but are not identical... 
					 */
				        vm_map_unlock(map);
					return KERN_FAILURE;
				}
				if ((file_off < (obj->paging_offset + obj_off_aligned)) &&
				    ((file_off + len) > (obj->paging_offset + obj_off_aligned))) {
				        /*
					 * some portion of the tail of the I/O will fall
					 * within the encompass of the target map
					 */
				        vm_map_unlock(map);
					return KERN_FAILURE;
				}
				if ((file_off_aligned > (obj->paging_offset + obj_off)) &&
				    (file_off_aligned < (obj->paging_offset + obj_off) + len)) {
				        /*
					 * the beginning page of the file offset falls within
					 * the target map's encompass
					 */
				        vm_map_unlock(map);
					return KERN_FAILURE;
				}
			}
		} else if(kr != KERN_SUCCESS) {
		        vm_map_unlock(map);
			return KERN_FAILURE;
		}

		if(len <= ((entry->vme_end - entry->vme_start) -
						(off - entry->vme_start))) {
			vm_map_unlock(map);
			return kr;
		} else {
			len -= (entry->vme_end - entry->vme_start) -
						(off - entry->vme_start);
		}
		base_offset = base_offset + (local_len - len);
		file_off = file_off + (local_len - len);
		off = base_offset;
		if(map != base_map) {
			vm_map_unlock(map);
			vm_map_lock(base_map);
			map = base_map;
		}
	}

	vm_map_unlock(map);
	return kr;
}

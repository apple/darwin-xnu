/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
/*
 *	Variables exported by this module.
 */

vm_map_t	kernel_map;
vm_map_t	kernel_pageable_map;

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

	if (map == VM_MAP_NULL || (flags && (flags ^ KMA_KOBJECT))) 
		return KERN_INVALID_ARGUMENT;
	
	if (size == 0) {
		*addrp = 0;
		return KERN_INVALID_ARGUMENT;
	}

	map_size = vm_map_round_page(size);
	map_mask = (vm_map_offset_t)mask;

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

	kr = vm_map_find_space(map, &map_addr, map_size, map_mask, &entry);
	if (KERN_SUCCESS != kr) {
		vm_object_deallocate(object);
		return kr;
	}

	entry->object.vm_object = object;
	entry->offset = offset = (object == kernel_object) ? 
		        map_addr - VM_MIN_KERNEL_ADDRESS : 0;

	/* Take an extra object ref in case the map entry gets deleted */
	vm_object_reference(object);
	vm_map_unlock(map);

	kr = cpm_allocate(CAST_DOWN(vm_size_t, map_size), &pages, FALSE);

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

	*addrp = map_addr;
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
	vm_map_entry_t 		entry;
	vm_map_offset_t 	map_addr;
	vm_map_offset_t		map_mask;
	vm_map_size_t		map_size;
	vm_map_size_t		i;
	kern_return_t 		kr;

	if (size == 0) {
		*addrp = 0;
		return KERN_INVALID_ARGUMENT;
	}

	map_size = vm_map_round_page(size);
	map_mask = (vm_map_offset_t) mask;

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

	kr = vm_map_find_space(map, &map_addr, map_size, map_mask, &entry);
	if (KERN_SUCCESS != kr) {
		vm_object_deallocate(object);
		return kr;
	}

	entry->object.vm_object = object;
	entry->offset = offset = (object == kernel_object) ? 
		        map_addr - VM_MIN_KERNEL_ADDRESS : 0;

	vm_object_reference(object);
	vm_map_unlock(map);

	vm_object_lock(object);
	for (i = 0; i < map_size; i += PAGE_SIZE) {
		vm_page_t	mem;

		while (VM_PAGE_NULL == 
		       (mem = vm_page_alloc(object, offset + i))) {
			if (flags & KMA_NOPAGEWAIT) {
				if (object == kernel_object)
					vm_object_page_remove(object, offset, offset + i);
				vm_object_unlock(object);
				vm_map_remove(map, map_addr, map_addr + map_size, 0);
				vm_object_deallocate(object);
				return KERN_RESOURCE_SHORTAGE;
			}
			vm_object_unlock(object);
			VM_PAGE_WAIT();
			vm_object_lock(object);
		}
		mem->busy = FALSE;
	}
	vm_object_unlock(object);

	if ((kr = vm_map_wire(map, map_addr, map_addr + map_size, VM_PROT_DEFAULT, FALSE)) 
		!= KERN_SUCCESS) {
		if (object == kernel_object) {
			vm_object_lock(object);
			vm_object_page_remove(object, offset, offset + map_size);
			vm_object_unlock(object);
		}
		vm_map_remove(map, map_addr, map_addr + map_size, 0);
		vm_object_deallocate(object);
		return (kr);
	}
	/* now that the page is wired, we no longer have to fear coalesce */
	vm_object_deallocate(object);
	if (object == kernel_object)
		vm_map_simplify(map, map_addr);

	/*
	 *	Return the memory, not zeroed.
	 */
	*addrp = CAST_DOWN(vm_offset_t, map_addr);
	return KERN_SUCCESS;
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
	return kernel_memory_allocate(map, addrp, size, 0, 0);
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
	if (object->size != oldmapsize)
		panic("kmem_realloc");
	object->size = newmapsize;
	vm_object_unlock(object);

	/* allocate the new pages while expanded portion of the */
	/* object is still not mapped */
	kmem_alloc_pages(object, vm_object_round_page(oldmapsize),
			 vm_object_round_page(newmapsize-oldmapsize));

	/*
	 *	Find space for the new region.
	 */

	kr = vm_map_find_space(map, &newmapaddr, newmapsize,
			       (vm_map_offset_t) 0, &newentry);
	if (kr != KERN_SUCCESS) {
		vm_object_lock(object);
		for(offset = oldmapsize; 
		    offset < newmapsize; offset += PAGE_SIZE) {
	    		if ((mem = vm_page_lookup(object, offset)) != VM_PAGE_NULL) {
				vm_page_lock_queues();
				vm_page_free(mem);
				vm_page_unlock_queues();
			}
		}
		object->size = oldmapsize;
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
				vm_page_lock_queues();
				vm_page_free(mem);
				vm_page_unlock_queues();
			}
		}
		object->size = oldmapsize;
		vm_object_unlock(object);
		vm_object_deallocate(object);
		return (kr);
	}
	vm_object_deallocate(object);

	*newaddrp = CAST_DOWN(vm_offset_t, newmapaddr);
	return KERN_SUCCESS;
}

/*
 *	kmem_alloc_wired:
 *
 *	Allocate wired-down memory in the kernel's address map
 *	or a submap.  The memory is not zero-filled.
 *
 *	The memory is allocated in the kernel_object.
 *	It may not be copied with vm_map_copy, and
 *	it may not be reallocated with kmem_realloc.
 */

kern_return_t
kmem_alloc_wired(
	vm_map_t	map,
	vm_offset_t	*addrp,
	vm_size_t	size)
{
	return kernel_memory_allocate(map, addrp, size, 0, KMA_KOBJECT);
}

/*
 *	kmem_alloc_aligned:
 *
 *	Like kmem_alloc_wired, except that the memory is aligned.
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
 *	with kmem_alloc, kmem_alloc_wired, or kmem_alloc_pageable,
 *	and return the physical pages associated with that region.
 */

void
kmem_free(
	vm_map_t	map,
	vm_offset_t	addr,
	vm_size_t	size)
{
	kern_return_t kr;

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
	    vm_page_lock_queues();
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
	    PMAP_ENTER(kernel_pmap, map_start, mem, protection, 
			((unsigned int)(mem->object->wimg_bits))
					& VM_WIMG_MASK,
			TRUE);

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

	kernel_map = vm_map_create(pmap_kernel(),VM_MIN_KERNEL_ADDRESS,
				   map_end, FALSE);

	/*
	 *	Reserve virtual memory allocated up to this time.
	 */

	if (start != VM_MIN_KERNEL_ADDRESS) {
		vm_map_offset_t map_addr;

		map_addr = VM_MIN_KERNEL_ADDRESS;
		(void) vm_map_enter(kernel_map,
				    &map_addr, 
				    (vm_map_size_t)(map_start - VM_MIN_KERNEL_ADDRESS),
				    (vm_map_offset_t) 0,
				    VM_FLAGS_ANYWHERE | VM_FLAGS_NO_PMAP_CHECK,
				    VM_OBJECT_NULL, 
				    (vm_object_offset_t) 0, FALSE,
				    VM_PROT_DEFAULT, VM_PROT_ALL,
				    VM_INHERIT_DEFAULT);
	}

        /*
         * Account for kernel memory (text, data, bss, vm shenanigans).
         * This may include inaccessible "holes" as determined by what
         * the machine-dependent init code includes in max_mem.
         */
        vm_page_wire_count = (atop_64(max_mem) - (vm_page_free_count
                                                + vm_page_active_count
                                                + vm_page_inactive_count));
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
			obj_off += obj->shadow_offset;
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

/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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

#include <cpus.h>
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
	register vm_offset_t		start,
	register vm_offset_t		end,
	vm_prot_t			protection);

extern void kmem_remap_pages(
	register vm_object_t		object,
	register vm_object_offset_t	offset,
	register vm_offset_t		start,
	register vm_offset_t		end,
	vm_prot_t			protection);

kern_return_t
kmem_alloc_contig(
	vm_map_t	map,
	vm_offset_t	*addrp,
	vm_size_t	size,
	vm_offset_t 	mask,
	int 		flags)
{
	vm_object_t		object;
	vm_page_t		m, pages;
	kern_return_t		kr;
	vm_offset_t		addr, i; 
	vm_object_offset_t	offset;
	vm_map_entry_t		entry;

	if (map == VM_MAP_NULL || (flags && (flags ^ KMA_KOBJECT))) 
		return KERN_INVALID_ARGUMENT;
	
	if (size == 0) {
		*addrp = 0;
		return KERN_INVALID_ARGUMENT;
	}

	size = round_page(size);
	if ((flags & KMA_KOBJECT) == 0) {
		object = vm_object_allocate(size);
		kr = vm_map_find_space(map, &addr, size, mask, &entry);
	}
	else {
		object = kernel_object;
		kr = vm_map_find_space(map, &addr, size, mask, &entry);
	}

	if ((flags & KMA_KOBJECT) == 0) {
		entry->object.vm_object = object;
		entry->offset = offset = 0;
	} else {
		offset = addr - VM_MIN_KERNEL_ADDRESS;

		if (entry->object.vm_object == VM_OBJECT_NULL) {
			vm_object_reference(object);
			entry->object.vm_object = object;
			entry->offset = offset;
		}
	}

	if (kr != KERN_SUCCESS) {
		if ((flags & KMA_KOBJECT) == 0)
			vm_object_deallocate(object);
		return kr;
	}

	vm_map_unlock(map);

	kr = cpm_allocate(size, &pages, FALSE);

	if (kr != KERN_SUCCESS) {
		vm_map_remove(map, addr, addr + size, 0);
		*addrp = 0;
		return kr;
	}

	vm_object_lock(object);
	for (i = 0; i < size; i += PAGE_SIZE) {
		m = pages;
		pages = NEXT_PAGE(m);
		m->busy = FALSE;
		vm_page_insert(m, object, offset + i);
	}
	vm_object_unlock(object);

	if ((kr = vm_map_wire(map, addr, addr + size, VM_PROT_DEFAULT, FALSE)) 
		!= KERN_SUCCESS) {
		if (object == kernel_object) {
			vm_object_lock(object);
			vm_object_page_remove(object, offset, offset + size);
			vm_object_unlock(object);
		}
		vm_map_remove(map, addr, addr + size, 0);
		return kr;
	}
	if (object == kernel_object)
		vm_map_simplify(map, addr);

	*addrp = addr;
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
	vm_object_t 		object = VM_OBJECT_NULL;
	vm_map_entry_t 		entry;
	vm_object_offset_t 		offset;
	vm_offset_t 		addr;
	vm_offset_t		i;
	kern_return_t 		kr;

	size = round_page(size);
	if ((flags & KMA_KOBJECT) == 0) {
		/*
		 *	Allocate a new object.  We must do this before locking
		 *	the map, or risk deadlock with the default pager:
		 *		device_read_alloc uses kmem_alloc,
		 *		which tries to allocate an object,
		 *		which uses kmem_alloc_wired to get memory,
		 *		which blocks for pages.
		 *		then the default pager needs to read a block
		 *		to process a memory_object_data_write,
		 *		and device_read_alloc calls kmem_alloc
		 *		and deadlocks on the map lock.
		 */
		object = vm_object_allocate(size);
		kr = vm_map_find_space(map, &addr, size, mask, &entry);
	}
	else {
		object = kernel_object;
		kr = vm_map_find_space(map, &addr, size, mask, &entry);
	}
	if (kr != KERN_SUCCESS) {
		if ((flags & KMA_KOBJECT) == 0)
			vm_object_deallocate(object);
		return kr;
	}

	if ((flags & KMA_KOBJECT) == 0) {
		entry->object.vm_object = object;
		entry->offset = offset = 0;
	} else {
		offset = addr - VM_MIN_KERNEL_ADDRESS;

		if (entry->object.vm_object == VM_OBJECT_NULL) {
			vm_object_reference(object);
			entry->object.vm_object = object;
			entry->offset = offset;
		}
	}

	/*
	 *	Since we have not given out this address yet,
	 *	it is safe to unlock the map.
	 */
	vm_map_unlock(map);

	vm_object_lock(object);
	for (i = 0; i < size; i += PAGE_SIZE) {
		vm_page_t	mem;

		while ((mem = vm_page_alloc(object, 
					offset + (vm_object_offset_t)i))
			    == VM_PAGE_NULL) {
			if (flags & KMA_NOPAGEWAIT) {
				if (object == kernel_object)
					vm_object_page_remove(object, offset,
						offset + (vm_object_offset_t)i);
				vm_object_unlock(object);
				vm_map_remove(map, addr, addr + size, 0);
				return KERN_RESOURCE_SHORTAGE;
			}
			vm_object_unlock(object);
			VM_PAGE_WAIT();
			vm_object_lock(object);
		}
		mem->busy = FALSE;
	}
	vm_object_unlock(object);

	if ((kr = vm_map_wire(map, addr, addr + size, VM_PROT_DEFAULT, FALSE)) 
		!= KERN_SUCCESS) {
		if (object == kernel_object) {
			vm_object_lock(object);
			vm_object_page_remove(object, offset, offset + size);
			vm_object_unlock(object);
		}
		vm_map_remove(map, addr, addr + size, 0);
		return (kr);
	}
	if (object == kernel_object)
		vm_map_simplify(map, addr);

	/*
	 *	Return the memory, not zeroed.
	 */
#if	(NCPUS > 1)  &&  i860
	bzero( addr, size );
#endif                                  /* #if (NCPUS > 1)  &&  i860 */
	*addrp = addr;
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
	vm_map_t	map,
	vm_offset_t	oldaddr,
	vm_size_t	oldsize,
	vm_offset_t	*newaddrp,
	vm_size_t	newsize)
{
	vm_offset_t oldmin, oldmax;
	vm_offset_t newaddr;
	vm_object_t object;
	vm_map_entry_t oldentry, newentry;
	kern_return_t kr;

	oldmin = trunc_page(oldaddr);
	oldmax = round_page(oldaddr + oldsize);
	oldsize = oldmax - oldmin;
	newsize = round_page(newsize);

	/*
	 *	Find space for the new region.
	 */

	kr = vm_map_find_space(map, &newaddr, newsize, (vm_offset_t) 0,
			       &newentry);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	/*
	 *	Find the VM object backing the old region.
	 */

	if (!vm_map_lookup_entry(map, oldmin, &oldentry))
		panic("kmem_realloc");
	object = oldentry->object.vm_object;

	/*
	 *	Increase the size of the object and
	 *	fill in the new region.
	 */

	vm_object_reference(object);
	vm_object_lock(object);
	if (object->size != oldsize)
		panic("kmem_realloc");
	object->size = newsize;
	vm_object_unlock(object);

	newentry->object.vm_object = object;
	newentry->offset = 0;
	assert (newentry->wired_count == 0);
	newentry->wired_count = 1;

	/*
	 *	Since we have not given out this address yet,
	 *	it is safe to unlock the map.  We are trusting
	 *	that nobody will play with either region.
	 */

	vm_map_unlock(map);

	/*
	 *	Remap the pages in the old region and
	 *	allocate more pages for the new region.
	 */

	kmem_remap_pages(object, 0,
			 newaddr, newaddr + oldsize,
			 VM_PROT_DEFAULT);
	kmem_alloc_pages(object, oldsize,
			 newaddr + oldsize, newaddr + newsize,
			 VM_PROT_DEFAULT);

	*newaddrp = newaddr;
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
	vm_offset_t addr;
	kern_return_t kr;

#ifndef normal
	addr = (vm_map_min(map)) + 0x1000;
#else
	addr = vm_map_min(map);
#endif
	kr = vm_map_enter(map, &addr, round_page(size),
			  (vm_offset_t) 0, TRUE,
			  VM_OBJECT_NULL, (vm_object_offset_t) 0, FALSE,
			  VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);
	if (kr != KERN_SUCCESS)
		return kr;

	*addrp = addr;
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

	kr = vm_map_remove(map, trunc_page(addr),
			   round_page(addr + size), VM_MAP_REMOVE_KUNWIRE);
	if (kr != KERN_SUCCESS)
		panic("kmem_free");
}

/*
 *	Allocate new wired pages in an object.
 *	The object is assumed to be mapped into the kernel map or
 *	a submap.
 */

kern_return_t
kmem_alloc_pages(
	register vm_object_t		object,
	register vm_object_offset_t	offset,
	register vm_offset_t		start,
	register vm_offset_t		end,
	vm_prot_t			protection)
{
	/*
	 *	Mark the pmap region as not pageable.
	 */
	pmap_pageable(kernel_pmap, start, end, FALSE);

	while (start < end) {
	    register vm_page_t	mem;

	    vm_object_lock(object);

	    /*
	     *	Allocate a page
	     */
	    while ((mem = vm_page_alloc(object, offset))
			 == VM_PAGE_NULL) {
		vm_object_unlock(object);
		VM_PAGE_WAIT();
		vm_object_lock(object);
	    }

	    /*
	     *	Wire it down
	     */
	    vm_page_lock_queues();
	    vm_page_wire(mem);
	    vm_page_unlock_queues();
	    vm_object_unlock(object);

	    /*
	     *	Enter it in the kernel pmap
	     */
	    PMAP_ENTER(kernel_pmap, start, mem,
		       protection, TRUE);

	    vm_object_lock(object);
	    PAGE_WAKEUP_DONE(mem);
	    vm_object_unlock(object);

	    start += PAGE_SIZE;
	    offset += PAGE_SIZE_64;
	}
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
	/*
	 *	Mark the pmap region as not pageable.
	 */
	pmap_pageable(kernel_pmap, start, end, FALSE);

	while (start < end) {
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
	     *	Enter it in the kernel pmap.  The page isn't busy,
	     *	but this shouldn't be a problem because it is wired.
	     */
	    PMAP_ENTER(kernel_pmap, start, mem,
		       protection, TRUE);

	    start += PAGE_SIZE;
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
	boolean_t	anywhere,
	vm_map_t	*new_map)
{
	vm_map_t map;
	kern_return_t kr;

	size = round_page(size);

	/*
	 *	Need reference on submap object because it is internal
	 *	to the vm_system.  vm_object_enter will never be called
	 *	on it (usual source of reference for vm_map_enter).
	 */
	vm_object_reference(vm_submap_object);

	if (anywhere == TRUE)
		*addr = (vm_offset_t)vm_map_min(parent);
	kr = vm_map_enter(parent, addr, size,
			  (vm_offset_t) 0, anywhere,
			  vm_submap_object, (vm_object_offset_t) 0, FALSE,
			  VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);
	if (kr != KERN_SUCCESS) {
		vm_object_deallocate(vm_submap_object);
		return (kr);
	}

	pmap_reference(vm_map_pmap(parent));
	map = vm_map_create(vm_map_pmap(parent), *addr, *addr + size, pageable);
	if (map == VM_MAP_NULL)
		panic("kmem_suballoc: vm_map_create failed");	/* "can't happen" */

	kr = vm_map_submap(parent, *addr, *addr + size, map, *addr, FALSE);
	if (kr != KERN_SUCCESS) {
		/*
		 * See comment preceding vm_map_submap().
		 */
		vm_map_remove(parent, *addr, *addr + size, VM_MAP_NO_FLAGS);
		vm_map_deallocate(map);	/* also removes ref to pmap */
		vm_object_deallocate(vm_submap_object);
		return (kr);
	}

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
	kernel_map = vm_map_create(pmap_kernel(),
				   VM_MIN_KERNEL_ADDRESS, end,
				   FALSE);

	/*
	 *	Reserve virtual memory allocated up to this time.
	 */

	if (start != VM_MIN_KERNEL_ADDRESS) {
		vm_offset_t addr = VM_MIN_KERNEL_ADDRESS;
		(void) vm_map_enter(kernel_map,
				    &addr, start - VM_MIN_KERNEL_ADDRESS,
				    (vm_offset_t) 0, TRUE,
				    VM_OBJECT_NULL, 
				    (vm_object_offset_t) 0, FALSE,
				    VM_PROT_DEFAULT, VM_PROT_ALL,
				    VM_INHERIT_DEFAULT);
	}

        /*
         * Account for kernel memory (text, data, bss, vm shenanigans).
         * This may include inaccessible "holes" as determined by what
         * the machine-dependent init code includes in mem_size.
         */
        vm_page_wire_count = (atop(mem_size) - (vm_page_free_count
                                                + vm_page_active_count
                                                + vm_page_inactive_count));
}

/*
 *	kmem_io_map_copyout:
 *
 *	Establish temporary mapping in designated map for the memory
 *	passed in.  Memory format must be a page_list vm_map_copy.
 */

kern_return_t
kmem_io_map_copyout(
	vm_map_t 	map,
	vm_offset_t	*addr,  	/* actual addr of data */
	vm_size_t	*alloc_size,	/* size allocated */
	vm_map_copy_t	copy,
	vm_size_t	min_size,	/* Do at least this much */
	vm_prot_t	prot)		/* Protection of mapping */
{
	vm_offset_t	myaddr, offset;
	vm_size_t	mysize, copy_size;
	kern_return_t	ret;
	register
	vm_page_t	*page_list;
	vm_map_copy_t	new_copy;
	register
	int		i;

	assert(copy->type == VM_MAP_COPY_PAGE_LIST);
	assert(min_size != 0);

	/*
	 *	Figure out the size in vm pages.
	 */
	min_size += (vm_size_t)(copy->offset - trunc_page_64(copy->offset));
	min_size = round_page(min_size);
	mysize = (vm_size_t)(round_page_64(
			copy->offset + (vm_object_offset_t)copy->size) -
			trunc_page_64(copy->offset));

	/*
	 *	If total size is larger than one page list and
	 *	we don't have to do more than one page list, then
	 *	only do one page list.  
	 *
	 * XXX	Could be much smarter about this ... like trimming length
	 * XXX	if we need more than one page list but not all of them.
	 */

	copy_size = ptoa(copy->cpy_npages);
	if (mysize > copy_size && copy_size > min_size)
		mysize = copy_size;

	/*
	 *	Allocate some address space in the map (must be kernel
	 *	space).
	 */
	myaddr = vm_map_min(map);
	ret = vm_map_enter(map, &myaddr, mysize,
			  (vm_offset_t) 0, TRUE,
			  VM_OBJECT_NULL, (vm_object_offset_t) 0, FALSE,
			  prot, prot, VM_INHERIT_DEFAULT);

	if (ret != KERN_SUCCESS)
		return(ret);

	/*
	 *	Tell the pmap module that this will be wired, and
	 *	enter the mappings.
	 */
	pmap_pageable(vm_map_pmap(map), myaddr, myaddr + mysize, TRUE);

	*addr = myaddr + (vm_offset_t)
				(copy->offset - trunc_page_64(copy->offset));
	*alloc_size = mysize;

	offset = myaddr;
	page_list = &copy->cpy_page_list[0];
	while (TRUE) {
		for ( i = 0; i < copy->cpy_npages; i++, offset+=PAGE_SIZE_64) {
			PMAP_ENTER(vm_map_pmap(map), 
				   (vm_offset_t)offset, *page_list,
				   prot, TRUE);
			page_list++;
		}

		if (offset == (myaddr + mysize))
			break;

		/*
		 *	Onward to the next page_list.  The extend_cont
		 *	leaves the current page list's pages alone; 
		 *	they'll be cleaned up at discard.  Reset this
		 *	copy's continuation to discard the next one.
		 */
		vm_map_copy_invoke_extend_cont(copy, &new_copy, &ret);

		if (ret != KERN_SUCCESS) {
			kmem_io_map_deallocate(map, myaddr, mysize);
			return(ret);
		}
		copy->cpy_cont = vm_map_copy_discard_cont;
		copy->cpy_cont_args = (vm_map_copyin_args_t) new_copy;
		assert(new_copy != VM_MAP_COPY_NULL);
		assert(new_copy->type == VM_MAP_COPY_PAGE_LIST);
		copy = new_copy;
		page_list = &copy->cpy_page_list[0];
	}

	return(ret);
}

/*
 *	kmem_io_map_deallocate:
 *
 *	Get rid of the mapping established by kmem_io_map_copyout.
 *	Assumes that addr and size have been rounded to page boundaries.
 */

void
kmem_io_map_deallocate(
	vm_map_t	map,
	vm_offset_t	addr,
	vm_size_t	size)
{

	register vm_offset_t	va, end;

	end = round_page(addr + size);
	for (va = trunc_page(addr); va < end; va += PAGE_SIZE)
	    pmap_change_wiring(vm_map_pmap(map), va, FALSE);

	/*
	 *	Remove the mappings.  The pmap_remove is needed.
	 */
	
	pmap_remove(vm_map_pmap(map), addr, addr + size);
	vm_map_remove(map, addr, addr + size, VM_MAP_REMOVE_KUNWIRE);
}


/*
 *	kmem_io_object_trunc:
 *
 *	Truncate an object vm_map_copy_t.
 *	Called by the scatter/gather list network code to remove pages from
 *	the tail end of a packet. Also unwires the objects pages.
 */

kern_return_t
kmem_io_object_trunc(copy, new_size)
     vm_map_copy_t	copy;		/* IN/OUT copy object */
     register vm_size_t new_size;	/* IN new object size */
{
	register vm_size_t	offset, old_size;

	assert(copy->type == VM_MAP_COPY_OBJECT);

	old_size = (vm_size_t)round_page_64(copy->size);
	copy->size = new_size;
	new_size = round_page(new_size);

        vm_object_lock(copy->cpy_object);
        vm_object_page_remove(copy->cpy_object,
        	(vm_object_offset_t)new_size, (vm_object_offset_t)old_size);
        for (offset = 0; offset < new_size; offset += PAGE_SIZE) {
		register vm_page_t	mem;

		if ((mem = vm_page_lookup(copy->cpy_object, 
				(vm_object_offset_t)offset)) == VM_PAGE_NULL)
		    panic("kmem_io_object_trunc: unable to find object page");

		/*
		 * Make sure these pages are marked dirty
		 */
		mem->dirty = TRUE;
		vm_page_lock_queues();
		vm_page_unwire(mem);
		vm_page_unlock_queues();
	}
        copy->cpy_object->size = new_size;	/*  adjust size of object */
        vm_object_unlock(copy->cpy_object);
        return(KERN_SUCCESS);
}

/*
 *	kmem_io_object_deallocate:
 *
 *	Free an vm_map_copy_t.
 *	Called by the scatter/gather list network code to free a packet.
 */

void
kmem_io_object_deallocate(
     vm_map_copy_t	copy)		/* IN/OUT copy object */
{
	kern_return_t	ret;

	/*
	 * Clear out all the object pages (this will leave an empty object).
	 */
	ret = kmem_io_object_trunc(copy, 0);
	if (ret != KERN_SUCCESS)
		panic("kmem_io_object_deallocate: unable to truncate object");
	/*
	 * ...and discard the copy object.
	 */
	vm_map_copy_discard(copy);
}

/*
 *	Routine:	copyinmap
 *	Purpose:
 *		Like copyin, except that fromaddr is an address
 *		in the specified VM map.  This implementation
 *		is incomplete; it handles the current user map
 *		and the kernel map/submaps.
 */
boolean_t
copyinmap(
	vm_map_t	map,
	vm_offset_t	fromaddr,
	vm_offset_t	toaddr,
	vm_size_t	length)
{
	if (vm_map_pmap(map) == pmap_kernel()) {
		/* assume a correct copy */
		memcpy((void *)toaddr, (void *)fromaddr, length);
		return FALSE;
	}

	if (current_map() == map)
		return copyin((char *)fromaddr, (char *)toaddr, length);

	return TRUE;
}

/*
 *	Routine:	copyoutmap
 *	Purpose:
 *		Like copyout, except that toaddr is an address
 *		in the specified VM map.  This implementation
 *		is incomplete; it handles the current user map
 *		and the kernel map/submaps.
 */
boolean_t
copyoutmap(
	vm_map_t	map,
	vm_offset_t	fromaddr,
	vm_offset_t	toaddr,
	vm_size_t	length)
{
	if (vm_map_pmap(map) == pmap_kernel()) {
		/* assume a correct copy */
		memcpy((void *)toaddr, (void *)fromaddr, length);
		return FALSE;
	}

	if (current_map() == map)
		return copyout((char *)fromaddr, (char *)toaddr, length);

	return TRUE;
}

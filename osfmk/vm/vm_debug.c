/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
/*
 *	File:	vm/vm_debug.c.
 *	Author:	Rich Draves
 *	Date:	March, 1990
 *
 *	Exported kernel calls.  See mach_debug/mach_debug.defs.
 */
#include <mach_vm_debug.h>
#include <mach/kern_return.h>
#include <mach/mach_host_server.h>
#include <mach/vm_map_server.h>
#include <mach_debug/vm_info.h>
#include <mach_debug/page_info.h>
#include <mach_debug/hash_info.h>

#if MACH_VM_DEBUG
#include <mach/machine/vm_types.h>
#include <mach/memory_object_types.h>
#include <mach/vm_prot.h>
#include <mach/vm_inherit.h>
#include <mach/vm_param.h>
#include <kern/thread.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <kern/task.h>
#include <kern/host.h>
#include <ipc/ipc_port.h>
#include <vm/vm_debug.h>
#endif

/*
 *	Routine:	mach_vm_region_info [kernel call]
 *	Purpose:
 *		Retrieve information about a VM region,
 *		including info about the object chain.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Retrieve region/object info.
 *		KERN_INVALID_TASK	The map is null.
 *		KERN_NO_SPACE		There is no entry at/after the address.
 *		KERN_RESOURCE_SHORTAGE	Can't allocate memory.
 */

kern_return_t
mach_vm_region_info(
	vm_map_t		map,
	vm_offset_t		address,
	vm_info_region_t	*regionp,
	vm_info_object_array_t	*objectsp,
	mach_msg_type_number_t	*objectsCntp)
{
#if !MACH_VM_DEBUG
        return KERN_FAILURE;
#else
	vm_map_copy_t copy;
	vm_offset_t addr;	/* memory for OOL data */
	vm_size_t size;		/* size of the memory */
	unsigned int room;	/* room for this many objects */
	unsigned int used;	/* actually this many objects */
	vm_info_region_t region;
	kern_return_t kr;

	if (map == VM_MAP_NULL)
		return KERN_INVALID_TASK;

	size = 0;		/* no memory allocated yet */

	for (;;) {
		vm_map_t cmap;	/* current map in traversal */
		vm_map_t nmap;	/* next map to look at */
		vm_map_entry_t entry;
		vm_object_t object, cobject, nobject;

		/* nothing is locked */

		vm_map_lock_read(map);
		for (cmap = map;; cmap = nmap) {
			/* cmap is read-locked */

			if (!vm_map_lookup_entry(cmap, address, &entry)) {
				entry = entry->vme_next;
				if (entry == vm_map_to_entry(cmap)) {
					vm_map_unlock_read(cmap);
					if (size != 0)
						kmem_free(ipc_kernel_map,
							  addr, size);
					return KERN_NO_SPACE;
				}
			}

			if (entry->is_sub_map)
				nmap = entry->object.sub_map;
			else
				break;

			/* move down to the lower map */

			vm_map_lock_read(nmap);
			vm_map_unlock_read(cmap);
		}

		/* cmap is read-locked; we have a real entry */

		object = entry->object.vm_object;
		region.vir_start = entry->vme_start;
		region.vir_end = entry->vme_end;
		region.vir_object = (vm_offset_t) object;
		region.vir_offset = entry->offset;
		region.vir_needs_copy = entry->needs_copy;
		region.vir_protection = entry->protection;
		region.vir_max_protection = entry->max_protection;
		region.vir_inheritance = entry->inheritance;
		region.vir_wired_count = entry->wired_count;
		region.vir_user_wired_count = entry->user_wired_count;

		used = 0;
		room = size / sizeof(vm_info_object_t);

		if (object == VM_OBJECT_NULL) {
			vm_map_unlock_read(cmap);
			/* no memory needed */
			break;
		}

		vm_object_lock(object);
		vm_map_unlock_read(cmap);

		for (cobject = object;; cobject = nobject) {
			/* cobject is locked */

			if (used < room) {
				vm_info_object_t *vio =
					&((vm_info_object_t *) addr)[used];

				vio->vio_object =
					(vm_offset_t) cobject;
				vio->vio_size =
					cobject->size;
				vio->vio_ref_count =
					cobject->ref_count;
				vio->vio_resident_page_count =
					cobject->resident_page_count;
				vio->vio_absent_count =
					cobject->absent_count;
				vio->vio_copy =
					(vm_offset_t) cobject->copy;
				vio->vio_shadow =
					(vm_offset_t) cobject->shadow;
				vio->vio_shadow_offset =
					cobject->shadow_offset;
				vio->vio_paging_offset =
					cobject->paging_offset;
				vio->vio_copy_strategy =
					cobject->copy_strategy;
				vio->vio_last_alloc =
					cobject->last_alloc;
				vio->vio_paging_in_progress =
					cobject->paging_in_progress;
				vio->vio_pager_created =
					cobject->pager_created;
				vio->vio_pager_initialized =
					cobject->pager_initialized;
				vio->vio_pager_ready =
					cobject->pager_ready;
				vio->vio_can_persist =
					cobject->can_persist;
				vio->vio_internal =
					cobject->internal;
				vio->vio_temporary =
					cobject->temporary;
				vio->vio_alive =
					cobject->alive;
				vio->vio_lock_in_progress =
					cobject->lock_in_progress;
				vio->vio_lock_restart =
					cobject->lock_restart;
			}

			used++;
			nobject = cobject->shadow;
			if (nobject == VM_OBJECT_NULL) {
				vm_object_unlock(cobject);
				break;
			}

			vm_object_lock(nobject);
			vm_object_unlock(cobject);
		}

		/* nothing locked */

		if (used <= room)
			break;

		/* must allocate more memory */

		if (size != 0)
			kmem_free(ipc_kernel_map, addr, size);
		size = round_page(2 * used * sizeof(vm_info_object_t));

		kr = vm_allocate(ipc_kernel_map, &addr, size, TRUE);
		if (kr != KERN_SUCCESS)
			return KERN_RESOURCE_SHORTAGE;

		kr = vm_map_wire(ipc_kernel_map, addr, addr + size,
				     VM_PROT_READ|VM_PROT_WRITE, FALSE);
		assert(kr == KERN_SUCCESS);
	}

	/* free excess memory; make remaining memory pageable */

	if (used == 0) {
		copy = VM_MAP_COPY_NULL;

		if (size != 0)
			kmem_free(ipc_kernel_map, addr, size);
	} else {
		vm_size_t size_used =
			round_page(used * sizeof(vm_info_object_t));

		kr = vm_map_unwire(ipc_kernel_map, addr, addr + size_used, FALSE);
		assert(kr == KERN_SUCCESS);

		kr = vm_map_copyin(ipc_kernel_map, addr, size_used,
				   TRUE, &copy);
		assert(kr == KERN_SUCCESS);

		if (size != size_used)
			kmem_free(ipc_kernel_map,
				  addr + size_used, size - size_used);
	}

	*regionp = region;
	*objectsp = (vm_info_object_array_t) copy;
	*objectsCntp = used;
	return KERN_SUCCESS;
#endif /* MACH_VM_DEBUG */
}
/*
 *  Temporary call for 64 bit data path interface transiotion
 */

kern_return_t
mach_vm_region_info_64(
	vm_map_t		map,
	vm_offset_t		address,
	vm_info_region_64_t	*regionp,
	vm_info_object_array_t	*objectsp,
	mach_msg_type_number_t	*objectsCntp)
{
#if !MACH_VM_DEBUG
        return KERN_FAILURE;
#else
	vm_map_copy_t copy;
	vm_offset_t addr;	/* memory for OOL data */
	vm_size_t size;		/* size of the memory */
	unsigned int room;	/* room for this many objects */
	unsigned int used;	/* actually this many objects */
	vm_info_region_64_t region;
	kern_return_t kr;

	if (map == VM_MAP_NULL)
		return KERN_INVALID_TASK;

	size = 0;		/* no memory allocated yet */

	for (;;) {
		vm_map_t cmap;	/* current map in traversal */
		vm_map_t nmap;	/* next map to look at */
		vm_map_entry_t entry;
		vm_object_t object, cobject, nobject;

		/* nothing is locked */

		vm_map_lock_read(map);
		for (cmap = map;; cmap = nmap) {
			/* cmap is read-locked */

			if (!vm_map_lookup_entry(cmap, address, &entry)) {
				entry = entry->vme_next;
				if (entry == vm_map_to_entry(cmap)) {
					vm_map_unlock_read(cmap);
					if (size != 0)
						kmem_free(ipc_kernel_map,
							  addr, size);
					return KERN_NO_SPACE;
				}
			}

			if (entry->is_sub_map)
				nmap = entry->object.sub_map;
			else
				break;

			/* move down to the lower map */

			vm_map_lock_read(nmap);
			vm_map_unlock_read(cmap);
		}

		/* cmap is read-locked; we have a real entry */

		object = entry->object.vm_object;
		region.vir_start = entry->vme_start;
		region.vir_end = entry->vme_end;
		region.vir_object = (vm_offset_t) object;
		region.vir_offset = entry->offset;
		region.vir_needs_copy = entry->needs_copy;
		region.vir_protection = entry->protection;
		region.vir_max_protection = entry->max_protection;
		region.vir_inheritance = entry->inheritance;
		region.vir_wired_count = entry->wired_count;
		region.vir_user_wired_count = entry->user_wired_count;

		used = 0;
		room = size / sizeof(vm_info_object_t);

		if (object == VM_OBJECT_NULL) {
			vm_map_unlock_read(cmap);
			/* no memory needed */
			break;
		}

		vm_object_lock(object);
		vm_map_unlock_read(cmap);

		for (cobject = object;; cobject = nobject) {
			/* cobject is locked */

			if (used < room) {
				vm_info_object_t *vio =
					&((vm_info_object_t *) addr)[used];

				vio->vio_object =
					(vm_offset_t) cobject;
				vio->vio_size =
					cobject->size;
				vio->vio_ref_count =
					cobject->ref_count;
				vio->vio_resident_page_count =
					cobject->resident_page_count;
				vio->vio_absent_count =
					cobject->absent_count;
				vio->vio_copy =
					(vm_offset_t) cobject->copy;
				vio->vio_shadow =
					(vm_offset_t) cobject->shadow;
				vio->vio_shadow_offset =
					cobject->shadow_offset;
				vio->vio_paging_offset =
					cobject->paging_offset;
				vio->vio_copy_strategy =
					cobject->copy_strategy;
				vio->vio_last_alloc =
					cobject->last_alloc;
				vio->vio_paging_in_progress =
					cobject->paging_in_progress;
				vio->vio_pager_created =
					cobject->pager_created;
				vio->vio_pager_initialized =
					cobject->pager_initialized;
				vio->vio_pager_ready =
					cobject->pager_ready;
				vio->vio_can_persist =
					cobject->can_persist;
				vio->vio_internal =
					cobject->internal;
				vio->vio_temporary =
					cobject->temporary;
				vio->vio_alive =
					cobject->alive;
				vio->vio_lock_in_progress =
					cobject->lock_in_progress;
				vio->vio_lock_restart =
					cobject->lock_restart;
			}

			used++;
			nobject = cobject->shadow;
			if (nobject == VM_OBJECT_NULL) {
				vm_object_unlock(cobject);
				break;
			}

			vm_object_lock(nobject);
			vm_object_unlock(cobject);
		}

		/* nothing locked */

		if (used <= room)
			break;

		/* must allocate more memory */

		if (size != 0)
			kmem_free(ipc_kernel_map, addr, size);
		size = round_page(2 * used * sizeof(vm_info_object_t));

		kr = vm_allocate(ipc_kernel_map, &addr, size, TRUE);
		if (kr != KERN_SUCCESS)
			return KERN_RESOURCE_SHORTAGE;

		kr = vm_map_wire(ipc_kernel_map, addr, addr + size,
				     VM_PROT_READ|VM_PROT_WRITE, FALSE);
		assert(kr == KERN_SUCCESS);
	}

	/* free excess memory; make remaining memory pageable */

	if (used == 0) {
		copy = VM_MAP_COPY_NULL;

		if (size != 0)
			kmem_free(ipc_kernel_map, addr, size);
	} else {
		vm_size_t size_used =
			round_page(used * sizeof(vm_info_object_t));

		kr = vm_map_unwire(ipc_kernel_map, addr, addr + size_used, FALSE);
		assert(kr == KERN_SUCCESS);

		kr = vm_map_copyin(ipc_kernel_map, addr, size_used,
				   TRUE, &copy);
		assert(kr == KERN_SUCCESS);

		if (size != size_used)
			kmem_free(ipc_kernel_map,
				  addr + size_used, size - size_used);
	}

	*regionp = region;
	*objectsp = (vm_info_object_array_t) copy;
	*objectsCntp = used;
	return KERN_SUCCESS;
#endif /* MACH_VM_DEBUG */
}
/*
 * Return an array of virtual pages that are mapped to a task.
 */
kern_return_t
vm_mapped_pages_info(
	vm_map_t		map,
	page_address_array_t	*pages,
	mach_msg_type_number_t  *pages_count)
{
#if !MACH_VM_DEBUG
        return KERN_FAILURE;
#else
	pmap_t		pmap;
	vm_size_t	size, size_used;
	unsigned int	actual, space;
	page_address_array_t list;
	vm_offset_t	addr;

	if (map == VM_MAP_NULL)
	    return (KERN_INVALID_ARGUMENT);

	pmap = map->pmap;
	size = pmap_resident_count(pmap) * sizeof(vm_offset_t);
	size = round_page(size);

	for (;;) {
	    (void) vm_allocate(ipc_kernel_map, &addr, size, TRUE);
	    (void) vm_map_unwire(ipc_kernel_map, addr, addr + size, FALSE);

	    list = (page_address_array_t) addr;
	    space = size / sizeof(vm_offset_t);

	    actual = pmap_list_resident_pages(pmap,
					list,
					space);
	    if (actual <= space)
		break;

	    /*
	     * Free memory if not enough
	     */
	    (void) kmem_free(ipc_kernel_map, addr, size);

	    /*
	     * Try again, doubling the size
	     */
	    size = round_page(actual * sizeof(vm_offset_t));
	}
	if (actual == 0) {
	    *pages = 0;
	    *pages_count = 0;
	    (void) kmem_free(ipc_kernel_map, addr, size);
	}
	else {
	    *pages_count = actual;
	    size_used = round_page(actual * sizeof(vm_offset_t));
	    (void) vm_map_wire(ipc_kernel_map,
				addr, addr + size, 
				VM_PROT_READ|VM_PROT_WRITE, FALSE);
	    (void) vm_map_copyin(
				ipc_kernel_map,
				addr,
				size_used,
				TRUE,
				(vm_map_copy_t *)pages);
	    if (size_used != size) {
		(void) kmem_free(ipc_kernel_map,
				addr + size_used,
				size - size_used);
	    }
	}

	return (KERN_SUCCESS);
#endif /* MACH_VM_DEBUG */
}

/*
 *	Routine:	host_virtual_physical_table_info
 *	Purpose:
 *		Return information about the VP table.
 *	Conditions:
 *		Nothing locked.  Obeys CountInOut protocol.
 *	Returns:
 *		KERN_SUCCESS		Returned information.
 *		KERN_INVALID_HOST	The host is null.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
host_virtual_physical_table_info(
	host_t				host,
	hash_info_bucket_array_t	*infop,
	mach_msg_type_number_t 		*countp)
{
#if !MACH_VM_DEBUG
        return KERN_FAILURE;
#else
	vm_offset_t addr;
	vm_size_t size;
	hash_info_bucket_t *info;
	unsigned int potential, actual;
	kern_return_t kr;

	if (host == HOST_NULL)
		return KERN_INVALID_HOST;

	/* start with in-line data */

	info = *infop;
	potential = *countp;

	for (;;) {
		actual = vm_page_info(info, potential);
		if (actual <= potential)
			break;

		/* allocate more memory */

		if (info != *infop)
			kmem_free(ipc_kernel_map, addr, size);

		size = round_page(actual * sizeof *info);
		kr = kmem_alloc_pageable(ipc_kernel_map, &addr, size);
		if (kr != KERN_SUCCESS)
			return KERN_RESOURCE_SHORTAGE;

		info = (hash_info_bucket_t *) addr;
		potential = size/sizeof *info;
	}

	if (info == *infop) {
		/* data fit in-line; nothing to deallocate */

		*countp = actual;
	} else if (actual == 0) {
		kmem_free(ipc_kernel_map, addr, size);

		*countp = 0;
	} else {
		vm_map_copy_t copy;
		vm_size_t used;

		used = round_page(actual * sizeof *info);

		if (used != size)
			kmem_free(ipc_kernel_map, addr + used, size - used);

		kr = vm_map_copyin(ipc_kernel_map, addr, used,
				   TRUE, &copy);
		assert(kr == KERN_SUCCESS);

		*infop = (hash_info_bucket_t *) copy;
		*countp = actual;
	}

	return KERN_SUCCESS;
#endif /* MACH_VM_DEBUG */
}

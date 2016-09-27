/*
 * Copyright (c) 2008-2016 Apple Inc. All rights reserved.
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
 * Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University
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
 *	File:	vm/vm32_user.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 * 
 *	User-exported virtual memory functions.
 */

#include <debug.h>

#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/mach_types.h>	/* to get vm_address_t */
#include <mach/memory_object.h>
#include <mach/std_types.h>	/* to get pointer_t */
#include <mach/vm_attributes.h>
#include <mach/vm_param.h>
#include <mach/vm_statistics.h>
#include <mach/mach_syscalls.h>

#include <mach/host_priv_server.h>
#include <mach/mach_vm_server.h>
#include <mach/vm32_map_server.h>

#include <kern/host.h>
#include <kern/kalloc.h>
#include <kern/task.h>
#include <kern/misc_protos.h>
#include <vm/vm_fault.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/memory_object.h>
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>

#ifdef VM32_SUPPORT

/*
 * See vm_user.c for the real implementation of all of these functions.
 * We call through to the mach_ "wide" versions of the routines, and trust
 * that the VM system verifies the arguments and only returns address that
 * are appropriate for the task's address space size.
 *
 * New VM call implementations should not be added here, because they would
 * be available only to 32-bit userspace clients. Add them to vm_user.c
 * and the corresponding prototype to mach_vm.defs (subsystem 4800).
 */

kern_return_t
vm32_allocate(
	vm_map_t	map,
	vm32_offset_t	*addr,
	vm32_size_t	size,
	int		flags)
{
	mach_vm_offset_t	maddr;
	kern_return_t		result;

	maddr = *addr;
	result = mach_vm_allocate(map, &maddr, size, flags);
	*addr = CAST_DOWN_EXPLICIT(vm32_offset_t, maddr);
	
	return result;
}

kern_return_t
vm32_deallocate(
	vm_map_t	map,
	vm32_offset_t		start,
	vm32_size_t		size)
{
	if ((map == VM_MAP_NULL) || (start + size < start))
		return(KERN_INVALID_ARGUMENT);

	return mach_vm_deallocate(map, start, size);
}

kern_return_t
vm32_inherit(
	vm_map_t	map,
	vm32_offset_t		start,
	vm32_size_t		size,
	vm_inherit_t		new_inheritance)
{
	if ((map == VM_MAP_NULL) || (start + size < start))
		return(KERN_INVALID_ARGUMENT);

	return mach_vm_inherit(map, start, size, new_inheritance);
}

kern_return_t
vm32_protect(
	vm_map_t		map,
	vm32_offset_t		start,
	vm32_size_t		size,
	boolean_t		set_maximum,
	vm_prot_t		new_protection)
{
	if ((map == VM_MAP_NULL) || (start + size < start))
		return(KERN_INVALID_ARGUMENT);

	return mach_vm_protect(map, start, size, set_maximum, new_protection);
}

kern_return_t
vm32_machine_attribute(
	vm_map_t	map,
	vm32_address_t	addr,
	vm32_size_t	size,
	vm_machine_attribute_t	attribute,
	vm_machine_attribute_val_t* value)		/* IN/OUT */
{
	if ((map == VM_MAP_NULL) || (addr + size < addr))
		return(KERN_INVALID_ARGUMENT);

	return mach_vm_machine_attribute(map, addr, size, attribute, value);
}

kern_return_t
vm32_read(
	vm_map_t		map,
	vm32_address_t		addr,
	vm32_size_t		size,
	pointer_t		*data,
	mach_msg_type_number_t	*data_size)
{
	return mach_vm_read(map, addr, size, data, data_size);
}

kern_return_t
vm32_read_list(
	vm_map_t		map,
	vm32_read_entry_t	data_list,
	natural_t		count)
{
	mach_vm_read_entry_t	mdata_list;
	mach_msg_type_number_t	i;
	kern_return_t			result;

	for (i=0; i < VM_MAP_ENTRY_MAX; i++) {
		mdata_list[i].address = data_list[i].address;
		mdata_list[i].size = data_list[i].size;
	}
	
	result = mach_vm_read_list(map, mdata_list, count);

	for (i=0; i < VM_MAP_ENTRY_MAX; i++) {
		data_list[i].address = CAST_DOWN_EXPLICIT(vm32_address_t, mdata_list[i].address);
		data_list[i].size = CAST_DOWN_EXPLICIT(vm32_size_t, mdata_list[i].size);
	}

	return result;
}

kern_return_t
vm32_read_overwrite(
	vm_map_t	map,
	vm32_address_t	address,
	vm32_size_t	size,
	vm32_address_t	data,
	vm32_size_t	*data_size)
{
	kern_return_t	result;
	mach_vm_size_t	mdata_size;

	mdata_size = *data_size;
	result = mach_vm_read_overwrite(map, address, size, data, &mdata_size);	
	*data_size = CAST_DOWN_EXPLICIT(vm32_size_t, mdata_size);
	
	return result;
}

kern_return_t
vm32_write(
	vm_map_t			map,
	vm32_address_t			address,
	pointer_t			data,
	mach_msg_type_number_t	size)
{
	return mach_vm_write(map, address, data, size);
}

kern_return_t
vm32_copy(
	vm_map_t	map,
	vm32_address_t	source_address,
	vm32_size_t	size,
	vm32_address_t	dest_address)
{
	return mach_vm_copy(map, source_address, size, dest_address);
}

kern_return_t
vm32_map_64(
	vm_map_t		target_map,
	vm32_offset_t		*address,
	vm32_size_t		size,
	vm32_offset_t		mask,
	int			flags,
	ipc_port_t		port,
	vm_object_offset_t	offset,
	boolean_t		copy,
	vm_prot_t		cur_protection,
	vm_prot_t		max_protection,
	vm_inherit_t		inheritance)
{
	mach_vm_offset_t	maddress;
	kern_return_t		result;

	maddress = *address;
	result = mach_vm_map(target_map, &maddress, size, mask,
						 flags, port, offset, copy,
						 cur_protection, max_protection, inheritance);
	*address = CAST_DOWN_EXPLICIT(vm32_offset_t, maddress);
	
	return result;
}

kern_return_t
vm32_map(
	vm_map_t		target_map,
	vm32_offset_t		*address,
	vm32_size_t		size,
	vm32_offset_t		mask,
	int			flags,
	ipc_port_t		port,
	vm32_offset_t		offset,
	boolean_t		copy,
	vm_prot_t		cur_protection,
	vm_prot_t		max_protection,
	vm_inherit_t		inheritance)
{
	return vm32_map_64(target_map, address, size, mask,
						  flags, port, offset, copy,
						  cur_protection, max_protection, inheritance);
}

kern_return_t
vm32_remap(
	vm_map_t		target_map,
	vm32_offset_t		*address,
	vm32_size_t		size,
	vm32_offset_t		mask,
	boolean_t		anywhere,
	vm_map_t		src_map,
	vm32_offset_t		memory_address,
	boolean_t		copy,
	vm_prot_t		*cur_protection,
	vm_prot_t		*max_protection,
	vm_inherit_t		inheritance)
{
	mach_vm_offset_t	maddress;
	kern_return_t		result;
	
	maddress = *address;
	result = mach_vm_remap(target_map, &maddress, size, mask,
						 anywhere, src_map, memory_address, copy,
						 cur_protection, max_protection, inheritance);
	*address = CAST_DOWN_EXPLICIT(vm32_offset_t, maddress);
	
	return result;
}

kern_return_t
vm32_msync(
	vm_map_t	map,
	vm32_address_t	address,
	vm32_size_t	size,
	vm_sync_t	sync_flags)
{
	return mach_vm_msync(map, address, size, sync_flags);
}

kern_return_t 
vm32_behavior_set(
	vm_map_t		map,
	vm32_offset_t		start,
	vm32_size_t		size,
	vm_behavior_t		new_behavior)
{
	if ((map == VM_MAP_NULL) || (start + size < start))
		return(KERN_INVALID_ARGUMENT);

	return mach_vm_behavior_set(map, start, size, new_behavior);
}

kern_return_t
vm32_region_64(
	vm_map_t		 map,
	vm32_offset_t	        *address,		/* IN/OUT */
	vm32_size_t		*size,			/* OUT */
	vm_region_flavor_t	 flavor,		/* IN */
	vm_region_info_t	 info,			/* OUT */
	mach_msg_type_number_t	*count,			/* IN/OUT */
	mach_port_t		*object_name)		/* OUT */
{
	mach_vm_offset_t	maddress;
	mach_vm_size_t		msize;
	kern_return_t		result;

	maddress = *address;
	msize = *size;
	result = mach_vm_region(map, &maddress, &msize, flavor, info, count, object_name);
	*size = CAST_DOWN_EXPLICIT(vm32_size_t, msize);
	*address = CAST_DOWN_EXPLICIT(vm32_offset_t, maddress);
	
	return result;
}

kern_return_t
vm32_region(
	vm_map_t			map,
	vm32_address_t	      		*address,	/* IN/OUT */
	vm32_size_t			*size,		/* OUT */
	vm_region_flavor_t	 	flavor,	/* IN */
	vm_region_info_t	 	info,		/* OUT */
	mach_msg_type_number_t	*count,	/* IN/OUT */
	mach_port_t			*object_name)	/* OUT */
{
	vm_map_address_t 	map_addr;
	vm_map_size_t 		map_size;
	kern_return_t		kr;

	if (VM_MAP_NULL == map)
		return KERN_INVALID_ARGUMENT;

	map_addr = (vm_map_address_t)*address;
	map_size = (vm_map_size_t)*size;

	kr = vm_map_region(map,
			   &map_addr, &map_size,
			   flavor, info, count,
			   object_name);

	*address = CAST_DOWN_EXPLICIT(vm32_address_t, map_addr);
	*size = CAST_DOWN_EXPLICIT(vm32_size_t, map_size);

	if (KERN_SUCCESS == kr && map_addr + map_size > VM32_MAX_ADDRESS)
		return KERN_INVALID_ADDRESS;
	return kr;
}

kern_return_t
vm32_region_recurse_64(
	vm_map_t			map,
	vm32_address_t			*address,
	vm32_size_t			*size,
	uint32_t			*depth,
	vm_region_recurse_info_64_t	info,
	mach_msg_type_number_t 	*infoCnt)
{
	mach_vm_address_t	maddress;
	mach_vm_size_t		msize;
	kern_return_t		result;

	maddress = *address;
	msize = *size;
	result = mach_vm_region_recurse(map, &maddress, &msize, depth, info, infoCnt);
	*address = CAST_DOWN_EXPLICIT(vm32_address_t, maddress);
	*size = CAST_DOWN_EXPLICIT(vm32_size_t, msize);
	
	return result;
}

kern_return_t
vm32_region_recurse(
	vm_map_t			map,
	vm32_offset_t	       	*address,	/* IN/OUT */
	vm32_size_t			*size,		/* OUT */
	natural_t	 		*depth,	/* IN/OUT */
	vm_region_recurse_info_t	info32,	/* IN/OUT */
	mach_msg_type_number_t	*infoCnt)	/* IN/OUT */
{
	vm_region_submap_info_data_64_t info64;
	vm_region_submap_info_t info;
	vm_map_address_t	map_addr;
	vm_map_size_t		map_size;
	kern_return_t		kr;

	if (VM_MAP_NULL == map || *infoCnt < VM_REGION_SUBMAP_INFO_COUNT)
		return KERN_INVALID_ARGUMENT;

	
	map_addr = (vm_map_address_t)*address;
	map_size = (vm_map_size_t)*size;
	info = (vm_region_submap_info_t)info32;
	*infoCnt = VM_REGION_SUBMAP_INFO_COUNT_64;

	kr = vm_map_region_recurse_64(map, &map_addr,&map_size,
				      depth, &info64, infoCnt);

	info->protection = info64.protection;
	info->max_protection = info64.max_protection;
	info->inheritance = info64.inheritance;
	info->offset = (uint32_t)info64.offset; /* trouble-maker */
        info->user_tag = info64.user_tag;
        info->pages_resident = info64.pages_resident;
        info->pages_shared_now_private = info64.pages_shared_now_private;
        info->pages_swapped_out = info64.pages_swapped_out;
        info->pages_dirtied = info64.pages_dirtied;
        info->ref_count = info64.ref_count;
        info->shadow_depth = info64.shadow_depth;
        info->external_pager = info64.external_pager;
        info->share_mode = info64.share_mode;
	info->is_submap = info64.is_submap;
	info->behavior = info64.behavior;
	info->object_id = info64.object_id;
	info->user_wired_count = info64.user_wired_count; 

	*address = CAST_DOWN_EXPLICIT(vm32_address_t, map_addr);
	*size = CAST_DOWN_EXPLICIT(vm32_size_t, map_size);
	*infoCnt = VM_REGION_SUBMAP_INFO_COUNT;

	if (KERN_SUCCESS == kr && map_addr + map_size > VM32_MAX_ADDRESS)
		return KERN_INVALID_ADDRESS;
	return kr;
}

kern_return_t
vm32_purgable_control(
	vm_map_t		map,
	vm32_offset_t		address,
	vm_purgable_t		control,
	int			*state)
{
	if (VM_MAP_NULL == map)
		return KERN_INVALID_ARGUMENT;

	return vm_map_purgable_control(map,
				       vm_map_trunc_page(address, PAGE_MASK),
				       control,
				       state);
}
					
kern_return_t
vm32_map_page_query(
	vm_map_t		map,
	vm32_offset_t		offset,
	int			*disposition,
	int			*ref_count)
{
	if (VM_MAP_NULL == map)
		return KERN_INVALID_ARGUMENT;

	return vm_map_page_query_internal(
		map,
		vm_map_trunc_page(offset, PAGE_MASK),
		disposition,
		ref_count);
}

kern_return_t
vm32_make_memory_entry_64(
	vm_map_t		target_map,
	memory_object_size_t	*size,
	memory_object_offset_t offset,
	vm_prot_t		permission,
	ipc_port_t		*object_handle,
	ipc_port_t		parent_handle)
{
	// use the existing entrypoint
	return _mach_make_memory_entry(target_map, size, offset, permission, object_handle, parent_handle);
}

kern_return_t
vm32_make_memory_entry(
	vm_map_t		target_map,
	vm32_size_t		*size,
	vm32_offset_t		offset,
	vm_prot_t		permission,
	ipc_port_t		*object_handle,
	ipc_port_t		parent_entry)
{	
	memory_object_size_t 	mo_size;
	kern_return_t		kr;
	
	mo_size = (memory_object_size_t)*size;
	kr = _mach_make_memory_entry(target_map, &mo_size, 
			(memory_object_offset_t)offset, permission, object_handle,
			parent_entry);
	*size = CAST_DOWN_EXPLICIT(vm32_size_t, mo_size);
	return kr;
}

kern_return_t
vm32__task_wire(
	vm_map_t	map,
	boolean_t	must_wire)
{
	if (map == VM_MAP_NULL)
		return(KERN_INVALID_ARGUMENT);

	if (must_wire)
		map->wiring_required = TRUE;
	else
		map->wiring_required = FALSE;

	return(KERN_SUCCESS);
}

#endif /* VM32_SUPPORT */

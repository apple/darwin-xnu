/*
 * Copyright (c) 2000-2001 Apple Computer, Inc. All rights reserved.
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
 *	File:	vm/vm_user.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 * 
 *	User-exported virtual memory functions.
 */

#include <vm_cpm.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/mach_types.h>	/* to get vm_address_t */
#include <mach/memory_object.h>
#include <mach/std_types.h>	/* to get pointer_t */
#include <mach/vm_attributes.h>
#include <mach/vm_param.h>
#include <mach/vm_statistics.h>
#include <mach/vm_map_server.h>
#include <mach/mach_syscalls.h>
#include <mach/shared_memory_server.h>

#include <kern/host.h>
#include <kern/task.h>
#include <kern/misc_protos.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/memory_object.h>
#include <vm/vm_pageout.h>



vm_size_t        upl_offset_to_pagelist = 0;

#if	VM_CPM
#include <vm/cpm.h>
#endif	/* VM_CPM */

ipc_port_t	dynamic_pager_control_port=NULL;

/*
 *	vm_allocate allocates "zero fill" memory in the specfied
 *	map.
 */
kern_return_t
vm_allocate(
	register vm_map_t	map,
	register vm_offset_t	*addr,
	register vm_size_t	size,
	int			flags)
{
	kern_return_t	result;
	boolean_t	anywhere = VM_FLAGS_ANYWHERE & flags;

	if (map == VM_MAP_NULL)
		return(KERN_INVALID_ARGUMENT);
	if (size == 0) {
		*addr = 0;
		return(KERN_SUCCESS);
	}

	if (anywhere)
		*addr = vm_map_min(map);
	else
		*addr = trunc_page(*addr);
	size = round_page(size);
	if (size == 0) {
	  return(KERN_INVALID_ARGUMENT);
	}

	result = vm_map_enter(
			map,
			addr,
			size,
			(vm_offset_t)0,
			flags,
			VM_OBJECT_NULL,
			(vm_object_offset_t)0,
			FALSE,
			VM_PROT_DEFAULT,
			VM_PROT_ALL,
			VM_INHERIT_DEFAULT);

	return(result);
}

/*
 *	vm_deallocate deallocates the specified range of addresses in the
 *	specified address map.
 */
kern_return_t
vm_deallocate(
	register vm_map_t	map,
	vm_offset_t		start,
	vm_size_t		size)
{
	if (map == VM_MAP_NULL)
		return(KERN_INVALID_ARGUMENT);

	if (size == (vm_offset_t) 0)
		return(KERN_SUCCESS);

	return(vm_map_remove(map, trunc_page(start),
			     round_page(start+size), VM_MAP_NO_FLAGS));
}

/*
 *	vm_inherit sets the inheritance of the specified range in the
 *	specified map.
 */
kern_return_t
vm_inherit(
	register vm_map_t	map,
	vm_offset_t		start,
	vm_size_t		size,
	vm_inherit_t		new_inheritance)
{
	if (map == VM_MAP_NULL)
		return(KERN_INVALID_ARGUMENT);

	if (new_inheritance > VM_INHERIT_LAST_VALID)
                return(KERN_INVALID_ARGUMENT);

	return(vm_map_inherit(map,
			      trunc_page(start),
			      round_page(start+size),
			      new_inheritance));
}

/*
 *	vm_protect sets the protection of the specified range in the
 *	specified map.
 */

kern_return_t
vm_protect(
	register vm_map_t	map,
	vm_offset_t		start,
	vm_size_t		size,
	boolean_t		set_maximum,
	vm_prot_t		new_protection)
{
	if ((map == VM_MAP_NULL) || 
			(new_protection & ~(VM_PROT_ALL | VM_PROT_COPY)))
		return(KERN_INVALID_ARGUMENT);

	return(vm_map_protect(map,
			      trunc_page(start),
			      round_page(start+size),
			      new_protection,
			      set_maximum));
}

/*
 * Handle machine-specific attributes for a mapping, such
 * as cachability, migrability, etc.
 */
kern_return_t
vm_machine_attribute(
	vm_map_t	map,
	vm_address_t	address,
	vm_size_t	size,
	vm_machine_attribute_t	attribute,
	vm_machine_attribute_val_t* value)		/* IN/OUT */
{
	if (map == VM_MAP_NULL)
		return(KERN_INVALID_ARGUMENT);

	return vm_map_machine_attribute(map, address, size, attribute, value);
}

kern_return_t
vm_read(
	vm_map_t		map,
	vm_address_t		address,
	vm_size_t		size,
	pointer_t		*data,
	mach_msg_type_number_t	*data_size)
{
	kern_return_t	error;
	vm_map_copy_t	ipc_address;

	if (map == VM_MAP_NULL)
		return(KERN_INVALID_ARGUMENT);

	if ((error = vm_map_copyin(map,
				address,
				size,
				FALSE,	/* src_destroy */
				&ipc_address)) == KERN_SUCCESS) {
		*data = (pointer_t) ipc_address;
		*data_size = size;
	}
	return(error);
}

kern_return_t
vm_read_list(
	vm_map_t		map,
	vm_read_entry_t		data_list,
	mach_msg_type_number_t	count)
{
	mach_msg_type_number_t	i;
	kern_return_t	error;
	vm_map_copy_t	ipc_address;

	if (map == VM_MAP_NULL)
		return(KERN_INVALID_ARGUMENT);

	for(i=0; i<count; i++) {
		error = vm_map_copyin(map,
				data_list[i].address,
				data_list[i].size,
				FALSE,	/* src_destroy */
				&ipc_address);
		if(error != KERN_SUCCESS) {
			data_list[i].address = (vm_address_t)0;
			data_list[i].size = (vm_size_t)0;
			break;
		}
		if(data_list[i].size != 0) {
			error = vm_map_copyout(current_task()->map, 
						&(data_list[i].address),
                                                (vm_map_copy_t) ipc_address);
			if(error != KERN_SUCCESS) {
				data_list[i].address = (vm_address_t)0;
				data_list[i].size = (vm_size_t)0;
				break;
			}
		}
	}
	return(error);
}

/*
 * This routine reads from the specified map and overwrites part of the current
 * activation's map.  In making an assumption that the current thread is local,
 * it is no longer cluster-safe without a fully supportive local proxy thread/
 * task (but we don't support cluster's anymore so this is moot).
 */

#define VM_OVERWRITE_SMALL 512

kern_return_t
vm_read_overwrite(
		  vm_map_t	map,
		  vm_address_t	address,
		  vm_size_t	size,
		  vm_address_t	data,
		  vm_size_t	*data_size)
{
	struct {
	    long	align;
	    char	buf[VM_OVERWRITE_SMALL];
	} inbuf;
	vm_map_t	oldmap;
	kern_return_t	error = KERN_SUCCESS;
	vm_map_copy_t	copy;

	if (map == VM_MAP_NULL)
		return(KERN_INVALID_ARGUMENT);

	if (size <= VM_OVERWRITE_SMALL) {
		if(vm_map_read_user(map, (vm_offset_t)address, 
					(vm_offset_t)&inbuf, size)) {
			error = KERN_INVALID_ADDRESS;
		} else {
			if(vm_map_write_user(current_map(), 
				(vm_offset_t)&inbuf, (vm_offset_t)data, size))
			error = KERN_INVALID_ADDRESS;
		}
	}
	else {
		if ((error = vm_map_copyin(map,
					address,
					size,
					FALSE,	/* src_destroy */
					&copy)) == KERN_SUCCESS) {
			if ((error = vm_map_copy_overwrite(
					current_act()->map,
 					data, 
					copy,
					FALSE)) == KERN_SUCCESS) {
			}
			else {
				vm_map_copy_discard(copy);
			}
		}
	}
	*data_size = size;
	return(error);
}




/*ARGSUSED*/
kern_return_t
vm_write(
	vm_map_t		map,
	vm_address_t		address,
	vm_offset_t		data,
	mach_msg_type_number_t	size)
{
	if (map == VM_MAP_NULL)
		return KERN_INVALID_ARGUMENT;

	return vm_map_copy_overwrite(map, address, (vm_map_copy_t) data,
				     FALSE /* interruptible XXX */);
}

kern_return_t
vm_copy(
	vm_map_t	map,
	vm_address_t	source_address,
	vm_size_t	size,
	vm_address_t	dest_address)
{
	vm_map_copy_t copy;
	kern_return_t kr;

	if (map == VM_MAP_NULL)
		return KERN_INVALID_ARGUMENT;

	kr = vm_map_copyin(map, source_address, size,
			   FALSE, &copy);
	if (kr != KERN_SUCCESS)
		return kr;

	kr = vm_map_copy_overwrite(map, dest_address, copy,
				   FALSE /* interruptible XXX */);
	if (kr != KERN_SUCCESS) {
		vm_map_copy_discard(copy);
		return kr;
	}

	return KERN_SUCCESS;
}

/*
 *	Routine:	vm_map
 */
kern_return_t
vm_map_64(
	vm_map_t		target_map,
	vm_offset_t		*address,
	vm_size_t		initial_size,
	vm_offset_t		mask,
	int			flags,
	ipc_port_t		port,
	vm_object_offset_t	offset,
	boolean_t		copy,
	vm_prot_t		cur_protection,
	vm_prot_t		max_protection,
	vm_inherit_t		inheritance)
{
	register
	vm_object_t		object;
	vm_prot_t		prot;
	vm_object_size_t	size = (vm_object_size_t)initial_size;
	kern_return_t		result;

	/*
	 * Check arguments for validity
	 */
	if ((target_map == VM_MAP_NULL) ||
		(cur_protection & ~VM_PROT_ALL) ||
		(max_protection & ~VM_PROT_ALL) ||
		(inheritance > VM_INHERIT_LAST_VALID) ||
		size == 0)
		return(KERN_INVALID_ARGUMENT);

	/*
	 * Find the vm object (if any) corresponding to this port.
	 */
	if (!IP_VALID(port)) {
		object = VM_OBJECT_NULL;
		offset = 0;
		copy = FALSE;
	} else if (ip_kotype(port) == IKOT_NAMED_ENTRY) {
		vm_named_entry_t	named_entry;

		named_entry = (vm_named_entry_t)port->ip_kobject;
		/* a few checks to make sure user is obeying rules */
		if(size == 0) {
			if(offset >= named_entry->size)
				return(KERN_INVALID_RIGHT);
			size = named_entry->size - offset;
		}
		if((named_entry->protection & max_protection) != max_protection)
			return(KERN_INVALID_RIGHT);
		if((named_entry->protection & cur_protection) != cur_protection)
			return(KERN_INVALID_RIGHT);
		if(named_entry->size < (offset + size))
			return(KERN_INVALID_ARGUMENT);

		/* the callers parameter offset is defined to be the */
		/* offset from beginning of named entry offset in object */
		offset = offset + named_entry->offset;
		
		named_entry_lock(named_entry);
		if(named_entry->is_sub_map) {
			vm_map_entry_t		map_entry;

			named_entry_unlock(named_entry);
			*address = trunc_page(*address);
			size = round_page(size);
			vm_object_reference(vm_submap_object);
			if ((result = vm_map_enter(target_map,
				address, size, mask, flags,
				vm_submap_object, 0,
				FALSE,
				cur_protection, max_protection, inheritance
				)) != KERN_SUCCESS) {
					vm_object_deallocate(vm_submap_object);
			} else {
				char	alias;

				VM_GET_FLAGS_ALIAS(flags, alias);
				if ((alias == VM_MEMORY_SHARED_PMAP) &&
					!copy) {
					vm_map_submap(target_map, *address, 
						(*address) + size, 
						named_entry->backing.map,
						(vm_offset_t)offset, TRUE);
				} else {
					vm_map_submap(target_map, *address, 
						(*address) + size, 
						named_entry->backing.map,
						(vm_offset_t)offset, FALSE);
				}
				if(copy) {
					if(vm_map_lookup_entry(
					   target_map, *address, &map_entry)) {
						map_entry->needs_copy = TRUE;
					}
				}
			}
			return(result);

		} else if(named_entry->object) {
			/* This is the case where we are going to map */
			/* an already mapped object.  If the object is */
			/* not ready it is internal.  An external     */
			/* object cannot be mapped until it is ready  */
			/* we can therefore avoid the ready check     */
			/* in this case.  */
			named_entry_unlock(named_entry);
			vm_object_reference(named_entry->object);
			object = named_entry->object;
		} else {
			object = vm_object_enter(named_entry->backing.pager, 
					named_entry->size, 
					named_entry->internal, 
					FALSE,
					FALSE);
			if (object == VM_OBJECT_NULL) {
				named_entry_unlock(named_entry);
				return(KERN_INVALID_OBJECT);
			}
			object->true_share = TRUE;
			named_entry->object = object;
			named_entry_unlock(named_entry);
			/* create an extra reference for the named entry */
			vm_object_reference(named_entry->object);
			/* wait for object (if any) to be ready */
			if (object != VM_OBJECT_NULL) {
				vm_object_lock(object);
				while (!object->pager_ready) {
					vm_object_wait(object,
						VM_OBJECT_EVENT_PAGER_READY,
						THREAD_UNINT);
					vm_object_lock(object);
				}
				vm_object_unlock(object);
			}
		}
	} else if (ip_kotype(port) == IKOT_MEMORY_OBJECT) {
		/*
		 * JMM - This is temporary until we unify named entries
		 * and raw memory objects.
		 *
		 * Detected fake ip_kotype for a memory object.  In
		 * this case, the port isn't really a port at all, but
		 * instead is just a raw memory object.
		 */
		 
		if ((object = vm_object_enter((memory_object_t)port,
					      size, FALSE, FALSE, FALSE))
			== VM_OBJECT_NULL)
			return(KERN_INVALID_OBJECT);

		/* wait for object (if any) to be ready */
		if (object != VM_OBJECT_NULL) {
			vm_object_lock(object);
			while (!object->pager_ready) {
				vm_object_wait(object,
					VM_OBJECT_EVENT_PAGER_READY,
					THREAD_UNINT);
				vm_object_lock(object);
			}
			vm_object_unlock(object);
		}
	} else {
		return (KERN_INVALID_OBJECT);
	}

	*address = trunc_page(*address);
	size = round_page(size);

	/*
	 *	Perform the copy if requested
	 */

	if (copy) {
		vm_object_t		new_object;
		vm_object_offset_t	new_offset;

		result = vm_object_copy_strategically(object, offset, size,
				&new_object, &new_offset,
				&copy);


		if (result == KERN_MEMORY_RESTART_COPY) {
			boolean_t success;
			boolean_t src_needs_copy;

			/*
			 * XXX
			 * We currently ignore src_needs_copy.
			 * This really is the issue of how to make
			 * MEMORY_OBJECT_COPY_SYMMETRIC safe for
			 * non-kernel users to use. Solution forthcoming.
			 * In the meantime, since we don't allow non-kernel
			 * memory managers to specify symmetric copy,
			 * we won't run into problems here.
			 */
			new_object = object;
			new_offset = offset;
			success = vm_object_copy_quickly(&new_object,
							 new_offset, size,
							 &src_needs_copy,
							 &copy);
			assert(success);
			result = KERN_SUCCESS;
		}
		/*
		 *	Throw away the reference to the
		 *	original object, as it won't be mapped.
		 */

		vm_object_deallocate(object);

		if (result != KERN_SUCCESS)
			return (result);

		object = new_object;
		offset = new_offset;
	}

	if ((result = vm_map_enter(target_map,
				address, size, mask, flags,
				object, offset,
				copy,
				cur_protection, max_protection, inheritance
				)) != KERN_SUCCESS)
	vm_object_deallocate(object);
	return(result);
}

/* temporary, until world build */
vm_map(
	vm_map_t		target_map,
	vm_offset_t		*address,
	vm_size_t		size,
	vm_offset_t		mask,
	int			flags,
	ipc_port_t		port,
	vm_offset_t		offset,
	boolean_t		copy,
	vm_prot_t		cur_protection,
	vm_prot_t		max_protection,
	vm_inherit_t		inheritance)
{
	vm_map_64(target_map, address, size, mask, flags, 
			port, (vm_object_offset_t)offset, copy,
			cur_protection, max_protection, inheritance);
}


/*
 * NOTE: this routine (and this file) will no longer require mach_host_server.h
 * when vm_wire is changed to use ledgers.
 */
#include <mach/mach_host_server.h>
/*
 *	Specify that the range of the virtual address space
 *	of the target task must not cause page faults for
 *	the indicated accesses.
 *
 *	[ To unwire the pages, specify VM_PROT_NONE. ]
 */
kern_return_t
vm_wire(
	host_priv_t		host_priv,
	register vm_map_t	map,
	vm_offset_t		start,
	vm_size_t		size,
	vm_prot_t		access)
{
	kern_return_t		rc;

	if (host_priv == HOST_PRIV_NULL)
		return KERN_INVALID_HOST;

	assert(host_priv == &realhost);

	if (map == VM_MAP_NULL)
		return KERN_INVALID_TASK;

	if (access & ~VM_PROT_ALL)
		return KERN_INVALID_ARGUMENT;

	if (access != VM_PROT_NONE) {
		rc = vm_map_wire(map, trunc_page(start),
				 round_page(start+size), access, TRUE);
	} else {
		rc = vm_map_unwire(map, trunc_page(start),
				   round_page(start+size), TRUE);
	}
	return rc;
}

/*
 *	vm_msync
 *
 *	Synchronises the memory range specified with its backing store
 *	image by either flushing or cleaning the contents to the appropriate
 *	memory manager engaging in a memory object synchronize dialog with
 *	the manager.  The client doesn't return until the manager issues
 *	m_o_s_completed message.  MIG Magically converts user task parameter
 *	to the task's address map.
 *
 *	interpretation of sync_flags
 *	VM_SYNC_INVALIDATE	- discard pages, only return precious
 *				  pages to manager.
 *
 *	VM_SYNC_INVALIDATE & (VM_SYNC_SYNCHRONOUS | VM_SYNC_ASYNCHRONOUS)
 *				- discard pages, write dirty or precious
 *				  pages back to memory manager.
 *
 *	VM_SYNC_SYNCHRONOUS | VM_SYNC_ASYNCHRONOUS
 *				- write dirty or precious pages back to
 *				  the memory manager.
 *
 *	NOTE
 *	The memory object attributes have not yet been implemented, this
 *	function will have to deal with the invalidate attribute
 *
 *	RETURNS
 *	KERN_INVALID_TASK		Bad task parameter
 *	KERN_INVALID_ARGUMENT		both sync and async were specified.
 *	KERN_SUCCESS			The usual.
 */

kern_return_t
vm_msync(
	vm_map_t	map,
	vm_address_t	address,
	vm_size_t	size,
	vm_sync_t	sync_flags)
{
	msync_req_t		msr;
	msync_req_t		new_msr;
	queue_chain_t		req_q;	/* queue of requests for this msync */
	vm_map_entry_t		entry;
	vm_size_t		amount_left;
	vm_object_offset_t	offset;
	boolean_t		do_sync_req;
	boolean_t		modifiable;
	

	if ((sync_flags & VM_SYNC_ASYNCHRONOUS) &&
	    (sync_flags & VM_SYNC_SYNCHRONOUS))
		return(KERN_INVALID_ARGUMENT);

	/*
	 * align address and size on page boundaries
	 */
	size = round_page(address + size) - trunc_page(address);
	address = trunc_page(address);

        if (map == VM_MAP_NULL)
                return(KERN_INVALID_TASK);

	if (size == 0)
		return(KERN_SUCCESS);

	queue_init(&req_q);
	amount_left = size;

	while (amount_left > 0) {
		vm_size_t		flush_size;
		vm_object_t		object;

		vm_map_lock(map);
		if (!vm_map_lookup_entry(map, address, &entry)) {
			vm_size_t	skip;

			/*
			 * hole in the address map.
			 */

			/*
			 * Check for empty map.
			 */
			if (entry == vm_map_to_entry(map) &&
			    entry->vme_next == entry) {
				vm_map_unlock(map);
				break;
			}
			/*
			 * Check that we don't wrap and that
			 * we have at least one real map entry.
			 */
			if ((map->hdr.nentries == 0) ||
			    (entry->vme_next->vme_start < address)) {
				vm_map_unlock(map);
				break;
			}
			/*
			 * Move up to the next entry if needed
			 */
			skip = (entry->vme_next->vme_start - address);
			if (skip >= amount_left)
				amount_left = 0;
			else
				amount_left -= skip;
			address = entry->vme_next->vme_start;
			vm_map_unlock(map);
			continue;
		}

		offset = address - entry->vme_start;

		/*
		 * do we have more to flush than is contained in this
		 * entry ?
		 */
		if (amount_left + entry->vme_start + offset > entry->vme_end) {
			flush_size = entry->vme_end -
						 (entry->vme_start + offset);
		} else {
			flush_size = amount_left;
		}
		amount_left -= flush_size;
		address += flush_size;

		if (entry->is_sub_map == TRUE) {
			vm_map_t	local_map;
			vm_offset_t	local_offset;

			local_map = entry->object.sub_map;
			local_offset = entry->offset;
			vm_map_unlock(map);
			vm_msync(
				local_map,
				local_offset,
				flush_size,
				sync_flags);
			continue;
		}
		object = entry->object.vm_object;

		/*
		 * We can't sync this object if the object has not been
		 * created yet
		 */
		if (object == VM_OBJECT_NULL) {
			vm_map_unlock(map);
			continue;
		}
		offset += entry->offset;
		modifiable = (entry->protection & VM_PROT_WRITE)
				!= VM_PROT_NONE;

                vm_object_lock(object);

		if (sync_flags & (VM_SYNC_KILLPAGES | VM_SYNC_DEACTIVATE)) {
		        boolean_t kill_pages = 0;

			if (sync_flags & VM_SYNC_KILLPAGES) {
			        if (object->ref_count == 1 && !entry->needs_copy && !object->shadow)
				        kill_pages = 1;
				else
				        kill_pages = -1;
			}
			if (kill_pages != -1)
			        vm_object_deactivate_pages(object, offset, 
							       (vm_object_size_t)flush_size, kill_pages);
			vm_object_unlock(object);
			vm_map_unlock(map);
			continue;
		}
		/*
		 * We can't sync this object if there isn't a pager.
		 * Don't bother to sync internal objects, since there can't
		 * be any "permanent" storage for these objects anyway.
		 */
		if ((object->pager == MEMORY_OBJECT_NULL) ||
		    (object->internal) || (object->private)) {
			vm_object_unlock(object);
			vm_map_unlock(map);
			continue;
		}
		/*
		 * keep reference on the object until syncing is done
		 */
		assert(object->ref_count > 0);
		object->ref_count++;
		vm_object_res_reference(object);
		vm_object_unlock(object);

		vm_map_unlock(map);

		do_sync_req = vm_object_sync(object,
					offset,
					flush_size,
					sync_flags & VM_SYNC_INVALIDATE,
					(modifiable &&
					(sync_flags & VM_SYNC_SYNCHRONOUS ||
					 sync_flags & VM_SYNC_ASYNCHRONOUS)));

		/*
		 * only send a m_o_s if we returned pages or if the entry
		 * is writable (ie dirty pages may have already been sent back)
		 */
		if (!do_sync_req && !modifiable) {
			vm_object_deallocate(object);
			continue;
		}
		msync_req_alloc(new_msr);

                vm_object_lock(object);
		offset += object->paging_offset;

		new_msr->offset = offset;
		new_msr->length = flush_size;
		new_msr->object = object;
		new_msr->flag = VM_MSYNC_SYNCHRONIZING;
re_iterate:
		queue_iterate(&object->msr_q, msr, msync_req_t, msr_q) {
			/*
			 * need to check for overlapping entry, if found, wait
			 * on overlapping msr to be done, then reiterate
			 */
			msr_lock(msr);
			if (msr->flag == VM_MSYNC_SYNCHRONIZING &&
			    ((offset >= msr->offset && 
			      offset < (msr->offset + msr->length)) ||
			     (msr->offset >= offset &&
			      msr->offset < (offset + flush_size))))
			{
				assert_wait((event_t) msr,THREAD_INTERRUPTIBLE);
				msr_unlock(msr);
				vm_object_unlock(object);
				thread_block((void (*)(void))0);
				vm_object_lock(object);
				goto re_iterate;
			}
			msr_unlock(msr);
		}/* queue_iterate */

		queue_enter(&object->msr_q, new_msr, msync_req_t, msr_q);
		vm_object_unlock(object);

		queue_enter(&req_q, new_msr, msync_req_t, req_q);

		(void) memory_object_synchronize(
				object->pager,
				offset,
				flush_size,
				sync_flags);
	}/* while */

	/*
	 * wait for memory_object_sychronize_completed messages from pager(s)
	 */

	while (!queue_empty(&req_q)) {
		msr = (msync_req_t)queue_first(&req_q);
		msr_lock(msr);
		while(msr->flag != VM_MSYNC_DONE) {
			assert_wait((event_t) msr, THREAD_INTERRUPTIBLE);
			msr_unlock(msr);
			thread_block((void (*)(void))0);
			msr_lock(msr);
		}/* while */
		queue_remove(&req_q, msr, msync_req_t, req_q);
		msr_unlock(msr);
		vm_object_deallocate(msr->object);
		msync_req_free(msr);
	}/* queue_iterate */

	return(KERN_SUCCESS);
}/* vm_msync */


/*
 *	task_wire
 *
 *	Set or clear the map's wiring_required flag.  This flag, if set,
 *	will cause all future virtual memory allocation to allocate
 *	user wired memory.  Unwiring pages wired down as a result of
 *	this routine is done with the vm_wire interface.
 */
kern_return_t
task_wire(
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

/*
 *	vm_behavior_set sets the paging behavior attribute for the 
 *	specified range in the specified map. This routine will fail
 *	with KERN_INVALID_ADDRESS if any address in [start,start+size)
 *	is not a valid allocated or reserved memory region.
 */
kern_return_t 
vm_behavior_set(
	vm_map_t		map,
	vm_offset_t		start,
	vm_size_t		size,
	vm_behavior_t		new_behavior)
{
	if (map == VM_MAP_NULL)
		return(KERN_INVALID_ARGUMENT);

	return(vm_map_behavior_set(map, trunc_page(start), 
				   round_page(start+size), new_behavior));
}

#if	VM_CPM
/*
 *	Control whether the kernel will permit use of
 *	vm_allocate_cpm at all.
 */
unsigned int	vm_allocate_cpm_enabled = 1;

/*
 *	Ordinarily, the right to allocate CPM is restricted
 *	to privileged applications (those that can gain access
 *	to the host port).  Set this variable to zero if you
 *	want to let any application allocate CPM.
 */
unsigned int	vm_allocate_cpm_privileged = 0;

/*
 *	Allocate memory in the specified map, with the caveat that
 *	the memory is physically contiguous.  This call may fail
 *	if the system can't find sufficient contiguous memory.
 *	This call may cause or lead to heart-stopping amounts of
 *	paging activity.
 *
 *	Memory obtained from this call should be freed in the
 *	normal way, viz., via vm_deallocate.
 */
kern_return_t
vm_allocate_cpm(
	host_priv_t		host_priv,
	register vm_map_t	map,
	register vm_offset_t	*addr,
	register vm_size_t	size,
	int			flags)
{
	vm_object_t		cpm_obj;
	pmap_t			pmap;
	vm_page_t		m, pages;
	kern_return_t		kr;
	vm_offset_t		va, start, end, offset;
#if	MACH_ASSERT
	extern vm_offset_t	avail_start, avail_end;
	vm_offset_t		prev_addr;
#endif	/* MACH_ASSERT */

	boolean_t		anywhere = VM_FLAGS_ANYWHERE & flags;

	if (!vm_allocate_cpm_enabled)
		return KERN_FAILURE;

	if (vm_allocate_cpm_privileged && host_priv == HOST_PRIV_NULL)
		return KERN_INVALID_HOST;

	if (map == VM_MAP_NULL)
		return KERN_INVALID_ARGUMENT;
	
	assert(host_priv == &realhost);

	if (size == 0) {
		*addr = 0;
		return KERN_SUCCESS;
	}

	if (anywhere)
		*addr = vm_map_min(map);
	else
		*addr = trunc_page(*addr);
	size = round_page(size);

	if ((kr = cpm_allocate(size, &pages, TRUE)) != KERN_SUCCESS)
		return kr;

	cpm_obj = vm_object_allocate(size);
	assert(cpm_obj != VM_OBJECT_NULL);
	assert(cpm_obj->internal);
	assert(cpm_obj->size == size);
	assert(cpm_obj->can_persist == FALSE);
	assert(cpm_obj->pager_created == FALSE);
	assert(cpm_obj->pageout == FALSE);
	assert(cpm_obj->shadow == VM_OBJECT_NULL);

	/*
	 *	Insert pages into object.
	 */

	vm_object_lock(cpm_obj);
	for (offset = 0; offset < size; offset += PAGE_SIZE) {
		m = pages;
		pages = NEXT_PAGE(m);

		assert(!m->gobbled);
		assert(!m->wanted);
		assert(!m->pageout);
		assert(!m->tabled);
		assert(m->busy);
		assert(m->phys_addr>=avail_start && m->phys_addr<=avail_end);

		m->busy = FALSE;
		vm_page_insert(m, cpm_obj, offset);
	}
	assert(cpm_obj->resident_page_count == size / PAGE_SIZE);
	vm_object_unlock(cpm_obj);

	/*
	 *	Hang onto a reference on the object in case a
	 *	multi-threaded application for some reason decides
	 *	to deallocate the portion of the address space into
	 *	which we will insert this object.
	 *
	 *	Unfortunately, we must insert the object now before
	 *	we can talk to the pmap module about which addresses
	 *	must be wired down.  Hence, the race with a multi-
	 *	threaded app.
	 */
	vm_object_reference(cpm_obj);

	/*
	 *	Insert object into map.
	 */

	kr = vm_map_enter(
			  map,
			  addr,
			  size,
			  (vm_offset_t)0,
			  flags,
			  cpm_obj,
			  (vm_object_offset_t)0,
			  FALSE,
			  VM_PROT_ALL,
			  VM_PROT_ALL,
			  VM_INHERIT_DEFAULT);

	if (kr != KERN_SUCCESS) {
		/*
		 *	A CPM object doesn't have can_persist set,
		 *	so all we have to do is deallocate it to
		 *	free up these pages.
		 */
		assert(cpm_obj->pager_created == FALSE);
		assert(cpm_obj->can_persist == FALSE);
		assert(cpm_obj->pageout == FALSE);
		assert(cpm_obj->shadow == VM_OBJECT_NULL);
		vm_object_deallocate(cpm_obj); /* kill acquired ref */
		vm_object_deallocate(cpm_obj); /* kill creation ref */
	}

	/*
	 *	Inform the physical mapping system that the
	 *	range of addresses may not fault, so that
	 *	page tables and such can be locked down as well.
	 */
	start = *addr;
	end = start + size;
	pmap = vm_map_pmap(map);
	pmap_pageable(pmap, start, end, FALSE);

	/*
	 *	Enter each page into the pmap, to avoid faults.
	 *	Note that this loop could be coded more efficiently,
	 *	if the need arose, rather than looking up each page
	 *	again.
	 */
	for (offset = 0, va = start; offset < size;
	     va += PAGE_SIZE, offset += PAGE_SIZE) {
		vm_object_lock(cpm_obj);
		m = vm_page_lookup(cpm_obj, (vm_object_offset_t)offset);
		vm_object_unlock(cpm_obj);
		assert(m != VM_PAGE_NULL);
		PMAP_ENTER(pmap, va, m, VM_PROT_ALL, TRUE);
	}

#if	MACH_ASSERT
	/*
	 *	Verify ordering in address space.
	 */
	for (offset = 0; offset < size; offset += PAGE_SIZE) {
		vm_object_lock(cpm_obj);
		m = vm_page_lookup(cpm_obj, (vm_object_offset_t)offset);
		vm_object_unlock(cpm_obj);
		if (m == VM_PAGE_NULL)
			panic("vm_allocate_cpm:  obj 0x%x off 0x%x no page",
			      cpm_obj, offset);
		assert(m->tabled);
		assert(!m->busy);
		assert(!m->wanted);
		assert(!m->fictitious);
		assert(!m->private);
		assert(!m->absent);
		assert(!m->error);
		assert(!m->cleaning);
		assert(!m->precious);
		assert(!m->clustered);
		if (offset != 0) {
			if (m->phys_addr != prev_addr + PAGE_SIZE) {
				printf("start 0x%x end 0x%x va 0x%x\n",
				       start, end, va);
				printf("obj 0x%x off 0x%x\n", cpm_obj, offset);
				printf("m 0x%x prev_address 0x%x\n", m,
				       prev_addr);
				panic("vm_allocate_cpm:  pages not contig!");
			}
		}
		prev_addr = m->phys_addr;
	}
#endif	/* MACH_ASSERT */

	vm_object_deallocate(cpm_obj); /* kill extra ref */

	return kr;
}


#else	/* VM_CPM */

/*
 *	Interface is defined in all cases, but unless the kernel
 *	is built explicitly for this option, the interface does
 *	nothing.
 */

kern_return_t
vm_allocate_cpm(
	host_priv_t		host_priv,
	register vm_map_t	map,
	register vm_offset_t	*addr,
	register vm_size_t	size,
	int			flags)
{
	return KERN_FAILURE;
}

/*
 */
kern_return_t
mach_memory_object_memory_entry_64(
	host_t			host,
	boolean_t		internal,
	vm_object_offset_t	size,
	vm_prot_t		permission,
 	memory_object_t		pager,
	ipc_port_t		*entry_handle)
{
	vm_named_entry_t	user_object;
	ipc_port_t		user_handle;
	ipc_port_t		previous;
	kern_return_t		kr;

        if (host == HOST_NULL)
                return(KERN_INVALID_HOST);

	user_object = (vm_named_entry_t) 
			kalloc(sizeof (struct vm_named_entry));
	if(user_object == NULL)
		return KERN_FAILURE;
	named_entry_lock_init(user_object);
	user_handle = ipc_port_alloc_kernel();
	ip_lock(user_handle);

	/* make a sonce right */
	user_handle->ip_sorights++;
	ip_reference(user_handle);

	user_handle->ip_destination = IP_NULL;
	user_handle->ip_receiver_name = MACH_PORT_NULL;
	user_handle->ip_receiver = ipc_space_kernel;

	/* make a send right */
        user_handle->ip_mscount++;
        user_handle->ip_srights++;
        ip_reference(user_handle);

	ipc_port_nsrequest(user_handle, 1, user_handle, &previous);
	/* nsrequest unlocks user_handle */

	user_object->object = NULL;
	user_object->size = size;
	user_object->offset = 0;
	user_object->backing.pager = pager;
	user_object->protection = permission;
	user_object->internal = internal;
	user_object->is_sub_map = FALSE;
	user_object->ref_count = 1;

	ipc_kobject_set(user_handle, (ipc_kobject_t) user_object,
							IKOT_NAMED_ENTRY);
	*entry_handle = user_handle;
	return KERN_SUCCESS;
}	

kern_return_t
mach_memory_object_memory_entry(
	host_t		host,
	boolean_t	internal,
	vm_size_t	size,
	vm_prot_t	permission,
 	memory_object_t	pager,
	ipc_port_t	*entry_handle)
{
	return mach_memory_object_memory_entry_64( host, internal, 
		(vm_object_offset_t)size, permission, pager, entry_handle);
}



/*
 */

kern_return_t
mach_make_memory_entry_64(
	vm_map_t		target_map,
	vm_object_size_t	*size,
	vm_object_offset_t	offset,
	vm_prot_t		permission,
	ipc_port_t		*object_handle,
	ipc_port_t		parent_entry)
{
	vm_map_version_t	version;
	vm_named_entry_t	user_object;
	ipc_port_t		user_handle;
	ipc_port_t		previous;
	kern_return_t		kr;
	vm_map_t		pmap_map;

	/* needed for call to vm_map_lookup_locked */
	boolean_t		wired;
	vm_object_offset_t	obj_off;
	vm_prot_t		prot;
	vm_object_offset_t	lo_offset, hi_offset;
	vm_behavior_t		behavior;
	vm_object_t		object;

	/* needed for direct map entry manipulation */
	vm_map_entry_t		map_entry;
	vm_map_t		local_map;
	vm_object_size_t	mappable_size;

	
	user_object = (vm_named_entry_t) 
			kalloc(sizeof (struct vm_named_entry));
	if(user_object == NULL)
		return KERN_FAILURE;
	named_entry_lock_init(user_object);
	user_handle = ipc_port_alloc_kernel();
	ip_lock(user_handle);

	/* make a sonce right */
	user_handle->ip_sorights++;
	ip_reference(user_handle);

	user_handle->ip_destination = IP_NULL;
	user_handle->ip_receiver_name = MACH_PORT_NULL;
	user_handle->ip_receiver = ipc_space_kernel;

	/* make a send right */
        user_handle->ip_mscount++;
        user_handle->ip_srights++;
        ip_reference(user_handle);

	ipc_port_nsrequest(user_handle, 1, user_handle, &previous);
	/* nsrequest unlocks user_handle */

	user_object->backing.pager = NULL;
	user_object->ref_count = 1;

	if(parent_entry == NULL) {
	/* Create a named object based on address range within the task map */
	/* Go find the object at given address */

		permission &= VM_PROT_ALL;
		vm_map_lock_read(target_map);

		/* get the object associated with the target address */
		/* note we check the permission of the range against */
		/* that requested by the caller */

		kr = vm_map_lookup_locked(&target_map, offset, 
				permission, &version,
				&object, &obj_off, &prot, &wired, &behavior,
				&lo_offset, &hi_offset, &pmap_map);
		if (kr != KERN_SUCCESS) {
			vm_map_unlock_read(target_map);
			goto make_mem_done;
		}
		if ((prot & permission) != permission) {
			kr = KERN_INVALID_RIGHT;
			vm_object_unlock(object);
			vm_map_unlock_read(target_map);
			if(pmap_map != target_map)
				vm_map_unlock_read(pmap_map);
			goto make_mem_done;
		}

		/* We have an object, now check to see if this object */
		/* is suitable.  If not, create a shadow and share that */
		
		local_map = target_map;
redo_lookup:
		while(TRUE) {
		   if(!vm_map_lookup_entry(local_map, offset, &map_entry)) {
			kr = KERN_INVALID_ARGUMENT;
                        vm_object_unlock(object);
                        vm_map_unlock_read(target_map);
			if(pmap_map != target_map)
				vm_map_unlock_read(pmap_map);
                        goto make_mem_done;
		   }
		   if(!(map_entry->is_sub_map)) {
		      if(map_entry->object.vm_object != object) {
			 kr = KERN_INVALID_ARGUMENT;
                         vm_object_unlock(object);
                         vm_map_unlock_read(target_map);
			 if(pmap_map != target_map)
				vm_map_unlock_read(pmap_map);
                         goto make_mem_done;
	              }
		      break;
		   } else {
			local_map = map_entry->object.sub_map;
			vm_map_lock_read(local_map);
			vm_map_unlock_read(target_map);
			if(pmap_map != target_map)
				vm_map_unlock_read(pmap_map);
			target_map = local_map;
		   }
		}
		if(((map_entry->max_protection) & permission) != permission) {
			 kr = KERN_INVALID_RIGHT;
                         vm_object_unlock(object);
                         vm_map_unlock_read(target_map);
			 if(pmap_map != target_map)
				vm_map_unlock_read(pmap_map);
                         goto make_mem_done;
		}
		if(object->internal) {
	   		/* vm_map_lookup_locked will create a shadow if   */
		 	/* needs_copy is set but does not check for the   */
			/* other two conditions shown. It is important to */ 
			/* set up an object which will not be pulled from */
			/* under us.  */

	      		if ((map_entry->needs_copy  || object->shadowed ||
			     (object->size > 
			 	       ((vm_object_size_t)map_entry->vme_end -
			     	                      map_entry->vme_start)))
				&& !object->true_share) {
		   		if (vm_map_lock_read_to_write(target_map)) {
		            		vm_map_lock_read(target_map);
		            		goto redo_lookup;
		   		}


		   		/* create a shadow object */

		   		vm_object_shadow(&map_entry->object.vm_object, 
					&map_entry->offset, 
					(map_entry->vme_end
					 - map_entry->vme_start));
		   		map_entry->needs_copy = FALSE;
		   		vm_object_unlock(object);
				object = map_entry->object.vm_object;
		   		vm_object_lock(object);
				object->size = map_entry->vme_end 
						- map_entry->vme_start;
		   		obj_off = (offset - map_entry->vme_start) + 
							map_entry->offset;
		   		lo_offset = map_entry->offset;
		   		hi_offset = (map_entry->vme_end -
		         		map_entry->vme_start) +
		         		map_entry->offset;

		   		vm_map_lock_write_to_read(target_map);

	        	}
	   	}

		/* note: in the future we can (if necessary) allow for  */
		/* memory object lists, this will better support        */
		/* fragmentation, but is it necessary?  The user should */
		/* be encouraged to create address space oriented       */
		/* shared objects from CLEAN memory regions which have  */
		/* a known and defined history.  i.e. no inheritence    */
		/* share, make this call before making the region the   */
		/* target of ipc's, etc.  The code above, protecting    */
		/* against delayed copy, etc. is mostly defensive.      */



		object->true_share = TRUE;
		user_object->object = object;
		user_object->internal = object->internal;
		user_object->is_sub_map = FALSE;
		user_object->offset = obj_off;
		user_object->protection = permission;

		/* the size of mapped entry that overlaps with our region */
		/* which is targeted for share.                           */
		/* (entry_end - entry_start) -                            */
		/*                   offset of our beg addr within entry  */
		/* it corresponds to this:                                */

		mappable_size  =  hi_offset - obj_off;
		if(*size > mappable_size)
			*size = mappable_size;

		user_object->size = *size;

		/* user_object pager and internal fields are not used */
		/* when the object field is filled in.		      */

		object->ref_count++; /* we now point to this object, hold on */
		vm_object_res_reference(object);
		vm_object_unlock(object);
		ipc_kobject_set(user_handle, (ipc_kobject_t) user_object,
							IKOT_NAMED_ENTRY);
		*size = user_object->size;
		*object_handle = user_handle;
		vm_map_unlock_read(target_map);
		if(pmap_map != target_map)
			vm_map_unlock_read(pmap_map);
		return KERN_SUCCESS;
	} else {

		vm_named_entry_t	parent_object;

		/* The new object will be base on an existing named object */
		if(ip_kotype(parent_entry) != IKOT_NAMED_ENTRY) {
			kr = KERN_INVALID_ARGUMENT;
			goto make_mem_done;
		}
		parent_object =  (vm_named_entry_t)parent_entry->ip_kobject;
		if(permission & parent_object->protection != permission) {
			kr = KERN_INVALID_ARGUMENT;
			goto make_mem_done;
		}
		if((offset + *size) > parent_object->size) {
			kr = KERN_INVALID_ARGUMENT;
			goto make_mem_done;
		}

		user_object->object = parent_object->object;
		user_object->size = *size;
		user_object->offset = parent_object->offset + offset;
		user_object->protection = permission;
		if(parent_object->is_sub_map) {
		   user_object->backing.map = parent_object->backing.map;
		   vm_map_lock(user_object->backing.map);
		   user_object->backing.map->ref_count++;
		   vm_map_unlock(user_object->backing.map);
		}
		else {
		   user_object->backing.pager = parent_object->backing.pager;
		}
		user_object->internal = parent_object->internal;
		user_object->is_sub_map = parent_object->is_sub_map;

		if(parent_object->object != NULL) {
			/* we now point to this object, hold on */
			vm_object_reference(parent_object->object); 
			vm_object_lock(parent_object->object);
			parent_object->object->true_share = TRUE;
			vm_object_unlock(parent_object->object);
		}
		ipc_kobject_set(user_handle, (ipc_kobject_t) user_object,
							IKOT_NAMED_ENTRY);
		*object_handle = user_handle;
		return KERN_SUCCESS;
	}



make_mem_done:
	ipc_port_dealloc_kernel(user_handle);
	kfree((vm_offset_t)user_object, sizeof (struct vm_named_entry));
	return kr;
}

kern_return_t
mach_make_memory_entry(
	vm_map_t		target_map,
	vm_size_t		*size,
	vm_offset_t		offset,
	vm_prot_t		permission,
	ipc_port_t		*object_handle,
	ipc_port_t		parent_entry)
{
	vm_object_offset_t 	size_64;
	kern_return_t		kr;
	
	size_64 = (vm_object_offset_t)*size;
	kr = mach_make_memory_entry_64(target_map, &size_64, 
			(vm_object_offset_t)offset, permission, object_handle,
			parent_entry);
	*size = (vm_size_t)size_64;
	return kr;
}

/*
 */

kern_return_t
vm_region_object_create(
	vm_map_t		target_map,
	vm_size_t		size,
	ipc_port_t		*object_handle)
{
	vm_named_entry_t	user_object;
	ipc_port_t		user_handle;
	kern_return_t		kr;

	pmap_t		new_pmap = pmap_create((vm_size_t) 0);
	ipc_port_t	previous;
	vm_map_t	new_map;
	
	if(new_pmap == PMAP_NULL)
		return KERN_FAILURE;
	user_object = (vm_named_entry_t) 
			kalloc(sizeof (struct vm_named_entry));
	if(user_object == NULL) {
		pmap_destroy(new_pmap);
		return KERN_FAILURE;
	}
	named_entry_lock_init(user_object);
	user_handle = ipc_port_alloc_kernel();


	ip_lock(user_handle);

	/* make a sonce right */
	user_handle->ip_sorights++;
	ip_reference(user_handle);

	user_handle->ip_destination = IP_NULL;
	user_handle->ip_receiver_name = MACH_PORT_NULL;
	user_handle->ip_receiver = ipc_space_kernel;

	/* make a send right */
        user_handle->ip_mscount++;
        user_handle->ip_srights++;
        ip_reference(user_handle);

	ipc_port_nsrequest(user_handle, 1, user_handle, &previous);
	/* nsrequest unlocks user_handle */

	/* Create a named object based on a submap of specified size */

	new_map = vm_map_create(new_pmap, 0, size, TRUE);
	user_object->backing.map = new_map;


	user_object->object = VM_OBJECT_NULL;
	user_object->internal = TRUE;
	user_object->is_sub_map = TRUE;
	user_object->offset = 0;
	user_object->protection = VM_PROT_ALL;
	user_object->size = size;
	user_object->ref_count = 1;

	ipc_kobject_set(user_handle, (ipc_kobject_t) user_object,
							IKOT_NAMED_ENTRY);
	*object_handle = user_handle;
	return KERN_SUCCESS;

}

/* For a given range, check all map entries.  If the entry coresponds to */
/* the old vm_region/map provided on the call, replace it with the 	 */
/* corresponding range in the new vm_region/map */
kern_return_t vm_map_region_replace(
	vm_map_t	target_map,
	ipc_port_t	old_region, 
	ipc_port_t	new_region,
	vm_offset_t	start,
	vm_offset_t	end)
{
	vm_named_entry_t	old_object;
	vm_named_entry_t	new_object;
	vm_map_t		old_submap;
	vm_map_t		new_submap;
	vm_offset_t		addr;
	vm_map_entry_t		entry;
	int			nested_pmap = 0;


	vm_map_lock(target_map);
	old_object = (vm_named_entry_t)old_region->ip_kobject;
	new_object = (vm_named_entry_t)new_region->ip_kobject;
	if((!old_object->is_sub_map) || (!new_object->is_sub_map)) {
		vm_map_unlock(target_map);
		return KERN_INVALID_ARGUMENT;
	}
	old_submap = (vm_map_t)old_object->backing.map;
	new_submap = (vm_map_t)new_object->backing.map;
	vm_map_lock(old_submap);
	if((old_submap->min_offset != new_submap->min_offset) || 
			(old_submap->max_offset != new_submap->max_offset)) {
		vm_map_unlock(old_submap);
		vm_map_unlock(target_map);
		return KERN_INVALID_ARGUMENT;
	}
	if(!vm_map_lookup_entry(target_map, start, &entry)) {
		/* if the src is not contained, the entry preceeds */
		/* our range */
		addr = entry->vme_start;
		if(entry == vm_map_to_entry(target_map)) {
			vm_map_unlock(old_submap);
			vm_map_unlock(target_map);
			return KERN_SUCCESS;
		}
		vm_map_lookup_entry(target_map, addr, &entry);
	}
	addr = entry->vme_start;
	vm_map_reference(old_submap);
	while((entry != vm_map_to_entry(target_map)) && 
					(entry->vme_start < end)) {
		if((entry->is_sub_map) && 
			(entry->object.sub_map == old_submap)) {
			entry->object.sub_map = new_submap;
			if(entry->use_pmap) {
				if((start & 0xfffffff) || 
					((end - start) != 0x10000000)) {
					vm_map_unlock(old_submap);
					vm_map_unlock(target_map);
					return  KERN_INVALID_ARGUMENT;
				}
				nested_pmap = 1;
			}
			vm_map_reference(new_submap);
			vm_map_deallocate(old_submap);
		}
		entry = entry->vme_next;
		addr = entry->vme_start;
	}
	if(nested_pmap) {
#ifndef i386
		pmap_unnest(target_map->pmap, start, end - start);
		pmap_nest(target_map->pmap, new_submap->pmap, 
						start, end - start);
#endif i386
	} else {
		pmap_remove(target_map->pmap, start, end);
	}
	vm_map_unlock(old_submap);
	vm_map_unlock(target_map);
	return KERN_SUCCESS;
}


void
mach_destroy_memory_entry(
	ipc_port_t	port)
{
	vm_named_entry_t	named_entry;
#if MACH_ASSERT
	assert(ip_kotype(port) == IKOT_NAMED_ENTRY);
#endif /* MACH_ASSERT */
	named_entry = (vm_named_entry_t)port->ip_kobject;
	mutex_lock(&(named_entry)->Lock);
	named_entry->ref_count-=1;
	if(named_entry->ref_count == 0) {
		if(named_entry->object) {
			/* release the memory object we've been pointing to */
			vm_object_deallocate(named_entry->object);
		}
		if(named_entry->is_sub_map) {
			vm_map_deallocate(named_entry->backing.map);
		}
		kfree((vm_offset_t)port->ip_kobject, 
				sizeof (struct vm_named_entry));
	} else
		mutex_unlock(&(named_entry)->Lock);
}


kern_return_t
vm_map_page_query(
	vm_map_t		target_map,
	vm_offset_t		offset,
	int			*disposition,
	int			*ref_count)
{
	vm_map_entry_t	map_entry;
	vm_object_t	object;
	vm_page_t	m;

restart_page_query:
	*disposition = 0;
	*ref_count = 0;
	vm_map_lock(target_map);
	if(!vm_map_lookup_entry(target_map, offset, &map_entry)) {
		vm_map_unlock(target_map);
		return KERN_FAILURE;
	}
	offset -= map_entry->vme_start;  /* adjust to offset within entry */
	offset += map_entry->offset;	 /* adjust to target object offset */
	if(map_entry->object.vm_object != VM_OBJECT_NULL) {
		if(!map_entry->is_sub_map) {
			object = map_entry->object.vm_object;
		} else {
			vm_map_unlock(target_map);
			target_map = map_entry->object.sub_map;
			goto restart_page_query;
		}
	} else {
		vm_map_unlock(target_map);
		return KERN_FAILURE;
	}
	vm_object_lock(object);
	vm_map_unlock(target_map);
	while(TRUE) {
		m = vm_page_lookup(object, offset);
		if (m != VM_PAGE_NULL) {
			*disposition |= VM_PAGE_QUERY_PAGE_PRESENT;
			break;
		} else {
			if(object->shadow) {
				offset += object->shadow_offset;
				vm_object_unlock(object);
				object = object->shadow;
				vm_object_lock(object);
				continue;
			}
			vm_object_unlock(object);
			return KERN_FAILURE;
		}
	}

	/* The ref_count is not strictly accurate, it measures the number   */
	/* of entities holding a ref on the object, they may not be mapping */
	/* the object or may not be mapping the section holding the         */
	/* target page but its still a ball park number and though an over- */
	/* count, it picks up the copy-on-write cases                       */

	/* We could also get a picture of page sharing from pmap_attributes */
	/* but this would under count as only faulted-in mappings would     */
	/* show up.							    */

	*ref_count = object->ref_count;

	if (m->fictitious) {
		*disposition |= VM_PAGE_QUERY_PAGE_FICTITIOUS;
		vm_object_unlock(object);
		return KERN_SUCCESS;
	}

	if (m->dirty)
		*disposition |= VM_PAGE_QUERY_PAGE_DIRTY;
	else if(pmap_is_modified(m->phys_addr))
		*disposition |= VM_PAGE_QUERY_PAGE_DIRTY;

	if (m->reference)
		*disposition |= VM_PAGE_QUERY_PAGE_REF;
	else if(pmap_is_referenced(m->phys_addr))
		*disposition |= VM_PAGE_QUERY_PAGE_REF;

	vm_object_unlock(object);
	return KERN_SUCCESS;
	
}

kern_return_t
set_dp_control_port(
	host_priv_t	host_priv,
	ipc_port_t	control_port)	
{
        if (host_priv == HOST_PRIV_NULL)
                return (KERN_INVALID_HOST);

	if (IP_VALID(dynamic_pager_control_port))
		ipc_port_release_send(dynamic_pager_control_port);

	dynamic_pager_control_port = control_port;
	return KERN_SUCCESS;
}

kern_return_t
get_dp_control_port(
	host_priv_t	host_priv,
	ipc_port_t	*control_port)	
{
        if (host_priv == HOST_PRIV_NULL)
                return (KERN_INVALID_HOST);

	*control_port = ipc_port_copy_send(dynamic_pager_control_port);
	return KERN_SUCCESS;
	
}


/* Retrieve a upl for an object underlying an address range in a map */

kern_return_t
vm_map_get_upl(
	vm_map_t		map,
	vm_address_t		offset,
	vm_size_t		*upl_size,
	upl_t			*upl,
	upl_page_info_array_t	page_list,
	unsigned int		*count,
	int			*flags,
	int             	force_data_sync)
{
	vm_map_entry_t	entry;
	int		caller_flags;
	int		sync_cow_data = FALSE;
	vm_object_t	local_object;
	vm_offset_t	local_offset;
	vm_offset_t	local_start;
	kern_return_t	ret;

	caller_flags = *flags;
	if (!(caller_flags & UPL_COPYOUT_FROM)) {
		sync_cow_data = TRUE;
	}
	if(upl == NULL)
		return KERN_INVALID_ARGUMENT;


REDISCOVER_ENTRY:
	vm_map_lock(map);
	if (vm_map_lookup_entry(map, offset, &entry)) {
		if (entry->object.vm_object == VM_OBJECT_NULL ||
			!entry->object.vm_object->phys_contiguous) {
        		if((*upl_size/page_size) > MAX_UPL_TRANSFER) {
               			*upl_size = MAX_UPL_TRANSFER * page_size;
			}
		}
		if((entry->vme_end - offset) < *upl_size) {
			*upl_size = entry->vme_end - offset;
		}
		if (caller_flags & UPL_QUERY_OBJECT_TYPE) {
			if (entry->object.vm_object == VM_OBJECT_NULL) {
				*flags = 0;
			} else if (entry->object.vm_object->private) {
				*flags = UPL_DEV_MEMORY;
				if (entry->object.vm_object->phys_contiguous) {
					*flags |= UPL_PHYS_CONTIG;
				}
			} else  {
				*flags = 0;
			}
			vm_map_unlock(map);
			return KERN_SUCCESS;
		}
		/*
		 *      Create an object if necessary.
		 */
		if (entry->object.vm_object == VM_OBJECT_NULL) {
			entry->object.vm_object = vm_object_allocate(
				(vm_size_t)(entry->vme_end - entry->vme_start));
			entry->offset = 0;
		}
		if (!(caller_flags & UPL_COPYOUT_FROM)) {
			if (entry->needs_copy)  {
				vm_map_t		local_map;
				vm_object_t		object;
				vm_object_offset_t	offset_hi;
				vm_object_offset_t	offset_lo;
				vm_object_offset_t	new_offset;
				vm_prot_t		prot;
				boolean_t		wired;
				vm_behavior_t		behavior;
				vm_map_version_t	 version;
				vm_map_t		pmap_map;

				local_map = map;
				vm_map_lock_write_to_read(map);
				if(vm_map_lookup_locked(&local_map,
					offset, VM_PROT_WRITE,
					&version, &object,
					&new_offset, &prot, &wired,
					&behavior, &offset_lo,
					&offset_hi, &pmap_map)) {
					vm_map_unlock(local_map);
					return KERN_FAILURE;
				}
				if (pmap_map != map) {
					vm_map_unlock(pmap_map);
				}
				vm_object_unlock(object);
				vm_map_unlock(local_map);

				goto REDISCOVER_ENTRY;
			}
		}
		if (entry->is_sub_map) {
			vm_map_t	submap;

			submap = entry->object.sub_map;
			local_start = entry->vme_start;
			local_offset = entry->offset;
			vm_map_reference(submap);
			vm_map_unlock(map);

			ret = (vm_map_get_upl(submap, 
				local_offset + (offset - local_start), 
				upl_size, upl, page_list, count, 
				flags, force_data_sync));

			vm_map_deallocate(submap);
			return ret;
		}
					
		if (sync_cow_data) {
			if (entry->object.vm_object->shadow
				    || entry->object.vm_object->copy) {
				int		flags;

				local_object = entry->object.vm_object;
				local_start = entry->vme_start;
				local_offset = entry->offset;
				vm_object_reference(local_object);
				vm_map_unlock(map);

				if(local_object->copy == NULL) {
					flags = MEMORY_OBJECT_DATA_SYNC;
				} else {
					flags = MEMORY_OBJECT_COPY_SYNC;
				}

				if((local_object->paging_offset) &&
						(local_object->pager == 0)) {
				   /* 
				    * do a little clean-up for our unorthodox
				    * entry into a pager call from a non-pager
				    * context.  Normally the pager code 
				    * assumes that an object it has been called
				    * with has a backing pager and so does
				    * not bother to check the pager field
				    * before relying on the paging_offset
				    */
				    vm_object_lock(local_object);
				    if (local_object->pager == 0) {
					local_object->paging_offset = 0;
				    }
				    vm_object_unlock(local_object);
				}
					
				if (entry->object.vm_object->shadow && 
					   entry->object.vm_object->copy) {
				   vm_object_lock_request(
					local_object->shadow,
					(vm_object_offset_t)
					((offset - local_start) +
					 local_offset) +
					local_object->shadow_offset +
					local_object->paging_offset,
					*upl_size, FALSE, 
					MEMORY_OBJECT_DATA_SYNC,
					VM_PROT_NO_CHANGE);
				}
				sync_cow_data = FALSE;
				vm_object_deallocate(local_object);
				goto REDISCOVER_ENTRY;
			}
		}

		if (force_data_sync) {

			local_object = entry->object.vm_object;
			local_start = entry->vme_start;
			local_offset = entry->offset;
			vm_object_reference(local_object);
		        vm_map_unlock(map);

			if((local_object->paging_offset) && 
					(local_object->pager == 0)) {
			   /* 
			    * do a little clean-up for our unorthodox
			    * entry into a pager call from a non-pager
			    * context.  Normally the pager code 
			    * assumes that an object it has been called
			    * with has a backing pager and so does
			    * not bother to check the pager field
			    * before relying on the paging_offset
			    */
			    vm_object_lock(local_object);
			    if (local_object->pager == 0) {
				local_object->paging_offset = 0;
			    }
			    vm_object_unlock(local_object);
			}
					
			vm_object_lock_request(
				   local_object,
				   (vm_object_offset_t)
				   ((offset - local_start) + local_offset) + 
				   local_object->paging_offset,
				   (vm_object_size_t)*upl_size, FALSE, 
				   MEMORY_OBJECT_DATA_SYNC,
				   VM_PROT_NO_CHANGE);
			force_data_sync = FALSE;
			vm_object_deallocate(local_object);
			goto REDISCOVER_ENTRY;
		}

		if(!(entry->object.vm_object->private)) {
			if(*upl_size > (MAX_UPL_TRANSFER*PAGE_SIZE))
				*upl_size = (MAX_UPL_TRANSFER*PAGE_SIZE);
			if(entry->object.vm_object->phys_contiguous) {
				*flags = UPL_PHYS_CONTIG;
			} else {
				*flags = 0;
			}
		} else {
			*flags = UPL_DEV_MEMORY | UPL_PHYS_CONTIG;
		}
		local_object = entry->object.vm_object;
		local_offset = entry->offset;
		local_start = entry->vme_start;
		vm_object_reference(local_object);
		vm_map_unlock(map);
		ret = (vm_object_upl_request(local_object, 
			(vm_object_offset_t)
				((offset - local_start) + local_offset),
			*upl_size,
			upl,
			page_list,
			count,
			caller_flags));
		vm_object_deallocate(local_object);
		return(ret);
	} 

	vm_map_unlock(map);
	return(KERN_FAILURE);

}

/* ******* Temporary Internal calls to UPL for BSD ***** */
kern_return_t
kernel_upl_map(
	vm_map_t	map,
	upl_t		upl,
	vm_offset_t	*dst_addr)
{
	return (vm_upl_map(map, upl, dst_addr));
}


kern_return_t
kernel_upl_unmap(
	vm_map_t	map,
	upl_t		upl)
{
	return(vm_upl_unmap(map, upl));
}

kern_return_t
kernel_upl_commit(
	upl_t 			upl,
	upl_page_info_t		*pl,
	mach_msg_type_number_t  count)
{
	kern_return_t 	kr;

	kr = upl_commit(upl, pl, count);
	upl_deallocate(upl);
	return kr;
}


kern_return_t
kernel_upl_commit_range(
	upl_t 			upl,
	vm_offset_t		offset,
	vm_size_t		size,
	int			flags,
	upl_page_info_array_t   pl,
	mach_msg_type_number_t  count)
{
	boolean_t		finished = FALSE;
	kern_return_t 		kr;

	if (flags & UPL_COMMIT_FREE_ON_EMPTY)
		flags |= UPL_COMMIT_NOTIFY_EMPTY;

	kr = upl_commit_range(upl, offset, size, flags, pl, count, &finished);

	if ((flags & UPL_COMMIT_NOTIFY_EMPTY) && finished)
		upl_deallocate(upl);

	return kr;
}
	
kern_return_t
kernel_upl_abort_range(
	upl_t			upl,
	vm_offset_t		offset,
	vm_size_t		size,
	int			abort_flags)
{
	kern_return_t 		kr;
	boolean_t		finished = FALSE;

	if (abort_flags & UPL_COMMIT_FREE_ON_EMPTY)
		abort_flags |= UPL_COMMIT_NOTIFY_EMPTY;

	kr = upl_abort_range(upl, offset, size, abort_flags, &finished);

	if ((abort_flags & UPL_COMMIT_FREE_ON_EMPTY) && finished)
		upl_deallocate(upl);

	return kr;
}

kern_return_t
kernel_upl_abort(
	upl_t			upl,
	int			abort_type)
{
	kern_return_t	kr;

	kr = upl_abort(upl, abort_type);
	upl_deallocate(upl);
	return kr;
}


kern_return_t
vm_get_shared_region(
	task_t	task,
	shared_region_mapping_t	*shared_region)
{
	*shared_region = (shared_region_mapping_t) task->system_shared_region;
	return KERN_SUCCESS;
}

kern_return_t
vm_set_shared_region(
	task_t	task,
	shared_region_mapping_t	shared_region)
{
	task->system_shared_region = (vm_offset_t) shared_region;
	return KERN_SUCCESS;
}

kern_return_t
shared_region_mapping_info(
	shared_region_mapping_t	shared_region,
	ipc_port_t		*text_region,
	vm_size_t		*text_size,
	ipc_port_t		*data_region,
	vm_size_t		*data_size,
	vm_offset_t		*region_mappings,
	vm_offset_t		*client_base,
	vm_offset_t		*alt_base,
	vm_offset_t		*alt_next,
	int			*flags,
	shared_region_mapping_t	*next)
{
	shared_region_mapping_lock(shared_region);

	*text_region = shared_region->text_region;
	*text_size = shared_region->text_size;
	*data_region = shared_region->data_region;
	*data_size = shared_region->data_size;
	*region_mappings = shared_region->region_mappings;
	*client_base = shared_region->client_base;
	*alt_base = shared_region->alternate_base;
	*alt_next = shared_region->alternate_next;
	*flags = shared_region->flags;
	*next = shared_region->next;

	shared_region_mapping_unlock(shared_region);
}

kern_return_t
shared_region_object_chain_attach(
	shared_region_mapping_t		target_region,
	shared_region_mapping_t		object_chain_region)
{
	shared_region_object_chain_t	object_ele;
	
	if(target_region->object_chain)
		return KERN_FAILURE;
	object_ele = (shared_region_object_chain_t)
			kalloc(sizeof (struct shared_region_object_chain));
	shared_region_mapping_lock(object_chain_region);
	target_region->object_chain = object_ele;
	object_ele->object_chain_region = object_chain_region;
	object_ele->next = object_chain_region->object_chain;
	object_ele->depth = object_chain_region->depth;
	object_chain_region->depth++;
	target_region->alternate_next = object_chain_region->alternate_next;
	shared_region_mapping_unlock(object_chain_region);
	return KERN_SUCCESS;
}

kern_return_t
shared_region_mapping_create(
	ipc_port_t		text_region,
	vm_size_t		text_size,
	ipc_port_t		data_region,
	vm_size_t		data_size,
	vm_offset_t		region_mappings,
	vm_offset_t		client_base,
	shared_region_mapping_t	*shared_region,
	vm_offset_t		alt_base,
	vm_offset_t		alt_next)
{
	*shared_region = (shared_region_mapping_t) 
			kalloc(sizeof (struct shared_region_mapping));
	if(*shared_region == NULL)
		return KERN_FAILURE;
	shared_region_mapping_lock_init((*shared_region));
	(*shared_region)->text_region = text_region;
	(*shared_region)->text_size = text_size;
	(*shared_region)->data_region = data_region;
	(*shared_region)->data_size = data_size;
	(*shared_region)->region_mappings = region_mappings;
	(*shared_region)->client_base = client_base;
	(*shared_region)->ref_count = 1;
	(*shared_region)->next = NULL;
	(*shared_region)->object_chain = NULL;
	(*shared_region)->self = *shared_region;
	(*shared_region)->flags = 0;
	(*shared_region)->depth = 0;
	(*shared_region)->alternate_base = alt_base;
	(*shared_region)->alternate_next = alt_next;
	return KERN_SUCCESS;
}

kern_return_t
shared_region_mapping_set_alt_next(
		shared_region_mapping_t	shared_region,
		vm_offset_t		alt_next) 
{
	shared_region->alternate_next = alt_next;
	return KERN_SUCCESS;
}

kern_return_t
shared_region_mapping_ref(
	shared_region_mapping_t	shared_region)
{
	if(shared_region == NULL)
		return KERN_SUCCESS;
	shared_region_mapping_lock(shared_region);
	shared_region->ref_count++;
	shared_region_mapping_unlock(shared_region);
	return KERN_SUCCESS;
}

kern_return_t
shared_region_mapping_dealloc(
	shared_region_mapping_t	shared_region)
{
	struct shared_region_task_mappings sm_info;
	shared_region_mapping_t		next;

	if(shared_region == NULL)
		return KERN_SUCCESS;
	shared_region_mapping_lock(shared_region);

	if((--shared_region->ref_count) == 0) {

		sm_info.text_region = shared_region->text_region;
		sm_info.text_size = shared_region->text_size;
		sm_info.data_region = shared_region->data_region;
		sm_info.data_size = shared_region->data_size;
		sm_info.region_mappings = shared_region->region_mappings;
		sm_info.client_base = shared_region->client_base;
		sm_info.alternate_base = shared_region->alternate_base;
		sm_info.alternate_next = shared_region->alternate_next;
		sm_info.flags = shared_region->flags;
		sm_info.self = (vm_offset_t)shared_region;

		lsf_remove_regions_mappings(shared_region, &sm_info);
		pmap_remove(((vm_named_entry_t)
			(shared_region->text_region->ip_kobject))
						->backing.map->pmap, 
			sm_info.client_base, 
			sm_info.client_base + sm_info.text_size);
		ipc_port_release_send(shared_region->text_region);
		ipc_port_release_send(shared_region->data_region);
		if(shared_region->object_chain) {
			shared_region_mapping_dealloc(
			     shared_region->object_chain->object_chain_region);
			kfree((vm_offset_t)shared_region->object_chain,
				sizeof (struct shared_region_object_chain));
		}
		kfree((vm_offset_t)shared_region,
				sizeof (struct shared_region_mapping));
		return KERN_SUCCESS;
	}
	shared_region_mapping_unlock(shared_region);
	return KERN_SUCCESS;
}

vm_offset_t
vm_map_get_phys_page(
	vm_map_t	map,
	vm_offset_t	offset)
{
	vm_map_entry_t	entry;
	int		ops;
	int		flags;
	vm_offset_t	phys_addr = 0;
	vm_object_t	object;

	vm_map_lock(map);
	while (vm_map_lookup_entry(map, offset, &entry)) {

		if (entry->object.vm_object == VM_OBJECT_NULL) {
			vm_map_unlock(map);
			return (vm_offset_t) 0;
		}
		if (entry->is_sub_map) {
			vm_map_t	old_map;
			vm_map_lock(entry->object.sub_map);
			old_map = map;
			map = entry->object.sub_map;
			offset = entry->offset + (offset - entry->vme_start);
			vm_map_unlock(old_map);
			continue;
		}
		offset = entry->offset + (offset - entry->vme_start);
		object = entry->object.vm_object;
		vm_object_lock(object);
		while (TRUE) {
			vm_page_t dst_page = vm_page_lookup(object,offset);
	                if(dst_page == VM_PAGE_NULL) {
				if(object->shadow) {
					vm_object_t old_object;
					vm_object_lock(object->shadow);
					old_object = object;
					offset = offset + object->shadow_offset;
					object = object->shadow;
					vm_object_unlock(old_object);
				} else {
					vm_object_unlock(object);
					break;
				}
			} else {
				phys_addr = dst_page->phys_addr;
				vm_object_unlock(object);
				break;
			}
		}
		break;

	} 

	vm_map_unlock(map);
	return phys_addr;
}
#endif	/* VM_CPM */

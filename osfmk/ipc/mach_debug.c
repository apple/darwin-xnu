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
 *	File:	ipc/mach_debug.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Exported IPC debug calls.
 */
#include <mach_ipc_debug.h>

#include <mach/vm_param.h>
#include <mach/kern_return.h>
#include <mach/machine/vm_types.h>
#include <mach/mach_host_server.h>
#include <mach/mach_port_server.h>
#include <mach_debug/ipc_info.h>
#include <mach_debug/hash_info.h>

#if MACH_IPC_DEBUG
#include <kern/host.h>
#include <kern/misc_protos.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_hash.h>
#include <ipc/ipc_table.h>
#include <ipc/ipc_right.h>
#endif

/*
 *	Routine:	mach_port_get_srights [kernel call]
 *	Purpose:
 *		Retrieve the number of extant send rights
 *		that a receive right has.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Retrieved number of send rights.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	The name doesn't denote a right.
 *		KERN_INVALID_RIGHT	Name doesn't denote receive rights.
 */

kern_return_t
mach_port_get_srights(
	ipc_space_t		space,
	mach_port_name_t	name,
	mach_port_rights_t	*srightsp)
{
#if !MACH_IPC_DEBUG
        return KERN_FAILURE;
#else
	ipc_port_t port;
	kern_return_t kr;
	mach_port_rights_t srights;

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	kr = ipc_port_translate_receive(space, name, &port);
	if (kr != KERN_SUCCESS)
		return kr;
	/* port is locked and active */

	srights = port->ip_srights;
	ip_unlock(port);

	*srightsp = srights;
	return KERN_SUCCESS;
#endif /* MACH_IPC_DEBUG */
}

/*
 *	Routine:	host_ipc_hash_info
 *	Purpose:
 *		Return information about the global reverse hash table.
 *	Conditions:
 *		Nothing locked.  Obeys CountInOut protocol.
 *	Returns:
 *		KERN_SUCCESS		Returned information.
 *		KERN_INVALID_HOST	The host is null.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
host_ipc_hash_info(
	host_t				host,
	hash_info_bucket_array_t	*infop,
	mach_msg_type_number_t 		*countp)
{
#if !MACH_IPC_DEBUG
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
		actual = ipc_hash_info(info, potential);
		if (actual <= potential)
			break;

		/* allocate more memory */

		if (info != *infop)
			kmem_free(ipc_kernel_map, addr, size);

		size = round_page_32(actual * sizeof *info);
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

		used = round_page_32(actual * sizeof *info);

		if (used != size)
			kmem_free(ipc_kernel_map, addr + used, size - used);

		kr = vm_map_copyin(ipc_kernel_map, addr, used,
				   TRUE, &copy);
		assert(kr == KERN_SUCCESS);

		*infop = (hash_info_bucket_t *) copy;
		*countp = actual;
	}

	return KERN_SUCCESS;
#endif /* MACH_IPC_DEBUG */
}

/*
 *	Routine:	mach_port_space_info
 *	Purpose:
 *		Returns information about an IPC space.
 *	Conditions:
 *		Nothing locked.  Obeys CountInOut protocol.
 *	Returns:
 *		KERN_SUCCESS		Returned information.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
mach_port_space_info(
	ipc_space_t			space,
	ipc_info_space_t		*infop,
	ipc_info_name_array_t		*tablep,
	mach_msg_type_number_t 		*tableCntp,
	ipc_info_tree_name_array_t	*treep,
	mach_msg_type_number_t 		*treeCntp)
{
#if !MACH_IPC_DEBUG
        return KERN_FAILURE;
#else
	ipc_info_name_t *table_info;
	unsigned int table_potential, table_actual;
	vm_offset_t table_addr;
	vm_size_t table_size;
	ipc_info_tree_name_t *tree_info;
	unsigned int tree_potential, tree_actual;
	vm_offset_t tree_addr;
	vm_size_t tree_size;
	ipc_tree_entry_t tentry;
	ipc_entry_t table;
	ipc_entry_num_t tsize;
	mach_port_index_t index;
	kern_return_t kr;
	ipc_entry_bits_t *capability;

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	/* start with in-line memory */

	table_info = *tablep;
	table_potential = *tableCntp;
	tree_info = *treep;
	tree_potential = *treeCntp;

	for (;;) {
		is_read_lock(space);
		if (!space->is_active) {
			is_read_unlock(space);
			if (table_info != *tablep)
				kmem_free(ipc_kernel_map,
					  table_addr, table_size);
			if (tree_info != *treep)
				kmem_free(ipc_kernel_map,
					  tree_addr, tree_size);
			return KERN_INVALID_TASK;
		}

		table_actual = space->is_table_size;
		tree_actual = space->is_tree_total;

		if ((table_actual <= table_potential) &&
		    (tree_actual <= tree_potential))
			break;

		is_read_unlock(space);

		if (table_actual > table_potential) {
			if (table_info != *tablep)
				kmem_free(ipc_kernel_map,
					  table_addr, table_size);

			table_size = round_page_32(table_actual *
						sizeof *table_info);
			kr = kmem_alloc(ipc_kernel_map,
					&table_addr, table_size);
			if (kr != KERN_SUCCESS) {
				if (tree_info != *treep)
					kmem_free(ipc_kernel_map,
						  tree_addr, tree_size);

				return KERN_RESOURCE_SHORTAGE;
			}

			table_info = (ipc_info_name_t *) table_addr;
			table_potential = table_size/sizeof *table_info;
		}

		if (tree_actual > tree_potential) {
			if (tree_info != *treep)
				kmem_free(ipc_kernel_map,
					  tree_addr, tree_size);

			tree_size = round_page_32(tree_actual *
					       sizeof *tree_info);
			kr = kmem_alloc(ipc_kernel_map,
					&tree_addr, tree_size);
			if (kr != KERN_SUCCESS) {
				if (table_info != *tablep)
					kmem_free(ipc_kernel_map,
						  table_addr, table_size);

				return KERN_RESOURCE_SHORTAGE;
			}

			tree_info = (ipc_info_tree_name_t *) tree_addr;
			tree_potential = tree_size/sizeof *tree_info;
		}
	}
	/* space is read-locked and active; we have enough wired memory */

	infop->iis_genno_mask = MACH_PORT_NGEN(MACH_PORT_DEAD);
	infop->iis_table_size = space->is_table_size;
	infop->iis_table_next = space->is_table_next->its_size;
	infop->iis_tree_size = space->is_tree_total;
	infop->iis_tree_small = space->is_tree_small;
	infop->iis_tree_hash = space->is_tree_hash;

	table = space->is_table;
	tsize = space->is_table_size;

	for (index = 0; index < tsize; index++) {
		ipc_info_name_t *iin = &table_info[index];
		ipc_entry_t entry = &table[index];
		ipc_entry_bits_t bits;

		bits = entry->ie_bits;
		iin->iin_name = MACH_PORT_MAKE(index, IE_BITS_GEN(bits));
		iin->iin_collision = (bits & IE_BITS_COLLISION) ? TRUE : FALSE;
		iin->iin_type = IE_BITS_TYPE(bits);
		iin->iin_urefs = IE_BITS_UREFS(bits);
		iin->iin_object = (vm_offset_t) entry->ie_object;
		iin->iin_next = entry->ie_next;
		iin->iin_hash = entry->ie_index;
	}

	for (tentry = ipc_splay_traverse_start(&space->is_tree), index = 0;
	     tentry != ITE_NULL;
	     tentry = ipc_splay_traverse_next(&space->is_tree, FALSE)) {
		ipc_info_tree_name_t *iitn = &tree_info[index++];
		ipc_info_name_t *iin = &iitn->iitn_name;
		ipc_entry_t entry = &tentry->ite_entry;
		ipc_entry_bits_t bits = entry->ie_bits;

		assert(IE_BITS_TYPE(bits) != MACH_PORT_TYPE_NONE);

		iin->iin_name = tentry->ite_name;
		iin->iin_collision = (bits & IE_BITS_COLLISION) ? TRUE : FALSE;
		iin->iin_type = IE_BITS_TYPE(bits);
		iin->iin_urefs = IE_BITS_UREFS(bits);
		iin->iin_object = (vm_offset_t) entry->ie_object;
		iin->iin_next = entry->ie_next;
		iin->iin_hash = entry->ie_index;

		if (tentry->ite_lchild == ITE_NULL)
			iitn->iitn_lchild = MACH_PORT_NULL;
		else
			iitn->iitn_lchild = tentry->ite_lchild->ite_name;

		if (tentry->ite_rchild == ITE_NULL)
			iitn->iitn_rchild = MACH_PORT_NULL;
		else
			iitn->iitn_rchild = tentry->ite_rchild->ite_name;

	}
	ipc_splay_traverse_finish(&space->is_tree);
	is_read_unlock(space);

	if (table_info == *tablep) {
		/* data fit in-line; nothing to deallocate */

		*tableCntp = table_actual;
	} else if (table_actual == 0) {
		kmem_free(ipc_kernel_map, table_addr, table_size);

		*tableCntp = 0;
	} else {
		vm_size_t size_used, rsize_used;
		vm_map_copy_t copy;

		/* kmem_alloc doesn't zero memory */

		size_used = table_actual * sizeof *table_info;
		rsize_used = round_page_32(size_used);

		if (rsize_used != table_size)
			kmem_free(ipc_kernel_map,
				  table_addr + rsize_used,
				  table_size - rsize_used);

		if (size_used != rsize_used)
			bzero((char *) (table_addr + size_used),
			      rsize_used - size_used);

		kr = vm_map_unwire(ipc_kernel_map, table_addr,
				   table_addr + rsize_used, FALSE);
		assert(kr == KERN_SUCCESS);

		kr = vm_map_copyin(ipc_kernel_map, table_addr, rsize_used,
				   TRUE, &copy);
		assert(kr == KERN_SUCCESS);

		*tablep = (ipc_info_name_t *) copy;
		*tableCntp = table_actual;
	}

	if (tree_info == *treep) {
		/* data fit in-line; nothing to deallocate */

		*treeCntp = tree_actual;
	} else if (tree_actual == 0) {
		kmem_free(ipc_kernel_map, tree_addr, tree_size);

		*treeCntp = 0;
	} else {
		vm_size_t size_used, rsize_used;
		vm_map_copy_t copy;

		/* kmem_alloc doesn't zero memory */

		size_used = tree_actual * sizeof *tree_info;
		rsize_used = round_page_32(size_used);

		if (rsize_used != tree_size)
			kmem_free(ipc_kernel_map,
				  tree_addr + rsize_used,
				  tree_size - rsize_used);

		if (size_used != rsize_used)
			bzero((char *) (tree_addr + size_used),
			      rsize_used - size_used);

		kr = vm_map_unwire(ipc_kernel_map, tree_addr,
				   tree_addr + rsize_used, FALSE);
		assert(kr == KERN_SUCCESS);

		kr = vm_map_copyin(ipc_kernel_map, tree_addr, rsize_used,
				   TRUE, &copy);
		assert(kr == KERN_SUCCESS);

		*treep = (ipc_info_tree_name_t *) copy;
		*treeCntp = tree_actual;
	}

	return KERN_SUCCESS;
#endif /* MACH_IPC_DEBUG */
}

/*
 *	Routine:	mach_port_dnrequest_info
 *	Purpose:
 *		Returns information about the dead-name requests
 *		registered with the named receive right.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Retrieved information.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	The name doesn't denote a right.
 *		KERN_INVALID_RIGHT	Name doesn't denote receive rights.
 */

kern_return_t
mach_port_dnrequest_info(
	ipc_space_t		space,
	mach_port_name_t	name,
	unsigned int		*totalp,
	unsigned int		*usedp)
{
#if !MACH_IPC_DEBUG
        return KERN_FAILURE;
#else
	unsigned int total, used;
	ipc_port_t port;
	kern_return_t kr;

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	kr = ipc_port_translate_receive(space, name, &port);
	if (kr != KERN_SUCCESS)
		return kr;
	/* port is locked and active */

	if (port->ip_dnrequests == IPR_NULL) {
		total = 0;
		used = 0;
	} else {
		ipc_port_request_t dnrequests = port->ip_dnrequests;
		ipc_port_request_index_t index;

		total = dnrequests->ipr_size->its_size;

		for (index = 1, used = 0;
		     index < total; index++) {
			ipc_port_request_t ipr = &dnrequests[index];

			if (ipr->ipr_name != MACH_PORT_NULL)
				used++;
		}
	}
	ip_unlock(port);

	*totalp = total;
	*usedp = used;
	return KERN_SUCCESS;
#endif /* MACH_IPC_DEBUG */
}

/*
 *	Routine:	mach_port_kernel_object [kernel call]
 *	Purpose:
 *		Retrieve the type and address of the kernel object
 *		represented by a send or receive right.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Retrieved kernel object info.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	The name doesn't denote a right.
 *		KERN_INVALID_RIGHT	Name doesn't denote
 *					send or receive rights.
 */

kern_return_t
mach_port_kernel_object(
	ipc_space_t		space,
	mach_port_name_t	name,
	unsigned int		*typep,
	vm_offset_t		*addrp)
{
#if !MACH_IPC_DEBUG
        return KERN_FAILURE;
#else
	ipc_entry_t entry;
	ipc_port_t port;
	kern_return_t kr;

	kr = ipc_right_lookup_read(space, name, &entry);
	if (kr != KERN_SUCCESS)
		return kr;
	/* space is read-locked and active */

	if ((entry->ie_bits & MACH_PORT_TYPE_SEND_RECEIVE) == 0) {
		is_read_unlock(space);
		return KERN_INVALID_RIGHT;
	}

	port = (ipc_port_t) entry->ie_object;
	assert(port != IP_NULL);

	ip_lock(port);
	is_read_unlock(space);

	if (!ip_active(port)) {
		ip_unlock(port);
		return KERN_INVALID_RIGHT;
	}

	*typep = (unsigned int) ip_kotype(port);
	*addrp = (vm_offset_t) port->ip_kobject;
	ip_unlock(port);
	return KERN_SUCCESS;

#endif /* MACH_IPC_DEBUG */
}

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
#include <ipc/port.h>
#include <ipc/ipc_types.h>
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

#if !MACH_IPC_DEBUG
kern_return_t
mach_port_get_srights(
	__unused ipc_space_t		space,
	__unused mach_port_name_t	name,
	__unused mach_port_rights_t	*srightsp)
{
        return KERN_FAILURE;
}
#else
kern_return_t
mach_port_get_srights(
	ipc_space_t		space,
	mach_port_name_t	name,
	mach_port_rights_t	*srightsp)
{
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
}
#endif /* MACH_IPC_DEBUG */


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

#if !MACH_IPC_DEBUG
kern_return_t
mach_port_space_info(
	__unused ipc_space_t			space,
	__unused ipc_info_space_t		*infop,
	__unused ipc_info_name_array_t	*tablep,
	__unused mach_msg_type_number_t 	*tableCntp,
	__unused ipc_info_tree_name_array_t *treep,
	__unused mach_msg_type_number_t 	*treeCntp)
{
        return KERN_FAILURE;
}
#else
kern_return_t
mach_port_space_info(
	ipc_space_t			space,
	ipc_info_space_t		*infop,
	ipc_info_name_array_t		*tablep,
	mach_msg_type_number_t 		*tableCntp,
	__unused ipc_info_tree_name_array_t	*treep,
	__unused mach_msg_type_number_t         *treeCntp)
{
	ipc_info_name_t *table_info;
	vm_offset_t table_addr;
	vm_size_t table_size, table_size_needed;
	ipc_entry_t table;
	ipc_entry_num_t tsize;
	mach_port_index_t index;
	kern_return_t kr;
	vm_map_copy_t copy;


	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	/* start with in-line memory */

	table_size = 0;

	for (;;) {
		is_read_lock(space);
		if (!is_active(space)) {
			is_read_unlock(space);
			if (table_size != 0)
				kmem_free(ipc_kernel_map,
					  table_addr, table_size);
			return KERN_INVALID_TASK;
		}

		table_size_needed =
			vm_map_round_page((space->is_table_size
					   * sizeof(ipc_info_name_t)),
					  VM_MAP_PAGE_MASK(ipc_kernel_map));

		if (table_size_needed == table_size)
			break;

		is_read_unlock(space);

		if (table_size != table_size_needed) {
			if (table_size != 0)
				kmem_free(ipc_kernel_map, table_addr, table_size);
			kr = kmem_alloc(ipc_kernel_map,	&table_addr, table_size_needed);
			if (kr != KERN_SUCCESS) {
				return KERN_RESOURCE_SHORTAGE;
			}
			table_size = table_size_needed;
		}

	}
	/* space is read-locked and active; we have enough wired memory */

	/* get the overall space info */
	infop->iis_genno_mask = MACH_PORT_NGEN(MACH_PORT_DEAD);
	infop->iis_table_size = space->is_table_size;
	infop->iis_table_next = space->is_table_next->its_size;

	/* walk the table for this space */
	table = space->is_table;
	tsize = space->is_table_size;
	table_info = (ipc_info_name_array_t)table_addr;
	for (index = 0; index < tsize; index++) {
		ipc_info_name_t *iin = &table_info[index];
		ipc_entry_t entry = &table[index];
		ipc_entry_bits_t bits;

		bits = entry->ie_bits;
		iin->iin_name = MACH_PORT_MAKE(index, IE_BITS_GEN(bits));
		iin->iin_collision = 0;
		iin->iin_type = IE_BITS_TYPE(bits);
		if ((entry->ie_bits & MACH_PORT_TYPE_PORT_RIGHTS) != MACH_PORT_TYPE_NONE &&
		    entry->ie_request != IE_REQ_NONE) {
			ipc_port_t port = (ipc_port_t) entry->ie_object;

			assert(IP_VALID(port));
			ip_lock(port);
			iin->iin_type |= ipc_port_request_type(port, iin->iin_name, entry->ie_request);
			ip_unlock(port);
		}

		iin->iin_urefs = IE_BITS_UREFS(bits);
		iin->iin_object = (natural_t)VM_KERNEL_ADDRPERM((uintptr_t)entry->ie_object);
		iin->iin_next = entry->ie_next;
		iin->iin_hash = entry->ie_index;
	}

	is_read_unlock(space);

	/* prepare the table out-of-line data for return */
	if (table_size > 0) {
		if (table_size > infop->iis_table_size * sizeof(ipc_info_name_t))
			bzero((char *)&table_info[infop->iis_table_size],
			      table_size - infop->iis_table_size * sizeof(ipc_info_name_t));

		kr = vm_map_unwire(
			ipc_kernel_map,
			vm_map_trunc_page(table_addr,
					  VM_MAP_PAGE_MASK(ipc_kernel_map)),
			vm_map_round_page(table_addr + table_size,
					  VM_MAP_PAGE_MASK(ipc_kernel_map)),
			FALSE);
		assert(kr == KERN_SUCCESS);
		kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)table_addr, 
				   (vm_map_size_t)table_size, TRUE, &copy);
		assert(kr == KERN_SUCCESS);
		*tablep = (ipc_info_name_t *)copy;
		*tableCntp = infop->iis_table_size;
	} else {
		*tablep = (ipc_info_name_t *)0;
		*tableCntp = 0;
	}

	/* splay tree is obsolete, no work to do... */
	*treep = (ipc_info_tree_name_t *)0;
	*treeCntp = 0;
	return KERN_SUCCESS;
}
#endif /* MACH_IPC_DEBUG */

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

#if !MACH_IPC_DEBUG
kern_return_t
mach_port_dnrequest_info(
	__unused ipc_space_t		space,
	__unused mach_port_name_t	name,
	__unused unsigned int	*totalp,
	__unused unsigned int	*usedp)
{
        return KERN_FAILURE;
}
#else
kern_return_t
mach_port_dnrequest_info(
	ipc_space_t			space,
	mach_port_name_t		name,
	unsigned int			*totalp,
	unsigned int			*usedp)
{
	unsigned int total, used;
	ipc_port_t port;
	kern_return_t kr;

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	kr = ipc_port_translate_receive(space, name, &port);
	if (kr != KERN_SUCCESS)
		return kr;
	/* port is locked and active */

	if (port->ip_requests == IPR_NULL) {
		total = 0;
		used = 0;
	} else {
		ipc_port_request_t requests = port->ip_requests;
		ipc_port_request_index_t index;

		total = requests->ipr_size->its_size;

		for (index = 1, used = 0;
		     index < total; index++) {
			ipc_port_request_t ipr = &requests[index];

			if (ipr->ipr_name != MACH_PORT_NULL)
				used++;
		}
	}
	ip_unlock(port);

	*totalp = total;
	*usedp = used;
	return KERN_SUCCESS;
}
#endif /* MACH_IPC_DEBUG */

/*
 *	Routine:	mach_port_kobject [kernel call]
 *	Purpose:
 *		Retrieve the type and address of the kernel object
 *		represented by a send or receive right. Returns
 *		the kernel address in a mach_vm_address_t to
 *		mask potential differences in kernel address space
 *		size.
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

#if !MACH_IPC_DEBUG
kern_return_t
mach_port_kobject(
	__unused ipc_space_t		space,
	__unused mach_port_name_t	name,
	__unused natural_t		*typep,
	__unused mach_vm_address_t	*addrp)
{
        return KERN_FAILURE;
}
#else
kern_return_t
mach_port_kobject(
	ipc_space_t			space,
	mach_port_name_t		name,
	natural_t			*typep,
	mach_vm_address_t		*addrp)
{
	ipc_entry_t entry;
	ipc_port_t port;
	kern_return_t kr;
	mach_vm_address_t kaddr;

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

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
	kaddr = (mach_vm_address_t)port->ip_kobject;
	ip_unlock(port);

	if (0 != kaddr && is_ipc_kobject(*typep))
		*addrp = VM_KERNEL_ADDRPERM(VM_KERNEL_UNSLIDE(kaddr));
	else
		*addrp = 0;

	return KERN_SUCCESS;
}
#endif /* MACH_IPC_DEBUG */
/*
 *	Routine:	mach_port_kernel_object [Legacy kernel call]
 *	Purpose:
 *		Retrieve the type and address of the kernel object
 *		represented by a send or receive right. Hard-coded
 *		to return only the low-order 32-bits of the kernel
 *		object.
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

#if !MACH_IPC_DEBUG
kern_return_t
mach_port_kernel_object(
	__unused ipc_space_t		space,
	__unused mach_port_name_t	name,
	__unused unsigned int		*typep,
	__unused unsigned int		*addrp)
{
        return KERN_FAILURE;
}
#else
kern_return_t
mach_port_kernel_object(
	ipc_space_t			space,
	mach_port_name_t		name,
	unsigned int			*typep,
	unsigned int			*addrp)
{
	mach_vm_address_t addr = 0;
	kern_return_t kr;

	kr = mach_port_kobject(space, name, typep, &addr);
	*addrp = (unsigned int) addr;
	return kr;
}
#endif /* MACH_IPC_DEBUG */

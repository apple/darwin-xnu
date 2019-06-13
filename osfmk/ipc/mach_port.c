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
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
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
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 * Copyright (c) 2005-2006 SPARTA, Inc.
 */
/*
 */
/*
 *	File:	ipc/mach_port.c
 *	Author:	Rich Draves
 *	Date: 	1989
 *
 *	Exported kernel calls.  See mach/mach_port.defs.
 */

#include <mach_debug.h>

#include <mach/port.h>
#include <mach/kern_return.h>
#include <mach/notify.h>
#include <mach/mach_param.h>
#include <mach/vm_param.h>
#include <mach/vm_prot.h>
#include <mach/vm_map.h>
#include <kern/task.h>
#include <kern/counters.h>
#include <kern/thread.h>
#include <kern/kalloc.h>
#include <kern/exc_guard.h>
#include <mach/mach_port_server.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <ipc/port.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_notify.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_pset.h>
#include <ipc/ipc_right.h>
#include <ipc/ipc_kmsg.h>
#include <kern/misc_protos.h>
#include <security/mac_mach_internal.h>

#if IMPORTANCE_INHERITANCE
#include <ipc/ipc_importance.h>
#endif


/*
 * Forward declarations
 */
void mach_port_names_helper(
	ipc_port_timestamp_t	timestamp,
	ipc_entry_t		entry,
	mach_port_name_t	name,
	mach_port_name_t	*names,
	mach_port_type_t	*types,
	ipc_entry_num_t		*actualp);

void mach_port_gst_helper(
	ipc_pset_t		pset,
	ipc_entry_num_t		maxnames,
	mach_port_name_t	*names,
	ipc_entry_num_t		*actualp);

/* Needs port locked */
void mach_port_get_status_helper(
	ipc_port_t		port,
	mach_port_status_t	*status);

/* Zeroed template of qos flags */

static mach_port_qos_t	qos_template;

/*
 *	Routine:	mach_port_names_helper
 *	Purpose:
 *		A helper function for mach_port_names.
 *
 *	Conditions:
 *		Space containing entry is [at least] read-locked.
 */

void
mach_port_names_helper(
	ipc_port_timestamp_t	timestamp,
	ipc_entry_t		entry,
	mach_port_name_t	name,
	mach_port_name_t	*names,
	mach_port_type_t	*types,
	ipc_entry_num_t		*actualp)
{
	ipc_entry_bits_t bits;
	ipc_port_request_index_t request;
	mach_port_type_t type = 0;
	ipc_entry_num_t actual;
	ipc_port_t port;

	bits = entry->ie_bits;
	request = entry->ie_request;
	__IGNORE_WCASTALIGN(port = (ipc_port_t) entry->ie_object);

	if (bits & MACH_PORT_TYPE_RECEIVE) {
		assert(IP_VALID(port));

		if (request != IE_REQ_NONE) {
			ip_lock(port);
			assert(ip_active(port));
			type |= ipc_port_request_type(port, name, request);
			ip_unlock(port);
		}

	} else if (bits & MACH_PORT_TYPE_SEND_RIGHTS) {
		mach_port_type_t reqtype;

		assert(IP_VALID(port));
		ip_lock(port);

		reqtype = (request != IE_REQ_NONE) ?
			  ipc_port_request_type(port, name, request) : 0;
		
		/*
		 * If the port is alive, or was alive when the mach_port_names
		 * started, then return that fact.  Otherwise, pretend we found
		 * a dead name entry.
		 */
		if (ip_active(port) || IP_TIMESTAMP_ORDER(timestamp, port->ip_timestamp)) {
			type |= reqtype;
		} else {
			bits &= ~(IE_BITS_TYPE_MASK);
			bits |= MACH_PORT_TYPE_DEAD_NAME;
			/* account for additional reference for dead-name notification */
			if (reqtype != 0)
				bits++;
		}
		ip_unlock(port);
	}

	type |= IE_BITS_TYPE(bits);

	actual = *actualp;
	names[actual] = name;
	types[actual] = type;
	*actualp = actual+1;
}

/*
 *	Routine:	mach_port_names [kernel call]
 *	Purpose:
 *		Retrieves a list of the rights present in the space,
 *		along with type information.  (Same as returned
 *		by mach_port_type.)  The names are returned in
 *		no particular order, but they (and the type info)
 *		are an accurate snapshot of the space.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Arrays of names and types returned.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
mach_port_names(
	ipc_space_t		space,
	mach_port_name_t	**namesp,
	mach_msg_type_number_t	*namesCnt,
	mach_port_type_t	**typesp,
	mach_msg_type_number_t	*typesCnt)
{
	ipc_entry_t table;
	ipc_entry_num_t tsize;
	mach_port_index_t index;
	ipc_entry_num_t actual;	/* this many names */
	ipc_port_timestamp_t timestamp;	/* logical time of this operation */
	mach_port_name_t *names;
	mach_port_type_t *types;
	kern_return_t kr;

	vm_size_t size;		/* size of allocated memory */
	vm_offset_t addr1;	/* allocated memory, for names */
	vm_offset_t addr2;	/* allocated memory, for types */
	vm_map_copy_t memory1;	/* copied-in memory, for names */
	vm_map_copy_t memory2;	/* copied-in memory, for types */

	/* safe simplifying assumption */
	static_assert(sizeof(mach_port_name_t) == sizeof(mach_port_type_t));

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	size = 0;

	for (;;) {
		ipc_entry_num_t bound;
		vm_size_t size_needed;

		is_read_lock(space);
		if (!is_active(space)) {
			is_read_unlock(space);
			if (size != 0) {
				kmem_free(ipc_kernel_map, addr1, size);
				kmem_free(ipc_kernel_map, addr2, size);
			}
			return KERN_INVALID_TASK;
		}

		/* upper bound on number of names in the space */
		bound = space->is_table_size;
		size_needed = vm_map_round_page(
			(bound * sizeof(mach_port_name_t)),
			VM_MAP_PAGE_MASK(ipc_kernel_map));

		if (size_needed <= size)
			break;

		is_read_unlock(space);

		if (size != 0) {
			kmem_free(ipc_kernel_map, addr1, size);
			kmem_free(ipc_kernel_map, addr2, size);
		}
		size = size_needed;

		kr = vm_allocate_kernel(ipc_kernel_map, &addr1, size, VM_FLAGS_ANYWHERE, VM_KERN_MEMORY_IPC);
		if (kr != KERN_SUCCESS)
			return KERN_RESOURCE_SHORTAGE;

		kr = vm_allocate_kernel(ipc_kernel_map, &addr2, size, VM_FLAGS_ANYWHERE, VM_KERN_MEMORY_IPC);
		if (kr != KERN_SUCCESS) {
			kmem_free(ipc_kernel_map, addr1, size);
			return KERN_RESOURCE_SHORTAGE;
		}

		/* can't fault while we hold locks */

		kr = vm_map_wire_kernel(
			ipc_kernel_map,
			vm_map_trunc_page(addr1,
					  VM_MAP_PAGE_MASK(ipc_kernel_map)),
			vm_map_round_page(addr1 + size,
					  VM_MAP_PAGE_MASK(ipc_kernel_map)),
			VM_PROT_READ|VM_PROT_WRITE, VM_KERN_MEMORY_IPC,
			FALSE);
		if (kr != KERN_SUCCESS) {
			kmem_free(ipc_kernel_map, addr1, size);
			kmem_free(ipc_kernel_map, addr2, size);
			return KERN_RESOURCE_SHORTAGE;
		}

		kr = vm_map_wire_kernel(
			ipc_kernel_map,
			vm_map_trunc_page(addr2,
					  VM_MAP_PAGE_MASK(ipc_kernel_map)),
			vm_map_round_page(addr2 + size,
					  VM_MAP_PAGE_MASK(ipc_kernel_map)),
			VM_PROT_READ|VM_PROT_WRITE,
			VM_KERN_MEMORY_IPC,
			FALSE);
		if (kr != KERN_SUCCESS) {
			kmem_free(ipc_kernel_map, addr1, size);
			kmem_free(ipc_kernel_map, addr2, size);
			return KERN_RESOURCE_SHORTAGE;
		}

	}
	/* space is read-locked and active */

	names = (mach_port_name_t *) addr1;
	types = (mach_port_type_t *) addr2;
	actual = 0;

	timestamp = ipc_port_timestamp();

	table = space->is_table;
	tsize = space->is_table_size;

	for (index = 0; index < tsize; index++) {
		ipc_entry_t entry = &table[index];
		ipc_entry_bits_t bits = entry->ie_bits;

		if (IE_BITS_TYPE(bits) != MACH_PORT_TYPE_NONE) {
			mach_port_name_t name;

			name = MACH_PORT_MAKE(index, IE_BITS_GEN(bits));
			mach_port_names_helper(timestamp, entry, name, names,
					       types, &actual);
		}
	}

	is_read_unlock(space);

	if (actual == 0) {
		memory1 = VM_MAP_COPY_NULL;
		memory2 = VM_MAP_COPY_NULL;

		if (size != 0) {
			kmem_free(ipc_kernel_map, addr1, size);
			kmem_free(ipc_kernel_map, addr2, size);
		}
	} else {
		vm_size_t size_used;
		vm_size_t vm_size_used;

		size_used = actual * sizeof(mach_port_name_t);
		vm_size_used =
			vm_map_round_page(size_used,
					  VM_MAP_PAGE_MASK(ipc_kernel_map));

		/*
		 *	Make used memory pageable and get it into
		 *	copied-in form.  Free any unused memory.
		 */

		kr = vm_map_unwire(
			ipc_kernel_map,
			vm_map_trunc_page(addr1,
					  VM_MAP_PAGE_MASK(ipc_kernel_map)),
			vm_map_round_page(addr1 + vm_size_used,
					  VM_MAP_PAGE_MASK(ipc_kernel_map)),
			FALSE);
		assert(kr == KERN_SUCCESS);

		kr = vm_map_unwire(
			ipc_kernel_map,
			vm_map_trunc_page(addr2,
					  VM_MAP_PAGE_MASK(ipc_kernel_map)),
			vm_map_round_page(addr2 + vm_size_used,
					  VM_MAP_PAGE_MASK(ipc_kernel_map)),
			FALSE);
		assert(kr == KERN_SUCCESS);

		kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)addr1,
				   (vm_map_size_t)size_used, TRUE, &memory1);
		assert(kr == KERN_SUCCESS);

		kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)addr2,
				   (vm_map_size_t)size_used, TRUE, &memory2);
		assert(kr == KERN_SUCCESS);

		if (vm_size_used != size) {
			kmem_free(ipc_kernel_map,
				  addr1 + vm_size_used, size - vm_size_used);
			kmem_free(ipc_kernel_map,
				  addr2 + vm_size_used, size - vm_size_used);
		}
	}

	*namesp = (mach_port_name_t *) memory1;
	*namesCnt = actual;
	*typesp = (mach_port_type_t *) memory2;
	*typesCnt = actual;
	return KERN_SUCCESS;
}

/*
 *	Routine:	mach_port_type [kernel call]
 *	Purpose:
 *		Retrieves the type of a right in the space.
 *		The type is a bitwise combination of one or more
 *		of the following type bits:
 *			MACH_PORT_TYPE_SEND
 *			MACH_PORT_TYPE_RECEIVE
 *			MACH_PORT_TYPE_SEND_ONCE
 *			MACH_PORT_TYPE_PORT_SET
 *			MACH_PORT_TYPE_DEAD_NAME
 *		In addition, the following pseudo-type bits may be present:
 *			MACH_PORT_TYPE_DNREQUEST
 *				A dead-name notification is requested.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Type is returned.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	The name doesn't denote a right.
 */

kern_return_t
mach_port_type(
	ipc_space_t		space,
	mach_port_name_t	name,
	mach_port_type_t	*typep)
{
	mach_port_urefs_t urefs;
	ipc_entry_t entry;
	kern_return_t kr;

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	if (name == MACH_PORT_NULL)
		return KERN_INVALID_NAME;

	if (name == MACH_PORT_DEAD) {
		*typep = MACH_PORT_TYPE_DEAD_NAME;
		return KERN_SUCCESS;
	}

	kr = ipc_right_lookup_write(space, name, &entry);
	if (kr != KERN_SUCCESS) {
		mach_port_guard_exception(name, 0, 0, kGUARD_EXC_INVALID_NAME);
		return kr;
	}

	/* space is write-locked and active */
	kr = ipc_right_info(space, name, entry, typep, &urefs);
	/* space is unlocked */

#if 1
        /* JMM - workaround rdar://problem/9121297 (CF being too picky on these bits). */
        *typep &= ~(MACH_PORT_TYPE_SPREQUEST | MACH_PORT_TYPE_SPREQUEST_DELAYED);
#endif

	return kr;
}

/*
 *	Routine:	mach_port_rename [kernel call]
 *	Purpose:
 *		Changes the name denoting a right,
 *		from oname to nname.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		The right is renamed.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	The oname doesn't denote a right.
 *		KERN_INVALID_VALUE	The nname isn't a legal name.
 *		KERN_NAME_EXISTS	The nname already denotes a right.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 *
 *      This interface is obsolete and always returns
 *      KERN_NOT_SUPPORTED.
 */

kern_return_t
mach_port_rename(
	__unused ipc_space_t		space,
	__unused mach_port_name_t	oname,
	__unused mach_port_name_t	nname)
{
	return KERN_NOT_SUPPORTED;
}


/*
 *	Routine:	mach_port_allocate_name [kernel call]
 *	Purpose:
 *		Allocates a right in a space, using a specific name
 *		for the new right.  Possible rights:
 *			MACH_PORT_RIGHT_RECEIVE
 *			MACH_PORT_RIGHT_PORT_SET
 *			MACH_PORT_RIGHT_DEAD_NAME
 *
 *		A new port (allocated with MACH_PORT_RIGHT_RECEIVE)
 *		has no extant send or send-once rights and no queued
 *		messages.  Its queue limit is MACH_PORT_QLIMIT_DEFAULT
 *		and its make-send count is 0.  It is not a member of
 *		a port set.  It has no registered no-senders or
 *		port-destroyed notification requests.
 *
 *		A new port set has no members.
 *
 *		A new dead name has one user reference.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		The right is allocated.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_VALUE	The name isn't a legal name.
 *		KERN_INVALID_VALUE	"right" isn't a legal kind of right.
 *		KERN_NAME_EXISTS	The name already denotes a right.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 *
 *	Restrictions on name allocation:  NT bits are reserved by kernel,
 *	must be set on any chosen name.  Can't do this at all in kernel
 *	loaded server.
 */

kern_return_t
mach_port_allocate_name(
	ipc_space_t		space,
	mach_port_right_t	right,
	mach_port_name_t	name)
{
	kern_return_t		kr;
	mach_port_qos_t		qos = qos_template;

	qos.name = TRUE;

	if (!MACH_PORT_VALID(name))
		return KERN_INVALID_VALUE;

	kr = mach_port_allocate_full (space, right, MACH_PORT_NULL,
					&qos, &name);
	return (kr);
}

/*
 *	Routine:	mach_port_allocate [kernel call]
 *	Purpose:
 *		Allocates a right in a space.  Like mach_port_allocate_name,
 *		except that the implementation picks a name for the right.
 *		The name may be any legal name in the space that doesn't
 *		currently denote a right.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		The right is allocated.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_VALUE	"right" isn't a legal kind of right.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 *		KERN_NO_SPACE		No room in space for another right.
 */

kern_return_t
mach_port_allocate(
	ipc_space_t		space,
	mach_port_right_t	right,
	mach_port_name_t	*namep)
{
	kern_return_t		kr;
	mach_port_qos_t		qos = qos_template;

	kr = mach_port_allocate_full (space, right, MACH_PORT_NULL,
					&qos, namep);
	return (kr);
}

/*
 *	Routine:	mach_port_allocate_qos [kernel call]
 *	Purpose:
 *		Allocates a right, with qos options, in a space.  Like 
 *		mach_port_allocate_name, except that the implementation 
 *		picks a name for the right. The name may be any legal name 
 *		in the space that doesn't currently denote a right.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		The right is allocated.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_VALUE	"right" isn't a legal kind of right.
 *		KERN_INVALID_ARGUMENT   The qos request was invalid.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 *		KERN_NO_SPACE		No room in space for another right.
 */

kern_return_t
mach_port_allocate_qos(
	ipc_space_t		space,
	mach_port_right_t	right,
	mach_port_qos_t		*qosp,
	mach_port_name_t	*namep)
{
	kern_return_t		kr;

	if (qosp->name)
		return KERN_INVALID_ARGUMENT;
	kr = mach_port_allocate_full (space, right, MACH_PORT_NULL,
					qosp, namep);
	return (kr);
}

/*
 *	Routine:	mach_port_allocate_full [kernel call]
 *	Purpose:
 *		Allocates a right in a space.  Supports all of the
 *		special cases, such as specifying a subsystem,
 *		a specific name, a real-time port, etc.
 *		The name may be any legal name in the space that doesn't
 *		currently denote a right.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		The right is allocated.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_VALUE	"right" isn't a legal kind of right.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 *		KERN_NO_SPACE		No room in space for another right.
 */

kern_return_t
mach_port_allocate_full(
	ipc_space_t		space,
	mach_port_right_t	right,
	mach_port_t		proto,
	mach_port_qos_t		*qosp,
	mach_port_name_t	*namep)
{
	ipc_kmsg_t		kmsg = IKM_NULL;
	kern_return_t		kr;

	if (space == IS_NULL)
		return (KERN_INVALID_TASK);

	if (proto != MACH_PORT_NULL)
		return (KERN_INVALID_VALUE);

	if (qosp->name) {
		if (!MACH_PORT_VALID (*namep))
			return (KERN_INVALID_VALUE);
	}

	if (qosp->prealloc) {
		if (qosp->len > MACH_MSG_SIZE_MAX - MAX_TRAILER_SIZE) {
			return KERN_RESOURCE_SHORTAGE;
		} else {
			mach_msg_size_t size = qosp->len + MAX_TRAILER_SIZE;

			if (right != MACH_PORT_RIGHT_RECEIVE) {
				return (KERN_INVALID_VALUE);
			}

			kmsg = (ipc_kmsg_t)ipc_kmsg_prealloc(size);
			if (kmsg == IKM_NULL) {
				return (KERN_RESOURCE_SHORTAGE);
			}
		}
	}

	switch (right) {
	    case MACH_PORT_RIGHT_RECEIVE:
	    {
		ipc_port_t	port;

		if (qosp->name)
			kr = ipc_port_alloc_name(space, *namep, &port);
		else
			kr = ipc_port_alloc(space, namep, &port);
		if (kr == KERN_SUCCESS) {
			if (kmsg != IKM_NULL) 
				ipc_kmsg_set_prealloc(kmsg, port);

			ip_unlock(port);

		} else if (kmsg != IKM_NULL)
			ipc_kmsg_free(kmsg);
		break;
	    }

	    case MACH_PORT_RIGHT_PORT_SET:
	    {
		ipc_pset_t	pset;

		if (qosp->name)
			kr = ipc_pset_alloc_name(space, *namep, &pset);
		else
			kr = ipc_pset_alloc(space, namep, &pset);
		if (kr == KERN_SUCCESS)
			ips_unlock(pset);
		break;
	    }

	    case MACH_PORT_RIGHT_DEAD_NAME:
		kr = ipc_object_alloc_dead(space, namep);
		break;

	    default:
		kr = KERN_INVALID_VALUE;
		break;
	}

	return (kr);
}

/*
 *	Routine:	mach_port_destroy [kernel call]
 *	Purpose:
 *		Cleans up and destroys all rights denoted by a name
 *		in a space.  The destruction of a receive right
 *		destroys the port, unless a port-destroyed request
 *		has been made for it; the destruction of a port-set right
 *		destroys the port set.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		The name is destroyed.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	The name doesn't denote a right.
 */

kern_return_t
mach_port_destroy(
	ipc_space_t		space,
	mach_port_name_t	name)
{
	ipc_entry_t entry;
	kern_return_t kr;

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	if (!MACH_PORT_VALID(name))
		return KERN_SUCCESS;

	kr = ipc_right_lookup_write(space, name, &entry);
	if (kr != KERN_SUCCESS) {
		mach_port_guard_exception(name, 0, 0, kGUARD_EXC_INVALID_NAME);
		return kr;
	}
	/* space is write-locked and active */

	kr = ipc_right_destroy(space, name, entry, TRUE, 0); /* unlocks space */
	return kr;
}

/*
 *	Routine:	mach_port_deallocate [kernel call]
 *	Purpose:
 *		Deallocates a user reference from a send right,
 *		send-once right, dead-name right or a port_set right.
 *		May deallocate the right, if this is the last uref,
 *		and destroy the name, if it doesn't denote
 *		other rights.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		The uref is deallocated.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	The name doesn't denote a right.
 *		KERN_INVALID_RIGHT	The right isn't correct.
 */

kern_return_t
mach_port_deallocate(
	ipc_space_t		space,
	mach_port_name_t	name)
{
	ipc_entry_t entry;
	kern_return_t kr;

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	if (!MACH_PORT_VALID(name))
		return KERN_SUCCESS;

	kr = ipc_right_lookup_write(space, name, &entry);
	if (kr != KERN_SUCCESS) {
		mach_port_guard_exception(name, 0, 0, kGUARD_EXC_INVALID_NAME);
		return kr;
	}
	/* space is write-locked */

	kr = ipc_right_dealloc(space, name, entry); /* unlocks space */
	return kr;
}

/*
 *	Routine:	mach_port_get_refs [kernel call]
 *	Purpose:
 *		Retrieves the number of user references held by a right.
 *		Receive rights, port-set rights, and send-once rights
 *		always have one user reference.  Returns zero if the
 *		name denotes a right, but not the queried right.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Number of urefs returned.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_VALUE	"right" isn't a legal value.
 *		KERN_INVALID_NAME	The name doesn't denote a right.
 */

kern_return_t
mach_port_get_refs(
	ipc_space_t		space,
	mach_port_name_t	name,
	mach_port_right_t	right,
	mach_port_urefs_t	*urefsp)
{
	mach_port_type_t type;
	mach_port_urefs_t urefs;
	ipc_entry_t entry;
	kern_return_t kr;

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	if (right >= MACH_PORT_RIGHT_NUMBER)
		return KERN_INVALID_VALUE;

	if (!MACH_PORT_VALID(name)) {
	  	if (right == MACH_PORT_RIGHT_SEND ||
		    right == MACH_PORT_RIGHT_SEND_ONCE) {
			*urefsp = 1;
			return KERN_SUCCESS;
		}
		return KERN_INVALID_NAME;
	}

	kr = ipc_right_lookup_write(space, name, &entry);
	if (kr != KERN_SUCCESS) {
		mach_port_guard_exception(name, 0, 0, kGUARD_EXC_INVALID_NAME);
		return kr;
	}

	/* space is write-locked and active */
	kr = ipc_right_info(space, name, entry, &type, &urefs);
	/* space is unlocked */

	if (kr != KERN_SUCCESS)
		return kr;	

	if (type & MACH_PORT_TYPE(right))
		switch (right) {
		    case MACH_PORT_RIGHT_SEND_ONCE:
			assert(urefs == 1);
			/* fall-through */

		    case MACH_PORT_RIGHT_PORT_SET:
		    case MACH_PORT_RIGHT_RECEIVE:
			*urefsp = 1;
			break;

		    case MACH_PORT_RIGHT_DEAD_NAME:
		    case MACH_PORT_RIGHT_SEND:
			assert(urefs > 0);
			*urefsp = urefs;
			break;

		    default:
			panic("mach_port_get_refs: strange rights");
		}
	else
		*urefsp = 0;

	return kr;
}

/*
 *	Routine:	mach_port_mod_refs
 *	Purpose:
 *		Modifies the number of user references held by a right.
 *		The resulting number of user references must be non-negative.
 *		If it is zero, the right is deallocated.  If the name
 *		doesn't denote other rights, it is destroyed.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Modified number of urefs.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_VALUE	"right" isn't a legal value.
 *		KERN_INVALID_NAME	The name doesn't denote a right.
 *		KERN_INVALID_RIGHT	Name doesn't denote specified right.
 *		KERN_INVALID_VALUE	Impossible modification to urefs.
 *		KERN_UREFS_OVERFLOW	Urefs would overflow.
 */

kern_return_t
mach_port_mod_refs(
	ipc_space_t		space,
	mach_port_name_t	name,
	mach_port_right_t	right,
	mach_port_delta_t	delta)
{
	ipc_entry_t entry;
	kern_return_t kr;

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	if (right >= MACH_PORT_RIGHT_NUMBER)
		return KERN_INVALID_VALUE;

	if (!MACH_PORT_VALID(name)) {
		if (right == MACH_PORT_RIGHT_SEND ||
		    right == MACH_PORT_RIGHT_SEND_ONCE)
			return KERN_SUCCESS;
		return KERN_INVALID_NAME;
	}

	kr = ipc_right_lookup_write(space, name, &entry);
	if (kr != KERN_SUCCESS) {
		mach_port_guard_exception(name, 0, 0, kGUARD_EXC_INVALID_NAME);
		return kr;
	}

	/* space is write-locked and active */

	kr = ipc_right_delta(space, name, entry, right, delta);	/* unlocks */
	return kr;
}


/*
 *	Routine:	mach_port_peek [kernel call]
 *	Purpose:
 *		Peek at the message queue for the specified receive
 *		right and return info about a message in the queue.
 *
 *		On input, seqnop points to a sequence number value
 *		to match the message being peeked. If zero is specified
 *		as the seqno, the first message in the queue will be
 *		peeked.
 *
 *		Only the following trailer types are currently supported:
 *			MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0)
 *
 *				or'ed with one of these element types:
 *			MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_NULL)
 *			MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_SEQNO)
 *			MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_SENDER)
 *			MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT)
 *
 *		On input, the value pointed to by trailer_sizep must be
 *		large enough to hold the requested trailer size.
 *
 *		The message sequence number, id, size, requested trailer info
 *		and requested trailer size are returned in their respective
 *		output parameters upon success.
 *
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Matching message found, out parameters set.
 *		KERN_INVALID_TASK	The space is null or dead.
 *		KERN_INVALID_NAME	The name doesn't denote a right.
 *		KERN_INVALID_RIGHT	Name doesn't denote receive rights.
 *		KERN_INVALID_VALUE	The input parameter values are out of bounds.
 *		KERN_FAILURE		The requested message was not found.
 */

kern_return_t
mach_port_peek(
	ipc_space_t			space,
	mach_port_name_t		name,
	mach_msg_trailer_type_t 	trailer_type,
	mach_port_seqno_t		*seqnop,
	mach_msg_size_t			*msg_sizep,
	mach_msg_id_t			*msg_idp,
	mach_msg_trailer_info_t 	trailer_infop,
	mach_msg_type_number_t		*trailer_sizep)
{
	ipc_port_t port;
	kern_return_t kr;
	boolean_t found;
	mach_msg_max_trailer_t max_trailer;

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	if (!MACH_PORT_VALID(name))
		return KERN_INVALID_RIGHT;

	/*
	 * We don't allow anything greater than the audit trailer - to avoid
	 * leaking the context pointer and to avoid variable-sized context issues.
	 */
	if (GET_RCV_ELEMENTS(trailer_type) > MACH_RCV_TRAILER_AUDIT ||
	    REQUESTED_TRAILER_SIZE(TRUE, trailer_type) > *trailer_sizep) {
		mach_port_guard_exception(name, 0, 0, kGUARD_EXC_INVALID_VALUE);
		return KERN_INVALID_VALUE;
	}

	*trailer_sizep = REQUESTED_TRAILER_SIZE(TRUE, trailer_type);

	kr = ipc_port_translate_receive(space, name, &port);
	if (kr != KERN_SUCCESS) {
		mach_port_guard_exception(name, 0, 0,
		                          ((KERN_INVALID_NAME == kr) ?
		                           kGUARD_EXC_INVALID_NAME :
		                           kGUARD_EXC_INVALID_RIGHT));
		return kr;
	}

	/* Port locked and active */

	found = ipc_mqueue_peek(&port->ip_messages, seqnop,
				msg_sizep, msg_idp, &max_trailer, NULL);
	ip_unlock(port);

	if (found != TRUE)
		return KERN_FAILURE;

	max_trailer.msgh_seqno = *seqnop;
	memcpy(trailer_infop, &max_trailer, *trailer_sizep);

	return KERN_SUCCESS;
}

/*
 *	Routine:	mach_port_set_mscount [kernel call]
 *	Purpose:
 *		Changes a receive right's make-send count.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Set make-send count.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	The name doesn't denote a right.
 *		KERN_INVALID_RIGHT	Name doesn't denote receive rights.
 */

kern_return_t
mach_port_set_mscount(
	ipc_space_t		space,
	mach_port_name_t	name,
	mach_port_mscount_t	mscount)
{
	ipc_port_t port;
	kern_return_t kr;

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	if (!MACH_PORT_VALID(name))
		return KERN_INVALID_RIGHT;

	kr = ipc_port_translate_receive(space, name, &port);
	if (kr != KERN_SUCCESS)
		return kr;
	/* port is locked and active */

	ipc_port_set_mscount(port, mscount);

	ip_unlock(port);
	return KERN_SUCCESS;
}

/*
 *	Routine:	mach_port_set_seqno [kernel call]
 *	Purpose:
 *		Changes a receive right's sequence number.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Set sequence number.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	The name doesn't denote a right.
 *		KERN_INVALID_RIGHT	Name doesn't denote receive rights.
 */

kern_return_t
mach_port_set_seqno(
	ipc_space_t		space,
	mach_port_name_t	name,
	mach_port_seqno_t	seqno)
{
	ipc_port_t port;
	kern_return_t kr;

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	if (!MACH_PORT_VALID(name))
		return KERN_INVALID_RIGHT;

	kr = ipc_port_translate_receive(space, name, &port);
	if (kr != KERN_SUCCESS)
		return kr;
	/* port is locked and active */

	ipc_mqueue_set_seqno(&port->ip_messages, seqno);

	ip_unlock(port);
	return KERN_SUCCESS;
}

/*
 *	Routine:	mach_port_get_context [kernel call]
 *	Purpose:
 *		Returns a receive right's context pointer.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Set context pointer.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	The name doesn't denote a right.
 *		KERN_INVALID_RIGHT	Name doesn't denote receive rights.
 */

kern_return_t
mach_port_get_context(
	ipc_space_t		space,
	mach_port_name_t	name,
	mach_vm_address_t	*context)
{
	ipc_port_t port;
	kern_return_t kr;

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	if (!MACH_PORT_VALID(name))
		return KERN_INVALID_RIGHT;

	kr = ipc_port_translate_receive(space, name, &port);
	if (kr != KERN_SUCCESS)
		return kr;

	/* Port locked and active */

	/* For strictly guarded ports, return empty context (which acts as guard) */
	if (port->ip_strict_guard)
		*context = 0;
	else
		*context = port->ip_context;

	ip_unlock(port);
	return KERN_SUCCESS;
}


/*
 *	Routine:	mach_port_set_context [kernel call]
 *	Purpose:
 *		Changes a receive right's context pointer.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Set context pointer.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	The name doesn't denote a right.
 *		KERN_INVALID_RIGHT	Name doesn't denote receive rights.
 */

kern_return_t
mach_port_set_context(
	ipc_space_t		space,
	mach_port_name_t	name,
	mach_vm_address_t	context)
{
	ipc_port_t port;
	kern_return_t kr;

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	if (!MACH_PORT_VALID(name))
		return KERN_INVALID_RIGHT;

	kr = ipc_port_translate_receive(space, name, &port);
	if (kr != KERN_SUCCESS)
		return kr;

	/* port is locked and active */
	if(port->ip_strict_guard) {
		uint64_t portguard = port->ip_context;
		ip_unlock(port);
		/* For strictly guarded ports, disallow overwriting context; Raise Exception */
		mach_port_guard_exception(name, context, portguard, kGUARD_EXC_SET_CONTEXT);
		return KERN_INVALID_ARGUMENT;
	}

	port->ip_context = context;

	ip_unlock(port);
	return KERN_SUCCESS;
}


/*
 *	Routine:	mach_port_get_set_status [kernel call]
 *	Purpose:
 *		Retrieves a list of members in a port set.
 *		Returns the space's name for each receive right member.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Retrieved list of members.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	The name doesn't denote a right.
 *		KERN_INVALID_RIGHT	Name doesn't denote a port set.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
mach_port_get_set_status(
	ipc_space_t			space,
	mach_port_name_t		name,
	mach_port_name_t		**members,
	mach_msg_type_number_t		*membersCnt)
{
	ipc_entry_num_t actual;		/* this many members */
	ipc_entry_num_t maxnames;	/* space for this many members */
	kern_return_t kr;

	vm_size_t size;		/* size of allocated memory */
	vm_offset_t addr;	/* allocated memory */
	vm_map_copy_t memory;	/* copied-in memory */

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	if (!MACH_PORT_VALID(name))
		return KERN_INVALID_RIGHT;

	size = VM_MAP_PAGE_SIZE(ipc_kernel_map);	/* initial guess */

	for (;;) {
		mach_port_name_t *names;
		ipc_object_t psobj;
		ipc_pset_t pset;

		kr = vm_allocate_kernel(ipc_kernel_map, &addr, size, VM_FLAGS_ANYWHERE, VM_KERN_MEMORY_IPC);
		if (kr != KERN_SUCCESS)
			return KERN_RESOURCE_SHORTAGE;

		/* can't fault while we hold locks */

		kr = vm_map_wire_kernel(ipc_kernel_map, addr, addr + size,
				     VM_PROT_READ|VM_PROT_WRITE, VM_KERN_MEMORY_IPC, FALSE);
		assert(kr == KERN_SUCCESS);

		kr = ipc_object_translate(space, name, MACH_PORT_RIGHT_PORT_SET, &psobj);
		if (kr != KERN_SUCCESS) {
			kmem_free(ipc_kernel_map, addr, size);
			return kr;
		}

		/* just use a portset reference from here on out */
		__IGNORE_WCASTALIGN(pset = (ipc_pset_t) psobj);
		ips_reference(pset);
		ips_unlock(pset); 

		names = (mach_port_name_t *) addr;
		maxnames = (ipc_entry_num_t)(size / sizeof(mach_port_name_t));

		ipc_mqueue_set_gather_member_names(space, &pset->ips_messages, maxnames, names, &actual);

		/* release the portset reference */
		ips_release(pset);

		if (actual <= maxnames)
			break;

		/* didn't have enough memory; allocate more */
		kmem_free(ipc_kernel_map, addr, size);
		size = vm_map_round_page(
			(actual * sizeof(mach_port_name_t)),
			 VM_MAP_PAGE_MASK(ipc_kernel_map)) +
			VM_MAP_PAGE_SIZE(ipc_kernel_map);
	}

	if (actual == 0) {
		memory = VM_MAP_COPY_NULL;

		kmem_free(ipc_kernel_map, addr, size);
	} else {
		vm_size_t size_used;
		vm_size_t vm_size_used;

		size_used = actual * sizeof(mach_port_name_t);
		vm_size_used = vm_map_round_page(
			size_used,
			VM_MAP_PAGE_MASK(ipc_kernel_map));

		/*
		 *	Make used memory pageable and get it into
		 *	copied-in form.  Free any unused memory.
		 */

		kr = vm_map_unwire(
			ipc_kernel_map,
			vm_map_trunc_page(addr,
					  VM_MAP_PAGE_MASK(ipc_kernel_map)), 
			vm_map_round_page(addr + vm_size_used,
					  VM_MAP_PAGE_MASK(ipc_kernel_map)),
			FALSE);
		assert(kr == KERN_SUCCESS);

		kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)addr,
				   (vm_map_size_t)size_used, TRUE, &memory);
		assert(kr == KERN_SUCCESS);

		if (vm_size_used != size)
			kmem_free(ipc_kernel_map,
				  addr + vm_size_used, size - vm_size_used);
	}

	*members = (mach_port_name_t *) memory;
	*membersCnt = actual;
	return KERN_SUCCESS;
}

/*
 *	Routine:	mach_port_move_member [kernel call]
 *	Purpose:
 *		If after is MACH_PORT_NULL, removes member
 *		from the port set it is in.  Otherwise, adds
 *		member to after, removing it from any set
 *		it might already be in.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Moved the port.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	Member didn't denote a right.
 *		KERN_INVALID_RIGHT	Member didn't denote a receive right.
 *		KERN_INVALID_NAME	After didn't denote a right.
 *		KERN_INVALID_RIGHT	After didn't denote a port set right.
 *		KERN_NOT_IN_SET
 *			After is MACH_PORT_NULL and Member isn't in a port set.
 */

kern_return_t
mach_port_move_member(
	ipc_space_t		space,
	mach_port_name_t	member,
	mach_port_name_t	after)
{
	ipc_entry_t entry;
	ipc_port_t port;
	ipc_pset_t nset;
	kern_return_t kr;
	uint64_t wq_link_id = 0;
	uint64_t wq_reserved_prepost = 0;

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	if (!MACH_PORT_VALID(member))
		return KERN_INVALID_RIGHT;

	if (after == MACH_PORT_DEAD) {
		return KERN_INVALID_RIGHT;
	} else if (after == MACH_PORT_NULL) {
		wq_link_id = 0;
	} else {
		/*
		 * We reserve both a link, and
		 * enough prepost objects to complete
		 * the set move atomically - we can't block
		 * while we're holding the space lock, and
		 * the ipc_pset_add calls ipc_mqueue_add
		 * which may have to prepost this port onto
		 * this set.
		 */
		wq_link_id = waitq_link_reserve(NULL);
		wq_reserved_prepost = waitq_prepost_reserve(NULL, 10,
		                                            WAITQ_DONT_LOCK);
		kr = ipc_pset_lazy_allocate(space, after);
		if (kr != KERN_SUCCESS)
			goto done;
	}

	kr = ipc_right_lookup_read(space, member, &entry);
	if (kr != KERN_SUCCESS)
		goto done;
	/* space is read-locked and active */

	if ((entry->ie_bits & MACH_PORT_TYPE_RECEIVE) == 0) {
		is_read_unlock(space);
		kr = KERN_INVALID_RIGHT;
		goto done;
	}

	__IGNORE_WCASTALIGN(port = (ipc_port_t) entry->ie_object);
	assert(port != IP_NULL);

	if (after == MACH_PORT_NULL)
		nset = IPS_NULL;
	else {
		entry = ipc_entry_lookup(space, after);
		if (entry == IE_NULL) {
			is_read_unlock(space);
			kr = KERN_INVALID_NAME;
			goto done;
		}

		if ((entry->ie_bits & MACH_PORT_TYPE_PORT_SET) == 0) {
			is_read_unlock(space);
			kr = KERN_INVALID_RIGHT;
			goto done;
		}

		__IGNORE_WCASTALIGN(nset = (ipc_pset_t) entry->ie_object);
		assert(nset != IPS_NULL);
	}
	ip_lock(port);
	assert(ip_active(port));
	ipc_pset_remove_from_all(port);

	if (nset != IPS_NULL) {
		ips_lock(nset);
		kr = ipc_pset_add(nset, port, &wq_link_id, &wq_reserved_prepost);
		ips_unlock(nset);
	}
	ip_unlock(port);
	is_read_unlock(space);

 done:

	/*
	 * on success the ipc_pset_add() will consume the wq_link_id
	 * value (resetting it to 0), so this function is always safe to call.
	 */
	waitq_link_release(wq_link_id);
	waitq_prepost_release_reserve(wq_reserved_prepost);

	return kr;
}

/*
 *	Routine:	mach_port_request_notification [kernel call]
 *	Purpose:
 *		Requests a notification.  The caller supplies
 *		a send-once right for the notification to use,
 *		and the call returns the previously registered
 *		send-once right, if any.  Possible types:
 *
 *		MACH_NOTIFY_PORT_DESTROYED
 *			Requests a port-destroyed notification
 *			for a receive right.  Sync should be zero.
 *		MACH_NOTIFY_NO_SENDERS
 *			Requests a no-senders notification for a
 *			receive right.  If there are currently no
 *			senders, sync is less than or equal to the
 *			current make-send count, and a send-once right
 *			is supplied, then an immediate no-senders
 *			notification is generated.
 *		MACH_NOTIFY_DEAD_NAME
 *			Requests a dead-name notification for a send
 *			or receive right.  If the name is already a
 *			dead name, sync is non-zero, and a send-once
 *			right is supplied, then an immediate dead-name
 *			notification is generated.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Requested a notification.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_VALUE	Bad id value.
 *		KERN_INVALID_NAME	Name doesn't denote a right.
 *		KERN_INVALID_RIGHT	Name doesn't denote appropriate right.
 *		KERN_INVALID_CAPABILITY	The notify port is dead.
 *	MACH_NOTIFY_PORT_DESTROYED:
 *		KERN_INVALID_VALUE	Sync isn't zero.
 *	MACH_NOTIFY_DEAD_NAME:
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 *		KERN_INVALID_ARGUMENT	Name denotes dead name, but
 *			sync is zero or notify is IP_NULL.
 *		KERN_UREFS_OVERFLOW	Name denotes dead name, but
 *			generating immediate notif. would overflow urefs.
 */

kern_return_t
mach_port_request_notification(
	ipc_space_t		space,
	mach_port_name_t	name,
	mach_msg_id_t		id,
	mach_port_mscount_t	sync,
	ipc_port_t		notify,
	ipc_port_t		*previousp)
{
	kern_return_t kr;

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	if (notify == IP_DEAD)
		return KERN_INVALID_CAPABILITY;

#if	NOTYET
	/*
	 *	Requesting notifications on RPC ports is an error.
	 */
	{
		ipc_port_t port;
		ipc_entry_t entry;	

		kr = ipc_right_lookup_write(space, name, &entry);	
		if (kr != KERN_SUCCESS)
			return kr;

		port = (ipc_port_t) entry->ie_object;

		if (port->ip_subsystem != NULL) {
			is_write_unlock(space);
			panic("mach_port_request_notification: on RPC port!!"); 
			return KERN_INVALID_CAPABILITY;
		}
		is_write_unlock(space);
	}
#endif 	/* NOTYET */


	switch (id) {
	    case MACH_NOTIFY_PORT_DESTROYED: {
		ipc_port_t port, previous;

		if (sync != 0)
			return KERN_INVALID_VALUE;

		if (!MACH_PORT_VALID(name))
			return KERN_INVALID_RIGHT;

		kr = ipc_port_translate_receive(space, name, &port);
		if (kr != KERN_SUCCESS)
			return kr;
		/* port is locked and active */

		/* you cannot register for port death notifications on a kobject */
		if (ip_kotype(port) != IKOT_NONE) {
			ip_unlock(port);
			return KERN_INVALID_RIGHT;
		}

		ipc_port_pdrequest(port, notify, &previous);
		/* port is unlocked */

		*previousp = previous;
		break;
	    }

	    case MACH_NOTIFY_NO_SENDERS: {
		ipc_port_t port;

		if (!MACH_PORT_VALID(name))
			return KERN_INVALID_RIGHT;

		kr = ipc_port_translate_receive(space, name, &port);
		if (kr != KERN_SUCCESS)
			return kr;
		/* port is locked and active */

		ipc_port_nsrequest(port, sync, notify, previousp);
		/* port is unlocked */
		break;
	    }

	    case MACH_NOTIFY_SEND_POSSIBLE:

	    	if (!MACH_PORT_VALID(name)) {
	      		return KERN_INVALID_ARGUMENT;
		}

		kr = ipc_right_request_alloc(space, name, sync != 0,
					     TRUE, notify, previousp);
		if (kr != KERN_SUCCESS)
			return kr;
		break;

	    case MACH_NOTIFY_DEAD_NAME:

	    	if (!MACH_PORT_VALID(name)) {
			/*
			 * Already dead.
			 * Should do immediate delivery check -
			 * will do that in the near future.
			 */
	      		return KERN_INVALID_ARGUMENT;
		}

		kr = ipc_right_request_alloc(space, name, sync != 0,
					     FALSE, notify, previousp);
		if (kr != KERN_SUCCESS)
			return kr;
		break;

	    default:
		return KERN_INVALID_VALUE;
	}

	return KERN_SUCCESS;
}

/*
 *	Routine:	mach_port_insert_right [kernel call]
 *	Purpose:
 *		Inserts a right into a space, as if the space
 *		voluntarily received the right in a message,
 *		except that the right gets the specified name.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Inserted the right.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_VALUE	The name isn't a legal name.
 *		KERN_NAME_EXISTS	The name already denotes a right.
 *		KERN_INVALID_VALUE	Message doesn't carry a port right.
 *		KERN_INVALID_CAPABILITY	Port is null or dead.
 *		KERN_UREFS_OVERFLOW	Urefs limit would be exceeded.
 *		KERN_RIGHT_EXISTS	Space has rights under another name.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
mach_port_insert_right(
	ipc_space_t			space,
	mach_port_name_t		name,
	ipc_port_t			poly,
	mach_msg_type_name_t		polyPoly)
{
	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	if (!MACH_PORT_VALID(name) ||
	    !MACH_MSG_TYPE_PORT_ANY_RIGHT(polyPoly))
		return KERN_INVALID_VALUE;

	if (!IO_VALID((ipc_object_t) poly))
		return KERN_INVALID_CAPABILITY;

	return ipc_object_copyout_name(space, (ipc_object_t) poly, 
				       polyPoly, FALSE, name);
}

/*
 *	Routine:	mach_port_extract_right [kernel call]
 *	Purpose:
 *		Extracts a right from a space, as if the space
 *		voluntarily sent the right to the caller.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Extracted the right.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_VALUE	Requested type isn't a port right.
 *		KERN_INVALID_NAME	Name doesn't denote a right.
 *		KERN_INVALID_RIGHT	Name doesn't denote appropriate right.
 */

kern_return_t
mach_port_extract_right(
	ipc_space_t		space,
	mach_port_name_t	name,
	mach_msg_type_name_t	msgt_name,
	ipc_port_t		*poly,
	mach_msg_type_name_t	*polyPoly)
{
	kern_return_t kr;

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	if (!MACH_MSG_TYPE_PORT_ANY(msgt_name))
		return KERN_INVALID_VALUE;

	if (!MACH_PORT_VALID(name)) {
		/*
		 * really should copy out a dead name, if it is a send or
		 * send-once right being copied, but instead return an
		 * error for now.
		 */
		return KERN_INVALID_RIGHT;
	}

	kr = ipc_object_copyin(space, name, msgt_name, (ipc_object_t *) poly);

	if (kr == KERN_SUCCESS)
		*polyPoly = ipc_object_copyin_type(msgt_name);
	return kr;
}

/*
 *	Routine:	mach_port_get_status_helper [helper]
 *	Purpose:
 *		Populates a mach_port_status_t structure with
 *		port information.
 *	Conditions:
 *		Port needs to be locked
 *	Returns:
 *		None.
 */
void mach_port_get_status_helper(
	ipc_port_t		port,
	mach_port_status_t	*statusp)
{
	imq_lock(&port->ip_messages);
	/* don't leak set IDs, just indicate that the port is in one or not */
	statusp->mps_pset = !!(port->ip_in_pset);
	statusp->mps_seqno = port->ip_messages.imq_seqno;
	statusp->mps_qlimit = port->ip_messages.imq_qlimit;
	statusp->mps_msgcount = port->ip_messages.imq_msgcount;
	imq_unlock(&port->ip_messages);

	statusp->mps_mscount = port->ip_mscount;
	statusp->mps_sorights = port->ip_sorights;
	statusp->mps_srights = port->ip_srights > 0;
	statusp->mps_pdrequest = port->ip_pdrequest != IP_NULL;
	statusp->mps_nsrequest = port->ip_nsrequest != IP_NULL;
	statusp->mps_flags = 0;
	if (port->ip_impdonation) {
		statusp->mps_flags |= MACH_PORT_STATUS_FLAG_IMP_DONATION;
		if (port->ip_tempowner) {
			statusp->mps_flags |= MACH_PORT_STATUS_FLAG_TEMPOWNER;
			if (IIT_NULL != port->ip_imp_task) {
				statusp->mps_flags |= MACH_PORT_STATUS_FLAG_TASKPTR;
			}
		}
	}
	if (port->ip_guarded) {
		statusp->mps_flags |= MACH_PORT_STATUS_FLAG_GUARDED;
		if (port->ip_strict_guard) {
			statusp->mps_flags |= MACH_PORT_STATUS_FLAG_STRICT_GUARD;
		}
	}
	return;
}



kern_return_t
mach_port_get_attributes(
	ipc_space_t		space,
	mach_port_name_t	name,
	int			flavor,
        mach_port_info_t	info,
        mach_msg_type_number_t	*count)
{
	ipc_port_t port;
	kern_return_t kr;

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

        switch (flavor) {
        case MACH_PORT_LIMITS_INFO: {
                mach_port_limits_t *lp = (mach_port_limits_t *)info;

                if (*count < MACH_PORT_LIMITS_INFO_COUNT)
                        return KERN_FAILURE;

                if (!MACH_PORT_VALID(name)) {
			*count = 0;
			break;
		}
			
                kr = ipc_port_translate_receive(space, name, &port);
                if (kr != KERN_SUCCESS)
                        return kr;
                /* port is locked and active */

                lp->mpl_qlimit = port->ip_messages.imq_qlimit;
                *count = MACH_PORT_LIMITS_INFO_COUNT;
                ip_unlock(port);
                break;
        }

        case MACH_PORT_RECEIVE_STATUS: {
		mach_port_status_t *statusp = (mach_port_status_t *)info;
		
		if (*count < MACH_PORT_RECEIVE_STATUS_COUNT)
			return KERN_FAILURE;

		if (!MACH_PORT_VALID(name))
			return KERN_INVALID_RIGHT;

		kr = ipc_port_translate_receive(space, name, &port);
		if (kr != KERN_SUCCESS)
			return kr;
		/* port is locked and active */
		mach_port_get_status_helper(port, statusp);
		*count = MACH_PORT_RECEIVE_STATUS_COUNT;
		ip_unlock(port);
		break;
	}
	
	case MACH_PORT_DNREQUESTS_SIZE: {
		ipc_port_request_t	table;
		
                if (*count < MACH_PORT_DNREQUESTS_SIZE_COUNT)
                        return KERN_FAILURE;

		if (!MACH_PORT_VALID(name)) {
			*(int *)info = 0;
			break;
		}

                kr = ipc_port_translate_receive(space, name, &port);
                if (kr != KERN_SUCCESS)
                        return kr;
                /* port is locked and active */
		
		table = port->ip_requests;
		if (table == IPR_NULL)
			*(int *)info = 0;
		else
			*(int *)info = table->ipr_size->its_size;
                *count = MACH_PORT_DNREQUESTS_SIZE_COUNT;
                ip_unlock(port);
		break;
	}

	case MACH_PORT_INFO_EXT: {
		mach_port_info_ext_t *mp_info = (mach_port_info_ext_t *)info;
		if (*count < MACH_PORT_INFO_EXT_COUNT)
			return KERN_FAILURE;
			
		if (!MACH_PORT_VALID(name))
			return KERN_INVALID_RIGHT;
		
		kr = ipc_port_translate_receive(space, name, &port);
		if (kr != KERN_SUCCESS)
			return kr;
		/* port is locked and active */
		mach_port_get_status_helper(port, &mp_info->mpie_status);
		mp_info->mpie_boost_cnt = port->ip_impcount;
		*count = MACH_PORT_INFO_EXT_COUNT;
		ip_unlock(port);
		break;
	}

        default:
		return KERN_INVALID_ARGUMENT;
                /*NOTREACHED*/
        }                

	return KERN_SUCCESS;
}

kern_return_t
mach_port_set_attributes(
	ipc_space_t		space,
	mach_port_name_t	name,
	int			flavor,
        mach_port_info_t	info,
        mach_msg_type_number_t	count)
{
	ipc_port_t port;
	kern_return_t kr;
        
	if (space == IS_NULL)
		return KERN_INVALID_TASK;

        switch (flavor) {
                
        case MACH_PORT_LIMITS_INFO: {
                mach_port_limits_t *mplp = (mach_port_limits_t *)info;
                
                if (count < MACH_PORT_LIMITS_INFO_COUNT)
                        return KERN_FAILURE;
                
                if (mplp->mpl_qlimit > MACH_PORT_QLIMIT_MAX)
                        return KERN_INVALID_VALUE;

		if (!MACH_PORT_VALID(name))
			return KERN_INVALID_RIGHT;

                kr = ipc_port_translate_receive(space, name, &port);
                if (kr != KERN_SUCCESS)
                        return kr;
                /* port is locked and active */

                ipc_mqueue_set_qlimit(&port->ip_messages, mplp->mpl_qlimit);
                ip_unlock(port);
                break;
        }
	case MACH_PORT_DNREQUESTS_SIZE: {
                if (count < MACH_PORT_DNREQUESTS_SIZE_COUNT)
                        return KERN_FAILURE;

		if (!MACH_PORT_VALID(name))
			return KERN_INVALID_RIGHT;
                
                kr = ipc_port_translate_receive(space, name, &port);
                if (kr != KERN_SUCCESS)
                        return kr;
                /* port is locked and active */
		
		kr = ipc_port_request_grow(port, *(int *)info);
		if (kr != KERN_SUCCESS)
			return kr;
		break;
	}
	case MACH_PORT_TEMPOWNER:
		if (!MACH_PORT_VALID(name))
			return KERN_INVALID_RIGHT;

		ipc_importance_task_t release_imp_task = IIT_NULL;
		natural_t assertcnt = 0;

		kr = ipc_port_translate_receive(space, name, &port);
		if (kr != KERN_SUCCESS)
			return kr;
		/* port is locked and active */

		/* 
		 * don't allow temp-owner importance donation if user
		 * associated it with a kobject already (timer, host_notify target),
		 * or is a special reply port.
		 */
		if (is_ipc_kobject(ip_kotype(port)) || port->ip_specialreply) {
			ip_unlock(port);
			return KERN_INVALID_ARGUMENT;
		}

		if (port->ip_tempowner != 0) {
			if (IIT_NULL != port->ip_imp_task) {
				release_imp_task = port->ip_imp_task;
				port->ip_imp_task = IIT_NULL;
				assertcnt = port->ip_impcount;
			}
		} else {
			assertcnt = port->ip_impcount;
		}

		port->ip_impdonation = 1;
		port->ip_tempowner = 1;
		ip_unlock(port);

#if IMPORTANCE_INHERITANCE
		/* drop assertions from previous destination task */
		if (release_imp_task != IIT_NULL) {
			assert(ipc_importance_task_is_any_receiver_type(release_imp_task));
			if (assertcnt > 0)
				ipc_importance_task_drop_internal_assertion(release_imp_task, assertcnt);
			ipc_importance_task_release(release_imp_task);
		} else if (assertcnt > 0) {
			release_imp_task = current_task()->task_imp_base;
			if (release_imp_task != IIT_NULL &&
			    ipc_importance_task_is_any_receiver_type(release_imp_task)) {
				ipc_importance_task_drop_internal_assertion(release_imp_task, assertcnt);
			}
		}
#else
		if (release_imp_task != IIT_NULL)
			ipc_importance_task_release(release_imp_task);
#endif /* IMPORTANCE_INHERITANCE */

		break;

#if IMPORTANCE_INHERITANCE
	case MACH_PORT_DENAP_RECEIVER:
	case MACH_PORT_IMPORTANCE_RECEIVER:
		if (!MACH_PORT_VALID(name))
			return KERN_INVALID_RIGHT;

		kr = ipc_port_translate_receive(space, name, &port);
		if (kr != KERN_SUCCESS)
			return kr;

		/* 
		 * don't allow importance donation if user associated
		 * it with a kobject already (timer, host_notify target),
		 * or is a special reply port.
		 */
		if (is_ipc_kobject(ip_kotype(port)) || port->ip_specialreply) {
			ip_unlock(port);
			return KERN_INVALID_ARGUMENT;
		}

		/* port is locked and active */
		port->ip_impdonation = 1;
		ip_unlock(port);

		break;
#endif /* IMPORTANCE_INHERITANCE */

        default:
		return KERN_INVALID_ARGUMENT;
                /*NOTREACHED*/
        }
	return KERN_SUCCESS;
}

/*
 *	Routine:	mach_port_insert_member [kernel call]
 *	Purpose:
 *		Add the receive right, specified by name, to
 *		a portset.
 *		The port cannot already be a member of the set.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Moved the port.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	name didn't denote a right.
 *		KERN_INVALID_RIGHT	name didn't denote a receive right.
 *		KERN_INVALID_NAME	pset_name didn't denote a right.
 *		KERN_INVALID_RIGHT	pset_name didn't denote a portset right.
 *		KERN_ALREADY_IN_SET	name was already a member of pset.
 */

kern_return_t
mach_port_insert_member(
	ipc_space_t		space,
	mach_port_name_t	name,
	mach_port_name_t	psname)
{
	ipc_object_t obj;
	ipc_object_t psobj;
	kern_return_t kr;
	uint64_t wq_link_id;
	uint64_t wq_reserved_prepost;

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	if (!MACH_PORT_VALID(name) || !MACH_PORT_VALID(psname))
		return KERN_INVALID_RIGHT;

	wq_link_id = waitq_link_reserve(NULL);
	wq_reserved_prepost = waitq_prepost_reserve(NULL, 10,
						    WAITQ_DONT_LOCK);
	kr = ipc_pset_lazy_allocate(space, psname);
	if (kr != KERN_SUCCESS)
		goto done;


	kr = ipc_object_translate_two(space, 
				      name, MACH_PORT_RIGHT_RECEIVE, &obj,
				      psname, MACH_PORT_RIGHT_PORT_SET, &psobj);
	if (kr != KERN_SUCCESS)
		goto done;

	/* obj and psobj are locked (and were locked in that order) */
	assert(psobj != IO_NULL);
	assert(obj != IO_NULL);

	__IGNORE_WCASTALIGN(kr = ipc_pset_add((ipc_pset_t)psobj, (ipc_port_t)obj,
					    &wq_link_id, &wq_reserved_prepost));

	io_unlock(psobj);
	io_unlock(obj);

 done:
	/* on success, wq_link_id is reset to 0, so this is always safe */
	waitq_link_release(wq_link_id);
	waitq_prepost_release_reserve(wq_reserved_prepost);

	return kr;
}

/*
 *	Routine:	mach_port_extract_member [kernel call]
 *	Purpose:
 *		Remove a port from one portset that it is a member of.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Moved the port.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	Member didn't denote a right.
 *		KERN_INVALID_RIGHT	Member didn't denote a receive right.
 *		KERN_INVALID_NAME	After didn't denote a right.
 *		KERN_INVALID_RIGHT	After didn't denote a port set right.
 *		KERN_NOT_IN_SET
 *			After is MACH_PORT_NULL and Member isn't in a port set.
 */

kern_return_t
mach_port_extract_member(
	ipc_space_t		space,
	mach_port_name_t	name,
	mach_port_name_t	psname)
{
	ipc_object_t psobj;
	ipc_object_t obj;
	kern_return_t kr;

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	if (!MACH_PORT_VALID(name) || !MACH_PORT_VALID(psname))
		return KERN_INVALID_RIGHT;

	kr = ipc_object_translate_two(space, 
				      name, MACH_PORT_RIGHT_RECEIVE, &obj,
				      psname, MACH_PORT_RIGHT_PORT_SET, &psobj);
	if (kr != KERN_SUCCESS)
		return kr;

	/* obj and psobj are both locked (and were locked in that order) */
	assert(psobj != IO_NULL);
	assert(obj != IO_NULL);

	__IGNORE_WCASTALIGN(kr = ipc_pset_remove((ipc_pset_t)psobj, (ipc_port_t)obj));

	io_unlock(psobj);
	io_unlock(obj);

	return kr;
}

/*
 *	task_set_port_space:
 *
 *	Set port name space of task to specified size.
 */
kern_return_t
task_set_port_space(
 	ipc_space_t	space,
 	int		table_entries)
{
	kern_return_t kr;
	
	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	is_write_lock(space);

	if (!is_active(space)) {
		is_write_unlock(space);
		return KERN_INVALID_TASK;
	}

	kr = ipc_entry_grow_table(space, table_entries);
	if (kr == KERN_SUCCESS)
		is_write_unlock(space);
	return kr;
}

/*
 *	Routine:	mach_port_guard_locked [helper routine]
 *	Purpose:
 *		Sets a new guard for a locked port.
 *	Conditions:
 *		Port Locked.
 *	Returns:
 *		KERN_SUCCESS		Port Guarded.
 *		KERN_INVALID_ARGUMENT	Port already contains a context/guard.
 */
static kern_return_t
mach_port_guard_locked(
	ipc_port_t		port,
	uint64_t		guard,
	boolean_t		strict)
{
	if (port->ip_context)
		return KERN_INVALID_ARGUMENT;

	port->ip_context = guard;
	port->ip_guarded = 1;
	port->ip_strict_guard = (strict)?1:0;
	return KERN_SUCCESS;
}

/*
 *	Routine:	mach_port_unguard_locked [helper routine]
 *	Purpose:
 *		Removes guard for a locked port.
 *	Conditions:
 *		Port Locked.
 *	Returns:
 *		KERN_SUCCESS		Port Unguarded.
 *		KERN_INVALID_ARGUMENT	Port is either unguarded already or guard mismatch.
 *					This also raises a EXC_GUARD exception.
 */
static kern_return_t
mach_port_unguard_locked(
	ipc_port_t		port,
	mach_port_name_t	name,
	uint64_t		guard)
{
	/* Port locked and active */
	if (!port->ip_guarded) {
		/* Port already unguarded; Raise exception */
		mach_port_guard_exception(name, guard, 0, kGUARD_EXC_UNGUARDED);
		return KERN_INVALID_ARGUMENT;
	}

	if (port->ip_context != guard) {
		/* Incorrect guard; Raise exception */
		mach_port_guard_exception(name, guard, port->ip_context, kGUARD_EXC_INCORRECT_GUARD);
		return KERN_INVALID_ARGUMENT;
	}

	port->ip_context = 0;
	port->ip_guarded = port->ip_strict_guard = 0;
	return KERN_SUCCESS;
}


/*
 *	Routine:	mach_port_guard_exception [helper routine]
 *	Purpose:
 *		Marks the thread with AST_GUARD for mach port guard violation.
 *		Also saves exception info in thread structure.
 *	Conditions:
 *		None.
 *	Returns:
 *		KERN_FAILURE		Thread marked with AST_GUARD.
 */
void
mach_port_guard_exception(
	mach_port_name_t 	name,
	__unused uint64_t 	inguard,
	uint64_t 			portguard,
	unsigned 			reason)
{
	mach_exception_code_t code = 0;
	EXC_GUARD_ENCODE_TYPE(code, GUARD_TYPE_MACH_PORT);
	EXC_GUARD_ENCODE_FLAVOR(code, reason);
	EXC_GUARD_ENCODE_TARGET(code, name);
	mach_exception_subcode_t subcode = (uint64_t)portguard;
	thread_t t = current_thread();
	thread_guard_violation(t, code, subcode);
}


/*
 *	Routine:	mach_port_guard_ast
 *	Purpose:
 *		Raises an exception for mach port guard violation.
 *	Conditions:
 *		None.
 *	Returns:
 *		None.
 */

void
mach_port_guard_ast(thread_t t,
	mach_exception_data_type_t code, mach_exception_data_type_t subcode)
{
	unsigned int reason = EXC_GUARD_DECODE_GUARD_FLAVOR(code);
	task_t task = t->task;
	unsigned int behavior = task->task_exc_guard;
	assert(task == current_task());
	assert(task != kernel_task);

	switch (reason) {
		/*
		 * Fatal Mach port guards - always delivered synchronously
		 */
	case kGUARD_EXC_DESTROY:
	case kGUARD_EXC_MOD_REFS:
	case kGUARD_EXC_SET_CONTEXT:
	case kGUARD_EXC_UNGUARDED:
	case kGUARD_EXC_INCORRECT_GUARD:
		task_exception_notify(EXC_GUARD, code, subcode);
		task_bsdtask_kill(task);
		break;

	default:
		/*
		 * Mach port guards controlled by task settings.
		 */

		/* Is delivery enabled */
		if ((behavior & TASK_EXC_GUARD_MP_DELIVER) == 0) {
			return;
		}

		/* If only once, make sure we're that once */
		while (behavior & TASK_EXC_GUARD_MP_ONCE) {
			uint32_t new_behavior = behavior & ~TASK_EXC_GUARD_MP_DELIVER;

			if (OSCompareAndSwap(behavior, new_behavior, &task->task_exc_guard)) {
				break;
			}
			behavior = task->task_exc_guard;
			if ((behavior & TASK_EXC_GUARD_MP_DELIVER) == 0) {
				return;
			}
		}

		/* Raise exception via corpse fork or synchronously */
		if ((task->task_exc_guard & TASK_EXC_GUARD_MP_CORPSE) &&
		    (task->task_exc_guard & TASK_EXC_GUARD_MP_FATAL) == 0) {
			task_violated_guard(code, subcode, NULL);
		} else {
			task_exception_notify(EXC_GUARD, code, subcode);
		}

		/* Terminate the task if desired */
		if (task->task_exc_guard & TASK_EXC_GUARD_MP_FATAL) {
			task_bsdtask_kill(task);
		}
		break;
	}
}

/*
 *	Routine:	mach_port_construct [kernel call]
 *	Purpose:
 *		Constructs a mach port with the provided set of options.
 *	Conditions:
 *		None.
 *	Returns:
 *		KERN_SUCCESS		The right is allocated.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 *		KERN_NO_SPACE		No room in space for another right.
 *		KERN_FAILURE		Illegal option values requested.
 */

kern_return_t
mach_port_construct(
	ipc_space_t		space,
	mach_port_options_t	*options,
	uint64_t		context,
	mach_port_name_t	*name)
{
	kern_return_t		kr;
	ipc_port_t		port;

	if (space == IS_NULL)
		return (KERN_INVALID_TASK);

	/* Allocate a new port in the IPC space */
	kr = ipc_port_alloc(space, name, &port);
	if (kr != KERN_SUCCESS)
		return kr;
	
	/* Port locked and active */
	if (options->flags & MPO_CONTEXT_AS_GUARD) {
		kr = mach_port_guard_locked(port, (uint64_t) context, (options->flags & MPO_STRICT));
		/* A newly allocated and locked port should always be guarded successfully */
		assert(kr == KERN_SUCCESS);
	} else {
		port->ip_context = context;
	}
	
	/* Unlock port */
	ip_unlock(port);

	/* Set port attributes as requested */

	if (options->flags & MPO_QLIMIT) {
		kr = mach_port_set_attributes(space, *name, MACH_PORT_LIMITS_INFO,
					      (mach_port_info_t)&options->mpl, sizeof(options->mpl)/sizeof(int));
		if (kr != KERN_SUCCESS)
			goto cleanup;	
	}

	if (options->flags & MPO_TEMPOWNER) {
		kr = mach_port_set_attributes(space, *name, MACH_PORT_TEMPOWNER, NULL, 0);
		if (kr != KERN_SUCCESS)
			goto cleanup;
	}

	if (options->flags & MPO_IMPORTANCE_RECEIVER) {
		kr = mach_port_set_attributes(space, *name, MACH_PORT_IMPORTANCE_RECEIVER, NULL, 0);
		if (kr != KERN_SUCCESS)
			goto cleanup;
	}

	if (options->flags & MPO_DENAP_RECEIVER) {
		kr = mach_port_set_attributes(space, *name, MACH_PORT_DENAP_RECEIVER, NULL, 0);
		if (kr != KERN_SUCCESS)
			goto cleanup;
	}

	if (options->flags & MPO_INSERT_SEND_RIGHT) {
		kr = ipc_object_copyin(space, *name, MACH_MSG_TYPE_MAKE_SEND, (ipc_object_t *)&port);
		if (kr != KERN_SUCCESS)
			goto cleanup;

		kr = mach_port_insert_right(space, *name, port, MACH_MSG_TYPE_PORT_SEND);
		if (kr != KERN_SUCCESS)
			goto cleanup;
	}

	return KERN_SUCCESS;

cleanup:
	/* Attempt to destroy port. If its already destroyed by some other thread, we're done */
	(void) mach_port_destruct(space, *name, 0, context);
	return kr;
}

/*
 *	Routine:	mach_port_destruct [kernel call]
 *	Purpose:
 *		Destroys a mach port with appropriate guard
 *	Conditions:
 *		None.
 *	Returns:
 *		KERN_SUCCESS		The name is destroyed.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	The name doesn't denote a right.
 *		KERN_INVALID_RIGHT	The right isn't correct.
 *		KERN_INVALID_VALUE	The delta for send right is incorrect.
 *		KERN_INVALID_ARGUMENT	Port is either unguarded already or guard mismatch.
 *					This also raises a EXC_GUARD exception.
 */

kern_return_t
mach_port_destruct(
	ipc_space_t		space,
	mach_port_name_t	name,
	mach_port_delta_t	srdelta,
	uint64_t		guard)
{
	kern_return_t		kr;
	ipc_entry_t		entry;

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	if (!MACH_PORT_VALID(name))
		return KERN_INVALID_NAME;

	/* Remove reference for receive right */
	kr = ipc_right_lookup_write(space, name, &entry);
	if (kr != KERN_SUCCESS) {
		mach_port_guard_exception(name, 0, 0, kGUARD_EXC_INVALID_NAME);
		return kr;
	}
	/* space is write-locked and active */
	kr = ipc_right_destruct(space, name, entry, srdelta, guard);	/* unlocks */

	return kr;
}

/*
 *	Routine:	mach_port_guard [kernel call]
 *	Purpose:
 *		Guard a mach port with specified guard value.
 *		The context field of the port is used as the guard.
 *	Conditions:
 *		None.
 *	Returns:
 *		KERN_SUCCESS		The name is destroyed.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	The name doesn't denote a right.
 *		KERN_INVALID_RIGHT	The right isn't correct.
 *		KERN_INVALID_ARGUMENT	Port already contains a context/guard.
 */
kern_return_t
mach_port_guard(
	ipc_space_t		space,
	mach_port_name_t	name,
	uint64_t		guard,
	boolean_t		strict)
{
	kern_return_t		kr;
	ipc_port_t		port;

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	if (!MACH_PORT_VALID(name))
		return KERN_INVALID_NAME;

	/* Guard can be applied only to receive rights */
	kr = ipc_port_translate_receive(space, name, &port);
	if (kr != KERN_SUCCESS) {
		mach_port_guard_exception(name, 0, 0,
		                          ((KERN_INVALID_NAME == kr) ?
		                           kGUARD_EXC_INVALID_NAME :
		                           kGUARD_EXC_INVALID_RIGHT));
		return kr;
	}

	/* Port locked and active */
	kr = mach_port_guard_locked(port, guard, strict);
	ip_unlock(port);

	if (KERN_INVALID_ARGUMENT == kr) {
		mach_port_guard_exception(name, 0, 0, kGUARD_EXC_INVALID_ARGUMENT);
	}

	return kr;
}

/*
 *	Routine:	mach_port_unguard [kernel call]
 *	Purpose:
 *		Unguard a mach port with specified guard value.
 *	Conditions:
 *		None.
 *	Returns:
 *		KERN_SUCCESS		The name is destroyed.
 *		KERN_INVALID_TASK	The space is null.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	The name doesn't denote a right.
 *		KERN_INVALID_RIGHT	The right isn't correct.
 *		KERN_INVALID_ARGUMENT	Port is either unguarded already or guard mismatch.
 *					This also raises a EXC_GUARD exception.
 */
kern_return_t
mach_port_unguard(
	ipc_space_t		space,
	mach_port_name_t	name,
	uint64_t		guard)
{
	
	kern_return_t		kr;
	ipc_port_t		port;

	if (space == IS_NULL)
		return KERN_INVALID_TASK;

	if (!MACH_PORT_VALID(name))
		return KERN_INVALID_NAME;

	kr = ipc_port_translate_receive(space, name, &port);
	if (kr != KERN_SUCCESS) {
		mach_port_guard_exception(name, 0, 0,
		                          ((KERN_INVALID_NAME == kr) ?
		                           kGUARD_EXC_INVALID_NAME :
		                           kGUARD_EXC_INVALID_RIGHT));
		return kr;
	}

	/* Port locked and active */
	kr = mach_port_unguard_locked(port, name, guard);
	ip_unlock(port);

	return kr;
}


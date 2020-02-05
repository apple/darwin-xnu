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
 *	File:	ipc/ipc_object.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Functions to manipulate IPC objects.
 */

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/port.h>
#include <mach/message.h>

#include <kern/kern_types.h>
#include <kern/misc_protos.h>
#include <kern/ipc_kobject.h>

#include <ipc/ipc_types.h>
#include <ipc/ipc_importance.h>
#include <ipc/port.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_hash.h>
#include <ipc/ipc_right.h>
#include <ipc/ipc_notify.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_pset.h>

#include <security/mac_mach_internal.h>

zone_t ipc_object_zones[IOT_NUMBER];

/*
 *	Routine:	ipc_object_reference
 *	Purpose:
 *		Take a reference to an object.
 */

void
ipc_object_reference(
	ipc_object_t    object)
{
	io_reference(object);
}

/*
 *	Routine:	ipc_object_release
 *	Purpose:
 *		Release a reference to an object.
 */

void
ipc_object_release(
	ipc_object_t    object)
{
	io_release(object);
}

/*
 *	Routine:	ipc_object_translate
 *	Purpose:
 *		Look up an object in a space.
 *	Conditions:
 *		Nothing locked before.  If successful, the object
 *		is returned active and locked.  The caller doesn't get a ref.
 *	Returns:
 *		KERN_SUCCESS		Object returned locked.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	The name doesn't denote a right
 *		KERN_INVALID_RIGHT	Name doesn't denote the correct right
 */
kern_return_t
ipc_object_translate(
	ipc_space_t             space,
	mach_port_name_t        name,
	mach_port_right_t       right,
	ipc_object_t            *objectp)
{
	ipc_entry_t entry;
	ipc_object_t object;
	kern_return_t kr;

	if (!MACH_PORT_RIGHT_VALID_TRANSLATE(right)) {
		return KERN_INVALID_RIGHT;
	}

	kr = ipc_right_lookup_read(space, name, &entry);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* space is read-locked and active */

	if ((entry->ie_bits & MACH_PORT_TYPE(right)) == MACH_PORT_TYPE_NONE) {
		is_read_unlock(space);
		return KERN_INVALID_RIGHT;
	}

	object = entry->ie_object;
	assert(object != IO_NULL);

	io_lock(object);
	is_read_unlock(space);

	if (!io_active(object)) {
		io_unlock(object);
		return KERN_INVALID_NAME;
	}

	*objectp = object;
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_object_translate_two
 *	Purpose:
 *		Look up two objects in a space.
 *	Conditions:
 *		Nothing locked before.  If successful, the objects
 *		are returned locked.  The caller doesn't get a ref.
 *	Returns:
 *		KERN_SUCCESS		Objects returned locked.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	A name doesn't denote a right.
 *		KERN_INVALID_RIGHT	A name doesn't denote the correct right.
 */

kern_return_t
ipc_object_translate_two(
	ipc_space_t             space,
	mach_port_name_t        name1,
	mach_port_right_t       right1,
	ipc_object_t            *objectp1,
	mach_port_name_t        name2,
	mach_port_right_t       right2,
	ipc_object_t            *objectp2)
{
	ipc_entry_t entry1;
	ipc_entry_t entry2;
	ipc_object_t object1, object2;
	kern_return_t kr;
	boolean_t doguard = TRUE;

	kr = ipc_right_lookup_two_read(space, name1, &entry1, name2, &entry2);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* space is read-locked and active */

	if ((entry1->ie_bits & MACH_PORT_TYPE(right1)) == MACH_PORT_TYPE_NONE) {
		/* If looking for receive, and the entry used to hold one, give a pass on EXC_GUARD */
		if ((right1 & MACH_PORT_RIGHT_RECEIVE) == MACH_PORT_RIGHT_RECEIVE &&
		    (entry1->ie_bits & MACH_PORT_TYPE_EX_RECEIVE) == MACH_PORT_TYPE_EX_RECEIVE) {
			doguard = FALSE;
		}
		is_read_unlock(space);
		if (doguard) {
			mach_port_guard_exception(name1, 0, 0, kGUARD_EXC_INVALID_RIGHT);
		}
		return KERN_INVALID_RIGHT;
	}

	if ((entry2->ie_bits & MACH_PORT_TYPE(right2)) == MACH_PORT_TYPE_NONE) {
		/* If looking for receive, and the entry used to hold one, give a pass on EXC_GUARD */
		if ((right2 & MACH_PORT_RIGHT_RECEIVE) == MACH_PORT_RIGHT_RECEIVE &&
		    (entry2->ie_bits & MACH_PORT_TYPE_EX_RECEIVE) == MACH_PORT_TYPE_EX_RECEIVE) {
			doguard = FALSE;
		}
		is_read_unlock(space);
		if (doguard) {
			mach_port_guard_exception(name2, 0, 0, kGUARD_EXC_INVALID_RIGHT);
		}
		return KERN_INVALID_RIGHT;
	}

	object1 = entry1->ie_object;
	assert(object1 != IO_NULL);
	io_lock(object1);
	if (!io_active(object1)) {
		io_unlock(object1);
		is_read_unlock(space);
		return KERN_INVALID_NAME;
	}

	object2 = entry2->ie_object;
	assert(object2 != IO_NULL);
	io_lock(object2);
	if (!io_active(object2)) {
		io_unlock(object1);
		io_unlock(object2);
		is_read_unlock(space);
		return KERN_INVALID_NAME;
	}

	*objectp1 = object1;
	*objectp2 = object2;

	is_read_unlock(space);
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_object_alloc_dead
 *	Purpose:
 *		Allocate a dead-name entry.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		The dead name is allocated.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_NO_SPACE		No room for an entry in the space.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
ipc_object_alloc_dead(
	ipc_space_t             space,
	mach_port_name_t        *namep)
{
	ipc_entry_t entry;
	kern_return_t kr;

	kr = ipc_entry_alloc(space, namep, &entry);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* space is write-locked */

	/* null object, MACH_PORT_TYPE_DEAD_NAME, 1 uref */

	assert(entry->ie_object == IO_NULL);
	entry->ie_bits |= MACH_PORT_TYPE_DEAD_NAME | 1;
	ipc_entry_modified(space, *namep, entry);
	is_write_unlock(space);
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_object_alloc_dead_name
 *	Purpose:
 *		Allocate a dead-name entry, with a specific name.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		The dead name is allocated.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_NAME_EXISTS	The name already denotes a right.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
ipc_object_alloc_dead_name(
	ipc_space_t             space,
	mach_port_name_t        name)
{
	ipc_entry_t entry;
	kern_return_t kr;

	kr = ipc_entry_alloc_name(space, name, &entry);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* space is write-locked */

	if (ipc_right_inuse(space, name, entry)) {
		return KERN_NAME_EXISTS;
	}

	/* null object, MACH_PORT_TYPE_DEAD_NAME, 1 uref */

	assert(entry->ie_object == IO_NULL);
	entry->ie_bits |= MACH_PORT_TYPE_DEAD_NAME | 1;
	ipc_entry_modified(space, name, entry);
	is_write_unlock(space);
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_object_alloc
 *	Purpose:
 *		Allocate an object.
 *	Conditions:
 *		Nothing locked.  If successful, the object is returned locked.
 *		The space is write locked on successful return.
 *		The caller doesn't get a reference for the object.
 *	Returns:
 *		KERN_SUCCESS		The object is allocated.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_NO_SPACE		No room for an entry in the space.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
ipc_object_alloc(
	ipc_space_t             space,
	ipc_object_type_t       otype,
	mach_port_type_t        type,
	mach_port_urefs_t       urefs,
	mach_port_name_t        *namep,
	ipc_object_t            *objectp)
{
	ipc_object_t object;
	ipc_entry_t entry;
	kern_return_t kr;

	assert(otype < IOT_NUMBER);
	assert((type & MACH_PORT_TYPE_ALL_RIGHTS) == type);
	assert(type != MACH_PORT_TYPE_NONE);
	assert(urefs <= MACH_PORT_UREFS_MAX);

	object = io_alloc(otype);
	if (object == IO_NULL) {
		return KERN_RESOURCE_SHORTAGE;
	}

	if (otype == IOT_PORT) {
		ipc_port_t port = ip_object_to_port(object);

		bzero((char *)port, sizeof(*port));
	} else if (otype == IOT_PORT_SET) {
		ipc_pset_t pset = ips_object_to_pset(object);

		bzero((char *)pset, sizeof(*pset));
	}

	io_lock_init(object);
	*namep = CAST_MACH_PORT_TO_NAME(object);
	kr = ipc_entry_alloc(space, namep, &entry);
	if (kr != KERN_SUCCESS) {
		io_free(otype, object);
		return kr;
	}
	/* space is write-locked */

	entry->ie_bits |= type | urefs;
	entry->ie_object = object;
	ipc_entry_modified(space, *namep, entry);

	object->io_bits = io_makebits(TRUE, otype, 0);
	io_lock(object);

	object->io_references = 1; /* for entry, not caller */

	*objectp = object;
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_object_alloc_name
 *	Purpose:
 *		Allocate an object, with a specific name.
 *	Conditions:
 *		Nothing locked.  If successful, the object is returned locked.
 *		The caller doesn't get a reference for the object.
 *	Returns:
 *		KERN_SUCCESS		The object is allocated.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_NAME_EXISTS	The name already denotes a right.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
ipc_object_alloc_name(
	ipc_space_t             space,
	ipc_object_type_t       otype,
	mach_port_type_t        type,
	mach_port_urefs_t       urefs,
	mach_port_name_t        name,
	ipc_object_t            *objectp)
{
	ipc_object_t object;
	ipc_entry_t entry;
	kern_return_t kr;

	assert(otype < IOT_NUMBER);
	assert((type & MACH_PORT_TYPE_ALL_RIGHTS) == type);
	assert(type != MACH_PORT_TYPE_NONE);
	assert(urefs <= MACH_PORT_UREFS_MAX);

	object = io_alloc(otype);
	if (object == IO_NULL) {
		return KERN_RESOURCE_SHORTAGE;
	}

	if (otype == IOT_PORT) {
		ipc_port_t port = ip_object_to_port(object);

		bzero((char *)port, sizeof(*port));
	} else if (otype == IOT_PORT_SET) {
		ipc_pset_t pset = ips_object_to_pset(object);

		bzero((char *)pset, sizeof(*pset));
	}

	io_lock_init(object);
	kr = ipc_entry_alloc_name(space, name, &entry);
	if (kr != KERN_SUCCESS) {
		io_free(otype, object);
		return kr;
	}
	/* space is write-locked */

	if (ipc_right_inuse(space, name, entry)) {
		io_free(otype, object);
		return KERN_NAME_EXISTS;
	}

	entry->ie_bits |= type | urefs;
	entry->ie_object = object;
	ipc_entry_modified(space, name, entry);

	object->io_bits = io_makebits(TRUE, otype, 0);

	io_lock(object);
	is_write_unlock(space);

	object->io_references = 1; /* for entry, not caller */

	*objectp = object;
	return KERN_SUCCESS;
}

/*	Routine:	ipc_object_validate
 *	Purpose:
 *		Validates an ipc port or port set as belonging to the correct
 *		zone.
 */

void
ipc_object_validate(
	ipc_object_t    object)
{
	int otype = (io_otype(object) == IOT_PORT_SET) ? IOT_PORT_SET : IOT_PORT;
	zone_require(object, ipc_object_zones[otype]);
}

/*
 *	Routine:	ipc_object_copyin_type
 *	Purpose:
 *		Convert a send type name to a received type name.
 */

mach_msg_type_name_t
ipc_object_copyin_type(
	mach_msg_type_name_t    msgt_name)
{
	switch (msgt_name) {
	case MACH_MSG_TYPE_MOVE_RECEIVE:
		return MACH_MSG_TYPE_PORT_RECEIVE;

	case MACH_MSG_TYPE_MOVE_SEND_ONCE:
	case MACH_MSG_TYPE_MAKE_SEND_ONCE:
		return MACH_MSG_TYPE_PORT_SEND_ONCE;

	case MACH_MSG_TYPE_MOVE_SEND:
	case MACH_MSG_TYPE_MAKE_SEND:
	case MACH_MSG_TYPE_COPY_SEND:
		return MACH_MSG_TYPE_PORT_SEND;

	case MACH_MSG_TYPE_DISPOSE_RECEIVE:
	case MACH_MSG_TYPE_DISPOSE_SEND:
	case MACH_MSG_TYPE_DISPOSE_SEND_ONCE:
	/* fall thru */
	default:
		return MACH_MSG_TYPE_PORT_NONE;
	}
}

/*
 *	Routine:	ipc_object_copyin
 *	Purpose:
 *		Copyin a capability from a space.
 *		If successful, the caller gets a ref
 *		for the resulting object, unless it is IO_DEAD.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Acquired an object, possibly IO_DEAD.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	Name doesn't exist in space.
 *		KERN_INVALID_RIGHT	Name doesn't denote correct right.
 */

kern_return_t
ipc_object_copyin(
	ipc_space_t             space,
	mach_port_name_t        name,
	mach_msg_type_name_t    msgt_name,
	ipc_object_t            *objectp,
	mach_port_context_t     context,
	mach_msg_guard_flags_t  *guard_flags,
	ipc_kmsg_flags_t        kmsg_flags)
{
	ipc_entry_t entry;
	ipc_port_t soright;
	ipc_port_t release_port;
	kern_return_t kr;
	int assertcnt = 0;

	ipc_right_copyin_flags_t irc_flags = IPC_RIGHT_COPYIN_FLAGS_DEADOK;
	if (kmsg_flags & IPC_KMSG_FLAGS_ALLOW_IMMOVABLE_SEND) {
		irc_flags |= IPC_RIGHT_COPYIN_FLAGS_ALLOW_IMMOVABLE_SEND;
	}

	/*
	 *	Could first try a read lock when doing
	 *	MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND,
	 *	and MACH_MSG_TYPE_MAKE_SEND_ONCE.
	 */

	kr = ipc_right_lookup_write(space, name, &entry);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* space is write-locked and active */

	release_port = IP_NULL;
	kr = ipc_right_copyin(space, name, entry,
	    msgt_name, irc_flags,
	    objectp, &soright,
	    &release_port,
	    &assertcnt,
	    context,
	    guard_flags);
	if (IE_BITS_TYPE(entry->ie_bits) == MACH_PORT_TYPE_NONE) {
		ipc_entry_dealloc(space, name, entry);
	}
	is_write_unlock(space);

#if IMPORTANCE_INHERITANCE
	if (0 < assertcnt && ipc_importance_task_is_any_receiver_type(current_task()->task_imp_base)) {
		ipc_importance_task_drop_internal_assertion(current_task()->task_imp_base, assertcnt);
	}
#endif /* IMPORTANCE_INHERITANCE */

	if (release_port != IP_NULL) {
		ip_release(release_port);
	}

	if ((kr == KERN_SUCCESS) && (soright != IP_NULL)) {
		ipc_notify_port_deleted(soright, name);
	}

	return kr;
}

/*
 *	Routine:	ipc_object_copyin_from_kernel
 *	Purpose:
 *		Copyin a naked capability from the kernel.
 *
 *		MACH_MSG_TYPE_MOVE_RECEIVE
 *			The receiver must be ipc_space_kernel
 *			or the receive right must already be in limbo.
 *			Consumes the naked receive right.
 *		MACH_MSG_TYPE_COPY_SEND
 *			A naked send right must be supplied.
 *			The port gains a reference, and a send right
 *			if the port is still active.
 *		MACH_MSG_TYPE_MAKE_SEND
 *			The receiver must be ipc_space_kernel.
 *			The port gains a reference and a send right.
 *		MACH_MSG_TYPE_MOVE_SEND
 *			Consumes a naked send right.
 *		MACH_MSG_TYPE_MAKE_SEND_ONCE
 *			The port gains a reference and a send-once right.
 *			Receiver also be the caller of device subsystem,
 *			so no assertion.
 *		MACH_MSG_TYPE_MOVE_SEND_ONCE
 *			Consumes a naked send-once right.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_object_copyin_from_kernel(
	ipc_object_t            object,
	mach_msg_type_name_t    msgt_name)
{
	assert(IO_VALID(object));

	switch (msgt_name) {
	case MACH_MSG_TYPE_MOVE_RECEIVE: {
		ipc_port_t port = ip_object_to_port(object);

		ip_lock(port);
		imq_lock(&port->ip_messages);
		require_ip_active(port);
		if (port->ip_destination != IP_NULL) {
			assert(port->ip_receiver == ipc_space_kernel);
			assert(port->ip_immovable_receive == 0);

			/* relevant part of ipc_port_clear_receiver */
			port->ip_mscount = 0;
			port->ip_receiver_name = MACH_PORT_NULL;
			port->ip_destination = IP_NULL;
		}
		imq_unlock(&port->ip_messages);
		ip_unlock(port);
		break;
	}

	case MACH_MSG_TYPE_COPY_SEND: {
		ipc_port_t port = ip_object_to_port(object);

		ip_lock(port);
		if (ip_active(port)) {
			assert(port->ip_srights > 0);
			port->ip_srights++;
		}
		ip_reference(port);
		ip_unlock(port);
		break;
	}

	case MACH_MSG_TYPE_MAKE_SEND: {
		ipc_port_t port = ip_object_to_port(object);

		ip_lock(port);
		if (ip_active(port)) {
			assert(port->ip_receiver_name != MACH_PORT_NULL);
			assert((port->ip_receiver == ipc_space_kernel) ||
			    (port->ip_receiver->is_node_id != HOST_LOCAL_NODE));
			port->ip_mscount++;
		}

		port->ip_srights++;
		ip_reference(port);
		ip_unlock(port);
		break;
	}

	case MACH_MSG_TYPE_MOVE_SEND: {
		/* move naked send right into the message */
		assert(ip_object_to_port(object)->ip_srights);
		break;
	}

	case MACH_MSG_TYPE_MAKE_SEND_ONCE: {
		ipc_port_t port = ip_object_to_port(object);

		ip_lock(port);
		if (ip_active(port)) {
			assert(port->ip_receiver_name != MACH_PORT_NULL);
		}
		ipc_port_make_sonce_locked(port);
		ip_unlock(port);
		break;
	}

	case MACH_MSG_TYPE_MOVE_SEND_ONCE: {
		/* move naked send-once right into the message */
		assert(ip_object_to_port(object)->ip_sorights);
		break;
	}

	default:
		panic("ipc_object_copyin_from_kernel: strange rights");
	}
}

/*
 *	Routine:	ipc_object_destroy
 *	Purpose:
 *		Destroys a naked capability.
 *		Consumes a ref for the object.
 *
 *		A receive right should be in limbo or in transit.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_object_destroy(
	ipc_object_t            object,
	mach_msg_type_name_t    msgt_name)
{
	assert(IO_VALID(object));
	assert(io_otype(object) == IOT_PORT);

	switch (msgt_name) {
	case MACH_MSG_TYPE_PORT_SEND:
		ipc_port_release_send(ip_object_to_port(object));
		break;

	case MACH_MSG_TYPE_PORT_SEND_ONCE:
		ipc_notify_send_once(ip_object_to_port(object));
		break;

	case MACH_MSG_TYPE_PORT_RECEIVE:
		ipc_port_release_receive(ip_object_to_port(object));
		break;

	default:
		panic("ipc_object_destroy: strange rights");
	}
}

/*
 *	Routine:	ipc_object_destroy_dest
 *	Purpose:
 *		Destroys a naked capability for the destination of
 *		of a message. Consumes a ref for the object.
 *
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_object_destroy_dest(
	ipc_object_t            object,
	mach_msg_type_name_t    msgt_name)
{
	assert(IO_VALID(object));
	assert(io_otype(object) == IOT_PORT);

	switch (msgt_name) {
	case MACH_MSG_TYPE_PORT_SEND:
		ipc_port_release_send(ip_object_to_port(object));
		break;

	case MACH_MSG_TYPE_PORT_SEND_ONCE:
		if (io_active(object) &&
		    !ip_full_kernel(ip_object_to_port(object))) {
			ipc_notify_send_once(ip_object_to_port(object));
		} else {
			ipc_port_release_sonce(ip_object_to_port(object));
		}
		break;

	default:
		panic("ipc_object_destroy_dest: strange rights");
	}
}

/*
 *	Routine:	ipc_object_insert_send_right
 *	Purpose:
 *		Insert a send right into an object already in the space.
 *		The specified name must already point to a valid object.
 *
 *		Note: This really is a combined copyin()/copyout(),
 *		that avoids most of the overhead of being implemented that way.
 *
 *		This is the fastpath for mach_port_insert_right.
 *
 *	Conditions:
 *		Nothing locked.
 *
 *		msgt_name must be MACH_MSG_TYPE_MAKE_SEND_ONCE or
 *		MACH_MSG_TYPE_MOVE_SEND_ONCE.
 *
 *	Returns:
 *		KERN_SUCCESS		Copied out object, consumed ref.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	Name doesn't exist in space.
 *		KERN_INVALID_CAPABILITY	The object is dead.
 *		KERN_RIGHT_EXISTS	Space has rights under another name.
 */
kern_return_t
ipc_object_insert_send_right(
	ipc_space_t             space,
	mach_port_name_t        name,
	mach_msg_type_name_t    msgt_name)
{
	ipc_entry_bits_t bits;
	ipc_object_t object;
	ipc_entry_t entry;
	kern_return_t kr;

	assert(msgt_name == MACH_MSG_TYPE_MAKE_SEND ||
	    msgt_name == MACH_MSG_TYPE_COPY_SEND);

	kr = ipc_right_lookup_write(space, name, &entry);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* space is write-locked and active */

	if (!IO_VALID(entry->ie_object)) {
		is_write_unlock(space);
		return KERN_INVALID_CAPABILITY;
	}

	bits = entry->ie_bits;
	object = entry->ie_object;

	io_lock(object);
	if (!io_active(object)) {
		kr = KERN_INVALID_CAPABILITY;
	} else if (msgt_name == MACH_MSG_TYPE_MAKE_SEND) {
		if (bits & MACH_PORT_TYPE_RECEIVE) {
			ipc_port_t port = ip_object_to_port(object);
			port->ip_mscount++;
			if ((bits & MACH_PORT_TYPE_SEND) == 0) {
				port->ip_srights++;
				bits |= MACH_PORT_TYPE_SEND;
			}
			/* leave urefs pegged to maximum if it overflowed */
			if (IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX) {
				bits += 1; /* increment urefs */
			}
			entry->ie_bits = bits;
			ipc_entry_modified(space, name, entry);
			kr = KERN_SUCCESS;
		} else {
			kr = KERN_INVALID_RIGHT;
		}
	} else { // MACH_MSG_TYPE_COPY_SEND
		if (bits & MACH_PORT_TYPE_SEND) {
			/* leave urefs pegged to maximum if it overflowed */
			if (IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX) {
				entry->ie_bits = bits + 1; /* increment urefs */
			}
			ipc_entry_modified(space, name, entry);
			kr = KERN_SUCCESS;
		} else {
			kr = KERN_INVALID_RIGHT;
		}
	}

	io_unlock(object);
	is_write_unlock(space);

	return kr;
}

/*
 *	Routine:	ipc_object_copyout
 *	Purpose:
 *		Copyout a capability, placing it into a space.
 *		If successful, consumes a ref for the object.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Copied out object, consumed ref.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_CAPABILITY	The object is dead.
 *		KERN_NO_SPACE		No room in space for another right.
 *		KERN_RESOURCE_SHORTAGE	No memory available.
 *		KERN_UREFS_OVERFLOW	Urefs limit exceeded
 *			and overflow wasn't specified.
 */

kern_return_t
ipc_object_copyout(
	ipc_space_t             space,
	ipc_object_t            object,
	mach_msg_type_name_t    msgt_name,
	mach_port_context_t     *context,
	mach_msg_guard_flags_t  *guard_flags,
	mach_port_name_t        *namep)
{
	struct knote *kn = current_thread()->ith_knote;
	mach_port_name_t name;
	ipc_entry_t entry;
	kern_return_t kr;

	assert(IO_VALID(object));
	assert(io_otype(object) == IOT_PORT);

	if (ITH_KNOTE_VALID(kn, msgt_name)) {
		filt_machport_turnstile_prepare_lazily(kn,
		    msgt_name, ip_object_to_port(object));
	}

	is_write_lock(space);

	for (;;) {
		if (!is_active(space)) {
			is_write_unlock(space);
			return KERN_INVALID_TASK;
		}

		if ((msgt_name != MACH_MSG_TYPE_PORT_SEND_ONCE) &&
		    ipc_right_reverse(space, object, &name, &entry)) {
			/* object is locked and active */

			assert(entry->ie_bits & MACH_PORT_TYPE_SEND_RECEIVE);
			break;
		}

		name = CAST_MACH_PORT_TO_NAME(object);
		kr = ipc_entry_get(space, &name, &entry);
		if (kr != KERN_SUCCESS) {
			/* unlocks/locks space, so must start again */

			kr = ipc_entry_grow_table(space, ITS_SIZE_NONE);
			if (kr != KERN_SUCCESS) {
				return kr; /* space is unlocked */
			}
			continue;
		}

		assert(IE_BITS_TYPE(entry->ie_bits) == MACH_PORT_TYPE_NONE);
		assert(entry->ie_object == IO_NULL);

		io_lock(object);
		if (!io_active(object)) {
			io_unlock(object);
			ipc_entry_dealloc(space, name, entry);
			is_write_unlock(space);
			return KERN_INVALID_CAPABILITY;
		}

		entry->ie_object = object;
		break;
	}

	/* space is write-locked and active, object is locked and active */

	kr = ipc_right_copyout(space, name, entry,
	    msgt_name, context, guard_flags, object);

	/* object is unlocked */
	is_write_unlock(space);

	if (kr == KERN_SUCCESS) {
		*namep = name;
	}
	return kr;
}

/*
 *	Routine:	ipc_object_copyout_name
 *	Purpose:
 *		Copyout a capability, placing it into a space.
 *		The specified name is used for the capability.
 *		If successful, consumes a ref for the object.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Copied out object, consumed ref.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_CAPABILITY	The object is dead.
 *		KERN_RESOURCE_SHORTAGE	No memory available.
 *		KERN_UREFS_OVERFLOW	Urefs limit exceeded
 *			and overflow wasn't specified.
 *		KERN_RIGHT_EXISTS	Space has rights under another name.
 *		KERN_NAME_EXISTS	Name is already used.
 */

kern_return_t
ipc_object_copyout_name(
	ipc_space_t             space,
	ipc_object_t            object,
	mach_msg_type_name_t    msgt_name,
	mach_port_name_t        name)
{
	mach_port_name_t oname;
	ipc_entry_t oentry;
	ipc_entry_t entry;
	kern_return_t kr;

#if IMPORTANCE_INHERITANCE
	int assertcnt = 0;
	ipc_importance_task_t task_imp = IIT_NULL;
#endif /* IMPORTANCE_INHERITANCE */

	assert(IO_VALID(object));
	assert(io_otype(object) == IOT_PORT);

	kr = ipc_entry_alloc_name(space, name, &entry);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* space is write-locked and active */

	if ((msgt_name != MACH_MSG_TYPE_PORT_SEND_ONCE) &&
	    ipc_right_reverse(space, object, &oname, &oentry)) {
		/* object is locked and active */

		if (name != oname) {
			io_unlock(object);

			if (IE_BITS_TYPE(entry->ie_bits) == MACH_PORT_TYPE_NONE) {
				ipc_entry_dealloc(space, name, entry);
			}

			is_write_unlock(space);
			return KERN_RIGHT_EXISTS;
		}

		assert(entry == oentry);
		assert(entry->ie_bits & MACH_PORT_TYPE_SEND_RECEIVE);
	} else {
		if (ipc_right_inuse(space, name, entry)) {
			return KERN_NAME_EXISTS;
		}

		assert(IE_BITS_TYPE(entry->ie_bits) == MACH_PORT_TYPE_NONE);
		assert(entry->ie_object == IO_NULL);

		io_lock(object);
		if (!io_active(object)) {
			io_unlock(object);
			ipc_entry_dealloc(space, name, entry);
			is_write_unlock(space);
			return KERN_INVALID_CAPABILITY;
		}

		entry->ie_object = object;
	}

	/* space is write-locked and active, object is locked and active */

#if IMPORTANCE_INHERITANCE
	/*
	 * We are slamming a receive right into the space, without
	 * first having been enqueued on a port destined there.  So,
	 * we have to arrange to boost the task appropriately if this
	 * port has assertions (and the task wants them).
	 */
	if (msgt_name == MACH_MSG_TYPE_PORT_RECEIVE) {
		ipc_port_t port = ip_object_to_port(object);

		if (space->is_task != TASK_NULL) {
			task_imp = space->is_task->task_imp_base;
			if (ipc_importance_task_is_any_receiver_type(task_imp)) {
				assertcnt = port->ip_impcount;
				ipc_importance_task_reference(task_imp);
			} else {
				task_imp = IIT_NULL;
			}
		}

		/* take port out of limbo */
		assert(port->ip_tempowner != 0);
		port->ip_tempowner = 0;
	}

#endif /* IMPORTANCE_INHERITANCE */

	kr = ipc_right_copyout(space, name, entry,
	    msgt_name, NULL, NULL, object);

	/* object is unlocked */
	is_write_unlock(space);

#if IMPORTANCE_INHERITANCE
	/*
	 * Add the assertions to the task that we captured before
	 */
	if (task_imp != IIT_NULL) {
		ipc_importance_task_hold_internal_assertion(task_imp, assertcnt);
		ipc_importance_task_release(task_imp);
	}
#endif /* IMPORTANCE_INHERITANCE */

	return kr;
}

/*
 *	Routine:	ipc_object_copyout_dest
 *	Purpose:
 *		Translates/consumes the destination right of a message.
 *		This is unlike normal copyout because the right is consumed
 *		in a funny way instead of being given to the receiving space.
 *		The receiver gets his name for the port, if he has receive
 *		rights, otherwise MACH_PORT_NULL.
 *	Conditions:
 *		The object is locked and active.  Nothing else locked.
 *		The object is unlocked and loses a reference.
 */

void
ipc_object_copyout_dest(
	ipc_space_t             space,
	ipc_object_t            object,
	mach_msg_type_name_t    msgt_name,
	mach_port_name_t        *namep)
{
	mach_port_name_t name;

	assert(IO_VALID(object));
	assert(io_active(object));

	/*
	 *	If the space is the receiver/owner of the object,
	 *	then we quietly consume the right and return
	 *	the space's name for the object.  Otherwise
	 *	we destroy the right and return MACH_PORT_NULL.
	 */

	switch (msgt_name) {
	case MACH_MSG_TYPE_PORT_SEND: {
		ipc_port_t port = ip_object_to_port(object);
		ipc_port_t nsrequest = IP_NULL;
		mach_port_mscount_t mscount;

		if (port->ip_receiver == space) {
			name = port->ip_receiver_name;
		} else {
			name = MACH_PORT_NULL;
		}

		assert(port->ip_srights > 0);
		if (--port->ip_srights == 0 &&
		    port->ip_nsrequest != IP_NULL) {
			nsrequest = port->ip_nsrequest;
			port->ip_nsrequest = IP_NULL;
			mscount = port->ip_mscount;
			ipc_port_clear_sync_rcv_thread_boost_locked(port);
			/* port unlocked */
			ipc_notify_no_senders(nsrequest, mscount);
		} else {
			ipc_port_clear_sync_rcv_thread_boost_locked(port);
			/* port unlocked */
		}

		ip_release(port);
		break;
	}

	case MACH_MSG_TYPE_PORT_SEND_ONCE: {
		ipc_port_t port = ip_object_to_port(object);

		assert(port->ip_sorights > 0);

		if (port->ip_receiver == space) {
			/* quietly consume the send-once right */

			port->ip_sorights--;
			name = port->ip_receiver_name;
			ipc_port_clear_sync_rcv_thread_boost_locked(port);
			/* port unlocked */
			ip_release(port);
		} else {
			/*
			 *	A very bizarre case.  The message
			 *	was received, but before this copyout
			 *	happened the space lost receive rights.
			 *	We can't quietly consume the soright
			 *	out from underneath some other task,
			 *	so generate a send-once notification.
			 */

			ip_unlock(port);

			ipc_notify_send_once(port);
			name = MACH_PORT_NULL;
		}

		break;
	}

	default:
		panic("ipc_object_copyout_dest: strange rights");
		name = MACH_PORT_DEAD;
	}

	*namep = name;
}

/*
 *	Routine:        io_lock
 *	Purpose:
 *		Validate, then acquire a lock on an ipc object
 */

void
io_lock(ipc_object_t io)
{
	ipc_object_validate(io);
	lck_spin_lock_grp(&(io)->io_lock_data, &ipc_lck_grp);
}

/*
 *	Routine:	io_lock_try
 *	Purpose:
 *		Validate, then try to acquire a lock on an object,
 *		fail if there is an existing busy lock
 */

boolean_t
io_lock_try(ipc_object_t io)
{
	ipc_object_validate(io);
	return lck_spin_try_lock_grp(&(io)->io_lock_data, &ipc_lck_grp);
}

/*
 *	Check whether the object is a port if so, free it.  But
 *	keep track of that fact.
 */
void
io_free(
	unsigned int    otype,
	ipc_object_t    object)
{
	if (otype == IOT_PORT) {
		ipc_port_finalize(ip_object_to_port(object));
	}
	io_lock_destroy(object);
	zfree(ipc_object_zones[otype], object);
}

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
 */
/*
 *	File:	ipc/ipc_object.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Functions to manipulate IPC objects.
 */

#include <mach_rt.h>

#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/port.h>
#include <mach/message.h>
#include <kern/misc_protos.h>
#include <ipc/port.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_hash.h>
#include <ipc/ipc_right.h>
#include <ipc/ipc_notify.h>
#include <ipc/ipc_pset.h>

zone_t ipc_object_zones[IOT_NUMBER];

/*
 *	Routine:	ipc_object_reference
 *	Purpose:
 *		Take a reference to an object.
 */

void
ipc_object_reference(
	ipc_object_t	object)
{
	io_lock(object);
	assert(object->io_references > 0);
	io_reference(object);
	io_unlock(object);
}

/*
 *	Routine:	ipc_object_release
 *	Purpose:
 *		Release a reference to an object.
 */

void
ipc_object_release(
	ipc_object_t	object)
{
	io_lock(object);
	assert(object->io_references > 0);
	io_release(object);
	io_check_unlock(object);
}

/*
 *	Routine:	ipc_object_translate
 *	Purpose:
 *		Look up an object in a space.
 *	Conditions:
 *		Nothing locked before.  If successful, the object
 *		is returned locked.  The caller doesn't get a ref.
 *	Returns:
 *		KERN_SUCCESS		Object returned locked.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	The name doesn't denote a right.
 *		KERN_INVALID_RIGHT	Name doesn't denote the correct right.
 */

kern_return_t
ipc_object_translate(
	ipc_space_t		space,
	mach_port_name_t	name,
	mach_port_right_t	right,
	ipc_object_t		*objectp)
{
	ipc_entry_t entry;
	ipc_object_t object;
	kern_return_t kr;

	kr = ipc_right_lookup_read(space, name, &entry);
	if (kr != KERN_SUCCESS)
		return kr;
	/* space is read-locked and active */

	if ((entry->ie_bits & MACH_PORT_TYPE(right)) == MACH_PORT_TYPE_NONE) {
		is_read_unlock(space);
		return KERN_INVALID_RIGHT;
	}

	object = entry->ie_object;
	assert(object != IO_NULL);

	io_lock(object);
	is_read_unlock(space);

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
	ipc_space_t		space,
	mach_port_name_t	name1,
	mach_port_right_t	right1,
	ipc_object_t		*objectp1,
	mach_port_name_t	name2,
	mach_port_right_t	right2,
	ipc_object_t		*objectp2)
{
	ipc_entry_t entry1;
	ipc_entry_t entry2;
	ipc_object_t object;
	kern_return_t kr;

	kr = ipc_right_lookup_two_read(space, name1, &entry1, name2, &entry2);
	if (kr != KERN_SUCCESS)
		return kr;
	/* space is read-locked and active */

	if ((entry1->ie_bits & MACH_PORT_TYPE(right1)) == MACH_PORT_TYPE_NONE) {
		is_read_unlock(space);
		return KERN_INVALID_RIGHT;
	}

	if ((entry2->ie_bits & MACH_PORT_TYPE(right2)) == MACH_PORT_TYPE_NONE) {
		is_read_unlock(space);
		return KERN_INVALID_RIGHT;
	}

	object = entry1->ie_object;
	assert(object != IO_NULL);
	io_lock(object);
	*objectp1 = object;

	object = entry2->ie_object;
	assert(object != IO_NULL);
	io_lock(object);
	*objectp2 = object;

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
	ipc_space_t		space,
	mach_port_name_t	*namep)
{
	ipc_entry_t entry;
	kern_return_t kr;

	int i;


	kr = ipc_entry_alloc(space, namep, &entry);
	if (kr != KERN_SUCCESS)
		return kr;
	/* space is write-locked */

	/* null object, MACH_PORT_TYPE_DEAD_NAME, 1 uref */

	assert(entry->ie_object == IO_NULL);
	entry->ie_bits |= MACH_PORT_TYPE_DEAD_NAME | 1;
	
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
	ipc_space_t		space,
	mach_port_name_t	name)
{
	ipc_entry_t entry;
	kern_return_t kr;

	int i;


	kr = ipc_entry_alloc_name(space, name, &entry);
	if (kr != KERN_SUCCESS)
		return kr;
	/* space is write-locked */

	if (ipc_right_inuse(space, name, entry))
		return KERN_NAME_EXISTS;

	/* null object, MACH_PORT_TYPE_DEAD_NAME, 1 uref */

	assert(entry->ie_object == IO_NULL);
	entry->ie_bits |= MACH_PORT_TYPE_DEAD_NAME | 1;

	is_write_unlock(space);
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_object_alloc
 *	Purpose:
 *		Allocate an object.
 *	Conditions:
 *		Nothing locked.  If successful, the object is returned locked.
 *		The caller doesn't get a reference for the object.
 *	Returns:
 *		KERN_SUCCESS		The object is allocated.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_NO_SPACE		No room for an entry in the space.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
ipc_object_alloc(
	ipc_space_t		space,
	ipc_object_type_t	otype,
	mach_port_type_t	type,
	mach_port_urefs_t	urefs,
	mach_port_name_t	*namep,
	ipc_object_t		*objectp)
{
	ipc_object_t object;
	ipc_entry_t entry;
	kern_return_t kr;

	assert(otype < IOT_NUMBER);
	assert((type & MACH_PORT_TYPE_ALL_RIGHTS) == type);
	assert(type != MACH_PORT_TYPE_NONE);
	assert(urefs <= MACH_PORT_UREFS_MAX);

	object = io_alloc(otype);
	if (object == IO_NULL)
		return KERN_RESOURCE_SHORTAGE;

	if (otype == IOT_PORT) {
		ipc_port_t port = (ipc_port_t)object;

		bzero((char *)port, sizeof(*port));
	} else if (otype == IOT_PORT_SET) {
		ipc_pset_t pset = (ipc_pset_t)object;

		bzero((char *)pset, sizeof(*pset));
	}

	io_lock_init(object);
	*namep = (mach_port_name_t)object;
	kr = ipc_entry_alloc(space, namep, &entry);
	if (kr != KERN_SUCCESS) {
		io_free(otype, object);
		return kr;
	}
	/* space is write-locked */

	entry->ie_bits |= type | urefs;
	entry->ie_object = object;

	io_lock(object);
	is_write_unlock(space);

	object->io_references = 1; /* for entry, not caller */
	object->io_bits = io_makebits(TRUE, otype, 0);

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
	ipc_space_t		space,
	ipc_object_type_t	otype,
	mach_port_type_t	type,
	mach_port_urefs_t	urefs,
	mach_port_name_t	name,
	ipc_object_t		*objectp)
{
	ipc_object_t object;
	ipc_entry_t entry;
	kern_return_t kr;

	assert(otype < IOT_NUMBER);
	assert((type & MACH_PORT_TYPE_ALL_RIGHTS) == type);
	assert(type != MACH_PORT_TYPE_NONE);
	assert(urefs <= MACH_PORT_UREFS_MAX);

	object = io_alloc(otype);
	if (object == IO_NULL)
		return KERN_RESOURCE_SHORTAGE;

	if (otype == IOT_PORT) {
		ipc_port_t port = (ipc_port_t)object;

		bzero((char *)port, sizeof(*port));
	} else if (otype == IOT_PORT_SET) {
		ipc_pset_t pset = (ipc_pset_t)object;

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

	io_lock(object);
	is_write_unlock(space);

	object->io_references = 1; /* for entry, not caller */
	object->io_bits = io_makebits(TRUE, otype, 0);

	*objectp = object;
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_object_copyin_type
 *	Purpose:
 *		Convert a send type name to a received type name.
 */

mach_msg_type_name_t
ipc_object_copyin_type(
	mach_msg_type_name_t	msgt_name)
{
	switch (msgt_name) {

	    case MACH_MSG_TYPE_MOVE_RECEIVE:
	    case MACH_MSG_TYPE_COPY_RECEIVE:
		return MACH_MSG_TYPE_PORT_RECEIVE;

	    case MACH_MSG_TYPE_MOVE_SEND_ONCE:
	    case MACH_MSG_TYPE_MAKE_SEND_ONCE:
		return MACH_MSG_TYPE_PORT_SEND_ONCE;

	    case MACH_MSG_TYPE_MOVE_SEND:
	    case MACH_MSG_TYPE_MAKE_SEND:
	    case MACH_MSG_TYPE_COPY_SEND:
		return MACH_MSG_TYPE_PORT_SEND;

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
	ipc_space_t		space,
	mach_port_name_t	name,
	mach_msg_type_name_t	msgt_name,
	ipc_object_t		*objectp)
{
	ipc_entry_t entry;
	ipc_port_t soright;
	kern_return_t kr;

	int i;

	/*
	 *	Could first try a read lock when doing
	 *	MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND,
	 *	and MACH_MSG_TYPE_MAKE_SEND_ONCE.
	 */

	kr = ipc_right_lookup_write(space, name, &entry);
	if (kr != KERN_SUCCESS)
		return kr;
	/* space is write-locked and active */

	kr = ipc_right_copyin(space, name, entry,
			      msgt_name, TRUE,
			      objectp, &soright);
	if (IE_BITS_TYPE(entry->ie_bits) == MACH_PORT_TYPE_NONE)
		ipc_entry_dealloc(space, name, entry);
	is_write_unlock(space);

	if ((kr == KERN_SUCCESS) && (soright != IP_NULL))
		ipc_notify_port_deleted(soright, name);

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
	ipc_object_t		object,
	mach_msg_type_name_t	msgt_name)
{
	assert(IO_VALID(object));

	switch (msgt_name) {
	    case MACH_MSG_TYPE_MOVE_RECEIVE: {
		ipc_port_t port = (ipc_port_t) object;

		ip_lock(port);
		assert(ip_active(port));
		if (port->ip_destination != IP_NULL) {
			assert(port->ip_receiver == ipc_space_kernel);

			/* relevant part of ipc_port_clear_receiver */
			ipc_port_set_mscount(port, 0);

			port->ip_receiver_name = MACH_PORT_NULL;
			port->ip_destination = IP_NULL;
		}
		ip_unlock(port);
		break;
	    }

	    case MACH_MSG_TYPE_COPY_SEND: {
		ipc_port_t port = (ipc_port_t) object;

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
		ipc_port_t port = (ipc_port_t) object;

		ip_lock(port);
		assert(ip_active(port));
		assert(port->ip_receiver_name != MACH_PORT_NULL);
		assert(port->ip_receiver == ipc_space_kernel);

		ip_reference(port);
		port->ip_mscount++;
		port->ip_srights++;
		ip_unlock(port);
		break;
	    }

	    case MACH_MSG_TYPE_MOVE_SEND: {
		/* move naked send right into the message */
		ipc_port_t port = (ipc_port_t) object;
		assert(port->ip_srights);
		break;
	    }

	    case MACH_MSG_TYPE_MAKE_SEND_ONCE: {
		ipc_port_t port = (ipc_port_t) object;

		ip_lock(port);
		assert(ip_active(port));
		assert(port->ip_receiver_name != MACH_PORT_NULL);

		ip_reference(port);
		port->ip_sorights++;
		ip_unlock(port);
		break;
	    }

	    case MACH_MSG_TYPE_MOVE_SEND_ONCE: {
		/* move naked send-once right into the message */
		ipc_port_t port = (ipc_port_t) object;
	    	assert(port->ip_sorights);
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
	ipc_object_t		object,
	mach_msg_type_name_t	msgt_name)
{
	assert(IO_VALID(object));
	assert(io_otype(object) == IOT_PORT);

	switch (msgt_name) {
	    case MACH_MSG_TYPE_PORT_SEND:
		ipc_port_release_send((ipc_port_t) object);
		break;

	    case MACH_MSG_TYPE_PORT_SEND_ONCE:
		ipc_notify_send_once((ipc_port_t) object);
		break;

	    case MACH_MSG_TYPE_PORT_RECEIVE:
		ipc_port_release_receive((ipc_port_t) object);
		break;

	    default:
		panic("ipc_object_destroy: strange rights");
	}
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
	ipc_space_t		space,
	ipc_object_t		object,
	mach_msg_type_name_t	msgt_name,
	boolean_t		overflow,
	mach_port_name_t	*namep)
{
	mach_port_name_t name;
	ipc_entry_t entry;
	kern_return_t kr;

	assert(IO_VALID(object));
	assert(io_otype(object) == IOT_PORT);

	is_write_lock(space);

	for (;;) {
		if (!space->is_active) {
			is_write_unlock(space);
			return KERN_INVALID_TASK;
		}

		if ((msgt_name != MACH_MSG_TYPE_PORT_SEND_ONCE) &&
		    ipc_right_reverse(space, object, &name, &entry)) { 
			/* object is locked and active */

			assert(entry->ie_bits & MACH_PORT_TYPE_SEND_RECEIVE);
			break;
		}

		name = (mach_port_name_t)object;
		kr = ipc_entry_get(space, &name, &entry);
		if (kr != KERN_SUCCESS) {
			/* unlocks/locks space, so must start again */

			kr = ipc_entry_grow_table(space, ITS_SIZE_NONE);
			if (kr != KERN_SUCCESS)
				return kr; /* space is unlocked */

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
			       msgt_name, overflow, object);
	/* object is unlocked */
	is_write_unlock(space);

	if (kr == KERN_SUCCESS)
		*namep = name;
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
	ipc_space_t		space,
	ipc_object_t		object,
	mach_msg_type_name_t	msgt_name,
	boolean_t		overflow,
	mach_port_name_t	name)
{
	mach_port_name_t oname;
	ipc_entry_t oentry;
	ipc_entry_t entry;
	kern_return_t kr;

	int i;

	assert(IO_VALID(object));
	assert(io_otype(object) == IOT_PORT);

	kr = ipc_entry_alloc_name(space, name, &entry);
	if (kr != KERN_SUCCESS)
		return kr;
	/* space is write-locked and active */

	if ((msgt_name != MACH_MSG_TYPE_PORT_SEND_ONCE) &&
	    ipc_right_reverse(space, object, &oname, &oentry)) {
		/* object is locked and active */

		if (name != oname) {
			io_unlock(object);

			if (IE_BITS_TYPE(entry->ie_bits) == MACH_PORT_TYPE_NONE)
				ipc_entry_dealloc(space, name, entry);

			is_write_unlock(space);
			return KERN_RIGHT_EXISTS;
		}

		assert(entry == oentry);
		assert(entry->ie_bits & MACH_PORT_TYPE_SEND_RECEIVE);
	} else {
		if (ipc_right_inuse(space, name, entry))
			return KERN_NAME_EXISTS;

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

	kr = ipc_right_copyout(space, name, entry,
			       msgt_name, overflow, object);
	/* object is unlocked */
	is_write_unlock(space);
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
	ipc_space_t		space,
	ipc_object_t		object,
	mach_msg_type_name_t	msgt_name,
	mach_port_name_t	*namep)
{
	mach_port_name_t name;

	assert(IO_VALID(object));
	assert(io_active(object));

	io_release(object);

	/*
	 *	If the space is the receiver/owner of the object,
	 *	then we quietly consume the right and return
	 *	the space's name for the object.  Otherwise
	 *	we destroy the right and return MACH_PORT_NULL.
	 */

	switch (msgt_name) {
	    case MACH_MSG_TYPE_PORT_SEND: {
		ipc_port_t port = (ipc_port_t) object;
		ipc_port_t nsrequest = IP_NULL;
		mach_port_mscount_t mscount;

		if (port->ip_receiver == space)
			name = port->ip_receiver_name;
		else
			name = MACH_PORT_NULL;

		assert(port->ip_srights > 0);
		if (--port->ip_srights == 0 &&
		    port->ip_nsrequest != IP_NULL) {
			nsrequest = port->ip_nsrequest;
			port->ip_nsrequest = IP_NULL;
			mscount = port->ip_mscount;
			ip_unlock(port);
			ipc_notify_no_senders(nsrequest, mscount);
		} else
			ip_unlock(port);
		break;
	    }

	    case MACH_MSG_TYPE_PORT_SEND_ONCE: {
		ipc_port_t port = (ipc_port_t) object;

		assert(port->ip_sorights > 0);

		if (port->ip_receiver == space) {
			/* quietly consume the send-once right */

			port->ip_sorights--;
			name = port->ip_receiver_name;
			ip_unlock(port);
		} else {
			/*
			 *	A very bizarre case.  The message
			 *	was received, but before this copyout
			 *	happened the space lost receive rights.
			 *	We can't quietly consume the soright
			 *	out from underneath some other task,
			 *	so generate a send-once notification.
			 */

			ip_reference(port); /* restore ref */
			ip_unlock(port);

			ipc_notify_send_once(port);
			name = MACH_PORT_NULL;
		}

		break;
	    }

	    default:
		panic("ipc_object_copyout_dest: strange rights");
	}

	*namep = name;
}

/*
 *	Routine:	ipc_object_rename
 *	Purpose:
 *		Rename an entry in a space.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Renamed the entry.
 *		KERN_INVALID_TASK	The space was dead.
 *		KERN_INVALID_NAME	oname didn't denote an entry.
 *		KERN_NAME_EXISTS	nname already denoted an entry.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate new entry.
 */

kern_return_t
ipc_object_rename(
	ipc_space_t		space,
	mach_port_name_t	oname,
	mach_port_name_t	nname)
{
	ipc_entry_t oentry, nentry;
	kern_return_t kr;
	
	int i;

	kr = ipc_entry_alloc_name(space, nname, &nentry);
	if (kr != KERN_SUCCESS)
		return kr;

	/* space is write-locked and active */

	if (ipc_right_inuse(space, nname, nentry)) {
		/* space is unlocked */
		return KERN_NAME_EXISTS;
	}

	/* don't let ipc_entry_lookup see the uninitialized new entry */

	if ((oname == nname) ||
	    ((oentry = ipc_entry_lookup(space, oname)) == IE_NULL)) {
		ipc_entry_dealloc(space, nname, nentry);
		is_write_unlock(space);
		return KERN_INVALID_NAME;
	}

	kr = ipc_right_rename(space, oname, oentry, nname, nentry);
	/* space is unlocked */
	return kr;
}

#if	MACH_ASSERT
/*
 *	Check whether the object is a port if so, free it.  But
 *	keep track of that fact.
 */
void
io_free(
	unsigned int	otype,
	ipc_object_t	object)
{
	ipc_port_t	port;

	if (otype == IOT_PORT) {
		port = (ipc_port_t) object;
#if	MACH_ASSERT
		ipc_port_track_dealloc(port);
#endif	/* MACH_ASSERT */
	}
	zfree(ipc_object_zones[otype], (vm_offset_t) object);
}
#endif	/* MACH_ASSERT */

#include <mach_kdb.h>
#if	MACH_KDB

#include <ddb/db_output.h>

#define	printf	kdbprintf 

/*
 *	Routine:	ipc_object_print
 *	Purpose:
 *		Pretty-print an object for kdb.
 */

char *ikot_print_array[IKOT_MAX_TYPE] = {
	"(NONE)             ",
	"(THREAD)           ",
	"(TASK)             ",
	"(HOST)             ",
	"(HOST_PRIV)        ",
	"(PROCESSOR)        ",
	"(PSET)             ",
	"(PSET_NAME)        ",
	"(TIMER)            ",
	"(PAGER_REQUEST)    ",
	"(DEVICE)           ",	/* 10 */
	"(XMM_OBJECT)       ",
	"(XMM_PAGER)        ",
	"(XMM_KERNEL)       ",
	"(XMM_REPLY)        ",
	"(NOTDEF 15)        ",
	"(NOTDEF 16)        ",
	"(HOST_SECURITY)    ",
	"(LEDGER)           ",
	"(MASTER_DEVICE)    ",
	"(ACTIVATION)       ",	/* 20 */
	"(SUBSYSTEM)        ",
	"(IO_DONE_QUEUE)    ",
	"(SEMAPHORE)        ",
	"(LOCK_SET)         ",
	"(CLOCK)            ",
	"(CLOCK_CTRL)       ",	/* 26 */
	"(IOKIT_SPARE)	    ",  /* 27 */
	"(NAMED_MEM_ENTRY)  ",	/* 28 */
	"(IOKIT_CONNECT)    ",
	"(IOKIT_OBJECT)     ",	/* 30 */
	"(UPL)              ",
						/* << new entries here	*/
	"(UNKNOWN)          "	/* magic catchall	*/
};
/* Please keep in sync with kern/ipc_kobject.h	*/

void
ipc_object_print(
	ipc_object_t	object)
{
	int kotype;

	iprintf("%s", io_active(object) ? "active" : "dead");
	printf(", refs=%d", object->io_references);
	printf(", otype=%d", io_otype(object));
	kotype = io_kotype(object);
	if (kotype >= 0 && kotype < IKOT_MAX_TYPE)
		printf(", kotype=%d %s\n", io_kotype(object),
		       ikot_print_array[kotype]);
	else
		printf(", kotype=0x%x %s\n", io_kotype(object),
		       ikot_print_array[IKOT_UNKNOWN]);
}

#endif	/* MACH_KDB */

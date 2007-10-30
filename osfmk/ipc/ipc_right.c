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
 * @OSF_FREE_COPYRIGHT@
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
 *	File:	ipc/ipc_right.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Functions to manipulate IPC capabilities.
 */

#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/port.h>
#include <mach/message.h>
#include <kern/assert.h>
#include <kern/misc_protos.h>
#include <ipc/port.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_hash.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_pset.h>
#include <ipc/ipc_right.h>
#include <ipc/ipc_notify.h>
#include <ipc/ipc_table.h>
#include <security/mac_mach_internal.h>

/*
 *	Routine:	ipc_right_lookup_write
 *	Purpose:
 *		Finds an entry in a space, given the name.
 *	Conditions:
 *		Nothing locked.  If successful, the space is write-locked.
 *	Returns:
 *		KERN_SUCCESS		Found an entry.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	Name doesn't exist in space.
 */

kern_return_t
ipc_right_lookup_write(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_entry_t		*entryp)
{
	ipc_entry_t entry;

	assert(space != IS_NULL);

	is_write_lock(space);

	if (!space->is_active) {
		is_write_unlock(space);
		return KERN_INVALID_TASK;
	}

	if ((entry = ipc_entry_lookup(space, name)) == IE_NULL) {
		is_write_unlock(space);
		return KERN_INVALID_NAME;
	}

	*entryp = entry;
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_right_lookup_two_write
 *	Purpose:
 *		Like ipc_right_lookup except that it returns two
 *		entries for two different names that were looked
 *		up under the same space lock.
 *	Conditions:
 *		Nothing locked.  If successful, the space is write-locked.
 *	Returns:
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	Name doesn't exist in space.
 */

kern_return_t
ipc_right_lookup_two_write(
	ipc_space_t		space,
	mach_port_name_t	name1,
	ipc_entry_t		*entryp1,
	mach_port_name_t	name2,
	ipc_entry_t		*entryp2)
{
	ipc_entry_t entry1;
	ipc_entry_t entry2;

	assert(space != IS_NULL);

	is_write_lock(space);

	if (!space->is_active) {
		is_write_unlock(space);
		return KERN_INVALID_TASK;
	}

	if ((entry1 = ipc_entry_lookup(space, name1)) == IE_NULL) {
		is_write_unlock(space);
		return KERN_INVALID_NAME;
	}
	if ((entry2 = ipc_entry_lookup(space, name2)) == IE_NULL) {
		is_write_unlock(space);
		return KERN_INVALID_NAME;
	}
	*entryp1 = entry1;
	*entryp2 = entry2;
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_right_reverse
 *	Purpose:
 *		Translate (space, object) -> (name, entry).
 *		Only finds send/receive rights.
 *		Returns TRUE if an entry is found; if so,
 *		the object is locked and active.
 *	Conditions:
 *		The space must be locked (read or write) and active.
 *		Nothing else locked.
 */

boolean_t
ipc_right_reverse(
	ipc_space_t		space,
	ipc_object_t		object,
	mach_port_name_t	*namep,
	ipc_entry_t		*entryp)
{
	ipc_port_t port;
	mach_port_name_t name;
	ipc_entry_t entry;

	/* would switch on io_otype to handle multiple types of object */

	assert(space->is_active);
	assert(io_otype(object) == IOT_PORT);

	port = (ipc_port_t) object;

	ip_lock(port);
	if (!ip_active(port)) {
		ip_unlock(port);

		return FALSE;
	}

	if (port->ip_receiver == space) {
		name = port->ip_receiver_name;
		assert(name != MACH_PORT_NULL);

		entry = ipc_entry_lookup(space, name);

		assert(entry != IE_NULL);
		assert(entry->ie_bits & MACH_PORT_TYPE_RECEIVE);
		assert(port == (ipc_port_t) entry->ie_object);

		*namep = name;
		*entryp = entry;
		return TRUE;
	}

	if (ipc_hash_lookup(space, (ipc_object_t) port, namep, entryp)) {
		assert((entry = *entryp) != IE_NULL);
		assert(IE_BITS_TYPE(entry->ie_bits) == MACH_PORT_TYPE_SEND);
		assert(port == (ipc_port_t) entry->ie_object);

		return TRUE;
	}

	ip_unlock(port);
	return FALSE;
}

/*
 *	Routine:	ipc_right_dnrequest
 *	Purpose:
 *		Make a dead-name request, returning the previously
 *		registered send-once right.  If notify is IP_NULL,
 *		just cancels the previously registered request.
 *
 *		This interacts with the IE_BITS_COMPAT, because they
 *		both use ie_request.  If this is a compat entry, then
 *		previous always gets IP_NULL.  If notify is IP_NULL,
 *		then the entry remains a compat entry.  Otherwise
 *		the real dead-name request is registered and the entry
 *		is no longer a compat entry.
 *	Conditions:
 *		Nothing locked.  May allocate memory.
 *		Only consumes/returns refs if successful.
 *	Returns:
 *		KERN_SUCCESS		Made/canceled dead-name request.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_INVALID_NAME	Name doesn't exist in space.
 *		KERN_INVALID_RIGHT	Name doesn't denote port/dead rights.
 *		KERN_INVALID_ARGUMENT	Name denotes dead name, but
 *			immediate is FALSE or notify is IP_NULL.
 *		KERN_UREFS_OVERFLOW	Name denotes dead name, but
 *			generating immediate notif. would overflow urefs.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
ipc_right_dnrequest(
	ipc_space_t		space,
	mach_port_name_t	name,
	boolean_t		immediate,
	ipc_port_t		notify,
	ipc_port_t		*previousp)
{
	ipc_port_t previous;

	for (;;) {
		ipc_entry_t entry;
		ipc_entry_bits_t bits;
		kern_return_t kr;

		kr = ipc_right_lookup_write(space, name, &entry);
		if (kr != KERN_SUCCESS)
			return kr;
		/* space is write-locked and active */
		bits = entry->ie_bits;
		if (bits & MACH_PORT_TYPE_PORT_RIGHTS) {
			ipc_port_t port;
			ipc_port_request_index_t request;

			port = (ipc_port_t) entry->ie_object;
			assert(port != IP_NULL);

			if (!ipc_right_check(space, port, name, entry)) {
				/* port is locked and active */

				if (notify == IP_NULL) {
					previous = ipc_right_dncancel_macro(
						   space, port, name, entry);

					ip_unlock(port);
					is_write_unlock(space);
					break;
				}

				/*
				 *	If a registered soright exists,
				 *	want to atomically switch with it.
				 *	If ipc_port_dncancel finds us a
				 *	soright, then the following
				 *	ipc_port_dnrequest will reuse
				 *	that slot, so we are guaranteed
				 *	not to unlock and retry.
				 */

				previous = ipc_right_dncancel_macro(space,
						port, name, entry);

				kr = ipc_port_dnrequest(port, name, notify,
							&request);
				if (kr != KERN_SUCCESS) {
					assert(previous == IP_NULL);
					is_write_unlock(space);

					kr = ipc_port_dngrow(port,
							     ITS_SIZE_NONE);
					/* port is unlocked */
					if (kr != KERN_SUCCESS)
						return kr;

					continue;
				}

				assert(request != 0);
				ip_unlock(port);

				entry->ie_request = request;
				is_write_unlock(space);
				break;
			} else {

			  /*
			   * Our capability bits were changed by ipc_right_check
			   * because it found an inactive port and removed our
			   * references to it (converting our entry into a dead
			   * one).  Reload the bits (and obviously we can't use
			   * the port name anymore).
			   */
			  bits = entry->ie_bits;

			}

			assert(bits & MACH_PORT_TYPE_DEAD_NAME);
		}

		if ((bits & MACH_PORT_TYPE_DEAD_NAME) &&
		    immediate && (notify != IP_NULL)) {
			mach_port_urefs_t urefs = IE_BITS_UREFS(bits);

			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_DEAD_NAME);
			assert(urefs > 0);

			if (MACH_PORT_UREFS_OVERFLOW(urefs, 1)) {
				is_write_unlock(space);
				return KERN_UREFS_OVERFLOW;
			}

			(entry->ie_bits)++; /* increment urefs */
			is_write_unlock(space);

			ipc_notify_dead_name(notify, name);
			previous = IP_NULL;
			break;
		}

		is_write_unlock(space);
		if (bits & MACH_PORT_TYPE_PORT_OR_DEAD)
			return KERN_INVALID_ARGUMENT;
		else
			return KERN_INVALID_RIGHT;
	}

	*previousp = previous;
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_right_dncancel
 *	Purpose:
 *		Cancel a dead-name request and return the send-once right.
 *		Afterwards, entry->ie_request == 0.
 *	Conditions:
 *		The space must be write-locked; the port must be locked.
 *		The port must be active; the space doesn't have to be.
 */

ipc_port_t
ipc_right_dncancel(
	__unused ipc_space_t		space,
	ipc_port_t			port,
	mach_port_name_t		name,
	ipc_entry_t			entry)
{
	ipc_port_t dnrequest;

	assert(ip_active(port));
	assert(port == (ipc_port_t) entry->ie_object);

	dnrequest = ipc_port_dncancel(port, name, entry->ie_request);
	entry->ie_request = 0;

	return dnrequest;
}

/*
 *	Routine:	ipc_right_inuse
 *	Purpose:
 *		Check if an entry is being used.
 *		Returns TRUE if it is.
 *	Conditions:
 *		The space is write-locked and active.
 *		It is unlocked if the entry is inuse.
 */

boolean_t
ipc_right_inuse(
	ipc_space_t			space,
	__unused mach_port_name_t	name,
	ipc_entry_t			entry)
{
	if (IE_BITS_TYPE(entry->ie_bits) != MACH_PORT_TYPE_NONE) {
		is_write_unlock(space);
		return TRUE;
	}
	return FALSE;
}

/*
 *	Routine:	ipc_right_check
 *	Purpose:
 *		Check if the port has died.  If it has,
 *		clean up the entry and return TRUE.
 *	Conditions:
 *		The space is write-locked; the port is not locked.
 *		If returns FALSE, the port is also locked and active.
 *		Otherwise, entry is converted to a dead name, freeing
 *		a reference to port.
 */

boolean_t
ipc_right_check(
	ipc_space_t		space,
	ipc_port_t		port,
	mach_port_name_t	name,
	ipc_entry_t		entry)
{
	ipc_entry_bits_t bits;

	assert(space->is_active);
	assert(port == (ipc_port_t) entry->ie_object);

	ip_lock(port);
	if (ip_active(port))
		return FALSE;
	ip_unlock(port);

	/* this was either a pure send right or a send-once right */

	bits = entry->ie_bits;
	assert((bits & MACH_PORT_TYPE_RECEIVE) == 0);
	assert(IE_BITS_UREFS(bits) > 0);

	if (bits & MACH_PORT_TYPE_SEND) {   
                assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND);
        } else {
                assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND_ONCE);
                assert(IE_BITS_UREFS(bits) == 1);
        }


	ipc_port_release(port);

	/* convert entry to dead name */

	if ((bits & MACH_PORT_TYPE_SEND) && !(bits & MACH_PORT_TYPE_RECEIVE))
		ipc_hash_delete(space, (ipc_object_t)port, name, entry);

	bits = (bits &~ IE_BITS_TYPE_MASK) | MACH_PORT_TYPE_DEAD_NAME;
	
	/*
	 * If there was a notification request outstanding on this
	 * name, and since the port went dead, that notification
	 * must already be on its way up from the port layer. We
	 * don't need the index of the notification port anymore.
	 *
	 * JMM - We also add a reference to the entry since the
	 * notification only carries the name and NOT a reference
	 * (or right). This makes for pretty loose reference
	 * counting, since it is only happenstance that we
	 * detected the notification in progress like this.
	 * But most (all?) calls that try to deal with this entry
	 * will also come through here, so the reference gets added
	 * before the entry gets used eventually (I would rather it
	 * be explicit in the notification generation, though)
	 */
	if (entry->ie_request != 0) {
		assert(IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX);
		entry->ie_request = 0; 
		bits++;	
	}
	entry->ie_bits = bits;
	entry->ie_object = IO_NULL;
	return TRUE;
}

/*
 *	Routine:	ipc_right_clean
 *	Purpose:
 *		Cleans up an entry in a dead space.
 *		The entry isn't deallocated or removed
 *		from reverse hash tables.
 *	Conditions:
 *		The space is dead and unlocked.
 */

void
ipc_right_clean(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_entry_t		entry)
{
	ipc_entry_bits_t bits;
	mach_port_type_t type;

	bits = entry->ie_bits;
	type = IE_BITS_TYPE(bits);

	assert(!space->is_active);

	/*
	 *	IE_BITS_COMPAT/ipc_right_dncancel doesn't have this
	 *	problem, because we check that the port is active.  If
	 *	we didn't cancel IE_BITS_COMPAT, ipc_port_destroy
	 *	would still work, but dead space refs would accumulate
	 *	in ip_dnrequests.  They would use up slots in
	 *	ip_dnrequests and keep the spaces from being freed.
	 */

	switch (type) {
	    case MACH_PORT_TYPE_DEAD_NAME:
		assert(entry->ie_request == 0);
		assert(entry->ie_object == IO_NULL);
		break;

	    case MACH_PORT_TYPE_PORT_SET: {
		ipc_pset_t pset = (ipc_pset_t) entry->ie_object;

		assert(entry->ie_request == 0);
		assert(pset != IPS_NULL);

		ips_lock(pset);
		assert(ips_active(pset));

		ipc_pset_destroy(pset); /* consumes ref, unlocks */
		break;
	    }

	    case MACH_PORT_TYPE_SEND:
	    case MACH_PORT_TYPE_RECEIVE:
	    case MACH_PORT_TYPE_SEND_RECEIVE:
	    case MACH_PORT_TYPE_SEND_ONCE: {
		ipc_port_t port = (ipc_port_t) entry->ie_object;
		ipc_port_t dnrequest;
		ipc_port_t nsrequest = IP_NULL;
		mach_port_mscount_t mscount = 0;

		assert(port != IP_NULL);
		ip_lock(port);

		if (!ip_active(port)) {
			ip_release(port);
			ip_check_unlock(port);
			break;
		}

		dnrequest = ipc_right_dncancel_macro(space, port, 
					name, entry);

		if (type & MACH_PORT_TYPE_SEND) {
			assert(port->ip_srights > 0);
			if (--port->ip_srights == 0
			    ) {
				nsrequest = port->ip_nsrequest;
				if (nsrequest != IP_NULL) {
					port->ip_nsrequest = IP_NULL;
					mscount = port->ip_mscount;
				}
			}
		}

		if (type & MACH_PORT_TYPE_RECEIVE) {
			assert(port->ip_receiver_name == name);
			assert(port->ip_receiver == space);

			ipc_port_clear_receiver(port);
			ipc_port_destroy(port); /* consumes our ref, unlocks */
		} else if (type & MACH_PORT_TYPE_SEND_ONCE) {
			assert(port->ip_sorights > 0);
			ip_unlock(port);

			ipc_notify_send_once(port); /* consumes our ref */
		} else {
			assert(port->ip_receiver != space);

			ip_release(port);
			ip_unlock(port); /* port is active */
		}

		if (nsrequest != IP_NULL)
			ipc_notify_no_senders(nsrequest, mscount);

		if (dnrequest != IP_NULL)
			ipc_notify_port_deleted(dnrequest, name);
		break;
	    }

	    default:
		panic("ipc_right_clean: strange type");
	}
}

/*
 *	Routine:	ipc_right_destroy
 *	Purpose:
 *		Destroys an entry in a space.
 *	Conditions:
 *		The space is write-locked.
 *		The space must be active.
 *	Returns:
 *		KERN_SUCCESS		The entry was destroyed.
 */

kern_return_t
ipc_right_destroy(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_entry_t		entry)
{
	ipc_entry_bits_t bits;
	mach_port_type_t type;

	bits = entry->ie_bits;
	entry->ie_bits &= ~IE_BITS_TYPE_MASK;
	type = IE_BITS_TYPE(bits);

	assert(space->is_active);

	switch (type) {
	    case MACH_PORT_TYPE_DEAD_NAME:
		assert(entry->ie_request == 0);
		assert(entry->ie_object == IO_NULL);

		ipc_entry_dealloc(space, name, entry);
		break;

	    case MACH_PORT_TYPE_PORT_SET: {
		ipc_pset_t pset = (ipc_pset_t) entry->ie_object;

		assert(entry->ie_request == 0);
		assert(pset != IPS_NULL);

		entry->ie_object = IO_NULL;
		ipc_entry_dealloc(space, name, entry);

		ips_lock(pset);
		assert(ips_active(pset));

		ipc_pset_destroy(pset); /* consumes ref, unlocks */
		break;
	    }

	    case MACH_PORT_TYPE_SEND:
	    case MACH_PORT_TYPE_RECEIVE:
	    case MACH_PORT_TYPE_SEND_RECEIVE:
	    case MACH_PORT_TYPE_SEND_ONCE: {
		ipc_port_t port = (ipc_port_t) entry->ie_object;
		ipc_port_t nsrequest = IP_NULL;
		mach_port_mscount_t mscount = 0;
		ipc_port_t dnrequest;

		assert(port != IP_NULL);

		if (type == MACH_PORT_TYPE_SEND)
			ipc_hash_delete(space, (ipc_object_t) port,
					name, entry);

		ip_lock(port);

		if (!ip_active(port)) {
			assert((type & MACH_PORT_TYPE_RECEIVE) == 0);
			ip_release(port);
			ip_check_unlock(port);

			entry->ie_request = 0;
			entry->ie_object = IO_NULL;
			ipc_entry_dealloc(space, name, entry);

			break;
		}

		dnrequest = ipc_right_dncancel_macro(space, port, name, entry);

		entry->ie_object = IO_NULL;
		ipc_entry_dealloc(space, name, entry);

		if (type & MACH_PORT_TYPE_SEND) {
			assert(port->ip_srights > 0);
			if (--port->ip_srights == 0) {
				nsrequest = port->ip_nsrequest;
				if (nsrequest != IP_NULL) {
					port->ip_nsrequest = IP_NULL;
					mscount = port->ip_mscount;
				}
			}
		}

		if (type & MACH_PORT_TYPE_RECEIVE) {
			assert(ip_active(port));
			assert(port->ip_receiver == space);

			ipc_port_clear_receiver(port);
			ipc_port_destroy(port); /* consumes our ref, unlocks */
		} else if (type & MACH_PORT_TYPE_SEND_ONCE) {
			assert(port->ip_sorights > 0);
			ip_unlock(port);

			ipc_notify_send_once(port); /* consumes our ref */
		} else {
			assert(port->ip_receiver != space);

			ip_release(port);
			ip_unlock(port);
		}

		if (nsrequest != IP_NULL)
			ipc_notify_no_senders(nsrequest, mscount);

		if (dnrequest != IP_NULL)
			ipc_notify_port_deleted(dnrequest, name);
		break;
	    }

	    default:
		panic("ipc_right_destroy: strange type");
	}

	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_right_dealloc
 *	Purpose:
 *		Releases a send/send-once/dead-name user ref.
 *		Like ipc_right_delta with a delta of -1,
 *		but looks at the entry to determine the right.
 *	Conditions:
 *		The space is write-locked, and is unlocked upon return.
 *		The space must be active.
 *	Returns:
 *		KERN_SUCCESS		A user ref was released.
 *		KERN_INVALID_RIGHT	Entry has wrong type.
 */

kern_return_t
ipc_right_dealloc(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_entry_t		entry)
{

	ipc_entry_bits_t bits;
	mach_port_type_t type;

	bits = entry->ie_bits;
	type = IE_BITS_TYPE(bits);


	assert(space->is_active);

	switch (type) {
	    case MACH_PORT_TYPE_DEAD_NAME: {
	    dead_name:

		assert(IE_BITS_UREFS(bits) > 0);
		assert(entry->ie_request == 0);
		assert(entry->ie_object == IO_NULL);

		if (IE_BITS_UREFS(bits) == 1) {
			ipc_entry_dealloc(space, name, entry);
		}
		else
			entry->ie_bits = bits-1; /* decrement urefs */

		is_write_unlock(space);
		break;
	    }

	    case MACH_PORT_TYPE_SEND_ONCE: {
		ipc_port_t port, dnrequest;

		assert(IE_BITS_UREFS(bits) == 1);

		port = (ipc_port_t) entry->ie_object;
		assert(port != IP_NULL);

		if (ipc_right_check(space, port, name, entry)) {

			bits = entry->ie_bits;
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_DEAD_NAME);
			goto dead_name;
		}
		/* port is locked and active */

		assert(port->ip_sorights > 0);

		dnrequest = ipc_right_dncancel_macro(space, port, name, entry);
		ip_unlock(port);

		entry->ie_object = IO_NULL;
		ipc_entry_dealloc(space, name, entry);

		is_write_unlock(space);

		ipc_notify_send_once(port);

		if (dnrequest != IP_NULL)
			ipc_notify_port_deleted(dnrequest, name);
		break;
	    }

	    case MACH_PORT_TYPE_SEND: {
		ipc_port_t port;
		ipc_port_t dnrequest = IP_NULL;
		ipc_port_t nsrequest = IP_NULL;
		mach_port_mscount_t mscount =  0;


		assert(IE_BITS_UREFS(bits) > 0);

		port = (ipc_port_t) entry->ie_object;
		assert(port != IP_NULL);

		if (ipc_right_check(space, port, name, entry)) {
			bits = entry->ie_bits;
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_DEAD_NAME);
			goto dead_name;
		}
		/* port is locked and active */

		assert(port->ip_srights > 0);

		if (IE_BITS_UREFS(bits) == 1) {
			if (--port->ip_srights == 0) {
				nsrequest = port->ip_nsrequest;
				if (nsrequest != IP_NULL) {
					port->ip_nsrequest = IP_NULL;
					mscount = port->ip_mscount;
				}
			}

			dnrequest = ipc_right_dncancel_macro(space, port,
							     name, entry);
			ipc_hash_delete(space, (ipc_object_t) port,
					name, entry);

			ip_release(port);
			entry->ie_object = IO_NULL;
			ipc_entry_dealloc(space, name, entry);

		} else
			entry->ie_bits = bits-1; /* decrement urefs */

		/* even if dropped a ref, port is active */
		ip_unlock(port);
		is_write_unlock(space);

		if (nsrequest != IP_NULL)
			ipc_notify_no_senders(nsrequest, mscount);

		if (dnrequest != IP_NULL)
			ipc_notify_port_deleted(dnrequest, name);
		break;
	    }

	    case MACH_PORT_TYPE_SEND_RECEIVE: {
		ipc_port_t port;
		ipc_port_t nsrequest = IP_NULL;
		mach_port_mscount_t mscount = 0;

		assert(IE_BITS_UREFS(bits) > 0);

		port = (ipc_port_t) entry->ie_object;
		assert(port != IP_NULL);

		ip_lock(port);
		assert(ip_active(port));
		assert(port->ip_receiver_name == name);
		assert(port->ip_receiver == space);
		assert(port->ip_srights > 0);

		if (IE_BITS_UREFS(bits) == 1) {
			if (--port->ip_srights == 0) {
				nsrequest = port->ip_nsrequest;
				if (nsrequest != IP_NULL) {
					port->ip_nsrequest = IP_NULL;
					mscount = port->ip_mscount;
				}
			}

			entry->ie_bits = bits &~ (IE_BITS_UREFS_MASK |
						  MACH_PORT_TYPE_SEND);
		} else
			entry->ie_bits = bits-1; /* decrement urefs */

		ip_unlock(port);
		is_write_unlock(space);

		if (nsrequest != IP_NULL)
			ipc_notify_no_senders(nsrequest, mscount);
		break;
	    }

	    default:
		is_write_unlock(space);
		return KERN_INVALID_RIGHT;
	}

	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_right_delta
 *	Purpose:
 *		Modifies the user-reference count for a right.
 *		May deallocate the right, if the count goes to zero.
 *	Conditions:
 *		The space is write-locked, and is unlocked upon return.
 *		The space must be active.
 *	Returns:
 *		KERN_SUCCESS		Count was modified.
 *		KERN_INVALID_RIGHT	Entry has wrong type.
 *		KERN_INVALID_VALUE	Bad delta for the right.
 *		KERN_UREFS_OVERFLOW	OK delta, except would overflow.
 */

kern_return_t
ipc_right_delta(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_entry_t		entry,
	mach_port_right_t	right,
	mach_port_delta_t	delta)
{
	ipc_entry_bits_t bits;
	
	bits = entry->ie_bits;


/*
 *	The following is used (for case MACH_PORT_RIGHT_DEAD_NAME) in the
 *	switch below. It is used to keep track of those cases (in DIPC)
 *	where we have postponed the dropping of a port reference. Since
 *	the dropping of the reference could cause the port to disappear
 *	we postpone doing so when we are holding the space lock.
 */

	assert(space->is_active);
	assert(right < MACH_PORT_RIGHT_NUMBER);

	/* Rights-specific restrictions and operations. */

	switch (right) {
	    case MACH_PORT_RIGHT_PORT_SET: {
		ipc_pset_t pset;

		if ((bits & MACH_PORT_TYPE_PORT_SET) == 0)
			goto invalid_right;

		assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_PORT_SET);
		assert(IE_BITS_UREFS(bits) == 0);
		assert(entry->ie_request == 0);

		if (delta == 0)
			goto success;

		if (delta != -1)
			goto invalid_value;

		pset = (ipc_pset_t) entry->ie_object;
		assert(pset != IPS_NULL);



		entry->ie_object = IO_NULL;
		ipc_entry_dealloc(space, name, entry);


		ips_lock(pset);
		assert(ips_active(pset));
		is_write_unlock(space);

		ipc_pset_destroy(pset); /* consumes ref, unlocks */
		break;
	    }

	    case MACH_PORT_RIGHT_RECEIVE: {
		ipc_port_t port;
		ipc_port_t dnrequest = IP_NULL;

		if ((bits & MACH_PORT_TYPE_RECEIVE) == 0)
			goto invalid_right;

		if (delta == 0)
			goto success;

		if (delta != -1)
			goto invalid_value;

		port = (ipc_port_t) entry->ie_object;
		assert(port != IP_NULL);

		/*
		 *	The port lock is needed for ipc_right_dncancel;
		 *	otherwise, we wouldn't have to take the lock
		 *	until just before dropping the space lock.
		 */

		ip_lock(port);
		assert(ip_active(port));
		assert(port->ip_receiver_name == name);
		assert(port->ip_receiver == space);

		if (bits & MACH_PORT_TYPE_SEND) {
			assert(IE_BITS_TYPE(bits) ==
					MACH_PORT_TYPE_SEND_RECEIVE);
			assert(IE_BITS_UREFS(bits) > 0);
			assert(IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX);
			assert(port->ip_srights > 0);

			/*
			 *	The remaining send right turns into a
			 *	dead name.  Notice we don't decrement
			 *	ip_srights, generate a no-senders notif,
			 *	or use ipc_right_dncancel, because the
			 *	port is destroyed "first".
			 */
			bits &= ~IE_BITS_TYPE_MASK;
			bits |= MACH_PORT_TYPE_DEAD_NAME;
			if (entry->ie_request) {
				entry->ie_request = 0;
				bits++;
			}
			entry->ie_bits = bits;
			entry->ie_object = IO_NULL;
		} else {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_RECEIVE);
			assert(IE_BITS_UREFS(bits) == 0);

			dnrequest = ipc_right_dncancel_macro(space, port,
							     name, entry);
			entry->ie_object = IO_NULL;
			ipc_entry_dealloc(space, name, entry);
		}
		is_write_unlock(space);

		ipc_port_clear_receiver(port);
		ipc_port_destroy(port);	/* consumes ref, unlocks */

		if (dnrequest != IP_NULL)
			ipc_notify_port_deleted(dnrequest, name);
		break;
	    }

	    case MACH_PORT_RIGHT_SEND_ONCE: {
		ipc_port_t port, dnrequest;

		if ((bits & MACH_PORT_TYPE_SEND_ONCE) == 0)
			goto invalid_right;

		assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND_ONCE);
		assert(IE_BITS_UREFS(bits) == 1);

		port = (ipc_port_t) entry->ie_object;
		assert(port != IP_NULL);

		if (ipc_right_check(space, port, name, entry)) {
			assert(!(entry->ie_bits & MACH_PORT_TYPE_SEND_ONCE));
			goto invalid_right;
		}
		/* port is locked and active */

		assert(port->ip_sorights > 0);

		if ((delta > 0) || (delta < -1)) {
			ip_unlock(port);
			goto invalid_value;
		}

		if (delta == 0) {
			ip_unlock(port);
			goto success;
		}

		dnrequest = ipc_right_dncancel_macro(space, port, name, entry);
		ip_unlock(port);

		entry->ie_object = IO_NULL;
		ipc_entry_dealloc(space, name, entry);

		is_write_unlock(space);

		ipc_notify_send_once(port);

		if (dnrequest != IP_NULL)
			ipc_notify_port_deleted(dnrequest, name);
		break;
	    }

	    case MACH_PORT_RIGHT_DEAD_NAME: {
		mach_port_urefs_t urefs;

		if (bits & MACH_PORT_TYPE_SEND_RIGHTS) {
			ipc_port_t port;

			port = (ipc_port_t) entry->ie_object;
			assert(port != IP_NULL);

			if (!ipc_right_check(space, port, name, entry)) {
				/* port is locked and active */
				ip_unlock(port);
				goto invalid_right;
			}
			bits = entry->ie_bits;
		} else if ((bits & MACH_PORT_TYPE_DEAD_NAME) == 0)
			goto invalid_right;

		assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_DEAD_NAME);
		assert(IE_BITS_UREFS(bits) > 0);
		assert(entry->ie_object == IO_NULL);
		assert(entry->ie_request == 0);

		urefs = IE_BITS_UREFS(bits);
		if (MACH_PORT_UREFS_UNDERFLOW(urefs, delta))
			goto invalid_value;
		if (MACH_PORT_UREFS_OVERFLOW(urefs, delta))
			goto urefs_overflow;

		if ((urefs + delta) == 0) {
			ipc_entry_dealloc(space, name, entry);
		}
		else
			entry->ie_bits = bits + delta;

		is_write_unlock(space);

		break;
	    }

	    case MACH_PORT_RIGHT_SEND: {
		mach_port_urefs_t urefs;
		ipc_port_t port;
		ipc_port_t dnrequest = IP_NULL;
		ipc_port_t nsrequest = IP_NULL;
		mach_port_mscount_t mscount = 0;

		if ((bits & MACH_PORT_TYPE_SEND) == 0)
			goto invalid_right;

		/* maximum urefs for send is MACH_PORT_UREFS_MAX-1 */

		port = (ipc_port_t) entry->ie_object;
		assert(port != IP_NULL);

		if (ipc_right_check(space, port, name, entry)) {
			assert((entry->ie_bits & MACH_PORT_TYPE_SEND) == 0);
			goto invalid_right;
		}
		/* port is locked and active */

		assert(port->ip_srights > 0);

		urefs = IE_BITS_UREFS(bits);
		if (MACH_PORT_UREFS_UNDERFLOW(urefs, delta)) {
			ip_unlock(port);
			goto invalid_value;
		}
		if (MACH_PORT_UREFS_OVERFLOW(urefs+1, delta)) {
			ip_unlock(port);
			goto urefs_overflow;
		}

		if ((urefs + delta) == 0) {
			if (--port->ip_srights == 0) {
				nsrequest = port->ip_nsrequest;
				if (nsrequest != IP_NULL) {
					port->ip_nsrequest = IP_NULL;
					mscount = port->ip_mscount;
				}
			}

			if (bits & MACH_PORT_TYPE_RECEIVE) {
				assert(port->ip_receiver_name == name);
				assert(port->ip_receiver == space);
				assert(IE_BITS_TYPE(bits) ==
						MACH_PORT_TYPE_SEND_RECEIVE);

				entry->ie_bits = bits &~ (IE_BITS_UREFS_MASK|
						       MACH_PORT_TYPE_SEND);
			} else {
				assert(IE_BITS_TYPE(bits) ==
						MACH_PORT_TYPE_SEND);

				dnrequest = ipc_right_dncancel_macro(space, port,
								     name, entry);
				ipc_hash_delete(space, (ipc_object_t) port,
						name, entry);

				ip_release(port);

				entry->ie_object = IO_NULL;
				ipc_entry_dealloc(space, name, entry);
			}
		} else
			entry->ie_bits = bits + delta;

		/* even if dropped a ref, port is active */
		ip_unlock(port);
		is_write_unlock(space);

		if (nsrequest != IP_NULL)
			ipc_notify_no_senders(nsrequest, mscount);

		if (dnrequest != IP_NULL)
			ipc_notify_port_deleted(dnrequest, name);
		break;
	    }

	    default:
		panic("ipc_right_delta: strange right");
	}

	return KERN_SUCCESS;

    success:
	is_write_unlock(space);
	return KERN_SUCCESS;

    invalid_right:
	is_write_unlock(space);
	return KERN_INVALID_RIGHT;

    invalid_value:
	is_write_unlock(space);
	return KERN_INVALID_VALUE;

    urefs_overflow:
	is_write_unlock(space);
	return KERN_UREFS_OVERFLOW;
}

/*
 *	Routine:	ipc_right_info
 *	Purpose:
 *		Retrieves information about the right.
 *	Conditions:
 *		The space is write-locked, and is unlocked upon return
 *		if the call is unsuccessful.  The space must be active.
 *	Returns:
 *		KERN_SUCCESS		Retrieved info; space still locked.
 */

kern_return_t
ipc_right_info(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_entry_t		entry,
	mach_port_type_t	*typep,
	mach_port_urefs_t	*urefsp)
{
	ipc_entry_bits_t bits;
	mach_port_type_t type;
	ipc_port_request_index_t request;

	bits = entry->ie_bits;

	if (bits & MACH_PORT_TYPE_SEND_RIGHTS) {
		ipc_port_t port = (ipc_port_t) entry->ie_object;

		if (ipc_right_check(space, port, name, entry)) {
			bits = entry->ie_bits;
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_DEAD_NAME);
		} else
			ip_unlock(port);
	}

	type = IE_BITS_TYPE(bits);
	request = entry->ie_request;

	if (request != 0)
		type |= MACH_PORT_TYPE_DNREQUEST;

	*typep = type;
	*urefsp = IE_BITS_UREFS(bits);
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_right_copyin_check
 *	Purpose:
 *		Check if a subsequent ipc_right_copyin would succeed.
 *	Conditions:
 *		The space is locked (read or write) and active.
 */

boolean_t
ipc_right_copyin_check(
	__assert_only ipc_space_t	space,
	__unused mach_port_name_t	name,
	ipc_entry_t			entry,
	mach_msg_type_name_t		msgt_name)
{
	ipc_entry_bits_t bits;
	ipc_port_t port;
#if CONFIG_MACF_MACH
	task_t self = current_task();
	int rc = 0;
#endif

	bits= entry->ie_bits;
	assert(space->is_active);

	switch (msgt_name) {
	    case MACH_MSG_TYPE_MAKE_SEND:
		if ((bits & MACH_PORT_TYPE_RECEIVE) == 0)
			return FALSE;

#if CONFIG_MACF_MACH
		port = (ipc_port_t) entry->ie_object;
		ip_lock(port);
		tasklabel_lock(self);
		rc = mac_port_check_make_send(&self->maclabel, &port->ip_label);                tasklabel_unlock(self);
		ip_unlock(port);
		if (rc)
			return FALSE;
#endif
		break;

	    case MACH_MSG_TYPE_MAKE_SEND_ONCE:
		if ((bits & MACH_PORT_TYPE_RECEIVE) == 0)
			return FALSE;

#if CONFIG_MACF_MACH
		port = (ipc_port_t) entry->ie_object;
		ip_lock(port);
		tasklabel_lock(self);
		rc = mac_port_check_make_send_once(&self->maclabel, &port->ip_label);
		tasklabel_unlock(self);
		ip_unlock(port);
		if (rc)
			return FALSE;
#endif
		break;

	    case MACH_MSG_TYPE_MOVE_RECEIVE:
		if ((bits & MACH_PORT_TYPE_RECEIVE) == 0)
			return FALSE;

#if CONFIG_MACF_MACH
		port = (ipc_port_t) entry->ie_object;
		ip_lock(port);
		tasklabel_lock(self);
		rc = mac_port_check_move_receive(&self->maclabel, &port->ip_label);
		tasklabel_unlock(self);
		ip_unlock(port);
		if (rc)
                        return FALSE;
#endif
		break;

	    case MACH_MSG_TYPE_COPY_SEND:
	    case MACH_MSG_TYPE_MOVE_SEND:
	    case MACH_MSG_TYPE_MOVE_SEND_ONCE: {
		boolean_t active;

		if (bits & MACH_PORT_TYPE_DEAD_NAME)
			break;

		if ((bits & MACH_PORT_TYPE_SEND_RIGHTS) == 0)
			return FALSE;

		port = (ipc_port_t) entry->ie_object;
		assert(port != IP_NULL);

		ip_lock(port);
		active = ip_active(port);
#if CONFIG_MACF_MACH
		tasklabel_lock(self);
		switch (msgt_name) {
		case MACH_MSG_TYPE_COPY_SEND:
			rc = mac_port_check_copy_send(&self->maclabel,
			    &port->ip_label);
			break;
		case MACH_MSG_TYPE_MOVE_SEND:
			rc = mac_port_check_move_send(&self->maclabel,
			    &port->ip_label);
			break;
		case MACH_MSG_TYPE_MOVE_SEND_ONCE:
			rc = mac_port_check_move_send_once(&self->maclabel,
			    &port->ip_label);
			break;
		default:
			panic("ipc_right_copyin_check: strange rights");
		}
		tasklabel_unlock(self);
		if (rc) {
			ip_unlock(port);
			return FALSE;
		}
#endif
		ip_unlock(port);

		if (!active) {
			break;
		}

		if (msgt_name == MACH_MSG_TYPE_MOVE_SEND_ONCE) {
			if ((bits & MACH_PORT_TYPE_SEND_ONCE) == 0)
				return FALSE;
		} else {
			if ((bits & MACH_PORT_TYPE_SEND) == 0)
				return FALSE;
		}

		break;
	    }

	    default:
		panic("ipc_right_copyin_check: strange rights");
	}

	return TRUE;
}

/*
 *	Routine:	ipc_right_copyin
 *	Purpose:
 *		Copyin a capability from a space.
 *		If successful, the caller gets a ref
 *		for the resulting object, unless it is IO_DEAD,
 *		and possibly a send-once right which should
 *		be used in a port-deleted notification.
 *
 *		If deadok is not TRUE, the copyin operation
 *		will fail instead of producing IO_DEAD.
 *
 *		The entry is never deallocated (except
 *		when KERN_INVALID_NAME), so the caller
 *		should deallocate the entry if its type
 *		is MACH_PORT_TYPE_NONE.
 *	Conditions:
 *		The space is write-locked and active.
 *	Returns:
 *		KERN_SUCCESS		Acquired an object, possibly IO_DEAD.
 *		KERN_INVALID_RIGHT	Name doesn't denote correct right.
 */

kern_return_t
ipc_right_copyin(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_entry_t		entry,
	mach_msg_type_name_t	msgt_name,
	boolean_t		deadok,
	ipc_object_t		*objectp,
	ipc_port_t		*sorightp)
{
	ipc_entry_bits_t bits;
#if CONFIG_MACF_MACH
	task_t self = current_task();
	int    rc;
#endif
	
	bits = entry->ie_bits;

	assert(space->is_active);

	switch (msgt_name) {
	    case MACH_MSG_TYPE_MAKE_SEND: {
		ipc_port_t port;

		if ((bits & MACH_PORT_TYPE_RECEIVE) == 0)
			goto invalid_right;

		port = (ipc_port_t) entry->ie_object;
		assert(port != IP_NULL);

		ip_lock(port);
		assert(ip_active(port));
		assert(port->ip_receiver_name == name);
		assert(port->ip_receiver == space);

#if CONFIG_MACF_MACH
		tasklabel_lock(self);
		rc = mac_port_check_make_send(&self->maclabel, &port->ip_label);
		tasklabel_unlock(self);
		if (rc) {
			ip_unlock(port);
			return KERN_NO_ACCESS;
		}
#endif

		port->ip_mscount++;
		port->ip_srights++;
		ip_reference(port);
		ip_unlock(port);

		*objectp = (ipc_object_t) port;
		*sorightp = IP_NULL;
		break;
	    }

	    case MACH_MSG_TYPE_MAKE_SEND_ONCE: {
		ipc_port_t port;

		if ((bits & MACH_PORT_TYPE_RECEIVE) == 0)
			goto invalid_right;

		port = (ipc_port_t) entry->ie_object;
		assert(port != IP_NULL);

		ip_lock(port);
		assert(ip_active(port));
		assert(port->ip_receiver_name == name);
		assert(port->ip_receiver == space);

#if CONFIG_MACF_MACH
		tasklabel_lock(self);
		rc = mac_port_check_make_send_once(&self->maclabel, &port->ip_label);
		tasklabel_unlock(self);
		if (rc) {
			ip_unlock(port);
			return KERN_NO_ACCESS;
		}
#endif

		port->ip_sorights++;
		ip_reference(port);
		ip_unlock(port);

		*objectp = (ipc_object_t) port;
		*sorightp = IP_NULL;
		break;
	    }

	    case MACH_MSG_TYPE_MOVE_RECEIVE: {
		ipc_port_t port;
		ipc_port_t dnrequest = IP_NULL;

		if ((bits & MACH_PORT_TYPE_RECEIVE) == 0)
			goto invalid_right;

		port = (ipc_port_t) entry->ie_object;
		assert(port != IP_NULL);

		ip_lock(port);
		assert(ip_active(port));
		assert(port->ip_receiver_name == name);
		assert(port->ip_receiver == space);

#if CONFIG_MACF_MACH
		tasklabel_lock(self);
		rc = mac_port_check_move_receive(&self->maclabel,
						 &port->ip_label);
		tasklabel_unlock(self);
		if (rc) {
			ip_unlock(port);
			return KERN_NO_ACCESS;
		}
#endif

		if (bits & MACH_PORT_TYPE_SEND) {
			assert(IE_BITS_TYPE(bits) ==
					MACH_PORT_TYPE_SEND_RECEIVE);
			assert(IE_BITS_UREFS(bits) > 0);
			assert(port->ip_srights > 0);

			ipc_hash_insert(space, (ipc_object_t) port,
					name, entry);
			ip_reference(port);
		} else {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_RECEIVE);
			assert(IE_BITS_UREFS(bits) == 0);

			dnrequest = ipc_right_dncancel_macro(space, port,
							     name, entry);
			entry->ie_object = IO_NULL;
		}
		entry->ie_bits = bits &~ MACH_PORT_TYPE_RECEIVE;

		ipc_port_clear_receiver(port);

		port->ip_receiver_name = MACH_PORT_NULL;
		port->ip_destination = IP_NULL;
		ip_unlock(port);

		*objectp = (ipc_object_t) port;
		*sorightp = dnrequest;
		break;
	    }

	    case MACH_MSG_TYPE_COPY_SEND: {
		ipc_port_t port;

		if (bits & MACH_PORT_TYPE_DEAD_NAME)
			goto copy_dead;

		/* allow for dead send-once rights */

		if ((bits & MACH_PORT_TYPE_SEND_RIGHTS) == 0)
			goto invalid_right;

		assert(IE_BITS_UREFS(bits) > 0);

		port = (ipc_port_t) entry->ie_object;
		assert(port != IP_NULL);

		if (ipc_right_check(space, port, name, entry)) {
			bits = entry->ie_bits;
			goto copy_dead;
		}
		/* port is locked and active */

#if CONFIG_MACF_MACH
		tasklabel_lock(self);
		rc = mac_port_check_copy_send(&self->maclabel, &port->ip_label);
		tasklabel_unlock(self);
		if (rc) {
			ip_unlock(port);
			return KERN_NO_ACCESS;
		}
#endif

		if ((bits & MACH_PORT_TYPE_SEND) == 0) {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND_ONCE);
			assert(port->ip_sorights > 0);

			ip_unlock(port);
			goto invalid_right;
		}

		assert(port->ip_srights > 0);

		port->ip_srights++;
		ip_reference(port);
		ip_unlock(port);

		*objectp = (ipc_object_t) port;
		*sorightp = IP_NULL;
		break;
	    }

	    case MACH_MSG_TYPE_MOVE_SEND: {
		ipc_port_t port;
		ipc_port_t dnrequest = IP_NULL;

		if (bits & MACH_PORT_TYPE_DEAD_NAME)
			goto move_dead;

		/* allow for dead send-once rights */

		if ((bits & MACH_PORT_TYPE_SEND_RIGHTS) == 0)
			goto invalid_right;

		assert(IE_BITS_UREFS(bits) > 0);

		port = (ipc_port_t) entry->ie_object;
		assert(port != IP_NULL);

		if (ipc_right_check(space, port, name, entry)) {
			bits = entry->ie_bits;
			goto move_dead;
		}
		/* port is locked and active */

#if CONFIG_MACF_MACH
		tasklabel_lock (self);
		rc = mac_port_check_copy_send (&self->maclabel, &port->ip_label);
		tasklabel_unlock (self);
		if (rc)
		  {
		    ip_unlock (port);
		    return KERN_NO_ACCESS;
		  }
#endif

		if ((bits & MACH_PORT_TYPE_SEND) == 0) {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND_ONCE);
			assert(port->ip_sorights > 0);

			ip_unlock(port);
			goto invalid_right;
		}

		assert(port->ip_srights > 0);

		if (IE_BITS_UREFS(bits) == 1) {
			if (bits & MACH_PORT_TYPE_RECEIVE) {
				assert(port->ip_receiver_name == name);
				assert(port->ip_receiver == space);
				assert(IE_BITS_TYPE(bits) ==
						MACH_PORT_TYPE_SEND_RECEIVE);

				ip_reference(port);
			} else {
				assert(IE_BITS_TYPE(bits) ==
						MACH_PORT_TYPE_SEND);

				dnrequest = ipc_right_dncancel_macro(space, port,
								     name, entry);
				ipc_hash_delete(space, (ipc_object_t) port,
						name, entry);
				entry->ie_object = IO_NULL;
			}
			entry->ie_bits = bits &~
				(IE_BITS_UREFS_MASK|MACH_PORT_TYPE_SEND);
		} else {
			port->ip_srights++;
			ip_reference(port);
			entry->ie_bits = bits-1; /* decrement urefs */
		}

		ip_unlock(port);

		*objectp = (ipc_object_t) port;
		*sorightp = dnrequest;
		break;
	    }

	    case MACH_MSG_TYPE_MOVE_SEND_ONCE: {
		ipc_port_t port;
		ipc_port_t dnrequest;

		if (bits & MACH_PORT_TYPE_DEAD_NAME)
			goto move_dead;

		/* allow for dead send rights */

		if ((bits & MACH_PORT_TYPE_SEND_RIGHTS) == 0)
			goto invalid_right;

		assert(IE_BITS_UREFS(bits) > 0);

		port = (ipc_port_t) entry->ie_object;
		assert(port != IP_NULL);

		if (ipc_right_check(space, port, name, entry)) {
			bits = entry->ie_bits;
			goto move_dead;
		}
		/* port is locked and active */

#if CONFIG_MACF_MACH
		tasklabel_lock (self);
		rc = mac_port_check_copy_send (&self->maclabel, &port->ip_label);
		tasklabel_unlock (self);
		if (rc)
		  {
		    ip_unlock (port);
		    return KERN_NO_ACCESS;
		  }
#endif

		if ((bits & MACH_PORT_TYPE_SEND_ONCE) == 0) {
			assert(bits & MACH_PORT_TYPE_SEND);
			assert(port->ip_srights > 0);

			ip_unlock(port);
			goto invalid_right;
		}

		assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND_ONCE);
		assert(IE_BITS_UREFS(bits) == 1);
		assert(port->ip_sorights > 0);

		dnrequest = ipc_right_dncancel_macro(space, port, name, entry);
		ip_unlock(port);

		entry->ie_object = IO_NULL;
		entry->ie_bits = bits &~
			(IE_BITS_UREFS_MASK | MACH_PORT_TYPE_SEND_ONCE);

		*objectp = (ipc_object_t) port;
		*sorightp = dnrequest;
		break;
	    }

	    default:
	    invalid_right:
		return KERN_INVALID_RIGHT;
	}

	return KERN_SUCCESS;

    copy_dead:
	assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_DEAD_NAME);
	assert(IE_BITS_UREFS(bits) > 0);
	assert(entry->ie_request == 0);
	assert(entry->ie_object == 0);

	if (!deadok)
		goto invalid_right;

	*objectp = IO_DEAD;
	*sorightp = IP_NULL;
	return KERN_SUCCESS;

    move_dead:
	assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_DEAD_NAME);
	assert(IE_BITS_UREFS(bits) > 0);
	assert(entry->ie_request == 0);
	assert(entry->ie_object == 0);

	if (!deadok)
		goto invalid_right;

	if (IE_BITS_UREFS(bits) == 1) {
		bits &= ~MACH_PORT_TYPE_DEAD_NAME;
	}
	entry->ie_bits = bits-1; /* decrement urefs */

	*objectp = IO_DEAD;
	*sorightp = IP_NULL;
	return KERN_SUCCESS;

}

/*
 *	Routine:	ipc_right_copyin_undo
 *	Purpose:
 *		Undoes the effects of an ipc_right_copyin
 *		of a send/send-once right that is dead.
 *		(Object is either IO_DEAD or a dead port.)
 *	Conditions:
 *		The space is write-locked and active.
 */

void
ipc_right_copyin_undo(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_entry_t		entry,
	mach_msg_type_name_t	msgt_name,
	ipc_object_t		object,
	ipc_port_t		soright)
{
	ipc_entry_bits_t bits;

	bits = entry->ie_bits;

	assert(space->is_active);

	assert((msgt_name == MACH_MSG_TYPE_MOVE_SEND) ||
	       (msgt_name == MACH_MSG_TYPE_COPY_SEND) ||
	       (msgt_name == MACH_MSG_TYPE_MOVE_SEND_ONCE));

	if (soright != IP_NULL) {
		assert((msgt_name == MACH_MSG_TYPE_MOVE_SEND) ||
		       (msgt_name == MACH_MSG_TYPE_MOVE_SEND_ONCE));
		assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_NONE);
		assert(object != IO_DEAD);

		entry->ie_bits = ((bits &~ IE_BITS_RIGHT_MASK) |
				  MACH_PORT_TYPE_DEAD_NAME | 2);

	} else if (IE_BITS_TYPE(bits) == MACH_PORT_TYPE_NONE) {
		assert((msgt_name == MACH_MSG_TYPE_MOVE_SEND) ||
		       (msgt_name == MACH_MSG_TYPE_MOVE_SEND_ONCE));

		entry->ie_bits = ((bits &~ IE_BITS_RIGHT_MASK) |
				  MACH_PORT_TYPE_DEAD_NAME | 1);
	} else if (IE_BITS_TYPE(bits) == MACH_PORT_TYPE_DEAD_NAME) {
		assert(object == IO_DEAD);
		assert(IE_BITS_UREFS(bits) > 0);

		if (msgt_name != MACH_MSG_TYPE_COPY_SEND) {
			assert(IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX);
			entry->ie_bits = bits+1; /* increment urefs */
		}
	} else {
		assert((msgt_name == MACH_MSG_TYPE_MOVE_SEND) ||
		       (msgt_name == MACH_MSG_TYPE_COPY_SEND));
		assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND);
		assert(object != IO_DEAD);
		assert(entry->ie_object == object);
		assert(IE_BITS_UREFS(bits) > 0);

		if (msgt_name != MACH_MSG_TYPE_COPY_SEND) {
			assert(IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX-1);
			entry->ie_bits = bits+1; /* increment urefs */
		}

		/*
		 *	May as well convert the entry to a dead name.
		 *	(Or if it is a compat entry, destroy it.)
		 */

		(void) ipc_right_check(space, (ipc_port_t) object,
				       name, entry);
		/* object is dead so it is not locked */
	}

	/* release the reference acquired by copyin */

	if (object != IO_DEAD)
		ipc_object_release(object);
}

/*
 *	Routine:	ipc_right_copyin_two
 *	Purpose:
 *		Like ipc_right_copyin with MACH_MSG_TYPE_MOVE_SEND
 *		and deadok == FALSE, except that this moves two
 *		send rights at once.
 *	Conditions:
 *		The space is write-locked and active.
 *		The object is returned with two refs/send rights.
 *	Returns:
 *		KERN_SUCCESS		Acquired an object.
 *		KERN_INVALID_RIGHT	Name doesn't denote correct right.
 */

kern_return_t
ipc_right_copyin_two(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_entry_t		entry,
	ipc_object_t		*objectp,
	ipc_port_t		*sorightp)
{
	ipc_entry_bits_t bits;
	mach_port_urefs_t urefs;
	ipc_port_t port;
	ipc_port_t dnrequest = IP_NULL;
#if CONFIG_MACF_MACH
	task_t self = current_task();
	int    rc;
#endif

	assert(space->is_active);

	bits = entry->ie_bits;

	if ((bits & MACH_PORT_TYPE_SEND) == 0)
		goto invalid_right;

	urefs = IE_BITS_UREFS(bits);
	if (urefs < 2)
		goto invalid_right;

	port = (ipc_port_t) entry->ie_object;
	assert(port != IP_NULL);

	if (ipc_right_check(space, port, name, entry)) {
		goto invalid_right;
	}
	/* port is locked and active */

#if CONFIG_MACF_MACH
	tasklabel_lock(self);
	rc = mac_port_check_copy_send(&self->maclabel, &port->ip_label);
	tasklabel_unlock(self);
	if (rc) {
		ip_unlock(port);
		return KERN_NO_ACCESS;
	}
#endif

	assert(port->ip_srights > 0);

	if (urefs == 2) {
		if (bits & MACH_PORT_TYPE_RECEIVE) {
			assert(port->ip_receiver_name == name);
			assert(port->ip_receiver == space);
			assert(IE_BITS_TYPE(bits) ==
					MACH_PORT_TYPE_SEND_RECEIVE);

			port->ip_srights++;
			ip_reference(port);
			ip_reference(port);
		} else {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND);

			dnrequest = ipc_right_dncancel_macro(space, port,
							     name, entry);

			port->ip_srights++;
			ip_reference(port);
			ipc_hash_delete(space, (ipc_object_t) port,
					name, entry);
			entry->ie_object = IO_NULL;
		}
		entry->ie_bits = bits &~ (IE_BITS_UREFS_MASK|MACH_PORT_TYPE_SEND);
	} else {
		port->ip_srights += 2;
		ip_reference(port);
		ip_reference(port);
		entry->ie_bits = bits-2; /* decrement urefs */
	}
	ip_unlock(port);

	*objectp = (ipc_object_t) port;
	*sorightp = dnrequest;
	return KERN_SUCCESS;

    invalid_right:
	return KERN_INVALID_RIGHT;
}

/*
 *	Routine:	ipc_right_copyout
 *	Purpose:
 *		Copyout a capability to a space.
 *		If successful, consumes a ref for the object.
 *
 *		Always succeeds when given a newly-allocated entry,
 *		because user-reference overflow isn't a possibility.
 *
 *		If copying out the object would cause the user-reference
 *		count in the entry to overflow, and overflow is TRUE,
 *		then instead the user-reference count is left pegged
 *		to its maximum value and the copyout succeeds anyway.
 *	Conditions:
 *		The space is write-locked and active.
 *		The object is locked and active.
 *		The object is unlocked; the space isn't.
 *	Returns:
 *		KERN_SUCCESS		Copied out capability.
 *		KERN_UREFS_OVERFLOW	User-refs would overflow;
 *			guaranteed not to happen with a fresh entry
 *			or if overflow=TRUE was specified.
 */

kern_return_t
ipc_right_copyout(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_entry_t		entry,
	mach_msg_type_name_t	msgt_name,
	boolean_t		overflow,
	ipc_object_t		object)
{
	ipc_entry_bits_t bits;
	ipc_port_t port;
#if CONFIG_MACF_MACH
	int rc;
#endif

	bits = entry->ie_bits;

	assert(IO_VALID(object));
	assert(io_otype(object) == IOT_PORT);
	assert(io_active(object));
	assert(entry->ie_object == object);

	port = (ipc_port_t) object;

	switch (msgt_name) {
	    case MACH_MSG_TYPE_PORT_SEND_ONCE:
		
		assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_NONE);
		assert(port->ip_sorights > 0);

#if CONFIG_MACF_MACH
		if (space->is_task) {
			tasklabel_lock(space->is_task);
			rc = mac_port_check_hold_send_once(&space->is_task->maclabel,
							   &port->ip_label);
			tasklabel_unlock(space->is_task);

			if (rc) {
				ip_unlock(port);
				return KERN_NO_ACCESS;
			}
		}
#endif
		/* transfer send-once right and ref to entry */
		ip_unlock(port);

		entry->ie_bits = bits | (MACH_PORT_TYPE_SEND_ONCE | 1);
		break;

	    case MACH_MSG_TYPE_PORT_SEND:
		assert(port->ip_srights > 0);

#if CONFIG_MACF_MACH
		if (space->is_task) {
			tasklabel_lock(space->is_task);
			rc = mac_port_check_hold_send(&space->is_task->maclabel,
						      &port->ip_label);
			tasklabel_unlock(space->is_task);

			if (rc) {
				ip_unlock(port);
				return KERN_NO_ACCESS;
			}
		}
#endif

		if (bits & MACH_PORT_TYPE_SEND) {
			mach_port_urefs_t urefs = IE_BITS_UREFS(bits);

			assert(port->ip_srights > 1);
			assert(urefs > 0);
			assert(urefs < MACH_PORT_UREFS_MAX);

			if (urefs+1 == MACH_PORT_UREFS_MAX) {
				if (overflow) {
					/* leave urefs pegged to maximum */

					port->ip_srights--;
					ip_release(port);
					ip_unlock(port);
					return KERN_SUCCESS;
				}

				ip_unlock(port);
				return KERN_UREFS_OVERFLOW;
			}

			port->ip_srights--;
			ip_release(port);
			ip_unlock(port);
		} else if (bits & MACH_PORT_TYPE_RECEIVE) {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_RECEIVE);
			assert(IE_BITS_UREFS(bits) == 0);

			/* transfer send right to entry */
			ip_release(port);
			ip_unlock(port);
		} else {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_NONE);
			assert(IE_BITS_UREFS(bits) == 0);

			/* transfer send right and ref to entry */
			ip_unlock(port);

			/* entry is locked holding ref, so can use port */

			ipc_hash_insert(space, (ipc_object_t) port,
					name, entry);
		}

		entry->ie_bits = (bits | MACH_PORT_TYPE_SEND) + 1;
		break;

	    case MACH_MSG_TYPE_PORT_RECEIVE: {
		ipc_port_t dest;

		assert(port->ip_mscount == 0);
		assert(port->ip_receiver_name == MACH_PORT_NULL);
		dest = port->ip_destination;

#if CONFIG_MACF_MACH
		if (space->is_task) {
			tasklabel_lock(space->is_task);
			rc = mac_port_check_hold_receive(&space->is_task->maclabel,
							 &port->ip_label);
			tasklabel_unlock(space->is_task);

			if (rc) {
				ip_unlock(port);
				return KERN_NO_ACCESS;
			}
		}
#endif

		port->ip_receiver_name = name;
		port->ip_receiver = space;

		assert((bits & MACH_PORT_TYPE_RECEIVE) == 0);

		if (bits & MACH_PORT_TYPE_SEND) {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND);
			assert(IE_BITS_UREFS(bits) > 0);
			assert(port->ip_srights > 0);

			ip_release(port);
			ip_unlock(port);

			/* entry is locked holding ref, so can use port */

			ipc_hash_delete(space, (ipc_object_t) port,
					name, entry);
		} else {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_NONE);
			assert(IE_BITS_UREFS(bits) == 0);

			/* transfer ref to entry */
			ip_unlock(port);
		}
		entry->ie_bits = bits | MACH_PORT_TYPE_RECEIVE;

		if (dest != IP_NULL)
			ipc_port_release(dest);
		break;
	    }

	    default:
		panic("ipc_right_copyout: strange rights");
	}

	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_right_rename
 *	Purpose:
 *		Transfer an entry from one name to another.
 *		The old entry is deallocated.
 *	Conditions:
 *		The space is write-locked and active.
 *		The new entry is unused.  Upon return,
 *		the space is unlocked.
 *	Returns:
 *		KERN_SUCCESS		Moved entry to new name.
 */

kern_return_t
ipc_right_rename(
	ipc_space_t		space,
	mach_port_name_t	oname,
	ipc_entry_t		oentry,
	mach_port_name_t	nname,
	ipc_entry_t		nentry)
{
	ipc_port_request_index_t request = oentry->ie_request;
	ipc_entry_bits_t bits = oentry->ie_bits;
	ipc_object_t object = oentry->ie_object;

	assert(space->is_active);
	assert(oname != nname);

	/*
	 *	If IE_BITS_COMPAT, we can't allow the entry to be renamed
	 *	if the port is dead.  (This would foil ipc_port_destroy.)
	 *	Instead we should fail because oentry shouldn't exist.
	 *	Note IE_BITS_COMPAT implies ie_request != 0.
	 */

	if (request != 0) {
		ipc_port_t port;

		assert(bits & MACH_PORT_TYPE_PORT_RIGHTS);
		port = (ipc_port_t) object;
		assert(port != IP_NULL);

		if (ipc_right_check(space, port, oname, oentry)) {
			request = 0;
			object = IO_NULL;
			bits = oentry->ie_bits;
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_DEAD_NAME);
			assert(oentry->ie_request == 0);
		} else {
			/* port is locked and active */

			ipc_port_dnrename(port, request, oname, nname);
			ip_unlock(port);
			oentry->ie_request = 0;
		}
	}

	/* initialize nentry before letting ipc_hash_insert see it */

	assert((nentry->ie_bits & IE_BITS_RIGHT_MASK) == 0);
	nentry->ie_bits |= bits & IE_BITS_RIGHT_MASK;
	nentry->ie_request = request;
	nentry->ie_object = object;

	switch (IE_BITS_TYPE(bits)) {
	    case MACH_PORT_TYPE_SEND: {
		ipc_port_t port;

		port = (ipc_port_t) object;
		assert(port != IP_NULL);

		/* remember, there are no other share entries possible */
		/* or we can't do the rename.  Therefore we do not need */
		/* to check the other subspaces */
	  	ipc_hash_delete(space, (ipc_object_t) port, oname, oentry);
		ipc_hash_insert(space, (ipc_object_t) port, nname, nentry);
		break;
	    }

	    case MACH_PORT_TYPE_RECEIVE:
	    case MACH_PORT_TYPE_SEND_RECEIVE: {
		ipc_port_t port;

		port = (ipc_port_t) object;
		assert(port != IP_NULL);

		ip_lock(port);
		assert(ip_active(port));
		assert(port->ip_receiver_name == oname);
		assert(port->ip_receiver == space);

		port->ip_receiver_name = nname;
		ip_unlock(port);
		break;
	    }

	    case MACH_PORT_TYPE_PORT_SET: {
		ipc_pset_t pset;

		pset = (ipc_pset_t) object;
		assert(pset != IPS_NULL);

		ips_lock(pset);
		assert(ips_active(pset));
		assert(pset->ips_local_name == oname);

		pset->ips_local_name = nname;
		ips_unlock(pset);
		break;
	    }

	    case MACH_PORT_TYPE_SEND_ONCE:
	    case MACH_PORT_TYPE_DEAD_NAME:
		break;

	    default:
		panic("ipc_right_rename: strange rights");
	}

	assert(oentry->ie_request == 0);
	oentry->ie_object = IO_NULL;
	ipc_entry_dealloc(space, oname, oentry);
	is_write_unlock(space);

	return KERN_SUCCESS;
}

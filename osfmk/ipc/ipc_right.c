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
#include <kern/ipc_kobject.h>
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
#include <ipc/ipc_importance.h>
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
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_entry_t             *entryp)
{
	ipc_entry_t entry;

	assert(space != IS_NULL);

	is_write_lock(space);

	if (!is_active(space)) {
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
	ipc_space_t             space,
	mach_port_name_t        name1,
	ipc_entry_t             *entryp1,
	mach_port_name_t        name2,
	ipc_entry_t             *entryp2)
{
	ipc_entry_t entry1;
	ipc_entry_t entry2;

	assert(space != IS_NULL);

	is_write_lock(space);

	if (!is_active(space)) {
		is_write_unlock(space);
		return KERN_INVALID_TASK;
	}

	if ((entry1 = ipc_entry_lookup(space, name1)) == IE_NULL) {
		is_write_unlock(space);
		mach_port_guard_exception(name1, 0, 0, kGUARD_EXC_INVALID_NAME);
		return KERN_INVALID_NAME;
	}
	if ((entry2 = ipc_entry_lookup(space, name2)) == IE_NULL) {
		is_write_unlock(space);
		mach_port_guard_exception(name2, 0, 0, kGUARD_EXC_INVALID_NAME);
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
	ipc_space_t             space,
	ipc_object_t            object,
	mach_port_name_t        *namep,
	ipc_entry_t             *entryp)
{
	ipc_port_t port;
	mach_port_name_t name;
	ipc_entry_t entry;

	/* would switch on io_otype to handle multiple types of object */

	assert(is_active(space));
	assert(io_otype(object) == IOT_PORT);

	port = ip_object_to_port(object);

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
		assert(port == ip_object_to_port(entry->ie_object));

		*namep = name;
		*entryp = entry;
		return TRUE;
	}

	if (ipc_hash_lookup(space, ip_to_object(port), namep, entryp)) {
		assert((entry = *entryp) != IE_NULL);
		assert(IE_BITS_TYPE(entry->ie_bits) == MACH_PORT_TYPE_SEND);
		assert(port == ip_object_to_port(entry->ie_object));

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
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
ipc_right_request_alloc(
	ipc_space_t             space,
	mach_port_name_t        name,
	boolean_t               immediate,
	boolean_t               send_possible,
	ipc_port_t              notify,
	ipc_port_t              *previousp)
{
	ipc_port_request_index_t prev_request;
	ipc_port_t previous = IP_NULL;
	ipc_entry_t entry;
	kern_return_t kr;

#if IMPORTANCE_INHERITANCE
	boolean_t needboost = FALSE;
#endif /* IMPORTANCE_INHERITANCE */

	for (;;) {
		ipc_port_t port = IP_NULL;

		kr = ipc_right_lookup_write(space, name, &entry);
		if (kr != KERN_SUCCESS) {
			return kr;
		}

		/* space is write-locked and active */

		prev_request = entry->ie_request;

		/* if nothing to do or undo, we're done */
		if (notify == IP_NULL && prev_request == IE_REQ_NONE) {
			is_write_unlock(space);
			*previousp = IP_NULL;
			return KERN_SUCCESS;
		}

		/* see if the entry is of proper type for requests */
		if (entry->ie_bits & MACH_PORT_TYPE_PORT_RIGHTS) {
			ipc_port_request_index_t new_request;

			port = ip_object_to_port(entry->ie_object);
			assert(port != IP_NULL);

			if (!ipc_right_check(space, port, name, entry, IPC_RIGHT_COPYIN_FLAGS_NONE)) {
				/* port is locked and active */

				/* if no new request, just cancel previous */
				if (notify == IP_NULL) {
					if (prev_request != IE_REQ_NONE) {
						previous = ipc_port_request_cancel(port, name, prev_request);
					}
					ip_unlock(port);
					entry->ie_request = IE_REQ_NONE;
					ipc_entry_modified(space, name, entry);
					is_write_unlock(space);
					break;
				}

				/*
				 * send-once rights, kernel objects, and non-full other queues
				 * fire immediately (if immediate specified).
				 */
				if (send_possible && immediate &&
				    ((entry->ie_bits & MACH_PORT_TYPE_SEND_ONCE) ||
				    port->ip_receiver == ipc_space_kernel || !ip_full(port))) {
					if (prev_request != IE_REQ_NONE) {
						previous = ipc_port_request_cancel(port, name, prev_request);
					}
					ip_unlock(port);
					entry->ie_request = IE_REQ_NONE;
					ipc_entry_modified(space, name, entry);
					is_write_unlock(space);

					ipc_notify_send_possible(notify, name);
					break;
				}

				/*
				 * If there is a previous request, free it.  Any subsequent
				 * allocation cannot fail, thus assuring an atomic swap.
				 */
				if (prev_request != IE_REQ_NONE) {
					previous = ipc_port_request_cancel(port, name, prev_request);
				}

#if IMPORTANCE_INHERITANCE
				kr = ipc_port_request_alloc(port, name, notify,
				    send_possible, immediate,
				    &new_request, &needboost);
#else
				kr = ipc_port_request_alloc(port, name, notify,
				    send_possible, immediate,
				    &new_request);
#endif /* IMPORTANCE_INHERITANCE */
				if (kr != KERN_SUCCESS) {
					assert(previous == IP_NULL);
					is_write_unlock(space);

					kr = ipc_port_request_grow(port, ITS_SIZE_NONE);
					/* port is unlocked */

					if (kr != KERN_SUCCESS) {
						return kr;
					}

					continue;
				}


				assert(new_request != IE_REQ_NONE);
				entry->ie_request = new_request;
				ipc_entry_modified(space, name, entry);
				is_write_unlock(space);

#if IMPORTANCE_INHERITANCE
				if (needboost == TRUE) {
					if (ipc_port_importance_delta(port, IPID_OPTION_SENDPOSSIBLE, 1) == FALSE) {
						ip_unlock(port);
					}
				} else
#endif /* IMPORTANCE_INHERITANCE */
				ip_unlock(port);

				break;
			}
			/* entry may have changed to dead-name by ipc_right_check() */
		}

		/* treat send_possible requests as immediate w.r.t. dead-name */
		if ((send_possible || immediate) && notify != IP_NULL &&
		    (entry->ie_bits & MACH_PORT_TYPE_DEAD_NAME)) {
			mach_port_urefs_t urefs = IE_BITS_UREFS(entry->ie_bits);

			assert(urefs > 0);

			/* leave urefs pegged to maximum if it overflowed */
			if (urefs < MACH_PORT_UREFS_MAX) {
				(entry->ie_bits)++; /* increment urefs */
			}
			ipc_entry_modified(space, name, entry);

			is_write_unlock(space);

			if (port != IP_NULL) {
				ip_release(port);
			}

			ipc_notify_dead_name(notify, name);
			previous = IP_NULL;
			break;
		}

		kr = (entry->ie_bits & MACH_PORT_TYPE_PORT_OR_DEAD) ?
		    KERN_INVALID_ARGUMENT : KERN_INVALID_RIGHT;

		is_write_unlock(space);

		if (port != IP_NULL) {
			ip_release(port);
		}

		return kr;
	}

	*previousp = previous;
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_right_request_cancel
 *	Purpose:
 *		Cancel a notification request and return the send-once right.
 *		Afterwards, entry->ie_request == 0.
 *	Conditions:
 *		The space must be write-locked; the port must be locked.
 *		The port must be active; the space doesn't have to be.
 */

ipc_port_t
ipc_right_request_cancel(
	__unused ipc_space_t            space,
	ipc_port_t                      port,
	mach_port_name_t                name,
	ipc_entry_t                     entry)
{
	ipc_port_t previous;

	require_ip_active(port);
	assert(port == ip_object_to_port(entry->ie_object));

	if (entry->ie_request == IE_REQ_NONE) {
		return IP_NULL;
	}

	previous = ipc_port_request_cancel(port, name, entry->ie_request);
	entry->ie_request = IE_REQ_NONE;
	ipc_entry_modified(space, name, entry);
	return previous;
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
	ipc_space_t                     space,
	__unused mach_port_name_t       name,
	ipc_entry_t                     entry)
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
 *              and IPC_RIGHT_COPYIN_FLAGS_ALLOW_DEAD_SEND_ONCE is not
 *              passed and it is not a send once right then
 *		clean up the entry and return TRUE.
 *	Conditions:
 *		The space is write-locked; the port is not locked.
 *		If returns FALSE, the port is also locked.
 *		Otherwise, entry is converted to a dead name.
 *
 *		Caller is responsible for a reference to port if it
 *		had died (returns TRUE).
 */

boolean_t
ipc_right_check(
	ipc_space_t              space,
	ipc_port_t               port,
	mach_port_name_t         name,
	ipc_entry_t              entry,
	ipc_right_copyin_flags_t flags)
{
	ipc_entry_bits_t bits;

	assert(is_active(space));
	assert(port == ip_object_to_port(entry->ie_object));

	ip_lock(port);
	if (ip_active(port) ||
	    ((flags & IPC_RIGHT_COPYIN_FLAGS_ALLOW_DEAD_SEND_ONCE) &&
	    entry->ie_request == IE_REQ_NONE &&
	    (entry->ie_bits & MACH_PORT_TYPE_SEND_ONCE))) {
		return FALSE;
	}

	/* this was either a pure send right or a send-once right */

	bits = entry->ie_bits;
	assert((bits & MACH_PORT_TYPE_RECEIVE) == 0);
	assert(IE_BITS_UREFS(bits) > 0);

	if (bits & MACH_PORT_TYPE_SEND) {
		assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND);
		assert(IE_BITS_UREFS(bits) > 0);
		assert(port->ip_srights > 0);
		port->ip_srights--;
	} else {
		assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND_ONCE);
		assert(IE_BITS_UREFS(bits) == 1);
		assert(port->ip_sorights > 0);
		port->ip_sorights--;
	}
	ip_unlock(port);

	/*
	 * delete SEND rights from ipc hash.
	 */

	if ((bits & MACH_PORT_TYPE_SEND) != 0) {
		ipc_hash_delete(space, ip_to_object(port), name, entry);
	}

	/* convert entry to dead name */
	bits = (bits & ~IE_BITS_TYPE_MASK) | MACH_PORT_TYPE_DEAD_NAME;

	/*
	 * If there was a notification request outstanding on this
	 * name, and the port went dead, that notification
	 * must already be on its way up from the port layer.
	 *
	 * Add the reference that the notification carries. It
	 * is done here, and not in the notification delivery,
	 * because the latter doesn't have a space reference and
	 * trying to actually move a send-right reference would
	 * get short-circuited into a MACH_PORT_DEAD by IPC. Since
	 * all calls that deal with the right eventually come
	 * through here, it has the same result.
	 *
	 * Once done, clear the request index so we only account
	 * for it once.
	 */
	if (entry->ie_request != IE_REQ_NONE) {
		if (ipc_port_request_type(port, name, entry->ie_request) != 0) {
			/* if urefs are pegged due to overflow, leave them pegged */
			if (IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX) {
				bits++; /* increment urefs */
			}
		}
		entry->ie_request = IE_REQ_NONE;
	}
	entry->ie_bits = bits;
	entry->ie_object = IO_NULL;
	ipc_entry_modified(space, name, entry);
	return TRUE;
}

/*
 *	Routine:	ipc_right_terminate
 *	Purpose:
 *		Cleans up an entry in a terminated space.
 *		The entry isn't deallocated or removed
 *		from reverse hash tables.
 *	Conditions:
 *		The space is dead and unlocked.
 */

void
ipc_right_terminate(
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_entry_t             entry)
{
	ipc_entry_bits_t bits;
	mach_port_type_t type;

	bits = entry->ie_bits;
	type = IE_BITS_TYPE(bits);

	assert(!is_active(space));

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
		assert(entry->ie_request == IE_REQ_NONE);
		assert(entry->ie_object == IO_NULL);
		break;

	case MACH_PORT_TYPE_PORT_SET: {
		ipc_pset_t pset = ips_object_to_pset(entry->ie_object);

		assert(entry->ie_request == IE_REQ_NONE);
		assert(pset != IPS_NULL);

		ips_lock(pset);
		assert(ips_active(pset));
		ipc_pset_destroy(space, pset); /* consumes ref, unlocks */
		break;
	}

	case MACH_PORT_TYPE_SEND:
	case MACH_PORT_TYPE_RECEIVE:
	case MACH_PORT_TYPE_SEND_RECEIVE:
	case MACH_PORT_TYPE_SEND_ONCE: {
		ipc_port_t port = ip_object_to_port(entry->ie_object);
		ipc_port_t request;
		ipc_port_t nsrequest = IP_NULL;
		mach_port_mscount_t mscount = 0;

		assert(port != IP_NULL);
		ip_lock(port);

		if (!ip_active(port)) {
			ip_unlock(port);
			ip_release(port);
			break;
		}

		request = ipc_right_request_cancel_macro(space, port,
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

			ipc_port_destroy(port); /* clears receiver, consumes our ref, unlocks */
		} else if (type & MACH_PORT_TYPE_SEND_ONCE) {
			assert(port->ip_sorights > 0);
			port->ip_reply_context = 0;
			ip_unlock(port);

			ipc_notify_send_once(port); /* consumes our ref */
		} else {
			assert(port->ip_receiver != space);

			ip_unlock(port);
			ip_release(port);
		}

		if (nsrequest != IP_NULL) {
			ipc_notify_no_senders(nsrequest, mscount);
		}

		if (request != IP_NULL) {
			ipc_notify_port_deleted(request, name);
		}
		break;
	}

	default:
		panic("ipc_right_terminate: strange type - 0x%x", type);
	}
}

/*
 *	Routine:	ipc_right_destroy
 *	Purpose:
 *		Destroys an entry in a space.
 *	Conditions:
 *		The space is write-locked (returns unlocked).
 *		The space must be active.
 *	Returns:
 *		KERN_SUCCESS		The entry was destroyed.
 */

kern_return_t
ipc_right_destroy(
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_entry_t             entry,
	boolean_t               check_guard,
	uint64_t                guard)
{
	ipc_entry_bits_t bits;
	mach_port_type_t type;

	bits = entry->ie_bits;
	entry->ie_bits &= ~IE_BITS_TYPE_MASK;
	type = IE_BITS_TYPE(bits);

	assert(is_active(space));

	switch (type) {
	case MACH_PORT_TYPE_DEAD_NAME:
		assert(entry->ie_request == IE_REQ_NONE);
		assert(entry->ie_object == IO_NULL);

		ipc_entry_dealloc(space, name, entry);
		is_write_unlock(space);
		break;

	case MACH_PORT_TYPE_PORT_SET: {
		ipc_pset_t pset = ips_object_to_pset(entry->ie_object);

		assert(entry->ie_request == IE_REQ_NONE);
		assert(pset != IPS_NULL);

		entry->ie_object = IO_NULL;
		ipc_entry_dealloc(space, name, entry);

		ips_lock(pset);
		is_write_unlock(space);

		assert(ips_active(pset));
		ipc_pset_destroy(space, pset); /* consumes ref, unlocks */
		break;
	}

	case MACH_PORT_TYPE_SEND:
	case MACH_PORT_TYPE_RECEIVE:
	case MACH_PORT_TYPE_SEND_RECEIVE:
	case MACH_PORT_TYPE_SEND_ONCE: {
		ipc_port_t port = ip_object_to_port(entry->ie_object);
		ipc_port_t nsrequest = IP_NULL;
		mach_port_mscount_t mscount = 0;
		ipc_port_t request;

		assert(port != IP_NULL);

		if (type == MACH_PORT_TYPE_SEND) {
			ipc_hash_delete(space, ip_to_object(port), name, entry);
		}

		ip_lock(port);

		if (!ip_active(port)) {
			assert((type & MACH_PORT_TYPE_RECEIVE) == 0);
			ip_unlock(port);
			entry->ie_request = IE_REQ_NONE;
			entry->ie_object = IO_NULL;
			ipc_entry_dealloc(space, name, entry);
			is_write_unlock(space);
			ip_release(port);
			break;
		}

		/* For receive rights, check for guarding */
		if ((type & MACH_PORT_TYPE_RECEIVE) &&
		    (check_guard) && (port->ip_guarded) &&
		    (guard != port->ip_context)) {
			/* Guard Violation */
			uint64_t portguard = port->ip_context;
			ip_unlock(port);
			is_write_unlock(space);
			/* Raise mach port guard exception */
			mach_port_guard_exception(name, 0, portguard, kGUARD_EXC_DESTROY);
			return KERN_INVALID_RIGHT;
		}


		request = ipc_right_request_cancel_macro(space, port, name, entry);

		entry->ie_object = IO_NULL;
		ipc_entry_dealloc(space, name, entry);
		is_write_unlock(space);

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
			require_ip_active(port);
			assert(port->ip_receiver == space);

			ipc_port_destroy(port); /* clears receiver, consumes our ref, unlocks */
		} else if (type & MACH_PORT_TYPE_SEND_ONCE) {
			assert(port->ip_sorights > 0);
			port->ip_reply_context = 0;
			ip_unlock(port);

			ipc_notify_send_once(port); /* consumes our ref */
		} else {
			assert(port->ip_receiver != space);

			ip_unlock(port);
			ip_release(port);
		}

		if (nsrequest != IP_NULL) {
			ipc_notify_no_senders(nsrequest, mscount);
		}

		if (request != IP_NULL) {
			ipc_notify_port_deleted(request, name);
		}


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
 *		Releases a send/send-once/dead-name/port_set user ref.
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
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_entry_t             entry)
{
	ipc_port_t port = IP_NULL;
	ipc_entry_bits_t bits;
	mach_port_type_t type;

	bits = entry->ie_bits;
	type = IE_BITS_TYPE(bits);


	assert(is_active(space));

	switch (type) {
	case MACH_PORT_TYPE_PORT_SET: {
		ipc_pset_t pset;

		assert(IE_BITS_UREFS(bits) == 0);
		assert(entry->ie_request == IE_REQ_NONE);

		pset = ips_object_to_pset(entry->ie_object);
		assert(pset != IPS_NULL);

		entry->ie_object = IO_NULL;
		ipc_entry_dealloc(space, name, entry);

		ips_lock(pset);
		assert(ips_active(pset));
		is_write_unlock(space);

		ipc_pset_destroy(space, pset); /* consumes ref, unlocks */
		break;
	}

	case MACH_PORT_TYPE_DEAD_NAME: {
dead_name:

		assert(IE_BITS_UREFS(bits) > 0);
		assert(entry->ie_request == IE_REQ_NONE);
		assert(entry->ie_object == IO_NULL);

		if (IE_BITS_UREFS(bits) == 1) {
			ipc_entry_dealloc(space, name, entry);
		} else {
			/* if urefs are pegged due to overflow, leave them pegged */
			if (IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX) {
				entry->ie_bits = bits - 1; /* decrement urefs */
			}
			ipc_entry_modified(space, name, entry);
		}
		is_write_unlock(space);

		/* release any port that got converted to dead name below */
		if (port != IP_NULL) {
			ip_release(port);
		}
		break;
	}

	case MACH_PORT_TYPE_SEND_ONCE: {
		ipc_port_t request;

		assert(IE_BITS_UREFS(bits) == 1);

		port = ip_object_to_port(entry->ie_object);
		assert(port != IP_NULL);

		if (ipc_right_check(space, port, name, entry, IPC_RIGHT_COPYIN_FLAGS_NONE)) {
			bits = entry->ie_bits;
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_DEAD_NAME);
			goto dead_name;     /* it will release port */
		}
		/* port is locked and active */

		assert(port->ip_sorights > 0);

		/*
		 * clear any reply context:
		 * no one will be sending the response b/c we are destroying
		 * the single, outstanding send once right.
		 */
		port->ip_reply_context = 0;

		request = ipc_right_request_cancel_macro(space, port, name, entry);
		ip_unlock(port);

		entry->ie_object = IO_NULL;
		ipc_entry_dealloc(space, name, entry);

		is_write_unlock(space);

		ipc_notify_send_once(port);

		if (request != IP_NULL) {
			ipc_notify_port_deleted(request, name);
		}
		break;
	}

	case MACH_PORT_TYPE_SEND: {
		ipc_port_t request = IP_NULL;
		ipc_port_t nsrequest = IP_NULL;
		mach_port_mscount_t mscount =  0;


		assert(IE_BITS_UREFS(bits) > 0);

		port = ip_object_to_port(entry->ie_object);
		assert(port != IP_NULL);

		if (ipc_right_check(space, port, name, entry, IPC_RIGHT_COPYIN_FLAGS_NONE)) {
			bits = entry->ie_bits;
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_DEAD_NAME);
			goto dead_name;     /* it will release port */
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

			request = ipc_right_request_cancel_macro(space, port,
			    name, entry);
			ipc_hash_delete(space, ip_to_object(port), name, entry);

			ip_unlock(port);
			entry->ie_object = IO_NULL;
			ipc_entry_dealloc(space, name, entry);
			is_write_unlock(space);
			ip_release(port);
		} else {
			ip_unlock(port);
			/* if urefs are pegged due to overflow, leave them pegged */
			if (IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX) {
				entry->ie_bits = bits - 1; /* decrement urefs */
			}
			ipc_entry_modified(space, name, entry);
			is_write_unlock(space);
		}

		if (nsrequest != IP_NULL) {
			ipc_notify_no_senders(nsrequest, mscount);
		}

		if (request != IP_NULL) {
			ipc_notify_port_deleted(request, name);
		}
		break;
	}

	case MACH_PORT_TYPE_SEND_RECEIVE: {
		ipc_port_t nsrequest = IP_NULL;
		mach_port_mscount_t mscount = 0;

		assert(IE_BITS_UREFS(bits) > 0);

		port = ip_object_to_port(entry->ie_object);
		assert(port != IP_NULL);

		ip_lock(port);
		require_ip_active(port);
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

			entry->ie_bits = bits & ~(IE_BITS_UREFS_MASK |
			    MACH_PORT_TYPE_SEND);
		} else {
			/* if urefs are pegged due to overflow, leave them pegged */
			if (IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX) {
				entry->ie_bits = bits - 1; /* decrement urefs */
			}
		}
		ip_unlock(port);

		ipc_entry_modified(space, name, entry);
		is_write_unlock(space);

		if (nsrequest != IP_NULL) {
			ipc_notify_no_senders(nsrequest, mscount);
		}
		break;
	}

	default:
		is_write_unlock(space);
		mach_port_guard_exception(name, 0, 0, kGUARD_EXC_INVALID_RIGHT);
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
 */

kern_return_t
ipc_right_delta(
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_entry_t             entry,
	mach_port_right_t       right,
	mach_port_delta_t       delta)
{
	ipc_port_t port = IP_NULL;
	ipc_entry_bits_t bits;

	bits = entry->ie_bits;

/*
 *	The following is used (for case MACH_PORT_RIGHT_DEAD_NAME) in the
 *	switch below. It is used to keep track of those cases (in DIPC)
 *	where we have postponed the dropping of a port reference. Since
 *	the dropping of the reference could cause the port to disappear
 *	we postpone doing so when we are holding the space lock.
 */

	assert(is_active(space));
	assert(right < MACH_PORT_RIGHT_NUMBER);

	/* Rights-specific restrictions and operations. */

	switch (right) {
	case MACH_PORT_RIGHT_PORT_SET: {
		ipc_pset_t pset;

		if ((bits & MACH_PORT_TYPE_PORT_SET) == 0) {
			mach_port_guard_exception(name, 0, 0, kGUARD_EXC_INVALID_RIGHT);
			goto invalid_right;
		}

		assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_PORT_SET);
		assert(IE_BITS_UREFS(bits) == 0);
		assert(entry->ie_request == IE_REQ_NONE);

		if (delta == 0) {
			goto success;
		}

		if (delta != -1) {
			goto invalid_value;
		}

		pset = ips_object_to_pset(entry->ie_object);
		assert(pset != IPS_NULL);

		entry->ie_object = IO_NULL;
		ipc_entry_dealloc(space, name, entry);

		ips_lock(pset);
		assert(ips_active(pset));
		is_write_unlock(space);

		ipc_pset_destroy(space, pset); /* consumes ref, unlocks */
		break;
	}

	case MACH_PORT_RIGHT_RECEIVE: {
		ipc_port_t request = IP_NULL;

		if ((bits & MACH_PORT_TYPE_RECEIVE) == 0) {
			if ((bits & MACH_PORT_TYPE_EX_RECEIVE) == 0) {
				mach_port_guard_exception(name, 0, 0, kGUARD_EXC_INVALID_RIGHT);
			}
			goto invalid_right;
		}

		if (delta == 0) {
			goto success;
		}

		if (delta != -1) {
			goto invalid_value;
		}

		port = ip_object_to_port(entry->ie_object);
		assert(port != IP_NULL);

		/*
		 *	The port lock is needed for ipc_right_dncancel;
		 *	otherwise, we wouldn't have to take the lock
		 *	until just before dropping the space lock.
		 */

		ip_lock(port);
		require_ip_active(port);
		assert(port->ip_receiver_name == name);
		assert(port->ip_receiver == space);

		/* Mach Port Guard Checking */
		if (port->ip_guarded) {
			uint64_t portguard = port->ip_context;
			ip_unlock(port);
			is_write_unlock(space);
			/* Raise mach port guard exception */
			mach_port_guard_exception(name, 0, portguard, kGUARD_EXC_MOD_REFS);
			goto guard_failure;
		}

		if (bits & MACH_PORT_TYPE_SEND) {
			assert(IE_BITS_TYPE(bits) ==
			    MACH_PORT_TYPE_SEND_RECEIVE);
			assert(IE_BITS_UREFS(bits) > 0);
			assert(port->ip_srights > 0);

			if (port->ip_pdrequest != NULL) {
				/*
				 * Since another task has requested a
				 * destroy notification for this port, it
				 * isn't actually being destroyed - the receive
				 * right is just being moved to another task.
				 * Since we still have one or more send rights,
				 * we need to record the loss of the receive
				 * right and enter the remaining send right
				 * into the hash table.
				 */
				ipc_entry_modified(space, name, entry);
				entry->ie_bits &= ~MACH_PORT_TYPE_RECEIVE;
				entry->ie_bits |= MACH_PORT_TYPE_EX_RECEIVE;
				ipc_hash_insert(space, ip_to_object(port),
				    name, entry);
				ip_reference(port);
			} else {
				/*
				 *	The remaining send right turns into a
				 *	dead name.  Notice we don't decrement
				 *	ip_srights, generate a no-senders notif,
				 *	or use ipc_right_dncancel, because the
				 *	port is destroyed "first".
				 */
				bits &= ~IE_BITS_TYPE_MASK;
				bits |= (MACH_PORT_TYPE_DEAD_NAME | MACH_PORT_TYPE_EX_RECEIVE);
				if (entry->ie_request) {
					entry->ie_request = IE_REQ_NONE;
					/* if urefs are pegged due to overflow, leave them pegged */
					if (IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX) {
						bits++; /* increment urefs */
					}
				}
				entry->ie_bits = bits;
				entry->ie_object = IO_NULL;
				ipc_entry_modified(space, name, entry);
			}
		} else {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_RECEIVE);
			assert(IE_BITS_UREFS(bits) == 0);

			request = ipc_right_request_cancel_macro(space, port,
			    name, entry);
			entry->ie_object = IO_NULL;
			ipc_entry_dealloc(space, name, entry);
		}
		is_write_unlock(space);

		ipc_port_destroy(port); /* clears receiver, consumes ref, unlocks */

		if (request != IP_NULL) {
			ipc_notify_port_deleted(request, name);
		}
		break;
	}

	case MACH_PORT_RIGHT_SEND_ONCE: {
		ipc_port_t request;

		if ((bits & MACH_PORT_TYPE_SEND_ONCE) == 0) {
			goto invalid_right;
		}

		assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND_ONCE);
		assert(IE_BITS_UREFS(bits) == 1);

		port = ip_object_to_port(entry->ie_object);
		assert(port != IP_NULL);

		if (ipc_right_check(space, port, name, entry, IPC_RIGHT_COPYIN_FLAGS_NONE)) {
			assert(!(entry->ie_bits & MACH_PORT_TYPE_SEND_ONCE));
			mach_port_guard_exception(name, 0, 0, kGUARD_EXC_INVALID_RIGHT);
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

		/*
		 * clear any reply context:
		 * no one will be sending the response b/c we are destroying
		 * the single, outstanding send once right.
		 */
		port->ip_reply_context = 0;

		request = ipc_right_request_cancel_macro(space, port, name, entry);
		ip_unlock(port);

		entry->ie_object = IO_NULL;
		ipc_entry_dealloc(space, name, entry);

		is_write_unlock(space);

		ipc_notify_send_once(port);

		if (request != IP_NULL) {
			ipc_notify_port_deleted(request, name);
		}
		break;
	}

	case MACH_PORT_RIGHT_DEAD_NAME: {
		ipc_port_t relport = IP_NULL;
		mach_port_urefs_t urefs;

		if (bits & MACH_PORT_TYPE_SEND_RIGHTS) {
			port = ip_object_to_port(entry->ie_object);
			assert(port != IP_NULL);

			if (!ipc_right_check(space, port, name, entry, IPC_RIGHT_COPYIN_FLAGS_NONE)) {
				/* port is locked and active */
				ip_unlock(port);
				port = IP_NULL;
				mach_port_guard_exception(name, 0, 0, kGUARD_EXC_INVALID_RIGHT);
				goto invalid_right;
			}
			bits = entry->ie_bits;
			relport = port;
			port = IP_NULL;
		} else if ((bits & MACH_PORT_TYPE_DEAD_NAME) == 0) {
			mach_port_guard_exception(name, 0, 0, kGUARD_EXC_INVALID_RIGHT);
			goto invalid_right;
		}

		assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_DEAD_NAME);
		assert(IE_BITS_UREFS(bits) > 0);
		assert(entry->ie_object == IO_NULL);
		assert(entry->ie_request == IE_REQ_NONE);

		if (delta > ((mach_port_delta_t)MACH_PORT_UREFS_MAX) ||
		    delta < (-((mach_port_delta_t)MACH_PORT_UREFS_MAX))) {
			goto invalid_value;
		}

		urefs = IE_BITS_UREFS(bits);

		if (urefs == MACH_PORT_UREFS_MAX) {
			/*
			 * urefs are pegged due to an overflow
			 * only a delta removing all refs at once can change it
			 */

			if (delta != (-((mach_port_delta_t)MACH_PORT_UREFS_MAX))) {
				delta = 0;
			}
		} else {
			if (MACH_PORT_UREFS_UNDERFLOW(urefs, delta)) {
				goto invalid_value;
			}
			if (MACH_PORT_UREFS_OVERFLOW(urefs, delta)) {
				/* leave urefs pegged to maximum if it overflowed */
				delta = MACH_PORT_UREFS_MAX - urefs;
			}
		}

		if ((urefs + delta) == 0) {
			ipc_entry_dealloc(space, name, entry);
		} else if (delta != 0) {
			entry->ie_bits = bits + delta;
			ipc_entry_modified(space, name, entry);
		}

		is_write_unlock(space);

		if (relport != IP_NULL) {
			ip_release(relport);
		}

		break;
	}

	case MACH_PORT_RIGHT_SEND: {
		mach_port_urefs_t urefs;
		ipc_port_t request = IP_NULL;
		ipc_port_t nsrequest = IP_NULL;
		ipc_port_t port_to_release = IP_NULL;
		mach_port_mscount_t mscount = 0;

		if ((bits & MACH_PORT_TYPE_SEND) == 0) {
			/* invalid right exception only when not live/dead confusion */
			if ((bits & MACH_PORT_TYPE_DEAD_NAME) == 0
#if !defined(AE_MAKESENDRIGHT_FIXED)
			    /*
			     * AE tries to add single send right without knowing if it already owns one.
			     * But if it doesn't, it should own the receive right and delta should be 1.
			     */
			    && (((bits & MACH_PORT_TYPE_RECEIVE) == 0) || (delta != 1))
#endif
			    ) {
				mach_port_guard_exception(name, 0, 0, kGUARD_EXC_INVALID_RIGHT);
			}
			goto invalid_right;
		}

		/* maximum urefs for send is MACH_PORT_UREFS_MAX */

		port = ip_object_to_port(entry->ie_object);
		assert(port != IP_NULL);

		if (ipc_right_check(space, port, name, entry, IPC_RIGHT_COPYIN_FLAGS_NONE)) {
			assert((entry->ie_bits & MACH_PORT_TYPE_SEND) == 0);
			goto invalid_right;
		}
		/* port is locked and active */

		assert(port->ip_srights > 0);

		if (delta > ((mach_port_delta_t)MACH_PORT_UREFS_MAX) ||
		    delta < (-((mach_port_delta_t)MACH_PORT_UREFS_MAX))) {
			ip_unlock(port);
			goto invalid_value;
		}

		urefs = IE_BITS_UREFS(bits);

		if (urefs == MACH_PORT_UREFS_MAX) {
			/*
			 * urefs are pegged due to an overflow
			 * only a delta removing all refs at once can change it
			 */

			if (delta != (-((mach_port_delta_t)MACH_PORT_UREFS_MAX))) {
				delta = 0;
			}
		} else {
			if (MACH_PORT_UREFS_UNDERFLOW(urefs, delta)) {
				ip_unlock(port);
				goto invalid_value;
			}
			if (MACH_PORT_UREFS_OVERFLOW(urefs, delta)) {
				/* leave urefs pegged to maximum if it overflowed */
				delta = MACH_PORT_UREFS_MAX - urefs;
			}
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
				ip_unlock(port);
				assert(IE_BITS_TYPE(bits) ==
				    MACH_PORT_TYPE_SEND_RECEIVE);

				entry->ie_bits = bits & ~(IE_BITS_UREFS_MASK |
				    MACH_PORT_TYPE_SEND);
				ipc_entry_modified(space, name, entry);
			} else {
				assert(IE_BITS_TYPE(bits) ==
				    MACH_PORT_TYPE_SEND);

				request = ipc_right_request_cancel_macro(space, port,
				    name, entry);
				ipc_hash_delete(space, ip_to_object(port),
				    name, entry);

				ip_unlock(port);
				port_to_release = port;

				entry->ie_object = IO_NULL;
				ipc_entry_dealloc(space, name, entry);
			}
		} else if (delta != 0) {
			ip_unlock(port);
			entry->ie_bits = bits + delta;
			ipc_entry_modified(space, name, entry);
		} else {
			ip_unlock(port);
		}

		is_write_unlock(space);

		if (port_to_release != IP_NULL) {
			ip_release(port_to_release);
		}

		if (nsrequest != IP_NULL) {
			ipc_notify_no_senders(nsrequest, mscount);
		}

		if (request != IP_NULL) {
			ipc_notify_port_deleted(request, name);
		}
		break;
	}

	case MACH_PORT_RIGHT_LABELH:
		goto invalid_right;

	default:
		panic("ipc_right_delta: strange right %d for 0x%x (%p) in space:%p",
		    right, name, (void *)entry, (void *)space);
	}

	return KERN_SUCCESS;

success:
	is_write_unlock(space);
	return KERN_SUCCESS;

invalid_right:
	is_write_unlock(space);
	if (port != IP_NULL) {
		ip_release(port);
	}
	return KERN_INVALID_RIGHT;

invalid_value:
	is_write_unlock(space);
	mach_port_guard_exception(name, 0, 0, kGUARD_EXC_INVALID_VALUE);
	return KERN_INVALID_VALUE;

guard_failure:
	return KERN_INVALID_RIGHT;
}

/*
 *	Routine:	ipc_right_destruct
 *	Purpose:
 *		Deallocates the receive right and modifies the
 *		user-reference count for the send rights as requested.
 *	Conditions:
 *		The space is write-locked, and is unlocked upon return.
 *		The space must be active.
 *	Returns:
 *		KERN_SUCCESS		Count was modified.
 *		KERN_INVALID_RIGHT	Entry has wrong type.
 *		KERN_INVALID_VALUE	Bad delta for the right.
 */

kern_return_t
ipc_right_destruct(
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_entry_t             entry,
	mach_port_delta_t       srdelta,
	uint64_t                guard)
{
	ipc_port_t port = IP_NULL;
	ipc_entry_bits_t bits;

	mach_port_urefs_t urefs;
	ipc_port_t request = IP_NULL;
	ipc_port_t nsrequest = IP_NULL;
	mach_port_mscount_t mscount = 0;

	bits = entry->ie_bits;

	assert(is_active(space));

	if ((bits & MACH_PORT_TYPE_RECEIVE) == 0) {
		is_write_unlock(space);

		/* No exception if we used to have receive and held entry since */
		if ((bits & MACH_PORT_TYPE_EX_RECEIVE) == 0) {
			mach_port_guard_exception(name, 0, 0, kGUARD_EXC_INVALID_RIGHT);
		}
		return KERN_INVALID_RIGHT;
	}

	if (srdelta && (bits & MACH_PORT_TYPE_SEND) == 0) {
		is_write_unlock(space);
		mach_port_guard_exception(name, 0, 0, kGUARD_EXC_INVALID_RIGHT);
		return KERN_INVALID_RIGHT;
	}

	if (srdelta > 0) {
		goto invalid_value;
	}

	port = ip_object_to_port(entry->ie_object);
	assert(port != IP_NULL);

	ip_lock(port);
	require_ip_active(port);
	assert(port->ip_receiver_name == name);
	assert(port->ip_receiver == space);

	/* Mach Port Guard Checking */
	if (port->ip_guarded && (guard != port->ip_context)) {
		uint64_t portguard = port->ip_context;
		ip_unlock(port);
		is_write_unlock(space);
		mach_port_guard_exception(name, 0, portguard, kGUARD_EXC_DESTROY);
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * First reduce the send rights as requested and
	 * adjust the entry->ie_bits accordingly. The
	 * ipc_entry_modified() call is made once the receive
	 * right is destroyed too.
	 */

	if (srdelta) {
		assert(port->ip_srights > 0);

		urefs = IE_BITS_UREFS(bits);

		/*
		 * Since we made sure that srdelta is negative,
		 * the check for urefs overflow is not required.
		 */
		if (MACH_PORT_UREFS_UNDERFLOW(urefs, srdelta)) {
			ip_unlock(port);
			goto invalid_value;
		}

		if (urefs == MACH_PORT_UREFS_MAX) {
			/*
			 * urefs are pegged due to an overflow
			 * only a delta removing all refs at once can change it
			 */
			if (srdelta != (-((mach_port_delta_t)MACH_PORT_UREFS_MAX))) {
				srdelta = 0;
			}
		}

		if ((urefs + srdelta) == 0) {
			if (--port->ip_srights == 0) {
				nsrequest = port->ip_nsrequest;
				if (nsrequest != IP_NULL) {
					port->ip_nsrequest = IP_NULL;
					mscount = port->ip_mscount;
				}
			}
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND_RECEIVE);
			entry->ie_bits = bits & ~(IE_BITS_UREFS_MASK |
			    MACH_PORT_TYPE_SEND);
		} else {
			entry->ie_bits = bits + srdelta;
		}
	}

	/*
	 * Now destroy the receive right. Update space and
	 * entry accordingly.
	 */

	bits = entry->ie_bits;
	if (bits & MACH_PORT_TYPE_SEND) {
		assert(IE_BITS_UREFS(bits) > 0);
		assert(IE_BITS_UREFS(bits) <= MACH_PORT_UREFS_MAX);

		if (port->ip_pdrequest != NULL) {
			/*
			 * Since another task has requested a
			 * destroy notification for this port, it
			 * isn't actually being destroyed - the receive
			 * right is just being moved to another task.
			 * Since we still have one or more send rights,
			 * we need to record the loss of the receive
			 * right and enter the remaining send right
			 * into the hash table.
			 */
			ipc_entry_modified(space, name, entry);
			entry->ie_bits &= ~MACH_PORT_TYPE_RECEIVE;
			entry->ie_bits |= MACH_PORT_TYPE_EX_RECEIVE;
			ipc_hash_insert(space, ip_to_object(port),
			    name, entry);
			ip_reference(port);
		} else {
			/*
			 *	The remaining send right turns into a
			 *	dead name.  Notice we don't decrement
			 *	ip_srights, generate a no-senders notif,
			 *	or use ipc_right_dncancel, because the
			 *	port is destroyed "first".
			 */
			bits &= ~IE_BITS_TYPE_MASK;
			bits |= (MACH_PORT_TYPE_DEAD_NAME | MACH_PORT_TYPE_EX_RECEIVE);
			if (entry->ie_request) {
				entry->ie_request = IE_REQ_NONE;
				if (IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX) {
					bits++; /* increment urefs */
				}
			}
			entry->ie_bits = bits;
			entry->ie_object = IO_NULL;
			ipc_entry_modified(space, name, entry);
		}
	} else {
		assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_RECEIVE);
		assert(IE_BITS_UREFS(bits) == 0);
		request = ipc_right_request_cancel_macro(space, port,
		    name, entry);
		entry->ie_object = IO_NULL;
		ipc_entry_dealloc(space, name, entry);
	}

	/* Unlock space */
	is_write_unlock(space);

	if (nsrequest != IP_NULL) {
		ipc_notify_no_senders(nsrequest, mscount);
	}

	ipc_port_destroy(port); /* clears receiver, consumes ref, unlocks */

	if (request != IP_NULL) {
		ipc_notify_port_deleted(request, name);
	}

	return KERN_SUCCESS;

invalid_value:
	is_write_unlock(space);
	mach_port_guard_exception(name, 0, 0, kGUARD_EXC_INVALID_VALUE);
	return KERN_INVALID_VALUE;
}


/*
 *	Routine:	ipc_right_info
 *	Purpose:
 *		Retrieves information about the right.
 *	Conditions:
 *		The space is active and write-locked.
 *	        The space is unlocked upon return.
 *	Returns:
 *		KERN_SUCCESS		Retrieved info
 */

kern_return_t
ipc_right_info(
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_entry_t             entry,
	mach_port_type_t        *typep,
	mach_port_urefs_t       *urefsp)
{
	ipc_port_t port;
	ipc_entry_bits_t bits;
	mach_port_type_t type = 0;
	ipc_port_request_index_t request;

	bits = entry->ie_bits;
	request = entry->ie_request;
	port = ip_object_to_port(entry->ie_object);

	if (bits & MACH_PORT_TYPE_RECEIVE) {
		assert(IP_VALID(port));

		if (request != IE_REQ_NONE) {
			ip_lock(port);
			require_ip_active(port);
			type |= ipc_port_request_type(port, name, request);
			ip_unlock(port);
		}
		is_write_unlock(space);
	} else if (bits & MACH_PORT_TYPE_SEND_RIGHTS) {
		/*
		 * validate port is still alive - if so, get request
		 * types while we still have it locked.  Otherwise,
		 * recapture the (now dead) bits.
		 */
		if (!ipc_right_check(space, port, name, entry, IPC_RIGHT_COPYIN_FLAGS_NONE)) {
			if (request != IE_REQ_NONE) {
				type |= ipc_port_request_type(port, name, request);
			}
			ip_unlock(port);
			is_write_unlock(space);
		} else {
			bits = entry->ie_bits;
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_DEAD_NAME);
			is_write_unlock(space);
			ip_release(port);
		}
	} else {
		is_write_unlock(space);
	}

	type |= IE_BITS_TYPE(bits);

	*typep = type;
	*urefsp = IE_BITS_UREFS(bits);
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_right_copyin_check_reply
 *	Purpose:
 *		Check if a subsequent ipc_right_copyin would succeed. Used only
 *		by ipc_kmsg_copyin_header to check if reply_port can be copied in.
 *		If the reply port is an immovable send right, it errors out.
 *	Conditions:
 *		The space is locked (read or write) and active.
 */

boolean_t
ipc_right_copyin_check_reply(
	__assert_only ipc_space_t       space,
	mach_port_name_t                reply_name,
	ipc_entry_t                     reply_entry,
	mach_msg_type_name_t            reply_type)
{
	ipc_entry_bits_t bits;
	ipc_port_t reply_port;

	bits = reply_entry->ie_bits;
	assert(is_active(space));

	switch (reply_type) {
	case MACH_MSG_TYPE_MAKE_SEND:
		if ((bits & MACH_PORT_TYPE_RECEIVE) == 0) {
			return FALSE;
		}
		break;

	case MACH_MSG_TYPE_MAKE_SEND_ONCE:
		if ((bits & MACH_PORT_TYPE_RECEIVE) == 0) {
			return FALSE;
		}
		break;

	case MACH_MSG_TYPE_MOVE_RECEIVE:
		/* ipc_kmsg_copyin_header already filters it out */
		return FALSE;

	case MACH_MSG_TYPE_COPY_SEND:
	case MACH_MSG_TYPE_MOVE_SEND:
	case MACH_MSG_TYPE_MOVE_SEND_ONCE: {
		if (bits & MACH_PORT_TYPE_DEAD_NAME) {
			break;
		}

		if ((bits & MACH_PORT_TYPE_SEND_RIGHTS) == 0) {
			return FALSE;
		}

		reply_port = ip_object_to_port(reply_entry->ie_object);
		assert(reply_port != IP_NULL);

		/*
		 * active status peek to avoid checks that will be skipped
		 * on copyin for dead ports.  Lock not held, so will not be
		 * atomic (but once dead, there's no going back).
		 */
		if (!ip_active(reply_port)) {
			break;
		}

		/*
		 * Can't copyin a send right that is marked immovable. This bit
		 * is set only during port creation and never unset. So it can
		 * be read without a lock.
		 */
		if (reply_port->ip_immovable_send) {
			mach_port_guard_exception(reply_name, 0, 0, kGUARD_EXC_IMMOVABLE);
			return FALSE;
		}

		if (reply_type == MACH_MSG_TYPE_MOVE_SEND_ONCE) {
			if ((bits & MACH_PORT_TYPE_SEND_ONCE) == 0) {
				return FALSE;
			}
		} else {
			if ((bits & MACH_PORT_TYPE_SEND) == 0) {
				return FALSE;
			}
		}

		break;
	}

	default:
		panic("ipc_right_copyin_check: strange rights");
	}

	return TRUE;
}

/*
 *	Routine:	ipc_right_copyin_check_guard_locked
 *	Purpose:
 *		Check if the port is guarded and the guard
 *		value matches the one passed in the arguments.
 *		If MACH_MSG_GUARD_FLAGS_UNGUARDED_ON_SEND is set,
 *		check if the port is unguarded.
 *	Conditions:
 *		The port is locked.
 *	Returns:
 *		KERN_SUCCESS		Port is either unguarded
 *					or guarded with expected value
 *		KERN_INVALID_ARGUMENT	Port is either unguarded already or guard mismatch.
 *					This also raises a EXC_GUARD exception.
 */
static kern_return_t
ipc_right_copyin_check_guard_locked(
	mach_port_name_t name,
	ipc_port_t port,
	mach_port_context_t context,
	mach_msg_guard_flags_t *guard_flags)
{
	mach_msg_guard_flags_t flags = *guard_flags;
	if ((flags & MACH_MSG_GUARD_FLAGS_UNGUARDED_ON_SEND) && !port->ip_guarded && !context) {
		return KERN_SUCCESS;
	} else if (port->ip_guarded && (port->ip_context == context)) {
		return KERN_SUCCESS;
	}

	/* Incorrect guard; Raise exception */
	mach_port_guard_exception(name, context, port->ip_context, kGUARD_EXC_INCORRECT_GUARD);
	return KERN_INVALID_ARGUMENT;
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
 *		KERN_INVALID_CAPABILITY	Trying to move an kobject port or an immovable right
 *		KERN_INVALID_ARGUMENT	Port is unguarded or guard mismatch
 */

kern_return_t
ipc_right_copyin(
	ipc_space_t                space,
	mach_port_name_t           name,
	ipc_entry_t                entry,
	mach_msg_type_name_t       msgt_name,
	ipc_right_copyin_flags_t   flags,
	ipc_object_t               *objectp,
	ipc_port_t                 *sorightp,
	ipc_port_t                 *releasep,
	int                        *assertcntp,
	mach_port_context_t        context,
	mach_msg_guard_flags_t     *guard_flags)
{
	ipc_entry_bits_t bits;
	ipc_port_t port;
	kern_return_t kr;
	boolean_t deadok = flags & IPC_RIGHT_COPYIN_FLAGS_DEADOK? TRUE : FALSE;
	boolean_t allow_imm_send = flags & IPC_RIGHT_COPYIN_FLAGS_ALLOW_IMMOVABLE_SEND? TRUE : FALSE;

	*releasep = IP_NULL;
	*assertcntp = 0;

	bits = entry->ie_bits;

	assert(is_active(space));

	switch (msgt_name) {
	case MACH_MSG_TYPE_MAKE_SEND: {
		if ((bits & MACH_PORT_TYPE_RECEIVE) == 0) {
			goto invalid_right;
		}

		port = ip_object_to_port(entry->ie_object);
		assert(port != IP_NULL);

		ip_lock(port);
		assert(port->ip_receiver_name == name);
		assert(port->ip_receiver == space);

		ipc_port_make_send_locked(port);
		ip_unlock(port);

		*objectp = ip_to_object(port);
		*sorightp = IP_NULL;
		break;
	}

	case MACH_MSG_TYPE_MAKE_SEND_ONCE: {
		if ((bits & MACH_PORT_TYPE_RECEIVE) == 0) {
			goto invalid_right;
		}

		port = ip_object_to_port(entry->ie_object);
		assert(port != IP_NULL);

		ip_lock(port);
		require_ip_active(port);
		assert(port->ip_receiver_name == name);
		assert(port->ip_receiver == space);

		ipc_port_make_sonce_locked(port);
		ip_unlock(port);

		*objectp = ip_to_object(port);
		*sorightp = IP_NULL;
		break;
	}

	case MACH_MSG_TYPE_MOVE_RECEIVE: {
		ipc_port_t request = IP_NULL;

		if ((bits & MACH_PORT_TYPE_RECEIVE) == 0) {
			goto invalid_right;
		}

		/*
		 * Disallow moving receive-right kobjects/kolabel, e.g. mk_timer ports
		 * The ipc_port structure uses the kdata union of kobject and
		 * imp_task exclusively. Thus, general use of a kobject port as
		 * a receive right can cause type confusion in the importance
		 * code.
		 */
		if (io_is_kobject(entry->ie_object) ||
		    io_is_kolabeled(entry->ie_object)) {
			/*
			 * Distinguish an invalid right, e.g., trying to move
			 * a send right as a receive right, from this
			 * situation which is, "This is a valid receive right,
			 * but it's also a kobject and you can't move it."
			 */
			mach_port_guard_exception(name, 0, 0, kGUARD_EXC_IMMOVABLE);
			return KERN_INVALID_CAPABILITY;
		}

		port = ip_object_to_port(entry->ie_object);
		assert(port != IP_NULL);

		ip_lock(port);
		require_ip_active(port);
		assert(port->ip_receiver_name == name);
		assert(port->ip_receiver == space);

		if (port->ip_immovable_receive || port->ip_specialreply) {
			assert(port->ip_receiver != ipc_space_kernel);
			ip_unlock(port);
			assert(current_task() != kernel_task);
			mach_port_guard_exception(name, 0, 0, kGUARD_EXC_IMMOVABLE);
			return KERN_INVALID_CAPABILITY;
		}

		if (guard_flags != NULL) {
			kr = ipc_right_copyin_check_guard_locked(name, port, context, guard_flags);
			if (kr != KERN_SUCCESS) {
				ip_unlock(port);
				return kr;
			}
		}

		if (bits & MACH_PORT_TYPE_SEND) {
			assert(IE_BITS_TYPE(bits) ==
			    MACH_PORT_TYPE_SEND_RECEIVE);
			assert(IE_BITS_UREFS(bits) > 0);
			assert(port->ip_srights > 0);

			ipc_hash_insert(space, ip_to_object(port),
			    name, entry);
			ip_reference(port);
		} else {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_RECEIVE);
			assert(IE_BITS_UREFS(bits) == 0);

			request = ipc_right_request_cancel_macro(space, port,
			    name, entry);
			entry->ie_object = IO_NULL;
		}
		entry->ie_bits = bits & ~MACH_PORT_TYPE_RECEIVE;
		entry->ie_bits |= MACH_PORT_TYPE_EX_RECEIVE;
		ipc_entry_modified(space, name, entry);

		/* ipc_port_clear_receiver unguards the port and clears the ip_immovable_receive bit */
		(void)ipc_port_clear_receiver(port, FALSE); /* don't destroy the port/mqueue */
		if (guard_flags != NULL) {
			/* this flag will be cleared during copyout */
			*guard_flags = *guard_flags | MACH_MSG_GUARD_FLAGS_UNGUARDED_ON_SEND;
		}

#if IMPORTANCE_INHERITANCE
		/*
		 * Account for boosts the current task is going to lose when
		 * copying this right in.  Tempowner ports have either not
		 * been accounting to any task (and therefore are already in
		 * "limbo" state w.r.t. assertions) or to some other specific
		 * task. As we have no way to drop the latter task's assertions
		 * here, We'll deduct those when we enqueue it on its
		 * destination port (see ipc_port_check_circularity()).
		 */
		if (port->ip_tempowner == 0) {
			assert(IIT_NULL == port->ip_imp_task);

			/* ports in limbo have to be tempowner */
			port->ip_tempowner = 1;
			*assertcntp = port->ip_impcount;
		}
#endif /* IMPORTANCE_INHERITANCE */

		ip_unlock(port);

		*objectp = ip_to_object(port);
		*sorightp = request;
		break;
	}

	case MACH_MSG_TYPE_COPY_SEND: {
		if (bits & MACH_PORT_TYPE_DEAD_NAME) {
			goto copy_dead;
		}

		/* allow for dead send-once rights */

		if ((bits & MACH_PORT_TYPE_SEND_RIGHTS) == 0) {
			goto invalid_right;
		}

		assert(IE_BITS_UREFS(bits) > 0);

		port = ip_object_to_port(entry->ie_object);
		assert(port != IP_NULL);

		if (ipc_right_check(space, port, name, entry, IPC_RIGHT_COPYIN_FLAGS_NONE)) {
			bits = entry->ie_bits;
			*releasep = port;
			goto copy_dead;
		}
		/* port is locked and active */

		if ((bits & MACH_PORT_TYPE_SEND) == 0) {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND_ONCE);
			assert(port->ip_sorights > 0);

			ip_unlock(port);
			goto invalid_right;
		}

		if (!allow_imm_send && port->ip_immovable_send) {
			ip_unlock(port);
			mach_port_guard_exception(name, 0, 0, kGUARD_EXC_IMMOVABLE);
			return KERN_INVALID_CAPABILITY;
		}

		ipc_port_copy_send_locked(port);
		ip_unlock(port);

		*objectp = ip_to_object(port);
		*sorightp = IP_NULL;
		break;
	}

	case MACH_MSG_TYPE_MOVE_SEND: {
		ipc_port_t request = IP_NULL;

		if (bits & MACH_PORT_TYPE_DEAD_NAME) {
			goto move_dead;
		}

		/* allow for dead send-once rights */

		if ((bits & MACH_PORT_TYPE_SEND_RIGHTS) == 0) {
			goto invalid_right;
		}

		assert(IE_BITS_UREFS(bits) > 0);

		port = ip_object_to_port(entry->ie_object);
		assert(port != IP_NULL);

		if (ipc_right_check(space, port, name, entry, IPC_RIGHT_COPYIN_FLAGS_NONE)) {
			bits = entry->ie_bits;
			*releasep = port;
			goto move_dead;
		}
		/* port is locked and active */

		if ((bits & MACH_PORT_TYPE_SEND) == 0) {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND_ONCE);
			assert(port->ip_sorights > 0);

			ip_unlock(port);
			goto invalid_right;
		}

		if (!allow_imm_send && port->ip_immovable_send) {
			ip_unlock(port);
			mach_port_guard_exception(name, 0, 0, kGUARD_EXC_IMMOVABLE);
			return KERN_INVALID_CAPABILITY;
		}

		if (IE_BITS_UREFS(bits) == 1) {
			assert(port->ip_srights > 0);
			if (bits & MACH_PORT_TYPE_RECEIVE) {
				assert(port->ip_receiver_name == name);
				assert(port->ip_receiver == space);
				assert(IE_BITS_TYPE(bits) ==
				    MACH_PORT_TYPE_SEND_RECEIVE);

				ip_reference(port);
			} else {
				assert(IE_BITS_TYPE(bits) ==
				    MACH_PORT_TYPE_SEND);

				request = ipc_right_request_cancel_macro(space, port,
				    name, entry);
				ipc_hash_delete(space, ip_to_object(port),
				    name, entry);
				entry->ie_object = IO_NULL;
				/* transfer entry's reference to caller */
			}
			entry->ie_bits = bits & ~
			    (IE_BITS_UREFS_MASK | MACH_PORT_TYPE_SEND);
		} else {
			ipc_port_copy_send_locked(port);
			/* if urefs are pegged due to overflow, leave them pegged */
			if (IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX) {
				entry->ie_bits = bits - 1; /* decrement urefs */
			}
		}

		ipc_entry_modified(space, name, entry);
		ip_unlock(port);

		*objectp = ip_to_object(port);
		*sorightp = request;
		break;
	}

	case MACH_MSG_TYPE_MOVE_SEND_ONCE: {
		ipc_port_t request;

		if (bits & MACH_PORT_TYPE_DEAD_NAME) {
			goto move_dead;
		}

		/* allow for dead send rights */

		if ((bits & MACH_PORT_TYPE_SEND_RIGHTS) == 0) {
			goto invalid_right;
		}

		assert(IE_BITS_UREFS(bits) > 0);

		port = ip_object_to_port(entry->ie_object);
		assert(port != IP_NULL);

		if (ipc_right_check(space, port, name, entry, flags)) {
			bits = entry->ie_bits;
			*releasep = port;
			goto move_dead;
		}
		/*
		 * port is locked, but may not be active:
		 * Allow copyin of inactive ports with no dead name request and treat it
		 * as if the copyin of the port was successful and port became inactive
		 * later.
		 */

		if ((bits & MACH_PORT_TYPE_SEND_ONCE) == 0) {
			assert(bits & MACH_PORT_TYPE_SEND);
			assert(port->ip_srights > 0);

			ip_unlock(port);
			goto invalid_right;
		}

		if (!allow_imm_send && port->ip_immovable_send) {
			ip_unlock(port);
			mach_port_guard_exception(name, 0, 0, kGUARD_EXC_IMMOVABLE);
			return KERN_INVALID_CAPABILITY;
		}

		assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND_ONCE);
		assert(IE_BITS_UREFS(bits) == 1);
		assert(port->ip_sorights > 0);

		request = ipc_right_request_cancel_macro(space, port, name, entry);
		ip_unlock(port);

		entry->ie_object = IO_NULL;
		entry->ie_bits = bits & ~
		    (IE_BITS_UREFS_MASK | MACH_PORT_TYPE_SEND_ONCE);
		ipc_entry_modified(space, name, entry);
		*objectp = ip_to_object(port);
		*sorightp = request;
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
	assert(entry->ie_request == IE_REQ_NONE);
	assert(entry->ie_object == 0);

	if (!deadok) {
		goto invalid_right;
	}

	*objectp = IO_DEAD;
	*sorightp = IP_NULL;
	return KERN_SUCCESS;

move_dead:
	assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_DEAD_NAME);
	assert(IE_BITS_UREFS(bits) > 0);
	assert(entry->ie_request == IE_REQ_NONE);
	assert(entry->ie_object == 0);

	if (!deadok) {
		goto invalid_right;
	}

	if (IE_BITS_UREFS(bits) == 1) {
		bits &= ~MACH_PORT_TYPE_DEAD_NAME;
	}
	/* if urefs are pegged due to overflow, leave them pegged */
	if (IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX) {
		entry->ie_bits = bits - 1; /* decrement urefs */
	}
	ipc_entry_modified(space, name, entry);
	*objectp = IO_DEAD;
	*sorightp = IP_NULL;
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_right_copyin_two_move_sends
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
static
kern_return_t
ipc_right_copyin_two_move_sends(
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_entry_t             entry,
	ipc_object_t            *objectp,
	ipc_port_t              *sorightp,
	ipc_port_t              *releasep)
{
	ipc_entry_bits_t bits;
	mach_port_urefs_t urefs;
	ipc_port_t port;
	ipc_port_t request = IP_NULL;

	*releasep = IP_NULL;

	assert(is_active(space));

	bits = entry->ie_bits;

	if ((bits & MACH_PORT_TYPE_SEND) == 0) {
		goto invalid_right;
	}

	urefs = IE_BITS_UREFS(bits);
	if (urefs < 2) {
		goto invalid_right;
	}

	port = ip_object_to_port(entry->ie_object);
	assert(port != IP_NULL);

	if (ipc_right_check(space, port, name, entry, IPC_RIGHT_COPYIN_FLAGS_NONE)) {
		*releasep = port;
		goto invalid_right;
	}
	/* port is locked and active */

	if (urefs > 2) {
		/*
		 * We are moving 2 urefs as naked send rights, which is decomposed as:
		 * - two copy sends (which doesn't affect the make send count)
		 * - decrementing the local urefs twice.
		 */
		ipc_port_copy_send_locked(port);
		ipc_port_copy_send_locked(port);
		/* if urefs are pegged due to overflow, leave them pegged */
		if (IE_BITS_UREFS(bits) < MACH_PORT_UREFS_MAX) {
			entry->ie_bits = bits - 2; /* decrement urefs */
		}
	} else {
		/*
		 * We have exactly 2 send rights for this port in this space,
		 * which means that we will liberate the naked send right held
		 * by this entry.
		 *
		 * However refcounting rules around entries are that naked send rights
		 * on behalf of spaces do not have an associated port reference,
		 * so we need to donate one ...
		 */
		ipc_port_copy_send_locked(port);

		if (bits & MACH_PORT_TYPE_RECEIVE) {
			assert(port->ip_receiver_name == name);
			assert(port->ip_receiver == space);
			assert(IE_BITS_TYPE(bits) ==
			    MACH_PORT_TYPE_SEND_RECEIVE);

			/* ... that we inject manually when the entry stays alive */
			ip_reference(port);
		} else {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND);

			/* ... that we steal from the entry when it dies */
			request = ipc_right_request_cancel_macro(space, port,
			    name, entry);

			ipc_hash_delete(space, ip_to_object(port),
			    name, entry);
			entry->ie_object = IO_NULL;
		}

		entry->ie_bits = bits & ~(IE_BITS_UREFS_MASK | MACH_PORT_TYPE_SEND);
	}
	ipc_entry_modified(space, name, entry);

	ip_unlock(port);

	*objectp = ip_to_object(port);
	*sorightp = request;
	return KERN_SUCCESS;

invalid_right:
	return KERN_INVALID_RIGHT;
}


/*
 *	Routine:	ipc_right_copyin_two
 *	Purpose:
 *		Like ipc_right_copyin with two dispositions,
 *		each of which results in a send or send-once right,
 *		and deadok = FALSE.
 *	Conditions:
 *		The space is write-locked and active.
 *		The object is returned with two refs/rights.
 *		Msgt_one refers to the dest_type
 *	Returns:
 *		KERN_SUCCESS		Acquired an object.
 *		KERN_INVALID_RIGHT	Name doesn't denote correct right(s).
 *		KERN_INVALID_CAPABILITY	Name doesn't denote correct right for msgt_two.
 */
kern_return_t
ipc_right_copyin_two(
	ipc_space_t               space,
	mach_port_name_t          name,
	ipc_entry_t               entry,
	mach_msg_type_name_t      msgt_one,
	mach_msg_type_name_t      msgt_two,
	ipc_object_t              *objectp,
	ipc_port_t                *sorightp,
	ipc_port_t                *releasep)
{
	kern_return_t kr;
	int assertcnt = 0;

	assert(MACH_MSG_TYPE_PORT_ANY_SEND(msgt_one));
	assert(MACH_MSG_TYPE_PORT_ANY_SEND(msgt_two));

	/*
	 *	This is a little tedious to make atomic, because
	 *	there are 25 combinations of valid dispositions.
	 *	However, most are easy.
	 */

	/*
	 *	If either is move-sonce, then there must be an error.
	 */
	if (msgt_one == MACH_MSG_TYPE_MOVE_SEND_ONCE ||
	    msgt_two == MACH_MSG_TYPE_MOVE_SEND_ONCE) {
		return KERN_INVALID_RIGHT;
	}

	if ((msgt_one == MACH_MSG_TYPE_MAKE_SEND) ||
	    (msgt_one == MACH_MSG_TYPE_MAKE_SEND_ONCE) ||
	    (msgt_two == MACH_MSG_TYPE_MAKE_SEND) ||
	    (msgt_two == MACH_MSG_TYPE_MAKE_SEND_ONCE)) {
		/*
		 *	One of the dispositions needs a receive right.
		 *
		 *	If the copyin below succeeds, we know the receive
		 *	right is there (because the pre-validation of
		 *	the second disposition already succeeded in our
		 *	caller).
		 *
		 *	Hence the port is not in danger of dying.
		 */
		ipc_object_t object_two;

		kr = ipc_right_copyin(space, name, entry,
		    msgt_one, IPC_RIGHT_COPYIN_FLAGS_ALLOW_IMMOVABLE_SEND,
		    objectp, sorightp, releasep,
		    &assertcnt, 0, NULL);
		assert(assertcnt == 0);
		if (kr != KERN_SUCCESS) {
			return kr;
		}

		assert(IO_VALID(*objectp));
		assert(*sorightp == IP_NULL);
		assert(*releasep == IP_NULL);

		/*
		 *	Now copyin the second (previously validated)
		 *	disposition.  The result can't be a dead port,
		 *	as no valid disposition can make us lose our
		 *	receive right.
		 */
		kr = ipc_right_copyin(space, name, entry,
		    msgt_two, IPC_RIGHT_COPYIN_FLAGS_NONE,
		    &object_two, sorightp, releasep,
		    &assertcnt, 0, NULL);
		assert(assertcnt == 0);
		assert(kr == KERN_SUCCESS);
		assert(*sorightp == IP_NULL);
		assert(*releasep == IP_NULL);
		assert(object_two == *objectp);
		assert(entry->ie_bits & MACH_PORT_TYPE_RECEIVE);
	} else if ((msgt_one == MACH_MSG_TYPE_MOVE_SEND) &&
	    (msgt_two == MACH_MSG_TYPE_MOVE_SEND)) {
		/*
		 *	This is an easy case.  Just use our
		 *	handy-dandy special-purpose copyin call
		 *	to get two send rights for the price of one.
		 */
		kr = ipc_right_copyin_two_move_sends(space, name, entry,
		    objectp, sorightp,
		    releasep);
		if (kr != KERN_SUCCESS) {
			return kr;
		}
	} else {
		mach_msg_type_name_t msgt_name;

		/*
		 *	Must be either a single move-send and a
		 *	copy-send, or two copy-send dispositions.
		 *	Use the disposition with the greatest side
		 *	effects for the actual copyin - then just
		 *	duplicate the send right you get back.
		 */
		if (msgt_one == MACH_MSG_TYPE_MOVE_SEND ||
		    msgt_two == MACH_MSG_TYPE_MOVE_SEND) {
			msgt_name = MACH_MSG_TYPE_MOVE_SEND;
		} else {
			msgt_name = MACH_MSG_TYPE_COPY_SEND;
		}

		kr = ipc_right_copyin(space, name, entry,
		    msgt_name, IPC_RIGHT_COPYIN_FLAGS_ALLOW_IMMOVABLE_SEND,
		    objectp, sorightp, releasep,
		    &assertcnt, 0, NULL);
		assert(assertcnt == 0);
		if (kr != KERN_SUCCESS) {
			return kr;
		}

		/*
		 *	Copy the right we got back.  If it is dead now,
		 *	that's OK.  Neither right will be usable to send
		 *	a message anyway.
		 */
		(void)ipc_port_copy_send(ip_object_to_port(*objectp));
	}

	return KERN_SUCCESS;
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
 *		count in the entry to overflow, then the user-reference
 *		count is left pegged to its maximum value and the copyout
 *		succeeds anyway.
 *	Conditions:
 *		The space is write-locked and active.
 *		The object is locked and active.
 *		The object is unlocked; the space isn't.
 *	Returns:
 *		KERN_SUCCESS		Copied out capability.
 */

kern_return_t
ipc_right_copyout(
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_entry_t             entry,
	mach_msg_type_name_t    msgt_name,
	mach_port_context_t     *context,
	mach_msg_guard_flags_t  *guard_flags,
	ipc_object_t            object)
{
	ipc_entry_bits_t bits;
	ipc_port_t port;

	bits = entry->ie_bits;

	assert(IO_VALID(object));
	assert(io_otype(object) == IOT_PORT);
	assert(io_active(object));
	assert(entry->ie_object == object);

	port = ip_object_to_port(object);

	switch (msgt_name) {
	case MACH_MSG_TYPE_PORT_SEND_ONCE:

		assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_NONE);
		assert(IE_BITS_UREFS(bits) == 0);
		assert(port->ip_sorights > 0);

		if (port->ip_specialreply) {
			ipc_port_adjust_special_reply_port_locked(port,
			    current_thread()->ith_knote, IPC_PORT_ADJUST_SR_LINK_WORKLOOP, FALSE);
			/* port unlocked on return */
		} else {
			ip_unlock(port);
		}

		entry->ie_bits = bits | (MACH_PORT_TYPE_SEND_ONCE | 1); /* set urefs to 1 */
		ipc_entry_modified(space, name, entry);
		break;

	case MACH_MSG_TYPE_PORT_SEND:
		assert(port->ip_srights > 0);

		if (bits & MACH_PORT_TYPE_SEND) {
			mach_port_urefs_t urefs = IE_BITS_UREFS(bits);

			assert(port->ip_srights > 1);
			assert(urefs > 0);
			assert(urefs <= MACH_PORT_UREFS_MAX);

			if (urefs == MACH_PORT_UREFS_MAX) {
				/*
				 * leave urefs pegged to maximum,
				 * consume send right and ref
				 */

				port->ip_srights--;
				ip_unlock(port);
				ip_release(port);
				return KERN_SUCCESS;
			}

			/* consume send right and ref */
			port->ip_srights--;
			ip_unlock(port);
			ip_release(port);
		} else if (bits & MACH_PORT_TYPE_RECEIVE) {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_RECEIVE);
			assert(IE_BITS_UREFS(bits) == 0);

			/* transfer send right to entry, consume ref */
			ip_unlock(port);
			ip_release(port);
		} else {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_NONE);
			assert(IE_BITS_UREFS(bits) == 0);

			/* transfer send right and ref to entry */
			ip_unlock(port);

			/* entry is locked holding ref, so can use port */

			ipc_hash_insert(space, ip_to_object(port), name, entry);
		}

		entry->ie_bits = (bits | MACH_PORT_TYPE_SEND) + 1; /* increment urefs */
		ipc_entry_modified(space, name, entry);
		break;

	case MACH_MSG_TYPE_PORT_RECEIVE: {
		ipc_port_t dest;
#if IMPORTANCE_INHERITANCE
		natural_t assertcnt = port->ip_impcount;
#endif /* IMPORTANCE_INHERITANCE */

		assert(port->ip_mscount == 0);
		assert(port->ip_receiver_name == MACH_PORT_NULL);

		/*
		 * Don't copyout kobjects or kolabels as receive right
		 */
		if (io_is_kobject(entry->ie_object) ||
		    io_is_kolabeled(entry->ie_object)) {
			panic("ipc_right_copyout: Copyout kobject/kolabel as receive right");
		}

		imq_lock(&port->ip_messages);
		dest = port->ip_destination;

		port->ip_receiver_name = name;
		port->ip_receiver = space;

		struct knote *kn = current_thread()->ith_knote;

		if ((guard_flags != NULL) && ((*guard_flags & MACH_MSG_GUARD_FLAGS_IMMOVABLE_RECEIVE) != 0)) {
			assert(port->ip_immovable_receive == 0);
			port->ip_guarded = 1;
			port->ip_strict_guard = 0;
			/* pseudo receive shouldn't set the receive right as immovable in the sender's space */
			if (kn != ITH_KNOTE_PSEUDO) {
				port->ip_immovable_receive = 1;
			}
			port->ip_context = current_thread()->ith_msg_addr;
			*context = port->ip_context;
			*guard_flags = *guard_flags & ~MACH_MSG_GUARD_FLAGS_UNGUARDED_ON_SEND;
		}

		assert((bits & MACH_PORT_TYPE_RECEIVE) == 0);
		if (bits & MACH_PORT_TYPE_SEND) {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_SEND);
			assert(IE_BITS_UREFS(bits) > 0);
			assert(port->ip_srights > 0);
		} else {
			assert(IE_BITS_TYPE(bits) == MACH_PORT_TYPE_NONE);
			assert(IE_BITS_UREFS(bits) == 0);
		}

		boolean_t sync_bootstrap_checkin = FALSE;
		if (kn != ITH_KNOTE_PSEUDO && port->ip_sync_bootstrap_checkin) {
			sync_bootstrap_checkin = TRUE;
		}
		if (!ITH_KNOTE_VALID(kn, MACH_MSG_TYPE_PORT_RECEIVE)) {
			kn = NULL;
		}
		ipc_port_adjust_port_locked(port, kn, sync_bootstrap_checkin);
		/* port & message queue are unlocked */

		if (bits & MACH_PORT_TYPE_SEND) {
			ip_release(port);

			/* entry is locked holding ref, so can use port */
			ipc_hash_delete(space, ip_to_object(port), name, entry);
		}
		entry->ie_bits = bits | MACH_PORT_TYPE_RECEIVE;
		ipc_entry_modified(space, name, entry);

		if (dest != IP_NULL) {
#if IMPORTANCE_INHERITANCE
			/*
			 * Deduct the assertion counts we contributed to
			 * the old destination port.  They've already
			 * been reflected into the task as a result of
			 * getting enqueued.
			 */
			ip_lock(dest);
			ipc_port_impcount_delta(dest, 0 - assertcnt, IP_NULL);
			ip_unlock(dest);
#endif /* IMPORTANCE_INHERITANCE */

			/* Drop turnstile ref on dest */
			ipc_port_send_turnstile_complete(dest);
			ip_release(dest);
		}
		break;
	}

	default:
		panic("ipc_right_copyout: strange rights");
	}
	return KERN_SUCCESS;
}

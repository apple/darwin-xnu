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
 */
/*
 *	File:	ipc/ipc_port.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Functions to manipulate IPC ports.
 */

#include <norma_vm.h>
#include <mach_kdb.h>
#include <zone_debug.h>
#include <mach_assert.h>

#include <mach/port.h>
#include <mach/kern_return.h>
#include <kern/lock.h>
#include <kern/ipc_kobject.h>
#include <kern/ipc_subsystem.h>
#include <kern/thread.h>
#include <kern/thread_pool.h>
#include <kern/misc_protos.h>
#include <kern/wait_queue.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_pset.h>
#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_mqueue.h>
#include <ipc/ipc_notify.h>
#include <ipc/ipc_print.h>
#include <ipc/ipc_table.h>

#if	MACH_KDB
#include <machine/db_machdep.h>
#include <ddb/db_command.h>
#include <ddb/db_expr.h>
#endif	/* MACH_KDB */

#include <string.h>

decl_mutex_data(,	ipc_port_multiple_lock_data)
decl_mutex_data(,	ipc_port_timestamp_lock_data)
ipc_port_timestamp_t	ipc_port_timestamp_data;

#if	MACH_ASSERT
void	ipc_port_init_debug(
		ipc_port_t	port);
#endif	/* MACH_ASSERT */

#if	MACH_KDB && ZONE_DEBUG
/* Forwards */
void	print_type_ports(unsigned, unsigned);
void	print_ports(void);
#endif	/* MACH_KDB && ZONE_DEBUG */

/*
 *	Routine:	ipc_port_timestamp
 *	Purpose:
 *		Retrieve a timestamp value.
 */

ipc_port_timestamp_t
ipc_port_timestamp(void)
{
	ipc_port_timestamp_t timestamp;

	ipc_port_timestamp_lock();
	timestamp = ipc_port_timestamp_data++;
	ipc_port_timestamp_unlock();

	return timestamp;
}

/*
 *	Routine:	ipc_port_dnrequest
 *	Purpose:
 *		Try to allocate a dead-name request slot.
 *		If successful, returns the request index.
 *		Otherwise returns zero.
 *	Conditions:
 *		The port is locked and active.
 *	Returns:
 *		KERN_SUCCESS		A request index was found.
 *		KERN_NO_SPACE		No index allocated.
 */

kern_return_t
ipc_port_dnrequest(
	ipc_port_t			port,
	mach_port_name_t		name,
	ipc_port_t			soright,
	ipc_port_request_index_t	*indexp)
{
	ipc_port_request_t ipr, table;
	ipc_port_request_index_t index;

	assert(ip_active(port));
	assert(name != MACH_PORT_NULL);
	assert(soright != IP_NULL);

	table = port->ip_dnrequests;
	if (table == IPR_NULL)
		return KERN_NO_SPACE;

	index = table->ipr_next;
	if (index == 0)
		return KERN_NO_SPACE;

	ipr = &table[index];
	assert(ipr->ipr_name == MACH_PORT_NULL);

	table->ipr_next = ipr->ipr_next;
	ipr->ipr_name = name;
	ipr->ipr_soright = soright;

	*indexp = index;
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_port_dngrow
 *	Purpose:
 *		Grow a port's table of dead-name requests.
 *	Conditions:
 *		The port must be locked and active.
 *		Nothing else locked; will allocate memory.
 *		Upon return the port is unlocked.
 *	Returns:
 *		KERN_SUCCESS		Grew the table.
 *		KERN_SUCCESS		Somebody else grew the table.
 *		KERN_SUCCESS		The port died.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate new table.
 *		KERN_NO_SPACE		Couldn't grow to desired size
 */

kern_return_t
ipc_port_dngrow(
	ipc_port_t	port,
	int		target_size)
{
	ipc_table_size_t its;
	ipc_port_request_t otable, ntable;

	assert(ip_active(port));

	otable = port->ip_dnrequests;
	if (otable == IPR_NULL)
		its = &ipc_table_dnrequests[0];
	else
		its = otable->ipr_size + 1;

	if (target_size != ITS_SIZE_NONE) {
		if ((otable != IPR_NULL) &&
		    (target_size <= otable->ipr_size->its_size)) {
			ip_unlock(port);
			return KERN_SUCCESS;
	        }
		while ((its->its_size) && (its->its_size < target_size)) {
			its++;
		}
		if (its->its_size == 0) {
			ip_unlock(port);
			return KERN_NO_SPACE;
		}
	}

	ip_reference(port);
	ip_unlock(port);

	if ((its->its_size == 0) ||
	    ((ntable = it_dnrequests_alloc(its)) == IPR_NULL)) {
		ipc_port_release(port);
		return KERN_RESOURCE_SHORTAGE;
	}

	ip_lock(port);
	ip_release(port);

	/*
	 *	Check that port is still active and that nobody else
	 *	has slipped in and grown the table on us.  Note that
	 *	just checking port->ip_dnrequests == otable isn't
	 *	sufficient; must check ipr_size.
	 */

	if (ip_active(port) &&
	    (port->ip_dnrequests == otable) &&
	    ((otable == IPR_NULL) || (otable->ipr_size+1 == its))) {
		ipc_table_size_t oits;
		ipc_table_elems_t osize, nsize;
		ipc_port_request_index_t free, i;

		/* copy old table to new table */

		if (otable != IPR_NULL) {
			oits = otable->ipr_size;
			osize = oits->its_size;
			free = otable->ipr_next;

			(void) memcpy((void *)(ntable + 1),
			      (const void *)(otable + 1),
			      (osize - 1) * sizeof(struct ipc_port_request));
		} else {
			osize = 1;
			free = 0;
		}

		nsize = its->its_size;
		assert(nsize > osize);

		/* add new elements to the new table's free list */

		for (i = osize; i < nsize; i++) {
			ipc_port_request_t ipr = &ntable[i];

			ipr->ipr_name = MACH_PORT_NULL;
			ipr->ipr_next = free;
			free = i;
		}

		ntable->ipr_next = free;
		ntable->ipr_size = its;
		port->ip_dnrequests = ntable;
		ip_unlock(port);

		if (otable != IPR_NULL) {
			it_dnrequests_free(oits, otable);
	        }
	} else {
		ip_check_unlock(port);
		it_dnrequests_free(its, ntable);
	}

	return KERN_SUCCESS;
}
 
/*
 *	Routine:	ipc_port_dncancel
 *	Purpose:
 *		Cancel a dead-name request and return the send-once right.
 *	Conditions:
 *		The port must locked and active.
 */

ipc_port_t
ipc_port_dncancel(
	ipc_port_t			port,
	mach_port_name_t		name,
	ipc_port_request_index_t	index)
{
	ipc_port_request_t ipr, table;
	ipc_port_t dnrequest;

	assert(ip_active(port));
	assert(name != MACH_PORT_NULL);
	assert(index != 0);

	table = port->ip_dnrequests;
	assert(table != IPR_NULL);

	ipr = &table[index];
	dnrequest = ipr->ipr_soright;
	assert(ipr->ipr_name == name);

	/* return ipr to the free list inside the table */

	ipr->ipr_name = MACH_PORT_NULL;
	ipr->ipr_next = table->ipr_next;
	table->ipr_next = index;

	return dnrequest;
}

/*
 *	Routine:	ipc_port_pdrequest
 *	Purpose:
 *		Make a port-deleted request, returning the
 *		previously registered send-once right.
 *		Just cancels the previous request if notify is IP_NULL.
 *	Conditions:
 *		The port is locked and active.  It is unlocked.
 *		Consumes a ref for notify (if non-null), and
 *		returns previous with a ref (if non-null).
 */

void
ipc_port_pdrequest(
	ipc_port_t	port,
	ipc_port_t	notify,
	ipc_port_t	*previousp)
{
	ipc_port_t previous;

	assert(ip_active(port));

	previous = port->ip_pdrequest;
	port->ip_pdrequest = notify;
	ip_unlock(port);

	*previousp = previous;
}

/*
 *	Routine:	ipc_port_nsrequest
 *	Purpose:
 *		Make a no-senders request, returning the
 *		previously registered send-once right.
 *		Just cancels the previous request if notify is IP_NULL.
 *	Conditions:
 *		The port is locked and active.  It is unlocked.
 *		Consumes a ref for notify (if non-null), and
 *		returns previous with a ref (if non-null).
 */

void
ipc_port_nsrequest(
	ipc_port_t		port,
	mach_port_mscount_t	sync,
	ipc_port_t		notify,
	ipc_port_t		*previousp)
{
	ipc_port_t previous;
	mach_port_mscount_t mscount;

	assert(ip_active(port));

	previous = port->ip_nsrequest;
	mscount = port->ip_mscount;

	if ((port->ip_srights == 0) && (sync <= mscount) &&
	    (notify != IP_NULL)) {
		port->ip_nsrequest = IP_NULL;
		ip_unlock(port);
		ipc_notify_no_senders(notify, mscount);
	} else {
		port->ip_nsrequest = notify;
		ip_unlock(port);
	}

	*previousp = previous;
}


/*
 *	Routine:	ipc_port_clear_receiver
 *	Purpose:
 *		Prepares a receive right for transmission/destruction.
 *	Conditions:
 *		The port is locked and active.
 */

void
ipc_port_clear_receiver(
	ipc_port_t	port)
{
	spl_t		s;

	assert(ip_active(port));

	/*
	 * pull ourselves from any sets.
	 */
	if (port->ip_pset_count != 0) {
		ipc_pset_remove_all(port);
		port->ip_pset_count = 0;
	}

	/*
	 * Send anyone waiting on the port's queue directly away.
	 * Also clear the mscount and seqno.
	 */
	s = splsched();
	imq_lock(&port->ip_messages);
	ipc_mqueue_changed(&port->ip_messages);
	ipc_port_set_mscount(port, 0);
	port->ip_messages.imq_seqno = 0;
	imq_unlock(&port->ip_messages);
	splx(s);
}

/*
 *	Routine:	ipc_port_init
 *	Purpose:
 *		Initializes a newly-allocated port.
 *		Doesn't touch the ip_object fields.
 */

void
ipc_port_init(
	ipc_port_t		port,
	ipc_space_t		space,
	mach_port_name_t	name)
{
	/* port->ip_kobject doesn't have to be initialized */

	port->ip_receiver = space;
	port->ip_receiver_name = name;

	port->ip_mscount = 0;
	port->ip_srights = 0;
	port->ip_sorights = 0;

	port->ip_nsrequest = IP_NULL;
	port->ip_pdrequest = IP_NULL;
	port->ip_dnrequests = IPR_NULL;

	port->ip_pset_count = 0;
	port->ip_premsg = IKM_NULL;

	thread_pool_init(&port->ip_thread_pool);

	port->ip_subsystem = RPC_SUBSYSTEM_NULL;
	
#if	MACH_ASSERT
	ipc_port_init_debug(port);
#endif	/* MACH_ASSERT */

	ipc_mqueue_init(&port->ip_messages, FALSE /* set */);
}

/*
 *	Routine:	ipc_port_alloc
 *	Purpose:
 *		Allocate a port.
 *	Conditions:
 *		Nothing locked.  If successful, the port is returned
 *		locked.  (The caller doesn't have a reference.)
 *	Returns:
 *		KERN_SUCCESS		The port is allocated.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_NO_SPACE		No room for an entry in the space.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
ipc_port_alloc(
	ipc_space_t		space,
	mach_port_name_t	*namep,
	ipc_port_t		*portp)
{
	ipc_port_t port;
	mach_port_name_t name;
	kern_return_t kr;

	kr = ipc_object_alloc(space, IOT_PORT,
			      MACH_PORT_TYPE_RECEIVE, 0,
			      &name, (ipc_object_t *) &port);
	if (kr != KERN_SUCCESS)
		return kr;

	/* port is locked */

	ipc_port_init(port, space, name);

	*namep = name;
	*portp = port;

	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_port_alloc_name
 *	Purpose:
 *		Allocate a port, with a specific name.
 *	Conditions:
 *		Nothing locked.  If successful, the port is returned
 *		locked.  (The caller doesn't have a reference.)
 *	Returns:
 *		KERN_SUCCESS		The port is allocated.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_NAME_EXISTS	The name already denotes a right.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
ipc_port_alloc_name(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_port_t		*portp)
{
	ipc_port_t port;
	kern_return_t kr;

	kr = ipc_object_alloc_name(space, IOT_PORT,
				   MACH_PORT_TYPE_RECEIVE, 0,
				   name, (ipc_object_t *) &port);
	if (kr != KERN_SUCCESS)
		return kr;

	/* port is locked */

	ipc_port_init(port, space, name);

	*portp = port;

	return KERN_SUCCESS;
}

/*
 * Generate dead name notifications.  Called from ipc_port_destroy.
 * Port is unlocked but still has reference(s);
 * dnrequests was taken from port while the port
 * was locked but the port now has port->ip_dnrequests set to IPR_NULL.
 */
void
ipc_port_dnnotify(
	ipc_port_t		port,
	ipc_port_request_t	dnrequests)
{
	ipc_table_size_t	its = dnrequests->ipr_size;
	ipc_table_elems_t	size = its->its_size;
	ipc_port_request_index_t index;

	for (index = 1; index < size; index++) {
		ipc_port_request_t	ipr = &dnrequests[index];
		mach_port_name_t		name = ipr->ipr_name;
		ipc_port_t		soright;

		if (name == MACH_PORT_NULL)
			continue;

		soright = ipr->ipr_soright;
		assert(soright != IP_NULL);

		ipc_notify_dead_name(soright, name);
	}

	it_dnrequests_free(its, dnrequests);
}

/*
 *	Routine:	ipc_port_destroy
 *	Purpose:
 *		Destroys a port.  Cleans up queued messages.
 *
 *		If the port has a backup, it doesn't get destroyed,
 *		but is sent in a port-destroyed notification to the backup.
 *	Conditions:
 *		The port is locked and alive; nothing else locked.
 *		The caller has a reference, which is consumed.
 *		Afterwards, the port is unlocked and dead.
 */

void
ipc_port_destroy(
	ipc_port_t	port)
{
	ipc_port_t pdrequest, nsrequest;
	ipc_mqueue_t mqueue;
	ipc_kmsg_queue_t kmqueue;
	ipc_kmsg_t kmsg;
	ipc_port_request_t dnrequests;
	thread_pool_t thread_pool;

	assert(ip_active(port));
	/* port->ip_receiver_name is garbage */
	/* port->ip_receiver/port->ip_destination is garbage */
	assert(port->ip_pset_count == 0);
	assert(port->ip_mscount == 0);

	/* first check for a backup port */

	pdrequest = port->ip_pdrequest;
	if (pdrequest != IP_NULL) {
		/* we assume the ref for pdrequest */
		port->ip_pdrequest = IP_NULL;

		/* make port be in limbo */
		port->ip_receiver_name = MACH_PORT_NULL;
		port->ip_destination = IP_NULL;
		ip_unlock(port);

		if (!ipc_port_check_circularity(port, pdrequest)) {
			/* consumes our refs for port and pdrequest */
			ipc_notify_port_destroyed(pdrequest, port);
			return;
		} else {
			/* consume pdrequest and destroy port */
			ipc_port_release_sonce(pdrequest);
		}

		ip_lock(port);
		assert(ip_active(port));
		assert(port->ip_pset_count == 0);
		assert(port->ip_mscount == 0);
		assert(port->ip_pdrequest == IP_NULL);
		assert(port->ip_receiver_name == MACH_PORT_NULL);
		assert(port->ip_destination == IP_NULL);

		/* fall through and destroy the port */
	}

	/* once port is dead, we don't need to keep it locked */

	port->ip_object.io_bits &= ~IO_BITS_ACTIVE;
	port->ip_timestamp = ipc_port_timestamp();

	/* save for later */
	dnrequests = port->ip_dnrequests;
	port->ip_dnrequests = IPR_NULL;

	/*
	 * If the port has a preallocated message buffer and that buffer
	 * is not inuse, free it.  If it has and inuse one, then the kmsg
	 * free will detect that we freed the association and it can free it
	 * like a normal buffer.
	 */
	if (IP_PREALLOC(port)) {
		kmsg = port->ip_premsg;
		assert(kmsg != IKM_NULL);
		if (!ikm_prealloc_inuse(kmsg)) {
			ikm_prealloc_clear_inuse(kmsg, port);
			IP_CLEAR_PREALLOC(port, kmsg);
			ipc_kmsg_free(kmsg);
		} else {
			assert(ikm_prealloc_inuse_port(kmsg) == port);
			ikm_prealloc_clear_inuse(kmsg, port);
			IP_CLEAR_PREALLOC(port, kmsg);
		}
	}

	ip_unlock(port);

	/* wakeup any threads waiting on this pool port for an activation */
	if ((thread_pool = &port->ip_thread_pool) != THREAD_POOL_NULL)
		thread_pool_wakeup(thread_pool);

	/* throw away no-senders request */

	nsrequest = port->ip_nsrequest;
	if (nsrequest != IP_NULL)
		ipc_notify_send_once(nsrequest); /* consumes ref */

	/* destroy any queued messages */
	mqueue = &port->ip_messages;
	ipc_mqueue_destroy(mqueue);

	/* generate dead-name notifications */
	if (dnrequests != IPR_NULL) {
		ipc_port_dnnotify(port, dnrequests);
	}

	ipc_kobject_destroy(port);

	if (port->ip_subsystem != RPC_SUBSYSTEM_NULL) {
		subsystem_deallocate((subsystem_t) port->ip_kobject);
	}

	/* XXXX Perhaps should verify that ip_thread_pool is empty! */

	ipc_port_release(port); /* consume caller's ref */
}

/*
 *	Routine:	ipc_port_check_circularity
 *	Purpose:
 *		Check if queueing "port" in a message for "dest"
 *		would create a circular group of ports and messages.
 *
 *		If no circularity (FALSE returned), then "port"
 *		is changed from "in limbo" to "in transit".
 *
 *		That is, we want to set port->ip_destination == dest,
 *		but guaranteeing that this doesn't create a circle
 *		port->ip_destination->ip_destination->... == port
 *	Conditions:
 *		No ports locked.  References held for "port" and "dest".
 */

boolean_t
ipc_port_check_circularity(
	ipc_port_t	port,
	ipc_port_t	dest)
{
	ipc_port_t base;

	assert(port != IP_NULL);
	assert(dest != IP_NULL);

	if (port == dest)
		return TRUE;
	base = dest;

	/*
	 *	First try a quick check that can run in parallel.
	 *	No circularity if dest is not in transit.
	 */

	ip_lock(port);
	if (ip_lock_try(dest)) {
		if (!ip_active(dest) ||
		    (dest->ip_receiver_name != MACH_PORT_NULL) ||
		    (dest->ip_destination == IP_NULL))
			goto not_circular;

		/* dest is in transit; further checking necessary */

		ip_unlock(dest);
	}
	ip_unlock(port);

	ipc_port_multiple_lock(); /* massive serialization */

	/*
	 *	Search for the end of the chain (a port not in transit),
	 *	acquiring locks along the way.
	 */

	for (;;) {
		ip_lock(base);

		if (!ip_active(base) ||
		    (base->ip_receiver_name != MACH_PORT_NULL) ||
		    (base->ip_destination == IP_NULL))
			break;

		base = base->ip_destination;
	}

	/* all ports in chain from dest to base, inclusive, are locked */

	if (port == base) {
		/* circularity detected! */

		ipc_port_multiple_unlock();

		/* port (== base) is in limbo */

		assert(ip_active(port));
		assert(port->ip_receiver_name == MACH_PORT_NULL);
		assert(port->ip_destination == IP_NULL);

		while (dest != IP_NULL) {
			ipc_port_t next;

			/* dest is in transit or in limbo */

			assert(ip_active(dest));
			assert(dest->ip_receiver_name == MACH_PORT_NULL);

			next = dest->ip_destination;
			ip_unlock(dest);
			dest = next;
		}

		return TRUE;
	}

	/*
	 *	The guarantee:  lock port while the entire chain is locked.
	 *	Once port is locked, we can take a reference to dest,
	 *	add port to the chain, and unlock everything.
	 */

	ip_lock(port);
	ipc_port_multiple_unlock();

    not_circular:

	/* port is in limbo */

	assert(ip_active(port));
	assert(port->ip_receiver_name == MACH_PORT_NULL);
	assert(port->ip_destination == IP_NULL);

	ip_reference(dest);
	port->ip_destination = dest;

	/* now unlock chain */

	while (port != base) {
		ipc_port_t next;

		/* port is in transit */

		assert(ip_active(port));
		assert(port->ip_receiver_name == MACH_PORT_NULL);
		assert(port->ip_destination != IP_NULL);

		next = port->ip_destination;
		ip_unlock(port);
		port = next;
	}

	/* base is not in transit */

	assert(!ip_active(base) ||
	       (base->ip_receiver_name != MACH_PORT_NULL) ||
	       (base->ip_destination == IP_NULL));
	ip_unlock(base);

	return FALSE;
}

/*
 *	Routine:	ipc_port_lookup_notify
 *	Purpose:
 *		Make a send-once notify port from a receive right.
 *		Returns IP_NULL if name doesn't denote a receive right.
 *	Conditions:
 *		The space must be locked (read or write) and active.
 *  		Being the active space, we can rely on thread server_id
 *		context to give us the proper server level sub-order
 *		within the space.
 */

ipc_port_t
ipc_port_lookup_notify(
	ipc_space_t		space,
	mach_port_name_t	name)
{
	ipc_port_t port;
	ipc_entry_t entry;

	assert(space->is_active);

	entry = ipc_entry_lookup(space, name);
	if (entry == IE_NULL)
		return IP_NULL;
	if ((entry->ie_bits & MACH_PORT_TYPE_RECEIVE) == 0)
		return IP_NULL;

	port = (ipc_port_t) entry->ie_object;
	assert(port != IP_NULL);

	ip_lock(port);
	assert(ip_active(port));
	assert(port->ip_receiver_name == name);
	assert(port->ip_receiver == space);

	ip_reference(port);
	port->ip_sorights++;
	ip_unlock(port);

	return port;
}

/*
 *	Routine:	ipc_port_make_send
 *	Purpose:
 *		Make a naked send right from a receive right.
 *	Conditions:
 *		The port is not locked but it is active.
 */

ipc_port_t
ipc_port_make_send(
	ipc_port_t	port)
{
	assert(IP_VALID(port));

	ip_lock(port);
	assert(ip_active(port));
	port->ip_mscount++;
	port->ip_srights++;
	ip_reference(port);
	ip_unlock(port);

	return port;
}

/*
 *	Routine:	ipc_port_copy_send
 *	Purpose:
 *		Make a naked send right from another naked send right.
 *			IP_NULL		-> IP_NULL
 *			IP_DEAD		-> IP_DEAD
 *			dead port	-> IP_DEAD
 *			live port	-> port + ref
 *	Conditions:
 *		Nothing locked except possibly a space.
 */

ipc_port_t
ipc_port_copy_send(
	ipc_port_t	port)
{
	ipc_port_t sright;

	if (!IP_VALID(port))
		return port;

	ip_lock(port);
	if (ip_active(port)) {
		assert(port->ip_srights > 0);

		ip_reference(port);
		port->ip_srights++;
		sright = port;
	} else
		sright = IP_DEAD;
	ip_unlock(port);

	return sright;
}

/*
 *	Routine:	ipc_port_copyout_send
 *	Purpose:
 *		Copyout a naked send right (possibly null/dead),
 *		or if that fails, destroy the right.
 *	Conditions:
 *		Nothing locked.
 */

mach_port_name_t
ipc_port_copyout_send(
	ipc_port_t	sright,
	ipc_space_t	space)
{
	mach_port_name_t name;

	if (IP_VALID(sright)) {
		kern_return_t kr;

		kr = ipc_object_copyout(space, (ipc_object_t) sright,
					MACH_MSG_TYPE_PORT_SEND, TRUE, &name);
		if (kr != KERN_SUCCESS) {
			ipc_port_release_send(sright);

			if (kr == KERN_INVALID_CAPABILITY)
				name = MACH_PORT_DEAD;
			else
				name = MACH_PORT_NULL;
		}
	} else
		name = (mach_port_name_t) sright;

	return name;
}

/*
 *	Routine:	ipc_port_release_send
 *	Purpose:
 *		Release a (valid) naked send right.
 *		Consumes a ref for the port.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_port_release_send(
	ipc_port_t	port)
{
	ipc_port_t nsrequest = IP_NULL;
	mach_port_mscount_t mscount;

	assert(IP_VALID(port));

	ip_lock(port);
	ip_release(port);

	if (!ip_active(port)) {
		ip_check_unlock(port);
		return;
	}

	assert(port->ip_srights > 0);

	if (--port->ip_srights == 0 &&
	    port->ip_nsrequest != IP_NULL) {
		nsrequest = port->ip_nsrequest;
		port->ip_nsrequest = IP_NULL;
		mscount = port->ip_mscount;
		ip_unlock(port);
		ipc_notify_no_senders(nsrequest, mscount);
		/*
		 * Check that there are no other locks taken, because
		 * [norma_]ipc_notify_no_senders routines may block.
		 */
		check_simple_locks();
	} else
		ip_unlock(port);
}

/*
 *	Routine:	ipc_port_make_sonce
 *	Purpose:
 *		Make a naked send-once right from a receive right.
 *	Conditions:
 *		The port is not locked but it is active.
 */

ipc_port_t
ipc_port_make_sonce(
	ipc_port_t	port)
{
	assert(IP_VALID(port));

	ip_lock(port);
	assert(ip_active(port));
	port->ip_sorights++;
	ip_reference(port);
	ip_unlock(port);

	return port;
}

/*
 *	Routine:	ipc_port_release_sonce
 *	Purpose:
 *		Release a naked send-once right.
 *		Consumes a ref for the port.
 *
 *		In normal situations, this is never used.
 *		Send-once rights are only consumed when
 *		a message (possibly a send-once notification)
 *		is sent to them.
 *	Conditions:
 *		Nothing locked except possibly a space.
 */

void
ipc_port_release_sonce(
	ipc_port_t	port)
{
	assert(IP_VALID(port));

	ip_lock(port);

	assert(port->ip_sorights > 0);

	port->ip_sorights--;

	ip_release(port);

	if (!ip_active(port)) {
		ip_check_unlock(port);
		return;
	}

	ip_unlock(port);
}

/*
 *	Routine:	ipc_port_release_receive
 *	Purpose:
 *		Release a naked (in limbo or in transit) receive right.
 *		Consumes a ref for the port; destroys the port.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_port_release_receive(
	ipc_port_t	port)
{
	ipc_port_t dest;

	assert(IP_VALID(port));

	ip_lock(port);
	assert(ip_active(port));
	assert(port->ip_receiver_name == MACH_PORT_NULL);
	dest = port->ip_destination;

	ipc_port_destroy(port); /* consumes ref, unlocks */

	if (dest != IP_NULL)
		ipc_port_release(dest);
}

/*
 *	Routine:	ipc_port_alloc_special
 *	Purpose:
 *		Allocate a port in a special space.
 *		The new port is returned with one ref.
 *		If unsuccessful, IP_NULL is returned.
 *	Conditions:
 *		Nothing locked.
 */

ipc_port_t
ipc_port_alloc_special(
	ipc_space_t	space)
{
	ipc_port_t port;

	port = (ipc_port_t) io_alloc(IOT_PORT);
	if (port == IP_NULL)
		return IP_NULL;

	bzero((char *)port, sizeof(*port));
	io_lock_init(&port->ip_object);
	port->ip_references = 1;
	port->ip_object.io_bits = io_makebits(TRUE, IOT_PORT, 0);

	ipc_port_init(port, space, 1);

	return port;
}

/*
 *	Routine:	ipc_port_dealloc_special
 *	Purpose:
 *		Deallocate a port in a special space.
 *		Consumes one ref for the port.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_port_dealloc_special(
	ipc_port_t	port,
	ipc_space_t	space)
{
	ip_lock(port);
	assert(ip_active(port));
	assert(port->ip_receiver_name != MACH_PORT_NULL);
	assert(port->ip_receiver == space);

	/*
	 *	We clear ip_receiver_name and ip_receiver to simplify
	 *	the ipc_space_kernel check in ipc_mqueue_send.
	 */

	port->ip_receiver_name = MACH_PORT_NULL;
	port->ip_receiver = IS_NULL;

	/* relevant part of ipc_port_clear_receiver */
	ipc_port_set_mscount(port, 0);
	port->ip_messages.imq_seqno = 0;

	ipc_port_destroy(port);
}


#if	MACH_ASSERT
/*
 *	Keep a list of all allocated ports.
 *	Allocation is intercepted via ipc_port_init;
 *	deallocation is intercepted via io_free.
 */
queue_head_t	port_alloc_queue;
decl_mutex_data(,port_alloc_queue_lock)

unsigned long	port_count = 0;
unsigned long	port_count_warning = 20000;
unsigned long	port_timestamp = 0;

void		db_port_stack_trace(
			ipc_port_t	port);
void		db_ref(
			int		refs);
int		db_port_walk(
			unsigned int	verbose,
			unsigned int	display,
			unsigned int	ref_search,
			unsigned int	ref_target);

/*
 *	Initialize global state needed for run-time
 *	port debugging.
 */
void
ipc_port_debug_init(void)
{
	queue_init(&port_alloc_queue);
	mutex_init(&port_alloc_queue_lock, ETAP_IPC_PORT_ALLOCQ);
}


/*
 *	Initialize all of the debugging state in a port.
 *	Insert the port into a global list of all allocated ports.
 */
void
ipc_port_init_debug(
	ipc_port_t	port)
{
	unsigned int	i;

	port->ip_thread = (unsigned long) current_thread();
	port->ip_timetrack = port_timestamp++;
	for (i = 0; i < IP_CALLSTACK_MAX; ++i)
		port->ip_callstack[i] = 0;
	for (i = 0; i < IP_NSPARES; ++i)
		port->ip_spares[i] = 0;

	/*
	 *	Machine-dependent routine to fill in an
	 *	array with up to IP_CALLSTACK_MAX levels
	 *	of return pc information.
	 */
	machine_callstack(&port->ip_callstack[0], IP_CALLSTACK_MAX);

#if 0
	mutex_lock(&port_alloc_queue_lock);
	++port_count;
	if (port_count_warning > 0 && port_count >= port_count_warning)
		assert(port_count < port_count_warning);
	queue_enter(&port_alloc_queue, port, ipc_port_t, ip_port_links);
	mutex_unlock(&port_alloc_queue_lock);
#endif
}


/*
 *	Remove a port from the queue of allocated ports.
 *	This routine should be invoked JUST prior to
 *	deallocating the actual memory occupied by the port.
 */
void
ipc_port_track_dealloc(
	ipc_port_t	port)
{
#if 0
	mutex_lock(&port_alloc_queue_lock);
	assert(port_count > 0);
	--port_count;
	queue_remove(&port_alloc_queue, port, ipc_port_t, ip_port_links);
	mutex_unlock(&port_alloc_queue_lock);
#endif
}

#endif	/* MACH_ASSERT */


#if	MACH_KDB

#include <ddb/db_output.h>
#include <ddb/db_print.h>

#define	printf	kdbprintf
extern int db_indent;

int
db_port_queue_print(
	ipc_port_t	port);

/*
 * ipc_entry_print - pretty-print an ipc_entry
 */
static void ipc_entry_print(struct ipc_entry *, char *); /* forward */

static void ipc_entry_print(struct ipc_entry *iep, char *tag)
{
	ipc_entry_bits_t bits = iep->ie_bits;

	iprintf("%s @", tag);
	printf(" 0x%x, bits=%x object=%x\n", iep, bits, iep->ie_object);
	db_indent += 2;
	iprintf("urefs=%x ", IE_BITS_UREFS(bits));
	printf("type=%x gen=%x\n", IE_BITS_TYPE(bits), IE_BITS_GEN(bits));
	db_indent -= 2;
}

/*
 *	Routine:	ipc_port_print
 *	Purpose:
 *		Pretty-print a port for kdb.
 */
int	ipc_port_print_long = 0;	/* set for more detail */

void
ipc_port_print(
	ipc_port_t	port,
	boolean_t	have_addr,
	db_expr_t	count,
	char		*modif)
{
	extern int	db_indent;
	db_addr_t	task;
	int		task_id;
	int		nmsgs;
	int		verbose = 0;
#if	MACH_ASSERT
	int		i, needs_db_indent, items_printed;
#endif	/* MACH_ASSERT */
	
	if (db_option(modif, 'l') || db_option(modif, 'v'))
		++verbose;

	printf("port 0x%x\n", port);

	db_indent += 2;

	ipc_object_print(&port->ip_object);

	if (ipc_port_print_long) {
		iprintf("pool=0x%x", port->ip_thread_pool);
		printf("\n");
	}

	if (!ip_active(port)) {
		iprintf("timestamp=0x%x", port->ip_timestamp);
	} else if (port->ip_receiver_name == MACH_PORT_NULL) {
		iprintf("destination=0x%x (", port->ip_destination);
		if (port->ip_destination != MACH_PORT_NULL &&
		    (task = db_task_from_space(port->ip_destination->
					       ip_receiver, &task_id)))
			printf("task%d at 0x%x", task_id, task);
		else
			printf("unknown");
		printf(")");
	} else {
		iprintf("receiver=0x%x (", port->ip_receiver);
		if (port->ip_receiver == ipc_space_kernel)
			printf("kernel");
		else if (port->ip_receiver == ipc_space_reply)
			printf("reply");
		else if (port->ip_receiver == default_pager_space)
			printf("default_pager");
		else if (task = db_task_from_space(port->ip_receiver, &task_id))
			printf("task%d at 0x%x", task_id, task);
		else
			printf("unknown");
		printf(")");
	}
	printf(", receiver_name=0x%x\n", port->ip_receiver_name);

	iprintf("mscount=%d", port->ip_mscount);
	printf(", srights=%d", port->ip_srights);
	printf(", sorights=%d\n", port->ip_sorights);

	iprintf("nsrequest=0x%x", port->ip_nsrequest);
	printf(", pdrequest=0x%x", port->ip_pdrequest);
	printf(", dnrequests=0x%x\n", port->ip_dnrequests);

	iprintf("pset_count=0x%x", port->ip_pset_count);
	printf(", seqno=%d", port->ip_messages.imq_seqno);
	printf(", msgcount=%d", port->ip_messages.imq_msgcount);
	printf(", qlimit=%d\n", port->ip_messages.imq_qlimit);

	iprintf("kmsgs=0x%x", port->ip_messages.imq_messages.ikmq_base);
	printf(", rcvrs queue=0x%x", port->ip_messages.imq_wait_queue);
	printf(", kobj=0x%x\n", port->ip_kobject);

	iprintf("premsg=0x%x", port->ip_premsg);

#if	MACH_ASSERT
	/* don't bother printing callstack or queue links */
	iprintf("ip_thread=0x%x, ip_timetrack=0x%x\n",
		port->ip_thread, port->ip_timetrack);
	items_printed = 0;
	needs_db_indent = 1;
	for (i = 0; i < IP_NSPARES; ++i) {
		if (port->ip_spares[i] != 0) {
			if (needs_db_indent) {
				iprintf("");
				needs_db_indent = 0;
			}
			printf("%sip_spares[%d] = %d",
			       items_printed ? ", " : "", i, 
			       port->ip_spares[i]);
			if (++items_printed >= 4) {
				needs_db_indent = 1;
				printf("\n");
				items_printed = 0;
			}
		}
	}
#endif	/* MACH_ASSERT */

	if (verbose) {
		iprintf("kmsg queue contents:\n");
		db_indent += 2;
		nmsgs = db_port_queue_print(port);
		db_indent -= 2;
		iprintf("...total kmsgs:  %d\n", nmsgs);
	}

	db_indent -=2;
}

ipc_port_t
ipc_name_to_data(
	task_t			task,
	mach_port_name_t	name)
{
	ipc_space_t	space;
	ipc_entry_t	entry;

	if (task == TASK_NULL) {
		db_printf("port_name_to_data: task is null\n");
		return (0);
	}
	if ((space = task->itk_space) == 0) {
		db_printf("port_name_to_data: task->itk_space is null\n");
		return (0);
	}
	if (!space->is_active) {
		db_printf("port_name_to_data: task->itk_space not active\n");
		return (0);
	}
	if ((entry = ipc_entry_lookup(space, name)) == 0) {
		db_printf("port_name_to_data: lookup yields zero\n");
		return (0);
	}
	return ((ipc_port_t)entry->ie_object);
}

#if	ZONE_DEBUG
void
print_type_ports(type, dead)
	unsigned type;
	unsigned dead;
{
	ipc_port_t port;
	int n;

	n = 0;
	for (port = (ipc_port_t)first_element(ipc_object_zones[IOT_PORT]);
	     port;
	     port = (ipc_port_t)next_element(ipc_object_zones[IOT_PORT], 
					     (vm_offset_t)port))
		if (ip_kotype(port) == type &&
		    (!dead || !ip_active(port))) {
			if (++n % 5)
				printf("0x%x\t", port);
			else
				printf("0x%x\n", port);
		}
	if (n % 5)
		printf("\n");
}

void
print_ports(void)
{
	ipc_port_t port;
	int total_port_count;
	int space_null_count;
	int space_kernel_count;
	int space_reply_count;
	int space_pager_count;
	int space_other_count;

	struct {
		int total_count;
		int dead_count;
	} port_types[IKOT_MAX_TYPE];

	total_port_count = 0;

	bzero((char *)&port_types[0], sizeof(port_types));
	space_null_count = 0;
	space_kernel_count = 0;
	space_reply_count = 0;
	space_pager_count = 0;
	space_other_count = 0;

	for (port = (ipc_port_t)first_element(ipc_object_zones[IOT_PORT]);
	     port;
	     port = (ipc_port_t)next_element(ipc_object_zones[IOT_PORT], 
					     (vm_offset_t)port)) {
		total_port_count++;
		if (ip_kotype(port) >= IKOT_MAX_TYPE) {
			port_types[IKOT_UNKNOWN].total_count++;
			if (!io_active(&port->ip_object))
				port_types[IKOT_UNKNOWN].dead_count++;
		} else {
			port_types[ip_kotype(port)].total_count++;
			if (!io_active(&port->ip_object))
				port_types[ip_kotype(port)].dead_count++;
		}

		if (!port->ip_receiver)
			space_null_count++;
		else if (port->ip_receiver == ipc_space_kernel)
		  	space_kernel_count++;
		else if (port->ip_receiver == ipc_space_reply)
		  	space_reply_count++;
		else if (port->ip_receiver == default_pager_space)
		  	space_pager_count++;
		else
			space_other_count++;
	}
	printf("\n%7d	total ports\n\n", total_port_count);

#define PRINT_ONE_PORT_TYPE(name) \
	printf("%7d	%s", port_types[IKOT_##name].total_count, # name); \
	if (port_types[IKOT_##name].dead_count) \
	     printf(" (%d dead ports)", port_types[IKOT_##name].dead_count);\
	printf("\n");

	PRINT_ONE_PORT_TYPE(NONE);
	PRINT_ONE_PORT_TYPE(THREAD);
	PRINT_ONE_PORT_TYPE(TASK);
	PRINT_ONE_PORT_TYPE(HOST);
	PRINT_ONE_PORT_TYPE(HOST_PRIV);
	PRINT_ONE_PORT_TYPE(PROCESSOR);
	PRINT_ONE_PORT_TYPE(PSET);
	PRINT_ONE_PORT_TYPE(PSET_NAME);
	PRINT_ONE_PORT_TYPE(PAGING_REQUEST);
	PRINT_ONE_PORT_TYPE(XMM_OBJECT);
	PRINT_ONE_PORT_TYPE(DEVICE);
	PRINT_ONE_PORT_TYPE(XMM_PAGER);
	PRINT_ONE_PORT_TYPE(XMM_KERNEL);
	PRINT_ONE_PORT_TYPE(XMM_REPLY);
	PRINT_ONE_PORT_TYPE(CLOCK);
	PRINT_ONE_PORT_TYPE(CLOCK_CTRL);
	PRINT_ONE_PORT_TYPE(MASTER_DEVICE);
	PRINT_ONE_PORT_TYPE(UNKNOWN);
	printf("\nipc_space:\n\n");
	printf("NULL	KERNEL	REPLY	PAGER	OTHER\n");
	printf("%d	%d	%d	%d	%d\n",
	       space_null_count,
	       space_kernel_count,
	       space_reply_count,
	       space_pager_count,
	       space_other_count
	);
}

#endif	/* ZONE_DEBUG */


/*
 *	Print out all the kmsgs in a queue.  Aggregate kmsgs with
 *	identical message ids into a single entry.  Count up the
 *	amount of inline and out-of-line data consumed by each
 *	and every kmsg.
 *
 */

#define	KMSG_MATCH_FIELD(kmsg)	((unsigned int) kmsg->ikm_header.msgh_id)
#define	DKQP_LONG(kmsg)	FALSE
char	*dkqp_long_format = "(%3d) <%10d> 0x%x   %10d %10d\n";
char	*dkqp_format = "(%3d) <%10d> 0x%x   %10d %10d\n";

int
db_kmsg_queue_print(
	ipc_kmsg_t	kmsg);
int
db_kmsg_queue_print(
	ipc_kmsg_t	kmsg)
{
	ipc_kmsg_t	ikmsg, first_kmsg;
	register int	icount;
	mach_msg_id_t	cur_id;
	unsigned int	inline_total, ool_total;
	int		nmsgs;

	iprintf("Count      msgh_id  kmsg addr inline bytes   ool bytes\n");
	inline_total = ool_total = (vm_size_t) 0;
	cur_id = KMSG_MATCH_FIELD(kmsg);
	for (icount = 0, nmsgs = 0, first_kmsg = ikmsg = kmsg;
	     kmsg != IKM_NULL && (kmsg != first_kmsg || nmsgs == 0);
	     kmsg = kmsg->ikm_next) {
		++nmsgs;
		if (!(KMSG_MATCH_FIELD(kmsg) == cur_id)) {
			iprintf(DKQP_LONG(kmsg) ? dkqp_long_format:dkqp_format,
				icount,	cur_id, ikmsg, inline_total,ool_total);
			cur_id = KMSG_MATCH_FIELD(kmsg);
			icount = 1;
			ikmsg = kmsg;
			inline_total = ool_total = 0;
		} else {
			icount++;
		}
		if (DKQP_LONG(kmsg))
			inline_total += kmsg->ikm_size;
		else
			inline_total += kmsg->ikm_header.msgh_size;
	}
	iprintf(DKQP_LONG(kmsg) ? dkqp_long_format : dkqp_format,
		icount,	cur_id, ikmsg, inline_total, ool_total);
	return nmsgs;
}


/*
 *	Process all of the messages on a port - prints out the
 *	number of occurences of each message type, and the first
 *	kmsg with a particular msgh_id.
 */
int
db_port_queue_print(
	ipc_port_t	port)
{
	ipc_kmsg_t	kmsg;

	if (ipc_kmsg_queue_empty(&port->ip_messages.imq_messages))
		return 0;
	kmsg = ipc_kmsg_queue_first(&port->ip_messages.imq_messages);
	return db_kmsg_queue_print(kmsg);
}


#if	MACH_ASSERT
#include <ddb/db_sym.h>
#include <ddb/db_access.h>

#define	FUNC_NULL	((void (*)) 0)
#define	MAX_REFS	5		/* bins for tracking ref counts */

/*
 *	Translate port's cache of call stack pointers
 *	into symbolic names.
 */
void
db_port_stack_trace(
	ipc_port_t	port)
{
	unsigned int	i;

	for (i = 0; i < IP_CALLSTACK_MAX; ++i) {
		iprintf("[%d] 0x%x\t", i, port->ip_callstack[i]);
		if (port->ip_callstack[i] != 0 &&
		    DB_VALID_KERN_ADDR(port->ip_callstack[i]))
			db_printsym(port->ip_callstack[i], DB_STGY_PROC);
		printf("\n");
	}
}


typedef struct port_item {
	unsigned long	item;
	unsigned long	count;
} port_item;


#define	ITEM_MAX	400
typedef struct port_track {
	char		*name;
	unsigned long	max;
	unsigned long	warning;
	port_item	items[ITEM_MAX];
} port_track;

port_track	port_callers;		/* match against calling addresses */
port_track	port_threads;		/* match against allocating threads */
port_track	port_spaces;		/* match against ipc spaces */

void		port_track_init(
			port_track	*trackp,
			char		*name);
void		port_item_add(
			port_track	*trackp,
			unsigned long	item);
void		port_track_sort(
			port_track	*trackp);
void		port_track_print(
			port_track	*trackp,
			void		(*func)(port_item *));
void		port_callers_print(
			port_item	*p);

void
port_track_init(
	port_track	*trackp,
	char		*name)
{
	port_item	*i;

	trackp->max = trackp->warning = 0;
	trackp->name = name;
	for (i = trackp->items; i < trackp->items + ITEM_MAX; ++i)
		i->item = i->count = 0;
}


void
port_item_add(
	port_track	*trackp,
	unsigned long	item)
{
	port_item	*limit, *i;

	limit = trackp->items + trackp->max;
	for (i = trackp->items; i < limit; ++i)
		if (i->item == item) {
			i->count++;
			return;
		}
	if (trackp->max >= ITEM_MAX) {
		if (trackp->warning++ == 0)
			iprintf("%s:  no room\n", trackp->name);
		return;
	}
	i->item = item;
	i->count = 1;
	trackp->max++;
}


/*
 *	Simple (and slow) bubble sort.
 */
void
port_track_sort(
	port_track	*trackp)
{
	port_item	*limit, *p;
	port_item	temp;
	boolean_t	unsorted;

	limit = trackp->items + trackp->max - 1;
	do {
		unsorted = FALSE;
		for (p = trackp->items; p < limit - 1; ++p) {
			if (p->count < (p+1)->count) {
				temp = *p;
				*p = *(p+1);
				*(p+1) = temp;
				unsorted = TRUE;
			}
		}
	} while (unsorted == TRUE);
}


void
port_track_print(
	port_track	*trackp,
	void		(*func)(port_item *))
{
	port_item	*limit, *p;

	limit = trackp->items + trackp->max;
	iprintf("%s:\n", trackp->name);
	for (p = trackp->items; p < limit; ++p) {
		if (func != FUNC_NULL)
			(*func)(p);
		else
			iprintf("0x%x\t%8d\n", p->item, p->count);
	}
}


void
port_callers_print(
	port_item	*p)
{
	iprintf("0x%x\t%8d\t", p->item, p->count);
	db_printsym(p->item, DB_STGY_PROC);
	printf("\n");
}


/*
 *	Show all ports with a given reference count.
 */
void
db_ref(
	int		refs)
{
	db_port_walk(1, 1, 1, refs);
}


/*
 *	Examine all currently allocated ports.
 *	Options:
 *		verbose		display suspicious ports
 *		display		print out each port encountered
 *		ref_search	restrict examination to ports with
 *				a specified reference count
 *		ref_target	reference count for ref_search
 */
int
db_port_walk(
	unsigned int	verbose,
	unsigned int	display,
	unsigned int	ref_search,
	unsigned int	ref_target)
{
	ipc_port_t	port;
	unsigned int	ref_overflow, refs, i, ref_inactive_overflow;
	unsigned int	no_receiver, no_match;
	unsigned int	ref_counts[MAX_REFS];
	unsigned int	inactive[MAX_REFS];
	unsigned int	ipc_ports = 0;
	unsigned int	proxies = 0, principals = 0;

	iprintf("Allocated port count is %d\n", port_count);
	no_receiver = no_match = ref_overflow = 0;
	ref_inactive_overflow = 0;
	for (i = 0; i < MAX_REFS; ++i) {
		ref_counts[i] = 0;
		inactive[i] = 0;
	}
	port_track_init(&port_callers, "port callers");
	port_track_init(&port_threads, "port threads");
	port_track_init(&port_spaces, "port spaces");
	if (ref_search)
		iprintf("Walking ports of ref_count=%d.\n", ref_target);
	else
		iprintf("Walking all ports.\n");

	queue_iterate(&port_alloc_queue, port, ipc_port_t, ip_port_links) {
		char	*port_type;

		port_type = " IPC port";
		if (ip_active(port))
		  ipc_ports++;

		refs = port->ip_references;
		if (ref_search && refs != ref_target)
			continue;

		if (refs >= MAX_REFS) {
			if (ip_active(port))
				++ref_overflow;
			else
				++ref_inactive_overflow;
		} else {
			if (refs == 0 && verbose)
				iprintf("%s 0x%x has ref count of zero!\n",
					port_type, port);
			if (ip_active(port))
				ref_counts[refs]++;
			else
				inactive[refs]++;
		}
		port_item_add(&port_threads, (unsigned long) port->ip_thread);
		for (i = 0; i < IP_CALLSTACK_MAX; ++i) {
			if (port->ip_callstack[i] != 0 &&
			    DB_VALID_KERN_ADDR(port->ip_callstack[i]))
				port_item_add(&port_callers,
					      port->ip_callstack[i]);
		}
		if (!ip_active(port)) {
			if (verbose)
				iprintf("%s 0x%x, inactive, refcnt %d\n",
					port_type, port, refs);
			continue;
		}

		if (port->ip_receiver_name == MACH_PORT_NULL) {
			iprintf("%s  0x%x, no receiver, refcnt %d\n",
				port, refs);
			++no_receiver;
			continue;
		}
		if (port->ip_receiver == ipc_space_kernel ||
		    port->ip_receiver == ipc_space_reply ||
		    ipc_entry_lookup(port->ip_receiver,
					port->ip_receiver_name) 
					!= IE_NULL) {
			port_item_add(&port_spaces,
				      (unsigned long)port->ip_receiver);
			if (display) {
				iprintf( "%s 0x%x time 0x%x ref_cnt %d\n",
						port_type, port,
						port->ip_timetrack, refs);
			}
			continue;
		}
		iprintf("%s 0x%x, rcvr 0x%x, name 0x%x, ref %d, no match\n",
				port_type, port, port->ip_receiver,
				port->ip_receiver_name, refs);
		++no_match;
	}
	iprintf("Active port type summary:\n");
	iprintf("\tlocal  IPC %6d\n", ipc_ports);
	iprintf("summary:\tcallers %d threads %d spaces %d\n",
		port_callers.max, port_threads.max, port_spaces.max);

	iprintf("\tref_counts:\n");
	for (i = 0; i < MAX_REFS; ++i)
		iprintf("\t  ref_counts[%d] = %d\n", i, ref_counts[i]);

	iprintf("\t%d ports w/o receivers, %d w/o matches\n",
		no_receiver, no_match);

	iprintf("\tinactives:");
	if ( ref_inactive_overflow || inactive[0] || inactive[1] ||
	     inactive[2] || inactive[3] || inactive[4] )
		printf(" [0]=%d [1]=%d [2]=%d [3]=%d [4]=%d [5+]=%d\n",
			inactive[0], inactive[1], inactive[2],
			inactive[3], inactive[4], ref_inactive_overflow);
	else
		printf(" No inactive ports.\n");

	port_track_sort(&port_spaces);
	port_track_print(&port_spaces, FUNC_NULL);
	port_track_sort(&port_threads);
	port_track_print(&port_threads, FUNC_NULL);
	port_track_sort(&port_callers);
	port_track_print(&port_callers, port_callers_print);
	return 0;
}


#endif	/* MACH_ASSERT */

#endif	/* MACH_KDB */

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
#include <zone_debug.h>
#include <mach_assert.h>

#include <mach/port.h>
#include <mach/kern_return.h>
#include <kern/lock.h>
#include <kern/ipc_kobject.h>
#include <kern/thread.h>
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
#include <ipc/ipc_table.h>

#include <security/mac_mach_internal.h>

#include <string.h>

decl_lck_mtx_data(,	ipc_port_multiple_lock_data)
lck_mtx_ext_t	ipc_port_multiple_lock_data_ext;
ipc_port_timestamp_t	ipc_port_timestamp_data;
int ipc_portbt;

#if	MACH_ASSERT
void	ipc_port_init_debug(
		ipc_port_t	port,
		natural_t	*callstack,
		unsigned int	callstack_max);

void	ipc_port_callstack_init_debug(
		natural_t	*callstack,
		unsigned int	callstack_max);
	
#endif	/* MACH_ASSERT */

void
ipc_port_release(ipc_port_t port)
{
	ip_release(port);
}

void
ipc_port_reference(ipc_port_t port)
{
	ip_reference(port);
}

/*
 *	Routine:	ipc_port_timestamp
 *	Purpose:
 *		Retrieve a timestamp value.
 */

ipc_port_timestamp_t
ipc_port_timestamp(void)
{
	return OSIncrementAtomic(&ipc_port_timestamp_data);
}

/*
 *	Routine:	ipc_port_request_alloc
 *	Purpose:
 *		Try to allocate a request slot.
 *		If successful, returns the request index.
 *		Otherwise returns zero.
 *	Conditions:
 *		The port is locked and active.
 *	Returns:
 *		KERN_SUCCESS		A request index was found.
 *		KERN_NO_SPACE		No index allocated.
 */

kern_return_t
ipc_port_request_alloc(
	ipc_port_t			port,
	mach_port_name_t		name,
	ipc_port_t			soright,
	boolean_t			send_possible,
	boolean_t			immediate,
	ipc_port_request_index_t	*indexp)
{
	ipc_port_request_t ipr, table;
	ipc_port_request_index_t index;
	uintptr_t mask = 0;

	assert(ip_active(port));
	assert(name != MACH_PORT_NULL);
	assert(soright != IP_NULL);

	table = port->ip_requests;

	if (table == IPR_NULL)
		return KERN_NO_SPACE;

	index = table->ipr_next;
	if (index == 0)
		return KERN_NO_SPACE;

	ipr = &table[index];
	assert(ipr->ipr_name == MACH_PORT_NULL);

	table->ipr_next = ipr->ipr_next;
	ipr->ipr_name = name;
	
	if (send_possible) {
		mask |= IPR_SOR_SPREQ_MASK;
		if (immediate) {
			mask |= IPR_SOR_SPARM_MASK;
			port->ip_sprequests = TRUE;
		}
	}
	ipr->ipr_soright = IPR_SOR_MAKE(soright, mask);

	*indexp = index;

	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_port_request_grow
 *	Purpose:
 *		Grow a port's table of requests.
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
ipc_port_request_grow(
	ipc_port_t		port,
	ipc_table_elems_t 	target_size)
{
	ipc_table_size_t its;
	ipc_port_request_t otable, ntable;

	assert(ip_active(port));

	otable = port->ip_requests;
	if (otable == IPR_NULL)
		its = &ipc_table_requests[0];
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
	    ((ntable = it_requests_alloc(its)) == IPR_NULL)) {
		ip_release(port);
		return KERN_RESOURCE_SHORTAGE;
	}

	ip_lock(port);

	/*
	 *	Check that port is still active and that nobody else
	 *	has slipped in and grown the table on us.  Note that
	 *	just checking if the current table pointer == otable
	 *	isn't sufficient; must check ipr_size.
	 */

	if (ip_active(port) && (port->ip_requests == otable) &&
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
			oits = 0;
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
		port->ip_requests = ntable;
		ip_unlock(port);
		ip_release(port);

		if (otable != IPR_NULL) {
			it_requests_free(oits, otable);
	        }
	} else {
		ip_unlock(port);
		ip_release(port);
		it_requests_free(its, ntable);
	}

	return KERN_SUCCESS;
}
 
/*
 *	Routine:	ipc_port_request_sparm
 *	Purpose:
 *		Arm delayed send-possible request.
 *	Conditions:
 *		The port must be locked and active.
 */

void
ipc_port_request_sparm(
	ipc_port_t			port,
	__assert_only mach_port_name_t	name,
	ipc_port_request_index_t	index)
{
	if (index != IE_REQ_NONE) {
		ipc_port_request_t ipr, table;

		assert(ip_active(port));
	
		table = port->ip_requests;
		assert(table != IPR_NULL);

		ipr = &table[index];
		assert(ipr->ipr_name == name);

		if (IPR_SOR_SPREQ(ipr->ipr_soright)) {
			ipr->ipr_soright = IPR_SOR_MAKE(ipr->ipr_soright, IPR_SOR_SPARM_MASK);
			port->ip_sprequests = TRUE;
		}
	}
}

/*
 *	Routine:	ipc_port_request_type
 *	Purpose:
 *		Determine the type(s) of port requests enabled for a name.
 *	Conditions:
 *		The port must be locked or inactive (to avoid table growth).
 *		The index must not be IE_REQ_NONE and for the name in question.
 */
mach_port_type_t
ipc_port_request_type(
	ipc_port_t			port,
	__assert_only mach_port_name_t	name,
	ipc_port_request_index_t	index)
{
	ipc_port_request_t ipr, table;
	mach_port_type_t type = 0;

	table = port->ip_requests;
	assert (table != IPR_NULL);

	assert(index != IE_REQ_NONE);
	ipr = &table[index];
	assert(ipr->ipr_name == name);

	if (IP_VALID(IPR_SOR_PORT(ipr->ipr_soright))) {
		type |= MACH_PORT_TYPE_DNREQUEST;

		if (IPR_SOR_SPREQ(ipr->ipr_soright)) {
			type |= MACH_PORT_TYPE_SPREQUEST;

			if (!IPR_SOR_SPARMED(ipr->ipr_soright)) {
				type |= MACH_PORT_TYPE_SPREQUEST_DELAYED;
			}
		}
	}
	return type;
}

/*
 *	Routine:	ipc_port_request_cancel
 *	Purpose:
 *		Cancel a dead-name/send-possible request and return the send-once right.
 *	Conditions:
 *		The port must be locked and active.
 *		The index must not be IPR_REQ_NONE and must correspond with name.
 */

ipc_port_t
ipc_port_request_cancel(
	ipc_port_t			port,
	__assert_only mach_port_name_t	name,
	ipc_port_request_index_t	index)
{
	ipc_port_request_t ipr, table;
	ipc_port_t request = IP_NULL;

	assert(ip_active(port));
	table = port->ip_requests;
	assert(table != IPR_NULL);

	assert (index != IE_REQ_NONE);
	ipr = &table[index];
	assert(ipr->ipr_name == name);
	request = IPR_SOR_PORT(ipr->ipr_soright);

	/* return ipr to the free list inside the table */
	ipr->ipr_name = MACH_PORT_NULL;
	ipr->ipr_next = table->ipr_next;
	table->ipr_next = index;

	return request;
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
	ipc_port_t	port,
	queue_t		links)
{
	spl_t		s;

	assert(ip_active(port));

	/*
	 * pull ourselves from any sets.
	 */
	if (port->ip_pset_count != 0) {
		ipc_pset_remove_from_all(port, links);
		assert(port->ip_pset_count == 0);
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
	port->ip_requests = IPR_NULL;

	port->ip_pset_count = 0;
	port->ip_premsg = IKM_NULL;
	port->ip_context = 0;

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

#if     MACH_ASSERT
	natural_t buf[IP_CALLSTACK_MAX];
	ipc_port_callstack_init_debug(&buf[0], IP_CALLSTACK_MAX);
#endif /* MACH_ASSERT */
	    
	kr = ipc_object_alloc(space, IOT_PORT,
			      MACH_PORT_TYPE_RECEIVE, 0,
			      &name, (ipc_object_t *) &port);
	if (kr != KERN_SUCCESS)
		return kr;

	/* port and space are locked */
	ipc_port_init(port, space, name);

#if     MACH_ASSERT
	ipc_port_init_debug(port, &buf[0], IP_CALLSTACK_MAX);
#endif  /* MACH_ASSERT */

	/* unlock space after init */
	is_write_unlock(space);

#if CONFIG_MACF_MACH
	task_t issuer = current_task();
	tasklabel_lock2 (issuer, space->is_task);
	mac_port_label_associate(&issuer->maclabel, &space->is_task->maclabel,
			 &port->ip_label);
	tasklabel_unlock2 (issuer, space->is_task);
#endif

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

#if     MACH_ASSERT
	natural_t buf[IP_CALLSTACK_MAX];
	ipc_port_callstack_init_debug(&buf[0], IP_CALLSTACK_MAX);
#endif /* MACH_ASSERT */	

	kr = ipc_object_alloc_name(space, IOT_PORT,
				   MACH_PORT_TYPE_RECEIVE, 0,
				   name, (ipc_object_t *) &port);
	if (kr != KERN_SUCCESS)
		return kr;

	/* port is locked */

	ipc_port_init(port, space, name);

#if     MACH_ASSERT
	ipc_port_init_debug(port, &buf[0], IP_CALLSTACK_MAX);
#endif  /* MACH_ASSERT */	

#if CONFIG_MACF_MACH
	task_t issuer = current_task();
	tasklabel_lock2 (issuer, space->is_task);
	mac_port_label_associate(&issuer->maclabel, &space->is_task->maclabel,
			 &port->ip_label);
	tasklabel_unlock2 (issuer, space->is_task);
#endif

	*portp = port;

	return KERN_SUCCESS;
}

/*
 * 	Routine:	ipc_port_spnotify
 *	Purpose:
 *		Generate send-possible port notifications.
 *	Conditions:
 *		Nothing locked, reference held on port.
 */
void
ipc_port_spnotify(
	ipc_port_t	port)
{
	ipc_port_request_index_t index = 0;
	ipc_table_elems_t size = 0;

	/*
	 * If the port has no send-possible request
	 * armed, don't bother to lock the port.
	 */
	if (!port->ip_sprequests)
		return;

	ip_lock(port);
	if (!port->ip_sprequests) {
		ip_unlock(port);
		return;
	}
	port->ip_sprequests = FALSE;

 revalidate:
	if (ip_active(port)) {
		ipc_port_request_t requests;

		/* table may change each time port unlocked (reload) */
		requests = port->ip_requests;
		assert(requests != IPR_NULL);

		/*
		 * no need to go beyond table size when first
		 * we entered - those are future notifications.
		 */
		if (size == 0)
			size = requests->ipr_size->its_size;

		/* no need to backtrack either */
		while (++index < size) {
			ipc_port_request_t ipr = &requests[index];
			mach_port_name_t name = ipr->ipr_name;
			ipc_port_t soright = IPR_SOR_PORT(ipr->ipr_soright);
			boolean_t armed = IPR_SOR_SPARMED(ipr->ipr_soright);

			if (MACH_PORT_VALID(name) && armed && IP_VALID(soright)) {
				/* claim send-once right - slot still inuse */
				ipr->ipr_soright = IP_NULL;
				ip_unlock(port);

				ipc_notify_send_possible(soright, name);

				ip_lock(port);
				goto revalidate;
			}
		}
	}
	ip_unlock(port);
}

/*
 * 	Routine:	ipc_port_dnnotify
 *	Purpose:
 *		Generate dead name notifications for
 *		all outstanding dead-name and send-
 *		possible requests.
 *	Conditions:
 *		Nothing locked.
 *		Port must be inactive.
 *		Reference held on port.
 */
void
ipc_port_dnnotify(
	ipc_port_t	port)
{
	ipc_port_request_t requests = port->ip_requests;

	assert(!ip_active(port));
	if (requests != IPR_NULL) {
		ipc_table_size_t its = requests->ipr_size;
		ipc_table_elems_t size = its->its_size;
		ipc_port_request_index_t index;
		for (index = 1; index < size; index++) {
			ipc_port_request_t ipr = &requests[index];
			mach_port_name_t name = ipr->ipr_name;
			ipc_port_t soright = IPR_SOR_PORT(ipr->ipr_soright);

			if (MACH_PORT_VALID(name) && IP_VALID(soright)) {
				ipc_notify_dead_name(soright, name);
			}
		}
	}
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
	ipc_kmsg_t kmsg;

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

		/* consumes our refs for port and pdrequest */
		ipc_notify_port_destroyed(pdrequest, port);
		return;
	}

	/* once port is dead, we don't need to keep it locked */

	port->ip_object.io_bits &= ~IO_BITS_ACTIVE;
	port->ip_timestamp = ipc_port_timestamp();

	/*
	 * If the port has a preallocated message buffer and that buffer
	 * is not inuse, free it.  If it has an inuse one, then the kmsg
	 * free will detect that we freed the association and it can free it
	 * like a normal buffer.
	 */
	if (IP_PREALLOC(port)) {
		ipc_port_t inuse_port;

		kmsg = port->ip_premsg;
		assert(kmsg != IKM_NULL);
		inuse_port = ikm_prealloc_inuse_port(kmsg);
		IP_CLEAR_PREALLOC(port, kmsg);
		ip_unlock(port);
		if (inuse_port != IP_NULL) {
			assert(inuse_port == port);
		} else {
			ipc_kmsg_free(kmsg);
		}
	} else {
		ip_unlock(port);
	}

	/* throw away no-senders request */
	nsrequest = port->ip_nsrequest;
	if (nsrequest != IP_NULL)
		ipc_notify_send_once(nsrequest); /* consumes ref */

	/* destroy any queued messages */
	mqueue = &port->ip_messages;
	ipc_mqueue_destroy(mqueue);

	/* generate dead-name notifications */
	ipc_port_dnnotify(port);

	ipc_kobject_destroy(port);

	ip_release(port); /* consume caller's ref */
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

	assert(is_active(space));

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
 *	Routine:	ipc_port_make_send_locked
 *	Purpose:
 *		Make a naked send right from a receive right.
 *
 *	Conditions:
 *		port locked and active.
 */
ipc_port_t
ipc_port_make_send_locked(
	ipc_port_t	port)
{
	assert(ip_active(port));
	port->ip_mscount++;
	port->ip_srights++;
	ip_reference(port);
	ip_unlock(port);
	return port;
}

/*
 *	Routine:	ipc_port_make_send
 *	Purpose:
 *		Make a naked send right from a receive right.
 */

ipc_port_t
ipc_port_make_send(
	ipc_port_t	port)
{
	
	if (!IP_VALID(port))
		return port;

	ip_lock(port);
	if (ip_active(port)) {
		port->ip_mscount++;
		port->ip_srights++;
		ip_reference(port);
		ip_unlock(port);
		return port;
	}
	ip_unlock(port);
	return IP_DEAD;
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
		name = CAST_MACH_PORT_TO_NAME(sright);

	return name;
}

/*
 *	Routine:	ipc_port_release_send
 *	Purpose:
 *		Release a naked send right.
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

	if (!IP_VALID(port))
		return;

	ip_lock(port);

	if (!ip_active(port)) {
		ip_unlock(port);
		ip_release(port);
		return;
	}

	assert(port->ip_srights > 0);

	if (--port->ip_srights == 0 &&
	    port->ip_nsrequest != IP_NULL) {
		nsrequest = port->ip_nsrequest;
		port->ip_nsrequest = IP_NULL;
		mscount = port->ip_mscount;
		ip_unlock(port);
		ip_release(port);
		ipc_notify_no_senders(nsrequest, mscount);
	} else {
		ip_unlock(port);
		ip_release(port);
	}
}

/*
 *	Routine:	ipc_port_make_sonce_locked
 *	Purpose:
 *		Make a naked send-once right from a receive right.
 *	Conditions:
 *		The port is locked and active.
 */

ipc_port_t
ipc_port_make_sonce_locked(
	ipc_port_t	port)
{
	assert(ip_active(port));
	port->ip_sorights++;
	ip_reference(port);
	return port;
}

/*
 *	Routine:	ipc_port_make_sonce
 *	Purpose:
 *		Make a naked send-once right from a receive right.
 *	Conditions:
 *		The port is not locked.
 */

ipc_port_t
ipc_port_make_sonce(
	ipc_port_t	port)
{
	if (!IP_VALID(port))
		return port;

	ip_lock(port);
	if (ip_active(port)) {
		port->ip_sorights++;
		ip_reference(port);
		ip_unlock(port);
		return port;
	}
	ip_unlock(port);
	return IP_DEAD;
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
	if (!IP_VALID(port))
		return;

	ip_lock(port);

	assert(port->ip_sorights > 0);

	port->ip_sorights--;

	ip_unlock(port);
	ip_release(port);
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

	if (!IP_VALID(port))
		return;

	ip_lock(port);
	assert(ip_active(port));
	assert(port->ip_receiver_name == MACH_PORT_NULL);
	dest = port->ip_destination;

	ipc_port_destroy(port); /* consumes ref, unlocks */

	if (dest != IP_NULL)
		ip_release(dest);
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

#if     MACH_ASSERT
	natural_t buf[IP_CALLSTACK_MAX];
	ipc_port_callstack_init_debug(&buf[0], IP_CALLSTACK_MAX);
#endif /* MACH_ASSERT */	

	bzero((char *)port, sizeof(*port));
	io_lock_init(&port->ip_object);
	port->ip_references = 1;
	port->ip_object.io_bits = io_makebits(TRUE, IOT_PORT, 0);

	ipc_port_init(port, space, 1);

#if     MACH_ASSERT
	ipc_port_init_debug(port, &buf[0], IP_CALLSTACK_MAX);
#endif  /* MACH_ASSERT */		

#if CONFIG_MACF_MACH
	/* Currently, ipc_port_alloc_special is used for two things:
	 * - Reply ports for messages from the kernel
	 * - Ports for communication with the kernel (e.g. task ports)
	 * Since both of these would typically be labelled as kernel objects,
	 * we will use a new entry point for this purpose, as current_task()
	 * is often wrong (i.e. not kernel_task) or null.
	 */
	mac_port_label_init(&port->ip_label);
	mac_port_label_associate_kernel(&port->ip_label, space == ipc_space_reply);
#endif

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
	ipc_port_t			port,
	__assert_only ipc_space_t	space)
{
	ip_lock(port);
	assert(ip_active(port));
//	assert(port->ip_receiver_name != MACH_PORT_NULL);
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

/*
 *	Routine:	ipc_port_finalize
 *	Purpose:
 *		Called on last reference deallocate to
 *		free any remaining data associated with the
 *		port.
 *	Conditions:
 *		Nothing locked.
 */
void
ipc_port_finalize(
	ipc_port_t		port)
{
	ipc_port_request_t requests = port->ip_requests;

	assert(!ip_active(port));
	if (requests != IPR_NULL) {
		ipc_table_size_t its = requests->ipr_size;
		it_requests_free(its, requests);
		port->ip_requests = IPR_NULL;
	}
	
#if	MACH_ASSERT
	ipc_port_track_dealloc(port);
#endif	/* MACH_ASSERT */

#if CONFIG_MACF_MACH
	/* Port label should have been initialized after creation. */
	mac_port_label_destroy(&port->ip_label);
#endif	  
}

#if	MACH_ASSERT
#include <kern/machine.h>

/*
 *	Keep a list of all allocated ports.
 *	Allocation is intercepted via ipc_port_init;
 *	deallocation is intercepted via io_free.
 */
queue_head_t	port_alloc_queue;
lck_spin_t	port_alloc_queue_lock;

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

	lck_spin_init(&port_alloc_queue_lock, &ipc_lck_grp, &ipc_lck_attr);

	if (!PE_parse_boot_argn("ipc_portbt", &ipc_portbt, sizeof (ipc_portbt)))
		ipc_portbt = 0;
}

#ifdef MACH_BSD
extern int proc_pid(struct proc*);
#endif /* MACH_BSD */

/*
 *	Initialize all of the debugging state in a port.
 *	Insert the port into a global list of all allocated ports.
 */
void
ipc_port_init_debug(
	ipc_port_t	port,
	natural_t 	*callstack,
	unsigned int	callstack_max)
{
	unsigned int	i;

	port->ip_thread = current_thread();
	port->ip_timetrack = port_timestamp++;
	for (i = 0; i < callstack_max; ++i)
		port->ip_callstack[i] = callstack[i];	
	for (i = 0; i < IP_NSPARES; ++i)
		port->ip_spares[i] = 0;	

#ifdef MACH_BSD
	task_t task = current_task();
	if (task != TASK_NULL) {
		struct proc* proc = (struct proc*) get_bsdtask_info(task);
		if (proc)
			port->ip_spares[0] = proc_pid(proc);
	}
#endif /* MACH_BSD */

#if 0
	lck_spin_lock(&port_alloc_queue_lock);
	++port_count;
	if (port_count_warning > 0 && port_count >= port_count_warning)
		assert(port_count < port_count_warning);
	queue_enter(&port_alloc_queue, port, ipc_port_t, ip_port_links);
	lck_spin_unlock(&port_alloc_queue_lock);
#endif
}

/*
 *	Routine:	ipc_port_callstack_init_debug
 *	Purpose:
 *		Calls the machine-dependent routine to
 *		fill in an array with up to IP_CALLSTACK_MAX
 *		levels of return pc information
 *	Conditions:
 *		May block (via copyin)
 */
void
ipc_port_callstack_init_debug(
	natural_t	*callstack,
	unsigned int	callstack_max)
{
	unsigned int	i;

	/* guarantee the callstack is initialized */
	for (i=0; i < callstack_max; i++)
		callstack[i] = 0;	

	if (ipc_portbt)
		machine_callstack(callstack, callstack_max);
}

/*
 *	Remove a port from the queue of allocated ports.
 *	This routine should be invoked JUST prior to
 *	deallocating the actual memory occupied by the port.
 */
#if 1
void
ipc_port_track_dealloc(
	__unused ipc_port_t	port)
{
}
#else
void
ipc_port_track_dealloc(
	ipc_port_t		port)
{
	lck_spin_lock(&port_alloc_queue_lock);
	assert(port_count > 0);
	--port_count;
	queue_remove(&port_alloc_queue, port, ipc_port_t, ip_port_links);
	lck_spin_unlock(&port_alloc_queue_lock);
}
#endif


#endif	/* MACH_ASSERT */

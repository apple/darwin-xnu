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
 *	File:	ipc/ipc_pset.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Functions to manipulate IPC port sets.
 */

#include <mach/port.h>
#include <mach/kern_return.h>
#include <mach/message.h>
#include <ipc/ipc_mqueue.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_pset.h>
#include <ipc/ipc_right.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_print.h>

/*
 *	Routine:	ipc_pset_alloc
 *	Purpose:
 *		Allocate a port set.
 *	Conditions:
 *		Nothing locked.  If successful, the port set is returned
 *		locked.  (The caller doesn't have a reference.)
 *	Returns:
 *		KERN_SUCCESS		The port set is allocated.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_NO_SPACE		No room for an entry in the space.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
ipc_pset_alloc(
	ipc_space_t		space,
	mach_port_name_t	*namep,
	ipc_pset_t		*psetp)
{
	ipc_pset_t pset;
	mach_port_name_t name;
	kern_return_t kr;

	kr = ipc_object_alloc(space, IOT_PORT_SET,
			      MACH_PORT_TYPE_PORT_SET, 0,
			      &name, (ipc_object_t *) &pset);
	if (kr != KERN_SUCCESS)
		return kr;
	/* pset is locked */

	pset->ips_local_name = name;
	ipc_mqueue_init(&pset->ips_messages, TRUE /* set */);

	*namep = name;
	*psetp = pset;
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_pset_alloc_name
 *	Purpose:
 *		Allocate a port set, with a specific name.
 *	Conditions:
 *		Nothing locked.  If successful, the port set is returned
 *		locked.  (The caller doesn't have a reference.)
 *	Returns:
 *		KERN_SUCCESS		The port set is allocated.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_NAME_EXISTS	The name already denotes a right.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
ipc_pset_alloc_name(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_pset_t		*psetp)
{
	ipc_pset_t pset;
	kern_return_t kr;


	kr = ipc_object_alloc_name(space, IOT_PORT_SET,
				   MACH_PORT_TYPE_PORT_SET, 0,
				   name, (ipc_object_t *) &pset);
	if (kr != KERN_SUCCESS)
		return kr;
	/* pset is locked */

	pset->ips_local_name = name;
	ipc_mqueue_init(&pset->ips_messages, TRUE /* set */);

	*psetp = pset;
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_pset_member
 *	Purpose:
 *		Checks to see if a port is a member of a pset
 *	Conditions:
 *		Both port and port set are locked.
 *		The port must be active.
 */
boolean_t
ipc_pset_member(
	ipc_pset_t	pset,
	ipc_port_t	port)
{
	assert(ip_active(port));

	return (ipc_mqueue_member(&port->ip_messages, &pset->ips_messages));
}


/*
 *	Routine:	ipc_pset_add
 *	Purpose:
 *		Puts a port into a port set.
 *	Conditions:
 *		Both port and port set are locked and active.
 *		The owner of the port set is also receiver for the port.
 */

kern_return_t
ipc_pset_add(
	ipc_pset_t	pset,
	ipc_port_t	port)
{
	kern_return_t kr;

	assert(ips_active(pset));
	assert(ip_active(port));
	
	kr = ipc_mqueue_add(&port->ip_messages, &pset->ips_messages);

	if (kr == KERN_SUCCESS)
		port->ip_pset_count++;

	return kr;
}



/*
 *	Routine:	ipc_pset_remove
 *	Purpose:
 *		Removes a port from a port set.
 *		The port set loses a reference.
 *	Conditions:
 *		Both port and port set are locked.
 *		The port must be active.
 */

kern_return_t
ipc_pset_remove(
	ipc_pset_t	pset,
	ipc_port_t	port)
{
	kern_return_t kr;

	assert(ip_active(port));
	
	if (port->ip_pset_count == 0)
		return KERN_NOT_IN_SET;

	kr = ipc_mqueue_remove(&port->ip_messages, &pset->ips_messages);

	if (kr == KERN_SUCCESS)
		port->ip_pset_count--;

	return kr;
}

/*
 *	Routine:	ipc_pset_remove_from_all
 *	Purpose:
 *		Removes a port from all it's port sets.
 *	Conditions:
 *		port is locked and active.
 */

kern_return_t
ipc_pset_remove_from_all(
	ipc_port_t	port)
{
	ipc_pset_t pset;

	assert(ip_active(port));
	
	if (port->ip_pset_count == 0)
		return KERN_NOT_IN_SET;

	/* 
	 * Remove the port's mqueue from all sets
	 */
	ipc_mqueue_remove_from_all(&port->ip_messages);
	port->ip_pset_count = 0;
	return KERN_SUCCESS;
}


/*
 *	Routine:	ipc_pset_destroy
 *	Purpose:
 *		Destroys a port_set.
 *	Conditions:
 *		The port_set is locked and alive.
 *		The caller has a reference, which is consumed.
 *		Afterwards, the port_set is unlocked and dead.
 */

void
ipc_pset_destroy(
	ipc_pset_t	pset)
{
	spl_t		s;

	assert(ips_active(pset));

	pset->ips_object.io_bits &= ~IO_BITS_ACTIVE;

	/*
	 * remove all the member message queues
	 */
	ipc_mqueue_remove_all(&pset->ips_messages);
	
	s = splsched();
	imq_lock(&pset->ips_messages);
	ipc_mqueue_changed(&pset->ips_messages);
	imq_unlock(&pset->ips_messages);
	splx(s);

	/* XXXX Perhaps ought to verify ips_thread_pool is empty */

	ips_release(pset);	/* consume the ref our caller gave us */
	ips_check_unlock(pset);
}

#include <mach_kdb.h>
#if	MACH_KDB

#include <ddb/db_output.h>

#define	printf	kdbprintf

int
ipc_list_count(
	struct ipc_kmsg *base)
{
	register int count = 0;

	if (base) {
		struct ipc_kmsg *kmsg = base;

		++count;
		while (kmsg && kmsg->ikm_next != base
			    && kmsg->ikm_next != IKM_BOGUS){
			kmsg = kmsg->ikm_next;
			++count;
		}
	}
	return(count);
}

/*
 *	Routine:	ipc_pset_print
 *	Purpose:
 *		Pretty-print a port set for kdb.
 */

void
ipc_pset_print(
	ipc_pset_t	pset)
{
	extern int db_indent;

	printf("pset 0x%x\n", pset);

	db_indent += 2;

	ipc_object_print(&pset->ips_object);
	iprintf("local_name = 0x%x\n", pset->ips_local_name);
	iprintf("%d kmsgs => 0x%x",
		ipc_list_count(pset->ips_messages.imq_messages.ikmq_base),
		pset->ips_messages.imq_messages.ikmq_base);
	printf(",rcvrs queue= 0x%x\n", &pset->ips_messages.imq_wait_queue);

	db_indent -=2;
}

#endif	/* MACH_KDB */

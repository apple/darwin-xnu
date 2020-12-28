/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 *
 */

#include <kern/sync_sema.h>
#include <kern/sync_lock.h>
#include <kern/ipc_kobject.h>
#include <kern/ipc_sync.h>
#include <ipc/port.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_port.h>
#include <mach/mach_types.h>
#include <mach/semaphore.h>
#include <mach/lock_set_server.h>
#include <mach/mach_port_server.h>
#include <mach/port.h>


/*
 *	Routine:	port_name_to_semaphore
 *	Purpose:
 *		Convert from a port name in the current space to a semaphore.
 *		Produces a semaphore ref, which may be null.
 *	Conditions:
 *		Nothing locked.
 */
kern_return_t
port_name_to_semaphore(
	mach_port_name_t        name,
	semaphore_t             *semaphorep)
{
	ipc_port_t kern_port;
	kern_return_t kr;

	if (!MACH_PORT_VALID(name)) {
		*semaphorep = SEMAPHORE_NULL;
		return KERN_INVALID_NAME;
	}

	kr = ipc_port_translate_send(current_space(), name, &kern_port);
	if (kr != KERN_SUCCESS) {
		*semaphorep = SEMAPHORE_NULL;
		return kr;
	}
	/* have the port locked */
	assert(IP_VALID(kern_port));

	*semaphorep = convert_port_to_semaphore(kern_port);
	if (*semaphorep == SEMAPHORE_NULL) {
		/* the port is valid, but doesn't denote a semaphore */
		kr = KERN_INVALID_CAPABILITY;
	} else {
		kr = KERN_SUCCESS;
	}
	ip_unlock(kern_port);

	return kr;
}

/*
 *	Routine:	convert_port_to_semaphore
 *	Purpose:
 *		Convert from a port to a semaphore.
 *		Doesn't consume the port [send-right] ref;
 *		produces a semaphore ref, which may be null.
 *	Conditions:
 *		Caller has a send-right reference to port.
 *		Port may or may not be locked.
 */
semaphore_t
convert_port_to_semaphore(ipc_port_t port)
{
	if (IP_VALID(port)) {
		semaphore_t semaphore;

		/*
		 * No need to lock because we have a reference on the
		 * port, and if it is a true semaphore port, that reference
		 * keeps the semaphore bound to the port (and active).
		 */
		if (ip_kotype(port) == IKOT_SEMAPHORE) {
			require_ip_active(port);
			semaphore = (semaphore_t) ip_get_kobject(port);
			semaphore_reference(semaphore);
			return semaphore;
		}
	}
	return SEMAPHORE_NULL;
}


/*
 *	Routine:	convert_semaphore_to_port
 *	Purpose:
 *		Convert a semaphore reference to a send right to a
 *		semaphore port.
 *
 *		Consumes the semaphore reference.  If the semaphore
 *		port currently has no send rights (or doesn't exist
 *		yet), the reference is donated to the port to represent
 *		all extant send rights collectively.
 */
ipc_port_t
convert_semaphore_to_port(semaphore_t semaphore)
{
	if (semaphore == SEMAPHORE_NULL) {
		return IP_NULL;
	}

	/*
	 * make a send right and donate our reference for
	 * semaphore_notify if this is the first send right
	 */
	if (!ipc_kobject_make_send_lazy_alloc_port(&semaphore->port,
	    (ipc_kobject_t) semaphore, IKOT_SEMAPHORE)) {
		semaphore_dereference(semaphore);
	}
	return semaphore->port;
}

/*
 * Routine:	semaphore_notify
 * Purpose:
 *	Called whenever the Mach port system detects no-senders
 *	on the semaphore port.
 *
 *	When a send-right is first created, a no-senders
 *	notification is armed (and a semaphore reference is donated).
 *
 *	A no-senders notification will be posted when no one else holds a
 *	send-right (reference) to the semaphore's port. This notification function
 *	will consume the semaphore reference donated to the extant collection of
 *	send-rights.
 */
void
semaphore_notify(mach_msg_header_t *msg)
{
	mach_no_senders_notification_t *notification = (void *)msg;
	ipc_port_t port = notification->not_header.msgh_remote_port;

	require_ip_active(port);
	assert(IKOT_SEMAPHORE == ip_kotype(port));

	semaphore_dereference((semaphore_t) ip_get_kobject(port));
}

lock_set_t
convert_port_to_lock_set(__unused ipc_port_t port)
{
	return LOCK_SET_NULL;
}

ipc_port_t
convert_lock_set_to_port(__unused lock_set_t lock_set)
{
	return IP_NULL;
}

/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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
#include <mach/semaphore.h>
#include <mach/lock_set_server.h>
#include <mach/mach_port_server.h>
#include <mach/port.h>


kern_return_t
port_name_to_semaphore(
	mach_port_name_t 	name,
	semaphore_t 		*semaphorep)
{
	semaphore_t semaphore;
	ipc_port_t kern_port;
	kern_return_t kr;

	if (!MACH_PORT_VALID(name)) {
		*semaphorep = SEMAPHORE_NULL;
		return KERN_INVALID_NAME;
	}
	
	kr = ipc_object_translate(current_space(), name, MACH_PORT_RIGHT_SEND,
				  (ipc_object_t *) &kern_port);
	if (kr != KERN_SUCCESS) {
		*semaphorep = SEMAPHORE_NULL;
		return kr;
	}
	/* have the port locked */
	assert(IP_VALID(kern_port));

	if (!ip_active(kern_port) || (ip_kotype(kern_port) != IKOT_SEMAPHORE)) {
		ip_unlock(kern_port);
		*semaphorep = SEMAPHORE_NULL;
		return KERN_INVALID_ARGUMENT;
	}

	semaphore = (semaphore_t) kern_port->ip_kobject;
	assert(semaphore != SEMAPHORE_NULL);
	semaphore_reference(semaphore);
	ip_unlock(kern_port);

	*semaphorep = semaphore;
	return KERN_SUCCESS;
}
	
semaphore_t
convert_port_to_semaphore (ipc_port_t port)
{
	semaphore_t semaphore = SEMAPHORE_NULL;

	if (IP_VALID (port)) {
		ip_lock(port);
		if (ip_active(port) && (ip_kotype(port) == IKOT_SEMAPHORE)) {
			semaphore = (semaphore_t) port->ip_kobject;
			semaphore_reference(semaphore);
		}
		ip_unlock(port);
	}

	return (semaphore);
}


ipc_port_t
convert_semaphore_to_port (semaphore_t semaphore)
{
	ipc_port_t port;

	if (semaphore != SEMAPHORE_NULL)
		port = ipc_port_make_send(semaphore->port);
	else
		port = IP_NULL;

	return (port);
}

lock_set_t
convert_port_to_lock_set (ipc_port_t port)
{
	lock_set_t lock_set = LOCK_SET_NULL;

	if (IP_VALID (port)) {
		ip_lock(port);
		if (ip_active(port) && (ip_kotype(port) == IKOT_LOCK_SET)) {
			lock_set = (lock_set_t) port->ip_kobject;
			lock_set_reference(lock_set);
		}
		ip_unlock(port);
	}

	return (lock_set);
}

ipc_port_t
convert_lock_set_to_port (lock_set_t lock_set)
{
	ipc_port_t port;

	if (lock_set != LOCK_SET_NULL)
		port = ipc_port_make_send(lock_set->port);
	else
		port = IP_NULL;

	return (port);
}


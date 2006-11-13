/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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
 *	File:	ipc/ipc_notify.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Notification-sending functions.
 */

#include <mach/port.h>
#include <mach/message.h>
#include <mach/mach_notify.h>
#include <kern/misc_protos.h>
#include <ipc/ipc_notify.h>
#include <ipc/ipc_port.h>

/*
 *	Routine:	ipc_notify_port_deleted
 *	Purpose:
 *		Send a port-deleted notification.
 *	Conditions:
 *		Nothing locked.
 *		Consumes a ref/soright for port.
 */

void
ipc_notify_port_deleted(
	ipc_port_t		port,
	mach_port_name_t	name)
{
	kern_return_t kr;

	kr = mach_notify_port_deleted(port, name);
	if (kr != KERN_SUCCESS) {
		printf("dropped port-deleted (0x%08x, 0x%x)\n", port, name);
		ipc_port_release_sonce(port);
	}
}

/*
 *	Routine:	ipc_notify_port_destroyed
 *	Purpose:
 *		Send a port-destroyed notification.
 *	Conditions:
 *		Nothing locked.
 *		Consumes a ref/soright for port.
 *		Consumes a ref for right, which should be a receive right
 *		prepped for placement into a message.  (In-transit,
 *		or in-limbo if a circularity was detected.)
 */

void
ipc_notify_port_destroyed(
	ipc_port_t	port,
	ipc_port_t	right)
{
	kern_return_t kr;

	kr = mach_notify_port_destroyed(port, right);
	if (kr != KERN_SUCCESS) {
		printf("dropped port-destroyed (0x%08x, 0x%08x)\n",
		       port, right);
		ipc_port_release_sonce(port);
		ipc_port_release_receive(right);
	}
}

/*
 *	Routine:	ipc_notify_no_senders
 *	Purpose:
 *		Send a no-senders notification.
 *	Conditions:
 *		Nothing locked.
 *		Consumes a ref/soright for port.
 */

void
ipc_notify_no_senders(
	ipc_port_t		port,
	mach_port_mscount_t	mscount)
{
	kern_return_t kr;

	kr = mach_notify_no_senders(port, mscount);
	if (kr != KERN_SUCCESS) {
		printf("dropped no-senders (0x%08x, %u)\n", port, mscount);
		ipc_port_release_sonce(port);
	}
}

/*
 *	Routine:	ipc_notify_send_once
 *	Purpose:
 *		Send a send-once notification.
 *	Conditions:
 *		Nothing locked.
 *		Consumes a ref/soright for port.
 */

void
ipc_notify_send_once(
	ipc_port_t	port)
{
	kern_return_t kr;

	kr = mach_notify_send_once(port);
	if (kr != KERN_SUCCESS) {
		printf("dropped send-once (0x%08x)\n", port);
		ipc_port_release_sonce(port);
	}
}

/*
 *	Routine:	ipc_notify_dead_name
 *	Purpose:
 *		Send a dead-name notification.
 *	Conditions:
 *		Nothing locked.
 *		Consumes a ref/soright for port.
 */

void
ipc_notify_dead_name(
	ipc_port_t		port,
	mach_port_name_t	name)
{
	kern_return_t kr;

	kr = mach_notify_dead_name(port, name);
	if (kr != KERN_SUCCESS) {
		printf("dropped dead-name (0x%08x, 0x%x)\n", port, name);
		ipc_port_release_sonce(port);
	}
}

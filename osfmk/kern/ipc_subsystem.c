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
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:34  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.2  1998/04/29 17:35:56  mburg
 * MK7.3 merger
 *
 * Revision 1.1.10.1  1998/02/03  09:28:28  gdt
 * 	Merge up to MK7.3
 * 	[1998/02/03  09:13:40  gdt]
 *
 * Revision 1.1.8.1  1997/06/17  02:57:46  devrcs
 * 	Added `ipc_subsystem_terminate().'
 * 	[1997/03/18  18:25:52  rkc]
 * 
 * Revision 1.1.5.1  1994/09/23  02:19:57  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:33:39  ezf]
 * 
 * Revision 1.1.3.1  1994/01/20  11:05:46  emcmanus
 * 	Copied for submission.
 * 	[1994/01/20  11:04:25  emcmanus]
 * 
 * Revision 1.1.1.2  1994/01/13  02:40:32  condict
 * 	IPC support for the RPC subsytem object (server co-location).
 * 
 * $EndLog$
 */

/*
 *	File:		kern/ipc_subsystem.c
 *	Purpose:	Routines to support ipc semantics of new kernel
 *			RPC subsystem descriptions
 */

#include <mach/message.h>
#include <kern/ipc_kobject.h>
#include <kern/task.h>
#include <kern/ipc_subsystem.h>
#include <kern/subsystem.h>
#include <kern/misc_protos.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>

/*
 *	Routine:	ipc_subsystem_init
 *	Purpose:
 *		Initialize ipc control of a subsystem.
 */
void
ipc_subsystem_init(
	subsystem_t		subsystem)
{
	ipc_port_t	port;

	port = ipc_port_alloc_kernel();
	if (port == IP_NULL)
		panic("ipc_subsystem_init");
	subsystem->ipc_self = port;
}

/*
 *	Routine:	ipc_subsystem_enable
 *	Purpose:
 *		Enable ipc access to a subsystem.
 */
void
ipc_subsystem_enable(
	subsystem_t		subsystem)
{
	ipc_kobject_set(subsystem->ipc_self,
			(ipc_kobject_t) subsystem, IKOT_SUBSYSTEM);
}


/*
 *      Routine:        ipc_subsystem_disable
 *      Purpose:
 *              Disable IPC access to a subsystem.
 *      Conditions:
 *              Nothing locked.
 */

void
ipc_subsystem_disable(
        subsystem_t        subsystem)
{
        ipc_port_t kport;

        kport = subsystem->ipc_self;
        if (kport != IP_NULL)
                ipc_kobject_set(kport, IKO_NULL, IKOT_NONE);
}

/*
 *	Routine:	ipc_subsystem_terminate
 *	Purpose:
 *		Clean up and destroy a subsystem's IPC state.
 */
void
ipc_subsystem_terminate(
	subsystem_t		subsystem)
{
	ipc_port_dealloc_kernel(subsystem->ipc_self);
}


/*
 *	Routine:	convert_port_to_subsystem
 *	Purpose:
 *		Convert from a port to a subsystem.
 *		Doesn't consume the port ref; produces a subsystem ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */
subsystem_t
convert_port_to_subsystem(
	ipc_port_t	port)
{
	subsystem_t		subsystem = SUBSYSTEM_NULL;

	if (IP_VALID(port)) {
		ip_lock(port);
		if (ip_active(port) &&
		    (ip_kotype(port) == IKOT_SUBSYSTEM)) {
			subsystem = (subsystem_t) port->ip_kobject;
		}
		ip_unlock(port);
	}
	return (subsystem);
}


/*
 *	Routine:	convert_subsystem_to_port
 *	Purpose:
 *		Convert from a subsystem to a port.
 *		Produces a naked send right which may be invalid.
 *	Conditions:
 *		Nothing locked.
 */
ipc_port_t
convert_subsystem_to_port(
	subsystem_t		subsystem)
{
	ipc_port_t	port;

	port = ipc_port_make_send(subsystem->ipc_self);
	return (port);
}


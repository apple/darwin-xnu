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
 * Revision 1.1.1.1  1998/03/07 02:25:55  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.5.1  1994/09/23  02:20:11  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:33:42  ezf]
 *
 * Revision 1.1.3.1  1994/01/20  11:05:50  emcmanus
 * 	Copied for submission.
 * 	[1994/01/20  11:04:35  emcmanus]
 * 
 * Revision 1.1.1.2  1994/01/13  02:41:12  condict
 * 	Declarations for kern/ipc_subsystem.c
 * 
 * $EndLog$
 */

#ifndef	_KERN_IPC_SUBSYSTEM_H_
#define _KERN_IPC_SUBSYSTEM_H_

#include <mach/boolean.h>
#include <mach/port.h>
#include <kern/subsystem.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_object.h>


/* Initialize a subsystem's IPC state */
extern void ipc_subsystem_init(
	subsystem_t		subsystem);

/* Enable a subsystem for IPC access */
extern void ipc_subsystem_enable(
	subsystem_t		subsystem);

/* Disable IPC access to a subsystem */
extern void ipc_subsystem_disable(
	subsystem_t		subsystem);

/* Clean up and destroy a subsystem's IPC state */
extern void ipc_subsystem_terminate(
	subsystem_t		subsystem);

/* Convert from a port to a subsystem */
extern subsystem_t convert_port_to_subsystem(
	ipc_port_t	port);

/* Convert from a subsystem to a port */
extern ipc_port_t convert_subsystem_to_port(
	subsystem_t	subsystem);

#endif	/* _KERN_IPC_SUBSYSTEM_H_ */

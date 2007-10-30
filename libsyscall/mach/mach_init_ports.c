/*
 * Copyright (c) 2003-2004 Apple Computer, Inc. All rights reserved.
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
 */

/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
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

#include <mach/mach.h>
#include <stdlib.h>
#include "externs.h"

mach_port_t	bootstrap_port = MACH_PORT_NULL;
mach_port_t	name_server_port = MACH_PORT_NULL;
mach_port_t	environment_port = MACH_PORT_NULL;
mach_port_t	service_port = MACH_PORT_NULL;
semaphore_t	clock_sem = MACH_PORT_NULL;
mach_port_t	clock_port = MACH_PORT_NULL;
mach_port_t thread_recycle_port = MACH_PORT_NULL;

void
mach_init_ports(void)
{
	mach_port_array_t	ports;
	mach_msg_type_number_t	ports_count;
	kern_return_t		kr;
	host_t			host;

	/*
	 *	Find those ports important to every task.
	 */
	kr = task_get_special_port(mach_task_self(),
				   TASK_BOOTSTRAP_PORT,
				   &bootstrap_port);
	if (kr != KERN_SUCCESS)
	    return;

        /* Get the clock service port for nanosleep */
	host = mach_host_self();
        kr = host_get_clock_service(host, SYSTEM_CLOCK, &clock_port);
        if (kr != KERN_SUCCESS) {
            abort();
	}
        kr = semaphore_create(mach_task_self(), &clock_sem, SYNC_POLICY_FIFO, 0);
        if (kr != KERN_SUCCESS) {
            abort();
        }
	mach_port_deallocate(mach_task_self(), host);
        kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &thread_recycle_port);
        if (kr != KERN_SUCCESS) {
            abort();
        }

	/*
	 *	Find the options service ports.
	 *	XXX - Don't need these on Darwin, should go away.
	 */
	kr = mach_ports_lookup(mach_task_self(), &ports,
			       &ports_count);
	if (kr == KERN_SUCCESS) {
		if (ports_count >= MACH_PORTS_SLOTS_USED) {
			name_server_port = ports[NAME_SERVER_SLOT];
			environment_port = ports[ENVIRONMENT_SLOT];
			service_port     = ports[SERVICE_SLOT];
		}

		/* get rid of out-of-line data */
		(void) vm_deallocate(mach_task_self(),
			     (vm_offset_t) ports,
			     (vm_size_t) (ports_count * sizeof *ports));
	}
}

#ifdef notdef
/* will have problems with dylib build --> not needed anyway */
#ifndef	lint
/*
 *	Routines which our library must suck in, to avoid
 *	a later library from referencing them and getting
 *	the wrong version.
 */
extern void _replacements(void);

void
_replacements(void)
{
	(void)sbrk(0);			/* Pull in our sbrk/brk */
	(void)malloc(0);		/* Pull in our malloc package */
}
#endif	/* lint */
#endif /* notdef */

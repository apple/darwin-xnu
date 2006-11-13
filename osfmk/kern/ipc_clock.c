/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 *	File:		kern/ipc_clock.c
 *	Purpose:	Routines to support ipc semantics of new kernel
 *			alarm clock facility.
 */

#include <mach/message.h>
#include <kern/host.h>
#include <kern/processor.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/ipc_host.h>
#include <kern/ipc_kobject.h>
#include <kern/clock.h>
#include <kern/misc_protos.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>

/*
 *	Routine:	ipc_clock_init
 *	Purpose:
 *		Initialize ipc control of a clock.
 */
void
ipc_clock_init(
	clock_t		clock)
{
	ipc_port_t	port;

	port = ipc_port_alloc_kernel();
	if (port == IP_NULL)
		panic("ipc_clock_init");
	clock->cl_service = port;

	port = ipc_port_alloc_kernel();
	if (port == IP_NULL)
		panic("ipc_clock_init");
	clock->cl_control = port;
}

/*
 *	Routine:	ipc_clock_enable
 *	Purpose:
 *		Enable ipc access to a clock.
 */
void
ipc_clock_enable(
	clock_t		clock)
{
	ipc_kobject_set(clock->cl_service,
			(ipc_kobject_t) clock, IKOT_CLOCK);
	ipc_kobject_set(clock->cl_control,
			(ipc_kobject_t) clock, IKOT_CLOCK_CTRL);
}

/*
 *	Routine:	convert_port_to_clock
 *	Purpose:
 *		Convert from a port to a clock.
 *		Doesn't consume the port ref; produces a clock ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */
clock_t
convert_port_to_clock(
	ipc_port_t	port)
{
	clock_t		clock = CLOCK_NULL;

	if (IP_VALID(port)) {
		ip_lock(port);
		if (ip_active(port) &&
		    ((ip_kotype(port) == IKOT_CLOCK) ||
		     (ip_kotype(port) == IKOT_CLOCK_CTRL))) {
			clock = (clock_t) port->ip_kobject;
		}
		ip_unlock(port);
	}
	return (clock);
}

/*
 *	Routine:	convert_port_to_clock_ctrl
 *	Purpose:
 *		Convert from a port to a clock.
 *		Doesn't consume the port ref; produces a clock ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */
clock_t
convert_port_to_clock_ctrl(
	ipc_port_t	port)
{
	clock_t		clock = CLOCK_NULL;

	if (IP_VALID(port)) {
		ip_lock(port);
		if (ip_active(port) &&
		    (ip_kotype(port) == IKOT_CLOCK_CTRL)) {
			clock = (clock_t) port->ip_kobject;
		}
		ip_unlock(port);
	}
	return (clock);
}

/*
 *	Routine:	convert_clock_to_port
 *	Purpose:
 *		Convert from a clock to a port.
 *		Produces a naked send right which may be invalid.
 *	Conditions:
 *		Nothing locked.
 */
ipc_port_t
convert_clock_to_port(
	clock_t		clock)
{
	ipc_port_t	port;

	port = ipc_port_make_send(clock->cl_service);
	return (port);
}

/*
 *	Routine:	convert_clock_ctrl_to_port
 *	Purpose:
 *		Convert from a clock to a port.
 *		Produces a naked send right which may be invalid.
 *	Conditions:
 *		Nothing locked.
 */
ipc_port_t
convert_clock_ctrl_to_port(
	clock_t		clock)
{
	ipc_port_t	port;

	port = ipc_port_make_send(clock->cl_control);
	return (port);
}

/*
 *	Routine:	port_name_to_clock
 *	Purpose:
 *		Convert from a clock name to a clock pointer.
 */
clock_t
port_name_to_clock(
	mach_port_name_t clock_name)
{
	clock_t		clock = CLOCK_NULL;
	ipc_space_t	space;
	ipc_port_t	port;

	if (clock_name == 0)
		return (clock);
	space = current_space();
	if (ipc_port_translate_send(space, clock_name, &port) != KERN_SUCCESS)
		return (clock);
	if (ip_active(port) && (ip_kotype(port) == IKOT_CLOCK))
		clock = (clock_t) port->ip_kobject;
	ip_unlock(port);
	return (clock);
}

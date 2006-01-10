/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
 *	File:	ipc/ipc_right.h
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Declarations of functions to manipulate IPC capabilities.
 */

#ifndef	_IPC_IPC_RIGHT_H_
#define	_IPC_IPC_RIGHT_H_

#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_entry.h>

#define	ipc_right_lookup_read		ipc_right_lookup_write
#define ipc_right_lookup_two_read	ipc_right_lookup_two_write

/* Find an entry in a space, given the name */
extern kern_return_t ipc_right_lookup_write(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_entry_t		*entryp);

/* Find two entries in a space, given two names */
extern kern_return_t ipc_right_lookup_two_write(
	ipc_space_t		space,
	mach_port_name_t	name1,
	ipc_entry_t		*entryp1,
	mach_port_name_t	name2,
	ipc_entry_t		*entryp2);

/* Translate (space, object) -> (name, entry) */
extern boolean_t ipc_right_reverse(
	ipc_space_t		space,
	ipc_object_t		object,
	mach_port_name_t	*namep,
	ipc_entry_t		*entryp);

/* Make a dead-name request, returning the registered send-once right */
extern kern_return_t ipc_right_dnrequest(
	ipc_space_t		space,
	mach_port_name_t	name,
	boolean_t		immediate,
	ipc_port_t		notify,
	ipc_port_t		*previousp);

/* Cancel a dead-name request and return the send-once right */
extern ipc_port_t ipc_right_dncancel(
	ipc_space_t		space,
	ipc_port_t		port,
	mach_port_name_t	name,
	ipc_entry_t		entry);

#define	ipc_right_dncancel_macro(space, port, name, entry)		\
		 ((entry->ie_request == 0) ? IP_NULL :			\
		 ipc_right_dncancel((space), (port), (name), (entry)))

/* Check if an entry is being used */
extern boolean_t ipc_right_inuse(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_entry_t		entry);

/* Check if the port has died */
extern boolean_t ipc_right_check(
	ipc_space_t		space,
	ipc_port_t		port,
	mach_port_name_t	name,
	ipc_entry_t		entry);

/* Clean up an entry in a dead space */
extern void ipc_right_clean(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_entry_t		entry);

/* Destroy an entry in a space */
extern kern_return_t ipc_right_destroy(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_entry_t		entry);

/* Release a send/send-once/dead-name user reference */
extern kern_return_t ipc_right_dealloc(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_entry_t		entry);

/* Modify the user-reference count for a right */
extern kern_return_t ipc_right_delta(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_entry_t		entry,
	mach_port_right_t	right,
	mach_port_delta_t	delta);

/* Retrieve information about a right */
extern kern_return_t ipc_right_info(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_entry_t		entry,
	mach_port_type_t	*typep,
	mach_port_urefs_t	*urefsp);

/* Check if a subsequent ipc_right_copyin would succeed */
extern boolean_t ipc_right_copyin_check(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_entry_t		entry,
	mach_msg_type_name_t	msgt_name);

/* Copyin a capability from a space */
extern kern_return_t ipc_right_copyin(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_entry_t		entry,
	mach_msg_type_name_t	msgt_name,
	boolean_t		deadok,
	ipc_object_t		*objectp,
	ipc_port_t		*sorightp);

/* Undo the effects of an ipc_right_copyin */
extern void ipc_right_copyin_undo(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_entry_t		entry,
	mach_msg_type_name_t	msgt_name,
	ipc_object_t		object,
	ipc_port_t		soright);

/* Copyin two send rights from a space */
extern kern_return_t ipc_right_copyin_two(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_entry_t		entry,
	ipc_object_t		*objectp,
	ipc_port_t		*sorightp);

/* Copyout a capability to a space */
extern kern_return_t ipc_right_copyout(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_entry_t		entry,
	mach_msg_type_name_t	msgt_name,
	boolean_t		overflow,
	ipc_object_t		object);

/* Reanme a capability */
extern kern_return_t ipc_right_rename(
	ipc_space_t		space,
	mach_port_name_t	oname,
	ipc_entry_t		oentry,
	mach_port_name_t	nname,
	ipc_entry_t		nentry);

#endif	/* _IPC_IPC_RIGHT_H_ */

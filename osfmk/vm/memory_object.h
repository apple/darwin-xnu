/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1991 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS 
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
 * any improvements or extensions that they make and grant Carnegie the
 * rights to redistribute these changes.
 */
/*
 */

#ifndef	_VM_MEMORY_OBJECT_H_
#define	_VM_MEMORY_OBJECT_H_

#include <mach_pagemap.h>

#include <mach/boolean.h>
#include <mach/mach_types.h>
#include <mach/memory_object_types.h>
#include <ipc/ipc_types.h>

__private_extern__
memory_object_default_t	memory_manager_default_reference(
				vm_size_t		*cluster_size);

__private_extern__
kern_return_t		memory_manager_default_check(void);

__private_extern__
void			memory_manager_default_init(void);

__private_extern__
void			memory_object_control_bootstrap(void);
__private_extern__
memory_object_control_t memory_object_control_allocate(
				vm_object_t		object);

__private_extern__
void			memory_object_control_collapse(
				memory_object_control_t control,
				vm_object_t		object);

__private_extern__
vm_object_t 		memory_object_control_to_vm_object(
				memory_object_control_t control);

extern
mach_port_t		convert_mo_control_to_port(
				memory_object_control_t	control);

extern void memory_object_control_disable(
	memory_object_control_t	control);

extern
memory_object_control_t convert_port_to_mo_control(
				mach_port_t		port);

extern
mach_port_t		convert_memory_object_to_port(
				memory_object_t		object);

extern
memory_object_t		convert_port_to_memory_object(
				mach_port_t		port);

extern upl_t convert_port_to_upl(
				ipc_port_t	port);

extern ipc_port_t convert_upl_to_port( upl_t );

__private_extern__ void upl_no_senders(ipc_port_t, mach_port_mscount_t);

extern kern_return_t	memory_object_free_from_cache(
				host_t		host,
				int		*pager_id,
				int		*count);

extern kern_return_t	memory_object_iopl_request(
	ipc_port_t		port,
	memory_object_offset_t	offset,
	vm_size_t		*upl_size,
	upl_t			*upl_ptr,
	upl_page_info_array_t	user_page_list,
	unsigned int		*page_list_count,
	int			*flags);
	

extern kern_return_t	memory_object_pages_resident(
	memory_object_control_t		control,
	boolean_t			*		has_pages_resident);

#endif	/* _VM_MEMORY_OBJECT_H_ */

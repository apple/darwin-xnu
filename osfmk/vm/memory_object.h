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
#include <ipc/ipc_types.h>

extern kern_return_t	memory_object_set_attributes_common(
				vm_object_t	object,
				boolean_t	may_cache,
				memory_object_copy_strategy_t copy_strategy,
				boolean_t	temporary,
				vm_size_t	cluster_size,
				boolean_t	silent_overwrite,
				boolean_t	advisory_pageout);

extern boolean_t	memory_object_sync (
				vm_object_t		object,
				vm_object_offset_t	offset,
				vm_object_size_t	size,
				boolean_t		should_flush,
				boolean_t		should_return);

extern ipc_port_t	memory_manager_default_reference(
					vm_size_t	*cluster_size);

extern boolean_t	memory_manager_default_port(ipc_port_t port);

extern kern_return_t	memory_manager_default_check(void);

extern void		memory_manager_default_init(void);


extern kern_return_t	memory_object_free_from_cache(
				host_t		host,
				int		pager_id,
				int		*count);

extern kern_return_t	memory_object_remove_cached_object(
				ipc_port_t	port);

extern void		memory_object_deactivate_pages(
				vm_object_t		object,
				vm_object_offset_t	offset,
				vm_object_size_t	size,
				boolean_t               kill_page);

#endif	/* _VM_MEMORY_OBJECT_H_ */

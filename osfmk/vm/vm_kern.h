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
/*
 */
/*
 *	File:	vm/vm_kern.h
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Kernel memory management definitions.
 */

#ifndef	_VM_VM_KERN_H_
#define _VM_VM_KERN_H_

#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/machine/vm_types.h>
#include <vm/vm_map.h>

extern void		kmem_init(
				vm_offset_t	start,
				vm_offset_t	end);

extern kern_return_t	kernel_memory_allocate(
				vm_map_t	map,
				vm_offset_t	*addrp,
				vm_size_t	size,
				vm_offset_t	mask,
				int		flags);

/* flags for kernel_memory_allocate */
#define KMA_HERE	0x01
#define KMA_NOPAGEWAIT	0x02
#define KMA_KOBJECT	0x04

extern kern_return_t kmem_alloc_contig(
				vm_map_t	map,
				vm_offset_t	*addrp,
				vm_size_t	size,
				vm_offset_t 	mask,
				int 		flags);

extern kern_return_t	kmem_alloc(
				vm_map_t	map,
				vm_offset_t	*addrp,
				vm_size_t	size);

extern kern_return_t	kmem_alloc_pageable(
				vm_map_t	map,
				vm_offset_t	*addrp,
				vm_size_t	size);

extern kern_return_t	kmem_alloc_wired(
				vm_map_t	map,
				vm_offset_t	*addrp,
				vm_size_t	size);

extern kern_return_t	kmem_alloc_aligned(
				vm_map_t	map,
				vm_offset_t	*addrp,
				vm_size_t	size);

extern kern_return_t	kmem_realloc(
				vm_map_t	map,
				vm_offset_t	oldaddr,
				vm_size_t	oldsize,
				vm_offset_t	*newaddrp,
				vm_size_t	newsize);

extern void		kmem_free(
				vm_map_t	map,
				vm_offset_t	addr,
				vm_size_t	size);

extern kern_return_t	kmem_suballoc(
				vm_map_t	parent,
				vm_offset_t	*addr,
				vm_size_t	size,
				boolean_t	pageable,
				boolean_t	anywhere,
				vm_map_t	*new_map);

extern void		kmem_io_object_deallocate(
				vm_map_copy_t	copy);

extern kern_return_t	kmem_io_object_trunc(
				vm_map_copy_t	copy,
				vm_size_t	new_size);

extern boolean_t	copyinmap(
				vm_map_t	map,
				vm_offset_t	fromaddr,
				vm_offset_t	toaddr,
				vm_size_t	length);

extern boolean_t	copyoutmap(
				vm_map_t	map,
				vm_offset_t	fromaddr,
				vm_offset_t	toaddr,
				vm_size_t	length);

extern vm_map_t	kernel_map;
extern vm_map_t	kernel_pageable_map;
extern vm_map_t ipc_kernel_map;

#endif	/* _VM_VM_KERN_H_ */

/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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

#ifndef VM_PRINT_H
#define	VM_PRINT_H

#include <vm/vm_map.h>
#include <machine/db_machdep.h>

extern void	vm_map_print(
			db_addr_t	map);

extern void	vm_map_copy_print(
			db_addr_t	copy);

#include <vm/vm_object.h>

extern int	vm_follow_object(
			vm_object_t	object);

extern void vm_object_print(db_expr_t, boolean_t, db_expr_t, char *);

#include <vm/vm_page.h>

extern void	vm_page_print(
			db_addr_t	p);

#include <mach_pagemap.h>
#if	MACH_PAGEMAP
#include <vm/vm_external.h>
extern void vm_external_print(
			vm_external_map_t	map,
			vm_object_size_t	size);
#endif	/* MACH_PAGEMAP */

extern void	db_vm(void);

extern vm_map_size_t db_vm_map_total_size(
			db_addr_t	map);

#endif	/* VM_PRINT_H */

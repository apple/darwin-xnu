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

extern void	vm_object_print(
			vm_object_t	object,
			boolean_t	have_addr,
			int		arg_count,
			char		*modif);

#include <vm/vm_page.h>

extern void	vm_page_print(
			vm_page_t	p);

#include <mach_pagemap.h>
#if	MACH_PAGEMAP
#include <vm/vm_external.h>
extern void vm_external_print(
			vm_external_map_t	map,
			vm_size_t		size);
#endif	/* MACH_PAGEMAP */

extern void	db_vm(void);

extern vm_size_t db_vm_map_total_size(
			db_addr_t	map);

#endif	/* VM_PRINT_H */

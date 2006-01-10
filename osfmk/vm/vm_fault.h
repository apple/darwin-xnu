/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 *	File:	vm/vm_fault.h
 *
 *	Page fault handling module declarations.
 */

#ifndef	_VM_VM_FAULT_H_
#define _VM_VM_FAULT_H_

#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <mach/boolean.h>
#include <mach/vm_prot.h>
#include <mach/vm_param.h>
#include <mach/vm_behavior.h>

#ifdef	KERNEL_PRIVATE

typedef	kern_return_t	vm_fault_return_t;

#define VM_FAULT_SUCCESS		0
#define VM_FAULT_RETRY			1
#define VM_FAULT_INTERRUPTED		2
#define VM_FAULT_MEMORY_SHORTAGE 	3
#define VM_FAULT_FICTITIOUS_SHORTAGE 	4
#define VM_FAULT_MEMORY_ERROR		5

/*
 *	Page fault handling based on vm_map (or entries therein)
 */

extern kern_return_t vm_fault(
		vm_map_t	map,
		vm_map_offset_t	vaddr,
		vm_prot_t	fault_type,
		boolean_t	change_wiring,
		int             interruptible,
		pmap_t		pmap,
		vm_map_offset_t	pmap_addr);

#ifdef	MACH_KERNEL_PRIVATE

#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <vm/vm_map.h>

extern void vm_fault_init(void);

/*
 *	Page fault handling based on vm_object only.
 */

extern vm_fault_return_t vm_fault_page(
		/* Arguments: */
		vm_object_t	first_object,	/* Object to begin search */
		vm_object_offset_t first_offset,/* Offset into object */
		vm_prot_t	fault_type,	/* What access is requested */
		boolean_t	must_be_resident,/* Must page be resident? */
		int		interruptible,/* how may fault be interrupted */
		vm_map_offset_t lo_offset,	/* Map entry start */
		vm_map_offset_t hi_offset,	/* Map entry end */
		vm_behavior_t	behavior,	/* Expected paging behavior */
		/* Modifies in place: */
		vm_prot_t	*protection,	/* Protection for mapping */
		/* Returns: */
		vm_page_t	*result_page,	/* Page found, if successful */
		vm_page_t	*top_page,	/* Page in top object, if
						 * not result_page.  */
		int             *type_of_fault, /* if non-zero, return COW, zero-filled, etc...
		                                 * used by kernel trace point in vm_fault */
		/* More arguments: */
		kern_return_t	*error_code,	/* code if page is in error */
		boolean_t	no_zero_fill,	/* don't fill absent pages */
		boolean_t	data_supply,	/* treat as data_supply */
		vm_map_t	map,
		vm_map_offset_t	vaddr);

extern void vm_fault_cleanup(
		vm_object_t	object,
		vm_page_t	top_page);

extern kern_return_t vm_fault_wire(
		vm_map_t	map,
		vm_map_entry_t	entry,
		pmap_t		pmap,
		vm_map_offset_t	pmap_addr);

extern void vm_fault_unwire(
		vm_map_t	map,
		vm_map_entry_t	entry,
		boolean_t	deallocate,
		pmap_t		pmap,
		vm_map_offset_t	pmap_addr);

extern kern_return_t	vm_fault_copy(
		vm_object_t		src_object,
		vm_object_offset_t	src_offset,
		vm_map_size_t		*copy_size,	/* INOUT */
		vm_object_t		dst_object,
		vm_object_offset_t	dst_offset,
		vm_map_t		dst_map,
		vm_map_version_t	 *dst_version,
		int			interruptible);

#endif	/* MACH_KERNEL_PRIVATE */

#endif	/* KERNEL_PRIVATE */

#endif	/* _VM_VM_FAULT_H_ */

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
 *	File:	mach/vm_param.h
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Machine independent virtual memory parameters.
 *
 */

#ifndef	_MACH_VM_PARAM_H_
#define _MACH_VM_PARAM_H_

#ifndef	KERNEL_PRIVATE

#error YOU HAVE MADE A MISTAKE BY INCLUDING THIS FILE;
#error
#error THIS FILE SHOULD NOT BE VISIBLE TO USER PROGRAMS.
#error
#error USE <mach/machine/vm_param.h> TO GET MACHINE-DEPENDENT ADDRESS
#error SPACE AND PAGE SIZE ITEMS.
#error
#error USE <mach/machine/vm_types.h> TO GET TYPE DECLARATIONS USED IN
#error THE MACH KERNEL INTERFACE.
#error
#error IN ALL PROBABILITY, YOU SHOULD GET ALL OF THE TYPES USED IN THE
#error INTERFACE FROM <mach/mach_types.h>

#endif	/* KERNEL_PRIVATE */

#include <mach/machine/vm_param.h>
#include <mach/machine/vm_types.h>

/*
 *	The machine independent pages are refered to as PAGES.  A page
 *	is some number of hardware pages, depending on the target machine.
 */

/*
 *	All references to the size of a page should be done with PAGE_SIZE
 *	or PAGE_SHIFT.  The fact they are variables is hidden here so that
 *	we can easily make them constant if we so desire.
 */

/*
 *	Regardless whether it is implemented with a constant or a variable,
 *	the PAGE_SIZE is assumed to be a power of two throughout the
 *	virtual memory system implementation.
 */

#ifndef	PAGE_SIZE_FIXED
extern vm_size_t	page_size;
extern vm_size_t	page_mask;
extern int		page_shift;

#define PAGE_SIZE	page_size 	/* pagesize in addr units */
#define PAGE_SHIFT	page_shift	/* number of bits to shift for pages */
#define PAGE_MASK	page_mask	/* mask for off in page */

#define PAGE_SIZE_64 (unsigned long long)page_size /* pagesize in addr units */
#define PAGE_MASK_64 (unsigned long long)page_mask /* mask for off in page */
#else	/* PAGE_SIZE_FIXED */
#define PAGE_SIZE	4096
#define PAGE_SHIFT	12
#define	PAGE_MASK	(PAGE_SIZE-1)
#define PAGE_SIZE_64	(unsigned long long)4096
#define PAGE_MASK_64	(PAGE_SIZE_64-1)
#endif	/* PAGE_SIZE_FIXED */

#ifndef	ASSEMBLER
/*
 *	Convert addresses to pages and vice versa.
 *	No rounding is used.
 */

#define atop(x)		(((natural_t)(x)) >> PAGE_SHIFT)
#define ptoa(x)		((vm_offset_t)((x) << PAGE_SHIFT))

/*
 *	Round off or truncate to the nearest page.  These will work
 *	for either addresses or counts.  (i.e. 1 byte rounds to 1 page
 *	bytes.
 */

#define round_page(x)	((vm_offset_t)((((vm_offset_t)(x)) + PAGE_MASK) & ~PAGE_MASK))
#define trunc_page(x)	((vm_offset_t)(((vm_offset_t)(x)) & ~PAGE_MASK))

#define round_page_64(x)	((unsigned long long)((((unsigned long long)(x)) + PAGE_MASK_64) & ~PAGE_MASK_64))
#define trunc_page_64(x)	((unsigned long long)(((unsigned long long)(x)) & ~PAGE_MASK_64))

/*
 *	Determine whether an address is page-aligned, or a count is
 *	an exact page multiple.
 */

#define	page_aligned(x)	((((vm_object_offset_t) (x)) & PAGE_MASK) == 0)

extern vm_size_t	mem_size;	/* size of physical memory (bytes) */

#endif	/* ASSEMBLER */
#endif	/* _MACH_VM_PARAM_H_ */

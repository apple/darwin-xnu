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
 *	File:	vm/pmap.h
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1985
 *
 *	Machine address mapping definitions -- machine-independent
 *	section.  [For machine-dependent section, see "machine/pmap.h".]
 */

#ifndef	_VM_PMAP_H_
#define _VM_PMAP_H_

#include <mach/kern_return.h>
#include <mach/vm_param.h>
#include <mach/vm_types.h>
#include <mach/vm_attributes.h>
#include <mach/boolean.h>
#include <mach/vm_prot.h>

/*
 *	The following is a description of the interface to the
 *	machine-dependent "physical map" data structure.  The module
 *	must provide a "pmap_t" data type that represents the
 *	set of valid virtual-to-physical addresses for one user
 *	address space.  [The kernel address space is represented
 *	by a distinguished "pmap_t".]  The routines described manage
 *	this type, install and update virtual-to-physical mappings,
 *	and perform operations on physical addresses common to
 *	many address spaces.
 */

#ifndef MACH_KERNEL_PRIVATE

typedef void *pmap_t;

#else /* MACH_KERNEL_PRIVATE */

typedef struct pmap *pmap_t;

#include <machine/pmap.h>

/*
 *	Routines used for initialization.
 *	There is traditionally also a pmap_bootstrap,
 *	used very early by machine-dependent code,
 *	but it is not part of the interface.
 */

extern vm_offset_t	pmap_steal_memory(vm_size_t size);
						/* During VM initialization,
						 * steal a chunk of memory.
						 */
extern unsigned int	pmap_free_pages(void);	/* During VM initialization,
						 * report remaining unused
						 * physical pages.
						 */
extern void		pmap_startup(
				vm_offset_t *startp,
				vm_offset_t *endp);
						/* During VM initialization,
						 * use remaining physical pages
						 * to allocate page frames.
						 */
extern void		pmap_init(void);	/* Initialization,
						 * after kernel runs
						 * in virtual memory.
						 */

#ifndef	MACHINE_PAGES
/*
 *	If machine/pmap.h defines MACHINE_PAGES, it must implement
 *	the above functions.  The pmap module has complete control.
 *	Otherwise, it must implement
 *		pmap_free_pages
 *		pmap_virtual_space
 *		pmap_next_page
 *		pmap_init
 *	and vm/vm_resident.c implements pmap_steal_memory and pmap_startup
 *	using pmap_free_pages, pmap_next_page, pmap_virtual_space,
 *	and pmap_enter.  pmap_free_pages may over-estimate the number
 *	of unused physical pages, and pmap_next_page may return FALSE
 *	to indicate that there are no more unused pages to return.
 *	However, for best performance pmap_free_pages should be accurate.
 */

extern boolean_t	pmap_next_page(vm_offset_t *paddr);
						/* During VM initialization,
						 * return the next unused
						 * physical page.
						 */
extern void		pmap_virtual_space(
					vm_offset_t	*virtual_start,
					vm_offset_t	*virtual_end);
						/* During VM initialization,
						 * report virtual space
						 * available for the kernel.
						 */
#endif	/* MACHINE_PAGES */

/*
 *	Routines to manage the physical map data structure.
 */
extern pmap_t		pmap_create(vm_size_t size);	/* Create a pmap_t. */
extern pmap_t		(pmap_kernel)(void);	/* Return the kernel's pmap */
extern void		pmap_reference(pmap_t pmap);	/* Gain a reference. */
extern void		pmap_destroy(pmap_t pmap); /* Release a reference. */
extern void		pmap_switch(pmap_t);


extern void		pmap_enter(	/* Enter a mapping */
				pmap_t		pmap,
				vm_offset_t	v,
				vm_offset_t	pa,
				vm_prot_t	prot,
				boolean_t	wired);

extern void		pmap_remove_some_phys(
				pmap_t		pmap,
				vm_offset_t	pa);


/*
 *	Routines that operate on physical addresses.
 */

extern void		pmap_page_protect(	/* Restrict access to page. */
				vm_offset_t	phys,
				vm_prot_t	prot);

extern void		(pmap_zero_page)(
				vm_offset_t	phys);

extern void		(pmap_zero_part_page)(
				vm_offset_t	p,
				vm_offset_t     offset,
				vm_size_t       len);

extern void		(pmap_copy_page)(
				vm_offset_t	src,
				vm_offset_t	dest);

extern void		(pmap_copy_part_page)(
				vm_offset_t	src,
				vm_offset_t	src_offset,
				vm_offset_t	dst,
				vm_offset_t	dst_offset,
				vm_size_t	len);

extern void		(pmap_copy_part_lpage)(
				vm_offset_t	src,
				vm_offset_t	dst,
				vm_offset_t	dst_offset,
				vm_size_t	len);

extern void		(pmap_copy_part_rpage)(
				vm_offset_t	src,
				vm_offset_t	src_offset,
				vm_offset_t	dst,
				vm_size_t	len);

/*
 * debug/assertions. pmap_verify_free returns true iff
 * the given physical page is mapped into no pmap.
 */
extern boolean_t	pmap_verify_free(vm_offset_t paddr);

/*
 *	Statistics routines
 */
extern int		(pmap_resident_count)(pmap_t pmap);

/*
 *	Sundry required (internal) routines
 */
extern void		pmap_collect(pmap_t pmap);/* Perform garbage
						 * collection, if any */


extern vm_offset_t	(pmap_phys_address)(	/* Transform address returned
						 * by device driver mapping
						 * function to physical address
						 * known to this module.  */
				int		frame);

extern int		(pmap_phys_to_frame)(	/* Inverse of pmap_phys_addess,
						 * for use by device driver
						 * mapping function in
						 * machine-independent
						 * pseudo-devices.  */
				vm_offset_t	phys);

/*
 *	Optional routines
 */
extern void		(pmap_copy)(		/* Copy range of mappings,
						 * if desired. */
				pmap_t		dest,
				pmap_t		source,
				vm_offset_t	dest_va,
				vm_size_t	size,
				vm_offset_t	source_va);

extern kern_return_t	(pmap_attribute)(	/* Get/Set special memory
						 * attributes */
				pmap_t		pmap,
				vm_offset_t	va,
				vm_size_t	size,
				vm_machine_attribute_t  attribute,
				vm_machine_attribute_val_t* value);

/*
 * Routines defined as macros.
 */
#ifndef PMAP_ACTIVATE_USER
#define PMAP_ACTIVATE_USER(act, cpu) {				\
	pmap_t  pmap;						\
								\
	pmap = (act)->map->pmap;				\
	if (pmap != pmap_kernel())				\
		PMAP_ACTIVATE(pmap, (act), (cpu));		\
}
#endif  /* PMAP_ACTIVATE_USER */

#ifndef PMAP_DEACTIVATE_USER
#define PMAP_DEACTIVATE_USER(act, cpu) {			\
	pmap_t  pmap;						\
								\
	pmap = (act)->map->pmap;				\
	if ((pmap) != pmap_kernel())				\
		PMAP_DEACTIVATE(pmap, (act), (cpu));		\
}
#endif  /* PMAP_DEACTIVATE_USER */

#ifndef	PMAP_ACTIVATE_KERNEL
#define	PMAP_ACTIVATE_KERNEL(cpu)			\
		PMAP_ACTIVATE(pmap_kernel(), THR_ACT_NULL, cpu)
#endif	/* PMAP_ACTIVATE_KERNEL */

#ifndef	PMAP_DEACTIVATE_KERNEL
#define	PMAP_DEACTIVATE_KERNEL(cpu)			\
		PMAP_DEACTIVATE(pmap_kernel(), THR_ACT_NULL, cpu)
#endif	/* PMAP_DEACTIVATE_KERNEL */

#ifndef	PMAP_ENTER
/*
 *	Macro to be used in place of pmap_enter()
 */
#define PMAP_ENTER(pmap, virtual_address, page, protection, wired) \
		MACRO_BEGIN					\
		pmap_enter(					\
			(pmap),					\
			(virtual_address),			\
			(page)->phys_addr,			\
			(protection) & ~(page)->page_lock,	\
			(wired)					\
		 );						\
		MACRO_END
#endif	/* !PMAP_ENTER */

#endif /* MACH_KERNEL_PRIVATE */

/*
 * JMM - This portion is exported to other kernel components right now,
 * but will be pulled back in the future when the needed functionality
 * is provided in a cleaner manner.
 */

#define PMAP_NULL  ((pmap_t) 0)

extern pmap_t	kernel_pmap;			/* The kernel's map */
#define		pmap_kernel()	(kernel_pmap)

/*
 *	Routines to manage reference/modify bits based on
 *	physical addresses, simulating them if not provided
 *	by the hardware.
 */
				/* Clear reference bit */
extern void		pmap_clear_reference(vm_offset_t paddr);
				/* Return reference bit */
extern boolean_t	(pmap_is_referenced)(vm_offset_t paddr);
				/* Set modify bit */
extern void             pmap_set_modify(vm_offset_t paddr);
				/* Clear modify bit */
extern void		pmap_clear_modify(vm_offset_t paddr);
				/* Return modify bit */
extern boolean_t	pmap_is_modified(vm_offset_t paddr);

/*
 *	Routines that operate on ranges of virtual addresses.
 */
extern void		pmap_remove(	/* Remove mappings. */
				pmap_t		map,
				vm_offset_t	s,
				vm_offset_t	e);

extern void		pmap_protect(	/* Change protections. */
				pmap_t		map,
				vm_offset_t	s,
				vm_offset_t	e,
				vm_prot_t	prot);

extern void		(pmap_pageable)(
				pmap_t		pmap,
				vm_offset_t	start,
				vm_offset_t	end,
				boolean_t	pageable);

extern void		pmap_modify_pages(	/* Set modify bit for pages */
				pmap_t		map,
				vm_offset_t	s,
				vm_offset_t	e);

extern vm_offset_t	pmap_extract(pmap_t pmap,
				vm_offset_t va);

extern void		pmap_change_wiring(	/* Specify pageability */
				pmap_t		pmap,
				vm_offset_t	va,
				boolean_t	wired);
#endif	/* _VM_PMAP_H_ */

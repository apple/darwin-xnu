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

#ifdef	KERNEL_PRIVATE

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

/* Copy between a physical page and a virtual address */
/* LP64todo - switch to vm_map_offset_t when it grows */
extern kern_return_t 	copypv(
				addr64_t source, 
				addr64_t sink, 
				unsigned int size, 
				int which);	
#define cppvPsnk        1
#define cppvPsnkb      31
#define cppvPsrc        2
#define cppvPsrcb      30
#define cppvFsnk        4
#define cppvFsnkb      29
#define cppvFsrc        8
#define cppvFsrcb      28
#define cppvNoModSnk   16
#define cppvNoModSnkb  27
#define cppvNoRefSrc   32
#define cppvNoRefSrcb  26
#define cppvKmap       64	/* Use the kernel's vm_map */
#define cppvKmapb      25

#ifdef	MACH_KERNEL_PRIVATE

#include <machine/pmap.h>

/*
 *	Routines used for initialization.
 *	There is traditionally also a pmap_bootstrap,
 *	used very early by machine-dependent code,
 *	but it is not part of the interface.
 *
 *	LP64todo -
 *	These interfaces are tied to the size of the
 *	kernel pmap - and therefore use the "local"
 *	vm_offset_t, etc... types.
 */

extern void 		*pmap_steal_memory(vm_size_t size);
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

extern void 		mapping_adjust(void);	/* Adjust free mapping count */

extern void 		mapping_free_prime(void); /* Primes the mapping block release list */

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

extern boolean_t	pmap_next_page(ppnum_t *pnum);
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
extern pmap_t		pmap_create(vm_map_size_t size);	/* Create a pmap_t. */
extern pmap_t		(pmap_kernel)(void);	/* Return the kernel's pmap */
extern void		pmap_reference(pmap_t pmap);	/* Gain a reference. */
extern void		pmap_destroy(pmap_t pmap); /* Release a reference. */
extern void		pmap_switch(pmap_t);


extern void		pmap_enter(	/* Enter a mapping */
				pmap_t		pmap,
				vm_map_offset_t	v,
				ppnum_t		pn,
				vm_prot_t	prot,
				unsigned int	flags,
				boolean_t	wired);

extern void		pmap_remove_some_phys(
				pmap_t		pmap,
				ppnum_t		pn);


/*
 *	Routines that operate on physical addresses.
 */

extern void		pmap_page_protect(	/* Restrict access to page. */
				ppnum_t	phys,
				vm_prot_t	prot);

extern void		(pmap_zero_page)(
				ppnum_t		pn);

extern void		(pmap_zero_part_page)(
				ppnum_t		pn,
				vm_offset_t     offset,
				vm_size_t       len);

extern void		(pmap_copy_page)(
				ppnum_t		src,
				ppnum_t		dest);

extern void		(pmap_copy_part_page)(
				ppnum_t		src,
				vm_offset_t	src_offset,
				ppnum_t		dst,
				vm_offset_t	dst_offset,
				vm_size_t	len);

extern void		(pmap_copy_part_lpage)(
				vm_offset_t	src,
				ppnum_t		dst,
				vm_offset_t	dst_offset,
				vm_size_t	len);

extern void		(pmap_copy_part_rpage)(
				ppnum_t		src,
				vm_offset_t	src_offset,
				vm_offset_t	dst,
				vm_size_t	len);
				
extern unsigned int (pmap_disconnect)(	/* disconnect mappings and return reference and change */
				ppnum_t		phys);

extern kern_return_t	(pmap_attribute_cache_sync)(  /* Flush appropriate 
						       * cache based on
						       * page number sent */
				ppnum_t		pn, 
				vm_size_t	size, 
				vm_machine_attribute_t attribute, 
				vm_machine_attribute_val_t* value);

/*
 * debug/assertions. pmap_verify_free returns true iff
 * the given physical page is mapped into no pmap.
 */
extern boolean_t	pmap_verify_free(ppnum_t pn);

/*
 *	Statistics routines
 */
extern int		(pmap_resident_count)(pmap_t pmap);

/*
 *	Sundry required (internal) routines
 */
extern void		pmap_collect(pmap_t pmap);/* Perform garbage
						 * collection, if any */

/*
 *	Optional routines
 */
extern void		(pmap_copy)(		/* Copy range of mappings,
						 * if desired. */
				pmap_t		dest,
				pmap_t		source,
				vm_map_offset_t	dest_va,
				vm_map_size_t	size,
				vm_map_offset_t	source_va);

extern kern_return_t	(pmap_attribute)(	/* Get/Set special memory
						 * attributes */
				pmap_t		pmap,
				vm_map_offset_t	va,
				vm_map_size_t	size,
				vm_machine_attribute_t  attribute,
				vm_machine_attribute_val_t* value);

/*
 * Routines defined as macros.
 */
#ifndef PMAP_ACTIVATE_USER
#ifndef	PMAP_ACTIVATE
#define PMAP_ACTIVATE_USER(thr, cpu)
#else	/* PMAP_ACTIVATE */
#define PMAP_ACTIVATE_USER(thr, cpu) {			\
	pmap_t  pmap;						\
								\
	pmap = (thr)->map->pmap;				\
	if (pmap != pmap_kernel())				\
		PMAP_ACTIVATE(pmap, (thr), (cpu));		\
}
#endif  /* PMAP_ACTIVATE */
#endif  /* PMAP_ACTIVATE_USER */

#ifndef PMAP_DEACTIVATE_USER
#ifndef PMAP_DEACTIVATE
#define PMAP_DEACTIVATE_USER(thr, cpu)
#else	/* PMAP_DEACTIVATE */
#define PMAP_DEACTIVATE_USER(thr, cpu) {			\
	pmap_t  pmap;						\
								\
	pmap = (thr)->map->pmap;				\
	if ((pmap) != pmap_kernel())			\
		PMAP_DEACTIVATE(pmap, (thr), (cpu));	\
}
#endif	/* PMAP_DEACTIVATE */
#endif  /* PMAP_DEACTIVATE_USER */

#ifndef	PMAP_ACTIVATE_KERNEL
#ifndef PMAP_ACTIVATE
#define	PMAP_ACTIVATE_KERNEL(cpu)
#else	/* PMAP_ACTIVATE */
#define	PMAP_ACTIVATE_KERNEL(cpu)			\
		PMAP_ACTIVATE(pmap_kernel(), THREAD_NULL, cpu)
#endif	/* PMAP_ACTIVATE */
#endif	/* PMAP_ACTIVATE_KERNEL */

#ifndef	PMAP_DEACTIVATE_KERNEL
#ifndef PMAP_DEACTIVATE
#define	PMAP_DEACTIVATE_KERNEL(cpu)
#else	/* PMAP_DEACTIVATE */
#define	PMAP_DEACTIVATE_KERNEL(cpu)			\
		PMAP_DEACTIVATE(pmap_kernel(), THREAD_NULL, cpu)
#endif	/* PMAP_DEACTIVATE */
#endif	/* PMAP_DEACTIVATE_KERNEL */

#ifndef	PMAP_ENTER
/*
 *	Macro to be used in place of pmap_enter()
 */
#define PMAP_ENTER(pmap, virtual_address, page, protection, flags, wired) \
	MACRO_BEGIN							\
	pmap_t		__pmap = (pmap);				\
	vm_page_t	__page = (page);				\
									\
	if (__pmap != kernel_pmap) {					\
		ASSERT_PAGE_DECRYPTED(__page);				\
	}								\
	pmap_enter(__pmap,						\
		   (virtual_address),					\
		   __page->phys_page,					\
		   (protection) & ~__page->page_lock,			\
		   (flags),						\
		   (wired));						\
	MACRO_END
#endif	/* !PMAP_ENTER */

/*
 *	Routines to manage reference/modify bits based on
 *	physical addresses, simulating them if not provided
 *	by the hardware.
 */
				/* Clear reference bit */
extern void		pmap_clear_reference(ppnum_t	 pn);
				/* Return reference bit */
extern boolean_t	(pmap_is_referenced)(ppnum_t	 pn);
				/* Set modify bit */
extern void             pmap_set_modify(ppnum_t	 pn);
				/* Clear modify bit */
extern void		pmap_clear_modify(ppnum_t pn);
				/* Return modify bit */
extern boolean_t	pmap_is_modified(ppnum_t pn);
				/* Return modified and referenced bits */
extern unsigned int pmap_get_refmod(ppnum_t pn);
				/* Clear modified and referenced bits */
extern void			pmap_clear_refmod(ppnum_t pn, unsigned int mask);
#define VM_MEM_MODIFIED		0x01	/* Modified bit */
#define VM_MEM_REFERENCED	0x02	/* Referenced bit */

/*
 *	Routines that operate on ranges of virtual addresses.
 */
extern void		pmap_protect(	/* Change protections. */
				pmap_t		map,
				vm_map_offset_t	s,
				vm_map_offset_t	e,
				vm_prot_t	prot);

extern void		(pmap_pageable)(
				pmap_t		pmap,
				vm_map_offset_t	start,
				vm_map_offset_t	end,
				boolean_t	pageable);

#endif	/* MACH_KERNEL_PRIVATE */

/*
 * JMM - This portion is exported to other kernel components right now,
 * but will be pulled back in the future when the needed functionality
 * is provided in a cleaner manner.
 */

extern pmap_t	kernel_pmap;			/* The kernel's map */
#define		pmap_kernel()	(kernel_pmap)

/* machine independent WIMG bits */

#define VM_MEM_GUARDED 		0x1		/* (G) Guarded Storage */
#define VM_MEM_COHERENT		0x2		/* (M) Memory Coherency */
#define VM_MEM_NOT_CACHEABLE	0x4		/* (I) Cache Inhibit */
#define VM_MEM_WRITE_THROUGH	0x8		/* (W) Write-Through */

#define VM_WIMG_MASK		0xFF
#define VM_WIMG_USE_DEFAULT	0x80000000

extern void		pmap_modify_pages(	/* Set modify bit for pages */
				pmap_t		map,
				vm_map_offset_t	s,
				vm_map_offset_t	e);

extern vm_offset_t	pmap_extract(pmap_t pmap,
				vm_map_offset_t va);

extern void		pmap_change_wiring(	/* Specify pageability */
				pmap_t		pmap,
				vm_map_offset_t	va,
				boolean_t	wired);

/* LP64todo - switch to vm_map_offset_t when it grows */
extern void		pmap_remove(	/* Remove mappings. */
				pmap_t		map,
				addr64_t	s,
				addr64_t	e);


#endif  /* KERNEL_PRIVATE */

#endif	/* _VM_PMAP_H_ */

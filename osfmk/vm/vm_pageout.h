/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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
 *	File:	vm/vm_pageout.h
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1986
 *
 *	Declarations for the pageout daemon interface.
 */

#ifndef	_VM_VM_PAGEOUT_H_
#define _VM_VM_PAGEOUT_H_

#ifdef	KERNEL_PRIVATE

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/machine/vm_types.h>
#include <mach/memory_object_types.h>

#include <kern/kern_types.h>
#include <kern/lock.h>

extern kern_return_t vm_map_create_upl(
	vm_map_t		map,
	vm_map_address_t	offset,
	upl_size_t		*upl_size,
	upl_t			*upl,
	upl_page_info_array_t	page_list,
	unsigned int		*count,
	int			*flags);

extern ppnum_t upl_get_highest_page(
	upl_t			upl);

#ifdef	MACH_KERNEL_PRIVATE

#include <vm/vm_page.h>

extern unsigned int	vm_pageout_scan_event_counter;
extern unsigned int	vm_zf_count;

/*
 *	Routines exported to Mach.
 */
extern void		vm_pageout(void);

extern vm_object_t	vm_pageout_object_allocate(
					vm_page_t		m,
					vm_size_t		size,
					vm_object_offset_t	offset);

extern void		vm_pageout_object_terminate(
					vm_object_t	object);

extern vm_page_t	vm_pageout_setup(
					vm_page_t		m,
					vm_object_t		new_object,
					vm_object_offset_t	new_offset);

extern void		vm_pageout_cluster(
					vm_page_t	m);

extern void		vm_pageout_initialize_page(
					vm_page_t	m);

extern void		vm_pageclean_setup(
					vm_page_t		m,
					vm_page_t		new_m,
					vm_object_t		new_object,
					vm_object_offset_t	new_offset);

extern void		vm_pageclean_copy(
					vm_page_t		m,
					vm_page_t		new_m,
					vm_object_t		new_object,
					vm_object_offset_t	new_offset);

/* UPL exported routines and structures */

#define upl_lock_init(object)	mutex_init(&(object)->Lock, 0)
#define upl_lock(object)	mutex_lock(&(object)->Lock)
#define upl_unlock(object)	mutex_unlock(&(object)->Lock)


/* universal page list structure */

struct upl {
	decl_mutex_data(,	Lock)	/* Synchronization */
	int		ref_count;
	int		flags;
	vm_object_t	src_object; /* object derived from */
	vm_object_offset_t offset;
	upl_size_t	size;	    /* size in bytes of the address space */
	vm_offset_t	kaddr;      /* secondary mapping in kernel */
	vm_object_t	map_object;
	ppnum_t		highest_page;
#ifdef	UPL_DEBUG
	unsigned int	ubc_alias1;
	unsigned int	ubc_alias2;
	queue_chain_t	uplq;	    /* List of outstanding upls on an obj */
#endif	/* UPL_DEBUG */
};

/* upl struct flags */
#define UPL_PAGE_LIST_MAPPED	0x1
#define UPL_KERNEL_MAPPED 	0x2
#define	UPL_CLEAR_DIRTY		0x4
#define UPL_COMPOSITE_LIST	0x8
#define UPL_INTERNAL		0x10
#define UPL_PAGE_SYNC_DONE	0x20
#define UPL_DEVICE_MEMORY	0x40
#define UPL_PAGEOUT		0x80
#define UPL_LITE		0x100
#define UPL_IO_WIRE		0x200
#define UPL_ACCESS_BLOCKED	0x400
#define UPL_ENCRYPTED		0x800


/* flags for upl_create flags parameter */
#define UPL_CREATE_EXTERNAL	0
#define UPL_CREATE_INTERNAL	0x1
#define UPL_CREATE_LITE		0x2

extern kern_return_t vm_object_iopl_request(
	vm_object_t		object,
	vm_object_offset_t	offset,
	upl_size_t		size,
	upl_t			*upl_ptr,
	upl_page_info_array_t	user_page_list,
	unsigned int		*page_list_count,
	int			cntrl_flags);

extern kern_return_t vm_object_super_upl_request(
	vm_object_t		object,
	vm_object_offset_t	offset,
	upl_size_t		size,
	upl_size_t		super_cluster,
	upl_t			*upl,
	upl_page_info_t		*user_page_list,
	unsigned int		*page_list_count,
	int			cntrl_flags);

/* should be just a regular vm_map_enter() */
extern kern_return_t vm_map_enter_upl(
	vm_map_t		map, 
	upl_t			upl, 
	vm_map_offset_t		*dst_addr);

/* should be just a regular vm_map_remove() */
extern kern_return_t vm_map_remove_upl(
	vm_map_t		map, 
	upl_t			upl);

#ifdef UPL_DEBUG
extern kern_return_t  upl_ubc_alias_set(
	upl_t upl,
	unsigned int alias1,
	unsigned int alias2);
extern int  upl_ubc_alias_get(
	upl_t upl,
	unsigned int * al,
	unsigned int * al2);
#endif /* UPL_DEBUG */

/* wired  page list structure */
typedef unsigned long *wpl_array_t;

extern void vm_page_free_list(
	register vm_page_t	mem);
	 
extern void vm_page_free_reserve(int pages);

extern void vm_pageout_throttle_down(vm_page_t page);
extern void vm_pageout_throttle_up(vm_page_t page);

/*
 * ENCRYPTED SWAP:
 */
extern void upl_encrypt(
	upl_t			upl,
	upl_offset_t		crypt_offset,
	upl_size_t		crypt_size);
extern void vm_page_encrypt(
	vm_page_t		page,
	vm_map_offset_t		kernel_map_offset);
extern boolean_t vm_pages_encrypted; /* are there encrypted pages ? */
extern void vm_page_decrypt(
	vm_page_t		page,
	vm_map_offset_t		kernel_map_offset);
extern kern_return_t vm_paging_map_object(
	vm_map_offset_t		*address,
	vm_page_t		page,
	vm_object_t		object,
	vm_object_offset_t	offset,
	vm_map_size_t		*size);
extern void vm_paging_unmap_object(
	vm_object_t		object,
	vm_map_offset_t		start,
	vm_map_offset_t		end);
decl_simple_lock_data(extern, vm_paging_lock)

/*
 * Backing store throttle when BS is exhausted
 */
extern unsigned int    vm_backing_store_low;

#endif  /* MACH_KERNEL_PRIVATE */

extern void vm_countdirtypages(void);

extern void vm_backing_store_disable(
			boolean_t	suspend);

extern kern_return_t upl_transpose(
	upl_t	upl1,
	upl_t	upl2);

#endif	/* KERNEL_PRIVATE */

#endif	/* _VM_VM_PAGEOUT_H_ */

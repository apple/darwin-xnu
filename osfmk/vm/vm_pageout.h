/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
 *	File:	vm/vm_pageout.h
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1986
 *
 *	Declarations for the pageout daemon interface.
 */

#ifndef	_VM_VM_PAGEOUT_H_
#define _VM_VM_PAGEOUT_H_

#include <mach/boolean.h>
#include <mach/machine/vm_types.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>




extern unsigned int	vm_pageout_scan_event_counter;
extern unsigned int	vm_zf_count;

/*
 *	The following ifdef only exists because XMM must (currently)
 *	be given a page at a time.  This should be removed
 *	in the future.
 */
#define	DATA_WRITE_MAX	16
#define	POINTER_T(copy)	(pointer_t)(copy)

/*
 *	Exported routines.
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

#define UPL_COMPOSITE_PAGE_LIST_MAX 16


#define upl_lock_init(object)	mutex_init(&(object)->Lock, ETAP_VM_OBJ)
#define upl_lock(object)	mutex_lock(&(object)->Lock)
#define upl_unlock(object)	mutex_unlock(&(object)->Lock)


/* universal page list structure */

struct upl {
	decl_mutex_data(,	Lock)	/* Synchronization */
	int		ref_count;
	int		flags;
	vm_object_t	src_object; /* object derived from */
	vm_object_offset_t offset;
	vm_size_t	size;	    /* size in bytes of the address space */
	vm_offset_t	kaddr;      /* secondary mapping in kernel */
	vm_object_t	map_object;
#ifdef	UBC_DEBUG
	unsigned int	ubc_alias1;
	unsigned int	ubc_alias2;
	queue_chain_t	uplq;	    /* List of outstanding upls on an obj */
#endif	/* UBC_DEBUG */

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

#define	UPL_PAGE_TICKET_MASK	0xF00
#define UPL_PAGE_TICKET_SHIFT	8





	 

#endif	/* _VM_VM_PAGEOUT_H_ */

/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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

#ifdef	KERNEL_PRIVATE

#ifndef	_KERN_KALLOC_H_
#define _KERN_KALLOC_H_

#include <mach/machine/vm_types.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

extern void *kalloc(vm_size_t	size);

extern void *kalloc_noblock(vm_size_t	size);

extern void *kget(vm_size_t	size);

extern void kfree(void		*data,
		  vm_size_t	size);

__END_DECLS

#ifdef	MACH_KERNEL_PRIVATE

#include <kern/lock.h>

#define KALLOC_MINSIZE		16

extern void		kalloc_init(void);

extern void		krealloc(void		**addrp,
				 vm_size_t	old_size,
				 vm_size_t	new_size,
				 simple_lock_t	lock);

extern void		kalloc_fake_zone_info(
				int		*count,
				vm_size_t	*cur_size,
				vm_size_t	*max_size,
				vm_size_t	*elem_size,
				vm_size_t	*alloc_size,
				int		*collectable,
				int		*exhaustable);

extern vm_size_t kalloc_max_prerounded;

#endif	/* MACH_KERNEL_PRIVATE */

#endif	/* _KERN_KALLOC_H_ */

#endif	/* KERNEL_PRIVATE */

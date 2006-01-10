/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
 * Copyright (C) 1998 Apple Computer
 * All Rights Reserved
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
 *	File:	kern/simple_lock.h (derived from kern/lock.h)
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Atomic primitives and Simple Locking primitives definitions
 */

#ifdef	KERNEL_PRIVATE

#ifndef	_KERN_SIMPLE_LOCK_H_
#define	_KERN_SIMPLE_LOCK_H_

#include <sys/cdefs.h>
#include <mach/boolean.h>
#include <kern/kern_types.h>
#include <machine/simple_lock.h>

#ifdef	MACH_KERNEL_PRIVATE
#include <mach_ldebug.h>

extern void			hw_lock_init(
					hw_lock_t);

extern void			hw_lock_lock(
					hw_lock_t);

extern void			hw_lock_unlock(
					hw_lock_t);

extern unsigned int		hw_lock_to(
					hw_lock_t,
					unsigned int);

extern unsigned int		hw_lock_try(
					hw_lock_t);

extern unsigned int		hw_lock_held(
					hw_lock_t);

#endif	/* MACH_KERNEL_PRIVATE */

__BEGIN_DECLS

extern uint32_t			hw_atomic_add(
					uint32_t	*dest,
					uint32_t	delt);

extern uint32_t			hw_atomic_sub(
					uint32_t	*dest,
					uint32_t	delt);

extern uint32_t			hw_atomic_or(
					uint32_t	*dest,
					uint32_t	mask);

extern uint32_t			hw_atomic_and(
					uint32_t	*dest,
					uint32_t	mask);

extern uint32_t			hw_compare_and_store(
					uint32_t	oldval,
					uint32_t	newval,
					uint32_t	*dest);

extern void			hw_queue_atomic(
					unsigned int *anchor,
					unsigned int *elem,
					unsigned int disp);

extern void 			hw_queue_atomic_list(
					unsigned int *anchor,
					unsigned int *first,
					unsigned int *last,
					unsigned int disp);

extern unsigned int 		*hw_dequeue_atomic(
					unsigned int *anchor,
					unsigned int disp);

extern void			usimple_lock_init(
					usimple_lock_t,
					unsigned short);

extern void			usimple_lock(
					usimple_lock_t);

extern void			usimple_unlock(
					usimple_lock_t);

extern unsigned int		usimple_lock_try(
					usimple_lock_t);

__END_DECLS

#define	ETAP_NO_TRACE	0
#define ETAP_IO_AHA		0

/*
 * If we got to here and we still don't have simple_lock_init
 * defined, then we must either be outside the osfmk component,
 * running on a true SMP, or need debug.
 */
#if !defined(simple_lock_init)
#define simple_lock_init(l,t)	usimple_lock_init(l,t)
#define	simple_lock(l)		usimple_lock(l)
#define	simple_unlock(l)	usimple_unlock(l)
#define simple_lock_try(l)	usimple_lock_try(l)
#define simple_lock_addr(l)	(&(l))
#define thread_sleep_simple_lock(l, e, i) \
				thread_sleep_usimple_lock((l), (e), (i))
#endif /* !defined(simple_lock_init) */

#endif /*!_KERN_SIMPLE_LOCK_H_*/

#endif	/* KERNEL_PRIVATE */

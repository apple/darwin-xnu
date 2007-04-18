/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
 *	File:	kern/lock.h
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Higher Level Locking primitives definitions
 */

#ifdef	KERNEL_PRIVATE

#ifndef	_KERN_LOCK_H_
#define	_KERN_LOCK_H_

#include <kern/simple_lock.h>
#include <machine/lock.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

#ifndef	MACH_KERNEL_PRIVATE

typedef struct __mutex__ mutex_t;

#else	/* MACH_KERNEL_PRIVATE */

#define	decl_mutex_data(class,name)	class mutex_t name;
#define mutex_addr(m)			(&(m))

extern void			mutex_init(
						mutex_t		*mutex,
						unsigned short	tag);

#endif	/* MACH_KERNEL_PRIVATE */

extern mutex_t		*mutex_alloc(
						unsigned short	tag);

extern void			mutex_free(
						mutex_t		*mutex);

extern void			mutex_lock(
						mutex_t		*mutex);

extern void			mutex_unlock(
						mutex_t		*mutex);

extern boolean_t	mutex_try(
						mutex_t		*mutex);

extern void			mutex_pause(void);

#define MA_OWNED        0x01
#define MA_NOTOWNED     0x02
 
void 				_mutex_assert (
						mutex_t		*mutex,
						unsigned int	what);

#define mutex_assert(a, b)	_mutex_assert(a, b)

#ifndef	MACH_KERNEL_PRIVATE

typedef struct __lock__ lock_t;

#else	/* MACH_KERNEL_PRIVATE */

extern void			lock_init(
						lock_t		*lock,
						boolean_t	can_sleep,
						unsigned short	tag0,
						unsigned short	tag1);

#endif	/* MACH_KERNEL_PRIVATE */

extern lock_t		 *lock_alloc(
						boolean_t	can_sleep, 
						unsigned short	tag0, 
						unsigned short	tag1);

extern void			 lock_free(
						lock_t 		*lock);

extern void			lock_write(
						lock_t		*lock);

extern void			lock_read(
						lock_t		*lock);

extern void			lock_done(
						lock_t		*lock);

extern void			lock_write_to_read(
						lock_t		*lock);

#define	lock_read_done(l)		lock_done(l)
#define	lock_write_done(l)		lock_done(l)

extern boolean_t	 lock_read_to_write(
						lock_t		*lock);


/* Sleep, unlocking and then relocking a usimple_lock in the process */
extern wait_result_t	thread_sleep_usimple_lock(
							event_t				event,
							usimple_lock_t		lock,
							wait_interrupt_t	interruptible);

/* Sleep, unlocking and then relocking a mutex in the process */
extern wait_result_t	thread_sleep_mutex(
							event_t				event,
							mutex_t				*mutex,
							wait_interrupt_t	interruptible);
										
/* Sleep with a deadline, unlocking and then relocking a mutex in the process */
extern wait_result_t	thread_sleep_mutex_deadline(
							event_t				event,
							mutex_t				*mutex,
							uint64_t			deadline,
							wait_interrupt_t	interruptible);

/* Sleep, unlocking and then relocking a write lock in the process */
extern wait_result_t	thread_sleep_lock_write(
							event_t				event,
							lock_t				*lock,
							wait_interrupt_t	interruptible);
__END_DECLS

#ifdef	MACH_KERNEL_PRIVATE

extern wait_result_t	thread_sleep_fast_usimple_lock(
							event_t					event,
							simple_lock_t			lock,
							wait_interrupt_t		 interruptible);
#endif	/* MACH_KERNEL_PRIVATE */

#endif	/* _KERN_LOCK_H_ */

#endif	/* KERNEL_PRIVATE */

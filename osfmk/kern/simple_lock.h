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
 *	Simple Locking primitives definitions
 */

#ifndef	_SIMPLE_LOCK_H_
#define	_SIMPLE_LOCK_H_

/*
 * Configuration variables:
 *
 *
 *	MACH_LDEBUG:    record pc and thread of callers, turn on
 *			all lock debugging.
 *
 *
 *	ETAP:		The Event Trace Analysis Package (ETAP) monitors
 *			and records micro-kernel lock behavior and general
 *			kernel events.  ETAP supports two levels of
 *			tracing for locks:
 *				- cumulative (ETAP_LOCK_ACCUMULATE)
 *				- monitored  (ETAP_LOCK_MONITOR)
 *
 *			Note: If either level of tracing is configured then
 *			      ETAP_LOCK_TRACE is automatically defined to 
 *			      equal one.
 *
 * 		        Several macros are added throughout the lock code to
 *                      allow for convenient configuration.
 */

#include <mach/boolean.h>
#include <kern/kern_types.h>

#include <kern/simple_lock_types.h>
#include <machine/lock.h>
#include <mach/etap_events.h>
#include <mach/etap.h>

/*
 *	The Mach lock package exports the following simple lock abstractions:
 *
 *	Lock Type  Properties
 *	hw_lock	   lowest level hardware abstraction; atomic,
 *		   non-blocking, mutual exclusion; supports pre-emption
 *	usimple	   non-blocking spinning lock, available in all
 *		   kernel configurations; may be used from thread
 *		   and interrupt contexts; supports debugging,
 *		   statistics and pre-emption
 *	simple	   non-blocking spinning lock, intended for SMP
 *		   synchronization (vanishes on a uniprocessor);
 *		   supports debugging, statistics and pre-emption
 *
 *	NOTES TO IMPLEMENTORS:  there are essentially two versions
 *	of the lock package.  One is portable, written in C, and
 *	supports all of the various flavors of debugging, statistics,
 *	uni- versus multi-processor, pre-emption, etc.  The "other"
 *	is whatever set of lock routines is provided by machine-dependent
 *	code.  Presumably, the machine-dependent package is heavily
 *	optimized and meant for production kernels.
 *
 *	We encourage implementors to focus on highly-efficient,
 *	production implementations of machine-dependent lock code,
 *	and use the portable lock package for everything else.
 */

#include <sys/appleapiopts.h>

#ifdef	__APPLE_API_PRIVATE

#ifdef	MACH_KERNEL_PRIVATE

/*
 *	Mach always initializes locks, even those statically
 *	allocated.
 *
 *	The conditional acquisition call, hw_lock_try,
 *	must return non-zero on success and zero on failure.
 *
 *	The hw_lock_held operation returns non-zero if the
 *	lock is set, zero if the lock is clear.  This operation
 *	should be implemented using an ordinary memory read,
 *	rather than a special atomic instruction, allowing
 *	a processor to spin in cache waiting for the lock to
 *	be released without chewing up bus cycles.
 */
extern void			hw_lock_init(hw_lock_t);
extern void			hw_lock_lock(hw_lock_t);
extern void			hw_lock_unlock(hw_lock_t);
extern unsigned int		hw_lock_to(hw_lock_t, unsigned int);
extern unsigned int		hw_lock_try(hw_lock_t);
extern unsigned int		hw_lock_held(hw_lock_t);

#endif	/* MACH_KERNEL_PRIVATE */

#endif	/* __APPLE_API_PRIVATE */

/*
 * Machine dependent ops.
 */
extern unsigned int		hw_lock_bit(unsigned int *, unsigned int, unsigned int);
extern unsigned int		hw_cpu_sync(unsigned int *, unsigned int);
extern unsigned int		hw_cpu_wcng(unsigned int *, unsigned int, unsigned int);
extern unsigned int		hw_lock_mbits(unsigned int *, unsigned int, unsigned int,
	unsigned int, unsigned int);
void				hw_unlock_bit(unsigned int *, unsigned int);

extern uint32_t		hw_atomic_add(
						uint32_t	*dest,
						uint32_t	delt);

extern uint32_t		hw_atomic_sub(
						uint32_t	*dest,
						uint32_t	delt);

extern uint32_t		hw_atomic_or(
						uint32_t	*dest,
						uint32_t	mask);

extern uint32_t		hw_atomic_and(
						uint32_t	*dest,
						uint32_t	mask);

extern uint32_t		hw_compare_and_store(
						uint32_t	oldval,
						uint32_t	newval,
						uint32_t	*dest);

extern void			hw_queue_atomic(unsigned int *anchor, unsigned int *elem, unsigned int disp);
extern void 			hw_queue_atomic_list(unsigned int *anchor, unsigned int *first, unsigned int *last, unsigned int disp);
extern unsigned int 		*hw_dequeue_atomic(unsigned int *anchor, unsigned int disp);


/*
 *	The remaining locking constructs may have two versions.
 *	One version is machine-independent, built in C on top of the
 *	hw_lock construct.  This version supports production, debugging
 *	and statistics configurations and is portable across architectures.
 *
 *	Any particular port may override some or all of the portable
 *	lock package for whatever reason -- usually efficiency.
 *
 *	The direct use of hw_locks by machine-independent Mach code
 *	should be rare; the preferred spinning lock is the simple_lock
 *	(see below).
 */

/*
 *	A "simple" spin lock, providing non-blocking mutual
 *	exclusion and conditional acquisition.
 *
 *	The usimple_lock exists even in uniprocessor configurations.
 *	A data structure is always allocated for it and the following
 *	operations are always defined:
 *
 *		usimple_lock_init	lock initialization (mandatory!)
 *		usimple_lock		lock acquisition
 *		usimple_unlock		lock release
 *		usimple_lock_try	conditional lock acquisition;
 *					non-zero means success
 *      Simple lock DEBUG interfaces
 *		usimple_lock_held	verify lock already held by me
 *		usimple_lock_none_held	verify no usimple locks are held
 *
 *	The usimple_lock may be used for synchronization between
 *	thread context and interrupt context, or between a uniprocessor
 *	and an intelligent device.  Obviously, it may also be used for
 *	multiprocessor synchronization.  Its use should be rare; the
 *	simple_lock is the preferred spinning lock (see below).
 *
 *	The usimple_lock supports optional lock debugging and statistics.
 *
 *	Normally, we expect the usimple_lock data structure to be
 *	defined here, with its operations implemented in an efficient,
 *	machine-dependent way.  However, any implementation may choose
 *	to rely on a C-based, portable  version of the usimple_lock for
 *	debugging, statistics, and/or tracing.  Three hooks are used in
 *	the portable lock package to allow the machine-dependent package
 *	to override some or all of the portable package's features.
 *
 *	The usimple_lock also handles pre-emption.  Lock acquisition
 *	implies disabling pre-emption, while lock release implies
 *	re-enabling pre-emption.  Conditional lock acquisition does
 *	not assume success:  on success, pre-emption is disabled
 *	but on failure the pre-emption state remains the same as
 *	the pre-emption state before the acquisition attempt.
 */

/*
 *	Each usimple_lock has a type, used for debugging and
 *	statistics.  This type may safely be ignored in a
 *	production configuration.
 *
 *	The conditional acquisition call, usimple_lock_try,
 *	must return non-zero on success and zero on failure.
 */
extern void		usimple_lock_init(usimple_lock_t,etap_event_t);
extern void		usimple_lock(usimple_lock_t);
extern void		usimple_unlock(usimple_lock_t);
extern unsigned int	usimple_lock_try(usimple_lock_t);
extern void		usimple_lock_held(usimple_lock_t);
extern void		usimple_lock_none_held(void);


/*
 *	Upon the usimple_lock we define the simple_lock, which
 *	exists for SMP configurations.  These locks aren't needed
 *	in a uniprocessor configuration, so compile-time tricks
 *	make them disappear when NCPUS==1.  (For debugging purposes,
 *	however, they can be enabled even on a uniprocessor.)  This
 *	should be the "most popular" spinning lock; the usimple_lock
 *	and hw_lock should only be used in rare cases.
 *
 *	IMPORTANT:  simple_locks that may be shared between interrupt
 *	and thread context must have their use coordinated with spl.
 *	The spl level must alway be the same when acquiring the lock.
 *	Otherwise, deadlock may result.
 */

#ifdef	__APPLE_API_PRIVATE

#ifdef	MACH_KERNEL_PRIVATE

#include <cpus.h>
#include <mach_ldebug.h>

#if	NCPUS == 1 && !ETAP_LOCK_TRACE && !USLOCK_DEBUG
/*
 *	MACH_RT is a very special case:  in the case that the
 *	machine-dependent lock package hasn't taken responsibility
 *	but there is no other reason to turn on locks, if MACH_RT
 *	is turned on locks denote critical, non-preemptable points
 *	in the code.
 *
 *	Otherwise, simple_locks may be layered directly on top of
 *	usimple_locks.
 *
 *	N.B.  The reason that simple_lock_try may be assumed to
 *	succeed under MACH_RT is that the definition only is used
 *	when NCPUS==1 AND because simple_locks shared between thread
 *	and interrupt context are always acquired with elevated spl.
 *	Thus, it is never possible to be interrupted in a dangerous
 *	way while holding a simple_lock.
 */
/*
 *	for locks and there is no other apparent reason to turn them on.
 *	So make them disappear.
 */
#define simple_lock_init(l,t)
#define	simple_lock(l)		disable_preemption()
#define	simple_unlock(l)	enable_preemption()
#define simple_lock_try(l)	(disable_preemption(), 1)
#define simple_lock_addr(lock)	((simple_lock_t)0)
#define	__slock_held_func__(l)	preemption_is_disabled()
#endif	/* NCPUS == 1 && !ETAP_LOCK_TRACE && !USLOCK_DEBUG */

#if	ETAP_LOCK_TRACE
extern	void	simple_lock_no_trace(simple_lock_t l);
extern	int	simple_lock_try_no_trace(simple_lock_t l);
extern	void	simple_unlock_no_trace(simple_lock_t l);
#endif	/* ETAP_LOCK_TRACE */

#endif	/* MACH_KERNEL_PRIVATE */

#endif	/* __APPLE_API_PRIVATE */

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
#define	__slock_held_func__(l)	usimple_lock_held(l)
#define thread_sleep_simple_lock(l, e, i) \
				thread_sleep_usimple_lock((l), (e), (i))
#endif / * !defined(simple_lock_init) */

#if	USLOCK_DEBUG
/*
 *	Debug-time only:
 *		+ verify that usimple_lock is already held by caller
 *		+ verify that usimple_lock is NOT held by caller
 *		+ verify that current processor owns no usimple_locks
 *
 *	We do not provide a simple_lock_NOT_held function because
 *	it's impossible to verify when only MACH_RT is turned on.
 *	In that situation, only preemption is enabled/disabled
 *	around lock use, and it's impossible to tell which lock
 *	acquisition caused preemption to be disabled.  However,
 *	note that it's still valid to use check_simple_locks
 *	when only MACH_RT is turned on -- no locks should be
 *	held, hence preemption should be enabled.
 *	Actually, the above isn't strictly true, as explicit calls
 *	to disable_preemption() need to be accounted for.
 */
#define	simple_lock_held(l)	__slock_held_func__(l)
#define	check_simple_locks()	usimple_lock_none_held()

#else	/* USLOCK_DEBUG */

#define	simple_lock_held(l)
#define	check_simple_locks()

#endif	/* USLOCK_DEBUG */

#endif /*!_SIMPLE_LOCK_H_*/

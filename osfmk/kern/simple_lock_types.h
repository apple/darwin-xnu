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
 *	File:	kern/simple_lock_types.h
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Simple lock data type definitions
 */

#ifndef	_SIMPLE_LOCK_TYPES_H_
#define	_SIMPLE_LOCK_TYPES_H_

#include <mach/boolean.h>
#include <kern/kern_types.h>
#include <machine/hw_lock_types.h>

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

/*
 *	All of the remaining locking constructs may have two versions.
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
 *	A data structure is always allocated for it.
 *
 *	The usimple_lock may be used for synchronization between
 *	thread context and interrupt context, or between a uniprocessor
 *	and an intelligent device.  Obviously, it may also be used for
 *	multiprocessor synchronization.  Its use should be rare; the
 *	simple_lock is the preferred spinning lock (see below).
 *
 *	The usimple_lock supports optional lock debugging and statistics.
 *
 *	The usimple_lock may be inlined or optimized in ways that
 *	depend on the particular machine architecture and kernel
 *	build configuration; e.g., processor type, number of CPUs,
 *	production v. debugging.
 *
 *	Normally, we expect the usimple_lock data structure to be
 *	defined here, with its operations implemented in an efficient,
 *	machine-dependent way.  However, any implementation may choose
 *	to rely on a C-based, portable  version of the usimple_lock for
 *	debugging, statistics, and/or tracing.  Three hooks are used in
 *	the portable lock package to allow the machine-dependent package
 *	to override some or all of the portable package's features.
 *
 *	
 *      The usimple_lock data structure
 *	can be overriden in a machine-dependent way by defining
 *	LOCK_USIMPLE_DATA, although we expect this to be unnecessary.
 *	(Note that if you choose to override LOCK_USIMPLE_DATA, you'd
 *      better also be prepared to override LOCK_USIMPLE_CALLS.) 
 *
 *	The usimple_lock also handles pre-emption.  Lock acquisition
 *	implies disabling pre-emption, while lock release implies
 *	re-enabling pre-emption.  Conditional lock acquisition does
 *	not assume success:  on success, pre-emption is disabled
 *	but on failure the pre-emption state remains the same as
 *	the pre-emption state before the acquisition attempt.
 */

#ifndef	USIMPLE_LOCK_DATA
#define USLOCK_DEBUG_DATA 1 /* Always allocate lock debug data for now */
#if	USLOCK_DEBUG_DATA
/*
 * 
 *
 *	This structure records additional information about lock state
 *	and recent operations.  The data are carefully organized so that
 *	some portions of it can be examined BEFORE actually acquiring
 *	the lock -- for instance, the lock_thread field, to detect an
 *	attempt to acquire a lock already owned by the calling thread.
 *	All *updates* to this structure are governed by the lock to which
 *	this structure belongs.
 *
 *	Note cache consistency dependency:  being able to examine some
 *	of the fields in this structure without first acquiring a lock
 *	implies strongly-ordered cache coherency OR release consistency.
 *	Perhaps needless to say, acquisition consistency may not suffice.
 *	However, it's hard to imagine a scenario using acquisition
 *	consistency that results in using stale data from this structure.
 *	It would be necessary for the thread manipulating the lock to
 *	switch to another processor without first executing any instructions
 *	that would cause the needed consistency updates; basically, without
 *	taking a lock.  Not possible in this kernel!
 */
typedef struct uslock_debug {
        void		*lock_pc;	/* pc where lock operation began    */
	void		*lock_thread;	/* thread that acquired lock */
	unsigned long	duration[2];
	unsigned short	state;
	unsigned char	lock_cpu;
	void		*unlock_thread;	/* last thread to release lock */
	unsigned char	unlock_cpu;
        void		*unlock_pc;	/* pc where lock operation ended    */
} uslock_debug;
#endif	/* USLOCK_DEBUG_DATA */

typedef struct slock {
	hw_lock_data_t	interlock;	/* must be first... see lock.c */
#if	USLOCK_DEBUG_DATA
	unsigned short	lock_type;	/* must be second... see lock.c */
#define	USLOCK_TAG	0x5353
	uslock_debug	debug;
#endif	/* USLOCK_DEBUG_DATA */
} usimple_lock_data_t, *usimple_lock_t;

#define	USIMPLE_LOCK_NULL	((usimple_lock_t) 0)

#endif	/* USIMPLE_LOCK_DATA */

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
 *
 *	Given that, in some configurations, Mach does not need to
 *	allocate simple_lock data structures, users of simple_locks
 *	should employ the "decl_simple_lock_data" macro when allocating
 *	simple_locks.  Note that it use should be something like
 *		decl_simple_lock_data(static,foo_lock)
 *	WITHOUT any terminating semi-colon.  Because the macro expands
 *	to include its own semi-colon, if one is needed, it may safely
 *	be used multiple times at arbitrary positions within a structure.
 *	Adding a semi-colon will cause structure definitions to fail
 *	when locks are turned off and a naked semi-colon is left behind. 
 */

/*
 *	Decide whether to allocate simple_lock data structures.
 *	If the machine-dependent code has turned on LOCK_SIMPLE_DATA,
 *	then it assumes all responsibility.  Otherwise, we need
 *	these data structures if the configuration includes SMP or
 *	lock debugging or statistics.
 *
 *	N.B.  Simple locks should be declared using
 *		decl_simple_lock_data(class,name)
 *	with no trailing semi-colon.  This syntax works best because
 *		- it correctly disappears in production uniprocessor
 *		  configurations, leaving behind no allocated data
 *		  structure
 *		- it can handle static and extern declarations:
 *			decl_simple_lock_data(extern,foo)	extern
 *			decl_simple_lock_data(static,foo)	static
 *			decl_simple_lock_data(,foo)		ordinary
 */

#include <sys/appleapiopts.h>

#ifdef	__APPLE_API_PRIVATE

#ifdef	MACH_KERNEL_PRIVATE

#include <mach_ldebug.h>
#include <cpus.h>

/*
 * Turn on the uslock debug (internally to oskmk) when we are using the
 * package and mach_ldebug build option is set.
 */
#if (MACH_LDEBUG) && !(defined(LOCK_SIMPLE_DATA))
#define USLOCK_DEBUG 1
#else
#define USLOCK_DEBUG 0
#endif

#if     (defined(LOCK_SIMPLE_DATA) || ((NCPUS == 1) && !USLOCK_DEBUG ))
typedef	usimple_lock_data_t	*simple_lock_t;
#define	decl_simple_lock_data(class,name)
#endif

#endif	/* MACH_KERNEL_PRIVATE */

#endif	/* __APPLE_API_PRIVATE */

/*
 *  Outside the mach kernel component, and even within it on SMP or
 *  debug systems, simple locks are the same as usimple locks.
 */
#if !defined(decl_simple_lock_data)
typedef usimple_lock_data_t	*simple_lock_t;
typedef usimple_lock_data_t	simple_lock_data_t;

#define	decl_simple_lock_data(class,name) \
	class	simple_lock_data_t	name;

#endif	/* !defined(decl_simple_lock_data) */

#endif /* !_SIMPLE_LOCK_TYPES_H_ */

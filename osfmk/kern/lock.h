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
 *	File:	kern/lock.h
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Higher Level Locking primitives definitions
 */

#ifndef	_KERN_LOCK_H_
#define	_KERN_LOCK_H_

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

#include <kern/simple_lock.h>
#include <machine/lock.h>
#include <mach/etap_events.h>
#include <mach/etap.h>

/*
 *	The Mach lock package exports the following high-level
 *      lock abstractions:
 *
 *	Lock Type  Properties
 *	mutex	   blocking mutual exclusion lock, intended for
 *		   SMP synchronization (vanishes on a uniprocessor);
 *		   supports debugging, statistics, and pre-emption
 *	lock	   blocking synchronization permitting multiple
 *		   simultaneous readers or a single writer; supports
 *		   debugging and statistics but not pre-emption
 *
 *	In general, mutex locks are preferred over all others, as the
 *	mutex supports pre-emption and relinquishes the processor
 *	upon contention.
 *
 */

#include <sys/appleapiopts.h>

#ifdef	__APPLE_API_PRIVATE

#ifdef	MACH_KERNEL_PRIVATE

/*
 *	A simple mutex lock.
 *	Do not change the order of the fields in this structure without
 *	changing the machine-dependent assembler routines which depend
 *	on them.
 */

#include <mach_ldebug.h>
#include <kern/etap_options.h>
#include <kern/etap_pool.h>

typedef struct {
	hw_lock_data_t	interlock;
	hw_lock_data_t	locked;
	uint16_t		waiters;
	uint16_t		promoted_pri;
#if	MACH_LDEBUG
	int		type;
#define	MUTEX_TAG	0x4d4d
	vm_offset_t	pc;
	vm_offset_t	thread;
#endif	/* MACH_LDEBUG */
#if     ETAP_LOCK_TRACE
	union {		/* Must be overlaid on the event_tablep */
	    struct event_table_chain event_table_chain;
	    struct {
		event_table_t   event_tablep;     /* ptr to event table entry */
		etap_time_t	start_hold_time;  /* Time of last acquistion */
	    } s;
	} u;
#endif 	/* ETAP_LOCK_TRACE */
#if     ETAP_LOCK_ACCUMULATE
        cbuff_entry_t  	cbuff_entry;	  /* cumulative buffer entry          */
#endif 	/* ETAP_LOCK_ACCUMULATE */
#if	ETAP_LOCK_MONITOR
        vm_offset_t	start_pc;	  /* pc where lock operation began    */
        vm_offset_t	end_pc;		  /* pc where lock operation ended    */
#endif 	/* ETAP_LOCK_MONITOR */
} mutex_t;

#define	decl_mutex_data(class,name)	class mutex_t name;
#define mutex_addr(m)			(&(m))

extern void		mutex_init(
					mutex_t			*mutex,
					etap_event_t	tag);

extern void		mutex_lock_wait(
					mutex_t			*mutex,
					thread_t		holder);

extern int		mutex_lock_acquire(
					mutex_t			*mutex);

extern void		mutex_unlock_wakeup(
					mutex_t			*mutex,
					thread_t		holder);

extern boolean_t	mutex_preblock(
						mutex_t			*mutex,
						thread_t		thread);

extern boolean_t	mutex_preblock_wait(
						mutex_t			*mutex,
						thread_t		thread,
						thread_t		holder);

extern void		interlock_unlock(
					hw_lock_t		lock);

#endif	/* MACH_KERNEL_PRIVATE */

extern void		mutex_pause(void);

#endif	/* __APPLE_API_PRIVATE */

#if		!defined(MACH_KERNEL_PRIVATE)

typedef struct __mutex__ mutex_t;

#endif	/* MACH_KERNEL_PRIVATE */

extern mutex_t	*mutex_alloc(
					etap_event_t	tag);

extern void		mutex_free(
					mutex_t			*mutex);

extern void		mutex_lock(
					mutex_t			*mutex);

extern void		mutex_unlock(
					mutex_t			*mutex);

extern boolean_t	mutex_try(
						mutex_t		*mutex);

#ifdef	__APPLE_API_PRIVATE

#ifdef MACH_KERNEL_PRIVATE

/*
 *	The general lock structure.  Provides for multiple readers,
 *	upgrading from read to write, and sleeping until the lock
 *	can be gained.
 *
 *	On some architectures, assembly language code in the 'inline'
 *	program fiddles the lock structures.  It must be changed in
 *	concert with the structure layout.
 *
 *	Only the "interlock" field is used for hardware exclusion;
 *	other fields are modified with normal instructions after
 *	acquiring the interlock bit.
 */

typedef struct {
	decl_simple_lock_data(,interlock) /* "hardware" interlock field */
	volatile unsigned int
		read_count:16,	/* No. of accepted readers */
		want_upgrade:1,	/* Read-to-write upgrade waiting */
		want_write:1,	/* Writer is waiting, or
				   locked for write */
		waiting:1,	/* Someone is sleeping on lock */
		can_sleep:1;	/* Can attempts to lock go to sleep? */
#if     ETAP_LOCK_TRACE
	union {		/* Must be overlaid on the event_tablep */
	    struct event_table_chain event_table_chain;
	    struct {
		event_table_t event_tablep;	/* ptr to event table entry */
		start_data_node_t start_list;	/* linked list of start times
						   and pcs */
	    } s;
	} u;
#endif 	/* ETAP_LOCK_TRACE */
#if     ETAP_LOCK_ACCUMULATE
       	cbuff_entry_t	cbuff_write;	/* write cumulative buffer entry      */
	cbuff_entry_t	cbuff_read;	/* read  cumulative buffer entry      */
#endif 	/* ETAP_LOCK_ACCUMULATE */
} lock_t;

/* Sleep locks must work even if no multiprocessing */

/*
 * Complex lock operations
 */

#if ETAP
/*
 *	Locks have a pointer into an event_table entry that names the
 *	corresponding lock event and controls whether it is being traced.
 *	Initially this pointer is into a read-only table event_table_init[].
 *	Once dynamic allocation becomes possible a modifiable copy of the table
 *	is allocated and pointers are set to within this copy.  The pointers
 *	that were already in place at that point need to be switched to point
 *	into the copy.  To do this we overlay the event_table_chain structure
 *	onto sufficiently-big elements of the various lock structures so we
 *	can sweep down this list switching the pointers.  The assumption is
 *	that we will not want to enable tracing before this is done (which is
 *	after all during kernel bootstrap, before any user tasks are launched).
 *
 *	This is admittedly rather ugly but so were the alternatives:
 *	- record the event_table pointers in a statically-allocated array
 *	  (dynamic allocation not yet being available) -- but there were
 *	  over 8000 of them;
 *	- add a new link field to each lock structure;
 *	- change pointers to array indices -- this adds quite a bit of
 *	  arithmetic to every lock operation that might be traced.
 */
#define lock_event_table(lockp)		((lockp)->u.s.event_tablep)
#define lock_start_hold_time(lockp)	((lockp)->u.s.start_hold_time)
#endif	/* ETAP_LOCK_TRACE */

extern void	lock_init		(lock_t*,
					 boolean_t,
					 etap_event_t,
					 etap_event_t);

#endif	/* MACH_KERNEL_PRIVATE */

extern unsigned int LockTimeOut;	/* Standard lock timeout value */

#endif	/* __APPLE_API_PRIVATE */

#if		!defined(MACH_KERNEL_PRIVATE)

typedef struct __lock__ lock_t;
extern lock_t *lock_alloc(boolean_t, etap_event_t, etap_event_t);
void lock_free(lock_t *);

#endif	/* MACH_KERNEL_PRIVATE */

extern void	lock_write		(lock_t*);
extern void	lock_read		(lock_t*);
extern void	lock_done		(lock_t*);
extern void	lock_write_to_read	(lock_t*);

#define	lock_read_done(l)		lock_done(l)
#define	lock_write_done(l)		lock_done(l)

extern boolean_t lock_read_to_write	(lock_t*);  /* vm_map is only user */

#endif	/* _KERN_LOCK_H_ */

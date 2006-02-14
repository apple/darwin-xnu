/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 * 
 */
/*
 *	File:	kern/sync_lock.h
 *	Author:	Joseph CaraDonna
 *
 *	Contains RT distributed lock synchronization service definitions.
 */

#ifndef _KERN_SYNC_LOCK_H_
#define _KERN_SYNC_LOCK_H_

#include <mach/mach_types.h>

#ifdef	MACH_KERNEL_PRIVATE

#include <kern/wait_queue.h>
#include <kern/macro_help.h>
#include <kern/queue.h>
#include <kern/lock.h>

typedef struct ulock {
	queue_chain_t	thread_link;	/* ulocks owned by a thread  	    */
	queue_chain_t	held_link;	/* ulocks held in the lock set	    */
	queue_chain_t	handoff_link;	/* ulocks w/ active handoffs	    */

	decl_mutex_data(,lock)		/* ulock lock			    */

	struct lock_set *lock_set;	/* the retaining lock set	    */
	thread_t	holder;		/* thread that holds the lock   */
	unsigned int			/* flags                            */
	/* boolean_t */ blocked:1,	/*     did threads block waiting?   */
	/* boolean_t */	unstable:1,	/*     unstable? (holder died)	    */
	/* boolean_t */ ho_wait:1,	/*     handoff thread waiting?	    */
	/* boolean_t */ accept_wait:1,	/*     accepting thread waiting?    */
			:0;		/*     force to long boundary       */

	struct wait_queue wait_queue;	/* queue of blocked threads	    */
} Ulock;

typedef struct ulock *ulock_t;

typedef struct lock_set {
	queue_chain_t	task_link;   /* chain of lock sets owned by a task  */
	decl_mutex_data(,lock)	     /* lock set lock			    */
	task_t		owner;	     /* task that owns the lock set	    */
	ipc_port_t	port;	     /* lock set port			    */
	int		ref_count;   /* reference count			    */

	boolean_t	active;	     /* active status			    */
	int		n_ulocks;    /* number of ulocks in the lock set    */

	struct ulock	ulock_list[1];	/* ulock group list place holder    */
} Lock_Set;

#define ULOCK_NULL	((ulock_t) 0)

#define ULOCK_FREE	0
#define ULOCK_HELD	1

/*
 *  Data structure internal lock macros
 */

#define lock_set_lock_init(ls)		mutex_init(&(ls)->lock, 0)
#define lock_set_lock(ls)		mutex_lock(&(ls)->lock)
#define lock_set_unlock(ls)		mutex_unlock(&(ls)->lock)

#define ulock_lock_init(ul)		mutex_init(&(ul)->lock, 0)
#define ulock_lock(ul)			mutex_lock(&(ul)->lock)
#define ulock_unlock(ul)		mutex_unlock(&(ul)->lock)

extern void lock_set_init(void);

extern	kern_return_t	ulock_release_internal(
					ulock_t		ulock,
					thread_t	thread);

extern	kern_return_t	lock_make_unstable(
					ulock_t 	ulock, 
					thread_t 	thread);

extern	void	ulock_release_all(
					thread_t	thread);

extern	void		lock_set_reference	(lock_set_t lock_set);
extern	void		lock_set_dereference	(lock_set_t lock_set);

#endif	/* MACH_KERNEL_PRIVATE */

#endif /* _KERN_SYNC_LOCK_H_ */

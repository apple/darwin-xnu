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
#ifndef _KERN_WAIT_QUEUE_H_
#define _KERN_WAIT_QUEUE_H_

#include <kern/kern_types.h>		/* for wait_queue_t */
#include <mach/sync_policy.h>
#include <mach/kern_return.h>		/* for kern_return_t */


#include <kern/lock.h>
#include <kern/queue.h>

/*
 *	wait_queue_t
 *	This is the definition of the common event wait queue
 *	that the scheduler APIs understand.  It is used
 *	internally by the gerneralized event waiting mechanism
 *	(assert_wait), and also for items that maintain their
 *	own wait queues (such as ports and semaphores).
 *
 *	It is not published to other kernel components.  They
 *	can create wait queues by calling wait_queue_alloc.
 *
 *	NOTE:  Hardware locks are used to protect event wait
 *	queues since interrupt code is free to post events to
 *	them.
 *	WARNING: Cannot change this data structure without updating SIZEOF_WAITQUEUE
 */
typedef struct wait_queue {
    hw_lock_data_t	wq_interlock;	/* interlock */
    unsigned int                        /* flags */
    /* boolean_t */	wq_fifo:1,	/* fifo wakeup policy? */
			wq_issub:1,	/* is waitq linked? */
			wq_isprepost:1,	/* is waitq preposted? sub only */
			:0;		/* force to long boundary */
    queue_head_t	wq_queue;	/* queue of elements */
} WaitQueue;

#define SIZEOF_WAITQUEUE 	16		/* 16 bytes for wq */
#define SIZEOF_WAITQUEUE_SUB 28		/* 24 byets for wqs */
#define SIZEOF_WAITQUEUE_ELEMENT 16		/* 16 byets per wqe */
#define SIZEOF_WAITQUEUE_LINK 28		/* 28 byets per wqe */

#ifdef MACH_KERNEL_PRIVATE

/*
 *	wait_queue_sub_t
 *	This is the common definition for a subordinate wait queue.
 *	These can be linked as members/elements of multiple regular
 *	wait queues.  They have an additional set of linkages to
 *	identify the linkage structures that point to them.
 *	WARNING: Cannot change this data structure without updating SIZEOF_WAITQUEUE_SUB
 */
typedef struct wait_queue_sub {
	WaitQueue	wqs_wait_queue; /* our wait queue */
	queue_head_t	wqs_sublinks;	/* links from sub perspective */
	unsigned int 	wqs_refcount;	/* refcount for preposting */
} WaitQueueSub;


#define WAIT_QUEUE_SUB_NULL ((wait_queue_sub_t)0)


/*
 *	wait_queue_element_t
 *	This structure describes the elements on an event wait
 *	queue.  It is the common first fields in a thread shuttle
 *	and wait_queue_link_t.  In that way, a wait queue can
 *	consist of both thread shuttle elements and links off of
 *	to other (subordinate) wait queues.
 *
 *	WARNING: The first three fields of the thread shuttle
 *	definition does not use this definition yet.  Any change in
 *	the layout here will have to be matched with a change there.
 *	WARNING: Cannot change this data structure without updating SIZEOF_WAITQUEUE_ELEMENT
 */
typedef struct wait_queue_element {
	queue_chain_t	wqe_links;	/* link of elements on this queue */
	wait_queue_t	wqe_queue;	/* queue this element is on */
	event_t		wqe_event;	/* event this element is waiting for */
} *wait_queue_element_t;


/*
 *	wait_queue_link_t
 *	Specialized wait queue element type for linking subordinate
 *	event waits queues onto a wait queue.  In this way, an event
 *	can be constructed so that any thread waiting on any number
 *	of associated wait queues can handle the event, while letting
 *	the thread only be linked on the single wait queue it blocked on.
 *
 *	One use: ports in multiple portsets.  Each thread is queued up
 *	on the portset that it specifically blocked on during a receive
 *	operation.  Each port's event queue links in all the portset
 *	event queues of which it is a member.  An IPC event post associated
 *	with that port may wake up any thread from any of those portsets,
 *	or one that was waiting locally on the port itself.
 *	WARNING: Cannot change this data structure without updating SIZEOF_WAITQUEUE_LINK
 */
typedef struct wait_queue_link {
	struct wait_queue_element	wql_element;	/* element on master */
	queue_chain_t			wql_sublinks;	/* element on sub */
    wait_queue_sub_t		wql_subqueue;	/* sub queue */
} WaitQueueLink;


#define WAIT_QUEUE_LINK_NULL ((wait_queue_link_t)0)

#define wql_links wql_element.wqe_links
#define wql_queue wql_element.wqe_queue
#define wql_event wql_element.wqe_event

#define wait_queue_empty(wq)	(queue_empty(&(wq)->wq_queue))

#define wait_queue_held(wq)	(hw_lock_held(&(wq)->wq_interlock))

#define wait_queue_is_sub(wqs)	((wqs)->wqs_wait_queue.wq_issub)
#define wqs_lock(wqs)		wait_queue_lock(&(wqs)->wqs_wait_queue)
#define wqs_unlock(wqs)		wait_queue_unlock(&(wqs)->wqs_wait_queue)
#define wqs_lock_try(wqs)	wait_queue__try_lock(&(wqs)->wqs_wait_queue)

extern int wait_queue_subordinate;
#define WAIT_QUEUE_SUBORDINATE &_wait_queue_subordinate

extern void wait_queue_init(
			wait_queue_t wait_queue,
			int policy);

extern kern_return_t wait_queue_link(
			wait_queue_t wait_queue,
			wait_queue_sub_t subordinate_queue);

extern kern_return_t wait_queue_unlink(
		        wait_queue_t wait_queue,
		        wait_queue_sub_t subordinate_queue);
extern void wait_queue_unlink_one(
			wait_queue_t wait_queue,
			wait_queue_sub_t *subordinate_queue_pointer);

extern boolean_t wait_queue_member_queue(
		        wait_queue_t wait_queue,
		        wait_queue_sub_t subordinate_queue);

extern kern_return_t clear_wait_queue_internal(
			thread_t thread,
			int result);

extern kern_return_t wait_queue_remove(
			thread_t thread);

#define wait_queue_assert_possible(thread) \
			((thread)->wait_queue == WAIT_QUEUE_NULL)



/******** Decomposed interfaces (to build higher level constructs) ***********/

extern void wait_queue_lock(
		        wait_queue_t wait_queue);

extern void wait_queue_unlock(
		        wait_queue_t wait_queue);

extern boolean_t wait_queue_lock_try(
			wait_queue_t wait_queue);

/* assert intent to wait on a locked wait queue */
extern boolean_t  wait_queue_assert_wait_locked(
			wait_queue_t wait_queue,
			event_t wait_event,
			int interruptible,
			boolean_t unlock);

/* peek to see which thread would be chosen for a wakeup - but keep on queue */
extern void wait_queue_peek_locked(
			wait_queue_t wait_queue,
			event_t event,
			thread_t *thread,
			wait_queue_t *found_queue);

/* peek to see which thread would be chosen for a wakeup - but keep on queue */
extern void wait_queue_pull_thread_locked(
			wait_queue_t wait_queue,
			thread_t thread,
			boolean_t unlock);

/* wakeup all threads waiting for a particular event on locked queue */
extern kern_return_t  wait_queue_wakeup_one_locked(
			wait_queue_t wait_queue,
			event_t wake_event,
			int result,
			boolean_t unlock);

/* wakeup one thread waiting for a particular event on locked queue */
extern kern_return_t  wait_queue_wakeup_one_locked(
			wait_queue_t wait_queue,
			event_t wake_event,
			int result,
			boolean_t unlock);

/* return the identity of a thread that is waiting for <wait_queue, event> */
extern thread_t wait_queue_recommend_locked(
			wait_queue_t wait_queue,
			event_t wake_event);
			
/* return identity of a thread awakened for a particular <wait_queue,event> */
extern thread_t wait_queue_wakeup_identity_locked(
			wait_queue_t wait_queue,
			event_t wake_event,
			int result,
			boolean_t unlock);

/* wakeup thread iff its still waiting for a particular event on locked queue */
extern kern_return_t wait_queue_wakeup_thread_locked(
			wait_queue_t wait_queue,
			event_t wake_event,
			thread_t thread,
			int result,
			boolean_t unlock);

#endif /* MACH_KERNEL_PRIVATE */

extern wait_queue_t wait_queue_alloc(
		        int policy);

extern void wait_queue_free(
			wait_queue_t wait_queue);

/******** Standalone interfaces (not a part of a higher construct) ************/

/* assert intent to wait on <wait_queue,event> pair */
extern boolean_t wait_queue_assert_wait(
			wait_queue_t wait_queue,
			event_t wait_event,
			int interruptible);

/* wakeup the most appropriate thread waiting on <wait_queue,event> pair */
extern kern_return_t  wait_queue_wakeup_one(
			wait_queue_t wait_queue,
			event_t wake_event,
			int result);

/* wakeup all the threads waiting on <wait_queue,event> pair */
extern kern_return_t  wait_queue_wakeup_all(
			wait_queue_t wait_queue,
			event_t wake_event,
			int result);

/* wakeup a specified thread waiting iff waiting on <wait_queue,event> pair */
extern kern_return_t  wait_queue_wakeup_thread(
			wait_queue_t wait_queue,
			event_t wake_event,
			thread_t thread,
			int result);

#endif /* _KERN_WAIT_QUEUE_H_ */

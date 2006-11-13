/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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

#ifdef	KERNEL_PRIVATE

#ifndef _KERN_WAIT_QUEUE_H_
#define _KERN_WAIT_QUEUE_H_

#include <mach/mach_types.h>
#include <mach/sync_policy.h>
#include <mach/kern_return.h>		/* for kern_return_t */

#include <kern/kern_types.h>		/* for wait_queue_t */

#include <sys/cdefs.h>

#ifdef	MACH_KERNEL_PRIVATE

#include <kern/lock.h>
#include <kern/queue.h>
#include <machine/cpu_number.h>

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
 */
typedef struct wait_queue {
    unsigned int                    /* flags */
    /* boolean_t */	wq_type:16,		/* only public field */
					wq_fifo:1,		/* fifo wakeup policy? */
					wq_isprepost:1,	/* is waitq preposted? set only */
					:0;				/* force to long boundary */
    hw_lock_data_t	wq_interlock;	/* interlock */
    queue_head_t	wq_queue;		/* queue of elements */
} WaitQueue;

/*
 *	wait_queue_set_t
 *	This is the common definition for a set wait queue.
 *	These can be linked as members/elements of multiple regular
 *	wait queues.  They have an additional set of linkages to
 *	identify the linkage structures that point to them.
 */
typedef struct wait_queue_set {
	WaitQueue		wqs_wait_queue; /* our wait queue */
	queue_head_t	wqs_setlinks;	/* links from set perspective */
	unsigned int 	wqs_refcount;	/* refcount for preposting */
} WaitQueueSet;

#define wqs_type		wqs_wait_queue.wq_type
#define wqs_fifo		wqs_wait_queue.wq_fifo
#define wqs_isprepost	wqs_wait_queue.wq_isprepost
#define wqs_queue		wqs_wait_queue.wq_queue

/*
 *	wait_queue_element_t
 *	This structure describes the elements on an event wait
 *	queue.  It is the common first fields in a thread shuttle
 *	and wait_queue_link_t.  In that way, a wait queue can
 *	consist of both thread shuttle elements and links off of
 *	to other (set) wait queues.
 *
 *	WARNING: These fields correspond to fields in the thread
 *	shuttle (run queue links and run queue pointer). Any change in
 *	the layout here will have to be matched with a change there.
 */
typedef struct wait_queue_element {
	queue_chain_t	wqe_links;	/* link of elements on this queue */
	void *			wqe_type;	/* Identifies link vs. thread */
	wait_queue_t	wqe_queue;	/* queue this element is on */
} WaitQueueElement;

typedef WaitQueueElement *wait_queue_element_t;

/*
 *	wait_queue_link_t
 *	Specialized wait queue element type for linking set
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
 */
typedef struct wait_queue_link {
	WaitQueueElement		wql_element;	/* element on master */
	queue_chain_t			wql_setlinks;	/* element on set */
    wait_queue_set_t		wql_setqueue;	/* set queue */
} WaitQueueLink;

#define wql_links wql_element.wqe_links
#define wql_type  wql_element.wqe_type
#define wql_queue wql_element.wqe_queue

#define _WAIT_QUEUE_inited			0xf1d0
#define _WAIT_QUEUE_SET_inited		0xf1d1

#define wait_queue_is_queue(wq)	\
	((wq)->wq_type == _WAIT_QUEUE_inited)

#define wait_queue_is_set(wqs)	\
	((wqs)->wqs_type == _WAIT_QUEUE_SET_inited)

#define wait_queue_is_valid(wq)	\
	(((wq)->wq_type & ~1) == _WAIT_QUEUE_inited)

#define wait_queue_empty(wq)	(queue_empty(&(wq)->wq_queue))
#define wait_queue_held(wq)		(hw_lock_held(&(wq)->wq_interlock))
#define wait_queue_lock_try(wq) (hw_lock_try(&(wq)->wq_interlock))

/*
 * Double the standard lock timeout, because wait queues tend
 * to iterate over a number of threads - locking each.  If there is
 * a problem with a thread lock, it normally times out at the wait
 * queue level first, hiding the real problem.
 */
#define wait_queue_lock(wq)	\
	((void) (!hw_lock_to(&(wq)->wq_interlock, LockTimeOut * 2) ? \
		 panic("wait queue deadlock - wq=0x%x, cpu=%d\n", \
		       wq, cpu_number()) : 0))

#define wait_queue_unlock(wq) \
	(assert(wait_queue_held(wq)), hw_lock_unlock(&(wq)->wq_interlock))

#define wqs_lock(wqs)		wait_queue_lock(&(wqs)->wqs_wait_queue)
#define wqs_unlock(wqs)		wait_queue_unlock(&(wqs)->wqs_wait_queue)
#define wqs_lock_try(wqs)	wait_queue__try_lock(&(wqs)->wqs_wait_queue)

#define wait_queue_assert_possible(thread) \
			((thread)->wait_queue == WAIT_QUEUE_NULL)

/******** Decomposed interfaces (to build higher level constructs) ***********/

/* assert intent to wait on a locked wait queue */
__private_extern__ wait_result_t wait_queue_assert_wait64_locked(
			wait_queue_t wait_queue,
			event64_t wait_event,
			wait_interrupt_t interruptible,
			uint64_t deadline,
			thread_t thread);

/* peek to see which thread would be chosen for a wakeup - but keep on queue */
__private_extern__ void wait_queue_peek64_locked(
			wait_queue_t wait_queue,
			event64_t event,
			thread_t *thread,
			wait_queue_t *found_queue);

/* peek to see which thread would be chosen for a wakeup - but keep on queue */
__private_extern__ void wait_queue_pull_thread_locked(
			wait_queue_t wait_queue,
			thread_t thread,
			boolean_t unlock);

/* wakeup all threads waiting for a particular event on locked queue */
__private_extern__ kern_return_t wait_queue_wakeup64_all_locked(
			wait_queue_t wait_queue,
			event64_t wake_event,
			wait_result_t result,
			boolean_t unlock);

/* wakeup one thread waiting for a particular event on locked queue */
__private_extern__ kern_return_t wait_queue_wakeup64_one_locked(
			wait_queue_t wait_queue,
			event64_t wake_event,
			wait_result_t result,
			boolean_t unlock);

/* return identity of a thread awakened for a particular <wait_queue,event> */
__private_extern__ thread_t wait_queue_wakeup64_identity_locked(
			wait_queue_t wait_queue,
			event64_t wake_event,
			wait_result_t result,
			boolean_t unlock);

/* wakeup thread iff its still waiting for a particular event on locked queue */
__private_extern__ kern_return_t wait_queue_wakeup64_thread_locked(
			wait_queue_t wait_queue,
			event64_t wake_event,
			thread_t thread,
			wait_result_t result,
			boolean_t unlock);

#endif	/* MACH_KERNEL_PRIVATE */

__BEGIN_DECLS

/******** Semi-Public interfaces (not a part of a higher construct) ************/

extern unsigned int wait_queue_set_size(void);
extern unsigned int wait_queue_link_size(void);

extern kern_return_t wait_queue_init(
			wait_queue_t wait_queue,
			int policy);

extern wait_queue_set_t wait_queue_set_alloc(
			int policy);

extern kern_return_t wait_queue_set_init(
			wait_queue_set_t set_queue,
			int policy);

extern kern_return_t wait_queue_set_free(
			wait_queue_set_t set_queue);

extern wait_queue_link_t wait_queue_link_alloc(
			int policy);

extern kern_return_t wait_queue_link_free(
			wait_queue_link_t link_element);

extern kern_return_t wait_queue_link(
			wait_queue_t wait_queue,
			wait_queue_set_t set_queue);

extern kern_return_t wait_queue_link_noalloc(
			wait_queue_t wait_queue,
			wait_queue_set_t set_queue,
			wait_queue_link_t link);

extern boolean_t wait_queue_member(
			wait_queue_t wait_queue,
			wait_queue_set_t set_queue);

extern kern_return_t wait_queue_unlink(
			wait_queue_t wait_queue,
			wait_queue_set_t set_queue);

extern kern_return_t wait_queue_unlink_all(
			wait_queue_t wait_queue);

extern kern_return_t wait_queue_unlinkall_nofree(
			wait_queue_t wait_queue);

extern kern_return_t wait_queue_set_unlink_all(
			wait_queue_set_t set_queue);

/* legacy API */
kern_return_t wait_queue_sub_init(
			wait_queue_set_t set_queue,
			int policy);

kern_return_t wait_queue_sub_clearrefs(
			wait_queue_set_t wq_set);

extern kern_return_t wait_subqueue_unlink_all(
			wait_queue_set_t set_queue);

extern wait_queue_t wait_queue_alloc(
			int policy);

extern kern_return_t wait_queue_free(
			wait_queue_t wait_queue);

/* assert intent to wait on <wait_queue,event64> pair */
extern wait_result_t wait_queue_assert_wait64(
			wait_queue_t wait_queue,
			event64_t wait_event,
			wait_interrupt_t interruptible,
			uint64_t deadline);

/* wakeup the most appropriate thread waiting on <wait_queue,event64> pair */
extern kern_return_t wait_queue_wakeup64_one(
			wait_queue_t wait_queue,
			event64_t wake_event,
			wait_result_t result);

/* wakeup all the threads waiting on <wait_queue,event64> pair */
extern kern_return_t wait_queue_wakeup64_all(
			wait_queue_t wait_queue,
			event64_t wake_event,
			wait_result_t result);

/* wakeup a specified thread waiting iff waiting on <wait_queue,event64> pair */
extern kern_return_t wait_queue_wakeup64_thread(
			wait_queue_t wait_queue,
			event64_t wake_event,
			thread_t thread,
			wait_result_t result);

/*
 * Compatibility Wait Queue APIs based on pointer events instead of 64bit
 * integer events.
 */

/* assert intent to wait on <wait_queue,event> pair */
extern wait_result_t wait_queue_assert_wait(
			wait_queue_t wait_queue,
			event_t wait_event,
			wait_interrupt_t interruptible,
			uint64_t deadline);

/* wakeup the most appropriate thread waiting on <wait_queue,event> pair */
extern kern_return_t wait_queue_wakeup_one(
			wait_queue_t wait_queue,
			event_t wake_event,
			wait_result_t result);

/* wakeup all the threads waiting on <wait_queue,event> pair */
extern kern_return_t wait_queue_wakeup_all(
			wait_queue_t wait_queue,
			event_t wake_event,
			wait_result_t result);

/* wakeup a specified thread waiting iff waiting on <wait_queue,event> pair */
extern kern_return_t wait_queue_wakeup_thread(
			wait_queue_t wait_queue,
			event_t wake_event,
			thread_t thread,
			wait_result_t result);

__END_DECLS

#endif	/* _KERN_WAIT_QUEUE_H_ */

#endif	/* KERNEL_PRIVATE */

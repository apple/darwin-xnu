/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
 * @OSF_FREE_COPYRIGHT@
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
 *	File:	wait_queue.c (adapted from sched_prim.c)
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1986
 *
 *	Primitives for manipulating wait queues: either global
 *	ones from sched_prim.c, or private ones associated with
 *	particular structures(pots, semaphores, etc..).
 */

#include <kern/kern_types.h>
#include <kern/simple_lock.h>
#include <kern/zalloc.h>
#include <kern/queue.h>
#include <kern/spl.h>
#include <mach/sync_policy.h>
#include <kern/mach_param.h>
#include <kern/sched_prim.h>

#include <kern/wait_queue.h>
#include <vm/vm_kern.h>

/* forward declarations */
static boolean_t wait_queue_member_locked(
			wait_queue_t		wq,
			wait_queue_set_t	wq_set);

static void wait_queues_init(void) __attribute__((section("__TEXT, initcode")));


#define WAIT_QUEUE_MAX thread_max
#define WAIT_QUEUE_SET_MAX task_max * 3
#define WAIT_QUEUE_LINK_MAX PORT_MAX / 2 + (WAIT_QUEUE_MAX * WAIT_QUEUE_SET_MAX) / 64

static zone_t _wait_queue_link_zone;
static zone_t _wait_queue_set_zone;
static zone_t _wait_queue_zone;

/* see rdar://6737748&5561610; we need an unshadowed
 * definition of a WaitQueueLink for debugging,
 * but it needs to be used somewhere to wind up in
 * the dSYM file. */
volatile WaitQueueLink *unused_except_for_debugging;


/*
 *	Waiting protocols and implementation:
 *
 *	Each thread may be waiting for exactly one event; this event
 *	is set using assert_wait().  That thread may be awakened either
 *	by performing a thread_wakeup_prim() on its event,
 *	or by directly waking that thread up with clear_wait().
 *
 *	The implementation of wait events uses a hash table.  Each
 *	bucket is queue of threads having the same hash function
 *	value; the chain for the queue (linked list) is the run queue
 *	field.  [It is not possible to be waiting and runnable at the
 *	same time.]
 *
 *	Locks on both the thread and on the hash buckets govern the
 *	wait event field and the queue chain field.  Because wakeup
 *	operations only have the event as an argument, the event hash
 *	bucket must be locked before any thread.
 *
 *	Scheduling operations may also occur at interrupt level; therefore,
 *	interrupts below splsched() must be prevented when holding
 *	thread or hash bucket locks.
 *
 *	The wait event hash table declarations are as follows:
 */

struct wait_queue boot_wait_queue[1];
__private_extern__ struct wait_queue *wait_queues = &boot_wait_queue[0];

__private_extern__ uint32_t num_wait_queues = 1;

static uint32_t
compute_wait_hash_size(__unused unsigned cpu_count, __unused uint64_t memsize) {
	uint32_t hsize = (uint32_t)round_page_64((thread_max / 11) * sizeof(struct wait_queue));
	uint32_t bhsize;
	
	if (PE_parse_boot_argn("wqsize", &bhsize, sizeof(bhsize)))
		hsize = bhsize;

	return hsize;
}

static void
wait_queues_init(void)
{
	uint32_t	i, whsize;
	kern_return_t	kret;

	whsize = compute_wait_hash_size(processor_avail_count, machine_info.max_mem);
	num_wait_queues = (whsize / ((uint32_t)sizeof(struct wait_queue))) - 1;

	kret = kernel_memory_allocate(kernel_map, (vm_offset_t *) &wait_queues, whsize, 0, KMA_KOBJECT|KMA_NOPAGEWAIT);

	if (kret != KERN_SUCCESS || wait_queues == NULL)
		panic("kernel_memory_allocate() failed to allocate wait queues, error: %d, whsize: 0x%x", kret, whsize);

	for (i = 0; i < num_wait_queues; i++) {
		wait_queue_init(&wait_queues[i], SYNC_POLICY_FIFO);
	}
}

void
wait_queue_bootstrap(void)
{
	wait_queues_init();
	_wait_queue_zone = zinit(sizeof(struct wait_queue),
				      WAIT_QUEUE_MAX * sizeof(struct wait_queue),
				      sizeof(struct wait_queue),
				      "wait queues");
	zone_change(_wait_queue_zone, Z_NOENCRYPT, TRUE);

	_wait_queue_set_zone = zinit(sizeof(struct wait_queue_set),
				      WAIT_QUEUE_SET_MAX * sizeof(struct wait_queue_set),
				      sizeof(struct wait_queue_set),
				      "wait queue sets");
	zone_change(_wait_queue_set_zone, Z_NOENCRYPT, TRUE);

	_wait_queue_link_zone = zinit(sizeof(struct _wait_queue_link),
				      WAIT_QUEUE_LINK_MAX * sizeof(struct _wait_queue_link),
				      sizeof(struct _wait_queue_link),
				      "wait queue links");
	zone_change(_wait_queue_link_zone, Z_NOENCRYPT, TRUE);
}

/*
 *	Routine:        wait_queue_init
 *	Purpose:
 *		Initialize a previously allocated wait queue.
 *	Returns:
 *		KERN_SUCCESS - The wait_queue_t was initialized
 *		KERN_INVALID_ARGUMENT - The policy parameter was invalid
 */
kern_return_t
wait_queue_init(
	wait_queue_t wq,
	int policy)
{
	/* only FIFO and LIFO for now */
	if ((policy & SYNC_POLICY_FIXED_PRIORITY) != 0)
		return KERN_INVALID_ARGUMENT;

	wq->wq_fifo = ((policy & SYNC_POLICY_REVERSED) == 0);
	wq->wq_type = _WAIT_QUEUE_inited;
	queue_init(&wq->wq_queue);
	hw_lock_init(&wq->wq_interlock);
	return KERN_SUCCESS;
}

/*
 *	Routine:		   wait_queue_alloc
 *	Purpose:
 *		Allocate and initialize a wait queue for use outside of
 *		of the mach part of the kernel.
 *	Conditions:
 *		Nothing locked - can block.
 *	Returns:
 *		The allocated and initialized wait queue
 *		WAIT_QUEUE_NULL if there is a resource shortage
 */
wait_queue_t
wait_queue_alloc(
	int policy)
{
	wait_queue_t wq;
	kern_return_t ret;

	wq = (wait_queue_t) zalloc(_wait_queue_zone);
	if (wq != WAIT_QUEUE_NULL) {
		ret = wait_queue_init(wq, policy);
		if (ret != KERN_SUCCESS) {
			zfree(_wait_queue_zone, wq);
			wq = WAIT_QUEUE_NULL;
		}
	}
	return wq;
}

/*
 *	Routine:        wait_queue_free
 *	Purpose:
 *		Free an allocated wait queue.
 *	Conditions:
 *		May block.
 */
kern_return_t
wait_queue_free(
	wait_queue_t wq)
{
	if (!wait_queue_is_queue(wq))
		return KERN_INVALID_ARGUMENT;
	if (!queue_empty(&wq->wq_queue))
		return KERN_FAILURE;
	zfree(_wait_queue_zone, wq);
	return KERN_SUCCESS;
}

/*
 *	Routine:        wait_queue_set_init
 *	Purpose:
 *		Initialize a previously allocated wait queue set.
 *	Returns:
 *		KERN_SUCCESS - The wait_queue_set_t was initialized
 *		KERN_INVALID_ARGUMENT - The policy parameter was invalid
 */
kern_return_t
wait_queue_set_init(
	wait_queue_set_t wqset,
	int policy)
{
	kern_return_t ret;

	ret = wait_queue_init(&wqset->wqs_wait_queue, policy);
	if (ret != KERN_SUCCESS)
		return ret;

	wqset->wqs_wait_queue.wq_type = _WAIT_QUEUE_SET_inited;
	if (policy & SYNC_POLICY_PREPOST)
		wqset->wqs_wait_queue.wq_prepost = TRUE;
	else 
		wqset->wqs_wait_queue.wq_prepost = FALSE;
	queue_init(&wqset->wqs_setlinks);
	queue_init(&wqset->wqs_preposts);
	return KERN_SUCCESS;
}


kern_return_t
wait_queue_sub_init(
	wait_queue_set_t wqset,
	int policy)
{
	return wait_queue_set_init(wqset, policy);
}

kern_return_t
wait_queue_sub_clearrefs(
        wait_queue_set_t wq_set)
{
	wait_queue_link_t wql;
	queue_t q;
	spl_t s;

	if (!wait_queue_is_set(wq_set))
		return KERN_INVALID_ARGUMENT;

	s = splsched();
	wqs_lock(wq_set);
	q = &wq_set->wqs_preposts;
	while (!queue_empty(q)) {
		queue_remove_first(q, wql, wait_queue_link_t, wql_preposts);
		assert(!wql_is_preposted(wql));
	}
	wqs_unlock(wq_set);
	splx(s);
	return KERN_SUCCESS;
}

/*
 *	Routine:        wait_queue_set_alloc
 *	Purpose:
 *		Allocate and initialize a wait queue set for
 *		use outside of the mach part of the kernel.
 *	Conditions:
 *		May block.
 *	Returns:
 *		The allocated and initialized wait queue set
 *		WAIT_QUEUE_SET_NULL if there is a resource shortage
 */
wait_queue_set_t
wait_queue_set_alloc(
    int policy)
{
	wait_queue_set_t wq_set;

	wq_set = (wait_queue_set_t) zalloc(_wait_queue_set_zone);
	if (wq_set != WAIT_QUEUE_SET_NULL) {
		kern_return_t ret;

		ret = wait_queue_set_init(wq_set, policy);
		if (ret != KERN_SUCCESS) {
			zfree(_wait_queue_set_zone, wq_set);
			wq_set = WAIT_QUEUE_SET_NULL;
		}
	}
	return wq_set;
}

/*
 *     Routine:        wait_queue_set_free
 *     Purpose:
 *             Free an allocated wait queue set
 *     Conditions:
 *             May block.
 */
kern_return_t
wait_queue_set_free(
	wait_queue_set_t wq_set)
{
	if (!wait_queue_is_set(wq_set))
		return KERN_INVALID_ARGUMENT;

	if (!queue_empty(&wq_set->wqs_wait_queue.wq_queue))
		return KERN_FAILURE;

	zfree(_wait_queue_set_zone, wq_set);
	return KERN_SUCCESS;
}


/*
 *	
 *     Routine:        wait_queue_set_size
 *     Routine:        wait_queue_link_size
 *     Purpose:
 *             Return the size of opaque wait queue structures
 */
unsigned int wait_queue_set_size(void) { return sizeof(WaitQueueSet); }
unsigned int wait_queue_link_size(void) { return sizeof(WaitQueueLink); }

/* declare a unique type for wait queue link structures */
static unsigned int _wait_queue_link;
static unsigned int _wait_queue_link_noalloc;
static unsigned int _wait_queue_unlinked;

#define WAIT_QUEUE_LINK ((void *)&_wait_queue_link)
#define WAIT_QUEUE_LINK_NOALLOC ((void *)&_wait_queue_link_noalloc)
#define WAIT_QUEUE_UNLINKED ((void *)&_wait_queue_unlinked)

#define WAIT_QUEUE_ELEMENT_CHECK(wq, wqe) \
	WQASSERT(((wqe)->wqe_queue == (wq) && \
	  queue_next(queue_prev((queue_t) (wqe))) == (queue_t)(wqe)), \
	  "wait queue element list corruption: wq=%#x, wqe=%#x", \
	  (wq), (wqe))

#define WQSPREV(wqs, wql) ((wait_queue_link_t)queue_prev( \
			((&(wqs)->wqs_setlinks == (queue_t)(wql)) ? \
			(queue_t)(wql) : &(wql)->wql_setlinks)))

#define WQSNEXT(wqs, wql) ((wait_queue_link_t)queue_next( \
			((&(wqs)->wqs_setlinks == (queue_t)(wql)) ? \
			(queue_t)(wql) : &(wql)->wql_setlinks)))

#define WAIT_QUEUE_SET_LINK_CHECK(wqs, wql) \
		WQASSERT(((((wql)->wql_type == WAIT_QUEUE_LINK) || \
			   ((wql)->wql_type == WAIT_QUEUE_LINK_NOALLOC)) && \
			((wql)->wql_setqueue == (wqs)) && \
			(((wql)->wql_queue->wq_type == _WAIT_QUEUE_inited) || \
			 ((wql)->wql_queue->wq_type == _WAIT_QUEUE_SET_inited)) && \
			(WQSNEXT((wqs), WQSPREV((wqs),(wql))) == (wql))), \
			"wait queue set links corruption: wqs=%#x, wql=%#x", \
			 (wqs), (wql))

#if defined(_WAIT_QUEUE_DEBUG_)

#define WQASSERT(e, s, p0, p1) ((e) ? 0 : panic(s, p0, p1))

#define WAIT_QUEUE_CHECK(wq) \
MACRO_BEGIN \
	queue_t q2 = &(wq)->wq_queue; \
	wait_queue_element_t wqe2 = (wait_queue_element_t) queue_first(q2); \
	while (!queue_end(q2, (queue_entry_t)wqe2)) { \
		WAIT_QUEUE_ELEMENT_CHECK((wq), wqe2); \
		wqe2 = (wait_queue_element_t) queue_next((queue_t) wqe2); \
	} \
MACRO_END

#define WAIT_QUEUE_SET_CHECK(wqs) \
MACRO_BEGIN \
	queue_t q2 = &(wqs)->wqs_setlinks; \
	wait_queue_link_t wql2 = (wait_queue_link_t) queue_first(q2); \
	while (!queue_end(q2, (queue_entry_t)wql2)) { \
		WAIT_QUEUE_SET_LINK_CHECK((wqs), wql2); \
		wql2 = (wait_queue_link_t) wql2->wql_setlinks.next; \
	} \
MACRO_END

#else /* !_WAIT_QUEUE_DEBUG_ */

#define WQASSERT(e, s, p0, p1) assert(e)

#define WAIT_QUEUE_CHECK(wq)
#define WAIT_QUEUE_SET_CHECK(wqs)

#endif /* !_WAIT_QUEUE_DEBUG_ */

/*
 *	Routine:	wait_queue_member_locked
 *	Purpose:
 *		Indicate if this set queue is a member of the queue
 *	Conditions:
 *		The wait queue is locked
 *		The set queue is just that, a set queue
 */
static boolean_t
wait_queue_member_locked(
	wait_queue_t wq,
	wait_queue_set_t wq_set)
{
	wait_queue_element_t wq_element;
	queue_t q;

	assert(wait_queue_held(wq));
	assert(wait_queue_is_set(wq_set));

	q = &wq->wq_queue;

	wq_element = (wait_queue_element_t) queue_first(q);
	while (!queue_end(q, (queue_entry_t)wq_element)) {
		WAIT_QUEUE_ELEMENT_CHECK(wq, wq_element);
		if ((wq_element->wqe_type == WAIT_QUEUE_LINK) ||
		    (wq_element->wqe_type == WAIT_QUEUE_LINK_NOALLOC)) {
			wait_queue_link_t wql = (wait_queue_link_t)wq_element;

			if (wql->wql_setqueue == wq_set)
				return TRUE;
		}
		wq_element = (wait_queue_element_t)
			     queue_next((queue_t) wq_element);
	}
	return FALSE;
}
	

/*
 *	Routine:	wait_queue_member
 *	Purpose:
 *		Indicate if this set queue is a member of the queue
 *	Conditions:
 *		The set queue is just that, a set queue
 */
boolean_t
wait_queue_member(
	wait_queue_t wq,
	wait_queue_set_t wq_set)
{
	boolean_t ret;
	spl_t s;

	if (!wait_queue_is_set(wq_set))
		return FALSE;

	s = splsched();
	wait_queue_lock(wq);
	ret = wait_queue_member_locked(wq, wq_set);
	wait_queue_unlock(wq);
	splx(s);

	return ret;
}


/*
 *	Routine:	wait_queue_link_internal
 *	Purpose:
 *		Insert a set wait queue into a wait queue.  This
 *		requires us to link the two together using a wait_queue_link
 *		structure that was provided.
 *	Conditions:
 *		The wait queue being inserted must be inited as a set queue
 *		The wait_queue_link structure must already be properly typed
 */
static 
kern_return_t
wait_queue_link_internal(
	wait_queue_t wq,
	wait_queue_set_t wq_set,
	wait_queue_link_t wql)
{
	wait_queue_element_t wq_element;
	queue_t q;
	spl_t s;

	if (!wait_queue_is_valid(wq) || !wait_queue_is_set(wq_set))
  		return KERN_INVALID_ARGUMENT;

	/*
	 * There are probably fewer threads and sets associated with
	 * the wait queue than there are wait queues associated with
	 * the set.  So let's validate it that way.
	 */
	s = splsched();
	wait_queue_lock(wq);
	q = &wq->wq_queue;
	wq_element = (wait_queue_element_t) queue_first(q);
	while (!queue_end(q, (queue_entry_t)wq_element)) {
		WAIT_QUEUE_ELEMENT_CHECK(wq, wq_element);
		if ((wq_element->wqe_type == WAIT_QUEUE_LINK ||
		     wq_element->wqe_type == WAIT_QUEUE_LINK_NOALLOC) &&
		    ((wait_queue_link_t)wq_element)->wql_setqueue == wq_set) {
			wait_queue_unlock(wq);
			splx(s);
			return KERN_ALREADY_IN_SET;
		}
		wq_element = (wait_queue_element_t)
				queue_next((queue_t) wq_element);
	}

	/*
	 * Not already a member, so we can add it.
	 */
	wqs_lock(wq_set);

	WAIT_QUEUE_SET_CHECK(wq_set);

	assert(wql->wql_type == WAIT_QUEUE_LINK ||
	       wql->wql_type == WAIT_QUEUE_LINK_NOALLOC);

	wql->wql_queue = wq;
	wql_clear_prepost(wql);
	queue_enter(&wq->wq_queue, wql, wait_queue_link_t, wql_links);
	wql->wql_setqueue = wq_set;
	queue_enter(&wq_set->wqs_setlinks, wql, wait_queue_link_t, wql_setlinks);

	wqs_unlock(wq_set);
	wait_queue_unlock(wq);
	splx(s);

	return KERN_SUCCESS;
}	

/*
 *	Routine:	wait_queue_link_noalloc
 *	Purpose:
 *		Insert a set wait queue into a wait queue.  This
 *		requires us to link the two together using a wait_queue_link
 *		structure that we allocate.
 *	Conditions:
 *		The wait queue being inserted must be inited as a set queue
 */
kern_return_t
wait_queue_link_noalloc(
	wait_queue_t wq,
	wait_queue_set_t wq_set,
	wait_queue_link_t wql)
{
	wql->wql_type = WAIT_QUEUE_LINK_NOALLOC;
	return wait_queue_link_internal(wq, wq_set, wql);
}

/*
 *	Routine:	wait_queue_link
 *	Purpose:
 *		Insert a set wait queue into a wait queue.  This
 *		requires us to link the two together using a wait_queue_link
 *		structure that we allocate.
 *	Conditions:
 *		The wait queue being inserted must be inited as a set queue
 */
kern_return_t
wait_queue_link(
	wait_queue_t wq,
	wait_queue_set_t wq_set)
{
	wait_queue_link_t wql;
	kern_return_t ret;

	wql = (wait_queue_link_t) zalloc(_wait_queue_link_zone);
	if (wql == WAIT_QUEUE_LINK_NULL)
		return KERN_RESOURCE_SHORTAGE;

	wql->wql_type = WAIT_QUEUE_LINK;
	ret = wait_queue_link_internal(wq, wq_set, wql);
	if (ret != KERN_SUCCESS)
		zfree(_wait_queue_link_zone, wql);

	return ret;
}	


/*
 *	Routine:	wait_queue_unlink_locked
 *	Purpose:
 *		Undo the linkage between a wait queue and a set.
 */
static void
wait_queue_unlink_locked(
	wait_queue_t wq,
	wait_queue_set_t wq_set,
	wait_queue_link_t wql)
{
	assert(wait_queue_held(wq));
	assert(wait_queue_held(&wq_set->wqs_wait_queue));

	wql->wql_queue = WAIT_QUEUE_NULL;
	queue_remove(&wq->wq_queue, wql, wait_queue_link_t, wql_links);
	wql->wql_setqueue = WAIT_QUEUE_SET_NULL;
	queue_remove(&wq_set->wqs_setlinks, wql, wait_queue_link_t, wql_setlinks);
	if (wql_is_preposted(wql)) {
		queue_t ppq = &wq_set->wqs_preposts;
		queue_remove(ppq, wql, wait_queue_link_t, wql_preposts);
	}
	wql->wql_type = WAIT_QUEUE_UNLINKED;

	WAIT_QUEUE_CHECK(wq);
	WAIT_QUEUE_SET_CHECK(wq_set);
}

/*
 *	Routine:	wait_queue_unlink
 *	Purpose:
 *		Remove the linkage between a wait queue and a set,
 *		freeing the linkage structure.
 *	Conditions:
 *		The wait queue being must be a member set queue
 */
kern_return_t
wait_queue_unlink(
	wait_queue_t wq,
	wait_queue_set_t wq_set)
{
	wait_queue_element_t wq_element;
	wait_queue_link_t wql;
	queue_t q;
	spl_t s;

	if (!wait_queue_is_valid(wq) || !wait_queue_is_set(wq_set)) {
		return KERN_INVALID_ARGUMENT;
	}
	s = splsched();
	wait_queue_lock(wq);

	q = &wq->wq_queue;
	wq_element = (wait_queue_element_t) queue_first(q);
	while (!queue_end(q, (queue_entry_t)wq_element)) {
		WAIT_QUEUE_ELEMENT_CHECK(wq, wq_element);
		if (wq_element->wqe_type == WAIT_QUEUE_LINK ||
		    wq_element->wqe_type == WAIT_QUEUE_LINK_NOALLOC) {

		   	wql = (wait_queue_link_t)wq_element;
			
			if (wql->wql_setqueue == wq_set) {
				boolean_t alloced;

				alloced = (wql->wql_type == WAIT_QUEUE_LINK);
				wqs_lock(wq_set);
				wait_queue_unlink_locked(wq, wq_set, wql);
				wqs_unlock(wq_set);
				wait_queue_unlock(wq);
				splx(s);
				if (alloced)
					zfree(_wait_queue_link_zone, wql);
				return KERN_SUCCESS;
			}
		}
		wq_element = (wait_queue_element_t)
				queue_next((queue_t) wq_element);
	}
	wait_queue_unlock(wq);
	splx(s);
	return KERN_NOT_IN_SET;
}	

/*
 *	Routine:	wait_queue_unlink_all
 *	Purpose:
 *		Remove the linkage between a wait queue and all its sets.
 *		All the linkage structures that were allocated internally
 *		are freed.  The others are the caller's responsibility.
 *	Conditions:
 *		Nothing of interest locked.
 */

kern_return_t
wait_queue_unlink_all(
	wait_queue_t wq)
{
	wait_queue_element_t wq_element;
	wait_queue_element_t wq_next_element;
	wait_queue_set_t wq_set;
	wait_queue_link_t wql;
	queue_head_t links_queue_head;
	queue_t links = &links_queue_head;
	queue_t q;
	spl_t s;

	if (!wait_queue_is_valid(wq)) {
		return KERN_INVALID_ARGUMENT;
	}

	queue_init(links);

	s = splsched();
	wait_queue_lock(wq);

	q = &wq->wq_queue;

	wq_element = (wait_queue_element_t) queue_first(q);
	while (!queue_end(q, (queue_entry_t)wq_element)) {
		boolean_t alloced;

		WAIT_QUEUE_ELEMENT_CHECK(wq, wq_element);
		wq_next_element = (wait_queue_element_t)
			     queue_next((queue_t) wq_element);

		alloced = (wq_element->wqe_type == WAIT_QUEUE_LINK);
		if (alloced || wq_element->wqe_type == WAIT_QUEUE_LINK_NOALLOC) {
			wql = (wait_queue_link_t)wq_element;
			wq_set = wql->wql_setqueue;
			wqs_lock(wq_set);
			wait_queue_unlink_locked(wq, wq_set, wql);
			wqs_unlock(wq_set);
			if (alloced)
				enqueue(links, &wql->wql_links);
		}
		wq_element = wq_next_element;
	}
	wait_queue_unlock(wq);
	splx(s);

	while(!queue_empty(links)) {
		wql = (wait_queue_link_t) dequeue(links);
		zfree(_wait_queue_link_zone, wql);
	}

	return(KERN_SUCCESS);
}	

/* legacy interface naming */
kern_return_t
wait_subqueue_unlink_all(
	wait_queue_set_t	wq_set)
{
	return wait_queue_set_unlink_all(wq_set);
}


/*
 *	Routine:	wait_queue_set_unlink_all
 *	Purpose:
 *		Remove the linkage between a set wait queue and all its
 *		member wait queues. The link structures are freed for those
 *		links which were dynamically allocated.
 *	Conditions:
 *		The wait queue must be a set
 */
kern_return_t
wait_queue_set_unlink_all(
	wait_queue_set_t wq_set)
{
	wait_queue_link_t wql;
	wait_queue_t wq;
	queue_t q;
	queue_head_t links_queue_head;
	queue_t links = &links_queue_head;
	spl_t s;

	if (!wait_queue_is_set(wq_set)) {
		return KERN_INVALID_ARGUMENT;
	}

	queue_init(links);

retry:
	s = splsched();
	wqs_lock(wq_set);

	q = &wq_set->wqs_setlinks;

	wql = (wait_queue_link_t)queue_first(q);
	while (!queue_end(q, (queue_entry_t)wql)) {
		WAIT_QUEUE_SET_LINK_CHECK(wq_set, wql);
		wq = wql->wql_queue;
		if (wait_queue_lock_try(wq)) {
			boolean_t alloced;

			alloced = (wql->wql_type == WAIT_QUEUE_LINK);
			wait_queue_unlink_locked(wq, wq_set, wql);
			wait_queue_unlock(wq);
			if (alloced)
				enqueue(links, &wql->wql_links);
			wql = (wait_queue_link_t)queue_first(q);
		} else {
			wqs_unlock(wq_set);
			splx(s);
			delay(1);
			goto retry;
		}
	}
	wqs_unlock(wq_set);
	splx(s);

	while (!queue_empty (links)) {
		wql = (wait_queue_link_t) dequeue(links);
		zfree(_wait_queue_link_zone, wql);
	}
	return(KERN_SUCCESS);
}	

/*
 *	Routine:	wait_queue_assert_wait64_locked
 *	Purpose:
 *		Insert the current thread into the supplied wait queue
 *		waiting for a particular event to be posted to that queue.
 *
 *	Conditions:
 *		The wait queue is assumed locked.
 *		The waiting thread is assumed locked.
 *
 */
__private_extern__ wait_result_t
wait_queue_assert_wait64_locked(
	wait_queue_t wq,
	event64_t event,
	wait_interrupt_t interruptible,
	uint64_t deadline,
	thread_t thread)
{
	wait_result_t wait_result;

	if (!wait_queue_assert_possible(thread))
		panic("wait_queue_assert_wait64_locked");

	if (wq->wq_type == _WAIT_QUEUE_SET_inited) {
		wait_queue_set_t wqs = (wait_queue_set_t)wq;

		if (event == NO_EVENT64 && wqs_is_preposted(wqs))
			return(THREAD_AWAKENED);
	}
	  
	/*
	 * This is the extent to which we currently take scheduling attributes
	 * into account.  If the thread is vm priviledged, we stick it at
	 * the front of the queue.  Later, these queues will honor the policy
	 * value set at wait_queue_init time.
	 */
	wait_result = thread_mark_wait_locked(thread, interruptible);
	if (wait_result == THREAD_WAITING) {
		if (!wq->wq_fifo || thread->options & TH_OPT_VMPRIV)
			enqueue_head(&wq->wq_queue, (queue_entry_t) thread);
		else
			enqueue_tail(&wq->wq_queue, (queue_entry_t) thread);

		thread->wait_event = event;
		thread->wait_queue = wq;

		if (deadline != 0) {
			if (!timer_call_enter(&thread->wait_timer, deadline))
				thread->wait_timer_active++;
			thread->wait_timer_is_set = TRUE;
		}
	}
	return(wait_result);
}

/*
 *	Routine:	wait_queue_assert_wait
 *	Purpose:
 *		Insert the current thread into the supplied wait queue
 *		waiting for a particular event to be posted to that queue.
 *
 *	Conditions:
 *		nothing of interest locked.
 */
wait_result_t
wait_queue_assert_wait(
	wait_queue_t wq,
	event_t event,
	wait_interrupt_t interruptible,
	uint64_t deadline)
{
	spl_t s;
	wait_result_t ret;
	thread_t thread = current_thread();

	/* If it is an invalid wait queue, you can't wait on it */
	if (!wait_queue_is_valid(wq))
		return (thread->wait_result = THREAD_RESTART);

	s = splsched();
	wait_queue_lock(wq);
	thread_lock(thread);
	ret = wait_queue_assert_wait64_locked(wq, CAST_DOWN(event64_t,event),
											interruptible, deadline, thread);
	thread_unlock(thread);
	wait_queue_unlock(wq);
	splx(s);
	return(ret);
}

/*
 *	Routine:	wait_queue_assert_wait64
 *	Purpose:
 *		Insert the current thread into the supplied wait queue
 *		waiting for a particular event to be posted to that queue.
 *	Conditions:
 *		nothing of interest locked.
 */
wait_result_t
wait_queue_assert_wait64(
	wait_queue_t wq,
	event64_t event,
	wait_interrupt_t interruptible,
	uint64_t deadline)
{
	spl_t s;
	wait_result_t ret;
	thread_t thread = current_thread();

	/* If it is an invalid wait queue, you cant wait on it */
	if (!wait_queue_is_valid(wq))
		return (thread->wait_result = THREAD_RESTART);

	s = splsched();
	wait_queue_lock(wq);
	thread_lock(thread);
	ret = wait_queue_assert_wait64_locked(wq, event, interruptible, deadline, thread);
	thread_unlock(thread);
	wait_queue_unlock(wq);
	splx(s);
	return(ret);
}

/*
 *	Routine:	_wait_queue_select64_all
 *	Purpose:
 *		Select all threads off a wait queue that meet the
 *		supplied criteria.
 *	Conditions:
 *		at splsched
 *		wait queue locked
 *		wake_queue initialized and ready for insertion
 *		possibly recursive
 *	Returns:
 *		a queue of locked threads
 */
static void
_wait_queue_select64_all(
	wait_queue_t wq,
	event64_t event,
	queue_t wake_queue)
{
	wait_queue_element_t wq_element;
	wait_queue_element_t wqe_next;
	queue_t q;

	q = &wq->wq_queue;

	wq_element = (wait_queue_element_t) queue_first(q);
	while (!queue_end(q, (queue_entry_t)wq_element)) {
		WAIT_QUEUE_ELEMENT_CHECK(wq, wq_element);
		wqe_next = (wait_queue_element_t)
			   queue_next((queue_t) wq_element);

		/*
		 * We may have to recurse if this is a compound wait queue.
		 */
		if (wq_element->wqe_type == WAIT_QUEUE_LINK ||
		    wq_element->wqe_type == WAIT_QUEUE_LINK_NOALLOC) {
			wait_queue_link_t wql = (wait_queue_link_t)wq_element;
			wait_queue_set_t set_queue = wql->wql_setqueue;

			/*
			 * We have to check the set wait queue. If it is marked
			 * as pre-post, and it is the "generic event" then mark
			 * it pre-posted now (if not already).
			 */
			wqs_lock(set_queue);
			if (event == NO_EVENT64 && set_queue->wqs_prepost && !wql_is_preposted(wql)) {
				queue_t ppq = &set_queue->wqs_preposts;
				queue_enter(ppq, wql, wait_queue_link_t, wql_preposts);
			}
			if (! wait_queue_empty(&set_queue->wqs_wait_queue)) 
				_wait_queue_select64_all(&set_queue->wqs_wait_queue, event, wake_queue);
			wqs_unlock(set_queue);
		} else {
			
			/*
			 * Otherwise, its a thread.  If it is waiting on
			 * the event we are posting to this queue, pull
			 * it off the queue and stick it in out wake_queue.
			 */
			thread_t t = (thread_t)wq_element;

			if (t->wait_event == event) {
				thread_lock(t);
				remqueue(q, (queue_entry_t) t);
				enqueue (wake_queue, (queue_entry_t) t);
				t->wait_queue = WAIT_QUEUE_NULL;
				t->wait_event = NO_EVENT64;
				t->at_safe_point = FALSE;
				/* returned locked */
			}
		}
		wq_element = wqe_next;
	}
}

/*
 *	Routine:        wait_queue_wakeup64_all_locked
 *	Purpose:
 *		Wakeup some number of threads that are in the specified
 *		wait queue and waiting on the specified event.
 *	Conditions:
 *		wait queue already locked (may be released).
 *	Returns:
 *		KERN_SUCCESS - Threads were woken up
 *		KERN_NOT_WAITING - No threads were waiting <wq,event> pair
 */
__private_extern__ kern_return_t
wait_queue_wakeup64_all_locked(
	wait_queue_t wq,
	event64_t event,
	wait_result_t result,
	boolean_t unlock)
{
	queue_head_t wake_queue_head;
	queue_t q = &wake_queue_head;
	kern_return_t res;

//	assert(wait_queue_held(wq));
//	if(!wq->wq_interlock.lock_data) {		/* (BRINGUP */
//		panic("wait_queue_wakeup64_all_locked: lock not held on %p\n", wq);	/* (BRINGUP) */
//	}

	queue_init(q);

	/*
	 * Select the threads that we will wake up.	 The threads
	 * are returned to us locked and cleanly removed from the
	 * wait queue.
	 */
	_wait_queue_select64_all(wq, event, q);
	if (unlock)
		wait_queue_unlock(wq);

	/*
	 * For each thread, set it running.
	 */
	res = KERN_NOT_WAITING;
	while (!queue_empty (q)) {
		thread_t thread = (thread_t) dequeue(q);
		res = thread_go(thread, result);
		assert(res == KERN_SUCCESS);
		thread_unlock(thread);
	}
	return res;
}


/*
 *	Routine:		wait_queue_wakeup_all
 *	Purpose:
 *		Wakeup some number of threads that are in the specified
 *		wait queue and waiting on the specified event.
 *	Conditions:
 *		Nothing locked
 *	Returns:
 *		KERN_SUCCESS - Threads were woken up
 *		KERN_NOT_WAITING - No threads were waiting <wq,event> pair
 */
kern_return_t
wait_queue_wakeup_all(
	wait_queue_t wq,
	event_t event,
	wait_result_t result)
{
	kern_return_t ret;
	spl_t s;

	if (!wait_queue_is_valid(wq)) {
		return KERN_INVALID_ARGUMENT;
	}

	s = splsched();
	wait_queue_lock(wq);
//	if(!wq->wq_interlock.lock_data) {		/* (BRINGUP */
//		panic("wait_queue_wakeup_all: we did not get the lock on %p\n", wq);	/* (BRINGUP) */
//	}
	ret = wait_queue_wakeup64_all_locked(
				wq, CAST_DOWN(event64_t,event),
				result, TRUE);
	/* lock released */
	splx(s);
	return ret;
}

/*
 *	Routine:		wait_queue_wakeup64_all
 *	Purpose:
 *		Wakeup some number of threads that are in the specified
 *		wait queue and waiting on the specified event.
 *	Conditions:
 *		Nothing locked
 *	Returns:
 *		KERN_SUCCESS - Threads were woken up
 *		KERN_NOT_WAITING - No threads were waiting <wq,event> pair
 */
kern_return_t
wait_queue_wakeup64_all(
	wait_queue_t wq,
	event64_t event,
	wait_result_t result)
{
	kern_return_t ret;
	spl_t s;

	if (!wait_queue_is_valid(wq)) {
		return KERN_INVALID_ARGUMENT;
	}

	s = splsched();
	wait_queue_lock(wq);
	ret = wait_queue_wakeup64_all_locked(wq, event, result, TRUE);
	/* lock released */
	splx(s);
	return ret;
}

/*
 *	Routine:	_wait_queue_select64_one
 *	Purpose:
 *		Select the best thread off a wait queue that meet the
 *		supplied criteria.
 * 	Conditions:
 *		at splsched
 *		wait queue locked
 *		possibly recursive
 * 	Returns:
 *		a locked thread - if one found
 *	Note:
 *		This is where the sync policy of the wait queue comes
 *		into effect.  For now, we just assume FIFO/LIFO.
 */
static thread_t
_wait_queue_select64_one(
	wait_queue_t wq,
	event64_t event)
{
	wait_queue_element_t wq_element;
	wait_queue_element_t wqe_next;
	thread_t t = THREAD_NULL;
	queue_t q;

	q = &wq->wq_queue;

	wq_element = (wait_queue_element_t) queue_first(q);
	while (!queue_end(q, (queue_entry_t)wq_element)) {
		WAIT_QUEUE_ELEMENT_CHECK(wq, wq_element);
		wqe_next = (wait_queue_element_t)
			       queue_next((queue_t) wq_element);

		/*
		 * We may have to recurse if this is a compound wait queue.
		 */
		if (wq_element->wqe_type == WAIT_QUEUE_LINK ||
		    wq_element->wqe_type == WAIT_QUEUE_LINK_NOALLOC) {
			wait_queue_link_t wql = (wait_queue_link_t)wq_element;
			wait_queue_set_t set_queue = wql->wql_setqueue;

			/*
			 * We have to check the set wait queue. If the set
			 * supports pre-posting, it isn't already preposted,
			 * and we didn't find a thread in the set, then mark it.
			 *
			 * If we later find a thread, there may be a spurious
			 * pre-post here on this set.  The wait side has to check
			 * for that either pre- or post-wait.
			 */
			wqs_lock(set_queue);
			if (! wait_queue_empty(&set_queue->wqs_wait_queue)) {
				t = _wait_queue_select64_one(&set_queue->wqs_wait_queue, event);
			}
			if (t != THREAD_NULL) {
				wqs_unlock(set_queue);
				return t;
			}
			if (event == NO_EVENT64 && set_queue->wqs_prepost && !wql_is_preposted(wql)) {
				queue_t ppq = &set_queue->wqs_preposts;
				queue_enter(ppq, wql, wait_queue_link_t, wql_preposts);
			}
			wqs_unlock(set_queue);

		} else {
			
			/*
			 * Otherwise, its a thread.  If it is waiting on
			 * the event we are posting to this queue, pull
			 * it off the queue and stick it in out wake_queue.
			 */
			t = (thread_t)wq_element;
			if (t->wait_event == event) {
				thread_lock(t);
				remqueue(q, (queue_entry_t) t);
				t->wait_queue = WAIT_QUEUE_NULL;
				t->wait_event = NO_EVENT64;
				t->at_safe_point = FALSE;
				return t;	/* still locked */
			}

			t = THREAD_NULL;
		}
		wq_element = wqe_next;
	}
	return THREAD_NULL;
}


/*
 *	Routine:	wait_queue_pull_thread_locked
 *	Purpose:
 *		Pull a thread off its wait queue and (possibly) unlock 
 *		the waitq.
 * 	Conditions:
 *		at splsched
 *		wait queue locked
 *		thread locked
 * 	Returns:
 *		with the thread still locked.
 */
void
wait_queue_pull_thread_locked(
	wait_queue_t waitq,
	thread_t thread,
	boolean_t unlock)
{

	assert(thread->wait_queue == waitq);

	remqueue(&waitq->wq_queue, (queue_entry_t)thread );
	thread->wait_queue = WAIT_QUEUE_NULL;
	thread->wait_event = NO_EVENT64;
	thread->at_safe_point = FALSE;
	if (unlock)
		wait_queue_unlock(waitq);
}


/*
 *	Routine:	wait_queue_select64_thread
 *	Purpose:
 *		Look for a thread and remove it from the queues, if
 *		(and only if) the thread is waiting on the supplied
 *		<wait_queue, event> pair.
 * 	Conditions:
 *		at splsched
 *		wait queue locked
 *		possibly recursive
 * 	Returns:
 *		KERN_NOT_WAITING: Thread is not waiting here.
 *		KERN_SUCCESS: It was, and is now removed (returned locked)
 */
static kern_return_t
_wait_queue_select64_thread(
	wait_queue_t wq,
	event64_t event,
	thread_t thread)
{
	wait_queue_element_t wq_element;
	wait_queue_element_t wqe_next;
	kern_return_t res = KERN_NOT_WAITING;
	queue_t q = &wq->wq_queue;

	thread_lock(thread);
	if ((thread->wait_queue == wq) && (thread->wait_event == event)) {
		remqueue(q, (queue_entry_t) thread);
		thread->at_safe_point = FALSE;
		thread->wait_event = NO_EVENT64;
		thread->wait_queue = WAIT_QUEUE_NULL;
		/* thread still locked */
		return KERN_SUCCESS;
	}
	thread_unlock(thread);
	
	/*
	 * The wait_queue associated with the thread may be one of this
	 * wait queue's sets.  Go see.  If so, removing it from
	 * there is like removing it from here.
	 */
	wq_element = (wait_queue_element_t) queue_first(q);
	while (!queue_end(q, (queue_entry_t)wq_element)) {
		WAIT_QUEUE_ELEMENT_CHECK(wq, wq_element);
		wqe_next = (wait_queue_element_t)
			       queue_next((queue_t) wq_element);

		if (wq_element->wqe_type == WAIT_QUEUE_LINK ||
		    wq_element->wqe_type == WAIT_QUEUE_LINK_NOALLOC) {
			wait_queue_link_t wql = (wait_queue_link_t)wq_element;
			wait_queue_set_t set_queue = wql->wql_setqueue;

			wqs_lock(set_queue);
			if (! wait_queue_empty(&set_queue->wqs_wait_queue)) {
				res = _wait_queue_select64_thread(&set_queue->wqs_wait_queue,
								event,
								thread);
			}
			wqs_unlock(set_queue);
			if (res == KERN_SUCCESS)
				return KERN_SUCCESS;
		}
		wq_element = wqe_next;
	}
	return res;
}


/*
 *	Routine:	wait_queue_wakeup64_identity_locked
 *	Purpose:
 *		Select a single thread that is most-eligible to run and set
 *		set it running.  But return the thread locked.
 *
 * 	Conditions:
 *		at splsched
 *		wait queue locked
 *		possibly recursive
 * 	Returns:
 *		a pointer to the locked thread that was awakened
 */
__private_extern__ thread_t
wait_queue_wakeup64_identity_locked(
	wait_queue_t wq,
	event64_t event,
	wait_result_t result,
	boolean_t unlock)
{
	kern_return_t res;
	thread_t thread;

	assert(wait_queue_held(wq));

	thread = _wait_queue_select64_one(wq, event);
	if (unlock)
		wait_queue_unlock(wq);

	if (thread) {
		res = thread_go(thread, result);
		assert(res == KERN_SUCCESS);
	}
	return thread;  /* still locked if not NULL */
}


/*
 *	Routine:	wait_queue_wakeup64_one_locked
 *	Purpose:
 *		Select a single thread that is most-eligible to run and set
 *		set it runnings.
 *
 * 	Conditions:
 *		at splsched
 *		wait queue locked
 *		possibly recursive
 * 	Returns:
 *		KERN_SUCCESS: It was, and is, now removed.
 *		KERN_NOT_WAITING - No thread was waiting <wq,event> pair
 */
__private_extern__ kern_return_t
wait_queue_wakeup64_one_locked(
	wait_queue_t wq,
	event64_t event,
	wait_result_t result,
	boolean_t unlock)
{
	thread_t thread;

	assert(wait_queue_held(wq));

	thread = _wait_queue_select64_one(wq, event);
	if (unlock)
		wait_queue_unlock(wq);

	if (thread) {
		kern_return_t res;
		
		res = thread_go(thread, result);
		assert(res == KERN_SUCCESS);
		thread_unlock(thread);
		return res;
	}

	return KERN_NOT_WAITING;
}

/*
 *	Routine:	wait_queue_wakeup_one
 *	Purpose:
 *		Wakeup the most appropriate thread that is in the specified
 *		wait queue for the specified event.
 *	Conditions:
 *		Nothing locked
 *	Returns:
 *		KERN_SUCCESS - Thread was woken up
 *		KERN_NOT_WAITING - No thread was waiting <wq,event> pair
 */
kern_return_t
wait_queue_wakeup_one(
	wait_queue_t wq,
	event_t event,
	wait_result_t result)
{
	thread_t thread;
	spl_t s;

	if (!wait_queue_is_valid(wq)) {
		return KERN_INVALID_ARGUMENT;
	}

	s = splsched();
	wait_queue_lock(wq);
	thread = _wait_queue_select64_one(wq, CAST_DOWN(event64_t,event));
	wait_queue_unlock(wq);

	if (thread) {
		kern_return_t res;

		res = thread_go(thread, result);
		assert(res == KERN_SUCCESS);
		thread_unlock(thread);
		splx(s);
		return res;
	}

	splx(s);
	return KERN_NOT_WAITING;
}

/*
 *	Routine:	wait_queue_wakeup64_one
 *	Purpose:
 *		Wakeup the most appropriate thread that is in the specified
 *		wait queue for the specified event.
 *	Conditions:
 *		Nothing locked
 *	Returns:
 *		KERN_SUCCESS - Thread was woken up
 *		KERN_NOT_WAITING - No thread was waiting <wq,event> pair
 */
kern_return_t
wait_queue_wakeup64_one(
	wait_queue_t wq,
	event64_t event,
	wait_result_t result)
{
	thread_t thread;
	spl_t s;

	if (!wait_queue_is_valid(wq)) {
		return KERN_INVALID_ARGUMENT;
	}
	s = splsched();
	wait_queue_lock(wq);
	thread = _wait_queue_select64_one(wq, event);
	wait_queue_unlock(wq);

	if (thread) {
		kern_return_t res;

		res = thread_go(thread, result);
		assert(res == KERN_SUCCESS);
		thread_unlock(thread);
		splx(s);
		return res;
	}

	splx(s);
	return KERN_NOT_WAITING;
}


/*
 *	Routine:	wait_queue_wakeup64_thread_locked
 *	Purpose:
 *		Wakeup the particular thread that was specified if and only
 *		it was in this wait queue (or one of it's set queues)
 *		and waiting on the specified event.
 *
 *		This is much safer than just removing the thread from
 *		whatever wait queue it happens to be on.  For instance, it
 *		may have already been awoken from the wait you intended to
 *		interrupt and waited on something else (like another
 *		semaphore).
 *	Conditions:
 *		at splsched
 *		wait queue already locked (may be released).
 *	Returns:
 *		KERN_SUCCESS - the thread was found waiting and awakened
 *		KERN_NOT_WAITING - the thread was not waiting here
 */
__private_extern__ kern_return_t
wait_queue_wakeup64_thread_locked(
	wait_queue_t wq,
	event64_t event,
	thread_t thread,
	wait_result_t result,
	boolean_t unlock)
{
	kern_return_t res;

	assert(wait_queue_held(wq));

	/*
	 * See if the thread was still waiting there.  If so, it got
	 * dequeued and returned locked.
	 */
	res = _wait_queue_select64_thread(wq, event, thread);
	if (unlock)
	    wait_queue_unlock(wq);

	if (res != KERN_SUCCESS)
		return KERN_NOT_WAITING;

	res = thread_go(thread, result);
	assert(res == KERN_SUCCESS);
	thread_unlock(thread);
	return res;
}

/*
 *	Routine:	wait_queue_wakeup_thread
 *	Purpose:
 *		Wakeup the particular thread that was specified if and only
 *		it was in this wait queue (or one of it's set queues)
 *		and waiting on the specified event.
 *
 *		This is much safer than just removing the thread from
 *		whatever wait queue it happens to be on.  For instance, it
 *		may have already been awoken from the wait you intended to
 *		interrupt and waited on something else (like another
 *		semaphore).
 *	Conditions:
 *		nothing of interest locked
 *		we need to assume spl needs to be raised
 *	Returns:
 *		KERN_SUCCESS - the thread was found waiting and awakened
 *		KERN_NOT_WAITING - the thread was not waiting here
 */
kern_return_t
wait_queue_wakeup_thread(
	wait_queue_t wq,
	event_t event,
	thread_t thread,
	wait_result_t result)
{
	kern_return_t res;
	spl_t s;

	if (!wait_queue_is_valid(wq)) {
		return KERN_INVALID_ARGUMENT;
	}

	s = splsched();
	wait_queue_lock(wq);
	res = _wait_queue_select64_thread(wq, CAST_DOWN(event64_t,event), thread);
	wait_queue_unlock(wq);

	if (res == KERN_SUCCESS) {
		res = thread_go(thread, result);
		assert(res == KERN_SUCCESS);
		thread_unlock(thread);
		splx(s);
		return res;
	}
	splx(s);
	return KERN_NOT_WAITING;
}

/*
 *	Routine:	wait_queue_wakeup64_thread
 *	Purpose:
 *		Wakeup the particular thread that was specified if and only
 *		it was in this wait queue (or one of it's set's queues)
 *		and waiting on the specified event.
 *
 *		This is much safer than just removing the thread from
 *		whatever wait queue it happens to be on.  For instance, it
 *		may have already been awoken from the wait you intended to
 *		interrupt and waited on something else (like another
 *		semaphore).
 *	Conditions:
 *		nothing of interest locked
 *		we need to assume spl needs to be raised
 *	Returns:
 *		KERN_SUCCESS - the thread was found waiting and awakened
 *		KERN_NOT_WAITING - the thread was not waiting here
 */
kern_return_t
wait_queue_wakeup64_thread(
	wait_queue_t wq,
	event64_t event,
	thread_t thread,
	wait_result_t result)
{
	kern_return_t res;
	spl_t s;

	if (!wait_queue_is_valid(wq)) {
		return KERN_INVALID_ARGUMENT;
	}

	s = splsched();
	wait_queue_lock(wq);
	res = _wait_queue_select64_thread(wq, event, thread);
	wait_queue_unlock(wq);

	if (res == KERN_SUCCESS) {
		res = thread_go(thread, result);
		assert(res == KERN_SUCCESS);
		thread_unlock(thread);
		splx(s);
		return res;
	}
	splx(s);
	return KERN_NOT_WAITING;
}

/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
#include <kern/kalloc.h>
#include <kern/queue.h>
#include <kern/spl.h>
#include <mach/sync_policy.h>
#include <kern/sched_prim.h>

#include <kern/wait_queue.h>

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
	if (!((policy & SYNC_POLICY_ORDER_MASK) == SYNC_POLICY_FIFO))
		return KERN_INVALID_ARGUMENT;

	wq->wq_fifo = TRUE;
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

	wq = (wait_queue_t) kalloc(sizeof(struct wait_queue));
	if (wq != WAIT_QUEUE_NULL) {
		ret = wait_queue_init(wq, policy);
		if (ret != KERN_SUCCESS) {
			kfree((vm_offset_t)wq, sizeof(struct wait_queue));
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
	kfree((vm_offset_t)wq, sizeof(struct wait_queue));
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
		wqset->wqs_wait_queue.wq_isprepost = TRUE;
	else 
		wqset->wqs_wait_queue.wq_isprepost = FALSE;
	queue_init(&wqset->wqs_setlinks);
	wqset->wqs_refcount = 0;
	return KERN_SUCCESS;
}

/* legacy API */
kern_return_t
wait_queue_sub_init(
	wait_queue_set_t wqset,
	int policy)
{
	return wait_queue_set_init(wqset, policy);
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

	wq_set = (wait_queue_set_t) kalloc(sizeof(struct wait_queue_set));
	if (wq_set != WAIT_QUEUE_SET_NULL) {
		kern_return_t ret;

		ret = wait_queue_set_init(wq_set, policy);
		if (ret != KERN_SUCCESS) {
			kfree((vm_offset_t)wq_set, sizeof(struct wait_queue_set));
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

	kfree((vm_offset_t)wq_set, sizeof(struct wait_queue_set));
	return KERN_SUCCESS;
}

kern_return_t
wait_queue_sub_clearrefs(
        wait_queue_set_t wq_set)
{
	if (!wait_queue_is_set(wq_set))
		return KERN_INVALID_ARGUMENT;

	wqs_lock(wq_set);
	wq_set->wqs_refcount = 0;
	wqs_unlock(wq_set);
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
static unsigned int _wait_queue_unlinked;

#define WAIT_QUEUE_LINK ((void *)&_wait_queue_link)
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
		WQASSERT((((wql)->wql_type == WAIT_QUEUE_LINK) && \
			((wql)->wql_setqueue == (wqs)) && \
			((wql)->wql_queue->wq_type == _WAIT_QUEUE_inited) && \
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
__private_extern__ boolean_t
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
		if ((wq_element->wqe_type == WAIT_QUEUE_LINK)) {
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
	wait_queue_element_t wq_element;
	queue_t q;
	spl_t s;

	if (!wait_queue_is_queue(wq) || !wait_queue_is_set(wq_set))
  		return KERN_INVALID_ARGUMENT;

	/*
	 * There are probably less threads and sets associated with
	 * the wait queue, then there are wait queues associated with
	 * the set.  So lets validate it that way.
	 */
	s = splsched();
	wait_queue_lock(wq);
	q = &wq->wq_queue;
	wq_element = (wait_queue_element_t) queue_first(q);
	while (!queue_end(q, (queue_entry_t)wq_element)) {
		WAIT_QUEUE_ELEMENT_CHECK(wq, wq_element);
		if (wq_element->wqe_type == WAIT_QUEUE_LINK &&
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

	wql->wql_queue = wq;
	queue_enter(&wq->wq_queue, wql, wait_queue_link_t, wql_links);
	wql->wql_setqueue = wq_set;
	queue_enter(&wq_set->wqs_setlinks, wql, wait_queue_link_t, wql_setlinks);
	wql->wql_type = WAIT_QUEUE_LINK;

	wqs_unlock(wq_set);
	wait_queue_unlock(wq);
	splx(s);

	return KERN_SUCCESS;
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

	wql = (wait_queue_link_t) kalloc(sizeof(struct wait_queue_link));
	if (wql == WAIT_QUEUE_LINK_NULL)
		return KERN_RESOURCE_SHORTAGE;

	ret = wait_queue_link_noalloc(wq, wq_set, wql);
	if (ret != KERN_SUCCESS)
		kfree((vm_offset_t)wql, sizeof(struct wait_queue_link));

	return ret;
}	


/*
 *	Routine:	wait_queue_unlink_nofree
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

	if (!wait_queue_is_queue(wq) || !wait_queue_is_set(wq_set)) {
		return KERN_INVALID_ARGUMENT;
	}
	s = splsched();
	wait_queue_lock(wq);

	q = &wq->wq_queue;
	wq_element = (wait_queue_element_t) queue_first(q);
	while (!queue_end(q, (queue_entry_t)wq_element)) {
		WAIT_QUEUE_ELEMENT_CHECK(wq, wq_element);
		if (wq_element->wqe_type == WAIT_QUEUE_LINK) {
		   	wql = (wait_queue_link_t)wq_element;
			
			if (wql->wql_setqueue == wq_set) {
				wqs_lock(wq_set);
				wait_queue_unlink_locked(wq, wq_set, wql);
				wqs_unlock(wq_set);
				wait_queue_unlock(wq);
				splx(s);
				kfree((vm_offset_t)wql, sizeof(struct wait_queue_link));
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
 *	Routine:	wait_queue_unlinkall_nofree
 *	Purpose:
 *		Remove the linkage between a wait queue and all its
 *		sets. The caller is responsible for freeing
 *		the wait queue link structures.
 */

kern_return_t
wait_queue_unlinkall_nofree(
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

	if (!wait_queue_is_queue(wq)) {
		return KERN_INVALID_ARGUMENT;
	}

	queue_init(links);

	s = splsched();
	wait_queue_lock(wq);

	q = &wq->wq_queue;

	wq_element = (wait_queue_element_t) queue_first(q);
	while (!queue_end(q, (queue_entry_t)wq_element)) {
		WAIT_QUEUE_ELEMENT_CHECK(wq, wq_element);
		wq_next_element = (wait_queue_element_t)
			     queue_next((queue_t) wq_element);

		if (wq_element->wqe_type == WAIT_QUEUE_LINK) {
			wql = (wait_queue_link_t)wq_element;
			wq_set = wql->wql_setqueue;
			wqs_lock(wq_set);
			wait_queue_unlink_locked(wq, wq_set, wql);
			wqs_unlock(wq_set);
		}
		wq_element = wq_next_element;
	}
	wait_queue_unlock(wq);
	splx(s);
	return(KERN_SUCCESS);
}	


/*
 *	Routine:	wait_queue_unlink_all
 *	Purpose:
 *		Remove the linkage between a wait queue and all its	sets.
 *		All the linkage structures are freed.
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

	if (!wait_queue_is_queue(wq)) {
		return KERN_INVALID_ARGUMENT;
	}

	queue_init(links);

	s = splsched();
	wait_queue_lock(wq);

	q = &wq->wq_queue;

	wq_element = (wait_queue_element_t) queue_first(q);
	while (!queue_end(q, (queue_entry_t)wq_element)) {
		WAIT_QUEUE_ELEMENT_CHECK(wq, wq_element);
		wq_next_element = (wait_queue_element_t)
			     queue_next((queue_t) wq_element);

		if (wq_element->wqe_type == WAIT_QUEUE_LINK) {
			wql = (wait_queue_link_t)wq_element;
			wq_set = wql->wql_setqueue;
			wqs_lock(wq_set);
			wait_queue_unlink_locked(wq, wq_set, wql);
			wqs_unlock(wq_set);
			enqueue(links, &wql->wql_links);
		}
		wq_element = wq_next_element;
	}
	wait_queue_unlock(wq);
	splx(s);

	while(!queue_empty(links)) {
		wql = (wait_queue_link_t) dequeue(links);
		kfree((vm_offset_t) wql, sizeof(struct wait_queue_link));
	}

	return(KERN_SUCCESS);
}	

/*
 *	Routine:	wait_queue_set_unlink_all_nofree
 *	Purpose:
 *		Remove the linkage between a set wait queue and all its
 *		member wait queues. The link structures are not freed, nor
 *		returned. It is the caller's responsibility to track and free
 *		them.
 *	Conditions:
 *		The wait queue being must be a member set queue
 */
kern_return_t
wait_queue_set_unlink_all_nofree(
	wait_queue_set_t wq_set)
{
	wait_queue_link_t wql;
	wait_queue_t wq;
	queue_t q;
	kern_return_t kret;
	spl_t s;

	if (!wait_queue_is_set(wq_set)) {
		return KERN_INVALID_ARGUMENT;
	}

retry:
	s = splsched();
	wqs_lock(wq_set);

	q = &wq_set->wqs_setlinks;

	wql = (wait_queue_link_t)queue_first(q);
	while (!queue_end(q, (queue_entry_t)wql)) {
		WAIT_QUEUE_SET_LINK_CHECK(wq_set, wql);
		wq = wql->wql_queue;
		if (wait_queue_lock_try(wq)) {
			wait_queue_unlink_locked(wq, wq_set, wql);
			wait_queue_unlock(wq);
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

	return(KERN_SUCCESS);
}	

/* legacy interface naming */
kern_return_t
wait_subqueue_unlink_all(
	wait_queue_set_t	wq_set)
{
	return wait_queue_set_unlink_all_nofree(wq_set);
}


/*
 *	Routine:	wait_queue_set_unlink_all
 *	Purpose:
 *		Remove the linkage between a set wait queue and all its
 *		member wait queues. The link structures are freed.
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
	kern_return_t kret;
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
			wait_queue_unlink_locked(wq, wq_set, wql);
			wait_queue_unlock(wq);
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
		kfree((vm_offset_t)wql, sizeof(struct wait_queue_link));
	}
	return(KERN_SUCCESS);
}	


/*
 *	Routine:	wait_queue_unlink_one
 *	Purpose:
 *		Find and unlink one set wait queue
 *	Conditions:
 *		Nothing of interest locked.
 */
void
wait_queue_unlink_one(
	wait_queue_t wq,
	wait_queue_set_t *wq_setp)
{
	wait_queue_element_t wq_element;
	queue_t q;
	spl_t s;

	s = splsched();
	wait_queue_lock(wq);

	q = &wq->wq_queue;
	
	wq_element = (wait_queue_element_t) queue_first(q);
	while (!queue_end(q, (queue_entry_t)wq_element)) {

		if (wq_element->wqe_type == WAIT_QUEUE_LINK) {
			wait_queue_link_t wql = (wait_queue_link_t)wq_element;
			wait_queue_set_t wq_set = wql->wql_setqueue;
			
			wqs_lock(wq_set);
			wait_queue_unlink_locked(wq, wq_set, wql);
			wqs_unlock(wq_set);
			wait_queue_unlock(wq);
			splx(s);
			kfree((vm_offset_t)wql,sizeof(struct wait_queue_link));
			*wq_setp = wq_set;
			return;
		}

		wq_element = (wait_queue_element_t)
			queue_next((queue_t) wq_element);
	}
	wait_queue_unlock(wq);
	splx(s);
	*wq_setp = WAIT_QUEUE_SET_NULL;
}


/*
 *	Routine:	wait_queue_assert_wait64_locked
 *	Purpose:
 *		Insert the current thread into the supplied wait queue
 *		waiting for a particular event to be posted to that queue.
 *
 *	Conditions:
 *		The wait queue is assumed locked.
 *
 */
__private_extern__ wait_result_t
wait_queue_assert_wait64_locked(
	wait_queue_t wq,
	event64_t event,
	wait_interrupt_t interruptible,
	boolean_t unlock)
{
	thread_t thread;
	wait_result_t wait_result;

	if (wq->wq_type == _WAIT_QUEUE_SET_inited) {
		wait_queue_set_t wqs = (wait_queue_set_t)wq;
		if (wqs->wqs_isprepost && wqs->wqs_refcount > 0) {
			if (unlock)
				wait_queue_unlock(wq);
			return(THREAD_AWAKENED);
		}
	}
	  
	/*
	 * This is the extent to which we currently take scheduling attributes
	 * into account.  If the thread is vm priviledged, we stick it at
	 * the front of the queue.  Later, these queues will honor the policy
	 * value set at wait_queue_init time.
	 */
	thread = current_thread();
	thread_lock(thread);
	wait_result = thread_mark_wait_locked(thread, interruptible);
	if (wait_result == THREAD_WAITING) {
		if (thread->vm_privilege)
			enqueue_head(&wq->wq_queue, (queue_entry_t) thread);
		else
			enqueue_tail(&wq->wq_queue, (queue_entry_t) thread);
		thread->wait_event = event;
		thread->wait_queue = wq;
	}
	thread_unlock(thread);
	if (unlock)
		wait_queue_unlock(wq);
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
	wait_interrupt_t interruptible)
{
	spl_t s;
	wait_result_t ret;

	/* If it is an invalid wait queue, you can't wait on it */
	if (!wait_queue_is_valid(wq)) {
		thread_t thread = current_thread();
		return (thread->wait_result = THREAD_RESTART);
	}

	s = splsched();
	wait_queue_lock(wq);
	ret = wait_queue_assert_wait64_locked(
				wq, (event64_t)((uint32_t)event),
				interruptible, TRUE);
	/* wait queue unlocked */
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
	wait_interrupt_t interruptible)
{
	spl_t s;
	wait_result_t ret;

	/* If it is an invalid wait queue, you cant wait on it */
	if (!wait_queue_is_valid(wq)) {
		thread_t thread = current_thread();
		return (thread->wait_result = THREAD_RESTART);
	}

	s = splsched();
	wait_queue_lock(wq);
	ret = wait_queue_assert_wait64_locked(wq, event, interruptible, TRUE);
	/* wait queue unlocked */
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
		if (wq_element->wqe_type == WAIT_QUEUE_LINK) {
			wait_queue_link_t wql = (wait_queue_link_t)wq_element;
			wait_queue_t set_queue;

			/*
			 * We have to check the set wait queue.
			 */
			set_queue = (wait_queue_t)wql->wql_setqueue;
			wait_queue_lock(set_queue);
			if (set_queue->wq_isprepost) {
				wait_queue_set_t wqs = (wait_queue_set_t)set_queue;
				
				/*
				 * Preposting is only for sets and wait queue
				 * is the first element of set 
				 */
				wqs->wqs_refcount++;
			}
			if (! wait_queue_empty(set_queue)) 
				_wait_queue_select64_all(set_queue, event, wake_queue);
			wait_queue_unlock(set_queue);
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

	assert(wait_queue_held(wq));
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
		res = thread_go_locked(thread, result);
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
	ret = wait_queue_wakeup64_all_locked(
				wq, (event64_t)((uint32_t)event),
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
 *		into effect.  For now, we just assume FIFO.
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

	assert(wq->wq_fifo);

	q = &wq->wq_queue;

	wq_element = (wait_queue_element_t) queue_first(q);
	while (!queue_end(q, (queue_entry_t)wq_element)) {
		WAIT_QUEUE_ELEMENT_CHECK(wq, wq_element);
		wqe_next = (wait_queue_element_t)
			       queue_next((queue_t) wq_element);

		/*
		 * We may have to recurse if this is a compound wait queue.
		 */
		if (wq_element->wqe_type == WAIT_QUEUE_LINK) {
			wait_queue_link_t wql = (wait_queue_link_t)wq_element;
			wait_queue_t set_queue;

			/*
			 * We have to check the set wait queue.
			 */
			set_queue = (wait_queue_t)wql->wql_setqueue;
			wait_queue_lock(set_queue);
			if (! wait_queue_empty(set_queue)) {
				t = _wait_queue_select64_one(set_queue, event);
			}
			wait_queue_unlock(set_queue);
			if (t != THREAD_NULL)
				return t;
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
				t->wait_queue = WAIT_QUEUE_NULL;
				t->wait_event = NO_EVENT64;
				t->at_safe_point = FALSE;
				return t;	/* still locked */
			}
		}
		wq_element = wqe_next;
	}
	return THREAD_NULL;
}

/*
 *	Routine:	wait_queue_peek64_locked
 *	Purpose:
 *		Select the best thread from a wait queue that meet the
 *		supplied criteria, but leave it on the queue it was
 *		found on.  The thread, and the actual wait_queue the
 *		thread was found on are identified.
 * 	Conditions:
 *		at splsched
 *		wait queue locked
 *		possibly recursive
 * 	Returns:
 *		a locked thread - if one found
 *		a locked waitq - the one the thread was found on
 *	Note:
 *		Both the waitq the thread was actually found on, and
 *		the supplied wait queue, are locked after this.
 */
__private_extern__ void
wait_queue_peek64_locked(
	wait_queue_t wq,
	event64_t event,
	thread_t *tp,
	wait_queue_t *wqp)
{
	wait_queue_element_t wq_element;
	wait_queue_element_t wqe_next;
	thread_t t;
	queue_t q;

	assert(wq->wq_fifo);

	*tp = THREAD_NULL;

	q = &wq->wq_queue;

	wq_element = (wait_queue_element_t) queue_first(q);
	while (!queue_end(q, (queue_entry_t)wq_element)) {
		WAIT_QUEUE_ELEMENT_CHECK(wq, wq_element);
		wqe_next = (wait_queue_element_t)
			       queue_next((queue_t) wq_element);

		/*
		 * We may have to recurse if this is a compound wait queue.
		 */
		if (wq_element->wqe_type == WAIT_QUEUE_LINK) {
			wait_queue_link_t wql = (wait_queue_link_t)wq_element;
			wait_queue_t set_queue;

			/*
			 * We have to check the set wait queue.
			 */
			set_queue = (wait_queue_t)wql->wql_setqueue;
			wait_queue_lock(set_queue);
			if (! wait_queue_empty(set_queue)) {
				wait_queue_peek64_locked(set_queue, event, tp, wqp);
			}
			if (*tp != THREAD_NULL) {
				if (*wqp != set_queue)
					wait_queue_unlock(set_queue);
				return;  /* thread and its waitq locked */
			}

			wait_queue_unlock(set_queue);
		} else {
			
			/*
			 * Otherwise, its a thread.  If it is waiting on
			 * the event we are posting to this queue, return
			 * it locked, but leave it on the queue.
			 */
			thread_t t = (thread_t)wq_element;

			if (t->wait_event == event) {
				thread_lock(t);
				*tp = t;
				*wqp = wq;
				return;
			}
		}
		wq_element = wqe_next;
	}
}

/*
 *	Routine:	wait_queue_pull_thread_locked
 *	Purpose:
 *		Pull a thread that was previously "peeked" off the wait
 *		queue and (possibly) unlock the waitq.
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

		if (wq_element->wqe_type == WAIT_QUEUE_LINK) {
			wait_queue_link_t wql = (wait_queue_link_t)wq_element;
			wait_queue_t set_queue;

			set_queue = (wait_queue_t)wql->wql_setqueue;
			wait_queue_lock(set_queue);
			if (! wait_queue_empty(set_queue)) {
				res = _wait_queue_select64_thread(set_queue,
								event,
								thread);
			}
			wait_queue_unlock(set_queue);
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
		res = thread_go_locked(thread, result);
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
		
		res = thread_go_locked(thread, result);
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
	thread = _wait_queue_select64_one(wq, (event64_t)((uint32_t)event));
	wait_queue_unlock(wq);

	if (thread) {
		kern_return_t res;

		res = thread_go_locked(thread, result);
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

		res = thread_go_locked(thread, result);
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

	res = thread_go_locked(thread, result);
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
	res = _wait_queue_select64_thread(wq, (event64_t)((uint32_t)event), thread);
	wait_queue_unlock(wq);

	if (res == KERN_SUCCESS) {
		res = thread_go_locked(thread, result);
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
		res = thread_go_locked(thread, result);
		assert(res == KERN_SUCCESS);
		thread_unlock(thread);
		splx(s);
		return res;
	}
	splx(s);
	return KERN_NOT_WAITING;
}

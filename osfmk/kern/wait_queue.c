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

void
wait_queue_init(
        wait_queue_t wq,
	int policy)
{
	wq->wq_fifo = (policy == SYNC_POLICY_FIFO);
	wq->wq_issub = FALSE;
	queue_init(&wq->wq_queue);
	hw_lock_init(&wq->wq_interlock);
}

void
wait_queue_sub_init(
        wait_queue_sub_t wqsub,
	int policy)
{
	wait_queue_init(&wqsub->wqs_wait_queue, policy);
	wqsub->wqs_wait_queue.wq_issub = TRUE;
	if ( policy & SYNC_POLICY_PREPOST) {
		wqsub->wqs_wait_queue.wq_isprepost = TRUE;
		wqsub->wqs_refcount = 0;
	} else 
		wqsub->wqs_wait_queue.wq_isprepost = FALSE;
	queue_init(&wqsub->wqs_sublinks);
}

void
wait_queue_sub_clearrefs(
        wait_queue_sub_t wq_sub)
{
	assert(wait_queue_is_sub(wq_sub));

	wqs_lock(wq_sub);

	wq_sub->wqs_refcount = 0;

	wqs_unlock(wq_sub);

}

void
wait_queue_link_init(
	wait_queue_link_t wql)
{
	queue_init(&wql->wql_links);
	queue_init(&wql->wql_sublinks);
	wql->wql_queue = WAIT_QUEUE_NULL;
	wql->wql_subqueue = WAIT_QUEUE_SUB_NULL;
	wql->wql_event = NO_EVENT;
}

/*
 *     Routine:        wait_queue_alloc
 *     Purpose:
 *             Allocate and initialize a wait queue for use outside of
 *             of the mach part of the kernel.
 *
 *     Conditions:
 *             Nothing locked - can block.
 *
 *     Returns:
 *             The allocated and initialized wait queue
 *             WAIT_QUEUE_NULL if there is a resource shortage
 */
wait_queue_t
wait_queue_alloc(
         int policy)
{
	wait_queue_t wq;

	wq = (wait_queue_t) kalloc(sizeof(struct wait_queue));
	if (wq != WAIT_QUEUE_NULL)
		wait_queue_init(wq, policy);
	return wq;
}

/*
 *     Routine:        wait_queue_free
 *     Purpose:
 *             Free an allocated wait queue.
 *
 *     Conditions:
 *             Nothing locked - can block.
 */
void
wait_queue_free(
	wait_queue_t wq)
{
	assert(queue_empty(&wq->wq_queue));
	kfree((vm_offset_t)wq, sizeof(struct wait_queue));
}


/*
 *	Routine:	wait_queue_lock
 *	Purpose:
 *		Lock the wait queue.
 *	Conditions:
 *		the appropriate spl level (if any) is already raised.
 */
void
wait_queue_lock(
        wait_queue_t wq)
{
#ifdef __ppc__
	vm_offset_t pc;

        /*
         * Double the standard lock timeout, because wait queues tend
         * to iterate over a number of threads - locking each.  If there is
         * a problem with a thread lock, it normally times out at the wait
         * queue level first, hiding the real problem.
         */
	pc = GET_RETURN_PC(&wq);
	if (!hw_lock_to(&wq->wq_interlock, LockTimeOut * 2)) {
		panic("wait queue deadlock detection - wq=0x%x, cpu=%d, ret=0x%x\n", wq, cpu_number(), pc);
	}
#else
	hw_lock_lock(&wq->wq_interlock);
#endif
}

/*
 *	Routine:	wait_queue_lock_try
 *	Purpose:
 *		Try to lock the wait queue without waiting
 *	Conditions:
 *		the appropriate spl level (if any) is already raised.
 *  Returns:
 *		TRUE if the lock was acquired
 *		FALSE if we would have needed to wait
 */
boolean_t
wait_queue_lock_try(
        wait_queue_t wq)
{
	return hw_lock_try(&wq->wq_interlock);
}

/*
 *	Routine:	wait_queue_unlock
 *	Purpose:
 *		unlock the wait queue
 *	Conditions:
 *		The wait queue is assumed locked.
 *		appropriate spl level is still maintained
 */
void
wait_queue_unlock(
	wait_queue_t wq)
{
	assert(hw_lock_held(&wq->wq_interlock));

	hw_lock_unlock(&wq->wq_interlock);
}

int _wait_queue_subordinate; /* phoney event for subordinate wait q elements */

	
/*
 *	Routine:	wait_queue_member_locked
 *	Purpose:
 *		Indicate if this sub queue is a member of the queue
 *	Conditions:
 *		The wait queue is locked
 *		The sub queue is just that, a sub queue
 */
boolean_t
wait_queue_member_locked(
	wait_queue_t wq,
	wait_queue_sub_t wq_sub)
{
	wait_queue_element_t wq_element;
	queue_t q;

	assert(wait_queue_held(wq));
	assert(wait_queue_is_sub(wq_sub));

	q = &wq->wq_queue;

	wq_element = (wait_queue_element_t) queue_first(q);
	while (!queue_end(q, (queue_entry_t)wq_element)) {

		if ((wq_element->wqe_event == WAIT_QUEUE_SUBORDINATE)) {
			wait_queue_link_t wql = (wait_queue_link_t)wq_element;

			if (wql->wql_subqueue == wq_sub)
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
 *		Indicate if this sub queue is a member of the queue
 *	Conditions:
 *		The sub queue is just that, a sub queue
 */
boolean_t
wait_queue_member(
	wait_queue_t wq,
	wait_queue_sub_t wq_sub)
{
	boolean_t ret;
	spl_t s;

	assert(wait_queue_is_sub(wq_sub));

	s = splsched();
	wait_queue_lock(wq);
	ret = wait_queue_member_locked(wq, wq_sub);
	wait_queue_unlock(wq);
	splx(s);

	return ret;
}

/*
 *	Routine:	wait_queue_link
 *	Purpose:
 *		Insert a subordinate wait queue into a wait queue.  This
 *		requires us to link the two together using a wait_queue_link
 *		structure that we allocate.
 *	Conditions:
 *		The wait queue being inserted must be inited as a sub queue
 *		The sub waitq is not already linked
 *
 */
kern_return_t
wait_queue_link(
	wait_queue_t wq,
	wait_queue_sub_t wq_sub)
{
	wait_queue_link_t wql;
	spl_t s;

	assert(wait_queue_is_sub(wq_sub));
	assert(!wait_queue_member(wq, wq_sub));

	wql = (wait_queue_link_t) kalloc(sizeof(struct wait_queue_link));
	if (wql == WAIT_QUEUE_LINK_NULL)
		return KERN_RESOURCE_SHORTAGE;
	
	wait_queue_link_init(wql);

	s = splsched();
	wait_queue_lock(wq);
	wqs_lock(wq_sub);

	wql->wql_queue = wq;
	wql->wql_subqueue = wq_sub;
	wql->wql_event = WAIT_QUEUE_SUBORDINATE;
	queue_enter(&wq->wq_queue, wql, wait_queue_link_t, wql_links);
	queue_enter(&wq_sub->wqs_sublinks, wql, wait_queue_link_t, wql_sublinks);
	
	wqs_unlock(wq_sub);
	wait_queue_unlock(wq);
	splx(s);

	return KERN_SUCCESS;
}	
/*
 *	Routine:	wait_queue_link_noalloc
 *	Purpose:
 *		Insert a subordinate wait queue into a wait queue.  This
 *		requires us to link the two together using a wait_queue_link
 *		structure that we allocate.
 *	Conditions:
 *		The wait queue being inserted must be inited as a sub queue
 *		The sub waitq is not already linked
 *
 */
kern_return_t
wait_queue_link_noalloc(
	wait_queue_t wq,
	wait_queue_sub_t wq_sub,
	wait_queue_link_t wql)
{
	spl_t s;

	assert(wait_queue_is_sub(wq_sub));
	assert(!wait_queue_member(wq, wq_sub));

	wait_queue_link_init(wql);

	s = splsched();
	wait_queue_lock(wq);
	wqs_lock(wq_sub);

	wql->wql_queue = wq;
	wql->wql_subqueue = wq_sub;
	wql->wql_event = WAIT_QUEUE_SUBORDINATE;
	queue_enter(&wq->wq_queue, wql, wait_queue_link_t, wql_links);
	queue_enter(&wq_sub->wqs_sublinks, wql, wait_queue_link_t, wql_sublinks);
	
	wqs_unlock(wq_sub);
	wait_queue_unlock(wq);
	splx(s);

	return KERN_SUCCESS;
}	

/*
 *	Routine:	wait_queue_unlink
 *	Purpose:
 *		Remove the linkage between a wait queue and its subordinate.
 *	Conditions:
 *		The wait queue being must be a member sub queue
 */
kern_return_t
wait_queue_unlink(
	wait_queue_t wq,
	wait_queue_sub_t wq_sub)
{
	wait_queue_element_t wq_element;
	queue_t q;
	spl_t s;

	assert(wait_queue_is_sub(wq_sub));
	assert(wait_queue_member(wq, wq_sub));

	s = splsched();
	wait_queue_lock(wq);
	wqs_lock(wq_sub);

	q = &wq->wq_queue;

	wq_element = (wait_queue_element_t) queue_first(q);
	while (!queue_end(q, (queue_entry_t)wq_element)) {

		if (wq_element->wqe_event == WAIT_QUEUE_SUBORDINATE) {
			wait_queue_link_t wql = (wait_queue_link_t)wq_element;
			queue_t sq;
			
			if (wql->wql_subqueue == wq_sub) {
				sq = &wq_sub->wqs_sublinks;
				queue_remove(q, wql, wait_queue_link_t, wql_links);
				queue_remove(sq, wql, wait_queue_link_t, wql_sublinks);
				wqs_unlock(wq_sub);
				wait_queue_unlock(wq);
				splx(s);
				kfree((vm_offset_t)wql,sizeof(struct wait_queue_link));
				return;
			}
		}

		wq_element = (wait_queue_element_t)
			     queue_next((queue_t) wq_element);
	}
	panic("wait_queue_unlink");
}	

/*
 *	Routine:	wait_queue_unlink_nofree
 *	Purpose:
 *		Remove the linkage between a wait queue and its subordinate. Do not deallcoate the wql
 *	Conditions:
 *		The wait queue being must be a member sub queue
 */
kern_return_t
wait_queue_unlink_nofree(
	wait_queue_t wq,
	wait_queue_sub_t wq_sub)
{
	wait_queue_element_t wq_element;
	queue_t q;

	assert(wait_queue_is_sub(wq_sub));

	q = &wq->wq_queue;

	wq_element = (wait_queue_element_t) queue_first(q);
	while (!queue_end(q, (queue_entry_t)wq_element)) {

		if (wq_element->wqe_event == WAIT_QUEUE_SUBORDINATE) {
			wait_queue_link_t wql = (wait_queue_link_t)wq_element;
			queue_t sq;
			
			if (wql->wql_subqueue == wq_sub) {
				sq = &wq_sub->wqs_sublinks;
				queue_remove(q, wql, wait_queue_link_t, wql_links);
				queue_remove(sq, wql, wait_queue_link_t, wql_sublinks);
				return(KERN_SUCCESS);
			}
		}

		wq_element = (wait_queue_element_t)
			     queue_next((queue_t) wq_element);
	}
	/* due to dropping the sub's lock to get to this routine we can see
	 * no entries in waitqueue. It is valid case, so we should just return
	 */
	return(KERN_FAILURE);
}

/*
 *	Routine:	wait_subqueue_unlink_all
 *	Purpose:
 *		Remove the linkage between a wait queue and its subordinate.
 *	Conditions:
 *		The wait queue being must be a member sub queue
 */
kern_return_t
wait_subqueue_unlink_all(
	wait_queue_sub_t wq_sub)
{
	wait_queue_link_t wql;
	wait_queue_t wq;
	queue_t q;
	kern_return_t kret;
	spl_t s;

	assert(wait_queue_is_sub(wq_sub));

retry:
	s = splsched();
	wqs_lock(wq_sub);

	q = &wq_sub->wqs_sublinks;

	wql = (wait_queue_link_t)queue_first(q);
	while (!queue_end(q, (queue_entry_t)wql)) {
		wq = wql->wql_queue;
		if (wait_queue_lock_try(wq)) {
#if 0
			queue_t q1;

				q1 = &wq->wq_queue;

				queue_remove(q1, wql, wait_queue_link_t, wql_links);
				queue_remove(q, wql, wait_queue_link_t, wql_sublinks);
#else
				if ((kret = wait_queue_unlink_nofree(wq, wq_sub)) != KERN_SUCCESS) {
				queue_remove(q, wql, wait_queue_link_t, wql_sublinks);

}
#endif
				wait_queue_unlock(wq);
				wql = (wait_queue_link_t)queue_first(q);
		} else {
			wqs_unlock(wq_sub);
			splx(s);
			mutex_pause();
			goto retry;
		}
	}
	wqs_unlock(wq_sub);
	splx(s);
	return(KERN_SUCCESS);
}	


/*
 *	Routine:	wait_queue_unlinkall_nofree
 *	Purpose:
 *		Remove the linkage between a wait queue and all subordinates.
 */

kern_return_t
wait_queue_unlinkall_nofree(
	wait_queue_t wq)
{
	wait_queue_element_t wq_element;
	wait_queue_sub_t wq_sub;
	queue_t q;
	spl_t s;


	s = splsched();
	wait_queue_lock(wq);

	q = &wq->wq_queue;

	wq_element = (wait_queue_element_t) queue_first(q);
	while (!queue_end(q, (queue_entry_t)wq_element)) {

		if (wq_element->wqe_event == WAIT_QUEUE_SUBORDINATE) {
			wait_queue_link_t wql = (wait_queue_link_t)wq_element;
			queue_t sq;
			
				wq_sub = wql->wql_subqueue;
				wqs_lock(wq_sub);
				sq = &wq_sub->wqs_sublinks;
				queue_remove(q, wql, wait_queue_link_t, wql_links);
				queue_remove(sq, wql, wait_queue_link_t, wql_sublinks);
				wqs_unlock(wq_sub);
				wq_element = (wait_queue_element_t) queue_first(q);
		} else {
			wq_element = (wait_queue_element_t)
			     queue_next((queue_t) wq_element);
		}

	}
	wait_queue_unlock(wq);
	splx(s);

	return(KERN_SUCCESS);
}	
/*
 *	Routine:	wait_queue_unlink_one
 *	Purpose:
 *		Find and unlink one subordinate wait queue
 *	Conditions:
 *		Nothing of interest locked.
 */
void
wait_queue_unlink_one(
	wait_queue_t wq,
	wait_queue_sub_t *wq_subp)
{
	wait_queue_element_t wq_element;
	queue_t q;
	spl_t s;

	s = splsched();
	wait_queue_lock(wq);

	q = &wq->wq_queue;

	wq_element = (wait_queue_element_t) queue_first(q);
	while (!queue_end(q, (queue_entry_t)wq_element)) {

		if (wq_element->wqe_event == WAIT_QUEUE_SUBORDINATE) {
			wait_queue_link_t wql = (wait_queue_link_t)wq_element;
			wait_queue_sub_t wq_sub = wql->wql_subqueue;
			queue_t sq;

			wqs_lock(wq_sub);
			sq = &wq_sub->wqs_sublinks;
			queue_remove(q, wql, wait_queue_link_t, wql_links);
			queue_remove(sq, wql, wait_queue_link_t, wql_sublinks);
			wqs_unlock(wq_sub);
			wait_queue_unlock(wq);
			splx(s);
			kfree((vm_offset_t)wql,sizeof(struct wait_queue_link));
			*wq_subp = wq_sub;
			return;
		}

		wq_element = (wait_queue_element_t)
			     queue_next((queue_t) wq_element);
	}
	wait_queue_unlock(wq);
	splx(s);
	*wq_subp = WAIT_QUEUE_SUB_NULL;
}	

/*
 *	Routine:	wait_queue_assert_wait_locked
 *	Purpose:
 *		Insert the current thread into the supplied wait queue
 *		waiting for a particular event to be posted to that queue.
 *
 *	Conditions:
 *		The wait queue is assumed locked.
 *
 */
boolean_t
wait_queue_assert_wait_locked(
	wait_queue_t wq,
	event_t event,
	int interruptible,
	boolean_t unlock)
{
	thread_t thread = current_thread();
	boolean_t ret;


	if (wq->wq_issub && wq->wq_isprepost) {
		wait_queue_sub_t wqs = (wait_queue_sub_t)wq;

		if (wqs->wqs_refcount > 0) {
			if (unlock)
				wait_queue_unlock(wq);
			return(FALSE);
		}
	}

	thread_lock(thread);

	/*
	 * This is the extent to which we currently take scheduling attributes
	 * into account.  If the thread is vm priviledged, we stick it at
	 * the front of the queue.  Later, these queues will honor the policy
	 * value set at wait_queue_init time.
	 */
	if (thread->vm_privilege)
		enqueue_head(&wq->wq_queue, (queue_entry_t) thread);
	else
		enqueue_tail(&wq->wq_queue, (queue_entry_t) thread);
	thread->wait_event = event;
	thread->wait_queue = wq;
	thread_mark_wait_locked(thread, interruptible);
	thread_unlock(thread);
	if (unlock)
		wait_queue_unlock(wq);
	return(TRUE);
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
boolean_t
wait_queue_assert_wait(
	wait_queue_t wq,
	event_t event,
	int interruptible)
{
	spl_t s;
	boolean_t ret;

	s = splsched();
	wait_queue_lock(wq);
	ret = wait_queue_assert_wait_locked(wq, event, interruptible, TRUE);
	/* wait queue unlocked */
	splx(s);
	return(ret);
}


/*
 *	Routine:	wait_queue_select_all
 *	Purpose:
 *		Select all threads off a wait queue that meet the
 *		supplied criteria.
 *
 *	Conditions:
 *		at splsched
 *		wait queue locked
 *		wake_queue initialized and ready for insertion
 *		possibly recursive
 *
 *	Returns:
 *		a queue of locked threads
 */
void
_wait_queue_select_all(
	wait_queue_t wq,
	event_t event,
	queue_t wake_queue)
{
	wait_queue_element_t wq_element;
	wait_queue_element_t wqe_next;
	queue_t q;

	q = &wq->wq_queue;

	wq_element = (wait_queue_element_t) queue_first(q);
	while (!queue_end(q, (queue_entry_t)wq_element)) {
		wqe_next = (wait_queue_element_t)
			   queue_next((queue_t) wq_element);

		/*
		 * We may have to recurse if this is a compound wait queue.
		 */
		if (wq_element->wqe_event == WAIT_QUEUE_SUBORDINATE) {
			wait_queue_link_t wql = (wait_queue_link_t)wq_element;
			wait_queue_t sub_queue;

			/*
			 * We have to check the subordinate wait queue.
			 */
			sub_queue = (wait_queue_t)wql->wql_subqueue;
			wait_queue_lock(sub_queue);
			if (sub_queue->wq_isprepost) {
				wait_queue_sub_t wqs = (wait_queue_sub_t)sub_queue;
				
				/*
				 * Preposting is only for subordinates and wait queue
				 * is the first element of subordinate 
				 */
				wqs->wqs_refcount++;
			}
			if (! wait_queue_empty(sub_queue)) 
				_wait_queue_select_all(sub_queue, event, wake_queue);
			wait_queue_unlock(sub_queue);
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
				t->wait_event = NO_EVENT;
				t->at_safe_point = FALSE;
				/* returned locked */
			}
		}
		wq_element = wqe_next;
	}
}

/*
 *      Routine:        wait_queue_wakeup_all_locked
 *      Purpose:
 *              Wakeup some number of threads that are in the specified
 *              wait queue and waiting on the specified event.
 *      Conditions:
 *              wait queue already locked (may be released).
 *      Returns:
 *              KERN_SUCCESS - Threads were woken up
 *              KERN_NOT_WAITING - No threads were waiting <wq,event> pair
 */
kern_return_t
wait_queue_wakeup_all_locked(
        wait_queue_t wq,
        event_t event,
        int result,
        boolean_t unlock)
{
        queue_head_t wake_queue_head;
        queue_t q = &wake_queue_head;
        kern_return_t ret = KERN_NOT_WAITING;

        assert(wait_queue_held(wq));

        queue_init(q);

        /*
         * Select the threads that we will wake up.  The threads
         * are returned to us locked and cleanly removed from the
         * wait queue.
         */
        _wait_queue_select_all(wq, event, q);
        if (unlock)
            wait_queue_unlock(wq);

        /*
         * For each thread, set it running.
         */
        while (!queue_empty (q)) {
                thread_t thread = (thread_t) dequeue(q);
                thread_go_locked(thread, result);
                thread_unlock(thread);
                ret = KERN_SUCCESS;
        }
        return ret;
}


/*
 *      Routine:        wait_queue_wakeup_all
 *      Purpose:
 *              Wakeup some number of threads that are in the specified
 *              wait queue and waiting on the specified event.
 *
 *      Conditions:
 *              Nothing locked
 *
 *      Returns:
 *              KERN_SUCCESS - Threads were woken up
 *              KERN_NOT_WAITING - No threads were waiting <wq,event> pair
 */
kern_return_t
wait_queue_wakeup_all(
        wait_queue_t wq,
        event_t event,
        int result)
{
        kern_return_t ret;
        spl_t s;

        s = splsched();
        wait_queue_lock(wq);
        ret = wait_queue_wakeup_all_locked(wq, event, result, TRUE);
        /* lock released */
        splx(s);

        return ret;
}

/*
 *	Routine:	wait_queue_select_one
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
thread_t
_wait_queue_select_one(
	wait_queue_t wq,
	event_t event)
{
	wait_queue_element_t wq_element;
	wait_queue_element_t wqe_next;
	thread_t t = THREAD_NULL;
	queue_t q;

	assert(wq->wq_fifo);

	q = &wq->wq_queue;

	wq_element = (wait_queue_element_t) queue_first(q);
	while (!queue_end(q, (queue_entry_t)wq_element)) {
		wqe_next = (wait_queue_element_t)
			       queue_next((queue_t) wq_element);

		/*
		 * We may have to recurse if this is a compound wait queue.
		 */
		if (wq_element->wqe_event == WAIT_QUEUE_SUBORDINATE) {
			wait_queue_link_t wql = (wait_queue_link_t)wq_element;
			wait_queue_t sub_queue;

			/*
			 * We have to check the subordinate wait queue.
			 */
			sub_queue = (wait_queue_t)wql->wql_subqueue;
			wait_queue_lock(sub_queue);
			if (! wait_queue_empty(sub_queue)) {
				t = _wait_queue_select_one(sub_queue, event);
			}
			wait_queue_unlock(sub_queue);
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
				t->wait_event = NO_EVENT;
				t->at_safe_point = FALSE;
				return t;	/* still locked */
			}
		}
		wq_element = wqe_next;
	}
	return THREAD_NULL;
}

/*
 *	Routine:	wait_queue_peek_locked
 *	Purpose:
 *		Select the best thread from a wait queue that meet the
 *		supplied criteria, but leave it on the queue you it was
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
 *		Only the waitq the thread was actually found on is locked
 *		after this.
 */
void
wait_queue_peek_locked(
	wait_queue_t wq,
	event_t event,
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
		wqe_next = (wait_queue_element_t)
			       queue_next((queue_t) wq_element);

		/*
		 * We may have to recurse if this is a compound wait queue.
		 */
		if (wq_element->wqe_event == WAIT_QUEUE_SUBORDINATE) {
			wait_queue_link_t wql = (wait_queue_link_t)wq_element;
			wait_queue_t sub_queue;

			/*
			 * We have to check the subordinate wait queue.
			 */
			sub_queue = (wait_queue_t)wql->wql_subqueue;
			wait_queue_lock(sub_queue);
			if (! wait_queue_empty(sub_queue)) {
				wait_queue_peek_locked(sub_queue, event, tp, wqp);
			}
			if (*tp != THREAD_NULL)
				return;  /* thread and its waitq locked */

			wait_queue_unlock(sub_queue);
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
	thread->wait_event = NO_EVENT;
	thread->at_safe_point = FALSE;
	if (unlock)
		wait_queue_unlock(waitq);
}


/*
 *	Routine:	wait_queue_select_thread
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
kern_return_t
_wait_queue_select_thread(
	wait_queue_t wq,
	event_t event,
	thread_t thread)
{
	wait_queue_element_t wq_element;
	wait_queue_element_t wqe_next;
	kern_return_t res = KERN_NOT_WAITING;
	queue_t q = &wq->wq_queue;

	assert(wq->wq_fifo);

	thread_lock(thread);
	if ((thread->wait_queue == wq) && (thread->wait_event == event)) {
		remqueue(q, (queue_entry_t) thread);
		thread->at_safe_point = FALSE;
		thread->wait_event = NO_EVENT;
		thread->wait_queue = WAIT_QUEUE_NULL;
		/* thread still locked */
		return KERN_SUCCESS;
	}
	thread_unlock(thread);
	
	/*
	 * The wait_queue associated with the thread may be one of this
	 * wait queue's subordinates.  Go see.  If so, removing it from
	 * there is like removing it from here.
	 */
	wq_element = (wait_queue_element_t) queue_first(q);
	while (!queue_end(q, (queue_entry_t)wq_element)) {
		wqe_next = (wait_queue_element_t)
			       queue_next((queue_t) wq_element);

		if (wq_element->wqe_event == WAIT_QUEUE_SUBORDINATE) {
			wait_queue_link_t wql = (wait_queue_link_t)wq_element;
			wait_queue_t sub_queue;

			sub_queue = (wait_queue_t)wql->wql_subqueue;
			wait_queue_lock(sub_queue);
			if (! wait_queue_empty(sub_queue)) {
				res = _wait_queue_select_thread(sub_queue,
								event,
								thread);
			}
			wait_queue_unlock(sub_queue);
			if (res == KERN_SUCCESS)
				return KERN_SUCCESS;
		}
		wq_element = wqe_next;
	}
	return res;
}


/*
 *	Routine:	wait_queue_wakeup_identity_locked
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
thread_t
wait_queue_wakeup_identity_locked(
	wait_queue_t wq,
	event_t event,
	int result,
	boolean_t unlock)
{
	thread_t thread;

	assert(wait_queue_held(wq));

	thread = _wait_queue_select_one(wq, event);
	if (unlock)
		wait_queue_unlock(wq);

	if (thread)
		thread_go_locked(thread, result);
	return thread;  /* still locked if not NULL */
}


/*
 *	Routine:	wait_queue_wakeup_one_locked
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
kern_return_t
wait_queue_wakeup_one_locked(
	wait_queue_t wq,
	event_t event,
	int result,
	boolean_t unlock)
{
	thread_t thread;

	assert(wait_queue_held(wq));

	thread = _wait_queue_select_one(wq, event);
	if (unlock)
		wait_queue_unlock(wq);

	if (thread) {
		thread_go_locked(thread, result);
		thread_unlock(thread);
		return KERN_SUCCESS;
	}

	return KERN_NOT_WAITING;
}

/*
 *	Routine:	wait_queue_wakeup_one
 *	Purpose:
 *		Wakeup the most appropriate thread that is in the specified
 *		wait queue for the specified event.
 *
 *	Conditions:
 *		Nothing locked
 *
 *	Returns:
 *		KERN_SUCCESS - Thread was woken up
 *		KERN_NOT_WAITING - No thread was waiting <wq,event> pair
 */
kern_return_t
wait_queue_wakeup_one(
	wait_queue_t wq,
	event_t event,
	int result)
{
	thread_t thread;
	spl_t s;

	s = splsched();
	wait_queue_lock(wq);
	thread = _wait_queue_select_one(wq, event);
	wait_queue_unlock(wq);

	if (thread) {
		thread_go_locked(thread, result);
		thread_unlock(thread);
		splx(s);
		return KERN_SUCCESS;
	}

	splx(s);
	return KERN_NOT_WAITING;
}



/*
 *	Routine:	wait_queue_wakeup_thread_locked
 *	Purpose:
 *		Wakeup the particular thread that was specified if and only
 *		it was in this wait queue (or one of it's subordinate queues)
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
kern_return_t
wait_queue_wakeup_thread_locked(
	wait_queue_t wq,
	event_t event,
	thread_t thread,
	int result,
	boolean_t unlock)
{
	kern_return_t res;

	assert(wait_queue_held(wq));

	/*
	 * See if the thread was still waiting there.  If so, it got
	 * dequeued and returned locked.
	 */
	res = _wait_queue_select_thread(wq, event, thread);
	if (unlock)
	    wait_queue_unlock(wq);

	if (res != KERN_SUCCESS)
		return KERN_NOT_WAITING;

	thread_go_locked(thread, result);
	thread_unlock(thread);
	return KERN_SUCCESS;
}

/*
 *	Routine:	wait_queue_wakeup_thread
 *	Purpose:
 *		Wakeup the particular thread that was specified if and only
 *		it was in this wait queue (or one of it's subordinate queues)
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
	int result)
{
	kern_return_t res;
	spl_t s;

	s = splsched();
	wait_queue_lock(wq);
	res = _wait_queue_select_thread(wq, event, thread);
	wait_queue_unlock(wq);

	if (res == KERN_SUCCESS) {
		thread_go_locked(thread, result);
		thread_unlock(thread);
		splx(s);
		return KERN_SUCCESS;
	}
	splx(s);
	return KERN_NOT_WAITING;
}


/*
 *	Routine:	wait_queue_remove
 *	Purpose:
 *		Normal removal operations from wait queues drive from the
 *		wait queue to select a thread.  However, if a thread is
 *		interrupted out of a wait, this routine is called to
 *		remove it from whatever wait queue it may be in.
 *
 *	Conditions:
 *		splsched
 *		thread locked on entry and exit, but may be dropped.
 *
 *	Returns:
 *		KERN_SUCCESS - if thread was in a wait queue
 *		KERN_NOT_WAITING - it was not
 */
kern_return_t
wait_queue_remove(
        thread_t thread)
{
	wait_queue_t wq = thread->wait_queue;

	if (wq == WAIT_QUEUE_NULL)
		return KERN_NOT_WAITING;

	/*
	 * have to get the locks again in the right order.
	 */
	thread_unlock(thread);
	wait_queue_lock(wq);
	thread_lock(thread);
	
	if (thread->wait_queue == wq) {
		remqueue(&wq->wq_queue, (queue_entry_t)thread);
		thread->wait_queue = WAIT_QUEUE_NULL;
		thread->wait_event = NO_EVENT;
		thread->at_safe_point = FALSE;
		wait_queue_unlock(wq);
		return KERN_SUCCESS;
	} else {
		wait_queue_unlock(wq);
		return KERN_NOT_WAITING; /* anymore */
	}
}


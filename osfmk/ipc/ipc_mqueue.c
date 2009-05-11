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
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
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
 *	File:	ipc/ipc_mqueue.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Functions to manipulate IPC message queues.
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2006 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */
    

#include <mach/port.h>
#include <mach/message.h>
#include <mach/sync_policy.h>

#include <kern/assert.h>
#include <kern/counters.h>
#include <kern/sched_prim.h>
#include <kern/ipc_kobject.h>
#include <kern/ipc_mig.h>	/* XXX - for mach_msg_receive_continue */
#include <kern/misc_protos.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/wait_queue.h>

#include <ipc/ipc_mqueue.h>
#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_pset.h>
#include <ipc/ipc_space.h>

#include <ddb/tr.h>

#if CONFIG_MACF_MACH
#include <security/mac_mach_internal.h>
#endif

int ipc_mqueue_full;		/* address is event for queue space */
int ipc_mqueue_rcv;		/* address is event for message arrival */

#define TR_ENABLE 0

/* forward declarations */
void ipc_mqueue_receive_results(wait_result_t result);

/*
 *	Routine:	ipc_mqueue_init
 *	Purpose:
 *		Initialize a newly-allocated message queue.
 */
void
ipc_mqueue_init(
	ipc_mqueue_t	mqueue,
	boolean_t	is_set)
{
	if (is_set) {
		wait_queue_set_init(&mqueue->imq_set_queue, SYNC_POLICY_FIFO);
	} else {
		wait_queue_init(&mqueue->imq_wait_queue, SYNC_POLICY_FIFO);
		ipc_kmsg_queue_init(&mqueue->imq_messages);
		mqueue->imq_seqno = 0;
		mqueue->imq_msgcount = 0;
		mqueue->imq_qlimit = MACH_PORT_QLIMIT_DEFAULT;
		mqueue->imq_fullwaiters = FALSE;
	}
}

/*
 *	Routine:	ipc_mqueue_member
 *	Purpose:
 *		Indicate whether the (port) mqueue is a member of
 *		this portset's mqueue.  We do this by checking
 *		whether the portset mqueue's waitq is an member of
 *		the port's mqueue waitq.
 *	Conditions:
 *		the portset's mqueue is not already a member
 *		this may block while allocating linkage structures.
 */

boolean_t
ipc_mqueue_member(
	ipc_mqueue_t		port_mqueue,
	ipc_mqueue_t		set_mqueue)
{
	wait_queue_t	port_waitq = &port_mqueue->imq_wait_queue;
	wait_queue_set_t set_waitq = &set_mqueue->imq_set_queue;

	return (wait_queue_member(port_waitq, set_waitq));

}

/*
 *	Routine:	ipc_mqueue_remove
 *	Purpose:
 *		Remove the association between the queue and the specified
 *		set message queue.
 */

kern_return_t
ipc_mqueue_remove(
	ipc_mqueue_t	 mqueue,
	ipc_mqueue_t	 set_mqueue)
{
	wait_queue_t	 mq_waitq = &mqueue->imq_wait_queue;
	wait_queue_set_t set_waitq = &set_mqueue->imq_set_queue;

	return wait_queue_unlink(mq_waitq, set_waitq);
}

/*
 *	Routine:	ipc_mqueue_remove_from_all
 *	Purpose:
 *		Remove the mqueue from all the sets it is a member of
 *	Conditions:
 *		Nothing locked.
 */
void
ipc_mqueue_remove_from_all(
	ipc_mqueue_t	mqueue)
{
	wait_queue_t	mq_waitq = &mqueue->imq_wait_queue;

	wait_queue_unlink_all(mq_waitq);
	return;
}

/*
 *	Routine:	ipc_mqueue_remove_all
 *	Purpose:
 *		Remove all the member queues from the specified set.
 *	Conditions:
 *		Nothing locked.
 */
void
ipc_mqueue_remove_all(
	ipc_mqueue_t	mqueue)
{
	wait_queue_set_t	mq_setq = &mqueue->imq_set_queue;

	wait_queue_set_unlink_all(mq_setq);
	return;
}


/*
 *	Routine:	ipc_mqueue_add
 *	Purpose:
 *		Associate the portset's mqueue with the port's mqueue.
 *		This has to be done so that posting the port will wakeup
 *		a portset waiter.  If there are waiters on the portset
 *		mqueue and messages on the port mqueue, try to match them
 *		up now.
 *	Conditions:
 *		May block.
 */
kern_return_t
ipc_mqueue_add(
	ipc_mqueue_t	 port_mqueue,
	ipc_mqueue_t	 set_mqueue)
{
	wait_queue_t	 port_waitq = &port_mqueue->imq_wait_queue;
	wait_queue_set_t set_waitq = &set_mqueue->imq_set_queue;
	ipc_kmsg_queue_t kmsgq;
	ipc_kmsg_t       kmsg, next;
	kern_return_t	 kr;
	spl_t		 s;

	kr = wait_queue_link(port_waitq, set_waitq);
	if (kr != KERN_SUCCESS)
		return kr;

	/*
	 * Now that the set has been added to the port, there may be
	 * messages queued on the port and threads waiting on the set
	 * waitq.  Lets get them together.
	 */
	s = splsched();
	imq_lock(port_mqueue);
	kmsgq = &port_mqueue->imq_messages;
	for (kmsg = ipc_kmsg_queue_first(kmsgq);
	     kmsg != IKM_NULL;
	     kmsg = next) {
		next = ipc_kmsg_queue_next(kmsgq, kmsg);

		for (;;) {
			thread_t th;

			th = wait_queue_wakeup64_identity_locked(
						port_waitq,
						IPC_MQUEUE_RECEIVE,
						THREAD_AWAKENED,
						FALSE);
			/* waitq/mqueue still locked, thread locked */

			if (th == THREAD_NULL)
				goto leave;

			/*
			 * Found a receiver. see if they can handle the message
			 * correctly (the message is not too large for them, or
			 * they didn't care to be informed that the message was
			 * too large).  If they can't handle it, take them off
			 * the list and let them go back and figure it out and
			 * just move onto the next.
			 */
			if (th->ith_msize <
			    kmsg->ikm_header->msgh_size +
			    REQUESTED_TRAILER_SIZE(th->ith_option)) {
				th->ith_state = MACH_RCV_TOO_LARGE;
				th->ith_msize = kmsg->ikm_header->msgh_size;
				if (th->ith_option & MACH_RCV_LARGE) {
					/*
					 * let him go without message
					 */
					th->ith_kmsg = IKM_NULL;
					th->ith_seqno = 0;
					thread_unlock(th);
					continue; /* find another thread */
				}
			} else {
				th->ith_state = MACH_MSG_SUCCESS;
			}

			/*
			 * This thread is going to take this message,
			 * so give it to him.
			 */
			ipc_kmsg_rmqueue(kmsgq, kmsg);
			ipc_mqueue_release_msgcount(port_mqueue);

			th->ith_kmsg = kmsg;
			th->ith_seqno = port_mqueue->imq_seqno++;
			thread_unlock(th);
			break;  /* go to next message */
		}
			
	}
 leave:
	imq_unlock(port_mqueue);
	splx(s);
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_mqueue_changed
 *	Purpose:
 *		Wake up receivers waiting in a message queue.
 *	Conditions:
 *		The message queue is locked.
 */

void
ipc_mqueue_changed(
	ipc_mqueue_t		mqueue)
{
	wait_queue_wakeup64_all_locked(
				&mqueue->imq_wait_queue,
				IPC_MQUEUE_RECEIVE,
				THREAD_RESTART,
				FALSE);		/* unlock waitq? */
}


		

/*
 *	Routine:	ipc_mqueue_send
 *	Purpose:
 *		Send a message to a message queue.  The message holds a reference
 *		for the destination port for this message queue in the 
 *		msgh_remote_port field.
 *
 *		If unsuccessful, the caller still has possession of
 *		the message and must do something with it.  If successful,
 *		the message is queued, given to a receiver, or destroyed.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	The message was accepted.
 *		MACH_SEND_TIMED_OUT	Caller still has message.
 *		MACH_SEND_INTERRUPTED	Caller still has message.
 */
mach_msg_return_t
ipc_mqueue_send(
	ipc_mqueue_t		mqueue,
	ipc_kmsg_t			kmsg,
	mach_msg_option_t	option,
	mach_msg_timeout_t	send_timeout)
{
	int wresult;
	spl_t s;

	/*
	 *  Don't block if:
	 *	1) We're under the queue limit.
	 *	2) Caller used the MACH_SEND_ALWAYS internal option.
	 *	3) Message is sent to a send-once right.
	 */
	s = splsched();
	imq_lock(mqueue);

	if (!imq_full(mqueue) ||
	    (!imq_full_kernel(mqueue) && 
	     ((option & MACH_SEND_ALWAYS) ||
	      (MACH_MSGH_BITS_REMOTE(kmsg->ikm_header->msgh_bits) ==
	       MACH_MSG_TYPE_PORT_SEND_ONCE)))) {
		mqueue->imq_msgcount++;
		assert(mqueue->imq_msgcount > 0);
		imq_unlock(mqueue);
		splx(s);
	} else {
		thread_t cur_thread = current_thread();
		uint64_t deadline;

		/* 
		 * We have to wait for space to be granted to us.
		 */
		if ((option & MACH_SEND_TIMEOUT) && (send_timeout == 0)) {
			imq_unlock(mqueue);
			splx(s);
			return MACH_SEND_TIMED_OUT;
		}
		if (imq_full_kernel(mqueue)) {
			imq_unlock(mqueue);
			splx(s);
			return MACH_SEND_NO_BUFFER;
		}
		mqueue->imq_fullwaiters = TRUE;
		thread_lock(cur_thread);
		if (option & MACH_SEND_TIMEOUT)
			clock_interval_to_deadline(send_timeout, 1000*NSEC_PER_USEC, &deadline);
		else
			deadline = 0;
		wresult = wait_queue_assert_wait64_locked(
						&mqueue->imq_wait_queue,
						IPC_MQUEUE_FULL,
						THREAD_ABORTSAFE, deadline,
						cur_thread);
		thread_unlock(cur_thread);
		imq_unlock(mqueue);
		splx(s);
		
		if (wresult == THREAD_WAITING) {
			wresult = thread_block(THREAD_CONTINUE_NULL);
			counter(c_ipc_mqueue_send_block++);
		}
		
		switch (wresult) {
		case THREAD_TIMED_OUT:
			assert(option & MACH_SEND_TIMEOUT);
			return MACH_SEND_TIMED_OUT;
			
		case THREAD_AWAKENED:
			/* we can proceed - inherited msgcount from waker */
			assert(mqueue->imq_msgcount > 0);
			break;
			
		case THREAD_INTERRUPTED:
			return MACH_SEND_INTERRUPTED;
			
		case THREAD_RESTART:
		default:
			panic("ipc_mqueue_send");
		}
	}

	ipc_mqueue_post(mqueue, kmsg);
	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	ipc_mqueue_release_msgcount
 *	Purpose:
 *		Release a message queue reference in the case where we
 *		found a waiter.
 *
 *	Conditions:
 *		The message queue is locked.
 *		The message corresponding to this reference is off the queue.
 */
void
ipc_mqueue_release_msgcount(
	ipc_mqueue_t mqueue)	
{
	assert(imq_held(mqueue));
	assert(mqueue->imq_msgcount > 1 || ipc_kmsg_queue_empty(&mqueue->imq_messages));

	mqueue->imq_msgcount--;

	if (!imq_full(mqueue) && mqueue->imq_fullwaiters) {
		if (wait_queue_wakeup64_one_locked(
						&mqueue->imq_wait_queue,
						IPC_MQUEUE_FULL,
						THREAD_AWAKENED,
						FALSE) != KERN_SUCCESS) {
			mqueue->imq_fullwaiters = FALSE;
		} else {
			/* gave away our slot - add reference back */
			mqueue->imq_msgcount++; 
		}
	}
}

/*
 *	Routine:	ipc_mqueue_post
 *	Purpose:
 *		Post a message to a waiting receiver or enqueue it.  If a
 *		receiver is waiting, we can release our reserved space in
 *		the message queue.
 *
 *	Conditions:
 *		If we need to queue, our space in the message queue is reserved.
 */
void
ipc_mqueue_post(
	register ipc_mqueue_t 	mqueue,
	register ipc_kmsg_t		kmsg)
{

	spl_t s;

	/*
	 *	While the msg queue	is locked, we have control of the
	 *  kmsg, so the ref in	it for the port is still good.
	 *
	 *	Check for a receiver for the message.
	 */
	s = splsched();
	imq_lock(mqueue);
	for (;;) {
		wait_queue_t waitq = &mqueue->imq_wait_queue;
		thread_t receiver;

		receiver = wait_queue_wakeup64_identity_locked(
							waitq,
							IPC_MQUEUE_RECEIVE,
							THREAD_AWAKENED,
							FALSE);
		/* waitq still locked, thread locked */

		if (receiver == THREAD_NULL) {
			/* 
			 * no receivers; queue kmsg
			 */
			assert(mqueue->imq_msgcount > 0);
			ipc_kmsg_enqueue_macro(&mqueue->imq_messages, kmsg);
			break;
		}
		
		/*
		 * We found a waiting thread.
		 * If the message is too large or the scatter list is too small
		 * the thread we wake up will get that as its status.
		 */
		if (receiver->ith_msize <
		    (kmsg->ikm_header->msgh_size) +
		    REQUESTED_TRAILER_SIZE(receiver->ith_option)) {
			receiver->ith_msize = kmsg->ikm_header->msgh_size;
			receiver->ith_state = MACH_RCV_TOO_LARGE;
		} else {
			receiver->ith_state = MACH_MSG_SUCCESS;
		}

		/*
		 * If there is no problem with the upcoming receive, or the
		 * receiver thread didn't specifically ask for special too
		 * large error condition, go ahead and select it anyway.
		 */
		if ((receiver->ith_state == MACH_MSG_SUCCESS) ||
		    !(receiver->ith_option & MACH_RCV_LARGE)) {

			receiver->ith_kmsg = kmsg;
			receiver->ith_seqno = mqueue->imq_seqno++;
			thread_unlock(receiver);

			/* we didn't need our reserved spot in the queue */
			ipc_mqueue_release_msgcount(mqueue);
			break;
		}

		/*
		 * Otherwise, this thread needs to be released to run
		 * and handle its error without getting the message.  We
		 * need to go back and pick another one.
		 */
		receiver->ith_kmsg = IKM_NULL;
		receiver->ith_seqno = 0;
		thread_unlock(receiver);
	}

	imq_unlock(mqueue);
	splx(s);
	
	current_task()->messages_sent++;
	return;
}


/* static */ void
ipc_mqueue_receive_results(wait_result_t saved_wait_result)
{
	thread_t     		self = current_thread();
	mach_msg_option_t	option = self->ith_option;

	/*
	 * why did we wake up?
	 */
	switch (saved_wait_result) {
	case THREAD_TIMED_OUT:
		self->ith_state = MACH_RCV_TIMED_OUT;
		return;

	case THREAD_INTERRUPTED:
		self->ith_state = MACH_RCV_INTERRUPTED;
		return;

	case THREAD_RESTART:
		/* something bad happened to the port/set */
		self->ith_state = MACH_RCV_PORT_CHANGED;
		return;

	case THREAD_AWAKENED:
		/*
		 * We do not need to go select a message, somebody
		 * handed us one (or a too-large indication).
		 */
		switch (self->ith_state) {
		case MACH_RCV_SCATTER_SMALL:
		case MACH_RCV_TOO_LARGE:
			/*
			 * Somebody tried to give us a too large
			 * message. If we indicated that we cared,
			 * then they only gave us the indication,
			 * otherwise they gave us the indication
			 * AND the message anyway.
			 */
			if (option & MACH_RCV_LARGE) {
				return;
			}

		case MACH_MSG_SUCCESS:
			return;

		default:
			panic("ipc_mqueue_receive_results: strange ith_state");
		}

	default:
		panic("ipc_mqueue_receive_results: strange wait_result");
	}
}

void
ipc_mqueue_receive_continue(
	__unused void *param,
	wait_result_t wresult)
{
	ipc_mqueue_receive_results(wresult);
	mach_msg_receive_continue();  /* hard-coded for now */
}

/*
 *	Routine:	ipc_mqueue_receive
 *	Purpose:
 *		Receive a message from a message queue.
 *
 *		If continuation is non-zero, then we might discard
 *		our kernel stack when we block.  We will continue
 *		after unblocking by executing continuation.
 *
 *		If resume is true, then we are resuming a receive
 *		operation after a blocked receive discarded our stack.
 *	Conditions:
 *		Our caller must hold a reference for the port or port set
 *		to which this queue belongs, to keep the queue
 *		from being deallocated.
 *
 *		The kmsg is returned with clean header fields
 *		and with the circular bit turned off.
 *	Returns:
 *		MACH_MSG_SUCCESS	Message returned in kmsgp.
 *		MACH_RCV_TOO_LARGE	Message size returned in kmsgp.
 *		MACH_RCV_TIMED_OUT	No message obtained.
 *		MACH_RCV_INTERRUPTED	No message obtained.
 *		MACH_RCV_PORT_DIED	Port/set died; no message.
 *		MACH_RCV_PORT_CHANGED	Port moved into set; no msg.
 *
 */

void
ipc_mqueue_receive(
	ipc_mqueue_t         mqueue,
	mach_msg_option_t    option,
	mach_msg_size_t      max_size,
	mach_msg_timeout_t   rcv_timeout,
	int                  interruptible)
{
	ipc_kmsg_queue_t        kmsgs;
	wait_result_t           wresult;
	thread_t                self;
	uint64_t				deadline;
	spl_t                   s;
#if CONFIG_MACF_MACH
	ipc_labelh_t lh;
	task_t task;
	int rc;
#endif

	s = splsched();
	imq_lock(mqueue);
	self = current_thread();
	
	if (imq_is_set(mqueue)) {
		wait_queue_link_t wql;
		ipc_mqueue_t port_mq;
		queue_t q;

		q = &mqueue->imq_setlinks;

		/*
		 * If we are waiting on a portset mqueue, we need to see if
		 * any of the member ports have work for us.  If so, try to
		 * deliver one of those messages. By holding the portset's
		 * mqueue lock during the search, we tie up any attempts by
		 * mqueue_deliver or portset membership changes that may
		 * cross our path. But this is a lock order violation, so we
		 * have to do it "softly."  If we don't find a message waiting
		 * for us, we will assert our intention to wait while still
		 * holding that lock.  When we release the lock, the deliver/
		 * change will succeed and find us.
		 */
	search_set:
		queue_iterate(q, wql, wait_queue_link_t, wql_setlinks) {
			port_mq = (ipc_mqueue_t)wql->wql_queue;
			kmsgs = &port_mq->imq_messages;
			
			if (!imq_lock_try(port_mq)) {
				imq_unlock(mqueue);
				splx(s);
				mutex_pause(0);
				s = splsched();
				imq_lock(mqueue);
				goto search_set; /* start again at beginning - SMP */
			}

			/*
			 * If there is still a message to be had, we will
			 * try to select it (may not succeed because of size
			 * and options).  In any case, we deliver those
			 * results back to the user.
			 *
			 * We also move the port's linkage to the tail of the
			 * list for this set (fairness). Future versions will
			 * sort by timestamp or priority.
			 */
			if (ipc_kmsg_queue_first(kmsgs) == IKM_NULL) {
				imq_unlock(port_mq);
				continue;
			}
			queue_remove(q, wql, wait_queue_link_t, wql_setlinks);
			queue_enter(q, wql, wait_queue_link_t, wql_setlinks);
			imq_unlock(mqueue);

			ipc_mqueue_select(port_mq, option, max_size);
			imq_unlock(port_mq);
#if CONFIG_MACF_MACH
			if (self->ith_kmsg != NULL &&
			    self->ith_kmsg->ikm_sender != NULL) {
				lh = self->ith_kmsg->ikm_sender->label;
				task = current_task();
				tasklabel_lock(task);
				ip_lock(lh->lh_port);
				rc = mac_port_check_receive(&task->maclabel,
				    &lh->lh_label);
				ip_unlock(lh->lh_port);
				tasklabel_unlock(task);
				if (rc)
					self->ith_state = MACH_RCV_INVALID_DATA;
			}
#endif
			splx(s);
			return;
			
		}

	} else {

		/*
		 * Receive on a single port. Just try to get the messages.
		 */
	  	kmsgs = &mqueue->imq_messages;
		if (ipc_kmsg_queue_first(kmsgs) != IKM_NULL) {
			ipc_mqueue_select(mqueue, option, max_size);
			imq_unlock(mqueue);
#if CONFIG_MACF_MACH
			if (self->ith_kmsg != NULL &&
			    self->ith_kmsg->ikm_sender != NULL) {
				lh = self->ith_kmsg->ikm_sender->label;
				task = current_task();
				tasklabel_lock(task);
				ip_lock(lh->lh_port);
				rc = mac_port_check_receive(&task->maclabel,
				    &lh->lh_label);
				ip_unlock(lh->lh_port);
				tasklabel_unlock(task);
				if (rc)
					self->ith_state = MACH_RCV_INVALID_DATA;
			}
#endif
			splx(s);
			return;
		}
	}
		
	/*
	 * Looks like we'll have to block.  The mqueue we will
	 * block on (whether the set's or the local port's) is
	 * still locked.
	 */
	if (option & MACH_RCV_TIMEOUT) {
		if (rcv_timeout == 0) {
			imq_unlock(mqueue);
			splx(s);
			self->ith_state = MACH_RCV_TIMED_OUT;
			return;
		}
	}

	thread_lock(self);
	self->ith_state = MACH_RCV_IN_PROGRESS;
	self->ith_option = option;
	self->ith_msize = max_size;

	if (option & MACH_RCV_TIMEOUT)
		clock_interval_to_deadline(rcv_timeout, 1000*NSEC_PER_USEC, &deadline);
	else
		deadline = 0;

	wresult = wait_queue_assert_wait64_locked(&mqueue->imq_wait_queue,
												IPC_MQUEUE_RECEIVE,
												interruptible, deadline,
												self);
	thread_unlock(self);
	imq_unlock(mqueue);
	splx(s);

	if (wresult == THREAD_WAITING) {
		counter((interruptible == THREAD_ABORTSAFE) ? 
			c_ipc_mqueue_receive_block_user++ :
			c_ipc_mqueue_receive_block_kernel++);

		if (self->ith_continuation)
			thread_block(ipc_mqueue_receive_continue);
			/* NOTREACHED */

		wresult = thread_block(THREAD_CONTINUE_NULL);
	}
	ipc_mqueue_receive_results(wresult);
}


/*
 *	Routine:	ipc_mqueue_select
 *	Purpose:
 *		A receiver discovered that there was a message on the queue
 *		before he had to block.  Pick the message off the queue and
 *		"post" it to himself.
 *	Conditions:
 *		mqueue locked.
 *		There is a message.
 *	Returns:
 *		MACH_MSG_SUCCESS	Actually selected a message for ourselves.
 *		MACH_RCV_TOO_LARGE  May or may not have pull it, but it is large
 */
void
ipc_mqueue_select(
	ipc_mqueue_t		mqueue,
	mach_msg_option_t	option,
	mach_msg_size_t		max_size)
{
	thread_t self = current_thread();
	ipc_kmsg_t kmsg;
	mach_msg_return_t mr;
	mach_msg_size_t rcv_size;

	mr = MACH_MSG_SUCCESS;


	/*
	 * Do some sanity checking of our ability to receive
	 * before pulling the message off the queue.
	 */
	kmsg = ipc_kmsg_queue_first(&mqueue->imq_messages);
	assert(kmsg != IKM_NULL);

	/*
	 * If we really can't receive it, but we had the
	 * MACH_RCV_LARGE option set, then don't take it off
	 * the queue, instead return the appropriate error
	 * (and size needed).
	 */
	rcv_size = ipc_kmsg_copyout_size(kmsg, self->map);
	if (rcv_size + REQUESTED_TRAILER_SIZE(option) > max_size) {
		mr = MACH_RCV_TOO_LARGE;
		if (option & MACH_RCV_LARGE) {
			self->ith_kmsg = IKM_NULL;
			self->ith_msize = rcv_size;
			self->ith_seqno = 0;
			self->ith_state = mr;
			return;
		}
	}

	ipc_kmsg_rmqueue_first_macro(&mqueue->imq_messages, kmsg);
	ipc_mqueue_release_msgcount(mqueue);
	self->ith_seqno = mqueue->imq_seqno++;
	self->ith_kmsg = kmsg;
	self->ith_state = mr;

	current_task()->messages_received++;
	return;
}

/*
 *	Routine:	ipc_mqueue_destroy
 *	Purpose:
 *		Destroy a message queue.  Set any blocked senders running.
 *	   	Destroy the kmsgs in the queue.
 *	Conditions:
 *		Nothing locked.
 *		Receivers were removed when the receive right was "changed"
 */
void
ipc_mqueue_destroy(
	ipc_mqueue_t	mqueue) 
{
	ipc_kmsg_queue_t kmqueue;
	ipc_kmsg_t kmsg;
	spl_t s;


	s = splsched();
	imq_lock(mqueue);
	/*
	 *	rouse all blocked senders
	 */
	mqueue->imq_fullwaiters = FALSE;
	wait_queue_wakeup64_all_locked(
				&mqueue->imq_wait_queue,
				IPC_MQUEUE_FULL,
				THREAD_AWAKENED,
				FALSE);

	kmqueue = &mqueue->imq_messages;

	while ((kmsg = ipc_kmsg_dequeue(kmqueue)) != IKM_NULL) {
		imq_unlock(mqueue);
		splx(s);

		ipc_kmsg_destroy_dest(kmsg);

		s = splsched();
		imq_lock(mqueue);
	}
	imq_unlock(mqueue);
	splx(s);
}

/*
 *	Routine:	ipc_mqueue_set_qlimit
 *	Purpose:
 *		Changes a message queue limit; the maximum number
 *		of messages which may be queued.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_mqueue_set_qlimit(
	 ipc_mqueue_t			mqueue,
	 mach_port_msgcount_t	qlimit)
{
	 spl_t s;

	 assert(qlimit <= MACH_PORT_QLIMIT_MAX);

	 /* wake up senders allowed by the new qlimit */
	 s = splsched();
	 imq_lock(mqueue);
	 if (qlimit > mqueue->imq_qlimit) {
		 mach_port_msgcount_t i, wakeup;

		 /* caution: wakeup, qlimit are unsigned */
		 wakeup = qlimit - mqueue->imq_qlimit;

		 for (i = 0; i < wakeup; i++) {
			 if (wait_queue_wakeup64_one_locked(
							&mqueue->imq_wait_queue,
							IPC_MQUEUE_FULL,
							THREAD_AWAKENED,
							FALSE) == KERN_NOT_WAITING) {
					 mqueue->imq_fullwaiters = FALSE;
					 break;
			 }
			 mqueue->imq_msgcount++;  /* give it to the awakened thread */
		 }
	 }
	mqueue->imq_qlimit = qlimit;
	imq_unlock(mqueue);
	splx(s);
}

/*
 *	Routine:	ipc_mqueue_set_seqno
 *	Purpose:
 *		Changes an mqueue's sequence number.
 *	Conditions:
 *		Caller holds a reference to the queue's containing object.
 */
void
ipc_mqueue_set_seqno(
	ipc_mqueue_t		mqueue,
	mach_port_seqno_t	seqno)
{
	spl_t s;

	s = splsched();
	imq_lock(mqueue);
	mqueue->imq_seqno = seqno;
	imq_unlock(mqueue);
	splx(s);
}


/*
 *	Routine:	ipc_mqueue_copyin
 *	Purpose:
 *		Convert a name in a space to a message queue.
 *	Conditions:
 *		Nothing locked.  If successful, the caller gets a ref for
 *		for the object.	This ref ensures the continued existence of
 *		the queue.
 *	Returns:
 *		MACH_MSG_SUCCESS	Found a message queue.
 *		MACH_RCV_INVALID_NAME	The space is dead.
 *		MACH_RCV_INVALID_NAME	The name doesn't denote a right.
 *		MACH_RCV_INVALID_NAME
 *			The denoted right is not receive or port set.
 *		MACH_RCV_IN_SET		Receive right is a member of a set.
 */

mach_msg_return_t
ipc_mqueue_copyin(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_mqueue_t		*mqueuep,
	ipc_object_t		*objectp)
{
	ipc_entry_t entry;
	ipc_object_t object;
	ipc_mqueue_t mqueue;

	is_read_lock(space);
	if (!space->is_active) {
		is_read_unlock(space);
		return MACH_RCV_INVALID_NAME;
	}

	entry = ipc_entry_lookup(space, name);
	if (entry == IE_NULL) {
		is_read_unlock(space);
		return MACH_RCV_INVALID_NAME;
	}

	object = entry->ie_object;

	if (entry->ie_bits & MACH_PORT_TYPE_RECEIVE) {
		ipc_port_t port;

		port = (ipc_port_t) object;
		assert(port != IP_NULL);

		ip_lock(port);
		assert(ip_active(port));
		assert(port->ip_receiver_name == name);
		assert(port->ip_receiver == space);
		is_read_unlock(space);
		mqueue = &port->ip_messages;

	} else if (entry->ie_bits & MACH_PORT_TYPE_PORT_SET) {
		ipc_pset_t pset;

		pset = (ipc_pset_t) object;
		assert(pset != IPS_NULL);

		ips_lock(pset);
		assert(ips_active(pset));
		assert(pset->ips_local_name == name);
		is_read_unlock(space);

		mqueue = &pset->ips_messages;
	} else {
		is_read_unlock(space);
		return MACH_RCV_INVALID_NAME;
	}

	/*
	 *	At this point, the object is locked and active,
	 *	the space is unlocked, and mqueue is initialized.
	 */

	io_reference(object);
	io_unlock(object);

	*objectp = object;
	*mqueuep = mqueue;
	return MACH_MSG_SUCCESS;
}


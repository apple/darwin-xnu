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
#include <kern/waitq.h>

#include <ipc/ipc_mqueue.h>
#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_pset.h>
#include <ipc/ipc_space.h>

#ifdef __LP64__
#include <vm/vm_map.h>
#endif

int ipc_mqueue_full;		/* address is event for queue space */
int ipc_mqueue_rcv;		/* address is event for message arrival */

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
	boolean_t	is_set,
	uint64_t	*reserved_link)
{
	if (is_set) {
		waitq_set_init(&mqueue->imq_set_queue,
			       SYNC_POLICY_FIFO|SYNC_POLICY_PREPOST|SYNC_POLICY_DISABLE_IRQ,
			       reserved_link);
	} else {
		waitq_init(&mqueue->imq_wait_queue, SYNC_POLICY_FIFO|SYNC_POLICY_DISABLE_IRQ);
		ipc_kmsg_queue_init(&mqueue->imq_messages);
		mqueue->imq_seqno = 0;
		mqueue->imq_msgcount = 0;
		mqueue->imq_qlimit = MACH_PORT_QLIMIT_DEFAULT;
		mqueue->imq_fullwaiters = FALSE;
	}
}

void ipc_mqueue_deinit(
	ipc_mqueue_t		mqueue)
{
	boolean_t is_set = imq_is_set(mqueue);

	if (is_set)
		waitq_set_deinit(&mqueue->imq_set_queue);
	else
		waitq_deinit(&mqueue->imq_wait_queue);
}

/*
 *	Routine:	imq_reserve_and_lock
 *	Purpose:
 *		Atomically lock an ipc_mqueue_t object and reserve
 *		an appropriate number of prepost linkage objects for
 *		use in wakeup operations.
 *	Conditions:
 *		mq is unlocked
 */
void
imq_reserve_and_lock(ipc_mqueue_t mq, uint64_t *reserved_prepost, spl_t *spl)
{
	*reserved_prepost = waitq_prepost_reserve(&mq->imq_wait_queue, 0,
						  WAITQ_KEEP_LOCKED, spl);

}


/*
 *	Routine:	imq_release_and_unlock
 *	Purpose:
 *		Unlock an ipc_mqueue_t object, re-enable interrupts,
 *		and release any unused prepost object reservations.
 *	Conditions:
 *		mq is locked
 */
void
imq_release_and_unlock(ipc_mqueue_t mq, uint64_t reserved_prepost, spl_t spl)
{
	assert(imq_held(mq));
	waitq_unlock(&mq->imq_wait_queue);
	splx(spl);
	waitq_prepost_release_reserve(reserved_prepost);
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
	struct waitq *port_waitq = &port_mqueue->imq_wait_queue;
	struct waitq_set *set_waitq = &set_mqueue->imq_set_queue;

	return waitq_member(port_waitq, set_waitq);

}

/*
 *	Routine:	ipc_mqueue_remove
 *	Purpose:
 *		Remove the association between the queue and the specified
 *		set message queue.
 */

kern_return_t
ipc_mqueue_remove(
	ipc_mqueue_t	  mqueue,
	ipc_mqueue_t	  set_mqueue)
{
	struct waitq *mq_waitq = &mqueue->imq_wait_queue;
	struct waitq_set *set_waitq = &set_mqueue->imq_set_queue;

	return waitq_unlink(mq_waitq, set_waitq);
}

/*
 *	Routine:	ipc_mqueue_remove_from_all
 *	Purpose:
 *		Remove the mqueue from all the sets it is a member of
 *	Conditions:
 *		Nothing locked.
 */
void
ipc_mqueue_remove_from_all(ipc_mqueue_t	mqueue)
{
	struct waitq *mq_waitq = &mqueue->imq_wait_queue;

	waitq_unlink_all(mq_waitq);
	return;
}

/*
 *	Routine:	ipc_mqueue_remove_all
 *	Purpose:
 *		Remove all the member queues from the specified set.
 *		Also removes the queue from any containing sets.
 *	Conditions:
 *		Nothing locked.
 */
void
ipc_mqueue_remove_all(ipc_mqueue_t	mqueue)
{
	struct waitq_set *mq_setq = &mqueue->imq_set_queue;
	waitq_set_unlink_all(mq_setq);
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
	ipc_mqueue_t	port_mqueue,
	ipc_mqueue_t	set_mqueue,
	uint64_t	*reserved_link,
	uint64_t	*reserved_prepost)
{
	struct waitq     *port_waitq = &port_mqueue->imq_wait_queue;
	struct waitq_set *set_waitq = &set_mqueue->imq_set_queue;
	ipc_kmsg_queue_t kmsgq;
	ipc_kmsg_t       kmsg, next;
	kern_return_t	 kr;
	spl_t		 s;

	assert(reserved_link && *reserved_link != 0);

	s = splsched();
	imq_lock(port_mqueue);

	/*
	 * The link operation is now under the same lock-hold as
	 * message iteration and thread wakeup, but doesn't have to be...
	 */
	kr = waitq_link(port_waitq, set_waitq, WAITQ_ALREADY_LOCKED, reserved_link);
	if (kr != KERN_SUCCESS) {
		imq_unlock(port_mqueue);
		splx(s);
		return kr;
	}

	/*
	 * Now that the set has been added to the port, there may be
	 * messages queued on the port and threads waiting on the set
	 * waitq.  Lets get them together.
	 */
	kmsgq = &port_mqueue->imq_messages;
	for (kmsg = ipc_kmsg_queue_first(kmsgq);
	     kmsg != IKM_NULL;
	     kmsg = next) {
		next = ipc_kmsg_queue_next(kmsgq, kmsg);

		for (;;) {
			thread_t th;
			mach_msg_size_t msize;
			spl_t th_spl;

			th = waitq_wakeup64_identity_locked(
						port_waitq,
						IPC_MQUEUE_RECEIVE,
						THREAD_AWAKENED, &th_spl,
						reserved_prepost, WAITQ_KEEP_LOCKED);
			/* waitq/mqueue still locked, thread locked */

			if (th == THREAD_NULL)
				goto leave;

			/*
			 * If the receiver waited with a facility not directly
			 * related to Mach messaging, then it isn't prepared to get
			 * handed the message directly.  Just set it running, and
			 * go look for another thread that can.
			 */
			if (th->ith_state != MACH_RCV_IN_PROGRESS) {
				  thread_unlock(th);
				  splx(th_spl);
				  continue;
			}

			/*
			 * Found a receiver. see if they can handle the message
			 * correctly (the message is not too large for them, or
			 * they didn't care to be informed that the message was
			 * too large).  If they can't handle it, take them off
			 * the list and let them go back and figure it out and
			 * just move onto the next.
			 */
			msize = ipc_kmsg_copyout_size(kmsg, th->map);
			if (th->ith_msize <
					(msize + REQUESTED_TRAILER_SIZE(thread_is_64bit(th), th->ith_option))) {
				th->ith_state = MACH_RCV_TOO_LARGE;
				th->ith_msize = msize;
				if (th->ith_option & MACH_RCV_LARGE) {
					/*
					 * let him go without message
					 */
					th->ith_receiver_name = port_mqueue->imq_receiver_name;
					th->ith_kmsg = IKM_NULL;
					th->ith_seqno = 0;
					thread_unlock(th);
					splx(th_spl);
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
			ipc_mqueue_release_msgcount(port_mqueue, IMQ_NULL);

			th->ith_kmsg = kmsg;
			th->ith_seqno = port_mqueue->imq_seqno++;
			thread_unlock(th);
			splx(th_spl);
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
	waitq_wakeup64_all_locked(&mqueue->imq_wait_queue,
				  IPC_MQUEUE_RECEIVE,
				  THREAD_RESTART,
				  NULL,
				  WAITQ_ALL_PRIORITIES,
				  WAITQ_KEEP_LOCKED);
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
 *		mqueue is locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	The message was accepted.
 *		MACH_SEND_TIMED_OUT	Caller still has message.
 *		MACH_SEND_INTERRUPTED	Caller still has message.
 */
mach_msg_return_t
ipc_mqueue_send(
	ipc_mqueue_t		mqueue,
	ipc_kmsg_t		kmsg,
	mach_msg_option_t	option,
	mach_msg_timeout_t	send_timeout,
	spl_t			s)
{
	int wresult;

	/*
	 *  Don't block if:
	 *	1) We're under the queue limit.
	 *	2) Caller used the MACH_SEND_ALWAYS internal option.
	 *	3) Message is sent to a send-once right.
	 */
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
		wresult = waitq_assert_wait64_locked(
						&mqueue->imq_wait_queue,
						IPC_MQUEUE_FULL,
						THREAD_ABORTSAFE,
						TIMEOUT_URGENCY_USER_NORMAL,
						deadline, TIMEOUT_NO_LEEWAY,
						cur_thread);
		thread_unlock(cur_thread);
		imq_unlock(mqueue);
		splx(s);
		
		if (wresult == THREAD_WAITING) {
			wresult = thread_block(THREAD_CONTINUE_NULL);
			counter(c_ipc_mqueue_send_block++);
		}
		
		switch (wresult) {

		case THREAD_AWAKENED:
			/* 
			 * we can proceed - inherited msgcount from waker
			 * or the message queue has been destroyed and the msgcount
			 * has been reset to zero (will detect in ipc_mqueue_post()).
			 */
			break;
			
		case THREAD_TIMED_OUT:
			assert(option & MACH_SEND_TIMEOUT);
			return MACH_SEND_TIMED_OUT;
			
		case THREAD_INTERRUPTED:
			return MACH_SEND_INTERRUPTED;
			
		case THREAD_RESTART:
			/* mqueue is being destroyed */
			return MACH_SEND_INVALID_DEST;
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
 *		There is no need to pass reserved preposts because this will
 *		never prepost to anyone
 */
void
ipc_mqueue_release_msgcount(ipc_mqueue_t port_mq, ipc_mqueue_t set_mq)
{
	(void)set_mq;
	assert(imq_held(port_mq));
	assert(port_mq->imq_msgcount > 1 || ipc_kmsg_queue_empty(&port_mq->imq_messages));

	port_mq->imq_msgcount--;

	if (!imq_full(port_mq) && port_mq->imq_fullwaiters) {
		/*
		 * boost the priority of the awoken thread
		 * (WAITQ_PROMOTE_PRIORITY) to ensure it uses
		 * the message queue slot we've just reserved.
		 *
		 * NOTE: this will never prepost
		 */
		if (waitq_wakeup64_one_locked(&port_mq->imq_wait_queue,
					      IPC_MQUEUE_FULL,
					      THREAD_AWAKENED,
					      NULL,
					      WAITQ_PROMOTE_PRIORITY,
					      WAITQ_KEEP_LOCKED) != KERN_SUCCESS) {
			port_mq->imq_fullwaiters = FALSE;
		} else {
			/* gave away our slot - add reference back */
			port_mq->imq_msgcount++;
		}
	}

	if (ipc_kmsg_queue_empty(&port_mq->imq_messages)) {
		/* no more msgs: invalidate the port's prepost object */
		waitq_clear_prepost_locked(&port_mq->imq_wait_queue, NULL);
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
 *		mqueue is unlocked
 *		If we need to queue, our space in the message queue is reserved.
 */
void
ipc_mqueue_post(
	register ipc_mqueue_t 	mqueue,
	register ipc_kmsg_t		kmsg)
{
	spl_t s;
	uint64_t reserved_prepost = 0;

	/*
	 *	While the msg queue	is locked, we have control of the
	 *  kmsg, so the ref in	it for the port is still good.
	 *
	 *	Check for a receiver for the message.
	 */
	imq_reserve_and_lock(mqueue, &reserved_prepost, &s);
	for (;;) {
		struct waitq *waitq = &mqueue->imq_wait_queue;
		spl_t th_spl;
		thread_t receiver;
		mach_msg_size_t msize;

		receiver = waitq_wakeup64_identity_locked(waitq,
							  IPC_MQUEUE_RECEIVE,
							  THREAD_AWAKENED,
							  &th_spl,
							  &reserved_prepost,
							  WAITQ_KEEP_LOCKED);
		/* waitq still locked, thread locked */

		if (receiver == THREAD_NULL) {
			
			/* 
			 * no receivers; queue kmsg if space still reserved.
			 */
			if (mqueue->imq_msgcount > 0) {
				ipc_kmsg_enqueue_macro(&mqueue->imq_messages, kmsg);
				break;
			}

			/*
			 * Otherwise, the message queue must belong to an inactive
			 * port, so just destroy the message and pretend it was posted.
			 */
			/* clear the waitq boost we may have been given */
			waitq_clear_promotion_locked(waitq, current_thread());
			imq_release_and_unlock(mqueue, reserved_prepost, s);
			ipc_kmsg_destroy(kmsg);
			current_task()->messages_sent++;
			return;
		}
	
		/*
		 * If the receiver waited with a facility not directly
		 * related to Mach messaging, then it isn't prepared to get
		 * handed the message directly.  Just set it running, and
		 * go look for another thread that can.
		 */
		if (receiver->ith_state != MACH_RCV_IN_PROGRESS) {
				  thread_unlock(receiver);
				  splx(th_spl);
				  continue;
		}

	
		/*
		 * We found a waiting thread.
		 * If the message is too large or the scatter list is too small
		 * the thread we wake up will get that as its status.
		 */
		msize =	ipc_kmsg_copyout_size(kmsg, receiver->map);
		if (receiver->ith_msize <
				(msize + REQUESTED_TRAILER_SIZE(thread_is_64bit(receiver), receiver->ith_option))) {
			receiver->ith_msize = msize;
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
			splx(th_spl);

			/* we didn't need our reserved spot in the queue */
			ipc_mqueue_release_msgcount(mqueue, IMQ_NULL);
			break;
		}

		/*
		 * Otherwise, this thread needs to be released to run
		 * and handle its error without getting the message.  We
		 * need to go back and pick another one.
		 */
		receiver->ith_receiver_name = mqueue->imq_receiver_name;
		receiver->ith_kmsg = IKM_NULL;
		receiver->ith_seqno = 0;
		thread_unlock(receiver);
		splx(th_spl);
	}

	/* clear the waitq boost we may have been given */
	waitq_clear_promotion_locked(&mqueue->imq_wait_queue, current_thread());
	imq_release_and_unlock(mqueue, reserved_prepost, s);
	
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
	ipc_mqueue_t            mqueue,
	mach_msg_option_t       option,
	mach_msg_size_t         max_size,
	mach_msg_timeout_t      rcv_timeout,
	int                     interruptible)
{
	wait_result_t           wresult;
        thread_t                self = current_thread();
        
        wresult = ipc_mqueue_receive_on_thread(mqueue, option, max_size,
                                               rcv_timeout, interruptible,
                                               self);
        if (wresult == THREAD_NOT_WAITING)
                return;

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

static int mqueue_process_prepost_receive(void *ctx, struct waitq *waitq,
					  struct waitq_set *wqset)
{
	ipc_mqueue_t     port_mq, *pmq_ptr;

	(void)wqset;
	port_mq = (ipc_mqueue_t)waitq;

	/*
	 * If there are no messages on this queue, skip it and remove
	 * it from the prepost list
	 */
	if (ipc_kmsg_queue_empty(&port_mq->imq_messages))
		return WQ_ITERATE_INVALIDATE_CONTINUE;

	/*
	 * There are messages waiting on this port.
	 * Instruct the prepost iteration logic to break, but keep the
	 * waitq locked.
	 */
	pmq_ptr = (ipc_mqueue_t *)ctx;
	if (pmq_ptr)
		*pmq_ptr = port_mq;
	return WQ_ITERATE_BREAK_KEEP_LOCKED;
}

wait_result_t
ipc_mqueue_receive_on_thread(
        ipc_mqueue_t            mqueue,
	mach_msg_option_t       option,
	mach_msg_size_t         max_size,
	mach_msg_timeout_t      rcv_timeout,
	int                     interruptible,
	thread_t                thread)
{
	wait_result_t           wresult;
	uint64_t		deadline;
	spl_t                   s;

	s = splsched();
	imq_lock(mqueue);
	/* no need to reserve anything: we never prepost to anyone */
	
	if (imq_is_set(mqueue)) {
		ipc_mqueue_t port_mq = IMQ_NULL;
		spl_t set_spl;

		(void)waitq_set_iterate_preposts(&mqueue->imq_set_queue,
						 &port_mq,
						 mqueue_process_prepost_receive,
						 &set_spl);

		if (port_mq != IMQ_NULL) {
			/*
			 * We get here if there is at least one message
			 * waiting on port_mq. We have instructed the prepost
			 * iteration logic to leave both the port_mq and the
			 * set mqueue locked.
			 *
			 * TODO: previously, we would place this port at the
			 *       back of the prepost list...
			 */
			imq_unlock(mqueue);

			/* TODO: if/when port mqueues become non irq safe,
			 *       we won't need this spl, and we should be
			 *       able to call splx(s) (if that's even
			 *       necessary).
			 * For now, we've still disabled interrupts via
			 * imq_reserve_and_lock();
			 */
			splx(set_spl);

			/*
			 * Continue on to handling the message with just
			 * the port mqueue locked.
			 */
			ipc_mqueue_select_on_thread(port_mq, mqueue, option,
						    max_size, thread);

			imq_unlock(port_mq);
			splx(s);
			return THREAD_NOT_WAITING;
		}
	} else {
		ipc_kmsg_queue_t kmsgs;

		/*
		 * Receive on a single port. Just try to get the messages.
		 */
	  	kmsgs = &mqueue->imq_messages;
		if (ipc_kmsg_queue_first(kmsgs) != IKM_NULL) {
			ipc_mqueue_select_on_thread(mqueue, IMQ_NULL, option,
						    max_size, thread);
			imq_unlock(mqueue);
			splx(s);
			return THREAD_NOT_WAITING;
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
			thread->ith_state = MACH_RCV_TIMED_OUT;
			return THREAD_NOT_WAITING;
		}
	}

	/* NOTE: need splsched() here if mqueue no longer needs irq disabled */
	thread_lock(thread);
	thread->ith_state = MACH_RCV_IN_PROGRESS;
	thread->ith_option = option;
	thread->ith_msize = max_size;

	if (option & MACH_RCV_TIMEOUT)
		clock_interval_to_deadline(rcv_timeout, 1000*NSEC_PER_USEC, &deadline);
	else
		deadline = 0;

	wresult = waitq_assert_wait64_locked(&mqueue->imq_wait_queue,
					     IPC_MQUEUE_RECEIVE,
					     interruptible,
					     TIMEOUT_URGENCY_USER_NORMAL,
					     deadline,
					     TIMEOUT_NO_LEEWAY,
					     thread);
	/* preposts should be detected above, not here */
	if (wresult == THREAD_AWAKENED)
		panic("ipc_mqueue_receive_on_thread: sleep walking");

	thread_unlock(thread);
	imq_unlock(mqueue);
	splx(s);
	return wresult;
}


/*
 *	Routine:	ipc_mqueue_select_on_thread
 *	Purpose:
 *		A receiver discovered that there was a message on the queue
 *		before he had to block.  Pick the message off the queue and
 *		"post" it to thread.
 *	Conditions:
 *		mqueue locked.
 *              thread not locked.
 *		There is a message.
 *		No need to reserve prepost objects - it will never prepost
 *
 *	Returns:
 *		MACH_MSG_SUCCESS	Actually selected a message for ourselves.
 *		MACH_RCV_TOO_LARGE  May or may not have pull it, but it is large
 */
void
ipc_mqueue_select_on_thread(
	ipc_mqueue_t		port_mq,
	ipc_mqueue_t		set_mq,
	mach_msg_option_t	option,
	mach_msg_size_t		max_size,
	thread_t                thread)
{
	ipc_kmsg_t kmsg;
	mach_msg_return_t mr = MACH_MSG_SUCCESS;
	mach_msg_size_t rcv_size;

	/*
	 * Do some sanity checking of our ability to receive
	 * before pulling the message off the queue.
	 */
	kmsg = ipc_kmsg_queue_first(&port_mq->imq_messages);
	assert(kmsg != IKM_NULL);

	/*
	 * If we really can't receive it, but we had the
	 * MACH_RCV_LARGE option set, then don't take it off
	 * the queue, instead return the appropriate error
	 * (and size needed).
	 */
	rcv_size = ipc_kmsg_copyout_size(kmsg, thread->map);
	if (rcv_size + REQUESTED_TRAILER_SIZE(thread_is_64bit(thread), option) > max_size) {
		mr = MACH_RCV_TOO_LARGE;
		if (option & MACH_RCV_LARGE) {
			thread->ith_receiver_name = port_mq->imq_receiver_name;
			thread->ith_kmsg = IKM_NULL;
			thread->ith_msize = rcv_size;
			thread->ith_seqno = 0;
			thread->ith_state = mr;
			return;
		}
	}

	ipc_kmsg_rmqueue_first_macro(&port_mq->imq_messages, kmsg);
	ipc_mqueue_release_msgcount(port_mq, set_mq);
	thread->ith_seqno = port_mq->imq_seqno++;
	thread->ith_kmsg = kmsg;
	thread->ith_state = mr;

	current_task()->messages_received++;
	return;
}

/*
 *	Routine:	ipc_mqueue_peek
 *	Purpose:
 *		Peek at a (non-set) message queue to see if it has a message
 *		matching the sequence number provided (if zero, then the
 *		first message in the queue) and return vital info about the
 *		message.
 *
 *	Conditions:
 *		Locks may be held by callers, so this routine cannot block.
 *		Caller holds reference on the message queue.
 */
unsigned
ipc_mqueue_peek(ipc_mqueue_t mq,
                mach_port_seqno_t * seqnop,
                mach_msg_size_t * msg_sizep,
                mach_msg_id_t * msg_idp,
                mach_msg_max_trailer_t * msg_trailerp)
{
	ipc_kmsg_queue_t kmsgq;
	ipc_kmsg_t kmsg;
	mach_port_seqno_t seqno, msgoff;
	int res = 0;
	spl_t s;

	assert(!imq_is_set(mq));

	s = splsched();
	imq_lock(mq);

	seqno = 0;
	if (seqnop != NULL)
		seqno = *seqnop;

	if (seqno == 0) {
		seqno = mq->imq_seqno;
		msgoff = 0;
	} else if (seqno >= mq->imq_seqno && 
		   seqno < mq->imq_seqno + mq->imq_msgcount) {
		msgoff = seqno - mq->imq_seqno;
	} else
		goto out;

	/* look for the message that would match that seqno */
	kmsgq = &mq->imq_messages;
	kmsg = ipc_kmsg_queue_first(kmsgq);
	while (msgoff-- && kmsg != IKM_NULL) {
		kmsg = ipc_kmsg_queue_next(kmsgq, kmsg);
	}
	if (kmsg == IKM_NULL)
		goto out;

	/* found one - return the requested info */
	if (seqnop != NULL)
		*seqnop = seqno;
	if (msg_sizep != NULL)
		*msg_sizep = kmsg->ikm_header->msgh_size;
	if (msg_idp != NULL)
		*msg_idp = kmsg->ikm_header->msgh_id;
	if (msg_trailerp != NULL)
		memcpy(msg_trailerp, 
		       (mach_msg_max_trailer_t *)((vm_offset_t)kmsg->ikm_header +
						  round_msg(kmsg->ikm_header->msgh_size)),
		       sizeof(mach_msg_max_trailer_t));
	res = 1;

 out:
	imq_unlock(mq);
	splx(s);
	return res;
}


/*
 * peek at the contained port message queues, break prepost iteration as soon
 * as we spot a message on one of the message queues referenced by the set's
 * prepost list.  No need to lock each message queue, as only the head of each
 * queue is checked. If a message wasn't there before we entered here, no need
 * to find it (if we do, great).
 */
static int mqueue_peek_iterator(void *ctx, struct waitq *waitq,
				struct waitq_set *wqset)
{
	ipc_mqueue_t port_mq = (ipc_mqueue_t)waitq;
	ipc_kmsg_queue_t kmsgs = &port_mq->imq_messages;

	(void)ctx;
	(void)wqset;
		
	if (ipc_kmsg_queue_first(kmsgs) != IKM_NULL)
		return WQ_ITERATE_BREAK; /* break out of the prepost iteration */

	return WQ_ITERATE_CONTINUE;
}

/*
 *	Routine:	ipc_mqueue_set_peek
 *	Purpose:
 *		Peek at a message queue set to see if it has any ports
 *		with messages.
 *
 *	Conditions:
 *		Locks may be held by callers, so this routine cannot block.
 *		Caller holds reference on the message queue.
 */
unsigned
ipc_mqueue_set_peek(ipc_mqueue_t mq)
{
	spl_t s;
	int ret;

	assert(imq_is_set(mq));

	s = splsched();
	imq_lock(mq);

	ret = waitq_set_iterate_preposts(&mq->imq_set_queue, NULL,
					 mqueue_peek_iterator, NULL);

	imq_unlock(mq);
	splx(s);
	return (ret == WQ_ITERATE_BREAK);
}

/*
 *	Routine:	ipc_mqueue_set_gather_member_names
 *	Purpose:
 *		Discover all ports which are members of a given port set.
 *		Because the waitq linkage mechanism was redesigned to save
 *		significan amounts of memory, it no longer keeps back-pointers
 *		from a port set to a port. Therefore, we must iterate over all
 *		ports within a given IPC space and individually query them to
 *		see if they are members of the given set. Port names of ports
 *		found to be members of the given set will be gathered into the
 *		provided 'names' array.  Actual returned names are limited to
 *		maxnames entries, but we keep counting the actual number of
 *		members to let the caller decide to retry if necessary.
 *
 *	Conditions:
 *		Locks may be held by callers, so this routine cannot block.
 *		Caller holds reference on the message queue (via port set).
 */
void
ipc_mqueue_set_gather_member_names(
	ipc_space_t space,
	ipc_mqueue_t set_mq,
	ipc_entry_num_t maxnames,
	mach_port_name_t *names,
	ipc_entry_num_t *actualp)
{
	ipc_entry_t table;
	ipc_entry_num_t tsize;
	struct waitq_set *wqset;
	ipc_entry_num_t actual = 0;

	assert(set_mq != IMQ_NULL);
	wqset = &set_mq->imq_set_queue;

	assert(space != IS_NULL);
	is_read_lock(space);
	if (!is_active(space)) {
		is_read_unlock(space);
		goto out;
	}

	if (!waitq_set_is_valid(wqset)) {
		is_read_unlock(space);
		goto out;
	}

	table = space->is_table;
	tsize = space->is_table_size;
	for (ipc_entry_num_t idx = 0; idx < tsize; idx++) {
		ipc_entry_t entry = &table[idx];

		/* only receive rights can be members of port sets */
		if ((entry->ie_bits & MACH_PORT_TYPE_RECEIVE) != MACH_PORT_TYPE_NONE) {
			__IGNORE_WCASTALIGN(ipc_port_t port = (ipc_port_t)entry->ie_object);
			ipc_mqueue_t mq = &port->ip_messages;

			assert(IP_VALID(port));
			if (ip_active(port) &&
			    waitq_member(&mq->imq_wait_queue, wqset)) {
				if (actual < maxnames)
					names[actual] = mq->imq_receiver_name;
				actual++;
			}
		}
	}

	is_read_unlock(space);

out:
	*actualp = actual;
}


/*
 *	Routine:	ipc_mqueue_destroy
 *	Purpose:
 *		Destroy a (non-set) message queue.
 *		Set any blocked senders running.
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
	boolean_t reap = FALSE;
	spl_t s;

	assert(!imq_is_set(mqueue));

	s = splsched();
	imq_lock(mqueue);

	/*
	 *	rouse all blocked senders
	 *	(don't boost anyone - we're tearing this queue down)
	 *	(never preposts)
	 */
	mqueue->imq_fullwaiters = FALSE;
	waitq_wakeup64_all_locked(&mqueue->imq_wait_queue,
				  IPC_MQUEUE_FULL,
				  THREAD_RESTART,
				  NULL,
				  WAITQ_ALL_PRIORITIES,
				  WAITQ_KEEP_LOCKED);

	/*
	 * Move messages from the specified queue to the per-thread
	 * clean/drain queue while we have the mqueue lock.
	 */
	kmqueue = &mqueue->imq_messages;
	while ((kmsg = ipc_kmsg_dequeue(kmqueue)) != IKM_NULL) {
		boolean_t first;
		first = ipc_kmsg_delayed_destroy(kmsg);
		if (first)
			reap = first;
	}

	/*
	 * Wipe out message count, both for messages about to be
	 * reaped and for reserved space for (previously) woken senders.
	 * This is the indication to them that their reserved space is gone
	 * (the mqueue was destroyed).
	 */
	mqueue->imq_msgcount = 0;

	/* clear out any preposting we may have done */
	waitq_clear_prepost_locked(&mqueue->imq_wait_queue, &s);

	imq_unlock(mqueue);
	splx(s);

	/*
	 * assert that we're destroying a queue that's not a
	 * member of any other queue
	 */
	assert(mqueue->imq_wait_queue.waitq_prepost_id == 0);
	assert(mqueue->imq_wait_queue.waitq_set_id == 0);


	/*
	 * Destroy the messages we enqueued if we aren't nested
	 * inside some other attempt to drain the same queue.
	 */
	if (reap)
		ipc_kmsg_reap_delayed();
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
			/*
			 * boost the priority of the awoken thread
			 * (WAITQ_PROMOTE_PRIORITY) to ensure it uses
			 * the message queue slot we've just reserved.
			 *
			 * NOTE: this will never prepost
			 */
			if (waitq_wakeup64_one_locked(&mqueue->imq_wait_queue,
						      IPC_MQUEUE_FULL,
						      THREAD_AWAKENED,
						      NULL,
						      WAITQ_PROMOTE_PRIORITY,
						      WAITQ_KEEP_LOCKED) == KERN_NOT_WAITING) {
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
	if (!is_active(space)) {
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

		__IGNORE_WCASTALIGN(port = (ipc_port_t) object);
		assert(port != IP_NULL);

		ip_lock(port);
		assert(ip_active(port));
		assert(port->ip_receiver_name == name);
		assert(port->ip_receiver == space);
		is_read_unlock(space);
		mqueue = &port->ip_messages;

	} else if (entry->ie_bits & MACH_PORT_TYPE_PORT_SET) {
		ipc_pset_t pset;

		__IGNORE_WCASTALIGN(pset = (ipc_pset_t) object);
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

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

#if MACH_FLIPC
#include <ipc/flipc.h>
#endif

#ifdef __LP64__
#include <vm/vm_map.h>
#endif

#include <sys/event.h>

extern char	*proc_name_address(void *p);

int ipc_mqueue_full;		/* address is event for queue space */
int ipc_mqueue_rcv;		/* address is event for message arrival */

/* forward declarations */
void ipc_mqueue_receive_results(wait_result_t result);
static void ipc_mqueue_peek_on_thread(
	ipc_mqueue_t        port_mq,
	mach_msg_option_t   option,
	thread_t            thread);

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
			       SYNC_POLICY_FIFO|SYNC_POLICY_PREPOST,
			       reserved_link, NULL);
	} else {
		waitq_init(&mqueue->imq_wait_queue, SYNC_POLICY_FIFO);
		ipc_kmsg_queue_init(&mqueue->imq_messages);
		mqueue->imq_seqno = 0;
		mqueue->imq_msgcount = 0;
		mqueue->imq_qlimit = MACH_PORT_QLIMIT_DEFAULT;
		mqueue->imq_fullwaiters = FALSE;
#if MACH_FLIPC
		mqueue->imq_fport = FPORT_NULL;
#endif
	}
	klist_init(&mqueue->imq_klist);
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
imq_reserve_and_lock(ipc_mqueue_t mq, uint64_t *reserved_prepost)
{
	*reserved_prepost = waitq_prepost_reserve(&mq->imq_wait_queue, 0,
						  WAITQ_KEEP_LOCKED);

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
imq_release_and_unlock(ipc_mqueue_t mq, uint64_t reserved_prepost)
{
	assert(imq_held(mq));
	waitq_unlock(&mq->imq_wait_queue);
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
 *	Returns:
 *		mqueue unlocked and set links deallocated
 */
void
ipc_mqueue_remove_from_all(ipc_mqueue_t	mqueue)
{
	struct waitq *mq_waitq = &mqueue->imq_wait_queue;
	kern_return_t kr;

	imq_lock(mqueue);

	assert(waitq_valid(mq_waitq));
	kr = waitq_unlink_all_unlock(mq_waitq);
	/* mqueue unlocked and set links deallocated */
}

/*
 *	Routine:	ipc_mqueue_remove_all
 *	Purpose:
 *		Remove all the member queues from the specified set.
 *		Also removes the queue from any containing sets.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		mqueue unlocked all set links deallocated
 */
void
ipc_mqueue_remove_all(ipc_mqueue_t	mqueue)
{
	struct waitq_set *mq_setq = &mqueue->imq_set_queue;

	imq_lock(mqueue);
	assert(waitqs_is_set(mq_setq));
	waitq_set_unlink_all_unlock(mq_setq);
	/* mqueue unlocked set links deallocated */
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

	assert(reserved_link && *reserved_link != 0);

	imq_lock(port_mqueue);

	/*
	 * The link operation is now under the same lock-hold as
	 * message iteration and thread wakeup, but doesn't have to be...
	 */
	kr = waitq_link(port_waitq, set_waitq, WAITQ_ALREADY_LOCKED, reserved_link);
	if (kr != KERN_SUCCESS) {
		imq_unlock(port_mqueue);
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

			th = waitq_wakeup64_identify_locked(
						port_waitq,
						IPC_MQUEUE_RECEIVE,
						THREAD_AWAKENED, &th_spl,
						reserved_prepost, WAITQ_ALL_PRIORITIES,
						WAITQ_KEEP_LOCKED);
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
				if (th->ith_state == MACH_PEEK_IN_PROGRESS) {
					/*
					 * wakeup the peeking thread, but
					 * continue to loop over the threads
					 * waiting on the port's mqueue to see
					 * if there are any actual receivers
					 */
					ipc_mqueue_peek_on_thread(port_mqueue,
								  th->ith_option,
								  th);
				}
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
			if (th->ith_rsize <
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
#if MACH_FLIPC
			mach_node_t  node = kmsg->ikm_node;
#endif
			ipc_mqueue_release_msgcount(port_mqueue, IMQ_NULL);

			th->ith_kmsg = kmsg;
			th->ith_seqno = port_mqueue->imq_seqno++;
			thread_unlock(th);
			splx(th_spl);
#if MACH_FLIPC
            if (MACH_NODE_VALID(node) && FPORT_VALID(port_mqueue->imq_fport))
                flipc_msg_ack(node, port_mqueue, TRUE);
#endif
			break;  /* go to next message */
		}
	}
 leave:
	imq_unlock(port_mqueue);
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
	/* Indicate that this message queue is vanishing */
	knote_vanish(&mqueue->imq_klist);

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
	mach_msg_timeout_t  send_timeout)
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
	} else {
		thread_t cur_thread = current_thread();
		uint64_t deadline;

		/* 
		 * We have to wait for space to be granted to us.
		 */
		if ((option & MACH_SEND_TIMEOUT) && (send_timeout == 0)) {
			imq_unlock(mqueue);
			return MACH_SEND_TIMED_OUT;
		}
		if (imq_full_kernel(mqueue)) {
			imq_unlock(mqueue);
			return MACH_SEND_NO_BUFFER;
		}
		mqueue->imq_fullwaiters = TRUE;

		if (option & MACH_SEND_TIMEOUT)
			clock_interval_to_deadline(send_timeout, 1000*NSEC_PER_USEC, &deadline);
		else
			deadline = 0;

		thread_set_pending_block_hint(cur_thread, kThreadWaitPortSend);
		wresult = waitq_assert_wait64_locked(
						&mqueue->imq_wait_queue,
						IPC_MQUEUE_FULL,
						THREAD_ABORTSAFE,
						TIMEOUT_URGENCY_USER_NORMAL,
						deadline, TIMEOUT_NO_LEEWAY,
						cur_thread);

		imq_unlock(mqueue);
		
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

	ipc_mqueue_post(mqueue, kmsg, option);
	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	ipc_mqueue_override_send
 *	Purpose:
 *		Set an override qos on the first message in the queue
 *		(if the queue is full). This is a send-possible override
 *		that will go away as soon as we drain a message from the
 *		queue.
 *
 *	Conditions:
 *		The message queue is not locked.
 *		The caller holds a reference on the message queue.
 */
extern void ipc_mqueue_override_send(
	ipc_mqueue_t        mqueue,
	mach_msg_priority_t override)
{
	boolean_t __unused full_queue_empty = FALSE;

	imq_lock(mqueue);
	assert(imq_valid(mqueue));
	assert(!imq_is_set(mqueue));
	
	if (imq_full(mqueue)) {
		ipc_kmsg_t first = ipc_kmsg_queue_first(&mqueue->imq_messages);

		if (first && ipc_kmsg_override_qos(&mqueue->imq_messages, first, override))
			KNOTE(&mqueue->imq_klist, 0);
		if (!first)
			full_queue_empty = TRUE;
	}
	imq_unlock(mqueue);

#if DEVELOPMENT || DEBUG
	if (full_queue_empty) {
		ipc_port_t port = ip_from_mq(mqueue);
		int dst_pid = 0;
		if (ip_active(port) && !port->ip_tempowner &&
		    port->ip_receiver_name && port->ip_receiver &&
		    port->ip_receiver != ipc_space_kernel) {
			dst_pid = task_pid(port->ip_receiver->is_task);
		}
	}
#endif
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
		waitq_clear_prepost_locked(&port_mq->imq_wait_queue);
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
	ipc_mqueue_t               mqueue,
	ipc_kmsg_t                 kmsg,
	mach_msg_option_t __unused option)
{
	uint64_t reserved_prepost = 0;
	boolean_t destroy_msg = FALSE;

	ipc_kmsg_trace_send(kmsg, option);

	/*
	 *	While the msg queue	is locked, we have control of the
	 *  kmsg, so the ref in	it for the port is still good.
	 *
	 *	Check for a receiver for the message.
	 */
	imq_reserve_and_lock(mqueue, &reserved_prepost);

	/* we may have raced with port destruction! */
	if (!imq_valid(mqueue)) {
		destroy_msg = TRUE;
		goto out_unlock;
	}

	for (;;) {
		struct waitq *waitq = &mqueue->imq_wait_queue;
		spl_t th_spl;
		thread_t receiver;
		mach_msg_size_t msize;

		receiver = waitq_wakeup64_identify_locked(waitq,
		                                          IPC_MQUEUE_RECEIVE,
		                                          THREAD_AWAKENED,
		                                          &th_spl,
		                                          &reserved_prepost,
		                                          WAITQ_ALL_PRIORITIES,
		                                          WAITQ_KEEP_LOCKED);
		/* waitq still locked, thread locked */

		if (receiver == THREAD_NULL) {

			/* 
			 * no receivers; queue kmsg if space still reserved
			 * Reservations are cancelled when the port goes inactive.
			 * note that this will enqueue the message for any
			 * "peeking" receivers. 
			 *
			 * Also, post the knote to wake up any threads waiting
			 * on that style of interface if this insertion is of
			 * note (first insertion, or adjusted override qos all
			 * the way to the head of the queue).
			 * 
			 * This is just for ports. portset knotes are stay-active,
			 * and their threads get awakened through the !MACH_RCV_IN_PROGRESS
			 * logic below).
			 */
			if (mqueue->imq_msgcount > 0) {
				if (ipc_kmsg_enqueue_qos(&mqueue->imq_messages, kmsg))
					KNOTE(&mqueue->imq_klist, 0);
				break;
			}

			/*
			 * Otherwise, the message queue must belong to an inactive
			 * port, so just destroy the message and pretend it was posted.
			 */
			destroy_msg = TRUE;
			goto out_unlock;
		}
	
		/*
		 * If a thread is attempting a "peek" into the message queue
		 * (MACH_PEEK_IN_PROGRESS), then we enqueue the message and set the
		 * thread running.  A successful peek is essentially the same as
		 * message delivery since the peeking thread takes responsibility
		 * for delivering the message and (eventually) removing it from
		 * the mqueue.  Only one thread can successfully use the peek
		 * facility on any given port, so we exit the waitq loop after
		 * encountering such a thread.
		 */
		if (receiver->ith_state == MACH_PEEK_IN_PROGRESS && mqueue->imq_msgcount > 0) {
			ipc_kmsg_enqueue_qos(&mqueue->imq_messages, kmsg);
			ipc_mqueue_peek_on_thread(mqueue, receiver->ith_option, receiver);
			thread_unlock(receiver);
			splx(th_spl);
			break; /* Message was posted, so break out of loop */
		}

		/*
		 * If the receiver waited with a facility not directly related
		 * to Mach messaging, then it isn't prepared to get handed the
		 * message directly. Just set it running, and go look for
		 * another thread that can.
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
		if (receiver->ith_rsize <
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
#if MACH_FLIPC
			mach_node_t node = kmsg->ikm_node;
#endif
			thread_unlock(receiver);
			splx(th_spl);

			/* we didn't need our reserved spot in the queue */
			ipc_mqueue_release_msgcount(mqueue, IMQ_NULL);

#if MACH_FLIPC
            if (MACH_NODE_VALID(node) && FPORT_VALID(mqueue->imq_fport))
                flipc_msg_ack(node, mqueue, TRUE);
#endif
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

out_unlock:
	/* clear the waitq boost we may have been given */
	waitq_clear_promotion_locked(&mqueue->imq_wait_queue, current_thread());
	imq_release_and_unlock(mqueue, reserved_prepost);
	if (destroy_msg)
		ipc_kmsg_destroy(kmsg);

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
		case MACH_PEEK_READY:
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
 *	Conditions:
 *		Our caller must hold a reference for the port or port set
 *		to which this queue belongs, to keep the queue
 *		from being deallocated.
 *
 *		The kmsg is returned with clean header fields
 *		and with the circular bit turned off through the ith_kmsg
 *		field of the thread's receive continuation state.
 *	Returns:
 *		MACH_MSG_SUCCESS	Message returned in ith_kmsg.
 *		MACH_RCV_TOO_LARGE	Message size returned in ith_msize.
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

	imq_lock(mqueue);
	wresult = ipc_mqueue_receive_on_thread(mqueue, option, max_size,
	                                       rcv_timeout, interruptible,
	                                       self);
	/* mqueue unlocked */
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

/*
 *	Routine:	ipc_mqueue_receive_on_thread
 *	Purpose:
 *		Receive a message from a message queue using a specified thread.
 *		If no message available, assert_wait on the appropriate waitq.
 *
 *	Conditions:
 *		Assumes thread is self.
 *		Called with mqueue locked.
 *		Returns with mqueue unlocked.
 *		May have assert-waited. Caller must block in those cases.
 */
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

	/* called with mqueue locked */

	/* no need to reserve anything: we never prepost to anyone */

	if (!imq_valid(mqueue)) {
		/* someone raced us to destroy this mqueue/port! */
		imq_unlock(mqueue);
		/*
		 * ipc_mqueue_receive_results updates the thread's ith_state
		 * TODO: differentiate between rights being moved and
		 * rights/ports being destroyed (21885327)
		 */
		return THREAD_RESTART;
	}
	
	if (imq_is_set(mqueue)) {
		ipc_mqueue_t port_mq = IMQ_NULL;

		(void)waitq_set_iterate_preposts(&mqueue->imq_set_queue,
						 &port_mq,
		                 mqueue_process_prepost_receive);

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

			/*
			 * Continue on to handling the message with just
			 * the port mqueue locked.
			 */
			if (option & MACH_PEEK_MSG)
				ipc_mqueue_peek_on_thread(port_mq, option, thread);
			else
				ipc_mqueue_select_on_thread(port_mq, mqueue, option,
							    max_size, thread);

			imq_unlock(port_mq);
			return THREAD_NOT_WAITING;
		}
	} else if (imq_is_queue(mqueue)) {
		ipc_kmsg_queue_t kmsgs;

		/*
		 * Receive on a single port. Just try to get the messages.
		 */
	  	kmsgs = &mqueue->imq_messages;
		if (ipc_kmsg_queue_first(kmsgs) != IKM_NULL) {
			if (option & MACH_PEEK_MSG)
				ipc_mqueue_peek_on_thread(mqueue, option, thread);
			else
				ipc_mqueue_select_on_thread(mqueue, IMQ_NULL, option,
							    max_size, thread);
			imq_unlock(mqueue);
			return THREAD_NOT_WAITING;
		}
	} else {
		panic("Unknown mqueue type 0x%x: likely memory corruption!\n",
		      mqueue->imq_wait_queue.waitq_type);
	}
	
	/*
	 * Looks like we'll have to block.  The mqueue we will
	 * block on (whether the set's or the local port's) is
	 * still locked.
	 */
	if (option & MACH_RCV_TIMEOUT) {
		if (rcv_timeout == 0) {
			imq_unlock(mqueue);
			thread->ith_state = MACH_RCV_TIMED_OUT;
			return THREAD_NOT_WAITING;
		}
	}

	thread->ith_option = option;
	thread->ith_rsize = max_size;
	thread->ith_msize = 0;

	if (option & MACH_PEEK_MSG)
		thread->ith_state = MACH_PEEK_IN_PROGRESS;
	else
		thread->ith_state = MACH_RCV_IN_PROGRESS;

	if (option & MACH_RCV_TIMEOUT)
		clock_interval_to_deadline(rcv_timeout, 1000*NSEC_PER_USEC, &deadline);
	else
		deadline = 0;

	thread_set_pending_block_hint(thread, kThreadWaitPortReceive);
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

	imq_unlock(mqueue);

	return wresult;
}


/*
 *	Routine:	ipc_mqueue_peek_on_thread
 *	Purpose:
 *		A receiver discovered that there was a message on the queue
 *		before he had to block. Tell a thread about the message queue,
 *		but don't pick off any messages.
 *	Conditions:
 *		port_mq locked
 *		at least one message on port_mq's message queue
 *
 *	Returns: (on thread->ith_state)
 *		MACH_PEEK_READY		ith_peekq contains a message queue
 */
void
ipc_mqueue_peek_on_thread(
	ipc_mqueue_t        port_mq,
	mach_msg_option_t   option,
	thread_t            thread)
{
	(void)option;
	assert(option & MACH_PEEK_MSG);
	assert(ipc_kmsg_queue_first(&port_mq->imq_messages) != IKM_NULL);

	/*
	 * Take a reference on the mqueue's associated port:
	 * the peeking thread will be responsible to release this reference
	 * using ip_release_mq()
	 */
	ip_reference_mq(port_mq);
	thread->ith_peekq = port_mq;
	thread->ith_state = MACH_PEEK_READY;
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
	mach_msg_size_t msize;

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
	msize = ipc_kmsg_copyout_size(kmsg, thread->map);
	if (msize + REQUESTED_TRAILER_SIZE(thread_is_64bit(thread), option) > max_size) {
		mr = MACH_RCV_TOO_LARGE;
		if (option & MACH_RCV_LARGE) {
			thread->ith_receiver_name = port_mq->imq_receiver_name;
			thread->ith_kmsg = IKM_NULL;
			thread->ith_msize = msize;
			thread->ith_seqno = 0;
			thread->ith_state = mr;
			return;
		}
	}

	ipc_kmsg_rmqueue(&port_mq->imq_messages, kmsg);
#if MACH_FLIPC
    if (MACH_NODE_VALID(kmsg->ikm_node) && FPORT_VALID(port_mq->imq_fport))
        flipc_msg_ack(kmsg->ikm_node, port_mq, TRUE);
#endif
	ipc_mqueue_release_msgcount(port_mq, set_mq);
	thread->ith_seqno = port_mq->imq_seqno++;
	thread->ith_kmsg = kmsg;
	thread->ith_state = mr;

	current_task()->messages_received++;
	return;
}

/*
 *	Routine:	ipc_mqueue_peek_locked
 *	Purpose:
 *		Peek at a (non-set) message queue to see if it has a message
 *		matching the sequence number provided (if zero, then the
 *		first message in the queue) and return vital info about the
 *		message.
 *
 *	Conditions:
 *		The ipc_mqueue_t is locked by callers.
 *		Other locks may be held by callers, so this routine cannot block.
 *		Caller holds reference on the message queue.
 */
unsigned
ipc_mqueue_peek_locked(ipc_mqueue_t mq,
		       mach_port_seqno_t * seqnop,
		       mach_msg_size_t * msg_sizep,
		       mach_msg_id_t * msg_idp,
		       mach_msg_max_trailer_t * msg_trailerp,
		       ipc_kmsg_t *kmsgp)
{
	ipc_kmsg_queue_t kmsgq;
	ipc_kmsg_t kmsg;
	mach_port_seqno_t seqno, msgoff;
	unsigned res = 0;

	assert(!imq_is_set(mq));

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
	if (kmsgp != NULL)
		*kmsgp = kmsg;

	res = 1;

out:
	return res;
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
 *		The ipc_mqueue_t is unlocked.
 *		Locks may be held by callers, so this routine cannot block.
 *		Caller holds reference on the message queue.
 */
unsigned
ipc_mqueue_peek(ipc_mqueue_t mq,
		mach_port_seqno_t * seqnop,
		mach_msg_size_t * msg_sizep,
		mach_msg_id_t * msg_idp,
		mach_msg_max_trailer_t * msg_trailerp,
		ipc_kmsg_t *kmsgp)
{
	unsigned res;

	imq_lock(mq);

	res = ipc_mqueue_peek_locked(mq, seqnop, msg_sizep, msg_idp,
				     msg_trailerp, kmsgp);

	imq_unlock(mq);
	return res;
}

/*
 *	Routine:	ipc_mqueue_release_peek_ref
 *	Purpose:
 *		Release the reference on an mqueue's associated port which was
 *		granted to a thread in ipc_mqueue_peek_on_thread (on the
 *		MACH_PEEK_MSG thread wakeup path).
 *
 *	Conditions:
 *		The ipc_mqueue_t should be locked on entry.
 *		The ipc_mqueue_t will be _unlocked_ on return
 *			(and potentially invalid!)
 *
 */
void ipc_mqueue_release_peek_ref(ipc_mqueue_t mq)
{
	assert(!imq_is_set(mq));
	assert(imq_held(mq));

	/*
	 * clear any preposts this mq may have generated
	 * (which would cause subsequent immediate wakeups)
	 */
	waitq_clear_prepost_locked(&mq->imq_wait_queue);

	imq_unlock(mq);

	/*
	 * release the port reference: we need to do this outside the lock
	 * because we might be holding the last port reference!
	 **/
	ip_release_mq(mq);
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
	int ret;

	imq_lock(mq);

	/*
	 * We may have raced with port destruction where the mqueue is marked
	 * as invalid. In that case, even though we don't have messages, we
	 * have an end-of-life event to deliver.
	 */
	if (!imq_is_valid(mq))
		return 1;

	ret = waitq_set_iterate_preposts(&mq->imq_set_queue, NULL,
					 mqueue_peek_iterator);

	imq_unlock(mq);

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
 *	Routine:	ipc_mqueue_destroy_locked
 *	Purpose:
 *		Destroy a (non-set) message queue.
 *		Set any blocked senders running.
 *	   	Destroy the kmsgs in the queue.
 *	Conditions:
 *		mqueue locked
 *		Receivers were removed when the receive right was "changed"
 */
boolean_t
ipc_mqueue_destroy_locked(ipc_mqueue_t mqueue)
{
	ipc_kmsg_queue_t kmqueue;
	ipc_kmsg_t kmsg;
	boolean_t reap = FALSE;

	assert(!imq_is_set(mqueue));

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
#if MACH_FLIPC
    if (MACH_NODE_VALID(kmsg->ikm_node) && FPORT_VALID(mqueue->imq_fport))
        flipc_msg_ack(kmsg->ikm_node, mqueue, TRUE);
#endif
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

	/* invalidate the waitq for subsequent mqueue operations */
	waitq_invalidate_locked(&mqueue->imq_wait_queue);

	/* clear out any preposting we may have done */
	waitq_clear_prepost_locked(&mqueue->imq_wait_queue);

	/*
	 * assert that we are destroying / invalidating a queue that's
	 * not a member of any other queue.
	 */
	assert(mqueue->imq_preposts == 0);
	assert(mqueue->imq_in_pset == 0);

	return reap;
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

	 assert(qlimit <= MACH_PORT_QLIMIT_MAX);

	 /* wake up senders allowed by the new qlimit */
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
	imq_lock(mqueue);
	mqueue->imq_seqno = seqno;
	imq_unlock(mqueue);
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

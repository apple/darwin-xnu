/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
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
 *	File:	ipc/ipc_pset.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Functions to manipulate IPC port sets.
 */

#include <mach/port.h>
#include <mach/kern_return.h>
#include <mach/message.h>
#include <ipc/ipc_mqueue.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_pset.h>
#include <ipc/ipc_right.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_port.h>

#include <kern/kern_types.h>

#include <vm/vm_map.h>

/*
 *	Routine:	ipc_pset_alloc
 *	Purpose:
 *		Allocate a port set.
 *	Conditions:
 *		Nothing locked.  If successful, the port set is returned
 *		locked.  (The caller doesn't have a reference.)
 *	Returns:
 *		KERN_SUCCESS		The port set is allocated.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_NO_SPACE		No room for an entry in the space.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
ipc_pset_alloc(
	ipc_space_t		space,
	mach_port_name_t	*namep,
	ipc_pset_t		*psetp)
{
	ipc_pset_t pset;
	mach_port_name_t name;
	kern_return_t kr;
	uint64_t reserved_link;

	reserved_link = waitq_link_reserve(NULL);

	kr = ipc_object_alloc(space, IOT_PORT_SET,
			      MACH_PORT_TYPE_PORT_SET, 0,
			      &name, (ipc_object_t *) &pset);
	if (kr != KERN_SUCCESS) {
		waitq_link_release(reserved_link);
		return kr;
	}
	/* pset and space are locked */

	ipc_mqueue_init(&pset->ips_messages, TRUE /* set */, &reserved_link);
	is_write_unlock(space);

	waitq_link_release(reserved_link);

	*namep = name;
	*psetp = pset;
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_pset_alloc_name
 *	Purpose:
 *		Allocate a port set, with a specific name.
 *	Conditions:
 *		Nothing locked.  If successful, the port set is returned
 *		locked.  (The caller doesn't have a reference.)
 *	Returns:
 *		KERN_SUCCESS		The port set is allocated.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_NAME_EXISTS	The name already denotes a right.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
ipc_pset_alloc_name(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_pset_t		*psetp)
{
	ipc_pset_t pset;
	kern_return_t kr;
	uint64_t reserved_link;


	reserved_link = waitq_link_reserve(NULL);

	kr = ipc_object_alloc_name(space, IOT_PORT_SET,
				   MACH_PORT_TYPE_PORT_SET, 0,
				   name, (ipc_object_t *) &pset);
	if (kr != KERN_SUCCESS) {
		waitq_link_release(reserved_link);
		return kr;
	}
	/* pset is locked */

	ipc_mqueue_init(&pset->ips_messages, TRUE /* set */, &reserved_link);

	waitq_link_release(reserved_link);

	*psetp = pset;
	return KERN_SUCCESS;
}


/*
 *	Routine:	ipc_pset_alloc_special
 *	Purpose:
 *		Allocate a port set in a special space.
 *		The new port set is returned with one ref.
 *		If unsuccessful, IPS_NULL is returned.
 *	Conditions:
 *		Nothing locked.
 */
ipc_pset_t
ipc_pset_alloc_special(
	__assert_only ipc_space_t space)
{
	ipc_pset_t pset;
	uint64_t reserved_link;

	assert(space != IS_NULL);
	assert(space->is_table == IE_NULL);
	assert(!is_active(space));

	reserved_link = waitq_link_reserve(NULL);

	__IGNORE_WCASTALIGN(pset = (ipc_pset_t)io_alloc(IOT_PORT_SET));
	if (pset == IPS_NULL)
		return IPS_NULL;

	bzero((char *)pset, sizeof(*pset));

	io_lock_init(&pset->ips_object);
	pset->ips_references = 1;
	pset->ips_object.io_bits = io_makebits(TRUE, IOT_PORT_SET, 0);

	ipc_mqueue_init(&pset->ips_messages, TRUE /* set */, &reserved_link);

	waitq_link_release(reserved_link);

	return pset;
}


/*
 *	Routine:	ipc_pset_member
 *	Purpose:
 *		Checks to see if a port is a member of a pset
 *	Conditions:
 *		Both port and port set are locked.
 *		The port must be active.
 */
boolean_t
ipc_pset_member(
	ipc_pset_t	pset,
	ipc_port_t	port)
{
	assert(ip_active(port));

	return (ipc_mqueue_member(&port->ip_messages, &pset->ips_messages));
}


/*
 *	Routine:	ipc_pset_add
 *	Purpose:
 *		Puts a port into a port set.
 *	Conditions:
 *		Both port and port set are locked and active.
 *		The owner of the port set is also receiver for the port.
 */

kern_return_t
ipc_pset_add(
	ipc_pset_t	  pset,
	ipc_port_t	  port,
	uint64_t	 *reserved_link,
	uint64_t	 *reserved_prepost)
{
	kern_return_t kr;

	assert(ips_active(pset));
	assert(ip_active(port));
	
	kr = ipc_mqueue_add(&port->ip_messages, &pset->ips_messages,
			    reserved_link, reserved_prepost);

	return kr;
}



/*
 *	Routine:	ipc_pset_remove
 *	Purpose:
 *		Removes a port from a port set.
 *		The port set loses a reference.
 *	Conditions:
 *		Both port and port set are locked.
 *		The port must be active.
 */

kern_return_t
ipc_pset_remove(
	ipc_pset_t	  pset,
	ipc_port_t	  port)
{
	kern_return_t kr;

	assert(ip_active(port));
	
	if (port->ip_in_pset == 0)
		return KERN_NOT_IN_SET;

	kr = ipc_mqueue_remove(&port->ip_messages, &pset->ips_messages);

	return kr;
}

/*
 *	Routine:	ipc_pset_remove_from_all
 *	Purpose:
 *		Removes a port from all it's port sets.
 *	Conditions:
 *		port is locked and active.
 */

kern_return_t
ipc_pset_remove_from_all(
	ipc_port_t	port)
{
	if (port->ip_in_pset == 0)
		return KERN_NOT_IN_SET;

	/* 
	 * Remove the port's mqueue from all sets
	 */
	ipc_mqueue_remove_from_all(&port->ip_messages);
	return KERN_SUCCESS;
}


/*
 *	Routine:	ipc_pset_destroy
 *	Purpose:
 *		Destroys a port_set.
 *	Conditions:
 *		The port_set is locked and alive.
 *		The caller has a reference, which is consumed.
 *		Afterwards, the port_set is unlocked and dead.
 */

void
ipc_pset_destroy(
	ipc_pset_t	pset)
{
	assert(ips_active(pset));

	pset->ips_object.io_bits &= ~IO_BITS_ACTIVE;

	/*
	 * remove all the member message queues
	 * AND remove this message queue from any containing sets
	 */
	ipc_mqueue_remove_all(&pset->ips_messages);

	/*
	 * Set all waiters on the portset running to
	 * discover the change.
	 */
	imq_lock(&pset->ips_messages);
	ipc_mqueue_changed(&pset->ips_messages);
	imq_unlock(&pset->ips_messages);

	ipc_mqueue_deinit(&pset->ips_messages);

	ips_unlock(pset);
	ips_release(pset);       /* consume the ref our caller gave us */
}

/* Kqueue EVFILT_MACHPORT support */

#include <sys/event.h>
#include <sys/errno.h>

static int      filt_machportattach(struct knote *kn);
static void	filt_machportdetach(struct knote *kn);
static int	filt_machport(struct knote *kn, long hint);
static int     filt_machporttouch(struct knote *kn, struct kevent_internal_s *kev);
static int     filt_machportprocess(struct knote *kn, struct filt_process_s *data, struct kevent_internal_s *kev);
static unsigned filt_machportpeek(struct knote *kn);
struct filterops machport_filtops = {
        .f_attach = filt_machportattach,
        .f_detach = filt_machportdetach,
        .f_event = filt_machport,
        .f_touch = filt_machporttouch,
        .f_process = filt_machportprocess,
	.f_peek = filt_machportpeek,
};

static int
filt_machportattach(
        struct knote *kn)
{
	mach_port_name_t name = (mach_port_name_t)kn->kn_kevent.ident;
	uint64_t wq_link_id = waitq_link_reserve(NULL);
	ipc_space_t space = current_space();
	ipc_kmsg_t first;

	int error;
	int result = 0;
	kern_return_t kr;
	ipc_entry_t entry;
	ipc_mqueue_t mqueue;

	kr = ipc_right_lookup_read(space, name, &entry);
	if (kr == KERN_SUCCESS) {
		/* space is read-locked and active */

		if (entry->ie_bits & MACH_PORT_TYPE_PORT_SET) {
			ipc_pset_t pset;

			__IGNORE_WCASTALIGN(pset = (ipc_pset_t)entry->ie_object);
			mqueue = &pset->ips_messages;

			imq_lock(mqueue);

			/*
			 * Bind the portset wait queue directly to knote/kqueue.
			 * This allows us to just use wait_queue foo to effect a wakeup,
			 * rather than having to call knote() from the Mach code on each
			 * message.  We still attach the knote to the mqueue klist for
			 * NOTE_REVOKE purposes only.
			 */
			error = knote_link_waitq(kn, &mqueue->imq_wait_queue, &wq_link_id);
			if (!error) {
				ips_reference(pset);
				kn->kn_ptr.p_mqueue = mqueue; 
				KNOTE_ATTACH(&mqueue->imq_klist, kn);
			}
			imq_unlock(mqueue);

			is_read_unlock(space);

			/*
			 * linked knotes are marked stay-active and therefore don't
			 * need an indication of their fired state to be returned
			 * from the attach operation.
			 */

		} else if (entry->ie_bits & MACH_PORT_TYPE_RECEIVE) {
			ipc_port_t port;

			__IGNORE_WCASTALIGN(port = (ipc_port_t)entry->ie_object);
			mqueue = &port->ip_messages;
			ip_reference(port);

			/*
			 * attach knote to port and determine result
			 * If the filter requested direct message receipt,
			 * we may need to adjust the qos of the knote to
			 * reflect the requested and override qos of the
			 * first message in the queue.
			 */
			imq_lock(mqueue);
			kn->kn_ptr.p_mqueue = mqueue; 
			KNOTE_ATTACH(&mqueue->imq_klist, kn);
			if ((first = ipc_kmsg_queue_first(&mqueue->imq_messages)) != IKM_NULL) {
				if (kn->kn_sfflags & MACH_RCV_MSG)
					knote_adjust_qos(kn, first->ikm_qos, first->ikm_qos_override);
				result = 1;
			}
			imq_unlock(mqueue);

			is_read_unlock(space);
			error = 0;
		} else {
			is_read_unlock(space);
			error = ENOTSUP;
		}
	} else  {
		error = ENOENT;
	}

	waitq_link_release(wq_link_id);

	/* bail out on errors */
	if (error) {
		kn->kn_flags |= EV_ERROR;
		kn->kn_data = error;
		return 0;
	}

	return result;
}

/* NOT proud of these - we should have a stricter relationship between mqueue and ipc object */
#define mqueue_to_pset(mq) ((ipc_pset_t)((uintptr_t)mq-offsetof(struct ipc_pset, ips_messages)))
#define mqueue_to_port(mq) ((ipc_port_t)((uintptr_t)mq-offsetof(struct ipc_port, ip_messages)))
#define mqueue_to_object(mq) (((ipc_object_t)(mq)) - 1)


static void
filt_machportdetach(
	struct knote *kn)
{
	ipc_mqueue_t mqueue = kn->kn_ptr.p_mqueue;
	ipc_object_t object = mqueue_to_object(mqueue);

	imq_lock(mqueue);
	KNOTE_DETACH(&mqueue->imq_klist, kn);
	kn->kn_ptr.p_mqueue = IMQ_NULL;
	imq_unlock(mqueue);

	if (io_otype(object) == IOT_PORT_SET) {
		/*
		 * Unlink the portset wait queue from knote/kqueue.
 		 * JMM - Does this need to be atomic under the mq lock?
		 */
		(void)knote_unlink_waitq(kn, &mqueue->imq_wait_queue);
	} 
	io_release(object);
}

/*
 * filt_machport - deliver events into the mach port filter
 *
 * Mach port message arrival events are currently only posted via the
 * kqueue filter routine for ports. Port sets are marked stay-active
 * and the wait queue code will break any kqueue waiters out to go
 * poll the stay-queued knotes again.
 *
 * If there is a message at the head of the queue,
 * we indicate that the knote should go active.  If
 * the message is to be direct-received, we adjust the
 * QoS of the knote according the requested and override
 * QoS of that first message.
 *
 * NOTE_REVOKE events are a legacy way to indicate that the port/portset
 * was deallocated or left the current Mach portspace (modern technique
 * is with an EV_VANISHED protocol).  If we see NOTE_REVOKE, deliver an
 * EV_EOF event for these changes (hopefully it will get delivered before
 * the port name recycles to the same generation count and someone tries
 * to re-register a kevent for it or the events are udata-specific -
 * avoiding a conflict).
 */
static int
filt_machport(
	struct knote *kn,
	long hint)
{
	ipc_mqueue_t mqueue = kn->kn_ptr.p_mqueue;
	ipc_kmsg_t first;
	int result = 0;

	/* mqueue locked by caller */
	assert(imq_held(mqueue));

	if (hint == NOTE_REVOKE) {
		kn->kn_flags |= EV_EOF | EV_ONESHOT;
		result = 1;
	} else if (imq_is_valid(mqueue)) {
		assert(!imq_is_set(mqueue));
		if ((first = ipc_kmsg_queue_first(&mqueue->imq_messages)) != IKM_NULL) {
			if (kn->kn_sfflags & MACH_RCV_MSG)
				knote_adjust_qos(kn, first->ikm_qos, first->ikm_qos_override);
			result = 1;
		}
	}

	return result;
}

static int
filt_machporttouch(
	struct knote *kn, 
	struct kevent_internal_s *kev)
{
	ipc_mqueue_t mqueue = kn->kn_ptr.p_mqueue;
	ipc_kmsg_t first;
	int result = 0;

	imq_lock(mqueue);

	/* copy in new settings and save off new input fflags */
	kn->kn_sfflags = kev->fflags;
	kn->kn_ext[0] = kev->ext[0];
	kn->kn_ext[1] = kev->ext[1];
	if ((kn->kn_status & KN_UDATA_SPECIFIC) == 0)
		kn->kn_udata = kev->udata;

	/*
	 * If the mqueue is a valid port and there is a message
	 * that will be direct-received from the knote, update
	 * the knote qos based on the first message and trigger
	 * the event. If there are no more messages, reset the
	 * QoS to the value provided by the kevent.
	 */
	if (imq_is_valid(mqueue) && !imq_is_set(mqueue) &&
	    (first = ipc_kmsg_queue_first(&mqueue->imq_messages)) != IKM_NULL) {
		if (kn->kn_sfflags & MACH_RCV_MSG)
			knote_adjust_qos(kn, first->ikm_qos, first->ikm_qos_override);
		result = 1;
	} else if (kn->kn_sfflags & MACH_RCV_MSG) {
		knote_adjust_qos(kn,
		                 MACH_MSG_PRIORITY_UNSPECIFIED,
		                 MACH_MSG_PRIORITY_UNSPECIFIED);
	}
	imq_unlock(mqueue);

	return result;
}

static int
filt_machportprocess(
	struct knote *kn,
	struct filt_process_s *process_data,
	struct kevent_internal_s *kev)
{
	ipc_mqueue_t mqueue = kn->kn_ptr.p_mqueue;
	ipc_object_t object = mqueue_to_object(mqueue);
	thread_t self = current_thread();
	boolean_t used_filtprocess_data = FALSE;

	wait_result_t wresult;
	mach_msg_option_t option;
	mach_vm_address_t addr;
	mach_msg_size_t	size;

	imq_lock(mqueue);

	/* Capture current state */
	*kev = kn->kn_kevent;

	/* If already deallocated/moved return one last EOF event */
	if (kev->flags & EV_EOF) {
		imq_unlock(mqueue);
		return 1;
        }

	/*
	 * Only honor supported receive options. If no options are
	 * provided, just force a MACH_RCV_TOO_LARGE to detect the
	 * name of the port and sizeof the waiting message.
	 */
	option = kn->kn_sfflags & (MACH_RCV_MSG|MACH_RCV_LARGE|MACH_RCV_LARGE_IDENTITY|
	                           MACH_RCV_TRAILER_MASK|MACH_RCV_VOUCHER);

	if (option & MACH_RCV_MSG) {
		addr = (mach_vm_address_t) kn->kn_ext[0];
		size = (mach_msg_size_t) kn->kn_ext[1];

		/*
		 * If the kevent didn't specify a buffer and length, carve a buffer
		 * from the filter processing data according to the flags.
		 */
		if (size == 0 && process_data != NULL) {
			used_filtprocess_data = TRUE;

			addr = (mach_vm_address_t)process_data->fp_data_out;
			size = (mach_msg_size_t)process_data->fp_data_resid;
			option |= (MACH_RCV_LARGE | MACH_RCV_LARGE_IDENTITY);
			if (process_data->fp_flags & KEVENT_FLAG_STACK_DATA)
				option |= MACH_RCV_STACK;
		}
	} else {
		/* just detect the port name (if a set) and size of the first message */
		option = MACH_RCV_LARGE;
		addr = 0;
		size = 0;
	}

	/* just use the reference from here on out */
	io_reference(object);

	/*
	 * Set up to receive a message or the notification of a
	 * too large message.  But never allow this call to wait.
	 * If the user provided aditional options, like trailer
	 * options, pass those through here.  But we don't support
	 * scatter lists through this interface.
	 */
	self->ith_object = object;
	self->ith_msg_addr = addr;
	self->ith_rsize = size;
	self->ith_msize = 0;
	self->ith_option = option;
	self->ith_receiver_name = MACH_PORT_NULL;
	self->ith_continuation = NULL;
	option |= MACH_RCV_TIMEOUT; // never wait
	self->ith_state = MACH_RCV_IN_PROGRESS;

	wresult = ipc_mqueue_receive_on_thread(
			mqueue,
			option,
			size, /* max_size */
			0, /* immediate timeout */
			THREAD_INTERRUPTIBLE,
			self);
	/* mqueue unlocked */

	/*
	 * If we timed out, or the process is exiting, just release the
	 * reference on the ipc_object and return zero.
	 */
	if (wresult == THREAD_RESTART || self->ith_state == MACH_RCV_TIMED_OUT) {
		io_release(object);
		return 0;
	}

	assert(wresult == THREAD_NOT_WAITING);
	assert(self->ith_state != MACH_RCV_IN_PROGRESS);

	/*
	 * If we weren't attempting to receive a message
	 * directly, we need to return the port name in
	 * the kevent structure.
	 */
	if ((option & MACH_RCV_MSG) != MACH_RCV_MSG) {
		assert(self->ith_state == MACH_RCV_TOO_LARGE);
		assert(self->ith_kmsg == IKM_NULL);
		kev->data = self->ith_receiver_name;
		io_release(object);
		return 1;
	}

	/*
	 * Attempt to receive the message directly, returning
	 * the results in the fflags field.
	 */
	kev->fflags = mach_msg_receive_results(&size);

	/* kmsg and object reference consumed */

	/*
	 * if the user asked for the identity of ports containing a
	 * a too-large message, return it in the data field (as we
	 * do for messages we didn't try to receive).
	 */
	if (kev->fflags == MACH_RCV_TOO_LARGE) {
		kev->ext[1] = self->ith_msize;
		if (option & MACH_RCV_LARGE_IDENTITY)
			kev->data = self->ith_receiver_name;
		else
			kev->data = MACH_PORT_NULL;
	} else {
		kev->ext[1] = size;
		kev->data = MACH_PORT_NULL;
	}

	/*
	 * If we used a data buffer carved out from the filt_process data,
	 * store the address used in the knote and adjust the residual and
	 * other parameters for future use.
	 */
	if (used_filtprocess_data) {
		assert(process_data->fp_data_resid >= size);
		process_data->fp_data_resid -= size;
		if ((process_data->fp_flags & KEVENT_FLAG_STACK_DATA) == 0) {
			kev->ext[0] = process_data->fp_data_out;
			process_data->fp_data_out += size;
		} else {
			assert(option & MACH_RCV_STACK);
			kev->ext[0] = process_data->fp_data_out + 
				      process_data->fp_data_resid;
		}
	}

	/*
	 * Apply message-based QoS values to output kevent as prescribed.
	 * The kev->qos field gets max(msg-qos, kn->kn_qos).
	 * The kev->ext[2] field gets (msg-qos << 32) | (override-qos).
	 *
	 * The mach_msg_receive_results() call saved off the message
	 * QoS values in the continuation save area on successful receive.
	 */
	if (kev->fflags == MACH_MSG_SUCCESS) {
		kev->qos = mach_msg_priority_combine(self->ith_qos, kn->kn_qos);
		kev->ext[2] = ((uint64_t)self->ith_qos << 32) | 
		               (uint64_t)self->ith_qos_override;
	}

	return 1;
}

/*
 * Peek to see if the message queue associated with the knote has any
 * events. This pre-hook is called when a filter uses the stay-
 * on-queue mechanism (as the knote_link_waitq mechanism does for
 * portsets) and someone calls select() against the containing kqueue.
 *
 * Just peek at the pre-post status of the portset's wait queue
 * to determine if it has anything interesting.  We can do it
 * without holding the lock, as it is just a snapshot in time
 * (if this is used as part of really waiting for events, we
 * will catch changes in this status when the event gets posted
 * up to the knote's kqueue).
 */
static unsigned
filt_machportpeek(struct knote *kn)
{
	ipc_mqueue_t mqueue = kn->kn_ptr.p_mqueue;

	return (ipc_mqueue_set_peek(mqueue));
}

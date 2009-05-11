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
 * Copyright (c) 1991,1990 Carnegie Mellon University
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

#include <mach/boolean.h>
#include <mach/port.h>
#include <mach/mig.h>
#include <mach/mig_errors.h>
#include <mach/mach_types.h>
#include <mach/mach_traps.h>

#include <kern/ipc_tt.h>
#include <kern/ipc_mig.h>
#include <kern/kalloc.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/ipc_kobject.h>
#include <kern/misc_protos.h>

#include <ipc/port.h>
#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_mqueue.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_pset.h>
#include <vm/vm_map.h>

/*
 *	Routine:	mach_msg_send_from_kernel
 *	Purpose:
 *		Send a message from the kernel.
 *
 *		This is used by the client side of KernelUser interfaces
 *		to implement SimpleRoutines.  Currently, this includes
 *		memory_object messages.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Sent the message.
 *		MACH_SEND_INVALID_DEST	Bad destination port.
 *		MACH_MSG_SEND_NO_BUFFER Destination port had inuse fixed bufer
 *		                        or destination is above kernel limit
 */

mach_msg_return_t
mach_msg_send_from_kernel(
	mach_msg_header_t	*msg,
	mach_msg_size_t		send_size)
{
	ipc_kmsg_t kmsg;
	mach_msg_return_t mr;

	if (!MACH_PORT_VALID((mach_port_name_t)msg->msgh_remote_port))
		return MACH_SEND_INVALID_DEST;

	mr = ipc_kmsg_get_from_kernel(msg, send_size, &kmsg);
	if (mr != MACH_MSG_SUCCESS)
		return mr;

	ipc_kmsg_copyin_from_kernel(kmsg);

	mr = ipc_kmsg_send_always(kmsg);
	if (mr != MACH_MSG_SUCCESS) {
		ipc_kmsg_destroy(kmsg);
	}

	return mr;
}

mach_msg_return_t
mach_msg_send_from_kernel_with_options(
	mach_msg_header_t	*msg,
	mach_msg_size_t		send_size,
	mach_msg_option_t	option,
	mach_msg_timeout_t	timeout_val)
{
	ipc_kmsg_t kmsg;
	mach_msg_return_t mr;

	if (!MACH_PORT_VALID((mach_port_name_t)msg->msgh_remote_port))
		return MACH_SEND_INVALID_DEST;

	mr = ipc_kmsg_get_from_kernel(msg, send_size, &kmsg);
	if (mr != MACH_MSG_SUCCESS)
		return mr;

	ipc_kmsg_copyin_from_kernel(kmsg);
	mr = ipc_kmsg_send(kmsg, option, timeout_val);
	if (mr != MACH_MSG_SUCCESS) {
		ipc_kmsg_destroy(kmsg);
	}
	
	return mr;
}

/*
 *	Routine:	mach_msg_rpc_from_kernel
 *	Purpose:
 *		Send a message from the kernel and receive a reply.
 *		Uses ith_rpc_reply for the reply port.
 *
 *		This is used by the client side of KernelUser interfaces
 *		to implement Routines.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Sent the message.
 *		MACH_RCV_PORT_DIED	The reply port was deallocated.
 */

mach_msg_return_t
mach_msg_rpc_from_kernel(
	mach_msg_header_t	*msg,
	mach_msg_size_t		send_size,
	mach_msg_size_t		rcv_size)
{
	thread_t self = current_thread();
	ipc_port_t reply;
	ipc_kmsg_t kmsg;
	mach_port_seqno_t seqno;
	mach_msg_return_t mr;

	assert(MACH_PORT_VALID((mach_port_name_t)msg->msgh_remote_port));
	assert(msg->msgh_local_port == MACH_PORT_NULL);

	mr = ipc_kmsg_get_from_kernel(msg, send_size, &kmsg);
	if (mr != MACH_MSG_SUCCESS)
		return mr;

	reply = self->ith_rpc_reply;
	if (reply == IP_NULL) {
		reply = ipc_port_alloc_reply();
		if ((reply == IP_NULL) ||
		    (self->ith_rpc_reply != IP_NULL))
			panic("mach_msg_rpc_from_kernel");
		self->ith_rpc_reply = reply;
	}

	/* insert send-once right for the reply port */
	kmsg->ikm_header->msgh_local_port = reply;
	kmsg->ikm_header->msgh_bits |=
		MACH_MSGH_BITS(0, MACH_MSG_TYPE_MAKE_SEND_ONCE);

	ipc_port_reference(reply);

	ipc_kmsg_copyin_from_kernel(kmsg);

	mr = ipc_kmsg_send_always(kmsg);
	if (mr != MACH_MSG_SUCCESS) {
		ipc_kmsg_destroy(kmsg);
		return mr;
	}

	for (;;) {
		ipc_mqueue_t mqueue;

		ip_lock(reply);
		if ( !ip_active(reply)) {
			ip_unlock(reply);
			ipc_port_release(reply);
			return MACH_RCV_PORT_DIED;
		}
		if (!self->active) {
			ip_unlock(reply);
			ipc_port_release(reply);
			return MACH_RCV_INTERRUPTED;
		}

		assert(reply->ip_pset_count == 0);
		mqueue = &reply->ip_messages;
		ip_unlock(reply);

		self->ith_continuation = (void (*)(mach_msg_return_t))0;

		ipc_mqueue_receive(mqueue,
				   MACH_MSG_OPTION_NONE,
				   MACH_MSG_SIZE_MAX,
				   MACH_MSG_TIMEOUT_NONE,
				   THREAD_INTERRUPTIBLE);

		mr = self->ith_state;
		kmsg = self->ith_kmsg;
		seqno = self->ith_seqno;

		if (mr == MACH_MSG_SUCCESS)
		  {
			break;
		  }

		assert(mr == MACH_RCV_INTERRUPTED);

		if (self->handlers) {
			ipc_port_release(reply);
			return(mr);
		}
	}
	ipc_port_release(reply);

	/* 
	 * Check to see how much of the message/trailer can be received.
	 * We chose the maximum trailer that will fit, since we don't
	 * have options telling us which trailer elements the caller needed.
	 */
	if (rcv_size >= kmsg->ikm_header->msgh_size) {
		mach_msg_format_0_trailer_t *trailer =  (mach_msg_format_0_trailer_t *)
			((vm_offset_t)kmsg->ikm_header + kmsg->ikm_header->msgh_size);

		if (rcv_size >= kmsg->ikm_header->msgh_size + MAX_TRAILER_SIZE) {
			/* Enough room for a maximum trailer */
			trailer->msgh_trailer_size = MAX_TRAILER_SIZE;
		} 
		else if (rcv_size < kmsg->ikm_header->msgh_size + 
			   trailer->msgh_trailer_size) {
			/* no room for even the basic (default) trailer */
			trailer->msgh_trailer_size = 0;
		}
		assert(trailer->msgh_trailer_type == MACH_MSG_TRAILER_FORMAT_0);
		rcv_size = kmsg->ikm_header->msgh_size + trailer->msgh_trailer_size;
		mr = MACH_MSG_SUCCESS;
	} else {
		mr = MACH_RCV_TOO_LARGE;
	}


	/*
	 *	We want to preserve rights and memory in reply!
	 *	We don't have to put them anywhere; just leave them
	 *	as they are.
	 */
	ipc_kmsg_copyout_to_kernel(kmsg, ipc_space_reply);
	ipc_kmsg_put_to_kernel(msg, kmsg, rcv_size);
	return mr;
}


/************** These Calls are set up for kernel-loaded tasks/threads **************/

/*
 *	Routine:	mach_msg_overwrite
 *	Purpose:
 *		Like mach_msg_overwrite_trap except that message buffers
 *		live in kernel space.  Doesn't handle any options.
 *
 *		This is used by in-kernel server threads to make
 *		kernel calls, to receive request messages, and
 *		to send reply messages.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 */

mach_msg_return_t
mach_msg_overwrite(
	mach_msg_header_t		*msg,
	mach_msg_option_t		option,
	mach_msg_size_t		send_size,
	mach_msg_size_t		rcv_size,
	mach_port_name_t		rcv_name,
	__unused mach_msg_timeout_t	msg_timeout,
	__unused mach_port_name_t	notify,
	__unused mach_msg_header_t	*rcv_msg,
       __unused mach_msg_size_t	rcv_msg_size)
{
	ipc_space_t space = current_space();
	vm_map_t map = current_map();
	ipc_kmsg_t kmsg;
	mach_port_seqno_t seqno;
	mach_msg_return_t mr;
	mach_msg_format_0_trailer_t *trailer;

	if (option & MACH_SEND_MSG) {
		mach_msg_size_t	msg_and_trailer_size;
		mach_msg_max_trailer_t	*max_trailer;

		if ((send_size < sizeof(mach_msg_header_t)) || (send_size & 3))
			return MACH_SEND_MSG_TOO_SMALL;

		if (send_size > MACH_MSG_SIZE_MAX - MAX_TRAILER_SIZE)
			return MACH_SEND_TOO_LARGE;

		msg_and_trailer_size = send_size + MAX_TRAILER_SIZE;
		kmsg = ipc_kmsg_alloc(msg_and_trailer_size);

		if (kmsg == IKM_NULL)
			return MACH_SEND_NO_BUFFER;

		(void) memcpy((void *) kmsg->ikm_header, (const void *) msg, send_size);

		kmsg->ikm_header->msgh_size = send_size;

		/* 
		 * Reserve for the trailer the largest space (MAX_TRAILER_SIZE)
		 * However, the internal size field of the trailer (msgh_trailer_size)
		 * is initialized to the minimum (sizeof(mach_msg_trailer_t)), to optimize
		 * the cases where no implicit data is requested.
		 */
		max_trailer = (mach_msg_max_trailer_t *) ((vm_offset_t)kmsg->ikm_header + send_size);
		max_trailer->msgh_sender = current_thread()->task->sec_token;
		max_trailer->msgh_audit = current_thread()->task->audit_token;
		max_trailer->msgh_trailer_type = MACH_MSG_TRAILER_FORMAT_0;
		max_trailer->msgh_trailer_size = MACH_MSG_TRAILER_MINIMUM_SIZE;
	
		mr = ipc_kmsg_copyin(kmsg, space, map, MACH_PORT_NULL);
		if (mr != MACH_MSG_SUCCESS) {
			ipc_kmsg_free(kmsg);
			return mr;
		}

		do
			mr = ipc_kmsg_send(kmsg, MACH_MSG_OPTION_NONE,
					     MACH_MSG_TIMEOUT_NONE);
		while (mr == MACH_SEND_INTERRUPTED);
		assert(mr == MACH_MSG_SUCCESS);
	}

	if (option & MACH_RCV_MSG) {
		thread_t self = current_thread();

		do {
			ipc_object_t object;
			ipc_mqueue_t mqueue;

			mr = ipc_mqueue_copyin(space, rcv_name,
					       &mqueue, &object);
			if (mr != MACH_MSG_SUCCESS)
				return mr;
			/* hold ref for object */

			self->ith_continuation = (void (*)(mach_msg_return_t))0;
			ipc_mqueue_receive(mqueue,
					   MACH_MSG_OPTION_NONE,
					   MACH_MSG_SIZE_MAX,
					   MACH_MSG_TIMEOUT_NONE,
					   THREAD_ABORTSAFE);
			mr = self->ith_state;
			kmsg = self->ith_kmsg;
			seqno = self->ith_seqno;

			ipc_object_release(object);

		} while (mr == MACH_RCV_INTERRUPTED);
		if (mr != MACH_MSG_SUCCESS)
			return mr;

		trailer = (mach_msg_format_0_trailer_t *) 
		    ((vm_offset_t)kmsg->ikm_header + kmsg->ikm_header->msgh_size);
		if (option & MACH_RCV_TRAILER_MASK) {
			trailer->msgh_seqno = seqno;
			trailer->msgh_trailer_size = REQUESTED_TRAILER_SIZE(option);
		}

		if (rcv_size < (kmsg->ikm_header->msgh_size + trailer->msgh_trailer_size)) {
			ipc_kmsg_copyout_dest(kmsg, space);
			(void) memcpy((void *) msg, (const void *) kmsg->ikm_header, sizeof *msg);
			ipc_kmsg_free(kmsg);
			return MACH_RCV_TOO_LARGE;
		}

		mr = ipc_kmsg_copyout(kmsg, space, map, MACH_PORT_NULL,
				      MACH_MSG_BODY_NULL);
		if (mr != MACH_MSG_SUCCESS) {
			if ((mr &~ MACH_MSG_MASK) == MACH_RCV_BODY_ERROR) {
				ipc_kmsg_put_to_kernel(msg, kmsg,
						kmsg->ikm_header->msgh_size + trailer->msgh_trailer_size);
			} else {
				ipc_kmsg_copyout_dest(kmsg, space);
				(void) memcpy((void *) msg, (const void *) kmsg->ikm_header, sizeof *msg);
				ipc_kmsg_free(kmsg);
			}

			return mr;
		}

		(void) memcpy((void *) msg, (const void *) kmsg->ikm_header,
			      kmsg->ikm_header->msgh_size + trailer->msgh_trailer_size);
		ipc_kmsg_free(kmsg);
	}

	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	mig_get_reply_port
 *	Purpose:
 *		Called by client side interfaces living in the kernel
 *		to get a reply port.
 */
mach_port_t
mig_get_reply_port(void)
{
	return (MACH_PORT_NULL);
}

/*
 *	Routine:	mig_dealloc_reply_port
 *	Purpose:
 *		Called by client side interfaces to get rid of a reply port.
 */

void
mig_dealloc_reply_port(
	__unused mach_port_t reply_port)
{
	panic("mig_dealloc_reply_port");
}

/*
 *	Routine:	mig_put_reply_port
 *	Purpose:
 *		Called by client side interfaces after each RPC to 
 *		let the client recycle the reply port if it wishes.
 */
void
mig_put_reply_port(
	__unused mach_port_t reply_port)
{
}

/*
 * mig_strncpy.c - by Joshua Block
 *
 * mig_strncp -- Bounded string copy.  Does what the library routine strncpy
 * OUGHT to do:  Copies the (null terminated) string in src into dest, a 
 * buffer of length len.  Assures that the copy is still null terminated
 * and doesn't overflow the buffer, truncating the copy if necessary.
 *
 * Parameters:
 * 
 *     dest - Pointer to destination buffer.
 * 
 *     src - Pointer to source string.
 * 
 *     len - Length of destination buffer.
 */
int 
mig_strncpy(
	char		*dest,
	const char	*src,
	int		len)
{
    int i = 0;

    if (len > 0)
	if (dest != NULL) {
	    if (src != NULL)
		   for (i=1; i<len; i++)
			if (! (*dest++ = *src++))
			    return i;
	        *dest = '\0';
	}
    return i;
}

char *
mig_user_allocate(
	vm_size_t	size)
{
	return (char *)kalloc(size);
}

void
mig_user_deallocate(
	char		*data,
	vm_size_t	size)
{
	kfree(data, size);
}

/*
 *	Routine:	mig_object_init
 *	Purpose:
 *		Initialize the base class portion of a MIG object.  We
 *		will lazy init the port, so just clear it for now.
 */
kern_return_t
mig_object_init(
	mig_object_t		mig_object,
	const IMIGObject	*interface)
{
	if (mig_object == MIG_OBJECT_NULL)
		return KERN_INVALID_ARGUMENT;
	mig_object->pVtbl = (const IMIGObjectVtbl *)interface;
	mig_object->port = MACH_PORT_NULL;
	return KERN_SUCCESS;
}

/*
 *	Routine:	mig_object_destroy
 *	Purpose:
 *		The object is being freed.  This call lets us clean
 *		up any state we have have built up over the object's
 *		lifetime.
 *	Conditions:
 *		Since notifications and the port hold references on
 *		on the object, neither can exist when this is called.
 *		This is a good place to assert() that condition.
 */
void
mig_object_destroy(
	__assert_only mig_object_t	mig_object)
{
	assert(mig_object->port == MACH_PORT_NULL);
	return;
}

/*
 *	Routine:	mig_object_reference
 *	Purpose:
 *		Pure virtual helper to invoke the MIG object's AddRef
 *		method.
 *	Conditions:
 *		MIG object port may be locked.
 */
void
mig_object_reference(
	mig_object_t	mig_object)
{
	assert(mig_object != MIG_OBJECT_NULL);
	mig_object->pVtbl->AddRef((IMIGObject *)mig_object);
}

/*
 *	Routine:	mig_object_deallocate
 *	Purpose:
 *		Pure virtual helper to invoke the MIG object's Release
 *		method.
 *	Conditions:
 *		Nothing locked.
 */
void
mig_object_deallocate(
	mig_object_t	mig_object)
{
	assert(mig_object != MIG_OBJECT_NULL);
	mig_object->pVtbl->Release((IMIGObject *)mig_object);
}

/*
 *	Routine:	convert_mig_object_to_port [interface]
 *	Purpose:
 *		Base implementation of MIG outtrans routine to convert from
 *		a mig object reference to a new send right on the object's
 *		port.  The object reference is consumed.
 *	Returns:
 *		IP_NULL - Null MIG object supplied
 *		Otherwise, a newly made send right for the port
 *	Conditions:
 *		Nothing locked.
 */
ipc_port_t
convert_mig_object_to_port(
	mig_object_t	mig_object)
{
	ipc_port_t	port;
	boolean_t	deallocate = TRUE;

	if (mig_object == MIG_OBJECT_NULL)
		return IP_NULL;

	port = mig_object->port;
	while ((port == IP_NULL) ||
	       ((port = ipc_port_make_send(port)) == IP_NULL)) {
		ipc_port_t	previous;

		/*
		 * Either the port was never set up, or it was just
		 * deallocated out from under us by the no-senders
		 * processing.  In either case, we must:
		 *	Attempt to make one
		 * 	Arrange for no senders
		 *	Try to atomically register it with the object
		 *		Destroy it if we are raced.
		 */
		port = ipc_port_alloc_kernel();
		ip_lock(port);
		ipc_kobject_set_atomically(port,
					   (ipc_kobject_t) mig_object,
					   IKOT_MIG);

		/* make a sonce right for the notification */
		port->ip_sorights++;
		ip_reference(port);

		ipc_port_nsrequest(port, 1, port, &previous);
		/* port unlocked */

		assert(previous == IP_NULL);

		if (hw_compare_and_store((uint32_t)IP_NULL, (uint32_t)port,
											(uint32_t *)&mig_object->port)) {
			deallocate = FALSE;
		} else {
			ipc_port_dealloc_kernel(port);
			port = mig_object->port;
		}
	}

	if (deallocate)
		mig_object->pVtbl->Release((IMIGObject *)mig_object);

	return (port);
}


/*
 *	Routine:	convert_port_to_mig_object [interface]
 *	Purpose:
 *		Base implementation of MIG intrans routine to convert from
 *		an incoming port reference to a new reference on the
 *		underlying object. A new reference must be created, because
 *		the port's reference could go away asynchronously.
 *	Returns:
 *		NULL - Not an active MIG object port or iid not supported
 *		Otherwise, a reference to the underlying MIG interface
 *	Conditions:
 *		Nothing locked.
 */
mig_object_t
convert_port_to_mig_object(
	ipc_port_t	port,
	const MIGIID	*iid)
{
	mig_object_t	mig_object;
	void 		*ppv;

	if (!IP_VALID(port))
		return NULL;

	ip_lock(port);
	if (!ip_active(port) || (ip_kotype(port) != IKOT_MIG)) {
		ip_unlock(port);
		return NULL;
	}

	/*
	 * Our port points to some MIG object interface.  Now
	 * query it to get a reference to the desired interface.
	 */
	ppv = NULL;
	mig_object = (mig_object_t)port->ip_kobject;
	mig_object->pVtbl->QueryInterface((IMIGObject *)mig_object, iid, &ppv);
	ip_unlock(port);
	return (mig_object_t)ppv;
}

/*
 *	Routine:	mig_object_no_senders [interface]
 *	Purpose:
 *		Base implementation of a no-senders notification handler
 *		for MIG objects. If there truly are no more senders, must
 *		destroy the port and drop its reference on the object.
 *	Returns:
 *		TRUE  - port deallocate and reference dropped
 *		FALSE - more senders arrived, re-registered for notification
 *	Conditions:
 *		Nothing locked.
 */

boolean_t
mig_object_no_senders(
	ipc_port_t		port,
	mach_port_mscount_t	mscount)
{
	mig_object_t		mig_object;

	ip_lock(port);
	if (port->ip_mscount > mscount) {
		ipc_port_t 	previous;

		/*
		 * Somebody created new send rights while the
		 * notification was in-flight.  Just create a
		 * new send-once right and re-register with 
		 * the new (higher) mscount threshold.
		 */
		/* make a sonce right for the notification */
		port->ip_sorights++;
		ip_reference(port);
		ipc_port_nsrequest(port, mscount, port, &previous);
		/* port unlocked */

		assert(previous == IP_NULL);
		return (FALSE);
	}

	/*
	 * Clear the port pointer while we have it locked.
	 */
	mig_object = (mig_object_t)port->ip_kobject;
	mig_object->port = IP_NULL;

	/*
	 * Bring the sequence number and mscount in
	 * line with ipc_port_destroy assertion.
	 */
	port->ip_mscount = 0;
	port->ip_messages.imq_seqno = 0;
	ipc_port_destroy(port); /* releases lock */
	
	/*
	 * Release the port's reference on the object.
	 */
	mig_object->pVtbl->Release((IMIGObject *)mig_object);
	return (TRUE);
}	

/*
 * Kernel implementation of the notification chain for MIG object
 * is kept separate from the actual objects, since there are expected
 * to be much fewer of them than actual objects.
 *
 * The implementation of this part of MIG objects is coming
 * "Real Soon Now"(TM).
 */

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

#include <norma_vm.h>
#include <mach_rt.h>

#include <mach/boolean.h>
#include <mach/port.h>
#include <mach/thread_status.h>
#include <mach/mig_errors.h>
#include <mach/mach_types.h>
#include <mach/mach_traps.h>
#include <kern/ast.h>
#include <kern/ipc_tt.h>
#include <kern/ipc_mig.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/ipc_kobject.h>
#include <kern/misc_protos.h>
#include <vm/vm_map.h>
#include <ipc/port.h>
#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_mqueue.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_pset.h>

/* Default (zeroed) template for qos */

static mach_port_qos_t	qos_template;

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
 *		MACH_MSG_SEND_NO_BUFFER Destination port had inuse fixed bufer
 *		MACH_SEND_INVALID_DEST	Bad destination port.
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
	ipc_kmsg_send_always(kmsg);

	return MACH_MSG_SUCCESS;
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

	rpc_lock(self);

	reply = self->ith_rpc_reply;
	if (reply == IP_NULL) {
		rpc_unlock(self);
		reply = ipc_port_alloc_reply();
		rpc_lock(self);
		if ((reply == IP_NULL) ||
		    (self->ith_rpc_reply != IP_NULL))
			panic("mach_msg_rpc_from_kernel");
		self->ith_rpc_reply = reply;
	}

	/* insert send-once right for the reply port */
	kmsg->ikm_header.msgh_local_port = reply;
	kmsg->ikm_header.msgh_bits |=
		MACH_MSGH_BITS(0, MACH_MSG_TYPE_MAKE_SEND_ONCE);

	ipc_port_reference(reply);
	rpc_unlock(self);

	ipc_kmsg_copyin_from_kernel(kmsg);

	ipc_kmsg_send_always(kmsg);

	for (;;) {
		ipc_mqueue_t mqueue;

		ip_lock(reply);
		if ( !ip_active(reply)) {
			ip_unlock(reply);
			ipc_port_release(reply);
			return MACH_RCV_PORT_DIED;
		}
		if (!self->top_act || !self->top_act->active) {
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

		if (self->top_act && self->top_act->handlers) {
			ipc_port_release(reply);
			return(mr);
		}
	}
	ipc_port_release(reply);

	/*
	 * XXXXX  Set manually for now ...
	 *	No, why even bother, since the effort is wasted?
	 *
	{ mach_msg_format_0_trailer_t *trailer = (mach_msg_format_0_trailer_t *)
		((vm_offset_t)&kmsg->ikm_header + kmsg->ikm_header.msgh_size);
	trailer->msgh_trailer_type = MACH_MSG_TRAILER_FORMAT_0;
	trailer->msgh_trailer_size = MACH_MSG_TRAILER_MINIMUM_SIZE;
	}
	 *****/

	if (rcv_size < kmsg->ikm_header.msgh_size) {
		ipc_kmsg_copyout_dest(kmsg, ipc_space_reply);
		ipc_kmsg_put_to_kernel(msg, kmsg, kmsg->ikm_header.msgh_size);
		return MACH_RCV_TOO_LARGE;
	}

	/*
	 *	We want to preserve rights and memory in reply!
	 *	We don't have to put them anywhere; just leave them
	 *	as they are.
	 */

	ipc_kmsg_copyout_to_kernel(kmsg, ipc_space_reply);
	ipc_kmsg_put_to_kernel(msg, kmsg, kmsg->ikm_header.msgh_size);
	return MACH_MSG_SUCCESS;
}


/************** These Calls are set up for kernel-loaded tasks   **************/
/************** Apple does not plan on supporting that. These    **************/
/************** need to be reworked to deal with the kernel      **************/
/************** proper to eliminate the kernel specific code MIG **************/
/************** must generate.                                   **************/


/*
 *	Routine:	mach_msg
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
	mach_msg_header_t	*msg,
	mach_msg_option_t	option,
	mach_msg_size_t		send_size,
	mach_msg_size_t		rcv_size,
	mach_port_name_t	rcv_name,
	mach_msg_timeout_t	timeout,
	mach_port_name_t	notify,
	mach_msg_header_t	*rcv_msg,
        mach_msg_size_t		rcv_msg_size)
{
	ipc_space_t space = current_space();
	vm_map_t map = current_map();
	ipc_kmsg_t kmsg;
	mach_port_seqno_t seqno;
	mach_msg_return_t mr;
	mach_msg_format_0_trailer_t *trailer;

	if (option & MACH_SEND_MSG) {
		mr = ipc_kmsg_get_from_kernel(msg, send_size, &kmsg);
		if (mr != MACH_MSG_SUCCESS)
			panic("mach_msg");

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
		    ((vm_offset_t)&kmsg->ikm_header + kmsg->ikm_header.msgh_size);
		if (option & MACH_RCV_TRAILER_MASK) {
			trailer->msgh_seqno = seqno;
			trailer->msgh_trailer_size = REQUESTED_TRAILER_SIZE(option);
		}

		if (rcv_size < (kmsg->ikm_header.msgh_size + trailer->msgh_trailer_size)) {
			ipc_kmsg_copyout_dest(kmsg, space);
			ipc_kmsg_put_to_kernel(msg, kmsg, sizeof *msg);
			return MACH_RCV_TOO_LARGE;
		}

		mr = ipc_kmsg_copyout(kmsg, space, map, MACH_PORT_NULL,
				      MACH_MSG_BODY_NULL);
		if (mr != MACH_MSG_SUCCESS) {
			if ((mr &~ MACH_MSG_MASK) == MACH_RCV_BODY_ERROR) {
				ipc_kmsg_put_to_kernel(msg, kmsg,
						kmsg->ikm_header.msgh_size + trailer->msgh_trailer_size);
			} else {
				ipc_kmsg_copyout_dest(kmsg, space);
				ipc_kmsg_put_to_kernel(msg, kmsg, sizeof *msg);
			}

			return mr;
		}

		ipc_kmsg_put_to_kernel(msg, kmsg, 
		      kmsg->ikm_header.msgh_size + trailer->msgh_trailer_size);
	}

	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	mig_get_reply_port
 *	Purpose:
 *		Called by client side interfaces living in the kernel
 *		to get a reply port.  This port is used for
 *		mach_msg() calls which are kernel calls.
 */
mach_port_t
mig_get_reply_port(void)
{
	thread_t self = current_thread();

	assert(self->ith_mig_reply == (mach_port_t)0);

	/* 
	 * JMM - for now we have no real clients of this under the kernel
	 * loaded server model because we only have one of those.  In order
	 * to avoid MIG changes, we just return null here - and return]
	 * references to ipc_port_t's instead of names.
	 *
	 * if (self->ith_mig_reply == MACH_PORT_NULL)
	 *	self->ith_mig_reply = mach_reply_port();
	 */
	return self->ith_mig_reply;
}

/*
 *	Routine:	mig_dealloc_reply_port
 *	Purpose:
 *		Called by client side interfaces to get rid of a reply port.
 *		Shouldn't ever be called inside the kernel, because
 *		kernel calls shouldn't prompt Mig to call it.
 */

void
mig_dealloc_reply_port(
	mach_port_t reply_port)
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
	mach_port_t reply_port)
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
	char	*dest,
	char	*src,
	int	len)
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
	kfree((vm_offset_t)data, size);
}


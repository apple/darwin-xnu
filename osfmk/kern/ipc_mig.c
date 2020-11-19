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
#include <ipc/ipc_notify.h>
#include <vm/vm_map.h>

#include <libkern/OSAtomic.h>

void
mach_msg_receive_results_complete(ipc_object_t object);

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

#if IKM_SUPPORT_LEGACY

#undef mach_msg_send_from_kernel
mach_msg_return_t mach_msg_send_from_kernel(
	mach_msg_header_t       *msg,
	mach_msg_size_t         send_size);

mach_msg_return_t
mach_msg_send_from_kernel(
	mach_msg_header_t       *msg,
	mach_msg_size_t         send_size)
{
	ipc_kmsg_t kmsg;
	mach_msg_return_t mr;

	KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_START);

	mr = ipc_kmsg_get_from_kernel(msg, send_size, &kmsg);
	if (mr != MACH_MSG_SUCCESS) {
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
		return mr;
	}

	mr = ipc_kmsg_copyin_from_kernel_legacy(kmsg);
	if (mr != MACH_MSG_SUCCESS) {
		ipc_kmsg_free(kmsg);
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
		return mr;
	}

	/*
	 * respect the thread's SEND_IMPORTANCE option to allow importance
	 * donation from the kernel-side of user threads
	 * (11938665 & 23925818)
	 */
	mach_msg_option_t option = MACH_SEND_KERNEL_DEFAULT;
	if (current_thread()->options & TH_OPT_SEND_IMPORTANCE) {
		option &= ~MACH_SEND_NOIMPORTANCE;
	}

	mr = ipc_kmsg_send(kmsg, option, MACH_MSG_TIMEOUT_NONE);
	if (mr != MACH_MSG_SUCCESS) {
		ipc_kmsg_destroy(kmsg);
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
	}

	return mr;
}

#endif /* IKM_SUPPORT_LEGACY */

mach_msg_return_t
mach_msg_send_from_kernel_proper(
	mach_msg_header_t       *msg,
	mach_msg_size_t         send_size)
{
	ipc_kmsg_t kmsg;
	mach_msg_return_t mr;

	KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_START);

	mr = ipc_kmsg_get_from_kernel(msg, send_size, &kmsg);
	if (mr != MACH_MSG_SUCCESS) {
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
		return mr;
	}

	mr = ipc_kmsg_copyin_from_kernel(kmsg);
	if (mr != MACH_MSG_SUCCESS) {
		ipc_kmsg_free(kmsg);
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
		return mr;
	}

	/*
	 * respect the thread's SEND_IMPORTANCE option to force importance
	 * donation from the kernel-side of user threads
	 * (11938665 & 23925818)
	 */
	mach_msg_option_t option = MACH_SEND_KERNEL_DEFAULT;
	if (current_thread()->options & TH_OPT_SEND_IMPORTANCE) {
		option &= ~MACH_SEND_NOIMPORTANCE;
	}

	mr = ipc_kmsg_send(kmsg, option, MACH_MSG_TIMEOUT_NONE);
	if (mr != MACH_MSG_SUCCESS) {
		ipc_kmsg_destroy(kmsg);
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
	}

	return mr;
}

mach_msg_return_t
mach_msg_send_from_kernel_with_options(
	mach_msg_header_t       *msg,
	mach_msg_size_t         send_size,
	mach_msg_option_t       option,
	mach_msg_timeout_t      timeout_val)
{
	return kernel_mach_msg_send(msg, send_size, option, timeout_val, NULL);
}

mach_msg_return_t
kernel_mach_msg_send(
	mach_msg_header_t       *msg,
	mach_msg_size_t         send_size,
	mach_msg_option_t       option,
	mach_msg_timeout_t      timeout_val,
	boolean_t               *message_moved)
{
	ipc_kmsg_t kmsg;
	mach_msg_return_t mr;

	KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_START);

	if (message_moved) {
		*message_moved = FALSE;
	}

	mr = ipc_kmsg_get_from_kernel(msg, send_size, &kmsg);
	if (mr != MACH_MSG_SUCCESS) {
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
		return mr;
	}

	mr = ipc_kmsg_copyin_from_kernel(kmsg);
	if (mr != MACH_MSG_SUCCESS) {
		ipc_kmsg_free(kmsg);
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
		return mr;
	}

	if (message_moved) {
		*message_moved = TRUE;
	}

	/*
	 * Until we are sure of its effects, we are disabling
	 * importance donation from the kernel-side of user
	 * threads in importance-donating tasks - unless the
	 * option to force importance donation is passed in,
	 * or the thread's SEND_IMPORTANCE option has been set.
	 * (11938665 & 23925818)
	 */
	if (current_thread()->options & TH_OPT_SEND_IMPORTANCE) {
		option &= ~MACH_SEND_NOIMPORTANCE;
	} else if ((option & MACH_SEND_IMPORTANCE) == 0) {
		option |= MACH_SEND_NOIMPORTANCE;
	}

	mr = ipc_kmsg_send(kmsg, option, timeout_val);

	if (mr != MACH_MSG_SUCCESS) {
		ipc_kmsg_destroy(kmsg);
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
	}

	return mr;
}


#if IKM_SUPPORT_LEGACY

mach_msg_return_t
mach_msg_send_from_kernel_with_options_legacy(
	mach_msg_header_t       *msg,
	mach_msg_size_t         send_size,
	mach_msg_option_t       option,
	mach_msg_timeout_t      timeout_val)
{
	ipc_kmsg_t kmsg;
	mach_msg_return_t mr;

	KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_START);

	mr = ipc_kmsg_get_from_kernel(msg, send_size, &kmsg);
	if (mr != MACH_MSG_SUCCESS) {
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
		return mr;
	}

	mr = ipc_kmsg_copyin_from_kernel_legacy(kmsg);
	if (mr != MACH_MSG_SUCCESS) {
		ipc_kmsg_free(kmsg);
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
		return mr;
	}

	/*
	 * Until we are sure of its effects, we are disabling
	 * importance donation from the kernel-side of user
	 * threads in importance-donating tasks.
	 * (11938665 & 23925818)
	 */
	if (current_thread()->options & TH_OPT_SEND_IMPORTANCE) {
		option &= ~MACH_SEND_NOIMPORTANCE;
	} else {
		option |= MACH_SEND_NOIMPORTANCE;
	}

	mr = ipc_kmsg_send(kmsg, option, timeout_val);

	if (mr != MACH_MSG_SUCCESS) {
		ipc_kmsg_destroy(kmsg);
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
	}

	return mr;
}

#endif /* IKM_SUPPORT_LEGACY */

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

#if IKM_SUPPORT_LEGACY

#undef mach_msg_rpc_from_kernel
mach_msg_return_t
mach_msg_rpc_from_kernel(
	mach_msg_header_t       *msg,
	mach_msg_size_t         send_size,
	mach_msg_size_t         rcv_size);

mach_msg_return_t
mach_msg_rpc_from_kernel(
	mach_msg_header_t       *msg,
	mach_msg_size_t         send_size,
	mach_msg_size_t         rcv_size)
{
	return kernel_mach_msg_rpc(msg, send_size, rcv_size, TRUE, NULL);
}
#endif /* IKM_SUPPORT_LEGACY */

mach_msg_return_t
mach_msg_rpc_from_kernel_proper(
	mach_msg_header_t       *msg,
	mach_msg_size_t         send_size,
	mach_msg_size_t         rcv_size)
{
	return kernel_mach_msg_rpc(msg, send_size, rcv_size, FALSE, NULL);
}

mach_msg_return_t
kernel_mach_msg_rpc(
	mach_msg_header_t       *msg,
	mach_msg_size_t         send_size,
	mach_msg_size_t         rcv_size,
#if !IKM_SUPPORT_LEGACY
	__unused
#endif
	boolean_t           legacy,
	boolean_t           *message_moved)
{
	thread_t self = current_thread();
	ipc_port_t reply;
	ipc_kmsg_t kmsg;
	mach_port_seqno_t seqno;
	mach_msg_return_t mr;

	assert(msg->msgh_local_port == MACH_PORT_NULL);

	KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_START);

	if (message_moved) {
		*message_moved = FALSE;
	}

	mr = ipc_kmsg_get_from_kernel(msg, send_size, &kmsg);
	if (mr != MACH_MSG_SUCCESS) {
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
		return mr;
	}

	reply = self->ith_rpc_reply;
	if (reply == IP_NULL) {
		reply = ipc_port_alloc_reply();
		if ((reply == IP_NULL) ||
		    (self->ith_rpc_reply != IP_NULL)) {
			panic("mach_msg_rpc_from_kernel");
		}
		self->ith_rpc_reply = reply;
	}

	/* insert send-once right for the reply port */
	kmsg->ikm_header->msgh_local_port = reply;
	kmsg->ikm_header->msgh_bits |=
	    MACH_MSGH_BITS(0, MACH_MSG_TYPE_MAKE_SEND_ONCE);

#if IKM_SUPPORT_LEGACY
	if (legacy) {
		mr = ipc_kmsg_copyin_from_kernel_legacy(kmsg);
	} else {
		mr = ipc_kmsg_copyin_from_kernel(kmsg);
	}
#else
	mr = ipc_kmsg_copyin_from_kernel(kmsg);
#endif
	if (mr != MACH_MSG_SUCCESS) {
		ipc_kmsg_free(kmsg);
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
		return mr;
	}

	if (message_moved) {
		*message_moved = TRUE;
	}

	/*
	 * respect the thread's SEND_IMPORTANCE option to force importance
	 * donation from the kernel-side of user threads
	 * (11938665 & 23925818)
	 */
	mach_msg_option_t option = MACH_SEND_KERNEL_DEFAULT;
	if (current_thread()->options & TH_OPT_SEND_IMPORTANCE) {
		option &= ~MACH_SEND_NOIMPORTANCE;
	}

	mr = ipc_kmsg_send(kmsg, option, MACH_MSG_TIMEOUT_NONE);
	if (mr != MACH_MSG_SUCCESS) {
		ipc_kmsg_destroy(kmsg);
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
		return mr;
	}

	for (;;) {
		ipc_mqueue_t mqueue;

		assert(reply->ip_in_pset == 0);
		require_ip_active(reply);

		/* JMM - why this check? */
		if (!self->active && !self->inspection) {
			ipc_port_dealloc_reply(reply);
			self->ith_rpc_reply = IP_NULL;
			return MACH_RCV_INTERRUPTED;
		}

		self->ith_continuation = (void (*)(mach_msg_return_t))0;

		mqueue = &reply->ip_messages;
		ipc_mqueue_receive(mqueue,
		    MACH_MSG_OPTION_NONE,
		    MACH_MSG_SIZE_MAX,
		    MACH_MSG_TIMEOUT_NONE,
		    THREAD_INTERRUPTIBLE);

		mr = self->ith_state;
		kmsg = self->ith_kmsg;
		seqno = self->ith_seqno;

		mach_msg_receive_results_complete(ip_to_object(reply));

		if (mr == MACH_MSG_SUCCESS) {
			break;
		}

		assert(mr == MACH_RCV_INTERRUPTED);

		assert(reply == self->ith_rpc_reply);

		if (self->ast & AST_APC) {
			ipc_port_dealloc_reply(reply);
			self->ith_rpc_reply = IP_NULL;
			return mr;
		}
	}

	mach_msg_format_0_trailer_t *trailer =  (mach_msg_format_0_trailer_t *)
	    ((vm_offset_t)kmsg->ikm_header + kmsg->ikm_header->msgh_size);

	/* must be able to receive message proper */
	if (rcv_size < kmsg->ikm_header->msgh_size) {
		ipc_kmsg_destroy(kmsg);
		return MACH_RCV_TOO_LARGE;
	}

	/*
	 *	We want to preserve rights and memory in reply!
	 *	We don't have to put them anywhere; just leave them
	 *	as they are.
	 */
#if IKM_SUPPORT_LEGACY
	if (legacy) {
		ipc_kmsg_copyout_to_kernel_legacy(kmsg, ipc_space_reply);
	} else {
		ipc_kmsg_copyout_to_kernel(kmsg, ipc_space_reply);
	}
#else
	ipc_kmsg_copyout_to_kernel(kmsg, ipc_space_reply);
#endif

	/* Determine what trailer bits we can receive (as no option specified) */
	if (rcv_size < kmsg->ikm_header->msgh_size + MACH_MSG_TRAILER_MINIMUM_SIZE) {
		rcv_size = kmsg->ikm_header->msgh_size;
	} else {
		if (rcv_size >= kmsg->ikm_header->msgh_size + MAX_TRAILER_SIZE) {
			/*
			 * Enough room for a maximum trailer.
			 * JMM - we really should set the expected receiver-set fields:
			 *       (seqno, context, filterid, etc...) but nothing currently
			 *       expects them anyway.
			 */
			trailer->msgh_trailer_size = MAX_TRAILER_SIZE;
		} else {
			assert(trailer->msgh_trailer_size == MACH_MSG_TRAILER_MINIMUM_SIZE);
		}
		rcv_size = kmsg->ikm_header->msgh_size + trailer->msgh_trailer_size;
	}
	assert(trailer->msgh_trailer_type == MACH_MSG_TRAILER_FORMAT_0);
	mr = MACH_MSG_SUCCESS;

	ipc_kmsg_put_to_kernel(msg, kmsg, rcv_size);
	return mr;
}

/*
 *	Routine:	mach_msg_destroy_from_kernel_proper
 *	Purpose:
 *		mach_msg_destroy_from_kernel_proper is used to destroy
 *		an unwanted/unexpected reply message from a MIG
 *		kernel-specific user-side stub.	It is like ipc_kmsg_destroy(),
 *		except we no longer have the kmsg - just the contents.
 */
void
mach_msg_destroy_from_kernel_proper(mach_msg_header_t *msg)
{
	mach_msg_bits_t mbits = msg->msgh_bits;
	ipc_object_t object;

	object = (ipc_object_t) msg->msgh_remote_port;
	if (IO_VALID(object)) {
		ipc_object_destroy(object, MACH_MSGH_BITS_REMOTE(mbits));
	}

	/*
	 * The destination (now in msg->msgh_local_port via
	 * ipc_kmsg_copyout_to_kernel) has been consumed with
	 * ipc_object_copyout_dest.
	 */

	/* MIG kernel users don't receive vouchers */
	assert(!MACH_MSGH_BITS_VOUCHER(mbits));

	/* For simple messages, we're done */
	if ((mbits & MACH_MSGH_BITS_COMPLEX) == 0) {
		return;
	}

	/* Discard descriptor contents */
	mach_msg_body_t *body = (mach_msg_body_t *)(msg + 1);
	mach_msg_descriptor_t *daddr = (mach_msg_descriptor_t *)(body + 1);
	mach_msg_size_t i;

	for (i = 0; i < body->msgh_descriptor_count; i++, daddr++) {
		switch (daddr->type.type) {
		case MACH_MSG_PORT_DESCRIPTOR: {
			mach_msg_port_descriptor_t *dsc = &daddr->port;
			if (IO_VALID((ipc_object_t) dsc->name)) {
				ipc_object_destroy((ipc_object_t) dsc->name, dsc->disposition);
			}
			break;
		}
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
		case MACH_MSG_OOL_DESCRIPTOR: {
			mach_msg_ool_descriptor_t *dsc =
			    (mach_msg_ool_descriptor_t *)&daddr->out_of_line;

			if (dsc->size > 0) {
				vm_map_copy_discard((vm_map_copy_t) dsc->address);
			} else {
				assert(dsc->address == (void *) 0);
			}
			break;
		}
		case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
			ipc_object_t                    *objects;
			mach_msg_type_number_t          j;
			mach_msg_ool_ports_descriptor_t *dsc;

			dsc = (mach_msg_ool_ports_descriptor_t  *)&daddr->ool_ports;
			objects = (ipc_object_t *) dsc->address;

			if (dsc->count == 0) {
				break;
			}
			assert(objects != 0);
			for (j = 0; j < dsc->count; j++) {
				object = objects[j];
				if (IO_VALID(object)) {
					ipc_object_destroy(object, dsc->disposition);
				}
			}
			kfree(dsc->address, (vm_size_t) dsc->count * sizeof(mach_port_t));
			break;
		}
		case MACH_MSG_GUARDED_PORT_DESCRIPTOR: {
			mach_msg_guarded_port_descriptor_t *dsc = (mach_msg_guarded_port_descriptor_t *)&daddr->guarded_port;
			if (IO_VALID((ipc_object_t) dsc->name)) {
				ipc_object_destroy((ipc_object_t) dsc->name, dsc->disposition);
			}
			break;
		}
		default:
			break;
		}
	}
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
	mach_msg_header_t               *msg,
	mach_msg_option_t               option,
	mach_msg_size_t         send_size,
	mach_msg_size_t         rcv_size,
	mach_port_name_t                rcv_name,
	__unused mach_msg_timeout_t     msg_timeout,
	mach_msg_priority_t     priority,
	__unused mach_msg_header_t      *rcv_msg,
	__unused mach_msg_size_t rcv_msg_size)
{
	ipc_space_t space = current_space();
	vm_map_t map = current_map();
	ipc_kmsg_t kmsg;
	mach_port_seqno_t seqno;
	mach_msg_return_t mr;
	mach_msg_trailer_size_t trailer_size;

	if (option & MACH_SEND_MSG) {
		mach_msg_size_t msg_and_trailer_size;
		mach_msg_max_trailer_t  *max_trailer;

		if ((send_size & 3) ||
		    send_size < sizeof(mach_msg_header_t) ||
		    (send_size < sizeof(mach_msg_base_t) && (msg->msgh_bits & MACH_MSGH_BITS_COMPLEX))) {
			return MACH_SEND_MSG_TOO_SMALL;
		}

		if (send_size > MACH_MSG_SIZE_MAX - MAX_TRAILER_SIZE) {
			return MACH_SEND_TOO_LARGE;
		}

		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_START);

		msg_and_trailer_size = send_size + MAX_TRAILER_SIZE;
		kmsg = ipc_kmsg_alloc(msg_and_trailer_size);

		if (kmsg == IKM_NULL) {
			KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, MACH_SEND_NO_BUFFER);
			return MACH_SEND_NO_BUFFER;
		}

		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_LINK) | DBG_FUNC_NONE,
		    (uintptr_t)0,                   /* this should only be called from the kernel! */
		    VM_KERNEL_ADDRPERM((uintptr_t)kmsg),
		    0, 0,
		    0);
		(void) memcpy((void *) kmsg->ikm_header, (const void *) msg, send_size);

		kmsg->ikm_header->msgh_size = send_size;

		/*
		 * Reserve for the trailer the largest space (MAX_TRAILER_SIZE)
		 * However, the internal size field of the trailer (msgh_trailer_size)
		 * is initialized to the minimum (sizeof(mach_msg_trailer_t)), to optimize
		 * the cases where no implicit data is requested.
		 */
		max_trailer = (mach_msg_max_trailer_t *) ((vm_offset_t)kmsg->ikm_header + send_size);
		bzero(max_trailer, sizeof(*max_trailer));
		max_trailer->msgh_sender = current_thread()->task->sec_token;
		max_trailer->msgh_audit = current_thread()->task->audit_token;
		max_trailer->msgh_trailer_type = MACH_MSG_TRAILER_FORMAT_0;
		max_trailer->msgh_trailer_size = MACH_MSG_TRAILER_MINIMUM_SIZE;

		mr = ipc_kmsg_copyin(kmsg, space, map, priority, &option);

		if (mr != MACH_MSG_SUCCESS) {
			ipc_kmsg_free(kmsg);
			KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
			return mr;
		}

		do {
			mr = ipc_kmsg_send(kmsg, MACH_MSG_OPTION_NONE, MACH_MSG_TIMEOUT_NONE);
		} while (mr == MACH_SEND_INTERRUPTED);

		assert(mr == MACH_MSG_SUCCESS);
	}

	if (option & MACH_RCV_MSG) {
		thread_t self = current_thread();
		mach_vm_address_t context;

		do {
			ipc_object_t object;
			ipc_mqueue_t mqueue;

			mr = ipc_mqueue_copyin(space, rcv_name,
			    &mqueue, &object);
			if (mr != MACH_MSG_SUCCESS) {
				return mr;
			}

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

			mach_msg_receive_results_complete(object);
			io_release(object);
		} while (mr == MACH_RCV_INTERRUPTED);

		if (mr != MACH_MSG_SUCCESS) {
			return mr;
		}

		trailer_size = ipc_kmsg_trailer_size(option, self);

		if (rcv_size < (kmsg->ikm_header->msgh_size + trailer_size)) {
			ipc_kmsg_copyout_dest(kmsg, space);
			(void) memcpy((void *) msg, (const void *) kmsg->ikm_header, sizeof *msg);
			ipc_kmsg_free(kmsg);
			return MACH_RCV_TOO_LARGE;
		}

		/* Save destination port context for the trailer before copyout */
		context = kmsg->ikm_header->msgh_remote_port->ip_context;

		mr = ipc_kmsg_copyout(kmsg, space, map, MACH_MSG_BODY_NULL, option);

		if (mr != MACH_MSG_SUCCESS) {
			if ((mr & ~MACH_MSG_MASK) == MACH_RCV_BODY_ERROR) {
				ipc_kmsg_add_trailer(kmsg, space, option, self, seqno, TRUE, context);
				ipc_kmsg_put_to_kernel(msg, kmsg,
				    kmsg->ikm_header->msgh_size + trailer_size);
			} else {
				ipc_kmsg_copyout_dest(kmsg, space);
				(void) memcpy((void *) msg, (const void *) kmsg->ikm_header, sizeof *msg);
				ipc_kmsg_free(kmsg);
			}

			return mr;
		}
		ipc_kmsg_add_trailer(kmsg, space, option, self, seqno, TRUE, context);
		(void) memcpy((void *) msg, (const void *) kmsg->ikm_header,
		    kmsg->ikm_header->msgh_size + trailer_size);
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
	return MACH_PORT_NULL;
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
	char            *dest,
	const char      *src,
	int             len)
{
	int i = 0;

	if (len > 0) {
		if (dest != NULL) {
			if (src != NULL) {
				for (i = 1; i < len; i++) {
					if (!(*dest++ = *src++)) {
						return i;
					}
				}
			}
			*dest = '\0';
		}
	}
	return i;
}

/*
 * mig_strncpy_zerofill -- Bounded string copy.  Does what the
 * library routine strncpy OUGHT to do:  Copies the (null terminated)
 * string in src into dest, a buffer of length len.  Assures that
 * the copy is still null terminated and doesn't overflow the buffer,
 * truncating the copy if necessary. If the string in src is smaller
 * than given length len, it will zero fill the remaining bytes in dest.
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
mig_strncpy_zerofill(
	char            *dest,
	const char      *src,
	int             len)
{
	int i = 0;
	boolean_t terminated = FALSE;
	int retval = 0;

	if (len <= 0 || dest == NULL) {
		return 0;
	}

	if (src == NULL) {
		terminated = TRUE;
	}

	for (i = 1; i < len; i++) {
		if (!terminated) {
			if (!(*dest++ = *src++)) {
				retval = i;
				terminated = TRUE;
			}
		} else {
			*dest++ = '\0';
		}
	}

	*dest = '\0';
	if (!terminated) {
		retval = i;
	}

	return retval;
}

void *
mig_user_allocate(
	vm_size_t       size)
{
	return (char *)kalloc(size);
}

void
mig_user_deallocate(
	char            *data,
	vm_size_t       size)
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
	mig_object_t            mig_object,
	const IMIGObject        *interface)
{
	if (mig_object == MIG_OBJECT_NULL) {
		return KERN_INVALID_ARGUMENT;
	}
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
	__assert_only mig_object_t      mig_object)
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
	mig_object_t    mig_object)
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
	mig_object_t    mig_object)
{
	assert(mig_object != MIG_OBJECT_NULL);
	ipc_port_t port = mig_object->port;
	if (mig_object->pVtbl->Release((IMIGObject *)mig_object) == 0) {
		if (IP_VALID(port)) {
			assert(!port->ip_srights);
			ipc_port_dealloc_kernel(port);
		}
	}
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
	mig_object_t    mig_object)
{
	if (mig_object == MIG_OBJECT_NULL) {
		return IP_NULL;
	}

	/*
	 * make a send right and donate our reference for mig_object_no_senders
	 * if this is the first send right
	 */
	if (!ipc_kobject_make_send_lazy_alloc_port(&mig_object->port,
	    (ipc_kobject_t) mig_object, IKOT_MIG, false, 0)) {
		mig_object_deallocate(mig_object);
	}

	return mig_object->port;
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
	ipc_port_t      port,
	const MIGIID    *iid)
{
	mig_object_t    mig_object;
	void            *ppv;

	if (!IP_VALID(port)) {
		return NULL;
	}

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
	mig_object = (mig_object_t) ip_get_kobject(port);
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
 *	Conditions:
 *		Nothing locked.
 */
void
mig_object_no_senders(
	ipc_port_t              port)
{
	require_ip_active(port);
	assert(IKOT_MIG == ip_kotype(port));

	/* consume the reference donated by convert_mig_object_to_port */
	mig_object_deallocate((mig_object_t) ip_get_kobject(port));
}

/*
 * Kernel implementation of the notification chain for MIG object
 * is kept separate from the actual objects, since there are expected
 * to be much fewer of them than actual objects.
 *
 * The implementation of this part of MIG objects is coming
 * "Real Soon Now"(TM).
 */

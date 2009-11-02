/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
 *	File:	ipc/mach_msg.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Exported message traps.  See mach/message.h.
 */

#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <mach/port.h>
#include <mach/message.h>
#include <mach/mig_errors.h>
#include <mach/mach_traps.h>

#include <kern/kern_types.h>
#include <kern/assert.h>
#include <kern/counters.h>
#include <kern/cpu_number.h>
#include <kern/ipc_kobject.h>
#include <kern/ipc_mig.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/lock.h>
#include <kern/sched_prim.h>
#include <kern/exception.h>
#include <kern/misc_protos.h>
#include <kern/kalloc.h>
#include <kern/processor.h>
#include <kern/syscall_subr.h>

#include <vm/vm_map.h>

#include <ipc/ipc_types.h>
#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_mqueue.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_notify.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_pset.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_entry.h>

#include <machine/machine_routines.h>

#include <sys/kdebug.h>

#ifndef offsetof
#define offsetof(type, member)  ((size_t)(&((type *)0)->member))
#endif /* offsetof */

/*
 * Forward declarations - kernel internal routines
 */

mach_msg_return_t mach_msg_send(
	mach_msg_header_t	*msg,
	mach_msg_option_t	option,
	mach_msg_size_t		send_size,
	mach_msg_timeout_t	send_timeout,
	mach_port_name_t	notify);

mach_msg_return_t mach_msg_receive(
	mach_msg_header_t	*msg,
	mach_msg_option_t	option,
	mach_msg_size_t		rcv_size,
	mach_port_name_t	rcv_name,
	mach_msg_timeout_t	rcv_timeout,
	void 			(*continuation)(mach_msg_return_t),
	mach_msg_size_t		slist_size);


mach_msg_return_t mach_msg_receive_results(void);

mach_msg_return_t msg_receive_error(
	ipc_kmsg_t		kmsg,
	mach_vm_address_t	msg_addr,
	mach_msg_option_t	option,
	mach_port_seqno_t	seqno,
	ipc_space_t		space);

security_token_t KERNEL_SECURITY_TOKEN = KERNEL_SECURITY_TOKEN_VALUE;
audit_token_t KERNEL_AUDIT_TOKEN = KERNEL_AUDIT_TOKEN_VALUE;

mach_msg_format_0_trailer_t trailer_template = {
	/* mach_msg_trailer_type_t */ MACH_MSG_TRAILER_FORMAT_0,
	/* mach_msg_trailer_size_t */ MACH_MSG_TRAILER_MINIMUM_SIZE,
        /* mach_port_seqno_t */       0,
	/* security_token_t */        KERNEL_SECURITY_TOKEN_VALUE
};

/*
 *	Routine:	mach_msg_send
 *	Purpose:
 *		Send a message.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Sent the message.
 *		MACH_SEND_MSG_TOO_SMALL	Message smaller than a header.
 *		MACH_SEND_NO_BUFFER	Couldn't allocate buffer.
 *		MACH_SEND_INVALID_DATA	Couldn't copy message data.
 *		MACH_SEND_INVALID_HEADER
 *			Illegal value in the message header bits.
 *		MACH_SEND_INVALID_DEST	The space is dead.
 *		MACH_SEND_INVALID_NOTIFY	Bad notify port.
 *		MACH_SEND_INVALID_DEST	Can't copyin destination port.
 *		MACH_SEND_INVALID_REPLY	Can't copyin reply port.
 *		MACH_SEND_TIMED_OUT	Timeout expired without delivery.
 *		MACH_SEND_INTERRUPTED	Delivery interrupted.
 *		MACH_SEND_NO_NOTIFY	Can't allocate a msg-accepted request.
 *		MACH_SEND_WILL_NOTIFY	Msg-accepted notif. requested.
 *		MACH_SEND_NOTIFY_IN_PROGRESS
 *			This space has already forced a message to this port.
 */

mach_msg_return_t
mach_msg_send(
	mach_msg_header_t	*msg,
	mach_msg_option_t	option,
	mach_msg_size_t		send_size,
	mach_msg_timeout_t	send_timeout,
	mach_port_name_t	notify)
{
	ipc_space_t space = current_space();
	vm_map_t map = current_map();
	ipc_kmsg_t kmsg;
	mach_msg_return_t mr;
	mach_msg_size_t	msg_and_trailer_size;
	mach_msg_max_trailer_t	*trailer;

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
	 * reserve for the trailer the largest space (MAX_TRAILER_SIZE)
	 * However, the internal size field of the trailer (msgh_trailer_size)
	 * is initialized to the minimum (sizeof(mach_msg_trailer_t)), to optimize
	 * the cases where no implicit data is requested.
	 */
	trailer = (mach_msg_max_trailer_t *) ((vm_offset_t)kmsg->ikm_header + send_size);
	trailer->msgh_sender = current_thread()->task->sec_token;
	trailer->msgh_audit = current_thread()->task->audit_token;
	trailer->msgh_trailer_type = MACH_MSG_TRAILER_FORMAT_0;
	trailer->msgh_trailer_size = MACH_MSG_TRAILER_MINIMUM_SIZE;
	
	if (option & MACH_SEND_CANCEL) {
		if (notify == MACH_PORT_NULL)
			mr = MACH_SEND_INVALID_NOTIFY;
		else
			mr = ipc_kmsg_copyin(kmsg, space, map, notify);
	} else
		mr = ipc_kmsg_copyin(kmsg, space, map, MACH_PORT_NULL);
	if (mr != MACH_MSG_SUCCESS) {
		ipc_kmsg_free(kmsg);
		return mr;
	}

	mr = ipc_kmsg_send(kmsg, option & MACH_SEND_TIMEOUT, send_timeout);

	if (mr != MACH_MSG_SUCCESS) {
	    mr |= ipc_kmsg_copyout_pseudo(kmsg, space, map, MACH_MSG_BODY_NULL);
	    (void) memcpy((void *) msg, (const void *) kmsg->ikm_header, 
			  kmsg->ikm_header->msgh_size);
	    ipc_kmsg_free(kmsg);
	}

	return mr;
}

/*
 *	Routine:	mach_msg_receive
 *	Purpose:
 *		Receive a message.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Received a message.
 *		MACH_RCV_INVALID_NAME	The name doesn't denote a right,
 *			or the denoted right is not receive or port set.
 *		MACH_RCV_IN_SET		Receive right is a member of a set.
 *		MACH_RCV_TOO_LARGE	Message wouldn't fit into buffer.
 *		MACH_RCV_TIMED_OUT	Timeout expired without a message.
 *		MACH_RCV_INTERRUPTED	Reception interrupted.
 *		MACH_RCV_PORT_DIED	Port/set died while receiving.
 *		MACH_RCV_PORT_CHANGED	Port moved into set while receiving.
 *		MACH_RCV_INVALID_DATA	Couldn't copy to user buffer.
 *		MACH_RCV_INVALID_NOTIFY	Bad notify port.
 *		MACH_RCV_HEADER_ERROR
 */

mach_msg_return_t
mach_msg_receive_results(void)
{
	thread_t          self = current_thread();
	ipc_space_t       space = current_space();
	vm_map_t	  map = current_map();

	ipc_object_t      object = self->ith_object;
	mach_msg_return_t mr = self->ith_state;
	mach_vm_address_t msg_addr = self->ith_msg_addr;
	mach_msg_option_t option = self->ith_option;
	ipc_kmsg_t        kmsg = self->ith_kmsg;
	mach_port_seqno_t seqno = self->ith_seqno;

	mach_msg_format_0_trailer_t *trailer;

	ipc_object_release(object);

	if (mr != MACH_MSG_SUCCESS) {

	  if (mr == MACH_RCV_TOO_LARGE ) {
	    if (option & MACH_RCV_LARGE) {
	      /*
	       * We need to inform the user-level code that it needs more
	       * space.  The value for how much space was returned in the
	       * msize save area instead of the message (which was left on
	       * the queue).
	       */
	      if (copyout((char *) &self->ith_msize,
			  msg_addr + offsetof(mach_msg_header_t, msgh_size),
			  sizeof(mach_msg_size_t)))
		mr = MACH_RCV_INVALID_DATA;
	      goto out;
	    }
		  
	    if (msg_receive_error(kmsg, msg_addr, option, seqno, space)
		== MACH_RCV_INVALID_DATA)
	      mr = MACH_RCV_INVALID_DATA;
	  }
	  goto out;
	}

	trailer = (mach_msg_format_0_trailer_t *)
			((vm_offset_t)kmsg->ikm_header +
			round_msg(kmsg->ikm_header->msgh_size));
	if (option & MACH_RCV_TRAILER_MASK) {
		trailer->msgh_seqno = seqno;
		trailer->msgh_trailer_size = REQUESTED_TRAILER_SIZE(option);
	}

	/*
	 * If MACH_RCV_OVERWRITE was specified, try to get the scatter
	 * list and verify it against the contents of the message.  If
	 * there is any problem with it, we will continue without it as
	 * normal.
	 */
	if (option & MACH_RCV_OVERWRITE) {
		mach_msg_size_t slist_size = self->ith_scatter_list_size;
		mach_msg_body_t *slist;

		slist = ipc_kmsg_get_scatter(msg_addr, slist_size, kmsg);
		mr = ipc_kmsg_copyout(kmsg, space, map, MACH_PORT_NULL, slist);
		ipc_kmsg_free_scatter(slist, slist_size);
	} else {
		mr = ipc_kmsg_copyout(kmsg, space, map,
				      MACH_PORT_NULL, MACH_MSG_BODY_NULL);
	}

	if (mr != MACH_MSG_SUCCESS) {
		if ((mr &~ MACH_MSG_MASK) == MACH_RCV_BODY_ERROR) {
			if (ipc_kmsg_put(msg_addr, kmsg, kmsg->ikm_header->msgh_size +
			   trailer->msgh_trailer_size) == MACH_RCV_INVALID_DATA)
				mr = MACH_RCV_INVALID_DATA;
		} 
		else {
			if (msg_receive_error(kmsg, msg_addr, option, seqno, space) 
						== MACH_RCV_INVALID_DATA)
				mr = MACH_RCV_INVALID_DATA;
		}
		goto out;
	}
	mr = ipc_kmsg_put(msg_addr,
			  kmsg,
			  kmsg->ikm_header->msgh_size + 
			  trailer->msgh_trailer_size);
 out:
	return mr;
}

mach_msg_return_t
mach_msg_receive(
	mach_msg_header_t	*msg,
	mach_msg_option_t	option,
	mach_msg_size_t		rcv_size,
	mach_port_name_t	rcv_name,
	mach_msg_timeout_t	rcv_timeout,
	void			(*continuation)(mach_msg_return_t),
	mach_msg_size_t		slist_size)
{
	thread_t self = current_thread();
	ipc_space_t space = current_space();
	ipc_object_t object;
	ipc_mqueue_t mqueue;
	mach_msg_return_t mr;

	mr = ipc_mqueue_copyin(space, rcv_name, &mqueue, &object);
 	if (mr != MACH_MSG_SUCCESS) {
		return mr;
	}
	/* hold ref for object */

	self->ith_msg_addr = CAST_DOWN(mach_vm_address_t, msg);
	self->ith_object = object;
	self->ith_msize = rcv_size;
	self->ith_option = option;
	self->ith_scatter_list_size = slist_size;
	self->ith_continuation = continuation;

	ipc_mqueue_receive(mqueue, option, rcv_size, rcv_timeout, THREAD_ABORTSAFE);
	if ((option & MACH_RCV_TIMEOUT) && rcv_timeout == 0)
		thread_poll_yield(self);
	return mach_msg_receive_results();
}

void
mach_msg_receive_continue(void)
{
	thread_t self = current_thread();

	(*self->ith_continuation)(mach_msg_receive_results());
}

/*
 * Toggle this to compile the hotpath in/out
 * If compiled in, the run-time toggle "enable_hotpath" below
 * eases testing & debugging
 */
#define ENABLE_HOTPATH 1   /* Hacked on for now */

#if	ENABLE_HOTPATH
/*
 * These counters allow tracing of hotpath behavior under test loads.
 * A couple key counters are unconditional (see below).
 */
#define	HOTPATH_DEBUG	0	/* Toggle to include lots of counters	*/
#if	HOTPATH_DEBUG
#define HOT(expr)	expr

unsigned int c_mmot_FIRST = 0;			/* Unused First Counter	*/
unsigned int c_mmot_combined_S_R = 0;		/* hotpath candidates	*/
unsigned int c_mach_msg_trap_switch_fast = 0;	/* hotpath successes	*/
unsigned int c_mmot_kernel_send = 0;		/*    kernel server	*/
unsigned int c_mmot_cold_000 = 0;		/*    see below ...	*/
unsigned int c_mmot_smallsendsize = 0;
unsigned int c_mmot_oddsendsize = 0;
unsigned int c_mmot_bigsendsize = 0;
unsigned int c_mmot_copyinmsg_fail = 0;
unsigned int c_mmot_g_slow_copyin3 = 0;
unsigned int c_mmot_cold_006 = 0;
unsigned int c_mmot_cold_007 = 0;
unsigned int c_mmot_cold_008 = 0;
unsigned int c_mmot_cold_009 = 0;
unsigned int c_mmot_cold_010 = 0;
unsigned int c_mmot_cold_012 = 0;
unsigned int c_mmot_cold_013 = 0;
unsigned int c_mmot_cold_014 = 0;
unsigned int c_mmot_cold_016 = 0;
unsigned int c_mmot_cold_018 = 0;
unsigned int c_mmot_cold_019 = 0;
unsigned int c_mmot_cold_020 = 0;
unsigned int c_mmot_cold_021 = 0;
unsigned int c_mmot_cold_022 = 0;
unsigned int c_mmot_cold_023 = 0;
unsigned int c_mmot_cold_024 = 0;
unsigned int c_mmot_cold_025 = 0;
unsigned int c_mmot_cold_026 = 0;
unsigned int c_mmot_cold_027 = 0;
unsigned int c_mmot_hot_fSR_ok = 0;
unsigned int c_mmot_cold_029 = 0;
unsigned int c_mmot_cold_030 = 0;
unsigned int c_mmot_cold_031 = 0;
unsigned int c_mmot_cold_032 = 0;
unsigned int c_mmot_cold_033 = 0;
unsigned int c_mmot_bad_rcvr = 0;
unsigned int c_mmot_rcvr_swapped = 0;
unsigned int c_mmot_rcvr_locked = 0;
unsigned int c_mmot_rcvr_tswapped = 0;
unsigned int c_mmot_rcvr_freed = 0;
unsigned int c_mmot_g_slow_copyout6 = 0;
unsigned int c_mmot_g_slow_copyout5 = 0;
unsigned int c_mmot_cold_037 = 0;
unsigned int c_mmot_cold_038 = 0;
unsigned int c_mmot_cold_039 = 0;
unsigned int c_mmot_g_slow_copyout4 = 0;
unsigned int c_mmot_g_slow_copyout3 = 0;
unsigned int c_mmot_hot_ok1 = 0;
unsigned int c_mmot_hot_ok2 = 0;
unsigned int c_mmot_hot_ok3 = 0;
unsigned int c_mmot_g_slow_copyout1 = 0;
unsigned int c_mmot_g_slow_copyout2 = 0;
unsigned int c_mmot_getback_fast_copyin = 0;
unsigned int c_mmot_cold_048 = 0;
unsigned int c_mmot_getback_FastSR = 0;
unsigned int c_mmot_cold_050 = 0;
unsigned int c_mmot_cold_051 = 0;
unsigned int c_mmot_cold_052 = 0;
unsigned int c_mmot_cold_053 = 0;
unsigned int c_mmot_fastkernelreply = 0;
unsigned int c_mmot_cold_055 = 0;
unsigned int c_mmot_getback_fast_put = 0;
unsigned int c_mmot_LAST = 0;			/* End Marker - Unused */

void db_mmot_zero_counters(void);		/* forward; */
void db_mmot_show_counters(void);		/* forward; */

void			/* Call from the debugger to clear all counters	*/
db_mmot_zero_counters(void)
{
	register unsigned int *ip = &c_mmot_FIRST;
	while (ip <= &c_mmot_LAST)
		*ip++ = 0;
}

void			/* Call from the debugger to show all counters */
db_mmot_show_counters(void)
{
#define	xx(str)	printf("%s: %d\n", # str, str);

	xx(c_mmot_combined_S_R);
	xx(c_mach_msg_trap_switch_fast);
	xx(c_mmot_kernel_send);
	xx(c_mmot_cold_000);
	xx(c_mmot_smallsendsize);
	xx(c_mmot_oddsendsize);
	xx(c_mmot_bigsendsize);
	xx(c_mmot_copyinmsg_fail);
	xx(c_mmot_g_slow_copyin3);
	xx(c_mmot_cold_006);
	xx(c_mmot_cold_007);
	xx(c_mmot_cold_008);
	xx(c_mmot_cold_009);
	xx(c_mmot_cold_010);
	xx(c_mmot_cold_012);
	xx(c_mmot_cold_013);
	xx(c_mmot_cold_014);
	xx(c_mmot_cold_016);
	xx(c_mmot_cold_018);
	xx(c_mmot_cold_019);
	xx(c_mmot_cold_020);
	xx(c_mmot_cold_021);
	xx(c_mmot_cold_022);
	xx(c_mmot_cold_023);
	xx(c_mmot_cold_024);
	xx(c_mmot_cold_025);
	xx(c_mmot_cold_026);
	xx(c_mmot_cold_027);
	xx(c_mmot_hot_fSR_ok);
	xx(c_mmot_cold_029);
	xx(c_mmot_cold_030);
	xx(c_mmot_cold_031);
	xx(c_mmot_cold_032);
	xx(c_mmot_cold_033);
	xx(c_mmot_bad_rcvr);
	xx(c_mmot_rcvr_swapped);
	xx(c_mmot_rcvr_locked);
	xx(c_mmot_rcvr_tswapped);
	xx(c_mmot_rcvr_freed);
	xx(c_mmot_g_slow_copyout6);
	xx(c_mmot_g_slow_copyout5);
	xx(c_mmot_cold_037);
	xx(c_mmot_cold_038);
	xx(c_mmot_cold_039);
	xx(c_mmot_g_slow_copyout4);
	xx(c_mmot_g_slow_copyout3);
	xx(c_mmot_g_slow_copyout1);
	xx(c_mmot_hot_ok3);
	xx(c_mmot_hot_ok2);
	xx(c_mmot_hot_ok1);
	xx(c_mmot_g_slow_copyout2);
	xx(c_mmot_getback_fast_copyin);
	xx(c_mmot_cold_048);
	xx(c_mmot_getback_FastSR);
	xx(c_mmot_cold_050);
	xx(c_mmot_cold_051);
	xx(c_mmot_cold_052);
	xx(c_mmot_cold_053);
	xx(c_mmot_fastkernelreply);
	xx(c_mmot_cold_055);
	xx(c_mmot_getback_fast_put);

#undef	xx
}

#else	/* !HOTPATH_DEBUG */

/*
 * Duplicate just these few so we can always do a quick sanity check
 */
unsigned int c_mmot_combined_S_R = 0;		/* hotpath candidates	*/
unsigned int c_mach_msg_trap_switch_fast = 0;	/* hotpath successes	*/
unsigned int c_mmot_kernel_send = 0;		/* kernel server calls	*/
#define HOT(expr)				/* no optional counters	*/

#endif	/* !HOTPATH_DEBUG */

boolean_t enable_hotpath = TRUE;	/* Patchable, just in case ...	*/
#endif	/* HOTPATH_ENABLE */

/*
 *	Routine:	mach_msg_overwrite_trap [mach trap]
 *	Purpose:
 *		Possibly send a message; possibly receive a message.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		All of mach_msg_send and mach_msg_receive error codes.
 */

mach_msg_return_t
mach_msg_overwrite_trap(
	struct mach_msg_overwrite_trap_args *args)
{
  	mach_vm_address_t	msg_addr = args->msg;
	mach_msg_option_t	option = args->option;
	mach_msg_size_t		send_size = args->send_size;
	mach_msg_size_t		rcv_size = args->rcv_size;
	mach_port_name_t	rcv_name = args->rcv_name;
	mach_msg_timeout_t	msg_timeout = args->timeout;
	mach_port_name_t	notify = args->notify;
	mach_vm_address_t	rcv_msg_addr = args->rcv_msg;
        mach_msg_size_t		scatter_list_size = 0; /* NOT INITIALIZED - but not used in pactice */

	register mach_msg_header_t *hdr;
	mach_msg_return_t  mr = MACH_MSG_SUCCESS;
	/* mask out some of the options before entering the hot path */
	mach_msg_option_t  masked_option = 
		option & ~(MACH_SEND_TRAILER|MACH_RCV_TRAILER_MASK|MACH_RCV_LARGE);

#if	ENABLE_HOTPATH
	/* BEGINNING OF HOT PATH */
	if ((masked_option == (MACH_SEND_MSG|MACH_RCV_MSG)) && enable_hotpath) {
		thread_t self = current_thread();
		mach_msg_format_0_trailer_t *trailer;
		ipc_space_t space = self->task->itk_space;
		ipc_kmsg_t kmsg;
		register ipc_port_t dest_port;
		ipc_object_t rcv_object;
		ipc_mqueue_t rcv_mqueue;
		mach_msg_size_t reply_size;

		c_mmot_combined_S_R++;

		/*
		 *	This case is divided into ten sections, each
		 *	with a label.  There are five optimized
		 *	sections and six unoptimized sections, which
		 *	do the same thing but handle all possible
		 *	cases and are slower.
		 *
		 *	The five sections for an RPC are
		 *	    1) Get request message into a buffer.
		 *	    2) Copyin request message and rcv_name.
		 *		(fast_copyin or slow_copyin)
		 *	    3) Enqueue request and dequeue reply.
		 *		(fast_send_receive or
		 *		 slow_send and slow_receive)
		 *	    4) Copyout reply message.
		 *		(fast_copyout or slow_copyout)
		 *	    5) Put reply message to user's buffer.
		 *
		 *	Keep the locking hierarchy firmly in mind.
		 *	(First spaces, then ports, then port sets,
		 *	then message queues.)  Only a non-blocking
		 *	attempt can be made to acquire locks out of
		 *	order, or acquire two locks on the same level.
		 *	Acquiring two locks on the same level will
		 *	fail if the objects are really the same,
		 *	unless simple locking is disabled.  This is OK,
		 *	because then the extra unlock does nothing.
		 *
		 *	There are two major reasons these RPCs can't use
		 *	ipc_thread_switch, and use slow_send/slow_receive:
		 *		1) Kernel RPCs.
		 *		2) Servers fall behind clients, so
		 *		client doesn't find a blocked server thread and
		 *		server finds waiting messages and can't block.
		 */

		mr = ipc_kmsg_get(msg_addr, send_size, &kmsg);
		if (mr != KERN_SUCCESS) {
			return mr;
		}
		hdr = kmsg->ikm_header;
		trailer = (mach_msg_format_0_trailer_t *) ((vm_offset_t) hdr +
							   send_size);

		/*
		 * fast_copyin:
		 *
		 *	optimized ipc_kmsg_copyin/ipc_mqueue_copyin
		 *
		 *	We have the request message data in kmsg.
		 *	Must still do copyin, send, receive, etc.
		 *
		 *	If the message isn't simple, we can't combine
		 *	ipc_kmsg_copyin_header and ipc_mqueue_copyin,
		 *	because copyin of the message body might
		 *	affect rcv_name.
		 */

		switch (hdr->msgh_bits) {
		    case MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,
					MACH_MSG_TYPE_MAKE_SEND_ONCE): {
			register ipc_entry_t table;
			register ipc_entry_num_t size;
			register ipc_port_t reply_port;

			/* sending a request message */

		    {
			register mach_port_index_t index;
			register mach_port_gen_t gen;

		    {
			register mach_port_name_t reply_name =
			        (mach_port_name_t)hdr->msgh_local_port;

			if (reply_name != rcv_name) {
				HOT(c_mmot_g_slow_copyin3++);
				goto slow_copyin;
			}

			/* optimized ipc_entry_lookup of reply_name */

			index = MACH_PORT_INDEX(reply_name);
			gen = MACH_PORT_GEN(reply_name);

			is_read_lock(space);
			assert(space->is_active);

			size = space->is_table_size;
			table = space->is_table;

		    {
			register ipc_entry_t entry;
			register ipc_entry_bits_t bits;

			if (index < size) {
				entry = &table[index];
				bits = entry->ie_bits;
				if (IE_BITS_GEN(bits) != gen ||
				    (bits & IE_BITS_COLLISION)) {
					entry = IE_NULL;
				}
			} else {
				entry = IE_NULL;
				bits = 0;
			}
			if (entry == IE_NULL) {
				entry = ipc_entry_lookup(space, reply_name);
				if (entry == IE_NULL) {
					HOT(c_mmot_cold_006++);
					goto abort_request_copyin;
				}
				bits = entry->ie_bits;
			}

			/* check type bit */

			if (! (bits & MACH_PORT_TYPE_RECEIVE)) {
				HOT(c_mmot_cold_007++);
				goto abort_request_copyin;
			}

			reply_port = (ipc_port_t) entry->ie_object;
			assert(reply_port != IP_NULL);
		    }
		    }
		    }

			/* optimized ipc_entry_lookup of dest_name */

		    {
			register mach_port_index_t index;
			register mach_port_gen_t gen;

		    {
			register mach_port_name_t dest_name =
				(mach_port_name_t)hdr->msgh_remote_port;

			index = MACH_PORT_INDEX(dest_name);
			gen = MACH_PORT_GEN(dest_name);

		    {
			register ipc_entry_t entry;
			register ipc_entry_bits_t bits;

			if (index < size) {
				entry = &table[index];
				bits = entry->ie_bits;
				if (IE_BITS_GEN(bits) != gen ||
				    (bits & IE_BITS_COLLISION)) {
					entry = IE_NULL;
				}
			} else {
				entry = IE_NULL;
				bits = 0;
			}
			if (entry == IE_NULL) {
				entry = ipc_entry_lookup(space, dest_name);
				if (entry == IE_NULL) {
					HOT(c_mmot_cold_008++);
					goto abort_request_copyin;
				}
				bits = entry->ie_bits;
			}

			/* check type bit */

			if (! (bits & MACH_PORT_TYPE_SEND)) {
				HOT(c_mmot_cold_009++);
				goto abort_request_copyin;
			}

			assert(IE_BITS_UREFS(bits) > 0);

			dest_port = (ipc_port_t) entry->ie_object;
			assert(dest_port != IP_NULL);
		    }
		    }
		    }

			/*
			 *	To do an atomic copyin, need simultaneous
			 *	locks on both ports and the space.  If
			 *	dest_port == reply_port, and simple locking is
			 *	enabled, then we will abort.  Otherwise it's
			 *	OK to unlock twice.
			 */

			ip_lock(dest_port);
			if (!ip_active(dest_port) ||
			    !ip_lock_try(reply_port)) {
				ip_unlock(dest_port);
				HOT(c_mmot_cold_010++);
				goto abort_request_copyin;
			}
			is_read_unlock(space);

			assert(dest_port->ip_srights > 0);
			dest_port->ip_srights++;
			ip_reference(dest_port);

			assert(ip_active(reply_port));
			assert(reply_port->ip_receiver_name ==
			       (mach_port_name_t)hdr->msgh_local_port);
			assert(reply_port->ip_receiver == space);

			reply_port->ip_sorights++;
			ip_reference(reply_port);

			hdr->msgh_bits =
				MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND,
					       MACH_MSG_TYPE_PORT_SEND_ONCE);
			hdr->msgh_remote_port = dest_port;
			hdr->msgh_local_port = reply_port;

			/* make sure we can queue to the destination */

			if (dest_port->ip_receiver == ipc_space_kernel) {
				/*
				 * The kernel server has a reference to
				 * the reply port, which it hands back
				 * to us in the reply message.  We do
				 * not need to keep another reference to
				 * it.
				 */
				ip_unlock(reply_port);

				assert(ip_active(dest_port));
				dest_port->ip_messages.imq_seqno++;
				ip_unlock(dest_port);
				goto kernel_send;
			}

			if (imq_full(&dest_port->ip_messages)) {
				HOT(c_mmot_cold_013++);
				goto abort_request_send_receive;
			}

			/* optimized ipc_mqueue_copyin */

			rcv_object = (ipc_object_t) reply_port;
			io_reference(rcv_object);
			rcv_mqueue = &reply_port->ip_messages;
			io_unlock(rcv_object);
			HOT(c_mmot_hot_fSR_ok++);
			goto fast_send_receive;

		    abort_request_copyin:
			is_read_unlock(space);
			goto slow_copyin;

		    abort_request_send_receive:
			ip_unlock(dest_port);
			ip_unlock(reply_port);
			goto slow_send;
		    }

		    case MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0): {
			register ipc_entry_num_t size;
			register ipc_entry_t table;

			/* sending a reply message */

		    {
			register mach_port_name_t reply_name =
				(mach_port_name_t)hdr->msgh_local_port;

			if (reply_name != MACH_PORT_NULL) {
				HOT(c_mmot_cold_018++);
				goto slow_copyin;
			}
		    }

			is_write_lock(space);
			assert(space->is_active);

			/* optimized ipc_entry_lookup */

			size = space->is_table_size;
			table = space->is_table;

		    {
			register ipc_entry_t entry;
			register mach_port_gen_t gen;
			register mach_port_index_t index;

		    {
			register mach_port_name_t dest_name =
				(mach_port_name_t)hdr->msgh_remote_port;

			index = MACH_PORT_INDEX(dest_name);
			gen = MACH_PORT_GEN(dest_name);
		    }

			if (index >= size) {
				HOT(c_mmot_cold_019++);
				goto abort_reply_dest_copyin;
			}

			entry = &table[index];

			/* check generation, collision bit, and type bit */

			if ((entry->ie_bits & (IE_BITS_GEN_MASK|
					       IE_BITS_COLLISION|
					       MACH_PORT_TYPE_SEND_ONCE)) !=
			    (gen | MACH_PORT_TYPE_SEND_ONCE)) {
				HOT(c_mmot_cold_020++);
				goto abort_reply_dest_copyin;
			}

			/* optimized ipc_right_copyin */

			assert(IE_BITS_TYPE(entry->ie_bits) ==
					    MACH_PORT_TYPE_SEND_ONCE);
			assert(IE_BITS_UREFS(entry->ie_bits) == 1);
			
			if (entry->ie_request != 0) {
				HOT(c_mmot_cold_021++);
				goto abort_reply_dest_copyin;
			}

			dest_port = (ipc_port_t) entry->ie_object;
			assert(dest_port != IP_NULL);

			ip_lock(dest_port);
			if (!ip_active(dest_port)) {
				ip_unlock(dest_port);
				HOT(c_mmot_cold_022++);
				goto abort_reply_dest_copyin;
			}

			assert(dest_port->ip_sorights > 0);

			/* optimized ipc_entry_dealloc */

                
			entry->ie_bits = gen;
			entry->ie_next = table->ie_next;
			table->ie_next = index;
			entry->ie_object = IO_NULL;
		    }

			hdr->msgh_bits =
				MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND_ONCE,
					       0);
			hdr->msgh_remote_port = dest_port;

			/* make sure we can queue to the destination */

			assert(dest_port->ip_receiver != ipc_space_kernel);

			/* optimized ipc_entry_lookup/ipc_mqueue_copyin */

		    {
			register ipc_entry_t entry;
			register ipc_entry_bits_t bits;

		    {
			register mach_port_index_t index;
			register mach_port_gen_t gen;

			index = MACH_PORT_INDEX(rcv_name);
			gen = MACH_PORT_GEN(rcv_name);

			if (index < size) {
				entry = &table[index];
				bits = entry->ie_bits;
				if (IE_BITS_GEN(bits) != gen ||
				    (bits & IE_BITS_COLLISION)) {
					entry = IE_NULL;
				}
			} else {
				entry = IE_NULL;
				bits = 0;
			}
			if (entry == IE_NULL) {
				entry = ipc_entry_lookup(space, rcv_name);
				if (entry == IE_NULL) {
					HOT(c_mmot_cold_024++);
					goto abort_reply_rcv_copyin;
				}
				bits = entry->ie_bits;
			}

		    }

			/* check type bits; looking for receive or set */
#if 0
		    /*
		     * JMM - The check below for messages in the receive
		     * mqueue is insufficient to work with port sets, since
		     * the messages stay in the port queues.  For now, don't
		     * allow portsets (but receiving on portsets when sending
		     * a message to a send-once right is actually a very
		     * common case (so we should re-enable).
		     */
			if (bits & MACH_PORT_TYPE_PORT_SET) {
				register ipc_pset_t rcv_pset;

				rcv_pset = (ipc_pset_t) entry->ie_object;
				assert(rcv_pset != IPS_NULL);

				ips_lock(rcv_pset);
				assert(ips_active(rcv_pset));

				rcv_object = (ipc_object_t) rcv_pset;
				rcv_mqueue = &rcv_pset->ips_messages;
			} else 
#endif /* 0 */
			  if (bits & MACH_PORT_TYPE_RECEIVE) {
				register ipc_port_t rcv_port;

				rcv_port = (ipc_port_t) entry->ie_object;
				assert(rcv_port != IP_NULL);

				if (!ip_lock_try(rcv_port)) {
					HOT(c_mmot_cold_025++);
					goto abort_reply_rcv_copyin;
				}
				assert(ip_active(rcv_port));

				if (rcv_port->ip_pset_count != 0) {
					ip_unlock(rcv_port);
					HOT(c_mmot_cold_026++);
					goto abort_reply_rcv_copyin;
				}

				rcv_object = (ipc_object_t) rcv_port;
				rcv_mqueue = &rcv_port->ip_messages;
			} else {
				HOT(c_mmot_cold_027++);
				goto abort_reply_rcv_copyin;
			}
		    }

			is_write_unlock(space);
			io_reference(rcv_object);
			io_unlock(rcv_object);
			HOT(c_mmot_hot_fSR_ok++);
			goto fast_send_receive;

		    abort_reply_dest_copyin:
			is_write_unlock(space);
			HOT(c_mmot_cold_029++);
			goto slow_copyin;

		    abort_reply_rcv_copyin:
			ip_unlock(dest_port);
			is_write_unlock(space);
			HOT(c_mmot_cold_030++);
			goto slow_send;
		    }

		    default:
			HOT(c_mmot_cold_031++);
			goto slow_copyin;
		}
		/*NOTREACHED*/

	    fast_send_receive:
		/*
		 *	optimized ipc_mqueue_send/ipc_mqueue_receive
		 *
		 *	Finished get/copyin of kmsg and copyin of rcv_name.
		 *	space is unlocked, dest_port is locked,
		 *	we can queue kmsg to dest_port,
		 *	rcv_mqueue is set, and rcv_object holds a ref
		 *  so the mqueue cannot go away.
		 *
		 * JMM - For now, rcv_object is just a port.  Portsets
		 * are disabled for the time being.
		 */

		assert(ip_active(dest_port));
		assert(dest_port->ip_receiver != ipc_space_kernel);
//		assert(!imq_full(&dest_port->ip_messages) ||
//		       (MACH_MSGH_BITS_REMOTE(hdr->msgh_bits) ==
//						MACH_MSG_TYPE_PORT_SEND_ONCE));
		assert((hdr->msgh_bits & MACH_MSGH_BITS_CIRCULAR) == 0);

	    {
		  register ipc_mqueue_t dest_mqueue;
		  wait_queue_t waitq;
		  thread_t receiver;
		  processor_t processor;
		  boolean_t still_running;
		  spl_t s;

		  s = splsched();
		  processor = current_processor();
		  if (processor->current_pri >= BASEPRI_RTQUEUES)
			  goto abort_send_receive1;

		  dest_mqueue = &dest_port->ip_messages;
		  waitq = &dest_mqueue->imq_wait_queue;
		  imq_lock(dest_mqueue);

		  wait_queue_peek64_locked(waitq, IPC_MQUEUE_RECEIVE, &receiver, &waitq);
		  /* queue still locked, thread locked - but still on q */

		  if (	receiver == THREAD_NULL ) {
		  abort_send_receive:
			imq_unlock(dest_mqueue);
		  abort_send_receive1:
			splx(s);
			ip_unlock(dest_port);
			ipc_object_release(rcv_object);
			HOT(c_mmot_cold_032++);
			goto slow_send;
		  }

		  assert(receiver->state & TH_WAIT);
		  assert(receiver->wait_queue == waitq);
		  assert(receiver->wait_event == IPC_MQUEUE_RECEIVE);
		
		  /*
		   * Make sure that the scheduling restrictions of the receiver
		   * are consistent with a handoff here (if it comes down to that).
		   */
		  if (	receiver->sched_pri >= BASEPRI_RTQUEUES ||
			  	receiver->processor_set != processor->processor_set ||
				(receiver->bound_processor != PROCESSOR_NULL &&
				 receiver->bound_processor != processor)) {
			HOT(c_mmot_cold_033++);
		fall_off:
			thread_unlock(receiver);
			if (waitq != &dest_mqueue->imq_wait_queue)
				wait_queue_unlock(waitq);
			goto abort_send_receive;
		  }

		  /*
		   * Check that the receiver can stay on the hot path.
		   */
		  if (ipc_kmsg_copyout_size(kmsg, receiver->map) + 
			  REQUESTED_TRAILER_SIZE(receiver->ith_option) > receiver->ith_msize) {
			/*
			 *	The receiver can't accept the message.
			 */
			HOT(c_mmot_bad_rcvr++);
			goto fall_off;
		  }

		  /*
		   * Before committing to the handoff, make sure that we are
		   * really going to block (i.e. there are no messages already
		   * queued for us.  This violates lock ordering, so make sure
		   * we don't deadlock. After the trylock succeeds below, we
		   * may have up to 3 message queues locked:
		   *	- the dest port mqueue
		   * 	- a portset mqueue (where waiting receiver was found)
		   *    - finally our own rcv_mqueue
		   *
		   * JMM - Need to make this check appropriate for portsets as
		   * well before re-enabling them.
		   */
		  if (!imq_lock_try(rcv_mqueue)) {
			goto fall_off;
		  }
		  if (ipc_kmsg_queue_first(&rcv_mqueue->imq_messages) != IKM_NULL) {
			imq_unlock(rcv_mqueue);
			HOT(c_mmot_cold_033++);
			goto fall_off;
		  }

		  /* At this point we are committed to do the "handoff". */
		  c_mach_msg_trap_switch_fast++;
		  
		  /*
		   * Go ahead and pull the receiver from the waitq.  If the
		   * waitq wasn't the one for the mqueue, unlock it.
		   */
		  wait_queue_pull_thread_locked(waitq,
								receiver,
								(waitq != &dest_mqueue->imq_wait_queue));

		  /*
		   *	Store the kmsg and seqno where the receiver can pick it up.
		   */
		  receiver->ith_state = MACH_MSG_SUCCESS;
		  receiver->ith_kmsg = kmsg;
		  receiver->ith_seqno = dest_mqueue->imq_seqno++;

		  /*
		   * Unblock the receiver.  If it was still running on another
		   * CPU, we'll give it a chance to run with the message where
		   * it is (and just select someother thread to run here).
		   * Otherwise, we'll invoke it here as part of the handoff.
		   */
		  still_running = thread_unblock(receiver, THREAD_AWAKENED);

		  thread_unlock(receiver);

		  imq_unlock(dest_mqueue);
		  ip_unlock(dest_port);
		  current_task()->messages_sent++;


		  /*
		   *	Put self on receive port's queue.
		   *	Also save state that the sender of
		   *	our reply message needs to determine if it
		   *	can hand off directly back to us.
		   */
		  thread_lock(self);
		  self->ith_msg_addr = (rcv_msg_addr) ? rcv_msg_addr : msg_addr;
		  self->ith_object = rcv_object; /* still holds reference */
		  self->ith_msize = rcv_size;
		  self->ith_option = option;
		  self->ith_scatter_list_size = scatter_list_size;
		  self->ith_continuation = thread_syscall_return;

		  waitq = &rcv_mqueue->imq_wait_queue;
		  (void)wait_queue_assert_wait64_locked(waitq,
										IPC_MQUEUE_RECEIVE,
										THREAD_ABORTSAFE, 0,
										self);
		  thread_unlock(self);
		  imq_unlock(rcv_mqueue);

		  /*
		   * If the receiving thread wasn't still running, we switch directly
		   * to it here.  Otherwise we let the scheduler pick something for
		   * here.  In either case, block this thread as though it had called
		   * ipc_mqueue_receive.
		   */
		  if (still_running) {
			  splx(s);
			  thread_block(ipc_mqueue_receive_continue);
		  } else {
			  thread_run(self, ipc_mqueue_receive_continue, NULL, receiver);
		  }
		  /* NOTREACHED */
		}

	    fast_copyout:
		/*
		 *	Nothing locked and no references held, except
		 *	we have kmsg with msgh_seqno filled in.  Must
		 *	still check against rcv_size and do
		 *	ipc_kmsg_copyout/ipc_kmsg_put.
		 */

		reply_size = send_size + trailer->msgh_trailer_size;
		if (rcv_size < reply_size) {
			HOT(c_mmot_g_slow_copyout6++);
			goto slow_copyout;
		}

		/* optimized ipc_kmsg_copyout/ipc_kmsg_copyout_header */

		switch (hdr->msgh_bits) {
		    case MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND,
					MACH_MSG_TYPE_PORT_SEND_ONCE): {
			ipc_port_t reply_port =
				(ipc_port_t) hdr->msgh_local_port;
			mach_port_name_t dest_name, reply_name;

			/* receiving a request message */

			if (!IP_VALID(reply_port)) {
				HOT(c_mmot_g_slow_copyout5++);
				goto slow_copyout;
			}

			is_write_lock(space);
			assert(space->is_active);

			/*
			 *	To do an atomic copyout, need simultaneous
			 *	locks on both ports and the space.  If
			 *	dest_port == reply_port, and simple locking is
			 *	enabled, then we will abort.  Otherwise it's
			 *	OK to unlock twice.
			 */

			ip_lock(dest_port);
			if (!ip_active(dest_port) ||
			    !ip_lock_try(reply_port)) {
				HOT(c_mmot_cold_037++);
				goto abort_request_copyout;
			}

			if (!ip_active(reply_port)) {
				ip_unlock(reply_port);
				HOT(c_mmot_cold_038++);
				goto abort_request_copyout;
			}

			assert(reply_port->ip_sorights > 0);
			ip_unlock(reply_port);

		    {
			register ipc_entry_t table;
			register ipc_entry_t entry;
			register mach_port_index_t index;

			/* optimized ipc_entry_get */

			table = space->is_table;
			index = table->ie_next;

			if (index == 0) {
				HOT(c_mmot_cold_039++);
				goto abort_request_copyout;
			}

			entry = &table[index];
			table->ie_next = entry->ie_next;
			entry->ie_request = 0;

		    {
			register mach_port_gen_t gen;

			assert((entry->ie_bits &~ IE_BITS_GEN_MASK) == 0);
			gen = IE_BITS_NEW_GEN(entry->ie_bits);

			reply_name = MACH_PORT_MAKE(index, gen);

			/* optimized ipc_right_copyout */

			entry->ie_bits = gen | (MACH_PORT_TYPE_SEND_ONCE | 1);
		    }

			assert(MACH_PORT_VALID(reply_name));
			entry->ie_object = (ipc_object_t) reply_port;
			is_write_unlock(space);
		    }

			/* optimized ipc_object_copyout_dest */

			assert(dest_port->ip_srights > 0);
			ip_release(dest_port);

			if (dest_port->ip_receiver == space)
				dest_name = dest_port->ip_receiver_name;
			else
				dest_name = MACH_PORT_NULL;

			if ((--dest_port->ip_srights == 0) &&
			    (dest_port->ip_nsrequest != IP_NULL)) {
				ipc_port_t nsrequest;
				mach_port_mscount_t mscount;

				/* a rather rare case */

				nsrequest = dest_port->ip_nsrequest;
				mscount = dest_port->ip_mscount;
				dest_port->ip_nsrequest = IP_NULL;
				ip_unlock(dest_port);
				ipc_notify_no_senders(nsrequest, mscount);
			} else
				ip_unlock(dest_port);

			hdr->msgh_bits =
				MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND_ONCE,
					       MACH_MSG_TYPE_PORT_SEND);
			hdr->msgh_remote_port = (mach_port_t)reply_name;
			hdr->msgh_local_port = (mach_port_t)dest_name;
			HOT(c_mmot_hot_ok1++);
			goto fast_put;

		    abort_request_copyout:
			ip_unlock(dest_port);
			is_write_unlock(space);
			HOT(c_mmot_g_slow_copyout4++);
			goto slow_copyout;
		    }

		    case MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND_ONCE, 0): {
			register mach_port_name_t dest_name;

			/* receiving a reply message */

			ip_lock(dest_port);
			if (!ip_active(dest_port)) {
				ip_unlock(dest_port);
				HOT(c_mmot_g_slow_copyout3++);
				goto slow_copyout;
			}

			/* optimized ipc_object_copyout_dest */

			assert(dest_port->ip_sorights > 0);

			if (dest_port->ip_receiver == space) {
				ip_release(dest_port);
				dest_port->ip_sorights--;
				dest_name = dest_port->ip_receiver_name;
				ip_unlock(dest_port);
			} else {
				ip_unlock(dest_port);

				ipc_notify_send_once(dest_port);
				dest_name = MACH_PORT_NULL;
			}

			hdr->msgh_bits = MACH_MSGH_BITS(0,
					       MACH_MSG_TYPE_PORT_SEND_ONCE);
			hdr->msgh_remote_port = MACH_PORT_NULL;
			hdr->msgh_local_port = (ipc_port_t)dest_name;
			HOT(c_mmot_hot_ok2++);
			goto fast_put;
		    }

		    case MACH_MSGH_BITS_COMPLEX|
			 MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND_ONCE, 0): {
			register mach_port_name_t dest_name;

			/* receiving a complex reply message */

			ip_lock(dest_port);
			if (!ip_active(dest_port)) {
				ip_unlock(dest_port);
				HOT(c_mmot_g_slow_copyout1++);
				goto slow_copyout;
			}

			/* optimized ipc_object_copyout_dest */

			assert(dest_port->ip_sorights > 0);

			if (dest_port->ip_receiver == space) {
				ip_release(dest_port);
				dest_port->ip_sorights--;
				dest_name = dest_port->ip_receiver_name;
				ip_unlock(dest_port);
			} else {
				ip_unlock(dest_port);

				ipc_notify_send_once(dest_port);
				dest_name = MACH_PORT_NULL;
			}

			hdr->msgh_bits =
				MACH_MSGH_BITS_COMPLEX |
				MACH_MSGH_BITS(0, MACH_MSG_TYPE_PORT_SEND_ONCE);
			hdr->msgh_remote_port = MACH_PORT_NULL;
			hdr->msgh_local_port = (mach_port_t)dest_name;

			mr = ipc_kmsg_copyout_body(kmsg, space,
						   current_map(), 
						   MACH_MSG_BODY_NULL);
			/* hdr and send_size may be invalid now - done use */
			if (mr != MACH_MSG_SUCCESS) {
				if (ipc_kmsg_put(msg_addr, kmsg, 
					       kmsg->ikm_header->msgh_size +
					       trailer->msgh_trailer_size) == 
							MACH_RCV_INVALID_DATA)
					return MACH_RCV_INVALID_DATA;
				else
					return mr | MACH_RCV_BODY_ERROR;
			}
			HOT(c_mmot_hot_ok3++);
			goto fast_put;
		    }

		    default:
			HOT(c_mmot_g_slow_copyout2++);
			goto slow_copyout;
		}
		/*NOTREACHED*/

	    fast_put:
		mr = ipc_kmsg_put(rcv_msg_addr ? rcv_msg_addr : msg_addr,
				  kmsg,
				  kmsg->ikm_header->msgh_size + 
				  trailer->msgh_trailer_size);
		if (mr != MACH_MSG_SUCCESS) {
			return MACH_RCV_INVALID_DATA;
		}
		current_task()->messages_received++;
		return mr;


		/* BEGINNING OF WARM PATH */

		/*
		 *	The slow path has a few non-register temporary
		 *	variables used only for call-by-reference.
		 */

	    slow_copyin:
	    {
		mach_port_seqno_t temp_seqno = 0;
		register mach_port_name_t reply_name =
			        (mach_port_name_t)hdr->msgh_local_port;


		/*
		 *	We have the message data in kmsg, but
		 *	we still need to copyin, send it,
		 *	receive a reply, and do copyout.
		 */

		mr = ipc_kmsg_copyin(kmsg, space, current_map(),
				     MACH_PORT_NULL);
		if (mr != MACH_MSG_SUCCESS) {
			ipc_kmsg_free(kmsg);
			return(mr);
		}

		/* 
		 *	LP64support - We have to recompute the header pointer
		 *	and send_size - as they could have changed during the
		 *	complex copyin.
		 */
		hdr = kmsg->ikm_header;
		send_size = hdr->msgh_size;

		/* try to get back on optimized path */
		if ((reply_name != rcv_name) ||
			(hdr->msgh_bits & MACH_MSGH_BITS_CIRCULAR)) {
			HOT(c_mmot_cold_048++);
			goto slow_send;
		}

		dest_port = (ipc_port_t) hdr->msgh_remote_port;
		assert(IP_VALID(dest_port));

		ip_lock(dest_port);
		if (!ip_active(dest_port)) {
		    ip_unlock(dest_port);
		    goto slow_send;
		}
		
		if (dest_port->ip_receiver == ipc_space_kernel) {
			dest_port->ip_messages.imq_seqno++;
			ip_unlock(dest_port);
			goto kernel_send;
		}

		if (!imq_full(&dest_port->ip_messages) ||
		     (MACH_MSGH_BITS_REMOTE(hdr->msgh_bits) ==
					MACH_MSG_TYPE_PORT_SEND_ONCE))
		{
		    /*
		     *	Try an optimized ipc_mqueue_copyin.
		     *	It will work if this is a request message.
		     */

		    register ipc_port_t reply_port;

		    reply_port = (ipc_port_t) hdr->msgh_local_port;
		    if (IP_VALID(reply_port)) {
			if (ip_lock_try(reply_port)) {
			    if (ip_active(reply_port) &&
				reply_port->ip_receiver == space &&
				reply_port->ip_receiver_name == rcv_name &&
				reply_port->ip_pset_count == 0)
			    {
				/* Grab a reference to the reply port. */
				rcv_object = (ipc_object_t) reply_port;
				io_reference(rcv_object);
				rcv_mqueue = &reply_port->ip_messages;
				io_unlock(rcv_object);
				HOT(c_mmot_getback_FastSR++);
				goto fast_send_receive;
			    }
			    ip_unlock(reply_port);
			}
		    }
		}

		ip_unlock(dest_port);
		HOT(c_mmot_cold_050++);
		goto slow_send;

	    kernel_send:
		/*
		 *	Special case: send message to kernel services.
		 *	The request message has been copied into the
		 *	kmsg.  Nothing is locked.
		 */

	    {
		register ipc_port_t	reply_port;
		mach_port_seqno_t	local_seqno;
		spl_t s;

		/*
		 * Perform the kernel function.
		 */
		c_mmot_kernel_send++;

		current_task()->messages_sent++;

		kmsg = ipc_kobject_server(kmsg);
		if (kmsg == IKM_NULL) {
			/*
			 * No reply.  Take the
			 * slow receive path.
			 */
			HOT(c_mmot_cold_051++);
			goto slow_get_rcv_port;
		}

		/*
		 * Check that:
		 *	the reply port is alive
		 *	we hold the receive right
		 *	the name has not changed.
		 *	the port is not in a set
		 * If any of these are not true,
		 * we cannot directly receive the reply
		 * message.
		 */
		hdr = kmsg->ikm_header;
		send_size = hdr->msgh_size;
		trailer = (mach_msg_format_0_trailer_t *) ((vm_offset_t) hdr +
			round_msg(send_size));
		reply_port = (ipc_port_t) hdr->msgh_remote_port;
		ip_lock(reply_port);

		if ((!ip_active(reply_port)) ||
		    (reply_port->ip_receiver != space) ||
		    (reply_port->ip_receiver_name != rcv_name) ||
		    (reply_port->ip_pset_count != 0))
		{
			ip_unlock(reply_port);
			ipc_kmsg_send_always(kmsg);
			HOT(c_mmot_cold_052++);
			goto slow_get_rcv_port;
		}

		s = splsched();
		rcv_mqueue = &reply_port->ip_messages;
		imq_lock(rcv_mqueue);

		/* keep port locked, and don`t change ref count yet */

		/*
		 * If there are messages on the port
		 * or other threads waiting for a message,
		 * we cannot directly receive the reply.
		 */
		if (!wait_queue_empty(&rcv_mqueue->imq_wait_queue) ||
		    (ipc_kmsg_queue_first(&rcv_mqueue->imq_messages) != IKM_NULL))
		{
			imq_unlock(rcv_mqueue);
			splx(s);
			ip_unlock(reply_port);
			ipc_kmsg_send_always(kmsg);
			HOT(c_mmot_cold_053++);
			goto slow_get_rcv_port;
		}

		/*
		 * We can directly receive this reply.
		 * Since there were no messages queued
		 * on the reply port, there should be
		 * no threads blocked waiting to send.
		 */
		dest_port = reply_port;
		local_seqno = rcv_mqueue->imq_seqno++;
		imq_unlock(rcv_mqueue);
		splx(s);

		/*
		 * inline ipc_object_release.
		 * Port is still locked.
		 * Reference count was not incremented.
		 */
		ip_check_unlock(reply_port);

		if (option & MACH_RCV_TRAILER_MASK) {
			trailer->msgh_seqno = local_seqno;	
			trailer->msgh_trailer_size = REQUESTED_TRAILER_SIZE(option);
		}
		/* copy out the kernel reply */
		HOT(c_mmot_fastkernelreply++);
		goto fast_copyout;
	    }

	    slow_send:
		/*
		 *	Nothing is locked.  We have acquired kmsg, but
		 *	we still need to send it and receive a reply.
		 */

		mr = ipc_kmsg_send(kmsg, MACH_MSG_OPTION_NONE,
				     MACH_MSG_TIMEOUT_NONE);
		if (mr != MACH_MSG_SUCCESS) {
			mr |= ipc_kmsg_copyout_pseudo(kmsg, space,
						      current_map(),
						      MACH_MSG_BODY_NULL);

			(void) ipc_kmsg_put(msg_addr, kmsg, 
					    kmsg->ikm_header->msgh_size);
			return(mr);
		}

	    slow_get_rcv_port:
		/*
		 * We have sent the message.  Copy in the receive port.
		 */
		mr = ipc_mqueue_copyin(space, rcv_name,
				       &rcv_mqueue, &rcv_object);
		if (mr != MACH_MSG_SUCCESS) {
			return(mr);
		}
		/* hold ref for rcv_object */

		/*
		 * slow_receive:
		 *
		 *	Now we have sent the request and copied in rcv_name,
		 *	and hold ref for rcv_object (to keep mqueue alive).
		 *  Just receive a reply and try to get back to fast path.
		 */

		self->ith_continuation = (void (*)(mach_msg_return_t))0;
		ipc_mqueue_receive(rcv_mqueue,
				   MACH_MSG_OPTION_NONE,
				   MACH_MSG_SIZE_MAX,
				   MACH_MSG_TIMEOUT_NONE,
				   THREAD_ABORTSAFE);

		mr = self->ith_state;
		temp_seqno = self->ith_seqno;

		ipc_object_release(rcv_object);

		  if (mr != MACH_MSG_SUCCESS) {
		    return(mr);
		  }

		  kmsg = self->ith_kmsg;
		  hdr = kmsg->ikm_header;
		  send_size = hdr->msgh_size;
		  trailer = (mach_msg_format_0_trailer_t *) ((vm_offset_t) hdr +
							     round_msg(send_size));
		  if (option & MACH_RCV_TRAILER_MASK) {
		    trailer->msgh_seqno = temp_seqno;	
		    trailer->msgh_trailer_size = REQUESTED_TRAILER_SIZE(option);
		  }
		  dest_port = (ipc_port_t) hdr->msgh_remote_port;
		  HOT(c_mmot_cold_055++);
		  goto fast_copyout;

	    slow_copyout:
		/*
		 *	Nothing locked and no references held, except
		 *	we have kmsg with msgh_seqno filled in.  Must
		 *	still check against rcv_size and do
		 *	ipc_kmsg_copyout/ipc_kmsg_put.
		 */

		/* LP64support - have to compute real size as it would be received */
		reply_size = ipc_kmsg_copyout_size(kmsg, current_map()) +
		             REQUESTED_TRAILER_SIZE(option);
		if (rcv_size < reply_size) {
			if (msg_receive_error(kmsg, msg_addr, option, temp_seqno,
				        space) == MACH_RCV_INVALID_DATA) {
				mr = MACH_RCV_INVALID_DATA;
				return(mr);
			}
			else {
				mr = MACH_RCV_TOO_LARGE;
				return(mr);
			}
		}

		mr = ipc_kmsg_copyout(kmsg, space, current_map(),
				      MACH_PORT_NULL, MACH_MSG_BODY_NULL);
		if (mr != MACH_MSG_SUCCESS) {
			if ((mr &~ MACH_MSG_MASK) == MACH_RCV_BODY_ERROR) {
				if (ipc_kmsg_put(msg_addr, kmsg, reply_size) == 
							MACH_RCV_INVALID_DATA)
				    	mr = MACH_RCV_INVALID_DATA;
			} 
			else {
				if (msg_receive_error(kmsg, msg_addr, option,
				    temp_seqno, space) == MACH_RCV_INVALID_DATA)
					mr = MACH_RCV_INVALID_DATA;
			}

			return(mr);
		}

		/* try to get back on optimized path */
		HOT(c_mmot_getback_fast_put++);
		goto fast_put;

		/*NOTREACHED*/
	    }
	} /* END OF HOT PATH */
#endif	/* ENABLE_HOTPATH */

	if (option & MACH_SEND_MSG) {
		ipc_space_t space = current_space();
		vm_map_t map = current_map();
		ipc_kmsg_t kmsg;

		mr = ipc_kmsg_get(msg_addr, send_size, &kmsg);

		if (mr != MACH_MSG_SUCCESS)
			return mr;

		if (option & MACH_SEND_CANCEL) {
			if (notify == MACH_PORT_NULL)
				mr = MACH_SEND_INVALID_NOTIFY;
			else
				mr = ipc_kmsg_copyin(kmsg, space, map, notify);
		} else
			mr = ipc_kmsg_copyin(kmsg, space, map, MACH_PORT_NULL);
		if (mr != MACH_MSG_SUCCESS) {
			ipc_kmsg_free(kmsg);
			return mr;
		}

		mr = ipc_kmsg_send(kmsg, option & MACH_SEND_TIMEOUT, msg_timeout);

		if (mr != MACH_MSG_SUCCESS) {
			mr |= ipc_kmsg_copyout_pseudo(kmsg, space, map, MACH_MSG_BODY_NULL);
			(void) ipc_kmsg_put(msg_addr, kmsg, kmsg->ikm_header->msgh_size);
			return mr;
		}

	}

	if (option & MACH_RCV_MSG) {
		thread_t self = current_thread();
		ipc_space_t space = current_space();
		ipc_object_t object;
		ipc_mqueue_t mqueue;

		mr = ipc_mqueue_copyin(space, rcv_name, &mqueue, &object);
		if (mr != MACH_MSG_SUCCESS) {
			return mr;
		}
		/* hold ref for object */

		/*
		 * 1. MACH_RCV_OVERWRITE is on, and rcv_msg is our scatter list
		 *    and receive buffer
		 * 2. MACH_RCV_OVERWRITE is off, and rcv_msg might be the
		 *    alternate receive buffer (separate send and receive buffers).
		 */
		if (option & MACH_RCV_OVERWRITE) 
			self->ith_msg_addr = rcv_msg_addr;
		else if (rcv_msg_addr != (mach_vm_address_t)0)
			self->ith_msg_addr = rcv_msg_addr;
		else
			self->ith_msg_addr = msg_addr;
		self->ith_object = object;
		self->ith_msize = rcv_size;
		self->ith_option = option;
		self->ith_scatter_list_size = scatter_list_size;
		self->ith_continuation = thread_syscall_return;

		ipc_mqueue_receive(mqueue, option, rcv_size, msg_timeout, THREAD_ABORTSAFE);
		if ((option & MACH_RCV_TIMEOUT) && msg_timeout == 0)
			thread_poll_yield(self);
		return mach_msg_receive_results();
	}

	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	mach_msg_trap [mach trap]
 *	Purpose:
 *		Possibly send a message; possibly receive a message.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		All of mach_msg_send and mach_msg_receive error codes.
 */

mach_msg_return_t
mach_msg_trap(
	struct mach_msg_overwrite_trap_args *args)
{
	kern_return_t kr;
	args->rcv_msg = (mach_vm_address_t)0;

 	kr = mach_msg_overwrite_trap(args);
	return kr;
}
 

/*
 *	Routine:	msg_receive_error	[internal]
 *	Purpose:
 *		Builds a minimal header/trailer and copies it to
 *		the user message buffer.  Invoked when in the case of a
 *		MACH_RCV_TOO_LARGE or MACH_RCV_BODY_ERROR error.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	minimal header/trailer copied
 *		MACH_RCV_INVALID_DATA	copyout to user buffer failed
 */
	
mach_msg_return_t
msg_receive_error(
	ipc_kmsg_t		kmsg,
	mach_vm_address_t	msg_addr,
	mach_msg_option_t	option,
	mach_port_seqno_t	seqno,
	ipc_space_t		space)
{
	mach_msg_format_0_trailer_t *trailer;

	/*
	 * Copy out the destination port in the message.
 	 * Destroy all other rights and memory in the message.
	 */
	ipc_kmsg_copyout_dest(kmsg, space);

	/*
	 * Build a minimal message with the requested trailer.
	 */
	trailer = (mach_msg_format_0_trailer_t *) 
			((vm_offset_t)kmsg->ikm_header +
			round_msg(sizeof(mach_msg_header_t)));
	kmsg->ikm_header->msgh_size = sizeof(mach_msg_header_t);
	bcopy(  (char *)&trailer_template, 
		(char *)trailer, 
		sizeof(trailer_template));
	if (option & MACH_RCV_TRAILER_MASK) {
		trailer->msgh_seqno = seqno;
		trailer->msgh_trailer_size = REQUESTED_TRAILER_SIZE(option);
	}

	/*
	 * Copy the message to user space
	 */
	if (ipc_kmsg_put(msg_addr, kmsg, kmsg->ikm_header->msgh_size +
			trailer->msgh_trailer_size) == MACH_RCV_INVALID_DATA)
		return(MACH_RCV_INVALID_DATA);
	else 
		return(MACH_MSG_SUCCESS);
}

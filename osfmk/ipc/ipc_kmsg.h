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
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 * Copyright (c) 2005 SPARTA, Inc.
 */
/*
 */
/*
 *	File:	ipc/ipc_kmsg.h
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Definitions for kernel messages.
 */

#ifndef	_IPC_IPC_KMSG_H_
#define _IPC_IPC_KMSG_H_

#include <mach/vm_types.h>
#include <mach/message.h>
#include <kern/kern_types.h>
#include <kern/assert.h>
#include <kern/macro_help.h>
#include <ipc/ipc_types.h>
#include <ipc/ipc_object.h>

/*
 *	This structure is only the header for a kmsg buffer;
 *	the actual buffer is normally larger.  The rest of the buffer
 *	holds the body of the message.
 *
 *	In a kmsg, the port fields hold pointers to ports instead
 *	of port names.  These pointers hold references.
 *
 *	The ikm_header.msgh_remote_port field is the destination
 *	of the message.
 */

struct ipc_labelh;

struct ipc_kmsg {
	struct ipc_kmsg *ikm_next;
	struct ipc_kmsg *ikm_prev;
	ipc_port_t ikm_prealloc;	/* port we were preallocated from */
	mach_msg_size_t ikm_size;
	struct ipc_labelh *ikm_sender;
	mach_msg_header_t *ikm_header;
};


#define	IKM_OVERHEAD		(sizeof(struct ipc_kmsg))

#define	ikm_plus_overhead(size)	((mach_msg_size_t)((size) + IKM_OVERHEAD))
#define	ikm_less_overhead(size)	((mach_msg_size_t)((size) - IKM_OVERHEAD))

/*
 * XXX	For debugging.
 */
#define IKM_BOGUS		((ipc_kmsg_t) 0xffffff10)

/*
 *	The size of the kernel message buffers that will be cached.
 *	IKM_SAVED_KMSG_SIZE includes overhead; IKM_SAVED_MSG_SIZE doesn't.
 */
extern zone_t ipc_kmsg_zone;
#define	IKM_SAVED_KMSG_SIZE	256
#define	IKM_SAVED_MSG_SIZE	ikm_less_overhead(IKM_SAVED_KMSG_SIZE)

#define	ikm_prealloc_inuse_port(kmsg)					\
	((kmsg)->ikm_prealloc)

#define	ikm_prealloc_inuse(kmsg)					\
	((kmsg)->ikm_prealloc != IP_NULL)

#define	ikm_prealloc_set_inuse(kmsg, port)				\
MACRO_BEGIN								\
	assert((port) != IP_NULL);					\
	(kmsg)->ikm_prealloc = (port);					\
	ip_reference(port);						\
MACRO_END

#define ikm_prealloc_clear_inuse(kmsg, port)				\
MACRO_BEGIN								\
	(kmsg)->ikm_prealloc = IP_NULL;					\
	ip_release(port);						\
MACRO_END

#define	ikm_init(kmsg, size)						\
MACRO_BEGIN								\
	(kmsg)->ikm_size = (size);					\
	(kmsg)->ikm_prealloc = IP_NULL;					\
        (kmsg)->ikm_sender = NULL;					\
	assert((kmsg)->ikm_prev = (kmsg)->ikm_next = IKM_BOGUS);	\
MACRO_END

#define	ikm_check_init(kmsg, size)					\
MACRO_BEGIN								\
	assert((kmsg)->ikm_size == (size));				\
	assert((kmsg)->ikm_prev == IKM_BOGUS);				\
	assert((kmsg)->ikm_next == IKM_BOGUS);				\
MACRO_END

struct ipc_kmsg_queue {
	struct ipc_kmsg *ikmq_base;
};

typedef struct ipc_kmsg_queue *ipc_kmsg_queue_t;

#define	IKMQ_NULL		((ipc_kmsg_queue_t) 0)


/*
 * Exported interfaces
 */

#define	ipc_kmsg_queue_init(queue)		\
MACRO_BEGIN					\
	(queue)->ikmq_base = IKM_NULL;		\
MACRO_END

#define	ipc_kmsg_queue_empty(queue)	((queue)->ikmq_base == IKM_NULL)

/* Enqueue a kmsg */
extern void ipc_kmsg_enqueue(
	ipc_kmsg_queue_t	queue,
	ipc_kmsg_t		kmsg);

/* Dequeue and return a kmsg */
extern ipc_kmsg_t ipc_kmsg_dequeue(
	ipc_kmsg_queue_t        queue);

/* Pull a kmsg out of a queue */
extern void ipc_kmsg_rmqueue(
	ipc_kmsg_queue_t	queue,
	ipc_kmsg_t		kmsg);

#define	ipc_kmsg_queue_first(queue)		((queue)->ikmq_base)

/* Return the kmsg following the given kmsg */
extern ipc_kmsg_t ipc_kmsg_queue_next(
	ipc_kmsg_queue_t	queue,
	ipc_kmsg_t		kmsg);

#define	ipc_kmsg_rmqueue_first_macro(queue, kmsg)			\
MACRO_BEGIN								\
	register ipc_kmsg_t _next;					\
									\
	assert((queue)->ikmq_base == (kmsg));				\
									\
	_next = (kmsg)->ikm_next;					\
	if (_next == (kmsg)) {						\
		assert((kmsg)->ikm_prev == (kmsg));			\
		(queue)->ikmq_base = IKM_NULL;				\
	} else {							\
		register ipc_kmsg_t _prev = (kmsg)->ikm_prev;		\
									\
		(queue)->ikmq_base = _next;				\
		_next->ikm_prev = _prev;				\
		_prev->ikm_next = _next;				\
	}								\
  	/* XXX Debug paranoia ASSIGNMENTS */				\
  	assert(kmsg->ikm_next = IKM_BOGUS);				\
  	assert(kmsg->ikm_prev = IKM_BOGUS);				\
MACRO_END

#define	ipc_kmsg_enqueue_macro(queue, kmsg)				\
MACRO_BEGIN								\
	register ipc_kmsg_t _first = (queue)->ikmq_base;		\
									\
	if (_first == IKM_NULL) {					\
		(queue)->ikmq_base = (kmsg);				\
		(kmsg)->ikm_next = (kmsg);				\
		(kmsg)->ikm_prev = (kmsg);				\
	} else {							\
		register ipc_kmsg_t _last = _first->ikm_prev;		\
									\
		(kmsg)->ikm_next = _first;				\
		(kmsg)->ikm_prev = _last;				\
		_first->ikm_prev = (kmsg);				\
		_last->ikm_next = (kmsg);				\
	}								\
MACRO_END

/*
 *	extern void
 *	ipc_kmsg_send_always(ipc_kmsg_t);
 */
#define	ipc_kmsg_send_always(kmsg)					\
	ipc_kmsg_send((kmsg), MACH_SEND_ALWAYS, MACH_MSG_TIMEOUT_NONE)


/* Allocate a kernel message */
extern ipc_kmsg_t ipc_kmsg_alloc(
        mach_msg_size_t size);

/* Free a kernel message buffer */
extern void ipc_kmsg_free(
	ipc_kmsg_t	kmsg);

/* Destroy kernel message */
extern void ipc_kmsg_destroy(
	ipc_kmsg_t	kmsg);

/* destroy kernel message and a reference on the dest */
extern void ipc_kmsg_destroy_dest(
	ipc_kmsg_t	kmsg);


/* Preallocate a kernel message buffer */
extern void ipc_kmsg_set_prealloc(
	ipc_kmsg_t	kmsg,
	ipc_port_t	port);

/* Clear a kernel message buffer */
extern void ipc_kmsg_clear_prealloc(
	ipc_kmsg_t	kmsg,
	ipc_port_t	port);

/* Allocate a kernel message buffer and copy a user message to the buffer */
extern mach_msg_return_t ipc_kmsg_get(
	mach_vm_address_t	msg_addr, 
	mach_msg_size_t		size,
	ipc_kmsg_t		*kmsgp);

/* Allocate a kernel message buffer and copy a kernel message to the buffer */
extern mach_msg_return_t ipc_kmsg_get_from_kernel(
	mach_msg_header_t	*msg,
	mach_msg_size_t		size,
	ipc_kmsg_t		*kmsgp);

/* Send a message to a port */
extern mach_msg_return_t ipc_kmsg_send(
	ipc_kmsg_t		kmsg,
	mach_msg_option_t	option,
	mach_msg_timeout_t	timeout_val);

/* Copy a kernel message buffer to a user message */
extern mach_msg_return_t ipc_kmsg_put(
	mach_vm_address_t	msg_addr,
	ipc_kmsg_t		kmsg,
	mach_msg_size_t		size);

/* Copy a kernel message buffer to a kernel message */
extern void ipc_kmsg_put_to_kernel(
	mach_msg_header_t	*msg,
	ipc_kmsg_t		kmsg,
	mach_msg_size_t		size);

/* Copyin port rights in the header of a message */
extern mach_msg_return_t ipc_kmsg_copyin_header(
	mach_msg_header_t	*msg,
	ipc_space_t		space,
	mach_port_name_t	notify);

/* Copyin port rights and out-of-line memory from a user message */
extern mach_msg_return_t ipc_kmsg_copyin(
	ipc_kmsg_t		kmsg,
	ipc_space_t		space,
	vm_map_t		map,
	mach_port_name_t	notify);

/* Copyin port rights and out-of-line memory from a kernel message */
extern void ipc_kmsg_copyin_from_kernel(
	ipc_kmsg_t		kmsg);

/* Copyout port rights in the header of a message */
extern mach_msg_return_t ipc_kmsg_copyout_header(
	mach_msg_header_t	*msg,
	ipc_space_t		space,
	mach_port_name_t	notify);

/* Copyout a port right returning a name */
extern mach_msg_return_t ipc_kmsg_copyout_object(
	ipc_space_t		space,
	ipc_object_t		object,
	mach_msg_type_name_t	msgt_name,
	mach_port_name_t	*namep);

/* Copyout the header and body to a user message */
extern mach_msg_return_t ipc_kmsg_copyout(
	ipc_kmsg_t		kmsg,
	ipc_space_t		space,
	vm_map_t		map,
	mach_port_name_t	notify,
	mach_msg_body_t		*slist);

/* Copyout port rights and out-of-line memory from the body of a message */
extern mach_msg_return_t ipc_kmsg_copyout_body(
    	ipc_kmsg_t		kmsg,
	ipc_space_t		space,
	vm_map_t		map,
	mach_msg_body_t		*slist);

/* Copyout port rights and out-of-line memory to a user message,
   not reversing the ports in the header */
extern mach_msg_return_t ipc_kmsg_copyout_pseudo(
	ipc_kmsg_t		kmsg,
	ipc_space_t		space,
	vm_map_t		map,
	mach_msg_body_t		*slist);

/* Compute size of message as copied out to the specified space/map */
extern mach_msg_size_t ipc_kmsg_copyout_size(
	ipc_kmsg_t		kmsg,
	vm_map_t		map);

/* Copyout the destination port in the message */
extern void ipc_kmsg_copyout_dest( 
	ipc_kmsg_t		kmsg,
	ipc_space_t		space);

/* kernel's version of ipc_kmsg_copyout_dest */
extern void ipc_kmsg_copyout_to_kernel(
	ipc_kmsg_t		kmsg,
	ipc_space_t		space);

/* get a scatter list and check consistency */
extern mach_msg_body_t *ipc_kmsg_get_scatter(
        mach_vm_address_t       msg_addr,
        mach_msg_size_t         slist_size,
        ipc_kmsg_t              kmsg);

/* free a scatter list */
extern void ipc_kmsg_free_scatter(
        mach_msg_body_t 	*slist,
        mach_msg_size_t		slist_size);

#endif	/* _IPC_IPC_KMSG_H_ */


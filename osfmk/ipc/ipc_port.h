/*
 * Copyright (c) 2000-2008 Apple Computer, Inc. All rights reserved.
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
 */
/*
 */
/*
 *	File:	ipc/ipc_port.h
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Definitions for ports.
 */

#ifndef	_IPC_IPC_PORT_H_
#define _IPC_IPC_PORT_H_

#if MACH_KERNEL_PRIVATE

#include <norma_vm.h>
#include <mach_rt.h>
#include <mach_assert.h>
#include <mach_debug.h>

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/port.h>

#include <kern/kern_types.h>

#include <ipc/ipc_types.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_mqueue.h>
#include <ipc/ipc_space.h>

#include <security/_label.h>

/*
 *  A receive right (port) can be in four states:
 *	1) dead (not active, ip_timestamp has death time)
 *	2) in a space (ip_receiver_name != 0, ip_receiver points
 *	to the space but doesn't hold a ref for it)
 *	3) in transit (ip_receiver_name == 0, ip_destination points
 *	to the destination port and holds a ref for it)
 *	4) in limbo (ip_receiver_name == 0, ip_destination == IP_NULL)
 *
 *  If the port is active, and ip_receiver points to some space,
 *  then ip_receiver_name != 0, and that space holds receive rights.
 *  If the port is not active, then ip_timestamp contains a timestamp
 *  taken when the port was destroyed.
 */

typedef unsigned int ipc_port_timestamp_t;

struct ipc_port {

	/*
	 * Initial sub-structure in common with ipc_pset
	 * First element is an ipc_object second is a
	 * message queue
	 */
	struct ipc_object ip_object;
	struct ipc_mqueue ip_messages;

	union {
		struct ipc_space *receiver;
		struct ipc_port *destination;
		ipc_port_timestamp_t timestamp;
	} data;

	ipc_kobject_t ip_kobject;
	mach_port_mscount_t ip_mscount;
	mach_port_rights_t ip_srights;
	mach_port_rights_t ip_sorights;

	struct ipc_port *ip_nsrequest;
	struct ipc_port *ip_pdrequest;
	struct ipc_port_request *ip_dnrequests;

	unsigned int ip_pset_count;
	struct ipc_kmsg *ip_premsg;
	mach_vm_address_t ip_context;

#if	NORMA_VM
	/*
	 *	These fields are needed for the use of XMM.
	 *	Few ports need this information; it should
	 *	be kept in XMM instead (TBD).  XXX
	 */
	long		ip_norma_xmm_object_refs;
	struct ipc_port	*ip_norma_xmm_object;
#endif

#if	MACH_ASSERT
#define	IP_NSPARES		4
#define	IP_CALLSTACK_MAX	16
	queue_chain_t	ip_port_links;	/* all allocated ports */
	thread_t	ip_thread;	/* who made me?  thread context */
	unsigned long	ip_timetrack;	/* give an idea of "when" created */
	natural_t	ip_callstack[IP_CALLSTACK_MAX]; /* stack trace */
	unsigned long	ip_spares[IP_NSPARES]; /* for debugging */
#endif	/* MACH_ASSERT */
	uintptr_t		alias;

#if CONFIG_MACF_MACH
        struct label    ip_label;
#endif
};


#define ip_references		ip_object.io_references
#define ip_bits			ip_object.io_bits

#define	ip_receiver		data.receiver
#define	ip_destination		data.destination
#define	ip_timestamp		data.timestamp

#define ip_receiver_name	ip_messages.imq_receiver_name

#define IP_NULL			IPC_PORT_NULL
#define IP_DEAD			IPC_PORT_DEAD
#define	IP_VALID(port)		IPC_PORT_VALID(port)

#define	ip_active(port)		io_active(&(port)->ip_object)
#define	ip_lock_init(port)	io_lock_init(&(port)->ip_object)
#define	ip_lock(port)		io_lock(&(port)->ip_object)
#define	ip_lock_try(port)	io_lock_try(&(port)->ip_object)
#define	ip_unlock(port)		io_unlock(&(port)->ip_object)
#define	ip_check_unlock(port)	io_check_unlock(&(port)->ip_object)

#define	ip_reference(port)	io_reference(&(port)->ip_object)
#define	ip_release(port)	io_release(&(port)->ip_object)

#define	ip_kotype(port)		io_kotype(&(port)->ip_object)

/*
 * JMM - Preallocation flag
 * This flag indicates that there is a message buffer preallocated for this
 * port and we should use that when sending (from the kernel) rather than
 * allocate a new one.  This avoids deadlocks during notification message
 * sends by critical system threads (which may be needed to free memory and
 * therefore cannot be blocked waiting for memory themselves).
 */
#define	IP_BIT_PREALLOC		0x00008000	/* preallocated mesg */
#define IP_PREALLOC(port)	((port)->ip_bits & IP_BIT_PREALLOC)

#define IP_SET_PREALLOC(port, kmsg)				 	\
MACRO_BEGIN								\
	(port)->ip_bits |= IP_BIT_PREALLOC;				\
	(port)->ip_premsg = (kmsg);					\
MACRO_END

#define IP_CLEAR_PREALLOC(port, kmsg)				 	\
MACRO_BEGIN								\
	assert((port)->ip_premsg == kmsg);				\
	(port)->ip_bits &= ~IP_BIT_PREALLOC;				\
	(port)->ip_premsg = IKM_NULL;					\
MACRO_END


struct ipc_port_request {
	union {
		struct ipc_port *port;
		ipc_port_request_index_t index;
	} notify;

	union {
		mach_port_name_t name;
		struct ipc_table_size *size;
	} name;
};

#define	ipr_next		notify.index
#define	ipr_size		name.size

#define	ipr_soright		notify.port
#define	ipr_name		name.name

extern lck_grp_t 	ipc_lck_grp;
extern lck_attr_t 	ipc_lck_attr;

/*
 *	Taking the ipc_port_multiple lock grants the privilege
 *	to lock multiple ports at once.  No ports must locked
 *	when it is taken.
 */

decl_lck_mtx_data(extern,ipc_port_multiple_lock_data)
extern lck_mtx_ext_t	ipc_port_multiple_lock_data_ext;

#define	ipc_port_multiple_lock_init()					\
		lck_mtx_init_ext(&ipc_port_multiple_lock_data, &ipc_port_multiple_lock_data_ext, &ipc_lck_grp, &ipc_lck_attr)

#define	ipc_port_multiple_lock()					\
		lck_mtx_lock(&ipc_port_multiple_lock_data)

#define	ipc_port_multiple_unlock()					\
		lck_mtx_unlock(&ipc_port_multiple_lock_data)

/*
 *	The port timestamp facility provides timestamps
 *	for port destruction.  It is used to serialize
 *	mach_port_names with port death.
 */

decl_lck_mtx_data(extern,ipc_port_timestamp_lock_data)
extern lck_mtx_ext_t	ipc_port_timestamp_lock_data_ext;

extern ipc_port_timestamp_t ipc_port_timestamp_data;

#define	ipc_port_timestamp_lock_init()					\
		lck_mtx_init_ext(&ipc_port_timestamp_lock_data, &ipc_port_timestamp_lock_data_ext, &ipc_lck_grp, &ipc_lck_attr)

#define	ipc_port_timestamp_lock()					\
		lck_mtx_lock(&ipc_port_timestamp_lock_data)

#define	ipc_port_timestamp_unlock()					\
		lck_mtx_unlock(&ipc_port_timestamp_lock_data)

/* Retrieve a port timestamp value */
extern ipc_port_timestamp_t ipc_port_timestamp(void);

/*
 *	Compares two timestamps, and returns TRUE if one
 *	happened before two.  Note that this formulation
 *	works when the timestamp wraps around at 2^32,
 *	as long as one and two aren't too far apart.
 */

#define	IP_TIMESTAMP_ORDER(one, two)	((int) ((one) - (two)) < 0)

#define	ipc_port_translate_receive(space, name, portp)			\
		ipc_object_translate((space), (name),			\
				     MACH_PORT_RIGHT_RECEIVE,		\
				     (ipc_object_t *) (portp))

#define	ipc_port_translate_send(space, name, portp)			\
		ipc_object_translate((space), (name),			\
				     MACH_PORT_RIGHT_SEND,		\
				     (ipc_object_t *) (portp))

/* Allocate a dead-name request slot */
extern kern_return_t
ipc_port_dnrequest(
	ipc_port_t			port,
	mach_port_name_t		name,
	ipc_port_t			soright,
	ipc_port_request_index_t	*indexp);

/* Grow a port's table of dead-name requests */
extern kern_return_t ipc_port_dngrow(
	ipc_port_t			port,
	ipc_table_elems_t		target_size);

/* Cancel a dead-name request and return the send-once right */
extern ipc_port_t ipc_port_dncancel(
	ipc_port_t			port,
	mach_port_name_t		name,
	ipc_port_request_index_t	index);

#define	ipc_port_dnrename(port, index, oname, nname)			\
MACRO_BEGIN								\
	ipc_port_request_t ipr, table;					\
									\
	assert(ip_active(port));					\
									\
	table = port->ip_dnrequests;					\
	assert(table != IPR_NULL);					\
									\
	ipr = &table[index];						\
	assert(ipr->ipr_name == oname);					\
									\
	ipr->ipr_name = nname;						\
MACRO_END

/* Make a port-deleted request */
extern void ipc_port_pdrequest(
	ipc_port_t	port,
	ipc_port_t	notify,
	ipc_port_t	*previousp);

/* Make a no-senders request */
extern void ipc_port_nsrequest(
	ipc_port_t		port,
	mach_port_mscount_t	sync,
	ipc_port_t		notify,
	ipc_port_t		*previousp);

#define	ipc_port_set_mscount(port, mscount)				\
MACRO_BEGIN								\
	assert(ip_active(port));					\
									\
	(port)->ip_mscount = (mscount);					\
MACRO_END

/* Prepare a receive right for transmission/destruction */
extern void ipc_port_clear_receiver(
	ipc_port_t		port);

/* Initialize a newly-allocated port */
extern void ipc_port_init(
	ipc_port_t		port,
	ipc_space_t		space,
	mach_port_name_t	name);

/* Allocate a port */
extern kern_return_t ipc_port_alloc(
	ipc_space_t		space,
	mach_port_name_t	*namep,
	ipc_port_t		*portp);

/* Allocate a port, with a specific name */
extern kern_return_t ipc_port_alloc_name(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_port_t		*portp);

/* Generate dead name notifications */
extern void ipc_port_dnnotify(
	ipc_port_t		port,
	ipc_port_request_t	dnrequests);

/* Destroy a port */
extern void ipc_port_destroy(
	ipc_port_t	port);

/* Check if queueing "port" in a message for "dest" would create a circular 
   group of ports and messages */
extern boolean_t
ipc_port_check_circularity(
	ipc_port_t	port,
	ipc_port_t	dest);

/* Make a send-once notify port from a receive right */
extern ipc_port_t ipc_port_lookup_notify(
	ipc_space_t		space, 
	mach_port_name_t 	name);

/* Make a naked send right from a receive right - port locked and active */
extern ipc_port_t ipc_port_make_send_locked(
	ipc_port_t	port);

/* Make a naked send right from a receive right */
extern ipc_port_t ipc_port_make_send(
	ipc_port_t	port);

/* Make a naked send right from another naked send right */
extern ipc_port_t ipc_port_copy_send(
	ipc_port_t	port);

/* Copyout a naked send right */
extern mach_port_name_t ipc_port_copyout_send(
	ipc_port_t	sright,
	ipc_space_t	space);

#endif /* MACH_KERNEL_PRIVATE */

#if KERNEL_PRIVATE

/* Release a (valid) naked send right */
extern void ipc_port_release_send(
	ipc_port_t	port);

#endif /* KERNEL_PRIVATE */

#if MACH_KERNEL_PRIVATE

/* Make a naked send-once right from a receive right */
extern ipc_port_t ipc_port_make_sonce(
	ipc_port_t	port);

/* Release a naked send-once right */
extern void ipc_port_release_sonce(
	ipc_port_t	port);

/* Release a naked (in limbo or in transit) receive right */
extern void ipc_port_release_receive(
	ipc_port_t	port);

/* Allocate a port in a special space */
extern ipc_port_t ipc_port_alloc_special(
	ipc_space_t	space);

/* Deallocate a port in a special space */
extern void ipc_port_dealloc_special(
	ipc_port_t	port,
	ipc_space_t	space);

#if	MACH_ASSERT
/* Track low-level port deallocation */
extern void ipc_port_track_dealloc(
	ipc_port_t	port);

/* Initialize general port debugging state */
extern void ipc_port_debug_init(void);
#endif	/* MACH_ASSERT */

#define	ipc_port_alloc_kernel()		\
		ipc_port_alloc_special(ipc_space_kernel)
#define	ipc_port_dealloc_kernel(port)	\
		ipc_port_dealloc_special((port), ipc_space_kernel)

#define	ipc_port_alloc_reply()		\
		ipc_port_alloc_special(ipc_space_reply)
#define	ipc_port_dealloc_reply(port)	\
		ipc_port_dealloc_special((port), ipc_space_reply)

#define	ipc_port_reference(port)	\
		ipc_object_reference(&(port)->ip_object)

#define	ipc_port_release(port)		\
		ipc_object_release(&(port)->ip_object)

#endif /* MACH_KERNEL_PRIVATE */

#endif	/* _IPC_IPC_PORT_H_ */

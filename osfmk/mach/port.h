/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
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
 *	File:	mach/port.h
 *
 *	Definition of a port
 *
 *	[The basic port_t type should probably be machine-dependent,
 *	as it must be represented by a 32-bit integer.]
 */

#ifndef	_MACH_PORT_H_
#define _MACH_PORT_H_

#include <stdint.h>
#include <mach/boolean.h>
#include <mach/machine/vm_types.h>

#include <sys/appleapiopts.h>

/*
 * A port_name_t is a 32 bit value which represents a name of a
 * port right within some ipc space.  This is a constant definition
 * everywhere.
 *
 * The type port_t represents a reference added or deleted to a
 * port right.
 *
 * 	At user space, this is represented by returning the name of
 *	the right(s) that got altered within the user's ipc space.
 *	So a port_t is the same type as a port_name_t there.
 *
 *	Since there is no right space for the kernel proper (all rights
 *	are naked rights) these rights are represented by passing a
 *	pointer to the specific ipc_object_t subclass (typically
 *	ipc_port_t) that got altered/is to be altered.
 *
 *	JMM - Because of this pointer/integer overloading, port names
 *	should be defined as uintptr_t types.  But that would make
 *	message headers and descriptors pointer-length dependent.
 */
typedef natural_t port_name_t;
typedef port_name_t *port_name_array_t;

#ifdef KERNEL_PRIVATE

#if !defined(__APPLE_API_PRIVATE) || !defined(MACH_KERNEL_PRIVATE)
/*
 * For kernel code that resides outside of mach
 * we define empty structs so that everything will
 * remain strongly typed, without giving out
 * implementation details.
 */
struct ipc_port ;

#endif /* !__APPLE_API_PRIVATE || !MACH_KERNEL_PRIVATE */

typedef struct ipc_port	        *ipc_port_t;
typedef ipc_port_t 		port_t;

#define	IPC_PORT_NULL		((ipc_port_t) 0)
#define	IPC_PORT_DEAD		((ipc_port_t)~0)
#define IPC_PORT_VALID(port)	(((port) != IPC_PORT_NULL) && \
				 ((port) != IPC_PORT_DEAD))

#else  /* ! KERNEL_PRIVATE */

typedef port_name_t 		port_t;

#endif /* KERNEL_PRIVATE */

/*
 *  PORT_NULL is a legal value that can be carried in messages.
 *  It indicates the absence of any port or port rights.  (A port
 *  argument keeps the message from being "simple", even if the
 *  value is PORT_NULL.)  The value PORT_DEAD is also a legal
 *  value that can be carried in messages.  It indicates
 *  that a port right was present, but it died.
 */
#define PORT_NULL		((port_t) 0)
#define PORT_DEAD		((port_t) ~0)
#define	PORT_VALID(name)				\
		(((port_t)(name) != PORT_NULL) &&	\
                 ((port_t)(name) != PORT_DEAD))

/*
 *  Mach 3.0 renamed everything to have mach_ in front of it.
 *  Do that mapping here, so we have the types and macros in
 *  both formats.
 */
typedef port_t			mach_port_t;
typedef port_t			*mach_port_array_t;
typedef port_name_t		mach_port_name_t;
typedef mach_port_name_t	*mach_port_name_array_t;

#define MACH_PORT_NULL		0  /* intentional loose typing */
#define MACH_PORT_DEAD		((mach_port_name_t) ~0)
#define MACH_PORT_VALID(name)				\
		(((name) != MACH_PORT_NULL) && 		\
		 ((name) != MACH_PORT_DEAD))

/*
 *  mach_port_name_t must be an unsigned type.  Port values
 *  have two parts, a generation number and an index.
 *  These macros encapsulate all knowledge of how
 *  a mach_port_name_t is laid out.  They are made visible 
 *  to user tasks so that packages to map from a mach_port_name_t
 *  to associated user data can discount the generation
 *  nuber (if desired) in doing the mapping.
 *
 *  Within the kernel, ipc/ipc_entry.c implicitly assumes
 *  when it uses the splay tree functions that the generation
 *  number is in the low bits, so that names are ordered first
 *  by index and then by generation.  If the size of generation
 *  numbers changes, be sure to update IE_BITS_GEN_MASK and
 *  friends in ipc/ipc_entry.h.
 */
#ifndef NO_PORT_GEN
#define	MACH_PORT_INDEX(name)		((name) >> 8)
#define	MACH_PORT_GEN(name)		(((name) & 0xff) << 24)
#define	MACH_PORT_MAKE(index, gen)	\
		(((index) << 8) | (gen) >> 24)
#else
#define	MACH_PORT_INDEX(name)		(name)
#define	MACH_PORT_GEN(name)		(0)
#define	MACH_PORT_MAKE(index, gen)	(index)
#endif	/* !NO_PORT_GEN */

/*
 *  These are the different rights a task may have.
 *  The MACH_PORT_RIGHT_* definitions are used as arguments
 *  to mach_port_allocate, mach_port_get_refs, etc, to specify
 *  a particular right to act upon.  The mach_port_names and
 *  mach_port_type calls return bitmasks using the MACH_PORT_TYPE_*
 *  definitions.  This is because a single name may denote
 *  multiple rights.
 */

typedef natural_t mach_port_right_t;

#define MACH_PORT_RIGHT_SEND		((mach_port_right_t) 0)
#define MACH_PORT_RIGHT_RECEIVE		((mach_port_right_t) 1)
#define MACH_PORT_RIGHT_SEND_ONCE	((mach_port_right_t) 2)
#define MACH_PORT_RIGHT_PORT_SET	((mach_port_right_t) 3)
#define MACH_PORT_RIGHT_DEAD_NAME	((mach_port_right_t) 4)
#define MACH_PORT_RIGHT_NUMBER		((mach_port_right_t) 5)

typedef natural_t mach_port_type_t;
typedef mach_port_type_t *mach_port_type_array_t;

#define MACH_PORT_TYPE(right)						\
		((mach_port_type_t)(((mach_port_type_t) 1)  		\
		<< ((right) + ((mach_port_right_t) 16))))	
#define MACH_PORT_TYPE_NONE	    ((mach_port_type_t) 0L)
#define MACH_PORT_TYPE_SEND	    MACH_PORT_TYPE(MACH_PORT_RIGHT_SEND)
#define MACH_PORT_TYPE_RECEIVE	    MACH_PORT_TYPE(MACH_PORT_RIGHT_RECEIVE)
#define MACH_PORT_TYPE_SEND_ONCE    MACH_PORT_TYPE(MACH_PORT_RIGHT_SEND_ONCE)
#define MACH_PORT_TYPE_PORT_SET	    MACH_PORT_TYPE(MACH_PORT_RIGHT_PORT_SET)
#define MACH_PORT_TYPE_DEAD_NAME    MACH_PORT_TYPE(MACH_PORT_RIGHT_DEAD_NAME)

/* Convenient combinations. */

#define MACH_PORT_TYPE_SEND_RECEIVE					\
		(MACH_PORT_TYPE_SEND|MACH_PORT_TYPE_RECEIVE)
#define	MACH_PORT_TYPE_SEND_RIGHTS					\
		(MACH_PORT_TYPE_SEND|MACH_PORT_TYPE_SEND_ONCE)
#define	MACH_PORT_TYPE_PORT_RIGHTS					\
		(MACH_PORT_TYPE_SEND_RIGHTS|MACH_PORT_TYPE_RECEIVE)
#define	MACH_PORT_TYPE_PORT_OR_DEAD					\
		(MACH_PORT_TYPE_PORT_RIGHTS|MACH_PORT_TYPE_DEAD_NAME)
#define MACH_PORT_TYPE_ALL_RIGHTS					\
		(MACH_PORT_TYPE_PORT_OR_DEAD|MACH_PORT_TYPE_PORT_SET)

/* Dummy type bits that mach_port_type/mach_port_names can return. */

#define MACH_PORT_TYPE_DNREQUEST	0x80000000

/* User-references for capabilities. */

typedef natural_t mach_port_urefs_t;
typedef integer_t mach_port_delta_t;			/* change in urefs */

/* Attributes of ports.  (See mach_port_get_receive_status.) */

typedef natural_t mach_port_seqno_t;		/* sequence number */
typedef natural_t mach_port_mscount_t;		/* make-send count */
typedef natural_t mach_port_msgcount_t;		/* number of msgs */
typedef natural_t mach_port_rights_t;		/* number of rights */

/*
 *	Are there outstanding send rights for a given port?
 */
#define	MACH_PORT_SRIGHTS_NONE		0		/* no srights */
#define	MACH_PORT_SRIGHTS_PRESENT	1		/* srights */
typedef unsigned int mach_port_srights_t;	/* status of send rights */

typedef struct mach_port_status {
	mach_port_name_t	mps_pset;	/* containing port set */
	mach_port_seqno_t	mps_seqno;	/* sequence number */
	mach_port_mscount_t	mps_mscount;	/* make-send count */
	mach_port_msgcount_t	mps_qlimit;	/* queue limit */
	mach_port_msgcount_t	mps_msgcount;	/* number in the queue */
	mach_port_rights_t	mps_sorights;	/* how many send-once rights */
	boolean_t		mps_srights;	/* do send rights exist? */
	boolean_t		mps_pdrequest;	/* port-deleted requested? */
	boolean_t		mps_nsrequest;	/* no-senders requested? */
	unsigned int		mps_flags;	/* port flags */
} mach_port_status_t;

#define MACH_PORT_QLIMIT_DEFAULT	((mach_port_msgcount_t) 5)
#define MACH_PORT_QLIMIT_MAX		((mach_port_msgcount_t) 16)

typedef struct mach_port_limits {
	mach_port_msgcount_t	mpl_qlimit;	/* number of msgs */
} mach_port_limits_t;

typedef integer_t *mach_port_info_t;		/* varying array of natural_t */

/* Flavors for mach_port_get/set_attributes() */
typedef int	mach_port_flavor_t;
#define MACH_PORT_LIMITS_INFO		1	/* uses mach_port_status_t */
#define MACH_PORT_RECEIVE_STATUS	2	/* uses mach_port_limits_t */
#define MACH_PORT_DNREQUESTS_SIZE	3	/* info is int */

#define MACH_PORT_LIMITS_INFO_COUNT \
	(sizeof(mach_port_limits_t)/sizeof(natural_t))
#define MACH_PORT_RECEIVE_STATUS_COUNT \
	(sizeof(mach_port_status_t)/sizeof(natural_t))
#define MACH_PORT_DNREQUESTS_SIZE_COUNT 1

/*
 * Structure used to pass information about port allocation requests.
 * Must be padded to 64-bits total length.
 */

typedef struct mach_port_qos {
	boolean_t		name:1;		/* name given */
	boolean_t		prealloc:1;	/* prealloced message */
	boolean_t		pad1:30;
	natural_t		len;
} mach_port_qos_t;

#endif	/* _MACH_PORT_H_ */

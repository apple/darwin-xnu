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
 * @OSF_COPYRIGHT@
 */

#ifndef	_KERN_KERN_TYPES_H_
#define	_KERN_KERN_TYPES_H_

#include <stdint.h>
#include <mach/mach_types.h>
#include <mach/machine/vm_types.h>

#ifdef	KERNEL_PRIVATE

#ifndef	MACH_KERNEL_PRIVATE

struct zone ;

struct wait_queue { unsigned int opaque[2]; uintptr_t opaquep[2]; } ;

#endif	/* MACH_KERNEL_PRIVATE */

typedef struct zone			*zone_t;
#define		ZONE_NULL			((zone_t) 0)

typedef struct wait_queue		*wait_queue_t;
#define		WAIT_QUEUE_NULL 	((wait_queue_t) 0)
#define 		SIZEOF_WAITQUEUE	sizeof(struct wait_queue)

typedef vm_offset_t			ipc_kobject_t;
#define		IKO_NULL			((ipc_kobject_t) 0)

#endif	/* KERNEL_PRIVATE */

typedef	void *event_t;		/* wait event */
#define		NO_EVENT			((event_t) 0)

typedef uint64_t event64_t;		/* 64 bit wait event */
#define		NO_EVENT64		((event64_t) 0)
#define		CAST_EVENT64_T(a_ptr)	((event64_t)((uintptr_t)(a_ptr)))

/*
 *	Possible wait_result_t values.
 */
typedef int wait_result_t;
#define THREAD_WAITING		-1		/* thread is waiting */
#define THREAD_AWAKENED		0		/* normal wakeup */
#define THREAD_TIMED_OUT	1		/* timeout expired */
#define THREAD_INTERRUPTED	2		/* aborted/interrupted */
#define THREAD_RESTART		3		/* restart operation entirely */

typedef	void (*thread_continue_t)(void *, wait_result_t);
#define	THREAD_CONTINUE_NULL	((thread_continue_t) 0)

/*
 * Interruptible flag for waits.
 */
typedef int wait_interrupt_t;
#define THREAD_UNINT			0		/* not interruptible      */
#define THREAD_INTERRUPTIBLE	1		/* may not be restartable */
#define THREAD_ABORTSAFE		2		/* abortable safely       */

#ifdef	KERNEL_PRIVATE

#ifdef	MACH_KERNEL_PRIVATE

#include <kern/misc_protos.h>
typedef  struct clock			*clock_t;

typedef struct mig_object		*mig_object_t;
#define MIG_OBJECT_NULL			((mig_object_t) 0)

typedef struct mig_notify		*mig_notify_t;
#define MIG_NOTIFY_NULL 		((mig_notify_t) 0)

typedef struct pset_node		*pset_node_t;
#define PSET_NODE_NULL			((pset_node_t) 0)

typedef struct affinity_set		*affinity_set_t;
#define AFFINITY_SET_NULL		((affinity_set_t) 0)

#else	/* MACH_KERNEL_PRIVATE */

struct wait_queue_set ;
struct _wait_queue_link ;

#endif	/* MACH_KERNEL_PRIVATE */

typedef struct wait_queue_set	*wait_queue_set_t;
#define WAIT_QUEUE_SET_NULL 	((wait_queue_set_t)0)
#define SIZEOF_WAITQUEUE_SET	wait_queue_set_size()

typedef struct _wait_queue_link	*wait_queue_link_t;
#define WAIT_QUEUE_LINK_NULL	((wait_queue_link_t)0)
#define SIZEOF_WAITQUEUE_LINK	wait_queue_link_size()

/* legacy definitions - going away */
struct wait_queue_sub ;
typedef struct wait_queue_sub	*wait_queue_sub_t;
#define WAIT_QUEUE_SUB_NULL 	((wait_queue_sub_t)0)
#define SIZEOF_WAITQUEUE_SUB	wait_queue_set_size()

#endif	/* KERNEL_PRIVATE */

#endif	/* _KERN_KERN_TYPES_H_ */

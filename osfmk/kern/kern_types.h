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

#ifndef	_KERN_KERN_TYPES_H_
#define	_KERN_KERN_TYPES_H_

#ifdef KERNEL_PRIVATE

#include <stdint.h>

#include <mach/machine/vm_types.h>
#include <ipc/ipc_types.h>

#if !defined(MACH_KERNEL_PRIVATE)

/*
 * Declare empty structure definitions for export to other
 * kernel components.  This lets us still provide some level
 * of type checking, without exposing our internal data
 * structures.
 */
struct thread_shuttle ;
struct task ;
struct host ;
struct processor ;
struct processor_set ;
struct thread_activation ;
struct subsystem ;
struct semaphore ;
struct lock_set ;
struct ledger ;
struct alarm ;
struct clock ;
struct zone ;
struct wait_queue_sub ;
struct wait_queue_link;

#else /* MACH_KERNEL_PRIVATE */

#include <kern/misc_protos.h>
typedef struct clock			*clock_t;          /* Internal use only */

#endif /* MACH_KERNEL_PRIVATE */

typedef struct mig_object		*mig_object_t;
typedef struct mig_notify		*mig_notify_t;
typedef struct thread_shuttle		*thread_t;
typedef struct thread_shuttle		*thread_shuttle_t;
typedef struct task			*task_t;
typedef struct host			*host_t;
typedef struct processor		*processor_t;
typedef struct processor_set		*processor_set_t;
typedef struct thread_activation	*thread_act_t;
typedef struct subsystem		*subsystem_t;
typedef struct semaphore 		*semaphore_t;
typedef struct lock_set 		*lock_set_t;
typedef struct ledger 			*ledger_t;
typedef	struct alarm			*alarm_t;
typedef	struct clock			*clock_serv_t;
typedef	struct clock			*clock_ctrl_t;
typedef struct zone			*zone_t;
typedef struct wait_queue		*wait_queue_t;
typedef struct wait_queue_sub		*wait_queue_sub_t;
typedef struct wait_queue_link		*wait_queue_link_t;

typedef host_t host_priv_t;
typedef host_t host_security_t;
typedef processor_set_t processor_set_name_t;
typedef vm_offset_t	ipc_kobject_t;

typedef	void	*event_t;			/* wait event */
typedef	void	(*continuation_t)(void);	/* continuation */

#define		ZONE_NULL	((zone_t) 0)

#define		NO_EVENT	((event_t) 0)
#define		WAIT_QUEUE_NULL ((wait_queue_t) 0)

#define		IKO_NULL	((ipc_kobject_t) 0)
#define		MIG_OBJECT_NULL ((mig_object_t) 0)
#define 	MIG_NOTIFY_NULL ((mig_notify_t) 0)

#endif /* KERNEL_PRIVATE */

#endif	/* _KERN_KERN_TYPES_H_ */

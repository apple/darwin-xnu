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
 *	Definitions for RPC subsystems.
 */

#ifndef	_IPC_IPC_SUBSYSTEM_H_
#define _IPC_IPC_SUBSYSTEM_H_

#include <mach/kern_return.h>
#include <mach/mach_types.h>
#include <mach/std_types.h>
#include <mach/rpc.h>

#ifdef MACH_KERNEL_PRIVATE
#include <kern/kern_types.h>
#include <kern/lock.h>

#define subsystem_lock_init(subsys) \
	simple_lock_init(&(subsys)->lock, ETAP_MISC_RPC_SUBSYS)
#define subsystem_lock(subsys)		simple_lock(&(subsys)->lock)
#define subsystem_unlock(subsys)	simple_unlock(&(subsys)->lock)

/*
 *	A subsystem describes a set of server routines that can be invoked by
 *	mach_rpc() on the ports that are registered with the subsystem.
 *	See struct rpc_subsystem in mach/rpc.h, for more details.
 */
struct subsystem {
	/* Synchronization/destruction information */
	decl_simple_lock_data(,lock)	/* Subsystem lock		     */
	int		ref_count;	/* Number of references to me	     */
	vm_size_t	size;		/* Number of bytes in this structure */
					/* including the variable length     */
					/* user_susbystem description	     */
        /* Task information */
        task_t          task;           /* Task to which I belong	     */
        queue_chain_t   subsystem_list; /* list of subsystems in task	     */

	/* IPC stuff: */
	struct ipc_port *ipc_self;	/* Port naming this subsystem	     */

	struct rpc_subsystem user;	/* MIG-generated subsystem descr     */
};

extern void		subsystem_init(void);

#endif /* MACH_KERNEL_PRIVATE */

/* Subsystem create, with 1 reference. */
extern kern_return_t	mach_subsystem_create(
				task_t			parent_task,
				user_subsystem_t	user_subsys,
				mach_msg_type_number_t	user_subsysCount,
				subsystem_t		*subsystem);

/* Take additional reference on subsystem (make sure it doesn't go away) */
extern void		subsystem_reference(
				subsystem_t	subsystem);

/* Remove one reference on subsystem (it is destroyed if 0 refs remain) */
extern void		subsystem_deallocate(
				subsystem_t	subsystem);

#if	MACH_KDB
extern void		subsystem_print(
				subsystem_t	subsystem);
#endif	/* MACH_KDB */

#endif	/* _IPC_IPC_SUBSYSTEM_H_ */

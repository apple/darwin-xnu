/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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
 * 
 */
/*
 *	File:	kern/sync_lock.c
 *	Author:	Joseph CaraDonna
 *
 *	Contains RT distributed lock synchronization services.
 */

#include <mach/mach_types.h>
#include <mach/lock_set_server.h>
#include <mach/task_server.h>

#include <kern/misc_protos.h>
#include <kern/kalloc.h>
#include <kern/sync_lock.h>
#include <kern/sched_prim.h>
#include <kern/ipc_kobject.h>
#include <kern/ipc_sync.h>
#include <kern/thread.h>
#include <kern/task.h>

#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>
#include <libkern/OSAtomic.h>



/*
 *	OBSOLETE: lock set routines are obsolete
 */      
kern_return_t
lock_set_create (
	__unused task_t		task,
	__unused lock_set_t	*new_lock_set,
	__unused int		n_ulocks,
	__unused int		policy)
{
	return KERN_FAILURE;
}

kern_return_t
lock_set_destroy (
	__unused task_t task,
	__unused lock_set_t lock_set)
{
	return KERN_FAILURE;
}

kern_return_t
lock_acquire (
	__unused lock_set_t lock_set,
	__unused int lock_id)
{
	return KERN_FAILURE;
}

kern_return_t
lock_release (
	__unused lock_set_t lock_set,
	__unused int lock_id)
{
	return KERN_FAILURE;
}

kern_return_t
lock_try (
	__unused lock_set_t lock_set,
	__unused int lock_id)
{
	return KERN_FAILURE;	
}

kern_return_t
lock_make_stable (
	__unused lock_set_t lock_set,
	__unused int lock_id)
{
	return KERN_FAILURE;		
}

kern_return_t
lock_handoff (
	__unused lock_set_t lock_set,
	__unused int lock_id)
{
	return KERN_FAILURE;
}

kern_return_t
lock_handoff_accept (
	__unused lock_set_t lock_set,
	__unused int lock_id)
{
	return KERN_FAILURE;
}

void
lock_set_reference(
	__unused lock_set_t lock_set)
{
	return;
}

void
lock_set_dereference(
	__unused lock_set_t lock_set)
{
	return;
}


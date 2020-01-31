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
 *	        File:	kern/task_swap.c
 *
 *	Task residency management primitives implementation.
 */
#include <mach_assert.h>
#include <task_swapper.h>

#include <kern/spl.h>
#include <kern/queue.h>
#include <kern/host.h>
#include <kern/task.h>
#include <kern/task_swap.h>
#include <kern/thread.h>
#include <kern/host_statistics.h>
#include <kern/misc_protos.h>
#include <kern/assert.h>
#include <mach/policy.h>

#include <ipc/ipc_port.h>       /* We use something from in here */

/*
 *	task_swappable:	[exported]
 *
 *	Make a task swappable or non-swappable. If made non-swappable,
 *	it will be swapped in.
 */
kern_return_t
task_swappable(
	host_priv_t host_priv,
	task_t task,
	__unused boolean_t make_swappable)
{
	if (host_priv == HOST_PRIV_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * We don't support swapping, this call is purely advisory.
	 */
	return KERN_SUCCESS;
}

/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
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

#include <kern/task.h>
#include <kern/thread.h>
#include <i386/misc_protos.h>
#include <i386/fpu.h>

#if HYPERVISOR
#include <kern/hv_support.h>
#endif

extern zone_t ids_zone;

kern_return_t
machine_task_set_state(
	task_t task,
	int flavor,
	thread_state_t state,
	mach_msg_type_number_t state_count)
{
	switch (flavor) {
	case x86_DEBUG_STATE32:
	{
		x86_debug_state32_t *tstate = (x86_debug_state32_t*) state;
		if ((task_has_64Bit_addr(task)) ||
		    (state_count != x86_DEBUG_STATE32_COUNT) ||
		    (!debug_state_is_valid32(tstate))) {
			return KERN_INVALID_ARGUMENT;
		}

		if (task->task_debug == NULL) {
			task->task_debug = zalloc(ids_zone);
		}

		copy_debug_state32(tstate, (x86_debug_state32_t*) task->task_debug, FALSE);

		return KERN_SUCCESS;
	}
	case x86_DEBUG_STATE64:
	{
		x86_debug_state64_t *tstate = (x86_debug_state64_t*) state;

		if ((!task_has_64Bit_addr(task)) ||
		    (state_count != x86_DEBUG_STATE64_COUNT) ||
		    (!debug_state_is_valid64(tstate))) {
			return KERN_INVALID_ARGUMENT;
		}

		if (task->task_debug == NULL) {
			task->task_debug = zalloc(ids_zone);
		}

		copy_debug_state64(tstate, (x86_debug_state64_t*) task->task_debug, FALSE);

		return KERN_SUCCESS;
	}
	case x86_DEBUG_STATE:
	{
		x86_debug_state_t *tstate = (x86_debug_state_t*) state;

		if (state_count != x86_DEBUG_STATE_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if ((tstate->dsh.flavor == x86_DEBUG_STATE32) &&
		    (tstate->dsh.count == x86_DEBUG_STATE32_COUNT) &&
		    (!task_has_64Bit_addr(task)) &&
		    debug_state_is_valid32(&tstate->uds.ds32)) {
			if (task->task_debug == NULL) {
				task->task_debug = zalloc(ids_zone);
			}

			copy_debug_state32(&tstate->uds.ds32, (x86_debug_state32_t*) task->task_debug, FALSE);
			return KERN_SUCCESS;
		} else if ((tstate->dsh.flavor == x86_DEBUG_STATE64) &&
		    (tstate->dsh.count == x86_DEBUG_STATE64_COUNT) &&
		    task_has_64Bit_addr(task) &&
		    debug_state_is_valid64(&tstate->uds.ds64)) {
			if (task->task_debug == NULL) {
				task->task_debug = zalloc(ids_zone);
			}

			copy_debug_state64(&tstate->uds.ds64, (x86_debug_state64_t*) task->task_debug, FALSE);
			return KERN_SUCCESS;
		} else {
			return KERN_INVALID_ARGUMENT;
		}
	}
	default:
	{
		return KERN_INVALID_ARGUMENT;
	}
	}
}

kern_return_t
machine_task_get_state(task_t task,
    int flavor,
    thread_state_t state,
    mach_msg_type_number_t *state_count)
{
	switch (flavor) {
	case x86_DEBUG_STATE32:
	{
		x86_debug_state32_t *tstate = (x86_debug_state32_t*) state;

		if ((task_has_64Bit_addr(task)) || (*state_count != x86_DEBUG_STATE32_COUNT)) {
			return KERN_INVALID_ARGUMENT;
		}

		if (task->task_debug == NULL) {
			bzero(state, sizeof(*tstate));
		} else {
			copy_debug_state32((x86_debug_state32_t*) task->task_debug, tstate, TRUE);
		}

		return KERN_SUCCESS;
	}
	case x86_DEBUG_STATE64:
	{
		x86_debug_state64_t *tstate = (x86_debug_state64_t*) state;

		if ((!task_has_64Bit_addr(task)) || (*state_count != x86_DEBUG_STATE64_COUNT)) {
			return KERN_INVALID_ARGUMENT;
		}

		if (task->task_debug == NULL) {
			bzero(state, sizeof(*tstate));
		} else {
			copy_debug_state64((x86_debug_state64_t*) task->task_debug, tstate, TRUE);
		}

		return KERN_SUCCESS;
	}
	case x86_DEBUG_STATE:
	{
		x86_debug_state_t   *tstate = (x86_debug_state_t*)state;

		if (*state_count != x86_DEBUG_STATE_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (task_has_64Bit_addr(task)) {
			tstate->dsh.flavor = x86_DEBUG_STATE64;
			tstate->dsh.count  = x86_DEBUG_STATE64_COUNT;

			if (task->task_debug == NULL) {
				bzero(&tstate->uds.ds64, sizeof(tstate->uds.ds64));
			} else {
				copy_debug_state64((x86_debug_state64_t*)task->task_debug, &tstate->uds.ds64, TRUE);
			}
		} else {
			tstate->dsh.flavor = x86_DEBUG_STATE32;
			tstate->dsh.count  = x86_DEBUG_STATE32_COUNT;

			if (task->task_debug == NULL) {
				bzero(&tstate->uds.ds32, sizeof(tstate->uds.ds32));
			} else {
				copy_debug_state32((x86_debug_state32_t*)task->task_debug, &tstate->uds.ds32, TRUE);
			}
		}

		return KERN_SUCCESS;
	}
	default:
	{
		return KERN_INVALID_ARGUMENT;
	}
	}
}

/*
 * This is called when a task is terminated, and also on exec().
 * Clear machine-dependent state that is stored on the task.
 */
void
machine_task_terminate(task_t task)
{
	if (task) {
		user_ldt_t user_ldt;
		void *task_debug;

#if HYPERVISOR
		if (task->hv_task_target) {
			hv_callbacks.task_destroy(task->hv_task_target);
			task->hv_task_target = NULL;
		}
#endif

		user_ldt = task->i386_ldt;
		if (user_ldt != 0) {
			task->i386_ldt = 0;
			user_ldt_free(user_ldt);
		}

		task_debug = task->task_debug;
		if (task_debug != NULL) {
			task->task_debug = NULL;
			zfree(ids_zone, task_debug);
		}
	}
}

/*
 * Set initial default state on a thread as stored in the MACHINE_TASK data.
 * Note: currently only debug state is supported.
 */
kern_return_t
machine_thread_inherit_taskwide(
	thread_t thread,
	task_t parent_task)
{
	if (parent_task->task_debug) {
		int flavor;
		mach_msg_type_number_t count;

		if (task_has_64Bit_addr(parent_task)) {
			flavor = x86_DEBUG_STATE64;
			count = x86_DEBUG_STATE64_COUNT;
		} else {
			flavor = x86_DEBUG_STATE32;
			count = x86_DEBUG_STATE32_COUNT;
		}

		return machine_thread_set_state(thread, flavor, parent_task->task_debug, count);
	}

	return KERN_SUCCESS;
}

void
machine_task_init(task_t new_task,
    task_t parent_task,
    boolean_t inherit_memory)
{
	new_task->uexc_range_start = 0;
	new_task->uexc_range_size = 0;
	new_task->uexc_handler = 0;

	new_task->i386_ldt = 0;

	if (parent_task != TASK_NULL) {
		if (inherit_memory && parent_task->i386_ldt) {
			new_task->i386_ldt = user_ldt_copy(parent_task->i386_ldt);
		}
		new_task->xstate = parent_task->xstate;
	} else {
		assert(fpu_default != UNDEFINED);
		new_task->xstate = fpu_default;
	}
}

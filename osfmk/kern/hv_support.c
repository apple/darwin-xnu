/*
 * Copyright (c) 2013 Apple Inc. All rights reserved.
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

#include <kern/locks.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <libkern/OSAtomic.h>
#include <vm/vm_pageout.h>

#if defined(__x86_64__) && CONFIG_VMX
#include <i386/vmx/vmx_cpu.h>
#endif

#include <kern/hv_support.h>

int hv_support_available = 0;

/* callbacks for tasks/threads with associated hv objects */
hv_callbacks_t hv_callbacks = {
	.dispatch = NULL,               /* thread is being dispatched for execution */
	.preempt = NULL,                /* thread is being preempted */
	.suspend = NULL,                /* system is being suspended */
	.thread_destroy = NULL, /* thread is being destroyed */
	.task_destroy = NULL,   /* task is being destroyed */
	.volatile_state = NULL, /* thread state is becoming volatile */
};

/* trap tables for hv_*_trap syscalls */
static hv_trap_table_t hv_trap_table[] = {
	[HV_TASK_TRAP] = {
		.traps = NULL,
		.trap_count = 0
	},
	[HV_THREAD_TRAP] = {
		.traps = NULL,
		.trap_count = 0
	}
};

static int hv_callbacks_enabled = 0;
static lck_grp_t *hv_support_lck_grp = NULL;
static lck_mtx_t *hv_support_lck_mtx = NULL;

/* hv_support boot initialization */
void
hv_support_init(void)
{
#if defined(__x86_64__) && CONFIG_VMX
	hv_support_available = vmx_hv_support();
#endif

	hv_support_lck_grp = lck_grp_alloc_init("hv_support", LCK_GRP_ATTR_NULL);
	assert(hv_support_lck_grp);

	hv_support_lck_mtx = lck_mtx_alloc_init(hv_support_lck_grp, LCK_ATTR_NULL);
	assert(hv_support_lck_mtx);
}

/* returns true if hv_support is available on this machine */
int
hv_get_support(void)
{
	return hv_support_available;
}

/* associate an hv object with the current task */
void
hv_set_task_target(void *target)
{
	current_task()->hv_task_target = target;
}

/* associate an hv object with the current thread */
void
hv_set_thread_target(void *target)
{
	current_thread()->hv_thread_target = target;
}

/* get hv object associated with the current task */
void*
hv_get_task_target(void)
{
	return current_task()->hv_task_target;
}

/* get hv object associated with the current thread */
void*
hv_get_thread_target(void)
{
	return current_thread()->hv_thread_target;
}

/* test if a given thread state may be volatile between dispatch
 *  and preemption */
int
hv_get_volatile_state(hv_volatile_state_t state)
{
	int is_volatile = 0;

#if (defined(__x86_64__))
	if (state == HV_DEBUG_STATE) {
		is_volatile = (current_thread()->machine.ids != NULL);
	}
#endif

	return is_volatile;
}

/* register a list of trap handlers for the hv_*_trap syscalls */
kern_return_t
hv_set_traps(hv_trap_type_t trap_type, const hv_trap_t *traps,
    unsigned trap_count)
{
	hv_trap_table_t *trap_table = &hv_trap_table[trap_type];
	kern_return_t kr = KERN_FAILURE;

	lck_mtx_lock(hv_support_lck_mtx);
	if (trap_table->trap_count == 0) {
		trap_table->traps = traps;
		OSMemoryBarrier();
		trap_table->trap_count = trap_count;
		kr = KERN_SUCCESS;
	}
	lck_mtx_unlock(hv_support_lck_mtx);

	return kr;
}

/* release hv_*_trap traps */
void
hv_release_traps(hv_trap_type_t trap_type)
{
	hv_trap_table_t *trap_table = &hv_trap_table[trap_type];

	lck_mtx_lock(hv_support_lck_mtx);
	trap_table->trap_count = 0;
	OSMemoryBarrier();
	trap_table->traps = NULL;
	lck_mtx_unlock(hv_support_lck_mtx);
}

/* register callbacks for certain task/thread events for tasks/threads with
 *  associated hv objects */
kern_return_t
hv_set_callbacks(hv_callbacks_t callbacks)
{
	kern_return_t kr = KERN_FAILURE;

	lck_mtx_lock(hv_support_lck_mtx);
	if (hv_callbacks_enabled == 0) {
		hv_callbacks = callbacks;
		hv_callbacks_enabled = 1;
		kr = KERN_SUCCESS;
	}
	lck_mtx_unlock(hv_support_lck_mtx);

	return kr;
}

/* release callbacks for task/thread events */
void
hv_release_callbacks(void)
{
	lck_mtx_lock(hv_support_lck_mtx);
	hv_callbacks = (hv_callbacks_t) {
		.dispatch = NULL,
		.preempt = NULL,
		.suspend = NULL,
		.thread_destroy = NULL,
		.task_destroy = NULL,
		.volatile_state = NULL,
		.memory_pressure = NULL
	};

	hv_callbacks_enabled = 0;
	lck_mtx_unlock(hv_support_lck_mtx);
}

/* system suspend notification */
void
hv_suspend(void)
{
	if (hv_callbacks_enabled) {
		hv_callbacks.suspend();
	}
}

/* dispatch hv_task_trap/hv_thread_trap syscalls to trap handlers,
 *  fail for invalid index or absence of trap handlers, trap handler is
 *  responsible for validating targets */
#define HV_TRAP_DISPATCH(type, index, target, argument) \
	((__probable(index < hv_trap_table[type].trap_count)) ? \
	        hv_trap_table[type].traps[index](target, argument) \
	                : KERN_INVALID_ARGUMENT)

kern_return_t
hv_task_trap(uint64_t index, uint64_t arg)
{
	return HV_TRAP_DISPATCH(HV_TASK_TRAP, index, hv_get_task_target(), arg);
}

kern_return_t
hv_thread_trap(uint64_t index, uint64_t arg)
{
	return HV_TRAP_DISPATCH(HV_THREAD_TRAP, index, hv_get_thread_target(), arg);
}

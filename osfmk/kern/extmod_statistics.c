/*
 * Copyright (c) 2011 Apple Inc. All rights reserved.
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

#include <mach/mach_types.h>

#include <kern/host.h>
#include <kern/thread.h>
#include <kern/task.h>
#include <kern/extmod_statistics.h>
#include <libkern/OSAtomic.h>

#include <uuid/uuid.h>

/*
 * This code module adds statistics to track when
 * a userspace task is modified by another userspace
 * task. This can facilitate triage of crashes
 * and abberant behavior, which are not expected
 * to occur when the program is running in its
 * qualified environment.
 *
 * We assume the target task has a lifecycle lock
 * that will prevent it from exiting
 * (task_reference/task_reference_internal), which
 * should be called either explicitly, or implicitly
 * via MIG glue code (convert_port_to_task).
 *
 * Host-wide statistics don't asssume any locks are
 * held, and use atomic operations.
 *
 * If we can detect that the kernel proper is
 * performing these operations, don't count
 * it as an external modification. Some of the
 * external modification routines are called
 * by the kernel during thread setup, in which
 * case we rename the userspace entrypoint called
 * by the MIG demuxer to have a "_from_user" suffix.
 */

/* externs for BSD kernel */
extern void fslog_extmod_msgtracer(void *, void *);

/* local routines */
static void
extmod_statistics_log(task_t current_task, task_t target);

void
extmod_statistics_incr_task_for_pid(task_t target)
{
	task_t ctask = current_task();

	if ((ctask == kernel_task) || (target == TASK_NULL)) {
		return;
	}

	if (target != ctask) {
		ctask->extmod_statistics.task_for_pid_caller_count++;
		target->extmod_statistics.task_for_pid_count++;
		OSIncrementAtomic64(&host_extmod_statistics.task_for_pid_count);
	}
}

void
extmod_statistics_incr_thread_set_state(thread_t target)
{
	task_t ctask = current_task();
	task_t ttask;

	if ((ctask == kernel_task) || (target == THREAD_NULL)) {
		return;
	}

	ttask = get_threadtask(target);

	if (ttask == TASK_NULL) {
		return;
	}

	if (ttask != ctask) {
		ctask->extmod_statistics.thread_set_state_caller_count++;
		ttask->extmod_statistics.thread_set_state_count++;
		OSIncrementAtomic64(&host_extmod_statistics.thread_set_state_count);
	}
}

void
extmod_statistics_incr_thread_create(task_t target)
{
	task_t ctask = current_task();

	if ((ctask == kernel_task) || (target == TASK_NULL)) {
		return;
	}

	if (target != ctask) {
		ctask->extmod_statistics.thread_creation_caller_count++;
		target->extmod_statistics.thread_creation_count++;
		OSIncrementAtomic64(&host_extmod_statistics.thread_creation_count);

		extmod_statistics_log(ctask, target);
	}
}

static void
extmod_statistics_log(task_t current_task, task_t target)
{
	void *c_proc;
	void *t_proc;

	c_proc = get_bsdtask_info(current_task);
	t_proc = get_bsdtask_info(target);
	if (c_proc && t_proc) {
		fslog_extmod_msgtracer(c_proc, t_proc);
	}
}

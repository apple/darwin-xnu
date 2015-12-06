/*
 * Copyright (c) 2011 Apple Computer, Inc. All rights reserved.
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
#include <kern/task.h> /* task_ledgers */
#include <kern/thread.h>
#include <kern/ledger.h>

#include <kperf/kperf.h>
#include <kperf/kperf_arch.h>

#include <kperf/buffer.h>
#include <kperf/context.h>
#include <kperf/meminfo.h>

/* collect current memory info */
void
kperf_meminfo_sample(struct meminfo *mi, struct kperf_context *context)
{
	task_t task;
	ledger_amount_t credit, debit;
	uint64_t phys_footprint;
	kern_return_t kr;

	assert(mi);
	assert(context);

	thread_t thread = context->cur_thread;

	BUF_INFO1(PERF_MI_SAMPLE, (uintptr_t)thread_tid(thread));

	task = get_threadtask(thread);

	kr = kperf_get_phys_footprint(task, &phys_footprint);
	if (kr == KERN_SUCCESS) {
		mi->phys_footprint = phys_footprint;
	} else {
		mi->phys_footprint = UINT64_MAX;
	}

	kr = ledger_get_entries(task->ledger, task_ledgers.purgeable_volatile,
	                        &credit, &debit);
	if (kr == KERN_SUCCESS) {
		mi->purgeable_volatile = credit - debit;
	} else {
		mi->purgeable_volatile = UINT64_MAX;
	}

	kr = ledger_get_entries(task->ledger,
	                        task_ledgers.purgeable_volatile_compressed,
	                        &credit, &debit);
	if (kr == KERN_SUCCESS) {
		mi->purgeable_volatile_compressed = credit - debit;
	} else {
		mi->purgeable_volatile_compressed = UINT64_MAX;
	}
}

/* log an existing sample into the buffer */
void
kperf_meminfo_log(struct meminfo *mi)
{
	BUF_DATA3(PERF_MI_DATA, mi->phys_footprint, mi->purgeable_volatile,
	          mi->purgeable_volatile_compressed);
}


/*
 * Copyright (c) 2015 Apple Computer, Inc. All rights reserved.
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

#include <kperf/kperf_arch.h>

kern_return_t
kperf_get_phys_footprint(task_t task, uint64_t *phys_footprint_out)
{
	kern_return_t kr;
	ledger_amount_t credit, debit;
	uint64_t phys_footprint;

	kr = ledger_get_entries(task->ledger, task_ledgers.internal,
	                        &credit, &debit);
	if (kr == KERN_SUCCESS) {
		phys_footprint = credit - debit;
	} else {
		return kr;
	}

	kr = ledger_get_entries(task->ledger, task_ledgers.internal_compressed,
	                        &credit, &debit);
	if (kr == KERN_SUCCESS) {
		phys_footprint += credit - debit;
	} else {
		return kr;
	}

	*phys_footprint_out = phys_footprint;
	return KERN_SUCCESS;
}


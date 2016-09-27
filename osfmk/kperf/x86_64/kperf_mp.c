/*
 * Copyright (c) 2011-2016 Apple Computer, Inc. All rights reserved.
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
#include <kern/processor.h>
#include <i386/mp.h>

#include <kperf/kperf.h>
#include <kperf/kperf_arch.h>
#include <kperf/kperf_timer.h>

void
kperf_mp_broadcast_running(struct kperf_timer *trigger)
{
	int ncpus = machine_info.logical_cpu_max;
	cpumask_t cpu_mask = 0;
	assert(ncpus < 64);

	for (int i = 0; i < ncpus; i++) {
		/* do not IPI processors that are not scheduling threads */
		processor_t processor = cpu_to_processor(i);
		if (processor == PROCESSOR_NULL ||
		    processor->state != PROCESSOR_RUNNING ||
		    processor->active_thread == THREAD_NULL)
		{
			continue;
		}

		/* nor processors that have not responded to the last IPI */
		bool already_pending = atomic_bit_set(&(trigger->pending_cpus), i,
			__ATOMIC_RELAXED);
		if (already_pending) {
#if DEVELOPMENT || DEBUG
			__c11_atomic_fetch_add(&kperf_pending_ipis, 1, __ATOMIC_RELAXED);
#endif
			continue;
		}

		cpu_mask |= cpu_to_cpumask(i);
	}

	mp_cpus_call(cpu_mask, NOSYNC, kperf_ipi_handler, trigger);
}

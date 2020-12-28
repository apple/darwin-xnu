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

#include <i386/mp.h>
#include <mach/mach_types.h>
#include <kern/processor.h>
#include <kperf/buffer.h>
#include <kperf/kperf.h>
#include <kperf/kperf_arch.h>
#include <kperf/kperf_timer.h>
#include <stdatomic.h>

bool
kperf_mp_broadcast_other_running(struct kperf_timer *trigger)
{
	int current_cpu = cpu_number();
	int ncpus = machine_info.logical_cpu_max;
	bool system_only_self = true;
	cpumask_t cpu_mask = 0;

	for (int i = 0; i < ncpus; i++) {
		uint64_t i_bit = UINT64_C(1) << i;
		processor_t processor = cpu_to_processor(i);

		/* do not IPI processors that are not scheduling threads */
		if (processor == PROCESSOR_NULL ||
		    processor->state != PROCESSOR_RUNNING ||
		    processor->active_thread == THREAD_NULL) {
#if DEVELOPMENT || DEBUG
			BUF_VERB(PERF_TM_SKIPPED, i,
			    processor != PROCESSOR_NULL ? processor->state : 0,
			    processor != PROCESSOR_NULL ? processor->active_thread : 0);
#endif /* DEVELOPMENT || DEBUG */
			continue;
		}

		/* don't run the handler on the current processor */
		if (i == current_cpu) {
			system_only_self = false;
			continue;
		}

		/* nor processors that have not responded to the last IPI */
		uint64_t already_pending = atomic_fetch_or_explicit(
			&trigger->pending_cpus, i_bit,
			memory_order_relaxed);
		if (already_pending & i_bit) {
#if DEVELOPMENT || DEBUG
			BUF_VERB(PERF_TM_PENDING, i_bit, already_pending);
			atomic_fetch_add_explicit(&kperf_pending_ipis, 1,
			    memory_order_relaxed);
#endif /* DEVELOPMENT || DEBUG */
			continue;
		}

		cpu_mask |= cpu_to_cpumask(i);
	}

	if (cpu_mask != 0) {
		mp_cpus_call(cpu_mask, NOSYNC, kperf_ipi_handler, trigger);
	}

	return system_only_self;
}

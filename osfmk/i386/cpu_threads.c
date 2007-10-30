/*
 * Copyright (c) 2003-2004 Apple Computer, Inc. All rights reserved.
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
#include <vm/vm_kern.h>
#include <mach/machine.h>
#include <i386/cpu_threads.h>
#include <i386/cpuid.h>
#include <i386/machine_cpu.h>
#include <i386/lock.h>
#include <i386/perfmon.h>

/*
 * Kernel parameter determining whether threads are halted unconditionally
 * in the idle state.  This is the default behavior.
 * See machine_idle() for use.
 */
int idlehalt = 1;


static boolean_t
cpu_is_hyperthreaded(void)
{
	if  (cpuid_features() & CPUID_FEATURE_HTT)
		return (cpuid_info()->cpuid_logical_per_package /
			cpuid_info()->cpuid_cores_per_package) > 1;
	else
		return FALSE;
}

void *
cpu_thread_alloc(int cpu)
{
	int		core_base_cpu;
	int		ret;
	cpu_core_t	*core;

	/*
 	 * Assume that all cpus have the same features.
	 */
	if (cpu_is_hyperthreaded()) {
		/*
		 * Get the cpu number of the base thread in the core.
		 */
		core_base_cpu = cpu_to_core_cpu(cpu);
		cpu_datap(cpu)->cpu_threadtype = CPU_THREADTYPE_INTEL_HTT;
	} else {
		core_base_cpu = cpu;
		cpu_datap(cpu)->cpu_threadtype = CPU_THREADTYPE_NONE;
	}

	core = (cpu_core_t *) cpu_to_core(core_base_cpu);
	if (core == NULL) {
		ret = kmem_alloc(kernel_map,
				 (void *) &core, sizeof(cpu_core_t));
		if (ret != KERN_SUCCESS)
			panic("cpu_thread_alloc() kmem_alloc ret=%d\n", ret);
		bzero((void *) core, sizeof(cpu_core_t));

		core->base_cpu = core_base_cpu;

		atomic_incl((long *) &machine_info.physical_cpu_max, 1);

		/* Allocate performance counter data area (if available) */
		core->pmc = pmc_alloc();
	}
	atomic_incl((long *) &machine_info.logical_cpu_max, 1);

	return (void *) core;
}

void
cpu_thread_init(void)
{
	int		my_cpu = get_cpu_number();
	cpu_core_t	*my_core;

	/*
	 * If we're the boot processor we allocate the core structure here.
	 * Otherwise the core has already been allocated (by the boot cpu).
	 */
	if (my_cpu == master_cpu)
		cpu_to_core(master_cpu) = cpu_thread_alloc(master_cpu);

	my_core = cpu_core();
	if (my_core == NULL)
		panic("cpu_thread_init() no core allocated for cpu %d", my_cpu);

	atomic_incl((long *) &my_core->active_threads, 1);
	atomic_incl((long *) &machine_info.logical_cpu, 1);
	/* Note: cpus are started serially so this isn't as racey as it looks */
	if (my_core->num_threads == 0)
		atomic_incl((long *) &machine_info.physical_cpu, 1);
	atomic_incl((long *) &my_core->num_threads, 1);
}

/*
 * Called for a cpu to halt permanently
 * (as opposed to halting and expecting an interrupt to awaken it).
 */
void
cpu_thread_halt(void)
{
	cpu_core_t	*my_core = cpu_core();

	atomic_decl((long *) &machine_info.logical_cpu, 1);
	atomic_decl((long *) &my_core->active_threads, 1);
	if (atomic_decl_and_test((long *) &my_core->num_threads, 1))
		atomic_decl((long *) &machine_info.physical_cpu, 1);

	cpu_halt();
}

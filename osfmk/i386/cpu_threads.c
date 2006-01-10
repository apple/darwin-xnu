/*
 * Copyright (c) 2003-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
#include <vm/vm_kern.h>
#include <mach/machine.h>
#include <i386/cpu_threads.h>
#include <i386/cpuid.h>
#include <i386/machine_cpu.h>
#include <i386/lock.h>

/*
 * Kernel parameter determining whether threads are halted unconditionally
 * in the idle state.  This is the default behavior.
 * See machine_idle() for use.
 */
int idlehalt = 1;

void
cpu_thread_init(void)
{
	int		my_cpu = get_cpu_number();
	int		my_core_base_cpu;
	int		ret;
	cpu_core_t	*my_core;

	/* Have we initialized already for this cpu? */
	if (cpu_core())
		return;

	if (cpuid_features() & CPUID_FEATURE_HTT) {
		/*
		 * Get the cpu number of the base thread in the core.
		 */
		my_core_base_cpu = cpu_to_core_cpu(my_cpu);
		current_cpu_datap()->cpu_threadtype = CPU_THREADTYPE_INTEL_HTT;
	} else {
		my_core_base_cpu = my_cpu;
		current_cpu_datap()->cpu_threadtype = CPU_THREADTYPE_NONE;
	}

	/*
	 * Allocate the base cpu_core struct if none exists.
	 * Since we could be racing with other threads in the same core,
	 * this needs care without using locks. We allocate a new core
	 * structure and assign it atomically, freeing it if we lost the race.
	 */
	my_core = (cpu_core_t *) cpu_to_core(my_core_base_cpu);
	if (my_core == NULL) {
		cpu_core_t	*new_core;

		ret = kmem_alloc(kernel_map,
				 (void *) &new_core, sizeof(cpu_core_t));
		if (ret != KERN_SUCCESS)
			panic("cpu_thread_init() kmem_alloc ret=%d\n", ret);
		bzero((void *) new_core, sizeof(cpu_core_t));
		new_core->base_cpu = my_core_base_cpu;
		if (atomic_cmpxchg((uint32_t *) &cpu_to_core(my_core_base_cpu),
				    0, (uint32_t) new_core)) {
			atomic_incl((long *) &machine_info.physical_cpu, 1);
			atomic_incl((long *) &machine_info.physical_cpu_max, 1);
		} else {
			kmem_free(kernel_map,
				  (vm_offset_t)new_core, sizeof(cpu_core_t));
		}
		my_core = (cpu_core_t *) cpu_to_core(my_core_base_cpu);
	}

	cpu_to_core(my_cpu) = (struct cpu_core *) my_core;

	atomic_incl((long *) &my_core->active_threads, 1);
	atomic_incl((long *) &my_core->num_threads, 1);
	atomic_incl((long *) &machine_info.logical_cpu, 1);
	atomic_incl((long *) &machine_info.logical_cpu_max, 1);

}

/*
 * Called for a cpu to halt permanently
 * (as opposed to halting and expecting an interrupt to awaken it).
 */
void
cpu_thread_halt(void)
{
	cpu_core_t	*my_core = cpu_core();

	/* Note: don't ever decrement the number of physical processors */
	atomic_decl((long *) &my_core->active_threads, 1);
	atomic_decl((long *) &my_core->num_threads, 1);
	atomic_decl((long *) &machine_info.logical_cpu, 1);

	cpu_halt();
}

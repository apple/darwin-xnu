/*
 * Copyright (c) 2003-2007 Apple Inc. All rights reserved.
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
#include <mach/mach_host.h>

#include <kern/host.h>
#include <kern/processor.h>

#include <i386/cpu_data.h>
#include <i386/machine_routines.h>
#include <i386/perfmon.h>
#include <i386/mp.h>
#include <i386/trap.h>
#include <mach/i386/syscall_sw.h>

#include <chud/chud_xnu.h>

#pragma mark **** cpu enable/disable ****

extern kern_return_t processor_start(processor_t     processor); // osfmk/kern/processor.c
extern kern_return_t processor_exit(processor_t     processor); // osfmk/kern/processor.c

__private_extern__
kern_return_t chudxnu_enable_cpu(int cpu, boolean_t enable)
{
    chudxnu_unbind_thread(current_thread(), 0);
	
    if(cpu < 0 || (unsigned int)cpu >= real_ncpus) // sanity check
        return KERN_FAILURE;
	
	if((cpu_data_ptr[cpu] != NULL) && cpu != master_cpu) {
		processor_t processor = cpu_to_processor(cpu);
		
		if(processor == master_processor) // don't mess with the boot processor
			return KERN_FAILURE;

        if(enable) {
            return processor_start(processor);
        } else {
            return processor_exit(processor);
        }
    }
    return KERN_FAILURE;
}

#pragma mark **** perfmon facility ****

__private_extern__ kern_return_t
chudxnu_perfmon_acquire_facility(task_t task)
{
    return pmc_acquire(task);
}

__private_extern__ kern_return_t
chudxnu_perfmon_release_facility(task_t task)
{
    return pmc_release(task);
}

#pragma mark **** interrupt counters ****

__private_extern__ kern_return_t
chudxnu_get_cpu_interrupt_counters(int cpu, rupt_counters_t *rupts)
{
    if(cpu < 0 || (unsigned int)cpu >= real_ncpus) { // sanity check
        return KERN_FAILURE;
    }

    if(rupts) {
        boolean_t oldlevel = ml_set_interrupts_enabled(FALSE);
        cpu_data_t	*per_proc;

        per_proc = cpu_data_ptr[cpu];
		// For now, we'll call an NMI a 'reset' interrupt
        rupts->hwResets = per_proc->cpu_hwIntCnt[T_NMI];
        rupts->hwMachineChecks = per_proc->cpu_hwIntCnt[T_MACHINE_CHECK];
        rupts->hwDSIs = 0;
        rupts->hwISIs = 0;
		// we could accumulate 0x20-0x7f, but that'd likely overflow...
        rupts->hwExternals = 0;
		// This appears to be wrong.
        rupts->hwAlignments = 0; //per_proc->cpu_hwIntCnt[0x11];
        rupts->hwPrograms = 0;
        rupts->hwFloatPointUnavailable = per_proc->cpu_hwIntCnt[T_NO_FPU];
		// osfmk/i386/mp.h
        rupts->hwDecrementers = per_proc->cpu_hwIntCnt[LAPIC_VECTOR(TIMER)];
		// LAPIC_ERROR == IO ERROR??
        rupts->hwIOErrors = per_proc->cpu_hwIntCnt[LAPIC_VECTOR(ERROR)];

		// accumulate all system call types
		// osfmk/mach/i386/syscall_sw.h
        rupts->hwSystemCalls = per_proc->cpu_hwIntCnt[UNIX_INT]  +
			per_proc->cpu_hwIntCnt[MACH_INT] +
			per_proc->cpu_hwIntCnt[MACHDEP_INT] +
			per_proc->cpu_hwIntCnt[DIAG_INT];

        rupts->hwTraces = per_proc->cpu_hwIntCnt[T_DEBUG]; // single steps == traces??
        rupts->hwFloatingPointAssists = 0;
		// osfmk/i386/mp.h
        rupts->hwPerformanceMonitors =
			per_proc->cpu_hwIntCnt[LAPIC_VECTOR(PERFCNT)];
        rupts->hwAltivecs = 0;
        rupts->hwInstBreakpoints = per_proc->cpu_hwIntCnt[T_INT3];
        rupts->hwSystemManagements = 0;
        rupts->hwAltivecAssists = 0;
        rupts->hwThermal = per_proc->cpu_hwIntCnt[LAPIC_VECTOR(THERMAL)];
        rupts->hwSoftPatches = 0;
        rupts->hwMaintenances = 0;
		// Watchpoint == instrumentation
		rupts->hwInstrumentations = per_proc->cpu_hwIntCnt[T_WATCHPOINT]; 

        ml_set_interrupts_enabled(oldlevel);
        return KERN_SUCCESS;
    } else {
        return KERN_FAILURE;
    }
}

__private_extern__ kern_return_t
chudxnu_clear_cpu_interrupt_counters(int cpu)
{
    if(cpu < 0 || (unsigned int)cpu >= real_ncpus) { // sanity check
        return KERN_FAILURE;
    }
	cpu_data_t	*per_proc;

	per_proc = cpu_data_ptr[cpu];

	bzero((char *)per_proc->cpu_hwIntCnt, sizeof(uint32_t)*256);

    return KERN_SUCCESS;
}

#pragma mark *** deprecated ***

//DEPRECATED
__private_extern__ kern_return_t
chudxnu_get_cpu_rupt_counters(int cpu, rupt_counters_t *rupts)
{
	return chudxnu_get_cpu_interrupt_counters(cpu, rupts);
}

//DEPRECATED
__private_extern__ kern_return_t
chudxnu_clear_cpu_rupt_counters(int cpu)
{
	return chudxnu_clear_cpu_interrupt_counters(cpu);
}

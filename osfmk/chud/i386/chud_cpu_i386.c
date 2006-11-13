/*
 * Copyright (c) 2003-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
#include <mach/mach_types.h>
#include <mach/mach_host.h>

#include <kern/host.h>
#include <kern/processor.h>

#include <i386/cpu_data.h>
#include <i386/machine_routines.h>
#include <i386/perfmon.h>
#include <i386/mp.h>

#include <chud/chud_xnu.h>

#pragma mark **** cpu enable/disable ****

extern kern_return_t processor_start(processor_t     processor); // osfmk/kern/processor.c
extern kern_return_t processor_exit(processor_t     processor); // osfmk/kern/processor.c

__private_extern__
kern_return_t chudxnu_enable_cpu(int cpu, boolean_t enable)
{
    chudxnu_unbind_thread(current_thread());
	
    if(cpu < 0 || (unsigned int)cpu >= real_ncpus) // sanity check
        return KERN_FAILURE;
	
	if((cpu_data_ptr[cpu] != NULL) && cpu != master_cpu) {
		processor_t processor = cpu_to_processor(cpu);
		
		if(processor == master_processor) // don't mess with the boot processor
			return KERN_FAILURE;

        if(enable) {
			// make sure it isn't already running
			if(processor->state == PROCESSOR_OFF_LINE || 
				processor->state == PROCESSOR_SHUTDOWN) {
				return processor_start(processor);
			}
			return KERN_SUCCESS;	// it's already running
        } else {
			// make sure it hasn't already exited
			if(processor->state != PROCESSOR_OFF_LINE &&
				processor->state != PROCESSOR_SHUTDOWN) {
				return processor_exit(processor);
			}
			return KERN_SUCCESS;
        }
    }
    return KERN_FAILURE;
}

#pragma mark **** cache flush ****

__private_extern__
void
chudxnu_flush_caches(void)
{
/* XXX */
}

__private_extern__
void
chudxnu_enable_caches(boolean_t enable)
{
#pragma unused (enable)
/* XXX */
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

#pragma mark **** rupt counters ****

__private_extern__ kern_return_t
chudxnu_get_cpu_rupt_counters(int cpu, rupt_counters_t *rupts)
{
    if(cpu < 0 || (unsigned int)cpu >= real_ncpus) { // sanity check
        return KERN_FAILURE;
    }

    if(rupts) {
        boolean_t oldlevel = ml_set_interrupts_enabled(FALSE);
        cpu_data_t	*per_proc;

        per_proc = cpu_data_ptr[cpu];
        rupts->hwResets = 0;
        rupts->hwMachineChecks = 0;
        rupts->hwDSIs = 0;
        rupts->hwISIs = 0;
        rupts->hwExternals = 0;
        rupts->hwAlignments = 0;
        rupts->hwPrograms = 0;
        rupts->hwFloatPointUnavailable = 0;
        rupts->hwDecrementers = 0;
        rupts->hwIOErrors = 0;
        rupts->hwSystemCalls = 0;
        rupts->hwTraces = 0;
        rupts->hwFloatingPointAssists = 0;
        rupts->hwPerformanceMonitors = 0;
        rupts->hwAltivecs = 0;
        rupts->hwInstBreakpoints = 0;
        rupts->hwSystemManagements = 0;
        rupts->hwAltivecAssists = 0;
        rupts->hwThermal = 0;
        rupts->hwSoftPatches = 0;
        rupts->hwMaintenances = 0;
        rupts->hwInstrumentations = 0;

        ml_set_interrupts_enabled(oldlevel);
        return KERN_SUCCESS;
    } else {
        return KERN_FAILURE;
    }
}

__private_extern__ kern_return_t
chudxnu_clear_cpu_rupt_counters(int cpu)
{
    if(cpu < 0 || (unsigned int)cpu >= real_ncpus) { // sanity check
        return KERN_FAILURE;
    }

/*
 * XXX
 *    bzero((char *)&(cpu_data_ptr[cpu]->hwCtrs), sizeof(struct hwCtrs));
 */
    return KERN_SUCCESS;
}

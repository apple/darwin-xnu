/*
 * Copyright (c) 2008-2010 Apple Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */

#include <mach/mach_types.h>
#include <mach/kern_return.h>

#include <i386/lapic.h>
#include <i386/cpuid.h>
#include <i386/proc_reg.h>
#include <i386/machine_cpu.h>
#include <i386/misc_protos.h>
#include <i386/mp.h>
#include <i386/postcode.h>
#include <i386/cpu_threads.h>
#include <i386/machine_routines.h>
#include <i386/tsc.h>

#include <sys/kdebug.h>

/* Base vector for local APIC interrupt sources */
int lapic_interrupt_base = LAPIC_DEFAULT_INTERRUPT_BASE;

int		lapic_to_cpu[MAX_LAPICIDS];
int		cpu_to_lapic[MAX_CPUS];

void
lapic_cpu_map_init(void)
{
	int	i;

	for (i = 0; i < MAX_CPUS; i++)
		cpu_to_lapic[i] = -1;
	for (i = 0; i < MAX_LAPICIDS; i++)
		lapic_to_cpu[i] = -1;
}

void
lapic_cpu_map(int apic_id, int cpu)
{
	assert(apic_id < MAX_LAPICIDS);
	assert(cpu < MAX_CPUS);
	cpu_to_lapic[cpu] = apic_id;
	lapic_to_cpu[apic_id] = cpu;
}

/*
 * Retrieve the local apic ID a cpu.
 *
 * Returns the local apic ID for the given processor.
 * If the processor does not exist or apic not configured, returns -1.
 */

uint32_t
ml_get_apicid(uint32_t cpu)
{
	if(cpu >= (uint32_t)MAX_CPUS)
		return 0xFFFFFFFF;	/* Return -1 if cpu too big */
	
	/* Return the apic ID (or -1 if not configured) */
	return (uint32_t)cpu_to_lapic[cpu];

}

uint32_t
ml_get_cpuid(uint32_t lapic_index)
{
	if(lapic_index >= (uint32_t)MAX_LAPICIDS)
		return 0xFFFFFFFF;	/* Return -1 if cpu too big */
	
	/* Return the cpu ID (or -1 if not configured) */
	return (uint32_t)lapic_to_cpu[lapic_index];

}

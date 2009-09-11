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
#include <kern/cpu_data.h>
#include <kern/machine.h>
#include <machine/machine_routines.h>

#include <chud/chud_xnu.h>

#if 0
#pragma mark **** cpu count ****
#endif

__private_extern__ int 
chudxnu_logical_cpu_count(void)
{
	return machine_info.logical_cpu_max;
}

__private_extern__ int
chudxnu_phys_cpu_count(void)
{
    host_basic_info_data_t hinfo;
    kern_return_t kr;
    mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;

    kr = host_info(host_self(), HOST_BASIC_INFO, (integer_t *)&hinfo, &count);
    if(kr == KERN_SUCCESS) {
        return hinfo.max_cpus;
    } else {
        return 1;  // fall back to 1, 0 doesn't make sense at all
    }
}

__private_extern__ int
chudxnu_cpu_number(void)
{
    return cpu_number();
}

#if 0
#pragma mark **** interrupts enable/disable ****
#endif

__private_extern__ boolean_t
chudxnu_get_interrupts_enabled(void)
{
    return ml_get_interrupts_enabled();
}

__private_extern__ boolean_t
chudxnu_set_interrupts_enabled(boolean_t enable)
{
    return ml_set_interrupts_enabled(enable);
}

__private_extern__ boolean_t
chudxnu_at_interrupt_context(void)
{
    return ml_at_interrupt_context();
}

__private_extern__ void
chudxnu_cause_interrupt(void)
{
    ml_cause_interrupt();
}

#if 0
#pragma mark **** preemption enable/disable ****
#endif

__private_extern__ void
chudxnu_enable_preemption(void)
{
	enable_preemption();
}

__private_extern__ void
chudxnu_disable_preemption(void)
{
	disable_preemption();
}

__private_extern__ int
chudxnu_get_preemption_level(void)
{
	return get_preemption_level();
}


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
#include <kern/cpu_data.h>

#include <machine/machine_routines.h>

#include <chud/chud_xnu.h>

#pragma mark **** cpu count ****

__private_extern__ int
chudxnu_avail_cpu_count(void)
{
    host_basic_info_data_t hinfo;
    kern_return_t kr;
    mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;

    kr = host_info(host_self(), HOST_BASIC_INFO, (integer_t *)&hinfo, &count);
    if(kr == KERN_SUCCESS) {
        return hinfo.avail_cpus;
    } else {
        return 0;
    }
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
        return 0;
    }
}

__private_extern__
int chudxnu_cpu_number(void)
{
    return cpu_number();
}

#pragma mark **** branch trace buffer ****

extern int pc_trace_buf[1024];

__private_extern__ uint32_t *
chudxnu_get_branch_trace_buffer(uint32_t *entries)
{
    if(entries) {
        *entries = sizeof(pc_trace_buf)/sizeof(int);
    }
    return pc_trace_buf;
}

#pragma mark **** interrupts enable/disable ****

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

#pragma mark **** preemption enable/disable ****

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

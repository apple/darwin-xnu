/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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

#include <ppc/chud/chud_spr.h>
#include <ppc/chud/chud_xnu.h>
#include <ppc/chud/chud_cpu_asm.h>
#include <kern/processor.h>
#include <ppc/machine_routines.h>
#include <ppc/exception.h>
#include <ppc/proc_reg.h>
#include <ppc/Diagnostics.h>

__private_extern__
int chudxnu_avail_cpu_count(void)
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

__private_extern__
int chudxnu_phys_cpu_count(void)
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

__private_extern__
kern_return_t chudxnu_enable_cpu(int cpu, boolean_t enable)
{
    chudxnu_unbind_current_thread();

    if(cpu<0 || cpu>=chudxnu_phys_cpu_count()) { // check sanity of cpu argument
        return KERN_FAILURE;
    }

    if(processor_ptr[cpu]!=PROCESSOR_NULL && processor_ptr[cpu]!=master_processor) {
        if(enable) {
            return processor_start(processor_ptr[cpu]);
        } else {
            return processor_exit(processor_ptr[cpu]);
        }
    }
    return KERN_FAILURE;
}

__private_extern__
kern_return_t chudxnu_enable_cpu_nap(int cpu, boolean_t enable)
{
    if(cpu<0 || cpu>=chudxnu_phys_cpu_count()) { // check sanity of cpu argument
        return KERN_FAILURE;
    }

    if(processor_ptr[cpu]!=PROCESSOR_NULL) {
        ml_enable_nap(cpu, enable);
        return KERN_SUCCESS;
    }

    return KERN_FAILURE;
}

__private_extern__
boolean_t chudxnu_cpu_nap_enabled(int cpu)
{
    boolean_t prev;

    if(cpu<0 || cpu>=chudxnu_phys_cpu_count()) { // check sanity of cpu argument
        cpu = 0;
    }

    prev = ml_enable_nap(cpu, TRUE);
    ml_enable_nap(cpu, prev);

    return prev;
}

__private_extern__
kern_return_t chudxnu_set_shadowed_spr(int cpu, int spr, uint32_t val)
{
    cpu_subtype_t cpu_subtype;
    uint32_t available;
    kern_return_t retval = KERN_FAILURE;

    if(cpu<0 || cpu>=chudxnu_phys_cpu_count()) { // check sanity of cpu argument
        return KERN_FAILURE;
    }

    chudxnu_bind_current_thread(cpu);

    available = per_proc_info[cpu].pf.Available;
    cpu_subtype = machine_slot[cpu].cpu_subtype;

    if(spr==chud_750_l2cr) {
        switch(cpu_subtype) {
        case CPU_SUBTYPE_POWERPC_750:
        case CPU_SUBTYPE_POWERPC_7400:
        case CPU_SUBTYPE_POWERPC_7450:
            if(available & pfL2) {
//               int enable = (val & 0x80000000) ? TRUE : FALSE;
//               if(enable) {
//                 per_proc_info[cpu].pf.l2cr = val;
//              } else {
//                 per_proc_info[cpu].pf.l2cr = 0;
//              }
                per_proc_info[cpu].pf.l2cr = val;
                cacheInit();
 //             mtspr(l2cr, per_proc_info[cpu].pf.l2cr); // XXXXXXX why is this necessary? XXXXXXX
                retval = KERN_SUCCESS;
            } else {
                retval = KERN_FAILURE;
            }
            break;
        default:
            retval = KERN_INVALID_ARGUMENT;
            break;
        }
    }
    else if(spr==chud_7450_l3cr) {
        switch(cpu_subtype) {
        case CPU_SUBTYPE_POWERPC_7450:
            if(available & pfL3) {
                int enable = (val & 0x80000000) ? TRUE : FALSE;
                if(enable) {
                    per_proc_info[cpu].pf.l3cr = val;
                } else {
                    per_proc_info[cpu].pf.l3cr = 0;
                }
                cacheInit();
                retval = KERN_SUCCESS;
            } else {
                retval = KERN_FAILURE;
            }
            break;
        default:
            retval = KERN_INVALID_ARGUMENT;
            break;
        }
    }
    else if(spr==chud_750_hid0) {
        switch(cpu_subtype) {
        case CPU_SUBTYPE_POWERPC_750:
            cacheInit();
            cacheDisable(); /* disable caches */
            __asm__ volatile ("mtspr %0, %1" : : "n" (chud_750_hid0), "r" (val));
            per_proc_info[cpu].pf.pfHID0 = val;
            cacheInit(); /* reenable caches */
            retval = KERN_SUCCESS;
            break;
        case CPU_SUBTYPE_POWERPC_7400:
        case CPU_SUBTYPE_POWERPC_7450:
            __asm__ volatile ("mtspr %0, %1" : : "n" (chud_750_hid0), "r" (val));
            per_proc_info[cpu].pf.pfHID0 = val;
            retval = KERN_SUCCESS;
            break;
        default:
            retval = KERN_INVALID_ARGUMENT;
            break;
        }
    }
    else if(spr==chud_750_hid1) {
        switch(cpu_subtype) {
        case CPU_SUBTYPE_POWERPC_750:
        case CPU_SUBTYPE_POWERPC_7400:
        case CPU_SUBTYPE_POWERPC_7450:
            __asm__ volatile ("mtspr %0, %1" : : "n" (chud_750_hid1), "r" (val));
            per_proc_info[cpu].pf.pfHID1 = val;
            retval = KERN_SUCCESS;
            break;
        default:
            retval = KERN_INVALID_ARGUMENT;
            break;
        }
    }
    else if(spr==chud_750fx_hid2 && cpu_subtype==CPU_SUBTYPE_POWERPC_750) {
        __asm__ volatile ("mtspr %0, %1" : : "n" (chud_750fx_hid2), "r" (val));
        per_proc_info[cpu].pf.pfHID2 = val;
        retval = KERN_SUCCESS;
    }
    else if(spr==chud_7400_msscr0 && (cpu_subtype==CPU_SUBTYPE_POWERPC_7400 || cpu_subtype==CPU_SUBTYPE_POWERPC_7450)) {
        __asm__ volatile ("mtspr %0, %1" : : "n" (chud_7400_msscr0), "r" (val));
        per_proc_info[cpu].pf.pfMSSCR0 = val;
        retval = KERN_SUCCESS;
    }
    else if(spr==chud_7400_msscr1 && cpu_subtype==CPU_SUBTYPE_POWERPC_7400 || cpu_subtype==CPU_SUBTYPE_POWERPC_7450) { // called msssr0 on 7450
        __asm__ volatile ("mtspr %0, %1" : : "n" (chud_7400_msscr1), "r" (val));
        per_proc_info[cpu].pf.pfMSSCR1 = val;
        retval = KERN_SUCCESS;
    }
    else if(spr==chud_7450_ldstcr && cpu_subtype==CPU_SUBTYPE_POWERPC_7450) {
        __asm__ volatile ("mtspr %0, %1" : : "n" (chud_7450_ldstcr), "r" (val));
        per_proc_info[cpu].pf.pfLDSTCR = val;
        retval = KERN_SUCCESS;
    }
    else if(spr==chud_7450_ictrl && cpu_subtype==CPU_SUBTYPE_POWERPC_7450) {
        __asm__ volatile ("mtspr %0, %1" : : "n" (chud_7450_ictrl), "r" (val));
        per_proc_info[cpu].pf.pfICTRL = val;
        retval = KERN_SUCCESS;
    } else {
        retval = KERN_INVALID_ARGUMENT;
    }

    chudxnu_unbind_current_thread();
    return retval;
}

__private_extern__
kern_return_t chudxnu_set_shadowed_spr64(int cpu, int spr, uint64_t val)
{
    cpu_subtype_t cpu_subtype;
    kern_return_t retval = KERN_FAILURE;

    if(cpu<0 || cpu>=chudxnu_phys_cpu_count()) { // check sanity of cpu argument
        return KERN_FAILURE;
    }

    chudxnu_bind_current_thread(cpu);

    cpu_subtype = machine_slot[cpu].cpu_subtype;

    if(spr==chud_970_hid0) {
        switch(cpu_subtype) {
        case CPU_SUBTYPE_POWERPC_970:
            chudxnu_mthid0_64(&val);
            per_proc_info[cpu].pf.pfHID0 = val;
            retval = KERN_SUCCESS;
            break;
        default:
            retval = KERN_INVALID_ARGUMENT;
            break;
        }
    }
    else if(spr==chud_970_hid1) {
        switch(cpu_subtype) {
        case CPU_SUBTYPE_POWERPC_970:
            chudxnu_mthid1_64(&val);
            per_proc_info[cpu].pf.pfHID1 = val;
            retval = KERN_SUCCESS;
            break;
        default:
            retval = KERN_INVALID_ARGUMENT;
            break;
        }
    }
    else if(spr==chud_970_hid4) {
        switch(cpu_subtype) {
        case CPU_SUBTYPE_POWERPC_970:
            chudxnu_mthid4_64(&val);
            per_proc_info[cpu].pf.pfHID4 = val;
            retval = KERN_SUCCESS;
            break;
        default:
            retval = KERN_INVALID_ARGUMENT;
            break;
        }
    }
    else if(spr==chud_970_hid5) {
        switch(cpu_subtype) {
        case CPU_SUBTYPE_POWERPC_970:
            chudxnu_mthid5_64(&val);
            per_proc_info[cpu].pf.pfHID5 = val;
            retval = KERN_SUCCESS;
            break;
        default:
            retval = KERN_INVALID_ARGUMENT;
            break;
        }
    } else {
        retval = KERN_INVALID_ARGUMENT;
    }

    chudxnu_unbind_current_thread();

    return retval;
}

__private_extern__
uint32_t chudxnu_get_orig_cpu_l2cr(int cpu)
{
    if(cpu<0 || cpu>=chudxnu_phys_cpu_count()) { // check sanity of cpu argument
        cpu = 0;
    }
    return per_proc_info[cpu].pf.l2crOriginal;
}

__private_extern__
uint32_t chudxnu_get_orig_cpu_l3cr(int cpu)
{
    if(cpu<0 || cpu>=chudxnu_phys_cpu_count()) { // check sanity of cpu argument
        cpu = 0;
    }
    return per_proc_info[cpu].pf.l3crOriginal;
}

__private_extern__
void chudxnu_flush_caches(void)
{
    cacheInit();
}

__private_extern__
void chudxnu_enable_caches(boolean_t enable)
{
    if(!enable) {
        cacheInit();
        cacheDisable();
    } else {
        cacheInit();
    }
}

__private_extern__
kern_return_t chudxnu_perfmon_acquire_facility(task_t task)
{
    return perfmon_acquire_facility(task);
}

__private_extern__
kern_return_t chudxnu_perfmon_release_facility(task_t task)
{
    return perfmon_release_facility(task);
}

__private_extern__
uint32_t * chudxnu_get_branch_trace_buffer(uint32_t *entries)
{
    extern int pc_trace_buf[1024];
    if(entries) {
        *entries = sizeof(pc_trace_buf)/sizeof(int);
    }
    return pc_trace_buf;
}

__private_extern__
boolean_t chudxnu_get_interrupts_enabled(void)
{
    return ml_get_interrupts_enabled();
}

__private_extern__
boolean_t chudxnu_set_interrupts_enabled(boolean_t enable)
{
    return ml_set_interrupts_enabled(enable);
}

__private_extern__
boolean_t chudxnu_at_interrupt_context(void)
{
    return ml_at_interrupt_context();
}

__private_extern__
void chudxnu_cause_interrupt(void)
{
    ml_cause_interrupt();
}

__private_extern__
kern_return_t chudxnu_get_cpu_rupt_counters(int cpu, rupt_counters_t *rupts)
{
    if(cpu<0 || cpu>=chudxnu_phys_cpu_count()) { // check sanity of cpu argument
        return KERN_FAILURE;
    }

    if(rupts) {
        boolean_t oldlevel = ml_set_interrupts_enabled(FALSE);

        rupts->hwResets = per_proc_info[cpu].hwCtr.hwResets;
        rupts->hwMachineChecks = per_proc_info[cpu].hwCtr.hwMachineChecks;
        rupts->hwDSIs = per_proc_info[cpu].hwCtr.hwDSIs;
        rupts->hwISIs = per_proc_info[cpu].hwCtr.hwISIs;
        rupts->hwExternals = per_proc_info[cpu].hwCtr.hwExternals;
        rupts->hwAlignments = per_proc_info[cpu].hwCtr.hwAlignments;
        rupts->hwPrograms = per_proc_info[cpu].hwCtr.hwPrograms;
        rupts->hwFloatPointUnavailable = per_proc_info[cpu].hwCtr.hwFloatPointUnavailable;
        rupts->hwDecrementers = per_proc_info[cpu].hwCtr.hwDecrementers;
        rupts->hwIOErrors = per_proc_info[cpu].hwCtr.hwIOErrors;
        rupts->hwSystemCalls = per_proc_info[cpu].hwCtr.hwSystemCalls;
        rupts->hwTraces = per_proc_info[cpu].hwCtr.hwTraces;
        rupts->hwFloatingPointAssists = per_proc_info[cpu].hwCtr.hwFloatingPointAssists;
        rupts->hwPerformanceMonitors = per_proc_info[cpu].hwCtr.hwPerformanceMonitors;
        rupts->hwAltivecs = per_proc_info[cpu].hwCtr.hwAltivecs;
        rupts->hwInstBreakpoints = per_proc_info[cpu].hwCtr.hwInstBreakpoints;
        rupts->hwSystemManagements = per_proc_info[cpu].hwCtr.hwSystemManagements;
        rupts->hwAltivecAssists = per_proc_info[cpu].hwCtr.hwAltivecAssists;
        rupts->hwThermal = per_proc_info[cpu].hwCtr.hwThermal;
        rupts->hwSoftPatches = per_proc_info[cpu].hwCtr.hwSoftPatches;
        rupts->hwMaintenances = per_proc_info[cpu].hwCtr.hwMaintenances;
        rupts->hwInstrumentations = per_proc_info[cpu].hwCtr.hwInstrumentations;

        ml_set_interrupts_enabled(oldlevel);
        return KERN_SUCCESS;
    } else {
        return KERN_FAILURE;
    }
}

__private_extern__
kern_return_t chudxnu_clear_cpu_rupt_counters(int cpu)
{
    if(cpu<0 || cpu>=chudxnu_phys_cpu_count()) { // check sanity of cpu argument
        return KERN_FAILURE;
    }

    bzero(&(per_proc_info[cpu].hwCtr), sizeof(struct hwCtrs));
    return KERN_SUCCESS;
}

__private_extern__
kern_return_t chudxnu_passup_alignment_exceptions(boolean_t enable)
{
    if(enable) {
        dgWork.dgFlags |= enaNotifyEM;
    } else {
        dgWork.dgFlags &= ~enaNotifyEM;
    }
}

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
#include <mach/mach_types.h>
#include <mach/mach_host.h>

#include <kern/host.h>
#include <kern/processor.h>

#include <chud/chud_xnu.h>
#include <chud/ppc/chud_spr.h>
#include <chud/ppc/chud_cpu_asm.h>
#include <ppc/machine_routines.h>
#include <ppc/exception.h>
#include <ppc/hw_perfmon.h>
#include <ppc/Diagnostics.h>

// the macros in proc_reg.h fail with "expression must be absolute"

#undef mtsprg
#undef mfsprg
#define mtsprg(n, reg)  __asm__ volatile("mtsprg  " # n ", %0" : : "r" (reg))
#define mfsprg(reg, n)  __asm__ volatile("mfsprg  %0, " # n : "=r" (reg))

#undef mtspr
#undef mfspr
#define mtspr(spr, reg)   __asm__ volatile ("mtspr %0, %1" : : "n" (spr), "r" (reg))
#define mfspr(reg, spr)  __asm__ volatile("mfspr %0, %1" : "=r" (reg) : "n" (spr));
     
#undef mtsr
#undef mfsr
#define mtsr(sr, reg) __asm__ volatile("sync" "@" "mtsr sr%0, %1 " "@" "isync" : : "i" (sr), "r" (reg)); 
#define mfsr(reg, sr) __asm__ volatile("mfsr %0, sr%1" : "=r" (reg) : "i" (sr));

#pragma mark **** cpu enable/disable ****

extern kern_return_t processor_start(processor_t     processor); // osfmk/kern/processor.c
extern kern_return_t processor_exit(processor_t     processor); // osfmk/kern/processor.c

__private_extern__
kern_return_t chudxnu_enable_cpu(int cpu, boolean_t enable)
{
    chudxnu_unbind_thread(current_thread());

    if(cpu<0 || cpu>=chudxnu_phys_cpu_count()) { // check sanity of cpu argument
        return KERN_FAILURE;
    }

    if((PerProcTable[cpu].ppe_vaddr != (struct per_proc_info *)NULL)
        && cpu != master_cpu) {
		processor_t		processor = cpu_to_processor(cpu);

        if(enable) {
            return processor_start(processor);
        } else {
            return processor_exit(processor);
        }
    }
    return KERN_FAILURE;
}

#pragma mark **** nap ****

__private_extern__
kern_return_t chudxnu_enable_cpu_nap(int cpu, boolean_t enable)
{
    if(cpu<0 || cpu>=chudxnu_phys_cpu_count()) { // check sanity of cpu argument
        return KERN_FAILURE;
    }

    if(PerProcTable[cpu].ppe_vaddr != (struct per_proc_info *)NULL) {
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

#pragma mark **** shadowed spr ****

__private_extern__
kern_return_t chudxnu_set_shadowed_spr(int cpu, int spr, uint32_t val)
{
    cpu_subtype_t target_cpu_subtype;
    uint32_t available;
    kern_return_t retval = KERN_FAILURE;
    struct per_proc_info *per_proc;
    boolean_t didBind = FALSE;

    if(cpu>=chudxnu_phys_cpu_count()) { // check sanity of cpu argument
        return KERN_FAILURE;
    }

    if(cpu<0) { // cpu<0 means don't bind (current cpu)
		cpu = chudxnu_cpu_number();
		didBind = FALSE;
    } else {
    chudxnu_bind_thread(current_thread(), cpu);
		didBind = TRUE;
    }

    per_proc = PerProcTable[cpu].ppe_vaddr;
    available = per_proc->pf.Available;
    target_cpu_subtype = per_proc->cpu_subtype;

    if(spr==chud_750_l2cr) {
        switch(target_cpu_subtype) {
        case CPU_SUBTYPE_POWERPC_750:
        case CPU_SUBTYPE_POWERPC_7400:
        case CPU_SUBTYPE_POWERPC_7450:
            if(available & pfL2) {
//               int enable = (val & 0x80000000) ? TRUE : FALSE;
//               if(enable) {
//                 per_proc->pf.l2cr = val;
//              } else {
//                 per_proc->pf.l2cr = 0;
//              }
                per_proc->pf.l2cr = val;
                cacheInit();
 //             mtspr(l2cr, per_proc->pf.l2cr); // XXXXXXX why is this necessary? XXXXXXX
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
        switch(target_cpu_subtype) {
        case CPU_SUBTYPE_POWERPC_7450:
            if(available & pfL3) {
                int enable = (val & 0x80000000) ? TRUE : FALSE;
                if(enable) {
                    per_proc->pf.l3cr = val;
                } else {
                    per_proc->pf.l3cr = 0;
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
        switch(target_cpu_subtype) {
        case CPU_SUBTYPE_POWERPC_750:
            cacheInit();
            cacheDisable(); /* disable caches */
	    mtspr(chud_750_hid0, val);
            per_proc->pf.pfHID0 = val;
            cacheInit(); /* reenable caches */
            retval = KERN_SUCCESS;
            break;
        case CPU_SUBTYPE_POWERPC_7400:
        case CPU_SUBTYPE_POWERPC_7450:
	    mtspr(chud_750_hid0, val);
            per_proc->pf.pfHID0 = val;
            retval = KERN_SUCCESS;
            break;
        default:
            retval = KERN_INVALID_ARGUMENT;
            break;
        }
    }
    else if(spr==chud_750_hid1) {
        switch(target_cpu_subtype) {
        case CPU_SUBTYPE_POWERPC_750:
        case CPU_SUBTYPE_POWERPC_7400:
        case CPU_SUBTYPE_POWERPC_7450:
	    mtspr(chud_750_hid1, val);
            per_proc->pf.pfHID1 = val;
            retval = KERN_SUCCESS;
            break;
        default:
            retval = KERN_INVALID_ARGUMENT;
            break;
        }
    }
    else if(spr==chud_750fx_hid2 && target_cpu_subtype==CPU_SUBTYPE_POWERPC_750) {
	mtspr(chud_750fx_hid2, val);
        per_proc->pf.pfHID2 = val;
        retval = KERN_SUCCESS;
    }
    else if(spr==chud_7400_msscr0 && (target_cpu_subtype==CPU_SUBTYPE_POWERPC_7400 || target_cpu_subtype==CPU_SUBTYPE_POWERPC_7450)) {
	mtspr(chud_7400_msscr0, val);
        per_proc->pf.pfMSSCR0 = val;
        retval = KERN_SUCCESS;
    }
    else if(spr==chud_7400_msscr1 && (target_cpu_subtype==CPU_SUBTYPE_POWERPC_7400 || target_cpu_subtype==CPU_SUBTYPE_POWERPC_7450)) { // called msssr0 on 7450
	mtspr(chud_7400_msscr1, val);
        per_proc->pf.pfMSSCR1 = val;
        retval = KERN_SUCCESS;
    }
    else if(spr==chud_7450_ldstcr && target_cpu_subtype==CPU_SUBTYPE_POWERPC_7450) {
	mtspr(chud_7450_ldstcr, val);
        per_proc->pf.pfLDSTCR = val;
        retval = KERN_SUCCESS;
    }
    else if(spr==chud_7450_ictrl && target_cpu_subtype==CPU_SUBTYPE_POWERPC_7450) {
	mtspr(chud_7450_ictrl, val);
        per_proc->pf.pfICTRL = val;
        retval = KERN_SUCCESS;
    } else {
        retval = KERN_INVALID_ARGUMENT;
    }

    if(didBind) {
    chudxnu_unbind_thread(current_thread());
    }
    
    return retval;
}

__private_extern__
kern_return_t chudxnu_set_shadowed_spr64(int cpu, int spr, uint64_t val)
{
    cpu_subtype_t target_cpu_subtype;
    kern_return_t retval = KERN_FAILURE;
    struct per_proc_info *per_proc;
    boolean_t didBind = FALSE;

    if(cpu>=chudxnu_phys_cpu_count()) { // check sanity of cpu argument
        return KERN_FAILURE;
    }

    if(cpu<0) { // cpu<0 means don't bind (current cpu)
		cpu = chudxnu_cpu_number();
		didBind = FALSE;
    } else {
    chudxnu_bind_thread(current_thread(), cpu);
		didBind = TRUE;
    }

    per_proc = PerProcTable[cpu].ppe_vaddr;
    target_cpu_subtype = per_proc->cpu_subtype;

    if(spr==chud_970_hid0) {
        switch(target_cpu_subtype) {
        case CPU_SUBTYPE_POWERPC_970:
            mtspr64(chud_970_hid0, &val);
            per_proc->pf.pfHID0 = val;
            retval = KERN_SUCCESS;
            break;
        default:
            retval = KERN_INVALID_ARGUMENT;
            break;
        }
    }
    else if(spr==chud_970_hid1) {
        switch(target_cpu_subtype) {
        case CPU_SUBTYPE_POWERPC_970:
            mtspr64(chud_970_hid1, &val);
            per_proc->pf.pfHID1 = val;
            retval = KERN_SUCCESS;
            break;
        default:
            retval = KERN_INVALID_ARGUMENT;
            break;
        }
    }
    else if(spr==chud_970_hid4) {
        switch(target_cpu_subtype) {
        case CPU_SUBTYPE_POWERPC_970:
            mtspr64(chud_970_hid4, &val);
            per_proc->pf.pfHID4 = val;
            retval = KERN_SUCCESS;
            break;
        default:
            retval = KERN_INVALID_ARGUMENT;
            break;
        }
    }
    else if(spr==chud_970_hid5) {
        switch(target_cpu_subtype) {
        case CPU_SUBTYPE_POWERPC_970:
            mtspr64(chud_970_hid5, &val);
            per_proc->pf.pfHID5 = val;
            retval = KERN_SUCCESS;
            break;
        default:
            retval = KERN_INVALID_ARGUMENT;
            break;
        }
    } else {
        retval = KERN_INVALID_ARGUMENT;
    }

    if(didBind) {
    chudxnu_unbind_thread(current_thread());
    }

    return retval;
}

__private_extern__
uint32_t chudxnu_get_orig_cpu_l2cr(int cpu)
{
    if(cpu<0 || cpu>=chudxnu_phys_cpu_count()) { // check sanity of cpu argument
        cpu = 0;
    }
    return PerProcTable[cpu].ppe_vaddr->pf.l2crOriginal;
}

__private_extern__
uint32_t chudxnu_get_orig_cpu_l3cr(int cpu)
{
    if(cpu<0 || cpu>=chudxnu_phys_cpu_count()) { // check sanity of cpu argument
        cpu = 0;
    }
    return PerProcTable[cpu].ppe_vaddr->pf.l3crOriginal;
}

#pragma mark **** spr ****

__private_extern__
kern_return_t chudxnu_read_spr(int cpu, int spr, uint32_t *val_p)
{
    kern_return_t retval = KERN_SUCCESS;
    boolean_t oldlevel;
    uint32_t val = 0xFFFFFFFF;

    /* bind to requested CPU */
    if(cpu>=0) { // cpu<0 means don't bind
		if(chudxnu_bind_thread(current_thread(), cpu)!=KERN_SUCCESS) {
			return KERN_INVALID_ARGUMENT;
		}
    }
  
    oldlevel = chudxnu_set_interrupts_enabled(FALSE); /* disable interrupts */

    do {
        /* PPC SPRs - 32-bit and 64-bit implementations */
        if(spr==chud_ppc_srr0) { mfspr(val, chud_ppc_srr0); break; }
        if(spr==chud_ppc_srr1) { mfspr(val, chud_ppc_srr1); break; }
        if(spr==chud_ppc_dsisr) { mfspr(val, chud_ppc_dsisr); break; }
        if(spr==chud_ppc_dar) { mfspr(val, chud_ppc_dar); break; }
        if(spr==chud_ppc_dec) { mfspr(val, chud_ppc_dec); break; }
        if(spr==chud_ppc_sdr1) { mfspr(val, chud_ppc_sdr1); break; }
        if(spr==chud_ppc_sprg0) { mfspr(val, chud_ppc_sprg0); break; }
        if(spr==chud_ppc_sprg1) { mfspr(val, chud_ppc_sprg1); break; }
        if(spr==chud_ppc_sprg2) { mfspr(val, chud_ppc_sprg2); break; }
        if(spr==chud_ppc_sprg3) { mfspr(val, chud_ppc_sprg3); break; }
        if(spr==chud_ppc_ear) { mfspr(val, chud_ppc_ear); break; }
        if(spr==chud_ppc_tbl) { mfspr(val, 268); break; } /* timebase consists of read registers and write registers */
        if(spr==chud_ppc_tbu) { mfspr(val, 269); break; }
        if(spr==chud_ppc_pvr) { mfspr(val, chud_ppc_pvr); break; }
        if(spr==chud_ppc_ibat0u) { mfspr(val, chud_ppc_ibat0u); break; }
        if(spr==chud_ppc_ibat0l) { mfspr(val, chud_ppc_ibat0l); break; }
        if(spr==chud_ppc_ibat1u) { mfspr(val, chud_ppc_ibat1u); break; }
        if(spr==chud_ppc_ibat1l) { mfspr(val, chud_ppc_ibat1l); break; }
        if(spr==chud_ppc_ibat2u) { mfspr(val, chud_ppc_ibat2u); break; }
        if(spr==chud_ppc_ibat2l) { mfspr(val, chud_ppc_ibat2l); break; }
        if(spr==chud_ppc_ibat3u) { mfspr(val, chud_ppc_ibat3u); break; }
        if(spr==chud_ppc_ibat3l) { mfspr(val, chud_ppc_ibat3l); break; }
        if(spr==chud_ppc_dbat0u) { mfspr(val, chud_ppc_dbat0u); break; }
        if(spr==chud_ppc_dbat0l) { mfspr(val, chud_ppc_dbat0l); break; }
        if(spr==chud_ppc_dbat1u) { mfspr(val, chud_ppc_dbat1u); break; }
        if(spr==chud_ppc_dbat1l) { mfspr(val, chud_ppc_dbat1l); break; }
        if(spr==chud_ppc_dbat2u) { mfspr(val, chud_ppc_dbat2u); break; }
        if(spr==chud_ppc_dbat2l) { mfspr(val, chud_ppc_dbat2l); break; }
        if(spr==chud_ppc_dbat3u) { mfspr(val, chud_ppc_dbat3u); break; }
        if(spr==chud_ppc_dbat3l) { mfspr(val, chud_ppc_dbat3l); break; }
        if(spr==chud_ppc_dabr) { mfspr(val, chud_ppc_dabr); break; }
        if(spr==chud_ppc_msr) { /* this is the MSR for the calling process */
            struct ppc_thread_state64 state;
            mach_msg_type_number_t count = PPC_THREAD_STATE64_COUNT;
            kern_return_t kr;
            kr = chudxnu_thread_get_state(current_thread(), PPC_THREAD_STATE64, (thread_state_t)&state, &count, TRUE /* user only */);
            if(KERN_SUCCESS==kr) {
                val = state.srr1;
            } else {
                retval = KERN_FAILURE;
            }
            break;
        }
        
        /* PPC SPRs - 32-bit implementations */
        if(spr==chud_ppc32_sr0) { mfsr(val, 0); break; }
        if(spr==chud_ppc32_sr1) { mfsr(val, 1); break; }
        if(spr==chud_ppc32_sr2) { mfsr(val, 2); break; }
        if(spr==chud_ppc32_sr3) { mfsr(val, 3); break; }
        if(spr==chud_ppc32_sr4) { mfsr(val, 4); break; }
        if(spr==chud_ppc32_sr5) { mfsr(val, 5); break; }
        if(spr==chud_ppc32_sr6) { mfsr(val, 6); break; }
        if(spr==chud_ppc32_sr7) { mfsr(val, 7); break; }
        if(spr==chud_ppc32_sr8) { mfsr(val, 8); break; }
        if(spr==chud_ppc32_sr9) { mfsr(val, 9); break; }
        if(spr==chud_ppc32_sr10) { mfsr(val, 10); break; }
        if(spr==chud_ppc32_sr11) { mfsr(val, 11); break; }
        if(spr==chud_ppc32_sr12) { mfsr(val, 12); break; }
        if(spr==chud_ppc32_sr13) { mfsr(val, 13); break; }
        if(spr==chud_ppc32_sr14) { mfsr(val, 14); break; }
        if(spr==chud_ppc32_sr15) { mfsr(val, 15); break; }
        
        /* PPC SPRs - 64-bit implementations */
        if(spr==chud_ppc64_ctrl) { mfspr(val, chud_ppc64_ctrl); break; }
        
        /* Implementation Specific SPRs */
        if(cpu_subtype()==CPU_SUBTYPE_POWERPC_750) {
            if(spr==chud_750_mmcr0) { mfspr(val, chud_750_mmcr0); break; }
            if(spr==chud_750_pmc1) { mfspr(val, chud_750_pmc1); break; }
            if(spr==chud_750_pmc2) { mfspr(val, chud_750_pmc2); break; }
            if(spr==chud_750_sia) { mfspr(val, chud_750_sia); break; }
            if(spr==chud_750_mmcr1) { mfspr(val, chud_750_mmcr1); break; }
            if(spr==chud_750_pmc3) { mfspr(val, chud_750_pmc3); break; }
            if(spr==chud_750_pmc4) { mfspr(val, chud_750_pmc4); break; }
            if(spr==chud_750_hid0) { mfspr(val, chud_750_hid0); break; }
            if(spr==chud_750_hid1) { mfspr(val, chud_750_hid1); break; }
            if(spr==chud_750_iabr) { mfspr(val, chud_750_iabr); break; }
            if(spr==chud_750_ictc) { mfspr(val, chud_750_ictc); break; }
            if(spr==chud_750_thrm1) { mfspr(val, chud_750_thrm1); break; }
            if(spr==chud_750_thrm2) { mfspr(val, chud_750_thrm2); break; }
            if(spr==chud_750_thrm3) { mfspr(val, chud_750_thrm3); break; }
            if(spr==chud_750_l2cr) { mfspr(val, chud_750_l2cr); break; }

	    // 750FX only
            if(spr==chud_750fx_ibat4u) { mfspr(val, chud_750fx_ibat4u); break; }
            if(spr==chud_750fx_ibat4l) { mfspr(val, chud_750fx_ibat4l); break; }
            if(spr==chud_750fx_ibat5u) { mfspr(val, chud_750fx_ibat5u); break; }
            if(spr==chud_750fx_ibat5l) { mfspr(val, chud_750fx_ibat5l); break; }
            if(spr==chud_750fx_ibat6u) { mfspr(val, chud_750fx_ibat6u); break; }
            if(spr==chud_750fx_ibat6l) { mfspr(val, chud_750fx_ibat6l); break; }
            if(spr==chud_750fx_ibat7u) { mfspr(val, chud_750fx_ibat7u); break; }
            if(spr==chud_750fx_ibat7l) { mfspr(val, chud_750fx_ibat7l); break; }
            if(spr==chud_750fx_dbat4u) { mfspr(val, chud_750fx_dbat4u); break; }
            if(spr==chud_750fx_dbat4l) { mfspr(val, chud_750fx_dbat4l); break; }
            if(spr==chud_750fx_dbat5u) { mfspr(val, chud_750fx_dbat5u); break; }
            if(spr==chud_750fx_dbat5l) { mfspr(val, chud_750fx_dbat5l); break; }
            if(spr==chud_750fx_dbat6u) { mfspr(val, chud_750fx_dbat6u); break; }
            if(spr==chud_750fx_dbat6l) { mfspr(val, chud_750fx_dbat6l); break; }
            if(spr==chud_750fx_dbat7u) { mfspr(val, chud_750fx_dbat7u); break; }
            if(spr==chud_750fx_dbat7l) { mfspr(val, chud_750fx_dbat7l); break; }

	    // 750FX >= DDR2.x only
	    if(spr==chud_750fx_hid2) { mfspr(val, chud_750fx_hid2); break; }
        }
        
        if(cpu_subtype()==CPU_SUBTYPE_POWERPC_7400) {
            if(spr==chud_7400_mmcr2) { mfspr(val, chud_7400_mmcr2); break; }
            if(spr==chud_7400_bamr) { mfspr(val, chud_7400_bamr); break; }
            if(spr==chud_7400_mmcr0) { mfspr(val, chud_7400_mmcr0); break; }
            if(spr==chud_7400_pmc1) { mfspr(val, chud_7400_pmc1); break; }
            if(spr==chud_7400_pmc2) { mfspr(val, chud_7400_pmc2); break; }
            if(spr==chud_7400_siar) { mfspr(val, chud_7400_siar); break; }
            if(spr==chud_7400_mmcr1) { mfspr(val, chud_7400_mmcr1); break; }
            if(spr==chud_7400_pmc3) { mfspr(val, chud_7400_pmc3); break; }
            if(spr==chud_7400_pmc4) { mfspr(val, chud_7400_pmc4); break; }
            if(spr==chud_7400_hid0) { mfspr(val, chud_7400_hid0); break; }
            if(spr==chud_7400_hid1) { mfspr(val, chud_7400_hid1); break; }
            if(spr==chud_7400_iabr) { mfspr(val, chud_7400_iabr); break; }
            if(spr==chud_7400_msscr0) { mfspr(val, chud_7400_msscr0); break; }
            if(spr==chud_7400_msscr1) { mfspr(val, chud_7400_msscr1); break; } /* private */
            if(spr==chud_7400_ictc) { mfspr(val, chud_7400_ictc); break; }
            if(spr==chud_7400_thrm1) { mfspr(val, chud_7400_thrm1); break; }
            if(spr==chud_7400_thrm2) { mfspr(val, chud_7400_thrm2); break; }
            if(spr==chud_7400_thrm3) { mfspr(val, chud_7400_thrm3); break; }
            if(spr==chud_7400_pir) { mfspr(val, chud_7400_pir); break; }
            if(spr==chud_7400_l2cr) { mfspr(val, chud_7400_l2cr); break; }
	    
	    // 7410 only
            if(spr==chud_7410_l2pmcr) { mfspr(val, chud_7410_l2pmcr); break; }
        }

        if(cpu_subtype()==CPU_SUBTYPE_POWERPC_7450) {
            if(spr==chud_7450_mmcr2) { mfspr(val, chud_7450_mmcr2); break; }
            if(spr==chud_7450_pmc5) { mfspr(val, chud_7450_pmc5); break; }
            if(spr==chud_7450_pmc6) { mfspr(val, chud_7450_pmc6); break; }
            if(spr==chud_7450_bamr) { mfspr(val, chud_7450_bamr); break; }
            if(spr==chud_7450_mmcr0) { mfspr(val, chud_7450_mmcr0); break; }
            if(spr==chud_7450_pmc1) { mfspr(val, chud_7450_pmc1); break; }
            if(spr==chud_7450_pmc2) { mfspr(val, chud_7450_pmc2); break; }
            if(spr==chud_7450_siar) { mfspr(val, chud_7450_siar); break; }
            if(spr==chud_7450_mmcr1) { mfspr(val, chud_7450_mmcr1); break; }
            if(spr==chud_7450_pmc3) { mfspr(val, chud_7450_pmc3); break; }
            if(spr==chud_7450_pmc4) { mfspr(val, chud_7450_pmc4); break; }
            if(spr==chud_7450_tlbmiss) { mfspr(val, chud_7450_tlbmiss); break; }
            if(spr==chud_7450_ptehi) { mfspr(val, chud_7450_ptehi); break; }
            if(spr==chud_7450_ptelo) { mfspr(val, chud_7450_ptelo); break; }
            if(spr==chud_7450_l3pm) { mfspr(val, chud_7450_l3pm); break; }
            if(spr==chud_7450_hid0) { mfspr(val, chud_7450_hid0); break; }
            if(spr==chud_7450_hid1) { mfspr(val, chud_7450_hid1); break; }
            if(spr==chud_7450_iabr) { mfspr(val, chud_7450_iabr); break; }
            if(spr==chud_7450_ldstdb) { mfspr(val, chud_7450_ldstdb); break; }
            if(spr==chud_7450_msscr0) { mfspr(val, chud_7450_msscr0); break; }
            if(spr==chud_7450_msssr0) { mfspr(val, chud_7450_msssr0); break; }
            if(spr==chud_7450_ldstcr) { mfspr(val, chud_7450_ldstcr); break; }
            if(spr==chud_7450_ictc) { mfspr(val, chud_7450_ictc); break; }
            if(spr==chud_7450_ictrl) { mfspr(val, chud_7450_ictrl); break; }
            if(spr==chud_7450_thrm1) { mfspr(val, chud_7450_thrm1); break; }
            if(spr==chud_7450_thrm2) { mfspr(val, chud_7450_thrm2); break; }
            if(spr==chud_7450_thrm3) { mfspr(val, chud_7450_thrm3); break; }
            if(spr==chud_7450_pir) { mfspr(val, chud_7450_pir); break; }
            if(spr==chud_7450_l2cr) { mfspr(val, chud_7450_l2cr); break; }
            if(spr==chud_7450_l3cr) { mfspr(val, chud_7450_l3cr); break; }
	    
	    // 7455/7457 only
            if(spr==chud_7455_sprg4) { mfspr(val, chud_7455_sprg4); break; }
            if(spr==chud_7455_sprg5) { mfspr(val, chud_7455_sprg5); break; }
            if(spr==chud_7455_sprg6) { mfspr(val, chud_7455_sprg6); break; }
            if(spr==chud_7455_sprg7) { mfspr(val, chud_7455_sprg7); break; }
            if(spr==chud_7455_ibat4u) { mfspr(val, chud_7455_ibat4u); break; }
            if(spr==chud_7455_ibat4l) { mfspr(val, chud_7455_ibat4l); break; }
            if(spr==chud_7455_ibat5u) { mfspr(val, chud_7455_ibat5u); break; }
            if(spr==chud_7455_ibat5l) { mfspr(val, chud_7455_ibat5l); break; }
            if(spr==chud_7455_ibat6u) { mfspr(val, chud_7455_ibat6u); break; }
            if(spr==chud_7455_ibat6l) { mfspr(val, chud_7455_ibat6l); break; }
            if(spr==chud_7455_ibat7u) { mfspr(val, chud_7455_ibat7u); break; }
            if(spr==chud_7455_ibat7l) { mfspr(val, chud_7455_ibat7l); break; }
            if(spr==chud_7455_dbat4u) { mfspr(val, chud_7455_dbat4u); break; }
            if(spr==chud_7455_dbat4l) { mfspr(val, chud_7455_dbat4l); break; }
            if(spr==chud_7455_dbat5u) { mfspr(val, chud_7455_dbat5u); break; }
            if(spr==chud_7455_dbat5l) { mfspr(val, chud_7455_dbat5l); break; }
            if(spr==chud_7455_dbat6u) { mfspr(val, chud_7455_dbat6u); break; }
            if(spr==chud_7455_dbat6l) { mfspr(val, chud_7455_dbat6l); break; }
            if(spr==chud_7455_dbat7u) { mfspr(val, chud_7455_dbat7u); break; }
            if(spr==chud_7455_dbat7l) { mfspr(val, chud_7455_dbat7l); break; }
        }
        
        if(cpu_subtype()==CPU_SUBTYPE_POWERPC_970) {
	    if(spr==chud_970_pir) { mfspr(val, chud_970_pir); break; }
	    if(spr==chud_970_pmc1) { mfspr(val, chud_970_pmc1); break; }
	    if(spr==chud_970_pmc2) { mfspr(val, chud_970_pmc2); break; }
	    if(spr==chud_970_pmc3) { mfspr(val, chud_970_pmc3); break; }
	    if(spr==chud_970_pmc4) { mfspr(val, chud_970_pmc4); break; }
	    if(spr==chud_970_pmc5) { mfspr(val, chud_970_pmc5); break; }
	    if(spr==chud_970_pmc6) { mfspr(val, chud_970_pmc6); break; }
	    if(spr==chud_970_pmc7) { mfspr(val, chud_970_pmc7); break; }
	    if(spr==chud_970_pmc8) { mfspr(val, chud_970_pmc8); break; }
	    if(spr==chud_970_hdec) { mfspr(val, chud_970_hdec); break; }
        }

        /* we only get here if none of the above cases qualify */
        retval = KERN_INVALID_ARGUMENT;
    } while(0);
    
    chudxnu_set_interrupts_enabled(oldlevel); /* enable interrupts */

    if(cpu>=0) { // cpu<0 means don't bind
		chudxnu_unbind_thread(current_thread());
    }

    *val_p = val;

    return retval;
}

__private_extern__
kern_return_t chudxnu_read_spr64(int cpu, int spr, uint64_t *val_p)
{
    kern_return_t retval = KERN_SUCCESS;
    boolean_t oldlevel;

    /* bind to requested CPU */
    if(cpu>=0) { // cpu<0 means don't bind
		if(chudxnu_bind_thread(current_thread(), cpu)!=KERN_SUCCESS) {
			return KERN_INVALID_ARGUMENT;
		}
    }
  
    oldlevel = chudxnu_set_interrupts_enabled(FALSE); /* disable interrupts */

    do {
        /* PPC SPRs - 32-bit and 64-bit implementations */
        if(spr==chud_ppc_srr0) { retval = mfspr64(val_p, chud_ppc_srr0); break; }
        if(spr==chud_ppc_srr1) { retval = mfspr64(val_p, chud_ppc_srr1); break; }
        if(spr==chud_ppc_dar) { retval = mfspr64(val_p, chud_ppc_dar); break; }
        if(spr==chud_ppc_dsisr) { retval = mfspr64(val_p, chud_ppc_dsisr); break; }
        if(spr==chud_ppc_sdr1) { retval = mfspr64(val_p, chud_ppc_sdr1); break; }
        if(spr==chud_ppc_sprg0) { retval = mfspr64(val_p, chud_ppc_sprg0); break; }
        if(spr==chud_ppc_sprg1) { retval = mfspr64(val_p, chud_ppc_sprg1); break; }
        if(spr==chud_ppc_sprg2) { retval = mfspr64(val_p, chud_ppc_sprg2); break; }
        if(spr==chud_ppc_sprg3) { retval = mfspr64(val_p, chud_ppc_sprg3); break; }
        if(spr==chud_ppc_dabr) { retval = mfspr64(val_p, chud_ppc_dabr); break; }
        if(spr==chud_ppc_msr) { /* this is the MSR for the calling process */
            struct ppc_thread_state64 state;
            mach_msg_type_number_t count = PPC_THREAD_STATE64_COUNT;
            kern_return_t kr;
            kr = chudxnu_thread_get_state(current_thread(), PPC_THREAD_STATE64, (thread_state_t)&state, &count, TRUE /* user only */);
            if(KERN_SUCCESS==kr) {
                *val_p = state.srr1;
            } else {
                retval = KERN_FAILURE;
            }
            break;
        }
        
        /* PPC SPRs - 64-bit implementations */
        if(spr==chud_ppc64_asr) { retval = mfspr64(val_p, chud_ppc64_asr); break; }
        if(spr==chud_ppc64_accr) { retval = mfspr64(val_p, chud_ppc64_accr); break; }        
        
        /* Implementation Specific SPRs */
        if(cpu_subtype()==CPU_SUBTYPE_POWERPC_970) {
            if(spr==chud_970_hid0) { retval = mfspr64(val_p, chud_970_hid0); break; }
            if(spr==chud_970_hid1) { retval = mfspr64(val_p, chud_970_hid1); break; }
            if(spr==chud_970_hid4) { retval = mfspr64(val_p, chud_970_hid4); break; }
            if(spr==chud_970_hid5) { retval = mfspr64(val_p, chud_970_hid5); break; }
            if(spr==chud_970_mmcr0) { retval = mfspr64(val_p, chud_970_mmcr0); break; }
            if(spr==chud_970_mmcr1) { retval = mfspr64(val_p, chud_970_mmcr1); break; }
            if(spr==chud_970_mmcra) { retval = mfspr64(val_p, chud_970_mmcra); break; }
            if(spr==chud_970_siar) { retval = mfspr64(val_p, chud_970_siar); break; }
            if(spr==chud_970_sdar) { retval = mfspr64(val_p, chud_970_sdar); break; }
            if(spr==chud_970_imc) { retval = mfspr64(val_p, chud_970_imc); break; }
            if(spr==chud_970_rmor) { retval = mfspr64(val_p, chud_970_rmor); break; }
            if(spr==chud_970_hrmor) { retval = mfspr64(val_p, chud_970_hrmor); break; }
            if(spr==chud_970_hior) { retval = mfspr64(val_p, chud_970_hior); break; }
            if(spr==chud_970_lpidr) { retval = mfspr64(val_p, chud_970_lpidr); break; }
            if(spr==chud_970_lpcr) { retval = mfspr64(val_p, chud_970_lpcr); break; }
            if(spr==chud_970_dabrx) { retval = mfspr64(val_p, chud_970_dabrx); break; }
            if(spr==chud_970_hsprg0) { retval = mfspr64(val_p, chud_970_hsprg0); break; }
            if(spr==chud_970_hsprg1) { retval = mfspr64(val_p, chud_970_hsprg1); break; }
            if(spr==chud_970_hsrr0) { retval = mfspr64(val_p, chud_970_hsrr0); break; }
            if(spr==chud_970_hsrr1) { retval = mfspr64(val_p, chud_970_hsrr1); break; }
            if(spr==chud_970_hdec) { retval = mfspr64(val_p, chud_970_hdec); break; }
            if(spr==chud_970_trig0) { retval = mfspr64(val_p, chud_970_trig0); break; }
            if(spr==chud_970_trig1) { retval = mfspr64(val_p, chud_970_trig1); break; }
            if(spr==chud_970_trig2) { retval = mfspr64(val_p, chud_970_trig2); break; }
            if(spr==chud_970_scomc) { retval = mfspr64(val_p, chud_970_scomc); break; }
            if(spr==chud_970_scomd) { retval = mfspr64(val_p, chud_970_scomd); break; }
        }

        /* we only get here if none of the above cases qualify */
	*val_p = 0xFFFFFFFFFFFFFFFFLL;
        retval = KERN_INVALID_ARGUMENT;
    } while(0);
    
    chudxnu_set_interrupts_enabled(oldlevel); /* enable interrupts */

    if(cpu>=0) { // cpu<0 means don't bind
		chudxnu_unbind_thread(current_thread());
    }

    return retval;
}

__private_extern__
kern_return_t chudxnu_write_spr(int cpu, int spr, uint32_t val)
{
    kern_return_t retval = KERN_SUCCESS;
    boolean_t oldlevel;

    /* bind to requested CPU */
    if(cpu>=0) { // cpu<0 means don't bind
		if(chudxnu_bind_thread(current_thread(), cpu)!=KERN_SUCCESS) {
			return KERN_INVALID_ARGUMENT;
		}
    }

    oldlevel = chudxnu_set_interrupts_enabled(FALSE); /* disable interrupts */

    do {          
        /* PPC SPRs - 32-bit and 64-bit implementations */
        if(spr==chud_ppc_srr0) { mtspr(chud_ppc_srr0, val); break; }
        if(spr==chud_ppc_srr1) { mtspr(chud_ppc_srr1, val); break; }
        if(spr==chud_ppc_dsisr) { mtspr(chud_ppc_dsisr, val); break; }
        if(spr==chud_ppc_dar) { mtspr(chud_ppc_dar, val); break; }
        if(spr==chud_ppc_dec) { mtspr(chud_ppc_dec, val); break; }
        if(spr==chud_ppc_sdr1) { mtspr(chud_ppc_sdr1, val); break; }
        if(spr==chud_ppc_sprg0) { mtspr(chud_ppc_sprg0, val); break; }
        if(spr==chud_ppc_sprg1) { mtspr(chud_ppc_sprg1, val); break; }
        if(spr==chud_ppc_sprg2) { mtspr(chud_ppc_sprg2, val); break; }
        if(spr==chud_ppc_sprg3) { mtspr(chud_ppc_sprg3, val); break; }
        if(spr==chud_ppc_ear) { mtspr(chud_ppc_ear, val); break; }
        if(spr==chud_ppc_tbl) { mtspr(284, val); break; } /* timebase consists of read registers and write registers */
        if(spr==chud_ppc_tbu) { mtspr(285, val); break; }
        if(spr==chud_ppc_pvr) { mtspr(chud_ppc_pvr, val); break; }
        if(spr==chud_ppc_ibat0u) { mtspr(chud_ppc_ibat0u, val); break; }
        if(spr==chud_ppc_ibat0l) { mtspr(chud_ppc_ibat0l, val); break; }
        if(spr==chud_ppc_ibat1u) { mtspr(chud_ppc_ibat1u, val); break; }
        if(spr==chud_ppc_ibat1l) { mtspr(chud_ppc_ibat1l, val); break; }
        if(spr==chud_ppc_ibat2u) { mtspr(chud_ppc_ibat2u, val); break; }
        if(spr==chud_ppc_ibat2l) { mtspr(chud_ppc_ibat2l, val); break; }
        if(spr==chud_ppc_ibat3u) { mtspr(chud_ppc_ibat3u, val); break; }
        if(spr==chud_ppc_ibat3l) { mtspr(chud_ppc_ibat3l, val); break; }
        if(spr==chud_ppc_dbat0u) { mtspr(chud_ppc_dbat0u, val); break; }
        if(spr==chud_ppc_dbat0l) { mtspr(chud_ppc_dbat0l, val); break; }
        if(spr==chud_ppc_dbat1u) { mtspr(chud_ppc_dbat1u, val); break; }
        if(spr==chud_ppc_dbat1l) { mtspr(chud_ppc_dbat1l, val); break; }
        if(spr==chud_ppc_dbat2u) { mtspr(chud_ppc_dbat2u, val); break; }
        if(spr==chud_ppc_dbat2l) { mtspr(chud_ppc_dbat2l, val); break; }
        if(spr==chud_ppc_dbat3u) { mtspr(chud_ppc_dbat3u, val); break; }
        if(spr==chud_ppc_dbat3l) { mtspr(chud_ppc_dbat3l, val); break; }
        if(spr==chud_ppc_dabr) { mtspr(chud_ppc_dabr, val); break; }
        if(spr==chud_ppc_msr) { /* this is the MSR for the calling process */
            struct ppc_thread_state64 state;
            mach_msg_type_number_t count = PPC_THREAD_STATE64_COUNT;
            kern_return_t kr;
            kr = chudxnu_thread_get_state(current_thread(), PPC_THREAD_STATE64, (thread_state_t)&state, &count, TRUE /* user only */);
            if(KERN_SUCCESS==kr) {
                state.srr1 = val;
                kr = chudxnu_thread_set_state(current_thread(), PPC_THREAD_STATE64, (thread_state_t)&state, count, TRUE /* user only */);
                if(KERN_SUCCESS!=kr) {
                    retval = KERN_FAILURE;
                }
            } else {
                retval = KERN_FAILURE;
            }
            break;
        }
        
        /* PPC SPRs - 32-bit implementations */
        if(spr==chud_ppc32_sr0) { mtsr(0, val); break; }
        if(spr==chud_ppc32_sr1) { mtsr(1, val); break; }
        if(spr==chud_ppc32_sr2) { mtsr(2, val); break; }
        if(spr==chud_ppc32_sr3) { mtsr(3, val); break; }
        if(spr==chud_ppc32_sr4) { mtsr(4, val); break; }
        if(spr==chud_ppc32_sr5) { mtsr(5, val); break; }
        if(spr==chud_ppc32_sr6) { mtsr(6, val); break; }
        if(spr==chud_ppc32_sr7) { mtsr(7, val); break; }
        if(spr==chud_ppc32_sr8) { mtsr(8, val); break; }
        if(spr==chud_ppc32_sr9) { mtsr(9, val); break; }
        if(spr==chud_ppc32_sr10) { mtsr(10, val); break; }
        if(spr==chud_ppc32_sr11) { mtsr(11, val); break; }
        if(spr==chud_ppc32_sr12) { mtsr(12, val); break; }
        if(spr==chud_ppc32_sr13) { mtsr(13, val); break; }
        if(spr==chud_ppc32_sr14) { mtsr(14, val); break; }
        if(spr==chud_ppc32_sr15) { mtsr(15, val); break; }
        
        /* Implementation Specific SPRs */
        if(cpu_subtype()==CPU_SUBTYPE_POWERPC_750) {
            if(spr==chud_750_mmcr0) { mtspr(chud_750_mmcr0, val); break; }
            if(spr==chud_750_pmc1) { mtspr(chud_750_pmc1, val); break; }
            if(spr==chud_750_pmc2) { mtspr(chud_750_pmc2, val); break; }
            if(spr==chud_750_sia) { mtspr(chud_750_sia, val); break; }
            if(spr==chud_750_mmcr1) { mtspr(chud_750_mmcr1, val); break; }
            if(spr==chud_750_pmc3) { mtspr(chud_750_pmc3, val); break; }
            if(spr==chud_750_pmc4) { mtspr(chud_750_pmc4, val); break; }
            if(spr==chud_750_iabr) { mtspr(chud_750_iabr, val); break; }
            if(spr==chud_750_ictc) { mtspr(chud_750_ictc, val); break; }
            if(spr==chud_750_thrm1) { mtspr(chud_750_thrm1, val); break; }
            if(spr==chud_750_thrm2) { mtspr(chud_750_thrm2, val); break; }
            if(spr==chud_750_thrm3) { mtspr(chud_750_thrm3, val); break; }
            if(spr==chud_750_l2cr) { 
		retval = chudxnu_set_shadowed_spr(cpu, spr, val);
		break;
            }
            if(spr==chud_750_hid0) {
		retval = chudxnu_set_shadowed_spr(cpu, spr, val);
		break;
            }
            if(spr==chud_750_hid1) {
		retval = chudxnu_set_shadowed_spr(cpu, spr, val);
		break;
            }

	    // 750FX only
            if(spr==chud_750fx_ibat4u) { mtspr(chud_750fx_ibat4u, val); break; }
            if(spr==chud_750fx_ibat4l) { mtspr(chud_750fx_ibat4l, val); break; }
            if(spr==chud_750fx_ibat5u) { mtspr(chud_750fx_ibat5u, val); break; }
            if(spr==chud_750fx_ibat5l) { mtspr(chud_750fx_ibat5l, val); break; }
            if(spr==chud_750fx_ibat6u) { mtspr(chud_750fx_ibat6u, val); break; }
            if(spr==chud_750fx_ibat6l) { mtspr(chud_750fx_ibat6l, val); break; }
            if(spr==chud_750fx_ibat7u) { mtspr(chud_750fx_ibat7u, val); break; }
            if(spr==chud_750fx_ibat7l) { mtspr(chud_750fx_ibat7l, val); break; }
            if(spr==chud_750fx_dbat4u) { mtspr(chud_750fx_dbat4u, val); break; }
            if(spr==chud_750fx_dbat4l) { mtspr(chud_750fx_dbat4l, val); break; }
            if(spr==chud_750fx_dbat5u) { mtspr(chud_750fx_dbat5u, val); break; }
            if(spr==chud_750fx_dbat5l) { mtspr(chud_750fx_dbat5l, val); break; }
            if(spr==chud_750fx_dbat6u) { mtspr(chud_750fx_dbat6u, val); break; }
            if(spr==chud_750fx_dbat6l) { mtspr(chud_750fx_dbat6l, val); break; }
            if(spr==chud_750fx_dbat7u) { mtspr(chud_750fx_dbat7u, val); break; }
            if(spr==chud_750fx_dbat7l) { mtspr(chud_750fx_dbat7l, val); break; }
	    
	    // 750FX >= DDR2.x
	    if(spr==chud_750fx_hid2) { mtspr(chud_750fx_hid2, val); break; }
        }
        
        if(cpu_subtype()==CPU_SUBTYPE_POWERPC_7400) {
            if(spr==chud_7400_mmcr2) { mtspr(chud_7400_mmcr2, val); break; }
            if(spr==chud_7400_bamr) { mtspr(chud_7400_bamr, val); break; }
            if(spr==chud_7400_mmcr0) { mtspr(chud_7400_mmcr0, val); break; }
            if(spr==chud_7400_pmc1) { mtspr(chud_7400_pmc1, val); break; }
            if(spr==chud_7400_pmc2) { mtspr(chud_7400_pmc2, val); break; }
            if(spr==chud_7400_siar) { mtspr(chud_7400_siar, val); break; }
            if(spr==chud_7400_mmcr1) { mtspr(chud_7400_mmcr1, val); break; }
            if(spr==chud_7400_pmc3) { mtspr(chud_7400_pmc3, val); break; }
            if(spr==chud_7400_pmc4) { mtspr(chud_7400_pmc4, val); break; }
            if(spr==chud_7400_iabr) { mtspr(chud_7400_iabr, val); break; }
            if(spr==chud_7400_ictc) { mtspr(chud_7400_ictc, val); break; }
            if(spr==chud_7400_thrm1) { mtspr(chud_7400_thrm1, val); break; }
            if(spr==chud_7400_thrm2) { mtspr(chud_7400_thrm2, val); break; }
            if(spr==chud_7400_thrm3) { mtspr(chud_7400_thrm3, val); break; }
            if(spr==chud_7400_pir) { mtspr(chud_7400_pir, val); break; }
            
            if(spr==chud_7400_l2cr) {
                retval = chudxnu_set_shadowed_spr(cpu, spr, val);
		break;
            }
            if(spr==chud_7400_hid0) {
                retval = chudxnu_set_shadowed_spr(cpu, spr, val);
		break;
            }
            if(spr==chud_7400_hid1) {
                retval = chudxnu_set_shadowed_spr(cpu, spr, val);
		break;
            }
            if(spr==chud_7400_msscr0) {
                retval = chudxnu_set_shadowed_spr(cpu, spr, val);
		break;
            }
            if(spr==chud_7400_msscr1) { /* private */
                retval = chudxnu_set_shadowed_spr(cpu, spr, val);
		break;
            }

	    // 7410 only
            if(spr==chud_7410_l2pmcr) { mtspr(chud_7410_l2pmcr, val); break; }
        }

        if(cpu_subtype()==CPU_SUBTYPE_POWERPC_7450) {
            if(spr==chud_7450_mmcr2) { mtspr(chud_7450_mmcr2, val); break; }
            if(spr==chud_7450_pmc5) { mtspr(chud_7450_pmc5, val); break; }
            if(spr==chud_7450_pmc6) { mtspr(chud_7450_pmc6, val); break; }
            if(spr==chud_7450_bamr) { mtspr(chud_7450_bamr, val); break; }
            if(spr==chud_7450_mmcr0) { mtspr(chud_7450_mmcr0, val); break; }
            if(spr==chud_7450_pmc1) { mtspr(chud_7450_pmc1, val); break; }
            if(spr==chud_7450_pmc2) { mtspr(chud_7450_pmc2, val); break; }
            if(spr==chud_7450_siar) { mtspr(chud_7450_siar, val); break; }
            if(spr==chud_7450_mmcr1) { mtspr(chud_7450_mmcr1, val); break; }
            if(spr==chud_7450_pmc3) { mtspr(chud_7450_pmc3, val); break; }
            if(spr==chud_7450_pmc4) { mtspr(chud_7450_pmc4, val); break; }
            if(spr==chud_7450_tlbmiss) { mtspr(chud_7450_tlbmiss, val); break; }
            if(spr==chud_7450_ptehi) { mtspr(chud_7450_ptehi, val); break; }
            if(spr==chud_7450_ptelo) { mtspr(chud_7450_ptelo, val); break; }
            if(spr==chud_7450_l3pm) { mtspr(chud_7450_l3pm, val); break; }
            if(spr==chud_7450_iabr) { mtspr(chud_7450_iabr, val); break; }
            if(spr==chud_7450_ldstdb) { mtspr(chud_7450_ldstdb, val); break; }
            if(spr==chud_7450_ictc) { mtspr(chud_7450_ictc, val); break; }
            if(spr==chud_7450_thrm1) { mtspr(chud_7450_thrm1, val); break; }
            if(spr==chud_7450_thrm2) { mtspr(chud_7450_thrm2, val); break; }
            if(spr==chud_7450_thrm3) { mtspr(chud_7450_thrm3, val); break; }
            if(spr==chud_7450_pir) { mtspr(chud_7450_pir, val); break; }

            if(spr==chud_7450_l2cr) {
                retval = chudxnu_set_shadowed_spr(cpu, spr, val);
		break;
            }
            
            if(spr==chud_7450_l3cr) {
                retval = chudxnu_set_shadowed_spr(cpu, spr, val);
		break;
            }
            if(spr==chud_7450_ldstcr) {
                retval = chudxnu_set_shadowed_spr(cpu, spr, val);
		break;
            }
            if(spr==chud_7450_hid0) {
                retval = chudxnu_set_shadowed_spr(cpu, spr, val);
		break;
            }
            if(spr==chud_7450_hid1) {
                retval = chudxnu_set_shadowed_spr(cpu, spr, val);
		break;
            }
            if(spr==chud_7450_msscr0) {
                retval = chudxnu_set_shadowed_spr(cpu, spr, val);
		break;
            }
            if(spr==chud_7450_msssr0) {
                retval = chudxnu_set_shadowed_spr(cpu, spr, val);
		break;
            }
            if(spr==chud_7450_ictrl) {
                retval = chudxnu_set_shadowed_spr(cpu, spr, val);
		break;
            }

	    // 7455/7457 only
            if(spr==chud_7455_sprg4) { mtspr(chud_7455_sprg4, val); break; }
            if(spr==chud_7455_sprg5) { mtspr(chud_7455_sprg5, val); break; }
            if(spr==chud_7455_sprg6) { mtspr(chud_7455_sprg6, val); break; }
            if(spr==chud_7455_sprg7) { mtspr(chud_7455_sprg7, val); break; }
            if(spr==chud_7455_ibat4u) { mtspr(chud_7455_ibat4u, val); break; }
            if(spr==chud_7455_ibat4l) { mtspr(chud_7455_ibat4l, val); break; }
            if(spr==chud_7455_ibat5u) { mtspr(chud_7455_ibat5u, val); break; }
            if(spr==chud_7455_ibat5l) { mtspr(chud_7455_ibat5l, val); break; }
            if(spr==chud_7455_ibat6u) { mtspr(chud_7455_ibat6u, val); break; }
            if(spr==chud_7455_ibat6l) { mtspr(chud_7455_ibat6l, val); break; }
            if(spr==chud_7455_ibat7u) { mtspr(chud_7455_ibat7u, val); break; }
            if(spr==chud_7455_ibat7l) { mtspr(chud_7455_ibat7l, val); break; }
            if(spr==chud_7455_dbat4u) { mtspr(chud_7455_dbat4u, val); break; }
            if(spr==chud_7455_dbat4l) { mtspr(chud_7455_dbat4l, val); break; }
            if(spr==chud_7455_dbat5u) { mtspr(chud_7455_dbat5u, val); break; }
            if(spr==chud_7455_dbat5l) { mtspr(chud_7455_dbat5l, val); break; }
            if(spr==chud_7455_dbat6u) { mtspr(chud_7455_dbat6u, val); break; }
            if(spr==chud_7455_dbat6l) { mtspr(chud_7455_dbat6l, val); break; }
            if(spr==chud_7455_dbat7u) { mtspr(chud_7455_dbat7u, val); break; }
            if(spr==chud_7455_dbat7l) { mtspr(chud_7455_dbat7l, val); break; }
        }
        
        if(cpu_subtype()==CPU_SUBTYPE_POWERPC_970) {
            if(spr==chud_970_pir) { mtspr(chud_970_pir, val); break; }
            if(spr==chud_970_pmc1) { mtspr(chud_970_pmc1, val); break; }
            if(spr==chud_970_pmc2) { mtspr(chud_970_pmc2, val); break; }
            if(spr==chud_970_pmc3) { mtspr(chud_970_pmc3, val); break; }
            if(spr==chud_970_pmc4) { mtspr(chud_970_pmc4, val); break; }
            if(spr==chud_970_pmc5) { mtspr(chud_970_pmc5, val); break; }
            if(spr==chud_970_pmc6) { mtspr(chud_970_pmc6, val); break; }
            if(spr==chud_970_pmc7) { mtspr(chud_970_pmc7, val); break; }
            if(spr==chud_970_pmc8) { mtspr(chud_970_pmc8, val); break; }
            if(spr==chud_970_hdec) { mtspr(chud_970_hdec, val); break; }
        }
        
        /* we only get here if none of the above cases qualify */
        retval = KERN_INVALID_ARGUMENT;
    } while(0);

    chudxnu_set_interrupts_enabled(oldlevel); /* re-enable interrupts */
	
    if(cpu>=0) { // cpu<0 means don't bind
		chudxnu_unbind_thread(current_thread());
    }
  
    return retval;
}

__private_extern__
kern_return_t chudxnu_write_spr64(int cpu, int spr, uint64_t val)
{
    kern_return_t retval = KERN_SUCCESS;
    boolean_t oldlevel;
    uint64_t *val_p = &val;

    /* bind to requested CPU */
    if(cpu>=0) { // cpu<0 means don't bind
		if(chudxnu_bind_thread(current_thread(), cpu)!=KERN_SUCCESS) {
			return KERN_INVALID_ARGUMENT;
		}
    }

    oldlevel = ml_set_interrupts_enabled(FALSE); /* disable interrupts */

    do {
        /* PPC SPRs - 32-bit and 64-bit implementations */
        if(spr==chud_ppc_srr0) { retval = mtspr64(chud_ppc_srr0, val_p); break; }
        if(spr==chud_ppc_srr1) { retval = mtspr64(chud_ppc_srr1, val_p); break; }
        if(spr==chud_ppc_dar) { retval = mtspr64(chud_ppc_dar, val_p); break; }
        if(spr==chud_ppc_dsisr) { retval = mtspr64(chud_ppc_dsisr, val_p); break; }
        if(spr==chud_ppc_sdr1) { retval = mtspr64(chud_ppc_sdr1, val_p); break; }
        if(spr==chud_ppc_sprg0) { retval = mtspr64(chud_ppc_sprg0, val_p); break; }
        if(spr==chud_ppc_sprg1) { retval = mtspr64(chud_ppc_sprg1, val_p); break; }
        if(spr==chud_ppc_sprg2) { retval = mtspr64(chud_ppc_sprg2, val_p); break; }
        if(spr==chud_ppc_sprg3) { retval = mtspr64(chud_ppc_sprg3, val_p); break; }
        if(spr==chud_ppc_dabr) { retval = mtspr64(chud_ppc_dabr, val_p); break; }
        if(spr==chud_ppc_msr) { /* this is the MSR for the calling process */
            struct ppc_thread_state64 state;
            mach_msg_type_number_t count = PPC_THREAD_STATE64_COUNT;
            kern_return_t kr;
            kr = chudxnu_thread_get_state(current_thread(), PPC_THREAD_STATE64, (thread_state_t)&state, &count, TRUE /* user only */);
            if(KERN_SUCCESS==kr) {
                state.srr1 = val;
                kr = chudxnu_thread_set_state(current_thread(), PPC_THREAD_STATE64, (thread_state_t)&state, count, TRUE /* user only */);
                if(KERN_SUCCESS!=kr) {
                    retval = KERN_FAILURE;
                }
            } else {
                retval = KERN_FAILURE;
            }
            break;
        }
        
        /* PPC SPRs - 64-bit implementations */
        if(spr==chud_ppc64_asr) { retval = mtspr64(chud_ppc64_asr, val_p); break; }
        if(spr==chud_ppc64_accr) { retval = mtspr64(chud_ppc64_accr, val_p); break; }
        if(spr==chud_ppc64_ctrl) { retval = mtspr64(chud_ppc64_ctrl, val_p); break; }
        
        /* Implementation Specific SPRs */
        if(cpu_subtype()==CPU_SUBTYPE_POWERPC_970) {
            if(spr==chud_970_hid0) { retval = mtspr64(chud_970_hid0, val_p); break; }
            if(spr==chud_970_hid1) { retval = mtspr64(chud_970_hid1, val_p); break; }
            if(spr==chud_970_hid4) { retval = mtspr64(chud_970_hid4, val_p); break; }
            if(spr==chud_970_hid5) { retval = mtspr64(chud_970_hid5, val_p); break; }
            if(spr==chud_970_mmcr0) { retval = mtspr64(chud_970_mmcr0, val_p); break; }
            if(spr==chud_970_mmcr1) { retval = mtspr64(chud_970_mmcr1, val_p); break; }
            if(spr==chud_970_mmcra) { retval = mtspr64(chud_970_mmcra, val_p); break; }
            if(spr==chud_970_siar) { retval = mtspr64(chud_970_siar, val_p); break; }
            if(spr==chud_970_sdar) { retval = mtspr64(chud_970_sdar, val_p); break; }
            if(spr==chud_970_imc) { retval = mtspr64(chud_970_imc, val_p); break; }

            if(spr==chud_970_rmor) { retval = mtspr64(chud_970_rmor, val_p); break; }
            if(spr==chud_970_hrmor) { retval = mtspr64(chud_970_hrmor, val_p); break; }
            if(spr==chud_970_hior) { retval = mtspr64(chud_970_hior, val_p); break; }
            if(spr==chud_970_lpidr) { retval = mtspr64(chud_970_lpidr, val_p); break; }
            if(spr==chud_970_lpcr) { retval = mtspr64(chud_970_lpcr, val_p); break; }
            if(spr==chud_970_dabrx) { retval = mtspr64(chud_970_dabrx, val_p); break; }
            
            if(spr==chud_970_hsprg0) { retval = mtspr64(chud_970_hsprg0, val_p); break; }
            if(spr==chud_970_hsprg1) { retval = mtspr64(chud_970_hsprg1, val_p); break; }
            if(spr==chud_970_hsrr0) { retval = mtspr64(chud_970_hsrr0, val_p); break; }
            if(spr==chud_970_hsrr1) { retval = mtspr64(chud_970_hsrr1, val_p); break; }
            if(spr==chud_970_hdec) { retval = mtspr64(chud_970_hdec, val_p); break; }
            if(spr==chud_970_trig0) { retval = mtspr64(chud_970_trig0, val_p); break; }
            if(spr==chud_970_trig1) { retval = mtspr64(chud_970_trig1, val_p); break; }
            if(spr==chud_970_trig2) { retval = mtspr64(chud_970_trig2, val_p); break; }
            if(spr==chud_970_scomc) { retval = mtspr64(chud_970_scomc, val_p); break; }
            if(spr==chud_970_scomd) { retval = mtspr64(chud_970_scomd, val_p); break; }
            
            if(spr==chud_970_hid0) {
                retval = chudxnu_set_shadowed_spr64(cpu, spr, val);
                break;
            }

            if(spr==chud_970_hid1) {
                retval = chudxnu_set_shadowed_spr64(cpu, spr, val);
                break;
            }

            if(spr==chud_970_hid4) {
                retval = chudxnu_set_shadowed_spr64(cpu, spr, val);
                break;
            }
            
            if(spr==chud_970_hid5) {
                retval = chudxnu_set_shadowed_spr64(cpu, spr, val);
                break;
            }
            
        }

        /* we only get here if none of the above cases qualify */
        retval = KERN_INVALID_ARGUMENT;
    } while(0);

    chudxnu_set_interrupts_enabled(oldlevel); /* re-enable interrupts */

    if(cpu>=0) { // cpu<0 means don't bind
		chudxnu_unbind_thread(current_thread());
    }
 
    return retval;
}

#pragma mark **** cache flush ****

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

#pragma mark **** perfmon facility ****

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

#pragma mark **** rupt counters ****

__private_extern__
kern_return_t chudxnu_get_cpu_rupt_counters(int cpu, rupt_counters_t *rupts)
{
    if(cpu<0 || cpu>=chudxnu_phys_cpu_count()) { // check sanity of cpu argument
        return KERN_FAILURE;
    }

    if(rupts) {
        boolean_t oldlevel = ml_set_interrupts_enabled(FALSE);
        struct per_proc_info *per_proc;

        per_proc = PerProcTable[cpu].ppe_vaddr;
        rupts->hwResets = per_proc->hwCtr.hwResets;
        rupts->hwMachineChecks = per_proc->hwCtr.hwMachineChecks;
        rupts->hwDSIs = per_proc->hwCtr.hwDSIs;
        rupts->hwISIs = per_proc->hwCtr.hwISIs;
        rupts->hwExternals = per_proc->hwCtr.hwExternals;
        rupts->hwAlignments = per_proc->hwCtr.hwAlignments;
        rupts->hwPrograms = per_proc->hwCtr.hwPrograms;
        rupts->hwFloatPointUnavailable = per_proc->hwCtr.hwFloatPointUnavailable;
        rupts->hwDecrementers = per_proc->hwCtr.hwDecrementers;
        rupts->hwIOErrors = per_proc->hwCtr.hwIOErrors;
        rupts->hwSystemCalls = per_proc->hwCtr.hwSystemCalls;
        rupts->hwTraces = per_proc->hwCtr.hwTraces;
        rupts->hwFloatingPointAssists = per_proc->hwCtr.hwFloatingPointAssists;
        rupts->hwPerformanceMonitors = per_proc->hwCtr.hwPerformanceMonitors;
        rupts->hwAltivecs = per_proc->hwCtr.hwAltivecs;
        rupts->hwInstBreakpoints = per_proc->hwCtr.hwInstBreakpoints;
        rupts->hwSystemManagements = per_proc->hwCtr.hwSystemManagements;
        rupts->hwAltivecAssists = per_proc->hwCtr.hwAltivecAssists;
        rupts->hwThermal = per_proc->hwCtr.hwThermal;
        rupts->hwSoftPatches = per_proc->hwCtr.hwSoftPatches;
        rupts->hwMaintenances = per_proc->hwCtr.hwMaintenances;
        rupts->hwInstrumentations = per_proc->hwCtr.hwInstrumentations;

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

    bzero((char *)&(PerProcTable[cpu].ppe_vaddr->hwCtr), sizeof(struct hwCtrs));
    return KERN_SUCCESS;
}

#pragma mark **** alignment exceptions ****

__private_extern__
kern_return_t chudxnu_passup_alignment_exceptions(boolean_t enable)
{
    if(enable) {
        dgWork.dgFlags |= enaNotifyEM;
    } else {
        dgWork.dgFlags &= ~enaNotifyEM;
    }
    return KERN_SUCCESS;
}

#pragma mark **** scom ****
kern_return_t chudxnu_scom_read(uint32_t reg, uint64_t *data)
{
	ml_scom_read(reg, data);
	return KERN_SUCCESS;
}

kern_return_t chudxnu_scom_write(uint32_t reg, uint64_t data)
{
	ml_scom_write(reg, data);
	return KERN_SUCCESS;
}

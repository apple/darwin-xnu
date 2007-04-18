/*
 * Copyright (c) 2005-2006 Apple Computer, Inc. All rights reserved.
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

/*
 *	File:		i386/tsc.c
 *	Purpose:	Initializes the TSC and the various conversion
 *			factors needed by other parts of the system.
 */

#include <platforms.h>
#include <mach_kdb.h>

#include <mach/mach_types.h>

#include <kern/cpu_data.h>
#include <kern/cpu_number.h>
#include <kern/clock.h>
#include <kern/host_notify.h>
#include <kern/macro_help.h>
#include <kern/misc_protos.h>
#include <kern/spl.h>
#include <kern/assert.h>
#include <mach/vm_prot.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>		/* for kernel_map */
#include <i386/ipl.h>
#include <i386/pit.h>
#include <architecture/i386/pio.h>
#include <i386/misc_protos.h>
#include <i386/proc_reg.h>
#include <i386/machine_cpu.h>
#include <i386/mp.h>
#include <i386/cpuid.h>
#include <i386/cpu_data.h>
#include <i386/cpu_threads.h>
#include <i386/perfmon.h>
#include <i386/machine_routines.h>
#include <pexpert/pexpert.h>
#include <machine/limits.h>
#include <machine/commpage.h>
#include <sys/kdebug.h>
#include <pexpert/device_tree.h>
#include <i386/tsc.h>

uint64_t	busFCvtt2n = 0;
uint64_t	busFCvtn2t = 0;
uint64_t	tscFreq = 0;
uint64_t	tscFCvtt2n = 0;
uint64_t	tscFCvtn2t = 0;
uint64_t	tscGranularity = 0;
uint64_t	bus2tsc = 0;

/* Decimal powers: */
#define kilo (1000ULL)
#define Mega (kilo * kilo)
#define Giga (kilo * Mega)
#define Tera (kilo * Giga)
#define Peta (kilo * Tera)

static const char	FSB_Frequency_prop[] = "FSBFrequency";
/*
 * This routine extracts the front-side bus frequency in Hz from
 * the device tree.
 */
static uint64_t
EFI_FSB_frequency(void)
{
	uint64_t	frequency = 0;
	DTEntry		entry;
	void		*value;
	int		size;

	if (DTLookupEntry(0, "/efi/platform", &entry) != kSuccess) {
		kprintf("EFI_FSB_frequency: didn't find /efi/platform\n");
		return 0;
	}
	if (DTGetProperty(entry,FSB_Frequency_prop,&value,&size) != kSuccess) {
		kprintf("EFI_FSB_frequency: property %s not found\n");
		return 0;
	}
	if (size == sizeof(uint64_t)) {
		frequency = *(uint64_t *) value;
		kprintf("EFI_FSB_frequency: read %s value: %llu\n",
			FSB_Frequency_prop, frequency);
		if (!(90*Mega < frequency && frequency < 10*Giga)) {
			kprintf("EFI_FSB_frequency: value out of range\n");
			frequency = 0;
		}
	} else {
		kprintf("EFI_FSB_frequency: unexpected size %d\n", size);
	}
	return frequency;
}

/*
 * Initialize the various conversion factors needed by code referencing
 * the TSC.
 */
void
tsc_init(void)
{
    uint64_t	busFreq;
    uint64_t	busFCvtInt;
    uint32_t	cpuModel;
    uint32_t	cpuFamily;
    uint32_t	xcpuid[4];

    /*
     * Get the FSB frequency and conversion factors.
     */
    busFreq = EFI_FSB_frequency();
    if (busFreq != 0) {
	busFCvtt2n = ((1 * Giga) << 32) / busFreq;
	busFCvtn2t = 0xFFFFFFFFFFFFFFFFULL / busFCvtt2n;
	busFCvtInt = tmrCvt(1 * Peta, 0xFFFFFFFFFFFFFFFFULL / busFreq); 
    } else {
	panic("rtclock_init: EFI not supported!\n");
    }
	
    kprintf(" BUS: Frequency = %6d.%04dMHz, "
	    "cvtt2n = %08X.%08X, cvtn2t = %08X.%08X, "
	    "cvtInt = %08X.%08X\n",
	    (uint32_t)(busFreq / Mega),
	    (uint32_t)(busFreq % Mega), 
	    (uint32_t)(busFCvtt2n >> 32), (uint32_t)busFCvtt2n,
	    (uint32_t)(busFCvtn2t >> 32), (uint32_t)busFCvtn2t,
	    (uint32_t)(busFCvtInt >> 32), (uint32_t)busFCvtInt);

    do_cpuid(1, xcpuid);
    cpuFamily = ( xcpuid[eax] >> 8 ) & 0xf;
    /*
     * Get the extended family if necessary.
     */
    if (cpuFamily == 0x0f)
	cpuFamily += (xcpuid[eax] >> 20) & 0x00ff;

    cpuModel = ( xcpuid[eax] >> 4 ) & 0xf;
    /*
     * Get the extended model if necessary.
     */
    if (cpuFamily == CPUID_FAMILY_686
	|| cpuFamily == CPUID_FAMILY_EXTENDED)
	cpuModel += ((xcpuid[eax] >> 16) & 0xf) << 4;

    /*
     * Get the TSC increment.  The TSC is incremented by this
     * on every bus tick.  Calculate the TSC conversion factors
     * to and from nano-seconds.
     */
    if (cpuFamily == CPUID_FAMILY_686) {
	if (cpuModel == CPUID_MODEL_CORE || cpuModel == CPUID_MODEL_CORE2) {
	uint64_t	prfsts;
	
	prfsts = rdmsr64(IA32_PERF_STS);
	tscGranularity = (uint32_t)(prfsts >> BusRatioShift) & BusRatioMask;
	} else {
	    panic("rtclock_init: unknown CPU model: 0x%X\n",
	      cpuModel);
	}
    } else {
	panic("rtclock_init: unknown CPU family: 0x%X\n",
	      cpuFamily);
    }
	
    tscFCvtt2n = busFCvtt2n / (uint64_t)tscGranularity;
    tscFreq = ((1 * Giga)  << 32) / tscFCvtt2n;
    tscFCvtn2t = 0xFFFFFFFFFFFFFFFFULL / tscFCvtt2n;

    kprintf(" TSC: Frequency = %6d.%04dMHz, "
	    "cvtt2n = %08X.%08X, cvtn2t = %08X.%08X, gran = %d\n",
	    (uint32_t)(tscFreq / Mega),
	    (uint32_t)(tscFreq % Mega), 
	    (uint32_t)(tscFCvtt2n >> 32), (uint32_t)tscFCvtt2n,
	    (uint32_t)(tscFCvtn2t >> 32), (uint32_t)tscFCvtn2t,
	    tscGranularity);

    /*
     * Calculate conversion from BUS to TSC
     */
    bus2tsc = tmrCvt(busFCvtt2n, tscFCvtn2t);
}

void
tsc_get_info(tscInfo_t *info)
{
    info->busFCvtt2n     = busFCvtt2n;
    info->busFCvtn2t     = busFCvtn2t;
    info->tscFreq        = tscFreq;
    info->tscFCvtt2n     = tscFCvtt2n;
    info->tscFCvtn2t     = tscFCvtn2t;
    info->tscGranularity = tscGranularity;
    info->bus2tsc        = bus2tsc;
}

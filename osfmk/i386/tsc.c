/*
 * Copyright (c) 2005-2007 Apple Inc. All rights reserved.
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
#include <vm/vm_kern.h>         /* for kernel_map */
#include <architecture/i386/pio.h>
#include <i386/machine_cpu.h>
#include <i386/cpuid.h>
#include <i386/mp.h>
#include <i386/machine_routines.h>
#include <i386/proc_reg.h>
#include <i386/tsc.h>
#include <i386/misc_protos.h>
#include <pexpert/pexpert.h>
#include <machine/limits.h>
#include <machine/commpage.h>
#include <sys/kdebug.h>
#include <pexpert/device_tree.h>

uint64_t        busFCvtt2n = 0;
uint64_t        busFCvtn2t = 0;
uint64_t        tscFreq = 0;
uint64_t        tscFCvtt2n = 0;
uint64_t        tscFCvtn2t = 0;
uint64_t        tscGranularity = 0;
uint64_t        bus2tsc = 0;
uint64_t        busFreq = 0;
uint32_t        flex_ratio = 0;
uint32_t        flex_ratio_min = 0;
uint32_t        flex_ratio_max = 0;

uint64_t        tsc_at_boot = 0;

#define bit(n)          (1ULL << (n))
#define bitmask(h, l)    ((bit(h)|(bit(h)-1)) & ~(bit(l)-1))
#define bitfield(x, h, l) (((x) & bitmask(h,l)) >> l)

/* Decimal powers: */
#define kilo (1000ULL)
#define Mega (kilo * kilo)
#define Giga (kilo * Mega)
#define Tera (kilo * Giga)
#define Peta (kilo * Tera)

#define CPU_FAMILY_PENTIUM_M    (0x6)

/*
 * This routine extracts a frequency property in Hz from the device tree.
 * Also reads any initial TSC value at boot from the device tree.
 */
static uint64_t
EFI_get_frequency(const char *prop)
{
	uint64_t        frequency = 0;
	DTEntry         entry;
	void const      *value;
	unsigned int    size;

	if (SecureDTLookupEntry(0, "/efi/platform", &entry) != kSuccess) {
		kprintf("EFI_get_frequency: didn't find /efi/platform\n");
		return 0;
	}

	/*
	 * While we're here, see if EFI published an initial TSC value.
	 */
	if (SecureDTGetProperty(entry, "InitialTSC", &value, &size) == kSuccess) {
		if (size == sizeof(uint64_t)) {
			tsc_at_boot = *(uint64_t const *) value;
			kprintf("EFI_get_frequency: read InitialTSC: %llu\n",
			    tsc_at_boot);
		}
	}

	if (SecureDTGetProperty(entry, prop, &value, &size) != kSuccess) {
		kprintf("EFI_get_frequency: property %s not found\n", prop);
		return 0;
	}
	if (size == sizeof(uint64_t)) {
		frequency = *(uint64_t const *) value;
		kprintf("EFI_get_frequency: read %s value: %llu\n",
		    prop, frequency);
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
	boolean_t       N_by_2_bus_ratio = FALSE;

	if (cpuid_vmm_present()) {
		kprintf("VMM vendor %s TSC frequency %u KHz bus frequency %u KHz\n",
		    cpuid_vmm_family_string(),
		    cpuid_vmm_info()->cpuid_vmm_tsc_frequency,
		    cpuid_vmm_info()->cpuid_vmm_bus_frequency);

		if (cpuid_vmm_info()->cpuid_vmm_tsc_frequency &&
		    cpuid_vmm_info()->cpuid_vmm_bus_frequency) {
			busFreq = (uint64_t)cpuid_vmm_info()->cpuid_vmm_bus_frequency * kilo;
			busFCvtt2n = ((1 * Giga) << 32) / busFreq;
			busFCvtn2t = 0xFFFFFFFFFFFFFFFFULL / busFCvtt2n;

			tscFreq = (uint64_t)cpuid_vmm_info()->cpuid_vmm_tsc_frequency * kilo;
			tscFCvtt2n = ((1 * Giga) << 32) / tscFreq;
			tscFCvtn2t = 0xFFFFFFFFFFFFFFFFULL / tscFCvtt2n;

			tscGranularity = tscFreq / busFreq;

			bus2tsc = tmrCvt(busFCvtt2n, tscFCvtn2t);

			return;
		}
	}

	switch (cpuid_cpufamily()) {
	case CPUFAMILY_INTEL_KABYLAKE:
	case CPUFAMILY_INTEL_ICELAKE:
	case CPUFAMILY_INTEL_SKYLAKE: {
		/*
		 * SkyLake and later has an Always Running Timer (ART) providing
		 * the reference frequency. CPUID leaf 0x15 determines the
		 * rationship between this and the TSC frequency expressed as
		 *   -	multiplier (numerator, N), and
		 *   -	divisor (denominator, M).
		 * So that TSC = ART * N / M.
		 */
		i386_cpu_info_t *infop = cpuid_info();
		cpuid_tsc_leaf_t *tsc_leafp = &infop->cpuid_tsc_leaf;
		uint64_t         N = (uint64_t) tsc_leafp->numerator;
		uint64_t         M = (uint64_t) tsc_leafp->denominator;
		uint64_t         refFreq;

		refFreq = EFI_get_frequency("ARTFrequency");
		if (refFreq == 0) {
			/*
			 * Intel Scalable Processor (Xeon-SP) CPUs use a different
			 * ART frequency.  Use that default here if EFI didn't
			 * specify the frequency.  Since Xeon-SP uses the same
			 * DisplayModel / DisplayFamily as Xeon-W, we need to
			 * use the platform ID (or, as XNU calls it, the "processor
			 * flag") to differentiate the two.
			 */
			if (cpuid_family() == 0x06 &&
			    infop->cpuid_model == CPUID_MODEL_SKYLAKE_W &&
			    is_xeon_sp(infop->cpuid_processor_flag)) {
				refFreq = BASE_ART_CLOCK_SOURCE_SP;
			} else {
				refFreq = BASE_ART_CLOCK_SOURCE;
			}
		}

		assert(N != 0);
		assert(M != 1);
		tscFreq = refFreq * N / M;
		busFreq = tscFreq;              /* bus is APIC frequency */

		kprintf(" ART: Frequency = %6d.%06dMHz, N/M = %lld/%llu\n",
		    (uint32_t)(refFreq / Mega),
		    (uint32_t)(refFreq % Mega),
		    N, M);

		break;
	}
	default: {
		uint64_t msr_flex_ratio;
		uint64_t msr_platform_info;

		/* See if FLEX_RATIO is being used */
		msr_flex_ratio = rdmsr64(MSR_FLEX_RATIO);
		msr_platform_info = rdmsr64(MSR_PLATFORM_INFO);
		flex_ratio_min = (uint32_t)bitfield(msr_platform_info, 47, 40);
		flex_ratio_max = (uint32_t)bitfield(msr_platform_info, 15, 8);
		/* No BIOS-programed flex ratio. Use hardware max as default */
		tscGranularity = flex_ratio_max;
		if (msr_flex_ratio & bit(16)) {
			/* Flex Enabled: Use this MSR if less than max */
			flex_ratio = (uint32_t)bitfield(msr_flex_ratio, 15, 8);
			if (flex_ratio < flex_ratio_max) {
				tscGranularity = flex_ratio;
			}
		}

		busFreq = EFI_get_frequency("FSBFrequency");
		/* If EFI isn't configured correctly, use a constant
		 * value. See 6036811.
		 */
		if (busFreq == 0) {
			busFreq = BASE_NHM_CLOCK_SOURCE;
		}

		break;
	}
	case CPUFAMILY_INTEL_PENRYN: {
		uint64_t        prfsts;

		prfsts = rdmsr64(IA32_PERF_STS);
		tscGranularity = (uint32_t)bitfield(prfsts, 44, 40);
		N_by_2_bus_ratio = (prfsts & bit(46)) != 0;

		busFreq = EFI_get_frequency("FSBFrequency");
	}
	}

	if (busFreq != 0) {
		busFCvtt2n = ((1 * Giga) << 32) / busFreq;
		busFCvtn2t = 0xFFFFFFFFFFFFFFFFULL / busFCvtt2n;
	} else {
		panic("tsc_init: EFI not supported!\n");
	}

	kprintf(" BUS: Frequency = %6d.%06dMHz, "
	    "cvtt2n = %08X.%08X, cvtn2t = %08X.%08X\n",
	    (uint32_t)(busFreq / Mega),
	    (uint32_t)(busFreq % Mega),
	    (uint32_t)(busFCvtt2n >> 32), (uint32_t)busFCvtt2n,
	    (uint32_t)(busFCvtn2t >> 32), (uint32_t)busFCvtn2t);

	if (tscFreq == busFreq) {
		bus2tsc = 1;
		tscGranularity = 1;
		tscFCvtn2t = busFCvtn2t;
		tscFCvtt2n = busFCvtt2n;
	} else {
		/*
		 * Get the TSC increment.  The TSC is incremented by this
		 * on every bus tick.  Calculate the TSC conversion factors
		 * to and from nano-seconds.
		 * The tsc granularity is also called the "bus ratio".
		 * If the N/2 bit is set this indicates the bus ration is
		 * 0.5 more than this - i.e.  that the true bus ratio
		 * is (2*tscGranularity + 1)/2.
		 */
		if (N_by_2_bus_ratio) {
			tscFCvtt2n = busFCvtt2n * 2 / (1 + 2 * tscGranularity);
		} else {
			tscFCvtt2n = busFCvtt2n / tscGranularity;
		}

		tscFreq = ((1 * Giga) << 32) / tscFCvtt2n;
		tscFCvtn2t = 0xFFFFFFFFFFFFFFFFULL / tscFCvtt2n;

		/*
		 * Calculate conversion from BUS to TSC
		 */
		bus2tsc = tmrCvt(busFCvtt2n, tscFCvtn2t);
	}

	kprintf(" TSC: Frequency = %6d.%06dMHz, "
	    "cvtt2n = %08X.%08X, cvtn2t = %08X.%08X, gran = %lld%s\n",
	    (uint32_t)(tscFreq / Mega),
	    (uint32_t)(tscFreq % Mega),
	    (uint32_t)(tscFCvtt2n >> 32), (uint32_t)tscFCvtt2n,
	    (uint32_t)(tscFCvtn2t >> 32), (uint32_t)tscFCvtn2t,
	    tscGranularity, N_by_2_bus_ratio ? " (N/2)" : "");
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
	info->busFreq        = busFreq;
	info->flex_ratio     = flex_ratio;
	info->flex_ratio_min = flex_ratio_min;
	info->flex_ratio_max = flex_ratio_max;
}

#if DEVELOPMENT || DEBUG
void
cpu_data_tsc_sync_deltas_string(char *buf, uint32_t buflen,
    uint32_t start_cpu, uint32_t end_cpu)
{
	int cnt;
	uint32_t offset = 0;

	if (start_cpu >= real_ncpus || end_cpu >= real_ncpus) {
		if (buflen >= 1) {
			buf[0] = 0;
		}
		return;
	}

	for (uint32_t curcpu = start_cpu; curcpu <= end_cpu; curcpu++) {
		cnt = snprintf(buf + offset, buflen - offset, "0x%llx ", cpu_datap(curcpu)->tsc_sync_delta);
		if (cnt < 0 || (offset + (unsigned) cnt >= buflen)) {
			break;
		}
		offset += cnt;
	}
	if (offset >= 1) {
		buf[offset - 1] = 0;    /* Clip the final, trailing space */
	}
}
#endif /* DEVELOPMENT || DEBUG */

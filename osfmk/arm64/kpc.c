/*
 * Copyright (c) 2012-2016 Apple Inc. All rights reserved.
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

#include <arm/cpu_data_internal.h>
#include <arm/cpu_internal.h>
#include <kern/kalloc.h>
#include <kern/kpc.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <mach/mach_types.h>
#include <machine/machine_routines.h>
#include <stdint.h>
#include <sys/errno.h>

#if MONOTONIC
#include <kern/monotonic.h>
#endif /* MONOTONIC */

void kpc_pmi_handler(unsigned int ctr);

/*
 * PMCs 8 and 9 were added to Hurricane and to maintain the existing bit
 * positions of the other PMCs, their configuration bits start at position 32.
 */
#define PMCR_PMC_8_9_OFFSET     (32)
#define PMCR_PMC_8_9_SHIFT(PMC) (((PMC) - 8) + PMCR_PMC_8_9_OFFSET)
#define PMCR_PMC_SHIFT(PMC)     (((PMC) <= 7) ? (PMC) : \
                                  PMCR_PMC_8_9_SHIFT(PMC))

/*
 * PMCR0 controls enabling, interrupts, and overflow of performance counters.
 */

/* PMC is enabled */
#define PMCR0_PMC_ENABLE_MASK(PMC)  (UINT64_C(0x1) << PMCR_PMC_SHIFT(PMC))
#define PMCR0_PMC_DISABLE_MASK(PMC) (~PMCR0_PMC_ENABLE_MASK(PMC))

/* how interrupts are generated on PMIs */
#define PMCR0_INTGEN_SHIFT   (8)
#define PMCR0_INTGEN_MASK    (UINT64_C(0x7) << PMCR0_INTGEN_SHIFT)
#define PMCR0_INTGEN_OFF     (UINT64_C(0) << PMCR0_INTGEN_SHIFT)
#define PMCR0_INTGEN_PMI     (UINT64_C(1) << PMCR0_INTGEN_SHIFT)
#define PMCR0_INTGEN_AIC     (UINT64_C(2) << PMCR0_INTGEN_SHIFT)
#define PMCR0_INTGEN_DBG_HLT (UINT64_C(3) << PMCR0_INTGEN_SHIFT)
#define PMCR0_INTGEN_FIQ     (UINT64_C(4) << PMCR0_INTGEN_SHIFT)

/* 10 unused */

/* set by hardware if PMI was generated */
#define PMCR0_PMAI_SHIFT (11)
#define PMCR0_PMAI_MASK  (UINT64_C(1) << PMCR0_PMAI_SHIFT)

/* overflow on a PMC generates an interrupt */
#define PMCR0_PMI_OFFSET            (12)
#define PMCR0_PMI_SHIFT(PMC)        (PMCR0_PMI_OFFSET + PMCR_PMC_SHIFT(PMC))
#define PMCR0_PMI_ENABLE_MASK(PMC)  (UINT64_C(1) << PMCR0_PMI_SHIFT(PMC))
#define PMCR0_PMI_DISABLE_MASK(PMC) (~PMCR0_PMI_ENABLE_MASK(PMC))

/* disable counting when a PMI is signaled (except for AIC interrupts) */
#define PMCR0_DISCNT_SHIFT        (20)
#define PMCR0_DISCNT_ENABLE_MASK  (UINT64_C(1) << PMCR0_DISCNT_SHIFT)
#define PMCR0_DISCNT_DISABLE_MASK (~PMCR0_DISCNT_ENABLE_MASK)

/* 21 unused */

/* block PMIs until ERET retires */
#define PMCR0_WFRFE_SHIFT        (22)
#define PMCR0_WFRFE_ENABLE_MASK  (UINT64_C(1) << PMCR0_WFRE_SHIFT)
#define PMCR0_WFRFE_DISABLE_MASK (~PMCR0_WFRFE_ENABLE_MASK)

/* count global L2C events */
#define PMCR0_L2CGLOBAL_SHIFT        (23)
#define PMCR0_L2CGLOBAL_ENABLE_MASK  (UINT64_C(1) << PMCR0_L2CGLOBAL_SHIFT)
#define PMCR0_L2CGLOBAL_DISABLE_MASK (~PMCR0_L2CGLOBAL_ENABLE_MASK)

/* allow user mode access to configuration registers */
#define PMCR0_USEREN_SHIFT        (30)
#define PMCR0_USEREN_ENABLE_MASK  (UINT64_C(1) << PMCR0_USEREN_SHIFT)
#define PMCR0_USEREN_DISABLE_MASK (~PMCR0_USEREN_ENABLE_MASK)

/* force the CPMU clocks in case of a clocking bug */
#define PMCR0_CLKEN_SHIFT        (31)
#define PMCR0_CLKEN_ENABLE_MASK  (UINT64_C(1) << PMCR0_USEREN_SHIFT)
#define PMCR0_CLKEN_DISABLE_MASK (~PMCR0_CLKEN_ENABLE_MASK)

/* 32 - 44 mirror the low bits for PMCs 8 and 9 */

/* PMCR1 enables counters in different processor modes */

#define PMCR1_EL0_A32_OFFSET (0)
#define PMCR1_EL0_A64_OFFSET (8)
#define PMCR1_EL1_A64_OFFSET (16)
#define PMCR1_EL3_A64_OFFSET (24)

#define PMCR1_EL0_A32_SHIFT(PMC) (PMCR1_EL0_A32_OFFSET + PMCR_PMC_SHIFT(PMC))
#define PMCR1_EL0_A64_SHIFT(PMC) (PMCR1_EL0_A64_OFFSET + PMCR_PMC_SHIFT(PMC))
#define PMCR1_EL1_A64_SHIFT(PMC) (PMCR1_EL1_A64_OFFSET + PMCR_PMC_SHIFT(PMC))
#define PMCR1_EL3_A64_SHIFT(PMC) (PMCR1_EL0_A64_OFFSET + PMCR_PMC_SHIFT(PMC))

#define PMCR1_EL0_A32_ENABLE_MASK(PMC) (UINT64_C(1) << PMCR1_EL0_A32_SHIFT(PMC))
#define PMCR1_EL0_A64_ENABLE_MASK(PMC) (UINT64_C(1) << PMCR1_EL0_A64_SHIFT(PMC))
#define PMCR1_EL1_A64_ENABLE_MASK(PMC) (UINT64_C(1) << PMCR1_EL1_A64_SHIFT(PMC))
/* PMCR1_EL3_A64 is not supported on PMCs 8 and 9 */
#if NO_MONITOR
#define PMCR1_EL3_A64_ENABLE_MASK(PMC) UINT64_C(0)
#else
#define PMCR1_EL3_A64_ENABLE_MASK(PMC) (UINT64_C(1) << PMCR1_EL3_A64_SHIFT(PMC))
#endif

#define PMCR1_EL_ALL_ENABLE_MASK(PMC) (PMCR1_EL0_A32_ENABLE_MASK(PMC) | \
                                       PMCR1_EL0_A64_ENABLE_MASK(PMC) | \
                                       PMCR1_EL1_A64_ENABLE_MASK(PMC) | \
                                       PMCR1_EL3_A64_ENABLE_MASK(PMC))
#define PMCR1_EL_ALL_DISABLE_MASK(PMC) (~PMCR1_EL_ALL_ENABLE_MASK(PMC))

/* PMESR0 and PMESR1 are event selection registers */

/* PMESR0 selects which event is counted on PMCs 2, 3, 4, and 5 */
/* PMESR1 selects which event is counted on PMCs 6, 7, 8, and 9 */

#define PMESR_PMC_WIDTH           (8)
#define PMESR_PMC_MASK            (UINT8_MAX)
#define PMESR_SHIFT(PMC, OFF)     (8 * ((PMC) - (OFF)))
#define PMESR_EVT_MASK(PMC, OFF)  (PMESR_PMC_MASK << PMESR_SHIFT(PMC, OFF))
#define PMESR_EVT_CLEAR(PMC, OFF) (~PMESR_EVT_MASK(PMC, OFF))

#define PMESR_EVT_DECODE(PMESR, PMC, OFF) \
	(((PMESR) >> PMESR_SHIFT(PMC, OFF)) & PMESR_PMC_MASK)
#define PMESR_EVT_ENCODE(EVT, PMC, OFF) \
	(((EVT) & PMESR_PMC_MASK) << PMESR_SHIFT(PMC, OFF))

/* system registers in the CPMU */

#define SREG_PMCR0  "S3_1_c15_c0_0"
#define SREG_PMCR1  "S3_1_c15_c1_0"
#define SREG_PMCR2  "S3_1_c15_c2_0"
#define SREG_PMCR3  "S3_1_c15_c3_0"
#define SREG_PMCR4  "S3_1_c15_c4_0"
#define SREG_PMESR0 "S3_1_c15_c5_0"
#define SREG_PMESR1 "S3_1_c15_c6_0"
#define SREG_PMSR   "S3_1_c15_c13_0"
#define SREG_OPMAT0 "S3_1_c15_c7_0"
#define SREG_OPMAT1 "S3_1_c15_c8_0"
#define SREG_OPMSK0 "S3_1_c15_c9_0"
#define SREG_OPMSK1 "S3_1_c15_c10_0"

#define SREG_PMC0 "S3_2_c15_c0_0"
#define SREG_PMC1 "S3_2_c15_c1_0"
#define SREG_PMC2 "S3_2_c15_c2_0"
#define SREG_PMC3 "S3_2_c15_c3_0"
#define SREG_PMC4 "S3_2_c15_c4_0"
#define SREG_PMC5 "S3_2_c15_c5_0"
#define SREG_PMC6 "S3_2_c15_c6_0"
#define SREG_PMC7 "S3_2_c15_c7_0"
#define SREG_PMC8 "S3_2_c15_c9_0"
#define SREG_PMC9 "S3_2_c15_c10_0"

#if !defined(APPLECYCLONE)
#define SREG_PMMMAP   "S3_2_c15_c15_0"
#define SREG_PMTRHLD2 "S3_2_c15_c14_0"
#define SREG_PMTRHLD4 "S3_2_c15_c13_0"
#define SREG_PMTRHLD6 "S3_2_c15_c12_0"
#endif

/*
 * The low 8 bits of a configuration words select the event to program on
 * PMESR{0,1}. Bits 16-19 are mapped to PMCR1 bits.
 */
#define CFGWORD_EL0A32EN_MASK (0x10000)
#define CFGWORD_EL0A64EN_MASK (0x20000)
#define CFGWORD_EL1EN_MASK    (0x40000)
#define CFGWORD_EL3EN_MASK    (0x80000)
#define CFGWORD_ALLMODES_MASK (0xf0000)

/* ACC offsets for PIO */
#define ACC_CPMU_PMC0_OFFSET (0x200)
#define ACC_CPMU_PMC8_OFFSET (0x280)

/*
 * Macros for reading and writing system registers.
 *
 * SR must be one of the SREG_* defines above.
 */
#define SREG_WRITE(SR, V) __asm__ volatile("msr " SR ", %0 ; isb" : : "r"(V))
#define SREG_READ(SR)     ({ uint64_t VAL; \
                             __asm__ volatile("mrs %0, " SR : "=r"(VAL)); \
                             VAL; })

/*
 * Configuration registers that can be controlled by RAWPMU:
 *
 * All: PMCR2-4, OPMAT0-1, OPMSK0-1.
 * Typhoon/Twister/Hurricane: PMMMAP, PMTRHLD2/4/6.
 */
#if defined(APPLECYCLONE)
#define RAWPMU_CONFIG_COUNT 7
#else
#define RAWPMU_CONFIG_COUNT 11
#endif

/* TODO: allocate dynamically */
static uint64_t saved_PMCR[MAX_CPUS][2];
static uint64_t saved_PMESR[MAX_CPUS][2];
static uint64_t saved_RAWPMU[MAX_CPUS][RAWPMU_CONFIG_COUNT];
static uint64_t saved_counter[MAX_CPUS][KPC_MAX_COUNTERS];
static uint64_t kpc_running_cfg_pmc_mask = 0;
static uint32_t kpc_running_classes = 0;
static uint32_t kpc_configured = 0;

/*
 * The whitelist is disabled by default on development/debug kernel. This can
 * be changed via the kpc.disable_whitelist sysctl. The whitelist is enabled on
 * release kernel and cannot be disabled.
 */
#if DEVELOPMENT || DEBUG
static boolean_t whitelist_disabled = TRUE;
#else
static boolean_t whitelist_disabled = FALSE;
#endif

/* List of counter events that are allowed externally */
static kpc_config_t whitelist[] = {
	0,    /* NO_EVENT */

#if defined(APPLECYCLONE)
	0x02, /* CORE_CYCLE */
	0x19, /* BIU_UPSTREAM_CYCLE */
	0x1a, /* BIU_DOWNSTREAM_CYCLE */
	0x22, /* L2C_AGENT_LD */
	0x23, /* L2C_AGENT_LD_MISS */
	0x24, /* L2C_AGENT_ST */
	0x25, /* L2C_AGENT_ST_MISS */
	0x78, /* INST_A32 */
	0x79, /* INST_THUMB */
	0x7a, /* INST_A64 */
	0x7b, /* INST_BRANCH */
	0xb4, /* SYNC_DC_LOAD_MISS */
	0xb5, /* SYNC_DC_STORE_MISS */
	0xb6, /* SYNC_DTLB_MISS */
	0xb9, /* SYNC_ST_HIT_YNGR_LD */
	0xc0, /* SYNC_BR_ANY_MISP */
	0xce, /* FED_IC_MISS_DEM */
	0xcf, /* FED_ITLB_MISS */

#elif defined(APPLETYPHOON)
	0x02, /* CORE_CYCLE */
	0x13, /* BIU_UPSTREAM_CYCLE */
	0x14, /* BIU_DOWNSTREAM_CYCLE */
	0x1a, /* L2C_AGENT_LD */
	0x1b, /* L2C_AGENT_LD_MISS */
	0x1c, /* L2C_AGENT_ST */
	0x1d, /* L2C_AGENT_ST_MISS */
	0x8a, /* INST_A32 */
	0x8b, /* INST_THUMB */
	0x8c, /* INST_A64 */
	0x8d, /* INST_BRANCH */
	0xbf, /* SYNC_DC_LOAD_MISS */
	0xc0, /* SYNC_DC_STORE_MISS */
	0xc1, /* SYNC_DTLB_MISS */
	0xc4, /* SYNC_ST_HIT_YNGR_LD */
	0xcb, /* SYNC_BR_ANY_MISP */
	0xd3, /* FED_IC_MISS_DEM */
	0xd4, /* FED_ITLB_MISS */

#elif defined(APPLETWISTER) || defined(APPLEHURRICANE)
	0x02, /* CORE_CYCLE */
	0x1a, /* L2C_AGENT_LD */
	0x1b, /* L2C_AGENT_LD_MISS */
	0x1c, /* L2C_AGENT_ST */
	0x1d, /* L2C_AGENT_ST_MISS */
	0x8a, /* INST_A32 */
	0x8b, /* INST_THUMB */
	0x8c, /* INST_A64 */
	0x8d, /* INST_BRANCH */
	0xbf, /* SYNC_DC_LOAD_MISS */
	0xc0, /* SYNC_DC_STORE_MISS */
	0xc1, /* SYNC_DTLB_MISS */
	0xc4, /* SYNC_ST_HIT_YNGR_LD */
	0xcb, /* SYNC_BR_ANY_MISP */
	0xd3, /* FED_IC_MISS_DEM */
	0xd4, /* FED_ITLB_MISS */

#elif defined(APPLEMONSOON)
	0x02, /* CORE_CYCLE */
	0x8a, /* INST_A32 */
	0x8b, /* INST_THUMB */
	0x8c, /* INST_A64 */
	0x8d, /* INST_BRANCH */
	0xbf, /* SYNC_DC_LOAD_MISS */
	0xc0, /* SYNC_DC_STORE_MISS */
	0xc1, /* SYNC_DTLB_MISS */
	0xc4, /* SYNC_ST_HIT_YNGR_LD */
	0xcb, /* SYNC_BR_ANY_MISP */
	0xd3, /* FED_IC_MISS_DEM */
	0xd4, /* FED_ITLB_MISS */

#else
	/* An unknown CPU gets a trivial { NO_EVENT } whitelist. */
#endif
};
#define WHITELIST_COUNT (sizeof(whitelist)/sizeof(*whitelist))

static boolean_t
config_in_whitelist(kpc_config_t cfg)
{
	unsigned int i;

	for (i = 0; i < WHITELIST_COUNT; i++) {
		if (cfg == whitelist[i]) {
			return TRUE;
		}
	}

	return FALSE;
}

#ifdef KPC_DEBUG
static void dump_regs(void)
{
	uint64_t val;
	kprintf("PMCR0 = 0x%" PRIx64 "\n", SREG_READ(SREG_PMCR0));
	kprintf("PMCR1 = 0x%" PRIx64 "\n", SREG_READ(SREG_PMCR1));
	kprintf("PMCR2 = 0x%" PRIx64 "\n", SREG_READ(SREG_PMCR2));
	kprintf("PMCR3 = 0x%" PRIx64 "\n", SREG_READ(SREG_PMCR3));
	kprintf("PMCR4 = 0x%" PRIx64 "\n", SREG_READ(SREG_PMCR4));
	kprintf("PMESR0 = 0x%" PRIx64 "\n", SREG_READ(SREG_PMESR0));
	kprintf("PMESR1 = 0x%" PRIx64 "\n", SREG_READ(SREG_PMESR1));

	kprintf("PMC0 = 0x%" PRIx64 "\n", SREG_READ(SREG_PMC0));
	kprintf("PMC1 = 0x%" PRIx64 "\n", SREG_READ(SREG_PMC1));
	kprintf("PMC2 = 0x%" PRIx64 "\n", SREG_READ(SREG_PMC2));
	kprintf("PMC3 = 0x%" PRIx64 "\n", SREG_READ(SREG_PMC3));
	kprintf("PMC4 = 0x%" PRIx64 "\n", SREG_READ(SREG_PMC4));
	kprintf("PMC5 = 0x%" PRIx64 "\n", SREG_READ(SREG_PMC5));
	kprintf("PMC6 = 0x%" PRIx64 "\n", SREG_READ(SREG_PMC6));
	kprintf("PMC7 = 0x%" PRIx64 "\n", SREG_READ(SREG_PMC7));

#if (KPC_ARM64_CONFIGURABLE_COUNT > 6)
	kprintf("PMC8 = 0x%" PRIx64 "\n", SREG_READ(SREG_PMC8));
	kprintf("PMC9 = 0x%" PRIx64 "\n", SREG_READ(SREG_PMC9));
#endif
}
#endif

static boolean_t
enable_counter(uint32_t counter)
{
	int cpuid = cpu_number();
	uint64_t pmcr0 = 0, intgen_type;
	boolean_t counter_running, pmi_enabled, intgen_correct, enabled;

	pmcr0 = SREG_READ(SREG_PMCR0) | 0x3 /* leave the fixed counters enabled for monotonic */;

	counter_running = (pmcr0 & PMCR0_PMC_ENABLE_MASK(counter)) != 0;
	pmi_enabled = (pmcr0 & PMCR0_PMI_ENABLE_MASK(counter)) != 0;

	/* TODO this should use the PMI path rather than AIC for the interrupt
	 *      as it is faster
	 */
	intgen_type = PMCR0_INTGEN_AIC;
	intgen_correct = (pmcr0 & PMCR0_INTGEN_MASK) == intgen_type;

	enabled = counter_running && pmi_enabled && intgen_correct;

	if (!enabled) {
		pmcr0 |= PMCR0_PMC_ENABLE_MASK(counter);
		pmcr0 |= PMCR0_PMI_ENABLE_MASK(counter);
		pmcr0 &= ~PMCR0_INTGEN_MASK;
		pmcr0 |= intgen_type;

		SREG_WRITE(SREG_PMCR0, pmcr0);
	}

	saved_PMCR[cpuid][0] = pmcr0;
	return enabled;
}

static boolean_t
disable_counter(uint32_t counter)
{
	uint64_t pmcr0;
	boolean_t enabled;
	int cpuid = cpu_number();

	if (counter < 2) {
		return true;
	}

	pmcr0 = SREG_READ(SREG_PMCR0) | 0x3;
	enabled = (pmcr0 & PMCR0_PMC_ENABLE_MASK(counter)) != 0;

	if (enabled) {
		pmcr0 &= PMCR0_PMC_DISABLE_MASK(counter);
		SREG_WRITE(SREG_PMCR0, pmcr0);
	}

	saved_PMCR[cpuid][0] = pmcr0;
	return enabled;
}

/*
 * Enable counter in processor modes determined by configuration word.
 */
static void
set_modes(uint32_t counter, kpc_config_t cfgword)
{
	uint64_t bits = 0;
	int cpuid = cpu_number();

	if (cfgword & CFGWORD_EL0A32EN_MASK) {
		bits |= PMCR1_EL0_A32_ENABLE_MASK(counter);
	}
	if (cfgword & CFGWORD_EL0A64EN_MASK) {
		bits |= PMCR1_EL0_A64_ENABLE_MASK(counter);
	}
	if (cfgword & CFGWORD_EL1EN_MASK) {
		bits |= PMCR1_EL1_A64_ENABLE_MASK(counter);
	}
#if !NO_MONITOR
	if (cfgword & CFGWORD_EL3EN_MASK) {
		bits |= PMCR1_EL3_A64_ENABLE_MASK(counter);
	}
#endif

	/*
	 * Backwards compatibility: Writing a non-zero configuration word with
	 * all zeros in bits 16-19 is interpreted as enabling in all modes.
	 * This matches the behavior when the PMCR1 bits weren't exposed.
	 */
	if (bits == 0 && cfgword != 0) {
		bits = PMCR1_EL_ALL_ENABLE_MASK(counter);
	}

	uint64_t pmcr1 = SREG_READ(SREG_PMCR1);
	pmcr1 &= PMCR1_EL_ALL_DISABLE_MASK(counter);
	pmcr1 |= bits;
	pmcr1 |= 0x30303; /* monotonic compatibility */
	SREG_WRITE(SREG_PMCR1, pmcr1);
	saved_PMCR[cpuid][1] = pmcr1;
}

static uint64_t
read_counter(uint32_t counter)
{
	switch (counter) {
		// case 0: return SREG_READ(SREG_PMC0);
		// case 1: return SREG_READ(SREG_PMC1);
		case 2: return SREG_READ(SREG_PMC2);
		case 3: return SREG_READ(SREG_PMC3);
		case 4: return SREG_READ(SREG_PMC4);
		case 5: return SREG_READ(SREG_PMC5);
		case 6: return SREG_READ(SREG_PMC6);
		case 7: return SREG_READ(SREG_PMC7);
#if (KPC_ARM64_CONFIGURABLE_COUNT > 6)
		case 8: return SREG_READ(SREG_PMC8);
		case 9: return SREG_READ(SREG_PMC9);
#endif
		default: return 0;
	}
}

static void
write_counter(uint32_t counter, uint64_t value)
{
	switch (counter) {
		// case 0: SREG_WRITE(SREG_PMC0, value); break;
		// case 1: SREG_WRITE(SREG_PMC1, value); break;
		case 2: SREG_WRITE(SREG_PMC2, value); break;
		case 3: SREG_WRITE(SREG_PMC3, value); break;
		case 4: SREG_WRITE(SREG_PMC4, value); break;
		case 5: SREG_WRITE(SREG_PMC5, value); break;
		case 6: SREG_WRITE(SREG_PMC6, value); break;
		case 7: SREG_WRITE(SREG_PMC7, value); break;
#if (KPC_ARM64_CONFIGURABLE_COUNT > 6)
		case 8: SREG_WRITE(SREG_PMC8, value); break;
		case 9: SREG_WRITE(SREG_PMC9, value); break;
#endif
		default: break;
	}
}

uint32_t
kpc_rawpmu_config_count(void)
{
	return RAWPMU_CONFIG_COUNT;
}

int
kpc_get_rawpmu_config(kpc_config_t *configv)
{
	configv[0] = SREG_READ(SREG_PMCR2);
	configv[1] = SREG_READ(SREG_PMCR3);
	configv[2] = SREG_READ(SREG_PMCR4);
	configv[3] = SREG_READ(SREG_OPMAT0);
	configv[4] = SREG_READ(SREG_OPMAT1);
	configv[5] = SREG_READ(SREG_OPMSK0);
	configv[6] = SREG_READ(SREG_OPMSK1);
#if RAWPMU_CONFIG_COUNT > 7
	configv[7] = SREG_READ(SREG_PMMMAP);
	configv[8] = SREG_READ(SREG_PMTRHLD2);
	configv[9] = SREG_READ(SREG_PMTRHLD4);
	configv[10] = SREG_READ(SREG_PMTRHLD6);
#endif
	return 0;
}

static int
kpc_set_rawpmu_config(kpc_config_t *configv)
{
	SREG_WRITE(SREG_PMCR2, configv[0]);
	SREG_WRITE(SREG_PMCR3, configv[1]);
	SREG_WRITE(SREG_PMCR4, configv[2]);
	SREG_WRITE(SREG_OPMAT0, configv[3]);
	SREG_WRITE(SREG_OPMAT1, configv[4]);
	SREG_WRITE(SREG_OPMSK0, configv[5]);
	SREG_WRITE(SREG_OPMSK1, configv[6]);
#if RAWPMU_CONFIG_COUNT > 7
	SREG_WRITE(SREG_PMMMAP, configv[7]);
	SREG_WRITE(SREG_PMTRHLD2, configv[8]);
	SREG_WRITE(SREG_PMTRHLD4, configv[9]);
	SREG_WRITE(SREG_PMTRHLD6, configv[10]);
#endif
	return 0;
}

static void
save_regs(void)
{
	int cpuid = cpu_number();

	__asm__ volatile("dmb ish");

	assert(ml_get_interrupts_enabled() == FALSE);

	/* Save current PMCR0/1 values. PMCR2-4 are in the RAWPMU set. */
	saved_PMCR[cpuid][0] = SREG_READ(SREG_PMCR0) | 0x3;

	/* Save event selections. */
	saved_PMESR[cpuid][0] = SREG_READ(SREG_PMESR0);
	saved_PMESR[cpuid][1] = SREG_READ(SREG_PMESR1);

	kpc_get_rawpmu_config(saved_RAWPMU[cpuid]);

	/* Disable the counters. */
	// SREG_WRITE(SREG_PMCR0, clear);

	/* Finally, save state for each counter*/
	for (int i = 2; i < KPC_ARM64_PMC_COUNT; i++) {
		saved_counter[cpuid][i] = read_counter(i);
	}
}

static void
restore_regs(void)
{
	int cpuid = cpu_number();

	/* Restore PMESR values. */
	SREG_WRITE(SREG_PMESR0, saved_PMESR[cpuid][0]);
	SREG_WRITE(SREG_PMESR1, saved_PMESR[cpuid][1]);

	kpc_set_rawpmu_config(saved_RAWPMU[cpuid]);

	/* Restore counter values */
	for (int i = 2; i < KPC_ARM64_PMC_COUNT; i++) {
		write_counter(i, saved_counter[cpuid][i]);
	}

	/* Restore PMCR0/1 values (with PMCR0 last to enable). */
	SREG_WRITE(SREG_PMCR1, saved_PMCR[cpuid][1] | 0x30303);
	SREG_WRITE(SREG_PMCR0, saved_PMCR[cpuid][0] | 0x3);
}

static uint64_t
get_counter_config(uint32_t counter)
{
	uint64_t pmesr;

	switch (counter) {
		case 2: /* FALLTHROUGH */
		case 3: /* FALLTHROUGH */
		case 4: /* FALLTHROUGH */
		case 5:
			pmesr = PMESR_EVT_DECODE(SREG_READ(SREG_PMESR0), counter, 2);
			break;
		case 6: /* FALLTHROUGH */
		case 7:
#if (KPC_ARM64_CONFIGURABLE_COUNT > 6)
			/* FALLTHROUGH */
		case 8: /* FALLTHROUGH */
		case 9:
#endif
			pmesr = PMESR_EVT_DECODE(SREG_READ(SREG_PMESR1), counter, 6);
			break;
		default:
			pmesr = 0;
			break;
	}

	kpc_config_t config = pmesr;

	uint64_t pmcr1 = SREG_READ(SREG_PMCR1);

	if (pmcr1 & PMCR1_EL0_A32_ENABLE_MASK(counter)) {
		config |= CFGWORD_EL0A32EN_MASK;
	}
	if (pmcr1 & PMCR1_EL0_A64_ENABLE_MASK(counter)) {
		config |= CFGWORD_EL0A64EN_MASK;
	}
	if (pmcr1 & PMCR1_EL1_A64_ENABLE_MASK(counter)) {
		config |= CFGWORD_EL1EN_MASK;
#if NO_MONITOR
		config |= CFGWORD_EL3EN_MASK;
#endif
	}
#if !NO_MONITOR
	if (pmcr1 & PMCR1_EL3_A64_ENABLE_MASK(counter)) {
		config |= CFGWORD_EL3EN_MASK;
	}
#endif

	return config;
}

static void
set_counter_config(uint32_t counter, uint64_t config)
{
	int cpuid = cpu_number();
	uint64_t pmesr = 0;

	switch (counter) {
		case 2: /* FALLTHROUGH */
		case 3: /* FALLTHROUGH */
		case 4: /* FALLTHROUGH */
		case 5:
			pmesr = SREG_READ(SREG_PMESR0);
			pmesr &= PMESR_EVT_CLEAR(counter, 2);
			pmesr |= PMESR_EVT_ENCODE(config, counter, 2);
			SREG_WRITE(SREG_PMESR0, pmesr);
			saved_PMESR[cpuid][0] = pmesr;
			break;

		case 6: /* FALLTHROUGH */
		case 7:
#if KPC_ARM64_CONFIGURABLE_COUNT > 6
			/* FALLTHROUGH */
		case 8: /* FALLTHROUGH */
		case 9:
#endif
			pmesr = SREG_READ(SREG_PMESR1);
			pmesr &= PMESR_EVT_CLEAR(counter, 6);
			pmesr |= PMESR_EVT_ENCODE(config, counter, 6);
			SREG_WRITE(SREG_PMESR1, pmesr);
			saved_PMESR[cpuid][1] = pmesr;
			break;
		default:
			break;
	}

	set_modes(counter, config);
}

/* internal functions */

void
kpc_arch_init(void)
{
}

boolean_t
kpc_is_running_fixed(void)
{
	return (kpc_running_classes & KPC_CLASS_FIXED_MASK) == KPC_CLASS_FIXED_MASK;
}

boolean_t
kpc_is_running_configurable(uint64_t pmc_mask)
{
	assert(kpc_popcount(pmc_mask) <= kpc_configurable_count());
	return ((kpc_running_classes & KPC_CLASS_CONFIGURABLE_MASK) == KPC_CLASS_CONFIGURABLE_MASK) &&
	       ((kpc_running_cfg_pmc_mask & pmc_mask) == pmc_mask);
}

uint32_t
kpc_fixed_count(void)
{
	return KPC_ARM64_FIXED_COUNT;
}

uint32_t
kpc_configurable_count(void)
{
	return KPC_ARM64_CONFIGURABLE_COUNT;
}

uint32_t
kpc_fixed_config_count(void)
{
	return 0;
}

uint32_t
kpc_configurable_config_count(uint64_t pmc_mask)
{
	assert(kpc_popcount(pmc_mask) <= kpc_configurable_count());
	return kpc_popcount(pmc_mask);
}

int
kpc_get_fixed_config(kpc_config_t *configv __unused)
{
	return 0;
}

uint64_t
kpc_fixed_max(void)
{
	return (1ULL << KPC_ARM64_COUNTER_WIDTH) - 1;
}

uint64_t
kpc_configurable_max(void)
{
	return (1ULL << KPC_ARM64_COUNTER_WIDTH) - 1;
}

static void
set_running_configurable(uint64_t target_mask, uint64_t state_mask)
{
	uint32_t cfg_count = kpc_configurable_count(), offset = kpc_fixed_count();
	boolean_t enabled;

	enabled = ml_set_interrupts_enabled(FALSE);

	for (uint32_t i = 0; i < cfg_count; ++i) {
		if (((1ULL << i) & target_mask) == 0)
			continue;
		assert(kpc_controls_counter(offset + i));

		if ((1ULL << i) & state_mask) {
			enable_counter(offset + i);
		} else {
			disable_counter(offset + i);
		}
	}

	ml_set_interrupts_enabled(enabled);
}

static uint32_t kpc_xcall_sync;
static void
kpc_set_running_xcall( void *vstate )
{
	struct kpc_running_remote *mp_config = (struct kpc_running_remote*) vstate;
	assert(mp_config);

	set_running_configurable(mp_config->cfg_target_mask,
				 mp_config->cfg_state_mask);

	if (hw_atomic_sub(&kpc_xcall_sync, 1) == 0)
		thread_wakeup((event_t) &kpc_xcall_sync);
}

static uint32_t kpc_xread_sync;
static void
kpc_get_curcpu_counters_xcall(void *args)
{
	struct kpc_get_counters_remote *handler = args;

	assert(handler != NULL);
	assert(handler->buf != NULL);

	int offset = cpu_number() * handler->buf_stride;
	int r = kpc_get_curcpu_counters(handler->classes, NULL, &handler->buf[offset]);

	/* number of counters added by this CPU, needs to be atomic  */
	hw_atomic_add(&(handler->nb_counters), r);

	if (hw_atomic_sub(&kpc_xread_sync, 1) == 0) {
		thread_wakeup((event_t) &kpc_xread_sync);
	}
}

int
kpc_get_all_cpus_counters(uint32_t classes, int *curcpu, uint64_t *buf)
{
	assert(buf != NULL);

	int enabled = ml_set_interrupts_enabled(FALSE);

	/* grab counters and CPU number as close as possible */
	if (curcpu) {
		*curcpu = current_processor()->cpu_id;
	}

	struct kpc_get_counters_remote hdl = {
		.classes = classes,
		.nb_counters = 0,
		.buf = buf,
		.buf_stride = kpc_get_counter_count(classes)
	};

	cpu_broadcast_xcall(&kpc_xread_sync, TRUE, kpc_get_curcpu_counters_xcall, &hdl);
	int offset = hdl.nb_counters;

	(void)ml_set_interrupts_enabled(enabled);

	return offset;
}

int
kpc_get_fixed_counters(uint64_t *counterv)
{
#if MONOTONIC
	mt_fixed_counts(counterv);
	return 0;
#else /* MONOTONIC */
#pragma unused(counterv)
	return ENOTSUP;
#endif /* !MONOTONIC */
}

int
kpc_get_configurable_counters(uint64_t *counterv, uint64_t pmc_mask)
{
	uint32_t cfg_count = kpc_configurable_count(), offset = kpc_fixed_count();
	uint64_t ctr = 0ULL;

	assert(counterv);

	for (uint32_t i = 0; i < cfg_count; ++i) {
		if (((1ULL << i) & pmc_mask) == 0)
			continue;
		ctr = read_counter(i + offset);

		if (ctr & KPC_ARM64_COUNTER_OVF_MASK) {
			ctr = CONFIGURABLE_SHADOW(i) +
				(kpc_configurable_max() - CONFIGURABLE_RELOAD(i) + 1 /* Wrap */) +
				(ctr & KPC_ARM64_COUNTER_MASK);
		} else {
			ctr = CONFIGURABLE_SHADOW(i) +
				(ctr - CONFIGURABLE_RELOAD(i));
		}

		*counterv++ = ctr;
	}

	return 0;
}

int
kpc_get_configurable_config(kpc_config_t *configv, uint64_t pmc_mask)
{
	uint32_t cfg_count = kpc_configurable_count(), offset = kpc_fixed_count();

	assert(configv);

	for (uint32_t i = 0; i < cfg_count; ++i)
		if ((1ULL << i) & pmc_mask)
			*configv++ = get_counter_config(i + offset);
	return 0;
}

static int
kpc_set_configurable_config(kpc_config_t *configv, uint64_t pmc_mask)
{
	uint32_t cfg_count = kpc_configurable_count(), offset = kpc_fixed_count();
	boolean_t enabled;

	assert(configv);

	enabled = ml_set_interrupts_enabled(FALSE);

	for (uint32_t i = 0; i < cfg_count; ++i) {
		if (((1ULL << i) & pmc_mask) == 0)
			continue;
		assert(kpc_controls_counter(i + offset));

		set_counter_config(i + offset, *configv++);
	}

	ml_set_interrupts_enabled(enabled);

	return 0;
}

static uint32_t kpc_config_sync;
static void
kpc_set_config_xcall(void *vmp_config)
{
	struct kpc_config_remote *mp_config = vmp_config;
	kpc_config_t *new_config = NULL;
	uint32_t classes = 0ULL;

	assert(mp_config);
	assert(mp_config->configv);
	classes = mp_config->classes;
	new_config = mp_config->configv;

	if (classes & KPC_CLASS_CONFIGURABLE_MASK) {
		kpc_set_configurable_config(new_config, mp_config->pmc_mask);
		new_config += kpc_popcount(mp_config->pmc_mask);
	}

	if (classes & KPC_CLASS_RAWPMU_MASK) {
		kpc_set_rawpmu_config(new_config);
		new_config += RAWPMU_CONFIG_COUNT;
	}

	if (hw_atomic_sub(&kpc_config_sync, 1) == 0)
		thread_wakeup((event_t) &kpc_config_sync);
}

static uint64_t
kpc_reload_counter(uint32_t ctr)
{
	assert(ctr < (kpc_configurable_count() + kpc_fixed_count()));

	/* don't reload counters reserved for power management */
	if (!kpc_controls_counter(ctr))
		return 0ULL;

	uint64_t old = read_counter(ctr);
	write_counter(ctr, FIXED_RELOAD(ctr));
	return old & KPC_ARM64_COUNTER_MASK;
}

static uint32_t kpc_reload_sync;
static void
kpc_set_reload_xcall(void *vmp_config)
{
	struct kpc_config_remote *mp_config = vmp_config;
	uint32_t classes = 0, count = 0, offset = kpc_fixed_count();
	uint64_t *new_period = NULL, max = kpc_configurable_max();
	boolean_t enabled;

	assert(mp_config);
	assert(mp_config->configv);
	classes = mp_config->classes;
	new_period = mp_config->configv;

	enabled = ml_set_interrupts_enabled(FALSE);

	if (classes & KPC_CLASS_CONFIGURABLE_MASK) {
		/*
		 * Update _all_ shadow counters, this cannot be done for only
		 * selected PMCs. Otherwise, we would corrupt the configurable
		 * shadow buffer since the PMCs are muxed according to the pmc
		 * mask.
		 */
		uint64_t all_cfg_mask = (1ULL << kpc_configurable_count()) - 1;
		kpc_get_configurable_counters(&CONFIGURABLE_SHADOW(0), all_cfg_mask);

		/* set the new period */
		count = kpc_configurable_count();
		for (uint32_t i = 0; i < count; ++i) {
			/* ignore the counter */
			if (((1ULL << i) & mp_config->pmc_mask) == 0)
				continue;
			if (*new_period == 0)
				*new_period = kpc_configurable_max();
			CONFIGURABLE_RELOAD(i) = max - *new_period;
			/* reload the counter */
			kpc_reload_counter(offset + i);
			/* next period value */
			new_period++;
		}
	}

	ml_set_interrupts_enabled(enabled);

	if (hw_atomic_sub(&kpc_reload_sync, 1) == 0)
		thread_wakeup((event_t) &kpc_reload_sync);
}

void
kpc_pmi_handler(unsigned int ctr)
{
	uint64_t extra = kpc_reload_counter(ctr);

	FIXED_SHADOW(ctr) += (kpc_fixed_max() - FIXED_RELOAD(ctr) + 1 /* Wrap */) + extra;

	if (FIXED_ACTIONID(ctr)) {
		kpc_sample_kperf(FIXED_ACTIONID(ctr));
	}
}

uint32_t
kpc_get_classes(void)
{
	return KPC_CLASS_FIXED_MASK | KPC_CLASS_CONFIGURABLE_MASK | KPC_CLASS_RAWPMU_MASK;
}

int
kpc_set_running_arch(struct kpc_running_remote *mp_config)
{
	assert(mp_config != NULL);

	/* dispatch to all CPUs */
	cpu_broadcast_xcall(&kpc_xcall_sync, TRUE, kpc_set_running_xcall, mp_config);

	kpc_running_cfg_pmc_mask = mp_config->cfg_state_mask;
	kpc_running_classes = mp_config->classes;
	kpc_configured = 1;

	return 0;
}

int
kpc_set_period_arch(struct kpc_config_remote *mp_config)
{
	assert(mp_config);

	/* dispatch to all CPUs */
	cpu_broadcast_xcall(&kpc_reload_sync, TRUE, kpc_set_reload_xcall, mp_config);

	kpc_configured = 1;

	return 0;
}

int
kpc_set_config_arch(struct kpc_config_remote *mp_config)
{
	uint32_t count = kpc_popcount(mp_config->pmc_mask);

	assert(mp_config);
	assert(mp_config->configv);

	/* check config against whitelist for external devs */
	for (uint32_t i = 0; i < count; ++i) {
		if (!whitelist_disabled && !config_in_whitelist(mp_config->configv[i])) {
			return EPERM;
		}
	}

	/* dispatch to all CPUs */
	cpu_broadcast_xcall(&kpc_config_sync, TRUE, kpc_set_config_xcall, mp_config);

	kpc_configured = 1;

	return 0;
}

void 
kpc_idle(void)
{
	if (kpc_configured) {
		save_regs();
	}
}

void 
kpc_idle_exit(void) 
{
	if (kpc_configured) {
		restore_regs();
	}
}

int
kpc_set_sw_inc( uint32_t mask __unused )
{
	return ENOTSUP;
}

int
kpc_disable_whitelist( int val )
{
	whitelist_disabled = val;
	return 0;
}

int
kpc_get_whitelist_disabled( void )
{
	return whitelist_disabled;
}

int
kpc_get_pmu_version(void)
{
	return KPC_PMU_ARM_APPLE;
}

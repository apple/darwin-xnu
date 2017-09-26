/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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
#include <arm/machine_routines.h>
#include <arm64/monotonic.h>
#include <kern/assert.h> /* static_assert, assert */
#include <kern/debug.h> /* panic */
#include <kern/monotonic.h>
#include <machine/limits.h> /* CHAR_BIT */
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/monotonic.h>
#include <pexpert/arm64/board_config.h>
#include <pexpert/pexpert.h>

#pragma mark core counters

bool mt_core_supported = true;
void mt_fiq_internal(uint64_t upmsr);

/*
 * PMC[0-1] are the 48-bit fixed counters -- PMC0 is cycles and PMC1 is
 * instructions (see arm64/monotonic.h).
 *
 * PMC2+ are currently handled by kpc.
 */

#define PMC0 "s3_2_c15_c0_0"
#define PMC1 "s3_2_c15_c1_0"
#define PMC2 "s3_2_c15_c2_0"
#define PMC3 "s3_2_c15_c3_0"
#define PMC4 "s3_2_c15_c4_0"
#define PMC5 "s3_2_c15_c5_0"
#define PMC6 "s3_2_c15_c6_0"
#define PMC7 "s3_2_c15_c7_0"
#define PMC8 "s3_2_c15_c9_0"
#define PMC9 "s3_2_c15_c10_0"

#define CYCLES 0
#define INSTRS 1

/*
 * PMC0's offset into a core's PIO range.
 *
 * This allows cores to remotely query another core's counters.
 */

#define PIO_PMC0_OFFSET (0x200)

/*
 * The offset of the counter in the configuration registers.  Post-Hurricane
 * devices have additional counters that need a larger shift than the original
 * counters.
 *
 * XXX For now, just support the lower-numbered counters.
 */
#define CTR_POS(CTR) (CTR)

/*
 * PMCR0 is the main control register for the performance monitor.  It
 * controls whether the counters are enabled, how they deliver interrupts, and
 * other features.
 */

#define PMCR0 "s3_1_c15_c0_0"

#define PMCR0_CTR_EN(CTR) (UINT64_C(1) << CTR_POS(CTR))
#define PMCR0_FIXED_EN (PMCR0_CTR_EN(CYCLES) | PMCR0_CTR_EN(INSTRS))
/* how interrupts are delivered on a PMI */
enum {
	PMCR0_INTGEN_OFF = 0,
	PMCR0_INTGEN_PMI = 1,
	PMCR0_INTGEN_AIC = 2,
	PMCR0_INTGEN_HALT = 3,
	PMCR0_INTGEN_FIQ = 4,
};
#define PMCR0_INTGEN_SET(INT) ((uint64_t)(INT) << 8)
/* use AIC for backwards compatibility with kpc */
#define PMCR0_INTGEN_INIT PMCR0_INTGEN_SET(PMCR0_INTGEN_AIC)
/* set by hardware if a PMI was delivered */
#define PMCR0_PMAI        (UINT64_C(1) << 11)
#define PMCR0_PMI_EN(CTR) (UINT64_C(1) << (12 + CTR_POS(CTR)))
/* fixed counters are always counting XXX probably need to just set this to all true */
#define PMCR0_PMI_INIT (PMCR0_PMI_EN(CYCLES) | PMCR0_PMI_EN(INSTRS))
/* disable counting on a PMI (except for AIC interrupts) */
#define PMCR0_DISCNT_EN (UINT64_C(1) << 20)
/* block PMIs until ERET retires */
#define PMCR0_WFRFE_EN (UINT64_C(1) << 22)
/* count global (not just core-local) L2C events */
#define PMCR0_L2CGLOBAL_EN (UINT64_C(1) << 23)
/* user mode access to configuration registers */
#define PMCR0_USEREN_EN (UINT64_C(1) << 30)

/* XXX this needs to be synchronized with kpc... */
#define PMCR0_INIT (PMCR0_INTGEN_INIT | PMCR0_PMI_INIT | PMCR0_DISCNT_EN)

/*
 * PMCR1 controls which execution modes count events.
 */

#define PMCR1 "s3_1_c15_c1_0"

#define PMCR1_EL0A32_EN(CTR) (UINT64_C(1) << (0 + CTR_POS(CTR)))
#define PMCR1_EL0A64_EN(CTR) (UINT64_C(1) << (8 + CTR_POS(CTR)))
#define PMCR1_EL1A64_EN(CTR) (UINT64_C(1) << (16 + CTR_POS(CTR)))
/* PMCR1_EL3A64 is not supported on systems with no monitor */
#if defined(APPLEHURRICANE)
#define PMCR1_EL3A64_EN(CTR) UINT64_C(0)
#else
#define PMCR1_EL3A64_EN(CTR) (UINT64_C(1) << (24 + CTR_POS(CTR)))
#endif
#define PMCR1_ALL_EN(CTR) (PMCR1_EL0A32_EN(CTR) | PMCR1_EL0A64_EN(CTR) | \
                           PMCR1_EL1A64_EN(CTR) | PMCR1_EL3A64_EN(CTR))

/* fixed counters always count in all modes */
#define PMCR1_INIT (PMCR1_ALL_EN(CYCLES) | PMCR1_ALL_EN(INSTRS))

static inline void
core_init_execution_modes(void)
{
	uint64_t pmcr1;

	pmcr1 = __builtin_arm_rsr64(PMCR1);
	pmcr1 |= PMCR1_INIT;
	__builtin_arm_wsr64(PMCR1, pmcr1);
}

/*
 * PMSR reports the overflow status of all counters.
 */

#define PMSR "s3_1_c15_c13_0"

#define PMSR_OVF(CTR) (UINT64_C(1) << (CTR))

/*
 * PMCR2 controls watchpoint registers.
 *
 * PMCR3 controls breakpoints and address matching.
 *
 * PMCR4 controls opcode matching.
 */

#define PMCR2 "s3_1_c15_c2_0"
#define PMCR3 "s3_1_c15_c3_0"
#define PMCR4 "s3_1_c15_c4_0"

/*
 * PMCR_AFFINITY does ??? XXX.
 */

#define PMCR_AFFINITY "s3_1_c15_c11_0"

void
mt_init(void)
{
}

static int
core_init(void)
{
	/* the dev node interface to the core counters is still unsupported */
	return ENOTSUP;
}

struct mt_cpu *
mt_cur_cpu(void)
{
	return &getCpuDatap()->cpu_monotonic;
}

uint64_t
mt_core_snap(unsigned int ctr)
{
	switch (ctr) {
	case 0:
		return __builtin_arm_rsr64(PMC0);
	case 1:
		return __builtin_arm_rsr64(PMC1);
	default:
		panic("monotonic: invalid core counter read: %u", ctr);
		__builtin_trap();
	}
}

void
mt_core_set_snap(unsigned int ctr, uint64_t count)
{
	switch (ctr) {
	case 0:
		__builtin_arm_wsr64(PMC0, count);
		break;
	case 1:
		__builtin_arm_wsr64(PMC1, count);
		break;
	default:
		panic("monotonic: invalid core counter %u write %llu", ctr, count);
		__builtin_trap();
	}
}

static void
core_set_enabled(void)
{
	uint64_t pmcr0;

	pmcr0 = __builtin_arm_rsr64(PMCR0);
	pmcr0 |= PMCR0_INIT | PMCR0_FIXED_EN;
	__builtin_arm_wsr64(PMCR0, pmcr0);
}

static void
core_idle(__unused cpu_data_t *cpu)
{
	assert(cpu != NULL);
	assert(ml_get_interrupts_enabled() == FALSE);

#if DEBUG
	uint64_t pmcr0 = __builtin_arm_rsr64(PMCR0);
	if ((pmcr0 & PMCR0_FIXED_EN) == 0) {
		panic("monotonic: counters disabled while idling, pmcr0 = 0x%llx\n", pmcr0);
	}
	uint64_t pmcr1 = __builtin_arm_rsr64(PMCR1);
	if ((pmcr1 & PMCR1_INIT) == 0) {
		panic("monotonic: counter modes disabled while idling, pmcr1 = 0x%llx\n", pmcr1);
	}
#endif /* DEBUG */

	/* disable counters before updating */
	__builtin_arm_wsr64(PMCR0, PMCR0_INIT);

	mt_update_fixed_counts();
}

static void
core_run(cpu_data_t *cpu)
{
	uint64_t pmcr0;
	struct mt_cpu *mtc;

	assert(cpu != NULL);
	assert(ml_get_interrupts_enabled() == FALSE);

	mtc = &cpu->cpu_monotonic;

	for (int i = 0; i < MT_CORE_NFIXED; i++) {
		mt_core_set_snap(i, mtc->mtc_snaps[i]);
	}

	/* re-enable the counters */
	core_init_execution_modes();

	pmcr0 = __builtin_arm_rsr64(PMCR0);
	pmcr0 |= PMCR0_INIT | PMCR0_FIXED_EN;
	__builtin_arm_wsr64(PMCR0, pmcr0);
}

static void
core_up(__unused cpu_data_t *cpu)
{
	assert(ml_get_interrupts_enabled() == FALSE);

	core_init_execution_modes();
}

#pragma mark uncore counters


static void
uncore_sleep(void)
{
}

static void
uncore_wake(void)
{
}

static void
uncore_fiq(uint64_t upmsr)
{
#pragma unused(upmsr)
}

#pragma mark common hooks

void
mt_cpu_idle(cpu_data_t *cpu)
{
	core_idle(cpu);
}

void
mt_cpu_run(cpu_data_t *cpu)
{
	core_run(cpu);
}

void
mt_cpu_down(cpu_data_t *cpu)
{
	mt_cpu_idle(cpu);
}

void
mt_cpu_up(cpu_data_t *cpu)
{
	core_up(cpu);
	mt_cpu_run(cpu);
}

void
mt_sleep(void)
{
	uncore_sleep();
}

void
mt_wake(void)
{
	uncore_wake();
}

void
mt_cpu_pmi(cpu_data_t *cpu, uint64_t pmsr)
{
	bool found_overflow = false;

	assert(cpu != NULL);
	assert(ml_get_interrupts_enabled() == FALSE);

	(void)atomic_fetch_add_explicit(&mt_pmis, 1, memory_order_relaxed);

	for (int i = 0; i < MT_CORE_NFIXED; i++) {
		if (pmsr & PMSR_OVF(i)) {
			mt_cpu_update_count(cpu, i);
			mt_core_set_snap(i, 0);
			found_overflow = true;
		}
	}

	assert(found_overflow);
	core_set_enabled();
}

void
mt_fiq_internal(uint64_t upmsr)
{
	uncore_fiq(upmsr);
}

#pragma mark dev nodes

const struct monotonic_dev monotonic_devs[] = {
	[0] = {
		.mtd_name = "monotonic/core",
		.mtd_init = core_init,
	},
};

static_assert(
		(sizeof(monotonic_devs) / sizeof(monotonic_devs[0])) == MT_NDEVS,
		"MT_NDEVS macro should be same as the length of monotonic_devs");

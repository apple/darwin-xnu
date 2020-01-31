/*
 * Copyright (c) 2017-2019 Apple Inc. All rights reserved.
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
#include <kern/assert.h>
#include <kern/debug.h> /* panic */
#include <kern/monotonic.h>
#include <machine/atomic.h>
#include <machine/limits.h> /* CHAR_BIT */
#include <os/overflow.h>
#include <pexpert/arm64/board_config.h>
#include <pexpert/device_tree.h> /* DTFindEntry */
#include <pexpert/pexpert.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/monotonic.h>

/*
 * Ensure that control registers read back what was written under MACH_ASSERT
 * kernels.
 *
 * A static inline function cannot be used due to passing the register through
 * the builtin -- it requires a constant string as its first argument, since
 * MSRs registers are encoded as an immediate in the instruction.
 */
#if MACH_ASSERT
#define CTRL_REG_SET(reg, val) do { \
	__builtin_arm_wsr64((reg), (val)); \
	uint64_t __check_reg = __builtin_arm_rsr64((reg)); \
	if (__check_reg != (val)) { \
	        panic("value written to %s was not read back (wrote %llx, read %llx)", \
	            #reg, (val), __check_reg); \
	} \
} while (0)
#else /* MACH_ASSERT */
#define CTRL_REG_SET(reg, val) __builtin_arm_wsr64((reg), (val))
#endif /* MACH_ASSERT */

#pragma mark core counters

bool mt_core_supported = true;

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

#define CTR_MAX ((UINT64_C(1) << 47) - 1)

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

#if CPMU_AIC_PMI
#define PMCR0_INTGEN_INIT PMCR0_INTGEN_SET(PMCR0_INTGEN_AIC)
#else /* CPMU_AIC_PMI */
#define PMCR0_INTGEN_INIT PMCR0_INTGEN_SET(PMCR0_INTGEN_FIQ)
#endif /* !CPMU_AIC_PMI */

#define PMCR0_PMI_EN(CTR) (UINT64_C(1) << (12 + CTR_POS(CTR)))
/* fixed counters are always counting */
#define PMCR0_PMI_INIT (PMCR0_PMI_EN(CYCLES) | PMCR0_PMI_EN(INSTRS))
/* disable counting on a PMI */
#define PMCR0_DISCNT_EN (UINT64_C(1) << 20)
/* block PMIs until ERET retires */
#define PMCR0_WFRFE_EN (UINT64_C(1) << 22)
/* count global (not just core-local) L2C events */
#define PMCR0_L2CGLOBAL_EN (UINT64_C(1) << 23)
/* user mode access to configuration registers */
#define PMCR0_USEREN_EN (UINT64_C(1) << 30)

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
 * PMCR2 controls watchpoint registers.
 *
 * PMCR3 controls breakpoints and address matching.
 *
 * PMCR4 controls opcode matching.
 */

#define PMCR2 "s3_1_c15_c2_0"
#define PMCR3 "s3_1_c15_c3_0"
#define PMCR4 "s3_1_c15_c4_0"

#define PMSR "s3_1_c15_c13_0"

#define PMSR_OVF(CTR) (1ULL << (CTR))

static int
core_init(__unused mt_device_t dev)
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
		__builtin_unreachable();
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
		__builtin_unreachable();
	}
}

static void
core_set_enabled(void)
{
	uint64_t pmcr0 = __builtin_arm_rsr64(PMCR0);
	pmcr0 |= PMCR0_INIT | PMCR0_FIXED_EN;
	pmcr0 &= ~PMCR0_PMAI;
	__builtin_arm_wsr64(PMCR0, pmcr0);
#if MACH_ASSERT
	/*
	 * Only check for the values that were ORed in.
	 */
	uint64_t pmcr0_check = __builtin_arm_rsr64(PMCR0);
	if (!(pmcr0_check & (PMCR0_INIT | PMCR0_FIXED_EN))) {
		panic("monotonic: hardware ignored enable (read %llx)",
		    pmcr0_check);
	}
#endif /* MACH_ASSERT */
}

static void
core_idle(__unused cpu_data_t *cpu)
{
	assert(cpu != NULL);
	assert(ml_get_interrupts_enabled() == FALSE);

#if DEBUG
	uint64_t pmcr0 = __builtin_arm_rsr64(PMCR0);
	if ((pmcr0 & PMCR0_FIXED_EN) == 0) {
		panic("monotonic: counters disabled before idling, pmcr0 = 0x%llx\n", pmcr0);
	}
	uint64_t pmcr1 = __builtin_arm_rsr64(PMCR1);
	if ((pmcr1 & PMCR1_INIT) == 0) {
		panic("monotonic: counter modes disabled before idling, pmcr1 = 0x%llx\n", pmcr1);
	}
#endif /* DEBUG */

	/* disable counters before updating */
	__builtin_arm_wsr64(PMCR0, PMCR0_INIT);

	mt_update_fixed_counts();
}

#pragma mark uncore performance monitor


#pragma mark common hooks

void
mt_cpu_idle(cpu_data_t *cpu)
{
	core_idle(cpu);
}

void
mt_cpu_run(cpu_data_t *cpu)
{
	struct mt_cpu *mtc;

	assert(cpu != NULL);
	assert(ml_get_interrupts_enabled() == FALSE);

	mtc = &cpu->cpu_monotonic;

	for (int i = 0; i < MT_CORE_NFIXED; i++) {
		mt_core_set_snap(i, mtc->mtc_snaps[i]);
	}

	/* re-enable the counters */
	core_init_execution_modes();

	core_set_enabled();
}

void
mt_cpu_down(cpu_data_t *cpu)
{
	mt_cpu_idle(cpu);
}

void
mt_cpu_up(cpu_data_t *cpu)
{
	mt_cpu_run(cpu);
}

void
mt_sleep(void)
{
}

void
mt_wake_per_core(void)
{
}

static void
mt_cpu_pmi(cpu_data_t *cpu, uint64_t pmcr0)
{
	assert(cpu != NULL);
	assert(ml_get_interrupts_enabled() == FALSE);

	os_atomic_inc(&mt_pmis, relaxed);
	cpu->cpu_stat.pmi_cnt++;
	cpu->cpu_stat.pmi_cnt_wake++;

#if MONOTONIC_DEBUG
	if (!PMCR0_PMI(pmcr0)) {
		kprintf("monotonic: mt_cpu_pmi but no PMI (PMCR0 = %#llx)\n",
		    pmcr0);
	}
#else /* MONOTONIC_DEBUG */
#pragma unused(pmcr0)
#endif /* !MONOTONIC_DEBUG */

	uint64_t pmsr = __builtin_arm_rsr64(PMSR);

#if MONOTONIC_DEBUG
	kprintf("monotonic: cpu = %d, PMSR = 0x%llx, PMCR0 = 0x%llx",
	    cpu_number(), pmsr, pmcr0);
#endif /* MONOTONIC_DEBUG */

	/*
	 * monotonic handles any fixed counter PMIs.
	 */
	for (unsigned int i = 0; i < MT_CORE_NFIXED; i++) {
		if ((pmsr & PMSR_OVF(i)) == 0) {
			continue;
		}

		uint64_t count = mt_cpu_update_count(cpu, i);
		cpu->cpu_monotonic.mtc_counts[i] += count;
		mt_core_set_snap(i, mt_core_reset_values[i]);
		cpu->cpu_monotonic.mtc_snaps[i] = mt_core_reset_values[i];

		if (mt_microstackshots && mt_microstackshot_ctr == i) {
			bool user_mode = false;
			arm_saved_state_t *state = get_user_regs(current_thread());
			if (state) {
				user_mode = PSR64_IS_USER(get_saved_state_cpsr(state));
			}
			KDBG_RELEASE(KDBG_EVENTID(DBG_MONOTONIC, DBG_MT_DEBUG, 1),
			    mt_microstackshot_ctr, user_mode);
			mt_microstackshot_pmi_handler(user_mode, mt_microstackshot_ctx);
		}
	}

	/*
	 * KPC handles the configurable counter PMIs.
	 */
	for (unsigned int i = MT_CORE_NFIXED; i < CORE_NCTRS; i++) {
		if (pmsr & PMSR_OVF(i)) {
			extern void kpc_pmi_handler(unsigned int ctr);
			kpc_pmi_handler(i);
		}
	}

#if MACH_ASSERT
	pmsr = __builtin_arm_rsr64(PMSR);
	assert(pmsr == 0);
#endif /* MACH_ASSERT */

	core_set_enabled();
}

#if CPMU_AIC_PMI
void
mt_cpmu_aic_pmi(cpu_id_t source)
{
	struct cpu_data *curcpu = getCpuDatap();
	if (source != curcpu->interrupt_nub) {
		panic("monotonic: PMI from IOCPU %p delivered to %p", source,
		    curcpu->interrupt_nub);
	}
	mt_cpu_pmi(curcpu, __builtin_arm_rsr64(PMCR0));
}
#endif /* CPMU_AIC_PMI */

void
mt_fiq(void *cpu, uint64_t pmcr0, uint64_t upmsr)
{
#if CPMU_AIC_PMI
#pragma unused(cpu, pmcr0)
#else /* CPMU_AIC_PMI */
	mt_cpu_pmi(cpu, pmcr0);
#endif /* !CPMU_AIC_PMI */

#pragma unused(upmsr)
}

static uint32_t mt_xc_sync;

static void
mt_microstackshot_start_remote(__unused void *arg)
{
	cpu_data_t *cpu = getCpuDatap();

	__builtin_arm_wsr64(PMCR0, PMCR0_INIT);

	for (int i = 0; i < MT_CORE_NFIXED; i++) {
		uint64_t count = mt_cpu_update_count(cpu, i);
		cpu->cpu_monotonic.mtc_counts[i] += count;
		mt_core_set_snap(i, mt_core_reset_values[i]);
		cpu->cpu_monotonic.mtc_snaps[i] = mt_core_reset_values[i];
	}

	core_set_enabled();

	if (hw_atomic_sub(&mt_xc_sync, 1) == 0) {
		thread_wakeup((event_t)&mt_xc_sync);
	}
}

int
mt_microstackshot_start_arch(uint64_t period)
{
	uint64_t reset_value = 0;
	int ovf = os_sub_overflow(CTR_MAX, period, &reset_value);
	if (ovf) {
		return ERANGE;
	}

	mt_core_reset_values[mt_microstackshot_ctr] = reset_value;
	cpu_broadcast_xcall(&mt_xc_sync, TRUE, mt_microstackshot_start_remote,
	    mt_microstackshot_start_remote /* cannot pass NULL */);
	return 0;
}

#pragma mark dev nodes

struct mt_device mt_devices[] = {
	[0] = {
		.mtd_name = "core",
		.mtd_init = core_init,
	},
};

static_assert(
	(sizeof(mt_devices) / sizeof(mt_devices[0])) == MT_NDEVS,
	"MT_NDEVS macro should be same as the length of mt_devices");

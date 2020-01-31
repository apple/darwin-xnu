/*
 * Copyright (c) 2012 Apple Inc. All rights reserved.
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
#include <machine/machine_routines.h>
#include <kern/processor.h>
#include <kern/kalloc.h>
#include <kern/thread.h>
#include <sys/errno.h>
#include <arm/cpu_data_internal.h>
#include <arm/cpu_internal.h>
#include <kern/kpc.h>

#ifdef ARMA7
/* PMU v2 based implementation for A7 */
static uint32_t saved_PMXEVTYPER[MAX_CPUS][KPC_ARM_TOTAL_COUNT];
static uint32_t saved_PMCNTENSET[MAX_CPUS];
static uint64_t saved_counter[MAX_CPUS][KPC_ARM_TOTAL_COUNT];
static uint32_t saved_PMOVSR[MAX_CPUS];

static uint32_t kpc_configured = 0;
static uint32_t kpc_xcall_sync;
static uint64_t kpc_running_cfg_pmc_mask = 0;
static uint32_t kpc_running_classes = 0;
static uint32_t kpc_reload_sync;
static uint32_t kpc_enabled_counters = 0;

static int first_time = 1;

/* Private */

static boolean_t
enable_counter(uint32_t counter)
{
	boolean_t enabled;
	uint32_t PMCNTENSET;
	/* Cycle counter is MSB; configurable counters reside in LSBs */
	uint32_t mask = (counter == 0) ? (1 << 31) : (1 << (counter - 1));

	/* Enabled? */
	__asm__ volatile ("mrc p15, 0, %0, c9, c12, 1;" : "=r" (PMCNTENSET));

	enabled = (PMCNTENSET & mask);
	if (!enabled) {
		/* Counter interrupt enable (PMINTENSET) */
		__asm__ volatile ("mcr p15, 0, %0, c9, c14, 1;" : : "r" (mask));

		/* Individual counter enable set (PMCNTENSET) */
		__asm__ volatile ("mcr p15, 0, %0, c9, c12, 1;" : : "r" (mask));

		kpc_enabled_counters++;

		/* 1st enabled counter? Set the master enable bit in PMCR */
		if (kpc_enabled_counters == 1) {
			uint32_t PMCR = 1;
			__asm__ volatile ("mcr p15, 0, %0, c9, c12, 0;" : : "r" (PMCR));
		}
	}

	return enabled;
}

static boolean_t
disable_counter(uint32_t counter)
{
	boolean_t enabled;
	uint32_t PMCNTENCLR;
	/* Cycle counter is MSB; configurable counters reside in LSBs */
	uint32_t mask = (counter == 0) ? (1 << 31) : (1 << (counter - 1));

	/* Enabled? */
	__asm__ volatile ("mrc p15, 0, %0, c9, c12, 2;" : "=r" (PMCNTENCLR));

	enabled = (PMCNTENCLR & mask);
	if (enabled) {
		/* Individual counter enable clear (PMCNTENCLR) */
		__asm__ volatile ("mcr p15, 0, %0, c9, c12, 2;" : : "r" (mask));

		/* Counter interrupt disable (PMINTENCLR) */
		__asm__ volatile ("mcr p15, 0, %0, c9, c14, 2;" : : "r" (mask));

		kpc_enabled_counters--;

		/* Last enabled counter? Clear the master enable bit in PMCR */
		if (kpc_enabled_counters == 0) {
			uint32_t PMCR = 0;
			__asm__ volatile ("mcr p15, 0, %0, c9, c12, 0;" : : "r" (PMCR));
		}
	}

	return enabled;
}

static uint64_t
read_counter(uint32_t counter)
{
	uint32_t low = 0;

	switch (counter) {
	case 0:
		/* Fixed counter */
		__asm__ volatile ("mrc p15, 0, %0, c9, c13, 0;" : "=r" (low));
		break;
	case 1:
	case 2:
	case 3:
	case 4:
		/* Configurable. Set PMSELR... */
		__asm__ volatile ("mcr p15, 0, %0, c9, c12, 5;" : : "r" (counter - 1));
		/* ...then read PMXEVCNTR */
		__asm__ volatile ("mrc p15, 0, %0, c9, c13, 2;" : "=r" (low));
		break;
	default:
		/* ??? */
		break;
	}

	return (uint64_t)low;
}

static void
write_counter(uint32_t counter, uint64_t value)
{
	uint32_t low = value & 0xFFFFFFFF;

	switch (counter) {
	case 0:
		/* Fixed counter */
		__asm__ volatile ("mcr p15, 0, %0, c9, c13, 0;" : : "r" (low));
		break;
	case 1:
	case 2:
	case 3:
	case 4:
		/* Configurable. Set PMSELR... */
		__asm__ volatile ("mcr p15, 0, %0, c9, c12, 5;" : : "r" (counter - 1));
		/* ...then write PMXEVCNTR */
		__asm__ volatile ("mcr p15, 0, %0, c9, c13, 2;" : : "r" (low));
		break;
	default:
		/* ??? */
		break;
	}
}

static uint64_t
kpc_reload_counter(int ctr)
{
	uint64_t old = read_counter(ctr);
	write_counter(ctr, FIXED_RELOAD(ctr));
	return old;
}

static void
set_running_fixed(boolean_t on)
{
	int i;
	boolean_t enabled;
	int n = KPC_ARM_FIXED_COUNT;

	enabled = ml_set_interrupts_enabled(FALSE);

	for (i = 0; i < n; i++) {
		if (on) {
			enable_counter(i);
		} else {
			disable_counter(i);
		}
	}

	ml_set_interrupts_enabled(enabled);
}

static void
set_running_configurable(uint64_t target_mask, uint64_t state_mask)
{
	uint32_t cfg_count = kpc_configurable_count(), offset = kpc_fixed_count();
	boolean_t enabled;

	enabled = ml_set_interrupts_enabled(FALSE);

	for (uint32_t i = 0; i < cfg_count; ++i) {
		if (((1ULL << i) & target_mask) == 0) {
			continue;
		}
		assert(kpc_controls_counter(offset + i));

		if ((1ULL << i) & state_mask) {
			enable_counter(offset + i);
		} else {
			disable_counter(offset + i);
		}
	}

	ml_set_interrupts_enabled(enabled);
}

void kpc_pmi_handler(cpu_id_t source);
void
kpc_pmi_handler(cpu_id_t source)
{
	uint64_t extra;
	int ctr;
	int enabled;

	enabled = ml_set_interrupts_enabled(FALSE);

	/* The pmi must be delivered to the CPU that generated it */
	if (source != getCpuDatap()->interrupt_nub) {
		panic("pmi from IOCPU %p delivered to IOCPU %p", source, getCpuDatap()->interrupt_nub);
	}

	for (ctr = 0;
	    ctr < (KPC_ARM_FIXED_COUNT + KPC_ARM_CONFIGURABLE_COUNT);
	    ctr++) {
		uint32_t PMOVSR;
		uint32_t mask;

		/* check the counter for overflow */
		if (ctr == 0) {
			mask = 1 << 31;
		} else {
			mask = 1 << (ctr - 1);
		}

		/* read PMOVSR */
		__asm__ volatile ("mrc p15, 0, %0, c9, c12, 3;" : "=r" (PMOVSR));

		if (PMOVSR & mask) {
			extra = kpc_reload_counter(ctr);

			FIXED_SHADOW(ctr)
			        += (kpc_fixed_max() - FIXED_RELOAD(ctr) + 1 /* wrap */) + extra;

			if (FIXED_ACTIONID(ctr)) {
				kpc_sample_kperf(FIXED_ACTIONID(ctr));
			}

			/* clear PMOVSR bit */
			__asm__ volatile ("mcr p15, 0, %0, c9, c12, 3;" : : "r" (mask));
		}
	}

	ml_set_interrupts_enabled(enabled);
}

static void
kpc_set_running_xcall( void *vstate )
{
	struct kpc_running_remote *mp_config = (struct kpc_running_remote*) vstate;
	assert(mp_config);

	if (kpc_controls_fixed_counters()) {
		set_running_fixed(mp_config->classes & KPC_CLASS_FIXED_MASK);
	}

	set_running_configurable(mp_config->cfg_target_mask,
	    mp_config->cfg_state_mask);

	if (hw_atomic_sub(&kpc_xcall_sync, 1) == 0) {
		thread_wakeup((event_t) &kpc_xcall_sync);
	}
}

static uint64_t
get_counter_config(uint32_t counter)
{
	uint32_t config = 0;

	switch (counter) {
	case 0:
		/* Fixed counter accessed via top bit... */
		counter = 31;
		/* Write PMSELR.SEL */
		__asm__ volatile ("mcr p15, 0, %0, c9, c12, 5;" : : "r" (counter));
		/* Read PMXEVTYPER */
		__asm__ volatile ("mcr p15, 0, %0, c9, c13, 1;" : "=r" (config));
		break;
	case 1:
	case 2:
	case 3:
	case 4:
		/* Offset */
		counter -= 1;
		/* Write PMSELR.SEL to select the configurable counter */
		__asm__ volatile ("mcr p15, 0, %0, c9, c12, 5;" : : "r" (counter));
		/* Read PMXEVTYPER to get the config */
		__asm__ volatile ("mrc p15, 0, %0, c9, c13, 1;" : "=r" (config));
		break;
	default:
		break;
	}

	return config;
}

static void
set_counter_config(uint32_t counter, uint64_t config)
{
	switch (counter) {
	case 0:
		/* Write PMSELR.SEL */
		__asm__ volatile ("mcr p15, 0, %0, c9, c12, 5;" : : "r" (31));
		/* Write PMXEVTYPER */
		__asm__ volatile ("mcr p15, 0, %0, c9, c13, 1;" : : "r" (config & 0xFFFFFFFF));
		break;
	case 1:
	case 2:
	case 3:
	case 4:
		/* Write PMSELR.SEL */
		__asm__ volatile ("mcr p15, 0, %0, c9, c12, 5;" : : "r" (counter - 1));
		/* Write PMXEVTYPER */
		__asm__ volatile ("mcr p15, 0, %0, c9, c13, 1;" : : "r" (config & 0xFFFFFFFF));
		break;
	default:
		break;
	}
}

/* Common */

void
kpc_arch_init(void)
{
	uint32_t PMCR;
	uint32_t event_counters;

	/* read PMOVSR and determine the number of event counters */
	__asm__ volatile ("mrc p15, 0, %0, c9, c12, 0;" : "=r" (PMCR));
	event_counters = (PMCR >> 11) & 0x1F;

	assert(event_counters >= KPC_ARM_CONFIGURABLE_COUNT);
}

uint32_t
kpc_get_classes(void)
{
	return KPC_CLASS_FIXED_MASK | KPC_CLASS_CONFIGURABLE_MASK;
}

uint32_t
kpc_fixed_count(void)
{
	return KPC_ARM_FIXED_COUNT;
}

uint32_t
kpc_configurable_count(void)
{
	return KPC_ARM_CONFIGURABLE_COUNT;
}

uint32_t
kpc_fixed_config_count(void)
{
	return KPC_ARM_FIXED_COUNT;
}

uint32_t
kpc_configurable_config_count(uint64_t pmc_mask)
{
	assert(kpc_popcount(pmc_mask) <= kpc_configurable_count());
	return kpc_popcount(pmc_mask);
}

int
kpc_get_fixed_config(kpc_config_t *configv)
{
	configv[0] = get_counter_config(0);
	return 0;
}

uint64_t
kpc_fixed_max(void)
{
	return (1ULL << KPC_ARM_COUNTER_WIDTH) - 1;
}

uint64_t
kpc_configurable_max(void)
{
	return (1ULL << KPC_ARM_COUNTER_WIDTH) - 1;
}

int
kpc_get_configurable_counters(uint64_t *counterv, uint64_t pmc_mask)
{
	uint32_t cfg_count = kpc_configurable_count(), offset = kpc_fixed_count();

	assert(counterv);

	for (uint32_t i = 0; i < cfg_count; ++i) {
		uint32_t PMOVSR;
		uint32_t mask;
		uint64_t ctr;

		if (((1ULL << i) & pmc_mask) == 0) {
			continue;
		}
		ctr = read_counter(i + offset);

		/* check the counter for overflow */
		mask = 1 << i;

		/* read PMOVSR */
		__asm__ volatile ("mrc p15, 0, %0, c9, c12, 3;" : "=r" (PMOVSR));

		if (PMOVSR & mask) {
			ctr = CONFIGURABLE_SHADOW(i) +
			    (kpc_configurable_max() - CONFIGURABLE_RELOAD(i) + 1 /* Wrap */) +
			    ctr;
		} else {
			ctr = CONFIGURABLE_SHADOW(i) +
			    (ctr - CONFIGURABLE_RELOAD(i));
		}

		*counterv++ = ctr;
	}

	return 0;
}

int
kpc_get_fixed_counters(uint64_t *counterv)
{
	uint32_t PMOVSR;
	uint32_t mask;
	uint64_t ctr;

	/* check the counter for overflow */
	mask = 1 << 31;

	/* read PMOVSR */
	__asm__ volatile ("mrc p15, 0, %0, c9, c12, 3;" : "=r" (PMOVSR));

	ctr = read_counter(0);

	if (PMOVSR & mask) {
		ctr = FIXED_SHADOW(0) +
		    (kpc_fixed_max() - FIXED_RELOAD(0) + 1 /* Wrap */) +
		    (ctr & 0xFFFFFFFF);
	} else {
		ctr = FIXED_SHADOW(0) +
		    (ctr - FIXED_RELOAD(0));
	}

	counterv[0] = ctr;

	return 0;
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

int
kpc_set_running_arch(struct kpc_running_remote *mp_config)
{
	unsigned int cpu;

	assert(mp_config);

	if (first_time) {
		kprintf( "kpc: setting PMI handler\n" );
		PE_cpu_perfmon_interrupt_install_handler(kpc_pmi_handler);
		for (cpu = 0; cpu < real_ncpus; cpu++) {
			PE_cpu_perfmon_interrupt_enable(cpu_datap(cpu)->cpu_id,
			    TRUE);
		}
		first_time = 0;
	}

	/* dispatch to all CPUs */
	cpu_broadcast_xcall(&kpc_xcall_sync, TRUE, kpc_set_running_xcall,
	    mp_config);

	kpc_running_cfg_pmc_mask = mp_config->cfg_state_mask;
	kpc_running_classes = mp_config->classes;
	kpc_configured = 1;

	return 0;
}

static void
save_regs(void)
{
	int i;
	int cpuid = current_processor()->cpu_id;
	uint32_t PMCR = 0;

	__asm__ volatile ("dmb ish");

	/* Clear master enable */
	__asm__ volatile ("mcr p15, 0, %0, c9, c12, 0;" : : "r" (PMCR));

	/* Save individual enable state */
	__asm__ volatile ("mrc p15, 0, %0, c9, c12, 1;" : "=r" (saved_PMCNTENSET[cpuid]));

	/* Save PMOVSR */
	__asm__ volatile ("mrc p15, 0, %0, c9, c12, 3;" : "=r" (saved_PMOVSR[cpuid]));

	/* Select fixed counter with PMSELR.SEL */
	__asm__ volatile ("mcr p15, 0, %0, c9, c12, 5;" : : "r" (31));
	/* Read PMXEVTYPER */
	__asm__ volatile ("mrc p15, 0, %0, c9, c13, 1;" : "=r" (saved_PMXEVTYPER[cpuid][0]));

	/* Save configurable event selections */
	for (i = 0; i < 4; i++) {
		/* Select counter with PMSELR.SEL */
		__asm__ volatile ("mcr p15, 0, %0, c9, c12, 5;" : : "r" (i));
		/* Read PMXEVTYPER */
		__asm__ volatile ("mrc p15, 0, %0, c9, c13, 1;" : "=r" (saved_PMXEVTYPER[cpuid][i + 1]));
	}

	/* Finally, save count for each counter */
	for (i = 0; i < 5; i++) {
		saved_counter[cpuid][i] = read_counter(i);
	}
}

static void
restore_regs(void)
{
	int i;
	int cpuid = current_processor()->cpu_id;
	uint64_t extra;
	uint32_t PMCR = 1;

	/* Restore counter values */
	for (i = 0; i < 5; i++) {
		/* did we overflow? if so handle it now since we won't get a pmi */
		uint32_t mask;

		/* check the counter for overflow */
		if (i == 0) {
			mask = 1 << 31;
		} else {
			mask = 1 << (i - 1);
		}

		if (saved_PMOVSR[cpuid] & mask) {
			extra = kpc_reload_counter(i);

			/*
			 * CONFIGURABLE_* directly follows FIXED, so we can simply
			 * increment the index here. Although it's ugly.
			 */
			FIXED_SHADOW(i)
			        += (kpc_fixed_max() - FIXED_RELOAD(i) + 1 /* Wrap */) + extra;

			if (FIXED_ACTIONID(i)) {
				kpc_sample_kperf(FIXED_ACTIONID(i));
			}
		} else {
			write_counter(i, saved_counter[cpuid][i]);
		}
	}

	/* Restore configuration - first, the fixed... */
	__asm__ volatile ("mcr p15, 0, %0, c9, c12, 5;" : : "r" (31));
	/* Write PMXEVTYPER */
	__asm__ volatile ("mcr p15, 0, %0, c9, c13, 1;" : : "r" (saved_PMXEVTYPER[cpuid][0]));

	/* ...then the configurable */
	for (i = 0; i < 4; i++) {
		/* Select counter with PMSELR.SEL */
		__asm__ volatile ("mcr p15, 0, %0, c9, c12, 5;" : : "r" (i));
		/* Write PMXEVTYPER */
		__asm__ volatile ("mcr p15, 0, %0, c9, c13, 1;" : : "r" (saved_PMXEVTYPER[cpuid][i + 1]));
	}

	/* Restore enable state */
	__asm__ volatile ("mcr p15, 0, %0, c9, c12, 1;" : : "r" (saved_PMCNTENSET[cpuid]));

	/* Counter master re-enable */
	__asm__ volatile ("mcr p15, 0, %0, c9, c12, 0;" : : "r" (PMCR));
}

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

	if ((classes & KPC_CLASS_FIXED_MASK) && kpc_controls_fixed_counters()) {
		/* update shadow counters */
		kpc_get_fixed_counters(&FIXED_SHADOW(0));

		/* set the new period */
		count = kpc_fixed_count();
		for (uint32_t i = 0; i < count; ++i) {
			if (*new_period == 0) {
				*new_period = kpc_fixed_max();
			}
			FIXED_RELOAD(i) = max - *new_period;
			/* reload the counter if possible */
			kpc_reload_counter(i);
			/* next period value */
			new_period++;
		}
	}

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
			if (((1ULL << i) & mp_config->pmc_mask) == 0) {
				continue;
			}
			if (*new_period == 0) {
				*new_period = kpc_configurable_max();
			}
			CONFIGURABLE_RELOAD(i) = max - *new_period;
			/* reload the counter */
			kpc_reload_counter(offset + i);
			/* next period value */
			new_period++;
		}
	}

	ml_set_interrupts_enabled(enabled);

	if (hw_atomic_sub(&kpc_reload_sync, 1) == 0) {
		thread_wakeup((event_t) &kpc_reload_sync);
	}
}


int
kpc_set_period_arch(struct kpc_config_remote *mp_config)
{
	/* dispatch to all CPUs */
	cpu_broadcast_xcall(&kpc_reload_sync, TRUE, kpc_set_reload_xcall, mp_config);

	kpc_configured = 1;

	return 0;
}

int
kpc_get_configurable_config(kpc_config_t *configv, uint64_t pmc_mask)
{
	uint32_t cfg_count = kpc_configurable_count(), offset = kpc_fixed_count();

	assert(configv);

	for (uint32_t i = 0; i < cfg_count; ++i) {
		if ((1ULL << i) & pmc_mask) {
			*configv++ = get_counter_config(i + offset);
		}
	}

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
		if (((1ULL << i) & pmc_mask) == 0) {
			continue;
		}
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

	if (hw_atomic_sub(&kpc_config_sync, 1) == 0) {
		thread_wakeup((event_t) &kpc_config_sync);
	}
}

int
kpc_set_config_arch(struct kpc_config_remote *mp_config)
{
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

static uint32_t kpc_xread_sync;
static void
kpc_get_curcpu_counters_xcall(void *args)
{
	struct kpc_get_counters_remote *handler = args;
	int offset = 0, r = 0;

	assert(handler);
	assert(handler->buf);

	offset = cpu_number() * handler->buf_stride;
	r = kpc_get_curcpu_counters(handler->classes, NULL, &handler->buf[offset]);

	/* number of counters added by this CPU, needs to be atomic  */
	hw_atomic_add(&(handler->nb_counters), r);

	if (hw_atomic_sub(&kpc_xread_sync, 1) == 0) {
		thread_wakeup((event_t) &kpc_xread_sync);
	}
}

int
kpc_get_all_cpus_counters(uint32_t classes, int *curcpu, uint64_t *buf)
{
	int enabled = 0;

	struct kpc_get_counters_remote hdl = {
		.classes = classes, .nb_counters = 0,
		.buf_stride = kpc_get_counter_count(classes),
		.buf = buf
	};

	assert(buf);

	enabled = ml_set_interrupts_enabled(FALSE);

	if (curcpu) {
		*curcpu = current_processor()->cpu_id;
	}
	cpu_broadcast_xcall(&kpc_xread_sync, TRUE, kpc_get_curcpu_counters_xcall, &hdl);

	ml_set_interrupts_enabled(enabled);

	return hdl.nb_counters;
}

int
kpc_get_pmu_version(void)
{
	return KPC_PMU_ARM_V2;
}

int
kpc_set_sw_inc( uint32_t mask )
{
	/* Only works with the configurable counters set to count the increment event (0x0) */

	/* Write to PMSWINC */
	__asm__ volatile ("mcr p15, 0, %0, c9, c12, 4;" : : "r" (mask));

	return 0;
}

#else /* !ARMA7 */

/* no kpc */

void
kpc_arch_init(void)
{
	/* No-op */
}

uint32_t
kpc_get_classes(void)
{
	return 0;
}

uint32_t
kpc_fixed_count(void)
{
	return 0;
}

uint32_t
kpc_configurable_count(void)
{
	return 0;
}

uint32_t
kpc_fixed_config_count(void)
{
	return 0;
}

uint32_t
kpc_configurable_config_count(uint64_t pmc_mask __unused)
{
	return 0;
}

int
kpc_get_fixed_config(kpc_config_t *configv __unused)
{
	return 0;
}

uint64_t
kpc_fixed_max(void)
{
	return 0;
}

uint64_t
kpc_configurable_max(void)
{
	return 0;
}

int
kpc_get_configurable_config(kpc_config_t *configv __unused, uint64_t pmc_mask __unused)
{
	return ENOTSUP;
}

int
kpc_get_configurable_counters(uint64_t *counterv __unused, uint64_t pmc_mask __unused)
{
	return ENOTSUP;
}

int
kpc_get_fixed_counters(uint64_t *counterv __unused)
{
	return 0;
}

boolean_t
kpc_is_running_fixed(void)
{
	return FALSE;
}

boolean_t
kpc_is_running_configurable(uint64_t pmc_mask __unused)
{
	return FALSE;
}

int
kpc_set_running_arch(struct kpc_running_remote *mp_config __unused)
{
	return ENOTSUP;
}

int
kpc_set_period_arch(struct kpc_config_remote *mp_config __unused)
{
	return ENOTSUP;
}

int
kpc_set_config_arch(struct kpc_config_remote *mp_config __unused)
{
	return ENOTSUP;
}

void
kpc_idle(void)
{
	// do nothing
}

void
kpc_idle_exit(void)
{
	// do nothing
}

int
kpc_get_all_cpus_counters(uint32_t classes, int *curcpu, uint64_t *buf)
{
#pragma unused(classes)
#pragma unused(curcpu)
#pragma unused(buf)

	return 0;
}

int
kpc_set_sw_inc( uint32_t mask __unused )
{
	return ENOTSUP;
}

int
kpc_get_pmu_version(void)
{
	return KPC_PMU_ERROR;
}

#endif

/*
 * RAWPMU isn't implemented for any of the 32-bit ARMs.
 */

uint32_t
kpc_rawpmu_config_count(void)
{
	return 0;
}

int
kpc_get_rawpmu_config(__unused kpc_config_t *configv)
{
	return 0;
}

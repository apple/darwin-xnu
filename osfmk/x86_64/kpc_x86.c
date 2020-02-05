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
#include <i386/cpuid.h>
#include <i386/proc_reg.h>
#include <i386/mp.h>
#include <sys/errno.h>
#include <kperf/buffer.h>

#include <kern/kpc.h>

#include <kperf/kperf.h>
#include <kperf/sample.h>
#include <kperf/context.h>
#include <kperf/action.h>

/* Fixed counter mask -- three counters, each with OS and USER */
#define IA32_FIXED_CTR_ENABLE_ALL_CTRS_ALL_RINGS (0x333)
#define IA32_FIXED_CTR_ENABLE_ALL_PMI (0x888)

#define IA32_PERFEVTSEL_PMI (1ull << 20)
#define IA32_PERFEVTSEL_EN (1ull << 22)

/* Non-serialising */
#define USE_RDPMC

#define RDPMC_FIXED_COUNTER_SELECTOR (1ULL<<30)

/* track the last config we enabled */
static uint64_t kpc_running_cfg_pmc_mask = 0;
static uint32_t kpc_running_classes = 0;

/* PMC / MSR accesses */

static uint64_t
IA32_FIXED_CTR_CTRL(void)
{
	return rdmsr64( MSR_IA32_PERF_FIXED_CTR_CTRL );
}

static uint64_t
IA32_FIXED_CTRx(uint32_t ctr)
{
#ifdef USE_RDPMC
	return rdpmc64(RDPMC_FIXED_COUNTER_SELECTOR | ctr);
#else /* !USE_RDPMC */
	return rdmsr64(MSR_IA32_PERF_FIXED_CTR0 + ctr);
#endif /* !USE_RDPMC */
}

#ifdef FIXED_COUNTER_RELOAD
static void
wrIA32_FIXED_CTRx(uint32_t ctr, uint64_t value)
{
	return wrmsr64(MSR_IA32_PERF_FIXED_CTR0 + ctr, value);
}
#endif

static uint64_t
IA32_PMCx(uint32_t ctr)
{
#ifdef USE_RDPMC
	return rdpmc64(ctr);
#else /* !USE_RDPMC */
	return rdmsr64(MSR_IA32_PERFCTR0 + ctr);
#endif /* !USE_RDPMC */
}

static void
wrIA32_PMCx(uint32_t ctr, uint64_t value)
{
	return wrmsr64(MSR_IA32_PERFCTR0 + ctr, value);
}

static uint64_t
IA32_PERFEVTSELx(uint32_t ctr)
{
	return rdmsr64(MSR_IA32_EVNTSEL0 + ctr);
}

static void
wrIA32_PERFEVTSELx(uint32_t ctr, uint64_t value)
{
	wrmsr64(MSR_IA32_EVNTSEL0 + ctr, value);
}


/* internal functions */

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
	i386_cpu_info_t *info = NULL;
	info = cpuid_info();
	return info->cpuid_arch_perf_leaf.fixed_number;
}

uint32_t
kpc_configurable_count(void)
{
	i386_cpu_info_t *info = NULL;
	info = cpuid_info();
	return info->cpuid_arch_perf_leaf.number;
}

uint32_t
kpc_fixed_config_count(void)
{
	return KPC_X86_64_FIXED_CONFIGS;
}

uint32_t
kpc_configurable_config_count(uint64_t pmc_mask)
{
	assert(kpc_popcount(pmc_mask) <= kpc_configurable_count());
	return kpc_popcount(pmc_mask);
}

uint32_t
kpc_rawpmu_config_count(void)
{
	// RAW PMU access not implemented.
	return 0;
}

int
kpc_get_rawpmu_config(__unused kpc_config_t *configv)
{
	return 0;
}

static uint8_t
kpc_fixed_width(void)
{
	i386_cpu_info_t *info = NULL;

	info = cpuid_info();

	return info->cpuid_arch_perf_leaf.fixed_width;
}

static uint8_t
kpc_configurable_width(void)
{
	i386_cpu_info_t *info = NULL;

	info = cpuid_info();

	return info->cpuid_arch_perf_leaf.width;
}

uint64_t
kpc_fixed_max(void)
{
	return (1ULL << kpc_fixed_width()) - 1;
}

uint64_t
kpc_configurable_max(void)
{
	return (1ULL << kpc_configurable_width()) - 1;
}

#ifdef FIXED_COUNTER_SHADOW
static uint64_t
kpc_reload_fixed(int ctr)
{
	uint64_t old = IA32_FIXED_CTRx(ctr);
	wrIA32_FIXED_CTRx(ctr, FIXED_RELOAD(ctr));
	return old;
}
#endif

static uint64_t
kpc_reload_configurable(int ctr)
{
	uint64_t cfg = IA32_PERFEVTSELx(ctr);

	/* counters must be disabled before they can be written to */
	uint64_t old = IA32_PMCx(ctr);
	wrIA32_PERFEVTSELx(ctr, cfg & ~IA32_PERFEVTSEL_EN);
	wrIA32_PMCx(ctr, CONFIGURABLE_RELOAD(ctr));
	wrIA32_PERFEVTSELx(ctr, cfg);
	return old;
}

void kpc_pmi_handler(void);

static void
set_running_fixed(boolean_t on)
{
	uint64_t global = 0, mask = 0, fixed_ctrl = 0;
	int i;
	boolean_t enabled;

	if (on) {
		/* these are per-thread in SMT */
		fixed_ctrl = IA32_FIXED_CTR_ENABLE_ALL_CTRS_ALL_RINGS | IA32_FIXED_CTR_ENABLE_ALL_PMI;
	} else {
		/* don't allow disabling fixed counters */
		return;
	}

	wrmsr64( MSR_IA32_PERF_FIXED_CTR_CTRL, fixed_ctrl );

	enabled = ml_set_interrupts_enabled(FALSE);

	/* rmw the global control */
	global = rdmsr64(MSR_IA32_PERF_GLOBAL_CTRL);
	for (i = 0; i < (int) kpc_fixed_count(); i++) {
		mask |= (1ULL << (32 + i));
	}

	if (on) {
		global |= mask;
	} else {
		global &= ~mask;
	}

	wrmsr64(MSR_IA32_PERF_GLOBAL_CTRL, global);

	ml_set_interrupts_enabled(enabled);
}

static void
set_running_configurable(uint64_t target_mask, uint64_t state_mask)
{
	uint32_t cfg_count = kpc_configurable_count();
	uint64_t global = 0ULL, cfg = 0ULL, save = 0ULL;
	boolean_t enabled;

	enabled = ml_set_interrupts_enabled(FALSE);

	/* rmw the global control */
	global = rdmsr64(MSR_IA32_PERF_GLOBAL_CTRL);

	/* need to save and restore counter since it resets when reconfigured */
	for (uint32_t i = 0; i < cfg_count; ++i) {
		cfg = IA32_PERFEVTSELx(i);
		save = IA32_PMCx(i);
		wrIA32_PERFEVTSELx(i, cfg | IA32_PERFEVTSEL_PMI | IA32_PERFEVTSEL_EN);
		wrIA32_PMCx(i, save);
	}

	/* update the global control value */
	global &= ~target_mask; /* clear the targeted PMCs bits */
	global |= state_mask;   /* update the targeted PMCs bits with their new states */
	wrmsr64(MSR_IA32_PERF_GLOBAL_CTRL, global);

	ml_set_interrupts_enabled(enabled);
}

static void
kpc_set_running_mp_call( void *vstate )
{
	struct kpc_running_remote *mp_config = (struct kpc_running_remote*) vstate;
	assert(mp_config);

	if (kpc_controls_fixed_counters()) {
		set_running_fixed(mp_config->classes & KPC_CLASS_FIXED_MASK);
	}

	set_running_configurable(mp_config->cfg_target_mask,
	    mp_config->cfg_state_mask);
}

int
kpc_get_fixed_config(kpc_config_t *configv)
{
	configv[0] = IA32_FIXED_CTR_CTRL();
	return 0;
}

static int
kpc_set_fixed_config(kpc_config_t *configv)
{
	(void) configv;

	/* NYI */
	return -1;
}

int
kpc_get_fixed_counters(uint64_t *counterv)
{
	int i, n = kpc_fixed_count();

#ifdef FIXED_COUNTER_SHADOW
	uint64_t status;

	/* snap the counters */
	for (i = 0; i < n; i++) {
		counterv[i] = FIXED_SHADOW(ctr) +
		    (IA32_FIXED_CTRx(i) - FIXED_RELOAD(ctr));
	}

	/* Grab the overflow bits */
	status = rdmsr64(MSR_IA32_PERF_GLOBAL_STATUS);

	/* If the overflow bit is set for a counter, our previous read may or may not have been
	 * before the counter overflowed. Re-read any counter with it's overflow bit set so
	 * we know for sure that it has overflowed. The reason this matters is that the math
	 * is different for a counter that has overflowed. */
	for (i = 0; i < n; i++) {
		if ((1ull << (i + 32)) & status) {
			counterv[i] = FIXED_SHADOW(ctr) +
			    (kpc_fixed_max() - FIXED_RELOAD(ctr) + 1 /* Wrap */) + IA32_FIXED_CTRx(i);
		}
	}
#else
	for (i = 0; i < n; i++) {
		counterv[i] = IA32_FIXED_CTRx(i);
	}
#endif

	return 0;
}

int
kpc_get_configurable_config(kpc_config_t *configv, uint64_t pmc_mask)
{
	uint32_t cfg_count = kpc_configurable_count();

	assert(configv);

	for (uint32_t i = 0; i < cfg_count; ++i) {
		if ((1ULL << i) & pmc_mask) {
			*configv++  = IA32_PERFEVTSELx(i);
		}
	}
	return 0;
}

static int
kpc_set_configurable_config(kpc_config_t *configv, uint64_t pmc_mask)
{
	uint32_t cfg_count = kpc_configurable_count();
	uint64_t save;

	for (uint32_t i = 0; i < cfg_count; i++) {
		if (((1ULL << i) & pmc_mask) == 0) {
			continue;
		}

		/* need to save and restore counter since it resets when reconfigured */
		save = IA32_PMCx(i);

		/*
		 * Some bits are not safe to set from user space.
		 * Allow these bits to be set:
		 *
		 *   0-7    Event select
		 *   8-15   UMASK
		 *   16     USR
		 *   17     OS
		 *   18     E
		 *   22     EN
		 *   23     INV
		 *   24-31  CMASK
		 *
		 * Excluding:
		 *
		 *   19     PC
		 *   20     INT
		 *   21     AnyThread
		 *   32     IN_TX
		 *   33     IN_TXCP
		 *   34-63  Reserved
		 */
		wrIA32_PERFEVTSELx(i, *configv & 0xffc7ffffull);
		wrIA32_PMCx(i, save);

		/* next configuration word */
		configv++;
	}

	return 0;
}

int
kpc_get_configurable_counters(uint64_t *counterv, uint64_t pmc_mask)
{
	uint32_t cfg_count = kpc_configurable_count();
	uint64_t status, *it_counterv = counterv;

	/* snap the counters */
	for (uint32_t i = 0; i < cfg_count; ++i) {
		if ((1ULL << i) & pmc_mask) {
			*it_counterv++ = CONFIGURABLE_SHADOW(i) +
			    (IA32_PMCx(i) - CONFIGURABLE_RELOAD(i));
		}
	}

	/* Grab the overflow bits */
	status = rdmsr64(MSR_IA32_PERF_GLOBAL_STATUS);

	/* reset the iterator */
	it_counterv = counterv;

	/*
	 * If the overflow bit is set for a counter, our previous read may or may not have been
	 * before the counter overflowed. Re-read any counter with it's overflow bit set so
	 * we know for sure that it has overflowed. The reason this matters is that the math
	 * is different for a counter that has overflowed.
	 */
	for (uint32_t i = 0; i < cfg_count; ++i) {
		if (((1ULL << i) & pmc_mask) &&
		    ((1ULL << i) & status)) {
			*it_counterv++ = CONFIGURABLE_SHADOW(i) +
			    (kpc_configurable_max() - CONFIGURABLE_RELOAD(i)) + IA32_PMCx(i);
		}
	}

	return 0;
}

static void
kpc_get_curcpu_counters_mp_call(void *args)
{
	struct kpc_get_counters_remote *handler = args;
	int offset = 0, r = 0;

	assert(handler);
	assert(handler->buf);

	offset = cpu_number() * handler->buf_stride;
	r = kpc_get_curcpu_counters(handler->classes, NULL, &handler->buf[offset]);

	/* number of counters added by this CPU, needs to be atomic  */
	os_atomic_add(&(handler->nb_counters), r, relaxed);
}

int
kpc_get_all_cpus_counters(uint32_t classes, int *curcpu, uint64_t *buf)
{
	int enabled = 0;

	struct kpc_get_counters_remote hdl = {
		.classes = classes, .nb_counters = 0,
		.buf_stride = kpc_get_counter_count(classes), .buf = buf
	};

	assert(buf);

	enabled = ml_set_interrupts_enabled(FALSE);

	if (curcpu) {
		*curcpu = current_processor()->cpu_id;
	}
	mp_cpus_call(CPUMASK_ALL, ASYNC, kpc_get_curcpu_counters_mp_call, &hdl);

	ml_set_interrupts_enabled(enabled);

	return hdl.nb_counters;
}

static void
kpc_set_config_mp_call(void *vmp_config)
{
	struct kpc_config_remote *mp_config = vmp_config;
	kpc_config_t *new_config = NULL;
	uint32_t classes = 0, count = 0;
	boolean_t enabled;

	assert(mp_config);
	assert(mp_config->configv);
	classes = mp_config->classes;
	new_config = mp_config->configv;

	enabled = ml_set_interrupts_enabled(FALSE);

	if (classes & KPC_CLASS_FIXED_MASK) {
		kpc_set_fixed_config(&new_config[count]);
		count += kpc_get_config_count(KPC_CLASS_FIXED_MASK);
	}

	if (classes & KPC_CLASS_CONFIGURABLE_MASK) {
		kpc_set_configurable_config(&new_config[count], mp_config->pmc_mask);
		count += kpc_popcount(mp_config->pmc_mask);
	}

	ml_set_interrupts_enabled(enabled);
}

static void
kpc_set_reload_mp_call(void *vmp_config)
{
	struct kpc_config_remote *mp_config = vmp_config;
	uint64_t *new_period = NULL, max = kpc_configurable_max();
	uint32_t classes = 0, count = 0;
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
			if (((1ULL << i) & mp_config->pmc_mask) == 0) {
				continue;
			}

			if (*new_period == 0) {
				*new_period = kpc_configurable_max();
			}

			CONFIGURABLE_RELOAD(i) = max - *new_period;

			/* reload the counter */
			kpc_reload_configurable(i);

			/* clear overflow bit just in case */
			wrmsr64(MSR_IA32_PERF_GLOBAL_OVF_CTRL, 1ull << i);

			/* next period value */
			new_period++;
		}
	}

	ml_set_interrupts_enabled(enabled);
}

int
kpc_set_period_arch( struct kpc_config_remote *mp_config )
{
	mp_cpus_call( CPUMASK_ALL, ASYNC, kpc_set_reload_mp_call, mp_config );

	return 0;
}


/* interface functions */

void
kpc_arch_init(void)
{
	i386_cpu_info_t *info = cpuid_info();
	uint8_t version_id = info->cpuid_arch_perf_leaf.version;
	/*
	 * kpc only supports Intel PMU versions 2 and above.
	 */
	if (version_id < 2) {
		kpc_supported = false;
	}
}

uint32_t
kpc_get_classes(void)
{
	return KPC_CLASS_FIXED_MASK | KPC_CLASS_CONFIGURABLE_MASK;
}

int
kpc_set_running_arch(struct kpc_running_remote *mp_config)
{
	assert(mp_config);

	/* dispatch to all CPUs */
	mp_cpus_call(CPUMASK_ALL, ASYNC, kpc_set_running_mp_call, mp_config);

	kpc_running_cfg_pmc_mask = mp_config->cfg_state_mask;
	kpc_running_classes = mp_config->classes;

	return 0;
}

int
kpc_set_config_arch(struct kpc_config_remote *mp_config)
{
	mp_cpus_call( CPUMASK_ALL, ASYNC, kpc_set_config_mp_call, mp_config );

	return 0;
}

/* PMI stuff */
void
kpc_pmi_handler(void)
{
	uint64_t status, extra;
	uint32_t ctr;
	int enabled;

	enabled = ml_set_interrupts_enabled(FALSE);

	status = rdmsr64(MSR_IA32_PERF_GLOBAL_STATUS);

#ifdef FIXED_COUNTER_SHADOW
	for (ctr = 0; ctr < kpc_fixed_count(); ctr++) {
		if ((1ULL << (ctr + 32)) & status) {
			extra = kpc_reload_fixed(ctr);

			FIXED_SHADOW(ctr)
			        += (kpc_fixed_max() - FIXED_RELOAD(ctr) + 1 /* Wrap */) + extra;

			BUF_INFO(PERF_KPC_FCOUNTER, ctr, FIXED_SHADOW(ctr), extra, FIXED_ACTIONID(ctr));

			if (FIXED_ACTIONID(ctr)) {
				kpc_sample_kperf(FIXED_ACTIONID(ctr));
			}
		}
	}
#endif

	for (ctr = 0; ctr < kpc_configurable_count(); ctr++) {
		if ((1ULL << ctr) & status) {
			extra = kpc_reload_configurable(ctr);

			CONFIGURABLE_SHADOW(ctr)
			        += kpc_configurable_max() - CONFIGURABLE_RELOAD(ctr) + extra;

			/* kperf can grab the PMCs when it samples so we need to make sure the overflow
			 * bits are in the correct state before the call to kperf_sample */
			wrmsr64(MSR_IA32_PERF_GLOBAL_OVF_CTRL, 1ull << ctr);

			BUF_INFO(PERF_KPC_COUNTER, ctr, CONFIGURABLE_SHADOW(ctr), extra, CONFIGURABLE_ACTIONID(ctr));

			if (CONFIGURABLE_ACTIONID(ctr)) {
				kpc_sample_kperf(CONFIGURABLE_ACTIONID(ctr));
			}
		}
	}

	ml_set_interrupts_enabled(enabled);
}

int
kpc_set_sw_inc( uint32_t mask __unused )
{
	return ENOTSUP;
}

int
kpc_get_pmu_version(void)
{
	i386_cpu_info_t *info = cpuid_info();

	uint8_t version_id = info->cpuid_arch_perf_leaf.version;

	if (version_id == 3) {
		return KPC_PMU_INTEL_V3;
	} else if (version_id == 2) {
		return KPC_PMU_INTEL_V2;
	}

	return KPC_PMU_ERROR;
}

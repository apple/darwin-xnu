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
#include <i386/lapic.h>
#include <sys/errno.h>
#include <kperf/buffer.h>

#include <kern/kpc.h>

#include <kperf/kperf.h>
#include <kperf/sample.h>
#include <kperf/context.h>
#include <kperf/action.h>

#include <chud/chud_xnu.h>



/* Fixed counter mask -- three counters, each with OS and USER */
#define IA32_FIXED_CTR_ENABLE_ALL_CTRS_ALL_RINGS (0x333)
#define IA32_FIXED_CTR_ENABLE_ALL_PMI (0x888)

#define IA32_PERFEVTSEL_PMI (1ull << 20)
#define IA32_PERFEVTSEL_EN (1ull << 22)

/* Non-serialising */
#define USE_RDPMC

#define RDPMC_FIXED_COUNTER_SELECTOR (1ULL<<30)

/* track the last config we enabled */
static uint32_t kpc_running = 0;

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
	return (kpc_running & KPC_CLASS_FIXED_MASK) == KPC_CLASS_FIXED_MASK;
}

boolean_t
kpc_is_running_configurable(void)
{
	return (kpc_running & KPC_CLASS_CONFIGURABLE_MASK) == KPC_CLASS_CONFIGURABLE_MASK;
}

uint32_t
kpc_fixed_count(void)
{
	i386_cpu_info_t	*info = NULL;

	info = cpuid_info();

	return info->cpuid_arch_perf_leaf.fixed_number;
}

uint32_t
kpc_configurable_count(void)
{
	i386_cpu_info_t	*info = NULL;

	info = cpuid_info();

	return info->cpuid_arch_perf_leaf.number;
}

uint32_t
kpc_fixed_config_count(void)
{
	return KPC_X86_64_FIXED_CONFIGS;
}

uint32_t
kpc_configurable_config_count(void)
{
	return kpc_configurable_count();
}

static uint8_t
kpc_fixed_width(void)
{
	i386_cpu_info_t	*info = NULL;
 
	info = cpuid_info();

	return info->cpuid_arch_perf_leaf.fixed_width;
}

static uint8_t
kpc_configurable_width(void)
{
	i386_cpu_info_t	*info = NULL;

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

void kpc_pmi_handler(x86_saved_state_t *state);

static void
set_running_fixed(boolean_t on)
{
	uint64_t global = 0, mask = 0, fixed_ctrl = 0;
	int i;
	boolean_t enabled;

	if( on )
		/* these are per-thread in SMT */
		fixed_ctrl = IA32_FIXED_CTR_ENABLE_ALL_CTRS_ALL_RINGS | IA32_FIXED_CTR_ENABLE_ALL_PMI;
	else
		/* don't allow disabling fixed counters */
		return;

	wrmsr64( MSR_IA32_PERF_FIXED_CTR_CTRL, fixed_ctrl );

	enabled = ml_set_interrupts_enabled(FALSE);

	/* rmw the global control */
	global = rdmsr64(MSR_IA32_PERF_GLOBAL_CTRL);
	for( i = 0; i < (int) kpc_fixed_count(); i++ )
		mask |= (1ULL<<(32+i));

	if( on )
		global |= mask;
	else
		global &= ~mask;

	wrmsr64(MSR_IA32_PERF_GLOBAL_CTRL, global);

	ml_set_interrupts_enabled(enabled);
}

static void
set_running_configurable(boolean_t on)
{
	uint64_t global = 0, mask = 0;
	uint64_t cfg, save;
	int i;
	boolean_t enabled;
	int ncnt = (int) kpc_get_counter_count(KPC_CLASS_CONFIGURABLE_MASK);

	enabled = ml_set_interrupts_enabled(FALSE);

	/* rmw the global control */
	global = rdmsr64(MSR_IA32_PERF_GLOBAL_CTRL);
	for( i = 0; i < ncnt; i++ ) {
		mask |= (1ULL<<i);

		/* need to save and restore counter since it resets when reconfigured */
		cfg = IA32_PERFEVTSELx(i);
		save = IA32_PMCx(i);
		wrIA32_PERFEVTSELx(i, cfg | IA32_PERFEVTSEL_PMI | IA32_PERFEVTSEL_EN);
		wrIA32_PMCx(i, save);
	}

	if( on )
		global |= mask;
	else
		global &= ~mask;

	wrmsr64(MSR_IA32_PERF_GLOBAL_CTRL, global);

	ml_set_interrupts_enabled(enabled);
}

static void
kpc_set_running_mp_call( void *vstate )
{
	uint32_t new_state = *(uint32_t*)vstate;

	set_running_fixed((new_state & KPC_CLASS_FIXED_MASK) != 0);
	set_running_configurable((new_state & KPC_CLASS_CONFIGURABLE_MASK) != 0);
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
	for( i = 0; i < n; i++ ) {
		counterv[i] = FIXED_SHADOW(ctr) +
			(IA32_FIXED_CTRx(i) - FIXED_RELOAD(ctr));
	}

	/* Grab the overflow bits */
	status = rdmsr64(MSR_IA32_PERF_GLOBAL_STATUS);

	/* If the overflow bit is set for a counter, our previous read may or may not have been
	 * before the counter overflowed. Re-read any counter with it's overflow bit set so
	 * we know for sure that it has overflowed. The reason this matters is that the math
	 * is different for a counter that has overflowed. */
	for( i = 0; i < n; i++ ) {
		if ((1ull << (i + 32)) & status)
			counterv[i] = FIXED_SHADOW(ctr) +
				(kpc_fixed_max() - FIXED_RELOAD(ctr)) + IA32_FIXED_CTRx(i);
	}
#else
	for( i = 0; i < n; i++ )
		counterv[i] = IA32_FIXED_CTRx(i);
#endif

	return 0;
}

int
kpc_get_configurable_config(kpc_config_t *configv)
{
	int i, n = kpc_get_config_count(KPC_CLASS_CONFIGURABLE_MASK);

	for( i = 0; i < n; i++ )
		configv[i] = IA32_PERFEVTSELx(i);

	return 0;
}

static int
kpc_set_configurable_config(kpc_config_t *configv)
{
	int i, n = kpc_get_config_count(KPC_CLASS_CONFIGURABLE_MASK);
	uint64_t save;

	for( i = 0; i < n; i++ ) {
		/* need to save and restore counter since it resets when reconfigured */
		save = IA32_PMCx(i);
		wrIA32_PERFEVTSELx(i, configv[i]);
		wrIA32_PMCx(i, save);
	}

	return 0;
}

int
kpc_get_configurable_counters(uint64_t *counterv)
{
	int i, n = kpc_get_config_count(KPC_CLASS_CONFIGURABLE_MASK);
	uint64_t status;

	/* snap the counters */
	for( i = 0; i < n; i++ ) {
		counterv[i] = CONFIGURABLE_SHADOW(i) +
			(IA32_PMCx(i) - CONFIGURABLE_RELOAD(i));
	}

	/* Grab the overflow bits */
	status = rdmsr64(MSR_IA32_PERF_GLOBAL_STATUS);

	/* If the overflow bit is set for a counter, our previous read may or may not have been
	 * before the counter overflowed. Re-read any counter with it's overflow bit set so
	 * we know for sure that it has overflowed. The reason this matters is that the math
	 * is different for a counter that has overflowed. */
	for( i = 0; i < n; i++ ) {
		if ((1ull << i) & status) {
			counterv[i] = CONFIGURABLE_SHADOW(i) +
				(kpc_configurable_max() - CONFIGURABLE_RELOAD(i)) + IA32_PMCx(i);
		}
	}

	return 0;
}

static void
kpc_set_config_mp_call(void *vmp_config)
{
	struct kpc_config_remote *mp_config = vmp_config;
	uint32_t classes = mp_config->classes;
	kpc_config_t *new_config = mp_config->configv;
	int count = 0;
	boolean_t enabled;

	enabled = ml_set_interrupts_enabled(FALSE);
	
	if( classes & KPC_CLASS_FIXED_MASK )
	{
		kpc_set_fixed_config(&new_config[count]);
		count += kpc_get_config_count(KPC_CLASS_FIXED_MASK);
	}

	if( classes & KPC_CLASS_CONFIGURABLE_MASK )
	{
		kpc_set_configurable_config(&new_config[count]);
		count += kpc_get_config_count(KPC_CLASS_CONFIGURABLE_MASK);
	}

	ml_set_interrupts_enabled(enabled);
}

static void
kpc_set_reload_mp_call(void *vmp_config)
{
	struct kpc_config_remote *mp_config = vmp_config;
	uint64_t max = kpc_configurable_max();
	uint32_t i, count = kpc_get_counter_count(KPC_CLASS_CONFIGURABLE_MASK);
	uint64_t *new_period;
	uint64_t classes;
	int enabled;

	classes = mp_config->classes;
	new_period = mp_config->configv;

	if (classes & KPC_CLASS_CONFIGURABLE_MASK) {
		enabled = ml_set_interrupts_enabled(FALSE);

		kpc_get_configurable_counters(&CONFIGURABLE_SHADOW(0));

		for (i = 0; i < count; i++) {
			if (new_period[i] == 0)
				new_period[i] = kpc_configurable_max();

			CONFIGURABLE_RELOAD(i) = max - new_period[i];

			kpc_reload_configurable(i);

			/* clear overflow bit just in case */
			wrmsr64(MSR_IA32_PERF_GLOBAL_OVF_CTRL, 1ull << i);
		}

		ml_set_interrupts_enabled(enabled);
	}
}

int
kpc_set_period_arch( struct kpc_config_remote *mp_config )
{
	mp_cpus_call( CPUMASK_ALL, ASYNC, kpc_set_reload_mp_call, mp_config );

	return 0;
}


/* interface functions */

uint32_t
kpc_get_classes(void)
{
	return KPC_CLASS_FIXED_MASK | KPC_CLASS_CONFIGURABLE_MASK;
}

int
kpc_set_running(uint32_t new_state)
{
	lapic_set_pmi_func((i386_intr_func_t)kpc_pmi_handler);

	/* dispatch to all CPUs */
	mp_cpus_call( CPUMASK_ALL, ASYNC, kpc_set_running_mp_call, &new_state );

	kpc_running = new_state;

	return 0;
}

int
kpc_set_config_arch(struct kpc_config_remote *mp_config)
{
	mp_cpus_call( CPUMASK_ALL, ASYNC, kpc_set_config_mp_call, mp_config );

	return 0;
}

/* PMI stuff */
void kpc_pmi_handler(__unused x86_saved_state_t *state)
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
				+= kpc_fixed_max() - FIXED_RELOAD(ctr) + extra;

			BUF_INFO(PERF_KPC_FCOUNTER, ctr, FIXED_SHADOW(ctr), extra, FIXED_ACTIONID(ctr));

			if (FIXED_ACTIONID(ctr))
				kpc_sample_kperf(FIXED_ACTIONID(ctr));
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
			
			if (CONFIGURABLE_ACTIONID(ctr))
				kpc_sample_kperf(CONFIGURABLE_ACTIONID(ctr));
		}
	}

	ml_set_interrupts_enabled(enabled);
}





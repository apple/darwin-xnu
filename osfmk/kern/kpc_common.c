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
#include <sys/errno.h>
#include <sys/vm.h>
#include <kperf/buffer.h>
#include <kern/thread.h>
#if defined(__arm64__) || defined(__arm__)
#include <arm/cpu_data_internal.h>
#endif

#include <kern/kpc.h>

#include <kperf/kperf.h>
#include <kperf/sample.h>
#include <kperf/context.h>
#include <kperf/action.h>

uint32_t kpc_actionid[KPC_MAX_COUNTERS];

#define COUNTERBUF_SIZE_PER_CPU (KPC_MAX_COUNTERS * sizeof(uint64_t))
#define COUNTERBUF_SIZE (machine_info.logical_cpu_max * \
                         COUNTERBUF_SIZE_PER_CPU)

/* locks */
static lck_grp_attr_t *kpc_config_lckgrp_attr = NULL;
static lck_grp_t      *kpc_config_lckgrp = NULL;
static lck_mtx_t       kpc_config_lock;

/* state specifying if all counters have been requested by kperf */
static boolean_t force_all_ctrs = FALSE;

/* power manager */
static kpc_pm_handler_t kpc_pm_handler;
static boolean_t kpc_pm_has_custom_config;
static uint64_t kpc_pm_pmc_mask;
#if MACH_ASSERT
static bool kpc_calling_pm = false;
#endif /* MACH_ASSERT */

boolean_t kpc_context_switch_active = FALSE;

void kpc_common_init(void);
void
kpc_common_init(void)
{
	kpc_config_lckgrp_attr = lck_grp_attr_alloc_init();
	kpc_config_lckgrp = lck_grp_alloc_init("kpc", kpc_config_lckgrp_attr);
	lck_mtx_init(&kpc_config_lock, kpc_config_lckgrp, LCK_ATTR_NULL);
}

boolean_t
kpc_register_cpu(struct cpu_data *cpu_data)
{
	assert(cpu_data);
	assert(cpu_data->cpu_kpc_buf[0] == NULL);
	assert(cpu_data->cpu_kpc_buf[1] == NULL);
	assert(cpu_data->cpu_kpc_shadow == NULL);
	assert(cpu_data->cpu_kpc_reload == NULL);

	/*
	 * Buffers allocated through kpc_counterbuf_alloc() are large enough to
	 * store all PMCs values from all CPUs. This mimics the userspace API.
	 * This does not suit well with the per-CPU kpc buffers, since:
	 * 	1. Buffers don't need to be this large.
	 * 	2. The actual number of CPUs is not known at this point.
	 *
	 * CPUs are asked to callout into kpc when being registered, we'll
	 * allocate the memory here.
	 */

	if ((cpu_data->cpu_kpc_buf[0] = kalloc(COUNTERBUF_SIZE_PER_CPU)) == NULL)
		goto error;
	if ((cpu_data->cpu_kpc_buf[1] = kalloc(COUNTERBUF_SIZE_PER_CPU)) == NULL)
		goto error;
	if ((cpu_data->cpu_kpc_shadow = kalloc(COUNTERBUF_SIZE_PER_CPU)) == NULL)
		goto error;
	if ((cpu_data->cpu_kpc_reload = kalloc(COUNTERBUF_SIZE_PER_CPU)) == NULL)
		goto error;

	memset(cpu_data->cpu_kpc_buf[0], 0, COUNTERBUF_SIZE_PER_CPU);
	memset(cpu_data->cpu_kpc_buf[1], 0, COUNTERBUF_SIZE_PER_CPU);
	memset(cpu_data->cpu_kpc_shadow, 0, COUNTERBUF_SIZE_PER_CPU);
	memset(cpu_data->cpu_kpc_reload, 0, COUNTERBUF_SIZE_PER_CPU);

	/* success */
	return TRUE;

error:
	kpc_unregister_cpu(cpu_data);
	return FALSE;
}

void
kpc_unregister_cpu(struct cpu_data *cpu_data)
{
	assert(cpu_data);
	if (cpu_data->cpu_kpc_buf[0] != NULL) {
		kfree(cpu_data->cpu_kpc_buf[0], COUNTERBUF_SIZE_PER_CPU);
		cpu_data->cpu_kpc_buf[0] = NULL;
	}
	if (cpu_data->cpu_kpc_buf[1] != NULL) {
		kfree(cpu_data->cpu_kpc_buf[1], COUNTERBUF_SIZE_PER_CPU);
		cpu_data->cpu_kpc_buf[1] = NULL;
	}
	if (cpu_data->cpu_kpc_shadow != NULL) {
		kfree(cpu_data->cpu_kpc_shadow, COUNTERBUF_SIZE_PER_CPU);
		cpu_data->cpu_kpc_shadow = NULL;
	}
	if (cpu_data->cpu_kpc_reload != NULL) {	
		kfree(cpu_data->cpu_kpc_reload, COUNTERBUF_SIZE_PER_CPU);
		cpu_data->cpu_kpc_reload = NULL;
	}
}


static void
kpc_task_set_forced_all_ctrs(task_t task, boolean_t state)
{
	assert(task);

	task_lock(task);
	if (state)
		task->t_kpc |= TASK_KPC_FORCED_ALL_CTRS;
	else
		task->t_kpc &= ~TASK_KPC_FORCED_ALL_CTRS;
	task_unlock(task);
}

static boolean_t
kpc_task_get_forced_all_ctrs(task_t task)
{
	assert(task);
	return task->t_kpc & TASK_KPC_FORCED_ALL_CTRS ? TRUE : FALSE;
}

int
kpc_force_all_ctrs(task_t task, int val)
{
	boolean_t new_state = val ? TRUE : FALSE;
	boolean_t old_state = kpc_get_force_all_ctrs();

	/*
	 * Refuse to do the operation if the counters are already forced by
	 * another task.
	 */
	if (kpc_get_force_all_ctrs() && !kpc_task_get_forced_all_ctrs(task))
		return EACCES;

	/* nothing to do if the state is not changing */
	if (old_state == new_state)
		return 0;

	/* notify the power manager */
	if (kpc_pm_handler) {
#if MACH_ASSERT
		kpc_calling_pm = true;
#endif /* MACH_ASSERT */
		kpc_pm_handler( new_state ? FALSE : TRUE );
#if MACH_ASSERT
		kpc_calling_pm = false;
#endif /* MACH_ASSERT */
	}

	/*
	 * This is a force -- ensure that counters are forced, even if power
	 * management fails to acknowledge it.
	 */
	if (force_all_ctrs != new_state) {
		force_all_ctrs = new_state;
	}

	/* update the task bits */
	kpc_task_set_forced_all_ctrs(task, new_state);

	return 0;
}

void
kpc_pm_acknowledge(boolean_t available_to_pm)
{
	/*
	 * Force-all-counters should still be true when the counters are being
	 * made available to power management and false when counters are going
	 * to be taken away.
	 */
	assert(force_all_ctrs == available_to_pm);
	/*
	 * Make sure power management isn't playing games with us.
	 */
	assert(kpc_calling_pm == true);

	/*
	 * Counters being available means no one is forcing all counters.
	 */
	force_all_ctrs = available_to_pm ? FALSE : TRUE;
}

int
kpc_get_force_all_ctrs(void)
{
	return force_all_ctrs;
}

boolean_t
kpc_multiple_clients(void)
{
	return kpc_pm_handler != NULL;
}

boolean_t
kpc_controls_fixed_counters(void)
{
	return !kpc_pm_handler || force_all_ctrs || !kpc_pm_has_custom_config;
}

boolean_t
kpc_controls_counter(uint32_t ctr)
{
	uint64_t pmc_mask = 0ULL;

	assert(ctr < (kpc_fixed_count() + kpc_configurable_count()));

	if (ctr < kpc_fixed_count())
		return kpc_controls_fixed_counters();

	/*
	 * By default kpc manages all PMCs, but if the Power Manager registered
	 * with custom_config=TRUE, the Power Manager manages its reserved PMCs.
	 * However, kpc takes ownership back if a task acquired all PMCs via
	 * force_all_ctrs.
	 */
	pmc_mask = (1ULL << (ctr - kpc_fixed_count()));
	if ((pmc_mask & kpc_pm_pmc_mask) && kpc_pm_has_custom_config && !force_all_ctrs)
		return FALSE;

	return TRUE;
}

uint32_t
kpc_get_running(void)
{
	uint64_t pmc_mask = 0;
	uint32_t cur_state = 0;

	if (kpc_is_running_fixed())
		cur_state |= KPC_CLASS_FIXED_MASK;

	pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_CONFIGURABLE_MASK);
	if (kpc_is_running_configurable(pmc_mask))
		cur_state |= KPC_CLASS_CONFIGURABLE_MASK;

	pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_POWER_MASK);
	if ((pmc_mask != 0) && kpc_is_running_configurable(pmc_mask))
		cur_state |= KPC_CLASS_POWER_MASK;

	return cur_state;
}

/* may be called from an IPI */
int
kpc_get_curcpu_counters(uint32_t classes, int *curcpu, uint64_t *buf)
{
	int enabled=0, offset=0;
	uint64_t pmc_mask = 0ULL;

	assert(buf);

	enabled = ml_set_interrupts_enabled(FALSE);

	/* grab counters and CPU number as close as possible */
	if (curcpu)
		*curcpu = current_processor()->cpu_id;

	if (classes & KPC_CLASS_FIXED_MASK) {
		kpc_get_fixed_counters(&buf[offset]);
		offset += kpc_get_counter_count(KPC_CLASS_FIXED_MASK);
	}

	if (classes & KPC_CLASS_CONFIGURABLE_MASK) {
		pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_CONFIGURABLE_MASK);
		kpc_get_configurable_counters(&buf[offset], pmc_mask);
		offset += kpc_popcount(pmc_mask);
	}

	if (classes & KPC_CLASS_POWER_MASK) {
		pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_POWER_MASK);
		kpc_get_configurable_counters(&buf[offset], pmc_mask);
		offset += kpc_popcount(pmc_mask);
	}

	ml_set_interrupts_enabled(enabled);

	return offset;
}

/* generic counter reading function, public api */
int
kpc_get_cpu_counters(boolean_t all_cpus, uint32_t classes,
                     int *curcpu, uint64_t *buf)
{
	assert(buf);

	/*
	 * Unlike reading the current CPU counters, reading counters from all
	 * CPUs is architecture dependent. This allows kpc to make the most of
	 * the platform if memory mapped registers is supported.
	 */
	if (all_cpus)
		return kpc_get_all_cpus_counters(classes, curcpu, buf);
	else
		return kpc_get_curcpu_counters(classes, curcpu, buf);
}

int
kpc_get_shadow_counters(boolean_t all_cpus, uint32_t classes,
                        int *curcpu, uint64_t *buf)
{
	int curcpu_id = current_processor()->cpu_id;
	uint32_t cfg_count = kpc_configurable_count(), offset = 0;
	uint64_t pmc_mask = 0ULL;
	boolean_t enabled;

	assert(buf);

	enabled = ml_set_interrupts_enabled(FALSE);

	curcpu_id = current_processor()->cpu_id;
	if (curcpu)
		*curcpu = curcpu_id;

	for (int cpu = 0; cpu < machine_info.logical_cpu_max; ++cpu) {
		/* filter if the caller did not request all cpus */
		if (!all_cpus && (cpu != curcpu_id))
			continue;

		if (classes & KPC_CLASS_FIXED_MASK) {
			uint32_t count = kpc_get_counter_count(KPC_CLASS_FIXED_MASK);
			memcpy(&buf[offset], &FIXED_SHADOW_CPU(cpu, 0), count * sizeof(uint64_t));
			offset += count;
		}

		if (classes & KPC_CLASS_CONFIGURABLE_MASK) {
			pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_CONFIGURABLE_MASK);

			for (uint32_t cfg_ctr = 0; cfg_ctr < cfg_count; ++cfg_ctr)
				if ((1ULL << cfg_ctr) & pmc_mask)
					buf[offset++] = CONFIGURABLE_SHADOW_CPU(cpu, cfg_ctr);
		}

		if (classes & KPC_CLASS_POWER_MASK) {
			pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_POWER_MASK);

			for (uint32_t cfg_ctr = 0; cfg_ctr < cfg_count; ++cfg_ctr)
				if ((1ULL << cfg_ctr) & pmc_mask)
					buf[offset++] = CONFIGURABLE_SHADOW_CPU(cpu, cfg_ctr);
		}
	}

	ml_set_interrupts_enabled(enabled);

	return offset;
}

uint32_t
kpc_get_counter_count(uint32_t classes)
{
	uint32_t count = 0;

	if (classes & KPC_CLASS_FIXED_MASK)
		count += kpc_fixed_count();

	if (classes & (KPC_CLASS_CONFIGURABLE_MASK | KPC_CLASS_POWER_MASK)) {
		uint64_t pmc_msk = kpc_get_configurable_pmc_mask(classes);
		uint32_t pmc_cnt = kpc_popcount(pmc_msk);
		count += pmc_cnt;
	}

	return count;
}

uint32_t
kpc_get_config_count(uint32_t classes)
{
	uint32_t count = 0;

	if (classes & KPC_CLASS_FIXED_MASK)
		count += kpc_fixed_config_count();

	if (classes & (KPC_CLASS_CONFIGURABLE_MASK | KPC_CLASS_POWER_MASK)) {
		uint64_t pmc_mask = kpc_get_configurable_pmc_mask(classes);
		count += kpc_configurable_config_count(pmc_mask);
	}

	if ((classes & KPC_CLASS_RAWPMU_MASK) && !kpc_multiple_clients())
		count += kpc_rawpmu_config_count();

	return count;
}

int
kpc_get_config(uint32_t classes, kpc_config_t *current_config)
{
	uint32_t count = 0;

	assert(current_config);

	if (classes & KPC_CLASS_FIXED_MASK) {
		kpc_get_fixed_config(&current_config[count]);
		count += kpc_get_config_count(KPC_CLASS_FIXED_MASK);
	}

	if (classes & KPC_CLASS_CONFIGURABLE_MASK) {
		uint64_t pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_CONFIGURABLE_MASK);
		kpc_get_configurable_config(&current_config[count], pmc_mask);
		count += kpc_get_config_count(KPC_CLASS_CONFIGURABLE_MASK);
	}

	if (classes & KPC_CLASS_POWER_MASK) {
		uint64_t pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_POWER_MASK);
		kpc_get_configurable_config(&current_config[count], pmc_mask);
		count += kpc_get_config_count(KPC_CLASS_POWER_MASK);
	}

	if (classes & KPC_CLASS_RAWPMU_MASK)
	{
		// Client shouldn't ask for config words that aren't available.
		// Most likely, they'd misinterpret the returned buffer if we
		// allowed this.
		if( kpc_multiple_clients() )
		{
			return EPERM;
		}
		kpc_get_rawpmu_config(&current_config[count]);
		count += kpc_get_config_count(KPC_CLASS_RAWPMU_MASK);
	}

	return 0;
}

int
kpc_set_config(uint32_t classes, kpc_config_t *configv)
{
	int ret = 0;
	struct kpc_config_remote mp_config = {
		.classes = classes, .configv = configv,
		.pmc_mask = kpc_get_configurable_pmc_mask(classes)
	};

	assert(configv);

	/* don't allow RAWPMU configuration when sharing counters */
	if ((classes & KPC_CLASS_RAWPMU_MASK) && kpc_multiple_clients()) {
		return EPERM;
	}

	/* no clients have the right to modify both classes */
	if ((classes & (KPC_CLASS_CONFIGURABLE_MASK)) &&
	    (classes & (KPC_CLASS_POWER_MASK)))
	{
		return EPERM;
	}

	lck_mtx_lock(&kpc_config_lock);

	/* translate the power class for the machine layer */
	if (classes & KPC_CLASS_POWER_MASK)
		mp_config.classes |= KPC_CLASS_CONFIGURABLE_MASK;

	ret = kpc_set_config_arch( &mp_config );

	lck_mtx_unlock(&kpc_config_lock);

	return ret;
}

/* allocate a buffer large enough for all possible counters */
uint64_t *
kpc_counterbuf_alloc(void)
{
	uint64_t *buf = NULL;

	buf = kalloc(COUNTERBUF_SIZE);
	if (buf) {
		bzero(buf, COUNTERBUF_SIZE);
	}

	return buf;
}

void
kpc_counterbuf_free(uint64_t *buf)
{
	if (buf) {
		kfree(buf, COUNTERBUF_SIZE);
	}
}

void
kpc_sample_kperf(uint32_t actionid)
{
	struct kperf_sample sbuf;
	struct kperf_context ctx;

	BUF_DATA(PERF_KPC_HNDLR | DBG_FUNC_START);

	ctx.cur_pid = 0;
	ctx.cur_thread = current_thread();
	ctx.cur_pid = task_pid(current_task());

	ctx.trigger_type = TRIGGER_TYPE_PMI;
	ctx.trigger_id = 0;

	int r = kperf_sample(&sbuf, &ctx, actionid, SAMPLE_FLAG_PEND_USER);

	BUF_INFO(PERF_KPC_HNDLR | DBG_FUNC_END, r);
}


int
kpc_set_period(uint32_t classes, uint64_t *val)
{
	struct kpc_config_remote mp_config = {
		.classes = classes, .configv = val,
		.pmc_mask = kpc_get_configurable_pmc_mask(classes)
	};

	assert(val);

	/* no clients have the right to modify both classes */
	if ((classes & (KPC_CLASS_CONFIGURABLE_MASK)) &&
	    (classes & (KPC_CLASS_POWER_MASK)))
	{
		return EPERM;
	}

	lck_mtx_lock(&kpc_config_lock);

#ifdef FIXED_COUNTER_SHADOW
	if ((classes & KPC_CLASS_FIXED_MASK) && !kpc_controls_fixed_counters()) {
		lck_mtx_unlock(&kpc_config_lock);
		return EPERM;
	}
# else
	if (classes & KPC_CLASS_FIXED_MASK) {
		lck_mtx_unlock(&kpc_config_lock);
		return EINVAL;
	}
#endif

	/* translate the power class for the machine layer */
	if (classes & KPC_CLASS_POWER_MASK)
		mp_config.classes |= KPC_CLASS_CONFIGURABLE_MASK;

	kprintf("setting period %u\n", classes);
	kpc_set_period_arch( &mp_config );

	lck_mtx_unlock(&kpc_config_lock);

	return 0;
}

int
kpc_get_period(uint32_t classes, uint64_t *val)
{
	uint32_t count = 0 ;
	uint64_t pmc_mask = 0ULL;

	assert(val);

	lck_mtx_lock(&kpc_config_lock);

	if (classes & KPC_CLASS_FIXED_MASK) {
		/* convert reload values to periods */
		count = kpc_get_counter_count(KPC_CLASS_FIXED_MASK);
		for (uint32_t i = 0; i < count; ++i)
			*val++ = kpc_fixed_max() - FIXED_RELOAD(i);
	}

	if (classes & KPC_CLASS_CONFIGURABLE_MASK) {
		pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_CONFIGURABLE_MASK);

		/* convert reload values to periods */
		count = kpc_configurable_count();
		for (uint32_t i = 0; i < count; ++i)
			if ((1ULL << i) & pmc_mask)
				*val++ = kpc_configurable_max() - CONFIGURABLE_RELOAD(i);
	}

	if (classes & KPC_CLASS_POWER_MASK) {
		pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_POWER_MASK);

		/* convert reload values to periods */
		count = kpc_configurable_count();
		for (uint32_t i = 0; i < count; ++i)
			if ((1ULL << i) & pmc_mask)
				*val++ = kpc_configurable_max() - CONFIGURABLE_RELOAD(i);
	}

	lck_mtx_unlock(&kpc_config_lock);

	return 0;
}

int
kpc_set_actionid(uint32_t classes, uint32_t *val)
{
	uint32_t count = 0;
	uint64_t pmc_mask = 0ULL;

	assert(val);

	/* NOTE: what happens if a pmi occurs while actionids are being
	 * set is undefined. */
	lck_mtx_lock(&kpc_config_lock);

	if (classes & KPC_CLASS_FIXED_MASK) {
		count = kpc_get_counter_count(KPC_CLASS_FIXED_MASK);
		memcpy(&FIXED_ACTIONID(0), val, count*sizeof(uint32_t));
		val += count;
	}

	if (classes & KPC_CLASS_CONFIGURABLE_MASK) {
		pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_CONFIGURABLE_MASK);

		count = kpc_configurable_count();
		for (uint32_t i = 0; i < count; ++i)
			if ((1ULL << i) & pmc_mask)
				CONFIGURABLE_ACTIONID(i) = *val++;
	}

	if (classes & KPC_CLASS_POWER_MASK) {
		pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_POWER_MASK);

		count = kpc_configurable_count();
		for (uint32_t i = 0; i < count; ++i)
			if ((1ULL << i) & pmc_mask)
				CONFIGURABLE_ACTIONID(i) = *val++;
	}

	lck_mtx_unlock(&kpc_config_lock);

	return 0;
}

int kpc_get_actionid(uint32_t classes, uint32_t *val)
{
	uint32_t count = 0;
	uint64_t pmc_mask = 0ULL;

	assert(val);

	lck_mtx_lock(&kpc_config_lock);

	if (classes & KPC_CLASS_FIXED_MASK) {
		count = kpc_get_counter_count(KPC_CLASS_FIXED_MASK);
		memcpy(val, &FIXED_ACTIONID(0), count*sizeof(uint32_t));
		val += count;
	}

	if (classes & KPC_CLASS_CONFIGURABLE_MASK) {
		pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_CONFIGURABLE_MASK);

		count = kpc_configurable_count();
		for (uint32_t i = 0; i < count; ++i)
			if ((1ULL << i) & pmc_mask)
				*val++ = CONFIGURABLE_ACTIONID(i);
	}

	if (classes & KPC_CLASS_POWER_MASK) {
		pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_POWER_MASK);

		count = kpc_configurable_count();
		for (uint32_t i = 0; i < count; ++i)
			if ((1ULL << i) & pmc_mask)
				*val++ = CONFIGURABLE_ACTIONID(i);
	}

	lck_mtx_unlock(&kpc_config_lock);

	return 0;

}

int
kpc_set_running(uint32_t classes)
{
	uint32_t all_cfg_classes = KPC_CLASS_CONFIGURABLE_MASK | KPC_CLASS_POWER_MASK;
	struct kpc_running_remote mp_config = {
		.classes = classes, .cfg_target_mask= 0ULL, .cfg_state_mask = 0ULL
	};

	/* target all available PMCs */
	mp_config.cfg_target_mask = kpc_get_configurable_pmc_mask(all_cfg_classes);

	/* translate the power class for the machine layer */
	if (classes & KPC_CLASS_POWER_MASK)
		mp_config.classes |= KPC_CLASS_CONFIGURABLE_MASK;

	/* generate the state of each configurable PMCs */
	mp_config.cfg_state_mask = kpc_get_configurable_pmc_mask(classes);

	return kpc_set_running_arch(&mp_config);
}

boolean_t
kpc_register_pm_handler(kpc_pm_handler_t handler)
{
	return kpc_reserve_pm_counters(0x38, handler, TRUE);
}

boolean_t
kpc_reserve_pm_counters(uint64_t pmc_mask, kpc_pm_handler_t handler,
                        boolean_t custom_config)
{
	uint64_t all_mask = (1ULL << kpc_configurable_count()) - 1;
	uint64_t req_mask = 0ULL;

	/* pre-condition */
	assert(handler != NULL);
	assert(kpc_pm_handler == NULL);

	/* check number of counters requested */
	req_mask = (pmc_mask & all_mask);
	assert(kpc_popcount(req_mask) <= kpc_configurable_count());

	/* save the power manager states */
	kpc_pm_has_custom_config = custom_config;
	kpc_pm_pmc_mask = req_mask;
	kpc_pm_handler = handler;

	printf("kpc: pm registered pmc_mask=%llx custom_config=%d\n",
	       req_mask, custom_config);

	/* post-condition */
	{
		uint32_t cfg_count = kpc_get_counter_count(KPC_CLASS_CONFIGURABLE_MASK);
		uint32_t pwr_count = kpc_popcount(kpc_pm_pmc_mask);
#pragma unused(cfg_count, pwr_count)
		assert((cfg_count + pwr_count) == kpc_configurable_count());
	}

	return force_all_ctrs ? FALSE : TRUE;
}

void
kpc_release_pm_counters(void)
{
	/* pre-condition */
	assert(kpc_pm_handler != NULL);

	/* release the counters */
	kpc_pm_has_custom_config = FALSE;
	kpc_pm_pmc_mask = 0ULL;
	kpc_pm_handler = NULL;

	printf("kpc: pm released counters\n");

	/* post-condition */
	assert(kpc_get_counter_count(KPC_CLASS_CONFIGURABLE_MASK) == kpc_configurable_count());
}

uint8_t
kpc_popcount(uint64_t value)
{
	return __builtin_popcountll(value);
}

uint64_t
kpc_get_configurable_pmc_mask(uint32_t classes)
{
	uint32_t configurable_count = kpc_configurable_count();
	uint64_t cfg_mask = 0ULL, pwr_mask = 0ULL, all_cfg_pmcs_mask = 0ULL;

	/* not configurable classes or no configurable counters */
	if (((classes & (KPC_CLASS_CONFIGURABLE_MASK | KPC_CLASS_POWER_MASK)) == 0) ||
	    (configurable_count == 0))
	{
		goto exit;
	}

	assert(configurable_count < 64);
	all_cfg_pmcs_mask = (1ULL << configurable_count) - 1;

	if (classes & KPC_CLASS_CONFIGURABLE_MASK) {
		if (force_all_ctrs == TRUE)
			cfg_mask |= all_cfg_pmcs_mask;
		else
			cfg_mask |= (~kpc_pm_pmc_mask) & all_cfg_pmcs_mask;
	}

	/*
	 * The power class exists iff:
	 * 	- No tasks acquired all PMCs
	 * 	- PM registered and uses kpc to interact with PMCs
	 */
	if ((force_all_ctrs == FALSE) &&
	    (kpc_pm_handler != NULL) &&
	    (kpc_pm_has_custom_config == FALSE) &&
	    (classes & KPC_CLASS_POWER_MASK))
	{
		pwr_mask |= kpc_pm_pmc_mask & all_cfg_pmcs_mask;
	}

exit:
	/* post-conditions */
	assert( ((cfg_mask | pwr_mask) & (~all_cfg_pmcs_mask)) == 0 );
	assert( kpc_popcount(cfg_mask | pwr_mask) <= kpc_configurable_count() );
	assert( (cfg_mask & pwr_mask) == 0ULL );

	return cfg_mask | pwr_mask;
}

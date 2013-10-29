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
#include <kperf/buffer.h>
#include <kern/thread.h>

#include <kern/kpc.h>

#include <kperf/kperf.h>
#include <kperf/sample.h>
#include <kperf/context.h>
#include <kperf/action.h>

#include <chud/chud_xnu.h>

uint32_t kpc_actionid[KPC_MAX_COUNTERS];

/* locks */
static lck_grp_attr_t *kpc_config_lckgrp_attr = NULL;
static lck_grp_t      *kpc_config_lckgrp = NULL;
static lck_mtx_t       kpc_config_lock;

void kpc_arch_init(void);
void
kpc_arch_init(void)
{
	kpc_config_lckgrp_attr = lck_grp_attr_alloc_init();
	kpc_config_lckgrp = lck_grp_alloc_init("kpc", kpc_config_lckgrp_attr);
	lck_mtx_init(&kpc_config_lock, kpc_config_lckgrp, LCK_ATTR_NULL);
}

uint32_t
kpc_get_running(void)
{
	uint32_t cur_state = 0;

	if( kpc_is_running_fixed() )
		cur_state |= KPC_CLASS_FIXED_MASK;

	if( kpc_is_running_configurable() )
		cur_state |= KPC_CLASS_CONFIGURABLE_MASK;

	return cur_state;
}

/* generic counter reading function */
int
kpc_get_cpu_counters( boolean_t all_cpus, uint32_t classes, 
                      int *curcpu, uint64_t *buf  )
{
	int r, enabled, offset = 0;

	(void) all_cpus;

	/* grab counters and CPU number as close as possible */
	enabled = ml_set_interrupts_enabled(FALSE);

	/* and the CPU ID */
	if( curcpu )
		*curcpu = current_processor()->cpu_id;

	if( classes & KPC_CLASS_FIXED_MASK )
	{
		kpc_get_fixed_counters( &buf[offset] );

		offset += kpc_get_counter_count(KPC_CLASS_FIXED_MASK);
	}

	if( classes & KPC_CLASS_CONFIGURABLE_MASK )
	{
		r = kpc_get_configurable_counters(  &buf[offset] );

		offset += kpc_get_counter_count(KPC_CLASS_CONFIGURABLE_MASK);
	}

	ml_set_interrupts_enabled(enabled);

	return offset;
}

int
kpc_get_shadow_counters( boolean_t all_cpus, uint32_t classes,
                         int *curcpu, uint64_t *buf )
{
	int enabled, count, offset = 0;

	(void)all_cpus;

	enabled = ml_set_interrupts_enabled(FALSE);

	if( curcpu )
		*curcpu = current_processor()->cpu_id;

	if( classes & KPC_CLASS_FIXED_MASK )
	{
		count = kpc_get_counter_count(KPC_CLASS_FIXED_MASK);

		memcpy( &buf[offset], &FIXED_SHADOW(0), count*sizeof(uint64_t) );

		offset += count;
	}

	if( classes & KPC_CLASS_CONFIGURABLE_MASK )
	{
		count = kpc_get_counter_count(KPC_CLASS_CONFIGURABLE_MASK);

		memcpy( &buf[offset], &CONFIGURABLE_SHADOW(0), count*sizeof(uint64_t) );

		offset += count;
	}

	ml_set_interrupts_enabled(enabled);

	return offset;
}

uint32_t
kpc_get_counter_count(uint32_t classes)
{
	int count = 0;

	if( classes & KPC_CLASS_FIXED_MASK )
		count += kpc_fixed_count();

	if( classes & KPC_CLASS_CONFIGURABLE_MASK )
		count += kpc_configurable_count() ;

	return count;
}

uint32_t
kpc_get_config_count(uint32_t classes)
{
	int count = 0;

	if( classes & KPC_CLASS_FIXED_MASK )
		count += kpc_fixed_config_count();

	if( classes & KPC_CLASS_CONFIGURABLE_MASK )
		count += kpc_configurable_config_count();

	return count;
}

int
kpc_get_config(uint32_t classes, kpc_config_t *current_config)
{
	int count = 0;

	if( classes & KPC_CLASS_FIXED_MASK )
	{
		kpc_get_fixed_config(&current_config[count]);
		count += kpc_get_config_count(KPC_CLASS_FIXED_MASK);
	}

	if( classes & KPC_CLASS_CONFIGURABLE_MASK )
	{
		kpc_get_configurable_config(&current_config[count]);
		count += kpc_get_config_count(KPC_CLASS_CONFIGURABLE_MASK);
	}

	return 0;
}

int
kpc_set_config(uint32_t classes, kpc_config_t *configv)
{
	struct kpc_config_remote mp_config;

	lck_mtx_lock(&kpc_config_lock);

	mp_config.classes = classes;
	mp_config.configv = configv;

	kpc_set_config_arch( &mp_config );

	lck_mtx_unlock(&kpc_config_lock);

	return 0;
}

/* allocate a buffer big enough for all the counters */
uint64_t *
kpc_counterbuf_alloc(void)
{
	uint64_t *buf;

	buf = kalloc(KPC_MAX_COUNTERS * sizeof(uint64_t));
	if(buf)
		bzero( buf, KPC_MAX_COUNTERS * sizeof(uint64_t) );

	return buf;
}

void
kpc_counterbuf_free(uint64_t *buf)
{
	if( buf )
		kfree(buf, KPC_MAX_COUNTERS * sizeof(uint64_t));
}

void kpc_sample_kperf(uint32_t actionid)
{
	struct kperf_sample sbuf;
	struct kperf_context ctx;
	task_t task = NULL;
	int r;

	BUF_DATA1(PERF_KPC_HNDLR | DBG_FUNC_START, 0);

	ctx.cur_pid = 0;
	ctx.cur_thread = current_thread();

	task = chudxnu_task_for_thread(ctx.cur_thread);
	if (task)
		ctx.cur_pid = chudxnu_pid_for_task(task);

	ctx.trigger_type = TRIGGER_TYPE_PMI;
	ctx.trigger_id = 0;

	r = kperf_sample(&sbuf, &ctx, actionid, SAMPLE_FLAG_PEND_USER);

	BUF_INFO1(PERF_KPC_HNDLR | DBG_FUNC_END, r);
}


int kpc_set_period(uint32_t classes, uint64_t *val)
{
	struct kpc_config_remote mp_config;

	lck_mtx_lock(&kpc_config_lock);

#ifndef FIXED_COUNTER_SHADOW
	if (classes & KPC_CLASS_FIXED_MASK) {
		lck_mtx_unlock(&kpc_config_lock);
		return -1;
	}
#endif

	kprintf("setting period %u\n", classes);

	mp_config.classes = classes;
	mp_config.configv = val;

	kpc_set_period_arch( &mp_config );

	lck_mtx_unlock(&kpc_config_lock);

	return 0;
}


int kpc_get_period(uint32_t classes, uint64_t *val)
{
	uint32_t i, count, offset = 0;

	lck_mtx_lock(&kpc_config_lock);

	if (classes & KPC_CLASS_FIXED_MASK) {
		count = kpc_get_counter_count(KPC_CLASS_FIXED_MASK);

		/* convert reload values to periods */
		for (i = 0; i < count; i++)
			val[i] = kpc_fixed_max() - FIXED_RELOAD(i);

		offset += count;
	}

	if (classes & KPC_CLASS_CONFIGURABLE_MASK) {
		count = kpc_get_counter_count(KPC_CLASS_CONFIGURABLE_MASK);

		/* convert reload values to periods */
		for (i = 0; i < count; i++)
			val[i + offset] = kpc_configurable_max() - CONFIGURABLE_RELOAD(i);
	}

	lck_mtx_unlock(&kpc_config_lock);

	return 0;
}

int kpc_set_actionid(uint32_t classes, uint32_t *val)
{
	uint32_t count, offset = 0;

	/* NOTE: what happens if a pmi occurs while actionids are being
	 * set is undefined. */
	lck_mtx_lock(&kpc_config_lock);

	if (classes & KPC_CLASS_FIXED_MASK) {
		count = kpc_get_counter_count(KPC_CLASS_FIXED_MASK);

		memcpy(&FIXED_ACTIONID(0), val, count*sizeof(uint32_t));

		offset += count;
	}

	if (classes & KPC_CLASS_CONFIGURABLE_MASK) {
		count = kpc_get_counter_count(KPC_CLASS_CONFIGURABLE_MASK);

		memcpy(&CONFIGURABLE_ACTIONID(0), &val[offset], count*sizeof(uint32_t));
	}

	lck_mtx_unlock(&kpc_config_lock);

	return 0;
}

int kpc_get_actionid(uint32_t classes, uint32_t *val)
{
	uint32_t count, offset = 0;

	lck_mtx_lock(&kpc_config_lock);

	if (classes & KPC_CLASS_FIXED_MASK) {
		count = kpc_get_counter_count(KPC_CLASS_FIXED_MASK);

		memcpy(val, &FIXED_ACTIONID(0), count*sizeof(uint32_t));

		offset += count;
	}

	if (classes & KPC_CLASS_CONFIGURABLE_MASK) {
		count = kpc_get_counter_count(KPC_CLASS_CONFIGURABLE_MASK);

		memcpy(&val[offset], &CONFIGURABLE_ACTIONID(0), count*sizeof(uint32_t));
	}

	lck_mtx_unlock(&kpc_config_lock);

	return 0;

}


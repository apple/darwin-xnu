/*
 * Copyright (c) 2013 Apple Computer, Inc. All rights reserved.
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
 * Sample KPC data into kperf and manage shared context-switch and AST handlers
 */

#include <kperf/kperf.h>
#include <kperf/buffer.h>
#include <kperf/context.h>
#include <kperf/pet.h>
#include <kperf/kperf_kpc.h>
#include <kern/kpc.h> /* kpc_cswitch_context, kpc_threads_counting */

void
kperf_kpc_thread_ast(thread_t thread)
{
	kpc_thread_ast_handler(thread);
	kperf_thread_ast_handler(thread);

	thread->kperf_flags = 0;
}

void
kperf_kpc_thread_sample(struct kpcdata *kpcd, int sample_config)
{
	BUF_INFO(PERF_KPC_THREAD_SAMPLE | DBG_FUNC_START, sample_config);

	kpcd->running = kpc_get_running();
	/* let kpc_get_curthread_counters set the correct count */
	kpcd->counterc = KPC_MAX_COUNTERS;
	if (kpc_get_curthread_counters(&kpcd->counterc,
	    kpcd->counterv)) {
		/* if thread counters aren't ready, default to 0 */
		memset(kpcd->counterv, 0,
		    sizeof(uint64_t) * kpcd->counterc);
	}
	/* help out Instruments by sampling KPC's config */
	if (!sample_config) {
		kpcd->configc = 0;
	} else {
		kpcd->configc = kpc_get_config_count(kpcd->running);
		kpc_get_config(kpcd->running, kpcd->configv);
	}

	BUF_INFO(PERF_KPC_THREAD_SAMPLE | DBG_FUNC_END, kpcd->running, kpcd->counterc);
}

void
kperf_kpc_cpu_sample(struct kpcdata *kpcd, int sample_config)
{
	BUF_INFO(PERF_KPC_CPU_SAMPLE | DBG_FUNC_START, sample_config);

	kpcd->running  = kpc_get_running();
	kpcd->counterc = kpc_get_cpu_counters(0, kpcd->running,
	    &kpcd->curcpu,
	    kpcd->counterv);
	if (!sample_config) {
		kpcd->configc = 0;
	} else {
		kpcd->configc = kpc_get_config_count(kpcd->running);
		kpc_get_config(kpcd->running, kpcd->configv);
	}

	BUF_INFO(PERF_KPC_CPU_SAMPLE | DBG_FUNC_END, kpcd->running, kpcd->counterc);
}

void
kperf_kpc_config_log(const struct kpcdata *kpcd)
{
	BUF_DATA(PERF_KPC_CONFIG,
	    kpcd->running,
	    kpcd->counterc,
	    kpc_get_counter_count(KPC_CLASS_FIXED_MASK),
	    kpcd->configc);

#if __LP64__
	unsigned int max = (kpcd->configc + 3) / 4;
	for (unsigned int i = 0; i < max; i++) {
		uint32_t flag = (i == 0) ? DBG_FUNC_START : ((i == (max - 1)) ? DBG_FUNC_END : DBG_FUNC_NONE);
		BUF_DATA(PERF_KPC_CFG_REG | flag,
		    kpcd->configv[0 + i * 4], kpcd->configv[1 + i * 4],
		    kpcd->configv[2 + i * 4], kpcd->configv[3 + i * 4]);
	}
#else /* __LP64__ */
	unsigned int max = (kpcd->configc + 1) / 2;
	for (unsigned int i = 0; i < max; i++) {
		uint32_t flag = (i == 0) ? DBG_FUNC_START : ((i == (max - 1)) ? DBG_FUNC_END : DBG_FUNC_NONE);
		BUF_DATA(PERF_KPC_CFG_REG32 | flag,
		    kpcd->configv[i * 2] >> 32ULL,
		    kpcd->configv[i * 2] & 0xffffffffULL,
		    kpcd->configv[i * 2 + 1] >> 32ULL,
		    kpcd->configv[i * 2 + 1] & 0xffffffffULL);
	}
#endif /* !__LP64__ */
}

static void
kperf_kpc_log(uint32_t code, uint32_t code32, const struct kpcdata *kpcd)
{
#if __LP64__
#pragma unused(code32)
	unsigned int max = (kpcd->counterc + 3) / 4;
	/* and the actual counts with one 64-bit argument each */
	for (unsigned int i = 0; i < max; i++) {
		uint32_t flag = (i == 0) ? DBG_FUNC_START : ((i == (max - 1)) ? DBG_FUNC_END : DBG_FUNC_NONE);
		BUF_DATA(code | flag,
		    kpcd->counterv[0 + i * 4],
		    kpcd->counterv[1 + i * 4],
		    kpcd->counterv[2 + i * 4],
		    kpcd->counterv[3 + i * 4]);
	}
#else /* __LP64__ */
#pragma unused(code)
	unsigned int max = (kpcd->counterc + 1) / 2;
	/* and the actual counts with two 32-bit trace arguments each */
	for (unsigned int i = 0; i < max; i++) {
		uint32_t flag = (i == 0) ? DBG_FUNC_START : ((i == (max - 1)) ? DBG_FUNC_END : DBG_FUNC_NONE);
		BUF_DATA(code32 | flag,
		    (kpcd->counterv[0 + i * 2] >> 32ULL),
		    kpcd->counterv[0 + i * 2] & 0xffffffffULL,
		    (kpcd->counterv[1 + i * 2] >> 32ULL),
		    kpcd->counterv[1 + i * 2] & 0xffffffffULL);
	}
#endif /* !__LP64__ */
}

void
kperf_kpc_cpu_log(const struct kpcdata *kpcd)
{
	kperf_kpc_log(PERF_KPC_DATA, PERF_KPC_DATA32, kpcd);
}

void
kperf_kpc_thread_log(const struct kpcdata *kpcd)
{
	kperf_kpc_log(PERF_KPC_DATA_THREAD, PERF_KPC_DATA_THREAD32, kpcd);
}

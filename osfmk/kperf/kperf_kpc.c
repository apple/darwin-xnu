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


/*  Sample KPC data into kperf */

#include <mach/mach_types.h>
#include <kern/thread.h> /* thread_* */
#include <kern/debug.h> /* panic */
// #include <sys/proc.h>

#include <chud/chud_xnu.h>
#include <kperf/kperf.h>

#include <kperf/buffer.h>
#include <kperf/context.h>

#include <kperf/kperf_kpc.h>

/* If we have kperf enabled, but not KPC */
#if KPC

void
kperf_kpc_cpu_sample( struct kpcdata *kpcd, int sample_config )
{
	kpcd->running  = kpc_get_running();
	kpcd->counterc = kpc_get_cpu_counters(0, kpcd->running,
	                                      &kpcd->curcpu, kpcd->counterv);
	if( !sample_config )
		kpcd->configc = 0;
	else
	{
		kpcd->configc = kpc_get_config_count(kpcd->running);
		kpc_get_config(kpcd->running, kpcd->configv);
	}
	
}

void
kperf_kpc_cpu_log( struct kpcdata *kpcd )
{
	unsigned i;

	/* cut a config for instruments -- what's running and
	 * how many fixed counters there are
	 */
	BUF_DATA(PERF_KPC_CONFIG,
	         kpcd->running,
	         kpcd->counterc,
	         kpc_get_counter_count(KPC_CLASS_FIXED_MASK),
	         kpcd->configc);

#if __LP64__
	/* config registers, if they were asked for */
	for (i = 0; i < ((kpcd->configc+3) / 4); i++) {
		BUF_DATA( PERF_KPC_CFG_REG,
		          kpcd->configv[0 + i * 4],
		          kpcd->configv[1 + i * 4],
		          kpcd->configv[2 + i * 4],
		          kpcd->configv[3 + i * 4] );
	}

	/* and the actual data -- 64-bit trace entries */
	for (i = 0; i < ((kpcd->counterc+3) / 4); i++) {
		BUF_DATA( PERF_KPC_DATA,
		          kpcd->counterv[0 + i * 4],
		          kpcd->counterv[1 + i * 4],
		          kpcd->counterv[2 + i * 4],
		          kpcd->counterv[3 + i * 4] );
	}

#else
	/* config registers, if requested */
	for (i = 0; i < ((kpcd->configc+1) / 2); i++) {
		BUF_DATA( PERF_KPC_CFG_REG32,
		          (kpcd->configv[0 + i * 2] >> 32ULL),
		           kpcd->configv[0 + i * 2] & 0xffffffffULL,
		          (kpcd->configv[1 + i * 2] >> 32ULL),
		           kpcd->configv[1 + i * 2] & 0xffffffffULL );
	}

	/* and the actual data -- two counters per tracepoint */
	for (i = 0; i < ((kpcd->counterc+1) / 2); i++) {
		BUF_DATA( PERF_KPC_DATA32,
		          (kpcd->counterv[0 + i * 2] >> 32ULL),
		           kpcd->counterv[0 + i * 2] & 0xffffffffULL,
		          (kpcd->counterv[1 + i * 2] >> 32ULL),
		           kpcd->counterv[1 + i * 2] & 0xffffffffULL );
	}
#endif
}

#endif /* KPC */

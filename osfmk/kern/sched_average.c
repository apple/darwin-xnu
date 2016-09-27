/*
 * Copyright (c) 2000-2007 Apple Computer, Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */
/*
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1986
 *
 *	Compute various averages.
 */

#include <mach/mach_types.h>

#include <kern/sched.h>
#include <kern/assert.h>
#include <kern/processor.h>
#include <kern/thread.h>
#if CONFIG_TELEMETRY
#include <kern/telemetry.h>
#endif

#include <sys/kdebug.h>

uint32_t	avenrun[3] = {0, 0, 0};
uint32_t	mach_factor[3] = {0, 0, 0};

uint32_t	sched_load_average, sched_mach_factor;

#if defined(CONFIG_SCHED_TIMESHARE_CORE)
/*
 * Values are scaled by LOAD_SCALE, defined in processor_info.h
 */
#define base(n)		((n) << SCHED_TICK_SHIFT)
#define frac(n)		(((base(n) - 1) * LOAD_SCALE) /	base(n))

static uint32_t		fract[3] = {
	frac(5),		/* 5 second average */
	frac(30),		/* 30 second average */
	frac(60),		/* 1 minute average */
};

#undef base
#undef frac

#endif /* CONFIG_SCHED_TIMESHARE_CORE */

static unsigned int		sched_nrun;

typedef void	(*sched_avg_comp_t)(
					void			*param);

static struct sched_average {
	sched_avg_comp_t	comp;
	void			*param;
	int			period; /* in seconds */
	uint64_t		deadline;
} sched_average[] = {
	{ compute_averunnable, &sched_nrun, 5, 0 },
	{ compute_stack_target, NULL, 5, 1 },
	{ compute_memory_pressure, NULL, 1, 0 },
	{ compute_pageout_gc_throttle, NULL, 1, 0 },
	{ compute_pmap_gc_throttle, NULL, 60, 0 },
#if CONFIG_TELEMETRY
	{ compute_telemetry, NULL, 1, 0 },
#endif
	{ NULL, NULL, 0, 0 }
};

typedef struct sched_average	*sched_average_t;

uint32_t load_now[TH_BUCKET_MAX];

/* The "stdelta" parameter represents the number of scheduler maintenance
 * "ticks" that have elapsed since the last invocation, subject to
 * integer division imprecision.
 */

void
compute_averages(uint64_t stdelta)
{
	/*
	 * Retrieve a snapshot of the current run counts.
	 *
	 * Why not a bcopy()? Because we need atomic word-sized reads of sched_run_buckets,
	 * not byte-by-byte copy.
	 */
	uint32_t ncpus = processor_avail_count;

	load_now[TH_BUCKET_RUN]      = sched_run_buckets[TH_BUCKET_RUN];
	load_now[TH_BUCKET_FIXPRI]   = sched_run_buckets[TH_BUCKET_FIXPRI];
	load_now[TH_BUCKET_SHARE_FG] = sched_run_buckets[TH_BUCKET_SHARE_FG];
	load_now[TH_BUCKET_SHARE_UT] = sched_run_buckets[TH_BUCKET_SHARE_UT];
	load_now[TH_BUCKET_SHARE_BG] = sched_run_buckets[TH_BUCKET_SHARE_BG];

	assert(load_now[TH_BUCKET_RUN] >= 0);
	assert(load_now[TH_BUCKET_FIXPRI] >= 0);

	/* Ignore the current thread, which is a running fixpri thread */

	uint32_t nthreads = load_now[TH_BUCKET_RUN] - 1;
	uint32_t nfixpri  = load_now[TH_BUCKET_FIXPRI] - 1;

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	        MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_LOAD) | DBG_FUNC_NONE,
	        load_now[TH_BUCKET_FIXPRI] - 1, load_now[TH_BUCKET_SHARE_FG],
	        load_now[TH_BUCKET_SHARE_BG],   load_now[TH_BUCKET_SHARE_UT], 0);

	/*
	 * Compute the timeshare priority conversion factor based on loading.
	 * Because our counters may be incremented and accessed
	 * concurrently with respect to each other, we may have
	 * windows where the invariant (nthreads - nfixpri) == (fg + bg + ut)
	 * is broken, so truncate values in these cases.
	 */

	uint32_t timeshare_threads = (nthreads - nfixpri);

	for (uint32_t i = TH_BUCKET_SHARE_FG; i <= TH_BUCKET_SHARE_BG ; i++) {
		if (load_now[i] > timeshare_threads)
			load_now[i] = timeshare_threads;
	}

	/*
	 * Utility threads contribute up to NCPUS of load to FG threads
	 */
	if (load_now[TH_BUCKET_SHARE_UT] <= ncpus) {
		load_now[TH_BUCKET_SHARE_FG] += load_now[TH_BUCKET_SHARE_UT];
	} else {
		load_now[TH_BUCKET_SHARE_FG] += ncpus;
	}

	/*
	 * FG and UT should notice there's one thread of competition from BG,
	 * but no more.
	 */
	if (load_now[TH_BUCKET_SHARE_BG] > 0) {
		load_now[TH_BUCKET_SHARE_FG] += 1;
		load_now[TH_BUCKET_SHARE_UT] += 1;
	}

	/*
	 * The conversion factor consists of two components:
	 * a fixed value based on the absolute time unit (sched_fixed_shift),
	 * and a dynamic portion based on load (sched_load_shifts).
	 *
	 * Zero load results in a out of range shift count.
	 */

	for (uint32_t i = TH_BUCKET_SHARE_FG; i <= TH_BUCKET_SHARE_BG ; i++) {
		uint32_t bucket_load = 0;

		if (load_now[i] > ncpus) {
			if (ncpus > 1)
				bucket_load = load_now[i] / ncpus;
			else
				bucket_load = load_now[i];

			if (bucket_load > MAX_LOAD)
				bucket_load = MAX_LOAD;
		}

		sched_pri_shifts[i] = sched_fixed_shift - sched_load_shifts[bucket_load];
	}

	/*
	 * Sample total running threads for the load average calculation.
	 */
	sched_nrun = nthreads;

	/*
	 * Load average and mach factor calculations for
	 * those which ask about these things.
	 */
	uint32_t average_now = nthreads * LOAD_SCALE;
	uint32_t factor_now;

	if (nthreads > ncpus)
		factor_now = (ncpus * LOAD_SCALE) / (nthreads + 1);
	else
		factor_now = (ncpus - nthreads) * LOAD_SCALE;

	/*
	 * For those statistics that formerly relied on being recomputed
	 * on timer ticks, advance by the approximate number of corresponding
	 * elapsed intervals, thus compensating for potential idle intervals.
	 */
	for (uint32_t index = 0; index < stdelta; index++) {
		sched_mach_factor = ((sched_mach_factor << 2) + factor_now) / 5;
		sched_load_average = ((sched_load_average << 2) + average_now) / 5;
	}

	/*
	 * Compute old-style Mach load averages.
	 */
	for (uint32_t index = 0; index < stdelta; index++) {
		for (uint32_t i = 0; i < 3; i++) {
			mach_factor[i] = ((mach_factor[i] * fract[i]) +
						(factor_now * (LOAD_SCALE - fract[i]))) / LOAD_SCALE;

			avenrun[i] = ((avenrun[i] * fract[i]) +
						(average_now * (LOAD_SCALE - fract[i]))) / LOAD_SCALE;
		}
	}

	/*
	 * Compute averages in other components.
	 */
	uint64_t abstime = mach_absolute_time();

	for (sched_average_t avg = sched_average; avg->comp != NULL; ++avg) {
		if (abstime >= avg->deadline) {
			uint64_t period_abs = (avg->period * sched_one_second_interval);
			uint64_t ninvokes = 1;

			ninvokes += (abstime - avg->deadline) / period_abs;
			ninvokes = MIN(ninvokes, SCHED_TICK_MAX_DELTA);

			for (uint32_t index = 0; index < ninvokes; index++) {
				(*avg->comp)(avg->param);
			}
			avg->deadline = abstime + period_abs;
		}
	}
}

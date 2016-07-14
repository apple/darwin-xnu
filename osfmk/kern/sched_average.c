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
	{ compute_zone_gc_throttle, NULL, 60, 0 },
	{ compute_pageout_gc_throttle, NULL, 1, 0 },
	{ compute_pmap_gc_throttle, NULL, 60, 0 },
#if CONFIG_TELEMETRY
	{ compute_telemetry, NULL, 1, 0 },
#endif
	{ NULL, NULL, 0, 0 }
};

typedef struct sched_average	*sched_average_t;

/* The "stdelta" parameter represents the number of scheduler maintenance
 * "ticks" that have elapsed since the last invocation, subject to
 * integer division imprecision.
 */

void
compute_averages(uint64_t stdelta)
{
	int			ncpus, nthreads, nshared, nbackground, nshared_non_bg;
	uint32_t		factor_now, average_now, load_now = 0, background_load_now = 0, combined_fgbg_load_now = 0;
	sched_average_t		avg;
	uint64_t		abstime, index;

	/*
	 *	Retrieve counts, ignoring
	 *	the current thread.
	 */
	ncpus = processor_avail_count;
	nthreads = sched_run_count - 1;
	nshared = sched_share_count;
	nbackground = sched_background_count;

	/*
	 *	Load average and mach factor calculations for
	 *	those which ask about these things.
	 */
	average_now = nthreads * LOAD_SCALE;

	if (nthreads > ncpus)
		factor_now = (ncpus * LOAD_SCALE) / (nthreads + 1);
	else
		factor_now = (ncpus - nthreads) * LOAD_SCALE;

	/* For those statistics that formerly relied on being recomputed
	 * on timer ticks, advance by the approximate number of corresponding
	 * elapsed intervals, thus compensating for potential idle intervals.
	 */
	for (index = 0; index < stdelta; index++) {
		sched_mach_factor = ((sched_mach_factor << 2) + factor_now) / 5;
		sched_load_average = ((sched_load_average << 2) + average_now) / 5;
	}
	/*
	 * Compute the timeshare priority conversion factor based on loading.
	 * Because our counters may be incremented and accessed
	 * concurrently with respect to each other, we may have
	 * windows where the invariant nthreads >= nshared >= nbackground
	 * is broken, so truncate values in these cases.
	 */

	if (nshared > nthreads)
		nshared = nthreads;

	if (nbackground > nshared)
		nbackground = nshared;

	nshared_non_bg = nshared - nbackground;

	if (nshared_non_bg > ncpus) {
		if (ncpus > 1)
			load_now = nshared_non_bg / ncpus;
		else
			load_now = nshared_non_bg;

		if (load_now > NRQS - 1)
			load_now = NRQS - 1;
	}

	if (nbackground > ncpus) {
		if (ncpus > 1)
			background_load_now = nbackground / ncpus;
		else
			background_load_now = nbackground;

		if (background_load_now > NRQS - 1)
			background_load_now = NRQS - 1;
	}

	if (nshared > ncpus) {
		if (ncpus > 1)
			combined_fgbg_load_now = nshared / ncpus;
		else
			combined_fgbg_load_now = nshared;

		if (combined_fgbg_load_now > NRQS - 1)
			combined_fgbg_load_now = NRQS - 1;
	}

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_LOAD) | DBG_FUNC_NONE,
		(nthreads - nshared), (nshared - nbackground), nbackground, 0, 0);

	/*
	 *	Sample total running threads.
	 */
	sched_nrun = nthreads;
	
#if defined(CONFIG_SCHED_TIMESHARE_CORE)

	/*
	 *	The conversion factor consists of
	 *	two components: a fixed value based
	 *	on the absolute time unit, and a
	 *	dynamic portion based on loading.
	 *
	 *	Zero loading results in a out of range
	 *	shift count.  Accumulated usage is ignored
	 *	during conversion and new usage deltas
	 *	are discarded.
	 */
	sched_pri_shift = sched_fixed_shift - sched_load_shifts[load_now];
	sched_background_pri_shift = sched_fixed_shift - sched_load_shifts[background_load_now];
	sched_combined_fgbg_pri_shift = sched_fixed_shift - sched_load_shifts[combined_fgbg_load_now];

	/*
	 * Compute old-style Mach load averages.
	 */

	for (index = 0; index < stdelta; index++) {
		register int		i;

		for (i = 0; i < 3; i++) {
			mach_factor[i] = ((mach_factor[i] * fract[i]) +
						(factor_now * (LOAD_SCALE - fract[i]))) / LOAD_SCALE;

			avenrun[i] = ((avenrun[i] * fract[i]) +
						(average_now * (LOAD_SCALE - fract[i]))) / LOAD_SCALE;
		}
	}
#endif /* CONFIG_SCHED_TIMESHARE_CORE */

	/*
	 *	Compute averages in other components.
	 */
	abstime = mach_absolute_time();
	for (avg = sched_average; avg->comp != NULL; ++avg) {
		if (abstime >= avg->deadline) {
			uint64_t period_abs = (avg->period * sched_one_second_interval);
			uint64_t ninvokes = 1;

			ninvokes += (abstime - avg->deadline) / period_abs;
			ninvokes = MIN(ninvokes, SCHED_TICK_MAX_DELTA);

			for (index = 0; index < ninvokes; index++) {
				(*avg->comp)(avg->param);
			}
			avg->deadline = abstime + period_abs;
		}
	}
}

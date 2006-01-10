/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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
	
uint32_t	avenrun[3] = {0, 0, 0};
uint32_t	mach_factor[3] = {0, 0, 0};

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

static unsigned int		sched_nrun;

typedef void	(*sched_avg_comp_t)(
					void			*param);

#define SCHED_AVG_SECS(n)	((n) << SCHED_TICK_SHIFT)

static struct sched_average {
	sched_avg_comp_t	comp;
	void				*param;
	int					period;
	int					tick;			
} sched_average[] = {
	{ compute_averunnable, &sched_nrun, SCHED_AVG_SECS(5), 0 },
	{ compute_stack_target, NULL, SCHED_AVG_SECS(5), 1 },
	{ NULL, NULL, 0, 0 }
};

typedef struct sched_average	*sched_average_t;

void
compute_averages(void)
{
	register processor_set_t	pset = &default_pset;
	register int				ncpus;
	register int				nthreads, nshared;
	sched_average_t				avg;
	register uint32_t			factor_now = 0;
	register uint32_t			average_now = 0;
	register uint32_t			load_now = 0;

	if ((ncpus = pset->processor_count) > 0) {
		/*
		 *	Retrieve counts, ignoring
		 *	the current thread.
		 */
		nthreads = pset->run_count - 1;
		nshared = pset->share_count;

		/*
		 *	Load average and mach factor calculations for
		 *	those which ask about these things.
		 */
		average_now = nthreads * LOAD_SCALE;

		if (nthreads > ncpus)
			factor_now = (ncpus * LOAD_SCALE) / (nthreads + 1);
		else
			factor_now = (ncpus - nthreads) * LOAD_SCALE;

		pset->mach_factor =	((pset->mach_factor << 2) + factor_now) / 5;
		pset->load_average = ((pset->load_average << 2) + average_now) / 5;

		/*
		 *	Compute the timeshare priority
		 *	conversion factor based on loading.
		 */
		if (nshared > nthreads)
			nshared = nthreads;

		if (nshared > ncpus) {
			if (ncpus > 1)
				load_now = nshared / ncpus;
			else
				load_now = nshared;

			if (load_now > NRQS - 1)
				load_now = NRQS - 1;
		}

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
		pset->pri_shift = sched_pri_shift - sched_load_shifts[load_now];
	}
	else {
		pset->mach_factor = pset->load_average = 0;
		pset->pri_shift = INT8_MAX;
		nthreads = pset->run_count;
	}

	/*
	 *	Sample total running threads.
	 */
	sched_nrun = nthreads;

	/*
	 * Compute old-style Mach load averages.
	 */
	{
		register int		i;

		for (i = 0; i < 3; i++) {
			mach_factor[i] = ((mach_factor[i] * fract[i]) +
						(factor_now * (LOAD_SCALE - fract[i]))) / LOAD_SCALE;

			avenrun[i] = ((avenrun[i] * fract[i]) +
						(average_now * (LOAD_SCALE - fract[i]))) / LOAD_SCALE;
		}
	}

	/*
	 *	Compute averages in other components.
	 */
	for (avg = sched_average; avg->comp != NULL; ++avg) {
		if (++avg->tick >= avg->period) {
			(*avg->comp)(avg->param);
			avg->tick = 0;
		}
	}
}

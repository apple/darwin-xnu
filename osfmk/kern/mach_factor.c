/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
 *	File:	kern/mach_factor.c
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1986
 *
 *	Compute the Mach Factor.
 */

#include <cpus.h>

#include <mach/machine.h>
#include <mach/processor_info.h>
#include <kern/sched.h>
#include <kern/assert.h>
#include <kern/processor.h>
#include <kern/thread.h>
#if	MACH_KERNEL
#include <mach/kern_return.h>
#include <mach/port.h>
#endif	/* MACH_KERNEL */

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

void
compute_mach_factor(void)
{
	register processor_set_t	pset = &default_pset;
	register int				ncpus;
	register int				nthreads, nshared;
	register uint32_t			factor_now = 0;
	register uint32_t			average_now = 0;
	register uint32_t			load_now = 0;

	if ((ncpus = pset->processor_count) > 0) {
		/*
		 *	Retrieve thread counts.
		 */
		nthreads = pset->run_count;
		nshared = pset->share_count;

		/*
		 *	Don't include the current thread.
		 */
		nthreads -= 1;

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
		 *	Compute the load factor used by the timesharing
		 *	algorithm.
		 */
		if (nshared > nthreads)
			nshared = nthreads;

		if (nshared > ncpus)
			load_now = (nshared << SCHED_SHIFT) / ncpus;

		pset->sched_load = (pset->sched_load + load_now) >> 1;
	}
	else {
		pset->mach_factor = pset->load_average = 0;
		pset->sched_load = 0;
	}

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
	 * Call out to BSD for averunnable.
	 */
	{
#define AVGTICK_PERIOD		(5 << SCHED_TICK_SHIFT)
		static uint32_t		avgtick_count;
		extern void			compute_averunnable(
								int				nrun);

		if (++avgtick_count == 1)
			compute_averunnable(nthreads);
		else
		if (avgtick_count >= AVGTICK_PERIOD)
			avgtick_count = 0;
	}
}

/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
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

integer_t	avenrun[3] = {0, 0, 0};
integer_t	mach_factor[3] = {0, 0, 0};

/*
 * Values are scaled by LOAD_SCALE, defined in processor_info.h
 */
#define base(n)		((n) << SCHED_TICK_SHIFT)
#define frac(n)		(((base(n) - 1) * LOAD_SCALE) /	base(n))

static	long	fract[3] = {
	frac(5),		/* 5 second average */
	frac(30),		/* 30 second average */
	frac(60),		/* 1 minute average */
};
#undef base
#undef frac

void
compute_mach_factor(void)
{
	register processor_set_t	pset;
	register processor_t		processor;
	register int				ncpus;
	register int				nthreads;
	register long				factor_now = 0L;
	register long				average_now = 0L;
	register long				load_now = 0L;

	pset = &default_pset;
	simple_lock(&pset->processors_lock);
	if ((ncpus = pset->processor_count) > 0) {
		/*
		 *	Count number of threads.
		 */
		nthreads = pset->runq.count;
		processor = (processor_t)queue_first(&pset->processors);
		while (!queue_end(&pset->processors, (queue_entry_t)processor)) {
			nthreads += processor->runq.count;

			processor = (processor_t)queue_next(&processor->processors);
		}

		/*
		 * account for threads on cpus.
		 */
		nthreads += ncpus - pset->idle_count; 

		/*
		 *	The current thread (running this calculation)
		 *	doesn't count; it's always in the default pset.
		 */
		if (pset == &default_pset)
			nthreads -= 1;

		if (nthreads >= ncpus)
			factor_now = (ncpus * LOAD_SCALE) / (nthreads + 1);
		else
			factor_now = (ncpus - nthreads) * LOAD_SCALE;

		if (nthreads > ncpus)
			load_now = (nthreads << SCHED_SHIFT) / ncpus;
		else
			load_now = 0;

		/*
		 *	Load average and mach factor calculations for
		 *	those that ask about these things.
		 */

		average_now = (nthreads * LOAD_SCALE) / ncpus;

		pset->mach_factor =	((pset->mach_factor << 2) + factor_now) / 5;
		pset->load_average = ((pset->load_average << 2) + average_now) / 5;

		/*
		 *	sched_load is the only thing used by scheduler.
		 */
		pset->sched_load = (pset->sched_load + load_now) >> 1;
	}
	else {
		pset->mach_factor = pset->load_average = 0;
		pset->sched_load = 0;
	}

	simple_unlock(&pset->processors_lock);

	/*
	 *	And some ugly stuff to keep w happy.
	 */
	{
		register int i;

		for (i = 0; i < 3; i++) {
			mach_factor[i] = ((mach_factor[i] * fract[i]) +
						(factor_now * (LOAD_SCALE - fract[i]))) / LOAD_SCALE;

			avenrun[i] = ((avenrun[i] * fract[i]) +
						(average_now * (LOAD_SCALE - fract[i]))) / LOAD_SCALE;
		}
	}
}

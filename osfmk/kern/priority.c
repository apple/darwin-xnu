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
 *	File:	clock_prim.c
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1986
 *
 *	Clock primitives.
 */

#include <cpus.h>

#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/machine.h>
#include <kern/host.h>
#include <kern/mach_param.h>
#include <kern/sched.h>
#include <kern/spl.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <machine/machparam.h>
#include <kern/sf.h>
#include <kern/mk_sp.h>	/*** ??? fix so this can be removed ***/
/*** ??? Should this file be MK SP-specific?  Or is it more general purpose? ***/



/*
 *	USAGE_THRESHOLD is the amount by which usage must change to
 *	cause a priority shift that moves a thread between run queues.
 */

#ifdef	PRI_SHIFT_2
#if	PRI_SHIFT_2 > 0
#define	USAGE_THRESHOLD (((1 << PRI_SHIFT) + (1 << PRI_SHIFT_2)) << (2 + SCHED_SHIFT))
#else	/* PRI_SHIFT_2 > 0 */
#define	USAGE_THRESHOLD (((1 << PRI_SHIFT) - (1 << -(PRI_SHIFT_2))) << (2 + SCHED_SHIFT))
#endif	/* PRI_SHIFT_2 > 0 */
#else	/* PRI_SHIFT_2 */
#define USAGE_THRESHOLD	(1 << (PRI_SHIFT + 2 + SCHED_SHIFT))
#endif	/* PRI_SHIFT_2 */

/*
 *	thread_quantum_update:
 *
 *	Recalculate the quantum and priority for a thread.
 *	The number of ticks that has elapsed since we were last called
 *	is passed as "nticks."
 */

void
thread_quantum_update(
	register int		mycpu,
	register thread_t	thread,
	int					nticks,
	int					state)
{
	register int				quantum;
	register processor_t		myprocessor;
	register processor_set_t	pset;
	spl_t						s;

	myprocessor = cpu_to_processor(mycpu);
	pset = myprocessor->processor_set;

	/*
	 *	Account for thread's utilization of these ticks.
	 *	This assumes that there is *always* a current thread.
	 *	When the processor is idle, it should be the idle thread.
	 */

	/*
	 *	Update set_quantum and calculate the current quantum.
	 */
	pset->set_quantum = pset->machine_quantum[
							(pset->runq.count > pset->processor_count) ?
								  pset->processor_count : pset->runq.count];

	if (myprocessor->runq.count != 0)
		quantum = min_quantum;
	else
		quantum = pset->set_quantum;
		
	/*
	 *	Now recompute the priority of the thread if appropriate.
	 */

	{
		s = splsched();
		thread_lock(thread);

		if (!(thread->policy & (POLICY_TIMESHARE|POLICY_RR|POLICY_FIFO))) {
			thread_unlock(thread);
			splx(s);
			return;
		}

		if (thread->state&TH_IDLE) {
			/* Don't try to time-slice idle threads */
			myprocessor->first_quantum = TRUE;
			if (thread->sched_stamp != sched_tick)
				update_priority(thread);
			thread_unlock(thread);
			splx(s);
			ast_check();
			return;
		}

		myprocessor->quantum -= nticks;
		/*
		 *	Runtime quantum adjustment.  Use quantum_adj_index
		 *	to avoid synchronizing quantum expirations.
		 */
		if (	quantum != myprocessor->last_quantum	&&
					pset->processor_count > 1					) {
			myprocessor->last_quantum = quantum;
			simple_lock(&pset->quantum_adj_lock);
			quantum = min_quantum + (pset->quantum_adj_index *
											(quantum - min_quantum)) / 
												(pset->processor_count - 1);
			if (++(pset->quantum_adj_index) >= pset->processor_count)
				pset->quantum_adj_index = 0;
			simple_unlock(&pset->quantum_adj_lock);
		}
		if (myprocessor->quantum <= 0) {
			if (thread->sched_stamp != sched_tick)
				update_priority(thread);
			else
			if (	thread->policy == POLICY_TIMESHARE		&&
					thread->depress_priority < 0				) {
				thread_timer_delta(thread);
				thread->sched_usage += thread->sched_delta;
				thread->sched_delta = 0;
				compute_my_priority(thread);
			}

			/*
			 *	This quantum is up, give this thread another.
			 */
			myprocessor->first_quantum = FALSE;
			if (thread->policy == POLICY_TIMESHARE)
				myprocessor->quantum += quantum;
			else
				myprocessor->quantum += min_quantum;
		}
		/*
		 *	Recompute priority if appropriate.
		 */
		else {
		    if (thread->sched_stamp != sched_tick)
				update_priority(thread);
		    else
			if (	thread->policy == POLICY_TIMESHARE		&&
					thread->depress_priority < 0				) {
				thread_timer_delta(thread);
				if (thread->sched_delta >= USAGE_THRESHOLD) {
				    thread->sched_usage +=	thread->sched_delta;
				    thread->sched_delta = 0;
				    compute_my_priority(thread);
				}
			}
		}

		thread_unlock(thread);
		splx(s);

		/*
		 * Check for and schedule ast if needed.
		 */
		ast_check();
	}
}

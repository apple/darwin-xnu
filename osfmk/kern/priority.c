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

/*
 *	thread_quantum_expire:
 *
 *	Recalculate the quantum and priority for a thread.
 */

void
thread_quantum_expire(
	timer_call_param_t	p0,
	timer_call_param_t	p1)
{
	register processor_t		myprocessor = p0;
	register thread_t			thread = p1;
	spl_t						s;

	s = splsched();
	thread_lock(thread);

	/*
	 *	Check for fail-safe trip.
	 */
	if (!(thread->sched_mode & TH_MODE_TIMESHARE)) {
		extern uint64_t		max_unsafe_computation;
		uint64_t			new_computation;

		new_computation = myprocessor->quantum_end;
		new_computation -= thread->computation_epoch;
		if (new_computation + thread->computation_metered >
											max_unsafe_computation) {
			extern uint32_t		sched_safe_duration;

			if (thread->sched_mode & TH_MODE_REALTIME) {
				thread->priority = DEPRESSPRI;

				thread->safe_mode |= TH_MODE_REALTIME;
				thread->sched_mode &= ~TH_MODE_REALTIME;
			}

			thread->safe_release = sched_tick + sched_safe_duration;
			thread->sched_mode |= (TH_MODE_FAILSAFE|TH_MODE_TIMESHARE);
			thread->sched_mode &= ~TH_MODE_PREEMPT;
		}
	}
		
	/*
	 *	Recompute scheduled priority if appropriate.
	 */
	if (thread->sched_stamp != sched_tick)
		update_priority(thread);
	else
	if (thread->sched_mode & TH_MODE_TIMESHARE) {
		thread_timer_delta(thread);
		thread->sched_usage += thread->sched_delta;
		thread->sched_delta = 0;

		/*
		 * Adjust the scheduled priority if
		 * the thread has not been promoted
		 * and is not depressed.
		 */
		if (	!(thread->sched_mode & TH_MODE_PROMOTED)	&&
				!(thread->sched_mode & TH_MODE_ISDEPRESSED)		)
			compute_my_priority(thread);
	}

	/*
	 *	This quantum is up, give this thread another.
	 */
	if (first_quantum(myprocessor))
		myprocessor->slice_quanta--;

	thread->current_quantum = (thread->sched_mode & TH_MODE_REALTIME)?
									thread->realtime.computation: std_quantum;
	myprocessor->quantum_end += thread->current_quantum;
	timer_call_enter1(&myprocessor->quantum_timer,
							thread, myprocessor->quantum_end);

	thread_unlock(thread);

	/*
	 * Check for and schedule ast if needed.
	 */
	ast_check(myprocessor);

	splx(s);
}

/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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
 *	File:	clock_prim.c
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1986
 *
 *	Clock primitives.
 */

#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/machine.h>
#include <kern/host.h>
#include <kern/mach_param.h>
#include <kern/sched.h>
#include <sys/kdebug.h>
#include <kern/spl.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <machine/machparam.h>

/*
 *	thread_quantum_expire:
 *
 *	Recalculate the quantum and priority for a thread.
 *
 *	Called at splsched.
 */

void
thread_quantum_expire(
	timer_call_param_t	p0,
	timer_call_param_t	p1)
{
	processor_t			processor = p0;
	thread_t			thread = p1;
	ast_t				preempt;

	thread_lock(thread);

	/*
	 * We've run up until our quantum expiration, and will (potentially)
	 * continue without re-entering the scheduler, so update this now.
	 */
	thread->last_run_time = processor->quantum_end;
	
	/*
	 *	Check for fail-safe trip.
	 */
	if ((thread->sched_mode == TH_MODE_REALTIME || thread->sched_mode == TH_MODE_FIXED) && 
	    !(thread->sched_flags & TH_SFLAG_PROMOTED) &&
	    !(thread->options & TH_OPT_SYSTEM_CRITICAL)) {
		uint64_t new_computation;

		new_computation = processor->quantum_end - thread->computation_epoch;
		new_computation += thread->computation_metered;
		if (new_computation > max_unsafe_computation) {

			KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_FAILSAFE)|DBG_FUNC_NONE,
					(uintptr_t)thread->sched_pri, (uintptr_t)thread->sched_mode, 0, 0, 0);

			if (thread->sched_mode == TH_MODE_REALTIME) {
				thread->priority = DEPRESSPRI;
			}
			
			thread->saved_mode = thread->sched_mode;

			if (SCHED(supports_timeshare_mode)) {
				sched_share_incr();
				thread->sched_mode = TH_MODE_TIMESHARE;
			} else {
				/* XXX handle fixed->fixed case */
				thread->sched_mode = TH_MODE_FIXED;
			}

			thread->safe_release = processor->quantum_end + sched_safe_duration;
			thread->sched_flags |= TH_SFLAG_FAILSAFE;
		}
	}
		
	/*
	 *	Recompute scheduled priority if appropriate.
	 */
	if (SCHED(can_update_priority)(thread))
		SCHED(update_priority)(thread);
	else
		SCHED(lightweight_update_priority)(thread);

	SCHED(quantum_expire)(thread);
	
	processor->current_pri = thread->sched_pri;
	processor->current_thmode = thread->sched_mode;

	/*
	 *	This quantum is up, give this thread another.
	 */
	if (first_timeslice(processor))
		processor->timeslice--;

	thread_quantum_init(thread);
	thread->last_quantum_refill_time = processor->quantum_end;

	processor->quantum_end += thread->current_quantum;
	timer_call_enter1(&processor->quantum_timer,
							thread, processor->quantum_end, 0);

	/*
	 *	Context switch check.
	 */
	if ((preempt = csw_check(processor)) != AST_NONE)
		ast_on(preempt);
	else {
		processor_set_t		pset = processor->processor_set;

		pset_lock(pset);

		pset_pri_hint(pset, processor, processor->current_pri);
		pset_count_hint(pset, processor, SCHED(processor_runq_count)(processor));

		pset_unlock(pset);
	}

	thread_unlock(thread);
}

#if defined(CONFIG_SCHED_TRADITIONAL)

void
sched_traditional_quantum_expire(thread_t	thread __unused)
{
	/*
	 * No special behavior when a timeshare, fixed, or realtime thread
	 * uses up its entire quantum
	 */
}

void
lightweight_update_priority(thread_t thread)
{
	if (thread->sched_mode == TH_MODE_TIMESHARE) {
		register uint32_t	delta;
		
		thread_timer_delta(thread, delta);
		
		/*
		 *	Accumulate timesharing usage only
		 *	during contention for processor
		 *	resources.
		 */
		if (thread->pri_shift < INT8_MAX)
			thread->sched_usage += delta;
		
		thread->cpu_delta += delta;
		
		/*
		 * Adjust the scheduled priority if
		 * the thread has not been promoted
		 * and is not depressed.
		 */
		if (	!(thread->sched_flags & TH_SFLAG_PROMOTED)	&&
			!(thread->sched_flags & TH_SFLAG_DEPRESSED_MASK)		)
			compute_my_priority(thread);
	}	
}

/*
 *	Define shifts for simulating (5/8) ** n
 *
 *	Shift structures for holding update shifts.  Actual computation
 *	is  usage = (usage >> shift1) +/- (usage >> abs(shift2))  where the
 *	+/- is determined by the sign of shift 2.
 */
struct shift_data {
	int	shift1;
	int	shift2;
};

#define SCHED_DECAY_TICKS	32
static struct shift_data	sched_decay_shifts[SCHED_DECAY_TICKS] = {
	{1,1},{1,3},{1,-3},{2,-7},{3,5},{3,-5},{4,-8},{5,7},
	{5,-7},{6,-10},{7,10},{7,-9},{8,-11},{9,12},{9,-11},{10,-13},
	{11,14},{11,-13},{12,-15},{13,17},{13,-15},{14,-17},{15,19},{16,18},
	{16,-19},{17,22},{18,20},{18,-20},{19,26},{20,22},{20,-22},{21,-27}
};

/*
 *	do_priority_computation:
 *
 *	Calculate the timesharing priority based upon usage and load.
 */
#ifdef CONFIG_EMBEDDED

#define do_priority_computation(thread, pri)							\
	MACRO_BEGIN															\
	(pri) = (thread)->priority		/* start with base priority */		\
	    - ((thread)->sched_usage >> (thread)->pri_shift);				\
	if ((pri) < MAXPRI_THROTTLE) {										\
		if ((thread)->task->max_priority > MAXPRI_THROTTLE)				\
			(pri) = MAXPRI_THROTTLE;									\
		else															\
			if ((pri) < MINPRI_USER)									\
				(pri) = MINPRI_USER;									\
	} else																\
	if ((pri) > MAXPRI_KERNEL)											\
		(pri) = MAXPRI_KERNEL;											\
	MACRO_END

#else

#define do_priority_computation(thread, pri)							\
	MACRO_BEGIN															\
	(pri) = (thread)->priority		/* start with base priority */		\
	    - ((thread)->sched_usage >> (thread)->pri_shift);				\
	if ((pri) < MINPRI_USER)											\
		(pri) = MINPRI_USER;											\
	else																\
	if ((pri) > MAXPRI_KERNEL)											\
		(pri) = MAXPRI_KERNEL;											\
	MACRO_END

#endif /* defined(CONFIG_SCHED_TRADITIONAL) */

#endif

/*
 *	set_priority:
 *
 *	Set the base priority of the thread
 *	and reset its scheduled priority.
 *
 *	Called with the thread locked.
 */
void
set_priority(
	register thread_t	thread,
	register int		priority)
{
	thread->priority = priority;
	SCHED(compute_priority)(thread, FALSE);
}

#if defined(CONFIG_SCHED_TRADITIONAL)

/*
 *	compute_priority:
 *
 *	Reset the scheduled priority of the thread
 *	according to its base priority if the
 *	thread has not been promoted or depressed.
 *
 *	Called with the thread locked.
 */
void
compute_priority(
	register thread_t	thread,
	boolean_t			override_depress)
{
	register int		priority;

	if (	!(thread->sched_flags & TH_SFLAG_PROMOTED)			&&
			(!(thread->sched_flags & TH_SFLAG_DEPRESSED_MASK)	||
				 override_depress							)		) {
		if (thread->sched_mode == TH_MODE_TIMESHARE)
			do_priority_computation(thread, priority);
		else
			priority = thread->priority;

		set_sched_pri(thread, priority);
	}
}

/*
 *	compute_my_priority:
 *
 *	Reset the scheduled priority for
 *	a timesharing thread.
 *
 *	Only for use on the current thread
 *	if timesharing and not depressed.
 *
 *	Called with the thread locked.
 */
void
compute_my_priority(
	register thread_t	thread)
{
	register int		priority;

	do_priority_computation(thread, priority);
	assert(thread->runq == PROCESSOR_NULL);
	thread->sched_pri = priority;
}

/*
 *	can_update_priority
 *
 *	Make sure we don't do re-dispatches more frequently than a scheduler tick.
 *
 *	Called with the thread locked.
 */
boolean_t
can_update_priority(
					thread_t	thread)
{
	if (sched_tick == thread->sched_stamp)
		return (FALSE);
	else
		return (TRUE);
}

/*
 *	update_priority
 *
 *	Perform housekeeping operations driven by scheduler tick.
 *
 *	Called with the thread locked.
 */
void
update_priority(
	register thread_t	thread)
{
	register unsigned	ticks;
	register uint32_t	delta;

	ticks = sched_tick - thread->sched_stamp;
	assert(ticks != 0);
	thread->sched_stamp += ticks;
	thread->pri_shift = sched_pri_shift;

	/*
	 *	Gather cpu usage data.
	 */
	thread_timer_delta(thread, delta);
	if (ticks < SCHED_DECAY_TICKS) {
		register struct shift_data	*shiftp;

		/*
		 *	Accumulate timesharing usage only
		 *	during contention for processor
		 *	resources.
		 */
		if (thread->pri_shift < INT8_MAX)
			thread->sched_usage += delta;

		thread->cpu_usage += delta + thread->cpu_delta;
		thread->cpu_delta = 0;

		shiftp = &sched_decay_shifts[ticks];
		if (shiftp->shift2 > 0) {
		    thread->cpu_usage =
						(thread->cpu_usage >> shiftp->shift1) +
						(thread->cpu_usage >> shiftp->shift2);
		    thread->sched_usage =
						(thread->sched_usage >> shiftp->shift1) +
						(thread->sched_usage >> shiftp->shift2);
		}
		else {
		    thread->cpu_usage =
						(thread->cpu_usage >> shiftp->shift1) -
						(thread->cpu_usage >> -(shiftp->shift2));
		    thread->sched_usage =
						(thread->sched_usage >> shiftp->shift1) -
						(thread->sched_usage >> -(shiftp->shift2));
		}
	}
	else {
		thread->cpu_usage = thread->cpu_delta = 0;
		thread->sched_usage = 0;
	}

	/*
	 *	Check for fail-safe release.
	 */
	if (	(thread->sched_flags & TH_SFLAG_FAILSAFE)		&&
			mach_absolute_time() >= thread->safe_release		) {
		if (thread->saved_mode != TH_MODE_TIMESHARE) {
			if (thread->saved_mode == TH_MODE_REALTIME) {
				thread->priority = BASEPRI_RTQUEUES;
			}

			thread->sched_mode = thread->saved_mode;
			thread->saved_mode = TH_MODE_NONE;

			if ((thread->state & (TH_RUN|TH_IDLE)) == TH_RUN)
				sched_share_decr();

			if (!(thread->sched_flags & TH_SFLAG_DEPRESSED_MASK))
				set_sched_pri(thread, thread->priority);
		}

		thread->sched_flags &= ~TH_SFLAG_FAILSAFE;
	}

	/*
	 *	Recompute scheduled priority if appropriate.
	 */
	if (	(thread->sched_mode == TH_MODE_TIMESHARE)	&&
			!(thread->sched_flags & TH_SFLAG_PROMOTED)	&&
			!(thread->sched_flags & TH_SFLAG_DEPRESSED_MASK)		) {
		register int		new_pri;

		do_priority_computation(thread, new_pri);
		if (new_pri != thread->sched_pri) {
			boolean_t		removed = thread_run_queue_remove(thread);

			thread->sched_pri = new_pri;
			if (removed)
				thread_setrun(thread, SCHED_TAILQ);
		}
	}
	
	return;
}

#endif /* CONFIG_SCHED_TRADITIONAL */

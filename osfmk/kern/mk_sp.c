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
 * 
 */

/***
 *** ??? The following lines were picked up when code was incorporated
 *** into this file from `kern/syscall_subr.c.'  These should be moved
 *** with the code if it moves again.  Otherwise, they should be trimmed,
 *** based on the files included above.
 ***/

#include <mach/boolean.h>
#include <mach/thread_switch.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>
#include <kern/ipc_kobject.h>
#include <kern/processor.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/spl.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/ast.h>
#include <mach/policy.h>

#include <kern/syscall_subr.h>
#include <mach/mach_host_server.h>
#include <mach/mach_syscalls.h>

/***
 *** ??? End of lines picked up when code was incorporated
 *** into this file from `kern/syscall_subr.c.'
 ***/

#include <kern/mk_sp.h>
#include <kern/misc_protos.h>
#include <kern/spl.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/assert.h>
#include <kern/thread.h>
#include <mach/mach_host_server.h>

/***
 *** ??? The next two files supply the prototypes for `thread_set_policy()'
 *** and `thread_policy.'  These routines cannot stay here if they are
 *** exported Mach system calls.
 ***/
#include <mach/thread_act_server.h>
#include <mach/host_priv_server.h>

void
_mk_sp_thread_unblock(
	thread_t			thread)
{
	if (thread->state & TH_IDLE)
		return;

	if (thread->sched_mode & TH_MODE_REALTIME) {
		thread->realtime.deadline = mach_absolute_time();
		thread->realtime.deadline += thread->realtime.constraint;
	}

	thread->current_quantum = 0;
	thread->computation_metered = 0;
	thread->reason = AST_NONE;
}

void
_mk_sp_thread_done(
	thread_t			old_thread,
	thread_t			new_thread,
	processor_t			processor)
{
	/*
	 * A running thread is being taken off a processor:
	 */
	processor->last_dispatch = mach_absolute_time();

	if (old_thread->state & TH_IDLE)
		return;

	/*
	 * Compute remainder of current quantum.
	 */
	if (		first_timeslice(processor)							&&
			processor->quantum_end > processor->last_dispatch		)
		old_thread->current_quantum =
			(processor->quantum_end - processor->last_dispatch);
	else
		old_thread->current_quantum = 0;

	if (old_thread->sched_mode & TH_MODE_REALTIME) {
		/*
		 * Cancel the deadline if the thread has
		 * consumed the entire quantum.
		 */
		if (old_thread->current_quantum == 0) {
			old_thread->realtime.deadline = UINT64_MAX;
			old_thread->reason |= AST_QUANTUM;
		}
	}
	else {
		/*
		 * For non-realtime threads treat a tiny
		 * remaining quantum as an expired quantum
		 * but include what's left next time.
		 */
		if (old_thread->current_quantum < min_std_quantum) {
			old_thread->reason |= AST_QUANTUM;
			old_thread->current_quantum += std_quantum;
		}
	}

	/*
	 * If we are doing a direct handoff then
	 * give the remainder of our quantum to
	 * the next guy.
	 */
	if ((old_thread->reason & (AST_HANDOFF|AST_QUANTUM)) == AST_HANDOFF) {
		new_thread->current_quantum = old_thread->current_quantum;
		old_thread->reason |= AST_QUANTUM;
		old_thread->current_quantum = 0;
	}

	old_thread->last_switch = processor->last_dispatch;

	old_thread->computation_metered +=
			(old_thread->last_switch - old_thread->computation_epoch);
}

void
_mk_sp_thread_begin(
	thread_t			thread,
	processor_t			processor)
{

	/*
	 * The designated thread is beginning execution:
	 */
	if (thread->state & TH_IDLE) {
		timer_call_cancel(&processor->quantum_timer);
		processor->timeslice = 1;

		return;
	}

	if (thread->current_quantum == 0)
		thread_quantum_init(thread);

	processor->quantum_end =
				(processor->last_dispatch + thread->current_quantum);
	timer_call_enter1(&processor->quantum_timer,
							thread, processor->quantum_end);

	processor_timeslice_setup(processor, thread);

	thread->last_switch = processor->last_dispatch;

	thread->computation_epoch = thread->last_switch;
}

void
_mk_sp_thread_dispatch(
	thread_t		thread)
{
	if (thread->reason & AST_QUANTUM)
		thread_setrun(thread, SCHED_TAILQ);
	else
	if (thread->reason & AST_PREEMPT)
		thread_setrun(thread, SCHED_HEADQ);
	else
		thread_setrun(thread, SCHED_PREEMPT | SCHED_TAILQ);

	thread->reason = AST_NONE;
}

/*
 *	thread_policy_common:
 *
 *	Set scheduling policy & priority for thread.
 */
static kern_return_t
thread_policy_common(
	thread_t		thread,
	integer_t		policy,
	integer_t		priority)
{
	spl_t			s;

	if (	thread == THREAD_NULL		||
			invalid_policy(policy)		)
		return(KERN_INVALID_ARGUMENT);

	s = splsched();
	thread_lock(thread);

	if (	!(thread->sched_mode & TH_MODE_REALTIME)	&&
			!(thread->safe_mode & TH_MODE_REALTIME)			) {
		if (!(thread->sched_mode & TH_MODE_FAILSAFE)) {
			integer_t	oldmode = (thread->sched_mode & TH_MODE_TIMESHARE);

			if (policy == POLICY_TIMESHARE && !oldmode) {
				thread->sched_mode |= TH_MODE_TIMESHARE;

				if (thread->state & TH_RUN)
					pset_share_incr(thread->processor_set);
			}
			else
			if (policy != POLICY_TIMESHARE && oldmode) {
				thread->sched_mode &= ~TH_MODE_TIMESHARE;

				if (thread->state & TH_RUN)
					pset_share_decr(thread->processor_set);
			}
		}
		else {
			if (policy == POLICY_TIMESHARE)
				thread->safe_mode |= TH_MODE_TIMESHARE;
			else
				thread->safe_mode &= ~TH_MODE_TIMESHARE;
		}

		if (priority >= thread->max_priority)
			priority = thread->max_priority - thread->task_priority;
		else
		if (priority >= MINPRI_KERNEL)
			priority -= MINPRI_KERNEL;
		else
		if (priority >= MINPRI_SYSTEM)
			priority -= MINPRI_SYSTEM;
		else
			priority -= BASEPRI_DEFAULT;

		priority += thread->task_priority;

		if (priority > thread->max_priority)
			priority = thread->max_priority;
		else
		if (priority < MINPRI)
			priority = MINPRI;

		thread->importance = priority - thread->task_priority;

		set_priority(thread, priority);
	}

	thread_unlock(thread);
	splx(s);

	return (KERN_SUCCESS);
}

/*
 *	thread_set_policy
 *
 *	Set scheduling policy and parameters, both base and limit, for 
 *	the given thread. Policy can be any policy implemented by the
 *	processor set, whether enabled or not. 
 */
kern_return_t
thread_set_policy(
	thread_act_t			thr_act,
	processor_set_t			pset,
	policy_t				policy,
	policy_base_t			base,
	mach_msg_type_number_t	base_count,
	policy_limit_t			limit,
	mach_msg_type_number_t	limit_count)
{
	thread_t				thread;
	int 					max, bas;
	kern_return_t			result = KERN_SUCCESS;

	if (	thr_act == THR_ACT_NULL			||
			pset == PROCESSOR_SET_NULL		)
		return (KERN_INVALID_ARGUMENT);

	thread = act_lock_thread(thr_act);
	if (thread == THREAD_NULL) {
		act_unlock_thread(thr_act);

		return(KERN_INVALID_ARGUMENT);
	}

	if (pset != thread->processor_set) {
		act_unlock_thread(thr_act);

		return(KERN_FAILURE);
	}

	switch (policy) {

	case POLICY_RR:
	{
		policy_rr_base_t		rr_base = (policy_rr_base_t) base;
		policy_rr_limit_t		rr_limit = (policy_rr_limit_t) limit;

		if (	base_count != POLICY_RR_BASE_COUNT		||
				limit_count != POLICY_RR_LIMIT_COUNT		) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		bas = rr_base->base_priority;
		max = rr_limit->max_priority;
		if (invalid_pri(bas) || invalid_pri(max)) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		break;
	}

	case POLICY_FIFO:
	{
		policy_fifo_base_t		fifo_base = (policy_fifo_base_t) base;
		policy_fifo_limit_t		fifo_limit = (policy_fifo_limit_t) limit;

		if (	base_count != POLICY_FIFO_BASE_COUNT	||
				limit_count != POLICY_FIFO_LIMIT_COUNT)		{
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		bas = fifo_base->base_priority;
		max = fifo_limit->max_priority;
		if (invalid_pri(bas) || invalid_pri(max)) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		break;
	}

	case POLICY_TIMESHARE:
	{
		policy_timeshare_base_t		ts_base = (policy_timeshare_base_t) base;
		policy_timeshare_limit_t	ts_limit =
						(policy_timeshare_limit_t) limit;

		if (	base_count != POLICY_TIMESHARE_BASE_COUNT		||
				limit_count != POLICY_TIMESHARE_LIMIT_COUNT			) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		bas = ts_base->base_priority;
		max = ts_limit->max_priority;
		if (invalid_pri(bas) || invalid_pri(max)) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		break;
	}

	default:
		result = KERN_INVALID_POLICY;
	}

	if (result != KERN_SUCCESS) {
		act_unlock_thread(thr_act);

		return(result);
	}

	result = thread_policy_common(thread, policy, bas);
	act_unlock_thread(thr_act);

	return(result);
}


/*
 * 	thread_policy
 *
 *	Set scheduling policy and parameters, both base and limit, for
 *	the given thread. Policy must be a policy which is enabled for the
 *	processor set. Change contained threads if requested. 
 */
kern_return_t
thread_policy(
	thread_act_t			thr_act,
	policy_t				policy,
	policy_base_t			base,
	mach_msg_type_number_t	count,
	boolean_t				set_limit)
{
	thread_t				thread;
	processor_set_t			pset;
	kern_return_t			result = KERN_SUCCESS;
	policy_limit_t			limit;
	int						limcount;
	policy_rr_limit_data_t			rr_limit;
	policy_fifo_limit_data_t		fifo_limit;
	policy_timeshare_limit_data_t	ts_limit;
	
	if (thr_act == THR_ACT_NULL)
		return (KERN_INVALID_ARGUMENT);

	thread = act_lock_thread(thr_act);
	pset = thread->processor_set;
	if (	thread == THREAD_NULL		||
			pset == PROCESSOR_SET_NULL		){
		act_unlock_thread(thr_act);

		return(KERN_INVALID_ARGUMENT);
	}

	if (	invalid_policy(policy)											||
			((POLICY_TIMESHARE | POLICY_RR | POLICY_FIFO) & policy) == 0	) {
		act_unlock_thread(thr_act);

		return(KERN_INVALID_POLICY);
	}

	if (set_limit) {
		/*
	 	 * 	Set scheduling limits to base priority.
		 */
		switch (policy) {

		case POLICY_RR:
		{
			policy_rr_base_t rr_base;

			if (count != POLICY_RR_BASE_COUNT) {
				result = KERN_INVALID_ARGUMENT;
				break;
			}

			limcount = POLICY_RR_LIMIT_COUNT;
			rr_base = (policy_rr_base_t) base;
			rr_limit.max_priority = rr_base->base_priority;
			limit = (policy_limit_t) &rr_limit;

			break;
		}

		case POLICY_FIFO:
		{
			policy_fifo_base_t fifo_base;

			if (count != POLICY_FIFO_BASE_COUNT) {
				result = KERN_INVALID_ARGUMENT;
				break;
			}

			limcount = POLICY_FIFO_LIMIT_COUNT;
			fifo_base = (policy_fifo_base_t) base;
			fifo_limit.max_priority = fifo_base->base_priority;
			limit = (policy_limit_t) &fifo_limit;

			break;
		}

		case POLICY_TIMESHARE:
		{
			policy_timeshare_base_t ts_base;

			if (count != POLICY_TIMESHARE_BASE_COUNT) {
				result = KERN_INVALID_ARGUMENT;
				break;
			}

			limcount = POLICY_TIMESHARE_LIMIT_COUNT;
			ts_base = (policy_timeshare_base_t) base;
			ts_limit.max_priority = ts_base->base_priority;
			limit = (policy_limit_t) &ts_limit;

			break;
		}

		default:
			result = KERN_INVALID_POLICY;
			break;
		}

	}
	else {
		/*
		 *	Use current scheduling limits. Ensure that the
		 *	new base priority will not exceed current limits.
		 */
		switch (policy) {

		case POLICY_RR:
		{
			policy_rr_base_t rr_base;

			if (count != POLICY_RR_BASE_COUNT) {
				result = KERN_INVALID_ARGUMENT;
				break;
			}

			limcount = POLICY_RR_LIMIT_COUNT;
			rr_base = (policy_rr_base_t) base;
			if (rr_base->base_priority > thread->max_priority) {
				result = KERN_POLICY_LIMIT;
				break;
			}

			rr_limit.max_priority = thread->max_priority;
			limit = (policy_limit_t) &rr_limit;

			break;
		}

		case POLICY_FIFO:
		{
			policy_fifo_base_t fifo_base;

			if (count != POLICY_FIFO_BASE_COUNT) {
				result = KERN_INVALID_ARGUMENT;
				break;
			}

			limcount = POLICY_FIFO_LIMIT_COUNT;
			fifo_base = (policy_fifo_base_t) base;
			if (fifo_base->base_priority > thread->max_priority) {
				result = KERN_POLICY_LIMIT;
				break;
			}

			fifo_limit.max_priority = thread->max_priority;
			limit = (policy_limit_t) &fifo_limit;

			break;
		}

		case POLICY_TIMESHARE:
		{
			policy_timeshare_base_t ts_base;

			if (count != POLICY_TIMESHARE_BASE_COUNT) {
				result = KERN_INVALID_ARGUMENT;
				break;
			}

			limcount = POLICY_TIMESHARE_LIMIT_COUNT;
			ts_base = (policy_timeshare_base_t) base;
			if (ts_base->base_priority > thread->max_priority) {
				result = KERN_POLICY_LIMIT;
				break;
			}

			ts_limit.max_priority = thread->max_priority;
			limit = (policy_limit_t) &ts_limit;

			break;
		}

		default:
			result = KERN_INVALID_POLICY;
			break;
		}

	}

	act_unlock_thread(thr_act);

	if (result == KERN_SUCCESS)
	    result = thread_set_policy(thr_act, pset,
					 policy, base, count, limit, limcount);

	return(result);
}

/*
 *	Define shifts for simulating (5/8)**n
 */

shift_data_t	wait_shift[32] = {
	{1,1},{1,3},{1,-3},{2,-7},{3,5},{3,-5},{4,-8},{5,7},
	{5,-7},{6,-10},{7,10},{7,-9},{8,-11},{9,12},{9,-11},{10,-13},
	{11,14},{11,-13},{12,-15},{13,17},{13,-15},{14,-17},{15,19},{16,18},
	{16,-19},{17,22},{18,20},{18,-20},{19,26},{20,22},{20,-22},{21,-27}};

/*
 *	do_priority_computation:
 *
 *	Calculate new priority for thread based on its base priority plus
 *	accumulated usage.  PRI_SHIFT and PRI_SHIFT_2 convert from
 *	usage to priorities.  SCHED_SHIFT converts for the scaling
 *	of the sched_usage field by SCHED_SCALE.  This scaling comes
 *	from the multiplication by sched_load (thread_timer_delta)
 *	in sched.h.  sched_load is calculated as a scaled overload
 *	factor in compute_mach_factor (mach_factor.c).
 */
#ifdef	PRI_SHIFT_2
#if	PRI_SHIFT_2 > 0
#define do_priority_computation(thread, pri)						\
	MACRO_BEGIN														\
	(pri) = (thread)->priority		/* start with base priority */	\
	    - ((thread)->sched_usage >> (PRI_SHIFT + SCHED_SHIFT))		\
	    - ((thread)->sched_usage >> (PRI_SHIFT_2 + SCHED_SHIFT));	\
	if ((pri) < MINPRI_STANDARD)									\
		(pri) = MINPRI_STANDARD;									\
	else															\
	if ((pri) > MAXPRI_STANDARD)									\
		(pri) = MAXPRI_STANDARD;									\
	MACRO_END
#else	/* PRI_SHIFT_2 */
#define do_priority_computation(thread, pri)						\
	MACRO_BEGIN														\
	(pri) = (thread)->priority		/* start with base priority */	\
	    - ((thread)->sched_usage >> (PRI_SHIFT + SCHED_SHIFT))		\
	    + ((thread)->sched_usage >> (SCHED_SHIFT - PRI_SHIFT_2));	\
	if ((pri) < MINPRI_STANDARD)									\
		(pri) = MINPRI_STANDARD;									\
	else															\
	if ((pri) > MAXPRI_STANDARD)									\
		(pri) = MAXPRI_STANDARD;									\
	MACRO_END
#endif	/* PRI_SHIFT_2 */
#else	/* defined(PRI_SHIFT_2) */
#define do_priority_computation(thread, pri)						\
	MACRO_BEGIN														\
	(pri) = (thread)->priority		/* start with base priority */	\
	    - ((thread)->sched_usage >> (PRI_SHIFT + SCHED_SHIFT));		\
	if ((pri) < MINPRI_STANDARD)									\
		(pri) = MINPRI_STANDARD;									\
	else															\
	if ((pri) > MAXPRI_STANDARD)									\
		(pri) = MAXPRI_STANDARD;									\
	MACRO_END
#endif	/* defined(PRI_SHIFT_2) */

void
set_priority(
	register thread_t	thread,
	register int		priority)
{
	thread->priority = priority;
	compute_priority(thread, FALSE);
}

/*
 *	compute_priority:
 *
 *	Reset the current scheduled priority of the
 *	thread according to its base priority if the
 *	thread has not been promoted or depressed.
 *
 *	If the thread is timesharing, adjust according
 *	to recent cpu usage.
 *
 *	The thread *must* be locked by the caller.
 */
void
compute_priority(
	register thread_t	thread,
	boolean_t			override_depress)
{
	register int		priority;

	if (	!(thread->sched_mode & TH_MODE_PROMOTED)			&&
			(!(thread->sched_mode & TH_MODE_ISDEPRESSED)	||
				 override_depress							)		) {
		if (thread->sched_mode & TH_MODE_TIMESHARE)
			do_priority_computation(thread, priority);
		else
			priority = thread->priority;

		set_sched_pri(thread, priority);
	}
}

/*
 *	compute_my_priority:
 *
 *	Version of compute priority for current thread.
 *	Caller must	have thread	locked and thread must
 *	be timesharing and not depressed.
 *
 *	Only used for priority updates.
 */
void
compute_my_priority(
	register thread_t	thread)
{
	register int		priority;

	do_priority_computation(thread, priority);
	assert(thread->runq == RUN_QUEUE_NULL);
	thread->sched_pri = priority;
}

/*
 *	update_priority
 *
 *	Cause the priority computation of a thread that has been 
 *	sleeping or suspended to "catch up" with the system.  Thread
 *	*MUST* be locked by caller.  If thread is running, then this
 *	can only be called by the thread on itself.
 */
void
update_priority(
	register thread_t		thread)
{
	register unsigned int	ticks;
	register shift_t		shiftp;

	ticks = sched_tick - thread->sched_stamp;
	assert(ticks != 0);

	/*
	 *	If asleep for more than 30 seconds forget all
	 *	cpu_usage, else catch up on missed aging.
	 *	5/8 ** n is approximated by the two shifts
	 *	in the wait_shift array.
	 */
	thread->sched_stamp += ticks;
	thread_timer_delta(thread);
	if (ticks >  30) {
		thread->cpu_usage = 0;
		thread->sched_usage = 0;
	}
	else {
		thread->cpu_usage += thread->cpu_delta;
		thread->sched_usage += thread->sched_delta;

		shiftp = &wait_shift[ticks];
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

	thread->cpu_delta = 0;
	thread->sched_delta = 0;

	/*
	 *	Check for fail-safe release.
	 */
	if (	(thread->sched_mode & TH_MODE_FAILSAFE)		&&
			thread->sched_stamp >= thread->safe_release		) {
		if (!(thread->safe_mode & TH_MODE_TIMESHARE)) {
			if (thread->safe_mode & TH_MODE_REALTIME) {
				thread->priority = BASEPRI_RTQUEUES;

				thread->sched_mode |= TH_MODE_REALTIME;
			}

			thread->sched_mode &= ~TH_MODE_TIMESHARE;

			if (thread->state & TH_RUN)
				pset_share_decr(thread->processor_set);

			if (!(thread->sched_mode & TH_MODE_ISDEPRESSED))
				set_sched_pri(thread, thread->priority);
		}

		thread->safe_mode = 0;
		thread->sched_mode &= ~TH_MODE_FAILSAFE;
	}

	/*
	 *	Recompute scheduled priority if appropriate.
	 */
	if (	(thread->sched_mode & TH_MODE_TIMESHARE)	&&
			!(thread->sched_mode & TH_MODE_PROMOTED)	&&
			!(thread->sched_mode & TH_MODE_ISDEPRESSED)		) {
		register int		new_pri;

		do_priority_computation(thread, new_pri);
		if (new_pri != thread->sched_pri) {
			run_queue_t		runq;

			runq = run_queue_remove(thread);
			thread->sched_pri = new_pri;
			if (runq != RUN_QUEUE_NULL)
				thread_setrun(thread, SCHED_TAILQ);
		}
	}
}

/*
 *	thread_switch_continue:
 *
 *	Continuation routine for a thread switch.
 *
 *	Just need to arrange the return value gets sent out correctly and that
 *  we cancel the timer or the depression called for by the options to the
 *  thread_switch call.
 */
void
_mk_sp_thread_switch_continue(void)
{
	register thread_t	self = current_thread();
	int					wait_result = self->wait_result;
	int					option = self->saved.swtch.option;

	if (option == SWITCH_OPTION_WAIT && wait_result != THREAD_TIMED_OUT)
		thread_cancel_timer();
	else
	if (option == SWITCH_OPTION_DEPRESS)
		_mk_sp_thread_depress_abort(self, FALSE);

	thread_syscall_return(KERN_SUCCESS);
	/*NOTREACHED*/
}

/*
 *	thread_switch:
 *
 *	Context switch.  User may supply thread hint.
 *
 *	Fixed priority threads that call this get what they asked for
 *	even if that violates priority order.
 */
kern_return_t
_mk_sp_thread_switch(
	thread_act_t			hint_act,
	int						option,
	mach_msg_timeout_t		option_time)
{
    register thread_t		self = current_thread();
	int						s;

    /*
     *	Check and use thr_act hint if appropriate.  It is not
     *  appropriate to give a hint that shares the current shuttle.
     */
	if (hint_act != THR_ACT_NULL) {
		register thread_t		thread = act_lock_thread(hint_act);

		if (		thread != THREAD_NULL			&&
					thread != self					&&
					thread->top_act == hint_act				) {
			processor_t		processor;

			s = splsched();
			thread_lock(thread);

			/*
			 *	Check if the thread is in the right pset,
			 *	is not bound to a different processor,
			 *	and that realtime is not involved.
			 *
			 *	Next, pull it off its run queue.  If it
			 *	doesn't come, it's not eligible.
			 */
			processor = current_processor();
			if (processor->current_pri < BASEPRI_RTQUEUES			&&
				thread->sched_pri < BASEPRI_RTQUEUES				&&
				thread->processor_set == processor->processor_set	&&
				(thread->bound_processor == PROCESSOR_NULL	||
				 thread->bound_processor == processor)				&&
					run_queue_remove(thread) != RUN_QUEUE_NULL			) {
				/*
				 *	Hah, got it!!
				 */
				thread_unlock(thread);

				act_unlock_thread(hint_act);
				act_deallocate(hint_act);

				if (option == SWITCH_OPTION_WAIT)
					assert_wait_timeout(option_time, THREAD_ABORTSAFE);
				else
				if (option == SWITCH_OPTION_DEPRESS)
					_mk_sp_thread_depress_ms(option_time);

				self->saved.swtch.option = option;

				thread_run(self, _mk_sp_thread_switch_continue, thread);
				/* NOTREACHED */
			}

			thread_unlock(thread);
			splx(s);
		}

		act_unlock_thread(hint_act);
		act_deallocate(hint_act);
    }

    /*
     *	No handoff hint supplied, or hint was wrong.  Call thread_block() in
     *	hopes of running something else.  If nothing else is runnable,
     *	thread_block will detect this.  WARNING: thread_switch with no
     *	option will not do anything useful if the thread calling it is the
     *	highest priority thread (can easily happen with a collection
     *	of timesharing threads).
     */
	if (option == SWITCH_OPTION_WAIT)
		assert_wait_timeout(option_time, THREAD_ABORTSAFE);
	else
	if (option == SWITCH_OPTION_DEPRESS)
		_mk_sp_thread_depress_ms(option_time);
	  
	self->saved.swtch.option = option;

	thread_block_reason(_mk_sp_thread_switch_continue, AST_YIELD);

	if (option == SWITCH_OPTION_WAIT)
		thread_cancel_timer();
	else
	if (option == SWITCH_OPTION_DEPRESS)
		_mk_sp_thread_depress_abort(self, FALSE);

    return (KERN_SUCCESS);
}

/*
 * Depress thread's priority to lowest possible for the specified interval,
 * with a value of zero resulting in no timeout being scheduled.
 */
void
_mk_sp_thread_depress_abstime(
	uint64_t				interval)
{
	register thread_t		self = current_thread();
	uint64_t				deadline;
    spl_t					s;

    s = splsched();
    thread_lock(self);
	if (!(self->sched_mode & TH_MODE_ISDEPRESSED)) {
		processor_t		myprocessor = self->last_processor;

		self->sched_pri = DEPRESSPRI;
		myprocessor->current_pri = self->sched_pri;
		self->sched_mode &= ~TH_MODE_PREEMPT;
		self->sched_mode |= TH_MODE_DEPRESS;

		if (interval != 0) {
			clock_absolutetime_interval_to_deadline(interval, &deadline);
			if (!timer_call_enter(&self->depress_timer, deadline))
				self->depress_timer_active++;
		}
	}
	thread_unlock(self);
    splx(s);
}

void
_mk_sp_thread_depress_ms(
	mach_msg_timeout_t		interval)
{
	uint64_t		abstime;

	clock_interval_to_absolutetime_interval(
							interval, 1000*NSEC_PER_USEC, &abstime);
	_mk_sp_thread_depress_abstime(abstime);
}

/*
 *	Priority depression expiration.
 */
void
thread_depress_expire(
	timer_call_param_t		p0,
	timer_call_param_t		p1)
{
	thread_t		thread = p0;
    spl_t			s;

    s = splsched();
    thread_lock(thread);
	if (--thread->depress_timer_active == 1) {
		thread->sched_mode &= ~TH_MODE_ISDEPRESSED;
		compute_priority(thread, FALSE);
	}
    thread_unlock(thread);
    splx(s);
}

/*
 *	Prematurely abort priority depression if there is one.
 */
kern_return_t
_mk_sp_thread_depress_abort(
	register thread_t		thread,
	boolean_t				abortall)
{
    kern_return_t 			result = KERN_NOT_DEPRESSED;
    spl_t					s;

    s = splsched();
    thread_lock(thread);
	if (abortall || !(thread->sched_mode & TH_MODE_POLLDEPRESS)) {
		if (thread->sched_mode & TH_MODE_ISDEPRESSED) {
			thread->sched_mode &= ~TH_MODE_ISDEPRESSED;
			compute_priority(thread, FALSE);
			result = KERN_SUCCESS;
		}

		if (timer_call_cancel(&thread->depress_timer))
			thread->depress_timer_active--;
	}
	thread_unlock(thread);
    splx(s);

    return (result);
}

void
_mk_sp_thread_perhaps_yield(
	thread_t			self)
{
	spl_t			s;

	assert(self == current_thread());

	s = splsched();
	if (!(self->sched_mode & (TH_MODE_REALTIME|TH_MODE_TIMESHARE))) {
		extern uint64_t		max_poll_computation;
		extern int			sched_poll_yield_shift;
		uint64_t			total_computation, abstime;

		abstime = mach_absolute_time();
		total_computation = abstime - self->computation_epoch;
		total_computation += self->computation_metered;
		if (total_computation >= max_poll_computation) {
			processor_t		myprocessor = current_processor();
			ast_t			preempt;

			thread_lock(self);
			if (!(self->sched_mode & TH_MODE_ISDEPRESSED)) {
				self->sched_pri = DEPRESSPRI;
				myprocessor->current_pri = self->sched_pri;
				self->sched_mode &= ~TH_MODE_PREEMPT;
			}
			self->computation_epoch = abstime;
			self->computation_metered = 0;
			self->sched_mode |= TH_MODE_POLLDEPRESS;

			abstime += (total_computation >> sched_poll_yield_shift);
			if (!timer_call_enter(&self->depress_timer, abstime))
				self->depress_timer_active++;
			thread_unlock(self);

			if ((preempt = csw_check(self, myprocessor)) != AST_NONE)
				ast_on(preempt);
		}
	}
	splx(s);
}

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

#include <kern/sf.h>
#include <kern/mk_sp.h>
#include <kern/misc_protos.h>
#include <kern/spl.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/assert.h>
#include <kern/thread.h>
#include <mach/mach_host_server.h>

/* Forwards */
void	_mk_sp_thread_depress_priority(
			sf_object_t			policy,
			mach_msg_timeout_t	depress_time);

/***
 *** ??? The next two files supply the prototypes for `thread_set_policy()'
 *** and `thread_policy.'  These routines cannot stay here if they are
 *** exported Mach system calls.
 ***/
#include <mach/thread_act_server.h>
#include <mach/host_priv_server.h>

/*
 * Vector containing standard scheduling policy operations
 */
sp_ops_t	mk_sp_ops = {
		    _mk_sp_thread_update_mpri,
		    _mk_sp_thread_unblock,
		    _mk_sp_thread_done,
		    _mk_sp_thread_begin,
		    _mk_sp_thread_dispatch,
		    _mk_sp_thread_attach,
		    _mk_sp_thread_detach,
		    _mk_sp_thread_processor,
		    _mk_sp_thread_processor_set,
		    _mk_sp_thread_setup,
		    _mk_sp_swtch_pri,
		    _mk_sp_thread_switch,
		    _mk_sp_thread_depress_abort,
		    _mk_sp_thread_depress_timeout,
		    _mk_sp_thread_runnable,
};

/* Forwards */
kern_return_t	thread_policy_common(
					thread_t		thread,
					int				policy,
					int				data,
					processor_set_t	pset);

/*
 * Standard operations for MK Scheduling Policy
 */

sf_return_t
_mk_sp_thread_update_mpri(
	sf_object_t			policy,
	thread_t			thread)
{
	if (thread->sched_stamp != sched_tick)
		update_priority(thread);

	return(SF_SUCCESS);
}

sf_return_t
_mk_sp_thread_unblock(
	sf_object_t			policy,
	thread_t			thread)
{
	/* indicate thread is now runnable */
	thread->sp_state = MK_SP_RUNNABLE;

	/* place thread at end of appropriate run queue */
	if (!(thread->state&TH_IDLE))
		thread_setrun(thread, TRUE, TAIL_Q);

	return(SF_SUCCESS);
}

sf_return_t
_mk_sp_thread_done(
	sf_object_t			policy,
	thread_t			old_thread)
{
	processor_t			myprocessor = cpu_to_processor(cpu_number());

	/*
	 * A running thread is being taken off a processor:
	 *
	 *   - update the thread's `unconsumed_quantum' field
	 *   - update the thread's state field
	 */

	old_thread->unconsumed_quantum = myprocessor->quantum;

	if (old_thread->state & TH_WAIT)
		old_thread->sp_state = MK_SP_BLOCKED;

	return(SF_SUCCESS);
}

sf_return_t
_mk_sp_thread_begin(
	sf_object_t			policy,
	thread_t			thread)
{

	processor_t			myprocessor = cpu_to_processor(cpu_number());
	processor_set_t		pset;

	pset = myprocessor->processor_set;
	/*
	 * The designated thread is about to begin execution:
	 *
	 *   - update the processor's `quantum' field
	 */
	/* check for legal thread state */
	assert(thread->sp_state == MK_SP_RUNNABLE);

	if (thread->policy & (POLICY_RR|POLICY_FIFO))
		myprocessor->quantum = thread->unconsumed_quantum;
	else
		myprocessor->quantum = (thread->bound_processor ?
										min_quantum : pset->set_quantum);

	return(SF_SUCCESS);
}

sf_return_t
_mk_sp_thread_dispatch(
	sf_object_t			policy,
	thread_t			old_thread)
{
	if (old_thread->sp_state & MK_SP_RUNNABLE) {
		if (old_thread->reason & AST_QUANTUM) {
			thread_setrun(old_thread, FALSE, TAIL_Q);
			old_thread->unconsumed_quantum = min_quantum;
		}
		else
			thread_setrun(old_thread, FALSE, HEAD_Q);
	}

	if (old_thread->sp_state & MK_SP_ATTACHED) {
		/* indicate thread is now runnable */
		old_thread->sp_state = MK_SP_RUNNABLE;

		/* place thread at end of appropriate run queue */
		thread_setrun(old_thread, FALSE, TAIL_Q);
	}

	return(SF_SUCCESS);
}

/*
 * Thread must already be locked.
 */
sf_return_t
_mk_sp_thread_attach(
	sf_object_t			policy,
	thread_t			thread)
{
	thread->sp_state = MK_SP_ATTACHED;

	thread->max_priority = thread->priority = BASEPRI_DEFAULT;
	thread->depress_priority = -1;

	thread->cpu_usage = 0;
	thread->sched_usage = 0;
	thread->sched_stamp = 0;

	thread->unconsumed_quantum = min_quantum;

	/* Reflect this policy in thread data structure */
	thread->policy = policy->policy_id;

	return(SF_SUCCESS);
}

/*
 * Check to make sure that thread is removed from run
 * queues and active execution; and clear pending
 * priority depression.
 *
 * Thread must already be locked.
 */
sf_return_t
_mk_sp_thread_detach(
	sf_object_t			policy,
	thread_t			thread)
{
	struct run_queue	*rq;

	assert(thread->policy == policy->policy_id);

	/* make sure that the thread is no longer on any run queue */
	if (thread->runq != RUN_QUEUE_NULL) {
		rq = rem_runq(thread);
		if (rq == RUN_QUEUE_NULL) {
			panic("mk_sp_thread_detach: missed thread");
		}
	}

	/* clear pending priority depression */

	if (thread->depress_priority >= 0) {
		thread->priority = thread->depress_priority;
		thread->depress_priority = -1;
		if (thread_call_cancel(&thread->depress_timer))
			thread_call_enter(&thread->depress_timer);
	}

	/* clear the thread's policy field */
	thread->policy = POLICY_NULL;

	return(SF_SUCCESS);
}

sf_return_t
_mk_sp_thread_processor(
	sf_object_t			policy,
	thread_t			*thread,
	processor_t			processor)
{
	return(SF_FAILURE);
}

sf_return_t
_mk_sp_thread_processor_set(
	sf_object_t			policy,
	thread_t			thread,
	processor_set_t		processor_set)
{
	pset_add_thread(processor_set, thread);

	return(SF_SUCCESS);
}

sf_return_t
_mk_sp_thread_setup(
	sf_object_t			policy,
	thread_t			thread)
{
	/*
	 * Determine thread's state.  (It may be an "older" thread
	 * that has just been associated with this policy.)
	 */
	if (thread->state & TH_WAIT)
	    thread->sp_state = MK_SP_BLOCKED;

	/* recompute priority */
	thread->sched_stamp = sched_tick;
	compute_priority(thread, TRUE);

	return(SF_SUCCESS);
}

/*
 *	thread_priority_internal:
 *
 *	Kernel-internal work function for thread_priority().  Called
 *	with thread "properly locked" to ensure synchrony with RPC
 *	(see act_lock_thread()).
 */
kern_return_t
thread_priority_internal(
	thread_t		thread,
	int				priority)
{
	kern_return_t	result = KERN_SUCCESS;
	spl_t			s;

	s = splsched();
	thread_lock(thread);

	/*
	 *	Check for violation of max priority
	 */
	if (priority > thread->max_priority)
		priority = thread->max_priority;

	/*
	 *	Set priorities.  If a depression is in progress,
	 *	change the priority to restore.
	 */
	if (thread->depress_priority >= 0)
		thread->depress_priority = priority;
	else {
		thread->priority = priority;
		compute_priority(thread, TRUE);

		/*
		 * If the current thread has changed its
		 * priority let the ast code decide whether
		 * a different thread should run.
		 */
		if (thread == current_thread())
			ast_on(AST_BLOCK);
	}

	thread_unlock(thread);
	splx(s);

	return (result);
}

/*
 *	thread_policy_common:
 *
 *	Set scheduling policy for thread. If pset == PROCESSOR_SET_NULL,
 * 	policy will be checked to make sure it is enabled.
 */
kern_return_t
thread_policy_common(
	thread_t		thread,
	integer_t		policy,
	integer_t		data,
	processor_set_t	pset)
{
	kern_return_t	result = KERN_SUCCESS;
	register int	temp;
	spl_t			s;

	if (	thread == THREAD_NULL		||
			invalid_policy(policy)		)
		return(KERN_INVALID_ARGUMENT);

	s = splsched();
	thread_lock(thread);

	/*
	 *	Check if changing policy.
	 */
	if (policy != thread->policy) {
	    /*
	     *	Changing policy.  Check if new policy is allowed.
	     */
	    if (	pset == PROCESSOR_SET_NULL							&&
				(thread->processor_set->policies & policy) == 0			)
			result = KERN_FAILURE;
	    else {
			if (pset != thread->processor_set)
				result = KERN_FAILURE;
			else {
				/*
				 *	Changing policy.  Calculate new
				 *	priority.
				 */
				thread->policy = policy;
				compute_priority(thread, TRUE);
			}
	    }
	}

	thread_unlock(thread);
	splx(s);

	return (result);
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
	int 					max, bas, dat, incr;
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

		dat = rr_base->quantum;
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

		dat = 0;
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

		dat = 0;
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

	result = thread_priority_internal(thread, bas);
	if (result == KERN_SUCCESS)
		result = thread_policy_common(thread, policy, dat, pset);
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

	if (	invalid_policy(policy)			||
			(pset->policies & policy) == 0		) {
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

/*
 *	compute_priority:
 *
 *	Compute the effective priority of the specified thread.
 *	The effective priority computation is as follows:
 *
 *	Take the base priority for this thread and add
 *	to it an increment derived from its cpu_usage.
 *
 *	The thread *must* be locked by the caller. 
 */

void
compute_priority(
	register thread_t	thread,
	boolean_t			resched)
{
	register int		pri;

	if (thread->policy == POLICY_TIMESHARE) {
	    do_priority_computation(thread, pri);
	    if (thread->depress_priority < 0)
			set_pri(thread, pri, resched);
	    else
			thread->depress_priority = pri;
	}
	else
	    set_pri(thread, thread->priority, resched);
}

/*
 *	compute_my_priority:
 *
 *	Version of compute priority for current thread or thread
 *	being manipulated by scheduler (going on or off a runq).
 *	Only used for priority updates.  Policy or priority changes
 *	must call compute_priority above.  Caller must have thread
 *	locked and know it is timesharing and not depressed.
 */

void
compute_my_priority(
	register thread_t	thread)
{
	register int		pri;

	do_priority_computation(thread, pri);
	assert(thread->runq == RUN_QUEUE_NULL);
	thread->sched_pri = pri;
}

#if		DEBUG
struct mk_sp_usage {
	natural_t	cpu_delta, sched_delta;
	natural_t	sched_tick, ticks;
	natural_t	cpu_usage, sched_usage,
				aged_cpu, aged_sched;
	thread_t	thread;
} idled_info, loaded_info;
#endif

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
#if		DEBUG
		struct mk_sp_usage *sp_usage;
#endif

		thread->cpu_usage += thread->cpu_delta;
		thread->sched_usage += thread->sched_delta;

#if		DEBUG
		if (thread->state & TH_IDLE)
			sp_usage = &idled_info;
		else
		if (thread == loaded_info.thread)
			sp_usage = &loaded_info;
		else
			sp_usage = NULL;

		if (sp_usage != NULL) {
			sp_usage->cpu_delta = thread->cpu_delta;
			sp_usage->sched_delta = thread->sched_delta;
			sp_usage->sched_tick = thread->sched_stamp;
			sp_usage->ticks = ticks;
			sp_usage->cpu_usage = thread->cpu_usage;
			sp_usage->sched_usage = thread->sched_usage;
			sp_usage->thread = thread;
		}
#endif

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

#if		DEBUG
		if (sp_usage != NULL) {
			sp_usage->aged_cpu = thread->cpu_usage;
			sp_usage->aged_sched = thread->sched_usage;
		}
#endif
	}
	thread->cpu_delta = 0;
	thread->sched_delta = 0;

	/*
	 *	Recompute priority if appropriate.
	 */
	if (	thread->policy == POLICY_TIMESHARE		&&
			thread->depress_priority < 0			) {
		register int		new_pri;
		run_queue_t			runq;

		do_priority_computation(thread, new_pri);
		if (new_pri != thread->sched_pri) {
			runq = rem_runq(thread);
			thread->sched_pri = new_pri;
			if (runq != RUN_QUEUE_NULL)
				thread_setrun(thread, TRUE, TAIL_Q);
		}
	}
}

/*
 *	`mk_sp_swtch_pri()' attempts to context switch (logic in
 *	thread_block no-ops the context switch if nothing would happen).
 *	A boolean is returned that indicates whether there is anything
 *	else runnable.
 *
 *	This boolean can be used by a thread waiting on a
 *	lock or condition:  If FALSE is returned, the thread is justified
 *	in becoming a resource hog by continuing to spin because there's
 *	nothing else useful that the processor could do.  If TRUE is
 *	returned, the thread should make one more check on the
 *	lock and then be a good citizen and really suspend.
 */

void
_mk_sp_swtch_pri(
	sf_object_t			policy,
	int					pri)
{
	register thread_t	self = current_thread();
	extern natural_t	min_quantum_ms;

#ifdef	lint
	pri++;
#endif	/* lint */

	/*
	 *	XXX need to think about depression duration.
	 *	XXX currently using min quantum.
	 */
	_mk_sp_thread_depress_priority(policy, min_quantum_ms);

	thread_block((void (*)(void)) 0);

	_mk_sp_thread_depress_abort(policy, self);
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
	thread_t self = current_thread();
	int wait_result = self->wait_result;
	int option = self->saved.swtch.option;
	sf_object_t policy = self->saved.swtch.policy;

	if (option == SWITCH_OPTION_WAIT && wait_result != THREAD_TIMED_OUT)
		thread_cancel_timer();
	else if (option == SWITCH_OPTION_DEPRESS)
		_mk_sp_thread_depress_abort(policy, self);
	thread_syscall_return(KERN_SUCCESS);
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
	sf_object_t				policy,
	thread_act_t			hint_act,
	int						option,
	mach_msg_timeout_t		option_time)
{
    register thread_t		self = current_thread();
    register processor_t	myprocessor;
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
			s = splsched();
			thread_lock(thread);

			/*
			 *	Check if the thread is in the right pset. Then
			 *	pull it off its run queue.  If it
			 *	doesn't come, then it's not eligible.
			 */
			if (	thread->processor_set == self->processor_set	&&
					rem_runq(thread) != RUN_QUEUE_NULL					) {
				/*
				 *	Hah, got it!!
				 */
				if (thread->policy & (POLICY_FIFO|POLICY_RR)) {
					myprocessor = current_processor();

					myprocessor->quantum = thread->unconsumed_quantum;
					myprocessor->first_quantum = TRUE;
				}
				thread_unlock(thread);

				act_unlock_thread(hint_act);
				act_deallocate(hint_act);

				if (option == SWITCH_OPTION_WAIT)
					assert_wait_timeout(option_time, THREAD_ABORTSAFE);
				else if (option == SWITCH_OPTION_DEPRESS)
					_mk_sp_thread_depress_priority(policy, option_time);

				self->saved.swtch.policy = policy;
				self->saved.swtch.option = option;

				thread_run(self, _mk_sp_thread_switch_continue, thread);
				splx(s);

				goto out;
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
	mp_disable_preemption();
    myprocessor = current_processor();
    if (	option != SWITCH_OPTION_NONE					||
			myprocessor->processor_set->runq.count > 0		||
			myprocessor->runq.count > 0							) {
		myprocessor->first_quantum = FALSE;
		mp_enable_preemption();

		if (option == SWITCH_OPTION_WAIT)
			assert_wait_timeout(option_time, THREAD_ABORTSAFE);
		else if (option == SWITCH_OPTION_DEPRESS)
			_mk_sp_thread_depress_priority(policy, option_time);
	  
		self->saved.swtch.policy = policy;
		self->saved.swtch.option = option;

		thread_block(_mk_sp_thread_switch_continue);
	}
	else
		mp_enable_preemption();

out:
	if (option == SWITCH_OPTION_WAIT)
		thread_cancel_timer();
	else if (option == SWITCH_OPTION_DEPRESS)
		_mk_sp_thread_depress_abort(policy, self);

    return (KERN_SUCCESS);
}

/*
 *	mk_sp_thread_depress_priority
 *
 *	Depress thread's priority to lowest possible for specified period.
 *	Intended for use when thread wants a lock but doesn't know which
 *	other thread is holding it.  As with thread_switch, fixed
 *	priority threads get exactly what they asked for.  Users access
 *	this by the SWITCH_OPTION_DEPRESS option to thread_switch.  A Time
 *      of zero will result in no timeout being scheduled.
 */
void
_mk_sp_thread_depress_priority(
	sf_object_t				policy,
	mach_msg_timeout_t		interval)
{
	register thread_t		self = current_thread();
	AbsoluteTime			deadline;
	boolean_t				release = FALSE;
    spl_t					s;

    s = splsched();
    thread_lock(self);

	if (self->policy == policy->policy_id) {
		/*
		 * If we haven't already saved the priority to be restored
		 * (depress_priority), then save it.
		 */
		if (self->depress_priority < 0)
			self->depress_priority = self->priority;
		else if (thread_call_cancel(&self->depress_timer))
			release = TRUE;

		self->sched_pri = self->priority = DEPRESSPRI;

		if (interval != 0) {
			clock_interval_to_deadline(
								interval, 1000*NSEC_PER_USEC, &deadline);
			thread_call_enter_delayed(&self->depress_timer, deadline);
			if (!release)
				self->ref_count++;
			else
				release = FALSE;
		}
	}

    thread_unlock(self);
    splx(s);

	if (release)
		thread_deallocate(self);
}	

/*
 *	mk_sp_thread_depress_timeout:
 *
 *	Timeout routine for priority depression.
 */
void
_mk_sp_thread_depress_timeout(
	sf_object_t				policy,
	register thread_t		thread)
{
    spl_t					s;

    s = splsched();
    thread_lock(thread);
	if (thread->policy == policy->policy_id) {
		/*
		 *	If we lose a race with mk_sp_thread_depress_abort,
		 *	then depress_priority might be -1.
		 */
		if (	thread->depress_priority >= 0							&&
				!thread_call_is_delayed(&thread->depress_timer, NULL)		) {
			thread->priority = thread->depress_priority;
			thread->depress_priority = -1;
			compute_priority(thread, FALSE);
		}
		else
		if (thread->depress_priority == -2) {
			/*
			 * Thread was temporarily undepressed by thread_suspend, to
			 * be redepressed in special_handler as it blocks.  We need to
			 * prevent special_handler from redepressing it, since depression
			 * has timed out:
			 */
			thread->depress_priority = -1;
		}
	}
	thread_unlock(thread);
	splx(s);
}

/*
 *	mk_sp_thread_depress_abort:
 *
 *	Prematurely abort priority depression if there is one.
 */
kern_return_t
_mk_sp_thread_depress_abort(
	sf_object_t				policy,
	register thread_t		thread)
{
    kern_return_t 			result = KERN_SUCCESS;
	boolean_t				release = FALSE;
    spl_t					s;

    s = splsched();
    thread_lock(thread);

	if (thread->policy == policy->policy_id) {
		if (thread->depress_priority >= 0) {
			if (thread_call_cancel(&thread->depress_timer))
				release = TRUE;
			thread->priority = thread->depress_priority;
			thread->depress_priority = -1;
			compute_priority(thread, FALSE);
		}
		else
			result = KERN_NOT_DEPRESSED;
	}

    thread_unlock(thread);
    splx(s);

	if (release)
		thread_deallocate(thread);

    return (result);
}

/*
 *	mk_sp_thread_runnable:
 *
 *	Return TRUE iff policy believes thread is runnable
 */
boolean_t
_mk_sp_thread_runnable(
	sf_object_t			policy,
	thread_t			thread)
{
	return (thread->sp_state == MK_SP_RUNNABLE);
}

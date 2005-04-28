/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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

/* The routines in this module are all obsolete */

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
#include <mach/policy.h>

#include <kern/syscall_subr.h>
#include <mach/mach_host_server.h>
#include <mach/mach_syscalls.h>

#include <kern/misc_protos.h>
#include <kern/spl.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/assert.h>
#include <kern/thread.h>
#include <mach/mach_host_server.h>
#include <mach/thread_act_server.h>
#include <mach/host_priv_server.h>

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
		if (priority >= MINPRI_RESERVED)
			priority -= MINPRI_RESERVED;
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
	thread_t				thread,
	processor_set_t			pset,
	policy_t				policy,
	policy_base_t			base,
	mach_msg_type_number_t	base_count,
	policy_limit_t			limit,
	mach_msg_type_number_t	limit_count)
{
	int 					max, bas;
	kern_return_t			result = KERN_SUCCESS;

	if (	thread == THREAD_NULL			||
			pset == PROCESSOR_SET_NULL		)
		return (KERN_INVALID_ARGUMENT);

	thread_mtx_lock(thread);

	if (pset != thread->processor_set) {
		thread_mtx_unlock(thread);

		return (KERN_FAILURE);
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
		thread_mtx_unlock(thread);

		return (result);
	}

	result = thread_policy_common(thread, policy, bas);

	thread_mtx_unlock(thread);

	return (result);
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
	thread_t				thread,
	policy_t				policy,
	policy_base_t			base,
	mach_msg_type_number_t	count,
	boolean_t				set_limit)
{
	kern_return_t			result = KERN_SUCCESS;
	processor_set_t			pset;
	policy_limit_t			limit;
	int						limcount;
	policy_rr_limit_data_t			rr_limit;
	policy_fifo_limit_data_t		fifo_limit;
	policy_timeshare_limit_data_t	ts_limit;
	
	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	thread_mtx_lock(thread);

	pset = thread->processor_set;
	if (pset == PROCESSOR_SET_NULL) {
		thread_mtx_unlock(thread);

		return (KERN_INVALID_ARGUMENT);
	}

	if (	invalid_policy(policy)											||
			((POLICY_TIMESHARE | POLICY_RR | POLICY_FIFO) & policy) == 0	) {
		thread_mtx_unlock(thread);

		return (KERN_INVALID_POLICY);
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

	thread_mtx_unlock(thread);

	if (result == KERN_SUCCESS)
	    result = thread_set_policy(thread, pset,
					 policy, base, count, limit, limcount);

	return(result);
}

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
 * Copyright (c) 2000 Apple Computer, Inc.  All rights reserved.
 *
 * HISTORY
 *
 * 15 October 2000 (debo)
 *  Created.
 */

#include <kern/thread.h>

static void
thread_recompute_priority(
	thread_t		thread);

kern_return_t
thread_policy_set(
	thread_act_t			act,
	thread_policy_flavor_t	flavor,
	thread_policy_t			policy_info,
	mach_msg_type_number_t	count)
{
	kern_return_t			result = KERN_SUCCESS;
	thread_t				thread;
	spl_t					s;

	if (act == THR_ACT_NULL)
		return (KERN_INVALID_ARGUMENT);

	thread = act_lock_thread(act);
	if (!act->active) {
		act_unlock_thread(act);

		return (KERN_TERMINATED);
	}

	assert(thread != THREAD_NULL);

	switch (flavor) {

	case THREAD_EXTENDED_POLICY:
	{
		boolean_t				timeshare = TRUE;

		if (count >= THREAD_EXTENDED_POLICY_COUNT) {
			thread_extended_policy_t	info;

			info = (thread_extended_policy_t)policy_info;
			timeshare = info->timeshare;
		}

		s = splsched();
		thread_lock(thread);

		if (!(thread->sched_mode & TH_MODE_FAILSAFE)) {
			thread->sched_mode &= ~TH_MODE_REALTIME;

			if (timeshare)
				thread->sched_mode |= TH_MODE_TIMESHARE;
			else
				thread->sched_mode &= ~TH_MODE_TIMESHARE;

			thread_recompute_priority(thread);
		}
		else {
			thread->safe_mode &= ~TH_MODE_REALTIME;

			if (timeshare)
				thread->safe_mode |= TH_MODE_TIMESHARE;
			else
				thread->safe_mode &= ~TH_MODE_TIMESHARE;
		}

		thread_unlock(thread);
		splx(s);

		break;
	}

	case THREAD_TIME_CONSTRAINT_POLICY:
	{
		thread_time_constraint_policy_t		info;

		if (count < THREAD_TIME_CONSTRAINT_POLICY_COUNT) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		info = (thread_time_constraint_policy_t)policy_info;
		if (	info->computation > max_rt_quantum	||
				info->computation < min_rt_quantum		) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		s = splsched();
		thread_lock(thread);

		thread->realtime.period = info->period;
		thread->realtime.computation = info->computation;
		thread->realtime.constraint = info->constraint;
		thread->realtime.preemptible = info->preemptible;

		if (!(thread->sched_mode & TH_MODE_FAILSAFE)) {
			thread->sched_mode &= ~TH_MODE_TIMESHARE;
			thread->sched_mode |= TH_MODE_REALTIME;
			thread_recompute_priority(thread);
		}
		else {
			thread->safe_mode &= ~TH_MODE_TIMESHARE;
			thread->safe_mode |= TH_MODE_REALTIME;
		}

		thread_unlock(thread);
		splx(s);

		break;
	}

	case THREAD_PRECEDENCE_POLICY:
	{
		thread_precedence_policy_t		info;

		if (count < THREAD_PRECEDENCE_POLICY_COUNT) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		info = (thread_precedence_policy_t)policy_info;

		s = splsched();
		thread_lock(thread);

		thread->importance = info->importance;

		thread_recompute_priority(thread);

		thread_unlock(thread);
		splx(s);

		break;
	}

	default:
		result = KERN_INVALID_ARGUMENT;
		break;
	}

	act_unlock_thread(act);

	return (result);
}

static void
thread_recompute_priority(
	thread_t		thread)
{
	integer_t		priority;

	if (thread->sched_mode & TH_MODE_REALTIME)
		priority = BASEPRI_REALTIME;
	else {
		if (thread->importance > MAXPRI)
			priority = MAXPRI;
		else
		if (thread->importance < -MAXPRI)
			priority = -MAXPRI;
		else
			priority = thread->importance;

		priority += thread->task_priority;

		if (priority > thread->max_priority)
			priority = thread->max_priority;
		else
		if (priority < MINPRI)
			priority = MINPRI;
	}

	set_priority(thread, priority);
}

void
thread_task_priority(
	thread_t		thread,
	integer_t		priority,
	integer_t		max_priority)
{
	spl_t				s;

	assert(thread != THREAD_NULL);

	s = splsched();
	thread_lock(thread);

	thread->task_priority = priority;
	thread->max_priority = max_priority;

	thread_recompute_priority(thread);

	thread_unlock(thread);
	splx(s);
}

kern_return_t
thread_policy_get(
	thread_act_t			act,
	thread_policy_flavor_t	flavor,
	thread_policy_t			policy_info,
	mach_msg_type_number_t	*count,
	boolean_t				*get_default)
{
	kern_return_t			result = KERN_SUCCESS;
	thread_t				thread;
	spl_t					s;

	if (act == THR_ACT_NULL)
		return (KERN_INVALID_ARGUMENT);

	thread = act_lock_thread(act);
	if (!act->active) {
		act_unlock_thread(act);

		return (KERN_TERMINATED);
	}

	assert(thread != THREAD_NULL);

	switch (flavor) {

	case THREAD_EXTENDED_POLICY:
	{
		boolean_t		timeshare = TRUE;

		if (!(*get_default)) {
			s = splsched();
			thread_lock(thread);

			if (	!(thread->sched_mode & TH_MODE_REALTIME)	&&
					!(thread->safe_mode & TH_MODE_REALTIME)			) {
				if (!(thread->sched_mode & TH_MODE_FAILSAFE))
					timeshare = (thread->sched_mode & TH_MODE_TIMESHARE) != 0;
				else
					timeshare = (thread->safe_mode & TH_MODE_TIMESHARE) != 0;
			}
			else
				*get_default = TRUE;

			thread_unlock(thread);
			splx(s);
		}

		if (*count >= THREAD_EXTENDED_POLICY_COUNT) {
			thread_extended_policy_t	info;

			info = (thread_extended_policy_t)policy_info;
			info->timeshare = timeshare;
		}

		break;
	}

	case THREAD_TIME_CONSTRAINT_POLICY:
	{
		thread_time_constraint_policy_t		info;

		if (*count < THREAD_TIME_CONSTRAINT_POLICY_COUNT) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		info = (thread_time_constraint_policy_t)policy_info;

		if (!(*get_default)) {
			s = splsched();
			thread_lock(thread);

			if (	(thread->sched_mode & TH_MODE_REALTIME)	||
					(thread->safe_mode & TH_MODE_REALTIME)		) {
				info->period = thread->realtime.period;
				info->computation = thread->realtime.computation;
				info->constraint = thread->realtime.constraint;
				info->preemptible = thread->realtime.preemptible;
			}
			else
				*get_default = TRUE;

			thread_unlock(thread);
			splx(s);
		}

		if (*get_default) {
			info->period = 0;
			info->computation = std_quantum / 2;
			info->constraint = std_quantum;
			info->preemptible = TRUE;
		}

		break;
	}

	case THREAD_PRECEDENCE_POLICY:
	{
		thread_precedence_policy_t		info;

		if (*count < THREAD_PRECEDENCE_POLICY_COUNT) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		info = (thread_precedence_policy_t)policy_info;

		if (!(*get_default)) {
			s = splsched();
			thread_lock(thread);

			info->importance = thread->importance;

			thread_unlock(thread);
			splx(s);
		}
		else
			info->importance = 0;

		break;
	}

	default:
		result = KERN_INVALID_ARGUMENT;
		break;
	}

	act_unlock_thread(act);

	return (result);
}

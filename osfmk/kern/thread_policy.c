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

kern_return_t
thread_policy_set(
	thread_act_t			act,
	thread_policy_flavor_t	flavor,
	thread_policy_t			policy_info,
	mach_msg_type_number_t	count)
{
	kern_return_t			result = KERN_SUCCESS;
	thread_t				thread;
	task_t					task;
	spl_t					s;

	if (act == THR_ACT_NULL)
		return (KERN_INVALID_ARGUMENT);

	act_lock(act);
	task = act->task;
	act_unlock(act);

	task_lock(task);

	thread = act_lock_thread(act);
	if (!act->active) {
		act_unlock_thread(act);
		task_unlock(task);

		return (KERN_TERMINATED);
	}

	if (thread == THREAD_NULL) {
		act_unlock_thread(act);
		task_unlock(task);

		return (KERN_NOT_SUPPORTED);
	}

#define	thread_priority_set(thread, pri)					\
MACRO_BEGIN													\
	if ((thread)->depress_priority >= 0)					\
		(thread)->depress_priority = (pri);					\
	else {													\
		(thread)->priority = (pri);							\
		compute_priority((thread), TRUE);					\
															\
		if ((thread) == current_thread())					\
			ast_on(AST_BLOCK);								\
	}														\
MACRO_END

	switch (flavor) {

	case THREAD_STANDARD_POLICY:
	{
		integer_t				priority;

		s = splsched();
		thread_lock(thread);

		thread->sched_mode &=~ TH_MODE_REALTIME;

		thread->policy = POLICY_TIMESHARE;

		if (thread->importance > MAXPRI)
			priority = MAXPRI;
		else
		if (thread->importance < -MAXPRI)
			priority = -MAXPRI;
		else
			priority = thread->importance;

		priority += task->priority;

		if (priority > thread->max_priority)
			priority = thread->max_priority;
		else
		if (priority < MINPRI)
			priority = MINPRI;

		thread_priority_set(thread, priority);

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

		s = splsched();
		thread_lock(thread);

		thread->sched_mode |= TH_MODE_REALTIME;

		thread->realtime.period = info->period;
		thread->realtime.computation = info->computation;
		thread->realtime.constraint = info->constraint;
		thread->realtime.preemptible = info->preemptible;

		thread->policy = POLICY_RR;

		thread_priority_set(thread, BASEPRI_REALTIME);

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

		if (!(thread->sched_mode & TH_MODE_REALTIME)) {
			integer_t					priority;

			if (thread->importance > MAXPRI)
				priority = MAXPRI;
			else
			if (thread->importance < -MAXPRI)
				priority = -MAXPRI;
			else
				priority = thread->importance;

			priority += task->priority;

			if (priority > thread->max_priority)
				priority = thread->max_priority;
			else
			if (priority < MINPRI)
				priority = MINPRI;

			thread_priority_set(thread, priority);
		}

		thread_unlock(thread);
		splx(s);

		break;
	}

	default:
		result = KERN_INVALID_ARGUMENT;
		break;
	}

	act_unlock_thread(act);

	task_unlock(task);

	return (result);
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

	if (thread == THREAD_NULL) {
		act_unlock_thread(act);

		return (KERN_NOT_SUPPORTED);
	}

	switch (flavor) {

	case THREAD_STANDARD_POLICY:
		s = splsched();
		thread_lock(thread);

		if (thread->sched_mode & TH_MODE_REALTIME)
			*get_default = TRUE;

		thread_unlock(thread);
		splx(s);
		break;

	case THREAD_TIME_CONSTRAINT_POLICY:
	{
		thread_time_constraint_policy_t		info;

		if (*count < THREAD_TIME_CONSTRAINT_POLICY_COUNT) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		info = (thread_time_constraint_policy_t)policy_info;

		s = splsched();
		thread_lock(thread);

		if ((thread->sched_mode & TH_MODE_REALTIME) && !(*get_default)) {
			info->period = thread->realtime.period;
			info->computation = thread->realtime.computation;
			info->constraint = thread->realtime.constraint;
			info->preemptible = thread->realtime.preemptible;
		}
		else {
			extern natural_t		min_quantum_abstime;

			*get_default = TRUE;

			info->period = 0;
			info->computation = min_quantum_abstime / 2;
			info->constraint = min_quantum_abstime;
			info->preemptible = TRUE;
		}

		thread_unlock(thread);
		splx(s);

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

		if (*get_default)
			info->importance = 0;
		else {
			s = splsched();
			thread_lock(thread);

			info->importance = thread->importance;

			thread_unlock(thread);
			splx(s);
		}

		break;
	}

	default:
		result = KERN_INVALID_ARGUMENT;
		break;
	}

	act_unlock_thread(act);

	return (result);
}

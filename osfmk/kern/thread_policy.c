/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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

#include <mach/mach_types.h>
#include <mach/thread_act_server.h>

#include <kern/kern_types.h>
#include <kern/processor.h>
#include <kern/thread.h>
#include <kern/affinity.h>

static void
thread_recompute_priority(
	thread_t		thread);

#if CONFIG_EMBEDDED
static void
thread_throttle(
	thread_t		thread,
	integer_t		task_priority);

extern int mach_do_background_thread(thread_t thread, int prio);
#endif


kern_return_t
thread_policy_set(
	thread_t				thread,
	thread_policy_flavor_t	flavor,
	thread_policy_t			policy_info,
	mach_msg_type_number_t	count)
{

	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	if (thread->static_param)
		return (KERN_SUCCESS);

	return (thread_policy_set_internal(thread, flavor, policy_info, count));
}

kern_return_t
thread_policy_set_internal(
	thread_t				thread,
	thread_policy_flavor_t	flavor,
	thread_policy_t			policy_info,
	mach_msg_type_number_t	count)
{
	kern_return_t			result = KERN_SUCCESS;
	spl_t					s;

	thread_mtx_lock(thread);
	if (!thread->active) {
		thread_mtx_unlock(thread);

		return (KERN_TERMINATED);
	}
	switch (flavor) {

	case THREAD_EXTENDED_POLICY:
	{
		boolean_t				timeshare = TRUE;

		if (count >= THREAD_EXTENDED_POLICY_COUNT) {
			thread_extended_policy_t	info;

			info = (thread_extended_policy_t)policy_info;
			timeshare = info->timeshare;
		}

		if (!SCHED(supports_timeshare_mode)())
			timeshare = FALSE;
		
		s = splsched();
		thread_lock(thread);

		if (!(thread->sched_flags & TH_SFLAG_DEMOTED_MASK)) {
			integer_t	oldmode = (thread->sched_mode == TH_MODE_TIMESHARE);

			if (timeshare) {
				thread->sched_mode = TH_MODE_TIMESHARE;

				if (!oldmode) {
					if ((thread->state & (TH_RUN|TH_IDLE)) == TH_RUN)
						sched_share_incr();
				}
			}
			else {
				thread->sched_mode = TH_MODE_FIXED;

				if (oldmode) {
					if ((thread->state & (TH_RUN|TH_IDLE)) == TH_RUN)
						sched_share_decr();
				}
			}

			thread_recompute_priority(thread);
		}
		else {

			if (timeshare)
				thread->saved_mode = TH_MODE_TIMESHARE;
			else
				thread->saved_mode = TH_MODE_FIXED;
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
		if (	info->constraint < info->computation	||
				info->computation > max_rt_quantum		||
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

		if (thread->sched_flags & TH_SFLAG_DEMOTED_MASK) {
			thread->saved_mode = TH_MODE_REALTIME;
		}
#if CONFIG_EMBEDDED
		else if (thread->task_priority <= MAXPRI_THROTTLE) {
			thread->saved_mode = TH_MODE_REALTIME;
			thread->sched_flags |= TH_SFLAG_THROTTLED;		
		}
#endif
		else {
			if (thread->sched_mode == TH_MODE_TIMESHARE) {
				if ((thread->state & (TH_RUN|TH_IDLE)) == TH_RUN)
					sched_share_decr();
			}
			thread->sched_mode = TH_MODE_REALTIME;
			thread_recompute_priority(thread);
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

	case THREAD_AFFINITY_POLICY:
	{
		thread_affinity_policy_t	info;

		if (!thread_affinity_is_supported()) {
			result = KERN_NOT_SUPPORTED;
			break;
		}
		if (count < THREAD_AFFINITY_POLICY_COUNT) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		info = (thread_affinity_policy_t) policy_info;
		/*
		 * Unlock the thread mutex here and
		 * return directly after calling thread_affinity_set().
		 * This is necessary for correct lock ordering because
		 * thread_affinity_set() takes the task lock.
		 */
		thread_mtx_unlock(thread);
		return thread_affinity_set(thread, info->affinity_tag);
	}

#if CONFIG_EMBEDDED
	case THREAD_BACKGROUND_POLICY:
	{
		thread_background_policy_t	info;

		info = (thread_background_policy_t) policy_info;

		thread_mtx_unlock(thread);
		return mach_do_background_thread(thread, info->priority);
	}
#endif /* CONFIG_EMBEDDED */

	default:
		result = KERN_INVALID_ARGUMENT;
		break;
	}

	thread_mtx_unlock(thread);
	return (result);
}

static void
thread_recompute_priority(
	thread_t		thread)
{
	integer_t		priority;

	if (thread->sched_mode == TH_MODE_REALTIME)
		priority = BASEPRI_RTQUEUES;
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
#if CONFIG_EMBEDDED
		/* No one can have a base priority less than MAXPRI_THROTTLE */
		if (priority < MAXPRI_THROTTLE) 
			priority = MAXPRI_THROTTLE;
#endif /* CONFIG_EMBEDDED */
	}

	set_priority(thread, priority);
}

#if CONFIG_EMBEDDED
static void
thread_throttle(
	thread_t		thread,
	integer_t		task_priority)
{
	if (!(thread->sched_flags & TH_SFLAG_THROTTLED) && 
		(task_priority <= MAXPRI_THROTTLE)) {

		if (!((thread->sched_mode == TH_MODE_REALTIME) ||
			  (thread->saved_mode == TH_MODE_REALTIME))) {
			return;
		}

		/* Demote to timeshare if throttling */
		if (thread->sched_mode == TH_MODE_REALTIME)		
		{
			thread->saved_mode = TH_MODE_REALTIME;

			if (thread->sched_mode == TH_MODE_TIMESHARE) {
				if ((thread->state & (TH_RUN|TH_IDLE)) == TH_RUN)
					sched_share_incr();
			}
		}

		/* TH_SFLAG_FAILSAFE and TH_SFLAG_THROTTLED are mutually exclusive,
		 * since a throttled thread is not realtime during the throttle
		 * and doesn't need the failsafe repromotion. We therefore clear
		 * the former and set the latter flags here.
		 */
		thread->sched_flags &= ~TH_SFLAG_FAILSAFE;
		thread->sched_flags |= TH_SFLAG_THROTTLED;
		
		if (SCHED(supports_timeshare_mode)())
			thread->sched_mode = TH_MODE_TIMESHARE;
		else
			thread->sched_mode = TH_MODE_FIXED;
	}
	else if ((thread->sched_flags & TH_SFLAG_THROTTLED) &&
			 (task_priority > MAXPRI_THROTTLE)) {

		/* Promote back to real time if unthrottling */
		if (!(thread->saved_mode == TH_MODE_TIMESHARE)) {

			thread->sched_mode = thread->saved_mode;

			if (thread->sched_mode == TH_MODE_TIMESHARE) {
				if ((thread->state & (TH_RUN|TH_IDLE)) == TH_RUN)
					sched_share_decr();
			}
			
			thread->saved_mode = TH_MODE_NONE;
		}

		thread->sched_flags &= ~TH_SFLAG_THROTTLED;
	}	
}
#endif

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

#if CONFIG_EMBEDDED
	thread_throttle(thread, priority);
#endif

	thread->task_priority = priority;
	thread->max_priority = max_priority;

	thread_recompute_priority(thread);

	thread_unlock(thread);
	splx(s);
}

void
thread_policy_reset(
	thread_t		thread)
{
	spl_t		s;

	s = splsched();
	thread_lock(thread);

	if (!(thread->sched_flags & TH_SFLAG_DEMOTED_MASK)) {
		sched_mode_t oldmode = thread->sched_mode;
		
		thread->sched_mode = SCHED(initial_thread_sched_mode)(thread->task);

		if ((oldmode != TH_MODE_TIMESHARE) && (thread->sched_mode == TH_MODE_TIMESHARE)) {

			if ((thread->state & (TH_RUN|TH_IDLE)) == TH_RUN)
				sched_share_incr();
		}
	}
	else {
		thread->saved_mode = TH_MODE_NONE;
		thread->sched_flags &= ~TH_SFLAG_DEMOTED_MASK;
	}

	thread->importance = 0;

	thread_recompute_priority(thread);

	thread_unlock(thread);
	splx(s);
}

kern_return_t
thread_policy_get(
	thread_t				thread,
	thread_policy_flavor_t	flavor,
	thread_policy_t			policy_info,
	mach_msg_type_number_t	*count,
	boolean_t				*get_default)
{
	kern_return_t			result = KERN_SUCCESS;
	spl_t					s;

	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	thread_mtx_lock(thread);
	if (!thread->active) {
		thread_mtx_unlock(thread);

		return (KERN_TERMINATED);
	}

	switch (flavor) {

	case THREAD_EXTENDED_POLICY:
	{
		boolean_t		timeshare = TRUE;

		if (!(*get_default)) {
			s = splsched();
			thread_lock(thread);

			if (	 (thread->sched_mode != TH_MODE_REALTIME)	&&
					 (thread->saved_mode != TH_MODE_REALTIME)			) {
				if (!(thread->sched_flags & TH_SFLAG_DEMOTED_MASK))
					timeshare = (thread->sched_mode == TH_MODE_TIMESHARE) != 0;
				else
					timeshare = (thread->saved_mode == TH_MODE_TIMESHARE) != 0;
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

			if (	(thread->sched_mode == TH_MODE_REALTIME)	||
					(thread->saved_mode == TH_MODE_REALTIME)		) {
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
			info->computation = default_timeshare_computation;
			info->constraint = default_timeshare_constraint;
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

	case THREAD_AFFINITY_POLICY:
	{
		thread_affinity_policy_t		info;

		if (!thread_affinity_is_supported()) {
			result = KERN_NOT_SUPPORTED;
			break;
		}
		if (*count < THREAD_AFFINITY_POLICY_COUNT) {
			result = KERN_INVALID_ARGUMENT;
			break;
		}

		info = (thread_affinity_policy_t)policy_info;

		if (!(*get_default))
			info->affinity_tag = thread_affinity_get(thread);
		else
			info->affinity_tag = THREAD_AFFINITY_TAG_NULL;

		break;
	}

	default:
		result = KERN_INVALID_ARGUMENT;
		break;
	}

	thread_mtx_unlock(thread);

	return (result);
}

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

#include <kern/task.h>

static void
task_priority(
	task_t			task,
	integer_t		priority,
	integer_t		max_priority);

kern_return_t
task_policy_set(
	task_t					task,
	task_policy_flavor_t	flavor,
	task_policy_t			policy_info,
	mach_msg_type_number_t	count)
{
	kern_return_t		result = KERN_SUCCESS;

	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	switch (flavor) {

	case TASK_CATEGORY_POLICY:
	{
		task_category_policy_t		info = (task_category_policy_t)policy_info;

		if (count < TASK_CATEGORY_POLICY_COUNT)
			return (KERN_INVALID_ARGUMENT);

		task_lock(task);

		if (	info->role == TASK_FOREGROUND_APPLICATION	||
				info->role == TASK_BACKGROUND_APPLICATION		) {
			switch (task->role) {

			case TASK_FOREGROUND_APPLICATION:
			case TASK_BACKGROUND_APPLICATION:
			case TASK_UNSPECIFIED:
				task_priority(task,
								((info->role == TASK_FOREGROUND_APPLICATION)?
									BASEPRI_FOREGROUND: BASEPRI_BACKGROUND),
							  task->max_priority);
				task->role = info->role;
				break;

			case TASK_CONTROL_APPLICATION:
			case TASK_RENICED:
				/* fail silently */
				break;

			default:
				result = KERN_INVALID_ARGUMENT;
				break;
			}
		}
		else
		if (info->role == TASK_CONTROL_APPLICATION) {
			if (	task != current_task()			||
					task->sec_token.val[0] != 0			)
				result = KERN_INVALID_ARGUMENT;
			else {
				task_priority(task, BASEPRI_CONTROL, task->max_priority);
				task->role = info->role;
			}
		}
		else
		if (info->role == TASK_GRAPHICS_SERVER) {
			if (	task != current_task()			||
					task->sec_token.val[0] != 0			)
				result = KERN_INVALID_ARGUMENT;
			else {
				task_priority(task, MAXPRI_SYSTEM - 3, MAXPRI_SYSTEM);
				task->role = info->role;
			}
		}
		else
			result = KERN_INVALID_ARGUMENT;

		task_unlock(task);

		break;
	}

	default:
		result = KERN_INVALID_ARGUMENT;
		break;
	}

	return (result);
}

static void
task_priority(
	task_t			task,
	integer_t		priority,
	integer_t		max_priority)
{
	thread_act_t	act;

	task->max_priority = max_priority;

	if (priority > task->max_priority)
		priority = task->max_priority;
	else
	if (priority < MINPRI)
		priority = MINPRI;

	task->priority = priority;

	queue_iterate(&task->threads, act, thread_act_t, task_threads) {
		thread_t		thread = act_lock_thread(act);

		if (act->active)
			thread_task_priority(thread, priority, max_priority);

		act_unlock_thread(act);
	}
}

kern_return_t
task_importance(
	task_t				task,
	integer_t			importance)
{
	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);

	if (!task->active) {
		task_unlock(task);

		return (KERN_TERMINATED);
	}

	if (task->role >= TASK_CONTROL_APPLICATION) {
		task_unlock(task);

		return (KERN_INVALID_ARGUMENT);
	}

	task_priority(task, importance + BASEPRI_DEFAULT, task->max_priority);
	task->role = TASK_RENICED;

	task_unlock(task);

	return (KERN_SUCCESS);
}
		
kern_return_t
task_policy_get(
	task_t					task,
	task_policy_flavor_t	flavor,
	task_policy_t			policy_info,
	mach_msg_type_number_t	*count,
	boolean_t				*get_default)
{
	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	switch (flavor) {

	case TASK_CATEGORY_POLICY:
	{
		task_category_policy_t		info = (task_category_policy_t)policy_info;

		if (*count < TASK_CATEGORY_POLICY_COUNT)
			return (KERN_INVALID_ARGUMENT);

		if (*get_default)
			info->role = TASK_UNSPECIFIED;
		else {
			task_lock(task);
			info->role = task->role;
			task_unlock(task);
		}
		break;
	}

	default:
		return (KERN_INVALID_ARGUMENT);
	}

	return (KERN_SUCCESS);
}

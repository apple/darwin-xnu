/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
#include <mach/task_server.h>

#include <kern/sched.h>
#include <kern/task.h>
#include <mach/thread_policy.h>
#include <sys/errno.h>
#include <sys/resource.h>
#include <machine/limits.h>

static int proc_apply_bgtaskpolicy_locked(task_t task, int, int);
static int proc_restore_bgtaskpolicy_locked(task_t, int, int, int);
static int task_get_cpuusage(task_t task, uint32_t * percentagep, uint64_t * intervalp, uint64_t * deadlinep);
static int task_set_cpuusage(task_t task, uint32_t percentage, uint64_t interval, uint64_t deadline);
static int task_apply_resource_actions(task_t task, int type);
static int proc_apply_bgthreadpolicy_locked(thread_t thread, int selfset);
static void restore_bgthreadpolicy_locked(thread_t thread, int selfset);

process_policy_t default_task_proc_policy = {0,
					     0,
					    TASK_POLICY_RESOURCE_ATTRIBUTE_NONE, 
					    TASK_POLICY_RESOURCE_ATTRIBUTE_NONE, 
					    TASK_POLICY_RESOURCE_ATTRIBUTE_NONE, 
					    TASK_POLICY_RESOURCE_ATTRIBUTE_NONE, 
					    TASK_POLICY_RESOURCE_ATTRIBUTE_NONE, 
					    TASK_POLICY_RESOURCE_ATTRIBUTE_NONE, 
					    TASK_POLICY_RESOURCE_ATTRIBUTE_NONE, 
					    0,
					    TASK_POLICY_HWACCESS_CPU_ATTRIBUTE_ALL,
					    TASK_POLICY_HWACCESS_NET_ATTRIBUTE_NORMAL,
					    TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_FULLACCESS,
					    TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_NORMAL,
					    TASK_POLICY_BACKGROUND_ATTRIBUTE_ALL
					    };

process_policy_t default_task_null_policy = {0,
					     0,
					    TASK_POLICY_RESOURCE_ATTRIBUTE_NONE, 
					    TASK_POLICY_RESOURCE_ATTRIBUTE_NONE, 
					    TASK_POLICY_RESOURCE_ATTRIBUTE_NONE, 
					    TASK_POLICY_RESOURCE_ATTRIBUTE_NONE, 
					    TASK_POLICY_RESOURCE_ATTRIBUTE_NONE, 
					    TASK_POLICY_RESOURCE_ATTRIBUTE_NONE, 
					    TASK_POLICY_RESOURCE_ATTRIBUTE_NONE, 
					    0,
					    TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NONE,
					    TASK_POLICY_HWACCESS_NET_ATTRIBUTE_NONE,
					    TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NONE,
					    TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_NORMAL,
					    TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE
					    };
			

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
	void * bsdinfo = NULL;
	int setbg = 0;

	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	switch (flavor) {

	case TASK_CATEGORY_POLICY:
	{
		task_category_policy_t info = (task_category_policy_t)policy_info;

		if (count < TASK_CATEGORY_POLICY_COUNT)
			return (KERN_INVALID_ARGUMENT);

#if CONFIG_EMBEDDED
		if ((current_task() == task) && (info != NULL) &&
		    (info->role != TASK_THROTTLE_APPLICATION))
		return (KERN_INVALID_ARGUMENT);
#endif

		task_lock(task);
		if (	info->role == TASK_FOREGROUND_APPLICATION ||
				info->role == TASK_BACKGROUND_APPLICATION) {
#if !CONFIG_EMBEDDED
			if (task->ext_actionstate.apptype != PROC_POLICY_OSX_APPTYPE_NONE) {
				switch (info->role) {
					case TASK_FOREGROUND_APPLICATION:
						switch (task->ext_actionstate.apptype) {
							case PROC_POLICY_OSX_APPTYPE_TAL:
								/* Move the app to foreground with no DarwinBG */
								proc_restore_bgtaskpolicy_locked(task, 1, 1, BASEPRI_FOREGROUND);
								bsdinfo = task->bsd_info;
								setbg = 0;
								break;

							case PROC_POLICY_OSX_APPTYPE_DBCLIENT: 
								/* reset the apptype so enforcement on background/foregound */
								task->ext_actionstate.apptype = PROC_POLICY_OSX_APPTYPE_NONE;
								/* Internal application and make it foreground pri */
								proc_restore_bgtaskpolicy_locked(task, 1, 0, BASEPRI_FOREGROUND);
								bsdinfo = task->bsd_info;
								setbg = 0;
								break;

							default:
								/* the app types cannot be in CONTROL, GRAPHICS STATE, so it will de default state here */
								task_priority(task,
									((info->role == TASK_FOREGROUND_APPLICATION)?
									BASEPRI_FOREGROUND: BASEPRI_BACKGROUND),
									task->max_priority);
								break;
					}
					task->role = TASK_FOREGROUND_APPLICATION;
					break;

					case TASK_BACKGROUND_APPLICATION:
						switch (task->ext_actionstate.apptype) {
							case PROC_POLICY_OSX_APPTYPE_TAL:
								/* TAL apps will get Darwin backgrounded if not already set */
								if (task->ext_actionstate.hw_bg == TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE) {
									/* external application of Darwin BG */
									proc_apply_bgtaskpolicy_locked(task, 1, 1);
									bsdinfo = task->bsd_info;
									setbg = 1;
								}
								break;

							default:
								task_priority(task,
									((info->role == TASK_FOREGROUND_APPLICATION)?
									BASEPRI_FOREGROUND: BASEPRI_BACKGROUND),
									task->max_priority);
								break;
						}
						task->role = TASK_BACKGROUND_APPLICATION;
						break;

					default:
						/* do nothing */
						break;

				} /* switch info->role */
			} else   { /* apptype != PROC_POLICY_OSX_APPTYPE_NONE */
#endif /* !CONFIG_EMBEDDED */
			switch (task->role) {

			case TASK_FOREGROUND_APPLICATION:
			case TASK_BACKGROUND_APPLICATION:
			case TASK_UNSPECIFIED:
				/* if there are no process wide backgrounding ... */
				if ((task->ext_actionstate.hw_bg == TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE) &&
					(task->actionstate.hw_bg == TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE)) {
						task_priority(task,
							((info->role == TASK_FOREGROUND_APPLICATION)?
							BASEPRI_FOREGROUND: BASEPRI_BACKGROUND),
							task->max_priority);
				}
				task->role = info->role;
				break;

			case TASK_CONTROL_APPLICATION:
			case TASK_RENICED:
				/* else fail silently */
				break;

			default:
				result = KERN_INVALID_ARGUMENT;
				break;
			}
#if !CONFIG_EMBEDDED
		} /* apptype != PROC_POLICY_OSX_APPTYPE_NONE */
#endif /* !CONFIG_EMBEDDED */

		} else if (info->role == TASK_CONTROL_APPLICATION) {
			if (task != current_task()||
					task->sec_token.val[0] != 0)
				result = KERN_INVALID_ARGUMENT;
			else {
				task_priority(task, BASEPRI_CONTROL, task->max_priority);
				task->role = info->role;
			}
		} else if (info->role == TASK_GRAPHICS_SERVER) {
			if (task != current_task() ||
					task->sec_token.val[0] != 0)
				result = KERN_INVALID_ARGUMENT;
			else {
				task_priority(task, MAXPRI_RESERVED - 3, MAXPRI_RESERVED);
				task->role = info->role;
			}
		} else
#if CONFIG_EMBEDDED
		if (info->role == TASK_THROTTLE_APPLICATION) {
			task_priority(task, MAXPRI_THROTTLE, MAXPRI_THROTTLE);
			task->role = info->role;
		} else if (info->role == TASK_DEFAULT_APPLICATION || info->role == TASK_NONUI_APPLICATION)
		{
			task_priority(task, BASEPRI_DEFAULT, MAXPRI_USER);
			task->role = info->role;
		} else
#else /* CONFIG_EMBEDDED */
		if (info->role == TASK_DEFAULT_APPLICATION)
		{
			task_priority(task, BASEPRI_DEFAULT, MAXPRI_USER);
			task->role = info->role;
		} else
#endif /* CONFIG_EMBEDDED */
			result = KERN_INVALID_ARGUMENT;

		task_unlock(task);

		/* if backgrounding action ... */
		if (bsdinfo != NULL)
			proc_set_task_networkbg(bsdinfo, setbg);

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
	thread_t		thread;

	task->max_priority = max_priority;

	if (priority > task->max_priority)
		priority = task->max_priority;
	else
	if (priority < MINPRI)
		priority = MINPRI;

	task->priority = priority;

	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		thread_mtx_lock(thread);

		if (thread->active)
			thread_task_priority(thread, priority, max_priority);

		thread_mtx_unlock(thread);
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

/* task Darwin BG enforcement/settings related routines */
int 
proc_get_task_bg_policy(task_t task)
{

	int selfset = 0;
	int val = 0;

	if (current_task() == task) 
		selfset = 1;

	if (selfset == 0) {
		val = task->ext_policystate.hw_bg;
	} else {
		val = task->policystate.hw_bg;
	}

	return(val);
}


int 
proc_get_thread_bg_policy(task_t task, uint64_t tid)
{
	thread_t self = current_thread();
	thread_t thread = THREAD_NULL;
	int val = 0;

	if (tid == self->thread_id)  {
		val = self->policystate.hw_bg;
	} else {
		task_lock(task);
		thread = task_findtid(task, tid);
		if (thread != NULL)
			val = thread->ext_policystate.hw_bg;
		task_unlock(task);
	}

	return(val);
}

int
proc_get_self_isbackground(void)
{
	task_t task = current_task();;
	thread_t thread = current_thread();

	if ((task->ext_actionstate.hw_bg != TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE) ||
		(task->actionstate.hw_bg != TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE) ||
		(thread->ext_actionstate.hw_bg != TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE) ||
		(thread->actionstate.hw_bg != TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE))
			return(1);
	else
		return(0);	
	
}

int proc_get_selfthread_isbackground(void)
{
	thread_t thread = current_thread();

	if ((thread->ext_actionstate.hw_bg != TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE) ||
		(thread->actionstate.hw_bg != TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE))
			return(1);
	else
		return(0);	
}


int 
proc_set_bgtaskpolicy(task_t task, int intval)
{

	int selfset = 0;

	if (current_task() == task) 
		selfset = 1;

	task_lock(task);

	if (selfset == 0) {
		/* allready set? */
		if (task->ext_policystate.hw_bg != intval)
			task->ext_policystate.hw_bg = intval;
	} else {
		if (task->policystate.hw_bg != intval)
			task->policystate.hw_bg = intval;
	}

	task_unlock(task);
	return(0);
}

/* set and apply as well */
int proc_set1_bgtaskpolicy(task_t task, int prio)
{
	int error = 0;

	if (prio == PRIO_DARWIN_BG) {
		error = proc_set_bgtaskpolicy(task, TASK_POLICY_BACKGROUND_ATTRIBUTE_ALL);
		if (error == 0)
			error = proc_apply_bgtaskpolicy(task);
	} else {
		error = proc_restore_bgtaskpolicy(task);
	}

	return(error);
}


int 
proc_set_bgthreadpolicy(task_t task, uint64_t tid, int prio)
{
	thread_t self = current_thread();
	thread_t thread = THREAD_NULL;
	int reset;

	if (prio == 0)
		reset = 1;
	task_lock(task);
	if (tid == self->thread_id) {
		self->policystate.hw_bg = prio;
	} else {
		thread = task_findtid(task, tid);
		if (thread != NULL)
			thread->ext_policystate.hw_bg = prio;
	}
		
	task_unlock(task);

	return(0);
}

int 
proc_set1_bgthreadpolicy(task_t task, uint64_t tid, int prio)
{
	int error = 0;

	if (prio == PRIO_DARWIN_BG) {
		error = proc_set_bgthreadpolicy(task, tid, TASK_POLICY_BACKGROUND_ATTRIBUTE_ALL);
		if (error == 0)
			error = proc_apply_bgthreadpolicy(task, tid);
	} else {
		error = proc_restore_bgthreadpolicy(task, tid);
	}

	return(error);
}

int 
proc_add_bgtaskpolicy(task_t task, int val)
{
	int selfset = 0;

	if (current_task() == task) 
		selfset = 1;

	task_lock(task);

	if (selfset == 0) {
		task->policystate.hw_bg |= val;
	} else {
		task->ext_policystate.hw_bg |= val;
	}

	task_unlock(task);
	return(0);
}

int 
proc_add_bgthreadpolicy(task_t task, uint64_t tid, int val)
{
	thread_t self = current_thread();
	thread_t thread = THREAD_NULL;
	int reset;

	if (val == 0)
		reset = 1;
	task_lock(task);
	if (tid == self->thread_id) {
		self->policystate.hw_bg |= val;
	} else {
		thread = task_findtid(task, tid);
		if (thread != NULL)
			thread->ext_policystate.hw_bg |= val;
	}
		
	task_unlock(task);

	return(val);
}

int 
proc_remove_bgtaskpolicy(task_t task, int intval)
{
	int selfset = 0;

	if (current_task() == task) 
		selfset = 1;

	task_lock(task);

	if (selfset == 0) {
		task->policystate.hw_bg &= ~intval;
	} else {
		task->ext_policystate.hw_bg &= ~intval;
	}

	task_unlock(task);
	return(0);
}

int 
proc_remove_bgthreadpolicy(task_t task, uint64_t tid, int val)
{
	thread_t self = current_thread();
	thread_t thread = THREAD_NULL;
	int reset;

	if (val == 0)
		reset = 1;
	task_lock(task);
	if (tid == self->thread_id) {
		self->policystate.hw_bg &= ~val;
	} else {
		thread = task_findtid(task, tid);
		if (thread != NULL)
			thread->ext_policystate.hw_bg &= ~val;
	}
		
	task_unlock(task);

	return(val);
}

int
proc_apply_bgtask_selfpolicy(void)
{
	return(proc_apply_bgtaskpolicy(current_task()));
}

int 
proc_apply_bgtaskpolicy(task_t task)
{
	int external = 1;

	if (task == current_task())
		external = 0;

	return(proc_apply_bgtaskpolicy_locked(task, 0, external));
}

int
proc_apply_bgtaskpolicy_external(task_t task)
{
	return(proc_apply_bgtaskpolicy_locked(task, 0, 1));

}

int
proc_apply_bgtaskpolicy_internal(task_t task)
{
	return(proc_apply_bgtaskpolicy_locked(task, 0, 0));
}


static int
proc_apply_bgtaskpolicy_locked(task_t task, int locked, int external)
{
	if (locked == 0)
		task_lock(task);

	if (external != 0) {
		/* allready set? */
		if (task->ext_actionstate.hw_bg != task->ext_policystate.hw_bg) {
			task->ext_actionstate.hw_bg = task->ext_policystate.hw_bg;
			task_priority(task, MAXPRI_THROTTLE, MAXPRI_THROTTLE);
			/* background state applied */
		}
	} else {
		if (task->actionstate.hw_bg != task->policystate.hw_bg) {
			task->actionstate.hw_bg = task->policystate.hw_bg;
			task_priority(task, MAXPRI_THROTTLE, MAXPRI_THROTTLE);
		}
	}
	if (locked == 0)
		task_unlock(task);
	return(0);
}

/* apply the self backgrounding even if the thread is not current thread/task(timer threads) */
int
proc_apply_workq_bgthreadpolicy(thread_t thread)
{
	int error;
	task_t wqtask = TASK_NULL;

	if (thread != THREAD_NULL) {
		wqtask = thread->task;
		task_lock(wqtask);
		/* apply the background as selfset internal one */
		error = proc_apply_bgthreadpolicy_locked(thread, 1);
		task_unlock(wqtask);
	} else	
		error = ESRCH;

	return(error);
}

int 
proc_apply_bgthreadpolicy(task_t task, uint64_t tid)
{
	thread_t self = current_thread();
	thread_t thread = THREAD_NULL;
	int selfset = 0, error = 0;
	task_t localtask = TASK_NULL;

	if (tid == self->thread_id) {
		selfset = 1;
		localtask = current_task();
	} else {
		localtask = task;
	}

	task_lock(localtask);
	if (selfset != 0) {
		thread = self;
	} else {
		thread = task_findtid(task, tid);
	}

	error = proc_apply_bgthreadpolicy_locked(thread, selfset);
	task_unlock(localtask);

	return(error);
}

static int
proc_apply_bgthreadpolicy_locked(thread_t thread, int selfset)
{
	int set = 0;
	thread_precedence_policy_data_t policy;

	if (thread != NULL) {
		if (selfset != 0) {
			/* internal application */
			if (thread->actionstate.hw_bg != thread->policystate.hw_bg) {
				thread->actionstate.hw_bg = thread->policystate.hw_bg;
				if (thread->ext_actionstate.hw_bg == TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE) 
					set = 1;
		
			}
		} else {
			/* external application */
			if (thread->ext_actionstate.hw_bg != thread->ext_policystate.hw_bg) {
				thread->ext_actionstate.hw_bg = thread->ext_policystate.hw_bg;
				if (thread->actionstate.hw_bg == TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE)
					set = 1;
			}
		}
			
		if (set != 0) {
			/* set thread priority (we did not save previous value) */
			policy.importance = INT_MIN;
				
			thread_policy_set_internal(thread, THREAD_PRECEDENCE_POLICY,
                                                   (thread_policy_t)&policy,
                                                   THREAD_PRECEDENCE_POLICY_COUNT );

		}
	} else	
		return(ESRCH);
		
	return(0);
}

int
proc_apply_bgthread_selfpolicy(void)
{
	return(proc_apply_bgthreadpolicy(current_task(), current_thread()->thread_id));
}


int 
proc_restore_bgtaskpolicy(task_t task)
{
	int external = 1;

	if (current_task() == task) 
		external = 0;
	return(proc_restore_bgtaskpolicy_locked(task, 0, external,  BASEPRI_DEFAULT));
}

static int
proc_restore_bgtaskpolicy_locked(task_t task, int locked, int external, int pri)
{
	if (locked == 0)
		task_lock(task);

	if (external != 0) {
		task->ext_actionstate.hw_bg = TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE;
		/* self BG in flight? */
		if (task->actionstate.hw_bg == TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE) {
			task_priority(task, pri, MAXPRI_USER);
#if CONFIG_EMBEDDED
			/* non embedded users need role for policy reapplication */
			task->role = TASK_DEFAULT_APPLICATION;
#endif /* CONFIG_EMBEDDED */
		}
	 } else {
		task->actionstate.hw_bg = TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE;
		/* external BG in flight? */
		if (task->ext_actionstate.hw_bg == TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE) {
			task_priority(task, pri, MAXPRI_USER);
#if CONFIG_EMBEDDED
			/* non embedded users need role for policy reapplication */
			task->role = TASK_DEFAULT_APPLICATION;
#endif /* CONFIG_EMBEDDED */
		}
	}

	if (locked == 0)
		task_unlock(task);

	return(0);
}

/* restore the self backgrounding even if the thread is not current thread */
int
proc_restore_workq_bgthreadpolicy(thread_t thread)
{
	int error = 0;
	task_t wqtask = TASK_NULL;

	if (thread != THREAD_NULL) {
		wqtask = thread->task;
		task_lock(wqtask);
		/* remove the background and restore default importance as self(internal) removal */
		restore_bgthreadpolicy_locked(thread, 1);
		task_unlock(wqtask);
	} else
		error = ESRCH;

	return(error);
}

int proc_restore_bgthread_selfpolicy(void)
{
	return(proc_restore_bgthreadpolicy(current_task(), thread_tid(current_thread())));

}


int 
proc_restore_bgthreadpolicy(task_t task, uint64_t tid)
{
	int selfset = 0;
	thread_t self = current_thread();
	thread_t thread = THREAD_NULL;

	task_lock(task);
	if (tid == self->thread_id) {
		thread = self;
		selfset = 1;
	} else {
		thread = task_findtid(task, tid);
	}

	if (thread != NULL)
		restore_bgthreadpolicy_locked(thread, selfset);

	task_unlock(task);

	if (thread != NULL)
		return(0);
	else
		return(1);
}

static void
restore_bgthreadpolicy_locked(thread_t thread, int selfset)
{
	thread_precedence_policy_data_t policy;
	int reset = 0;

	if (thread != NULL) {
		if (selfset != 0) {
			thread->actionstate.hw_bg = TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE;
			/* external BG in flight? */
			if (thread->ext_actionstate.hw_bg == TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE)
					reset = 1;
		
		} else {
			thread->ext_actionstate.hw_bg = TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE;
			/* self BG in flight? */
			if (thread->actionstate.hw_bg == TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE)
					reset = 1;
		}
			
		if (reset != 0) {
			/* reset thread priority (we did not save previous value) */
			policy.importance = 0;
			thread_policy_set_internal(thread, THREAD_PRECEDENCE_POLICY,
                                                   (thread_policy_t)&policy,
                                                   THREAD_PRECEDENCE_POLICY_COUNT );
		}
	}
}

void 
proc_set_task_apptype(task_t task, int type)
{
	switch (type) {
		case PROC_POLICY_OSX_APPTYPE_TAL:
			task->ext_policystate.apptype = type;
			task->policystate.apptype = type;
			proc_apply_bgtaskpolicy_external(task);
			/* indicate that BG is set and next foreground needs to reset */
			task->ext_actionstate.apptype = type;
			break;

		case PROC_POLICY_OSX_APPTYPE_DBCLIENT:
			task->ext_policystate.apptype = type;
			task->policystate.apptype = type;
			proc_apply_bgtaskpolicy_internal(task);
			/* indicate that BG is set and next foreground needs to reset */
			task->ext_actionstate.apptype = type;
			break;
	
		case PROC_POLICY_IOS_APPTYPE:
			task->ext_policystate.apptype = type;
			task->policystate.apptype = type;
			break;
		case PROC_POLICY_IOS_NONUITYPE:
			task->ext_policystate.apptype = type;
			task->policystate.apptype = type;
			/* set to deny access to gpu */
			task->ext_actionstate.hw_gpu = TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS;
			task->ext_policystate.hw_gpu = TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS;
			break;

		default:
			break;
	}
}

/* update the darwin backdground action state in the flags field for libproc */
#define PROC_FLAG_DARWINBG      0x8000  /* process in darwin background */
#define PROC_FLAG_EXT_DARWINBG  0x10000 /* process in darwin background - external enforcement */

int
proc_get_darwinbgstate(task_t task, uint32_t * flagsp)
{
	if (task->ext_actionstate.hw_bg == TASK_POLICY_BACKGROUND_ATTRIBUTE_ALL){
		*flagsp |= PROC_FLAG_EXT_DARWINBG;
	}
	if (task->actionstate.hw_bg == TASK_POLICY_BACKGROUND_ATTRIBUTE_ALL){
		*flagsp |= PROC_FLAG_DARWINBG;
	}
		
	return(0);
}

/* 
 * HW disk access realted routines, they need to return 
 * IOPOL_XXX equivalents for spec_xxx/throttle updates.
 */

int 
proc_get_task_disacc(task_t task)
{
	if ((task->ext_actionstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_DISKTHROTTLE) != 0)
		return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE);
	if (task->ext_actionstate.hw_disk != TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_NORMAL)
		return(task->ext_actionstate.hw_disk);
	if ((task->actionstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_DISKTHROTTLE) != 0)
		return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE);
	if (task->actionstate.hw_disk != TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_NORMAL)
		return(task->actionstate.hw_disk);
	return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_NORMAL);
}

int
proc_get_task_selfdiskacc(void)
{
	task_t task = current_task();
	thread_t thread= current_thread();

	/* 
	 * As per defined iopolicysys behavior, thread trumps task. 
	 * Do we need to follow that for external enforcements of BG or hw access?
	 * Status quo for now..
	 */
	if((thread->ext_actionstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_DISKTHROTTLE) != 0)
		return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE);
	if (thread->ext_actionstate.hw_disk != TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_NORMAL)
		return(thread->ext_actionstate.hw_disk);
	if((thread->actionstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_DISKTHROTTLE) != 0)
		return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE);
	if (thread->actionstate.hw_disk != TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_NORMAL)
		return(thread->actionstate.hw_disk);

	if ((task->ext_actionstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_DISKTHROTTLE) != 0)
		return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE);
	if (task->ext_actionstate.hw_disk != TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_NORMAL)
		return(task->ext_actionstate.hw_disk);
	if ((task->actionstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_DISKTHROTTLE) != 0)
		return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE);
	if (task->actionstate.hw_disk != TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_NORMAL)
		return(task->actionstate.hw_disk);
	return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_NORMAL);
}

int
proc_get_thread_selfdiskacc(void)
{
	thread_t thread = current_thread();

	if((thread->ext_actionstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_DISKTHROTTLE) != 0)
		return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE);
	if (thread->ext_actionstate.hw_disk != TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_NORMAL)
		return(thread->ext_actionstate.hw_disk);
	if((thread->actionstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_DISKTHROTTLE) != 0)
		return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE);
	if (thread->actionstate.hw_disk != TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_NORMAL)
		return(thread->actionstate.hw_disk);
	return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_NORMAL);
}

int proc_apply_task_diskacc(task_t task, int policy)
{
	task_t self = current_task();

	task_lock(task);
	if (task ==  self) {
		task->actionstate.hw_disk = policy;
		task->policystate.hw_disk = policy;
	} else {
		task->ext_actionstate.hw_disk = policy;
		task->ext_policystate.hw_disk = policy;
	}
	task_unlock(task);
	return(0);
}

int proc_apply_thread_diskacc(task_t task, uint64_t tid, int policy)
{
	thread_t thread;

	if (tid == TID_NULL) {
		thread = current_thread();
		proc_apply_thread_selfdiskacc(policy);
	} else {
		task_lock(task);
		thread = task_findtid(task, tid);
		if (thread != NULL) {
			thread->ext_actionstate.hw_disk = policy;
			thread->ext_policystate.hw_disk = policy;
		}
		task_unlock(task);
	}
	if (thread != NULL)
		return(0);
	else
		return(0);
}

int
proc_apply_thread_selfdiskacc(int policy)
{
	task_t task = current_task();
	thread_t thread = current_thread();

	task_lock(task);
	thread->actionstate.hw_disk = policy;
	thread->policystate.hw_disk = policy;
	task_unlock(task);
	return(0);
}

int 
proc_denyinherit_policy(__unused task_t task)
{
	return(0);
}

int 
proc_denyselfset_policy(__unused task_t task)
{
	return(0);
}

/* HW GPU access related routines */
int
proc_get_task_selfgpuacc_deny(void)
{
	task_t task = current_task();
	thread_t thread = current_thread();

	if (((task->ext_actionstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_NOGPU) != 0) || (task->ext_actionstate.hw_gpu == TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS))
		return(TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS);
	if (((task->actionstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_NOGPU) != 0) || (task->actionstate.hw_gpu == TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS))
		return(TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS);
	if (((thread->ext_actionstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_NOGPU) != 0) || (thread->ext_actionstate.hw_gpu == TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS))
		return(TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS);
	if (((thread->actionstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_NOGPU) != 0) || (thread->actionstate.hw_gpu == TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS))
		return(TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS);

	return(TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NORMAL);
}

int
proc_apply_task_gpuacc(task_t task, int policy)
{

	task_t self = current_task();

	task_lock(task);
	if (task ==  self) {
		task->actionstate.hw_gpu = policy;
		task->policystate.hw_gpu = policy;
	} else {
		task->ext_actionstate.hw_gpu = policy;
		task->ext_policystate.hw_gpu = policy;
	}
	task_unlock(task);

	return(0);
}

/* Resource usage , CPU realted routines */
int 
proc_get_task_ruse_cpu(task_t task, uint32_t * policyp, uint32_t * percentagep, uint64_t * intervalp, uint64_t * deadlinep)
{
	
	int error = 0;

	task_lock(task);
	if (task != current_task()) {
		*policyp = task->ext_policystate.ru_cpu;
	} else {
		*policyp = task->policystate.ru_cpu;
	}
	
	error = task_get_cpuusage(task, percentagep, intervalp, deadlinep);

	return(error);
}

int 
proc_set_task_ruse_cpu(task_t task, uint32_t policy, uint32_t percentage, uint64_t interval, uint64_t deadline)
{
	int error = 0;

	task_lock(task);
	if (task != current_task()) {
		task->ext_policystate.ru_cpu = policy;	
	} else {
		task->policystate.ru_cpu = policy;	
	}
	error = task_set_cpuusage(task, percentage, interval, deadline);
	task_unlock(task);
	return(error);
}


/* used to apply resource limit related actions */
static int
task_apply_resource_actions(task_t task, int type)
{
	int action = TASK_POLICY_RESOURCE_ATTRIBUTE_NONE;
	void * bsdinfo = NULL;
	
	switch (type) {
		case TASK_POLICY_CPU_RESOURCE_USAGE:
			break;
		case TASK_POLICY_WIREDMEM_RESOURCE_USAGE:
		case TASK_POLICY_VIRTUALMEM_RESOURCE_USAGE:
		case TASK_POLICY_DISK_RESOURCE_USAGE:
		case TASK_POLICY_NETWORK_RESOURCE_USAGE:
		case TASK_POLICY_POWER_RESOURCE_USAGE:
			return(0);

		default:
			return(1);
	};

	/* only cpu actions for now */
	task_lock(task);
	
	if (task->ext_actionstate.ru_cpu == TASK_POLICY_RESOURCE_ATTRIBUTE_NONE) {
		/* apply action */
		task->ext_actionstate.ru_cpu = task->ext_policystate.ru_cpu;
		action = task->ext_actionstate.ru_cpu;
	}
	if (action != TASK_POLICY_RESOURCE_ATTRIBUTE_NONE) {
		bsdinfo = task->bsd_info;
		task_unlock(task);
		proc_apply_resource_actions(bsdinfo, TASK_POLICY_CPU_RESOURCE_USAGE, action);
	} else
		task_unlock(task);

	return(0);
}

int
task_restore_resource_actions(task_t task, int type)
{
	int action;
	void * bsdinfo = NULL;
	
	switch (type) {
		case TASK_POLICY_CPU_RESOURCE_USAGE:
			break;
		case TASK_POLICY_WIREDMEM_RESOURCE_USAGE:
		case TASK_POLICY_VIRTUALMEM_RESOURCE_USAGE:
		case TASK_POLICY_DISK_RESOURCE_USAGE:
		case TASK_POLICY_NETWORK_RESOURCE_USAGE:
		case TASK_POLICY_POWER_RESOURCE_USAGE:
			return(0);

		default:
			return(1);
	};

	/* only cpu actions for now */
	task_lock(task);
	
	action = task->ext_actionstate.ru_cpu;
	if (task->ext_actionstate.ru_cpu != TASK_POLICY_RESOURCE_ATTRIBUTE_NONE) {
		/* reset action */
		task->ext_actionstate.ru_cpu = TASK_POLICY_RESOURCE_ATTRIBUTE_NONE;
	}
	if (action != TASK_POLICY_RESOURCE_ATTRIBUTE_NONE) {
		bsdinfo = task->bsd_info;
		task_unlock(task);
		proc_restore_resource_actions(bsdinfo, TASK_POLICY_CPU_RESOURCE_USAGE, action);
	} else
		task_unlock(task);

	return(0);

}

/* For ledger hookups */
static int
task_get_cpuusage(__unused task_t task, uint32_t * percentagep, uint64_t * intervalp, uint64_t * deadlinep)
{
	*percentagep = 0;
	*intervalp = 0;
	*deadlinep = 0;

	return(0);
}

static int
task_set_cpuusage(__unused task_t task, __unused uint32_t percentage, __unused uint64_t interval, __unused uint64_t deadline)
{
	return(0);
}

/* called by ledger unit to enforce action due to  resource usage criteria being met */
int
task_action_cpuusage(task_t task)
{
	return(task_apply_resource_actions(task, TASK_POLICY_CPU_RESOURCE_USAGE));
}

int 
proc_disable_task_apptype(task_t task, int policy_subtype)
{
	void * bsdinfo = NULL;
	int setbg = 0;
	int ret = 0;
	int maxpri = BASEPRI_DEFAULT;

	task_lock(task);

	if (task->ext_policystate.apptype != policy_subtype) {
		ret = EINVAL;
		goto out;
	}

#if !CONFIG_EMBEDDED
	switch (task->role) {
		case TASK_FOREGROUND_APPLICATION:
			maxpri = BASEPRI_FOREGROUND;
			break;
		case TASK_BACKGROUND_APPLICATION:
			maxpri = BASEPRI_BACKGROUND;
			break;
		default:
			maxpri = BASEPRI_DEFAULT;
	}
#endif
			
	if (task->ext_actionstate.apptype != PROC_POLICY_OSX_APPTYPE_NONE) {
			switch (task->ext_actionstate.apptype) {
				case PROC_POLICY_OSX_APPTYPE_TAL:
					/* disable foreground/background handling */
					task->ext_actionstate.apptype = PROC_POLICY_OSX_APPTYPE_NONE;
					/* external BG application removal */
					proc_restore_bgtaskpolicy_locked(task, 1, 1, maxpri);
					bsdinfo = task->bsd_info;
					setbg = 0;
					break;

				case PROC_POLICY_OSX_APPTYPE_DBCLIENT:
					/* disable foreground/background handling */
					task->ext_actionstate.apptype = PROC_POLICY_OSX_APPTYPE_NONE;
					/* internal BG application removal */
					proc_restore_bgtaskpolicy_locked(task, 1, 0, maxpri);
					bsdinfo = task->bsd_info;
					setbg = 0;
					break;

				default:
					ret = EINVAL;
					break;
			}
	} else
		ret = EINVAL;

out:
	task_unlock(task);
	/* if backgrounding action ... */
	if (bsdinfo != NULL)
		proc_set_task_networkbg(bsdinfo, setbg);

	return(ret);
}

int 
proc_enable_task_apptype(task_t task, int policy_subtype)
{
	void * bsdinfo = NULL;
	int setbg = 0;
	int ret = 0;

	task_lock(task);

	if (task->ext_policystate.apptype != policy_subtype) {
		ret = EINVAL;
		goto out;
	}

	if (task->ext_actionstate.apptype == PROC_POLICY_OSX_APPTYPE_NONE) {
		switch (task->ext_policystate.apptype) {
			case PROC_POLICY_OSX_APPTYPE_TAL:
			 	 /* TAL policy is activated again */
				task->ext_actionstate.apptype = task->ext_policystate.apptype;
				if (task->role == TASK_BACKGROUND_APPLICATION) {
					if (task->role == TASK_BACKGROUND_APPLICATION) {
						proc_apply_bgtaskpolicy_locked(task, 1, 1);
						bsdinfo = task->bsd_info;
						setbg = 1;
					}
				}
				ret = 0;
				break;
			default:
				ret = EINVAL;
		}
	} else
		ret = EINVAL;

out:
	task_unlock(task);
	/* if backgrounding action ... */
	if (bsdinfo != NULL)
		proc_set_task_networkbg(bsdinfo, setbg);

	return(ret);
}


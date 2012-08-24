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
#include <kern/ledger.h>
#include <kern/thread_call.h>
#if CONFIG_EMBEDDED
#include <kern/kalloc.h>
#include <sys/errno.h>
#endif /* CONFIG_EMBEDDED */
#include <sys/kdebug.h>

#if CONFIG_MEMORYSTATUS
extern void memorystatus_on_suspend(int pid);
extern void memorystatus_on_resume(int pid);
#endif

static int proc_apply_bgtaskpolicy_internal(task_t, int, int);
static int proc_restore_bgtaskpolicy_internal(task_t, int, int, int);
static int task_get_cpuusage(task_t task, uint32_t * percentagep, uint64_t * intervalp, uint64_t * deadlinep);
int task_set_cpuusage(task_t task, uint64_t percentage, uint64_t interval, uint64_t deadline, int scope);
static int task_clear_cpuusage_locked(task_t task);
static int task_apply_resource_actions(task_t task, int type);
static void task_priority(task_t task, integer_t priority, integer_t max_priority);
static kern_return_t task_role_default_handler(task_t task, task_role_t role);
void task_action_cpuusage(thread_call_param_t param0, thread_call_param_t param1);
static int proc_apply_bgthreadpolicy_locked(thread_t thread, int selfset);
static void restore_bgthreadpolicy_locked(thread_t thread, int selfset, int importance);
static int proc_get_task_selfdiskacc_internal(task_t task, thread_t thread);
extern void unthrottle_thread(void * uthread);

#if CONFIG_EMBEDDED
static void set_thread_appbg(thread_t thread, int setbg,int importance);
static void apply_bgthreadpolicy_external(thread_t thread);
static void add_taskwatch_locked(task_t task, task_watch_t * twp);
static void remove_taskwatch_locked(task_t task, task_watch_t * twp);
static void task_watch_lock(void);
static void task_watch_unlock(void);
static void apply_appstate_watchers(task_t task, int setbg);
void proc_apply_task_networkbg_internal(void *, thread_t);
void proc_restore_task_networkbg_internal(void *, thread_t);
int proc_pid(void * proc);

typedef struct thread_watchlist {
	thread_t thread;	/* thread being worked on for taskwatch action */
	int	importance;	/* importance to be restored if thread is being made active */
} thread_watchlist_t;

#endif /* CONFIG_EMBEDDED */


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
					    TASK_POLICY_HWACCESS_CPU_ATTRIBUTE_FULLACCESS,
					    TASK_POLICY_HWACCESS_NET_ATTRIBUTE_FULLACCESS,
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
			


/*
 * This routine should always be called with the task lock held.
 * This routine handles Default operations for TASK_FOREGROUND_APPLICATION 
 * and TASK_BACKGROUND_APPLICATION of task with no special app type.
 */
static kern_return_t
task_role_default_handler(task_t task, task_role_t role)
{
	kern_return_t result = KERN_SUCCESS;

	switch (task->role) {
		case TASK_FOREGROUND_APPLICATION:
		case TASK_BACKGROUND_APPLICATION:
		case TASK_UNSPECIFIED:
			/* if there are no process wide backgrounding ... */
			if ((task->ext_appliedstate.hw_bg == TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE) &&
				(task->appliedstate.hw_bg == TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE)) {
					task_priority(task,
						((role == TASK_FOREGROUND_APPLICATION)?
						BASEPRI_FOREGROUND: BASEPRI_BACKGROUND),
						task->max_priority);
			}
			task->role = role;
			break;

		case TASK_CONTROL_APPLICATION:
		case TASK_RENICED:
			/* else fail silently */
			break;

		default:
			result = KERN_INVALID_ARGUMENT;
			break;
	}
	return(result);
}


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
		switch(info->role) {
			case TASK_FOREGROUND_APPLICATION : {
				if (task->ext_appliedstate.apptype == PROC_POLICY_OSX_APPTYPE_NONE) {
					result = task_role_default_handler(task, info->role);
				} else {
					switch (task->ext_appliedstate.apptype) {
#if !CONFIG_EMBEDDED
						case PROC_POLICY_OSX_APPTYPE_TAL:
							/* Move the app to foreground with no DarwinBG */
							proc_restore_bgtaskpolicy_internal(task, 1, 1, BASEPRI_FOREGROUND);
							bsdinfo = task->bsd_info;
							setbg = 0;
							break;

						case PROC_POLICY_OSX_APPTYPE_DBCLIENT: 
							/* reset the apptype so enforcement on background/foregound */
							task->ext_appliedstate.apptype = PROC_POLICY_OSX_APPTYPE_NONE;
							/* Internal application and make it foreground pri */
							proc_restore_bgtaskpolicy_internal(task, 1, 0, BASEPRI_FOREGROUND);
							bsdinfo = task->bsd_info;
							setbg = 0;
							break;
#endif /* !CONFIG_EMBEDDED */

						default:
						/* the app types cannot be in CONTROL, GRAPHICS STATE, so it will de default state here */
							task_priority(task, BASEPRI_FOREGROUND, task->max_priority);
							break;

					} /* switch (task->ext_appliedstate.apptype) */
					task->role = TASK_FOREGROUND_APPLICATION;
				}
			}
			break;

			case TASK_BACKGROUND_APPLICATION : {
				if (task->ext_appliedstate.apptype == PROC_POLICY_OSX_APPTYPE_NONE) {
					result = task_role_default_handler(task, info->role);
				} else  { /* apptype != PROC_POLICY_OSX_APPTYPE_NONE */
					switch (task->ext_appliedstate.apptype) {
#if !CONFIG_EMBEDDED
						case PROC_POLICY_OSX_APPTYPE_TAL:
							 /* TAL apps will get Darwin backgrounded if not already set */
							if (task->ext_appliedstate.hw_bg == TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE) {
								proc_apply_bgtaskpolicy_internal(task, 1, 1);
								bsdinfo = task->bsd_info;
								setbg = 1;
							}
							break;
#endif /* !CONFIG_EMBEDDED */
						default:
							task_priority(task, BASEPRI_BACKGROUND, task->max_priority);
							break;
					} /* switch (task->ext_appliedstate.apptype) */
					task->role = TASK_BACKGROUND_APPLICATION;
				}
			}
			break;

		case TASK_CONTROL_APPLICATION: 
			if (task != current_task()||
					task->sec_token.val[0] != 0)
				result = KERN_INVALID_ARGUMENT;
			else {
				task_priority(task, BASEPRI_CONTROL, task->max_priority);
				task->role = info->role;
			}
			break;

		case TASK_GRAPHICS_SERVER:
			if (task != current_task() ||
					task->sec_token.val[0] != 0)
				result = KERN_INVALID_ARGUMENT;
			else {
				task_priority(task, MAXPRI_RESERVED - 3, MAXPRI_RESERVED);
				task->role = info->role;
			}
			break;
		case TASK_DEFAULT_APPLICATION:
			task_priority(task, BASEPRI_DEFAULT, MAXPRI_USER);
			task->role = info->role;
			break;

		default :
			result = KERN_INVALID_ARGUMENT;
			break;
		} /* switch (info->role) */

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
	int selfset = 0;
	thread_t self = current_thread();
	thread_t thread = THREAD_NULL;
	int val = 0;

	if (tid == self->thread_id)
		selfset = 1;
	
	if (selfset == 0)  {
		task_lock(task);
		thread = task_findtid(task, tid);
		if (thread != NULL)
			val = thread->ext_policystate.hw_bg;
		task_unlock(task);
	} else {
		val = self->policystate.hw_bg;
	}

	return(val);
}

int
proc_get_self_isbackground(void)
{
	task_t task = current_task();;
	thread_t thread = current_thread();

	if ((task->ext_appliedstate.hw_bg != TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE) ||
		(task->appliedstate.hw_bg != TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE) ||
		(thread->ext_appliedstate.hw_bg != TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE) ||
		(thread->appliedstate.hw_bg != TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE))
			return(1);
	else
		return(0);	
	
}

int proc_get_selfthread_isbackground(void)
{
	thread_t thread = current_thread();

	if ((thread->ext_appliedstate.hw_bg != TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE) ||
		(thread->appliedstate.hw_bg != TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE))
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

/* set and apply as well , handles reset of NONUI due to setprio() task app state implmn side effect */
int 
proc_set_and_apply_bgtaskpolicy(task_t task, int prio)
{
	int error = 0;

	if (prio == PRIO_DARWIN_BG) {
		error = proc_set_bgtaskpolicy(task, TASK_POLICY_BACKGROUND_ATTRIBUTE_ALL);
		if (error == 0) {
			error = proc_apply_bgtaskpolicy(task);
#if CONFIG_EMBEDDED
			/* XXX: till SB uses newer SPIs */
			apply_appstate_watchers(task, 1);
#endif /* CONFIG_EMBEDDED */
		}
	} else {
		error = proc_restore_bgtaskpolicy(task);
		if (error == 0) {
			/* since prior impl of non UI was overloaded with bg state, need to reset */
			error = proc_apply_task_gpuacc(task, TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_DEFAULT);
#if CONFIG_EMBEDDED
			/* XXX: till SB uses newer SPIs */
			apply_appstate_watchers(task, 0);
#endif /* CONFIG_EMBEDDED */
		}
		
	}

	return(error);
}


int 
proc_set_bgthreadpolicy(task_t task, uint64_t tid, int prio)
{
	int selfset = 0;
	thread_t self = current_thread();
	thread_t thread = THREAD_NULL;
	int reset;

	if (prio == 0)
		reset = 1;
	if (tid == self->thread_id)
		selfset = 1;

	task_lock(task);
	if (selfset == 0)  {
		thread = task_findtid(task, tid);
		if (thread != NULL)
			thread->ext_policystate.hw_bg = prio;
	} else {
		self->policystate.hw_bg = prio;
	}
		
	task_unlock(task);

	return(0);
}

int 
proc_set_and_apply_bgthreadpolicy(task_t task, uint64_t tid, int prio)
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
	int selfset = 0;
	thread_t self = current_thread();
	thread_t thread = THREAD_NULL;
	int reset;

	if (val == 0)
		reset = 1;
	if (tid == self->thread_id)
		selfset = 1;

	task_lock(task);
	if (selfset == 0)  {
		thread = task_findtid(task, tid);
		if (thread != NULL)
			thread->ext_policystate.hw_bg |= val;
	} else {
		self->policystate.hw_bg |= val;
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
	int selfset = 0;
	thread_t self = current_thread();
	thread_t thread = THREAD_NULL;
	int reset;

	if (val == 0)
		reset = 1;
	if (tid == self->thread_id)
		selfset = 1;

	task_lock(task);
	if (selfset == 0)  {
		thread = task_findtid(task, tid);
		if (thread != NULL)
			thread->ext_policystate.hw_bg &= ~val;
	} else {
		self->policystate.hw_bg &= ~val;
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
	return(proc_apply_bgtaskpolicy_internal(task, 0, external));
}

int 
proc_apply_bgtaskpolicy_external(task_t task)
{
	return(proc_apply_bgtaskpolicy_internal(task, 0, 1));
}

static int
proc_apply_bgtaskpolicy_internal(task_t task, int locked, int external)
{

	if (locked == 0)
		task_lock(task);

	/* if the process is exiting, no action to be done */
	if (task->proc_terminate != 0)
		goto out;

	if (external != 0) {
		/* allready set? */
		if (task->ext_appliedstate.hw_bg != task->ext_policystate.hw_bg) {
			task->ext_appliedstate.hw_bg = task->ext_policystate.hw_bg;
			task_priority(task, MAXPRI_THROTTLE, MAXPRI_THROTTLE);
			/* background state applied */
		}
	} else {
		if (task->appliedstate.hw_bg != task->policystate.hw_bg) {
			task->appliedstate.hw_bg = task->policystate.hw_bg;
			task_priority(task, MAXPRI_THROTTLE, MAXPRI_THROTTLE);
		}
	}
out:
	if (locked == 0)
		task_unlock(task);
	return(0);
}

/* apply the self backgrounding even if the thread is not current thread */
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
	int selfset = 0, error = 0;
	thread_t self = current_thread();
	thread_t thread = THREAD_NULL;
	task_t localtask = TASK_NULL;

	if (tid == self->thread_id) {
		selfset = 1;
		localtask = current_task();
	} else
		localtask = task;

	task_lock(localtask);
	if (selfset != 0)  {
		thread = self;
	} else {
		thread = task_findtid(localtask, tid);
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
		/* if the process is exiting, no action to be done */
		if (thread->task->proc_terminate != 0)
			goto out;

		if (selfset != 0)  {
			/* internal application */
			if (thread->appliedstate.hw_bg != thread->policystate.hw_bg) {
				thread->appliedstate.hw_bg = thread->policystate.hw_bg;
				if (thread->ext_appliedstate.hw_bg == TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE) 
					set = 1;
		
			}
		} else {
			/* external application */
			if (thread->ext_appliedstate.hw_bg != thread->ext_policystate.hw_bg) {
				thread->ext_appliedstate.hw_bg = thread->ext_policystate.hw_bg;
				if (thread->appliedstate.hw_bg == TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE)
					set = 1;
			}
		}
			
		if (set != 0) {
#if CONFIG_EMBEDDED
		if (thread->task->ext_appliedstate.apptype == PROC_POLICY_IOS_APPLE_DAEMON) {
			thread->saved_importance = thread->importance;
		}
#endif /* CONFIG_EMBEDDED */
			/* set thread priority (we did not save previous value) */
			policy.importance = INT_MIN;
				
			thread_policy_set_internal(thread, THREAD_PRECEDENCE_POLICY,
                                                   (thread_policy_t)&policy,
                                                   THREAD_PRECEDENCE_POLICY_COUNT );

		}
	} else
		return(ESRCH);

out:
	return(0);
}

#if CONFIG_EMBEDDED
/* set external application of background */
static void 
apply_bgthreadpolicy_external(thread_t thread)
{
int set = 0;
thread_precedence_policy_data_t policy;

	/* if the process is exiting, no action to be done */
	if (thread->task->proc_terminate != 0)
		return;

	thread->ext_policystate.hw_bg = TASK_POLICY_BACKGROUND_ATTRIBUTE_ALL;

	if (thread->ext_appliedstate.hw_bg != thread->ext_policystate.hw_bg) {
		thread->ext_appliedstate.hw_bg = thread->ext_policystate.hw_bg;
		if (thread->appliedstate.hw_bg == TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE)
			set = 1;
	}

	if (set != 0) {
		/* set thread priority (we did not save previous value) */
		policy.importance = INT_MIN;

		thread_policy_set_internal(thread, THREAD_PRECEDENCE_POLICY,
                                                   (thread_policy_t)&policy,
                                                   THREAD_PRECEDENCE_POLICY_COUNT );
	}

}
#endif /* CONFIG_EMBEDDED */

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
	return(proc_restore_bgtaskpolicy_internal(task, 0, external, BASEPRI_DEFAULT));
}

static int
proc_restore_bgtaskpolicy_internal(task_t task, int locked, int external, int pri)
{
	if (locked == 0)
		task_lock(task);

	/* if the process is exiting, no action to be done */
	if (task->proc_terminate != 0)
		goto out;

	if (external != 0) {
		task->ext_appliedstate.hw_bg = TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE;
		/* self BG in flight? */
		if (task->appliedstate.hw_bg == TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE) {
			task_priority(task, pri, MAXPRI_USER);
#if CONFIG_EMBEDDED
			task->role = TASK_DEFAULT_APPLICATION;
#endif /* CONFIG_EMBEDDED */
		}
	 } else {
		task->appliedstate.hw_bg = TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE;
		/* external BG in flight? */
		if (task->ext_appliedstate.hw_bg == TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE) {
			task_priority(task, pri, MAXPRI_USER);
#if CONFIG_EMBEDDED
			task->role = TASK_DEFAULT_APPLICATION;
#endif /* CONFIG_EMBEDDED */
		}
	}
out:
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
	int importance = 0;

	if (thread != THREAD_NULL) {
		wqtask = thread->task;
		task_lock(wqtask);
		/* remove the background and restore default importance as self(internal) removal */
#if CONFIG_EMBEDDED
		if (thread->task->ext_appliedstate.apptype == PROC_POLICY_IOS_APPLE_DAEMON) {
			/* restore prev set importnace */
			importance = thread->saved_importance;
			thread->saved_importance = 0;
		}
#endif /* CONFIG_EMBEDDED */
		restore_bgthreadpolicy_locked(thread, 1, importance);
		task_unlock(wqtask);
	} else
		error = ESRCH;

	return(error);
}

int 
proc_restore_bgthread_selfpolicy(void)
{
	return(proc_restore_bgthreadpolicy(current_task(), thread_tid(current_thread())));
}

int 
proc_restore_bgthreadpolicy(task_t task, uint64_t tid)
{

	int selfset = 0;
	thread_t self = current_thread();
	thread_t thread = THREAD_NULL;
	int importance = 0;

	if (tid == self->thread_id)
		selfset = 1;

	task_lock(task);
	if (selfset == 0)  {
		thread = task_findtid(task, tid);
	} else {
		thread = self;
	}

	if (thread != NULL) {
#if CONFIG_EMBEDDED
		if (thread->task->ext_appliedstate.apptype == PROC_POLICY_IOS_APPLE_DAEMON) {
			/* restore prev set importnace */
			importance = thread->saved_importance;
			thread->saved_importance = 0;
		}
#endif /* CONFIG_EMBEDDED */
		restore_bgthreadpolicy_locked(thread, selfset, importance);
	}
	task_unlock(task);

	if (thread != NULL)
		return(0);
	else
		return(1);
}

static void
restore_bgthreadpolicy_locked(thread_t thread, int selfset, int importance)
{
	thread_precedence_policy_data_t policy;
	int reset = 0;

	if (thread != NULL) {
		/* if the process is exiting, no action to be done */
		if (thread->task->proc_terminate != 0)
			return;

		if (selfset != 0)  {
			thread->appliedstate.hw_bg = TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE;
			/* external BG in flight? */
			if (thread->ext_appliedstate.hw_bg == TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE)
					reset = 1;
		
		} else {
			thread->ext_appliedstate.hw_bg = TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE;
			/* self BG in flight? */
			if (thread->appliedstate.hw_bg == TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE)
					reset = 1;
		}
			
		if (reset != 0) {
			/* reset thread priority (we did not save previous value) */
			policy.importance = importance;
			thread_policy_set_internal(thread, THREAD_PRECEDENCE_POLICY,
                                                   (thread_policy_t)&policy,
                                                   THREAD_PRECEDENCE_POLICY_COUNT );
		}
	}
}

void 
#if CONFIG_EMBEDDED
proc_set_task_apptype(task_t task, int type, thread_t thread)
#else
proc_set_task_apptype(task_t task, int type, __unused thread_t thread)
#endif
{
#if CONFIG_EMBEDDED
	thread_t th = THREAD_NULL;
#endif /* CONFIG_EMBEDDED */

	switch (type) {
#if CONFIG_EMBEDDED
		case PROC_POLICY_IOS_RESV1_APPTYPE:
			task->ext_policystate.apptype = type;
			task->policystate.apptype = type;
			proc_apply_bgtaskpolicy_external(task);
			/* indicate that BG is set and next foreground needs to reset */
			task->ext_appliedstate.apptype = type;
			break;

		case PROC_POLICY_IOS_APPLE_DAEMON:
			task->ext_policystate.apptype = type;
			task->policystate.apptype = type;
			task->ext_appliedstate.apptype = type;
			/* posix spawn will already have thread created, so backround it */
			if (thread == NULL)
				th = current_thread();
			else
				th = thread;
			if (th->appliedstate.hw_bg != TASK_POLICY_BACKGROUND_ATTRIBUTE_ALL) {
				/* apply self backgrounding if not already set */
				task_lock(th->task);
				proc_apply_bgthreadpolicy_locked(th, 1);
				task_unlock(th->task);
			}
			break;
	
		case PROC_POLICY_IOS_APPTYPE:
			task->ext_policystate.apptype = type;
			task->policystate.apptype = type;
			break;
		case PROC_POLICY_IOS_NONUITYPE:
			task->ext_policystate.apptype = type;
			task->policystate.apptype = type;
			/* set to deny access to gpu */
			task->ext_appliedstate.hw_gpu = TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS;
			task->ext_policystate.hw_gpu = TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS;
			break;
#else /* CONFIG_EMBEDDED */
		case PROC_POLICY_OSX_APPTYPE_TAL:
			task->ext_policystate.apptype = type;
			task->policystate.apptype = type;
			proc_apply_bgtaskpolicy_external(task);
			/* indicate that BG is set and next foreground needs to reset */
			task->ext_appliedstate.apptype = type;
			break;

		case PROC_POLICY_OSX_APPTYPE_DBCLIENT:
			task->ext_policystate.apptype = type;
			task->policystate.apptype = type;
			proc_apply_bgtaskpolicy_internal(task, 0, 0);
			break;
	
#endif /* CONFIG_EMBEDDED */

		default:
			break;
	}
}

/* update the darwin backdground action state in the flags field for libproc */
#define PROC_FLAG_DARWINBG      0x8000  /* process in darwin background */
#define PROC_FLAG_EXT_DARWINBG  0x10000 /* process in darwin background - external enforcement */
#define PROC_FLAG_IOS_APPLEDAEMON  0x20000 /* process is apple ios daemon */

int
proc_get_darwinbgstate(task_t task, uint32_t * flagsp)
{
	if (task->ext_appliedstate.hw_bg == TASK_POLICY_BACKGROUND_ATTRIBUTE_ALL){
		*flagsp |= PROC_FLAG_EXT_DARWINBG;
	}
	if (task->appliedstate.hw_bg == TASK_POLICY_BACKGROUND_ATTRIBUTE_ALL){
		*flagsp |= PROC_FLAG_DARWINBG;
	}
#if CONFIG_EMBEDDED
	if (task->ext_appliedstate.apptype == PROC_POLICY_IOS_APPLE_DAEMON) {
		*flagsp |= PROC_FLAG_IOS_APPLEDAEMON;
	}
#endif /* CONFIG_EMBEDDED */
		
	return(0);
}

/* 
 * HW disk access realted routines, they need to return 
 * IOPOL_XXX equivalents for spec_xxx/throttle updates.
 */

int 
proc_get_task_disacc(task_t task)
{
#if CONFIG_EMBEDDED
	if ((task->ext_appliedstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_DISKTHROTTLE) != 0)
		return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE);
#else /* CONFIG_EMBEDDED */
	if ((task->ext_appliedstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_DISKTHROTTLE) != 0) {
		/* if it is a TAL or DBClient and not self throttled, return Utility */
		if ((task->ext_appliedstate.apptype == PROC_POLICY_OSX_APPTYPE_TAL) || (task->ext_appliedstate.apptype == PROC_POLICY_OSX_APPTYPE_DBCLIENT)) {
			/* any setting for DBG, we need to honor that */
			if ((task->ext_appliedstate.hw_disk != TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE) &&
				((task->appliedstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_DISKTHROTTLE)!= 0) &&
				(task->appliedstate.hw_disk !=  TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE)) {
				return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_UTILITY);
			}  else
				return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE);
		 } else 
			return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE);
	}
#endif /* CONFIG_EMBEDDED */
	if (task->ext_appliedstate.hw_disk != TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_FULLACCESS)
		return(task->ext_appliedstate.hw_disk);
	if ((task->appliedstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_DISKTHROTTLE) != 0)
		return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE);
	if (task->appliedstate.hw_disk != TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_FULLACCESS)
		return(task->appliedstate.hw_disk);
	return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_FULLACCESS);
}

int
proc_get_task_selfdiskacc_internal(task_t task, thread_t thread)
{
	/* if the task is marked for proc_terminate, no throttling for it */
	if (task->proc_terminate != 0)
		goto out;
	/* 
	 * As per defined iopolicysys behavior, thread trumps task. 
	 * Do we need to follow that for external enforcements of BG or hw access?
	 * Status quo for now..
	 */
		
	if((thread->ext_appliedstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_DISKTHROTTLE) != 0)
		return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE);
	if (thread->ext_appliedstate.hw_disk != TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_FULLACCESS)
		return(thread->ext_appliedstate.hw_disk);
	if((thread->appliedstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_DISKTHROTTLE) != 0)
		return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE);
	if (thread->appliedstate.hw_disk != TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_FULLACCESS)
		return(thread->appliedstate.hw_disk);

#if CONFIG_EMBEDDED
	if ((task->ext_appliedstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_DISKTHROTTLE) != 0)
		return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE);
#else /* CONFIG_EMBEDDED */
	if ((task->ext_appliedstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_DISKTHROTTLE) != 0) {
		/* if it is a TAL or DBClient and not self throttled, return Utility */
		if ((task->ext_appliedstate.apptype == PROC_POLICY_OSX_APPTYPE_TAL) || (task->ext_appliedstate.apptype == PROC_POLICY_OSX_APPTYPE_DBCLIENT)) {
			/* any setting for DBG, we need to honor that */
			if ((task->ext_appliedstate.hw_disk != TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE) &&
				((task->appliedstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_DISKTHROTTLE)!= 0) &&
				(task->appliedstate.hw_disk !=  TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE)) {
				return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_UTILITY);
			}  else
				return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE);
		 } else 
			return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE);
	}
#endif /* CONFIG_EMBEDDED */
	if (task->ext_appliedstate.hw_disk != TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_FULLACCESS)
		return(task->ext_appliedstate.hw_disk);
	if ((task->appliedstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_DISKTHROTTLE) != 0)
		return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE);
	if (task->appliedstate.hw_disk != TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_FULLACCESS)
		return(task->appliedstate.hw_disk);
out:
	return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_FULLACCESS);
}


int
proc_get_task_selfdiskacc(void)
{
	return(proc_get_task_selfdiskacc_internal(current_task(), current_thread()));
}


int
proc_get_diskacc(thread_t thread)
{
	return(proc_get_task_selfdiskacc_internal(thread->task, thread));
}


int
proc_get_thread_selfdiskacc(void)
{
	thread_t thread = current_thread();

	if((thread->ext_appliedstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_DISKTHROTTLE) != 0)
		return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE);
	if (thread->ext_appliedstate.hw_disk != TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_FULLACCESS)
		return(thread->ext_appliedstate.hw_disk);
	if((thread->appliedstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_DISKTHROTTLE) != 0)
		return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE);
	if (thread->appliedstate.hw_disk != TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_FULLACCESS)
		return(thread->appliedstate.hw_disk);
	return(TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_FULLACCESS);
}

int 
proc_apply_task_diskacc(task_t task, int policy)
{
	task_t self = current_task();

	task_lock(task);
	if (task ==  self) {
		task->appliedstate.hw_disk = policy;
		task->policystate.hw_disk = policy;
	} else {
		task->ext_appliedstate.hw_disk = policy;
		task->ext_policystate.hw_disk = policy;
	}
	task_unlock(task);
	return(0);
}

int 
proc_apply_thread_diskacc(task_t task, uint64_t tid, int policy)
{
	thread_t thread;

	if (tid == TID_NULL) {
		thread = current_thread();
		proc_apply_thread_selfdiskacc(policy);
	} else {
		task_lock(task);
		thread = task_findtid(task, tid);
		if (thread != NULL) {
			thread->ext_appliedstate.hw_disk = policy;
			thread->ext_policystate.hw_disk = policy;
		}
		task_unlock(task);
	}
	if (thread != NULL)
		return(0);
	else
		return(0);
}

void
proc_task_remove_throttle(task_t task)
{
	thread_t	thread;
	int importance = 0;

	task_lock(task);


	/* remove processwide internal DBG applicationn */
	proc_restore_bgtaskpolicy_internal(task, 1, 0, BASEPRI_DEFAULT);
	/* remove processwide external DBG applicationn */
	proc_restore_bgtaskpolicy_internal(task, 1, 1, BASEPRI_DEFAULT);

	for (thread  = (thread_t)queue_first(&task->threads);
			!queue_end(&task->threads, (queue_entry_t)thread); ) {
#if CONFIG_EMBEDDED
		if (thread->task->ext_appliedstate.apptype == PROC_POLICY_IOS_APPLE_DAEMON) {
			/* restore prev set importnace */
			importance = thread->saved_importance;
			thread->saved_importance = 0;
		}
#endif /* CONFIG_EMBEDDED */
		/* remove thread level internal DBG application */
		restore_bgthreadpolicy_locked(thread, 1, importance);
		/* remove thread level external DBG application */
		restore_bgthreadpolicy_locked(thread, 0, importance);
		/* reset thread io policy */
		thread->ext_appliedstate.hw_disk = TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_FULLACCESS;
		thread->appliedstate.hw_disk = TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_FULLACCESS;
		unthrottle_thread(thread->uthread);
		thread = (thread_t)queue_next(&thread->task_threads);
	}

	/* reset task iopolicy */
	task->ext_appliedstate.hw_disk = TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_FULLACCESS;
	task->appliedstate.hw_disk = TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_FULLACCESS;
	task->proc_terminate = 1;

	task_unlock(task);
}



int
proc_apply_thread_selfdiskacc(int policy)
{
	task_t task = current_task();
	thread_t thread = current_thread();

	task_lock(task);
	thread->appliedstate.hw_disk = policy;
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
#ifdef NOTYET
	thread_t thread = current_thread();
#endif /* NOTYET */

	if (((task->ext_appliedstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_NOGPU) != 0) || (task->ext_appliedstate.hw_gpu == TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS))
		return(TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS);
	if (((task->appliedstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_NOGPU) != 0) || (task->appliedstate.hw_gpu == TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS))
		return(TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS);
#ifdef NOTYET
	/* 
	 * Since background dispatch items run in a thread can also be
	 * denied access, we need to make sure there are no unintended
	 * consequences of background dispatch usage. So till this is 
	 * hashed out, disable thread level checking.
	 */
	if (((thread->ext_appliedstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_NOGPU) != 0) || (thread->ext_appliedstate.hw_gpu == TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS))
		return(TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS);
	if (((thread->appliedstate.hw_bg & TASK_POLICY_BACKGROUND_ATTRIBUTE_NOGPU) != 0) || (thread->appliedstate.hw_gpu == TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS))
		return(TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS);

#endif /* NOTYET */
	return(TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_FULLACCESS);
}

int
proc_apply_task_gpuacc(task_t task, int policy)
{

	task_t self = current_task();

	task_lock(task);
	if (task ==  self) {
		task->appliedstate.hw_gpu = policy;
		task->policystate.hw_gpu = policy;
	} else {
		task->ext_appliedstate.hw_gpu = policy;
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

/*
 * Currently supported configurations for CPU limits.
 *
 * 					Deadline-based CPU limit    	Percentage-based CPU limit
 * PROC_POLICY_RSRCACT_THROTTLE		ENOTSUP				Task-wide scope only
 * PROC_POLICY_RSRCACT_SUSPEND		Task-wide scope only		ENOTSUP
 * PROC_POLICY_RSRCACT_TERMINATE	Task-wide scope only		ENOTSUP
 * PROC_POLICY_RSRCACT_NOTIFY_KQ	Task-wide scope only		ENOTSUP
 * PROC_POLICY_RSRCACT_NOTIFY_EXC	ENOTSUP				Per-thread scope only
 *
 * A deadline-based CPU limit is actually a simple wallclock timer - the requested action is performed
 * after the specified amount of wallclock time has elapsed.
 *
 * A percentage-based CPU limit performs the requested action after the specified amount of actual CPU time
 * has been consumed -- regardless of how much wallclock time has elapsed -- by either the task as an
 * aggregate entity (so-called "Task-wide" or "Proc-wide" scope, whereby the CPU time consumed by all threads
 * in the task are added together), or by any one thread in the task (so-called "per-thread" scope).
 *
 * We support either deadline != 0 OR percentage != 0, but not both. The original intention in having them
 * share an API was to use actual CPU time as the basis of the deadline-based limit (as in: perform an action
 * after I have used some amount of CPU time; this is different than the recurring percentage/interval model)
 * but the potential consumer of the API at the time was insisting on wallclock time instead.
 *
 * Currently, requesting notification via an exception is the only way to get per-thread scope for a
 * CPU limit. All other types of notifications force task-wide scope for the limit.
 */
int 
proc_set_task_ruse_cpu(task_t task, uint32_t policy, uint32_t percentage, uint64_t interval, uint64_t deadline)
{
	int error = 0;
	int scope;

 	/*
 	 * Enforce the matrix of supported configurations for policy, percentage, and deadline.
 	 */
 	switch (policy) {
 	// If no policy is explicitly given, the default is to throttle.
 	case TASK_POLICY_RESOURCE_ATTRIBUTE_NONE:
	case TASK_POLICY_RESOURCE_ATTRIBUTE_THROTTLE:
		if (deadline != 0)
			return (ENOTSUP);
		scope = TASK_RUSECPU_FLAGS_PROC_LIMIT;
		break;
	case TASK_POLICY_RESOURCE_ATTRIBUTE_SUSPEND:
	case TASK_POLICY_RESOURCE_ATTRIBUTE_TERMINATE:
	case TASK_POLICY_RESOURCE_ATTRIBUTE_NOTIFY_KQ:
		if (percentage != 0)
			return (ENOTSUP);
		scope = TASK_RUSECPU_FLAGS_DEADLINE;
		break;
 	case TASK_POLICY_RESOURCE_ATTRIBUTE_NOTIFY_EXC:
		if (deadline != 0)
			return (ENOTSUP);
		scope = TASK_RUSECPU_FLAGS_PERTHR_LIMIT;
		break;
	default:
		return (EINVAL);
	}

	task_lock(task);
	if (task != current_task()) {
		task->ext_policystate.ru_cpu = policy;	
	} else {
		task->policystate.ru_cpu = policy;	
	}
	error = task_set_cpuusage(task, percentage, interval, deadline, scope);
	task_unlock(task);
	return(error);
}

int 
proc_clear_task_ruse_cpu(task_t task)
{
	int error = 0;
	int action;
	void * bsdinfo = NULL;

	task_lock(task);
	if (task != current_task()) {
		task->ext_policystate.ru_cpu = TASK_POLICY_RESOURCE_ATTRIBUTE_DEFAULT;	
	} else {
		task->policystate.ru_cpu = TASK_POLICY_RESOURCE_ATTRIBUTE_DEFAULT;	
	}

	error = task_clear_cpuusage_locked(task);
	if (error != 0)
		goto out;	

	action = task->ext_appliedstate.ru_cpu;
	if (task->ext_appliedstate.ru_cpu != TASK_POLICY_RESOURCE_ATTRIBUTE_NONE) {
		/* reset action */
		task->ext_appliedstate.ru_cpu = TASK_POLICY_RESOURCE_ATTRIBUTE_NONE;
	}
	if (action != TASK_POLICY_RESOURCE_ATTRIBUTE_NONE) {
		bsdinfo = task->bsd_info;
		task_unlock(task);
		proc_restore_resource_actions(bsdinfo, TASK_POLICY_CPU_RESOURCE_USAGE, action);
		goto out1;
	}

out:
	task_unlock(task);
out1:
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
	
	if (task->ext_appliedstate.ru_cpu == TASK_POLICY_RESOURCE_ATTRIBUTE_NONE) {
		/* apply action */
		task->ext_appliedstate.ru_cpu = task->ext_policystate.ru_cpu;
		action = task->ext_appliedstate.ru_cpu;
	} else {
		action = task->ext_appliedstate.ru_cpu;
	}

	if (action != TASK_POLICY_RESOURCE_ATTRIBUTE_NONE) {
		bsdinfo = task->bsd_info;
		task_unlock(task);
		proc_apply_resource_actions(bsdinfo, TASK_POLICY_CPU_RESOURCE_USAGE, action);
	} else
		task_unlock(task);

	return(0);
}

/* For ledger hookups */
static int
task_get_cpuusage(task_t task, uint32_t * percentagep, uint64_t * intervalp, uint64_t * deadlinep)
{
	*percentagep = task->rusage_cpu_percentage;
	*intervalp = task->rusage_cpu_interval;
	*deadlinep = task->rusage_cpu_deadline;

	return(0);
}

int
task_set_cpuusage(task_t task, uint64_t percentage, uint64_t interval, uint64_t deadline, int scope)
{
	uint64_t abstime = 0;
	uint64_t save_abstime = 0;
	uint64_t limittime = 0;
	thread_t thread;

	lck_mtx_assert(&task->lock, LCK_MTX_ASSERT_OWNED);

	/* By default, refill once per second */
	if (interval == 0)
		interval = NSEC_PER_SEC;

	if (percentage != 0) {
		if (percentage > 100)
			percentage = 100;
		limittime = (interval * percentage)/ 100;
		nanoseconds_to_absolutetime(limittime, &abstime);
		if (scope == TASK_RUSECPU_FLAGS_PERTHR_LIMIT) {
			/*
			 * A per-thread CPU limit on a task generates an exception
			 * (LEDGER_ACTION_EXCEPTION) if any one thread in the task
			 * exceeds the limit.
			 */
			task->rusage_cpu_flags |= TASK_RUSECPU_FLAGS_PERTHR_LIMIT;
			task->rusage_cpu_perthr_percentage = percentage;
			task->rusage_cpu_perthr_interval = interval;
			queue_iterate(&task->threads, thread, thread_t, task_threads) {
				set_astledger(thread);
			}
		} else if (scope == TASK_RUSECPU_FLAGS_PROC_LIMIT) {
			/*
			 * Currently, a proc-wide CPU limit always blocks if the limit is
			 * exceeded (LEDGER_ACTION_BLOCK).
			 */
			task->rusage_cpu_flags |= TASK_RUSECPU_FLAGS_PROC_LIMIT;
			task->rusage_cpu_percentage = percentage;
			task->rusage_cpu_interval = interval;

			ledger_set_limit(task->ledger, task_ledgers.cpu_time, abstime);
			ledger_set_period(task->ledger, task_ledgers.cpu_time, interval);
			ledger_set_action(task->ledger, task_ledgers.cpu_time, LEDGER_ACTION_BLOCK);
		}
	}

	if (deadline != 0) {
		assert(scope == TASK_RUSECPU_FLAGS_DEADLINE);

		/* if already in use, cancel and wait for it to cleanout */
		if (task->rusage_cpu_callt != NULL) {
			task_unlock(task);
			thread_call_cancel_wait(task->rusage_cpu_callt);
			task_lock(task);
		}
		if (task->rusage_cpu_callt == NULL) {
			task->rusage_cpu_callt = thread_call_allocate_with_priority(task_action_cpuusage, (thread_call_param_t)task, THREAD_CALL_PRIORITY_KERNEL);
		}
		/* setup callout */
		if (task->rusage_cpu_callt != 0) {
			task->rusage_cpu_flags |= TASK_RUSECPU_FLAGS_DEADLINE;
			task->rusage_cpu_deadline = deadline;

			nanoseconds_to_absolutetime(deadline, &abstime);
			save_abstime = abstime;
			clock_absolutetime_interval_to_deadline(save_abstime, &abstime);
			thread_call_enter_delayed(task->rusage_cpu_callt, abstime);
		}
	}

	return(0);
}

int
task_clear_cpuusage(task_t task)
{
	int retval = 0;

	task_lock(task);
	retval = task_clear_cpuusage_locked(task);
	task_unlock(task);

	return(retval);
}

int
task_clear_cpuusage_locked(task_t task)
{
	thread_call_t savecallt;
	thread_t thread;

	/* cancel percentage handling if set */
	if (task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_PROC_LIMIT) {
		task->rusage_cpu_flags &= ~TASK_RUSECPU_FLAGS_PROC_LIMIT;		
		ledger_set_limit(task->ledger, task_ledgers.cpu_time, LEDGER_LIMIT_INFINITY);
		task->rusage_cpu_percentage = 0;
		task->rusage_cpu_interval = 0;
	}

	if (task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_PERTHR_LIMIT) {
		task->rusage_cpu_flags &= ~TASK_RUSECPU_FLAGS_PERTHR_LIMIT;		
		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			set_astledger(thread);
		}
		task->rusage_cpu_perthr_percentage = 0;
		task->rusage_cpu_perthr_interval = 0;

	}

	/* cancel deadline handling if set */
	if (task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_DEADLINE) {
		task->rusage_cpu_flags &= ~TASK_RUSECPU_FLAGS_DEADLINE;
		if (task->rusage_cpu_callt != 0) {
			savecallt = task->rusage_cpu_callt;
			task->rusage_cpu_callt = NULL;
			task->rusage_cpu_deadline = 0;
			task_unlock(task);
			thread_call_cancel_wait(savecallt);
			thread_call_free(savecallt);
			task_lock(task);
		}
	}
	return(0);
}

/* called by ledger unit to enforce action due to  resource usage criteria being met */
void
task_action_cpuusage(thread_call_param_t param0, __unused thread_call_param_t param1)
{
	task_t task = (task_t)param0;
	(void)task_apply_resource_actions(task, TASK_POLICY_CPU_RESOURCE_USAGE);
	return;
}

#if CONFIG_EMBEDDED
/* return the appstate of a task */
int
proc_lf_getappstate(task_t task)
{
	return(task->appstate);

}


/* set appstate of a task and apply approp actions */
int 
proc_lf_setappstate(task_t task, int state)
{
	int ret = 0, oldstate;
	kern_return_t kret = KERN_SUCCESS;
	int applywatch = 0, setbg = 0, setnetbg = 0;
	int sethib_suspend = 0, sethib_resume=0;

	if (state == TASK_APPSTATE_NONE)
		goto out;

	/* valid states? */
	switch (state) {
		case TASK_APPSTATE_ACTIVE:
		case TASK_APPSTATE_BACKGROUND:
		case TASK_APPSTATE_NONUI:
		case TASK_APPSTATE_INACTIVE:
			break;
		default:
			ret = EINVAL;
			goto out;

	}

	task_lock(task);
	oldstate = task->appstate;
	if (oldstate == state) {
		/* no changes */
		goto out1;
	}

	switch(oldstate) {
		case TASK_APPSTATE_ACTIVE:
			switch(state) {
				case TASK_APPSTATE_BACKGROUND:
					/* moving from active to  app background */
					task->ext_policystate.hw_bg = TASK_POLICY_BACKGROUND_ATTRIBUTE_ALL;
					proc_apply_bgtaskpolicy_internal(task, 1, 1);
					/* watchers need update */
					applywatch = 1;
					setbg = 1;
					/* set network part */
					setnetbg = 1;
					break;

				case TASK_APPSTATE_NONUI:
					/* set no graphics */
					task->ext_policystate.hw_gpu = TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS;
					task->ext_appliedstate.hw_gpu = TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS;
					break;

				case TASK_APPSTATE_INACTIVE:
					/* suspend the process */
					kret = task_pidsuspend_locked(task);
					if (kret != KERN_SUCCESS)
						ret = EINVAL;
					else
						sethib_suspend = 1;
						
					break;
			}
			break;

		case TASK_APPSTATE_BACKGROUND:
			switch(state) {
				/* watchers need update */
				applywatch = 1;
				setbg = 0;
				/* set network part */
				setnetbg = 1;
				case TASK_APPSTATE_ACTIVE:
					/* remove app background */
					ret = proc_restore_bgtaskpolicy_internal(task, 1, 1, BASEPRI_DEFAULT);
					/* going from BG to active */
					break;

				case TASK_APPSTATE_NONUI:
					/* remove app background + no graphics */
					task->ext_policystate.hw_gpu = TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS;
					task->ext_appliedstate.hw_gpu = TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS;
					ret = proc_restore_bgtaskpolicy_internal(task, 1, 1, BASEPRI_DEFAULT);
					break;

				case TASK_APPSTATE_INACTIVE:
					/* suspend and then remove app background */
					kret = task_pidsuspend_locked(task);
					if (kret != KERN_SUCCESS) {
						ret = EINVAL;
					} else {
						ret = proc_restore_bgtaskpolicy_internal(task, 1, 1, BASEPRI_DEFAULT);
						sethib_suspend = 1;
					}
				
					break;

			}
			break;

		case TASK_APPSTATE_NONUI:
			switch(state) {
				case TASK_APPSTATE_ACTIVE:
					/* restore graphics access */
					task->ext_policystate.hw_gpu = TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS;
					task->ext_appliedstate.hw_gpu = TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_DEFAULT;
					break;

				case TASK_APPSTATE_BACKGROUND:
					/* set app background */
					task->ext_policystate.hw_bg = TASK_POLICY_BACKGROUND_ATTRIBUTE_ALL;
			
					ret = proc_apply_bgtaskpolicy_internal(task, 1, 1);
					if (ret == 0) {
						task->ext_policystate.hw_gpu = TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_DEFAULT;
						task->ext_appliedstate.hw_gpu = TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_DEFAULT;
					}
					/* watchers need update */
					applywatch = 1;
					setbg = 1;
					/* set network part */
					setnetbg = 1;
					break;

				case TASK_APPSTATE_INACTIVE:
					/* suspend & restore graphics access */
					kret = task_pidsuspend_locked(task);
					if (kret != KERN_SUCCESS) {
						ret = EINVAL;
					} else {
						ret = proc_restore_bgtaskpolicy_internal(task, 1, 1, BASEPRI_DEFAULT);
						task->ext_policystate.hw_gpu = TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_DEFAULT;
						task->ext_appliedstate.hw_gpu = TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_DEFAULT;
						sethib_suspend = 1;
					}
					break;
			}
			break;

		case TASK_APPSTATE_INACTIVE:
			switch(state) {
				case TASK_APPSTATE_ACTIVE:
					/* resume process */
					/* going from inactive to active */
					break;

				case TASK_APPSTATE_BACKGROUND:
					task->ext_policystate.hw_bg = TASK_POLICY_BACKGROUND_ATTRIBUTE_ALL;
					ret = proc_apply_bgtaskpolicy_internal(task, 1, 1);
					/* put in app background & resume process */
					/* watchers need update */
					applywatch = 1;
					setbg = 1;
					/* set network part */
					setnetbg = 1;
					break;

				case TASK_APPSTATE_NONUI:
					/* remove graphics access and resume */
					task->ext_policystate.hw_gpu = TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS;
					task->ext_appliedstate.hw_gpu = TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS;
					break;
			}
			/* pidresume does drop task lock,so no need to have locked version */
			task_unlock(task);
			kret = task_pidresume(task);
			task_lock(task);
			sethib_resume = 1;
			break;
	}
	/* set the new app state on the task */
	task->appstate = state;
out1:
	task_unlock(task);
	if (setnetbg != 0) {
		/* apply network background */
		if (setbg != 0)
			proc_apply_task_networkbg_internal(task->bsd_info, NULL);
		else
			proc_restore_task_networkbg_internal(task->bsd_info, NULL);
	}
#if CONFIG_MEMORYSTATUS
	if (sethib_suspend != 0)
			memorystatus_on_suspend(proc_pid(task->bsd_info));
	if (sethib_resume != 0)
			memorystatus_on_resume(proc_pid(task->bsd_info));
#endif /* CONFIG_MEMORYSTATUS */
	/* if watchers need update, safe point to do that */
	if (applywatch != 0)
		apply_appstate_watchers(task, setbg);

out:
	return(ret);
}

static void
task_watch_lock(void)
{
	lck_mtx_lock(&task_watch_mtx);
}

static void
task_watch_unlock(void)
{
	lck_mtx_unlock(&task_watch_mtx);
}

static void
add_taskwatch_locked(task_t task, task_watch_t * twp)
{
	queue_enter(&task->task_watchers, twp, task_watch_t *, tw_links);
	task->num_taskwatchers++;

}

static void
remove_taskwatch_locked(task_t task, task_watch_t * twp)
{
	queue_remove(&task->task_watchers, twp, task_watch_t *, tw_links);
	task->num_taskwatchers--;
}


int 
proc_lf_pidbind(task_t curtask, uint64_t tid, task_t target_task, int bind)
{
	thread_t self = current_thread();
	thread_t target_thread = NULL;
	int selfset = 0, ret = 0, setbg = 0;
	task_watch_t *twp = NULL;
	task_t task = TASK_NULL;


	if ((tid == 0) || (tid == self->thread_id)) {
		selfset = 1;
		target_thread = self;
		thread_reference(target_thread);
	} else {
		task_lock(curtask);
		target_thread = task_findtid(curtask, tid);
		if (target_thread != NULL)
			thread_reference(target_thread);
		else {
			ret = ESRCH;
			goto out;
		}
			
		task_unlock(curtask);
	}
	
	if (bind != 0) {
		/* task is still active ? */
		task_lock(target_task);
		if (target_task->active == 0) {
			task_unlock(target_task);
			ret = ESRCH;
			goto out;
		}
		task_unlock(target_task);

		twp = (task_watch_t *)kalloc(sizeof(task_watch_t));
		if (twp == NULL) {
			task_watch_unlock();
			ret = ENOMEM;
			goto out;
		}

		bzero(twp, sizeof(task_watch_t));

		task_watch_lock();

		if (target_thread->taskwatch != NULL){
			/* already bound to another task */
			task_watch_unlock();

			kfree(twp, sizeof(task_watch_t));
			ret = EBUSY;
			goto out;
		}

		task_reference(target_task);

		twp->tw_task = target_task;		/* holds the task reference */
		twp->tw_thread = target_thread;		/* holds the thread reference */
		twp->tw_state = target_task->appstate;
		twp->tw_importance = target_thread->importance;
	
		add_taskwatch_locked(target_task, twp);

		target_thread->taskwatch = twp;

		if (target_task->appstate == TASK_APPSTATE_BACKGROUND)
			setbg = 1;

		task_watch_unlock();

		if (setbg != 0) {
			set_thread_appbg(target_thread, setbg, INT_MIN);
		}

		/* retain the thread reference as it is in twp */
		target_thread = NULL;
	} else {
		/* unbind */		
		task_watch_lock();
		if ((twp = target_thread->taskwatch) != NULL) {
			task = twp->tw_task;
			target_thread->taskwatch = NULL;
			remove_taskwatch_locked(task, twp);

			task_watch_unlock();

			task_deallocate(task);			/* drop task ref in twp */
			set_thread_appbg(target_thread, 0, twp->tw_importance);
			thread_deallocate(target_thread);	/* drop thread ref in twp */
			kfree(twp, sizeof(task_watch_t));
		} else {
			task_watch_unlock();
			ret = 0;		/* return success if it not alredy bound */
			goto out;
		}
	}
out:
	if (target_thread != NULL)
		thread_deallocate(target_thread);	/* drop thread ref acquired in this routine */
	return(ret);
}

static void
set_thread_appbg(thread_t thread, int setbg,int importance)
{
	/* TBD: ensure the proc for network is fine */
	if (setbg == 0) {
		restore_bgthreadpolicy_locked(thread, 0, importance);
		proc_restore_task_networkbg_internal(thread->task->bsd_info, thread);
	 } else {
		apply_bgthreadpolicy_external(thread);
		proc_apply_task_networkbg_internal(thread->task->bsd_info, thread);
	}
}

static void
apply_appstate_watchers(task_t task, int setbg)
{
	int numwatchers = 0, i, j;
	thread_watchlist_t * threadlist;
	task_watch_t * twp;

retry:
	/* if no watchers on the list return */
	if ((numwatchers = task->num_taskwatchers) == 0)
		return;

	threadlist = (thread_watchlist_t *)kalloc(numwatchers*sizeof(thread_watchlist_t));
	if (threadlist == NULL)
		return;

	bzero(threadlist, numwatchers*sizeof(thread_watchlist_t));

	task_watch_lock();
	/*serialize application of app state changes */
	if (task->watchapplying != 0) {
		lck_mtx_sleep(&task_watch_mtx, LCK_SLEEP_DEFAULT, &task->watchapplying, THREAD_UNINT);
		task_watch_unlock();
		kfree(threadlist, numwatchers*sizeof(thread_watchlist_t));
		goto retry;
	}

	if (numwatchers != task->num_taskwatchers) {
		task_watch_unlock();
		kfree(threadlist, numwatchers*sizeof(thread_watchlist_t));
		goto retry;
	}
	
	task->watchapplying = 1;
	i = 0;
	queue_iterate(&task->task_watchers, twp, task_watch_t *, tw_links) {

		threadlist[i].thread = twp->tw_thread;
		thread_reference(threadlist[i].thread);
		if (setbg != 0) {
			twp->tw_importance = twp->tw_thread->importance;
			threadlist[i].importance = INT_MIN;
		} else
			threadlist[i].importance = twp->tw_importance;
		i++;
		if (i > numwatchers)
			break;
	}
	task_watch_unlock();

	for (j = 0; j< i; j++) {
		set_thread_appbg(threadlist[j].thread, setbg, threadlist[j].importance);
		thread_deallocate(threadlist[j].thread);
	}
	kfree(threadlist, numwatchers*sizeof(thread_watchlist_t));


	task_watch_lock();
	task->watchapplying = 0;
	thread_wakeup_one(&task->watchapplying);
	task_watch_unlock();
}

void
thead_remove_taskwatch(thread_t thread)
{
	task_watch_t * twp;
	int importance = 0;

	task_watch_lock();
	if ((twp = thread->taskwatch) != NULL) {
		thread->taskwatch = NULL;
		remove_taskwatch_locked(twp->tw_task, twp);
	}
	task_watch_unlock();
	if (twp != NULL) {
		thread_deallocate(twp->tw_thread);
		task_deallocate(twp->tw_task);
		importance = twp->tw_importance;
		kfree(twp, sizeof(task_watch_t));
		/* remove the thread and networkbg */
		set_thread_appbg(thread, 0, importance);
	}
}

void
task_removewatchers(task_t task)
{
	int numwatchers = 0, i, j;
	task_watch_t ** twplist = NULL;
	task_watch_t * twp = NULL;

retry:
	if ((numwatchers = task->num_taskwatchers) == 0)
		return;

	twplist = (task_watch_t **)kalloc(numwatchers*sizeof(task_watch_t *));
	if (twplist == NULL)
		return;

	bzero(twplist, numwatchers*sizeof(task_watch_t *));

	task_watch_lock();
	if (task->num_taskwatchers == 0) {
		task_watch_unlock();
		goto out;
	}

	if (numwatchers != task->num_taskwatchers) {
		task_watch_unlock();
		kfree(twplist, numwatchers*sizeof(task_watch_t *));
		numwatchers = 0;
		goto retry;
	}
	
	i = 0;
	while((twp = (task_watch_t *)dequeue_head(&task->task_watchers)) != NULL)
	{
		twplist[i] = twp;
		task->num_taskwatchers--;	

		/* 
		 * Since the linkage is removed and thead state cleanup is already set up,
		 * remove the refernce from the thread.
		 */
		twp->tw_thread->taskwatch = NULL;	/* removed linkage, clear thread holding ref */
		i++;
		if ((task->num_taskwatchers == 0) || (i > numwatchers))
			break;
	}

	task_watch_unlock();

	for (j = 0; j< i; j++) {
		
		twp = twplist[j];
		/* remove thread and network bg */
		set_thread_appbg(twp->tw_thread, 0, twp->tw_importance);
		thread_deallocate(twp->tw_thread);
		task_deallocate(twp->tw_task);
		kfree(twp, sizeof(task_watch_t));
	}

out:
	kfree(twplist, numwatchers*sizeof(task_watch_t *));

}
#endif /* CONFIG_EMBEDDED */


int 
proc_disable_task_apptype(task_t task, int policy_subtype)
{
	void * bsdinfo = NULL;
	int ret = 0;
	int setbg = 0;
#if !CONFIG_EMBEDDED
	int maxpri = BASEPRI_DEFAULT;
#endif /* !CONFIG_EMBEDDED */

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


#endif /* !CONFIG_EMBEDDED */

	/* TAL apps are cleared with BG handling on first foreground application */
	if (task->ext_appliedstate.apptype != PROC_POLICY_OSX_APPTYPE_NONE) {
			switch (task->ext_appliedstate.apptype) {
#if !CONFIG_EMBEDDED
				case PROC_POLICY_OSX_APPTYPE_TAL:
					/* disable foreground/background handling */
					task->ext_appliedstate.apptype = PROC_POLICY_OSX_APPTYPE_NONE;
					/* external BG application removal */
					proc_restore_bgtaskpolicy_internal(task, 1, 1, maxpri);
					bsdinfo = task->bsd_info;
					setbg = 0;
					break;

				case PROC_POLICY_OSX_APPTYPE_DBCLIENT:
					/* disable foreground/background handling */
					task->ext_appliedstate.apptype = PROC_POLICY_OSX_APPTYPE_NONE;
					/* internal BG application removal */
					proc_restore_bgtaskpolicy_internal(task, 1, 0, maxpri);
					bsdinfo = task->bsd_info;
					setbg = 0;
					break;

#endif /* !CONFIG_EMBEDDED */
				default:
					ret = EINVAL;
					break;
			}

	} else {
		ret = EINVAL;
	}

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

	if (task->ext_appliedstate.apptype == PROC_POLICY_OSX_APPTYPE_NONE) {
		switch (task->ext_policystate.apptype) {
#if !CONFIG_EMBEDDED
			case PROC_POLICY_OSX_APPTYPE_TAL:
			 	 /* TAL policy is activated again */
				task->ext_appliedstate.apptype = task->ext_policystate.apptype;
				if (task->role == TASK_BACKGROUND_APPLICATION) {
					if (task->role == TASK_BACKGROUND_APPLICATION) {
						proc_apply_bgtaskpolicy_internal(task, 1, 1);
						bsdinfo = task->bsd_info;
						setbg = 1;
					}
				}
				ret = 0;
				break;
#endif /* !CONFIG_EMBEDDED */
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

#if CONFIG_EMBEDDED
int
proc_setthread_saved_importance(thread_t thread, int importance)
{
	if ((thread->task->ext_appliedstate.apptype == PROC_POLICY_IOS_APPLE_DAEMON)  &&
		(thread->appliedstate.hw_bg == TASK_POLICY_BACKGROUND_ATTRIBUTE_ALL))
	{
		/* the thread is still backgrounded , save the importance for restore time */
		thread->saved_importance = importance;

		return(1);
	} else
		return(0);
}
#endif /* CONFIG_EMBEDDED */

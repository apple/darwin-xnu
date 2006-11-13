/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 * @OSF_FREE_COPYRIGHT@
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
 *	File:	kern/thread.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young, David Golub
 *	Date:	1986
 *
 *	Thread management primitives implementation.
 */
/*
 * Copyright (c) 1993 The University of Utah and
 * the Computer Systems Laboratory (CSL).  All rights reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * THE UNIVERSITY OF UTAH AND CSL ALLOW FREE USE OF THIS SOFTWARE IN ITS "AS
 * IS" CONDITION.  THE UNIVERSITY OF UTAH AND CSL DISCLAIM ANY LIABILITY OF
 * ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * CSL requests users of this software to return to csl-dist@cs.utah.edu any
 * improvements that they make and grant CSL redistribution rights.
 *
 */

#include <mach_host.h>
#include <mach_prof.h>

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/policy.h>
#include <mach/thread_info.h>
#include <mach/thread_special_ports.h>
#include <mach/thread_status.h>
#include <mach/time_value.h>
#include <mach/vm_param.h>

#include <machine/thread.h>

#include <kern/kern_types.h>
#include <kern/kalloc.h>
#include <kern/cpu_data.h>
#include <kern/counters.h>
#include <kern/ipc_mig.h>
#include <kern/ipc_tt.h>
#include <kern/mach_param.h>
#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/processor.h>
#include <kern/queue.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/sync_lock.h>
#include <kern/syscall_subr.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/host.h>
#include <kern/zalloc.h>
#include <kern/profile.h>
#include <kern/assert.h>

#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_port.h>

#include <vm/vm_kern.h>
#include <vm/vm_pageout.h>

#include <sys/kdebug.h>

/*
 * Exported interfaces
 */
#include <mach/task_server.h>
#include <mach/thread_act_server.h>
#include <mach/mach_host_server.h>
#include <mach/host_priv_server.h>

static struct zone			*thread_zone;

decl_simple_lock_data(static,thread_stack_lock)
static queue_head_t		thread_stack_queue;

decl_simple_lock_data(static,thread_terminate_lock)
static queue_head_t		thread_terminate_queue;

static struct thread	thread_template, init_thread;

#ifdef MACH_BSD
extern void proc_exit(void *);
#endif /* MACH_BSD */

void
thread_bootstrap(void)
{
	/*
	 *	Fill in a template thread for fast initialization.
	 */

	thread_template.runq = RUN_QUEUE_NULL;

	thread_template.ref_count = 2;

	thread_template.reason = AST_NONE;
	thread_template.at_safe_point = FALSE;
	thread_template.wait_event = NO_EVENT64;
	thread_template.wait_queue = WAIT_QUEUE_NULL;
	thread_template.wait_result = THREAD_WAITING;
	thread_template.options = THREAD_ABORTSAFE;
	thread_template.state = TH_WAIT | TH_UNINT;
	thread_template.wake_active = FALSE;
	thread_template.continuation = THREAD_CONTINUE_NULL;
	thread_template.parameter = NULL;

	thread_template.importance = 0;
	thread_template.sched_mode = 0;
	thread_template.safe_mode = 0;
	thread_template.safe_release = 0;

	thread_template.priority = 0;
	thread_template.sched_pri = 0;
	thread_template.max_priority = 0;
	thread_template.task_priority = 0;
	thread_template.promotions = 0;
	thread_template.pending_promoter_index = 0;
	thread_template.pending_promoter[0] =
		thread_template.pending_promoter[1] = NULL;

	thread_template.realtime.deadline = UINT64_MAX;

	thread_template.current_quantum = 0;

	thread_template.computation_metered = 0;
	thread_template.computation_epoch = 0;

	thread_template.sched_stamp = 0;
	thread_template.sched_usage = 0;
	thread_template.pri_shift = INT8_MAX;
	thread_template.cpu_usage = thread_template.cpu_delta = 0;

	thread_template.bound_processor = PROCESSOR_NULL;
	thread_template.last_processor = PROCESSOR_NULL;
	thread_template.last_switch = 0;

	timer_init(&thread_template.user_timer);
	timer_init(&thread_template.system_timer);
	thread_template.user_timer_save = 0;
	thread_template.system_timer_save = 0;

	thread_template.wait_timer_is_set = FALSE;
	thread_template.wait_timer_active = 0;

	thread_template.depress_timer_active = 0;

	thread_template.processor_set = PROCESSOR_SET_NULL;

	thread_template.special_handler.handler = special_handler;
	thread_template.special_handler.next = 0;

#if	MACH_HOST
	thread_template.may_assign = TRUE;
	thread_template.assign_active = FALSE;
#endif	/* MACH_HOST */
	thread_template.funnel_lock = THR_FUNNEL_NULL;
	thread_template.funnel_state = 0;
	thread_template.recover = (vm_offset_t)NULL;

	init_thread = thread_template;
	machine_set_current_thread(&init_thread);
}

void
thread_init(void)
{
	thread_zone = zinit(
			sizeof(struct thread),
			THREAD_MAX * sizeof(struct thread),
			THREAD_CHUNK * sizeof(struct thread),
			"threads");

	stack_init();

	/*
	 *	Initialize any machine-dependent
	 *	per-thread structures necessary.
	 */
	machine_thread_init();
}

static void
thread_terminate_continue(void)
{
	panic("thread_terminate_continue");
	/*NOTREACHED*/
}

/*
 *	thread_terminate_self:
 */
void
thread_terminate_self(void)
{
	thread_t		thread = current_thread();
	task_t			task;
	spl_t			s;

	s = splsched();
	thread_lock(thread);

	/*
	 *	Cancel priority depression, reset scheduling parameters,
	 *	and wait for concurrent expirations on other processors.
	 */
	if (thread->sched_mode & TH_MODE_ISDEPRESSED) {
		thread->sched_mode &= ~TH_MODE_ISDEPRESSED;

		if (timer_call_cancel(&thread->depress_timer))
			thread->depress_timer_active--;
	}

	thread_policy_reset(thread);

	while (thread->depress_timer_active > 0) {
		thread_unlock(thread);
		splx(s);

		delay(1);

		s = splsched();
		thread_lock(thread);
	}

	thread_unlock(thread);
	splx(s);

	thread_mtx_lock(thread);

	ulock_release_all(thread);

	ipc_thread_disable(thread);
	
	thread_mtx_unlock(thread);

	/*
	 * If we are the last thread to terminate and the task is
	 * associated with a BSD process, perform BSD process exit.
	 */
	task = thread->task;
	if (	hw_atomic_sub(&task->active_thread_count, 1) == 0	&&
					task->bsd_info != NULL						)
		proc_exit(task->bsd_info);

	s = splsched();
	thread_lock(thread);

	/*
	 *	Cancel wait timer, and wait for
	 *	concurrent expirations.
	 */
	if (thread->wait_timer_is_set) {
		thread->wait_timer_is_set = FALSE;

		if (timer_call_cancel(&thread->wait_timer))
			thread->wait_timer_active--;
	}

	while (thread->wait_timer_active > 0) {
		thread_unlock(thread);
		splx(s);

		delay(1);

		s = splsched();
		thread_lock(thread);
	}

	/*
	 *	If there is a reserved stack, release it.
	 */
	if (thread->reserved_stack != 0) {
		if (thread->reserved_stack != thread->kernel_stack)
			stack_free_stack(thread->reserved_stack);
		thread->reserved_stack = 0;
	}

	/*
	 *	Mark thread as terminating, and block.
	 */
	thread->state |= TH_TERMINATE;
	thread_mark_wait_locked(thread, THREAD_UNINT);
	assert(thread->promotions == 0);
	thread_unlock(thread);
	/* splsched */

	thread_block((thread_continue_t)thread_terminate_continue);
	/*NOTREACHED*/
}

void
thread_deallocate(
	thread_t			thread)
{
	processor_set_t		pset;
	task_t				task;

	if (thread == THREAD_NULL)
		return;

	if (thread_deallocate_internal(thread) > 0)
		return;

	ipc_thread_terminate(thread);

	task = thread->task;

#ifdef MACH_BSD 
	{
		void *ut = thread->uthread;

		thread->uthread = NULL;
		uthread_free(task, ut, task->bsd_info);
	}
#endif  /* MACH_BSD */   

	task_deallocate(task);

	pset = thread->processor_set;
	pset_deallocate(pset);

	if (thread->kernel_stack != 0)
		stack_free(thread);

	machine_thread_destroy(thread);

	zfree(thread_zone, thread);
}

/*
 *	thread_terminate_daemon:
 *
 *	Perform final clean up for terminating threads.
 */
static void
thread_terminate_daemon(void)
{
	thread_t			thread;
	task_t				task;
	processor_set_t		pset;

	(void)splsched();
	simple_lock(&thread_terminate_lock);

	while ((thread = (thread_t)dequeue_head(&thread_terminate_queue)) != THREAD_NULL) {
		simple_unlock(&thread_terminate_lock);
		(void)spllo();

		task = thread->task;

		task_lock(task);
		task->total_user_time += timer_grab(&thread->user_timer);
		task->total_system_time += timer_grab(&thread->system_timer);

		queue_remove(&task->threads, thread, thread_t, task_threads);
		task->thread_count--;
		task_unlock(task);

		pset = thread->processor_set;

		pset_lock(pset);
		pset_remove_thread(pset, thread);
		pset_unlock(pset);

		thread_deallocate(thread);

		(void)splsched();
		simple_lock(&thread_terminate_lock);
	}

	assert_wait((event_t)&thread_terminate_queue, THREAD_UNINT);
	simple_unlock(&thread_terminate_lock);
	/* splsched */

	thread_block((thread_continue_t)thread_terminate_daemon);
	/*NOTREACHED*/
}

/*
 *	thread_terminate_enqueue:
 *
 *	Enqueue a terminating thread for final disposition.
 *
 *	Called at splsched.
 */
void
thread_terminate_enqueue(
	thread_t		thread)
{
	simple_lock(&thread_terminate_lock);
	enqueue_tail(&thread_terminate_queue, (queue_entry_t)thread);
	simple_unlock(&thread_terminate_lock);

	thread_wakeup((event_t)&thread_terminate_queue);
}

/*
 *	thread_stack_daemon:
 *
 *	Perform stack allocation as required due to
 *	invoke failures.
 */
static void
thread_stack_daemon(void)
{
	thread_t		thread;

	(void)splsched();
	simple_lock(&thread_stack_lock);

	while ((thread = (thread_t)dequeue_head(&thread_stack_queue)) != THREAD_NULL) {
		simple_unlock(&thread_stack_lock);
		/* splsched */

		stack_alloc(thread);

		thread_lock(thread);
		thread_setrun(thread, SCHED_PREEMPT | SCHED_TAILQ);
		thread_unlock(thread);
		(void)spllo();

		(void)splsched();
		simple_lock(&thread_stack_lock);
	}

	assert_wait((event_t)&thread_stack_queue, THREAD_UNINT);
	simple_unlock(&thread_stack_lock);
	/* splsched */

	thread_block((thread_continue_t)thread_stack_daemon);
	/*NOTREACHED*/
}

/*
 *	thread_stack_enqueue:
 *
 *	Enqueue a thread for stack allocation.
 *
 *	Called at splsched.
 */
void
thread_stack_enqueue(
	thread_t		thread)
{
	simple_lock(&thread_stack_lock);
	enqueue_tail(&thread_stack_queue, (queue_entry_t)thread);
	simple_unlock(&thread_stack_lock);

	thread_wakeup((event_t)&thread_stack_queue);
}

void
thread_daemon_init(void)
{
	kern_return_t	result;
	thread_t		thread;

	simple_lock_init(&thread_terminate_lock, 0);
	queue_init(&thread_terminate_queue);

	result = kernel_thread_start_priority((thread_continue_t)thread_terminate_daemon, NULL, MINPRI_KERNEL, &thread);
	if (result != KERN_SUCCESS)
		panic("thread_daemon_init: thread_terminate_daemon");

	thread_deallocate(thread);

	simple_lock_init(&thread_stack_lock, 0);
	queue_init(&thread_stack_queue);

	result = kernel_thread_start_priority((thread_continue_t)thread_stack_daemon, NULL, BASEPRI_PREEMPT, &thread);
	if (result != KERN_SUCCESS)
		panic("thread_daemon_init: thread_stack_daemon");

	thread_deallocate(thread);
}

/*
 * Create a new thread.
 * Doesn't start the thread running.
 */
static kern_return_t
thread_create_internal(
	task_t					parent_task,
	integer_t				priority,
	thread_continue_t		continuation,
	thread_t				*out_thread)
{
	thread_t				new_thread;
	processor_set_t			pset;
	static thread_t			first_thread;

	/*
	 *	Allocate a thread and initialize static fields
	 */
	if (first_thread == NULL)
		new_thread = first_thread = current_thread();
	else
		new_thread = (thread_t)zalloc(thread_zone);
	if (new_thread == NULL)
		return (KERN_RESOURCE_SHORTAGE);

	if (new_thread != first_thread)
		*new_thread = thread_template;

#ifdef MACH_BSD
    {
		new_thread->uthread = uthread_alloc(parent_task, new_thread);
		if (new_thread->uthread == NULL) {
			zfree(thread_zone, new_thread);
			return (KERN_RESOURCE_SHORTAGE);
		}
	}
#endif  /* MACH_BSD */

	if (machine_thread_create(new_thread, parent_task) != KERN_SUCCESS) {
#ifdef MACH_BSD
		{
			void *ut = new_thread->uthread;

			new_thread->uthread = NULL;
			uthread_free(parent_task, ut, parent_task->bsd_info);
		}
#endif  /* MACH_BSD */
		zfree(thread_zone, new_thread);
		return (KERN_FAILURE);
	}

    new_thread->task = parent_task;

	thread_lock_init(new_thread);
	wake_lock_init(new_thread);

	mutex_init(&new_thread->mutex, 0);

	ipc_thread_init(new_thread);
	queue_init(&new_thread->held_ulocks);
	thread_prof_init(new_thread, parent_task);

	new_thread->continuation = continuation;

	pset = parent_task->processor_set;
	assert(pset == &default_pset);
	pset_lock(pset);

	task_lock(parent_task);
	assert(parent_task->processor_set == pset);

	if (	!parent_task->active							||
			(parent_task->thread_count >= THREAD_MAX	&&
			 parent_task != kernel_task)) {
		task_unlock(parent_task);
		pset_unlock(pset);

#ifdef MACH_BSD
		{
			void *ut = new_thread->uthread;

			new_thread->uthread = NULL;
			uthread_free(parent_task, ut, parent_task->bsd_info);
		}
#endif  /* MACH_BSD */
		ipc_thread_disable(new_thread);
		ipc_thread_terminate(new_thread);
		machine_thread_destroy(new_thread);
		zfree(thread_zone, new_thread);
		return (KERN_FAILURE);
	}

	task_reference_internal(parent_task);

	/* Cache the task's map */
	new_thread->map = parent_task->map;

	/* Chain the thread onto the task's list */
	queue_enter(&parent_task->threads, new_thread, thread_t, task_threads);
	parent_task->thread_count++;
	
	/* So terminating threads don't need to take the task lock to decrement */
	hw_atomic_add(&parent_task->active_thread_count, 1);

	/* Associate the thread with the processor set */
	pset_add_thread(pset, new_thread);

	timer_call_setup(&new_thread->wait_timer, thread_timer_expire, new_thread);
	timer_call_setup(&new_thread->depress_timer, thread_depress_expire, new_thread);

	/* Set the thread's scheduling parameters */
	if (parent_task != kernel_task)
		new_thread->sched_mode |= TH_MODE_TIMESHARE;
	new_thread->max_priority = parent_task->max_priority;
	new_thread->task_priority = parent_task->priority;
	new_thread->priority = (priority < 0)? parent_task->priority: priority;
	if (new_thread->priority > new_thread->max_priority)
		new_thread->priority = new_thread->max_priority;
	new_thread->importance =
					new_thread->priority - new_thread->task_priority;
	new_thread->sched_stamp = sched_tick;
	new_thread->pri_shift = new_thread->processor_set->pri_shift;
	compute_priority(new_thread, FALSE);

	new_thread->active = TRUE;

	*out_thread = new_thread;

	{
		long	dbg_arg1, dbg_arg2, dbg_arg3, dbg_arg4;

		kdbg_trace_data(parent_task->bsd_info, &dbg_arg2);

		KERNEL_DEBUG_CONSTANT(
					TRACEDBG_CODE(DBG_TRACE_DATA, 1) | DBG_FUNC_NONE,
							(vm_address_t)new_thread, dbg_arg2, 0, 0, 0);

		kdbg_trace_string(parent_task->bsd_info,
							&dbg_arg1, &dbg_arg2, &dbg_arg3, &dbg_arg4);

		KERNEL_DEBUG_CONSTANT(
					TRACEDBG_CODE(DBG_TRACE_STRING, 1) | DBG_FUNC_NONE,
							dbg_arg1, dbg_arg2, dbg_arg3, dbg_arg4, 0);
	}

	return (KERN_SUCCESS);
}

kern_return_t
thread_create(
	task_t				task,
	thread_t			*new_thread)
{
	kern_return_t		result;
	thread_t			thread;

	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	result = thread_create_internal(task, -1, (thread_continue_t)thread_bootstrap_return, &thread);
	if (result != KERN_SUCCESS)
		return (result);

	thread->user_stop_count = 1;
	thread_hold(thread);
	if (task->suspend_count > 0)
		thread_hold(thread);

	pset_unlock(task->processor_set);
	task_unlock(task);
	
	*new_thread = thread;

	return (KERN_SUCCESS);
}

kern_return_t
thread_create_running(
	register task_t         task,
	int                     flavor,
	thread_state_t          new_state,
	mach_msg_type_number_t  new_state_count,
	thread_t				*new_thread)
{
	register kern_return_t  result;
	thread_t				thread;

	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	result = thread_create_internal(task, -1, (thread_continue_t)thread_bootstrap_return, &thread);
	if (result != KERN_SUCCESS)
		return (result);

	result = machine_thread_set_state(
						thread, flavor, new_state, new_state_count);
	if (result != KERN_SUCCESS) {
		pset_unlock(task->processor_set);
		task_unlock(task);

		thread_terminate(thread);
		thread_deallocate(thread);
		return (result);
	}

	thread_mtx_lock(thread);
	clear_wait(thread, THREAD_AWAKENED);
	thread->started = TRUE;
	thread_mtx_unlock(thread);
	pset_unlock(task->processor_set);
	task_unlock(task);

	*new_thread = thread;

	return (result);
}

/*
 *	kernel_thread_create:
 *
 *	Create a thread in the kernel task
 *	to execute in kernel context.
 */
kern_return_t
kernel_thread_create(
	thread_continue_t	continuation,
	void				*parameter,
	integer_t			priority,
	thread_t			*new_thread)
{
	kern_return_t		result;
	thread_t			thread;
	task_t				task = kernel_task;

	result = thread_create_internal(task, priority, continuation, &thread);
	if (result != KERN_SUCCESS)
		return (result);

	pset_unlock(task->processor_set);
	task_unlock(task);

	stack_alloc(thread);
	assert(thread->kernel_stack != 0);
	thread->reserved_stack = thread->kernel_stack;

	thread->parameter = parameter;

	*new_thread = thread;

	return (result);
}

kern_return_t
kernel_thread_start_priority(
	thread_continue_t	continuation,
	void				*parameter,
	integer_t			priority,
	thread_t			*new_thread)
{
	kern_return_t	result;
	thread_t		thread;

	result = kernel_thread_create(continuation, parameter, priority, &thread);
	if (result != KERN_SUCCESS)
		return (result);

	thread_mtx_lock(thread);
	clear_wait(thread, THREAD_AWAKENED);
	thread->started = TRUE;
	thread_mtx_unlock(thread);

	*new_thread = thread;

	return (result);
}

kern_return_t
kernel_thread_start(
	thread_continue_t	continuation,
	void				*parameter,
	thread_t			*new_thread)
{
	return kernel_thread_start_priority(continuation, parameter, -1, new_thread);
}

thread_t
kernel_thread(
	task_t			task,
	void			(*start)(void))
{
	kern_return_t	result;
	thread_t		thread;

	if (task != kernel_task)
		panic("kernel_thread");

	result = kernel_thread_start_priority((thread_continue_t)start, NULL, -1, &thread);
	if (result != KERN_SUCCESS)
		return (THREAD_NULL);

	thread_deallocate(thread);

	return (thread);
}

kern_return_t
thread_info_internal(
	register thread_t		thread,
	thread_flavor_t			flavor,
	thread_info_t			thread_info_out,	/* ptr to OUT array */
	mach_msg_type_number_t	*thread_info_count)	/*IN/OUT*/
{
	int						state, flags;
	spl_t					s;

	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	if (flavor == THREAD_BASIC_INFO) {
	    register thread_basic_info_t	basic_info;

	    if (*thread_info_count < THREAD_BASIC_INFO_COUNT)
			return (KERN_INVALID_ARGUMENT);

	    basic_info = (thread_basic_info_t) thread_info_out;

	    s = splsched();
	    thread_lock(thread);

	    /* fill in info */

	    thread_read_times(thread, &basic_info->user_time,
									&basic_info->system_time);

		/*
		 *	Update lazy-evaluated scheduler info because someone wants it.
		 */
		if (thread->sched_stamp != sched_tick)
			update_priority(thread);

		basic_info->sleep_time = 0;

		/*
		 *	To calculate cpu_usage, first correct for timer rate,
		 *	then for 5/8 ageing.  The correction factor [3/5] is
		 *	(1/(5/8) - 1).
		 */
		basic_info->cpu_usage =	((uint64_t)thread->cpu_usage
									* TH_USAGE_SCALE) /	sched_tick_interval;
		basic_info->cpu_usage = (basic_info->cpu_usage * 3) / 5;

		if (basic_info->cpu_usage > TH_USAGE_SCALE)
			basic_info->cpu_usage = TH_USAGE_SCALE;

		basic_info->policy = ((thread->sched_mode & TH_MODE_TIMESHARE)?
												POLICY_TIMESHARE: POLICY_RR);

	    flags = 0;
		if (thread->state & TH_IDLE)
			flags |= TH_FLAGS_IDLE;

	    if (!thread->kernel_stack)
			flags |= TH_FLAGS_SWAPPED;

	    state = 0;
	    if (thread->state & TH_TERMINATE)
			state = TH_STATE_HALTED;
	    else
		if (thread->state & TH_RUN)
			state = TH_STATE_RUNNING;
	    else
		if (thread->state & TH_UNINT)
			state = TH_STATE_UNINTERRUPTIBLE;
	    else
		if (thread->state & TH_SUSP)
			state = TH_STATE_STOPPED;
	    else
		if (thread->state & TH_WAIT)
			state = TH_STATE_WAITING;

	    basic_info->run_state = state;
	    basic_info->flags = flags;

	    basic_info->suspend_count = thread->user_stop_count;

	    thread_unlock(thread);
	    splx(s);

	    *thread_info_count = THREAD_BASIC_INFO_COUNT;

	    return (KERN_SUCCESS);
	}
	else
	if (flavor == THREAD_SCHED_TIMESHARE_INFO) {
		policy_timeshare_info_t		ts_info;

		if (*thread_info_count < POLICY_TIMESHARE_INFO_COUNT)
			return (KERN_INVALID_ARGUMENT);

		ts_info = (policy_timeshare_info_t)thread_info_out;

	    s = splsched();
		thread_lock(thread);

	    if (!(thread->sched_mode & TH_MODE_TIMESHARE)) {
	    	thread_unlock(thread);
			splx(s);

			return (KERN_INVALID_POLICY);
	    }

		ts_info->depressed = (thread->sched_mode & TH_MODE_ISDEPRESSED) != 0;
		if (ts_info->depressed) {
			ts_info->base_priority = DEPRESSPRI;
			ts_info->depress_priority = thread->priority;
		}
		else {
			ts_info->base_priority = thread->priority;
			ts_info->depress_priority = -1;
		}

		ts_info->cur_priority = thread->sched_pri;
		ts_info->max_priority =	thread->max_priority;

		thread_unlock(thread);
	    splx(s);

		*thread_info_count = POLICY_TIMESHARE_INFO_COUNT;

		return (KERN_SUCCESS);	
	}
	else
	if (flavor == THREAD_SCHED_FIFO_INFO) {
		if (*thread_info_count < POLICY_FIFO_INFO_COUNT)
			return (KERN_INVALID_ARGUMENT);

		return (KERN_INVALID_POLICY);
	}
	else
	if (flavor == THREAD_SCHED_RR_INFO) {
		policy_rr_info_t			rr_info;

		if (*thread_info_count < POLICY_RR_INFO_COUNT)
			return (KERN_INVALID_ARGUMENT);

		rr_info = (policy_rr_info_t) thread_info_out;

	    s = splsched();
		thread_lock(thread);

	    if (thread->sched_mode & TH_MODE_TIMESHARE) {
	    	thread_unlock(thread);
			splx(s);

			return (KERN_INVALID_POLICY);
	    }

		rr_info->depressed = (thread->sched_mode & TH_MODE_ISDEPRESSED) != 0;
		if (rr_info->depressed) {
			rr_info->base_priority = DEPRESSPRI;
			rr_info->depress_priority = thread->priority;
		}
		else {
			rr_info->base_priority = thread->priority;
			rr_info->depress_priority = -1;
		}

		rr_info->max_priority = thread->max_priority;
	    rr_info->quantum = std_quantum_us / 1000;

		thread_unlock(thread);
	    splx(s);

		*thread_info_count = POLICY_RR_INFO_COUNT;

		return (KERN_SUCCESS);	
	}

	return (KERN_INVALID_ARGUMENT);
}

void
thread_read_times(
	thread_t		thread,
	time_value_t	*user_time,
	time_value_t	*system_time)
{
	absolutetime_to_microtime(
			timer_grab(&thread->user_timer),
							&user_time->seconds, &user_time->microseconds);

	absolutetime_to_microtime(
			timer_grab(&thread->system_timer),
							&system_time->seconds, &system_time->microseconds);
}

kern_return_t
thread_assign(
	__unused thread_t			thread,
	__unused processor_set_t	new_pset)
{
	return (KERN_FAILURE);
}

/*
 *	thread_assign_default:
 *
 *	Special version of thread_assign for assigning threads to default
 *	processor set.
 */
kern_return_t
thread_assign_default(
	thread_t		thread)
{
	return (thread_assign(thread, &default_pset));
}

/*
 *	thread_get_assignment
 *
 *	Return current assignment for this thread.
 */	    
kern_return_t
thread_get_assignment(
	thread_t		thread,
	processor_set_t	*pset)
{
	if (thread == NULL)
		return (KERN_INVALID_ARGUMENT);

	*pset = thread->processor_set;
	pset_reference(*pset);
	return (KERN_SUCCESS);
}

/*
 *	thread_wire_internal:
 *
 *	Specify that the target thread must always be able
 *	to run and to allocate memory.
 */
kern_return_t
thread_wire_internal(
	host_priv_t		host_priv,
	thread_t		thread,
	boolean_t		wired,
	boolean_t		*prev_state)
{
	if (host_priv == NULL || thread != current_thread())
		return (KERN_INVALID_ARGUMENT);

	assert(host_priv == &realhost);

	if (prev_state)
	    *prev_state = (thread->options & TH_OPT_VMPRIV) != 0;
	
	if (wired) {
	    if (!(thread->options & TH_OPT_VMPRIV)) 
		    vm_page_free_reserve(1);	/* XXX */
	    thread->options |= TH_OPT_VMPRIV;
	}
	else {
	    if (thread->options & TH_OPT_VMPRIV) 
		    vm_page_free_reserve(-1);	/* XXX */
	    thread->options &= ~TH_OPT_VMPRIV;
	}

	return (KERN_SUCCESS);
}


/*
 *	thread_wire:
 *
 *	User-api wrapper for thread_wire_internal()
 */
kern_return_t
thread_wire(
	host_priv_t	host_priv,
	thread_t	thread,
	boolean_t	wired)
{
    return (thread_wire_internal(host_priv, thread, wired, NULL));
}

int		split_funnel_off = 0;
lck_grp_t	*funnel_lck_grp = LCK_GRP_NULL;
lck_grp_attr_t	*funnel_lck_grp_attr;
lck_attr_t	*funnel_lck_attr;

funnel_t *
funnel_alloc(
	int type)
{
	lck_mtx_t	*m;
	funnel_t	*fnl;

	if (funnel_lck_grp == LCK_GRP_NULL) {
		funnel_lck_grp_attr = lck_grp_attr_alloc_init();

		funnel_lck_grp = lck_grp_alloc_init("Funnel",  funnel_lck_grp_attr);

		funnel_lck_attr = lck_attr_alloc_init();
	}
	if ((fnl = (funnel_t *)kalloc(sizeof(funnel_t))) != 0){
		bzero((void *)fnl, sizeof(funnel_t));
		if ((m = lck_mtx_alloc_init(funnel_lck_grp, funnel_lck_attr)) == (lck_mtx_t *)NULL) {
			kfree(fnl, sizeof(funnel_t));
			return(THR_FUNNEL_NULL);
		}
		fnl->fnl_mutex = m;
		fnl->fnl_type = type;
	}
	return(fnl);
}

void 
funnel_free(
	funnel_t * fnl)
{
	lck_mtx_free(fnl->fnl_mutex, funnel_lck_grp);
	if (fnl->fnl_oldmutex)
		lck_mtx_free(fnl->fnl_oldmutex, funnel_lck_grp);
	kfree(fnl, sizeof(funnel_t));
}

void 
funnel_lock(
	funnel_t * fnl)
{
	lck_mtx_lock(fnl->fnl_mutex);
	fnl->fnl_mtxholder = current_thread();
}

void 
funnel_unlock(
	funnel_t * fnl)
{
	lck_mtx_unlock(fnl->fnl_mutex);
	fnl->fnl_mtxrelease = current_thread();
}

funnel_t *
thread_funnel_get(
	void)
{
	thread_t th = current_thread();

	if (th->funnel_state & TH_FN_OWNED) {
		return(th->funnel_lock);
	}
	return(THR_FUNNEL_NULL);
}

boolean_t
thread_funnel_set(
        funnel_t *	fnl,
	boolean_t	funneled)
{
	thread_t	cur_thread;
	boolean_t	funnel_state_prev;
	boolean_t	intr;
        
	cur_thread = current_thread();
	funnel_state_prev = ((cur_thread->funnel_state & TH_FN_OWNED) == TH_FN_OWNED);

	if (funnel_state_prev != funneled) {
		intr = ml_set_interrupts_enabled(FALSE);

		if (funneled == TRUE) {
			if (cur_thread->funnel_lock)
				panic("Funnel lock called when holding one %x", cur_thread->funnel_lock);
			KERNEL_DEBUG(0x6032428 | DBG_FUNC_NONE,
											fnl, 1, 0, 0, 0);
			funnel_lock(fnl);
			KERNEL_DEBUG(0x6032434 | DBG_FUNC_NONE,
											fnl, 1, 0, 0, 0);
			cur_thread->funnel_state |= TH_FN_OWNED;
			cur_thread->funnel_lock = fnl;
		} else {
			if(cur_thread->funnel_lock->fnl_mutex != fnl->fnl_mutex)
				panic("Funnel unlock  when not holding funnel");
			cur_thread->funnel_state &= ~TH_FN_OWNED;
			KERNEL_DEBUG(0x603242c | DBG_FUNC_NONE,
								fnl, 1, 0, 0, 0);

			cur_thread->funnel_lock = THR_FUNNEL_NULL;
			funnel_unlock(fnl);
		}
		(void)ml_set_interrupts_enabled(intr);
	} else {
		/* if we are trying to acquire funnel recursively
		 * check for funnel to be held already
		 */
		if (funneled && (fnl->fnl_mutex != cur_thread->funnel_lock->fnl_mutex)) {
				panic("thread_funnel_set: already holding a different funnel");
		}
	}
	return(funnel_state_prev);
}


/*
 * Export routines to other components for things that are done as macros
 * within the osfmk component.
 */

#undef thread_reference
void thread_reference(thread_t thread);
void
thread_reference(
	thread_t	thread)
{
	if (thread != THREAD_NULL)
		thread_reference_internal(thread);
}

#undef thread_should_halt

boolean_t
thread_should_halt(
	thread_t		th)
{
	return (thread_should_halt_fast(th));
}

/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
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

#include <mach/boolean.h>
#include <mach/thread_switch.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>
#include <kern/counters.h>
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
#include <sys/kdebug.h>

#ifdef MACH_BSD
extern void workqueue_thread_yielded(void);
extern sched_call_t workqueue_get_sched_callback(void);
#endif /* MACH_BSD */


/* Called from commpage to take a delayed preemption when exiting
 * the "Preemption Free Zone" (PFZ).
 */
kern_return_t
pfz_exit(
__unused	struct pfz_exit_args *args)
{
	/* For now, nothing special to do.  We'll pick up the ASTs on kernel exit. */

	return (KERN_SUCCESS);
}


/*
 *	swtch and swtch_pri both attempt to context switch (logic in
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

static void
swtch_continue(void)
{
	register processor_t	myprocessor;
    boolean_t				result;

    disable_preemption();
	myprocessor = current_processor();
	result = !SCHED(processor_queue_empty)(myprocessor) || rt_runq.count > 0;
	enable_preemption();

	thread_syscall_return(result);
	/*NOTREACHED*/
}

boolean_t
swtch(
	__unused struct swtch_args *args)
{
	register processor_t	myprocessor;
	boolean_t				result;

	disable_preemption();
	myprocessor = current_processor();
	if (SCHED(processor_queue_empty)(myprocessor) &&	rt_runq.count == 0) {
		mp_enable_preemption();

		return (FALSE);
	}
	enable_preemption();

	counter(c_swtch_block++);

	thread_block_reason((thread_continue_t)swtch_continue, NULL, AST_YIELD);

	disable_preemption();
	myprocessor = current_processor();
	result = !SCHED(processor_queue_empty)(myprocessor) || rt_runq.count > 0;
	enable_preemption();

	return (result);
}

static void
swtch_pri_continue(void)
{
	register processor_t	myprocessor;
    boolean_t				result;

	thread_depress_abort_internal(current_thread());

    disable_preemption();
	myprocessor = current_processor();
	result = !SCHED(processor_queue_empty)(myprocessor) || rt_runq.count > 0;
	mp_enable_preemption();

	thread_syscall_return(result);
	/*NOTREACHED*/
}

boolean_t
swtch_pri(
__unused	struct swtch_pri_args *args)
{
	register processor_t	myprocessor;
	boolean_t				result;

	disable_preemption();
	myprocessor = current_processor();
	if (SCHED(processor_queue_empty)(myprocessor) && rt_runq.count == 0) {
		mp_enable_preemption();

		return (FALSE);
	}
	enable_preemption();

	counter(c_swtch_pri_block++);

	thread_depress_abstime(thread_depress_time);

	thread_block_reason((thread_continue_t)swtch_pri_continue, NULL, AST_YIELD);

	thread_depress_abort_internal(current_thread());

	disable_preemption();
	myprocessor = current_processor();
	result = !SCHED(processor_queue_empty)(myprocessor) || rt_runq.count > 0;
	enable_preemption();

	return (result);
}

static int
thread_switch_disable_workqueue_sched_callback(void)
{
	sched_call_t callback = workqueue_get_sched_callback();
	thread_t self = current_thread();
	if (!callback || self->sched_call != callback) {
		return FALSE;
	}
	spl_t s = splsched();
	thread_lock(self);
	thread_sched_call(self, NULL);
	thread_unlock(self);
	splx(s);
	return TRUE;
}

static void
thread_switch_enable_workqueue_sched_callback(void)
{
	sched_call_t callback = workqueue_get_sched_callback();
	thread_t self = current_thread();
	spl_t s = splsched();
	thread_lock(self);
	thread_sched_call(self, callback);
	thread_unlock(self);
	splx(s);
}

static void
thread_switch_continue(void)
{
	register thread_t	self = current_thread();
	int					option = self->saved.swtch.option;
	boolean_t			reenable_workq_callback = self->saved.swtch.reenable_workq_callback;


	if (option == SWITCH_OPTION_DEPRESS || option == SWITCH_OPTION_OSLOCK_DEPRESS)
		thread_depress_abort_internal(self);

	if (reenable_workq_callback)
		thread_switch_enable_workqueue_sched_callback();

	thread_syscall_return(KERN_SUCCESS);
	/*NOTREACHED*/
}

/*
 *	thread_switch:
 *
 *	Context switch.  User may supply thread hint.
 */
kern_return_t
thread_switch(
	struct thread_switch_args *args)
{
	register thread_t		thread, self = current_thread();
	mach_port_name_t		thread_name = args->thread_name;
	int						option = args->option;
	mach_msg_timeout_t		option_time = args->option_time;
	uint32_t				scale_factor = NSEC_PER_MSEC;
	boolean_t				reenable_workq_callback = FALSE;
	boolean_t				depress_option = FALSE;
	boolean_t				wait_option = FALSE;

    /*
     *	Validate and process option.
     */
    switch (option) {

	case SWITCH_OPTION_NONE:
		workqueue_thread_yielded();
		break;
	case SWITCH_OPTION_WAIT:
		wait_option = TRUE;
		workqueue_thread_yielded();
		break;
	case SWITCH_OPTION_DEPRESS:
		depress_option = TRUE;
		workqueue_thread_yielded();
		break;
	case SWITCH_OPTION_DISPATCH_CONTENTION:
		scale_factor = NSEC_PER_USEC;
		wait_option = TRUE;
		if (thread_switch_disable_workqueue_sched_callback())
			reenable_workq_callback = TRUE;
		break;
	case SWITCH_OPTION_OSLOCK_DEPRESS:
		depress_option = TRUE;
		if (thread_switch_disable_workqueue_sched_callback())
			reenable_workq_callback = TRUE;
		break;
	case SWITCH_OPTION_OSLOCK_WAIT:
		wait_option = TRUE;
		if (thread_switch_disable_workqueue_sched_callback())
			reenable_workq_callback = TRUE;
		break;
	default:
	    return (KERN_INVALID_ARGUMENT);
    }

	/*
	 * Translate the port name if supplied.
	 */
    if (thread_name != MACH_PORT_NULL) {
		ipc_port_t			port;

		if (ipc_port_translate_send(self->task->itk_space,
									thread_name, &port) == KERN_SUCCESS) {
			ip_reference(port);
			ip_unlock(port);

			thread = convert_port_to_thread(port);
			ip_release(port);

			if (thread == self) {
				(void)thread_deallocate_internal(thread);
				thread = THREAD_NULL;
			}
		}
		else
			thread = THREAD_NULL;
	}
	else
		thread = THREAD_NULL;


	if (option == SWITCH_OPTION_OSLOCK_DEPRESS || option == SWITCH_OPTION_OSLOCK_WAIT) {
		if (thread != THREAD_NULL) {

			if (thread->task != self->task) {
				/*
				 * OSLock boosting only applies to other threads
				 * in your same task (even if you have a port for
				 * a thread in another task)
				 */

				(void)thread_deallocate_internal(thread);
				thread = THREAD_NULL;
			} else {
				/*
				 * Attempt to kick the lock owner up to our same IO throttling tier.
				 * If the thread is currently blocked in throttle_lowpri_io(),
				 * it will immediately break out.
				 */
				int new_policy = proc_get_effective_thread_policy(self, TASK_POLICY_IO);
				
				set_thread_iotier_override(thread, new_policy);
			}
		}
	}

	/*
	 * Try to handoff if supplied.
	 */
	if (thread != THREAD_NULL) {
		processor_t		processor;
		spl_t			s;

		s = splsched();
		thread_lock(thread);

		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED,MACH_SCHED_THREAD_SWITCH)|DBG_FUNC_NONE,
							  thread_tid(thread), thread->state, 0, 0, 0);

		/*
		 *	Check that the thread is not bound
		 *	to a different processor, and that realtime
		 *	is not involved.
		 *
		 *	Next, pull it off its run queue.  If it
		 *	doesn't come, it's not eligible.
		 */
		processor = current_processor();
		if (processor->current_pri < BASEPRI_RTQUEUES			&&
			thread->sched_pri < BASEPRI_RTQUEUES				&&
			(thread->bound_processor == PROCESSOR_NULL	||
			 thread->bound_processor == processor)				&&
				thread_run_queue_remove(thread)							) {
			/*
			 *	Hah, got it!!
			 */
			thread_unlock(thread);

			(void)thread_deallocate_internal(thread);

			if (wait_option)
				assert_wait_timeout((event_t)assert_wait_timeout, THREAD_ABORTSAFE,
														option_time, scale_factor);
			else
			if (depress_option)
				thread_depress_ms(option_time);

			self->saved.swtch.option = option;
			self->saved.swtch.reenable_workq_callback = reenable_workq_callback;

			thread_run(self, (thread_continue_t)thread_switch_continue, NULL, thread);
			/* NOTREACHED */
		}

		thread_unlock(thread);
		splx(s);

		thread_deallocate(thread);
	}
		
	if (wait_option)
		assert_wait_timeout((event_t)assert_wait_timeout, THREAD_ABORTSAFE, option_time, scale_factor);
	else
	if (depress_option)
		thread_depress_ms(option_time);
	  
	self->saved.swtch.option = option;
	self->saved.swtch.reenable_workq_callback = reenable_workq_callback;

	thread_block_reason((thread_continue_t)thread_switch_continue, NULL, AST_YIELD);

	if (depress_option)
		thread_depress_abort_internal(self);

	if (reenable_workq_callback)
		thread_switch_enable_workqueue_sched_callback();

    return (KERN_SUCCESS);
}

/*
 * Depress thread's priority to lowest possible for the specified interval,
 * with a value of zero resulting in no timeout being scheduled.
 */
void
thread_depress_abstime(
	uint64_t				interval)
{
	register thread_t		self = current_thread();
	uint64_t				deadline;
    spl_t					s;

    s = splsched();
    thread_lock(self);
	if (!(self->sched_flags & TH_SFLAG_DEPRESSED_MASK)) {
		processor_t		myprocessor = self->last_processor;

		self->sched_pri = DEPRESSPRI;
		myprocessor->current_pri = self->sched_pri;
		self->sched_flags |= TH_SFLAG_DEPRESS;

		if (interval != 0) {
			clock_absolutetime_interval_to_deadline(interval, &deadline);
			if (!timer_call_enter(&self->depress_timer, deadline, TIMER_CALL_USER_CRITICAL))
				self->depress_timer_active++;
		}
	}
	thread_unlock(self);
    splx(s);
}

void
thread_depress_ms(
	mach_msg_timeout_t		interval)
{
	uint64_t		abstime;

	clock_interval_to_absolutetime_interval(
							interval, NSEC_PER_MSEC, &abstime);
	thread_depress_abstime(abstime);
}

/*
 *	Priority depression expiration.
 */
void
thread_depress_expire(
	void			*p0,
	__unused void	*p1)
{
	thread_t		thread = p0;
    spl_t			s;

    s = splsched();
    thread_lock(thread);
	if (--thread->depress_timer_active == 0) {
		thread->sched_flags &= ~TH_SFLAG_DEPRESSED_MASK;
		SCHED(compute_priority)(thread, FALSE);
	}
    thread_unlock(thread);
    splx(s);
}

/*
 *	Prematurely abort priority depression if there is one.
 */
kern_return_t
thread_depress_abort_internal(
	thread_t				thread)
{
    kern_return_t 			result = KERN_NOT_DEPRESSED;
    spl_t					s;

    s = splsched();
    thread_lock(thread);
	if (!(thread->sched_flags & TH_SFLAG_POLLDEPRESS)) {
		if (thread->sched_flags & TH_SFLAG_DEPRESSED_MASK) {
			thread->sched_flags &= ~TH_SFLAG_DEPRESSED_MASK;
			SCHED(compute_priority)(thread, FALSE);
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
thread_poll_yield(
	thread_t		self)
{
	spl_t			s;

	assert(self == current_thread());

	s = splsched();
	if (self->sched_mode == TH_MODE_FIXED) {
		uint64_t			total_computation, abstime;

		abstime = mach_absolute_time();
		total_computation = abstime - self->computation_epoch;
		total_computation += self->computation_metered;
		if (total_computation >= max_poll_computation) {
			processor_t		myprocessor = current_processor();
			ast_t			preempt;

			thread_lock(self);
			if (!(self->sched_flags & TH_SFLAG_DEPRESSED_MASK)) {
				self->sched_pri = DEPRESSPRI;
				myprocessor->current_pri = self->sched_pri;
			}
			self->computation_epoch = abstime;
			self->computation_metered = 0;
			self->sched_flags |= TH_SFLAG_POLLDEPRESS;

			abstime += (total_computation >> sched_poll_yield_shift);
			if (!timer_call_enter(&self->depress_timer, abstime, TIMER_CALL_USER_CRITICAL))
				self->depress_timer_active++;

			if ((preempt = csw_check(myprocessor, AST_NONE)) != AST_NONE)
				ast_on(preempt);

			thread_unlock(self);
		}
	}
	splx(s);
}


void
thread_yield_internal(
	mach_msg_timeout_t	ms)
{
	processor_t	myprocessor;

	disable_preemption();
	myprocessor = current_processor();
	if (SCHED(processor_queue_empty)(myprocessor) && rt_runq.count == 0) {
		mp_enable_preemption();

		return;
	}
	enable_preemption();

	thread_depress_ms(ms);

	thread_block_reason(THREAD_CONTINUE_NULL, NULL, AST_YIELD);

	thread_depress_abort_internal(current_thread());
}


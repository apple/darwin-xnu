/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
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
 * @OSF_FREE_COPYRIGHT@
 */
/*
 * Copyright (c) 1993 The University of Utah and
 * the Center for Software Science (CSS).  All rights reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * THE UNIVERSITY OF UTAH AND CSS ALLOW FREE USE OF THIS SOFTWARE IN ITS "AS
 * IS" CONDITION.  THE UNIVERSITY OF UTAH AND CSS DISCLAIM ANY LIABILITY OF
 * ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * CSS requests users of this software to return to css-dist@cs.utah.edu any
 * improvements that they make and grant CSS redistribution rights.
 *
 *	Author:	Bryan Ford, University of Utah CSS
 *
 *	Thread management routines
 */
#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <mach/thread_act_server.h>

#include <kern/kern_types.h>
#include <kern/ast.h>
#include <kern/mach_param.h>
#include <kern/zalloc.h>
#include <kern/extmod_statistics.h>
#include <kern/thread.h>
#include <kern/task.h>
#include <kern/sched_prim.h>
#include <kern/misc_protos.h>
#include <kern/assert.h>
#include <kern/exception.h>
#include <kern/ipc_mig.h>
#include <kern/ipc_tt.h>
#include <kern/machine.h>
#include <kern/spl.h>
#include <kern/syscall_subr.h>
#include <kern/sync_lock.h>
#include <kern/processor.h>
#include <kern/timer.h>
#include <kern/affinity.h>

#include <stdatomic.h>

#include <security/mac_mach_internal.h>

static void act_abort(thread_t thread);

static void thread_suspended(void *arg, wait_result_t result);
static void thread_set_apc_ast(thread_t thread);
static void thread_set_apc_ast_locked(thread_t thread);

/*
 * Internal routine to mark a thread as started.
 * Always called with the thread mutex locked.
 */
void
thread_start(
	thread_t			thread)
{
	clear_wait(thread, THREAD_AWAKENED);
	thread->started = TRUE;
}

/*
 * Internal routine to mark a thread as waiting
 * right after it has been created.  The caller
 * is responsible to call wakeup()/thread_wakeup()
 * or thread_terminate() to get it going.
 *
 * Always called with the thread mutex locked.
 *
 * Task and task_threads mutexes also held 
 * (so nobody can set the thread running before
 * this point)
 *
 * Converts TH_UNINT wait to THREAD_INTERRUPTIBLE
 * to allow termination from this point forward.
 */
void
thread_start_in_assert_wait(
	thread_t			thread,
	event_t             event,
	wait_interrupt_t    interruptible)
{
	struct waitq *waitq = assert_wait_queue(event);
	wait_result_t wait_result;
	spl_t spl;

	spl = splsched();
	waitq_lock(waitq);

	/* clear out startup condition (safe because thread not started yet) */
	thread_lock(thread);
	assert(!thread->started);
	assert((thread->state & (TH_WAIT | TH_UNINT)) == (TH_WAIT | TH_UNINT));
	thread->state &= ~(TH_WAIT | TH_UNINT);
	thread_unlock(thread);

	/* assert wait interruptibly forever */
	wait_result = waitq_assert_wait64_locked(waitq, CAST_EVENT64_T(event),
	                                 interruptible,
	                                 TIMEOUT_URGENCY_SYS_NORMAL,
	                                 TIMEOUT_WAIT_FOREVER,
	                                 TIMEOUT_NO_LEEWAY,
	                                 thread);
	assert (wait_result == THREAD_WAITING);

	/* mark thread started while we still hold the waitq lock */
	thread_lock(thread);
	thread->started = TRUE;
	thread_unlock(thread);

	waitq_unlock(waitq);
	splx(spl);
}

/*
 * Internal routine to terminate a thread.
 * Sometimes called with task already locked.
 */
kern_return_t
thread_terminate_internal(
	thread_t			thread)
{
	kern_return_t		result = KERN_SUCCESS;

	thread_mtx_lock(thread);

	if (thread->active) {
		thread->active = FALSE;

		act_abort(thread);

		if (thread->started)
			clear_wait(thread, THREAD_INTERRUPTED);
		else {
			thread_start(thread);
		}
	}
	else
		result = KERN_TERMINATED;

	if (thread->affinity_set != NULL)
		thread_affinity_terminate(thread);

	thread_mtx_unlock(thread);

	if (thread != current_thread() && result == KERN_SUCCESS)
		thread_wait(thread, FALSE);

	return (result);
}

/*
 * Terminate a thread.
 */
kern_return_t
thread_terminate(
	thread_t		thread)
{
	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	/* Kernel threads can't be terminated without their own cooperation */
	if (thread->task == kernel_task && thread != current_thread())
		return (KERN_FAILURE);

	kern_return_t result = thread_terminate_internal(thread);

	/*
	 * If a kernel thread is terminating itself, force handle the APC_AST here.
	 * Kernel threads don't pass through the return-to-user AST checking code,
	 * but all threads must finish their own termination in thread_apc_ast.
	 */
	if (thread->task == kernel_task) {
		assert(thread->active == FALSE);
		thread_ast_clear(thread, AST_APC);
		thread_apc_ast(thread);

		panic("thread_terminate");
		/* NOTREACHED */
	}

	return (result);
}

/*
 * Suspend execution of the specified thread.
 * This is a recursive-style suspension of the thread, a count of
 * suspends is maintained.
 *
 * Called with thread mutex held.
 */
void
thread_hold(thread_t thread)
{
	if (thread->suspend_count++ == 0) {
		thread_set_apc_ast(thread);
		assert(thread->suspend_parked == FALSE);
	}
}

/*
 * Decrement internal suspension count, setting thread
 * runnable when count falls to zero.
 *
 * Because the wait is abortsafe, we can't be guaranteed that the thread
 * is currently actually waiting even if suspend_parked is set.
 *
 * Called with thread mutex held.
 */
void
thread_release(thread_t thread)
{
	assertf(thread->suspend_count > 0, "thread %p over-resumed", thread);

	/* fail-safe on non-assert builds */
	if (thread->suspend_count == 0)
		return;

	if (--thread->suspend_count == 0) {
		if (!thread->started) {
			thread_start(thread);
		} else if (thread->suspend_parked) {
			thread->suspend_parked = FALSE;
			thread_wakeup_thread(&thread->suspend_count, thread);
		}
	}
}

kern_return_t
thread_suspend(thread_t thread)
{
	kern_return_t result = KERN_SUCCESS;

	if (thread == THREAD_NULL || thread->task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	thread_mtx_lock(thread);

	if (thread->active) {
		if (thread->user_stop_count++ == 0)
			thread_hold(thread);
	} else {
		result = KERN_TERMINATED;
	}

	thread_mtx_unlock(thread);

	if (thread != current_thread() && result == KERN_SUCCESS)
		thread_wait(thread, FALSE);

	return (result);
}

kern_return_t
thread_resume(thread_t thread)
{
	kern_return_t result = KERN_SUCCESS;

	if (thread == THREAD_NULL || thread->task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	thread_mtx_lock(thread);

	if (thread->active) {
		if (thread->user_stop_count > 0) {
			if (--thread->user_stop_count == 0)
				thread_release(thread);
		} else {
			result = KERN_FAILURE;
		}
	} else {
		result = KERN_TERMINATED;
	}

	thread_mtx_unlock(thread);

	return (result);
}

/*
 *	thread_depress_abort:
 *
 *	Prematurely abort priority depression if there is one.
 */
kern_return_t
thread_depress_abort(
	thread_t	thread)
{
	kern_return_t		result;

    if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

    thread_mtx_lock(thread);

	if (thread->active)
		result = thread_depress_abort_internal(thread);
	else
		result = KERN_TERMINATED;

    thread_mtx_unlock(thread);

	return (result);
}


/*
 * Indicate that the thread should run the AST_APC callback
 * to detect an abort condition.
 *
 * Called with thread mutex held.
 */
static void
act_abort(
	thread_t	thread)
{
	spl_t		s = splsched();

	thread_lock(thread);

	if (!(thread->sched_flags & TH_SFLAG_ABORT)) {
		thread->sched_flags |= TH_SFLAG_ABORT;
		thread_set_apc_ast_locked(thread);
	} else {
		thread->sched_flags &= ~TH_SFLAG_ABORTSAFELY;
	}

	thread_unlock(thread);
	splx(s);
}

kern_return_t
thread_abort(
	thread_t	thread)
{
	kern_return_t	result = KERN_SUCCESS;

	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	thread_mtx_lock(thread);

	if (thread->active) {
		act_abort(thread);
		clear_wait(thread, THREAD_INTERRUPTED);
	}
	else
		result = KERN_TERMINATED;

	thread_mtx_unlock(thread);

	return (result);
}

kern_return_t
thread_abort_safely(
	thread_t		thread)
{
	kern_return_t	result = KERN_SUCCESS;

	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	thread_mtx_lock(thread);

	if (thread->active) {
		spl_t		s = splsched();

		thread_lock(thread);
		if (!thread->at_safe_point ||
				clear_wait_internal(thread, THREAD_INTERRUPTED) != KERN_SUCCESS) {
			if (!(thread->sched_flags & TH_SFLAG_ABORT)) {
				thread->sched_flags |= TH_SFLAG_ABORTED_MASK;
				thread_set_apc_ast_locked(thread);
			}
		}
		thread_unlock(thread);
		splx(s);
	} else {
		result = KERN_TERMINATED;
	}

	thread_mtx_unlock(thread);

	return (result);
}

/*** backward compatibility hacks ***/
#include <mach/thread_info.h>
#include <mach/thread_special_ports.h>
#include <ipc/ipc_port.h>

kern_return_t
thread_info(
	thread_t			thread,
	thread_flavor_t			flavor,
	thread_info_t			thread_info_out,
	mach_msg_type_number_t	*thread_info_count)
{
	kern_return_t			result;

	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	thread_mtx_lock(thread);

	if (thread->active || thread->inspection)
		result = thread_info_internal(
						thread, flavor, thread_info_out, thread_info_count);
	else
		result = KERN_TERMINATED;

	thread_mtx_unlock(thread);

	return (result);
}

kern_return_t
thread_get_state(
	thread_t		thread,
	int						flavor,
	thread_state_t			state,			/* pointer to OUT array */
	mach_msg_type_number_t	*state_count)	/*IN/OUT*/
{
	kern_return_t		result = KERN_SUCCESS;

	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	thread_mtx_lock(thread);

	if (thread->active) {
		if (thread != current_thread()) {
			thread_hold(thread);

			thread_mtx_unlock(thread);

			if (thread_stop(thread, FALSE)) {
				thread_mtx_lock(thread);
				result = machine_thread_get_state(
										thread, flavor, state, state_count);
				thread_unstop(thread);
			}
			else {
				thread_mtx_lock(thread);
				result = KERN_ABORTED;
			}

			thread_release(thread);
		}
		else
			result = machine_thread_get_state(
									thread, flavor, state, state_count);
	}
	else if (thread->inspection)
	{
		result = machine_thread_get_state(
									thread, flavor, state, state_count);
	}
	else
		result = KERN_TERMINATED;

	thread_mtx_unlock(thread);

	return (result);
}

/*
 *	Change thread's machine-dependent state.  Called with nothing
 *	locked.  Returns same way.
 */
static kern_return_t
thread_set_state_internal(
	thread_t		thread,
	int						flavor,
	thread_state_t			state,
	mach_msg_type_number_t	state_count,
	boolean_t				from_user)
{
	kern_return_t		result = KERN_SUCCESS;

	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	thread_mtx_lock(thread);

	if (thread->active) {
		if (thread != current_thread()) {
			thread_hold(thread);

			thread_mtx_unlock(thread);

			if (thread_stop(thread, TRUE)) {
				thread_mtx_lock(thread);
				result = machine_thread_set_state(
										thread, flavor, state, state_count);
				thread_unstop(thread);
			}
			else {
				thread_mtx_lock(thread);
				result = KERN_ABORTED;
			}

			thread_release(thread);
		}
		else
			result = machine_thread_set_state(
									thread, flavor, state, state_count);
	}
	else
		result = KERN_TERMINATED;

	if ((result == KERN_SUCCESS) && from_user)
		extmod_statistics_incr_thread_set_state(thread);

	thread_mtx_unlock(thread);

	return (result);
}

/* No prototype, since thread_act_server.h has the _from_user version if KERNEL_SERVER */ 
kern_return_t
thread_set_state(
	thread_t		thread,
	int						flavor,
	thread_state_t			state,
	mach_msg_type_number_t	state_count);

kern_return_t
thread_set_state(
	thread_t		thread,
	int						flavor,
	thread_state_t			state,
	mach_msg_type_number_t	state_count)
{
	return thread_set_state_internal(thread, flavor, state, state_count, FALSE);
}
 
kern_return_t
thread_set_state_from_user(
	thread_t		thread,
	int						flavor,
	thread_state_t			state,
	mach_msg_type_number_t	state_count)
{
	return thread_set_state_internal(thread, flavor, state, state_count, TRUE);
}
 
/*
 * Kernel-internal "thread" interfaces used outside this file:
 */

/* Initialize (or re-initialize) a thread state.  Called from execve
 * with nothing locked, returns same way.
 */
kern_return_t
thread_state_initialize(
	thread_t		thread)
{
	kern_return_t		result = KERN_SUCCESS;

	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	thread_mtx_lock(thread);

	if (thread->active) {
		if (thread != current_thread()) {
			thread_hold(thread);

			thread_mtx_unlock(thread);

			if (thread_stop(thread, TRUE)) {
				thread_mtx_lock(thread);
				result = machine_thread_state_initialize( thread );
				thread_unstop(thread);
			}
			else {
				thread_mtx_lock(thread);
				result = KERN_ABORTED;
			}

			thread_release(thread);
		}
		else
			result = machine_thread_state_initialize( thread );
	}
	else
		result = KERN_TERMINATED;

	thread_mtx_unlock(thread);

	return (result);
}


kern_return_t
thread_dup(
	thread_t	target)
{
	thread_t			self = current_thread();
	kern_return_t		result = KERN_SUCCESS;

	if (target == THREAD_NULL || target == self)
		return (KERN_INVALID_ARGUMENT);

	thread_mtx_lock(target);

	if (target->active) {
		thread_hold(target);

		thread_mtx_unlock(target);

		if (thread_stop(target, TRUE)) {
			thread_mtx_lock(target);
			result = machine_thread_dup(self, target);
			if (self->affinity_set != AFFINITY_SET_NULL)
				thread_affinity_dup(self, target);
			thread_unstop(target);
		}
		else {
			thread_mtx_lock(target);
			result = KERN_ABORTED;
		}

		thread_release(target);
	}
	else
		result = KERN_TERMINATED;

	thread_mtx_unlock(target);

	return (result);
}


kern_return_t
thread_dup2(
	thread_t	source,
	thread_t	target)
{
	kern_return_t		result = KERN_SUCCESS;
	uint32_t		active = 0;

	if (source == THREAD_NULL || target == THREAD_NULL || target == source)
		return (KERN_INVALID_ARGUMENT);

	thread_mtx_lock(source);
	active = source->active;
	thread_mtx_unlock(source);

	if (!active) {
		return KERN_TERMINATED;
	}

	thread_mtx_lock(target);

	if (target->active || target->inspection) {
		thread_hold(target);

		thread_mtx_unlock(target);

		if (thread_stop(target, TRUE)) {
			thread_mtx_lock(target);
			result = machine_thread_dup(source, target);
			if (source->affinity_set != AFFINITY_SET_NULL)
				thread_affinity_dup(source, target);
			thread_unstop(target);
		}
		else {
			thread_mtx_lock(target);
			result = KERN_ABORTED;
		}

		thread_release(target);
	}
	else
		result = KERN_TERMINATED;

	thread_mtx_unlock(target);

	return (result);
}

/*
 *	thread_setstatus:
 *
 *	Set the status of the specified thread.
 *	Called with (and returns with) no locks held.
 */
kern_return_t
thread_setstatus(
	thread_t		thread,
	int						flavor,
	thread_state_t			tstate,
	mach_msg_type_number_t	count)
{

	return (thread_set_state(thread, flavor, tstate, count));
}

/*
 *	thread_getstatus:
 *
 *	Get the status of the specified thread.
 */
kern_return_t
thread_getstatus(
	thread_t		thread,
	int						flavor,
	thread_state_t			tstate,
	mach_msg_type_number_t	*count)
{
	return (thread_get_state(thread, flavor, tstate, count));
}

/*
 *	Change thread's machine-dependent userspace TSD base.
 *  Called with nothing locked.  Returns same way.
 */
kern_return_t
thread_set_tsd_base(
	thread_t			thread,
	mach_vm_offset_t	tsd_base)
{
	kern_return_t		result = KERN_SUCCESS;

	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	thread_mtx_lock(thread);

	if (thread->active) {
		if (thread != current_thread()) {
			thread_hold(thread);

			thread_mtx_unlock(thread);

			if (thread_stop(thread, TRUE)) {
				thread_mtx_lock(thread);
				result = machine_thread_set_tsd_base(thread, tsd_base);
				thread_unstop(thread);
			}
			else {
				thread_mtx_lock(thread);
				result = KERN_ABORTED;
			}

			thread_release(thread);
		}
		else
			result = machine_thread_set_tsd_base(thread, tsd_base);
	}
	else
		result = KERN_TERMINATED;

	thread_mtx_unlock(thread);

	return (result);
}

/*
 * thread_set_apc_ast:
 *
 * Register the AST_APC callback that handles suspension and
 * termination, if it hasn't been installed already.
 *
 * Called with the thread mutex held.
 */
static void
thread_set_apc_ast(thread_t thread)
{
	spl_t s = splsched();

	thread_lock(thread);
	thread_set_apc_ast_locked(thread);
	thread_unlock(thread);

	splx(s);
}

/*
 * thread_set_apc_ast_locked:
 *
 * Do the work of registering for the AST_APC callback.
 *
 * Called with the thread mutex and scheduling lock held.
 */
static void
thread_set_apc_ast_locked(thread_t thread)
{
	/*
	 * Temporarily undepress, so target has
	 * a chance to do locking required to
	 * block itself in thread_suspended.
	 *
	 * Leaves the depress flag set so we can reinstate when it's blocked.
	 */
	if (thread->sched_flags & TH_SFLAG_DEPRESSED_MASK)
		thread_recompute_sched_pri(thread, TRUE);

	thread_ast_set(thread, AST_APC);

	if (thread == current_thread()) {
		ast_propagate(thread);
	} else {
		processor_t processor = thread->last_processor;

		if (processor != PROCESSOR_NULL &&
		    processor->state == PROCESSOR_RUNNING &&
		    processor->active_thread == thread) {
			cause_ast_check(processor);
		}
	}
}

/*
 * Activation control support routines internal to this file:
 *
 */

/*
 * thread_suspended
 *
 * Continuation routine for thread suspension.  It checks
 * to see whether there has been any new suspensions.  If so, it
 * installs the AST_APC handler again.  Otherwise, it checks to see
 * if the current depression needs to be re-instated (it may have
 * been temporarily removed in order to get to this point in a hurry).
 */
__attribute__((noreturn))
static void
thread_suspended(__unused void *parameter, wait_result_t result)
{
	thread_t thread = current_thread();

	thread_mtx_lock(thread);

	if (result == THREAD_INTERRUPTED)
		thread->suspend_parked = FALSE;
	else
		assert(thread->suspend_parked == FALSE);

	if (thread->suspend_count > 0) {
		thread_set_apc_ast(thread);
	} else {
		spl_t s = splsched();

		thread_lock(thread);
		if (thread->sched_flags & TH_SFLAG_DEPRESSED_MASK) {
			thread->sched_pri = DEPRESSPRI;
			thread->last_processor->current_pri = thread->sched_pri;
			thread->last_processor->current_perfctl_class = thread_get_perfcontrol_class(thread);

			KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_CHANGE_PRIORITY),
			                      (uintptr_t)thread_tid(thread),
			                      thread->base_pri,
			                      thread->sched_pri,
			                      thread->sched_usage,
			                      0);
		}
		thread_unlock(thread);
		splx(s);
	}

	thread_mtx_unlock(thread);

	thread_exception_return();
	/*NOTREACHED*/
}

/*
 * thread_apc_ast - handles AST_APC and drives thread suspension and termination.
 * Called with nothing locked.  Returns (if it returns) the same way.
 */
void
thread_apc_ast(thread_t thread)
{
	thread_mtx_lock(thread);

	assert(thread->suspend_parked == FALSE);

	spl_t s = splsched();
	thread_lock(thread);

	/* TH_SFLAG_POLLDEPRESS is OK to have here */
	assert((thread->sched_flags & TH_SFLAG_DEPRESS) == 0);

	thread->sched_flags &= ~TH_SFLAG_ABORTED_MASK;
	thread_unlock(thread);
	splx(s);

	if (!thread->active) {
		/* Thread is ready to terminate, time to tear it down */
		thread_mtx_unlock(thread);

		thread_terminate_self();
		/*NOTREACHED*/
	}

	/* If we're suspended, go to sleep and wait for someone to wake us up. */
	if (thread->suspend_count > 0) {
		thread->suspend_parked = TRUE;
		assert_wait(&thread->suspend_count, THREAD_ABORTSAFE);
		thread_mtx_unlock(thread);

		thread_block(thread_suspended);
		/*NOTREACHED*/
	}

	thread_mtx_unlock(thread);
}

/* Prototype, see justification above */
kern_return_t
act_set_state(
	thread_t				thread,
	int						flavor,
	thread_state_t			state,
	mach_msg_type_number_t	count);

kern_return_t
act_set_state(
	thread_t				thread,
	int						flavor,
	thread_state_t			state,
	mach_msg_type_number_t	count)
{
    if (thread == current_thread())
	    return (KERN_INVALID_ARGUMENT);

    return (thread_set_state(thread, flavor, state, count));
    
}

kern_return_t
act_set_state_from_user(
	thread_t				thread,
	int						flavor,
	thread_state_t			state,
	mach_msg_type_number_t	count)
{
    if (thread == current_thread())
	    return (KERN_INVALID_ARGUMENT);

    return (thread_set_state_from_user(thread, flavor, state, count));
    
}

kern_return_t
act_get_state(
	thread_t				thread,
	int						flavor,
	thread_state_t			state,
	mach_msg_type_number_t	*count)
{
    if (thread == current_thread())
	    return (KERN_INVALID_ARGUMENT);

    return (thread_get_state(thread, flavor, state, count));
}

static void
act_set_ast(
	    thread_t thread,
	    ast_t ast)
{
	spl_t s = splsched();

	if (thread == current_thread()) {
		thread_ast_set(thread, ast);
		ast_propagate(thread);
	} else {
		processor_t processor;

		thread_lock(thread);
		thread_ast_set(thread, ast);
		processor = thread->last_processor;
		if ( processor != PROCESSOR_NULL            &&
		     processor->state == PROCESSOR_RUNNING  &&
		     processor->active_thread == thread     )
			cause_ast_check(processor);
		thread_unlock(thread);
	}

	splx(s);
}

/*
 * set AST on thread without causing an AST check
 * and without taking the thread lock
 *
 * If thread is not the current thread, then it may take
 * up until the next context switch or quantum expiration
 * on that thread for it to notice the AST.
 */
static void
act_set_ast_async(thread_t  thread,
                  ast_t     ast)
{
	thread_ast_set(thread, ast);

	if (thread == current_thread()) {
		spl_t s = splsched();
		ast_propagate(thread);
		splx(s);
	}
}

void
act_set_astbsd(
	thread_t	thread)
{
	act_set_ast( thread, AST_BSD );
}

void
act_set_astkevent(thread_t thread, uint16_t bits)
{
	atomic_fetch_or(&thread->kevent_ast_bits, bits);

	/* kevent AST shouldn't send immediate IPIs */
	act_set_ast_async(thread, AST_KEVENT);
}

void
act_set_kperf(
	thread_t	thread)
{
	/* safety check */
	if (thread != current_thread())
		if( !ml_get_interrupts_enabled() )
			panic("unsafe act_set_kperf operation");

	act_set_ast( thread, AST_KPERF );
}

#if CONFIG_MACF
void
act_set_astmacf(
	thread_t	thread)
{
	act_set_ast( thread, AST_MACF);
}
#endif

void
act_set_astledger(thread_t thread)
{
	act_set_ast(thread, AST_LEDGER);
}

/*
 * The ledger AST may need to be set while already holding
 * the thread lock.  This routine skips sending the IPI,
 * allowing us to avoid the lock hold.
 *
 * However, it means the targeted thread must context switch
 * to recognize the ledger AST.
 */
void
act_set_astledger_async(thread_t thread)
{
	act_set_ast_async(thread, AST_LEDGER);
}

void
act_set_io_telemetry_ast(thread_t thread)
{
	act_set_ast(thread, AST_TELEMETRY_IO);
}


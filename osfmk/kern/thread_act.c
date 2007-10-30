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
#include <mach/alert.h>
#include <mach/rpc.h>
#include <mach/thread_act_server.h>

#include <kern/kern_types.h>
#include <kern/ast.h>
#include <kern/mach_param.h>
#include <kern/zalloc.h>
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

#include <mach/rpc.h>

#include <mach/sdt.h>

void			act_abort(thread_t);
void			install_special_handler_locked(thread_t);
void			special_handler_continue(void);

/*
 * Internal routine to mark a thread as started.
 * Always called with the thread locked.
 *
 * Note: function intentionall declared with the noinline attribute to
 * prevent multiple declaration of probe symbols in this file; we would
 * prefer "#pragma noinline", but gcc does not support it.
 */
void
thread_start_internal(
	thread_t			thread)
{
	clear_wait(thread, THREAD_AWAKENED);
	thread->started = TRUE;
	DTRACE_PROC1(lwp__start, thread_t, thread);
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

	DTRACE_PROC(lwp__exit);

	thread_mtx_lock(thread);

	if (thread->active) {
		thread->active = FALSE;

		act_abort(thread);

		if (thread->started)
			clear_wait(thread, THREAD_INTERRUPTED);
		else {
			thread_start_internal(thread);
		}
	}
	else
		result = KERN_TERMINATED;

	if (thread->affinity_set != NULL)
		thread_affinity_terminate(thread);

	thread_mtx_unlock(thread);

	if (thread != current_thread() && result == KERN_SUCCESS)
		thread_wait(thread);

	return (result);
}

/*
 * Terminate a thread.
 */
kern_return_t
thread_terminate(
	thread_t		thread)
{
	kern_return_t	result;

	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	if (	thread->task == kernel_task		&&
			thread != current_thread()			)
		return (KERN_FAILURE);

	result = thread_terminate_internal(thread);

	/*
	 * If a kernel thread is terminating itself, force an AST here.
	 * Kernel threads don't normally pass through the AST checking
	 * code - and all threads finish their own termination in the
	 * special handler APC.
	 */
	if (thread->task == kernel_task) {
		ml_set_interrupts_enabled(FALSE);
		ast_taken(AST_APC, TRUE);
		panic("thread_terminate");
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
thread_hold(
	register thread_t	thread)
{
	if (thread->suspend_count++ == 0) {
		install_special_handler(thread);
		if (thread->started)
			thread_wakeup_one(&thread->suspend_count);
	}
}

/*
 * Decrement internal suspension count, setting thread
 * runnable when count falls to zero.
 *
 * Called with thread mutex held.
 */
void
thread_release(
	register thread_t	thread)
{
	if (	thread->suspend_count > 0		&&
			--thread->suspend_count == 0	) {
		if (thread->started)
			thread_wakeup_one(&thread->suspend_count);
		else {
			thread_start_internal(thread);
		}
	}
}

kern_return_t
thread_suspend(
	register thread_t	thread)
{
	thread_t			self = current_thread();
	kern_return_t		result = KERN_SUCCESS;

	if (thread == THREAD_NULL || thread->task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	thread_mtx_lock(thread);

	if (thread->active) {
		if (	thread->user_stop_count++ == 0		&&
				thread->suspend_count++ == 0		) {
			install_special_handler(thread);
			if (thread != self)
				thread_wakeup_one(&thread->suspend_count);
		}
	}
	else
		result = KERN_TERMINATED;

	thread_mtx_unlock(thread);

	if (thread != self && result == KERN_SUCCESS)
		thread_wait(thread);

	return (result);
}

kern_return_t
thread_resume(
	register thread_t	thread)
{
	kern_return_t		result = KERN_SUCCESS;

	if (thread == THREAD_NULL || thread->task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	thread_mtx_lock(thread);

	if (thread->active) {
		if (thread->user_stop_count > 0) {
			if (	--thread->user_stop_count == 0		&&
					--thread->suspend_count == 0		) {
				if (thread->started)
					thread_wakeup_one(&thread->suspend_count);
				else {
					thread_start_internal(thread);
				}
			}
		}
		else
			result = KERN_FAILURE;
	}
	else
		result = KERN_TERMINATED;

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
	register thread_t	thread)
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
 * Indicate that the activation should run its
 * special handler to detect a condition.
 *
 * Called with thread mutex held.
 */
void
act_abort(
	thread_t	thread)
{
	spl_t		s = splsched();

	thread_lock(thread);

	if (!(thread->sched_mode & TH_MODE_ABORT)) {
		thread->sched_mode |= TH_MODE_ABORT;
		install_special_handler_locked(thread);
	}
	else
		thread->sched_mode &= ~TH_MODE_ABORTSAFELY;

	thread_unlock(thread);
	splx(s);
}
	
kern_return_t
thread_abort(
	register thread_t	thread)
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
			if (!(thread->sched_mode & TH_MODE_ABORT)) {
				thread->sched_mode |= TH_MODE_ISABORTED;
				install_special_handler_locked(thread);
			}
		}
		thread_unlock(thread);
		splx(s);
	}
	else
		result = KERN_TERMINATED;
		
	thread_mtx_unlock(thread);

	return (result);
}

/*** backward compatibility hacks ***/
#include <mach/thread_info.h>
#include <mach/thread_special_ports.h>
#include <ipc/ipc_port.h>

kern_return_t
thread_info(
	thread_t				thread,
	thread_flavor_t			flavor,
	thread_info_t			thread_info_out,
	mach_msg_type_number_t	*thread_info_count)
{
	kern_return_t			result;

	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	thread_mtx_lock(thread);

	if (thread->active)
		result = thread_info_internal(
						thread, flavor, thread_info_out, thread_info_count);
	else
		result = KERN_TERMINATED;

	thread_mtx_unlock(thread);

	return (result);
}

kern_return_t
thread_get_state(
	register thread_t		thread,
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

			if (thread_stop(thread)) {
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
	else
		result = KERN_TERMINATED;

	thread_mtx_unlock(thread);

	return (result);
}

/*
 *	Change thread's machine-dependent state.  Called with nothing
 *	locked.  Returns same way.
 */
kern_return_t
thread_set_state(
	register thread_t		thread,
	int						flavor,
	thread_state_t			state,
	mach_msg_type_number_t	state_count)
{
	kern_return_t		result = KERN_SUCCESS;

	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	thread_mtx_lock(thread);

	if (thread->active) {
		if (thread != current_thread()) {
			thread_hold(thread);

			thread_mtx_unlock(thread);

			if (thread_stop(thread)) {
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

	thread_mtx_unlock(thread);

	return (result);
}
 
 
/*
 * Kernel-internal "thread" interfaces used outside this file:
 */

/* Initialize (or re-initialize) a thread state.  Called from execve
 * with nothing locked, returns same way.
 */
kern_return_t
thread_state_initialize(
	register thread_t		thread)
{
	kern_return_t		result = KERN_SUCCESS;

	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	thread_mtx_lock(thread);

	if (thread->active) {
		if (thread != current_thread()) {
			thread_hold(thread);

			thread_mtx_unlock(thread);

			if (thread_stop(thread)) {
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
	register thread_t	target)
{
	thread_t			self = current_thread();
	kern_return_t		result = KERN_SUCCESS;

	if (target == THREAD_NULL || target == self)
		return (KERN_INVALID_ARGUMENT);

	thread_mtx_lock(target);

	if (target->active) {
		thread_hold(target);

		thread_mtx_unlock(target);

		if (thread_stop(target)) {
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


/*
 *	thread_setstatus:
 *
 *	Set the status of the specified thread.
 *	Called with (and returns with) no locks held.
 */
kern_return_t
thread_setstatus(
	register thread_t		thread,
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
	register thread_t		thread,
	int						flavor,
	thread_state_t			tstate,
	mach_msg_type_number_t	*count)
{
	return (thread_get_state(thread, flavor, tstate, count));
}

/*
 * install_special_handler:
 *
 *	Install the special returnhandler that handles suspension and
 *	termination, if it hasn't been installed already.
 *
 *	Called with the thread mutex held.
 */
void
install_special_handler(
	thread_t		thread)
{
	spl_t		s = splsched();

	thread_lock(thread);
	install_special_handler_locked(thread);
	thread_unlock(thread);
	splx(s);
}

/*
 * install_special_handler_locked:
 *
 *	Do the work of installing the special_handler.
 *
 *	Called with the thread mutex and scheduling lock held.
 */
void
install_special_handler_locked(
	thread_t				thread)
{
	ReturnHandler	**rh;

	/* The work handler must always be the last ReturnHandler on the list,
	   because it can do tricky things like detach the thr_act.  */
	for (rh = &thread->handlers; *rh; rh = &(*rh)->next)
		continue;

	if (rh != &thread->special_handler.next)
		*rh = &thread->special_handler;

	/*
	 * Temporarily undepress, so target has
	 * a chance to do locking required to
	 * block itself in special_handler().
	 */
	if (thread->sched_mode & TH_MODE_ISDEPRESSED)
		compute_priority(thread, TRUE);

	thread_ast_set(thread, AST_APC);

	if (thread == current_thread())
		ast_propagate(thread->ast);
	else {
		processor_t		processor = thread->last_processor;

		if (	processor != PROCESSOR_NULL					&&
				processor->state == PROCESSOR_RUNNING		&&
				processor->active_thread == thread			)
			cause_ast_check(processor);
	}
}

/*
 * Activation control support routines internal to this file:
 */

void
act_execute_returnhandlers(void)
{
	thread_t	thread = current_thread();

	thread_ast_clear(thread, AST_APC);
	spllo();

	for (;;) {
		ReturnHandler	*rh;

		thread_mtx_lock(thread);

		(void)splsched();
		thread_lock(thread);

		rh = thread->handlers;
		if (rh != NULL) {
			thread->handlers = rh->next;

			thread_unlock(thread);
			spllo();

			thread_mtx_unlock(thread);

			/* Execute it */
			(*rh->handler)(rh, thread);
		}
		else
			break;
	}

	thread_unlock(thread);
	spllo();

	thread_mtx_unlock(thread);
}

/*
 * special_handler_continue
 *
 * Continuation routine for the special handler blocks.  It checks
 * to see whether there has been any new suspensions.  If so, it
 * installs the special handler again.  Otherwise, it checks to see
 * if the current depression needs to be re-instated (it may have
 * been temporarily removed in order to get to this point in a hurry).
 */
void
special_handler_continue(void)
{
	thread_t		thread = current_thread();

	thread_mtx_lock(thread);

	if (thread->suspend_count > 0)
		install_special_handler(thread);
	else {
		spl_t			s = splsched();

		thread_lock(thread);
		if (thread->sched_mode & TH_MODE_ISDEPRESSED) {
			processor_t		myprocessor = thread->last_processor;

			thread->sched_pri = DEPRESSPRI;
			myprocessor->current_pri = thread->sched_pri;
			thread->sched_mode &= ~TH_MODE_PREEMPT;
		}
		thread_unlock(thread);
		splx(s);
	}

	thread_mtx_unlock(thread);

	thread_exception_return();
	/*NOTREACHED*/
}

/*
 * special_handler	- handles suspension, termination.  Called
 * with nothing locked.  Returns (if it returns) the same way.
 */
void
special_handler(
	__unused ReturnHandler	*rh,
	thread_t				thread)
{
	spl_t		s;

	thread_mtx_lock(thread);

	s = splsched();
	thread_lock(thread);
	thread->sched_mode &= ~TH_MODE_ISABORTED;
	thread_unlock(thread);
	splx(s);

	/*
	 * If we're suspended, go to sleep and wait for someone to wake us up.
	 */
	if (thread->active) {
		if (thread->suspend_count > 0) {
			if (thread->handlers == NULL) {
				assert_wait(&thread->suspend_count, THREAD_ABORTSAFE);
				thread_mtx_unlock(thread);
				thread_block((thread_continue_t)special_handler_continue);
				/*NOTREACHED*/
			}

			thread_mtx_unlock(thread);

			special_handler_continue();
			/*NOTREACHED*/
		}
	}
	else {
		thread_mtx_unlock(thread);

		thread_terminate_self();
		/*NOTREACHED*/
	}

	thread_mtx_unlock(thread);
}

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

void
act_set_astbsd(
	thread_t	thread)
{
	spl_t		s = splsched();
	
	if (thread == current_thread()) {
		thread_ast_set(thread, AST_BSD);
		ast_propagate(thread->ast);
	}
	else {
		processor_t		processor;

		thread_lock(thread);
		thread_ast_set(thread, AST_BSD);
		processor = thread->last_processor;
		if (	processor != PROCESSOR_NULL					&&
				processor->state == PROCESSOR_RUNNING		&&
				processor->active_thread == thread			)
			cause_ast_check(processor);
		thread_unlock(thread);
	}
	
	splx(s);
}

void
act_set_apc(
	thread_t	thread)
{
	spl_t		s = splsched();
	
	if (thread == current_thread()) {
		thread_ast_set(thread, AST_APC);
		ast_propagate(thread->ast);
	}
	else {
		processor_t		processor;

		thread_lock(thread);
		thread_ast_set(thread, AST_APC);
		processor = thread->last_processor;
		if (	processor != PROCESSOR_NULL					&&
				processor->state == PROCESSOR_RUNNING		&&
				processor->active_thread == thread			)
			cause_ast_check(processor);
		thread_unlock(thread);
	}
	
	splx(s);
}

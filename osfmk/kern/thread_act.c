/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
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
 *	Thread_Activation management routines
 */

#include <cpus.h>
#include <task_swapper.h>
#include <mach/kern_return.h>
#include <mach/alert.h>
#include <kern/etap_macros.h>
#include <kern/mach_param.h>
#include <kern/zalloc.h>
#include <kern/thread.h>
#include <kern/thread_swap.h>
#include <kern/task.h>
#include <kern/task_swap.h>
#include <kern/thread_act.h>
#include <kern/sched_prim.h>
#include <kern/misc_protos.h>
#include <kern/assert.h>
#include <kern/exception.h>
#include <kern/ipc_mig.h>
#include <kern/ipc_tt.h>
#include <kern/profile.h>
#include <kern/machine.h>
#include <kern/spl.h>
#include <kern/syscall_subr.h>
#include <kern/sync_lock.h>
#include <kern/mk_sp.h>	/*** ??? fix so this can be removed ***/
#include <kern/processor.h>
#include <mach_prof.h>
#include <mach/rpc.h>

/*
 * Track the number of times we need to swapin a thread to deallocate it.
 */
int act_free_swapin = 0;

/*
 * Forward declarations for functions local to this file.
 */
kern_return_t	act_abort( thread_act_t, boolean_t);
void		special_handler(ReturnHandler *, thread_act_t);
kern_return_t	act_set_state_locked(thread_act_t, int,
					thread_state_t,
					mach_msg_type_number_t);
kern_return_t	act_get_state_locked(thread_act_t, int,
					thread_state_t,
					mach_msg_type_number_t *);
void		act_set_astbsd(thread_act_t);
void		act_set_apc(thread_act_t);
void		act_ulock_release_all(thread_act_t thr_act);

void		install_special_handler_locked(thread_act_t);

static void		act_disable(thread_act_t);

/*
 * Thread interfaces accessed via a thread_activation:
 */


/*
 * Internal routine to terminate a thread.
 * Sometimes called with task already locked.
 */
kern_return_t
thread_terminate_internal(
	register thread_act_t	act)
{
	kern_return_t	result;
	thread_t		thread;

	thread = act_lock_thread(act);

	if (!act->active) {
		act_unlock_thread(act);
		return (KERN_TERMINATED);
	}

	act_disable(act);
	result = act_abort(act, FALSE);

	/* 
	 * Make sure this thread enters the kernel
	 * Must unlock the act, but leave the shuttle
	 * captured in this act.
	 */
	if (thread != current_thread()) {
		act_unlock(act);

		if (thread_stop(thread))
			thread_unstop(thread);
		else
			result = KERN_ABORTED;

		act_lock(act);
	}

	clear_wait(thread, act->started? THREAD_INTERRUPTED: THREAD_AWAKENED);
	act_unlock_thread(act);

	return (result);
}

/*
 * Terminate a thread.
 */
kern_return_t
thread_terminate(
	register thread_act_t	act)
{
	kern_return_t	result;

	if (act == THR_ACT_NULL)
		return (KERN_INVALID_ARGUMENT);

	if (	act->task == kernel_task	&&
			act != current_act()			)
		return (KERN_FAILURE);

	result = thread_terminate_internal(act);

	/*
	 * If a kernel thread is terminating itself, force an AST here.
	 * Kernel threads don't normally pass through the AST checking
	 * code - and all threads finish their own termination in the
	 * special handler APC.
	 */
	if (act->task == kernel_task) {
		ml_set_interrupts_enabled(FALSE);
		assert(act == current_act());
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
 * Called with act_lock held.
 */
void
thread_hold(
	register thread_act_t	act)
{
	thread_t	thread = act->thread;

	if (act->suspend_count++ == 0) {
		install_special_handler(act);
		if (	act->started				&&
				thread != THREAD_NULL		&&
				thread->top_act == act		)
			thread_wakeup_one(&act->suspend_count);
	}
}

/*
 * Decrement internal suspension count for thr_act, setting thread
 * runnable when count falls to zero.
 *
 * Called with act_lock held.
 */
void
thread_release(
	register thread_act_t	act)
{
	thread_t	thread = act->thread;

	if (	act->suspend_count > 0		&&
			--act->suspend_count == 0	&&
			thread != THREAD_NULL		&&
			thread->top_act == act		) {
		if (!act->started) {
			clear_wait(thread, THREAD_AWAKENED);
			act->started = TRUE;
		}
		else
			thread_wakeup_one(&act->suspend_count);
	}
}

kern_return_t
thread_suspend(
	register thread_act_t	act)
{
	thread_t	thread;

	if (act == THR_ACT_NULL || act->task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	thread = act_lock_thread(act);

	if (!act->active) {
		act_unlock_thread(act);
		return (KERN_TERMINATED);
	}

	if (	act->user_stop_count++ == 0		&&
			act->suspend_count++ == 0		) {
		install_special_handler(act);
		if (	thread != current_thread()		&&
				thread != THREAD_NULL			&&
				thread->top_act == act			) {
			assert(act->started);
			thread_wakeup_one(&act->suspend_count);
			act_unlock_thread(act);

			thread_wait(thread);
		}
		else
			act_unlock_thread(act);
	}
	else
		act_unlock_thread(act);

	return (KERN_SUCCESS);
}

kern_return_t
thread_resume(
	register thread_act_t	act)
{
	kern_return_t	result = KERN_SUCCESS;
	thread_t		thread;

	if (act == THR_ACT_NULL || act->task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	thread = act_lock_thread(act);

	if (act->active) {
		if (act->user_stop_count > 0) {
			if (	--act->user_stop_count == 0		&&
					--act->suspend_count == 0		&&
					thread != THREAD_NULL			&&
					thread->top_act == act			) {
				if (!act->started) {
					clear_wait(thread, THREAD_AWAKENED);
					act->started = TRUE;
				}
				else
					thread_wakeup_one(&act->suspend_count);
			}
		}
		else
			result = KERN_FAILURE;
	}
	else
		result = KERN_TERMINATED;

	act_unlock_thread(act);

	return (result);
}

/*
 *	thread_depress_abort:
 *
 *	Prematurely abort priority depression if there is one.
 */
kern_return_t
thread_depress_abort(
	register thread_act_t	thr_act)
{
    register thread_t		thread;
	kern_return_t			result;

    if (thr_act == THR_ACT_NULL)
		return (KERN_INVALID_ARGUMENT);

    thread = act_lock_thread(thr_act);
    /* if activation is terminating, this operation is not meaningful */
    if (!thr_act->active) {
		act_unlock_thread(thr_act);

		return (KERN_TERMINATED);
    }

    result = _mk_sp_thread_depress_abort(thread, FALSE);

    act_unlock_thread(thr_act);

	return (result);
}


/*
 * Indicate that the activation should run its
 * special handler to detect the condition.
 *
 * Called with act_lock held.
 */
kern_return_t
act_abort(
	thread_act_t	act, 
	boolean_t 	chain_break )
{
	thread_t	thread = act->thread;
	spl_t		s = splsched();

	assert(thread->top_act == act);

	thread_lock(thread);
	if (!(thread->state & TH_ABORT)) {
		thread->state |= TH_ABORT;
		install_special_handler_locked(act);
	} else {
		thread->state &= ~TH_ABORT_SAFELY;
	}
	thread_unlock(thread);
	splx(s);

	return (KERN_SUCCESS);
}
	
kern_return_t
thread_abort(
	register thread_act_t	act)
{
	kern_return_t	result;
	thread_t		thread;

	if (act == THR_ACT_NULL)
		return (KERN_INVALID_ARGUMENT);

	thread = act_lock_thread(act);

	if (!act->active) {
		act_unlock_thread(act);
		return (KERN_TERMINATED);
	}

	result = act_abort(act, FALSE);
	clear_wait(thread, THREAD_INTERRUPTED);
	act_unlock_thread(act);

	return (result);
}

kern_return_t
thread_abort_safely(
	thread_act_t	act)
{
	thread_t		thread;
	kern_return_t	ret;
	spl_t			s;

	if (	act == THR_ACT_NULL )
		return (KERN_INVALID_ARGUMENT);

	thread = act_lock_thread(act);

	if (!act->active) {
		act_unlock_thread(act);
		return (KERN_TERMINATED);
	}

	s = splsched();
	thread_lock(thread);
	if (!thread->at_safe_point ||
		clear_wait_internal(thread, THREAD_INTERRUPTED) != KERN_SUCCESS) {
		if (!(thread->state & TH_ABORT)) {
			thread->state |= (TH_ABORT|TH_ABORT_SAFELY);
			install_special_handler_locked(act);
		}
	}
	thread_unlock(thread);
	splx(s);
		
	act_unlock_thread(act);

	return (KERN_SUCCESS);
}

/*** backward compatibility hacks ***/
#include <mach/thread_info.h>
#include <mach/thread_special_ports.h>
#include <ipc/ipc_port.h>
#include <mach/thread_act_server.h>

kern_return_t
thread_info(
	thread_act_t			thr_act,
	thread_flavor_t			flavor,
	thread_info_t			thread_info_out,
	mach_msg_type_number_t	*thread_info_count)
{
	register thread_t		thread;
	kern_return_t			result;

	if (thr_act == THR_ACT_NULL)
		return (KERN_INVALID_ARGUMENT);

	thread = act_lock_thread(thr_act);
	if (!thr_act->active) {
		act_unlock_thread(thr_act);

		return (KERN_TERMINATED);
	}

	result = thread_info_shuttle(thr_act, flavor,
					thread_info_out, thread_info_count);

	act_unlock_thread(thr_act);

	return (result);
}

/*
 *	Routine:	thread_get_special_port [kernel call]
 *	Purpose:
 *		Clones a send right for one of the thread's
 *		special ports.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Extracted a send right.
 *		KERN_INVALID_ARGUMENT	The thread is null.
 *		KERN_FAILURE		The thread is dead.
 *		KERN_INVALID_ARGUMENT	Invalid special port.
 */

kern_return_t
thread_get_special_port(
	thread_act_t	thr_act,
	int		which,
	ipc_port_t	*portp)
{
	ipc_port_t	*whichp;
	ipc_port_t	port;
	thread_t	thread;

	if (!thr_act)
		return KERN_INVALID_ARGUMENT;
 	thread = act_lock_thread(thr_act);
	switch (which) {
		case THREAD_KERNEL_PORT:
			whichp = &thr_act->ith_sself;
			break;

		default:
			act_unlock_thread(thr_act);
			return KERN_INVALID_ARGUMENT;
	}

	if (!thr_act->active) {
		act_unlock_thread(thr_act);
		return KERN_FAILURE;
	}

	port = ipc_port_copy_send(*whichp);
	act_unlock_thread(thr_act);

	*portp = port;
	return KERN_SUCCESS;
}

/*
 *	Routine:	thread_set_special_port [kernel call]
 *	Purpose:
 *		Changes one of the thread's special ports,
 *		setting it to the supplied send right.
 *	Conditions:
 *		Nothing locked.  If successful, consumes
 *		the supplied send right.
 *	Returns:
 *		KERN_SUCCESS		Changed the special port.
 *		KERN_INVALID_ARGUMENT	The thread is null.
 *		KERN_FAILURE		The thread is dead.
 *		KERN_INVALID_ARGUMENT	Invalid special port.
 */

kern_return_t
thread_set_special_port(
	thread_act_t	thr_act,
	int		which,
	ipc_port_t	port)
{
	ipc_port_t	*whichp;
	ipc_port_t	old;
	thread_t	thread;

	if (thr_act == 0)
		return KERN_INVALID_ARGUMENT;

	thread = act_lock_thread(thr_act);
	switch (which) {
		case THREAD_KERNEL_PORT:
			whichp = &thr_act->ith_self;
			break;

		default:
			act_unlock_thread(thr_act);
			return KERN_INVALID_ARGUMENT;
	}

	if (!thr_act->active) {
		act_unlock_thread(thr_act);
		return KERN_FAILURE;
	}

	old = *whichp;
	*whichp = port;
	act_unlock_thread(thr_act);

	if (IP_VALID(old))
		ipc_port_release_send(old);
	return KERN_SUCCESS;
}

/*
 *  thread state should always be accessible by locking the thread
 *  and copying it.  The activation messes things up so for right
 *  now if it's not the top of the chain, use a special handler to
 *  get the information when the shuttle returns to the activation.
 */
kern_return_t
thread_get_state(
	register thread_act_t	act,
	int						flavor,
	thread_state_t			state,			/* pointer to OUT array */
	mach_msg_type_number_t	*state_count)	/*IN/OUT*/
{
	kern_return_t		result = KERN_SUCCESS;
	thread_t			thread;

	if (act == THR_ACT_NULL || act == current_act())
		return (KERN_INVALID_ARGUMENT);

	thread = act_lock_thread(act);

	if (!act->active) {
		act_unlock_thread(act);
		return (KERN_TERMINATED);
	}

	thread_hold(act);

	for (;;) {
		thread_t			thread1;

		if (	thread == THREAD_NULL		||
				thread->top_act != act		)
			break;
		act_unlock_thread(act);

		if (!thread_stop(thread)) {
			result = KERN_ABORTED;
			(void)act_lock_thread(act);
			thread = THREAD_NULL;
			break;
		}
			
		thread1 = act_lock_thread(act);
		if (thread1 == thread)
			break;

		thread_unstop(thread);
		thread = thread1;
	}

	if (result == KERN_SUCCESS)
		result = machine_thread_get_state(act, flavor, state, state_count);

	if (	thread != THREAD_NULL		&&
			thread->top_act == act		)
		thread_unstop(thread);

	thread_release(act);
	act_unlock_thread(act);

	return (result);
}

/*
 *	Change thread's machine-dependent state.  Called with nothing
 *	locked.  Returns same way.
 */
kern_return_t
thread_set_state(
	register thread_act_t	act,
	int						flavor,
	thread_state_t			state,
	mach_msg_type_number_t	state_count)
{
	kern_return_t		result = KERN_SUCCESS;
	thread_t			thread;

	if (act == THR_ACT_NULL || act == current_act())
		return (KERN_INVALID_ARGUMENT);

	thread = act_lock_thread(act);

	if (!act->active) {
		act_unlock_thread(act);
		return (KERN_TERMINATED);
	}

	thread_hold(act);

	for (;;) {
		thread_t			thread1;

		if (	thread == THREAD_NULL		||
				thread->top_act != act		)
			break;
		act_unlock_thread(act);

		if (!thread_stop(thread)) {
			result = KERN_ABORTED;
			(void)act_lock_thread(act);
			thread = THREAD_NULL;
			break;
		}

		thread1 = act_lock_thread(act);
		if (thread1 == thread)
			break;

		thread_unstop(thread);
		thread = thread1;
	}

	if (result == KERN_SUCCESS)
		result = machine_thread_set_state(act, flavor, state, state_count);

	if (	thread != THREAD_NULL		&&
			thread->top_act == act		)
	    thread_unstop(thread);

	thread_release(act);
	act_unlock_thread(act);

	return (result);
}

/*
 * Kernel-internal "thread" interfaces used outside this file:
 */

kern_return_t
thread_dup(
	register thread_act_t	target)
{
	kern_return_t		result = KERN_SUCCESS;
	thread_act_t		self = current_act();
	thread_t			thread;

	if (target == THR_ACT_NULL || target == self)
		return (KERN_INVALID_ARGUMENT);

	thread = act_lock_thread(target);

	if (!target->active) {
		act_unlock_thread(target);
		return (KERN_TERMINATED);
	}

	thread_hold(target);

	for (;;) {
		thread_t			thread1;

		if (	thread == THREAD_NULL		||
				thread->top_act != target	)
			break;
		act_unlock_thread(target);

		if (!thread_stop(thread)) {
			result = KERN_ABORTED;
			(void)act_lock_thread(target);
			thread = THREAD_NULL;
			break;
		}

		thread1 = act_lock_thread(target);
		if (thread1 == thread)
			break;

		thread_unstop(thread);
		thread = thread1;
	}

	if (result == KERN_SUCCESS)
		result = machine_thread_dup(self, target);

	if (	thread != THREAD_NULL		&&
			thread->top_act == target	)
	    thread_unstop(thread);

	thread_release(target);
	act_unlock_thread(target);

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
	register thread_act_t	act,
	int						flavor,
	thread_state_t			tstate,
	mach_msg_type_number_t	count)
{
	kern_return_t		result = KERN_SUCCESS;
	thread_t			thread;

	thread = act_lock_thread(act);

	if (	act != current_act()			&&
			(act->suspend_count == 0	||
			 thread == THREAD_NULL		||
			 (thread->state & TH_RUN)	||
			 thread->top_act != act)		)
		result = KERN_FAILURE;

	if (result == KERN_SUCCESS)
		result = machine_thread_set_state(act, flavor, tstate, count);

	act_unlock_thread(act);

	return (result);
}

/*
 *	thread_getstatus:
 *
 *	Get the status of the specified thread.
 */
kern_return_t
thread_getstatus(
	register thread_act_t	act,
	int						flavor,
	thread_state_t			tstate,
	mach_msg_type_number_t	*count)
{
	kern_return_t		result = KERN_SUCCESS;
	thread_t			thread;

	thread = act_lock_thread(act);

	if (	act != current_act()			&&
			(act->suspend_count == 0	||
			 thread == THREAD_NULL		||
			 (thread->state & TH_RUN)	||
			 thread->top_act != act)		)
		result = KERN_FAILURE;

	if (result == KERN_SUCCESS)
		result = machine_thread_get_state(act, flavor, tstate, count);

	act_unlock_thread(act);

	return (result);
}

/*
 * Kernel-internal thread_activation interfaces used outside this file:
 */

void
act_reference(
	thread_act_t	act)
{
	if (act == NULL)
		return;

	act_lock(act);
	act_reference_locked(act);
	act_unlock(act);
}

void
act_deallocate(
	thread_act_t	act)
{
	task_t		task;
	thread_t	thread;
	void		*task_proc;

	if (act == NULL)
		return;

	act_lock(act);

	if (--act->act_ref_count > 0) {
		act_unlock(act);
		return;
	}

	assert(!act->active);

	thread = act->thread;
	assert(thread != NULL);

	thread->top_act = NULL;

	act_unlock(act);

	task = act->task;
	task_lock(task);

	task_proc = task->bsd_info;

	{
		time_value_t	user_time, system_time;

		thread_read_times(thread, &user_time, &system_time);
		time_value_add(&task->total_user_time, &user_time);
		time_value_add(&task->total_system_time, &system_time);
	
		queue_remove(&task->threads, act, thread_act_t, task_threads);
		act->task_threads.next = NULL;
		task->thread_count--;
		task->res_thread_count--;
	}

	task_unlock(task);

	act_prof_deallocate(act);
	ipc_thr_act_terminate(act);

#ifdef MACH_BSD 
	{
		extern void uthread_free(task_t, void *, void *);
		void *ut = act->uthread;

		act->uthread = NULL;
		uthread_free(task, ut, task_proc);
	}
#endif  /* MACH_BSD */   

	task_deallocate(task);

	thread_deallocate(thread);
}


/*
 * act_attach	- Attach an thr_act to the top of a thread ("push the stack").
 *
 * The thread_shuttle must be either the current one or a brand-new one.
 * Assumes the thr_act is active but not in use.
 *
 * Already locked: thr_act plus "appropriate" thread-related locks
 * (see act_lock_thread()).
 */
void 
act_attach(
	thread_act_t		act,
	thread_t			thread)
{
	thread_act_t    lower;

	/* 
	 *	Chain the act onto the thread's act stack.  
	 */
	act->act_ref_count++;
	act->thread = thread;
	act->higher = THR_ACT_NULL;
	lower = act->lower = thread->top_act;
	if (lower != THR_ACT_NULL)
		lower->higher = act;

	thread->top_act = act;
}

/*
 * 	act_detach	
 *
 *	Remove the current thr_act from the top of the current thread, i.e.
 *	"pop the stack". Assumes already locked: thr_act plus "appropriate"
 * 	thread-related locks (see act_lock_thread).
 */
void 
act_detach(
	thread_act_t	cur_act)
{
	thread_t	cur_thread = cur_act->thread;

	/* Unlink the thr_act from the thread's thr_act stack */
	cur_thread->top_act = cur_act->lower;
	cur_act->thread = 0;
	cur_act->act_ref_count--;
	assert(cur_act->act_ref_count > 0);

#if	MACH_ASSERT
	cur_act->lower = cur_act->higher = THR_ACT_NULL; 
	if (cur_thread->top_act)
		cur_thread->top_act->higher = THR_ACT_NULL;
#endif	/* MACH_ASSERT */

	return;
}


/*
 * Synchronize a thread operation with migration.
 * Called with nothing locked.
 * Returns with thr_act locked.
 */
thread_t
act_lock_thread(
	thread_act_t thr_act)
{

	/*
	 * JMM - We have moved away from explicit RPC locks
	 * and towards a generic migration approach.  The wait
	 * queue lock will be the point of synchronization for
	 * the shuttle linkage when this is rolled out.  Until
	 * then, just lock the act.
	 */
	act_lock(thr_act);
	return (thr_act->thread);
}

/*
 * Unsynchronize with migration (i.e., undo an act_lock_thread() call).
 * Called with thr_act locked, plus thread locks held that are
 * "correct" for thr_act's state.  Returns with nothing locked.
 */
void
act_unlock_thread(thread_act_t	thr_act)
{
	act_unlock(thr_act);
}

/*
 * Synchronize with migration given a pointer to a shuttle (instead of an
 * activation).  Called with nothing locked; returns with all
 * "appropriate" thread-related locks held (see act_lock_thread()).
 */
thread_act_t
thread_lock_act(
	thread_t	thread)
{
	thread_act_t	thr_act;

	while (1) {
		thr_act = thread->top_act;
		if (!thr_act)
			break;
		if (!act_lock_try(thr_act)) {
			mutex_pause();
			continue;
		}
		break;
	}
	return (thr_act);
}

/*
 * Unsynchronize with an activation starting from a pointer to
 * a shuttle.
 */
void
thread_unlock_act(
	thread_t	thread)
{
	thread_act_t 	thr_act;

	if (thr_act = thread->top_act) {
		act_unlock(thr_act);
	}
}

/*
 * switch_act
 *
 * If a new activation is given, switch to it. If not,
 * switch to the lower activation (pop). Returns the old
 * activation. This is for migration support.
 */
thread_act_t
switch_act( 
	thread_act_t act)
{
	thread_act_t	old, new;
	thread_t		thread;

	disable_preemption();

	thread  = current_thread();

	/*
	 *	Find the old and new activation for switch.
	 */
	old = thread->top_act;

	if (act) {
		new = act;
                new->thread = thread;
	}
	else {
		new = old->lower;
	}

	assert(new != THR_ACT_NULL);
	assert(current_processor()->active_thread == thread);

	/* This is where all the work happens */
	machine_switch_act(thread, old, new);

	/*
	 *	Push or pop an activation on the chain.
	 */
	if (act) {
		act_attach(new, thread);
	}
	else {
		act_detach(old);
	}

        enable_preemption();

	return(old);
}

/*
 * install_special_handler
 *	Install the special returnhandler that handles suspension and
 *	termination, if it hasn't been installed already.
 *
 * Already locked: RPC-related locks for thr_act, but not
 * scheduling lock (thread_lock()) of the associated thread.
 */
void
install_special_handler(
	thread_act_t	thr_act)
{
	spl_t		spl;
	thread_t	thread = thr_act->thread;

	spl = splsched();
	thread_lock(thread);
	install_special_handler_locked(thr_act);
	thread_unlock(thread);
	splx(spl);
}

/*
 * install_special_handler_locked
 *	Do the work of installing the special_handler.
 *
 * Already locked: RPC-related locks for thr_act, plus the
 * scheduling lock (thread_lock()) of the associated thread.
 */
void
install_special_handler_locked(
	thread_act_t				act)
{
	thread_t		thread = act->thread;
	ReturnHandler	**rh;

	/* The work handler must always be the last ReturnHandler on the list,
	   because it can do tricky things like detach the thr_act.  */
	for (rh = &act->handlers; *rh; rh = &(*rh)->next)
		continue;
	if (rh != &act->special_handler.next)
		*rh = &act->special_handler;

	if (act == thread->top_act) {
		/*
		 * Temporarily undepress, so target has
		 * a chance to do locking required to
		 * block itself in special_handler().
		 */
		if (thread->sched_mode & TH_MODE_ISDEPRESSED)
			compute_priority(thread, TRUE);
	}

	thread_ast_set(act, AST_APC);
	if (act == current_act())
		ast_propagate(act->ast);
	else {
		processor_t		processor = thread->last_processor;

		if (	processor != PROCESSOR_NULL					&&
				processor->state == PROCESSOR_RUNNING		&&
				processor->active_thread == thread			)
			cause_ast_check(processor);
	}
}

kern_return_t
thread_apc_set(
	thread_act_t 			act,
	thread_apc_handler_t	apc)
{
	extern thread_apc_handler_t	bsd_ast;

	assert(apc == bsd_ast);
	return (KERN_FAILURE);
}

kern_return_t
thread_apc_clear(
	thread_act_t 			act,
	thread_apc_handler_t	apc)
{
	extern thread_apc_handler_t	bsd_ast;

	assert(apc == bsd_ast);
	return (KERN_FAILURE);
}

/*
 * Activation control support routines internal to this file:
 */

/*
 * act_execute_returnhandlers()	- does just what the name says
 *
 * This is called by system-dependent code when it detects that
 * thr_act->handlers is non-null while returning into user mode.
 */
void
act_execute_returnhandlers(void)
{
	thread_act_t	act = current_act();

	thread_ast_clear(act, AST_APC);
	spllo();

	for (;;) {
		ReturnHandler	*rh;
		thread_t		thread = act_lock_thread(act);

		(void)splsched();
		thread_lock(thread);
		rh = act->handlers;
		if (!rh) {
			thread_unlock(thread);
			spllo();
			act_unlock_thread(act);
			return;
		}
		act->handlers = rh->next;
		thread_unlock(thread);
		spllo();
		act_unlock_thread(act);

		/* Execute it */
		(*rh->handler)(rh, act);
	}
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
	thread_act_t		self = current_act();

	if (self->suspend_count > 0)
		install_special_handler(self);
	else {
		thread_t		thread = self->thread;
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

	thread_exception_return();
	/*NOTREACHED*/
}

/*
 * special_handler	- handles suspension, termination.  Called
 * with nothing locked.  Returns (if it returns) the same way.
 */
void
special_handler(
	ReturnHandler	*rh,
	thread_act_t	self)
{
	thread_t		thread = act_lock_thread(self);
	spl_t			s;

	assert(thread != THREAD_NULL);

	s = splsched();
	thread_lock(thread);
	thread->state &= ~(TH_ABORT|TH_ABORT_SAFELY);	/* clear any aborts */
	thread_unlock(thread);
	splx(s);

	if (!self->active) {
		act_unlock_thread(self);
		thread_terminate_self();
		/*NOTREACHED*/
	}

	/*
	 * If we're suspended, go to sleep and wait for someone to wake us up.
	 */
	if (self->suspend_count > 0) {
		if (self->handlers == NULL) {
			assert_wait(&self->suspend_count, THREAD_ABORTSAFE);
			act_unlock_thread(self);
			thread_block(special_handler_continue);
			/*NOTREACHED*/
		}

		act_unlock_thread(self);

		special_handler_continue();
		/*NOTREACHED*/
	}

	act_unlock_thread(self);
}

/*
 * Already locked: activation (shuttle frozen within)
 *
 * Mark an activation inactive, and prepare it to terminate
 * itself.
 */
static void
act_disable(
	thread_act_t	thr_act)
{
	thr_act->active = 0;

	/* Drop the thr_act reference taken for being active.
	 * (There is still at least one reference left:
	 * the one we were passed.)
	 * Inline the deallocate because thr_act is locked.
	 */
	act_deallocate_locked(thr_act);
}

typedef struct GetSetState {
	struct ReturnHandler rh;
	int flavor;
	void *state;
	int *pcount;
	int result;
} GetSetState;

/* Local Forward decls */
kern_return_t get_set_state(
			thread_act_t thr_act, int flavor,
			thread_state_t state, int *pcount,
			void (*handler)(ReturnHandler *rh, thread_act_t thr_act));
void get_state_handler(ReturnHandler *rh, thread_act_t thr_act);
void set_state_handler(ReturnHandler *rh, thread_act_t thr_act);

/*
 * get_set_state(thr_act ...)
 *
 * General code to install g/set_state handler.
 * Called with thr_act's act_lock() and "appropriate"
 * thread-related locks held.  (See act_lock_thread().)
 */
kern_return_t
get_set_state(
	thread_act_t		act,
	int					flavor,
	thread_state_t		state,
	int					*pcount,
	void				(*handler)(
							ReturnHandler	*rh,
							thread_act_t	 act))
{
	GetSetState			gss;

	/* Initialize a small parameter structure */
	gss.rh.handler = handler;
	gss.flavor = flavor;
	gss.state = state;
	gss.pcount = pcount;
	gss.result = KERN_ABORTED;	/* iff wait below is interrupted */

	/* Add it to the thr_act's return handler list */
	gss.rh.next = act->handlers;
	act->handlers = &gss.rh;

	act_set_apc(act);

	assert(act->thread);
	assert(act != current_act());

	for (;;) {
		wait_result_t		result;

		if (	act->started					&&
				act->thread->top_act == act		)
				thread_wakeup_one(&act->suspend_count);

		/*
		 * Wait must be interruptible to avoid deadlock (e.g.) with
		 * task_suspend() when caller and target of get_set_state()
		 * are in same task.
		 */
		result = assert_wait(&gss, THREAD_ABORTSAFE);
		act_unlock_thread(act);

		if (result == THREAD_WAITING)
			result = thread_block(THREAD_CONTINUE_NULL);

		assert(result != THREAD_WAITING);

		if (gss.result != KERN_ABORTED) {
			assert(result != THREAD_INTERRUPTED);
			break;
		}

		/* JMM - What about other aborts (like BSD signals)? */
		if (current_act()->handlers)
			act_execute_returnhandlers();

		act_lock_thread(act);
	}

	return (gss.result);
}

void
set_state_handler(ReturnHandler *rh, thread_act_t thr_act)
{
	GetSetState *gss = (GetSetState*)rh;

	gss->result = machine_thread_set_state(thr_act, gss->flavor,
						gss->state, *gss->pcount);
	thread_wakeup((event_t)gss);
}

void
get_state_handler(ReturnHandler *rh, thread_act_t thr_act)
{
	GetSetState *gss = (GetSetState*)rh;

	gss->result = machine_thread_get_state(thr_act, gss->flavor,
			gss->state, 
			(mach_msg_type_number_t *) gss->pcount);
	thread_wakeup((event_t)gss);
}

kern_return_t
act_get_state_locked(thread_act_t thr_act, int flavor, thread_state_t state,
					mach_msg_type_number_t *pcount)
{
    return(get_set_state(thr_act, flavor, state, (int*)pcount, get_state_handler));
}

kern_return_t
act_set_state_locked(thread_act_t thr_act, int flavor, thread_state_t state,
					mach_msg_type_number_t count)
{
    return(get_set_state(thr_act, flavor, state, (int*)&count, set_state_handler));
}

kern_return_t
act_set_state(thread_act_t thr_act, int flavor, thread_state_t state,
					mach_msg_type_number_t count)
{
    if (thr_act == THR_ACT_NULL || thr_act == current_act())
	    return(KERN_INVALID_ARGUMENT);

    act_lock_thread(thr_act);
    return(act_set_state_locked(thr_act, flavor, state, count));
    
}

kern_return_t
act_get_state(thread_act_t thr_act, int flavor, thread_state_t state,
					mach_msg_type_number_t *pcount)
{
    if (thr_act == THR_ACT_NULL || thr_act == current_act())
	    return(KERN_INVALID_ARGUMENT);

    act_lock_thread(thr_act);
    return(act_get_state_locked(thr_act, flavor, state, pcount));
}

void
act_set_astbsd(
	thread_act_t	act)
{
	spl_t			s = splsched();
	
	if (act == current_act()) {
		thread_ast_set(act, AST_BSD);
		ast_propagate(act->ast);
	}
	else {
		thread_t		thread = act->thread;
		processor_t		processor;

		thread_lock(thread);
		thread_ast_set(act, AST_BSD);
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
	thread_act_t	act)
{
	spl_t			s = splsched();
	
	if (act == current_act()) {
		thread_ast_set(act, AST_APC);
		ast_propagate(act->ast);
	}
	else {
		thread_t		thread = act->thread;
		processor_t		processor;

		thread_lock(thread);
		thread_ast_set(act, AST_APC);
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
act_ulock_release_all(thread_act_t thr_act)
{
	ulock_t	ulock;

	while (!queue_empty(&thr_act->held_ulocks)) {
		ulock = (ulock_t) queue_first(&thr_act->held_ulocks);
		(void) lock_make_unstable(ulock, thr_act);
		(void) lock_release_internal(ulock, thr_act);
	}
}

/*
 * Provide routines (for export to other components) of things that
 * are implemented as macros insternally.
 */
thread_act_t
thread_self(void)
{
	thread_act_t self = current_act_fast();

	act_reference(self);
	return self;
}

thread_act_t
mach_thread_self(void)
{
	thread_act_t self = current_act_fast();

	act_reference(self);
	return self;
}

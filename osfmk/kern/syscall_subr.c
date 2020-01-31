/*
 * Copyright (c) 2000-2017 Apple Inc. All rights reserved.
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
#include <kern/policy_internal.h>

#include <mach/policy.h>

#include <kern/syscall_subr.h>
#include <mach/mach_host_server.h>
#include <mach/mach_syscalls.h>
#include <sys/kdebug.h>
#include <kern/ast.h>

static void thread_depress_abstime(uint64_t interval);
static void thread_depress_ms(mach_msg_timeout_t interval);

/* Called from commpage to take a delayed preemption when exiting
 * the "Preemption Free Zone" (PFZ).
 */
kern_return_t
pfz_exit(
	__unused        struct pfz_exit_args *args)
{
	/* For now, nothing special to do.  We'll pick up the ASTs on kernel exit. */

	return KERN_SUCCESS;
}


/*
 *	swtch and swtch_pri both attempt to context switch (logic in
 *	thread_block no-ops the context switch if nothing would happen).
 *	A boolean is returned that indicates whether there is anything
 *	else runnable.  That's no excuse to spin, though.
 */

static void
swtch_continue(void)
{
	processor_t     myprocessor;
	boolean_t       result;

	disable_preemption();
	myprocessor = current_processor();
	result = SCHED(thread_should_yield)(myprocessor, current_thread());
	enable_preemption();

	ml_delay_on_yield();

	thread_syscall_return(result);
	/*NOTREACHED*/
}

boolean_t
swtch(
	__unused struct swtch_args *args)
{
	processor_t     myprocessor;

	disable_preemption();
	myprocessor = current_processor();
	if (!SCHED(thread_should_yield)(myprocessor, current_thread())) {
		mp_enable_preemption();

		return FALSE;
	}
	enable_preemption();

	counter(c_swtch_block++);

	thread_yield_with_continuation((thread_continue_t)swtch_continue, NULL);
}

static void
swtch_pri_continue(void)
{
	processor_t     myprocessor;
	boolean_t       result;

	thread_depress_abort(current_thread());

	disable_preemption();
	myprocessor = current_processor();
	result = SCHED(thread_should_yield)(myprocessor, current_thread());
	mp_enable_preemption();

	ml_delay_on_yield();

	thread_syscall_return(result);
	/*NOTREACHED*/
}

boolean_t
swtch_pri(
	__unused        struct swtch_pri_args *args)
{
	processor_t     myprocessor;

	disable_preemption();
	myprocessor = current_processor();
	if (!SCHED(thread_should_yield)(myprocessor, current_thread())) {
		mp_enable_preemption();

		return FALSE;
	}
	enable_preemption();

	counter(c_swtch_pri_block++);

	thread_depress_abstime(thread_depress_time);

	thread_yield_with_continuation((thread_continue_t)swtch_pri_continue, NULL);
}

static void
thread_switch_continue(void *parameter, __unused int ret)
{
	thread_t self = current_thread();
	int option = (int)(intptr_t)parameter;

	if (option == SWITCH_OPTION_DEPRESS || option == SWITCH_OPTION_OSLOCK_DEPRESS) {
		thread_depress_abort(self);
	}

	ml_delay_on_yield();

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
	thread_t                        thread = THREAD_NULL;
	thread_t                        self = current_thread();
	mach_port_name_t                thread_name = args->thread_name;
	int                                             option = args->option;
	mach_msg_timeout_t              option_time = args->option_time;
	uint32_t                                scale_factor = NSEC_PER_MSEC;
	boolean_t                               depress_option = FALSE;
	boolean_t                               wait_option = FALSE;
	wait_interrupt_t                interruptible = THREAD_ABORTSAFE;

	/*
	 *	Validate and process option.
	 */
	switch (option) {
	case SWITCH_OPTION_NONE:
		break;
	case SWITCH_OPTION_WAIT:
		wait_option = TRUE;
		break;
	case SWITCH_OPTION_DEPRESS:
		depress_option = TRUE;
		break;
	case SWITCH_OPTION_DISPATCH_CONTENTION:
		scale_factor = NSEC_PER_USEC;
		wait_option = TRUE;
		interruptible |= THREAD_WAIT_NOREPORT;
		break;
	case SWITCH_OPTION_OSLOCK_DEPRESS:
		depress_option = TRUE;
		interruptible |= THREAD_WAIT_NOREPORT;
		break;
	case SWITCH_OPTION_OSLOCK_WAIT:
		wait_option = TRUE;
		interruptible |= THREAD_WAIT_NOREPORT;
		break;
	default:
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * Translate the port name if supplied.
	 */
	if (thread_name != MACH_PORT_NULL) {
		ipc_port_t port;

		if (ipc_port_translate_send(self->task->itk_space,
		    thread_name, &port) == KERN_SUCCESS) {
			ip_reference(port);
			ip_unlock(port);

			thread = convert_port_to_thread(port);
			ip_release(port);

			if (thread == self) {
				thread_deallocate(thread);
				thread = THREAD_NULL;
			}
		}
	}

	if (option == SWITCH_OPTION_OSLOCK_DEPRESS || option == SWITCH_OPTION_OSLOCK_WAIT) {
		if (thread != THREAD_NULL) {
			if (thread->task != self->task) {
				/*
				 * OSLock boosting only applies to other threads
				 * in your same task (even if you have a port for
				 * a thread in another task)
				 */

				thread_deallocate(thread);
				thread = THREAD_NULL;
			} else {
				/*
				 * Attempt to kick the lock owner up to our same IO throttling tier.
				 * If the thread is currently blocked in throttle_lowpri_io(),
				 * it will immediately break out.
				 *
				 * TODO: SFI break out?
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
		spl_t s = splsched();

		/* This may return a different thread if the target is pushing on something */
		thread_t pulled_thread = thread_run_queue_remove_for_handoff(thread);

		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_THREAD_SWITCH) | DBG_FUNC_NONE,
		    thread_tid(thread), thread->state,
		    pulled_thread ? TRUE : FALSE, 0, 0);

		if (pulled_thread != THREAD_NULL) {
			/* We can't be dropping the last ref here */
			thread_deallocate_safe(thread);

			if (wait_option) {
				assert_wait_timeout((event_t)assert_wait_timeout, interruptible,
				    option_time, scale_factor);
			} else if (depress_option) {
				thread_depress_ms(option_time);
			}

			thread_run(self, thread_switch_continue, (void *)(intptr_t)option, pulled_thread);
			__builtin_unreachable();
		}

		splx(s);

		thread_deallocate(thread);
	}

	if (wait_option) {
		assert_wait_timeout((event_t)assert_wait_timeout, interruptible, option_time, scale_factor);
	} else {
		disable_preemption();
		bool should_yield = SCHED(thread_should_yield)(current_processor(), current_thread());
		enable_preemption();

		if (should_yield == false) {
			/* Early-return if yielding to the scheduler will not be beneficial */
			return KERN_SUCCESS;
		}

		if (depress_option) {
			thread_depress_ms(option_time);
		}
	}

	thread_yield_with_continuation(thread_switch_continue, (void *)(intptr_t)option);
	__builtin_unreachable();
}

void
thread_yield_with_continuation(
	thread_continue_t       continuation,
	void                            *parameter)
{
	assert(continuation);
	thread_block_reason(continuation, parameter, AST_YIELD);
	__builtin_unreachable();
}


/* Returns a +1 thread reference */
thread_t
port_name_to_thread_for_ulock(mach_port_name_t thread_name)
{
	thread_t thread = THREAD_NULL;
	thread_t self = current_thread();

	/*
	 * Translate the port name if supplied.
	 */
	if (thread_name != MACH_PORT_NULL) {
		ipc_port_t port;

		if (ipc_port_translate_send(self->task->itk_space,
		    thread_name, &port) == KERN_SUCCESS) {
			ip_reference(port);
			ip_unlock(port);

			thread = convert_port_to_thread(port);
			ip_release(port);

			if (thread == THREAD_NULL) {
				return thread;
			}

			if ((thread == self) || (thread->task != self->task)) {
				thread_deallocate(thread);
				thread = THREAD_NULL;
			}
		}
	}

	return thread;
}

/* This function is called after an assert_wait(), therefore it must not
 * cause another wait until after the thread_run() or thread_block()
 *
 *
 * When called with a NULL continuation, the thread ref is consumed
 * (thread_handoff_deallocate calling convention) else it is up to the
 * continuation to do the cleanup (thread_handoff_parameter calling convention)
 * and it instead doesn't return.
 */
static wait_result_t
thread_handoff_internal(thread_t thread, thread_continue_t continuation,
    void *parameter)
{
	thread_t deallocate_thread = THREAD_NULL;
	thread_t self = current_thread();

	/*
	 * Try to handoff if supplied.
	 */
	if (thread != THREAD_NULL) {
		spl_t s = splsched();

		thread_t pulled_thread = thread_run_queue_remove_for_handoff(thread);

		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_THREAD_SWITCH) | DBG_FUNC_NONE,
		    thread_tid(thread), thread->state,
		    pulled_thread ? TRUE : FALSE, 0, 0);

		if (pulled_thread != THREAD_NULL) {
			if (continuation == NULL) {
				/* We can't be dropping the last ref here */
				thread_deallocate_safe(thread);
			}

			int result = thread_run(self, continuation, parameter, pulled_thread);

			splx(s);
			return result;
		}

		splx(s);

		deallocate_thread = thread;
		thread = THREAD_NULL;
	}

	int result = thread_block_parameter(continuation, parameter);
	if (deallocate_thread != THREAD_NULL) {
		thread_deallocate(deallocate_thread);
	}

	return result;
}

void
thread_handoff_parameter(thread_t thread, thread_continue_t continuation,
    void *parameter)
{
	thread_handoff_internal(thread, continuation, parameter);
	panic("NULL continuation passed to %s", __func__);
	__builtin_unreachable();
}

wait_result_t
thread_handoff_deallocate(thread_t thread)
{
	return thread_handoff_internal(thread, NULL, NULL);
}

/*
 * Thread depression
 *
 * This mechanism drops a thread to priority 0 in order for it to yield to
 * all other runnnable threads on the system.  It can be canceled or timed out,
 * whereupon the thread goes back to where it was.
 *
 * Note that TH_SFLAG_DEPRESS and TH_SFLAG_POLLDEPRESS are never set at the
 * same time.  DEPRESS always defers to POLLDEPRESS.
 *
 * DEPRESS only lasts across a single thread_block call, and never returns
 * to userspace.
 * POLLDEPRESS can be active anywhere up until thread termination.
 */

/*
 * Depress thread's priority to lowest possible for the specified interval,
 * with an interval of zero resulting in no timeout being scheduled.
 *
 * Must block with AST_YIELD afterwards to take effect
 */
void
thread_depress_abstime(uint64_t interval)
{
	thread_t self = current_thread();

	spl_t s = splsched();
	thread_lock(self);

	assert((self->sched_flags & TH_SFLAG_DEPRESS) == 0);

	if ((self->sched_flags & TH_SFLAG_POLLDEPRESS) == 0) {
		self->sched_flags |= TH_SFLAG_DEPRESS;
		thread_recompute_sched_pri(self, SETPRI_LAZY);

		if (interval != 0) {
			uint64_t deadline;

			clock_absolutetime_interval_to_deadline(interval, &deadline);
			if (!timer_call_enter(&self->depress_timer, deadline, TIMER_CALL_USER_CRITICAL)) {
				self->depress_timer_active++;
			}
		}
	}

	thread_unlock(self);
	splx(s);
}

void
thread_depress_ms(mach_msg_timeout_t interval)
{
	uint64_t abstime;

	clock_interval_to_absolutetime_interval(interval, NSEC_PER_MSEC, &abstime);
	thread_depress_abstime(abstime);
}

/*
 *	Priority depression expiration.
 */
void
thread_depress_expire(void      *p0,
    __unused void      *p1)
{
	thread_t thread = (thread_t)p0;

	spl_t s = splsched();
	thread_lock(thread);

	assert((thread->sched_flags & TH_SFLAG_DEPRESSED_MASK) != TH_SFLAG_DEPRESSED_MASK);

	if (--thread->depress_timer_active == 0) {
		thread->sched_flags &= ~TH_SFLAG_DEPRESSED_MASK;
		thread_recompute_sched_pri(thread, SETPRI_DEFAULT);
	}

	thread_unlock(thread);
	splx(s);
}

/*
 * Prematurely abort priority depression if there is one.
 */
kern_return_t
thread_depress_abort(thread_t thread)
{
	kern_return_t result = KERN_NOT_DEPRESSED;

	spl_t s = splsched();
	thread_lock(thread);

	assert((thread->sched_flags & TH_SFLAG_DEPRESSED_MASK) != TH_SFLAG_DEPRESSED_MASK);

	/*
	 * User-triggered depress-aborts should not get out
	 * of the poll-depress, but they should cancel a regular depress.
	 */
	if ((thread->sched_flags & TH_SFLAG_POLLDEPRESS) == 0) {
		result = thread_depress_abort_locked(thread);
	}

	thread_unlock(thread);
	splx(s);

	return result;
}

/*
 * Prematurely abort priority depression or poll depression if one is active.
 * Called with the thread locked.
 */
kern_return_t
thread_depress_abort_locked(thread_t thread)
{
	if ((thread->sched_flags & TH_SFLAG_DEPRESSED_MASK) == 0) {
		return KERN_NOT_DEPRESSED;
	}

	assert((thread->sched_flags & TH_SFLAG_DEPRESSED_MASK) != TH_SFLAG_DEPRESSED_MASK);

	thread->sched_flags &= ~TH_SFLAG_DEPRESSED_MASK;

	thread_recompute_sched_pri(thread, SETPRI_LAZY);

	if (timer_call_cancel(&thread->depress_timer)) {
		thread->depress_timer_active--;
	}

	return KERN_SUCCESS;
}

/*
 * Invoked as part of a polling operation like a no-timeout port receive
 *
 * Forces a fixpri thread to yield if it is detected polling without blocking for too long.
 */
void
thread_poll_yield(thread_t self)
{
	assert(self == current_thread());
	assert((self->sched_flags & TH_SFLAG_DEPRESS) == 0);

	if (self->sched_mode != TH_MODE_FIXED) {
		return;
	}

	spl_t s = splsched();

	uint64_t abstime = mach_absolute_time();
	uint64_t total_computation = abstime -
	    self->computation_epoch + self->computation_metered;

	if (total_computation >= max_poll_computation) {
		thread_lock(self);

		self->computation_epoch   = abstime;
		self->computation_metered = 0;

		uint64_t yield_expiration = abstime +
		    (total_computation >> sched_poll_yield_shift);

		if (!timer_call_enter(&self->depress_timer, yield_expiration,
		    TIMER_CALL_USER_CRITICAL)) {
			self->depress_timer_active++;
		}

		self->sched_flags |= TH_SFLAG_POLLDEPRESS;
		thread_recompute_sched_pri(self, SETPRI_DEFAULT);

		thread_unlock(self);
	}
	splx(s);
}

/*
 * Kernel-internal interface to yield for a specified period
 *
 * WARNING: Will still yield to priority 0 even if the thread is holding a contended lock!
 */
void
thread_yield_internal(mach_msg_timeout_t ms)
{
	thread_t self = current_thread();

	assert((self->sched_flags & TH_SFLAG_DEPRESSED_MASK) != TH_SFLAG_DEPRESSED_MASK);

	processor_t     myprocessor;

	disable_preemption();
	myprocessor = current_processor();
	if (!SCHED(thread_should_yield)(myprocessor, self)) {
		mp_enable_preemption();

		return;
	}
	enable_preemption();

	thread_depress_ms(ms);

	thread_block_reason(THREAD_CONTINUE_NULL, NULL, AST_YIELD);

	thread_depress_abort(self);
}

/*
 * This yields to a possible non-urgent preemption pending on the current processor.
 *
 * This is useful when doing a long computation in the kernel without returning to userspace.
 *
 * As opposed to other yielding mechanisms, this does not drop the priority of the current thread.
 */
void
thread_yield_to_preemption()
{
	/*
	 * ast_pending() should ideally be called with interrupts disabled, but
	 * the check here is fine because csw_check() will do the right thing.
	 */
	ast_t *pending_ast = ast_pending();
	ast_t ast = AST_NONE;
	processor_t p;

	if (*pending_ast & AST_PREEMPT) {
		thread_t self = current_thread();

		spl_t s = splsched();

		p = current_processor();
		thread_lock(self);
		ast = csw_check(self, p, AST_YIELD);
		ast_on(ast);
		thread_unlock(self);

		if (ast != AST_NONE) {
			(void)thread_block_reason(THREAD_CONTINUE_NULL, NULL, ast);
		}

		splx(s);
	}
}

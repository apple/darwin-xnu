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
 *	File:	sched_prim.c
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1986
 *
 *	Scheduling primitives
 *
 */

#include <debug.h>
#include <cpus.h>
#include <mach_kdb.h>
#include <simple_clock.h>
#include <power_save.h>
#include <task_swapper.h>

#include <ddb/db_output.h>
#include <mach/machine.h>
#include <machine/machine_routines.h>
#include <machine/sched_param.h>
#include <kern/ast.h>
#include <kern/clock.h>
#include <kern/counters.h>
#include <kern/cpu_number.h>
#include <kern/cpu_data.h>
#include <kern/etap_macros.h>
#include <kern/lock.h>
#include <kern/macro_help.h>
#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/processor.h>
#include <kern/queue.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/syscall_subr.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/thread_swap.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <mach/policy.h>
#include <mach/sync_policy.h>
#include <kern/mk_sp.h>	/*** ??? fix so this can be removed ***/
#include <sys/kdebug.h>

#if	TASK_SWAPPER
#include <kern/task_swap.h>
extern int	task_swap_on;
#endif	/* TASK_SWAPPER */

extern int	hz;

#define		DEFAULT_PREEMPTION_RATE		100		/* (1/s) */
int			default_preemption_rate = DEFAULT_PREEMPTION_RATE;

#define		MAX_UNSAFE_QUANTA			800
int			max_unsafe_quanta = MAX_UNSAFE_QUANTA;

#define		MAX_POLL_QUANTA				2
int			max_poll_quanta = MAX_POLL_QUANTA;

#define		SCHED_POLL_YIELD_SHIFT		4		/* 1/16 */
int			sched_poll_yield_shift = SCHED_POLL_YIELD_SHIFT;

uint32_t	std_quantum_us;

unsigned	sched_tick;

#if	SIMPLE_CLOCK
int			sched_usec;
#endif	/* SIMPLE_CLOCK */

/* Forwards */
void		wait_queues_init(void);

thread_t	choose_pset_thread(
				processor_t			myprocessor,
				processor_set_t		pset);

thread_t	choose_thread(
				processor_t		myprocessor);

boolean_t	run_queue_enqueue(
				run_queue_t		runq,
				thread_t		thread,
				boolean_t		tail);

void		do_thread_scan(void);

#if	DEBUG
void		dump_run_queues(
				run_queue_t			rq);
void		dump_run_queue_struct(
				run_queue_t			rq);
void		dump_processor(
				processor_t		p);
void		dump_processor_set(
				processor_set_t		ps);

void		checkrq(
				run_queue_t		rq,
				char			*msg);

void		thread_check(
				thread_t		thread,
				run_queue_t		runq);

static
boolean_t	thread_runnable(
				thread_t		thread);

#endif	/*DEBUG*/


/*
 *	State machine
 *
 * states are combinations of:
 *  R	running
 *  W	waiting (or on wait queue)
 *  N	non-interruptible
 *  O	swapped out
 *  I	being swapped in
 *
 * init	action 
 *	assert_wait thread_block    clear_wait 		swapout	swapin
 *
 * R	RW, RWN	    R;   setrun	    -	       		-
 * RN	RWN	    RN;  setrun	    -	       		-
 *
 * RW		    W		    R	       		-
 * RWN		    WN		    RN	       		-
 *
 * W				    R;   setrun		WO
 * WN				    RN;  setrun		-
 *
 * RO				    -			-	R
 *
 */

/*
 *	Waiting protocols and implementation:
 *
 *	Each thread may be waiting for exactly one event; this event
 *	is set using assert_wait().  That thread may be awakened either
 *	by performing a thread_wakeup_prim() on its event,
 *	or by directly waking that thread up with clear_wait().
 *
 *	The implementation of wait events uses a hash table.  Each
 *	bucket is queue of threads having the same hash function
 *	value; the chain for the queue (linked list) is the run queue
 *	field.  [It is not possible to be waiting and runnable at the
 *	same time.]
 *
 *	Locks on both the thread and on the hash buckets govern the
 *	wait event field and the queue chain field.  Because wakeup
 *	operations only have the event as an argument, the event hash
 *	bucket must be locked before any thread.
 *
 *	Scheduling operations may also occur at interrupt level; therefore,
 *	interrupts below splsched() must be prevented when holding
 *	thread or hash bucket locks.
 *
 *	The wait event hash table declarations are as follows:
 */

#define NUMQUEUES	59

struct wait_queue wait_queues[NUMQUEUES];

#define wait_hash(event) \
	((((int)(event) < 0)? ~(int)(event): (int)(event)) % NUMQUEUES)

void
sched_init(void)
{
	/*
	 * Calculate the timeslicing quantum
	 * in us.
	 */
	if (default_preemption_rate < 1)
		default_preemption_rate = DEFAULT_PREEMPTION_RATE;
	std_quantum_us = (1000 * 1000) / default_preemption_rate;

	printf("standard timeslicing quantum is %d us\n", std_quantum_us);

	wait_queues_init();
	pset_sys_bootstrap();		/* initialize processor mgmt. */
	processor_action();
	sched_tick = 0;
#if	SIMPLE_CLOCK
	sched_usec = 0;
#endif	/* SIMPLE_CLOCK */
	ast_init();
}

void
wait_queues_init(void)
{
	register int	i;

	for (i = 0; i < NUMQUEUES; i++) {
		wait_queue_init(&wait_queues[i], SYNC_POLICY_FIFO);
	}
}

/*
 *	Thread wait timer expiration.
 */
void
thread_timer_expire(
	timer_call_param_t		p0,
	timer_call_param_t		p1)
{
	thread_t		thread = p0;
	spl_t			s;

	s = splsched();
	wake_lock(thread);
	if (--thread->wait_timer_active == 1) {
		if (thread->wait_timer_is_set) {
			thread->wait_timer_is_set = FALSE;
			thread_lock(thread);
			if (thread->active)
				clear_wait_internal(thread, THREAD_TIMED_OUT);
			thread_unlock(thread);
		}
	}
	else
	if (thread->wait_timer_active == 0)
		thread_wakeup_one(&thread->wait_timer_active);
	wake_unlock(thread);
	splx(s);
}

/*
 *	thread_set_timer:
 *
 *	Set a timer for the current thread, if the thread
 *	is ready to wait.  Must be called between assert_wait()
 *	and thread_block().
 */
void
thread_set_timer(
	uint32_t		interval,
	uint32_t		scale_factor)
{
	thread_t		thread = current_thread();
	uint64_t		deadline;
	spl_t			s;

	s = splsched();
	wake_lock(thread);
	thread_lock(thread);
	if ((thread->state & TH_WAIT) != 0) {
		clock_interval_to_deadline(interval, scale_factor, &deadline);
		timer_call_enter(&thread->wait_timer, deadline);
		assert(!thread->wait_timer_is_set);
		thread->wait_timer_active++;
		thread->wait_timer_is_set = TRUE;
	}
	thread_unlock(thread);
	wake_unlock(thread);
	splx(s);
}

void
thread_set_timer_deadline(
	uint64_t		deadline)
{
	thread_t		thread = current_thread();
	spl_t			s;

	s = splsched();
	wake_lock(thread);
	thread_lock(thread);
	if ((thread->state & TH_WAIT) != 0) {
		timer_call_enter(&thread->wait_timer, deadline);
		assert(!thread->wait_timer_is_set);
		thread->wait_timer_active++;
		thread->wait_timer_is_set = TRUE;
	}
	thread_unlock(thread);
	wake_unlock(thread);
	splx(s);
}

void
thread_cancel_timer(void)
{
	thread_t		thread = current_thread();
	spl_t			s;

	s = splsched();
	wake_lock(thread);
	if (thread->wait_timer_is_set) {
		if (timer_call_cancel(&thread->wait_timer))
			thread->wait_timer_active--;
		thread->wait_timer_is_set = FALSE;
	}
	wake_unlock(thread);
	splx(s);
}

/*
 * Set up thread timeout element when thread is created.
 */
void
thread_timer_setup(
	 thread_t		thread)
{
	extern void	thread_depress_expire(
					timer_call_param_t	p0,
					timer_call_param_t	p1);

	timer_call_setup(&thread->wait_timer, thread_timer_expire, thread);
	thread->wait_timer_is_set = FALSE;
	thread->wait_timer_active = 1;

	timer_call_setup(&thread->depress_timer, thread_depress_expire, thread);
	thread->depress_timer_active = 1;

	thread->ref_count++;
}

void
thread_timer_terminate(void)
{
	thread_t		thread = current_thread();
	wait_result_t	res;
	spl_t			s;

	s = splsched();
	wake_lock(thread);
	if (thread->wait_timer_is_set) {
		if (timer_call_cancel(&thread->wait_timer))
			thread->wait_timer_active--;
		thread->wait_timer_is_set = FALSE;
	}

	thread->wait_timer_active--;

	while (thread->wait_timer_active > 0) {
		res = assert_wait((event_t)&thread->wait_timer_active, THREAD_UNINT);
		assert(res == THREAD_WAITING);
		wake_unlock(thread);
		splx(s);

		res = thread_block(THREAD_CONTINUE_NULL);
		assert(res == THREAD_AWAKENED);

		s = splsched();
		wake_lock(thread);
	}

	thread->depress_timer_active--;

	while (thread->depress_timer_active > 0) {
		res = assert_wait((event_t)&thread->depress_timer_active, THREAD_UNINT);
		assert(res == THREAD_WAITING);
		wake_unlock(thread);
		splx(s);

		res = thread_block(THREAD_CONTINUE_NULL);
		assert(res == THREAD_AWAKENED);

		s = splsched();
		wake_lock(thread);
	}

	wake_unlock(thread);
	splx(s);

	thread_deallocate(thread);
}

/*
 *	Routine:	thread_go_locked
 *	Purpose:
 *		Start a thread running.
 *	Conditions:
 *		thread lock held, IPC locks may be held.
 *		thread must have been pulled from wait queue under same lock hold.
 *  Returns:
 *		KERN_SUCCESS - Thread was set running
 *		KERN_NOT_WAITING - Thread was not waiting
 */
kern_return_t
thread_go_locked(
	thread_t		thread,
	wait_result_t	result)
{
	assert(thread->at_safe_point == FALSE);
	assert(thread->wait_event == NO_EVENT64);
	assert(thread->wait_queue == WAIT_QUEUE_NULL);

	if ((thread->state & (TH_WAIT|TH_TERMINATE)) == TH_WAIT) {
		thread->state &= ~(TH_WAIT|TH_UNINT);
		if (!(thread->state & TH_RUN)) {
			thread->state |= TH_RUN;

			if (thread->active_callout)
				call_thread_unblock();

			if (!(thread->state & TH_IDLE)) {
				_mk_sp_thread_unblock(thread);
				hw_atomic_add(&thread->processor_set->run_count, 1);
			}
		}

		thread->wait_result = result;
		return KERN_SUCCESS;
	}
	return KERN_NOT_WAITING;
}

/*
 *	Routine:	thread_mark_wait_locked
 *	Purpose:
 *		Mark a thread as waiting.  If, given the circumstances,
 *		it doesn't want to wait (i.e. already aborted), then
 *		indicate that in the return value.
 *	Conditions:
 *		at splsched() and thread is locked.
 */
__private_extern__
wait_result_t
thread_mark_wait_locked(
	thread_t			thread,
	wait_interrupt_t 	interruptible)
{
	wait_result_t 	wait_result;
	boolean_t			at_safe_point;

	assert(thread == current_thread());

	/*
	 *	The thread may have certain types of interrupts/aborts masked
	 *	off.  Even if the wait location says these types of interrupts
	 *	are OK, we have to honor mask settings (outer-scoped code may
	 *	not be able to handle aborts at the moment).
	 */
	if (interruptible > thread->interrupt_level)
		interruptible = thread->interrupt_level;

	at_safe_point = (interruptible == THREAD_ABORTSAFE);

	if ((interruptible == THREAD_UNINT) || 
		!(thread->state & TH_ABORT) ||
		(!at_safe_point && (thread->state & TH_ABORT_SAFELY))) {
		thread->state |= (interruptible) ? TH_WAIT : (TH_WAIT | TH_UNINT);
		thread->at_safe_point = at_safe_point;
		thread->sleep_stamp = sched_tick;
		return (thread->wait_result = THREAD_WAITING);
	} else if (thread->state & TH_ABORT_SAFELY) {
		thread->state &= ~(TH_ABORT|TH_ABORT_SAFELY);
	}
	return (thread->wait_result = THREAD_INTERRUPTED);
}

/*
 *	Routine:	thread_interrupt_level
 *	Purpose:
 *	        Set the maximum interruptible state for the
 *		current thread.  The effective value of any
 *		interruptible flag passed into assert_wait
 *		will never exceed this.
 *
 *		Useful for code that must not be interrupted,
 *		but which calls code that doesn't know that.
 *	Returns:
 *		The old interrupt level for the thread.
 */
__private_extern__ 
wait_interrupt_t
thread_interrupt_level(
	wait_interrupt_t new_level)
{
	thread_t thread = current_thread();
	wait_interrupt_t result = thread->interrupt_level;

	thread->interrupt_level = new_level;
	return result;
}

/*
 *	Routine:	assert_wait_timeout
 *	Purpose:
 *		Assert that the thread intends to block,
 *		waiting for a timeout (no user known event).
 */
unsigned int assert_wait_timeout_event;

wait_result_t
assert_wait_timeout(
	mach_msg_timeout_t		msecs,
	wait_interrupt_t		interruptible)
{
	wait_result_t res;

	res = assert_wait((event_t)&assert_wait_timeout_event, interruptible);
	if (res == THREAD_WAITING)
		thread_set_timer(msecs, 1000*NSEC_PER_USEC);
	return res;
}

/*
 * Check to see if an assert wait is possible, without actually doing one.
 * This is used by debug code in locks and elsewhere to verify that it is
 * always OK to block when trying to take a blocking lock (since waiting
 * for the actual assert_wait to catch the case may make it hard to detect
 * this case.
 */
boolean_t
assert_wait_possible(void)
{

	thread_t thread;
	extern unsigned int debug_mode;

#if	DEBUG
	if(debug_mode) return TRUE;		/* Always succeed in debug mode */
#endif
	
	thread = current_thread();

	return (thread == NULL || wait_queue_assert_possible(thread));
}

/*
 *	assert_wait:
 *
 *	Assert that the current thread is about to go to
 *	sleep until the specified event occurs.
 */
wait_result_t
assert_wait(
	event_t				event,
	wait_interrupt_t	interruptible)
{
	register wait_queue_t	wq;
	register int		index;

	assert(event != NO_EVENT);
	assert(assert_wait_possible());

	index = wait_hash(event);
	wq = &wait_queues[index];
	return wait_queue_assert_wait(wq, event, interruptible);
}


/*
 *	thread_sleep_fast_usimple_lock:
 *
 *	Cause the current thread to wait until the specified event
 *	occurs.  The specified simple_lock is unlocked before releasing
 *	the cpu and re-acquired as part of waking up.
 *
 *	This is the simple lock sleep interface for components that use a
 *	faster version of simple_lock() than is provided by usimple_lock().
 */
__private_extern__ wait_result_t
thread_sleep_fast_usimple_lock(
	event_t			event,
	simple_lock_t		lock,
	wait_interrupt_t	interruptible)
{
	wait_result_t res;

	res = assert_wait(event, interruptible);
	if (res == THREAD_WAITING) {
		simple_unlock(lock);
		res = thread_block(THREAD_CONTINUE_NULL);
		simple_lock(lock);
	}
	return res;
}


/*
 *	thread_sleep_usimple_lock:
 *
 *	Cause the current thread to wait until the specified event
 *	occurs.  The specified usimple_lock is unlocked before releasing
 *	the cpu and re-acquired as part of waking up.
 *
 *	This is the simple lock sleep interface for components where
 *	simple_lock() is defined in terms of usimple_lock().
 */
wait_result_t
thread_sleep_usimple_lock(
	event_t			event,
	usimple_lock_t		lock,
	wait_interrupt_t	interruptible)
{
	wait_result_t res;

	res = assert_wait(event, interruptible);
	if (res == THREAD_WAITING) {
		usimple_unlock(lock);
		res = thread_block(THREAD_CONTINUE_NULL);
		usimple_lock(lock);
	}
	return res;
}

/*
 *	thread_sleep_mutex:
 *
 *	Cause the current thread to wait until the specified event
 *	occurs.  The specified mutex is unlocked before releasing
 *	the cpu. The mutex will be re-acquired before returning.
 *
 *	JMM - Add hint to make sure mutex is available before rousting
 */
wait_result_t
thread_sleep_mutex(
	event_t			event,
	mutex_t			*mutex,
	wait_interrupt_t interruptible)
{
	wait_result_t	res;

	res = assert_wait(event, interruptible);
	if (res == THREAD_WAITING) {
		mutex_unlock(mutex);
		res = thread_block(THREAD_CONTINUE_NULL);
		mutex_lock(mutex);
	}
	return res;
}
  
/*
 *	thread_sleep_mutex_deadline:
 *
 *	Cause the current thread to wait until the specified event
 *	(or deadline) occurs.  The specified mutex is unlocked before
 *	releasing the cpu. The mutex will be re-acquired before returning.
 *
 *	JMM - Add hint to make sure mutex is available before rousting
 */
wait_result_t
thread_sleep_mutex_deadline(
	event_t			event,
	mutex_t			*mutex,
	uint64_t		deadline,
	wait_interrupt_t interruptible)
{
	wait_result_t	res;

	res = assert_wait(event, interruptible);
	if (res == THREAD_WAITING) {
		mutex_unlock(mutex);
		thread_set_timer_deadline(deadline);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (res != THREAD_TIMED_OUT)
			thread_cancel_timer();
		mutex_lock(mutex);
	}
	return res;
}

/*
 *	thread_sleep_lock_write:
 *
 *	Cause the current thread to wait until the specified event
 *	occurs.  The specified (write) lock is unlocked before releasing
 *	the cpu. The (write) lock will be re-acquired before returning.
 *
 *	JMM - Add hint to make sure mutex is available before rousting
 */
wait_result_t
thread_sleep_lock_write(
	event_t			event,
	lock_t			*lock,
	wait_interrupt_t interruptible)
{
	wait_result_t	res;

	res = assert_wait(event, interruptible);
	if (res == THREAD_WAITING) {
		lock_write_done(lock);
		res = thread_block(THREAD_CONTINUE_NULL);
		lock_write(lock);
	}
	return res;
}


/*
 *	thread_sleep_funnel:
 *
 *	Cause the current thread to wait until the specified event
 *	occurs.  If the thread is funnelled, the funnel will be released
 *	before giving up the cpu. The funnel will be re-acquired before returning.
 *
 *	JMM - Right now the funnel is dropped and re-acquired inside
 *		  thread_block().  At some point, this may give thread_block() a hint.
 */
wait_result_t
thread_sleep_funnel(
	event_t			event,
	wait_interrupt_t interruptible)
{
	wait_result_t	res;

	res = assert_wait(event, interruptible);
	if (res == THREAD_WAITING) {
		res = thread_block(THREAD_CONTINUE_NULL);
	}
	return res;
}

/*
 * thread_[un]stop(thread)
 *	Once a thread has blocked interruptibly (via assert_wait) prevent 
 *	it from running until thread_unstop.
 *
 * 	If someone else has already stopped the thread, wait for the
 * 	stop to be cleared, and then stop it again.
 *
 * 	Return FALSE if interrupted.
 *
 * NOTE: thread_hold/thread_suspend should be called on the activation
 *	before calling thread_stop.  TH_SUSP is only recognized when
 *	a thread blocks and only prevents clear_wait/thread_wakeup
 *	from restarting an interruptible wait.  The wake_active flag is
 *	used to indicate that someone is waiting on the thread.
 */
boolean_t
thread_stop(
	thread_t	thread)
{
	spl_t		s = splsched();

	wake_lock(thread);

	while (thread->state & TH_SUSP) {
		wait_result_t	result;

		thread->wake_active = TRUE;
		result = assert_wait(&thread->wake_active, THREAD_ABORTSAFE);
		wake_unlock(thread);
		splx(s);

		if (result == THREAD_WAITING)
			result = thread_block(THREAD_CONTINUE_NULL);

		if (result != THREAD_AWAKENED)
			return (FALSE);

		s = splsched();
		wake_lock(thread);
	}

	thread_lock(thread);
	thread->state |= TH_SUSP;

	while (thread->state & TH_RUN) {
		wait_result_t	result;
		processor_t		processor = thread->last_processor;

		if (	processor != PROCESSOR_NULL						&&
				processor->state == PROCESSOR_RUNNING			&&
				processor->cpu_data->active_thread == thread	)
			cause_ast_check(processor);
		thread_unlock(thread);

		thread->wake_active = TRUE;
		result = assert_wait(&thread->wake_active, THREAD_ABORTSAFE);
		wake_unlock(thread);
		splx(s);

		if (result == THREAD_WAITING)
			result = thread_block(THREAD_CONTINUE_NULL);

		if (result != THREAD_AWAKENED) {
			thread_unstop(thread);
			return (FALSE);
		}

		s = splsched();
		wake_lock(thread);
		thread_lock(thread);
	}

	thread_unlock(thread);
	wake_unlock(thread);
	splx(s);

	return (TRUE);
}

/*
 *	Clear TH_SUSP and if the thread has been stopped and is now runnable,
 *	put it back on the run queue.
 */
void
thread_unstop(
	thread_t	thread)
{
	spl_t		s = splsched();

	wake_lock(thread);
	thread_lock(thread);

	if ((thread->state & (TH_RUN|TH_WAIT|TH_SUSP)) == TH_SUSP) {
		thread->state &= ~TH_SUSP;
		thread->state |= TH_RUN;

		assert(!(thread->state & TH_IDLE));
		_mk_sp_thread_unblock(thread);
		hw_atomic_add(&thread->processor_set->run_count, 1);
	}
	else
	if (thread->state & TH_SUSP) {
		thread->state &= ~TH_SUSP;

		if (thread->wake_active) {
			thread->wake_active = FALSE;
			thread_unlock(thread);
			wake_unlock(thread);
			splx(s);

			thread_wakeup(&thread->wake_active);
			return;
		}
	}

	thread_unlock(thread);
	wake_unlock(thread);
	splx(s);
}

/*
 * Wait for the thread's RUN bit to clear
 */
boolean_t
thread_wait(
	thread_t	thread)
{
	spl_t		s = splsched();

	wake_lock(thread);
	thread_lock(thread);

	while (thread->state & TH_RUN) {
		wait_result_t	result;
		processor_t		processor = thread->last_processor;

		if (	processor != PROCESSOR_NULL						&&
				processor->state == PROCESSOR_RUNNING			&&
				processor->cpu_data->active_thread == thread	)
			cause_ast_check(processor);
		thread_unlock(thread);

		thread->wake_active = TRUE;
		result = assert_wait(&thread->wake_active, THREAD_ABORTSAFE);
		wake_unlock(thread);
		splx(s);

		if (result == THREAD_WAITING)
			result = thread_block(THREAD_CONTINUE_NULL);

		if (result != THREAD_AWAKENED)
			return (FALSE);

		s = splsched();
		wake_lock(thread);
		thread_lock(thread);
	}

	thread_unlock(thread);
	wake_unlock(thread);
	splx(s);

	return (TRUE);
}

/*
 *	Routine: clear_wait_internal
 *
 *		Clear the wait condition for the specified thread.
 *		Start the thread executing if that is appropriate.
 *	Arguments:
 *		thread		thread to awaken
 *		result		Wakeup result the thread should see
 *	Conditions:
 *		At splsched
 *		the thread is locked.
 *	Returns:
 *		KERN_SUCCESS		thread was rousted out a wait
 *		KERN_FAILURE		thread was waiting but could not be rousted
 *		KERN_NOT_WAITING	thread was not waiting
 */
__private_extern__ kern_return_t
clear_wait_internal(
	thread_t		thread,
	wait_result_t	result)
{
	wait_queue_t	wq = thread->wait_queue;
	kern_return_t	ret;
	int				loop_count;

	loop_count = 0;
	do {
		if ((result == THREAD_INTERRUPTED) && (thread->state & TH_UNINT))
			return KERN_FAILURE;

		if (wq != WAIT_QUEUE_NULL) {
			if (wait_queue_lock_try(wq)) {
				wait_queue_pull_thread_locked(wq, thread, TRUE);
				/* wait queue unlocked, thread still locked */
			} else {
				thread_unlock(thread);
				delay(1);
				thread_lock(thread);

				if (wq != thread->wait_queue) {
					return KERN_NOT_WAITING; /* we know it moved */
				}
				continue;
			}
		}
		ret = thread_go_locked(thread, result);
		return ret; 
	} while (++loop_count < LockTimeOut);
	panic("clear_wait_internal: deadlock: thread=0x%x, wq=0x%x, cpu=%d\n",
		  thread, wq, cpu_number());
	return KERN_FAILURE;
}


/*
 *	clear_wait:
 *
 *	Clear the wait condition for the specified thread.  Start the thread
 *	executing if that is appropriate.
 *
 *	parameters:
 *	  thread		thread to awaken
 *	  result		Wakeup result the thread should see
 */
kern_return_t
clear_wait(
	thread_t		thread,
	wait_result_t	result)
{
	kern_return_t ret;
	spl_t		s;

	s = splsched();
	thread_lock(thread);
	ret = clear_wait_internal(thread, result);
	thread_unlock(thread);
	splx(s);
	return ret;
}


/*
 *	thread_wakeup_prim:
 *
 *	Common routine for thread_wakeup, thread_wakeup_with_result,
 *	and thread_wakeup_one.
 *
 */
kern_return_t
thread_wakeup_prim(
	event_t			event,
	boolean_t		one_thread,
	wait_result_t	result)
{
	register wait_queue_t	wq;
	register int			index;

	index = wait_hash(event);
	wq = &wait_queues[index];
	if (one_thread)
	    return (wait_queue_wakeup_one(wq, event, result));
	else
	    return (wait_queue_wakeup_all(wq, event, result));
}

/*
 *	thread_bind:
 *
 *	Force a thread to execute on the specified processor.
 *	If the thread is currently executing, it may wait until its
 *	time slice is up before switching onto the specified processor.
 *
 *	A processor of PROCESSOR_NULL causes the thread to be unbound.
 *	xxx - DO NOT export this to users.
 */
void
thread_bind(
	register thread_t	thread,
	processor_t			processor)
{
	spl_t		s;

	s = splsched();
	thread_lock(thread);
	thread_bind_locked(thread, processor);
	thread_unlock(thread);
	splx(s);
}

/*
 *	Select a thread for this processor (the current processor) to run.
 *	May select the current thread, which must already be locked.
 */
thread_t
thread_select(
	register processor_t	myprocessor)
{
	register thread_t		thread;
	processor_set_t			pset;
	register run_queue_t	runq = &myprocessor->runq;
	boolean_t				other_runnable;

	/*
	 *	Check for other non-idle runnable threads.
	 */
	pset = myprocessor->processor_set;
	thread = myprocessor->cpu_data->active_thread;

	/* Update the thread's priority */
	if (thread->sched_stamp != sched_tick)
		update_priority(thread);

	myprocessor->current_pri = thread->sched_pri;

	simple_lock(&runq->lock);
	simple_lock(&pset->runq.lock);

	other_runnable = runq->count > 0 || pset->runq.count > 0;

	if (	thread->state == TH_RUN							&&
			(!other_runnable							||
			 (runq->highq < thread->sched_pri		&&
			  pset->runq.highq < thread->sched_pri))		&&
			thread->processor_set == pset					&&
			(thread->bound_processor == PROCESSOR_NULL	||
			 thread->bound_processor == myprocessor)				) {

		/* I am the highest priority runnable (non-idle) thread */
		simple_unlock(&pset->runq.lock);
		simple_unlock(&runq->lock);

		myprocessor->slice_quanta =
				(thread->sched_mode & TH_MODE_TIMESHARE)? pset->set_quanta: 1;
	}
	else
	if (other_runnable)
		thread = choose_thread(myprocessor);
	else {
		simple_unlock(&pset->runq.lock);
		simple_unlock(&runq->lock);

		/*
		 *	Nothing is runnable, so set this processor idle if it
		 *	was running.  If it was in an assignment or shutdown,
		 *	leave it alone.  Return its idle thread.
		 */
		simple_lock(&pset->sched_lock);
		if (myprocessor->state == PROCESSOR_RUNNING) {
			remqueue(&pset->active_queue, (queue_entry_t)myprocessor);
			myprocessor->state = PROCESSOR_IDLE;

			if (myprocessor == master_processor)
				enqueue_tail(&pset->idle_queue, (queue_entry_t)myprocessor);
			else
				enqueue_head(&pset->idle_queue, (queue_entry_t)myprocessor);

			pset->idle_count++;
		}
		simple_unlock(&pset->sched_lock);

		thread = myprocessor->idle_thread;
	}

	return (thread);
}


/*
 *	Stop running the current thread and start running the new thread.
 *	If continuation is non-zero, and the current thread is blocked,
 *	then it will resume by executing continuation on a new stack.
 *	Returns TRUE if the hand-off succeeds.
 *
 *	Assumes splsched.
 */

static thread_t
__current_thread(void)
{
  return (current_thread());
}

boolean_t
thread_invoke(
	register thread_t	old_thread,
	register thread_t	new_thread,
	int					reason,
	thread_continue_t	old_cont)
{
	thread_continue_t	new_cont;
	processor_t			processor;

	if (get_preemption_level() != 0)
		panic("thread_invoke: preemption_level %d\n",
								get_preemption_level());

	/*
	 * Mark thread interruptible.
	 */
	thread_lock(new_thread);
	new_thread->state &= ~TH_UNINT;

	assert(thread_runnable(new_thread));

	assert(old_thread->continuation == NULL);	

	/*
	 * Allow time constraint threads to hang onto
	 * a stack.
	 */
	if (	(old_thread->sched_mode & TH_MODE_REALTIME)		&&
					!old_thread->stack_privilege				) {
		old_thread->stack_privilege = old_thread->kernel_stack;
	}

	if (old_cont != NULL) {
		if (new_thread->state & TH_STACK_HANDOFF) {
			/*
			 * If the old thread is using a privileged stack,
			 * check to see whether we can exchange it with
			 * that of the new thread.
			 */
			if (	old_thread->kernel_stack == old_thread->stack_privilege	&&
							!new_thread->stack_privilege)
				goto need_stack;

			new_thread->state &= ~TH_STACK_HANDOFF;
			new_cont = new_thread->continuation;
			new_thread->continuation = NULL;

			/*
			 * Set up ast context of new thread and switch
			 * to its timer.
			 */
			processor = current_processor();
			new_thread->last_processor = processor;
			processor->current_pri = new_thread->sched_pri;
			ast_context(new_thread->top_act, processor->slot_num);
			timer_switch(&new_thread->system_timer);
			thread_unlock(new_thread);
		
			current_task()->csw++;

			old_thread->reason = reason;
			old_thread->continuation = old_cont;
	   
			_mk_sp_thread_done(old_thread, new_thread, processor);

			stack_handoff(old_thread, new_thread);

			_mk_sp_thread_begin(new_thread, processor);

			wake_lock(old_thread);
			thread_lock(old_thread);

			/* 
			 * Inline thread_dispatch but
			 * don't free stack.
			 */

			switch (old_thread->state & (TH_RUN|TH_WAIT|TH_UNINT|TH_IDLE)) {
 
			case TH_RUN				| TH_UNINT:
			case TH_RUN:
				/*
				 * Still running, put back
				 * onto a run queue.
				 */
				old_thread->state |= TH_STACK_HANDOFF;
				_mk_sp_thread_dispatch(old_thread);

				thread_unlock(old_thread);
				wake_unlock(old_thread);
				break;

			case TH_RUN | TH_WAIT	| TH_UNINT:
			case TH_RUN | TH_WAIT:
			{
				boolean_t	reap, wake, callblock;

				/*
				 * Waiting.
				 */
				old_thread->sleep_stamp = sched_tick;
				old_thread->state |= TH_STACK_HANDOFF;
				old_thread->state &= ~TH_RUN;
				hw_atomic_sub(&old_thread->processor_set->run_count, 1);
				callblock = old_thread->active_callout;
				wake = old_thread->wake_active;
				old_thread->wake_active = FALSE;
				reap = (old_thread->state & TH_TERMINATE)? TRUE: FALSE;

				thread_unlock(old_thread);
				wake_unlock(old_thread);

				if (callblock)
					call_thread_block();

				if (wake)
					thread_wakeup((event_t)&old_thread->wake_active);

				if (reap)
					thread_reaper_enqueue(old_thread);
				break;
			}

			case TH_RUN				| TH_IDLE:
				/*
				 * The idle threads don't go
				 * onto a run queue.
				 */
				old_thread->state |= TH_STACK_HANDOFF;
				thread_unlock(old_thread);
				wake_unlock(old_thread);
				break;

			default:
				panic("thread_invoke: state 0x%x\n", old_thread->state);
			}

			counter_always(c_thread_invoke_hits++);

			if (new_thread->funnel_state & TH_FN_REFUNNEL) {
				kern_return_t		wait_result = new_thread->wait_result;

				new_thread->funnel_state = 0;
				KERNEL_DEBUG(0x6032428 | DBG_FUNC_NONE,
									new_thread->funnel_lock, 2, 0, 0, 0);
				funnel_lock(new_thread->funnel_lock);
				KERNEL_DEBUG(0x6032430 | DBG_FUNC_NONE,
									new_thread->funnel_lock, 2, 0, 0, 0);
				new_thread->funnel_state = TH_FN_OWNED;
				new_thread->wait_result = wait_result;
			}
			(void) spllo();

			assert(new_cont);
			call_continuation(new_cont);
			/*NOTREACHED*/
			return (TRUE);
		}
		else
		if (new_thread->state & TH_STACK_ALLOC) {
			/*
			 * Waiting for a stack
			 */
			counter_always(c_thread_invoke_misses++);
			thread_unlock(new_thread);
			return (FALSE);
		}
		else
		if (new_thread == old_thread) {
			/* same thread but with continuation */
			counter(++c_thread_invoke_same);
			thread_unlock(new_thread);

			if (new_thread->funnel_state & TH_FN_REFUNNEL) {
				kern_return_t	wait_result = new_thread->wait_result;

				new_thread->funnel_state = 0;
				KERNEL_DEBUG(0x6032428 | DBG_FUNC_NONE,
									new_thread->funnel_lock, 3, 0, 0, 0);
				funnel_lock(new_thread->funnel_lock);
				KERNEL_DEBUG(0x6032430 | DBG_FUNC_NONE,
									new_thread->funnel_lock, 3, 0, 0, 0);
				new_thread->funnel_state = TH_FN_OWNED;
				new_thread->wait_result = wait_result;
			}
			(void) spllo();
			call_continuation(old_cont);
			/*NOTREACHED*/
		}
	}
	else {
		/*
		 * Check that the new thread has a stack
		 */
		if (new_thread->state & TH_STACK_HANDOFF) {
need_stack:
			if (!stack_alloc_try(new_thread, thread_continue)) {
				counter_always(c_thread_invoke_misses++);
				thread_swapin(new_thread);
				return (FALSE);
			}
	 
			new_thread->state &= ~TH_STACK_HANDOFF;
		}
		else
		if (new_thread->state & TH_STACK_ALLOC) {
			/*
			 * Waiting for a stack
			 */
			counter_always(c_thread_invoke_misses++);
			thread_unlock(new_thread);
			return (FALSE);
		}
		else
		if (old_thread == new_thread) {
			counter(++c_thread_invoke_same);
			thread_unlock(new_thread);
			return (TRUE);
		}
	}

	/*
	 * Set up ast context of new thread and switch to its timer.
	 */
	processor = current_processor();
	new_thread->last_processor = processor;
	processor->current_pri = new_thread->sched_pri;
	ast_context(new_thread->top_act, processor->slot_num);
	timer_switch(&new_thread->system_timer);
	assert(thread_runnable(new_thread));
	thread_unlock(new_thread);

	counter_always(c_thread_invoke_csw++);
	current_task()->csw++;

	assert(old_thread->runq == RUN_QUEUE_NULL);
	old_thread->reason = reason;
	old_thread->continuation = old_cont;

	_mk_sp_thread_done(old_thread, new_thread, processor);

	/*
	 *	switch_context is machine-dependent.  It does the
	 *	machine-dependent components of a context-switch, like
	 *	changing address spaces.  It updates active_threads.
	 */
	old_thread = switch_context(old_thread, old_cont, new_thread);
	
	/* Now on new thread's stack.  Set a local variable to refer to it. */
	new_thread = __current_thread();
	assert(old_thread != new_thread);

	assert(thread_runnable(new_thread));
	_mk_sp_thread_begin(new_thread, new_thread->last_processor);

	/*
	 *	We're back.  Now old_thread is the thread that resumed
	 *	us, and we have to dispatch it.
	 */
	thread_dispatch(old_thread);

	if (old_cont) {
		if (new_thread->funnel_state & TH_FN_REFUNNEL) {
			kern_return_t		wait_result = new_thread->wait_result;

			new_thread->funnel_state = 0;
			KERNEL_DEBUG(0x6032428 | DBG_FUNC_NONE,
								new_thread->funnel_lock, 3, 0, 0, 0);
			funnel_lock(new_thread->funnel_lock);
			KERNEL_DEBUG(0x6032430 | DBG_FUNC_NONE,
								new_thread->funnel_lock, 3, 0, 0, 0);
			new_thread->funnel_state = TH_FN_OWNED;
			new_thread->wait_result = wait_result;
		}
		(void) spllo();
		call_continuation(old_cont);
		/*NOTREACHED*/
	}

	return (TRUE);
}

/*
 *	thread_continue:
 *
 *	Called when a thread gets a new stack, at splsched();
 */
void
thread_continue(
	register thread_t	old_thread)
{
	register thread_t			self = current_thread();
	register thread_continue_t	continuation;
	
	continuation = self->continuation;
	self->continuation = NULL;

	_mk_sp_thread_begin(self, self->last_processor);
	
	/*
	 *	We must dispatch the old thread and then
	 *	call the current thread's continuation.
	 *	There might not be an old thread, if we are
	 *	the first thread to run on this processor.
	 */
	if (old_thread != THREAD_NULL)
		thread_dispatch(old_thread);

	if (self->funnel_state & TH_FN_REFUNNEL) {
		kern_return_t		wait_result = self->wait_result;

		self->funnel_state = 0;
		KERNEL_DEBUG(0x6032428 | DBG_FUNC_NONE, self->funnel_lock, 4, 0, 0, 0);
		funnel_lock(self->funnel_lock);
		KERNEL_DEBUG(0x6032430 | DBG_FUNC_NONE, self->funnel_lock, 4, 0, 0, 0);
		self->funnel_state = TH_FN_OWNED;
		self->wait_result = wait_result;
	}
	(void)spllo();
	assert(continuation);
	call_continuation(continuation);
	/*NOTREACHED*/
}

#if	MACH_LDEBUG || MACH_KDB

#define THREAD_LOG_SIZE		300

struct t64 {
	unsigned long h;
	unsigned long l;
};

struct {
	struct t64	stamp;
	thread_t	thread;
	long		info1;
	long		info2;
	long		info3;
	char		* action;
} thread_log[THREAD_LOG_SIZE];

int		thread_log_index;

void		check_thread_time(long n);


int	check_thread_time_crash;

#if 0
void
check_thread_time(long us)
{
	struct t64	temp;

	if (!check_thread_time_crash)
		return;

	temp = thread_log[0].stamp;
	cyctm05_diff (&thread_log[1].stamp, &thread_log[0].stamp, &temp);

	if (temp.l >= us && thread_log[1].info != 0x49) /* HACK!!! */
		panic ("check_thread_time");
}
#endif

void
log_thread_action(char * action, long info1, long info2, long info3)
{
	int	i;
	spl_t	x;
	static  unsigned int tstamp;

	x = splhigh();

	for (i = THREAD_LOG_SIZE-1; i > 0; i--) {
		thread_log[i] = thread_log[i-1];
	}

	thread_log[0].stamp.h = 0;
	thread_log[0].stamp.l = tstamp++;
	thread_log[0].thread = current_thread();
	thread_log[0].info1 = info1;
	thread_log[0].info2 = info2;
	thread_log[0].info3 = info3;
	thread_log[0].action = action;
/*	strcpy (&thread_log[0].action[0], action);*/

	splx(x);
}
#endif /* MACH_LDEBUG || MACH_KDB */

#if	MACH_KDB
#include <ddb/db_output.h>
void		db_show_thread_log(void);

void
db_show_thread_log(void)
{
	int	i;

	db_printf ("%s %s %s %s %s %s\n", " Thread ", "  Info1 ", "  Info2 ",
			"  Info3 ", "    Timestamp    ", "Action");

	for (i = 0; i < THREAD_LOG_SIZE; i++) {
		db_printf ("%08x %08x %08x %08x %08x/%08x %s\n",
			thread_log[i].thread,
			thread_log[i].info1,
			thread_log[i].info2,
			thread_log[i].info3,
			thread_log[i].stamp.h,
			thread_log[i].stamp.l,
			thread_log[i].action);
	}
}
#endif	/* MACH_KDB */

/*
 *	thread_block_reason:
 *
 *	Block the current thread if a wait has been asserted,
 *	otherwise unconditionally yield the remainder of the
 *	current quantum unless reason contains AST_BLOCK.
 *	
 *	If a continuation is specified, then thread_block will
 *	attempt to discard the thread's kernel stack.  When the
 *	thread resumes, it will execute the continuation function
 *	on a new kernel stack.
 */
counter(mach_counter_t  c_thread_block_calls = 0;)
 
int
thread_block_reason(
	thread_continue_t	continuation,
	ast_t				reason)
{
	register thread_t		thread = current_thread();
	register processor_t	myprocessor;
	register thread_t		new_thread;
	spl_t					s;

	counter(++c_thread_block_calls);

	check_simple_locks();

	machine_clock_assist();

	s = splsched();

	if ((thread->funnel_state & TH_FN_OWNED) && !(reason & AST_PREEMPT)) {
		thread->funnel_state = TH_FN_REFUNNEL;
		KERNEL_DEBUG(
			0x603242c | DBG_FUNC_NONE, thread->funnel_lock, 2, 0, 0, 0);
		funnel_unlock(thread->funnel_lock);
	}

	myprocessor = current_processor();

	/* If we're explicitly yielding, force a subsequent quantum */
	if (reason & AST_YIELD)
		myprocessor->slice_quanta = 0;

	/* We're handling all scheduling AST's */
	ast_off(AST_SCHEDULING);

	thread_lock(thread);
	new_thread = thread_select(myprocessor);
	assert(new_thread && thread_runnable(new_thread));
	thread_unlock(thread);
	while (!thread_invoke(thread, new_thread, reason, continuation)) {
		thread_lock(thread);
		new_thread = thread_select(myprocessor);
		assert(new_thread && thread_runnable(new_thread));
		thread_unlock(thread);
	}

	if (thread->funnel_state & TH_FN_REFUNNEL) {
		kern_return_t	wait_result = thread->wait_result;

		thread->funnel_state = 0;
		KERNEL_DEBUG(
			0x6032428 | DBG_FUNC_NONE, thread->funnel_lock, 5, 0, 0, 0);
		funnel_lock(thread->funnel_lock);
		KERNEL_DEBUG(
			0x6032430 | DBG_FUNC_NONE, thread->funnel_lock, 5, 0, 0, 0);
		thread->funnel_state = TH_FN_OWNED;
		thread->wait_result = wait_result;
	}

	splx(s);

	return (thread->wait_result);
}

/*
 *	thread_block:
 *
 *	Block the current thread if a wait has been asserted.
 */
int
thread_block(
	thread_continue_t	continuation)
{
	return thread_block_reason(continuation, AST_NONE);
}

/*
 *	thread_run:
 *
 *	Switch directly from the current (old) thread to the
 *	specified thread, handing off our quantum if possible.
 *
 *	New thread must be runnable, and not on a run queue.
 *
 *  Assumption:
 *	at splsched.
 */
int
thread_run(
	thread_t			old_thread,
	thread_continue_t	continuation,
	thread_t			new_thread)
{
	ast_t		handoff = AST_HANDOFF;

	assert(old_thread == current_thread());

	machine_clock_assist();

	if (old_thread->funnel_state & TH_FN_OWNED) {
		old_thread->funnel_state = TH_FN_REFUNNEL;
		KERNEL_DEBUG(
			0x603242c | DBG_FUNC_NONE, old_thread->funnel_lock, 3, 0, 0, 0);
		funnel_unlock(old_thread->funnel_lock);
	}

	while (!thread_invoke(old_thread, new_thread, handoff, continuation)) {
		register processor_t		myprocessor = current_processor();

		thread_lock(old_thread);
		new_thread = thread_select(myprocessor);
		thread_unlock(old_thread);
		handoff = AST_NONE;
	}

	/* if we fell thru */
	if (old_thread->funnel_state & TH_FN_REFUNNEL) {
		kern_return_t	wait_result = old_thread->wait_result;

		old_thread->funnel_state = 0;
		KERNEL_DEBUG(
			0x6032428 | DBG_FUNC_NONE, old_thread->funnel_lock, 6, 0, 0, 0);
		funnel_lock(old_thread->funnel_lock);
		KERNEL_DEBUG(
			0x6032430 | DBG_FUNC_NONE, old_thread->funnel_lock, 6, 0, 0, 0);
		old_thread->funnel_state = TH_FN_OWNED;
		old_thread->wait_result = wait_result;
	}

	return (old_thread->wait_result);
}

/*
 *	Dispatches a running thread that is not	on a runq.
 *	Called at splsched.
 */
void
thread_dispatch(
	register thread_t	thread)
{
	wake_lock(thread);
	thread_lock(thread);

	/*
	 *	If we are discarding the thread's stack, we must do it
	 *	before the thread has a chance to run.
	 */
#ifndef i386
    if (thread->continuation != NULL) {
		assert((thread->state & TH_STACK_STATE) == 0);
		thread->state |= TH_STACK_HANDOFF;
		stack_free(thread);
	}
#endif

	switch (thread->state & (TH_RUN|TH_WAIT|TH_UNINT|TH_IDLE)) {

	case TH_RUN				 | TH_UNINT:
	case TH_RUN:
		/*
		 *	No reason to stop.  Put back on a run queue.
		 */
		_mk_sp_thread_dispatch(thread);
		break;

	case TH_RUN | TH_WAIT	| TH_UNINT:
	case TH_RUN | TH_WAIT:
	{
		boolean_t	reap, wake, callblock;
	
		/*
		 *	Waiting
		 */
		thread->sleep_stamp = sched_tick;
		thread->state &= ~TH_RUN;
		hw_atomic_sub(&thread->processor_set->run_count, 1);
		callblock = thread->active_callout;
		wake = thread->wake_active;
		thread->wake_active = FALSE;
		reap = (thread->state & TH_TERMINATE)? TRUE: FALSE;

		thread_unlock(thread);
		wake_unlock(thread);

		if (callblock)
			call_thread_block();

		if (wake)
		    thread_wakeup((event_t)&thread->wake_active);

		if (reap)
			thread_reaper_enqueue(thread);

		return;
	}

	case TH_RUN						| TH_IDLE:
		/*
		 * The idle threads don't go
		 * onto a run queue.
		 */
		break;

	default:
		panic("thread_dispatch: bad thread state 0x%x\n", thread->state);
	}

	thread_unlock(thread);
	wake_unlock(thread);
}

/*
 * Enqueue thread on run queue.  Thread must be locked,
 * and not already be on a run queue.  Returns TRUE iff
 * the particular queue level was empty beforehand.
 */
boolean_t
run_queue_enqueue(
	register run_queue_t	rq,
	register thread_t		thread,
	boolean_t				tail)
{
	register int			whichq = thread->sched_pri;
	register queue_t		queue = &rq->queues[whichq];
	boolean_t				result = FALSE;
	
	assert(whichq >= MINPRI && whichq <= MAXPRI);

	simple_lock(&rq->lock);
	assert(thread->runq == RUN_QUEUE_NULL);
	if (queue_empty(queue)) {
		enqueue_tail(queue, (queue_entry_t)thread);

		setbit(MAXPRI - whichq, rq->bitmap);
		if (whichq > rq->highq)
			rq->highq = whichq;
		result = TRUE;
	}
	else
	if (tail)
		enqueue_tail(queue, (queue_entry_t)thread);
	else
		enqueue_head(queue, (queue_entry_t)thread);

	thread->runq = rq;
	if (thread->sched_mode & TH_MODE_PREEMPT)
		rq->urgency++;
	rq->count++;
#if	DEBUG
	thread_check(thread, rq);
#endif	/* DEBUG */
	simple_unlock(&rq->lock);

	return (result);
}

struct {
	uint32_t	pset_idle_last,
				pset_idle_any,
				pset_self,
				pset_last,
				pset_other,
				bound_idle,
				bound_self,
				bound_other;
} dispatch_counts;

/*
 *	thread_setrun:
 *
 *	Dispatch thread for execution, directly onto an idle
 *	processor if possible.  Else put on appropriate run
 *	queue. (local if bound, else processor set)
 *
 *	Thread must be locked.
 *
 *	The tail parameter indicates the proper placement of
 *	the thread on a run queue.
 */
void
thread_setrun(
	register thread_t			new_thread,
	boolean_t					tail)
{
	register processor_t		processor;
	register processor_set_t	pset;
	register thread_t			thread;
	boolean_t					try_preempt = FALSE;
	ast_t						preempt = AST_BLOCK;

	assert(thread_runnable(new_thread));
	
	/*
	 *	Update priority if needed.
	 */
	if (new_thread->sched_stamp != sched_tick)
		update_priority(new_thread);

	/*
	 *	Check for urgent preemption.
	 */
	if (new_thread->sched_mode & TH_MODE_PREEMPT)
		preempt |= AST_URGENT;

	assert(new_thread->runq == RUN_QUEUE_NULL);

	if ((processor = new_thread->bound_processor) == PROCESSOR_NULL) {
	    /*
	     *	First try to dispatch on
		 *	the last processor.
	     */
	    pset = new_thread->processor_set;
		processor = new_thread->last_processor;
		if (	pset->processor_count > 1				&&
				processor != PROCESSOR_NULL				&&
				processor->state == PROCESSOR_IDLE		) {
			simple_lock(&processor->lock);
			simple_lock(&pset->sched_lock);
			if (	processor->processor_set == pset		&&
					processor->state == PROCESSOR_IDLE		) {
				remqueue(&pset->idle_queue, (queue_entry_t)processor);
				pset->idle_count--;
				processor->next_thread = new_thread;
				processor->state = PROCESSOR_DISPATCHING;
				simple_unlock(&pset->sched_lock);
				simple_unlock(&processor->lock);
				if (processor != current_processor())
					machine_signal_idle(processor);
				dispatch_counts.pset_idle_last++;
				return;
			}
			simple_unlock(&processor->lock);
		}
		else
		simple_lock(&pset->sched_lock);

		/*
		 *	Next pick any idle processor
		 *	in the processor set.
		 */
		if (pset->idle_count > 0) {
			processor = (processor_t)dequeue_head(&pset->idle_queue);
			pset->idle_count--;
			processor->next_thread = new_thread;
			processor->state = PROCESSOR_DISPATCHING;
			simple_unlock(&pset->sched_lock);
			if (processor != current_processor())	
				machine_signal_idle(processor);
			dispatch_counts.pset_idle_any++;
			return;
		}

		/*
		 * Place thread on run queue.
		 */
		if (run_queue_enqueue(&pset->runq, new_thread, tail))
			try_preempt = TRUE;

		/*
		 *	Update the timesharing quanta.
		 */
		pset_quanta_update(pset);
	
	    /*
	     *	Preempt check.
	     */
	    processor = current_processor();
		thread = processor->cpu_data->active_thread;
	    if (try_preempt) {
			/*
			 * First try the current processor
			 * if it is a member of the correct
			 * processor set.
			 */
			if (	pset == processor->processor_set	&&
					csw_needed(thread, processor)		) {
				simple_unlock(&pset->sched_lock);

				ast_on(preempt);
				dispatch_counts.pset_self++;
				return;
			}

			/*
			 * If that failed and we have other
			 * processors available keep trying.
			 */
			if (	pset->processor_count > 1			||
					pset != processor->processor_set	) {
				queue_t			active = &pset->active_queue;
				processor_t		myprocessor, lastprocessor;
				queue_entry_t	next;

				/*
				 * Next try the last processor
				 * dispatched on.
				 */
				myprocessor = processor;
				processor = new_thread->last_processor;
				if (	processor != myprocessor						&&
						processor != PROCESSOR_NULL						&&
						processor->processor_set == pset				&&
						processor->state == PROCESSOR_RUNNING			&&
						new_thread->sched_pri > processor->current_pri	) {
					cause_ast_check(processor);
					simple_unlock(&pset->sched_lock);
					dispatch_counts.pset_last++;
					return;
				}

				/*
				 * Lastly, pick any other
				 * available processor.
				 */
				lastprocessor = processor;
				processor = (processor_t)queue_first(active);
				while (!queue_end(active, (queue_entry_t)processor)) {
					next = queue_next((queue_entry_t)processor);

					if (	processor != myprocessor						&&
							processor != lastprocessor						&&
							new_thread->sched_pri > processor->current_pri	) {
						if (!queue_end(active, next)) {
							remqueue(active, (queue_entry_t)processor);
							enqueue_tail(active, (queue_entry_t)processor);
						}
						cause_ast_check(processor);
						simple_unlock(&pset->sched_lock);
						dispatch_counts.pset_other++;
						return;
					}

					processor = (processor_t)next;
				}
			}
	    }

		simple_unlock(&pset->sched_lock);
	}
	else {
	    /*
	     *	Bound, can only run on bound processor.  Have to lock
	     *  processor here because it may not be the current one.
	     */
		if (processor->state == PROCESSOR_IDLE) {
			simple_lock(&processor->lock);
			pset = processor->processor_set;
			simple_lock(&pset->sched_lock);
			if (processor->state == PROCESSOR_IDLE) {
				remqueue(&pset->idle_queue, (queue_entry_t)processor);
				pset->idle_count--;
				processor->next_thread = new_thread;
				processor->state = PROCESSOR_DISPATCHING;
				simple_unlock(&pset->sched_lock);
				simple_unlock(&processor->lock);
				if (processor != current_processor())	
					machine_signal_idle(processor);
				dispatch_counts.bound_idle++;
				return;
			}
			simple_unlock(&pset->sched_lock);
			simple_unlock(&processor->lock);
		}
	  
		if (run_queue_enqueue(&processor->runq, new_thread, tail))
			try_preempt = TRUE;

		if (processor == current_processor()) {
			if (try_preempt) {
				thread = processor->cpu_data->active_thread;
				if (csw_needed(thread, processor)) {
					ast_on(preempt);
					dispatch_counts.bound_self++;
				}
			}
		}
		else {
			if (try_preempt) {
				if (	processor->state == PROCESSOR_RUNNING			&&
						new_thread->sched_pri > processor->current_pri	) {
					cause_ast_check(processor);
					dispatch_counts.bound_other++;
					return;
				}
			}

			if (processor->state == PROCESSOR_IDLE) {
				machine_signal_idle(processor);
				dispatch_counts.bound_idle++;
			}
		}
	}
}

/*
 * Called at splsched by a thread on itself.
 */
ast_t
csw_check(
	thread_t		thread,
	processor_t		processor)
{
	int				current_pri = thread->sched_pri;
	ast_t			result = AST_NONE;
	run_queue_t		runq;

	if (first_quantum(processor)) {
		runq = &processor->processor_set->runq;
		if (runq->highq > current_pri) {
			if (runq->urgency > 0)
				return (AST_BLOCK | AST_URGENT);

			result |= AST_BLOCK;
		}

		runq = &processor->runq;
		if (runq->highq > current_pri) {
			if (runq->urgency > 0)
				return (AST_BLOCK | AST_URGENT);

			result |= AST_BLOCK;
		}
	}
	else {
		runq = &processor->processor_set->runq;
		if (runq->highq >= current_pri) {
			if (runq->urgency > 0)
				return (AST_BLOCK | AST_URGENT);

			result |= AST_BLOCK;
		}

		runq = &processor->runq;
		if (runq->highq >= current_pri) {
			if (runq->urgency > 0)
				return (AST_BLOCK | AST_URGENT);

			result |= AST_BLOCK;
		}
	}

	if (result != AST_NONE)
		return (result);

	if (thread->state & TH_SUSP)
		result |= AST_BLOCK;

	return (result);
}

/*
 *	set_sched_pri:
 *
 *	Set the current scheduled priority of the specified thread.
 *	This may cause the thread to change queues.
 *
 *	The thread *must* be locked by the caller.
 */
void
set_sched_pri(
	thread_t			thread,
	int					priority)
{
	register struct run_queue	*rq = rem_runq(thread);

	if (	!(thread->sched_mode & TH_MODE_TIMESHARE)				&&
			(priority >= BASEPRI_PREEMPT						||
			 (thread->task_priority < MINPRI_KERNEL			&&
			  thread->task_priority >= BASEPRI_BACKGROUND	&&
			  priority > thread->task_priority)					||
			 (thread->sched_mode & TH_MODE_FORCEDPREEMPT)		)	)
		thread->sched_mode |= TH_MODE_PREEMPT;
	else
		thread->sched_mode &= ~TH_MODE_PREEMPT;

	thread->sched_pri = priority;
	if (rq != RUN_QUEUE_NULL)
		thread_setrun(thread, TAIL_Q);
	else
	if ((thread->state & (TH_RUN|TH_WAIT)) == TH_RUN) {
		processor_t		processor = thread->last_processor;

		if (thread == current_thread()) {
			ast_t		preempt = csw_check(thread, processor);

			if (preempt != AST_NONE)
				ast_on(preempt);
			processor->current_pri = priority;
		}
		else
		if (	processor != PROCESSOR_NULL						&&
				processor->cpu_data->active_thread == thread	)
			cause_ast_check(processor);
	}
}

/*
 *	rem_runq:
 *
 *	Remove a thread from its run queue.
 *	The run queue that the process was on is returned
 *	(or RUN_QUEUE_NULL if not on a run queue).  Thread *must* be locked
 *	before calling this routine.  Unusual locking protocol on runq
 *	field in thread structure makes this code interesting; see thread.h.
 */
run_queue_t
rem_runq(
	thread_t			thread)
{
	register struct run_queue	*rq;

	rq = thread->runq;
	/*
	 *	If rq is RUN_QUEUE_NULL, the thread will stay out of the
	 *	run_queues because the caller locked the thread.  Otherwise
	 *	the thread is on a runq, but could leave.
	 */
	if (rq != RUN_QUEUE_NULL) {
		simple_lock(&rq->lock);
		if (rq == thread->runq) {
			/*
			 *	Thread is in a runq and we have a lock on
			 *	that runq.
			 */
#if	DEBUG
			thread_check(thread, rq);
#endif	/* DEBUG */
			remqueue(&rq->queues[0], (queue_entry_t)thread);
			rq->count--;
			if (thread->sched_mode & TH_MODE_PREEMPT)
				rq->urgency--;
			assert(rq->urgency >= 0);

			if (queue_empty(rq->queues + thread->sched_pri)) {
				/* update run queue status */
				if (thread->sched_pri != IDLEPRI)
					clrbit(MAXPRI - thread->sched_pri, rq->bitmap);
				rq->highq = MAXPRI - ffsbit(rq->bitmap);
			}
			thread->runq = RUN_QUEUE_NULL;
			simple_unlock(&rq->lock);
		}
		else {
			/*
			 *	The thread left the runq before we could
			 * 	lock the runq.  It is not on a runq now, and
			 *	can't move again because this routine's
			 *	caller locked the thread.
			 */
			assert(thread->runq == RUN_QUEUE_NULL);
			simple_unlock(&rq->lock);
			rq = RUN_QUEUE_NULL;
		}
	}

	return (rq);
}

/*
 *	choose_thread:
 *
 *	Choose a thread to execute.  The thread chosen is removed
 *	from its run queue.  Note that this requires only that the runq
 *	lock be held.
 *
 *	Strategy:
 *		Check processor runq first; if anything found, run it.
 *		Else check pset runq; if nothing found, return idle thread.
 *
 *	Second line of strategy is implemented by choose_pset_thread.
 *
 *	Called with both the local & pset run queues locked, returned
 *	unlocked.
 */
thread_t
choose_thread(
	processor_t		myprocessor)
{
	thread_t				thread;
	register queue_t		q;
	register run_queue_t	runq;
	processor_set_t			pset;

	runq = &myprocessor->runq;
	pset = myprocessor->processor_set;

	if (runq->count > 0 && runq->highq >= pset->runq.highq) {
		simple_unlock(&pset->runq.lock);
		q = runq->queues + runq->highq;
#if	MACH_ASSERT
		if (!queue_empty(q)) {
#endif	/*MACH_ASSERT*/
			thread = (thread_t)q->next;
			((queue_entry_t)thread)->next->prev = q;
			q->next = ((queue_entry_t)thread)->next;
			thread->runq = RUN_QUEUE_NULL;
			runq->count--;
			if (thread->sched_mode & TH_MODE_PREEMPT)
				runq->urgency--;
			assert(runq->urgency >= 0);
			if (queue_empty(q)) {
				if (runq->highq != IDLEPRI)
					clrbit(MAXPRI - runq->highq, runq->bitmap);
				runq->highq = MAXPRI - ffsbit(runq->bitmap);
			}
			simple_unlock(&runq->lock);
			return (thread);
#if	MACH_ASSERT
		}
		panic("choose_thread");
#endif	/*MACH_ASSERT*/
		/*NOTREACHED*/
	}
	simple_unlock(&myprocessor->runq.lock);

	return (choose_pset_thread(myprocessor, pset));
}

/*
 *	choose_pset_thread:  choose a thread from processor_set runq or
 *		set processor idle and choose its idle thread.
 *
 *	This routine chooses and removes a thread from the runq if there
 *	is one (and returns it), else it sets the processor idle and
 *	returns its idle thread.
 *
 *	Called with both local & pset run queues locked, returned
 *	unlocked.
 */
thread_t
choose_pset_thread(
	register processor_t	myprocessor,
	processor_set_t			pset)
{
	register run_queue_t	runq;
	register thread_t		thread;
	register queue_t		q;

	runq = &pset->runq;
	if (runq->count > 0) {
		q = runq->queues + runq->highq;
#if	MACH_ASSERT
		if (!queue_empty(q)) {
#endif	/*MACH_ASSERT*/
			thread = (thread_t)q->next;
			((queue_entry_t)thread)->next->prev = q;
			q->next = ((queue_entry_t)thread)->next;
			thread->runq = RUN_QUEUE_NULL;
			runq->count--;
			if (thread->sched_mode & TH_MODE_PREEMPT)
				runq->urgency--;
			assert(runq->urgency >= 0);
			if (queue_empty(q)) {
				if (runq->highq != IDLEPRI)
					clrbit(MAXPRI - runq->highq, runq->bitmap);
				runq->highq = MAXPRI - ffsbit(runq->bitmap);
			}
			pset_quanta_update(pset);
			simple_unlock(&runq->lock);
			return (thread);
#if	MACH_ASSERT
		}
		panic("choose_pset_thread");
#endif	/*MACH_ASSERT*/
		/*NOTREACHED*/
	}
	simple_unlock(&runq->lock);

	/*
	 *	Nothing is runnable, so set this processor idle if it
	 *	was running.  If it was in an assignment or shutdown,
	 *	leave it alone.  Return its idle thread.
	 */
	simple_lock(&pset->sched_lock);
	if (myprocessor->state == PROCESSOR_RUNNING) {
		remqueue(&pset->active_queue, (queue_entry_t)myprocessor);
	    myprocessor->state = PROCESSOR_IDLE;

	    if (myprocessor == master_processor)
			enqueue_tail(&pset->idle_queue, (queue_entry_t)myprocessor);
	    else
			enqueue_head(&pset->idle_queue, (queue_entry_t)myprocessor);

	    pset->idle_count++;
	}
	simple_unlock(&pset->sched_lock);

	return (myprocessor->idle_thread);
}

/*
 *	no_dispatch_count counts number of times processors go non-idle
 *	without being dispatched.  This should be very rare.
 */
int	no_dispatch_count = 0;

/*
 *	This is the idle thread, which just looks for other threads
 *	to execute.
 */
void
idle_thread_continue(void)
{
	register processor_t		myprocessor;
	register volatile thread_t	*threadp;
	register volatile int		*gcount;
	register volatile int		*lcount;
	register thread_t			new_thread;
	register int				state;
	register processor_set_t 	pset;
	int							mycpu;

	mycpu = cpu_number();
	myprocessor = cpu_to_processor(mycpu);
	threadp = (volatile thread_t *) &myprocessor->next_thread;
	lcount = (volatile int *) &myprocessor->runq.count;

	for (;;) {
		gcount = (volatile int *)&myprocessor->processor_set->runq.count;

		(void)splsched();
		while (	(*threadp == (volatile thread_t)THREAD_NULL)	&&
					(*gcount == 0) && (*lcount == 0)				) {

			/* check for ASTs while we wait */
			if (need_ast[mycpu] &~ (	AST_SCHEDULING | AST_BSD	)) {
				/* don't allow scheduling ASTs */
				need_ast[mycpu] &= ~(	AST_SCHEDULING | AST_BSD	);
				ast_taken(AST_ALL, TRUE);	/* back at spllo */
			}
			else
#ifdef	__ppc__
				machine_idle();
#else
				(void)spllo();
#endif
	        machine_clock_assist();

			(void)splsched();
		}

		/*
		 *	This is not a switch statement to avoid the
		 *	bounds checking code in the common case.
		 */
		pset = myprocessor->processor_set;
		simple_lock(&pset->sched_lock);
retry:
		state = myprocessor->state;
		if (state == PROCESSOR_DISPATCHING) {
			/*
			 *	Commmon case -- cpu dispatched.
			 */
			new_thread = *threadp;
			*threadp = (volatile thread_t) THREAD_NULL;
			myprocessor->state = PROCESSOR_RUNNING;
			enqueue_tail(&pset->active_queue, (queue_entry_t)myprocessor);
			simple_unlock(&pset->sched_lock);

			if (	myprocessor->runq.highq > new_thread->sched_pri		||
					pset->runq.highq > new_thread->sched_pri				) {
				thread_lock(new_thread);
				thread_setrun(new_thread, HEAD_Q);
				thread_unlock(new_thread);

				counter(c_idle_thread_block++);
				thread_block(idle_thread_continue);
				/* NOTREACHED */
			}
			else {
				counter(c_idle_thread_handoff++);
				thread_run(myprocessor->idle_thread,
									idle_thread_continue, new_thread);
				/* NOTREACHED */
			}
		}
		else
		if (state == PROCESSOR_IDLE) {
			if (myprocessor->state != PROCESSOR_IDLE) {
				/*
				 *	Something happened, try again.
				 */
				goto retry;
			}
			/*
			 *	Processor was not dispatched (Rare).
			 *	Set it running again.
			 */
			no_dispatch_count++;
			pset->idle_count--;
			remqueue(&pset->idle_queue, (queue_entry_t)myprocessor);
			myprocessor->state = PROCESSOR_RUNNING;
			enqueue_tail(&pset->active_queue, (queue_entry_t)myprocessor);
			simple_unlock(&pset->sched_lock);

			counter(c_idle_thread_block++);
			thread_block(idle_thread_continue);
			/* NOTREACHED */
		}
		else
		if (	state == PROCESSOR_ASSIGN		||
				state == PROCESSOR_SHUTDOWN			) {
			/*
			 *	Changing processor sets, or going off-line.
			 *	Release next_thread if there is one.  Actual
			 *	thread to run is on a runq.
			 */
			if ((new_thread = (thread_t)*threadp) != THREAD_NULL) {
				*threadp = (volatile thread_t) THREAD_NULL;
				simple_unlock(&pset->sched_lock);

				thread_lock(new_thread);
				thread_setrun(new_thread, TAIL_Q);
				thread_unlock(new_thread);
			}
			else
				simple_unlock(&pset->sched_lock);

			counter(c_idle_thread_block++);
			thread_block(idle_thread_continue);
			/* NOTREACHED */
		}
		else {
			simple_unlock(&pset->sched_lock);

			panic("idle_thread: bad processor state %d\n", cpu_state(mycpu));
		}

		(void)spllo();
	}
}

void
idle_thread(void)
{
	thread_t		self = current_thread();
	spl_t			s;

	stack_privilege(self);

	s = splsched();
	thread_lock(self);
	self->priority = IDLEPRI;
	set_sched_pri(self, self->priority);
	thread_unlock(self);
	splx(s);

	counter(c_idle_thread_block++);
	thread_block(idle_thread_continue);
	/*NOTREACHED*/
}

static uint64_t				sched_tick_interval, sched_tick_deadline;

void	sched_tick_thread(void);

void
sched_tick_init(void)
{
	kernel_thread_with_priority(
						kernel_task, MAXPRI_STANDARD,
								sched_tick_thread, TRUE, TRUE);
}

/*
 *	sched_tick_thread
 *
 *	Update the priorities of all threads periodically.
 */
void
sched_tick_thread_continue(void)
{
	uint64_t			abstime;
#if	SIMPLE_CLOCK
	int					new_usec;
#endif	/* SIMPLE_CLOCK */

	clock_get_uptime(&abstime);

	sched_tick++;		/* age usage one more time */
#if	SIMPLE_CLOCK
	/*
	 *	Compensate for clock drift.  sched_usec is an
	 *	exponential average of the number of microseconds in
	 *	a second.  It decays in the same fashion as cpu_usage.
	 */
	new_usec = sched_usec_elapsed();
	sched_usec = (5*sched_usec + 3*new_usec)/8;
#endif	/* SIMPLE_CLOCK */

	/*
	 *  Compute the scheduler load factors.
	 */
	compute_mach_factor();

	/*
	 *  Scan the run queues for runnable threads that need to
	 *  have their priorities recalculated.
	 */
	do_thread_scan();

	clock_deadline_for_periodic_event(sched_tick_interval, abstime,
														&sched_tick_deadline);

	assert_wait((event_t)sched_tick_thread_continue, THREAD_INTERRUPTIBLE);
	thread_set_timer_deadline(sched_tick_deadline);
	thread_block(sched_tick_thread_continue);
	/*NOTREACHED*/
}

void
sched_tick_thread(void)
{
	thread_t		self = current_thread();
	natural_t		rate;
	spl_t			s;

	stack_privilege(self);

	rate = (1000 >> SCHED_TICK_SHIFT);
	clock_interval_to_absolutetime_interval(rate, USEC_PER_SEC,
												&sched_tick_interval);
	clock_get_uptime(&sched_tick_deadline);

	thread_block(sched_tick_thread_continue);
	/*NOTREACHED*/
}

#define	MAX_STUCK_THREADS	128

/*
 *	do_thread_scan: scan for stuck threads.  A thread is stuck if
 *	it is runnable but its priority is so low that it has not
 *	run for several seconds.  Its priority should be higher, but
 *	won't be until it runs and calls update_priority.  The scanner
 *	finds these threads and does the updates.
 *
 *	Scanner runs in two passes.  Pass one squirrels likely
 *	thread ids away in an array  (takes out references for them).
 *	Pass two does the priority updates.  This is necessary because
 *	the run queue lock is required for the candidate scan, but
 *	cannot be held during updates.
 *
 *	Array length should be enough so that restart isn't necessary,
 *	but restart logic is included.
 *
 */
thread_t		stuck_threads[MAX_STUCK_THREADS];
int				stuck_count = 0;

/*
 *	do_runq_scan is the guts of pass 1.  It scans a runq for
 *	stuck threads.  A boolean is returned indicating whether
 *	a retry is needed.
 */
boolean_t
do_runq_scan(
	run_queue_t				runq)
{
	register queue_t		q;
	register thread_t		thread;
	register int			count;
	spl_t					s;
	boolean_t				result = FALSE;

	s = splsched();
	simple_lock(&runq->lock);
	if ((count = runq->count) > 0) {
	    q = runq->queues + runq->highq;
		while (count > 0) {
			queue_iterate(q, thread, thread_t, links) {
				if (	!(thread->state & (TH_WAIT|TH_SUSP))		&&
						(thread->sched_mode & TH_MODE_TIMESHARE)	) {
					if (thread->sched_stamp != sched_tick) {
						/*
						 *	Stuck, save its id for later.
						 */
						if (stuck_count == MAX_STUCK_THREADS) {
							/*
							 *	!@#$% No more room.
							 */
							simple_unlock(&runq->lock);
							splx(s);

							return (TRUE);
						}

						/*
						 * Inline version of thread_reference
						 * XXX - lock ordering problem here:
						 * thread locks should be taken before runq
						 * locks: just try and get the thread's locks
						 * and ignore this thread if we fail, we might
						 * have better luck next time.
						 */
						if (thread_lock_try(thread)) {
							thread->ref_count++;
							thread_unlock(thread);
							stuck_threads[stuck_count++] = thread;
						}
						else
							result = TRUE;
					}
				}

				count--;
			}

			q--;
		}
	}
	simple_unlock(&runq->lock);
	splx(s);

	return (result);
}

boolean_t	thread_scan_enabled = TRUE;

void
do_thread_scan(void)
{
	register boolean_t			restart_needed = FALSE;
	register thread_t			thread;
	register processor_set_t	pset = &default_pset;
	register processor_t		processor;
	spl_t						s;

	if (!thread_scan_enabled)
		return;

	do {
	    restart_needed = do_runq_scan(&pset->runq);
		if (!restart_needed) {
			simple_lock(&pset->processors_lock);
			processor = (processor_t)queue_first(&pset->processors);
			while (!queue_end(&pset->processors, (queue_entry_t)processor)) {
				if (restart_needed = do_runq_scan(&processor->runq))
					break;

				thread = processor->idle_thread;
				if (thread->sched_stamp != sched_tick) {
					if (stuck_count == MAX_STUCK_THREADS) {
						restart_needed = TRUE;
						break;
					}

					stuck_threads[stuck_count++] = thread;
				}

				processor = (processor_t)queue_next(&processor->processors);
			}
			simple_unlock(&pset->processors_lock);
		}

	    /*
	     *	Ok, we now have a collection of candidates -- fix them.
	     */
	    while (stuck_count > 0) {
			thread = stuck_threads[--stuck_count];
			stuck_threads[stuck_count] = THREAD_NULL;
			s = splsched();
			thread_lock(thread);
			if (	(thread->sched_mode & TH_MODE_TIMESHARE)	||
							(thread->state & TH_IDLE)				) {
				if (	!(thread->state & (TH_WAIT|TH_SUSP))	&&
						thread->sched_stamp != sched_tick		)
					update_priority(thread);
			}
			thread_unlock(thread);
			splx(s);
			if (!(thread->state & TH_IDLE))
				thread_deallocate(thread);
	    }

		if (restart_needed)
			delay(1);			/* XXX */
		
	} while (restart_needed);
}
		
/*
 *	Just in case someone doesn't use the macro
 */
#undef	thread_wakeup
void
thread_wakeup(
	event_t		x);

void
thread_wakeup(
	event_t		x)
{
	thread_wakeup_with_result(x, THREAD_AWAKENED);
}


#if	DEBUG

static boolean_t
thread_runnable(
	thread_t	thread)
{
	return ((thread->state & (TH_RUN|TH_WAIT)) == TH_RUN);
}

void
dump_processor_set(
	processor_set_t	ps)
{
    printf("processor_set: %08x\n",ps);
    printf("idle_queue: %08x %08x, idle_count:      0x%x\n",
	ps->idle_queue.next,ps->idle_queue.prev,ps->idle_count);
    printf("processors: %08x %08x, processor_count: 0x%x\n",
	ps->processors.next,ps->processors.prev,ps->processor_count);
    printf("tasks:      %08x %08x, task_count:      0x%x\n",
	ps->tasks.next,ps->tasks.prev,ps->task_count);
    printf("threads:    %08x %08x, thread_count:    0x%x\n",
	ps->threads.next,ps->threads.prev,ps->thread_count);
    printf("ref_count: 0x%x, active: %x\n",
	ps->ref_count,ps->active);
    printf("pset_self: %08x, pset_name_self: %08x\n",ps->pset_self, ps->pset_name_self);
    printf("set_quanta: 0x%x\n", ps->set_quanta);
}

#define processor_state(s) (((s)>PROCESSOR_SHUTDOWN)?"*unknown*":states[s])

void
dump_processor(
	processor_t	p)
{
    char *states[]={"OFF_LINE","RUNNING","IDLE","DISPATCHING",
		   "ASSIGN","SHUTDOWN"};

    printf("processor: %08x\n",p);
    printf("processor_queue: %08x %08x\n",
	p->processor_queue.next,p->processor_queue.prev);
    printf("state: %8s, next_thread: %08x, idle_thread: %08x\n",
	processor_state(p->state), p->next_thread, p->idle_thread);
    printf("slice_quanta: %x\n", p->slice_quanta);
    printf("processor_set: %08x, processor_set_next: %08x\n",
	p->processor_set, p->processor_set_next);
    printf("processors: %08x %08x\n", p->processors.next,p->processors.prev);
    printf("processor_self: %08x, slot_num: 0x%x\n", p->processor_self, p->slot_num);
}

void
dump_run_queue_struct(
	run_queue_t	rq)
{
    char dump_buf[80];
    int i;

    for( i=0; i < NRQS; ) {
        int j;

	printf("%6s",(i==0)?"runq:":"");
	for( j=0; (j<8) && (i < NRQS); j++,i++ ) {
	    if( rq->queues[i].next == &rq->queues[i] )
		printf( " --------");
	    else
		printf(" %08x",rq->queues[i].next);
	}
	printf("\n");
    }
    for( i=0; i < NRQBM; ) {
        register unsigned int mask;
	char *d=dump_buf;

	mask = ~0;
	mask ^= (mask>>1);

	do {
	    *d++ = ((rq->bitmap[i]&mask)?'r':'e');
	    mask >>=1;
	} while( mask );
	*d = '\0';
	printf("%8s%s\n",((i==0)?"bitmap:":""),dump_buf);
	i++;
    }	
    printf("highq: 0x%x, count: %u\n", rq->highq, rq->count);
}
 
void
dump_run_queues(
	run_queue_t	runq)
{
	register queue_t	q1;
	register int		i;
	register queue_entry_t	e;

	q1 = runq->queues;
	for (i = 0; i < NRQS; i++) {
	    if (q1->next != q1) {
		int t_cnt;

		printf("[%u]",i);
		for (t_cnt=0, e = q1->next; e != q1; e = e->next) {
		    printf("\t0x%08x",e);
		    if( (t_cnt = ++t_cnt%4) == 0 )
			printf("\n");
		}
		if( t_cnt )
			printf("\n");
	    }
	    /* else
		printf("[%u]\t<empty>\n",i);
	     */
	    q1++;
	}
}

void
checkrq(
	run_queue_t	rq,
	char		*msg)
{
	register queue_t	q1;
	register int		i, j;
	register queue_entry_t	e;
	register int		highq;

	highq = NRQS;
	j = 0;
	q1 = rq->queues;
	for (i = MAXPRI; i >= 0; i--) {
	    if (q1->next == q1) {
		if (q1->prev != q1) {
		    panic("checkrq: empty at %s", msg);
	        }
	    }
	    else {
		if (highq == -1)
		    highq = i;
		
		for (e = q1->next; e != q1; e = e->next) {
		    j++;
		    if (e->next->prev != e)
			panic("checkrq-2 at %s", msg);
		    if (e->prev->next != e)
			panic("checkrq-3 at %s", msg);
		}
	    }
	    q1++;
	}
	if (j != rq->count)
	    panic("checkrq: count wrong at %s", msg);
	if (rq->count != 0 && highq > rq->highq)
	    panic("checkrq: highq wrong at %s", msg);
}

void
thread_check(
	register thread_t		thread,
	register run_queue_t	rq)
{
	register int			whichq = thread->sched_pri;
	register queue_entry_t	queue, entry;

	if (whichq < MINPRI || whichq > MAXPRI)
		panic("thread_check: bad pri");

	queue = &rq->queues[whichq];
	entry = queue_first(queue);
	while (!queue_end(queue, entry)) {
		if (entry == (queue_entry_t)thread)
			return;

		entry = queue_next(entry);
	}

	panic("thread_check: not found");
}

#endif	/* DEBUG */

#if	MACH_KDB
#include <ddb/db_output.h>
#define	printf		kdbprintf
extern int		db_indent;
void			db_sched(void);

void
db_sched(void)
{
	iprintf("Scheduling Statistics:\n");
	db_indent += 2;
	iprintf("Thread invocations:  csw %d same %d\n",
		c_thread_invoke_csw, c_thread_invoke_same);
#if	MACH_COUNTERS
	iprintf("Thread block:  calls %d\n",
		c_thread_block_calls);
	iprintf("Idle thread:\n\thandoff %d block %d no_dispatch %d\n",
		c_idle_thread_handoff,
		c_idle_thread_block, no_dispatch_count);
	iprintf("Sched thread blocks:  %d\n", c_sched_thread_block);
#endif	/* MACH_COUNTERS */
	db_indent -= 2;
}
#endif	/* MACH_KDB */

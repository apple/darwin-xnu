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

#define		DEFAULT_PREEMPTION_RATE		100		/* (1/s) */
int			default_preemption_rate = DEFAULT_PREEMPTION_RATE;

#define		MAX_UNSAFE_QUANTA			800
int			max_unsafe_quanta = MAX_UNSAFE_QUANTA;

#define		MAX_POLL_QUANTA				2
int			max_poll_quanta = MAX_POLL_QUANTA;

#define		SCHED_POLL_YIELD_SHIFT		4		/* 1/16 */
int			sched_poll_yield_shift = SCHED_POLL_YIELD_SHIFT;

uint32_t	std_quantum_us;

uint64_t	max_unsafe_computation;
uint32_t	sched_safe_duration;
uint64_t	max_poll_computation;

uint32_t	std_quantum;
uint32_t	min_std_quantum;

uint32_t	max_rt_quantum;
uint32_t	min_rt_quantum;

static uint32_t		sched_tick_interval;

unsigned	sched_tick;

#if	SIMPLE_CLOCK
int			sched_usec;
#endif	/* SIMPLE_CLOCK */

/* Forwards */
void		wait_queues_init(void);

static thread_t	choose_thread(
					processor_set_t		pset,
					processor_t			processor);

static void		do_thread_scan(void);

#if	DEBUG
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

	sched_safe_duration = (2 * max_unsafe_quanta / default_preemption_rate) *
											(1 << SCHED_TICK_SHIFT);

	wait_queues_init();
	pset_sys_bootstrap();		/* initialize processor mgmt. */
	sched_tick = 0;
#if	SIMPLE_CLOCK
	sched_usec = 0;
#endif	/* SIMPLE_CLOCK */
	ast_init();
}

void
sched_timebase_init(void)
{
	uint64_t			abstime;

	clock_interval_to_absolutetime_interval(
							std_quantum_us, NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	std_quantum = abstime;

	/* 250 us */
	clock_interval_to_absolutetime_interval(250, NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	min_std_quantum = abstime;

	/* 50 us */
	clock_interval_to_absolutetime_interval(50, NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	min_rt_quantum = abstime;

	/* 50 ms */
	clock_interval_to_absolutetime_interval(
							50, 1000*NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	max_rt_quantum = abstime;

	clock_interval_to_absolutetime_interval(1000 >> SCHED_TICK_SHIFT,
													USEC_PER_SEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	sched_tick_interval = abstime;

	max_unsafe_computation = max_unsafe_quanta * std_quantum;
	max_poll_computation = max_poll_quanta * std_quantum;
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
	thread_lock(thread);
	if (--thread->wait_timer_active == 1) {
		if (thread->wait_timer_is_set) {
			thread->wait_timer_is_set = FALSE;
			clear_wait_internal(thread, THREAD_TIMED_OUT);
		}
	}
	thread_unlock(thread);
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
	thread_lock(thread);
	if ((thread->state & TH_WAIT) != 0) {
		clock_interval_to_deadline(interval, scale_factor, &deadline);
		timer_call_enter(&thread->wait_timer, deadline);
		assert(!thread->wait_timer_is_set);
		thread->wait_timer_active++;
		thread->wait_timer_is_set = TRUE;
	}
	thread_unlock(thread);
	splx(s);
}

void
thread_set_timer_deadline(
	uint64_t		deadline)
{
	thread_t		thread = current_thread();
	spl_t			s;

	s = splsched();
	thread_lock(thread);
	if ((thread->state & TH_WAIT) != 0) {
		timer_call_enter(&thread->wait_timer, deadline);
		assert(!thread->wait_timer_is_set);
		thread->wait_timer_active++;
		thread->wait_timer_is_set = TRUE;
	}
	thread_unlock(thread);
	splx(s);
}

void
thread_cancel_timer(void)
{
	thread_t		thread = current_thread();
	spl_t			s;

	s = splsched();
	thread_lock(thread);
	if (thread->wait_timer_is_set) {
		if (timer_call_cancel(&thread->wait_timer))
			thread->wait_timer_active--;
		thread->wait_timer_is_set = FALSE;
	}
	thread_unlock(thread);
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
	thread_lock(thread);
	if (thread->wait_timer_is_set) {
		if (timer_call_cancel(&thread->wait_timer))
			thread->wait_timer_active--;
		thread->wait_timer_is_set = FALSE;
	}

	thread->wait_timer_active--;

	while (thread->wait_timer_active > 0) {
		thread_unlock(thread);
		splx(s);

		delay(1);

		s = splsched();
		thread_lock(thread);
	}

	thread->depress_timer_active--;

	while (thread->depress_timer_active > 0) {
		thread_unlock(thread);
		splx(s);

		delay(1);

		s = splsched();
		thread_lock(thread);
	}

	thread_unlock(thread);
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
	wait_result_t	wresult)
{
	assert(thread->at_safe_point == FALSE);
	assert(thread->wait_event == NO_EVENT64);
	assert(thread->wait_queue == WAIT_QUEUE_NULL);

	if ((thread->state & (TH_WAIT|TH_TERMINATE)) == TH_WAIT) {
		thread_roust_t		roust_hint;

		thread->state &= ~(TH_WAIT|TH_UNINT);
		_mk_sp_thread_unblock(thread);

		roust_hint = thread->roust;
		thread->roust = NULL;
		if (		roust_hint != NULL				&&
				(*roust_hint)(thread, wresult)		) {
			if (thread->wait_timer_is_set) {
				if (timer_call_cancel(&thread->wait_timer))
					thread->wait_timer_active--;
				thread->wait_timer_is_set = FALSE;
			}

			return (KERN_SUCCESS);
		}

		thread->wait_result = wresult;

		if (!(thread->state & TH_RUN)) {
			thread->state |= TH_RUN;

			if (thread->active_callout)
				call_thread_unblock();

			pset_run_incr(thread->processor_set);
			if (thread->sched_mode & TH_MODE_TIMESHARE)
				pset_share_incr(thread->processor_set);

			thread_setrun(thread, SCHED_PREEMPT | SCHED_TAILQ);
		}

		KERNEL_DEBUG_CONSTANT(
			MACHDBG_CODE(DBG_MACH_SCHED,MACH_MAKE_RUNNABLE) | DBG_FUNC_NONE,
					(int)thread, (int)thread->sched_pri, 0, 0, 0);

		return (KERN_SUCCESS);
	}

	return (KERN_NOT_WAITING);
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
	boolean_t		at_safe_point;

	/*
	 *	The thread may have certain types of interrupts/aborts masked
	 *	off.  Even if the wait location says these types of interrupts
	 *	are OK, we have to honor mask settings (outer-scoped code may
	 *	not be able to handle aborts at the moment).
	 */
	if (interruptible > thread->interrupt_level)
		interruptible = thread->interrupt_level;

	at_safe_point = (interruptible == THREAD_ABORTSAFE);

	if (	interruptible == THREAD_UNINT			||
			!(thread->state & TH_ABORT)				||
			(!at_safe_point &&
			 (thread->state & TH_ABORT_SAFELY))		) {
		thread->state |= (interruptible) ? TH_WAIT : (TH_WAIT | TH_UNINT);
		thread->at_safe_point = at_safe_point;
		thread->sleep_stamp = sched_tick;
		return (thread->wait_result = THREAD_WAITING);
	}
	else
	if (thread->state & TH_ABORT_SAFELY)
		thread->state &= ~(TH_ABORT|TH_ABORT_SAFELY);

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

	index = wait_hash(event);
	wq = &wait_queues[index];
	return wait_queue_assert_wait(wq, event, interruptible);
}

__private_extern__
wait_queue_t
wait_event_wait_queue(
	event_t			event)
{
	assert(event != NO_EVENT);

	return (&wait_queues[wait_hash(event)]);
}

wait_result_t
assert_wait_prim(
	event_t				event,
	thread_roust_t		roust_hint,
	uint64_t			deadline,
	wait_interrupt_t	interruptible)
{
	thread_t			thread = current_thread();
	wait_result_t		wresult;		
	wait_queue_t		wq;
	spl_t				s;

	assert(event != NO_EVENT);

	wq = &wait_queues[wait_hash(event)];

	s = splsched();
	wait_queue_lock(wq);
	thread_lock(thread);

	wresult = wait_queue_assert_wait64_locked(wq, (uint32_t)event,
													interruptible, thread);
	if (wresult == THREAD_WAITING) {
		if (roust_hint != NULL)
			thread->roust = roust_hint;

		if (deadline != 0) {
			timer_call_enter(&thread->wait_timer, deadline);
			assert(!thread->wait_timer_is_set);
			thread->wait_timer_active++;
			thread->wait_timer_is_set = TRUE;
		}
	}

	thread_unlock(thread);
	wait_queue_unlock(wq);
	splx(s);

	return (wresult);
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

		if (	processor != PROCESSOR_NULL					&&
				processor->state == PROCESSOR_RUNNING		&&
				processor->active_thread == thread			)
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

		_mk_sp_thread_unblock(thread);

		pset_run_incr(thread->processor_set);
		if (thread->sched_mode & TH_MODE_TIMESHARE)
			pset_share_incr(thread->processor_set);

		thread_setrun(thread, SCHED_PREEMPT | SCHED_TAILQ);

		KERNEL_DEBUG_CONSTANT(
			MACHDBG_CODE(DBG_MACH_SCHED,MACH_MAKE_RUNNABLE) | DBG_FUNC_NONE,
					(int)thread, (int)thread->sched_pri, 0, 0, 0);
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

		if (	processor != PROCESSOR_NULL					&&
				processor->state == PROCESSOR_RUNNING		&&
				processor->active_thread == thread			)
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
	wait_result_t	wresult)
{
	wait_queue_t	wq = thread->wait_queue;
	int				i = LockTimeOut;

	do {
		if (wresult == THREAD_INTERRUPTED && (thread->state & TH_UNINT))
			return (KERN_FAILURE);

		if (wq != WAIT_QUEUE_NULL) {
			if (wait_queue_lock_try(wq)) {
				wait_queue_pull_thread_locked(wq, thread, TRUE);
				/* wait queue unlocked, thread still locked */
			}
			else {
				thread_unlock(thread);
				delay(1);

				thread_lock(thread);
				if (wq != thread->wait_queue)
					return (KERN_NOT_WAITING);

				continue;
			}
		}

		return (thread_go_locked(thread, wresult));
	} while (--i > 0);

	panic("clear_wait_internal: deadlock: thread=0x%x, wq=0x%x, cpu=%d\n",
		  thread, wq, cpu_number());

	return (KERN_FAILURE);
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
 *
 *	Returns the previous binding.  PROCESSOR_NULL means
 *	not bound.
 *
 *	XXX - DO NOT export this to users - XXX
 */
processor_t
thread_bind(
	register thread_t	thread,
	processor_t			processor)
{
	processor_t		prev;
	run_queue_t		runq = RUN_QUEUE_NULL;
	spl_t			s;

	s = splsched();
	thread_lock(thread);
	prev = thread->bound_processor;
	if (prev != PROCESSOR_NULL)
		runq = run_queue_remove(thread);

	thread->bound_processor = processor;

	if (runq != RUN_QUEUE_NULL)
		thread_setrun(thread, SCHED_PREEMPT | SCHED_TAILQ);
	thread_unlock(thread);
	splx(s);

	return (prev);
}

struct {
	uint32_t	idle_pset_last,
				idle_pset_any,
				idle_bound;

	uint32_t	pset_self,
				pset_last,
				pset_other,
				bound_self,
				bound_other;

	uint32_t	realtime_self,
				realtime_last,
				realtime_other;

	uint32_t	missed_realtime,
				missed_other;
} dispatch_counts;

/*
 *	Select a thread for the current processor to run.
 *
 *	May select the current thread, which must be locked.
 */
thread_t
thread_select(
	register processor_t	processor)
{
	register thread_t		thread;
	processor_set_t			pset;
	boolean_t				other_runnable;

	/*
	 *	Check for other non-idle runnable threads.
	 */
	pset = processor->processor_set;
	thread = processor->active_thread;

	/* Update the thread's priority */
	if (thread->sched_stamp != sched_tick)
		update_priority(thread);

	processor->current_pri = thread->sched_pri;

	simple_lock(&pset->sched_lock);

	other_runnable = processor->runq.count > 0 || pset->runq.count > 0;

	if (	thread->state == TH_RUN							&&
			thread->processor_set == pset					&&
			(thread->bound_processor == PROCESSOR_NULL	||
			 thread->bound_processor == processor)				) {
		if (	thread->sched_pri >= BASEPRI_RTQUEUES	&&
						first_timeslice(processor)			) {
			if (pset->runq.highq >= BASEPRI_RTQUEUES) {
				register run_queue_t	runq = &pset->runq;
				register queue_t		q;

				q = runq->queues + runq->highq;
				if (((thread_t)q->next)->realtime.deadline <
												processor->deadline) {
					thread = (thread_t)q->next;
					((queue_entry_t)thread)->next->prev = q;
					q->next = ((queue_entry_t)thread)->next;
					thread->runq = RUN_QUEUE_NULL;
					assert(thread->sched_mode & TH_MODE_PREEMPT);
					runq->count--; runq->urgency--;
					if (queue_empty(q)) {
						if (runq->highq != IDLEPRI)
							clrbit(MAXPRI - runq->highq, runq->bitmap);
						runq->highq = MAXPRI - ffsbit(runq->bitmap);
					}
				}
			}

			processor->deadline = thread->realtime.deadline;

			simple_unlock(&pset->sched_lock);

			return (thread);
		}

		if (	(!other_runnable							||
				 (processor->runq.highq < thread->sched_pri		&&
				  pset->runq.highq < thread->sched_pri))			) {

			/* I am the highest priority runnable (non-idle) thread */

			processor->deadline = UINT64_MAX;

			simple_unlock(&pset->sched_lock);

			return (thread);
		}
	}

	if (other_runnable)
		thread = choose_thread(pset, processor);
	else {
		/*
		 *	Nothing is runnable, so set this processor idle if it
		 *	was running.  Return its idle thread.
		 */
		if (processor->state == PROCESSOR_RUNNING) {
			remqueue(&pset->active_queue, (queue_entry_t)processor);
			processor->state = PROCESSOR_IDLE;

			enqueue_tail(&pset->idle_queue, (queue_entry_t)processor);
			pset->idle_count++;
		}

		processor->deadline = UINT64_MAX;

		thread = processor->idle_thread;
	}

	simple_unlock(&pset->sched_lock);

	return (thread);
}

/*
 *	Perform a context switch and start executing the new thread.
 *
 *	If continuation is non-zero, resume the old (current) thread
 *	next by executing at continuation on a new stack, in lieu
 *	of returning.
 *
 *	Returns TRUE if the hand-off succeeds.
 *
 *	Called at splsched.
 */

#define funnel_release_check(thread, debug)				\
MACRO_BEGIN												\
	if ((thread)->funnel_state & TH_FN_OWNED) {			\
		(thread)->funnel_state = TH_FN_REFUNNEL;		\
		KERNEL_DEBUG(0x603242c | DBG_FUNC_NONE,			\
			(thread)->funnel_lock, (debug), 0, 0, 0);	\
		funnel_unlock((thread)->funnel_lock);			\
	}													\
MACRO_END

#define funnel_refunnel_check(thread, debug)				\
MACRO_BEGIN													\
	if ((thread)->funnel_state & TH_FN_REFUNNEL) {			\
		kern_return_t	result = (thread)->wait_result;		\
															\
		(thread)->funnel_state = 0;							\
		KERNEL_DEBUG(0x6032428 | DBG_FUNC_NONE,				\
			(thread)->funnel_lock, (debug), 0, 0, 0);		\
		funnel_lock((thread)->funnel_lock);					\
		KERNEL_DEBUG(0x6032430 | DBG_FUNC_NONE,				\
			(thread)->funnel_lock, (debug), 0, 0, 0);		\
		(thread)->funnel_state = TH_FN_OWNED;				\
		(thread)->wait_result = result;						\
	}														\
MACRO_END

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
					!old_thread->reserved_stack				) {
		old_thread->reserved_stack = old_thread->kernel_stack;
	}

	if (old_cont != NULL) {
		if (new_thread->state & TH_STACK_HANDOFF) {
			/*
			 * If the old thread is using a privileged stack,
			 * check to see whether we can exchange it with
			 * that of the new thread.
			 */
			if (	old_thread->kernel_stack == old_thread->reserved_stack	&&
							!new_thread->reserved_stack)
				goto need_stack;

			new_thread->state &= ~TH_STACK_HANDOFF;
			new_cont = new_thread->continuation;
			new_thread->continuation = NULL;

			/*
			 * Set up ast context of new thread and switch
			 * to its timer.
			 */
			processor = current_processor();
			processor->active_thread = new_thread;
			processor->current_pri = new_thread->sched_pri;
			new_thread->last_processor = processor;
			ast_context(new_thread->top_act, processor->slot_num);
			timer_switch(&new_thread->system_timer);
			thread_unlock(new_thread);
		
			current_task()->csw++;

			old_thread->reason = reason;
			old_thread->continuation = old_cont;
	   
			_mk_sp_thread_done(old_thread, new_thread, processor);

			machine_stack_handoff(old_thread, new_thread);

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
				boolean_t	term, wake, callout;

				/*
				 * Waiting.
				 */
				old_thread->sleep_stamp = sched_tick;
				old_thread->state |= TH_STACK_HANDOFF;
				old_thread->state &= ~TH_RUN;

				term = (old_thread->state & TH_TERMINATE)? TRUE: FALSE;
				callout = old_thread->active_callout;
				wake = old_thread->wake_active;
				old_thread->wake_active = FALSE;

				if (old_thread->sched_mode & TH_MODE_TIMESHARE)
					pset_share_decr(old_thread->processor_set);
				pset_run_decr(old_thread->processor_set);

				thread_unlock(old_thread);
				wake_unlock(old_thread);

				if (callout)
					call_thread_block();

				if (wake)
					thread_wakeup((event_t)&old_thread->wake_active);

				if (term)
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

			funnel_refunnel_check(new_thread, 2);
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

			funnel_refunnel_check(new_thread, 3);
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
	processor->active_thread = new_thread;
	processor->current_pri = new_thread->sched_pri;
	new_thread->last_processor = processor;
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
	 * Here is where we actually change register context,
	 * and address space if required.  Note that control
	 * will not return here immediately.
	 */
	old_thread = machine_switch_context(old_thread, old_cont, new_thread);
	
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
		funnel_refunnel_check(new_thread, 3);
		(void) spllo();

		call_continuation(old_cont);
		/*NOTREACHED*/
	}

	return (TRUE);
}

/*
 *	thread_continue:
 *
 *	Called at splsched when a thread first receives
 *	a new stack after a continuation.
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

	funnel_refunnel_check(self, 4);
	(void)spllo();

	call_continuation(continuation);
	/*NOTREACHED*/
}

/*
 *	thread_block_reason:
 *
 *	Forces a reschedule, blocking the caller if a wait
 *	has been asserted.
 *
 *	If a continuation is specified, then thread_invoke will
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
	register processor_t	processor;
	register thread_t		new_thread;
	spl_t					s;

	counter(++c_thread_block_calls);

	check_simple_locks();

	s = splsched();

	if (!(reason & AST_PREEMPT))
		funnel_release_check(thread, 2);

	processor = current_processor();

	/* If we're explicitly yielding, force a subsequent quantum */
	if (reason & AST_YIELD)
		processor->timeslice = 0;

	/* We're handling all scheduling AST's */
	ast_off(AST_SCHEDULING);

	thread_lock(thread);
	new_thread = thread_select(processor);
	assert(new_thread && thread_runnable(new_thread));
	thread_unlock(thread);
	while (!thread_invoke(thread, new_thread, reason, continuation)) {
		thread_lock(thread);
		new_thread = thread_select(processor);
		assert(new_thread && thread_runnable(new_thread));
		thread_unlock(thread);
	}

	funnel_refunnel_check(thread, 5);
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
 *	new thread, handing off our quantum if appropriate.
 *
 *	New thread must be runnable, and not on a run queue.
 *
 *	Called at splsched.
 */
int
thread_run(
	thread_t			old_thread,
	thread_continue_t	continuation,
	thread_t			new_thread)
{
	ast_t		handoff = AST_HANDOFF;

	assert(old_thread == current_thread());

	funnel_release_check(old_thread, 3);

	while (!thread_invoke(old_thread, new_thread, handoff, continuation)) {
		register processor_t		processor = current_processor();

		thread_lock(old_thread);
		new_thread = thread_select(processor);
		thread_unlock(old_thread);
		handoff = AST_NONE;
	}

	funnel_refunnel_check(old_thread, 6);

	return (old_thread->wait_result);
}

/*
 *	Dispatches a running thread that is not	on a
 *	run queue.
 *
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
		boolean_t	term, wake, callout;
	
		/*
		 *	Waiting
		 */
		thread->sleep_stamp = sched_tick;
		thread->state &= ~TH_RUN;

		term = (thread->state & TH_TERMINATE)? TRUE: FALSE;
		callout = thread->active_callout;
		wake = thread->wake_active;
		thread->wake_active = FALSE;

		if (thread->sched_mode & TH_MODE_TIMESHARE)
			pset_share_decr(thread->processor_set);
		pset_run_decr(thread->processor_set);

		thread_unlock(thread);
		wake_unlock(thread);

		if (callout)
			call_thread_block();

		if (wake)
		    thread_wakeup((event_t)&thread->wake_active);

		if (term)
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
		panic("thread_dispatch: state 0x%x\n", thread->state);
	}

	thread_unlock(thread);
	wake_unlock(thread);
}

/*
 *	Enqueue thread on run queue.  Thread must be locked,
 *	and not already be on a run queue.  Returns TRUE
 *	if a preemption is indicated based on the state
 *	of the run queue.
 *
 *	Run queue must be locked, see run_queue_remove()
 *	for more info.
 */
static boolean_t
run_queue_enqueue(
	register run_queue_t	rq,
	register thread_t		thread,
	integer_t				options)
{
	register int			whichq = thread->sched_pri;
	register queue_t		queue = &rq->queues[whichq];
	boolean_t				result = FALSE;
	
	assert(whichq >= MINPRI && whichq <= MAXPRI);

	assert(thread->runq == RUN_QUEUE_NULL);
	if (queue_empty(queue)) {
		enqueue_tail(queue, (queue_entry_t)thread);

		setbit(MAXPRI - whichq, rq->bitmap);
		if (whichq > rq->highq) {
			rq->highq = whichq;
			result = TRUE;
		}
	}
	else
	if (options & SCHED_HEADQ)
		enqueue_head(queue, (queue_entry_t)thread);
	else
		enqueue_tail(queue, (queue_entry_t)thread);

	thread->runq = rq;
	if (thread->sched_mode & TH_MODE_PREEMPT)
		rq->urgency++;
	rq->count++;

	return (result);
}

/*
 *	Enqueue a thread for realtime execution, similar
 *	to above.  Handles preemption directly.
 */
static void
realtime_schedule_insert(
	register processor_set_t	pset,
	register thread_t			thread)
{
	register run_queue_t	rq = &pset->runq;
	register int			whichq = thread->sched_pri;
	register queue_t		queue = &rq->queues[whichq];
	uint64_t				deadline = thread->realtime.deadline;
	boolean_t				try_preempt = FALSE;

	assert(whichq >= BASEPRI_REALTIME && whichq <= MAXPRI);

	assert(thread->runq == RUN_QUEUE_NULL);
	if (queue_empty(queue)) {
		enqueue_tail(queue, (queue_entry_t)thread);

		setbit(MAXPRI - whichq, rq->bitmap);
		if (whichq > rq->highq)
			rq->highq = whichq;
		try_preempt = TRUE;
	}
	else {
		register thread_t	entry = (thread_t)queue_first(queue);

		while (TRUE) {
			if (	queue_end(queue, (queue_entry_t)entry)	||
						deadline < entry->realtime.deadline		) {
				entry = (thread_t)queue_prev((queue_entry_t)entry);
				break;
			}

			entry = (thread_t)queue_next((queue_entry_t)entry);
		}

		if ((queue_entry_t)entry == queue)
			try_preempt = TRUE;

		insque((queue_entry_t)thread, (queue_entry_t)entry);
	}

	thread->runq = rq;
	assert(thread->sched_mode & TH_MODE_PREEMPT);
	rq->count++; rq->urgency++;

	if (try_preempt) {
		register processor_t	processor;

		processor = current_processor();
		if (	pset == processor->processor_set				&&
				(thread->sched_pri > processor->current_pri	||
					deadline < processor->deadline			)		) {
			dispatch_counts.realtime_self++;
			simple_unlock(&pset->sched_lock);

			ast_on(AST_PREEMPT | AST_URGENT);
			return;
		}

		if (	pset->processor_count > 1			||
				pset != processor->processor_set	) {
			processor_t		myprocessor, lastprocessor;
			queue_entry_t	next;

			myprocessor = processor;
			processor = thread->last_processor;
			if (	processor != myprocessor						&&
					processor != PROCESSOR_NULL						&&
					processor->processor_set == pset				&&
					processor->state == PROCESSOR_RUNNING			&&
					(thread->sched_pri > processor->current_pri	||
						deadline < processor->deadline			)		) {
				dispatch_counts.realtime_last++;
				cause_ast_check(processor);
				simple_unlock(&pset->sched_lock);
				return;
			}

			lastprocessor = processor;
			queue = &pset->active_queue;
			processor = (processor_t)queue_first(queue);
			while (!queue_end(queue, (queue_entry_t)processor)) {
				next = queue_next((queue_entry_t)processor);

				if (	processor != myprocessor						&&
						processor != lastprocessor						&&
						(thread->sched_pri > processor->current_pri	||
							deadline < processor->deadline			)		) {
					if (!queue_end(queue, next)) {
						remqueue(queue, (queue_entry_t)processor);
						enqueue_tail(queue, (queue_entry_t)processor);
					}
					dispatch_counts.realtime_other++;
					cause_ast_check(processor);
					simple_unlock(&pset->sched_lock);
					return;
				}

				processor = (processor_t)next;
			}
		}
	}

	simple_unlock(&pset->sched_lock);
}

/*
 *	thread_setrun:
 *
 *	Dispatch thread for execution, directly onto an idle
 *	processor if possible.  Else put on appropriate run
 *	queue. (local if bound, else processor set)
 *
 *	Thread must be locked.
 */
void
thread_setrun(
	register thread_t			new_thread,
	integer_t					options)
{
	register processor_t		processor;
	register processor_set_t	pset;
	register thread_t			thread;
	ast_t						preempt = (options & SCHED_PREEMPT)?
													AST_PREEMPT: AST_NONE;

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
		preempt = (AST_PREEMPT | AST_URGENT);

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
			processor_lock(processor);
			simple_lock(&pset->sched_lock);
			if (	processor->processor_set == pset		&&
					processor->state == PROCESSOR_IDLE		) {
				remqueue(&pset->idle_queue, (queue_entry_t)processor);
				pset->idle_count--;
				processor->next_thread = new_thread;
				if (new_thread->sched_pri >= BASEPRI_RTQUEUES)
					processor->deadline = new_thread->realtime.deadline;
				else
					processor->deadline = UINT64_MAX;
				processor->state = PROCESSOR_DISPATCHING;
				dispatch_counts.idle_pset_last++;
				simple_unlock(&pset->sched_lock);
				processor_unlock(processor);
				if (processor != current_processor())
					machine_signal_idle(processor);
				return;
			}
			processor_unlock(processor);
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
			if (new_thread->sched_pri >= BASEPRI_RTQUEUES)
				processor->deadline = new_thread->realtime.deadline;
			else
				processor->deadline = UINT64_MAX;
			processor->state = PROCESSOR_DISPATCHING;
			dispatch_counts.idle_pset_any++;
			simple_unlock(&pset->sched_lock);
			if (processor != current_processor())	
				machine_signal_idle(processor);
			return;
		}

		if (new_thread->sched_pri >= BASEPRI_RTQUEUES)
			realtime_schedule_insert(pset, new_thread);
		else {
			if (!run_queue_enqueue(&pset->runq, new_thread, options))
				preempt = AST_NONE;

			/*
			 *	Update the timesharing quanta.
			 */
			timeshare_quanta_update(pset);
	
			/*
			 *	Preempt check.
			 */
			if (preempt != AST_NONE) {
				/*
				 * First try the current processor
				 * if it is a member of the correct
				 * processor set.
				 */
				processor = current_processor();
				thread = processor->active_thread;
				if (	pset == processor->processor_set	&&
						csw_needed(thread, processor)		) {
					dispatch_counts.pset_self++;
					simple_unlock(&pset->sched_lock);

					ast_on(preempt);
					return;
				}

				/*
				 * If that failed and we have other
				 * processors available keep trying.
				 */
				if (	pset->processor_count > 1			||
						pset != processor->processor_set	) {
					queue_t			queue = &pset->active_queue;
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
						dispatch_counts.pset_last++;
						cause_ast_check(processor);
						simple_unlock(&pset->sched_lock);
						return;
					}

					/*
					 * Lastly, pick any other
					 * available processor.
					 */
					lastprocessor = processor;
					processor = (processor_t)queue_first(queue);
					while (!queue_end(queue, (queue_entry_t)processor)) {
						next = queue_next((queue_entry_t)processor);

						if (	processor != myprocessor			&&
								processor != lastprocessor			&&
								new_thread->sched_pri >
											processor->current_pri		) {
							if (!queue_end(queue, next)) {
								remqueue(queue, (queue_entry_t)processor);
								enqueue_tail(queue, (queue_entry_t)processor);
							}
							dispatch_counts.pset_other++;
							cause_ast_check(processor);
							simple_unlock(&pset->sched_lock);
							return;
						}

						processor = (processor_t)next;
					}
				}
			}

			simple_unlock(&pset->sched_lock);
		}
	}
	else {
	    /*
	     *	Bound, can only run on bound processor.  Have to lock
	     *  processor here because it may not be the current one.
	     */
		processor_lock(processor);
		pset = processor->processor_set;
		if (pset != PROCESSOR_SET_NULL) {
			simple_lock(&pset->sched_lock);
			if (processor->state == PROCESSOR_IDLE) {
				remqueue(&pset->idle_queue, (queue_entry_t)processor);
				pset->idle_count--;
				processor->next_thread = new_thread;
				processor->deadline = UINT64_MAX;
				processor->state = PROCESSOR_DISPATCHING;
				dispatch_counts.idle_bound++;
				simple_unlock(&pset->sched_lock);
				processor_unlock(processor);
				if (processor != current_processor())	
					machine_signal_idle(processor);
				return;
			}
		}
	  
		if (!run_queue_enqueue(&processor->runq, new_thread, options))
			preempt = AST_NONE;

		if (preempt != AST_NONE) {
			if (processor == current_processor()) {
				thread = processor->active_thread;
				if (csw_needed(thread, processor)) {
					dispatch_counts.bound_self++;
					ast_on(preempt);
				}
			}
			else
			if (	processor->state == PROCESSOR_RUNNING			&&
					new_thread->sched_pri > processor->current_pri	) {
				dispatch_counts.bound_other++;
				cause_ast_check(processor);
			}
		}

		if (pset != PROCESSOR_SET_NULL)
			simple_unlock(&pset->sched_lock);

		processor_unlock(processor);
	}
}

/*
 *	Check for a possible preemption point in
 *	the (current) thread.
 *
 *	Called at splsched.
 */
ast_t
csw_check(
	thread_t		thread,
	processor_t		processor)
{
	int				current_pri = thread->sched_pri;
	ast_t			result = AST_NONE;
	run_queue_t		runq;

	if (first_timeslice(processor)) {
		runq = &processor->processor_set->runq;
		if (runq->highq >= BASEPRI_RTQUEUES)
			return (AST_PREEMPT | AST_URGENT);

		if (runq->highq > current_pri) {
			if (runq->urgency > 0)
				return (AST_PREEMPT | AST_URGENT);

			result |= AST_PREEMPT;
		}

		runq = &processor->runq;
		if (runq->highq > current_pri) {
			if (runq->urgency > 0)
				return (AST_PREEMPT | AST_URGENT);

			result |= AST_PREEMPT;
		}
	}
	else {
		runq = &processor->processor_set->runq;
		if (runq->highq >= current_pri) {
			if (runq->urgency > 0)
				return (AST_PREEMPT | AST_URGENT);

			result |= AST_PREEMPT;
		}

		runq = &processor->runq;
		if (runq->highq >= current_pri) {
			if (runq->urgency > 0)
				return (AST_PREEMPT | AST_URGENT);

			result |= AST_PREEMPT;
		}
	}

	if (result != AST_NONE)
		return (result);

	if (thread->state & TH_SUSP)
		result |= AST_PREEMPT;

	return (result);
}

/*
 *	set_sched_pri:
 *
 *	Set the scheduled priority of the specified thread.
 *
 *	This may cause the thread to change queues.
 *
 *	Thread must be locked.
 */
void
set_sched_pri(
	thread_t			thread,
	int					priority)
{
	register struct run_queue	*rq = run_queue_remove(thread);

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
		thread_setrun(thread, SCHED_PREEMPT | SCHED_TAILQ);
	else
	if (thread->state & TH_RUN) {
		processor_t		processor = thread->last_processor;

		if (thread == current_thread()) {
			ast_t		preempt = csw_check(thread, processor);

			if (preempt != AST_NONE)
				ast_on(preempt);
			processor->current_pri = priority;
		}
		else
		if (	processor != PROCESSOR_NULL						&&
				processor->active_thread == thread	)
			cause_ast_check(processor);
	}
}

/*
 *	run_queue_remove:
 *
 *	Remove a thread from its current run queue and
 *	return the run queue if successful.
 *
 *	Thread must be locked.
 */
run_queue_t
run_queue_remove(
	thread_t			thread)
{
	register run_queue_t	rq = thread->runq;

	/*
	 *	If rq is RUN_QUEUE_NULL, the thread will stay out of the
	 *	run queues because the caller locked the thread.  Otherwise
	 *	the thread is on a run queue, but could be chosen for dispatch
	 *	and removed.
	 */
	if (rq != RUN_QUEUE_NULL) {
		processor_set_t		pset = thread->processor_set;
		processor_t			processor = thread->bound_processor;

		/*
		 *	The run queues are locked by the pset scheduling
		 *	lock, except when a processor is off-line the
		 *	local run queue is locked by the processor lock.
		 */
		if (processor != PROCESSOR_NULL) {
			processor_lock(processor);
			pset = processor->processor_set;
		}

		if (pset != PROCESSOR_SET_NULL)
			simple_lock(&pset->sched_lock);

		if (rq == thread->runq) {
			/*
			 *	Thread is on a run queue and we have a lock on
			 *	that run queue.
			 */
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
		}
		else {
			/*
			 *	The thread left the run queue before we could
			 * 	lock the run queue.
			 */
			assert(thread->runq == RUN_QUEUE_NULL);
			rq = RUN_QUEUE_NULL;
		}

		if (pset != PROCESSOR_SET_NULL)
			simple_unlock(&pset->sched_lock);

		if (processor != PROCESSOR_NULL)
			processor_unlock(processor);
	}

	return (rq);
}

/*
 *	choose_thread:
 *
 *	Remove a thread to execute from the run queues
 *	and return it.
 *
 *	Called with pset scheduling lock held.
 */
static thread_t
choose_thread(
	processor_set_t		pset,
	processor_t			processor)
{
	register run_queue_t	runq;
	register thread_t		thread;
	register queue_t		q;

	runq = &processor->runq;

	if (runq->count > 0 && runq->highq >= pset->runq.highq) {
		q = runq->queues + runq->highq;

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

		processor->deadline = UINT64_MAX;

		return (thread);
	}

	runq = &pset->runq;

	assert(runq->count > 0);
	q = runq->queues + runq->highq;

	thread = (thread_t)q->next;
	((queue_entry_t)thread)->next->prev = q;
	q->next = ((queue_entry_t)thread)->next;
	thread->runq = RUN_QUEUE_NULL;
	runq->count--;
	if (runq->highq >= BASEPRI_RTQUEUES)
		processor->deadline = thread->realtime.deadline;
	else
		processor->deadline = UINT64_MAX;
	if (thread->sched_mode & TH_MODE_PREEMPT)
		runq->urgency--;
	assert(runq->urgency >= 0);
	if (queue_empty(q)) {
		if (runq->highq != IDLEPRI)
			clrbit(MAXPRI - runq->highq, runq->bitmap);
		runq->highq = MAXPRI - ffsbit(runq->bitmap);
	}

	timeshare_quanta_update(pset);

	return (thread);
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
	register processor_t		processor;
	register volatile thread_t	*threadp;
	register volatile int		*gcount;
	register volatile int		*lcount;
	register thread_t			new_thread;
	register int				state;
	register processor_set_t 	pset;
	int							mycpu;

	mycpu = cpu_number();
	processor = cpu_to_processor(mycpu);
	threadp = (volatile thread_t *) &processor->next_thread;
	lcount = (volatile int *) &processor->runq.count;

	gcount = (volatile int *)&processor->processor_set->runq.count;

	(void)splsched();
	while (	(*threadp == (volatile thread_t)THREAD_NULL)	&&
				(*gcount == 0) && (*lcount == 0)				) {

		/* check for ASTs while we wait */
		if (need_ast[mycpu] &~ (	AST_SCHEDULING | AST_BSD	)) {
			/* no ASTs for us */
			need_ast[mycpu] &= AST_NONE;
			(void)spllo();
		}
		else
			machine_idle();

		(void)splsched();
	}

	/*
	 *	This is not a switch statement to avoid the
	 *	bounds checking code in the common case.
	 */
	pset = processor->processor_set;
	simple_lock(&pset->sched_lock);

	state = processor->state;
	if (state == PROCESSOR_DISPATCHING) {
		/*
		 *	Commmon case -- cpu dispatched.
		 */
		new_thread = *threadp;
		*threadp = (volatile thread_t) THREAD_NULL;
		processor->state = PROCESSOR_RUNNING;
		enqueue_tail(&pset->active_queue, (queue_entry_t)processor);

		if (	pset->runq.highq >= BASEPRI_RTQUEUES			&&
				new_thread->sched_pri >= BASEPRI_RTQUEUES		) {
			register run_queue_t	runq = &pset->runq;
			register queue_t		q;

			q = runq->queues + runq->highq;
			if (((thread_t)q->next)->realtime.deadline <
											processor->deadline) {
				thread_t	thread = new_thread;

				new_thread = (thread_t)q->next;
				((queue_entry_t)new_thread)->next->prev = q;
				q->next = ((queue_entry_t)new_thread)->next;
				new_thread->runq = RUN_QUEUE_NULL;
				processor->deadline = new_thread->realtime.deadline;
				assert(new_thread->sched_mode & TH_MODE_PREEMPT);
				runq->count--; runq->urgency--;
				if (queue_empty(q)) {
					if (runq->highq != IDLEPRI)
						clrbit(MAXPRI - runq->highq, runq->bitmap);
					runq->highq = MAXPRI - ffsbit(runq->bitmap);
				}
				dispatch_counts.missed_realtime++;
				simple_unlock(&pset->sched_lock);

				thread_lock(thread);
				thread_setrun(thread, SCHED_HEADQ);
				thread_unlock(thread);

				counter(c_idle_thread_handoff++);
				thread_run(processor->idle_thread,
									idle_thread_continue, new_thread);
				/*NOTREACHED*/
			}
			simple_unlock(&pset->sched_lock);

			counter(c_idle_thread_handoff++);
			thread_run(processor->idle_thread,
								idle_thread_continue, new_thread);
			/*NOTREACHED*/
		}

		if (	processor->runq.highq > new_thread->sched_pri		||
				pset->runq.highq > new_thread->sched_pri				) {
			thread_t	thread = new_thread;

			new_thread = choose_thread(pset, processor);
			dispatch_counts.missed_other++;
			simple_unlock(&pset->sched_lock);

			thread_lock(thread);
			thread_setrun(thread, SCHED_HEADQ);
			thread_unlock(thread);

			counter(c_idle_thread_handoff++);
			thread_run(processor->idle_thread,
								idle_thread_continue, new_thread);
			/* NOTREACHED */
		}
		else {
			simple_unlock(&pset->sched_lock);

			counter(c_idle_thread_handoff++);
			thread_run(processor->idle_thread,
								idle_thread_continue, new_thread);
			/* NOTREACHED */
		}
	}
	else
	if (state == PROCESSOR_IDLE) {
		/*
		 *	Processor was not dispatched (Rare).
		 *	Set it running again and force a
		 *	reschedule.
		 */
		no_dispatch_count++;
		pset->idle_count--;
		remqueue(&pset->idle_queue, (queue_entry_t)processor);
		processor->state = PROCESSOR_RUNNING;
		enqueue_tail(&pset->active_queue, (queue_entry_t)processor);
		simple_unlock(&pset->sched_lock);

		counter(c_idle_thread_block++);
		thread_block(idle_thread_continue);
		/* NOTREACHED */
	}
	else
	if (state == PROCESSOR_SHUTDOWN) {
		/*
		 *	Going off-line.  Force a
		 *	reschedule.
		 */
		if ((new_thread = (thread_t)*threadp) != THREAD_NULL) {
			*threadp = (volatile thread_t) THREAD_NULL;
			processor->deadline = UINT64_MAX;
			simple_unlock(&pset->sched_lock);

			thread_lock(new_thread);
			thread_setrun(new_thread, SCHED_HEADQ);
			thread_unlock(new_thread);
		}
		else
			simple_unlock(&pset->sched_lock);

		counter(c_idle_thread_block++);
		thread_block(idle_thread_continue);
		/* NOTREACHED */
	}

	simple_unlock(&pset->sched_lock);

	panic("idle_thread: state %d\n", cpu_state(mycpu));
	/*NOTREACHED*/
}

void
idle_thread(void)
{
	counter(c_idle_thread_block++);
	thread_block(idle_thread_continue);
	/*NOTREACHED*/
}

static uint64_t		sched_tick_deadline;

void	sched_tick_thread(void);

void
sched_tick_init(void)
{
	kernel_thread_with_priority(sched_tick_thread, MAXPRI_STANDARD);
}

/*
 *	sched_tick_thread
 *
 *	Perform periodic bookkeeping functions about ten
 *	times per second.
 */
void
sched_tick_thread_continue(void)
{
	uint64_t			abstime;
#if	SIMPLE_CLOCK
	int					new_usec;
#endif	/* SIMPLE_CLOCK */

	abstime = mach_absolute_time();

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
	 *  Scan the run queues for timesharing threads which
	 *  may need to have their priorities recalculated.
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
	sched_tick_deadline = mach_absolute_time();

	thread_block(sched_tick_thread_continue);
	/*NOTREACHED*/
}

/*
 *	do_thread_scan:
 *
 *	Scan the run queues for timesharing threads which need
 *	to be aged, possibily adjusting their priorities upwards.
 *
 *	Scanner runs in two passes.  Pass one squirrels likely
 *	thread away in an array  (takes out references for them).
 *	Pass two does the priority updates.  This is necessary because
 *	the run queue lock is required for the candidate scan, but
 *	cannot be held during updates.
 *
 *	Array length should be enough so that restart isn't necessary,
 *	but restart logic is included.
 *
 */

#define	MAX_STUCK_THREADS	128

static thread_t	stuck_threads[MAX_STUCK_THREADS];
static int		stuck_count = 0;

/*
 *	do_runq_scan is the guts of pass 1.  It scans a runq for
 *	stuck threads.  A boolean is returned indicating whether
 *	a retry is needed.
 */
static boolean_t
do_runq_scan(
	run_queue_t				runq)
{
	register queue_t		q;
	register thread_t		thread;
	register int			count;
	boolean_t				result = FALSE;

	if ((count = runq->count) > 0) {
	    q = runq->queues + runq->highq;
		while (count > 0) {
			queue_iterate(q, thread, thread_t, links) {
				if (		thread->sched_stamp != sched_tick		&&
						(thread->sched_mode & TH_MODE_TIMESHARE)	) {
					/*
					 *	Stuck, save its id for later.
					 */
					if (stuck_count == MAX_STUCK_THREADS) {
						/*
						 *	!@#$% No more room.
						 */
						return (TRUE);
					}

					if (thread_lock_try(thread)) {
						thread->ref_count++;
						thread_unlock(thread);
						stuck_threads[stuck_count++] = thread;
					}
					else
						result = TRUE;
				}

				count--;
			}

			q--;
		}
	}

	return (result);
}

boolean_t	thread_scan_enabled = TRUE;

static void
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
		s = splsched();
		simple_lock(&pset->sched_lock);
	    restart_needed = do_runq_scan(&pset->runq);
		simple_unlock(&pset->sched_lock);

		if (!restart_needed) {
			simple_lock(&pset->sched_lock);
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
			simple_unlock(&pset->sched_lock);
		}
		splx(s);

	    /*
	     *	Ok, we now have a collection of candidates -- fix them.
	     */
	    while (stuck_count > 0) {
			boolean_t		idle_thread;

			thread = stuck_threads[--stuck_count];
			stuck_threads[stuck_count] = THREAD_NULL;

			s = splsched();
			thread_lock(thread);
			idle_thread = (thread->state & TH_IDLE) != 0;
			if (	!(thread->state & (TH_WAIT|TH_SUSP))	&&
						thread->sched_stamp != sched_tick	)
				update_priority(thread);
			thread_unlock(thread);
			splx(s);

			if (!idle_thread)
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

#include <ddb/db_output.h>
void		db_show_thread_log(void);

void
db_show_thread_log(void)
{
}
#endif	/* MACH_KDB */

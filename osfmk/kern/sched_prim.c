/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
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
#include <mach_kdb.h>

#include <ddb/db_output.h>

#include <mach/mach_types.h>
#include <mach/machine.h>
#include <mach/policy.h>
#include <mach/sync_policy.h>

#include <machine/machine_routines.h>
#include <machine/sched_param.h>
#include <machine/machine_cpu.h>

#include <kern/kern_types.h>
#include <kern/clock.h>
#include <kern/counters.h>
#include <kern/cpu_number.h>
#include <kern/cpu_data.h>
#include <kern/debug.h>
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
#include <kern/wait_queue.h>

#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>

#include <sys/kdebug.h>

#include <kern/pms.h>

struct run_queue	rt_runq;
#define RT_RUNQ		((processor_t)-1)
decl_simple_lock_data(static,rt_lock);

#define		DEFAULT_PREEMPTION_RATE		100		/* (1/s) */
int			default_preemption_rate = DEFAULT_PREEMPTION_RATE;

#define		MAX_UNSAFE_QUANTA			800
int			max_unsafe_quanta = MAX_UNSAFE_QUANTA;

#define		MAX_POLL_QUANTA				2
int			max_poll_quanta = MAX_POLL_QUANTA;

#define		SCHED_POLL_YIELD_SHIFT		4		/* 1/16 */
int			sched_poll_yield_shift = SCHED_POLL_YIELD_SHIFT;

uint64_t	max_unsafe_computation;
uint32_t	sched_safe_duration;
uint64_t	max_poll_computation;

uint32_t	std_quantum;
uint32_t	min_std_quantum;

uint32_t	std_quantum_us;

uint32_t	max_rt_quantum;
uint32_t	min_rt_quantum;

uint32_t	sched_cswtime;

unsigned	sched_tick;
uint32_t	sched_tick_interval;

uint32_t	sched_pri_shift = INT8_MAX;
uint32_t	sched_fixed_shift;

uint32_t	sched_run_count, sched_share_count;
uint32_t	sched_load_average, sched_mach_factor;

/* Forwards */
void wait_queues_init(void) __attribute__((section("__TEXT, initcode")));

static void load_shift_init(void) __attribute__((section("__TEXT, initcode")));
static void preempt_pri_init(void) __attribute__((section("__TEXT, initcode")));

static thread_t	thread_select_idle(
					thread_t			thread,
					processor_t			processor);

static thread_t	processor_idle(
					thread_t			thread,
					processor_t			processor);

static thread_t	choose_thread(
					processor_t			processor);

static thread_t	steal_thread(
					processor_set_t		pset);

static thread_t	steal_processor_thread(
					processor_t			processor);

static void		thread_update_scan(void);

#if	DEBUG
extern int debug_task;
#define TLOG(a, fmt, args...) if(debug_task & a) kprintf(fmt, ## args)
#else
#define TLOG(a, fmt, args...) do {} while (0)
#endif

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

int8_t		sched_load_shifts[NRQS];
int			sched_preempt_pri[NRQBM];

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
	load_shift_init();
	preempt_pri_init();
	simple_lock_init(&rt_lock, 0);
	run_queue_init(&rt_runq);
	sched_tick = 0;
	ast_init();
}

void
sched_timebase_init(void)
{
	uint64_t	abstime;
	uint32_t	shift;

	/* standard timeslicing quantum */
	clock_interval_to_absolutetime_interval(
							std_quantum_us, NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	std_quantum = abstime;

	/* smallest remaining quantum (250 us) */
	clock_interval_to_absolutetime_interval(250, NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	min_std_quantum = abstime;

	/* smallest rt computaton (50 us) */
	clock_interval_to_absolutetime_interval(50, NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	min_rt_quantum = abstime;

	/* maximum rt computation (50 ms) */
	clock_interval_to_absolutetime_interval(
							50, 1000*NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	max_rt_quantum = abstime;

	/* scheduler tick interval */
	clock_interval_to_absolutetime_interval(USEC_PER_SEC >> SCHED_TICK_SHIFT,
													NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	sched_tick_interval = abstime;

	/*
	 * Compute conversion factor from usage to
	 * timesharing priorities with 5/8 ** n aging.
	 */
	abstime = (abstime * 5) / 3;
	for (shift = 0; abstime > BASEPRI_DEFAULT; ++shift)
		abstime >>= 1;
	sched_fixed_shift = shift;

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
 * Set up values for timeshare
 * loading factors.
 */
static void
load_shift_init(void)
{
	int8_t		k, *p = sched_load_shifts;
	uint32_t	i, j;

	*p++ = INT8_MIN; *p++ = 0;

	for (i = j = 2, k = 1; i < NRQS; ++k) {
		for (j <<= 1; i < j; ++i)
			*p++ = k;
	}
}

static void
preempt_pri_init(void)
{
	int		i, *p = sched_preempt_pri;

	for (i = BASEPRI_FOREGROUND + 1; i < MINPRI_KERNEL; ++i)
		setbit(i, p);

	for (i = BASEPRI_PREEMPT; i <= MAXPRI; ++i)
		setbit(i, p);
}

/*
 *	Thread wait timer expiration.
 */
void
thread_timer_expire(
	void			*p0,
	__unused void	*p1)
{
	thread_t		thread = p0;
	spl_t			s;

	s = splsched();
	thread_lock(thread);
	if (--thread->wait_timer_active == 0) {
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
		if (!timer_call_enter(&thread->wait_timer, deadline))
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
		if (!timer_call_enter(&thread->wait_timer, deadline))
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
 *	thread_unblock:
 *
 *	Unblock thread on wake up.
 *
 *	Returns TRUE if the thread is still running.
 *
 *	Thread must be locked.
 */
boolean_t
thread_unblock(
	thread_t		thread,
	wait_result_t	wresult)
{
	boolean_t		result = FALSE;

	/*
	 *	Set wait_result.
	 */
	thread->wait_result = wresult;

	/*
	 *	Cancel pending wait timer.
	 */
	if (thread->wait_timer_is_set) {
		if (timer_call_cancel(&thread->wait_timer))
			thread->wait_timer_active--;
		thread->wait_timer_is_set = FALSE;
	}

	/*
	 *	Update scheduling state: not waiting,
	 *	set running.
	 */
	thread->state &= ~(TH_WAIT|TH_UNINT);

	if (!(thread->state & TH_RUN)) {
		thread->state |= TH_RUN;

		(*thread->sched_call)(SCHED_CALL_UNBLOCK, thread);

		/*
		 *	Update run counts.
		 */
		sched_run_incr();
		if (thread->sched_mode & TH_MODE_TIMESHARE)
			sched_share_incr();
	}
	else {
		/*
		 *	Signal if idling on another processor.
		 */
		if (thread->state & TH_IDLE) {
			processor_t		processor = thread->last_processor;

			if (processor != current_processor())
				machine_signal_idle(processor);
		}

		result = TRUE;
	}

	/*
	 * Calculate deadline for real-time threads.
	 */
	if (thread->sched_mode & TH_MODE_REALTIME) {
		thread->realtime.deadline = mach_absolute_time();
		thread->realtime.deadline += thread->realtime.constraint;
	}

	/*
	 * Clear old quantum, fail-safe computation, etc.
	 */
	thread->current_quantum = 0;
	thread->computation_metered = 0;
	thread->reason = AST_NONE;

	KERNEL_DEBUG_CONSTANT(
		MACHDBG_CODE(DBG_MACH_SCHED,MACH_MAKE_RUNNABLE) | DBG_FUNC_NONE,
					(int)thread, (int)thread->sched_pri, 0, 0, 0);

	return (result);
}

/*
 *	Routine:	thread_go
 *	Purpose:
 *		Unblock and dispatch thread.
 *	Conditions:
 *		thread lock held, IPC locks may be held.
 *		thread must have been pulled from wait queue under same lock hold.
 *  Returns:
 *		KERN_SUCCESS - Thread was set running
 *		KERN_NOT_WAITING - Thread was not waiting
 */
kern_return_t
thread_go(
	thread_t		thread,
	wait_result_t	wresult)
{
	assert(thread->at_safe_point == FALSE);
	assert(thread->wait_event == NO_EVENT64);
	assert(thread->wait_queue == WAIT_QUEUE_NULL);

	if ((thread->state & (TH_WAIT|TH_TERMINATE)) == TH_WAIT) {
		if (!thread_unblock(thread, wresult))
			thread_setrun(thread, SCHED_PREEMPT | SCHED_TAILQ);

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
	if (interruptible > (thread->options & TH_OPT_INTMASK))
		interruptible = thread->options & TH_OPT_INTMASK;

	at_safe_point = (interruptible == THREAD_ABORTSAFE);

	if (	interruptible == THREAD_UNINT			||
			!(thread->sched_mode & TH_MODE_ABORT)	||
			(!at_safe_point &&
				(thread->sched_mode & TH_MODE_ABORTSAFELY))) {
		thread->state |= (interruptible) ? TH_WAIT : (TH_WAIT | TH_UNINT);
		thread->at_safe_point = at_safe_point;
		return (thread->wait_result = THREAD_WAITING);
	}
	else
	if (thread->sched_mode & TH_MODE_ABORTSAFELY)
		thread->sched_mode &= ~TH_MODE_ISABORTED;

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
	wait_interrupt_t result = thread->options & TH_OPT_INTMASK;

	thread->options = (thread->options & ~TH_OPT_INTMASK) | (new_level & TH_OPT_INTMASK);

	return result;
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
	return wait_queue_assert_wait(wq, event, interruptible, 0);
}

wait_result_t
assert_wait_timeout(
	event_t				event,
	wait_interrupt_t	interruptible,
	uint32_t			interval,
	uint32_t			scale_factor)
{
	thread_t			thread = current_thread();
	wait_result_t		wresult;
	wait_queue_t		wqueue;
	uint64_t			deadline;
	spl_t				s;

	assert(event != NO_EVENT);
	wqueue = &wait_queues[wait_hash(event)];

	s = splsched();
	wait_queue_lock(wqueue);
	thread_lock(thread);

	clock_interval_to_deadline(interval, scale_factor, &deadline);
	wresult = wait_queue_assert_wait64_locked(wqueue, (uint32_t)event,
													interruptible, deadline, thread);

	thread_unlock(thread);
	wait_queue_unlock(wqueue);
	splx(s);

	return (wresult);
}

wait_result_t
assert_wait_deadline(
	event_t				event,
	wait_interrupt_t	interruptible,
	uint64_t			deadline)
{
	thread_t			thread = current_thread();
	wait_result_t		wresult;
	wait_queue_t		wqueue;
	spl_t				s;

	assert(event != NO_EVENT);
	wqueue = &wait_queues[wait_hash(event)];

	s = splsched();
	wait_queue_lock(wqueue);
	thread_lock(thread);

	wresult = wait_queue_assert_wait64_locked(wqueue, (uint32_t)event,
													interruptible, deadline, thread);

	thread_unlock(thread);
	wait_queue_unlock(wqueue);
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
 */
wait_result_t
thread_sleep_mutex_deadline(
	event_t			event,
	mutex_t			*mutex,
	uint64_t		deadline,
	wait_interrupt_t interruptible)
{
	wait_result_t	res;

	res = assert_wait_deadline(event, interruptible, deadline);
	if (res == THREAD_WAITING) {
		mutex_unlock(mutex);
		res = thread_block(THREAD_CONTINUE_NULL);
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
 * thread_stop:
 *
 * Force a preemption point for a thread and wait
 * for it to stop running.  Arbitrates access among
 * multiple stop requests. (released by unstop)
 *
 * The thread must enter a wait state and stop via a
 * separate means.
 *
 * Returns FALSE if interrupted.
 */
boolean_t
thread_stop(
	thread_t		thread)
{
	wait_result_t	wresult;
	spl_t			s = splsched();

	wake_lock(thread);
	thread_lock(thread);

	while (thread->state & TH_SUSP) {
		thread->wake_active = TRUE;
		thread_unlock(thread);

		wresult = assert_wait(&thread->wake_active, THREAD_ABORTSAFE);
		wake_unlock(thread);
		splx(s);

		if (wresult == THREAD_WAITING)
			wresult = thread_block(THREAD_CONTINUE_NULL);

		if (wresult != THREAD_AWAKENED)
			return (FALSE);

		s = splsched();
		wake_lock(thread);
		thread_lock(thread);
	}

	thread->state |= TH_SUSP;

	while (thread->state & TH_RUN) {
		processor_t		processor = thread->last_processor;

		if (processor != PROCESSOR_NULL && processor->active_thread == thread)
			cause_ast_check(processor);

		thread->wake_active = TRUE;
		thread_unlock(thread);

		wresult = assert_wait(&thread->wake_active, THREAD_ABORTSAFE);
		wake_unlock(thread);
		splx(s);

		if (wresult == THREAD_WAITING)
			wresult = thread_block(THREAD_CONTINUE_NULL);

		if (wresult != THREAD_AWAKENED) {
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
 * thread_unstop:
 *
 * Release a previous stop request and set
 * the thread running if appropriate.
 *
 * Use only after a successful stop operation.
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
		thread_unblock(thread, THREAD_AWAKENED);

		thread_setrun(thread, SCHED_PREEMPT | SCHED_TAILQ);
	}
	else
	if (thread->state & TH_SUSP) {
		thread->state &= ~TH_SUSP;

		if (thread->wake_active) {
			thread->wake_active = FALSE;
			thread_unlock(thread);

			thread_wakeup(&thread->wake_active);
			wake_unlock(thread);
			splx(s);

			return;
		}
	}

	thread_unlock(thread);
	wake_unlock(thread);
	splx(s);
}

/*
 * thread_wait:
 *
 * Wait for a thread to stop running. (non-interruptible)
 *
 */
void
thread_wait(
	thread_t		thread)
{
	wait_result_t	wresult;
	spl_t			s = splsched();

	wake_lock(thread);
	thread_lock(thread);

	while (thread->state & TH_RUN) {
		processor_t		processor = thread->last_processor;

		if (processor != PROCESSOR_NULL && processor->active_thread == thread)
			cause_ast_check(processor);

		thread->wake_active = TRUE;
		thread_unlock(thread);

		wresult = assert_wait(&thread->wake_active, THREAD_UNINT);
		wake_unlock(thread);
		splx(s);

		if (wresult == THREAD_WAITING)
			thread_block(THREAD_CONTINUE_NULL);

		s = splsched();
		wake_lock(thread);
		thread_lock(thread);
	}

	thread_unlock(thread);
	wake_unlock(thread);
	splx(s);
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

		return (thread_go(thread, wresult));
	} while (--i > 0);

	panic("clear_wait_internal: deadlock: thread=%p, wq=%p, cpu=%d\n",
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
 *	Force the current thread to execute on the specified processor.
 *
 *	Returns the previous binding.  PROCESSOR_NULL means
 *	not bound.
 *
 *	XXX - DO NOT export this to users - XXX
 */
processor_t
thread_bind(
	processor_t		processor)
{
	thread_t		self = current_thread();
	processor_t		prev;
	spl_t			s;

	s = splsched();
	thread_lock(self);

	prev = self->bound_processor;
	self->bound_processor = processor;

	thread_unlock(self);
	splx(s);

	return (prev);
}

/*
 *	thread_select:
 *
 *	Select a new thread for the current processor to execute.
 *
 *	May select the current thread, which must be locked.
 */
static thread_t
thread_select(
	thread_t			thread,
	processor_t			processor)
{
	processor_set_t		pset = processor->processor_set;
	thread_t			new_thread = THREAD_NULL;
	boolean_t			other_runnable;

	do {
		/*
		 *	Update the priority.
		 */
		if (thread->sched_stamp != sched_tick)
			update_priority(thread);

		processor->current_pri = thread->sched_pri;

		pset_lock(pset);

		simple_lock(&rt_lock);

		/*
		 *	Check for other runnable threads.
		 */
		other_runnable = processor->runq.count > 0 || rt_runq.count > 0;

		/*
		 *	Test to see if the current thread should continue
		 *	to run on this processor.  Must be runnable, and not
		 *	bound to a different processor, nor be in the wrong
		 *	processor set.
		 */
		if (	thread->state == TH_RUN							&&
				(thread->bound_processor == PROCESSOR_NULL	||
				 thread->bound_processor == processor)			&&
				(thread->affinity_set == AFFINITY_SET_NULL	||
				 thread->affinity_set->aset_pset == pset)			) {
			if (	thread->sched_pri >= BASEPRI_RTQUEUES	&&
						first_timeslice(processor)				) {
				if (rt_runq.highq >= BASEPRI_RTQUEUES) {
					register run_queue_t	runq = &rt_runq;
					register queue_t		q;

					q = runq->queues + runq->highq;
					if (((thread_t)q->next)->realtime.deadline <
													processor->deadline) {
						thread = (thread_t)q->next;
						((queue_entry_t)thread)->next->prev = q;
						q->next = ((queue_entry_t)thread)->next;
						thread->runq = PROCESSOR_NULL;
						runq->count--; runq->urgency--;
						assert(runq->urgency >= 0);
						if (queue_empty(q)) {
							if (runq->highq != IDLEPRI)
								clrbit(MAXPRI - runq->highq, runq->bitmap);
							runq->highq = MAXPRI - ffsbit(runq->bitmap);
						}
					}
				}

				simple_unlock(&rt_lock);

				processor->deadline = thread->realtime.deadline;

				pset_unlock(pset);

				return (thread);
			}

			if (	(!other_runnable							||
					 (processor->runq.highq < thread->sched_pri		&&
					  rt_runq.highq < thread->sched_pri))				) {

				simple_unlock(&rt_lock);

				/* I am the highest priority runnable (non-idle) thread */

				pset_pri_hint(pset, processor, processor->current_pri);

				processor->deadline = UINT64_MAX;

				pset_unlock(pset);

				return (thread);
			}
		}

		if (other_runnable)
			return choose_thread(processor);

		simple_unlock(&rt_lock);

		/*
		 *	No runnable threads, attempt to steal
		 *	from other processors.
		 */
		new_thread = steal_thread(pset);
		if (new_thread != THREAD_NULL)
			return (new_thread);

		/*
		 *	If other threads have appeared, shortcut
		 *	around again.
		 */
		if (processor->runq.count > 0 || rt_runq.count > 0)
			continue;

		pset_lock(pset);

		/*
		 *	Nothing is runnable, so set this processor idle if it
		 *	was running.
		 */
		if (processor->state == PROCESSOR_RUNNING) {
			remqueue(&pset->active_queue, (queue_entry_t)processor);
			processor->state = PROCESSOR_IDLE;

			enqueue_head(&pset->idle_queue, (queue_entry_t)processor);
			pset->low_pri = processor;
			pset->idle_count++;
		}

		processor->deadline = UINT64_MAX;

		pset_unlock(pset);

		/*
		 *	Choose idle thread if fast idle is not possible.
		 */
		if ((thread->state & (TH_IDLE|TH_TERMINATE|TH_SUSP)) || !(thread->state & TH_WAIT) || thread->wake_active)
			return (processor->idle_thread);

		/*
		 *	Perform idling activities directly without a
		 *	context switch.  Return dispatched thread,
		 *	else check again for a runnable thread.
		 */
		new_thread = thread_select_idle(thread, processor);

	} while (new_thread == THREAD_NULL);

	return (new_thread);
}

/*
 *	thread_select_idle:
 *
 *	Idle the processor using the current thread context.
 *
 *	Called with thread locked, then dropped and relocked.
 */
static thread_t
thread_select_idle(
	thread_t		thread,
	processor_t		processor)
{
	thread_t		new_thread;

	if (thread->sched_mode & TH_MODE_TIMESHARE)
		sched_share_decr();
	sched_run_decr();

	thread->state |= TH_IDLE;
	processor->current_pri = IDLEPRI;

	thread_unlock(thread);

	/*
	 *	Switch execution timing to processor idle thread.
	 */
	processor->last_dispatch = mach_absolute_time();
	thread_timer_event(processor->last_dispatch, &processor->idle_thread->system_timer);
	PROCESSOR_DATA(processor, kernel_timer) = &processor->idle_thread->system_timer;

	/*
	 *	Cancel the quantum timer while idling.
	 */
	timer_call_cancel(&processor->quantum_timer);
	processor->timeslice = 0;

	(*thread->sched_call)(SCHED_CALL_BLOCK, thread);

	/*
	 *	Enable interrupts and perform idling activities.  No
	 *	preemption due to TH_IDLE being set.
	 */
	spllo(); new_thread = processor_idle(thread, processor);

	/*
	 *	Return at splsched.
	 */
	(*thread->sched_call)(SCHED_CALL_UNBLOCK, thread);

	thread_lock(thread);

	/*
	 *	If awakened, switch to thread timer and start a new quantum.
	 *	Otherwise skip; we will context switch to another thread or return here.
	 */
	if (!(thread->state & TH_WAIT)) {
		processor->last_dispatch = mach_absolute_time();
		thread_timer_event(processor->last_dispatch, &thread->system_timer);
		PROCESSOR_DATA(processor, kernel_timer) = &thread->system_timer;

		thread_quantum_init(thread);

		processor->quantum_end = processor->last_dispatch + thread->current_quantum;
		timer_call_enter1(&processor->quantum_timer, thread, processor->quantum_end);
		processor->timeslice = 1;

		thread->computation_epoch = processor->last_dispatch;
	}

	thread->state &= ~TH_IDLE;

	sched_run_incr();
	if (thread->sched_mode & TH_MODE_TIMESHARE)
		sched_share_incr();

	return (new_thread);
}

/*
 *	Perform a context switch and start executing the new thread.
 *
 *	Returns FALSE on failure, and the thread is re-dispatched.
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

static boolean_t
thread_invoke(
	register thread_t	self,
	register thread_t	thread,
	ast_t				reason)
{
	thread_continue_t	continuation = self->continuation;
	void				*parameter = self->parameter;
	processor_t			processor;

	if (get_preemption_level() != 0)
		panic("thread_invoke: preemption_level %d\n",
				get_preemption_level());

	assert(self == current_thread());

	/*
	 * Mark thread interruptible.
	 */
	thread_lock(thread);
	thread->state &= ~TH_UNINT;

#if DEBUG
	assert(thread_runnable(thread));
#endif

	/*
	 * Allow time constraint threads to hang onto
	 * a stack.
	 */
	if ((self->sched_mode & TH_MODE_REALTIME) && !self->reserved_stack)
		self->reserved_stack = self->kernel_stack;

	if (continuation != NULL) {
		if (!thread->kernel_stack) {
			/*
			 * If we are using a privileged stack,
			 * check to see whether we can exchange it with
			 * that of the other thread.
			 */
			if (self->kernel_stack == self->reserved_stack && !thread->reserved_stack)
				goto need_stack;

			/*
			 * Context switch by performing a stack handoff.
			 */
			continuation = thread->continuation;
			parameter = thread->parameter;

			processor = current_processor();
			processor->active_thread = thread;
			processor->current_pri = thread->sched_pri;
			if (thread->last_processor != processor && thread->last_processor != NULL) {
				if (thread->last_processor->processor_set != processor->processor_set)
					thread->ps_switch++;
				thread->p_switch++;
			}
			thread->last_processor = processor;
			thread->c_switch++;
			ast_context(thread);
			thread_unlock(thread);

			self->reason = reason;

			processor->last_dispatch = mach_absolute_time();
			thread_timer_event(processor->last_dispatch, &thread->system_timer);
			PROCESSOR_DATA(processor, kernel_timer) = &thread->system_timer;
	
			KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_STACK_HANDOFF)|DBG_FUNC_NONE,
										self->reason, (int)thread, self->sched_pri, thread->sched_pri, 0);

TLOG(1, "thread_invoke: calling machine_stack_handoff\n");
			machine_stack_handoff(self, thread);

			thread_dispatch(self, thread);

			thread->continuation = thread->parameter = NULL;

			counter(c_thread_invoke_hits++);

			funnel_refunnel_check(thread, 2);
			(void) spllo();

			assert(continuation);
			call_continuation(continuation, parameter, thread->wait_result);
			/*NOTREACHED*/
		}
		else if (thread == self) {
			/* same thread but with continuation */
			ast_context(self);
			counter(++c_thread_invoke_same);
			thread_unlock(self);

			self->continuation = self->parameter = NULL;

			funnel_refunnel_check(self, 3);
			(void) spllo();

			call_continuation(continuation, parameter, self->wait_result);
			/*NOTREACHED*/
		}
	}
	else {
		/*
		 * Check that the other thread has a stack
		 */
		if (!thread->kernel_stack) {
need_stack:
			if (!stack_alloc_try(thread)) {
				counter(c_thread_invoke_misses++);
				thread_unlock(thread);
				thread_stack_enqueue(thread);
				return (FALSE);
			}
		}
		else if (thread == self) {
			ast_context(self);
			counter(++c_thread_invoke_same);
			thread_unlock(self);
			return (TRUE);
		}
	}

	/*
	 * Context switch by full context save.
	 */
	processor = current_processor();
	processor->active_thread = thread;
	processor->current_pri = thread->sched_pri;
	if (thread->last_processor != processor && thread->last_processor != NULL) {
		if (thread->last_processor->processor_set != processor->processor_set)
			thread->ps_switch++;
		thread->p_switch++;
	}
	thread->last_processor = processor;
	thread->c_switch++;
	ast_context(thread);
	thread_unlock(thread);

	counter(c_thread_invoke_csw++);

	assert(self->runq == PROCESSOR_NULL);
	self->reason = reason;

	processor->last_dispatch = mach_absolute_time();
	thread_timer_event(processor->last_dispatch, &thread->system_timer);
	PROCESSOR_DATA(processor, kernel_timer) = &thread->system_timer;

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED,MACH_SCHED) | DBG_FUNC_NONE,
							(int)self->reason, (int)thread, self->sched_pri, thread->sched_pri, 0);

	/*
	 * This is where we actually switch register context,
	 * and address space if required.  We will next run
	 * as a result of a subsequent context switch.
	 */
	thread = machine_switch_context(self, continuation, thread);
TLOG(1,"thread_invoke: returning machine_switch_context: self %p continuation %p thread %p\n", self, continuation, thread);

	/*
	 * We have been resumed and are set to run.
	 */
	thread_dispatch(thread, self);

	if (continuation) {
		self->continuation = self->parameter = NULL;

		funnel_refunnel_check(self, 3);
		(void) spllo();

		call_continuation(continuation, parameter, self->wait_result);
		/*NOTREACHED*/
	}

	return (TRUE);
}

/*
 *	thread_dispatch:
 *
 *	Handle threads at context switch.  Re-dispatch other thread
 *	if still running, otherwise update run state and perform
 *	special actions.  Update quantum for other thread and begin
 *	the quantum for ourselves.
 *
 *	Called at splsched.
 */
void
thread_dispatch(
	thread_t		thread,
	thread_t		self)
{
	processor_t		processor = self->last_processor;

	if (thread != THREAD_NULL) {
		/*
		 *	If blocked at a continuation, discard
		 *	the stack.
		 */
		if (thread->continuation != NULL && thread->kernel_stack != 0)
			stack_free(thread);

		if (!(thread->state & TH_IDLE)) {
			wake_lock(thread);
			thread_lock(thread);

			/*
			 *	Compute remainder of current quantum.
			 */
			if (	first_timeslice(processor)							&&
					processor->quantum_end > processor->last_dispatch		)
				thread->current_quantum = (processor->quantum_end - processor->last_dispatch);
			else
				thread->current_quantum = 0;

			if (thread->sched_mode & TH_MODE_REALTIME) {
				/*
				 *	Cancel the deadline if the thread has
				 *	consumed the entire quantum.
				 */
				if (thread->current_quantum == 0) {
					thread->realtime.deadline = UINT64_MAX;
					thread->reason |= AST_QUANTUM;
				}
			}
			else {
				/*
				 *	For non-realtime threads treat a tiny
				 *	remaining quantum as an expired quantum
				 *	but include what's left next time.
				 */
				if (thread->current_quantum < min_std_quantum) {
					thread->reason |= AST_QUANTUM;
					thread->current_quantum += std_quantum;
				}
			}

			/*
			 *	If we are doing a direct handoff then
			 *	take the remainder of the quantum.
			 */
			if ((thread->reason & (AST_HANDOFF|AST_QUANTUM)) == AST_HANDOFF) {
				self->current_quantum = thread->current_quantum;
				thread->reason |= AST_QUANTUM;
				thread->current_quantum = 0;
			}

			thread->last_switch = processor->last_dispatch;

			thread->computation_metered += (thread->last_switch - thread->computation_epoch);

			if (!(thread->state & TH_WAIT)) {
				/*
				 *	Still running.
				 */
				if (thread->reason & AST_QUANTUM)
					thread_setrun(thread, SCHED_TAILQ);
				else
				if (thread->reason & AST_PREEMPT)
					thread_setrun(thread, SCHED_HEADQ);
				else
					thread_setrun(thread, SCHED_PREEMPT | SCHED_TAILQ);

				thread->reason = AST_NONE;

				thread_unlock(thread);
				wake_unlock(thread);
			}
			else {
				/*
				 *	Waiting.
				 */
				thread->state &= ~TH_RUN;

				if (thread->sched_mode & TH_MODE_TIMESHARE)
					sched_share_decr();
				sched_run_decr();

				if (thread->wake_active) {
					thread->wake_active = FALSE;
					thread_unlock(thread);

					thread_wakeup(&thread->wake_active);
				}
				else
					thread_unlock(thread);

				wake_unlock(thread);

				(*thread->sched_call)(SCHED_CALL_BLOCK, thread);

				if (thread->state & TH_TERMINATE)
					thread_terminate_enqueue(thread);
			}
		}
	}

	if (!(self->state & TH_IDLE)) {
		/*
		 *	Get a new quantum if none remaining.
		 */
		if (self->current_quantum == 0)
			thread_quantum_init(self);

		/*
		 *	Set up quantum timer and timeslice.
		 */
		processor->quantum_end = (processor->last_dispatch + self->current_quantum);
		timer_call_enter1(&processor->quantum_timer, self, processor->quantum_end);

		processor->timeslice = 1;

		self->last_switch = processor->last_dispatch;

		self->computation_epoch = self->last_switch;
	}
	else {
		timer_call_cancel(&processor->quantum_timer);
		processor->timeslice = 0;
	}
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
 
wait_result_t
thread_block_reason(
	thread_continue_t	continuation,
	void				*parameter,
	ast_t				reason)
{
	register thread_t		self = current_thread();
	register processor_t	processor;
	register thread_t		new_thread;
	spl_t					s;

	counter(++c_thread_block_calls);

	s = splsched();

	if (!(reason & AST_PREEMPT))
		funnel_release_check(self, 2);

	processor = current_processor();

	/* If we're explicitly yielding, force a subsequent quantum */
	if (reason & AST_YIELD)
		processor->timeslice = 0;

	/* We're handling all scheduling AST's */
	ast_off(AST_SCHEDULING);

	self->continuation = continuation;
	self->parameter = parameter;

	do {
		thread_lock(self);
		new_thread = thread_select(self, processor);
		thread_unlock(self);
	} while (!thread_invoke(self, new_thread, reason));

	funnel_refunnel_check(self, 5);
	splx(s);

	return (self->wait_result);
}

/*
 *	thread_block:
 *
 *	Block the current thread if a wait has been asserted.
 */
wait_result_t
thread_block(
	thread_continue_t	continuation)
{
	return thread_block_reason(continuation, NULL, AST_NONE);
}

wait_result_t
thread_block_parameter(
	thread_continue_t	continuation,
	void				*parameter)
{
	return thread_block_reason(continuation, parameter, AST_NONE);
}

/*
 *	thread_run:
 *
 *	Switch directly from the current thread to the
 *	new thread, handing off our quantum if appropriate.
 *
 *	New thread must be runnable, and not on a run queue.
 *
 *	Called at splsched.
 */
int
thread_run(
	thread_t			self,
	thread_continue_t	continuation,
	void				*parameter,
	thread_t			new_thread)
{
	ast_t		handoff = AST_HANDOFF;

	funnel_release_check(self, 3);

	self->continuation = continuation;
	self->parameter = parameter;

	while (!thread_invoke(self, new_thread, handoff)) {
		processor_t		processor = current_processor();

		thread_lock(self);
		new_thread = thread_select(self, processor);
		thread_unlock(self);
		handoff = AST_NONE;
	}

	funnel_refunnel_check(self, 6);

	return (self->wait_result);
}

/*
 *	thread_continue:
 *
 *	Called at splsched when a thread first receives
 *	a new stack after a continuation.
 */
void
thread_continue(
	register thread_t	thread)
{
	register thread_t			self = current_thread();
	register thread_continue_t	continuation;
	register void				*parameter;
	
	continuation = self->continuation;
	parameter = self->parameter;

	thread_dispatch(thread, self);

	self->continuation = self->parameter = NULL;

	funnel_refunnel_check(self, 4);

	if (thread != THREAD_NULL)
		(void)spllo();

 TLOG(1, "thread_continue: calling call_continuation \n");
	call_continuation(continuation, parameter, self->wait_result);
	/*NOTREACHED*/
}

/*
 *	run_queue_init:
 *
 *	Initialize a run queue before first use.
 */
void
run_queue_init(
	run_queue_t		rq)
{
	int				i;

	rq->highq = IDLEPRI;
	for (i = 0; i < NRQBM; i++)
		rq->bitmap[i] = 0;
	setbit(MAXPRI - IDLEPRI, rq->bitmap);
	rq->urgency = rq->count = 0;
	for (i = 0; i < NRQS; i++)
		queue_init(&rq->queues[i]);
}

/*
 *	run_queue_dequeue:
 *
 *	Perform a dequeue operation on a run queue,
 *	and return the resulting thread.
 *
 *	The run queue must be locked (see run_queue_remove()
 *	for more info), and not empty.
 */
static thread_t
run_queue_dequeue(
	run_queue_t		rq,
	integer_t		options)
{
	thread_t		thread;
	queue_t			queue = rq->queues + rq->highq;

	if (options & SCHED_HEADQ) {
		thread = (thread_t)queue->next;
		((queue_entry_t)thread)->next->prev = queue;
		queue->next = ((queue_entry_t)thread)->next;
	}
	else {
		thread = (thread_t)queue->prev;
		((queue_entry_t)thread)->prev->next = queue;
		queue->prev = ((queue_entry_t)thread)->prev;
	}

	thread->runq = PROCESSOR_NULL;
	rq->count--;
	if (testbit(rq->highq, sched_preempt_pri)) {
		rq->urgency--; assert(rq->urgency >= 0);
	}
	if (queue_empty(queue)) {
		if (rq->highq != IDLEPRI)
			clrbit(MAXPRI - rq->highq, rq->bitmap);
		rq->highq = MAXPRI - ffsbit(rq->bitmap);
	}

	return (thread);
}

/*
 *	realtime_queue_insert:
 *
 *	Enqueue a thread for realtime execution.
 */
static boolean_t
realtime_queue_insert(
	thread_t			thread)
{
	run_queue_t			rq = &rt_runq;
	queue_t				queue = rq->queues + thread->sched_pri;
	uint64_t			deadline = thread->realtime.deadline;
	boolean_t			preempt = FALSE;

	simple_lock(&rt_lock);

	if (queue_empty(queue)) {
		enqueue_tail(queue, (queue_entry_t)thread);

		setbit(MAXPRI - thread->sched_pri, rq->bitmap);
		if (thread->sched_pri > rq->highq)
			rq->highq = thread->sched_pri;
		preempt = TRUE;
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
			preempt = TRUE;

		insque((queue_entry_t)thread, (queue_entry_t)entry);
	}

	thread->runq = RT_RUNQ;
	rq->count++; rq->urgency++;

	simple_unlock(&rt_lock);

	return (preempt);
}

/*
 *	realtime_setrun:
 *
 *	Dispatch a thread for realtime execution.
 *
 *	Thread must be locked.  Associated pset must
 *	be locked, and is returned unlocked.
 */
static void
realtime_setrun(
	processor_t			processor,
	thread_t			thread)
{
	processor_set_t		pset = processor->processor_set;

	/*
	 *	Dispatch directly onto idle processor.
	 */
	if (processor->state == PROCESSOR_IDLE) {
		remqueue(&pset->idle_queue, (queue_entry_t)processor);
		pset->idle_count--;
		enqueue_tail(&pset->active_queue, (queue_entry_t)processor);

		processor->next_thread = thread;
		processor->deadline = thread->realtime.deadline;
		processor->state = PROCESSOR_DISPATCHING;
		pset_unlock(pset);

		if (processor != current_processor())
			machine_signal_idle(processor);
		return;
	}

	if (realtime_queue_insert(thread)) {
		if (processor == current_processor())
			ast_on(AST_PREEMPT | AST_URGENT);
		else
			cause_ast_check(processor);
	}

	pset_unlock(pset);
}

/*
 *	processor_enqueue:
 *
 *	Enqueue thread on a processor run queue.  Thread must be locked,
 *	and not already be on a run queue.
 *
 *	Returns TRUE if a preemption is indicated based on the state
 *	of the run queue.
 *
 *	The run queue must be locked (see run_queue_remove()
 *	for more info).
 */
static boolean_t
processor_enqueue(
	processor_t		processor,
	thread_t		thread,
	integer_t		options)
{
	run_queue_t		rq = &processor->runq;
	queue_t			queue = rq->queues + thread->sched_pri;
	boolean_t		result = FALSE;
	
	if (queue_empty(queue)) {
		enqueue_tail(queue, (queue_entry_t)thread);

		setbit(MAXPRI - thread->sched_pri, rq->bitmap);
		if (thread->sched_pri > rq->highq) {
			rq->highq = thread->sched_pri;
			result = TRUE;
		}
	}
	else
	if (options & SCHED_TAILQ)
		enqueue_tail(queue, (queue_entry_t)thread);
	else
		enqueue_head(queue, (queue_entry_t)thread);

	thread->runq = processor;
	if (testbit(thread->sched_pri, sched_preempt_pri))
		rq->urgency++;
	rq->count++;

	return (result);
}

/*
 *	processor_setrun:
 *
 *	Dispatch a thread for execution on a
 *	processor.
 *
 *	Thread must be locked.  Associated pset must
 *	be locked, and is returned unlocked.
 */
static void
processor_setrun(
	processor_t			processor,
	thread_t			thread,
	integer_t			options)
{
	processor_set_t		pset = processor->processor_set;
	ast_t				preempt;

	/*
	 *	Dispatch directly onto idle processor.
	 */
	if (processor->state == PROCESSOR_IDLE) {
		remqueue(&pset->idle_queue, (queue_entry_t)processor);
		pset->idle_count--;
		enqueue_tail(&pset->active_queue, (queue_entry_t)processor);

		processor->next_thread = thread;
		processor->deadline = UINT64_MAX;
		processor->state = PROCESSOR_DISPATCHING;
		pset_unlock(pset);

		if (processor != current_processor())
			machine_signal_idle(processor);
		return;
	}

	/*
	 *	Set preemption mode.
	 */
	if (testbit(thread->sched_pri, sched_preempt_pri))
		preempt = (AST_PREEMPT | AST_URGENT);
	else
	if (thread->sched_mode & TH_MODE_TIMESHARE && thread->priority < BASEPRI_BACKGROUND)
		preempt = AST_NONE;
	else
		preempt = (options & SCHED_PREEMPT)? AST_PREEMPT: AST_NONE;

	if (!processor_enqueue(processor, thread, options))
		preempt = AST_NONE;

	if (preempt != AST_NONE) {
		if (processor == current_processor()) {
			thread_t	self = processor->active_thread;

			if (csw_needed(self, processor))
				ast_on(preempt);
		}
		else
		if (	(processor->state == PROCESSOR_RUNNING		||
				 processor->state == PROCESSOR_SHUTDOWN)		&&
				thread->sched_pri >= processor->current_pri		) {
			cause_ast_check(processor);
		}
	}
	else
	if (	processor->state == PROCESSOR_SHUTDOWN		&&
			thread->sched_pri >= processor->current_pri	) {
		cause_ast_check(processor);
	}

	pset_unlock(pset);
}

#define next_pset(p)	(((p)->pset_list != PROCESSOR_SET_NULL)? (p)->pset_list: (p)->node->psets)

/*
 *	choose_next_pset:
 *
 *	Return the next sibling pset containing
 *	available processors.
 *
 *	Returns the original pset if none other is
 *	suitable.
 */
static processor_set_t
choose_next_pset(
	processor_set_t		pset)
{
	processor_set_t		nset = pset;

	do {
		nset = next_pset(nset);
	} while (nset->processor_count < 1 && nset != pset);

	return (nset);
}

/*
 *	choose_processor:
 *
 *	Choose a processor for the thread, beginning at
 *	the pset.
 *
 *	Returns a processor, possibly from a different pset.
 *
 *	The thread must be locked.  The pset must be locked,
 *	and the resulting pset is locked on return.
 */
static processor_t
choose_processor(
	processor_set_t		pset,
	thread_t			thread)
{
	processor_set_t		nset, cset = pset;
	processor_t			processor = thread->last_processor;

	/*
	 *	Prefer the last processor, when appropriate.
	 */
	if (processor != PROCESSOR_NULL) {
		if (processor->processor_set != pset ||
				processor->state == PROCESSOR_SHUTDOWN || processor->state == PROCESSOR_OFF_LINE)
			processor = PROCESSOR_NULL;
		else
		if (processor->state == PROCESSOR_IDLE || processor->current_pri < thread->sched_pri)
			return (processor);
	}

	/*
	 *	Iterate through the processor sets to locate
	 *	an appropriate processor.
	 */
	do {
		/*
		 *	Choose an idle processor.
		 */
		if (!queue_empty(&cset->idle_queue))
			return ((processor_t)queue_first(&cset->idle_queue));

		if (thread->sched_pri >= BASEPRI_RTQUEUES) {
			/*
			 *	For an RT thread, iterate through active processors, first fit.
			 */
			processor = (processor_t)queue_first(&cset->active_queue);
			while (!queue_end(&cset->active_queue, (queue_entry_t)processor)) {
				if (thread->sched_pri > processor->current_pri ||
						thread->realtime.deadline < processor->deadline)
					return (processor);

				processor = (processor_t)queue_next((queue_entry_t)processor);
			}

			processor = PROCESSOR_NULL;
		}
		else {
			/*
			 *	Check the low hint processor in the processor set if available.
			 */
			if (cset->low_pri != PROCESSOR_NULL &&
						cset->low_pri->state != PROCESSOR_SHUTDOWN && cset->low_pri->state != PROCESSOR_OFF_LINE) {
				if (processor == PROCESSOR_NULL || cset->low_pri->current_pri < thread->sched_pri)
					processor = cset->low_pri;
			}

			/*
			 *	Otherwise, choose an available processor in the set.
			 */
			if (processor == PROCESSOR_NULL) {
				processor = (processor_t)dequeue_head(&cset->active_queue);
				if (processor != PROCESSOR_NULL)
					enqueue_tail(&cset->active_queue, (queue_entry_t)processor);
			}
		}

		/*
		 *	Move onto the next processor set.
		 */
		nset = next_pset(cset);

		if (nset != pset) {
			pset_unlock(cset);

			cset = nset;
			pset_lock(cset);
		}
	} while (nset != pset);

	/*
	 *	Make sure that we pick a running processor,
	 *	and that the correct processor set is locked.
	 */
	do {
		/*
		 *	If we haven't been able to choose a processor,
		 *	pick the current one and return it.
		 */
		if (processor == PROCESSOR_NULL) {
			processor = current_processor();

			/*
			 *	Check that the correct processor set is
			 *	returned locked.
			 */
			if (cset != processor->processor_set) {
				pset_unlock(cset);

				cset = processor->processor_set;
				pset_lock(cset);
			}

			return (processor);
		}

		/*
		 *	Check that the processor set for the chosen
		 *	processor is locked.
		 */
		if (cset != processor->processor_set) {
			pset_unlock(cset);

			cset = processor->processor_set;
			pset_lock(cset);
		}

		/*
		 *	We must verify that the chosen processor is still available.
		 */
		if (processor->state == PROCESSOR_SHUTDOWN || processor->state == PROCESSOR_OFF_LINE)
			processor = PROCESSOR_NULL;
	} while (processor == PROCESSOR_NULL);

	return (processor);
}

/*
 *	thread_setrun:
 *
 *	Dispatch thread for execution, onto an idle
 *	processor or run queue, and signal a preemption
 *	as appropriate.
 *
 *	Thread must be locked.
 */
void
thread_setrun(
	thread_t			thread,
	integer_t			options)
{
	processor_t			processor;
	processor_set_t		pset;

#if DEBUG
	assert(thread_runnable(thread));
#endif
	
	/*
	 *	Update priority if needed.
	 */
	if (thread->sched_stamp != sched_tick)
		update_priority(thread);

	assert(thread->runq == PROCESSOR_NULL);

	if (thread->bound_processor == PROCESSOR_NULL) {
		/*
		 *	Unbound case.
		 */
		if (thread->affinity_set != AFFINITY_SET_NULL) {
			/*
			 * Use affinity set policy hint.
			 */
			pset = thread->affinity_set->aset_pset;
			pset_lock(pset);

			processor = choose_processor(pset, thread);
		}
		else
		if (thread->last_processor != PROCESSOR_NULL) {
			/*
			 *	Simple (last processor) affinity case.
			 */
			processor = thread->last_processor;
			pset = processor->processor_set;
			pset_lock(pset);

			/*
			 *	Choose a different processor in certain cases.
			 */
			if (thread->sched_pri >= BASEPRI_RTQUEUES) {
				/*
				 *	If the processor is executing an RT thread with
				 *	an earlier deadline, choose another.
				 */
				if (thread->sched_pri <= processor->current_pri ||
						thread->realtime.deadline >= processor->deadline)
					processor = choose_processor(pset, thread);
			}
			else
				processor = choose_processor(pset, thread);
		}
		else {
			/*
			 *	No Affinity case:
			 *
			 *	Utilitize a per task hint to spread threads
			 *	among the available processor sets.
			 */
			task_t		task = thread->task;

			pset = task->pset_hint;
			if (pset == PROCESSOR_SET_NULL)
				pset = current_processor()->processor_set;

			pset = choose_next_pset(pset);
			pset_lock(pset);

			processor = choose_processor(pset, thread);
			task->pset_hint = processor->processor_set;
		}
	}
	else {
		/*
		 *	Bound case:
		 *
		 *	Unconditionally dispatch on the processor.
		 */
		processor = thread->bound_processor;
		pset = processor->processor_set;
		pset_lock(pset);
	}

	/*
	 *	Dispatch the thread on the choosen processor.
	 */
	if (thread->sched_pri >= BASEPRI_RTQUEUES)
		realtime_setrun(processor, thread);
	else
		processor_setrun(processor, thread, options);
}

/*
 *	processor_queue_shutdown:
 *
 *	Shutdown a processor run queue by moving
 *	non-bound threads to the current processor.
 *
 *	Associated pset must be locked, and is
 *	returned unlocked.
 */
void
processor_queue_shutdown(
	processor_t			processor)
{
	processor_set_t		pset = processor->processor_set;
	run_queue_t			rq = &processor->runq;
	queue_t				queue = rq->queues + rq->highq;
	int					pri = rq->highq, count = rq->count;
	thread_t			next, thread;
	queue_head_t		tqueue;

	queue_init(&tqueue);
	
	while (count > 0) {
		thread = (thread_t)queue_first(queue);
		while (!queue_end(queue, (queue_entry_t)thread)) {
			next = (thread_t)queue_next((queue_entry_t)thread);

			if (thread->bound_processor != processor) {
				remqueue(queue, (queue_entry_t)thread);

				thread->runq = PROCESSOR_NULL;
				rq->count--;
				if (testbit(pri, sched_preempt_pri)) {
					rq->urgency--; assert(rq->urgency >= 0);
				}
				if (queue_empty(queue)) {
					if (pri != IDLEPRI)
						clrbit(MAXPRI - pri, rq->bitmap);
					rq->highq = MAXPRI - ffsbit(rq->bitmap);
				}

				enqueue_tail(&tqueue, (queue_entry_t)thread);
			}
			count--;

			thread = next;
		}

		queue--; pri--;
	}

	pset_unlock(pset);

	processor = current_processor();
	pset = processor->processor_set;

	while ((thread = (thread_t)dequeue_head(&tqueue)) != THREAD_NULL) {
		thread_lock(thread);
		thread->last_processor = PROCESSOR_NULL;

		pset_lock(pset);

		processor_enqueue(processor, thread, SCHED_TAILQ);

		pset_unlock(pset);

		thread_unlock(thread);
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
		runq = &rt_runq;
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
		runq = &rt_runq;
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
	thread_t		thread,
	int				priority)
{
	boolean_t		removed = run_queue_remove(thread);

	thread->sched_pri = priority;
	if (removed)
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

#if		0

static void
run_queue_check(
	run_queue_t		rq,
	thread_t		thread)
{
	queue_t			q;
	queue_entry_t	qe;

	if (rq != thread->runq)
		panic("run_queue_check: thread runq");

	if (thread->sched_pri > MAXPRI || thread->sched_pri < MINPRI)
		panic("run_queue_check: thread sched_pri");

	q = &rq->queues[thread->sched_pri];
	qe = queue_first(q);
	while (!queue_end(q, qe)) {
		if (qe == (queue_entry_t)thread)
			return;

		qe = queue_next(qe);
	}

	panic("run_queue_check: end");
}

#endif	/* DEBUG */

/*
 *	run_queue_remove:
 *
 *	Remove a thread from a current run queue and
 *	return TRUE if successful.
 *
 *	Thread must be locked.
 */
boolean_t
run_queue_remove(
	thread_t		thread)
{
	processor_t		processor = thread->runq;

	/*
	 *	If processor is PROCESSOR_NULL, the thread will stay out of the
	 *	run queues because the caller locked the thread.  Otherwise
	 *	the thread is on a run queue, but could be chosen for dispatch
	 *	and removed.
	 */
	if (processor != PROCESSOR_NULL) {
		void *			rqlock;
		run_queue_t		rq;

		/*
		 *	The processor run queues are locked by the
		 *	processor set.  Real-time priorities use a
		 *	global queue with a dedicated lock.
		 */
		if (thread->sched_pri < BASEPRI_RTQUEUES) {
			rqlock = &processor->processor_set->sched_lock;
			rq = &processor->runq;
		}
		else {
			rqlock = &rt_lock; rq = &rt_runq;
		}

		simple_lock(rqlock);

		if (processor == thread->runq) {
			/*
			 *	Thread is on a run queue and we have a lock on
			 *	that run queue.
			 */
			remqueue(&rq->queues[0], (queue_entry_t)thread);
			rq->count--;
			if (testbit(thread->sched_pri, sched_preempt_pri)) {
				rq->urgency--; assert(rq->urgency >= 0);
			}

			if (queue_empty(rq->queues + thread->sched_pri)) {
				/* update run queue status */
				if (thread->sched_pri != IDLEPRI)
					clrbit(MAXPRI - thread->sched_pri, rq->bitmap);
				rq->highq = MAXPRI - ffsbit(rq->bitmap);
			}

			thread->runq = PROCESSOR_NULL;
		}
		else {
			/*
			 *	The thread left the run queue before we could
			 * 	lock the run queue.
			 */
			assert(thread->runq == PROCESSOR_NULL);
			processor = PROCESSOR_NULL;
		}

		simple_unlock(rqlock);
	}

	return (processor != PROCESSOR_NULL);
}

/*
 *	choose_thread:
 *
 *	Choose a thread to execute from the run queues
 *	and return it.
 *
 *	Called with pset scheduling lock and rt lock held,
 *	released on return.
 */
static thread_t
choose_thread(
	processor_t			processor)
{
	processor_set_t		pset = processor->processor_set;
	thread_t			thread;

	if (processor->runq.count > 0 && processor->runq.highq >= rt_runq.highq) {
		simple_unlock(&rt_lock);

		thread = run_queue_dequeue(&processor->runq, SCHED_HEADQ);

		pset_pri_hint(pset, processor, thread->sched_pri);

		processor->deadline = UINT64_MAX;
		pset_unlock(pset);

		return (thread);
	}

	thread = run_queue_dequeue(&rt_runq, SCHED_HEADQ);
	simple_unlock(&rt_lock);

	processor->deadline = thread->realtime.deadline;
	pset_unlock(pset);

	return (thread);
}

/*
 *	steal_processor_thread:
 *
 *	Locate a thread to steal from the processor and
 *	return it.
 *
 *	Associated pset must be locked.  Returns THREAD_NULL
 *	on failure.
 */
static thread_t
steal_processor_thread(
	processor_t		processor)
{
	run_queue_t		rq = &processor->runq;
	queue_t			queue = rq->queues + rq->highq;
	int				pri = rq->highq, count = rq->count;
	thread_t		thread;

	while (count > 0) {
		thread = (thread_t)queue_first(queue);
		while (!queue_end(queue, (queue_entry_t)thread)) {
			if (thread->bound_processor != processor) {
				remqueue(queue, (queue_entry_t)thread);

				thread->runq = PROCESSOR_NULL;
				rq->count--;
				if (testbit(pri, sched_preempt_pri)) {
					rq->urgency--; assert(rq->urgency >= 0);
				}
				if (queue_empty(queue)) {
					if (pri != IDLEPRI)
						clrbit(MAXPRI - pri, rq->bitmap);
					rq->highq = MAXPRI - ffsbit(rq->bitmap);
				}

				return (thread);
			}
			count--;

			thread = (thread_t)queue_next((queue_entry_t)thread);
		}

		queue--; pri--;
	}

	return (THREAD_NULL);
}

/*
 *	Locate and steal a thread, beginning
 *	at the pset.
 *
 *	The pset must be locked, and is returned
 *	unlocked.
 *
 *	Returns the stolen thread, or THREAD_NULL on
 *	failure.
 */
static thread_t
steal_thread(
	processor_set_t		pset)
{
	processor_set_t		nset, cset = pset;
	processor_t			processor;
	thread_t			thread;

	do {
		processor = (processor_t)queue_first(&cset->active_queue);
		while (!queue_end(&cset->active_queue, (queue_entry_t)processor)) {
			if (processor->runq.count > 0) {
				thread = steal_processor_thread(processor);
				if (thread != THREAD_NULL) {
					remqueue(&cset->active_queue, (queue_entry_t)processor);
					enqueue_tail(&cset->active_queue, (queue_entry_t)processor);

					processor->deadline = UINT64_MAX;
					pset_unlock(cset);

					return (thread);
				}
			}

			processor = (processor_t)queue_next((queue_entry_t)processor);
		}

		nset = next_pset(cset);

		if (nset != pset) {
			pset_unlock(cset);

			cset = nset;
			pset_lock(cset);
		}
	} while (nset != pset);

	pset_unlock(cset);

	return (THREAD_NULL);
}

/*
 *	This is the processor idle loop, which just looks for other threads
 *	to execute.  Processor idle threads invoke this without supplying a
 *	current thread to idle without an asserted wait state.
 *
 *	Returns a the next thread to execute if dispatched directly.
 */
static thread_t
processor_idle(
	thread_t			thread,
	processor_t			processor)
{
	processor_set_t		pset = processor->processor_set;
	thread_t			new_thread;
	int					state;

	(void)splsched();

#ifdef __ppc__
	pmsDown();					/* Step power down */
#endif

	KERNEL_DEBUG_CONSTANT(
		MACHDBG_CODE(DBG_MACH_SCHED,MACH_IDLE) | DBG_FUNC_START, (int)thread, 0, 0, 0, 0);

	timer_switch(&PROCESSOR_DATA(processor, system_state),
									mach_absolute_time(), &PROCESSOR_DATA(processor, idle_state));
	PROCESSOR_DATA(processor, current_state) = &PROCESSOR_DATA(processor, idle_state);

	while (processor->next_thread == THREAD_NULL && processor->runq.count == 0 && rt_runq.count == 0 &&
				(thread == THREAD_NULL || ((thread->state & (TH_WAIT|TH_SUSP)) == TH_WAIT && !thread->wake_active))) {
		machine_idle();

		(void)splsched();
	}

	timer_switch(&PROCESSOR_DATA(processor, idle_state),
									mach_absolute_time(), &PROCESSOR_DATA(processor, system_state));
	PROCESSOR_DATA(processor, current_state) = &PROCESSOR_DATA(processor, system_state);

	pset_lock(pset);

#ifdef __ppc__
	pmsStep(0);					/* Step up out of idle power */
#endif

	state = processor->state;
	if (state == PROCESSOR_DISPATCHING) {
		/*
		 *	Commmon case -- cpu dispatched.
		 */
		new_thread = processor->next_thread;
		processor->next_thread = THREAD_NULL;
		processor->state = PROCESSOR_RUNNING;

		if (	processor->runq.highq > new_thread->sched_pri					||
				(rt_runq.highq > 0 && rt_runq.highq >= new_thread->sched_pri)	) {
			processor->deadline = UINT64_MAX;

			pset_unlock(pset);

			thread_lock(new_thread);
			thread_setrun(new_thread, SCHED_HEADQ);
			thread_unlock(new_thread);

			KERNEL_DEBUG_CONSTANT(
				MACHDBG_CODE(DBG_MACH_SCHED,MACH_IDLE) | DBG_FUNC_END, (int)thread, (int)state, 0, 0, 0);
	
			return (THREAD_NULL);
		}

		pset_unlock(pset);

		KERNEL_DEBUG_CONSTANT(
			MACHDBG_CODE(DBG_MACH_SCHED,MACH_IDLE) | DBG_FUNC_END, (int)thread, (int)state, (int)new_thread, 0, 0);

		return (new_thread);
	}
	else
	if (state == PROCESSOR_IDLE) {
		remqueue(&pset->idle_queue, (queue_entry_t)processor);
		pset->idle_count--;

		processor->state = PROCESSOR_RUNNING;
		enqueue_tail(&pset->active_queue, (queue_entry_t)processor);
	}
	else
	if (state == PROCESSOR_SHUTDOWN) {
		/*
		 *	Going off-line.  Force a
		 *	reschedule.
		 */
		if ((new_thread = processor->next_thread) != THREAD_NULL) {
			processor->next_thread = THREAD_NULL;
			processor->deadline = UINT64_MAX;

			pset_unlock(pset);

			thread_lock(new_thread);
			thread_setrun(new_thread, SCHED_HEADQ);
			thread_unlock(new_thread);

			KERNEL_DEBUG_CONSTANT(
				MACHDBG_CODE(DBG_MACH_SCHED,MACH_IDLE) | DBG_FUNC_END, (int)thread, (int)state, 0, 0, 0);

			return (THREAD_NULL);
		}
	}

	pset_unlock(pset);

	KERNEL_DEBUG_CONSTANT(
		MACHDBG_CODE(DBG_MACH_SCHED,MACH_IDLE) | DBG_FUNC_END, (int)thread, (int)state, 0, 0, 0);

	return (THREAD_NULL);
}

/*
 *	Each processor has a dedicated thread which
 *	executes the idle loop when there is no suitable
 *	previous context.
 */
void
idle_thread(void)
{
	processor_t		processor = current_processor();
	thread_t		new_thread;

	new_thread = processor_idle(THREAD_NULL, processor);
	if (new_thread != THREAD_NULL) {
		thread_run(processor->idle_thread, (thread_continue_t)idle_thread, NULL, new_thread);
		/*NOTREACHED*/
	}

	thread_block((thread_continue_t)idle_thread);
	/*NOTREACHED*/
}

kern_return_t
idle_thread_create(
	processor_t		processor)
{
	kern_return_t	result;
	thread_t		thread;
	spl_t			s;

	result = kernel_thread_create((thread_continue_t)idle_thread, NULL, MAXPRI_KERNEL, &thread);
	if (result != KERN_SUCCESS)
		return (result);

	s = splsched();
	thread_lock(thread);
	thread->bound_processor = processor;
	processor->idle_thread = thread;
	thread->sched_pri = thread->priority = IDLEPRI;
	thread->state = (TH_RUN | TH_IDLE);
	thread_unlock(thread);
	splx(s);

	thread_deallocate(thread);

	return (KERN_SUCCESS);
}

static uint64_t		sched_tick_deadline;

/*
 * sched_startup:
 *
 * Kicks off scheduler services.
 *
 * Called at splsched.
 */
void
sched_startup(void)
{
	kern_return_t	result;
	thread_t		thread;

	result = kernel_thread_start_priority((thread_continue_t)sched_tick_thread, NULL, MAXPRI_KERNEL, &thread);
	if (result != KERN_SUCCESS)
		panic("sched_startup");

	thread_deallocate(thread);

	/*
	 * Yield to the sched_tick_thread while it times
	 * a series of context switches back.  It stores
	 * the baseline value in sched_cswtime.
	 *
	 * The current thread is the only other thread
	 * active at this point.
	 */
	while (sched_cswtime == 0)
		thread_block(THREAD_CONTINUE_NULL);

	thread_daemon_init();

	thread_call_initialize();
}

/*
 *	sched_tick_thread:
 *
 *	Perform periodic bookkeeping functions about ten
 *	times per second.
 */
static void
sched_tick_continue(void)
{
	uint64_t			abstime = mach_absolute_time();

	sched_tick++;

	/*
	 *  Compute various averages.
	 */
	compute_averages();

	/*
	 *  Scan the run queues for threads which
	 *  may need to be updated.
	 */
	thread_update_scan();

	clock_deadline_for_periodic_event(sched_tick_interval, abstime,
														&sched_tick_deadline);

	assert_wait_deadline((event_t)sched_tick_thread, THREAD_UNINT, sched_tick_deadline);
	thread_block((thread_continue_t)sched_tick_continue);
	/*NOTREACHED*/
}

/*
 * Time a series of context switches to determine
 * a baseline.  Toss the high and low and return
 * the one-way value.
 */
static uint32_t
time_cswitch(void)
{
	uint32_t	new, hi, low, accum;
	uint64_t	abstime;
	int			i, tries = 7;

	accum = hi = low = 0;
	for (i = 0; i < tries; ++i) {
		abstime = mach_absolute_time();
		thread_block(THREAD_CONTINUE_NULL);

		new = mach_absolute_time() - abstime;

		if (i == 0)
			accum = hi = low = new;
		else {
			if (new < low)
				low = new;
			else
			if (new > hi)
				hi = new;
			accum += new;
		}
	}

	return ((accum - hi - low) / (2 * (tries - 2)));
}

void
sched_tick_thread(void)
{
	sched_cswtime = time_cswitch();

	sched_tick_deadline = mach_absolute_time();

	sched_tick_continue();
	/*NOTREACHED*/
}

/*
 *	thread_update_scan / runq_scan:
 *
 *	Scan the run queues to account for timesharing threads 
 *	which need to be updated.
 *
 *	Scanner runs in two passes.  Pass one squirrels likely
 *	threads away in an array, pass two does the update.
 *
 *	This is necessary because the run queue is locked for
 *	the candidate scan, but	the thread is locked for the update.
 *
 *	Array should be sized to make forward progress, without
 *	disabling preemption for long periods.
 */

#define	THREAD_UPDATE_SIZE		128

static thread_t		thread_update_array[THREAD_UPDATE_SIZE];
static int			thread_update_count = 0;

/*
 *	Scan a runq for candidate threads.
 *
 *	Returns TRUE if retry is needed.
 */
static boolean_t
runq_scan(
	run_queue_t				runq)
{
	register int			count;
	register queue_t		q;
	register thread_t		thread;

	if ((count = runq->count) > 0) {
	    q = runq->queues + runq->highq;
		while (count > 0) {
			queue_iterate(q, thread, thread_t, links) {
				if (		thread->sched_stamp != sched_tick		&&
						(thread->sched_mode & TH_MODE_TIMESHARE)	) {
					if (thread_update_count == THREAD_UPDATE_SIZE)
						return (TRUE);

					thread_update_array[thread_update_count++] = thread;
					thread_reference_internal(thread);
				}

				count--;
			}

			q--;
		}
	}

	return (FALSE);
}

static void
thread_update_scan(void)
{
	boolean_t			restart_needed = FALSE;
	processor_t			processor = processor_list;
	processor_set_t		pset;
	thread_t			thread;
	spl_t				s;

	do {
		do {
			pset = processor->processor_set;

			s = splsched();
			pset_lock(pset);

			restart_needed = runq_scan(&processor->runq);

			pset_unlock(pset);
			splx(s);

			if (restart_needed)
				break;

			thread = processor->idle_thread;
			if (thread != THREAD_NULL && thread->sched_stamp != sched_tick) {
				if (thread_update_count == THREAD_UPDATE_SIZE) {
					restart_needed = TRUE;
					break;
				}

				thread_update_array[thread_update_count++] = thread;
				thread_reference_internal(thread);
			}
		} while ((processor = processor->processor_list) != NULL);

	    /*
	     *	Ok, we now have a collection of candidates -- fix them.
	     */
	    while (thread_update_count > 0) {
			thread = thread_update_array[--thread_update_count];
			thread_update_array[thread_update_count] = THREAD_NULL;

			s = splsched();
			thread_lock(thread);
			if (	!(thread->state & (TH_WAIT|TH_SUSP))	&&
						thread->sched_stamp != sched_tick	)
				update_priority(thread);
			thread_unlock(thread);
			splx(s);

			thread_deallocate(thread);
	    }
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

boolean_t
preemption_enabled(void)
{
	return (get_preemption_level() == 0 && ml_get_interrupts_enabled());
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
	iprintf("Idle thread:\n\thandoff %d block %d\n",
		c_idle_thread_handoff,
		c_idle_thread_block);
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

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
#include <kern/sf.h>
#include <kern/mk_sp.h>	/*** ??? fix so this can be removed ***/
#include <sys/kdebug.h>

#if	TASK_SWAPPER
#include <kern/task_swap.h>
extern int	task_swap_on;
#endif	/* TASK_SWAPPER */

extern int	hz;

#define		DEFAULT_PREEMPTION_RATE		100	/* (1/s) */
int			default_preemption_rate = DEFAULT_PREEMPTION_RATE;

#define		NO_KERNEL_PREEMPT	0
#define		KERNEL_PREEMPT		1
int			kernel_preemption_mode = KERNEL_PREEMPT;

int			min_quantum;
natural_t	min_quantum_ms;

unsigned	sched_tick;

#if	SIMPLE_CLOCK
int			sched_usec;
#endif	/* SIMPLE_CLOCK */

/* Forwards */
void        thread_continue(thread_t);

void		wait_queues_init(void);

void		set_pri(
				thread_t		thread,
				int				pri,
				int				resched);

thread_t	choose_pset_thread(
				processor_t			myprocessor,
				processor_set_t		pset);

thread_t	choose_thread(
				processor_t		myprocessor);

int			run_queue_enqueue(
				run_queue_t		runq,
				thread_t		thread,
				boolean_t		tail);

void		idle_thread_continue(void);
void		do_thread_scan(void);

void		clear_wait_internal(
				thread_t		thread,
				int				result);

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
#endif	/*DEBUG*/

boolean_t	thread_runnable(
				thread_t		thread);

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
	 *	Calculate the minimum quantum
	 *	in ticks.
	 */
	if (default_preemption_rate < 1)
		default_preemption_rate = DEFAULT_PREEMPTION_RATE;
	min_quantum = hz / default_preemption_rate;

	/*
	 *	Round up result (4/5) to an
	 *	integral number of ticks.
	 */
	if (((hz * 10) / default_preemption_rate) - (min_quantum * 10) >= 5)
		min_quantum++;
	if (min_quantum < 1)
		min_quantum = 1;

	min_quantum_ms = (1000 / hz) * min_quantum;

	printf("scheduling quantum is %d ms\n", min_quantum_ms);

	wait_queues_init();
	pset_sys_bootstrap();		/* initialize processor mgmt. */
	processor_action();
	sched_tick = 0;
#if	SIMPLE_CLOCK
	sched_usec = 0;
#endif	/* SIMPLE_CLOCK */
	ast_init();
	sf_init();
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
 *	Thread timeout routine, called when timer expires.
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
	if (	thread->wait_timer_is_set							&&
			!timer_call_is_delayed(&thread->wait_timer, NULL)		) {
		thread->wait_timer_active--;
		thread->wait_timer_is_set = FALSE;
		thread_lock(thread);
		if (thread->active)
			clear_wait_internal(thread, THREAD_TIMED_OUT);
		thread_unlock(thread);
	}
	else
	if (--thread->wait_timer_active == 0)
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
	natural_t		interval,
	natural_t		scale_factor)
{
	thread_t		thread = current_thread();
	AbsoluteTime	deadline;
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
	AbsoluteTime	deadline)
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
 *	thread_depress_timeout:
 *
 *	Timeout routine for priority depression.
 */
void
thread_depress_timeout(
	thread_call_param_t		p0,
	thread_call_param_t		p1)
{
	thread_t		thread = p0;
    sched_policy_t	*policy;
    spl_t			s;

    s = splsched();
    thread_lock(thread);
    policy = policy_id_to_sched_policy(thread->policy);
    thread_unlock(thread);
    splx(s);

	if (policy != SCHED_POLICY_NULL)
		policy->sp_ops.sp_thread_depress_timeout(policy, thread);

	thread_deallocate(thread);
}

/*
 * Set up thread timeout element when thread is created.
 */
void
thread_timer_setup(
	 thread_t		thread)
{
	timer_call_setup(&thread->wait_timer, thread_timer_expire, thread);
	thread->wait_timer_is_set = FALSE;
	thread->wait_timer_active = 1;
	thread->ref_count++;

	thread_call_setup(&thread->depress_timer, thread_depress_timeout, thread);
}

void
thread_timer_terminate(void)
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

	thread->wait_timer_active--;

	while (thread->wait_timer_active > 0) {
		assert_wait((event_t)&thread->wait_timer_active, THREAD_UNINT);
		wake_unlock(thread);
		splx(s);

		thread_block((void (*)(void)) 0);

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
 */
void
thread_go_locked(
	thread_t		thread,
	int				result)
{
	int				state;
	sched_policy_t	*policy;
	sf_return_t		sfr;

	assert(thread->at_safe_point == FALSE);
	assert(thread->wait_event == NO_EVENT);
	assert(thread->wait_queue == WAIT_QUEUE_NULL);

	if (thread->state & TH_WAIT) {

		thread->state &= ~(TH_WAIT|TH_UNINT);
		if (!(thread->state & TH_RUN)) {
			thread->state |= TH_RUN;
#if	THREAD_SWAPPER
			if (thread->state & TH_SWAPPED_OUT)
				thread_swapin(thread->top_act, FALSE);
			else 
#endif	/* THREAD_SWAPPER */
			{
				policy = &sched_policy[thread->policy];
				sfr = policy->sp_ops.sp_thread_unblock(policy, thread);
				assert(sfr == SF_SUCCESS);
			}
		}
		thread->wait_result = result;
	}

					
	/*
	 * The next few lines are a major hack. Hopefully this will get us
	 * around all of the scheduling framework hooha. We can't call
	 * sp_thread_unblock yet because we could still be finishing up the
	 * durn two stage block on another processor and thread_setrun
	 * could be called by s_t_u and we'll really be messed up then.
	 */		
	/* Don't mess with this if we are still swapped out */
	if (!(thread->state & TH_SWAPPED_OUT))
		thread->sp_state = MK_SP_RUNNABLE;
			
}

void
thread_mark_wait_locked(
	thread_t		thread,
	int		    interruptible)
{

	assert(thread == current_thread());

	thread->wait_result = -1; /* JMM - Needed for non-assert kernel */
	thread->state |= (interruptible && thread->interruptible) ? 
							TH_WAIT : (TH_WAIT | TH_UNINT);
	thread->at_safe_point = (interruptible == THREAD_ABORTSAFE) && (thread->interruptible);
	thread->sleep_stamp = sched_tick;
}



/*
 *	Routine:	assert_wait_timeout
 *	Purpose:
 *		Assert that the thread intends to block,
 *		waiting for a timeout (no user known event).
 */
unsigned int assert_wait_timeout_event;

void
assert_wait_timeout(
        mach_msg_timeout_t		msecs,
	int				interruptible)
{
	spl_t		s;

	assert_wait((event_t)&assert_wait_timeout_event, interruptible);
	thread_set_timer(msecs, 1000*NSEC_PER_USEC);
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
void
assert_wait(
	event_t				event,
	int				interruptible)
{
	register wait_queue_t	wq;
	register int		index;

	assert(event != NO_EVENT);
	assert(assert_wait_possible());

	index = wait_hash(event);
	wq = &wait_queues[index];
	wait_queue_assert_wait(wq,
			       event,
			       interruptible);
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
	thread_t			thread)
{
	spl_t				s;

	s = splsched();
	wake_lock(thread);

	while (thread->state & TH_SUSP) {
		thread->wake_active = TRUE;
		assert_wait((event_t)&thread->wake_active, THREAD_ABORTSAFE);
		wake_unlock(thread);
		splx(s);

		thread_block((void (*)(void)) 0);
		if (current_thread()->wait_result != THREAD_AWAKENED)
			return (FALSE);

		s = splsched();
		wake_lock(thread);
	}
	thread_lock(thread);
	thread->state |= TH_SUSP;
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
	thread_t			thread)
{
	sched_policy_t		*policy;
	sf_return_t			sfr;
	spl_t				s;

	s = splsched();
	wake_lock(thread);
	thread_lock(thread);

	if ((thread->state & (TH_RUN|TH_WAIT|TH_SUSP/*|TH_UNINT*/)) == TH_SUSP) {
		thread->state = (thread->state & ~TH_SUSP) | TH_RUN;
#if	THREAD_SWAPPER
		if (thread->state & TH_SWAPPED_OUT)
			thread_swapin(thread->top_act, FALSE);
		else
#endif	/* THREAD_SWAPPER */
			{
				policy = &sched_policy[thread->policy];
				sfr = policy->sp_ops.sp_thread_unblock(policy, thread);
				assert(sfr == SF_SUCCESS);
			}
	}
	else
	if (thread->state & TH_SUSP) {
		thread->state &= ~TH_SUSP;

		if (thread->wake_active) {
			thread->wake_active = FALSE;
			thread_unlock(thread);
			wake_unlock(thread);
			splx(s);
			thread_wakeup((event_t)&thread->wake_active);

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
	thread_t		thread)
{
	spl_t			s;

	s = splsched();
	wake_lock(thread);

	while (thread->state & (TH_RUN/*|TH_UNINT*/)) {
		if (thread->last_processor != PROCESSOR_NULL)
			cause_ast_check(thread->last_processor);

		thread->wake_active = TRUE;
		assert_wait((event_t)&thread->wake_active, THREAD_ABORTSAFE);
		wake_unlock(thread);
		splx(s);

		thread_block((void (*)(void))0);
		if (current_thread()->wait_result != THREAD_AWAKENED)
			return (FALSE);

		s = splsched();
		wake_lock(thread);
	}

	wake_unlock(thread);
	splx(s);

	return (TRUE);
}


/*
 * thread_stop_wait(thread)
 *	Stop the thread then wait for it to block interruptibly
 */
boolean_t
thread_stop_wait(
	thread_t		thread)
{
	if (thread_stop(thread)) {
		if (thread_wait(thread))
			return (TRUE);

		thread_unstop(thread);
	}

	return (FALSE);
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
 */
void
clear_wait_internal(
	thread_t	thread,
	int		result)
{
	/*
	 * If the thread isn't in a wait queue, just set it running.  Otherwise,
	 * try to remove it from the queue and, if successful, then set it
	 * running.  NEVER interrupt an uninterruptible thread.
	 */
	if (!((result == THREAD_INTERRUPTED) && (thread->state & TH_UNINT))) {
		if (wait_queue_assert_possible(thread) ||
		    (wait_queue_remove(thread) == KERN_SUCCESS)) {
			thread_go_locked(thread, result);
		}
	}
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
void
clear_wait(
	thread_t	thread,
	int		result)
{
	spl_t		s;

	s = splsched();
	thread_lock(thread);
	clear_wait_internal(thread, result);
	thread_unlock(thread);
	splx(s);
}


/*
 *	thread_wakeup_prim:
 *
 *	Common routine for thread_wakeup, thread_wakeup_with_result,
 *	and thread_wakeup_one.
 *
 */
void
thread_wakeup_prim(
	event_t			event,
	boolean_t		one_thread,
	int			result)
{
	register wait_queue_t	wq;
	register int			index;

	index = wait_hash(event);
	wq = &wait_queues[index];
	if (one_thread)
	    wait_queue_wakeup_one(wq, event, result);
	else
	    wait_queue_wakeup_all(wq, event, result);
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
	sched_policy_t			*policy;

	/*
	 *	Check for other non-idle runnable threads.
	 */
	myprocessor->first_quantum = TRUE;
	pset = myprocessor->processor_set;
	thread = current_thread();

#if 0 /* CHECKME! */
	thread->unconsumed_quantum = myprocessor->quantum;
#endif

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

		/* Update the thread's meta-priority */
		policy = policy_id_to_sched_policy(thread->policy);
		assert(policy != SCHED_POLICY_NULL);
		(void)policy->sp_ops.sp_thread_update_mpri(policy, thread);
	}
	else
	if (other_runnable) {
		simple_unlock(&pset->runq.lock);
		simple_unlock(&runq->lock);
		thread = choose_thread(myprocessor);
	}
	else {
		simple_unlock(&pset->runq.lock);
		simple_unlock(&runq->lock);

		/*
		 *	Nothing is runnable, so set this processor idle if it
		 *	was running.  If it was in an assignment or shutdown,
		 *	leave it alone.  Return its idle thread.
		 */
		simple_lock(&pset->idle_lock);
		if (myprocessor->state == PROCESSOR_RUNNING) {
			myprocessor->state = PROCESSOR_IDLE;
			/*
			 *	XXX Until it goes away, put master on end of queue, others
			 *	XXX on front so master gets used last.
			 */
			if (myprocessor == master_processor)
				queue_enter(&(pset->idle_queue), myprocessor,
											processor_t, processor_queue);
			else
				queue_enter_first(&(pset->idle_queue), myprocessor,
											processor_t, processor_queue);

			pset->idle_count++;
		}
		simple_unlock(&pset->idle_lock);

		thread = myprocessor->idle_thread;
	}

	return (thread);
}


/*
 *	Stop running the current thread and start running the new thread.
 *	If continuation is non-zero, and the current thread is blocked,
 *	then it will resume by executing continuation on a new stack.
 *	Returns TRUE if the hand-off succeeds.
 *	The reason parameter == AST_QUANTUM if the thread blocked
 *	because its quantum expired.
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
	void                (*continuation)(void))
{
	sched_policy_t		*policy;
	sf_return_t			sfr;
	void                (*lcont)(void);

	/*
	 *	Mark thread interruptible.
	 */
	thread_lock(new_thread);
	new_thread->state &= ~TH_UNINT;

	if (cpu_data[cpu_number()].preemption_level != 1)
		panic("thread_invoke: preemption_level %d\n",
								cpu_data[cpu_number()].preemption_level);


	assert(thread_runnable(new_thread));

	assert(old_thread->continuation == (void (*)(void))0);	

	if ((old_thread->sched_mode & TH_MODE_REALTIME) && (!old_thread->stack_privilege)) {
	  old_thread->stack_privilege = old_thread->kernel_stack;
	}

	if (continuation != (void (*)()) 0) {
	  switch (new_thread->state & TH_STACK_STATE) {
	  case TH_STACK_HANDOFF:

		/*
		 * If the old thread has stack privilege, we can't give
		 * his stack away. So go and get him one and treat this
		 * as a traditional context switch.
		 */
		if (old_thread->stack_privilege == current_stack()) 
			goto get_new_stack;

		/*
		 * Make the whole handoff/dispatch atomic to match the
		 * non-handoff case.
		 */
		disable_preemption();

		/*
		 *	Set up ast context of new thread and switch to its timer.
		 */
		new_thread->state &= ~(TH_STACK_HANDOFF|TH_UNINT);
		new_thread->last_processor = current_processor();
		ast_context(new_thread->top_act, cpu_number());
		timer_switch(&new_thread->system_timer);
		thread_unlock(new_thread);

		old_thread->continuation = continuation;
		stack_handoff(old_thread, new_thread);

		wake_lock(old_thread);
		thread_lock(old_thread);
		act_machine_sv_free(old_thread->top_act);

		/* 
		 *  inline thread_dispatch but don't free stack
		 */

		switch (old_thread->state & (TH_RUN|TH_WAIT|TH_UNINT|TH_IDLE)) {
		  sched_policy_t *policy;
		  sf_return_t sfr;
 
	    case TH_RUN			    | TH_UNINT:
	    case TH_RUN:
		  /*
		   *	No reason to stop.  Put back on a run queue.
		   */
		  old_thread->state |= TH_STACK_HANDOFF;

		  /* Get pointer to scheduling policy "object" */
		  policy = &sched_policy[old_thread->policy];

		  /* Leave enqueueing thread up to scheduling policy */
		  sfr = policy->sp_ops.sp_thread_dispatch(policy, old_thread);
		  assert(sfr == SF_SUCCESS);
		  break;

	    case TH_RUN | TH_WAIT	    | TH_UNINT:
	    case TH_RUN | TH_WAIT:
		  old_thread->sleep_stamp = sched_tick;
		  /* fallthrough */

	    case	  TH_WAIT:			/* this happens! */
		  /*
		   *	Waiting
		   */
		  old_thread->state |= TH_STACK_HANDOFF;
		  old_thread->state &= ~TH_RUN;
		  if (old_thread->state & TH_TERMINATE)
			thread_reaper_enqueue(old_thread);

		  if (old_thread->wake_active) {
			old_thread->wake_active = FALSE;
			thread_unlock(old_thread);
			wake_unlock(old_thread);
			thread_wakeup((event_t)&old_thread->wake_active);
			wake_lock(old_thread);
			thread_lock(old_thread);
		  }
		  break;

	    case TH_RUN | TH_IDLE:
		  /*
		   *	Drop idle thread -- it is already in
		   *	idle_thread_array.
		   */
		  old_thread->state |= TH_STACK_HANDOFF;
		  break;

	    default:
		  panic("State 0x%x \n",old_thread->state);
		}
	   
		/* Get pointer to scheduling policy "object" */
		policy = &sched_policy[old_thread->policy];

		/* Indicate to sched policy that old thread has stopped execution */
		/*** ??? maybe use a macro -- rkc, 1/4/96 ***/
		sfr = policy->sp_ops.sp_thread_done(policy,	old_thread);
		assert(sfr == SF_SUCCESS);
		thread_unlock(old_thread);
		wake_unlock(old_thread);
		thread_lock(new_thread);

		assert(thread_runnable(new_thread));

		/* Get pointer to scheduling policy "object" */
		policy = &sched_policy[new_thread->policy];

		/* Indicate to sched policy that new thread has started execution */
		/*** ??? maybe use a macro ***/
		sfr = policy->sp_ops.sp_thread_begin(policy, new_thread);
		assert(sfr == SF_SUCCESS);

		lcont = new_thread->continuation;
		new_thread->continuation = (void(*)(void))0;

		thread_unlock(new_thread);
		enable_preemption();

		counter_always(c_thread_invoke_hits++);

		if (new_thread->funnel_state & TH_FN_REFUNNEL) {
		  kern_return_t save_wait_result;
		  new_thread->funnel_state = 0;
		  save_wait_result = new_thread->wait_result;
		  KERNEL_DEBUG(0x6032428 | DBG_FUNC_NONE, new_thread->funnel_lock, 2, 0, 0, 0);
		  //mutex_lock(new_thread->funnel_lock);
		  funnel_lock(new_thread->funnel_lock);
		  KERNEL_DEBUG(0x6032430 | DBG_FUNC_NONE, new_thread->funnel_lock, 2, 0, 0, 0);
		  new_thread->funnel_state = TH_FN_OWNED;
		  new_thread->wait_result = save_wait_result;
		}
		(void) spllo();

		assert(lcont);
		call_continuation(lcont);
		/*NOTREACHED*/
		return TRUE;

	  case TH_STACK_COMING_IN:
		/*
		 * waiting for a stack
		 */
		thread_swapin(new_thread);
		thread_unlock(new_thread);
		counter_always(c_thread_invoke_misses++);
		return FALSE;

      case 0:
        /*
         * already has a stack - can't handoff
         */
		if (new_thread == old_thread) {

		  /* same thread but with continuation */
		  counter(++c_thread_invoke_same);
		  thread_unlock(new_thread);

		  if (old_thread->funnel_state & TH_FN_REFUNNEL) {
			kern_return_t save_wait_result;

			old_thread->funnel_state = 0;
			save_wait_result = old_thread->wait_result;
			KERNEL_DEBUG(0x6032428 | DBG_FUNC_NONE, old_thread->funnel_lock, 3, 0, 0, 0);
			funnel_lock(old_thread->funnel_lock);
			KERNEL_DEBUG(0x6032430 | DBG_FUNC_NONE, old_thread->funnel_lock, 3, 0, 0, 0);
			old_thread->funnel_state = TH_FN_OWNED;
			old_thread->wait_result = save_wait_result;
		  }
		  (void) spllo();
		  call_continuation(continuation);
          /*NOTREACHED*/
		}
        break;
      }
	} else {
	  /*
	   * check that the new thread has a stack
	   */
	  if (new_thread->state & TH_STACK_STATE) {
	  get_new_stack:
		/* has no stack. if not already waiting for one try to get one */
		if ((new_thread->state & TH_STACK_COMING_IN) ||
			/* not already waiting. nonblocking try to get one */
			!stack_alloc_try(new_thread, thread_continue))
		  {
			/* couldn't get one. schedule new thread to get a stack and
			   return failure so we can try another thread. */
			thread_swapin(new_thread);
			thread_unlock(new_thread);
			counter_always(c_thread_invoke_misses++);
            return FALSE;
          }
	  } else if (old_thread == new_thread) {
		  counter(++c_thread_invoke_same);
		  thread_unlock(new_thread);
		  return TRUE;
	  }

	  /* new thread now has a stack. it has been setup to resume in
		 thread_continue so it can dispatch the old thread, deal with
		 funnelling and then go to it's true continuation point */
	}
	 
	new_thread->state &= ~(TH_STACK_HANDOFF | TH_UNINT);

	/*
	 *	Set up ast context of new thread and switch to its timer.
	 */
	new_thread->last_processor = current_processor();
	ast_context(new_thread->top_act, cpu_number());
	timer_switch(&new_thread->system_timer);
	assert(thread_runnable(new_thread));
	
	/*
	 * N.B. On return from the call to switch_context, 'old_thread'
	 * points at the thread that yielded to us.  Unfortunately, at
	 * this point, there are no simple_locks held, so if we are preempted
	 * before the call to thread_dispatch blocks preemption, it is
	 * possible for 'old_thread' to terminate, leaving us with a
	 * stale thread pointer.
	 */
	disable_preemption();

	thread_unlock(new_thread);

	counter_always(c_thread_invoke_csw++);
	current_task()->csw++;

	
	thread_lock(old_thread);
	old_thread->reason = reason;
	assert(old_thread->runq == RUN_QUEUE_NULL);

	if (continuation != (void (*)(void))0)
		old_thread->continuation = continuation;

	/* Indicate to sched policy that old thread has stopped execution */
	policy = &sched_policy[old_thread->policy];
	/*** ??? maybe use a macro -- ***/
	sfr = policy->sp_ops.sp_thread_done(policy, old_thread);
	assert(sfr == SF_SUCCESS);
	thread_unlock(old_thread);

	/*
	 *	switch_context is machine-dependent.  It does the
	 *	machine-dependent components of a context-switch, like
	 *	changing address spaces.  It updates active_threads.
	 */
	old_thread = switch_context(old_thread, continuation, new_thread);
	
	/* Now on new thread's stack.  Set a local variable to refer to it. */
	new_thread = __current_thread();
	assert(old_thread != new_thread);

	assert(thread_runnable(new_thread));

	thread_lock(new_thread);
	assert(thread_runnable(new_thread));
	/* Indicate to sched policy that new thread has started execution */
	policy = &sched_policy[new_thread->policy];
	/*** ??? maybe use a macro -- rkc, 1/4/96 ***/
	sfr = policy->sp_ops.sp_thread_begin(policy, new_thread);
	assert(sfr == SF_SUCCESS);
	thread_unlock(new_thread);

	/*
	 *	We're back.  Now old_thread is the thread that resumed
	 *	us, and we have to dispatch it.
	 */
	/* CHECKME! */
//	Code from OSF in Grenoble deleted the following fields. They were
//	used in HPPA and 386 code, but not in the PPC for other than
//	just setting and resetting. They didn't delete these lines from
//	the MACH_RT builds, though, causing compile errors.  I'm going
//	to make a wild guess and assume we can just delete these.
#if 0
	if (old_thread->preempt == TH_NOT_PREEMPTABLE) {
	    /*
	     * Mark that we have been really preempted
	     */
	    old_thread->preempt = TH_PREEMPTED;
	}
#endif
	thread_dispatch(old_thread);
	enable_preemption();

	/* if we get here and 'continuation' is set that means the
	 * switch_context() path returned and did not call out
	 * to the continuation. we will do it manually here */
	if (continuation) {
	  call_continuation(continuation);
	  /* NOTREACHED */
	}

	return TRUE;
}

/*
 *	thread_continue:
 *
 *	Called when the launching a new thread, at splsched();
 */
void
thread_continue(
	register thread_t old_thread)
{
	register thread_t self;
	register void (*continuation)();
	sched_policy_t          *policy;
	sf_return_t             sfr;

	self = current_thread();
	
	/*
	 *	We must dispatch the old thread and then
	 *	call the current thread's continuation.
	 *	There might not be an old thread, if we are
	 *	the first thread to run on this processor.
	 */
	if (old_thread != THREAD_NULL) {
		thread_dispatch(old_thread);
	
		thread_lock(self);

        /* Get pointer to scheduling policy "object" */
        policy = &sched_policy[self->policy];

       /* Indicate to sched policy that new thread has started execution */
       /*** ??? maybe use a macro -- rkc, 1/4/96 ***/
       sfr = policy->sp_ops.sp_thread_begin(policy,self);
       assert(sfr == SF_SUCCESS);
	} else {
		thread_lock(self);
	}
	
	continuation = self->continuation;
	self->continuation = (void (*)(void))0;
	thread_unlock(self);

	/*
	 * N.B. - the following is necessary, since thread_invoke()
	 * inhibits preemption on entry and reenables before it
	 * returns.  Unfortunately, the first time a newly-created
	 * thread executes, it magically appears here, and never
	 * executes the enable_preemption() call in thread_invoke().
	 */
	enable_preemption();

	if (self->funnel_state & TH_FN_REFUNNEL) {
	  kern_return_t save_wait_result;
	  self->funnel_state = 0;
	  save_wait_result = self->wait_result;
	  KERNEL_DEBUG(0x6032428 | DBG_FUNC_NONE, self->funnel_lock, 4, 0, 0, 0);
	  funnel_lock(self->funnel_lock);
	  KERNEL_DEBUG(0x6032430 | DBG_FUNC_NONE, self->funnel_lock, 4, 0, 0, 0);
	  self->wait_result = save_wait_result;
	  self->funnel_state = TH_FN_OWNED;
	}
	spllo();

	assert(continuation);
	(*continuation)();
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
 *	Block the current thread.  If the thread is runnable
 *	then someone must have woken it up between its request
 *	to sleep and now.  In this case, it goes back on a
 *	run queue.
 *
 *	If a continuation is specified, then thread_block will
 *	attempt to discard the thread's kernel stack.  When the
 *	thread resumes, it will execute the continuation function
 *	on a new kernel stack.
 */
counter(mach_counter_t  c_thread_block_calls = 0;)
 
int
thread_block_reason(
	void		(*continuation)(void),
	int			reason)
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
	  KERNEL_DEBUG(0x603242c | DBG_FUNC_NONE, thread->funnel_lock, 2, 0, 0, 0);
	  funnel_unlock(thread->funnel_lock);
	}

	myprocessor = current_processor();

	thread_lock(thread);
	if (thread->state & TH_ABORT)
		clear_wait_internal(thread, THREAD_INTERRUPTED);

	/* Unconditionally remove either | both */
	ast_off(AST_QUANTUM|AST_BLOCK|AST_URGENT);

	new_thread = thread_select(myprocessor);
	assert(new_thread);
	assert(thread_runnable(new_thread));
	thread_unlock(thread);
	while (!thread_invoke(thread, new_thread, reason, continuation)) {
		thread_lock(thread);
		new_thread = thread_select(myprocessor);
		assert(new_thread);
		assert(thread_runnable(new_thread));
		thread_unlock(thread);
	}

	if (thread->funnel_state & TH_FN_REFUNNEL) {
		kern_return_t	save_wait_result;

		save_wait_result = thread->wait_result;
		thread->funnel_state = 0;
		KERNEL_DEBUG(0x6032428 | DBG_FUNC_NONE, thread->funnel_lock, 5, 0, 0, 0);
		funnel_lock(thread->funnel_lock);
		KERNEL_DEBUG(0x6032430 | DBG_FUNC_NONE, thread->funnel_lock, 5, 0, 0, 0);
		thread->funnel_state = TH_FN_OWNED;
		thread->wait_result = save_wait_result;
	}

	splx(s);

	return thread->wait_result;
}

/*
 *	thread_block:
 *
 *	Now calls thread_block_reason() which forwards the
 *	the reason parameter to thread_invoke() so it can
 *	do the right thing if the thread's quantum expired.
 */
int
thread_block(
	void		(*continuation)(void))
{
	return thread_block_reason(continuation, 0);
}

/*
 *	thread_run:
 *
 *	Switch directly from the current thread to a specified
 *	thread.  Both the current and new threads must be
 *	runnable.
 *
 *  Assumption:
 *	at splsched.
 */
int
thread_run(
	thread_t	old_thread,
	void		(*continuation)(void),
	thread_t	new_thread)
{
	while (!thread_invoke(old_thread, new_thread, 0, continuation)) {
		register processor_t myprocessor = current_processor();
		thread_lock(old_thread);
		new_thread = thread_select(myprocessor);
		thread_unlock(old_thread);
	}
	return old_thread->wait_result;
}

/*
 *	Dispatches a running thread that is not	on a runq.
 *	Called at splsched.
 */
void
thread_dispatch(
	register thread_t	thread)
{
	sched_policy_t		*policy;
	sf_return_t			sfr;

	/*
	 *	If we are discarding the thread's stack, we must do it
	 *	before the thread has a chance to run.
	 */
	wake_lock(thread);
	thread_lock(thread);

#ifndef i386
	/* no continuations on i386 for now */
    if (thread->continuation != (void (*)())0) {
      assert((thread->state & TH_STACK_STATE) == 0);
      thread->state |= TH_STACK_HANDOFF;
      stack_free(thread);
      if (thread->top_act) {
        act_machine_sv_free(thread->top_act);
        }
      }
#endif

	switch (thread->state & (TH_RUN|TH_WAIT|TH_UNINT|TH_IDLE)) {

	case TH_RUN				 | TH_UNINT:
	case TH_RUN:
		/*
		 *	No reason to stop.  Put back on a run queue.
		 */
		/* Leave enqueueing thread up to scheduling policy */
		policy = &sched_policy[thread->policy];
		/*** ??? maybe use a macro ***/
		sfr = policy->sp_ops.sp_thread_dispatch(policy, thread);
		assert(sfr == SF_SUCCESS);
		break;

	case TH_RUN | TH_WAIT	| TH_UNINT:
	case TH_RUN | TH_WAIT:
		thread->sleep_stamp = sched_tick;
		/* fallthrough */
	case		  TH_WAIT:			/* this happens! */
	
		/*
		 *	Waiting
		 */
		thread->state &= ~TH_RUN;
		if (thread->state & TH_TERMINATE)
			thread_reaper_enqueue(thread);

		if (thread->wake_active) {
		    thread->wake_active = FALSE;
		    thread_unlock(thread);
		    wake_unlock(thread);
		    thread_wakeup((event_t)&thread->wake_active);
		    return;
		}
		break;

	case TH_RUN						| TH_IDLE:
		/*
		 *	Drop idle thread -- it is already in
		 *	idle_thread_array.
		 */
		break;

	default:
		panic("State 0x%x \n",thread->state);
	}
	thread_unlock(thread);
	wake_unlock(thread);
}

/*
 * Enqueue thread on run queue.  Thread must be locked,
 * and not already be on a run queue.
 */
int
run_queue_enqueue(
	register run_queue_t	rq,
	register thread_t		thread,
	boolean_t				tail)
{
	register int			whichq;
	int						oldrqcount;
	
	whichq = thread->sched_pri;
	assert(whichq >= MINPRI && whichq <= MAXPRI);

	simple_lock(&rq->lock);	/* lock the run queue */
	assert(thread->runq == RUN_QUEUE_NULL);
	if (tail)
		enqueue_tail(&rq->queues[whichq], (queue_entry_t)thread);
	else
		enqueue_head(&rq->queues[whichq], (queue_entry_t)thread);

	setbit(MAXPRI - whichq, rq->bitmap);
	if (whichq > rq->highq)
		rq->highq = whichq;

	oldrqcount = rq->count++;
	thread->runq = rq;
	thread->whichq = whichq;
#if	DEBUG
	thread_check(thread, rq);
#endif	/* DEBUG */
	simple_unlock(&rq->lock);

	return (oldrqcount);
}

/*
 *	thread_setrun:
 *
 *	Make thread runnable; dispatch directly onto an idle processor
 *	if possible.  Else put on appropriate run queue (processor
 *	if bound, else processor set.  Caller must have lock on thread.
 *	This is always called at splsched.
 *	The tail parameter, if TRUE || TAIL_Q, indicates that the 
 *	thread should be placed at the tail of the runq. If 
 *	FALSE || HEAD_Q the thread will be placed at the head of the 
 *      appropriate runq.
 */
void
thread_setrun(
	register thread_t			new_thread,
	boolean_t					may_preempt,
	boolean_t					tail)
{
	register processor_t		processor;
	register run_queue_t		runq;
	register processor_set_t	pset;
	thread_t					thread;
	ast_t						ast_flags = AST_BLOCK;

	mp_disable_preemption();

	assert(!(new_thread->state & TH_SWAPPED_OUT));
	assert(thread_runnable(new_thread));
	
	/*
	 *	Update priority if needed.
	 */
	if (new_thread->sched_stamp != sched_tick)
		update_priority(new_thread);

	if (new_thread->policy & (POLICY_FIFO|POLICY_RR)) {
		if (	new_thread->sched_pri >= (MAXPRI_KERNBAND - 2)		&&
				kernel_preemption_mode == KERNEL_PREEMPT			)
			ast_flags |= AST_URGENT;
	}
	
	assert(new_thread->runq == RUN_QUEUE_NULL);

	/*
	 *	Try to dispatch the thread directly onto an idle processor.
	 */
	if ((processor = new_thread->bound_processor) == PROCESSOR_NULL) {
	    /*
	     *	Not bound, any processor in the processor set is ok.
	     */
	    pset = new_thread->processor_set;
	    if (pset->idle_count > 0) {
			simple_lock(&pset->idle_lock);
			if (pset->idle_count > 0) {
				processor = (processor_t) queue_first(&pset->idle_queue);
				queue_remove(&(pset->idle_queue), processor, processor_t,
					processor_queue);
				pset->idle_count--;
				processor->next_thread = new_thread;
				processor->state = PROCESSOR_DISPATCHING;
				simple_unlock(&pset->idle_lock);
				if(processor->slot_num != cpu_number())	
					machine_signal_idle(processor);
				mp_enable_preemption();
				return;
			}
			simple_unlock(&pset->idle_lock);
	    }
	

	    /*
	     * Preempt check
	     */
	    runq = &pset->runq;
		thread = current_thread();
	    processor = current_processor();
	    if (	may_preempt									&&
				pset == processor->processor_set			&&
				thread->sched_pri < new_thread->sched_pri			) {
		    /*
		     * XXX if we have a non-empty local runq or are
		     * XXX running a bound thread, ought to check for
		     * XXX another cpu running lower-pri thread to preempt.
			 */
		    /*
		     *	Turn off first_quantum to allow csw.
		     */
			processor->first_quantum = FALSE;

			ast_on(ast_flags);
	    }

		/*
		 * Put us on the end of the runq, if we are not preempting
		 * or the guy we are preempting.
		 */
		run_queue_enqueue(runq, new_thread, tail);
	}
	else {
	    /*
	     *	Bound, can only run on bound processor.  Have to lock
	     *  processor here because it may not be the current one.
	     */
	    if (processor->state == PROCESSOR_IDLE) {
			simple_lock(&processor->lock);
			pset = processor->processor_set;
			simple_lock(&pset->idle_lock);
			if (processor->state == PROCESSOR_IDLE) {
				queue_remove(&pset->idle_queue, processor,
				processor_t, processor_queue);
				pset->idle_count--;
				processor->next_thread = new_thread;
				processor->state = PROCESSOR_DISPATCHING;
				simple_unlock(&pset->idle_lock);
				simple_unlock(&processor->lock);
				if(processor->slot_num != cpu_number())	
					machine_signal_idle(processor);
				mp_enable_preemption();
				return;
			}
			simple_unlock(&pset->idle_lock);
			simple_unlock(&processor->lock);
		}
	  
	    /*
	     * Cause ast on processor if processor is on line, and the
	     * currently executing thread is not bound to that processor
	     * (bound threads have implicit priority over non-bound threads).
	     * We also avoid sending the AST to the idle thread (if it got
	     * scheduled in the window between the 'if' above and here),
	     * since the idle_thread is bound.
	     */
	    runq = &processor->runq;
		thread = current_thread();
	    if (processor == current_processor()) {
			if (	thread->bound_processor == PROCESSOR_NULL		||
						thread->sched_pri < new_thread->sched_pri		) {
				processor->first_quantum = FALSE;
				ast_on(ast_flags);
			}

			run_queue_enqueue(runq, new_thread, tail);
	    }
		else {
			thread = cpu_data[processor->slot_num].active_thread;
			if (	run_queue_enqueue(runq, new_thread, tail) == 0	&&
					processor->state != PROCESSOR_OFF_LINE			&&
					thread && thread->bound_processor != processor		)
				cause_ast_check(processor);
	    }
	}

	mp_enable_preemption();
}

/*
 *	set_pri:
 *
 *	Set the priority of the specified thread to the specified
 *	priority.  This may cause the thread to change queues.
 *
 *	The thread *must* be locked by the caller.
 */
void
set_pri(
	thread_t			thread,
	int					pri,
	boolean_t			resched)
{
	register struct run_queue	*rq;

	rq = rem_runq(thread);
	assert(thread->runq == RUN_QUEUE_NULL);
	thread->sched_pri = pri;
	if (rq != RUN_QUEUE_NULL) {
	    if (resched)
			thread_setrun(thread, TRUE, TAIL_Q);
	    else
			run_queue_enqueue(rq, thread, TAIL_Q);
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
 *	This is only called on processor startup and when thread_block
 *	thinks there's something in the processor runq.
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

	simple_lock(&runq->lock);
	if (runq->count > 0 && runq->highq >= pset->runq.highq) {
		q = runq->queues + runq->highq;
#if	MACH_ASSERT
		if (!queue_empty(q)) {
#endif	/*MACH_ASSERT*/
			thread = (thread_t)q->next;
			((queue_entry_t)thread)->next->prev = q;
			q->next = ((queue_entry_t)thread)->next;
			thread->runq = RUN_QUEUE_NULL;
			runq->count--;
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

	simple_unlock(&runq->lock);
	simple_lock(&pset->runq.lock);
	return (choose_pset_thread(myprocessor, pset));
}


/*
 *	choose_pset_thread:  choose a thread from processor_set runq or
 *		set processor idle and choose its idle thread.
 *
 *	Caller must be at splsched and have a lock on the runq.  This
 *	lock is released by this routine.  myprocessor is always the current
 *	processor, and pset must be its processor set.
 *	This routine chooses and removes a thread from the runq if there
 *	is one (and returns it), else it sets the processor idle and
 *	returns its idle thread.
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
			if (queue_empty(q)) {
				if (runq->highq != IDLEPRI)
					clrbit(MAXPRI - runq->highq, runq->bitmap);
				runq->highq = MAXPRI - ffsbit(runq->bitmap);
			}
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
	simple_lock(&pset->idle_lock);
	if (myprocessor->state == PROCESSOR_RUNNING) {
	    myprocessor->state = PROCESSOR_IDLE;
	    /*
	     *	XXX Until it goes away, put master on end of queue, others
	     *	XXX on front so master gets used last.
	     */
	    if (myprocessor == master_processor)
			queue_enter(&(pset->idle_queue), myprocessor,
									processor_t, processor_queue);
	    else
			queue_enter_first(&(pset->idle_queue), myprocessor,
										processor_t, processor_queue);

	    pset->idle_count++;
	}
	simple_unlock(&pset->idle_lock);

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
	myprocessor = current_processor();
	threadp = (volatile thread_t *) &myprocessor->next_thread;
	lcount = (volatile int *) &myprocessor->runq.count;

	for (;;) {
#ifdef	MARK_CPU_IDLE
		MARK_CPU_IDLE(mycpu);
#endif	/* MARK_CPU_IDLE */

		gcount = (volatile int *)&myprocessor->processor_set->runq.count;

		(void)splsched();
		while (	(*threadp == (volatile thread_t)THREAD_NULL)	&&
					(*gcount == 0) && (*lcount == 0)				) {

			/* check for ASTs while we wait */

			if (need_ast[mycpu] &~ (AST_SCHEDULING|AST_URGENT|AST_BSD|AST_BSD_INIT)) {
				/* don't allow scheduling ASTs */
				need_ast[mycpu] &= ~(AST_SCHEDULING|AST_URGENT|AST_BSD|AST_BSD_INIT);
				ast_taken(FALSE, AST_ALL, TRUE);	/* back at spllo */
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

#ifdef	MARK_CPU_ACTIVE
		(void)spllo();
		MARK_CPU_ACTIVE(mycpu);
		(void)splsched();
#endif	/* MARK_CPU_ACTIVE */

		/*
		 *	This is not a switch statement to avoid the
		 *	bounds checking code in the common case.
		 */
		pset = myprocessor->processor_set;
		simple_lock(&pset->idle_lock);
retry:
		state = myprocessor->state;
		if (state == PROCESSOR_DISPATCHING) {
			/*
			 *	Commmon case -- cpu dispatched.
			 */
			new_thread = *threadp;
			*threadp = (volatile thread_t) THREAD_NULL;
			myprocessor->state = PROCESSOR_RUNNING;
			simple_unlock(&pset->idle_lock);

			thread_lock(new_thread);
			simple_lock(&myprocessor->runq.lock);
			simple_lock(&pset->runq.lock);
			if (	myprocessor->runq.highq > new_thread->sched_pri		||
					pset->runq.highq > new_thread->sched_pri				) {
				simple_unlock(&pset->runq.lock);
				simple_unlock(&myprocessor->runq.lock);

				if (new_thread->bound_processor != PROCESSOR_NULL)
					run_queue_enqueue(&myprocessor->runq, new_thread, HEAD_Q);
				else
					run_queue_enqueue(&pset->runq, new_thread, HEAD_Q);
				thread_unlock(new_thread);

				counter(c_idle_thread_block++);
				thread_block(idle_thread_continue);
			}
			else {
				simple_unlock(&pset->runq.lock);
				simple_unlock(&myprocessor->runq.lock);

				/*
				 *	set up quantum for new thread.
				 */
				if (new_thread->policy & (POLICY_RR|POLICY_FIFO))
					myprocessor->quantum = new_thread->unconsumed_quantum;
				else
					myprocessor->quantum = pset->set_quantum;
				thread_unlock(new_thread);

				myprocessor->first_quantum = TRUE;
				counter(c_idle_thread_handoff++);
				thread_run(myprocessor->idle_thread,
									idle_thread_continue, new_thread);
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
			queue_remove(&pset->idle_queue, myprocessor,
									processor_t, processor_queue);
			myprocessor->state = PROCESSOR_RUNNING;
			simple_unlock(&pset->idle_lock);

			counter(c_idle_thread_block++);
			thread_block(idle_thread_continue);
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
				simple_unlock(&pset->idle_lock);
				thread_lock(new_thread);
				thread_setrun(new_thread, FALSE, TAIL_Q);
				thread_unlock(new_thread);
			} else
				simple_unlock(&pset->idle_lock);

			counter(c_idle_thread_block++);
			thread_block(idle_thread_continue);
		}
		else {
			simple_unlock(&pset->idle_lock);
			printf("Bad processor state %d (Cpu %d)\n",
												cpu_state(mycpu), mycpu);
			panic("idle_thread");

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
	thread_swappable(current_act(), FALSE);

	s = splsched();
	thread_lock(self);

	self->priority = IDLEPRI;
	self->sched_pri = self->priority;

	thread_unlock(self);
	splx(s);

	counter(c_idle_thread_block++);
	thread_block((void(*)(void))0);
	idle_thread_continue();
	/*NOTREACHED*/
}

static AbsoluteTime			sched_tick_interval, sched_tick_deadline;

/*
 *	sched_tick_thread
 *
 *	Update the priorities of all threads periodically.
 */
void
sched_tick_thread_continue(void)
{
	AbsoluteTime		abstime;
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
	thread_swappable(self->top_act, FALSE);

	s = splsched();
	thread_lock(self);

	self->priority = MAXPRI_STANDARD;
	self->sched_pri = self->priority;

	thread_unlock(self);
	splx(s);

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
 *	cannot be held during updates [set_pri will deadlock].
 *
 *	Array length should be enough so that restart isn't necessary,
 *	but restart logic is included.  Does not scan processor runqs.
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
				if (	!(thread->state & (TH_WAIT|TH_SUSP))	&&
						thread->policy == POLICY_TIMESHARE				) {
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
						if (simple_lock_try(&thread->lock)) {
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
			if (thread->policy == POLICY_TIMESHARE) {
				if (	!(thread->state & (TH_WAIT|TH_SUSP))	&&
						thread->sched_stamp != sched_tick			)
					update_priority(thread);
			}
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
thread_runnable(
	thread_t		thread)
{
	sched_policy_t	*policy;

	/* Ask sched policy if thread is runnable */
	policy = policy_id_to_sched_policy(thread->policy);

	return ((policy != SCHED_POLICY_NULL)?
				policy->sp_ops.sp_thread_runnable(policy, thread) : FALSE);
}

#if	DEBUG

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
    printf("max_priority: 0x%x, policies: 0x%x, set_quantum: 0x%x\n",
	ps->max_priority, ps->policies, ps->set_quantum);
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
    printf("quantum: %u, first_quantum: %x, last_quantum: %u\n",
	p->quantum, p->first_quantum, p->last_quantum);
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

	if (whichq != thread->whichq)
		panic("thread_check: whichq");

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

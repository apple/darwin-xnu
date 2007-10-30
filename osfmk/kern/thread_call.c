/*
 * Copyright (c) 1993-1995, 1999-2007 Apple Inc. All rights reserved.
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
 
#include <mach/mach_types.h>
#include <mach/thread_act.h>

#include <kern/kern_types.h>
#include <kern/kalloc.h>
#include <kern/sched_prim.h>
#include <kern/clock.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/wait_queue.h>

#include <vm/vm_pageout.h>

#include <kern/thread_call.h>
#include <kern/call_entry.h>

#include <kern/timer_call.h>

#include <sys/kdebug.h>

#define internal_call_num	768

#define thread_call_thread_min	4

static
thread_call_data_t
	internal_call_storage[internal_call_num];

decl_simple_lock_data(static,thread_call_lock)

static
timer_call_data_t
	thread_call_delaytimer;

static
queue_head_t
	thread_call_xxx_queue,
	thread_call_pending_queue, thread_call_delayed_queue;

static
struct wait_queue
	call_thread_waitqueue;

static
boolean_t
	activate_thread_awake;

static struct {
	int		pending_num,
			pending_hiwat;
	int		active_num,
			active_hiwat,
			active_lowat;
	int		delayed_num,
			delayed_hiwat;
	int		idle_thread_num;
	int		thread_num,
			thread_hiwat,
			thread_lowat;
} thread_call_vars;

static __inline__ thread_call_t
	_internal_call_allocate(void);

static __inline__ void
_internal_call_release(
	thread_call_t		call
);

static __inline__ void
_pending_call_enqueue(
	thread_call_t		call
),
_pending_call_dequeue(
	thread_call_t		call
),
_delayed_call_enqueue(
	thread_call_t		call
),
_delayed_call_dequeue(
	thread_call_t		call
);

static __inline__ void
_set_delayed_call_timer(
	thread_call_t		call
);
					
static boolean_t
_remove_from_pending_queue(
	thread_call_func_t	func,
	thread_call_param_t	param0,
	boolean_t			remove_all
),
_remove_from_delayed_queue(
	thread_call_func_t	func,
	thread_call_param_t	param0,
	boolean_t			remove_all
);

static inline void
	_call_thread_wake(void);

static void
	_call_thread(void),
	_activate_thread(void);

static void
_delayed_call_timer(
	timer_call_param_t		p0,
	timer_call_param_t		p1
);

#define qe(x)		((queue_entry_t)(x))
#define TC(x)		((thread_call_t)(x))

/*
 * Routine:	thread_call_initialize [public]
 *
 * Description:	Initialize this module, called
 *		early during system initialization.
 *
 * Preconditions:	None.
 *
 * Postconditions:	None.
 */

void
thread_call_initialize(void)
{
	kern_return_t	result;
	thread_t		thread;
    thread_call_t	call;
	spl_t			s;

    simple_lock_init(&thread_call_lock, 0);

	s = splsched();
	simple_lock(&thread_call_lock);

    queue_init(&thread_call_pending_queue);
    queue_init(&thread_call_delayed_queue);

    queue_init(&thread_call_xxx_queue);
    for (
	    	call = internal_call_storage;
			call < &internal_call_storage[internal_call_num];
			call++) {

		enqueue_tail(&thread_call_xxx_queue, qe(call));
    }

	timer_call_setup(&thread_call_delaytimer, _delayed_call_timer, NULL);

	wait_queue_init(&call_thread_waitqueue, SYNC_POLICY_FIFO);
	thread_call_vars.thread_lowat = thread_call_thread_min;

	activate_thread_awake = TRUE;

	simple_unlock(&thread_call_lock);
	splx(s);

	result = kernel_thread_start_priority((thread_continue_t)_activate_thread, NULL, MAXPRI_KERNEL - 2, &thread);
	if (result != KERN_SUCCESS)
		panic("thread_call_initialize");

	thread_deallocate(thread);
}

void
thread_call_setup(
	thread_call_t			call,
	thread_call_func_t		func,
	thread_call_param_t		param0
)
{
	call_entry_setup(call, func, param0);
}

/*
 * Routine:	_internal_call_allocate [private, inline]
 *
 * Purpose:	Allocate an internal callout entry.
 *
 * Preconditions:	thread_call_lock held.
 *
 * Postconditions:	None.
 */

static __inline__ thread_call_t
_internal_call_allocate(void)
{
    thread_call_t		call;
    
    if (queue_empty(&thread_call_xxx_queue))
    	panic("_internal_call_allocate");
	
    call = TC(dequeue_head(&thread_call_xxx_queue));
    
    return (call);
}

/*
 * Routine:	_internal_call_release [private, inline]
 *
 * Purpose:	Release an internal callout entry which
 *		is no longer pending (or delayed).
 *
 * Preconditions:	thread_call_lock held.
 *
 * Postconditions:	None.
 */

static __inline__
void
_internal_call_release(
    thread_call_t		call
)
{
    if (    call >= internal_call_storage						&&
	   	    call < &internal_call_storage[internal_call_num]		)
		enqueue_head(&thread_call_xxx_queue, qe(call));
}

/*
 * Routine:	_pending_call_enqueue [private, inline]
 *
 * Purpose:	Place an entry at the end of the
 *		pending queue, to be executed soon.
 *
 * Preconditions:	thread_call_lock held.
 *
 * Postconditions:	None.
 */

static __inline__
void
_pending_call_enqueue(
    thread_call_t		call
)
{
    enqueue_tail(&thread_call_pending_queue, qe(call));
	if (++thread_call_vars.pending_num > thread_call_vars.pending_hiwat)
		thread_call_vars.pending_hiwat = thread_call_vars.pending_num;

    call->state = PENDING;
}

/*
 * Routine:	_pending_call_dequeue [private, inline]
 *
 * Purpose:	Remove an entry from the pending queue,
 *		effectively unscheduling it.
 *
 * Preconditions:	thread_call_lock held.
 *
 * Postconditions:	None.
 */

static __inline__
void
_pending_call_dequeue(
    thread_call_t		call
)
{
    (void)remque(qe(call));
	thread_call_vars.pending_num--;
    
    call->state = IDLE;
}

/*
 * Routine:	_delayed_call_enqueue [private, inline]
 *
 * Purpose:	Place an entry on the delayed queue,
 *		after existing entries with an earlier
 * 		(or identical) deadline.
 *
 * Preconditions:	thread_call_lock held.
 *
 * Postconditions:	None.
 */

static __inline__
void
_delayed_call_enqueue(
    thread_call_t		call
)
{
    thread_call_t		current;
    
    current = TC(queue_first(&thread_call_delayed_queue));
    
    while (TRUE) {
    	if (	queue_end(&thread_call_delayed_queue, qe(current))		||
					call->deadline < current->deadline			) {
			current = TC(queue_prev(qe(current)));
			break;
		}
	    
		current = TC(queue_next(qe(current)));
    }

    insque(qe(call), qe(current));
	if (++thread_call_vars.delayed_num > thread_call_vars.delayed_hiwat)
		thread_call_vars.delayed_hiwat = thread_call_vars.delayed_num;
    
    call->state = DELAYED;
}

/*
 * Routine:	_delayed_call_dequeue [private, inline]
 *
 * Purpose:	Remove an entry from the delayed queue,
 *		effectively unscheduling it.
 *
 * Preconditions:	thread_call_lock held.
 *
 * Postconditions:	None.
 */

static __inline__
void
_delayed_call_dequeue(
    thread_call_t		call
)
{
    (void)remque(qe(call));
	thread_call_vars.delayed_num--;
    
    call->state = IDLE;
}

/*
 * Routine:	_set_delayed_call_timer [private]
 *
 * Purpose:	Reset the timer so that it
 *		next expires when the entry is due.
 *
 * Preconditions:	thread_call_lock held.
 *
 * Postconditions:	None.
 */

static __inline__ void
_set_delayed_call_timer(
    thread_call_t		call
)
{
    timer_call_enter(&thread_call_delaytimer, call->deadline);
}

/*
 * Routine:	_remove_from_pending_queue [private]
 *
 * Purpose:	Remove the first (or all) matching
 *		entries	from the pending queue,
 *		effectively unscheduling them.
 *		Returns	whether any matching entries
 *		were found.
 *
 * Preconditions:	thread_call_lock held.
 *
 * Postconditions:	None.
 */

static
boolean_t
_remove_from_pending_queue(
    thread_call_func_t		func,
    thread_call_param_t		param0,
    boolean_t				remove_all
)
{
	boolean_t			call_removed = FALSE;
	thread_call_t		call;
    
    call = TC(queue_first(&thread_call_pending_queue));
    
    while (!queue_end(&thread_call_pending_queue, qe(call))) {
    	if (	call->func == func			&&
				call->param0 == param0			) {
			thread_call_t	next = TC(queue_next(qe(call)));
		
			_pending_call_dequeue(call);

			_internal_call_release(call);
	    
			call_removed = TRUE;
			if (!remove_all)
				break;
		
			call = next;
		}
		else	
			call = TC(queue_next(qe(call)));
    }
    
    return (call_removed);
}

/*
 * Routine:	_remove_from_delayed_queue [private]
 *
 * Purpose:	Remove the first (or all) matching
 *		entries	from the delayed queue,
 *		effectively unscheduling them.
 *		Returns	whether any matching entries
 *		were found.
 *
 * Preconditions:	thread_call_lock held.
 *
 * Postconditions:	None.
 */

static
boolean_t
_remove_from_delayed_queue(
    thread_call_func_t		func,
    thread_call_param_t		param0,
    boolean_t				remove_all
)
{
    boolean_t			call_removed = FALSE;
    thread_call_t		call;
    
    call = TC(queue_first(&thread_call_delayed_queue));
    
    while (!queue_end(&thread_call_delayed_queue, qe(call))) {
    	if (	call->func == func			&&
				call->param0 == param0			) {
			thread_call_t	next = TC(queue_next(qe(call)));
		
			_delayed_call_dequeue(call);
	    
			_internal_call_release(call);
	    
			call_removed = TRUE;
			if (!remove_all)
				break;
		
			call = next;
		}
		else	
			call = TC(queue_next(qe(call)));
    }
    
    return (call_removed);
}

/*
 * Routine:	thread_call_func [public]
 *
 * Purpose:	Schedule a function callout.
 *		Guarantees { function, argument }
 *		uniqueness if unique_call is TRUE.
 *
 * Preconditions:	Callable from an interrupt context
 *					below splsched.
 *
 * Postconditions:	None.
 */

void
thread_call_func(
    thread_call_func_t		func,
    thread_call_param_t		param,
    boolean_t				unique_call
)
{
    thread_call_t		call;
    spl_t				s;
    
    s = splsched();
    simple_lock(&thread_call_lock);
    
    call = TC(queue_first(&thread_call_pending_queue));
    
	while (unique_call && !queue_end(&thread_call_pending_queue, qe(call))) {
    	if (	call->func == func			&&
				call->param0 == param			) {
			break;
		}
	
		call = TC(queue_next(qe(call)));
    }
    
    if (!unique_call || queue_end(&thread_call_pending_queue, qe(call))) {
		call = _internal_call_allocate();
		call->func			= func;
		call->param0		= param;
		call->param1		= NULL;
	
		_pending_call_enqueue(call);
		
		if (thread_call_vars.active_num <= 0)
			_call_thread_wake();
    }

	simple_unlock(&thread_call_lock);
    splx(s);
}

/*
 * Routine:	thread_call_func_delayed [public]
 *
 * Purpose:	Schedule a function callout to
 *		occur at the stated time.
 *
 * Preconditions:	Callable from an interrupt context
 *					below splsched.
 *
 * Postconditions:	None.
 */

void
thread_call_func_delayed(
    thread_call_func_t		func,
    thread_call_param_t		param,
    uint64_t				deadline
)
{
    thread_call_t		call;
    spl_t				s;
    
    s = splsched();
    simple_lock(&thread_call_lock);
    
    call = _internal_call_allocate();
    call->func			= func;
    call->param0		= param;
    call->param1		= 0;
    call->deadline		= deadline;
    
    _delayed_call_enqueue(call);
    
    if (queue_first(&thread_call_delayed_queue) == qe(call))
    	_set_delayed_call_timer(call);
    
    simple_unlock(&thread_call_lock);
    splx(s);
}

/*
 * Routine:	thread_call_func_cancel [public]
 *
 * Purpose:	Unschedule a function callout.
 *		Removes one (or all)
 *		{ function, argument }
 *		instance(s) from either (or both)
 *		the pending and	the delayed queue,
 *		in that order.  Returns a boolean
 *		indicating whether any calls were
 *		cancelled.
 *
 * Preconditions:	Callable from an interrupt context
 *					below splsched.
 *
 * Postconditions:	None.
 */

boolean_t
thread_call_func_cancel(
    thread_call_func_t		func,
    thread_call_param_t		param,
    boolean_t				cancel_all
)
{
	boolean_t			result;
    spl_t				s;
    
    s = splsched();
    simple_lock(&thread_call_lock);

    if (cancel_all)
		result = _remove_from_pending_queue(func, param, cancel_all) |
						_remove_from_delayed_queue(func, param, cancel_all);
	else
		result = _remove_from_pending_queue(func, param, cancel_all) ||
						_remove_from_delayed_queue(func, param, cancel_all);
    
    simple_unlock(&thread_call_lock);
    splx(s);

	return (result);
}

/*
 * Routine:	thread_call_allocate [public]
 *
 * Purpose:	Allocate an external callout
 *		entry.
 *
 * Preconditions:	None.
 *
 * Postconditions:	None.
 */

thread_call_t
thread_call_allocate(
    thread_call_func_t		func,
    thread_call_param_t		param0
)
{
    thread_call_t		call = (void *)kalloc(sizeof (thread_call_data_t));
    
    call->func			= func;
    call->param0		= param0;
    call->state			= IDLE;
    
    return (call);
}

/*
 * Routine:	thread_call_free [public]
 *
 * Purpose:	Free an external callout
 *		entry.
 *
 * Preconditions:	None.
 *
 * Postconditions:	None.
 */

boolean_t
thread_call_free(
    thread_call_t		call
)
{
    spl_t		s;
    
    s = splsched();
    simple_lock(&thread_call_lock);
    
    if (call->state != IDLE) {
    	simple_unlock(&thread_call_lock);
		splx(s);

		return (FALSE);
    }
    
    simple_unlock(&thread_call_lock);
    splx(s);
    
    kfree(call, sizeof (thread_call_data_t));

	return (TRUE);
}

/*
 * Routine:	thread_call_enter [public]
 *
 * Purpose:	Schedule an external callout 
 *		entry to occur "soon".  Returns a
 *		boolean indicating whether the call
 *		had been already scheduled.
 *
 * Preconditions:	Callable from an interrupt context
 *					below splsched.
 *
 * Postconditions:	None.
 */

boolean_t
thread_call_enter(
    thread_call_t		call
)
{
	boolean_t		result = TRUE;
    spl_t			s;
    
    s = splsched();
    simple_lock(&thread_call_lock);
    
    if (call->state != PENDING) {
		if (call->state == DELAYED)
			_delayed_call_dequeue(call);
		else if (call->state == IDLE)
			result = FALSE;

    	_pending_call_enqueue(call);
		
		if (thread_call_vars.active_num <= 0)
			_call_thread_wake();
	}

	call->param1 = 0;

	simple_unlock(&thread_call_lock);
    splx(s);

	return (result);
}

boolean_t
thread_call_enter1(
    thread_call_t			call,
    thread_call_param_t		param1
)
{
	boolean_t			result = TRUE;
    spl_t				s;
    
    s = splsched();
    simple_lock(&thread_call_lock);
    
    if (call->state != PENDING) {
		if (call->state == DELAYED)
			_delayed_call_dequeue(call);
		else if (call->state == IDLE)
			result = FALSE;

    	_pending_call_enqueue(call);

		if (thread_call_vars.active_num <= 0)
			_call_thread_wake();
    }

	call->param1 = param1;

	simple_unlock(&thread_call_lock);
    splx(s);

	return (result);
}

/*
 * Routine:	thread_call_enter_delayed [public]
 *
 * Purpose:	Schedule an external callout 
 *		entry to occur at the stated time.
 *		Returns a boolean indicating whether
 *		the call had been already scheduled.
 *
 * Preconditions:	Callable from an interrupt context
 *					below splsched.
 *
 * Postconditions:	None.
 */

boolean_t
thread_call_enter_delayed(
    thread_call_t		call,
    uint64_t			deadline
)
{
	boolean_t		result = TRUE;
    spl_t			s;

    s = splsched();
    simple_lock(&thread_call_lock);

	if (call->state == PENDING)
		_pending_call_dequeue(call);
	else if (call->state == DELAYED)
		_delayed_call_dequeue(call);
	else if (call->state == IDLE)
		result = FALSE;

	call->param1	= 0;
	call->deadline	= deadline;

	_delayed_call_enqueue(call);

	if (queue_first(&thread_call_delayed_queue) == qe(call))
		_set_delayed_call_timer(call);

    simple_unlock(&thread_call_lock);
    splx(s);

	return (result);
}

boolean_t
thread_call_enter1_delayed(
    thread_call_t			call,
    thread_call_param_t		param1,
    uint64_t				deadline
)
{
	boolean_t			result = TRUE;
    spl_t				s;

    s = splsched();
    simple_lock(&thread_call_lock);

	if (call->state == PENDING)
		_pending_call_dequeue(call);
	else if (call->state == DELAYED)
		_delayed_call_dequeue(call);
	else if (call->state == IDLE)
		result = FALSE;

	call->param1	= param1;
	call->deadline	= deadline;

	_delayed_call_enqueue(call);

	if (queue_first(&thread_call_delayed_queue) == qe(call))
		_set_delayed_call_timer(call);

    simple_unlock(&thread_call_lock);
    splx(s);

	return (result);
}

/*
 * Routine:	thread_call_cancel [public]
 *
 * Purpose:	Unschedule a callout entry.
 *		Returns a boolean indicating
 *		whether the call had actually
 *		been scheduled.
 *
 * Preconditions:	Callable from an interrupt context
 *					below splsched.
 *
 * Postconditions:	None.
 */

boolean_t
thread_call_cancel(
    thread_call_t		call
)
{
	boolean_t		result = TRUE;
    spl_t			s;
    
    s = splsched();
    simple_lock(&thread_call_lock);
    
    if (call->state == PENDING)
    	_pending_call_dequeue(call);
    else if (call->state == DELAYED)
    	_delayed_call_dequeue(call);
    else
    	result = FALSE;
	
    simple_unlock(&thread_call_lock);
    splx(s);

	return (result);
}

/*
 * Routine:	thread_call_is_delayed [public]
 *
 * Purpose:	Returns a boolean indicating
 *		whether a call is currently scheduled
 *		to occur at a later time.  Optionally
 *		returns the expiration time.
 *
 * Preconditions:	Callable from an interrupt context
 *					below splsched.
 *
 * Postconditions:	None.
 */

boolean_t
thread_call_is_delayed(
	thread_call_t		call,
	uint64_t			*deadline)
{
	boolean_t		result = FALSE;
	spl_t			s;

	s = splsched();
	simple_lock(&thread_call_lock);

	if (call->state == DELAYED) {
		if (deadline != NULL)
			*deadline = call->deadline;
		result = TRUE;
	}

	simple_unlock(&thread_call_lock);
	splx(s);

	return (result);
}

/*
 * Routine:	_call_thread_wake [private, inline]
 *
 * Purpose:	Wake a callout thread to service
 *		pending callout entries.  May wake
 *		the activate thread in order to
 *		create additional callout threads.
 *
 * Preconditions:	thread_call_lock held.
 *
 * Postconditions:	None.
 */

static inline void
_call_thread_wake(void)
{
	if (wait_queue_wakeup_one(&call_thread_waitqueue, NULL, THREAD_AWAKENED) == KERN_SUCCESS) {
		thread_call_vars.idle_thread_num--;

		if (++thread_call_vars.active_num > thread_call_vars.active_hiwat)
			thread_call_vars.active_hiwat = thread_call_vars.active_num;
	}
	else
	if (!activate_thread_awake) {
		thread_wakeup_one(&activate_thread_awake);
		activate_thread_awake = TRUE;
	}
}

/*
 *	sched_call_thread:
 *
 *	Call out invoked by the scheduler.
 */

static void
sched_call_thread(
			int			type,
__unused	thread_t	thread)
{
	simple_lock(&thread_call_lock);

	switch (type) {

	case SCHED_CALL_BLOCK:
		if (--thread_call_vars.active_num < thread_call_vars.active_lowat)
			thread_call_vars.active_lowat = thread_call_vars.active_num;

		if (	thread_call_vars.active_num <= 0	&&
				thread_call_vars.pending_num > 0		)
			_call_thread_wake();
		break;

	case SCHED_CALL_UNBLOCK:
		if (++thread_call_vars.active_num > thread_call_vars.active_hiwat)
			thread_call_vars.active_hiwat = thread_call_vars.active_num;
		break;
	}

	simple_unlock(&thread_call_lock);
}

/*
 * Routine:	_call_thread [private]
 *
 * Purpose:	Executed by a callout thread.
 *
 * Preconditions:	None.
 *
 * Postconditions:	None.
 */

static
void
_call_thread_continue(void)
{
	thread_t		self = current_thread();

    (void) splsched();
    simple_lock(&thread_call_lock);

	thread_sched_call(self, sched_call_thread);

    while (thread_call_vars.pending_num > 0) {
		thread_call_t			call;
		thread_call_func_t		func;
		thread_call_param_t		param0, param1;

		call = TC(dequeue_head(&thread_call_pending_queue));
		thread_call_vars.pending_num--;

		func = call->func;
		param0 = call->param0;
		param1 = call->param1;
	
		call->state = IDLE;

		_internal_call_release(call);

		simple_unlock(&thread_call_lock);
		(void) spllo();

		KERNEL_DEBUG_CONSTANT(
			MACHDBG_CODE(DBG_MACH_SCHED,MACH_CALLOUT) | DBG_FUNC_NONE,
				(int)func, (int)param0, (int)param1, 0, 0);

		(*func)(param0, param1);

		(void)thread_funnel_set(self->funnel_lock, FALSE);

		(void) splsched();
		simple_lock(&thread_call_lock);
    }

	thread_sched_call(self, NULL);

	if (--thread_call_vars.active_num < thread_call_vars.active_lowat)
		thread_call_vars.active_lowat = thread_call_vars.active_num;
	
    if (thread_call_vars.idle_thread_num < thread_call_vars.thread_lowat) {
		thread_call_vars.idle_thread_num++;

		wait_queue_assert_wait(&call_thread_waitqueue, NULL, THREAD_UNINT, 0);
	
		simple_unlock(&thread_call_lock);
		(void) spllo();

		thread_block((thread_continue_t)_call_thread_continue);
		/* NOTREACHED */
    }
    
    thread_call_vars.thread_num--;
    
    simple_unlock(&thread_call_lock);
    (void) spllo();
    
    thread_terminate(self);
	/* NOTREACHED */
}

static
void
_call_thread(void)
{
    _call_thread_continue();
    /* NOTREACHED */
}

/*
 * Routine:	_activate_thread [private]
 *
 * Purpose:	Executed by the activate thread.
 *
 * Preconditions:	None.
 *
 * Postconditions:	Never terminates.
 */

static
void
_activate_thread_continue(void)
{
	kern_return_t	result;
	thread_t		thread;

    (void) splsched();
    simple_lock(&thread_call_lock);
        
	while (		thread_call_vars.active_num <= 0	&&
				thread_call_vars.pending_num > 0		) {

		if (++thread_call_vars.active_num > thread_call_vars.active_hiwat)
			thread_call_vars.active_hiwat = thread_call_vars.active_num;

		if (++thread_call_vars.thread_num > thread_call_vars.thread_hiwat)
			thread_call_vars.thread_hiwat = thread_call_vars.thread_num;

		simple_unlock(&thread_call_lock);
		(void) spllo();
	
		result = kernel_thread_start_priority((thread_continue_t)_call_thread, NULL, MAXPRI_KERNEL - 1, &thread);
		if (result != KERN_SUCCESS)
			panic("activate_thread");

		thread_deallocate(thread);

		(void) splsched();
		simple_lock(&thread_call_lock);
    }
		
    assert_wait(&activate_thread_awake, THREAD_INTERRUPTIBLE);
	activate_thread_awake = FALSE;
    
    simple_unlock(&thread_call_lock);
	(void) spllo();
    
	thread_block((thread_continue_t)_activate_thread_continue);
	/* NOTREACHED */
}

static
void
_activate_thread(void)
{
	thread_t	self = current_thread();

	self->options |= TH_OPT_VMPRIV;
	vm_page_free_reserve(2);	/* XXX */
    
    _activate_thread_continue();
    /* NOTREACHED */
}

static
void
_delayed_call_timer(
	__unused timer_call_param_t		p0,
	__unused timer_call_param_t		p1
)
{
	uint64_t			timestamp;
    thread_call_t		call;
	boolean_t			new_pending = FALSE;
    spl_t				s;

    s = splsched();
    simple_lock(&thread_call_lock);

	clock_get_uptime(&timestamp);
    
    call = TC(queue_first(&thread_call_delayed_queue));
    
    while (!queue_end(&thread_call_delayed_queue, qe(call))) {
    	if (call->deadline <= timestamp) {
			_delayed_call_dequeue(call);

			_pending_call_enqueue(call);
			new_pending = TRUE;
		}
		else
			break;
	    
		call = TC(queue_first(&thread_call_delayed_queue));
    }

	if (!queue_end(&thread_call_delayed_queue, qe(call)))
		_set_delayed_call_timer(call);

    if (new_pending && thread_call_vars.active_num <= 0)
		_call_thread_wake();

    simple_unlock(&thread_call_lock);
    splx(s);
}

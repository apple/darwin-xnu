/*
 * Copyright (c) 1993-1995, 1999-2000 Apple Computer, Inc.
 * All rights reserved.
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
 * Thread-based callout module.
 *
 * HISTORY
 *
 * 10 July 1999 (debo)
 *  Pulled into Mac OS X (microkernel).
 *
 * 3 July 1993 (debo)
 *	Created.
 */
 
#include <mach/mach_types.h>

#include <kern/sched_prim.h>
#include <kern/clock.h>
#include <kern/task.h>
#include <kern/thread.h>

#include <kern/thread_call.h>
#include <kern/call_entry.h>

#include <kern/timer_call.h>

#define internal_call_num	768

#define thread_call_thread_min	4

static
thread_call_data_t
	internal_call_storage[internal_call_num];

decl_simple_lock_data(static,thread_call_lock)

static
timer_call_data_t
	thread_call_delayed_timers[NCPUS];

static
queue_head_t
	internal_call_free_queue,
	pending_call_queue, delayed_call_queue;

static
queue_head_t
	idle_thread_queue;

static
thread_t
	activate_thread;

static
boolean_t
	activate_thread_awake;

static struct {
	int		pending_num,
			pending_hiwat;
	int		active_num,
			active_hiwat;
	int		delayed_num,
			delayed_hiwat;
	int		idle_thread_num;
	int		thread_num,
			thread_hiwat,
			thread_lowat;
} thread_calls;

static boolean_t
	thread_call_initialized = FALSE;

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

static void __inline__
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

static __inline__ void
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
    thread_call_t		call;
	spl_t				s;
	int					i;

    if (thread_call_initialized)
    	panic("thread_call_initialize");

    simple_lock_init(&thread_call_lock, ETAP_MISC_TIMER);

	s = splsched();
	simple_lock(&thread_call_lock);

    queue_init(&pending_call_queue);
    queue_init(&delayed_call_queue);

    queue_init(&internal_call_free_queue);
    for (
	    	call = internal_call_storage;
			call < &internal_call_storage[internal_call_num];
			call++) {

		enqueue_tail(&internal_call_free_queue, qe(call));
    }

	for (i = 0; i < NCPUS; i++) {
		timer_call_setup(&thread_call_delayed_timers[i],
												_delayed_call_timer, NULL);
	}

	queue_init(&idle_thread_queue);
	thread_calls.thread_lowat = thread_call_thread_min;

	activate_thread_awake = TRUE;
    thread_call_initialized = TRUE;

	simple_unlock(&thread_call_lock);
	splx(s);

    activate_thread = kernel_thread_with_priority(kernel_task,
									MAXPRI_KERNBAND-2, _activate_thread, TRUE);
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
    
    if (queue_empty(&internal_call_free_queue))
    	panic("_internal_call_allocate");
	
    call = TC(dequeue_head(&internal_call_free_queue));
    
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
		enqueue_tail(&internal_call_free_queue, qe(call));
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
    enqueue_tail(&pending_call_queue, qe(call));
	if (++thread_calls.pending_num > thread_calls.pending_hiwat)
		thread_calls.pending_hiwat = thread_calls.pending_num;

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
	thread_calls.pending_num--;
    
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
    
    current = TC(queue_first(&delayed_call_queue));
    
    while (TRUE) {
    	if (	queue_end(&delayed_call_queue, qe(current))			||
					CMP_ABSOLUTETIME(&call->deadline,
											&current->deadline) < 0		) {
			current = TC(queue_prev(qe(current)));
			break;
		}
	    
		current = TC(queue_next(qe(current)));
    }

    insque(qe(call), qe(current));
	if (++thread_calls.delayed_num > thread_calls.delayed_hiwat)
		thread_calls.delayed_hiwat = thread_calls.delayed_num;
    
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
	thread_calls.delayed_num--;
    
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
	timer_call_t	timer = &thread_call_delayed_timers[cpu_number()];

    timer_call_enter(timer, call->deadline);
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
    
    call = TC(queue_first(&pending_call_queue));
    
    while (!queue_end(&pending_call_queue, qe(call))) {
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
    
    call = TC(queue_first(&delayed_call_queue));
    
    while (!queue_end(&delayed_call_queue, qe(call))) {
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
    int					s;
    
    if (!thread_call_initialized)
    	panic("thread_call_func");
	
    s = splsched();
    simple_lock(&thread_call_lock);
    
    call = TC(queue_first(&pending_call_queue));
    
	while (unique_call && !queue_end(&pending_call_queue, qe(call))) {
    	if (	call->func == func			&&
				call->param0 == param			) {
			break;
		}
	
		call = TC(queue_next(qe(call)));
    }
    
    if (!unique_call || queue_end(&pending_call_queue, qe(call))) {
		call = _internal_call_allocate();
		call->func			= func;
		call->param0		= param;
		call->param1		= 0;
	
		_pending_call_enqueue(call);
		
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
    AbsoluteTime			deadline
)
{
    thread_call_t		call;
    int					s;
    
    if (!thread_call_initialized)
    	panic("thread_call_func_delayed");

    s = splsched();
    simple_lock(&thread_call_lock);
    
    call = _internal_call_allocate();
    call->func			= func;
    call->param0		= param;
    call->param1		= 0;
    call->deadline		= deadline;
    
    _delayed_call_enqueue(call);
    
    if (queue_first(&delayed_call_queue) == qe(call))
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
    int					s;
    
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
    int			s;
    
    s = splsched();
    simple_lock(&thread_call_lock);
    
    if (call->state != IDLE) {
    	simple_unlock(&thread_call_lock);
		splx(s);

		return (FALSE);
    }
    
    simple_unlock(&thread_call_lock);
    splx(s);
    
    kfree((vm_offset_t)call, sizeof (thread_call_data_t));

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
    int				s;
    
    s = splsched();
    simple_lock(&thread_call_lock);
    
    if (call->state != PENDING) {
		if (call->state == DELAYED)
			_delayed_call_dequeue(call);
		else if (call->state == IDLE)
			result = FALSE;

    	_pending_call_enqueue(call);

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
    int					s;
    
    s = splsched();
    simple_lock(&thread_call_lock);
    
    if (call->state != PENDING) {
		if (call->state == DELAYED)
			_delayed_call_dequeue(call);
		else if (call->state == IDLE)
			result = FALSE;

    	_pending_call_enqueue(call);

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
    AbsoluteTime		deadline
)
{
	boolean_t		result = TRUE;
    int				s;

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

	if (queue_first(&delayed_call_queue) == qe(call))
		_set_delayed_call_timer(call);

    simple_unlock(&thread_call_lock);
    splx(s);

	return (result);
}

boolean_t
thread_call_enter1_delayed(
    thread_call_t			call,
    thread_call_param_t		param1,
    AbsoluteTime			deadline
)
{
	boolean_t			result = TRUE;
    int					s;

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

	if (queue_first(&delayed_call_queue) == qe(call))
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
    int				s;
    
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
	AbsoluteTime		*deadline)
{
	boolean_t		result = FALSE;
	int				s;

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
 * Routine:	_call_thread_wake [private]
 *
 * Purpose:	Wake a callout thread to service
 *		newly pending callout entries.  May wake
 *		the activate thread to either wake or
 *		create additional callout threads.
 *
 * Preconditions:	thread_call_lock held.
 *
 * Postconditions:	None.
 */

static __inline__
void
_call_thread_wake(void)
{
	thread_t		thread_to_wake;

	if (!queue_empty(&idle_thread_queue)) {
		queue_remove_first(
				&idle_thread_queue, thread_to_wake, thread_t, wait_link);
		clear_wait(thread_to_wake, THREAD_AWAKENED);
		thread_calls.idle_thread_num--;
	}
	else
		thread_to_wake = THREAD_NULL;

	if (!activate_thread_awake &&
			(thread_to_wake == THREAD_NULL || thread_calls.thread_num <
					(thread_calls.active_num + thread_calls.pending_num))) {
		clear_wait(activate_thread, THREAD_AWAKENED);
		activate_thread_awake = TRUE;
	}
}

#if defined (__i386__)
#define NO_CONTINUATIONS	(1)
#else
#define NO_CONTINUATIONS	(0)
#endif

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

#if	NO_CONTINUATIONS
 loop:
#endif
    (void) splsched();
    simple_lock(&thread_call_lock);

    while (thread_calls.pending_num > 0) {
		thread_call_t			call;
		thread_call_func_t		func;
		thread_call_param_t		param0, param1;

		call = TC(dequeue_head(&pending_call_queue));
		thread_calls.pending_num--;

		func = call->func;
		param0 = call->param0;
		param1 = call->param1;
	
		call->state = IDLE;

		_internal_call_release(call);

		if (++thread_calls.active_num > thread_calls.active_hiwat)
			thread_calls.active_hiwat = thread_calls.active_num;

		if (thread_calls.pending_num > 0)
			_call_thread_wake();

		simple_unlock(&thread_call_lock);
		(void) spllo();

		(*func)(param0, param1);

		(void)thread_funnel_set(self->funnel_lock, FALSE);

		(void) splsched();
		simple_lock(&thread_call_lock);

		thread_calls.active_num--;
    }
	
    if ((thread_calls.thread_num - thread_calls.active_num) <=
											thread_calls.thread_lowat) {
		queue_enter(&idle_thread_queue, self, thread_t, wait_link);
		thread_calls.idle_thread_num++;

		assert_wait(&idle_thread_queue, THREAD_INTERRUPTIBLE);
	
		simple_unlock(&thread_call_lock);
		(void) spllo();

#if	NO_CONTINUATIONS
		thread_block((void (*)(void)) 0);
		goto loop;
#else	
		thread_block(_call_thread_continue);
#endif
		/* NOTREACHED */
    }
    
    thread_calls.thread_num--;
    
    simple_unlock(&thread_call_lock);
    (void) spllo();
    
    (void) thread_terminate(self->top_act);
	/* NOTREACHED */
}

static
void
_call_thread(void)
{
	thread_t					self = current_thread();

    stack_privilege(self);

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
#if	NO_CONTINUATIONS
 loop:
#endif
    (void) splsched();
    simple_lock(&thread_call_lock);
        
    if (thread_calls.thread_num <
			(thread_calls.active_num + thread_calls.pending_num)) {

		if (++thread_calls.thread_num > thread_calls.thread_hiwat)
			thread_calls.thread_hiwat = thread_calls.thread_num;

		simple_unlock(&thread_call_lock);
		(void) spllo();
	
		(void) kernel_thread_with_priority(kernel_task,
									MAXPRI_KERNBAND-1, _call_thread, TRUE);
#if	NO_CONTINUATIONS
		thread_block((void (*)(void)) 0);
		goto loop;
#else	
		thread_block(_activate_thread_continue);
#endif
		/* NOTREACHED */
    }
	else if (thread_calls.pending_num > 0) {
		_call_thread_wake();

		simple_unlock(&thread_call_lock);
		(void) spllo();

#if	NO_CONTINUATIONS
		thread_block((void (*)(void)) 0);
		goto loop;
#else	
		thread_block(_activate_thread_continue);
#endif
		/* NOTREACHED */
	}
		
    assert_wait(&activate_thread_awake, THREAD_INTERRUPTIBLE);
	activate_thread_awake = FALSE;
    
    simple_unlock(&thread_call_lock);
	(void) spllo();
    
#if	NO_CONTINUATIONS
	thread_block((void (*)(void)) 0);
	goto loop;
#else	
	thread_block(_activate_thread_continue);
#endif
	/* NOTREACHED */
}

static
void
_activate_thread(void)
{
	thread_t		self = current_thread();

	self->vm_privilege = TRUE;
	vm_page_free_reserve(2);	/* XXX */
    stack_privilege(self);
    
    _activate_thread_continue();
    /* NOTREACHED */
}

static
void
_delayed_call_timer(
	timer_call_param_t		p0,
	timer_call_param_t		p1
)
{
	AbsoluteTime		timestamp;
    thread_call_t		call;
	boolean_t			new_pending = FALSE;
    int					s;

    s = splsched();
    simple_lock(&thread_call_lock);

	clock_get_uptime(&timestamp);
    
    call = TC(queue_first(&delayed_call_queue));
    
    while (!queue_end(&delayed_call_queue, qe(call))) {
    	if (CMP_ABSOLUTETIME(&call->deadline, &timestamp) <= 0) {
			_delayed_call_dequeue(call);

			_pending_call_enqueue(call);
			new_pending = TRUE;
		}
		else
			break;
	    
		call = TC(queue_first(&delayed_call_queue));
    }

	if (!queue_end(&delayed_call_queue, qe(call)))
		_set_delayed_call_timer(call);

    if (new_pending)
		_call_thread_wake();

    simple_unlock(&thread_call_lock);
    splx(s);
}

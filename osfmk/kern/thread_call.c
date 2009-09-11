/*
 * Copyright (c) 1993-1995, 1999-2008 Apple Inc. All rights reserved.
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
#include <kern/zalloc.h>
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

decl_simple_lock_data(static,thread_call_lock)

static zone_t		thread_call_zone;

struct thread_call_group {
	queue_head_t		pending_queue;
	uint32_t			pending_count;

	queue_head_t		delayed_queue;

	timer_call_data_t	delayed_timer;

	struct wait_queue	idle_wqueue;
	uint32_t			idle_count, active_count;
};

typedef struct thread_call_group	*thread_call_group_t;

static struct thread_call_group		thread_call_group0;

static boolean_t			thread_call_daemon_awake;

#define thread_call_thread_min	4

#define internal_call_count	768

static thread_call_data_t	internal_call_storage[internal_call_count];
static queue_head_t			thread_call_internal_queue;

static __inline__ thread_call_t		_internal_call_allocate(void);

static __inline__ void	_internal_call_release(
							thread_call_t		call);

static __inline__ boolean_t	_pending_call_enqueue(
								thread_call_t		call,
								thread_call_group_t	group),
							_delayed_call_enqueue(
								thread_call_t		call,
								thread_call_group_t	group,
								uint64_t			deadline),
							_call_dequeue(
								thread_call_t		call,
								thread_call_group_t	group);

static __inline__ void	thread_call_wake(
							thread_call_group_t	group);

static __inline__ void	_set_delayed_call_timer(
							thread_call_t		call,
							thread_call_group_t	group);
					
static boolean_t	_remove_from_pending_queue(
						thread_call_func_t		func,
						thread_call_param_t		param0,
						boolean_t				remove_all),
					_remove_from_delayed_queue(
						thread_call_func_t		func,
						thread_call_param_t		param0,
						boolean_t				remove_all);

static void		thread_call_daemon(
					thread_call_group_t		group),
				thread_call_thread(
					thread_call_group_t		group);

static void		thread_call_delayed_timer(
					timer_call_param_t		p0,
					timer_call_param_t		p1);

#define qe(x)		((queue_entry_t)(x))
#define TC(x)		((thread_call_t)(x))

/*
 *	thread_call_initialize:
 *
 *	Initialize this module, called
 *	early during system initialization.
 */
void
thread_call_initialize(void)
{
    thread_call_t			call;
	thread_call_group_t		group = &thread_call_group0;
	kern_return_t			result;
	thread_t				thread;
	int						i;
	spl_t					s;

	i = sizeof (thread_call_data_t);
	thread_call_zone = zinit(i, 4096 * i, 16 * i, "thread_call");

    simple_lock_init(&thread_call_lock, 0);

	s = splsched();
	simple_lock(&thread_call_lock);

    queue_init(&group->pending_queue);
    queue_init(&group->delayed_queue);

	timer_call_setup(&group->delayed_timer, thread_call_delayed_timer, group);

	wait_queue_init(&group->idle_wqueue, SYNC_POLICY_FIFO);

    queue_init(&thread_call_internal_queue);
    for (
	    	call = internal_call_storage;
			call < &internal_call_storage[internal_call_count];
			call++) {

		enqueue_tail(&thread_call_internal_queue, qe(call));
    }

	thread_call_daemon_awake = TRUE;

	simple_unlock(&thread_call_lock);
	splx(s);

	result = kernel_thread_start_priority((thread_continue_t)thread_call_daemon, group, BASEPRI_PREEMPT + 1, &thread);
	if (result != KERN_SUCCESS)
		panic("thread_call_initialize");

	thread_deallocate(thread);
}

void
thread_call_setup(
	thread_call_t			call,
	thread_call_func_t		func,
	thread_call_param_t		param0)
{
	call_entry_setup(call, func, param0);
}

/*
 *	_internal_call_allocate:
 *
 *	Allocate an internal callout entry.
 *
 *	Called with thread_call_lock held.
 */
static __inline__ thread_call_t
_internal_call_allocate(void)
{
    thread_call_t		call;
    
    if (queue_empty(&thread_call_internal_queue))
    	panic("_internal_call_allocate");
	
    call = TC(dequeue_head(&thread_call_internal_queue));
    
    return (call);
}

/*
 *	_internal_call_release:
 *
 *	Release an internal callout entry which
 *	is no longer pending (or delayed).
 *
 * 	Called with thread_call_lock held.
 */
static __inline__ void
_internal_call_release(
    thread_call_t		call)
{
    if (    call >= internal_call_storage						&&
	   	    call < &internal_call_storage[internal_call_count]		)
		enqueue_head(&thread_call_internal_queue, qe(call));
}

/*
 *	_pending_call_enqueue:
 *
 *	Place an entry at the end of the
 *	pending queue, to be executed soon.
 *
 *	Returns TRUE if the entry was already
 *	on a queue.
 *
 *	Called with thread_call_lock held.
 */
static __inline__ boolean_t
_pending_call_enqueue(
    thread_call_t		call,
	thread_call_group_t	group)
{
	queue_t		old_queue;

	old_queue = call_entry_enqueue_tail(call, &group->pending_queue);

	group->pending_count++;

	return (old_queue != NULL);
}

/*
 *	_delayed_call_enqueue:
 *
 *	Place an entry on the delayed queue,
 *	after existing entries with an earlier
 * 	(or identical) deadline.
 *
 *	Returns TRUE if the entry was already
 *	on a queue.
 *
 *	Called with thread_call_lock held.
 */
static __inline__ boolean_t
_delayed_call_enqueue(
    thread_call_t		call,
	thread_call_group_t	group,
	uint64_t			deadline)
{
	queue_t			old_queue;

	old_queue = call_entry_enqueue_deadline(call, &group->delayed_queue, deadline);

	if (old_queue == &group->pending_queue)
		group->pending_count--;

	return (old_queue != NULL);
}

/*
 *	_call_dequeue:
 *
 *	Remove an entry from a queue.
 *
 *	Returns TRUE if the entry was on a queue.
 *
 *	Called with thread_call_lock held.
 */
static __inline__ boolean_t
_call_dequeue(
	thread_call_t		call,
	thread_call_group_t	group)
{
	queue_t			old_queue;

	old_queue = call_entry_dequeue(call);

	if (old_queue == &group->pending_queue)
		group->pending_count--;

	return (old_queue != NULL);
}

/*
 *	_set_delayed_call_timer:
 *
 *	Reset the timer so that it
 *	next expires when the entry is due.
 *
 *	Called with thread_call_lock held.
 */
static __inline__ void
_set_delayed_call_timer(
    thread_call_t		call,
	thread_call_group_t	group)
{
    timer_call_enter(&group->delayed_timer, call->deadline);
}

/*
 *	_remove_from_pending_queue:
 *
 *	Remove the first (or all) matching
 *	entries	from the pending queue.
 *
 *	Returns	TRUE if any matching entries
 *	were found.
 *
 *	Called with thread_call_lock held.
 */
static boolean_t
_remove_from_pending_queue(
    thread_call_func_t		func,
    thread_call_param_t		param0,
    boolean_t				remove_all)
{
	boolean_t				call_removed = FALSE;
	thread_call_t			call;
	thread_call_group_t		group = &thread_call_group0;
    
    call = TC(queue_first(&group->pending_queue));
    
    while (!queue_end(&group->pending_queue, qe(call))) {
    	if (	call->func == func			&&
				call->param0 == param0			) {
			thread_call_t	next = TC(queue_next(qe(call)));
		
			_call_dequeue(call, group);

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
 *	_remove_from_delayed_queue:
 *
 *	Remove the first (or all) matching
 *	entries	from the delayed queue.
 *
 *	Returns	TRUE if any matching entries
 *	were found.
 *
 *	Called with thread_call_lock held.
 */
static boolean_t
_remove_from_delayed_queue(
    thread_call_func_t		func,
    thread_call_param_t		param0,
    boolean_t				remove_all)
{
    boolean_t				call_removed = FALSE;
    thread_call_t			call;
	thread_call_group_t		group = &thread_call_group0;
    
    call = TC(queue_first(&group->delayed_queue));
    
    while (!queue_end(&group->delayed_queue, qe(call))) {
    	if (	call->func == func			&&
				call->param0 == param0			) {
			thread_call_t	next = TC(queue_next(qe(call)));
		
			_call_dequeue(call, group);
	    
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

#ifndef	__LP64__

/*
 *	thread_call_func:
 *
 *	Enqueue a function callout.
 *
 *	Guarantees { function, argument }
 *	uniqueness if unique_call is TRUE.
 */
void
thread_call_func(
    thread_call_func_t		func,
    thread_call_param_t		param,
    boolean_t				unique_call)
{
    thread_call_t			call;
	thread_call_group_t		group = &thread_call_group0;
    spl_t					s;
    
    s = splsched();
    simple_lock(&thread_call_lock);
    
    call = TC(queue_first(&group->pending_queue));
    
	while (unique_call && !queue_end(&group->pending_queue, qe(call))) {
    	if (	call->func == func			&&
				call->param0 == param			) {
			break;
		}
	
		call = TC(queue_next(qe(call)));
    }
    
    if (!unique_call || queue_end(&group->pending_queue, qe(call))) {
		call = _internal_call_allocate();
		call->func			= func;
		call->param0		= param;
		call->param1		= NULL;
	
		_pending_call_enqueue(call, group);
		
		if (group->active_count == 0)
			thread_call_wake(group);
    }

	simple_unlock(&thread_call_lock);
    splx(s);
}

#endif	/* __LP64__ */

/*
 *	thread_call_func_delayed:
 *
 *	Enqueue a function callout to
 *	occur at the stated time.
 */
void
thread_call_func_delayed(
    thread_call_func_t		func,
    thread_call_param_t		param,
    uint64_t				deadline)
{
    thread_call_t			call;
	thread_call_group_t		group = &thread_call_group0;
    spl_t					s;
    
    s = splsched();
    simple_lock(&thread_call_lock);
    
    call = _internal_call_allocate();
    call->func			= func;
    call->param0		= param;
    call->param1		= 0;
    
    _delayed_call_enqueue(call, group, deadline);
    
    if (queue_first(&group->delayed_queue) == qe(call))
    	_set_delayed_call_timer(call, group);
    
    simple_unlock(&thread_call_lock);
    splx(s);
}

/*
 *	thread_call_func_cancel:
 *
 *	Dequeue a function callout.
 *
 *	Removes one (or all) { function, argument }
 *	instance(s) from either (or both)
 *	the pending and	the delayed queue,
 *	in that order.
 *
 *	Returns TRUE if any calls were cancelled.
 */
boolean_t
thread_call_func_cancel(
    thread_call_func_t		func,
    thread_call_param_t		param,
    boolean_t				cancel_all)
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
 *	thread_call_allocate:
 *
 *	Allocate a callout entry.
 */
thread_call_t
thread_call_allocate(
    thread_call_func_t		func,
    thread_call_param_t		param0)
{
    thread_call_t		call = zalloc(thread_call_zone);

	call_entry_setup(call, func, param0);

    return (call);
}

/*
 *	thread_call_free:
 *
 *	Free a callout entry.
 */
boolean_t
thread_call_free(
    thread_call_t		call)
{
    spl_t		s;
    
    s = splsched();
    simple_lock(&thread_call_lock);
    
    if (call->queue != NULL) {
    	simple_unlock(&thread_call_lock);
		splx(s);

		return (FALSE);
    }
    
    simple_unlock(&thread_call_lock);
    splx(s);
    
	zfree(thread_call_zone, call);

	return (TRUE);
}

/*
 *	thread_call_enter:
 *
 *	Enqueue a callout entry to occur "soon".
 *
 *	Returns TRUE if the call was
 *	already on a queue.
 */
boolean_t
thread_call_enter(
    thread_call_t		call)
{
	boolean_t				result = TRUE;
	thread_call_group_t		group = &thread_call_group0;
    spl_t					s;
    
    s = splsched();
    simple_lock(&thread_call_lock);
    
    if (call->queue != &group->pending_queue) {
    	result = _pending_call_enqueue(call, group);
		
		if (group->active_count == 0)
			thread_call_wake(group);
	}

	call->param1 = 0;

	simple_unlock(&thread_call_lock);
    splx(s);

	return (result);
}

boolean_t
thread_call_enter1(
    thread_call_t			call,
    thread_call_param_t		param1)
{
	boolean_t				result = TRUE;
	thread_call_group_t		group = &thread_call_group0;
    spl_t					s;
    
    s = splsched();
    simple_lock(&thread_call_lock);
    
    if (call->queue != &group->pending_queue) {
    	result = _pending_call_enqueue(call, group);
		
		if (group->active_count == 0)
			thread_call_wake(group);
	}

	call->param1 = param1;

	simple_unlock(&thread_call_lock);
    splx(s);

	return (result);
}

/*
 *	thread_call_enter_delayed:
 *
 *	Enqueue a callout entry to occur
 *	at the stated time.
 *
 *	Returns TRUE if the call was
 *	already on a queue.
 */
boolean_t
thread_call_enter_delayed(
    thread_call_t		call,
    uint64_t			deadline)
{
	boolean_t				result = TRUE;
	thread_call_group_t		group = &thread_call_group0;
    spl_t					s;

    s = splsched();
    simple_lock(&thread_call_lock);

	result = _delayed_call_enqueue(call, group, deadline);

	if (queue_first(&group->delayed_queue) == qe(call))
		_set_delayed_call_timer(call, group);

	call->param1 = 0;

    simple_unlock(&thread_call_lock);
    splx(s);

	return (result);
}

boolean_t
thread_call_enter1_delayed(
    thread_call_t			call,
    thread_call_param_t		param1,
    uint64_t				deadline)
{
	boolean_t				result = TRUE;
	thread_call_group_t		group = &thread_call_group0;
    spl_t					s;

    s = splsched();
    simple_lock(&thread_call_lock);

	result = _delayed_call_enqueue(call, group, deadline);

	if (queue_first(&group->delayed_queue) == qe(call))
		_set_delayed_call_timer(call, group);

	call->param1 = param1;

    simple_unlock(&thread_call_lock);
    splx(s);

	return (result);
}

/*
 *	thread_call_cancel:
 *
 *	Dequeue a callout entry.
 *
 *	Returns TRUE if the call was
 *	on a queue.
 */
boolean_t
thread_call_cancel(
    thread_call_t		call)
{
	boolean_t				result;
	thread_call_group_t		group = &thread_call_group0;
    spl_t					s;
    
    s = splsched();
    simple_lock(&thread_call_lock);

	result = _call_dequeue(call, group);
	
    simple_unlock(&thread_call_lock);
    splx(s);

	return (result);
}

#ifndef	__LP64__

/*
 *	thread_call_is_delayed:
 *
 *	Returns TRUE if the call is
 *	currently on a delayed queue.
 *
 *	Optionally returns the expiration time.
 */
boolean_t
thread_call_is_delayed(
	thread_call_t		call,
	uint64_t			*deadline)
{
	boolean_t				result = FALSE;
	thread_call_group_t		group = &thread_call_group0;
	spl_t					s;

	s = splsched();
	simple_lock(&thread_call_lock);

	if (call->queue == &group->delayed_queue) {
		if (deadline != NULL)
			*deadline = call->deadline;
		result = TRUE;
	}

	simple_unlock(&thread_call_lock);
	splx(s);

	return (result);
}

#endif	/* __LP64__ */

/*
 *	thread_call_wake:
 *
 *	Wake a call thread to service
 *	pending call entries.  May wake
 *	the daemon thread in order to
 *	create additional call threads.
 *
 *	Called with thread_call_lock held.
 */
static __inline__ void
thread_call_wake(
	thread_call_group_t		group)
{
	if (group->idle_count > 0 && wait_queue_wakeup_one(&group->idle_wqueue, NULL, THREAD_AWAKENED) == KERN_SUCCESS) {
		group->idle_count--; group->active_count++;
	}
	else
	if (!thread_call_daemon_awake) {
		thread_call_daemon_awake = TRUE;
		thread_wakeup_one(&thread_call_daemon_awake);
	}
}

/*
 *	sched_call_thread:
 *
 *	Call out invoked by the scheduler.
 */
static void
sched_call_thread(
	int				type,
__unused	thread_t		thread)
{
	thread_call_group_t		group = &thread_call_group0;

	simple_lock(&thread_call_lock);

	switch (type) {

	case SCHED_CALL_BLOCK:
		if (--group->active_count == 0 && group->pending_count > 0)
			thread_call_wake(group);
		break;

	case SCHED_CALL_UNBLOCK:
		group->active_count++;
		break;
	}

	simple_unlock(&thread_call_lock);
}

/*
 *	thread_call_thread:
 */
static void
thread_call_thread(
	thread_call_group_t		group)
{
	thread_t		self = current_thread();

    (void) splsched();
    simple_lock(&thread_call_lock);

	thread_sched_call(self, sched_call_thread);

    while (group->pending_count > 0) {
		thread_call_t			call;
		thread_call_func_t		func;
		thread_call_param_t		param0, param1;

		call = TC(dequeue_head(&group->pending_queue));
		group->pending_count--;

		func = call->func;
		param0 = call->param0;
		param1 = call->param1;
	
		call->queue = NULL;

		_internal_call_release(call);

		simple_unlock(&thread_call_lock);
		(void) spllo();

		KERNEL_DEBUG_CONSTANT(
			MACHDBG_CODE(DBG_MACH_SCHED,MACH_CALLOUT) | DBG_FUNC_NONE,
				func, param0, param1, 0, 0);

		(*func)(param0, param1);

		(void)thread_funnel_set(self->funnel_lock, FALSE);		/* XXX */

		(void) splsched();
		simple_lock(&thread_call_lock);
    }

	thread_sched_call(self, NULL);
	group->active_count--;

    if (group->idle_count < thread_call_thread_min) {
		group->idle_count++;

		wait_queue_assert_wait(&group->idle_wqueue, NULL, THREAD_UNINT, 0);
	
		simple_unlock(&thread_call_lock);
		(void) spllo();

		thread_block_parameter((thread_continue_t)thread_call_thread, group);
		/* NOTREACHED */
    }

    simple_unlock(&thread_call_lock);
    (void) spllo();
    
    thread_terminate(self);
	/* NOTREACHED */
}

/*
 *	thread_call_daemon:
 */
static void
thread_call_daemon_continue(
	thread_call_group_t		group)
{
	kern_return_t	result;
	thread_t		thread;

    (void) splsched();
    simple_lock(&thread_call_lock);
        
	while (group->active_count == 0	&& group->pending_count > 0) {
		group->active_count++;

		simple_unlock(&thread_call_lock);
		(void) spllo();
	
		result = kernel_thread_start_priority((thread_continue_t)thread_call_thread, group, BASEPRI_PREEMPT, &thread);
		if (result != KERN_SUCCESS)
			panic("thread_call_daemon");

		thread_deallocate(thread);

		(void) splsched();
		simple_lock(&thread_call_lock);
    }

	thread_call_daemon_awake = FALSE;
    assert_wait(&thread_call_daemon_awake, THREAD_UNINT);
    
    simple_unlock(&thread_call_lock);
	(void) spllo();
    
	thread_block_parameter((thread_continue_t)thread_call_daemon_continue, group);
	/* NOTREACHED */
}

static void
thread_call_daemon(
	thread_call_group_t		group)
{
	thread_t	self = current_thread();

	self->options |= TH_OPT_VMPRIV;
	vm_page_free_reserve(2);	/* XXX */
    
    thread_call_daemon_continue(group);
    /* NOTREACHED */
}

static void
thread_call_delayed_timer(
	timer_call_param_t				p0,
	__unused timer_call_param_t		p1
)
{
    thread_call_t			call;
	thread_call_group_t		group = p0;
	boolean_t				new_pending = FALSE;
	uint64_t				timestamp;

    simple_lock(&thread_call_lock);

	timestamp = mach_absolute_time();
    
    call = TC(queue_first(&group->delayed_queue));
    
    while (!queue_end(&group->delayed_queue, qe(call))) {
    	if (call->deadline <= timestamp) {
			_pending_call_enqueue(call, group);
			new_pending = TRUE;
		}
		else
			break;
	    
		call = TC(queue_first(&group->delayed_queue));
    }

	if (!queue_end(&group->delayed_queue, qe(call)))
		_set_delayed_call_timer(call, group);

    if (new_pending && group->active_count == 0)
		thread_call_wake(group);

    simple_unlock(&thread_call_lock);
}

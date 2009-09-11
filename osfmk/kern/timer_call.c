/*
 * Copyright (c) 1993-2008 Apple Inc. All rights reserved.
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
 * Timer interrupt callout module.
 */

#include <mach/mach_types.h>

#include <kern/clock.h>
#include <kern/processor.h>
#include <kern/etimer.h>
#include <kern/timer_call.h>
#include <kern/timer_queue.h>
#include <kern/call_entry.h>

#include <sys/kdebug.h>

#if CONFIG_DTRACE && (DEVELOPMENT || DEBUG )
#include <mach/sdt.h>
#endif

decl_simple_lock_data(static,timer_call_lock)

#define qe(x)		((queue_entry_t)(x))
#define TC(x)		((timer_call_t)(x))

void
timer_call_initialize(void)
{
	simple_lock_init(&timer_call_lock, 0);
}

void
timer_call_setup(
	timer_call_t			call,
	timer_call_func_t		func,
	timer_call_param_t		param0)
{
	call_entry_setup(call, func, param0);
}

__inline__ queue_t
call_entry_enqueue_deadline(
	call_entry_t		entry,
	queue_t				queue,
	uint64_t			deadline)
{
	queue_t			old_queue = entry->queue;
	timer_call_t	current;

	if (old_queue != queue || entry->deadline < deadline) {
		if (old_queue != queue)
			current = TC(queue_first(queue));
		else
			current = TC(queue_next(qe(entry)));

		if (old_queue != NULL)
			(void)remque(qe(entry));

		while (TRUE) {
			if (	queue_end(queue, qe(current))		||
					deadline < current->deadline		) {
				current = TC(queue_prev(qe(current)));
				break;
			}

			current = TC(queue_next(qe(current)));
		}

		insque(qe(entry), qe(current));
	}
	else
	if (deadline < entry->deadline) {
		current = TC(queue_prev(qe(entry)));

		(void)remque(qe(entry));

		while (TRUE) {
			if (	queue_end(queue, qe(current))		||
					current->deadline <= deadline		) {
				break;
			}

			current = TC(queue_prev(qe(current)));
		}

		insque(qe(entry), qe(current));
	}

	entry->queue = queue;
	entry->deadline = deadline;

	return (old_queue);
}

__inline__ queue_t
call_entry_enqueue_tail(
	call_entry_t		entry,
	queue_t				queue)
{
	queue_t			old_queue = entry->queue;

	if (old_queue != NULL)
		(void)remque(qe(entry));

	enqueue_tail(queue, qe(entry));

	entry->queue = queue;

	return (old_queue);
}

__inline__ queue_t
call_entry_dequeue(
	call_entry_t		entry)
{
	queue_t			old_queue = entry->queue;

	if (old_queue != NULL)
		(void)remque(qe(entry));

	entry->queue = NULL;

	return (old_queue);
}

boolean_t
timer_call_enter(
	timer_call_t		call,
	uint64_t			deadline)
{
	queue_t			queue, old_queue;
	spl_t			s;

	s = splclock();
	simple_lock(&timer_call_lock);

	queue = timer_queue_assign(deadline);

	old_queue = call_entry_enqueue_deadline(call, queue, deadline);

	call->param1 = NULL;

	simple_unlock(&timer_call_lock);
	splx(s);

	return (old_queue != NULL);
}

boolean_t
timer_call_enter1(
	timer_call_t		call,
	timer_call_param_t	param1,
	uint64_t			deadline)
{
	queue_t			queue, old_queue;
	spl_t			s;

	s = splclock();
	simple_lock(&timer_call_lock);

	queue = timer_queue_assign(deadline);

	old_queue = call_entry_enqueue_deadline(call, queue, deadline);

	call->param1 = param1;

	simple_unlock(&timer_call_lock);
	splx(s);

	return (old_queue != NULL);
}

boolean_t
timer_call_cancel(
	timer_call_t		call)
{
	queue_t			old_queue;
	spl_t			s;

	s = splclock();
	simple_lock(&timer_call_lock);

	old_queue = call_entry_dequeue(call);

	if (old_queue != NULL) {
		if (!queue_empty(old_queue))
			timer_queue_cancel(old_queue, call->deadline, TC(queue_first(old_queue))->deadline);
		else
			timer_queue_cancel(old_queue, call->deadline, UINT64_MAX);
	}

	simple_unlock(&timer_call_lock);
	splx(s);

	return (old_queue != NULL);
}

void
timer_queue_shutdown(
	queue_t			queue)
{
	timer_call_t	call;
	queue_t			new_queue;
	spl_t			s;

	s = splclock();
	simple_lock(&timer_call_lock);

	call = TC(queue_first(queue));

	while (!queue_end(queue, qe(call))) {
		new_queue = timer_queue_assign(call->deadline);

		call_entry_enqueue_deadline(call, new_queue, call->deadline);

		call = TC(queue_first(queue));
	}

	simple_unlock(&timer_call_lock);
	splx(s);
}

uint64_t
timer_queue_expire(
	queue_t			queue,
	uint64_t		deadline)
{
	timer_call_t	call;

	simple_lock(&timer_call_lock);

	call = TC(queue_first(queue));

	while (!queue_end(queue, qe(call))) {
		if (call->deadline <= deadline) {
			timer_call_func_t		func;
			timer_call_param_t		param0, param1;

			call_entry_dequeue(call);

			func = call->func;
			param0 = call->param0;
			param1 = call->param1;

			simple_unlock(&timer_call_lock);

			KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_DECI,
							   2)
							| DBG_FUNC_START,
					      func,
					      param0,
					      param1, 0, 0);

#if CONFIG_DTRACE && (DEVELOPMENT || DEBUG )
			DTRACE_TMR3(callout__start, timer_call_func_t, func, 
										timer_call_param_t, param0, 
										timer_call_param_t, param1);
#endif

			(*func)(param0, param1);

#if CONFIG_DTRACE && (DEVELOPMENT || DEBUG )
			DTRACE_TMR3(callout__end, timer_call_func_t, func, 
										timer_call_param_t, param0, 
										timer_call_param_t, param1);
#endif

			KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_DECI,
							   2)
							| DBG_FUNC_END,
					      func,
					      param0,
					      param1, 0, 0);

			simple_lock(&timer_call_lock);
		}
		else
			break;

		call = TC(queue_first(queue));
	}

	if (!queue_end(queue, qe(call)))
		deadline = call->deadline;
	else
		deadline = UINT64_MAX;

	simple_unlock(&timer_call_lock);

	return (deadline);
}

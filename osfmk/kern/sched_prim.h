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
/*
 */
/*
 *	File:	sched_prim.h
 *	Author:	David Golub
 *
 *	Scheduling primitive definitions file
 *
 */

#ifndef	_KERN_SCHED_PRIM_H_
#define _KERN_SCHED_PRIM_H_

#include <mach/boolean.h>
#include <mach/machine/vm_types.h>
#include <mach/kern_return.h>
#include <kern/clock.h>
#include <kern/kern_types.h>
#include <kern/thread.h>
#include <kern/lock.h>
#include <kern/time_out.h>	/*** ??? temp - remove me soon ***/
#include <kern/cpu_data.h>
#include <kern/wait_queue.h>

#ifdef MACH_KERNEL_PRIVATE

#include <mach_ldebug.h>
/*
 *	Exported interface to sched_prim.c.
 *	A few of these functions are actually defined in
 *	ipc_sched.c, for historical reasons.
 */

/* Initialize scheduler module */
extern void		sched_init(void);

/*
 * Set up thread timeout element(s) when thread is created.
 */
extern void		thread_timer_setup(
					thread_t		thread);

extern void		thread_timer_terminate(void);

#define thread_bind_locked(thread, processor)	\
		(thread)->bound_processor = (processor)

/*
 * Prevent a thread from restarting after it blocks interruptibly
 */
extern boolean_t	thread_stop( 
						thread_t	thread);

/*
 * wait for a thread to stop
 */
extern boolean_t	thread_wait(
						thread_t	thread);

/* Select a thread to run on a particular processor */
extern thread_t	thread_select(
						processor_t	myprocessor);

extern void		thread_go_locked(
					 	thread_t	thread,
						int		result);

/* Stop old thread and run new thread */
extern boolean_t thread_invoke(
						thread_t	old_thread,
						thread_t	new_thread,
						int			reason,
						void        (*continuation)(void));

/* Called when current thread is given new stack */
extern void		thread_continue(
						thread_t	old_thread);

/* Switch directly to a particular thread */
extern int		thread_run(
						thread_t	old_thread,
						void		(*continuation)(void),
						thread_t	new_thread);

/* Dispatch a thread not on a run queue */
extern void		thread_dispatch(
						thread_t	thread);

/* Invoke continuation */
extern void		call_continuation(
						void		(*continuation)(void));

/* Compute effective priority of the specified thread */
extern void		compute_priority(
						thread_t	thread,
						int			resched);

/* Version of compute_priority for current thread or
 * thread being manipuldated by scheduler.
 */
extern void		compute_my_priority(
						thread_t	thread);

/* Periodic scheduler activity */
extern void		sched_tick_thread(void);

/* Update priority of thread that has been sleeping or suspended.
 * Used to "catch up" with the system.
 */
extern void		update_priority(
						thread_t	thread);

/* Idle thread loop */
extern void		idle_thread(void);

/*
 *	thread_sleep_interlock:
 *
 *	Cause the current thread to wait until the specified event
 *	occurs.  The specified HW interlock is unlocked before releasing
 *	the cpu.  (This is a convenient way to sleep without manually
 *	calling assert_wait).
 */

#define thread_sleep_interlock(event, lock, interruptible)	\
MACRO_BEGIN													\
	assert_wait(event, interruptible);						\
	interlock_unlock(lock);									\
	thread_block((void (*)(void)) 0);						\
MACRO_END

/*
 *	Machine-dependent code must define these functions.
 */

/* Start thread running */
extern void		thread_bootstrap_return(void);

/* Return from exception */
extern void		thread_exception_return(void);

/* Continuation return from syscall */
extern void     thread_syscall_return(
                        kern_return_t   ret);

extern thread_t	switch_context(
						thread_t	old_thread,
						void		(*continuation)(void),
						thread_t	new_thread);

/* Attach stack to thread */
extern void		machine_kernel_stack_init(
						thread_t	thread,
						void		(*start_pos)(thread_t));

extern void		load_context(
						thread_t	thread);

extern thread_act_t		switch_act(
							thread_act_t	act);

extern void		machine_switch_act(
							thread_t		thread,
							thread_act_t	old,
							thread_act_t	new,
							int				cpu);

/*
 *	These functions are either defined in kern/thread.c
 *	or are defined directly by machine-dependent code.
 */

/* Allocate an activation stack */
extern vm_offset_t	stack_alloc(thread_t thread, void (*start_pos)(thread_t));

/* Free an activation stack */
extern void		stack_free(thread_t thread);

/* Collect excess kernel stacks */
extern void		stack_collect(void);

extern void		set_pri(
					thread_t	thread,
					int			pri,
					boolean_t	resched);

/* Block current thread, indicating reason (Block or Quantum expiration) */
extern int		thread_block_reason(
						void		(*continuation)(void),
						int		reason);

/* Make thread runnable */
extern void		thread_setrun(
						thread_t	thread,
						boolean_t	may_preempt,
						boolean_t	tail);
/*
 *	Flags for thread_setrun()
 */

#define HEAD_Q		0		/* FALSE */
#define TAIL_Q		1		/* TRUE */

/* Bind thread to a particular processor */
extern void		thread_bind(
						thread_t	thread,
						processor_t	processor);

extern void		thread_mark_wait_locked(
						thread_t	thread,
						int			interruptible);

#endif /* MACH_KERNEL_PRIVATE */

/*
 ****************** Only exported until BSD stops using ********************
 */

/*
 * Cancel a stop and continue the thread if necessary.
 */
extern void		thread_unstop(
						thread_t	thread);

/* Wake up thread directly, passing result */
extern void		clear_wait(
						thread_t	thread,
						int		result);

/* Bind thread to a particular processor */
extern void		thread_bind(
						thread_t	thread,
						processor_t	processor);


/*
 * *********************   PUBLIC APIs ************************************
 */

/* Set timer for current thread */
extern void		thread_set_timer(
					natural_t		interval,
					natural_t		scale_factor);

extern void		thread_set_timer_deadline(
					AbsoluteTime	deadline);

extern void		thread_cancel_timer(void);

/*
 * thread_stop a thread then wait for it to stop (both of the above)
 */
extern boolean_t	thread_stop_wait(
						thread_t	thread);

/* Declare thread will wait on a particular event */
extern void		assert_wait(
						event_t		event,
						int		interruptflag);

/* Assert that the thread intends to wait for a timeout */
extern void		assert_wait_timeout(
					        natural_t	msecs,
						int		interruptflags);

/* Wake up thread (or threads) waiting on a particular event */
extern void		thread_wakeup_prim(
						event_t		event,
						boolean_t	one_thread,
						int		result);

/* Block current thread (Block reason) */
extern int		thread_block(
						void		(*continuation)(void));


/*
 *	Routines defined as macros
 */

#define thread_wakeup(x)					\
			thread_wakeup_prim((x), FALSE, THREAD_AWAKENED)
#define thread_wakeup_with_result(x, z)		\
			thread_wakeup_prim((x), FALSE, (z))
#define thread_wakeup_one(x)				\
			thread_wakeup_prim((x), TRUE, THREAD_AWAKENED)

/*
 *	thread_sleep_mutex:
 *
 *	Cause the current thread to wait until the specified event
 *	occurs.  The specified mutex is unlocked before releasing
 *	the cpu.  (This is a convenient way to sleep without manually
 *	calling assert_wait).
 */

#define thread_sleep_mutex(event, lock, interruptible)	\
MACRO_BEGIN												\
	assert_wait(event, interruptible);					\
	mutex_unlock(lock);									\
	thread_block((void (*)(void)) 0);					\
MACRO_END

/*
 *	thread_sleep_simple_lock:
 *
 *	Cause the current thread to wait until the specified event
 *	occurs.  The specified simple_lock is unlocked before releasing
 *	the cpu.  (This is a convenient way to sleep without manually
 *	calling assert_wait).
 */

#define thread_sleep_simple_lock(event, lock, interruptible)	\
MACRO_BEGIN														\
	assert_wait(event, interruptible);							\
	simple_unlock(lock);										\
	thread_block((void (*)(void)) 0);							\
MACRO_END


#endif	/* _KERN_SCHED_PRIM_H_ */

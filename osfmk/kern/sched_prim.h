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

#include <sys/appleapiopts.h>

#ifdef	__APPLE_API_PRIVATE

#ifdef	MACH_KERNEL_PRIVATE

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
 * Stop a thread and wait for it to stop running.
 */
extern boolean_t	thread_stop( 
						thread_t	thread);

/*
 * Wait for a thread to stop running.
 */
extern boolean_t	thread_wait(
						thread_t	thread);

/* Select a thread to run on a particular processor */
extern thread_t	thread_select(
						processor_t	myprocessor);

extern kern_return_t thread_go_locked(
					 	thread_t		thread,
						wait_result_t	result);

/* Stop old thread and run new thread */
extern boolean_t thread_invoke(
						thread_t		old_thread,
						thread_t		new_thread,
						int				reason,
						thread_continue_t continuation);

/* Called when current thread is given new stack */
extern void		thread_continue(
						thread_t		old_thread);

/* Switch directly to a particular thread */
extern int		thread_run(
						thread_t		old_thread,
						thread_continue_t continuation,
						thread_t		new_thread);

/* Dispatch a thread not on a run queue */
extern void		thread_dispatch(
						thread_t		thread);

/* Invoke continuation */
extern void		call_continuation(
						thread_continue_t continuation);		  

/* Set the current scheduled priority */
extern void		set_sched_pri(
					thread_t		thread,
					int				priority);

/* Set base priority of the specified thread */
extern void		set_priority(
					thread_t		thread,
					int				priority);

/* Reset scheduled priority of thread */
extern void		compute_priority(
					thread_t		thread,
					boolean_t		override_depress);

/* Adjust scheduled priority of thread during execution */
extern void		compute_my_priority(
					thread_t		thread);

/* Periodic scheduler activity */
extern void		sched_tick_init(void);

/*
 * Update thread to the current scheduler tick.
 */
extern void		update_priority(
					thread_t		thread);

/* Idle thread loop */
extern void		idle_thread(void);

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
						thread_continue_t continuation,
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

/* Block current thread, indicating reason */
extern wait_result_t	thread_block_reason(
							thread_continue_t	continuation,
							ast_t				reason);

/* Dispatch a thread for execution */
extern void		thread_setrun(
					thread_t	thread,
					boolean_t	tail);

#define HEAD_Q		0		/* FALSE */
#define TAIL_Q		1		/* TRUE */

/* Bind thread to a particular processor */
extern void		thread_bind(
						thread_t		thread,
						processor_t		processor);

/* Set the maximum interrupt level for the thread */
__private_extern__ wait_interrupt_t thread_interrupt_level(
						wait_interrupt_t interruptible);

__private_extern__ wait_result_t thread_mark_wait_locked(
						thread_t		 thread,
						wait_interrupt_t interruptible);

/* Sleep, unlocking and then relocking a usimple_lock in the process */
__private_extern__ wait_result_t thread_sleep_fast_usimple_lock(
						event_t			event,
						simple_lock_t	lock,
						wait_interrupt_t interruptible);

/* Wake up locked thread directly, passing result */
__private_extern__ kern_return_t clear_wait_internal(
						thread_t		thread,
						wait_result_t	result);

#endif /* MACH_KERNEL_PRIVATE */

/*
 ****************** Only exported until BSD stops using ********************
 */

/*
 * Cancel a stop and unblock the thread if already stopped.
 */
extern void		thread_unstop(
						thread_t		thread);

/* Wake up thread directly, passing result */
extern kern_return_t clear_wait(
						thread_t		thread,
						wait_result_t	result);

#endif	/* __APPLE_API_PRIVATE */

/*
 * *********************   PUBLIC APIs ************************************
 */

/* Set timer for current thread */
extern void		thread_set_timer(
					uint32_t		interval,
					uint32_t		scale_factor);

extern void		thread_set_timer_deadline(
					uint64_t		deadline);

extern void		thread_cancel_timer(void);

/* Declare thread will wait on a particular event */
extern wait_result_t assert_wait(
						event_t			 event,
						wait_interrupt_t interruptflag);

/* Assert that the thread intends to wait for a timeout */
extern wait_result_t assert_wait_timeout(
						natural_t		 msecs,
						wait_interrupt_t interruptflags);

/* Sleep, unlocking and then relocking a usimple_lock in the process */
extern wait_result_t thread_sleep_usimple_lock(
						event_t			event,
						usimple_lock_t	lock,
						wait_interrupt_t interruptible);	

/* Sleep, unlocking and then relocking a mutex in the process */
extern wait_result_t thread_sleep_mutex(
						event_t			event,
						mutex_t			*mutex,
						wait_interrupt_t interruptible);	
										
/* Sleep with a deadline, unlocking and then relocking a mutex in the process */
extern wait_result_t thread_sleep_mutex_deadline(
						event_t			event,
						mutex_t			*mutex,
						uint64_t		deadline,
						wait_interrupt_t interruptible);	

/* Sleep, unlocking and then relocking a write lock in the process */
extern wait_result_t thread_sleep_lock_write(
						event_t			event,
						lock_t			*lock,
						wait_interrupt_t interruptible);	
									   
/* Sleep, hinting that a thread funnel may be involved in the process */
extern wait_result_t thread_sleep_funnel(
						event_t			event,
						wait_interrupt_t interruptible);	

/* Wake up thread (or threads) waiting on a particular event */
extern kern_return_t thread_wakeup_prim(
						event_t			event,
						boolean_t		one_thread,
						wait_result_t	result);

#ifdef	__APPLE_API_UNSTABLE

/* Block current thread (Block reason) */
extern wait_result_t thread_block(
						thread_continue_t continuation);

#endif	/* __APPLE_API_UNSTABLE */

/*
 *	Routines defined as macros
 */

#define thread_wakeup(x)					\
			thread_wakeup_prim((x), FALSE, THREAD_AWAKENED)
#define thread_wakeup_with_result(x, z)		\
			thread_wakeup_prim((x), FALSE, (z))
#define thread_wakeup_one(x)				\
			thread_wakeup_prim((x), TRUE, THREAD_AWAKENED)

#if		!defined(MACH_KERNEL_PRIVATE) && !defined(ABSOLUTETIME_SCALAR_TYPE)

#include <libkern/OSBase.h>

#define thread_set_timer_deadline(a)	\
	thread_set_timer_deadline(__OSAbsoluteTime(a))

#endif

#endif	/* _KERN_SCHED_PRIM_H_ */

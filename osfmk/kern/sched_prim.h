/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
#include <sys/cdefs.h>

#ifdef	MACH_KERNEL_PRIVATE

/* Initialization */
extern void		sched_init(void);

extern void		sched_startup(void);

extern void		sched_timebase_init(void);

/* Force a preemption point for a thread and wait for it to stop running */
extern boolean_t	thread_stop( 
						thread_t	thread);

/* Release a previous stop request */
extern void			thread_unstop(
						thread_t	thread);

/* Wait for a thread to stop running */
extern void			thread_wait(
						thread_t	thread);

/* Select a thread to run */
extern thread_t		thread_select(
						processor_t		myprocessor);

/* Unblock thread on wake up */
extern boolean_t	thread_unblock(
						thread_t		thread,
						wait_result_t	wresult);

/* Unblock and dispatch thread */
extern kern_return_t	thread_go(
						 	thread_t		thread,
							wait_result_t	wresult);

/* Context switch primitive */
extern boolean_t	thread_invoke(
						thread_t			old_thread,
						thread_t			new_thread,
						ast_t				reason);

/* Perform calculations for thread finishing execution */
extern void			thread_done(
						thread_t		old_thread,
						thread_t		new_thread,
						processor_t		processor);

/* Set up for thread beginning execution */
extern void			thread_begin(
						thread_t		thread,
						processor_t		processor);

/* Handle previous thread at context switch */
extern void			thread_dispatch(
						thread_t		thread);

/* Switch directly to a particular thread */
extern int			thread_run(
						thread_t			self,
						thread_continue_t	continuation,
						void				*parameter,
						thread_t			new_thread);

/* Resume thread with new stack */
extern void			thread_continue(
						thread_t		old_thread);

/* Invoke continuation */
extern void		call_continuation(
					thread_continue_t	continuation,
					void				*parameter,
					wait_result_t		wresult);

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
extern void		sched_tick_thread(void);

/* Perform sched_tick housekeeping activities */
extern void		update_priority(
					thread_t		thread);

/* Idle processor thread */
extern void		idle_thread(void);

extern kern_return_t	idle_thread_create(
							processor_t		processor);

/* Start thread running */
extern void		thread_bootstrap_return(void);

/* Continuation return from syscall */
extern void     thread_syscall_return(
                        kern_return_t   ret);

/* Context switch */
extern wait_result_t	thread_block_reason(
							thread_continue_t	continuation,
							void				*parameter,
							ast_t				reason);

/* Reschedule thread for execution */
extern void		thread_setrun(
					thread_t	thread,
					integer_t	options);

#define SCHED_TAILQ		0
#define SCHED_HEADQ		1
#define SCHED_PREEMPT	2

/* Bind thread to a particular processor */
extern processor_t		thread_bind(
							thread_t		thread,
							processor_t		processor);

extern void		thread_timer_expire(
					void			*thread,
					void			*p1);

/* Set the maximum interrupt level for the thread */
__private_extern__ wait_interrupt_t thread_interrupt_level(
						wait_interrupt_t interruptible);

__private_extern__ wait_result_t thread_mark_wait_locked(
						thread_t		 thread,
						wait_interrupt_t interruptible);

/* Wake up locked thread directly, passing result */
__private_extern__ kern_return_t clear_wait_internal(
						thread_t		thread,
						wait_result_t	result);

#endif /* MACH_KERNEL_PRIVATE */

__BEGIN_DECLS

#ifdef	XNU_KERNEL_PRIVATE

extern boolean_t		assert_wait_possible(void);

/*
 ****************** Only exported until BSD stops using ********************
 */

/* Wake up thread directly, passing result */
extern kern_return_t clear_wait(
						thread_t		thread,
						wait_result_t	result);

/* Return from exception (BSD-visible interface) */
extern void		thread_exception_return(void);

#endif	/* XNU_KERNEL_PRIVATE */

/* Context switch */
extern wait_result_t	thread_block(
							thread_continue_t	continuation);

extern wait_result_t	thread_block_parameter(
							thread_continue_t	continuation,
							void				*parameter);

/* Declare thread will wait on a particular event */
extern wait_result_t	assert_wait(
							event_t				event,
							wait_interrupt_t	interruptible);

/* Assert that the thread intends to wait with a timeout */
extern wait_result_t	assert_wait_timeout(
							event_t				event,
							wait_interrupt_t	interruptible,
							uint32_t			interval,
							uint32_t			scale_factor);

extern wait_result_t	assert_wait_deadline(
							event_t				event,
							wait_interrupt_t	interruptible,
							uint64_t			deadline);

/* Wake up thread (or threads) waiting on a particular event */
extern kern_return_t	thread_wakeup_prim(
							event_t				event,
							boolean_t			one_thread,
							wait_result_t		result);

#define thread_wakeup(x)					\
			thread_wakeup_prim((x), FALSE, THREAD_AWAKENED)
#define thread_wakeup_with_result(x, z)		\
			thread_wakeup_prim((x), FALSE, (z))
#define thread_wakeup_one(x)				\
			thread_wakeup_prim((x), TRUE, THREAD_AWAKENED)

extern boolean_t		preemption_enabled(void);

#ifdef	KERNEL_PRIVATE

/*
 * Obsolete interfaces.
 */

extern void		thread_set_timer(
					uint32_t		interval,
					uint32_t		scale_factor);

extern void		thread_set_timer_deadline(
					uint64_t		deadline);

extern void		thread_cancel_timer(void);

#ifndef	MACH_KERNEL_PRIVATE

#ifndef	ABSOLUTETIME_SCALAR_TYPE

#define thread_set_timer_deadline(a)	\
	thread_set_timer_deadline(__OSAbsoluteTime(a))

#endif	/* ABSOLUTETIME_SCALAR_TYPE */

#endif	/* MACH_KERNEL_PRIVATE */

#endif	/* KERNEL_PRIVATE */

__END_DECLS

#endif	/* _KERN_SCHED_PRIM_H_ */

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

#include <kern/thread.h>
#include <kern/lock.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <mach/vm_param.h>
#include <kern/sched_prim.h>
#include <kern/processor.h>
#include <kern/thread_swap.h>
#include <kern/spl.h>		/* for splsched */
#include <kern/misc_protos.h>
#include <kern/counters.h>
#include <mach/policy.h>

queue_head_t		swapin_queue;
decl_simple_lock_data(,swapin_lock_data)

#define swapin_lock()		simple_lock(&swapin_lock_data)
#define swapin_unlock()		simple_unlock(&swapin_lock_data)

mach_counter_t c_swapin_thread_block;

void	swapin_thread(void);

/*
 *	swapin_init: [exported]
 *
 *	Initialize the swapper module.
 */
void
swapin_init(void)
{
	 queue_init(&swapin_queue);
	 simple_lock_init(&swapin_lock_data, ETAP_THREAD_SWAPPER);
	 kernel_thread_with_priority(
						kernel_task, BASEPRI_PREEMPT - 2,
										swapin_thread, TRUE, TRUE);
}

/*
 *	thread_swapin: [exported]
 *
 *	Place the specified thread in the list of threads to swapin.  It
 *	is assumed that the thread is locked, therefore we are at splsched.
 *
 *	We don't bother with stack_alloc_try to optimize swapin;
 *	our callers have already tried that route.
 */

void
thread_swapin(
	register thread_t	thread)
{
	switch (thread->state & TH_STACK_STATE) {

	case TH_STACK_HANDOFF:
		/*
		 *	Swapped out - queue for swapin thread.
		 */
		thread->state = (thread->state & ~TH_STACK_STATE) | TH_STACK_ALLOC;
		swapin_lock();
		enqueue_tail(&swapin_queue, (queue_entry_t) thread);
		swapin_unlock();
		thread_wakeup((event_t) &swapin_queue);
		break;

	    case TH_STACK_ALLOC:
		/*
		 *	Already queued for swapin thread, or being
		 *	swapped in.
		 */
		break;

	    default:
		/*
		 *	Already swapped in.
		 */
		panic("thread_swapin");
	}
}

/*
 *	thread_doswapin:
 *
 *	Swapin the specified thread, if it should be runnable, then put
 *	it on a run queue.  No locks should be held on entry, as it is
 *	likely that this routine will sleep (waiting for stack allocation).
 */
void
thread_doswapin(
	register thread_t	thread)
{
	vm_offset_t		stack;
	spl_t			s;

	/*
	 *	Allocate the kernel stack.
	 */
	stack = stack_alloc(thread, thread_continue);
	assert(stack);

	/*
	 *	Place on run queue.  
	 */

	s = splsched();
	thread_lock(thread);
	thread->state &= ~(TH_STACK_HANDOFF | TH_STACK_ALLOC);
	if (thread->state & TH_RUN)
		thread_setrun(thread, TRUE, FALSE);
	thread_unlock(thread);
	(void) splx(s);
}

/*
 *	swapin_thread: [exported]
 *
 *	This procedure executes as a kernel thread.  Threads that need to
 *	be swapped in are swapped in by this thread.
 */
void
swapin_thread_continue(void)
{
	register thread_t	thread;

#if defined(__i386__)
loop:
#endif
	(void)splsched();
	swapin_lock();

	while ((thread = (thread_t)dequeue_head(&swapin_queue)) != THREAD_NULL) {
		swapin_unlock();
		(void)spllo();

		thread_doswapin(thread);

		(void)splsched();
		swapin_lock();
	}

	assert_wait((event_t) &swapin_queue, THREAD_UNINT);
	swapin_unlock();
	(void)spllo();

	counter(c_swapin_thread_block++);
#if defined (__i386__)
	thread_block((void (*)(void)) 0);
	goto loop;
#else
	thread_block(swapin_thread_continue);
#endif
	/*NOTREACHED*/
}

void
swapin_thread(void)
{
	thread_t	self = current_thread();

	stack_privilege(self);

	swapin_thread_continue();
	/*NOTREACHED*/
}

/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
 *	File:	kern/thread.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young, David Golub
 *	Date:	1986
 *
 *	Thread/thread_shuttle management primitives implementation.
 */
/*
 * Copyright (c) 1993 The University of Utah and
 * the Computer Systems Laboratory (CSL).  All rights reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * THE UNIVERSITY OF UTAH AND CSL ALLOW FREE USE OF THIS SOFTWARE IN ITS "AS
 * IS" CONDITION.  THE UNIVERSITY OF UTAH AND CSL DISCLAIM ANY LIABILITY OF
 * ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * CSL requests users of this software to return to csl-dist@cs.utah.edu any
 * improvements that they make and grant CSL redistribution rights.
 *
 */

#include <cpus.h>
#include <mach_host.h>
#include <simple_clock.h>
#include <mach_debug.h>
#include <mach_prof.h>

#include <mach/boolean.h>
#include <mach/policy.h>
#include <mach/thread_info.h>
#include <mach/thread_special_ports.h>
#include <mach/thread_status.h>
#include <mach/time_value.h>
#include <mach/vm_param.h>
#include <kern/ast.h>
#include <kern/cpu_data.h>
#include <kern/counters.h>
#include <kern/etap_macros.h>
#include <kern/ipc_mig.h>
#include <kern/ipc_tt.h>
#include <kern/mach_param.h>
#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/processor.h>
#include <kern/queue.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/mk_sp.h>	/*** ??? fix so this can be removed ***/
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/thread_act.h>
#include <kern/thread_swap.h>
#include <kern/host.h>
#include <kern/zalloc.h>
#include <vm/vm_kern.h>
#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_port.h>
#include <machine/thread.h>		/* for MACHINE_STACK */
#include <kern/profile.h>
#include <kern/assert.h>
#include <sys/kdebug.h>

/*
 * Exported interfaces
 */

#include <mach/thread_act_server.h>
#include <mach/mach_host_server.h>

/*
 * Per-Cpu stashed global state
 */
vm_offset_t			active_stacks[NCPUS];	/* per-cpu active stacks	*/
vm_offset_t			kernel_stack[NCPUS];	/* top of active stacks		*/
thread_act_t		active_kloaded[NCPUS];	/*  + act if kernel loaded	*/
boolean_t			first_thread;

struct zone			*thread_shuttle_zone;

queue_head_t		reaper_queue;
decl_simple_lock_data(,reaper_lock)

extern int		tick;

extern void		pcb_module_init(void);

struct thread_shuttle	pageout_thread;

/* private */
static struct thread_shuttle	thr_sh_template;

#if	MACH_DEBUG

#ifdef	MACHINE_STACK
extern void	stack_statistics(
			unsigned int	*totalp,
			vm_size_t	*maxusagep);
#endif	/* MACHINE_STACK */
#endif	/* MACH_DEBUG */

/* Forwards */
void		thread_collect_scan(void);

kern_return_t thread_create_shuttle(
	thread_act_t			thr_act,
	integer_t				priority,
	void					(*start)(void),
	thread_t				*new_thread);

extern void		Load_context(
	thread_t                thread);


/*
 *	Machine-dependent code must define:
 *		thread_machine_init
 *		thread_machine_terminate
 *		thread_machine_collect
 *
 *	The thread->pcb field is reserved for machine-dependent code.
 */

#ifdef	MACHINE_STACK
/*
 *	Machine-dependent code must define:
 *		stack_alloc_try
 *		stack_alloc
 *		stack_free
 *		stack_free_stack
 *		stack_collect
 *	and if MACH_DEBUG:
 *		stack_statistics
 */
#else	/* MACHINE_STACK */
/*
 *	We allocate stacks from generic kernel VM.
 *	Machine-dependent code must define:
 *		machine_kernel_stack_init
 *
 *	The stack_free_list can only be accessed at splsched,
 *	because stack_alloc_try/thread_invoke operate at splsched.
 */

decl_simple_lock_data(,stack_lock_data)         /* splsched only */
#define stack_lock()	simple_lock(&stack_lock_data)
#define stack_unlock()	simple_unlock(&stack_lock_data)

mutex_t stack_map_lock;				/* Lock when allocating stacks maps */
vm_map_t stack_map;					/* Map for allocating stacks */
vm_offset_t stack_free_list;		/* splsched only */
unsigned int stack_free_max = 0;
unsigned int stack_free_count = 0;	/* splsched only */
unsigned int stack_free_limit = 1;	/* Arbitrary  */

unsigned int stack_alloc_hits = 0;	/* debugging */
unsigned int stack_alloc_misses = 0;	/* debugging */

unsigned int stack_alloc_total = 0;
unsigned int stack_alloc_hiwater = 0;
unsigned int stack_alloc_bndry = 0;


/*
 *	The next field is at the base of the stack,
 *	so the low end is left unsullied.
 */

#define stack_next(stack) (*((vm_offset_t *)((stack) + KERNEL_STACK_SIZE) - 1))

/*
 *	stack_alloc:
 *
 *	Allocate a kernel stack for an activation.
 *	May block.
 */
vm_offset_t
stack_alloc(
	thread_t thread,
	void (*start_pos)(thread_t))
{
	vm_offset_t 	stack = thread->kernel_stack;
	spl_t			s;

	if (stack)
		return (stack);

/*
 *	We first try the free list.  It is probably empty, or
 *	stack_alloc_try would have succeeded, but possibly a stack was
 *	freed before the swapin thread got to us.
 *
 *	We allocate stacks from their own map which is submaps of the
 *	kernel map.  Because we want to have a guard page (at least) in
 *	front of each stack to catch evil code that overruns its stack, we
 *	allocate the stack on aligned boundaries.  The boundary is
 *	calculated as the next power of 2 above the stack size. For
 *	example, a stack of 4 pages would have a boundry of 8, likewise 5
 *	would also be 8.
 *
 *	We limit the number of stacks to be one allocation chunk
 *	(THREAD_CHUNK) more than the maximum number of threads
 *	(THREAD_MAX).  The extra is to allow for priviliged threads that
 *	can sometimes have 2 stacks.
 *
 */

	s = splsched();
	stack_lock();
	stack = stack_free_list;
	if (stack != 0) {
		stack_free_list = stack_next(stack);
		stack_free_count--;
	}
	stack_unlock();
	splx(s);

	if (stack != 0) {							/* Did we find a free one? */
		stack_attach(thread, stack, start_pos);	/* Initialize it */
		return (stack);							/* Send it on home */
	}
		
	if (kernel_memory_allocate(
					stack_map, &stack,
						KERNEL_STACK_SIZE, stack_alloc_bndry - 1,
										KMA_KOBJECT) != KERN_SUCCESS)
		panic("stack_alloc: no space left for stack maps");

	stack_alloc_total++;
	if (stack_alloc_total > stack_alloc_hiwater)
		stack_alloc_hiwater = stack_alloc_total;

	stack_attach(thread, stack, start_pos);
	return (stack);
}

/*
 *	stack_free:
 *
 *	Free a kernel stack.
 *	Called at splsched.
 */

void
stack_free(
	thread_t thread)
{
    vm_offset_t stack = stack_detach(thread);

	assert(stack);
	if (stack != thread->stack_privilege) {
		stack_lock();
		stack_next(stack) = stack_free_list;
		stack_free_list = stack;
		if (++stack_free_count > stack_free_max)
			stack_free_max = stack_free_count;
		stack_unlock();
	}
}

static void
stack_free_stack(
	vm_offset_t		stack)
{
	spl_t	s;

	s = splsched();
	stack_lock();
	stack_next(stack) = stack_free_list;
	stack_free_list = stack;
	if (++stack_free_count > stack_free_max)
		stack_free_max = stack_free_count;
	stack_unlock();
	splx(s);
}

/*
 *	stack_collect:
 *
 *	Free excess kernel stacks.
 *	May block.
 */

void
stack_collect(void)
{
	vm_offset_t	stack;
	int			i;
	spl_t		s;

	s = splsched();
	stack_lock();
	while (stack_free_count > stack_free_limit) {
		stack = stack_free_list;
		stack_free_list = stack_next(stack);
		stack_free_count--;
		stack_unlock();
		splx(s);

		if (vm_map_remove(
					stack_map, stack, stack + KERNEL_STACK_SIZE,
									VM_MAP_REMOVE_KUNWIRE) != KERN_SUCCESS)
			panic("stack_collect: vm_map_remove failed");

		s = splsched();
		stack_lock();
		stack_alloc_total--;
	}
	stack_unlock();
	splx(s);
}


#if	MACH_DEBUG
/*
 *	stack_statistics:
 *
 *	Return statistics on cached kernel stacks.
 *	*maxusagep must be initialized by the caller.
 */

void
stack_statistics(
	unsigned int	*totalp,
	vm_size_t	*maxusagep)
{
	spl_t	s;

	s = splsched();
	stack_lock();

	*totalp = stack_free_count;
	*maxusagep = 0;

	stack_unlock();
	splx(s);
}
#endif	/* MACH_DEBUG */

#endif	/* MACHINE_STACK */


stack_fake_zone_info(int *count, vm_size_t *cur_size, vm_size_t *max_size, vm_size_t *elem_size,
		     vm_size_t *alloc_size, int *collectable, int *exhaustable)
{
        *count      = stack_alloc_total - stack_free_count;
	*cur_size   = KERNEL_STACK_SIZE * stack_alloc_total;
	*max_size   = KERNEL_STACK_SIZE * stack_alloc_hiwater;
	*elem_size  = KERNEL_STACK_SIZE;
	*alloc_size = KERNEL_STACK_SIZE;
	*collectable = 1;
	*exhaustable = 0;
}


/*
 *	stack_privilege:
 *
 *	stack_alloc_try on this thread must always succeed.
 */

void
stack_privilege(
	register thread_t thread)
{
	/*
	 *	This implementation only works for the current thread.
	 */

	if (thread != current_thread())
		panic("stack_privilege");

	if (thread->stack_privilege == 0)
		thread->stack_privilege = current_stack();
}

/*
 *	stack_alloc_try:
 *
 *	Non-blocking attempt to allocate a kernel stack.
 *	Called at splsched with the thread locked.
 */

boolean_t stack_alloc_try(
	thread_t	thread,
	void		(*start_pos)(thread_t))
{
	register vm_offset_t stack = thread->stack_privilege;

	if (stack == 0) {
		stack_lock();

		stack = stack_free_list;
		if (stack != (vm_offset_t)0) {
			stack_free_list = stack_next(stack);
			stack_free_count--;
		}

		stack_unlock();
	}

	if (stack != 0) {
		stack_attach(thread, stack, start_pos);
		stack_alloc_hits++;

		return (TRUE);
	}
	else {
		stack_alloc_misses++;

		return (FALSE);
	}
}

uint64_t			max_unsafe_computation;
extern int			max_unsafe_quanta;

uint32_t			sched_safe_duration;

uint64_t			max_poll_computation;
extern int			max_poll_quanta;

uint32_t			std_quantum;
uint32_t			min_std_quantum;

uint32_t			max_rt_quantum;
uint32_t			min_rt_quantum;

void
thread_init(void)
{
	kern_return_t ret;
	unsigned int stack;
	
	thread_shuttle_zone = zinit(
			sizeof(struct thread_shuttle),
			THREAD_MAX * sizeof(struct thread_shuttle),
			THREAD_CHUNK * sizeof(struct thread_shuttle),
			"threads");

	/*
	 *	Fill in a template thread_shuttle for fast initialization.
	 *	[Fields that must be (or are typically) reset at
	 *	time of creation are so noted.]
	 */

	/* thr_sh_template.links (none) */
	thr_sh_template.runq = RUN_QUEUE_NULL;


	/* thr_sh_template.task (later) */
	/* thr_sh_template.thread_list (later) */
	/* thr_sh_template.pset_threads (later) */

	/* reference for activation */
	thr_sh_template.ref_count = 1;

	thr_sh_template.reason = AST_NONE;
	thr_sh_template.at_safe_point = FALSE;
	thr_sh_template.wait_event = NO_EVENT64;
	thr_sh_template.wait_queue = WAIT_QUEUE_NULL;
	thr_sh_template.wait_result = THREAD_WAITING;
	thr_sh_template.interrupt_level = THREAD_ABORTSAFE;
	thr_sh_template.state = TH_STACK_HANDOFF | TH_WAIT | TH_UNINT;
	thr_sh_template.wake_active = FALSE;
	thr_sh_template.active_callout = FALSE;
	thr_sh_template.continuation = (void (*)(void))0;
	thr_sh_template.top_act = THR_ACT_NULL;

	thr_sh_template.importance = 0;
	thr_sh_template.sched_mode = 0;
	thr_sh_template.safe_mode = 0;

	thr_sh_template.priority = 0;
	thr_sh_template.sched_pri = 0;
	thr_sh_template.max_priority = 0;
	thr_sh_template.task_priority = 0;
	thr_sh_template.promotions = 0;
	thr_sh_template.pending_promoter_index = 0;
	thr_sh_template.pending_promoter[0] =
		thr_sh_template.pending_promoter[1] = NULL;

	thr_sh_template.current_quantum = 0;

	thr_sh_template.computation_metered = 0;
	thr_sh_template.computation_epoch = 0;

	thr_sh_template.cpu_usage = 0;
	thr_sh_template.cpu_delta = 0;
	thr_sh_template.sched_usage = 0;
	thr_sh_template.sched_delta = 0;
	thr_sh_template.sched_stamp = 0;
	thr_sh_template.sleep_stamp = 0;
	thr_sh_template.safe_release = 0;

	thr_sh_template.bound_processor = PROCESSOR_NULL;
	thr_sh_template.last_processor = PROCESSOR_NULL;
	thr_sh_template.last_switch = 0;

	thr_sh_template.vm_privilege = FALSE;

	timer_init(&(thr_sh_template.user_timer));
	timer_init(&(thr_sh_template.system_timer));
	thr_sh_template.user_timer_save.low = 0;
	thr_sh_template.user_timer_save.high = 0;
	thr_sh_template.system_timer_save.low = 0;
	thr_sh_template.system_timer_save.high = 0;

	thr_sh_template.active = FALSE; /* reset */

	thr_sh_template.processor_set = PROCESSOR_SET_NULL;
#if	MACH_HOST
	thr_sh_template.may_assign = TRUE;
	thr_sh_template.assign_active = FALSE;
#endif	/* MACH_HOST */
	thr_sh_template.funnel_state = 0;

	/*
	 *	Initialize other data structures used in
	 *	this module.
	 */

	queue_init(&reaper_queue);
	simple_lock_init(&reaper_lock, ETAP_THREAD_REAPER);
    thr_sh_template.funnel_lock = THR_FUNNEL_NULL;

#ifndef MACHINE_STACK
	simple_lock_init(&stack_lock_data, ETAP_THREAD_STACK);	/* Initialize the stack lock */
	
	if (KERNEL_STACK_SIZE < round_page_32(KERNEL_STACK_SIZE)) {	/* Kernel stacks must be multiples of pages */
		panic("thread_init: kernel stack size (%08X) must be a multiple of page size (%08X)\n", 
			KERNEL_STACK_SIZE, PAGE_SIZE);
	}
	
	for(stack_alloc_bndry = PAGE_SIZE; stack_alloc_bndry <= KERNEL_STACK_SIZE; stack_alloc_bndry <<= 1);	/* Find next power of 2 above stack size */

	ret = kmem_suballoc(kernel_map, 		/* Suballocate from the kernel map */

		&stack,
		(stack_alloc_bndry * (2*THREAD_MAX + 64)),	/* Allocate enough for all of it */
		FALSE,								/* Say not pageable so that it is wired */
		TRUE,								/* Allocate from anywhere */
		&stack_map);						/* Allocate a submap */
		
	if(ret != KERN_SUCCESS) {				/* Did we get one? */
		panic("thread_init: kmem_suballoc for stacks failed - ret = %d\n", ret);	/* Die */
	}	
	stack = vm_map_min(stack_map);			/* Make sure we skip the first hunk */
	ret = vm_map_enter(stack_map, &stack, PAGE_SIZE, 0,	/* Make sure there is nothing at the start */
		0, 									/* Force it at start */
		VM_OBJECT_NULL, 0, 					/* No object yet */
		FALSE,								/* No copy */
		VM_PROT_NONE,						/* Allow no access */
		VM_PROT_NONE,						/* Allow no access */
		VM_INHERIT_DEFAULT);				/* Just be normal */
		
	if(ret != KERN_SUCCESS) {					/* Did it work? */
		panic("thread_init: dummy alignment allocation failed; ret = %d\n", ret);
	}
		
#endif  /* MACHINE_STACK */

#if	MACH_LDEBUG
	thr_sh_template.mutex_count = 0;
#endif	/* MACH_LDEBUG */

	{
		uint64_t			abstime;

		clock_interval_to_absolutetime_interval(
							std_quantum_us, NSEC_PER_USEC, &abstime);
		assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
		std_quantum = abstime;

		/* 250 us */
		clock_interval_to_absolutetime_interval(250, NSEC_PER_USEC, &abstime);
		assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
		min_std_quantum = abstime;

		/* 50 us */
		clock_interval_to_absolutetime_interval(50, NSEC_PER_USEC, &abstime);
		assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
		min_rt_quantum = abstime;

		/* 50 ms */
		clock_interval_to_absolutetime_interval(
										50, 1000*NSEC_PER_USEC, &abstime);
		assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
		max_rt_quantum = abstime;

		max_unsafe_computation = max_unsafe_quanta * std_quantum;
		max_poll_computation = max_poll_quanta * std_quantum;

		sched_safe_duration = 2 * max_unsafe_quanta *
										(std_quantum_us / (1000 * 1000)) *
												(1 << SCHED_TICK_SHIFT);
	}

	first_thread = TRUE;
	/*
	 *	Initialize any machine-dependent
	 *	per-thread structures necessary.
	 */
	thread_machine_init();
}

/*
 * Called at splsched.
 */
void
thread_reaper_enqueue(
	thread_t		thread)
{
	simple_lock(&reaper_lock);
	enqueue_tail(&reaper_queue, (queue_entry_t)thread);
	simple_unlock(&reaper_lock);

	thread_wakeup((event_t)&reaper_queue);
}

void
thread_termination_continue(void)
{
	panic("thread_termination_continue");
	/*NOTREACHED*/
}

/*
 *	Routine: thread_terminate_self
 *
 *		This routine is called by a thread which has unwound from
 *		its current RPC and kernel contexts and found that it's
 *		root activation has been marked for extinction.  This lets
 *		it clean up the last few things that can only be cleaned
 *		up in this context and then impale itself on the reaper
 *		queue.
 *
 *		When the reaper gets the thread, it will deallocate the
 *		thread_act's reference on itself, which in turn will release
 *		its own reference on this thread. By doing things in that
 *		order, a thread_act will always have a valid thread - but the
 *		thread may persist beyond having a thread_act (but must never
 *		run like that).
 */
void
thread_terminate_self(void)
{
	thread_act_t	thr_act = current_act();
	thread_t		thread;
	task_t			task = thr_act->task;
	long			active_acts;
	spl_t			s;

	/*
	 * We should be at the base of the inheritance chain.
	 */
	thread = act_lock_thread(thr_act);
	assert(thr_act->thread == thread);

	/* This will allow no more control ops on this thr_act. */
	ipc_thr_act_disable(thr_act);

	/* Clean-up any ulocks that are still owned by the thread
	 * activation (acquired but not released or handed-off).
	 */
	act_ulock_release_all(thr_act);
	
	act_unlock_thread(thr_act);

	_mk_sp_thread_depress_abort(thread, TRUE);

	/*
	 * Check to see if this is the last active activation.  By
	 * this we mean the last activation to call thread_terminate_self.
	 * If so, and the task is associated with a BSD process, we
	 * need to call BSD and let them clean up.
	 */
	active_acts = hw_atomic_sub(&task->active_act_count, 1);

	if (active_acts == 0 && task->bsd_info)
		proc_exit(task->bsd_info);

	/* JMM - for now, no migration */
	assert(!thr_act->lower);

	s = splsched();
	thread_lock(thread);
	thread->active = FALSE;
	thread_unlock(thread);
	splx(s);

	thread_timer_terminate();

	/* flush any lazy HW state while in own context */
	thread_machine_flush(thr_act);

	ipc_thread_terminate(thread);

	s = splsched();
	thread_lock(thread);
	thread->state |= TH_TERMINATE;
	assert((thread->state & TH_UNINT) == 0);
	thread_mark_wait_locked(thread, THREAD_UNINT);
	assert(thread->promotions == 0);
	thread_unlock(thread);
	/* splx(s); */

	ETAP_SET_REASON(thread, BLOCKED_ON_TERMINATION);
	thread_block(thread_termination_continue);
	/*NOTREACHED*/
}

/*
 * Create a new thread.
 * Doesn't start the thread running; It first must be attached to
 * an activation - then use thread_go to start it.
 */
kern_return_t
thread_create_shuttle(
	thread_act_t			thr_act,
	integer_t				priority,
	void					(*start)(void),
	thread_t				*new_thread)
{
	kern_return_t			result;
	thread_t				new_shuttle;
	task_t					parent_task = thr_act->task;
	processor_set_t			pset;

	/*
	 *	Allocate a thread and initialize static fields
	 */
	if (first_thread) {
		new_shuttle = &pageout_thread;
		first_thread = FALSE;
	} else
		new_shuttle = (thread_t)zalloc(thread_shuttle_zone);
	if (new_shuttle == THREAD_NULL)
		return (KERN_RESOURCE_SHORTAGE);

#ifdef  DEBUG
	if (new_shuttle != &pageout_thread)
		assert(!thr_act->thread);
#endif

	*new_shuttle = thr_sh_template;

	thread_lock_init(new_shuttle);
	wake_lock_init(new_shuttle);
	new_shuttle->sleep_stamp = sched_tick;

	/*
	 *	Thread still isn't runnable yet (our caller will do
	 *	that).  Initialize runtime-dependent fields here.
	 */
	result = thread_machine_create(new_shuttle, thr_act, thread_continue);
	assert (result == KERN_SUCCESS);

	thread_start(new_shuttle, start);
	thread_timer_setup(new_shuttle);
	ipc_thread_init(new_shuttle);

	pset = parent_task->processor_set;
	assert(pset == &default_pset);
	pset_lock(pset);

	task_lock(parent_task);
	assert(parent_task->processor_set == pset);

	/*
	 *	Don't need to initialize because the context switch
	 *	code will set it before it can be used.
	 */
	if (!parent_task->active) {
		task_unlock(parent_task);
		pset_unlock(pset);
		thread_machine_destroy(new_shuttle);
		zfree(thread_shuttle_zone, (vm_offset_t) new_shuttle);
		return (KERN_FAILURE);
	}

	act_attach(thr_act, new_shuttle, 0);

	/* Chain the thr_act onto the task's list */
	queue_enter(&parent_task->thr_acts, thr_act, thread_act_t, thr_acts);
	parent_task->thr_act_count++;
	parent_task->res_act_count++;
	
	/* So terminating threads don't need to take the task lock to decrement */
	hw_atomic_add(&parent_task->active_act_count, 1);

	/* Associate the thread with the processor set */
	pset_add_thread(pset, new_shuttle);

	/* Set the thread's scheduling parameters */
	if (parent_task != kernel_task)
		new_shuttle->sched_mode |= TH_MODE_TIMESHARE;
	new_shuttle->max_priority = parent_task->max_priority;
	new_shuttle->task_priority = parent_task->priority;
	new_shuttle->priority = (priority < 0)? parent_task->priority: priority;
	if (new_shuttle->priority > new_shuttle->max_priority)
		new_shuttle->priority = new_shuttle->max_priority;
	new_shuttle->importance =
					new_shuttle->priority - new_shuttle->task_priority;
	new_shuttle->sched_stamp = sched_tick;
	compute_priority(new_shuttle, FALSE);

#if	ETAP_EVENT_MONITOR
	new_thread->etap_reason = 0;
	new_thread->etap_trace  = FALSE;
#endif	/* ETAP_EVENT_MONITOR */

	new_shuttle->active = TRUE;
	thr_act->active = TRUE;

	*new_thread = new_shuttle;

	{
		long	dbg_arg1, dbg_arg2, dbg_arg3, dbg_arg4;

		KERNEL_DEBUG_CONSTANT(
					TRACEDBG_CODE(DBG_TRACE_DATA, 1) | DBG_FUNC_NONE,
							(vm_address_t)new_shuttle, 0, 0, 0, 0);

		kdbg_trace_string(parent_task->bsd_info,
							&dbg_arg1, &dbg_arg2, &dbg_arg3, &dbg_arg4);

		KERNEL_DEBUG_CONSTANT(
					TRACEDBG_CODE(DBG_TRACE_STRING, 1) | DBG_FUNC_NONE,
							dbg_arg1, dbg_arg2, dbg_arg3, dbg_arg4, 0);
	}

	return (KERN_SUCCESS);
}

extern void			thread_bootstrap_return(void);

kern_return_t
thread_create(
	task_t				task,
	thread_act_t		*new_act)
{
	kern_return_t		result;
	thread_t			thread;
	thread_act_t		act;

	if (task == TASK_NULL)
		return KERN_INVALID_ARGUMENT;

	result = act_create(task, &act);
	if (result != KERN_SUCCESS)
		return (result);

	result = thread_create_shuttle(act, -1, thread_bootstrap_return, &thread);
	if (result != KERN_SUCCESS) {
		act_deallocate(act);
		return (result);
	}

	act->user_stop_count = 1;
	thread_hold(act);
	if (task->suspend_count > 0)
		thread_hold(act);

	pset_unlock(task->processor_set);
	task_unlock(task);
	
	*new_act = act;

	return (KERN_SUCCESS);
}

kern_return_t
thread_create_running(
	register task_t         task,
	int                     flavor,
	thread_state_t          new_state,
	mach_msg_type_number_t  new_state_count,
	thread_act_t			*new_act)			/* OUT */
{
	register kern_return_t  result;
	thread_t				thread;
	thread_act_t			act;

	if (task == TASK_NULL)
		return KERN_INVALID_ARGUMENT;

	result = act_create(task, &act);
	if (result != KERN_SUCCESS)
		return (result);

	result = thread_create_shuttle(act, -1, thread_bootstrap_return, &thread);
	if (result != KERN_SUCCESS) {
		act_deallocate(act);
		return (result);
	}

	act_lock(act);
	result = act_machine_set_state(act, flavor, new_state, new_state_count);
	if (result != KERN_SUCCESS) {
		act_unlock(act);
		pset_unlock(task->processor_set);
		task_unlock(task);

		(void)thread_terminate(act);
		return (result);
	}

	clear_wait(thread, THREAD_AWAKENED);
	act->inited = TRUE;
	act_unlock(act);
	pset_unlock(task->processor_set);
	task_unlock(task);

	*new_act = act;

	return (result);
}

/*
 *	kernel_thread:
 *
 *	Create and kernel thread in the specified task, and
 *	optionally start it running.
 */
thread_t
kernel_thread_with_priority(
	task_t				task,
	integer_t			priority,
	void				(*start)(void),
	boolean_t			alloc_stack,
	boolean_t			start_running)
{
	kern_return_t		result;
	thread_t			thread;
	thread_act_t		act;

	result = act_create(task, &act);
	if (result != KERN_SUCCESS)
		return (THREAD_NULL);

	result = thread_create_shuttle(act, priority, start, &thread);
	if (result != KERN_SUCCESS) {
		act_deallocate(act);
		return (THREAD_NULL);
	}

	pset_unlock(task->processor_set);
	task_unlock(task);

	if (alloc_stack)
		thread_doswapin(thread);

	act_lock(act);
	if (start_running)
		clear_wait(thread, THREAD_AWAKENED);
	act->inited = TRUE;
	act_unlock(act);

	act_deallocate(act);

	return (thread);
}

thread_t
kernel_thread(
	task_t			task,
	void			(*start)(void))
{
	return kernel_thread_with_priority(task, -1, start, FALSE, TRUE);
}

unsigned int c_weird_pset_ref_exit = 0;	/* pset code raced us */

#if	MACH_HOST
/* Preclude thread processor set assignement */
#define thread_freeze(thread) 	assert((thread)->processor_set == &default_pset)

/* Allow thread processor set assignement */
#define thread_unfreeze(thread)	assert((thread)->processor_set == &default_pset)

#endif	/* MACH_HOST */

void
thread_deallocate(
	thread_t			thread)
{
	task_t				task;
	processor_set_t		pset;
	int					refs;
	spl_t				s;

	if (thread == THREAD_NULL)
		return;

	/*
	 *	First, check for new count > 0 (the common case).
	 *	Only the thread needs to be locked.
	 */
	s = splsched();
	thread_lock(thread);
	refs = --thread->ref_count;
	thread_unlock(thread);
	splx(s);

	if (refs > 0)
		return;

	if (thread == current_thread())
	    panic("thread deallocating itself");

	/*
	 *	There is a dangling pointer to the thread from the
	 *	processor_set.  To clean it up, we freeze the thread
	 *	in the pset (because pset destruction can cause even
	 *	reference-less threads to be reassigned to the default
	 *	pset) and then remove it.
	 */

#if MACH_HOST
	thread_freeze(thread);
#endif

	pset = thread->processor_set;
	pset_lock(pset);
	pset_remove_thread(pset, thread);
	pset_unlock(pset);

#if MACH_HOST
	thread_unfreeze(thread);
#endif

	pset_deallocate(pset);

	if (thread->stack_privilege != 0) {
		if (thread->stack_privilege != thread->kernel_stack)
			stack_free_stack(thread->stack_privilege);
		thread->stack_privilege = 0;
	}
	/* frees kernel stack & other MD resources */
	thread_machine_destroy(thread);

	zfree(thread_shuttle_zone, (vm_offset_t) thread);
}

void
thread_reference(
	thread_t	thread)
{
	spl_t		s;

	if (thread == THREAD_NULL)
		return;

	s = splsched();
	thread_lock(thread);
	thread_reference_locked(thread);
	thread_unlock(thread);
	splx(s);
}

/*
 * Called with "appropriate" thread-related locks held on
 * thread and its top_act for synchrony with RPC (see
 * act_lock_thread()).
 */
kern_return_t
thread_info_shuttle(
	register thread_act_t	thr_act,
	thread_flavor_t			flavor,
	thread_info_t			thread_info_out,	/* ptr to OUT array */
	mach_msg_type_number_t	*thread_info_count)	/*IN/OUT*/
{
	register thread_t		thread = thr_act->thread;
	int						state, flags;
	spl_t					s;

	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	if (flavor == THREAD_BASIC_INFO) {
	    register thread_basic_info_t	basic_info;

	    if (*thread_info_count < THREAD_BASIC_INFO_COUNT)
			return (KERN_INVALID_ARGUMENT);

	    basic_info = (thread_basic_info_t) thread_info_out;

	    s = splsched();
	    thread_lock(thread);

	    /* fill in info */

	    thread_read_times(thread, &basic_info->user_time,
									&basic_info->system_time);

		/*
		 *	Update lazy-evaluated scheduler info because someone wants it.
		 */
		if (thread->sched_stamp != sched_tick)
			update_priority(thread);

		basic_info->sleep_time = 0;

		/*
		 *	To calculate cpu_usage, first correct for timer rate,
		 *	then for 5/8 ageing.  The correction factor [3/5] is
		 *	(1/(5/8) - 1).
		 */
		basic_info->cpu_usage = (thread->cpu_usage << SCHED_TICK_SHIFT) /
												(TIMER_RATE / TH_USAGE_SCALE);
		basic_info->cpu_usage = (basic_info->cpu_usage * 3) / 5;
#if	SIMPLE_CLOCK
		/*
		 *	Clock drift compensation.
		 */
		basic_info->cpu_usage = (basic_info->cpu_usage * 1000000) / sched_usec;
#endif	/* SIMPLE_CLOCK */

		basic_info->policy = ((thread->sched_mode & TH_MODE_TIMESHARE)?
												POLICY_TIMESHARE: POLICY_RR);

	    flags = 0;
		if (thread->state & TH_IDLE)
			flags |= TH_FLAGS_IDLE;

	    if (thread->state & TH_STACK_HANDOFF)
			flags |= TH_FLAGS_SWAPPED;

	    state = 0;
	    if (thread->state & TH_TERMINATE)
			state = TH_STATE_HALTED;
	    else
		if (thread->state & TH_RUN)
			state = TH_STATE_RUNNING;
	    else
		if (thread->state & TH_UNINT)
			state = TH_STATE_UNINTERRUPTIBLE;
	    else
		if (thread->state & TH_SUSP)
			state = TH_STATE_STOPPED;
	    else
		if (thread->state & TH_WAIT)
			state = TH_STATE_WAITING;

	    basic_info->run_state = state;
	    basic_info->flags = flags;

	    basic_info->suspend_count = thr_act->user_stop_count;

	    thread_unlock(thread);
	    splx(s);

	    *thread_info_count = THREAD_BASIC_INFO_COUNT;

	    return (KERN_SUCCESS);
	}
	else
	if (flavor == THREAD_SCHED_TIMESHARE_INFO) {
		policy_timeshare_info_t		ts_info;

		if (*thread_info_count < POLICY_TIMESHARE_INFO_COUNT)
			return (KERN_INVALID_ARGUMENT);

		ts_info = (policy_timeshare_info_t)thread_info_out;

	    s = splsched();
		thread_lock(thread);

	    if (!(thread->sched_mode & TH_MODE_TIMESHARE)) {
	    	thread_unlock(thread);
			splx(s);

			return (KERN_INVALID_POLICY);
	    }

		ts_info->depressed = (thread->sched_mode & TH_MODE_ISDEPRESSED) != 0;
		if (ts_info->depressed) {
			ts_info->base_priority = DEPRESSPRI;
			ts_info->depress_priority = thread->priority;
		}
		else {
			ts_info->base_priority = thread->priority;
			ts_info->depress_priority = -1;
		}

		ts_info->cur_priority = thread->sched_pri;
		ts_info->max_priority =	thread->max_priority;

		thread_unlock(thread);
	    splx(s);

		*thread_info_count = POLICY_TIMESHARE_INFO_COUNT;

		return (KERN_SUCCESS);	
	}
	else
	if (flavor == THREAD_SCHED_FIFO_INFO) {
		if (*thread_info_count < POLICY_FIFO_INFO_COUNT)
			return (KERN_INVALID_ARGUMENT);

		return (KERN_INVALID_POLICY);
	}
	else
	if (flavor == THREAD_SCHED_RR_INFO) {
		policy_rr_info_t			rr_info;

		if (*thread_info_count < POLICY_RR_INFO_COUNT)
			return (KERN_INVALID_ARGUMENT);

		rr_info = (policy_rr_info_t) thread_info_out;

	    s = splsched();
		thread_lock(thread);

	    if (thread->sched_mode & TH_MODE_TIMESHARE) {
	    	thread_unlock(thread);
			splx(s);

			return (KERN_INVALID_POLICY);
	    }

		rr_info->depressed = (thread->sched_mode & TH_MODE_ISDEPRESSED) != 0;
		if (rr_info->depressed) {
			rr_info->base_priority = DEPRESSPRI;
			rr_info->depress_priority = thread->priority;
		}
		else {
			rr_info->base_priority = thread->priority;
			rr_info->depress_priority = -1;
		}

		rr_info->max_priority = thread->max_priority;
	    rr_info->quantum = std_quantum_us / 1000;

		thread_unlock(thread);
	    splx(s);

		*thread_info_count = POLICY_RR_INFO_COUNT;

		return (KERN_SUCCESS);	
	}

	return (KERN_INVALID_ARGUMENT);
}

void
thread_doreap(
	register thread_t	thread)
{
	thread_act_t		thr_act;


	thr_act = thread_lock_act(thread);
	assert(thr_act && thr_act->thread == thread);

	act_locked_act_reference(thr_act);

	/*
	 * Replace `act_unlock_thread()' with individual
	 * calls.  (`act_detach()' can change fields used
	 * to determine which locks are held, confusing
	 * `act_unlock_thread()'.)
	 */
	act_unlock(thr_act);

	/* Remove the reference held by a rooted thread */
	act_deallocate(thr_act);

	/* Remove the reference held by the thread: */
	act_deallocate(thr_act);
}

/*
 *	reaper_thread:
 *
 *	This kernel thread runs forever looking for terminating
 *	threads, releasing their "self" references.
 */
static void
reaper_thread_continue(void)
{
	register thread_t	thread;

	(void)splsched();
	simple_lock(&reaper_lock);

	while ((thread = (thread_t) dequeue_head(&reaper_queue)) != THREAD_NULL) {
		simple_unlock(&reaper_lock);
		(void)spllo();

		thread_doreap(thread);

		(void)splsched();
		simple_lock(&reaper_lock);
	}

	assert_wait((event_t)&reaper_queue, THREAD_UNINT);
	simple_unlock(&reaper_lock);
	(void)spllo();

	thread_block(reaper_thread_continue);
	/*NOTREACHED*/
}

static void
reaper_thread(void)
{
	thread_t	self = current_thread();

	stack_privilege(self);

	reaper_thread_continue();
	/*NOTREACHED*/
}

void
thread_reaper_init(void)
{
	kernel_thread(kernel_task, reaper_thread);
}

kern_return_t
thread_assign(
	thread_act_t	thr_act,
	processor_set_t	new_pset)
{
	return(KERN_FAILURE);
}

/*
 *	thread_assign_default:
 *
 *	Special version of thread_assign for assigning threads to default
 *	processor set.
 */
kern_return_t
thread_assign_default(
	thread_act_t	thr_act)
{
	return (thread_assign(thr_act, &default_pset));
}

/*
 *	thread_get_assignment
 *
 *	Return current assignment for this thread.
 */	    
kern_return_t
thread_get_assignment(
	thread_act_t	thr_act,
	processor_set_t	*pset)
{
	thread_t	thread;

	if (thr_act == THR_ACT_NULL)
		return(KERN_INVALID_ARGUMENT);
	thread = act_lock_thread(thr_act);
	if (thread == THREAD_NULL) {
		act_unlock_thread(thr_act);
		return(KERN_INVALID_ARGUMENT);
	}
	*pset = thread->processor_set;
	act_unlock_thread(thr_act);
	pset_reference(*pset);
	return(KERN_SUCCESS);
}

/*
 *	thread_wire:
 *
 *	Specify that the target thread must always be able
 *	to run and to allocate memory.
 */
kern_return_t
thread_wire(
	host_priv_t	host_priv,
	thread_act_t	thr_act,
	boolean_t	wired)
{
	spl_t		s;
	thread_t	thread;
	extern void vm_page_free_reserve(int pages);

	if (thr_act == THR_ACT_NULL || host_priv == HOST_PRIV_NULL)
		return (KERN_INVALID_ARGUMENT);

	assert(host_priv == &realhost);

	thread = act_lock_thread(thr_act);
	if (thread ==THREAD_NULL) {
		act_unlock_thread(thr_act);
		return(KERN_INVALID_ARGUMENT);
	}

	/*
	 * This implementation only works for the current thread.
	 * See stack_privilege.
	 */
	if (thr_act != current_act())
	    return KERN_INVALID_ARGUMENT;

	s = splsched();
	thread_lock(thread);

	if (wired) {
	    if (thread->vm_privilege == FALSE) 
		    vm_page_free_reserve(1);	/* XXX */
	    thread->vm_privilege = TRUE;
	} else {
	    if (thread->vm_privilege == TRUE) 
		    vm_page_free_reserve(-1);	/* XXX */
	    thread->vm_privilege = FALSE;
	}

	thread_unlock(thread);
	splx(s);
	act_unlock_thread(thr_act);

	return KERN_SUCCESS;
}

/*
 *	thread_collect_scan:
 *
 *	Attempt to free resources owned by threads.
 */

void
thread_collect_scan(void)
{
	/* This code runs very quickly! */
}

/* Also disabled in vm/vm_pageout.c */
boolean_t thread_collect_allowed = FALSE;
unsigned thread_collect_last_tick = 0;
unsigned thread_collect_max_rate = 0;		/* in ticks */

/*
 *	consider_thread_collect:
 *
 *	Called by the pageout daemon when the system needs more free pages.
 */

void
consider_thread_collect(void)
{
	/*
	 *	By default, don't attempt thread collection more frequently
	 *	than once a second.
	 */

	if (thread_collect_max_rate == 0)
		thread_collect_max_rate = (1 << SCHED_TICK_SHIFT) + 1;

	if (thread_collect_allowed &&
	    (sched_tick >
	     (thread_collect_last_tick + thread_collect_max_rate))) {
		thread_collect_last_tick = sched_tick;
		thread_collect_scan();
	}
}

kern_return_t
host_stack_usage(
	host_t		host,
	vm_size_t	*reservedp,
	unsigned int	*totalp,
	vm_size_t	*spacep,
	vm_size_t	*residentp,
	vm_size_t	*maxusagep,
	vm_offset_t	*maxstackp)
{
#if !MACH_DEBUG
        return KERN_NOT_SUPPORTED;
#else
	unsigned int total;
	vm_size_t maxusage;

	if (host == HOST_NULL)
		return KERN_INVALID_HOST;

	maxusage = 0;

	stack_statistics(&total, &maxusage);

	*reservedp = 0;
	*totalp = total;
	*spacep = *residentp = total * round_page_32(KERNEL_STACK_SIZE);
	*maxusagep = maxusage;
	*maxstackp = 0;
	return KERN_SUCCESS;

#endif /* MACH_DEBUG */
}

/*
 * Return info on stack usage for threads in a specific processor set
 */
kern_return_t
processor_set_stack_usage(
	processor_set_t	pset,
	unsigned int	*totalp,
	vm_size_t	*spacep,
	vm_size_t	*residentp,
	vm_size_t	*maxusagep,
	vm_offset_t	*maxstackp)
{
#if !MACH_DEBUG
        return KERN_NOT_SUPPORTED;
#else
	unsigned int total;
	vm_size_t maxusage;
	vm_offset_t maxstack;

	register thread_t *threads;
	register thread_t thread;

	unsigned int actual;	/* this many things */
	unsigned int i;

	vm_size_t size, size_needed;
	vm_offset_t addr;

	spl_t s;

	if (pset == PROCESSOR_SET_NULL)
		return KERN_INVALID_ARGUMENT;

	size = 0; addr = 0;

	for (;;) {
		pset_lock(pset);
		if (!pset->active) {
			pset_unlock(pset);
			return KERN_INVALID_ARGUMENT;
		}

		actual = pset->thread_count;

		/* do we have the memory we need? */

		size_needed = actual * sizeof(thread_t);
		if (size_needed <= size)
			break;

		/* unlock the pset and allocate more memory */
		pset_unlock(pset);

		if (size != 0)
			kfree(addr, size);

		assert(size_needed > 0);
		size = size_needed;

		addr = kalloc(size);
		if (addr == 0)
			return KERN_RESOURCE_SHORTAGE;
	}

	/* OK, have memory and the processor_set is locked & active */
	s = splsched();
	threads = (thread_t *) addr;
	for (i = 0, thread = (thread_t) queue_first(&pset->threads);
	     !queue_end(&pset->threads, (queue_entry_t) thread);
	     thread = (thread_t) queue_next(&thread->pset_threads)) {
		thread_lock(thread);
		if (thread->ref_count > 0) {
			thread_reference_locked(thread);
			threads[i++] = thread;
		}
		thread_unlock(thread);
	}
	splx(s);
	assert(i <= actual);

	/* can unlock processor set now that we have the thread refs */
	pset_unlock(pset);

	/* calculate maxusage and free thread references */

	total = 0;
	maxusage = 0;
	maxstack = 0;
	while (i > 0) {
		int cpu;
		thread_t thread = threads[--i];
		vm_offset_t stack = 0;

		/*
		 *	thread->kernel_stack is only accurate if the
		 *	thread isn't swapped and is not executing.
		 *
		 *	Of course, we don't have the appropriate locks
		 *	for these shenanigans.
		 */

		stack = thread->kernel_stack;

		for (cpu = 0; cpu < NCPUS; cpu++)
			if (cpu_to_processor(cpu)->cpu_data->active_thread == thread) {
				stack = active_stacks[cpu];
				break;
			}

		if (stack != 0) {
			total++;
		}

		thread_deallocate(thread);
	}

	if (size != 0)
		kfree(addr, size);

	*totalp = total;
	*residentp = *spacep = total * round_page_32(KERNEL_STACK_SIZE);
	*maxusagep = maxusage;
	*maxstackp = maxstack;
	return KERN_SUCCESS;

#endif	/* MACH_DEBUG */
}

int split_funnel_off = 0;
funnel_t *
funnel_alloc(
	int type)
{
	mutex_t *m;
	funnel_t * fnl;
	if ((fnl = (funnel_t *)kalloc(sizeof(funnel_t))) != 0){
		bzero((void *)fnl, sizeof(funnel_t));
		if ((m = mutex_alloc(0)) == (mutex_t *)NULL) {
			kfree((vm_offset_t)fnl, sizeof(funnel_t));
			return(THR_FUNNEL_NULL);
		}
		fnl->fnl_mutex = m;
		fnl->fnl_type = type;
	}
	return(fnl);
}

void 
funnel_free(
	funnel_t * fnl)
{
	mutex_free(fnl->fnl_mutex);
	if (fnl->fnl_oldmutex)
		mutex_free(fnl->fnl_oldmutex);
	kfree((vm_offset_t)fnl, sizeof(funnel_t));
}

void 
funnel_lock(
	funnel_t * fnl)
{
	mutex_t * m;

	m = fnl->fnl_mutex;
restart:
	mutex_lock(m);
	fnl->fnl_mtxholder = current_thread();
	if (split_funnel_off && (m != fnl->fnl_mutex)) {
		mutex_unlock(m);
		m = fnl->fnl_mutex;	
		goto restart;
	}
}

void 
funnel_unlock(
	funnel_t * fnl)
{
	mutex_unlock(fnl->fnl_mutex);
	fnl->fnl_mtxrelease = current_thread();
}

funnel_t *
thread_funnel_get(
	void)
{
	thread_t th = current_thread();

	if (th->funnel_state & TH_FN_OWNED) {
		return(th->funnel_lock);
	}
	return(THR_FUNNEL_NULL);
}

boolean_t
thread_funnel_set(
        funnel_t *	fnl,
	boolean_t	funneled)
{
	thread_t	cur_thread;
	boolean_t	funnel_state_prev;
	boolean_t	intr;
        
	cur_thread = current_thread();
	funnel_state_prev = ((cur_thread->funnel_state & TH_FN_OWNED) == TH_FN_OWNED);

	if (funnel_state_prev != funneled) {
		intr = ml_set_interrupts_enabled(FALSE);

		if (funneled == TRUE) {
			if (cur_thread->funnel_lock)
				panic("Funnel lock called when holding one %x", cur_thread->funnel_lock);
			KERNEL_DEBUG(0x6032428 | DBG_FUNC_NONE,
											fnl, 1, 0, 0, 0);
			funnel_lock(fnl);
			KERNEL_DEBUG(0x6032434 | DBG_FUNC_NONE,
											fnl, 1, 0, 0, 0);
			cur_thread->funnel_state |= TH_FN_OWNED;
			cur_thread->funnel_lock = fnl;
		} else {
			if(cur_thread->funnel_lock->fnl_mutex != fnl->fnl_mutex)
				panic("Funnel unlock  when not holding funnel");
			cur_thread->funnel_state &= ~TH_FN_OWNED;
			KERNEL_DEBUG(0x603242c | DBG_FUNC_NONE,
								fnl, 1, 0, 0, 0);

			cur_thread->funnel_lock = THR_FUNNEL_NULL;
			funnel_unlock(fnl);
		}
		(void)ml_set_interrupts_enabled(intr);
	} else {
		/* if we are trying to acquire funnel recursively
		 * check for funnel to be held already
		 */
		if (funneled && (fnl->fnl_mutex != cur_thread->funnel_lock->fnl_mutex)) {
				panic("thread_funnel_set: already holding a different funnel");
		}
	}
	return(funnel_state_prev);
}

boolean_t
thread_funnel_merge(
	funnel_t * fnl,
	funnel_t * otherfnl)
{
	mutex_t * m;
	mutex_t * otherm;
	funnel_t * gfnl;
	extern int disable_funnel;

	if ((gfnl = thread_funnel_get()) == THR_FUNNEL_NULL)
		panic("thread_funnel_merge called with no funnels held");

	if (gfnl->fnl_type != 1)
		panic("thread_funnel_merge called from non kernel funnel");

	if (gfnl != fnl)
		panic("thread_funnel_merge incorrect invocation");

	if (disable_funnel || split_funnel_off)
		return (KERN_FAILURE);

	m = fnl->fnl_mutex;
	otherm = otherfnl->fnl_mutex;

	/* Acquire other funnel mutex */
	mutex_lock(otherm);
	split_funnel_off = 1;
	disable_funnel = 1;
	otherfnl->fnl_mutex = m;
	otherfnl->fnl_type = fnl->fnl_type;
	otherfnl->fnl_oldmutex = otherm;	/* save this for future use */

	mutex_unlock(otherm);
	return(KERN_SUCCESS);
}

void
thread_set_cont_arg(
	int				arg)
{
	thread_t		self = current_thread();

	self->saved.misc = arg; 
}

int
thread_get_cont_arg(void)
{
	thread_t		self = current_thread();

	return (self->saved.misc); 
}

/*
 * Export routines to other components for things that are done as macros
 * within the osfmk component.
 */
#undef thread_should_halt
boolean_t
thread_should_halt(
	thread_shuttle_t th)
{
	return(thread_should_halt_fast(th));
}

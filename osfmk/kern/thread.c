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

static struct zone			*thread_zone;

static queue_head_t			reaper_queue;
decl_simple_lock_data(static,reaper_lock)

extern int		tick;

/* private */
static struct thread	thread_template, init_thread;

#if	MACH_DEBUG

#ifdef	MACHINE_STACK
extern void	stack_statistics(
			unsigned int	*totalp,
			vm_size_t	*maxusagep);
#endif	/* MACHINE_STACK */
#endif	/* MACH_DEBUG */

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

decl_simple_lock_data(static,stack_lock_data)
#define stack_lock()		simple_lock(&stack_lock_data)
#define stack_unlock()		simple_unlock(&stack_lock_data)

static vm_map_t				stack_map;
static vm_offset_t			stack_free_list;

static vm_offset_t			stack_free_cache[NCPUS];

unsigned int stack_free_max = 0;
unsigned int stack_free_count = 0;		/* splsched only */
unsigned int stack_free_limit = 1;		/* Arbitrary  */

unsigned int stack_cache_hits = 0;		/* debugging */

unsigned int stack_alloc_hits = 0;		/* debugging */
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
 *	Allocate a kernel stack for a thread.
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

	s = splsched();
	stack_lock();
	stack = stack_free_list;
	if (stack != 0) {
		stack_free_list = stack_next(stack);
		stack_free_count--;
	}
	stack_unlock();
	splx(s);

	if (stack != 0) {
		machine_stack_attach(thread, stack, start_pos);
		return (stack);
	}
		
	if (kernel_memory_allocate(
					stack_map, &stack,
						KERNEL_STACK_SIZE, stack_alloc_bndry - 1,
										KMA_KOBJECT) != KERN_SUCCESS)
		panic("stack_alloc: no space left for stack maps");

	stack_alloc_total++;
	if (stack_alloc_total > stack_alloc_hiwater)
		stack_alloc_hiwater = stack_alloc_total;

	machine_stack_attach(thread, stack, start_pos);
	return (stack);
}

/*
 *	stack_free:
 *
 *	Free a kernel stack.
 */

void
stack_free(
	thread_t thread)
{
    vm_offset_t stack = machine_stack_detach(thread);

	assert(stack);
	if (stack != thread->reserved_stack) {
		spl_t			s = splsched();
		vm_offset_t		*cache;

		cache = &stack_free_cache[cpu_number()];
		if (*cache == 0) {
			*cache = stack;
			splx(s);

			return;
		}

		stack_lock();
		stack_next(stack) = stack_free_list;
		stack_free_list = stack;
		if (++stack_free_count > stack_free_max)
			stack_free_max = stack_free_count;
		stack_unlock();
		splx(s);
	}
}

void
stack_free_stack(
	vm_offset_t		stack)
{
	spl_t			s = splsched();
	vm_offset_t		*cache;

	cache = &stack_free_cache[cpu_number()];
	if (*cache == 0) {
		*cache = stack;
		splx(s);

		return;
	}

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
	spl_t	s = splsched();

	stack_lock();
	while (stack_free_count > stack_free_limit) {
		vm_offset_t		stack = stack_free_list;

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

/*
 *	stack_alloc_try:
 *
 *	Non-blocking attempt to allocate a kernel stack.
 *	Called at splsched with the thread locked.
 */

boolean_t stack_alloc_try(
	thread_t	thread,
	void		(*start)(thread_t))
{
	register vm_offset_t	stack, *cache;

	cache = &stack_free_cache[cpu_number()];
	if (stack = *cache) {
		*cache = 0;
		machine_stack_attach(thread, stack, start);
		stack_cache_hits++;

		return (TRUE);
	}

	stack_lock();
	stack = stack_free_list;
	if (stack != (vm_offset_t)0) {
		stack_free_list = stack_next(stack);
		stack_free_count--;
	}
	stack_unlock();

	if (stack == 0)
		stack = thread->reserved_stack;

	if (stack != 0) {
		machine_stack_attach(thread, stack, start);
		stack_alloc_hits++;

		return (TRUE);
	}
	else {
		stack_alloc_misses++;

		return (FALSE);
	}
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

void
stack_privilege(
	register thread_t	thread)
{
	/* OBSOLETE */
}

void
thread_bootstrap(void)
{
	/*
	 *	Fill in a template thread for fast initialization.
	 */

	thread_template.runq = RUN_QUEUE_NULL;

	thread_template.ref_count = 1;

	thread_template.reason = AST_NONE;
	thread_template.at_safe_point = FALSE;
	thread_template.wait_event = NO_EVENT64;
	thread_template.wait_queue = WAIT_QUEUE_NULL;
	thread_template.wait_result = THREAD_WAITING;
	thread_template.interrupt_level = THREAD_ABORTSAFE;
	thread_template.state = TH_STACK_HANDOFF | TH_WAIT | TH_UNINT;
	thread_template.wake_active = FALSE;
	thread_template.active_callout = FALSE;
	thread_template.continuation = (void (*)(void))0;
	thread_template.top_act = THR_ACT_NULL;

	thread_template.importance = 0;
	thread_template.sched_mode = 0;
	thread_template.safe_mode = 0;

	thread_template.priority = 0;
	thread_template.sched_pri = 0;
	thread_template.max_priority = 0;
	thread_template.task_priority = 0;
	thread_template.promotions = 0;
	thread_template.pending_promoter_index = 0;
	thread_template.pending_promoter[0] =
		thread_template.pending_promoter[1] = NULL;

	thread_template.realtime.deadline = UINT64_MAX;

	thread_template.current_quantum = 0;

	thread_template.computation_metered = 0;
	thread_template.computation_epoch = 0;

	thread_template.cpu_usage = 0;
	thread_template.cpu_delta = 0;
	thread_template.sched_usage = 0;
	thread_template.sched_delta = 0;
	thread_template.sched_stamp = 0;
	thread_template.sleep_stamp = 0;
	thread_template.safe_release = 0;

	thread_template.bound_processor = PROCESSOR_NULL;
	thread_template.last_processor = PROCESSOR_NULL;
	thread_template.last_switch = 0;

	thread_template.vm_privilege = FALSE;

	timer_init(&(thread_template.user_timer));
	timer_init(&(thread_template.system_timer));
	thread_template.user_timer_save.low = 0;
	thread_template.user_timer_save.high = 0;
	thread_template.system_timer_save.low = 0;
	thread_template.system_timer_save.high = 0;

	thread_template.processor_set = PROCESSOR_SET_NULL;

	thread_template.act_ref_count = 2;

	thread_template.special_handler.handler = special_handler;
	thread_template.special_handler.next = 0;

#if	MACH_HOST
	thread_template.may_assign = TRUE;
	thread_template.assign_active = FALSE;
#endif	/* MACH_HOST */
    thread_template.funnel_lock = THR_FUNNEL_NULL;
	thread_template.funnel_state = 0;
#if	MACH_LDEBUG
	thread_template.mutex_count = 0;
#endif	/* MACH_LDEBUG */

	init_thread = thread_template;

	init_thread.top_act = &init_thread;
	init_thread.thread = &init_thread;
	machine_thread_set_current(&init_thread);
}

void
thread_init(void)
{
	kern_return_t ret;
	unsigned int stack;
	
	thread_zone = zinit(
			sizeof(struct thread),
			THREAD_MAX * sizeof(struct thread),
			THREAD_CHUNK * sizeof(struct thread),
			"threads");

	/*
	 *	Initialize other data structures used in
	 *	this module.
	 */

	queue_init(&reaper_queue);
	simple_lock_init(&reaper_lock, ETAP_THREAD_REAPER);

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

	/*
	 *	Initialize any machine-dependent
	 *	per-thread structures necessary.
	 */
	machine_thread_init();
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
	active_acts = hw_atomic_sub(&task->active_thread_count, 1);

	if (active_acts == 0 && task->bsd_info)
		proc_exit(task->bsd_info);

	/* JMM - for now, no migration */
	assert(!thr_act->lower);

	thread_timer_terminate();

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
 * Doesn't start the thread running.
 */
static kern_return_t
thread_create_internal(
	task_t					parent_task,
	integer_t				priority,
	void					(*start)(void),
	thread_t				*out_thread)
{
	thread_t				new_thread;
	processor_set_t			pset;
	static thread_t			first_thread;

	/*
	 *	Allocate a thread and initialize static fields
	 */
	if (first_thread == NULL)
		new_thread = first_thread = current_act();
	else
		new_thread = (thread_t)zalloc(thread_zone);
	if (new_thread == NULL)
		return (KERN_RESOURCE_SHORTAGE);

	if (new_thread != first_thread)
		*new_thread = thread_template;

#ifdef MACH_BSD
    {
		extern void     *uthread_alloc(task_t, thread_act_t);

		new_thread->uthread = uthread_alloc(parent_task, new_thread);
		if (new_thread->uthread == NULL) {
			zfree(thread_zone, (vm_offset_t)new_thread);
			return (KERN_RESOURCE_SHORTAGE);
		}
	}
#endif  /* MACH_BSD */

	if (machine_thread_create(new_thread, parent_task) != KERN_SUCCESS) {
#ifdef MACH_BSD
		{
			extern void uthread_free(task_t, void *, void *);
			void *ut = new_thread->uthread;

			new_thread->uthread = NULL;
			uthread_free(parent_task, ut, parent_task->bsd_info);
		}
#endif  /* MACH_BSD */
		zfree(thread_zone, (vm_offset_t)new_thread);
		return (KERN_FAILURE);
	}

    new_thread->task = parent_task;

	thread_lock_init(new_thread);
	wake_lock_init(new_thread);

	mutex_init(&new_thread->lock, ETAP_THREAD_ACT);

	ipc_thr_act_init(parent_task, new_thread);

	ipc_thread_init(new_thread);
	queue_init(&new_thread->held_ulocks);
	act_prof_init(new_thread, parent_task);

	new_thread->continuation = start;
	new_thread->sleep_stamp = sched_tick;

	pset = parent_task->processor_set;
	assert(pset == &default_pset);
	pset_lock(pset);

	task_lock(parent_task);
	assert(parent_task->processor_set == pset);

	if (	!parent_task->active							||
			(parent_task->thread_count >= THREAD_MAX	&&
			 parent_task != kernel_task)) {
		task_unlock(parent_task);
		pset_unlock(pset);

#ifdef MACH_BSD
		{
			extern void uthread_free(task_t, void *, void *);
			void *ut = new_thread->uthread;

			new_thread->uthread = NULL;
			uthread_free(parent_task, ut, parent_task->bsd_info);
		}
#endif  /* MACH_BSD */
		act_prof_deallocate(new_thread);
		ipc_thr_act_terminate(new_thread);
		machine_thread_destroy(new_thread);
		zfree(thread_zone, (vm_offset_t) new_thread);
		return (KERN_FAILURE);
	}

	act_attach(new_thread, new_thread);

	task_reference_locked(parent_task);

	/* Cache the task's map */
	new_thread->map = parent_task->map;

	/* Chain the thread onto the task's list */
	queue_enter(&parent_task->threads, new_thread, thread_act_t, task_threads);
	parent_task->thread_count++;
	parent_task->res_thread_count++;
	
	/* So terminating threads don't need to take the task lock to decrement */
	hw_atomic_add(&parent_task->active_thread_count, 1);

	/* Associate the thread with the processor set */
	pset_add_thread(pset, new_thread);

	thread_timer_setup(new_thread);

	/* Set the thread's scheduling parameters */
	if (parent_task != kernel_task)
		new_thread->sched_mode |= TH_MODE_TIMESHARE;
	new_thread->max_priority = parent_task->max_priority;
	new_thread->task_priority = parent_task->priority;
	new_thread->priority = (priority < 0)? parent_task->priority: priority;
	if (new_thread->priority > new_thread->max_priority)
		new_thread->priority = new_thread->max_priority;
	new_thread->importance =
					new_thread->priority - new_thread->task_priority;
	new_thread->sched_stamp = sched_tick;
	compute_priority(new_thread, FALSE);

#if	ETAP_EVENT_MONITOR
	new_thread->etap_reason = 0;
	new_thread->etap_trace  = FALSE;
#endif	/* ETAP_EVENT_MONITOR */

	new_thread->active = TRUE;

	*out_thread = new_thread;

	{
		long	dbg_arg1, dbg_arg2, dbg_arg3, dbg_arg4;

		kdbg_trace_data(parent_task->bsd_info, &dbg_arg2);

		KERNEL_DEBUG_CONSTANT(
					TRACEDBG_CODE(DBG_TRACE_DATA, 1) | DBG_FUNC_NONE,
							(vm_address_t)new_thread, dbg_arg2, 0, 0, 0);

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
	thread_act_t		*new_thread)
{
	kern_return_t		result;
	thread_t			thread;

	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	result = thread_create_internal(task, -1, thread_bootstrap_return, &thread);
	if (result != KERN_SUCCESS)
		return (result);

	thread->user_stop_count = 1;
	thread_hold(thread);
	if (task->suspend_count > 0)
		thread_hold(thread);

	pset_unlock(task->processor_set);
	task_unlock(task);
	
	*new_thread = thread;

	return (KERN_SUCCESS);
}

kern_return_t
thread_create_running(
	register task_t         task,
	int                     flavor,
	thread_state_t          new_state,
	mach_msg_type_number_t  new_state_count,
	thread_act_t			*new_thread)
{
	register kern_return_t  result;
	thread_t				thread;

	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	result = thread_create_internal(task, -1, thread_bootstrap_return, &thread);
	if (result != KERN_SUCCESS)
		return (result);

	result = machine_thread_set_state(thread, flavor, new_state, new_state_count);
	if (result != KERN_SUCCESS) {
		pset_unlock(task->processor_set);
		task_unlock(task);

		thread_terminate(thread);
		act_deallocate(thread);
		return (result);
	}

	act_lock(thread);
	clear_wait(thread, THREAD_AWAKENED);
	thread->started = TRUE;
	act_unlock(thread);
	pset_unlock(task->processor_set);
	task_unlock(task);

	*new_thread = thread;

	return (result);
}

/*
 *	kernel_thread:
 *
 *	Create a thread in the kernel task
 *	to execute in kernel context.
 */
thread_t
kernel_thread_create(
	void				(*start)(void),
	integer_t			priority)
{
	kern_return_t		result;
	task_t				task = kernel_task;
	thread_t			thread;

	result = thread_create_internal(task, priority, start, &thread);
	if (result != KERN_SUCCESS)
		return (THREAD_NULL);

	pset_unlock(task->processor_set);
	task_unlock(task);

	thread_doswapin(thread);
	assert(thread->kernel_stack != 0);
	thread->reserved_stack = thread->kernel_stack;

	act_deallocate(thread);

	return (thread);
}

thread_t
kernel_thread_with_priority(
	void			(*start)(void),
	integer_t		priority)
{
	thread_t		thread;

	thread = kernel_thread_create(start, priority);
	if (thread == THREAD_NULL)
		return (THREAD_NULL);

	act_lock(thread);
	clear_wait(thread, THREAD_AWAKENED);
	thread->started = TRUE;
	act_unlock(thread);

#ifdef i386
	thread_bind(thread, master_processor);
#endif /* i386 */
	return (thread);
}

thread_t
kernel_thread(
	task_t			task,
	void			(*start)(void))
{
	if (task != kernel_task)
		panic("kernel_thread");

	return kernel_thread_with_priority(start, -1);
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
	    panic("thread_deallocate");

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

	if (thread->reserved_stack != 0) {
		if (thread->reserved_stack != thread->kernel_stack)
			stack_free_stack(thread->reserved_stack);
		thread->reserved_stack = 0;
	}

	if (thread->kernel_stack != 0)
		stack_free(thread);

	machine_thread_destroy(thread);

	zfree(thread_zone, (vm_offset_t) thread);
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

	act_reference_locked(thr_act);

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
	reaper_thread_continue();
	/*NOTREACHED*/
}

void
thread_reaper_init(void)
{
	kernel_thread_with_priority(reaper_thread, MINPRI_KERNEL);
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
 *	thread_wire_internal:
 *
 *	Specify that the target thread must always be able
 *	to run and to allocate memory.
 */
kern_return_t
thread_wire_internal(
	host_priv_t	host_priv,
	thread_act_t	thr_act,
	boolean_t	wired,
	boolean_t	*prev_state)
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
	 */
	if (thr_act != current_act())
	    return KERN_INVALID_ARGUMENT;

	s = splsched();
	thread_lock(thread);

	if (prev_state) {
	    *prev_state = thread->vm_privilege;
	}
	
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
 *	thread_wire:
 *
 *	User-api wrapper for thread_wire_internal()
 */
kern_return_t
thread_wire(
	host_priv_t	host_priv,
	thread_act_t	thr_act,
	boolean_t	wired)

{
    return thread_wire_internal(host_priv, thr_act, wired, NULL);
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
		thread_t thread = threads[--i];

		if (thread->kernel_stack != 0)
			total++;

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

int		refunnel_hint_enabled = 0;

boolean_t
refunnel_hint(
	thread_t		thread,
	wait_result_t	wresult)
{
	if (	!(thread->funnel_state & TH_FN_REFUNNEL)	||
				wresult != THREAD_AWAKENED				)
		return (FALSE);

	if (!refunnel_hint_enabled)
		return (FALSE);

	return (mutex_preblock(thread->funnel_lock->fnl_mutex, thread));
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
	thread_t		th)
{
	return(thread_should_halt_fast(th));
}

vm_offset_t min_valid_stack_address(void)
{
	return vm_map_min(stack_map);
}

vm_offset_t max_valid_stack_address(void)
{
	return vm_map_max(stack_map);
}

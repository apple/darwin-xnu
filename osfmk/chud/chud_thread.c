/*
 * Copyright (c) 2003-2009 Apple Inc. All rights reserved.
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
#include <mach/task.h>
#include <mach/thread_act.h>

#include <kern/kern_types.h>
#include <kern/processor.h>
#include <kern/thread.h>
#include <kern/kalloc.h>

#include <chud/chud_xnu.h>
#include <chud/chud_xnu_private.h>
#include <chud/chud_thread.h>

#include <machine/machine_routines.h>

#include <libkern/OSAtomic.h>

#if KPC
#include <kern/kpc.h>
#endif

#if KPERF
#include <kperf/kperf.h>
#endif

// include the correct file to find real_ncpus
#if defined(__i386__) || defined(__x86_64__)
#	include <i386/mp.h>	
#else
// fall back on declaring it extern.  The linker will sort us out.
extern unsigned int real_ncpus;
#endif

// Mask for supported options
#define T_CHUD_BIND_OPT_MASK (-1UL)

#if 0
#pragma mark **** thread binding ****
#endif

/*
 * This method will bind a given thread to the requested CPU starting at the
 * next time quantum.  If the thread is the current thread, this method will
 * force a thread_block().  The result is that if you call this method on the
 * current thread, you will be on the requested CPU when this method returns.
 */
__private_extern__ kern_return_t
chudxnu_bind_thread(thread_t thread, int cpu, __unused int options)
{
    processor_t proc = NULL;

	if(cpu < 0 || (unsigned int)cpu >= real_ncpus) // sanity check
		return KERN_FAILURE;

	// temporary restriction until after phase 2 of the scheduler
	if(thread != current_thread())
		return KERN_FAILURE; 
	
	proc = cpu_to_processor(cpu);

	/* 
	 * Potentially racey, but mainly to prevent bind to shutdown
	 * processor.
	 */
	if(proc && !(proc->state == PROCESSOR_OFF_LINE) &&
			!(proc->state == PROCESSOR_SHUTDOWN)) {
		
		thread_bind(proc);

		/*
		 * If we're trying to bind the current thread, and
		 * we're not on the target cpu, and not at interrupt
		 * context, block the current thread to force a
		 * reschedule on the target CPU.
		 */
		if(thread == current_thread() && 
			!ml_at_interrupt_context() && cpu_number() != cpu) {
			(void)thread_block(THREAD_CONTINUE_NULL);
		}
		return KERN_SUCCESS;
	}
    return KERN_FAILURE;
}

__private_extern__ kern_return_t
chudxnu_unbind_thread(thread_t thread, __unused int options)
{
	if(thread == current_thread())
		thread_bind(PROCESSOR_NULL);
    return KERN_SUCCESS;
}

__private_extern__ boolean_t
chudxnu_thread_get_idle(thread_t thread) {
	/* 
	 * Instantaneous snapshot of the idle state of
	 * a given thread.
	 *
	 * Should be called only on an interrupted or 
	 * suspended thread to avoid a race.
	 */
	return ((thread->state & TH_IDLE) == TH_IDLE);
}

__private_extern__ int
chudxnu_thread_get_scheduler_state(thread_t thread) {
	/* 
	 * Instantaneous snapshot of the scheduler state of
	 * a given thread.
	 *
	 * MUST ONLY be called on an interrupted or 
	 * locked thread, to avoid a race.
	 */
	
	int state = 0;
	int schedulerState = (volatile int)(thread->state);
	processor_t lastProcessor = (volatile processor_t)(thread->last_processor);
	
	if ((PROCESSOR_NULL != lastProcessor) && (thread == lastProcessor->active_thread)) {
		state |= CHUDXNU_TS_RUNNING;
	}
		
	if (schedulerState & TH_RUN) {
		state |= CHUDXNU_TS_RUNNABLE;
	}
	
	if (schedulerState & TH_WAIT) {
		state |= CHUDXNU_TS_WAIT;
	}
	
	if (schedulerState & TH_UNINT) {
		state |= CHUDXNU_TS_UNINT;
	}
	
	if (schedulerState & TH_SUSP) {
		state |= CHUDXNU_TS_SUSP;
	}
	
	if (schedulerState & TH_TERMINATE) {
		state |= CHUDXNU_TS_TERMINATE;
	}	
	
	if (schedulerState & TH_IDLE) {
		state |= CHUDXNU_TS_IDLE;
	}
	
	return state;
}

#if 0
#pragma mark **** task and thread info ****
#endif

__private_extern__ boolean_t
chudxnu_is_64bit_task(task_t task)
{
	return (task_has_64BitAddr(task));
}

// an exact copy of task_threads() except no mig conversion at the end!
static kern_return_t
chudxnu_private_task_threads(
	task_t			task,
	thread_act_array_t      *threads_out,
    	mach_msg_type_number_t  *count)
{
	mach_msg_type_number_t	actual;
	thread_t				*thread_list;
	thread_t				thread;
	vm_size_t				size, size_needed;
	void					*addr;
	unsigned int			i, j;

	if (task == TASK_NULL)
		return (KERN_INVALID_ARGUMENT);

	size = 0; addr = NULL;

	for (;;) {
		task_lock(task);
		if (!task->active) {
			task_unlock(task);

			if (size != 0)
				kfree(addr, size);

			return (KERN_FAILURE);
		}

		actual = task->thread_count;

		/* do we have the memory we need? */
		size_needed = actual * sizeof (mach_port_t);
		if (size_needed <= size)
			break;

		/* unlock the task and allocate more memory */
		task_unlock(task);

		if (size != 0)
			kfree(addr, size);

		assert(size_needed > 0);
		size = size_needed;

		addr = kalloc(size);
		if (addr == 0)
			return (KERN_RESOURCE_SHORTAGE);
	}

	/* OK, have memory and the task is locked & active */
	thread_list = (thread_t *)addr;

	i = j = 0;

	for (thread = (thread_t)queue_first(&task->threads); i < actual;
				++i, thread = (thread_t)queue_next(&thread->task_threads)) {
		thread_reference_internal(thread);
		thread_list[j++] = thread;
	}

	assert(queue_end(&task->threads, (queue_entry_t)thread));

	actual = j;
	size_needed = actual * sizeof (mach_port_t);

	/* can unlock task now that we've got the thread refs */
	task_unlock(task);

	if (actual == 0) {
		/* no threads, so return null pointer and deallocate memory */

		*threads_out = NULL;
		*count = 0;

		if (size != 0)
			kfree(addr, size);
	}
	else {
		/* if we allocated too much, must copy */

		if (size_needed < size) {
			void *newaddr;

			newaddr = kalloc(size_needed);
			if (newaddr == 0) {
				for (i = 0; i < actual; ++i)
					thread_deallocate(thread_list[i]);
				kfree(addr, size);
				return (KERN_RESOURCE_SHORTAGE);
			}

			bcopy(addr, newaddr, size_needed);
			kfree(addr, size);
			thread_list = (thread_t *)newaddr;
		}

		*threads_out = thread_list;
		*count = actual;
	}

	return (KERN_SUCCESS);
}


__private_extern__ kern_return_t
chudxnu_all_tasks(
	task_array_t		*task_list,
	mach_msg_type_number_t	*count)
{
	return processor_set_things(&pset0, (void **)task_list, count, PSET_THING_TASK);	
}

__private_extern__ kern_return_t
chudxnu_free_task_list(
	task_array_t		*task_list,
	mach_msg_type_number_t	*count)
{
	vm_size_t size = (*count)*sizeof(mach_port_t);
	void *addr = *task_list;

	if(addr) {
		int i, maxCount = *count;
		for(i=0; i<maxCount; i++) {
			task_deallocate((*task_list)[i]);
		}		
		kfree(addr, size);
		*task_list = NULL;
		*count = 0;
		return KERN_SUCCESS;
	} else {
		return KERN_FAILURE;
	}
}
__private_extern__ kern_return_t
chudxnu_all_threads(
	thread_array_t		*thread_list,
	mach_msg_type_number_t	*count)
{
	return processor_set_things(&pset0, (void **)thread_list, count, PSET_THING_THREAD);
}

__private_extern__ kern_return_t
chudxnu_task_threads(
	task_t task,
	thread_array_t *thread_list,
	mach_msg_type_number_t *count)
{
	return chudxnu_private_task_threads(task, thread_list, count);
}

__private_extern__ kern_return_t
chudxnu_free_thread_list(
	thread_array_t	*thread_list,
	mach_msg_type_number_t	*count)
{
	vm_size_t size = (*count)*sizeof(mach_port_t);
	void *addr = *thread_list;

	if(addr) {
		int i, maxCount = *count;
		for(i=0; i<maxCount; i++) {
			thread_deallocate((*thread_list)[i]);
		}		
		kfree(addr, size);
		*thread_list = NULL;
		*count = 0;
		return KERN_SUCCESS;
	} else {
		return KERN_FAILURE;
	}
}

__private_extern__ task_t
chudxnu_current_task(void)
{
	return current_task();
}

__private_extern__ thread_t
chudxnu_current_thread(void)
{
	return current_thread();
}

__private_extern__ task_t
chudxnu_task_for_thread(thread_t thread)
{
    return get_threadtask(thread);
}

__private_extern__ kern_return_t
chudxnu_thread_info(
	thread_t thread,
	thread_flavor_t flavor,
	thread_info_t thread_info_out,
	mach_msg_type_number_t *thread_info_count)
{
	return thread_info(thread, flavor, thread_info_out, thread_info_count);
}


/* thread marking stuff */

__private_extern__ boolean_t 
chudxnu_thread_get_marked(thread_t thread) 
{
	if(thread)
		return ((thread->t_chud & T_CHUD_MARKED) != 0);
	return FALSE;
}

__private_extern__ boolean_t
chudxnu_thread_set_marked(thread_t thread, boolean_t new_value)
{
	boolean_t old_val;

	if(thread) {
		if(new_value) {
			// set the marked bit
			old_val = OSBitOrAtomic(T_CHUD_MARKED,  &(thread->t_chud));
		} else {
			// clear the marked bit
			old_val = OSBitAndAtomic(~T_CHUD_MARKED,  &(thread->t_chud));
		}
		return (old_val & T_CHUD_MARKED) == T_CHUD_MARKED;
	}
	return FALSE;
}

/* XXX: good thing this code is experimental... */

/* external handler */
extern void (*chudxnu_thread_ast_handler)(thread_t);
void (*chudxnu_thread_ast_handler)(thread_t) = NULL;

/* AST callback to dispatch to AppleProfile */
extern void chudxnu_thread_ast(thread_t);
void
chudxnu_thread_ast(thread_t thread)
{
#if KPC
	/* check for PMC work */
	kpc_thread_ast_handler(thread);
#endif

#if KPERF
	/* check for kperf work */
	kperf_thread_ast_handler(thread);
#endif

	/* atomicness for kdebug events */
	void (*handler)(thread_t) = chudxnu_thread_ast_handler;
	if( handler )
		handler( thread );

	thread->t_chud = 0;
}



/* Get and set bits on the thread and trigger an AST handler */
void chudxnu_set_thread_ast( thread_t thread );
void
chudxnu_set_thread_ast( thread_t thread )
{
	/* FIXME: only call this on current thread from an interrupt handler for now... */
	if( thread != current_thread() )
		panic( "unsafe AST set" );

	act_set_kperf(thread);
}

/* get and set the thread bits */
extern uint32_t chudxnu_get_thread_bits( thread_t thread );
extern void chudxnu_set_thread_bits( thread_t thread, uint32_t bits );

uint32_t
chudxnu_get_thread_bits( thread_t thread )
{
	return thread->t_chud;
}

void
chudxnu_set_thread_bits( thread_t thread, uint32_t bits )
{
	thread->t_chud = bits;
}

/* get and set thread dirty bits. so CHUD can track whether the thread
 * has been dispatched since it last looked. caller must hold the
 * thread lock
 */
boolean_t
chudxnu_thread_get_dirty(thread_t thread)
{
	if( thread->c_switch != thread->chud_c_switch )
		return TRUE;
	else
		return FALSE;
}

void
chudxnu_thread_set_dirty(thread_t thread, boolean_t makedirty)
{
	if( makedirty )
		thread->chud_c_switch = thread->c_switch - 1;
	else
		thread->chud_c_switch = thread->c_switch;
}

/*
 * Copyright (c) 2003-2007 Apple Inc. All rights reserved.
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

// include the correct file to find real_ncpus
#if defined(__i386__) || defined(__x86_64__)
#	include <i386/mp.h>	
#elif defined(__ppc__) || defined(__ppc64__)
#	include <ppc/cpu_internal.h>
#elif defined(__arm__)
#	include <arm/cpu_internal.h>
#else
// fall back on declaring it extern.  The linker will sort us out.
extern unsigned int real_ncpus;
#endif

// Mask for supported options
#define T_CHUD_BIND_OPT_MASK (-1UL)

#pragma mark **** thread binding ****

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
			!(ml_at_interrupt_context() && cpu_number() == cpu)) {
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

#pragma mark **** task and thread info ****

__private_extern__ boolean_t
chudxnu_is_64bit_task(task_t task)
{
	return (task_has_64BitAddr(task));
}

#define THING_TASK		0
#define THING_THREAD	1

// an exact copy of processor_set_things() except no mig conversion at the end!
static kern_return_t
chudxnu_private_processor_set_things(
	processor_set_t		pset,
	mach_port_t		**thing_list,
	mach_msg_type_number_t	*count,
	int			type)
{
	unsigned int actual;	/* this many things */
	unsigned int maxthings;
	unsigned int i;

	vm_size_t size, size_needed;
	void  *addr;

	if (pset == PROCESSOR_SET_NULL || pset != &pset0)
		return (KERN_INVALID_ARGUMENT);

	size = 0; addr = NULL;

	for (;;) {
		mutex_lock(&tasks_threads_lock);

		if (type == THING_TASK)
			maxthings = tasks_count;
		else
			maxthings = threads_count;

		/* do we have the memory we need? */

		size_needed = maxthings * sizeof (mach_port_t);
		if (size_needed <= size)
			break;

		mutex_unlock(&tasks_threads_lock);

		if (size != 0)
			kfree(addr, size);

		assert(size_needed > 0);
		size = size_needed;

		addr = kalloc(size);
		if (addr == 0)
			return (KERN_RESOURCE_SHORTAGE);
	}

	/* OK, have memory and the processor_set is locked & active */

	actual = 0;
	switch (type) {

	case THING_TASK:
	{
		task_t		task, *task_list = (task_t *)addr;

		for (task = (task_t)queue_first(&tasks);
				!queue_end(&tasks, (queue_entry_t)task);
					task = (task_t)queue_next(&task->tasks)) {
			task_reference_internal(task);
			task_list[actual++] = task;
		}

		break;
	}

	case THING_THREAD:
	{
		thread_t	thread, *thread_list = (thread_t *)addr;

		for (i = 0, thread = (thread_t)queue_first(&threads);
				!queue_end(&threads, (queue_entry_t)thread);
					thread = (thread_t)queue_next(&thread->threads)) {
			thread_reference_internal(thread);
			thread_list[actual++] = thread;
		}

		break;
	}
	}
		
	mutex_unlock(&tasks_threads_lock);

	if (actual < maxthings)
		size_needed = actual * sizeof (mach_port_t);

	if (actual == 0) {
		/* no things, so return null pointer and deallocate memory */
		*thing_list = NULL;
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
				switch (type) {

				case THING_TASK:
				{
					task_t		*task_list = (task_t *)addr;

					for (i = 0; i < actual; i++)
						task_deallocate(task_list[i]);
					break;
				}

				case THING_THREAD:
				{
					thread_t	*thread_list = (thread_t *)addr;

					for (i = 0; i < actual; i++)
						thread_deallocate(thread_list[i]);
					break;
				}
				}

				kfree(addr, size);
				return (KERN_RESOURCE_SHORTAGE);
			}

			bcopy((void *) addr, (void *) newaddr, size_needed);
			kfree(addr, size);
			addr = newaddr;
		}

		*thing_list = (mach_port_t *)addr;
		*count = actual;
	}

	return (KERN_SUCCESS);
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
	return chudxnu_private_processor_set_things(&pset0, (mach_port_t **)task_list, count, THING_TASK);	
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
	return chudxnu_private_processor_set_things(&pset0, (mach_port_t **)thread_list, count, THING_THREAD);
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


__private_extern__ kern_return_t
chudxnu_thread_last_context_switch(thread_t thread, uint64_t *timestamp)
{
    *timestamp = thread->last_switch;
    return KERN_SUCCESS;
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
			old_val = OSBitOrAtomic(T_CHUD_MARKED, (UInt32 *) &(thread->t_chud));
		} else {
			// clear the marked bit
			old_val = OSBitAndAtomic(~T_CHUD_MARKED, (UInt32 *) &(thread->t_chud));
		}
		return (old_val & T_CHUD_MARKED) == T_CHUD_MARKED;
	}
	return FALSE;
}


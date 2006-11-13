/*
 * Copyright (c) 2003-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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

#include <machine/machine_routines.h>

// include the correct file to find real_ncpus
#if defined(__i386__) || defined(__x86_64__)
#	include <i386/mp.h>	
#endif // i386 or x86_64

#if defined(__ppc__) || defined(__ppc64__)
#	include <ppc/cpu_internal.h>
#endif // ppc or ppc64

#pragma mark **** thread binding ****

__private_extern__ kern_return_t
chudxnu_bind_thread(thread_t thread, int cpu)
{
    processor_t proc = NULL;
	
	if(cpu >= real_ncpus) // sanity check
		return KERN_FAILURE;
	
	proc = cpu_to_processor(cpu);

	if(proc && !(proc->state == PROCESSOR_OFF_LINE) &&
			   !(proc->state == PROCESSOR_SHUTDOWN)) {
		/* disallow bind to shutdown processor */
		thread_bind(thread, proc);
		if(thread==current_thread()) {
			(void)thread_block(THREAD_CONTINUE_NULL);
		}
		return KERN_SUCCESS;
	}
    return KERN_FAILURE;
}

__private_extern__ kern_return_t
chudxnu_unbind_thread(thread_t thread)
{
    thread_bind(thread, PROCESSOR_NULL);
    return KERN_SUCCESS;
}

#pragma mark **** task and thread info ****

__private_extern__
boolean_t chudxnu_is_64bit_task(task_t task)
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

	if (pset == PROCESSOR_SET_NULL)
		return (KERN_INVALID_ARGUMENT);

	size = 0; addr = 0;

	for (;;) {
		pset_lock(pset);
		if (!pset->active) {
			pset_unlock(pset);

			return (KERN_FAILURE);
		}

		if (type == THING_TASK)
			maxthings = pset->task_count;
		else
			maxthings = pset->thread_count;

		/* do we have the memory we need? */

		size_needed = maxthings * sizeof (mach_port_t);
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
			return (KERN_RESOURCE_SHORTAGE);
	}

	/* OK, have memory and the processor_set is locked & active */

	actual = 0;
	switch (type) {

	case THING_TASK:
	{
		task_t		task, *tasks = (task_t *)addr;

		for (task = (task_t)queue_first(&pset->tasks);
				!queue_end(&pset->tasks, (queue_entry_t)task);
					task = (task_t)queue_next(&task->pset_tasks)) {
			task_reference_internal(task);
			tasks[actual++] = task;
		}

		break;
	}

	case THING_THREAD:
	{
		thread_t	thread, *threads = (thread_t *)addr;

		for (i = 0, thread = (thread_t)queue_first(&pset->threads);
				!queue_end(&pset->threads, (queue_entry_t)thread);
					thread = (thread_t)queue_next(&thread->pset_threads)) {
			thread_reference_internal(thread);
			threads[actual++] = thread;
		}

		break;
	}
	}
		
	pset_unlock(pset);

	if (actual < maxthings)
		size_needed = actual * sizeof (mach_port_t);

	if (actual == 0) {
		/* no things, so return null pointer and deallocate memory */
		*thing_list = 0;
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
					task_t		*tasks = (task_t *)addr;

					for (i = 0; i < actual; i++)
						task_deallocate(tasks[i]);
					break;
				}

				case THING_THREAD:
				{
					thread_t	*threads = (thread_t *)addr;

					for (i = 0; i < actual; i++)
						thread_deallocate(threads[i]);
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
	thread_t				*threads;
	thread_t				thread;
	vm_size_t				size, size_needed;
	void					*addr;
	unsigned int			i, j;

	if (task == TASK_NULL)
		return (KERN_INVALID_ARGUMENT);

	size = 0; addr = 0;

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
	threads = (thread_t *)addr;

	i = j = 0;

	for (thread = (thread_t)queue_first(&task->threads); i < actual;
				++i, thread = (thread_t)queue_next(&thread->task_threads)) {
		thread_reference_internal(thread);
		threads[j++] = thread;
	}

	assert(queue_end(&task->threads, (queue_entry_t)thread));

	actual = j;
	size_needed = actual * sizeof (mach_port_t);

	/* can unlock task now that we've got the thread refs */
	task_unlock(task);

	if (actual == 0) {
		/* no threads, so return null pointer and deallocate memory */

		*threads_out = 0;
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
					thread_deallocate(threads[i]);
				kfree(addr, size);
				return (KERN_RESOURCE_SHORTAGE);
			}

			bcopy(addr, newaddr, size_needed);
			kfree(addr, size);
			threads = (thread_t *)newaddr;
		}

		*threads_out = threads;
		*count = actual;
	}

	return (KERN_SUCCESS);
}


__private_extern__ kern_return_t
chudxnu_all_tasks(
	task_array_t		*task_list,
	mach_msg_type_number_t	*count)
{
	return chudxnu_private_processor_set_things(&default_pset, (mach_port_t **)task_list, count, THING_TASK);	
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
	return chudxnu_private_processor_set_things(&default_pset, (mach_port_t **)thread_list, count, THING_THREAD);
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


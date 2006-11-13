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
/*
 *	Kernel stack management routines.
 */

#include <mach/mach_host.h>
#include <mach/mach_types.h>
#include <mach/processor_set.h>

#include <kern/kern_types.h>
#include <kern/mach_param.h>
#include <kern/processor.h>
#include <kern/thread.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>

#include <vm/vm_map.h>
#include <vm/vm_kern.h>

#include <mach_debug.h>

/*
 *	We allocate stacks from generic kernel VM.
 *
 *	The stack_free_list can only be accessed at splsched,
 *	because stack_alloc_try/thread_invoke operate at splsched.
 */

decl_simple_lock_data(static,stack_lock_data)
#define stack_lock()		simple_lock(&stack_lock_data)
#define stack_unlock()		simple_unlock(&stack_lock_data)

#define STACK_CACHE_SIZE	2

static vm_map_t			stack_map;
static vm_offset_t		stack_free_list;

static unsigned int		stack_free_count, stack_free_hiwat;		/* free list count */
static unsigned int		stack_total, stack_hiwat;				/* current total count */

static unsigned int		stack_free_target;
static int				stack_free_delta;

static unsigned int		stack_new_count;						/* total new stack allocations */

static vm_offset_t		stack_addr_mask;

/*
 *	The next field is at the base of the stack,
 *	so the low end is left unsullied.
 */
#define stack_next(stack)	\
			(*((vm_offset_t *)((stack) + KERNEL_STACK_SIZE) - 1))

void
stack_init(void)
{
	vm_offset_t			stacks, boundary;
	vm_map_offset_t		map_addr;

	simple_lock_init(&stack_lock_data, 0);
	
	if (KERNEL_STACK_SIZE < round_page(KERNEL_STACK_SIZE))
		panic("stack_init: stack size %d not a multiple of page size %d\n",	KERNEL_STACK_SIZE, PAGE_SIZE);
	
	for (boundary = PAGE_SIZE; boundary <= KERNEL_STACK_SIZE; )
		boundary <<= 1;

	stack_addr_mask = boundary - 1;

	if (kmem_suballoc(kernel_map, &stacks, (boundary * (2 * THREAD_MAX + 64)),
								FALSE, VM_FLAGS_ANYWHERE, &stack_map) != KERN_SUCCESS)
		panic("stack_init: kmem_suballoc");

	map_addr = vm_map_min(stack_map);
	if (vm_map_enter(stack_map, &map_addr, vm_map_round_page(PAGE_SIZE), 0, VM_FLAGS_FIXED,
						VM_OBJECT_NULL, 0, FALSE, VM_PROT_NONE, VM_PROT_NONE, VM_INHERIT_DEFAULT) != KERN_SUCCESS)
		panic("stack_init: vm_map_enter");
}

/*
 *	stack_alloc:
 *
 *	Allocate a stack for a thread, may
 *	block.
 */
void
stack_alloc(
	thread_t	thread)
{
	vm_offset_t		stack;
	spl_t			s;

	assert(thread->kernel_stack == 0);

	s = splsched();
	stack_lock();
	stack = stack_free_list;
	if (stack != 0) {
		stack_free_list = stack_next(stack);
		stack_free_count--;
	}
	else {
		if (++stack_total > stack_hiwat)
			stack_hiwat = stack_total;
		stack_new_count++;
	}
	stack_free_delta--;
	stack_unlock();
	splx(s);
		
	if (stack == 0) {
		if (kernel_memory_allocate(stack_map, &stack, KERNEL_STACK_SIZE, stack_addr_mask, KMA_KOBJECT) != KERN_SUCCESS)
			panic("stack_alloc: kernel_memory_allocate");
	}

	machine_stack_attach(thread, stack);
}

/*
 *	stack_free:
 *
 *	Detach and free the stack for a thread.
 */
void
stack_free(
	thread_t	thread)
{
    vm_offset_t		stack = machine_stack_detach(thread);

	assert(stack);
	if (stack != thread->reserved_stack) {
		struct stack_cache	*cache;
		spl_t				s;

		s = splsched();
		cache = &PROCESSOR_DATA(current_processor(), stack_cache);
		if (cache->count < STACK_CACHE_SIZE) {
			stack_next(stack) = cache->free;
			cache->free = stack;
			cache->count++;
		}
		else {
			stack_lock();
			stack_next(stack) = stack_free_list;
			stack_free_list = stack;
			if (++stack_free_count > stack_free_hiwat)
				stack_free_hiwat = stack_free_count;
			stack_free_delta++;
			stack_unlock();
		}
		splx(s);
	}
}

void
stack_free_stack(
	vm_offset_t		stack)
{
	struct stack_cache	*cache;
	spl_t				s;

	s = splsched();
	cache = &PROCESSOR_DATA(current_processor(), stack_cache);
	if (cache->count < STACK_CACHE_SIZE) {
		stack_next(stack) = cache->free;
		cache->free = stack;
		cache->count++;
	}
	else {
		stack_lock();
		stack_next(stack) = stack_free_list;
		stack_free_list = stack;
		if (++stack_free_count > stack_free_hiwat)
			stack_free_hiwat = stack_free_count;
		stack_free_delta++;
		stack_unlock();
	}
	splx(s);
}

/*
 *	stack_alloc_try:
 *
 *	Non-blocking attempt to allocate a
 *	stack for a thread.
 *
 *	Returns TRUE on success.
 *
 *	Called at splsched.
 */
boolean_t
stack_alloc_try(
	thread_t		thread)
{
	struct stack_cache	*cache;
	vm_offset_t			stack;

	cache = &PROCESSOR_DATA(current_processor(), stack_cache);
	stack = cache->free;
	if (stack != 0) {
		cache->free = stack_next(stack);
		cache->count--;
	}
	else {
		if (stack_free_list != 0) {
			stack_lock();
			stack = stack_free_list;
			if (stack != 0) {
				stack_free_list = stack_next(stack);
				stack_free_count--;
				stack_free_delta--;
			}
			stack_unlock();
		}
	}

	if (stack != 0 || (stack = thread->reserved_stack) != 0) {
		machine_stack_attach(thread, stack);
		return (TRUE);
	}

	return (FALSE);
}

static unsigned int		stack_collect_tick, last_stack_tick;

/*
 *	stack_collect:
 *
 *	Free excess kernel stacks, may
 *	block.
 */
void
stack_collect(void)
{
	if (stack_collect_tick != last_stack_tick) {
		unsigned int	target;
		vm_offset_t		stack;
		spl_t			s;

		s = splsched();
		stack_lock();

		target = stack_free_target + (STACK_CACHE_SIZE * processor_count);
		target += (stack_free_delta >= 0)? stack_free_delta: -stack_free_delta;

		while (stack_free_count > target) {
			stack = stack_free_list;
			stack_free_list = stack_next(stack);
			stack_free_count--; stack_total--;
			stack_unlock();
			splx(s);

			if (vm_map_remove(stack_map, vm_map_trunc_page(stack),
								vm_map_round_page(stack + KERNEL_STACK_SIZE), VM_MAP_REMOVE_KUNWIRE) != KERN_SUCCESS)
				panic("stack_collect: vm_map_remove");

			s = splsched();
			stack_lock();

			target = stack_free_target + (STACK_CACHE_SIZE * processor_count);
			target += (stack_free_delta >= 0)? stack_free_delta: -stack_free_delta;
		}

		last_stack_tick = stack_collect_tick;

		stack_unlock();
		splx(s);
	}
}

/*
 *	compute_stack_target:
 *
 *	Computes a new target free list count
 *	based on recent alloc / free activity.
 *
 *	Limits stack collection to once per
 *	computation period.
 */
void
compute_stack_target(
__unused void		*arg)
{
	spl_t		s;

	s = splsched();
	stack_lock();

	if (stack_free_target > 5)
		stack_free_target = (4 * stack_free_target) / 5;
	else
	if (stack_free_target > 0)
		stack_free_target--;

	stack_free_target += (stack_free_delta >= 0)? stack_free_delta: -stack_free_delta;

	stack_free_delta = 0;
	stack_collect_tick++;

	stack_unlock();
	splx(s);
}

void
stack_fake_zone_info(int *count, vm_size_t *cur_size, vm_size_t *max_size, vm_size_t *elem_size,
		     vm_size_t *alloc_size, int *collectable, int *exhaustable)
{
	unsigned int	total, hiwat, free;
	spl_t			s;

	s = splsched();
	stack_lock();
	total = stack_total;
	hiwat = stack_hiwat;
	free = stack_free_count;
	stack_unlock();
	splx(s);

	*count      = total - free;
	*cur_size   = KERNEL_STACK_SIZE * total;
	*max_size   = KERNEL_STACK_SIZE * hiwat;
	*elem_size  = KERNEL_STACK_SIZE;
	*alloc_size = KERNEL_STACK_SIZE;
	*collectable = 1;
	*exhaustable = 0;
}

/* OBSOLETE */
void	stack_privilege(
			thread_t	thread);

void
stack_privilege(
	__unused thread_t	thread)
{
	/* OBSOLETE */
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
	void *addr;

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
	threads = (thread_t *) addr;
	for (i = 0, thread = (thread_t) queue_first(&pset->threads);
					!queue_end(&pset->threads, (queue_entry_t) thread);
					thread = (thread_t) queue_next(&thread->pset_threads)) {
		thread_reference_internal(thread);
		threads[i++] = thread;
	}
	assert(i <= actual);

	/* can unlock processor set now that we have the thread refs */
	pset_unlock(pset);

	/* calculate maxusage and free thread references */

	total = 0;
	maxusage = 0;
	maxstack = 0;
	while (i > 0) {
		thread_t threadref = threads[--i];

		if (threadref->kernel_stack != 0)
			total++;

		thread_deallocate(threadref);
	}

	if (size != 0)
		kfree(addr, size);

	*totalp = total;
	*residentp = *spacep = total * round_page(KERNEL_STACK_SIZE);
	*maxusagep = maxusage;
	*maxstackp = maxstack;
	return KERN_SUCCESS;

#endif	/* MACH_DEBUG */
}

vm_offset_t min_valid_stack_address(void)
{
	return vm_map_min(stack_map);
}

vm_offset_t max_valid_stack_address(void)
{
	return vm_map_max(stack_map);
}

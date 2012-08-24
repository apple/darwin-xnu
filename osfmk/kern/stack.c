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
#include <kern/ledger.h>

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

static vm_offset_t		stack_free_list;

static unsigned int		stack_free_count, stack_free_hiwat;		/* free list count */
static unsigned int		stack_hiwat;
unsigned int			stack_total;				/* current total count */
unsigned long long		stack_allocs;				/* total count of allocations */

static int			stack_fake_zone_index = -1;	/* index in zone_info array */

static unsigned int		stack_free_target;
static int				stack_free_delta;

static unsigned int		stack_new_count;						/* total new stack allocations */

static vm_offset_t		stack_addr_mask;

unsigned int			kernel_stack_pages = KERNEL_STACK_SIZE / PAGE_SIZE;
vm_offset_t			kernel_stack_size = KERNEL_STACK_SIZE;
vm_offset_t			kernel_stack_mask = -KERNEL_STACK_SIZE;
vm_offset_t			kernel_stack_depth_max = 0;

static inline void
STACK_ZINFO_PALLOC(thread_t thread)
{
	task_t task;
	zinfo_usage_t zinfo;

	ledger_credit(thread->t_ledger, task_ledgers.tkm_private, kernel_stack_size);

	if (stack_fake_zone_index != -1 &&
	    (task = thread->task) != NULL && (zinfo = task->tkm_zinfo) != NULL)
		OSAddAtomic64(kernel_stack_size,
			      (int64_t *)&zinfo[stack_fake_zone_index].alloc);
}

static inline void
STACK_ZINFO_PFREE(thread_t thread)
{
	task_t task;
	zinfo_usage_t zinfo;

	ledger_debit(thread->t_ledger, task_ledgers.tkm_private, kernel_stack_size);

	if (stack_fake_zone_index != -1 &&
	    (task = thread->task) != NULL && (zinfo = task->tkm_zinfo) != NULL)
		OSAddAtomic64(kernel_stack_size, 
			      (int64_t *)&zinfo[stack_fake_zone_index].free);
}

static inline void
STACK_ZINFO_HANDOFF(thread_t from, thread_t to)
{
	ledger_debit(from->t_ledger, task_ledgers.tkm_private, kernel_stack_size);
	ledger_credit(to->t_ledger, task_ledgers.tkm_private, kernel_stack_size);

	if (stack_fake_zone_index != -1) {
		task_t task;
		zinfo_usage_t zinfo;
	
		if ((task = from->task) != NULL && (zinfo = task->tkm_zinfo) != NULL)
			OSAddAtomic64(kernel_stack_size, 
				      (int64_t *)&zinfo[stack_fake_zone_index].free);

		if ((task = to->task) != NULL && (zinfo = task->tkm_zinfo) != NULL)
			OSAddAtomic64(kernel_stack_size, 
				      (int64_t *)&zinfo[stack_fake_zone_index].alloc);
	}
}

/*
 *	The next field is at the base of the stack,
 *	so the low end is left unsullied.
 */
#define stack_next(stack)	\
	(*((vm_offset_t *)((stack) + kernel_stack_size) - 1))

static inline int
log2(vm_offset_t size)
{
	int	result;
	for (result = 0; size > 0; result++)
		size >>= 1;
	return result;
}

static inline vm_offset_t
roundup_pow2(vm_offset_t size)
{
	return 1UL << (log2(size - 1) + 1); 
}

static vm_offset_t stack_alloc_internal(void);
static void stack_free_stack(vm_offset_t);

void
stack_init(void)
{
	simple_lock_init(&stack_lock_data, 0);
	
	if (PE_parse_boot_argn("kernel_stack_pages",
			       &kernel_stack_pages,
			       sizeof (kernel_stack_pages))) {
		kernel_stack_size = kernel_stack_pages * PAGE_SIZE;
		printf("stack_init: kernel_stack_pages=%d kernel_stack_size=%p\n",
			kernel_stack_pages, (void *) kernel_stack_size);
	}

	if (kernel_stack_size < round_page(kernel_stack_size))
		panic("stack_init: stack size %p not a multiple of page size %d\n",
			(void *) kernel_stack_size, PAGE_SIZE);
	
	stack_addr_mask = roundup_pow2(kernel_stack_size) - 1;
	kernel_stack_mask = ~stack_addr_mask;
}

/*
 *	stack_alloc:
 *
 *	Allocate a stack for a thread, may
 *	block.
 */

static vm_offset_t 
stack_alloc_internal(void)
{
	vm_offset_t		stack;
	spl_t			s;
	int			guard_flags;

	s = splsched();
	stack_lock();
	stack_allocs++;
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

		/*
		 * Request guard pages on either side of the stack.  Ask
		 * kernel_memory_allocate() for two extra pages to account
		 * for these.
		 */

		guard_flags = KMA_GUARD_FIRST | KMA_GUARD_LAST;
		if (kernel_memory_allocate(kernel_map, &stack,
					   kernel_stack_size + (2*PAGE_SIZE),
					   stack_addr_mask,
					   KMA_KSTACK | KMA_KOBJECT | guard_flags)
		    != KERN_SUCCESS)
			panic("stack_alloc: kernel_memory_allocate");

		/*
		 * The stack address that comes back is the address of the lower
		 * guard page.  Skip past it to get the actual stack base address.
		 */

		stack += PAGE_SIZE;
	}
	return stack;
}

void
stack_alloc(
	thread_t	thread)
{

	assert(thread->kernel_stack == 0);
	machine_stack_attach(thread, stack_alloc_internal());
	STACK_ZINFO_PALLOC(thread);
}

void
stack_handoff(thread_t from, thread_t to)
{
	assert(from == current_thread());
	machine_stack_handoff(from, to);
	STACK_ZINFO_HANDOFF(from, to);
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
		STACK_ZINFO_PFREE(thread);
		stack_free_stack(stack);
	}
}

void
stack_free_reserved(
	thread_t	thread)
{
	if (thread->reserved_stack != thread->kernel_stack) {
		stack_free_stack(thread->reserved_stack);
		STACK_ZINFO_PFREE(thread);
	}
}

static void
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
		STACK_ZINFO_PALLOC(thread);
		cache->free = stack_next(stack);
		cache->count--;
	}
	else {
		if (stack_free_list != 0) {
			stack_lock();
			stack = stack_free_list;
			if (stack != 0) {
				STACK_ZINFO_PALLOC(thread);
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

			/*
			 * Get the stack base address, then decrement by one page
			 * to account for the lower guard page.  Add two extra pages
			 * to the size to account for the guard pages on both ends
			 * that were originally requested when the stack was allocated
			 * back in stack_alloc().
			 */

			stack = (vm_offset_t)vm_map_trunc_page(stack);
			stack -= PAGE_SIZE;
			if (vm_map_remove(
				    kernel_map,
				    stack,
				    stack + kernel_stack_size+(2*PAGE_SIZE),
				    VM_MAP_REMOVE_KUNWIRE)
			    != KERN_SUCCESS)
				panic("stack_collect: vm_map_remove");
			stack = 0;

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
stack_fake_zone_init(int zone_index)
{
	stack_fake_zone_index = zone_index;
}

void
stack_fake_zone_info(int *count, 
		     vm_size_t *cur_size, vm_size_t *max_size, vm_size_t *elem_size, vm_size_t *alloc_size,
		     uint64_t *sum_size, int *collectable, int *exhaustable, int *caller_acct)
{
	unsigned int	total, hiwat, free;
	unsigned long long all;
	spl_t			s;

	s = splsched();
	stack_lock();
	all = stack_allocs;
	total = stack_total;
	hiwat = stack_hiwat;
	free = stack_free_count;
	stack_unlock();
	splx(s);

	*count      = total - free;
	*cur_size   = kernel_stack_size * total;
	*max_size   = kernel_stack_size * hiwat;
	*elem_size  = kernel_stack_size;
	*alloc_size = kernel_stack_size;
	*sum_size = all * kernel_stack_size;

	*collectable = 1;
	*exhaustable = 0;
	*caller_acct = 1;
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

	register thread_t *thread_list;
	register thread_t thread;

	unsigned int actual;	/* this many things */
	unsigned int i;

	vm_size_t size, size_needed;
	void *addr;

	if (pset == PROCESSOR_SET_NULL || pset != &pset0)
		return KERN_INVALID_ARGUMENT;

	size = 0;
	addr = NULL;

	for (;;) {
		lck_mtx_lock(&tasks_threads_lock);

		actual = threads_count;

		/* do we have the memory we need? */

		size_needed = actual * sizeof(thread_t);
		if (size_needed <= size)
			break;

		lck_mtx_unlock(&tasks_threads_lock);

		if (size != 0)
			kfree(addr, size);

		assert(size_needed > 0);
		size = size_needed;

		addr = kalloc(size);
		if (addr == 0)
			return KERN_RESOURCE_SHORTAGE;
	}

	/* OK, have memory and list is locked */
	thread_list = (thread_t *) addr;
	for (i = 0, thread = (thread_t) queue_first(&threads);
					!queue_end(&threads, (queue_entry_t) thread);
					thread = (thread_t) queue_next(&thread->threads)) {
		thread_reference_internal(thread);
		thread_list[i++] = thread;
	}
	assert(i <= actual);

	lck_mtx_unlock(&tasks_threads_lock);

	/* calculate maxusage and free thread references */

	total = 0;
	maxusage = 0;
	maxstack = 0;
	while (i > 0) {
		thread_t threadref = thread_list[--i];

		if (threadref->kernel_stack != 0)
			total++;

		thread_deallocate(threadref);
	}

	if (size != 0)
		kfree(addr, size);

	*totalp = total;
	*residentp = *spacep = total * round_page(kernel_stack_size);
	*maxusagep = maxusage;
	*maxstackp = maxstack;
	return KERN_SUCCESS;

#endif	/* MACH_DEBUG */
}

vm_offset_t min_valid_stack_address(void)
{
	return (vm_offset_t)vm_map_min(kernel_map);
}

vm_offset_t max_valid_stack_address(void)
{
	return (vm_offset_t)vm_map_max(kernel_map);
}

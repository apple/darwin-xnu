/*
 * Copyright (c) 2009 Apple Inc. All rights reserved.
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
#include <mach/machine.h>
#include <mach/policy.h>
#include <mach/sync_policy.h>
#include <mach/thread_act.h>

#include <machine/machine_routines.h>
#include <machine/sched_param.h>
#include <machine/machine_cpu.h>

#include <kern/kern_types.h>
#include <kern/clock.h>
#include <kern/counters.h>
#include <kern/cpu_number.h>
#include <kern/cpu_data.h>
#include <kern/debug.h>
#include <kern/lock.h>
#include <kern/macro_help.h>
#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/processor.h>
#include <kern/queue.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/syscall_subr.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/wait_queue.h>

#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>

#include <mach/sdt.h>

#include <sys/kdebug.h>

static void
sched_fixedpriority_init(void);

static void
sched_fixedpriority_with_pset_runqueue_init(void);

static void
sched_fixedpriority_timebase_init(void);

static void
sched_fixedpriority_processor_init(processor_t processor);

static void
sched_fixedpriority_pset_init(processor_set_t pset);

static void
sched_fixedpriority_maintenance_continuation(void);

static thread_t
sched_fixedpriority_choose_thread(processor_t		processor,
							 int				priority);

static thread_t
sched_fixedpriority_steal_thread(processor_set_t		pset);

static void
sched_fixedpriority_compute_priority(thread_t	thread,
							 boolean_t			override_depress);

static processor_t
sched_fixedpriority_choose_processor(	processor_set_t		pset,
								processor_t			processor,
								thread_t			thread);


static boolean_t
sched_fixedpriority_processor_enqueue(
							 processor_t			processor,
							 thread_t			thread,
							 integer_t			options);

static void
sched_fixedpriority_processor_queue_shutdown(
									 processor_t			processor);

static boolean_t
sched_fixedpriority_processor_queue_remove(
						    processor_t			processor,
							thread_t		thread);

static boolean_t
sched_fixedpriority_processor_queue_empty(processor_t		processor);

static boolean_t
sched_fixedpriority_processor_queue_has_priority(processor_t		processor,
										 int				priority,
										 boolean_t		gte);

static boolean_t
sched_fixedpriority_priority_is_urgent(int priority);

static ast_t
sched_fixedpriority_processor_csw_check(processor_t processor);

static uint32_t
sched_fixedpriority_initial_quantum_size(thread_t thread);

static sched_mode_t
sched_fixedpriority_initial_thread_sched_mode(task_t parent_task);

static boolean_t
sched_fixedpriority_supports_timeshare_mode(void);

static boolean_t
sched_fixedpriority_can_update_priority(thread_t	thread);

static void
sched_fixedpriority_update_priority(thread_t	thread);

static void
sched_fixedpriority_lightweight_update_priority(thread_t	thread);

static void
sched_fixedpriority_quantum_expire(thread_t	thread);

static boolean_t
sched_fixedpriority_should_current_thread_rechoose_processor(processor_t			processor);

static int
sched_fixedpriority_processor_runq_count(processor_t	processor);

static uint64_t
sched_fixedpriority_processor_runq_stats_count_sum(processor_t   processor);

const struct sched_dispatch_table sched_fixedpriority_dispatch = {
	sched_fixedpriority_init,
	sched_fixedpriority_timebase_init,
	sched_fixedpriority_processor_init,
	sched_fixedpriority_pset_init,
	sched_fixedpriority_maintenance_continuation,
	sched_fixedpriority_choose_thread,
	sched_fixedpriority_steal_thread,
	sched_fixedpriority_compute_priority,
	sched_fixedpriority_choose_processor,
	sched_fixedpriority_processor_enqueue,
	sched_fixedpriority_processor_queue_shutdown,
	sched_fixedpriority_processor_queue_remove,
	sched_fixedpriority_processor_queue_empty,
	sched_fixedpriority_priority_is_urgent,
	sched_fixedpriority_processor_csw_check,
	sched_fixedpriority_processor_queue_has_priority,
	sched_fixedpriority_initial_quantum_size,
	sched_fixedpriority_initial_thread_sched_mode,
	sched_fixedpriority_supports_timeshare_mode,
	sched_fixedpriority_can_update_priority,
	sched_fixedpriority_update_priority,
	sched_fixedpriority_lightweight_update_priority,
	sched_fixedpriority_quantum_expire,
	sched_fixedpriority_should_current_thread_rechoose_processor,
	sched_fixedpriority_processor_runq_count,
	sched_fixedpriority_processor_runq_stats_count_sum,
	sched_traditional_fairshare_init,
	sched_traditional_fairshare_runq_count,
	sched_traditional_fairshare_runq_stats_count_sum,
	sched_traditional_fairshare_enqueue,
	sched_traditional_fairshare_dequeue,
	sched_traditional_fairshare_queue_remove,
	TRUE /* direct_dispatch_to_idle_processors */
};

const struct sched_dispatch_table sched_fixedpriority_with_pset_runqueue_dispatch = {
	sched_fixedpriority_with_pset_runqueue_init,
	sched_fixedpriority_timebase_init,
	sched_fixedpriority_processor_init,
	sched_fixedpriority_pset_init,
	sched_fixedpriority_maintenance_continuation,
	sched_fixedpriority_choose_thread,
	sched_fixedpriority_steal_thread,
	sched_fixedpriority_compute_priority,
	sched_fixedpriority_choose_processor,
	sched_fixedpriority_processor_enqueue,
	sched_fixedpriority_processor_queue_shutdown,
	sched_fixedpriority_processor_queue_remove,
	sched_fixedpriority_processor_queue_empty,
	sched_fixedpriority_priority_is_urgent,
	sched_fixedpriority_processor_csw_check,
	sched_fixedpriority_processor_queue_has_priority,
	sched_fixedpriority_initial_quantum_size,
	sched_fixedpriority_initial_thread_sched_mode,
	sched_fixedpriority_supports_timeshare_mode,
	sched_fixedpriority_can_update_priority,
	sched_fixedpriority_update_priority,
	sched_fixedpriority_lightweight_update_priority,
	sched_fixedpriority_quantum_expire,
	sched_fixedpriority_should_current_thread_rechoose_processor,
	sched_fixedpriority_processor_runq_count,
	sched_fixedpriority_processor_runq_stats_count_sum,
	sched_traditional_fairshare_init,
	sched_traditional_fairshare_runq_count,
	sched_traditional_fairshare_runq_stats_count_sum,
	sched_traditional_fairshare_enqueue,
	sched_traditional_fairshare_dequeue,
	sched_traditional_fairshare_queue_remove,
	FALSE /* direct_dispatch_to_idle_processors */
};

extern int	max_unsafe_quanta;

#define		SCHED_FIXEDPRIORITY_DEFAULT_QUANTUM		5		/* in ms */
static uint32_t sched_fixedpriority_quantum_ms = SCHED_FIXEDPRIORITY_DEFAULT_QUANTUM;
static uint32_t sched_fixedpriority_quantum;

#define SCHED_FIXEDPRIORITY_DEFAULT_FAIRSHARE_MINIMUM_BLOCK_TIME 100 /* ms */
static uint32_t fairshare_minimum_blocked_time_ms = SCHED_FIXEDPRIORITY_DEFAULT_FAIRSHARE_MINIMUM_BLOCK_TIME;
static uint32_t fairshare_minimum_blocked_time;

static uint32_t			sched_fixedpriority_tick;
static uint64_t			sched_fixedpriority_tick_deadline;
extern uint32_t			grrr_rescale_tick;

static boolean_t sched_fixedpriority_use_pset_runqueue = FALSE;

__attribute__((always_inline))
static inline run_queue_t runq_for_processor(processor_t processor)
{
	if (sched_fixedpriority_use_pset_runqueue)
		return &processor->processor_set->pset_runq;
	else
		return &processor->runq;
}

__attribute__((always_inline))
static inline void runq_consider_incr_bound_count(processor_t processor, thread_t thread)
{
	if (thread->bound_processor == PROCESSOR_NULL)
		return;
    
	assert(thread->bound_processor == processor);
    
	if (sched_fixedpriority_use_pset_runqueue)
		processor->processor_set->pset_runq_bound_count++;
    
	processor->runq_bound_count++;
}

__attribute__((always_inline))
static inline void runq_consider_decr_bound_count(processor_t processor, thread_t thread)
{
	if (thread->bound_processor == PROCESSOR_NULL)
		return;
    
	assert(thread->bound_processor == processor);
    
	if (sched_fixedpriority_use_pset_runqueue)
		processor->processor_set->pset_runq_bound_count--;
    
	processor->runq_bound_count--;
}

static void
sched_fixedpriority_init(void)
{
	if (!PE_parse_boot_argn("fixedpriority_quantum", &sched_fixedpriority_quantum_ms, sizeof (sched_fixedpriority_quantum_ms))) {
		sched_fixedpriority_quantum_ms = SCHED_FIXEDPRIORITY_DEFAULT_QUANTUM;
	}
	
	if (sched_fixedpriority_quantum_ms < 1)
		sched_fixedpriority_quantum_ms = SCHED_FIXEDPRIORITY_DEFAULT_QUANTUM;
	
	printf("standard fixed priority timeslicing quantum is %u ms\n", sched_fixedpriority_quantum_ms);
}

static void
sched_fixedpriority_with_pset_runqueue_init(void)
{
	sched_fixedpriority_init();
	sched_fixedpriority_use_pset_runqueue = TRUE;
}

static void
sched_fixedpriority_timebase_init(void)
{
	uint64_t	abstime;

	/* standard timeslicing quantum */
	clock_interval_to_absolutetime_interval(
											sched_fixedpriority_quantum_ms, NSEC_PER_MSEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	sched_fixedpriority_quantum = (uint32_t)abstime;
	
	thread_depress_time = 1 * sched_fixedpriority_quantum;
	default_timeshare_computation = sched_fixedpriority_quantum / 2;
	default_timeshare_constraint = sched_fixedpriority_quantum;
	
	max_unsafe_computation = max_unsafe_quanta * sched_fixedpriority_quantum;
	sched_safe_duration = 2 * max_unsafe_quanta * sched_fixedpriority_quantum;

	if (!PE_parse_boot_argn("fairshare_minblockedtime", &fairshare_minimum_blocked_time_ms, sizeof (fairshare_minimum_blocked_time_ms))) {
		fairshare_minimum_blocked_time_ms = SCHED_FIXEDPRIORITY_DEFAULT_FAIRSHARE_MINIMUM_BLOCK_TIME;
	}
	
	clock_interval_to_absolutetime_interval(
											fairshare_minimum_blocked_time_ms, NSEC_PER_MSEC, &abstime);
	
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	fairshare_minimum_blocked_time = (uint32_t)abstime;
}

static void
sched_fixedpriority_processor_init(processor_t processor)
{
	if (!sched_fixedpriority_use_pset_runqueue) {
		run_queue_init(&processor->runq);
	}
	processor->runq_bound_count = 0;
}

static void
sched_fixedpriority_pset_init(processor_set_t pset)
{
	if (sched_fixedpriority_use_pset_runqueue) {
		run_queue_init(&pset->pset_runq);
	}
	pset->pset_runq_bound_count = 0;
}


static void
sched_fixedpriority_maintenance_continuation(void)
{
	uint64_t			abstime = mach_absolute_time();
	
	sched_fixedpriority_tick++;
	grrr_rescale_tick++;
    
	/*
	 *  Compute various averages.
	 */
	compute_averages();
	
	if (sched_fixedpriority_tick_deadline == 0)
		sched_fixedpriority_tick_deadline = abstime;
	
	clock_deadline_for_periodic_event(10*sched_one_second_interval, abstime,
						&sched_fixedpriority_tick_deadline);
	
	assert_wait_deadline((event_t)sched_fixedpriority_maintenance_continuation, THREAD_UNINT, sched_fixedpriority_tick_deadline);
	thread_block((thread_continue_t)sched_fixedpriority_maintenance_continuation);
	/*NOTREACHED*/
}


static thread_t
sched_fixedpriority_choose_thread(processor_t		processor,
						  int				priority)
{
	thread_t thread;
	
	thread = choose_thread(processor, runq_for_processor(processor), priority);
	if (thread != THREAD_NULL) {
		runq_consider_decr_bound_count(processor, thread);
	}
	
	return thread;
}

static thread_t
sched_fixedpriority_steal_thread(processor_set_t		pset)
{
	pset_unlock(pset);
	
	return (THREAD_NULL);
	
}

static void
sched_fixedpriority_compute_priority(thread_t	thread,
							 boolean_t			override_depress)
{
	/* Reset current priority to base priority */
	if (	!(thread->sched_flags & TH_SFLAG_PROMOTED)			&&
		(!(thread->sched_flags & TH_SFLAG_DEPRESSED_MASK)	||
		 override_depress							)		) {
			set_sched_pri(thread, thread->priority);
		}
}

static processor_t
sched_fixedpriority_choose_processor(	processor_set_t		pset,
							 processor_t			processor,
							 thread_t			thread)
{
	return choose_processor(pset, processor, thread);
}
static boolean_t
sched_fixedpriority_processor_enqueue(
							 processor_t			processor,
							 thread_t			thread,
							 integer_t			options)
{
	run_queue_t		rq = runq_for_processor(processor);
	boolean_t		result;
	
	result = run_queue_enqueue(rq, thread, options);
	thread->runq = processor;
	runq_consider_incr_bound_count(processor, thread);

	return (result);
}

static void
sched_fixedpriority_processor_queue_shutdown(
									 processor_t			processor)
{
	processor_set_t		pset = processor->processor_set;
	thread_t			thread;
	queue_head_t		tqueue, bqueue;
	
	queue_init(&tqueue);
	queue_init(&bqueue);
	
	while ((thread = sched_fixedpriority_choose_thread(processor, IDLEPRI)) != THREAD_NULL) {
		if (thread->bound_processor == PROCESSOR_NULL) {
			enqueue_tail(&tqueue, (queue_entry_t)thread);
		} else {
			enqueue_tail(&bqueue, (queue_entry_t)thread);				
		}
	}
	
	while ((thread = (thread_t)dequeue_head(&bqueue)) != THREAD_NULL) {
		sched_fixedpriority_processor_enqueue(processor, thread, SCHED_TAILQ);
	}	
	
	pset_unlock(pset);
	
	while ((thread = (thread_t)dequeue_head(&tqueue)) != THREAD_NULL) {
		thread_lock(thread);
		
		thread_setrun(thread, SCHED_TAILQ);
		
		thread_unlock(thread);
	}
}

static boolean_t
sched_fixedpriority_processor_queue_remove(
								processor_t			processor,
								thread_t		thread)
{
	void *			rqlock;
	run_queue_t		rq;

	rqlock = &processor->processor_set->sched_lock;
	rq = runq_for_processor(processor);

	simple_lock(rqlock);
	if (processor == thread->runq) {
		/*
		 *	Thread is on a run queue and we have a lock on
		 *	that run queue.
		 */
		runq_consider_decr_bound_count(processor, thread);
		run_queue_remove(rq, thread);
	}
	else {
		/*
		 *	The thread left the run queue before we could
		 * 	lock the run queue.
		 */
		assert(thread->runq == PROCESSOR_NULL);
		processor = PROCESSOR_NULL;
	}
	
	simple_unlock(rqlock);
	
	return (processor != PROCESSOR_NULL);
}

static boolean_t
sched_fixedpriority_processor_queue_empty(processor_t		processor)
{
	/*
	 * See sched_traditional_with_pset_runqueue_processor_queue_empty
	 * for algorithm
	 */
	int count = runq_for_processor(processor)->count;

	if (sched_fixedpriority_use_pset_runqueue) {
		processor_set_t pset = processor->processor_set;

		count -= pset->pset_runq_bound_count;
		count += processor->runq_bound_count;
	}
	
	return count == 0;
}

static boolean_t
sched_fixedpriority_processor_queue_has_priority(processor_t		processor,
										 int				priority,
										 boolean_t		gte)
{
	if (gte)
		return runq_for_processor(processor)->highq >= priority;
	else
		return runq_for_processor(processor)->highq > priority;
}

/* Implement sched_preempt_pri in code */
static boolean_t
sched_fixedpriority_priority_is_urgent(int priority)
{
	if (priority <= BASEPRI_FOREGROUND)
		return FALSE;
	
	if (priority < MINPRI_KERNEL)
		return TRUE;

	if (priority >= BASEPRI_PREEMPT)
		return TRUE;
	
	return FALSE;
}

static ast_t
sched_fixedpriority_processor_csw_check(processor_t processor)
{
	run_queue_t		runq;
	
	runq = runq_for_processor(processor);
	if (runq->highq > processor->current_pri) {
		if (runq->urgency > 0)
			return (AST_PREEMPT | AST_URGENT);

		if (processor->active_thread && thread_eager_preemption(processor->active_thread))
			return (AST_PREEMPT | AST_URGENT);
		
		return AST_PREEMPT;
	} else if (processor->current_thmode == TH_MODE_FAIRSHARE) {
		if (!sched_fixedpriority_processor_queue_empty(processor)) {
			/* Allow queued threads to run if the current thread got demoted to fairshare */
			return (AST_PREEMPT | AST_URGENT);
		} else if ((!first_timeslice(processor)) && SCHED(fairshare_runq_count)() > 0) {
			/* Allow other fairshare threads to run */
			return AST_PREEMPT | AST_URGENT;
		}
	}
	
	return AST_NONE;
}

static uint32_t
sched_fixedpriority_initial_quantum_size(thread_t thread __unused)
{
	return sched_fixedpriority_quantum;
}

static sched_mode_t
sched_fixedpriority_initial_thread_sched_mode(task_t parent_task)
{
	if (parent_task == kernel_task)
		return TH_MODE_FIXED;
	else
		return TH_MODE_TIMESHARE;
}

static boolean_t
sched_fixedpriority_supports_timeshare_mode(void)
{
	return TRUE;
}

static boolean_t
sched_fixedpriority_can_update_priority(thread_t	thread __unused)
{
	return ((thread->sched_flags & TH_SFLAG_PRI_UPDATE) == 0);
}

static void
sched_fixedpriority_update_priority(thread_t	thread)
{
	uint64_t current_time = mach_absolute_time();

	thread->sched_flags |= TH_SFLAG_PRI_UPDATE;

	if (thread->sched_flags & TH_SFLAG_FAIRSHARE_TRIPPED) {
		
		/*
		 * Make sure we've waited fairshare_minimum_blocked_time both from the time
		 * we were throttled into the fairshare band, and the last time
		 * we ran.
		 */
		if (current_time >= thread->last_run_time + fairshare_minimum_blocked_time) {
			
			boolean_t		removed = thread_run_queue_remove(thread);
						
			thread->sched_flags &= ~TH_SFLAG_FAIRSHARE_TRIPPED;
			thread->sched_mode = thread->saved_mode;
			thread->saved_mode = TH_MODE_NONE;
			
			if (removed)
				thread_setrun(thread, SCHED_TAILQ);

			KERNEL_DEBUG_CONSTANT1(
								   MACHDBG_CODE(DBG_MACH_SCHED,MACH_FAIRSHARE_EXIT) | DBG_FUNC_NONE, (uint32_t)(thread->last_run_time & 0xFFFFFFFF), (uint32_t)(thread->last_run_time >> 32), (uint32_t)(current_time & 0xFFFFFFFF), (uint32_t)(current_time >> 32), thread_tid(thread));

		}
	} else if ((thread->sched_flags & TH_SFLAG_DEPRESSED_MASK) && (thread->bound_processor == PROCESSOR_NULL)) {
		boolean_t		removed = thread_run_queue_remove(thread);
		
		thread->sched_flags |= TH_SFLAG_FAIRSHARE_TRIPPED;
		thread->saved_mode = thread->sched_mode;
		thread->sched_mode = TH_MODE_FAIRSHARE;
		
		thread->last_quantum_refill_time = thread->last_run_time - 2 * sched_fixedpriority_quantum - 1;
		
		if (removed)
			thread_setrun(thread, SCHED_TAILQ);

		KERNEL_DEBUG_CONSTANT(
							   MACHDBG_CODE(DBG_MACH_SCHED,MACH_FAIRSHARE_ENTER) | DBG_FUNC_NONE, (uintptr_t)thread_tid(thread), 0xFFFFFFFF, 0, 0, 0);

	}
	
	/*
	 *	Check for fail-safe release.
	 */
	if (	(thread->sched_flags & TH_SFLAG_FAILSAFE)		&&
		current_time >= thread->safe_release		) {
		
		
		thread->sched_flags &= ~TH_SFLAG_FAILSAFE;
		
		if (!(thread->sched_flags & TH_SFLAG_DEMOTED_MASK)) {
			/* Restore to previous */
			
			thread->sched_mode = thread->saved_mode;
			thread->saved_mode = TH_MODE_NONE;
			
			if (thread->sched_mode == TH_MODE_REALTIME) {
				thread->priority = BASEPRI_RTQUEUES;
				
			}
			
			if (!(thread->sched_flags & TH_SFLAG_DEPRESSED_MASK))
				set_sched_pri(thread, thread->priority);
		}
	}
	
	thread->sched_flags &= ~TH_SFLAG_PRI_UPDATE;
	return;
}

static void
sched_fixedpriority_lightweight_update_priority(thread_t	thread __unused)
{
	return;
}

static void
sched_fixedpriority_quantum_expire(
						  thread_t	thread)
{
	/* Put thread into fairshare class, core scheduler will manage runqueue */
	if ((thread->sched_mode == TH_MODE_TIMESHARE) && (thread->task != kernel_task) && !(thread->sched_flags & TH_SFLAG_DEMOTED_MASK)) {
		uint64_t elapsed = thread->last_run_time - thread->last_quantum_refill_time;
		
		/* If we managed to use our quantum in less than 2*quantum wall clock time,
		 * we are considered CPU bound and eligible for demotion. Since the quantum
		 * is reset when thread_unblock() is called, we are only really considering
		 * threads that elongate their execution time due to preemption.
		 */
		if ((elapsed < 2 * sched_fixedpriority_quantum) && (thread->bound_processor == PROCESSOR_NULL)) {
		
			thread->saved_mode = thread->sched_mode;
			thread->sched_mode = TH_MODE_FAIRSHARE;
			thread->sched_flags |= TH_SFLAG_FAIRSHARE_TRIPPED;
			KERNEL_DEBUG_CONSTANT(
							  MACHDBG_CODE(DBG_MACH_SCHED,MACH_FAIRSHARE_ENTER) | DBG_FUNC_NONE, (uintptr_t)thread_tid(thread), (uint32_t)(elapsed & 0xFFFFFFFF), (uint32_t)(elapsed >> 32), 0, 0);
		}
	}
}


static boolean_t
sched_fixedpriority_should_current_thread_rechoose_processor(processor_t			processor __unused)
{
	return (TRUE);
}


static int
sched_fixedpriority_processor_runq_count(processor_t	processor)
{
	return runq_for_processor(processor)->count;
}

static uint64_t
sched_fixedpriority_processor_runq_stats_count_sum(processor_t	processor)
{
	return runq_for_processor(processor)->runq_stats.count_sum;
}

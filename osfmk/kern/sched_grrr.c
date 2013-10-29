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

#if defined(CONFIG_SCHED_GRRR_CORE)

static void
grrr_priority_mapping_init(void);

static boolean_t
grrr_enqueue(
				   grrr_run_queue_t			rq,
				   thread_t			thread);
				   
static thread_t
grrr_select(
					grrr_run_queue_t	rq);

static void
grrr_remove(
				  grrr_run_queue_t			rq,
				  thread_t		thread);


static void
grrr_sorted_list_insert_group(grrr_run_queue_t rq,
									grrr_group_t group);

static void
grrr_rescale_work(grrr_run_queue_t rq);

static void
grrr_runqueue_init(grrr_run_queue_t		runq);

/* Map Mach priorities to ones suitable for proportional sharing */
static grrr_proportional_priority_t grrr_priority_mapping[NRQS];

/* Map each proportional priority to its group */
static grrr_group_index_t grrr_group_mapping[NUM_GRRR_PROPORTIONAL_PRIORITIES];

uint32_t			grrr_rescale_tick;

#endif /* defined(CONFIG_SCHED_GRRR_CORE) */

#if defined(CONFIG_SCHED_GRRR)

static void
sched_grrr_init(void);

static void
sched_grrr_timebase_init(void);

static void
sched_grrr_processor_init(processor_t processor);

static void
sched_grrr_pset_init(processor_set_t pset);

static void
sched_grrr_maintenance_continuation(void);

static thread_t
sched_grrr_choose_thread(processor_t		processor,
							 int				priority);

static thread_t
sched_grrr_steal_thread(processor_set_t		pset);

static void
sched_grrr_compute_priority(thread_t	thread,
							 boolean_t			override_depress);

static processor_t
sched_grrr_choose_processor(	processor_set_t		pset,
								processor_t			processor,
								thread_t			thread);

static boolean_t
sched_grrr_processor_enqueue(
							 processor_t			processor,
							 thread_t			thread,
							 integer_t			options);

static void
sched_grrr_processor_queue_shutdown(
									 processor_t			processor);

static boolean_t
sched_grrr_processor_queue_remove(
						    processor_t			processor,
							thread_t		thread);

static boolean_t
sched_grrr_processor_queue_empty(processor_t		processor);

static boolean_t
sched_grrr_processor_queue_has_priority(processor_t		processor,
										 int				priority,
										 boolean_t		gte);

static boolean_t
sched_grrr_priority_is_urgent(int priority);

static ast_t
sched_grrr_processor_csw_check(processor_t processor);

static uint32_t
sched_grrr_initial_quantum_size(thread_t thread);

static sched_mode_t
sched_grrr_initial_thread_sched_mode(task_t parent_task);

static boolean_t
sched_grrr_supports_timeshare_mode(void);

static boolean_t
sched_grrr_can_update_priority(thread_t	thread);

static void
sched_grrr_update_priority(thread_t	thread);

static void
sched_grrr_lightweight_update_priority(thread_t	thread);

static void
sched_grrr_quantum_expire(thread_t	thread);

static boolean_t
sched_grrr_should_current_thread_rechoose_processor(processor_t			processor);

static int
sched_grrr_processor_runq_count(processor_t	processor);

static uint64_t
sched_grrr_processor_runq_stats_count_sum(processor_t   processor);

const struct sched_dispatch_table sched_grrr_dispatch = {
	sched_grrr_init,
	sched_grrr_timebase_init,
	sched_grrr_processor_init,
	sched_grrr_pset_init,
	sched_grrr_maintenance_continuation,
	sched_grrr_choose_thread,
	sched_grrr_steal_thread,
	sched_grrr_compute_priority,
	sched_grrr_choose_processor,
	sched_grrr_processor_enqueue,
	sched_grrr_processor_queue_shutdown,
	sched_grrr_processor_queue_remove,
	sched_grrr_processor_queue_empty,
	sched_grrr_priority_is_urgent,
	sched_grrr_processor_csw_check,
	sched_grrr_processor_queue_has_priority,
	sched_grrr_initial_quantum_size,
	sched_grrr_initial_thread_sched_mode,
	sched_grrr_supports_timeshare_mode,
	sched_grrr_can_update_priority,
	sched_grrr_update_priority,
	sched_grrr_lightweight_update_priority,
	sched_grrr_quantum_expire,
	sched_grrr_should_current_thread_rechoose_processor,
	sched_grrr_processor_runq_count,
	sched_grrr_processor_runq_stats_count_sum,
	sched_grrr_fairshare_init,
	sched_grrr_fairshare_runq_count,
	sched_grrr_fairshare_runq_stats_count_sum,
	sched_grrr_fairshare_enqueue,
	sched_grrr_fairshare_dequeue,
	sched_grrr_fairshare_queue_remove,
	TRUE /* direct_dispatch_to_idle_processors */
};

extern int	max_unsafe_quanta;

static uint32_t grrr_quantum_us;
static uint32_t grrr_quantum;

static uint64_t			sched_grrr_tick_deadline;

static void
sched_grrr_init(void)
{
	if (default_preemption_rate < 1)
		default_preemption_rate = 100;
	grrr_quantum_us = (1000 * 1000) / default_preemption_rate;
	
	printf("standard grrr timeslicing quantum is %d us\n", grrr_quantum_us);

	grrr_priority_mapping_init();
}

static void
sched_grrr_timebase_init(void)
{
	uint64_t	abstime;

	/* standard timeslicing quantum */
	clock_interval_to_absolutetime_interval(
											grrr_quantum_us, NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	grrr_quantum = (uint32_t)abstime;
	
	thread_depress_time = 1 * grrr_quantum;
	default_timeshare_computation = grrr_quantum / 2;
	default_timeshare_constraint = grrr_quantum;
	
	max_unsafe_computation = max_unsafe_quanta * grrr_quantum;
	sched_safe_duration = 2 * max_unsafe_quanta * grrr_quantum;

}

static void
sched_grrr_processor_init(processor_t processor)
{
	grrr_runqueue_init(&processor->grrr_runq);
}

static void
sched_grrr_pset_init(processor_set_t pset __unused)
{
}

static void
sched_grrr_maintenance_continuation(void)
{
	uint64_t			abstime = mach_absolute_time();
	
	grrr_rescale_tick++;
    
	/*
	 *  Compute various averages.
	 */
	compute_averages(1);
	
	if (sched_grrr_tick_deadline == 0)
		sched_grrr_tick_deadline = abstime;
	
	clock_deadline_for_periodic_event(10*sched_one_second_interval, abstime,
						&sched_grrr_tick_deadline);
	
	assert_wait_deadline((event_t)sched_grrr_maintenance_continuation, THREAD_UNINT, sched_grrr_tick_deadline);
	thread_block((thread_continue_t)sched_grrr_maintenance_continuation);
	/*NOTREACHED*/
}


static thread_t
sched_grrr_choose_thread(processor_t		processor,
						  int				priority __unused)
{
	grrr_run_queue_t		rq = &processor->grrr_runq;
	
	return 	grrr_select(rq);
}

static thread_t
sched_grrr_steal_thread(processor_set_t		pset)
{
	pset_unlock(pset);
	
	return (THREAD_NULL);
	
}

static void
sched_grrr_compute_priority(thread_t	thread,
							 boolean_t			override_depress __unused)
{
	set_sched_pri(thread, thread->priority);
}

static processor_t
sched_grrr_choose_processor(	processor_set_t		pset,
							 processor_t			processor,
							 thread_t			thread)
{
	return choose_processor(pset, processor, thread);
}

static boolean_t
sched_grrr_processor_enqueue(
							 processor_t			processor,
							 thread_t			thread,
							 integer_t			options __unused)
{
	grrr_run_queue_t		rq = &processor->grrr_runq;
	boolean_t				result;
	
	result = grrr_enqueue(rq, thread);
	
	thread->runq = processor;
	
	return result;
}

static void
sched_grrr_processor_queue_shutdown(
									 processor_t			processor)
{
	processor_set_t		pset = processor->processor_set;
	thread_t			thread;
	queue_head_t		tqueue, bqueue;
	
	queue_init(&tqueue);
	queue_init(&bqueue);
	
	while ((thread = sched_grrr_choose_thread(processor, IDLEPRI)) != THREAD_NULL) {
		if (thread->bound_processor == PROCESSOR_NULL) {
			enqueue_tail(&tqueue, (queue_entry_t)thread);
		} else {
			enqueue_tail(&bqueue, (queue_entry_t)thread);				
		}
	}
	
	while ((thread = (thread_t)(void *)dequeue_head(&bqueue)) != THREAD_NULL) {
		sched_grrr_processor_enqueue(processor, thread, SCHED_TAILQ);
	}	
	
	pset_unlock(pset);
	
	while ((thread = (thread_t)(void *)dequeue_head(&tqueue)) != THREAD_NULL) {
		thread_lock(thread);
		
		thread_setrun(thread, SCHED_TAILQ);
		
		thread_unlock(thread);
	}
}

static boolean_t
sched_grrr_processor_queue_remove(
								processor_t			processor,
								thread_t		thread)
{
	void *			rqlock;
	
	rqlock = &processor->processor_set->sched_lock;
	simple_lock(rqlock);
	
	if (processor == thread->runq) {
		/*
		 *	Thread is on a run queue and we have a lock on
		 *	that run queue.
		 */
		grrr_run_queue_t		rq = &processor->grrr_runq;

		grrr_remove(rq, thread);
	} else {
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
sched_grrr_processor_queue_empty(processor_t		processor __unused)
{
	boolean_t result;
	
	result = (processor->grrr_runq.count == 0);
	
	return result;
}

static boolean_t
sched_grrr_processor_queue_has_priority(processor_t		processor,
										 int				priority,
										 boolean_t		gte __unused)
{
	grrr_run_queue_t		rq = &processor->grrr_runq;
	unsigned int	i;

	i = grrr_group_mapping[grrr_priority_mapping[priority]];
	for ( ; i < NUM_GRRR_GROUPS; i++) {
		if (rq->groups[i].count > 0)
			return (TRUE);
	}
	
	return (FALSE);
}

/* Implement sched_preempt_pri in code */
static boolean_t
sched_grrr_priority_is_urgent(int priority)
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
sched_grrr_processor_csw_check(processor_t processor)
{
	int				count;
	
	count = sched_grrr_processor_runq_count(processor);
	
	if (count > 0) {
		
		return AST_PREEMPT;
	}
	
	return AST_NONE;
}

static uint32_t
sched_grrr_initial_quantum_size(thread_t thread __unused)
{
	return grrr_quantum;
}

static sched_mode_t
sched_grrr_initial_thread_sched_mode(task_t parent_task)
{
	if (parent_task == kernel_task)
		return TH_MODE_FIXED;
	else
		return TH_MODE_TIMESHARE;	
}

static boolean_t
sched_grrr_supports_timeshare_mode(void)
{
	return TRUE;
}

static boolean_t
sched_grrr_can_update_priority(thread_t	thread __unused)
{
	return FALSE;
}

static void
sched_grrr_update_priority(thread_t	thread __unused)
{
	
}

static void
sched_grrr_lightweight_update_priority(thread_t	thread __unused)
{
	return;
}

static void
sched_grrr_quantum_expire(
						  thread_t	thread __unused)
{
}


static boolean_t
sched_grrr_should_current_thread_rechoose_processor(processor_t			processor __unused)
{
	return (TRUE);
}

static int
sched_grrr_processor_runq_count(processor_t	processor)
{
	return processor->grrr_runq.count;
}

static uint64_t
sched_grrr_processor_runq_stats_count_sum(processor_t	processor)
{
	return processor->grrr_runq.runq_stats.count_sum;
}

#endif /* defined(CONFIG_SCHED_GRRR) */

#if defined(CONFIG_SCHED_GRRR_CORE)

static void
grrr_priority_mapping_init(void)
{
	unsigned int i;
	
	/* Map 0->0 up to 10->20 */
	for (i=0; i <= 10; i++) {
		grrr_priority_mapping[i] = 2*i;
	}
	
	/* Map user priorities 11->33 up to 51 -> 153 */
	for (i=11; i <= 51; i++) {
		grrr_priority_mapping[i] = 3*i;
	}
	
	/* Map high priorities 52->180 up to 127->255 */
	for (i=52; i <= 127; i++) {
		grrr_priority_mapping[i] = 128 + i;
	}
	
	for (i = 0; i < NUM_GRRR_PROPORTIONAL_PRIORITIES; i++) {
		
#if 0		
		unsigned j, k;
		/* Calculate log(i); */
		for (j=0, k=1; k <= i; j++, k *= 2);
#endif
		
		/* Groups of 4 */
		grrr_group_mapping[i] = i >> 2;
	}
	
}

static thread_t
grrr_intragroup_schedule(grrr_group_t group)
{
	thread_t thread;

	if (group->count == 0) {
		return THREAD_NULL;
	}
	
	thread = group->current_client;
	if (thread == THREAD_NULL) {
		thread = (thread_t)(void *)queue_first(&group->clients);
	}
	
	if (1 /* deficit */) {
		group->current_client = (thread_t)(void *)queue_next((queue_entry_t)thread);
		if (queue_end(&group->clients, (queue_entry_t)group->current_client)) {
			group->current_client = (thread_t)(void *)queue_first(&group->clients);
		}
		
		thread = group->current_client;
	}
	
	return thread;
}

static thread_t
grrr_intergroup_schedule(grrr_run_queue_t rq)
{
	thread_t thread;
	grrr_group_t group;
	
	if (rq->count == 0) {
		return THREAD_NULL;
	}
	
	group = rq->current_group;
	
	if (group == GRRR_GROUP_NULL) {
		group = (grrr_group_t)queue_first(&rq->sorted_group_list);
	}
	
	thread = grrr_intragroup_schedule(group);
	
	if ((group->work >= (UINT32_MAX-256)) || (rq->last_rescale_tick != grrr_rescale_tick)) {
		grrr_rescale_work(rq);
	}
	group->work++;
	
	if (queue_end(&rq->sorted_group_list, queue_next((queue_entry_t)group))) {
		/* last group, go back to beginning */
		group = (grrr_group_t)queue_first(&rq->sorted_group_list);
	} else {
		grrr_group_t nextgroup = (grrr_group_t)queue_next((queue_entry_t)group);
		uint64_t orderleft, orderright;
		
		/*
		 * The well-ordering condition for intergroup selection is:
		 *
		 * (group->work+1) / (nextgroup->work+1) > (group->weight) / (nextgroup->weight)
		 *
		 * Multiply both sides by their denominators to avoid division
		 *
		 */
		orderleft = (group->work + 1) * ((uint64_t)nextgroup->weight);
		orderright = (nextgroup->work + 1) * ((uint64_t)group->weight);
		if (orderleft > orderright) {
			group = nextgroup;
		} else {
			group = (grrr_group_t)queue_first(&rq->sorted_group_list);
		}
	}
	
	rq->current_group = group;
	
	return thread;
}

static void
grrr_runqueue_init(grrr_run_queue_t		runq)
{
	grrr_group_index_t index;
	
	runq->count = 0;
	
	for (index = 0; index < NUM_GRRR_GROUPS; index++) {
		unsigned int prisearch;

		for (prisearch = 0;
			 prisearch < NUM_GRRR_PROPORTIONAL_PRIORITIES;
			 prisearch++) {
			if (grrr_group_mapping[prisearch] == index) {
				runq->groups[index].minpriority = (grrr_proportional_priority_t)prisearch;
				break;
			}
		}
		
		runq->groups[index].index = index;

		queue_init(&runq->groups[index].clients);
		runq->groups[index].count = 0;
		runq->groups[index].weight = 0;
		runq->groups[index].work = 0;
		runq->groups[index].current_client = THREAD_NULL;
	}
	
	queue_init(&runq->sorted_group_list);
	runq->weight = 0;
	runq->current_group = GRRR_GROUP_NULL;
}

static void
grrr_rescale_work(grrr_run_queue_t rq)
{
	grrr_group_index_t index;

	/* avoid overflow by scaling by 1/8th */
	for (index = 0; index < NUM_GRRR_GROUPS; index++) {
		rq->groups[index].work >>= 3;
	}

	rq->last_rescale_tick = grrr_rescale_tick;
}

static boolean_t
grrr_enqueue(
							 grrr_run_queue_t			rq,
							 thread_t			thread)
{							 
	grrr_proportional_priority_t	gpriority;
	grrr_group_index_t		gindex;
	grrr_group_t			group;

	gpriority = grrr_priority_mapping[thread->sched_pri];
	gindex = grrr_group_mapping[gpriority];
	group = &rq->groups[gindex];

#if 0
	thread->grrr_deficit = 0;
#endif
	
	if (group->count == 0) {
		/* Empty group, this is the first client */
		enqueue_tail(&group->clients, (queue_entry_t)thread);
		group->count = 1;
		group->weight = gpriority;
		group->current_client = thread;
	} else {
		/* Insert before the current client */
		if (group->current_client == THREAD_NULL ||
			queue_first(&group->clients) == (queue_entry_t)group->current_client) {
			enqueue_head(&group->clients, (queue_entry_t)thread);
		} else {
			insque((queue_entry_t)thread, queue_prev((queue_entry_t)group->current_client));
		}
		SCHED_STATS_RUNQ_CHANGE(&rq->runq_stats, rq->count);
		group->count++;
		group->weight += gpriority;

		/* Since there was already a client, this is on the per-processor sorted list already */
		remqueue((queue_entry_t)group);
	}
	
	grrr_sorted_list_insert_group(rq, group);

	rq->count++;
	rq->weight += gpriority;
	
	return (FALSE);
}

static thread_t
grrr_select(grrr_run_queue_t	rq)
{
	thread_t		thread;

	thread = grrr_intergroup_schedule(rq);
	if (thread != THREAD_NULL) {
		grrr_proportional_priority_t	gpriority;
		grrr_group_index_t		gindex;
		grrr_group_t			group;
		
		gpriority = grrr_priority_mapping[thread->sched_pri];
		gindex = grrr_group_mapping[gpriority];
		group = &rq->groups[gindex];
		
		remqueue((queue_entry_t)thread);
		SCHED_STATS_RUNQ_CHANGE(&rq->runq_stats, rq->count);
		group->count--;
		group->weight -= gpriority;
		if (group->current_client == thread) {
			group->current_client = THREAD_NULL;
		}
		
		remqueue((queue_entry_t)group);
		if (group->count == 0) {
			if (rq->current_group == group) {
				rq->current_group = GRRR_GROUP_NULL;
			}
		} else {
			/* Need to re-insert in sorted location */
			grrr_sorted_list_insert_group(rq, group);
		}
		
		rq->count--;
		rq->weight -= gpriority;
		
		thread->runq = PROCESSOR_NULL;
	}		
	
	
	return (thread);
}

static void
grrr_remove(
								 grrr_run_queue_t			rq,
								 thread_t		thread)
{				   
	grrr_proportional_priority_t	gpriority;
	grrr_group_index_t		gindex;
	grrr_group_t			group;
	
	gpriority = grrr_priority_mapping[thread->sched_pri];
	gindex = grrr_group_mapping[gpriority];
	group = &rq->groups[gindex];
	
	remqueue((queue_entry_t)thread);
	SCHED_STATS_RUNQ_CHANGE(&rq->runq_stats, rq->count);
	group->count--;
	group->weight -= gpriority;
	if (group->current_client == thread) {
		group->current_client = THREAD_NULL;
	}
	
	remqueue((queue_entry_t)group);
	if (group->count == 0) {
		if (rq->current_group == group) {
			rq->current_group = GRRR_GROUP_NULL;
		}
	} else {
		/* Need to re-insert in sorted location */
		grrr_sorted_list_insert_group(rq, group);
	}
	
	rq->count--;
	rq->weight -= gpriority;
	
	thread->runq = PROCESSOR_NULL;
}

static void
grrr_sorted_list_insert_group(grrr_run_queue_t rq,
												grrr_group_t group)
{
	/* Simple insertion sort */
	if (queue_empty(&rq->sorted_group_list)) {
		enqueue_tail(&rq->sorted_group_list, (queue_entry_t)group);
	} else {
		grrr_group_t search_group;
		
		/* Start searching from the head (heaviest weight) for the first
		 * element less than us, so we can insert before it
		 */
		search_group = (grrr_group_t)queue_first(&rq->sorted_group_list);
		while (!queue_end(&rq->sorted_group_list, (queue_entry_t)search_group) ) {
			
			if (search_group->weight < group->weight) {
				/* we should be before this */
				search_group = (grrr_group_t)queue_prev((queue_entry_t)search_group);
				break;
			} if (search_group->weight == group->weight) {
				/* Use group index as a tie breaker */
				if (search_group->index < group->index) {
					search_group = (grrr_group_t)queue_prev((queue_entry_t)search_group);
					break;
				}
			}
			
			/* otherwise, our weight is too small, keep going */
			search_group = (grrr_group_t)queue_next((queue_entry_t)search_group);
		}
		
		if (queue_end(&rq->sorted_group_list, (queue_entry_t)search_group)) {
			enqueue_tail(&rq->sorted_group_list, (queue_entry_t)group);
		} else {
			insque((queue_entry_t)group, (queue_entry_t)search_group);
		}
	}
}

#endif /* defined(CONFIG_SCHED_GRRR_CORE) */

#if defined(CONFIG_SCHED_GRRR) || defined(CONFIG_SCHED_FIXEDPRIORITY)

static struct grrr_run_queue	fs_grrr_runq;
#define FS_GRRR_RUNQ		((processor_t)-2)
decl_simple_lock_data(static,fs_grrr_lock);

void
sched_grrr_fairshare_init(void)
{
	grrr_priority_mapping_init();
	
	simple_lock_init(&fs_grrr_lock, 0);
	grrr_runqueue_init(&fs_grrr_runq);
}


int
sched_grrr_fairshare_runq_count(void)
{
	return fs_grrr_runq.count;
}

uint64_t
sched_grrr_fairshare_runq_stats_count_sum(void)
{
	return fs_grrr_runq.runq_stats.count_sum;
}

void
sched_grrr_fairshare_enqueue(thread_t thread)
{
	simple_lock(&fs_grrr_lock);
	
	(void)grrr_enqueue(&fs_grrr_runq, thread);

	thread->runq = FS_GRRR_RUNQ;

	simple_unlock(&fs_grrr_lock);	
}

thread_t	sched_grrr_fairshare_dequeue(void)
{
	thread_t thread;
	
	simple_lock(&fs_grrr_lock);
	if (fs_grrr_runq.count > 0) {
		thread = grrr_select(&fs_grrr_runq);
		
		simple_unlock(&fs_grrr_lock);
		
		return (thread);
	}
	simple_unlock(&fs_grrr_lock);		
	
	return THREAD_NULL;
}

boolean_t	sched_grrr_fairshare_queue_remove(thread_t thread)
{
	
	simple_lock(&fs_grrr_lock);
	
	if (FS_GRRR_RUNQ == thread->runq) {
		grrr_remove(&fs_grrr_runq, thread);
		
		simple_unlock(&fs_grrr_lock);
		return (TRUE);
	}
	else {
		/*
		 *	The thread left the run queue before we could
		 * 	lock the run queue.
		 */
		assert(thread->runq == PROCESSOR_NULL);
		simple_unlock(&fs_grrr_lock);
		return (FALSE);
	}	
}

#endif /* defined(CONFIG_SCHED_GRRR) || defined(CONFIG_SCHED_FIXEDPRIORITY) */

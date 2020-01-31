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

#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>

#include <mach/sdt.h>

#include <sys/kdebug.h>

static void
sched_proto_init(void);

static void
sched_proto_timebase_init(void);

static void
sched_proto_processor_init(processor_t processor);

static void
sched_proto_pset_init(processor_set_t pset);

static void
sched_proto_maintenance_continuation(void);

static thread_t
sched_proto_choose_thread(processor_t           processor,
    int                            priority,
    ast_t                          reason);

static thread_t
sched_proto_steal_thread(processor_set_t                pset);

static int
sched_proto_compute_priority(thread_t thread);

static processor_t
sched_proto_choose_processor(   processor_set_t         pset,
    processor_t                     processor,
    thread_t                        thread);


static boolean_t
sched_proto_processor_enqueue(
	processor_t                    processor,
	thread_t                       thread,
	integer_t                      options);

static void
sched_proto_processor_queue_shutdown(
	processor_t                    processor);

static boolean_t
sched_proto_processor_queue_remove(
	processor_t                 processor,
	thread_t                thread);

static boolean_t
sched_proto_processor_queue_empty(processor_t           processor);

static boolean_t
sched_proto_processor_queue_has_priority(processor_t            processor,
    int                            priority,
    boolean_t              gte);

static boolean_t
sched_proto_priority_is_urgent(int priority);

static ast_t
sched_proto_processor_csw_check(processor_t processor);

static uint32_t
sched_proto_initial_quantum_size(thread_t thread);

static sched_mode_t
sched_proto_initial_thread_sched_mode(task_t parent_task);

static boolean_t
sched_proto_can_update_priority(thread_t        thread);

static void
sched_proto_update_priority(thread_t    thread);

static void
sched_proto_lightweight_update_priority(thread_t        thread);

static void
sched_proto_quantum_expire(thread_t     thread);

static int
sched_proto_processor_runq_count(processor_t   processor);

static uint64_t
sched_proto_processor_runq_stats_count_sum(processor_t   processor);

static int
sched_proto_processor_bound_count(processor_t   processor);

static void
sched_proto_thread_update_scan(sched_update_scan_context_t scan_context);


const struct sched_dispatch_table sched_proto_dispatch = {
	.sched_name                                     = "proto",
	.init                                           = sched_proto_init,
	.timebase_init                                  = sched_proto_timebase_init,
	.processor_init                                 = sched_proto_processor_init,
	.pset_init                                      = sched_proto_pset_init,
	.maintenance_continuation                       = sched_proto_maintenance_continuation,
	.choose_thread                                  = sched_proto_choose_thread,
	.steal_thread_enabled                           = sched_steal_thread_DISABLED,
	.steal_thread                                   = sched_proto_steal_thread,
	.compute_timeshare_priority                     = sched_proto_compute_priority,
	.choose_processor                               = sched_proto_choose_processor,
	.processor_enqueue                              = sched_proto_processor_enqueue,
	.processor_queue_shutdown                       = sched_proto_processor_queue_shutdown,
	.processor_queue_remove                         = sched_proto_processor_queue_remove,
	.processor_queue_empty                          = sched_proto_processor_queue_empty,
	.priority_is_urgent                             = sched_proto_priority_is_urgent,
	.processor_csw_check                            = sched_proto_processor_csw_check,
	.processor_queue_has_priority                   = sched_proto_processor_queue_has_priority,
	.initial_quantum_size                           = sched_proto_initial_quantum_size,
	.initial_thread_sched_mode                      = sched_proto_initial_thread_sched_mode,
	.can_update_priority                            = sched_proto_can_update_priority,
	.update_priority                                = sched_proto_update_priority,
	.lightweight_update_priority                    = sched_proto_lightweight_update_priority,
	.quantum_expire                                 = sched_proto_quantum_expire,
	.processor_runq_count                           = sched_proto_processor_runq_count,
	.processor_runq_stats_count_sum                 = sched_proto_processor_runq_stats_count_sum,
	.processor_bound_count                          = sched_proto_processor_bound_count,
	.thread_update_scan                             = sched_proto_thread_update_scan,
	.direct_dispatch_to_idle_processors             = TRUE,
	.multiple_psets_enabled                         = TRUE,
	.sched_groups_enabled                           = FALSE,
	.avoid_processor_enabled                        = FALSE,
	.thread_avoid_processor                         = NULL,
	.processor_balance                              = sched_SMT_balance,

	.rt_runq                                        = sched_rtglobal_runq,
	.rt_init                                        = sched_rtglobal_init,
	.rt_queue_shutdown                              = sched_rtglobal_queue_shutdown,
	.rt_runq_scan                                   = sched_rtglobal_runq_scan,
	.rt_runq_count_sum                              = sched_rtglobal_runq_count_sum,

	.qos_max_parallelism                            = sched_qos_max_parallelism,
	.check_spill                                    = sched_check_spill,
	.ipi_policy                                     = sched_ipi_policy,
	.thread_should_yield                            = sched_thread_should_yield,
};

static struct run_queue *global_runq;
static struct run_queue global_runq_storage;

#define GLOBAL_RUNQ             ((processor_t)-2)
decl_simple_lock_data(static, global_runq_lock);

extern int      max_unsafe_quanta;

static uint32_t proto_quantum_us;
static uint32_t proto_quantum;

static uint32_t runqueue_generation;

static processor_t proto_processor;

static uint64_t                 sched_proto_tick_deadline;
static uint32_t                 sched_proto_tick;

static void
sched_proto_init(void)
{
	proto_quantum_us = 10 * 1000;

	printf("standard proto timeslicing quantum is %d us\n", proto_quantum_us);

	simple_lock_init(&global_runq_lock, 0);
	global_runq = &global_runq_storage;
	run_queue_init(global_runq);
	runqueue_generation = 0;

	proto_processor = master_processor;
}

static void
sched_proto_timebase_init(void)
{
	uint64_t        abstime;

	/* standard timeslicing quantum */
	clock_interval_to_absolutetime_interval(
		proto_quantum_us, NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	proto_quantum = (uint32_t)abstime;

	thread_depress_time = 1 * proto_quantum;
	default_timeshare_computation = proto_quantum / 2;
	default_timeshare_constraint = proto_quantum;

	max_unsafe_computation = max_unsafe_quanta * proto_quantum;
	sched_safe_duration = 2 * max_unsafe_quanta * proto_quantum;
}

static void
sched_proto_processor_init(processor_t processor __unused)
{
	/* No per-processor state */
}

static void
sched_proto_pset_init(processor_set_t pset __unused)
{
}

static void
sched_proto_maintenance_continuation(void)
{
	uint64_t                        abstime = mach_absolute_time();

	sched_proto_tick++;

	/* Every 8 seconds, switch to another processor */
	if ((sched_proto_tick & 0x7) == 0) {
		processor_t new_processor;

		new_processor = proto_processor->processor_list;
		if (new_processor == PROCESSOR_NULL) {
			proto_processor = master_processor;
		} else {
			proto_processor = new_processor;
		}
	}


	/*
	 *  Compute various averages.
	 */
	compute_averages(1);

	if (sched_proto_tick_deadline == 0) {
		sched_proto_tick_deadline = abstime;
	}

	clock_deadline_for_periodic_event(sched_one_second_interval, abstime,
	    &sched_proto_tick_deadline);

	assert_wait_deadline((event_t)sched_proto_maintenance_continuation, THREAD_UNINT, sched_proto_tick_deadline);
	thread_block((thread_continue_t)sched_proto_maintenance_continuation);
	/*NOTREACHED*/
}

static thread_t
sched_proto_choose_thread(processor_t           processor,
    int                           priority,
    ast_t                         reason __unused)
{
	run_queue_t             rq = global_runq;
	queue_t                 queue;
	int                             pri, count;
	thread_t                thread;


	simple_lock(&global_runq_lock, LCK_GRP_NULL);

	queue = rq->queues + rq->highq;
	pri = rq->highq;
	count = rq->count;

	/*
	 * Since we don't depress priorities, a high priority thread
	 * may get selected over and over again. Put a runqueue
	 * generation number in the thread structure so that we
	 * can ensure that we've cycled through all runnable tasks
	 * before coming back to a high priority thread. This isn't
	 * perfect, especially if the number of runnable threads always
	 * stays high, but is a workable approximation
	 */

	while (count > 0 && pri >= priority) {
		thread = (thread_t)queue_first(queue);
		while (!queue_end(queue, (queue_entry_t)thread)) {
			if ((thread->bound_processor == PROCESSOR_NULL ||
			    thread->bound_processor == processor) &&
			    runqueue_generation != thread->runqueue_generation) {
				remqueue((queue_entry_t)thread);

				thread->runq = PROCESSOR_NULL;
				thread->runqueue_generation = runqueue_generation;
				SCHED_STATS_RUNQ_CHANGE(&rq->runq_stats, rq->count);
				rq->count--;
				if (queue_empty(queue)) {
					bitmap_clear(rq->bitmap, pri);
					rq->highq = bitmap_first(rq->bitmap, NRQS);
				}

				simple_unlock(&global_runq_lock);
				return thread;
			}
			count--;

			thread = (thread_t)queue_next((queue_entry_t)thread);
		}

		queue--; pri--;
	}

	runqueue_generation++;

	simple_unlock(&global_runq_lock);
	return THREAD_NULL;
}

static thread_t
sched_proto_steal_thread(processor_set_t                pset)
{
	pset_unlock(pset);

	return THREAD_NULL;
}

static int
sched_proto_compute_priority(thread_t thread)
{
	return thread->base_pri;
}

static processor_t
sched_proto_choose_processor(   processor_set_t         pset,
    processor_t                    processor,
    thread_t                       thread __unused)
{
	processor = proto_processor;

	/*
	 *	Check that the correct processor set is
	 *	returned locked.
	 */
	if (pset != processor->processor_set) {
		pset_unlock(pset);

		pset = processor->processor_set;
		pset_lock(pset);
	}

	return processor;
}

static boolean_t
sched_proto_processor_enqueue(
	processor_t                    processor __unused,
	thread_t                       thread,
	integer_t                      options)
{
	run_queue_t             rq = global_runq;
	boolean_t               result;

	simple_lock(&global_runq_lock, LCK_GRP_NULL);
	result = run_queue_enqueue(rq, thread, options);
	thread->runq = GLOBAL_RUNQ;
	simple_unlock(&global_runq_lock);

	return result;
}

static void
sched_proto_processor_queue_shutdown(
	processor_t                    processor)
{
	/* With a global runqueue, just stop choosing this processor */
	(void)processor;
}

static boolean_t
sched_proto_processor_queue_remove(
	processor_t                     processor,
	thread_t                thread)
{
	void *                  rqlock;
	run_queue_t             rq;

	rqlock = &global_runq_lock;
	rq = global_runq;

	simple_lock(rqlock, LCK_GRP_NULL);
	if (processor == thread->runq) {
		/*
		 *	Thread is on a run queue and we have a lock on
		 *	that run queue.
		 */
		remqueue((queue_entry_t)thread);
		SCHED_STATS_RUNQ_CHANGE(&rq->runq_stats, rq->count);
		rq->count--;
		if (SCHED(priority_is_urgent)(thread->sched_pri)) {
			rq->urgency--; assert(rq->urgency >= 0);
		}

		if (queue_empty(rq->queues + thread->sched_pri)) {
			/* update run queue status */
			bitmap_clear(rq->bitmap, thread->sched_pri);
			rq->highq = bitmap_first(rq->bitmap, NRQS);
		}

		thread->runq = PROCESSOR_NULL;
	} else {
		/*
		 *	The thread left the run queue before we could
		 *      lock the run queue.
		 */
		assert(thread->runq == PROCESSOR_NULL);
		processor = PROCESSOR_NULL;
	}

	simple_unlock(rqlock);

	return processor != PROCESSOR_NULL;
}

static boolean_t
sched_proto_processor_queue_empty(processor_t           processor __unused)
{
	boolean_t result;

	result = (global_runq->count == 0);

	return result;
}

static boolean_t
sched_proto_processor_queue_has_priority(processor_t            processor __unused,
    int                            priority,
    boolean_t              gte)
{
	boolean_t result;

	simple_lock(&global_runq_lock, LCK_GRP_NULL);

	if (gte) {
		result = global_runq->highq >= priority;
	} else {
		result = global_runq->highq > priority;
	}

	simple_unlock(&global_runq_lock);

	return result;
}

/* Implement sched_preempt_pri in code */
static boolean_t
sched_proto_priority_is_urgent(int priority)
{
	if (priority <= BASEPRI_FOREGROUND) {
		return FALSE;
	}

	if (priority < MINPRI_KERNEL) {
		return TRUE;
	}

	if (priority >= BASEPRI_PREEMPT) {
		return TRUE;
	}

	return FALSE;
}

static ast_t
sched_proto_processor_csw_check(processor_t processor)
{
	run_queue_t             runq;
	int                             count, urgency;

	runq = global_runq;
	count = runq->count;
	urgency = runq->urgency;

	if (count > 0) {
		if (urgency > 0) {
			return AST_PREEMPT | AST_URGENT;
		}

		return AST_PREEMPT;
	}

	if (proto_processor != processor) {
		return AST_PREEMPT;
	}

	return AST_NONE;
}

static uint32_t
sched_proto_initial_quantum_size(thread_t thread __unused)
{
	return proto_quantum;
}

static sched_mode_t
sched_proto_initial_thread_sched_mode(task_t parent_task)
{
	if (parent_task == kernel_task) {
		return TH_MODE_FIXED;
	} else {
		return TH_MODE_TIMESHARE;
	}
}

static boolean_t
sched_proto_can_update_priority(thread_t        thread __unused)
{
	return FALSE;
}

static void
sched_proto_update_priority(thread_t    thread __unused)
{
}

static void
sched_proto_lightweight_update_priority(thread_t        thread __unused)
{
}

static void
sched_proto_quantum_expire(thread_t    thread __unused)
{
}

static int
sched_proto_processor_runq_count(processor_t   processor)
{
	if (master_processor == processor) {
		return global_runq->count;
	} else {
		return 0;
	}
}

static uint64_t
sched_proto_processor_runq_stats_count_sum(processor_t   processor)
{
	if (master_processor == processor) {
		return global_runq->runq_stats.count_sum;
	} else {
		return 0ULL;
	}
}

static int
sched_proto_processor_bound_count(__unused processor_t   processor)
{
	return 0;
}

static void
sched_proto_thread_update_scan(__unused sched_update_scan_context_t scan_context)
{
}

/*
 * Copyright (c) 1993-1995, 1999-2008 Apple Inc. All rights reserved.
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
#include <mach/thread_act.h>

#include <kern/kern_types.h>
#include <kern/zalloc.h>
#include <kern/sched_prim.h>
#include <kern/clock.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/waitq.h>
#include <kern/ledger.h>

#include <vm/vm_pageout.h>

#include <kern/thread_call.h>
#include <kern/call_entry.h>
#include <kern/timer_call.h>

#include <libkern/OSAtomic.h>
#include <kern/timer_queue.h>

#include <sys/kdebug.h>
#if CONFIG_DTRACE
#include <mach/sdt.h>
#endif
#include <machine/machine_routines.h>

static zone_t			thread_call_zone;
static struct waitq		daemon_waitq;

struct thread_call_group {
	queue_head_t		pending_queue;
	uint32_t		pending_count;

	queue_head_t		delayed_queue;
	uint32_t		delayed_count;

	timer_call_data_t	delayed_timer;
	timer_call_data_t	dealloc_timer;

	struct waitq		idle_waitq;
	uint32_t		idle_count, active_count;

	integer_t		pri;
	uint32_t 		target_thread_count;
	uint64_t		idle_timestamp;

	uint32_t		flags;
	sched_call_t		sched_call;
};

typedef struct thread_call_group	*thread_call_group_t;

#define TCG_PARALLEL		0x01
#define TCG_DEALLOC_ACTIVE	0x02
#define TCG_CONTINUOUS      0x04

#define THREAD_CALL_PRIO_COUNT		4
#define THREAD_CALL_ABSTIME_COUNT	4
#define THREAD_CALL_CONTTIME_COUNT	4
#define THREAD_CALL_GROUP_COUNT		(THREAD_CALL_CONTTIME_COUNT + THREAD_CALL_ABSTIME_COUNT)
#define THREAD_CALL_THREAD_MIN		4
#define INTERNAL_CALL_COUNT		768
#define THREAD_CALL_DEALLOC_INTERVAL_NS (5 * 1000 * 1000) /* 5 ms */
#define THREAD_CALL_ADD_RATIO		4
#define THREAD_CALL_MACH_FACTOR_CAP	3

#define IS_CONT_GROUP(group) \
	(((group)->flags & TCG_CONTINUOUS) ? TRUE : FALSE)

// groups [0..4]: thread calls in mach_absolute_time
// groups [4..8]: thread calls in mach_continuous_time 
static struct thread_call_group thread_call_groups[THREAD_CALL_GROUP_COUNT];

static struct thread_call_group *abstime_thread_call_groups;
static struct thread_call_group *conttime_thread_call_groups;

static boolean_t		thread_call_daemon_awake;
static thread_call_data_t	internal_call_storage[INTERNAL_CALL_COUNT];
static queue_head_t		thread_call_internal_queue;
int						thread_call_internal_queue_count = 0;
static uint64_t 		thread_call_dealloc_interval_abs;

static __inline__ thread_call_t	_internal_call_allocate(thread_call_func_t func, thread_call_param_t param0);
static __inline__ void		_internal_call_release(thread_call_t call);
static __inline__ boolean_t	_pending_call_enqueue(thread_call_t call, thread_call_group_t group);
static __inline__ boolean_t 	_delayed_call_enqueue(thread_call_t call, thread_call_group_t group, uint64_t deadline);
static __inline__ boolean_t 	_call_dequeue(thread_call_t call, thread_call_group_t group);
static __inline__ void		thread_call_wake(thread_call_group_t group);
static __inline__ void		_set_delayed_call_timer(thread_call_t call, thread_call_group_t	group);
static boolean_t		_remove_from_pending_queue(thread_call_func_t func, thread_call_param_t	param0, boolean_t remove_all);
static boolean_t 		_remove_from_delayed_queue(thread_call_func_t func, thread_call_param_t	param0, boolean_t remove_all);
static void			thread_call_daemon(void *arg);
static void			thread_call_thread(thread_call_group_t group, wait_result_t wres);
extern void			thread_call_delayed_timer(timer_call_param_t p0, timer_call_param_t p1);
static void			thread_call_dealloc_timer(timer_call_param_t p0, timer_call_param_t p1);
static void			thread_call_group_setup(thread_call_group_t group, thread_call_priority_t pri, uint32_t target_thread_count, boolean_t parallel, boolean_t continuous);
static void			sched_call_thread(int type, thread_t thread);
static void			thread_call_start_deallocate_timer(thread_call_group_t group);
static void			thread_call_wait_locked(thread_call_t call);
static boolean_t		thread_call_enter_delayed_internal(thread_call_t call,
						thread_call_func_t alt_func, thread_call_param_t alt_param0,
						thread_call_param_t param1, uint64_t deadline,
						uint64_t leeway, unsigned int flags);

#define qe(x)		((queue_entry_t)(x))
#define TC(x)		((thread_call_t)(x))


lck_grp_t               thread_call_queues_lck_grp;
lck_grp_t               thread_call_lck_grp;
lck_attr_t              thread_call_lck_attr;
lck_grp_attr_t          thread_call_lck_grp_attr;

lck_mtx_t		thread_call_lock_data;


#define thread_call_lock_spin()			\
	lck_mtx_lock_spin_always(&thread_call_lock_data)

#define thread_call_unlock()			\
	lck_mtx_unlock_always(&thread_call_lock_data)

extern boolean_t	mach_timer_coalescing_enabled;

static inline spl_t
disable_ints_and_lock(void)
{
	spl_t s;

	s = splsched();
	thread_call_lock_spin();

	return s;
}

static inline void 
enable_ints_and_unlock(spl_t s)
{
	thread_call_unlock();
	splx(s);
}


static inline boolean_t
group_isparallel(thread_call_group_t group)
{
	return ((group->flags & TCG_PARALLEL) != 0);
}

static boolean_t
thread_call_group_should_add_thread(thread_call_group_t group) 
{
	uint32_t thread_count;

	if (!group_isparallel(group)) {
		if (group->pending_count > 0 && group->active_count == 0) {
			return TRUE;
		}

		return FALSE;
	}

	if (group->pending_count > 0) {
		if (group->idle_count > 0) {
			panic("Pending work, but threads are idle?");
		}

		thread_count = group->active_count;

		/*
		 * Add a thread if either there are no threads,
		 * the group has fewer than its target number of
		 * threads, or the amount of work is large relative
		 * to the number of threads.  In the last case, pay attention
		 * to the total load on the system, and back off if 
         * it's high.
		 */
		if ((thread_count == 0) ||
			(thread_count < group->target_thread_count) ||
			((group->pending_count > THREAD_CALL_ADD_RATIO * thread_count) && 
			 (sched_mach_factor < THREAD_CALL_MACH_FACTOR_CAP))) {
			return TRUE;
		}
	}
			
	return FALSE;
}

static inline integer_t
thread_call_priority_to_sched_pri(thread_call_priority_t pri) 
{
	switch (pri) {
	case THREAD_CALL_PRIORITY_HIGH:
		return BASEPRI_PREEMPT;
	case THREAD_CALL_PRIORITY_KERNEL:
		return BASEPRI_KERNEL;
	case THREAD_CALL_PRIORITY_USER:
		return BASEPRI_DEFAULT;
	case THREAD_CALL_PRIORITY_LOW:
		return MAXPRI_THROTTLE;
	default:
		panic("Invalid priority.");
	}

	return 0;
}

/* Lock held */
static inline thread_call_group_t
thread_call_get_group(
		thread_call_t call)
{
	thread_call_priority_t 	pri = call->tc_pri;

	assert(pri == THREAD_CALL_PRIORITY_LOW ||
			pri == THREAD_CALL_PRIORITY_USER ||
			pri == THREAD_CALL_PRIORITY_KERNEL ||
			pri == THREAD_CALL_PRIORITY_HIGH);

	thread_call_group_t group;

	if(call->tc_flags & THREAD_CALL_CONTINUOUS) {
		group = &conttime_thread_call_groups[pri];
	} else {
		group = &abstime_thread_call_groups[pri];
	}

	assert(IS_CONT_GROUP(group) == ((call->tc_flags & THREAD_CALL_CONTINUOUS) ? TRUE : FALSE));
	return group;
}

static void
thread_call_group_setup(
		thread_call_group_t 		group, 
		thread_call_priority_t		pri,
		uint32_t			target_thread_count,
		boolean_t			parallel,
		boolean_t			continuous)
{
	queue_init(&group->pending_queue);
	queue_init(&group->delayed_queue);

	timer_call_setup(&group->delayed_timer, thread_call_delayed_timer, group);
	timer_call_setup(&group->dealloc_timer, thread_call_dealloc_timer, group);

	waitq_init(&group->idle_waitq, SYNC_POLICY_FIFO|SYNC_POLICY_DISABLE_IRQ);

	group->target_thread_count = target_thread_count;
	group->pri = thread_call_priority_to_sched_pri(pri);

	group->sched_call = sched_call_thread; 
	if (parallel) {
		group->flags |= TCG_PARALLEL;
		group->sched_call = NULL;
	}

	if(continuous) {
		group->flags |= TCG_CONTINUOUS;
	}
}

/*
 * Simple wrapper for creating threads bound to 
 * thread call groups.
 */
static kern_return_t
thread_call_thread_create(
		thread_call_group_t             group)
{
	thread_t thread;
	kern_return_t result;

	result = kernel_thread_start_priority((thread_continue_t)thread_call_thread, group, group->pri, &thread);
	if (result != KERN_SUCCESS) {
		return result;
	}

	if (group->pri < BASEPRI_PREEMPT) {
		/*
		 * New style doesn't get to run to completion in 
		 * kernel if there are higher priority threads 
		 * available.
		 */
		thread_set_eager_preempt(thread);
	}

	thread_deallocate(thread);
	return KERN_SUCCESS;
}

/*
 *	thread_call_initialize:
 *
 *	Initialize this module, called
 *	early during system initialization.
 */
void
thread_call_initialize(void)
{
	thread_call_t			call;
	kern_return_t			result;
	thread_t			thread;
	int				i;
	spl_t			s;

	i = sizeof (thread_call_data_t);
	thread_call_zone = zinit(i, 4096 * i, 16 * i, "thread_call");
	zone_change(thread_call_zone, Z_CALLERACCT, FALSE);
	zone_change(thread_call_zone, Z_NOENCRYPT, TRUE);

	abstime_thread_call_groups  = &thread_call_groups[0];
	conttime_thread_call_groups = &thread_call_groups[THREAD_CALL_ABSTIME_COUNT];

	lck_attr_setdefault(&thread_call_lck_attr);
	lck_grp_attr_setdefault(&thread_call_lck_grp_attr);
	lck_grp_init(&thread_call_queues_lck_grp, "thread_call_queues", &thread_call_lck_grp_attr);
	lck_grp_init(&thread_call_lck_grp, "thread_call", &thread_call_lck_grp_attr);
	lck_mtx_init(&thread_call_lock_data, &thread_call_lck_grp, &thread_call_lck_attr);
	nanotime_to_absolutetime(0, THREAD_CALL_DEALLOC_INTERVAL_NS, &thread_call_dealloc_interval_abs);
	waitq_init(&daemon_waitq, SYNC_POLICY_DISABLE_IRQ | SYNC_POLICY_FIFO);

	thread_call_group_setup(&abstime_thread_call_groups[THREAD_CALL_PRIORITY_LOW],      THREAD_CALL_PRIORITY_LOW,                       0, TRUE,  FALSE);
	thread_call_group_setup(&abstime_thread_call_groups[THREAD_CALL_PRIORITY_USER],     THREAD_CALL_PRIORITY_USER,                      0, TRUE,  FALSE);
	thread_call_group_setup(&abstime_thread_call_groups[THREAD_CALL_PRIORITY_KERNEL],   THREAD_CALL_PRIORITY_KERNEL,                    1, TRUE,  FALSE);
	thread_call_group_setup(&abstime_thread_call_groups[THREAD_CALL_PRIORITY_HIGH],     THREAD_CALL_PRIORITY_HIGH, THREAD_CALL_THREAD_MIN, FALSE, FALSE);
	thread_call_group_setup(&conttime_thread_call_groups[THREAD_CALL_PRIORITY_LOW],     THREAD_CALL_PRIORITY_LOW,                       0, TRUE,  TRUE);
	thread_call_group_setup(&conttime_thread_call_groups[THREAD_CALL_PRIORITY_USER],    THREAD_CALL_PRIORITY_USER,                      0, TRUE,  TRUE);
	thread_call_group_setup(&conttime_thread_call_groups[THREAD_CALL_PRIORITY_KERNEL],  THREAD_CALL_PRIORITY_KERNEL,                    0, TRUE,  TRUE);
	thread_call_group_setup(&conttime_thread_call_groups[THREAD_CALL_PRIORITY_HIGH],    THREAD_CALL_PRIORITY_HIGH,                      1, FALSE, TRUE);

	s = disable_ints_and_lock();

	queue_init(&thread_call_internal_queue);
	for (
			call = internal_call_storage;
			call < &internal_call_storage[INTERNAL_CALL_COUNT];
			call++) {

		enqueue_tail(&thread_call_internal_queue, qe(call));
		thread_call_internal_queue_count++;
	}

	thread_call_daemon_awake = TRUE;

	enable_ints_and_unlock(s);

	result = kernel_thread_start_priority((thread_continue_t)thread_call_daemon, NULL, BASEPRI_PREEMPT + 1, &thread);
	if (result != KERN_SUCCESS)
		panic("thread_call_initialize");

	thread_deallocate(thread);
}

void
thread_call_setup(
	thread_call_t			call,
	thread_call_func_t		func,
	thread_call_param_t		param0)
{
	bzero(call, sizeof(*call));
	call_entry_setup((call_entry_t)call, func, param0);
	call->tc_pri = THREAD_CALL_PRIORITY_HIGH; /* Default priority */
}

/*
 *	_internal_call_allocate:
 *
 *	Allocate an internal callout entry.
 *
 *	Called with thread_call_lock held.
 */
static __inline__ thread_call_t
_internal_call_allocate(thread_call_func_t func, thread_call_param_t param0)
{
    thread_call_t		call;
    
    if (queue_empty(&thread_call_internal_queue))
    	panic("_internal_call_allocate");
	
    call = TC(dequeue_head(&thread_call_internal_queue));
    thread_call_internal_queue_count--;

    thread_call_setup(call, func, param0);
    call->tc_refs = 0;
    call->tc_flags = 0; /* THREAD_CALL_ALLOC not set, do not free back to zone */

    return (call);
}

/*
 *	_internal_call_release:
 *
 *	Release an internal callout entry which
 *	is no longer pending (or delayed). This is
 *	safe to call on a non-internal entry, in which
 *	case nothing happens.
 *
 * 	Called with thread_call_lock held.
 */
static __inline__ void
_internal_call_release(
    thread_call_t		call)
{
    if (    call >= internal_call_storage						&&
	   	    call < &internal_call_storage[INTERNAL_CALL_COUNT]		) {
		assert((call->tc_flags & THREAD_CALL_ALLOC) == 0);
		enqueue_head(&thread_call_internal_queue, qe(call));
		thread_call_internal_queue_count++;
	}
}

/*
 *	_pending_call_enqueue:
 *
 *	Place an entry at the end of the
 *	pending queue, to be executed soon.
 *
 *	Returns TRUE if the entry was already
 *	on a queue.
 *
 *	Called with thread_call_lock held.
 */
static __inline__ boolean_t
_pending_call_enqueue(
    thread_call_t		call,
	thread_call_group_t	group)
{
	queue_head_t		*old_queue;

	old_queue = call_entry_enqueue_tail(CE(call), &group->pending_queue);

	if (old_queue == NULL) {
		call->tc_submit_count++;
	} else if (old_queue != &group->pending_queue &&
			   old_queue != &group->delayed_queue){
		panic("tried to move a thread call (%p) between groups (old_queue: %p)", call, old_queue);
	}

	group->pending_count++;

	thread_call_wake(group);

	return (old_queue != NULL);
}

/*
 *	_delayed_call_enqueue:
 *
 *	Place an entry on the delayed queue,
 *	after existing entries with an earlier
 * 	(or identical) deadline.
 *
 *	Returns TRUE if the entry was already
 *	on a queue.
 *
 *	Called with thread_call_lock held.
 */
static __inline__ boolean_t
_delayed_call_enqueue(
    	thread_call_t		call,
	thread_call_group_t	group,
	uint64_t		deadline)
{
	queue_head_t		*old_queue;

	old_queue = call_entry_enqueue_deadline(CE(call), &group->delayed_queue, deadline);

	if (old_queue == &group->pending_queue) {
		group->pending_count--;
	} else if (old_queue == NULL) {
		call->tc_submit_count++;
	} else if (old_queue == &group->delayed_queue) {
		// we did nothing, and that's fine
	} else {
		panic("tried to move a thread call (%p) between groups (old_queue: %p)", call, old_queue);
	}

	return (old_queue != NULL);
}

/*
 *	_call_dequeue:
 *
 *	Remove an entry from a queue.
 *
 *	Returns TRUE if the entry was on a queue.
 *
 *	Called with thread_call_lock held.
 */
static __inline__ boolean_t
_call_dequeue(
	thread_call_t		call,
	thread_call_group_t	group)
{
	queue_head_t		*old_queue;

	old_queue = call_entry_dequeue(CE(call));

	if (old_queue != NULL) {
		call->tc_finish_count++;
		if (old_queue == &group->pending_queue)
			group->pending_count--;
	}

	return (old_queue != NULL);
}

/*
 *	_set_delayed_call_timer:
 *
 *	Reset the timer so that it
 *	next expires when the entry is due.
 *
 *	Called with thread_call_lock held.
 */
static __inline__ void
_set_delayed_call_timer(
    thread_call_t		call,
	thread_call_group_t	group)
{
	uint64_t leeway, fire_at;

	assert((call->tc_soft_deadline != 0) && ((call->tc_soft_deadline <= call->tc_call.deadline)));
	assert(IS_CONT_GROUP(group) == ((call->tc_flags & THREAD_CALL_CONTINUOUS) ? TRUE : FALSE));

	fire_at = call->tc_soft_deadline;

	if (IS_CONT_GROUP(group)) {
		fire_at = continuoustime_to_absolutetime(fire_at);
	}

	leeway = call->tc_call.deadline - call->tc_soft_deadline;
	timer_call_enter_with_leeway(&group->delayed_timer, NULL,
	    fire_at, leeway,
	    TIMER_CALL_SYS_CRITICAL|TIMER_CALL_LEEWAY,
	    ((call->tc_flags & THREAD_CALL_RATELIMITED) == THREAD_CALL_RATELIMITED));
}

/*
 *	_remove_from_pending_queue:
 *
 *	Remove the first (or all) matching
 *	entries	from the pending queue.
 *
 *	Returns	TRUE if any matching entries
 *	were found.
 *
 *	Called with thread_call_lock held.
 */
static boolean_t
_remove_from_pending_queue(
    thread_call_func_t		func,
    thread_call_param_t		param0,
    boolean_t				remove_all)
{
	boolean_t				call_removed = FALSE;
	thread_call_t			call;
	thread_call_group_t		group = &abstime_thread_call_groups[THREAD_CALL_PRIORITY_HIGH];

	call = TC(queue_first(&group->pending_queue));

	while (!queue_end(&group->pending_queue, qe(call))) {
		if (call->tc_call.func == func &&
				call->tc_call.param0 == param0) {
			thread_call_t	next = TC(queue_next(qe(call)));

			_call_dequeue(call, group);

			_internal_call_release(call);

			call_removed = TRUE;
			if (!remove_all)
				break;

			call = next;
		}
		else	
			call = TC(queue_next(qe(call)));
	}

	return (call_removed);
}

/*
 *	_remove_from_delayed_queue:
 *
 *	Remove the first (or all) matching
 *	entries	from the delayed queue.
 *
 *	Returns	TRUE if any matching entries
 *	were found.
 *
 *	Called with thread_call_lock held.
 */
static boolean_t
_remove_from_delayed_queue(
    thread_call_func_t		func,
    thread_call_param_t		param0,
    boolean_t				remove_all)
{
	boolean_t			call_removed = FALSE;
	thread_call_t			call;
	thread_call_group_t		group = &abstime_thread_call_groups[THREAD_CALL_PRIORITY_HIGH];

	call = TC(queue_first(&group->delayed_queue));

	while (!queue_end(&group->delayed_queue, qe(call))) {
		if (call->tc_call.func == func	&&
				call->tc_call.param0 == param0) {
			thread_call_t	next = TC(queue_next(qe(call)));

			_call_dequeue(call, group);

			_internal_call_release(call);

			call_removed = TRUE;
			if (!remove_all)
				break;

			call = next;
		}
		else	
			call = TC(queue_next(qe(call)));
	}

	return (call_removed);
}

/*
 *	thread_call_func_delayed:
 *
 *	Enqueue a function callout to
 *	occur at the stated time.
 */
void
thread_call_func_delayed(
		thread_call_func_t		func,
		thread_call_param_t		param,
		uint64_t			deadline)
{
	(void)thread_call_enter_delayed_internal(NULL, func, param, 0, deadline, 0, 0);
}

/*
 * thread_call_func_delayed_with_leeway:
 *
 * Same as thread_call_func_delayed(), but with
 * leeway/flags threaded through.
 */

void
thread_call_func_delayed_with_leeway(
	thread_call_func_t		func,
	thread_call_param_t		param,
	uint64_t		deadline,
	uint64_t		leeway,
	uint32_t		flags)
{
	(void)thread_call_enter_delayed_internal(NULL, func, param, 0, deadline, leeway, flags);
}

/*
 *	thread_call_func_cancel:
 *
 *	Dequeue a function callout.
 *
 *	Removes one (or all) { function, argument }
 *	instance(s) from either (or both)
 *	the pending and	the delayed queue,
 *	in that order.
 *
 *	Returns TRUE if any calls were cancelled.
 */
boolean_t
thread_call_func_cancel(
		thread_call_func_t		func,
		thread_call_param_t		param,
		boolean_t			cancel_all)
{
	boolean_t	result;
	spl_t		s;

	assert(func != NULL);

	s = splsched();
	thread_call_lock_spin();

	if (cancel_all)
		result = _remove_from_pending_queue(func, param, cancel_all) |
			_remove_from_delayed_queue(func, param, cancel_all);
	else
		result = _remove_from_pending_queue(func, param, cancel_all) ||
			_remove_from_delayed_queue(func, param, cancel_all);

	thread_call_unlock();
	splx(s);

	return (result);
}

/*
 * Allocate a thread call with a given priority.  Importances
 * other than THREAD_CALL_PRIORITY_HIGH will be run in threads
 * with eager preemption enabled (i.e. may be aggressively preempted
 * by higher-priority threads which are not in the normal "urgent" bands).
 */
thread_call_t
thread_call_allocate_with_priority(
		thread_call_func_t		func,
		thread_call_param_t		param0,
		thread_call_priority_t		pri)
{
	thread_call_t call;

	if (pri > THREAD_CALL_PRIORITY_LOW) {
		panic("Invalid pri: %d\n", pri);
	}

	call = thread_call_allocate(func, param0);
	call->tc_pri = pri;

	return call;
}

/*
 *	thread_call_allocate:
 *
 *	Allocate a callout entry.
 */
thread_call_t
thread_call_allocate(
		thread_call_func_t		func,
		thread_call_param_t		param0)
{
	thread_call_t	call = zalloc(thread_call_zone);

	thread_call_setup(call, func, param0);
	call->tc_refs = 1;
	call->tc_flags = THREAD_CALL_ALLOC;

	return (call);
}

/*
 *	thread_call_free:
 *
 *	Release a callout.  If the callout is currently
 *	executing, it will be freed when all invocations
 *	finish.
 */
boolean_t
thread_call_free(
		thread_call_t		call)
{
	spl_t	s;
	int32_t refs;

	s = splsched();
	thread_call_lock_spin();

	if (call->tc_call.queue != NULL) {
		thread_call_unlock();
		splx(s);

		return (FALSE);
	}

	refs = --call->tc_refs;
	if (refs < 0) {
		panic("Refcount negative: %d\n", refs);
	}	

	thread_call_unlock();
	splx(s);

	if (refs == 0) {
		zfree(thread_call_zone, call);
	}

	return (TRUE);
}

/*
 *	thread_call_enter:
 *
 *	Enqueue a callout entry to occur "soon".
 *
 *	Returns TRUE if the call was
 *	already on a queue.
 */
boolean_t
thread_call_enter(
		thread_call_t		call)
{
	return thread_call_enter1(call, 0);
}

boolean_t
thread_call_enter1(
		thread_call_t			call,
		thread_call_param_t		param1)
{
	boolean_t		result = TRUE;
	thread_call_group_t	group;
	spl_t			s;

	assert(call->tc_call.func != NULL);

	group = thread_call_get_group(call);

	s = splsched();
	thread_call_lock_spin();

	if (call->tc_call.queue != &group->pending_queue) {
		result = _pending_call_enqueue(call, group);
	}

	call->tc_call.param1 = param1;

	thread_call_unlock();
	splx(s);

	return (result);
}

/*
 *	thread_call_enter_delayed:
 *
 *	Enqueue a callout entry to occur
 *	at the stated time.
 *
 *	Returns TRUE if the call was
 *	already on a queue.
 */
boolean_t
thread_call_enter_delayed(
		thread_call_t		call,
		uint64_t		deadline)
{
	assert(call != NULL);
	return thread_call_enter_delayed_internal(call, NULL, 0, 0, deadline, 0, 0);
}

boolean_t
thread_call_enter1_delayed(
		thread_call_t			call,
		thread_call_param_t		param1,
		uint64_t			deadline)
{
	assert(call != NULL);
	return thread_call_enter_delayed_internal(call, NULL, 0, param1, deadline, 0, 0);
}

boolean_t
thread_call_enter_delayed_with_leeway(
		thread_call_t		call,
		thread_call_param_t	param1,
		uint64_t		deadline,
		uint64_t		leeway,
		unsigned int		flags)
{
	assert(call != NULL);
	return thread_call_enter_delayed_internal(call, NULL, 0, param1, deadline, leeway, flags);
}


/*
 * thread_call_enter_delayed_internal:
 * enqueue a callout entry to occur at the stated time
 *
 * Returns True if the call was already on a queue
 * params:
 * call     - structure encapsulating state of the callout
 * alt_func/alt_param0 - if call is NULL, allocate temporary storage using these parameters
 * deadline - time deadline in nanoseconds
 * leeway   - timer slack represented as delta of deadline.
 * flags    - THREAD_CALL_DELAY_XXX : classification of caller's desires wrt timer coalescing.
 *            THREAD_CALL_DELAY_LEEWAY : value in leeway is used for timer coalescing.
 *            THREAD_CALL_CONTINUOUS: thread call will be called according to mach_continuous_time rather
 * 									  than mach_absolute_time
 */
boolean_t
thread_call_enter_delayed_internal(
		thread_call_t 		call,
		thread_call_func_t	alt_func,
		thread_call_param_t	alt_param0,
		thread_call_param_t 	param1,
		uint64_t 		deadline,
		uint64_t 		leeway,
		unsigned int 		flags)
{
	boolean_t		result = TRUE;
	thread_call_group_t	group;
	spl_t			s;
	uint64_t		abstime, conttime, sdeadline, slop;
	uint32_t		urgency;
	const boolean_t is_cont_time = (flags & THREAD_CALL_CONTINUOUS) ? TRUE : FALSE;

	/* direct mapping between thread_call, timer_call, and timeout_urgency values */
	urgency = (flags & TIMEOUT_URGENCY_MASK);

	s = splsched();
	thread_call_lock_spin();

	if (call == NULL) {
		/* allocate a structure out of internal storage, as a convenience for BSD callers */
		call = _internal_call_allocate(alt_func, alt_param0);
	}

	if (is_cont_time) {
		call->tc_flags |= THREAD_CALL_CONTINUOUS;
	}

	assert(call->tc_call.func != NULL);
	group = thread_call_get_group(call);
	abstime =  mach_absolute_time();
	conttime =  absolutetime_to_continuoustime(abstime);
	
	call->tc_flags |= THREAD_CALL_DELAYED;

	call->tc_soft_deadline = sdeadline = deadline;

	boolean_t ratelimited = FALSE;
	slop = timer_call_slop(deadline, is_cont_time ? conttime : abstime, urgency, current_thread(), &ratelimited);
	
	if ((flags & THREAD_CALL_DELAY_LEEWAY) != 0 && leeway > slop)
		slop = leeway;

	if (UINT64_MAX - deadline <= slop)
		deadline = UINT64_MAX;
	else
		deadline += slop;

	if (ratelimited) {
		call->tc_flags |= TIMER_CALL_RATELIMITED;
	} else {
		call->tc_flags &= ~TIMER_CALL_RATELIMITED;
	}


	call->tc_call.param1 = param1;

	if(is_cont_time) {
		call->ttd = (sdeadline > conttime) ? (sdeadline - conttime) : 0;
	}
	else {
		call->ttd = (sdeadline > abstime) ? (sdeadline - abstime) : 0;
	}

	result = _delayed_call_enqueue(call, group, deadline);

	if (queue_first(&group->delayed_queue) == qe(call)) {
		_set_delayed_call_timer(call, group);
	}

#if CONFIG_DTRACE
	DTRACE_TMR5(thread_callout__create, thread_call_func_t, call->tc_call.func, uint64_t, (deadline - sdeadline), uint64_t, (call->ttd >> 32), (unsigned) (call->ttd & 0xFFFFFFFF), call);
#endif

	thread_call_unlock();
	splx(s);

	return (result);
}

/*
 *	thread_call_cancel:
 *
 *	Dequeue a callout entry.
 *
 *	Returns TRUE if the call was
 *	on a queue.
 */
boolean_t
thread_call_cancel(
		thread_call_t		call)
{
	boolean_t		result, do_cancel_callout = FALSE;
	thread_call_group_t	group;
	spl_t			s;

	group = thread_call_get_group(call);

	s = splsched();
	thread_call_lock_spin();

	if ((call->tc_call.deadline != 0) &&
	    (queue_first(&group->delayed_queue) == qe(call))) {
		assert (call->tc_call.queue == &group->delayed_queue);
		do_cancel_callout = TRUE;
	}

	result = _call_dequeue(call, group);

	if (do_cancel_callout) {
		timer_call_cancel(&group->delayed_timer);
		if (!queue_empty(&group->delayed_queue)) {
			_set_delayed_call_timer(TC(queue_first(&group->delayed_queue)), group);
		}
	}

	thread_call_unlock();
	splx(s);
#if CONFIG_DTRACE
	DTRACE_TMR4(thread_callout__cancel, thread_call_func_t, call->tc_call.func, 0, (call->ttd >> 32), (unsigned) (call->ttd & 0xFFFFFFFF));
#endif

	return (result);
}

/*
 * Cancel a thread call.  If it cannot be cancelled (i.e.
 * is already in flight), waits for the most recent invocation
 * to finish.  Note that if clients re-submit this thread call,
 * it may still be pending or in flight when thread_call_cancel_wait
 * returns, but all requests to execute this work item prior
 * to the call to thread_call_cancel_wait will have finished.
 */
boolean_t
thread_call_cancel_wait(
		thread_call_t		call)
{
	boolean_t		result;
	thread_call_group_t	group;

	if ((call->tc_flags & THREAD_CALL_ALLOC) == 0) {
		panic("%s: Can't wait on thread call whose storage I don't own.", __FUNCTION__);
	}

	group = thread_call_get_group(call);

	(void) splsched();
	thread_call_lock_spin();

	result = _call_dequeue(call, group);
	if (result == FALSE) {
		thread_call_wait_locked(call);
	}

	thread_call_unlock();
	(void) spllo();

	return result;
}


/*
 *	thread_call_wake:
 *
 *	Wake a call thread to service
 *	pending call entries.  May wake
 *	the daemon thread in order to
 *	create additional call threads.
 *
 *	Called with thread_call_lock held.
 *
 *	For high-priority group, only does wakeup/creation if there are no threads
 *	running.
 */
static __inline__ void
thread_call_wake(
	thread_call_group_t		group)
{
	/* 
	 * New behavior: use threads if you've got 'em.
	 * Traditional behavior: wake only if no threads running.
	 */
	if (group_isparallel(group) || group->active_count == 0) {
		if (waitq_wakeup64_one(&group->idle_waitq, NO_EVENT64,
				       THREAD_AWAKENED, WAITQ_ALL_PRIORITIES) == KERN_SUCCESS) {
			group->idle_count--; group->active_count++;

			if (group->idle_count == 0) {
				timer_call_cancel(&group->dealloc_timer);
				group->flags &= ~TCG_DEALLOC_ACTIVE;
			}
		} else {
			if (!thread_call_daemon_awake && thread_call_group_should_add_thread(group)) {
				thread_call_daemon_awake = TRUE;
				waitq_wakeup64_one(&daemon_waitq, NO_EVENT64,
						   THREAD_AWAKENED, WAITQ_ALL_PRIORITIES);
			}
		}
	}
}

/*
 *	sched_call_thread:
 *
 *	Call out invoked by the scheduler.  Used only for high-priority
 *	thread call group.
 */
static void
sched_call_thread(
		int				type,
		__unused	thread_t		thread)
{
	thread_call_group_t		group;

	group = &thread_call_groups[THREAD_CALL_PRIORITY_HIGH]; /* XXX */

	thread_call_lock_spin();

	switch (type) {

		case SCHED_CALL_BLOCK:
			--group->active_count;
			if (group->pending_count > 0)
				thread_call_wake(group);
			break;

		case SCHED_CALL_UNBLOCK:
			group->active_count++;
			break;
	}

	thread_call_unlock();
}

/* 
 * Interrupts disabled, lock held; returns the same way. 
 * Only called on thread calls whose storage we own.  Wakes up
 * anyone who might be waiting on this work item and frees it
 * if the client has so requested.
 */
static void
thread_call_finish(thread_call_t call, spl_t *s)
{
	boolean_t dowake = FALSE;

	call->tc_finish_count++;
	call->tc_refs--;

	if ((call->tc_flags & THREAD_CALL_WAIT) != 0) {
		dowake = TRUE;
		call->tc_flags &= ~THREAD_CALL_WAIT;

		/* 
		 * Dropping lock here because the sched call for the 
		 * high-pri group can take the big lock from under
		 * a thread lock.
		 */
		thread_call_unlock();
		thread_wakeup((event_t)call);
		thread_call_lock_spin();
	}

	if (call->tc_refs == 0) {
		if (dowake) {
			panic("Someone waiting on a thread call that is scheduled for free: %p\n", call->tc_call.func);
		}

		enable_ints_and_unlock(*s);

		zfree(thread_call_zone, call);

		*s = disable_ints_and_lock();
	}

}

/*
 *	thread_call_thread:
 */
static void
thread_call_thread(
		thread_call_group_t		group,
		wait_result_t			wres)
{
	thread_t	self = current_thread();
	boolean_t	canwait;
	spl_t		s;

	if ((thread_get_tag_internal(self) & THREAD_TAG_CALLOUT) == 0)
		(void)thread_set_tag_internal(self, THREAD_TAG_CALLOUT);

	/*
	 * A wakeup with THREAD_INTERRUPTED indicates that 
	 * we should terminate.
	 */
	if (wres == THREAD_INTERRUPTED) {
		thread_terminate(self);

		/* NOTREACHED */
		panic("thread_terminate() returned?");
	}

	s = disable_ints_and_lock();

	thread_sched_call(self, group->sched_call);

	while (group->pending_count > 0) {
		thread_call_t			call;
		thread_call_func_t		func;
		thread_call_param_t		param0, param1;

		call = TC(dequeue_head(&group->pending_queue));
		assert(call != NULL);
		group->pending_count--;

		func = call->tc_call.func;
		param0 = call->tc_call.param0;
		param1 = call->tc_call.param1;

		call->tc_call.queue = NULL;

		_internal_call_release(call);

		/*
		 * Can only do wakeups for thread calls whose storage
		 * we control.
		 */
		if ((call->tc_flags & THREAD_CALL_ALLOC) != 0) {
			canwait = TRUE;
			call->tc_refs++;	/* Delay free until we're done */
		} else
			canwait = FALSE;

		enable_ints_and_unlock(s);

#if DEVELOPMENT || DEBUG
		KERNEL_DEBUG_CONSTANT(
				MACHDBG_CODE(DBG_MACH_SCHED,MACH_CALLOUT) | DBG_FUNC_NONE,
				VM_KERNEL_UNSLIDE(func), VM_KERNEL_UNSLIDE_OR_PERM(param0), VM_KERNEL_UNSLIDE_OR_PERM(param1), 0, 0);
#endif /* DEVELOPMENT || DEBUG */

#if CONFIG_DTRACE
		DTRACE_TMR6(thread_callout__start, thread_call_func_t, func, int, 0, int, (call->ttd >> 32), (unsigned) (call->ttd & 0xFFFFFFFF), (call->tc_flags & THREAD_CALL_DELAYED), call);
#endif

		(*func)(param0, param1);

#if CONFIG_DTRACE
		DTRACE_TMR6(thread_callout__end, thread_call_func_t, func, int, 0, int, (call->ttd >> 32), (unsigned) (call->ttd & 0xFFFFFFFF), (call->tc_flags & THREAD_CALL_DELAYED), call);
#endif

		if (get_preemption_level() != 0) {
			int pl = get_preemption_level();
			panic("thread_call_thread: preemption_level %d, last callout %p(%p, %p)",
					pl, (void *)VM_KERNEL_UNSLIDE(func), param0, param1);
		}

		s = disable_ints_and_lock();
		
		if (canwait) {
			/* Frees if so desired */
			thread_call_finish(call, &s);
		}
	}

	thread_sched_call(self, NULL);
	group->active_count--;
	
	if (self->callout_woken_from_icontext && !self->callout_woke_thread) {
		ledger_credit(self->t_ledger, task_ledgers.interrupt_wakeups, 1);
		if (self->callout_woken_from_platform_idle)
		        ledger_credit(self->t_ledger, task_ledgers.platform_idle_wakeups, 1);
	}
	
	self->callout_woken_from_icontext = FALSE;
	self->callout_woken_from_platform_idle = FALSE;
	self->callout_woke_thread = FALSE;

	if (group_isparallel(group)) {
		/*
		 * For new style of thread group, thread always blocks. 
		 * If we have more than the target number of threads,
		 * and this is the first to block, and it isn't active 
		 * already, set a timer for deallocating a thread if we 
		 * continue to have a surplus.
		 */
		group->idle_count++;

		if (group->idle_count == 1) {
			group->idle_timestamp = mach_absolute_time();
		}   

		if (((group->flags & TCG_DEALLOC_ACTIVE) == 0) &&
				((group->active_count + group->idle_count) > group->target_thread_count)) {
			group->flags |= TCG_DEALLOC_ACTIVE;
			thread_call_start_deallocate_timer(group);
		}   

		/* Wait for more work (or termination) */
		wres = waitq_assert_wait64(&group->idle_waitq, NO_EVENT64, THREAD_INTERRUPTIBLE, 0);
		if (wres != THREAD_WAITING) {
			panic("kcall worker unable to assert wait?");
		}   

		enable_ints_and_unlock(s);

		thread_block_parameter((thread_continue_t)thread_call_thread, group);
	} else {
		if (group->idle_count < group->target_thread_count) {
			group->idle_count++;

			waitq_assert_wait64(&group->idle_waitq, NO_EVENT64, THREAD_UNINT, 0); /* Interrupted means to exit */

			enable_ints_and_unlock(s);

			thread_block_parameter((thread_continue_t)thread_call_thread, group);
			/* NOTREACHED */
		}
	}

	enable_ints_and_unlock(s);

	thread_terminate(self);
	/* NOTREACHED */
}

/*
 *	thread_call_daemon: walk list of groups, allocating
 *	threads if appropriate (as determined by 
 *	thread_call_group_should_add_thread()).  
 */
static void
thread_call_daemon_continue(__unused void *arg)
{
	int		i;
	kern_return_t	kr;
	thread_call_group_t group;
	spl_t	s;

	s = disable_ints_and_lock();

	/* Starting at zero happens to be high-priority first. */
	for (i = 0; i < THREAD_CALL_GROUP_COUNT; i++) {
		group = &thread_call_groups[i];
		while (thread_call_group_should_add_thread(group)) {
			group->active_count++;

			enable_ints_and_unlock(s);

			kr = thread_call_thread_create(group);
			if (kr != KERN_SUCCESS) {
				/*
				 * On failure, just pause for a moment and give up. 
				 * We can try again later.
				 */
				delay(10000); /* 10 ms */
				s = disable_ints_and_lock();
				goto out;
			}

			s = disable_ints_and_lock();
		}
	}

out:
	thread_call_daemon_awake = FALSE;
	waitq_assert_wait64(&daemon_waitq, NO_EVENT64, THREAD_UNINT, 0);

	enable_ints_and_unlock(s);

	thread_block_parameter((thread_continue_t)thread_call_daemon_continue, NULL);
	/* NOTREACHED */
}

static void
thread_call_daemon(
		__unused void	 *arg)
{
	thread_t	self = current_thread();

	self->options |= TH_OPT_VMPRIV;
	vm_page_free_reserve(2);	/* XXX */

	thread_call_daemon_continue(NULL);
	/* NOTREACHED */
}

/*
 * Schedule timer to deallocate a worker thread if we have a surplus 
 * of threads (in excess of the group's target) and at least one thread
 * is idle the whole time.
 */
static void
thread_call_start_deallocate_timer(
		thread_call_group_t group)
{
        uint64_t deadline;
        boolean_t onqueue;

	assert(group->idle_count > 0);

        group->flags |= TCG_DEALLOC_ACTIVE;
        deadline = group->idle_timestamp + thread_call_dealloc_interval_abs;
        onqueue = timer_call_enter(&group->dealloc_timer, deadline, 0); 

        if (onqueue) {
                panic("Deallocate timer already active?");
        }   
}

void
thread_call_delayed_timer(
		timer_call_param_t		p0,
		__unused timer_call_param_t	p1
)
{
	thread_call_t			call;
	thread_call_group_t		group = p0;
	uint64_t			timestamp;

	thread_call_lock_spin();

	const boolean_t is_cont_time = IS_CONT_GROUP(group) ? TRUE : FALSE;

	if (is_cont_time) {
		timestamp = mach_continuous_time();
	}
	else {
		timestamp = mach_absolute_time();
	}

	call = TC(queue_first(&group->delayed_queue));

	while (!queue_end(&group->delayed_queue, qe(call))) {
		assert((!is_cont_time) || (call->tc_flags & THREAD_CALL_CONTINUOUS));

		if (call->tc_soft_deadline <= timestamp) {
			if ((call->tc_flags & THREAD_CALL_RATELIMITED) &&
			    (CE(call)->deadline > timestamp) &&
			    (ml_timer_forced_evaluation() == FALSE)) {
				break;
			}
			_pending_call_enqueue(call, group);
		} /* TODO, identify differentially coalesced timers */
		else
			break;

		call = TC(queue_first(&group->delayed_queue));
	}

	if (!queue_end(&group->delayed_queue, qe(call))) {
		_set_delayed_call_timer(call, group);
	}

	thread_call_unlock();
}

static void
thread_call_delayed_timer_rescan(thread_call_group_t group)
{
	thread_call_t			call;
	uint64_t				timestamp;
	boolean_t		istate;

	istate = ml_set_interrupts_enabled(FALSE);
	thread_call_lock_spin();

	assert(ml_timer_forced_evaluation() == TRUE);

	if (IS_CONT_GROUP(group)) {
		timestamp = mach_continuous_time();
	} else {
		timestamp = mach_absolute_time();
	}

	call = TC(queue_first(&group->delayed_queue));

	while (!queue_end(&group->delayed_queue, qe(call))) {
		if (call->tc_soft_deadline <= timestamp) {
			_pending_call_enqueue(call, group);
			call = TC(queue_first(&group->delayed_queue));
		}
		else {
			uint64_t skew = call->tc_call.deadline - call->tc_soft_deadline;
			assert (call->tc_call.deadline >= call->tc_soft_deadline);
			/* On a latency quality-of-service level change,
			 * re-sort potentially rate-limited callout. The platform
			 * layer determines which timers require this.
			 */
			if (timer_resort_threshold(skew)) {
				_call_dequeue(call, group);
				_delayed_call_enqueue(call, group, call->tc_soft_deadline);
			}
			call = TC(queue_next(qe(call)));
		}
	}

	if (!queue_empty(&group->delayed_queue))
 		_set_delayed_call_timer(TC(queue_first(&group->delayed_queue)), group);
	thread_call_unlock();
	ml_set_interrupts_enabled(istate);
}

void
thread_call_delayed_timer_rescan_all(void) {
	int i;
	for(i = 0; i < THREAD_CALL_GROUP_COUNT; i++) {
		thread_call_delayed_timer_rescan(&thread_call_groups[i]);
	}
}

/*
 * Timer callback to tell a thread to terminate if
 * we have an excess of threads and at least one has been
 * idle for a long time.
 */
static void
thread_call_dealloc_timer(
		timer_call_param_t 		p0,
		__unused timer_call_param_t 	p1)
{
	thread_call_group_t group = (thread_call_group_t)p0;
	uint64_t now;
	kern_return_t res;
	boolean_t terminated = FALSE;
	
	thread_call_lock_spin();

	now = mach_absolute_time();
	if (group->idle_count > 0) {
		if (now > group->idle_timestamp + thread_call_dealloc_interval_abs) {
			terminated = TRUE;
			group->idle_count--;
			res = waitq_wakeup64_one(&group->idle_waitq, NO_EVENT64,
						 THREAD_INTERRUPTED, WAITQ_ALL_PRIORITIES);
			if (res != KERN_SUCCESS) {
				panic("Unable to wake up idle thread for termination?");
			}
		}

	}

	/*
	 * If we still have an excess of threads, schedule another
	 * invocation of this function.
	 */
	if (group->idle_count > 0 && (group->idle_count + group->active_count > group->target_thread_count)) {
		/*
		 * If we killed someone just now, push out the
		 * next deadline.
		 */
		if (terminated) {
			group->idle_timestamp = now;
		}

		thread_call_start_deallocate_timer(group);
	} else {
		group->flags &= ~TCG_DEALLOC_ACTIVE;
	}

	thread_call_unlock();
}

/*
 * Wait for all requested invocations of a thread call prior to now
 * to finish.  Can only be invoked on thread calls whose storage we manage.  
 * Just waits for the finish count to catch up to the submit count we find
 * at the beginning of our wait.
 */
static void
thread_call_wait_locked(thread_call_t call)
{
	uint64_t submit_count;
	wait_result_t res;

	assert(call->tc_flags & THREAD_CALL_ALLOC);

	submit_count = call->tc_submit_count;

	while (call->tc_finish_count < submit_count) {
		call->tc_flags |= THREAD_CALL_WAIT;

		res = assert_wait(call, THREAD_UNINT);
		if (res != THREAD_WAITING) {
			panic("Unable to assert wait?");
		}

		thread_call_unlock();
		(void) spllo();

		res = thread_block(NULL);
		if (res != THREAD_AWAKENED) {
			panic("Awoken with %d?", res);
		}
	
		(void) splsched();
		thread_call_lock_spin();
	}
}

/*
 * Determine whether a thread call is either on a queue or
 * currently being executed.
 */
boolean_t
thread_call_isactive(thread_call_t call) 
{
	boolean_t active;
	spl_t	s;

	s = disable_ints_and_lock();
	active = (call->tc_submit_count > call->tc_finish_count);
	enable_ints_and_unlock(s);

	return active;
}

/*
 * adjust_cont_time_thread_calls
 * on wake, reenqueue delayed call timer for continuous time thread call groups
 */
void
adjust_cont_time_thread_calls(void)
{
	thread_call_group_t group;

	spl_t s;
	int i;
	s = disable_ints_and_lock();
	
	for (i = 0; i < THREAD_CALL_CONTTIME_COUNT; i++) {	
		// only the continuous thread call groups
		group = &conttime_thread_call_groups[i];
		assert(IS_CONT_GROUP(group));

		if (!queue_empty(&group->delayed_queue)) {
			_set_delayed_call_timer(TC(queue_first(&group->delayed_queue)), group);
		}
	} 

	enable_ints_and_unlock(s);
}

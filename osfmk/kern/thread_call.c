/*
 * Copyright (c) 1993-1995, 1999-2020 Apple Inc. All rights reserved.
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
#include <kern/policy_internal.h>

#include <vm/vm_pageout.h>

#include <kern/thread_call.h>
#include <kern/timer_call.h>

#include <libkern/OSAtomic.h>
#include <kern/timer_queue.h>

#include <sys/kdebug.h>
#if CONFIG_DTRACE
#include <mach/sdt.h>
#endif
#include <machine/machine_routines.h>

static ZONE_DECLARE(thread_call_zone, "thread_call",
    sizeof(thread_call_data_t), ZC_NOENCRYPT);

static struct waitq daemon_waitq;

typedef enum {
	TCF_ABSOLUTE    = 0,
	TCF_CONTINUOUS  = 1,
	TCF_COUNT       = 2,
} thread_call_flavor_t;

__options_decl(thread_call_group_flags_t, uint32_t, {
	TCG_NONE                = 0x0,
	TCG_PARALLEL            = 0x1,
	TCG_DEALLOC_ACTIVE      = 0x2,
});

static struct thread_call_group {
	__attribute__((aligned(128))) lck_ticket_t tcg_lock;

	const char *            tcg_name;

	queue_head_t            pending_queue;
	uint32_t                pending_count;

	queue_head_t            delayed_queues[TCF_COUNT];
	struct priority_queue_deadline_min delayed_pqueues[TCF_COUNT];
	timer_call_data_t       delayed_timers[TCF_COUNT];

	timer_call_data_t       dealloc_timer;

	struct waitq            idle_waitq;
	uint64_t                idle_timestamp;
	uint32_t                idle_count, active_count, blocked_count;

	uint32_t                tcg_thread_pri;
	uint32_t                target_thread_count;

	thread_call_group_flags_t tcg_flags;
} thread_call_groups[THREAD_CALL_INDEX_MAX] = {
	[THREAD_CALL_INDEX_HIGH] = {
		.tcg_name               = "high",
		.tcg_thread_pri         = BASEPRI_PREEMPT_HIGH,
		.target_thread_count    = 4,
		.tcg_flags              = TCG_NONE,
	},
	[THREAD_CALL_INDEX_KERNEL] = {
		.tcg_name               = "kernel",
		.tcg_thread_pri         = BASEPRI_KERNEL,
		.target_thread_count    = 1,
		.tcg_flags              = TCG_PARALLEL,
	},
	[THREAD_CALL_INDEX_USER] = {
		.tcg_name               = "user",
		.tcg_thread_pri         = BASEPRI_DEFAULT,
		.target_thread_count    = 1,
		.tcg_flags              = TCG_PARALLEL,
	},
	[THREAD_CALL_INDEX_LOW] = {
		.tcg_name               = "low",
		.tcg_thread_pri         = MAXPRI_THROTTLE,
		.target_thread_count    = 1,
		.tcg_flags              = TCG_PARALLEL,
	},
	[THREAD_CALL_INDEX_KERNEL_HIGH] = {
		.tcg_name               = "kernel-high",
		.tcg_thread_pri         = BASEPRI_PREEMPT,
		.target_thread_count    = 2,
		.tcg_flags              = TCG_NONE,
	},
	[THREAD_CALL_INDEX_QOS_UI] = {
		.tcg_name               = "qos-ui",
		.tcg_thread_pri         = BASEPRI_FOREGROUND,
		.target_thread_count    = 1,
		.tcg_flags              = TCG_NONE,
	},
	[THREAD_CALL_INDEX_QOS_IN] = {
		.tcg_name               = "qos-in",
		.tcg_thread_pri         = BASEPRI_USER_INITIATED,
		.target_thread_count    = 1,
		.tcg_flags              = TCG_NONE,
	},
	[THREAD_CALL_INDEX_QOS_UT] = {
		.tcg_name               = "qos-ut",
		.tcg_thread_pri         = BASEPRI_UTILITY,
		.target_thread_count    = 1,
		.tcg_flags              = TCG_NONE,
	},
};

typedef struct thread_call_group        *thread_call_group_t;

#define INTERNAL_CALL_COUNT             768
#define THREAD_CALL_DEALLOC_INTERVAL_NS (5 * NSEC_PER_MSEC) /* 5 ms */
#define THREAD_CALL_ADD_RATIO           4
#define THREAD_CALL_MACH_FACTOR_CAP     3
#define THREAD_CALL_GROUP_MAX_THREADS   500

struct thread_call_thread_state {
	struct thread_call_group * thc_group;
	struct thread_call *       thc_call;    /* debug only, may be deallocated */
	uint64_t thc_call_start;
	uint64_t thc_call_soft_deadline;
	uint64_t thc_call_hard_deadline;
	uint64_t thc_call_pending_timestamp;
	uint64_t thc_IOTES_invocation_timestamp;
	thread_call_func_t  thc_func;
	thread_call_param_t thc_param0;
	thread_call_param_t thc_param1;
};

static bool                     thread_call_daemon_awake = true;
/*
 * This special waitq exists because the daemon thread
 * might need to be woken while already holding a global waitq locked.
 */
static struct waitq             daemon_waitq;

static thread_call_data_t       internal_call_storage[INTERNAL_CALL_COUNT];
static queue_head_t             thread_call_internal_queue;
int                                             thread_call_internal_queue_count = 0;
static uint64_t                 thread_call_dealloc_interval_abs;

static void                     _internal_call_init(void);

static thread_call_t            _internal_call_allocate(thread_call_func_t func, thread_call_param_t param0);
static bool                     _is_internal_call(thread_call_t call);
static void                     _internal_call_release(thread_call_t call);
static bool                     _pending_call_enqueue(thread_call_t call, thread_call_group_t group, uint64_t now);
static bool                     _delayed_call_enqueue(thread_call_t call, thread_call_group_t group,
    uint64_t deadline, thread_call_flavor_t flavor);
static bool                     _call_dequeue(thread_call_t call, thread_call_group_t group);
static void                     thread_call_wake(thread_call_group_t group);
static void                     thread_call_daemon(void *arg);
static void                     thread_call_thread(thread_call_group_t group, wait_result_t wres);
static void                     thread_call_dealloc_timer(timer_call_param_t p0, timer_call_param_t p1);
static void                     thread_call_group_setup(thread_call_group_t group);
static void                     sched_call_thread(int type, thread_t thread);
static void                     thread_call_start_deallocate_timer(thread_call_group_t group);
static void                     thread_call_wait_locked(thread_call_t call, spl_t s);
static bool                     thread_call_wait_once_locked(thread_call_t call, spl_t s);

static boolean_t                thread_call_enter_delayed_internal(thread_call_t call,
    thread_call_func_t alt_func, thread_call_param_t alt_param0,
    thread_call_param_t param1, uint64_t deadline,
    uint64_t leeway, unsigned int flags);

/* non-static so dtrace can find it rdar://problem/31156135&31379348 */
extern void thread_call_delayed_timer(timer_call_param_t p0, timer_call_param_t p1);

LCK_GRP_DECLARE(thread_call_lck_grp, "thread_call");


static void
thread_call_lock_spin(thread_call_group_t group)
{
	lck_ticket_lock(&group->tcg_lock, &thread_call_lck_grp);
}

static void
thread_call_unlock(thread_call_group_t group)
{
	lck_ticket_unlock(&group->tcg_lock);
}

static void __assert_only
thread_call_assert_locked(thread_call_group_t group)
{
	lck_ticket_assert_owned(&group->tcg_lock);
}


static spl_t
disable_ints_and_lock(thread_call_group_t group)
{
	spl_t s = splsched();
	thread_call_lock_spin(group);

	return s;
}

static void
enable_ints_and_unlock(thread_call_group_t group, spl_t s)
{
	thread_call_unlock(group);
	splx(s);
}

/* Lock held */
static thread_call_group_t
thread_call_get_group(thread_call_t call)
{
	thread_call_index_t index = call->tc_index;

	assert(index >= 0 && index < THREAD_CALL_INDEX_MAX);

	return &thread_call_groups[index];
}

/* Lock held */
static thread_call_flavor_t
thread_call_get_flavor(thread_call_t call)
{
	return (call->tc_flags & THREAD_CALL_FLAG_CONTINUOUS) ? TCF_CONTINUOUS : TCF_ABSOLUTE;
}

/* Lock held */
static thread_call_flavor_t
thread_call_set_flavor(thread_call_t call, thread_call_flavor_t flavor)
{
	assert(flavor == TCF_CONTINUOUS || flavor == TCF_ABSOLUTE);
	thread_call_flavor_t old_flavor = thread_call_get_flavor(call);

	if (old_flavor != flavor) {
		if (flavor == TCF_CONTINUOUS) {
			call->tc_flags |= THREAD_CALL_FLAG_CONTINUOUS;
		} else {
			call->tc_flags &= ~THREAD_CALL_FLAG_CONTINUOUS;
		}
	}

	return old_flavor;
}

/* returns true if it was on a queue */
static bool
thread_call_enqueue_tail(
	thread_call_t           call,
	queue_t                 new_queue)
{
	queue_t                 old_queue = call->tc_queue;

	thread_call_group_t     group = thread_call_get_group(call);
	thread_call_flavor_t    flavor = thread_call_get_flavor(call);

	if (old_queue != NULL &&
	    old_queue != &group->delayed_queues[flavor]) {
		panic("thread call (%p) on bad queue (old_queue: %p)", call, old_queue);
	}

	if (old_queue == &group->delayed_queues[flavor]) {
		priority_queue_remove(&group->delayed_pqueues[flavor], &call->tc_pqlink);
	}

	if (old_queue == NULL) {
		enqueue_tail(new_queue, &call->tc_qlink);
	} else {
		re_queue_tail(new_queue, &call->tc_qlink);
	}

	call->tc_queue = new_queue;

	return old_queue != NULL;
}

static queue_head_t *
thread_call_dequeue(
	thread_call_t            call)
{
	queue_t                 old_queue = call->tc_queue;

	thread_call_group_t     group = thread_call_get_group(call);
	thread_call_flavor_t    flavor = thread_call_get_flavor(call);

	if (old_queue != NULL &&
	    old_queue != &group->pending_queue &&
	    old_queue != &group->delayed_queues[flavor]) {
		panic("thread call (%p) on bad queue (old_queue: %p)", call, old_queue);
	}

	if (old_queue == &group->delayed_queues[flavor]) {
		priority_queue_remove(&group->delayed_pqueues[flavor], &call->tc_pqlink);
	}

	if (old_queue != NULL) {
		remqueue(&call->tc_qlink);

		call->tc_queue = NULL;
	}
	return old_queue;
}

static queue_head_t *
thread_call_enqueue_deadline(
	thread_call_t           call,
	thread_call_group_t     group,
	thread_call_flavor_t    flavor,
	uint64_t                deadline)
{
	queue_t old_queue = call->tc_queue;
	queue_t new_queue = &group->delayed_queues[flavor];

	thread_call_flavor_t old_flavor = thread_call_set_flavor(call, flavor);

	if (old_queue != NULL &&
	    old_queue != &group->pending_queue &&
	    old_queue != &group->delayed_queues[old_flavor]) {
		panic("thread call (%p) on bad queue (old_queue: %p)", call, old_queue);
	}

	if (old_queue == new_queue) {
		/* optimize the same-queue case to avoid a full re-insert */
		uint64_t old_deadline = call->tc_pqlink.deadline;
		call->tc_pqlink.deadline = deadline;

		if (old_deadline < deadline) {
			priority_queue_entry_increased(&group->delayed_pqueues[flavor],
			    &call->tc_pqlink);
		} else {
			priority_queue_entry_decreased(&group->delayed_pqueues[flavor],
			    &call->tc_pqlink);
		}
	} else {
		if (old_queue == &group->delayed_queues[old_flavor]) {
			priority_queue_remove(&group->delayed_pqueues[old_flavor],
			    &call->tc_pqlink);
		}

		call->tc_pqlink.deadline = deadline;

		priority_queue_insert(&group->delayed_pqueues[flavor], &call->tc_pqlink);
	}

	if (old_queue == NULL) {
		enqueue_tail(new_queue, &call->tc_qlink);
	} else if (old_queue != new_queue) {
		re_queue_tail(new_queue, &call->tc_qlink);
	}

	call->tc_queue = new_queue;

	return old_queue;
}

uint64_t
thread_call_get_armed_deadline(thread_call_t call)
{
	return call->tc_pqlink.deadline;
}


static bool
group_isparallel(thread_call_group_t group)
{
	return (group->tcg_flags & TCG_PARALLEL) != 0;
}

static bool
thread_call_group_should_add_thread(thread_call_group_t group)
{
	if ((group->active_count + group->blocked_count + group->idle_count) >= THREAD_CALL_GROUP_MAX_THREADS) {
		panic("thread_call group '%s' reached max thread cap (%d): active: %d, blocked: %d, idle: %d",
		    group->tcg_name, THREAD_CALL_GROUP_MAX_THREADS,
		    group->active_count, group->blocked_count, group->idle_count);
	}

	if (group_isparallel(group) == false) {
		if (group->pending_count > 0 && group->active_count == 0) {
			return true;
		}

		return false;
	}

	if (group->pending_count > 0) {
		if (group->idle_count > 0) {
			return false;
		}

		uint32_t thread_count = group->active_count;

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
			return true;
		}
	}

	return false;
}

static void
thread_call_group_setup(thread_call_group_t group)
{
	lck_ticket_init(&group->tcg_lock, &thread_call_lck_grp);

	queue_init(&group->pending_queue);

	for (thread_call_flavor_t flavor = 0; flavor < TCF_COUNT; flavor++) {
		queue_init(&group->delayed_queues[flavor]);
		priority_queue_init(&group->delayed_pqueues[flavor]);
		timer_call_setup(&group->delayed_timers[flavor], thread_call_delayed_timer, group);
	}

	timer_call_setup(&group->dealloc_timer, thread_call_dealloc_timer, group);

	/* Reverse the wait order so we re-use the most recently parked thread from the pool */
	waitq_init(&group->idle_waitq, SYNC_POLICY_REVERSED | SYNC_POLICY_DISABLE_IRQ);
}

/*
 * Simple wrapper for creating threads bound to
 * thread call groups.
 */
static void
thread_call_thread_create(
	thread_call_group_t             group)
{
	thread_t thread;
	kern_return_t result;

	int thread_pri = group->tcg_thread_pri;

	result = kernel_thread_start_priority((thread_continue_t)thread_call_thread,
	    group, thread_pri, &thread);
	if (result != KERN_SUCCESS) {
		panic("cannot create new thread call thread %d", result);
	}

	if (thread_pri <= BASEPRI_KERNEL) {
		/*
		 * THREAD_CALL_PRIORITY_KERNEL and lower don't get to run to completion
		 * in kernel if there are higher priority threads available.
		 */
		thread_set_eager_preempt(thread);
	}

	char name[MAXTHREADNAMESIZE] = "";

	int group_thread_count = group->idle_count + group->active_count + group->blocked_count;

	snprintf(name, sizeof(name), "thread call %s #%d", group->tcg_name, group_thread_count);
	thread_set_thread_name(thread, name);

	thread_deallocate(thread);
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
	nanotime_to_absolutetime(0, THREAD_CALL_DEALLOC_INTERVAL_NS, &thread_call_dealloc_interval_abs);
	waitq_init(&daemon_waitq, SYNC_POLICY_DISABLE_IRQ | SYNC_POLICY_FIFO);

	for (uint32_t i = 0; i < THREAD_CALL_INDEX_MAX; i++) {
		thread_call_group_setup(&thread_call_groups[i]);
	}

	_internal_call_init();

	thread_t thread;
	kern_return_t result;

	result = kernel_thread_start_priority((thread_continue_t)thread_call_daemon,
	    NULL, BASEPRI_PREEMPT_HIGH + 1, &thread);
	if (result != KERN_SUCCESS) {
		panic("thread_call_initialize");
	}

	thread_deallocate(thread);
}

void
thread_call_setup(
	thread_call_t                   call,
	thread_call_func_t              func,
	thread_call_param_t             param0)
{
	bzero(call, sizeof(*call));

	*call = (struct thread_call) {
		.tc_func = func,
		.tc_param0 = param0,

		/*
		 * Thread calls default to the HIGH group
		 * unless otherwise specified.
		 */
		.tc_index = THREAD_CALL_INDEX_HIGH,
	};
}

static void
_internal_call_init(void)
{
	/* Function-only thread calls are only kept in the default HIGH group */
	thread_call_group_t group = &thread_call_groups[THREAD_CALL_INDEX_HIGH];

	spl_t s = disable_ints_and_lock(group);

	queue_init(&thread_call_internal_queue);

	for (unsigned i = 0; i < INTERNAL_CALL_COUNT; i++) {
		enqueue_tail(&thread_call_internal_queue, &internal_call_storage[i].tc_qlink);
		thread_call_internal_queue_count++;
	}

	enable_ints_and_unlock(group, s);
}

/*
 *	_internal_call_allocate:
 *
 *	Allocate an internal callout entry.
 *
 *	Called with thread_call_lock held.
 */
static thread_call_t
_internal_call_allocate(thread_call_func_t func, thread_call_param_t param0)
{
	/* Function-only thread calls are only kept in the default HIGH group */
	thread_call_group_t group = &thread_call_groups[THREAD_CALL_INDEX_HIGH];

	spl_t s = disable_ints_and_lock(group);

	thread_call_t call = qe_dequeue_head(&thread_call_internal_queue,
	    struct thread_call, tc_qlink);

	if (call == NULL) {
		panic("_internal_call_allocate: thread_call_internal_queue empty");
	}

	thread_call_internal_queue_count--;

	thread_call_setup(call, func, param0);
	call->tc_refs = 0;
	call->tc_flags = 0; /* THREAD_CALL_ALLOC not set, do not free back to zone */
	enable_ints_and_unlock(group, s);

	return call;
}

/* Check if a call is internal and needs to be returned to the internal pool. */
static bool
_is_internal_call(thread_call_t call)
{
	if (call >= internal_call_storage &&
	    call < &internal_call_storage[INTERNAL_CALL_COUNT]) {
		assert((call->tc_flags & THREAD_CALL_ALLOC) == 0);
		return true;
	}
	return false;
}

/*
 *	_internal_call_release:
 *
 *	Release an internal callout entry which
 *	is no longer pending (or delayed).
 *
 *      Called with thread_call_lock held.
 */
static void
_internal_call_release(thread_call_t call)
{
	assert(_is_internal_call(call));

	thread_call_group_t group = thread_call_get_group(call);

	assert(group == &thread_call_groups[THREAD_CALL_INDEX_HIGH]);
	thread_call_assert_locked(group);

	enqueue_head(&thread_call_internal_queue, &call->tc_qlink);
	thread_call_internal_queue_count++;
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
static bool
_pending_call_enqueue(thread_call_t call,
    thread_call_group_t group,
    uint64_t now)
{
	if ((THREAD_CALL_ONCE | THREAD_CALL_RUNNING)
	    == (call->tc_flags & (THREAD_CALL_ONCE | THREAD_CALL_RUNNING))) {
		call->tc_pqlink.deadline = 0;

		thread_call_flags_t flags = call->tc_flags;
		call->tc_flags |= THREAD_CALL_RESCHEDULE;

		assert(call->tc_queue == NULL);

		return flags & THREAD_CALL_RESCHEDULE;
	}

	call->tc_pending_timestamp = now;

	bool was_on_queue = thread_call_enqueue_tail(call, &group->pending_queue);

	if (!was_on_queue) {
		call->tc_submit_count++;
	}

	group->pending_count++;

	thread_call_wake(group);

	return was_on_queue;
}

/*
 *	_delayed_call_enqueue:
 *
 *	Place an entry on the delayed queue,
 *	after existing entries with an earlier
 *      (or identical) deadline.
 *
 *	Returns TRUE if the entry was already
 *	on a queue.
 *
 *	Called with thread_call_lock held.
 */
static bool
_delayed_call_enqueue(
	thread_call_t           call,
	thread_call_group_t     group,
	uint64_t                deadline,
	thread_call_flavor_t    flavor)
{
	if ((THREAD_CALL_ONCE | THREAD_CALL_RUNNING)
	    == (call->tc_flags & (THREAD_CALL_ONCE | THREAD_CALL_RUNNING))) {
		call->tc_pqlink.deadline = deadline;

		thread_call_flags_t flags = call->tc_flags;
		call->tc_flags |= THREAD_CALL_RESCHEDULE;

		assert(call->tc_queue == NULL);
		thread_call_set_flavor(call, flavor);

		return flags & THREAD_CALL_RESCHEDULE;
	}

	queue_head_t *old_queue = thread_call_enqueue_deadline(call, group, flavor, deadline);

	if (old_queue == &group->pending_queue) {
		group->pending_count--;
	} else if (old_queue == NULL) {
		call->tc_submit_count++;
	}

	return old_queue != NULL;
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
static bool
_call_dequeue(
	thread_call_t           call,
	thread_call_group_t     group)
{
	queue_head_t *old_queue = thread_call_dequeue(call);

	if (old_queue == NULL) {
		return false;
	}

	call->tc_finish_count++;

	if (old_queue == &group->pending_queue) {
		group->pending_count--;
	}

	return true;
}

/*
 * _arm_delayed_call_timer:
 *
 * Check if the timer needs to be armed for this flavor,
 * and if so, arm it.
 *
 * If call is non-NULL, only re-arm the timer if the specified call
 * is the first in the queue.
 *
 * Returns true if the timer was armed/re-armed, false if it was left unset
 * Caller should cancel the timer if need be.
 *
 * Called with thread_call_lock held.
 */
static bool
_arm_delayed_call_timer(thread_call_t           new_call,
    thread_call_group_t     group,
    thread_call_flavor_t    flavor)
{
	/* No calls implies no timer needed */
	if (queue_empty(&group->delayed_queues[flavor])) {
		return false;
	}

	thread_call_t call = priority_queue_min(&group->delayed_pqueues[flavor], struct thread_call, tc_pqlink);

	/* We only need to change the hard timer if this new call is the first in the list */
	if (new_call != NULL && new_call != call) {
		return false;
	}

	assert((call->tc_soft_deadline != 0) && ((call->tc_soft_deadline <= call->tc_pqlink.deadline)));

	uint64_t fire_at = call->tc_soft_deadline;

	if (flavor == TCF_CONTINUOUS) {
		assert(call->tc_flags & THREAD_CALL_FLAG_CONTINUOUS);
		fire_at = continuoustime_to_absolutetime(fire_at);
	} else {
		assert((call->tc_flags & THREAD_CALL_FLAG_CONTINUOUS) == 0);
	}

	/*
	 * Note: This picks the soonest-deadline call's leeway as the hard timer's leeway,
	 * which does not take into account later-deadline timers with a larger leeway.
	 * This is a valid coalescing behavior, but masks a possible window to
	 * fire a timer instead of going idle.
	 */
	uint64_t leeway = call->tc_pqlink.deadline - call->tc_soft_deadline;

	timer_call_enter_with_leeway(&group->delayed_timers[flavor], (timer_call_param_t)flavor,
	    fire_at, leeway,
	    TIMER_CALL_SYS_CRITICAL | TIMER_CALL_LEEWAY,
	    ((call->tc_flags & THREAD_CALL_RATELIMITED) == THREAD_CALL_RATELIMITED));

	return true;
}

/*
 *	_cancel_func_from_queue:
 *
 *	Remove the first (or all) matching
 *	entries from the specified queue.
 *
 *	Returns TRUE if any matching entries
 *	were found.
 *
 *	Called with thread_call_lock held.
 */
static boolean_t
_cancel_func_from_queue(thread_call_func_t      func,
    thread_call_param_t     param0,
    thread_call_group_t     group,
    boolean_t               remove_all,
    queue_head_t            *queue)
{
	boolean_t call_removed = FALSE;
	thread_call_t call;

	qe_foreach_element_safe(call, queue, tc_qlink) {
		if (call->tc_func != func ||
		    call->tc_param0 != param0) {
			continue;
		}

		_call_dequeue(call, group);

		if (_is_internal_call(call)) {
			_internal_call_release(call);
		}

		call_removed = TRUE;
		if (!remove_all) {
			break;
		}
	}

	return call_removed;
}

/*
 *	thread_call_func_delayed:
 *
 *	Enqueue a function callout to
 *	occur at the stated time.
 */
void
thread_call_func_delayed(
	thread_call_func_t              func,
	thread_call_param_t             param,
	uint64_t                        deadline)
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
	thread_call_func_t              func,
	thread_call_param_t             param,
	uint64_t                deadline,
	uint64_t                leeway,
	uint32_t                flags)
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
 *
 *	This iterates all of the pending or delayed thread calls in the group,
 *	which is really inefficient.  Switch to an allocated thread call instead.
 *
 *	TODO: Give 'func' thread calls their own group, so this silliness doesn't
 *	affect the main 'high' group.
 */
boolean_t
thread_call_func_cancel(
	thread_call_func_t              func,
	thread_call_param_t             param,
	boolean_t                       cancel_all)
{
	boolean_t       result;

	assert(func != NULL);

	/* Function-only thread calls are only kept in the default HIGH group */
	thread_call_group_t group = &thread_call_groups[THREAD_CALL_INDEX_HIGH];

	spl_t s = disable_ints_and_lock(group);

	if (cancel_all) {
		/* exhaustively search every queue, and return true if any search found something */
		result = _cancel_func_from_queue(func, param, group, cancel_all, &group->pending_queue) |
		    _cancel_func_from_queue(func, param, group, cancel_all, &group->delayed_queues[TCF_ABSOLUTE])  |
		    _cancel_func_from_queue(func, param, group, cancel_all, &group->delayed_queues[TCF_CONTINUOUS]);
	} else {
		/* early-exit as soon as we find something, don't search other queues */
		result = _cancel_func_from_queue(func, param, group, cancel_all, &group->pending_queue) ||
		    _cancel_func_from_queue(func, param, group, cancel_all, &group->delayed_queues[TCF_ABSOLUTE]) ||
		    _cancel_func_from_queue(func, param, group, cancel_all, &group->delayed_queues[TCF_CONTINUOUS]);
	}

	enable_ints_and_unlock(group, s);

	return result;
}

/*
 * Allocate a thread call with a given priority.  Importances other than
 * THREAD_CALL_PRIORITY_HIGH or THREAD_CALL_PRIORITY_KERNEL_HIGH will be run in threads
 * with eager preemption enabled (i.e. may be aggressively preempted by higher-priority
 * threads which are not in the normal "urgent" bands).
 */
thread_call_t
thread_call_allocate_with_priority(
	thread_call_func_t              func,
	thread_call_param_t             param0,
	thread_call_priority_t          pri)
{
	return thread_call_allocate_with_options(func, param0, pri, 0);
}

thread_call_t
thread_call_allocate_with_options(
	thread_call_func_t              func,
	thread_call_param_t             param0,
	thread_call_priority_t          pri,
	thread_call_options_t           options)
{
	thread_call_t call = thread_call_allocate(func, param0);

	switch (pri) {
	case THREAD_CALL_PRIORITY_HIGH:
		call->tc_index = THREAD_CALL_INDEX_HIGH;
		break;
	case THREAD_CALL_PRIORITY_KERNEL:
		call->tc_index = THREAD_CALL_INDEX_KERNEL;
		break;
	case THREAD_CALL_PRIORITY_USER:
		call->tc_index = THREAD_CALL_INDEX_USER;
		break;
	case THREAD_CALL_PRIORITY_LOW:
		call->tc_index = THREAD_CALL_INDEX_LOW;
		break;
	case THREAD_CALL_PRIORITY_KERNEL_HIGH:
		call->tc_index = THREAD_CALL_INDEX_KERNEL_HIGH;
		break;
	default:
		panic("Invalid thread call pri value: %d", pri);
		break;
	}

	if (options & THREAD_CALL_OPTIONS_ONCE) {
		call->tc_flags |= THREAD_CALL_ONCE;
	}
	if (options & THREAD_CALL_OPTIONS_SIGNAL) {
		call->tc_flags |= THREAD_CALL_SIGNAL | THREAD_CALL_ONCE;
	}

	return call;
}

thread_call_t
thread_call_allocate_with_qos(thread_call_func_t        func,
    thread_call_param_t       param0,
    int                       qos_tier,
    thread_call_options_t     options)
{
	thread_call_t call = thread_call_allocate(func, param0);

	switch (qos_tier) {
	case THREAD_QOS_UNSPECIFIED:
		call->tc_index = THREAD_CALL_INDEX_HIGH;
		break;
	case THREAD_QOS_LEGACY:
		call->tc_index = THREAD_CALL_INDEX_USER;
		break;
	case THREAD_QOS_MAINTENANCE:
	case THREAD_QOS_BACKGROUND:
		call->tc_index = THREAD_CALL_INDEX_LOW;
		break;
	case THREAD_QOS_UTILITY:
		call->tc_index = THREAD_CALL_INDEX_QOS_UT;
		break;
	case THREAD_QOS_USER_INITIATED:
		call->tc_index = THREAD_CALL_INDEX_QOS_IN;
		break;
	case THREAD_QOS_USER_INTERACTIVE:
		call->tc_index = THREAD_CALL_INDEX_QOS_UI;
		break;
	default:
		panic("Invalid thread call qos value: %d", qos_tier);
		break;
	}

	if (options & THREAD_CALL_OPTIONS_ONCE) {
		call->tc_flags |= THREAD_CALL_ONCE;
	}

	/* does not support THREAD_CALL_OPTIONS_SIGNAL */

	return call;
}


/*
 *	thread_call_allocate:
 *
 *	Allocate a callout entry.
 */
thread_call_t
thread_call_allocate(
	thread_call_func_t              func,
	thread_call_param_t             param0)
{
	thread_call_t   call = zalloc(thread_call_zone);

	thread_call_setup(call, func, param0);
	call->tc_refs = 1;
	call->tc_flags = THREAD_CALL_ALLOC;

	return call;
}

/*
 *	thread_call_free:
 *
 *	Release a callout.  If the callout is currently
 *	executing, it will be freed when all invocations
 *	finish.
 *
 *	If the callout is currently armed to fire again, then
 *	freeing is not allowed and returns FALSE.  The
 *	client must have canceled the pending invocation before freeing.
 */
boolean_t
thread_call_free(
	thread_call_t           call)
{
	thread_call_group_t group = thread_call_get_group(call);

	spl_t s = disable_ints_and_lock(group);

	if (call->tc_queue != NULL ||
	    ((call->tc_flags & THREAD_CALL_RESCHEDULE) != 0)) {
		thread_call_unlock(group);
		splx(s);

		return FALSE;
	}

	int32_t refs = --call->tc_refs;
	if (refs < 0) {
		panic("Refcount negative: %d\n", refs);
	}

	if ((THREAD_CALL_SIGNAL | THREAD_CALL_RUNNING)
	    == ((THREAD_CALL_SIGNAL | THREAD_CALL_RUNNING) & call->tc_flags)) {
		thread_call_wait_once_locked(call, s);
		/* thread call lock has been unlocked */
	} else {
		enable_ints_and_unlock(group, s);
	}

	if (refs == 0) {
		assert(call->tc_finish_count == call->tc_submit_count);
		zfree(thread_call_zone, call);
	}

	return TRUE;
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
	thread_call_t           call)
{
	return thread_call_enter1(call, 0);
}

boolean_t
thread_call_enter1(
	thread_call_t                   call,
	thread_call_param_t             param1)
{
	assert(call->tc_func != NULL);
	assert((call->tc_flags & THREAD_CALL_SIGNAL) == 0);

	thread_call_group_t group = thread_call_get_group(call);
	bool result = true;

	spl_t s = disable_ints_and_lock(group);

	if (call->tc_queue != &group->pending_queue) {
		result = _pending_call_enqueue(call, group, mach_absolute_time());
	}

	call->tc_param1 = param1;

	enable_ints_and_unlock(group, s);

	return result;
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
	thread_call_t           call,
	uint64_t                deadline)
{
	assert(call != NULL);
	return thread_call_enter_delayed_internal(call, NULL, 0, 0, deadline, 0, 0);
}

boolean_t
thread_call_enter1_delayed(
	thread_call_t                   call,
	thread_call_param_t             param1,
	uint64_t                        deadline)
{
	assert(call != NULL);
	return thread_call_enter_delayed_internal(call, NULL, 0, param1, deadline, 0, 0);
}

boolean_t
thread_call_enter_delayed_with_leeway(
	thread_call_t           call,
	thread_call_param_t     param1,
	uint64_t                deadline,
	uint64_t                leeway,
	unsigned int            flags)
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
 *                                                                        than mach_absolute_time
 */
boolean_t
thread_call_enter_delayed_internal(
	thread_call_t           call,
	thread_call_func_t      alt_func,
	thread_call_param_t     alt_param0,
	thread_call_param_t     param1,
	uint64_t                deadline,
	uint64_t                leeway,
	unsigned int            flags)
{
	uint64_t                now, sdeadline;

	thread_call_flavor_t flavor = (flags & THREAD_CALL_CONTINUOUS) ? TCF_CONTINUOUS : TCF_ABSOLUTE;

	/* direct mapping between thread_call, timer_call, and timeout_urgency values */
	uint32_t urgency = (flags & TIMEOUT_URGENCY_MASK);

	if (call == NULL) {
		/* allocate a structure out of internal storage, as a convenience for BSD callers */
		call = _internal_call_allocate(alt_func, alt_param0);
	}

	assert(call->tc_func != NULL);
	thread_call_group_t group = thread_call_get_group(call);

	spl_t s = disable_ints_and_lock(group);

	/*
	 * kevent and IOTES let you change flavor for an existing timer, so we have to
	 * support flipping flavors for enqueued thread calls.
	 */
	if (flavor == TCF_CONTINUOUS) {
		now = mach_continuous_time();
	} else {
		now = mach_absolute_time();
	}

	call->tc_flags |= THREAD_CALL_DELAYED;

	call->tc_soft_deadline = sdeadline = deadline;

	boolean_t ratelimited = FALSE;
	uint64_t slop = timer_call_slop(deadline, now, urgency, current_thread(), &ratelimited);

	if ((flags & THREAD_CALL_DELAY_LEEWAY) != 0 && leeway > slop) {
		slop = leeway;
	}

	if (UINT64_MAX - deadline <= slop) {
		deadline = UINT64_MAX;
	} else {
		deadline += slop;
	}

	if (ratelimited) {
		call->tc_flags |= THREAD_CALL_RATELIMITED;
	} else {
		call->tc_flags &= ~THREAD_CALL_RATELIMITED;
	}

	call->tc_param1 = param1;

	call->tc_ttd = (sdeadline > now) ? (sdeadline - now) : 0;

	bool result = _delayed_call_enqueue(call, group, deadline, flavor);

	_arm_delayed_call_timer(call, group, flavor);

#if CONFIG_DTRACE
	DTRACE_TMR5(thread_callout__create, thread_call_func_t, call->tc_func,
	    uint64_t, (deadline - sdeadline), uint64_t, (call->tc_ttd >> 32),
	    (unsigned) (call->tc_ttd & 0xFFFFFFFF), call);
#endif

	enable_ints_and_unlock(group, s);

	return result;
}

/*
 * Remove a callout entry from the queue
 * Called with thread_call_lock held
 */
static bool
thread_call_cancel_locked(thread_call_t call)
{
	bool canceled;

	if (call->tc_flags & THREAD_CALL_RESCHEDULE) {
		call->tc_flags &= ~THREAD_CALL_RESCHEDULE;
		canceled = true;

		/* if reschedule was set, it must not have been queued */
		assert(call->tc_queue == NULL);
	} else {
		bool queue_head_changed = false;

		thread_call_flavor_t flavor = thread_call_get_flavor(call);
		thread_call_group_t  group  = thread_call_get_group(call);

		if (call->tc_pqlink.deadline != 0 &&
		    call == priority_queue_min(&group->delayed_pqueues[flavor], struct thread_call, tc_pqlink)) {
			assert(call->tc_queue == &group->delayed_queues[flavor]);
			queue_head_changed = true;
		}

		canceled = _call_dequeue(call, group);

		if (queue_head_changed) {
			if (_arm_delayed_call_timer(NULL, group, flavor) == false) {
				timer_call_cancel(&group->delayed_timers[flavor]);
			}
		}
	}

#if CONFIG_DTRACE
	DTRACE_TMR4(thread_callout__cancel, thread_call_func_t, call->tc_func,
	    0, (call->tc_ttd >> 32), (unsigned) (call->tc_ttd & 0xFFFFFFFF));
#endif

	return canceled;
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
thread_call_cancel(thread_call_t call)
{
	thread_call_group_t group = thread_call_get_group(call);

	spl_t s = disable_ints_and_lock(group);

	boolean_t result = thread_call_cancel_locked(call);

	enable_ints_and_unlock(group, s);

	return result;
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
thread_call_cancel_wait(thread_call_t call)
{
	thread_call_group_t group = thread_call_get_group(call);

	if ((call->tc_flags & THREAD_CALL_ALLOC) == 0) {
		panic("thread_call_cancel_wait: can't wait on thread call whose storage I don't own");
	}

	if (!ml_get_interrupts_enabled()) {
		panic("unsafe thread_call_cancel_wait");
	}

	thread_t self = current_thread();

	if ((thread_get_tag_internal(self) & THREAD_TAG_CALLOUT) &&
	    self->thc_state && self->thc_state->thc_call == call) {
		panic("thread_call_cancel_wait: deadlock waiting on self from inside call: %p to function %p",
		    call, call->tc_func);
	}

	spl_t s = disable_ints_and_lock(group);

	boolean_t canceled = thread_call_cancel_locked(call);

	if ((call->tc_flags & THREAD_CALL_ONCE) == THREAD_CALL_ONCE) {
		/*
		 * A cancel-wait on a 'once' call will both cancel
		 * the pending call and wait for the in-flight call
		 */

		thread_call_wait_once_locked(call, s);
		/* thread call lock unlocked */
	} else {
		/*
		 * A cancel-wait on a normal call will only wait for the in-flight calls
		 * if it did not cancel the pending call.
		 *
		 * TODO: This seems less than useful - shouldn't it do the wait as well?
		 */

		if (canceled == FALSE) {
			thread_call_wait_locked(call, s);
			/* thread call lock unlocked */
		} else {
			enable_ints_and_unlock(group, s);
		}
	}

	return canceled;
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
static void
thread_call_wake(
	thread_call_group_t             group)
{
	/*
	 * New behavior: use threads if you've got 'em.
	 * Traditional behavior: wake only if no threads running.
	 */
	if (group_isparallel(group) || group->active_count == 0) {
		if (group->idle_count) {
			__assert_only kern_return_t kr;

			kr = waitq_wakeup64_one(&group->idle_waitq, NO_EVENT64,
			    THREAD_AWAKENED, WAITQ_ALL_PRIORITIES);
			assert(kr == KERN_SUCCESS);

			group->idle_count--;
			group->active_count++;

			if (group->idle_count == 0 && (group->tcg_flags & TCG_DEALLOC_ACTIVE) == TCG_DEALLOC_ACTIVE) {
				if (timer_call_cancel(&group->dealloc_timer) == TRUE) {
					group->tcg_flags &= ~TCG_DEALLOC_ACTIVE;
				}
			}
		} else {
			if (thread_call_group_should_add_thread(group) &&
			    os_atomic_cmpxchg(&thread_call_daemon_awake,
			    false, true, relaxed)) {
				waitq_wakeup64_all(&daemon_waitq, NO_EVENT64,
				    THREAD_AWAKENED, WAITQ_ALL_PRIORITIES);
			}
		}
	}
}

/*
 *	sched_call_thread:
 *
 *	Call out invoked by the scheduler.
 */
static void
sched_call_thread(
	int                             type,
	thread_t                thread)
{
	thread_call_group_t             group;

	assert(thread_get_tag_internal(thread) & THREAD_TAG_CALLOUT);
	assert(thread->thc_state != NULL);

	group = thread->thc_state->thc_group;
	assert((group - &thread_call_groups[0]) < THREAD_CALL_INDEX_MAX);

	thread_call_lock_spin(group);

	switch (type) {
	case SCHED_CALL_BLOCK:
		assert(group->active_count);
		--group->active_count;
		group->blocked_count++;
		if (group->pending_count > 0) {
			thread_call_wake(group);
		}
		break;

	case SCHED_CALL_UNBLOCK:
		assert(group->blocked_count);
		--group->blocked_count;
		group->active_count++;
		break;
	}

	thread_call_unlock(group);
}

/*
 * Interrupts disabled, lock held; returns the same way.
 * Only called on thread calls whose storage we own.  Wakes up
 * anyone who might be waiting on this work item and frees it
 * if the client has so requested.
 */
static bool
thread_call_finish(thread_call_t call, thread_call_group_t group, spl_t *s)
{
	assert(thread_call_get_group(call) == group);

	bool repend = false;
	bool signal = call->tc_flags & THREAD_CALL_SIGNAL;

	call->tc_finish_count++;

	if (!signal) {
		/* The thread call thread owns a ref until the call is finished */
		if (call->tc_refs <= 0) {
			panic("thread_call_finish: detected over-released thread call: %p", call);
		}
		call->tc_refs--;
	}

	thread_call_flags_t old_flags = call->tc_flags;
	call->tc_flags &= ~(THREAD_CALL_RESCHEDULE | THREAD_CALL_RUNNING | THREAD_CALL_WAIT);

	if (call->tc_refs != 0 && (old_flags & THREAD_CALL_RESCHEDULE) != 0) {
		assert(old_flags & THREAD_CALL_ONCE);
		thread_call_flavor_t flavor = thread_call_get_flavor(call);

		if (old_flags & THREAD_CALL_DELAYED) {
			uint64_t now = mach_absolute_time();
			if (flavor == TCF_CONTINUOUS) {
				now = absolutetime_to_continuoustime(now);
			}
			if (call->tc_soft_deadline <= now) {
				/* The deadline has already expired, go straight to pending */
				call->tc_flags &= ~(THREAD_CALL_DELAYED | THREAD_CALL_RATELIMITED);
				call->tc_pqlink.deadline = 0;
			}
		}

		if (call->tc_pqlink.deadline) {
			_delayed_call_enqueue(call, group, call->tc_pqlink.deadline, flavor);
			if (!signal) {
				_arm_delayed_call_timer(call, group, flavor);
			}
		} else if (signal) {
			call->tc_submit_count++;
			repend = true;
		} else {
			_pending_call_enqueue(call, group, mach_absolute_time());
		}
	}

	if (!signal && (call->tc_refs == 0)) {
		if ((old_flags & THREAD_CALL_WAIT) != 0) {
			panic("Someone waiting on a thread call that is scheduled for free: %p\n", call->tc_func);
		}

		assert(call->tc_finish_count == call->tc_submit_count);

		enable_ints_and_unlock(group, *s);

		zfree(thread_call_zone, call);

		*s = disable_ints_and_lock(group);
	}

	if ((old_flags & THREAD_CALL_WAIT) != 0) {
		/*
		 * Dropping lock here because the sched call for the
		 * high-pri group can take the big lock from under
		 * a thread lock.
		 */
		thread_call_unlock(group);
		thread_wakeup((event_t)call);
		thread_call_lock_spin(group);
		/* THREAD_CALL_SIGNAL call may have been freed */
	}

	return repend;
}

/*
 * thread_call_invoke
 *
 * Invoke the function provided for this thread call
 *
 * Note that the thread call object can be deallocated by the function if we do not control its storage.
 */
static void __attribute__((noinline))
thread_call_invoke(thread_call_func_t func,
    thread_call_param_t param0,
    thread_call_param_t param1,
    __unused thread_call_t call)
{
#if DEVELOPMENT || DEBUG
	KERNEL_DEBUG_CONSTANT(
		MACHDBG_CODE(DBG_MACH_SCHED, MACH_CALLOUT) | DBG_FUNC_START,
		VM_KERNEL_UNSLIDE(func), VM_KERNEL_ADDRHIDE(param0), VM_KERNEL_ADDRHIDE(param1), 0, 0);
#endif /* DEVELOPMENT || DEBUG */

#if CONFIG_DTRACE
	uint64_t tc_ttd = call->tc_ttd;
	boolean_t is_delayed = call->tc_flags & THREAD_CALL_DELAYED;
	DTRACE_TMR6(thread_callout__start, thread_call_func_t, func, int, 0, int, (tc_ttd >> 32),
	    (unsigned) (tc_ttd & 0xFFFFFFFF), is_delayed, call);
#endif

	(*func)(param0, param1);

#if CONFIG_DTRACE
	DTRACE_TMR6(thread_callout__end, thread_call_func_t, func, int, 0, int, (tc_ttd >> 32),
	    (unsigned) (tc_ttd & 0xFFFFFFFF), is_delayed, call);
#endif

#if DEVELOPMENT || DEBUG
	KERNEL_DEBUG_CONSTANT(
		MACHDBG_CODE(DBG_MACH_SCHED, MACH_CALLOUT) | DBG_FUNC_END,
		VM_KERNEL_UNSLIDE(func), 0, 0, 0, 0);
#endif /* DEVELOPMENT || DEBUG */
}

/*
 *	thread_call_thread:
 */
static void
thread_call_thread(
	thread_call_group_t             group,
	wait_result_t                   wres)
{
	thread_t self = current_thread();

	if ((thread_get_tag_internal(self) & THREAD_TAG_CALLOUT) == 0) {
		(void)thread_set_tag_internal(self, THREAD_TAG_CALLOUT);
	}

	/*
	 * A wakeup with THREAD_INTERRUPTED indicates that
	 * we should terminate.
	 */
	if (wres == THREAD_INTERRUPTED) {
		thread_terminate(self);

		/* NOTREACHED */
		panic("thread_terminate() returned?");
	}

	spl_t s = disable_ints_and_lock(group);

	struct thread_call_thread_state thc_state = { .thc_group = group };
	self->thc_state = &thc_state;

	thread_sched_call(self, sched_call_thread);

	while (group->pending_count > 0) {
		thread_call_t call = qe_dequeue_head(&group->pending_queue,
		    struct thread_call, tc_qlink);
		assert(call != NULL);

		group->pending_count--;
		if (group->pending_count == 0) {
			assert(queue_empty(&group->pending_queue));
		}

		thread_call_func_t  func   = call->tc_func;
		thread_call_param_t param0 = call->tc_param0;
		thread_call_param_t param1 = call->tc_param1;

		call->tc_queue = NULL;

		if (_is_internal_call(call)) {
			_internal_call_release(call);
		}

		/*
		 * Can only do wakeups for thread calls whose storage
		 * we control.
		 */
		bool needs_finish = false;
		if (call->tc_flags & THREAD_CALL_ALLOC) {
			needs_finish = true;
			call->tc_flags |= THREAD_CALL_RUNNING;
			call->tc_refs++;        /* Delay free until we're done */
		}

		thc_state.thc_call = call;
		thc_state.thc_call_pending_timestamp = call->tc_pending_timestamp;
		thc_state.thc_call_soft_deadline = call->tc_soft_deadline;
		thc_state.thc_call_hard_deadline = call->tc_pqlink.deadline;
		thc_state.thc_func = func;
		thc_state.thc_param0 = param0;
		thc_state.thc_param1 = param1;
		thc_state.thc_IOTES_invocation_timestamp = 0;

		enable_ints_and_unlock(group, s);

		thc_state.thc_call_start = mach_absolute_time();

		thread_call_invoke(func, param0, param1, call);

		thc_state.thc_call = NULL;

		if (get_preemption_level() != 0) {
			int pl = get_preemption_level();
			panic("thread_call_thread: preemption_level %d, last callout %p(%p, %p)",
			    pl, (void *)VM_KERNEL_UNSLIDE(func), param0, param1);
		}

		s = disable_ints_and_lock(group);

		if (needs_finish) {
			/* Release refcount, may free */
			thread_call_finish(call, group, &s);
		}
	}

	thread_sched_call(self, NULL);
	group->active_count--;

	if (self->callout_woken_from_icontext && !self->callout_woke_thread) {
		ledger_credit(self->t_ledger, task_ledgers.interrupt_wakeups, 1);
		if (self->callout_woken_from_platform_idle) {
			ledger_credit(self->t_ledger, task_ledgers.platform_idle_wakeups, 1);
		}
	}

	self->callout_woken_from_icontext = FALSE;
	self->callout_woken_from_platform_idle = FALSE;
	self->callout_woke_thread = FALSE;

	self->thc_state = NULL;

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

		if (((group->tcg_flags & TCG_DEALLOC_ACTIVE) == 0) &&
		    ((group->active_count + group->idle_count) > group->target_thread_count)) {
			thread_call_start_deallocate_timer(group);
		}

		/* Wait for more work (or termination) */
		wres = waitq_assert_wait64(&group->idle_waitq, NO_EVENT64, THREAD_INTERRUPTIBLE, 0);
		if (wres != THREAD_WAITING) {
			panic("kcall worker unable to assert wait?");
		}

		enable_ints_and_unlock(group, s);

		thread_block_parameter((thread_continue_t)thread_call_thread, group);
	} else {
		if (group->idle_count < group->target_thread_count) {
			group->idle_count++;

			waitq_assert_wait64(&group->idle_waitq, NO_EVENT64, THREAD_UNINT, 0); /* Interrupted means to exit */

			enable_ints_and_unlock(group, s);

			thread_block_parameter((thread_continue_t)thread_call_thread, group);
			/* NOTREACHED */
		}
	}

	enable_ints_and_unlock(group, s);

	thread_terminate(self);
	/* NOTREACHED */
}

void
thread_call_start_iotes_invocation(__assert_only thread_call_t call)
{
	thread_t self = current_thread();

	if ((thread_get_tag_internal(self) & THREAD_TAG_CALLOUT) == 0) {
		/* not a thread call thread, might be a workloop IOTES */
		return;
	}

	assert(self->thc_state);
	assert(self->thc_state->thc_call == call);

	self->thc_state->thc_IOTES_invocation_timestamp = mach_absolute_time();
}


/*
 *	thread_call_daemon: walk list of groups, allocating
 *	threads if appropriate (as determined by
 *	thread_call_group_should_add_thread()).
 */
static void
thread_call_daemon_continue(__unused void *arg)
{
	do {
		os_atomic_store(&thread_call_daemon_awake, false, relaxed);

		/* Starting at zero happens to be high-priority first. */
		for (int i = 0; i < THREAD_CALL_INDEX_MAX; i++) {
			thread_call_group_t group = &thread_call_groups[i];

			spl_t s = disable_ints_and_lock(group);

			while (thread_call_group_should_add_thread(group)) {
				group->active_count++;

				enable_ints_and_unlock(group, s);

				thread_call_thread_create(group);

				s = disable_ints_and_lock(group);
			}

			enable_ints_and_unlock(group, s);
		}
	} while (os_atomic_load(&thread_call_daemon_awake, relaxed));

	waitq_assert_wait64(&daemon_waitq, NO_EVENT64, THREAD_UNINT, 0);

	if (os_atomic_load(&thread_call_daemon_awake, relaxed)) {
		clear_wait(current_thread(), THREAD_AWAKENED);
	}

	thread_block_parameter((thread_continue_t)thread_call_daemon_continue, NULL);
	/* NOTREACHED */
}

static void
thread_call_daemon(
	__unused void    *arg)
{
	thread_t        self = current_thread();

	self->options |= TH_OPT_VMPRIV;
	vm_page_free_reserve(2);        /* XXX */

	thread_set_thread_name(self, "thread_call_daemon");

	thread_call_daemon_continue(NULL);
	/* NOTREACHED */
}

/*
 * Schedule timer to deallocate a worker thread if we have a surplus
 * of threads (in excess of the group's target) and at least one thread
 * is idle the whole time.
 */
static void
thread_call_start_deallocate_timer(thread_call_group_t group)
{
	__assert_only bool already_enqueued;

	assert(group->idle_count > 0);
	assert((group->tcg_flags & TCG_DEALLOC_ACTIVE) == 0);

	group->tcg_flags |= TCG_DEALLOC_ACTIVE;

	uint64_t deadline = group->idle_timestamp + thread_call_dealloc_interval_abs;

	already_enqueued = timer_call_enter(&group->dealloc_timer, deadline, 0);

	assert(already_enqueued == false);
}

/* non-static so dtrace can find it rdar://problem/31156135&31379348 */
void
thread_call_delayed_timer(timer_call_param_t p0, timer_call_param_t p1)
{
	thread_call_group_t  group  = (thread_call_group_t)  p0;
	thread_call_flavor_t flavor = (thread_call_flavor_t) p1;

	thread_call_t   call;
	uint64_t        now;

	thread_call_lock_spin(group);

	if (flavor == TCF_CONTINUOUS) {
		now = mach_continuous_time();
	} else if (flavor == TCF_ABSOLUTE) {
		now = mach_absolute_time();
	} else {
		panic("invalid timer flavor: %d", flavor);
	}

	while ((call = priority_queue_min(&group->delayed_pqueues[flavor],
	    struct thread_call, tc_pqlink)) != NULL) {
		assert(thread_call_get_group(call) == group);
		assert(thread_call_get_flavor(call) == flavor);

		/*
		 * if we hit a call that isn't yet ready to expire,
		 * then we're done for now
		 * TODO: The next timer in the list could have a larger leeway
		 *       and therefore be ready to expire.
		 */
		if (call->tc_soft_deadline > now) {
			break;
		}

		/*
		 * If we hit a rate-limited timer, don't eagerly wake it up.
		 * Wait until it reaches the end of the leeway window.
		 *
		 * TODO: What if the next timer is not rate-limited?
		 *       Have a separate rate-limited queue to avoid this
		 */
		if ((call->tc_flags & THREAD_CALL_RATELIMITED) &&
		    (call->tc_pqlink.deadline > now) &&
		    (ml_timer_forced_evaluation() == FALSE)) {
			break;
		}

		if (THREAD_CALL_SIGNAL & call->tc_flags) {
			__assert_only queue_head_t *old_queue;
			old_queue = thread_call_dequeue(call);
			assert(old_queue == &group->delayed_queues[flavor]);

			do {
				thread_call_func_t  func   = call->tc_func;
				thread_call_param_t param0 = call->tc_param0;
				thread_call_param_t param1 = call->tc_param1;

				call->tc_flags |= THREAD_CALL_RUNNING;

				thread_call_unlock(group);
				thread_call_invoke(func, param0, param1, call);
				thread_call_lock_spin(group);

				/* finish may detect that the call has been re-pended */
			} while (thread_call_finish(call, group, NULL));
			/* call may have been freed by the finish */
		} else {
			_pending_call_enqueue(call, group, now);
		}
	}

	_arm_delayed_call_timer(call, group, flavor);

	thread_call_unlock(group);
}

static void
thread_call_delayed_timer_rescan(thread_call_group_t group,
    thread_call_flavor_t flavor)
{
	thread_call_t call;
	uint64_t now;

	spl_t s = disable_ints_and_lock(group);

	assert(ml_timer_forced_evaluation() == TRUE);

	if (flavor == TCF_CONTINUOUS) {
		now = mach_continuous_time();
	} else {
		now = mach_absolute_time();
	}

	qe_foreach_element_safe(call, &group->delayed_queues[flavor], tc_qlink) {
		if (call->tc_soft_deadline <= now) {
			_pending_call_enqueue(call, group, now);
		} else {
			uint64_t skew = call->tc_pqlink.deadline - call->tc_soft_deadline;
			assert(call->tc_pqlink.deadline >= call->tc_soft_deadline);
			/*
			 * On a latency quality-of-service level change,
			 * re-sort potentially rate-limited callout. The platform
			 * layer determines which timers require this.
			 *
			 * This trick works by updating the deadline value to
			 * equal soft-deadline, effectively crushing away
			 * timer coalescing slop values for any armed
			 * timer in the queue.
			 *
			 * TODO: keep a hint on the timer to tell whether its inputs changed, so we
			 * only have to crush coalescing for timers that need it.
			 *
			 * TODO: Keep a separate queue of timers above the re-sort
			 * threshold, so we only have to look at those.
			 */
			if (timer_resort_threshold(skew)) {
				_call_dequeue(call, group);
				_delayed_call_enqueue(call, group, call->tc_soft_deadline, flavor);
			}
		}
	}

	_arm_delayed_call_timer(NULL, group, flavor);

	enable_ints_and_unlock(group, s);
}

void
thread_call_delayed_timer_rescan_all(void)
{
	for (int i = 0; i < THREAD_CALL_INDEX_MAX; i++) {
		for (thread_call_flavor_t flavor = 0; flavor < TCF_COUNT; flavor++) {
			thread_call_delayed_timer_rescan(&thread_call_groups[i], flavor);
		}
	}
}

/*
 * Timer callback to tell a thread to terminate if
 * we have an excess of threads and at least one has been
 * idle for a long time.
 */
static void
thread_call_dealloc_timer(
	timer_call_param_t              p0,
	__unused timer_call_param_t     p1)
{
	thread_call_group_t group = (thread_call_group_t)p0;
	uint64_t now;
	kern_return_t res;
	bool terminated = false;

	thread_call_lock_spin(group);

	assert(group->tcg_flags & TCG_DEALLOC_ACTIVE);

	now = mach_absolute_time();

	if (group->idle_count > 0) {
		if (now > group->idle_timestamp + thread_call_dealloc_interval_abs) {
			terminated = true;
			group->idle_count--;
			res = waitq_wakeup64_one(&group->idle_waitq, NO_EVENT64,
			    THREAD_INTERRUPTED, WAITQ_ALL_PRIORITIES);
			if (res != KERN_SUCCESS) {
				panic("Unable to wake up idle thread for termination?");
			}
		}
	}

	group->tcg_flags &= ~TCG_DEALLOC_ACTIVE;

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
	}

	thread_call_unlock(group);
}

/*
 * Wait for the invocation of the thread call to complete
 * We know there's only one in flight because of the 'once' flag.
 *
 * If a subsequent invocation comes in before we wake up, that's OK
 *
 * TODO: Here is where we will add priority inheritance to the thread executing
 * the thread call in case it's lower priority than the current thread
 *      <rdar://problem/30321792> Priority inheritance for thread_call_wait_once
 *
 * Takes the thread call lock locked, returns unlocked
 *      This lets us avoid a spurious take/drop after waking up from thread_block
 */
static bool
thread_call_wait_once_locked(thread_call_t call, spl_t s)
{
	assert(call->tc_flags & THREAD_CALL_ALLOC);
	assert(call->tc_flags & THREAD_CALL_ONCE);

	thread_call_group_t group = thread_call_get_group(call);

	if ((call->tc_flags & THREAD_CALL_RUNNING) == 0) {
		enable_ints_and_unlock(group, s);
		return false;
	}

	/* call is running, so we have to wait for it */
	call->tc_flags |= THREAD_CALL_WAIT;

	wait_result_t res = assert_wait(call, THREAD_UNINT);
	if (res != THREAD_WAITING) {
		panic("Unable to assert wait: %d", res);
	}

	enable_ints_and_unlock(group, s);

	res = thread_block(THREAD_CONTINUE_NULL);
	if (res != THREAD_AWAKENED) {
		panic("Awoken with %d?", res);
	}

	/* returns unlocked */
	return true;
}

/*
 * Wait for an in-flight invocation to complete
 * Does NOT try to cancel, so the client doesn't need to hold their
 * lock while calling this function.
 *
 * Returns whether or not it had to wait.
 *
 * Only works for THREAD_CALL_ONCE calls.
 */
boolean_t
thread_call_wait_once(thread_call_t call)
{
	if ((call->tc_flags & THREAD_CALL_ALLOC) == 0) {
		panic("thread_call_wait_once: can't wait on thread call whose storage I don't own");
	}

	if ((call->tc_flags & THREAD_CALL_ONCE) == 0) {
		panic("thread_call_wait_once: can't wait_once on a non-once call");
	}

	if (!ml_get_interrupts_enabled()) {
		panic("unsafe thread_call_wait_once");
	}

	thread_t self = current_thread();

	if ((thread_get_tag_internal(self) & THREAD_TAG_CALLOUT) &&
	    self->thc_state && self->thc_state->thc_call == call) {
		panic("thread_call_wait_once: deadlock waiting on self from inside call: %p to function %p",
		    call, call->tc_func);
	}

	thread_call_group_t group = thread_call_get_group(call);

	spl_t s = disable_ints_and_lock(group);

	bool waited = thread_call_wait_once_locked(call, s);
	/* thread call lock unlocked */

	return waited;
}


/*
 * Wait for all requested invocations of a thread call prior to now
 * to finish.  Can only be invoked on thread calls whose storage we manage.
 * Just waits for the finish count to catch up to the submit count we find
 * at the beginning of our wait.
 *
 * Called with thread_call_lock held.  Returns with lock released.
 */
static void
thread_call_wait_locked(thread_call_t call, spl_t s)
{
	thread_call_group_t group = thread_call_get_group(call);

	assert(call->tc_flags & THREAD_CALL_ALLOC);

	uint64_t submit_count = call->tc_submit_count;

	while (call->tc_finish_count < submit_count) {
		call->tc_flags |= THREAD_CALL_WAIT;

		wait_result_t res = assert_wait(call, THREAD_UNINT);
		if (res != THREAD_WAITING) {
			panic("Unable to assert wait: %d", res);
		}

		enable_ints_and_unlock(group, s);

		res = thread_block(THREAD_CONTINUE_NULL);
		if (res != THREAD_AWAKENED) {
			panic("Awoken with %d?", res);
		}

		s = disable_ints_and_lock(group);
	}

	enable_ints_and_unlock(group, s);
}

/*
 * Determine whether a thread call is either on a queue or
 * currently being executed.
 */
boolean_t
thread_call_isactive(thread_call_t call)
{
	thread_call_group_t group = thread_call_get_group(call);

	spl_t s = disable_ints_and_lock(group);
	boolean_t active = (call->tc_submit_count > call->tc_finish_count);
	enable_ints_and_unlock(group, s);

	return active;
}

/*
 * adjust_cont_time_thread_calls
 * on wake, reenqueue delayed call timer for continuous time thread call groups
 */
void
adjust_cont_time_thread_calls(void)
{
	for (int i = 0; i < THREAD_CALL_INDEX_MAX; i++) {
		thread_call_group_t group = &thread_call_groups[i];
		spl_t s = disable_ints_and_lock(group);

		/* only the continuous timers need to be re-armed */

		_arm_delayed_call_timer(NULL, group, TCF_CONTINUOUS);
		enable_ints_and_unlock(group, s);
	}
}

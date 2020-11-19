/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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


#include <sys/work_interval.h>

#include <kern/work_interval.h>

#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/machine.h>
#include <kern/thread_group.h>
#include <kern/ipc_kobject.h>
#include <kern/task.h>
#include <kern/coalition.h>
#include <kern/policy_internal.h>
#include <kern/mpsc_queue.h>

#include <mach/kern_return.h>
#include <mach/notify.h>
#include <os/refcnt.h>

#include <stdatomic.h>

/*
 * With the introduction of auto-join work intervals, it is possible
 * to change the work interval (and related thread group) of a thread in a
 * variety of contexts (thread termination, context switch, thread mode
 * change etc.). In order to clearly specify the policy expectation and
 * the locking behavior, all calls to thread_set_work_interval() pass
 * in a set of flags.
 */

__options_decl(thread_work_interval_options_t, uint32_t, {
	/* Change the work interval using the explicit join rules */
	THREAD_WI_EXPLICIT_JOIN_POLICY = 0x1,
	/* Change the work interval using the auto-join rules */
	THREAD_WI_AUTO_JOIN_POLICY     = 0x2,
	/* Caller already holds the thread lock */
	THREAD_WI_THREAD_LOCK_HELD     = 0x4,
	/* Caller does not hold the thread lock */
	THREAD_WI_THREAD_LOCK_NEEDED   = 0x8,
	/* Change the work interval from the context switch path (thread may not be running or on a runq) */
	THREAD_WI_THREAD_CTX_SWITCH    = 0x10,
});

static kern_return_t thread_set_work_interval(thread_t, struct work_interval *, thread_work_interval_options_t);

#if CONFIG_SCHED_AUTO_JOIN
/* MPSC queue used to defer deallocate work intervals */
static struct mpsc_daemon_queue work_interval_deallocate_queue;

static void work_interval_deferred_release(struct work_interval *);

/*
 * Work Interval Auto-Join Status
 *
 * work_interval_auto_join_status_t represents the state of auto-join for a given work interval.
 * It packs the following information:
 * - A bit representing if a "finish" is deferred on the work interval
 * - Count of number of threads auto-joined to the work interval
 */
#define WORK_INTERVAL_STATUS_DEFERRED_FINISH_MASK    ((uint32_t)(1 << 31))
#define WORK_INTERVAL_STATUS_AUTO_JOIN_COUNT_MASK    ((uint32_t)(WORK_INTERVAL_STATUS_DEFERRED_FINISH_MASK - 1))
#define WORK_INTERVAL_STATUS_AUTO_JOIN_COUNT_MAX     WORK_INTERVAL_STATUS_AUTO_JOIN_COUNT_MASK
typedef uint32_t work_interval_auto_join_status_t;

static inline bool __unused
work_interval_status_deferred_finish(work_interval_auto_join_status_t status)
{
	return (status & WORK_INTERVAL_STATUS_DEFERRED_FINISH_MASK) ? true : false;
}

static inline uint32_t __unused
work_interval_status_auto_join_count(work_interval_auto_join_status_t status)
{
	return (uint32_t)(status & WORK_INTERVAL_STATUS_AUTO_JOIN_COUNT_MASK);
}

/*
 * struct work_interval_deferred_finish_state
 *
 * Contains the parameters of the finish operation which is being deferred.
 */
struct work_interval_deferred_finish_state {
	uint64_t instance_id;
	uint64_t start;
	uint64_t deadline;
	uint64_t complexity;
};

struct work_interval_auto_join_info {
	struct work_interval_deferred_finish_state deferred_finish_state;
	work_interval_auto_join_status_t _Atomic status;
};
#endif /* CONFIG_SCHED_AUTO_JOIN */

/*
 * Work Interval structs
 *
 * This struct represents a thread group and/or work interval context
 * in a mechanism that is represented with a kobject.
 *
 * Every thread that has joined a WI has a +1 ref, and the port
 * has a +1 ref as well.
 *
 * TODO: groups need to have a 'is for WI' flag
 *      and they need a flag to create that says 'for WI'
 *      This would allow CLPC to avoid allocating WI support
 *      data unless it is needed
 *
 * TODO: Enforce not having more than one non-group joinable work
 *      interval per thread group.
 *      CLPC only wants to see one WI-notify callout per group.
 */

struct work_interval {
	uint64_t wi_id;
	struct os_refcnt wi_ref_count;
	uint32_t wi_create_flags;

	/* for debugging purposes only, does not hold a ref on port */
	ipc_port_t wi_port;

	/*
	 * holds uniqueid and version of creating process,
	 * used to permission-gate notify
	 * TODO: you'd think there would be a better way to do this
	 */
	uint64_t wi_creator_uniqueid;
	uint32_t wi_creator_pid;
	int wi_creator_pidversion;

#if CONFIG_THREAD_GROUPS
	struct thread_group *wi_group;  /* holds +1 ref on group */
#endif /* CONFIG_THREAD_GROUPS */

#if CONFIG_SCHED_AUTO_JOIN
	/* Information related to auto-join and deferred finish for work interval */
	struct work_interval_auto_join_info wi_auto_join_info;

	/*
	 * Since the deallocation of auto-join work intervals
	 * can happen in the scheduler when the last thread in
	 * the WI blocks and the thread lock is held, the deallocation
	 * might have to be done on a separate thread.
	 */
	struct mpsc_queue_chain   wi_deallocate_link;
#endif /* CONFIG_SCHED_AUTO_JOIN */
};

#if CONFIG_SCHED_AUTO_JOIN

/*
 * work_interval_perform_deferred_finish()
 *
 * Perform a deferred finish for a work interval. The routine accepts the deferred_finish_state as an
 * argument rather than looking at the work_interval since the deferred finish can race with another
 * start-finish cycle. To address that, the caller ensures that it gets a consistent snapshot of the
 * deferred state before calling this routine. This allows the racing start-finish cycle to overwrite
 * the deferred state without issues.
 */
static inline void
work_interval_perform_deferred_finish(__unused struct work_interval_deferred_finish_state *deferred_finish_state,
    __unused struct work_interval *work_interval, __unused thread_t thread)
{

	KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_WI_DEFERRED_FINISH),
	    thread_tid(thread), thread_group_get_id(work_interval->wi_group));
}

/*
 * work_interval_auto_join_increment()
 *
 * Routine to increment auto-join counter when a new thread is auto-joined to
 * the work interval.
 */
static void
work_interval_auto_join_increment(struct work_interval *work_interval)
{
	struct work_interval_auto_join_info *join_info = &work_interval->wi_auto_join_info;
	__assert_only work_interval_auto_join_status_t old_status = os_atomic_add_orig(&join_info->status, 1, relaxed);
	assert(work_interval_status_auto_join_count(old_status) < WORK_INTERVAL_STATUS_AUTO_JOIN_COUNT_MAX);
}

/*
 * work_interval_auto_join_decrement()
 *
 * Routine to decrement the auto-join counter when a thread unjoins the work interval (due to
 * blocking or termination). If this was the last auto-joined thread in the work interval and
 * there was a deferred finish, performs the finish operation for the work interval.
 */
static void
work_interval_auto_join_decrement(struct work_interval *work_interval, thread_t thread)
{
	struct work_interval_auto_join_info *join_info = &work_interval->wi_auto_join_info;
	work_interval_auto_join_status_t old_status, new_status;
	struct work_interval_deferred_finish_state deferred_finish_state;
	bool perform_finish;

	/* Update the auto-join count for the work interval atomically */
	os_atomic_rmw_loop(&join_info->status, old_status, new_status, acquire, {
		perform_finish = false;
		new_status = old_status;
		assert(work_interval_status_auto_join_count(old_status) > 0);
		new_status -= 1;
		if (new_status == WORK_INTERVAL_STATUS_DEFERRED_FINISH_MASK) {
		        /* No auto-joined threads remaining and finish is deferred */
		        new_status = 0;
		        perform_finish = true;
		        /*
		         * Its important to copy the deferred finish state here so that this works
		         * when racing with another start-finish cycle.
		         */
		        deferred_finish_state = join_info->deferred_finish_state;
		}
	});

	if (perform_finish == true) {
		/*
		 * Since work_interval_perform_deferred_finish() calls down to
		 * the machine layer callout for finish which gets the thread
		 * group from the thread passed in here, it is important to
		 * make sure that the thread still has the work interval thread
		 * group here.
		 */
		assert(thread->thread_group == work_interval->wi_group);
		work_interval_perform_deferred_finish(&deferred_finish_state, work_interval, thread);
	}
}

/*
 * work_interval_auto_join_enabled()
 *
 * Helper routine to check if work interval has auto-join enabled.
 */
static inline bool
work_interval_auto_join_enabled(struct work_interval *work_interval)
{
	return (work_interval->wi_create_flags & WORK_INTERVAL_FLAG_ENABLE_AUTO_JOIN) != 0;
}

/*
 * work_interval_deferred_finish_enabled()
 *
 * Helper routine to check if work interval has deferred finish enabled.
 */
static inline bool __unused
work_interval_deferred_finish_enabled(struct work_interval *work_interval)
{
	return (work_interval->wi_create_flags & WORK_INTERVAL_FLAG_ENABLE_DEFERRED_FINISH) != 0;
}

#endif /* CONFIG_SCHED_AUTO_JOIN */

static inline void
work_interval_retain(struct work_interval *work_interval)
{
	/*
	 * Even though wi_retain is called under a port lock, we have
	 * to use os_ref_retain instead of os_ref_retain_locked
	 * because wi_release is not synchronized. wi_release calls
	 * os_ref_release which is unsafe to pair with os_ref_retain_locked.
	 */
	os_ref_retain(&work_interval->wi_ref_count);
}

static inline void
work_interval_deallocate(struct work_interval *work_interval)
{
	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_WORKGROUP, WORKGROUP_INTERVAL_DESTROY),
	    work_interval->wi_id);
#if CONFIG_THREAD_GROUPS
	thread_group_release(work_interval->wi_group);
	work_interval->wi_group = NULL;
#endif /* CONFIG_THREAD_GROUPS */
	kfree(work_interval, sizeof(struct work_interval));
}

/*
 * work_interval_release()
 *
 * Routine to release a ref count on the work interval. If the refcount goes down
 * to zero, the work interval needs to be de-allocated.
 *
 * For non auto-join work intervals, they are de-allocated in this context.
 *
 * For auto-join work intervals, the de-allocation cannot be done from this context
 * since that might need the kernel memory allocator lock. In that case, the
 * deallocation is done via a thread-call based mpsc queue.
 */
static void
work_interval_release(struct work_interval *work_interval, __unused thread_work_interval_options_t options)
{
	if (os_ref_release(&work_interval->wi_ref_count) == 0) {
#if CONFIG_SCHED_AUTO_JOIN
		if (options & THREAD_WI_THREAD_LOCK_HELD) {
			work_interval_deferred_release(work_interval);
		} else {
			work_interval_deallocate(work_interval);
		}
#else /* CONFIG_SCHED_AUTO_JOIN */
		work_interval_deallocate(work_interval);
#endif /* CONFIG_SCHED_AUTO_JOIN */
	}
}

#if CONFIG_SCHED_AUTO_JOIN

/*
 * work_interval_deferred_release()
 *
 * Routine to enqueue the work interval on the deallocation mpsc queue.
 */
static void
work_interval_deferred_release(struct work_interval *work_interval)
{
	mpsc_daemon_enqueue(&work_interval_deallocate_queue,
	    &work_interval->wi_deallocate_link, MPSC_QUEUE_NONE);
}

/*
 * work_interval_should_propagate()
 *
 * Main policy routine to decide if a thread should be auto-joined to
 * another thread's work interval. The conditions are arranged such that
 * the most common bailout condition are checked the earliest. This routine
 * is called from the scheduler context; so it needs to be efficient and
 * be careful when taking locks or performing wakeups.
 */
inline bool
work_interval_should_propagate(thread_t cthread, thread_t thread)
{
	/* Only allow propagation if the current thread has a work interval and the woken up thread does not */
	if ((cthread->th_work_interval == NULL) || (thread->th_work_interval != NULL)) {
		return false;
	}

	/* Only propagate work intervals which have auto-join enabled */
	if (work_interval_auto_join_enabled(cthread->th_work_interval) == false) {
		return false;
	}

	/* Work interval propagation is enabled for realtime threads only */
	if ((cthread->sched_mode != TH_MODE_REALTIME) || (thread->sched_mode != TH_MODE_REALTIME)) {
		return false;
	}


	/* Work interval propagation only works for threads with the same home thread group */
	struct thread_group *thread_home_tg = thread_group_get_home_group(thread);
	if (thread_group_get_home_group(cthread) != thread_home_tg) {
		return false;
	}

	/* If woken up thread has adopted vouchers and other thread groups, it does not get propagation */
	if (thread->thread_group != thread_home_tg) {
		return false;
	}

	/* If either thread is inactive (in the termination path), do not propagate auto-join */
	if ((!cthread->active) || (!thread->active)) {
		return false;
	}

	return true;
}

/*
 * work_interval_auto_join_propagate()
 *
 * Routine to auto-join a thread into another thread's work interval
 *
 * Should only be invoked if work_interval_should_propagate() returns
 * true. Also expects "from" thread to be current thread and "to" thread
 * to be locked.
 */
void
work_interval_auto_join_propagate(thread_t from, thread_t to)
{
	assert(from == current_thread());
	work_interval_retain(from->th_work_interval);
	work_interval_auto_join_increment(from->th_work_interval);
	__assert_only kern_return_t kr = thread_set_work_interval(to, from->th_work_interval,
	    THREAD_WI_AUTO_JOIN_POLICY | THREAD_WI_THREAD_LOCK_HELD | THREAD_WI_THREAD_CTX_SWITCH);
	assert(kr == KERN_SUCCESS);
}

/*
 * work_interval_auto_join_unwind()
 *
 * Routine to un-join an auto-joined work interval for a thread that is blocking.
 *
 * Expects thread to be locked.
 */
void
work_interval_auto_join_unwind(thread_t thread)
{
	__assert_only kern_return_t kr = thread_set_work_interval(thread, NULL,
	    THREAD_WI_AUTO_JOIN_POLICY | THREAD_WI_THREAD_LOCK_HELD | THREAD_WI_THREAD_CTX_SWITCH);
	assert(kr == KERN_SUCCESS);
}

/*
 * work_interval_auto_join_demote()
 *
 * Routine to un-join an auto-joined work interval when a thread is changing from
 * realtime to non-realtime scheduling mode. This could happen due to multiple
 * reasons such as RT failsafe, thread backgrounding or thread termination. Also,
 * the thread being demoted may not be the current thread.
 *
 * Expects thread to be locked.
 */
void
work_interval_auto_join_demote(thread_t thread)
{
	__assert_only kern_return_t kr = thread_set_work_interval(thread, NULL,
	    THREAD_WI_AUTO_JOIN_POLICY | THREAD_WI_THREAD_LOCK_HELD);
	assert(kr == KERN_SUCCESS);
}

static void
work_interval_deallocate_queue_invoke(mpsc_queue_chain_t e,
    __assert_only mpsc_daemon_queue_t dq)
{
	struct work_interval *work_interval = NULL;
	work_interval = mpsc_queue_element(e, struct work_interval, wi_deallocate_link);
	assert(dq == &work_interval_deallocate_queue);
	assert(os_ref_get_count(&work_interval->wi_ref_count) == 0);
	work_interval_deallocate(work_interval);
}

#endif /* CONFIG_SCHED_AUTO_JOIN */

void
work_interval_subsystem_init(void)
{
#if CONFIG_SCHED_AUTO_JOIN
	/*
	 * The work interval deallocation queue must be a thread call based queue
	 * because it is woken up from contexts where the thread lock is held. The
	 * only way to perform wakeups safely in those contexts is to wakeup a
	 * thread call which is guaranteed to be on a different waitq and would
	 * not hash onto the same global waitq which might be currently locked.
	 */
	mpsc_daemon_queue_init_with_thread_call(&work_interval_deallocate_queue,
	    work_interval_deallocate_queue_invoke, THREAD_CALL_PRIORITY_KERNEL);
#endif /* CONFIG_SCHED_AUTO_JOIN */
}

/*
 * work_interval_port_convert
 *
 * Called with port locked, returns reference to work interval
 * if indeed the port is a work interval kobject port
 */
static struct work_interval *
work_interval_port_convert_locked(ipc_port_t port)
{
	struct work_interval *work_interval = NULL;

	if (!IP_VALID(port)) {
		return NULL;
	}

	if (!ip_active(port)) {
		return NULL;
	}

	if (IKOT_WORK_INTERVAL != ip_kotype(port)) {
		return NULL;
	}

	work_interval = (struct work_interval *) ip_get_kobject(port);

	work_interval_retain(work_interval);

	return work_interval;
}

/*
 * port_name_to_work_interval
 *
 * Description: Obtain a reference to the work_interval associated with a given port.
 *
 * Parameters:  name    A Mach port name to translate.
 *
 * Returns:     NULL    The given Mach port did not reference a work_interval.
 *              !NULL   The work_interval that is associated with the Mach port.
 */
static kern_return_t
port_name_to_work_interval(mach_port_name_t     name,
    struct work_interval **work_interval)
{
	if (!MACH_PORT_VALID(name)) {
		return KERN_INVALID_NAME;
	}

	ipc_port_t port = IPC_PORT_NULL;
	kern_return_t kr = KERN_SUCCESS;

	kr = ipc_port_translate_send(current_space(), name, &port);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* port is locked */

	assert(IP_VALID(port));

	struct work_interval *converted_work_interval;

	converted_work_interval = work_interval_port_convert_locked(port);

	/* the port is valid, but doesn't denote a work_interval */
	if (converted_work_interval == NULL) {
		kr = KERN_INVALID_CAPABILITY;
	}

	ip_unlock(port);

	if (kr == KERN_SUCCESS) {
		*work_interval = converted_work_interval;
	}

	return kr;
}


/*
 * work_interval_port_notify
 *
 * Description: Handle a no-senders notification for a work interval port.
 *              Destroys the port and releases its reference on the work interval.
 *
 * Parameters:  msg     A Mach no-senders notification message.
 *
 * Note: This assumes that there is only one create-right-from-work-interval point,
 *       if the ability to extract another send right after creation is added,
 *       this will have to change to handle make-send counts correctly.
 */
void
work_interval_port_notify(mach_msg_header_t *msg)
{
	mach_no_senders_notification_t *notification = (void *)msg;
	ipc_port_t port = notification->not_header.msgh_remote_port;
	struct work_interval *work_interval = NULL;

	if (!IP_VALID(port)) {
		panic("work_interval_port_notify(): invalid port");
	}

	ip_lock(port);

	if (!ip_active(port)) {
		panic("work_interval_port_notify(): inactive port %p", port);
	}

	if (ip_kotype(port) != IKOT_WORK_INTERVAL) {
		panic("work_interval_port_notify(): not the right kobject: %p, %d\n",
		    port, ip_kotype(port));
	}

	if (port->ip_mscount != notification->not_count) {
		panic("work_interval_port_notify(): unexpected make-send count: %p, %d, %d",
		    port, port->ip_mscount, notification->not_count);
	}

	if (port->ip_srights != 0) {
		panic("work_interval_port_notify(): unexpected send right count: %p, %d",
		    port, port->ip_srights);
	}

	work_interval = (struct work_interval *) ip_get_kobject(port);

	if (work_interval == NULL) {
		panic("work_interval_port_notify(): missing kobject: %p", port);
	}

	ipc_kobject_set_atomically(port, IKO_NULL, IKOT_NONE);

	work_interval->wi_port = MACH_PORT_NULL;

	ip_unlock(port);

	ipc_port_dealloc_kernel(port);
	work_interval_release(work_interval, THREAD_WI_THREAD_LOCK_NEEDED);
}

/*
 * work_interval_port_type()
 *
 * Converts a port name into the work interval object and returns its type.
 *
 * For invalid ports, it returns WORK_INTERVAL_TYPE_LAST (which is not a
 * valid type for work intervals).
 */
static uint32_t
work_interval_port_type(mach_port_name_t port_name)
{
	struct work_interval *work_interval = NULL;
	kern_return_t kr;
	uint32_t work_interval_type;

	if (port_name == MACH_PORT_NULL) {
		return WORK_INTERVAL_TYPE_LAST;
	}

	kr = port_name_to_work_interval(port_name, &work_interval);
	if (kr != KERN_SUCCESS) {
		return WORK_INTERVAL_TYPE_LAST;
	}
	/* work_interval has a +1 ref */

	assert(work_interval != NULL);
	work_interval_type = work_interval->wi_create_flags & WORK_INTERVAL_TYPE_MASK;
	work_interval_release(work_interval, THREAD_WI_THREAD_LOCK_NEEDED);
	return work_interval_type;
}


/*
 * thread_set_work_interval()
 *
 * Change thread's bound work interval to the passed-in work interval
 * Consumes +1 ref on work_interval upon success.
 *
 * May also pass NULL to un-set work_interval on the thread
 * Will deallocate any old work interval on the thread
 * Return error if thread does not satisfy requirements to join work interval
 *
 * For non auto-join work intervals, deallocate any old work interval on the thread
 * For auto-join work intervals, the routine may wakeup the work interval deferred
 * deallocation queue since thread locks might be currently held.
 */
static kern_return_t
thread_set_work_interval(thread_t thread,
    struct work_interval *work_interval, thread_work_interval_options_t options)
{
	/* All explicit work interval operations should always be from the current thread */
	if (options & THREAD_WI_EXPLICIT_JOIN_POLICY) {
		assert(thread == current_thread());
	}

	/* All cases of needing the thread lock should be from explicit join scenarios */
	if (options & THREAD_WI_THREAD_LOCK_NEEDED) {
		assert((options & THREAD_WI_EXPLICIT_JOIN_POLICY) != 0);
	}

	/* For all cases of auto join must come in with the thread lock held */
	if (options & THREAD_WI_AUTO_JOIN_POLICY) {
		assert((options & THREAD_WI_THREAD_LOCK_HELD) != 0);
	}

	if (work_interval) {
		uint32_t work_interval_type = work_interval->wi_create_flags & WORK_INTERVAL_TYPE_MASK;

		if ((work_interval_type == WORK_INTERVAL_TYPE_COREAUDIO) &&
		    (thread->sched_mode != TH_MODE_REALTIME) && (thread->saved_mode != TH_MODE_REALTIME)) {
			return KERN_INVALID_ARGUMENT;
		}
	}

	struct work_interval *old_th_wi = thread->th_work_interval;
#if CONFIG_SCHED_AUTO_JOIN
	bool old_wi_auto_joined = ((thread->sched_flags & TH_SFLAG_THREAD_GROUP_AUTO_JOIN) != 0);

	spl_t s;
	/* Take the thread lock if needed */
	if (options & THREAD_WI_THREAD_LOCK_NEEDED) {
		s = splsched();
		thread_lock(thread);
	}

	/*
	 * Work interval auto-join leak to non-RT threads.
	 *
	 * If thread might be running on a remote core and it's not in the context switch path (where
	 * thread is neither running, blocked or in the runq), its not possible to update the
	 * work interval & thread group remotely since its not possible to update CLPC for a remote
	 * core. This situation might happen when a thread is transitioning from realtime to
	 * non-realtime due to backgrounding etc., which would mean that non-RT threads would now
	 * be part of the work interval.
	 *
	 * Since there is no immediate mitigation to this issue, the policy is to set a new
	 * flag on the thread which indicates that such a "leak" has happened. This flag will
	 * be cleared when the remote thread eventually blocks and unjoins from the work interval.
	 */
	bool thread_on_remote_core = ((thread != current_thread()) && (thread->state & TH_RUN) && (thread->runq == PROCESSOR_NULL));

	if (thread_on_remote_core && ((options & THREAD_WI_THREAD_CTX_SWITCH) == 0)) {
		assert((options & THREAD_WI_THREAD_LOCK_NEEDED) == 0);
		os_atomic_or(&thread->th_work_interval_flags, TH_WORK_INTERVAL_FLAGS_AUTO_JOIN_LEAK, relaxed);
		return KERN_SUCCESS;
	}

	old_wi_auto_joined = ((thread->sched_flags & TH_SFLAG_THREAD_GROUP_AUTO_JOIN) != 0);

	if ((options & THREAD_WI_AUTO_JOIN_POLICY) || old_wi_auto_joined) {
		__kdebug_only uint64_t old_tg_id = (old_th_wi) ? thread_group_get_id(old_th_wi->wi_group) : ~0;
		__kdebug_only uint64_t new_tg_id = (work_interval) ? thread_group_get_id(work_interval->wi_group) : ~0;
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_WI_AUTO_JOIN),
		    thread_tid(thread), old_tg_id, new_tg_id, options);
	}

	if (old_wi_auto_joined) {
		/*
		 * If thread was auto-joined to a work interval and is not realtime, make sure it
		 * happened due to the "leak" described above.
		 */
		if (thread->sched_mode != TH_MODE_REALTIME) {
			assert((thread->th_work_interval_flags & TH_WORK_INTERVAL_FLAGS_AUTO_JOIN_LEAK) != 0);
		}

		os_atomic_andnot(&thread->th_work_interval_flags, TH_WORK_INTERVAL_FLAGS_AUTO_JOIN_LEAK, relaxed);
		work_interval_auto_join_decrement(old_th_wi, thread);
		thread->sched_flags &= ~TH_SFLAG_THREAD_GROUP_AUTO_JOIN;
	}

#endif /* CONFIG_SCHED_AUTO_JOIN */

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_WORKGROUP, WORKGROUP_INTERVAL_CHANGE),
	    thread_tid(thread), (old_th_wi ? old_th_wi->wi_id : 0), (work_interval ? work_interval->wi_id : 0), !!(options & THREAD_WI_AUTO_JOIN_POLICY));

	/* transfer +1 ref to thread */
	thread->th_work_interval = work_interval;

#if CONFIG_SCHED_AUTO_JOIN

	if ((options & THREAD_WI_AUTO_JOIN_POLICY) && work_interval) {
		assert(work_interval_auto_join_enabled(work_interval) == true);
		thread->sched_flags |= TH_SFLAG_THREAD_GROUP_AUTO_JOIN;
	}

	if (options & THREAD_WI_THREAD_LOCK_NEEDED) {
		thread_unlock(thread);
		splx(s);
	}
#endif /* CONFIG_SCHED_AUTO_JOIN */

#if CONFIG_THREAD_GROUPS
	struct thread_group *new_tg = (work_interval) ? (work_interval->wi_group) : NULL;
	thread_set_work_interval_thread_group(thread, new_tg, (options & THREAD_WI_AUTO_JOIN_POLICY));
#endif /* CONFIG_THREAD_GROUPS */

	if (old_th_wi != NULL) {
		work_interval_release(old_th_wi, options);
	}

	return KERN_SUCCESS;
}

static kern_return_t
thread_set_work_interval_explicit_join(thread_t thread, struct work_interval *work_interval)
{
	assert(thread == current_thread());
	return thread_set_work_interval(thread, work_interval, THREAD_WI_EXPLICIT_JOIN_POLICY | THREAD_WI_THREAD_LOCK_NEEDED);
}

kern_return_t
work_interval_thread_terminate(thread_t thread)
{
	assert(thread == current_thread());
	if (thread->th_work_interval != NULL) {
		return thread_set_work_interval(thread, NULL, THREAD_WI_EXPLICIT_JOIN_POLICY | THREAD_WI_THREAD_LOCK_NEEDED);
	}
	return KERN_SUCCESS;
}

kern_return_t
kern_work_interval_notify(thread_t thread, struct kern_work_interval_args* kwi_args)
{
	assert(thread == current_thread());
	assert(kwi_args->work_interval_id != 0);

	struct work_interval *work_interval = thread->th_work_interval;

	if (work_interval == NULL ||
	    work_interval->wi_id != kwi_args->work_interval_id) {
		/* This thread must have adopted the work interval to be able to notify */
		return KERN_INVALID_ARGUMENT;
	}

	task_t notifying_task = current_task();

	if (work_interval->wi_creator_uniqueid != get_task_uniqueid(notifying_task) ||
	    work_interval->wi_creator_pidversion != get_task_version(notifying_task)) {
		/* Only the creating task can do a notify */
		return KERN_INVALID_ARGUMENT;
	}

	spl_t s = splsched();

#if CONFIG_THREAD_GROUPS
	assert(work_interval->wi_group == thread->thread_group);
#endif /* CONFIG_THREAD_GROUPS */

	uint64_t urgency_param1, urgency_param2;
	kwi_args->urgency = (uint16_t)thread_get_urgency(thread, &urgency_param1, &urgency_param2);

	splx(s);

	/* called without interrupts disabled */
	machine_work_interval_notify(thread, kwi_args);

	return KERN_SUCCESS;
}

/* Start at 1, 0 is not a valid work interval ID */
static _Atomic uint64_t unique_work_interval_id = 1;

kern_return_t
kern_work_interval_create(thread_t thread,
    struct kern_work_interval_create_args *create_params)
{
	assert(thread == current_thread());

	uint32_t create_flags = create_params->wica_create_flags;

	if (((create_flags & WORK_INTERVAL_FLAG_JOINABLE) == 0) &&
	    thread->th_work_interval != NULL) {
		/*
		 * If the thread is doing a legacy combined create and join,
		 * it shouldn't already be part of a work interval.
		 *
		 * (Creating a joinable WI is allowed anytime.)
		 */
		return KERN_FAILURE;
	}

	/*
	 * Check the validity of the create flags before allocating the work
	 * interval.
	 */
	task_t creating_task = current_task();
	if ((create_flags & WORK_INTERVAL_TYPE_MASK) == WORK_INTERVAL_TYPE_CA_CLIENT) {
		/*
		 * CA_CLIENT work intervals do not create new thread groups.
		 * There can only be one CA_CLIENT work interval (created by UIKit or AppKit)
		 * per each application task
		 */
		if (create_flags & WORK_INTERVAL_FLAG_GROUP) {
			return KERN_FAILURE;
		}
		if (!task_is_app(creating_task)) {
#if XNU_TARGET_OS_OSX
			/*
			 * Soft-fail the case of a non-app pretending to be an
			 * app, by allowing it to press the buttons, but they're
			 * not actually connected to anything.
			 */
			create_flags |= WORK_INTERVAL_FLAG_IGNORED;
#else
			/*
			 * On iOS, it's a hard failure to get your apptype
			 * wrong and then try to render something.
			 */
			return KERN_NOT_SUPPORTED;
#endif /* XNU_TARGET_OS_OSX */
		}
		if (task_set_ca_client_wi(creating_task, true) == false) {
			return KERN_FAILURE;
		}
	}

#if CONFIG_SCHED_AUTO_JOIN
	if (create_flags & WORK_INTERVAL_FLAG_ENABLE_AUTO_JOIN) {
		uint32_t type = (create_flags & WORK_INTERVAL_TYPE_MASK);
		if (type != WORK_INTERVAL_TYPE_COREAUDIO) {
			return KERN_NOT_SUPPORTED;
		}
		if ((create_flags & WORK_INTERVAL_FLAG_GROUP) == 0) {
			return KERN_NOT_SUPPORTED;
		}
	}

	if (create_flags & WORK_INTERVAL_FLAG_ENABLE_DEFERRED_FINISH) {
		if ((create_flags & WORK_INTERVAL_FLAG_ENABLE_AUTO_JOIN) == 0) {
			return KERN_NOT_SUPPORTED;
		}
	}
#endif /* CONFIG_SCHED_AUTO_JOIN */

	struct work_interval *work_interval = kalloc_flags(sizeof(*work_interval),
	    Z_WAITOK | Z_ZERO);
	assert(work_interval != NULL);

	uint64_t work_interval_id = os_atomic_inc(&unique_work_interval_id, relaxed);

	*work_interval = (struct work_interval) {
		.wi_id                  = work_interval_id,
		.wi_ref_count           = {},
		.wi_create_flags        = create_flags,
		.wi_creator_pid         = pid_from_task(creating_task),
		.wi_creator_uniqueid    = get_task_uniqueid(creating_task),
		.wi_creator_pidversion  = get_task_version(creating_task),
	};
	os_ref_init(&work_interval->wi_ref_count, NULL);

	__kdebug_only uint64_t tg_id = 0;
#if CONFIG_THREAD_GROUPS
	struct thread_group *tg;
	if (create_flags & WORK_INTERVAL_FLAG_GROUP) {
		/* create a new group for the interval to represent */
		char name[THREAD_GROUP_MAXNAME] = "";

		snprintf(name, sizeof(name), "WI[%d] #%lld",
		    work_interval->wi_creator_pid, work_interval_id);

		tg = thread_group_create_and_retain();

		thread_group_set_name(tg, name);

		work_interval->wi_group = tg;
	} else {
		/* the interval represents the thread's home group */
		tg = thread_group_get_home_group(thread);

		thread_group_retain(tg);

		work_interval->wi_group = tg;
	}

	/* Capture the tg_id for tracing purposes */
	tg_id = thread_group_get_id(work_interval->wi_group);

#endif /* CONFIG_THREAD_GROUPS */

	if (create_flags & WORK_INTERVAL_FLAG_JOINABLE) {
		mach_port_name_t name = MACH_PORT_NULL;

		/* work_interval has a +1 ref, moves to the port */
		work_interval->wi_port = ipc_kobject_alloc_port(
			(ipc_kobject_t)work_interval, IKOT_WORK_INTERVAL,
			IPC_KOBJECT_ALLOC_MAKE_SEND | IPC_KOBJECT_ALLOC_NSREQUEST);

		name = ipc_port_copyout_send(work_interval->wi_port, current_space());

		if (!MACH_PORT_VALID(name)) {
			/*
			 * copyout failed (port is already deallocated)
			 * Because of the port-destroyed magic,
			 * the work interval is already deallocated too.
			 */
			return KERN_RESOURCE_SHORTAGE;
		}

		create_params->wica_port = name;
	} else {
		/* work_interval has a +1 ref, moves to the thread */
		kern_return_t kr = thread_set_work_interval_explicit_join(thread, work_interval);
		if (kr != KERN_SUCCESS) {
			/* No other thread can join this work interval since it isn't
			 * JOINABLE so release the reference on work interval */
			work_interval_release(work_interval, THREAD_WI_THREAD_LOCK_NEEDED);
			return kr;
		}
		create_params->wica_port = MACH_PORT_NULL;
	}

	create_params->wica_id = work_interval_id;

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_WORKGROUP, WORKGROUP_INTERVAL_CREATE),
	    work_interval_id, create_flags, pid_from_task(creating_task), tg_id);
	return KERN_SUCCESS;
}

kern_return_t
kern_work_interval_get_flags_from_port(mach_port_name_t port_name, uint32_t *flags)
{
	assert(flags != NULL);

	kern_return_t kr;
	struct work_interval *work_interval;

	kr = port_name_to_work_interval(port_name, &work_interval);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	assert(work_interval != NULL);
	*flags = work_interval->wi_create_flags;

	work_interval_release(work_interval, THREAD_WI_THREAD_LOCK_NEEDED);

	return KERN_SUCCESS;
}


kern_return_t
kern_work_interval_destroy(thread_t thread, uint64_t work_interval_id)
{
	if (work_interval_id == 0) {
		return KERN_INVALID_ARGUMENT;
	}

	if (thread->th_work_interval == NULL ||
	    thread->th_work_interval->wi_id != work_interval_id) {
		/* work ID isn't valid or doesn't match joined work interval ID */
		return KERN_INVALID_ARGUMENT;
	}

	return thread_set_work_interval_explicit_join(thread, NULL);
}

kern_return_t
kern_work_interval_join(thread_t            thread,
    mach_port_name_t    port_name)
{
	struct work_interval *work_interval = NULL;
	kern_return_t kr;

	if (port_name == MACH_PORT_NULL) {
		/* 'Un-join' the current work interval */
		return thread_set_work_interval_explicit_join(thread, NULL);
	}

	kr = port_name_to_work_interval(port_name, &work_interval);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* work_interval has a +1 ref */

	assert(work_interval != NULL);

	kr = thread_set_work_interval_explicit_join(thread, work_interval);
	/* ref was consumed by passing it to the thread in the successful case */
	if (kr != KERN_SUCCESS) {
		work_interval_release(work_interval, THREAD_WI_THREAD_LOCK_NEEDED);
	}
	return kr;
}

/*
 * work_interval_port_type_render_server()
 *
 * Helper routine to determine if the port points to a
 * WORK_INTERVAL_TYPE_CA_RENDER_SERVER work interval.
 */
bool
work_interval_port_type_render_server(mach_port_name_t port_name)
{
	return work_interval_port_type(port_name) == WORK_INTERVAL_TYPE_CA_RENDER_SERVER;
}

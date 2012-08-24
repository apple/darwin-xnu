/*
 * Copyright (c) 1993-2008 Apple Inc. All rights reserved.
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
 * Timer interrupt callout module.
 */

#include <mach/mach_types.h>

#include <kern/clock.h>
#include <kern/processor.h>
#include <kern/etimer.h>
#include <kern/timer_call.h>
#include <kern/timer_queue.h>
#include <kern/call_entry.h>

#include <sys/kdebug.h>

#if CONFIG_DTRACE && (DEVELOPMENT || DEBUG )
#include <mach/sdt.h>
#endif


#if DEBUG
#define TIMER_ASSERT	1
#endif

//#define TIMER_ASSERT	1
//#define TIMER_DBG	1

#if TIMER_DBG
#define DBG(x...) kprintf("DBG: " x);
#else
#define DBG(x...)
#endif

lck_grp_t               timer_call_lck_grp;
lck_attr_t              timer_call_lck_attr;
lck_grp_attr_t          timer_call_lck_grp_attr;


#define timer_call_lock_spin(queue)		\
	lck_mtx_lock_spin_always(&queue->lock_data)

#define timer_call_unlock(queue)		\
	lck_mtx_unlock_always(&queue->lock_data)


#define QUEUE(x)	((queue_t)(x))
#define MPQUEUE(x)	((mpqueue_head_t *)(x))
#define TIMER_CALL(x)	((timer_call_t)(x))


uint64_t past_deadline_timers;
uint64_t past_deadline_deltas;
uint64_t past_deadline_longest;
uint64_t past_deadline_shortest = ~0ULL;
enum {PAST_DEADLINE_TIMER_ADJUSTMENT_NS = 10 * 1000};

uint64_t past_deadline_timer_adjustment;

static boolean_t timer_call_enter_internal(timer_call_t call, timer_call_param_t param1, uint64_t deadline, uint32_t flags);
boolean_t 	mach_timer_coalescing_enabled = TRUE;

mpqueue_head_t	*timer_call_enqueue_deadline_unlocked(
			timer_call_t		call,
			mpqueue_head_t		*queue,
			uint64_t		deadline);

mpqueue_head_t	*timer_call_dequeue_unlocked(
			timer_call_t 		call);


void
timer_call_initialize(void)
{
	lck_attr_setdefault(&timer_call_lck_attr);
	lck_grp_attr_setdefault(&timer_call_lck_grp_attr);
	lck_grp_init(&timer_call_lck_grp, "timer_call", &timer_call_lck_grp_attr);
	nanotime_to_absolutetime(0, PAST_DEADLINE_TIMER_ADJUSTMENT_NS, &past_deadline_timer_adjustment);
}


void
timer_call_initialize_queue(mpqueue_head_t *queue)
{
	DBG("timer_call_initialize_queue(%p)\n", queue);
	mpqueue_init(queue, &timer_call_lck_grp, &timer_call_lck_attr);
}


void
timer_call_setup(
	timer_call_t			call,
	timer_call_func_t		func,
	timer_call_param_t		param0)
{
	DBG("timer_call_setup(%p,%p,%p)\n", call, func, param0);
	call_entry_setup(CE(call), func, param0);
	simple_lock_init(&(call)->lock, 0);
	call->async_dequeue = FALSE;
}

/*
 * Timer call entry locking model
 * ==============================
 *
 * Timer call entries are linked on per-cpu timer queues which are protected
 * by the queue lock and the call entry lock. The locking protocol is:
 *
 *  0) The canonical locking order is timer call entry followed by queue.
 *
 *  1) With only the entry lock held, entry.queue is valid:
 *    1a) NULL: the entry is not queued, or
 *    1b) non-NULL: this queue must be locked before the entry is modified.
 *        After locking the queue, the call.async_dequeue flag must be checked:
 *    1c) TRUE: the entry was removed from the queue by another thread
 *	        and we must NULL the entry.queue and reset this flag, or
 *    1d) FALSE: (ie. queued), the entry can be manipulated.
 *
 *  2) If a queue lock is obtained first, the queue is stable:
 *    2a) If a try-lock of a queued entry succeeds, the call can be operated on
 *	  and dequeued.
 *    2b) If a try-lock fails, it indicates that another thread is attempting
 *        to change the entry and move it to a different position in this queue
 *        or to different queue. The entry can be dequeued but it should not be
 *        operated upon since it is being changed. Furthermore, we don't null
 *	  the entry.queue pointer (protected by the entry lock we don't own).
 *	  Instead, we set the async_dequeue flag -- see (1c).
 */

/*
 * Inlines timer_call_entry_dequeue() and timer_call_entry_enqueue_deadline()
 * cast between pointer types (mpqueue_head_t *) and (queue_t) so that
 * we can use the call_entry_dequeue() and call_entry_enqueue_deadline()
 * methods to operate on timer_call structs as if they are call_entry structs.
 * These structures are identical except for their queue head pointer fields.
 *
 * In the debug case, we assert that the timer call locking protocol 
 * is being obeyed.
 */
#if TIMER_ASSERT
static __inline__ mpqueue_head_t *
timer_call_entry_dequeue(
	timer_call_t		entry)
{
        mpqueue_head_t	*old_queue = MPQUEUE(CE(entry)->queue);

	if (!hw_lock_held((hw_lock_t)&entry->lock))
		panic("_call_entry_dequeue() "
			"entry %p is not locked\n", entry);
	/*
	 * XXX The queue lock is actually a mutex in spin mode
	 *     but there's no way to test for it being held
	 *     so we pretend it's a spinlock!
	 */
	if (!hw_lock_held((hw_lock_t)&old_queue->lock_data))
		panic("_call_entry_dequeue() "
			"queue %p is not locked\n", old_queue);

	call_entry_dequeue(CE(entry));

	return (old_queue);
}

static __inline__ mpqueue_head_t *
timer_call_entry_enqueue_deadline(
	timer_call_t		entry,
	mpqueue_head_t		*queue,
	uint64_t		deadline)
{
	mpqueue_head_t	*old_queue = MPQUEUE(CE(entry)->queue);

	if (!hw_lock_held((hw_lock_t)&entry->lock))
		panic("_call_entry_enqueue_deadline() "
			"entry %p is not locked\n", entry);
	/* XXX More lock pretense:  */
	if (!hw_lock_held((hw_lock_t)&queue->lock_data))
		panic("_call_entry_enqueue_deadline() "
			"queue %p is not locked\n", queue);
	if (old_queue != NULL && old_queue != queue)
		panic("_call_entry_enqueue_deadline() "
			"old_queue %p != queue", old_queue);

	call_entry_enqueue_deadline(CE(entry), QUEUE(queue), deadline);

	return (old_queue);
}

#else

static __inline__ mpqueue_head_t *
timer_call_entry_dequeue(
	timer_call_t		entry)
{
	return MPQUEUE(call_entry_dequeue(CE(entry)));
}

static __inline__ mpqueue_head_t *
timer_call_entry_enqueue_deadline(
	timer_call_t			entry,
	mpqueue_head_t			*queue,
	uint64_t			deadline)
{
	return MPQUEUE(call_entry_enqueue_deadline(CE(entry),
						   QUEUE(queue), deadline));
}

#endif

#if TIMER_ASSERT
unsigned timer_call_enqueue_deadline_unlocked_async1;
unsigned timer_call_enqueue_deadline_unlocked_async2;
#endif
/*
 * Assumes call_entry and queues unlocked, interrupts disabled.
 */
__inline__ mpqueue_head_t *
timer_call_enqueue_deadline_unlocked(
	timer_call_t 			call,
	mpqueue_head_t			*queue,
	uint64_t			deadline)
{
	call_entry_t	entry = CE(call);
	mpqueue_head_t	*old_queue;

	DBG("timer_call_enqueue_deadline_unlocked(%p,%p,)\n", call, queue);

	simple_lock(&call->lock);
	old_queue = MPQUEUE(entry->queue);
	if (old_queue != NULL) {
		timer_call_lock_spin(old_queue);
		if (call->async_dequeue) {
			/* collision (1c): null queue pointer and reset flag */
			call->async_dequeue = FALSE;
			entry->queue = NULL;
#if TIMER_ASSERT
			timer_call_enqueue_deadline_unlocked_async1++;
#endif
		} else if (old_queue != queue) {
			(void)remque(qe(entry));
			entry->queue = NULL;
#if TIMER_ASSERT
			timer_call_enqueue_deadline_unlocked_async2++;
#endif
		}
		if (old_queue != queue) {
			timer_call_unlock(old_queue);
			timer_call_lock_spin(queue);
		}
	} else {
		timer_call_lock_spin(queue);
	}

	timer_call_entry_enqueue_deadline(call, queue, deadline);
	timer_call_unlock(queue);
	simple_unlock(&call->lock);

	return (old_queue);
}

#if TIMER_ASSERT
unsigned timer_call_dequeue_unlocked_async1;
unsigned timer_call_dequeue_unlocked_async2;
#endif
mpqueue_head_t *
timer_call_dequeue_unlocked(
	timer_call_t 		call)
{
	call_entry_t	entry = CE(call);
	mpqueue_head_t	*old_queue;

	DBG("timer_call_dequeue_unlocked(%p)\n", call);

	simple_lock(&call->lock);
	old_queue = MPQUEUE(entry->queue);
	if (old_queue != NULL) {
		timer_call_lock_spin(old_queue);
		if (call->async_dequeue) {
			/* collision (1c): null queue pointer and reset flag */
			call->async_dequeue = FALSE;
#if TIMER_ASSERT
			timer_call_dequeue_unlocked_async1++;
#endif
		} else {
			(void)remque(qe(entry));
#if TIMER_ASSERT
			timer_call_dequeue_unlocked_async2++;
#endif
		}
		entry->queue = NULL;
		timer_call_unlock(old_queue);
	}
	simple_unlock(&call->lock);
	return (old_queue);
}

static boolean_t 
timer_call_enter_internal(
	timer_call_t 		call,
	timer_call_param_t	param1,
	uint64_t 		deadline,
	uint32_t 		flags)
{
	mpqueue_head_t		*queue;
	mpqueue_head_t		*old_queue;
	spl_t			s;
	uint64_t 		slop = 0;

	s = splclock();

	call->soft_deadline = deadline;
	call->flags = flags;

	if ((flags & TIMER_CALL_CRITICAL) == 0 &&
	     mach_timer_coalescing_enabled) {
		slop = timer_call_slop(deadline);
		deadline += slop;
	}

#if	defined(__i386__) || defined(__x86_64__)	
	uint64_t ctime = mach_absolute_time();
	if (__improbable(deadline < ctime)) {
		uint64_t delta = (ctime - deadline);

		past_deadline_timers++;
		past_deadline_deltas += delta;
		if (delta > past_deadline_longest)
			past_deadline_longest = deadline;
		if (delta < past_deadline_shortest)
			past_deadline_shortest = delta;

		deadline = ctime + past_deadline_timer_adjustment;
		call->soft_deadline = deadline;
	}
#endif
	queue = timer_queue_assign(deadline);

	old_queue = timer_call_enqueue_deadline_unlocked(call, queue, deadline);

	CE(call)->param1 = param1;

	splx(s);

	return (old_queue != NULL);
}

boolean_t
timer_call_enter(
	timer_call_t		call,
	uint64_t		deadline,
	uint32_t		flags)
{
	return timer_call_enter_internal(call, NULL, deadline, flags);
}

boolean_t
timer_call_enter1(
	timer_call_t		call,
	timer_call_param_t	param1,
	uint64_t		deadline,
	uint32_t		flags)
{
	return timer_call_enter_internal(call, param1, deadline, flags);
}

boolean_t
timer_call_cancel(
	timer_call_t		call)
{
	mpqueue_head_t		*old_queue;
	spl_t			s;

	s = splclock();

	old_queue = timer_call_dequeue_unlocked(call);

	if (old_queue != NULL) {
		timer_call_lock_spin(old_queue);
		if (!queue_empty(&old_queue->head))
			timer_queue_cancel(old_queue, CE(call)->deadline, CE(queue_first(&old_queue->head))->deadline);
		else
			timer_queue_cancel(old_queue, CE(call)->deadline, UINT64_MAX);
		timer_call_unlock(old_queue);
	}
	splx(s);

	return (old_queue != NULL);
}

uint32_t	timer_queue_shutdown_lock_skips;
void
timer_queue_shutdown(
	mpqueue_head_t		*queue)
{
	timer_call_t		call;
	mpqueue_head_t		*new_queue;
	spl_t			s;

	DBG("timer_queue_shutdown(%p)\n", queue);

	s = splclock();

	/* Note comma operator in while expression re-locking each iteration */
	while (timer_call_lock_spin(queue), !queue_empty(&queue->head)) {
		call = TIMER_CALL(queue_first(&queue->head));
		if (!simple_lock_try(&call->lock)) {
			/*
			 * case (2b) lock order inversion, dequeue and skip
			 * Don't change the call_entry queue back-pointer
			 * but set the async_dequeue field.
			 */
			timer_queue_shutdown_lock_skips++;
			(void) remque(qe(call));
			call->async_dequeue = TRUE;
			timer_call_unlock(queue);
			continue;
		}

		/* remove entry from old queue */
		timer_call_entry_dequeue(call);
		timer_call_unlock(queue);

		/* and queue it on new */
		new_queue = timer_queue_assign(CE(call)->deadline);
		timer_call_lock_spin(new_queue);
		timer_call_entry_enqueue_deadline(
			call, new_queue, CE(call)->deadline);
		timer_call_unlock(new_queue);

		simple_unlock(&call->lock);
	}

	timer_call_unlock(queue);
	splx(s);
}

uint32_t	timer_queue_expire_lock_skips;
uint64_t
timer_queue_expire(
	mpqueue_head_t		*queue,
	uint64_t		deadline)
{
	timer_call_t	call;

	DBG("timer_queue_expire(%p,)\n", queue);

	timer_call_lock_spin(queue);

	while (!queue_empty(&queue->head)) {
		call = TIMER_CALL(queue_first(&queue->head));

		if (call->soft_deadline <= deadline) {
			timer_call_func_t		func;
			timer_call_param_t		param0, param1;

			if (!simple_lock_try(&call->lock)) {
				/* case (2b) lock inversion, dequeue and skip */
				timer_queue_expire_lock_skips++;
				(void) remque(qe(call));
				call->async_dequeue = TRUE;
				continue;
			}

			timer_call_entry_dequeue(call);

			func = CE(call)->func;
			param0 = CE(call)->param0;
			param1 = CE(call)->param1;

			simple_unlock(&call->lock);
			timer_call_unlock(queue);

			KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, 
				DECR_TIMER_CALLOUT | DBG_FUNC_START,
				VM_KERNEL_UNSLIDE(func), param0, param1, 0, 0);

#if CONFIG_DTRACE && (DEVELOPMENT || DEBUG )
			DTRACE_TMR3(callout__start, timer_call_func_t, func, 
										timer_call_param_t, param0, 
										timer_call_param_t, param1);
#endif

			(*func)(param0, param1);

#if CONFIG_DTRACE && (DEVELOPMENT || DEBUG )
			DTRACE_TMR3(callout__end, timer_call_func_t, func, 
										timer_call_param_t, param0, 
										timer_call_param_t, param1);
#endif

			KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, 
				DECR_TIMER_CALLOUT | DBG_FUNC_END,
				VM_KERNEL_UNSLIDE(func), param0, param1, 0, 0);

			timer_call_lock_spin(queue);
		}
		else
			break;
	}

	if (!queue_empty(&queue->head))
		deadline = CE(call)->deadline;
	else
		deadline = UINT64_MAX;

	timer_call_unlock(queue);

	return (deadline);
}


extern int serverperfmode;
uint32_t	timer_queue_migrate_lock_skips;
/*
 * timer_queue_migrate() is called by etimer_queue_migrate()
 * to move timer requests from the local processor (queue_from)
 * to a target processor's (queue_to).
 */
int
timer_queue_migrate(mpqueue_head_t *queue_from, mpqueue_head_t *queue_to)
{
	timer_call_t	call;
	timer_call_t	head_to;
	int		timers_migrated = 0;

	DBG("timer_queue_migrate(%p,%p)\n", queue_from, queue_to);

	assert(!ml_get_interrupts_enabled());
	assert(queue_from != queue_to);

	if (serverperfmode) {
		/*
		 * if we're running a high end server
		 * avoid migrations... they add latency
		 * and don't save us power under typical
		 * server workloads
		 */
		return -4;
	}

	/*
	 * Take both local (from) and target (to) timer queue locks while
	 * moving the timers from the local queue to the target processor.
	 * We assume that the target is always the boot processor.
	 * But only move if all of the following is true:
	 *  - the target queue is non-empty
	 *  - the local queue is non-empty
	 *  - the local queue's first deadline is later than the target's
	 *  - the local queue contains no non-migrateable "local" call
	 * so that we need not have the target resync.
	 */

        timer_call_lock_spin(queue_to);

	head_to = TIMER_CALL(queue_first(&queue_to->head));
	if (queue_empty(&queue_to->head)) {
		timers_migrated = -1;
		goto abort1;
	}

        timer_call_lock_spin(queue_from);

	if (queue_empty(&queue_from->head)) {
		timers_migrated = -2;
		goto abort2;
	}

	call = TIMER_CALL(queue_first(&queue_from->head));
	if (CE(call)->deadline < CE(head_to)->deadline) {
		timers_migrated = 0;
		goto abort2;
	}

	/* perform scan for non-migratable timers */
	do {
		if (call->flags & TIMER_CALL_LOCAL) {
			timers_migrated = -3;
			goto abort2;
		}
		call = TIMER_CALL(queue_next(qe(call)));
	} while (!queue_end(&queue_from->head, qe(call)));

	/* migration loop itself -- both queues are locked */
	while (!queue_empty(&queue_from->head)) {
		call = TIMER_CALL(queue_first(&queue_from->head));
		if (!simple_lock_try(&call->lock)) {
			/* case (2b) lock order inversion, dequeue only */
			timer_queue_migrate_lock_skips++;
			(void) remque(qe(call));
			call->async_dequeue = TRUE;
			continue;
		}
		timer_call_entry_dequeue(call);
		timer_call_entry_enqueue_deadline(
			call, queue_to, CE(call)->deadline);
		timers_migrated++;
		simple_unlock(&call->lock);
	}

abort2:
       	timer_call_unlock(queue_from);
abort1:
       	timer_call_unlock(queue_to);

	return timers_migrated;
}

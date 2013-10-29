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
#include <kern/timer_call.h>
#include <kern/timer_queue.h>
#include <kern/call_entry.h>
#include <kern/thread.h>

#include <sys/kdebug.h>

#if CONFIG_DTRACE
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

#if TIMER_TRACE
#define TIMER_KDEBUG_TRACE	KERNEL_DEBUG_CONSTANT_IST
#else
#define TIMER_KDEBUG_TRACE(x...)
#endif


lck_grp_t               timer_call_lck_grp;
lck_attr_t              timer_call_lck_attr;
lck_grp_attr_t          timer_call_lck_grp_attr;

lck_grp_t               timer_longterm_lck_grp;
lck_attr_t              timer_longterm_lck_attr;
lck_grp_attr_t          timer_longterm_lck_grp_attr;


#define timer_queue_lock_spin(queue)					\
	lck_mtx_lock_spin_always(&queue->lock_data)

#define timer_queue_unlock(queue)		\
	lck_mtx_unlock_always(&queue->lock_data)


#define QUEUE(x)	((queue_t)(x))
#define MPQUEUE(x)	((mpqueue_head_t *)(x))
#define TIMER_CALL(x)	((timer_call_t)(x))

/*
 * The longterm timer object is a global structure holding all timers
 * beyond the short-term, local timer queue threshold. The boot processor
 * is responsible for moving each timer to its local timer queue
 * if and when that timer becomes due within the threshold.
 */
#define TIMER_LONGTERM_NONE		EndOfAllTime
#if defined(__x86_64__)
#define	TIMER_LONGTERM_THRESHOLD	(1ULL * NSEC_PER_SEC)
#else
#define	TIMER_LONGTERM_THRESHOLD	TIMER_LONGTERM_NONE
#endif

typedef struct {
	uint64_t	interval;	/* longterm timer interval */
	uint64_t	margin;		/* fudge factor (10% of interval */
	uint64_t	deadline;	/* first/soonest longterm deadline */
	uint64_t	preempted;	/* sooner timer has pre-empted */
	timer_call_t	call;		/* first/soonest longterm timer call */
	uint64_t	deadline_set;	/* next timer set */
	timer_call_data_t timer;	/* timer used by threshold management */
					/* Stats: */
	uint64_t	scans;		/*   num threshold timer scans */
	uint64_t	preempts;	/*   num threshold reductions */
	uint64_t	latency;	/*   average threshold latency */	
	uint64_t	latency_min;	/*   minimum threshold latency */ 
	uint64_t	latency_max;	/*   maximum threshold latency */
} threshold_t;

typedef struct {
	mpqueue_head_t	queue;		/* longterm timer list */
	uint64_t	enqueues;	/* num timers queued */
	uint64_t	dequeues;	/* num timers dequeued */
	uint64_t	escalates;	/* num timers becoming shortterm */
	uint64_t	scan_time;	/* last time the list was scanned */
	threshold_t	threshold;	/* longterm timer threshold */
} timer_longterm_t;

timer_longterm_t		timer_longterm;

static mpqueue_head_t		*timer_longterm_queue = NULL;

static void			timer_longterm_init(void);
static void			timer_longterm_callout(
					timer_call_param_t	p0,
					timer_call_param_t	p1);
extern void			timer_longterm_scan(	
					timer_longterm_t	*tlp,
					uint64_t		now);
static void			timer_longterm_update(
					timer_longterm_t *tlp);
static void			timer_longterm_update_locked(
					timer_longterm_t *tlp);
static mpqueue_head_t *		timer_longterm_enqueue_unlocked(
					timer_call_t		call,
					uint64_t		now,
					uint64_t		deadline,
					mpqueue_head_t **	old_queue);
static void			timer_longterm_dequeued_locked(
					timer_call_t		call);

uint64_t past_deadline_timers;
uint64_t past_deadline_deltas;
uint64_t past_deadline_longest;
uint64_t past_deadline_shortest = ~0ULL;
enum {PAST_DEADLINE_TIMER_ADJUSTMENT_NS = 10 * 1000};

uint64_t past_deadline_timer_adjustment;

static boolean_t timer_call_enter_internal(timer_call_t call, timer_call_param_t param1, uint64_t deadline, uint64_t leeway, uint32_t flags, boolean_t ratelimited);
boolean_t 	mach_timer_coalescing_enabled = TRUE;

mpqueue_head_t	*timer_call_enqueue_deadline_unlocked(
			timer_call_t		call,
			mpqueue_head_t		*queue,
			uint64_t		deadline);

mpqueue_head_t	*timer_call_dequeue_unlocked(
			timer_call_t 		call);


void
timer_call_init(void)
{
	lck_attr_setdefault(&timer_call_lck_attr);
	lck_grp_attr_setdefault(&timer_call_lck_grp_attr);
	lck_grp_init(&timer_call_lck_grp, "timer_call", &timer_call_lck_grp_attr);
	nanotime_to_absolutetime(0, PAST_DEADLINE_TIMER_ADJUSTMENT_NS, &past_deadline_timer_adjustment);

	timer_longterm_init();
}


void
timer_call_queue_init(mpqueue_head_t *queue)
{
	DBG("timer_call_queue_init(%p)\n", queue);
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
 *    2c) Same as 2b but occurring when a longterm timer is matured.
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
	old_queue->count--;

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

/* For efficiency, track the earliest soft deadline on the queue, so that
 * fuzzy decisions can be made without lock acquisitions.
 */
	queue->earliest_soft_deadline = ((timer_call_t)queue_first(&queue->head))->soft_deadline;

	if (old_queue)
		old_queue->count--;
	queue->count++;

	return (old_queue);
}

#else

static __inline__ mpqueue_head_t *
timer_call_entry_dequeue(
	timer_call_t		entry)
{
	mpqueue_head_t	*old_queue = MPQUEUE(CE(entry)->queue);

	call_entry_dequeue(CE(entry));
	old_queue->count--;

	return old_queue;
}

static __inline__ mpqueue_head_t *
timer_call_entry_enqueue_deadline(
	timer_call_t			entry,
	mpqueue_head_t			*queue,
	uint64_t			deadline)
{
	mpqueue_head_t	*old_queue = MPQUEUE(CE(entry)->queue);

	call_entry_enqueue_deadline(CE(entry), QUEUE(queue), deadline);

	/* For efficiency, track the earliest soft deadline on the queue,
	 * so that fuzzy decisions can be made without lock acquisitions.
	 */
	queue->earliest_soft_deadline = ((timer_call_t)queue_first(&queue->head))->soft_deadline;

	if (old_queue)
		old_queue->count--;
	queue->count++;

	return old_queue;
}

#endif

static __inline__ void
timer_call_entry_enqueue_tail(
	timer_call_t			entry,
	mpqueue_head_t			*queue)
{
	call_entry_enqueue_tail(CE(entry), QUEUE(queue));
	queue->count++;
	return;
}

/*
 * Remove timer entry from its queue but don't change the queue pointer
 * and set the async_dequeue flag. This is locking case 2b.
 */
static __inline__ void
timer_call_entry_dequeue_async(
	timer_call_t		entry)
{
	mpqueue_head_t	*old_queue = MPQUEUE(CE(entry)->queue);
	if (old_queue) {
		old_queue->count--;
		(void) remque(qe(entry));
		entry->async_dequeue = TRUE;
	}
	return;
}

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
		timer_queue_lock_spin(old_queue);
		if (call->async_dequeue) {
			/* collision (1c): timer already dequeued, clear flag */
#if TIMER_ASSERT
			TIMER_KDEBUG_TRACE(KDEBUG_TRACE, 
				DECR_TIMER_ASYNC_DEQ | DBG_FUNC_NONE,
				call,
				call->async_dequeue,
				CE(call)->queue,
				0x1c, 0);
			timer_call_enqueue_deadline_unlocked_async1++;
#endif
			call->async_dequeue = FALSE;
			entry->queue = NULL;
		} else if (old_queue != queue) {
			timer_call_entry_dequeue(call);
#if TIMER_ASSERT
			timer_call_enqueue_deadline_unlocked_async2++;
#endif
		}
		if (old_queue == timer_longterm_queue)
			timer_longterm_dequeued_locked(call);
		if (old_queue != queue) {
			timer_queue_unlock(old_queue);
			timer_queue_lock_spin(queue);
		}
	} else {
		timer_queue_lock_spin(queue);
	}

	timer_call_entry_enqueue_deadline(call, queue, deadline);
	timer_queue_unlock(queue);
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
#if TIMER_ASSERT
	TIMER_KDEBUG_TRACE(KDEBUG_TRACE, 
		DECR_TIMER_ASYNC_DEQ | DBG_FUNC_NONE,
		call,
		call->async_dequeue,
		CE(call)->queue,
		0, 0);
#endif
	if (old_queue != NULL) {
		timer_queue_lock_spin(old_queue);
		if (call->async_dequeue) {
			/* collision (1c): timer already dequeued, clear flag */
#if TIMER_ASSERT
			TIMER_KDEBUG_TRACE(KDEBUG_TRACE, 
				DECR_TIMER_ASYNC_DEQ | DBG_FUNC_NONE,
				call,
				call->async_dequeue,
				CE(call)->queue,
				0x1c, 0);
			timer_call_dequeue_unlocked_async1++;
#endif
			call->async_dequeue = FALSE;
			entry->queue = NULL;
		} else {
			timer_call_entry_dequeue(call);
		}
		if (old_queue == timer_longterm_queue)
			timer_longterm_dequeued_locked(call);
		timer_queue_unlock(old_queue);
	}
	simple_unlock(&call->lock);
	return (old_queue);
}

static boolean_t 
timer_call_enter_internal(
	timer_call_t 		call,
	timer_call_param_t	param1,
	uint64_t 		deadline,
	uint64_t 		leeway,
	uint32_t 		flags,
	boolean_t		ratelimited)
{
	mpqueue_head_t		*queue = NULL;
	mpqueue_head_t		*old_queue;
	spl_t			s;
	uint64_t 		slop;
	uint32_t		urgency;

	s = splclock();

	call->soft_deadline = deadline;
	call->flags = flags;

	uint64_t ctime = mach_absolute_time();

	TIMER_KDEBUG_TRACE(KDEBUG_TRACE,
        	DECR_TIMER_ENTER | DBG_FUNC_START,
		call,
		param1, deadline, flags, 0); 

	urgency = (flags & TIMER_CALL_URGENCY_MASK);

	boolean_t slop_ratelimited = FALSE;
	slop = timer_call_slop(deadline, ctime, urgency, current_thread(), &slop_ratelimited);

	if ((flags & TIMER_CALL_LEEWAY) != 0 && leeway > slop)
		slop = leeway;

	if (UINT64_MAX - deadline <= slop) {
		deadline = UINT64_MAX;
	} else {
		deadline += slop;
	}

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

	/* Bit 0 of the "soft" deadline indicates that
	 * this particular timer call requires rate-limiting
	 * behaviour. Maintain the invariant deadline >= soft_deadline by
	 * setting bit 0 of "deadline".
	 */

	deadline |= 1;
	if (ratelimited || slop_ratelimited) {
		call->soft_deadline |= 1ULL;
	} else {
		call->soft_deadline &= ~0x1ULL;
	}

	call->ttd =  call->soft_deadline - ctime;

#if CONFIG_DTRACE
	DTRACE_TMR7(callout__create, timer_call_func_t, CE(call)->func,
	timer_call_param_t, CE(call)->param0, uint32_t, call->flags,
	    (deadline - call->soft_deadline),
	    (call->ttd >> 32), (unsigned) (call->ttd & 0xFFFFFFFF), call);
#endif

	if (!ratelimited && !slop_ratelimited) {
		queue = timer_longterm_enqueue_unlocked(call, ctime, deadline, &old_queue);
	}

	if (queue == NULL) {
		queue = timer_queue_assign(deadline);
		old_queue = timer_call_enqueue_deadline_unlocked(call, queue, deadline);
	}

	CE(call)->param1 = param1;
#if TIMER_TRACE
	CE(call)->entry_time = ctime;
#endif

	TIMER_KDEBUG_TRACE(KDEBUG_TRACE,
        	DECR_TIMER_ENTER | DBG_FUNC_END,
		call,
		(old_queue != NULL), call->soft_deadline, queue->count, 0); 

	splx(s);

	return (old_queue != NULL);
}

/*
 * timer_call_*()
 *	return boolean indicating whether the call was previously queued.
 */
boolean_t
timer_call_enter(
	timer_call_t		call,
	uint64_t		deadline,
	uint32_t		flags)
{
	return timer_call_enter_internal(call, NULL, deadline, 0, flags, FALSE);
}

boolean_t
timer_call_enter1(
	timer_call_t		call,
	timer_call_param_t	param1,
	uint64_t		deadline,
	uint32_t		flags)
{
	return timer_call_enter_internal(call, param1, deadline, 0, flags, FALSE);
}

boolean_t
timer_call_enter_with_leeway(
	timer_call_t		call,
	timer_call_param_t	param1,
	uint64_t		deadline,
	uint64_t		leeway,
	uint32_t		flags,
	boolean_t		ratelimited)
{
	return timer_call_enter_internal(call, param1, deadline, leeway, flags, ratelimited);
}

boolean_t
timer_call_cancel(
	timer_call_t		call)
{
	mpqueue_head_t		*old_queue;
	spl_t			s;

	s = splclock();

	TIMER_KDEBUG_TRACE(KDEBUG_TRACE,
        	DECR_TIMER_CANCEL | DBG_FUNC_START,
		call,
		CE(call)->deadline, call->soft_deadline, call->flags, 0);

	old_queue = timer_call_dequeue_unlocked(call);

	if (old_queue != NULL) {
		timer_queue_lock_spin(old_queue);
		if (!queue_empty(&old_queue->head)) {
			timer_queue_cancel(old_queue, CE(call)->deadline, CE(queue_first(&old_queue->head))->deadline);
			old_queue->earliest_soft_deadline = ((timer_call_t)queue_first(&old_queue->head))->soft_deadline;
		}
		else {
			timer_queue_cancel(old_queue, CE(call)->deadline, UINT64_MAX);
			old_queue->earliest_soft_deadline = UINT64_MAX;
		}
		timer_queue_unlock(old_queue);
	}
	TIMER_KDEBUG_TRACE(KDEBUG_TRACE,
        	DECR_TIMER_CANCEL | DBG_FUNC_END,
		call,
		old_queue,
		CE(call)->deadline - mach_absolute_time(),
		CE(call)->deadline - CE(call)->entry_time, 0);
	splx(s);

#if CONFIG_DTRACE
	DTRACE_TMR6(callout__cancel, timer_call_func_t, CE(call)->func,
	    timer_call_param_t, CE(call)->param0, uint32_t, call->flags, 0,
	    (call->ttd >> 32), (unsigned) (call->ttd & 0xFFFFFFFF));
#endif

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
	while (timer_queue_lock_spin(queue), !queue_empty(&queue->head)) {
		call = TIMER_CALL(queue_first(&queue->head));
		if (!simple_lock_try(&call->lock)) {
			/*
			 * case (2b) lock order inversion, dequeue and skip
			 * Don't change the call_entry queue back-pointer
			 * but set the async_dequeue field.
			 */
			timer_queue_shutdown_lock_skips++;
			timer_call_entry_dequeue_async(call);
#if TIMER_ASSERT
			TIMER_KDEBUG_TRACE(KDEBUG_TRACE, 
				DECR_TIMER_ASYNC_DEQ | DBG_FUNC_NONE,
				call,
				call->async_dequeue,
				CE(call)->queue,
				0x2b, 0);
#endif
			timer_queue_unlock(queue);
			continue;
		}

		/* remove entry from old queue */
		timer_call_entry_dequeue(call);
		timer_queue_unlock(queue);

		/* and queue it on new */
		new_queue = timer_queue_assign(CE(call)->deadline);
		timer_queue_lock_spin(new_queue);
		timer_call_entry_enqueue_deadline(
			call, new_queue, CE(call)->deadline);
		timer_queue_unlock(new_queue);

		simple_unlock(&call->lock);
	}

	timer_queue_unlock(queue);
	splx(s);
}

uint32_t	timer_queue_expire_lock_skips;
uint64_t
timer_queue_expire_with_options(
	mpqueue_head_t		*queue,
	uint64_t		deadline,
	boolean_t		rescan)
{
	timer_call_t	call = NULL;
	uint32_t tc_iterations = 0;
	DBG("timer_queue_expire(%p,)\n", queue);

	uint64_t cur_deadline = deadline;
	timer_queue_lock_spin(queue);

	while (!queue_empty(&queue->head)) {
		/* Upon processing one or more timer calls, refresh the
		 * deadline to account for time elapsed in the callout
		 */
		if (++tc_iterations > 1)
			cur_deadline = mach_absolute_time();

		if (call == NULL)
			call = TIMER_CALL(queue_first(&queue->head));

		if (call->soft_deadline <= cur_deadline) {
			timer_call_func_t		func;
			timer_call_param_t		param0, param1;

			TCOAL_DEBUG(0xDDDD0000, queue->earliest_soft_deadline, call->soft_deadline, 0, 0, 0);
			TIMER_KDEBUG_TRACE(KDEBUG_TRACE, 
				DECR_TIMER_EXPIRE | DBG_FUNC_NONE,
				call,
				call->soft_deadline,
				CE(call)->deadline,
				CE(call)->entry_time, 0);

			/* Bit 0 of the "soft" deadline indicates that
			 * this particular timer call is rate-limited
			 * and hence shouldn't be processed before its
			 * hard deadline.
			 */
			if ((call->soft_deadline & 0x1) &&
			    (CE(call)->deadline > cur_deadline)) {
				if (rescan == FALSE)
					break;
			}

			if (!simple_lock_try(&call->lock)) {
				/* case (2b) lock inversion, dequeue and skip */
				timer_queue_expire_lock_skips++;
				timer_call_entry_dequeue_async(call);
				call = NULL;
				continue;
			}

			timer_call_entry_dequeue(call);

			func = CE(call)->func;
			param0 = CE(call)->param0;
			param1 = CE(call)->param1;

			simple_unlock(&call->lock);
			timer_queue_unlock(queue);

			TIMER_KDEBUG_TRACE(KDEBUG_TRACE, 
				DECR_TIMER_CALLOUT | DBG_FUNC_START,
				call, VM_KERNEL_UNSLIDE(func), param0, param1, 0);

#if CONFIG_DTRACE
			DTRACE_TMR7(callout__start, timer_call_func_t, func,
			    timer_call_param_t, param0, unsigned, call->flags,
			    0, (call->ttd >> 32),
			    (unsigned) (call->ttd & 0xFFFFFFFF), call);
#endif
			/* Maintain time-to-deadline in per-processor data
			 * structure for thread wakeup deadline statistics.
			 */
			uint64_t *ttdp = &(PROCESSOR_DATA(current_processor(), timer_call_ttd));
			*ttdp = call->ttd;
			(*func)(param0, param1);
			*ttdp = 0;
#if CONFIG_DTRACE
			DTRACE_TMR4(callout__end, timer_call_func_t, func,
			    param0, param1, call);
#endif

			TIMER_KDEBUG_TRACE(KDEBUG_TRACE, 
				DECR_TIMER_CALLOUT | DBG_FUNC_END,
				call, VM_KERNEL_UNSLIDE(func), param0, param1, 0);
			call = NULL;
			timer_queue_lock_spin(queue);
		} else {
			if (__probable(rescan == FALSE)) {
				break;
			} else {
				int64_t skew = CE(call)->deadline - call->soft_deadline;
				assert(CE(call)->deadline >= call->soft_deadline);

				/* DRK: On a latency quality-of-service level change,
				 * re-sort potentially rate-limited timers. The platform
				 * layer determines which timers require
				 * this. In the absence of the per-callout
				 * synchronization requirement, a global resort could
				 * be more efficient. The re-sort effectively
				 * annuls all timer adjustments, i.e. the "soft
				 * deadline" is the sort key.
				 */
	
				if (timer_resort_threshold(skew)) {
					if (__probable(simple_lock_try(&call->lock))) {
						timer_call_entry_dequeue(call);
						timer_call_entry_enqueue_deadline(call, queue, call->soft_deadline);
						simple_unlock(&call->lock);
						call = NULL;
					}
				}
				if (call) {
					call = TIMER_CALL(queue_next(qe(call)));
					if (queue_end(&queue->head, qe(call)))
						break;
				}
			}
		}
	}

	if (!queue_empty(&queue->head)) {
		call = TIMER_CALL(queue_first(&queue->head));
		cur_deadline = CE(call)->deadline;
		queue->earliest_soft_deadline = call->soft_deadline;
	} else {
		queue->earliest_soft_deadline = cur_deadline = UINT64_MAX;
	}

	timer_queue_unlock(queue);

	return (cur_deadline);
}

uint64_t
timer_queue_expire(
	mpqueue_head_t		*queue,
	uint64_t		deadline)
{
	return timer_queue_expire_with_options(queue, deadline, FALSE);
}

extern int serverperfmode;
uint32_t	timer_queue_migrate_lock_skips;
/*
 * timer_queue_migrate() is called by timer_queue_migrate_cpu()
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

        timer_queue_lock_spin(queue_to);

	head_to = TIMER_CALL(queue_first(&queue_to->head));
	if (queue_empty(&queue_to->head)) {
		timers_migrated = -1;
		goto abort1;
	}

        timer_queue_lock_spin(queue_from);

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
#ifdef TIMER_ASSERT
			TIMER_KDEBUG_TRACE(KDEBUG_TRACE, 
				DECR_TIMER_ASYNC_DEQ | DBG_FUNC_NONE,
				call,
				CE(call)->queue,
				call->lock.interlock.lock_data,
				0x2b, 0);
#endif
			timer_queue_migrate_lock_skips++;
			timer_call_entry_dequeue_async(call);
			continue;
		}
		timer_call_entry_dequeue(call);
		timer_call_entry_enqueue_deadline(
			call, queue_to, CE(call)->deadline);
		timers_migrated++;
		simple_unlock(&call->lock);
	}
	queue_from->earliest_soft_deadline = UINT64_MAX;
abort2:
       	timer_queue_unlock(queue_from);
abort1:
       	timer_queue_unlock(queue_to);

	return timers_migrated;
}

void
timer_queue_trace_cpu(int ncpu)
{
	timer_call_nosync_cpu(
		ncpu,
		(void(*)())timer_queue_trace,
		(void*) timer_queue_cpu(ncpu));
}

void
timer_queue_trace(
	mpqueue_head_t			*queue)
{
	timer_call_t	call;
	spl_t		s;

	if (!kdebug_enable)
		return;

	s = splclock();
	timer_queue_lock_spin(queue);

	TIMER_KDEBUG_TRACE(KDEBUG_TRACE,
        	DECR_TIMER_QUEUE | DBG_FUNC_START,
		queue->count, mach_absolute_time(), 0, 0, 0); 

	if (!queue_empty(&queue->head)) {
		call = TIMER_CALL(queue_first(&queue->head));
		do {
			TIMER_KDEBUG_TRACE(KDEBUG_TRACE,
        			DECR_TIMER_QUEUE | DBG_FUNC_NONE,
				call->soft_deadline,
				CE(call)->deadline,
				CE(call)->entry_time,
				CE(call)->func,
				0);
			call = TIMER_CALL(queue_next(qe(call)));
		} while (!queue_end(&queue->head, qe(call)));
	}

	TIMER_KDEBUG_TRACE(KDEBUG_TRACE,
        	DECR_TIMER_QUEUE | DBG_FUNC_END,
		queue->count, mach_absolute_time(), 0, 0, 0); 

	timer_queue_unlock(queue);
	splx(s);
}

void
timer_longterm_dequeued_locked(timer_call_t call)
{
	timer_longterm_t	*tlp = &timer_longterm;

	tlp->dequeues++;
	if (call == tlp->threshold.call)
		tlp->threshold.call = NULL;
}

/*
 * Place a timer call in the longterm list
 * and adjust the next timer callout deadline if the new timer is first.
 */
mpqueue_head_t *
timer_longterm_enqueue_unlocked(timer_call_t	call,
				uint64_t	now,
				uint64_t	deadline,
				mpqueue_head_t	**old_queue)
{
	timer_longterm_t	*tlp = &timer_longterm;
	boolean_t		update_required = FALSE;
	uint64_t		longterm_threshold;

	longterm_threshold = now + tlp->threshold.interval;

	/*
	 * Return NULL without doing anything if:
	 *  - this timer is local, or
	 *  - the longterm mechanism is disabled, or
	 *  - this deadline is too short.
	 */
	if (__probable((call->flags & TIMER_CALL_LOCAL) != 0 ||
	    (tlp->threshold.interval == TIMER_LONGTERM_NONE) ||
		(deadline <= longterm_threshold)))
		return NULL;

	/*
 	 * Remove timer from its current queue, if any.
	 */
	*old_queue = timer_call_dequeue_unlocked(call);

	/*
	 * Lock the longterm queue, queue timer and determine
	 * whether an update is necessary.
	 */
	assert(!ml_get_interrupts_enabled());
	simple_lock(&call->lock);
	timer_queue_lock_spin(timer_longterm_queue);
	timer_call_entry_enqueue_tail(call, timer_longterm_queue);
	CE(call)->deadline = deadline;
	
	tlp->enqueues++;

	/*
	 * We'll need to update the currently set threshold timer
	 * if the new deadline is sooner and no sooner update is in flight.
	 */ 
	if (deadline < tlp->threshold.deadline &&
	    deadline < tlp->threshold.preempted) {
		tlp->threshold.preempted = deadline;
		tlp->threshold.call = call;
		update_required = TRUE;
	}
	timer_queue_unlock(timer_longterm_queue);
	simple_unlock(&call->lock);
	
	if (update_required) {
		timer_call_nosync_cpu(
			master_cpu,
			(void (*)(void *)) timer_longterm_update,
			(void *)tlp);
	}

	return timer_longterm_queue;
}

/*
 * Scan for timers below the longterm threshold.
 * Move these to the local timer queue (of the boot processor on which the
 * calling thread is running).
 * Both the local (boot) queue and the longterm queue are locked.
 * The scan is similar to the timer migrate sequence but is performed by
 * successively examining each timer on the longterm queue:
 *  - if within the short-term threshold
 *    - enter on the local queue (unless being deleted), 
 *  - otherwise:
 *    - if sooner, deadline becomes the next threshold deadline.
 */
void
timer_longterm_scan(timer_longterm_t	*tlp,
		    uint64_t		now)
{
	queue_entry_t	qe;
	timer_call_t	call;
	uint64_t	threshold;
	uint64_t	deadline;
	mpqueue_head_t	*timer_master_queue;

	assert(!ml_get_interrupts_enabled());
	assert(cpu_number() == master_cpu);

	if (tlp->threshold.interval != TIMER_LONGTERM_NONE)
		threshold = now + tlp->threshold.interval;
	else
		threshold = TIMER_LONGTERM_NONE;

	tlp->threshold.deadline = TIMER_LONGTERM_NONE;
	tlp->threshold.call = NULL;

	if (queue_empty(&timer_longterm_queue->head))
		return;

	timer_master_queue = timer_queue_cpu(master_cpu);
	timer_queue_lock_spin(timer_master_queue);

	qe = queue_first(&timer_longterm_queue->head);
	while (!queue_end(&timer_longterm_queue->head, qe)) {
		call = TIMER_CALL(qe);
		deadline = call->soft_deadline;
		qe = queue_next(qe);
		if (!simple_lock_try(&call->lock)) {
			/* case (2c) lock order inversion, dequeue only */
#ifdef TIMER_ASSERT
			TIMER_KDEBUG_TRACE(KDEBUG_TRACE,
				DECR_TIMER_ASYNC_DEQ | DBG_FUNC_NONE,
				call,
				CE(call)->queue,
				call->lock.interlock.lock_data,
				0x2c, 0);
#endif
			timer_call_entry_dequeue_async(call);
			continue;
		}
		if (deadline < threshold) {
			/*
			 * This timer needs moving (escalating)
			 * to the local (boot) processor's queue.
			 */
#ifdef TIMER_ASSERT
			if (deadline < now)
				TIMER_KDEBUG_TRACE(KDEBUG_TRACE,
       		 			DECR_TIMER_OVERDUE | DBG_FUNC_NONE,
					call,
					deadline,
					now,
					threshold,
					0);
#endif
			TIMER_KDEBUG_TRACE(KDEBUG_TRACE,
       	 			DECR_TIMER_ESCALATE | DBG_FUNC_NONE,
				call,
				CE(call)->deadline,
				CE(call)->entry_time,
				CE(call)->func,
				0);
			tlp->escalates++;
			timer_call_entry_dequeue(call);
			timer_call_entry_enqueue_deadline(
				call, timer_master_queue, CE(call)->deadline);
			/*
			 * A side-effect of the following call is to update
			 * the actual hardware deadline if required.
			 */
			(void) timer_queue_assign(deadline);
		} else {
			if (deadline < tlp->threshold.deadline) {
				tlp->threshold.deadline = deadline;
				tlp->threshold.call = call;
			}
		}
		simple_unlock(&call->lock);
	}

	timer_queue_unlock(timer_master_queue);
}

void
timer_longterm_callout(timer_call_param_t p0, __unused timer_call_param_t p1)
{
	timer_longterm_t	*tlp = (timer_longterm_t *) p0;

	timer_longterm_update(tlp);
}

void
timer_longterm_update_locked(timer_longterm_t *tlp)
{
	uint64_t	latency;

	TIMER_KDEBUG_TRACE(KDEBUG_TRACE, 
		DECR_TIMER_UPDATE | DBG_FUNC_START,
		&tlp->queue,
		tlp->threshold.deadline,
		tlp->threshold.preempted,
		tlp->queue.count, 0);

	tlp->scan_time = mach_absolute_time();
	if (tlp->threshold.preempted != TIMER_LONGTERM_NONE) {
		tlp->threshold.preempts++;
		tlp->threshold.deadline = tlp->threshold.preempted;
		tlp->threshold.preempted = TIMER_LONGTERM_NONE;
		/*
		 * Note: in the unlikely event that a pre-empted timer has
		 * itself been cancelled, we'll simply re-scan later at the
		 * time of the preempted/cancelled timer.
		 */
	} else {
		tlp->threshold.scans++;

		/*
		 * Maintain a moving average of our wakeup latency.
		 * Clamp latency to 0 and ignore above threshold interval.
		 */
		if (tlp->scan_time > tlp->threshold.deadline_set)
			latency = tlp->scan_time - tlp->threshold.deadline_set;
		else
			latency = 0;
		if (latency < tlp->threshold.interval) {
			tlp->threshold.latency_min =
				MIN(tlp->threshold.latency_min, latency);
			tlp->threshold.latency_max =
				MAX(tlp->threshold.latency_max, latency);
			tlp->threshold.latency =
				(tlp->threshold.latency*99 + latency) / 100;
		}

		timer_longterm_scan(tlp, tlp->scan_time); 
	}

	tlp->threshold.deadline_set = tlp->threshold.deadline;
	/* The next deadline timer to be set is adjusted */
	if (tlp->threshold.deadline != TIMER_LONGTERM_NONE) {
		tlp->threshold.deadline_set -= tlp->threshold.margin;
		tlp->threshold.deadline_set -= tlp->threshold.latency;
	}

	TIMER_KDEBUG_TRACE(KDEBUG_TRACE, 
		DECR_TIMER_UPDATE | DBG_FUNC_END,
		&tlp->queue,
		tlp->threshold.deadline,
		tlp->threshold.scans,
		tlp->queue.count, 0);
}

void
timer_longterm_update(timer_longterm_t *tlp)
{
	spl_t	s = splclock();

	timer_queue_lock_spin(timer_longterm_queue);

	if (cpu_number() != master_cpu)
		panic("timer_longterm_update_master() on non-boot cpu");

	timer_longterm_update_locked(tlp);

	if (tlp->threshold.deadline != TIMER_LONGTERM_NONE)
		timer_call_enter(
			&tlp->threshold.timer,
			tlp->threshold.deadline_set,
			TIMER_CALL_LOCAL | TIMER_CALL_SYS_CRITICAL);
	
	timer_queue_unlock(timer_longterm_queue);
	splx(s);
}

void
timer_longterm_init(void)
{
	uint32_t		longterm;
	timer_longterm_t	*tlp = &timer_longterm;

	DBG("timer_longterm_init() tlp: %p, queue: %p\n", tlp, &tlp->queue);

	/*
	 * Set the longterm timer threshold.
	 * Defaults to TIMER_LONGTERM_THRESHOLD; overridden longterm boot-arg 
	 */
	tlp->threshold.interval = TIMER_LONGTERM_THRESHOLD;
	if (PE_parse_boot_argn("longterm", &longterm, sizeof (longterm))) {
		tlp->threshold.interval = (longterm == 0) ?
						TIMER_LONGTERM_NONE :
						longterm * NSEC_PER_MSEC;
	}
	if (tlp->threshold.interval != TIMER_LONGTERM_NONE) {
		printf("Longterm timer threshold: %llu ms\n",
			tlp->threshold.interval / NSEC_PER_MSEC); 
		kprintf("Longterm timer threshold: %llu ms\n",
			tlp->threshold.interval / NSEC_PER_MSEC); 
		nanoseconds_to_absolutetime(tlp->threshold.interval,
					    &tlp->threshold.interval);
		tlp->threshold.margin = tlp->threshold.interval / 10;
		tlp->threshold.latency_min = EndOfAllTime;
		tlp->threshold.latency_max = 0;
	}

	tlp->threshold.preempted = TIMER_LONGTERM_NONE;
	tlp->threshold.deadline = TIMER_LONGTERM_NONE;

	lck_attr_setdefault(&timer_longterm_lck_attr);
	lck_grp_attr_setdefault(&timer_longterm_lck_grp_attr);
	lck_grp_init(&timer_longterm_lck_grp,
		     "timer_longterm", &timer_longterm_lck_grp_attr);
	mpqueue_init(&tlp->queue,
		     &timer_longterm_lck_grp, &timer_longterm_lck_attr);

	timer_call_setup(&tlp->threshold.timer,
			 timer_longterm_callout, (timer_call_param_t) tlp);

	timer_longterm_queue = &tlp->queue;
}

enum {
	THRESHOLD, QCOUNT,
	ENQUEUES, DEQUEUES, ESCALATES, SCANS, PREEMPTS,
	LATENCY, LATENCY_MIN, LATENCY_MAX
};
uint64_t
timer_sysctl_get(int oid)
{
	timer_longterm_t	*tlp = &timer_longterm;

	switch (oid) {
	case THRESHOLD:
		return (tlp->threshold.interval == TIMER_LONGTERM_NONE) ?
			0 : tlp->threshold.interval / NSEC_PER_MSEC;
	case QCOUNT:
		return tlp->queue.count;
	case ENQUEUES:
		return tlp->enqueues;
	case DEQUEUES:
		return tlp->dequeues;
	case ESCALATES:
		return tlp->escalates;
	case SCANS:
		return tlp->threshold.scans;
	case PREEMPTS:
		return tlp->threshold.preempts;
	case LATENCY:
		return tlp->threshold.latency;
	case LATENCY_MIN:
		return tlp->threshold.latency_min;
	case LATENCY_MAX:
		return tlp->threshold.latency_max;
	default:
		return 0;
	}
}

/*
 * timer_master_scan() is the inverse of timer_longterm_scan()
 * since it un-escalates timers to the longterm queue.
 */
static void
timer_master_scan(timer_longterm_t	*tlp,
		  uint64_t		now)
{
	queue_entry_t	qe;
	timer_call_t	call;
	uint64_t	threshold;
	uint64_t	deadline;
	mpqueue_head_t	*timer_master_queue;

	if (tlp->threshold.interval != TIMER_LONGTERM_NONE)
		threshold = now + tlp->threshold.interval;
	else
		threshold = TIMER_LONGTERM_NONE;

	timer_master_queue = timer_queue_cpu(master_cpu);
	timer_queue_lock_spin(timer_master_queue);

	qe = queue_first(&timer_master_queue->head);
	while (!queue_end(&timer_master_queue->head, qe)) {
		call = TIMER_CALL(qe);
		deadline = CE(call)->deadline;
		qe = queue_next(qe);
		if ((call->flags & TIMER_CALL_LOCAL) != 0)
			continue;
		if (!simple_lock_try(&call->lock)) {
			/* case (2c) lock order inversion, dequeue only */
			timer_call_entry_dequeue_async(call);
			continue;
		}
		if (deadline > threshold) {
			/* move from master to longterm */
			timer_call_entry_dequeue(call);
			timer_call_entry_enqueue_tail(call, timer_longterm_queue);
			if (deadline < tlp->threshold.deadline) {
				tlp->threshold.deadline = deadline;
				tlp->threshold.call = call;
			}
		}
		simple_unlock(&call->lock);
	}
	timer_queue_unlock(timer_master_queue);
}

static void
timer_sysctl_set_threshold(uint64_t value)
{
	timer_longterm_t	*tlp = &timer_longterm;
	spl_t			s = splclock();
	boolean_t		threshold_increase;

	timer_queue_lock_spin(timer_longterm_queue);

	timer_call_cancel(&tlp->threshold.timer);

	/*
	 * Set the new threshold and note whther it's increasing.
	 */
	if (value == 0) {
		tlp->threshold.interval = TIMER_LONGTERM_NONE;
		threshold_increase = TRUE;
		timer_call_cancel(&tlp->threshold.timer);
	} else {
		uint64_t	old_interval = tlp->threshold.interval;
		tlp->threshold.interval = value * NSEC_PER_MSEC;
		nanoseconds_to_absolutetime(tlp->threshold.interval,
					    &tlp->threshold.interval);
		tlp->threshold.margin = tlp->threshold.interval / 10;
		if  (old_interval == TIMER_LONGTERM_NONE)
			threshold_increase = FALSE;
		else
			threshold_increase = (tlp->threshold.interval > old_interval);
	}

	if (threshold_increase /* or removal */) {
		/* Escalate timers from the longterm queue */
		timer_longterm_scan(tlp, mach_absolute_time());
	} else /* decrease or addition  */ {
		/*
		 * We scan the local/master queue for timers now longterm.
		 * To be strictly correct, we should scan all processor queues
		 * but timer migration results in most timers gravitating to the
		 * master processor in any case.
		 */
		timer_master_scan(tlp, mach_absolute_time());
	}

	/* Set new timer accordingly */
	tlp->threshold.deadline_set = tlp->threshold.deadline;
	if (tlp->threshold.deadline != TIMER_LONGTERM_NONE) {
		tlp->threshold.deadline_set -= tlp->threshold.margin;
		tlp->threshold.deadline_set -= tlp->threshold.latency;
		timer_call_enter(
			&tlp->threshold.timer,
			tlp->threshold.deadline_set,
			TIMER_CALL_LOCAL | TIMER_CALL_SYS_CRITICAL);
	}

	/* Reset stats */
	tlp->enqueues = 0;
	tlp->dequeues = 0;
	tlp->escalates = 0;
	tlp->threshold.scans = 0;
	tlp->threshold.preempts = 0;
	tlp->threshold.latency = 0;
	tlp->threshold.latency_min = EndOfAllTime;
	tlp->threshold.latency_max = 0;

	timer_queue_unlock(timer_longterm_queue);
	splx(s);
}

int
timer_sysctl_set(int oid, uint64_t value)
{
	switch (oid) {
	case THRESHOLD:
		timer_call_cpu(
			master_cpu,
			(void (*)(void *)) timer_sysctl_set_threshold,
			(void *) value);
		return KERN_SUCCESS;
	default:
		return KERN_INVALID_ARGUMENT;
	}
}

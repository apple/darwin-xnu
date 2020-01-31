/*
 * Copyright (c) 2000-2010 Apple Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */
/*
 *	File:	priority.c
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1986
 *
 *	Priority related scheduler bits.
 */

#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/machine.h>
#include <kern/host.h>
#include <kern/mach_param.h>
#include <kern/sched.h>
#include <sys/kdebug.h>
#include <kern/spl.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/ledger.h>
#include <machine/machparam.h>
#include <kern/machine.h>

#ifdef CONFIG_MACH_APPROXIMATE_TIME
#include <machine/commpage.h>  /* for commpage_update_mach_approximate_time */
#endif

#if MONOTONIC
#include <kern/monotonic.h>
#endif /* MONOTONIC */

static void sched_update_thread_bucket(thread_t thread);

/*
 *	thread_quantum_expire:
 *
 *	Recalculate the quantum and priority for a thread.
 *
 *	Called at splsched.
 */

void
thread_quantum_expire(
	timer_call_param_t      p0,
	timer_call_param_t      p1)
{
	processor_t                     processor = p0;
	thread_t                        thread = p1;
	ast_t                           preempt;
	uint64_t                        ctime;

	assert(processor == current_processor());
	assert(thread == current_thread());

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_QUANTUM_EXPIRED) | DBG_FUNC_START, 0, 0, 0, 0, 0);

	SCHED_STATS_QUANTUM_TIMER_EXPIRATION(processor);

	/*
	 * We bill CPU time to both the individual thread and its task.
	 *
	 * Because this balance adjustment could potentially attempt to wake this
	 * very thread, we must credit the ledger before taking the thread lock.
	 * The ledger pointers are only manipulated by the thread itself at the ast
	 * boundary.
	 *
	 * TODO: This fails to account for the time between when the timer was
	 * armed and when it fired.  It should be based on the system_timer and
	 * running a timer_update operation here.
	 */
	ledger_credit(thread->t_ledger, task_ledgers.cpu_time, thread->quantum_remaining);
	ledger_credit(thread->t_threadledger, thread_ledgers.cpu_time, thread->quantum_remaining);
	if (thread->t_bankledger) {
		ledger_credit(thread->t_bankledger, bank_ledgers.cpu_time,
		    (thread->quantum_remaining - thread->t_deduct_bank_ledger_time));
	}
	thread->t_deduct_bank_ledger_time = 0;

	ctime = mach_absolute_time();

#ifdef CONFIG_MACH_APPROXIMATE_TIME
	commpage_update_mach_approximate_time(ctime);
#endif

#if MONOTONIC
	mt_sched_update(thread);
#endif /* MONOTONIC */

	thread_lock(thread);

	/*
	 * We've run up until our quantum expiration, and will (potentially)
	 * continue without re-entering the scheduler, so update this now.
	 */
	processor->last_dispatch = ctime;
	thread->last_run_time = ctime;

	/*
	 *	Check for fail-safe trip.
	 */
	if ((thread->sched_mode == TH_MODE_REALTIME || thread->sched_mode == TH_MODE_FIXED) &&
	    !(thread->sched_flags & TH_SFLAG_PROMOTED) &&
	    !(thread->sched_flags & TH_SFLAG_PROMOTE_REASON_MASK) &&
	    !(thread->options & TH_OPT_SYSTEM_CRITICAL)) {
		uint64_t new_computation;

		new_computation = ctime - thread->computation_epoch;
		new_computation += thread->computation_metered;
		if (new_computation > max_unsafe_computation) {
			KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_FAILSAFE) | DBG_FUNC_NONE,
			    (uintptr_t)thread->sched_pri, (uintptr_t)thread->sched_mode, 0, 0, 0);

			thread->safe_release = ctime + sched_safe_duration;

			sched_thread_mode_demote(thread, TH_SFLAG_FAILSAFE);
		}
	}

	/*
	 *	Recompute scheduled priority if appropriate.
	 */
	if (SCHED(can_update_priority)(thread)) {
		SCHED(update_priority)(thread);
	} else {
		SCHED(lightweight_update_priority)(thread);
	}

	if (thread->sched_mode != TH_MODE_REALTIME) {
		SCHED(quantum_expire)(thread);
	}

	/*
	 *	This quantum is up, give this thread another.
	 */
	processor->first_timeslice = FALSE;

	thread_quantum_init(thread);

	/* Reload precise timing global policy to thread-local policy */
	thread->precise_user_kernel_time = use_precise_user_kernel_time(thread);

	/*
	 * Since non-precise user/kernel time doesn't update the state/thread timer
	 * during privilege transitions, synthesize an event now.
	 */
	if (!thread->precise_user_kernel_time) {
		timer_update(PROCESSOR_DATA(processor, current_state), ctime);
		timer_update(PROCESSOR_DATA(processor, thread_timer), ctime);
		timer_update(&thread->runnable_timer, ctime);
	}


	processor->quantum_end = ctime + thread->quantum_remaining;

	/*
	 * Context switch check
	 *
	 * non-urgent flags don't affect kernel threads, so upgrade to urgent
	 * to ensure that rebalancing and non-recommendation kick in quickly.
	 */

	ast_t check_reason = AST_QUANTUM;
	if (thread->task == kernel_task) {
		check_reason |= AST_URGENT;
	}

	if ((preempt = csw_check(thread, processor, check_reason)) != AST_NONE) {
		ast_on(preempt);
	}

	/*
	 * AST_KEVENT does not send an IPI when setting the AST,
	 * to avoid waiting for the next context switch to propagate the AST,
	 * the AST is propagated here at quantum expiration.
	 */
	ast_propagate(thread);

	thread_unlock(thread);

	timer_call_quantum_timer_enter(&processor->quantum_timer, thread,
	    processor->quantum_end, ctime);

	/* Tell platform layer that we are still running this thread */
	thread_urgency_t urgency = thread_get_urgency(thread, NULL, NULL);
	machine_thread_going_on_core(thread, urgency, 0, 0, ctime);
	machine_switch_perfcontrol_state_update(QUANTUM_EXPIRY, ctime,
	    0, thread);

#if defined(CONFIG_SCHED_TIMESHARE_CORE)
	sched_timeshare_consider_maintenance(ctime);
#endif /* CONFIG_SCHED_TIMESHARE_CORE */

#if __arm__ || __arm64__
	if (thread->sched_mode == TH_MODE_REALTIME) {
		sched_consider_recommended_cores(ctime, thread);
	}
#endif /* __arm__ || __arm64__ */

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_QUANTUM_EXPIRED) | DBG_FUNC_END, preempt, 0, 0, 0, 0);
}

/*
 *	sched_set_thread_base_priority:
 *
 *	Set the base priority of the thread
 *	and reset its scheduled priority.
 *
 *	This is the only path to change base_pri.
 *
 *	Called with the thread locked.
 */
void
sched_set_thread_base_priority(thread_t thread, int priority)
{
	assert(priority >= MINPRI);
	uint64_t ctime = 0;

	if (thread->sched_mode == TH_MODE_REALTIME) {
		assert(priority <= BASEPRI_RTQUEUES);
	} else {
		assert(priority < BASEPRI_RTQUEUES);
	}

	int old_base_pri = thread->base_pri;
	thread->base_pri = priority;

	if ((thread->state & TH_RUN) == TH_RUN) {
		assert(thread->last_made_runnable_time != THREAD_NOT_RUNNABLE);
		ctime = mach_approximate_time();
		thread->last_basepri_change_time = ctime;
	} else {
		assert(thread->last_basepri_change_time == THREAD_NOT_RUNNABLE);
		assert(thread->last_made_runnable_time == THREAD_NOT_RUNNABLE);
	}

	/*
	 * Currently the perfcontrol_attr depends on the base pri of the
	 * thread. Therefore, we use this function as the hook for the
	 * perfcontrol callout.
	 */
	if (thread == current_thread() && old_base_pri != priority) {
		if (!ctime) {
			ctime = mach_approximate_time();
		}
		machine_switch_perfcontrol_state_update(PERFCONTROL_ATTR_UPDATE,
		    ctime, PERFCONTROL_CALLOUT_WAKE_UNSAFE, thread);
	}
	sched_update_thread_bucket(thread);

	thread_recompute_sched_pri(thread, SETPRI_DEFAULT);
}

/*
 *	thread_recompute_sched_pri:
 *
 *	Reset the scheduled priority of the thread
 *	according to its base priority if the
 *	thread has not been promoted or depressed.
 *
 *	This is the only way to push base_pri changes into sched_pri,
 *	or to recalculate the appropriate sched_pri after changing
 *	a promotion or depression.
 *
 *	Called at splsched with the thread locked.
 *
 *	TODO: Add an 'update urgency' flag to avoid urgency callouts on every rwlock operation
 */
void
thread_recompute_sched_pri(thread_t thread, set_sched_pri_options_t options)
{
	uint32_t     sched_flags = thread->sched_flags;
	sched_mode_t sched_mode  = thread->sched_mode;

	int priority = thread->base_pri;

	if (sched_mode == TH_MODE_TIMESHARE) {
		priority = SCHED(compute_timeshare_priority)(thread);
	}

	if (sched_flags & TH_SFLAG_DEPRESS) {
		/* thread_yield_internal overrides kernel mutex promotion */
		priority = DEPRESSPRI;
	} else {
		/* poll-depress is overridden by mutex promotion and promote-reasons */
		if ((sched_flags & TH_SFLAG_POLLDEPRESS)) {
			priority = DEPRESSPRI;
		}

		if (sched_flags & TH_SFLAG_PROMOTED) {
			priority = MAX(priority, thread->promotion_priority);

			if (sched_mode != TH_MODE_REALTIME) {
				priority = MIN(priority, MAXPRI_PROMOTE);
			}
		}

		if (sched_flags & TH_SFLAG_PROMOTE_REASON_MASK) {
			if (sched_flags & TH_SFLAG_RW_PROMOTED) {
				priority = MAX(priority, MINPRI_RWLOCK);
			}

			if (sched_flags & TH_SFLAG_WAITQ_PROMOTED) {
				priority = MAX(priority, MINPRI_WAITQ);
			}

			if (sched_flags & TH_SFLAG_EXEC_PROMOTED) {
				priority = MAX(priority, MINPRI_EXEC);
			}
		}
	}

	set_sched_pri(thread, priority, options);
}

void
sched_default_quantum_expire(thread_t thread __unused)
{
	/*
	 * No special behavior when a timeshare, fixed, or realtime thread
	 * uses up its entire quantum
	 */
}

#if defined(CONFIG_SCHED_TIMESHARE_CORE)

/*
 *	lightweight_update_priority:
 *
 *	Update the scheduled priority for
 *	a timesharing thread.
 *
 *	Only for use on the current thread.
 *
 *	Called with the thread locked.
 */
void
lightweight_update_priority(thread_t thread)
{
	assert(thread->runq == PROCESSOR_NULL);
	assert(thread == current_thread());

	if (thread->sched_mode == TH_MODE_TIMESHARE) {
		int priority;
		uint32_t delta;

		thread_timer_delta(thread, delta);

		/*
		 *	Accumulate timesharing usage only
		 *	during contention for processor
		 *	resources.
		 */
		if (thread->pri_shift < INT8_MAX) {
			thread->sched_usage += delta;
		}

		thread->cpu_delta += delta;

		priority = sched_compute_timeshare_priority(thread);

		if (priority != thread->sched_pri) {
			thread_recompute_sched_pri(thread, SETPRI_LAZY);
		}
	}
}

/*
 *	Define shifts for simulating (5/8) ** n
 *
 *	Shift structures for holding update shifts.  Actual computation
 *	is  usage = (usage >> shift1) +/- (usage >> abs(shift2))  where the
 *	+/- is determined by the sign of shift 2.
 */
struct shift_data {
	int     shift1;
	int     shift2;
};

#define SCHED_DECAY_TICKS       32
static struct shift_data        sched_decay_shifts[SCHED_DECAY_TICKS] = {
	{1, 1}, {1, 3}, {1, -3}, {2, -7}, {3, 5}, {3, -5}, {4, -8}, {5, 7},
	{5, -7}, {6, -10}, {7, 10}, {7, -9}, {8, -11}, {9, 12}, {9, -11}, {10, -13},
	{11, 14}, {11, -13}, {12, -15}, {13, 17}, {13, -15}, {14, -17}, {15, 19}, {16, 18},
	{16, -19}, {17, 22}, {18, 20}, {18, -20}, {19, 26}, {20, 22}, {20, -22}, {21, -27}
};

/*
 *	sched_compute_timeshare_priority:
 *
 *	Calculate the timesharing priority based upon usage and load.
 */
extern int sched_pri_decay_band_limit;

#ifdef CONFIG_EMBEDDED

int
sched_compute_timeshare_priority(thread_t thread)
{
	int decay_amount = (thread->sched_usage >> thread->pri_shift);
	int decay_limit = sched_pri_decay_band_limit;

	if (thread->base_pri > BASEPRI_FOREGROUND) {
		decay_limit += (thread->base_pri - BASEPRI_FOREGROUND);
	}

	if (decay_amount > decay_limit) {
		decay_amount = decay_limit;
	}

	/* start with base priority */
	int priority = thread->base_pri - decay_amount;

	if (priority < MAXPRI_THROTTLE) {
		if (thread->task->max_priority > MAXPRI_THROTTLE) {
			priority = MAXPRI_THROTTLE;
		} else if (priority < MINPRI_USER) {
			priority = MINPRI_USER;
		}
	} else if (priority > MAXPRI_KERNEL) {
		priority = MAXPRI_KERNEL;
	}

	return priority;
}

#else /* CONFIG_EMBEDDED */

int
sched_compute_timeshare_priority(thread_t thread)
{
	/* start with base priority */
	int priority = thread->base_pri - (thread->sched_usage >> thread->pri_shift);

	if (priority < MINPRI_USER) {
		priority = MINPRI_USER;
	} else if (priority > MAXPRI_KERNEL) {
		priority = MAXPRI_KERNEL;
	}

	return priority;
}

#endif /* CONFIG_EMBEDDED */

/*
 *	can_update_priority
 *
 *	Make sure we don't do re-dispatches more frequently than a scheduler tick.
 *
 *	Called with the thread locked.
 */
boolean_t
can_update_priority(
	thread_t        thread)
{
	if (sched_tick == thread->sched_stamp) {
		return FALSE;
	} else {
		return TRUE;
	}
}

/*
 *	update_priority
 *
 *	Perform housekeeping operations driven by scheduler tick.
 *
 *	Called with the thread locked.
 */
void
update_priority(
	thread_t        thread)
{
	uint32_t ticks, delta;

	ticks = sched_tick - thread->sched_stamp;
	assert(ticks != 0);

	thread->sched_stamp += ticks;

	/* If requested, accelerate aging of sched_usage */
	if (sched_decay_usage_age_factor > 1) {
		ticks *= sched_decay_usage_age_factor;
	}

	/*
	 *	Gather cpu usage data.
	 */
	thread_timer_delta(thread, delta);
	if (ticks < SCHED_DECAY_TICKS) {
		/*
		 *	Accumulate timesharing usage only during contention for processor
		 *	resources. Use the pri_shift from the previous tick window to
		 *	determine if the system was in a contended state.
		 */
		if (thread->pri_shift < INT8_MAX) {
			thread->sched_usage += delta;
		}

		thread->cpu_usage += delta + thread->cpu_delta;
		thread->cpu_delta = 0;

		struct shift_data *shiftp = &sched_decay_shifts[ticks];

		if (shiftp->shift2 > 0) {
			thread->cpu_usage =   (thread->cpu_usage >> shiftp->shift1) +
			    (thread->cpu_usage >> shiftp->shift2);
			thread->sched_usage = (thread->sched_usage >> shiftp->shift1) +
			    (thread->sched_usage >> shiftp->shift2);
		} else {
			thread->cpu_usage =   (thread->cpu_usage >>   shiftp->shift1) -
			    (thread->cpu_usage >> -(shiftp->shift2));
			thread->sched_usage = (thread->sched_usage >>   shiftp->shift1) -
			    (thread->sched_usage >> -(shiftp->shift2));
		}
	} else {
		thread->cpu_usage = thread->cpu_delta = 0;
		thread->sched_usage = 0;
	}

	/*
	 *	Check for fail-safe release.
	 */
	if ((thread->sched_flags & TH_SFLAG_FAILSAFE) &&
	    mach_absolute_time() >= thread->safe_release) {
		sched_thread_mode_undemote(thread, TH_SFLAG_FAILSAFE);
	}

	/*
	 * Now that the thread's CPU usage has been accumulated and aged
	 * based on contention of the previous tick window, update the
	 * pri_shift of the thread to match the current global load/shift
	 * values. The updated pri_shift would be used to calculate the
	 * new priority of the thread.
	 */
	thread->pri_shift = sched_pri_shifts[thread->th_sched_bucket];

	/* Recompute scheduled priority if appropriate. */
	if (thread->sched_mode == TH_MODE_TIMESHARE) {
		thread_recompute_sched_pri(thread, SETPRI_LAZY);
	}
}

#endif /* CONFIG_SCHED_TIMESHARE_CORE */


/*
 * TH_BUCKET_RUN is a count of *all* runnable non-idle threads.
 * Each other bucket is a count of the runnable non-idle threads
 * with that property.
 */
volatile uint32_t       sched_run_buckets[TH_BUCKET_MAX];

static void
sched_incr_bucket(sched_bucket_t bucket)
{
	assert(bucket >= TH_BUCKET_FIXPRI &&
	    bucket <= TH_BUCKET_SHARE_BG);

	hw_atomic_add(&sched_run_buckets[bucket], 1);
}

static void
sched_decr_bucket(sched_bucket_t bucket)
{
	assert(bucket >= TH_BUCKET_FIXPRI &&
	    bucket <= TH_BUCKET_SHARE_BG);

	assert(sched_run_buckets[bucket] > 0);

	hw_atomic_sub(&sched_run_buckets[bucket], 1);
}

/* TH_RUN & !TH_IDLE controls whether a thread has a run count */

uint32_t
sched_run_incr(thread_t thread)
{
	assert((thread->state & (TH_RUN | TH_IDLE)) == TH_RUN);

	uint32_t new_count = hw_atomic_add(&sched_run_buckets[TH_BUCKET_RUN], 1);

	sched_incr_bucket(thread->th_sched_bucket);

	return new_count;
}

uint32_t
sched_run_decr(thread_t thread)
{
	assert((thread->state & (TH_RUN | TH_IDLE)) != TH_RUN);

	sched_decr_bucket(thread->th_sched_bucket);

	uint32_t new_count = hw_atomic_sub(&sched_run_buckets[TH_BUCKET_RUN], 1);

	return new_count;
}

static void
sched_update_thread_bucket(thread_t thread)
{
	sched_bucket_t old_bucket = thread->th_sched_bucket;
	sched_bucket_t new_bucket = TH_BUCKET_RUN;

	switch (thread->sched_mode) {
	case TH_MODE_FIXED:
	case TH_MODE_REALTIME:
		new_bucket = TH_BUCKET_FIXPRI;
		break;

	case TH_MODE_TIMESHARE:
		if (thread->base_pri > BASEPRI_DEFAULT) {
			new_bucket = TH_BUCKET_SHARE_FG;
		} else if (thread->base_pri > BASEPRI_UTILITY) {
			new_bucket = TH_BUCKET_SHARE_DF;
		} else if (thread->base_pri > MAXPRI_THROTTLE) {
			new_bucket = TH_BUCKET_SHARE_UT;
		} else {
			new_bucket = TH_BUCKET_SHARE_BG;
		}
		break;

	default:
		panic("unexpected mode: %d", thread->sched_mode);
		break;
	}

	if (old_bucket != new_bucket) {
		thread->th_sched_bucket = new_bucket;
		thread->pri_shift = sched_pri_shifts[new_bucket];

		if ((thread->state & (TH_RUN | TH_IDLE)) == TH_RUN) {
			sched_decr_bucket(old_bucket);
			sched_incr_bucket(new_bucket);
		}
	}
}

/*
 * Set the thread's true scheduling mode
 * Called with thread mutex and thread locked
 * The thread has already been removed from the runqueue.
 *
 * (saved_mode is handled before this point)
 */
void
sched_set_thread_mode(thread_t thread, sched_mode_t new_mode)
{
	assert(thread->runq == PROCESSOR_NULL);

	switch (new_mode) {
	case TH_MODE_FIXED:
	case TH_MODE_REALTIME:
	case TH_MODE_TIMESHARE:
		break;

	default:
		panic("unexpected mode: %d", new_mode);
		break;
	}

	thread->sched_mode = new_mode;

	sched_update_thread_bucket(thread);
}

/*
 * Demote the true scheduler mode to timeshare (called with the thread locked)
 */
void
sched_thread_mode_demote(thread_t thread, uint32_t reason)
{
	assert(reason & TH_SFLAG_DEMOTED_MASK);
	assert((thread->sched_flags & reason) != reason);

	if (thread->policy_reset) {
		return;
	}

	if (thread->sched_flags & TH_SFLAG_DEMOTED_MASK) {
		/* Another demotion reason is already active */
		thread->sched_flags |= reason;
		return;
	}

	assert(thread->saved_mode == TH_MODE_NONE);

	boolean_t removed = thread_run_queue_remove(thread);

	thread->sched_flags |= reason;

	thread->saved_mode = thread->sched_mode;

	sched_set_thread_mode(thread, TH_MODE_TIMESHARE);

	thread_recompute_priority(thread);

	if (removed) {
		thread_run_queue_reinsert(thread, SCHED_TAILQ);
	}
}

/*
 * Un-demote the true scheduler mode back to the saved mode (called with the thread locked)
 */
void
sched_thread_mode_undemote(thread_t thread, uint32_t reason)
{
	assert(reason & TH_SFLAG_DEMOTED_MASK);
	assert((thread->sched_flags & reason) == reason);
	assert(thread->saved_mode != TH_MODE_NONE);
	assert(thread->sched_mode == TH_MODE_TIMESHARE);
	assert(thread->policy_reset == 0);

	thread->sched_flags &= ~reason;

	if (thread->sched_flags & TH_SFLAG_DEMOTED_MASK) {
		/* Another demotion reason is still active */
		return;
	}

	boolean_t removed = thread_run_queue_remove(thread);

	sched_set_thread_mode(thread, thread->saved_mode);

	thread->saved_mode = TH_MODE_NONE;

	thread_recompute_priority(thread);

	if (removed) {
		thread_run_queue_reinsert(thread, SCHED_TAILQ);
	}
}

/*
 * Promote thread to a specific priority
 *
 * Promotion must not last past syscall boundary
 * Clients must always pair promote and unpromote 1:1
 *
 * Called at splsched with thread locked
 */
void
sched_thread_promote_to_pri(thread_t    thread,
    int         priority,
    __kdebug_only uintptr_t   trace_obj /* already unslid */)
{
	assert((thread->sched_flags & TH_SFLAG_PROMOTED) != TH_SFLAG_PROMOTED);
	assert(thread->promotion_priority == 0);
	assert(priority <= MAXPRI_PROMOTE);
	assert(priority > 0);

	KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_PROMOTED),
	    thread_tid(thread), trace_obj, priority);

	thread->sched_flags |= TH_SFLAG_PROMOTED;
	thread->promotion_priority = priority;

	thread_recompute_sched_pri(thread, SETPRI_DEFAULT);
}


/*
 * Update a pre-existing priority promotion to have a higher priority floor
 * Priority can only go up from the previous value
 * Update must occur while a promotion is active
 *
 * Called at splsched with thread locked
 */
void
sched_thread_update_promotion_to_pri(thread_t   thread,
    int        priority,
    __kdebug_only uintptr_t  trace_obj /* already unslid */)
{
	assert(thread->promotions > 0);
	assert((thread->sched_flags & TH_SFLAG_PROMOTED) == TH_SFLAG_PROMOTED);
	assert(thread->promotion_priority > 0);
	assert(priority <= MAXPRI_PROMOTE);

	if (thread->promotion_priority < priority) {
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_PROMOTED_UPDATE),
		    thread_tid(thread), trace_obj, priority);

		thread->promotion_priority = priority;
		thread_recompute_sched_pri(thread, SETPRI_DEFAULT);
	}
}

/*
 * End a priority promotion
 * Demotes a thread back to its expected priority without the promotion in place
 *
 * Called at splsched with thread locked
 */
void
sched_thread_unpromote(thread_t     thread,
    __kdebug_only uintptr_t    trace_obj /* already unslid */)
{
	assert((thread->sched_flags & TH_SFLAG_PROMOTED) == TH_SFLAG_PROMOTED);
	assert(thread->promotion_priority > 0);

	KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_UNPROMOTED),
	    thread_tid(thread), trace_obj, 0);

	thread->sched_flags &= ~TH_SFLAG_PROMOTED;
	thread->promotion_priority = 0;

	thread_recompute_sched_pri(thread, SETPRI_DEFAULT);
}

/* called with thread locked */
void
assert_promotions_invariant(thread_t thread)
{
	if (thread->promotions > 0) {
		assert((thread->sched_flags & TH_SFLAG_PROMOTED) == TH_SFLAG_PROMOTED);
	}

	if (thread->promotions == 0) {
		assert((thread->sched_flags & TH_SFLAG_PROMOTED) != TH_SFLAG_PROMOTED);
	}
}

/*
 * Promote thread to have a sched pri floor for a specific reason
 *
 * Promotion must not last past syscall boundary
 * Clients must always pair promote and demote 1:1,
 * Handling nesting of the same promote reason is the client's responsibility
 *
 * Called at splsched with thread locked
 */
void
sched_thread_promote_reason(thread_t    thread,
    uint32_t    reason,
    __kdebug_only uintptr_t   trace_obj /* already unslid */)
{
	assert(reason & TH_SFLAG_PROMOTE_REASON_MASK);
	assert((thread->sched_flags & reason) != reason);

	switch (reason) {
	case TH_SFLAG_RW_PROMOTED:
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_RW_PROMOTE),
		    thread_tid(thread), thread->sched_pri,
		    thread->base_pri, trace_obj);
		break;
	case TH_SFLAG_WAITQ_PROMOTED:
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_WAITQ_PROMOTE),
		    thread_tid(thread), thread->sched_pri,
		    thread->base_pri, trace_obj);
		break;
	case TH_SFLAG_EXEC_PROMOTED:
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_EXEC_PROMOTE),
		    thread_tid(thread), thread->sched_pri,
		    thread->base_pri, trace_obj);
		break;
	}

	thread->sched_flags |= reason;

	thread_recompute_sched_pri(thread, SETPRI_DEFAULT);
}

/*
 * End a specific promotion reason
 * Demotes a thread back to its expected priority without the promotion in place
 *
 * Called at splsched with thread locked
 */
void
sched_thread_unpromote_reason(thread_t  thread,
    uint32_t  reason,
    __kdebug_only uintptr_t trace_obj /* already unslid */)
{
	assert(reason & TH_SFLAG_PROMOTE_REASON_MASK);
	assert((thread->sched_flags & reason) == reason);

	switch (reason) {
	case TH_SFLAG_RW_PROMOTED:
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_RW_DEMOTE),
		    thread_tid(thread), thread->sched_pri,
		    thread->base_pri, trace_obj);
		break;
	case TH_SFLAG_WAITQ_PROMOTED:
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_WAITQ_DEMOTE),
		    thread_tid(thread), thread->sched_pri,
		    thread->base_pri, trace_obj);
		break;
	case TH_SFLAG_EXEC_PROMOTED:
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_EXEC_DEMOTE),
		    thread_tid(thread), thread->sched_pri,
		    thread->base_pri, trace_obj);
		break;
	}

	thread->sched_flags &= ~reason;

	thread_recompute_sched_pri(thread, SETPRI_DEFAULT);
}

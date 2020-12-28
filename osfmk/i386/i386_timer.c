/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
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
 * @APPLE_FREE_COPYRIGHT@
 */
/*
 *	File:		timer.c
 *	Purpose:	Routines for handling the machine independent timer.
 */

#include <mach/mach_types.h>

#include <kern/timer_queue.h>
#include <kern/timer_call.h>
#include <kern/clock.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/macro_help.h>
#include <kern/spl.h>
#include <kern/timer_queue.h>
#include <kern/pms.h>

#include <machine/commpage.h>
#include <machine/machine_routines.h>

#include <sys/kdebug.h>
#include <i386/cpu_data.h>
#include <i386/cpu_topology.h>
#include <i386/cpu_threads.h>

uint32_t spurious_timers;

/*
 *      Event timer interrupt.
 *
 * XXX a drawback of this implementation is that events serviced earlier must not set deadlines
 *     that occur before the entire chain completes.
 *
 * XXX a better implementation would use a set of generic callouts and iterate over them
 */
void
timer_intr(int          user_mode,
    uint64_t    rip)
{
	uint64_t                abstime;
	rtclock_timer_t         *mytimer;
	cpu_data_t              *pp;
	int64_t                 latency;
	uint64_t                pmdeadline;
	boolean_t               timer_processed = FALSE;

	pp = current_cpu_datap();

	SCHED_STATS_TIMER_POP(current_processor());

	abstime = mach_absolute_time();         /* Get the time now */

	/* has a pending clock timer expired? */
	mytimer = &pp->rtclock_timer;           /* Point to the event timer */

	if ((timer_processed = ((mytimer->deadline <= abstime) ||
	    (abstime >= (mytimer->queue.earliest_soft_deadline))))) {
		/*
		 * Log interrupt service latency (-ve value expected by tool)
		 * a non-PM event is expected next.
		 * The requested deadline may be earlier than when it was set
		 * - use MAX to avoid reporting bogus latencies.
		 */
		latency = (int64_t) (abstime - MAX(mytimer->deadline,
		    mytimer->when_set));
		/* Log zero timer latencies when opportunistically processing
		 * coalesced timers.
		 */
		if (latency < 0) {
			TCOAL_DEBUG(0xEEEE0000, abstime, mytimer->queue.earliest_soft_deadline, abstime - mytimer->queue.earliest_soft_deadline, 0, 0);
			latency = 0;
		}

		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		    DECR_TRAP_LATENCY | DBG_FUNC_NONE,
		    -latency,
		    ((user_mode != 0) ? rip : VM_KERNEL_UNSLIDE(rip)),
		    user_mode, 0, 0);

		mytimer->has_expired = TRUE;    /* Remember that we popped */
		mytimer->deadline = timer_queue_expire(&mytimer->queue, abstime);
		mytimer->has_expired = FALSE;

		/* Get the time again since we ran a bit */
		abstime = mach_absolute_time();
		mytimer->when_set = abstime;
	}

	/* is it time for power management state change? */
	if ((pmdeadline = pmCPUGetDeadline(pp)) && (pmdeadline <= abstime)) {
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		    DECR_PM_DEADLINE | DBG_FUNC_START,
		    0, 0, 0, 0, 0);
		pmCPUDeadline(pp);
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		    DECR_PM_DEADLINE | DBG_FUNC_END,
		    0, 0, 0, 0, 0);
		timer_processed = TRUE;
		abstime = mach_absolute_time(); /* Get the time again since we ran a bit */
	}

	uint64_t quantum_deadline = pp->quantum_timer_deadline;
	/* is it the quantum timer expiration? */
	if ((quantum_deadline <= abstime) && (quantum_deadline > 0)) {
		pp->quantum_timer_deadline = 0;
		quantum_timer_expire(abstime);
	}

	/* schedule our next deadline */
	x86_lcpu()->rtcDeadline = EndOfAllTime;
	timer_resync_deadlines();

	if (__improbable(timer_processed == FALSE)) {
		spurious_timers++;
	}
}

/*
 * Set the clock deadline.
 */
void
timer_set_deadline(uint64_t deadline)
{
	rtclock_timer_t         *mytimer;
	spl_t                   s;
	cpu_data_t              *pp;

	s = splclock();                         /* no interruptions */
	pp = current_cpu_datap();

	mytimer = &pp->rtclock_timer;           /* Point to the timer itself */
	mytimer->deadline = deadline;           /* Set new expiration time */
	mytimer->when_set = mach_absolute_time();

	timer_resync_deadlines();

	splx(s);
}

void
quantum_timer_set_deadline(uint64_t deadline)
{
	cpu_data_t              *pp;
	/* We should've only come into this path with interrupts disabled */
	assert(ml_get_interrupts_enabled() == FALSE);

	pp = current_cpu_datap();
	pp->quantum_timer_deadline = deadline;
	timer_resync_deadlines();
}

/*
 * Re-evaluate the outstanding deadlines and select the most proximate.
 *
 * Should be called at splclock.
 */
void
timer_resync_deadlines(void)
{
	uint64_t                deadline = EndOfAllTime;
	uint64_t                pmdeadline;
	uint64_t                quantum_deadline;
	rtclock_timer_t         *mytimer;
	spl_t                   s = splclock();
	cpu_data_t              *pp;
	uint32_t                decr;

	pp = current_cpu_datap();
	if (!pp->cpu_running) {
		/* There's really nothing to do if this processor is down */
		return;
	}

	/*
	 * If we have a clock timer set, pick that.
	 */
	mytimer = &pp->rtclock_timer;
	if (!mytimer->has_expired &&
	    0 < mytimer->deadline && mytimer->deadline < EndOfAllTime) {
		deadline = mytimer->deadline;
	}

	/*
	 * If we have a power management deadline, see if that's earlier.
	 */
	pmdeadline = pmCPUGetDeadline(pp);
	if (0 < pmdeadline && pmdeadline < deadline) {
		deadline = pmdeadline;
	}

	/* If we have the quantum timer setup, check that */
	quantum_deadline = pp->quantum_timer_deadline;
	if ((quantum_deadline > 0) &&
	    (quantum_deadline < deadline)) {
		deadline = quantum_deadline;
	}


	/*
	 * Go and set the "pop" event.
	 */
	decr = (uint32_t) setPop(deadline);

	/* Record non-PM deadline for latency tool */
	if (decr != 0 && deadline != pmdeadline) {
		uint64_t queue_count = 0;
		if (deadline != quantum_deadline) {
			/*
			 * For non-quantum timer put the queue count
			 * in the tracepoint.
			 */
			queue_count = mytimer->queue.count;
		}
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		    DECR_SET_DEADLINE | DBG_FUNC_NONE,
		    decr, 2,
		    deadline,
		    queue_count, 0);
	}
	splx(s);
}

void
timer_queue_expire_local(
	__unused void                   *arg)
{
	rtclock_timer_t         *mytimer;
	uint64_t                        abstime;
	cpu_data_t                      *pp;

	pp = current_cpu_datap();

	mytimer = &pp->rtclock_timer;
	abstime = mach_absolute_time();

	mytimer->has_expired = TRUE;
	mytimer->deadline = timer_queue_expire(&mytimer->queue, abstime);
	mytimer->has_expired = FALSE;
	mytimer->when_set = mach_absolute_time();

	timer_resync_deadlines();
}

void
timer_queue_expire_rescan(
	__unused void                   *arg)
{
	rtclock_timer_t         *mytimer;
	uint64_t                abstime;
	cpu_data_t              *pp;

	assert(ml_get_interrupts_enabled() == FALSE);
	pp = current_cpu_datap();

	mytimer = &pp->rtclock_timer;
	abstime = mach_absolute_time();

	mytimer->has_expired = TRUE;
	mytimer->deadline = timer_queue_expire_with_options(&mytimer->queue, abstime, TRUE);
	mytimer->has_expired = FALSE;
	mytimer->when_set = mach_absolute_time();

	timer_resync_deadlines();
}

#define TIMER_RESORT_THRESHOLD_ABSTIME (50 * NSEC_PER_MSEC)

#if TCOAL_PRIO_STATS
int32_t nc_tcl, rt_tcl, bg_tcl, kt_tcl, fp_tcl, ts_tcl, qos_tcl;
#define TCOAL_PRIO_STAT(x) (x++)
#else
#define TCOAL_PRIO_STAT(x)
#endif

boolean_t
timer_resort_threshold(uint64_t skew)
{
	if (skew >= TIMER_RESORT_THRESHOLD_ABSTIME) {
		return TRUE;
	} else {
		return FALSE;
	}
}

/*
 * Return the local timer queue for a running processor
 * else return the boot processor's timer queue.
 */
mpqueue_head_t *
timer_queue_assign(
	uint64_t        deadline)
{
	cpu_data_t              *cdp = current_cpu_datap();
	mpqueue_head_t          *queue;

	if (cdp->cpu_running) {
		queue = &cdp->rtclock_timer.queue;

		if (deadline < cdp->rtclock_timer.deadline) {
			timer_set_deadline(deadline);
		}
	} else {
		queue = &cpu_datap(master_cpu)->rtclock_timer.queue;
	}

	return queue;
}

void
timer_queue_cancel(
	mpqueue_head_t  *queue,
	uint64_t        deadline,
	uint64_t        new_deadline)
{
	if (queue == &current_cpu_datap()->rtclock_timer.queue) {
		if (deadline < new_deadline) {
			timer_set_deadline(new_deadline);
		}
	}
}

/*
 * timer_queue_migrate_cpu() is called from the Power-Management kext
 * when a logical processor goes idle (in a deep C-state) with a distant
 * deadline so that it's timer queue can be moved to another processor.
 * This target processor should be the least idle (most busy) --
 * currently this is the primary processor for the calling thread's package.
 * Locking restrictions demand that the target cpu must be the boot cpu.
 */
uint32_t
timer_queue_migrate_cpu(int target_cpu)
{
	cpu_data_t      *target_cdp = cpu_datap(target_cpu);
	cpu_data_t      *cdp = current_cpu_datap();
	int             ntimers_moved;

	assert(!ml_get_interrupts_enabled());
	assert(target_cpu != cdp->cpu_number);
	assert(target_cpu == master_cpu);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    DECR_TIMER_MIGRATE | DBG_FUNC_START,
	    target_cpu,
	    cdp->rtclock_timer.deadline, (cdp->rtclock_timer.deadline >> 32),
	    0, 0);

	/*
	 * Move timer requests from the local queue to the target processor's.
	 * The return value is the number of requests moved. If this is 0,
	 * it indicates that the first (i.e. earliest) timer is earlier than
	 * the earliest for the target processor. Since this would force a
	 * resync, the move of this and all later requests is aborted.
	 */
	ntimers_moved = timer_queue_migrate(&cdp->rtclock_timer.queue,
	    &target_cdp->rtclock_timer.queue);

	/*
	 * Assuming we moved stuff, clear local deadline.
	 */
	if (ntimers_moved > 0) {
		cdp->rtclock_timer.deadline = EndOfAllTime;
		setPop(EndOfAllTime);
	}

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    DECR_TIMER_MIGRATE | DBG_FUNC_END,
	    target_cpu, ntimers_moved, 0, 0, 0);

	return ntimers_moved;
}

mpqueue_head_t *
timer_queue_cpu(int cpu)
{
	return &cpu_datap(cpu)->rtclock_timer.queue;
}

void
timer_call_cpu(int cpu, void (*fn)(void *), void *arg)
{
	mp_cpus_call(cpu_to_cpumask(cpu), SYNC, fn, arg);
}

void
timer_call_nosync_cpu(int cpu, void (*fn)(void *), void *arg)
{
	/* XXX Needs error checking and retry */
	mp_cpus_call(cpu_to_cpumask(cpu), NOSYNC, fn, arg);
}


static timer_coalescing_priority_params_ns_t tcoal_prio_params_init =
{
	.idle_entry_timer_processing_hdeadline_threshold_ns = 5000ULL * NSEC_PER_USEC,
	.interrupt_timer_coalescing_ilat_threshold_ns = 30ULL * NSEC_PER_USEC,
	.timer_resort_threshold_ns = 50 * NSEC_PER_MSEC,
	.timer_coalesce_rt_shift = 0,
	.timer_coalesce_bg_shift = -5,
	.timer_coalesce_kt_shift = 3,
	.timer_coalesce_fp_shift = 3,
	.timer_coalesce_ts_shift = 3,
	.timer_coalesce_rt_ns_max = 0ULL,
	.timer_coalesce_bg_ns_max = 100 * NSEC_PER_MSEC,
	.timer_coalesce_kt_ns_max = 1 * NSEC_PER_MSEC,
	.timer_coalesce_fp_ns_max = 1 * NSEC_PER_MSEC,
	.timer_coalesce_ts_ns_max = 1 * NSEC_PER_MSEC,
	.latency_qos_scale = {3, 2, 1, -2, -15, -15},
	.latency_qos_ns_max = {1 * NSEC_PER_MSEC, 5 * NSEC_PER_MSEC, 20 * NSEC_PER_MSEC,
		               75 * NSEC_PER_MSEC, 10000 * NSEC_PER_MSEC, 10000 * NSEC_PER_MSEC},
	.latency_tier_rate_limited = {FALSE, FALSE, FALSE, FALSE, TRUE, TRUE},
};

timer_coalescing_priority_params_ns_t *
timer_call_get_priority_params(void)
{
	return &tcoal_prio_params_init;
}

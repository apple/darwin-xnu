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
 *	File:		etimer.c
 *	Purpose:	Routines for handling the machine independent
 *				event timer.
 */

#include <mach/mach_types.h>

#include <kern/timer_queue.h>
#include <kern/clock.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/macro_help.h>
#include <kern/spl.h>
#include <kern/etimer.h>
#include <kern/pms.h>

#include <machine/commpage.h>
#include <machine/machine_routines.h>

#include <sys/kdebug.h>
#include <i386/cpu_data.h>
#include <i386/cpu_topology.h>
#include <i386/cpu_threads.h>

/*
 * 	Event timer interrupt.
 *
 * XXX a drawback of this implementation is that events serviced earlier must not set deadlines
 *     that occur before the entire chain completes.
 *
 * XXX a better implementation would use a set of generic callouts and iterate over them
 */
void
etimer_intr(int		user_mode,
	    uint64_t	rip)
{
	uint64_t		abstime;
	rtclock_timer_t		*mytimer;
	cpu_data_t		*pp;
	int32_t			latency;
	uint64_t		pmdeadline;

	pp = current_cpu_datap();

	SCHED_STATS_TIMER_POP(current_processor());

	abstime = mach_absolute_time();		/* Get the time now */

	/* has a pending clock timer expired? */
	mytimer = &pp->rtclock_timer;		/* Point to the event timer */
	if (mytimer->deadline <= abstime) {
		/*
		 * Log interrupt service latency (-ve value expected by tool)
		 * a non-PM event is expected next.
		 * The requested deadline may be earlier than when it was set 
		 * - use MAX to avoid reporting bogus latencies.
		 */
		latency = (int32_t) (abstime - MAX(mytimer->deadline,
						   mytimer->when_set));
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
			DECR_TRAP_LATENCY | DBG_FUNC_NONE,
			-latency,
			((user_mode != 0) ? rip : VM_KERNEL_UNSLIDE(rip)),
			user_mode, 0, 0);

		mytimer->has_expired = TRUE;	/* Remember that we popped */
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
	}

	/* schedule our next deadline */
	etimer_resync_deadlines();
}

/*
 * Set the clock deadline.
 */
void etimer_set_deadline(uint64_t deadline)
{
	rtclock_timer_t		*mytimer;
	spl_t			s;
	cpu_data_t		*pp;

	s = splclock();				/* no interruptions */
	pp = current_cpu_datap();

	mytimer = &pp->rtclock_timer;		/* Point to the timer itself */
	mytimer->deadline = deadline;		/* Set new expiration time */
	mytimer->when_set = mach_absolute_time();

	etimer_resync_deadlines();

	splx(s);
}

/*
 * Re-evaluate the outstanding deadlines and select the most proximate.
 *
 * Should be called at splclock.
 */
void
etimer_resync_deadlines(void)
{
	uint64_t		deadline = EndOfAllTime;
	uint64_t		pmdeadline;
	rtclock_timer_t		*mytimer;
	spl_t			s = splclock();
	cpu_data_t		*pp;
	uint32_t		decr;

	pp = current_cpu_datap();
	if (!pp->cpu_running)
		/* There's really nothing to do if this procesor is down */
		return;

	/*
	 * If we have a clock timer set, pick that.
	 */
	mytimer = &pp->rtclock_timer;
	if (!mytimer->has_expired &&
	    0 < mytimer->deadline && mytimer->deadline < EndOfAllTime)
		deadline = mytimer->deadline;

	/*
	 * If we have a power management deadline, see if that's earlier.
	 */
	pmdeadline = pmCPUGetDeadline(pp);
	if (0 < pmdeadline && pmdeadline < deadline)
		deadline = pmdeadline;

	/*
	 * Go and set the "pop" event.
	 */
	decr = (uint32_t) setPop(deadline);

	/* Record non-PM deadline for latency tool */
	if (deadline != pmdeadline) {
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
			DECR_SET_DEADLINE | DBG_FUNC_NONE,
			decr, 2,
			deadline, (uint32_t)(deadline >> 32), 0);
	}
	splx(s);
}

void etimer_timer_expire(void	*arg);

void
etimer_timer_expire(
__unused void			*arg)
{
	rtclock_timer_t		*mytimer;
	uint64_t			abstime;
	cpu_data_t			*pp;

	pp = current_cpu_datap();

	mytimer = &pp->rtclock_timer;
	abstime = mach_absolute_time();

	mytimer->has_expired = TRUE;
	mytimer->deadline = timer_queue_expire(&mytimer->queue, abstime);
	mytimer->has_expired = FALSE;
	mytimer->when_set = mach_absolute_time();

	etimer_resync_deadlines();
}

uint64_t	
timer_call_slop(
	uint64_t	deadline)
{
	uint64_t now = mach_absolute_time();
	if (deadline > now) {
		return MIN((deadline - now) >> 3, NSEC_PER_MSEC); /* Min of 12.5% and 1ms */
	}

	return 0;
}

mpqueue_head_t *
timer_queue_assign(
    uint64_t        deadline)
{
	cpu_data_t			*cdp = current_cpu_datap();
	mpqueue_head_t		*queue;

	if (cdp->cpu_running) {
		queue = &cdp->rtclock_timer.queue;

		if (deadline < cdp->rtclock_timer.deadline)
			etimer_set_deadline(deadline);
	}
	else
		queue = &cpu_datap(master_cpu)->rtclock_timer.queue;

    return (queue);
}

void
timer_queue_cancel(
    mpqueue_head_t  *queue,
    uint64_t        deadline,
    uint64_t        new_deadline)
{
    if (queue == &current_cpu_datap()->rtclock_timer.queue) {
        if (deadline < new_deadline)
            etimer_set_deadline(new_deadline);
    }
}

/*
 * etimer_queue_migrate() is called from the Power-Management kext
 * when a logical processor goes idle (in a deep C-state) with a distant
 * deadline so that it's timer queue can be moved to another processor.
 * This target processor should be the least idle (most busy) --
 * currently this is the primary processor for the calling thread's package.
 * Locking restrictions demand that the target cpu must be the boot cpu.
 */
uint32_t
etimer_queue_migrate(int target_cpu)
{
	cpu_data_t	*target_cdp = cpu_datap(target_cpu);
	cpu_data_t	*cdp = current_cpu_datap();
	int		ntimers_moved;

	assert(!ml_get_interrupts_enabled());
	assert(target_cpu != cdp->cpu_number);
	assert(target_cpu == master_cpu);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		DECR_TIMER_MIGRATE | DBG_FUNC_START,
		target_cpu,
		cdp->rtclock_timer.deadline, (cdp->rtclock_timer.deadline >>32),
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

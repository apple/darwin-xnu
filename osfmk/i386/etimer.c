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
etimer_intr(
__unused int inuser,
__unused uint64_t iaddr)
{
	uint64_t		abstime;
	rtclock_timer_t		*mytimer;
	cpu_data_t		*pp;
	x86_lcpu_t		*lcpu;

	pp = current_cpu_datap();
	lcpu = x86_lcpu();

	mytimer = &pp->rtclock_timer;				/* Point to the event timer */
	abstime = mach_absolute_time();				/* Get the time now */

	/* is it time for power management state change? */	
	if (pmCPUGetDeadline(pp) <= abstime) {
	        KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_DECI, 3) | DBG_FUNC_START, 0, 0, 0, 0, 0);
		pmCPUDeadline(pp);
	        KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_DECI, 3) | DBG_FUNC_END, 0, 0, 0, 0, 0);

		abstime = mach_absolute_time();			/* Get the time again since we ran a bit */
	}

	/* has a pending clock timer expired? */
	if (mytimer->deadline <= abstime) {			/* Have we expired the deadline? */
		mytimer->has_expired = TRUE;			/* Remember that we popped */
		mytimer->deadline = timer_queue_expire(&mytimer->queue, abstime);
		mytimer->has_expired = FALSE;
	}

	/* schedule our next deadline */
	lcpu->rtcPop = EndOfAllTime;				/* any real deadline will be earlier */
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

	s = splclock();					/* no interruptions */
	pp = current_cpu_datap();

	mytimer = &pp->rtclock_timer;			/* Point to the timer itself */
	mytimer->deadline = deadline;			/* Set the new expiration time */

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
	uint64_t		deadline;
	uint64_t		pmdeadline;
	rtclock_timer_t		*mytimer;
	spl_t			s = splclock();
	cpu_data_t		*pp;
	x86_lcpu_t		*lcpu;

	pp = current_cpu_datap();
	lcpu = x86_lcpu();
	deadline = ~0ULL;

	/*
	 * If we have a clock timer set sooner, pop on that.
	 */
	mytimer = &pp->rtclock_timer;
	if (!mytimer->has_expired && mytimer->deadline > 0)
		deadline = mytimer->deadline;

	/*
	 * If we have a power management deadline, see if that's earlier.
	 */
	pmdeadline = pmCPUGetDeadline(pp);
	if (pmdeadline > 0 && pmdeadline < deadline)
	    deadline = pmdeadline;

	/*
	 * Go and set the "pop" event.
	 */
	if (deadline > 0) {
		int     decr;
		uint64_t now;

		now = mach_absolute_time();
		decr = setPop(deadline);

		if (deadline < now)
		        lcpu->rtcPop = now + decr;
		else
		        lcpu->rtcPop = deadline;

		lcpu->rtcDeadline = lcpu->rtcPop;

		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_DECI, 1) | DBG_FUNC_NONE, decr, 2, 0, 0, 0);
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
	x86_lcpu_t			*lcpu;

	pp = current_cpu_datap();
	lcpu = x86_lcpu();

	mytimer = &pp->rtclock_timer;
	abstime = mach_absolute_time();

	mytimer->has_expired = TRUE;
	mytimer->deadline = timer_queue_expire(&mytimer->queue, abstime);
	mytimer->has_expired = FALSE;

	lcpu->rtcPop = EndOfAllTime;
	etimer_resync_deadlines();
}

queue_t
timer_queue_assign(
    uint64_t        deadline)
{
	cpu_data_t			*cdp = current_cpu_datap();
	rtclock_timer_t		*timer;

	if (cdp->cpu_running) {
		timer = &cdp->rtclock_timer;

		if (deadline < timer->deadline)
			etimer_set_deadline(deadline);
	}
	else
		timer = &cpu_datap(master_cpu)->rtclock_timer;

    return (&timer->queue);
}

void
timer_queue_cancel(
    queue_t         queue,
    uint64_t        deadline,
    uint64_t        new_deadline)
{
    if (queue == &current_cpu_datap()->rtclock_timer.queue) {
        if (deadline < new_deadline)
            etimer_set_deadline(new_deadline);
    }
}

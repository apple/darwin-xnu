/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
#include <ppc/exception.h>

/* XXX from <arch>/rtclock.c */
clock_timer_func_t		rtclock_timer_expire;

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
	struct per_proc_info	*pp;

	pp = getPerProc();

	mytimer = &pp->rtclock_timer;				/* Point to the event timer */

	abstime = mach_absolute_time();				/* Get the time now */

	/* is it time for power management state change? */	
	if (pp->pms.pmsPop <= abstime) {
	        KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_DECI, 3) | DBG_FUNC_START, 0, 0, 0, 0, 0);
		pmsStep(1);					/* Yes, advance step */
	        KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_DECI, 3) | DBG_FUNC_END, 0, 0, 0, 0, 0);

		abstime = mach_absolute_time();			/* Get the time again since we ran a bit */
	}

	/* has a pending clock timer expired? */
	if (mytimer->deadline <= abstime) {			/* Have we expired the deadline? */
		mytimer->has_expired = TRUE;			/* Remember that we popped */
		mytimer->deadline = EndOfAllTime;		/* Set timer request to the end of all time in case we have no more events */
		(*rtclock_timer_expire)(abstime);		/* Process pop */
		mytimer->has_expired = FALSE;
	}

	/* schedule our next deadline */
	pp->rtcPop = EndOfAllTime;				/* any real deadline will be earlier */
	etimer_resync_deadlines();
}

/*
 * Set the clock deadline; called by the thread scheduler.
 */
void etimer_set_deadline(uint64_t deadline)
{
	rtclock_timer_t		*mytimer;
	spl_t			s;
	struct per_proc_info	*pp;

	s = splclock();					/* no interruptions */
	pp = getPerProc();

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
	rtclock_timer_t		*mytimer;
	spl_t			s = splclock();		/* No interruptions please */
	struct per_proc_info	*pp;

	pp = getPerProc();

	deadline = ~0ULL;

	/* if we have a clock timer set sooner, pop on that */
	mytimer = &pp->rtclock_timer;			/* Point to the timer itself */
	if (!mytimer->has_expired && mytimer->deadline > 0)
		deadline = mytimer->deadline;

	/* if we have a power management event coming up, how about that? */
	if (pp->pms.pmsPop > 0 && pp->pms.pmsPop < deadline)
		deadline = pp->pms.pmsPop;
	

	if (deadline > 0 && deadline <= pp->rtcPop) {
		int     decr;
		uint64_t now;

		now = mach_absolute_time();
		decr = setPop(deadline);

		if (deadline < now)
		        pp->rtcPop = now + decr;
		else
		        pp->rtcPop = deadline;

		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_DECI, 1) | DBG_FUNC_NONE, decr, 2, 0, 0, 0);
	}
	splx(s);
}

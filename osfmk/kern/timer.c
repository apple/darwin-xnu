/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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

#include <stat_time.h>
#include <machine_timer_routines.h>

#include <mach/kern_return.h>
#include <mach/port.h>
#include <kern/queue.h>
#include <kern/processor.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/timer.h>

/*
 *	timer_init initializes a timer.
 */
void
timer_init(
	timer_t		timer)
{
	timer->low_bits = 0;
	timer->high_bits = 0;
	timer->high_bits_check = 0;
#if	!STAT_TIME
	timer->tstamp = 0;
#endif	/* STAT_TIME */
}

/*
 *	Calculate the difference between a timer
 *	and saved value, and update the saved value.
 */
uint64_t
timer_delta(
	timer_t		timer,
	uint64_t	*save)
{
	uint64_t	new, old = *save;

	*save = new = timer_grab(timer);

	return (new - old);
}

#if	!STAT_TIME

/*
 *	Update the current timer (if any)
 *	and start the new timer, which
 *	could be either the same or NULL.
 *
 *	Called with interrupts disabled.
 */
void
timer_switch(
	uint32_t		tstamp,
	timer_t			new_timer)
{
	processor_t		processor = current_processor();
	timer_t			timer;
	uint32_t		old_low, low;

	/*
	 *	Update current timer.
	 */
	timer = PROCESSOR_DATA(processor, current_timer);
	if (timer != NULL) {
		old_low = timer->low_bits;
		low = old_low + tstamp - timer->tstamp;
		if (low < old_low)
			timer_update(timer, timer->high_bits + 1, low);
		else
			timer->low_bits = low;
	}

	/*
	 *	Start new timer.
	 */
	PROCESSOR_DATA(processor, current_timer) = new_timer;
	if (new_timer != NULL)
		new_timer->tstamp = tstamp;
}

#if	MACHINE_TIMER_ROUTINES

/*
 *	Machine-dependent code implements the timer event routine.
 */

#else	/* MACHINE_TIMER_ROUTINES */

/*
 *	Update the current timer and start
 *	the new timer.  Requires a current
 *	and new timer.
 *
 *	Called with interrupts disabled.
 */
void
timer_event(
	uint32_t		tstamp,
	timer_t			new_timer)
{
	processor_t		processor = current_processor();
	timer_t			timer;
	uint32_t		old_low, low;

	/*
	 *	Update current timer.
	 */
	timer = PROCESSOR_DATA(processor, current_timer);
	old_low = timer->low_bits;
	low = old_low + tstamp - timer->tstamp;
	if (low < old_low)
		timer_update(timer, timer->high_bits + 1, low);
	else
		timer->low_bits = low;

	/*
	 *	Start new timer.
	 */
	PROCESSOR_DATA(processor, current_timer) = new_timer;
	new_timer->tstamp = tstamp;
}

#endif	/* MACHINE_TIMER_ROUTINES */

#endif	/* STAT_TIME */

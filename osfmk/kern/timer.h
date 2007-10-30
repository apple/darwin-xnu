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

#ifndef	_KERN_TIMER_H_
#define _KERN_TIMER_H_

#include <stat_time.h>

#include <kern/kern_types.h>

/*
 *	Definitions for high resolution timers.  A check
 *	word on the high portion allows atomic updates.
 */

struct timer {
#if	!STAT_TIME
	uint64_t	tstamp;
#endif	/* STAT_TIME */
	uint32_t	low_bits;
	uint32_t	high_bits;
	uint32_t	high_bits_check;
};

typedef struct timer	timer_data_t, *timer_t;

/*
 *	Exported kernel interface to timers
 */

#if	STAT_TIME

#include <kern/macro_help.h>

/* Advance a timer by a 32 bit value */
#define TIMER_BUMP(timer, ticks)								\
MACRO_BEGIN														\
	uint32_t	old_low, low;									\
																\
	old_low = (timer)->low_bits;								\
	low = old_low + (ticks);									\
	if (low < old_low)											\
		timer_update((timer), (timer)->high_bits + 1, low);		\
	else														\
		(timer)->low_bits = low;								\
MACRO_END

#define timer_start(timer, tstamp)
#define timer_stop(timer, tstamp)
#define timer_switch(timer, tstamp, new_timer)
#define thread_timer_event(tstamp, new_timer)

#else	/* STAT_TIME */

#define	TIMER_BUMP(timer, ticks)

/* Start a timer by setting the timestamp */
extern void		timer_start(
					timer_t		timer,
					uint64_t	tstamp);

/* Stop a timer by updating from the timestamp */
extern void		timer_stop(
					timer_t		timer,
					uint64_t	tstamp);

/* Update the timer and start a new one */
extern void		timer_switch(
					timer_t		timer,
					uint64_t	tstamp,
					timer_t		new_timer);

/* Update the thread timer at an event */
extern void		thread_timer_event(
					uint64_t	tstamp,
					timer_t		new_timer);

#endif	/* STAT_TIME */

/* Initialize a timer */
extern void		timer_init(
					timer_t		timer);

/* Update a saved timer value and return delta to current value */
extern uint64_t	timer_delta(
					timer_t		timer,
					uint64_t	*save);

/* Advance a timer by a 64 bit value */
extern void		timer_advance(
					timer_t		timer,
					uint64_t	delta);

/*
 *	Exported hardware interface to timers
 */

/* Read timer value */
extern uint64_t	timer_grab(
					timer_t		timer);

/* Update timer value */
extern void		timer_update(
					timer_t		timer,
					uint32_t	new_high,
					uint32_t	new_low);

#endif	/* _KERN_TIMER_H_ */

/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
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

#ifndef	_KERN_TIMER_H_
#define _KERN_TIMER_H_

#include <cpus.h>
#include <stat_time.h>

#include <kern/macro_help.h>
#include <kern/kern_types.h>

#if	STAT_TIME
/*
 *	Statistical timer definitions - use microseconds in timer, seconds
 *	in high unit field.  No adjustment needed to convert to time_value_t
 *	as a result.  Service timers once an hour.
 */

#define TIMER_RATE	1000000
#define TIMER_HIGH_UNIT	TIMER_RATE
#undef	TIMER_ADJUST

#else	/* STAT_TIME */
/*
 *	Machine dependent definitions based on hardware support.
 */

#include <machine/timer.h>

#endif	/* STAT_TIME */

/*
 *	Definitions for accurate timers.  high_bits_check is a copy of
 *	high_bits that allows reader to verify that values read are ok.
 */

struct timer {
	unsigned	low_bits;
	unsigned	high_bits;
	unsigned	high_bits_check;
	unsigned	tstamp;
};

typedef struct timer		timer_data_t;
typedef	struct timer		*timer_t;

/*
 *	Mask to check if low_bits is in danger of overflowing
 */

#define	TIMER_LOW_FULL	0x80000000

/*
 *	Kernel timers and current timer array.  [Exported]
 */

extern timer_t		current_timer[NCPUS];
extern timer_data_t	kernel_timer[NCPUS];

/*
 *	save structure for timer readings.  This is used to save timer
 *	readings for elapsed time computations.
 */

struct timer_save {
	unsigned	low;
	unsigned	high;
};

typedef struct timer_save	timer_save_data_t, *timer_save_t;

/*
 *	Exported kernel interface to timers
 */

#if	STAT_TIME
#define start_timer(timer)
#define timer_switch(timer)
#else	/* STAT_TIME */
/* Start timer for this cpu */
extern void		start_timer(
				timer_t		timer);

/* Switch to a new timer */
extern void		timer_switch(
				timer_t		new_timer);
#endif	/* STAT_TIME */

/* Initialize timer module */
extern void		init_timers(void);

/*
 * Initializes a single timer.
 */
extern void		timer_init(
				timer_t	this_timer);

/* Normalize timer value */
extern void		timer_normalize(
				timer_t	timer);

/* Read value of timer into tv */
extern void		timer_read(
				timer_t timer,
				time_value_t *tv);

/* Read thread times */
extern void		thread_read_times(
				thread_t 	thread,
				time_value_t	*user_time_p,
				time_value_t	*system_time_p);

/* Compute timer difference */
extern unsigned		timer_delta(
				timer_t		timer,
				timer_save_t	save);

#if	STAT_TIME
/*
 *	Macro to bump timer values.
 */	
#define timer_bump(timer, usec)					\
MACRO_BEGIN							\
	(timer)->low_bits += usec;				\
	if ((timer)->low_bits & TIMER_LOW_FULL) {		\
		timer_normalize(timer);				\
	}							\
MACRO_END

#else	/* STAT_TIME */
/*
 *	Exported hardware interface to timers
 */
/* Time trap entry */
extern void		time_trap_uentry(
				unsigned	ts);

/* Time trap exit */
extern void		time_trap_uexit(
				unsigned	ts);

/* Time interrupt entry */
extern timer_t		time_int_entry(
				unsigned	ts,
				timer_t		new_timer);

/* Time interrrupt exit */
extern void		time_int_exit(
				unsigned	ts,
				timer_t		old_timer);

#endif	/* STAT_TIME */

/*
 *	TIMER_DELTA finds the difference between a timer and a saved value,
 *	and updates the saved value.  Look at high_bits check field after
 *	reading low because that's the first written by a normalize
 *	operation; this isn't necessary for current usage because
 *	this macro is only used when the timer can't be normalized:
 *	thread is not running, or running thread calls it on itself at
 *	splsched().
 */

#define TIMER_DELTA(timer, save, result)			\
MACRO_BEGIN							\
	register unsigned	temp;				\
								\
	temp = (timer).low_bits;				\
	if ((save).high != (timer).high_bits_check) {		\
		result += timer_delta(&(timer), &(save));	\
	}							\
	else {							\
		result += temp - (save).low;			\
		(save).low = temp;				\
	}							\
MACRO_END

#endif	/* _KERN_TIMER_H_ */

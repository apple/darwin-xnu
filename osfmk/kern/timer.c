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

#include <cpus.h>
#include <stat_time.h>

#include <mach/kern_return.h>
#include <mach/port.h>
#include <kern/queue.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <mach/time_value.h>
#include <kern/timer.h>
#include <kern/cpu_number.h>

#include <kern/assert.h>
#include <kern/macro_help.h>

timer_t		current_timer[NCPUS];
timer_data_t	kernel_timer[NCPUS];

/* Forwards */
void		timer_grab(
			timer_t		timer,
			timer_save_t	save);

void		db_timer_grab(
			timer_t		timer,
			timer_save_t	save);

void		db_thread_read_times(
			thread_t 	thread,
			time_value_t	*user_time_p,
			time_value_t	*system_time_p);

/*
 *	init_timers initializes all non-thread timers and puts the
 *	service routine on the callout queue.  All timers must be
 *	serviced by the callout routine once an hour.
 */
void
init_timers(void)
{
	register int	i;
	register timer_t	this_timer;

	/*
	 *	Initialize all the kernel timers and start the one
	 *	for this cpu (master) slaves start theirs later.
	 */
	this_timer = &kernel_timer[0];
	for ( i=0 ; i<NCPUS ; i++, this_timer++) {
		timer_init(this_timer);
		current_timer[i] = (timer_t) 0;
	}

	mp_disable_preemption();
	start_timer(&kernel_timer[cpu_number()]);
	mp_enable_preemption();
}

/*
 *	timer_init initializes a single timer.
 */
void
timer_init(
	register timer_t	this_timer)
{
	this_timer->low_bits = 0;
	this_timer->high_bits = 0;
	this_timer->tstamp = 0;
	this_timer->high_bits_check = 0;
}

#if	STAT_TIME
#else	/* STAT_TIME */

#ifdef	MACHINE_TIMER_ROUTINES

/*
 *	Machine-dependent code implements the timer routines.
 */

#else	/* MACHINE_TIMER_ROUTINES */

/*
 *	start_timer starts the given timer for this cpu. It is called
 *	exactly once for each cpu during the boot sequence.
 */
void
start_timer(
	register timer_t	timer)
{
	timer->tstamp = get_timestamp();
	mp_disable_preemption();
	current_timer[cpu_number()] = timer;
	mp_enable_preemption();
}

/*
 *	time_trap_uentry does trap entry timing.  Caller must lock out
 *	interrupts and take a timestamp.  ts is a timestamp taken after
 *	interrupts were locked out. Must only be called if trap was
 *	from user mode.
 */
void
time_trap_uentry(
	unsigned	ts)
{
	int	elapsed;
	int	mycpu;
	timer_t	mytimer;

	mp_disable_preemption();

	/*
	 *	Calculate elapsed time.
	 */
	mycpu = cpu_number();
	mytimer = current_timer[mycpu];
	elapsed = ts - mytimer->tstamp;
#ifdef	TIMER_MAX
	if (elapsed < 0) elapsed += TIMER_MAX;
#endif	/* TIMER_MAX */

	/*
	 *	Update current timer.
	 */
	mytimer->low_bits += elapsed;
	mytimer->tstamp = 0;

	if (mytimer->low_bits & TIMER_LOW_FULL) {
		timer_normalize(mytimer);
	}

	/*
	 *	Record new timer.
	 */
	mytimer = &(current_thread()->system_timer);
	current_timer[mycpu] = mytimer;
	mytimer->tstamp = ts;

	mp_enable_preemption();
}

/*
 *	time_trap_uexit does trap exit timing.  Caller must lock out
 *	interrupts and take a timestamp.  ts is a timestamp taken after
 *	interrupts were locked out.  Must only be called if returning to
 *	user mode.
 */
void
time_trap_uexit(
	unsigned	ts)
{
	int	elapsed;
	int	mycpu;
	timer_t	mytimer;

	mp_disable_preemption();

	/*
	 *	Calculate elapsed time.
	 */
	mycpu = cpu_number();
	mytimer = current_timer[mycpu];
	elapsed = ts - mytimer->tstamp;
#ifdef	TIMER_MAX
	if (elapsed < 0) elapsed += TIMER_MAX;
#endif	/* TIMER_MAX */

	/*
	 *	Update current timer.
	 */
	mytimer->low_bits += elapsed;
	mytimer->tstamp = 0;

	if (mytimer->low_bits & TIMER_LOW_FULL) {
		timer_normalize(mytimer);	/* SYSTEMMODE */
	}

	mytimer = &(current_thread()->user_timer);

	/*
	 *	Record new timer.
	 */
	current_timer[mycpu] = mytimer;
	mytimer->tstamp = ts;

	mp_enable_preemption();
}

/*
 *	time_int_entry does interrupt entry timing.  Caller must lock out
 *	interrupts and take a timestamp. ts is a timestamp taken after
 *	interrupts were locked out.  new_timer is the new timer to
 *	switch to.  This routine returns the currently running timer,
 *	which MUST be pushed onto the stack by the caller, or otherwise
 *	saved for time_int_exit.
 */
timer_t
time_int_entry(
	unsigned	ts,
	timer_t		new_timer)
{
	int	elapsed;
	int	mycpu;
	timer_t	mytimer;

	mp_disable_preemption();

	/*
	 *	Calculate elapsed time.
	 */
	mycpu = cpu_number();
	mytimer = current_timer[mycpu];

	elapsed = ts - mytimer->tstamp;
#ifdef	TIMER_MAX
	if (elapsed < 0) elapsed += TIMER_MAX;
#endif	/* TIMER_MAX */

	/*
	 *	Update current timer.
	 */
	mytimer->low_bits += elapsed;
	mytimer->tstamp = 0;

	/*
	 *	Switch to new timer, and save old one on stack.
	 */
	new_timer->tstamp = ts;
	current_timer[mycpu] = new_timer;

	mp_enable_preemption();

	return(mytimer);
}

/*
 *	time_int_exit does interrupt exit timing.  Caller must lock out
 *	interrupts and take a timestamp.  ts is a timestamp taken after
 *	interrupts were locked out.  old_timer is the timer value pushed
 *	onto the stack or otherwise saved after time_int_entry returned
 *	it.
 */
void
time_int_exit(
	unsigned	ts,
	timer_t		old_timer)
{
	int	elapsed;
	int	mycpu;
	timer_t	mytimer;

	mp_disable_preemption();

	/*
	 *	Calculate elapsed time.
	 */
	mycpu = cpu_number();
	mytimer = current_timer[mycpu];
	elapsed = ts - mytimer->tstamp;
#ifdef	TIMER_MAX
	if (elapsed < 0) elapsed += TIMER_MAX;
#endif	/* TIMER_MAX */

	/*
	 *	Update current timer.
	 */
	mytimer->low_bits += elapsed;
	mytimer->tstamp = 0;

	/*
	 *	If normalization requested, do it.
	 */
	if (mytimer->low_bits & TIMER_LOW_FULL) {
		timer_normalize(mytimer);
	}
	if (old_timer->low_bits & TIMER_LOW_FULL) {
		timer_normalize(old_timer);
	}

	/*
	 *	Start timer that was running before interrupt.
	 */
	old_timer->tstamp = ts;
	current_timer[mycpu] = old_timer;

	mp_enable_preemption();
}

/*
 *	timer_switch switches to a new timer.  The machine
 *	dependent routine/macro get_timestamp must return a timestamp.
 *	Caller must lock out interrupts.
 */
void
timer_switch(
	timer_t	new_timer)
{
	int		elapsed;
	int		mycpu;
	timer_t		mytimer;
	unsigned	ts;

	mp_disable_preemption();

	/*
	 *	Calculate elapsed time.
	 */
	mycpu = cpu_number();
	mytimer = current_timer[mycpu];
	ts = get_timestamp();
	elapsed = ts - mytimer->tstamp;
#ifdef	TIMER_MAX
	if (elapsed < 0) elapsed += TIMER_MAX;
#endif	/* TIMER_MAX */

	/*
	 *	Update current timer.
	 */
	mytimer->low_bits += elapsed;
	mytimer->tstamp = 0;

	/*
	 *	Normalization check
	 */
	if (mytimer->low_bits & TIMER_LOW_FULL) {
		timer_normalize(mytimer);
	}

	/*
	 *	Record new timer.
	 */
	current_timer[mycpu] = new_timer;
	new_timer->tstamp = ts;

	mp_enable_preemption();
}

#endif	/* MACHINE_TIMER_ROUTINES */
#endif	/* STAT_TIME */

/*
 *	timer_normalize normalizes the value of a timer.  It is
 *	called only rarely, to make sure low_bits never overflows.
 */

void
timer_normalize(
	register timer_t	timer)
{
	unsigned int	high_increment;

	/*
	 *	Calculate high_increment, then write high check field first
	 *	followed by low and high.  timer_grab() reads these fields in
	 *	reverse order so if high and high check match, we know
	 *	that the values read are ok.
	 */

	high_increment = timer->low_bits/TIMER_HIGH_UNIT;
	timer->high_bits_check += high_increment;
	timer->low_bits %= TIMER_HIGH_UNIT;
	timer->high_bits += high_increment;
}

/*
 *	timer_grab() retrieves the value of a timer.
 *
 *	Critical scheduling code uses TIMER_DELTA macro in timer.h
 *	(called from thread_timer_delta in sched.h).
 *    
 *      Keep coherent with db_time_grab below.
 */

void
timer_grab(
	timer_t		timer,
	timer_save_t	save)
{
#if MACH_ASSERT
	unsigned int passes=0;
#endif
	do {
		(save)->high = (timer)->high_bits;
		(save)->low = (timer)->low_bits;
	/*
	 *	If the timer was normalized while we were doing this,
	 *	the high_bits value read above and the high_bits check
	 *	value will not match because high_bits_check is the first
	 *	field touched by the normalization procedure, and
	 *	high_bits is the last.
	 *
	 *	Additions to timer only touch low bits and
	 *	are therefore atomic with respect to this.
	 */
#if MACH_ASSERT
		passes++;
		assert(passes < 10000);
#endif		
	} while ( (save)->high != (timer)->high_bits_check);
}

/*
 *
 * 	Db_timer_grab(): used by db_thread_read_times. An nonblocking
 *      version of db_thread_get_times. Keep coherent with timer_grab
 *      above.
 *
 */
void
db_timer_grab(
	timer_t		timer,
	timer_save_t	save)
{
  /* Don't worry about coherency */

  (save)->high = (timer)->high_bits;
  (save)->low = (timer)->low_bits;
}


/*
 *	timer_read reads the value of a timer into a time_value_t.  If the
 *	timer was modified during the read, retry.  The value returned
 *	is accurate to the last update; time accumulated by a running
 *	timer since its last timestamp is not included.
 */

void
timer_read(
	timer_t timer,
	register time_value_t *tv)
{
	timer_save_data_t	temp;

	timer_grab(timer,&temp);
	/*
	 *	Normalize the result
	 */
#ifdef	TIMER_ADJUST
	TIMER_ADJUST(&temp);
#endif	/* TIMER_ADJUST */
	tv->seconds = temp.high + temp.low/1000000;
	tv->microseconds = temp.low%1000000;
}

/*
 *	thread_read_times reads the user and system times from a thread.
 *	Time accumulated since last timestamp is not included.  Should
 *	be called at splsched() to avoid having user and system times
 *	be out of step.  Doesn't care if caller locked thread.
 *
 *      Needs to be kept coherent with thread_read_times ahead.
 */
void
thread_read_times(
	thread_t 	thread,
	time_value_t	*user_time_p,
	time_value_t	*system_time_p)
{
	timer_save_data_t	temp;
	register timer_t	timer;

	timer = &thread->user_timer;
	timer_grab(timer, &temp);

#ifdef	TIMER_ADJUST
	TIMER_ADJUST(&temp);
#endif	/* TIMER_ADJUST */
	user_time_p->seconds = temp.high + temp.low/1000000;
	user_time_p->microseconds = temp.low % 1000000;

	timer = &thread->system_timer;
	timer_grab(timer, &temp);

#ifdef	TIMER_ADJUST
	TIMER_ADJUST(&temp);
#endif	/* TIMER_ADJUST */
	system_time_p->seconds = temp.high + temp.low/1000000;
	system_time_p->microseconds = temp.low % 1000000;
}

/*
 *      Db_thread_read_times: A version of thread_read_times that
 *      can be called by the debugger. This version does not call
 *      timer_grab, which can block. Please keep it up to date with
 *      thread_read_times above.
 *
 */
void
db_thread_read_times(
	thread_t 	thread,
	time_value_t	*user_time_p,
	time_value_t	*system_time_p)
{
	timer_save_data_t	temp;
	register timer_t	timer;

	timer = &thread->user_timer;
	db_timer_grab(timer, &temp);

#ifdef	TIMER_ADJUST
	TIMER_ADJUST(&temp);
#endif	/* TIMER_ADJUST */
	user_time_p->seconds = temp.high + temp.low/1000000;
	user_time_p->microseconds = temp.low % 1000000;

	timer = &thread->system_timer;
	timer_grab(timer, &temp);

#ifdef	TIMER_ADJUST
	TIMER_ADJUST(&temp);
#endif	/* TIMER_ADJUST */
	system_time_p->seconds = temp.high + temp.low/1000000;
	system_time_p->microseconds = temp.low % 1000000;
}

/*
 *	timer_delta takes the difference of a saved timer value
 *	and the current one, and updates the saved value to current.
 *	The difference is returned as a function value.  See
 *	TIMER_DELTA macro (timer.h) for optimization to this.
 */

unsigned
timer_delta(
	register timer_t timer,
	timer_save_t	save)
{
	timer_save_data_t	new_save;
	register unsigned	result;

	timer_grab(timer,&new_save);
	result = (new_save.high - save->high) * TIMER_HIGH_UNIT +
		new_save.low - save->low;
	save->high = new_save.high;
	save->low = new_save.low;
	return(result);
}

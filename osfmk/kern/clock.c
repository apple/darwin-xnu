/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
 */

#include <mach/mach_types.h>

#include <kern/lock.h>
#include <kern/spl.h>
#include <kern/sched_prim.h>
#include <kern/thread.h>
#include <kern/clock.h>
#include <kern/host_notify.h>

#include <IOKit/IOPlatformExpert.h>

#include <machine/commpage.h>

#include <mach/mach_traps.h>
#include <mach/mach_time.h>

decl_simple_lock_data(static,clock_lock)

/*
 *	Time of day (calendar) variables.
 *
 *	Algorithm:
 *
 *	TOD <- (seconds + epoch, fraction) <- CONV(current absolute time + offset)
 *
 *	where CONV converts absolute time units into seconds and a fraction.
 */
static struct clock_calend {
	uint64_t			epoch;
	uint64_t			offset;
}					clock_calend;

/*
 *	Calendar adjustment variables and values.
 */
#define calend_adjperiod	(NSEC_PER_SEC / 100)	/* adjustment period, ns */
#define calend_adjskew		(40 * NSEC_PER_USEC)	/* "standard" skew, ns / period */
#define	calend_adjbig		(NSEC_PER_SEC)			/* use 10x skew above adjbig ns */

static uint64_t			calend_adjstart;		/* Absolute time value for start of this adjustment period */
static uint32_t			calend_adjoffset;		/* Absolute time offset for this adjustment period as absolute value */

static int32_t			calend_adjdelta;		/* Nanosecond time delta for this adjustment period */
static int64_t			calend_adjtotal;		/* Nanosecond remaining total adjustment */

static uint64_t			calend_adjdeadline;		/* Absolute time value for next adjustment period */
static uint32_t			calend_adjinterval;		/* Absolute time interval of adjustment period */

static timer_call_data_t	calend_adjcall;
static uint32_t				calend_adjactive;

static uint32_t		calend_set_adjustment(
						int32_t			*secs,
						int32_t			*microsecs);

static void			calend_adjust_call(void);
static uint32_t		calend_adjust(void);

static thread_call_data_t	calend_wakecall;

extern	void	IOKitResetTime(void);

static uint64_t		clock_boottime;				/* Seconds boottime epoch */

#define TIME_ADD(rsecs, secs, rfrac, frac, unit)	\
MACRO_BEGIN											\
	if (((rfrac) += (frac)) >= (unit)) {			\
		(rfrac) -= (unit);							\
		(rsecs) += 1;								\
	}												\
	(rsecs) += (secs);								\
MACRO_END

#define TIME_SUB(rsecs, secs, rfrac, frac, unit)	\
MACRO_BEGIN											\
	if ((int32_t)((rfrac) -= (frac)) < 0) {			\
		(rfrac) += (unit);							\
		(rsecs) -= 1;								\
	}												\
	(rsecs) -= (secs);								\
MACRO_END

/*
 *	clock_config:
 *
 *	Called once at boot to configure the clock subsystem.
 */
void
clock_config(void)
{
	simple_lock_init(&clock_lock, 0);

	timer_call_setup(&calend_adjcall, (timer_call_func_t)calend_adjust_call, NULL);
	thread_call_setup(&calend_wakecall, (thread_call_func_t)IOKitResetTime, NULL);

	clock_oldconfig();

	/*
	 * Initialize the timer callouts.
	 */
	timer_call_initialize();
}

/*
 *	clock_init:
 *
 *	Called on a processor each time started.
 */
void
clock_init(void)
{
	clock_oldinit();
}

/*
 *	clock_timebase_init:
 *
 *	Called by machine dependent code
 *	to initialize areas dependent on the
 *	timebase value.  May be called multiple
 *	times during start up.
 */
void
clock_timebase_init(void)
{
	uint64_t	abstime;

	nanoseconds_to_absolutetime(calend_adjperiod, &abstime);
	calend_adjinterval = abstime;

	sched_timebase_init();
}

/*
 *	mach_timebase_info_trap:
 *
 *	User trap returns timebase constant.
 */
kern_return_t
mach_timebase_info_trap(
	struct mach_timebase_info_trap_args *args)
{
	mach_vm_address_t 			out_info_addr = args->info;
	mach_timebase_info_data_t	info;

	clock_timebase_info(&info);

	copyout((void *)&info, out_info_addr, sizeof (info));

	return (KERN_SUCCESS);
}

/*
 *	Calendar routines.
 */

/*
 *	clock_get_calendar_microtime:
 *
 *	Returns the current calendar value,
 *	microseconds as the fraction.
 */
void
clock_get_calendar_microtime(
	uint32_t			*secs,
	uint32_t			*microsecs)
{
	uint64_t		now;
	spl_t			s;

	s = splclock();
	simple_lock(&clock_lock);

	now = mach_absolute_time();

	if (calend_adjdelta < 0) {
		uint32_t	t32;

		if (now > calend_adjstart) {
			t32 = now - calend_adjstart;

			if (t32 > calend_adjoffset)
				now -= calend_adjoffset;
			else
				now = calend_adjstart;
		}
	}

	now += clock_calend.offset;

	absolutetime_to_microtime(now, secs, microsecs);

	*secs += clock_calend.epoch;

	simple_unlock(&clock_lock);
	splx(s);
}

/*
 *	clock_get_calendar_nanotime:
 *
 *	Returns the current calendar value,
 *	nanoseconds as the fraction.
 *
 *	Since we do not have an interface to
 *	set the calendar with resolution greater
 *	than a microsecond, we honor that here.
 */
void
clock_get_calendar_nanotime(
	uint32_t			*secs,
	uint32_t			*nanosecs)
{
	uint64_t		now;
	spl_t			s;

	s = splclock();
	simple_lock(&clock_lock);

	now = mach_absolute_time();

	if (calend_adjdelta < 0) {
		uint32_t	t32;

		if (now > calend_adjstart) {
			t32 = now - calend_adjstart;

			if (t32 > calend_adjoffset)
				now -= calend_adjoffset;
			else
				now = calend_adjstart;
		}
	}

	now += clock_calend.offset;

	absolutetime_to_microtime(now, secs, nanosecs);
	*nanosecs *= NSEC_PER_USEC;

	*secs += clock_calend.epoch;

	simple_unlock(&clock_lock);
	splx(s);
}

/*
 *	clock_gettimeofday:
 *
 *	Kernel interface for commpage implementation of
 *	gettimeofday() syscall.
 *
 *	Returns the current calendar value, and updates the
 *	commpage info as appropriate.  Because most calls to
 *	gettimeofday() are handled in user mode by the commpage,
 *	this routine should be used infrequently.
 */
void
clock_gettimeofday(
	uint32_t			*secs,
	uint32_t			*microsecs)
{
	uint64_t		now;
	spl_t			s;

	s = splclock();
	simple_lock(&clock_lock);

	now = mach_absolute_time();

	if (calend_adjdelta >= 0) {
		clock_gettimeofday_set_commpage(now, clock_calend.epoch, clock_calend.offset, secs, microsecs);
	}
	else {
		uint32_t	t32;

		if (now > calend_adjstart) {
			t32 = now - calend_adjstart;

			if (t32 > calend_adjoffset)
				now -= calend_adjoffset;
			else
				now = calend_adjstart;
		}

		now += clock_calend.offset;

		absolutetime_to_microtime(now, secs, microsecs);

		*secs += clock_calend.epoch;
	}

	simple_unlock(&clock_lock);
	splx(s);
}

/*
 *	clock_set_calendar_microtime:
 *
 *	Sets the current calendar value by
 *	recalculating the epoch and offset
 *	from the system clock.
 *
 *	Also adjusts the boottime to keep the
 *	value consistent, writes the new
 *	calendar value to the platform clock,
 *	and sends calendar change notifications.
 */
void
clock_set_calendar_microtime(
	uint32_t			secs,
	uint32_t			microsecs)
{
	uint32_t		sys, microsys;
	uint32_t		newsecs;
	spl_t			s;

	newsecs = (microsecs < 500*USEC_PER_SEC)?
						secs: secs + 1;

	s = splclock();
	simple_lock(&clock_lock);

    commpage_set_timestamp(0,0,0);

	/*
	 *	Calculate the new calendar epoch based on
	 *	the new value and the system clock.
	 */
	clock_get_system_microtime(&sys, &microsys);
	TIME_SUB(secs, sys, microsecs, microsys, USEC_PER_SEC);

	/*
	 *	Adjust the boottime based on the delta.
	 */
	clock_boottime += secs - clock_calend.epoch;

	/*
	 *	Set the new calendar epoch.
	 */
	clock_calend.epoch = secs;
	nanoseconds_to_absolutetime((uint64_t)microsecs * NSEC_PER_USEC, &clock_calend.offset);

	/*
	 *	Cancel any adjustment in progress.
	 */
	calend_adjdelta = calend_adjtotal = 0;

	simple_unlock(&clock_lock);

	/*
	 *	Set the new value for the platform clock.
	 */
	PESetGMTTimeOfDay(newsecs);

	splx(s);

	/*
	 *	Send host notifications.
	 */
	host_notify_calendar_change();
}

/*
 *	clock_initialize_calendar:
 *
 *	Set the calendar and related clocks
 *	from the platform clock at boot or
 *	wake event.
 *
 *	Also sends host notifications.
 */
void
clock_initialize_calendar(void)
{
	uint32_t		sys, microsys;
	uint32_t		microsecs = 0, secs = PEGetGMTTimeOfDay();
	spl_t			s;

	s = splclock();
	simple_lock(&clock_lock);

    commpage_set_timestamp(0,0,0);

	if ((int32_t)secs >= (int32_t)clock_boottime) {
		/*
		 *	Initialize the boot time based on the platform clock.
		 */
		if (clock_boottime == 0)
			clock_boottime = secs;

		/*
		 *	Calculate the new calendar epoch based on
		 *	the platform clock and the system clock.
		 */
		clock_get_system_microtime(&sys, &microsys);
		TIME_SUB(secs, sys, microsecs, microsys, USEC_PER_SEC);

		/*
		 *	Set the new calendar epoch.
		 */
		clock_calend.epoch = secs;
		nanoseconds_to_absolutetime((uint64_t)microsecs * NSEC_PER_USEC, &clock_calend.offset);

		/*
		 *	 Cancel any adjustment in progress.
		 */
		calend_adjdelta = calend_adjtotal = 0;
	}

	simple_unlock(&clock_lock);
	splx(s);

	/*
	 *	Send host notifications.
	 */
	host_notify_calendar_change();
}

/*
 *	clock_get_boottime_nanotime:
 *
 *	Return the boottime, used by sysctl.
 */
void
clock_get_boottime_nanotime(
	uint32_t			*secs,
	uint32_t			*nanosecs)
{
	*secs = clock_boottime;
	*nanosecs = 0;
}

/*
 *	clock_adjtime:
 *
 *	Interface to adjtime() syscall.
 *
 *	Calculates adjustment variables and
 *	initiates adjustment.
 */
void
clock_adjtime(
	int32_t		*secs,
	int32_t		*microsecs)
{
	uint32_t	interval;
	spl_t		s;

	s = splclock();
	simple_lock(&clock_lock);

	interval = calend_set_adjustment(secs, microsecs);
	if (interval != 0) {
		calend_adjdeadline = mach_absolute_time() + interval;
		if (!timer_call_enter(&calend_adjcall, calend_adjdeadline))
			calend_adjactive++;
	}
	else
	if (timer_call_cancel(&calend_adjcall))
		calend_adjactive--;

	simple_unlock(&clock_lock);
	splx(s);
}

static uint32_t
calend_set_adjustment(
	int32_t				*secs,
	int32_t				*microsecs)
{
	uint64_t		now, t64;
	int64_t			total, ototal;
	uint32_t		interval = 0;

	total = (int64_t)*secs * NSEC_PER_SEC + *microsecs * NSEC_PER_USEC;

    commpage_set_timestamp(0,0,0);

	now = mach_absolute_time();

	ototal = calend_adjtotal;

	if (total != 0) {
		int32_t		delta = calend_adjskew;

		if (total > 0) {
			if (total > calend_adjbig)
				delta *= 10;
			if (delta > total)
				delta = total;

			nanoseconds_to_absolutetime((uint64_t)delta, &t64);
			calend_adjoffset = t64;
		}
		else {
			if (total < -calend_adjbig)
				delta *= 10;
			delta = -delta;
			if (delta < total)
				delta = total;

			calend_adjstart = now;

			nanoseconds_to_absolutetime((uint64_t)-delta, &t64);
			calend_adjoffset = t64;
		}

		calend_adjtotal = total;
		calend_adjdelta = delta;

		interval = calend_adjinterval;
	}
	else
		calend_adjdelta = calend_adjtotal = 0;

	if (ototal != 0) {
		*secs = ototal / NSEC_PER_SEC;
		*microsecs = (ototal % NSEC_PER_SEC) / NSEC_PER_USEC;
	}
	else
		*secs = *microsecs = 0;

	return (interval);
}

static void
calend_adjust_call(void)
{
	uint32_t	interval;
	spl_t		s;

	s = splclock();
	simple_lock(&clock_lock);

	if (--calend_adjactive == 0) {
		interval = calend_adjust();
		if (interval != 0) {
			clock_deadline_for_periodic_event(interval, mach_absolute_time(),
																&calend_adjdeadline);

			if (!timer_call_enter(&calend_adjcall, calend_adjdeadline))
				calend_adjactive++;
		}
	}

	simple_unlock(&clock_lock);
	splx(s);
}

static uint32_t
calend_adjust(void)
{
	uint64_t		now, t64;
	int32_t			delta;
	uint32_t		interval = 0;

    commpage_set_timestamp(0,0,0);

	now = mach_absolute_time();

	delta = calend_adjdelta;

	if (delta > 0) {
		clock_calend.offset += calend_adjoffset;

		calend_adjtotal -= delta;
		if (delta > calend_adjtotal) {
			calend_adjdelta = delta = calend_adjtotal;

			nanoseconds_to_absolutetime((uint64_t)delta, &t64);
			calend_adjoffset = t64;
		}
	}
	else
	if (delta < 0) {
		clock_calend.offset -= calend_adjoffset;

		calend_adjtotal -= delta;
		if (delta < calend_adjtotal) {
			calend_adjdelta = delta = calend_adjtotal;

			nanoseconds_to_absolutetime((uint64_t)-delta, &t64);
			calend_adjoffset = t64;
		}

		if (calend_adjdelta != 0)
			calend_adjstart = now;
	}

	if (calend_adjdelta != 0)
		interval = calend_adjinterval;

	return (interval);
}

/*
 *	clock_wakeup_calendar:
 *
 *	Interface to power management, used
 *	to initiate the reset of the calendar
 *	on wake from sleep event.
 */
void
clock_wakeup_calendar(void)
{
	thread_call_enter(&calend_wakecall);
}

/*
 *	Wait / delay routines.
 */
static void
mach_wait_until_continue(
	__unused void	*parameter,
	wait_result_t	wresult)
{
	thread_syscall_return((wresult == THREAD_INTERRUPTED)? KERN_ABORTED: KERN_SUCCESS);
	/*NOTREACHED*/
}

kern_return_t
mach_wait_until_trap(
	struct mach_wait_until_trap_args	*args)
{
	uint64_t		deadline = args->deadline;
	wait_result_t	wresult;

	wresult = assert_wait_deadline((event_t)mach_wait_until_trap, THREAD_ABORTSAFE, deadline);
	if (wresult == THREAD_WAITING)
		wresult = thread_block(mach_wait_until_continue);

	return ((wresult == THREAD_INTERRUPTED)? KERN_ABORTED: KERN_SUCCESS);
}

void
clock_delay_until(
	uint64_t		deadline)
{
	uint64_t		now = mach_absolute_time();

	if (now >= deadline)
		return;

	if (	(deadline - now) < (8 * sched_cswtime)	||
			get_preemption_level() != 0				||
			ml_get_interrupts_enabled() == FALSE	)
		machine_delay_until(deadline);
	else {
		assert_wait_deadline((event_t)clock_delay_until, THREAD_UNINT, deadline - sched_cswtime);

		thread_block(THREAD_CONTINUE_NULL);
	}
}

void
delay_for_interval(
	uint32_t		interval,
	uint32_t		scale_factor)
{
	uint64_t		end;

	clock_interval_to_deadline(interval, scale_factor, &end);

	clock_delay_until(end);
}

void
delay(
	int		usec)
{
	delay_for_interval((usec < 0)? -usec: usec, NSEC_PER_USEC);
}

/*
 *	Miscellaneous routines.
 */
void
clock_interval_to_deadline(
	uint32_t			interval,
	uint32_t			scale_factor,
	uint64_t			*result)
{
	uint64_t	abstime;

	clock_interval_to_absolutetime_interval(interval, scale_factor, &abstime);

	*result = mach_absolute_time() + abstime;
}

void
clock_absolutetime_interval_to_deadline(
	uint64_t			abstime,
	uint64_t			*result)
{
	*result = mach_absolute_time() + abstime;
}

void
clock_get_uptime(
	uint64_t	*result)
{
	*result = mach_absolute_time();
}

void
clock_deadline_for_periodic_event(
	uint64_t			interval,
	uint64_t			abstime,
	uint64_t			*deadline)
{
	assert(interval != 0);

	*deadline += interval;

	if (*deadline <= abstime) {
		*deadline = abstime + interval;
		abstime = mach_absolute_time();

		if (*deadline <= abstime)
			*deadline = abstime + interval;
	}
}

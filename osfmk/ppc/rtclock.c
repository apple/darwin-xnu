/*
 * Copyright (c) 2004-2005 Apple Computer, Inc. All rights reserved.
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
 *	File:		rtclock.c
 *	Purpose:	Routines for handling the machine dependent
 *				real-time clock.
 */

#include <mach/mach_types.h>

#include <kern/clock.h>
#include <kern/thread.h>
#include <kern/macro_help.h>
#include <kern/spl.h>

#include <kern/host_notify.h>

#include <machine/commpage.h>
#include <machine/machine_routines.h>
#include <ppc/exception.h>
#include <ppc/proc_reg.h>
#include <ppc/pms.h>
#include <ppc/rtclock.h>

#include <IOKit/IOPlatformExpert.h>

#include <sys/kdebug.h>

int		sysclk_config(void);

int		sysclk_init(void);

kern_return_t	sysclk_gettime(
	mach_timespec_t			*cur_time);

kern_return_t	sysclk_getattr(
	clock_flavor_t			flavor,
	clock_attr_t			attr,
	mach_msg_type_number_t	*count);

void		sysclk_setalarm(
	mach_timespec_t			*deadline);

struct clock_ops sysclk_ops = {
	sysclk_config,			sysclk_init,
	sysclk_gettime,			0,
	sysclk_getattr,			0,
	sysclk_setalarm,
};

int		calend_config(void);

kern_return_t	calend_gettime(
	mach_timespec_t			*cur_time);

kern_return_t	calend_getattr(
	clock_flavor_t			flavor,
	clock_attr_t			attr,
	mach_msg_type_number_t	*count);

struct clock_ops calend_ops = {
	calend_config,			0,
	calend_gettime,			0,
	calend_getattr,			0,
	0,
};

/* local data declarations */

static struct rtclock_calend {
	uint32_t			epoch;
	uint32_t			microepoch;

	uint64_t			epoch1;

	int64_t				adjtotal;
	int32_t				adjdelta;
}					rtclock_calend;

static uint32_t		rtclock_boottime;

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

#define NSEC_PER_HZ		(NSEC_PER_SEC / 100)
static uint32_t		 	rtclock_tick_interval;

static uint32_t			rtclock_sec_divisor;

static mach_timebase_info_data_t	rtclock_timebase_const;

static boolean_t		rtclock_timebase_initialized;

static clock_timer_func_t	rtclock_timer_expire;

static timer_call_data_t	rtclock_alarm_timer;

static void		nanotime_to_absolutetime(
					uint32_t		secs,
					uint32_t		nanosecs,
					uint64_t		*result);

static void		rtclock_alarm_expire(
					timer_call_param_t		p0,
					timer_call_param_t		p1);

/* global data declarations */

decl_simple_lock_data(static,rtclock_lock)

/*
 *	Macros to lock/unlock real-time clock device.
 */
#define LOCK_RTC(s)					\
MACRO_BEGIN							\
	(s) = splclock();				\
	simple_lock(&rtclock_lock);		\
MACRO_END

#define UNLOCK_RTC(s)				\
MACRO_BEGIN							\
	simple_unlock(&rtclock_lock);	\
	splx(s);						\
MACRO_END

static void
timebase_callback(
	struct timebase_freq_t	*freq)
{
	uint32_t	numer, denom;
	uint64_t	abstime;
	spl_t		s;

	if (	freq->timebase_den < 1 || freq->timebase_den > 4	||
			freq->timebase_num < freq->timebase_den				)			
		panic("rtclock timebase_callback: invalid constant %d / %d",
					freq->timebase_num, freq->timebase_den);

	denom = freq->timebase_num;
	numer = freq->timebase_den * NSEC_PER_SEC;

	LOCK_RTC(s);
	if (!rtclock_timebase_initialized) {
		commpage_set_timestamp(0,0,0,0);

		rtclock_timebase_const.numer = numer;
		rtclock_timebase_const.denom = denom;
		rtclock_sec_divisor = freq->timebase_num / freq->timebase_den;

		nanoseconds_to_absolutetime(NSEC_PER_HZ, &abstime);
		rtclock_tick_interval = abstime;

		ml_init_lock_timeout();
	}
	else {
		UNLOCK_RTC(s);
		printf("rtclock timebase_callback: late old %d / %d new %d / %d\n",
					rtclock_timebase_const.numer, rtclock_timebase_const.denom,
							numer, denom);
		return;
	}
	UNLOCK_RTC(s);

	clock_timebase_init();
}

/*
 * Configure the real-time clock device.
 */
int
sysclk_config(void)
{
	timer_call_setup(&rtclock_alarm_timer, rtclock_alarm_expire, NULL);

	simple_lock_init(&rtclock_lock, 0);

	PE_register_timebase_callback(timebase_callback);

	return (1);
}

/*
 * Initialize the system clock device.
 */
int
sysclk_init(void)
{
	uint64_t				abstime;
	struct per_proc_info	*pp;

	pp = getPerProc();

	abstime = mach_absolute_time();
	pp->rtclock_tick_deadline = abstime + rtclock_tick_interval;	/* Get the time we need to pop */
	pp->rtcPop = pp->rtclock_tick_deadline;	/* Set the rtc pop time the same for now */
	
	(void)setTimerReq();			/* Start the timers going */

	return (1);
}

kern_return_t
sysclk_gettime(
	mach_timespec_t		*time)	/* OUT */
{
	uint64_t	now, t64;
	uint32_t	divisor;

	now = mach_absolute_time();

	time->tv_sec = t64 = now / (divisor = rtclock_sec_divisor);
	now -= (t64 * divisor);
	time->tv_nsec = (now * NSEC_PER_SEC) / divisor;

	return (KERN_SUCCESS);
}

void
clock_get_system_microtime(
	uint32_t			*secs,
	uint32_t			*microsecs)
{
	uint64_t	now, t64;
	uint32_t	divisor;

	now = mach_absolute_time();

	*secs = t64 = now / (divisor = rtclock_sec_divisor);
	now -= (t64 * divisor);
	*microsecs = (now * USEC_PER_SEC) / divisor;
}

void
clock_get_system_nanotime(
	uint32_t			*secs,
	uint32_t			*nanosecs)
{
	uint64_t	now, t64;
	uint32_t	divisor;

	now = mach_absolute_time();

	*secs = t64 = now / (divisor = rtclock_sec_divisor);
	now -= (t64 * divisor);
	*nanosecs = (now * NSEC_PER_SEC) / divisor;
}

/*
 * Get clock device attributes.
 */
kern_return_t
sysclk_getattr(
	clock_flavor_t			flavor,
	clock_attr_t			attr,		/* OUT */
	mach_msg_type_number_t	*count)		/* IN/OUT */
{
	spl_t		s;

	if (*count != 1)
		return (KERN_FAILURE);

	switch (flavor) {

	case CLOCK_GET_TIME_RES:	/* >0 res */
	case CLOCK_ALARM_CURRES:	/* =0 no alarm */
	case CLOCK_ALARM_MINRES:
	case CLOCK_ALARM_MAXRES:
		LOCK_RTC(s);
		*(clock_res_t *) attr = NSEC_PER_HZ;
		UNLOCK_RTC(s);
		break;

	default:
		return (KERN_INVALID_VALUE);
	}

	return (KERN_SUCCESS);
}

/*
 * Set deadline for the next alarm on the clock device. This call
 * always resets the time to deliver an alarm for the clock.
 */
void
sysclk_setalarm(
	mach_timespec_t		*deadline)
{
	uint64_t	abstime;

	nanotime_to_absolutetime(deadline->tv_sec, deadline->tv_nsec, &abstime);
	timer_call_enter(&rtclock_alarm_timer, abstime);
}

/*
 * Configure the calendar clock.
 */
int
calend_config(void)
{
	return (1);
}

/*
 * Get the current clock time.
 */
kern_return_t
calend_gettime(
	mach_timespec_t		*time)	/* OUT */
{
	clock_get_calendar_nanotime(
				&time->tv_sec, &time->tv_nsec);

	return (KERN_SUCCESS);
}

/*
 * Get clock device attributes.
 */
kern_return_t
calend_getattr(
	clock_flavor_t			flavor,
	clock_attr_t			attr,		/* OUT */
	mach_msg_type_number_t	*count)		/* IN/OUT */
{
	spl_t		s;

	if (*count != 1)
		return (KERN_FAILURE);

	switch (flavor) {

	case CLOCK_GET_TIME_RES:	/* >0 res */
		LOCK_RTC(s);
		*(clock_res_t *) attr = NSEC_PER_HZ;
		UNLOCK_RTC(s);
		break;

	case CLOCK_ALARM_CURRES:	/* =0 no alarm */
	case CLOCK_ALARM_MINRES:
	case CLOCK_ALARM_MAXRES:
		*(clock_res_t *) attr = 0;
		break;

	default:
		return (KERN_INVALID_VALUE);
	}

	return (KERN_SUCCESS);
}

void
clock_get_calendar_microtime(
	uint32_t			*secs,
	uint32_t			*microsecs)
{
	uint32_t		epoch, microepoch;
	uint64_t		now, t64;
	spl_t			s = splclock();

	simple_lock(&rtclock_lock);

	if (rtclock_calend.adjdelta >= 0) {
		uint32_t		divisor;

		now = mach_absolute_time();

		epoch = rtclock_calend.epoch;
		microepoch = rtclock_calend.microepoch;

		simple_unlock(&rtclock_lock);

		*secs = t64 = now / (divisor = rtclock_sec_divisor);
		now -= (t64 * divisor);
		*microsecs = (now * USEC_PER_SEC) / divisor;

		TIME_ADD(*secs, epoch, *microsecs, microepoch, USEC_PER_SEC);
	}
	else {
		uint32_t	delta, t32;

		delta = -rtclock_calend.adjdelta;

		now = mach_absolute_time();

		*secs = rtclock_calend.epoch;
		*microsecs = rtclock_calend.microepoch;

		if (now > rtclock_calend.epoch1) {
			t64 = now - rtclock_calend.epoch1;

			t32 = (t64 * USEC_PER_SEC) / rtclock_sec_divisor;

			if (t32 > delta)
				TIME_ADD(*secs, 0, *microsecs, (t32 - delta), USEC_PER_SEC);
		}

		simple_unlock(&rtclock_lock);
	}

	splx(s);
}

/* This is only called from the gettimeofday() syscall.  As a side
 * effect, it updates the commpage timestamp.  Otherwise it is
 * identical to clock_get_calendar_microtime().  Because most
 * gettimeofday() calls are handled by the commpage in user mode,
 * this routine should be infrequently used except when slowing down
 * the clock.
 */
void
clock_gettimeofday(
	uint32_t			*secs_p,
	uint32_t			*microsecs_p)
{
	uint32_t		epoch, microepoch;
    uint32_t		secs, microsecs;
	uint64_t		now, t64, secs_64, usec_64;
	spl_t			s = splclock();

	simple_lock(&rtclock_lock);

	if (rtclock_calend.adjdelta >= 0) {
		now = mach_absolute_time();

		epoch = rtclock_calend.epoch;
		microepoch = rtclock_calend.microepoch;

		secs = secs_64 = now / rtclock_sec_divisor;
		t64 = now - (secs_64 * rtclock_sec_divisor);
		microsecs = usec_64 = (t64 * USEC_PER_SEC) / rtclock_sec_divisor;

		TIME_ADD(secs, epoch, microsecs, microepoch, USEC_PER_SEC);
        
        /* adjust "now" to be absolute time at _start_ of usecond */
        now -= t64 - ((usec_64 * rtclock_sec_divisor) / USEC_PER_SEC);
        
        commpage_set_timestamp(now,secs,microsecs,rtclock_sec_divisor);
	}
	else {
		uint32_t	delta, t32;

		delta = -rtclock_calend.adjdelta;

		now = mach_absolute_time();

		secs = rtclock_calend.epoch;
		microsecs = rtclock_calend.microepoch;

		if (now > rtclock_calend.epoch1) {
			t64 = now - rtclock_calend.epoch1;

			t32 = (t64 * USEC_PER_SEC) / rtclock_sec_divisor;

			if (t32 > delta)
				TIME_ADD(secs, 0, microsecs, (t32 - delta), USEC_PER_SEC);
		}

        /* no need to disable timestamp, it is already off */
	}

    simple_unlock(&rtclock_lock);
	splx(s);
    
    *secs_p = secs;
    *microsecs_p = microsecs;
}

void
clock_get_calendar_nanotime(
	uint32_t			*secs,
	uint32_t			*nanosecs)
{
	uint32_t		epoch, nanoepoch;
	uint64_t		now, t64;
	spl_t			s = splclock();

	simple_lock(&rtclock_lock);

	if (rtclock_calend.adjdelta >= 0) {
		uint32_t		divisor;

		now = mach_absolute_time();

		epoch = rtclock_calend.epoch;
		nanoepoch = rtclock_calend.microepoch * NSEC_PER_USEC;

		simple_unlock(&rtclock_lock);

		*secs = t64 = now / (divisor = rtclock_sec_divisor);
		now -= (t64 * divisor);
		*nanosecs = ((now * USEC_PER_SEC) / divisor) * NSEC_PER_USEC;

		TIME_ADD(*secs, epoch, *nanosecs, nanoepoch, NSEC_PER_SEC);
	}
	else {
		uint32_t	delta, t32;

		delta = -rtclock_calend.adjdelta;

		now = mach_absolute_time();

		*secs = rtclock_calend.epoch;
		*nanosecs = rtclock_calend.microepoch * NSEC_PER_USEC;

		if (now > rtclock_calend.epoch1) {
			t64 = now - rtclock_calend.epoch1;

			t32 = (t64 * USEC_PER_SEC) / rtclock_sec_divisor;

			if (t32 > delta)
				TIME_ADD(*secs, 0, *nanosecs, ((t32 - delta) * NSEC_PER_USEC), NSEC_PER_SEC);
		}

		simple_unlock(&rtclock_lock);
	}

	splx(s);
}

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
	simple_lock(&rtclock_lock);

    commpage_set_timestamp(0,0,0,0);

	/*
	 *	Cancel any adjustment in progress.
	 */
	if (rtclock_calend.adjdelta < 0) {
		uint64_t	now, t64;
		uint32_t	delta, t32;

		delta = -rtclock_calend.adjdelta;

		sys = rtclock_calend.epoch;
		microsys = rtclock_calend.microepoch;

		now = mach_absolute_time();

		if (now > rtclock_calend.epoch1)
			t64 = now - rtclock_calend.epoch1;
		else
			t64 = 0;

		t32 = (t64 * USEC_PER_SEC) / rtclock_sec_divisor;

		if (t32 > delta)
			TIME_ADD(sys, 0, microsys, (t32 - delta), USEC_PER_SEC);

		rtclock_calend.epoch = sys;
		rtclock_calend.microepoch = microsys;

		sys = t64 = now / rtclock_sec_divisor;
		now -= (t64 * rtclock_sec_divisor);
		microsys = (now * USEC_PER_SEC) / rtclock_sec_divisor;

		TIME_SUB(rtclock_calend.epoch, sys, rtclock_calend.microepoch, microsys, USEC_PER_SEC);
	}

	rtclock_calend.epoch1 = 0;
	rtclock_calend.adjdelta = rtclock_calend.adjtotal = 0;

	/*
	 *	Calculate the new calendar epoch based on
	 *	the new value and the system clock.
	 */
	clock_get_system_microtime(&sys, &microsys);
	TIME_SUB(secs, sys, microsecs, microsys, USEC_PER_SEC);

	/*
	 *	Adjust the boottime based on the delta.
	 */
	rtclock_boottime += secs - rtclock_calend.epoch;

	/*
	 *	Set the new calendar epoch.
	 */
	rtclock_calend.epoch = secs;
	rtclock_calend.microepoch = microsecs;

	simple_unlock(&rtclock_lock);

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

#define tickadj		(40)				/* "standard" skew, us / tick */
#define	bigadj		(USEC_PER_SEC)		/* use 10x skew above bigadj us */

uint32_t
clock_set_calendar_adjtime(
	int32_t				*secs,
	int32_t				*microsecs)
{
	int64_t			total, ototal;
	uint32_t		interval = 0;
	spl_t			s;

	total = (int64_t)*secs * USEC_PER_SEC + *microsecs;

	LOCK_RTC(s);
    commpage_set_timestamp(0,0,0,0);

	ototal = rtclock_calend.adjtotal;

	if (rtclock_calend.adjdelta < 0) {
		uint64_t		now, t64;
		uint32_t		delta, t32;
		uint32_t		sys, microsys;

		delta = -rtclock_calend.adjdelta;

		sys = rtclock_calend.epoch;
		microsys = rtclock_calend.microepoch;

		now = mach_absolute_time();

		if (now > rtclock_calend.epoch1)
			t64 = now - rtclock_calend.epoch1;
		else
			t64 = 0;

		t32 = (t64 * USEC_PER_SEC) / rtclock_sec_divisor;

		if (t32 > delta)
			TIME_ADD(sys, 0, microsys, (t32 - delta), USEC_PER_SEC);

		rtclock_calend.epoch = sys;
		rtclock_calend.microepoch = microsys;

		sys = t64 = now / rtclock_sec_divisor;
		now -= (t64 * rtclock_sec_divisor);
		microsys = (now * USEC_PER_SEC) / rtclock_sec_divisor;

		TIME_SUB(rtclock_calend.epoch, sys, rtclock_calend.microepoch, microsys, USEC_PER_SEC);
	}

	if (total != 0) {
		int32_t		delta = tickadj;

		if (total > 0) {
			if (total > bigadj)
				delta *= 10;
			if (delta > total)
				delta = total;

			rtclock_calend.epoch1 = 0;
		}
		else {
			uint64_t		now, t64;
			uint32_t		sys, microsys;

			if (total < -bigadj)
				delta *= 10;
			delta = -delta;
			if (delta < total)
				delta = total;

			rtclock_calend.epoch1 = now = mach_absolute_time();

			sys = t64 = now / rtclock_sec_divisor;
			now -= (t64 * rtclock_sec_divisor);
			microsys = (now * USEC_PER_SEC) / rtclock_sec_divisor;

			TIME_ADD(rtclock_calend.epoch, sys, rtclock_calend.microepoch, microsys, USEC_PER_SEC);
		}

		rtclock_calend.adjtotal = total;
		rtclock_calend.adjdelta = delta;

		interval = rtclock_tick_interval;
	}
	else {
		rtclock_calend.epoch1 = 0;
		rtclock_calend.adjdelta = rtclock_calend.adjtotal = 0;
	}

	UNLOCK_RTC(s);

	if (ototal == 0)
		*secs = *microsecs = 0;
	else {
		*secs = ototal / USEC_PER_SEC;
		*microsecs = ototal % USEC_PER_SEC;
	}

	return (interval);
}

uint32_t
clock_adjust_calendar(void)
{
	uint32_t		interval = 0;
	int32_t			delta;
	spl_t			s;

	LOCK_RTC(s);
    commpage_set_timestamp(0,0,0,0);

	delta = rtclock_calend.adjdelta;

	if (delta > 0) {
		TIME_ADD(rtclock_calend.epoch, 0, rtclock_calend.microepoch, delta, USEC_PER_SEC);

		rtclock_calend.adjtotal -= delta;
		if (delta > rtclock_calend.adjtotal)
			rtclock_calend.adjdelta = rtclock_calend.adjtotal;
	}
	else
	if (delta < 0) {
		uint64_t		now, t64;
		uint32_t		t32;

		now = mach_absolute_time();

		if (now > rtclock_calend.epoch1)
			t64 = now - rtclock_calend.epoch1;
		else
			t64 = 0;

		rtclock_calend.epoch1 = now;

		t32 = (t64 * USEC_PER_SEC) / rtclock_sec_divisor;

		TIME_ADD(rtclock_calend.epoch, 0, rtclock_calend.microepoch, (t32 + delta), USEC_PER_SEC);

		rtclock_calend.adjtotal -= delta;
		if (delta < rtclock_calend.adjtotal)
			rtclock_calend.adjdelta = rtclock_calend.adjtotal;

		if (rtclock_calend.adjdelta == 0) {
			uint32_t		sys, microsys;

			sys = t64 = now / rtclock_sec_divisor;
			now -= (t64 * rtclock_sec_divisor);
			microsys = (now * USEC_PER_SEC) / rtclock_sec_divisor;

			TIME_SUB(rtclock_calend.epoch, sys, rtclock_calend.microepoch, microsys, USEC_PER_SEC);

			rtclock_calend.epoch1 = 0;
		}
	}

	if (rtclock_calend.adjdelta != 0)
		interval = rtclock_tick_interval;

	UNLOCK_RTC(s);

	return (interval);
}

/*
 *	clock_initialize_calendar:
 *
 *	Set the calendar and related clocks
 *	from the platform clock at boot or
 *	wake event.
 */
void
clock_initialize_calendar(void)
{
	uint32_t		sys, microsys;
	uint32_t		microsecs = 0, secs = PEGetGMTTimeOfDay();
	spl_t			s;

	LOCK_RTC(s);
    commpage_set_timestamp(0,0,0,0);

	if ((int32_t)secs >= (int32_t)rtclock_boottime) {
		/*
		 *	Initialize the boot time based on the platform clock.
		 */
		if (rtclock_boottime == 0)
			rtclock_boottime = secs;

		/*
		 *	Calculate the new calendar epoch based
		 *	on the platform clock and the system
		 *	clock.
		 */
		clock_get_system_microtime(&sys, &microsys);
		TIME_SUB(secs, sys, microsecs, microsys, USEC_PER_SEC);

		/*
		 *	Set the new calendar epoch.
		 */
		rtclock_calend.epoch = secs;
		rtclock_calend.microepoch = microsecs;

		/*
		 *	 Cancel any adjustment in progress.
		 */
		rtclock_calend.epoch1 = 0;
		rtclock_calend.adjdelta = rtclock_calend.adjtotal = 0;
	}

	UNLOCK_RTC(s);

	/*
	 *	Send host notifications.
	 */
	host_notify_calendar_change();
}

void
clock_get_boottime_nanotime(
	uint32_t			*secs,
	uint32_t			*nanosecs)
{
	*secs = rtclock_boottime;
	*nanosecs = 0;
}

void
clock_timebase_info(
	mach_timebase_info_t	info)
{
	spl_t		s;

	LOCK_RTC(s);
	rtclock_timebase_initialized = TRUE;
	*info = rtclock_timebase_const;
	UNLOCK_RTC(s);
}	

void
clock_set_timer_deadline(
	uint64_t				deadline)
{
	int						decr;
	uint64_t				abstime;
	rtclock_timer_t			*mytimer;
	struct per_proc_info	*pp;
	spl_t					s;

	s = splclock();
	pp = getPerProc();
	mytimer = &pp->rtclock_timer;
	mytimer->deadline = deadline;

	if (!mytimer->has_expired && (deadline < pp->rtclock_tick_deadline)) {		/* Has the timer already expired or is less that set? */
		pp->rtcPop = deadline;			/* Yes, set the new rtc pop time */
		decr = setTimerReq();			/* Start the timers going */

		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_DECI, 1)
									| DBG_FUNC_NONE, decr, 2, 0, 0, 0);
	}

	splx(s);
}

void
clock_set_timer_func(
	clock_timer_func_t		func)
{
	spl_t		s;

	LOCK_RTC(s);
	if (rtclock_timer_expire == NULL)
		rtclock_timer_expire = func;
	UNLOCK_RTC(s);
}

/*
 * Real-time clock device interrupt.
 */
void
rtclock_intr(struct savearea *ssp) {
	
	uint64_t				abstime;
	int						decr;
	rtclock_timer_t			*mytimer;
	struct per_proc_info	*pp;

	pp = getPerProc();
	mytimer = &pp->rtclock_timer;

	abstime = mach_absolute_time();
	if (pp->rtclock_tick_deadline <= abstime) {	/* Have we passed the pop time? */
		clock_deadline_for_periodic_event(rtclock_tick_interval, abstime,
										  		&pp->rtclock_tick_deadline);
		hertz_tick(USER_MODE(ssp->save_srr1), ssp->save_srr0);
		abstime = mach_absolute_time();			/* Refresh the current time since we went away */
	}

	if (mytimer->deadline <= abstime) {			/* Have we expired the deadline? */
		mytimer->has_expired = TRUE;			/* Remember that we popped */
		mytimer->deadline = EndOfAllTime;		/* Set timer request to the end of all time in case we have no more events */
		(*rtclock_timer_expire)(abstime);		/* Process pop */
		mytimer->has_expired = FALSE;
	}

	pp->rtcPop = (pp->rtclock_tick_deadline < mytimer->deadline) ?	/* Get shortest pop */
		pp->rtclock_tick_deadline :				/* It was the periodic timer */
		mytimer->deadline;						/* Actually, an event request */
	
	decr = setTimerReq();						/* Request the timer pop */

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_DECI, 1)
						  | DBG_FUNC_NONE, decr, 3, 0, 0, 0);
}

/*
 *	Request an interruption at a specific time 
 *
 *	Sets the decrementer to pop at the right time based on the timebase.
 *	The value is chosen by comparing the rtc request with the power management.
 *	request.  We may add other values at a future time.
 *
 */
 
int setTimerReq(void) {

	struct per_proc_info *pp;
	int decr;
	uint64_t nexttime;
	
	pp = getPerProc();							/* Get per_proc */

	nexttime = pp->rtcPop;						/* Assume main timer */

	decr = setPop((pp->pms.pmsPop < nexttime) ? pp->pms.pmsPop : nexttime);	/* Schedule timer pop */

	return decr;								/* Pass back what we actually set */
}

static void
rtclock_alarm_expire(
	__unused void	*p0,
	__unused void	*p1)
{
	mach_timespec_t		timestamp;

	(void) sysclk_gettime(&timestamp);

	clock_alarm_intr(SYSTEM_CLOCK, &timestamp);
}

static void
nanotime_to_absolutetime(
	uint32_t			secs,
	uint32_t			nanosecs,
	uint64_t			*result)
{
	uint32_t	divisor = rtclock_sec_divisor;

	*result = ((uint64_t)secs * divisor) +
				((uint64_t)nanosecs * divisor) / NSEC_PER_SEC;
}

void
absolutetime_to_microtime(
	uint64_t			abstime,
	uint32_t			*secs,
	uint32_t			*microsecs)
{
	uint64_t	t64;
	uint32_t	divisor;

	*secs = t64 = abstime / (divisor = rtclock_sec_divisor);
	abstime -= (t64 * divisor);
	*microsecs = (abstime * USEC_PER_SEC) / divisor;
}

void
clock_interval_to_deadline(
	uint32_t			interval,
	uint32_t			scale_factor,
	uint64_t			*result)
{
	uint64_t	abstime;

	clock_get_uptime(result);

	clock_interval_to_absolutetime_interval(interval, scale_factor, &abstime);

	*result += abstime;
}

void
clock_interval_to_absolutetime_interval(
	uint32_t			interval,
	uint32_t			scale_factor,
	uint64_t			*result)
{
	uint64_t		nanosecs = (uint64_t)interval * scale_factor;
	uint64_t		t64;
	uint32_t		divisor;

	*result = (t64 = nanosecs / NSEC_PER_SEC) *
							(divisor = rtclock_sec_divisor);
	nanosecs -= (t64 * NSEC_PER_SEC);
	*result += (nanosecs * divisor) / NSEC_PER_SEC;
}

void
clock_absolutetime_interval_to_deadline(
	uint64_t			abstime,
	uint64_t			*result)
{
	clock_get_uptime(result);

	*result += abstime;
}

void
absolutetime_to_nanoseconds(
	uint64_t			abstime,
	uint64_t			*result)
{
	uint64_t		t64;
	uint32_t		divisor;

	*result = (t64 = abstime / (divisor = rtclock_sec_divisor)) * NSEC_PER_SEC;
	abstime -= (t64 * divisor);
	*result += (abstime * NSEC_PER_SEC) / divisor;
}

void
nanoseconds_to_absolutetime(
	uint64_t			nanosecs,
	uint64_t			*result)
{
	uint64_t		t64;
	uint32_t		divisor;

	*result = (t64 = nanosecs / NSEC_PER_SEC) *
							(divisor = rtclock_sec_divisor);
	nanosecs -= (t64 * NSEC_PER_SEC);
	*result += (nanosecs * divisor) / NSEC_PER_SEC;
}

void
machine_delay_until(
	uint64_t		deadline)
{
	uint64_t		now;

	do {
		now = mach_absolute_time();
	} while (now < deadline);
}


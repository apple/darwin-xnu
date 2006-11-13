/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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
#include <kern/processor.h>
#include <kern/macro_help.h>
#include <kern/spl.h>

#include <machine/commpage.h>
#include <machine/machine_routines.h>
#include <ppc/exception.h>
#include <ppc/proc_reg.h>
#include <ppc/pms.h>
#include <ppc/rtclock.h>

#include <sys/kdebug.h>

int		rtclock_config(void);

int		rtclock_init(void);

#define NSEC_PER_HZ		(NSEC_PER_SEC / 100)

static uint32_t			rtclock_sec_divisor;

static mach_timebase_info_data_t	rtclock_timebase_const;

static boolean_t		rtclock_timebase_initialized;

/* XXX this should really be in a header somewhere */
extern clock_timer_func_t	rtclock_timer_expire;

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
		commpage_set_timestamp(0,0,0);

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
 * Configure the system clock device.
 */
int
rtclock_config(void)
{
	simple_lock_init(&rtclock_lock, 0);

	PE_register_timebase_callback(timebase_callback);

	return (1);
}

/*
 * Initialize the system clock device.
 */
int
rtclock_init(void)
{
	uint64_t				abstime;
	struct per_proc_info	*pp;

	pp = getPerProc();

	abstime = mach_absolute_time();
	pp->rtclock_intr_deadline = abstime + rtclock_tick_interval;	/* Get the time we need to pop */
	
	etimer_resync_deadlines();			/* Start the timers going */

	return (1);
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

void
clock_gettimeofday_set_commpage(
	uint64_t				abstime,
	uint64_t				epoch,
	uint64_t				offset,
	uint32_t				*secs,
	uint32_t				*microsecs)
{
	uint64_t				t64, now = abstime;

	simple_lock(&rtclock_lock);

	now += offset;

	*secs = t64 = now / rtclock_sec_divisor;
	now -= (t64 * rtclock_sec_divisor);
	*microsecs = (now * USEC_PER_SEC) / rtclock_sec_divisor;

	*secs += epoch;

	commpage_set_timestamp(abstime - now, *secs, rtclock_sec_divisor);

	simple_unlock(&rtclock_lock);
}

void
clock_timebase_info(
	mach_timebase_info_t	info)
{
	spl_t		s;

	LOCK_RTC(s);
	*info = rtclock_timebase_const;
	rtclock_timebase_initialized = TRUE;
	UNLOCK_RTC(s);
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
absolutetime_to_nanotime(
	uint64_t			abstime,
	uint32_t			*secs,
	uint32_t			*nanosecs)
{
	uint64_t	t64;
	uint32_t	divisor;

	*secs = t64 = abstime / (divisor = rtclock_sec_divisor);
	abstime -= (t64 * divisor);
	*nanosecs = (abstime * NSEC_PER_SEC) / divisor;
}

void
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

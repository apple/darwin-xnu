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
 */

#include <mach/mach_types.h>

#include <kern/spl.h>
#include <kern/sched_prim.h>
#include <kern/thread.h>
#include <kern/clock.h>
#include <kern/host_notify.h>
#include <kern/thread_call.h>
#include <libkern/OSAtomic.h>

#include <IOKit/IOPlatformExpert.h>

#include <machine/commpage.h>

#include <mach/mach_traps.h>
#include <mach/mach_time.h>

#include <sys/kdebug.h>

uint32_t	hz_tick_interval = 1;


decl_simple_lock_data(,clock_lock)

#define clock_lock()	\
	simple_lock(&clock_lock)

#define clock_unlock()	\
	simple_unlock(&clock_lock)

#define clock_lock_init()	\
	simple_lock_init(&clock_lock, 0)

#ifdef kdp_simple_lock_is_acquired
boolean_t kdp_clock_is_locked()
{
	return kdp_simple_lock_is_acquired(&clock_lock);
}
#endif

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
	uint64_t	epoch;
	uint64_t	offset;
	uint64_t    epoch_absolute;

	int32_t		adjdelta;	/* Nanosecond time delta for this adjustment period */
	uint64_t	adjstart;	/* Absolute time value for start of this adjustment period */
	uint32_t	adjoffset;	/* Absolute time offset for this adjustment period as absolute value */
} clock_calend;

#if	CONFIG_DTRACE

/*
 *	Unlocked calendar flipflop; this is used to track a clock_calend such
 *	that we can safely access a snapshot of a valid  clock_calend structure
 *	without needing to take any locks to do it.
 *
 *	The trick is to use a generation count and set the low bit when it is
 *	being updated/read; by doing this, we guarantee, through use of the
 *	hw_atomic functions, that the generation is incremented when the bit
 *	is cleared atomically (by using a 1 bit add).
 */
static struct unlocked_clock_calend {
	struct clock_calend	calend;		/* copy of calendar */
	uint32_t		gen;		/* generation count */
} flipflop[ 2];

static void clock_track_calend_nowait(void);

#endif

/*
 *	Calendar adjustment variables and values.
 */
#define calend_adjperiod	(NSEC_PER_SEC / 100)	/* adjustment period, ns */
#define calend_adjskew		(40 * NSEC_PER_USEC)	/* "standard" skew, ns / period */
#define	calend_adjbig		(NSEC_PER_SEC)			/* use 10x skew above adjbig ns */

static int64_t				calend_adjtotal;		/* Nanosecond remaining total adjustment */
static uint64_t				calend_adjdeadline;		/* Absolute time value for next adjustment period */
static uint32_t				calend_adjinterval;		/* Absolute time interval of adjustment period */

static timer_call_data_t	calend_adjcall;
static uint32_t				calend_adjactive;

static uint32_t		calend_set_adjustment(
						long			*secs,
						int				*microsecs);

static void			calend_adjust_call(void);
static uint32_t		calend_adjust(void);

void _clock_delay_until_deadline(uint64_t		interval,
								 uint64_t		deadline);
void _clock_delay_until_deadline_with_leeway(uint64_t		interval,
											 uint64_t		deadline,
											 uint64_t		leeway);

/* Seconds boottime epoch */
static uint64_t clock_boottime;
static uint32_t clock_boottime_usec;

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
	if ((int)((rfrac) -= (frac)) < 0) {				\
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
	clock_lock_init();

	timer_call_setup(&calend_adjcall, (timer_call_func_t)calend_adjust_call, NULL);

	clock_oldconfig();
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
	calend_adjinterval = (uint32_t)abstime;

	nanoseconds_to_absolutetime(NSEC_PER_SEC / 100, &abstime);
	hz_tick_interval = (uint32_t)abstime;

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
	clock_sec_t			*secs,
	clock_usec_t		*microsecs)
{
	clock_get_calendar_absolute_and_microtime(secs, microsecs, NULL);
}

static void
clock_get_calendar_absolute_and_microtime_locked(
	clock_sec_t			*secs,
	clock_usec_t		*microsecs,
	uint64_t    		*abstime)
{
	uint64_t now  = mach_absolute_time();
	if (abstime)
		*abstime = now;

	if (clock_calend.adjdelta < 0) {
		uint32_t	t32;

		/*
		 * Since offset is decremented during a negative adjustment,
		 * ensure that time increases monotonically without going
		 * temporarily backwards.
		 * If the delta has not yet passed, now is set to the start
		 * of the current adjustment period; otherwise, we're between
		 * the expiry of the delta and the next call to calend_adjust(),
		 * and we offset accordingly.
		 */
		if (now > clock_calend.adjstart) {
			t32 = (uint32_t)(now - clock_calend.adjstart);

			if (t32 > clock_calend.adjoffset)
				now -= clock_calend.adjoffset;
			else
				now = clock_calend.adjstart;
		}
	}

	now += clock_calend.offset;

	absolutetime_to_microtime(now, secs, microsecs);

	*secs += (clock_sec_t)clock_calend.epoch;
}

/*
 *	clock_get_calendar_absolute_and_microtime:
 *
 *	Returns the current calendar value,
 *	microseconds as the fraction. Also
 *	returns mach_absolute_time if abstime
 *	is not NULL.
 */
void
clock_get_calendar_absolute_and_microtime(
	clock_sec_t			*secs,
	clock_usec_t		*microsecs,
	uint64_t    		*abstime)
{
	spl_t			s;

	s = splclock();
	clock_lock();

	clock_get_calendar_absolute_and_microtime_locked(secs, microsecs, abstime);

	clock_unlock();
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
	clock_sec_t			*secs,
	clock_nsec_t		*nanosecs)
{
	spl_t			s;

	s = splclock();
	clock_lock();

	clock_get_calendar_absolute_and_microtime_locked(secs, nanosecs, NULL);

	*nanosecs *= NSEC_PER_USEC;

	clock_unlock();
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
	clock_sec_t		*secs,
	clock_usec_t	*microsecs)
{
	clock_gettimeofday_and_absolute_time(secs, microsecs, NULL);
}

void
clock_gettimeofday_and_absolute_time(
	clock_sec_t		*secs,
	clock_usec_t	*microsecs,
	uint64_t		*mach_time)
{
	uint64_t		now;
	spl_t			s;

	s = splclock();
	clock_lock();

	now = mach_absolute_time();

	if (clock_calend.adjdelta >= 0) {
		clock_gettimeofday_set_commpage(now, clock_calend.epoch, clock_calend.offset, secs, microsecs);
	}
	else {
		uint32_t	t32;

		if (now > clock_calend.adjstart) {
			t32 = (uint32_t)(now - clock_calend.adjstart);

			if (t32 > clock_calend.adjoffset)
				now -= clock_calend.adjoffset;
			else
				now = clock_calend.adjstart;
		}

		now += clock_calend.offset;

		absolutetime_to_microtime(now, secs, microsecs);

		*secs += (clock_sec_t)clock_calend.epoch;
	}

	clock_unlock();
	splx(s);

	if (mach_time) {
		*mach_time = now;
	}
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
	clock_sec_t			secs,
	clock_usec_t		microsecs)
{
	clock_sec_t			sys;
	clock_usec_t		microsys;
	uint64_t			absolutesys;
	clock_sec_t			newsecs;
	clock_sec_t			oldsecs;
    clock_usec_t        newmicrosecs;
	clock_usec_t		oldmicrosecs;
	uint64_t			commpage_value;
	spl_t				s;

    newsecs = secs;
    newmicrosecs = microsecs;

	s = splclock();
	clock_lock();

	commpage_disable_timestamp();

	/*
	 *	Adjust the boottime based on the delta.
	 */
	clock_get_calendar_absolute_and_microtime_locked(&oldsecs, &oldmicrosecs, &absolutesys);
	if (oldsecs < secs || (oldsecs == secs && oldmicrosecs < microsecs)){
		// moving forwards
		long deltasecs = secs, deltamicrosecs = microsecs;
		TIME_SUB(deltasecs, oldsecs, deltamicrosecs, oldmicrosecs, USEC_PER_SEC);
		TIME_ADD(clock_boottime, deltasecs, clock_boottime_usec, deltamicrosecs, USEC_PER_SEC);
	} else {
		// moving backwards
		long deltasecs = oldsecs, deltamicrosecs = oldmicrosecs;
		TIME_SUB(deltasecs, secs, deltamicrosecs, microsecs, USEC_PER_SEC);
		TIME_SUB(clock_boottime, deltasecs, clock_boottime_usec, deltamicrosecs, USEC_PER_SEC);
	}
	commpage_value = clock_boottime * USEC_PER_SEC + clock_boottime_usec;

	/*
	 *	Calculate the new calendar epoch based on
	 *	the new value and the system clock.
	 */
	absolutetime_to_microtime(absolutesys, &sys, &microsys);
	TIME_SUB(secs, sys, microsecs, microsys, USEC_PER_SEC);

	/*
	 *	Set the new calendar epoch.
	 */
	clock_calend.epoch = secs;

	nanoseconds_to_absolutetime((uint64_t)microsecs * NSEC_PER_USEC, &clock_calend.offset);

	clock_interval_to_absolutetime_interval((uint32_t) secs, NSEC_PER_SEC, &clock_calend.epoch_absolute);
	clock_calend.epoch_absolute += clock_calend.offset;

	/*
	 *	Cancel any adjustment in progress.
	 */
	calend_adjtotal = clock_calend.adjdelta = 0;

	clock_unlock();

	/*
	 *	Set the new value for the platform clock.
	 */
	PESetUTCTimeOfDay(newsecs, newmicrosecs);

	splx(s);

	commpage_update_boottime(commpage_value);

	/*
	 *	Send host notifications.
	 */
	host_notify_calendar_change();
	host_notify_calendar_set();

#if CONFIG_DTRACE
	clock_track_calend_nowait();
#endif
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

uint64_t mach_absolutetime_asleep;
uint64_t mach_absolutetime_last_sleep;

void
clock_initialize_calendar(void)
{
	clock_sec_t			sys;  // sleepless time since boot in seconds
	clock_sec_t			secs; // Current UTC time
	clock_sec_t			utc_offset_secs; // Difference in current UTC time and sleepless time since boot
	clock_usec_t		microsys;  
	clock_usec_t		microsecs; 
	clock_usec_t		utc_offset_microsecs; 
	uint64_t			new_epoch; // utc_offset_secs in mach absolute time units
	spl_t				s;

	PEGetUTCTimeOfDay(&secs, &microsecs);

	s = splclock();
	clock_lock();

	commpage_disable_timestamp();

	if ((long)secs >= (long)clock_boottime) {
		/*
		 *	Initialize the boot time based on the platform clock.
		 */
		if (clock_boottime == 0){
			clock_boottime = secs;
			clock_boottime_usec = microsecs;
			commpage_update_boottime(clock_boottime * USEC_PER_SEC + clock_boottime_usec);
		}

		/*
		 *	Calculate the new calendar epoch based on
		 *	the platform clock and the system clock.
		 */
		clock_get_system_microtime(&sys, &microsys);
		utc_offset_secs = secs;
		utc_offset_microsecs = microsecs;

		// This macro mutates utc_offset_secs and micro_utc_offset
		TIME_SUB(utc_offset_secs, sys, utc_offset_microsecs, microsys, USEC_PER_SEC);

		/*
		 *	Set the new calendar epoch.
		 */

		clock_calend.epoch = utc_offset_secs;

		nanoseconds_to_absolutetime((uint64_t)utc_offset_microsecs * NSEC_PER_USEC, &clock_calend.offset);

		clock_interval_to_absolutetime_interval((uint32_t) utc_offset_secs, NSEC_PER_SEC, &new_epoch);
		new_epoch += clock_calend.offset;

		if (clock_calend.epoch_absolute)
		{
			/* new_epoch is the difference between absolute_time and utc_time
			 * this value will remain constant until the system sleeps.
			 * Then, difference between values would go up by the time the system sleeps.
			 * epoch_absolute is the last difference between the two values
			 * so the difference in the differences would be the time of the last sleep
			 */

			if(new_epoch > clock_calend.epoch_absolute) {
				mach_absolutetime_last_sleep = new_epoch - clock_calend.epoch_absolute;
			}
			else {
				mach_absolutetime_last_sleep = 0;
			}
			mach_absolutetime_asleep += mach_absolutetime_last_sleep;
			KERNEL_DEBUG_CONSTANT(
				  MACHDBG_CODE(DBG_MACH_CLOCK,MACH_EPOCH_CHANGE) | DBG_FUNC_NONE,
				  (uintptr_t) mach_absolutetime_last_sleep,
				  (uintptr_t) mach_absolutetime_asleep,
				  (uintptr_t) (mach_absolutetime_last_sleep >> 32),
				  (uintptr_t) (mach_absolutetime_asleep >> 32),
				  0);
		}
		clock_calend.epoch_absolute = new_epoch;

		/*
		 *	 Cancel any adjustment in progress.
		 */
		calend_adjtotal = clock_calend.adjdelta = 0;
	}

	commpage_update_mach_continuous_time(mach_absolutetime_asleep);
	adjust_cont_time_thread_calls();

	clock_unlock();
	splx(s);

	/*
	 *	Send host notifications.
	 */
	host_notify_calendar_change();
	
#if CONFIG_DTRACE
	clock_track_calend_nowait();
#endif
}

/*
 *	clock_get_boottime_nanotime:
 *
 *	Return the boottime, used by sysctl.
 */
void
clock_get_boottime_nanotime(
	clock_sec_t			*secs,
	clock_nsec_t		*nanosecs)
{
	spl_t	s;

	s = splclock();
	clock_lock();

	*secs = (clock_sec_t)clock_boottime;
	*nanosecs = (clock_nsec_t)clock_boottime_usec * NSEC_PER_USEC;

	clock_unlock();
	splx(s);
}

/*
 *	clock_get_boottime_nanotime:
 *
 *	Return the boottime, used by sysctl.
 */
void
clock_get_boottime_microtime(
	clock_sec_t			*secs,
	clock_usec_t		*microsecs)
{
	spl_t	s;

	s = splclock();
	clock_lock();

	*secs = (clock_sec_t)clock_boottime;
	*microsecs = (clock_nsec_t)clock_boottime_usec;

	clock_unlock();
	splx(s);
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
	long		*secs,
	int			*microsecs)
{
	uint32_t	interval;
	spl_t		s;

	s = splclock();
	clock_lock();

	interval = calend_set_adjustment(secs, microsecs);
	if (interval != 0) {
		calend_adjdeadline = mach_absolute_time() + interval;
		if (!timer_call_enter(&calend_adjcall, calend_adjdeadline, TIMER_CALL_SYS_CRITICAL))
			calend_adjactive++;
	}
	else
	if (timer_call_cancel(&calend_adjcall))
		calend_adjactive--;

	clock_unlock();
	splx(s);
}

static uint32_t
calend_set_adjustment(
	long			*secs,
	int				*microsecs)
{
	uint64_t		now, t64;
	int64_t			total, ototal;
	uint32_t		interval = 0;

	/* 
	 * Compute the total adjustment time in nanoseconds.
	 */
	total = ((int64_t)*secs * (int64_t)NSEC_PER_SEC) + (*microsecs * (int64_t)NSEC_PER_USEC);

	/* 
	 * Disable commpage gettimeofday().
	 */
	commpage_disable_timestamp();

	/* 
	 * Get current absolute time.
	 */
	now = mach_absolute_time();

	/* 
	 * Save the old adjustment total for later return.
	 */
	ototal = calend_adjtotal;

	/*
	 * Is a new correction specified?
	 */
	if (total != 0) {
		/*
		 * Set delta to the standard, small, adjustment skew.
		 */
		int32_t		delta = calend_adjskew;

		if (total > 0) {
			/*
			 * Positive adjustment. If greater than the preset 'big' 
			 * threshold, slew at a faster rate, capping if necessary.
			 */
			if (total > (int64_t) calend_adjbig)
				delta *= 10;
			if (delta > total)
				delta = (int32_t)total;

			/* 
			 * Convert the delta back from ns to absolute time and store in adjoffset.
			 */
			nanoseconds_to_absolutetime((uint64_t)delta, &t64);
			clock_calend.adjoffset = (uint32_t)t64;
		}
		else {
			/*
			 * Negative adjustment; therefore, negate the delta. If 
			 * greater than the preset 'big' threshold, slew at a faster 
			 * rate, capping if necessary.
			 */
			if (total < (int64_t) -calend_adjbig)
				delta *= 10;
			delta = -delta;
			if (delta < total)
				delta = (int32_t)total;

			/* 
			 * Save the current absolute time. Subsequent time operations occuring
			 * during this negative correction can make use of this value to ensure 
			 * that time increases monotonically.
			 */
			clock_calend.adjstart = now;

			/* 
			 * Convert the delta back from ns to absolute time and store in adjoffset.
			 */
			nanoseconds_to_absolutetime((uint64_t)-delta, &t64);
			clock_calend.adjoffset = (uint32_t)t64;
		}

		/* 
		 * Store the total adjustment time in ns. 
		 */
		calend_adjtotal = total;
		
		/* 
		 * Store the delta for this adjustment period in ns. 
		 */
		clock_calend.adjdelta = delta;

		/* 
		 * Set the interval in absolute time for later return. 
		 */
		interval = calend_adjinterval;
	}
	else {
		/* 
		 * No change; clear any prior adjustment.
		 */
		calend_adjtotal = clock_calend.adjdelta = 0;
	}

	/* 
	 * If an prior correction was in progress, return the
	 * remaining uncorrected time from it. 
	 */
	if (ototal != 0) {
		*secs = (long)(ototal / (long)NSEC_PER_SEC);
		*microsecs = (int)((ototal % (int)NSEC_PER_SEC) / (int)NSEC_PER_USEC);
	}
	else
		*secs = *microsecs = 0;

#if CONFIG_DTRACE
	clock_track_calend_nowait();
#endif
	
	return (interval);
}

static void
calend_adjust_call(void)
{
	uint32_t	interval;
	spl_t		s;

	s = splclock();
	clock_lock();

	if (--calend_adjactive == 0) {
		interval = calend_adjust();
		if (interval != 0) {
			clock_deadline_for_periodic_event(interval, mach_absolute_time(), &calend_adjdeadline);

			if (!timer_call_enter(&calend_adjcall, calend_adjdeadline, TIMER_CALL_SYS_CRITICAL))
				calend_adjactive++;
		}
	}

	clock_unlock();
	splx(s);
}

static uint32_t
calend_adjust(void)
{
	uint64_t		now, t64;
	int32_t			delta;
	uint32_t		interval = 0;

	commpage_disable_timestamp();

	now = mach_absolute_time();

	delta = clock_calend.adjdelta;

	if (delta > 0) {
		clock_calend.offset += clock_calend.adjoffset;

		calend_adjtotal -= delta;
		if (delta > calend_adjtotal) {
			clock_calend.adjdelta = delta = (int32_t)calend_adjtotal;

			nanoseconds_to_absolutetime((uint64_t)delta, &t64);
			clock_calend.adjoffset = (uint32_t)t64;
		}
	}
	else
		if (delta < 0) {
			clock_calend.offset -= clock_calend.adjoffset;

			calend_adjtotal -= delta;
			if (delta < calend_adjtotal) {
				clock_calend.adjdelta = delta = (int32_t)calend_adjtotal;

				nanoseconds_to_absolutetime((uint64_t)-delta, &t64);
				clock_calend.adjoffset = (uint32_t)t64;
			}

			if (clock_calend.adjdelta != 0)
				clock_calend.adjstart = now;
		}

	if (clock_calend.adjdelta != 0)
		interval = calend_adjinterval;

#if CONFIG_DTRACE
	clock_track_calend_nowait();
#endif

	return (interval);
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

/*
 * mach_wait_until_trap: Suspend execution of calling thread until the specified time has passed
 *
 * Parameters:    args->deadline          Amount of time to wait
 *
 * Returns:        0                      Success
 *                !0                      Not success           
 *
 */
kern_return_t
mach_wait_until_trap(
	struct mach_wait_until_trap_args	*args)
{
	uint64_t		deadline = args->deadline;
	wait_result_t	wresult;

	wresult = assert_wait_deadline_with_leeway((event_t)mach_wait_until_trap, THREAD_ABORTSAFE,
						   TIMEOUT_URGENCY_USER_NORMAL, deadline, 0);
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

	_clock_delay_until_deadline(deadline - now, deadline);
}

/*
 * Preserve the original precise interval that the client
 * requested for comparison to the spin threshold.
 */
void
_clock_delay_until_deadline(
	uint64_t		interval,
	uint64_t		deadline)
{
	_clock_delay_until_deadline_with_leeway(interval, deadline, 0);
}

/*
 * Like _clock_delay_until_deadline, but it accepts a
 * leeway value.
 */
void
_clock_delay_until_deadline_with_leeway(
	uint64_t		interval,
	uint64_t		deadline,
	uint64_t		leeway)
{

	if (interval == 0)
		return;

	if (	ml_delay_should_spin(interval)	||
			get_preemption_level() != 0				||
			ml_get_interrupts_enabled() == FALSE	) {
		machine_delay_until(interval, deadline);
	} else {
		/*
		 * For now, assume a leeway request of 0 means the client does not want a leeway
		 * value. We may want to change this interpretation in the future.
		 */

		if (leeway) {
			assert_wait_deadline_with_leeway((event_t)clock_delay_until, THREAD_UNINT, TIMEOUT_URGENCY_LEEWAY, deadline, leeway);
		} else {
			assert_wait_deadline((event_t)clock_delay_until, THREAD_UNINT, deadline);
		}

		thread_block(THREAD_CONTINUE_NULL);
	}
}

void
delay_for_interval(
	uint32_t		interval,
	uint32_t		scale_factor)
{
	uint64_t		abstime;

	clock_interval_to_absolutetime_interval(interval, scale_factor, &abstime);

	_clock_delay_until_deadline(abstime, mach_absolute_time() + abstime);
}

void
delay_for_interval_with_leeway(
	uint32_t		interval,
	uint32_t		leeway,
	uint32_t		scale_factor)
{
	uint64_t		abstime_interval;
	uint64_t		abstime_leeway;

	clock_interval_to_absolutetime_interval(interval, scale_factor, &abstime_interval);
	clock_interval_to_absolutetime_interval(leeway, scale_factor, &abstime_leeway);

	_clock_delay_until_deadline_with_leeway(abstime_interval, mach_absolute_time() + abstime_interval, abstime_leeway);
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
clock_continuoustime_interval_to_deadline(
	uint64_t			conttime,
	uint64_t			*result)
{
	*result = mach_continuous_time() + conttime;
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

uint64_t
mach_continuous_time(void)
{
	while(1) {	
		uint64_t read1 = mach_absolutetime_asleep;
		uint64_t absolute = mach_absolute_time();
		OSMemoryBarrier();
		uint64_t read2 = mach_absolutetime_asleep;

		if(__builtin_expect(read1 == read2, 1)) {
			return absolute + read1;
		}
	}
}

uint64_t
mach_continuous_approximate_time(void)
{
	while(1) {
		uint64_t read1 = mach_absolutetime_asleep;
		uint64_t absolute = mach_approximate_time();
		OSMemoryBarrier();
		uint64_t read2 = mach_absolutetime_asleep;

		if(__builtin_expect(read1 == read2, 1)) {
			return absolute + read1;
		}
	}
}

/*
 * continuoustime_to_absolutetime
 * Must be called with interrupts disabled
 * Returned value is only valid until the next update to
 * mach_continuous_time 
 */
uint64_t
continuoustime_to_absolutetime(uint64_t conttime) {
	if (conttime <= mach_absolutetime_asleep)
		return 0;
	else
		return conttime - mach_absolutetime_asleep;
}

/*
 * absolutetime_to_continuoustime
 * Must be called with interrupts disabled
 * Returned value is only valid until the next update to
 * mach_continuous_time 
 */
uint64_t
absolutetime_to_continuoustime(uint64_t abstime) {
	return abstime + mach_absolutetime_asleep;
}

#if	CONFIG_DTRACE

/*
 * clock_get_calendar_nanotime_nowait
 *
 * Description:	Non-blocking version of clock_get_calendar_nanotime()
 *
 * Notes:	This function operates by separately tracking calendar time
 *		updates using a two element structure to copy the calendar
 *		state, which may be asynchronously modified.  It utilizes
 *		barrier instructions in the tracking process and in the local
 *		stable snapshot process in order to ensure that a consistent
 *		snapshot is used to perform the calculation.
 */
void
clock_get_calendar_nanotime_nowait(
	clock_sec_t			*secs,
	clock_nsec_t		*nanosecs)
{
	int i = 0;
	uint64_t		now;
	struct unlocked_clock_calend stable;

	for (;;) {
		stable = flipflop[i];		/* take snapshot */

		/*
		 * Use a barrier instructions to ensure atomicity.  We AND
		 * off the "in progress" bit to get the current generation
		 * count.
		 */
		(void)hw_atomic_and(&stable.gen, ~(uint32_t)1);

		/*
		 * If an update _is_ in progress, the generation count will be
		 * off by one, if it _was_ in progress, it will be off by two,
		 * and if we caught it at a good time, it will be equal (and
		 * our snapshot is threfore stable).
		 */
		if (flipflop[i].gen == stable.gen)
			break;

		/* Switch to the oher element of the flipflop, and try again. */
		i ^= 1;
	}

	now = mach_absolute_time();

	if (stable.calend.adjdelta < 0) {
		uint32_t	t32;

		if (now > stable.calend.adjstart) {
			t32 = (uint32_t)(now - stable.calend.adjstart);

			if (t32 > stable.calend.adjoffset)
				now -= stable.calend.adjoffset;
			else
				now = stable.calend.adjstart;
		}
	}

	now += stable.calend.offset;

	absolutetime_to_microtime(now, secs, nanosecs);
	*nanosecs *= NSEC_PER_USEC;

	*secs += (clock_sec_t)stable.calend.epoch;
}

static void 
clock_track_calend_nowait(void)
{
	int i;

	for (i = 0; i < 2; i++) {
		struct clock_calend tmp = clock_calend;

		/*
		 * Set the low bit if the generation count; since we use a
		 * barrier instruction to do this, we are guaranteed that this
		 * will flag an update in progress to an async caller trying
		 * to examine the contents.
		 */
		(void)hw_atomic_or(&flipflop[i].gen, 1);

		flipflop[i].calend = tmp;

		/*
		 * Increment the generation count to clear the low bit to
		 * signal completion.  If a caller compares the generation
		 * count after taking a copy while in progress, the count
		 * will be off by two.
		 */
		(void)hw_atomic_add(&flipflop[i].gen, 1);
	}
}

#endif	/* CONFIG_DTRACE */


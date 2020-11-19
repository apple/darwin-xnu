/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
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
/*-
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)time.h	8.5 (Berkeley) 5/4/95
 * $FreeBSD$
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
#include <machine/config.h>
#include <machine/machine_routines.h>

#include <mach/mach_traps.h>
#include <mach/mach_time.h>

#include <sys/kdebug.h>
#include <sys/timex.h>
#include <kern/arithmetic_128.h>
#include <os/log.h>

#if HIBERNATION && HAS_CONTINUOUS_HWCLOCK
// On ARM64, the hwclock keeps ticking across a normal S2R so we use it to reset the
// system clock after a normal wake. However, on hibernation we cut power to the hwclock,
// so we have to add an offset to the hwclock to compute continuous_time after hibernate resume.
uint64_t hwclock_conttime_offset = 0;
#endif /* HIBERNATION && HAS_CONTINUOUS_HWCLOCK */

#if HIBERNATION_USES_LEGACY_CLOCK || !HAS_CONTINUOUS_HWCLOCK
#define ENABLE_LEGACY_CLOCK_CODE 1
#endif /* HIBERNATION_USES_LEGACY_CLOCK || !HAS_CONTINUOUS_HWCLOCK */

#if HIBERNATION_USES_LEGACY_CLOCK
#include <IOKit/IOHibernatePrivate.h>
#endif /* HIBERNATION_USES_LEGACY_CLOCK */

uint32_t        hz_tick_interval = 1;
#if ENABLE_LEGACY_CLOCK_CODE
static uint64_t has_monotonic_clock = 0;
#endif /* ENABLE_LEGACY_CLOCK_CODE */

SIMPLE_LOCK_DECLARE(clock_lock, 0);

static LCK_GRP_DECLARE(settime_lock_grp, "settime");
static LCK_MTX_DECLARE(settime_lock, &settime_lock_grp);

#define clock_lock()    \
	simple_lock(&clock_lock, LCK_GRP_NULL)

#define clock_unlock()  \
	simple_unlock(&clock_lock)

#ifdef kdp_simple_lock_is_acquired
boolean_t
kdp_clock_is_locked()
{
	return kdp_simple_lock_is_acquired(&clock_lock);
}
#endif

struct bintime {
	time_t  sec;
	uint64_t frac;
};

static __inline void
bintime_addx(struct bintime *_bt, uint64_t _x)
{
	uint64_t _u;

	_u = _bt->frac;
	_bt->frac += _x;
	if (_u > _bt->frac) {
		_bt->sec++;
	}
}

static __inline void
bintime_subx(struct bintime *_bt, uint64_t _x)
{
	uint64_t _u;

	_u = _bt->frac;
	_bt->frac -= _x;
	if (_u < _bt->frac) {
		_bt->sec--;
	}
}

static __inline void
bintime_addns(struct bintime *bt, uint64_t ns)
{
	bt->sec += ns / (uint64_t)NSEC_PER_SEC;
	ns = ns % (uint64_t)NSEC_PER_SEC;
	if (ns) {
		/* 18446744073 = int(2^64 / NSEC_PER_SEC) */
		ns = ns * (uint64_t)18446744073LL;
		bintime_addx(bt, ns);
	}
}

static __inline void
bintime_subns(struct bintime *bt, uint64_t ns)
{
	bt->sec -= ns / (uint64_t)NSEC_PER_SEC;
	ns = ns % (uint64_t)NSEC_PER_SEC;
	if (ns) {
		/* 18446744073 = int(2^64 / NSEC_PER_SEC) */
		ns = ns * (uint64_t)18446744073LL;
		bintime_subx(bt, ns);
	}
}

static __inline void
bintime_addxns(struct bintime *bt, uint64_t a, int64_t xns)
{
	uint64_t uxns = (xns > 0)?(uint64_t)xns:(uint64_t)-xns;
	uint64_t ns = multi_overflow(a, uxns);
	if (xns > 0) {
		if (ns) {
			bintime_addns(bt, ns);
		}
		ns = (a * uxns) / (uint64_t)NSEC_PER_SEC;
		bintime_addx(bt, ns);
	} else {
		if (ns) {
			bintime_subns(bt, ns);
		}
		ns = (a * uxns) / (uint64_t)NSEC_PER_SEC;
		bintime_subx(bt, ns);
	}
}


static __inline void
bintime_add(struct bintime *_bt, const struct bintime *_bt2)
{
	uint64_t _u;

	_u = _bt->frac;
	_bt->frac += _bt2->frac;
	if (_u > _bt->frac) {
		_bt->sec++;
	}
	_bt->sec += _bt2->sec;
}

static __inline void
bintime_sub(struct bintime *_bt, const struct bintime *_bt2)
{
	uint64_t _u;

	_u = _bt->frac;
	_bt->frac -= _bt2->frac;
	if (_u < _bt->frac) {
		_bt->sec--;
	}
	_bt->sec -= _bt2->sec;
}

static __inline void
clock2bintime(const clock_sec_t *secs, const clock_usec_t *microsecs, struct bintime *_bt)
{
	_bt->sec = *secs;
	/* 18446744073709 = int(2^64 / 1000000) */
	_bt->frac = *microsecs * (uint64_t)18446744073709LL;
}

static __inline void
bintime2usclock(const struct bintime *_bt, clock_sec_t *secs, clock_usec_t *microsecs)
{
	*secs = _bt->sec;
	*microsecs = ((uint64_t)USEC_PER_SEC * (uint32_t)(_bt->frac >> 32)) >> 32;
}

static __inline void
bintime2nsclock(const struct bintime *_bt, clock_sec_t *secs, clock_usec_t *nanosecs)
{
	*secs = _bt->sec;
	*nanosecs = ((uint64_t)NSEC_PER_SEC * (uint32_t)(_bt->frac >> 32)) >> 32;
}

#if ENABLE_LEGACY_CLOCK_CODE
static __inline void
bintime2absolutetime(const struct bintime *_bt, uint64_t *abs)
{
	uint64_t nsec;
	nsec = (uint64_t) _bt->sec * (uint64_t)NSEC_PER_SEC + (((uint64_t)NSEC_PER_SEC * (uint32_t)(_bt->frac >> 32)) >> 32);
	nanoseconds_to_absolutetime(nsec, abs);
}

struct latched_time {
	uint64_t monotonic_time_usec;
	uint64_t mach_time;
};

extern int
kernel_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);

#endif /* ENABLE_LEGACY_CLOCK_CODE */
/*
 *	Time of day (calendar) variables.
 *
 *	Algorithm:
 *
 *	TOD <- bintime + delta*scale
 *
 *	where :
 *      bintime is a cumulative offset that includes bootime and scaled time elapsed betweed bootime and last scale update.
 *	delta is ticks elapsed since last scale update.
 *	scale is computed according to an adjustment provided by ntp_kern.
 */
static struct clock_calend {
	uint64_t                s_scale_ns; /* scale to apply for each second elapsed, it converts in ns */
	int64_t                 s_adj_nsx; /* additional adj to apply for each second elapsed, it is expressed in 64 bit frac of ns */
	uint64_t                tick_scale_x; /* scale to apply for each tick elapsed, it converts in 64 bit frac of s */
	uint64_t                offset_count; /* abs time from which apply current scales */
	struct bintime          offset; /* cumulative offset expressed in (sec, 64 bits frac of a second) */
	struct bintime          bintime; /* cumulative offset (it includes bootime) expressed in (sec, 64 bits frac of a second) */
	struct bintime          boottime; /* boot time expressed in (sec, 64 bits frac of a second) */
#if ENABLE_LEGACY_CLOCK_CODE
	struct bintime          basesleep;
#endif /* ENABLE_LEGACY_CLOCK_CODE */
} clock_calend;

static uint64_t ticks_per_sec; /* ticks in a second (expressed in abs time) */

#if DEVELOPMENT || DEBUG
extern int g_should_log_clock_adjustments;

static void print_all_clock_variables(const char*, clock_sec_t* pmu_secs, clock_usec_t* pmu_usec, clock_sec_t* sys_secs, clock_usec_t* sys_usec, struct clock_calend* calend_cp);
static void print_all_clock_variables_internal(const char *, struct clock_calend* calend_cp);
#else
#define print_all_clock_variables(...) do { } while (0)
#define print_all_clock_variables_internal(...) do { } while (0)
#endif

#if     CONFIG_DTRACE


/*
 *	Unlocked calendar flipflop; this is used to track a clock_calend such
 *	that we can safely access a snapshot of a valid  clock_calend structure
 *	without needing to take any locks to do it.
 *
 *	The trick is to use a generation count and set the low bit when it is
 *	being updated/read; by doing this, we guarantee, through use of the
 *	os_atomic functions, that the generation is incremented when the bit
 *	is cleared atomically (by using a 1 bit add).
 */
static struct unlocked_clock_calend {
	struct clock_calend     calend;         /* copy of calendar */
	uint32_t                gen;            /* generation count */
} flipflop[2];

static void clock_track_calend_nowait(void);

#endif

void _clock_delay_until_deadline(uint64_t interval, uint64_t deadline);
void _clock_delay_until_deadline_with_leeway(uint64_t interval, uint64_t deadline, uint64_t leeway);

/* Boottime variables*/
static uint64_t clock_boottime;
static uint32_t clock_boottime_usec;

#define TIME_ADD(rsecs, secs, rfrac, frac, unit)        \
MACRO_BEGIN                                                                                     \
	if (((rfrac) += (frac)) >= (unit)) {                    \
	        (rfrac) -= (unit);                                                      \
	        (rsecs) += 1;                                                           \
	}                                                                                               \
	(rsecs) += (secs);                                                              \
MACRO_END

#define TIME_SUB(rsecs, secs, rfrac, frac, unit)        \
MACRO_BEGIN                                                                                     \
	if ((int)((rfrac) -= (frac)) < 0) {                             \
	        (rfrac) += (unit);                                                      \
	        (rsecs) -= 1;                                                           \
	}                                                                                               \
	(rsecs) -= (secs);                                                              \
MACRO_END

/*
 *	clock_config:
 *
 *	Called once at boot to configure the clock subsystem.
 */
void
clock_config(void)
{
	clock_oldconfig();

	ntp_init();

	nanoseconds_to_absolutetime((uint64_t)NSEC_PER_SEC, &ticks_per_sec);
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
	uint64_t        abstime;

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
	mach_vm_address_t                       out_info_addr = args->info;
	mach_timebase_info_data_t       info = {};

	clock_timebase_info(&info);

	copyout((void *)&info, out_info_addr, sizeof(info));

	return KERN_SUCCESS;
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
	clock_sec_t             *secs,
	clock_usec_t            *microsecs)
{
	clock_get_calendar_absolute_and_microtime(secs, microsecs, NULL);
}

/*
 * get_scale_factors_from_adj:
 *
 * computes scale factors from the value given in adjustment.
 *
 * Part of the code has been taken from tc_windup of FreeBSD
 * written by Poul-Henning Kamp <phk@FreeBSD.ORG>, Julien Ridoux and
 * Konstantin Belousov.
 * https://github.com/freebsd/freebsd/blob/master/sys/kern/kern_tc.c
 */
static void
get_scale_factors_from_adj(int64_t adjustment, uint64_t* tick_scale_x, uint64_t* s_scale_ns, int64_t* s_adj_nsx)
{
	uint64_t scale;
	int64_t nano, frac;

	/*-
	 * Calculating the scaling factor.  We want the number of 1/2^64
	 * fractions of a second per period of the hardware counter, taking
	 * into account the th_adjustment factor which the NTP PLL/adjtime(2)
	 * processing provides us with.
	 *
	 * The th_adjustment is nanoseconds per second with 32 bit binary
	 * fraction and we want 64 bit binary fraction of second:
	 *
	 *	 x = a * 2^32 / 10^9 = a * 4.294967296
	 *
	 * The range of th_adjustment is +/- 5000PPM so inside a 64bit int
	 * we can only multiply by about 850 without overflowing, that
	 * leaves no suitably precise fractions for multiply before divide.
	 *
	 * Divide before multiply with a fraction of 2199/512 results in a
	 * systematic undercompensation of 10PPM of th_adjustment.  On a
	 * 5000PPM adjustment this is a 0.05PPM error.  This is acceptable.
	 *
	 * We happily sacrifice the lowest of the 64 bits of our result
	 * to the goddess of code clarity.
	 *
	 */
	scale = (uint64_t)1 << 63;
	scale += (adjustment / 1024) * 2199;
	scale /= ticks_per_sec;
	*tick_scale_x = scale * 2;

	/*
	 * hi part of adj
	 * it contains ns (without fraction) to add to the next sec.
	 * Get ns scale factor for the next sec.
	 */
	nano = (adjustment > 0)? adjustment >> 32 : -((-adjustment) >> 32);
	scale = (uint64_t) NSEC_PER_SEC;
	scale += nano;
	*s_scale_ns = scale;

	/*
	 * lo part of adj
	 * it contains 32 bit frac of ns to add to the next sec.
	 * Keep it as additional adjustment for the next sec.
	 */
	frac = (adjustment > 0)? ((uint32_t) adjustment) : -((uint32_t) (-adjustment));
	*s_adj_nsx = (frac > 0)? ((uint64_t) frac) << 32 : -(((uint64_t) (-frac)) << 32);

	return;
}

/*
 * scale_delta:
 *
 * returns a bintime struct representing delta scaled accordingly to the
 * scale factors provided to this function.
 */
static struct bintime
scale_delta(uint64_t delta, uint64_t tick_scale_x, uint64_t s_scale_ns, int64_t s_adj_nsx)
{
	uint64_t sec, new_ns, over;
	struct bintime bt;

	bt.sec = 0;
	bt.frac = 0;

	/*
	 * If more than one second is elapsed,
	 * scale fully elapsed seconds using scale factors for seconds.
	 * s_scale_ns -> scales sec to ns.
	 * s_adj_nsx -> additional adj expressed in 64 bit frac of ns to apply to each sec.
	 */
	if (delta > ticks_per_sec) {
		sec = (delta / ticks_per_sec);
		new_ns = sec * s_scale_ns;
		bintime_addns(&bt, new_ns);
		if (s_adj_nsx) {
			if (sec == 1) {
				/* shortcut, no overflow can occur */
				if (s_adj_nsx > 0) {
					bintime_addx(&bt, (uint64_t)s_adj_nsx / (uint64_t)NSEC_PER_SEC);
				} else {
					bintime_subx(&bt, (uint64_t)-s_adj_nsx / (uint64_t)NSEC_PER_SEC);
				}
			} else {
				/*
				 * s_adj_nsx is 64 bit frac of ns.
				 * sec*s_adj_nsx might overflow in int64_t.
				 * use bintime_addxns to not lose overflowed ns.
				 */
				bintime_addxns(&bt, sec, s_adj_nsx);
			}
		}
		delta = (delta % ticks_per_sec);
	}

	over = multi_overflow(tick_scale_x, delta);
	if (over) {
		bt.sec += over;
	}

	/*
	 * scale elapsed ticks using the scale factor for ticks.
	 */
	bintime_addx(&bt, delta * tick_scale_x);

	return bt;
}

/*
 * get_scaled_time:
 *
 * returns the scaled time of the time elapsed from the last time
 * scale factors were updated to now.
 */
static struct bintime
get_scaled_time(uint64_t now)
{
	uint64_t delta;

	/*
	 * Compute ticks elapsed since last scale update.
	 * This time will be scaled according to the value given by ntp kern.
	 */
	delta = now - clock_calend.offset_count;

	return scale_delta(delta, clock_calend.tick_scale_x, clock_calend.s_scale_ns, clock_calend.s_adj_nsx);
}

static void
clock_get_calendar_absolute_and_microtime_locked(
	clock_sec_t             *secs,
	clock_usec_t            *microsecs,
	uint64_t                *abstime)
{
	uint64_t now;
	struct bintime bt;

	now  = mach_absolute_time();
	if (abstime) {
		*abstime = now;
	}

	bt = get_scaled_time(now);
	bintime_add(&bt, &clock_calend.bintime);
	bintime2usclock(&bt, secs, microsecs);
}

static void
clock_get_calendar_absolute_and_nanotime_locked(
	clock_sec_t             *secs,
	clock_usec_t            *nanosecs,
	uint64_t                *abstime)
{
	uint64_t now;
	struct bintime bt;

	now  = mach_absolute_time();
	if (abstime) {
		*abstime = now;
	}

	bt = get_scaled_time(now);
	bintime_add(&bt, &clock_calend.bintime);
	bintime2nsclock(&bt, secs, nanosecs);
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
	clock_sec_t             *secs,
	clock_usec_t            *microsecs,
	uint64_t                *abstime)
{
	spl_t                   s;

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
	clock_sec_t             *secs,
	clock_nsec_t            *nanosecs)
{
	spl_t                   s;

	s = splclock();
	clock_lock();

	clock_get_calendar_absolute_and_nanotime_locked(secs, nanosecs, NULL);

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
	clock_sec_t     *secs,
	clock_usec_t    *microsecs)
{
	clock_gettimeofday_and_absolute_time(secs, microsecs, NULL);
}

void
clock_gettimeofday_and_absolute_time(
	clock_sec_t     *secs,
	clock_usec_t    *microsecs,
	uint64_t        *mach_time)
{
	uint64_t                now;
	spl_t                   s;
	struct bintime  bt;

	s = splclock();
	clock_lock();

	now = mach_absolute_time();
	bt = get_scaled_time(now);
	bintime_add(&bt, &clock_calend.bintime);
	bintime2usclock(&bt, secs, microsecs);

	clock_gettimeofday_set_commpage(now, bt.sec, bt.frac, clock_calend.tick_scale_x, ticks_per_sec);

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
	clock_sec_t             secs,
	clock_usec_t            microsecs)
{
	uint64_t                absolutesys;
	clock_sec_t             newsecs;
	clock_sec_t             oldsecs;
	clock_usec_t            newmicrosecs;
	clock_usec_t            oldmicrosecs;
	uint64_t                commpage_value;
	spl_t                   s;
	struct bintime          bt;
	clock_sec_t             deltasecs;
	clock_usec_t            deltamicrosecs;

	newsecs = secs;
	newmicrosecs = microsecs;

	/*
	 * settime_lock mtx is used to avoid that racing settimeofdays update the wall clock and
	 * the platform clock concurrently.
	 *
	 * clock_lock cannot be used for this race because it is acquired from interrupt context
	 * and it needs interrupts disabled while instead updating the platform clock needs to be
	 * called with interrupts enabled.
	 */
	lck_mtx_lock(&settime_lock);

	s = splclock();
	clock_lock();

#if DEVELOPMENT || DEBUG
	struct clock_calend clock_calend_cp = clock_calend;
#endif
	commpage_disable_timestamp();

	/*
	 *	Adjust the boottime based on the delta.
	 */
	clock_get_calendar_absolute_and_microtime_locked(&oldsecs, &oldmicrosecs, &absolutesys);

#if DEVELOPMENT || DEBUG
	if (g_should_log_clock_adjustments) {
		os_log(OS_LOG_DEFAULT, "%s wall %lu s %d u computed with %llu abs\n",
		    __func__, (unsigned long)oldsecs, oldmicrosecs, absolutesys);
		os_log(OS_LOG_DEFAULT, "%s requested %lu s %d u\n",
		    __func__, (unsigned long)secs, microsecs );
	}
#endif

	if (oldsecs < secs || (oldsecs == secs && oldmicrosecs < microsecs)) {
		// moving forwards
		deltasecs = secs;
		deltamicrosecs = microsecs;

		TIME_SUB(deltasecs, oldsecs, deltamicrosecs, oldmicrosecs, USEC_PER_SEC);

		TIME_ADD(clock_boottime, deltasecs, clock_boottime_usec, deltamicrosecs, USEC_PER_SEC);
		clock2bintime(&deltasecs, &deltamicrosecs, &bt);
		bintime_add(&clock_calend.boottime, &bt);
	} else {
		// moving backwards
		deltasecs = oldsecs;
		deltamicrosecs = oldmicrosecs;

		TIME_SUB(deltasecs, secs, deltamicrosecs, microsecs, USEC_PER_SEC);

		TIME_SUB(clock_boottime, deltasecs, clock_boottime_usec, deltamicrosecs, USEC_PER_SEC);
		clock2bintime(&deltasecs, &deltamicrosecs, &bt);
		bintime_sub(&clock_calend.boottime, &bt);
	}

	clock_calend.bintime = clock_calend.boottime;
	bintime_add(&clock_calend.bintime, &clock_calend.offset);

	clock2bintime((clock_sec_t *) &secs, (clock_usec_t *) &microsecs, &bt);

	clock_gettimeofday_set_commpage(absolutesys, bt.sec, bt.frac, clock_calend.tick_scale_x, ticks_per_sec);

#if DEVELOPMENT || DEBUG
	struct clock_calend clock_calend_cp1 = clock_calend;
#endif

	commpage_value = clock_boottime * USEC_PER_SEC + clock_boottime_usec;

	clock_unlock();
	splx(s);

	/*
	 *	Set the new value for the platform clock.
	 *	This call might block, so interrupts must be enabled.
	 */
#if DEVELOPMENT || DEBUG
	uint64_t now_b = mach_absolute_time();
#endif

	PESetUTCTimeOfDay(newsecs, newmicrosecs);

#if DEVELOPMENT || DEBUG
	uint64_t now_a = mach_absolute_time();
	if (g_should_log_clock_adjustments) {
		os_log(OS_LOG_DEFAULT, "%s mach bef PESet %llu mach aft %llu \n", __func__, now_b, now_a);
	}
#endif

	print_all_clock_variables_internal(__func__, &clock_calend_cp);
	print_all_clock_variables_internal(__func__, &clock_calend_cp1);

	commpage_update_boottime(commpage_value);

	/*
	 *	Send host notifications.
	 */
	host_notify_calendar_change();
	host_notify_calendar_set();

#if CONFIG_DTRACE
	clock_track_calend_nowait();
#endif

	lck_mtx_unlock(&settime_lock);
}

uint64_t mach_absolutetime_asleep = 0;
uint64_t mach_absolutetime_last_sleep = 0;

void
clock_get_calendar_uptime(clock_sec_t *secs)
{
	uint64_t now;
	spl_t s;
	struct bintime bt;

	s = splclock();
	clock_lock();

	now = mach_absolute_time();

	bt = get_scaled_time(now);
	bintime_add(&bt, &clock_calend.offset);

	*secs = bt.sec;

	clock_unlock();
	splx(s);
}


/*
 * clock_update_calendar:
 *
 * called by ntp timer to update scale factors.
 */
void
clock_update_calendar(void)
{
	uint64_t now, delta;
	struct bintime bt;
	spl_t s;
	int64_t adjustment;

	s = splclock();
	clock_lock();

	now  = mach_absolute_time();

	/*
	 * scale the time elapsed since the last update and
	 * add it to offset.
	 */
	bt = get_scaled_time(now);
	bintime_add(&clock_calend.offset, &bt);

	/*
	 * update the base from which apply next scale factors.
	 */
	delta = now - clock_calend.offset_count;
	clock_calend.offset_count += delta;

	clock_calend.bintime = clock_calend.offset;
	bintime_add(&clock_calend.bintime, &clock_calend.boottime);

	/*
	 * recompute next adjustment.
	 */
	ntp_update_second(&adjustment, clock_calend.bintime.sec);

#if DEVELOPMENT || DEBUG
	if (g_should_log_clock_adjustments) {
		os_log(OS_LOG_DEFAULT, "%s adjustment %lld\n", __func__, adjustment);
	}
#endif

	/*
	 * recomputing scale factors.
	 */
	get_scale_factors_from_adj(adjustment, &clock_calend.tick_scale_x, &clock_calend.s_scale_ns, &clock_calend.s_adj_nsx);

	clock_gettimeofday_set_commpage(now, clock_calend.bintime.sec, clock_calend.bintime.frac, clock_calend.tick_scale_x, ticks_per_sec);

#if DEVELOPMENT || DEBUG
	struct clock_calend calend_cp = clock_calend;
#endif

	clock_unlock();
	splx(s);

	print_all_clock_variables(__func__, NULL, NULL, NULL, NULL, &calend_cp);
}


#if DEVELOPMENT || DEBUG

void
print_all_clock_variables_internal(const char* func, struct clock_calend* clock_calend_cp)
{
	clock_sec_t     offset_secs;
	clock_usec_t    offset_microsecs;
	clock_sec_t     bintime_secs;
	clock_usec_t    bintime_microsecs;
	clock_sec_t     bootime_secs;
	clock_usec_t    bootime_microsecs;

	if (!g_should_log_clock_adjustments) {
		return;
	}

	bintime2usclock(&clock_calend_cp->offset, &offset_secs, &offset_microsecs);
	bintime2usclock(&clock_calend_cp->bintime, &bintime_secs, &bintime_microsecs);
	bintime2usclock(&clock_calend_cp->boottime, &bootime_secs, &bootime_microsecs);

	os_log(OS_LOG_DEFAULT, "%s s_scale_ns %llu s_adj_nsx %lld tick_scale_x %llu offset_count %llu\n",
	    func, clock_calend_cp->s_scale_ns, clock_calend_cp->s_adj_nsx,
	    clock_calend_cp->tick_scale_x, clock_calend_cp->offset_count);
	os_log(OS_LOG_DEFAULT, "%s offset.sec %ld offset.frac %llu offset_secs %lu offset_microsecs %d\n",
	    func, clock_calend_cp->offset.sec, clock_calend_cp->offset.frac,
	    (unsigned long)offset_secs, offset_microsecs);
	os_log(OS_LOG_DEFAULT, "%s bintime.sec %ld bintime.frac %llu bintime_secs %lu bintime_microsecs %d\n",
	    func, clock_calend_cp->bintime.sec, clock_calend_cp->bintime.frac,
	    (unsigned long)bintime_secs, bintime_microsecs);
	os_log(OS_LOG_DEFAULT, "%s bootime.sec %ld bootime.frac %llu bootime_secs %lu bootime_microsecs %d\n",
	    func, clock_calend_cp->boottime.sec, clock_calend_cp->boottime.frac,
	    (unsigned long)bootime_secs, bootime_microsecs);

#if !HAS_CONTINUOUS_HWCLOCK
	clock_sec_t     basesleep_secs;
	clock_usec_t    basesleep_microsecs;

	bintime2usclock(&clock_calend_cp->basesleep, &basesleep_secs, &basesleep_microsecs);
	os_log(OS_LOG_DEFAULT, "%s basesleep.sec %ld basesleep.frac %llu basesleep_secs %lu basesleep_microsecs %d\n",
	    func, clock_calend_cp->basesleep.sec, clock_calend_cp->basesleep.frac,
	    (unsigned long)basesleep_secs, basesleep_microsecs);
#endif
}


void
print_all_clock_variables(const char* func, clock_sec_t* pmu_secs, clock_usec_t* pmu_usec, clock_sec_t* sys_secs, clock_usec_t* sys_usec, struct clock_calend* clock_calend_cp)
{
	if (!g_should_log_clock_adjustments) {
		return;
	}

	struct bintime  bt;
	clock_sec_t     wall_secs;
	clock_usec_t    wall_microsecs;
	uint64_t now;
	uint64_t delta;

	if (pmu_secs) {
		os_log(OS_LOG_DEFAULT, "%s PMU %lu s %d u \n", func, (unsigned long)*pmu_secs, *pmu_usec);
	}
	if (sys_secs) {
		os_log(OS_LOG_DEFAULT, "%s sys %lu s %d u \n", func, (unsigned long)*sys_secs, *sys_usec);
	}

	print_all_clock_variables_internal(func, clock_calend_cp);

	now = mach_absolute_time();
	delta = now - clock_calend_cp->offset_count;

	bt = scale_delta(delta, clock_calend_cp->tick_scale_x, clock_calend_cp->s_scale_ns, clock_calend_cp->s_adj_nsx);
	bintime_add(&bt, &clock_calend_cp->bintime);
	bintime2usclock(&bt, &wall_secs, &wall_microsecs);

	os_log(OS_LOG_DEFAULT, "%s wall %lu s %d u computed with %llu abs\n",
	    func, (unsigned long)wall_secs, wall_microsecs, now);
}


#endif /* DEVELOPMENT || DEBUG */


/*
 *	clock_initialize_calendar:
 *
 *	Set the calendar and related clocks
 *	from the platform clock at boot.
 *
 *	Also sends host notifications.
 */
void
clock_initialize_calendar(void)
{
	clock_sec_t             sys;  // sleepless time since boot in seconds
	clock_sec_t             secs; // Current UTC time
	clock_sec_t             utc_offset_secs; // Difference in current UTC time and sleepless time since boot
	clock_usec_t            microsys;
	clock_usec_t            microsecs;
	clock_usec_t            utc_offset_microsecs;
	spl_t                   s;
	struct bintime          bt;
#if ENABLE_LEGACY_CLOCK_CODE
	struct bintime          monotonic_bt;
	struct latched_time     monotonic_time;
	uint64_t                monotonic_usec_total;
	clock_sec_t             sys2, monotonic_sec;
	clock_usec_t            microsys2, monotonic_usec;
	size_t                  size;

#endif /* ENABLE_LEGACY_CLOCK_CODE */
	//Get the UTC time and corresponding sys time
	PEGetUTCTimeOfDay(&secs, &microsecs);
	clock_get_system_microtime(&sys, &microsys);

#if ENABLE_LEGACY_CLOCK_CODE
	/*
	 * If the platform has a monotonic clock, use kern.monotonicclock_usecs
	 * to estimate the sleep/wake time, otherwise use the UTC time to estimate
	 * the sleep time.
	 */
	size = sizeof(monotonic_time);
	if (kernel_sysctlbyname("kern.monotonicclock_usecs", &monotonic_time, &size, NULL, 0) != 0) {
		has_monotonic_clock = 0;
		os_log(OS_LOG_DEFAULT, "%s system does not have monotonic clock\n", __func__);
	} else {
		has_monotonic_clock = 1;
		monotonic_usec_total = monotonic_time.monotonic_time_usec;
		absolutetime_to_microtime(monotonic_time.mach_time, &sys2, &microsys2);
		os_log(OS_LOG_DEFAULT, "%s system has monotonic clock\n", __func__);
	}
#endif /* ENABLE_LEGACY_CLOCK_CODE */

	s = splclock();
	clock_lock();

	commpage_disable_timestamp();

	utc_offset_secs = secs;
	utc_offset_microsecs = microsecs;

	/*
	 * We normally expect the UTC clock to be always-on and produce
	 * greater readings than the tick counter.  There may be corner cases
	 * due to differing clock resolutions (UTC clock is likely lower) and
	 * and errors reading the UTC clock (some implementations return 0
	 * on error) in which that doesn't hold true.  Bring the UTC measurements
	 * in-line with the tick counter measurements as a best effort in that case.
	 */
	if ((sys > secs) || ((sys == secs) && (microsys > microsecs))) {
		os_log(OS_LOG_DEFAULT, "%s WARNING: UTC time is less then sys time, (%lu s %d u) UTC (%lu s %d u) sys\n",
		    __func__, (unsigned long) secs, microsecs, (unsigned long)sys, microsys);
		secs = utc_offset_secs = sys;
		microsecs = utc_offset_microsecs = microsys;
	}

	// UTC - sys
	// This macro stores the subtraction result in utc_offset_secs and utc_offset_microsecs
	TIME_SUB(utc_offset_secs, sys, utc_offset_microsecs, microsys, USEC_PER_SEC);
	// This function converts utc_offset_secs and utc_offset_microsecs in bintime
	clock2bintime(&utc_offset_secs, &utc_offset_microsecs, &bt);

	/*
	 *	Initialize the boot time based on the platform clock.
	 */
	clock_boottime = secs;
	clock_boottime_usec = microsecs;
	commpage_update_boottime(clock_boottime * USEC_PER_SEC + clock_boottime_usec);

	nanoseconds_to_absolutetime((uint64_t)NSEC_PER_SEC, &ticks_per_sec);
	clock_calend.boottime = bt;
	clock_calend.bintime = bt;
	clock_calend.offset.sec = 0;
	clock_calend.offset.frac = 0;

	clock_calend.tick_scale_x = (uint64_t)1 << 63;
	clock_calend.tick_scale_x /= ticks_per_sec;
	clock_calend.tick_scale_x *= 2;

	clock_calend.s_scale_ns = NSEC_PER_SEC;
	clock_calend.s_adj_nsx = 0;

#if ENABLE_LEGACY_CLOCK_CODE
	if (has_monotonic_clock) {
		monotonic_sec = monotonic_usec_total / (clock_sec_t)USEC_PER_SEC;
		monotonic_usec = monotonic_usec_total % (clock_usec_t)USEC_PER_SEC;

		// monotonic clock - sys
		// This macro stores the subtraction result in monotonic_sec and monotonic_usec
		TIME_SUB(monotonic_sec, sys2, monotonic_usec, microsys2, USEC_PER_SEC);
		clock2bintime(&monotonic_sec, &monotonic_usec, &monotonic_bt);

		// set the baseleep as the difference between monotonic clock - sys
		clock_calend.basesleep = monotonic_bt;
	}
#endif /* ENABLE_LEGACY_CLOCK_CODE */
	commpage_update_mach_continuous_time(mach_absolutetime_asleep);

#if DEVELOPMENT || DEBUG
	struct clock_calend clock_calend_cp = clock_calend;
#endif

	clock_unlock();
	splx(s);

	print_all_clock_variables(__func__, &secs, &microsecs, &sys, &microsys, &clock_calend_cp);

	/*
	 *	Send host notifications.
	 */
	host_notify_calendar_change();

#if CONFIG_DTRACE
	clock_track_calend_nowait();
#endif
}

#if HAS_CONTINUOUS_HWCLOCK

static void
scale_sleep_time(void)
{
	/* Apply the current NTP frequency adjustment to the time slept.
	 * The frequency adjustment remains stable between calls to ntp_adjtime(),
	 * and should thus provide a reasonable approximation of the total adjustment
	 * required for the time slept. */
	struct bintime sleep_time;
	uint64_t tick_scale_x, s_scale_ns;
	int64_t s_adj_nsx;
	int64_t sleep_adj = ntp_get_freq();
	if (sleep_adj) {
		get_scale_factors_from_adj(sleep_adj, &tick_scale_x, &s_scale_ns, &s_adj_nsx);
		sleep_time = scale_delta(mach_absolutetime_last_sleep, tick_scale_x, s_scale_ns, s_adj_nsx);
	} else {
		tick_scale_x = (uint64_t)1 << 63;
		tick_scale_x /= ticks_per_sec;
		tick_scale_x *= 2;
		sleep_time.sec = mach_absolutetime_last_sleep / ticks_per_sec;
		sleep_time.frac = (mach_absolutetime_last_sleep % ticks_per_sec) * tick_scale_x;
	}
	bintime_add(&clock_calend.offset, &sleep_time);
	bintime_add(&clock_calend.bintime, &sleep_time);
}

static void
clock_wakeup_calendar_hwclock(void)
{
	spl_t   s;

	s = splclock();
	clock_lock();

	commpage_disable_timestamp();

	uint64_t abstime = mach_absolute_time();
	uint64_t total_sleep_time = mach_continuous_time() - abstime;

	mach_absolutetime_last_sleep = total_sleep_time - mach_absolutetime_asleep;
	mach_absolutetime_asleep = total_sleep_time;

	scale_sleep_time();

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_CLOCK, MACH_EPOCH_CHANGE),
	    (uintptr_t)mach_absolutetime_last_sleep,
	    (uintptr_t)mach_absolutetime_asleep,
	    (uintptr_t)(mach_absolutetime_last_sleep >> 32),
	    (uintptr_t)(mach_absolutetime_asleep >> 32));

	commpage_update_mach_continuous_time(mach_absolutetime_asleep);
#if HIBERNATION
	commpage_update_mach_continuous_time_hw_offset(hwclock_conttime_offset);
#endif
	adjust_cont_time_thread_calls();

	clock_unlock();
	splx(s);

	host_notify_calendar_change();

#if CONFIG_DTRACE
	clock_track_calend_nowait();
#endif
}

#endif /* HAS_CONTINUOUS_HWCLOCK */

#if ENABLE_LEGACY_CLOCK_CODE

static void
clock_wakeup_calendar_legacy(void)
{
	clock_sec_t             wake_sys_sec;
	clock_usec_t            wake_sys_usec;
	clock_sec_t             wake_sec;
	clock_usec_t            wake_usec;
	clock_sec_t             wall_time_sec;
	clock_usec_t            wall_time_usec;
	clock_sec_t             diff_sec;
	clock_usec_t            diff_usec;
	clock_sec_t             var_s;
	clock_usec_t            var_us;
	spl_t                   s;
	struct bintime          bt, last_sleep_bt;
	struct latched_time     monotonic_time;
	uint64_t                monotonic_usec_total;
	uint64_t                wake_abs;
	size_t                  size;

	/*
	 * If the platform has the monotonic clock use that to
	 * compute the sleep time. The monotonic clock does not have an offset
	 * that can be modified, so nor kernel or userspace can change the time
	 * of this clock, it can only monotonically increase over time.
	 * During sleep mach_absolute_time (sys time) does not tick,
	 * so the sleep time is the difference between the current monotonic time
	 * less the absolute time and the previous difference stored at wake time.
	 *
	 * basesleep = (monotonic - sys) ---> computed at last wake
	 * sleep_time = (monotonic - sys) - basesleep
	 *
	 * If the platform does not support monotonic clock we set the wall time to what the
	 * UTC clock returns us.
	 * Setting the wall time to UTC time implies that we loose all the adjustments
	 * done during wake time through adjtime/ntp_adjustime.
	 * The UTC time is the monotonic clock + an offset that can be set
	 * by kernel.
	 * The time slept in this case is the difference between wall time and UTC
	 * at wake.
	 *
	 * IMPORTANT:
	 * We assume that only the kernel is setting the offset of the PMU/RTC and that
	 * it is doing it only througth the settimeofday interface.
	 */
	if (has_monotonic_clock) {
#if DEVELOPMENT || DEBUG
		/*
		 * Just for debugging, get the wake UTC time.
		 */
		PEGetUTCTimeOfDay(&var_s, &var_us);
#endif
		/*
		 * Get monotonic time with corresponding sys time
		 */
		size = sizeof(monotonic_time);
		if (kernel_sysctlbyname("kern.monotonicclock_usecs", &monotonic_time, &size, NULL, 0) != 0) {
			panic("%s: could not call kern.monotonicclock_usecs", __func__);
		}
		wake_abs = monotonic_time.mach_time;
		absolutetime_to_microtime(wake_abs, &wake_sys_sec, &wake_sys_usec);

		monotonic_usec_total = monotonic_time.monotonic_time_usec;
		wake_sec = monotonic_usec_total / (clock_sec_t)USEC_PER_SEC;
		wake_usec = monotonic_usec_total % (clock_usec_t)USEC_PER_SEC;
	} else {
		/*
		 * Get UTC time and corresponding sys time
		 */
		PEGetUTCTimeOfDay(&wake_sec, &wake_usec);
		wake_abs = mach_absolute_time();
		absolutetime_to_microtime(wake_abs, &wake_sys_sec, &wake_sys_usec);
	}

#if DEVELOPMENT || DEBUG
	os_log(OS_LOG_DEFAULT, "time at wake %lu s %d u from %s clock, abs %llu\n", (unsigned long)wake_sec, wake_usec, (has_monotonic_clock)?"monotonic":"UTC", wake_abs);
	if (has_monotonic_clock) {
		os_log(OS_LOG_DEFAULT, "UTC time %lu s %d u\n", (unsigned long)var_s, var_us);
	}
#endif /* DEVELOPMENT || DEBUG */

	s = splclock();
	clock_lock();

	commpage_disable_timestamp();

#if DEVELOPMENT || DEBUG
	struct clock_calend clock_calend_cp1 = clock_calend;
#endif /* DEVELOPMENT || DEBUG */

	/*
	 * We normally expect the UTC/monotonic clock to be always-on and produce
	 * greater readings than the sys counter.  There may be corner cases
	 * due to differing clock resolutions (UTC/monotonic clock is likely lower) and
	 * and errors reading the UTC/monotonic clock (some implementations return 0
	 * on error) in which that doesn't hold true.
	 */
	if ((wake_sys_sec > wake_sec) || ((wake_sys_sec == wake_sec) && (wake_sys_usec > wake_usec))) {
		os_log_error(OS_LOG_DEFAULT, "WARNING: %s clock is less then sys clock at wake: %lu s %d u vs %lu s %d u, defaulting sleep time to zero\n", (has_monotonic_clock)?"monotonic":"UTC", (unsigned long)wake_sec, wake_usec, (unsigned long)wake_sys_sec, wake_sys_usec);
		mach_absolutetime_last_sleep = 0;
		goto done;
	}

	if (has_monotonic_clock) {
		/*
		 * computer the difference monotonic - sys
		 * we already checked that monotonic time is
		 * greater than sys.
		 */
		diff_sec = wake_sec;
		diff_usec = wake_usec;
		// This macro stores the subtraction result in diff_sec and diff_usec
		TIME_SUB(diff_sec, wake_sys_sec, diff_usec, wake_sys_usec, USEC_PER_SEC);
		//This function converts diff_sec and diff_usec in bintime
		clock2bintime(&diff_sec, &diff_usec, &bt);

		/*
		 * Safety belt: the monotonic clock will likely have a lower resolution than the sys counter.
		 * It's also possible that the device didn't fully transition to the powered-off state on
		 * the most recent sleep, so the sys counter may not have reset or may have only briefly
		 * turned off.  In that case it's possible for the difference between the monotonic clock and the
		 * sys counter to be less than the previously recorded value in clock.calend.basesleep.
		 * In that case simply record that we slept for 0 ticks.
		 */
		if ((bt.sec > clock_calend.basesleep.sec) ||
		    ((bt.sec == clock_calend.basesleep.sec) && (bt.frac > clock_calend.basesleep.frac))) {
			//last_sleep is the difference between (current monotonic - abs) and (last wake monotonic - abs)
			last_sleep_bt = bt;
			bintime_sub(&last_sleep_bt, &clock_calend.basesleep);

			bintime2absolutetime(&last_sleep_bt, &mach_absolutetime_last_sleep);
			mach_absolutetime_asleep += mach_absolutetime_last_sleep;

			//set basesleep to current monotonic - abs
			clock_calend.basesleep = bt;

			//update wall time
			bintime_add(&clock_calend.offset, &last_sleep_bt);
			bintime_add(&clock_calend.bintime, &last_sleep_bt);

			bintime2usclock(&last_sleep_bt, &var_s, &var_us);
			os_log(OS_LOG_DEFAULT, "time_slept (%lu s %d u)\n", (unsigned long) var_s, var_us);
		} else {
			bintime2usclock(&clock_calend.basesleep, &var_s, &var_us);
			os_log_error(OS_LOG_DEFAULT, "WARNING: last wake monotonic-sys time (%lu s %d u) is greater then current monotonic-sys time(%lu s %d u), defaulting sleep time to zero\n", (unsigned long) var_s, var_us, (unsigned long) diff_sec, diff_usec);

			mach_absolutetime_last_sleep = 0;
		}
	} else {
		/*
		 * set the wall time to UTC value
		 */
		bt = get_scaled_time(wake_abs);
		bintime_add(&bt, &clock_calend.bintime);
		bintime2usclock(&bt, &wall_time_sec, &wall_time_usec);

		if (wall_time_sec > wake_sec || (wall_time_sec == wake_sec && wall_time_usec > wake_usec)) {
			os_log(OS_LOG_DEFAULT, "WARNING: wall time (%lu s %d u) is greater than current UTC time (%lu s %d u), defaulting sleep time to zero\n", (unsigned long) wall_time_sec, wall_time_usec, (unsigned long) wake_sec, wake_usec);

			mach_absolutetime_last_sleep = 0;
		} else {
			diff_sec = wake_sec;
			diff_usec = wake_usec;
			// This macro stores the subtraction result in diff_sec and diff_usec
			TIME_SUB(diff_sec, wall_time_sec, diff_usec, wall_time_usec, USEC_PER_SEC);
			//This function converts diff_sec and diff_usec in bintime
			clock2bintime(&diff_sec, &diff_usec, &bt);

			//time slept in this case is the difference between PMU/RTC and wall time
			last_sleep_bt = bt;

			bintime2absolutetime(&last_sleep_bt, &mach_absolutetime_last_sleep);
			mach_absolutetime_asleep += mach_absolutetime_last_sleep;

			//update wall time
			bintime_add(&clock_calend.offset, &last_sleep_bt);
			bintime_add(&clock_calend.bintime, &last_sleep_bt);

			bintime2usclock(&last_sleep_bt, &var_s, &var_us);
			os_log(OS_LOG_DEFAULT, "time_slept (%lu s %d u)\n", (unsigned long)var_s, var_us);
		}
	}
done:
	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_CLOCK, MACH_EPOCH_CHANGE),
	    (uintptr_t)mach_absolutetime_last_sleep,
	    (uintptr_t)mach_absolutetime_asleep,
	    (uintptr_t)(mach_absolutetime_last_sleep >> 32),
	    (uintptr_t)(mach_absolutetime_asleep >> 32));

	commpage_update_mach_continuous_time(mach_absolutetime_asleep);
	adjust_cont_time_thread_calls();

#if DEVELOPMENT || DEBUG
	struct clock_calend clock_calend_cp = clock_calend;
#endif

	clock_unlock();
	splx(s);

#if DEVELOPMENT || DEBUG
	if (g_should_log_clock_adjustments) {
		print_all_clock_variables("clock_wakeup_calendar: BEFORE", NULL, NULL, NULL, NULL, &clock_calend_cp1);
		print_all_clock_variables("clock_wakeup_calendar: AFTER", NULL, NULL, NULL, NULL, &clock_calend_cp);
	}
#endif /* DEVELOPMENT || DEBUG */

	host_notify_calendar_change();

#if CONFIG_DTRACE
	clock_track_calend_nowait();
#endif
}

#endif /* ENABLE_LEGACY_CLOCK_CODE */

void
clock_wakeup_calendar(void)
{
#if HAS_CONTINUOUS_HWCLOCK
#if HIBERNATION_USES_LEGACY_CLOCK
	if (gIOHibernateState) {
		// if we're resuming from hibernation, we have to take the legacy wakeup path
		return clock_wakeup_calendar_legacy();
	}
#endif /* HIBERNATION_USES_LEGACY_CLOCK */
	// use the hwclock wakeup path
	return clock_wakeup_calendar_hwclock();
#elif ENABLE_LEGACY_CLOCK_CODE
	return clock_wakeup_calendar_legacy();
#else
#error "can't determine which clock code to run"
#endif
}

/*
 *	clock_get_boottime_nanotime:
 *
 *	Return the boottime, used by sysctl.
 */
void
clock_get_boottime_nanotime(
	clock_sec_t                     *secs,
	clock_nsec_t            *nanosecs)
{
	spl_t   s;

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
	clock_sec_t                     *secs,
	clock_usec_t            *microsecs)
{
	spl_t   s;

	s = splclock();
	clock_lock();

	*secs = (clock_sec_t)clock_boottime;
	*microsecs = (clock_nsec_t)clock_boottime_usec;

	clock_unlock();
	splx(s);
}


/*
 *	Wait / delay routines.
 */
static void
mach_wait_until_continue(
	__unused void   *parameter,
	wait_result_t   wresult)
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
	struct mach_wait_until_trap_args        *args)
{
	uint64_t                deadline = args->deadline;
	wait_result_t   wresult;


	wresult = assert_wait_deadline_with_leeway((event_t)mach_wait_until_trap, THREAD_ABORTSAFE,
	    TIMEOUT_URGENCY_USER_NORMAL, deadline, 0);
	if (wresult == THREAD_WAITING) {
		wresult = thread_block(mach_wait_until_continue);
	}

	return (wresult == THREAD_INTERRUPTED)? KERN_ABORTED: KERN_SUCCESS;
}

void
clock_delay_until(
	uint64_t                deadline)
{
	uint64_t                now = mach_absolute_time();

	if (now >= deadline) {
		return;
	}

	_clock_delay_until_deadline(deadline - now, deadline);
}

/*
 * Preserve the original precise interval that the client
 * requested for comparison to the spin threshold.
 */
void
_clock_delay_until_deadline(
	uint64_t                interval,
	uint64_t                deadline)
{
	_clock_delay_until_deadline_with_leeway(interval, deadline, 0);
}

/*
 * Like _clock_delay_until_deadline, but it accepts a
 * leeway value.
 */
void
_clock_delay_until_deadline_with_leeway(
	uint64_t                interval,
	uint64_t                deadline,
	uint64_t                leeway)
{
	if (interval == 0) {
		return;
	}

	if (ml_delay_should_spin(interval) ||
	    get_preemption_level() != 0 ||
	    ml_get_interrupts_enabled() == FALSE) {
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
	uint32_t                interval,
	uint32_t                scale_factor)
{
	uint64_t                abstime;

	clock_interval_to_absolutetime_interval(interval, scale_factor, &abstime);

	_clock_delay_until_deadline(abstime, mach_absolute_time() + abstime);
}

void
delay_for_interval_with_leeway(
	uint32_t                interval,
	uint32_t                leeway,
	uint32_t                scale_factor)
{
	uint64_t                abstime_interval;
	uint64_t                abstime_leeway;

	clock_interval_to_absolutetime_interval(interval, scale_factor, &abstime_interval);
	clock_interval_to_absolutetime_interval(leeway, scale_factor, &abstime_leeway);

	_clock_delay_until_deadline_with_leeway(abstime_interval, mach_absolute_time() + abstime_interval, abstime_leeway);
}

void
delay(
	int             usec)
{
	delay_for_interval((usec < 0)? -usec: usec, NSEC_PER_USEC);
}

/*
 *	Miscellaneous routines.
 */
void
clock_interval_to_deadline(
	uint32_t                        interval,
	uint32_t                        scale_factor,
	uint64_t                        *result)
{
	uint64_t        abstime;

	clock_interval_to_absolutetime_interval(interval, scale_factor, &abstime);

	if (os_add_overflow(mach_absolute_time(), abstime, result)) {
		*result = UINT64_MAX;
	}
}

void
nanoseconds_to_deadline(
	uint64_t                        interval,
	uint64_t                        *result)
{
	uint64_t        abstime;

	nanoseconds_to_absolutetime(interval, &abstime);

	if (os_add_overflow(mach_absolute_time(), abstime, result)) {
		*result = UINT64_MAX;
	}
}

void
clock_absolutetime_interval_to_deadline(
	uint64_t                        abstime,
	uint64_t                        *result)
{
	if (os_add_overflow(mach_absolute_time(), abstime, result)) {
		*result = UINT64_MAX;
	}
}

void
clock_continuoustime_interval_to_deadline(
	uint64_t                        conttime,
	uint64_t                        *result)
{
	if (os_add_overflow(mach_continuous_time(), conttime, result)) {
		*result = UINT64_MAX;
	}
}

void
clock_get_uptime(
	uint64_t        *result)
{
	*result = mach_absolute_time();
}

void
clock_deadline_for_periodic_event(
	uint64_t                        interval,
	uint64_t                        abstime,
	uint64_t                        *deadline)
{
	assert(interval != 0);

	// *deadline += interval;
	if (os_add_overflow(*deadline, interval, deadline)) {
		*deadline = UINT64_MAX;
	}

	if (*deadline <= abstime) {
		// *deadline = abstime + interval;
		if (os_add_overflow(abstime, interval, deadline)) {
			*deadline = UINT64_MAX;
		}

		abstime = mach_absolute_time();
		if (*deadline <= abstime) {
			// *deadline = abstime + interval;
			if (os_add_overflow(abstime, interval, deadline)) {
				*deadline = UINT64_MAX;
			}
		}
	}
}

uint64_t
mach_continuous_time(void)
{
#if HIBERNATION && HAS_CONTINUOUS_HWCLOCK
	return ml_get_hwclock() + hwclock_conttime_offset;
#elif HAS_CONTINUOUS_HWCLOCK
	return ml_get_hwclock();
#else
	while (1) {
		uint64_t read1 = mach_absolutetime_asleep;
		uint64_t absolute = mach_absolute_time();
		OSMemoryBarrier();
		uint64_t read2 = mach_absolutetime_asleep;

		if (__builtin_expect(read1 == read2, 1)) {
			return absolute + read1;
		}
	}
#endif
}

uint64_t
mach_continuous_approximate_time(void)
{
#if HAS_CONTINUOUS_HWCLOCK
	return mach_continuous_time();
#else
	while (1) {
		uint64_t read1 = mach_absolutetime_asleep;
		uint64_t absolute = mach_approximate_time();
		OSMemoryBarrier();
		uint64_t read2 = mach_absolutetime_asleep;

		if (__builtin_expect(read1 == read2, 1)) {
			return absolute + read1;
		}
	}
#endif
}

/*
 * continuoustime_to_absolutetime
 * Must be called with interrupts disabled
 * Returned value is only valid until the next update to
 * mach_continuous_time
 */
uint64_t
continuoustime_to_absolutetime(uint64_t conttime)
{
	if (conttime <= mach_absolutetime_asleep) {
		return 0;
	} else {
		return conttime - mach_absolutetime_asleep;
	}
}

/*
 * absolutetime_to_continuoustime
 * Must be called with interrupts disabled
 * Returned value is only valid until the next update to
 * mach_continuous_time
 */
uint64_t
absolutetime_to_continuoustime(uint64_t abstime)
{
	return abstime + mach_absolutetime_asleep;
}

#if     CONFIG_DTRACE

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
	clock_sec_t                     *secs,
	clock_nsec_t            *nanosecs)
{
	int i = 0;
	uint64_t                now;
	struct unlocked_clock_calend stable;
	struct bintime bt;

	for (;;) {
		stable = flipflop[i];           /* take snapshot */

		/*
		 * Use a barrier instructions to ensure atomicity.  We AND
		 * off the "in progress" bit to get the current generation
		 * count.
		 */
		os_atomic_andnot(&stable.gen, 1, relaxed);

		/*
		 * If an update _is_ in progress, the generation count will be
		 * off by one, if it _was_ in progress, it will be off by two,
		 * and if we caught it at a good time, it will be equal (and
		 * our snapshot is threfore stable).
		 */
		if (flipflop[i].gen == stable.gen) {
			break;
		}

		/* Switch to the other element of the flipflop, and try again. */
		i ^= 1;
	}

	now = mach_absolute_time();

	bt = get_scaled_time(now);

	bintime_add(&bt, &clock_calend.bintime);

	bintime2nsclock(&bt, secs, nanosecs);
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
		os_atomic_or(&flipflop[i].gen, 1, relaxed);

		flipflop[i].calend = tmp;

		/*
		 * Increment the generation count to clear the low bit to
		 * signal completion.  If a caller compares the generation
		 * count after taking a copy while in progress, the count
		 * will be off by two.
		 */
		os_atomic_inc(&flipflop[i].gen, relaxed);
	}
}

#endif  /* CONFIG_DTRACE */

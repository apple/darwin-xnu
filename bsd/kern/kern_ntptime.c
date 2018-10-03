/*-
 ***********************************************************************
 *								       *
 * Copyright (c) David L. Mills 1993-2001			       *
 *								       *
 * Permission to use, copy, modify, and distribute this software and   *
 * its documentation for any purpose and without fee is hereby	       *
 * granted, provided that the above copyright notice appears in all    *
 * copies and that both the copyright notice and this permission       *
 * notice appear in supporting documentation, and that the name	       *
 * University of Delaware not be used in advertising or publicity      *
 * pertaining to distribution of the software without specific,	       *
 * written prior permission. The University of Delaware makes no       *
 * representations about the suitability this software for any	       *
 * purpose. It is provided "as is" without express or implied	       *
 * warranty.							       *
 *								       *
 **********************************************************************/


/*
 * Adapted from the original sources for FreeBSD and timecounters by:
 * Poul-Henning Kamp <phk@FreeBSD.org>.
 *
 * The 32bit version of the "LP" macros seems a bit past its "sell by"
 * date so I have retained only the 64bit version and included it directly
 * in this file.
 *
 * Only minor changes done to interface with the timecounters over in
 * sys/kern/kern_clock.c.   Some of the comments below may be (even more)
 * confusing and/or plain wrong in that context.
 */

/*
 * Copyright (c) 2017 Apple Computer, Inc. All rights reserved.
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

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <kern/clock.h>
#include <sys/sysctl.h>
#include <sys/sysproto.h>
#include <sys/kauth.h>
#include <kern/thread_call.h>
#include <kern/timer_call.h>
#include <machine/machine_routines.h>
#if CONFIG_MACF
#include <security/mac_framework.h>
#endif
#include <IOKit/IOBSD.h>
#include <os/log.h>

typedef int64_t l_fp;
#define L_ADD(v, u)	((v) += (u))
#define L_SUB(v, u)	((v) -= (u))
#define L_ADDHI(v, a)	((v) += (int64_t)(a) << 32)
#define L_NEG(v)	((v) = -(v))
#define L_RSHIFT(v, n) \
	do { \
		if ((v) < 0) \
			(v) = -(-(v) >> (n)); \
		else \
			(v) = (v) >> (n); \
	} while (0)
#define L_MPY(v, a)	((v) *= (a))
#define L_CLR(v)	((v) = 0)
#define L_ISNEG(v)	((v) < 0)
#define L_LINT(v, a) \
	do { \
		if ((a) > 0) \
			((v) = (int64_t)(a) << 32); \
		else \
			((v) = -((int64_t)(-(a)) << 32)); \
	} while (0)
#define L_GINT(v)	((v) < 0 ? -(-(v) >> 32) : (v) >> 32)

/*
 * Generic NTP kernel interface
 *
 * These routines constitute the Network Time Protocol (NTP) interfaces
 * for user and daemon application programs. The ntp_gettime() routine
 * provides the time, maximum error (synch distance) and estimated error
 * (dispersion) to client user application programs. The ntp_adjtime()
 * routine is used by the NTP daemon to adjust the calendar clock to an
 * externally derived time. The time offset and related variables set by
 * this routine are used by other routines in this module to adjust the
 * phase and frequency of the clock discipline loop which controls the
 * system clock.
 *
 * When the kernel time is reckoned directly in nanoseconds (NTP_NANO
 * defined), the time at each tick interrupt is derived directly from
 * the kernel time variable. When the kernel time is reckoned in
 * microseconds, (NTP_NANO undefined), the time is derived from the
 * kernel time variable together with a variable representing the
 * leftover nanoseconds at the last tick interrupt. In either case, the
 * current nanosecond time is reckoned from these values plus an
 * interpolated value derived by the clock routines in another
 * architecture-specific module. The interpolation can use either a
 * dedicated counter or a processor cycle counter (PCC) implemented in
 * some architectures.
 *
 */
/*
 * Phase/frequency-lock loop (PLL/FLL) definitions
 *
 * The nanosecond clock discipline uses two variable types, time
 * variables and frequency variables. Both types are represented as 64-
 * bit fixed-point quantities with the decimal point between two 32-bit
 * halves. On a 32-bit machine, each half is represented as a single
 * word and mathematical operations are done using multiple-precision
 * arithmetic. On a 64-bit machine, ordinary computer arithmetic is
 * used.
 *
 * A time variable is a signed 64-bit fixed-point number in ns and
 * fraction. It represents the remaining time offset to be amortized
 * over succeeding tick interrupts. The maximum time offset is about
 * 0.5 s and the resolution is about 2.3e-10 ns.
 *
 *			1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |s s s|			 ns				   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |			    fraction				   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * A frequency variable is a signed 64-bit fixed-point number in ns/s
 * and fraction. It represents the ns and fraction to be added to the
 * kernel time variable at each second. The maximum frequency offset is
 * about +-500000 ns/s and the resolution is about 2.3e-10 ns/s.
 *
 *			1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |s s s s s s s s s s s s s|	          ns/s			   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |			    fraction				   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define SHIFT_PLL	4
#define SHIFT_FLL	2

static int time_state = TIME_OK;
int time_status = STA_UNSYNC;
static long time_tai;
static long time_constant;
static long time_precision = 1;
static long time_maxerror = MAXPHASE / 1000;
static unsigned long last_time_maxerror_update;
long time_esterror = MAXPHASE / 1000;
static long time_reftime;
static l_fp time_offset;
static l_fp time_freq;
static int64_t time_adjtime;
static int updated;

static lck_spin_t * ntp_lock;
static lck_grp_t * ntp_lock_grp;
static lck_attr_t * ntp_lock_attr;
static lck_grp_attr_t	*ntp_lock_grp_attr;

#define	NTP_LOCK(enable) \
		enable =  ml_set_interrupts_enabled(FALSE); \
		lck_spin_lock(ntp_lock);

#define	NTP_UNLOCK(enable) \
		lck_spin_unlock(ntp_lock);\
		ml_set_interrupts_enabled(enable);

#define	NTP_ASSERT_LOCKED()	LCK_SPIN_ASSERT(ntp_lock, LCK_ASSERT_OWNED)

static timer_call_data_t ntp_loop_update;
static uint64_t ntp_loop_deadline;
static uint32_t ntp_loop_active;
static uint32_t ntp_loop_period;
#define NTP_LOOP_PERIOD_INTERVAL (NSEC_PER_SEC) /*1 second interval*/

void ntp_init(void);
static void hardupdate(long offset);
static void ntp_gettime1(struct ntptimeval *ntvp);
static bool ntp_is_time_error(int tsl);

static void ntp_loop_update_call(void);
static void refresh_ntp_loop(void);
static void start_ntp_loop(void);

#if DEVELOPMENT || DEBUG
uint32_t g_should_log_clock_adjustments = 0;
SYSCTL_INT(_kern, OID_AUTO, log_clock_adjustments, CTLFLAG_RW | CTLFLAG_LOCKED, &g_should_log_clock_adjustments, 0, "enable kernel clock adjustment logging");
#endif

static bool
ntp_is_time_error(int tsl)
{

	if (tsl & (STA_UNSYNC | STA_CLOCKERR))
		return (true);

	return (false);
}

static void
ntp_gettime1(struct ntptimeval *ntvp)
{
	struct timespec atv;

	NTP_ASSERT_LOCKED();

	nanotime(&atv);
	ntvp->time.tv_sec = atv.tv_sec;
	ntvp->time.tv_nsec = atv.tv_nsec;
	if ((unsigned long)atv.tv_sec > last_time_maxerror_update) {
		time_maxerror += (MAXFREQ / 1000)*(atv.tv_sec-last_time_maxerror_update);
		last_time_maxerror_update = atv.tv_sec;
	}
	ntvp->maxerror = time_maxerror;
	ntvp->esterror = time_esterror;
	ntvp->tai = time_tai;
	ntvp->time_state = time_state;

	if (ntp_is_time_error(time_status))
		ntvp->time_state = TIME_ERROR;
}

int
ntp_gettime(struct proc *p, struct ntp_gettime_args *uap, __unused int32_t *retval)
{
	struct ntptimeval ntv;
	int error;
	boolean_t enable;

	NTP_LOCK(enable);
	ntp_gettime1(&ntv);
	NTP_UNLOCK(enable);

	if (IS_64BIT_PROCESS(p)) {
		struct user64_ntptimeval user_ntv = {};
		user_ntv.time.tv_sec = ntv.time.tv_sec;
		user_ntv.time.tv_nsec = ntv.time.tv_nsec;
		user_ntv.maxerror = ntv.maxerror;
		user_ntv.esterror = ntv.esterror;
		user_ntv.tai = ntv.tai;
		user_ntv.time_state = ntv.time_state;
		error = copyout(&user_ntv, uap->ntvp, sizeof(user_ntv));
	} else {
		struct user32_ntptimeval user_ntv = {};
		user_ntv.time.tv_sec = ntv.time.tv_sec;
		user_ntv.time.tv_nsec = ntv.time.tv_nsec;
		user_ntv.maxerror = ntv.maxerror;
		user_ntv.esterror = ntv.esterror;
		user_ntv.tai = ntv.tai;
		user_ntv.time_state = ntv.time_state;
		error = copyout(&user_ntv, uap->ntvp, sizeof(user_ntv));
	}

	if (error)
		return error;

	return ntv.time_state;
}

int
ntp_adjtime(struct proc *p, struct ntp_adjtime_args *uap, __unused int32_t *retval)
{
	struct timex ntv;
	long freq;
	int modes;
	int error, ret = 0;
	clock_sec_t sec;
	clock_usec_t microsecs;
	boolean_t enable;

	if (IS_64BIT_PROCESS(p)) {
		struct user64_timex user_ntv;
		error = copyin(uap->tp, &user_ntv, sizeof(user_ntv));
		ntv.modes = user_ntv.modes;
		ntv.offset = user_ntv.offset;
		ntv.freq = user_ntv.freq;
		ntv.maxerror = user_ntv.maxerror;
		ntv.esterror = user_ntv.esterror;
		ntv.status = user_ntv.status;
		ntv.constant = user_ntv.constant;
		ntv.precision = user_ntv.precision;
		ntv.tolerance = user_ntv.tolerance;

	} else {
		struct user32_timex user_ntv;
		error = copyin(uap->tp, &user_ntv, sizeof(user_ntv));
		ntv.modes = user_ntv.modes;
		ntv.offset = user_ntv.offset;
		ntv.freq = user_ntv.freq;
		ntv.maxerror = user_ntv.maxerror;
		ntv.esterror = user_ntv.esterror;
		ntv.status = user_ntv.status;
		ntv.constant = user_ntv.constant;
		ntv.precision = user_ntv.precision;
		ntv.tolerance = user_ntv.tolerance;
	}
	if (error)
		return (error);

#if DEVELOPEMNT || DEBUG
	if (g_should_log_clock_adjustments) {
		os_log(OS_LOG_DEFAULT, "%s:BEFORE modes %u offset %ld freq %ld status %d constant %ld time_adjtime %lld\n",
		       __func__, ntv.modes, ntv.offset, ntv.freq, ntv.status, ntv.constant, time_adjtime);
	}
#endif
	/*
	 * Update selected clock variables - only the superuser can
	 * change anything. Note that there is no error checking here on
	 * the assumption the superuser should know what it is doing.
	 * Note that either the time constant or TAI offset are loaded
	 * from the ntv.constant member, depending on the mode bits. If
	 * the STA_PLL bit in the status word is cleared, the state and
	 * status words are reset to the initial values at boot.
	 */
	modes = ntv.modes;
	if (modes) {
		/* Check that this task is entitled to set the time or it is root */
		if (!IOTaskHasEntitlement(current_task(), SETTIME_ENTITLEMENT)) {
#if CONFIG_MACF
			error = mac_system_check_settime(kauth_cred_get());
			if (error)
				return (error);
#endif
			if ((error = priv_check_cred(kauth_cred_get(), PRIV_ADJTIME, 0)))
				return (error);

		}
	}

	NTP_LOCK(enable);

	if (modes & MOD_MAXERROR) {
		clock_gettimeofday(&sec, &microsecs);
		time_maxerror = ntv.maxerror;
		last_time_maxerror_update = sec;
	}
	if (modes & MOD_ESTERROR)
		time_esterror = ntv.esterror;
	if (modes & MOD_STATUS) {
		if (time_status & STA_PLL && !(ntv.status & STA_PLL)) {
			time_state = TIME_OK;
			time_status = STA_UNSYNC;
		}
		time_status &= STA_RONLY;
		time_status |= ntv.status & ~STA_RONLY;
		/*
		 * Nor PPS or leaps seconds are supported.
		 * Filter out unsupported bits.
		 */
		time_status &= STA_SUPPORTED;
	}
	if (modes & MOD_TIMECONST) {
		if (ntv.constant < 0)
			time_constant = 0;
		else if (ntv.constant > MAXTC)
			time_constant = MAXTC;
		else
			time_constant = ntv.constant;
	}
	if (modes & MOD_TAI) {
		if (ntv.constant > 0)
			time_tai = ntv.constant;
	}
	if (modes & MOD_NANO)
		time_status |= STA_NANO;
	if (modes & MOD_MICRO)
		time_status &= ~STA_NANO;
	if (modes & MOD_CLKB)
		time_status |= STA_CLK;
	if (modes & MOD_CLKA)
		time_status &= ~STA_CLK;
	if (modes & MOD_FREQUENCY) {
		freq = (ntv.freq * 1000LL) >> 16;
		if (freq > MAXFREQ)
			L_LINT(time_freq, MAXFREQ);
		else if (freq < -MAXFREQ)
			L_LINT(time_freq, -MAXFREQ);
		else {
			/*
			 * ntv.freq is [PPM * 2^16] = [us/s * 2^16]
			 * time_freq is [ns/s * 2^32]
			 */
			time_freq = ntv.freq * 1000LL * 65536LL;
		}
	}
	if (modes & MOD_OFFSET) {
		if (time_status & STA_NANO)
			hardupdate(ntv.offset);
		else
			hardupdate(ntv.offset * 1000);
	}

	ret = ntp_is_time_error(time_status) ? TIME_ERROR : time_state;

#if DEVELOPEMNT || DEBUG
	if (g_should_log_clock_adjustments) {
		os_log(OS_LOG_DEFAULT, "%s:AFTER offset %lld freq %lld status %d constant %ld time_adjtime %lld\n",
		       __func__, time_offset, time_freq, time_status, time_constant, time_adjtime);
	}
#endif

	/*
	 * Retrieve all clock variables. Note that the TAI offset is
	 * returned only by ntp_gettime();
	 */
	if (IS_64BIT_PROCESS(p)) {
		struct user64_timex user_ntv = {};

		if (time_status & STA_NANO)
			user_ntv.offset = L_GINT(time_offset);
		else
			user_ntv.offset = L_GINT(time_offset) / 1000;
		user_ntv.freq = L_GINT((time_freq / 1000LL) << 16);
		user_ntv.maxerror = time_maxerror;
		user_ntv.esterror = time_esterror;
		user_ntv.status = time_status;
		user_ntv.constant = time_constant;
		if (time_status & STA_NANO)
			user_ntv.precision = time_precision;
		else
			user_ntv.precision = time_precision / 1000;
		user_ntv.tolerance = MAXFREQ * SCALE_PPM;

		/* unlock before copyout */
		NTP_UNLOCK(enable);

		error = copyout(&user_ntv, uap->tp, sizeof(user_ntv));

	}
	else{
		struct user32_timex user_ntv = {};

		if (time_status & STA_NANO)
			user_ntv.offset = L_GINT(time_offset);
		else
			user_ntv.offset = L_GINT(time_offset) / 1000;
		user_ntv.freq = L_GINT((time_freq / 1000LL) << 16);
		user_ntv.maxerror = time_maxerror;
		user_ntv.esterror = time_esterror;
		user_ntv.status = time_status;
		user_ntv.constant = time_constant;
		if (time_status & STA_NANO)
			user_ntv.precision = time_precision;
		else
			user_ntv.precision = time_precision / 1000;
		user_ntv.tolerance = MAXFREQ * SCALE_PPM;

		/* unlock before copyout */
		NTP_UNLOCK(enable);

		error = copyout(&user_ntv, uap->tp, sizeof(user_ntv));
	}

	if (modes)
		start_ntp_loop();

	if (error == 0)
		*retval = ret;

	return (error);
}

int64_t
ntp_get_freq(void){
	return time_freq;
}

/*
 * Compute the adjustment to add to the next second.
 */
void
ntp_update_second(int64_t *adjustment, clock_sec_t secs)
{
	int tickrate;
	l_fp time_adj;
	l_fp ftemp, old_time_adjtime, old_offset;

	NTP_ASSERT_LOCKED();

	if (secs > last_time_maxerror_update) {
		time_maxerror += (MAXFREQ / 1000)*(secs-last_time_maxerror_update);
		last_time_maxerror_update = secs;
	}

	old_offset = time_offset;
	old_time_adjtime = time_adjtime;

	ftemp = time_offset;
	L_RSHIFT(ftemp, SHIFT_PLL + time_constant);
	time_adj = ftemp;
	L_SUB(time_offset, ftemp);
	L_ADD(time_adj, time_freq);

	/*
	 * Apply any correction from adjtime.  If more than one second
	 * off we slew at a rate of 5ms/s (5000 PPM) else 500us/s (500PPM)
	 * until the last second is slewed the final < 500 usecs.
	 */
	if (time_adjtime != 0) {
		if (time_adjtime > 1000000)
			tickrate = 5000;
		else if (time_adjtime < -1000000)
			tickrate = -5000;
		else if (time_adjtime > 500)
			tickrate = 500;
		else if (time_adjtime < -500)
			tickrate = -500;
		else
			tickrate = time_adjtime;
		time_adjtime -= tickrate;
		L_LINT(ftemp, tickrate * 1000);
		L_ADD(time_adj, ftemp);
	}

	if (old_time_adjtime || ((time_offset || old_offset) && (time_offset != old_offset))) {
		updated = 1;
	}
	else{
		updated = 0;
	}

#if DEVELOPEMNT || DEBUG
	if (g_should_log_clock_adjustments) {
		int64_t nano = (time_adj > 0)? time_adj >> 32 : -((-time_adj) >> 32); 
		int64_t frac = (time_adj > 0)? ((uint32_t) time_adj) : -((uint32_t) (-time_adj)); 

		os_log(OS_LOG_DEFAULT, "%s:AFTER offset %lld (%lld) freq %lld status %d "
		       "constant %ld time_adjtime %lld nano %lld frac %lld adj %lld\n",
		       __func__, time_offset, (time_offset > 0)? time_offset >> 32 : -((-time_offset) >> 32),
		       time_freq, time_status, time_constant, time_adjtime, nano, frac, time_adj);
	}
#endif

	*adjustment = time_adj;
}

/*
 * hardupdate() - local clock update
 *
 * This routine is called by ntp_adjtime() when an offset is provided
 * to update the local clock phase and frequency.
 * The implementation is of an adaptive-parameter, hybrid
 * phase/frequency-lock loop (PLL/FLL). The routine computes new
 * time and frequency offset estimates for each call.
 * Presumably, calls to ntp_adjtime() occur only when the caller
 * believes the local clock is valid within some bound (+-128 ms with
 * NTP).
 *
 * For uncompensated quartz crystal oscillators and nominal update
 * intervals less than 256 s, operation should be in phase-lock mode,
 * where the loop is disciplined to phase. For update intervals greater
 * than 1024 s, operation should be in frequency-lock mode, where the
 * loop is disciplined to frequency. Between 256 s and 1024 s, the mode
 * is selected by the STA_MODE status bit.
 */
static void
hardupdate(offset)
	long offset;
{
	long mtemp = 0;
	long time_monitor;
	clock_sec_t time_uptime;
	l_fp ftemp;

	NTP_ASSERT_LOCKED();

	if (!(time_status & STA_PLL))
		return;

	if (offset > MAXPHASE)
		time_monitor = MAXPHASE;
	else if (offset < -MAXPHASE)
		time_monitor = -MAXPHASE;
	else
		time_monitor = offset;
	L_LINT(time_offset, time_monitor);

	clock_get_calendar_uptime(&time_uptime);

	if (time_status & STA_FREQHOLD || time_reftime == 0) {
		time_reftime = time_uptime;
	}

	mtemp = time_uptime - time_reftime;
	L_LINT(ftemp, time_monitor);
	L_RSHIFT(ftemp, (SHIFT_PLL + 2 + time_constant) << 1);
	L_MPY(ftemp, mtemp);
	L_ADD(time_freq, ftemp);
	time_status &= ~STA_MODE;
	if (mtemp >= MINSEC && (time_status & STA_FLL || mtemp >
	    MAXSEC)) {
		L_LINT(ftemp, (time_monitor << 4) / mtemp);
		L_RSHIFT(ftemp, SHIFT_FLL + 4);
		L_ADD(time_freq, ftemp);
		time_status |= STA_MODE;
	}
	time_reftime = time_uptime;

	if (L_GINT(time_freq) > MAXFREQ)
		L_LINT(time_freq, MAXFREQ);
	else if (L_GINT(time_freq) < -MAXFREQ)
		L_LINT(time_freq, -MAXFREQ);
}


static int
kern_adjtime(struct timeval *delta)
{
	struct timeval atv;
	int64_t ltr, ltw;
	boolean_t enable;

	if (delta == NULL)
		return (EINVAL);

	ltw = (int64_t)delta->tv_sec * (int64_t)USEC_PER_SEC + delta->tv_usec;

	NTP_LOCK(enable);
	ltr = time_adjtime;
	time_adjtime = ltw;
#if DEVELOPEMNT || DEBUG
	if (g_should_log_clock_adjustments) {
		os_log(OS_LOG_DEFAULT, "%s:AFTER offset %lld freq %lld status %d constant %ld time_adjtime %lld\n",
		       __func__, time_offset, time_freq, time_status, time_constant, time_adjtime);
	}
#endif
	NTP_UNLOCK(enable);

	atv.tv_sec = ltr / (int64_t)USEC_PER_SEC;
	atv.tv_usec = ltr % (int64_t)USEC_PER_SEC;
	if (atv.tv_usec < 0) {
		atv.tv_usec += (suseconds_t)USEC_PER_SEC;
		atv.tv_sec--;
	}

	*delta = atv;

	start_ntp_loop();

	return (0);
}

int
adjtime(struct proc *p, struct adjtime_args *uap, __unused int32_t *retval)
{

	struct timeval atv;
	int error;

	/* Check that this task is entitled to set the time or it is root */
	if (!IOTaskHasEntitlement(current_task(), SETTIME_ENTITLEMENT)) {

#if CONFIG_MACF
		error = mac_system_check_settime(kauth_cred_get());
		if (error)
			return (error);
#endif
		if ((error = priv_check_cred(kauth_cred_get(), PRIV_ADJTIME, 0)))
			return (error);
	}

	if (IS_64BIT_PROCESS(p)) {
		struct user64_timeval user_atv;
		error = copyin(uap->delta, &user_atv, sizeof(user_atv));
		atv.tv_sec = user_atv.tv_sec;
		atv.tv_usec = user_atv.tv_usec;
	} else {
		struct user32_timeval user_atv;
		error = copyin(uap->delta, &user_atv, sizeof(user_atv));
		atv.tv_sec = user_atv.tv_sec;
		atv.tv_usec = user_atv.tv_usec;
	}
	if (error)
		return (error);

	kern_adjtime(&atv);

	if (uap->olddelta) {
		if (IS_64BIT_PROCESS(p)) {
			struct user64_timeval user_atv = {};
			user_atv.tv_sec = atv.tv_sec;
			user_atv.tv_usec = atv.tv_usec;
			error = copyout(&user_atv, uap->olddelta, sizeof(user_atv));
		} else {
			struct user32_timeval user_atv = {};
			user_atv.tv_sec = atv.tv_sec;
			user_atv.tv_usec = atv.tv_usec;
			error = copyout(&user_atv, uap->olddelta, sizeof(user_atv));
		}
	}

	return (error);

}

static void
ntp_loop_update_call(void)
{
	boolean_t enable;

	NTP_LOCK(enable);

	/*
	 * Update the scale factor used by clock_calend.
	 * NOTE: clock_update_calendar will call ntp_update_second to compute the next adjustment.
	 */
	clock_update_calendar();

	refresh_ntp_loop();

	NTP_UNLOCK(enable);
}

static void
refresh_ntp_loop(void)
{

	NTP_ASSERT_LOCKED();
	if (--ntp_loop_active == 0) {
		/*
		 * Activate the timer only if the next second adjustment might change.
		 * ntp_update_second checks it and sets updated accordingly.
		 */
		if (updated) {
			clock_deadline_for_periodic_event(ntp_loop_period, mach_absolute_time(), &ntp_loop_deadline);

			if (!timer_call_enter(&ntp_loop_update, ntp_loop_deadline, TIMER_CALL_SYS_CRITICAL))
					ntp_loop_active++;
		}
	}

}

/*
 * This function triggers a timer that each second will calculate the adjustment to
 * provide to clock_calendar to scale the time (used by gettimeofday-family syscalls).
 * The periodic timer will stop when the adjustment will reach a stable value.
 */
static void
start_ntp_loop(void)
{
	boolean_t enable;

	NTP_LOCK(enable);

	ntp_loop_deadline = mach_absolute_time() + ntp_loop_period;

	if (!timer_call_enter(&ntp_loop_update, ntp_loop_deadline, TIMER_CALL_SYS_CRITICAL)) {
			ntp_loop_active++;
	}

	NTP_UNLOCK(enable);
}


static void
init_ntp_loop(void)
{
	uint64_t	abstime;

	ntp_loop_active = 0;
	nanoseconds_to_absolutetime(NTP_LOOP_PERIOD_INTERVAL, &abstime);
	ntp_loop_period = (uint32_t)abstime;
	timer_call_setup(&ntp_loop_update, (timer_call_func_t)ntp_loop_update_call, NULL);
}

void
ntp_init(void)
{

	L_CLR(time_offset);
	L_CLR(time_freq);

	ntp_lock_grp_attr = lck_grp_attr_alloc_init();
	ntp_lock_grp =  lck_grp_alloc_init("ntp_lock", ntp_lock_grp_attr);
	ntp_lock_attr = lck_attr_alloc_init();
	ntp_lock = lck_spin_alloc_init(ntp_lock_grp, ntp_lock_attr);

	updated = 0;

	init_ntp_loop();
}

SYSINIT(ntpclocks, SI_SUB_CLOCKS, SI_ORDER_MIDDLE, ntp_init, NULL);

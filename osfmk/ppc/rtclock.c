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

#include <machine/mach_param.h>	/* HZ */
#include <ppc/proc_reg.h>

#include <pexpert/pexpert.h>

/*XXX power management hacks XXX*/
#include <IOKit/IOReturn.h>
#include <IOKit/IOMessage.h>

extern void *registerSleepWakeInterest(
						void		*callback,
						void		*target,
						void		*refCon);
/*XXX power management hacks XXX*/

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

int		calend_init(void);

kern_return_t	calend_gettime(
	mach_timespec_t			*cur_time);

kern_return_t	calend_settime(
	mach_timespec_t			*cur_time);

kern_return_t	calend_getattr(
	clock_flavor_t			flavor,
	clock_attr_t			attr,
	mach_msg_type_number_t	*count);

struct clock_ops calend_ops = {
	calend_config,			calend_init,
	calend_gettime,			calend_settime,
	calend_getattr,			0,
	0,
};

/* local data declarations */

static struct rtclock {
	mach_timespec_t		calend_offset;
	boolean_t			calend_is_set;

	mach_timebase_info_data_t	timebase_const;

	struct rtclock_timer {
		AbsoluteTime		deadline;
		boolean_t			is_set;
	}					timer[NCPUS];

	clock_timer_func_t	timer_expire;

	timer_call_data_t	alarm[NCPUS];

	/* debugging */
	AbsoluteTime		last_abstime[NCPUS];
	int					last_decr[NCPUS];

	decl_simple_lock_data(,lock)	/* real-time clock device lock */
} rtclock;

static boolean_t		rtclock_initialized;

static AbsoluteTime		rtclock_tick_deadline[NCPUS];
static AbsoluteTime	 	rtclock_tick_interval;

static void		timespec_to_absolutetime(
							mach_timespec_t		timespec,
							AbsoluteTime		*result);

static int		deadline_to_decrementer(
							AbsoluteTime		deadline,
							AbsoluteTime		now);

static void		rtclock_alarm_timer(
					timer_call_param_t		p0,
					timer_call_param_t		p1);

/* global data declarations */

#define RTC_TICKPERIOD	(NSEC_PER_SEC / HZ)

#define DECREMENTER_MAX		0x7FFFFFFFUL
#define DECREMENTER_MIN		0xAUL

natural_t		rtclock_decrementer_min;

/*
 *	Macros to lock/unlock real-time clock device.
 */
#define LOCK_RTC(s)					\
MACRO_BEGIN							\
	(s) = splclock();				\
	simple_lock(&rtclock.lock);		\
MACRO_END

#define UNLOCK_RTC(s)				\
MACRO_BEGIN							\
	simple_unlock(&rtclock.lock);	\
	splx(s);						\
MACRO_END

static void
timebase_callback(
	struct timebase_freq_t	*freq)
{
	natural_t	numer, denom;
	int			n;
	spl_t		s;

	denom = freq->timebase_num;
	n = 9;
	while (!(denom % 10)) {
		if (n < 1)
			break;
		denom /= 10;
		n--;
	}

	numer = freq->timebase_den;
	while (n-- > 0) {
		numer *= 10;
	}

	LOCK_RTC(s);
	rtclock.timebase_const.numer = numer;
	rtclock.timebase_const.denom = denom;
	UNLOCK_RTC(s);
}

/*
 * Configure the real-time clock device.
 */
int
sysclk_config(void)
{
	int			i;

	if (cpu_number() != master_cpu)
		return(1);

	for (i = 0; i < NCPUS; i++)
		timer_call_setup(&rtclock.alarm[i], rtclock_alarm_timer, NULL);

	simple_lock_init(&rtclock.lock, ETAP_MISC_RT_CLOCK);

	PE_register_timebase_callback(timebase_callback);

	return (1);
}

/*
 * Initialize the system clock device.
 */
int
sysclk_init(void)
{
	AbsoluteTime	abstime;
	int				decr, mycpu = cpu_number();

	if (mycpu != master_cpu) {
		if (rtclock_initialized == FALSE) {
			panic("sysclk_init on cpu %d, rtc not initialized\n", mycpu);
		}
		/* Set decrementer and hence our next tick due */
		clock_get_uptime(&abstime);
		rtclock_tick_deadline[mycpu] = abstime;
		ADD_ABSOLUTETIME(&rtclock_tick_deadline[mycpu],
											&rtclock_tick_interval);
		decr = deadline_to_decrementer(rtclock_tick_deadline[mycpu], abstime);
		mtdec(decr);
		rtclock.last_decr[mycpu] = decr;

		return(1);
	}

	/*
	 * Initialize non-zero clock structure values.
	 */
	clock_interval_to_absolutetime_interval(RTC_TICKPERIOD, 1,
												&rtclock_tick_interval);
	/* Set decrementer and our next tick due */
	clock_get_uptime(&abstime);
	rtclock_tick_deadline[mycpu] = abstime;
	ADD_ABSOLUTETIME(&rtclock_tick_deadline[mycpu], &rtclock_tick_interval);
	decr = deadline_to_decrementer(rtclock_tick_deadline[mycpu], abstime);
	mtdec(decr);
	rtclock.last_decr[mycpu] = decr;

	rtclock_initialized = TRUE;

	return (1);
}

/*
 * Perform a full 64 bit by 32 bit unsigned multiply,
 * yielding a 96 bit product.  The most significant
 * portion of the product is returned as a 64 bit
 * quantity, with the lower portion as a 32 bit word.
 */
static void
umul_64by32(
	AbsoluteTime 		now64,
	natural_t			mult32,
	AbsoluteTime		*result64,
	natural_t			*result32)
{
	natural_t			mid, mid2;

	asm volatile("	mullw %0,%1,%2" :
				 			"=r" (*result32) :
					 			"r" (now64.lo), "r" (mult32));

	asm volatile("	mullw %0,%1,%2" :
							"=r" (mid2) :
					 			"r" (now64.hi), "r" (mult32));
	asm volatile("	mulhwu %0,%1,%2" :
							"=r" (mid) :
					 			"r" (now64.lo), "r" (mult32));

	asm volatile("	mulhwu %0,%1,%2" :
							"=r" (result64->hi) :
					 			"r" (now64.hi), "r" (mult32));

	asm volatile("	addc %0,%2,%3;
					addze %1,%4" :
							"=r" (result64->lo), "=r" (result64->hi) :
								"r" (mid), "r" (mid2), "1" (result64->hi));
}

/*
 * Perform a partial 64 bit by 32 bit unsigned multiply,
 * yielding a 64 bit product.  Only the least significant
 * 64 bits of the product are calculated and returned.
 */
static void
umul_64by32to64(
	AbsoluteTime		now64,
	natural_t			mult32,
	AbsoluteTime		*result64)
{
	natural_t			mid, mid2;

	asm volatile("	mullw %0,%1,%2" :
				 			"=r" (result64->lo) :
					 			"r" (now64.lo), "r" (mult32));

	asm volatile("	mullw %0,%1,%2" :
							"=r" (mid2) :
					 			"r" (now64.hi), "r" (mult32));
	asm volatile("	mulhwu %0,%1,%2" :
							"=r" (mid) :
					 			"r" (now64.lo), "r" (mult32));

	asm volatile("	add %0,%1,%2" :
							"=r" (result64->hi) :
								"r" (mid), "r" (mid2));
}

/*
 * Perform an unsigned division of a 96 bit value
 * by a 32 bit value, yielding a 96 bit quotient.
 * The most significant portion of the product is
 * returned as a 64 bit quantity, with the lower
 * portion as a 32 bit word.
 */
static __inline__
void
udiv_96by32(
	AbsoluteTime	now64,
	natural_t		now32,
	natural_t		div32,
	AbsoluteTime	*result64,
	natural_t		*result32)
{
	AbsoluteTime	t64;

	if (now64.hi > 0 || now64.lo >= div32) {
		AbsoluteTime_to_scalar(result64) =
							AbsoluteTime_to_scalar(&now64) / div32;

		umul_64by32to64(*result64, div32, &t64);

		AbsoluteTime_to_scalar(&t64) =
				AbsoluteTime_to_scalar(&now64) - AbsoluteTime_to_scalar(&t64);

		*result32 =	(((unsigned long long)t64.lo << 32) | now32) / div32;
	}
	else {
		AbsoluteTime_to_scalar(result64) =
					(((unsigned long long)now64.lo << 32) | now32) / div32;

		*result32 = result64->lo;
		result64->lo = result64->hi;
		result64->hi = 0;
	}
}

/*
 * Perform an unsigned division of a 96 bit value
 * by a 32 bit value, yielding a 64 bit quotient.
 * Any higher order bits of the quotient are simply
 * discarded.
 */
static __inline__
void
udiv_96by32to64(
	AbsoluteTime	now64,
	natural_t		now32,
	natural_t		div32,
	AbsoluteTime	*result64)
{
	AbsoluteTime	t64;

	if (now64.hi > 0 || now64.lo >= div32) {
		AbsoluteTime_to_scalar(result64) =
						AbsoluteTime_to_scalar(&now64) / div32;

		umul_64by32to64(*result64, div32, &t64);

		AbsoluteTime_to_scalar(&t64) =
				AbsoluteTime_to_scalar(&now64) - AbsoluteTime_to_scalar(&t64);

		result64->hi = result64->lo;
		result64->lo = (((unsigned long long)t64.lo << 32) | now32) / div32;
	}
	else {
		AbsoluteTime_to_scalar(result64) =
					(((unsigned long long)now64.lo << 32) | now32) / div32;
	}
}

/*
 * Perform an unsigned division of a 96 bit value
 * by a 32 bit value, yielding a 32 bit quotient,
 * and a 32 bit remainder.  Any higher order bits
 * of the quotient are simply discarded.
 */
static __inline__
void
udiv_96by32to32and32(
	AbsoluteTime	now64,
	natural_t		now32,
	natural_t		div32,
	natural_t		*result32,
	natural_t		*remain32)
{
	AbsoluteTime	t64, u64;

	if (now64.hi > 0 || now64.lo >= div32) {
		AbsoluteTime_to_scalar(&t64) =
							AbsoluteTime_to_scalar(&now64) / div32;

		umul_64by32to64(t64, div32, &t64);

		AbsoluteTime_to_scalar(&t64) =
			AbsoluteTime_to_scalar(&now64) - AbsoluteTime_to_scalar(&t64);

		AbsoluteTime_to_scalar(&t64) =
						((unsigned long long)t64.lo << 32) | now32;

		AbsoluteTime_to_scalar(&u64) =
							AbsoluteTime_to_scalar(&t64) / div32;

		*result32 = u64.lo;

		umul_64by32to64(u64, div32, &u64);

		*remain32 = AbsoluteTime_to_scalar(&t64) -
									AbsoluteTime_to_scalar(&u64);
	}
	else {
		AbsoluteTime_to_scalar(&t64) =
						((unsigned long long)now64.lo << 32) | now32;

		AbsoluteTime_to_scalar(&u64) =
							AbsoluteTime_to_scalar(&t64) / div32;

		*result32 =	 u64.lo;

		umul_64by32to64(u64, div32, &u64);

		*remain32 =	AbsoluteTime_to_scalar(&t64) -
									AbsoluteTime_to_scalar(&u64);
	}
}

/*
 * Get the clock device time. This routine is responsible
 * for converting the device's machine dependent time value
 * into a canonical mach_timespec_t value.
 *
 * SMP configurations - *this currently assumes that the processor
 * clocks will be synchronised*
 */
kern_return_t
sysclk_gettime_internal(
	mach_timespec_t	*time)	/* OUT */
{
	AbsoluteTime		now;
	AbsoluteTime		t64;
	natural_t			t32;
	natural_t			numer, denom;

	numer = rtclock.timebase_const.numer;
	denom = rtclock.timebase_const.denom;

	clock_get_uptime(&now);

	umul_64by32(now, numer, &t64, &t32);

	udiv_96by32(t64, t32, denom, &t64, &t32);

	udiv_96by32to32and32(t64, t32, NSEC_PER_SEC,
								&time->tv_sec, &time->tv_nsec);

	return (KERN_SUCCESS);
}

kern_return_t
sysclk_gettime(
	mach_timespec_t	*time)	/* OUT */
{
	AbsoluteTime		now;
	AbsoluteTime		t64;
	natural_t			t32;
	natural_t			numer, denom;
	spl_t				s;

	LOCK_RTC(s);
	numer = rtclock.timebase_const.numer;
	denom = rtclock.timebase_const.denom;
	UNLOCK_RTC(s);

	clock_get_uptime(&now);

	umul_64by32(now, numer, &t64, &t32);

	udiv_96by32(t64, t32, denom, &t64, &t32);

	udiv_96by32to32and32(t64, t32, NSEC_PER_SEC,
								&time->tv_sec, &time->tv_nsec);

	return (KERN_SUCCESS);
}

/*
 * Get clock device attributes.
 */
kern_return_t
sysclk_getattr(
	clock_flavor_t		flavor,
	clock_attr_t		attr,		/* OUT */
	mach_msg_type_number_t	*count)		/* IN/OUT */
{
	spl_t	s;

	if (*count != 1)
		return (KERN_FAILURE);
	switch (flavor) {

	case CLOCK_GET_TIME_RES:	/* >0 res */
	case CLOCK_ALARM_CURRES:	/* =0 no alarm */
	case CLOCK_ALARM_MINRES:
	case CLOCK_ALARM_MAXRES:
		LOCK_RTC(s);
		*(clock_res_t *) attr = RTC_TICKPERIOD;
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
	AbsoluteTime			abstime;

	timespec_to_absolutetime(*deadline, &abstime);
	timer_call_enter(&rtclock.alarm[cpu_number()], abstime);
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
 * Initialize the calendar clock.
 */
int
calend_init(void)
{
	if (cpu_number() != master_cpu)
		return(1);

	return (1);
}

/*
 * Get the current clock time.
 */
kern_return_t
calend_gettime(
	mach_timespec_t	*curr_time)	/* OUT */
{
	spl_t		s;

	LOCK_RTC(s);
	if (!rtclock.calend_is_set) {
		UNLOCK_RTC(s);
		return (KERN_FAILURE);
	}

	(void) sysclk_gettime_internal(curr_time);
	ADD_MACH_TIMESPEC(curr_time, &rtclock.calend_offset);
	UNLOCK_RTC(s);

	return (KERN_SUCCESS);
}

/*
 * Set the current clock time.
 */
kern_return_t
calend_settime(
	mach_timespec_t	*new_time)
{
	mach_timespec_t	curr_time;
	spl_t		s;

	LOCK_RTC(s);
	(void) sysclk_gettime_internal(&curr_time);
	rtclock.calend_offset = *new_time;
	SUB_MACH_TIMESPEC(&rtclock.calend_offset, &curr_time);
	rtclock.calend_is_set = TRUE;
	UNLOCK_RTC(s);

	PESetGMTTimeOfDay(new_time->tv_sec);

	return (KERN_SUCCESS);
}

/*
 * Get clock device attributes.
 */
kern_return_t
calend_getattr(
	clock_flavor_t		flavor,
	clock_attr_t		attr,		/* OUT */
	mach_msg_type_number_t	*count)		/* IN/OUT */
{
	spl_t	s;

	if (*count != 1)
		return (KERN_FAILURE);
	switch (flavor) {

	case CLOCK_GET_TIME_RES:	/* >0 res */
		LOCK_RTC(s);
		*(clock_res_t *) attr = RTC_TICKPERIOD;
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
clock_adjust_calendar(
	clock_res_t	nsec)
{
	spl_t		s;

	LOCK_RTC(s);
	if (rtclock.calend_is_set)
		ADD_MACH_TIMESPEC_NSEC(&rtclock.calend_offset, nsec);
	UNLOCK_RTC(s);
}

static void
calend_setup_internal(
	long			seconds)
{
	mach_timespec_t	curr_time;

	(void) sysclk_gettime_internal(&curr_time);
	if (curr_time.tv_nsec < 500*USEC_PER_SEC)
		rtclock.calend_offset.tv_sec = seconds;
	else
		rtclock.calend_offset.tv_sec = seconds + 1;
	rtclock.calend_offset.tv_nsec = 0;
	SUB_MACH_TIMESPEC(&rtclock.calend_offset, &curr_time);
	rtclock.calend_is_set = TRUE;
}

static thread_call_t		calend_wakeup_call;
static thread_call_data_t	calend_wakeup_call_data;

static void
calend_wakeup_resynch(
	thread_call_param_t		p0,
	thread_call_param_t		p1)
{
	long		seconds = PEGetGMTTimeOfDay();
	spl_t		s;

	LOCK_RTC(s);
	calend_setup_internal(seconds);
	UNLOCK_RTC(s);
}

static IOReturn
calend_sleep_wake_notif(
	void		*target,
	void		*refCon,
	UInt32		messageType,
	void		*provider,
	void		*messageArg,
	vm_size_t	argSize)
{
	if (messageType != kIOMessageSystemHasPoweredOn)
		return (kIOReturnUnsupported);

	if (calend_wakeup_call != NULL)
		thread_call_enter(calend_wakeup_call);

	return (kIOReturnSuccess);
}

void
clock_initialize_calendar(void)
{
	long		seconds;
	spl_t		s;

	thread_call_setup(&calend_wakeup_call_data, calend_wakeup_resynch, NULL);
	calend_wakeup_call = &calend_wakeup_call_data;

	registerSleepWakeInterest(calend_sleep_wake_notif, NULL, NULL);

	seconds = PEGetGMTTimeOfDay();

	LOCK_RTC(s);
	if (!rtclock.calend_is_set)
		calend_setup_internal(seconds);
	UNLOCK_RTC(s);
}

mach_timespec_t
clock_get_calendar_offset(void)
{
	mach_timespec_t	result = MACH_TIMESPEC_ZERO;
	spl_t		s;

	LOCK_RTC(s);
	if (rtclock.calend_is_set)
		result = rtclock.calend_offset;
	UNLOCK_RTC(s);

	return (result);
}

void
clock_timebase_info(
	mach_timebase_info_t	info)
{
	spl_t	s;

	LOCK_RTC(s);
	*info = rtclock.timebase_const;
	UNLOCK_RTC(s);
}	

void
clock_set_timer_deadline(
	AbsoluteTime			deadline)
{
	AbsoluteTime			abstime;
	int						decr, mycpu;
	struct rtclock_timer	*mytimer;
	spl_t					s;

	s = splclock();
	mycpu = cpu_number();
	mytimer = &rtclock.timer[mycpu];
	clock_get_uptime(&abstime);
	rtclock.last_abstime[mycpu] = abstime;
	mytimer->deadline = deadline;
	mytimer->is_set = TRUE;
	if (	CMP_ABSOLUTETIME(&mytimer->deadline,
										&rtclock_tick_deadline[mycpu]) < 0) {
		decr = deadline_to_decrementer(mytimer->deadline, abstime);
		if (	rtclock_decrementer_min != 0				&&
				rtclock_decrementer_min < (natural_t)decr		)
			decr = rtclock_decrementer_min;

		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_DECI, 1)
							  | DBG_FUNC_NONE, decr, 2, 0, 0, 0);

		mtdec(decr);
		rtclock.last_decr[mycpu] = decr;
	}
	splx(s);
}

void
clock_set_timer_func(
	clock_timer_func_t		func)
{
	spl_t		s;

	LOCK_RTC(s);
	if (rtclock.timer_expire == NULL)
		rtclock.timer_expire = func;
	UNLOCK_RTC(s);
}

/*
 * Reset the clock device. This causes the realtime clock
 * device to reload its mode and count value (frequency).
 */
void
rtclock_reset(void)
{
	return;
}

/*
 * Real-time clock device interrupt.
 */
void
rtclock_intr(
	int						device,
	struct ppc_saved_state	*ssp,
	spl_t					old_spl)
{
	AbsoluteTime			abstime;
	int						decr[3], mycpu = cpu_number();
	struct rtclock_timer	*mytimer = &rtclock.timer[mycpu];

	/*
	 * We may receive interrupts too early, we must reject them.
	 */
	if (rtclock_initialized == FALSE) {
		mtdec(DECREMENTER_MAX);		/* Max the decrementer if not init */
		return;
	}

	decr[1] = decr[2] = DECREMENTER_MAX;

	clock_get_uptime(&abstime);
	rtclock.last_abstime[mycpu] = abstime;
	if (CMP_ABSOLUTETIME(&rtclock_tick_deadline[mycpu], &abstime) <= 0) {
		clock_deadline_for_periodic_event(rtclock_tick_interval, abstime,
										  		&rtclock_tick_deadline[mycpu]);
		hertz_tick(USER_MODE(ssp->srr1), ssp->srr0);
	}

	clock_get_uptime(&abstime);
	rtclock.last_abstime[mycpu] = abstime;
	if (mytimer->is_set &&
					CMP_ABSOLUTETIME(&mytimer->deadline, &abstime) <= 0) {
		mytimer->is_set = FALSE;
		(*rtclock.timer_expire)(abstime);
	}

	clock_get_uptime(&abstime);
	rtclock.last_abstime[mycpu] = abstime;
	decr[1] = deadline_to_decrementer(rtclock_tick_deadline[mycpu], abstime);

	if (mytimer->is_set)
		decr[2] = deadline_to_decrementer(mytimer->deadline, abstime);

	if (decr[1] > decr[2])
		decr[1] = decr[2];

	if (	rtclock_decrementer_min != 0					&&
			rtclock_decrementer_min < (natural_t)decr[1]		)
		decr[1] = rtclock_decrementer_min;

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_DECI, 1)
						  | DBG_FUNC_NONE, decr[1], 3, 0, 0, 0);

	mtdec(decr[1]);
	rtclock.last_decr[mycpu] = decr[1];
}

static void
rtclock_alarm_timer(
	timer_call_param_t		p0,
	timer_call_param_t		p1)
{
	mach_timespec_t		timestamp;

	(void) sysclk_gettime(&timestamp);

	clock_alarm_intr(SYSTEM_CLOCK, &timestamp);
}

void
clock_get_uptime(
	AbsoluteTime	*result)
{
	natural_t	hi, lo, hic;

	do {
		asm volatile("	mftbu %0" : "=r" (hi));
		asm volatile("	mftb %0" : "=r" (lo));
		asm volatile("	mftbu %0" : "=r" (hic));
	} while (hic != hi);

	result->lo = lo;
	result->hi = hi;
}

static int
deadline_to_decrementer(
	AbsoluteTime		deadline,
	AbsoluteTime		now)
{
	uint64_t			delt;

	if (CMP_ABSOLUTETIME(&deadline, &now) <= 0)
		return DECREMENTER_MIN;
	else {
		delt = AbsoluteTime_to_scalar(&deadline) -
									AbsoluteTime_to_scalar(&now);
		return (delt >= (DECREMENTER_MAX + 1))? DECREMENTER_MAX:
				((delt >= (DECREMENTER_MIN + 1))? (delt - 1): DECREMENTER_MIN);
	}
}

static void
timespec_to_absolutetime(
	mach_timespec_t			timespec,
	AbsoluteTime			*result)
{
	AbsoluteTime			t64;
	natural_t				t32;
	natural_t				numer, denom;
	spl_t					s;

	LOCK_RTC(s);
	numer = rtclock.timebase_const.numer;
	denom = rtclock.timebase_const.denom;
	UNLOCK_RTC(s);

	asm volatile("	mullw %0,%1,%2" :
							"=r" (t64.lo) :
								"r" (timespec.tv_sec), "r" (NSEC_PER_SEC));

	asm volatile("	mulhwu %0,%1,%2" :
							"=r" (t64.hi) :
								"r" (timespec.tv_sec), "r" (NSEC_PER_SEC));

	AbsoluteTime_to_scalar(&t64) += timespec.tv_nsec;

	umul_64by32(t64, denom, &t64, &t32);

	udiv_96by32(t64, t32, numer, &t64, &t32);

	result->hi = t64.lo;
	result->lo = t32;
}

void
clock_interval_to_deadline(
	natural_t			interval,
	natural_t			scale_factor,
	AbsoluteTime		*result)
{
	AbsoluteTime		abstime;

	clock_get_uptime(result);

	clock_interval_to_absolutetime_interval(interval, scale_factor, &abstime);

	ADD_ABSOLUTETIME(result, &abstime);
}

void
clock_interval_to_absolutetime_interval(
	natural_t			interval,
	natural_t			scale_factor,
	AbsoluteTime		*result)
{
	AbsoluteTime		t64;
	natural_t			t32;
	natural_t			numer, denom;
	spl_t				s;

	LOCK_RTC(s);
	numer = rtclock.timebase_const.numer;
	denom = rtclock.timebase_const.denom;
	UNLOCK_RTC(s);

	asm volatile("	mullw %0,%1,%2" :
							"=r" (t64.lo) :
				 				"r" (interval), "r" (scale_factor));
	asm volatile("	mulhwu %0,%1,%2" :
							"=r" (t64.hi) :
				 				"r" (interval), "r" (scale_factor));

	umul_64by32(t64, denom, &t64, &t32);

	udiv_96by32(t64, t32, numer, &t64, &t32);

	result->hi = t64.lo;
	result->lo = t32;
}

void
clock_absolutetime_interval_to_deadline(
	AbsoluteTime		abstime,
	AbsoluteTime		*result)
{
	clock_get_uptime(result);

	ADD_ABSOLUTETIME(result, &abstime);
}

void
absolutetime_to_nanoseconds(
	AbsoluteTime		abstime,
	UInt64				*result)
{
	AbsoluteTime		t64;
	natural_t			t32;
	natural_t			numer, denom;
	spl_t				s;

	LOCK_RTC(s);
	numer = rtclock.timebase_const.numer;
	denom = rtclock.timebase_const.denom;
	UNLOCK_RTC(s);

	umul_64by32(abstime, numer, &t64, &t32);

	udiv_96by32to64(t64, t32, denom, (void *)result);
}

void
nanoseconds_to_absolutetime(
	UInt64				nanoseconds,
	AbsoluteTime		*result)
{
	AbsoluteTime		t64;
	natural_t			t32;
	natural_t			numer, denom;
	spl_t				s;

	LOCK_RTC(s);
	numer = rtclock.timebase_const.numer;
	denom = rtclock.timebase_const.denom;
	UNLOCK_RTC(s);

	AbsoluteTime_to_scalar(&t64) = nanoseconds;

	umul_64by32(t64, denom, &t64, &t32);

	udiv_96by32to64(t64, t32, numer, result);
}

/*
 * Spin-loop delay primitives.
 */
void
delay_for_interval(
	natural_t			interval,
	natural_t			scale_factor)
{
	AbsoluteTime		now, end;

	clock_interval_to_deadline(interval, scale_factor, &end);

	do {
		clock_get_uptime(&now);
	} while (CMP_ABSOLUTETIME(&now, &end) < 0);
}

void
clock_delay_until(
	AbsoluteTime		deadline)
{
	AbsoluteTime		now;

	do {
		clock_get_uptime(&now);
	} while (CMP_ABSOLUTETIME(&now, &deadline) < 0);
}

void
delay(
	int			usec)
{
	delay_for_interval((usec < 0)? -usec: usec, NSEC_PER_USEC);
}

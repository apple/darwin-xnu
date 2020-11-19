/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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
 * File: arm/rtclock.c
 * Purpose: Routines for handling the machine dependent
 *   real-time clock.
 */

#include <mach/mach_types.h>

#include <kern/clock.h>
#include <kern/thread.h>
#include <kern/macro_help.h>
#include <kern/spl.h>
#include <kern/timer_queue.h>

#include <kern/host_notify.h>

#include <machine/commpage.h>
#include <machine/machine_routines.h>
#include <machine/config.h>
#include <arm/exception.h>
#include <arm/cpu_data_internal.h>
#if __arm64__
#include <arm64/proc_reg.h>
#elif __arm__
#include <arm/proc_reg.h>
#else
#error Unsupported arch
#endif
#include <arm/rtclock.h>

#include <IOKit/IOPlatformExpert.h>
#include <libkern/OSAtomic.h>

#include <sys/kdebug.h>

#define MAX_TIMEBASE_TRIES 10

int rtclock_init(void);

static int
deadline_to_decrementer(uint64_t deadline,
    uint64_t now);
static void
timebase_callback(struct timebase_freq_t * freq);

#if DEVELOPMENT || DEBUG
uint32_t absolute_time_validation = 0;
#endif

/*
 * Configure the real-time clock device at boot
 */
void
rtclock_early_init(void)
{
	PE_register_timebase_callback(timebase_callback);
#if DEVELOPMENT || DEBUG
	uint32_t tmp_mv = 1;

#if defined(APPLE_ARM64_ARCH_FAMILY)
	/* Enable MAT validation on A0 hardware by default. */
	absolute_time_validation = ml_get_topology_info()->chip_revision == CPU_VERSION_A0;
#endif

	if (kern_feature_override(KF_MATV_OVRD)) {
		absolute_time_validation = 0;
	}
	if (PE_parse_boot_argn("timebase_validation", &tmp_mv, sizeof(tmp_mv))) {
		absolute_time_validation = tmp_mv;
	}
#endif
}

static void
timebase_callback(struct timebase_freq_t * freq)
{
	unsigned long numer, denom;
	uint64_t      t64_1, t64_2;
	uint32_t      divisor;

	if (freq->timebase_den < 1 || freq->timebase_den > 4 ||
	    freq->timebase_num < freq->timebase_den) {
		panic("rtclock timebase_callback: invalid constant %ld / %ld",
		    freq->timebase_num, freq->timebase_den);
	}

	denom = freq->timebase_num;
	numer = freq->timebase_den * NSEC_PER_SEC;
	// reduce by the greatest common denominator to minimize overflow
	if (numer > denom) {
		t64_1 = numer;
		t64_2 = denom;
	} else {
		t64_1 = denom;
		t64_2 = numer;
	}
	while (t64_2 != 0) {
		uint64_t temp = t64_2;
		t64_2 = t64_1 % t64_2;
		t64_1 = temp;
	}
	numer /= t64_1;
	denom /= t64_1;

	rtclock_timebase_const.numer = (uint32_t)numer;
	rtclock_timebase_const.denom = (uint32_t)denom;
	divisor = (uint32_t)(freq->timebase_num / freq->timebase_den);

	rtclock_sec_divisor = divisor;
	rtclock_usec_divisor = divisor / USEC_PER_SEC;
}

/*
 * Initialize the system clock device for the current cpu
 */
int
rtclock_init(void)
{
	uint64_t     abstime;
	cpu_data_t * cdp;

	clock_timebase_init();
	ml_init_lock_timeout();

	cdp = getCpuDatap();

	abstime = mach_absolute_time();
	cdp->rtcPop = EndOfAllTime;                                     /* Init Pop time */
	timer_resync_deadlines();                                       /* Start the timers going */

	return 1;
}

uint64_t
mach_absolute_time(void)
{
#if DEVELOPMENT || DEBUG
	if (__improbable(absolute_time_validation == 1)) {
		static volatile uint64_t s_last_absolute_time = 0;
		uint64_t                 new_absolute_time, old_absolute_time;
		int                      attempts = 0;

		/* ARM 64: We need a dsb here to ensure that the load of s_last_absolute_time
		 * completes before the timebase read. Were the load to complete after the
		 * timebase read, there would be a window for another CPU to update
		 * s_last_absolute_time and leave us in an inconsistent state. Consider the
		 * following interleaving:
		 *
		 *   Let s_last_absolute_time = t0
		 *   CPU0: Read timebase at t1
		 *   CPU1: Read timebase at t2
		 *   CPU1: Update s_last_absolute_time to t2
		 *   CPU0: Load completes
		 *   CPU0: Update s_last_absolute_time to t1
		 *
		 * This would cause the assertion to fail even though time did not go
		 * backwards. Thus, we use a dsb to guarantee completion of the load before
		 * the timebase read.
		 */
		do {
			attempts++;
			old_absolute_time = s_last_absolute_time;

#if __arm64__
			__asm__ volatile ("dsb ld" ::: "memory");
#else
			OSSynchronizeIO(); // See osfmk/arm64/rtclock.c
#endif

			new_absolute_time = ml_get_timebase();
		} while (attempts < MAX_TIMEBASE_TRIES && !OSCompareAndSwap64(old_absolute_time, new_absolute_time, &s_last_absolute_time));

		if (attempts < MAX_TIMEBASE_TRIES && old_absolute_time > new_absolute_time) {
			panic("mach_absolute_time returning non-monotonically increasing value 0x%llx (old value 0x%llx\n)\n",
			    new_absolute_time, old_absolute_time);
		}
		return new_absolute_time;
	} else {
		return ml_get_timebase();
	}
#else
	return ml_get_timebase();
#endif
}

uint64_t
mach_approximate_time(void)
{
#if __ARM_TIME__ || __ARM_TIME_TIMEBASE_ONLY__ || __arm64__
	/* Hardware supports a fast timestamp, so grab it without asserting monotonicity */
	return ml_get_timebase();
#else
	processor_t processor;
	uint64_t    approx_time;

	disable_preemption();
	processor = current_processor();
	approx_time = processor->last_dispatch;
	enable_preemption();

	return approx_time;
#endif
}

void
clock_get_system_microtime(clock_sec_t *  secs,
    clock_usec_t * microsecs)
{
	absolutetime_to_microtime(mach_absolute_time(), secs, microsecs);
}

void
clock_get_system_nanotime(clock_sec_t *  secs,
    clock_nsec_t * nanosecs)
{
	uint64_t abstime;
	uint64_t t64;

	abstime = mach_absolute_time();
	*secs = (t64 = abstime / rtclock_sec_divisor);
	abstime -= (t64 * rtclock_sec_divisor);

	*nanosecs = (clock_nsec_t)((abstime * NSEC_PER_SEC) / rtclock_sec_divisor);
}

void
clock_gettimeofday_set_commpage(uint64_t abstime,
    uint64_t sec,
    uint64_t frac,
    uint64_t scale,
    uint64_t tick_per_sec)
{
	commpage_set_timestamp(abstime, sec, frac, scale, tick_per_sec);
}

void
clock_timebase_info(mach_timebase_info_t info)
{
	*info = rtclock_timebase_const;
}

/*
 * Real-time clock device interrupt.
 */
void
rtclock_intr(__unused unsigned int is_user_context)
{
	uint64_t                 abstime;
	cpu_data_t *             cdp;
	struct arm_saved_state * regs;
	unsigned int             user_mode;
	uintptr_t                pc;

	cdp = getCpuDatap();

	cdp->cpu_stat.timer_cnt++;
	SCHED_STATS_INC(timer_pop_count);

	assert(!ml_get_interrupts_enabled());

	abstime = mach_absolute_time();

	if (cdp->cpu_idle_pop != 0x0ULL) {
		if ((cdp->rtcPop - abstime) < cdp->cpu_idle_latency) {
			cdp->cpu_idle_pop = 0x0ULL;
			while (abstime < cdp->rtcPop) {
				abstime = mach_absolute_time();
			}
		} else {
			ClearIdlePop(FALSE);
		}
	}

	if ((regs = cdp->cpu_int_state)) {
		pc = get_saved_state_pc(regs);

#if __arm64__
		user_mode = PSR64_IS_USER(get_saved_state_cpsr(regs));
#else
		user_mode = (regs->cpsr & PSR_MODE_MASK) == PSR_USER_MODE;
#endif
	} else {
		pc = 0;
		user_mode = 0;
	}
	if (abstime >= cdp->rtcPop) {
		/* Log the interrupt service latency (-ve value expected by tool) */
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		    MACHDBG_CODE(DBG_MACH_EXCP_DECI, 0) | DBG_FUNC_NONE,
		    -(abstime - cdp->rtcPop),
		    user_mode ? pc : VM_KERNEL_UNSLIDE(pc), user_mode, 0, 0);
	}

	/* call the generic etimer */
	timer_intr(user_mode, pc);
}

static int
deadline_to_decrementer(uint64_t deadline,
    uint64_t now)
{
	uint64_t delt;

	if (deadline <= now) {
		return DECREMENTER_MIN;
	} else {
		delt = deadline - now;

		return (delt >= (DECREMENTER_MAX + 1)) ? DECREMENTER_MAX : ((delt >= (DECREMENTER_MIN + 1)) ? (int)delt : DECREMENTER_MIN);
	}
}

/*
 *	Request a decrementer pop
 */
int
setPop(uint64_t time)
{
	int          delay_time;
	uint64_t     current_time;
	cpu_data_t * cdp;

	cdp = getCpuDatap();
	current_time = mach_absolute_time();

	delay_time = deadline_to_decrementer(time, current_time);
	cdp->rtcPop = delay_time + current_time;

	ml_set_decrementer((uint32_t) delay_time);

	return delay_time;
}

/*
 *	Request decrementer Idle Pop. Return true if set
 */
boolean_t
SetIdlePop(void)
{
	int          delay_time;
	uint64_t     time;
	uint64_t     current_time;
	cpu_data_t * cdp;

	cdp = getCpuDatap();
	current_time = mach_absolute_time();

	if (((cdp->rtcPop < current_time) ||
	    (cdp->rtcPop - current_time) < cdp->cpu_idle_latency)) {
		return FALSE;
	}

	time = cdp->rtcPop - cdp->cpu_idle_latency;

	delay_time = deadline_to_decrementer(time, current_time);
	cdp->cpu_idle_pop = delay_time + current_time;
	ml_set_decrementer((uint32_t) delay_time);

	return TRUE;
}

/*
 *	Clear decrementer Idle Pop
 */
void
ClearIdlePop(
	boolean_t wfi)
{
#if !__arm64__
#pragma unused(wfi)
#endif
	cpu_data_t * cdp;

	cdp = getCpuDatap();
	cdp->cpu_idle_pop = 0x0ULL;

#if __arm64__
	/*
	 * Don't update the HW timer if there's a pending
	 * interrupt (we can lose interrupt assertion);
	 * we want to take the interrupt right now and update
	 * the deadline from the handler).
	 *
	 * ARM64_TODO: consider this more carefully.
	 */
	if (!(wfi && ml_get_timer_pending()))
#endif
	{
		setPop(cdp->rtcPop);
	}
}

void
absolutetime_to_microtime(uint64_t       abstime,
    clock_sec_t *  secs,
    clock_usec_t * microsecs)
{
	uint64_t t64;

	*secs = t64 = abstime / rtclock_sec_divisor;
	abstime -= (t64 * rtclock_sec_divisor);

	*microsecs = (uint32_t)(abstime / rtclock_usec_divisor);
}

void
absolutetime_to_nanoseconds(uint64_t   abstime,
    uint64_t * result)
{
	uint64_t        t64;

	*result = (t64 = abstime / rtclock_sec_divisor) * NSEC_PER_SEC;
	abstime -= (t64 * rtclock_sec_divisor);
	*result += (abstime * NSEC_PER_SEC) / rtclock_sec_divisor;
}

void
nanoseconds_to_absolutetime(uint64_t   nanosecs,
    uint64_t * result)
{
	uint64_t        t64;

	*result = (t64 = nanosecs / NSEC_PER_SEC) * rtclock_sec_divisor;
	nanosecs -= (t64 * NSEC_PER_SEC);
	*result += (nanosecs * rtclock_sec_divisor) / NSEC_PER_SEC;
}

void
nanotime_to_absolutetime(clock_sec_t  secs,
    clock_nsec_t nanosecs,
    uint64_t *   result)
{
	*result = ((uint64_t) secs * rtclock_sec_divisor) +
	    ((uint64_t) nanosecs * rtclock_sec_divisor) / NSEC_PER_SEC;
}

void
clock_interval_to_absolutetime_interval(uint32_t   interval,
    uint32_t   scale_factor,
    uint64_t * result)
{
	uint64_t nanosecs = (uint64_t) interval * scale_factor;
	uint64_t t64;

	*result = (t64 = nanosecs / NSEC_PER_SEC) * rtclock_sec_divisor;
	nanosecs -= (t64 * NSEC_PER_SEC);
	*result += (nanosecs * rtclock_sec_divisor) / NSEC_PER_SEC;
}

void
machine_delay_until(uint64_t interval,
    uint64_t deadline)
{
#pragma unused(interval)
	uint64_t now;

	do {
#if     __ARM_ENABLE_WFE_
		__builtin_arm_wfe();
#endif /* __ARM_ENABLE_WFE_ */

		now = mach_absolute_time();
	} while (now < deadline);
}

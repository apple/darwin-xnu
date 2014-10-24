/*
 * Copyright (c) 2000-2011 Apple Inc. All rights reserved.
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


#include <mach/mach_types.h>

#include <architecture/i386/pio.h>
#include <i386/machine_cpu.h>
#include <i386/cpuid.h>
#include <i386/cpu_threads.h>
#include <i386/mp.h>
#include <i386/machine_routines.h>
#include <i386/pal_routines.h>
#include <i386/proc_reg.h>
#include <i386/misc_protos.h>
#include <i386/lapic.h>
#include <pexpert/pexpert.h>
#include <machine/limits.h>
#include <sys/kdebug.h>
#include <i386/tsc.h>
#include <i386/rtclock_protos.h>
#include <i386/pal_routines.h>
#include <kern/timer_queue.h>

static uint64_t	rtc_decrementer_min;
static uint64_t	rtc_decrementer_max;

static uint64_t
deadline_to_decrementer(
	uint64_t	deadline,
	uint64_t	now)
{
	uint64_t	delta;

	if (deadline <= now)
		return rtc_decrementer_min;
	else {
		delta = deadline - now;
		return MIN(MAX(rtc_decrementer_min,delta),rtc_decrementer_max); 
	}
}


/*
 * Regular local APIC timer case:
 */
static void
rtc_lapic_config_timer(void)
{
	lapic_config_timer(TRUE, one_shot, divide_by_1);
}
static uint64_t
rtc_lapic_set_timer(uint64_t deadline, uint64_t now)
{
	uint64_t count;
	uint64_t set = 0;

	if (deadline > 0) {
		/*
		 * Convert delta to bus ticks
		 * - time now is not relevant
		 */
		count = deadline_to_decrementer(deadline, now);
		set = now + count;
		lapic_set_timer_fast((uint32_t) tmrCvt(count, busFCvtn2t));
	} else {
		lapic_set_timer(FALSE, one_shot, divide_by_1, 0);
	}

	KERNEL_DEBUG_CONSTANT(
		DECR_SET_APIC_DEADLINE | DBG_FUNC_NONE,
		now, deadline,
		set, LAPIC_READ(TIMER_CURRENT_COUNT),
		0);

	return set;
}

/*
 * TSC-deadline timer case:
 */
static void
rtc_lapic_config_tsc_deadline_timer(void)
{
	lapic_config_tsc_deadline_timer();
}
static uint64_t
rtc_lapic_set_tsc_deadline_timer(uint64_t deadline, uint64_t now)
{
	uint64_t delta;
	uint64_t delta_tsc;
	uint64_t tsc = rdtsc64();
	uint64_t set = 0;

	if (deadline > 0) {
		/*
		 * Convert to TSC
		 */
		delta = deadline_to_decrementer(deadline, now);
		set = now + delta;
		delta_tsc = tmrCvt(delta, tscFCvtn2t);
		lapic_set_tsc_deadline_timer(tsc + delta_tsc);
	} else {
		lapic_set_tsc_deadline_timer(0);
	}
	
	KERNEL_DEBUG_CONSTANT(
		DECR_SET_TSC_DEADLINE | DBG_FUNC_NONE,
		now, deadline,
		tsc, lapic_get_tsc_deadline_timer(),
		0);

	return set;
} 

/*
 * Definitions for timer operations table
 */

rtc_timer_t	rtc_timer_lapic  = {
	rtc_lapic_config_timer,
	rtc_lapic_set_timer
};

rtc_timer_t	rtc_timer_tsc_deadline  = {
	rtc_lapic_config_tsc_deadline_timer,
	rtc_lapic_set_tsc_deadline_timer
};

rtc_timer_t	*rtc_timer = &rtc_timer_lapic; /* defaults to LAPIC timer */

/*
 * rtc_timer_init() is called at startup on the boot processor only.
 */
void
rtc_timer_init(void)
{
	int	TSC_deadline_timer = 0;

	/* See whether we can use the local apic in TSC-deadline mode */
	if ((cpuid_features() & CPUID_FEATURE_TSCTMR)) {
		TSC_deadline_timer = 1;
		PE_parse_boot_argn("TSC_deadline_timer", &TSC_deadline_timer,
				   sizeof(TSC_deadline_timer));
		printf("TSC Deadline Timer supported %s enabled\n",
			TSC_deadline_timer ? "and" : "but not");
	}

	if (TSC_deadline_timer) {
		rtc_timer = &rtc_timer_tsc_deadline;
		rtc_decrementer_max = UINT64_MAX;	/* effectively none */
		/*
		 * The min could be as low as 1nsec,
		 * but we're being conservative for now and making it the same
		 * as for the local apic timer.
		 */
		rtc_decrementer_min = 1*NSEC_PER_USEC;	/* 1 usec */
	} else {
		/*
		 * Compute the longest interval using LAPIC timer.
		 */
		rtc_decrementer_max = tmrCvt(0x7fffffffULL, busFCvtt2n);
		kprintf("maxDec: %lld\n", rtc_decrementer_max);
		rtc_decrementer_min = 1*NSEC_PER_USEC;	/* 1 usec */
	}

	/* Point LAPIC interrupts to hardclock() */
	lapic_set_timer_func((i386_intr_func_t) rtclock_intr);
}

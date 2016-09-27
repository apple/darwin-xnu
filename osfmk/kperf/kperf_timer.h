#ifndef KPERF_TIMER_H
#define KPERF_TIMER_H
/*
 * Copyright (c) 2011 Apple Computer, Inc. All rights reserved.
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

#include <kern/timer_call.h>
#include <kern/bits.h>

struct kperf_timer {
	struct timer_call tcall;
	uint64_t period;
	unsigned actionid;
	volatile unsigned active;

	/*
	 * A bitmap of CPUs that have a pending timer to service.  On Intel, it
	 * allows the core responding to the timer interrupt to not queue up
	 * cross-calls on cores that haven't yet responded.  On ARM, it allows
	 * the signal handler to multiplex simultaneous fires of different
	 * timers.
	 */
	bitmap_t pending_cpus;
};

extern struct kperf_timer *kperf_timerv;
extern unsigned int kperf_timerc;

void kperf_timer_reprogram(void);
void kperf_timer_reprogram_all(void);

void kperf_ipi_handler(void *param);

// return values from the action
#define TIMER_REPROGRAM (0)
#define TIMER_STOP      (1)

/* getters and setters on timers */
unsigned kperf_timer_get_count(void);
int kperf_timer_set_count(unsigned int count);

int kperf_timer_get_period(unsigned int timer, uint64_t *period);
int kperf_timer_set_period(unsigned int timer, uint64_t period);

int kperf_timer_get_action(unsigned int timer, uint32_t *action);
int kperf_timer_set_action(unsigned int timer, uint32_t action);

void kperf_timer_go(void);
void kperf_timer_stop(void);
void kperf_timer_reset(void);

unsigned int kperf_timer_get_petid(void);
int kperf_timer_set_petid(unsigned int count);

/* so PET thread can re-arm the timer */
void kperf_timer_pet_rearm(uint64_t elapsed_ticks);

#endif /* !defined(KPERF_TIMER_H) */

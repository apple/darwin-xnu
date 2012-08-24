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

// extern uint64_t timer_period;
extern void kperf_timer_reprogram(void);
extern void kperf_timer_reprogram_all(void);


// return values from the action
#define TIMER_REPROGRAM (0)
#define TIMER_STOP (1)

/* blah */
extern unsigned kperf_timer_get_count(void);
extern int kperf_timer_set_count(unsigned count);

extern int kperf_timer_get_period( unsigned timer, uint64_t *period );
extern int kperf_timer_set_period( unsigned timer, uint64_t period );

extern int kperf_timer_go(void);
extern int kperf_timer_stop(void);

extern unsigned kperf_timer_get_petid(void);
extern int kperf_timer_set_petid(unsigned count);

/* so PET thread can re-arm the timer */
extern int kperf_timer_pet_set( unsigned timer );

/*
 * Copyright (c) 2000-2018 Apple Inc. All rights reserved.
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
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */

#include <mach/kern_return.h>
#include <mach/port.h>
#include <kern/queue.h>
#include <kern/processor.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/timer.h>

#include <machine/config.h>

#if CONFIG_SKIP_PRECISE_USER_KERNEL_TIME && !HAS_FAST_CNTVCT
int precise_user_kernel_time = 0;
#else
int precise_user_kernel_time = 1;
#endif

void
timer_init(timer_t timer)
{
	memset(timer, 0, sizeof(*timer));
}

uint64_t
timer_delta(timer_t timer, uint64_t *prev_in_cur_out)
{
	uint64_t old = *prev_in_cur_out;
	uint64_t new = *prev_in_cur_out = timer_grab(timer);
	return new - old;
}

static void
timer_advance(timer_t timer, uint64_t delta)
{
#if defined(__LP64__)
	timer->all_bits += delta;
#else /* defined(__LP64__) */
	extern void timer_advance_internal_32(timer_t timer, uint32_t high,
	    uint32_t low);
	uint64_t low = delta + timer->low_bits;
	if (low >> 32) {
		timer_advance_internal_32(timer,
		    (uint32_t)(timer->high_bits + (low >> 32)), (uint32_t)low);
	} else {
		timer->low_bits = (uint32_t)low;
	}
#endif /* defined(__LP64__) */
}

void
timer_start(timer_t timer, uint64_t tstamp)
{
	timer->tstamp = tstamp;
}

void
timer_stop(timer_t timer, uint64_t tstamp)
{
	timer_advance(timer, tstamp - timer->tstamp);
}

void
timer_update(timer_t timer, uint64_t tstamp)
{
	timer_advance(timer, tstamp - timer->tstamp);
	timer->tstamp = tstamp;
}

void
timer_switch(timer_t timer, uint64_t tstamp, timer_t new_timer)
{
	timer_advance(timer, tstamp - timer->tstamp);
	new_timer->tstamp = tstamp;
}

/*
 * Update the current processor's thread timer with `tstamp` and switch the
 * processor's thread timer to `new_timer`.
 *
 * Called with interrupts disabled.
 */
void
processor_timer_switch_thread(uint64_t tstamp, timer_t new_timer)
{
	processor_t processor = current_processor();
	timer_t timer;

	/* Update current timer. */
	timer = processor->thread_timer;
	timer_advance(timer, tstamp - timer->tstamp);

	/* Start new timer. */
	processor->thread_timer = new_timer;
	new_timer->tstamp = tstamp;
}

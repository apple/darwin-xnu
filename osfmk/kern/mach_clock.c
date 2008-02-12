/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
 * Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University
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
/*
 */
/*
 *	File:	clock_prim.c
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1986
 *
 *	Clock primitives.
 */
#include <gprof.h>

#include <mach/boolean.h>
#include <mach/machine.h>
#include <mach/time_value.h>
#include <mach/vm_param.h>
#include <mach/vm_prot.h>
#include <kern/clock.h>
#include <kern/cpu_number.h>
#include <kern/host.h>
#include <kern/lock.h>
#include <kern/mach_param.h>
#include <kern/misc_protos.h>
#include <kern/processor.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/thread.h>

#include <profiling/profile-mk.h>

#if GPROF
static void prof_tick(boolean_t usermode, natural_t pc);
#endif

#if STAT_TIME || GPROF
/*
 * Hertz rate clock interrupt servicing. Used to update processor
 * statistics and perform kernel profiling.
 */
void
hertz_tick(
#if GPROF
	__unused natural_t	ticks,
#else
	natural_t		ticks,
#endif
	boolean_t		usermode,
#if GPROF
	natural_t		pc)
#else
	__unused natural_t		pc)
#endif
{
	processor_t		processor = current_processor();
	thread_t		thread = current_thread();
	timer_t			state;

	if (usermode) {
		TIMER_BUMP(&thread->user_timer, ticks);

		state = &PROCESSOR_DATA(processor, user_state);
	}
	else {
		/* If this thread is idling, do not charge that time as system time */
		if ((thread->state & TH_IDLE) == 0) {
			TIMER_BUMP(&thread->system_timer, ticks);
		}
        
		if (processor->state == PROCESSOR_IDLE)
			state = &PROCESSOR_DATA(processor, idle_state);
		else
			state = &PROCESSOR_DATA(processor, system_state);
	}

	TIMER_BUMP(state, ticks);

#if GPROF
	prof_tick(usermode, pc);
#endif	/* GPROF */
}

#endif	/* STAT_TIME */

#if GPROF

static void
prof_tick(
	boolean_t	usermode,
	natural_t	pc)
{
	struct profile_vars	*pv;
	prof_uptrint_t		s;

	pv = PROFILE_VARS(cpu_number());

	if (usermode) {
		if (pv->active)
			PROF_CNT_INC(pv->stats.user_ticks);
	}
	else {
		if (pv->active) {
			if (current_processor()->state == CPU_STATE_IDLE)
				PROF_CNT_INC(pv->stats.idle_ticks);
			else
				PROF_CNT_INC(pv->stats.kernel_ticks);

			if ((prof_uptrint_t)pc < _profile_vars.profil_info.lowpc)
				PROF_CNT_INC(pv->stats.too_low);
			else {
				s = (prof_uptrint_t)pc - _profile_vars.profil_info.lowpc;
				if (s < pv->profil_info.text_len) {
					LHISTCOUNTER *ptr = (LHISTCOUNTER *) pv->profil_buf;
					LPROF_CNT_INC(ptr[s / HISTFRACTION]);
				}
				else
					PROF_CNT_INC(pv->stats.too_high);
			}
		}
	}
}

#endif	/* GPROF */

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
 *	File:		etimer.c
 *	Purpose:	Routines for handling the machine independent
 *				event timer.
 */

#include <mach/mach_types.h>

#include <kern/clock.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/macro_help.h>
#include <kern/spl.h>
#include <kern/timer_queue.h>
#include <kern/timer_call.h>

#include <machine/commpage.h>
#include <machine/machine_routines.h>

#include <sys/kdebug.h>
#include <arm/cpu_data.h>
#include <arm/cpu_data_internal.h>
#include <arm/cpu_internal.h>

/*
 * 	Event timer interrupt.
 *
 * XXX a drawback of this implementation is that events serviced earlier must not set deadlines
 *     that occur before the entire chain completes.
 *
 * XXX a better implementation would use a set of generic callouts and iterate over them
 */
void
timer_intr(__unused int inuser, __unused uint64_t iaddr)
{
	uint64_t        abstime, new_idle_timeout_ticks;
	rtclock_timer_t *mytimer;
	cpu_data_t     *cpu_data_ptr;

	cpu_data_ptr = getCpuDatap();
	mytimer = &cpu_data_ptr->rtclock_timer;	/* Point to the event timer */
	abstime = mach_absolute_time();	/* Get the time now */

	/* is it time for an idle timer event? */
	if ((cpu_data_ptr->idle_timer_deadline > 0) && (cpu_data_ptr->idle_timer_deadline <= abstime)) {
		cpu_data_ptr->idle_timer_deadline = 0x0ULL;
		new_idle_timeout_ticks = 0x0ULL;

		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_COMMON, MACHDBG_CODE(DBG_MACH_EXCP_DECI, 3) | DBG_FUNC_START, 0, 0, 0, 0, 0);
		((idle_timer_t)cpu_data_ptr->idle_timer_notify)(cpu_data_ptr->idle_timer_refcon, &new_idle_timeout_ticks);
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_COMMON, MACHDBG_CODE(DBG_MACH_EXCP_DECI, 3) | DBG_FUNC_END, 0, 0, 0, 0, 0);

		/* if a new idle timeout was requested set the new idle timer deadline */
		if (new_idle_timeout_ticks != 0x0ULL) {
			clock_absolutetime_interval_to_deadline(new_idle_timeout_ticks, &cpu_data_ptr->idle_timer_deadline);
		}

		abstime = mach_absolute_time();	/* Get the time again since we ran a bit */
	}

	/* has a pending clock timer expired? */
	if (mytimer->deadline <= abstime) {	/* Have we expired the
						 * deadline? */
		mytimer->has_expired = TRUE;	/* Remember that we popped */
		mytimer->deadline = EndOfAllTime;	/* Set timer request to
							 * the end of all time
							 * in case we have no
							 * more events */
		mytimer->deadline = timer_queue_expire(&mytimer->queue, abstime);
		mytimer->has_expired = FALSE;
		abstime = mach_absolute_time(); /* Get the time again since we ran a bit */
	}

	uint64_t quantum_deadline = cpu_data_ptr->quantum_timer_deadline;
	/* is it the quantum timer expiration? */
	if ((quantum_deadline <= abstime) && (quantum_deadline > 0)) {
		cpu_data_ptr->quantum_timer_deadline = 0;
		quantum_timer_expire(abstime);
	}

	/* Force reload our next deadline */
	cpu_data_ptr->rtcPop = EndOfAllTime;
	/* schedule our next deadline */
	timer_resync_deadlines();
}

/*
 * Set the clock deadline
 */
void 
timer_set_deadline(uint64_t deadline)
{
	rtclock_timer_t *mytimer;
	spl_t           s;
	cpu_data_t     *cpu_data_ptr;

	s = splclock();		/* no interruptions */
	cpu_data_ptr = getCpuDatap();

	mytimer = &cpu_data_ptr->rtclock_timer;	/* Point to the timer itself */
	mytimer->deadline = deadline;	/* Set the new expiration time */

	timer_resync_deadlines();

	splx(s);
}

void
quantum_timer_set_deadline(uint64_t deadline)
{
	cpu_data_t     *cpu_data_ptr;

	/* We should've only come into this path with interrupts disabled */
	assert(ml_get_interrupts_enabled() == FALSE);

	cpu_data_ptr = getCpuDatap();
	cpu_data_ptr->quantum_timer_deadline = deadline;
	timer_resync_deadlines();
}

/*
 * Re-evaluate the outstanding deadlines and select the most proximate.
 *
 * Should be called at splclock.
 */
void
timer_resync_deadlines(void)
{
	uint64_t        deadline;
	rtclock_timer_t *mytimer;
	spl_t           s = splclock();	/* No interruptions please */
	cpu_data_t     *cpu_data_ptr;

	cpu_data_ptr = getCpuDatap();

	deadline = 0;

	/* if we have a clock timer set sooner, pop on that */
	mytimer = &cpu_data_ptr->rtclock_timer;	/* Point to the timer itself */
	if ((!mytimer->has_expired) && (mytimer->deadline > 0))
		deadline = mytimer->deadline;

	/* if we have a idle timer event coming up, how about that? */
	if ((cpu_data_ptr->idle_timer_deadline > 0)
	     && (cpu_data_ptr->idle_timer_deadline < deadline))
		deadline = cpu_data_ptr->idle_timer_deadline;

	/* If we have the quantum timer setup, check that */
	if ((cpu_data_ptr->quantum_timer_deadline > 0)
	    && (cpu_data_ptr->quantum_timer_deadline < deadline))
		deadline = cpu_data_ptr->quantum_timer_deadline;

	if ((deadline == EndOfAllTime)
	    || ((deadline > 0) && (cpu_data_ptr->rtcPop != deadline))) {
		int             decr;

		decr = setPop(deadline);

		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, 
		    MACHDBG_CODE(DBG_MACH_EXCP_DECI, 1) | DBG_FUNC_NONE, 
		    decr, 2, 0, 0, 0);
	}
	splx(s);
}


boolean_t
timer_resort_threshold(__unused uint64_t skew) {
		return FALSE;
}

mpqueue_head_t *
timer_queue_assign(
	uint64_t		deadline)
{
	cpu_data_t				*cpu_data_ptr = getCpuDatap();
	mpqueue_head_t		*queue;

	if (cpu_data_ptr->cpu_running) {
		queue = &cpu_data_ptr->rtclock_timer.queue;

		if (deadline < cpu_data_ptr->rtclock_timer.deadline)
			timer_set_deadline(deadline);
	}
	else
		queue = &cpu_datap(master_cpu)->rtclock_timer.queue;

	return (queue);
}

void
timer_queue_cancel(
	mpqueue_head_t		*queue,
	uint64_t		deadline,
	uint64_t		new_deadline)
{
	if (queue == &getCpuDatap()->rtclock_timer.queue) {
		if (deadline < new_deadline)
			timer_set_deadline(new_deadline);
	}
}

mpqueue_head_t *
timer_queue_cpu(int cpu)
{
	return &cpu_datap(cpu)->rtclock_timer.queue;
}

void
timer_call_cpu(int cpu, void (*fn)(void *), void *arg)
{
	cpu_signal(cpu_datap(cpu), SIGPxcall, (void *) fn, arg);
}

void
timer_call_nosync_cpu(int cpu, void (*fn)(void *), void *arg)
{
	/* XXX Needs error checking and retry */
	cpu_signal(cpu_datap(cpu), SIGPxcall, (void *) fn, arg);
}


static timer_coalescing_priority_params_ns_t tcoal_prio_params_init =
{
	.idle_entry_timer_processing_hdeadline_threshold_ns = 5000ULL * NSEC_PER_USEC,
	.interrupt_timer_coalescing_ilat_threshold_ns = 30ULL * NSEC_PER_USEC,
	.timer_resort_threshold_ns = 50 * NSEC_PER_MSEC,
	.timer_coalesce_rt_shift = 0,
	.timer_coalesce_bg_shift = -5,
	.timer_coalesce_kt_shift = 3,
	.timer_coalesce_fp_shift = 3,
	.timer_coalesce_ts_shift = 3,
	.timer_coalesce_rt_ns_max = 0ULL,
	.timer_coalesce_bg_ns_max = 100 * NSEC_PER_MSEC,
	.timer_coalesce_kt_ns_max = 1 * NSEC_PER_MSEC,
	.timer_coalesce_fp_ns_max = 1 * NSEC_PER_MSEC,
	.timer_coalesce_ts_ns_max = 1 * NSEC_PER_MSEC,
	.latency_qos_scale = {3, 2, 1, -2, -15, -15},
	.latency_qos_ns_max ={1 * NSEC_PER_MSEC, 5 * NSEC_PER_MSEC, 20 * NSEC_PER_MSEC,
			      75 * NSEC_PER_MSEC, 10000 * NSEC_PER_MSEC, 10000 * NSEC_PER_MSEC},
	.latency_tier_rate_limited = {FALSE, FALSE, FALSE, FALSE, TRUE, TRUE},
};
timer_coalescing_priority_params_ns_t * timer_call_get_priority_params(void)
{
	return &tcoal_prio_params_init;
}

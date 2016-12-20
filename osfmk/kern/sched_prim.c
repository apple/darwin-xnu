/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
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
 * @OSF_FREE_COPYRIGHT@
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
/*
 */
/*
 *	File:	sched_prim.c
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1986
 *
 *	Scheduling primitives
 *
 */

#include <debug.h>

#include <mach/mach_types.h>
#include <mach/machine.h>
#include <mach/policy.h>
#include <mach/sync_policy.h>
#include <mach/thread_act.h>

#include <machine/machine_routines.h>
#include <machine/sched_param.h>
#include <machine/machine_cpu.h>
#include <machine/machlimits.h>

#ifdef CONFIG_MACH_APPROXIMATE_TIME
#include <machine/commpage.h>
#endif

#include <kern/kern_types.h>
#include <kern/backtrace.h>
#include <kern/clock.h>
#include <kern/counters.h>
#include <kern/cpu_number.h>
#include <kern/cpu_data.h>
#include <kern/smp.h>
#include <kern/debug.h>
#include <kern/macro_help.h>
#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/processor.h>
#include <kern/queue.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/sfi.h>
#include <kern/syscall_subr.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/ledger.h>
#include <kern/timer_queue.h>
#include <kern/waitq.h>
#include <kern/policy_internal.h>

#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>

#include <mach/sdt.h>

#include <sys/kdebug.h>
#include <kperf/kperf.h>
#include <kern/kpc.h>

#include <kern/pms.h>

struct rt_queue	rt_runq;

uintptr_t sched_thread_on_rt_queue = (uintptr_t)0xDEAFBEE0;

/* Lock RT runq, must be done with interrupts disabled (under splsched()) */
#if __SMP__
decl_simple_lock_data(static,rt_lock);
#define rt_lock_init()		simple_lock_init(&rt_lock, 0)
#define rt_lock_lock()		simple_lock(&rt_lock)
#define rt_lock_unlock()	simple_unlock(&rt_lock)
#else
#define rt_lock_init()		do { } while(0)
#define rt_lock_lock()		do { } while(0)
#define rt_lock_unlock()	do { } while(0)
#endif

#define		DEFAULT_PREEMPTION_RATE		100		/* (1/s) */
int			default_preemption_rate = DEFAULT_PREEMPTION_RATE;

#define		DEFAULT_BG_PREEMPTION_RATE	400		/* (1/s) */
int			default_bg_preemption_rate = DEFAULT_BG_PREEMPTION_RATE;

#define		MAX_UNSAFE_QUANTA			800
int			max_unsafe_quanta = MAX_UNSAFE_QUANTA;

#define		MAX_POLL_QUANTA				2
int			max_poll_quanta = MAX_POLL_QUANTA;

#define		SCHED_POLL_YIELD_SHIFT		4		/* 1/16 */
int			sched_poll_yield_shift = SCHED_POLL_YIELD_SHIFT;

uint64_t	max_poll_computation;

uint64_t	max_unsafe_computation;
uint64_t	sched_safe_duration;

#if defined(CONFIG_SCHED_TIMESHARE_CORE)

uint32_t	std_quantum;
uint32_t	min_std_quantum;
uint32_t	bg_quantum;

uint32_t	std_quantum_us;
uint32_t	bg_quantum_us;

#endif /* CONFIG_SCHED_TIMESHARE_CORE */

uint32_t	thread_depress_time;
uint32_t	default_timeshare_computation;
uint32_t	default_timeshare_constraint;

uint32_t	max_rt_quantum;
uint32_t	min_rt_quantum;

#if defined(CONFIG_SCHED_TIMESHARE_CORE)

unsigned	sched_tick;
uint32_t	sched_tick_interval;

uint32_t	sched_pri_shifts[TH_BUCKET_MAX];
uint32_t	sched_fixed_shift;

uint32_t	sched_decay_usage_age_factor = 1; /* accelerate 5/8^n usage aging */

/* Allow foreground to decay past default to resolve inversions */
#define DEFAULT_DECAY_BAND_LIMIT ((BASEPRI_FOREGROUND - BASEPRI_DEFAULT) + 2)
int 		sched_pri_decay_band_limit = DEFAULT_DECAY_BAND_LIMIT;

/* Defaults for timer deadline profiling */
#define TIMER_DEADLINE_TRACKING_BIN_1_DEFAULT 2000000 /* Timers with deadlines <=
							* 2ms */
#define TIMER_DEADLINE_TRACKING_BIN_2_DEFAULT 5000000 /* Timers with deadlines
							  <= 5ms */

uint64_t timer_deadline_tracking_bin_1;
uint64_t timer_deadline_tracking_bin_2;

#endif /* CONFIG_SCHED_TIMESHARE_CORE */

thread_t sched_maintenance_thread;


uint64_t	sched_one_second_interval;

/* Forwards */

#if defined(CONFIG_SCHED_TIMESHARE_CORE)

static void load_shift_init(void);
static void preempt_pri_init(void);

#endif /* CONFIG_SCHED_TIMESHARE_CORE */

static thread_t	thread_select(
					thread_t			thread,
					processor_t			processor,
					ast_t				reason);

#if CONFIG_SCHED_IDLE_IN_PLACE
static thread_t	thread_select_idle(
					thread_t			thread,
					processor_t			processor);
#endif

thread_t	processor_idle(
					thread_t			thread,
					processor_t			processor);

ast_t
csw_check_locked(	processor_t		processor,
					processor_set_t	pset,
					ast_t			check_reason);

static void processor_setrun(
				 processor_t			processor,
				 thread_t			thread,
				 integer_t			options);

static void
sched_realtime_init(void);

static void
sched_realtime_timebase_init(void);

static void
sched_timer_deadline_tracking_init(void);

#if	DEBUG
extern int debug_task;
#define TLOG(a, fmt, args...) if(debug_task & a) kprintf(fmt, ## args)
#else
#define TLOG(a, fmt, args...) do {} while (0)
#endif

static processor_t
thread_bind_internal(
	thread_t		thread,
	processor_t		processor);

static void
sched_vm_group_maintenance(void);

#if defined(CONFIG_SCHED_TIMESHARE_CORE)
int8_t		sched_load_shifts[NRQS];
bitmap_t	sched_preempt_pri[BITMAP_LEN(NRQS)];
#endif /* CONFIG_SCHED_TIMESHARE_CORE */

const struct sched_dispatch_table *sched_current_dispatch = NULL;

/*
 * Statically allocate a buffer to hold the longest possible
 * scheduler description string, as currently implemented.
 * bsd/kern/kern_sysctl.c has a corresponding definition in bsd/
 * to export to userspace via sysctl(3). If either version
 * changes, update the other.
 *
 * Note that in addition to being an upper bound on the strings
 * in the kernel, it's also an exact parameter to PE_get_default(),
 * which interrogates the device tree on some platforms. That
 * API requires the caller know the exact size of the device tree
 * property, so we need both a legacy size (32) and the current size
 * (48) to deal with old and new device trees. The device tree property
 * is similarly padded to a fixed size so that the same kernel image
 * can run on multiple devices with different schedulers configured
 * in the device tree.
 */
char sched_string[SCHED_STRING_MAX_LENGTH];

uint32_t sched_debug_flags;

/* Global flag which indicates whether Background Stepper Context is enabled */
static int cpu_throttle_enabled = 1;

void
sched_init(void)
{
	char sched_arg[SCHED_STRING_MAX_LENGTH] = { '\0' };

	/* Check for runtime selection of the scheduler algorithm */
	if (!PE_parse_boot_argn("sched", sched_arg, sizeof (sched_arg))) {
		/* If no boot-args override, look in device tree */
		if (!PE_get_default("kern.sched", sched_arg,
							SCHED_STRING_MAX_LENGTH)) {
			sched_arg[0] = '\0';
		}
	}

	
	if (!PE_parse_boot_argn("sched_pri_decay_limit", &sched_pri_decay_band_limit, sizeof(sched_pri_decay_band_limit))) {
		/* No boot-args, check in device tree */
		if (!PE_get_default("kern.sched_pri_decay_limit",
							&sched_pri_decay_band_limit,
							sizeof(sched_pri_decay_band_limit))) {
			/* Allow decay all the way to normal limits */
			sched_pri_decay_band_limit = DEFAULT_DECAY_BAND_LIMIT;
		}
	}

	kprintf("Setting scheduler priority decay band limit %d\n", sched_pri_decay_band_limit);

	if (strlen(sched_arg) > 0) {
		if (0) {
			/* Allow pattern below */
#if defined(CONFIG_SCHED_TRADITIONAL)
		} else if (0 == strcmp(sched_arg, sched_traditional_dispatch.sched_name)) {
			sched_current_dispatch = &sched_traditional_dispatch;
		} else if (0 == strcmp(sched_arg, sched_traditional_with_pset_runqueue_dispatch.sched_name)) {
			sched_current_dispatch = &sched_traditional_with_pset_runqueue_dispatch;
#endif
#if defined(CONFIG_SCHED_PROTO)
		} else if (0 == strcmp(sched_arg, sched_proto_dispatch.sched_name)) {
			sched_current_dispatch = &sched_proto_dispatch;
#endif
#if defined(CONFIG_SCHED_GRRR)
		} else if (0 == strcmp(sched_arg, sched_grrr_dispatch.sched_name)) {
			sched_current_dispatch = &sched_grrr_dispatch;
#endif
#if defined(CONFIG_SCHED_MULTIQ)
		} else if (0 == strcmp(sched_arg, sched_multiq_dispatch.sched_name)) {
			sched_current_dispatch = &sched_multiq_dispatch;
		} else if (0 == strcmp(sched_arg, sched_dualq_dispatch.sched_name)) {
			sched_current_dispatch = &sched_dualq_dispatch;
#endif
		} else {
#if defined(CONFIG_SCHED_TRADITIONAL)
			printf("Unrecognized scheduler algorithm: %s\n", sched_arg);
			printf("Scheduler: Using instead: %s\n", sched_traditional_with_pset_runqueue_dispatch.sched_name);
			sched_current_dispatch = &sched_traditional_with_pset_runqueue_dispatch;
#else
			panic("Unrecognized scheduler algorithm: %s", sched_arg);
#endif
		}
		kprintf("Scheduler: Runtime selection of %s\n", SCHED(sched_name));
	} else {
#if   defined(CONFIG_SCHED_MULTIQ)
		sched_current_dispatch = &sched_multiq_dispatch;
#elif defined(CONFIG_SCHED_TRADITIONAL)
		sched_current_dispatch = &sched_traditional_with_pset_runqueue_dispatch;
#elif defined(CONFIG_SCHED_PROTO)
		sched_current_dispatch = &sched_proto_dispatch;
#elif defined(CONFIG_SCHED_GRRR)
		sched_current_dispatch = &sched_grrr_dispatch;
#else
#error No default scheduler implementation
#endif
		kprintf("Scheduler: Default of %s\n", SCHED(sched_name));
	}

	strlcpy(sched_string, SCHED(sched_name), sizeof(sched_string));

	if (PE_parse_boot_argn("sched_debug", &sched_debug_flags, sizeof(sched_debug_flags))) {
		kprintf("Scheduler: Debug flags 0x%08x\n", sched_debug_flags);
	}
	
	SCHED(init)();
	sched_realtime_init();
	ast_init();
	sched_timer_deadline_tracking_init();

	SCHED(pset_init)(&pset0);
	SCHED(processor_init)(master_processor);
}

void
sched_timebase_init(void)
{
	uint64_t	abstime;
	
	clock_interval_to_absolutetime_interval(1, NSEC_PER_SEC, &abstime);
	sched_one_second_interval = abstime;
	
	SCHED(timebase_init)();
	sched_realtime_timebase_init();
}

#if defined(CONFIG_SCHED_TIMESHARE_CORE)

void
sched_timeshare_init(void)
{
	/*
	 * Calculate the timeslicing quantum
	 * in us.
	 */
	if (default_preemption_rate < 1)
		default_preemption_rate = DEFAULT_PREEMPTION_RATE;
	std_quantum_us = (1000 * 1000) / default_preemption_rate;

	printf("standard timeslicing quantum is %d us\n", std_quantum_us);

	if (default_bg_preemption_rate < 1)
		default_bg_preemption_rate = DEFAULT_BG_PREEMPTION_RATE;
	bg_quantum_us = (1000 * 1000) / default_bg_preemption_rate;

	printf("standard background quantum is %d us\n", bg_quantum_us);

	load_shift_init();
	preempt_pri_init();
	sched_tick = 0;
}

void
sched_timeshare_timebase_init(void)
{
	uint64_t	abstime;
	uint32_t	shift;

	/* standard timeslicing quantum */
	clock_interval_to_absolutetime_interval(
							std_quantum_us, NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	std_quantum = (uint32_t)abstime;

	/* smallest remaining quantum (250 us) */
	clock_interval_to_absolutetime_interval(250, NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	min_std_quantum = (uint32_t)abstime;

	/* quantum for background tasks */
	clock_interval_to_absolutetime_interval(
							bg_quantum_us, NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	bg_quantum = (uint32_t)abstime;

	/* scheduler tick interval */
	clock_interval_to_absolutetime_interval(USEC_PER_SEC >> SCHED_TICK_SHIFT,
													NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	sched_tick_interval = (uint32_t)abstime;

	/*
	 * Compute conversion factor from usage to
	 * timesharing priorities with 5/8 ** n aging.
	 */
	abstime = (abstime * 5) / 3;
	for (shift = 0; abstime > BASEPRI_DEFAULT; ++shift)
		abstime >>= 1;
	sched_fixed_shift = shift;

	for (uint32_t i = 0 ; i < TH_BUCKET_MAX ; i++)
		sched_pri_shifts[i] = INT8_MAX;

	max_unsafe_computation = ((uint64_t)max_unsafe_quanta) * std_quantum;
	sched_safe_duration = 2 * ((uint64_t)max_unsafe_quanta) * std_quantum;

	max_poll_computation = ((uint64_t)max_poll_quanta) * std_quantum;
	thread_depress_time = 1 * std_quantum;
	default_timeshare_computation = std_quantum / 2;
	default_timeshare_constraint = std_quantum;

}

#endif /* CONFIG_SCHED_TIMESHARE_CORE */

static void
sched_realtime_init(void)
{
	rt_lock_init();

	rt_runq.count = 0;
	queue_init(&rt_runq.queue);
}

static void
sched_realtime_timebase_init(void)
{
	uint64_t abstime;

	/* smallest rt computaton (50 us) */
	clock_interval_to_absolutetime_interval(50, NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	min_rt_quantum = (uint32_t)abstime;

	/* maximum rt computation (50 ms) */
	clock_interval_to_absolutetime_interval(
		50, 1000*NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	max_rt_quantum = (uint32_t)abstime;

}

#if defined(CONFIG_SCHED_TIMESHARE_CORE)

/*
 * Set up values for timeshare
 * loading factors.
 */
static void
load_shift_init(void)
{
	int8_t		k, *p = sched_load_shifts;
	uint32_t	i, j;

	uint32_t	sched_decay_penalty = 1;

	if (PE_parse_boot_argn("sched_decay_penalty", &sched_decay_penalty, sizeof (sched_decay_penalty))) {
		kprintf("Overriding scheduler decay penalty %u\n", sched_decay_penalty);
	}

	if (PE_parse_boot_argn("sched_decay_usage_age_factor", &sched_decay_usage_age_factor, sizeof (sched_decay_usage_age_factor))) {
		kprintf("Overriding scheduler decay usage age factor %u\n", sched_decay_usage_age_factor);
	}

	if (sched_decay_penalty == 0) {
		/*
		 * There is no penalty for timeshare threads for using too much
		 * CPU, so set all load shifts to INT8_MIN. Even under high load,
		 * sched_pri_shift will be >INT8_MAX, and there will be no
		 * penalty applied to threads (nor will sched_usage be updated per
		 * thread).
		 */
		for (i = 0; i < NRQS; i++) {
			sched_load_shifts[i] = INT8_MIN;
		}

		return;
	}

	*p++ = INT8_MIN; *p++ = 0;

	/*
	 * For a given system load "i", the per-thread priority
	 * penalty per quantum of CPU usage is ~2^k priority
	 * levels. "sched_decay_penalty" can cause more
	 * array entries to be filled with smaller "k" values
	 */
	for (i = 2, j = 1 << sched_decay_penalty, k = 1; i < NRQS; ++k) {
		for (j <<= 1; (i < j) && (i < NRQS); ++i)
			*p++ = k;
	}
}

static void
preempt_pri_init(void)
{
	bitmap_t *p = sched_preempt_pri;

	for (int i = BASEPRI_FOREGROUND; i < MINPRI_KERNEL; ++i)
		bitmap_set(p, i);

	for (int i = BASEPRI_PREEMPT; i <= MAXPRI; ++i)
		bitmap_set(p, i);
}

#endif /* CONFIG_SCHED_TIMESHARE_CORE */

/*
 *	Thread wait timer expiration.
 */
void
thread_timer_expire(
	void			*p0,
	__unused void	*p1)
{
	thread_t		thread = p0;
	spl_t			s;

	assert_thread_magic(thread);

	s = splsched();
	thread_lock(thread);
	if (--thread->wait_timer_active == 0) {
		if (thread->wait_timer_is_set) {
			thread->wait_timer_is_set = FALSE;
			clear_wait_internal(thread, THREAD_TIMED_OUT);
		}
	}
	thread_unlock(thread);
	splx(s);
}

/*
 *	thread_unblock:
 *
 *	Unblock thread on wake up.
 *
 *	Returns TRUE if the thread should now be placed on the runqueue.
 *
 *	Thread must be locked.
 *
 *	Called at splsched().
 */
boolean_t
thread_unblock(
	thread_t		thread,
	wait_result_t	wresult)
{
	boolean_t		ready_for_runq = FALSE;
	thread_t		cthread = current_thread();
	uint32_t		new_run_count;

	/*
	 *	Set wait_result.
	 */
	thread->wait_result = wresult;

	/*
	 *	Cancel pending wait timer.
	 */
	if (thread->wait_timer_is_set) {
		if (timer_call_cancel(&thread->wait_timer))
			thread->wait_timer_active--;
		thread->wait_timer_is_set = FALSE;
	}

	/*
	 *	Update scheduling state: not waiting,
	 *	set running.
	 */
	thread->state &= ~(TH_WAIT|TH_UNINT);

	if (!(thread->state & TH_RUN)) {
		thread->state |= TH_RUN;
		thread->last_made_runnable_time = mach_approximate_time();

		ready_for_runq = TRUE;

		(*thread->sched_call)(SCHED_CALL_UNBLOCK, thread);

		/* Update the runnable thread count */
		new_run_count = sched_run_incr(thread);
	} else {
		/*
		 * Either the thread is idling in place on another processor,
		 * or it hasn't finished context switching yet.
		 */
#if CONFIG_SCHED_IDLE_IN_PLACE
		if (thread->state & TH_IDLE) {
			processor_t		processor = thread->last_processor;

			if (processor != current_processor())
				machine_signal_idle(processor);
		}
#else
		assert((thread->state & TH_IDLE) == 0);
#endif
		/*
		 * The run count is only dropped after the context switch completes
		 * and the thread is still waiting, so we should not run_incr here
		 */
		new_run_count = sched_run_buckets[TH_BUCKET_RUN];
	}


	/*
	 * Calculate deadline for real-time threads.
	 */
	if (thread->sched_mode == TH_MODE_REALTIME) {
		uint64_t ctime;

		ctime = mach_absolute_time();
		thread->realtime.deadline = thread->realtime.constraint + ctime;
	}

	/*
	 * Clear old quantum, fail-safe computation, etc.
	 */
	thread->quantum_remaining = 0;
	thread->computation_metered = 0;
	thread->reason = AST_NONE;

	/* Obtain power-relevant interrupt and "platform-idle exit" statistics.
	 * We also account for "double hop" thread signaling via
	 * the thread callout infrastructure.
	 * DRK: consider removing the callout wakeup counters in the future
	 * they're present for verification at the moment.
	 */
	boolean_t aticontext, pidle;
	ml_get_power_state(&aticontext, &pidle);

	if (__improbable(aticontext && !(thread_get_tag_internal(thread) & THREAD_TAG_CALLOUT))) {
		ledger_credit(thread->t_ledger, task_ledgers.interrupt_wakeups, 1);
		DTRACE_SCHED2(iwakeup, struct thread *, thread, struct proc *, thread->task->bsd_info);

		uint64_t ttd = PROCESSOR_DATA(current_processor(), timer_call_ttd);

		if (ttd) {
			if (ttd <= timer_deadline_tracking_bin_1)
				thread->thread_timer_wakeups_bin_1++;
			else
				if (ttd <= timer_deadline_tracking_bin_2)
					thread->thread_timer_wakeups_bin_2++;
		}

		if (pidle) {
			ledger_credit(thread->t_ledger, task_ledgers.platform_idle_wakeups, 1);
		}

	} else if (thread_get_tag_internal(cthread) & THREAD_TAG_CALLOUT) {
		if (cthread->callout_woken_from_icontext) {
			ledger_credit(thread->t_ledger, task_ledgers.interrupt_wakeups, 1);
			thread->thread_callout_interrupt_wakeups++;
			if (cthread->callout_woken_from_platform_idle) {
				ledger_credit(thread->t_ledger, task_ledgers.platform_idle_wakeups, 1);
				thread->thread_callout_platform_idle_wakeups++;
			}
			
			cthread->callout_woke_thread = TRUE;
		}
	}
	
	if (thread_get_tag_internal(thread) & THREAD_TAG_CALLOUT) {
		thread->callout_woken_from_icontext = aticontext;
		thread->callout_woken_from_platform_idle = pidle;
		thread->callout_woke_thread = FALSE;
	}

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		MACHDBG_CODE(DBG_MACH_SCHED,MACH_MAKE_RUNNABLE) | DBG_FUNC_NONE,
		(uintptr_t)thread_tid(thread), thread->sched_pri, thread->wait_result,
		sched_run_buckets[TH_BUCKET_RUN], 0);

	DTRACE_SCHED2(wakeup, struct thread *, thread, struct proc *, thread->task->bsd_info);

	return (ready_for_runq);
}

/*
 *	Routine:	thread_go
 *	Purpose:
 *		Unblock and dispatch thread.
 *	Conditions:
 *		thread lock held, IPC locks may be held.
 *		thread must have been pulled from wait queue under same lock hold.
 *		thread must have been waiting
 *	Returns:
 *		KERN_SUCCESS - Thread was set running
 *
 * TODO: This should return void
 */
kern_return_t
thread_go(
          thread_t        thread,
          wait_result_t   wresult)
{
	assert_thread_magic(thread);

	assert(thread->at_safe_point == FALSE);
	assert(thread->wait_event == NO_EVENT64);
	assert(thread->waitq == NULL);

	assert(!(thread->state & (TH_TERMINATE|TH_TERMINATE2)));
	assert(thread->state & TH_WAIT);


	if (thread_unblock(thread, wresult)) {
#if	SCHED_TRACE_THREAD_WAKEUPS
		backtrace(&thread->thread_wakeup_bt[0],
		    (sizeof(thread->thread_wakeup_bt)/sizeof(uintptr_t)));
#endif
		thread_setrun(thread, SCHED_PREEMPT | SCHED_TAILQ);
	}

	return (KERN_SUCCESS);
}

/*
 *	Routine:	thread_mark_wait_locked
 *	Purpose:
 *		Mark a thread as waiting.  If, given the circumstances,
 *		it doesn't want to wait (i.e. already aborted), then
 *		indicate that in the return value.
 *	Conditions:
 *		at splsched() and thread is locked.
 */
__private_extern__
wait_result_t
thread_mark_wait_locked(
	thread_t			thread,
	wait_interrupt_t 	interruptible)
{
	boolean_t		at_safe_point;

	assert(!(thread->state & (TH_WAIT|TH_IDLE|TH_UNINT|TH_TERMINATE2)));

	/*
	 *	The thread may have certain types of interrupts/aborts masked
	 *	off.  Even if the wait location says these types of interrupts
	 *	are OK, we have to honor mask settings (outer-scoped code may
	 *	not be able to handle aborts at the moment).
	 */
	if (interruptible > (thread->options & TH_OPT_INTMASK))
		interruptible = thread->options & TH_OPT_INTMASK;

	at_safe_point = (interruptible == THREAD_ABORTSAFE);

	if (	interruptible == THREAD_UNINT			||
			!(thread->sched_flags & TH_SFLAG_ABORT)	||
			(!at_safe_point &&
				(thread->sched_flags & TH_SFLAG_ABORTSAFELY))) {

		if ( !(thread->state & TH_TERMINATE))
			DTRACE_SCHED(sleep);

		thread->state |= (interruptible) ? TH_WAIT : (TH_WAIT | TH_UNINT);
		thread->at_safe_point = at_safe_point;
		return (thread->wait_result = THREAD_WAITING);
	}
	else
	if (thread->sched_flags & TH_SFLAG_ABORTSAFELY)
		thread->sched_flags &= ~TH_SFLAG_ABORTED_MASK;

	return (thread->wait_result = THREAD_INTERRUPTED);
}

/*
 *	Routine:	thread_interrupt_level
 *	Purpose:
 *	        Set the maximum interruptible state for the
 *		current thread.  The effective value of any
 *		interruptible flag passed into assert_wait
 *		will never exceed this.
 *
 *		Useful for code that must not be interrupted,
 *		but which calls code that doesn't know that.
 *	Returns:
 *		The old interrupt level for the thread.
 */
__private_extern__ 
wait_interrupt_t
thread_interrupt_level(
	wait_interrupt_t new_level)
{
	thread_t thread = current_thread();
	wait_interrupt_t result = thread->options & TH_OPT_INTMASK;

	thread->options = (thread->options & ~TH_OPT_INTMASK) | (new_level & TH_OPT_INTMASK);

	return result;
}

/*
 * Check to see if an assert wait is possible, without actually doing one.
 * This is used by debug code in locks and elsewhere to verify that it is
 * always OK to block when trying to take a blocking lock (since waiting
 * for the actual assert_wait to catch the case may make it hard to detect
 * this case.
 */
boolean_t
assert_wait_possible(void)
{

	thread_t thread;

#if	DEBUG
	if(debug_mode) return TRUE;		/* Always succeed in debug mode */
#endif
	
	thread = current_thread();

	return (thread == NULL || waitq_wait_possible(thread));
}

/*
 *	assert_wait:
 *
 *	Assert that the current thread is about to go to
 *	sleep until the specified event occurs.
 */
wait_result_t
assert_wait(
	event_t				event,
	wait_interrupt_t	interruptible)
{
	if (__improbable(event == NO_EVENT))
		panic("%s() called with NO_EVENT", __func__);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		MACHDBG_CODE(DBG_MACH_SCHED, MACH_WAIT)|DBG_FUNC_NONE,
		VM_KERNEL_UNSLIDE_OR_PERM(event), 0, 0, 0, 0);

	struct waitq *waitq;
	waitq = global_eventq(event);
	return waitq_assert_wait64(waitq, CAST_EVENT64_T(event), interruptible, TIMEOUT_WAIT_FOREVER);
}

/*
 *	assert_wait_queue:
 *
 *	Return the global waitq for the specified event
 */
struct waitq *
assert_wait_queue(
	event_t				event)
{
	return global_eventq(event);
}

wait_result_t
assert_wait_timeout(
	event_t				event,
	wait_interrupt_t	interruptible,
	uint32_t			interval,
	uint32_t			scale_factor)
{
	thread_t			thread = current_thread();
	wait_result_t		wresult;
	uint64_t			deadline;
	spl_t				s;

	if (__improbable(event == NO_EVENT))
		panic("%s() called with NO_EVENT", __func__);

	struct waitq *waitq;
	waitq = global_eventq(event);

	s = splsched();
	waitq_lock(waitq);

	clock_interval_to_deadline(interval, scale_factor, &deadline);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				  MACHDBG_CODE(DBG_MACH_SCHED, MACH_WAIT)|DBG_FUNC_NONE,
				  VM_KERNEL_UNSLIDE_OR_PERM(event), interruptible, deadline, 0, 0);

	wresult = waitq_assert_wait64_locked(waitq, CAST_EVENT64_T(event),
					     interruptible,
					     TIMEOUT_URGENCY_SYS_NORMAL,
					     deadline, TIMEOUT_NO_LEEWAY,
					     thread);

	waitq_unlock(waitq);
	splx(s);
	return wresult;
}

wait_result_t
assert_wait_timeout_with_leeway(
	event_t				event,
	wait_interrupt_t	interruptible,
	wait_timeout_urgency_t	urgency,
	uint32_t			interval,
	uint32_t			leeway,
	uint32_t			scale_factor)
{
	thread_t			thread = current_thread();
	wait_result_t		wresult;
	uint64_t			deadline;
	uint64_t			abstime;
	uint64_t			slop;
	uint64_t			now;
	spl_t				s;

	if (__improbable(event == NO_EVENT))
		panic("%s() called with NO_EVENT", __func__);

	now = mach_absolute_time();
	clock_interval_to_absolutetime_interval(interval, scale_factor, &abstime);
	deadline = now + abstime;

	clock_interval_to_absolutetime_interval(leeway, scale_factor, &slop);

	struct waitq *waitq;
	waitq = global_eventq(event);

	s = splsched();
	waitq_lock(waitq);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				  MACHDBG_CODE(DBG_MACH_SCHED, MACH_WAIT)|DBG_FUNC_NONE,
				  VM_KERNEL_UNSLIDE_OR_PERM(event), interruptible, deadline, 0, 0);

	wresult = waitq_assert_wait64_locked(waitq, CAST_EVENT64_T(event),
					     interruptible,
					     urgency, deadline, slop,
					     thread);

	waitq_unlock(waitq);
	splx(s);
	return wresult;
}

wait_result_t
assert_wait_deadline(
	event_t				event,
	wait_interrupt_t	interruptible,
	uint64_t			deadline)
{
	thread_t			thread = current_thread();
	wait_result_t		wresult;
	spl_t				s;

	if (__improbable(event == NO_EVENT))
		panic("%s() called with NO_EVENT", __func__);

	struct waitq *waitq;
	waitq = global_eventq(event);

	s = splsched();
	waitq_lock(waitq);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				  MACHDBG_CODE(DBG_MACH_SCHED, MACH_WAIT)|DBG_FUNC_NONE,
				  VM_KERNEL_UNSLIDE_OR_PERM(event), interruptible, deadline, 0, 0);

	wresult = waitq_assert_wait64_locked(waitq, CAST_EVENT64_T(event),
					     interruptible,
					     TIMEOUT_URGENCY_SYS_NORMAL, deadline,
					     TIMEOUT_NO_LEEWAY, thread);
	waitq_unlock(waitq);
	splx(s);
	return wresult;
}

wait_result_t
assert_wait_deadline_with_leeway(
	event_t				event,
	wait_interrupt_t	interruptible,
	wait_timeout_urgency_t	urgency,
	uint64_t			deadline,
	uint64_t			leeway)
{
	thread_t			thread = current_thread();
	wait_result_t		wresult;
	spl_t				s;

	if (__improbable(event == NO_EVENT))
		panic("%s() called with NO_EVENT", __func__);

	struct waitq *waitq;
	waitq = global_eventq(event);

	s = splsched();
	waitq_lock(waitq);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				  MACHDBG_CODE(DBG_MACH_SCHED, MACH_WAIT)|DBG_FUNC_NONE,
				  VM_KERNEL_UNSLIDE_OR_PERM(event), interruptible, deadline, 0, 0);

	wresult = waitq_assert_wait64_locked(waitq, CAST_EVENT64_T(event),
					     interruptible,
					     urgency, deadline, leeway,
					     thread);
	waitq_unlock(waitq);
	splx(s);
	return wresult;
}

/*
 * thread_isoncpu:
 *
 * Return TRUE if a thread is running on a processor such that an AST
 * is needed to pull it out of userspace execution, or if executing in
 * the kernel, bring to a context switch boundary that would cause
 * thread state to be serialized in the thread PCB.
 * 
 * Thread locked, returns the same way. While locked, fields
 * like "state" cannot change. "runq" can change only from set to unset.
 */
static inline boolean_t
thread_isoncpu(thread_t thread)
{
	/* Not running or runnable */
	if (!(thread->state & TH_RUN))
		return (FALSE);

	/* Waiting on a runqueue, not currently running */
	/* TODO: This is invalid - it can get dequeued without thread lock, but not context switched. */
	if (thread->runq != PROCESSOR_NULL)
		return (FALSE);

	/*
	 * Thread does not have a stack yet
	 * It could be on the stack alloc queue or preparing to be invoked
	 */
	if (!thread->kernel_stack)
		return (FALSE);

	/*
	 * Thread must be running on a processor, or
	 * about to run, or just did run. In all these
	 * cases, an AST to the processor is needed
	 * to guarantee that the thread is kicked out
	 * of userspace and the processor has
	 * context switched (and saved register state).
	 */
	return (TRUE);
}

/*
 * thread_stop:
 *
 * Force a preemption point for a thread and wait
 * for it to stop running on a CPU. If a stronger
 * guarantee is requested, wait until no longer
 * runnable. Arbitrates access among
 * multiple stop requests. (released by unstop)
 *
 * The thread must enter a wait state and stop via a
 * separate means.
 *
 * Returns FALSE if interrupted.
 */
boolean_t
thread_stop(
	thread_t		thread,
	boolean_t	until_not_runnable)
{
	wait_result_t	wresult;
	spl_t			s = splsched();
	boolean_t		oncpu;

	wake_lock(thread);
	thread_lock(thread);

	while (thread->state & TH_SUSP) {
		thread->wake_active = TRUE;
		thread_unlock(thread);

		wresult = assert_wait(&thread->wake_active, THREAD_ABORTSAFE);
		wake_unlock(thread);
		splx(s);

		if (wresult == THREAD_WAITING)
			wresult = thread_block(THREAD_CONTINUE_NULL);

		if (wresult != THREAD_AWAKENED)
			return (FALSE);

		s = splsched();
		wake_lock(thread);
		thread_lock(thread);
	}

	thread->state |= TH_SUSP;

	while ((oncpu = thread_isoncpu(thread)) ||
		   (until_not_runnable && (thread->state & TH_RUN))) {
		processor_t		processor;
		
		if (oncpu) {
			assert(thread->state & TH_RUN);
			processor = thread->chosen_processor;
			cause_ast_check(processor);
		}

		thread->wake_active = TRUE;
		thread_unlock(thread);

		wresult = assert_wait(&thread->wake_active, THREAD_ABORTSAFE);
		wake_unlock(thread);
		splx(s);

		if (wresult == THREAD_WAITING)
			wresult = thread_block(THREAD_CONTINUE_NULL);

		if (wresult != THREAD_AWAKENED) {
			thread_unstop(thread);
			return (FALSE);
		}

		s = splsched();
		wake_lock(thread);
		thread_lock(thread);
	}

	thread_unlock(thread);
	wake_unlock(thread);
	splx(s);
	
	/*
	 * We return with the thread unlocked. To prevent it from
	 * transitioning to a runnable state (or from TH_RUN to
	 * being on the CPU), the caller must ensure the thread
	 * is stopped via an external means (such as an AST)
	 */

	return (TRUE);
}

/*
 * thread_unstop:
 *
 * Release a previous stop request and set
 * the thread running if appropriate.
 *
 * Use only after a successful stop operation.
 */
void
thread_unstop(
	thread_t	thread)
{
	spl_t		s = splsched();

	wake_lock(thread);
	thread_lock(thread);

	assert((thread->state & (TH_RUN|TH_WAIT|TH_SUSP)) != TH_SUSP);

	if (thread->state & TH_SUSP) {
		thread->state &= ~TH_SUSP;

		if (thread->wake_active) {
			thread->wake_active = FALSE;
			thread_unlock(thread);

			thread_wakeup(&thread->wake_active);
			wake_unlock(thread);
			splx(s);

			return;
		}
	}

	thread_unlock(thread);
	wake_unlock(thread);
	splx(s);
}

/*
 * thread_wait:
 *
 * Wait for a thread to stop running. (non-interruptible)
 *
 */
void
thread_wait(
	thread_t	thread,
	boolean_t	until_not_runnable)
{
	wait_result_t	wresult;
	boolean_t 	oncpu;
	processor_t	processor;
	spl_t		s = splsched();

	wake_lock(thread);
	thread_lock(thread);

	/*
	 * Wait until not running on a CPU.  If stronger requirement
	 * desired, wait until not runnable.  Assumption: if thread is
	 * on CPU, then TH_RUN is set, so we're not waiting in any case
	 * where the original, pure "TH_RUN" check would have let us 
	 * finish.
	 */
	while ((oncpu = thread_isoncpu(thread)) ||
			(until_not_runnable && (thread->state & TH_RUN))) {

		if (oncpu) {
			assert(thread->state & TH_RUN);
			processor = thread->chosen_processor;
			cause_ast_check(processor);
		}

		thread->wake_active = TRUE;
		thread_unlock(thread);

		wresult = assert_wait(&thread->wake_active, THREAD_UNINT);
		wake_unlock(thread);
		splx(s);

		if (wresult == THREAD_WAITING)
			thread_block(THREAD_CONTINUE_NULL);

		s = splsched();
		wake_lock(thread);
		thread_lock(thread);
	}

	thread_unlock(thread);
	wake_unlock(thread);
	splx(s);
}

/*
 *	Routine: clear_wait_internal
 *
 *		Clear the wait condition for the specified thread.
 *		Start the thread executing if that is appropriate.
 *	Arguments:
 *		thread		thread to awaken
 *		result		Wakeup result the thread should see
 *	Conditions:
 *		At splsched
 *		the thread is locked.
 *	Returns:
 *		KERN_SUCCESS		thread was rousted out a wait
 *		KERN_FAILURE		thread was waiting but could not be rousted
 *		KERN_NOT_WAITING	thread was not waiting
 */
__private_extern__ kern_return_t
clear_wait_internal(
	thread_t		thread,
	wait_result_t	wresult)
{
	uint32_t	i = LockTimeOutUsec;
	struct waitq *waitq = thread->waitq;
	
	do {
		if (wresult == THREAD_INTERRUPTED && (thread->state & TH_UNINT))
			return (KERN_FAILURE);

		if (waitq != NULL) {
			if (!waitq_pull_thread_locked(waitq, thread)) {
				thread_unlock(thread);
				delay(1);
				if (i > 0 && !machine_timeout_suspended())
					i--;
				thread_lock(thread);
				if (waitq != thread->waitq)
					return KERN_NOT_WAITING;
				continue;
			}
		}

		/* TODO: Can we instead assert TH_TERMINATE is not set?  */
		if ((thread->state & (TH_WAIT|TH_TERMINATE)) == TH_WAIT)
			return (thread_go(thread, wresult));
		else
			return (KERN_NOT_WAITING);
	} while (i > 0);

	panic("clear_wait_internal: deadlock: thread=%p, wq=%p, cpu=%d\n",
		  thread, waitq, cpu_number());

	return (KERN_FAILURE);
}


/*
 *	clear_wait:
 *
 *	Clear the wait condition for the specified thread.  Start the thread
 *	executing if that is appropriate.
 *
 *	parameters:
 *	  thread		thread to awaken
 *	  result		Wakeup result the thread should see
 */
kern_return_t
clear_wait(
	thread_t		thread,
	wait_result_t	result)
{
	kern_return_t ret;
	spl_t		s;

	s = splsched();
	thread_lock(thread);
	ret = clear_wait_internal(thread, result);
	thread_unlock(thread);
	splx(s);
	return ret;
}


/*
 *	thread_wakeup_prim:
 *
 *	Common routine for thread_wakeup, thread_wakeup_with_result,
 *	and thread_wakeup_one.
 *
 */
kern_return_t
thread_wakeup_prim(
                   event_t          event,
                   boolean_t        one_thread,
                   wait_result_t    result)
{
	if (__improbable(event == NO_EVENT))
		panic("%s() called with NO_EVENT", __func__);

	struct waitq *wq = global_eventq(event);

	if (one_thread)
		return waitq_wakeup64_one(wq, CAST_EVENT64_T(event), result, WAITQ_ALL_PRIORITIES);
	else
		return waitq_wakeup64_all(wq, CAST_EVENT64_T(event), result, WAITQ_ALL_PRIORITIES);
}

/*
 * Wakeup a specified thread if and only if it's waiting for this event
 */
kern_return_t
thread_wakeup_thread(
                     event_t         event,
                     thread_t        thread)
{
	if (__improbable(event == NO_EVENT))
		panic("%s() called with NO_EVENT", __func__);

	struct waitq *wq = global_eventq(event);

	return waitq_wakeup64_thread(wq, CAST_EVENT64_T(event), thread, THREAD_AWAKENED);
}

/*
 * Wakeup a thread waiting on an event and promote it to a priority.
 *
 * Requires woken thread to un-promote itself when done.
 */
kern_return_t
thread_wakeup_one_with_pri(
                           event_t      event,
                           int          priority)
{
	if (__improbable(event == NO_EVENT))
		panic("%s() called with NO_EVENT", __func__);

	struct waitq *wq = global_eventq(event);

	return waitq_wakeup64_one(wq, CAST_EVENT64_T(event), THREAD_AWAKENED, priority);
}

/*
 * Wakeup a thread waiting on an event,
 * promote it to a priority,
 * and return a reference to the woken thread.
 *
 * Requires woken thread to un-promote itself when done.
 */
thread_t
thread_wakeup_identify(event_t  event,
                       int      priority)
{
	if (__improbable(event == NO_EVENT))
		panic("%s() called with NO_EVENT", __func__);

	struct waitq *wq = global_eventq(event);

	return waitq_wakeup64_identify(wq, CAST_EVENT64_T(event), THREAD_AWAKENED, priority);
}

/*
 *	thread_bind:
 *
 *	Force the current thread to execute on the specified processor.
 *	Takes effect after the next thread_block().
 *
 *	Returns the previous binding.  PROCESSOR_NULL means
 *	not bound.
 *
 *	XXX - DO NOT export this to users - XXX
 */
processor_t
thread_bind(
	processor_t		processor)
{
	thread_t		self = current_thread();
	processor_t		prev;
	spl_t			s;

	s = splsched();
	thread_lock(self);

	prev = thread_bind_internal(self, processor);

	thread_unlock(self);
	splx(s);

	return (prev);
}

/*
 * thread_bind_internal:
 *
 * If the specified thread is not the current thread, and it is currently
 * running on another CPU, a remote AST must be sent to that CPU to cause
 * the thread to migrate to its bound processor. Otherwise, the migration
 * will occur at the next quantum expiration or blocking point.
 *
 * When the thread is the current thread, and explicit thread_block() should
 * be used to force the current processor to context switch away and
 * let the thread migrate to the bound processor.
 *
 * Thread must be locked, and at splsched.
 */

static processor_t
thread_bind_internal(
	thread_t		thread,
	processor_t		processor)
{
	processor_t		prev;

	/* <rdar://problem/15102234> */
	assert(thread->sched_pri < BASEPRI_RTQUEUES);
	/* A thread can't be bound if it's sitting on a (potentially incorrect) runqueue */
	assert(thread->runq == PROCESSOR_NULL);

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_THREAD_BIND), thread_tid(thread), processor ? (uintptr_t)processor->cpu_id : (uintptr_t)-1, 0, 0, 0);

	prev = thread->bound_processor;
	thread->bound_processor = processor;

	return (prev);
}

/*
 * thread_vm_bind_group_add:
 *
 * The "VM bind group" is a special mechanism to mark a collection
 * of threads from the VM subsystem that, in general, should be scheduled
 * with only one CPU of parallelism. To accomplish this, we initially
 * bind all the threads to the master processor, which has the effect
 * that only one of the threads in the group can execute at once, including
 * preempting threads in the group that are a lower priority. Future
 * mechanisms may use more dynamic mechanisms to prevent the collection
 * of VM threads from using more CPU time than desired.
 *
 * The current implementation can result in priority inversions where
 * compute-bound priority 95 or realtime threads that happen to have
 * landed on the master processor prevent the VM threads from running.
 * When this situation is detected, we unbind the threads for one
 * scheduler tick to allow the scheduler to run the threads an
 * additional CPUs, before restoring the binding (assuming high latency
 * is no longer a problem).
 */

/*
 * The current max is provisioned for:
 * vm_compressor_swap_trigger_thread (92)
 * 2 x vm_pageout_iothread_internal (92) when vm_restricted_to_single_processor==TRUE
 * vm_pageout_continue (92)
 * memorystatus_thread (95)
 */
#define MAX_VM_BIND_GROUP_COUNT (5)
decl_simple_lock_data(static,sched_vm_group_list_lock);
static thread_t sched_vm_group_thread_list[MAX_VM_BIND_GROUP_COUNT];
static int sched_vm_group_thread_count;
static boolean_t sched_vm_group_temporarily_unbound = FALSE;

void
thread_vm_bind_group_add(void)
{
	thread_t self = current_thread();

	thread_reference_internal(self);
	self->options |= TH_OPT_SCHED_VM_GROUP;

	simple_lock(&sched_vm_group_list_lock);
	assert(sched_vm_group_thread_count < MAX_VM_BIND_GROUP_COUNT);
	sched_vm_group_thread_list[sched_vm_group_thread_count++] = self;
	simple_unlock(&sched_vm_group_list_lock);

	thread_bind(master_processor);

	/* Switch to bound processor if not already there */
	thread_block(THREAD_CONTINUE_NULL);
}

static void
sched_vm_group_maintenance(void)
{
	uint64_t ctime = mach_absolute_time();
	uint64_t longtime = ctime - sched_tick_interval;
	int i;
	spl_t s;
	boolean_t high_latency_observed = FALSE;
	boolean_t runnable_and_not_on_runq_observed = FALSE;
	boolean_t bind_target_changed = FALSE;
	processor_t bind_target = PROCESSOR_NULL;

	/* Make sure nobody attempts to add new threads while we are enumerating them */
	simple_lock(&sched_vm_group_list_lock);

	s = splsched();

	for (i=0; i < sched_vm_group_thread_count; i++) {
		thread_t thread = sched_vm_group_thread_list[i];
		assert(thread != THREAD_NULL);
		thread_lock(thread);
		if ((thread->state & (TH_RUN|TH_WAIT)) == TH_RUN) {
			if (thread->runq != PROCESSOR_NULL && thread->last_made_runnable_time < longtime) {
				high_latency_observed = TRUE;
			} else if (thread->runq == PROCESSOR_NULL) {
				/* There are some cases where a thread be transitiong that also fall into this case */
				runnable_and_not_on_runq_observed = TRUE;
			}
		}
		thread_unlock(thread);

		if (high_latency_observed && runnable_and_not_on_runq_observed) {
			/* All the things we are looking for are true, stop looking */
			break;
		}
	}

	splx(s);

	if (sched_vm_group_temporarily_unbound) {
		/* If we turned off binding, make sure everything is OK before rebinding */
		if (!high_latency_observed) {
			/* rebind */
			bind_target_changed = TRUE;
			bind_target = master_processor;
			sched_vm_group_temporarily_unbound = FALSE; /* might be reset to TRUE if change cannot be completed */
		}
	} else {
		/*
		 * Check if we're in a bad state, which is defined by high
		 * latency with no core currently executing a thread. If a
		 * single thread is making progress on a CPU, that means the
		 * binding concept to reduce parallelism is working as
		 * designed.
		 */
		if (high_latency_observed && !runnable_and_not_on_runq_observed) {
			/* unbind */
			bind_target_changed = TRUE;
			bind_target = PROCESSOR_NULL;
			sched_vm_group_temporarily_unbound = TRUE;
		}
	}

	if (bind_target_changed) {
		s = splsched();
		for (i=0; i < sched_vm_group_thread_count; i++) {
			thread_t thread = sched_vm_group_thread_list[i];
			boolean_t removed;
			assert(thread != THREAD_NULL);

			thread_lock(thread);
			removed = thread_run_queue_remove(thread);
			if (removed || ((thread->state & (TH_RUN | TH_WAIT)) == TH_WAIT)) {
				thread_bind_internal(thread, bind_target);
			} else {
				/*
				 * Thread was in the middle of being context-switched-to,
				 * or was in the process of blocking. To avoid switching the bind
				 * state out mid-flight, defer the change if possible.
				 */
				if (bind_target == PROCESSOR_NULL) {
					thread_bind_internal(thread, bind_target);
				} else {
					sched_vm_group_temporarily_unbound = TRUE; /* next pass will try again */
				}
			}

			if (removed) {
				thread_run_queue_reinsert(thread, SCHED_PREEMPT | SCHED_TAILQ);
			}
			thread_unlock(thread);
		}
		splx(s);
	}

	simple_unlock(&sched_vm_group_list_lock);
}

/* Invoked prior to idle entry to determine if, on SMT capable processors, an SMT
 * rebalancing opportunity exists when a core is (instantaneously) idle, but
 * other SMT-capable cores may be over-committed. TODO: some possible negatives:
 * IPI thrash if this core does not remain idle following the load balancing ASTs
 * Idle "thrash", when IPI issue is followed by idle entry/core power down
 * followed by a wakeup shortly thereafter.
 */

#if (DEVELOPMENT || DEBUG)
int sched_smt_balance = 1;
#endif

#if __SMP__
/* Invoked with pset locked, returns with pset unlocked */
static void
sched_SMT_balance(processor_t cprocessor, processor_set_t cpset) {
	processor_t ast_processor = NULL;

#if (DEVELOPMENT || DEBUG)
	if (__improbable(sched_smt_balance == 0))
		goto smt_balance_exit;
#endif
	
	assert(cprocessor == current_processor());
	if (cprocessor->is_SMT == FALSE)
		goto smt_balance_exit;

	processor_t sib_processor = cprocessor->processor_secondary ? cprocessor->processor_secondary : cprocessor->processor_primary;

	/* Determine if both this processor and its sibling are idle,
	 * indicating an SMT rebalancing opportunity.
	 */
	if (sib_processor->state != PROCESSOR_IDLE)
		goto smt_balance_exit;

	processor_t sprocessor;

	qe_foreach_element(sprocessor, &cpset->active_queue, processor_queue) {
		if ((sprocessor->state == PROCESSOR_RUNNING) &&
		    (sprocessor->processor_primary != sprocessor) &&
		    (sprocessor->processor_primary->state == PROCESSOR_RUNNING) &&
		    (sprocessor->current_pri < BASEPRI_RTQUEUES) &&
		    ((cpset->pending_AST_cpu_mask & (1ULL << sprocessor->cpu_id)) == 0)) {
			assert(sprocessor != cprocessor);
			ast_processor = sprocessor;
			break;
		}
	}

smt_balance_exit:
	pset_unlock(cpset);

	if (ast_processor) {
		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_SMT_BALANCE), ast_processor->cpu_id, ast_processor->state, ast_processor->processor_primary->state, 0, 0);
		cause_ast_check(ast_processor);
	}
}
#endif /* __SMP__ */

/*
 *	thread_select:
 *
 *	Select a new thread for the current processor to execute.
 *
 *	May select the current thread, which must be locked.
 */
static thread_t
thread_select(
	thread_t			thread,
	processor_t			processor,
	ast_t				reason)
{
	processor_set_t		pset = processor->processor_set;
	thread_t			new_thread = THREAD_NULL;

	assert(processor == current_processor());
	assert((thread->state & (TH_RUN|TH_TERMINATE2)) == TH_RUN);

	do {
		/*
		 *	Update the priority.
		 */
		if (SCHED(can_update_priority)(thread))
			SCHED(update_priority)(thread);
		
		processor->current_pri = thread->sched_pri;
		processor->current_thmode = thread->sched_mode;
		processor->current_sfi_class = thread->sfi_class;

		pset_lock(pset);

		assert(processor->state != PROCESSOR_OFF_LINE);

		if (!processor->is_recommended) {
			/*
			 * The performance controller has provided a hint to not dispatch more threads,
			 * unless they are bound to us (and thus we are the only option
			 */
			if (!SCHED(processor_bound_count)(processor)) {
				goto idle;
			}
		} else if (processor->processor_primary != processor) {
			/*
			 * Should this secondary SMT processor attempt to find work? For pset runqueue systems,
			 * we should look for work only under the same conditions that choose_processor()
			 * would have assigned work, which is when all primary processors have been assigned work.
			 *
			 * An exception is that bound threads are dispatched to a processor without going through
			 * choose_processor(), so in those cases we should continue trying to dequeue work.
			 */
			if (!SCHED(processor_bound_count)(processor) && !queue_empty(&pset->idle_queue) && !rt_runq.count) {
				goto idle;
			}
		}

		rt_lock_lock();

		/*
		 *	Test to see if the current thread should continue
		 *	to run on this processor.  Must not be attempting to wait, and not
		 *	bound to a different processor, nor be in the wrong
		 *	processor set, nor be forced to context switch by TH_SUSP.
		 *
		 *	Note that there are never any RT threads in the regular runqueue.
		 *
		 *	This code is very insanely tricky.
		 */

		if (((thread->state & (TH_TERMINATE|TH_IDLE|TH_WAIT|TH_RUN|TH_SUSP)) == TH_RUN) &&
		    (thread->sched_pri >= BASEPRI_RTQUEUES     || processor->processor_primary == processor) &&
		    (thread->bound_processor == PROCESSOR_NULL || thread->bound_processor == processor)      &&
		    (thread->affinity_set == AFFINITY_SET_NULL || thread->affinity_set->aset_pset == pset)) {
			/*
			 * RT threads with un-expired quantum stay on processor,
			 * unless there's a valid RT thread with an earlier deadline.
			 */
			if (thread->sched_pri >= BASEPRI_RTQUEUES && processor->first_timeslice) {
				if (rt_runq.count > 0) {
					thread_t next_rt = qe_queue_first(&rt_runq.queue, struct thread, runq_links);

					assert(next_rt->runq == THREAD_ON_RT_RUNQ);

					if (next_rt->realtime.deadline < processor->deadline &&
					    (next_rt->bound_processor == PROCESSOR_NULL ||
					     next_rt->bound_processor == processor)) {
						/* The next RT thread is better, so pick it off the runqueue. */
						goto pick_new_rt_thread;
					}
				}

				/* This is still the best RT thread to run. */
				processor->deadline = thread->realtime.deadline;

				rt_lock_unlock();
				pset_unlock(pset);

				return (thread);
			}

			if ((rt_runq.count == 0) &&
			    SCHED(processor_queue_has_priority)(processor, thread->sched_pri, TRUE) == FALSE) {
				/* This thread is still the highest priority runnable (non-idle) thread */
				processor->deadline = UINT64_MAX;

				rt_lock_unlock();
				pset_unlock(pset);

				return (thread);
			}
		}

		/* OK, so we're not going to run the current thread. Look at the RT queue. */
		if (rt_runq.count > 0) {
			thread_t next_rt = qe_queue_first(&rt_runq.queue, struct thread, runq_links);

			assert(next_rt->runq == THREAD_ON_RT_RUNQ);

			if (__probable((next_rt->bound_processor == PROCESSOR_NULL ||
			               (next_rt->bound_processor == processor)))) {
pick_new_rt_thread:
				new_thread = qe_dequeue_head(&rt_runq.queue, struct thread, runq_links);

				new_thread->runq = PROCESSOR_NULL;
				SCHED_STATS_RUNQ_CHANGE(&rt_runq.runq_stats, rt_runq.count);
				rt_runq.count--;

				processor->deadline = new_thread->realtime.deadline;

				rt_lock_unlock();
				pset_unlock(pset);

				return (new_thread);
			}
		}

		processor->deadline = UINT64_MAX;
		rt_lock_unlock();

		/* No RT threads, so let's look at the regular threads. */
		if ((new_thread = SCHED(choose_thread)(processor, MINPRI, reason)) != THREAD_NULL) {
			pset_unlock(pset);
			return (new_thread);
		}

#if __SMP__
		if (SCHED(steal_thread_enabled)) {
			/*
			 * No runnable threads, attempt to steal
			 * from other processors. Returns with pset lock dropped.
			 */

			if ((new_thread = SCHED(steal_thread)(pset)) != THREAD_NULL) {
				return (new_thread);
			}

			/*
			 * If other threads have appeared, shortcut
			 * around again.
			 */
			if (!SCHED(processor_queue_empty)(processor) || rt_runq.count > 0)
				continue;

			pset_lock(pset);
		}
#endif

	idle:
		/*
		 *	Nothing is runnable, so set this processor idle if it
		 *	was running.
		 */
		if (processor->state == PROCESSOR_RUNNING) {
			processor->state = PROCESSOR_IDLE;

			if (processor->processor_primary == processor) {
				re_queue_head(&pset->idle_queue, &processor->processor_queue);
			} else {
				re_queue_head(&pset->idle_secondary_queue, &processor->processor_queue);
			}
		}

#if __SMP__
		/* Invoked with pset locked, returns with pset unlocked */
		sched_SMT_balance(processor, pset);
#else
		pset_unlock(pset);
#endif

#if CONFIG_SCHED_IDLE_IN_PLACE
		/*
		 *	Choose idle thread if fast idle is not possible.
		 */
		if (processor->processor_primary != processor)
			return (processor->idle_thread);

		if ((thread->state & (TH_IDLE|TH_TERMINATE|TH_SUSP)) || !(thread->state & TH_WAIT) || thread->wake_active || thread->sched_pri >= BASEPRI_RTQUEUES)
			return (processor->idle_thread);

		/*
		 *	Perform idling activities directly without a
		 *	context switch.  Return dispatched thread,
		 *	else check again for a runnable thread.
		 */
		new_thread = thread_select_idle(thread, processor);

#else /* !CONFIG_SCHED_IDLE_IN_PLACE */
		
		/*
		 * Do a full context switch to idle so that the current
		 * thread can start running on another processor without
		 * waiting for the fast-idled processor to wake up.
		 */
		new_thread = processor->idle_thread;

#endif /* !CONFIG_SCHED_IDLE_IN_PLACE */

	} while (new_thread == THREAD_NULL);

	return (new_thread);
}

#if CONFIG_SCHED_IDLE_IN_PLACE
/*
 *	thread_select_idle:
 *
 *	Idle the processor using the current thread context.
 *
 *	Called with thread locked, then dropped and relocked.
 */
static thread_t
thread_select_idle(
	thread_t		thread,
	processor_t		processor)
{
	thread_t		new_thread;
	uint64_t		arg1, arg2;
	int			urgency;

	sched_run_decr(thread);

	thread->state |= TH_IDLE;
	processor->current_pri = IDLEPRI;
	processor->current_thmode = TH_MODE_NONE;
	processor->current_sfi_class = SFI_CLASS_KERNEL;

	/* Reload precise timing global policy to thread-local policy */
	thread->precise_user_kernel_time = use_precise_user_kernel_time(thread);
	
	thread_unlock(thread);

	/*
	 *	Switch execution timing to processor idle thread.
	 */
	processor->last_dispatch = mach_absolute_time();

#ifdef CONFIG_MACH_APPROXIMATE_TIME
	commpage_update_mach_approximate_time(processor->last_dispatch);
#endif

	thread->last_run_time = processor->last_dispatch;
	thread_timer_event(processor->last_dispatch, &processor->idle_thread->system_timer);
	PROCESSOR_DATA(processor, kernel_timer) = &processor->idle_thread->system_timer;

	/*
	 *	Cancel the quantum timer while idling.
	 */
	timer_call_cancel(&processor->quantum_timer);
	processor->first_timeslice = FALSE;

	(*thread->sched_call)(SCHED_CALL_BLOCK, thread);

	thread_tell_urgency(THREAD_URGENCY_NONE, 0, 0, 0, NULL);

	/*
	 *	Enable interrupts and perform idling activities.  No
	 *	preemption due to TH_IDLE being set.
	 */
	spllo(); new_thread = processor_idle(thread, processor);

	/*
	 *	Return at splsched.
	 */
	(*thread->sched_call)(SCHED_CALL_UNBLOCK, thread);

	thread_lock(thread);

	/*
	 *	If awakened, switch to thread timer and start a new quantum.
	 *	Otherwise skip; we will context switch to another thread or return here.
	 */
	if (!(thread->state & TH_WAIT)) {
		processor->last_dispatch = mach_absolute_time();
		thread_timer_event(processor->last_dispatch, &thread->system_timer);
		PROCESSOR_DATA(processor, kernel_timer) = &thread->system_timer;

		thread_quantum_init(thread);
		processor->quantum_end = processor->last_dispatch + thread->quantum_remaining;
		timer_call_enter1(&processor->quantum_timer, thread, processor->quantum_end, TIMER_CALL_SYS_CRITICAL | TIMER_CALL_LOCAL);
		processor->first_timeslice = TRUE;

		thread->computation_epoch = processor->last_dispatch;
	}

	thread->state &= ~TH_IDLE;

	urgency = thread_get_urgency(thread, &arg1, &arg2);

	thread_tell_urgency(urgency, arg1, arg2, 0, new_thread);

	sched_run_incr(thread);

	return (new_thread);
}
#endif /* CONFIG_SCHED_IDLE_IN_PLACE */

/*
 * thread_invoke
 *
 * Called at splsched with neither thread locked.
 *
 * Perform a context switch and start executing the new thread.
 *
 * Returns FALSE when the context switch didn't happen.
 * The reference to the new thread is still consumed.
 *
 * "self" is what is currently running on the processor,
 * "thread" is the new thread to context switch to
 * (which may be the same thread in some cases)
 */
static boolean_t
thread_invoke(
	thread_t			self,
	thread_t			thread,
	ast_t				reason)
{
	if (__improbable(get_preemption_level() != 0)) {
		int pl = get_preemption_level();
		panic("thread_invoke: preemption_level %d, possible cause: %s",
		    pl, (pl < 0 ? "unlocking an unlocked mutex or spinlock" :
			"blocking while holding a spinlock, or within interrupt context"));
	}

	thread_continue_t       continuation = self->continuation;
	void                    *parameter   = self->parameter;
	processor_t             processor;

	uint64_t                ctime = mach_absolute_time();

#ifdef CONFIG_MACH_APPROXIMATE_TIME
	commpage_update_mach_approximate_time(ctime);
#endif

#if defined(CONFIG_SCHED_TIMESHARE_CORE)
	sched_timeshare_consider_maintenance(ctime);
#endif

	assert_thread_magic(self);
	assert(self == current_thread());
	assert(self->runq == PROCESSOR_NULL);
	assert((self->state & (TH_RUN|TH_TERMINATE2)) == TH_RUN);

	thread_lock(thread);

	assert_thread_magic(thread);
	assert((thread->state & (TH_RUN|TH_WAIT|TH_UNINT|TH_TERMINATE|TH_TERMINATE2)) == TH_RUN);
	assert(thread->bound_processor == PROCESSOR_NULL || thread->bound_processor == current_processor());
	assert(thread->runq == PROCESSOR_NULL);

	/* Reload precise timing global policy to thread-local policy */
	thread->precise_user_kernel_time = use_precise_user_kernel_time(thread);

	/* Update SFI class based on other factors */
	thread->sfi_class = sfi_thread_classify(thread);

	/* Allow realtime threads to hang onto a stack. */
	if ((self->sched_mode == TH_MODE_REALTIME) && !self->reserved_stack)
		self->reserved_stack = self->kernel_stack;

	if (continuation != NULL) {
		if (!thread->kernel_stack) {
			/*
			 * If we are using a privileged stack,
			 * check to see whether we can exchange it with
			 * that of the other thread.
			 */
			if (self->kernel_stack == self->reserved_stack && !thread->reserved_stack)
				goto need_stack;

			/*
			 * Context switch by performing a stack handoff.
			 */
			continuation = thread->continuation;
			parameter = thread->parameter;

			processor = current_processor();
			processor->active_thread = thread;
			processor->current_pri = thread->sched_pri;
			processor->current_thmode = thread->sched_mode;
			processor->current_sfi_class = thread->sfi_class;
			if (thread->last_processor != processor && thread->last_processor != NULL) {
				if (thread->last_processor->processor_set != processor->processor_set)
					thread->ps_switch++;
				thread->p_switch++;
			}
			thread->last_processor = processor;
			thread->c_switch++;
			ast_context(thread);

			thread_unlock(thread);

			self->reason = reason;

			processor->last_dispatch = ctime;
			self->last_run_time = ctime;
			thread_timer_event(ctime, &thread->system_timer);
			PROCESSOR_DATA(processor, kernel_timer) = &thread->system_timer;

			/*
			 * Since non-precise user/kernel time doesn't update the state timer
			 * during privilege transitions, synthesize an event now.
			 */
			if (!thread->precise_user_kernel_time) {
				timer_switch(PROCESSOR_DATA(processor, current_state),
							ctime,
							 PROCESSOR_DATA(processor, current_state));
			}
	
			KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				MACHDBG_CODE(DBG_MACH_SCHED, MACH_STACK_HANDOFF)|DBG_FUNC_NONE,
				self->reason, (uintptr_t)thread_tid(thread), self->sched_pri, thread->sched_pri, 0);

			if ((thread->chosen_processor != processor) && (thread->chosen_processor != PROCESSOR_NULL)) {
				SCHED_DEBUG_CHOOSE_PROCESSOR_KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_MOVED)|DBG_FUNC_NONE,
						(uintptr_t)thread_tid(thread), (uintptr_t)thread->chosen_processor->cpu_id, 0, 0, 0);
			}

			DTRACE_SCHED2(off__cpu, struct thread *, thread, struct proc *, thread->task->bsd_info);

			SCHED_STATS_CSW(processor, self->reason, self->sched_pri, thread->sched_pri);

			TLOG(1, "thread_invoke: calling stack_handoff\n");
			stack_handoff(self, thread);

			/* 'self' is now off core */
			assert(thread == current_thread());

			DTRACE_SCHED(on__cpu);

#if KPERF
			kperf_on_cpu(thread, continuation, NULL);
#endif /* KPERF */

			thread_dispatch(self, thread);

			thread->continuation = thread->parameter = NULL;

			counter(c_thread_invoke_hits++);

			(void) spllo();

			assert(continuation);
			call_continuation(continuation, parameter, thread->wait_result);
			/*NOTREACHED*/
		}
		else if (thread == self) {
			/* same thread but with continuation */
			ast_context(self);
			counter(++c_thread_invoke_same);

			thread_unlock(self);

#if KPERF
			kperf_on_cpu(thread, continuation, NULL);
#endif /* KPERF */

			KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				MACHDBG_CODE(DBG_MACH_SCHED,MACH_SCHED) | DBG_FUNC_NONE,
				self->reason, (uintptr_t)thread_tid(thread), self->sched_pri, thread->sched_pri, 0);

			self->continuation = self->parameter = NULL;

			(void) spllo();

			call_continuation(continuation, parameter, self->wait_result);
			/*NOTREACHED*/
		}
	} else {
		/*
		 * Check that the other thread has a stack
		 */
		if (!thread->kernel_stack) {
need_stack:
			if (!stack_alloc_try(thread)) {
				counter(c_thread_invoke_misses++);
				thread_unlock(thread);
				thread_stack_enqueue(thread);
				return (FALSE);
			}
		} else if (thread == self) {
			ast_context(self);
			counter(++c_thread_invoke_same);
			thread_unlock(self);

			KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				MACHDBG_CODE(DBG_MACH_SCHED,MACH_SCHED) | DBG_FUNC_NONE,
				self->reason, (uintptr_t)thread_tid(thread), self->sched_pri, thread->sched_pri, 0);

			return (TRUE);
		}
	}

	/*
	 * Context switch by full context save.
	 */
	processor = current_processor();
	processor->active_thread = thread;
	processor->current_pri = thread->sched_pri;
	processor->current_thmode = thread->sched_mode;
	processor->current_sfi_class = thread->sfi_class;
	if (thread->last_processor != processor && thread->last_processor != NULL) {
		if (thread->last_processor->processor_set != processor->processor_set)
			thread->ps_switch++;
		thread->p_switch++;
	}
	thread->last_processor = processor;
	thread->c_switch++;
	ast_context(thread);

	thread_unlock(thread);

	counter(c_thread_invoke_csw++);

	self->reason = reason;

	processor->last_dispatch = ctime;
	self->last_run_time = ctime;
	thread_timer_event(ctime, &thread->system_timer);
	PROCESSOR_DATA(processor, kernel_timer) = &thread->system_timer;

	/*
	 * Since non-precise user/kernel time doesn't update the state timer
	 * during privilege transitions, synthesize an event now.
	 */
	if (!thread->precise_user_kernel_time) {
		timer_switch(PROCESSOR_DATA(processor, current_state),
					ctime,
					 PROCESSOR_DATA(processor, current_state));
	}

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		MACHDBG_CODE(DBG_MACH_SCHED,MACH_SCHED) | DBG_FUNC_NONE,
		self->reason, (uintptr_t)thread_tid(thread), self->sched_pri, thread->sched_pri, 0);

	if ((thread->chosen_processor != processor) && (thread->chosen_processor != NULL)) {
		SCHED_DEBUG_CHOOSE_PROCESSOR_KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_MOVED)|DBG_FUNC_NONE,
				(uintptr_t)thread_tid(thread), (uintptr_t)thread->chosen_processor->cpu_id, 0, 0, 0);
	}

	DTRACE_SCHED2(off__cpu, struct thread *, thread, struct proc *, thread->task->bsd_info);

	SCHED_STATS_CSW(processor, self->reason, self->sched_pri, thread->sched_pri);

	/*
	 * This is where we actually switch register context,
	 * and address space if required.  We will next run
	 * as a result of a subsequent context switch.
	 *
	 * Once registers are switched and the processor is running "thread",
	 * the stack variables and non-volatile registers will contain whatever
	 * was there the last time that thread blocked. No local variables should
	 * be used after this point, except for the special case of "thread", which
	 * the platform layer returns as the previous thread running on the processor
	 * via the function call ABI as a return register, and "self", which may have
	 * been stored on the stack or a non-volatile register, but a stale idea of
	 * what was on the CPU is newly-accurate because that thread is again
	 * running on the CPU.
	 */
	assert(continuation == self->continuation);
	thread = machine_switch_context(self, continuation, thread);
	assert(self == current_thread());
	TLOG(1,"thread_invoke: returning machine_switch_context: self %p continuation %p thread %p\n", self, continuation, thread);

	DTRACE_SCHED(on__cpu);

#if KPERF
	kperf_on_cpu(self, NULL, __builtin_frame_address(0));
#endif /* KPERF */

	/*
	 * We have been resumed and are set to run.
	 */
	thread_dispatch(thread, self);

	if (continuation) {
		self->continuation = self->parameter = NULL;

		(void) spllo();

		call_continuation(continuation, parameter, self->wait_result);
		/*NOTREACHED*/
	}

	return (TRUE);
}

#if defined(CONFIG_SCHED_DEFERRED_AST)
/*
 *	pset_cancel_deferred_dispatch:
 *
 *	Cancels all ASTs that we can cancel for the given processor set
 *	if the current processor is running the last runnable thread in the
 *	system.
 *
 *	This function assumes the current thread is runnable.  This must
 *	be called with the pset unlocked.
 */
static void
pset_cancel_deferred_dispatch(
	processor_set_t		pset,
	processor_t		processor)
{
	processor_t		active_processor = NULL;
	uint32_t		sampled_sched_run_count;

	pset_lock(pset);
	sampled_sched_run_count = (volatile uint32_t) sched_run_buckets[TH_BUCKET_RUN];

	/*
	 * If we have emptied the run queue, and our current thread is runnable, we
	 * should tell any processors that are still DISPATCHING that they will
	 * probably not have any work to do.  In the event that there are no
	 * pending signals that we can cancel, this is also uninteresting.
	 *
	 * In the unlikely event that another thread becomes runnable while we are
	 * doing this (sched_run_count is atomically updated, not guarded), the
	 * codepath making it runnable SHOULD (a dangerous word) need the pset lock
	 * in order to dispatch it to a processor in our pset.  So, the other
	 * codepath will wait while we squash all cancelable ASTs, get the pset
	 * lock, and then dispatch the freshly runnable thread.  So this should be
	 * correct (we won't accidentally have a runnable thread that hasn't been
	 * dispatched to an idle processor), if not ideal (we may be restarting the
	 * dispatch process, which could have some overhead).
	 *
	 */
	if ((sampled_sched_run_count == 1) &&
	    (pset->pending_deferred_AST_cpu_mask)) {
		qe_foreach_element_safe(active_processor, &pset->active_queue, processor_queue) {
			/*
			 * If a processor is DISPATCHING, it could be because of
			 * a cancelable signal.
			 *
			 * IF the processor is not our
			 * current processor (the current processor should not
			 * be DISPATCHING, so this is a bit paranoid), AND there
			 * is a cancelable signal pending on the processor, AND
			 * there is no non-cancelable signal pending (as there is
			 * no point trying to backtrack on bringing the processor
			 * up if a signal we cannot cancel is outstanding), THEN
			 * it should make sense to roll back the processor state
			 * to the IDLE state.
			 *
			 * If the racey nature of this approach (as the signal
			 * will be arbitrated by hardware, and can fire as we
			 * roll back state) results in the core responding
			 * despite being pushed back to the IDLE state, it
			 * should be no different than if the core took some
			 * interrupt while IDLE.
			 */
			if ((active_processor->state == PROCESSOR_DISPATCHING) &&
			    (pset->pending_deferred_AST_cpu_mask & (1ULL << active_processor->cpu_id)) &&
			    (!(pset->pending_AST_cpu_mask & (1ULL << active_processor->cpu_id))) &&
			    (active_processor != processor)) {
				/*
				 * Squash all of the processor state back to some
				 * reasonable facsimile of PROCESSOR_IDLE.
				 *
				 * TODO: What queue policy do we actually want here?
				 * We want to promote selection of a good processor
				 * to run on.  Do we want to enqueue at the head?
				 * The tail?  At the (relative) old position in the
				 * queue?  Or something else entirely?
				 */
				re_queue_head(&pset->idle_queue, &active_processor->processor_queue);

				assert(active_processor->next_thread == THREAD_NULL);

				active_processor->current_pri = IDLEPRI;
				active_processor->current_thmode = TH_MODE_FIXED;
				active_processor->current_sfi_class = SFI_CLASS_KERNEL;
				active_processor->deadline = UINT64_MAX;
				active_processor->state = PROCESSOR_IDLE;
				pset->pending_deferred_AST_cpu_mask &= ~(1U << active_processor->cpu_id);
				machine_signal_idle_cancel(active_processor);
			}

		}
	}

	pset_unlock(pset);
}
#else
/* We don't support deferred ASTs; everything is candycanes and sunshine. */
#endif

/*
 *	thread_dispatch:
 *
 *	Handle threads at context switch.  Re-dispatch other thread
 *	if still running, otherwise update run state and perform
 *	special actions.  Update quantum for other thread and begin
 *	the quantum for ourselves.
 *
 *      "thread" is the old thread that we have switched away from.
 *      "self" is the new current thread that we have context switched to
 *
 *	Called at splsched.
 */
void
thread_dispatch(
	thread_t		thread,
	thread_t		self)
{
	processor_t		processor = self->last_processor;

	assert(processor == current_processor());
	assert(self == current_thread());
	assert(thread != self);

	if (thread != THREAD_NULL) {
		/*
		 *	If blocked at a continuation, discard
		 *	the stack.
		 */
		if (thread->continuation != NULL && thread->kernel_stack != 0)
			stack_free(thread);

		if (thread->state & TH_IDLE) {
			KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
			        MACHDBG_CODE(DBG_MACH_SCHED,MACH_DISPATCH) | DBG_FUNC_NONE,
			        (uintptr_t)thread_tid(thread), 0, thread->state,
			        sched_run_buckets[TH_BUCKET_RUN], 0);
		} else {
			int64_t consumed;
			int64_t remainder = 0;

			if (processor->quantum_end > processor->last_dispatch)
				remainder = processor->quantum_end -
				    processor->last_dispatch;

			consumed = thread->quantum_remaining - remainder;

			if ((thread->reason & AST_LEDGER) == 0) {
				/*
				 * Bill CPU time to both the task and
				 * the individual thread.
				 */
				ledger_credit(thread->t_ledger,
				    task_ledgers.cpu_time, consumed);
				ledger_credit(thread->t_threadledger,
				    thread_ledgers.cpu_time, consumed);
#ifdef CONFIG_BANK
				if (thread->t_bankledger) {
					ledger_credit(thread->t_bankledger,
				    		bank_ledgers.cpu_time,
						(consumed - thread->t_deduct_bank_ledger_time));

				}
				thread->t_deduct_bank_ledger_time =0;
#endif
			}

			wake_lock(thread);
			thread_lock(thread);

			/*
			 * Apply a priority floor if the thread holds a kernel resource
			 * Do this before checking starting_pri to avoid overpenalizing
			 * repeated rwlock blockers.
			 */
			if (__improbable(thread->rwlock_count != 0))
				lck_rw_set_promotion_locked(thread);

			boolean_t keep_quantum = processor->first_timeslice;

			/*
			 * Treat a thread which has dropped priority since it got on core
			 * as having expired its quantum.
			 */
			if (processor->starting_pri > thread->sched_pri)
				keep_quantum = FALSE;

			/* Compute remainder of current quantum. */
			if (keep_quantum &&
			    processor->quantum_end > processor->last_dispatch)
				thread->quantum_remaining = (uint32_t)remainder;
			else
				thread->quantum_remaining = 0;

			if (thread->sched_mode == TH_MODE_REALTIME) {
				/*
				 *	Cancel the deadline if the thread has
				 *	consumed the entire quantum.
				 */
				if (thread->quantum_remaining == 0) {
					thread->realtime.deadline = UINT64_MAX;
				}
			} else {
#if defined(CONFIG_SCHED_TIMESHARE_CORE)
				/*
				 *	For non-realtime threads treat a tiny
				 *	remaining quantum as an expired quantum
				 *	but include what's left next time.
				 */
				if (thread->quantum_remaining < min_std_quantum) {
					thread->reason |= AST_QUANTUM;
					thread->quantum_remaining += SCHED(initial_quantum_size)(thread);
				}
#endif /* CONFIG_SCHED_TIMESHARE_CORE */
			}

			/*
			 *	If we are doing a direct handoff then
			 *	take the remainder of the quantum.
			 */
			if ((thread->reason & (AST_HANDOFF|AST_QUANTUM)) == AST_HANDOFF) {
				self->quantum_remaining = thread->quantum_remaining;
				thread->reason |= AST_QUANTUM;
				thread->quantum_remaining = 0;
			} else {
#if defined(CONFIG_SCHED_MULTIQ)
				if (SCHED(sched_groups_enabled) &&
				    thread->sched_group == self->sched_group) {
					KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
					    MACHDBG_CODE(DBG_MACH_SCHED, MACH_QUANTUM_HANDOFF),
					    self->reason, (uintptr_t)thread_tid(thread),
					    self->quantum_remaining, thread->quantum_remaining, 0);

					self->quantum_remaining = thread->quantum_remaining;
					thread->quantum_remaining = 0;
					/* Don't set AST_QUANTUM here - old thread might still want to preempt someone else */
				}
#endif /* defined(CONFIG_SCHED_MULTIQ) */
			}

			thread->computation_metered += (processor->last_dispatch - thread->computation_epoch);

			if (!(thread->state & TH_WAIT)) {
				/*
				 *	Still runnable.
				 */
				thread->last_made_runnable_time = mach_approximate_time();

				machine_thread_going_off_core(thread, FALSE, processor->last_dispatch);

				if (thread->reason & AST_QUANTUM)
					thread_setrun(thread, SCHED_TAILQ);
				else if (thread->reason & AST_PREEMPT)
					thread_setrun(thread, SCHED_HEADQ);
				else
					thread_setrun(thread, SCHED_PREEMPT | SCHED_TAILQ);

				KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				        MACHDBG_CODE(DBG_MACH_SCHED,MACH_DISPATCH) | DBG_FUNC_NONE,
				        (uintptr_t)thread_tid(thread), thread->reason, thread->state,
				        sched_run_buckets[TH_BUCKET_RUN], 0);

				if (thread->wake_active) {
					thread->wake_active = FALSE;
					thread_unlock(thread);

					thread_wakeup(&thread->wake_active);
				} else {
					thread_unlock(thread);
				}

				wake_unlock(thread);
			} else {
				/*
				 *	Waiting.
				 */
				boolean_t should_terminate = FALSE;
				uint32_t new_run_count;

				/* Only the first call to thread_dispatch
				 * after explicit termination should add
				 * the thread to the termination queue
				 */
				if ((thread->state & (TH_TERMINATE|TH_TERMINATE2)) == TH_TERMINATE) {
					should_terminate = TRUE;
					thread->state |= TH_TERMINATE2;
				}

				thread->state &= ~TH_RUN;
				thread->last_made_runnable_time = ~0ULL;
				thread->chosen_processor = PROCESSOR_NULL;

				new_run_count = sched_run_decr(thread);

#if CONFIG_SCHED_SFI
				if ((thread->state & (TH_WAIT | TH_TERMINATE)) == TH_WAIT) {
					if (thread->reason & AST_SFI) {
						thread->wait_sfi_begin_time = processor->last_dispatch;
					}
				}
#endif

				machine_thread_going_off_core(thread, should_terminate, processor->last_dispatch);

				KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				        MACHDBG_CODE(DBG_MACH_SCHED,MACH_DISPATCH) | DBG_FUNC_NONE,
				        (uintptr_t)thread_tid(thread), thread->reason, thread->state,
				        new_run_count, 0);

				(*thread->sched_call)(SCHED_CALL_BLOCK, thread);

				if (thread->wake_active) {
					thread->wake_active = FALSE;
					thread_unlock(thread);

					thread_wakeup(&thread->wake_active);
				} else {
					thread_unlock(thread);
				}

				wake_unlock(thread);

				if (should_terminate)
					thread_terminate_enqueue(thread);
			}
		}
	}

	/* Update (new) current thread and reprogram quantum timer */
	thread_lock(self);
	if (!(self->state & TH_IDLE)) {
		uint64_t        arg1, arg2;
		int             urgency;
		uint64_t		latency;

#if CONFIG_SCHED_SFI
		ast_t			new_ast;

		new_ast = sfi_thread_needs_ast(self, NULL);

		if (new_ast != AST_NONE) {
			ast_on(new_ast);
		}
#endif

		assertf(processor->last_dispatch >= self->last_made_runnable_time, "Non-monotonic time? dispatch at 0x%llx, runnable at 0x%llx", processor->last_dispatch, self->last_made_runnable_time);
		latency = processor->last_dispatch - self->last_made_runnable_time;

		urgency = thread_get_urgency(self, &arg1, &arg2);

		thread_tell_urgency(urgency, arg1, arg2, latency, self);

		machine_thread_going_on_core(self, urgency, latency, processor->last_dispatch);
		
		/*
		 *	Get a new quantum if none remaining.
		 */
		if (self->quantum_remaining == 0) {
			thread_quantum_init(self);
		}

		/*
		 *	Set up quantum timer and timeslice.
		 */
		processor->quantum_end = processor->last_dispatch + self->quantum_remaining;
		timer_call_enter1(&processor->quantum_timer, self, processor->quantum_end, TIMER_CALL_SYS_CRITICAL | TIMER_CALL_LOCAL);

		processor->first_timeslice = TRUE;
	} else {
		timer_call_cancel(&processor->quantum_timer);
		processor->first_timeslice = FALSE;

		thread_tell_urgency(THREAD_URGENCY_NONE, 0, 0, 0, self);
		machine_thread_going_on_core(self, THREAD_URGENCY_NONE, 0, processor->last_dispatch);
	}

	self->computation_epoch = processor->last_dispatch;
	self->reason = AST_NONE;
	processor->starting_pri = self->sched_pri;

	thread_unlock(self);

#if defined(CONFIG_SCHED_DEFERRED_AST)
	/*
	 * TODO: Can we state that redispatching our old thread is also
	 * uninteresting?
	 */
	if ((((volatile uint32_t)sched_run_buckets[TH_BUCKET_RUN]) == 1) &&
	    !(self->state & TH_IDLE)) {
		pset_cancel_deferred_dispatch(processor->processor_set, processor);
	}
#endif

}

/*
 *	thread_block_reason:
 *
 *	Forces a reschedule, blocking the caller if a wait
 *	has been asserted.
 *
 *	If a continuation is specified, then thread_invoke will
 *	attempt to discard the thread's kernel stack.  When the
 *	thread resumes, it will execute the continuation function
 *	on a new kernel stack.
 */
counter(mach_counter_t  c_thread_block_calls = 0;)
 
wait_result_t
thread_block_reason(
	thread_continue_t	continuation,
	void				*parameter,
	ast_t				reason)
{
	thread_t        self = current_thread();
	processor_t     processor;
	thread_t        new_thread;
	spl_t           s;

	counter(++c_thread_block_calls);

	s = splsched();

	processor = current_processor();

	/* If we're explicitly yielding, force a subsequent quantum */
	if (reason & AST_YIELD)
		processor->first_timeslice = FALSE;

	/* We're handling all scheduling AST's */
	ast_off(AST_SCHEDULING);

#if PROC_REF_DEBUG
	if ((continuation != NULL) && (self->task != kernel_task)) {
		if (uthread_get_proc_refcount(self->uthread) != 0) {
			panic("thread_block_reason with continuation uthread %p with uu_proc_refcount != 0", self->uthread);
		}
	}
#endif

	self->continuation = continuation;
	self->parameter = parameter;

	if (self->state & ~(TH_RUN | TH_IDLE)) {
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
			MACHDBG_CODE(DBG_MACH_SCHED,MACH_BLOCK), 
			reason, VM_KERNEL_UNSLIDE(continuation), 0, 0, 0);
	}

	do {
		thread_lock(self);
		new_thread = thread_select(self, processor, reason);
		thread_unlock(self);
	} while (!thread_invoke(self, new_thread, reason));

	splx(s);

	return (self->wait_result);
}

/*
 *	thread_block:
 *
 *	Block the current thread if a wait has been asserted.
 */
wait_result_t
thread_block(
	thread_continue_t	continuation)
{
	return thread_block_reason(continuation, NULL, AST_NONE);
}

wait_result_t
thread_block_parameter(
	thread_continue_t	continuation,
	void				*parameter)
{
	return thread_block_reason(continuation, parameter, AST_NONE);
}

/*
 *	thread_run:
 *
 *	Switch directly from the current thread to the
 *	new thread, handing off our quantum if appropriate.
 *
 *	New thread must be runnable, and not on a run queue.
 *
 *	Called at splsched.
 */
int
thread_run(
	thread_t			self,
	thread_continue_t	continuation,
	void				*parameter,
	thread_t			new_thread)
{
	ast_t		handoff = AST_HANDOFF;

	self->continuation = continuation;
	self->parameter = parameter;

	while (!thread_invoke(self, new_thread, handoff)) {
		processor_t		processor = current_processor();

		thread_lock(self);
		new_thread = thread_select(self, processor, AST_NONE);
		thread_unlock(self);
		handoff = AST_NONE;
	}

	return (self->wait_result);
}

/*
 *	thread_continue:
 *
 *	Called at splsched when a thread first receives
 *	a new stack after a continuation.
 */
void
thread_continue(
	thread_t	thread)
{
	thread_t                self = current_thread();
	thread_continue_t       continuation;
	void                    *parameter;

	DTRACE_SCHED(on__cpu);

	continuation = self->continuation;
	parameter = self->parameter;

#if KPERF
	kperf_on_cpu(self, continuation, NULL);
#endif

	thread_dispatch(thread, self);

	self->continuation = self->parameter = NULL;

	if (thread != THREAD_NULL)
		(void)spllo();

 TLOG(1, "thread_continue: calling call_continuation \n");
	call_continuation(continuation, parameter, self->wait_result);
	/*NOTREACHED*/
}

void
thread_quantum_init(thread_t thread)
{
	if (thread->sched_mode == TH_MODE_REALTIME) {
		thread->quantum_remaining = thread->realtime.computation;
	} else {
		thread->quantum_remaining = SCHED(initial_quantum_size)(thread);
	}
}

uint32_t
sched_timeshare_initial_quantum_size(thread_t thread)
{
	if ((thread != THREAD_NULL) && thread->th_sched_bucket == TH_BUCKET_SHARE_BG)
		return bg_quantum;
	else
		return std_quantum;
}

/*
 *	run_queue_init:
 *
 *	Initialize a run queue before first use.
 */
void
run_queue_init(
	run_queue_t		rq)
{
	rq->highq = NOPRI;
	for (u_int i = 0; i < BITMAP_LEN(NRQS); i++)
		rq->bitmap[i] = 0;
	rq->urgency = rq->count = 0;
	for (int i = 0; i < NRQS; i++)
		queue_init(&rq->queues[i]);
}

/*
 *	run_queue_dequeue:
 *
 *	Perform a dequeue operation on a run queue,
 *	and return the resulting thread.
 *
 *	The run queue must be locked (see thread_run_queue_remove()
 *	for more info), and not empty.
 */
thread_t
run_queue_dequeue(
                  run_queue_t   rq,
                  integer_t     options)
{
	thread_t    thread;
	queue_t     queue = &rq->queues[rq->highq];

	if (options & SCHED_HEADQ) {
		thread = qe_dequeue_head(queue, struct thread, runq_links);
	} else {
		thread = qe_dequeue_tail(queue, struct thread, runq_links);
	}

	assert(thread != THREAD_NULL);
	assert_thread_magic(thread);

	thread->runq = PROCESSOR_NULL;
	SCHED_STATS_RUNQ_CHANGE(&rq->runq_stats, rq->count);
	rq->count--;
	if (SCHED(priority_is_urgent)(rq->highq)) {
		rq->urgency--; assert(rq->urgency >= 0);
	}
	if (queue_empty(queue)) {
		bitmap_clear(rq->bitmap, rq->highq);
		rq->highq = bitmap_first(rq->bitmap, NRQS);
	}

	return thread;
}

/*
 *	run_queue_enqueue:
 *
 *	Perform a enqueue operation on a run queue.
 *
 *	The run queue must be locked (see thread_run_queue_remove()
 *	for more info).
 */
boolean_t
run_queue_enqueue(
                  run_queue_t   rq,
                  thread_t      thread,
                  integer_t     options)
{
	queue_t     queue = &rq->queues[thread->sched_pri];
	boolean_t   result = FALSE;

	assert_thread_magic(thread);

	if (queue_empty(queue)) {
		enqueue_tail(queue, &thread->runq_links);

		rq_bitmap_set(rq->bitmap, thread->sched_pri);
		if (thread->sched_pri > rq->highq) {
			rq->highq = thread->sched_pri;
			result = TRUE;
		}
	} else {
		if (options & SCHED_TAILQ)
			enqueue_tail(queue, &thread->runq_links);
		else
			enqueue_head(queue, &thread->runq_links);
	}
	if (SCHED(priority_is_urgent)(thread->sched_pri))
		rq->urgency++;
	SCHED_STATS_RUNQ_CHANGE(&rq->runq_stats, rq->count);
	rq->count++;

	return (result);
}

/*
 *	run_queue_remove:
 *
 *	Remove a specific thread from a runqueue.
 *
 *	The run queue must be locked.
 */
void
run_queue_remove(
                 run_queue_t    rq,
                 thread_t       thread)
{
	assert(thread->runq != PROCESSOR_NULL);
	assert_thread_magic(thread);

	remqueue(&thread->runq_links);
	SCHED_STATS_RUNQ_CHANGE(&rq->runq_stats, rq->count);
	rq->count--;
	if (SCHED(priority_is_urgent)(thread->sched_pri)) {
		rq->urgency--; assert(rq->urgency >= 0);
	}

	if (queue_empty(&rq->queues[thread->sched_pri])) {
		/* update run queue status */
		bitmap_clear(rq->bitmap, thread->sched_pri);
		rq->highq = bitmap_first(rq->bitmap, NRQS);
	}

	thread->runq = PROCESSOR_NULL;
}

/* Assumes RT lock is not held, and acquires splsched/rt_lock itself */
void
rt_runq_scan(sched_update_scan_context_t scan_context)
{
	spl_t		s;
	thread_t	thread;

	s = splsched();
	rt_lock_lock();

	qe_foreach_element_safe(thread, &rt_runq.queue, runq_links) {
		if (thread->last_made_runnable_time < scan_context->earliest_rt_make_runnable_time) {
			scan_context->earliest_rt_make_runnable_time = thread->last_made_runnable_time;
		}
	}

	rt_lock_unlock();
	splx(s);
}


/*
 *	realtime_queue_insert:
 *
 *	Enqueue a thread for realtime execution.
 */
static boolean_t
realtime_queue_insert(thread_t thread)
{
	queue_t     queue       = &rt_runq.queue;
	uint64_t    deadline    = thread->realtime.deadline;
	boolean_t   preempt     = FALSE;

	rt_lock_lock();

	if (queue_empty(queue)) {
		enqueue_tail(queue, &thread->runq_links);
		preempt = TRUE;
	} else {
		/* Insert into rt_runq in thread deadline order */
		queue_entry_t iter;
		qe_foreach(iter, queue) {
			thread_t iter_thread = qe_element(iter, struct thread, runq_links);
			assert_thread_magic(iter_thread);

			if (deadline < iter_thread->realtime.deadline) {
				if (iter == queue_first(queue))
					preempt = TRUE;
				insque(&thread->runq_links, queue_prev(iter));
				break;
			} else if (iter == queue_last(queue)) {
				enqueue_tail(queue, &thread->runq_links);
				break;
			}
		}
	}

	thread->runq = THREAD_ON_RT_RUNQ;
	SCHED_STATS_RUNQ_CHANGE(&rt_runq.runq_stats, rt_runq.count);
	rt_runq.count++;

	rt_lock_unlock();

	return (preempt);
}

/*
 *	realtime_setrun:
 *
 *	Dispatch a thread for realtime execution.
 *
 *	Thread must be locked.  Associated pset must
 *	be locked, and is returned unlocked.
 */
static void
realtime_setrun(
	processor_t			processor,
	thread_t			thread)
{
	processor_set_t		pset = processor->processor_set;
	ast_t				preempt;

	boolean_t do_signal_idle = FALSE, do_cause_ast = FALSE;

	thread->chosen_processor = processor;

	/* <rdar://problem/15102234> */
	assert(thread->bound_processor == PROCESSOR_NULL);

	/*
	 *	Dispatch directly onto idle processor.
	 */
	if ( (thread->bound_processor == processor)
		&& processor->state == PROCESSOR_IDLE) {
		re_queue_tail(&pset->active_queue, &processor->processor_queue);

		processor->next_thread = thread;
		processor->current_pri = thread->sched_pri;
		processor->current_thmode = thread->sched_mode;
		processor->current_sfi_class = thread->sfi_class;
		processor->deadline = thread->realtime.deadline;
		processor->state = PROCESSOR_DISPATCHING;

		if (processor != current_processor()) {
			if (!(pset->pending_AST_cpu_mask & (1ULL << processor->cpu_id))) {
				/* cleared on exit from main processor_idle() loop */
				pset->pending_AST_cpu_mask |= (1ULL << processor->cpu_id);
				do_signal_idle = TRUE;
			}
		}
		pset_unlock(pset);

		if (do_signal_idle) {
			machine_signal_idle(processor);
		}
		return;
	}

	if (processor->current_pri < BASEPRI_RTQUEUES)
		preempt = (AST_PREEMPT | AST_URGENT);
	else if (thread->realtime.deadline < processor->deadline)
		preempt = (AST_PREEMPT | AST_URGENT);
	else
		preempt = AST_NONE;

	realtime_queue_insert(thread);

	if (preempt != AST_NONE) {
		if (processor->state == PROCESSOR_IDLE) {
			re_queue_tail(&pset->active_queue, &processor->processor_queue);

			processor->next_thread = THREAD_NULL;
			processor->current_pri = thread->sched_pri;
			processor->current_thmode = thread->sched_mode;
			processor->current_sfi_class = thread->sfi_class;
			processor->deadline = thread->realtime.deadline;
			processor->state = PROCESSOR_DISPATCHING;
			if (processor == current_processor()) {
				ast_on(preempt);
			} else {
				if (!(pset->pending_AST_cpu_mask & (1ULL << processor->cpu_id))) {
					/* cleared on exit from main processor_idle() loop */
					pset->pending_AST_cpu_mask |= (1ULL << processor->cpu_id);
					do_signal_idle = TRUE;
				}
			}
		} else if (processor->state == PROCESSOR_DISPATCHING) {
			if ((processor->next_thread == THREAD_NULL) && ((processor->current_pri < thread->sched_pri) || (processor->deadline > thread->realtime.deadline))) {
				processor->current_pri = thread->sched_pri;
				processor->current_thmode = thread->sched_mode;
				processor->current_sfi_class = thread->sfi_class;
				processor->deadline = thread->realtime.deadline;
			}
		} else {
			if (processor == current_processor()) {
				ast_on(preempt);
			} else {
				if (!(pset->pending_AST_cpu_mask & (1ULL << processor->cpu_id))) {
					/* cleared after IPI causes csw_check() to be called */
					pset->pending_AST_cpu_mask |= (1ULL << processor->cpu_id);
					do_cause_ast = TRUE;
				}
			}
		}
	} else {
		/* Selected processor was too busy, just keep thread enqueued and let other processors drain it naturally. */
	}

	pset_unlock(pset);

	if (do_signal_idle) {
		machine_signal_idle(processor);
	} else if (do_cause_ast) {
		cause_ast_check(processor);
	}
}


#if defined(CONFIG_SCHED_TIMESHARE_CORE)

boolean_t
priority_is_urgent(int priority)
{
	return bitmap_test(sched_preempt_pri, priority) ? TRUE : FALSE;
}

#endif /* CONFIG_SCHED_TIMESHARE_CORE */

/*
 *	processor_setrun:
 *
 *	Dispatch a thread for execution on a
 *	processor.
 *
 *	Thread must be locked.  Associated pset must
 *	be locked, and is returned unlocked.
 */
static void
processor_setrun(
	processor_t			processor,
	thread_t			thread,
	integer_t			options)
{
	processor_set_t		pset = processor->processor_set;
	ast_t				preempt;
	enum { eExitIdle, eInterruptRunning, eDoNothing } ipi_action = eDoNothing;
	enum { eNoSignal, eDoSignal, eDoDeferredSignal } do_signal_idle = eNoSignal;

	boolean_t do_cause_ast = FALSE;

	thread->chosen_processor = processor;

	/*
	 *	Dispatch directly onto idle processor.
	 */
	if ( (SCHED(direct_dispatch_to_idle_processors) ||
		  thread->bound_processor == processor)
		&& processor->state == PROCESSOR_IDLE) {

		re_queue_tail(&pset->active_queue, &processor->processor_queue);

		processor->next_thread = thread;
		processor->current_pri = thread->sched_pri;
		processor->current_thmode = thread->sched_mode;
		processor->current_sfi_class = thread->sfi_class;
		processor->deadline = UINT64_MAX;
		processor->state = PROCESSOR_DISPATCHING;

		if (!(pset->pending_AST_cpu_mask & (1ULL << processor->cpu_id))) {
			/* cleared on exit from main processor_idle() loop */
			pset->pending_AST_cpu_mask |= (1ULL << processor->cpu_id);
			do_signal_idle = eDoSignal;
		}

		pset_unlock(pset);

		if (do_signal_idle == eDoSignal) {
			machine_signal_idle(processor);
		}

		return;
	}

	/*
	 *	Set preemption mode.
	 */
#if defined(CONFIG_SCHED_DEFERRED_AST)
	/* TODO: Do we need to care about urgency (see rdar://problem/20136239)? */
#endif
	if (SCHED(priority_is_urgent)(thread->sched_pri) && thread->sched_pri > processor->current_pri)
		preempt = (AST_PREEMPT | AST_URGENT);
	else if(processor->active_thread && thread_eager_preemption(processor->active_thread))
		preempt = (AST_PREEMPT | AST_URGENT);
	else if ((thread->sched_mode == TH_MODE_TIMESHARE) && (thread->sched_pri < thread->base_pri)) {
		if(SCHED(priority_is_urgent)(thread->base_pri) && thread->sched_pri > processor->current_pri) {
			preempt = (options & SCHED_PREEMPT)? AST_PREEMPT: AST_NONE;
		} else {
			preempt = AST_NONE;
		}
	} else
		preempt = (options & SCHED_PREEMPT)? AST_PREEMPT: AST_NONE;

	SCHED(processor_enqueue)(processor, thread, options);

	if (preempt != AST_NONE) {
		if (processor->state == PROCESSOR_IDLE) {
			re_queue_tail(&pset->active_queue, &processor->processor_queue);

			processor->next_thread = THREAD_NULL;
			processor->current_pri = thread->sched_pri;
			processor->current_thmode = thread->sched_mode;
			processor->current_sfi_class = thread->sfi_class;
			processor->deadline = UINT64_MAX;
			processor->state = PROCESSOR_DISPATCHING;

			ipi_action = eExitIdle;
		} else if ( processor->state == PROCESSOR_DISPATCHING) {
			if ((processor->next_thread == THREAD_NULL) && (processor->current_pri < thread->sched_pri)) {
				processor->current_pri = thread->sched_pri;
				processor->current_thmode = thread->sched_mode;
				processor->current_sfi_class = thread->sfi_class;
				processor->deadline = UINT64_MAX;
			}
		} else if (	(processor->state == PROCESSOR_RUNNING		||
				 processor->state == PROCESSOR_SHUTDOWN)		&&
				(thread->sched_pri >= processor->current_pri)) {
			ipi_action = eInterruptRunning;
		}
	} else {
		/*
		 * New thread is not important enough to preempt what is running, but
		 * special processor states may need special handling
		 */
		if (processor->state == PROCESSOR_SHUTDOWN		&&
			thread->sched_pri >= processor->current_pri	) {
			ipi_action = eInterruptRunning;
		} else if (processor->state == PROCESSOR_IDLE) {
			re_queue_tail(&pset->active_queue, &processor->processor_queue);

			processor->next_thread = THREAD_NULL;
			processor->current_pri = thread->sched_pri;
			processor->current_thmode = thread->sched_mode;
			processor->current_sfi_class = thread->sfi_class;
			processor->deadline = UINT64_MAX;
			processor->state = PROCESSOR_DISPATCHING;

			ipi_action = eExitIdle;
		}
	}

	switch (ipi_action) {
		case eDoNothing:
			break;
		case eExitIdle:
			if (processor == current_processor()) {
				if (csw_check_locked(processor, pset, AST_NONE) != AST_NONE)
					ast_on(preempt);
			} else {
#if defined(CONFIG_SCHED_DEFERRED_AST)
				if (!(pset->pending_deferred_AST_cpu_mask & (1ULL << processor->cpu_id)) &&
				    !(pset->pending_AST_cpu_mask & (1ULL << processor->cpu_id))) {
					/* cleared on exit from main processor_idle() loop */
					pset->pending_deferred_AST_cpu_mask |= (1ULL << processor->cpu_id);
					do_signal_idle = eDoDeferredSignal;
				}
#else
				if (!(pset->pending_AST_cpu_mask & (1ULL << processor->cpu_id))) {
					/* cleared on exit from main processor_idle() loop */
					pset->pending_AST_cpu_mask |= (1ULL << processor->cpu_id);
					do_signal_idle = eDoSignal;
				}
#endif
			}
			break;
		case eInterruptRunning:
			if (processor == current_processor()) {
				if (csw_check_locked(processor, pset, AST_NONE) != AST_NONE)
					ast_on(preempt);
			} else {
				if (!(pset->pending_AST_cpu_mask & (1ULL << processor->cpu_id))) {
					/* cleared after IPI causes csw_check() to be called */
					pset->pending_AST_cpu_mask |= (1ULL << processor->cpu_id);
					do_cause_ast = TRUE;
				}
			}
			break;
	}

	pset_unlock(pset);

	if (do_signal_idle == eDoSignal) {
		machine_signal_idle(processor);
	}
#if defined(CONFIG_SCHED_DEFERRED_AST)
	else if (do_signal_idle == eDoDeferredSignal) {
		/*
		 * TODO: The ability to cancel this signal could make
		 * sending it outside of the pset lock an issue.  Do
		 * we need to address this?  Or would the only fallout
		 * be that the core takes a signal?  As long as we do
		 * not run the risk of having a core marked as signal
		 * outstanding, with no real signal outstanding, the
		 * only result should be that we fail to cancel some
		 * signals.
		 */
		machine_signal_idle_deferred(processor);
	}
#endif
	else if (do_cause_ast) {
		cause_ast_check(processor);
	}
}

/*
 *	choose_next_pset:
 *
 *	Return the next sibling pset containing
 *	available processors.
 *
 *	Returns the original pset if none other is
 *	suitable.
 */
static processor_set_t
choose_next_pset(
	processor_set_t		pset)
{
	processor_set_t		nset = pset;

	do {
		nset = next_pset(nset);
	} while (nset->online_processor_count < 1 && nset != pset);

	return (nset);
}

/*
 *	choose_processor:
 *
 *	Choose a processor for the thread, beginning at
 *	the pset.  Accepts an optional processor hint in
 *	the pset.
 *
 *	Returns a processor, possibly from a different pset.
 *
 *	The thread must be locked.  The pset must be locked,
 *	and the resulting pset is locked on return.
 */
processor_t
choose_processor(
	processor_set_t		pset,
	processor_t			processor,
	thread_t			thread)
{
	processor_set_t		nset, cset = pset;

	assert(thread->sched_pri <= BASEPRI_RTQUEUES);

	/*
	 * Prefer the hinted processor, when appropriate.
	 */

	/* Fold last processor hint from secondary processor to its primary */
	if (processor != PROCESSOR_NULL) {
		processor = processor->processor_primary;
	}

	/*
	 * Only consult platform layer if pset is active, which
	 * it may not be in some cases when a multi-set system
	 * is going to sleep.
	 */
	if (pset->online_processor_count) {
		if ((processor == PROCESSOR_NULL) || (processor->processor_set == pset && processor->state == PROCESSOR_IDLE)) {
			processor_t mc_processor = machine_choose_processor(pset, processor);
			if (mc_processor != PROCESSOR_NULL)
				processor = mc_processor->processor_primary;
		}
	}

	/*
	 * At this point, we may have a processor hint, and we may have
	 * an initial starting pset. If the hint is not in the pset, or
	 * if the hint is for a processor in an invalid state, discard
	 * the hint.
	 */
	if (processor != PROCESSOR_NULL) {
		if (processor->processor_set != pset) {
			processor = PROCESSOR_NULL;
		} else if (!processor->is_recommended) {
			processor = PROCESSOR_NULL;
		} else {
			switch (processor->state) {
				case PROCESSOR_START:
				case PROCESSOR_SHUTDOWN:
				case PROCESSOR_OFF_LINE:
					/*
					 * Hint is for a processor that cannot support running new threads.
					 */
					processor = PROCESSOR_NULL;
					break;
				case PROCESSOR_IDLE:
					/*
					 * Hint is for an idle processor. Assume it is no worse than any other
					 * idle processor. The platform layer had an opportunity to provide
					 * the "least cost idle" processor above.
					 */
					return (processor);
				case PROCESSOR_RUNNING:
				case PROCESSOR_DISPATCHING:
					/*
					 * Hint is for an active CPU. This fast-path allows
					 * realtime threads to preempt non-realtime threads
					 * to regain their previous executing processor.
					 */
					if ((thread->sched_pri >= BASEPRI_RTQUEUES) &&
						(processor->current_pri < BASEPRI_RTQUEUES))
						return (processor);

					/* Otherwise, use hint as part of search below */
					break;
				default:
					processor = PROCESSOR_NULL;
					break;
			}
		}
	}

	/*
	 * Iterate through the processor sets to locate
	 * an appropriate processor. Seed results with
	 * a last-processor hint, if available, so that
	 * a search must find something strictly better
	 * to replace it.
	 *
	 * A primary/secondary pair of SMT processors are
	 * "unpaired" if the primary is busy but its
	 * corresponding secondary is idle (so the physical
	 * core has full use of its resources).
	 */

	integer_t lowest_priority = MAXPRI + 1;
	integer_t lowest_unpaired_primary_priority = MAXPRI + 1;
	integer_t lowest_count = INT_MAX;
	uint64_t  furthest_deadline = 1;
	processor_t lp_processor = PROCESSOR_NULL;
	processor_t lp_unpaired_primary_processor = PROCESSOR_NULL;
	processor_t lp_unpaired_secondary_processor = PROCESSOR_NULL;
	processor_t lc_processor = PROCESSOR_NULL;
	processor_t fd_processor = PROCESSOR_NULL;

	if (processor != PROCESSOR_NULL) {
		/* All other states should be enumerated above. */
		assert(processor->state == PROCESSOR_RUNNING || processor->state == PROCESSOR_DISPATCHING);

		lowest_priority = processor->current_pri;
		lp_processor = processor;

		if (processor->current_pri >= BASEPRI_RTQUEUES) {
			furthest_deadline = processor->deadline;
			fd_processor = processor;
		}

		lowest_count = SCHED(processor_runq_count)(processor);
		lc_processor = processor;
	}

	do {

		/*
		 * Choose an idle processor, in pset traversal order
		 */
		qe_foreach_element(processor, &cset->idle_queue, processor_queue) {
			if (processor->is_recommended)
				return processor;
		}

		/*
		 * Otherwise, enumerate active and idle processors to find candidates
		 * with lower priority/etc.
		 */

		qe_foreach_element(processor, &cset->active_queue, processor_queue) {

			if (!processor->is_recommended) {
				continue;
			}

			integer_t cpri = processor->current_pri;
			if (cpri < lowest_priority) {
				lowest_priority = cpri;
				lp_processor = processor;
			}

			if ((cpri >= BASEPRI_RTQUEUES) && (processor->deadline > furthest_deadline)) {
				furthest_deadline = processor->deadline;
				fd_processor = processor;
			}

			integer_t ccount = SCHED(processor_runq_count)(processor);
			if (ccount < lowest_count) {
				lowest_count = ccount;
				lc_processor = processor;
			}
		}

		/*
		 * For SMT configs, these idle secondary processors must have active primary. Otherwise
		 * the idle primary would have short-circuited the loop above
		 */
		qe_foreach_element(processor, &cset->idle_secondary_queue, processor_queue) {

			if (!processor->is_recommended) {
				continue;
			}

			processor_t cprimary = processor->processor_primary;

			/* If the primary processor is offline or starting up, it's not a candidate for this path */
			if (cprimary->state == PROCESSOR_RUNNING || cprimary->state == PROCESSOR_DISPATCHING) {
				integer_t primary_pri = cprimary->current_pri;

				if (primary_pri < lowest_unpaired_primary_priority) {
					lowest_unpaired_primary_priority = primary_pri;
					lp_unpaired_primary_processor = cprimary;
					lp_unpaired_secondary_processor = processor;
				}
			}
		}


		if (thread->sched_pri >= BASEPRI_RTQUEUES) {

			/*
			 * For realtime threads, the most important aspect is
			 * scheduling latency, so we attempt to assign threads
			 * to good preemption candidates (assuming an idle primary
			 * processor was not available above).
			 */

			if (thread->sched_pri > lowest_unpaired_primary_priority) {
				/* Move to end of active queue so that the next thread doesn't also pick it */
				re_queue_tail(&cset->active_queue, &lp_unpaired_primary_processor->processor_queue);
				return lp_unpaired_primary_processor;
			}
			if (thread->sched_pri > lowest_priority) {
				/* Move to end of active queue so that the next thread doesn't also pick it */
				re_queue_tail(&cset->active_queue, &lp_processor->processor_queue);
				return lp_processor;
			}
			if (thread->realtime.deadline < furthest_deadline)
				return fd_processor;

			/*
			 * If all primary and secondary CPUs are busy with realtime
			 * threads with deadlines earlier than us, move on to next
			 * pset.
			 */
		}
		else {

			if (thread->sched_pri > lowest_unpaired_primary_priority) {
				/* Move to end of active queue so that the next thread doesn't also pick it */
				re_queue_tail(&cset->active_queue, &lp_unpaired_primary_processor->processor_queue);
				return lp_unpaired_primary_processor;
			}
			if (thread->sched_pri > lowest_priority) {
				/* Move to end of active queue so that the next thread doesn't also pick it */
				re_queue_tail(&cset->active_queue, &lp_processor->processor_queue);
				return lp_processor;
			}

			/*
			 * If all primary processor in this pset are running a higher
			 * priority thread, move on to next pset. Only when we have
			 * exhausted this search do we fall back to other heuristics.
			 */
		}

		/*
		 * Move onto the next processor set.
		 */
		nset = next_pset(cset);

		if (nset != pset) {
			pset_unlock(cset);

			cset = nset;
			pset_lock(cset);
		}
	} while (nset != pset);

	/*
	 * Make sure that we pick a running processor,
	 * and that the correct processor set is locked.
	 * Since we may have unlock the candidate processor's
	 * pset, it may have changed state.
	 *
	 * All primary processors are running a higher priority
	 * thread, so the only options left are enqueuing on
	 * the secondary processor that would perturb the least priority
	 * primary, or the least busy primary.
	 */
	do {

		/* lowest_priority is evaluated in the main loops above */
		if (lp_unpaired_secondary_processor != PROCESSOR_NULL) {
			processor = lp_unpaired_secondary_processor;
			lp_unpaired_secondary_processor = PROCESSOR_NULL;
		} else if (lc_processor != PROCESSOR_NULL) {
			processor = lc_processor;
			lc_processor = PROCESSOR_NULL;
		} else {
			/*
			 * All processors are executing higher
			 * priority threads, and the lowest_count
			 * candidate was not usable
			 */
			processor = master_processor;
		}

		/*
		 * Check that the correct processor set is
		 * returned locked.
		 */
		if (cset != processor->processor_set) {
			pset_unlock(cset);
			cset = processor->processor_set;
			pset_lock(cset);
		}

		/*
		 * We must verify that the chosen processor is still available.
		 * master_processor is an exception, since we may need to preempt
		 * a running thread on it during processor shutdown (for sleep),
		 * and that thread needs to be enqueued on its runqueue to run
		 * when the processor is restarted.
		 */
		if (processor != master_processor && (processor->state == PROCESSOR_SHUTDOWN || processor->state == PROCESSOR_OFF_LINE))
			processor = PROCESSOR_NULL;

	} while (processor == PROCESSOR_NULL);

	return (processor);
}

/*
 *	thread_setrun:
 *
 *	Dispatch thread for execution, onto an idle
 *	processor or run queue, and signal a preemption
 *	as appropriate.
 *
 *	Thread must be locked.
 */
void
thread_setrun(
	thread_t			thread,
	integer_t			options)
{
	processor_t			processor;
	processor_set_t		pset;

	assert((thread->state & (TH_RUN|TH_WAIT|TH_UNINT|TH_TERMINATE|TH_TERMINATE2)) == TH_RUN);
	assert(thread->runq == PROCESSOR_NULL);

	/*
	 *	Update priority if needed.
	 */
	if (SCHED(can_update_priority)(thread))
		SCHED(update_priority)(thread);

	thread->sfi_class = sfi_thread_classify(thread);

	assert(thread->runq == PROCESSOR_NULL);

#if __SMP__
	if (thread->bound_processor == PROCESSOR_NULL) {
		/*
		 *	Unbound case.
		 */
		if (thread->affinity_set != AFFINITY_SET_NULL) {
			/*
			 * Use affinity set policy hint.
			 */
			pset = thread->affinity_set->aset_pset;
			pset_lock(pset);

			processor = SCHED(choose_processor)(pset, PROCESSOR_NULL, thread);

			SCHED_DEBUG_CHOOSE_PROCESSOR_KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_CHOOSE_PROCESSOR)|DBG_FUNC_NONE,
									  (uintptr_t)thread_tid(thread), (uintptr_t)-1, processor->cpu_id, processor->state, 0);
		} else if (thread->last_processor != PROCESSOR_NULL) {
			/*
			 *	Simple (last processor) affinity case.
			 */
			processor = thread->last_processor;
			pset = processor->processor_set;
			pset_lock(pset);
			processor = SCHED(choose_processor)(pset, processor, thread);

			SCHED_DEBUG_CHOOSE_PROCESSOR_KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_CHOOSE_PROCESSOR)|DBG_FUNC_NONE,
								  (uintptr_t)thread_tid(thread), thread->last_processor->cpu_id, processor->cpu_id, processor->state, 0);
		} else {
			/*
			 *	No Affinity case:
			 *
			 *	Utilitize a per task hint to spread threads
			 *	among the available processor sets.
			 */
			task_t		task = thread->task;

			pset = task->pset_hint;
			if (pset == PROCESSOR_SET_NULL)
				pset = current_processor()->processor_set;

			pset = choose_next_pset(pset);
			pset_lock(pset);

			processor = SCHED(choose_processor)(pset, PROCESSOR_NULL, thread);
			task->pset_hint = processor->processor_set;

			SCHED_DEBUG_CHOOSE_PROCESSOR_KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_CHOOSE_PROCESSOR)|DBG_FUNC_NONE,
									  (uintptr_t)thread_tid(thread), (uintptr_t)-1, processor->cpu_id, processor->state, 0);
		}
	} else {
		/*
		 *	Bound case:
		 *
		 *	Unconditionally dispatch on the processor.
		 */
		processor = thread->bound_processor;
		pset = processor->processor_set;
		pset_lock(pset);

		SCHED_DEBUG_CHOOSE_PROCESSOR_KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_CHOOSE_PROCESSOR)|DBG_FUNC_NONE,
							  (uintptr_t)thread_tid(thread), (uintptr_t)-2, processor->cpu_id, processor->state, 0);
	}
#else /* !__SMP__ */
	/* Only one processor to choose */
	assert(thread->bound_processor == PROCESSOR_NULL || thread->bound_processor == master_processor);
	processor = master_processor;
	pset = processor->processor_set;
	pset_lock(pset);
#endif /* !__SMP__ */

	/*
	 *	Dispatch the thread on the chosen processor.
	 *	TODO: This should be based on sched_mode, not sched_pri
	 */
	if (thread->sched_pri >= BASEPRI_RTQUEUES)
		realtime_setrun(processor, thread);
	else
		processor_setrun(processor, thread, options);
}

processor_set_t
task_choose_pset(
	task_t		task)
{
	processor_set_t		pset = task->pset_hint;

	if (pset != PROCESSOR_SET_NULL)
		pset = choose_next_pset(pset);

	return (pset);
}

/*
 *	Check for a preemption point in
 *	the current context.
 *
 *	Called at splsched with thread locked.
 */
ast_t
csw_check(
	processor_t		processor,
	ast_t			check_reason)
{
	processor_set_t	pset = processor->processor_set;
	ast_t			result;

	pset_lock(pset);

	/* If we were sent a remote AST and interrupted a running processor, acknowledge it here with pset lock held */
	pset->pending_AST_cpu_mask &= ~(1ULL << processor->cpu_id);

	result = csw_check_locked(processor, pset, check_reason);

	pset_unlock(pset);

	return result;
}

/*
 * Check for preemption at splsched with
 * pset and thread locked
 */
ast_t
csw_check_locked(
	processor_t		processor,
	processor_set_t	pset __unused,
	ast_t			check_reason)
{
	ast_t			result;
	thread_t		thread = processor->active_thread;

	if (processor->first_timeslice) {
		if (rt_runq.count > 0)
			return (check_reason | AST_PREEMPT | AST_URGENT);
	}
	else {
		if (rt_runq.count > 0) {
			if (BASEPRI_RTQUEUES > processor->current_pri)
				return (check_reason | AST_PREEMPT | AST_URGENT);
			else
				return (check_reason | AST_PREEMPT);
		}
	}

	result = SCHED(processor_csw_check)(processor);
	if (result != AST_NONE)
		return (check_reason | result | (thread_eager_preemption(thread) ? AST_URGENT : AST_NONE));

#if __SMP__

	/*
	 * If the current thread is running on a processor that is no longer recommended, gently
	 * (non-urgently) get to a point and then block, and which point thread_select() should
	 * try to idle the processor and re-dispatch the thread to a recommended processor.
	 */
	if (!processor->is_recommended)
		return (check_reason | AST_PREEMPT);

	/*
	 * Even though we could continue executing on this processor, a
	 * secondary SMT core should try to shed load to another primary core.
	 *
	 * TODO: Should this do the same check that thread_select does? i.e.
	 * if no bound threads target this processor, and idle primaries exist, preempt
	 * The case of RT threads existing is already taken care of above
	 * Consider Capri in this scenario.
	 *
	 * if (!SCHED(processor_bound_count)(processor) && !queue_empty(&pset->idle_queue))
	 *
	 * TODO: Alternatively - check if only primary is idle, or check if primary's pri is lower than mine.
	 */

	if (processor->current_pri < BASEPRI_RTQUEUES &&
	    processor->processor_primary != processor)
		return (check_reason | AST_PREEMPT);
#endif

	if (thread->state & TH_SUSP)
		return (check_reason | AST_PREEMPT);

#if CONFIG_SCHED_SFI
	/*
	 * Current thread may not need to be preempted, but maybe needs
	 * an SFI wait?
	 */
	result = sfi_thread_needs_ast(thread, NULL);
	if (result != AST_NONE)
		return (check_reason | result);
#endif

	return (AST_NONE);
}

/*
 *	set_sched_pri:
 *
 *	Set the scheduled priority of the specified thread.
 *
 *	This may cause the thread to change queues.
 *
 *	Thread must be locked.
 */
void
set_sched_pri(
              thread_t        thread,
              int             priority)
{
	thread_t cthread = current_thread();
	boolean_t is_current_thread = (thread == cthread) ? TRUE : FALSE;
	int curgency, nurgency;
	uint64_t urgency_param1, urgency_param2;
	boolean_t removed_from_runq = FALSE;

	/* If we're already at this priority, no need to mess with the runqueue */
	if (priority == thread->sched_pri)
		return;

	if (is_current_thread) {
		assert(thread->runq == PROCESSOR_NULL);
		curgency = thread_get_urgency(thread, &urgency_param1, &urgency_param2);
	} else {
		removed_from_runq = thread_run_queue_remove(thread);
	}

	thread->sched_pri = priority;

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_CHANGE_PRIORITY),
	                      (uintptr_t)thread_tid(thread),
	                      thread->base_pri,
	                      thread->sched_pri,
	                      0, /* eventually, 'reason' */
	                      0);

	if (is_current_thread) {
		nurgency = thread_get_urgency(thread, &urgency_param1, &urgency_param2);
		/*
		 * set_sched_pri doesn't alter RT params. We expect direct base priority/QoS
		 * class alterations from user space to occur relatively infrequently, hence
		 * those are lazily handled. QoS classes have distinct priority bands, and QoS
		 * inheritance is expected to involve priority changes.
		 */
		if (nurgency != curgency) {
			thread_tell_urgency(nurgency, urgency_param1, urgency_param2, 0, thread);
			machine_thread_going_on_core(thread, nurgency, 0, 0);
		}
	}

	/* TODO: Should this be TAILQ if it went down, HEADQ if it went up? */
	if (removed_from_runq)
		thread_run_queue_reinsert(thread, SCHED_PREEMPT | SCHED_TAILQ);
	else if (thread->state & TH_RUN) {
		processor_t processor = thread->last_processor;

		if (is_current_thread) {
			ast_t preempt;

			processor->current_pri = priority;
			processor->current_thmode = thread->sched_mode;
			processor->current_sfi_class = thread->sfi_class = sfi_thread_classify(thread);
			if ((preempt = csw_check(processor, AST_NONE)) != AST_NONE)
				ast_on(preempt);
		} else if (processor != PROCESSOR_NULL && processor->active_thread == thread)
			cause_ast_check(processor);
	}
}

/*
 * thread_run_queue_remove_for_handoff
 *
 * Pull a thread or its (recursive) push target out of the runqueue
 * so that it is ready for thread_run()
 *
 * Called at splsched
 *
 * Returns the thread that was pulled or THREAD_NULL if no thread could be pulled.
 * This may be different than the thread that was passed in.
 */
thread_t
thread_run_queue_remove_for_handoff(thread_t thread) {

	thread_t pulled_thread = THREAD_NULL;

	thread_lock(thread);

	/*
	 * Check that the thread is not bound
	 * to a different processor, and that realtime
	 * is not involved.
	 *
	 * Next, pull it off its run queue.  If it
	 * doesn't come, it's not eligible.
	 */

	processor_t processor = current_processor();
	if (processor->current_pri < BASEPRI_RTQUEUES && thread->sched_pri < BASEPRI_RTQUEUES &&
	    (thread->bound_processor == PROCESSOR_NULL || thread->bound_processor == processor)) {

			if (thread_run_queue_remove(thread))
				pulled_thread = thread;
	}

	thread_unlock(thread);

	return pulled_thread;
}

/*
 *	thread_run_queue_remove:
 *
 *	Remove a thread from its current run queue and
 *	return TRUE if successful.
 *
 *	Thread must be locked.
 *
 *	If thread->runq is PROCESSOR_NULL, the thread will not re-enter the
 *	run queues because the caller locked the thread.  Otherwise
 *	the thread is on a run queue, but could be chosen for dispatch
 *	and removed by another processor under a different lock, which
 *	will set thread->runq to PROCESSOR_NULL.
 *
 *	Hence the thread select path must not rely on anything that could
 *	be changed under the thread lock after calling this function,
 *	most importantly thread->sched_pri.
 */
boolean_t
thread_run_queue_remove(
                        thread_t        thread)
{
	boolean_t removed = FALSE;
	processor_t processor = thread->runq;

	if ((thread->state & (TH_RUN|TH_WAIT)) == TH_WAIT) {
		/* Thread isn't runnable */
		assert(thread->runq == PROCESSOR_NULL);
		return FALSE;
	}

	if (processor == PROCESSOR_NULL) {
		/*
		 * The thread is either not on the runq,
		 * or is in the midst of being removed from the runq.
		 *
		 * runq is set to NULL under the pset lock, not the thread
		 * lock, so the thread may still be in the process of being dequeued
		 * from the runq. It will wait in invoke for the thread lock to be
		 * dropped.
		 */

		return FALSE;
	}

	if (thread->sched_pri < BASEPRI_RTQUEUES) {
		return SCHED(processor_queue_remove)(processor, thread);
	}

	rt_lock_lock();

	if (thread->runq != PROCESSOR_NULL) {
		/*
		 *	Thread is on the RT run queue and we have a lock on
		 *	that run queue.
		 */

		assert(thread->runq == THREAD_ON_RT_RUNQ);

		remqueue(&thread->runq_links);
		SCHED_STATS_RUNQ_CHANGE(&rt_runq.runq_stats, rt_runq.count);
		rt_runq.count--;

		thread->runq = PROCESSOR_NULL;

		removed = TRUE;
	}

	rt_lock_unlock();

	return (removed);
}

/*
 * Put the thread back where it goes after a thread_run_queue_remove
 *
 * Thread must have been removed under the same thread lock hold
 *
 * thread locked, at splsched
 */
void
thread_run_queue_reinsert(thread_t thread, integer_t options)
{
	assert(thread->runq == PROCESSOR_NULL);

		assert(thread->state & (TH_RUN));
		thread_setrun(thread, options);

}

void
sys_override_cpu_throttle(int flag)
{
	if (flag == CPU_THROTTLE_ENABLE)
		cpu_throttle_enabled = 1;
	if (flag == CPU_THROTTLE_DISABLE)
		cpu_throttle_enabled = 0;
}

int
thread_get_urgency(thread_t thread, uint64_t *arg1, uint64_t *arg2)
{
	if (thread == NULL || (thread->state & TH_IDLE)) {
		*arg1 = 0;
		*arg2 = 0;

		return (THREAD_URGENCY_NONE);
	} else if (thread->sched_mode == TH_MODE_REALTIME) {
		*arg1 = thread->realtime.period;
		*arg2 = thread->realtime.deadline;

		return (THREAD_URGENCY_REAL_TIME);
	} else if (cpu_throttle_enabled &&
		   ((thread->sched_pri <= MAXPRI_THROTTLE) && (thread->base_pri <= MAXPRI_THROTTLE)))  {
		/*
		 * Background urgency applied when thread priority is MAXPRI_THROTTLE or lower and thread is not promoted
		 */
		*arg1 = thread->sched_pri;
		*arg2 = thread->base_pri;

		return (THREAD_URGENCY_BACKGROUND);
	} else {
		/* For otherwise unclassified threads, report throughput QoS
		 * parameters
		 */
		*arg1 = proc_get_effective_thread_policy(thread, TASK_POLICY_THROUGH_QOS);
		*arg2 = proc_get_effective_task_policy(thread->task, TASK_POLICY_THROUGH_QOS);

		return (THREAD_URGENCY_NORMAL);
	}
}


/*
 *	This is the processor idle loop, which just looks for other threads
 *	to execute.  Processor idle threads invoke this without supplying a
 *	current thread to idle without an asserted wait state.
 *
 *	Returns a the next thread to execute if dispatched directly.
 */

#if 0
#define IDLE_KERNEL_DEBUG_CONSTANT(...) KERNEL_DEBUG_CONSTANT(__VA_ARGS__)
#else
#define IDLE_KERNEL_DEBUG_CONSTANT(...) do { } while(0)
#endif

thread_t
processor_idle(
	thread_t			thread,
	processor_t			processor)
{
	processor_set_t		pset = processor->processor_set;
	thread_t			new_thread;
	int					state;
	(void)splsched();

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		MACHDBG_CODE(DBG_MACH_SCHED,MACH_IDLE) | DBG_FUNC_START, 
		(uintptr_t)thread_tid(thread), 0, 0, 0, 0);

	SCHED_STATS_CPU_IDLE_START(processor);

	timer_switch(&PROCESSOR_DATA(processor, system_state),
									mach_absolute_time(), &PROCESSOR_DATA(processor, idle_state));
	PROCESSOR_DATA(processor, current_state) = &PROCESSOR_DATA(processor, idle_state);

	while (1) {
		if (processor->state != PROCESSOR_IDLE) /* unsafe, but worst case we loop around once */
			break;
		if (pset->pending_AST_cpu_mask & (1ULL << processor->cpu_id))
			break;
		if (processor->is_recommended) {
			if (rt_runq.count)
				break;
		} else {
			if (SCHED(processor_bound_count)(processor))
				break;
		}

#if CONFIG_SCHED_IDLE_IN_PLACE
		if (thread != THREAD_NULL) {
			/* Did idle-in-place thread wake up */
			if ((thread->state & (TH_WAIT|TH_SUSP)) != TH_WAIT || thread->wake_active)
				break;
		}
#endif

		IDLE_KERNEL_DEBUG_CONSTANT(
			MACHDBG_CODE(DBG_MACH_SCHED,MACH_IDLE) | DBG_FUNC_NONE, (uintptr_t)thread_tid(thread), rt_runq.count, SCHED(processor_runq_count)(processor), -1, 0);

		machine_track_platform_idle(TRUE);

		machine_idle();

		machine_track_platform_idle(FALSE);

		(void)splsched();

		IDLE_KERNEL_DEBUG_CONSTANT(
			MACHDBG_CODE(DBG_MACH_SCHED,MACH_IDLE) | DBG_FUNC_NONE, (uintptr_t)thread_tid(thread), rt_runq.count, SCHED(processor_runq_count)(processor), -2, 0);

		if (!SCHED(processor_queue_empty)(processor)) {
			/* Secondary SMT processors respond to directed wakeups
			 * exclusively. Some platforms induce 'spurious' SMT wakeups.
			 */
			if (processor->processor_primary == processor)
					break;
		}
	}

	timer_switch(&PROCESSOR_DATA(processor, idle_state),
									mach_absolute_time(), &PROCESSOR_DATA(processor, system_state));
	PROCESSOR_DATA(processor, current_state) = &PROCESSOR_DATA(processor, system_state);

	pset_lock(pset);

	/* If we were sent a remote AST and came out of idle, acknowledge it here with pset lock held */
	pset->pending_AST_cpu_mask &= ~(1ULL << processor->cpu_id);
#if defined(CONFIG_SCHED_DEFERRED_AST)
	pset->pending_deferred_AST_cpu_mask &= ~(1ULL << processor->cpu_id);
#endif

	state = processor->state;
	if (state == PROCESSOR_DISPATCHING) {
		/*
		 *	Commmon case -- cpu dispatched.
		 */
		new_thread = processor->next_thread;
		processor->next_thread = THREAD_NULL;
		processor->state = PROCESSOR_RUNNING;

		if ((new_thread != THREAD_NULL) && (SCHED(processor_queue_has_priority)(processor, new_thread->sched_pri, FALSE)					||
											(rt_runq.count > 0))	) {
   			/* Something higher priority has popped up on the runqueue - redispatch this thread elsewhere */
			processor->current_pri = IDLEPRI;
			processor->current_thmode = TH_MODE_FIXED;
			processor->current_sfi_class = SFI_CLASS_KERNEL;
			processor->deadline = UINT64_MAX;

			pset_unlock(pset);

			thread_lock(new_thread);
			KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_REDISPATCH), (uintptr_t)thread_tid(new_thread), new_thread->sched_pri, rt_runq.count, 0, 0);
			thread_setrun(new_thread, SCHED_HEADQ);
			thread_unlock(new_thread);

			KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				MACHDBG_CODE(DBG_MACH_SCHED,MACH_IDLE) | DBG_FUNC_END, 
				(uintptr_t)thread_tid(thread), state, 0, 0, 0);

			return (THREAD_NULL);
		}

		pset_unlock(pset);

		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
			MACHDBG_CODE(DBG_MACH_SCHED,MACH_IDLE) | DBG_FUNC_END, 
			(uintptr_t)thread_tid(thread), state, (uintptr_t)thread_tid(new_thread), 0, 0);

		return (new_thread);

	} else if (state == PROCESSOR_IDLE) {
		re_queue_tail(&pset->active_queue, &processor->processor_queue);

		processor->state = PROCESSOR_RUNNING;
		processor->current_pri = IDLEPRI;
		processor->current_thmode = TH_MODE_FIXED;
		processor->current_sfi_class = SFI_CLASS_KERNEL;
		processor->deadline = UINT64_MAX;

	} else if (state == PROCESSOR_SHUTDOWN) {
		/*
		 *	Going off-line.  Force a
		 *	reschedule.
		 */
		if ((new_thread = processor->next_thread) != THREAD_NULL) {
			processor->next_thread = THREAD_NULL;
			processor->current_pri = IDLEPRI;
			processor->current_thmode = TH_MODE_FIXED;
			processor->current_sfi_class = SFI_CLASS_KERNEL;
			processor->deadline = UINT64_MAX;

			pset_unlock(pset);

			thread_lock(new_thread);
			thread_setrun(new_thread, SCHED_HEADQ);
			thread_unlock(new_thread);

			KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				MACHDBG_CODE(DBG_MACH_SCHED,MACH_IDLE) | DBG_FUNC_END, 
				(uintptr_t)thread_tid(thread), state, 0, 0, 0);
		
			return (THREAD_NULL);
		}
	}

	pset_unlock(pset);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		MACHDBG_CODE(DBG_MACH_SCHED,MACH_IDLE) | DBG_FUNC_END, 
		(uintptr_t)thread_tid(thread), state, 0, 0, 0);
		
	return (THREAD_NULL);
}

/*
 *	Each processor has a dedicated thread which
 *	executes the idle loop when there is no suitable
 *	previous context.
 */
void
idle_thread(void)
{
	processor_t		processor = current_processor();
	thread_t		new_thread;

	new_thread = processor_idle(THREAD_NULL, processor);
	if (new_thread != THREAD_NULL) {
		thread_run(processor->idle_thread, (thread_continue_t)idle_thread, NULL, new_thread);
		/*NOTREACHED*/
	}

	thread_block((thread_continue_t)idle_thread);
	/*NOTREACHED*/
}

kern_return_t
idle_thread_create(
	processor_t		processor)
{
	kern_return_t	result;
	thread_t		thread;
	spl_t			s;

	result = kernel_thread_create((thread_continue_t)idle_thread, NULL, MAXPRI_KERNEL, &thread);
	if (result != KERN_SUCCESS)
		return (result);

	s = splsched();
	thread_lock(thread);
	thread->bound_processor = processor;
	processor->idle_thread = thread;
	thread->sched_pri = thread->base_pri = IDLEPRI;
	thread->state = (TH_RUN | TH_IDLE);
	thread->options |= TH_OPT_IDLE_THREAD;
	thread_unlock(thread);
	splx(s);

	thread_deallocate(thread);

	return (KERN_SUCCESS);
}

/*
 * sched_startup:
 *
 * Kicks off scheduler services.
 *
 * Called at splsched.
 */
void
sched_startup(void)
{
	kern_return_t	result;
	thread_t		thread;

	simple_lock_init(&sched_vm_group_list_lock, 0);


	result = kernel_thread_start_priority((thread_continue_t)sched_init_thread,
	    (void *)SCHED(maintenance_continuation), MAXPRI_KERNEL, &thread);
	if (result != KERN_SUCCESS)
		panic("sched_startup");

	thread_deallocate(thread);

	assert_thread_magic(thread);

	/*
	 * Yield to the sched_init_thread once, to
	 * initialize our own thread after being switched
	 * back to.
	 *
	 * The current thread is the only other thread
	 * active at this point.
	 */
	thread_block(THREAD_CONTINUE_NULL);
}

#if defined(CONFIG_SCHED_TIMESHARE_CORE)

static volatile uint64_t 		sched_maintenance_deadline;
static uint64_t				sched_tick_last_abstime;
static uint64_t				sched_tick_delta;
uint64_t				sched_tick_max_delta;
/*
 *	sched_init_thread:
 *
 *	Perform periodic bookkeeping functions about ten
 *	times per second.
 */
void
sched_timeshare_maintenance_continue(void)
{
	uint64_t	sched_tick_ctime, late_time;

	struct sched_update_scan_context scan_context = {
		.earliest_bg_make_runnable_time = UINT64_MAX,
		.earliest_normal_make_runnable_time = UINT64_MAX,
		.earliest_rt_make_runnable_time = UINT64_MAX
	};

	sched_tick_ctime = mach_absolute_time();	

	if (__improbable(sched_tick_last_abstime == 0)) {
		sched_tick_last_abstime = sched_tick_ctime;
		late_time = 0;
		sched_tick_delta = 1;
	} else {
		late_time = sched_tick_ctime - sched_tick_last_abstime;
		sched_tick_delta = late_time / sched_tick_interval;
		/* Ensure a delta of 1, since the interval could be slightly
		 * smaller than the sched_tick_interval due to dispatch
		 * latencies.
		 */
		sched_tick_delta = MAX(sched_tick_delta, 1);

		/* In the event interrupt latencies or platform
		 * idle events that advanced the timebase resulted
		 * in periods where no threads were dispatched,
		 * cap the maximum "tick delta" at SCHED_TICK_MAX_DELTA
		 * iterations.
		 */
		sched_tick_delta = MIN(sched_tick_delta, SCHED_TICK_MAX_DELTA);

		sched_tick_last_abstime = sched_tick_ctime;
		sched_tick_max_delta = MAX(sched_tick_delta, sched_tick_max_delta);
	}

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_MAINTENANCE)|DBG_FUNC_START,
	        sched_tick_delta, late_time, 0, 0, 0);

	/* Add a number of pseudo-ticks corresponding to the elapsed interval
	 * This could be greater than 1 if substantial intervals where
	 * all processors are idle occur, which rarely occurs in practice.
	 */

	sched_tick += sched_tick_delta;

	/*
	 *  Compute various averages.
	 */
	compute_averages(sched_tick_delta);

	/*
	 *  Scan the run queues for threads which
	 *  may need to be updated, and find the earliest runnable thread on the runqueue
	 *  to report its latency.
	 */
	SCHED(thread_update_scan)(&scan_context);

	rt_runq_scan(&scan_context);

	uint64_t ctime = mach_absolute_time();

	uint64_t bg_max_latency       = (ctime > scan_context.earliest_bg_make_runnable_time) ?
	                                 ctime - scan_context.earliest_bg_make_runnable_time : 0;

	uint64_t default_max_latency  = (ctime > scan_context.earliest_normal_make_runnable_time) ?
	                                 ctime - scan_context.earliest_normal_make_runnable_time : 0;

	uint64_t realtime_max_latency = (ctime > scan_context.earliest_rt_make_runnable_time) ?
	                                 ctime - scan_context.earliest_rt_make_runnable_time : 0;

	machine_max_runnable_latency(bg_max_latency, default_max_latency, realtime_max_latency);

	/*
	 * Check to see if the special sched VM group needs attention.
	 */
	sched_vm_group_maintenance();


	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_MAINTENANCE) | DBG_FUNC_END,
	        sched_pri_shifts[TH_BUCKET_SHARE_FG], sched_pri_shifts[TH_BUCKET_SHARE_BG],
	        sched_pri_shifts[TH_BUCKET_SHARE_UT], 0, 0);

	assert_wait((event_t)sched_timeshare_maintenance_continue, THREAD_UNINT);
	thread_block((thread_continue_t)sched_timeshare_maintenance_continue);
	/*NOTREACHED*/
}

static uint64_t sched_maintenance_wakeups;

/*
 * Determine if the set of routines formerly driven by a maintenance timer
 * must be invoked, based on a deadline comparison. Signals the scheduler
 * maintenance thread on deadline expiration. Must be invoked at an interval
 * lower than the "sched_tick_interval", currently accomplished by
 * invocation via the quantum expiration timer and at context switch time.
 * Performance matters: this routine reuses a timestamp approximating the
 * current absolute time received from the caller, and should perform
 * no more than a comparison against the deadline in the common case.
 */
void
sched_timeshare_consider_maintenance(uint64_t ctime) {
	uint64_t ndeadline, deadline = sched_maintenance_deadline;

	if (__improbable(ctime >= deadline)) {
		if (__improbable(current_thread() == sched_maintenance_thread))
			return;
		OSMemoryBarrier();

		ndeadline = ctime + sched_tick_interval;

		if (__probable(__sync_bool_compare_and_swap(&sched_maintenance_deadline, deadline, ndeadline))) {
			thread_wakeup((event_t)sched_timeshare_maintenance_continue);
			sched_maintenance_wakeups++;
		}
	}
}

#endif /* CONFIG_SCHED_TIMESHARE_CORE */

void
sched_init_thread(void (*continuation)(void))
{
	thread_block(THREAD_CONTINUE_NULL);

	thread_t thread = current_thread();

	thread_set_thread_name(thread, "sched_maintenance_thread");

	sched_maintenance_thread = thread;

	continuation();

	/*NOTREACHED*/
}

#if defined(CONFIG_SCHED_TIMESHARE_CORE)

/*
 *	thread_update_scan / runq_scan:
 *
 *	Scan the run queues to account for timesharing threads 
 *	which need to be updated.
 *
 *	Scanner runs in two passes.  Pass one squirrels likely
 *	threads away in an array, pass two does the update.
 *
 *	This is necessary because the run queue is locked for
 *	the candidate scan, but	the thread is locked for the update.
 *
 *	Array should be sized to make forward progress, without
 *	disabling preemption for long periods.
 */

#define	THREAD_UPDATE_SIZE		128

static thread_t thread_update_array[THREAD_UPDATE_SIZE];
static uint32_t thread_update_count = 0;

/* Returns TRUE if thread was added, FALSE if thread_update_array is full */
boolean_t
thread_update_add_thread(thread_t thread)
{
	if (thread_update_count == THREAD_UPDATE_SIZE)
		return (FALSE);

	thread_update_array[thread_update_count++] = thread;
	thread_reference_internal(thread);
	return (TRUE);
}

void
thread_update_process_threads(void)
{
	assert(thread_update_count <= THREAD_UPDATE_SIZE);

	for (uint32_t i = 0 ; i < thread_update_count ; i++) {
		thread_t thread = thread_update_array[i];
		assert_thread_magic(thread);
		thread_update_array[i] = THREAD_NULL;

		spl_t s = splsched();
		thread_lock(thread);
		if (!(thread->state & (TH_WAIT)) && thread->sched_stamp != sched_tick) {
			SCHED(update_priority)(thread);
		}
		thread_unlock(thread);
		splx(s);

		thread_deallocate(thread);
	}

	thread_update_count = 0;
}

/*
 *	Scan a runq for candidate threads.
 *
 *	Returns TRUE if retry is needed.
 */
boolean_t
runq_scan(
          run_queue_t                   runq,
          sched_update_scan_context_t   scan_context)
{
	int count       = runq->count;
	int queue_index;

	assert(count >= 0);

	if (count == 0)
		return FALSE;

	for (queue_index = bitmap_first(runq->bitmap, NRQS);
	     queue_index >= 0;
	     queue_index = bitmap_next(runq->bitmap, queue_index)) {

		thread_t thread;
		queue_t  queue = &runq->queues[queue_index];

		qe_foreach_element(thread, queue, runq_links) {
			assert(count > 0);
			assert_thread_magic(thread);

			if (thread->sched_stamp != sched_tick &&
			    thread->sched_mode == TH_MODE_TIMESHARE) {
				if (thread_update_add_thread(thread) == FALSE)
					return TRUE;
			}

			if (cpu_throttle_enabled && ((thread->sched_pri <= MAXPRI_THROTTLE) && (thread->base_pri <= MAXPRI_THROTTLE))) {
				if (thread->last_made_runnable_time < scan_context->earliest_bg_make_runnable_time) {
					scan_context->earliest_bg_make_runnable_time = thread->last_made_runnable_time;
				}
			} else {
				if (thread->last_made_runnable_time < scan_context->earliest_normal_make_runnable_time) {
					scan_context->earliest_normal_make_runnable_time = thread->last_made_runnable_time;
				}
			}
			count--;
		}
	}

	return FALSE;
}

#endif /* CONFIG_SCHED_TIMESHARE_CORE */

boolean_t
thread_eager_preemption(thread_t thread) 
{
	return ((thread->sched_flags & TH_SFLAG_EAGERPREEMPT) != 0);
}

void
thread_set_eager_preempt(thread_t thread) 
{
	spl_t x;
	processor_t p;
	ast_t ast = AST_NONE;

	x = splsched();
	p = current_processor();

	thread_lock(thread);
	thread->sched_flags |= TH_SFLAG_EAGERPREEMPT;

	if (thread == current_thread()) {

		ast = csw_check(p, AST_NONE);
		thread_unlock(thread);
		if (ast != AST_NONE) {
			(void) thread_block_reason(THREAD_CONTINUE_NULL, NULL, ast);
		}
	} else {
		p = thread->last_processor;

		if (p != PROCESSOR_NULL	&& p->state == PROCESSOR_RUNNING &&
			p->active_thread == thread) {
			cause_ast_check(p);
		}
		
		thread_unlock(thread);
	}

	splx(x);
}

void
thread_clear_eager_preempt(thread_t thread) 
{
	spl_t x;

	x = splsched();
	thread_lock(thread);

	thread->sched_flags &= ~TH_SFLAG_EAGERPREEMPT;
	
	thread_unlock(thread);
	splx(x);
}

/*
 * Scheduling statistics
 */
void
sched_stats_handle_csw(processor_t processor, int reasons, int selfpri, int otherpri)
{
	struct processor_sched_statistics *stats;
	boolean_t to_realtime = FALSE;
	
	stats = &processor->processor_data.sched_stats;
	stats->csw_count++;

	if (otherpri >= BASEPRI_REALTIME) {
		stats->rt_sched_count++;
		to_realtime = TRUE;
	}

	if ((reasons & AST_PREEMPT) != 0) {
		stats->preempt_count++;

		if (selfpri >= BASEPRI_REALTIME) {
			stats->preempted_rt_count++;
		} 

		if (to_realtime) {
			stats->preempted_by_rt_count++;
		}

	}
}

void
sched_stats_handle_runq_change(struct runq_stats *stats, int old_count) 
{
	uint64_t timestamp = mach_absolute_time();

	stats->count_sum += (timestamp - stats->last_change_timestamp) * old_count;
	stats->last_change_timestamp = timestamp;
}

/*
 *     For calls from assembly code
 */
#undef thread_wakeup
void
thread_wakeup(
       event_t         x);

void
thread_wakeup(
       event_t         x)
{
       thread_wakeup_with_result(x, THREAD_AWAKENED);
}

boolean_t
preemption_enabled(void)
{
	return (get_preemption_level() == 0 && ml_get_interrupts_enabled());
}

static void
sched_timer_deadline_tracking_init(void) {
	nanoseconds_to_absolutetime(TIMER_DEADLINE_TRACKING_BIN_1_DEFAULT, &timer_deadline_tracking_bin_1);
	nanoseconds_to_absolutetime(TIMER_DEADLINE_TRACKING_BIN_2_DEFAULT, &timer_deadline_tracking_bin_2);
}


kern_return_t
sched_work_interval_notify(thread_t thread, uint64_t work_interval_id, uint64_t start, uint64_t finish, uint64_t deadline, uint64_t next_start, uint32_t flags)
{
	int urgency;
	uint64_t urgency_param1, urgency_param2;
	spl_t s;

	if (work_interval_id == 0) {
		return (KERN_INVALID_ARGUMENT);
	}

	assert(thread == current_thread());

	thread_mtx_lock(thread);
	if (thread->work_interval_id != work_interval_id) {
		thread_mtx_unlock(thread);
		return (KERN_INVALID_ARGUMENT);
	}
	thread_mtx_unlock(thread);

	s = splsched();
	thread_lock(thread);
	urgency = thread_get_urgency(thread, &urgency_param1, &urgency_param2);
	thread_unlock(thread);
	splx(s);

	machine_work_interval_notify(thread, work_interval_id, start, finish, deadline, next_start, urgency, flags);
	return (KERN_SUCCESS);
}

void thread_set_options(uint32_t thopt) {
 	spl_t x;
 	thread_t t = current_thread();
 
 	x = splsched();
 	thread_lock(t);
 
 	t->options |= thopt;
 
 	thread_unlock(t);
 	splx(x);
}

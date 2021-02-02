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
#include <machine/limits.h>
#include <machine/atomic.h>

#include <machine/commpage.h>

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
#if MONOTONIC
#include <kern/monotonic.h>
#endif /* MONOTONIC */
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
#include <kern/cpu_quiesce.h>

#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_pageout.h>

#include <mach/sdt.h>
#include <mach/mach_host.h>
#include <mach/host_info.h>

#include <sys/kdebug.h>
#include <kperf/kperf.h>
#include <kern/kpc.h>
#include <san/kasan.h>
#include <kern/pms.h>
#include <kern/host.h>
#include <stdatomic.h>

struct sched_statistics PERCPU_DATA(sched_stats);
bool sched_stats_active;

int
rt_runq_count(processor_set_t pset)
{
	return atomic_load_explicit(&SCHED(rt_runq)(pset)->count, memory_order_relaxed);
}

void
rt_runq_count_incr(processor_set_t pset)
{
	atomic_fetch_add_explicit(&SCHED(rt_runq)(pset)->count, 1, memory_order_relaxed);
}

void
rt_runq_count_decr(processor_set_t pset)
{
	atomic_fetch_sub_explicit(&SCHED(rt_runq)(pset)->count, 1, memory_order_relaxed);
}

#define         DEFAULT_PREEMPTION_RATE         100             /* (1/s) */
TUNABLE(int, default_preemption_rate, "preempt", DEFAULT_PREEMPTION_RATE);

#define         DEFAULT_BG_PREEMPTION_RATE      400             /* (1/s) */
TUNABLE(int, default_bg_preemption_rate, "bg_preempt", DEFAULT_BG_PREEMPTION_RATE);

#define         MAX_UNSAFE_QUANTA               800
TUNABLE(int, max_unsafe_quanta, "unsafe", MAX_UNSAFE_QUANTA);

#define         MAX_POLL_QUANTA                 2
TUNABLE(int, max_poll_quanta, "poll", MAX_POLL_QUANTA);

#define         SCHED_POLL_YIELD_SHIFT          4               /* 1/16 */
int             sched_poll_yield_shift = SCHED_POLL_YIELD_SHIFT;

uint64_t        max_poll_computation;

uint64_t        max_unsafe_computation;
uint64_t        sched_safe_duration;

#if defined(CONFIG_SCHED_TIMESHARE_CORE)

uint32_t        std_quantum;
uint32_t        min_std_quantum;
uint32_t        bg_quantum;

uint32_t        std_quantum_us;
uint32_t        bg_quantum_us;

#endif /* CONFIG_SCHED_TIMESHARE_CORE */

uint32_t        thread_depress_time;
uint32_t        default_timeshare_computation;
uint32_t        default_timeshare_constraint;

uint32_t        max_rt_quantum;
uint32_t        min_rt_quantum;

uint32_t        rt_constraint_threshold;

#if defined(CONFIG_SCHED_TIMESHARE_CORE)

unsigned                sched_tick;
uint32_t                sched_tick_interval;

/* Timeshare load calculation interval (15ms) */
uint32_t                sched_load_compute_interval_us = 15000;
uint64_t                sched_load_compute_interval_abs;
static _Atomic uint64_t sched_load_compute_deadline;

uint32_t        sched_pri_shifts[TH_BUCKET_MAX];
uint32_t        sched_fixed_shift;

uint32_t        sched_decay_usage_age_factor = 1; /* accelerate 5/8^n usage aging */

/* Allow foreground to decay past default to resolve inversions */
#define DEFAULT_DECAY_BAND_LIMIT ((BASEPRI_FOREGROUND - BASEPRI_DEFAULT) + 2)
int             sched_pri_decay_band_limit = DEFAULT_DECAY_BAND_LIMIT;

/* Defaults for timer deadline profiling */
#define TIMER_DEADLINE_TRACKING_BIN_1_DEFAULT 2000000 /* Timers with deadlines <=
	                                               * 2ms */
#define TIMER_DEADLINE_TRACKING_BIN_2_DEFAULT 5000000 /* Timers with deadlines
	                                               *   <= 5ms */

uint64_t timer_deadline_tracking_bin_1;
uint64_t timer_deadline_tracking_bin_2;

#endif /* CONFIG_SCHED_TIMESHARE_CORE */

thread_t sched_maintenance_thread;

/* interrupts disabled lock to guard recommended cores state */
decl_simple_lock_data(static, sched_recommended_cores_lock);
static uint64_t    usercontrol_requested_recommended_cores = ALL_CORES_RECOMMENDED;
static void sched_update_recommended_cores(uint64_t recommended_cores);

#if __arm__ || __arm64__
static void sched_recommended_cores_maintenance(void);
uint64_t    perfcontrol_failsafe_starvation_threshold;
extern char *proc_name_address(struct proc *p);
#endif /* __arm__ || __arm64__ */

uint64_t        sched_one_second_interval;
boolean_t       allow_direct_handoff = TRUE;

/* Forwards */

#if defined(CONFIG_SCHED_TIMESHARE_CORE)

static void load_shift_init(void);
static void preempt_pri_init(void);

#endif /* CONFIG_SCHED_TIMESHARE_CORE */

thread_t        processor_idle(
	thread_t                        thread,
	processor_t                     processor);

static ast_t
csw_check_locked(
	thread_t        thread,
	processor_t     processor,
	processor_set_t pset,
	ast_t           check_reason);

static void processor_setrun(
	processor_t                    processor,
	thread_t                       thread,
	integer_t                      options);

static void
sched_realtime_timebase_init(void);

static void
sched_timer_deadline_tracking_init(void);

#if     DEBUG
extern int debug_task;
#define TLOG(a, fmt, args...) if(debug_task & a) kprintf(fmt, ## args)
#else
#define TLOG(a, fmt, args...) do {} while (0)
#endif

static processor_t
thread_bind_internal(
	thread_t                thread,
	processor_t             processor);

static void
sched_vm_group_maintenance(void);

#if defined(CONFIG_SCHED_TIMESHARE_CORE)
int8_t          sched_load_shifts[NRQS];
bitmap_t        sched_preempt_pri[BITMAP_LEN(NRQS_MAX)];
#endif /* CONFIG_SCHED_TIMESHARE_CORE */

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

uint32_t sched_debug_flags = SCHED_DEBUG_FLAG_CHOOSE_PROCESSOR_TRACEPOINTS;

/* Global flag which indicates whether Background Stepper Context is enabled */
static int cpu_throttle_enabled = 1;

void
sched_init(void)
{
	boolean_t direct_handoff = FALSE;
	kprintf("Scheduler: Default of %s\n", SCHED(sched_name));

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

	if (PE_parse_boot_argn("sched_debug", &sched_debug_flags, sizeof(sched_debug_flags))) {
		kprintf("Scheduler: Debug flags 0x%08x\n", sched_debug_flags);
	}
	strlcpy(sched_string, SCHED(sched_name), sizeof(sched_string));

	cpu_quiescent_counter_init();

	SCHED(init)();
	SCHED(rt_init)(&pset0);
	sched_timer_deadline_tracking_init();

	SCHED(pset_init)(&pset0);
	SCHED(processor_init)(master_processor);

	if (PE_parse_boot_argn("direct_handoff", &direct_handoff, sizeof(direct_handoff))) {
		allow_direct_handoff = direct_handoff;
	}
}

void
sched_timebase_init(void)
{
	uint64_t        abstime;

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
	if (default_preemption_rate < 1) {
		default_preemption_rate = DEFAULT_PREEMPTION_RATE;
	}
	std_quantum_us = (1000 * 1000) / default_preemption_rate;

	printf("standard timeslicing quantum is %d us\n", std_quantum_us);

	if (default_bg_preemption_rate < 1) {
		default_bg_preemption_rate = DEFAULT_BG_PREEMPTION_RATE;
	}
	bg_quantum_us = (1000 * 1000) / default_bg_preemption_rate;

	printf("standard background quantum is %d us\n", bg_quantum_us);

	load_shift_init();
	preempt_pri_init();
	sched_tick = 0;
}

void
sched_timeshare_timebase_init(void)
{
	uint64_t        abstime;
	uint32_t        shift;

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

	/* timeshare load calculation interval & deadline initialization */
	clock_interval_to_absolutetime_interval(sched_load_compute_interval_us, NSEC_PER_USEC, &sched_load_compute_interval_abs);
	os_atomic_init(&sched_load_compute_deadline, sched_load_compute_interval_abs);

	/*
	 * Compute conversion factor from usage to
	 * timesharing priorities with 5/8 ** n aging.
	 */
	abstime = (abstime * 5) / 3;
	for (shift = 0; abstime > BASEPRI_DEFAULT; ++shift) {
		abstime >>= 1;
	}
	sched_fixed_shift = shift;

	for (uint32_t i = 0; i < TH_BUCKET_MAX; i++) {
		sched_pri_shifts[i] = INT8_MAX;
	}

	max_unsafe_computation = ((uint64_t)max_unsafe_quanta) * std_quantum;
	sched_safe_duration = 2 * ((uint64_t)max_unsafe_quanta) * std_quantum;

	max_poll_computation = ((uint64_t)max_poll_quanta) * std_quantum;
	thread_depress_time = 1 * std_quantum;
	default_timeshare_computation = std_quantum / 2;
	default_timeshare_constraint = std_quantum;

#if __arm__ || __arm64__
	perfcontrol_failsafe_starvation_threshold = (2 * sched_tick_interval);
#endif /* __arm__ || __arm64__ */
}

#endif /* CONFIG_SCHED_TIMESHARE_CORE */

void
pset_rt_init(processor_set_t pset)
{
	os_atomic_init(&pset->rt_runq.count, 0);
	queue_init(&pset->rt_runq.queue);
	memset(&pset->rt_runq.runq_stats, 0, sizeof pset->rt_runq.runq_stats);
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
		50, 1000 * NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	max_rt_quantum = (uint32_t)abstime;

	/* constraint threshold for sending backup IPIs (4 ms) */
	clock_interval_to_absolutetime_interval(4, NSEC_PER_MSEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	rt_constraint_threshold = (uint32_t)abstime;
}

void
sched_check_spill(processor_set_t pset, thread_t thread)
{
	(void)pset;
	(void)thread;

	return;
}

bool
sched_thread_should_yield(processor_t processor, thread_t thread)
{
	(void)thread;

	return !SCHED(processor_queue_empty)(processor) || rt_runq_count(processor->processor_set) > 0;
}

/* Default implementations of .steal_thread_enabled */
bool
sched_steal_thread_DISABLED(processor_set_t pset)
{
	(void)pset;
	return false;
}

bool
sched_steal_thread_enabled(processor_set_t pset)
{
	return bit_count(pset->node->pset_map) > 1;
}

#if defined(CONFIG_SCHED_TIMESHARE_CORE)

/*
 * Set up values for timeshare
 * loading factors.
 */
static void
load_shift_init(void)
{
	int8_t          k, *p = sched_load_shifts;
	uint32_t        i, j;

	uint32_t        sched_decay_penalty = 1;

	if (PE_parse_boot_argn("sched_decay_penalty", &sched_decay_penalty, sizeof(sched_decay_penalty))) {
		kprintf("Overriding scheduler decay penalty %u\n", sched_decay_penalty);
	}

	if (PE_parse_boot_argn("sched_decay_usage_age_factor", &sched_decay_usage_age_factor, sizeof(sched_decay_usage_age_factor))) {
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
		for (j <<= 1; (i < j) && (i < NRQS); ++i) {
			*p++ = k;
		}
	}
}

static void
preempt_pri_init(void)
{
	bitmap_t *p = sched_preempt_pri;

	for (int i = BASEPRI_FOREGROUND; i < MINPRI_KERNEL; ++i) {
		bitmap_set(p, i);
	}

	for (int i = BASEPRI_PREEMPT; i <= MAXPRI; ++i) {
		bitmap_set(p, i);
	}
}

#endif /* CONFIG_SCHED_TIMESHARE_CORE */

/*
 *	Thread wait timer expiration.
 */
void
thread_timer_expire(
	void                    *p0,
	__unused void   *p1)
{
	thread_t                thread = p0;
	spl_t                   s;

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
	thread_t                thread,
	wait_result_t   wresult)
{
	boolean_t               ready_for_runq = FALSE;
	thread_t                cthread = current_thread();
	uint32_t                new_run_count;
	int                             old_thread_state;

	/*
	 *	Set wait_result.
	 */
	thread->wait_result = wresult;

	/*
	 *	Cancel pending wait timer.
	 */
	if (thread->wait_timer_is_set) {
		if (timer_call_cancel(&thread->wait_timer)) {
			thread->wait_timer_active--;
		}
		thread->wait_timer_is_set = FALSE;
	}

	boolean_t aticontext, pidle;
	ml_get_power_state(&aticontext, &pidle);

	/*
	 *	Update scheduling state: not waiting,
	 *	set running.
	 */
	old_thread_state = thread->state;
	thread->state = (old_thread_state | TH_RUN) &
	    ~(TH_WAIT | TH_UNINT | TH_WAIT_REPORT);

	if ((old_thread_state & TH_RUN) == 0) {
		uint64_t ctime = mach_approximate_time();
		thread->last_made_runnable_time = thread->last_basepri_change_time = ctime;
		timer_start(&thread->runnable_timer, ctime);

		ready_for_runq = TRUE;

		if (old_thread_state & TH_WAIT_REPORT) {
			(*thread->sched_call)(SCHED_CALL_UNBLOCK, thread);
		}

		/* Update the runnable thread count */
		new_run_count = SCHED(run_count_incr)(thread);

#if CONFIG_SCHED_AUTO_JOIN
		if (aticontext == FALSE && work_interval_should_propagate(cthread, thread)) {
			work_interval_auto_join_propagate(cthread, thread);
		}
#endif /*CONFIG_SCHED_AUTO_JOIN */
	} else {
		/*
		 * Either the thread is idling in place on another processor,
		 * or it hasn't finished context switching yet.
		 */
		assert((thread->state & TH_IDLE) == 0);
		/*
		 * The run count is only dropped after the context switch completes
		 * and the thread is still waiting, so we should not run_incr here
		 */
		new_run_count = os_atomic_load(&sched_run_buckets[TH_BUCKET_RUN], relaxed);
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
	thread->block_hint = kThreadWaitNone;

	/* Obtain power-relevant interrupt and "platform-idle exit" statistics.
	 * We also account for "double hop" thread signaling via
	 * the thread callout infrastructure.
	 * DRK: consider removing the callout wakeup counters in the future
	 * they're present for verification at the moment.
	 */

	if (__improbable(aticontext && !(thread_get_tag_internal(thread) & THREAD_TAG_CALLOUT))) {
		DTRACE_SCHED2(iwakeup, struct thread *, thread, struct proc *, thread->task->bsd_info);

		uint64_t ttd = current_processor()->timer_call_ttd;

		if (ttd) {
			if (ttd <= timer_deadline_tracking_bin_1) {
				thread->thread_timer_wakeups_bin_1++;
			} else if (ttd <= timer_deadline_tracking_bin_2) {
				thread->thread_timer_wakeups_bin_2++;
			}
		}

		ledger_credit_thread(thread, thread->t_ledger,
		    task_ledgers.interrupt_wakeups, 1);
		if (pidle) {
			ledger_credit_thread(thread, thread->t_ledger,
			    task_ledgers.platform_idle_wakeups, 1);
		}
	} else if (thread_get_tag_internal(cthread) & THREAD_TAG_CALLOUT) {
		/* TODO: what about an interrupt that does a wake taken on a callout thread? */
		if (cthread->callout_woken_from_icontext) {
			ledger_credit_thread(thread, thread->t_ledger,
			    task_ledgers.interrupt_wakeups, 1);
			thread->thread_callout_interrupt_wakeups++;

			if (cthread->callout_woken_from_platform_idle) {
				ledger_credit_thread(thread, thread->t_ledger,
				    task_ledgers.platform_idle_wakeups, 1);
				thread->thread_callout_platform_idle_wakeups++;
			}

			cthread->callout_woke_thread = TRUE;
		}
	}

	if (thread_get_tag_internal(thread) & THREAD_TAG_CALLOUT) {
		thread->callout_woken_from_icontext = !!aticontext;
		thread->callout_woken_from_platform_idle = !!pidle;
		thread->callout_woke_thread = FALSE;
	}

#if KPERF
	if (ready_for_runq) {
		kperf_make_runnable(thread, aticontext);
	}
#endif /* KPERF */

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_SCHED, MACH_MAKE_RUNNABLE) | DBG_FUNC_NONE,
	    (uintptr_t)thread_tid(thread), thread->sched_pri, thread->wait_result,
	    sched_run_buckets[TH_BUCKET_RUN], 0);

	DTRACE_SCHED2(wakeup, struct thread *, thread, struct proc *, thread->task->bsd_info);

	return ready_for_runq;
}

/*
 *	Routine:	thread_allowed_for_handoff
 *	Purpose:
 *		Check if the thread is allowed for handoff operation
 *	Conditions:
 *		thread lock held, IPC locks may be held.
 *	TODO: In future, do not allow handoff if threads have different cluster
 *	recommendations.
 */
boolean_t
thread_allowed_for_handoff(
	thread_t         thread)
{
	thread_t self = current_thread();

	if (allow_direct_handoff &&
	    thread->sched_mode == TH_MODE_REALTIME &&
	    self->sched_mode == TH_MODE_REALTIME) {
		return TRUE;
	}

	return FALSE;
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
	wait_result_t   wresult,
	waitq_options_t option)
{
	thread_t self = current_thread();

	assert_thread_magic(thread);

	assert(thread->at_safe_point == FALSE);
	assert(thread->wait_event == NO_EVENT64);
	assert(thread->waitq == NULL);

	assert(!(thread->state & (TH_TERMINATE | TH_TERMINATE2)));
	assert(thread->state & TH_WAIT);


	if (thread_unblock(thread, wresult)) {
#if     SCHED_TRACE_THREAD_WAKEUPS
		backtrace(&thread->thread_wakeup_bt[0],
		    (sizeof(thread->thread_wakeup_bt) / sizeof(uintptr_t)), NULL);
#endif
		if ((option & WQ_OPTION_HANDOFF) &&
		    thread_allowed_for_handoff(thread)) {
			thread_reference(thread);
			assert(self->handoff_thread == NULL);
			self->handoff_thread = thread;
		} else {
			thread_setrun(thread, SCHED_PREEMPT | SCHED_TAILQ);
		}
	}

	return KERN_SUCCESS;
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
	thread_t                        thread,
	wait_interrupt_t        interruptible_orig)
{
	boolean_t                       at_safe_point;
	wait_interrupt_t        interruptible = interruptible_orig;

	if (thread->state & TH_IDLE) {
		panic("Invalid attempt to wait while running the idle thread");
	}

	assert(!(thread->state & (TH_WAIT | TH_IDLE | TH_UNINT | TH_TERMINATE2 | TH_WAIT_REPORT)));

	/*
	 *	The thread may have certain types of interrupts/aborts masked
	 *	off.  Even if the wait location says these types of interrupts
	 *	are OK, we have to honor mask settings (outer-scoped code may
	 *	not be able to handle aborts at the moment).
	 */
	interruptible &= TH_OPT_INTMASK;
	if (interruptible > (thread->options & TH_OPT_INTMASK)) {
		interruptible = thread->options & TH_OPT_INTMASK;
	}

	at_safe_point = (interruptible == THREAD_ABORTSAFE);

	if (interruptible == THREAD_UNINT ||
	    !(thread->sched_flags & TH_SFLAG_ABORT) ||
	    (!at_safe_point &&
	    (thread->sched_flags & TH_SFLAG_ABORTSAFELY))) {
		if (!(thread->state & TH_TERMINATE)) {
			DTRACE_SCHED(sleep);
		}

		int state_bits = TH_WAIT;
		if (!interruptible) {
			state_bits |= TH_UNINT;
		}
		if (thread->sched_call) {
			wait_interrupt_t mask = THREAD_WAIT_NOREPORT_USER;
			if (is_kerneltask(thread->task)) {
				mask = THREAD_WAIT_NOREPORT_KERNEL;
			}
			if ((interruptible_orig & mask) == 0) {
				state_bits |= TH_WAIT_REPORT;
			}
		}
		thread->state |= state_bits;
		thread->at_safe_point = at_safe_point;

		/* TODO: pass this through assert_wait instead, have
		 * assert_wait just take a struct as an argument */
		assert(!thread->block_hint);
		thread->block_hint = thread->pending_block_hint;
		thread->pending_block_hint = kThreadWaitNone;

		return thread->wait_result = THREAD_WAITING;
	} else {
		if (thread->sched_flags & TH_SFLAG_ABORTSAFELY) {
			thread->sched_flags &= ~TH_SFLAG_ABORTED_MASK;
		}
	}
	thread->pending_block_hint = kThreadWaitNone;

	return thread->wait_result = THREAD_INTERRUPTED;
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
 *	assert_wait:
 *
 *	Assert that the current thread is about to go to
 *	sleep until the specified event occurs.
 */
wait_result_t
assert_wait(
	event_t                         event,
	wait_interrupt_t        interruptible)
{
	if (__improbable(event == NO_EVENT)) {
		panic("%s() called with NO_EVENT", __func__);
	}

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_SCHED, MACH_WAIT) | DBG_FUNC_NONE,
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
	event_t                         event)
{
	return global_eventq(event);
}

wait_result_t
assert_wait_timeout(
	event_t                         event,
	wait_interrupt_t        interruptible,
	uint32_t                        interval,
	uint32_t                        scale_factor)
{
	thread_t                        thread = current_thread();
	wait_result_t           wresult;
	uint64_t                        deadline;
	spl_t                           s;

	if (__improbable(event == NO_EVENT)) {
		panic("%s() called with NO_EVENT", __func__);
	}

	struct waitq *waitq;
	waitq = global_eventq(event);

	s = splsched();
	waitq_lock(waitq);

	clock_interval_to_deadline(interval, scale_factor, &deadline);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_SCHED, MACH_WAIT) | DBG_FUNC_NONE,
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
	event_t                         event,
	wait_interrupt_t        interruptible,
	wait_timeout_urgency_t  urgency,
	uint32_t                        interval,
	uint32_t                        leeway,
	uint32_t                        scale_factor)
{
	thread_t                        thread = current_thread();
	wait_result_t           wresult;
	uint64_t                        deadline;
	uint64_t                        abstime;
	uint64_t                        slop;
	uint64_t                        now;
	spl_t                           s;

	if (__improbable(event == NO_EVENT)) {
		panic("%s() called with NO_EVENT", __func__);
	}

	now = mach_absolute_time();
	clock_interval_to_absolutetime_interval(interval, scale_factor, &abstime);
	deadline = now + abstime;

	clock_interval_to_absolutetime_interval(leeway, scale_factor, &slop);

	struct waitq *waitq;
	waitq = global_eventq(event);

	s = splsched();
	waitq_lock(waitq);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_SCHED, MACH_WAIT) | DBG_FUNC_NONE,
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
	event_t                         event,
	wait_interrupt_t        interruptible,
	uint64_t                        deadline)
{
	thread_t                        thread = current_thread();
	wait_result_t           wresult;
	spl_t                           s;

	if (__improbable(event == NO_EVENT)) {
		panic("%s() called with NO_EVENT", __func__);
	}

	struct waitq *waitq;
	waitq = global_eventq(event);

	s = splsched();
	waitq_lock(waitq);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_SCHED, MACH_WAIT) | DBG_FUNC_NONE,
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
	event_t                         event,
	wait_interrupt_t        interruptible,
	wait_timeout_urgency_t  urgency,
	uint64_t                        deadline,
	uint64_t                        leeway)
{
	thread_t                        thread = current_thread();
	wait_result_t           wresult;
	spl_t                           s;

	if (__improbable(event == NO_EVENT)) {
		panic("%s() called with NO_EVENT", __func__);
	}

	struct waitq *waitq;
	waitq = global_eventq(event);

	s = splsched();
	waitq_lock(waitq);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_SCHED, MACH_WAIT) | DBG_FUNC_NONE,
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
	if (!(thread->state & TH_RUN)) {
		return FALSE;
	}

	/* Waiting on a runqueue, not currently running */
	/* TODO: This is invalid - it can get dequeued without thread lock, but not context switched. */
	if (thread->runq != PROCESSOR_NULL) {
		return FALSE;
	}

	/*
	 * Thread does not have a stack yet
	 * It could be on the stack alloc queue or preparing to be invoked
	 */
	if (!thread->kernel_stack) {
		return FALSE;
	}

	/*
	 * Thread must be running on a processor, or
	 * about to run, or just did run. In all these
	 * cases, an AST to the processor is needed
	 * to guarantee that the thread is kicked out
	 * of userspace and the processor has
	 * context switched (and saved register state).
	 */
	return TRUE;
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
	thread_t                thread,
	boolean_t       until_not_runnable)
{
	wait_result_t   wresult;
	spl_t                   s = splsched();
	boolean_t               oncpu;

	wake_lock(thread);
	thread_lock(thread);

	while (thread->state & TH_SUSP) {
		thread->wake_active = TRUE;
		thread_unlock(thread);

		wresult = assert_wait(&thread->wake_active, THREAD_ABORTSAFE);
		wake_unlock(thread);
		splx(s);

		if (wresult == THREAD_WAITING) {
			wresult = thread_block(THREAD_CONTINUE_NULL);
		}

		if (wresult != THREAD_AWAKENED) {
			return FALSE;
		}

		s = splsched();
		wake_lock(thread);
		thread_lock(thread);
	}

	thread->state |= TH_SUSP;

	while ((oncpu = thread_isoncpu(thread)) ||
	    (until_not_runnable && (thread->state & TH_RUN))) {
		processor_t             processor;

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

		if (wresult == THREAD_WAITING) {
			wresult = thread_block(THREAD_CONTINUE_NULL);
		}

		if (wresult != THREAD_AWAKENED) {
			thread_unstop(thread);
			return FALSE;
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

	return TRUE;
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
	thread_t        thread)
{
	spl_t           s = splsched();

	wake_lock(thread);
	thread_lock(thread);

	assert((thread->state & (TH_RUN | TH_WAIT | TH_SUSP)) != TH_SUSP);

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
	thread_t        thread,
	boolean_t       until_not_runnable)
{
	wait_result_t   wresult;
	boolean_t       oncpu;
	processor_t     processor;
	spl_t           s = splsched();

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

		if (wresult == THREAD_WAITING) {
			thread_block(THREAD_CONTINUE_NULL);
		}

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
	thread_t                thread,
	wait_result_t   wresult)
{
	uint32_t        i = LockTimeOutUsec;
	struct waitq *waitq = thread->waitq;

	do {
		if (wresult == THREAD_INTERRUPTED && (thread->state & TH_UNINT)) {
			return KERN_FAILURE;
		}

		if (waitq != NULL) {
			if (!waitq_pull_thread_locked(waitq, thread)) {
				thread_unlock(thread);
				delay(1);
				if (i > 0 && !machine_timeout_suspended()) {
					i--;
				}
				thread_lock(thread);
				if (waitq != thread->waitq) {
					return KERN_NOT_WAITING;
				}
				continue;
			}
		}

		/* TODO: Can we instead assert TH_TERMINATE is not set?  */
		if ((thread->state & (TH_WAIT | TH_TERMINATE)) == TH_WAIT) {
			return thread_go(thread, wresult, WQ_OPTION_NONE);
		} else {
			return KERN_NOT_WAITING;
		}
	} while (i > 0);

	panic("clear_wait_internal: deadlock: thread=%p, wq=%p, cpu=%d\n",
	    thread, waitq, cpu_number());

	return KERN_FAILURE;
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
	thread_t                thread,
	wait_result_t   result)
{
	kern_return_t ret;
	spl_t           s;

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
	if (__improbable(event == NO_EVENT)) {
		panic("%s() called with NO_EVENT", __func__);
	}

	struct waitq *wq = global_eventq(event);

	if (one_thread) {
		return waitq_wakeup64_one(wq, CAST_EVENT64_T(event), result, WAITQ_ALL_PRIORITIES);
	} else {
		return waitq_wakeup64_all(wq, CAST_EVENT64_T(event), result, WAITQ_ALL_PRIORITIES);
	}
}

/*
 * Wakeup a specified thread if and only if it's waiting for this event
 */
kern_return_t
thread_wakeup_thread(
	event_t         event,
	thread_t        thread)
{
	if (__improbable(event == NO_EVENT)) {
		panic("%s() called with NO_EVENT", __func__);
	}

	if (__improbable(thread == THREAD_NULL)) {
		panic("%s() called with THREAD_NULL", __func__);
	}

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
	if (__improbable(event == NO_EVENT)) {
		panic("%s() called with NO_EVENT", __func__);
	}

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
	if (__improbable(event == NO_EVENT)) {
		panic("%s() called with NO_EVENT", __func__);
	}

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
	processor_t             processor)
{
	thread_t                self = current_thread();
	processor_t             prev;
	spl_t                   s;

	s = splsched();
	thread_lock(self);

	prev = thread_bind_internal(self, processor);

	thread_unlock(self);
	splx(s);

	return prev;
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
	thread_t                thread,
	processor_t             processor)
{
	processor_t             prev;

	/* <rdar://problem/15102234> */
	assert(thread->sched_pri < BASEPRI_RTQUEUES);
	/* A thread can't be bound if it's sitting on a (potentially incorrect) runqueue */
	assert(thread->runq == PROCESSOR_NULL);

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_THREAD_BIND), thread_tid(thread), processor ? (uintptr_t)processor->cpu_id : (uintptr_t)-1, 0, 0, 0);

	prev = thread->bound_processor;
	thread->bound_processor = processor;

	return prev;
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
decl_simple_lock_data(static, sched_vm_group_list_lock);
static thread_t sched_vm_group_thread_list[MAX_VM_BIND_GROUP_COUNT];
static int sched_vm_group_thread_count;
static boolean_t sched_vm_group_temporarily_unbound = FALSE;

void
thread_vm_bind_group_add(void)
{
	thread_t self = current_thread();

	thread_reference_internal(self);
	self->options |= TH_OPT_SCHED_VM_GROUP;

	simple_lock(&sched_vm_group_list_lock, LCK_GRP_NULL);
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
	simple_lock(&sched_vm_group_list_lock, LCK_GRP_NULL);

	s = splsched();

	for (i = 0; i < sched_vm_group_thread_count; i++) {
		thread_t thread = sched_vm_group_thread_list[i];
		assert(thread != THREAD_NULL);
		thread_lock(thread);
		if ((thread->state & (TH_RUN | TH_WAIT)) == TH_RUN) {
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
		for (i = 0; i < sched_vm_group_thread_count; i++) {
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

/* Invoked with pset locked, returns with pset unlocked */
void
sched_SMT_balance(processor_t cprocessor, processor_set_t cpset)
{
	processor_t ast_processor = NULL;

#if (DEVELOPMENT || DEBUG)
	if (__improbable(sched_smt_balance == 0)) {
		goto smt_balance_exit;
	}
#endif

	assert(cprocessor == current_processor());
	if (cprocessor->is_SMT == FALSE) {
		goto smt_balance_exit;
	}

	processor_t sib_processor = cprocessor->processor_secondary ? cprocessor->processor_secondary : cprocessor->processor_primary;

	/* Determine if both this processor and its sibling are idle,
	 * indicating an SMT rebalancing opportunity.
	 */
	if (sib_processor->state != PROCESSOR_IDLE) {
		goto smt_balance_exit;
	}

	processor_t sprocessor;

	sched_ipi_type_t ipi_type = SCHED_IPI_NONE;
	uint64_t running_secondary_map = (cpset->cpu_state_map[PROCESSOR_RUNNING] &
	    ~cpset->primary_map);
	for (int cpuid = lsb_first(running_secondary_map); cpuid >= 0; cpuid = lsb_next(running_secondary_map, cpuid)) {
		sprocessor = processor_array[cpuid];
		if ((sprocessor->processor_primary->state == PROCESSOR_RUNNING) &&
		    (sprocessor->current_pri < BASEPRI_RTQUEUES)) {
			ipi_type = sched_ipi_action(sprocessor, NULL, false, SCHED_IPI_EVENT_SMT_REBAL);
			if (ipi_type != SCHED_IPI_NONE) {
				assert(sprocessor != cprocessor);
				ast_processor = sprocessor;
				break;
			}
		}
	}

smt_balance_exit:
	pset_unlock(cpset);

	if (ast_processor) {
		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_SMT_BALANCE), ast_processor->cpu_id, ast_processor->state, ast_processor->processor_primary->state, 0, 0);
		sched_ipi_perform(ast_processor, ipi_type);
	}
}

static cpumap_t
pset_available_cpumap(processor_set_t pset)
{
	return (pset->cpu_state_map[PROCESSOR_IDLE] | pset->cpu_state_map[PROCESSOR_DISPATCHING] | pset->cpu_state_map[PROCESSOR_RUNNING]) &
	       pset->recommended_bitmask;
}

static cpumap_t
pset_available_but_not_running_cpumap(processor_set_t pset)
{
	return (pset->cpu_state_map[PROCESSOR_IDLE] | pset->cpu_state_map[PROCESSOR_DISPATCHING]) &
	       pset->recommended_bitmask;
}

bool
pset_has_stealable_threads(processor_set_t pset)
{
	pset_assert_locked(pset);

	cpumap_t avail_map = pset_available_but_not_running_cpumap(pset);
	/*
	 * Secondary CPUs never steal, so allow stealing of threads if there are more threads than
	 * available primary CPUs
	 */
	avail_map &= pset->primary_map;

	return (pset->pset_runq.count > 0) && ((pset->pset_runq.count + rt_runq_count(pset)) > bit_count(avail_map));
}

/*
 * Called with pset locked, on a processor that is committing to run a new thread
 * Will transition an idle or dispatching processor to running as it picks up
 * the first new thread from the idle thread.
 */
static void
pset_commit_processor_to_new_thread(processor_set_t pset, processor_t processor, thread_t new_thread)
{
	pset_assert_locked(pset);

	if (processor->state == PROCESSOR_DISPATCHING || processor->state == PROCESSOR_IDLE) {
		assert(current_thread() == processor->idle_thread);

		/*
		 * Dispatching processor is now committed to running new_thread,
		 * so change its state to PROCESSOR_RUNNING.
		 */
		pset_update_processor_state(pset, processor, PROCESSOR_RUNNING);
	} else {
		assert((processor->state == PROCESSOR_RUNNING) || (processor->state == PROCESSOR_SHUTDOWN));
	}

	processor_state_update_from_thread(processor, new_thread);

	if (new_thread->sched_pri >= BASEPRI_RTQUEUES) {
		bit_set(pset->realtime_map, processor->cpu_id);
	} else {
		bit_clear(pset->realtime_map, processor->cpu_id);
	}

	pset_node_t node = pset->node;

	if (bit_count(node->pset_map) == 1) {
		/* Node has only a single pset, so skip node pset map updates */
		return;
	}

	cpumap_t avail_map = pset_available_cpumap(pset);

	if (new_thread->sched_pri >= BASEPRI_RTQUEUES) {
		if ((avail_map & pset->realtime_map) == avail_map) {
			/* No more non-RT CPUs in this pset */
			atomic_bit_clear(&node->pset_non_rt_map, pset->pset_id, memory_order_relaxed);
		}
		avail_map &= pset->primary_map;
		if ((avail_map & pset->realtime_map) == avail_map) {
			/* No more non-RT primary CPUs in this pset */
			atomic_bit_clear(&node->pset_non_rt_primary_map, pset->pset_id, memory_order_relaxed);
		}
	} else {
		if ((avail_map & pset->realtime_map) != avail_map) {
			if (!bit_test(atomic_load(&node->pset_non_rt_map), pset->pset_id)) {
				atomic_bit_set(&node->pset_non_rt_map, pset->pset_id, memory_order_relaxed);
			}
		}
		avail_map &= pset->primary_map;
		if ((avail_map & pset->realtime_map) != avail_map) {
			if (!bit_test(atomic_load(&node->pset_non_rt_primary_map), pset->pset_id)) {
				atomic_bit_set(&node->pset_non_rt_primary_map, pset->pset_id, memory_order_relaxed);
			}
		}
	}
}

static processor_t choose_processor_for_realtime_thread(processor_set_t pset, processor_t skip_processor, bool consider_secondaries);
static bool all_available_primaries_are_running_realtime_threads(processor_set_t pset);
#if defined(__x86_64__)
static bool these_processors_are_running_realtime_threads(processor_set_t pset, uint64_t these_map);
#endif
static bool sched_ok_to_run_realtime_thread(processor_set_t pset, processor_t processor);
static bool processor_is_fast_track_candidate_for_realtime_thread(processor_set_t pset, processor_t processor);
int sched_allow_rt_smt = 1;
int sched_avoid_cpu0 = 1;

/*
 *	thread_select:
 *
 *	Select a new thread for the current processor to execute.
 *
 *	May select the current thread, which must be locked.
 */
static thread_t
thread_select(thread_t          thread,
    processor_t       processor,
    ast_t            *reason)
{
	processor_set_t         pset = processor->processor_set;
	thread_t                        new_thread = THREAD_NULL;

	assert(processor == current_processor());
	assert((thread->state & (TH_RUN | TH_TERMINATE2)) == TH_RUN);

	do {
		/*
		 *	Update the priority.
		 */
		if (SCHED(can_update_priority)(thread)) {
			SCHED(update_priority)(thread);
		}

		pset_lock(pset);

		processor_state_update_from_thread(processor, thread);

restart:
		/* Acknowledge any pending IPIs here with pset lock held */
		bit_clear(pset->pending_AST_URGENT_cpu_mask, processor->cpu_id);
		bit_clear(pset->pending_AST_PREEMPT_cpu_mask, processor->cpu_id);

#if defined(CONFIG_SCHED_DEFERRED_AST)
		bit_clear(pset->pending_deferred_AST_cpu_mask, processor->cpu_id);
#endif

		bool secondary_can_only_run_realtime_thread = false;

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
			if (!SCHED(processor_bound_count)(processor)) {
				if ((pset->recommended_bitmask & pset->primary_map & pset->cpu_state_map[PROCESSOR_IDLE]) != 0) {
					goto idle;
				}

				/*
				 * TODO: What if a secondary core beat an idle primary to waking up from an IPI?
				 * Should it dequeue immediately, or spin waiting for the primary to wake up?
				 */

				/* There are no idle primaries */

				if (processor->processor_primary->current_pri >= BASEPRI_RTQUEUES) {
					bool secondary_can_run_realtime_thread = sched_allow_rt_smt && rt_runq_count(pset) && all_available_primaries_are_running_realtime_threads(pset);
					if (!secondary_can_run_realtime_thread) {
						goto idle;
					}
					secondary_can_only_run_realtime_thread = true;
				}
			}
		}

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

		/* i.e. not waiting, not TH_SUSP'ed */
		bool still_running = ((thread->state & (TH_TERMINATE | TH_IDLE | TH_WAIT | TH_RUN | TH_SUSP)) == TH_RUN);

		/*
		 * Threads running on SMT processors are forced to context switch. Don't rebalance realtime threads.
		 * TODO: This should check if it's worth it to rebalance, i.e. 'are there any idle primary processors'
		 *       <rdar://problem/47907700>
		 *
		 * A yielding thread shouldn't be forced to context switch.
		 */

		bool is_yielding         = (*reason & AST_YIELD) == AST_YIELD;

		bool needs_smt_rebalance = !is_yielding && thread->sched_pri < BASEPRI_RTQUEUES && processor->processor_primary != processor;

		bool affinity_mismatch   = thread->affinity_set != AFFINITY_SET_NULL && thread->affinity_set->aset_pset != pset;

		bool bound_elsewhere     = thread->bound_processor != PROCESSOR_NULL && thread->bound_processor != processor;

		bool avoid_processor     = !is_yielding && SCHED(avoid_processor_enabled) && SCHED(thread_avoid_processor)(processor, thread);

		if (still_running && !needs_smt_rebalance && !affinity_mismatch && !bound_elsewhere && !avoid_processor) {
			/*
			 * This thread is eligible to keep running on this processor.
			 *
			 * RT threads with un-expired quantum stay on processor,
			 * unless there's a valid RT thread with an earlier deadline.
			 */
			if (thread->sched_pri >= BASEPRI_RTQUEUES && processor->first_timeslice) {
				if (rt_runq_count(pset) > 0) {
					thread_t next_rt = qe_queue_first(&SCHED(rt_runq)(pset)->queue, struct thread, runq_links);

					if (next_rt->realtime.deadline < processor->deadline &&
					    (next_rt->bound_processor == PROCESSOR_NULL ||
					    next_rt->bound_processor == processor)) {
						/* The next RT thread is better, so pick it off the runqueue. */
						goto pick_new_rt_thread;
					}
				}

				/* This is still the best RT thread to run. */
				processor->deadline = thread->realtime.deadline;

				sched_update_pset_load_average(pset, 0);

				processor_t next_rt_processor = PROCESSOR_NULL;
				sched_ipi_type_t next_rt_ipi_type = SCHED_IPI_NONE;

				if (rt_runq_count(pset) - bit_count(pset->pending_AST_URGENT_cpu_mask) > 0) {
					next_rt_processor = choose_processor_for_realtime_thread(pset, processor, true);
					if (next_rt_processor) {
						SCHED_DEBUG_CHOOSE_PROCESSOR_KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_CHOOSE_PROCESSOR) | DBG_FUNC_NONE,
						    (uintptr_t)0, (uintptr_t)-4, next_rt_processor->cpu_id, next_rt_processor->state, 0);
						if (next_rt_processor->state == PROCESSOR_IDLE) {
							pset_update_processor_state(pset, next_rt_processor, PROCESSOR_DISPATCHING);
						}
						next_rt_ipi_type = sched_ipi_action(next_rt_processor, NULL, false, SCHED_IPI_EVENT_PREEMPT);
					}
				}
				pset_unlock(pset);

				if (next_rt_processor) {
					sched_ipi_perform(next_rt_processor, next_rt_ipi_type);
				}

				return thread;
			}

			if ((rt_runq_count(pset) == 0) &&
			    SCHED(processor_queue_has_priority)(processor, thread->sched_pri, TRUE) == FALSE) {
				/* This thread is still the highest priority runnable (non-idle) thread */
				processor->deadline = UINT64_MAX;

				sched_update_pset_load_average(pset, 0);
				pset_unlock(pset);

				return thread;
			}
		} else {
			/*
			 * This processor must context switch.
			 * If it's due to a rebalance, we should aggressively find this thread a new home.
			 */
			if (needs_smt_rebalance || affinity_mismatch || bound_elsewhere || avoid_processor) {
				*reason |= AST_REBALANCE;
			}
		}

		/* OK, so we're not going to run the current thread. Look at the RT queue. */
		bool ok_to_run_realtime_thread = sched_ok_to_run_realtime_thread(pset, processor);
		if ((rt_runq_count(pset) > 0) && ok_to_run_realtime_thread) {
			thread_t next_rt = qe_queue_first(&SCHED(rt_runq)(pset)->queue, struct thread, runq_links);

			if (__probable((next_rt->bound_processor == PROCESSOR_NULL ||
			    (next_rt->bound_processor == processor)))) {
pick_new_rt_thread:
				new_thread = qe_dequeue_head(&SCHED(rt_runq)(pset)->queue, struct thread, runq_links);

				new_thread->runq = PROCESSOR_NULL;
				SCHED_STATS_RUNQ_CHANGE(&SCHED(rt_runq)(pset)->runq_stats, rt_runq_count(pset));
				rt_runq_count_decr(pset);

				processor->deadline = new_thread->realtime.deadline;

				pset_commit_processor_to_new_thread(pset, processor, new_thread);

				sched_update_pset_load_average(pset, 0);

				processor_t ast_processor = PROCESSOR_NULL;
				processor_t next_rt_processor = PROCESSOR_NULL;
				sched_ipi_type_t ipi_type = SCHED_IPI_NONE;
				sched_ipi_type_t next_rt_ipi_type = SCHED_IPI_NONE;

				if (processor->processor_secondary != NULL) {
					processor_t sprocessor = processor->processor_secondary;
					if ((sprocessor->state == PROCESSOR_RUNNING) || (sprocessor->state == PROCESSOR_DISPATCHING)) {
						ipi_type = sched_ipi_action(sprocessor, NULL, false, SCHED_IPI_EVENT_SMT_REBAL);
						ast_processor = sprocessor;
					}
				}
				if (rt_runq_count(pset) - bit_count(pset->pending_AST_URGENT_cpu_mask) > 0) {
					next_rt_processor = choose_processor_for_realtime_thread(pset, processor, true);
					if (next_rt_processor) {
						SCHED_DEBUG_CHOOSE_PROCESSOR_KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_CHOOSE_PROCESSOR) | DBG_FUNC_NONE,
						    (uintptr_t)0, (uintptr_t)-5, next_rt_processor->cpu_id, next_rt_processor->state, 0);
						if (next_rt_processor->state == PROCESSOR_IDLE) {
							pset_update_processor_state(pset, next_rt_processor, PROCESSOR_DISPATCHING);
						}
						next_rt_ipi_type = sched_ipi_action(next_rt_processor, NULL, false, SCHED_IPI_EVENT_PREEMPT);
					}
				}
				pset_unlock(pset);

				if (ast_processor) {
					sched_ipi_perform(ast_processor, ipi_type);
				}

				if (next_rt_processor) {
					sched_ipi_perform(next_rt_processor, next_rt_ipi_type);
				}

				return new_thread;
			}
		}
		if (secondary_can_only_run_realtime_thread) {
			goto idle;
		}

		processor->deadline = UINT64_MAX;

		/* No RT threads, so let's look at the regular threads. */
		if ((new_thread = SCHED(choose_thread)(processor, MINPRI, *reason)) != THREAD_NULL) {
			pset_commit_processor_to_new_thread(pset, processor, new_thread);
			sched_update_pset_load_average(pset, 0);

			processor_t ast_processor = PROCESSOR_NULL;
			sched_ipi_type_t ipi_type = SCHED_IPI_NONE;

			processor_t sprocessor = processor->processor_secondary;
			if ((sprocessor != NULL) && (sprocessor->state == PROCESSOR_RUNNING)) {
				if (thread_no_smt(new_thread)) {
					ipi_type = sched_ipi_action(sprocessor, NULL, false, SCHED_IPI_EVENT_SMT_REBAL);
					ast_processor = sprocessor;
				}
			}
			pset_unlock(pset);

			if (ast_processor) {
				sched_ipi_perform(ast_processor, ipi_type);
			}
			return new_thread;
		}

		if (processor->must_idle) {
			processor->must_idle = false;
			goto idle;
		}

		if (SCHED(steal_thread_enabled)(pset) && (processor->processor_primary == processor)) {
			/*
			 * No runnable threads, attempt to steal
			 * from other processors. Returns with pset lock dropped.
			 */

			if ((new_thread = SCHED(steal_thread)(pset)) != THREAD_NULL) {
				/*
				 * Avoid taking the pset_lock unless it is necessary to change state.
				 * It's safe to read processor->state here, as only the current processor can change state
				 * from this point (interrupts are disabled and this processor is committed to run new_thread).
				 */
				if (processor->state == PROCESSOR_DISPATCHING || processor->state == PROCESSOR_IDLE) {
					pset_lock(pset);
					pset_commit_processor_to_new_thread(pset, processor, new_thread);
					pset_unlock(pset);
				} else {
					assert((processor->state == PROCESSOR_RUNNING) || (processor->state == PROCESSOR_SHUTDOWN));
					processor_state_update_from_thread(processor, new_thread);
				}

				return new_thread;
			}

			/*
			 * If other threads have appeared, shortcut
			 * around again.
			 */
			if (!SCHED(processor_queue_empty)(processor) || (ok_to_run_realtime_thread && (rt_runq_count(pset) > 0))) {
				continue;
			}

			pset_lock(pset);

			/* Someone selected this processor while we had dropped the lock */
			if (bit_test(pset->pending_AST_URGENT_cpu_mask, processor->cpu_id)) {
				goto restart;
			}
		}

idle:
		/*
		 *	Nothing is runnable, so set this processor idle if it
		 *	was running.
		 */
		if ((processor->state == PROCESSOR_RUNNING) || (processor->state == PROCESSOR_DISPATCHING)) {
			pset_update_processor_state(pset, processor, PROCESSOR_IDLE);
			processor_state_update_idle(processor);
		}

		/* Invoked with pset locked, returns with pset unlocked */
		SCHED(processor_balance)(processor, pset);

		new_thread = processor->idle_thread;
	} while (new_thread == THREAD_NULL);

	return new_thread;
}

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
	thread_t                        self,
	thread_t                        thread,
	ast_t                           reason)
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
	if (!((thread->state & TH_IDLE) != 0 ||
	    ((reason & AST_HANDOFF) && self->sched_mode == TH_MODE_REALTIME))) {
		sched_timeshare_consider_maintenance(ctime);
	}
#endif

#if MONOTONIC
	mt_sched_update(self);
#endif /* MONOTONIC */

	assert_thread_magic(self);
	assert(self == current_thread());
	assert(self->runq == PROCESSOR_NULL);
	assert((self->state & (TH_RUN | TH_TERMINATE2)) == TH_RUN);

	thread_lock(thread);

	assert_thread_magic(thread);
	assert((thread->state & (TH_RUN | TH_WAIT | TH_UNINT | TH_TERMINATE | TH_TERMINATE2)) == TH_RUN);
	assert(thread->bound_processor == PROCESSOR_NULL || thread->bound_processor == current_processor());
	assert(thread->runq == PROCESSOR_NULL);

	/* Reload precise timing global policy to thread-local policy */
	thread->precise_user_kernel_time = use_precise_user_kernel_time(thread);

	/* Update SFI class based on other factors */
	thread->sfi_class = sfi_thread_classify(thread);

	/* Update the same_pri_latency for the thread (used by perfcontrol callouts) */
	thread->same_pri_latency = ctime - thread->last_basepri_change_time;
	/*
	 * In case a base_pri update happened between the timestamp and
	 * taking the thread lock
	 */
	if (ctime <= thread->last_basepri_change_time) {
		thread->same_pri_latency = ctime - thread->last_made_runnable_time;
	}

	/* Allow realtime threads to hang onto a stack. */
	if ((self->sched_mode == TH_MODE_REALTIME) && !self->reserved_stack) {
		self->reserved_stack = self->kernel_stack;
	}

	/* Prepare for spin debugging */
#if INTERRUPT_MASKED_DEBUG
	ml_spin_debug_clear(thread);
#endif

	if (continuation != NULL) {
		if (!thread->kernel_stack) {
			/*
			 * If we are using a privileged stack,
			 * check to see whether we can exchange it with
			 * that of the other thread.
			 */
			if (self->kernel_stack == self->reserved_stack && !thread->reserved_stack) {
				goto need_stack;
			}

			/*
			 * Context switch by performing a stack handoff.
			 * Requires both threads to be parked in a continuation.
			 */
			continuation = thread->continuation;
			parameter = thread->parameter;

			processor = current_processor();
			processor->active_thread = thread;
			processor_state_update_from_thread(processor, thread);

			if (thread->last_processor != processor && thread->last_processor != NULL) {
				if (thread->last_processor->processor_set != processor->processor_set) {
					thread->ps_switch++;
				}
				thread->p_switch++;
			}
			thread->last_processor = processor;
			thread->c_switch++;
			ast_context(thread);

			thread_unlock(thread);

			self->reason = reason;

			processor->last_dispatch = ctime;
			self->last_run_time = ctime;
			processor_timer_switch_thread(ctime, &thread->system_timer);
			timer_update(&thread->runnable_timer, ctime);
			processor->kernel_timer = &thread->system_timer;

			/*
			 * Since non-precise user/kernel time doesn't update the state timer
			 * during privilege transitions, synthesize an event now.
			 */
			if (!thread->precise_user_kernel_time) {
				timer_update(processor->current_state, ctime);
			}

			KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
			    MACHDBG_CODE(DBG_MACH_SCHED, MACH_STACK_HANDOFF) | DBG_FUNC_NONE,
			    self->reason, (uintptr_t)thread_tid(thread), self->sched_pri, thread->sched_pri, 0);

			if ((thread->chosen_processor != processor) && (thread->chosen_processor != PROCESSOR_NULL)) {
				SCHED_DEBUG_CHOOSE_PROCESSOR_KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_MOVED) | DBG_FUNC_NONE,
				    (uintptr_t)thread_tid(thread), (uintptr_t)thread->chosen_processor->cpu_id, 0, 0, 0);
			}

			DTRACE_SCHED2(off__cpu, struct thread *, thread, struct proc *, thread->task->bsd_info);

			SCHED_STATS_CSW(processor, self->reason, self->sched_pri, thread->sched_pri);

#if KPERF
			kperf_off_cpu(self);
#endif /* KPERF */

			/*
			 * This is where we actually switch thread identity,
			 * and address space if required.  However, register
			 * state is not switched - this routine leaves the
			 * stack and register state active on the current CPU.
			 */
			TLOG(1, "thread_invoke: calling stack_handoff\n");
			stack_handoff(self, thread);

			/* 'self' is now off core */
			assert(thread == current_thread_volatile());

			DTRACE_SCHED(on__cpu);

#if KPERF
			kperf_on_cpu(thread, continuation, NULL);
#endif /* KPERF */

			thread_dispatch(self, thread);

#if KASAN
			/* Old thread's stack has been moved to the new thread, so explicitly
			 * unpoison it. */
			kasan_unpoison_stack(thread->kernel_stack, kernel_stack_size);
#endif

			thread->continuation = thread->parameter = NULL;

			counter(c_thread_invoke_hits++);

			boolean_t enable_interrupts = TRUE;

			/* idle thread needs to stay interrupts-disabled */
			if ((thread->state & TH_IDLE)) {
				enable_interrupts = FALSE;
			}

			assert(continuation);
			call_continuation(continuation, parameter,
			    thread->wait_result, enable_interrupts);
			/*NOTREACHED*/
		} else if (thread == self) {
			/* same thread but with continuation */
			ast_context(self);
			counter(++c_thread_invoke_same);

			thread_unlock(self);

#if KPERF
			kperf_on_cpu(thread, continuation, NULL);
#endif /* KPERF */

			KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
			    MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED) | DBG_FUNC_NONE,
			    self->reason, (uintptr_t)thread_tid(thread), self->sched_pri, thread->sched_pri, 0);

#if KASAN
			/* stack handoff to self - no thread_dispatch(), so clear the stack
			 * and free the fakestack directly */
			kasan_fakestack_drop(self);
			kasan_fakestack_gc(self);
			kasan_unpoison_stack(self->kernel_stack, kernel_stack_size);
#endif

			self->continuation = self->parameter = NULL;

			boolean_t enable_interrupts = TRUE;

			/* idle thread needs to stay interrupts-disabled */
			if ((self->state & TH_IDLE)) {
				enable_interrupts = FALSE;
			}

			call_continuation(continuation, parameter,
			    self->wait_result, enable_interrupts);
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
				return FALSE;
			}
		} else if (thread == self) {
			ast_context(self);
			counter(++c_thread_invoke_same);
			thread_unlock(self);

			KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
			    MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED) | DBG_FUNC_NONE,
			    self->reason, (uintptr_t)thread_tid(thread), self->sched_pri, thread->sched_pri, 0);

			return TRUE;
		}
	}

	/*
	 * Context switch by full context save.
	 */
	processor = current_processor();
	processor->active_thread = thread;
	processor_state_update_from_thread(processor, thread);

	if (thread->last_processor != processor && thread->last_processor != NULL) {
		if (thread->last_processor->processor_set != processor->processor_set) {
			thread->ps_switch++;
		}
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
	processor_timer_switch_thread(ctime, &thread->system_timer);
	timer_update(&thread->runnable_timer, ctime);
	processor->kernel_timer = &thread->system_timer;

	/*
	 * Since non-precise user/kernel time doesn't update the state timer
	 * during privilege transitions, synthesize an event now.
	 */
	if (!thread->precise_user_kernel_time) {
		timer_update(processor->current_state, ctime);
	}

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED) | DBG_FUNC_NONE,
	    self->reason, (uintptr_t)thread_tid(thread), self->sched_pri, thread->sched_pri, 0);

	if ((thread->chosen_processor != processor) && (thread->chosen_processor != NULL)) {
		SCHED_DEBUG_CHOOSE_PROCESSOR_KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_MOVED) | DBG_FUNC_NONE,
		    (uintptr_t)thread_tid(thread), (uintptr_t)thread->chosen_processor->cpu_id, 0, 0, 0);
	}

	DTRACE_SCHED2(off__cpu, struct thread *, thread, struct proc *, thread->task->bsd_info);

	SCHED_STATS_CSW(processor, self->reason, self->sched_pri, thread->sched_pri);

#if KPERF
	kperf_off_cpu(self);
#endif /* KPERF */

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
	 *
	 * If one of the threads is using a continuation, thread_continue
	 * is used to stitch up its context.
	 *
	 * If we are invoking a thread which is resuming from a continuation,
	 * the CPU will invoke thread_continue next.
	 *
	 * If the current thread is parking in a continuation, then its state
	 * won't be saved and the stack will be discarded. When the stack is
	 * re-allocated, it will be configured to resume from thread_continue.
	 */
	assert(continuation == self->continuation);
	thread = machine_switch_context(self, continuation, thread);
	assert(self == current_thread_volatile());
	TLOG(1, "thread_invoke: returning machine_switch_context: self %p continuation %p thread %p\n", self, continuation, thread);

	assert(continuation == NULL && self->continuation == NULL);

	DTRACE_SCHED(on__cpu);

#if KPERF
	kperf_on_cpu(self, NULL, __builtin_frame_address(0));
#endif /* KPERF */

	/* We have been resumed and are set to run. */
	thread_dispatch(thread, self);

	return TRUE;
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
	processor_set_t         pset,
	processor_t             processor)
{
	processor_t             active_processor = NULL;
	uint32_t                sampled_sched_run_count;

	pset_lock(pset);
	sampled_sched_run_count = os_atomic_load(&sched_run_buckets[TH_BUCKET_RUN], relaxed);

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
	 */

	if ((sampled_sched_run_count == 1) && (pset->pending_deferred_AST_cpu_mask)) {
		uint64_t dispatching_map = (pset->cpu_state_map[PROCESSOR_DISPATCHING] &
		    pset->pending_deferred_AST_cpu_mask &
		    ~pset->pending_AST_URGENT_cpu_mask);
		for (int cpuid = lsb_first(dispatching_map); cpuid >= 0; cpuid = lsb_next(dispatching_map, cpuid)) {
			active_processor = processor_array[cpuid];
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
			if (active_processor != processor) {
				/*
				 * Squash all of the processor state back to some
				 * reasonable facsimile of PROCESSOR_IDLE.
				 */

				processor_state_update_idle(active_processor);
				active_processor->deadline = UINT64_MAX;
				pset_update_processor_state(pset, active_processor, PROCESSOR_IDLE);
				bit_clear(pset->pending_deferred_AST_cpu_mask, active_processor->cpu_id);
				machine_signal_idle_cancel(active_processor);
			}
		}
	}

	pset_unlock(pset);
}
#else
/* We don't support deferred ASTs; everything is candycanes and sunshine. */
#endif

static void
thread_csw_callout(
	thread_t            old,
	thread_t            new,
	uint64_t            timestamp)
{
	perfcontrol_event event = (new->state & TH_IDLE) ? IDLE : CONTEXT_SWITCH;
	uint64_t same_pri_latency = (new->state & TH_IDLE) ? 0 : new->same_pri_latency;
	machine_switch_perfcontrol_context(event, timestamp, 0,
	    same_pri_latency, old, new);
}


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
 *
 */
void
thread_dispatch(
	thread_t                thread,
	thread_t                self)
{
	processor_t             processor = self->last_processor;
	bool was_idle = false;

	assert(processor == current_processor());
	assert(self == current_thread_volatile());
	assert(thread != self);

	if (thread != THREAD_NULL) {
		/*
		 * Do the perfcontrol callout for context switch.
		 * The reason we do this here is:
		 * - thread_dispatch() is called from various places that are not
		 *   the direct context switch path for eg. processor shutdown etc.
		 *   So adding the callout here covers all those cases.
		 * - We want this callout as early as possible to be close
		 *   to the timestamp taken in thread_invoke()
		 * - We want to avoid holding the thread lock while doing the
		 *   callout
		 * - We do not want to callout if "thread" is NULL.
		 */
		thread_csw_callout(thread, self, processor->last_dispatch);

#if KASAN
		if (thread->continuation != NULL) {
			/*
			 * Thread has a continuation and the normal stack is going away.
			 * Unpoison the stack and mark all fakestack objects as unused.
			 */
			kasan_fakestack_drop(thread);
			if (thread->kernel_stack) {
				kasan_unpoison_stack(thread->kernel_stack, kernel_stack_size);
			}
		}

		/*
		 * Free all unused fakestack objects.
		 */
		kasan_fakestack_gc(thread);
#endif

		/*
		 *	If blocked at a continuation, discard
		 *	the stack.
		 */
		if (thread->continuation != NULL && thread->kernel_stack != 0) {
			stack_free(thread);
		}

		if (thread->state & TH_IDLE) {
			was_idle = true;
			KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
			    MACHDBG_CODE(DBG_MACH_SCHED, MACH_DISPATCH) | DBG_FUNC_NONE,
			    (uintptr_t)thread_tid(thread), 0, thread->state,
			    sched_run_buckets[TH_BUCKET_RUN], 0);
		} else {
			int64_t consumed;
			int64_t remainder = 0;

			if (processor->quantum_end > processor->last_dispatch) {
				remainder = processor->quantum_end -
				    processor->last_dispatch;
			}

			consumed = thread->quantum_remaining - remainder;

			if ((thread->reason & AST_LEDGER) == 0) {
				/*
				 * Bill CPU time to both the task and
				 * the individual thread.
				 */
				ledger_credit_thread(thread, thread->t_ledger,
				    task_ledgers.cpu_time, consumed);
				ledger_credit_thread(thread, thread->t_threadledger,
				    thread_ledgers.cpu_time, consumed);
				if (thread->t_bankledger) {
					ledger_credit_thread(thread, thread->t_bankledger,
					    bank_ledgers.cpu_time,
					    (consumed - thread->t_deduct_bank_ledger_time));
				}
				thread->t_deduct_bank_ledger_time = 0;
				if (consumed > 0) {
					/*
					 * This should never be negative, but in traces we are seeing some instances
					 * of consumed being negative.
					 * <rdar://problem/57782596> thread_dispatch() thread CPU consumed calculation sometimes results in negative value
					 */
					sched_update_pset_avg_execution_time(current_processor()->processor_set, consumed, processor->last_dispatch, thread->th_sched_bucket);
				}
			}

			wake_lock(thread);
			thread_lock(thread);

			/*
			 * Apply a priority floor if the thread holds a kernel resource
			 * Do this before checking starting_pri to avoid overpenalizing
			 * repeated rwlock blockers.
			 */
			if (__improbable(thread->rwlock_count != 0)) {
				lck_rw_set_promotion_locked(thread);
			}

			boolean_t keep_quantum = processor->first_timeslice;

			/*
			 * Treat a thread which has dropped priority since it got on core
			 * as having expired its quantum.
			 */
			if (processor->starting_pri > thread->sched_pri) {
				keep_quantum = FALSE;
			}

			/* Compute remainder of current quantum. */
			if (keep_quantum &&
			    processor->quantum_end > processor->last_dispatch) {
				thread->quantum_remaining = (uint32_t)remainder;
			} else {
				thread->quantum_remaining = 0;
			}

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
			if ((thread->reason & (AST_HANDOFF | AST_QUANTUM)) == AST_HANDOFF) {
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
				thread->last_made_runnable_time = thread->last_basepri_change_time = processor->last_dispatch;

				machine_thread_going_off_core(thread, FALSE, processor->last_dispatch, TRUE);

				ast_t reason = thread->reason;
				sched_options_t options = SCHED_NONE;

				if (reason & AST_REBALANCE) {
					options |= SCHED_REBALANCE;
					if (reason & AST_QUANTUM) {
						/*
						 * Having gone to the trouble of forcing this thread off a less preferred core,
						 * we should force the preferable core to reschedule immediately to give this
						 * thread a chance to run instead of just sitting on the run queue where
						 * it may just be stolen back by the idle core we just forced it off.
						 * But only do this at the end of a quantum to prevent cascading effects.
						 */
						options |= SCHED_PREEMPT;
					}
				}

				if (reason & AST_QUANTUM) {
					options |= SCHED_TAILQ;
				} else if (reason & AST_PREEMPT) {
					options |= SCHED_HEADQ;
				} else {
					options |= (SCHED_PREEMPT | SCHED_TAILQ);
				}

				thread_setrun(thread, options);

				KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				    MACHDBG_CODE(DBG_MACH_SCHED, MACH_DISPATCH) | DBG_FUNC_NONE,
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
				int thread_state = thread->state;

				/* Only the first call to thread_dispatch
				 * after explicit termination should add
				 * the thread to the termination queue
				 */
				if ((thread_state & (TH_TERMINATE | TH_TERMINATE2)) == TH_TERMINATE) {
					should_terminate = TRUE;
					thread_state |= TH_TERMINATE2;
				}

				timer_stop(&thread->runnable_timer, processor->last_dispatch);

				thread_state &= ~TH_RUN;
				thread->state = thread_state;

				thread->last_made_runnable_time = thread->last_basepri_change_time = THREAD_NOT_RUNNABLE;
				thread->chosen_processor = PROCESSOR_NULL;

				new_run_count = SCHED(run_count_decr)(thread);

#if CONFIG_SCHED_AUTO_JOIN
				if ((thread->sched_flags & TH_SFLAG_THREAD_GROUP_AUTO_JOIN) != 0) {
					work_interval_auto_join_unwind(thread);
				}
#endif /* CONFIG_SCHED_AUTO_JOIN */

#if CONFIG_SCHED_SFI
				if (thread->reason & AST_SFI) {
					thread->wait_sfi_begin_time = processor->last_dispatch;
				}
#endif
				machine_thread_going_off_core(thread, should_terminate, processor->last_dispatch, FALSE);

				KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				    MACHDBG_CODE(DBG_MACH_SCHED, MACH_DISPATCH) | DBG_FUNC_NONE,
				    (uintptr_t)thread_tid(thread), thread->reason, thread_state,
				    new_run_count, 0);

				if (thread_state & TH_WAIT_REPORT) {
					(*thread->sched_call)(SCHED_CALL_BLOCK, thread);
				}

				if (thread->wake_active) {
					thread->wake_active = FALSE;
					thread_unlock(thread);

					thread_wakeup(&thread->wake_active);
				} else {
					thread_unlock(thread);
				}

				wake_unlock(thread);

				if (should_terminate) {
					thread_terminate_enqueue(thread);
				}
			}
		}
		/*
		 * The thread could have been added to the termination queue, so it's
		 * unsafe to use after this point.
		 */
		thread = THREAD_NULL;
	}

	int urgency = THREAD_URGENCY_NONE;
	uint64_t latency = 0;

	/* Update (new) current thread and reprogram running timers */
	thread_lock(self);

	if (!(self->state & TH_IDLE)) {
		uint64_t        arg1, arg2;

#if CONFIG_SCHED_SFI
		ast_t                   new_ast;

		new_ast = sfi_thread_needs_ast(self, NULL);

		if (new_ast != AST_NONE) {
			ast_on(new_ast);
		}
#endif

		assertf(processor->last_dispatch >= self->last_made_runnable_time,
		    "Non-monotonic time? dispatch at 0x%llx, runnable at 0x%llx",
		    processor->last_dispatch, self->last_made_runnable_time);

		assert(self->last_made_runnable_time <= self->last_basepri_change_time);

		latency = processor->last_dispatch - self->last_made_runnable_time;
		assert(latency >= self->same_pri_latency);

		urgency = thread_get_urgency(self, &arg1, &arg2);

		thread_tell_urgency(urgency, arg1, arg2, latency, self);

		/*
		 *	Get a new quantum if none remaining.
		 */
		if (self->quantum_remaining == 0) {
			thread_quantum_init(self);
		}

		/*
		 *	Set up quantum timer and timeslice.
		 */
		processor->quantum_end = processor->last_dispatch +
		    self->quantum_remaining;

		running_timer_setup(processor, RUNNING_TIMER_QUANTUM, self,
		    processor->quantum_end, processor->last_dispatch);
		if (was_idle) {
			/*
			 * kperf's running timer is active whenever the idle thread for a
			 * CPU is not running.
			 */
			kperf_running_setup(processor, processor->last_dispatch);
		}
		running_timers_activate(processor);
		processor->first_timeslice = TRUE;
	} else {
		running_timers_deactivate(processor);
		processor->first_timeslice = FALSE;
		thread_tell_urgency(THREAD_URGENCY_NONE, 0, 0, 0, self);
	}

	assert(self->block_hint == kThreadWaitNone);
	self->computation_epoch = processor->last_dispatch;
	self->reason = AST_NONE;
	processor->starting_pri = self->sched_pri;

	thread_unlock(self);

	machine_thread_going_on_core(self, urgency, latency, self->same_pri_latency,
	    processor->last_dispatch);

#if defined(CONFIG_SCHED_DEFERRED_AST)
	/*
	 * TODO: Can we state that redispatching our old thread is also
	 * uninteresting?
	 */
	if ((os_atomic_load(&sched_run_buckets[TH_BUCKET_RUN], relaxed) == 1) && !(self->state & TH_IDLE)) {
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
counter(mach_counter_t  c_thread_block_calls = 0; )

wait_result_t
thread_block_reason(
	thread_continue_t       continuation,
	void                            *parameter,
	ast_t                           reason)
{
	thread_t        self = current_thread();
	processor_t     processor;
	thread_t        new_thread;
	spl_t           s;

	counter(++c_thread_block_calls);

	s = splsched();

	processor = current_processor();

	/* If we're explicitly yielding, force a subsequent quantum */
	if (reason & AST_YIELD) {
		processor->first_timeslice = FALSE;
	}

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
		    MACHDBG_CODE(DBG_MACH_SCHED, MACH_BLOCK),
		    reason, VM_KERNEL_UNSLIDE(continuation), 0, 0, 0);
	}

	do {
		thread_lock(self);
		new_thread = thread_select(self, processor, &reason);
		thread_unlock(self);
	} while (!thread_invoke(self, new_thread, reason));

	splx(s);

	return self->wait_result;
}

/*
 *	thread_block:
 *
 *	Block the current thread if a wait has been asserted.
 */
wait_result_t
thread_block(
	thread_continue_t       continuation)
{
	return thread_block_reason(continuation, NULL, AST_NONE);
}

wait_result_t
thread_block_parameter(
	thread_continue_t       continuation,
	void                            *parameter)
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
	thread_t                        self,
	thread_continue_t       continuation,
	void                            *parameter,
	thread_t                        new_thread)
{
	ast_t reason = AST_NONE;

	if ((self->state & TH_IDLE) == 0) {
		reason = AST_HANDOFF;
	}

	/*
	 * If this thread hadn't been setrun'ed, it
	 * might not have a chosen processor, so give it one
	 */
	if (new_thread->chosen_processor == NULL) {
		new_thread->chosen_processor = current_processor();
	}

	self->continuation = continuation;
	self->parameter = parameter;

	while (!thread_invoke(self, new_thread, reason)) {
		/* the handoff failed, so we have to fall back to the normal block path */
		processor_t processor = current_processor();

		reason = AST_NONE;

		thread_lock(self);
		new_thread = thread_select(self, processor, &reason);
		thread_unlock(self);
	}

	return self->wait_result;
}

/*
 *	thread_continue:
 *
 *	Called at splsched when a thread first receives
 *	a new stack after a continuation.
 *
 *	Called with THREAD_NULL as the old thread when
 *	invoked by machine_load_context.
 */
void
thread_continue(
	thread_t        thread)
{
	thread_t                self = current_thread();
	thread_continue_t       continuation;
	void                    *parameter;

	DTRACE_SCHED(on__cpu);

	continuation = self->continuation;
	parameter = self->parameter;

	assert(continuation != NULL);

#if KPERF
	kperf_on_cpu(self, continuation, NULL);
#endif

	thread_dispatch(thread, self);

	self->continuation = self->parameter = NULL;

#if INTERRUPT_MASKED_DEBUG
	/* Reset interrupt-masked spin debugging timeout */
	ml_spin_debug_clear(self);
#endif

	TLOG(1, "thread_continue: calling call_continuation\n");

	boolean_t enable_interrupts = TRUE;

	/* bootstrap thread, idle thread need to stay interrupts-disabled */
	if (thread == THREAD_NULL || (self->state & TH_IDLE)) {
		enable_interrupts = FALSE;
	}

	call_continuation(continuation, parameter, self->wait_result, enable_interrupts);
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
	if ((thread != THREAD_NULL) && thread->th_sched_bucket == TH_BUCKET_SHARE_BG) {
		return bg_quantum;
	} else {
		return std_quantum;
	}
}

/*
 *	run_queue_init:
 *
 *	Initialize a run queue before first use.
 */
void
run_queue_init(
	run_queue_t             rq)
{
	rq->highq = NOPRI;
	for (u_int i = 0; i < BITMAP_LEN(NRQS); i++) {
		rq->bitmap[i] = 0;
	}
	rq->urgency = rq->count = 0;
	for (int i = 0; i < NRQS; i++) {
		circle_queue_init(&rq->queues[i]);
	}
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
	run_queue_t     rq,
	sched_options_t options)
{
	thread_t        thread;
	circle_queue_t  queue = &rq->queues[rq->highq];

	if (options & SCHED_HEADQ) {
		thread = cqe_dequeue_head(queue, struct thread, runq_links);
	} else {
		thread = cqe_dequeue_tail(queue, struct thread, runq_links);
	}

	assert(thread != THREAD_NULL);
	assert_thread_magic(thread);

	thread->runq = PROCESSOR_NULL;
	SCHED_STATS_RUNQ_CHANGE(&rq->runq_stats, rq->count);
	rq->count--;
	if (SCHED(priority_is_urgent)(rq->highq)) {
		rq->urgency--; assert(rq->urgency >= 0);
	}
	if (circle_queue_empty(queue)) {
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
	run_queue_t      rq,
	thread_t         thread,
	sched_options_t  options)
{
	circle_queue_t  queue = &rq->queues[thread->sched_pri];
	boolean_t       result = FALSE;

	assert_thread_magic(thread);

	if (circle_queue_empty(queue)) {
		circle_enqueue_tail(queue, &thread->runq_links);

		rq_bitmap_set(rq->bitmap, thread->sched_pri);
		if (thread->sched_pri > rq->highq) {
			rq->highq = thread->sched_pri;
			result = TRUE;
		}
	} else {
		if (options & SCHED_TAILQ) {
			circle_enqueue_tail(queue, &thread->runq_links);
		} else {
			circle_enqueue_head(queue, &thread->runq_links);
		}
	}
	if (SCHED(priority_is_urgent)(thread->sched_pri)) {
		rq->urgency++;
	}
	SCHED_STATS_RUNQ_CHANGE(&rq->runq_stats, rq->count);
	rq->count++;

	return result;
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
	circle_queue_t  queue = &rq->queues[thread->sched_pri];

	assert(thread->runq != PROCESSOR_NULL);
	assert_thread_magic(thread);

	circle_dequeue(queue, &thread->runq_links);
	SCHED_STATS_RUNQ_CHANGE(&rq->runq_stats, rq->count);
	rq->count--;
	if (SCHED(priority_is_urgent)(thread->sched_pri)) {
		rq->urgency--; assert(rq->urgency >= 0);
	}

	if (circle_queue_empty(queue)) {
		/* update run queue status */
		bitmap_clear(rq->bitmap, thread->sched_pri);
		rq->highq = bitmap_first(rq->bitmap, NRQS);
	}

	thread->runq = PROCESSOR_NULL;
}

/*
 *      run_queue_peek
 *
 *      Peek at the runq and return the highest
 *      priority thread from the runq.
 *
 *	The run queue must be locked.
 */
thread_t
run_queue_peek(
	run_queue_t    rq)
{
	if (rq->count > 0) {
		circle_queue_t queue = &rq->queues[rq->highq];
		thread_t thread = cqe_queue_first(queue, struct thread, runq_links);
		assert_thread_magic(thread);
		return thread;
	} else {
		return THREAD_NULL;
	}
}

rt_queue_t
sched_rtlocal_runq(processor_set_t pset)
{
	return &pset->rt_runq;
}

void
sched_rtlocal_init(processor_set_t pset)
{
	pset_rt_init(pset);
}

void
sched_rtlocal_queue_shutdown(processor_t processor)
{
	processor_set_t pset = processor->processor_set;
	thread_t        thread;
	queue_head_t    tqueue;

	pset_lock(pset);

	/* We only need to migrate threads if this is the last active or last recommended processor in the pset */
	if ((pset->online_processor_count > 0) && pset_is_recommended(pset)) {
		pset_unlock(pset);
		return;
	}

	queue_init(&tqueue);

	while (rt_runq_count(pset) > 0) {
		thread = qe_dequeue_head(&pset->rt_runq.queue, struct thread, runq_links);
		thread->runq = PROCESSOR_NULL;
		SCHED_STATS_RUNQ_CHANGE(&pset->rt_runq.runq_stats, rt_runq_count(pset));
		rt_runq_count_decr(pset);
		enqueue_tail(&tqueue, &thread->runq_links);
	}
	sched_update_pset_load_average(pset, 0);
	pset_unlock(pset);

	qe_foreach_element_safe(thread, &tqueue, runq_links) {
		remqueue(&thread->runq_links);

		thread_lock(thread);

		thread_setrun(thread, SCHED_TAILQ);

		thread_unlock(thread);
	}
}

/* Assumes RT lock is not held, and acquires splsched/rt_lock itself */
void
sched_rtlocal_runq_scan(sched_update_scan_context_t scan_context)
{
	thread_t        thread;

	pset_node_t node = &pset_node0;
	processor_set_t pset = node->psets;

	spl_t s = splsched();
	do {
		while (pset != NULL) {
			pset_lock(pset);

			qe_foreach_element_safe(thread, &pset->rt_runq.queue, runq_links) {
				if (thread->last_made_runnable_time < scan_context->earliest_rt_make_runnable_time) {
					scan_context->earliest_rt_make_runnable_time = thread->last_made_runnable_time;
				}
			}

			pset_unlock(pset);

			pset = pset->pset_list;
		}
	} while (((node = node->node_list) != NULL) && ((pset = node->psets) != NULL));
	splx(s);
}

int64_t
sched_rtlocal_runq_count_sum(void)
{
	pset_node_t node = &pset_node0;
	processor_set_t pset = node->psets;
	int64_t count = 0;

	do {
		while (pset != NULL) {
			count += pset->rt_runq.runq_stats.count_sum;

			pset = pset->pset_list;
		}
	} while (((node = node->node_list) != NULL) && ((pset = node->psets) != NULL));

	return count;
}

/*
 *	realtime_queue_insert:
 *
 *	Enqueue a thread for realtime execution.
 */
static boolean_t
realtime_queue_insert(processor_t processor, processor_set_t pset, thread_t thread)
{
	queue_t     queue       = &SCHED(rt_runq)(pset)->queue;
	uint64_t    deadline    = thread->realtime.deadline;
	boolean_t   preempt     = FALSE;

	pset_assert_locked(pset);

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
				if (iter == queue_first(queue)) {
					preempt = TRUE;
				}
				insque(&thread->runq_links, queue_prev(iter));
				break;
			} else if (iter == queue_last(queue)) {
				enqueue_tail(queue, &thread->runq_links);
				break;
			}
		}
	}

	thread->runq = processor;
	SCHED_STATS_RUNQ_CHANGE(&SCHED(rt_runq)(pset)->runq_stats, rt_runq_count(pset));
	rt_runq_count_incr(pset);

	return preempt;
}

#define MAX_BACKUP_PROCESSORS 7
#if defined(__x86_64__)
#define DEFAULT_BACKUP_PROCESSORS 1
#else
#define DEFAULT_BACKUP_PROCESSORS 0
#endif

int sched_rt_n_backup_processors = DEFAULT_BACKUP_PROCESSORS;

int
sched_get_rt_n_backup_processors(void)
{
	return sched_rt_n_backup_processors;
}

void
sched_set_rt_n_backup_processors(int n)
{
	if (n < 0) {
		n = 0;
	} else if (n > MAX_BACKUP_PROCESSORS) {
		n = MAX_BACKUP_PROCESSORS;
	}

	sched_rt_n_backup_processors = n;
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
	processor_t                     chosen_processor,
	thread_t                        thread)
{
	processor_set_t pset = chosen_processor->processor_set;
	pset_assert_locked(pset);
	ast_t preempt;

	int n_backup = 0;

	if (thread->realtime.constraint <= rt_constraint_threshold) {
		n_backup = sched_rt_n_backup_processors;
	}
	assert((n_backup >= 0) && (n_backup <= MAX_BACKUP_PROCESSORS));

	sched_ipi_type_t ipi_type[MAX_BACKUP_PROCESSORS + 1] = {};
	processor_t ipi_processor[MAX_BACKUP_PROCESSORS + 1] = {};

	thread->chosen_processor = chosen_processor;

	/* <rdar://problem/15102234> */
	assert(thread->bound_processor == PROCESSOR_NULL);

	realtime_queue_insert(chosen_processor, pset, thread);

	processor_t processor = chosen_processor;
	bool chosen_process_is_secondary = chosen_processor->processor_primary != chosen_processor;

	int count = 0;
	for (int i = 0; i <= n_backup; i++) {
		if (i > 0) {
			processor = choose_processor_for_realtime_thread(pset, chosen_processor, chosen_process_is_secondary);
			if ((processor == PROCESSOR_NULL) || (sched_avoid_cpu0 && (processor->cpu_id == 0))) {
				break;
			}
			SCHED_DEBUG_CHOOSE_PROCESSOR_KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_CHOOSE_PROCESSOR) | DBG_FUNC_NONE,
			    (uintptr_t)thread_tid(thread), (uintptr_t)-3, processor->cpu_id, processor->state, 0);
		}
		ipi_type[i] = SCHED_IPI_NONE;
		ipi_processor[i] = processor;
		count++;

		if (processor->current_pri < BASEPRI_RTQUEUES) {
			preempt = (AST_PREEMPT | AST_URGENT);
		} else if (thread->realtime.deadline < processor->deadline) {
			preempt = (AST_PREEMPT | AST_URGENT);
		} else {
			preempt = AST_NONE;
		}

		if (preempt != AST_NONE) {
			if (processor->state == PROCESSOR_IDLE) {
				processor_state_update_from_thread(processor, thread);
				processor->deadline = thread->realtime.deadline;
				pset_update_processor_state(pset, processor, PROCESSOR_DISPATCHING);
				if (processor == current_processor()) {
					ast_on(preempt);

					if ((preempt & AST_URGENT) == AST_URGENT) {
						bit_set(pset->pending_AST_URGENT_cpu_mask, processor->cpu_id);
					}

					if ((preempt & AST_PREEMPT) == AST_PREEMPT) {
						bit_set(pset->pending_AST_PREEMPT_cpu_mask, processor->cpu_id);
					}
				} else {
					ipi_type[i] = sched_ipi_action(processor, thread, true, SCHED_IPI_EVENT_PREEMPT);
				}
			} else if (processor->state == PROCESSOR_DISPATCHING) {
				if ((processor->current_pri < thread->sched_pri) || (processor->deadline > thread->realtime.deadline)) {
					processor_state_update_from_thread(processor, thread);
					processor->deadline = thread->realtime.deadline;
				}
			} else {
				if (processor == current_processor()) {
					ast_on(preempt);

					if ((preempt & AST_URGENT) == AST_URGENT) {
						bit_set(pset->pending_AST_URGENT_cpu_mask, processor->cpu_id);
					}

					if ((preempt & AST_PREEMPT) == AST_PREEMPT) {
						bit_set(pset->pending_AST_PREEMPT_cpu_mask, processor->cpu_id);
					}
				} else {
					ipi_type[i] = sched_ipi_action(processor, thread, false, SCHED_IPI_EVENT_PREEMPT);
				}
			}
		} else {
			/* Selected processor was too busy, just keep thread enqueued and let other processors drain it naturally. */
		}
	}

	pset_unlock(pset);

	assert((count > 0) && (count <= (n_backup + 1)));
	for (int i = 0; i < count; i++) {
		assert(ipi_processor[i] != PROCESSOR_NULL);
		sched_ipi_perform(ipi_processor[i], ipi_type[i]);
	}
}


sched_ipi_type_t
sched_ipi_deferred_policy(processor_set_t pset, processor_t dst,
    __unused sched_ipi_event_t event)
{
#if defined(CONFIG_SCHED_DEFERRED_AST)
	if (!bit_test(pset->pending_deferred_AST_cpu_mask, dst->cpu_id)) {
		return SCHED_IPI_DEFERRED;
	}
#else /* CONFIG_SCHED_DEFERRED_AST */
	panic("Request for deferred IPI on an unsupported platform; pset: %p CPU: %d", pset, dst->cpu_id);
#endif /* CONFIG_SCHED_DEFERRED_AST */
	return SCHED_IPI_NONE;
}

sched_ipi_type_t
sched_ipi_action(processor_t dst, thread_t thread, boolean_t dst_idle, sched_ipi_event_t event)
{
	sched_ipi_type_t ipi_type = SCHED_IPI_NONE;
	assert(dst != NULL);

	processor_set_t pset = dst->processor_set;
	if (current_processor() == dst) {
		return SCHED_IPI_NONE;
	}

	if (bit_test(pset->pending_AST_URGENT_cpu_mask, dst->cpu_id)) {
		return SCHED_IPI_NONE;
	}

	ipi_type = SCHED(ipi_policy)(dst, thread, dst_idle, event);
	switch (ipi_type) {
	case SCHED_IPI_NONE:
		return SCHED_IPI_NONE;
#if defined(CONFIG_SCHED_DEFERRED_AST)
	case SCHED_IPI_DEFERRED:
		bit_set(pset->pending_deferred_AST_cpu_mask, dst->cpu_id);
		break;
#endif /* CONFIG_SCHED_DEFERRED_AST */
	default:
		bit_set(pset->pending_AST_URGENT_cpu_mask, dst->cpu_id);
		bit_set(pset->pending_AST_PREEMPT_cpu_mask, dst->cpu_id);
		break;
	}
	return ipi_type;
}

sched_ipi_type_t
sched_ipi_policy(processor_t dst, thread_t thread, boolean_t dst_idle, sched_ipi_event_t event)
{
	sched_ipi_type_t ipi_type = SCHED_IPI_NONE;
	boolean_t deferred_ipi_supported = false;
	processor_set_t pset = dst->processor_set;

#if defined(CONFIG_SCHED_DEFERRED_AST)
	deferred_ipi_supported = true;
#endif /* CONFIG_SCHED_DEFERRED_AST */

	switch (event) {
	case SCHED_IPI_EVENT_SPILL:
	case SCHED_IPI_EVENT_SMT_REBAL:
	case SCHED_IPI_EVENT_REBALANCE:
	case SCHED_IPI_EVENT_BOUND_THR:
		/*
		 * The spill, SMT rebalance, rebalance and the bound thread
		 * scenarios use immediate IPIs always.
		 */
		ipi_type = dst_idle ? SCHED_IPI_IDLE : SCHED_IPI_IMMEDIATE;
		break;
	case SCHED_IPI_EVENT_PREEMPT:
		/* In the preemption case, use immediate IPIs for RT threads */
		if (thread && (thread->sched_pri >= BASEPRI_RTQUEUES)) {
			ipi_type = dst_idle ? SCHED_IPI_IDLE : SCHED_IPI_IMMEDIATE;
			break;
		}

		/*
		 * For Non-RT threads preemption,
		 * If the core is active, use immediate IPIs.
		 * If the core is idle, use deferred IPIs if supported; otherwise immediate IPI.
		 */
		if (deferred_ipi_supported && dst_idle) {
			return sched_ipi_deferred_policy(pset, dst, event);
		}
		ipi_type = dst_idle ? SCHED_IPI_IDLE : SCHED_IPI_IMMEDIATE;
		break;
	default:
		panic("Unrecognized scheduler IPI event type %d", event);
	}
	assert(ipi_type != SCHED_IPI_NONE);
	return ipi_type;
}

void
sched_ipi_perform(processor_t dst, sched_ipi_type_t ipi)
{
	switch (ipi) {
	case SCHED_IPI_NONE:
		break;
	case SCHED_IPI_IDLE:
		machine_signal_idle(dst);
		break;
	case SCHED_IPI_IMMEDIATE:
		cause_ast_check(dst);
		break;
	case SCHED_IPI_DEFERRED:
		machine_signal_idle_deferred(dst);
		break;
	default:
		panic("Unrecognized scheduler IPI type: %d", ipi);
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
	processor_t                     processor,
	thread_t                        thread,
	integer_t                       options)
{
	processor_set_t pset = processor->processor_set;
	pset_assert_locked(pset);
	ast_t preempt;
	enum { eExitIdle, eInterruptRunning, eDoNothing } ipi_action = eDoNothing;

	sched_ipi_type_t ipi_type = SCHED_IPI_NONE;

	thread->chosen_processor = processor;

	/*
	 *	Set preemption mode.
	 */
#if defined(CONFIG_SCHED_DEFERRED_AST)
	/* TODO: Do we need to care about urgency (see rdar://problem/20136239)? */
#endif
	if (SCHED(priority_is_urgent)(thread->sched_pri) && thread->sched_pri > processor->current_pri) {
		preempt = (AST_PREEMPT | AST_URGENT);
	} else if (processor->current_is_eagerpreempt) {
		preempt = (AST_PREEMPT | AST_URGENT);
	} else if ((thread->sched_mode == TH_MODE_TIMESHARE) && (thread->sched_pri < thread->base_pri)) {
		if (SCHED(priority_is_urgent)(thread->base_pri) && thread->sched_pri > processor->current_pri) {
			preempt = (options & SCHED_PREEMPT)? AST_PREEMPT: AST_NONE;
		} else {
			preempt = AST_NONE;
		}
	} else {
		preempt = (options & SCHED_PREEMPT)? AST_PREEMPT: AST_NONE;
	}

	if ((options & (SCHED_PREEMPT | SCHED_REBALANCE)) == (SCHED_PREEMPT | SCHED_REBALANCE)) {
		/*
		 * Having gone to the trouble of forcing this thread off a less preferred core,
		 * we should force the preferable core to reschedule immediately to give this
		 * thread a chance to run instead of just sitting on the run queue where
		 * it may just be stolen back by the idle core we just forced it off.
		 */
		preempt |= AST_PREEMPT;
	}

	SCHED(processor_enqueue)(processor, thread, options);
	sched_update_pset_load_average(pset, 0);

	if (preempt != AST_NONE) {
		if (processor->state == PROCESSOR_IDLE) {
			processor_state_update_from_thread(processor, thread);
			processor->deadline = UINT64_MAX;
			pset_update_processor_state(pset, processor, PROCESSOR_DISPATCHING);
			ipi_action = eExitIdle;
		} else if (processor->state == PROCESSOR_DISPATCHING) {
			if (processor->current_pri < thread->sched_pri) {
				processor_state_update_from_thread(processor, thread);
				processor->deadline = UINT64_MAX;
			}
		} else if ((processor->state == PROCESSOR_RUNNING ||
		    processor->state == PROCESSOR_SHUTDOWN) &&
		    (thread->sched_pri >= processor->current_pri)) {
			ipi_action = eInterruptRunning;
		}
	} else {
		/*
		 * New thread is not important enough to preempt what is running, but
		 * special processor states may need special handling
		 */
		if (processor->state == PROCESSOR_SHUTDOWN &&
		    thread->sched_pri >= processor->current_pri) {
			ipi_action = eInterruptRunning;
		} else if (processor->state == PROCESSOR_IDLE) {
			processor_state_update_from_thread(processor, thread);
			processor->deadline = UINT64_MAX;
			pset_update_processor_state(pset, processor, PROCESSOR_DISPATCHING);

			ipi_action = eExitIdle;
		}
	}

	if (ipi_action != eDoNothing) {
		if (processor == current_processor()) {
			if ((preempt = csw_check_locked(processor->active_thread, processor, pset, AST_NONE)) != AST_NONE) {
				ast_on(preempt);
			}

			if ((preempt & AST_URGENT) == AST_URGENT) {
				bit_set(pset->pending_AST_URGENT_cpu_mask, processor->cpu_id);
			} else {
				bit_clear(pset->pending_AST_URGENT_cpu_mask, processor->cpu_id);
			}

			if ((preempt & AST_PREEMPT) == AST_PREEMPT) {
				bit_set(pset->pending_AST_PREEMPT_cpu_mask, processor->cpu_id);
			} else {
				bit_clear(pset->pending_AST_PREEMPT_cpu_mask, processor->cpu_id);
			}
		} else {
			sched_ipi_event_t event = (options & SCHED_REBALANCE) ? SCHED_IPI_EVENT_REBALANCE : SCHED_IPI_EVENT_PREEMPT;
			ipi_type = sched_ipi_action(processor, thread, (ipi_action == eExitIdle), event);
		}
	}
	pset_unlock(pset);
	sched_ipi_perform(processor, ipi_type);
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
	processor_set_t         pset)
{
	processor_set_t         nset = pset;

	do {
		nset = next_pset(nset);
	} while (nset->online_processor_count < 1 && nset != pset);

	return nset;
}

inline static processor_set_t
change_locked_pset(processor_set_t current_pset, processor_set_t new_pset)
{
	if (current_pset != new_pset) {
		pset_unlock(current_pset);
		pset_lock(new_pset);
	}

	return new_pset;
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
	processor_set_t         starting_pset,
	processor_t             processor,
	thread_t                thread)
{
	processor_set_t pset = starting_pset;
	processor_set_t nset;

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
			if (mc_processor != PROCESSOR_NULL) {
				processor = mc_processor->processor_primary;
			}
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
				if ((thread->sched_pri < BASEPRI_RTQUEUES) || processor_is_fast_track_candidate_for_realtime_thread(pset, processor)) {
					return processor;
				}
				processor = PROCESSOR_NULL;
				break;
			case PROCESSOR_RUNNING:
			case PROCESSOR_DISPATCHING:
				/*
				 * Hint is for an active CPU. This fast-path allows
				 * realtime threads to preempt non-realtime threads
				 * to regain their previous executing processor.
				 */
				if ((thread->sched_pri >= BASEPRI_RTQUEUES) &&
				    processor_is_fast_track_candidate_for_realtime_thread(pset, processor)) {
					return processor;
				}

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
	integer_t lowest_secondary_priority = MAXPRI + 1;
	integer_t lowest_unpaired_primary_priority = MAXPRI + 1;
	integer_t lowest_idle_secondary_priority = MAXPRI + 1;
	integer_t lowest_count = INT_MAX;
	uint64_t  furthest_deadline = 1;
	processor_t lp_processor = PROCESSOR_NULL;
	processor_t lp_unpaired_primary_processor = PROCESSOR_NULL;
	processor_t lp_idle_secondary_processor = PROCESSOR_NULL;
	processor_t lp_paired_secondary_processor = PROCESSOR_NULL;
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

	if (thread->sched_pri >= BASEPRI_RTQUEUES) {
		pset_node_t node = pset->node;
		int consider_secondaries = (!pset->is_SMT) || (bit_count(node->pset_map) == 1) || (node->pset_non_rt_primary_map == 0);
		for (; consider_secondaries < 2; consider_secondaries++) {
			pset = change_locked_pset(pset, starting_pset);
			do {
				processor = choose_processor_for_realtime_thread(pset, PROCESSOR_NULL, consider_secondaries);
				if (processor) {
					return processor;
				}

				/* NRG Collect processor stats for furthest deadline etc. here */

				nset = next_pset(pset);

				if (nset != starting_pset) {
					pset = change_locked_pset(pset, nset);
				}
			} while (nset != starting_pset);
		}
		/* Or we could just let it change to starting_pset in the loop above */
		pset = change_locked_pset(pset, starting_pset);
	}

	do {
		/*
		 * Choose an idle processor, in pset traversal order
		 */

		uint64_t idle_primary_map = (pset->cpu_state_map[PROCESSOR_IDLE] &
		    pset->primary_map &
		    pset->recommended_bitmask);

		/* there shouldn't be a pending AST if the processor is idle */
		assert((idle_primary_map & pset->pending_AST_URGENT_cpu_mask) == 0);

		int cpuid = lsb_first(idle_primary_map);
		if (cpuid >= 0) {
			processor = processor_array[cpuid];
			return processor;
		}

		/*
		 * Otherwise, enumerate active and idle processors to find primary candidates
		 * with lower priority/etc.
		 */

		uint64_t active_map = ((pset->cpu_state_map[PROCESSOR_RUNNING] | pset->cpu_state_map[PROCESSOR_DISPATCHING]) &
		    pset->recommended_bitmask &
		    ~pset->pending_AST_URGENT_cpu_mask);

		if (SCHED(priority_is_urgent)(thread->sched_pri) == FALSE) {
			active_map &= ~pset->pending_AST_PREEMPT_cpu_mask;
		}

		active_map = bit_ror64(active_map, (pset->last_chosen + 1));
		for (int rotid = lsb_first(active_map); rotid >= 0; rotid = lsb_next(active_map, rotid)) {
			cpuid = ((rotid + pset->last_chosen + 1) & 63);
			processor = processor_array[cpuid];

			integer_t cpri = processor->current_pri;
			processor_t primary = processor->processor_primary;
			if (primary != processor) {
				/* If primary is running a NO_SMT thread, don't choose its secondary */
				if (!((primary->state == PROCESSOR_RUNNING) && processor_active_thread_no_smt(primary))) {
					if (cpri < lowest_secondary_priority) {
						lowest_secondary_priority = cpri;
						lp_paired_secondary_processor = processor;
					}
				}
			} else {
				if (cpri < lowest_priority) {
					lowest_priority = cpri;
					lp_processor = processor;
				}
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
		uint64_t idle_secondary_map = (pset->cpu_state_map[PROCESSOR_IDLE] &
		    ~pset->primary_map &
		    pset->recommended_bitmask);

		/* there shouldn't be a pending AST if the processor is idle */
		assert((idle_secondary_map & pset->pending_AST_URGENT_cpu_mask) == 0);
		assert((idle_secondary_map & pset->pending_AST_PREEMPT_cpu_mask) == 0);

		for (cpuid = lsb_first(idle_secondary_map); cpuid >= 0; cpuid = lsb_next(idle_secondary_map, cpuid)) {
			processor = processor_array[cpuid];

			processor_t cprimary = processor->processor_primary;

			integer_t primary_pri = cprimary->current_pri;

			/*
			 * TODO: This should also make the same decisions
			 * as secondary_can_run_realtime_thread
			 *
			 * TODO: Keep track of the pending preemption priority
			 * of the primary to make this more accurate.
			 */

			/* If the primary is running a no-smt thread, then don't choose its secondary */
			if (cprimary->state == PROCESSOR_RUNNING &&
			    processor_active_thread_no_smt(cprimary)) {
				continue;
			}

			/*
			 * Find the idle secondary processor with the lowest priority primary
			 *
			 * We will choose this processor as a fallback if we find no better
			 * primary to preempt.
			 */
			if (primary_pri < lowest_idle_secondary_priority) {
				lp_idle_secondary_processor = processor;
				lowest_idle_secondary_priority = primary_pri;
			}

			/* Find the the lowest priority active primary with idle secondary */
			if (primary_pri < lowest_unpaired_primary_priority) {
				/* If the primary processor is offline or starting up, it's not a candidate for this path */
				if (cprimary->state != PROCESSOR_RUNNING &&
				    cprimary->state != PROCESSOR_DISPATCHING) {
					continue;
				}

				if (!cprimary->is_recommended) {
					continue;
				}

				/* if the primary is pending preemption, don't try to re-preempt it */
				if (bit_test(pset->pending_AST_URGENT_cpu_mask, cprimary->cpu_id)) {
					continue;
				}

				if (SCHED(priority_is_urgent)(thread->sched_pri) == FALSE &&
				    bit_test(pset->pending_AST_PREEMPT_cpu_mask, cprimary->cpu_id)) {
					continue;
				}

				lowest_unpaired_primary_priority = primary_pri;
				lp_unpaired_primary_processor = cprimary;
			}
		}

		/*
		 * We prefer preempting a primary processor over waking up its secondary.
		 * The secondary will then be woken up by the preempted thread.
		 */
		if (thread->sched_pri > lowest_unpaired_primary_priority) {
			pset->last_chosen = lp_unpaired_primary_processor->cpu_id;
			return lp_unpaired_primary_processor;
		}

		/*
		 * We prefer preempting a lower priority active processor over directly
		 * waking up an idle secondary.
		 * The preempted thread will then find the idle secondary.
		 */
		if (thread->sched_pri > lowest_priority) {
			pset->last_chosen = lp_processor->cpu_id;
			return lp_processor;
		}

		if (thread->sched_pri >= BASEPRI_RTQUEUES) {
			/*
			 * For realtime threads, the most important aspect is
			 * scheduling latency, so we will pick an active
			 * secondary processor in this pset, or preempt
			 * another RT thread with a further deadline before
			 * going to the next pset.
			 */

			if (sched_allow_rt_smt && (thread->sched_pri > lowest_secondary_priority)) {
				pset->last_chosen = lp_paired_secondary_processor->cpu_id;
				return lp_paired_secondary_processor;
			}

			if (thread->realtime.deadline < furthest_deadline) {
				return fd_processor;
			}
		}

		/*
		 * lc_processor is used to indicate the best processor set run queue
		 * on which to enqueue a thread when all available CPUs are busy with
		 * higher priority threads, so try to make sure it is initialized.
		 */
		if (lc_processor == PROCESSOR_NULL) {
			cpumap_t available_map = ((pset->cpu_state_map[PROCESSOR_IDLE] |
			    pset->cpu_state_map[PROCESSOR_RUNNING] |
			    pset->cpu_state_map[PROCESSOR_DISPATCHING]) &
			    pset->recommended_bitmask);
			cpuid = lsb_first(available_map);
			if (cpuid >= 0) {
				lc_processor = processor_array[cpuid];
				lowest_count = SCHED(processor_runq_count)(lc_processor);
			}
		}

		/*
		 * Move onto the next processor set.
		 *
		 * If all primary processors in this pset are running a higher
		 * priority thread, move on to next pset. Only when we have
		 * exhausted the search for primary processors do we
		 * fall back to secondaries.
		 */
		nset = next_pset(pset);

		if (nset != starting_pset) {
			pset = change_locked_pset(pset, nset);
		}
	} while (nset != starting_pset);

	/*
	 * Make sure that we pick a running processor,
	 * and that the correct processor set is locked.
	 * Since we may have unlocked the candidate processor's
	 * pset, it may have changed state.
	 *
	 * All primary processors are running a higher priority
	 * thread, so the only options left are enqueuing on
	 * the secondary processor that would perturb the least priority
	 * primary, or the least busy primary.
	 */
	boolean_t fallback_processor = false;
	do {
		/* lowest_priority is evaluated in the main loops above */
		if (lp_idle_secondary_processor != PROCESSOR_NULL) {
			processor = lp_idle_secondary_processor;
			lp_idle_secondary_processor = PROCESSOR_NULL;
		} else if (lp_paired_secondary_processor != PROCESSOR_NULL) {
			processor = lp_paired_secondary_processor;
			lp_paired_secondary_processor = PROCESSOR_NULL;
		} else if (lc_processor != PROCESSOR_NULL) {
			processor = lc_processor;
			lc_processor = PROCESSOR_NULL;
		} else {
			/*
			 * All processors are executing higher priority threads, and
			 * the lowest_count candidate was not usable.
			 *
			 * For AMP platforms running the clutch scheduler always
			 * return a processor from the requested pset to allow the
			 * thread to be enqueued in the correct runq. For non-AMP
			 * platforms, simply return the master_processor.
			 */
			fallback_processor = true;
#if CONFIG_SCHED_EDGE
			processor = processor_array[lsb_first(starting_pset->primary_map)];
#else /* CONFIG_SCHED_EDGE */
			processor = master_processor;
#endif /* CONFIG_SCHED_EDGE */
		}

		/*
		 * Check that the correct processor set is
		 * returned locked.
		 */
		pset = change_locked_pset(pset, processor->processor_set);

		/*
		 * We must verify that the chosen processor is still available.
		 * The cases where we pick the master_processor or the fallback
		 * processor are execptions, since we may need enqueue a thread
		 * on its runqueue if this is the last remaining processor
		 * during pset shutdown.
		 *
		 * <rdar://problem/47559304> would really help here since it
		 * gets rid of the weird last processor SHUTDOWN case where
		 * the pset is still schedulable.
		 */
		if (processor != master_processor && (fallback_processor == false) && (processor->state == PROCESSOR_SHUTDOWN || processor->state == PROCESSOR_OFF_LINE)) {
			processor = PROCESSOR_NULL;
		}
	} while (processor == PROCESSOR_NULL);

	pset->last_chosen = processor->cpu_id;
	return processor;
}

/*
 * Default implementation of SCHED(choose_node)()
 * for single node systems
 */
pset_node_t
sched_choose_node(__unused thread_t thread)
{
	return &pset_node0;
}

/*
 *	choose_starting_pset:
 *
 *	Choose a starting processor set for the thread.
 *	May return a processor hint within the pset.
 *
 *	Returns a starting processor set, to be used by
 *      choose_processor.
 *
 *	The thread must be locked.  The resulting pset is unlocked on return,
 *      and is chosen without taking any pset locks.
 */
processor_set_t
choose_starting_pset(pset_node_t node, thread_t thread, processor_t *processor_hint)
{
	processor_set_t pset;
	processor_t processor = PROCESSOR_NULL;

	if (thread->affinity_set != AFFINITY_SET_NULL) {
		/*
		 * Use affinity set policy hint.
		 */
		pset = thread->affinity_set->aset_pset;
	} else if (thread->last_processor != PROCESSOR_NULL) {
		/*
		 *	Simple (last processor) affinity case.
		 */
		processor = thread->last_processor;
		pset = processor->processor_set;
	} else {
		/*
		 *	No Affinity case:
		 *
		 *	Utilitize a per task hint to spread threads
		 *	among the available processor sets.
		 * NRG this seems like the wrong thing to do.
		 * See also task->pset_hint = pset in thread_setrun()
		 */
		task_t          task = thread->task;

		pset = task->pset_hint;
		if (pset == PROCESSOR_SET_NULL) {
			pset = current_processor()->processor_set;
		}

		pset = choose_next_pset(pset);
	}

	if (!bit_test(node->pset_map, pset->pset_id)) {
		/* pset is not from this node so choose one that is */
		int id = lsb_first(node->pset_map);
		assert(id >= 0);
		pset = pset_array[id];
	}

	if (bit_count(node->pset_map) == 1) {
		/* Only a single pset in this node */
		goto out;
	}

	bool avoid_cpu0 = false;

#if defined(__x86_64__)
	if ((thread->sched_pri >= BASEPRI_RTQUEUES) && sched_avoid_cpu0) {
		/* Avoid the pset containing cpu0 */
		avoid_cpu0 = true;
		/* Assert that cpu0 is in pset0.  I expect this to be true on __x86_64__ */
		assert(bit_test(pset_array[0]->cpu_bitmask, 0));
	}
#endif

	if (thread->sched_pri >= BASEPRI_RTQUEUES) {
		pset_map_t rt_target_map = atomic_load(&node->pset_non_rt_primary_map);
		if ((avoid_cpu0 && pset->pset_id == 0) || !bit_test(rt_target_map, pset->pset_id)) {
			if (avoid_cpu0) {
				rt_target_map = bit_ror64(rt_target_map, 1);
			}
			int rotid = lsb_first(rt_target_map);
			if (rotid >= 0) {
				int id = avoid_cpu0 ? ((rotid + 1) & 63) : rotid;
				pset = pset_array[id];
				goto out;
			}
		}
		if (!pset->is_SMT || !sched_allow_rt_smt) {
			/* All psets are full of RT threads - fall back to choose processor to find the furthest deadline RT thread */
			goto out;
		}
		rt_target_map = atomic_load(&node->pset_non_rt_map);
		if ((avoid_cpu0 && pset->pset_id == 0) || !bit_test(rt_target_map, pset->pset_id)) {
			if (avoid_cpu0) {
				rt_target_map = bit_ror64(rt_target_map, 1);
			}
			int rotid = lsb_first(rt_target_map);
			if (rotid >= 0) {
				int id = avoid_cpu0 ? ((rotid + 1) & 63) : rotid;
				pset = pset_array[id];
				goto out;
			}
		}
		/* All psets are full of RT threads - fall back to choose processor to find the furthest deadline RT thread */
	} else {
		pset_map_t idle_map = atomic_load(&node->pset_idle_map);
		if (!bit_test(idle_map, pset->pset_id)) {
			int next_idle_pset_id = lsb_first(idle_map);
			if (next_idle_pset_id >= 0) {
				pset = pset_array[next_idle_pset_id];
			}
		}
	}

out:
	if ((processor != PROCESSOR_NULL) && (processor->processor_set != pset)) {
		processor = PROCESSOR_NULL;
	}
	if (processor != PROCESSOR_NULL) {
		*processor_hint = processor;
	}

	return pset;
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
	thread_t                        thread,
	sched_options_t                 options)
{
	processor_t                     processor;
	processor_set_t         pset;

	assert((thread->state & (TH_RUN | TH_WAIT | TH_UNINT | TH_TERMINATE | TH_TERMINATE2)) == TH_RUN);
	assert(thread->runq == PROCESSOR_NULL);

	/*
	 *	Update priority if needed.
	 */
	if (SCHED(can_update_priority)(thread)) {
		SCHED(update_priority)(thread);
	}

	thread->sfi_class = sfi_thread_classify(thread);

	assert(thread->runq == PROCESSOR_NULL);

	if (thread->bound_processor == PROCESSOR_NULL) {
		/*
		 *	Unbound case.
		 */
		processor_t processor_hint = PROCESSOR_NULL;
		pset_node_t node = SCHED(choose_node)(thread);
		processor_set_t starting_pset = choose_starting_pset(node, thread, &processor_hint);

		pset_lock(starting_pset);

		processor = SCHED(choose_processor)(starting_pset, processor_hint, thread);
		pset = processor->processor_set;
		task_t task = thread->task;
		task->pset_hint = pset; /* NRG this is done without holding the task lock */

		SCHED_DEBUG_CHOOSE_PROCESSOR_KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_CHOOSE_PROCESSOR) | DBG_FUNC_NONE,
		    (uintptr_t)thread_tid(thread), (uintptr_t)-1, processor->cpu_id, processor->state, 0);
	} else {
		/*
		 *	Bound case:
		 *
		 *	Unconditionally dispatch on the processor.
		 */
		processor = thread->bound_processor;
		pset = processor->processor_set;
		pset_lock(pset);

		SCHED_DEBUG_CHOOSE_PROCESSOR_KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_CHOOSE_PROCESSOR) | DBG_FUNC_NONE,
		    (uintptr_t)thread_tid(thread), (uintptr_t)-2, processor->cpu_id, processor->state, 0);
	}

	/*
	 *	Dispatch the thread on the chosen processor.
	 *	TODO: This should be based on sched_mode, not sched_pri
	 */
	if (thread->sched_pri >= BASEPRI_RTQUEUES) {
		realtime_setrun(processor, thread);
	} else {
		processor_setrun(processor, thread, options);
	}
	/* pset is now unlocked */
	if (thread->bound_processor == PROCESSOR_NULL) {
		SCHED(check_spill)(pset, thread);
	}
}

processor_set_t
task_choose_pset(
	task_t          task)
{
	processor_set_t         pset = task->pset_hint;

	if (pset != PROCESSOR_SET_NULL) {
		pset = choose_next_pset(pset);
	}

	return pset;
}

/*
 *	Check for a preemption point in
 *	the current context.
 *
 *	Called at splsched with thread locked.
 */
ast_t
csw_check(
	thread_t                thread,
	processor_t             processor,
	ast_t                   check_reason)
{
	processor_set_t pset = processor->processor_set;

	assert(thread == processor->active_thread);

	pset_lock(pset);

	processor_state_update_from_thread(processor, thread);

	ast_t preempt = csw_check_locked(thread, processor, pset, check_reason);

	/* Acknowledge the IPI if we decided not to preempt */

	if ((preempt & AST_URGENT) == 0) {
		bit_clear(pset->pending_AST_URGENT_cpu_mask, processor->cpu_id);
	}

	if ((preempt & AST_PREEMPT) == 0) {
		bit_clear(pset->pending_AST_PREEMPT_cpu_mask, processor->cpu_id);
	}

	pset_unlock(pset);

	return preempt;
}

/*
 * Check for preemption at splsched with
 * pset and thread locked
 */
ast_t
csw_check_locked(
	thread_t                thread,
	processor_t             processor,
	processor_set_t         pset,
	ast_t                   check_reason)
{
	ast_t                   result;

	if (processor->first_timeslice) {
		if (rt_runq_count(pset) > 0) {
			return check_reason | AST_PREEMPT | AST_URGENT;
		}
	} else {
		if (rt_runq_count(pset) > 0) {
			if (BASEPRI_RTQUEUES > processor->current_pri) {
				return check_reason | AST_PREEMPT | AST_URGENT;
			} else {
				return check_reason | AST_PREEMPT;
			}
		}
	}

	/*
	 * If the current thread is running on a processor that is no longer recommended,
	 * urgently preempt it, at which point thread_select() should
	 * try to idle the processor and re-dispatch the thread to a recommended processor.
	 */
	if (!processor->is_recommended) {
		return check_reason | AST_PREEMPT | AST_URGENT;
	}

	result = SCHED(processor_csw_check)(processor);
	if (result != AST_NONE) {
		return check_reason | result | (thread_is_eager_preempt(thread) ? AST_URGENT : AST_NONE);
	}

	/*
	 * Same for avoid-processor
	 *
	 * TODO: Should these set AST_REBALANCE?
	 */
	if (SCHED(avoid_processor_enabled) && SCHED(thread_avoid_processor)(processor, thread)) {
		return check_reason | AST_PREEMPT;
	}

	/*
	 * Even though we could continue executing on this processor, a
	 * secondary SMT core should try to shed load to another primary core.
	 *
	 * TODO: Should this do the same check that thread_select does? i.e.
	 * if no bound threads target this processor, and idle primaries exist, preempt
	 * The case of RT threads existing is already taken care of above
	 */

	if (processor->current_pri < BASEPRI_RTQUEUES &&
	    processor->processor_primary != processor) {
		return check_reason | AST_PREEMPT;
	}

	if (thread->state & TH_SUSP) {
		return check_reason | AST_PREEMPT;
	}

#if CONFIG_SCHED_SFI
	/*
	 * Current thread may not need to be preempted, but maybe needs
	 * an SFI wait?
	 */
	result = sfi_thread_needs_ast(thread, NULL);
	if (result != AST_NONE) {
		return check_reason | result;
	}
#endif

	return AST_NONE;
}

/*
 * Handle preemption IPI or IPI in response to setting an AST flag
 * Triggered by cause_ast_check
 * Called at splsched
 */
void
ast_check(processor_t processor)
{
	if (processor->state != PROCESSOR_RUNNING &&
	    processor->state != PROCESSOR_SHUTDOWN) {
		return;
	}

	thread_t thread = processor->active_thread;

	assert(thread == current_thread());

	thread_lock(thread);

	/*
	 * Propagate thread ast to processor.
	 * (handles IPI in response to setting AST flag)
	 */
	ast_propagate(thread);

	/*
	 * Stash the old urgency and perfctl values to find out if
	 * csw_check updates them.
	 */
	thread_urgency_t old_urgency = processor->current_urgency;
	perfcontrol_class_t old_perfctl_class = processor->current_perfctl_class;

	ast_t preempt;

	if ((preempt = csw_check(thread, processor, AST_NONE)) != AST_NONE) {
		ast_on(preempt);
	}

	if (old_urgency != processor->current_urgency) {
		/*
		 * Urgency updates happen with the thread lock held (ugh).
		 * TODO: This doesn't notice QoS changes...
		 */
		uint64_t urgency_param1, urgency_param2;

		thread_urgency_t urgency = thread_get_urgency(thread, &urgency_param1, &urgency_param2);
		thread_tell_urgency(urgency, urgency_param1, urgency_param2, 0, thread);
	}

	thread_unlock(thread);

	if (old_perfctl_class != processor->current_perfctl_class) {
		/*
		 * We updated the perfctl class of this thread from another core.
		 * Let CLPC know that the currently running thread has a new
		 * class.
		 */

		machine_switch_perfcontrol_state_update(PERFCONTROL_ATTR_UPDATE,
		    mach_approximate_time(), 0, thread);
	}
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
	int16_t         new_priority,
	set_sched_pri_options_t options)
{
	bool is_current_thread = (thread == current_thread());
	bool removed_from_runq = false;
	bool lazy_update = ((options & SETPRI_LAZY) == SETPRI_LAZY);

	int16_t old_priority = thread->sched_pri;

	/* If we're already at this priority, no need to mess with the runqueue */
	if (new_priority == old_priority) {
#if CONFIG_SCHED_CLUTCH
		/* For the first thread in the system, the priority is correct but
		 * th_sched_bucket is still TH_BUCKET_RUN. Since the clutch
		 * scheduler relies on the bucket being set for all threads, update
		 * its bucket here.
		 */
		if (thread->th_sched_bucket == TH_BUCKET_RUN) {
			assert(is_current_thread);
			SCHED(update_thread_bucket)(thread);
		}
#endif /* CONFIG_SCHED_CLUTCH */

		return;
	}

	if (is_current_thread) {
		assert(thread->state & TH_RUN);
		assert(thread->runq == PROCESSOR_NULL);
	} else {
		removed_from_runq = thread_run_queue_remove(thread);
	}

	thread->sched_pri = new_priority;

#if CONFIG_SCHED_CLUTCH
	/*
	 * Since for the clutch scheduler, the thread's bucket determines its runq
	 * in the hierarchy it is important to update the bucket when the thread
	 * lock is held and the thread has been removed from the runq hierarchy.
	 */
	SCHED(update_thread_bucket)(thread);

#endif /* CONFIG_SCHED_CLUTCH */

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_CHANGE_PRIORITY),
	    (uintptr_t)thread_tid(thread),
	    thread->base_pri,
	    thread->sched_pri,
	    thread->sched_usage,
	    0);

	if (removed_from_runq) {
		thread_run_queue_reinsert(thread, SCHED_PREEMPT | SCHED_TAILQ);
	} else if (is_current_thread) {
		processor_t processor = thread->last_processor;
		assert(processor == current_processor());

		thread_urgency_t old_urgency = processor->current_urgency;

		/*
		 * When dropping in priority, check if the thread no longer belongs on core.
		 * If a thread raises its own priority, don't aggressively rebalance it.
		 * <rdar://problem/31699165>
		 *
		 * csw_check does a processor_state_update_from_thread, but
		 * we should do our own if we're being lazy.
		 */
		if (!lazy_update && new_priority < old_priority) {
			ast_t preempt;

			if ((preempt = csw_check(thread, processor, AST_NONE)) != AST_NONE) {
				ast_on(preempt);
			}
		} else {
			processor_state_update_from_thread(processor, thread);
		}

		/*
		 * set_sched_pri doesn't alter RT params. We expect direct base priority/QoS
		 * class alterations from user space to occur relatively infrequently, hence
		 * those are lazily handled. QoS classes have distinct priority bands, and QoS
		 * inheritance is expected to involve priority changes.
		 */
		if (processor->current_urgency != old_urgency) {
			uint64_t urgency_param1, urgency_param2;

			thread_urgency_t new_urgency = thread_get_urgency(thread,
			    &urgency_param1, &urgency_param2);

			thread_tell_urgency(new_urgency, urgency_param1,
			    urgency_param2, 0, thread);
		}

		/* TODO: only call this if current_perfctl_class changed */
		uint64_t ctime = mach_approximate_time();
		machine_thread_going_on_core(thread, processor->current_urgency, 0, 0, ctime);
	} else if (thread->state & TH_RUN) {
		processor_t processor = thread->last_processor;

		if (!lazy_update &&
		    processor != PROCESSOR_NULL &&
		    processor != current_processor() &&
		    processor->active_thread == thread) {
			cause_ast_check(processor);
		}
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
thread_run_queue_remove_for_handoff(thread_t thread)
{
	thread_t pulled_thread = THREAD_NULL;

	thread_lock(thread);

	/*
	 * Check that the thread is not bound to a different processor,
	 * NO_SMT flag is not set on the thread, cluster type of
	 * processor matches with thread if the thread is pinned to a
	 * particular cluster and that realtime is not involved.
	 *
	 * Next, pull it off its run queue.  If it doesn't come, it's not eligible.
	 */
	processor_t processor = current_processor();
	if ((thread->bound_processor == PROCESSOR_NULL || thread->bound_processor == processor)
	    && (!thread_no_smt(thread))
	    && (processor->current_pri < BASEPRI_RTQUEUES)
	    && (thread->sched_pri < BASEPRI_RTQUEUES)
#if __AMP__
	    && ((!(thread->sched_flags & TH_SFLAG_PCORE_ONLY)) ||
	    processor->processor_set->pset_cluster_type == PSET_AMP_P)
	    && ((!(thread->sched_flags & TH_SFLAG_ECORE_ONLY)) ||
	    processor->processor_set->pset_cluster_type == PSET_AMP_E)
#endif /* __AMP__ */
	    ) {
		if (thread_run_queue_remove(thread)) {
			pulled_thread = thread;
		}
	}

	thread_unlock(thread);

	return pulled_thread;
}

/*
 * thread_prepare_for_handoff
 *
 * Make the thread ready for handoff.
 * If the thread was runnable then pull it off the runq, if the thread could
 * not be pulled, return NULL.
 *
 * If the thread was woken up from wait for handoff, make sure it is not bound to
 * different processor.
 *
 * Called at splsched
 *
 * Returns the thread that was pulled or THREAD_NULL if no thread could be pulled.
 * This may be different than the thread that was passed in.
 */
thread_t
thread_prepare_for_handoff(thread_t thread, thread_handoff_option_t option)
{
	thread_t pulled_thread = THREAD_NULL;

	if (option & THREAD_HANDOFF_SETRUN_NEEDED) {
		processor_t processor = current_processor();
		thread_lock(thread);

		/*
		 * Check that the thread is not bound to a different processor,
		 * NO_SMT flag is not set on the thread and cluster type of
		 * processor matches with thread if the thread is pinned to a
		 * particular cluster. Call setrun instead if above conditions
		 * are not satisfied.
		 */
		if ((thread->bound_processor == PROCESSOR_NULL || thread->bound_processor == processor)
		    && (!thread_no_smt(thread))
#if __AMP__
		    && ((!(thread->sched_flags & TH_SFLAG_PCORE_ONLY)) ||
		    processor->processor_set->pset_cluster_type == PSET_AMP_P)
		    && ((!(thread->sched_flags & TH_SFLAG_ECORE_ONLY)) ||
		    processor->processor_set->pset_cluster_type == PSET_AMP_E)
#endif /* __AMP__ */
		    ) {
			pulled_thread = thread;
		} else {
			thread_setrun(thread, SCHED_PREEMPT | SCHED_TAILQ);
		}
		thread_unlock(thread);
	} else {
		pulled_thread = thread_run_queue_remove_for_handoff(thread);
	}

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

	if ((thread->state & (TH_RUN | TH_WAIT)) == TH_WAIT) {
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

	processor_set_t pset = processor->processor_set;

	pset_lock(pset);

	if (thread->runq != PROCESSOR_NULL) {
		/*
		 *	Thread is on the RT run queue and we have a lock on
		 *	that run queue.
		 */

		remqueue(&thread->runq_links);
		SCHED_STATS_RUNQ_CHANGE(&SCHED(rt_runq)(pset)->runq_stats, rt_runq_count(pset));
		rt_runq_count_decr(pset);

		thread->runq = PROCESSOR_NULL;

		removed = TRUE;
	}

	pset_unlock(pset);

	return removed;
}

/*
 * Put the thread back where it goes after a thread_run_queue_remove
 *
 * Thread must have been removed under the same thread lock hold
 *
 * thread locked, at splsched
 */
void
thread_run_queue_reinsert(thread_t thread, sched_options_t options)
{
	assert(thread->runq == PROCESSOR_NULL);
	assert(thread->state & (TH_RUN));

	thread_setrun(thread, options);
}

void
sys_override_cpu_throttle(boolean_t enable_override)
{
	if (enable_override) {
		cpu_throttle_enabled = 0;
	} else {
		cpu_throttle_enabled = 1;
	}
}

thread_urgency_t
thread_get_urgency(thread_t thread, uint64_t *arg1, uint64_t *arg2)
{
	uint64_t urgency_param1 = 0, urgency_param2 = 0;

	thread_urgency_t urgency;

	if (thread == NULL || (thread->state & TH_IDLE)) {
		urgency_param1 = 0;
		urgency_param2 = 0;

		urgency = THREAD_URGENCY_NONE;
	} else if (thread->sched_mode == TH_MODE_REALTIME) {
		urgency_param1 = thread->realtime.period;
		urgency_param2 = thread->realtime.deadline;

		urgency = THREAD_URGENCY_REAL_TIME;
	} else if (cpu_throttle_enabled &&
	    (thread->sched_pri <= MAXPRI_THROTTLE) &&
	    (thread->base_pri <= MAXPRI_THROTTLE)) {
		/*
		 * Threads that are running at low priority but are not
		 * tagged with a specific QoS are separated out from
		 * the "background" urgency. Performance management
		 * subsystem can decide to either treat these threads
		 * as normal threads or look at other signals like thermal
		 * levels for optimal power/perf tradeoffs for a platform.
		 */
		boolean_t thread_lacks_qos = (proc_get_effective_thread_policy(thread, TASK_POLICY_QOS) == THREAD_QOS_UNSPECIFIED); //thread_has_qos_policy(thread);
		boolean_t task_is_suppressed = (proc_get_effective_task_policy(thread->task, TASK_POLICY_SUP_ACTIVE) == 0x1);

		/*
		 * Background urgency applied when thread priority is
		 * MAXPRI_THROTTLE or lower and thread is not promoted
		 * and thread has a QoS specified
		 */
		urgency_param1 = thread->sched_pri;
		urgency_param2 = thread->base_pri;

		if (thread_lacks_qos && !task_is_suppressed) {
			urgency = THREAD_URGENCY_LOWPRI;
		} else {
			urgency = THREAD_URGENCY_BACKGROUND;
		}
	} else {
		/* For otherwise unclassified threads, report throughput QoS parameters */
		urgency_param1 = proc_get_effective_thread_policy(thread, TASK_POLICY_THROUGH_QOS);
		urgency_param2 = proc_get_effective_task_policy(thread->task, TASK_POLICY_THROUGH_QOS);
		urgency = THREAD_URGENCY_NORMAL;
	}

	if (arg1 != NULL) {
		*arg1 = urgency_param1;
	}
	if (arg2 != NULL) {
		*arg2 = urgency_param2;
	}

	return urgency;
}

perfcontrol_class_t
thread_get_perfcontrol_class(thread_t thread)
{
	/* Special case handling */
	if (thread->state & TH_IDLE) {
		return PERFCONTROL_CLASS_IDLE;
	}
	if (thread->task == kernel_task) {
		return PERFCONTROL_CLASS_KERNEL;
	}
	if (thread->sched_mode == TH_MODE_REALTIME) {
		return PERFCONTROL_CLASS_REALTIME;
	}

	/* perfcontrol_class based on base_pri */
	if (thread->base_pri <= MAXPRI_THROTTLE) {
		return PERFCONTROL_CLASS_BACKGROUND;
	} else if (thread->base_pri <= BASEPRI_UTILITY) {
		return PERFCONTROL_CLASS_UTILITY;
	} else if (thread->base_pri <= BASEPRI_DEFAULT) {
		return PERFCONTROL_CLASS_NONUI;
	} else if (thread->base_pri <= BASEPRI_FOREGROUND) {
		return PERFCONTROL_CLASS_UI;
	} else {
		return PERFCONTROL_CLASS_ABOVEUI;
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
	thread_t                        thread,
	processor_t                     processor)
{
	processor_set_t         pset = processor->processor_set;

	(void)splsched();

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_SCHED, MACH_IDLE) | DBG_FUNC_START,
	    (uintptr_t)thread_tid(thread), 0, 0, 0, 0);

	SCHED_STATS_INC(idle_transitions);
	assert(processor->running_timers_active == false);

	uint64_t ctime = mach_absolute_time();

	timer_switch(&processor->system_state, ctime, &processor->idle_state);
	processor->current_state = &processor->idle_state;

	cpu_quiescent_counter_leave(ctime);

	while (1) {
		/*
		 * Ensure that updates to my processor and pset state,
		 * made by the IPI source processor before sending the IPI,
		 * are visible on this processor now (even though we don't
		 * take the pset lock yet).
		 */
		atomic_thread_fence(memory_order_acquire);

		if (processor->state != PROCESSOR_IDLE) {
			break;
		}
		if (bit_test(pset->pending_AST_URGENT_cpu_mask, processor->cpu_id)) {
			break;
		}
#if defined(CONFIG_SCHED_DEFERRED_AST)
		if (bit_test(pset->pending_deferred_AST_cpu_mask, processor->cpu_id)) {
			break;
		}
#endif
		if (processor->is_recommended && (processor->processor_primary == processor)) {
			if (rt_runq_count(pset)) {
				break;
			}
		} else {
			if (SCHED(processor_bound_count)(processor)) {
				break;
			}
		}

		IDLE_KERNEL_DEBUG_CONSTANT(
			MACHDBG_CODE(DBG_MACH_SCHED, MACH_IDLE) | DBG_FUNC_NONE, (uintptr_t)thread_tid(thread), rt_runq_count(pset), SCHED(processor_runq_count)(processor), -1, 0);

		machine_track_platform_idle(TRUE);

		machine_idle();
		/* returns with interrupts enabled */

		machine_track_platform_idle(FALSE);

		(void)splsched();

		/*
		 * Check if we should call sched_timeshare_consider_maintenance() here.
		 * The CPU was woken out of idle due to an interrupt and we should do the
		 * call only if the processor is still idle. If the processor is non-idle,
		 * the threads running on the processor would do the call as part of
		 * context swithing.
		 */
		if (processor->state == PROCESSOR_IDLE) {
			sched_timeshare_consider_maintenance(mach_absolute_time());
		}

		IDLE_KERNEL_DEBUG_CONSTANT(
			MACHDBG_CODE(DBG_MACH_SCHED, MACH_IDLE) | DBG_FUNC_NONE, (uintptr_t)thread_tid(thread), rt_runq_count(pset), SCHED(processor_runq_count)(processor), -2, 0);

		if (!SCHED(processor_queue_empty)(processor)) {
			/* Secondary SMT processors respond to directed wakeups
			 * exclusively. Some platforms induce 'spurious' SMT wakeups.
			 */
			if (processor->processor_primary == processor) {
				break;
			}
		}
	}

	ctime = mach_absolute_time();

	timer_switch(&processor->idle_state, ctime, &processor->system_state);
	processor->current_state = &processor->system_state;

	cpu_quiescent_counter_join(ctime);

	ast_t reason = AST_NONE;

	/* We're handling all scheduling AST's */
	ast_off(AST_SCHEDULING);

	/*
	 * thread_select will move the processor from dispatching to running,
	 * or put it in idle if there's nothing to do.
	 */
	thread_t current_thread = current_thread();

	thread_lock(current_thread);
	thread_t new_thread = thread_select(current_thread, processor, &reason);
	thread_unlock(current_thread);

	assert(processor->running_timers_active == false);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_SCHED, MACH_IDLE) | DBG_FUNC_END,
	    (uintptr_t)thread_tid(thread), processor->state, (uintptr_t)thread_tid(new_thread), reason, 0);

	return new_thread;
}

/*
 *	Each processor has a dedicated thread which
 *	executes the idle loop when there is no suitable
 *	previous context.
 *
 *	This continuation is entered with interrupts disabled.
 */
void
idle_thread(__assert_only void* parameter,
    __unused wait_result_t result)
{
	assert(ml_get_interrupts_enabled() == FALSE);
	assert(parameter == NULL);

	processor_t processor = current_processor();

	/*
	 * Ensure that anything running in idle context triggers
	 * preemption-disabled checks.
	 */
	disable_preemption();

	/*
	 * Enable interrupts temporarily to handle any pending interrupts
	 * or IPIs before deciding to sleep
	 */
	spllo();

	thread_t new_thread = processor_idle(THREAD_NULL, processor);
	/* returns with interrupts disabled */

	enable_preemption();

	if (new_thread != THREAD_NULL) {
		thread_run(processor->idle_thread,
		    idle_thread, NULL, new_thread);
		/*NOTREACHED*/
	}

	thread_block(idle_thread);
	/*NOTREACHED*/
}

kern_return_t
idle_thread_create(
	processor_t             processor)
{
	kern_return_t   result;
	thread_t                thread;
	spl_t                   s;
	char                    name[MAXTHREADNAMESIZE];

	result = kernel_thread_create(idle_thread, NULL, MAXPRI_KERNEL, &thread);
	if (result != KERN_SUCCESS) {
		return result;
	}

	snprintf(name, sizeof(name), "idle #%d", processor->cpu_id);
	thread_set_thread_name(thread, name);

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

	return KERN_SUCCESS;
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
	kern_return_t   result;
	thread_t                thread;

	simple_lock_init(&sched_vm_group_list_lock, 0);

#if __arm__ || __arm64__
	simple_lock_init(&sched_recommended_cores_lock, 0);
#endif /* __arm__ || __arm64__ */

	result = kernel_thread_start_priority((thread_continue_t)sched_init_thread,
	    NULL, MAXPRI_KERNEL, &thread);
	if (result != KERN_SUCCESS) {
		panic("sched_startup");
	}

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

#if __arm64__
static _Atomic uint64_t sched_perfcontrol_callback_deadline;
#endif /* __arm64__ */


#if defined(CONFIG_SCHED_TIMESHARE_CORE)

static volatile uint64_t                sched_maintenance_deadline;
static uint64_t                         sched_tick_last_abstime;
static uint64_t                         sched_tick_delta;
uint64_t                                sched_tick_max_delta;


/*
 *	sched_init_thread:
 *
 *	Perform periodic bookkeeping functions about ten
 *	times per second.
 */
void
sched_timeshare_maintenance_continue(void)
{
	uint64_t        sched_tick_ctime, late_time;

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

	scan_context.sched_tick_last_abstime = sched_tick_last_abstime;
	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_MAINTENANCE) | DBG_FUNC_START,
	    sched_tick_delta, late_time, 0, 0, 0);

	/* Add a number of pseudo-ticks corresponding to the elapsed interval
	 * This could be greater than 1 if substantial intervals where
	 * all processors are idle occur, which rarely occurs in practice.
	 */

	sched_tick += sched_tick_delta;

	update_vm_info();

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

	SCHED(rt_runq_scan)(&scan_context);

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

#if __arm__ || __arm64__
	/* Check to see if the recommended cores failsafe is active */
	sched_recommended_cores_maintenance();
#endif /* __arm__ || __arm64__ */


#if DEBUG || DEVELOPMENT
#if __x86_64__
#include <i386/misc_protos.h>
	/* Check for long-duration interrupts */
	mp_interrupt_watchdog();
#endif /* __x86_64__ */
#endif /* DEBUG || DEVELOPMENT */

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_MAINTENANCE) | DBG_FUNC_END,
	    sched_pri_shifts[TH_BUCKET_SHARE_FG], sched_pri_shifts[TH_BUCKET_SHARE_BG],
	    sched_pri_shifts[TH_BUCKET_SHARE_UT], sched_pri_shifts[TH_BUCKET_SHARE_DF], 0);

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
sched_timeshare_consider_maintenance(uint64_t ctime)
{
	cpu_quiescent_counter_checkin(ctime);

	uint64_t deadline = sched_maintenance_deadline;

	if (__improbable(ctime >= deadline)) {
		if (__improbable(current_thread() == sched_maintenance_thread)) {
			return;
		}
		OSMemoryBarrier();

		uint64_t ndeadline = ctime + sched_tick_interval;

		if (__probable(os_atomic_cmpxchg(&sched_maintenance_deadline, deadline, ndeadline, seq_cst))) {
			thread_wakeup((event_t)sched_timeshare_maintenance_continue);
			sched_maintenance_wakeups++;
		}
	}

#if !CONFIG_SCHED_CLUTCH
	/*
	 * Only non-clutch schedulers use the global load calculation EWMA algorithm. For clutch
	 * scheduler, the load is maintained at the thread group and bucket level.
	 */
	uint64_t load_compute_deadline = os_atomic_load_wide(&sched_load_compute_deadline, relaxed);

	if (__improbable(load_compute_deadline && ctime >= load_compute_deadline)) {
		uint64_t new_deadline = 0;
		if (os_atomic_cmpxchg(&sched_load_compute_deadline, load_compute_deadline, new_deadline, relaxed)) {
			compute_sched_load();
			new_deadline = ctime + sched_load_compute_interval_abs;
			os_atomic_store_wide(&sched_load_compute_deadline, new_deadline, relaxed);
		}
	}
#endif /* CONFIG_SCHED_CLUTCH */

#if __arm64__
	uint64_t perf_deadline = os_atomic_load(&sched_perfcontrol_callback_deadline, relaxed);

	if (__improbable(perf_deadline && ctime >= perf_deadline)) {
		/* CAS in 0, if success, make callback. Otherwise let the next context switch check again. */
		if (os_atomic_cmpxchg(&sched_perfcontrol_callback_deadline, perf_deadline, 0, relaxed)) {
			machine_perfcontrol_deadline_passed(perf_deadline);
		}
	}
#endif /* __arm64__ */
}

#endif /* CONFIG_SCHED_TIMESHARE_CORE */

void
sched_init_thread(void)
{
	thread_block(THREAD_CONTINUE_NULL);

	thread_t thread = current_thread();

	thread_set_thread_name(thread, "sched_maintenance_thread");

	sched_maintenance_thread = thread;

	SCHED(maintenance_continuation)();

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

#define THREAD_UPDATE_SIZE              128

static thread_t thread_update_array[THREAD_UPDATE_SIZE];
static uint32_t thread_update_count = 0;

/* Returns TRUE if thread was added, FALSE if thread_update_array is full */
boolean_t
thread_update_add_thread(thread_t thread)
{
	if (thread_update_count == THREAD_UPDATE_SIZE) {
		return FALSE;
	}

	thread_update_array[thread_update_count++] = thread;
	thread_reference_internal(thread);
	return TRUE;
}

void
thread_update_process_threads(void)
{
	assert(thread_update_count <= THREAD_UPDATE_SIZE);

	for (uint32_t i = 0; i < thread_update_count; i++) {
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

static boolean_t
runq_scan_thread(
	thread_t thread,
	sched_update_scan_context_t scan_context)
{
	assert_thread_magic(thread);

	if (thread->sched_stamp != sched_tick &&
	    thread->sched_mode == TH_MODE_TIMESHARE) {
		if (thread_update_add_thread(thread) == FALSE) {
			return TRUE;
		}
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

	return FALSE;
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

	if (count == 0) {
		return FALSE;
	}

	for (queue_index = bitmap_first(runq->bitmap, NRQS);
	    queue_index >= 0;
	    queue_index = bitmap_next(runq->bitmap, queue_index)) {
		thread_t thread;
		circle_queue_t queue = &runq->queues[queue_index];

		cqe_foreach_element(thread, queue, runq_links) {
			assert(count > 0);
			if (runq_scan_thread(thread, scan_context) == TRUE) {
				return TRUE;
			}
			count--;
		}
	}

	return FALSE;
}

#if CONFIG_SCHED_CLUTCH

boolean_t
sched_clutch_timeshare_scan(
	queue_t thread_queue,
	uint16_t thread_count,
	sched_update_scan_context_t scan_context)
{
	if (thread_count == 0) {
		return FALSE;
	}

	thread_t thread;
	qe_foreach_element_safe(thread, thread_queue, th_clutch_timeshare_link) {
		if (runq_scan_thread(thread, scan_context) == TRUE) {
			return TRUE;
		}
		thread_count--;
	}

	assert(thread_count == 0);
	return FALSE;
}


#endif /* CONFIG_SCHED_CLUTCH */

#endif /* CONFIG_SCHED_TIMESHARE_CORE */

bool
thread_is_eager_preempt(thread_t thread)
{
	return thread->sched_flags & TH_SFLAG_EAGERPREEMPT;
}

void
thread_set_eager_preempt(thread_t thread)
{
	spl_t s = splsched();
	thread_lock(thread);

	assert(!thread_is_eager_preempt(thread));

	thread->sched_flags |= TH_SFLAG_EAGERPREEMPT;

	if (thread == current_thread()) {
		/* csw_check updates current_is_eagerpreempt on the processor */
		ast_t ast = csw_check(thread, current_processor(), AST_NONE);

		thread_unlock(thread);

		if (ast != AST_NONE) {
			thread_block_reason(THREAD_CONTINUE_NULL, NULL, ast);
		}
	} else {
		processor_t last_processor = thread->last_processor;

		if (last_processor != PROCESSOR_NULL &&
		    last_processor->state == PROCESSOR_RUNNING &&
		    last_processor->active_thread == thread) {
			cause_ast_check(last_processor);
		}

		thread_unlock(thread);
	}

	splx(s);
}

void
thread_clear_eager_preempt(thread_t thread)
{
	spl_t s = splsched();
	thread_lock(thread);

	assert(thread_is_eager_preempt(thread));

	thread->sched_flags &= ~TH_SFLAG_EAGERPREEMPT;

	if (thread == current_thread()) {
		current_processor()->current_is_eagerpreempt = false;
	}

	thread_unlock(thread);
	splx(s);
}

/*
 * Scheduling statistics
 */
void
sched_stats_handle_csw(processor_t processor, int reasons, int selfpri, int otherpri)
{
	struct sched_statistics *stats;
	boolean_t to_realtime = FALSE;

	stats = PERCPU_GET_RELATIVE(sched_stats, processor, processor);
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
	return get_preemption_level() == 0 && ml_get_interrupts_enabled();
}

static void
sched_timer_deadline_tracking_init(void)
{
	nanoseconds_to_absolutetime(TIMER_DEADLINE_TRACKING_BIN_1_DEFAULT, &timer_deadline_tracking_bin_1);
	nanoseconds_to_absolutetime(TIMER_DEADLINE_TRACKING_BIN_2_DEFAULT, &timer_deadline_tracking_bin_2);
}

#if __arm__ || __arm64__

uint32_t    perfcontrol_requested_recommended_cores = ALL_CORES_RECOMMENDED;
uint32_t    perfcontrol_requested_recommended_core_count = MAX_CPUS;
bool        perfcontrol_failsafe_active = false;
bool        perfcontrol_sleep_override = false;

uint64_t    perfcontrol_failsafe_maintenance_runnable_time;
uint64_t    perfcontrol_failsafe_activation_time;
uint64_t    perfcontrol_failsafe_deactivation_time;

/* data covering who likely caused it and how long they ran */
#define FAILSAFE_NAME_LEN       33 /* (2*MAXCOMLEN)+1 from size of p_name */
char        perfcontrol_failsafe_name[FAILSAFE_NAME_LEN];
int         perfcontrol_failsafe_pid;
uint64_t    perfcontrol_failsafe_tid;
uint64_t    perfcontrol_failsafe_thread_timer_at_start;
uint64_t    perfcontrol_failsafe_thread_timer_last_seen;
uint32_t    perfcontrol_failsafe_recommended_at_trigger;

/*
 * Perf controller calls here to update the recommended core bitmask.
 * If the failsafe is active, we don't immediately apply the new value.
 * Instead, we store the new request and use it after the failsafe deactivates.
 *
 * If the failsafe is not active, immediately apply the update.
 *
 * No scheduler locks are held, no other locks are held that scheduler might depend on,
 * interrupts are enabled
 *
 * currently prototype is in osfmk/arm/machine_routines.h
 */
void
sched_perfcontrol_update_recommended_cores(uint32_t recommended_cores)
{
	assert(preemption_enabled());

	spl_t s = splsched();
	simple_lock(&sched_recommended_cores_lock, LCK_GRP_NULL);

	perfcontrol_requested_recommended_cores = recommended_cores;
	perfcontrol_requested_recommended_core_count = __builtin_popcountll(recommended_cores);

	if ((perfcontrol_failsafe_active == false) && (perfcontrol_sleep_override == false)) {
		sched_update_recommended_cores(perfcontrol_requested_recommended_cores & usercontrol_requested_recommended_cores);
	} else {
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		    MACHDBG_CODE(DBG_MACH_SCHED, MACH_REC_CORES_FAILSAFE) | DBG_FUNC_NONE,
		    perfcontrol_requested_recommended_cores,
		    sched_maintenance_thread->last_made_runnable_time, 0, 0, 0);
	}

	simple_unlock(&sched_recommended_cores_lock);
	splx(s);
}

void
sched_override_recommended_cores_for_sleep(void)
{
	spl_t s = splsched();
	simple_lock(&sched_recommended_cores_lock, LCK_GRP_NULL);

	if (perfcontrol_sleep_override == false) {
		perfcontrol_sleep_override = true;
		sched_update_recommended_cores(ALL_CORES_RECOMMENDED);
	}

	simple_unlock(&sched_recommended_cores_lock);
	splx(s);
}

void
sched_restore_recommended_cores_after_sleep(void)
{
	spl_t s = splsched();
	simple_lock(&sched_recommended_cores_lock, LCK_GRP_NULL);

	if (perfcontrol_sleep_override == true) {
		perfcontrol_sleep_override = false;
		sched_update_recommended_cores(perfcontrol_requested_recommended_cores & usercontrol_requested_recommended_cores);
	}

	simple_unlock(&sched_recommended_cores_lock);
	splx(s);
}

/*
 * Consider whether we need to activate the recommended cores failsafe
 *
 * Called from quantum timer interrupt context of a realtime thread
 * No scheduler locks are held, interrupts are disabled
 */
void
sched_consider_recommended_cores(uint64_t ctime, thread_t cur_thread)
{
	/*
	 * Check if a realtime thread is starving the system
	 * and bringing up non-recommended cores would help
	 *
	 * TODO: Is this the correct check for recommended == possible cores?
	 * TODO: Validate the checks without the relevant lock are OK.
	 */

	if (__improbable(perfcontrol_failsafe_active == TRUE)) {
		/* keep track of how long the responsible thread runs */

		simple_lock(&sched_recommended_cores_lock, LCK_GRP_NULL);

		if (perfcontrol_failsafe_active == TRUE &&
		    cur_thread->thread_id == perfcontrol_failsafe_tid) {
			perfcontrol_failsafe_thread_timer_last_seen = timer_grab(&cur_thread->user_timer) +
			    timer_grab(&cur_thread->system_timer);
		}

		simple_unlock(&sched_recommended_cores_lock);

		/* we're already trying to solve the problem, so bail */
		return;
	}

	/* The failsafe won't help if there are no more processors to enable */
	if (__probable(perfcontrol_requested_recommended_core_count >= processor_count)) {
		return;
	}

	uint64_t too_long_ago = ctime - perfcontrol_failsafe_starvation_threshold;

	/* Use the maintenance thread as our canary in the coal mine */
	thread_t m_thread = sched_maintenance_thread;

	/* If it doesn't look bad, nothing to see here */
	if (__probable(m_thread->last_made_runnable_time >= too_long_ago)) {
		return;
	}

	/* It looks bad, take the lock to be sure */
	thread_lock(m_thread);

	if (m_thread->runq == PROCESSOR_NULL ||
	    (m_thread->state & (TH_RUN | TH_WAIT)) != TH_RUN ||
	    m_thread->last_made_runnable_time >= too_long_ago) {
		/*
		 * Maintenance thread is either on cpu or blocked, and
		 * therefore wouldn't benefit from more cores
		 */
		thread_unlock(m_thread);
		return;
	}

	uint64_t maintenance_runnable_time = m_thread->last_made_runnable_time;

	thread_unlock(m_thread);

	/*
	 * There are cores disabled at perfcontrol's recommendation, but the
	 * system is so overloaded that the maintenance thread can't run.
	 * That likely means that perfcontrol can't run either, so it can't fix
	 * the recommendation.  We have to kick in a failsafe to keep from starving.
	 *
	 * When the maintenance thread has been starved for too long,
	 * ignore the recommendation from perfcontrol and light up all the cores.
	 *
	 * TODO: Consider weird states like boot, sleep, or debugger
	 */

	simple_lock(&sched_recommended_cores_lock, LCK_GRP_NULL);

	if (perfcontrol_failsafe_active == TRUE) {
		simple_unlock(&sched_recommended_cores_lock);
		return;
	}

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_SCHED, MACH_REC_CORES_FAILSAFE) | DBG_FUNC_START,
	    perfcontrol_requested_recommended_cores, maintenance_runnable_time, 0, 0, 0);

	perfcontrol_failsafe_active = TRUE;
	perfcontrol_failsafe_activation_time = mach_absolute_time();
	perfcontrol_failsafe_maintenance_runnable_time = maintenance_runnable_time;
	perfcontrol_failsafe_recommended_at_trigger = perfcontrol_requested_recommended_cores;

	/* Capture some data about who screwed up (assuming that the thread on core is at fault) */
	task_t task = cur_thread->task;
	perfcontrol_failsafe_pid = task_pid(task);
	strlcpy(perfcontrol_failsafe_name, proc_name_address(task->bsd_info), sizeof(perfcontrol_failsafe_name));

	perfcontrol_failsafe_tid = cur_thread->thread_id;

	/* Blame the thread for time it has run recently */
	uint64_t recent_computation = (ctime - cur_thread->computation_epoch) + cur_thread->computation_metered;

	uint64_t last_seen = timer_grab(&cur_thread->user_timer) + timer_grab(&cur_thread->system_timer);

	/* Compute the start time of the bad behavior in terms of the thread's on core time */
	perfcontrol_failsafe_thread_timer_at_start  = last_seen - recent_computation;
	perfcontrol_failsafe_thread_timer_last_seen = last_seen;

	/* Ignore the previously recommended core configuration */
	sched_update_recommended_cores(ALL_CORES_RECOMMENDED);

	simple_unlock(&sched_recommended_cores_lock);
}

/*
 * Now that our bacon has been saved by the failsafe, consider whether to turn it off
 *
 * Runs in the context of the maintenance thread, no locks held
 */
static void
sched_recommended_cores_maintenance(void)
{
	/* Common case - no failsafe, nothing to be done here */
	if (__probable(perfcontrol_failsafe_active == FALSE)) {
		return;
	}

	uint64_t ctime = mach_absolute_time();

	boolean_t print_diagnostic = FALSE;
	char p_name[FAILSAFE_NAME_LEN] = "";

	spl_t s = splsched();
	simple_lock(&sched_recommended_cores_lock, LCK_GRP_NULL);

	/* Check again, under the lock, to avoid races */
	if (perfcontrol_failsafe_active == FALSE) {
		goto out;
	}

	/*
	 * Ensure that the other cores get another few ticks to run some threads
	 * If we don't have this hysteresis, the maintenance thread is the first
	 * to run, and then it immediately kills the other cores
	 */
	if ((ctime - perfcontrol_failsafe_activation_time) < perfcontrol_failsafe_starvation_threshold) {
		goto out;
	}

	/* Capture some diagnostic state under the lock so we can print it out later */

	int      pid = perfcontrol_failsafe_pid;
	uint64_t tid = perfcontrol_failsafe_tid;

	uint64_t thread_usage       = perfcontrol_failsafe_thread_timer_last_seen -
	    perfcontrol_failsafe_thread_timer_at_start;
	uint32_t rec_cores_before   = perfcontrol_failsafe_recommended_at_trigger;
	uint32_t rec_cores_after    = perfcontrol_requested_recommended_cores;
	uint64_t failsafe_duration  = ctime - perfcontrol_failsafe_activation_time;
	strlcpy(p_name, perfcontrol_failsafe_name, sizeof(p_name));

	print_diagnostic = TRUE;

	/* Deactivate the failsafe and reinstate the requested recommendation settings */

	perfcontrol_failsafe_deactivation_time = ctime;
	perfcontrol_failsafe_active = FALSE;

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_SCHED, MACH_REC_CORES_FAILSAFE) | DBG_FUNC_END,
	    perfcontrol_requested_recommended_cores, failsafe_duration, 0, 0, 0);

	sched_update_recommended_cores(perfcontrol_requested_recommended_cores & usercontrol_requested_recommended_cores);

out:
	simple_unlock(&sched_recommended_cores_lock);
	splx(s);

	if (print_diagnostic) {
		uint64_t failsafe_duration_ms = 0, thread_usage_ms = 0;

		absolutetime_to_nanoseconds(failsafe_duration, &failsafe_duration_ms);
		failsafe_duration_ms = failsafe_duration_ms / NSEC_PER_MSEC;

		absolutetime_to_nanoseconds(thread_usage, &thread_usage_ms);
		thread_usage_ms = thread_usage_ms / NSEC_PER_MSEC;

		printf("recommended core failsafe kicked in for %lld ms "
		    "likely due to %s[%d] thread 0x%llx spending "
		    "%lld ms on cpu at realtime priority - "
		    "new recommendation: 0x%x -> 0x%x\n",
		    failsafe_duration_ms, p_name, pid, tid, thread_usage_ms,
		    rec_cores_before, rec_cores_after);
	}
}

#endif /* __arm__ || __arm64__ */

kern_return_t
sched_processor_enable(processor_t processor, boolean_t enable)
{
	assert(preemption_enabled());

	spl_t s = splsched();
	simple_lock(&sched_recommended_cores_lock, LCK_GRP_NULL);

	if (enable) {
		bit_set(usercontrol_requested_recommended_cores, processor->cpu_id);
	} else {
		bit_clear(usercontrol_requested_recommended_cores, processor->cpu_id);
	}

#if __arm__ || __arm64__
	if ((perfcontrol_failsafe_active == false) && (perfcontrol_sleep_override == false)) {
		sched_update_recommended_cores(perfcontrol_requested_recommended_cores & usercontrol_requested_recommended_cores);
	} else {
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		    MACHDBG_CODE(DBG_MACH_SCHED, MACH_REC_CORES_FAILSAFE) | DBG_FUNC_NONE,
		    perfcontrol_requested_recommended_cores,
		    sched_maintenance_thread->last_made_runnable_time, 0, 0, 0);
	}
#else /* __arm__ || __arm64__ */
	sched_update_recommended_cores(usercontrol_requested_recommended_cores);
#endif /* !__arm__ || __arm64__ */

	simple_unlock(&sched_recommended_cores_lock);
	splx(s);

	return KERN_SUCCESS;
}


/*
 * Apply a new recommended cores mask to the processors it affects
 * Runs after considering failsafes and such
 *
 * Iterate over processors and update their ->is_recommended field.
 * If a processor is running, we let it drain out at its next
 * quantum expiration or blocking point. If a processor is idle, there
 * may be more work for it to do, so IPI it.
 *
 * interrupts disabled, sched_recommended_cores_lock is held
 */
static void
sched_update_recommended_cores(uint64_t recommended_cores)
{
	processor_set_t pset, nset;
	processor_t     processor;
	uint64_t        needs_exit_idle_mask = 0x0;
	uint32_t        avail_count;

	processor = processor_list;
	pset = processor->processor_set;

	KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_UPDATE_REC_CORES) | DBG_FUNC_START,
	    recommended_cores,
#if __arm__ || __arm64__
	    perfcontrol_failsafe_active, 0, 0);
#else /* __arm__ || __arm64__ */
	    0, 0, 0);
#endif /* ! __arm__ || __arm64__ */

	if (__builtin_popcountll(recommended_cores) == 0) {
		bit_set(recommended_cores, master_processor->cpu_id); /* add boot processor or we hang */
	}

	/* First set recommended cores */
	pset_lock(pset);
	avail_count = 0;
	do {
		nset = processor->processor_set;
		if (nset != pset) {
			pset_unlock(pset);
			pset = nset;
			pset_lock(pset);
		}

		if (bit_test(recommended_cores, processor->cpu_id)) {
			processor->is_recommended = TRUE;
			bit_set(pset->recommended_bitmask, processor->cpu_id);

			if (processor->state == PROCESSOR_IDLE) {
				if (processor != current_processor()) {
					bit_set(needs_exit_idle_mask, processor->cpu_id);
				}
			}
			if (processor->state != PROCESSOR_OFF_LINE) {
				avail_count++;
				SCHED(pset_made_schedulable)(processor, pset, false);
			}
		}
	} while ((processor = processor->processor_list) != NULL);
	pset_unlock(pset);

	/* Now shutdown not recommended cores */
	processor = processor_list;
	pset = processor->processor_set;

	pset_lock(pset);
	do {
		nset = processor->processor_set;
		if (nset != pset) {
			pset_unlock(pset);
			pset = nset;
			pset_lock(pset);
		}

		if (!bit_test(recommended_cores, processor->cpu_id)) {
			sched_ipi_type_t ipi_type = SCHED_IPI_NONE;

			processor->is_recommended = FALSE;
			bit_clear(pset->recommended_bitmask, processor->cpu_id);

			if ((processor->state == PROCESSOR_RUNNING) || (processor->state == PROCESSOR_DISPATCHING)) {
				ipi_type = SCHED_IPI_IMMEDIATE;
			}
			SCHED(processor_queue_shutdown)(processor);
			/* pset unlocked */

			SCHED(rt_queue_shutdown)(processor);

			if (ipi_type != SCHED_IPI_NONE) {
				if (processor == current_processor()) {
					ast_on(AST_PREEMPT);
				} else {
					sched_ipi_perform(processor, ipi_type);
				}
			}

			pset_lock(pset);
		}
	} while ((processor = processor->processor_list) != NULL);

	processor_avail_count_user = avail_count;
#if defined(__x86_64__)
	commpage_update_active_cpus();
#endif

	pset_unlock(pset);

	/* Issue all pending IPIs now that the pset lock has been dropped */
	for (int cpuid = lsb_first(needs_exit_idle_mask); cpuid >= 0; cpuid = lsb_next(needs_exit_idle_mask, cpuid)) {
		processor = processor_array[cpuid];
		machine_signal_idle(processor);
	}

	KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_UPDATE_REC_CORES) | DBG_FUNC_END,
	    needs_exit_idle_mask, 0, 0, 0);
}

void
thread_set_options(uint32_t thopt)
{
	spl_t x;
	thread_t t = current_thread();

	x = splsched();
	thread_lock(t);

	t->options |= thopt;

	thread_unlock(t);
	splx(x);
}

void
thread_set_pending_block_hint(thread_t thread, block_hint_t block_hint)
{
	thread->pending_block_hint = block_hint;
}

uint32_t
qos_max_parallelism(int qos, uint64_t options)
{
	return SCHED(qos_max_parallelism)(qos, options);
}

uint32_t
sched_qos_max_parallelism(__unused int qos, uint64_t options)
{
	host_basic_info_data_t hinfo;
	mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;
	/* Query the machine layer for core information */
	__assert_only kern_return_t kret = host_info(host_self(), HOST_BASIC_INFO,
	    (host_info_t)&hinfo, &count);
	assert(kret == KERN_SUCCESS);

	if (options & QOS_PARALLELISM_COUNT_LOGICAL) {
		return hinfo.logical_cpu;
	} else {
		return hinfo.physical_cpu;
	}
}

int sched_allow_NO_SMT_threads = 1;
bool
thread_no_smt(thread_t thread)
{
	return sched_allow_NO_SMT_threads && (thread->bound_processor == PROCESSOR_NULL) && ((thread->sched_flags & TH_SFLAG_NO_SMT) || (thread->task->t_flags & TF_NO_SMT));
}

bool
processor_active_thread_no_smt(processor_t processor)
{
	return sched_allow_NO_SMT_threads && !processor->current_is_bound && processor->current_is_NO_SMT;
}

#if __arm64__

/*
 * Set up or replace old timer with new timer
 *
 * Returns true if canceled old timer, false if it did not
 */
boolean_t
sched_perfcontrol_update_callback_deadline(uint64_t new_deadline)
{
	/*
	 * Exchange deadline for new deadline, if old deadline was nonzero,
	 * then I cancelled the callback, otherwise I didn't
	 */

	return os_atomic_xchg(&sched_perfcontrol_callback_deadline, new_deadline,
	           relaxed) != 0;
}

#endif /* __arm64__ */

#if CONFIG_SCHED_EDGE

#define SCHED_PSET_LOAD_EWMA_TC_NSECS 10000000u

/*
 * sched_edge_pset_running_higher_bucket()
 *
 * Routine to calculate cumulative running counts for each scheduling
 * bucket. This effectively lets the load calculation calculate if a
 * cluster is running any threads at a QoS lower than the thread being
 * migrated etc.
 */

static void
sched_edge_pset_running_higher_bucket(processor_set_t pset, uint32_t *running_higher)
{
	bitmap_t *active_map = &pset->cpu_state_map[PROCESSOR_RUNNING];

	/* Edge Scheduler Optimization */
	for (int cpu = bitmap_first(active_map, MAX_CPUS); cpu >= 0; cpu = bitmap_next(active_map, cpu)) {
		sched_bucket_t cpu_bucket = os_atomic_load(&pset->cpu_running_buckets[cpu], relaxed);
		for (sched_bucket_t bucket = cpu_bucket; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
			running_higher[bucket]++;
		}
	}
}

/*
 * sched_update_pset_load_average()
 *
 * Updates the load average for each sched bucket for a cluster.
 * This routine must be called with the pset lock held.
 */
void
sched_update_pset_load_average(processor_set_t pset, uint64_t curtime)
{
	if (pset->online_processor_count == 0) {
		/* Looks like the pset is not runnable any more; nothing to do here */
		return;
	}

	/*
	 * Edge Scheduler Optimization
	 *
	 * See if more callers of this routine can pass in timestamps to avoid the
	 * mach_absolute_time() call here.
	 */

	if (!curtime) {
		curtime = mach_absolute_time();
	}
	uint64_t last_update = os_atomic_load(&pset->pset_load_last_update, relaxed);
	int64_t delta_ticks = curtime - last_update;
	if (delta_ticks < 0) {
		return;
	}

	uint64_t delta_nsecs = 0;
	absolutetime_to_nanoseconds(delta_ticks, &delta_nsecs);

	if (__improbable(delta_nsecs > UINT32_MAX)) {
		delta_nsecs = UINT32_MAX;
	}

	uint32_t running_higher[TH_BUCKET_SCHED_MAX] = {0};
	sched_edge_pset_running_higher_bucket(pset, running_higher);

	for (sched_bucket_t sched_bucket = TH_BUCKET_FIXPRI; sched_bucket < TH_BUCKET_SCHED_MAX; sched_bucket++) {
		uint64_t old_load_average = os_atomic_load(&pset->pset_load_average[sched_bucket], relaxed);
		uint64_t old_load_average_factor = old_load_average * SCHED_PSET_LOAD_EWMA_TC_NSECS;
		uint32_t current_runq_depth = (sched_edge_cluster_cumulative_count(&pset->pset_clutch_root, sched_bucket) +  rt_runq_count(pset) + running_higher[sched_bucket]) / pset->online_processor_count;

		/*
		 * For the new load average multiply current_runq_depth by delta_nsecs (which resuts in a 32.0 value).
		 * Since we want to maintain the load average as a 24.8 fixed arithmetic value for precision, the
		 * new load averga needs to be shifted before it can be added to the old load average.
		 */
		uint64_t new_load_average_factor = (current_runq_depth * delta_nsecs) << SCHED_PSET_LOAD_EWMA_FRACTION_BITS;

		/*
		 * For extremely parallel workloads, it is important that the load average on a cluster moves zero to non-zero
		 * instantly to allow threads to be migrated to other (potentially idle) clusters quickly. Hence use the EWMA
		 * when the system is already loaded; otherwise for an idle system use the latest load average immediately.
		 */
		int old_load_shifted = (int)((old_load_average + SCHED_PSET_LOAD_EWMA_ROUND_BIT) >> SCHED_PSET_LOAD_EWMA_FRACTION_BITS);
		boolean_t load_uptick = (old_load_shifted == 0) && (current_runq_depth != 0);
		boolean_t load_downtick = (old_load_shifted != 0) && (current_runq_depth == 0);
		uint64_t load_average;
		if (load_uptick || load_downtick) {
			load_average = (current_runq_depth << SCHED_PSET_LOAD_EWMA_FRACTION_BITS);
		} else {
			/* Indicates a loaded system; use EWMA for load average calculation */
			load_average = (old_load_average_factor + new_load_average_factor) / (delta_nsecs + SCHED_PSET_LOAD_EWMA_TC_NSECS);
		}
		os_atomic_store(&pset->pset_load_average[sched_bucket], load_average, relaxed);
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_LOAD_AVG) | DBG_FUNC_NONE, pset->pset_cluster_id, (load_average >> SCHED_PSET_LOAD_EWMA_FRACTION_BITS), load_average & SCHED_PSET_LOAD_EWMA_FRACTION_MASK, sched_bucket);
	}
	os_atomic_store(&pset->pset_load_last_update, curtime, relaxed);
}

void
sched_update_pset_avg_execution_time(processor_set_t pset, uint64_t execution_time, uint64_t curtime, sched_bucket_t sched_bucket)
{
	pset_execution_time_t old_execution_time_packed, new_execution_time_packed;
	uint64_t avg_thread_execution_time = 0;

	os_atomic_rmw_loop(&pset->pset_execution_time[sched_bucket].pset_execution_time_packed,
	    old_execution_time_packed.pset_execution_time_packed,
	    new_execution_time_packed.pset_execution_time_packed, relaxed, {
		uint64_t last_update = old_execution_time_packed.pset_execution_time_last_update;
		int64_t delta_ticks = curtime - last_update;
		if (delta_ticks < 0) {
		        /*
		         * Its possible that another CPU came in and updated the pset_execution_time
		         * before this CPU could do it. Since the average execution time is meant to
		         * be an approximate measure per cluster, ignore the older update.
		         */
		        os_atomic_rmw_loop_give_up(return );
		}
		uint64_t delta_nsecs = 0;
		absolutetime_to_nanoseconds(delta_ticks, &delta_nsecs);

		uint64_t nanotime = 0;
		absolutetime_to_nanoseconds(execution_time, &nanotime);
		uint64_t execution_time_us = nanotime / NSEC_PER_USEC;

		uint64_t old_execution_time = (old_execution_time_packed.pset_avg_thread_execution_time * SCHED_PSET_LOAD_EWMA_TC_NSECS);
		uint64_t new_execution_time = (execution_time_us * delta_nsecs);

		avg_thread_execution_time = (old_execution_time + new_execution_time) / (delta_nsecs + SCHED_PSET_LOAD_EWMA_TC_NSECS);
		new_execution_time_packed.pset_avg_thread_execution_time = avg_thread_execution_time;
		new_execution_time_packed.pset_execution_time_last_update = curtime;
	});
	KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_PSET_AVG_EXEC_TIME) | DBG_FUNC_NONE, pset->pset_cluster_id, avg_thread_execution_time, sched_bucket);
}

#else /* CONFIG_SCHED_EDGE */

void
sched_update_pset_load_average(processor_set_t pset, __unused uint64_t curtime)
{
	int non_rt_load = pset->pset_runq.count;
	int load = ((bit_count(pset->cpu_state_map[PROCESSOR_RUNNING]) + non_rt_load + rt_runq_count(pset)) << PSET_LOAD_NUMERATOR_SHIFT);
	int new_load_average = ((int)pset->load_average + load) >> 1;

	pset->load_average = new_load_average;
#if (DEVELOPMENT || DEBUG)
#if __AMP__
	if (pset->pset_cluster_type == PSET_AMP_P) {
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_PSET_LOAD_AVERAGE) | DBG_FUNC_NONE, sched_get_pset_load_average(pset, 0), (bit_count(pset->cpu_state_map[PROCESSOR_RUNNING]) + pset->pset_runq.count + rt_runq_count(pset)));
	}
#endif
#endif
}

void
sched_update_pset_avg_execution_time(__unused processor_set_t pset, __unused uint64_t execution_time, __unused uint64_t curtime, __unused sched_bucket_t sched_bucket)
{
}
#endif /* CONFIG_SCHED_EDGE */

/* pset is locked */
static bool
processor_is_fast_track_candidate_for_realtime_thread(processor_set_t pset, processor_t processor)
{
	int cpuid = processor->cpu_id;
#if defined(__x86_64__)
	if (sched_avoid_cpu0 && (cpuid == 0)) {
		return false;
	}
#endif

	cpumap_t fasttrack_map = pset_available_cpumap(pset) & ~pset->pending_AST_URGENT_cpu_mask & ~pset->realtime_map;

	return bit_test(fasttrack_map, cpuid);
}

/* pset is locked */
static processor_t
choose_processor_for_realtime_thread(processor_set_t pset, processor_t skip_processor, bool consider_secondaries)
{
#if defined(__x86_64__)
	bool avoid_cpu0 = sched_avoid_cpu0 && bit_test(pset->cpu_bitmask, 0);
#else
	const bool avoid_cpu0 = false;
#endif

	cpumap_t cpu_map = pset_available_cpumap(pset) & ~pset->pending_AST_URGENT_cpu_mask & ~pset->realtime_map;
	if (skip_processor) {
		bit_clear(cpu_map, skip_processor->cpu_id);
	}

	cpumap_t primary_map = cpu_map & pset->primary_map;
	if (avoid_cpu0) {
		primary_map = bit_ror64(primary_map, 1);
	}

	int rotid = lsb_first(primary_map);
	if (rotid >= 0) {
		int cpuid = avoid_cpu0 ? ((rotid + 1) & 63) : rotid;

		processor_t processor = processor_array[cpuid];

		return processor;
	}

	if (!pset->is_SMT || !sched_allow_rt_smt || !consider_secondaries) {
		goto out;
	}

	/* Consider secondary processors */
	cpumap_t secondary_map = cpu_map & ~pset->primary_map;
	if (avoid_cpu0) {
		/* Also avoid cpu1 */
		secondary_map = bit_ror64(secondary_map, 2);
	}
	rotid = lsb_first(secondary_map);
	if (rotid >= 0) {
		int cpuid = avoid_cpu0 ?  ((rotid + 2) & 63) : rotid;

		processor_t processor = processor_array[cpuid];

		return processor;
	}

out:
	if (skip_processor) {
		return PROCESSOR_NULL;
	}

	/*
	 * If we didn't find an obvious processor to choose, but there are still more CPUs
	 * not already running realtime threads than realtime threads in the realtime run queue,
	 * this thread belongs in this pset, so choose some other processor in this pset
	 * to ensure the thread is enqueued here.
	 */
	cpumap_t non_realtime_map = pset_available_cpumap(pset) & pset->primary_map & ~pset->realtime_map;
	if (bit_count(non_realtime_map) > rt_runq_count(pset)) {
		cpu_map = non_realtime_map;
		assert(cpu_map != 0);
		int cpuid = bit_first(cpu_map);
		assert(cpuid >= 0);
		return processor_array[cpuid];
	}

	if (!pset->is_SMT || !sched_allow_rt_smt || !consider_secondaries) {
		goto skip_secondaries;
	}

	non_realtime_map = pset_available_cpumap(pset) & ~pset->realtime_map;
	if (bit_count(non_realtime_map) > rt_runq_count(pset)) {
		cpu_map = non_realtime_map;
		assert(cpu_map != 0);
		int cpuid = bit_first(cpu_map);
		assert(cpuid >= 0);
		return processor_array[cpuid];
	}

skip_secondaries:
	return PROCESSOR_NULL;
}

/* pset is locked */
static bool
all_available_primaries_are_running_realtime_threads(processor_set_t pset)
{
	cpumap_t cpu_map = pset_available_cpumap(pset) & pset->primary_map & ~pset->realtime_map;
	return rt_runq_count(pset) > bit_count(cpu_map);
}

#if defined(__x86_64__)
/* pset is locked */
static bool
these_processors_are_running_realtime_threads(processor_set_t pset, uint64_t these_map)
{
	cpumap_t cpu_map = pset_available_cpumap(pset) & these_map & ~pset->realtime_map;
	return rt_runq_count(pset) > bit_count(cpu_map);
}
#endif

static bool
sched_ok_to_run_realtime_thread(processor_set_t pset, processor_t processor)
{
	bool ok_to_run_realtime_thread = true;
#if defined(__x86_64__)
	if (sched_avoid_cpu0 && processor->cpu_id == 0) {
		ok_to_run_realtime_thread = these_processors_are_running_realtime_threads(pset, pset->primary_map & ~0x1);
	} else if (sched_avoid_cpu0 && (processor->cpu_id == 1) && processor->is_SMT) {
		ok_to_run_realtime_thread = sched_allow_rt_smt && these_processors_are_running_realtime_threads(pset, ~0x2);
	} else if (processor->processor_primary != processor) {
		ok_to_run_realtime_thread = (sched_allow_rt_smt && all_available_primaries_are_running_realtime_threads(pset));
	}
#else
	(void)pset;
	(void)processor;
#endif
	return ok_to_run_realtime_thread;
}

void
sched_pset_made_schedulable(__unused processor_t processor, processor_set_t pset, boolean_t drop_lock)
{
	if (drop_lock) {
		pset_unlock(pset);
	}
}

void
thread_set_no_smt(bool set)
{
	if (!system_is_SMT) {
		/* Not a machine that supports SMT */
		return;
	}

	thread_t thread = current_thread();

	spl_t s = splsched();
	thread_lock(thread);
	if (set) {
		thread->sched_flags |= TH_SFLAG_NO_SMT;
	}
	thread_unlock(thread);
	splx(s);
}

bool
thread_get_no_smt(void)
{
	return current_thread()->sched_flags & TH_SFLAG_NO_SMT;
}

extern void task_set_no_smt(task_t);
void
task_set_no_smt(task_t task)
{
	if (!system_is_SMT) {
		/* Not a machine that supports SMT */
		return;
	}

	if (task == TASK_NULL) {
		task = current_task();
	}

	task_lock(task);
	task->t_flags |= TF_NO_SMT;
	task_unlock(task);
}

#if DEBUG || DEVELOPMENT
extern void sysctl_task_set_no_smt(char no_smt);
void
sysctl_task_set_no_smt(char no_smt)
{
	if (!system_is_SMT) {
		/* Not a machine that supports SMT */
		return;
	}

	task_t task = current_task();

	task_lock(task);
	if (no_smt == '1') {
		task->t_flags |= TF_NO_SMT;
	}
	task_unlock(task);
}

extern char sysctl_task_get_no_smt(void);
char
sysctl_task_get_no_smt(void)
{
	task_t task = current_task();

	if (task->t_flags & TF_NO_SMT) {
		return '1';
	}
	return '0';
}
#endif /* DEVELOPMENT || DEBUG */


__private_extern__ void
thread_bind_cluster_type(thread_t thread, char cluster_type, bool soft_bound)
{
#if __AMP__
	spl_t s = splsched();
	thread_lock(thread);
	thread->sched_flags &= ~(TH_SFLAG_ECORE_ONLY | TH_SFLAG_PCORE_ONLY | TH_SFLAG_BOUND_SOFT);
	if (soft_bound) {
		thread->sched_flags |= TH_SFLAG_BOUND_SOFT;
	}
	switch (cluster_type) {
	case 'e':
	case 'E':
		thread->sched_flags |= TH_SFLAG_ECORE_ONLY;
		break;
	case 'p':
	case 'P':
		thread->sched_flags |= TH_SFLAG_PCORE_ONLY;
		break;
	default:
		break;
	}
	thread_unlock(thread);
	splx(s);

	if (thread == current_thread()) {
		thread_block(THREAD_CONTINUE_NULL);
	}
#else /* __AMP__ */
	(void)thread;
	(void)cluster_type;
	(void)soft_bound;
#endif /* __AMP__ */
}

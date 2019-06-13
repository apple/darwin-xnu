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

/*  Manage timers */

#include <mach/mach_types.h>
#include <kern/cpu_data.h> /* current_thread() */
#include <kern/kalloc.h>
#include <stdatomic.h>
#include <sys/errno.h>
#include <sys/vm.h>
#include <sys/ktrace.h>

#include <machine/machine_routines.h>
#if defined(__x86_64__)
#include <i386/mp.h>
#endif /* defined(__x86_64__) */

#include <kperf/kperf.h>
#include <kperf/buffer.h>
#include <kperf/context.h>
#include <kperf/action.h>
#include <kperf/kperf_timer.h>
#include <kperf/kperf_arch.h>
#include <kperf/pet.h>
#include <kperf/sample.h>

/* the list of timers */
struct kperf_timer *kperf_timerv = NULL;
unsigned int kperf_timerc = 0;

static unsigned int pet_timer_id = 999;

/* maximum number of timers we can construct */
#define TIMER_MAX (16)

static uint64_t min_period_abstime;
static uint64_t min_period_bg_abstime;
static uint64_t min_period_pet_abstime;
static uint64_t min_period_pet_bg_abstime;

static uint64_t
kperf_timer_min_period_abstime(void)
{
	if (ktrace_background_active()) {
		return min_period_bg_abstime;
	} else {
		return min_period_abstime;
	}
}

static uint64_t
kperf_timer_min_pet_period_abstime(void)
{
	if (ktrace_background_active()) {
		return min_period_pet_bg_abstime;
	} else {
		return min_period_pet_abstime;
	}
}

static void
kperf_timer_schedule(struct kperf_timer *timer, uint64_t now)
{
	BUF_INFO(PERF_TM_SCHED, timer->period);

	/* if we re-programmed the timer to zero, just drop it */
	if (timer->period == 0) {
		return;
	}

	/* calculate deadline */
	uint64_t deadline = now + timer->period;

	/* re-schedule the timer, making sure we don't apply slop */
	timer_call_enter(&timer->tcall, deadline, TIMER_CALL_SYS_CRITICAL);
}

static void
kperf_sample_cpu(struct kperf_timer *timer, bool system_sample,
		bool only_system)
{
	assert(timer != NULL);

	/* Always cut a tracepoint to show a sample event occurred */
	BUF_DATA(PERF_TM_HNDLR | DBG_FUNC_START, 0);

	int ncpu = cpu_number();

	struct kperf_sample *intbuf = kperf_intr_sample_buffer();
#if DEVELOPMENT || DEBUG
	intbuf->sample_time = mach_absolute_time();
#endif /* DEVELOPMENT || DEBUG */

	/* On a timer, we can see the "real" current thread */
	thread_t thread = current_thread();
	task_t task = get_threadtask(thread);
	struct kperf_context ctx = {
		.cur_thread = thread,
		.cur_task = task,
		.cur_pid = task_pid(task),
		.trigger_type = TRIGGER_TYPE_TIMER,
		.trigger_id = (unsigned int)(timer - kperf_timerv),
	};

	if (ctx.trigger_id == pet_timer_id && ncpu < machine_info.logical_cpu_max) {
		kperf_tid_on_cpus[ncpu] = thread_tid(ctx.cur_thread);
	}

	/* make sure sampling is on */
	unsigned int status = kperf_sampling_status();
	if (status == KPERF_SAMPLING_OFF) {
		BUF_INFO(PERF_TM_HNDLR | DBG_FUNC_END, SAMPLE_OFF);
		return;
	} else if (status == KPERF_SAMPLING_SHUTDOWN) {
		BUF_INFO(PERF_TM_HNDLR | DBG_FUNC_END, SAMPLE_SHUTDOWN);
		return;
	}

	/* call the action -- kernel-only from interrupt, pend user */
	int r = kperf_sample(intbuf, &ctx, timer->actionid,
			SAMPLE_FLAG_PEND_USER | (system_sample ? SAMPLE_FLAG_SYSTEM : 0) |
			(only_system ? SAMPLE_FLAG_ONLY_SYSTEM : 0));

	/* end tracepoint is informational */
	BUF_INFO(PERF_TM_HNDLR | DBG_FUNC_END, r);

	(void)atomic_fetch_and_explicit(&timer->pending_cpus,
			~(UINT64_C(1) << ncpu), memory_order_relaxed);
}

void
kperf_ipi_handler(void *param)
{
	kperf_sample_cpu((struct kperf_timer *)param, false, false);
}

static void
kperf_timer_handler(void *param0, __unused void *param1)
{
	struct kperf_timer *timer = param0;
	unsigned int ntimer = (unsigned int)(timer - kperf_timerv);
	unsigned int ncpus  = machine_info.logical_cpu_max;
	bool system_only_self = true;

	if (timer->actionid == 0) {
		return;
	}

	timer->active = 1;
#if DEVELOPMENT || DEBUG
	timer->fire_time = mach_absolute_time();
#endif /* DEVELOPMENT || DEBUG */

	/* along the lines of do not ipi if we are all shutting down */
	if (kperf_sampling_status() == KPERF_SAMPLING_SHUTDOWN) {
		goto deactivate;
	}

	BUF_DATA(PERF_TM_FIRE, ntimer, ntimer == pet_timer_id, timer->period,
	                       timer->actionid);

	if (ntimer == pet_timer_id) {
		kperf_pet_fire_before();

		/* clean-up the thread-on-CPUs cache */
		bzero(kperf_tid_on_cpus, ncpus * sizeof(*kperf_tid_on_cpus));
	}

	/*
	 * IPI other cores only if the action has non-system samplers.
	 */
	if (kperf_action_has_non_system(timer->actionid)) {
		/*
		 * If the core that's handling the timer is not scheduling
		 * threads, only run system samplers.
		 */
		system_only_self = kperf_mp_broadcast_other_running(timer);
	}
	kperf_sample_cpu(timer, true, system_only_self);

	/* release the pet thread? */
	if (ntimer == pet_timer_id) {
		/* PET mode is responsible for rearming the timer */
		kperf_pet_fire_after();
	} else {
		/*
		  * FIXME: Get the current time from elsewhere.  The next
		  * timer's period now includes the time taken to reach this
		  * point.  This causes a bias towards longer sampling periods
		  * than requested.
		  */
		kperf_timer_schedule(timer, mach_absolute_time());
	}

deactivate:
	timer->active = 0;
}

/* program the timer from the PET thread */
void
kperf_timer_pet_rearm(uint64_t elapsed_ticks)
{
	struct kperf_timer *timer = NULL;
	uint64_t period = 0;
	uint64_t deadline;

	/*
	 * If the pet_timer_id is invalid, it has been disabled, so this should
	 * do nothing.
	 */
	if (pet_timer_id >= kperf_timerc) {
		return;
	}

	unsigned int status = kperf_sampling_status();
	/* do not reprogram the timer if it has been shutdown or sampling is off */
	if (status == KPERF_SAMPLING_OFF) {
		BUF_INFO(PERF_PET_END, SAMPLE_OFF);
		return;
	} else if (status == KPERF_SAMPLING_SHUTDOWN) {
		BUF_INFO(PERF_PET_END, SAMPLE_SHUTDOWN);
		return;
	}

	timer = &(kperf_timerv[pet_timer_id]);

	/* if we re-programmed the timer to zero, just drop it */
	if (!timer->period) {
		return;
	}

	/* subtract the time the pet sample took being careful not to underflow */
	if (timer->period > elapsed_ticks) {
		period = timer->period - elapsed_ticks;
	}

	/* make sure we don't set the next PET sample to happen too soon */
	if (period < min_period_pet_abstime) {
		period = min_period_pet_abstime;
	}

	/* we probably took so long in the PET thread, it makes sense to take
	 * the time again.
	 */
	deadline = mach_absolute_time() + period;

	BUF_INFO(PERF_PET_SCHED, timer->period, period, elapsed_ticks, deadline);

	/* re-schedule the timer, making sure we don't apply slop */
	timer_call_enter(&timer->tcall, deadline, TIMER_CALL_SYS_CRITICAL);

	return;
}

/* turn on all the timers */
void
kperf_timer_go(void)
{
	/* get the PET thread going */
	if (pet_timer_id < kperf_timerc) {
		kperf_pet_config(kperf_timerv[pet_timer_id].actionid);
	}

	uint64_t now = mach_absolute_time();

	for (unsigned int i = 0; i < kperf_timerc; i++) {
		if (kperf_timerv[i].period == 0) {
			continue;
		}

		kperf_timer_schedule(&(kperf_timerv[i]), now);
	}
}

void
kperf_timer_stop(void)
{
	for (unsigned int i = 0; i < kperf_timerc; i++) {
		if (kperf_timerv[i].period == 0) {
			continue;
		}

		/* wait for the timer to stop */
		while (kperf_timerv[i].active);

		timer_call_cancel(&kperf_timerv[i].tcall);
	}

	/* wait for PET to stop, too */
	kperf_pet_config(0);
}

unsigned int
kperf_timer_get_petid(void)
{
	return pet_timer_id;
}

int
kperf_timer_set_petid(unsigned int timerid)
{
	if (timerid < kperf_timerc) {
		uint64_t min_period;

		min_period = kperf_timer_min_pet_period_abstime();
		if (kperf_timerv[timerid].period < min_period) {
			kperf_timerv[timerid].period = min_period;
		}
		kperf_pet_config(kperf_timerv[timerid].actionid);
	} else {
		/* clear the PET trigger if it's a bogus ID */
		kperf_pet_config(0);
	}

	pet_timer_id = timerid;

	return 0;
}

int
kperf_timer_get_period(unsigned int timerid, uint64_t *period_abstime)
{
	if (timerid >= kperf_timerc) {
		return EINVAL;
	}

	*period_abstime = kperf_timerv[timerid].period;
	return 0;
}

int
kperf_timer_set_period(unsigned int timerid, uint64_t period_abstime)
{
	uint64_t min_period;

	if (timerid >= kperf_timerc) {
		return EINVAL;
	}

	if (pet_timer_id == timerid) {
		min_period = kperf_timer_min_pet_period_abstime();
	} else {
		min_period = kperf_timer_min_period_abstime();
	}

	if (period_abstime > 0 && period_abstime < min_period) {
		period_abstime = min_period;
	}

	kperf_timerv[timerid].period = period_abstime;

	/* FIXME: re-program running timers? */

	return 0;
}

int
kperf_timer_get_action(unsigned int timerid, uint32_t *action)
{
	if (timerid >= kperf_timerc) {
		return EINVAL;
	}

	*action = kperf_timerv[timerid].actionid;
	return 0;
}

int
kperf_timer_set_action(unsigned int timerid, uint32_t action)
{
	if (timerid >= kperf_timerc) {
		return EINVAL;
	}

	kperf_timerv[timerid].actionid = action;
	return 0;
}

unsigned int
kperf_timer_get_count(void)
{
	return kperf_timerc;
}

void
kperf_timer_reset(void)
{
	kperf_timer_set_petid(999);
	kperf_set_pet_idle_rate(KPERF_PET_DEFAULT_IDLE_RATE);
	kperf_set_lightweight_pet(0);
	for (unsigned int i = 0; i < kperf_timerc; i++) {
		kperf_timerv[i].period = 0;
		kperf_timerv[i].actionid = 0;
		kperf_timerv[i].pending_cpus = 0;
	}
}

extern int
kperf_timer_set_count(unsigned int count)
{
	struct kperf_timer *new_timerv = NULL, *old_timerv = NULL;
	unsigned int old_count;

	if (min_period_abstime == 0) {
		nanoseconds_to_absolutetime(KP_MIN_PERIOD_NS, &min_period_abstime);
		nanoseconds_to_absolutetime(KP_MIN_PERIOD_BG_NS, &min_period_bg_abstime);
		nanoseconds_to_absolutetime(KP_MIN_PERIOD_PET_NS, &min_period_pet_abstime);
		nanoseconds_to_absolutetime(KP_MIN_PERIOD_PET_BG_NS,
			&min_period_pet_bg_abstime);
		assert(min_period_abstime > 0);
	}

	if (count == kperf_timerc) {
		return 0;
	}
	if (count > TIMER_MAX) {
		return EINVAL;
	}

	/* TODO: allow shrinking? */
	if (count < kperf_timerc) {
		return EINVAL;
	}

	/*
	 * Make sure kperf is initialized when creating the array for the first
	 * time.
	 */
	if (kperf_timerc == 0) {
		int r;

		/* main kperf */
		if ((r = kperf_init())) {
			return r;
		}
	}

	/*
	 * Shut down any running timers since we will be messing with the timer
	 * call structures.
	 */
	kperf_timer_stop();

	/* create a new array */
	new_timerv = kalloc_tag(count * sizeof(struct kperf_timer),
		VM_KERN_MEMORY_DIAG);
	if (new_timerv == NULL) {
		return ENOMEM;
	}
	old_timerv = kperf_timerv;
	old_count = kperf_timerc;

	if (old_timerv != NULL) {
		bcopy(kperf_timerv, new_timerv,
			kperf_timerc * sizeof(struct kperf_timer));
	}

	/* zero the new entries */
	bzero(&(new_timerv[kperf_timerc]),
		(count - old_count) * sizeof(struct kperf_timer));

	/* (re-)setup the timer call info for all entries */
	for (unsigned int i = 0; i < count; i++) {
		timer_call_setup(&new_timerv[i].tcall, kperf_timer_handler, &new_timerv[i]);
	}

	kperf_timerv = new_timerv;
	kperf_timerc = count;

	if (old_timerv != NULL) {
		kfree(old_timerv, old_count * sizeof(struct kperf_timer));
	}

	return 0;
}

/*
 * Copyright (c) 2011-2018 Apple Computer, Inc. All rights reserved.
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
 * This file manages the timers used for on-CPU samples and PET.
 *
 * Each timer configured by a tool is represented by a kptimer structure.
 * The timer calls present in each structure are used to schedule CPU-local
 * timers. As each timer fires, that CPU samples itself and schedules another
 * timer to fire at the next deadline.  The first timer to fire across all CPUs
 * determines that deadline.  This causes the timers to fire at a consistent
 * cadence.
 *
 * Traditional PET uses a timer call to wake up its sampling thread and take
 * on-CPU samples.
 *
 * Synchronization for start and stop is provided by the ktrace subsystem lock.
 * Global state is stored in a single struct, to ease debugging.
 */

#include <mach/mach_types.h>
#include <kern/cpu_data.h> /* current_thread() */
#include <kern/kalloc.h>
#include <kern/timer_queue.h>
#include <libkern/section_keywords.h>
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
#include <kperf/kptimer.h>
#include <kperf/pet.h>
#include <kperf/sample.h>

#define KPTIMER_PET_INACTIVE (999)
#define KPTIMER_MAX (8)

struct kptimer {
	uint32_t kt_actionid;
	uint64_t kt_period_abs;
	/*
	 * The `kt_cur_deadline` field represents when the timer should next fire.
	 * It's used to synchronize between timers firing on each CPU.  In the timer
	 * handler, each CPU will take the `kt_lock` and see if the
	 * `kt_cur_deadline` still needs to be updated for the timer fire.  If so,
	 * it updates it and logs the timer fire event under the lock.
	 */
	lck_spin_t kt_lock;
	uint64_t kt_cur_deadline;

#if DEVELOPMENT || DEBUG
	/*
	 * To be set by the timer leader as a debugging aid for timeouts, if kperf
	 * happens to be on-CPU when they occur.
	 */
	uint64_t kt_fire_time;
#endif /* DEVELOPMENT || DEBUG */
};

static struct {
	struct kptimer *g_timers;
	uint64_t *g_cpu_deadlines;
	unsigned int g_ntimers;
	unsigned int g_pet_timerid;

	bool g_setup:1;
	bool g_pet_active:1;
	bool g_started:1;

	struct timer_call g_pet_timer;
} kptimer = {
	.g_pet_timerid = KPTIMER_PET_INACTIVE,
};

SECURITY_READ_ONLY_LATE(static uint64_t) kptimer_minperiods_mtu[KTPL_MAX];

/*
 * Enforce a minimum timer period to prevent interrupt storms.
 */
const uint64_t kptimer_minperiods_ns[KTPL_MAX] = {
#if defined(__x86_64__)
	[KTPL_FG] = 20 * NSEC_PER_USEC, /* The minimum timer period in xnu, period. */
	[KTPL_BG] = 1 * NSEC_PER_MSEC,
	[KTPL_FG_PET] = 2 * NSEC_PER_MSEC,
	[KTPL_BG_PET] = 5 * NSEC_PER_MSEC,
#elif defined(__arm64__)
	[KTPL_FG] = 50 * NSEC_PER_USEC,
	[KTPL_BG] = 1 * NSEC_PER_MSEC,
	[KTPL_FG_PET] = 2 * NSEC_PER_MSEC,
	[KTPL_BG_PET] = 10 * NSEC_PER_MSEC,
#elif defined(__arm__)
	[KTPL_FG] = 100 * NSEC_PER_USEC,
	[KTPL_BG] = 10 * NSEC_PER_MSEC,
	[KTPL_FG_PET] = 2 * NSEC_PER_MSEC,
	[KTPL_BG_PET] = 50 * NSEC_PER_MSEC,
#else
#error unexpected architecture
#endif
};

static void kptimer_pet_handler(void * __unused param1, void * __unused param2);
static void kptimer_stop_curcpu(processor_t processor);

void
kptimer_init(void)
{
	for (int i = 0; i < KTPL_MAX; i++) {
		nanoseconds_to_absolutetime(kptimer_minperiods_ns[i],
		    &kptimer_minperiods_mtu[i]);
	}
}

static void
kptimer_set_cpu_deadline(int cpuid, int timerid, uint64_t deadline)
{
	kptimer.g_cpu_deadlines[(cpuid * KPTIMER_MAX) + timerid] =
	    deadline;
}

static void
kptimer_setup(void)
{
	if (kptimer.g_setup) {
		return;
	}
	static lck_grp_t kptimer_lock_grp;
	lck_grp_init(&kptimer_lock_grp, "kptimer", LCK_GRP_ATTR_NULL);

	const size_t timers_size = KPTIMER_MAX * sizeof(struct kptimer);
	kptimer.g_timers = kalloc_tag(timers_size, VM_KERN_MEMORY_DIAG);
	assert(kptimer.g_timers != NULL);
	memset(kptimer.g_timers, 0, timers_size);
	for (int i = 0; i < KPTIMER_MAX; i++) {
		lck_spin_init(&kptimer.g_timers[i].kt_lock, &kptimer_lock_grp,
		    LCK_ATTR_NULL);
	}

	const size_t deadlines_size = machine_info.logical_cpu_max * KPTIMER_MAX *
	    sizeof(kptimer.g_cpu_deadlines[0]);
	kptimer.g_cpu_deadlines = kalloc_tag(deadlines_size, VM_KERN_MEMORY_DIAG);
	assert(kptimer.g_cpu_deadlines != NULL);
	memset(kptimer.g_cpu_deadlines, 0, deadlines_size);
	for (int i = 0; i < KPTIMER_MAX; i++) {
		for (int j = 0; j < machine_info.logical_cpu_max; j++) {
			kptimer_set_cpu_deadline(j, i, EndOfAllTime);
		}
	}

	timer_call_setup(&kptimer.g_pet_timer, kptimer_pet_handler, NULL);

	kptimer.g_setup = true;
}

void
kptimer_reset(void)
{
	kptimer_stop();
	kptimer_set_pet_timerid(KPTIMER_PET_INACTIVE);

	for (unsigned int i = 0; i < kptimer.g_ntimers; i++) {
		kptimer.g_timers[i].kt_period_abs = 0;
		kptimer.g_timers[i].kt_actionid = 0;
		for (int j = 0; j < machine_info.logical_cpu_max; j++) {
			kptimer_set_cpu_deadline(j, i, EndOfAllTime);
		}
	}
}

#pragma mark - deadline management

static uint64_t
kptimer_get_cpu_deadline(int cpuid, int timerid)
{
	return kptimer.g_cpu_deadlines[(cpuid * KPTIMER_MAX) + timerid];
}

static void
kptimer_sample_curcpu(unsigned int actionid, unsigned int timerid,
    uint32_t flags)
{
	struct kperf_sample *intbuf = kperf_intr_sample_buffer();
#if DEVELOPMENT || DEBUG
	intbuf->sample_time = mach_absolute_time();
#endif /* DEVELOPMENT || DEBUG */

	BUF_DATA(PERF_TM_HNDLR | DBG_FUNC_START);

	thread_t thread = current_thread();
	task_t task = get_threadtask(thread);
	struct kperf_context ctx = {
		.cur_thread = thread,
		.cur_task = task,
		.cur_pid = task_pid(task),
		.trigger_type = TRIGGER_TYPE_TIMER,
		.trigger_id = timerid,
	};

	(void)kperf_sample(intbuf, &ctx, actionid,
	    SAMPLE_FLAG_PEND_USER | flags);

	BUF_INFO(PERF_TM_HNDLR | DBG_FUNC_END);
}

static void
kptimer_lock(struct kptimer *timer)
{
	lck_spin_lock(&timer->kt_lock);
}

static void
kptimer_unlock(struct kptimer *timer)
{
	lck_spin_unlock(&timer->kt_lock);
}

/*
 * If the deadline expired in the past, find the next deadline to program,
 * locked into the cadence provided by the period.
 */
static inline uint64_t
dead_reckon_deadline(uint64_t now, uint64_t deadline, uint64_t period)
{
	if (deadline < now) {
		uint64_t time_since = now - deadline;
		uint64_t extra_time = period - (time_since % period);
		return now + extra_time;
	}
	return deadline;
}

static uint64_t
kptimer_fire(struct kptimer *timer, unsigned int timerid,
    uint64_t deadline, int __unused cpuid, uint64_t now)
{
	bool first = false;
	uint64_t next_deadline = deadline + timer->kt_period_abs;

	/*
	 * It's not straightforward to replace this lock with a compare-exchange,
	 * since the PERF_TM_FIRE event must be emitted *before* any subsequent
	 * PERF_TM_HNDLR events, so tools can understand the handlers are responding
	 * to this timer fire.
	 */
	kptimer_lock(timer);
	if (timer->kt_cur_deadline < next_deadline) {
		first = true;
		next_deadline = dead_reckon_deadline(now, next_deadline,
		    timer->kt_period_abs);
		timer->kt_cur_deadline = next_deadline;
		BUF_DATA(PERF_TM_FIRE, timerid, timerid == kptimer.g_pet_timerid,
		    timer->kt_period_abs, timer->kt_actionid);
#if DEVELOPMENT || DEBUG
		/*
		 * Debugging aid to see the last time this timer fired.
		 */
		timer->kt_fire_time = mach_absolute_time();
#endif /* DEVELOPMENT || DEBUG */
		if (timerid == kptimer.g_pet_timerid && kppet_get_lightweight_pet()) {
			os_atomic_inc(&kppet_gencount, relaxed);
		}
	} else {
		/*
		 * In case this CPU has missed several timer fires, get it back on track
		 * by synchronizing with the latest timer fire.
		 */
		next_deadline = timer->kt_cur_deadline;
	}
	kptimer_unlock(timer);

	if (!first && !kperf_action_has_non_system(timer->kt_actionid)) {
		/*
		 * The first timer to fire will sample the system, so there's
		 * no need to run other timers if those are the only samplers
		 * for this action.
		 */
		return next_deadline;
	}

	kptimer_sample_curcpu(timer->kt_actionid, timerid,
	    first ? SAMPLE_FLAG_SYSTEM : 0);

	return next_deadline;
}

/*
 * Determine which of the timers fired.
 */
void
kptimer_expire(processor_t processor, int cpuid, uint64_t now)
{
	uint64_t min_deadline = UINT64_MAX;

	if (kperf_status != KPERF_SAMPLING_ON) {
		if (kperf_status == KPERF_SAMPLING_SHUTDOWN) {
			kptimer_stop_curcpu(processor);
			return;
		} else if (kperf_status == KPERF_SAMPLING_OFF) {
			panic("kperf: timer fired at %llu, but sampling is disabled", now);
		} else {
			panic("kperf: unknown sampling state 0x%x", kperf_status);
		}
	}

	for (unsigned int i = 0; i < kptimer.g_ntimers; i++) {
		struct kptimer *timer = &kptimer.g_timers[i];
		if (timer->kt_period_abs == 0) {
			continue;
		}

		uint64_t cpudeadline = kptimer_get_cpu_deadline(cpuid, i);
		if (now > cpudeadline) {
			uint64_t deadline = kptimer_fire(timer, i, cpudeadline, cpuid, now);
			if (deadline == 0) {
				kptimer_set_cpu_deadline(cpuid, i, EndOfAllTime);
			} else {
				kptimer_set_cpu_deadline(cpuid, i, deadline);
				if (deadline < min_deadline) {
					min_deadline = deadline;
				}
			}
		}
	}
	if (min_deadline < UINT64_MAX) {
		running_timer_enter(processor, RUNNING_TIMER_KPERF, NULL,
		    min_deadline, mach_absolute_time());
	}
}

#pragma mark - start/stop

static void
kptimer_broadcast(void (*fn)(void *))
{
	ktrace_assert_lock_held();

#if defined(__x86_64__)
	(void)mp_cpus_call(CPUMASK_ALL, ASYNC, fn, NULL);
#else /* defined(__x86_64__) */
	_Atomic uint32_t xcsync = 0;
	cpu_broadcast_xcall((uint32_t *)&xcsync, TRUE /* include self */, fn,
	    &xcsync);
#endif /* !defined(__x86_64__) */
}

static void
kptimer_broadcast_ack(void *arg)
{
#if defined(__x86_64__)
#pragma unused(arg)
#else /* defined(__x86_64__) */
	_Atomic uint32_t *xcsync = arg;
	int pending = os_atomic_dec(xcsync, relaxed);
	if (pending == 0) {
		thread_wakeup(xcsync);
	}
#endif /* !defined(__x86_64__) */
}

static void
kptimer_sample_pet_remote(void * __unused arg)
{
	if (!kperf_is_sampling()) {
		return;
	}
	struct kptimer *timer = &kptimer.g_timers[kptimer.g_pet_timerid];
	kptimer_sample_curcpu(timer->kt_actionid, kptimer.g_pet_timerid, 0);
}

#if !defined(__x86_64__)

#include <arm/cpu_internal.h>

void kperf_signal_handler(void);
void
kperf_signal_handler(void)
{
	kptimer_sample_pet_remote(NULL);
}

#endif /* !defined(__x86_64__) */

#include <stdatomic.h>
_Atomic uint64_t mycounter = 0;

static void
kptimer_broadcast_pet(void)
{
	atomic_fetch_add(&mycounter, 1);
#if defined(__x86_64__)
	(void)mp_cpus_call(CPUMASK_OTHERS, NOSYNC, kptimer_sample_pet_remote,
	    NULL);
#else /* defined(__x86_64__) */
	int curcpu = cpu_number();
	for (int i = 0; i < machine_info.logical_cpu_max; i++) {
		if (i != curcpu) {
			cpu_signal(cpu_datap(i), SIGPkppet, NULL, NULL);
		}
	}
#endif /* !defined(__x86_64__) */
}

static void
kptimer_pet_handler(void * __unused param1, void * __unused param2)
{
	if (!kptimer.g_pet_active) {
		return;
	}

	struct kptimer *timer = &kptimer.g_timers[kptimer.g_pet_timerid];

	BUF_DATA(PERF_TM_FIRE, kptimer.g_pet_timerid, 1, timer->kt_period_abs,
	    timer->kt_actionid);

	/*
	 * To get the on-CPU samples as close to this timer fire as possible, first
	 * broadcast to them to sample themselves.
	 */
	kptimer_broadcast_pet();

	/*
	 * Wakeup the PET thread afterwards so it's not inadvertently sampled (it's a
	 * high-priority kernel thread).  If the scheduler needs to IPI to run it,
	 * that IPI will be handled after the IPIs issued during the broadcast.
	 */
	kppet_wake_thread();

	/*
	 * Finally, sample this CPU, who's stacks and state have been preserved while
	 * running this handler.  Make sure to include system measurements.
	 */
	kptimer_sample_curcpu(timer->kt_actionid, kptimer.g_pet_timerid,
	    SAMPLE_FLAG_SYSTEM);

	BUF_INFO(PERF_TM_FIRE | DBG_FUNC_END);

	/*
	 * The PET thread will re-arm the timer when it's done.
	 */
}

void
kptimer_pet_enter(uint64_t sampledur_abs)
{
	if (!kperf_is_sampling()) {
		return;
	}

	uint64_t period_abs = kptimer.g_timers[kptimer.g_pet_timerid].kt_period_abs;
	uint64_t orig_period_abs = period_abs;

	if (period_abs > sampledur_abs) {
		period_abs -= sampledur_abs;
	}
	period_abs = MAX(kptimer_min_period_abs(true), period_abs);
	uint64_t deadline_abs = mach_absolute_time() + period_abs;

	BUF_INFO(PERF_PET_SCHED, orig_period_abs, period_abs, sampledur_abs,
	    deadline_abs);

	timer_call_enter(&kptimer.g_pet_timer, deadline_abs, TIMER_CALL_SYS_CRITICAL);
}

static uint64_t
kptimer_earliest_deadline(processor_t processor, uint64_t now)
{
	uint64_t min_deadline = UINT64_MAX;
	for (unsigned int i = 0; i < kptimer.g_ntimers; i++) {
		struct kptimer *timer = &kptimer.g_timers[i];
		uint64_t cur_deadline = timer->kt_cur_deadline;
		if (cur_deadline == 0) {
			continue;
		}
		cur_deadline = dead_reckon_deadline(now, cur_deadline,
		    timer->kt_period_abs);
		kptimer_set_cpu_deadline(processor->cpu_id, i, cur_deadline);
		if (cur_deadline < min_deadline) {
			min_deadline = cur_deadline;
		}
	}
	return min_deadline;
}

void kptimer_running_setup(processor_t processor, uint64_t now);
void
kptimer_running_setup(processor_t processor, uint64_t now)
{
	uint64_t deadline = kptimer_earliest_deadline(processor, now);
	if (deadline < UINT64_MAX) {
		running_timer_setup(processor, RUNNING_TIMER_KPERF, NULL, deadline,
		    now);
	}
}

static void
kptimer_start_remote(void *arg)
{
	processor_t processor = current_processor();
	uint64_t now = mach_absolute_time();
	uint64_t deadline = kptimer_earliest_deadline(processor, now);
	if (deadline < UINT64_MAX) {
		running_timer_enter(processor, RUNNING_TIMER_KPERF, NULL, deadline,
		    now);
	}
	kptimer_broadcast_ack(arg);
}

static void
kptimer_stop_curcpu(processor_t processor)
{
	for (unsigned int i = 0; i < kptimer.g_ntimers; i++) {
		kptimer_set_cpu_deadline(processor->cpu_id, i, EndOfAllTime);
	}
	running_timer_cancel(processor, RUNNING_TIMER_KPERF);
}

static void
kptimer_stop_remote(void * __unused arg)
{
	assert(ml_get_interrupts_enabled() == FALSE);
	kptimer_stop_curcpu(current_processor());
	kptimer_broadcast_ack(arg);
}

void
kptimer_start(void)
{
	ktrace_assert_lock_held();

	if (kptimer.g_started) {
		return;
	}

	uint64_t now = mach_absolute_time();
	unsigned int ntimers_active = 0;
	kptimer.g_started = true;
	for (unsigned int i = 0; i < kptimer.g_ntimers; i++) {
		struct kptimer *timer = &kptimer.g_timers[i];
		if (timer->kt_period_abs == 0 || timer->kt_actionid == 0) {
			/*
			 * No period or action means the timer is inactive.
			 */
			continue;
		} else if (!kppet_get_lightweight_pet() &&
		    i == kptimer.g_pet_timerid) {
			kptimer.g_pet_active = true;
			timer_call_enter(&kptimer.g_pet_timer, now + timer->kt_period_abs,
			    TIMER_CALL_SYS_CRITICAL);
		} else {
			timer->kt_cur_deadline = now + timer->kt_period_abs;
			ntimers_active++;
		}
	}
	if (ntimers_active > 0) {
		kptimer_broadcast(kptimer_start_remote);
	}
}

void
kptimer_stop(void)
{
	ktrace_assert_lock_held();

	if (!kptimer.g_started) {
		return;
	}

	int intrs_en = ml_set_interrupts_enabled(FALSE);

	if (kptimer.g_pet_active) {
		kptimer.g_pet_active = false;
		timer_call_cancel(&kptimer.g_pet_timer);
	}
	kptimer.g_started = false;
	kptimer_broadcast(kptimer_stop_remote);
	for (unsigned int i = 0; i < kptimer.g_ntimers; i++) {
		kptimer.g_timers[i].kt_cur_deadline = 0;
	}

	ml_set_interrupts_enabled(intrs_en);
}

#pragma mark - accessors

int
kptimer_get_period(unsigned int timerid, uint64_t *period_abs)
{
	if (timerid >= kptimer.g_ntimers) {
		return EINVAL;
	}
	*period_abs = kptimer.g_timers[timerid].kt_period_abs;
	return 0;
}

int
kptimer_set_period(unsigned int timerid, uint64_t period_abs)
{
	if (timerid >= kptimer.g_ntimers) {
		return EINVAL;
	}
	if (kptimer.g_started) {
		return EBUSY;
	}

	bool pet = kptimer.g_pet_timerid == timerid;
	uint64_t min_period = kptimer_min_period_abs(pet);
	if (period_abs != 0 && period_abs < min_period) {
		period_abs = min_period;
	}
	if (pet && !kppet_get_lightweight_pet()) {
		kppet_config(kptimer.g_timers[timerid].kt_actionid);
	}

	kptimer.g_timers[timerid].kt_period_abs = period_abs;
	return 0;
}

int
kptimer_get_action(unsigned int timerid, unsigned int *actionid)
{
	if (timerid >= kptimer.g_ntimers) {
		return EINVAL;
	}
	*actionid = kptimer.g_timers[timerid].kt_actionid;
	return 0;
}

int
kptimer_set_action(unsigned int timerid, unsigned int actionid)
{
	if (timerid >= kptimer.g_ntimers) {
		return EINVAL;
	}
	if (kptimer.g_started) {
		return EBUSY;
	}

	kptimer.g_timers[timerid].kt_actionid = actionid;
	if (kptimer.g_pet_timerid == timerid && !kppet_get_lightweight_pet()) {
		kppet_config(actionid);
	}
	return 0;
}

unsigned int
kptimer_get_count(void)
{
	return kptimer.g_ntimers;
}

int
kptimer_set_count(unsigned int count)
{
	kptimer_setup();
	if (kptimer.g_started) {
		return EBUSY;
	}
	if (count > KPTIMER_MAX) {
		return EINVAL;
	}
	kptimer.g_ntimers = count;
	return 0;
}

uint64_t
kptimer_min_period_abs(bool pet)
{
	enum kptimer_period_limit limit = 0;
	if (ktrace_background_active()) {
		limit = pet ? KTPL_BG_PET : KTPL_BG;
	} else {
		limit = pet ? KTPL_FG_PET : KTPL_FG;
	}
	return kptimer_minperiods_mtu[limit];
}

uint32_t
kptimer_get_pet_timerid(void)
{
	return kptimer.g_pet_timerid;
}

int
kptimer_set_pet_timerid(uint32_t petid)
{
	if (kptimer.g_started) {
		return EBUSY;
	}
	if (petid >= kptimer.g_ntimers) {
		kppet_config(0);
	} else {
		kppet_config(kptimer.g_timers[petid].kt_actionid);
		uint64_t period_abs = MAX(kptimer_min_period_abs(true),
		    kptimer.g_timers[petid].kt_period_abs);
		kptimer.g_timers[petid].kt_period_abs = period_abs;
	}

	kptimer.g_pet_timerid = petid;

	return 0;
}

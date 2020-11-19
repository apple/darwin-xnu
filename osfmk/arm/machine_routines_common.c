/*
 * Copyright (c) 2007-2013 Apple Inc. All rights reserved.
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

#include <arm/machine_cpu.h>
#include <arm/cpu_internal.h>
#include <arm/cpuid.h>
#include <arm/cpu_data.h>
#include <arm/cpu_data_internal.h>
#include <arm/misc_protos.h>
#include <arm/machdep_call.h>
#include <arm/machine_routines.h>
#include <arm/rtclock.h>
#include <kern/machine.h>
#include <kern/thread.h>
#include <kern/thread_group.h>
#include <kern/policy_internal.h>
#include <kern/startup.h>
#include <machine/config.h>
#include <machine/atomic.h>
#include <pexpert/pexpert.h>

#if MONOTONIC
#include <kern/monotonic.h>
#include <machine/monotonic.h>
#endif /* MONOTONIC */

#include <mach/machine.h>

#if !HAS_CONTINUOUS_HWCLOCK
extern uint64_t mach_absolutetime_asleep;
#else
extern uint64_t wake_abstime;
static uint64_t wake_conttime = UINT64_MAX;
#endif

extern volatile uint32_t debug_enabled;

static int max_cpus_initialized = 0;
#define MAX_CPUS_SET    0x1
#define MAX_CPUS_WAIT   0x2

LCK_GRP_DECLARE(max_cpus_grp, "max_cpus");
LCK_MTX_DECLARE(max_cpus_lock, &max_cpus_grp);
uint32_t lockdown_done = 0;
boolean_t is_clock_configured = FALSE;


static void
sched_perfcontrol_oncore_default(perfcontrol_state_t new_thread_state __unused, going_on_core_t on __unused)
{
}

static void
sched_perfcontrol_switch_default(perfcontrol_state_t old_thread_state __unused, perfcontrol_state_t new_thread_state __unused)
{
}

static void
sched_perfcontrol_offcore_default(perfcontrol_state_t old_thread_state __unused, going_off_core_t off __unused, boolean_t thread_terminating __unused)
{
}

static void
sched_perfcontrol_thread_group_default(thread_group_data_t data __unused)
{
}

static void
sched_perfcontrol_max_runnable_latency_default(perfcontrol_max_runnable_latency_t latencies __unused)
{
}

static void
sched_perfcontrol_work_interval_notify_default(perfcontrol_state_t thread_state __unused,
    perfcontrol_work_interval_t work_interval __unused)
{
}

static void
sched_perfcontrol_work_interval_ctl_default(perfcontrol_state_t thread_state __unused,
    perfcontrol_work_interval_instance_t instance __unused)
{
}

static void
sched_perfcontrol_deadline_passed_default(__unused uint64_t deadline)
{
}

static void
sched_perfcontrol_csw_default(
	__unused perfcontrol_event event, __unused uint32_t cpu_id, __unused uint64_t timestamp,
	__unused uint32_t flags, __unused struct perfcontrol_thread_data *offcore,
	__unused struct perfcontrol_thread_data *oncore,
	__unused struct perfcontrol_cpu_counters *cpu_counters, __unused void *unused)
{
}

static void
sched_perfcontrol_state_update_default(
	__unused perfcontrol_event event, __unused uint32_t cpu_id, __unused uint64_t timestamp,
	__unused uint32_t flags, __unused struct perfcontrol_thread_data *thr_data,
	__unused void *unused)
{
}

static void
sched_perfcontrol_thread_group_blocked_default(
	__unused thread_group_data_t blocked_tg, __unused thread_group_data_t blocking_tg,
	__unused uint32_t flags, __unused perfcontrol_state_t blocked_thr_state)
{
}

static void
sched_perfcontrol_thread_group_unblocked_default(
	__unused thread_group_data_t unblocked_tg, __unused thread_group_data_t unblocking_tg,
	__unused uint32_t flags, __unused perfcontrol_state_t unblocked_thr_state)
{
}

sched_perfcontrol_offcore_t                     sched_perfcontrol_offcore = sched_perfcontrol_offcore_default;
sched_perfcontrol_context_switch_t              sched_perfcontrol_switch = sched_perfcontrol_switch_default;
sched_perfcontrol_oncore_t                      sched_perfcontrol_oncore = sched_perfcontrol_oncore_default;
sched_perfcontrol_thread_group_init_t           sched_perfcontrol_thread_group_init = sched_perfcontrol_thread_group_default;
sched_perfcontrol_thread_group_deinit_t         sched_perfcontrol_thread_group_deinit = sched_perfcontrol_thread_group_default;
sched_perfcontrol_thread_group_flags_update_t   sched_perfcontrol_thread_group_flags_update = sched_perfcontrol_thread_group_default;
sched_perfcontrol_max_runnable_latency_t        sched_perfcontrol_max_runnable_latency = sched_perfcontrol_max_runnable_latency_default;
sched_perfcontrol_work_interval_notify_t        sched_perfcontrol_work_interval_notify = sched_perfcontrol_work_interval_notify_default;
sched_perfcontrol_work_interval_ctl_t           sched_perfcontrol_work_interval_ctl = sched_perfcontrol_work_interval_ctl_default;
sched_perfcontrol_deadline_passed_t             sched_perfcontrol_deadline_passed = sched_perfcontrol_deadline_passed_default;
sched_perfcontrol_csw_t                         sched_perfcontrol_csw = sched_perfcontrol_csw_default;
sched_perfcontrol_state_update_t                sched_perfcontrol_state_update = sched_perfcontrol_state_update_default;
sched_perfcontrol_thread_group_blocked_t        sched_perfcontrol_thread_group_blocked = sched_perfcontrol_thread_group_blocked_default;
sched_perfcontrol_thread_group_unblocked_t      sched_perfcontrol_thread_group_unblocked = sched_perfcontrol_thread_group_unblocked_default;

void
sched_perfcontrol_register_callbacks(sched_perfcontrol_callbacks_t callbacks, unsigned long size_of_state)
{
	assert(callbacks == NULL || callbacks->version >= SCHED_PERFCONTROL_CALLBACKS_VERSION_2);

	if (size_of_state > sizeof(struct perfcontrol_state)) {
		panic("%s: Invalid required state size %lu", __FUNCTION__, size_of_state);
	}

	if (callbacks) {
#if CONFIG_THREAD_GROUPS
		if (callbacks->version >= SCHED_PERFCONTROL_CALLBACKS_VERSION_3) {
			if (callbacks->thread_group_init != NULL) {
				sched_perfcontrol_thread_group_init = callbacks->thread_group_init;
			} else {
				sched_perfcontrol_thread_group_init = sched_perfcontrol_thread_group_default;
			}
			if (callbacks->thread_group_deinit != NULL) {
				sched_perfcontrol_thread_group_deinit = callbacks->thread_group_deinit;
			} else {
				sched_perfcontrol_thread_group_deinit = sched_perfcontrol_thread_group_default;
			}
			// tell CLPC about existing thread groups
			thread_group_resync(TRUE);
		}

		if (callbacks->version >= SCHED_PERFCONTROL_CALLBACKS_VERSION_6) {
			if (callbacks->thread_group_flags_update != NULL) {
				sched_perfcontrol_thread_group_flags_update = callbacks->thread_group_flags_update;
			} else {
				sched_perfcontrol_thread_group_flags_update = sched_perfcontrol_thread_group_default;
			}
		}

		if (callbacks->version >= SCHED_PERFCONTROL_CALLBACKS_VERSION_8) {
			if (callbacks->thread_group_blocked != NULL) {
				sched_perfcontrol_thread_group_blocked = callbacks->thread_group_blocked;
			} else {
				sched_perfcontrol_thread_group_blocked = sched_perfcontrol_thread_group_blocked_default;
			}

			if (callbacks->thread_group_unblocked != NULL) {
				sched_perfcontrol_thread_group_unblocked = callbacks->thread_group_unblocked;
			} else {
				sched_perfcontrol_thread_group_unblocked = sched_perfcontrol_thread_group_unblocked_default;
			}
		}
#endif

		if (callbacks->version >= SCHED_PERFCONTROL_CALLBACKS_VERSION_7) {
			if (callbacks->work_interval_ctl != NULL) {
				sched_perfcontrol_work_interval_ctl = callbacks->work_interval_ctl;
			} else {
				sched_perfcontrol_work_interval_ctl = sched_perfcontrol_work_interval_ctl_default;
			}
		}

		if (callbacks->version >= SCHED_PERFCONTROL_CALLBACKS_VERSION_5) {
			if (callbacks->csw != NULL) {
				sched_perfcontrol_csw = callbacks->csw;
			} else {
				sched_perfcontrol_csw = sched_perfcontrol_csw_default;
			}

			if (callbacks->state_update != NULL) {
				sched_perfcontrol_state_update = callbacks->state_update;
			} else {
				sched_perfcontrol_state_update = sched_perfcontrol_state_update_default;
			}
		}

		if (callbacks->version >= SCHED_PERFCONTROL_CALLBACKS_VERSION_4) {
			if (callbacks->deadline_passed != NULL) {
				sched_perfcontrol_deadline_passed = callbacks->deadline_passed;
			} else {
				sched_perfcontrol_deadline_passed = sched_perfcontrol_deadline_passed_default;
			}
		}

		if (callbacks->offcore != NULL) {
			sched_perfcontrol_offcore = callbacks->offcore;
		} else {
			sched_perfcontrol_offcore = sched_perfcontrol_offcore_default;
		}

		if (callbacks->context_switch != NULL) {
			sched_perfcontrol_switch = callbacks->context_switch;
		} else {
			sched_perfcontrol_switch = sched_perfcontrol_switch_default;
		}

		if (callbacks->oncore != NULL) {
			sched_perfcontrol_oncore = callbacks->oncore;
		} else {
			sched_perfcontrol_oncore = sched_perfcontrol_oncore_default;
		}

		if (callbacks->max_runnable_latency != NULL) {
			sched_perfcontrol_max_runnable_latency = callbacks->max_runnable_latency;
		} else {
			sched_perfcontrol_max_runnable_latency = sched_perfcontrol_max_runnable_latency_default;
		}

		if (callbacks->work_interval_notify != NULL) {
			sched_perfcontrol_work_interval_notify = callbacks->work_interval_notify;
		} else {
			sched_perfcontrol_work_interval_notify = sched_perfcontrol_work_interval_notify_default;
		}
	} else {
		/* reset to defaults */
#if CONFIG_THREAD_GROUPS
		thread_group_resync(FALSE);
#endif
		sched_perfcontrol_offcore = sched_perfcontrol_offcore_default;
		sched_perfcontrol_switch = sched_perfcontrol_switch_default;
		sched_perfcontrol_oncore = sched_perfcontrol_oncore_default;
		sched_perfcontrol_thread_group_init = sched_perfcontrol_thread_group_default;
		sched_perfcontrol_thread_group_deinit = sched_perfcontrol_thread_group_default;
		sched_perfcontrol_thread_group_flags_update = sched_perfcontrol_thread_group_default;
		sched_perfcontrol_max_runnable_latency = sched_perfcontrol_max_runnable_latency_default;
		sched_perfcontrol_work_interval_notify = sched_perfcontrol_work_interval_notify_default;
		sched_perfcontrol_work_interval_ctl = sched_perfcontrol_work_interval_ctl_default;
		sched_perfcontrol_csw = sched_perfcontrol_csw_default;
		sched_perfcontrol_state_update = sched_perfcontrol_state_update_default;
		sched_perfcontrol_thread_group_blocked = sched_perfcontrol_thread_group_blocked_default;
		sched_perfcontrol_thread_group_unblocked = sched_perfcontrol_thread_group_unblocked_default;
	}
}


static void
machine_switch_populate_perfcontrol_thread_data(struct perfcontrol_thread_data *data,
    thread_t thread,
    uint64_t same_pri_latency)
{
	bzero(data, sizeof(struct perfcontrol_thread_data));
	data->perfctl_class = thread_get_perfcontrol_class(thread);
	data->energy_estimate_nj = 0;
	data->thread_id = thread->thread_id;
#if CONFIG_THREAD_GROUPS
	struct thread_group *tg = thread_group_get(thread);
	data->thread_group_id = thread_group_get_id(tg);
	data->thread_group_data = thread_group_get_machine_data(tg);
#endif
	data->scheduling_latency_at_same_basepri = same_pri_latency;
	data->perfctl_state = FIND_PERFCONTROL_STATE(thread);
}

static void
machine_switch_populate_perfcontrol_cpu_counters(struct perfcontrol_cpu_counters *cpu_counters)
{
#if MONOTONIC
	mt_perfcontrol(&cpu_counters->instructions, &cpu_counters->cycles);
#else /* MONOTONIC */
	cpu_counters->instructions = 0;
	cpu_counters->cycles = 0;
#endif /* !MONOTONIC */
}

int perfcontrol_callout_stats_enabled = 0;
static _Atomic uint64_t perfcontrol_callout_stats[PERFCONTROL_CALLOUT_MAX][PERFCONTROL_STAT_MAX];
static _Atomic uint64_t perfcontrol_callout_count[PERFCONTROL_CALLOUT_MAX];

#if MONOTONIC
static inline
bool
perfcontrol_callout_counters_begin(uint64_t *counters)
{
	if (!perfcontrol_callout_stats_enabled) {
		return false;
	}
	mt_fixed_counts(counters);
	return true;
}

static inline
void
perfcontrol_callout_counters_end(uint64_t *start_counters,
    perfcontrol_callout_type_t type)
{
	uint64_t end_counters[MT_CORE_NFIXED];
	mt_fixed_counts(end_counters);
	os_atomic_add(&perfcontrol_callout_stats[type][PERFCONTROL_STAT_CYCLES],
	    end_counters[MT_CORE_CYCLES] - start_counters[MT_CORE_CYCLES], relaxed);
#ifdef MT_CORE_INSTRS
	os_atomic_add(&perfcontrol_callout_stats[type][PERFCONTROL_STAT_INSTRS],
	    end_counters[MT_CORE_INSTRS] - start_counters[MT_CORE_INSTRS], relaxed);
#endif /* defined(MT_CORE_INSTRS) */
	os_atomic_inc(&perfcontrol_callout_count[type], relaxed);
}
#endif /* MONOTONIC */

uint64_t
perfcontrol_callout_stat_avg(perfcontrol_callout_type_t type,
    perfcontrol_callout_stat_t stat)
{
	if (!perfcontrol_callout_stats_enabled) {
		return 0;
	}
	return os_atomic_load_wide(&perfcontrol_callout_stats[type][stat], relaxed) /
	       os_atomic_load_wide(&perfcontrol_callout_count[type], relaxed);
}


void
machine_switch_perfcontrol_context(perfcontrol_event event,
    uint64_t timestamp,
    uint32_t flags,
    uint64_t new_thread_same_pri_latency,
    thread_t old,
    thread_t new)
{

	if (sched_perfcontrol_switch != sched_perfcontrol_switch_default) {
		perfcontrol_state_t old_perfcontrol_state = FIND_PERFCONTROL_STATE(old);
		perfcontrol_state_t new_perfcontrol_state = FIND_PERFCONTROL_STATE(new);
		sched_perfcontrol_switch(old_perfcontrol_state, new_perfcontrol_state);
	}

	if (sched_perfcontrol_csw != sched_perfcontrol_csw_default) {
		uint32_t cpu_id = (uint32_t)cpu_number();
		struct perfcontrol_cpu_counters cpu_counters;
		struct perfcontrol_thread_data offcore, oncore;
		machine_switch_populate_perfcontrol_thread_data(&offcore, old, 0);
		machine_switch_populate_perfcontrol_thread_data(&oncore, new,
		    new_thread_same_pri_latency);
		machine_switch_populate_perfcontrol_cpu_counters(&cpu_counters);

#if MONOTONIC
		uint64_t counters[MT_CORE_NFIXED];
		bool ctrs_enabled = perfcontrol_callout_counters_begin(counters);
#endif /* MONOTONIC */
		sched_perfcontrol_csw(event, cpu_id, timestamp, flags,
		    &offcore, &oncore, &cpu_counters, NULL);
#if MONOTONIC
		if (ctrs_enabled) {
			perfcontrol_callout_counters_end(counters, PERFCONTROL_CALLOUT_CONTEXT);
		}
#endif /* MONOTONIC */

#if __arm64__
		old->machine.energy_estimate_nj += offcore.energy_estimate_nj;
		new->machine.energy_estimate_nj += oncore.energy_estimate_nj;
#endif
	}
}

void
machine_switch_perfcontrol_state_update(perfcontrol_event event,
    uint64_t timestamp,
    uint32_t flags,
    thread_t thread)
{

	if (sched_perfcontrol_state_update == sched_perfcontrol_state_update_default) {
		return;
	}
	uint32_t cpu_id = (uint32_t)cpu_number();
	struct perfcontrol_thread_data data;
	machine_switch_populate_perfcontrol_thread_data(&data, thread, 0);

#if MONOTONIC
	uint64_t counters[MT_CORE_NFIXED];
	bool ctrs_enabled = perfcontrol_callout_counters_begin(counters);
#endif /* MONOTONIC */
	sched_perfcontrol_state_update(event, cpu_id, timestamp, flags,
	    &data, NULL);
#if MONOTONIC
	if (ctrs_enabled) {
		perfcontrol_callout_counters_end(counters, PERFCONTROL_CALLOUT_STATE_UPDATE);
	}
#endif /* MONOTONIC */

#if __arm64__
	thread->machine.energy_estimate_nj += data.energy_estimate_nj;
#endif
}

void
machine_thread_going_on_core(thread_t   new_thread,
    thread_urgency_t        urgency,
    uint64_t   sched_latency,
    uint64_t   same_pri_latency,
    uint64_t   timestamp)
{
	if (sched_perfcontrol_oncore == sched_perfcontrol_oncore_default) {
		return;
	}
	struct going_on_core on_core;
	perfcontrol_state_t state = FIND_PERFCONTROL_STATE(new_thread);

	on_core.thread_id = new_thread->thread_id;
	on_core.energy_estimate_nj = 0;
	on_core.qos_class = (uint16_t)proc_get_effective_thread_policy(new_thread, TASK_POLICY_QOS);
	on_core.urgency = (uint16_t)urgency;
	on_core.is_32_bit = thread_is_64bit_data(new_thread) ? FALSE : TRUE;
	on_core.is_kernel_thread = new_thread->task == kernel_task;
#if CONFIG_THREAD_GROUPS
	struct thread_group *tg = thread_group_get(new_thread);
	on_core.thread_group_id = thread_group_get_id(tg);
	on_core.thread_group_data = thread_group_get_machine_data(tg);
#endif
	on_core.scheduling_latency = sched_latency;
	on_core.start_time = timestamp;
	on_core.scheduling_latency_at_same_basepri = same_pri_latency;

#if MONOTONIC
	uint64_t counters[MT_CORE_NFIXED];
	bool ctrs_enabled = perfcontrol_callout_counters_begin(counters);
#endif /* MONOTONIC */
	sched_perfcontrol_oncore(state, &on_core);
#if MONOTONIC
	if (ctrs_enabled) {
		perfcontrol_callout_counters_end(counters, PERFCONTROL_CALLOUT_ON_CORE);
	}
#endif /* MONOTONIC */

#if __arm64__
	new_thread->machine.energy_estimate_nj += on_core.energy_estimate_nj;
#endif
}

void
machine_thread_going_off_core(thread_t old_thread, boolean_t thread_terminating,
    uint64_t last_dispatch, __unused boolean_t thread_runnable)
{
	if (sched_perfcontrol_offcore == sched_perfcontrol_offcore_default) {
		return;
	}
	struct going_off_core off_core;
	perfcontrol_state_t state = FIND_PERFCONTROL_STATE(old_thread);

	off_core.thread_id = old_thread->thread_id;
	off_core.energy_estimate_nj = 0;
	off_core.end_time = last_dispatch;
#if CONFIG_THREAD_GROUPS
	struct thread_group *tg = thread_group_get(old_thread);
	off_core.thread_group_id = thread_group_get_id(tg);
	off_core.thread_group_data = thread_group_get_machine_data(tg);
#endif

#if MONOTONIC
	uint64_t counters[MT_CORE_NFIXED];
	bool ctrs_enabled = perfcontrol_callout_counters_begin(counters);
#endif /* MONOTONIC */
	sched_perfcontrol_offcore(state, &off_core, thread_terminating);
#if MONOTONIC
	if (ctrs_enabled) {
		perfcontrol_callout_counters_end(counters, PERFCONTROL_CALLOUT_OFF_CORE);
	}
#endif /* MONOTONIC */

#if __arm64__
	old_thread->machine.energy_estimate_nj += off_core.energy_estimate_nj;
#endif
}

#if CONFIG_THREAD_GROUPS
void
machine_thread_group_init(struct thread_group *tg)
{
	if (sched_perfcontrol_thread_group_init == sched_perfcontrol_thread_group_default) {
		return;
	}
	struct thread_group_data data;
	data.thread_group_id = thread_group_get_id(tg);
	data.thread_group_data = thread_group_get_machine_data(tg);
	data.thread_group_size = thread_group_machine_data_size();
	sched_perfcontrol_thread_group_init(&data);
}

void
machine_thread_group_deinit(struct thread_group *tg)
{
	if (sched_perfcontrol_thread_group_deinit == sched_perfcontrol_thread_group_default) {
		return;
	}
	struct thread_group_data data;
	data.thread_group_id = thread_group_get_id(tg);
	data.thread_group_data = thread_group_get_machine_data(tg);
	data.thread_group_size = thread_group_machine_data_size();
	sched_perfcontrol_thread_group_deinit(&data);
}

void
machine_thread_group_flags_update(struct thread_group *tg, uint32_t flags)
{
	if (sched_perfcontrol_thread_group_flags_update == sched_perfcontrol_thread_group_default) {
		return;
	}
	struct thread_group_data data;
	data.thread_group_id = thread_group_get_id(tg);
	data.thread_group_data = thread_group_get_machine_data(tg);
	data.thread_group_size = thread_group_machine_data_size();
	data.thread_group_flags = flags;
	sched_perfcontrol_thread_group_flags_update(&data);
}

void
machine_thread_group_blocked(struct thread_group *blocked_tg,
    struct thread_group *blocking_tg,
    uint32_t flags,
    thread_t blocked_thread)
{
	if (sched_perfcontrol_thread_group_blocked == sched_perfcontrol_thread_group_blocked_default) {
		return;
	}

	spl_t s = splsched();

	perfcontrol_state_t state = FIND_PERFCONTROL_STATE(blocked_thread);
	struct thread_group_data blocked_data;
	assert(blocked_tg != NULL);

	blocked_data.thread_group_id = thread_group_get_id(blocked_tg);
	blocked_data.thread_group_data = thread_group_get_machine_data(blocked_tg);
	blocked_data.thread_group_size = thread_group_machine_data_size();

	if (blocking_tg == NULL) {
		/*
		 * For special cases such as the render server, the blocking TG is a
		 * well known TG. Only in that case, the blocking_tg should be NULL.
		 */
		assert(flags & PERFCONTROL_CALLOUT_BLOCKING_TG_RENDER_SERVER);
		sched_perfcontrol_thread_group_blocked(&blocked_data, NULL, flags, state);
	} else {
		struct thread_group_data blocking_data;
		blocking_data.thread_group_id = thread_group_get_id(blocking_tg);
		blocking_data.thread_group_data = thread_group_get_machine_data(blocking_tg);
		blocking_data.thread_group_size = thread_group_machine_data_size();
		sched_perfcontrol_thread_group_blocked(&blocked_data, &blocking_data, flags, state);
	}
	KDBG(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_BLOCK) | DBG_FUNC_START,
	    thread_tid(blocked_thread), thread_group_get_id(blocked_tg),
	    blocking_tg ? thread_group_get_id(blocking_tg) : THREAD_GROUP_INVALID,
	    flags);

	splx(s);
}

void
machine_thread_group_unblocked(struct thread_group *unblocked_tg,
    struct thread_group *unblocking_tg,
    uint32_t flags,
    thread_t unblocked_thread)
{
	if (sched_perfcontrol_thread_group_unblocked == sched_perfcontrol_thread_group_unblocked_default) {
		return;
	}

	spl_t s = splsched();

	perfcontrol_state_t state = FIND_PERFCONTROL_STATE(unblocked_thread);
	struct thread_group_data unblocked_data;
	assert(unblocked_tg != NULL);

	unblocked_data.thread_group_id = thread_group_get_id(unblocked_tg);
	unblocked_data.thread_group_data = thread_group_get_machine_data(unblocked_tg);
	unblocked_data.thread_group_size = thread_group_machine_data_size();

	if (unblocking_tg == NULL) {
		/*
		 * For special cases such as the render server, the unblocking TG is a
		 * well known TG. Only in that case, the unblocking_tg should be NULL.
		 */
		assert(flags & PERFCONTROL_CALLOUT_BLOCKING_TG_RENDER_SERVER);
		sched_perfcontrol_thread_group_unblocked(&unblocked_data, NULL, flags, state);
	} else {
		struct thread_group_data unblocking_data;
		unblocking_data.thread_group_id = thread_group_get_id(unblocking_tg);
		unblocking_data.thread_group_data = thread_group_get_machine_data(unblocking_tg);
		unblocking_data.thread_group_size = thread_group_machine_data_size();
		sched_perfcontrol_thread_group_unblocked(&unblocked_data, &unblocking_data, flags, state);
	}
	KDBG(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_BLOCK) | DBG_FUNC_END,
	    thread_tid(unblocked_thread), thread_group_get_id(unblocked_tg),
	    unblocking_tg ? thread_group_get_id(unblocking_tg) : THREAD_GROUP_INVALID,
	    flags);

	splx(s);
}

#endif /* CONFIG_THREAD_GROUPS */

void
machine_max_runnable_latency(uint64_t bg_max_latency,
    uint64_t default_max_latency,
    uint64_t realtime_max_latency)
{
	if (sched_perfcontrol_max_runnable_latency == sched_perfcontrol_max_runnable_latency_default) {
		return;
	}
	struct perfcontrol_max_runnable_latency latencies = {
		.max_scheduling_latencies = {
			[THREAD_URGENCY_NONE] = 0,
			[THREAD_URGENCY_BACKGROUND] = bg_max_latency,
			[THREAD_URGENCY_NORMAL] = default_max_latency,
			[THREAD_URGENCY_REAL_TIME] = realtime_max_latency
		}
	};

	sched_perfcontrol_max_runnable_latency(&latencies);
}

void
machine_work_interval_notify(thread_t thread,
    struct kern_work_interval_args* kwi_args)
{
	if (sched_perfcontrol_work_interval_notify == sched_perfcontrol_work_interval_notify_default) {
		return;
	}
	perfcontrol_state_t state = FIND_PERFCONTROL_STATE(thread);
	struct perfcontrol_work_interval work_interval = {
		.thread_id      = thread->thread_id,
		.qos_class      = (uint16_t)proc_get_effective_thread_policy(thread, TASK_POLICY_QOS),
		.urgency        = kwi_args->urgency,
		.flags          = kwi_args->notify_flags,
		.work_interval_id = kwi_args->work_interval_id,
		.start          = kwi_args->start,
		.finish         = kwi_args->finish,
		.deadline       = kwi_args->deadline,
		.next_start     = kwi_args->next_start,
		.create_flags   = kwi_args->create_flags,
	};
#if CONFIG_THREAD_GROUPS
	struct thread_group *tg;
	tg = thread_group_get(thread);
	work_interval.thread_group_id = thread_group_get_id(tg);
	work_interval.thread_group_data = thread_group_get_machine_data(tg);
#endif
	sched_perfcontrol_work_interval_notify(state, &work_interval);
}


void
machine_perfcontrol_deadline_passed(uint64_t deadline)
{
	if (sched_perfcontrol_deadline_passed != sched_perfcontrol_deadline_passed_default) {
		sched_perfcontrol_deadline_passed(deadline);
	}
}

#if INTERRUPT_MASKED_DEBUG
/*
 * ml_spin_debug_reset()
 * Reset the timestamp on a thread that has been unscheduled
 * to avoid false alarms. Alarm will go off if interrupts are held
 * disabled for too long, starting from now.
 *
 * Call ml_get_timebase() directly to prevent extra overhead on newer
 * platforms that's enabled in DEVELOPMENT kernel configurations.
 */
void
ml_spin_debug_reset(thread_t thread)
{
	if (thread->machine.intmask_timestamp) {
		thread->machine.intmask_timestamp = ml_get_timebase();
	}
}

/*
 * ml_spin_debug_clear()
 * Clear the timestamp on a thread that has been unscheduled
 * to avoid false alarms
 */
void
ml_spin_debug_clear(thread_t thread)
{
	thread->machine.intmask_timestamp = 0;
}

/*
 * ml_spin_debug_clear_self()
 * Clear the timestamp on the current thread to prevent
 * false alarms
 */
void
ml_spin_debug_clear_self()
{
	ml_spin_debug_clear(current_thread());
}

static inline void
__ml_check_interrupts_disabled_duration(thread_t thread, uint64_t timeout, bool is_int_handler)
{
	uint64_t start;
	uint64_t now;

	start = is_int_handler ? thread->machine.inthandler_timestamp : thread->machine.intmask_timestamp;
	if (start != 0) {
		now = ml_get_timebase();

		if ((now - start) > timeout * debug_cpu_performance_degradation_factor) {
			mach_timebase_info_data_t timebase;
			clock_timebase_info(&timebase);

#ifndef KASAN
			/*
			 * Disable the actual panic for KASAN due to the overhead of KASAN itself, leave the rest of the
			 * mechanism enabled so that KASAN can catch any bugs in the mechanism itself.
			 */
			if (is_int_handler) {
				panic("Processing of an interrupt (type = %u, handler address = %p, vector = %p) took %llu nanoseconds (timeout = %llu ns)",
				    thread->machine.int_type, (void *)thread->machine.int_handler_addr, (void *)thread->machine.int_vector,
				    (((now - start) * timebase.numer) / timebase.denom),
				    ((timeout * debug_cpu_performance_degradation_factor) * timebase.numer) / timebase.denom);
			} else {
				panic("Interrupts held disabled for %llu nanoseconds (timeout = %llu ns)",
				    (((now - start) * timebase.numer) / timebase.denom),
				    ((timeout * debug_cpu_performance_degradation_factor) * timebase.numer) / timebase.denom);
			}
#endif
		}
	}

	return;
}

void
ml_check_interrupts_disabled_duration(thread_t thread)
{
	__ml_check_interrupts_disabled_duration(thread, interrupt_masked_timeout, false);
}

void
ml_check_stackshot_interrupt_disabled_duration(thread_t thread)
{
	/* Use MAX() to let the user bump the timeout further if needed */
	__ml_check_interrupts_disabled_duration(thread, MAX(stackshot_interrupt_masked_timeout, interrupt_masked_timeout), false);
}

void
ml_check_interrupt_handler_duration(thread_t thread)
{
	__ml_check_interrupts_disabled_duration(thread, interrupt_masked_timeout, true);
}

void
ml_irq_debug_start(uintptr_t handler, uintptr_t vector)
{
	INTERRUPT_MASKED_DEBUG_START(handler, DBG_INTR_TYPE_OTHER);
	current_thread()->machine.int_vector = (uintptr_t)VM_KERNEL_STRIP_PTR(vector);
}

void
ml_irq_debug_end()
{
	INTERRUPT_MASKED_DEBUG_END();
}
#endif // INTERRUPT_MASKED_DEBUG


boolean_t
ml_set_interrupts_enabled(boolean_t enable)
{
	thread_t        thread;
	uint64_t        state;

#if __arm__
#define INTERRUPT_MASK PSR_IRQF
	state = __builtin_arm_rsr("cpsr");
#else
#define INTERRUPT_MASK DAIF_IRQF
	state = __builtin_arm_rsr("DAIF");
#endif
	if (enable && (state & INTERRUPT_MASK)) {
		assert(getCpuDatap()->cpu_int_state == NULL); // Make sure we're not enabling interrupts from primary interrupt context
#if INTERRUPT_MASKED_DEBUG
		if (interrupt_masked_debug) {
			// Interrupts are currently masked, we will enable them (after finishing this check)
			thread = current_thread();
			if (stackshot_active()) {
				ml_check_stackshot_interrupt_disabled_duration(thread);
			} else {
				ml_check_interrupts_disabled_duration(thread);
			}
			thread->machine.intmask_timestamp = 0;
		}
#endif  // INTERRUPT_MASKED_DEBUG
		if (get_preemption_level() == 0) {
			thread = current_thread();
			while (thread->machine.CpuDatap->cpu_pending_ast & AST_URGENT) {
#if __ARM_USER_PROTECT__
				uintptr_t up = arm_user_protect_begin(thread);
#endif
				ast_taken_kernel();
#if __ARM_USER_PROTECT__
				arm_user_protect_end(thread, up, FALSE);
#endif
			}
		}
#if __arm__
		__asm__ volatile ("cpsie if" ::: "memory"); // Enable IRQ FIQ
#else
		__builtin_arm_wsr("DAIFClr", DAIFSC_STANDARD_DISABLE);
#endif
	} else if (!enable && ((state & INTERRUPT_MASK) == 0)) {
#if __arm__
		__asm__ volatile ("cpsid if" ::: "memory"); // Mask IRQ FIQ
#else
		__builtin_arm_wsr("DAIFSet", DAIFSC_STANDARD_DISABLE);
#endif
#if INTERRUPT_MASKED_DEBUG
		if (interrupt_masked_debug) {
			// Interrupts were enabled, we just masked them
			current_thread()->machine.intmask_timestamp = ml_get_timebase();
		}
#endif
	}
	return (state & INTERRUPT_MASK) == 0;
}

boolean_t
ml_early_set_interrupts_enabled(boolean_t enable)
{
	return ml_set_interrupts_enabled(enable);
}

/*
 *	Routine:        ml_at_interrupt_context
 *	Function:	Check if running at interrupt context
 */
boolean_t
ml_at_interrupt_context(void)
{
	/* Do not use a stack-based check here, as the top-level exception handler
	 * is free to use some other stack besides the per-CPU interrupt stack.
	 * Interrupts should always be disabled if we're at interrupt context.
	 * Check that first, as we may be in a preemptible non-interrupt context, in
	 * which case we could be migrated to a different CPU between obtaining
	 * the per-cpu data pointer and loading cpu_int_state.  We then might end
	 * up checking the interrupt state of a different CPU, resulting in a false
	 * positive.  But if interrupts are disabled, we also know we cannot be
	 * preempted. */
	return !ml_get_interrupts_enabled() && (getCpuDatap()->cpu_int_state != NULL);
}

vm_offset_t
ml_stack_remaining(void)
{
	uintptr_t local = (uintptr_t) &local;
	vm_offset_t     intstack_top_ptr;

	/* Since this is a stack-based check, we don't need to worry about
	 * preemption as we do in ml_at_interrupt_context().  If we are preemptible,
	 * then the sp should never be within any CPU's interrupt stack unless
	 * something has gone horribly wrong. */
	intstack_top_ptr = getCpuDatap()->intstack_top;
	if ((local < intstack_top_ptr) && (local > intstack_top_ptr - INTSTACK_SIZE)) {
		return local - (getCpuDatap()->intstack_top - INTSTACK_SIZE);
	} else {
		return local - current_thread()->kernel_stack;
	}
}

static boolean_t ml_quiescing = FALSE;

void
ml_set_is_quiescing(boolean_t quiescing)
{
	ml_quiescing = quiescing;
	os_atomic_thread_fence(release);
}

boolean_t
ml_is_quiescing(void)
{
	os_atomic_thread_fence(acquire);
	return ml_quiescing;
}

uint64_t
ml_get_booter_memory_size(void)
{
	uint64_t size;
	uint64_t roundsize = 512 * 1024 * 1024ULL;
	size = BootArgs->memSizeActual;
	if (!size) {
		size  = BootArgs->memSize;
		if (size < (2 * roundsize)) {
			roundsize >>= 1;
		}
		size  = (size + roundsize - 1) & ~(roundsize - 1);
	}

	size -= BootArgs->memSize;

	return size;
}

uint64_t
ml_get_abstime_offset(void)
{
	return rtclock_base_abstime;
}

uint64_t
ml_get_conttime_offset(void)
{
#if HIBERNATION && HAS_CONTINUOUS_HWCLOCK
	return hwclock_conttime_offset;
#elif HAS_CONTINUOUS_HWCLOCK
	return 0;
#else
	return rtclock_base_abstime + mach_absolutetime_asleep;
#endif
}

uint64_t
ml_get_time_since_reset(void)
{
#if HAS_CONTINUOUS_HWCLOCK
	if (wake_conttime == UINT64_MAX) {
		return UINT64_MAX;
	} else {
		return mach_continuous_time() - wake_conttime;
	}
#else
	/* The timebase resets across S2R, so just return the raw value. */
	return ml_get_hwclock();
#endif
}

void
ml_set_reset_time(__unused uint64_t wake_time)
{
#if HAS_CONTINUOUS_HWCLOCK
	wake_conttime = wake_time;
#endif
}

uint64_t
ml_get_conttime_wake_time(void)
{
#if HAS_CONTINUOUS_HWCLOCK
	/*
	 * For now, we will reconstitute the timebase value from
	 * cpu_timebase_init and use it as the wake time.
	 */
	return wake_abstime - ml_get_abstime_offset();
#else /* HAS_CONTINOUS_HWCLOCK */
	/* The wake time is simply our continuous time offset. */
	return ml_get_conttime_offset();
#endif /* HAS_CONTINOUS_HWCLOCK */
}

/*
 * ml_snoop_thread_is_on_core(thread_t thread)
 * Check if the given thread is currently on core.  This function does not take
 * locks, disable preemption, or otherwise guarantee synchronization.  The
 * result should be considered advisory.
 */
bool
ml_snoop_thread_is_on_core(thread_t thread)
{
	unsigned int cur_cpu_num = 0;
	const unsigned int max_cpu_id = ml_get_max_cpu_number();

	for (cur_cpu_num = 0; cur_cpu_num <= max_cpu_id; cur_cpu_num++) {
		if (CpuDataEntries[cur_cpu_num].cpu_data_vaddr) {
			if (CpuDataEntries[cur_cpu_num].cpu_data_vaddr->cpu_active_thread == thread) {
				return true;
			}
		}
	}

	return false;
}

int
ml_early_cpu_max_number(void)
{
	assert(startup_phase >= STARTUP_SUB_TUNABLES);
	return ml_get_max_cpu_number();
}

void
ml_set_max_cpus(unsigned int max_cpus __unused)
{
	lck_mtx_lock(&max_cpus_lock);
	if (max_cpus_initialized != MAX_CPUS_SET) {
		if (max_cpus_initialized == MAX_CPUS_WAIT) {
			thread_wakeup((event_t) &max_cpus_initialized);
		}
		max_cpus_initialized = MAX_CPUS_SET;
	}
	lck_mtx_unlock(&max_cpus_lock);
}

unsigned int
ml_wait_max_cpus(void)
{
	assert(lockdown_done);
	lck_mtx_lock(&max_cpus_lock);
	while (max_cpus_initialized != MAX_CPUS_SET) {
		max_cpus_initialized = MAX_CPUS_WAIT;
		lck_mtx_sleep(&max_cpus_lock, LCK_SLEEP_DEFAULT, &max_cpus_initialized, THREAD_UNINT);
	}
	lck_mtx_unlock(&max_cpus_lock);
	return machine_info.max_cpus;
}
void
machine_conf(void)
{
	/*
	 * This is known to be inaccurate. mem_size should always be capped at 2 GB
	 */
	machine_info.memory_size = (uint32_t)mem_size;

	// rdar://problem/58285685: Userland expects _COMM_PAGE_LOGICAL_CPUS to report
	// (max_cpu_id+1) rather than a literal *count* of logical CPUs.
	unsigned int num_cpus = ml_get_topology_info()->max_cpu_id + 1;
	machine_info.max_cpus = num_cpus;
	machine_info.physical_cpu_max = num_cpus;
	machine_info.logical_cpu_max = num_cpus;
}

void
machine_init(void)
{
	debug_log_init();
	clock_config();
	is_clock_configured = TRUE;
	if (debug_enabled) {
		pmap_map_globals();
	}
	ml_lockdown_init();
}

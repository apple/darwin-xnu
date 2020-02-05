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
#include <machine/config.h>
#include <machine/atomic.h>
#include <pexpert/pexpert.h>

#if MONOTONIC
#include <kern/monotonic.h>
#include <machine/monotonic.h>
#endif /* MONOTONIC */

#include <mach/machine.h>

#if INTERRUPT_MASKED_DEBUG
extern boolean_t interrupt_masked_debug;
extern uint64_t interrupt_masked_timeout;
#endif

extern uint64_t mach_absolutetime_asleep;

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

void
sched_perfcontrol_register_callbacks(sched_perfcontrol_callbacks_t callbacks, unsigned long size_of_state)
{
	assert(callbacks == NULL || callbacks->version >= SCHED_PERFCONTROL_CALLBACKS_VERSION_2);

	if (size_of_state > sizeof(struct perfcontrol_state)) {
		panic("%s: Invalid required state size %lu", __FUNCTION__, size_of_state);
	}

	if (callbacks) {

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
	on_core.qos_class = proc_get_effective_thread_policy(new_thread, TASK_POLICY_QOS);
	on_core.urgency = urgency;
	on_core.is_32_bit = thread_is_64bit_data(new_thread) ? FALSE : TRUE;
	on_core.is_kernel_thread = new_thread->task == kernel_task;
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
		.qos_class      = proc_get_effective_thread_policy(thread, TASK_POLICY_QOS),
		.urgency        = kwi_args->urgency,
		.flags          = kwi_args->notify_flags,
		.work_interval_id = kwi_args->work_interval_id,
		.start          = kwi_args->start,
		.finish         = kwi_args->finish,
		.deadline       = kwi_args->deadline,
		.next_start     = kwi_args->next_start,
		.create_flags   = kwi_args->create_flags,
	};
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
	thread->machine.intmask_timestamp = ml_get_timebase();
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

void
ml_check_interrupts_disabled_duration(thread_t thread)
{
	uint64_t start;
	uint64_t now;

	start = thread->machine.intmask_timestamp;
	if (start != 0) {
		now = ml_get_timebase();

		if ((now - start) > interrupt_masked_timeout * debug_cpu_performance_degradation_factor) {
			mach_timebase_info_data_t timebase;
			clock_timebase_info(&timebase);

#ifndef KASAN
			/*
			 * Disable the actual panic for KASAN due to the overhead of KASAN itself, leave the rest of the
			 * mechanism enabled so that KASAN can catch any bugs in the mechanism itself.
			 */
			panic("Interrupts held disabled for %llu nanoseconds", (((now - start) * timebase.numer) / timebase.denom));
#endif
		}
	}

	return;
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
			ml_check_interrupts_disabled_duration(thread);
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
		__builtin_arm_wsr("DAIFClr", (DAIFSC_IRQF | DAIFSC_FIQF));
#endif
	} else if (!enable && ((state & INTERRUPT_MASK) == 0)) {
#if __arm__
		__asm__ volatile ("cpsid if" ::: "memory"); // Mask IRQ FIQ
#else
		__builtin_arm_wsr("DAIFSet", (DAIFSC_IRQF | DAIFSC_FIQF));
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

static boolean_t ml_quiescing;

void
ml_set_is_quiescing(boolean_t quiescing)
{
	assert(FALSE == ml_get_interrupts_enabled());
	ml_quiescing = quiescing;
}

boolean_t
ml_is_quiescing(void)
{
	assert(FALSE == ml_get_interrupts_enabled());
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
		size -= BootArgs->memSize;
	}
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
	return rtclock_base_abstime + mach_absolutetime_asleep;
}

uint64_t
ml_get_time_since_reset(void)
{
	/* The timebase resets across S2R, so just return the raw value. */
	return ml_get_hwclock();
}

void
ml_set_reset_time(__unused uint64_t wake_time)
{
}

uint64_t
ml_get_conttime_wake_time(void)
{
	/* The wake time is simply our continuous time offset. */
	return ml_get_conttime_offset();
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

	for (cur_cpu_num = 0; cur_cpu_num < MAX_CPUS; cur_cpu_num++) {
		if (CpuDataEntries[cur_cpu_num].cpu_data_vaddr) {
			if (CpuDataEntries[cur_cpu_num].cpu_data_vaddr->cpu_active_thread == thread) {
				return true;
			}
		}
	}

	return false;
}

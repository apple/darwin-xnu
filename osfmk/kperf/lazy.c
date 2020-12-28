/*
 * Copyright (c) 2018 Apple Computer, Inc. All rights reserved.
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

#include <stdint.h>

#include <kern/thread.h>

#include <kperf/action.h>
#include <kperf/buffer.h>
#include <kperf/kperf.h>
#include <kperf/lazy.h>
#include <kperf/sample.h>

unsigned int kperf_lazy_wait_action = 0;
unsigned int kperf_lazy_cpu_action = 0;
uint64_t kperf_lazy_wait_time_threshold = 0;
uint64_t kperf_lazy_cpu_time_threshold = 0;

void
kperf_lazy_reset(void)
{
	kperf_lazy_wait_action = 0;
	kperf_lazy_wait_time_threshold = 0;
	kperf_lazy_cpu_action = 0;
	kperf_lazy_cpu_time_threshold = 0;
	kperf_on_cpu_update();
}

void
kperf_lazy_off_cpu(thread_t thread)
{
	/* try to lazily sample the CPU if the thread was pre-empted */
	if ((thread->reason & AST_SCHEDULING) != 0) {
		kperf_lazy_cpu_sample(thread, 0, 0);
	}
}

void
kperf_lazy_make_runnable(thread_t thread, bool in_interrupt)
{
	assert(thread->last_made_runnable_time != THREAD_NOT_RUNNABLE);
	/* ignore threads that race to wait and in waking up */
	if (thread->last_run_time > thread->last_made_runnable_time) {
		return;
	}

	uint64_t wait_time = thread_get_last_wait_duration(thread);
	if (wait_time > kperf_lazy_wait_time_threshold) {
		BUF_DATA(PERF_LZ_MKRUNNABLE, (uintptr_t)thread_tid(thread),
		    thread->sched_pri, in_interrupt ? 1 : 0);
	}
}

void
kperf_lazy_wait_sample(thread_t thread, thread_continue_t continuation,
    uintptr_t *starting_fp)
{
	/* ignore idle threads */
	if (thread->last_made_runnable_time == THREAD_NOT_RUNNABLE) {
		return;
	}
	/* ignore invalid made runnable times */
	if (thread->last_made_runnable_time < thread->last_run_time) {
		return;
	}

	/* take a sample if thread was waiting for longer than threshold */
	uint64_t wait_time = thread_get_last_wait_duration(thread);
	if (wait_time > kperf_lazy_wait_time_threshold) {
		uint64_t time_now = mach_absolute_time();
		timer_update(&thread->runnable_timer, time_now);
		timer_update(&thread->system_timer, time_now);

		uint64_t runnable_time = timer_grab(&thread->runnable_timer);
		uint64_t running_time = timer_grab(&thread->user_timer) +
		    timer_grab(&thread->system_timer);

		BUF_DATA(PERF_LZ_WAITSAMPLE, wait_time, runnable_time, running_time);

		task_t task = get_threadtask(thread);
		struct kperf_context ctx = {
			.cur_thread = thread,
			.cur_task = task,
			.cur_pid = task_pid(task),
			.trigger_type = TRIGGER_TYPE_LAZY_WAIT,
			.starting_fp = starting_fp,
		};

		struct kperf_sample *sample = kperf_intr_sample_buffer();
		if (!sample) {
			return;
		}

		unsigned int flags = SAMPLE_FLAG_PEND_USER;
		flags |= continuation ? SAMPLE_FLAG_CONTINUATION : 0;
		flags |= !ml_at_interrupt_context() ? SAMPLE_FLAG_NON_INTERRUPT : 0;

		kperf_sample(sample, &ctx, kperf_lazy_wait_action, flags);
	}
}

void
kperf_lazy_cpu_sample(thread_t thread, unsigned int flags, bool interrupt)
{
	assert(ml_get_interrupts_enabled() == FALSE);

	/* take a sample if this CPU's last sample time is beyond the threshold */
	processor_t processor = current_processor();
	uint64_t time_now = mach_absolute_time();
	uint64_t since_last_sample = time_now - processor->kperf_last_sample_time;
	if (since_last_sample > kperf_lazy_cpu_time_threshold) {
		processor->kperf_last_sample_time = time_now;
		timer_update(&thread->runnable_timer, time_now);
		timer_update(&thread->system_timer, time_now);

		uint64_t runnable_time = timer_grab(&thread->runnable_timer);
		uint64_t running_time = timer_grab(&thread->user_timer) +
		    timer_grab(&thread->system_timer);

		BUF_DATA(PERF_LZ_CPUSAMPLE, running_time, runnable_time,
		    thread->sched_pri, interrupt ? 1 : 0);

		task_t task = get_threadtask(thread);
		struct kperf_context ctx = {
			.cur_thread = thread,
			.cur_task = task,
			.cur_pid = task_pid(task),
			.trigger_type = TRIGGER_TYPE_LAZY_CPU,
			.starting_fp = 0,
		};

		struct kperf_sample *sample = kperf_intr_sample_buffer();
		if (!sample) {
			return;
		}

		kperf_sample(sample, &ctx, kperf_lazy_cpu_action,
		    SAMPLE_FLAG_PEND_USER | flags);
	}
}

/*
 * Accessors for configuration.
 */

int
kperf_lazy_get_wait_action(void)
{
	return kperf_lazy_wait_action;
}

int
kperf_lazy_set_wait_action(int action_id)
{
	if (action_id < 0 || (unsigned int)action_id > kperf_action_get_count()) {
		return 1;
	}

	kperf_lazy_wait_action = action_id;
	kperf_on_cpu_update();
	return 0;
}

uint64_t
kperf_lazy_get_wait_time_threshold(void)
{
	return kperf_lazy_wait_time_threshold;
}

int
kperf_lazy_set_wait_time_threshold(uint64_t threshold)
{
	kperf_lazy_wait_time_threshold = threshold;
	return 0;
}

int
kperf_lazy_get_cpu_action(void)
{
	return kperf_lazy_cpu_action;
}

int
kperf_lazy_set_cpu_action(int action_id)
{
	if (action_id < 0 || (unsigned int)action_id > kperf_action_get_count()) {
		return 1;
	}

	kperf_lazy_cpu_action = action_id;
	return 0;
}

uint64_t
kperf_lazy_get_cpu_time_threshold(void)
{
	return kperf_lazy_cpu_time_threshold;
}

int
kperf_lazy_set_cpu_time_threshold(uint64_t threshold)
{
	kperf_lazy_cpu_time_threshold = threshold;
	return 0;
}

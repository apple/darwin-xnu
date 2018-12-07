/*
 * Copyright (c) 2011-2016 Apple Computer, Inc. All rights reserved.
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

/* all thread states code */
#include <mach/mach_types.h>
#include <sys/errno.h>

#include <kperf/kperf.h>
#include <kperf/buffer.h>
#include <kperf/sample.h>
#include <kperf/context.h>
#include <kperf/action.h>
#include <kperf/pet.h>
#include <kperf/kperf_timer.h>

#include <kern/task.h>
#include <kern/kalloc.h>

/* action ID to call for each sample
 *
 * Address is used as the sync point for waiting.
 */
static unsigned int pet_action_id = 0;

static lck_mtx_t *pet_lock;
static boolean_t pet_initted = FALSE;
static boolean_t pet_running = FALSE;

/* number of callstack samples to skip for idle threads */
static uint32_t pet_idle_rate = KPERF_PET_DEFAULT_IDLE_RATE;

/*
 * Lightweight PET mode samples the system less-intrusively than normal PET
 * mode.  Instead of iterating tasks and threads on each sample, it increments
 * a global generation count, kperf_pet_gen, which is checked as threads are
 * context switched on-core.  If the thread's local generation count is older
 * than the global generation, the thread samples itself.
 *
 *            |  |
 * thread A   +--+---------|
 *            |  |
 * thread B   |--+---------------|
 *            |  |
 * thread C   |  |         |-------------------------------------
 *            |  |         |
 * thread D   |  |         |     |-------------------------------
 *            |  |         |     |
 *            +--+---------+-----+--------------------------------> time
 *               |         │     |
 *               |         +-----+--- threads sampled when they come on-core in
 *               |                    kperf_pet_switch_context
 *               |
 *               +--- PET timer fire, sample on-core threads A and B,
 *                    increment kperf_pet_gen
 */
static boolean_t lightweight_pet = FALSE;

/*
 * Whether or not lightweight PET and sampling is active.
 */
boolean_t kperf_lightweight_pet_active = FALSE;

uint32_t kperf_pet_gen = 0;

static struct kperf_sample *pet_sample;

/* thread lifecycle */

static kern_return_t pet_init(void);
static void pet_start(void);
static void pet_stop(void);

/* PET thread-only */

static void pet_thread_loop(void *param, wait_result_t wr);
static void pet_thread_idle(void);
static void pet_thread_work_unit(void);

/* listing things to sample */

static task_array_t pet_tasks = NULL;
static vm_size_t pet_tasks_size = 0;
static vm_size_t pet_tasks_count = 0;

static thread_array_t pet_threads = NULL;
static vm_size_t pet_threads_size = 0;
static vm_size_t pet_threads_count = 0;

static kern_return_t pet_tasks_prepare(void);
static kern_return_t pet_tasks_prepare_internal(void);

static kern_return_t pet_threads_prepare(task_t task);

/* sampling */

static void pet_sample_all_tasks(uint32_t idle_rate);
static void pet_sample_task(task_t task, uint32_t idle_rate);
static void pet_sample_thread(int pid, task_t task, thread_t thread,
		uint32_t idle_rate);

/* functions called by other areas of kperf */

void
kperf_pet_fire_before(void)
{
	if (!pet_initted || !pet_running) {
		return;
	}

	if (lightweight_pet) {
		BUF_INFO(PERF_PET_SAMPLE);
		OSIncrementAtomic(&kperf_pet_gen);
	}
}

void
kperf_pet_fire_after(void)
{
	if (!pet_initted || !pet_running) {
		return;
	}

	if (lightweight_pet) {
		kperf_timer_pet_rearm(0);
	} else {
		thread_wakeup(&pet_action_id);
	}
}

void
kperf_pet_on_cpu(thread_t thread, thread_continue_t continuation,
                 uintptr_t *starting_fp)
{
	assert(thread != NULL);
	assert(ml_get_interrupts_enabled() == FALSE);

	if (thread->kperf_pet_gen != kperf_pet_gen) {
		BUF_VERB(PERF_PET_SAMPLE_THREAD | DBG_FUNC_START, kperf_pet_gen, thread->kperf_pet_gen);

		task_t task = get_threadtask(thread);
		struct kperf_context ctx = {
			.cur_thread = thread,
			.cur_task = task,
			.cur_pid = task_pid(task),
			.starting_fp = starting_fp,
		};
		/*
		 * Use a per-CPU interrupt buffer, since this is only called
		 * while interrupts are disabled, from the scheduler.
		 */
		struct kperf_sample *sample = kperf_intr_sample_buffer();
		if (!sample) {
			BUF_VERB(PERF_PET_SAMPLE_THREAD | DBG_FUNC_END, 1);
			return;
		}

		unsigned int flags = SAMPLE_FLAG_NON_INTERRUPT | SAMPLE_FLAG_PEND_USER;
		if (continuation != NULL) {
			flags |= SAMPLE_FLAG_CONTINUATION;
		}
		kperf_sample(sample, &ctx, pet_action_id, flags);

		BUF_VERB(PERF_PET_SAMPLE_THREAD | DBG_FUNC_END);
	} else {
		BUF_VERB(PERF_PET_SAMPLE_THREAD, kperf_pet_gen, thread->kperf_pet_gen);
	}
}

void
kperf_pet_config(unsigned int action_id)
{
	kern_return_t kr = pet_init();
	if (kr != KERN_SUCCESS) {
		return;
	}

	lck_mtx_lock(pet_lock);

	BUF_INFO(PERF_PET_THREAD, 3, action_id);

	if (action_id == 0) {
		pet_stop();
	} else {
		pet_start();
	}

	pet_action_id = action_id;

	lck_mtx_unlock(pet_lock);
}

/* handle resource allocation */

void
pet_start(void)
{
	lck_mtx_assert(pet_lock, LCK_MTX_ASSERT_OWNED);

	if (pet_running) {
		return;
	}

	pet_sample = kalloc(sizeof(struct kperf_sample));
	if (!pet_sample) {
		return;
	}

	pet_running = TRUE;
}

void
pet_stop(void)
{
	lck_mtx_assert(pet_lock, LCK_MTX_ASSERT_OWNED);

	if (!pet_initted) {
		return;
	}

	if (pet_tasks != NULL) {
		assert(pet_tasks_size != 0);
		kfree(pet_tasks, pet_tasks_size);

		pet_tasks = NULL;
		pet_tasks_size = 0;
		pet_tasks_count = 0;
	}

	if (pet_threads != NULL) {
		assert(pet_threads_size != 0);
		kfree(pet_threads, pet_threads_size);

		pet_threads = NULL;
		pet_threads_size = 0;
		pet_threads_count = 0;
	}

	if (pet_sample != NULL) {
		kfree(pet_sample, sizeof(struct kperf_sample));
		pet_sample = NULL;
	}

	pet_running = FALSE;
}

/*
 * Lazily initialize PET.  The PET thread never exits once PET has been used
 * once.
 */
static kern_return_t
pet_init(void)
{
	if (pet_initted) {
		return KERN_SUCCESS;
	}

	/* make the sync point */
	pet_lock = lck_mtx_alloc_init(&kperf_lck_grp, NULL);
	assert(pet_lock);

	/* create the thread */

	BUF_INFO(PERF_PET_THREAD, 0);
	thread_t t;
	kern_return_t kr = kernel_thread_start(pet_thread_loop, NULL, &t);
	if (kr != KERN_SUCCESS) {
		lck_mtx_free(pet_lock, &kperf_lck_grp);
		return kr;
	}

	thread_set_thread_name(t, "kperf sampling");
	/* let the thread hold the only reference */
	thread_deallocate(t);

	pet_initted = TRUE;

	return KERN_SUCCESS;
}

/* called by PET thread only */

static void
pet_thread_work_unit(void)
{
	pet_sample_all_tasks(pet_idle_rate);
}

static void
pet_thread_idle(void)
{
	lck_mtx_assert(pet_lock, LCK_MTX_ASSERT_OWNED);

	(void)lck_mtx_sleep(pet_lock, LCK_SLEEP_DEFAULT, &pet_action_id,
	                    THREAD_UNINT);
}

__attribute__((noreturn))
static void
pet_thread_loop(void *param, wait_result_t wr)
{
#pragma unused(param, wr)
	uint64_t work_unit_ticks;

	BUF_INFO(PERF_PET_THREAD, 1);

	lck_mtx_lock(pet_lock);
	for (;;) {
		BUF_INFO(PERF_PET_IDLE);
		pet_thread_idle();

		BUF_INFO(PERF_PET_RUN);

		/* measure how long the work unit takes */
		work_unit_ticks = mach_absolute_time();
		pet_thread_work_unit();
		work_unit_ticks = mach_absolute_time() - work_unit_ticks;

		/* re-program the timer */
		kperf_timer_pet_rearm(work_unit_ticks);
	}
}

/* sampling */

static void
pet_sample_thread(int pid, task_t task, thread_t thread, uint32_t idle_rate)
{
	lck_mtx_assert(pet_lock, LCK_MTX_ASSERT_OWNED);

	uint32_t sample_flags = SAMPLE_FLAG_IDLE_THREADS | SAMPLE_FLAG_THREAD_ONLY;

	BUF_VERB(PERF_PET_SAMPLE_THREAD | DBG_FUNC_START);

	/* work out the context */
	struct kperf_context ctx = {
		.cur_thread = thread,
		.cur_task = task,
		.cur_pid = pid,
	};

	boolean_t thread_dirty = kperf_thread_get_dirty(thread);

	/*
	 * Clean a dirty thread and skip callstack sample if the thread was not
	 * dirty and thread has skipped less than pet_idle_rate samples.
	 */
	if (thread_dirty) {
		kperf_thread_set_dirty(thread, FALSE);
	} else if ((thread->kperf_pet_cnt % idle_rate) != 0) {
		sample_flags |= SAMPLE_FLAG_EMPTY_CALLSTACK;
	}
	thread->kperf_pet_cnt++;

	kperf_sample(pet_sample, &ctx, pet_action_id, sample_flags);

	BUF_VERB(PERF_PET_SAMPLE_THREAD | DBG_FUNC_END);
}

static kern_return_t
pet_threads_prepare(task_t task)
{
	lck_mtx_assert(pet_lock, LCK_MTX_ASSERT_OWNED);

	vm_size_t threads_size_needed;

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	for (;;) {
		task_lock(task);

		if (!task->active) {
			task_unlock(task);

			return KERN_FAILURE;
		}

		/* do we have the memory we need? */
		threads_size_needed = task->thread_count * sizeof(thread_t);
		if (threads_size_needed <= pet_threads_size) {
			break;
		}

		/* not enough memory, unlock the task and increase allocation */
		task_unlock(task);

		if (pet_threads_size != 0) {
			kfree(pet_threads, pet_threads_size);
		}

		assert(threads_size_needed > 0);
		pet_threads_size = threads_size_needed;

		pet_threads = kalloc(pet_threads_size);
		if (pet_threads == NULL) {
			pet_threads_size = 0;
			return KERN_RESOURCE_SHORTAGE;
		}
	}

	/* have memory and the task is locked and active */
	thread_t thread;
	pet_threads_count = 0;
	queue_iterate(&(task->threads), thread, thread_t, task_threads) {
		thread_reference_internal(thread);
		pet_threads[pet_threads_count++] = thread;
	}

	/* can unlock task now that threads are referenced */
	task_unlock(task);

	return (pet_threads_count == 0) ? KERN_FAILURE : KERN_SUCCESS;
}

static void
pet_sample_task(task_t task, uint32_t idle_rate)
{
	lck_mtx_assert(pet_lock, LCK_MTX_ASSERT_OWNED);

	BUF_VERB(PERF_PET_SAMPLE_TASK | DBG_FUNC_START);

	int pid = task_pid(task);
	if (kperf_action_has_task(pet_action_id)) {
		struct kperf_context ctx = {
			.cur_task = task,
			.cur_pid = pid,
		};

		kperf_sample(pet_sample, &ctx, pet_action_id, SAMPLE_FLAG_TASK_ONLY);
	}

	if (!kperf_action_has_thread(pet_action_id)) {
		BUF_VERB(PERF_PET_SAMPLE_TASK | DBG_FUNC_END);
		return;
	}

	kern_return_t kr = KERN_SUCCESS;

	/*
	 * Suspend the task to see an atomic snapshot of all its threads.  This
	 * is expensive, and disruptive.
	 */
	bool needs_suspend = task != kernel_task;
	if (needs_suspend) {
		kr = task_suspend_internal(task);
		if (kr != KERN_SUCCESS) {
			BUF_VERB(PERF_PET_SAMPLE_TASK | DBG_FUNC_END, 1);
			return;
		}
		needs_suspend = true;
	}

	kr = pet_threads_prepare(task);
	if (kr != KERN_SUCCESS) {
		BUF_INFO(PERF_PET_ERROR, ERR_THREAD, kr);
		goto out;
	}

	for (unsigned int i = 0; i < pet_threads_count; i++) {
		thread_t thread = pet_threads[i];
		assert(thread != THREAD_NULL);

		/*
		 * Do not sample the thread if it was on a CPU when the timer fired.
		 */
		int cpu = 0;
		for (cpu = 0; cpu < machine_info.logical_cpu_max; cpu++) {
			if (kperf_tid_on_cpus[cpu] == thread_tid(thread)) {
				break;
			}
		}

		/* the thread was not on a CPU */
		if (cpu == machine_info.logical_cpu_max) {
			pet_sample_thread(pid, task, thread, idle_rate);
		}

		thread_deallocate(pet_threads[i]);
	}

out:
	if (needs_suspend) {
		task_resume_internal(task);
	}

	BUF_VERB(PERF_PET_SAMPLE_TASK | DBG_FUNC_END, pet_threads_count);
}

static kern_return_t
pet_tasks_prepare_internal(void)
{
	lck_mtx_assert(pet_lock, LCK_MTX_ASSERT_OWNED);

	vm_size_t tasks_size_needed = 0;

	for (;;) {
		lck_mtx_lock(&tasks_threads_lock);

		/* do we have the memory we need? */
		tasks_size_needed = tasks_count * sizeof(task_t);
		if (tasks_size_needed <= pet_tasks_size) {
			break;
		}

		/* unlock and allocate more memory */
		lck_mtx_unlock(&tasks_threads_lock);

		/* grow task array */
		if (tasks_size_needed > pet_tasks_size) {
			if (pet_tasks_size != 0) {
				kfree(pet_tasks, pet_tasks_size);
			}

			assert(tasks_size_needed > 0);
			pet_tasks_size = tasks_size_needed;

			pet_tasks = (task_array_t)kalloc(pet_tasks_size);
			if (pet_tasks == NULL) {
				pet_tasks_size = 0;
				return KERN_RESOURCE_SHORTAGE;
			}
		}
	}

	return KERN_SUCCESS;
}

static kern_return_t
pet_tasks_prepare(void)
{
	lck_mtx_assert(pet_lock, LCK_MTX_ASSERT_OWNED);

	/* allocate space and take the tasks_threads_lock */
	kern_return_t kr = pet_tasks_prepare_internal();
	if (KERN_SUCCESS != kr) {
		return kr;
	}
	lck_mtx_assert(&tasks_threads_lock, LCK_MTX_ASSERT_OWNED);

	/* make sure the tasks are not deallocated after dropping the lock */
	task_t task;
	pet_tasks_count = 0;
	queue_iterate(&tasks, task, task_t, tasks) {
		if (task != kernel_task) {
			task_reference_internal(task);
			pet_tasks[pet_tasks_count++] = task;
		}
	}

	lck_mtx_unlock(&tasks_threads_lock);

	return KERN_SUCCESS;
}

static void
pet_sample_all_tasks(uint32_t idle_rate)
{
	lck_mtx_assert(pet_lock, LCK_MTX_ASSERT_OWNED);

	BUF_INFO(PERF_PET_SAMPLE | DBG_FUNC_START);

	kern_return_t kr = pet_tasks_prepare();
	if (kr != KERN_SUCCESS) {
		BUF_INFO(PERF_PET_ERROR, ERR_TASK, kr);
		BUF_INFO(PERF_PET_SAMPLE | DBG_FUNC_END, 0);
		return;
	}

	for (unsigned int i = 0; i < pet_tasks_count; i++) {
		task_t task = pet_tasks[i];

		pet_sample_task(task, idle_rate);
	}

	for(unsigned int i = 0; i < pet_tasks_count; i++) {
		task_deallocate(pet_tasks[i]);
	}

	BUF_INFO(PERF_PET_SAMPLE | DBG_FUNC_END, pet_tasks_count);
}

/* support sysctls */

int
kperf_get_pet_idle_rate(void)
{
	return pet_idle_rate;
}

int
kperf_set_pet_idle_rate(int val)
{
	pet_idle_rate = val;

	return 0;
}

int
kperf_get_lightweight_pet(void)
{
	return lightweight_pet;
}

int
kperf_set_lightweight_pet(int val)
{
	if (kperf_sampling_status() == KPERF_SAMPLING_ON) {
		return EBUSY;
	}

	lightweight_pet = (val == 1);
	kperf_lightweight_pet_active_update();

	return 0;
}

void
kperf_lightweight_pet_active_update(void)
{
	kperf_lightweight_pet_active = (kperf_sampling_status() && lightweight_pet);
	kperf_on_cpu_update();
}

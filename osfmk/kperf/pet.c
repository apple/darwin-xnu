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
 * Profile Every Thread (PET) provides a profile of all threads on the system
 * when a timer fires.  PET supports the "record waiting threads" mode in
 * Instruments, and used to be called All Thread States (ATS).  New tools should
 * adopt the lightweight PET mode, which provides the same information, but with
 * much less overhead.
 *
 * When traditional (non-lightweight) PET is active, a migrating timer call
 * causes the PET thread to wake up.  The timer handler also issues a broadcast
 * IPI to the other CPUs, to provide a (somewhat) synchronized set of on-core
 * samples.  This is provided for backwards-compatibility with clients that
 * expect on-core samples, when PET's timer was based off the on-core timers.
 * Because PET sampling can take on the order of milliseconds, the PET thread
 * will enter a new timer deadline after it finished sampling This perturbs the
 * timer cadence by the duration of PET sampling, but it leaves the system to
 * work on non-profiling tasks for the duration of the timer period.
 *
 * Lightweight PET samples the system less-intrusively than normal PET
 * mode.  Instead of iterating tasks and threads on each sample, it increments
 * a global generation count, `kppet_gencount`, which is checked as threads are
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
 *                    increment kppet_gencount
 */

#include <mach/mach_types.h>
#include <sys/errno.h>

#include <kperf/kperf.h>
#include <kperf/buffer.h>
#include <kperf/sample.h>
#include <kperf/context.h>
#include <kperf/action.h>
#include <kperf/pet.h>
#include <kperf/kptimer.h>

#include <kern/task.h>
#include <kern/kalloc.h>
#if defined(__x86_64__)
#include <i386/mp.h>
#endif /* defined(__x86_64__) */

static LCK_MTX_DECLARE(kppet_mtx, &kperf_lck_grp);

static struct {
	unsigned int g_actionid;
	/*
	 * The idle rate controls how many sampling periods to skip if a thread
	 * is idle.
	 */
	uint32_t g_idle_rate;
	bool g_setup:1;
	bool g_lightweight:1;
	struct kperf_sample *g_sample;

	thread_t g_sample_thread;

	/*
	 * Used by the PET thread to manage which threads and tasks to sample.
	 */
	thread_t *g_threads;
	unsigned int g_nthreads;
	size_t g_threads_size;

	task_t *g_tasks;
	unsigned int g_ntasks;
	size_t g_tasks_size;
} kppet = {
	.g_actionid = 0,
	.g_idle_rate = KPERF_PET_DEFAULT_IDLE_RATE,
};

bool kppet_lightweight_active = false;
_Atomic uint32_t kppet_gencount = 0;

static uint64_t kppet_sample_tasks(uint32_t idle_rate);
static void kppet_thread(void * param, wait_result_t wr);

static void
kppet_lock_assert_owned(void)
{
	lck_mtx_assert(&kppet_mtx, LCK_MTX_ASSERT_OWNED);
}

static void
kppet_lock(void)
{
	lck_mtx_lock(&kppet_mtx);
}

static void
kppet_unlock(void)
{
	lck_mtx_unlock(&kppet_mtx);
}

void
kppet_on_cpu(thread_t thread, thread_continue_t continuation,
    uintptr_t *starting_fp)
{
	assert(thread != NULL);
	assert(ml_get_interrupts_enabled() == FALSE);

	uint32_t actionid = kppet.g_actionid;
	if (actionid == 0) {
		return;
	}

	if (thread->kperf_pet_gen != atomic_load(&kppet_gencount)) {
		BUF_VERB(PERF_PET_SAMPLE_THREAD | DBG_FUNC_START,
		    atomic_load_explicit(&kppet_gencount,
		    memory_order_relaxed), thread->kperf_pet_gen);

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
		kperf_sample(sample, &ctx, actionid, flags);

		BUF_VERB(PERF_PET_SAMPLE_THREAD | DBG_FUNC_END);
	} else {
		BUF_VERB(PERF_PET_SAMPLE_THREAD,
		    os_atomic_load(&kppet_gencount, relaxed), thread->kperf_pet_gen);
	}
}

#pragma mark - state transitions

/*
 * Lazily initialize PET.  The PET thread never exits once PET has been used
 * once.
 */
static void
kppet_setup(void)
{
	if (kppet.g_setup) {
		return;
	}

	kern_return_t kr = kernel_thread_start(kppet_thread, NULL,
	    &kppet.g_sample_thread);
	if (kr != KERN_SUCCESS) {
		panic("kperf: failed to create PET thread %d", kr);
	}

	thread_set_thread_name(kppet.g_sample_thread, "kperf-pet-sampling");
	kppet.g_setup = true;
}

void
kppet_config(unsigned int actionid)
{
	/*
	 * Resetting kperf shouldn't get the PET thread started.
	 */
	if (actionid == 0 && !kppet.g_setup) {
		return;
	}

	kppet_setup();

	kppet_lock();

	kppet.g_actionid = actionid;

	if (actionid > 0) {
		if (!kppet.g_sample) {
			kppet.g_sample = kalloc_tag(sizeof(*kppet.g_sample),
			    VM_KERN_MEMORY_DIAG);
		}
	} else {
		if (kppet.g_tasks) {
			assert(kppet.g_tasks_size != 0);
			kfree(kppet.g_tasks, kppet.g_tasks_size);
			kppet.g_tasks = NULL;
			kppet.g_tasks_size = 0;
			kppet.g_ntasks = 0;
		}
		if (kppet.g_threads) {
			assert(kppet.g_threads_size != 0);
			kfree(kppet.g_threads, kppet.g_threads_size);
			kppet.g_threads = NULL;
			kppet.g_threads_size = 0;
			kppet.g_nthreads = 0;
		}
		if (kppet.g_sample != NULL) {
			kfree(kppet.g_sample, sizeof(*kppet.g_sample));
			kppet.g_sample = NULL;
		}
	}

	kppet_unlock();
}

void
kppet_reset(void)
{
	kppet_config(0);
	kppet_set_idle_rate(KPERF_PET_DEFAULT_IDLE_RATE);
	kppet_set_lightweight_pet(0);
}

void
kppet_wake_thread(void)
{
	thread_wakeup(&kppet);
}

__attribute__((noreturn))
static void
kppet_thread(void * __unused param, wait_result_t __unused wr)
{
	kppet_lock();

	for (;;) {
		BUF_INFO(PERF_PET_IDLE);

		do {
			(void)lck_mtx_sleep(&kppet_mtx, LCK_SLEEP_DEFAULT, &kppet,
			    THREAD_UNINT);
		} while (kppet.g_actionid == 0);

		BUF_INFO(PERF_PET_RUN);

		uint64_t sampledur_abs = kppet_sample_tasks(kppet.g_idle_rate);

		kptimer_pet_enter(sampledur_abs);
	}
}

#pragma mark - sampling

static void
kppet_sample_thread(int pid, task_t task, thread_t thread, uint32_t idle_rate)
{
	kppet_lock_assert_owned();

	uint32_t sample_flags = SAMPLE_FLAG_IDLE_THREADS |
	    SAMPLE_FLAG_THREAD_ONLY;

	BUF_VERB(PERF_PET_SAMPLE_THREAD | DBG_FUNC_START);

	struct kperf_context ctx = {
		.cur_thread = thread,
		.cur_task = task,
		.cur_pid = pid,
	};

	boolean_t thread_dirty = kperf_thread_get_dirty(thread);

	/*
	 * Clean a dirty thread and skip callstack sample if the thread was not
	 * dirty and thread had skipped less than `idle_rate` samples.
	 */
	if (thread_dirty) {
		kperf_thread_set_dirty(thread, FALSE);
	} else if ((thread->kperf_pet_cnt % idle_rate) != 0) {
		sample_flags |= SAMPLE_FLAG_EMPTY_CALLSTACK;
	}
	thread->kperf_pet_cnt++;

	kperf_sample(kppet.g_sample, &ctx, kppet.g_actionid, sample_flags);
	kperf_sample_user(&kppet.g_sample->usample, &ctx, kppet.g_actionid,
	    sample_flags);

	BUF_VERB(PERF_PET_SAMPLE_THREAD | DBG_FUNC_END);
}

static kern_return_t
kppet_threads_prepare(task_t task)
{
	kppet_lock_assert_owned();

	vm_size_t threads_size_needed;

	for (;;) {
		task_lock(task);

		if (!task->active) {
			task_unlock(task);
			return KERN_FAILURE;
		}

		/*
		 * With the task locked, figure out if enough space has been allocated to
		 * contain all of the thread references.
		 */
		threads_size_needed = task->thread_count * sizeof(thread_t);
		if (threads_size_needed <= kppet.g_threads_size) {
			break;
		}

		/*
		 * Otherwise, allocate more and try again.
		 */
		task_unlock(task);

		if (kppet.g_threads_size != 0) {
			kfree(kppet.g_threads, kppet.g_threads_size);
		}

		assert(threads_size_needed > 0);
		kppet.g_threads_size = threads_size_needed;

		kppet.g_threads = kalloc_tag(kppet.g_threads_size, VM_KERN_MEMORY_DIAG);
		if (kppet.g_threads == NULL) {
			kppet.g_threads_size = 0;
			return KERN_RESOURCE_SHORTAGE;
		}
	}

	thread_t thread;
	kppet.g_nthreads = 0;
	queue_iterate(&(task->threads), thread, thread_t, task_threads) {
		thread_reference_internal(thread);
		kppet.g_threads[kppet.g_nthreads++] = thread;
	}

	task_unlock(task);

	return (kppet.g_nthreads > 0) ? KERN_SUCCESS : KERN_FAILURE;
}

/*
 * Sample a `task`, using `idle_rate` to control whether idle threads need to be
 * re-sampled.
 *
 * The task must be referenced.
 */
static void
kppet_sample_task(task_t task, uint32_t idle_rate)
{
	kppet_lock_assert_owned();
	assert(task != kernel_task);
	if (task == kernel_task) {
		return;
	}

	BUF_VERB(PERF_PET_SAMPLE_TASK | DBG_FUNC_START);

	int pid = task_pid(task);
	if (kperf_action_has_task(kppet.g_actionid)) {
		struct kperf_context ctx = {
			.cur_task = task,
			.cur_pid = pid,
		};

		kperf_sample(kppet.g_sample, &ctx, kppet.g_actionid,
		    SAMPLE_FLAG_TASK_ONLY);
	}

	if (!kperf_action_has_thread(kppet.g_actionid)) {
		BUF_VERB(PERF_PET_SAMPLE_TASK | DBG_FUNC_END);
		return;
	}

	/*
	 * Suspend the task to see an atomic snapshot of all its threads.  This
	 * is expensive and disruptive.
	 */
	kern_return_t kr = task_suspend_internal(task);
	if (kr != KERN_SUCCESS) {
		BUF_VERB(PERF_PET_SAMPLE_TASK | DBG_FUNC_END, 1);
		return;
	}

	kr = kppet_threads_prepare(task);
	if (kr != KERN_SUCCESS) {
		BUF_INFO(PERF_PET_ERROR, ERR_THREAD, kr);
		goto out;
	}

	for (unsigned int i = 0; i < kppet.g_nthreads; i++) {
		thread_t thread = kppet.g_threads[i];
		assert(thread != THREAD_NULL);

		kppet_sample_thread(pid, task, thread, idle_rate);

		thread_deallocate(kppet.g_threads[i]);
	}

out:
	task_resume_internal(task);

	BUF_VERB(PERF_PET_SAMPLE_TASK | DBG_FUNC_END, kppet.g_nthreads);
}

/*
 * Store and reference all tasks on the system, so they can be safely inspected
 * outside the `tasks_threads_lock`.
 */
static kern_return_t
kppet_tasks_prepare(void)
{
	kppet_lock_assert_owned();

	vm_size_t size_needed = 0;

	for (;;) {
		lck_mtx_lock(&tasks_threads_lock);

		/*
		 * With the lock held, break out of the lock/unlock loop if
		 * there's enough space to store all the tasks.
		 */
		size_needed = tasks_count * sizeof(task_t);
		if (size_needed <= kppet.g_tasks_size) {
			break;
		}

		/*
		 * Otherwise, allocate more memory outside of the lock.
		 */
		lck_mtx_unlock(&tasks_threads_lock);

		if (size_needed > kppet.g_tasks_size) {
			if (kppet.g_tasks_size != 0) {
				kfree(kppet.g_tasks, kppet.g_tasks_size);
			}

			assert(size_needed > 0);
			kppet.g_tasks_size = size_needed;

			kppet.g_tasks = kalloc_tag(kppet.g_tasks_size, VM_KERN_MEMORY_DIAG);
			if (!kppet.g_tasks) {
				kppet.g_tasks_size = 0;
				return KERN_RESOURCE_SHORTAGE;
			}
		}
	}

	task_t task = TASK_NULL;
	kppet.g_ntasks = 0;
	queue_iterate(&tasks, task, task_t, tasks) {
		bool eligible_task = task != kernel_task;
		if (eligible_task) {
			task_reference_internal(task);
			kppet.g_tasks[kppet.g_ntasks++] = task;
		}
	}

	lck_mtx_unlock(&tasks_threads_lock);

	return KERN_SUCCESS;
}

static uint64_t
kppet_sample_tasks(uint32_t idle_rate)
{
	kppet_lock_assert_owned();
	assert(kppet.g_actionid > 0);

	uint64_t start_abs = mach_absolute_time();

	BUF_INFO(PERF_PET_SAMPLE | DBG_FUNC_START);

	kern_return_t kr = kppet_tasks_prepare();
	if (kr != KERN_SUCCESS) {
		BUF_INFO(PERF_PET_ERROR, ERR_TASK, kr);
		BUF_INFO(PERF_PET_SAMPLE | DBG_FUNC_END);
		return mach_absolute_time() - start_abs;
	}

	for (unsigned int i = 0; i < kppet.g_ntasks; i++) {
		task_t task = kppet.g_tasks[i];
		assert(task != TASK_NULL);
		kppet_sample_task(task, idle_rate);
		task_deallocate(task);
		kppet.g_tasks[i] = TASK_NULL;
	}

	BUF_INFO(PERF_PET_SAMPLE | DBG_FUNC_END, kppet.g_ntasks);
	kppet.g_ntasks = 0;
	return mach_absolute_time() - start_abs;
}

#pragma mark - sysctl accessors

int
kppet_get_idle_rate(void)
{
	return kppet.g_idle_rate;
}

int
kppet_set_idle_rate(int new_idle_rate)
{
	kppet.g_idle_rate = new_idle_rate;
	return 0;
}

void
kppet_lightweight_active_update(void)
{
	kppet_lightweight_active = (kperf_is_sampling() && kppet.g_lightweight);
	kperf_on_cpu_update();
}

int
kppet_get_lightweight_pet(void)
{
	return kppet.g_lightweight;
}

int
kppet_set_lightweight_pet(int on)
{
	if (kperf_is_sampling()) {
		return EBUSY;
	}

	kppet.g_lightweight = (on == 1);
	kppet_lightweight_active_update();
	return 0;
}

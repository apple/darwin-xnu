/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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

#include <kern/assert.h>
#include <kern/monotonic.h>
#include <kern/thread.h>
#include <machine/atomic.h>
#include <machine/monotonic.h>
#include <mach/mach_traps.h>
#include <stdatomic.h>
#include <sys/errno.h>

bool mt_debug = false;
_Atomic uint64_t mt_pmis = 0;
_Atomic uint64_t mt_retrograde = 0;

#define MT_KDBG_INSTRS_CYCLES(CODE) \
	KDBG_EVENTID(DBG_MONOTONIC, DBG_MT_INSTRS_CYCLES, CODE)

#define MT_KDBG_IC_CPU_CSWITCH MT_KDBG_INSTRS_CYCLES(1)

/*
 * Updating the thread counters takes place in the context switch path, so it
 * cannot introduce too much overhead.  Thus, updating takes no locks, instead
 * updating a generation count to an odd value to indicate that it's in the
 * critical section and that readers should wait until the generation count
 * returns to an even value.
 *
 * Reading the counters also needs to not see any "torn" states of the counters,
 * where a few of the counters are from a previous state and the rest are from
 * the current state.  For this reason, the reader redrives the entire read
 * operation if it sees mismatching generation counts at the beginning and end
 * of reading.
 */

#define MAXSPINS   100
#define MAXRETRIES 10

/*
 * Write the fixed counter values for the thread `thread` into `counts_out`.
 *
 * This function does not include the accumulated counter values since the
 * thread's last context switch or quantum expiration.
 */
int
mt_fixed_thread_counts(thread_t thread, uint64_t *counts_out)
{
	uint64_t start_gen, end_gen;
	uint64_t spins = 0, retries = 0;
	uint64_t counts[MT_CORE_NFIXED];

	/*
	 * Try to read a thread's counter values by ensuring its gen count is
	 * even.  If it's odd, it means that a thread is trying to update its
	 * counters.
	 *
	 * Spin until the gen count is even.
	 */
spin:
	start_gen = atomic_load_explicit(&thread->t_monotonic.mth_gen,
	    memory_order_acquire);
retry:
	if (start_gen & 1) {
		spins++;
		if (spins > MAXSPINS) {
			return EBUSY;
		}
		goto spin;
	}

	for (int i = 0; i < MT_CORE_NFIXED; i++) {
		counts[i] = thread->t_monotonic.mth_counts[i];
	}

	/*
	 * After reading the counters, check the gen count again.  If it is
	 * different from the value that we started with, the thread raced
	 * writing its counters with us reading them.  We need to redrive the
	 * entire operation.
	 *
	 * Go back to check if the value we just read was even and try to read
	 * again.
	 */
	end_gen = atomic_load_explicit(&thread->t_monotonic.mth_gen,
	    memory_order_acquire);
	if (end_gen != start_gen) {
		retries++;
		if (retries > MAXRETRIES) {
			return EAGAIN;
		}
		start_gen = end_gen;
		goto retry;
	}

	/*
	 * Only after getting a consistent snapshot of the counters should we
	 * write them into the provided buffer.
	 */
	for (int i = 0; i < MT_CORE_NFIXED; i++) {
		counts_out[i] = counts[i];
	}
	return 0;
}

static void mt_fixed_counts_internal(uint64_t *counts, uint64_t *counts_since);

bool
mt_update_thread(thread_t thread)
{
	if (!mt_core_supported) {
		return false;
	}

	assert(ml_get_interrupts_enabled() == FALSE);

	uint64_t counts[MT_CORE_NFIXED], counts_since[MT_CORE_NFIXED];
	mt_fixed_counts_internal(counts, counts_since);

	/*
	 * Enter the update cycle by incrementing the gen count to be odd --
	 * this tells any readers to spin on the gen count, waiting for it to go
	 * even.
	 */
	__assert_only uint64_t enter_gen = atomic_fetch_add_explicit(
		&thread->t_monotonic.mth_gen, 1, memory_order_release);
	/*
	 * Should not have pre-empted a modification to the counts.
	 */
	assert((enter_gen & 1) == 0);

	for (int i = 0; i < MT_CORE_NFIXED; i++) {
		thread->t_monotonic.mth_counts[i] += counts_since[i];
	}

	/*
	 * Exit the update by making the gen count even again.  Readers check
	 * the gen count for equality, and will redrive the reads if the values
	 * before and after reading don't match.
	 */
	__assert_only uint64_t exit_gen = atomic_fetch_add_explicit(
		&thread->t_monotonic.mth_gen, 1, memory_order_release);
	/*
	 * Make sure no other writers came through behind us.
	 */
	assert(exit_gen == (enter_gen + 1));

	return true;
}

void
mt_sched_update(thread_t thread)
{
	bool updated = mt_update_thread(thread);
	if (!updated) {
		return;
	}

	if (kdebug_debugid_explicitly_enabled(MT_KDBG_IC_CPU_CSWITCH)) {
		struct mt_cpu *mtc = mt_cur_cpu();

		KDBG_RELEASE(MT_KDBG_IC_CPU_CSWITCH,
#ifdef MT_CORE_INSTRS
		    mtc->mtc_counts[MT_CORE_INSTRS],
#else /* defined(MT_CORE_INSTRS) */
		    0,
#endif /* !defined(MT_CORE_INSTRS) */
		    mtc->mtc_counts[MT_CORE_CYCLES]);
	}
}

int
mt_fixed_task_counts(task_t task, uint64_t *counts_out)
{
	assert(task != TASK_NULL);
	assert(counts_out != NULL);

	if (!mt_core_supported) {
		memset(counts_out, 0, sizeof(*counts_out) * MT_CORE_NFIXED);
		return 1;
	}

	task_lock(task);

	uint64_t counts[MT_CORE_NFIXED] = { 0 };
	for (int i = 0; i < MT_CORE_NFIXED; i++) {
		counts[i] = task->task_monotonic.mtk_counts[i];
	}

	uint64_t thread_counts[MT_CORE_NFIXED] = { 0 };
	thread_t thread = THREAD_NULL;
	thread_t curthread = current_thread();
	bool needs_current = false;
	int r = 0;
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		/*
		 * Get the current thread's counters after doing this
		 * processing, without holding the task lock.
		 */
		if (thread == curthread) {
			needs_current = true;
			continue;
		} else {
			r = mt_fixed_thread_counts(thread, thread_counts);
			if (r) {
				goto error;
			}
		}

		for (int i = 0; i < MT_CORE_NFIXED; i++) {
			counts[i] += thread_counts[i];
		}
	}

	task_unlock(task);

	if (needs_current) {
		mt_cur_thread_fixed_counts(thread_counts);
	}

	for (int i = 0; i < MT_CORE_NFIXED; i++) {
		if (needs_current) {
			counts[i] += thread_counts[i];
		}
		counts_out[i] = counts[i];
	}
	return 0;

error:
	task_unlock(task);
	return r;
}

uint64_t
mt_mtc_update_count(struct mt_cpu *mtc, unsigned int ctr)
{
	uint64_t snap = mt_core_snap(ctr);
	if (snap < mtc->mtc_snaps[ctr]) {
		if (mt_debug) {
			kprintf("monotonic: cpu %d: thread %#llx: "
			    "retrograde counter %u value: %llu, last read = %llu\n",
			    cpu_number(), thread_tid(current_thread()), ctr, snap,
			    mtc->mtc_snaps[ctr]);
		}
		(void)atomic_fetch_add_explicit(&mt_retrograde, 1,
		    memory_order_relaxed);
		mtc->mtc_snaps[ctr] = snap;
		return 0;
	}

	uint64_t count = snap - mtc->mtc_snaps[ctr];
	mtc->mtc_snaps[ctr] = snap;

	return count;
}

uint64_t
mt_cpu_update_count(cpu_data_t *cpu, unsigned int ctr)
{
	return mt_mtc_update_count(&cpu->cpu_monotonic, ctr);
}

static void
mt_fixed_counts_internal(uint64_t *counts, uint64_t *counts_since)
{
	assert(ml_get_interrupts_enabled() == FALSE);

	struct mt_cpu *mtc = mt_cur_cpu();
	assert(mtc != NULL);

	mt_mtc_update_fixed_counts(mtc, counts, counts_since);
}

void
mt_mtc_update_fixed_counts(struct mt_cpu *mtc, uint64_t *counts,
    uint64_t *counts_since)
{
	if (!mt_core_supported) {
		return;
	}

	for (int i = 0; i < MT_CORE_NFIXED; i++) {
		uint64_t last_delta;
		uint64_t count;

		last_delta = mt_mtc_update_count(mtc, i);
		count = mtc->mtc_counts[i] + last_delta;

		if (counts) {
			counts[i] = count;
		}
		if (counts_since) {
			assert(counts != NULL);
			counts_since[i] = count - mtc->mtc_counts_last[i];
			mtc->mtc_counts_last[i] = count;
		}

		mtc->mtc_counts[i] = count;
	}
}

void
mt_update_fixed_counts(void)
{
	assert(ml_get_interrupts_enabled() == FALSE);

#if defined(__x86_64__)
	__builtin_ia32_lfence();
#elif defined(__arm__) || defined(__arm64__)
	__builtin_arm_isb(ISB_SY);
#endif /* !defined(__x86_64__) && (defined(__arm__) || defined(__arm64__)) */

	mt_fixed_counts_internal(NULL, NULL);
}

void
mt_fixed_counts(uint64_t *counts)
{
#if defined(__x86_64__)
	__builtin_ia32_lfence();
#elif defined(__arm__) || defined(__arm64__)
	__builtin_arm_isb(ISB_SY);
#endif /* !defined(__x86_64__) && (defined(__arm__) || defined(__arm64__)) */

	int intrs_en = ml_set_interrupts_enabled(FALSE);
	mt_fixed_counts_internal(counts, NULL);
	ml_set_interrupts_enabled(intrs_en);
}

void
mt_cur_thread_fixed_counts(uint64_t *counts)
{
	if (!mt_core_supported) {
		memset(counts, 0, sizeof(*counts) * MT_CORE_NFIXED);
		return;
	}

	thread_t curthread = current_thread();
	int intrs_en = ml_set_interrupts_enabled(FALSE);
	(void)mt_update_thread(curthread);
	for (int i = 0; i < MT_CORE_NFIXED; i++) {
		counts[i] = curthread->t_monotonic.mth_counts[i];
	}
	ml_set_interrupts_enabled(intrs_en);
}

void
mt_cur_task_fixed_counts(uint64_t *counts)
{
	task_t curtask = current_task();

	mt_fixed_task_counts(curtask, counts);
}

/* FIXME these should only update the counter that is being accessed */

uint64_t
mt_cur_thread_instrs(void)
{
#ifdef MT_CORE_INSTRS
	thread_t curthread = current_thread();
	boolean_t intrs_en;
	uint64_t count;

	if (!mt_core_supported) {
		return 0;
	}

	intrs_en = ml_set_interrupts_enabled(FALSE);
	(void)mt_update_thread(curthread);
	count = curthread->t_monotonic.mth_counts[MT_CORE_INSTRS];
	ml_set_interrupts_enabled(intrs_en);

	return count;
#else /* defined(MT_CORE_INSTRS) */
	return 0;
#endif /* !defined(MT_CORE_INSTRS) */
}

uint64_t
mt_cur_thread_cycles(void)
{
	thread_t curthread = current_thread();
	boolean_t intrs_en;
	uint64_t count;

	if (!mt_core_supported) {
		return 0;
	}

	intrs_en = ml_set_interrupts_enabled(FALSE);
	(void)mt_update_thread(curthread);
	count = curthread->t_monotonic.mth_counts[MT_CORE_CYCLES];
	ml_set_interrupts_enabled(intrs_en);

	return count;
}

uint64_t
mt_cur_cpu_instrs(void)
{
#ifdef MT_CORE_INSTRS
	uint64_t counts[MT_CORE_NFIXED];

	if (!mt_core_supported) {
		return 0;
	}

	mt_fixed_counts(counts);
	return counts[MT_CORE_INSTRS];
#else /* defined(MT_CORE_INSTRS) */
	return 0;
#endif /* !defined(MT_CORE_INSTRS) */
}

uint64_t
mt_cur_cpu_cycles(void)
{
	uint64_t counts[MT_CORE_NFIXED];

	if (!mt_core_supported) {
		return 0;
	}

	mt_fixed_counts(counts);
	return counts[MT_CORE_CYCLES];
}

void
mt_update_task(task_t task, thread_t thread)
{
	task_lock_assert_owned(task);

	if (!mt_core_supported) {
		return;
	}

	for (int i = 0; i < MT_CORE_NFIXED; i++) {
		task->task_monotonic.mtk_counts[i] += thread->t_monotonic.mth_counts[i];
	}
}

void
mt_terminate_update(task_t task, thread_t thread)
{
	mt_update_task(task, thread);
}

void
mt_perfcontrol(uint64_t *instrs, uint64_t *cycles)
{
	if (!mt_core_supported) {
		*instrs = 0;
		*cycles = 0;
		return;
	}

	struct mt_cpu *mtc = mt_cur_cpu();

	/*
	 * The performance controller queries the hardware directly, so provide the
	 * last snapshot we took for the core.  This is the value from when we
	 * updated the thread counts.
	 */

#ifdef MT_CORE_INSTRS
	*instrs = mtc->mtc_snaps[MT_CORE_INSTRS];
#else /* defined(MT_CORE_INSTRS) */
	*instrs = 0;
#endif /* !defined(MT_CORE_INSTRS) */

	*cycles = mtc->mtc_snaps[MT_CORE_CYCLES];
}

void
mt_stackshot_thread(thread_t thread, uint64_t *instrs, uint64_t *cycles)
{
	assert(mt_core_supported);

#ifdef MT_CORE_INSTRS
	*instrs = thread->t_monotonic.mth_counts[MT_CORE_INSTRS];
#else /* defined(MT_CORE_INSTRS) */
	*instrs = 0;
#endif /* !defined(MT_CORE_INSTRS) */

	*cycles = thread->t_monotonic.mth_counts[MT_CORE_CYCLES];
}

void
mt_stackshot_task(task_t task, uint64_t *instrs, uint64_t *cycles)
{
	assert(mt_core_supported);

#ifdef MT_CORE_INSTRS
	*instrs = task->task_monotonic.mtk_counts[MT_CORE_INSTRS];
#else /* defined(MT_CORE_INSTRS) */
	*instrs = 0;
#endif /* !defined(MT_CORE_INSTRS) */

	*cycles = task->task_monotonic.mtk_counts[MT_CORE_CYCLES];
}

/*
 * Maintain reset values for the fixed instruction and cycle counters so
 * clients can be notified after a given number of those events occur.  This is
 * only used by microstackshot.
 */

bool mt_microstackshots = false;
unsigned int mt_microstackshot_ctr = 0;
mt_pmi_fn mt_microstackshot_pmi_handler = NULL;
void *mt_microstackshot_ctx = NULL;
uint64_t mt_core_reset_values[MT_CORE_NFIXED] = { 0 };

#define MT_MIN_FIXED_PERIOD (10 * 1000 * 1000)

int
mt_microstackshot_start(unsigned int ctr, uint64_t period, mt_pmi_fn handler,
    void *ctx)
{
	assert(ctr < MT_CORE_NFIXED);

	if (period < MT_MIN_FIXED_PERIOD) {
		return EINVAL;
	}
	if (mt_microstackshots) {
		return EBUSY;
	}

	mt_microstackshot_ctr = ctr;
	mt_microstackshot_pmi_handler = handler;
	mt_microstackshot_ctx = ctx;

	int error = mt_microstackshot_start_arch(period);
	if (error) {
		mt_microstackshot_ctr = 0;
		mt_microstackshot_pmi_handler = NULL;
		mt_microstackshot_ctx = NULL;
		return error;
	}

	mt_microstackshots = true;

	return 0;
}

int
mt_microstackshot_stop(void)
{
	mt_microstackshots = false;
	memset(mt_core_reset_values, 0, sizeof(mt_core_reset_values));

	return 0;
}

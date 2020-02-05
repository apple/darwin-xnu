/*
 * Copyright (c) 2000-2018 Apple Inc. All rights reserved.
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

#define LOCK_PRIVATE 1

#include <mach_ldebug.h>

#include <kern/locks.h>
#include <kern/kalloc.h>
#include <kern/misc_protos.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/cpu_data.h>
#include <kern/cpu_number.h>
#include <kern/sched_prim.h>
#include <kern/debug.h>
#include <string.h>

#include <i386/machine_routines.h> /* machine_timeout_suspended() */
#include <machine/atomic.h>
#include <machine/machine_cpu.h>
#include <i386/mp.h>
#include <machine/atomic.h>
#include <sys/kdebug.h>
#include <i386/locks_i386_inlines.h>

/*
 * Fast path routines for lck_mtx locking and unlocking functions.
 * Fast paths will try a single compare and swap instruction to acquire/release the lock
 * and interlock, and they will fall through the slow path in case it fails.
 *
 * These functions were previously implemented in x86 assembly,
 * and some optimizations are in place in this c code to obtain a compiled code
 * as performant and compact as the assembly version.
 *
 * To avoid to inline these functions and increase the kernel text size all functions have
 * the __attribute__((noinline)) specified.
 *
 * The code is structured in such a way there are no calls to functions that will return
 * on the context of the caller function, i.e. all functions called are or tail call functions
 * or inline functions. The number of arguments of the tail call functions are less then six,
 * so that they can be passed over registers and do not need to be pushed on stack.
 * This allows the compiler to not create a stack frame for the functions.
 *
 * The file is compiled with momit-leaf-frame-pointer and O2.
 */

#if DEVELOPMENT || DEBUG

/*
 * If one or more simplelocks are currently held by a thread,
 * an attempt to acquire a mutex will cause this check to fail
 * (since a mutex lock may context switch, holding a simplelock
 * is not a good thing).
 */
void __inline__
lck_mtx_check_preemption(void)
{
	if (get_preemption_level() == 0) {
		return;
	}
	if (LckDisablePreemptCheck) {
		return;
	}
	if (current_cpu_datap()->cpu_hibernate) {
		return;
	}

	panic("preemption_level(%d) != 0\n", get_preemption_level());
}

#else /* DEVELOPMENT || DEBUG */

void __inline__
lck_mtx_check_preemption(void)
{
	return;
}

#endif /* DEVELOPMENT || DEBUG */

/*
 * Routine:	lck_mtx_lock
 *
 * Locks a mutex for current thread.
 * It tries the fast path first and
 * falls through the slow path in case
 * of contention.
 *
 * Interlock or mutex cannot be already held by current thread.
 * In case of contention it might sleep.
 */
__attribute__((noinline))
void
lck_mtx_lock(
	lck_mtx_t       *lock)
{
	uint32_t prev, state;

	lck_mtx_check_preemption();
	state = ordered_load_mtx_state(lock);

	/*
	 * Fast path only if the mutex is not held
	 * interlock is not contended and there are no waiters.
	 * Indirect mutexes will fall through the slow path as
	 * well as destroyed mutexes.
	 */

	prev = state & ~(LCK_MTX_ILOCKED_MSK | LCK_MTX_MLOCKED_MSK | LCK_MTX_WAITERS_MSK);
	state = prev | LCK_MTX_ILOCKED_MSK | LCK_MTX_MLOCKED_MSK;

	disable_preemption();
	if (!os_atomic_cmpxchg(&lock->lck_mtx_state, prev, state, acquire)) {
		enable_preemption();
		return lck_mtx_lock_slow(lock);
	}

	/* mutex acquired, interlock acquired and preemption disabled */

	thread_t thread = current_thread();
	/* record owner of mutex */
	ordered_store_mtx_owner(lock, (uintptr_t)thread);

#if MACH_LDEBUG
	if (thread) {
		thread->mutex_count++;          /* lock statistic */
	}
#endif

	/* release interlock and re-enable preemption */
	lck_mtx_lock_finish_inline(lock, state, FALSE);
}

/*
 * Routine:	lck_mtx_try_lock
 *
 * Try to lock a mutex for current thread.
 * It tries the fast path first and
 * falls through the slow path in case
 * of contention.
 *
 * Interlock or mutex cannot be already held by current thread.
 *
 * In case the mutex is held (either as spin or mutex)
 * the function will fail, it will acquire the mutex otherwise.
 */
__attribute__((noinline))
boolean_t
lck_mtx_try_lock(
	lck_mtx_t       *lock)
{
	uint32_t prev, state;

	state = ordered_load_mtx_state(lock);

	/*
	 * Fast path only if the mutex is not held
	 * interlock is not contended and there are no waiters.
	 * Indirect mutexes will fall through the slow path as
	 * well as destroyed mutexes.
	 */

	prev = state & ~(LCK_MTX_ILOCKED_MSK | LCK_MTX_MLOCKED_MSK | LCK_MTX_WAITERS_MSK);
	state = prev | LCK_MTX_ILOCKED_MSK | LCK_MTX_MLOCKED_MSK;

	disable_preemption();
	if (!os_atomic_cmpxchg(&lock->lck_mtx_state, prev, state, acquire)) {
		enable_preemption();
		return lck_mtx_try_lock_slow(lock);
	}

	/* mutex acquired, interlock acquired and preemption disabled */

	thread_t thread = current_thread();
	/* record owner of mutex */
	ordered_store_mtx_owner(lock, (uintptr_t)thread);

#if MACH_LDEBUG
	if (thread) {
		thread->mutex_count++;          /* lock statistic */
	}
#endif

	/* release interlock and re-enable preemption */
	lck_mtx_try_lock_finish_inline(lock, state);

	return TRUE;
}

/*
 * Routine:	lck_mtx_lock_spin_always
 *
 * Try to lock a mutex as spin lock for current thread.
 * It tries the fast path first and
 * falls through the slow path in case
 * of contention.
 *
 * Interlock or mutex cannot be already held by current thread.
 *
 * In case the mutex is held as mutex by another thread
 * this function will switch behavior and try to acquire the lock as mutex.
 *
 * In case the mutex is held as spinlock it will spin contending
 * for it.
 *
 * In case of contention it might sleep.
 */
__attribute__((noinline))
void
lck_mtx_lock_spin_always(
	lck_mtx_t       *lock)
{
	uint32_t prev, state;

	state = ordered_load_mtx_state(lock);

	/*
	 * Fast path only if the mutex is not held
	 * neither as mutex nor as spin and
	 * interlock is not contended.
	 * Indirect mutexes will fall through the slow path as
	 * well as destroyed mutexes.
	 */

	/* Note LCK_MTX_SPIN_MSK is set only if LCK_MTX_ILOCKED_MSK is set */
	prev = state & ~(LCK_MTX_ILOCKED_MSK | LCK_MTX_MLOCKED_MSK);
	state = prev | LCK_MTX_ILOCKED_MSK | LCK_MTX_SPIN_MSK;

	disable_preemption();
	if (!os_atomic_cmpxchg(&lock->lck_mtx_state, prev, state, acquire)) {
		enable_preemption();
		return lck_mtx_lock_spin_slow(lock);
	}

	/* mutex acquired as spinlock, interlock acquired and preemption disabled */

	thread_t thread = current_thread();
	/* record owner of mutex */
	ordered_store_mtx_owner(lock, (uintptr_t)thread);

#if MACH_LDEBUG
	if (thread) {
		thread->mutex_count++;          /* lock statistic */
	}
#endif

#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_MTX_LOCK_SPIN_ACQUIRE, lock, 0);
#endif
	/* return with the interlock held and preemption disabled */
	return;
}

/*
 * Routine:	lck_mtx_lock_spin
 *
 * Try to lock a mutex as spin lock for current thread.
 * It tries the fast path first and
 * falls through the slow path in case
 * of contention.
 *
 * Interlock or mutex cannot be already held by current thread.
 *
 * In case the mutex is held as mutex by another thread
 * this function will switch behavior and try to acquire the lock as mutex.
 *
 * In case the mutex is held as spinlock it will spin contending
 * for it.
 *
 * In case of contention it might sleep.
 */
void
lck_mtx_lock_spin(
	lck_mtx_t       *lock)
{
	lck_mtx_check_preemption();
	lck_mtx_lock_spin_always(lock);
}

/*
 * Routine:	lck_mtx_try_lock_spin_always
 *
 * Try to lock a mutex as spin lock for current thread.
 * It tries the fast path first and
 * falls through the slow path in case
 * of contention.
 *
 * Interlock or mutex cannot be already held by current thread.
 *
 * In case the mutex is held (either as spin or mutex)
 * the function will fail, it will acquire the mutex as spin lock
 * otherwise.
 *
 */
__attribute__((noinline))
boolean_t
lck_mtx_try_lock_spin_always(
	lck_mtx_t       *lock)
{
	uint32_t prev, state;

	state = ordered_load_mtx_state(lock);

	/*
	 * Fast path only if the mutex is not held
	 * neither as mutex nor as spin and
	 * interlock is not contended.
	 * Indirect mutexes will fall through the slow path as
	 * well as destroyed mutexes.
	 */

	/* Note LCK_MTX_SPIN_MSK is set only if LCK_MTX_ILOCKED_MSK is set */
	prev = state & ~(LCK_MTX_ILOCKED_MSK | LCK_MTX_MLOCKED_MSK);
	state = prev | LCK_MTX_ILOCKED_MSK | LCK_MTX_SPIN_MSK;

	disable_preemption();
	if (!os_atomic_cmpxchg(&lock->lck_mtx_state, prev, state, acquire)) {
		enable_preemption();
		return lck_mtx_try_lock_spin_slow(lock);
	}

	/* mutex acquired as spinlock, interlock acquired and preemption disabled */

	thread_t thread = current_thread();
	/* record owner of mutex */
	ordered_store_mtx_owner(lock, (uintptr_t)thread);

#if MACH_LDEBUG
	if (thread) {
		thread->mutex_count++;          /* lock statistic */
	}
#endif

#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_MTX_TRY_SPIN_LOCK_ACQUIRE, lock, 0);
#endif

	/* return with the interlock held and preemption disabled */
	return TRUE;
}

/*
 * Routine:	lck_mtx_try_lock_spin
 *
 * Try to lock a mutex as spin lock for current thread.
 * It tries the fast path first and
 * falls through the slow path in case
 * of contention.
 *
 * Interlock or mutex cannot be already held by current thread.
 *
 * In case the mutex is held (either as spin or mutex)
 * the function will fail, it will acquire the mutex as spin lock
 * otherwise.
 *
 */
boolean_t
lck_mtx_try_lock_spin(
	lck_mtx_t       *lock)
{
	return lck_mtx_try_lock_spin_always(lock);
}

/*
 * Routine:     lck_mtx_unlock
 *
 * Unlocks a mutex held by current thread.
 * It tries the fast path first, and falls
 * through the slow path in case waiters need to
 * be woken up.
 *
 * Interlock can be held, and the slow path will
 * unlock the mutex for this case.
 */
__attribute__((noinline))
void
lck_mtx_unlock(
	lck_mtx_t       *lock)
{
	uint32_t prev, state;

	state = ordered_load_mtx_state(lock);

	if (state & LCK_MTX_SPIN_MSK) {
		return lck_mtx_unlock_slow(lock);
	}

	/*
	 * Only full mutex will go through the fast path
	 * (if the lock was acquired as a spinlock it will
	 * fall through the slow path).
	 * If there are waiters it will fall
	 * through the slow path.
	 * If it is indirect it will fall through the slow path.
	 */

	/*
	 * Fast path state:
	 * interlock not held, no waiters, no promotion and mutex held.
	 */
	prev = state & ~(LCK_MTX_ILOCKED_MSK | LCK_MTX_WAITERS_MSK);
	prev |= LCK_MTX_MLOCKED_MSK;

	state = prev | LCK_MTX_ILOCKED_MSK;
	state &= ~LCK_MTX_MLOCKED_MSK;

	disable_preemption();

	/* the memory order needs to be acquire because it is acquiring the interlock */
	if (!os_atomic_cmpxchg(&lock->lck_mtx_state, prev, state, acquire)) {
		enable_preemption();
		return lck_mtx_unlock_slow(lock);
	}

	/* mutex released, interlock acquired and preemption disabled */

#if DEVELOPMENT | DEBUG
	thread_t owner = (thread_t)lock->lck_mtx_owner;
	if (__improbable(owner != current_thread())) {
		lck_mtx_owner_check_panic(lock);
	}
#endif

	/* clear owner */
	ordered_store_mtx_owner(lock, 0);
	/* release interlock */
	state &= ~LCK_MTX_ILOCKED_MSK;
	ordered_store_mtx_state_release(lock, state);

#if     MACH_LDEBUG
	thread_t thread = current_thread();
	if (thread) {
		thread->mutex_count--;
	}
#endif  /* MACH_LDEBUG */

	/* re-enable preemption */
	lck_mtx_unlock_finish_inline(lock, FALSE);
}

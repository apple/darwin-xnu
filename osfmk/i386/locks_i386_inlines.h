/*
 * Copyright (c) 201 Apple Inc. All rights reserved.
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

#ifndef _I386_LOCKS_I386_INLINES_H_
#define _I386_LOCKS_I386_INLINES_H_

#include <kern/locks.h>
/*
 * We need only enough declarations from the BSD-side to be able to
 * test if our probe is active, and to call __dtrace_probe().  Setting
 * NEED_DTRACE_DEFS gets a local copy of those definitions pulled in.
 */
#if	CONFIG_DTRACE
#define NEED_DTRACE_DEFS
#include <../bsd/sys/lockstat.h>
#endif

// Enforce program order of loads and stores.
#define ordered_load(target) _Generic( (target),\
		uint32_t* : __c11_atomic_load((_Atomic uint32_t* )(target), memory_order_relaxed), \
		uintptr_t*: __c11_atomic_load((_Atomic uintptr_t*)(target), memory_order_relaxed) )
#define ordered_store_release(target, value) _Generic( (target),\
		uint32_t* : __c11_atomic_store((_Atomic uint32_t* )(target), (value), memory_order_release_smp), \
		uintptr_t*: __c11_atomic_store((_Atomic uintptr_t*)(target), (value), memory_order_release_smp) )
#define ordered_store_volatile(target, value) _Generic( (target),\
		volatile uint32_t* : __c11_atomic_store((_Atomic volatile uint32_t* )(target), (value), memory_order_relaxed), \
		volatile uintptr_t*: __c11_atomic_store((_Atomic volatile uintptr_t*)(target), (value), memory_order_relaxed) )

/* Enforce program order of loads and stores. */
#define ordered_load_mtx_state(lock)			ordered_load(&(lock)->lck_mtx_state)
#define ordered_store_mtx_state_release(lock, value)		ordered_store_release(&(lock)->lck_mtx_state, (value))
#define ordered_store_mtx_owner(lock, value)	ordered_store_volatile(&(lock)->lck_mtx_owner, (value))

#if DEVELOPMENT | DEBUG
void lck_mtx_owner_check_panic(lck_mtx_t       *mutex);
#endif

__attribute__((always_inline))
static inline void
lck_mtx_ilk_unlock_inline(
	lck_mtx_t       *mutex,
	uint32_t	state)
{
	state &= ~LCK_MTX_ILOCKED_MSK;
	ordered_store_mtx_state_release(mutex, state);

	enable_preemption();
}

__attribute__((always_inline))
static inline void
lck_mtx_lock_finish_inline(
	lck_mtx_t       *mutex,
	uint32_t 	state,
	boolean_t	indirect)
{
	assert(state & LCK_MTX_ILOCKED_MSK);

	/* release the interlock and re-enable preemption */
	lck_mtx_ilk_unlock_inline(mutex, state);

#if	CONFIG_DTRACE
	if (indirect) {
		LOCKSTAT_RECORD(LS_LCK_MTX_EXT_LOCK_ACQUIRE, mutex, 0);
	} else {
		LOCKSTAT_RECORD(LS_LCK_MTX_LOCK_ACQUIRE, mutex, 0);
	}
#endif
}

__attribute__((always_inline))
static inline void
lck_mtx_try_lock_finish_inline(
	lck_mtx_t       *mutex,
	uint32_t 	state)
{
	/* release the interlock and re-enable preemption */
	lck_mtx_ilk_unlock_inline(mutex, state);

#if	CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_MTX_TRY_LOCK_ACQUIRE, mutex, 0);
#endif
}

__attribute__((always_inline))
static inline void
lck_mtx_convert_spin_finish_inline(
	lck_mtx_t       *mutex,
	uint32_t 	state)
{
	/* release the interlock and acquire it as mutex */
	state &= ~(LCK_MTX_ILOCKED_MSK | LCK_MTX_SPIN_MSK);
	state |= LCK_MTX_MLOCKED_MSK;

	ordered_store_mtx_state_release(mutex, state);
	enable_preemption();
}

__attribute__((always_inline))
static inline void
lck_mtx_unlock_finish_inline(
	lck_mtx_t       *mutex,
	boolean_t       indirect)
{
	enable_preemption();

#if	CONFIG_DTRACE
	if (indirect) {
		LOCKSTAT_RECORD(LS_LCK_MTX_EXT_UNLOCK_RELEASE, mutex, 0);
	} else {
		LOCKSTAT_RECORD(LS_LCK_MTX_UNLOCK_RELEASE, mutex, 0);
	}
#endif	// CONFIG_DTRACE
}

#endif /* _I386_LOCKS_I386_INLINES_H_ */


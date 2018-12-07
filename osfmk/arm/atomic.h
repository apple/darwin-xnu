/*
 * Copyright (c) 2015 Apple Inc. All rights reserved.
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

#ifndef _ARM_ATOMIC_H_
#define _ARM_ATOMIC_H_

#include <mach/boolean.h>
#include <arm/smp.h>

// Parameter for __builtin_arm_dmb
#define DMB_NSH		0x7
#define DMB_ISHLD	0x9
#define DMB_ISHST	0xa
#define DMB_ISH		0xb
#define DMB_SY		0xf

// Parameter for __builtin_arm_dsb
#define DSB_NSH		0x7
#define DSB_ISHLD	0x9
#define DSB_ISHST	0xa
#define DSB_ISH		0xb
#define DSB_SY		0xf

// Parameter for __builtin_arm_isb
#define ISB_SY		0xf

#if	__SMP__

#define memory_order_consume_smp memory_order_consume
#define memory_order_acquire_smp memory_order_acquire
#define memory_order_release_smp memory_order_release
#define memory_order_acq_rel_smp memory_order_acq_rel
#define memory_order_seq_cst_smp memory_order_seq_cst

#else

#define memory_order_consume_smp memory_order_relaxed
#define memory_order_acquire_smp memory_order_relaxed
#define memory_order_release_smp memory_order_relaxed
#define memory_order_acq_rel_smp memory_order_relaxed
#define memory_order_seq_cst_smp memory_order_relaxed

#endif

/*
 * Atomic operations functions
 *
 * These static functions are designed for inlining
 * It is expected that the memory_order arguments are
 * known at compile time.  This collapses these
 * functions into a simple atomic operation
 */

static inline boolean_t
memory_order_has_acquire(enum memory_order ord)
{
	switch (ord) {
	case memory_order_consume:
	case memory_order_acquire:
	case memory_order_acq_rel:
	case memory_order_seq_cst:
		return TRUE;
	default:
		return FALSE;
	}
}

static inline boolean_t
memory_order_has_release(enum memory_order ord)
{
	switch (ord) {
	case memory_order_release:
	case memory_order_acq_rel:
	case memory_order_seq_cst:
		return TRUE;
	default:
		return FALSE;
	}
}

#ifdef ATOMIC_PRIVATE

#define clear_exclusive()	__builtin_arm_clrex()

__unused static uint32_t
load_exclusive32(uint32_t *target, enum memory_order ord)
{
	uint32_t	value;

#if __arm__
	if (memory_order_has_release(ord)) {
		// Pre-load release barrier
		atomic_thread_fence(memory_order_release);
	}
	value = __builtin_arm_ldrex(target);
#else
	if (memory_order_has_acquire(ord))
		value = __builtin_arm_ldaex(target);	// ldaxr
	else
		value = __builtin_arm_ldrex(target);	// ldxr
#endif	// __arm__
	return value;
}

__unused static boolean_t
store_exclusive32(uint32_t *target, uint32_t value, enum memory_order ord)
{
	boolean_t err;

#if __arm__
	err = __builtin_arm_strex(value, target);
	if (memory_order_has_acquire(ord)) {
		// Post-store acquire barrier
		atomic_thread_fence(memory_order_acquire);
	}
#else
	if (memory_order_has_release(ord))
		err = __builtin_arm_stlex(value, target);	// stlxr
	else
		err = __builtin_arm_strex(value, target);	// stxr
#endif	// __arm__
	return !err;
}

__unused static uintptr_t
load_exclusive(uintptr_t *target, enum memory_order ord)
{
#if !__LP64__
	return load_exclusive32((uint32_t *)target, ord);
#else
	uintptr_t	value;

	if (memory_order_has_acquire(ord))
		value = __builtin_arm_ldaex(target);	// ldaxr
	else
		value = __builtin_arm_ldrex(target);	// ldxr
	return value;
#endif	// __arm__
}

__unused static boolean_t
store_exclusive(uintptr_t *target, uintptr_t value, enum memory_order ord)
{
#if !__LP64__
	return store_exclusive32((uint32_t *)target, value, ord);
#else
	boolean_t err;

	if (memory_order_has_release(ord))
		err = __builtin_arm_stlex(value, target);	// stlxr
	else
		err = __builtin_arm_strex(value, target);	// stxr
	return !err;
#endif
}

__unused static boolean_t
atomic_compare_exchange(uintptr_t *target, uintptr_t oldval, uintptr_t newval,
			enum memory_order orig_ord, boolean_t wait)
{
	enum memory_order	ord = orig_ord;
	uintptr_t			value;


#if __arm__
	ord = memory_order_relaxed;
	if (memory_order_has_release(orig_ord)) {
		atomic_thread_fence(memory_order_release);
	}
#endif
	do {
		value = load_exclusive(target, ord);
		if (value != oldval) {
			if (wait)
				wait_for_event();	// Wait with monitor held
			else
				clear_exclusive();	// Clear exclusive monitor
			return FALSE;
		}
	} while (!store_exclusive(target, newval, ord));
#if __arm__
	if (memory_order_has_acquire(orig_ord)) {
		atomic_thread_fence(memory_order_acquire);
	}
#endif
	return TRUE;
}

#endif // ATOMIC_PRIVATE

#if __arm__
#undef os_atomic_rmw_loop
#define os_atomic_rmw_loop(p, ov, nv, m, ...)  ({ \
		boolean_t _result = FALSE; uint32_t _err = 0; \
		typeof(atomic_load(p)) *_p = (typeof(atomic_load(p)) *)(p); \
		for (;;) { \
			ov = __builtin_arm_ldrex(_p); \
			__VA_ARGS__; \
			if (!_err && memory_order_has_release(memory_order_##m)) { \
				/* only done for the first loop iteration */ \
				atomic_thread_fence(memory_order_release); \
			} \
			_err = __builtin_arm_strex(nv, _p); \
			if (__builtin_expect(!_err, 1)) { \
				if (memory_order_has_acquire(memory_order_##m)) { \
					atomic_thread_fence(memory_order_acquire); \
				} \
				_result = TRUE; \
				break; \
			} \
		} \
		_result; \
	})

#undef os_atomic_rmw_loop_give_up
#define os_atomic_rmw_loop_give_up(expr) \
		({ __builtin_arm_clrex(); expr; __builtin_trap(); })

#else

#undef os_atomic_rmw_loop
#define os_atomic_rmw_loop(p, ov, nv, m, ...)  ({ \
		boolean_t _result = FALSE; \
		typeof(atomic_load(p)) *_p = (typeof(atomic_load(p)) *)(p); \
		do { \
			if (memory_order_has_acquire(memory_order_##m)) { \
				ov = __builtin_arm_ldaex(_p); \
			} else { \
				ov = __builtin_arm_ldrex(_p); \
			} \
			__VA_ARGS__; \
			if (memory_order_has_release(memory_order_##m)) { \
				_result = !__builtin_arm_stlex(nv, _p); \
			} else { \
				_result = !__builtin_arm_strex(nv, _p); \
			} \
		} while (__builtin_expect(!_result, 0)); \
		_result; \
	})

#undef os_atomic_rmw_loop_give_up
#define os_atomic_rmw_loop_give_up(expr) \
		({ __builtin_arm_clrex(); expr; __builtin_trap(); })
#endif

#undef os_atomic_force_dependency_on
#if defined(__arm64__)
#define os_atomic_force_dependency_on(p, e) ({ \
		unsigned long _v; \
		__asm__("and %x[_v], %x[_e], xzr" : [_v] "=r" (_v) : [_e] "r" (e)); \
		(typeof(*(p)) *)((char *)(p) + _v); \
	})
#else
#define os_atomic_force_dependency_on(p, e) ({ \
		unsigned long _v; \
		__asm__("and %[_v], %[_e], #0" : [_v] "=r" (_v) : [_e] "r" (e)); \
		(typeof(*(p)) *)((char *)(p) + _v); \
	})
#endif // defined(__arm64__)

#endif // _ARM_ATOMIC_H_

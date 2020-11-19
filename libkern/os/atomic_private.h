/*
 * Copyright (c) 2018 Apple Inc. All rights reserved.
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

#ifndef __OS_ATOMIC_PRIVATE_H__
#define __OS_ATOMIC_PRIVATE_H__

/*!
 * @file <os/atomic_private.h>
 *
 * @brief
 * This file defines nicer (terser and safer) wrappers for C11's <stdatomic.h>.
 *
 * @discussion
 * @see xnu.git::doc/atomics.md which provides more extensive documentation
 * about this header.
 *
 * Note that some of the macros defined in this file may be overridden by
 * architecture specific headers.
 *
 * All the os_atomic* functions take an operation ordering argument that can be:
 * - C11 memory orders: relaxed, acquire, release, acq_rel or seq_cst which
 *   imply a memory fence on SMP machines, and always carry the matching
 *   compiler barrier semantics.
 *
 * - the os_atomic-specific `dependency` memory ordering that is used to
 *   document intent to a carry a data or address dependency.
 *   See doc/atomics.md for more information.
 *
 * - a compiler barrier: compiler_acquire, compiler_release, compiler_acq_rel
 *   without a corresponding memory fence.
 */

#include <os/atomic.h>

/*!
 * @group <os/atomic_private.h> tunables.
 *
 * @{
 *
 * @brief
 * @c OS_ATOMIC_CONFIG_* macros provide tunables for clients.
 */

/*!
 * @macro OS_ATOMIC_CONFIG_SMP
 *
 * @brief
 * Whether this is used on an SMP system, defaults to 1.
 */
#ifndef OS_ATOMIC_CONFIG_SMP
#define OS_ATOMIC_CONFIG_SMP 1
#endif // OS_ATOMIC_CONFIG_SMP

/*!
 * @macro OS_ATOMIC_CONFIG_STARVATION_FREE_ONLY
 *
 * @brief
 * Hide interfaces that can lead to starvation on certain hardware/build
 * configurations.
 *
 * @discussion
 * The following ABIs are currently supported by os_atomic:
 * - i386 and x86_64: Intel atomics
 * - armv7:           load/store exclusive
 * - armv8:           load/store exclusive
 * - armv8.1:         armv8.1 style atomics
 *
 * On armv8 hardware with asymmetric cores, using load/store exclusive based
 * atomics can lead to starvation in very hot code or non-preemptible context,
 * and code that is sensitive to such must not use these interfaces.
 *
 * When OS_ATOMIC_CONFIG_STARVATION_FREE_ONLY is set, any os_atomic_* interface
 * that may cause starvation will be made unavailable to avoid accidental use.
 *
 * Defaults:
 * - XNU:   builds per SoC, already safe
 * - Kexts: default to avoid starvable interfaces by default
 * - User:  default to allow starvable interfaces by default
 *
 * Note: at this time, on Apple supported platforms, the only configuration
 *       that is affected by this would be for the "arm64" slices.
 *
 *       Intel, armv7 variants, and the arm64e slice always are unaffected.
 */
#ifndef OS_ATOMIC_CONFIG_STARVATION_FREE_ONLY
#if XNU_KERNEL_PRIVATE
#define OS_ATOMIC_CONFIG_STARVATION_FREE_ONLY 0
#elif KERNEL
#define OS_ATOMIC_CONFIG_STARVATION_FREE_ONLY 1
#else
#define OS_ATOMIC_CONFIG_STARVATION_FREE_ONLY 0
#endif
#endif // OS_ATOMIC_CONFIG_STARVATION_FREE_ONLY

/*!
 * @macro OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY
 *
 * @brief
 * Expose the os_atomic-specific fake `dependency` memory ordering.
 *
 * @discussion
 * The dependency ordering can be used to try to "repair" C11's consume ordering
 * and should be limited to extremely complex algorithms where every cycle counts.
 *
 * Due to the inherent risks (no compiler support) for this feature, it is
 * reserved for expert and very domain-specific code only and is off by default.
 *
 * Default: 0
 */
#ifndef OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY
#if XNU_KERNEL_PRIVATE
#define OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY 1
#else
#define OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY 0
#endif
#endif // OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY

/*! @} */

/*!
 * @group <os/atomic_private.h> features (arch specific).
 *
 * @{
 *
 * @brief
 * The @c OS_ATOMIC_USE_* and @c OS_ATOMIC_HAS_* defines expose some
 * specificities of <os/atomic_private.h> implementation that are relevant to
 * certain clients and can be used to conditionalize code.
 */

/*!
 * @const OS_ATOMIC_HAS_LLSC
 *
 * @brief
 * Whether the platform has LL/SC features.
 *
 * @discussion
 * When set, the os_atomic_*_exclusive() macros are defined.
 */
#if defined(__i386__) || defined(__x86_64__)
#define OS_ATOMIC_HAS_LLSC  0
#elif defined(__arm__) || defined(__arm64__)
#define OS_ATOMIC_HAS_LLSC  1
#else
#error unsupported architecture
#endif

/*!
 * @const OS_ATOMIC_USE_LLSC
 *
 * @brief
 * Whether os_atomic* use LL/SC internally.
 *
 * @discussion
 * OS_ATOMIC_USE_LLSC implies OS_ATOMIC_HAS_LLSC.
 */
#if defined(__arm64__) && defined(__ARM_ARCH_8_2__)
#define OS_ATOMIC_USE_LLSC  0
#else
#define OS_ATOMIC_USE_LLSC  OS_ATOMIC_HAS_LLSC
#endif

/*!
 * @const OS_ATOMIC_HAS_STARVATION_FREE_RMW
 *
 * @brief
 * Whether os_atomic* Read-Modify-Write operations are starvation free
 * in the current configuration.
 */
#define OS_ATOMIC_HAS_STARVATION_FREE_RMW (!OS_ATOMIC_USE_LLSC)

/*! @} */

#include "atomic_private_impl.h" // Internal implementation details

/*!
 * @function os_compiler_barrier
 *
 * @brief
 * Provide a compiler barrier according to the specified ordering.
 *
 * @param m
 * An optional ordering among `acquire`, `release` or `acq_rel` which defaults
 * to `acq_rel` when not specified.
 * These are equivalent to the `compiler_acquire`, `compiler_release` and
 * `compiler_acq_rel` orderings taken by the os_atomic* functions
 */
#undef os_compiler_barrier
#define os_compiler_barrier(b...) \
	os_atomic_std(atomic_signal_fence)(_os_compiler_barrier_##b)

/*!
 * @function os_atomic_thread_fence
 *
 * @brief
 * Memory fence which is elided in non-SMP mode, but always carries the
 * corresponding compiler barrier.
 *
 * @param m
 * The ordering for this fence.
 */
#define os_atomic_thread_fence(m)  ({ \
	os_atomic_std(atomic_thread_fence)(_os_atomic_mo_##m##_smp); \
	os_atomic_std(atomic_signal_fence)(_os_atomic_mo_##m); \
})

/*!
 * @function os_atomic_init
 *
 * @brief
 * Wrapper for C11 atomic_init()
 *
 * @discussion
 * This initialization is not performed atomically, and so must only be used as
 * part of object initialization before the object is made visible to other
 * threads/cores.
 *
 * @param p
 * A pointer to an atomic variable.
 *
 * @param v
 * The value to initialize the variable with.
 *
 * @returns
 * The value loaded from @a p.
 */
#define os_atomic_init(p, v) \
	os_atomic_std(atomic_init)(os_cast_to_atomic_pointer(p), v)

/*!
 * @function os_atomic_load_is_plain, os_atomic_store_is_plain
 *
 * @brief
 * Return whether a relaxed atomic load (resp. store) to an atomic variable
 * is implemented as a single plain load (resp. store) instruction.
 *
 * @discussion
 * Non-relaxed loads/stores may involve additional memory fence instructions
 * or more complex atomic instructions.
 *
 * This is a construct that can safely be used in static asserts.
 *
 * This doesn't check for alignment and it is assumed that `p` is
 * "aligned enough".
 *
 * @param p
 * A pointer to an atomic variable.
 *
 * @returns
 * True when relaxed atomic loads (resp. stores) compile to a plain load
 * (resp. store) instruction, false otherwise.
 */
#define os_atomic_load_is_plain(p)  (sizeof(*(p)) <= sizeof(void *))
#define os_atomic_store_is_plain(p) os_atomic_load_is_plain(p)

/*!
 * @function os_atomic_load
 *
 * @brief
 * Wrapper for C11 atomic_load_explicit(), guaranteed to compile to a single
 * plain load instruction (when @a m is `relaxed`).
 *
 * @param p
 * A pointer to an atomic variable.
 *
 * @param m
 * The ordering to use.
 *
 * @returns
 * The value loaded from @a p.
 */
#define os_atomic_load(p, m)  ({ \
	_Static_assert(os_atomic_load_is_plain(p), "Load is wide"); \
	_os_compiler_barrier_before_atomic(m); \
	__auto_type _r = os_atomic_std(atomic_load_explicit)( \
	    os_cast_to_atomic_pointer(p), _os_atomic_mo_##m##_smp); \
	_os_compiler_barrier_after_atomic(m); \
	_r; \
})

/*!
 * @function os_atomic_store
 *
 * @brief
 * Wrapper for C11 atomic_store_explicit(), guaranteed to compile to a single
 * plain store instruction (when @a m is `relaxed`).
 *
 * @param p
 * A pointer to an atomic variable.
 *
 * @param v
 * The value to store.
 *
 * @param m
 * The ordering to use.
 *
 * @returns
 * The value stored at @a p.
 */
#define os_atomic_store(p, v, m)  ({ \
	_Static_assert(os_atomic_store_is_plain(p), "Store is wide"); \
	__auto_type _v = (v); \
	_os_compiler_barrier_before_atomic(m); \
	os_atomic_std(atomic_store_explicit)(os_cast_to_atomic_pointer(p), _v, \
	    _os_atomic_mo_##m##_smp); \
	_os_compiler_barrier_after_atomic(m); \
	_v; \
})

#if OS_ATOMIC_HAS_STARVATION_FREE_RMW || !OS_ATOMIC_CONFIG_STARVATION_FREE_ONLY

/*!
 * @function os_atomic_load_wide
 *
 * @brief
 * Wrapper for C11 atomic_load_explicit(), which may be implemented by a
 * compare-exchange loop for double-wide variables.
 *
 * @param p
 * A pointer to an atomic variable.
 *
 * @param m
 * The ordering to use.
 *
 * @returns
 * The value loaded from @a p.
 */
#define os_atomic_load_wide(p, m)  ({ \
	_os_compiler_barrier_before_atomic(m); \
	__auto_type _r = os_atomic_std(atomic_load_explicit)( \
	    os_cast_to_atomic_pointer(p), _os_atomic_mo_##m##_smp); \
	_os_compiler_barrier_after_atomic(m); \
	_r; \
})

/*!
 * @function os_atomic_store_wide
 *
 * @brief
 * Wrapper for C11 atomic_store_explicit(), which may be implemented by a
 * compare-exchange loop for double-wide variables.
 *
 * @param p
 * A pointer to an atomic variable.
 *
 * @param v
 * The value to store.
 *
 * @param m
 * The ordering to use.
 *
 * @returns
 * The value stored at @a p.
 */
#define os_atomic_store_wide(p, v, m)  ({ \
	__auto_type _v = (v); \
	_os_compiler_barrier_before_atomic(m); \
	os_atomic_std(atomic_store_explicit)(os_cast_to_atomic_pointer(p), _v, \
	    _os_atomic_mo_##m##_smp); \
	_os_compiler_barrier_after_atomic(m); \
	_v; \
})

/*!
 * @function os_atomic_add, os_atomic_add_orig
 *
 * @brief
 * Wrappers for C11 atomic_fetch_add_explicit().
 *
 * @param p
 * A pointer to an atomic variable.
 *
 * @param v
 * The value to add.
 *
 * @param m
 * The ordering to use.
 *
 * @returns
 * os_atomic_add_orig returns the value of the variable before the atomic add,
 * os_atomic_add returns the value of the variable after the atomic add.
 */
#define os_atomic_add_orig(p, v, m) _os_atomic_c11_op_orig(p, v, m, fetch_add)
#define os_atomic_add(p, v, m)      _os_atomic_c11_op(p, v, m, fetch_add, +)

/*!
 * @function os_atomic_inc, os_atomic_inc_orig
 *
 * @brief
 * Perform an atomic increment.
 *
 * @param p
 * A pointer to an atomic variable.
 *
 * @param m
 * The ordering to use.
 *
 * @returns
 * os_atomic_inc_orig returns the value of the variable before the atomic increment,
 * os_atomic_inc returns the value of the variable after the atomic increment.
 */
#define os_atomic_inc_orig(p, m)    _os_atomic_c11_op_orig(p, 1, m, fetch_add)
#define os_atomic_inc(p, m)         _os_atomic_c11_op(p, 1, m, fetch_add, +)

/*!
 * @function os_atomic_sub, os_atomic_sub_orig
 *
 * @brief
 * Wrappers for C11 atomic_fetch_sub_explicit().
 *
 * @param p
 * A pointer to an atomic variable.
 *
 * @param v
 * The value to subtract.
 *
 * @param m
 * The ordering to use.
 *
 * @returns
 * os_atomic_sub_orig returns the value of the variable before the atomic subtract,
 * os_atomic_sub returns the value of the variable after the atomic subtract.
 */
#define os_atomic_sub_orig(p, v, m) _os_atomic_c11_op_orig(p, v, m, fetch_sub)
#define os_atomic_sub(p, v, m)      _os_atomic_c11_op(p, v, m, fetch_sub, -)

/*!
 * @function os_atomic_dec, os_atomic_dec_orig
 *
 * @brief
 * Perform an atomic decrement.
 *
 * @param p
 * A pointer to an atomic variable.
 *
 * @param m
 * The ordering to use.
 *
 * @returns
 * os_atomic_dec_orig returns the value of the variable before the atomic decrement,
 * os_atomic_dec returns the value of the variable after the atomic decrement.
 */
#define os_atomic_dec_orig(p, m)    _os_atomic_c11_op_orig(p, 1, m, fetch_sub)
#define os_atomic_dec(p, m)         _os_atomic_c11_op(p, 1, m, fetch_sub, -)

/*!
 * @function os_atomic_and, os_atomic_and_orig
 *
 * @brief
 * Wrappers for C11 atomic_fetch_and_explicit().
 *
 * @param p
 * A pointer to an atomic variable.
 *
 * @param v
 * The value to and.
 *
 * @param m
 * The ordering to use.
 *
 * @returns
 * os_atomic_and_orig returns the value of the variable before the atomic and,
 * os_atomic_and returns the value of the variable after the atomic and.
 */
#define os_atomic_and_orig(p, v, m) _os_atomic_c11_op_orig(p, v, m, fetch_and)
#define os_atomic_and(p, v, m)      _os_atomic_c11_op(p, v, m, fetch_and, &)

/*!
 * @function os_atomic_andnot, os_atomic_andnot_orig
 *
 * @brief
 * Wrappers for C11 atomic_fetch_and_explicit(p, ~value).
 *
 * @param p
 * A pointer to an atomic variable.
 *
 * @param v
 * The value whose complement to and.
 *
 * @param m
 * The ordering to use.
 *
 * @returns
 * os_atomic_andnot_orig returns the value of the variable before the atomic andnot,
 * os_atomic_andnot returns the value of the variable after the atomic andnot.
 */
#define os_atomic_andnot_orig(p, v, m) _os_atomic_c11_op_orig(p, (typeof(v))~(v), m, fetch_and)
#define os_atomic_andnot(p, v, m)      _os_atomic_c11_op(p, (typeof(v))~(v), m, fetch_and, &)

/*!
 * @function os_atomic_or, os_atomic_or_orig
 *
 * @brief
 * Wrappers for C11 atomic_fetch_or_explicit().
 *
 * @param p
 * A pointer to an atomic variable.
 *
 * @param v
 * The value to or.
 *
 * @param m
 * The ordering to use.
 *
 * @returns
 * os_atomic_or_orig returns the value of the variable before the atomic or,
 * os_atomic_or returns the value of the variable after the atomic or.
 */
#define os_atomic_or_orig(p, v, m)  _os_atomic_c11_op_orig(p, v, m, fetch_or)
#define os_atomic_or(p, v, m)       _os_atomic_c11_op(p, v, m, fetch_or, |)

/*!
 * @function os_atomic_xor, os_atomic_xor_orig
 *
 * @brief
 * Wrappers for C11 atomic_fetch_xor_explicit().
 *
 * @param p
 * A pointer to an atomic variable.
 *
 * @param v
 * The value to xor.
 *
 * @param m
 * The ordering to use.
 *
 * @returns
 * os_atomic_xor_orig returns the value of the variable before the atomic xor,
 * os_atomic_xor returns the value of the variable after the atomic xor.
 */
#define os_atomic_xor_orig(p, v, m) _os_atomic_c11_op_orig(p, v, m, fetch_xor)
#define os_atomic_xor(p, v, m)      _os_atomic_c11_op(p, v, m, fetch_xor, ^)

/*!
 * @function os_atomic_min, os_atomic_min_orig
 *
 * @brief
 * Wrappers for Clang's __atomic_fetch_min()
 *
 * @param p
 * A pointer to an atomic variable.
 *
 * @param v
 * The value to minimize.
 *
 * @param m
 * The ordering to use.
 *
 * @returns
 * os_atomic_min_orig returns the value of the variable before the atomic min,
 * os_atomic_min returns the value of the variable after the atomic min.
 */
#define os_atomic_min_orig(p, v, m) _os_atomic_clang_op_orig(p, v, m, fetch_min)
#define os_atomic_min(p, v, m)      _os_atomic_clang_op(p, v, m, fetch_min, MIN)

/*!
 * @function os_atomic_max, os_atomic_max_orig
 *
 * @brief
 * Wrappers for Clang's __atomic_fetch_max()
 *
 * @param p
 * A pointer to an atomic variable.
 *
 * @param v
 * The value to maximize.
 *
 * @param m
 * The ordering to use.
 *
 * @returns
 * os_atomic_max_orig returns the value of the variable before the atomic max,
 * os_atomic_max returns the value of the variable after the atomic max.
 */
#define os_atomic_max_orig(p, v, m) _os_atomic_clang_op_orig(p, v, m, fetch_max)
#define os_atomic_max(p, v, m)      _os_atomic_clang_op(p, v, m, fetch_max, MAX)

/*!
 * @function os_atomic_xchg
 *
 * @brief
 * Wrapper for C11 atomic_exchange_explicit().
 *
 * @param p
 * A pointer to an atomic variable.
 *
 * @param v
 * The value to exchange with.
 *
 * @param m
 * The ordering to use.
 *
 * @returns
 * The value of the variable before the exchange.
 */
#define os_atomic_xchg(p, v, m)     _os_atomic_c11_op_orig(p, v, m, exchange)

/*!
 * @function os_atomic_cmpxchg
 *
 * @brief
 * Wrapper for C11 atomic_compare_exchange_strong_explicit().
 *
 * @discussion
 * Loops around os_atomic_cmpxchg() may want to consider using the
 * os_atomic_rmw_loop() construct instead to take advantage of the C11 weak
 * compare-exchange operation.
 *
 * @param p
 * A pointer to an atomic variable.
 *
 * @param e
 * The value expected in the atomic variable.
 *
 * @param v
 * The value to store if the atomic variable has the expected value @a e.
 *
 * @param m
 * The ordering to use in case of success.
 * The ordering in case of failure is always `relaxed`.
 *
 * @returns
 * 0 if the compare-exchange failed.
 * 1 if the compare-exchange succeeded.
 */
#define os_atomic_cmpxchg(p, e, v, m)  ({ \
	os_atomic_basetypeof(p) _r = (e); int _b; \
	_os_compiler_barrier_before_atomic(m); \
	_b = os_atomic_std(atomic_compare_exchange_strong_explicit)( \
	    os_cast_to_atomic_pointer(p), &_r, \
	    _os_atomic_value_cast(p, v), \
	    _os_atomic_mo_##m##_smp, _os_atomic_mo_relaxed); \
	_os_compiler_barrier_after_atomic(m); \
	_b; \
})

/*!
 * @function os_atomic_cmpxchgv
 *
 * @brief
 * Wrapper for C11 atomic_compare_exchange_strong_explicit().
 *
 * @discussion
 * Loops around os_atomic_cmpxchgv() may want to consider using the
 * os_atomic_rmw_loop() construct instead to take advantage of the C11 weak
 * compare-exchange operation.
 *
 * @param p
 * A pointer to an atomic variable.
 *
 * @param e
 * The value expected in the atomic variable.
 *
 * @param v
 * The value to store if the atomic variable has the expected value @a e.
 *
 * @param g
 * A pointer to a location that is filled with the value that was present in
 * the atomic variable before the compare-exchange (whether successful or not).
 * This can be used to redrive compare-exchange loops.
 *
 * @param m
 * The ordering to use in case of success.
 * The ordering in case of failure is always `relaxed`.
 *
 * @returns
 * 0 if the compare-exchange failed.
 * 1 if the compare-exchange succeeded.
 */
#define os_atomic_cmpxchgv(p, e, v, g, m)  ({ \
	os_atomic_basetypeof(p) _r = (e); int _b; \
	_os_compiler_barrier_before_atomic(m); \
	_b = os_atomic_std(atomic_compare_exchange_strong_explicit)( \
	    os_cast_to_atomic_pointer(p), &_r, \
	    _os_atomic_value_cast(p, v), \
	    _os_atomic_mo_##m##_smp, _os_atomic_mo_relaxed); \
	_os_compiler_barrier_after_atomic(m); \
	*(g) = _r; _b; \
})

/*!
 * @function os_atomic_rmw_loop
 *
 * @brief
 * Advanced read-modify-write construct to wrap compare-exchange loops.
 *
 * @param p
 * A pointer to an atomic variable to be modified.
 *
 * @param ov
 * The name of the variable that will contain the original value of the atomic
 * variable (reloaded every iteration of the loop).
 *
 * @param nv
 * The name of the variable that will contain the new value to compare-exchange
 * the atomic variable to (typically computed from @a ov every iteration of the
 * loop).
 *
 * @param m
 * The ordering to use in case of success.
 * The ordering in case of failure is always `relaxed`.
 *
 * @param ...
 * Code block that validates the value of @p ov and computes the new value of
 * @p nv that the atomic variable will be compare-exchanged to in an iteration
 * of the loop.
 *
 * The loop can be aborted using os_atomic_rmw_loop_give_up(), e.g. when the
 * value of @p ov is found to be "invalid" for the ovarall operation.
 * `continue` cannot be used in this context.
 *
 * No stores to memory should be performed within the code block as it may cause
 * LL/SC transactions used to implement compare-exchange to fail persistently.
 *
 * @returns
 * 0 if the loop was aborted with os_atomic_rmw_loop_give_up().
 * 1 if the loop completed.
 */
#define os_atomic_rmw_loop(p, ov, nv, m, ...)  ({ \
	int _result = 0; \
	__auto_type _p = os_cast_to_nonatomic_pointer(p); \
	_os_compiler_barrier_before_atomic(m); \
	ov = *_p; \
	do { \
	    __VA_ARGS__; \
	    _result = os_atomic_std(atomic_compare_exchange_weak_explicit)( \
	        os_cast_to_atomic_pointer(_p), &ov, nv, \
	        _os_atomic_mo_##m##_smp, _os_atomic_mo_relaxed); \
	} while (__builtin_expect(!_result, 0)); \
	_os_compiler_barrier_after_atomic(m); \
	_result; \
})

/*!
 * @function os_atomic_rmw_loop_give_up
 *
 * @brief
 * Abort an os_atomic_rmw_loop() loop.
 *
 * @param ...
 * Optional code block to execute before the `break` out of the loop. May
 * further alter the control flow (e.g. using `return`, `goto`, ...).
 */
#define os_atomic_rmw_loop_give_up(...) ({ __VA_ARGS__; break; })

#else // !OS_ATOMIC_HAS_STARVATION_FREE_RMW && OS_ATOMIC_CONFIG_STARVATION_FREE_ONLY

#define _os_atomic_error_is_starvable(name) \
	_Static_assert(0, #name " is not starvation-free and isn't available in this configuration")
#define os_atomic_load_wide(p, m)               _os_atomic_error_is_starvable(os_atomic_load_wide)
#define os_atomic_store_wide(p, v, m)           _os_atomic_error_is_starvable(os_atomic_store_wide)
#define os_atomic_add_orig(p, v, m)             _os_atomic_error_is_starvable(os_atomic_add_orig)
#define os_atomic_add(p, v, m)                  _os_atomic_error_is_starvable(os_atomic_add)
#define os_atomic_inc_orig(p, m)                _os_atomic_error_is_starvable(os_atomic_inc_orig)
#define os_atomic_inc(p, m)                     _os_atomic_error_is_starvable(os_atomic_inc)
#define os_atomic_sub_orig(p, v, m)             _os_atomic_error_is_starvable(os_atomic_sub_orig)
#define os_atomic_sub(p, v, m)                  _os_atomic_error_is_starvable(os_atomic_sub)
#define os_atomic_dec_orig(p, m)                _os_atomic_error_is_starvable(os_atomic_dec_orig)
#define os_atomic_dec(p, m)                     _os_atomic_error_is_starvable(os_atomic_dec)
#define os_atomic_and_orig(p, v, m)             _os_atomic_error_is_starvable(os_atomic_and_orig)
#define os_atomic_and(p, v, m)                  _os_atomic_error_is_starvable(os_atomic_and)
#define os_atomic_andnot_orig(p, v, m)          _os_atomic_error_is_starvable(os_atomic_andnot_orig)
#define os_atomic_andnot(p, v, m)               _os_atomic_error_is_starvable(os_atomic_andnot)
#define os_atomic_or_orig(p, v, m)              _os_atomic_error_is_starvable(os_atomic_or_orig)
#define os_atomic_or(p, v, m)                   _os_atomic_error_is_starvable(os_atomic_or)
#define os_atomic_xor_orig(p, v, m)             _os_atomic_error_is_starvable(os_atomic_xor_orig)
#define os_atomic_xor(p, v, m)                  _os_atomic_error_is_starvable(os_atomic_xor)
#define os_atomic_min_orig(p, v, m)             _os_atomic_error_is_starvable(os_atomic_min_orig)
#define os_atomic_min(p, v, m)                  _os_atomic_error_is_starvable(os_atomic_min)
#define os_atomic_max_orig(p, v, m)             _os_atomic_error_is_starvable(os_atomic_max_orig)
#define os_atomic_max(p, v, m)                  _os_atomic_error_is_starvable(os_atomic_max)
#define os_atomic_xchg(p, v, m)                 _os_atomic_error_is_starvable(os_atomic_xchg)
#define os_atomic_cmpxchg(p, e, v, m)           _os_atomic_error_is_starvable(os_atomic_cmpxchg)
#define os_atomic_cmpxchgv(p, e, v, g, m)       _os_atomic_error_is_starvable(os_atomic_cmpxchgv)
#define os_atomic_rmw_loop(p, ov, nv, m, ...)   _os_atomic_error_is_starvable(os_atomic_rmw_loop)
#define os_atomic_rmw_loop_give_up(...)         _os_atomic_error_is_starvable(os_atomic_rmw_loop_give_up)

#endif // !OS_ATOMIC_HAS_STARVATION_FREE_RMW && OS_ATOMIC_CONFIG_STARVATION_FREE_ONLY

#if OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY

/*!
 * @typedef os_atomic_dependency_t
 *
 * @brief
 * Type for dependency tokens that can be derived from loads with dependency
 * and injected into various expressions.
 *
 * @warning
 * The implementation of atomic dependencies makes painstakingly sure that the
 * compiler doesn't know that os_atomic_dependency_t::__opaque_zero is always 0.
 *
 * Users of os_atomic_dependency_t MUST NOT test its value (even with an
 * assert), as doing so would allow the compiler to reason about the value and
 * elide its use to inject hardware dependencies (thwarting the entire purpose
 * of the construct).
 */
typedef struct { unsigned long __opaque_zero; } os_atomic_dependency_t;

/*!
 * @const OS_ATOMIC_DEPENDENCY_NONE
 *
 * @brief
 * A value to pass to functions that can carry dependencies, to indicate that
 * no dependency should be carried.
 */
#define OS_ATOMIC_DEPENDENCY_NONE \
	((os_atomic_dependency_t){ 0UL })

/*!
 * @function os_atomic_make_dependency
 *
 * @brief
 * Create a dependency token that can be injected into expressions to force a
 * hardware dependency.
 *
 * @discussion
 * This function is only useful for cases where the dependency needs to be used
 * several times.
 *
 * os_atomic_load_with_dependency_on() and os_atomic_inject_dependency() are
 * otherwise capable of automatically creating dependency tokens.
 *
 * @param v
 * The result of:
 * - an os_atomic_load(..., dependency),
 * - an os_atomic_inject_dependency(),
 * - an os_atomic_load_with_dependency_on().
 *
 * Note that due to implementation limitations, the type of @p v must be
 * register-sized, if necessary an explicit cast is required.
 *
 * @returns
 * An os_atomic_dependency_t token that can be used to prolongate dependency
 * chains.
 *
 * The token value is always 0, but the compiler must never be able to reason
 * about that fact (c.f. os_atomic_dependency_t)
 */
#define os_atomic_make_dependency(v) \
	((void)(v), OS_ATOMIC_DEPENDENCY_NONE)

/*!
 * @function os_atomic_inject_dependency
 *
 * @brief
 * Inject a hardware dependency resulting from a `dependency` load into a
 * specified pointer.
 *
 * @param p
 * A pointer to inject the dependency into.
 *
 * @param e
 * - a dependency token returned from os_atomic_make_dependency(),
 *
 * - OS_ATOMIC_DEPENDENCY_NONE, which turns this operation into a no-op,
 *
 * - any value accepted by os_atomic_make_dependency().
 *
 * @returns
 * A value equal to @a p but that prolongates the dependency chain rooted at
 * @a e.
 */
#define os_atomic_inject_dependency(p, e) \
	((typeof(*(p)) *)((p) + _os_atomic_auto_dependency(e).__opaque_zero))

/*!
 * @function os_atomic_load_with_dependency_on
 *
 * @brief
 * Load that prolongates the dependency chain rooted at `v`.
 *
 * @discussion
 * This is shorthand for:
 *
 * <code>
 *   os_atomic_load(os_atomic_inject_dependency(p, e), dependency)
 * </code>
 *
 * @param p
 * A pointer to an atomic variable.
 *
 * @param e
 * - a dependency token returned from os_atomic_make_dependency(),
 *
 * - OS_ATOMIC_DEPENDENCY_NONE, which turns this operation into a no-op,
 *
 * - any value accepted by os_atomic_make_dependency().
 *
 * @returns
 * The value loaded from @a p.
 */
#define os_atomic_load_with_dependency_on(p, e) \
	os_atomic_load(os_atomic_inject_dependency(p, e), dependency)

#endif // OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY

#include "atomic_private_arch.h" // Per architecture overrides

#endif /* __OS_ATOMIC_PRIVATE_H__ */

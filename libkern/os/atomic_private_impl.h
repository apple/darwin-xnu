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

/*
 * This header provides some gory details to implement the <os/atomic_private.h>
 * interfaces. Nothing in this header should be called directly, no promise is
 * made to keep this interface stable.
 */

#ifndef __OS_ATOMIC_PRIVATE_H__
#error "Do not include <os/atomic_private_impl.h> directly, use <os/atomic_private.h>"
#endif

#ifndef __OS_ATOMIC_PRIVATE_IMPL_H__
#define __OS_ATOMIC_PRIVATE_IMPL_H__

#pragma mark - implementation details

static inline int
_os_atomic_mo_has_acquire(OS_ATOMIC_STD memory_order ord)
{
	switch (ord) {
	case os_atomic_std(memory_order_consume):
	case os_atomic_std(memory_order_acquire):
	case os_atomic_std(memory_order_acq_rel):
	case os_atomic_std(memory_order_seq_cst):
		return 1;
	default:
		return 0;
	}
}

static inline int
_os_atomic_mo_has_release(OS_ATOMIC_STD memory_order ord)
{
	switch (ord) {
	case os_atomic_std(memory_order_release):
	case os_atomic_std(memory_order_acq_rel):
	case os_atomic_std(memory_order_seq_cst):
		return 1;
	default:
		return 0;
	}
}

#define _os_atomic_mo_relaxed               os_atomic_std(memory_order_relaxed)
#define _os_atomic_mo_compiler_acquire      os_atomic_std(memory_order_relaxed)
#define _os_atomic_mo_compiler_release      os_atomic_std(memory_order_relaxed)
#define _os_atomic_mo_compiler_acq_rel      os_atomic_std(memory_order_relaxed)
#define _os_atomic_mo_consume               os_atomic_std(memory_order_consume)
#if OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY
#define _os_atomic_mo_dependency            os_atomic_std(memory_order_acquire)
#endif // OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY
#define _os_atomic_mo_acquire               os_atomic_std(memory_order_acquire)
#define _os_atomic_mo_release               os_atomic_std(memory_order_release)
#define _os_atomic_mo_acq_rel               os_atomic_std(memory_order_acq_rel)
#define _os_atomic_mo_seq_cst               os_atomic_std(memory_order_seq_cst)

/*
 * Mapping between symbolic memory orderings and actual ones
 * to take SMP into account.
 */
#if OS_ATOMIC_CONFIG_SMP
#define _os_atomic_mo_relaxed_smp           _os_atomic_mo_relaxed
#define _os_atomic_mo_compiler_acquire_smp  _os_atomic_mo_relaxed
#define _os_atomic_mo_compiler_release_smp  _os_atomic_mo_relaxed
#define _os_atomic_mo_compiler_acq_rel_smp  _os_atomic_mo_relaxed
#define _os_atomic_mo_consume_smp           _os_atomic_mo_consume
#if OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY
#define _os_atomic_mo_dependency_smp        _os_atomic_mo_dependency
#endif // OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY
#define _os_atomic_mo_acquire_smp           _os_atomic_mo_acquire
#define _os_atomic_mo_release_smp           _os_atomic_mo_release
#define _os_atomic_mo_acq_rel_smp           _os_atomic_mo_acq_rel
#define _os_atomic_mo_seq_cst_smp           _os_atomic_mo_seq_cst
#else
#define _os_atomic_mo_relaxed_smp           _os_atomic_mo_relaxed
#define _os_atomic_mo_compiler_acquire_smp  _os_atomic_mo_relaxed
#define _os_atomic_mo_compiler_release_smp  _os_atomic_mo_relaxed
#define _os_atomic_mo_compiler_acq_rel_smp  _os_atomic_mo_relaxed
#define _os_atomic_mo_consume_smp           _os_atomic_mo_relaxed
#if OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY
#define _os_atomic_mo_dependency_smp        _os_atomic_mo_relaxed
#endif // OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY
#define _os_atomic_mo_acquire_smp           _os_atomic_mo_relaxed
#define _os_atomic_mo_release_smp           _os_atomic_mo_relaxed
#define _os_atomic_mo_acq_rel_smp           _os_atomic_mo_relaxed
#define _os_atomic_mo_seq_cst_smp           _os_atomic_mo_relaxed
#endif

#if KERNEL_PRIVATE
#define memory_order_relaxed_smp            _os_atomic_mo_relaxed_smp
#define memory_order_compiler_acquire_smp   _os_atomic_mo_compiler_acquire_smp
#define memory_order_compiler_release_smp   _os_atomic_mo_compiler_release_smp
#define memory_order_compiler_acq_rel_smp   _os_atomic_mo_compiler_acq_rel_smp
#define memory_order_consume_smp            _os_atomic_mo_consume_smp
#if OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY
#define memory_order_dependency             _os_atomic_mo_dependency
#define memory_order_dependency_smp         _os_atomic_mo_dependency_smp
#endif // OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY
#define memory_order_acquire_smp            _os_atomic_mo_acquire_smp
#define memory_order_release_smp            _os_atomic_mo_release_smp
#define memory_order_acq_rel_smp            _os_atomic_mo_acq_rel_smp
#define memory_order_seq_cst_smp            _os_atomic_mo_seq_cst_smp
#endif

/*
 * Hack needed for os_compiler_barrier() to work (including with empty argument)
 */
#define _os_compiler_barrier_relaxed        _os_atomic_mo_relaxed
#define _os_compiler_barrier_acquire        _os_atomic_mo_acquire
#define _os_compiler_barrier_release        _os_atomic_mo_release
#define _os_compiler_barrier_acq_rel        _os_atomic_mo_acq_rel
#define _os_compiler_barrier_               _os_atomic_mo_acq_rel

/*
 * Mapping between compiler barrier/memory orders and:
 * - compiler barriers before atomics ("rel_barrier")
 * - compiler barriers after atomics ("acq_barrier")
 */
#define _os_rel_barrier_relaxed             _os_atomic_mo_relaxed
#define _os_rel_barrier_compiler_acquire    _os_atomic_mo_relaxed
#define _os_rel_barrier_compiler_release    _os_atomic_mo_release
#define _os_rel_barrier_compiler_acq_rel    _os_atomic_mo_release
#define _os_rel_barrier_consume             _os_atomic_mo_relaxed
#if OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY
#define _os_rel_barrier_dependency          _os_atomic_mo_relaxed
#endif // OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY
#define _os_rel_barrier_acquire             _os_atomic_mo_relaxed
#define _os_rel_barrier_release             _os_atomic_mo_release
#define _os_rel_barrier_acq_rel             _os_atomic_mo_release
#define _os_rel_barrier_seq_cst             _os_atomic_mo_release

#define _os_acq_barrier_relaxed             _os_atomic_mo_relaxed
#define _os_acq_barrier_compiler_acquire    _os_atomic_mo_acquire
#define _os_acq_barrier_compiler_release    _os_atomic_mo_relaxed
#define _os_acq_barrier_compiler_acq_rel    _os_atomic_mo_acquire
#define _os_acq_barrier_consume             _os_atomic_mo_acquire
#if OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY
#define _os_acq_barrier_dependency          _os_atomic_mo_acquire
#endif // OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY
#define _os_acq_barrier_acquire             _os_atomic_mo_acquire
#define _os_acq_barrier_release             _os_atomic_mo_relaxed
#define _os_acq_barrier_acq_rel             _os_atomic_mo_acquire
#define _os_acq_barrier_seq_cst             _os_atomic_mo_acquire

#define _os_compiler_barrier_before_atomic(m) \
	os_atomic_std(atomic_signal_fence)(_os_rel_barrier_##m)
#define _os_compiler_barrier_after_atomic(m) \
	os_atomic_std(atomic_signal_fence)(_os_acq_barrier_##m)

/*
 * Mapping between compiler barrier/memmory orders and:
 * - memory fences before atomics ("rel_fence")
 * - memory fences after atomics ("acq_fence")
 */
#define _os_rel_fence_relaxed               _os_atomic_mo_relaxed
#define _os_rel_fence_compiler_acquire      _os_atomic_mo_relaxed
#define _os_rel_fence_compiler_release      _os_atomic_mo_release
#define _os_rel_fence_compiler_acq_rel      _os_atomic_mo_release
#define _os_rel_fence_consume               _os_atomic_mo_relaxed_smp
#if OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY
#define _os_rel_fence_dependency            _os_atomic_mo_relaxed_smp
#endif // OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY
#define _os_rel_fence_acquire               _os_atomic_mo_relaxed_smp
#define _os_rel_fence_release               _os_atomic_mo_release_smp
#define _os_rel_fence_acq_rel               _os_atomic_mo_release_smp
#define _os_rel_fence_seq_cst               _os_atomic_mo_release_smp

#define _os_acq_fence_relaxed               _os_atomic_mo_relaxed
#define _os_acq_fence_compiler_acquire      _os_atomic_mo_relaxed
#define _os_acq_fence_compiler_release      _os_atomic_mo_relaxed
#define _os_acq_fence_compiler_acq_rel      _os_atomic_mo_relaxed
#define _os_acq_fence_consume               _os_atomic_mo_acquire_smp
#if OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY
#define _os_acq_fence_dependency            _os_atomic_mo_dependency_smp
#endif // OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY
#define _os_acq_fence_acquire               _os_atomic_mo_acquire_smp
#define _os_acq_fence_release               _os_atomic_mo_relaxed_smp
#define _os_acq_fence_acq_rel               _os_atomic_mo_acquire_smp
#define _os_acq_fence_seq_cst               _os_atomic_mo_acquire_smp

#define _os_memory_fence_before_atomic(m) \
	os_atomic_std(atomic_thread_fence)(_os_rel_fence_##m)
#define _os_memory_fence_after_atomic(m) \
	os_atomic_std(atomic_thread_fence)(_os_acq_fence_##m)

/*
 * Misc. helpers
 */

#define _os_atomic_value_cast(p, v) \
	({ typeof(*os_cast_to_nonatomic_pointer(p)) ___v = (v); ___v; })

#define _os_atomic_c11_op_orig(p, v, m, o)  ({ \
	_os_compiler_barrier_before_atomic(m); \
	__auto_type _r = os_atomic_std(atomic_##o##_explicit)(\
	    os_cast_to_atomic_pointer(p), \
	    _os_atomic_value_cast(p, v), \
	    _os_atomic_mo_##m##_smp); \
	_os_compiler_barrier_after_atomic(m); \
	_r; \
})

#define _os_atomic_c11_op(p, v, m, o, op) ({ \
	__auto_type _v = _os_atomic_value_cast(p, v); \
	_os_atomic_c11_op_orig(p, _v, m, o) op _v; \
})

#define _os_atomic_clang_op_orig(p, v, m, o)  ({ \
	_os_compiler_barrier_before_atomic(m); \
	__auto_type _r = __atomic_##o(os_cast_to_nonatomic_pointer(p), \
	    _os_atomic_value_cast(p, v), \
	    _os_atomic_mo_##m##_smp); \
	_os_compiler_barrier_after_atomic(m); \
	_r; \
})

#define _os_atomic_clang_op(p, v, m, o, op) ({ \
	__auto_type _v = _os_atomic_value_cast(p, v); \
	__auto_type _r = _os_atomic_clang_op_orig(p, _v, m, o); \
	op(_r, _v); \
})

#if OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY
#define _os_atomic_auto_dependency(e) \
	_Generic(e, \
	    os_atomic_dependency_t: (e), \
	    default: os_atomic_make_dependency(e))
#endif // OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY

#endif /* __OS_ATOMIC_PRIVATE_IMPL_H__ */

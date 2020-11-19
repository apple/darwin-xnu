/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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
 *
 * Architecture overrides.
 */

#ifndef __OS_ATOMIC_PRIVATE_H__
#error "Do not include <os/atomic_private_arch.h> directly, use <os/atomic_private.h>"
#endif

#ifndef __OS_ATOMIC_PRIVATE_ARCH_H__
#define __OS_ATOMIC_PRIVATE_ARCH_H__

#pragma mark - arm v7

#if defined(__arm__)

#if OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY
/*
 * On armv7, we do provide fine grained dependency injection, so
 * memory_order_dependency maps to relaxed as far as thread fences are concerned
 */
#undef _os_atomic_mo_dependency
#define _os_atomic_mo_dependency      memory_order_relaxed

#undef os_atomic_make_dependency
#define os_atomic_make_dependency(v) ({ \
	os_atomic_dependency_t _dep; \
	__asm__ __volatile__("and %[_dep], %[_v], #0" \
	    : [_dep] "=r" (_dep.__opaque_zero) \
	    : [_v] "r" (v)); \
	os_compiler_barrier(acquire); \
	_dep; \
})
#endif // OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY

#define os_atomic_clear_exclusive()  __builtin_arm_clrex()

#define os_atomic_load_exclusive(p, m)  ({ \
	__auto_type _r = __builtin_arm_ldrex(os_cast_to_nonatomic_pointer(p)); \
	_os_memory_fence_after_atomic(m); \
	_os_compiler_barrier_after_atomic(m); \
	_r; \
})

#define os_atomic_store_exclusive(p, v, m)  ({ \
	_os_compiler_barrier_before_atomic(m); \
	_os_memory_fence_before_atomic(m); \
	!__builtin_arm_strex(v, os_cast_to_nonatomic_pointer(p)); \
})

#if !OS_ATOMIC_HAS_STARVATION_FREE_RMW && !OS_ATOMIC_CONFIG_STARVATION_FREE_ONLY

/*
 * armv7 override of os_atomic_rmw_loop
 * documentation for os_atomic_rmw_loop is in <os/atomic_private.h>
 */
#undef os_atomic_rmw_loop
#define os_atomic_rmw_loop(p, ov, nv, m, ...)  ({ \
	int _result = 0; uint32_t _err = 0; \
	__auto_type *_p = os_cast_to_nonatomic_pointer(p); \
	for (;;) { \
	        ov = __builtin_arm_ldrex(_p); \
	        __VA_ARGS__; \
	        if (!_err) { \
	/* release barrier only done for the first loop iteration */ \
	                _os_memory_fence_before_atomic(m); \
	        } \
	        _err = __builtin_arm_strex(nv, _p); \
	        if (__builtin_expect(!_err, 1)) { \
	                _os_memory_fence_after_atomic(m); \
	                _result = 1; \
	                break; \
	        } \
	} \
	_os_compiler_barrier_after_atomic(m); \
	_result; \
})

/*
 * armv7 override of os_atomic_rmw_loop_give_up
 * documentation for os_atomic_rmw_loop_give_up is in <os/atomic_private.h>
 */
#undef os_atomic_rmw_loop_give_up
#define os_atomic_rmw_loop_give_up(...) \
	({ os_atomic_clear_exclusive(); __VA_ARGS__; break; })

#endif // !OS_ATOMIC_HAS_STARVATION_FREE_RMW && !OS_ATOMIC_CONFIG_STARVATION_FREE_ONLY

#endif // __arm__

#pragma mark - arm64

#if defined(__arm64__)

#if OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY
/*
 * On arm64, we do provide fine grained dependency injection, so
 * memory_order_dependency maps to relaxed as far as thread fences are concerned
 */
#undef _os_atomic_mo_dependency
#define _os_atomic_mo_dependency      memory_order_relaxed

#undef os_atomic_make_dependency
#if __ARM64_ARCH_8_32__
#define os_atomic_make_dependency(v) ({ \
	os_atomic_dependency_t _dep; \
	__asm__ __volatile__("and %w[_dep], %w[_v], wzr" \
	    : [_dep] "=r" (_dep.__opaque_zero) \
	    : [_v] "r" (v)); \
	os_compiler_barrier(acquire); \
	_dep; \
})
#else
#define os_atomic_make_dependency(v) ({ \
	os_atomic_dependency_t _dep; \
	__asm__ __volatile__("and %[_dep], %[_v], xzr" \
	    : [_dep] "=r" (_dep.__opaque_zero) \
	    : [_v] "r" (v)); \
	os_compiler_barrier(acquire); \
	_dep; \
})
#endif
#endif // OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY

#if defined(__ARM_ARCH_8_4__)
/* on armv8.4 16-byte aligned load/store pair is atomic */
#undef os_atomic_load_is_plain
#define os_atomic_load_is_plain(p)   (sizeof(*(p)) <= 16)
#endif

#define os_atomic_clear_exclusive()  __builtin_arm_clrex()

#define os_atomic_load_exclusive(p, m)  ({ \
	__auto_type _r = _os_atomic_mo_has_acquire(_os_atomic_mo_##m##_smp) \
	    ? __builtin_arm_ldaex(os_cast_to_nonatomic_pointer(p)) \
	    : __builtin_arm_ldrex(os_cast_to_nonatomic_pointer(p)); \
	_os_compiler_barrier_after_atomic(m); \
	_r; \
})

#define os_atomic_store_exclusive(p, v, m)  ({ \
	_os_compiler_barrier_before_atomic(m); \
	(_os_atomic_mo_has_release(_os_atomic_mo_##m##_smp) \
	    ? !__builtin_arm_stlex(v, os_cast_to_nonatomic_pointer(p)) \
	        : !__builtin_arm_strex(v, os_cast_to_nonatomic_pointer(p))); \
})

#if !OS_ATOMIC_HAS_STARVATION_FREE_RMW && !OS_ATOMIC_CONFIG_STARVATION_FREE_ONLY

/*
 * arm64 (without armv81 atomics) override of os_atomic_rmw_loop
 * documentation for os_atomic_rmw_loop is in <os/atomic_private.h>
 */
#undef os_atomic_rmw_loop
#define os_atomic_rmw_loop(p, ov, nv, m, ...)  ({ \
	int _result = 0; \
	__auto_type *_p = os_cast_to_nonatomic_pointer(p); \
	_os_compiler_barrier_before_atomic(m); \
	do { \
	        if (_os_atomic_mo_has_acquire(_os_atomic_mo_##m##_smp)) { \
	                ov = __builtin_arm_ldaex(_p); \
	        } else { \
	                ov = __builtin_arm_ldrex(_p); \
	        } \
	        __VA_ARGS__; \
	        if (_os_atomic_mo_has_release(_os_atomic_mo_##m##_smp)) { \
	                _result = !__builtin_arm_stlex(nv, _p); \
	        } else { \
	                _result = !__builtin_arm_strex(nv, _p); \
	        } \
	} while (__builtin_expect(!_result, 0)); \
	_os_compiler_barrier_after_atomic(m); \
	_result; \
})

/*
 * arm64 override of os_atomic_rmw_loop_give_up
 * documentation for os_atomic_rmw_loop_give_up is in <os/atomic_private.h>
 */
#undef os_atomic_rmw_loop_give_up
#define os_atomic_rmw_loop_give_up(...) \
	({ os_atomic_clear_exclusive(); __VA_ARGS__; break; })

#endif // !OS_ATOMIC_HAS_STARVATION_FREE_RMW && !OS_ATOMIC_CONFIG_STARVATION_FREE_ONLY

#endif // __arm64__

#endif /* __OS_ATOMIC_PRIVATE_ARCH_H__ */

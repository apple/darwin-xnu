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

#ifndef _MACHINE_ATOMIC_H
#define _MACHINE_ATOMIC_H

#include <stdatomic.h>

#define _os_atomic_c11_atomic(p) \
	        ((typeof(*(p)) _Atomic *)(p))

#define _os_atomic_basetypeof(p) \
	        typeof(atomic_load(((typeof(*(p)) _Atomic *)(p))))

#define _os_atomic_c11_op_orig(p, v, m, o) \
	        atomic_##o##_explicit(_os_atomic_c11_atomic(p), v, \
	        memory_order_##m)

#define _os_atomic_c11_op(p, v, m, o, op) \
	        ({ typeof(v) _v = (v); _os_atomic_c11_op_orig(p, v, m, o) op _v; })

#define os_atomic_thread_fence(m)  atomic_thread_fence(memory_order_##m)

#define os_atomic_load(p, m) \
	        atomic_load_explicit(_os_atomic_c11_atomic(p), memory_order_##m)
#define os_atomic_store(p, v, m)    _os_atomic_c11_op_orig(p, v, m, store)

#define os_atomic_add_orig(p, v, m) _os_atomic_c11_op_orig(p, v, m, fetch_add)
#define os_atomic_add(p, v, m)      _os_atomic_c11_op(p, v, m, fetch_add, +)

#define os_atomic_inc_orig(p, m)    _os_atomic_c11_op_orig(p, 1, m, fetch_add)
#define os_atomic_inc(p, m)         _os_atomic_c11_op(p, 1, m, fetch_add, +)

#define os_atomic_sub_orig(p, v, m) _os_atomic_c11_op_orig(p, v, m, fetch_sub)
#define os_atomic_sub(p, v, m)      _os_atomic_c11_op(p, v, m, fetch_sub, -)

#define os_atomic_dec_orig(p, m)    _os_atomic_c11_op_orig(p, 1, m, fetch_sub)
#define os_atomic_dec(p, m)         _os_atomic_c11_op(p, 1, m, fetch_sub, -)

#define os_atomic_and_orig(p, v, m) _os_atomic_c11_op_orig(p, v, m, fetch_and)
#define os_atomic_and(p, v, m)      _os_atomic_c11_op(p, v, m, fetch_and, &)

#define os_atomic_or_orig(p, v, m)  _os_atomic_c11_op_orig(p, v, m, fetch_or)
#define os_atomic_or(p, v, m)       _os_atomic_c11_op(p, v, m, fetch_or, |)

#define os_atomic_xor_orig(p, v, m) _os_atomic_c11_op_orig(p, v, m, fetch_xor)
#define os_atomic_xor(p, v, m)      _os_atomic_c11_op(p, v, m, fetch_xor, ^)

#define os_atomic_xchg(p, v, m)     _os_atomic_c11_op_orig(p, v, m, exchange)

#define os_atomic_cmpxchg(p, e, v, m) \
	        ({ _os_atomic_basetypeof(p) _r = (e); \
	        atomic_compare_exchange_strong_explicit(_os_atomic_c11_atomic(p), \
	        &_r, v, memory_order_##m, memory_order_relaxed); })
#define os_atomic_cmpxchgv(p, e, v, g, m) \
	        ({ _os_atomic_basetypeof(p) _r = (e); int _b = \
	        atomic_compare_exchange_strong_explicit(_os_atomic_c11_atomic(p), \
	        &_r, v, memory_order_##m, memory_order_relaxed); *(g) = _r; _b; })
#define os_atomic_cmpxchgvw(p, e, v, g, m) \
	        ({ _os_atomic_basetypeof(p) _r = (e); int _b = \
	        atomic_compare_exchange_weak_explicit(_os_atomic_c11_atomic(p), \
	        &_r, v, memory_order_##m, memory_order_relaxed); *(g) = _r;  _b; })

#define os_atomic_rmw_loop(p, ov, nv, m, ...)  ({ \
	        bool _result = false; \
	        typeof(p) _p = (p); \
	        ov = os_atomic_load(_p, relaxed); \
	        do { \
	                __VA_ARGS__; \
	                _result = os_atomic_cmpxchgvw(_p, ov, nv, &ov, m); \
	        } while (!_result); \
	        _result; \
	})

#define os_atomic_rmw_loop_give_up_with_fence(m, expr) \
	        ({ os_atomic_thread_fence(m); expr; __builtin_unreachable(); })
#define os_atomic_rmw_loop_give_up(expr) \
	        os_atomic_rmw_loop_give_up_with_fence(relaxed, expr)

#define os_atomic_force_dependency_on(p, e) (p)
#define os_atomic_load_with_dependency_on(p, e) \
	        os_atomic_load(os_atomic_force_dependency_on(p, e), relaxed)

#if defined (__x86_64__)
#include "i386/atomic.h"
#elif defined (__arm__) || defined (__arm64__)
#include "arm/atomic.h"
#else
#error architecture not supported
#endif

#endif /* _MACHINE_ATOMIC_H */

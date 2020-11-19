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

#ifndef __OS_ATOMIC_H__
#define __OS_ATOMIC_H__

/*!
 * @file <os/atomic.h>
 *
 * @brief
 * Small header that helps write code that works with both C11 and C++11,
 * or pre-C11 type declarations.
 *
 * @discussion
 * The macros below allow to write code like this, that can be put in a header
 * and will work with both C11 and C++11:
 *
 * <code>
 * struct old_type {
 *     int atomic_field;
 * } old_variable;
 *
 * os_atomic_std(atomic_fetch_add_explicit)(
 *     os_cast_to_atomic_pointer(&old_variable), 1,
 *     os_atomic_std(memory_order_relaxed));
 * </code>
 */

#include <os/base.h>

#ifndef OS_ATOMIC_USES_CXX
#ifdef KERNEL
#define OS_ATOMIC_USES_CXX 0
#elif defined(__cplusplus) && __cplusplus >= 201103L
#define OS_ATOMIC_USES_CXX 1
#else
#define OS_ATOMIC_USES_CXX 0
#endif
#endif

#if OS_ATOMIC_USES_CXX
#include <atomic>
#define OS_ATOMIC_STD                    std::
#define os_atomic_std(op)                std::op
#define os_atomic(type)                  std::atomic<type> volatile
#define os_cast_to_atomic_pointer(p)     os::cast_to_atomic_pointer(p)
#define os_atomic_basetypeof(p)          decltype(os_cast_to_atomic_pointer(p)->load())
#define os_cast_to_nonatomic_pointer(p)  os::cast_to_nonatomic_pointer(p)
#else /* !OS_ATOMIC_USES_CXX */
#include <stdatomic.h>
#define OS_ATOMIC_STD
#define os_atomic_std(op)                op
#define os_atomic(type)                  type volatile _Atomic
#define os_cast_to_atomic_pointer(p)     (__typeof__(*(p)) volatile _Atomic *)(uintptr_t)(p)
#define os_atomic_basetypeof(p)          __typeof__(atomic_load(os_cast_to_atomic_pointer(p)))
#define os_cast_to_nonatomic_pointer(p)  (os_atomic_basetypeof(p) *)(uintptr_t)(p)
#endif /* !OS_ATOMIC_USES_CXX */

/*!
 * @group Internal implementation details
 *
 * @discussion The functions below are not intended to be used directly.
 */

#if OS_ATOMIC_USES_CXX
#include <type_traits>

namespace os {
template <class T> using add_volatile_t = typename std::add_volatile<T>::type;
template <class T> using remove_volatile_t = typename std::remove_volatile<T>::type;

template <class T>
inline add_volatile_t<std::atomic<remove_volatile_t<T> > > *
cast_to_atomic_pointer(T *v)
{
	return reinterpret_cast<add_volatile_t<std::atomic<remove_volatile_t<T> > > *>(v);
}

template <class T>
inline add_volatile_t<std::atomic<remove_volatile_t<T> > > *
cast_to_atomic_pointer(std::atomic<T> *v)
{
	return reinterpret_cast<add_volatile_t<std::atomic<remove_volatile_t<T> > > *>(v);
}

template <class T>
inline remove_volatile_t<T> *
cast_to_nonatomic_pointer(T *v)
{
	return const_cast<remove_volatile_t<T> *>(v);
}

template <class T>
inline remove_volatile_t<T> *
cast_to_nonatomic_pointer(std::atomic<T> *v)
{
	return reinterpret_cast<remove_volatile_t<T> *>(v);
}

template <class T>
inline remove_volatile_t<T> *
cast_to_nonatomic_pointer(volatile std::atomic<T> *v)
{
	auto _v = const_cast<std::atomic<T> *>(v);
	return reinterpret_cast<remove_volatile_t<T> *>(_v);
}
};
#endif /* OS_ATOMIC_USES_CXX */

#endif /* __OS_ATOMIC_H__ */

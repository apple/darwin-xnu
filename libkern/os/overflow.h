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

/*
 * Facilities for performing type- and overflow-checked arithmetic. These
 * functions return non-zero if overflow occured, zero otherwise. In either case,
 * the potentially overflowing operation is fully performed, mod the size of the
 * output type. See:
 * http://clang.llvm.org/docs/LanguageExtensions.html#checked-arithmetic-builtins
 * for full details.
 *
 * The compiler enforces that users of os_*_overflow() check the return value to
 * determine whether overflow occured.
 */

#ifndef _OS_OVERFLOW_H
#define _OS_OVERFLOW_H

#include <sys/cdefs.h>

/* compile-time assertion that 'x' and 'y' are equivalent types */
#define __OS_TYPE_CHECK(x, y) do { \
	_Static_assert(__builtin_types_compatible_p(typeof(x),typeof(y)), \
			"overflow arithmetic: incompatible types"); \
} while (0)

#define __os_add_overflow_func(T,U,V) _Generic((T), \
		unsigned:           __builtin_uadd_overflow, \
		unsigned long:      __builtin_uaddl_overflow, \
		unsigned long long: __builtin_uaddll_overflow, \
		int:                __builtin_sadd_overflow, \
		long:               __builtin_saddl_overflow, \
		long long:          __builtin_saddll_overflow \
	)(T,U,V)

#define __os_sub_overflow_func(T,U,V) _Generic((T), \
		unsigned:           __builtin_usub_overflow, \
		unsigned long:      __builtin_usubl_overflow, \
		unsigned long long: __builtin_usubll_overflow, \
		int:                __builtin_ssub_overflow, \
		long:               __builtin_ssubl_overflow, \
		long long:          __builtin_ssubll_overflow \
	)(T,U,V)

#define __os_mul_overflow_func(T,U,V) _Generic((T), \
		unsigned:           __builtin_umul_overflow, \
		unsigned long:      __builtin_umull_overflow, \
		unsigned long long: __builtin_umulll_overflow, \
		int:                __builtin_smul_overflow, \
		long:               __builtin_smull_overflow, \
		long long:          __builtin_smulll_overflow \
	)(T,U,V)

int __header_always_inline __attribute__((__warn_unused_result__))
__os_warn_unused(const int x)
{
	return x;
}

#define os_add_overflow(a, b, res) __os_warn_unused(({ \
	__OS_TYPE_CHECK((a), (b)); \
	__OS_TYPE_CHECK((b), *(res)); \
	__os_add_overflow_func((a), (b), (res)); \
}))

#define os_add3_overflow(a, b, c, res) __os_warn_unused(({ \
	typeof(a) _tmp; \
	int _s, _t; \
	_s = os_add_overflow((a), (b), &_tmp); \
	_t = os_add_overflow((c), _tmp, (res)); \
	_s | _t; \
}))

#define os_sub_overflow(a, b, res) __os_warn_unused(({ \
	__OS_TYPE_CHECK((a), (b)); \
	__OS_TYPE_CHECK((b), *(res)); \
	__os_sub_overflow_func((a), (b), (res)); \
}))

#define os_mul_overflow(a, b, res) __os_warn_unused(({ \
	__OS_TYPE_CHECK((a), (b)); \
	__OS_TYPE_CHECK((b), *(res)); \
	__os_mul_overflow_func((a), (b), (res)); \
}))

#endif /* _OS_OVERFLOW_H */

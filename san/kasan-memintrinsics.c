/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
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

#include <string.h>
#include <mach/boolean.h>

#include <mach/boolean.h>
#include <machine/limits.h>
#include <kern/debug.h>

#include <kasan_internal.h>
#include <memintrinsics.h>

#if MEMINTRINSICS
static bool check_intrinsics = true;
#else
static bool check_intrinsics = false;
#endif

void
__asan_bcopy(const void *src, void *dst, size_t sz)
{
	if (check_intrinsics) {
		kasan_check_range(src, sz, TYPE_MEMLD);
		kasan_check_range(dst, sz, TYPE_MEMSTR);
	}
	__nosan_bcopy(src, dst, sz);
}

void *
__asan_memmove(void *src, const void *dst, size_t sz)
{
	if (check_intrinsics) {
		kasan_check_range(src, sz, TYPE_MEMLD);
		kasan_check_range(dst, sz, TYPE_MEMSTR);
	}
	return __nosan_memmove(src, dst, sz);
}

void *
__asan_memcpy(void *dst, const void *src, size_t sz)
{
	if (check_intrinsics) {
		kasan_check_range(src, sz, TYPE_MEMLD);
		kasan_check_range(dst, sz, TYPE_MEMSTR);
	}
	return __nosan_memcpy(dst, src, sz);
}

void *
__asan_memset(void *dst, int c, size_t sz)
{
	if (check_intrinsics) {
		kasan_check_range(dst, sz, TYPE_MEMSTR);
	}
	return __nosan_memset(dst, c, sz);
}

void
__asan_bzero(void *dst, size_t sz)
{
	if (check_intrinsics) {
		kasan_check_range(dst, sz, TYPE_MEMSTR);
	}
	__nosan_bzero(dst, sz);
}

int
__asan_bcmp(const void *a, const void *b, size_t len)
{
	if (check_intrinsics) {
		kasan_check_range(a, len, TYPE_MEMLD);
		kasan_check_range(b, len, TYPE_MEMLD);
	}
	return __nosan_bcmp(a, b, len);
}

int
__asan_memcmp(const void *a, const void *b, size_t n)
{
	if (check_intrinsics) {
		kasan_check_range(a, n, TYPE_MEMLD);
		kasan_check_range(b, n, TYPE_MEMLD);
	}
	return __nosan_memcmp(a, b, n);
}

size_t
__asan_strlcpy(char *dst, const char *src, size_t sz)
{
	if (check_intrinsics) {
		kasan_check_range(dst, sz, TYPE_STRINGSTR);
	}
	return __nosan_strlcpy(dst, src, sz);
}

size_t
__asan_strlcat(char *dst, const char *src, size_t sz)
{
	if (check_intrinsics) {
		kasan_check_range(dst, sz, TYPE_STRINGSTR);
	}
	return __nosan_strlcat(dst, src, sz);
}

char *
__asan_strncpy(char *dst, const char *src, size_t sz)
{
	if (check_intrinsics) {
		kasan_check_range(dst, sz, TYPE_STRINGSTR);
	}
	return __nosan_strncpy(dst, src, sz);
}

char *
__asan_strncat(char *dst, const char *src, size_t sz)
{
	if (check_intrinsics) {
		kasan_check_range(dst, strlen(dst) + sz + 1, TYPE_STRINGSTR);
	}
	return __nosan_strncat(dst, src, sz);
}

size_t
__asan_strnlen(const char *src, size_t sz)
{
	if (check_intrinsics) {
		kasan_check_range(src, sz, TYPE_STRINGLD);
	}

	return __nosan_strnlen(src, sz);
}

size_t
__asan_strlen(const char *src)
{
	size_t sz = __nosan_strlen(src);
	if (check_intrinsics) {
		kasan_check_range(src, sz + 1, TYPE_STRINGLD);
	}
	return sz;
}

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
#ifndef _SAN_MEMINTRINSICS_H_
#define _SAN_MEMINTRINSICS_H_

/*
 * Non-sanitized versions of memory intrinsics
 */
static inline void *
__nosan_memcpy(void *dst, const void *src, size_t sz)
{
	return memcpy(dst, src, sz);
}
static inline void *
__nosan_memset(void *src, int c, size_t sz)
{
	return memset(src, c, sz);
}
static inline void *
__nosan_memmove(void *src, const void *dst, size_t sz)
{
	return memmove(src, dst, sz);
}
static inline int
__nosan_bcmp(const void *a, const void *b, size_t sz)
{
	return bcmp(a, b, sz);
}
static inline void
__nosan_bcopy(const void *src, void *dst, size_t sz)
{
	bcopy(src, dst, sz);
}
static inline int
__nosan_memcmp(const void *a, const void *b, size_t sz)
{
	return memcmp(a, b, sz);
}
static inline void
__nosan_bzero(void *dst, size_t sz)
{
	bzero(dst, sz);
}

static inline size_t
__nosan_strlcpy(char *dst, const char *src, size_t sz)
{
	return strlcpy(dst, src, sz);
}
static inline char  *
__nosan_strncpy(char *dst, const char *src, size_t sz)
{
	return strncpy(dst, src, sz);
}
static inline size_t
__nosan_strlcat(char *dst, const char *src, size_t sz)
{
	return strlcat(dst, src, sz);
}
static inline char  *
__nosan_strncat(char *dst, const char *src, size_t sz)
{
	return strncat(dst, src, sz);
}
static inline size_t
__nosan_strnlen(const char *src, size_t sz)
{
	return strnlen(src, sz);
}
static inline size_t
__nosan_strlen(const char *src)
{
	return strlen(src);
}

#if KASAN
void *__asan_memcpy(void *src, const void *dst, size_t sz);
void *__asan_memset(void *src, int c, size_t sz);
void *__asan_memmove(void *src, const void *dst, size_t sz);
void  __asan_bcopy(const void *src, void *dst, size_t sz);
void  __asan_bzero(void *dst, size_t sz);
int   __asan_bcmp(const void *a, const void *b, size_t sz);
int   __asan_memcmp(const void *a, const void *b, size_t sz);

size_t __asan_strlcpy(char *dst, const char *src, size_t sz);
char  *__asan_strncpy(char *dst, const char *src, size_t sz);
size_t __asan_strlcat(char *dst, const char *src, size_t sz);
char  *__asan_strncat(char *dst, const char *src, size_t sz);
size_t __asan_strnlen(const char *src, size_t sz);
size_t __asan_strlen(const char *src);

#define memcpy    __asan_memcpy
#define memmove   __asan_memmove
#define memset    __asan_memset
#define bcopy     __asan_bcopy
#define bzero     __asan_bzero
#define bcmp      __asan_bcmp
#define memcmp    __asan_memcmp

#define strlcpy   __asan_strlcpy
#define strncpy   __asan_strncpy
#define strlcat   __asan_strlcat
#define strncat   __asan_strncat
// #define strnlen   __asan_strnlen
// #define strlen    __asan_strlen

#endif

#endif /* _SAN_MEMINTRINSICS_H_ */

/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */
/*
   * HISTORY
 * @OSF_COPYRIGHT@
 */
#ifndef	_STRING_H_
#define	_STRING_H_	1

#ifdef MACH_KERNEL_PRIVATE
#include <types.h>
#else
#include <sys/types.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef	NULL
#if defined (__cplusplus)
#define NULL 0
#else
#define NULL ((void *)0)
#endif
#endif

extern void	*memcpy(void *, const void *, size_t);
extern int	memcmp(const void *, const void *, size_t);
extern void	*memmove(void *, const void *, size_t);
extern void	*memset(void *, int, size_t);
extern int	memset_s(void *, size_t, int, size_t);

extern size_t	strlen(const char *);
extern size_t	strnlen(const char *, size_t);

/* strcpy() is being deprecated. Please use strlcpy() instead. */
extern char	*strcpy(char *, const char *) __deprecated;
extern char	*strncpy(char *, const char *, size_t);

extern size_t	strlcat(char *, const char *, size_t);
extern size_t	strlcpy(char *, const char *, size_t);

/* strcat() is being deprecated. Please use strlcat() instead. */
extern char	*strcat(char *, const char *) __deprecated;
extern char	*strncat(char *, const char *, size_t);

/* strcmp() is being deprecated. Please use strncmp() instead. */
extern int	strcmp(const char *, const char *);
extern int	strncmp(const char *,const char *, size_t);

extern int	strcasecmp(const char *s1, const char *s2);
extern int	strncasecmp(const char *s1, const char *s2, size_t n);
extern char	*strnstr(char *s, const char *find, size_t slen);
extern char	*strchr(const char *s, int c);
#ifdef XNU_KERNEL_PRIVATE
extern char	*strrchr(const char *s, int c);
#endif
extern char	*STRDUP(const char *, int);
extern int	strprefix(const char *s1, const char *s2);

extern int	bcmp(const void *, const void *, size_t);
extern void	bcopy(const void *, void *, size_t);
extern void	bzero(void *, size_t);

#ifdef PRIVATE
#include <san/memintrinsics.h>
#endif

#if defined(__MAC_OS_X_VERSION_MIN_REQUIRED) && __MAC_OS_X_VERSION_MIN_REQUIRED < __MAC_10_13
/* older deployment target */
#elif defined(KASAN) || (defined (_FORTIFY_SOURCE) && _FORTIFY_SOURCE == 0)
/* FORTIFY_SOURCE disabled */
#else /* _chk macros */
#if __has_builtin(__builtin___memcpy_chk)
#define memcpy(dest, src, len) __builtin___memcpy_chk(dest, src, len, __builtin_object_size(dest, 0))
#endif

#if __has_builtin(__builtin___memmove_chk)
#define memmove(dest, src, len) __builtin___memmove_chk(dest, src, len, __builtin_object_size(dest, 0))
#endif

#if __has_builtin(__builtin___strncpy_chk)
#define strncpy(dest, src, len) __builtin___strncpy_chk(dest, src, len, __builtin_object_size(dest, 1))
#endif

#if __has_builtin(__builtin___strncat_chk)
#define strncat(dest, src, len) __builtin___strncat_chk(dest, src, len, __builtin_object_size(dest, 1))
#endif

#if __has_builtin(__builtin___strlcat_chk)
#define strlcat(dest, src, len) __builtin___strlcat_chk(dest, src, len, __builtin_object_size(dest, 1))
#endif

#if __has_builtin(__builtin___strlcpy_chk)
#define strlcpy(dest, src, len) __builtin___strlcpy_chk(dest, src, len, __builtin_object_size(dest, 1))
#endif

#if __has_builtin(__builtin___strcpy_chk)
#define strcpy(dest, src, len) __builtin___strcpy_chk(dest, src, __builtin_object_size(dest, 1))
#endif

#if __has_builtin(__builtin___strcat_chk)
#define strcat(dest, src) __builtin___strcat_chk(dest, src, __builtin_object_size(dest, 1))
#endif

#if __has_builtin(__builtin___memmove_chk)
#define bcopy(src, dest, len) __builtin___memmove_chk(dest, src, len, __builtin_object_size(dest, 0))
#endif

#endif /* _chk macros */
#ifdef __cplusplus
}
#endif

#endif	/* _STRING_H_ */

/*
 * Copyright (c) 1999-2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#ifndef _OS_OSBYTEORDERI386_H
#define _OS_OSBYTEORDERI386_H

#include <stdint.h>

#if !defined(OS_INLINE)
# if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#        define OS_INLINE static inline
# elif defined(__MWERKS__) || defined(__cplusplus)
#        define OS_INLINE static inline
# else
#        define OS_INLINE static __inline__
# endif
#endif

/* Generic byte swapping functions. */

OS_INLINE
uint16_t
_OSSwapInt16(
    uint16_t        data
)
{
    return ((data << 8) | (data >> 8));
}

OS_INLINE
uint32_t
_OSSwapInt32(
    uint32_t        data
)
{
    __asm__ ("bswap   %0" : "+r" (data));
    return data;
}

#if defined(__i386__)
OS_INLINE
uint64_t
_OSSwapInt64(
    uint64_t        data
)
{
    __asm__ ("bswap   %%eax\n\t"
             "bswap   %%edx\n\t" 
             "xchgl   %%eax, %%edx"
             : "+A" (data));
    return data;
}
#elif defined(__x86_64__)
OS_INLINE
uint64_t
_OSSwapInt64(
    uint64_t        data
)
{
    __asm__ ("bswap   %0" : "+r" (data));
    return data;
}
#else
#error Unknown architecture
#endif

/* Functions for byte reversed loads. */

OS_INLINE
uint16_t
OSReadSwapInt16(
    const volatile void   * base,
    uintptr_t       byteOffset
)
{
    uint16_t result;

    result = *(volatile uint16_t *)((uintptr_t)base + byteOffset);
    return _OSSwapInt16(result);
}

OS_INLINE
uint32_t
OSReadSwapInt32(
    const volatile void   * base,
    uintptr_t       byteOffset
)
{
    uint32_t result;

    result = *(volatile uint32_t *)((uintptr_t)base + byteOffset);
    return _OSSwapInt32(result);
}

OS_INLINE
uint64_t
OSReadSwapInt64(
    const volatile void   * base,
    uintptr_t       byteOffset
)
{
    uint64_t result;

    result = *(volatile uint64_t *)((uintptr_t)base + byteOffset);
    return _OSSwapInt64(result);
}

/* Functions for byte reversed stores. */

OS_INLINE
void
OSWriteSwapInt16(
    volatile void   * base,
    uintptr_t       byteOffset,
    uint16_t        data
)
{
    *(volatile uint16_t *)((uintptr_t)base + byteOffset) = _OSSwapInt16(data);
}

OS_INLINE
void
OSWriteSwapInt32(
    volatile void   * base,
    uintptr_t       byteOffset,
    uint32_t        data
)
{
    *(volatile uint32_t *)((uintptr_t)base + byteOffset) = _OSSwapInt32(data);
}

OS_INLINE
void
OSWriteSwapInt64(
    volatile void    * base,
    uintptr_t        byteOffset,
    uint64_t         data
)
{
    *(volatile uint64_t *)((uintptr_t)base + byteOffset) = _OSSwapInt64(data);
}

#endif /* ! _OS_OSBYTEORDERI386_H */

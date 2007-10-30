/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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

#ifndef _OS_OSBYTEORDERPPC_H
#define _OS_OSBYTEORDERPPC_H

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

/* Functions for byte reversed loads. */

OS_INLINE
uint16_t
OSReadSwapInt16(
    const volatile void * base,
    uintptr_t             byteOffset
)
{
    uint16_t result;
    volatile uint16_t *addr = (volatile uint16_t *)((uintptr_t)base + byteOffset);

    __asm__ ("lhbrx %0, %2, %1"
             : "=r" (result)
             : "r"  (base), "bO" (byteOffset), "m" (*addr));
    return result;
}

OS_INLINE
uint32_t
OSReadSwapInt32(
    const volatile void * base,
    uintptr_t             byteOffset
)
{
    uint32_t result;
    volatile uint32_t *addr = (volatile uint32_t *)((uintptr_t)base + byteOffset);

    __asm__ ("lwbrx %0, %2, %1"
             : "=r" (result)
             : "r"  (base), "bO" (byteOffset), "m" (*addr));
    return result;
}

OS_INLINE
uint64_t
OSReadSwapInt64(
    const volatile void * base,
    uintptr_t             byteOffset
)
{
    volatile uint64_t *addr = (volatile uint64_t *)((uintptr_t)base + byteOffset);
    union {
        uint64_t u64;
        uint32_t u32[2];
    } u;

    __asm__ ("lwbrx %0, %3, %2\n\t"
             "lwbrx %1, %4, %2"
             : "=&r" (u.u32[1]), "=r" (u.u32[0])
             : "r"  (base), "bO" (byteOffset), "b" (byteOffset + 4), "m" (*addr));
    return u.u64;
}

/* Functions for byte reversed stores. */

OS_INLINE
void
OSWriteSwapInt16(
    volatile void * base,
    uintptr_t       byteOffset,
    uint16_t        data
)
{
    volatile uint16_t *addr = (volatile uint16_t *)((uintptr_t)base + byteOffset);

    __asm__ ("sthbrx %1, %3, %2"
             : "=m" (*addr)
             : "r" (data), "r" (base), "bO" (byteOffset));
}

OS_INLINE
void
OSWriteSwapInt32(
    volatile void * base,
    uintptr_t       byteOffset,
    uint32_t        data
)
{
    volatile uint32_t *addr = (volatile uint32_t *)((uintptr_t)base + byteOffset);

    __asm__ ("stwbrx %1, %3, %2"
             : "=m" (*addr)
             : "r" (data), "r" (base), "bO" (byteOffset));
}

OS_INLINE
void
OSWriteSwapInt64(
    volatile void * base,
    uintptr_t       byteOffset,
    uint64_t        data
)
{
    volatile uint64_t *addr = (volatile uint64_t *)((uintptr_t)base + byteOffset);
    uint32_t hi = (uint32_t)(data >> 32);
    uint32_t lo = (uint32_t)(data & 0xffffffff);

    __asm__ ("stwbrx %1, %4, %3\n\t"
             "stwbrx %2, %5, %3"
             : "=m" (*addr)
             : "r" (lo), "r" (hi), "r" (base), "bO" (byteOffset), "b" (byteOffset + 4));
}

/* Generic byte swapping functions. */

OS_INLINE
uint16_t
_OSSwapInt16(
    uint16_t data
)
{
    return OSReadSwapInt16(&data, 0);
}

OS_INLINE
uint32_t
_OSSwapInt32(
    uint32_t data
)
{
    return OSReadSwapInt32(&data, 0);
}

OS_INLINE
uint64_t
_OSSwapInt64(
    uint64_t data
)
{
    return OSReadSwapInt64(&data, 0);
}

#endif /* ! _OS_OSBYTEORDERPPC_H */

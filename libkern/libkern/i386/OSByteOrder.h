/*
 * Copyright (c) 1999-2003 Apple Computer, Inc. All rights reserved.
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
#        define OS_INLINE static inline
#endif

/* Generic byte swapping functions. */

OS_INLINE
uint16_t
_OSSwapInt16(
    uint16_t        data
)
{
    __asm__ ("xchgb %b0, %h0" : "+q" (data));
    return data;
}

OS_INLINE
uint32_t
_OSSwapInt32(
    uint32_t        data
)
{
    __asm__ ("bswap %0" : "+r" (data));
    return data;
}

OS_INLINE
uint64_t
_OSSwapInt64(
    uint64_t        data
)
{
    union {
        uint64_t ull;
        uint32_t ul[2];
    } u;

    /* This actually generates the best code */
    u.ul[0] = data >> 32;
    u.ul[1] = data & 0xffffffff;
    u.ul[0] = _OSSwapInt32(u.ul[0]);
    u.ul[1] = _OSSwapInt32(u.ul[1]);
    return u.ull;
}

/* Functions for byte reversed loads. */

OS_INLINE
uint16_t
OSReadSwapInt16(
    volatile void   * base,
    uintptr_t       offset
)
{
    uint16_t result;

    result = *(uint16_t *)((uintptr_t)base + offset);
    return _OSSwapInt16(result);
}

OS_INLINE
uint32_t
OSReadSwapInt32(
    volatile void   * base,
    uintptr_t       offset
)
{
    uint32_t result;

    result = *(uint32_t *)((uintptr_t)base + offset);
    return _OSSwapInt32(result);
}

OS_INLINE
uint64_t
OSReadSwapInt64(
    volatile void   * base,
    uintptr_t       offset
)
{
    uint32_t * inp;
    union ullc {
        uint64_t     ull;
        uint32_t     ul[2];
    } outv;

    inp = (uint32_t *)((uintptr_t)base + offset);
    outv.ul[0] = inp[1];
    outv.ul[1] = inp[0];
    outv.ul[0] = _OSSwapInt32(outv.ul[0]);
    outv.ul[1] = _OSSwapInt32(outv.ul[1]);
    return outv.ull;
}

/* Functions for byte reversed stores. */

OS_INLINE
void
OSWriteSwapInt16(
    volatile void   * base,
    uintptr_t       offset,
    uint16_t        data
)
{
    *(uint16_t *)((uintptr_t)base + offset) = _OSSwapInt16(data);
}

OS_INLINE
void
OSWriteSwapInt32(
    volatile void   * base,
    uintptr_t       offset,
    uint32_t        data
)
{
    *(uint32_t *)((uintptr_t)base + offset) = _OSSwapInt32(data);
}

OS_INLINE
void
OSWriteSwapInt64(
    volatile void    * base,
    uintptr_t        offset,
    uint64_t         data
)
{
    *(uint64_t *)((uintptr_t)base + offset) = _OSSwapInt64(data);
}

#endif /* ! _OS_OSBYTEORDERI386_H */

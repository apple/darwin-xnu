/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved.
 *
 * HISTORY
 *
 */

#ifndef _OS_OSBYTEORDER_H
#define _OS_OSBYTEORDER_H

#include <stdint.h>

#if defined(__GNUC__) && defined(__ppc__)
#include <libkern/ppc/OSByteOrder.h>
#elif defined(__GNUC__) && defined(__i386__)
#include <libkern/i386/OSByteOrder.h>
#else
#include <libkern/machine/OSByteOrder.h>
#endif

enum {
    OSUnknownByteOrder,
    OSLittleEndian,
    OSBigEndian
};

OS_INLINE
int32_t
OSHostByteOrder(void) {
#if defined(__LITTLE_ENDIAN__)
    return OSLittleEndian;
#elif defined(__BIG_ENDIAN__)
    return OSBigEndian;
#else
    return OSUnknownByteOrder;
#endif
}

/* Macros for swapping constant values in the preprocessing stage. */
#define OSSwapConstInt16(x) ((((uint16_t)(x) & 0xff00) >> 8) | \
                             (((uint16_t)(x) & 0x00ff) << 8))

#define OSSwapConstInt32(x) ((((uint32_t)(x) & 0xff000000) >> 24) | \
                             (((uint32_t)(x) & 0x00ff0000) >>  8) | \
                             (((uint32_t)(x) & 0x0000ff00) <<  8) | \
                             (((uint32_t)(x) & 0x000000ff) << 24))

#define OSSwapConstInt64(x) ((((uint64_t)(x) & 0xff00000000000000ULL) >> 56) | \
                             (((uint64_t)(x) & 0x00ff000000000000ULL) >> 40) | \
                             (((uint64_t)(x) & 0x0000ff0000000000ULL) >> 24) | \
                             (((uint64_t)(x) & 0x000000ff00000000ULL) >>  8) | \
                             (((uint64_t)(x) & 0x00000000ff000000ULL) <<  8) | \
                             (((uint64_t)(x) & 0x0000000000ff0000ULL) << 24) | \
                             (((uint64_t)(x) & 0x000000000000ff00ULL) << 40) | \
                             (((uint64_t)(x) & 0x00000000000000ffULL) << 56))

#if !defined(__GNUC__)
#define __builtin_constant_p(x) (0)
#endif

#define OSSwapInt16(x) \
    (__builtin_constant_p(x) ? OSSwapConstInt16(x) : _OSSwapInt16(x))

#define OSSwapInt32(x) \
    (__builtin_constant_p(x) ? OSSwapConstInt32(x) : _OSSwapInt32(x))

#define OSSwapInt64(x) \
    (__builtin_constant_p(x) ? OSSwapConstInt64(x) : _OSSwapInt64(x))

#define OSReadBigInt(x, y)		OSReadBigInt32(x, y)
#define OSWriteBigInt(x, y, z)		OSWriteBigInt32(x, y, z)
#define OSSwapBigToHostInt(x)		OSSwapBigToHostInt32(x)
#define OSSwapHostToBigInt(x)		OSSwapHostToBigInt32(x)
#define OSReadLittleInt(x, y)		OSReadLittleInt32(x, y)
#define OSWriteLittleInt(x, y, z)	OSWriteLittleInt32(x, y, z)
#define OSSwapHostToLittleInt(x)	OSSwapHostToLittleInt32(x)
#define OSSwapLittleToHostInt(x)	OSSwapLittleToHostInt32(x)

#if		defined(__BIG_ENDIAN__)

/* Functions for loading big endian to host endianess. */

OS_INLINE
uint16_t
OSReadBigInt16(
    const volatile void               * base,
    uintptr_t                     offset
)
{
    return *(volatile uint16_t *)((uintptr_t)base + offset);
}

OS_INLINE
uint32_t
OSReadBigInt32(
    const volatile void               * base,
    uintptr_t                     offset
)
{
    return *(volatile uint32_t *)((uintptr_t)base + offset);
}

OS_INLINE
uint64_t
OSReadBigInt64(
    const volatile void               * base,
    uintptr_t                     offset
)
{
    return *(volatile uint64_t *)((uintptr_t)base + offset);
}

/* Functions for storing host endianess to big endian. */

OS_INLINE
void
OSWriteBigInt16(
    volatile void               * base,
    uintptr_t                     offset,
    uint16_t                      data
)
{
    *(volatile uint16_t *)((uintptr_t)base + offset) = data;
}

OS_INLINE
void
OSWriteBigInt32(
    volatile void               * base,
    uintptr_t                     offset,
    uint32_t                      data
)
{
    *(volatile uint32_t *)((uintptr_t)base + offset) = data;
}

OS_INLINE
void
OSWriteBigInt64(
    volatile void               * base,
    uintptr_t                     offset,
    uint64_t                      data
)
{
    *(volatile uint64_t *)((uintptr_t)base + offset) = data;
}

/* Functions for loading little endian to host endianess. */

OS_INLINE
uint16_t
OSReadLittleInt16(
    volatile void               * base,
    uintptr_t                     offset
)
{
    return OSReadSwapInt16(base, offset);
}

OS_INLINE
uint32_t
OSReadLittleInt32(
    volatile void               * base,
    uintptr_t                     offset
)
{
    return OSReadSwapInt32(base, offset);
}

OS_INLINE
uint64_t
OSReadLittleInt64(
    volatile void               * base,
    uintptr_t                     offset
)
{
    return OSReadSwapInt64(base, offset);
}

/* Functions for storing host endianess to little endian. */

OS_INLINE
void
OSWriteLittleInt16(
    volatile void               * base,
    uintptr_t                     offset,
    uint16_t                      data
)
{
    OSWriteSwapInt16(base, offset, data);
}

OS_INLINE
void
OSWriteLittleInt32(
    volatile void               * base,
    uintptr_t                     offset,
    uint32_t                      data
)
{
    OSWriteSwapInt32(base, offset, data);
}

OS_INLINE
void
OSWriteLittleInt64(
    volatile void               * base,
    uintptr_t                     offset,
    uint64_t                      data
)
{
    OSWriteSwapInt64(base, offset, data);
}

/* Host endianess to big endian byte swapping macros for constants. */

#define OSSwapHostToBigConstInt16(x) (x)
#define OSSwapHostToBigConstInt32(x) (x)
#define OSSwapHostToBigConstInt64(x) (x)

/* Generic host endianess to big endian byte swapping functions. */

OS_INLINE
uint16_t
OSSwapHostToBigInt16(
    uint16_t                        data
)
{
    return data;
}

OS_INLINE
uint32_t
OSSwapHostToBigInt32(
    uint32_t                        data
)
{
    return data;
}

OS_INLINE
uint64_t
OSSwapHostToBigInt64(
    uint64_t                        data
)
{
    return data;
}

/* Host endianess to little endian byte swapping macros for constants. */

#define OSSwapHostToLittleConstInt16(x) OSSwapConstInt16(x)
#define OSSwapHostToLittleConstInt32(x) OSSwapConstInt32(x) 
#define OSSwapHostToLittleConstInt64(x) OSSwapConstInt64(x) 

/* Generic host endianess to little endian byte swapping functions. */

#define OSSwapHostToLittleInt16(x) OSSwapInt16(x)
#define OSSwapHostToLittleInt32(x) OSSwapInt32(x)
#define OSSwapHostToLittleInt64(x) OSSwapInt64(x)

/* Big endian to host endianess byte swapping macros for constants. */
    
#define OSSwapBigToHostConstInt16(x) (x)
#define OSSwapBigToHostConstInt32(x) (x)
#define OSSwapBigToHostConstInt64(x) (x)

/* Generic big endian to host endianess byte swapping functions. */

OS_INLINE
uint16_t
OSSwapBigToHostInt16(
    uint16_t                        data
)
{
    return data;
}

OS_INLINE
uint32_t
OSSwapBigToHostInt32(
    uint32_t                        data
)
{
    return data;
}

OS_INLINE
uint64_t
OSSwapBigToHostInt64(
    uint64_t                        data
)
{
    return data;
}

/* Little endian to host endianess byte swapping macros for constants. */
   
#define OSSwapLittleToHostConstInt16(x) OSSwapConstInt16(x)
#define OSSwapLittleToHostConstInt32(x) OSSwapConstInt32(x)
#define OSSwapLittleToHostConstInt64(x) OSSwapConstInt64(x)

/* Generic little endian to host endianess byte swapping functions. */

#define OSSwapLittleToHostInt16(x) OSSwapInt16(x)
#define OSSwapLittleToHostInt32(x) OSSwapInt32(x)
#define OSSwapLittleToHostInt64(x) OSSwapInt64(x)

#elif		defined(__LITTLE_ENDIAN__)

/* Functions for loading big endian to host endianess. */

OS_INLINE
uint16_t
OSReadBigInt16(
    const volatile void               * base,
    uintptr_t                     offset
)
{
    return OSReadSwapInt16(base, offset);
}

OS_INLINE
uint32_t
OSReadBigInt32(
    const volatile void               * base,
    uintptr_t                     offset
)
{
    return OSReadSwapInt32(base, offset);
}

OS_INLINE
uint64_t
OSReadBigInt64(
    const volatile void               * base,
    uintptr_t                     offset
)
{
    return OSReadSwapInt64(base, offset);
}

/* Functions for storing host endianess to big endian. */

OS_INLINE
void
OSWriteBigInt16(
    volatile void               * base,
    uintptr_t                     offset,
    uint16_t                      data
)
{
    OSWriteSwapInt16(base, offset, data);
}

OS_INLINE
void
OSWriteBigInt32(
    volatile void               * base,
    uintptr_t                     offset,
    uint32_t                      data
)
{
    OSWriteSwapInt32(base, offset, data);
}

OS_INLINE
void
OSWriteBigInt64(
    volatile void               * base,
    uintptr_t                     offset,
    uint64_t                      data
)
{
    OSWriteSwapInt64(base, offset, data);
}

/* Functions for loading little endian to host endianess. */

OS_INLINE
uint16_t
OSReadLittleInt16(
    const volatile void               * base,
    uintptr_t                     offset
)
{
    return *(volatile uint16_t *)((uintptr_t)base + offset);
}

OS_INLINE
uint32_t
OSReadLittleInt32(
    const volatile void               * base,
    uintptr_t                     offset
)
{
    return *(volatile uint32_t *)((uintptr_t)base + offset);
}

OS_INLINE
uint64_t
OSReadLittleInt64(
    const volatile void               * base,
    uintptr_t                     offset
)
{
    return *(volatile uint64_t *)((uintptr_t)base + offset);
}

/* Functions for storing host endianess to little endian. */

OS_INLINE
void
OSWriteLittleInt16(
    volatile void               * base,
    uintptr_t                     offset,
    uint16_t                        data
)
{
    *(volatile uint16_t *)((uintptr_t)base + offset) = data;
}

OS_INLINE
void
OSWriteLittleInt32(
    volatile void               * base,
    uintptr_t                     offset,
    uint32_t                        data
)
{
    *(volatile uint32_t *)((uintptr_t)base + offset) = data;
}

OS_INLINE
void
OSWriteLittleInt64(
    volatile void               * base,
    uintptr_t                     offset,
    uint64_t                      data
)
{
    *(volatile uint64_t *)((uintptr_t)base + offset) = data;
}

/* Host endianess to big endian byte swapping macros for constants. */

#define OSSwapHostToBigConstInt16(x) OSSwapConstInt16(x)
#define OSSwapHostToBigConstInt32(x) OSSwapConstInt32(x)
#define OSSwapHostToBigConstInt64(x) OSSwapConstInt64(x)

/* Generic host endianess to big endian byte swapping functions. */

#define OSSwapHostToBigInt16(x) OSSwapInt16(x)
#define OSSwapHostToBigInt32(x) OSSwapInt32(x)
#define OSSwapHostToBigInt64(x) OSSwapInt64(x)

/* Host endianess to little endian byte swapping macros for constants. */

#define OSSwapHostToLittleConstInt16(x) (x)
#define OSSwapHostToLittleConstInt32(x) (x)
#define OSSwapHostToLittleConstInt64(x) (x) 

/* Generic host endianess to little endian byte swapping functions. */

OS_INLINE
uint16_t
OSSwapHostToLittleInt16(
    uint16_t                        data
)
{
    return data;
}

OS_INLINE
uint32_t
OSSwapHostToLittleInt32(
    uint32_t                        data
)
{
    return data;
}

OS_INLINE
uint64_t
OSSwapHostToLittleInt64(
    uint64_t                        data
)
{
    return data;
}

/* Big endian to host endianess byte swapping macros for constants. */

#define OSSwapBigToHostConstInt16(x) OSSwapConstInt16(x)
#define OSSwapBigToHostConstInt32(x) OSSwapConstInt32(x)
#define OSSwapBigToHostConstInt64(x) OSSwapConstInt64(x)

/* Generic big endian to host endianess byte swapping functions. */

#define OSSwapBigToHostInt16(x) OSSwapInt16(x)
#define OSSwapBigToHostInt32(x) OSSwapInt32(x)
#define OSSwapBigToHostInt64(x) OSSwapInt64(x)

/* Little endian to host endianess byte swapping macros for constants. */

#define OSSwapLittleToHostConstInt16(x) (x)
#define OSSwapLittleToHostConstInt32(x) (x)
#define OSSwapLittleToHostConstInt64(x) (x)

/* Generic little endian to host endianess byte swapping functions. */

OS_INLINE
uint16_t
OSSwapLittleToHostInt16(
    uint16_t                        data
)
{
    return data;
}

OS_INLINE
uint32_t
OSSwapLittleToHostInt32(
    uint32_t                        data
)
{
    return data;
}

OS_INLINE
uint64_t
OSSwapLittleToHostInt64(
    uint64_t                        data
)
{
    return data;
}

#else
#error Unknown endianess.
#endif

#endif /* ! _OS_OSBYTEORDER_H */



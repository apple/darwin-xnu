/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved.
 *
 * HISTORY
 *
 */

#ifndef _OS_OSBYTEORDER_H
#define _OS_OSBYTEORDER_H

#include <libkern/OSTypes.h>

#if		defined(__ppc__)
#include <libkern/ppc/OSByteOrder.h>
#elif		defined(__i386__)
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
UInt32
OSHostByteOrder(void) {
    UInt32 x = (OSBigEndian << 24) | OSLittleEndian;
    return (UInt32)*((UInt8 *)&x);
}

/* Macros for swapping constant values in the preprocessing stage. */
#define OSSwapConstInt16(x) ((((x) & 0xff00) >> 8) | (((x) & 0x00ff) << 8))

#define OSSwapConstInt32(x) ((OSSwapConstInt16(x) << 16) | \
			     (OSSwapConstInt16((x) >> 16)))

#define OSSwapConstInt64(x) ((OSSwapConstInt32(x) << 32) | \
			     (OSSwapConstInt32((x) >> 32)))

#if		defined(__BIG_ENDIAN__)

/* Functions for loading big endian to host endianess. */

OS_INLINE
UInt
OSReadBigInt(
    volatile void               * base,
    UInt                          offset
)
{
    return *(volatile UInt *)((UInt8 *)base + offset);
}

OS_INLINE
UInt16
OSReadBigInt16(
    volatile void               * base,
    UInt                          offset
)
{
    return *(volatile UInt16 *)((UInt8 *)base + offset);
}

OS_INLINE
UInt32
OSReadBigInt32(
    volatile void               * base,
    UInt                          offset
)
{
    return *(volatile UInt32 *)((UInt8 *)base + offset);
}

OS_INLINE
UInt64
OSReadBigInt64(
    volatile void               * base,
    UInt                          offset
)
{
    return *(volatile UInt64 *)((UInt8 *)base + offset);
}

/* Functions for storing host endianess to big endian. */

OS_INLINE
void
OSWriteBigInt(
    volatile void               * base,
    UInt                          offset,
    UInt                          data
)
{
    *(volatile UInt *)((UInt8 *)base + offset) = data;
}

OS_INLINE
void
OSWriteBigInt16(
    volatile void               * base,
    UInt                          offset,
    UInt16                        data
)
{
    *(volatile UInt16 *)((UInt8 *)base + offset) = data;
}

OS_INLINE
void
OSWriteBigInt32(
    volatile void               * base,
    UInt                          offset,
    UInt32                        data
)
{
    *(volatile UInt32 *)((UInt8 *)base + offset) = data;
}

OS_INLINE
void
OSWriteBigInt64(
    volatile void               * base,
    UInt                          offset,
    UInt64                        data
)
{
    *(volatile UInt64 *)((UInt8 *)base + offset) = data;
}

/* Functions for loading little endian to host endianess. */

OS_INLINE
UInt
OSReadLittleInt(
    volatile void               * base,
    UInt                          offset
)
{
    return OSReadSwapInt(base, offset);
}

OS_INLINE
UInt16
OSReadLittleInt16(
    volatile void               * base,
    UInt                          offset
)
{
    return OSReadSwapInt16(base, offset);
}

OS_INLINE
UInt32
OSReadLittleInt32(
    volatile void               * base,
    UInt                          offset
)
{
    return OSReadSwapInt32(base, offset);
}

OS_INLINE
UInt64
OSReadLittleInt64(
    volatile void               * base,
    UInt                          offset
)
{
    return OSReadSwapInt64(base, offset);
}

/* Functions for storing host endianess to little endian. */

OS_INLINE
void
OSWriteLittleInt(
    volatile void               * base,
    UInt                          offset,
    UInt                          data
)
{
    OSWriteSwapInt(base, offset, data);
}

OS_INLINE
void
OSWriteLittleInt16(
    volatile void               * base,
    UInt                          offset,
    UInt16                        data
)
{
    OSWriteSwapInt16(base, offset, data);
}

OS_INLINE
void
OSWriteLittleInt32(
    volatile void               * base,
    UInt                          offset,
    UInt32                        data
)
{
    OSWriteSwapInt32(base, offset, data);
}

OS_INLINE
void
OSWriteLittleInt64(
    volatile void               * base,
    UInt                          offset,
    UInt64                        data
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
UInt
OSSwapHostToBigInt(
    UInt                          data
)
{
    return data;
}

OS_INLINE
UInt16
OSSwapHostToBigInt16(
    UInt16                        data
)
{
    return data;
}

OS_INLINE
UInt32
OSSwapHostToBigInt32(
    UInt32                        data
)
{
    return data;
}

OS_INLINE
UInt64
OSSwapHostToBigInt64(
    UInt64                        data
)
{
    return data;
}

/* Host endianess to little endian byte swapping macros for constants. */

#define OSSwapHostToLittleConstInt16(x) OSSwapConstInt16(x)
#define OSSwapHostToLittleConstInt32(x) OSSwapConstInt32(x) 
#define OSSwapHostToLittleConstInt64(x) OSSwapConstInt64(x) 

/* Generic host endianess to little endian byte swapping functions. */

OS_INLINE
UInt
OSSwapHostToLittleInt(
    UInt                          data
)
{
    return OSSwapInt(data);
}

OS_INLINE
UInt16
OSSwapHostToLittleInt16(
    UInt16                        data
)
{
    return OSSwapInt16(data);
}

OS_INLINE
UInt32
OSSwapHostToLittleInt32(
    UInt32                        data
)
{
    return OSSwapInt32(data);
}

OS_INLINE
UInt64
OSSwapHostToLittleInt64(
    UInt64                        data
)
{
    return OSSwapInt64(data);
}

/* Big endian to host endianess byte swapping macros for constants. */
    
#define OSSwapBigToHostConstInt16(x) (x)
#define OSSwapBigToHostConstInt32(x) (x)
#define OSSwapBigToHostConstInt64(x) (x)

/* Generic big endian to host endianess byte swapping functions. */

OS_INLINE
UInt
OSSwapBigToHostInt(
    UInt                          data
)
{
    return data;
}

OS_INLINE
UInt16
OSSwapBigToHostInt16(
    UInt16                        data
)
{
    return data;
}

OS_INLINE
UInt32
OSSwapBigToHostInt32(
    UInt32                        data
)
{
    return data;
}

OS_INLINE
UInt64
OSSwapBigToHostInt64(
    UInt64                        data
)
{
    return data;
}

/* Little endian to host endianess byte swapping macros for constants. */
   
#define OSSwapLittleToHostConstInt16(x) OSSwapConstInt16(x)
#define OSSwapLittleToHostConstInt32(x) OSSwapConstInt32(x)
#define OSSwapLittleToHostConstInt64(x) OSSwapConstInt64(x)

/* Generic little endian to host endianess byte swapping functions. */

OS_INLINE
UInt
OSSwapLittleToHostInt(
    UInt                          data
)
{
    return OSSwapInt(data);
}

OS_INLINE
UInt16
OSSwapLittleToHostInt16(
    UInt16                        data
)
{
    return OSSwapInt16(data);
}

OS_INLINE
UInt32
OSSwapLittleToHostInt32(
    UInt32                        data
)
{
    return OSSwapInt32(data);
}

OS_INLINE
UInt64
OSSwapLittleToHostInt64(
    UInt64                        data
)
{
    return OSSwapInt64(data);
}

#elif		defined(__LITTLE_ENDIAN__)

/* Functions for loading big endian to host endianess. */

OS_INLINE
UInt
OSReadBigInt(
    volatile void               * base,
    UInt                          offset
)
{
    return OSReadSwapInt(base, offset);
}

OS_INLINE
UInt16
OSReadBigInt16(
    volatile void               * base,
    UInt                          offset
)
{
    return OSReadSwapInt16(base, offset);
}

OS_INLINE
UInt32
OSReadBigInt32(
    volatile void               * base,
    UInt                          offset
)
{
    return OSReadSwapInt32(base, offset);
}

OS_INLINE
UInt64
OSReadBigInt64(
    volatile void               * base,
    UInt                          offset
)
{
    return OSReadSwapInt64(base, offset);
}

/* Functions for storing host endianess to big endian. */

OS_INLINE
void
OSWriteBigInt(
    volatile void               * base,
    UInt                          offset,
    UInt                          data
)
{
    OSWriteSwapInt(base, offset, data);
}

OS_INLINE
void
OSWriteBigInt16(
    volatile void               * base,
    UInt                          offset,
    UInt16                        data
)
{
    OSWriteSwapInt16(base, offset, data);
}

OS_INLINE
void
OSWriteBigInt32(
    volatile void               * base,
    UInt                          offset,
    UInt32                        data
)
{
    OSWriteSwapInt32(base, offset, data);
}

OS_INLINE
void
OSWriteBigInt64(
    volatile void               * base,
    UInt                          offset,
    UInt64                        data
)
{
    OSWriteSwapInt64(base, offset, data);
}

/* Functions for loading little endian to host endianess. */

OS_INLINE
UInt
OSReadLittleInt(
    volatile void               * base,
    UInt                          offset
)
{
    return *(volatile UInt *)((UInt8 *)base + offset);
}

OS_INLINE
UInt16
OSReadLittleInt16(
    volatile void               * base,
    UInt                          offset
)
{
    return *(volatile UInt16 *)((UInt8 *)base + offset);
}

OS_INLINE
UInt32
OSReadLittleInt32(
    volatile void               * base,
    UInt                          offset
)
{
    return *(volatile UInt32 *)((UInt8 *)base + offset);
}

OS_INLINE
UInt64
OSReadLittleInt64(
    volatile void               * base,
    UInt                          offset
)
{
    return *(volatile UInt64 *)((UInt8 *)base + offset);
}

/* Functions for storing host endianess to little endian. */

OS_INLINE
void
OSWriteLittleInt(
    volatile void               * base,
    UInt                          offset,
    UInt                          data
)
{
    *(volatile UInt *)((UInt8 *)base + offset) = data;
}

OS_INLINE
void
OSWriteLittleInt16(
    volatile void               * base,
    UInt                          offset,
    UInt16                        data
)
{
    *(volatile UInt16 *)((UInt8 *)base + offset) = data;
}

OS_INLINE
void
OSWriteLittleInt32(
    volatile void               * base,
    UInt                          offset,
    UInt32                        data
)
{
    *(volatile UInt32 *)((UInt8 *)base + offset) = data;
}

OS_INLINE
void
OSWriteLittleInt64(
    volatile void               * base,
    UInt                          offset,
    UInt64                        data
)
{
    *(volatile UInt64 *)((UInt8 *)base + offset) = data;
}

/* Host endianess to big endian byte swapping macros for constants. */

#define OSSwapHostToBigConstInt16(x) OSSwapConstInt16(x)
#define OSSwapHostToBigConstInt32(x) OSSwapConstInt32(x)
#define OSSwapHostToBigConstInt64(x) OSSwapConstInt64(x)

/* Generic host endianess to big endian byte swapping functions. */

OS_INLINE
UInt
OSSwapHostToBigInt(
    UInt                          data
)
{
    return OSSwapInt(data);
}

OS_INLINE
UInt16
OSSwapHostToBigInt16(
    UInt16                        data
)
{
    return OSSwapInt16(data);
}

OS_INLINE
UInt32
OSSwapHostToBigInt32(
    UInt32                        data
)
{
    return OSSwapInt32(data);
}

OS_INLINE
UInt64
OSSwapHostToBigInt64(
    UInt64                        data
)
{
    return OSSwapInt64(data);
}

/* Host endianess to little endian byte swapping macros for constants. */

#define OSSwapHostToLittleConstInt16(x) (x)
#define OSSwapHostToLittleConstInt32(x) (x)
#define OSSwapHostToLittleConstInt64(x) (x) 

/* Generic host endianess to little endian byte swapping functions. */

OS_INLINE
UInt
OSSwapHostToLittleInt(
    UInt                          data
)
{
    return data;
}

OS_INLINE
UInt16
OSSwapHostToLittleInt16(
    UInt16                        data
)
{
    return data;
}

OS_INLINE
UInt32
OSSwapHostToLittleInt32(
    UInt32                        data
)
{
    return data;
}

OS_INLINE
UInt64
OSSwapHostToLittleInt64(
    UInt64                        data
)
{
    return data;
}

/* Big endian to host endianess byte swapping macros for constants. */

#define OSSwapBigToHostConstInt16(x) OSSwapConstInt16(x)
#define OSSwapBigToHostConstInt32(x) OSSwapConstInt32(x)
#define OSSwapBigToHostConstInt64(x) OSSwapConstInt64(x)

/* Generic big endian to host endianess byte swapping functions. */

OS_INLINE
UInt
OSSwapBigToHostInt(
    UInt                          data
)
{
    return OSSwapInt(data);
}

OS_INLINE
UInt16
OSSwapBigToHostInt16(
    UInt16                        data
)
{
    return OSSwapInt16(data);
}

OS_INLINE
UInt32
OSSwapBigToHostInt32(
    UInt32                        data
)
{
    return OSSwapInt32(data);
}

OS_INLINE
UInt64
OSSwapBigToHostInt64(
    UInt64                        data
)
{
    return OSSwapInt64(data);
}

/* Little endian to host endianess byte swapping macros for constants. */

#define OSSwapLittleToHostConstInt16(x) (x)
#define OSSwapLittleToHostConstInt32(x) (x)
#define OSSwapLittleToHostConstInt64(x) (x)

/* Generic little endian to host endianess byte swapping functions. */

OS_INLINE
UInt
OSSwapLittleToHostInt(
    UInt                          data
)
{
    return data;
}

OS_INLINE
UInt16
OSSwapLittleToHostInt16(
    UInt16                        data
)
{
    return data;
}

OS_INLINE
UInt32
OSSwapLittleToHostInt32(
    UInt32                        data
)
{
    return data;
}

OS_INLINE
UInt64
OSSwapLittleToHostInt64(
    UInt64                        data
)
{
    return data;
}

#else
#error Unknown endianess.
#endif

#endif /* ! _OS_OSBYTEORDER_H */



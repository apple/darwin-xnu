/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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

#ifndef _I82557INLINE_H
#define _I82557INLINE_H

#include <libkern/OSByteOrder.h>
#include <libkern/OSAtomic.h>

//---------------------------------------------------------------------------
// CSR macros.

#define CSR_VALUE(name, x)	(((x) & name ## _MASK) >> name ## _SHIFT)
#define CSR_FIELD(name, x)	(((x) << name ## _SHIFT) & name ## _MASK)
#define CSR_MASK(name, x)	((x) << name ## _SHIFT)
#define BIT(x)				(1 << (x))

#define IOSync()            OSSynchronizeIO()

//---------------------------------------------------------------------------
// CSR read & write.

static inline
UInt8
OSReadLE8(volatile void * base)
{
	return *(volatile UInt8 *)base;
}

static inline
UInt16
OSReadLE16(volatile void * base)
{
	return OSReadLittleInt16(base, 0);
}

static inline
UInt32
OSReadLE32(volatile void * base)
{
	return OSReadLittleInt32(base, 0);
}

static inline
void
OSWriteLE8(volatile void * base, UInt8 data)
{
	*(volatile UInt8 *)base = data;
	IOSync();
}

static inline
void
OSWriteLE16(volatile void * base, UInt16 data)
{
	OSWriteLittleInt16(base, 0, data);
	IOSync();
}

static inline
void
OSWriteLE32(volatile void * base, UInt32 data)
{
	OSWriteLittleInt32(base, 0, data);
	IOSync();
}

//---------------------------------------------------------------------------
// Set/clear bit(s) macros.

#define __SET(n) \
static inline void \
OSSetLE##n(volatile void * base, UInt##n bit) \
{ \
	OSWriteLE##n(base, (OSReadLE##n(base) | (bit))); \
}

#define __CLR(n) \
static inline void \
OSClearLE##n(volatile void * base, UInt##n bit) \
{ \
	OSWriteLE##n(base, (OSReadLE##n(base) & ~(bit))); \
}
	
__SET(8)
__SET(16)
__SET(32)

__CLR(8)
__CLR(16)
__CLR(32)

#endif /* !_I82557INLINE_H */

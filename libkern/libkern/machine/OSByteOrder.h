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


#ifndef _OS_OSBYTEORDERMACHINE_H
#define _OS_OSBYTEORDERMACHINE_H

#include <libkern/OSBase.h>

/* Functions for byte reversed loads. */

OS_INLINE
UInt16
OSReadSwapInt16(
    volatile void               * base,
    UInt                          offset
)
{
    union sconv {
	UInt16 us;
	UInt8  uc[2];
    } *inp, outv;
    inp = (union sconv *)((UInt8 *)base + offset);
    outv.uc[0] = inp->uc[1];
    outv.uc[1] = inp->uc[0];
    return (outv.us);
}

OS_INLINE
UInt32
OSReadSwapInt32(
    volatile void               * base,
    UInt                          offset
)
{
    union lconv {
	UInt32 ul;
	UInt8  uc[4];
    } *inp, outv;
    inp = (union lconv *)((UInt8 *)base + offset);
    outv.uc[0] = inp->uc[3];
    outv.uc[1] = inp->uc[2];
    outv.uc[2] = inp->uc[1];
    outv.uc[3] = inp->uc[0];
    return (outv.ul);
}

OS_INLINE
UInt64
OSReadSwapInt64(
    volatile void               * base,
    UInt                          offset
)
{
    union llconv {
	UInt64 ull;
	UInt8  uc[8];
    } *inp, outv;
    inp = (union llconv *)((UInt8 *)base + offset);
    outv.uc[0] = inp->uc[7];
    outv.uc[1] = inp->uc[6];
    outv.uc[2] = inp->uc[5];
    outv.uc[3] = inp->uc[4];
    outv.uc[4] = inp->uc[3];
    outv.uc[5] = inp->uc[2];
    outv.uc[6] = inp->uc[1];
    outv.uc[7] = inp->uc[0];
    return (outv.ull);
}

OS_INLINE
UInt
OSReadSwapInt(
    volatile void               * base,
    UInt                          offset
)
{
    return (UInt)OSReadSwapInt32(base, offset);
}

/* Functions for byte reversed stores. */

OS_INLINE
void
OSWriteSwapInt16(
    volatile void               * base,
    UInt                          offset,
    UInt16                        data
)
{
    union sconv {
	UInt16 us;
	UInt8  uc[2];
    } *inp, *outp;
    inp  = (union sconv *)((UInt8 *)base + offset);
    outp = (union sconv *)&data;
    outp->uc[0] = inp->uc[1];
    outp->uc[1] = inp->uc[0];
}

OS_INLINE
void
OSWriteSwapInt32(
    volatile void               * base,
    UInt                          offset,
    UInt32                        data
)
{
    union lconv {
	UInt32 ul;
	UInt8  uc[4];
    } *inp, *outp;
    inp  = (union lconv *)((UInt8 *)base + offset);
    outp = (union lconv *)&data;
    outp->uc[0] = inp->uc[3];
    outp->uc[1] = inp->uc[2];
    outp->uc[2] = inp->uc[1];
    outp->uc[3] = inp->uc[0];
}

OS_INLINE
void
OSWriteSwapInt64(
    volatile void               * base,
    UInt                          offset,
    UInt64                        data
)
{
    union llconv {
	UInt64 ull;
	UInt8  uc[8];
    } *inp, *outp;
    inp = (union llconv *)((UInt8 *)base + offset);
    outp = (union llconv *)&data;
    outp->uc[0] = inp->uc[7];
    outp->uc[1] = inp->uc[6];
    outp->uc[2] = inp->uc[5];
    outp->uc[3] = inp->uc[4];
    outp->uc[4] = inp->uc[3];
    outp->uc[5] = inp->uc[2];
    outp->uc[6] = inp->uc[1];
    outp->uc[7] = inp->uc[0];
}

OS_INLINE
void
OSWriteSwapInt(
    volatile void               * base,
    UInt                          offset,
    UInt                          data
)
{
    OSWriteSwapInt32(base, offset, (UInt32)data);
}

/* Generic byte swapping functions. */

OS_INLINE
UInt16
OSSwapInt16(
    UInt16                        data
)
{
    UInt16 temp = data;
    return OSReadSwapInt16(&temp, 0);
}

OS_INLINE
UInt32
OSSwapInt32(
    UInt32                        data
)
{
    UInt32 temp = data;
    return OSReadSwapInt32(&temp, 0);
}

OS_INLINE
UInt64
OSSwapInt64(
    UInt64                        data
)
{
    UInt64 temp = data;
    return OSReadSwapInt64(&temp, 0);
}

OS_INLINE
UInt
OSSwapInt(
    UInt                          data
)
{
    UInt temp = data;
    return OSReadSwapInt(&temp, 0);
}

#endif /* ! _OS_OSBYTEORDERMACHINE_H */

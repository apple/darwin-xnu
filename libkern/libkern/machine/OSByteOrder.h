/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
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

#include <stdint.h>

#if !defined(OS_INLINE)
#        define OS_INLINE static inline
#endif

/* Functions for byte reversed loads. */

OS_INLINE
uint16_t
OSReadSwapInt16(
    volatile void               * base,
    uintptr_t                     offset
)
{
    union sconv {
	uint16_t us;
	uint8_t  uc[2];
    } *inp, outv;
    inp = (union sconv *)((uint8_t *)base + offset);
    outv.uc[0] = inp->uc[1];
    outv.uc[1] = inp->uc[0];
    return (outv.us);
}

OS_INLINE
uint32_t
OSReadSwapInt32(
    volatile void               * base,
    uintptr_t                     offset
)
{
    union lconv {
	uint32_t ul;
	uint8_t  uc[4];
    } *inp, outv;
    inp = (union lconv *)((uint8_t *)base + offset);
    outv.uc[0] = inp->uc[3];
    outv.uc[1] = inp->uc[2];
    outv.uc[2] = inp->uc[1];
    outv.uc[3] = inp->uc[0];
    return (outv.ul);
}

OS_INLINE
uint64_t
OSReadSwapInt64(
    volatile void               * base,
    uintptr_t                     offset
)
{
    union llconv {
	uint64_t ull;
	uint8_t  uc[8];
    } *inp, outv;
    inp = (union llconv *)((uint8_t *)base + offset);
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

/* Functions for byte reversed stores. */

OS_INLINE
void
OSWriteSwapInt16(
    volatile void               * base,
    uintptr_t                     offset,
    uint16_t                      data
)
{
    union sconv {
	uint16_t us;
	uint8_t  uc[2];
    } *inp, *outp;
    inp  = (union sconv *)((uint8_t *)base + offset);
    outp = (union sconv *)&data;
    outp->uc[0] = inp->uc[1];
    outp->uc[1] = inp->uc[0];
}

OS_INLINE
void
OSWriteSwapInt32(
    volatile void               * base,
    uintptr_t                     offset,
    uint32_t                      data
)
{
    union lconv {
	uint32_t ul;
	uint8_t  uc[4];
    } *inp, *outp;
    inp  = (union lconv *)((uint8_t *)base + offset);
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
    uintptr_t                     offset,
    uint64_t                      data
)
{
    union llconv {
	uint64_t ull;
	uint8_t  uc[8];
    } *inp, *outp;
    inp = (union llconv *)((uint8_t *)base + offset);
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

/* Generic byte swapping functions. */

OS_INLINE
uint16_t
_OSSwapInt16(
    uint16_t                      data
)
{
    uint16_t temp = data;
    return OSReadSwapInt16(&temp, 0);
}

OS_INLINE
uint32_t
_OSSwapInt32(
    uint32_t                      data
)
{
    uint32_t temp = data;
    return OSReadSwapInt32(&temp, 0);
}

OS_INLINE
uint64_t
_OSSwapInt64(
    uint64_t                        data
)
{
    uint64_t temp = data;
    return OSReadSwapInt64(&temp, 0);
}

#endif /* ! _OS_OSBYTEORDERMACHINE_H */

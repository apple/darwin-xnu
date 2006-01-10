/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 *
 */


#ifndef _OS_OSBYTEORDERPPC_H
#define _OS_OSBYTEORDERPPC_H

#include <stdint.h>

#if !defined(OS_INLINE)
#        define OS_INLINE static inline
#endif

/* Functions for byte reversed loads. */

OS_INLINE
uint16_t
OSReadSwapInt16(
    const volatile void               * base,
    uintptr_t                          offset
)
{
    uint16_t result;
    __asm__ volatile("lhbrx %0, %1, %2"
                     : "=r" (result)
                     : "b%"  (base), "r" (offset)
                     : "memory");
    return result;
}

OS_INLINE
uint32_t
OSReadSwapInt32(
    const volatile void               * base,
    uintptr_t                          offset
)
{
    uint32_t result;
    __asm__ volatile("lwbrx %0, %1, %2"
                     : "=r" (result)
                     : "b%"  (base), "r" (offset)
                     : "memory");
    return result;
}

OS_INLINE
uint64_t
OSReadSwapInt64(
    const volatile void               * base,
    uintptr_t                          offset
)
{
    const volatile uint64_t * inp;
    union ullc {
        uint64_t     ull;
        uint32_t     ul[2];
    } outv;

    inp = (const volatile uint64_t *)base;
    outv.ul[0] = OSReadSwapInt32(inp, offset + 4);
    outv.ul[1] = OSReadSwapInt32(inp, offset);
    return outv.ull;
}

/* Functions for byte reversed stores. */

OS_INLINE
void
OSWriteSwapInt16(
    volatile void               * base,
    uintptr_t                          offset,
    uint16_t                        data
)
{
    __asm__ volatile("sthbrx %0, %1, %2"
                     :
                     : "r" (data), "b%" (base), "r" (offset)
                     : "memory");
}

OS_INLINE
void
OSWriteSwapInt32(
    volatile void               * base,
    uintptr_t                          offset,
    uint32_t                        data
)
{
    __asm__ volatile("stwbrx %0, %1, %2"
                     :
                     : "r" (data), "b%" (base), "r" (offset)
                     : "memory" );
}

OS_INLINE
void
OSWriteSwapInt64(
    volatile void               * base,
    uintptr_t                          offset,
    uint64_t                        data
)
{
    volatile uint64_t * outp;
    volatile union ullc {
        uint64_t     ull;
        uint32_t     ul[2];
    } *inp;

    outp = (volatile uint64_t *)base;
    inp  = (volatile union ullc *)&data;
    OSWriteSwapInt32(outp, offset, inp->ul[1]);
    OSWriteSwapInt32(outp, offset + 4, inp->ul[0]);
}

/* Generic byte swapping functions. */

OS_INLINE
uint16_t
_OSSwapInt16(
    uint16_t                        data
)
{
    uint16_t temp = data;
    return OSReadSwapInt16(&temp, 0);
}

OS_INLINE
uint32_t
_OSSwapInt32(
    uint32_t                        data
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

#endif /* ! _OS_OSBYTEORDERPPC_H */

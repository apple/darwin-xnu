/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
 * Copyright (c) 1992 NeXT Computer, Inc.
 *
 * Byte ordering conversion.
 *
 * HISTORY
 *
 * 20 October 1992 ? at NeXT
 *	Added #ifdef wrapper to prevent multiple inclusions of this file.
 *
 * 8 October 1992 ? at NeXT
 *	Converted to NXxxx versions.  Condensed history.
 *
 * 18 May 1992 ? at NeXT
 *	Created.
 */

#ifndef	_ARCHITECTURE_BYTE_ORDER_H_
#define _ARCHITECTURE_BYTE_ORDER_H_
 
typedef unsigned long NXSwappedFloat;
typedef unsigned long long NXSwappedDouble;

#if defined (__ppc__)
#include "architecture/ppc/byte_order.h"
#elif defined (__i386__)
#include "architecture/i386/byte_order.h"
#else
#error architecture not supported
#endif

/*
 * Identify the byte order
 * of the current host.
 */

enum NXByteOrder {
    NX_UnknownByteOrder,
    NX_LittleEndian,
    NX_BigEndian
};

static __inline__
enum NXByteOrder
NXHostByteOrder(void)
{
    unsigned int	_x;
    
    _x = (NX_BigEndian << 24) | NX_LittleEndian;
        
    return ((enum NXByteOrder)*((unsigned char *)&_x));
}

/*
 * The predicated versions
 * are defined here in terms
 * of the unpredicated ones.
 */

#if	__BIG_ENDIAN__

static __inline__
unsigned short
NXSwapBigShortToHost(
    unsigned short	x
)
{
    return (x);
}

static __inline__
unsigned int
NXSwapBigIntToHost(
    unsigned int	x
)
{
    return (x);
}

static __inline__
unsigned long
NXSwapBigLongToHost(
    unsigned long	x
)
{
    return (x);
}

static __inline__
unsigned long long
NXSwapBigLongLongToHost(
    unsigned long long	x
)
{
    return (x);
}

#ifndef KERNEL

static __inline__
double
NXSwapBigDoubleToHost(
    NXSwappedDouble	x
)
{
    return NXConvertSwappedDoubleToHost(x);
}

static __inline__
float
NXSwapBigFloatToHost(
    NXSwappedFloat	x
)
{
    return NXConvertSwappedFloatToHost(x);
}

#endif /* KERNEL */

static __inline__
unsigned short
NXSwapHostShortToBig(
    unsigned short	x
)
{
    return (x);
}

static __inline__
unsigned int
NXSwapHostIntToBig(
    unsigned int	x
)
{
    return (x);
}

static __inline__
unsigned long
NXSwapHostLongToBig(
    unsigned long	x
)
{
    return (x);
}

static __inline__
unsigned long long
NXSwapHostLongLongToBig(
    unsigned long long	x
)
{
    return (x);
}

#ifndef KERNEL

static __inline__
NXSwappedDouble
NXSwapHostDoubleToBig(
    double		x
)
{
    return NXConvertHostDoubleToSwapped(x);
}

static __inline__
NXSwappedFloat
NXSwapHostFloatToBig(
    float		x
)
{
    return NXConvertHostFloatToSwapped(x);
}

#endif /* KERNEL */

static __inline__
unsigned short
NXSwapLittleShortToHost(
    unsigned short	x
)
{
    return (NXSwapShort(x));
}

static __inline__
unsigned int
NXSwapLittleIntToHost(
    unsigned int	x
)
{
    return (NXSwapInt(x));
}

static __inline__
unsigned long
NXSwapLittleLongToHost(
    unsigned long	x
)
{
    return (NXSwapLong(x));
}

static __inline__
unsigned long long
NXSwapLittleLongLongToHost(
    unsigned long long	x
)
{
    return (NXSwapLongLong(x));
}

#ifndef KERNEL

static __inline__
double
NXSwapLittleDoubleToHost(
    NXSwappedDouble	x
)
{
    return NXConvertSwappedDoubleToHost(NXSwapDouble(x));
}

static __inline__
float
NXSwapLittleFloatToHost(
    NXSwappedFloat	x
)
{
    return NXConvertSwappedFloatToHost(NXSwapFloat(x));
}

#endif /* KERNEL */

static __inline__
unsigned short
NXSwapHostShortToLittle(
    unsigned short	x
)
{
    return (NXSwapShort(x));
}

static __inline__
unsigned int
NXSwapHostIntToLittle(
    unsigned int	x
)
{
    return (NXSwapInt(x));
}

static __inline__
unsigned long
NXSwapHostLongToLittle(
    unsigned long	x
)
{
    return (NXSwapLong(x));
}

static __inline__
unsigned long long
NXSwapHostLongLongToLittle(
    unsigned long long	x
)
{
    return (NXSwapLongLong(x));
}

#ifndef KERNEL

static __inline__
NXSwappedDouble
NXSwapHostDoubleToLittle(
    double		x
)
{
    return NXSwapDouble(NXConvertHostDoubleToSwapped(x));
}

static __inline__
NXSwappedFloat
NXSwapHostFloatToLittle(
    float		x
)
{
    return NXSwapFloat(NXConvertHostFloatToSwapped(x));
}

#endif /* KERNEL */
#endif /*__BIG_ENDIAN__ */

#if	__LITTLE_ENDIAN__

static __inline__
unsigned short
NXSwapBigShortToHost(
    unsigned short	x
)
{
    return (NXSwapShort(x));
}

static __inline__
unsigned int
NXSwapBigIntToHost(
    unsigned int	x
)
{
    return (NXSwapInt(x));
}

static __inline__
unsigned long
NXSwapBigLongToHost(
    unsigned long	x
)
{
    return (NXSwapLong(x));
}

static __inline__
unsigned long long
NXSwapBigLongLongToHost(
    unsigned long long	x
)
{
    return (NXSwapLongLong(x));
}

static __inline__
double
NXSwapBigDoubleToHost(
    NXSwappedDouble	x
)
{
    return NXConvertSwappedDoubleToHost(NXSwapDouble(x));
}

static __inline__
float
NXSwapBigFloatToHost(
    NXSwappedFloat	x
)
{
    return NXConvertSwappedFloatToHost(NXSwapFloat(x));
}

static __inline__
unsigned short
NXSwapHostShortToBig(
    unsigned short	x
)
{
    return (NXSwapShort(x));
}

static __inline__
unsigned int
NXSwapHostIntToBig(
    unsigned int	x
)
{
    return (NXSwapInt(x));
}

static __inline__
unsigned long
NXSwapHostLongToBig(
    unsigned long	x
)
{
    return (NXSwapLong(x));
}

static __inline__
unsigned long long
NXSwapHostLongLongToBig(
    unsigned long long	x
)
{
    return (NXSwapLongLong(x));
}

static __inline__
NXSwappedDouble
NXSwapHostDoubleToBig(
    double		x
)
{
    return (NXSwapDouble(NXConvertHostDoubleToSwapped(x)));
}

static __inline__
NXSwappedFloat
NXSwapHostFloatToBig(
    float		x
)
{
    return (NXSwapFloat(NXConvertHostFloatToSwapped(x)));
}

static __inline__
unsigned short
NXSwapLittleShortToHost(
    unsigned short	x
)
{
    return (x);
}

static __inline__
unsigned int
NXSwapLittleIntToHost(
    unsigned int	x
)
{
    return (x);
}

static __inline__
unsigned long
NXSwapLittleLongToHost(
    unsigned long	x
)
{
    return (x);
}

static __inline__
unsigned long long
NXSwapLittleLongLongToHost(
    unsigned long long	x
)
{
    return (x);
}

static __inline__
double
NXSwapLittleDoubleToHost(
    NXSwappedDouble	x
)
{
    return NXConvertSwappedDoubleToHost(x);
}

static __inline__
float
NXSwapLittleFloatToHost(
    NXSwappedFloat	x
)
{
    return NXConvertSwappedFloatToHost(x);
}

static __inline__
unsigned short
NXSwapHostShortToLittle(
    unsigned short	x
)
{
    return (x);
}

static __inline__
unsigned int
NXSwapHostIntToLittle(
    unsigned int	x
)
{
    return (x);
}

static __inline__
unsigned long
NXSwapHostLongToLittle(
    unsigned long	x
)
{
    return (x);
}

static __inline__
unsigned long long
NXSwapHostLongLongToLittle(
    unsigned long long	x
)
{
    return (x);
}

static __inline__
NXSwappedDouble
NXSwapHostDoubleToLittle(
    double		x
)
{
    return NXConvertHostDoubleToSwapped(x);
}

static __inline__
NXSwappedFloat
NXSwapHostFloatToLittle(
    float		x
)
{
    return NXConvertHostFloatToSwapped(x);
}

#endif /* __LITTLE_ENDIAN__ */

#endif	/* _ARCHITECTURE_BYTE_ORDER_H_ */

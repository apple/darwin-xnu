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
 * Copyright (c) 1996 NeXT Software, Inc.
 *
 * Byte ordering conversion (for ppc).
 *
 * HISTORY
 *
 * 29-Dec-96  Umesh Vaishampayan  (umeshv@NeXT.com)
 *	Ported from m98k.
 *
 * 8 October 1992 ? at NeXT
 *	Converted to NXxxx versions.  Condensed history.
 *
 * 28 August 1992 Bruce Martin @NeXT
 *	Created.
 */

static __inline__
unsigned short
NXSwapShort(
    unsigned short	inv
)
{
    union sconv {
	unsigned short	us;
	unsigned char	uc[2];
    } *inp, outv;
    
    inp = (union sconv *)&inv;
    
    outv.uc[0] = inp->uc[1];
    outv.uc[1] = inp->uc[0];
    
    return (outv.us);
}

static __inline__
unsigned int
NXSwapInt(
    unsigned int	inv
)
{
    union iconv {
	unsigned int	ui;
	unsigned char	uc[4];
    } *inp, outv;
    
    inp = (union iconv *)&inv;
    
    outv.uc[0] = inp->uc[3];
    outv.uc[1] = inp->uc[2];
    outv.uc[2] = inp->uc[1];
    outv.uc[3] = inp->uc[0];
    
    return (outv.ui);
}

static __inline__
unsigned long
NXSwapLong(
    unsigned long	inv
)
{
    union lconv {
	unsigned long	ul;
	unsigned char	uc[4];
    } *inp, outv;
    
    inp = (union lconv *)&inv;
    
    outv.uc[0] = inp->uc[3];
    outv.uc[1] = inp->uc[2];
    outv.uc[2] = inp->uc[1];
    outv.uc[3] = inp->uc[0];
    
    return (outv.ul);
}

static __inline__
unsigned long long
NXSwapLongLong(
    unsigned long long	inv
)
{
    union llconv {
	unsigned long long	ull;
	unsigned char		uc[8];
    } *inp, outv;
    
    inp = (union llconv *)&inv;
    
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

#ifndef KERNEL

static __inline__ NXSwappedFloat
NXConvertHostFloatToSwapped(float x)
{
    union fconv {
	float number;
	NXSwappedFloat sf;
    };
    return ((union fconv *)&x)->sf;
}

static __inline__ float
NXConvertSwappedFloatToHost(NXSwappedFloat x)
{
    union fconv {
	float number;
	NXSwappedFloat sf;
    };
    return ((union fconv *)&x)->number;
}

static __inline__ NXSwappedDouble
NXConvertHostDoubleToSwapped(double x)
{
    union dconv {
	double number;
	NXSwappedDouble sd;
    };
    return ((union dconv *)&x)->sd;
}

static __inline__ double
NXConvertSwappedDoubleToHost(NXSwappedDouble x)
{
    union dconv {
	double number;
	NXSwappedDouble sd;
    };
    return ((union dconv *)&x)->number;
}

static __inline__ NXSwappedFloat
NXSwapFloat(NXSwappedFloat x)
{
    return NXSwapLong(x);
}

static __inline__ NXSwappedDouble
NXSwapDouble(NXSwappedDouble x)
{
    return NXSwapLongLong(x);
}

#endif /* ! KERNEL */

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

#include <libkern/OSAtomic.h>

enum {
	false	= 0,
	true	= 1
};
#define	NULL 0L


/*
 * atomic operations
 *	these are _the_ atomic operations, currently cast atop CompareAndSwap,
 *	which is implemented in assembler.  if we are worried about the cost of
 *	this layering (we shouldn't be), then all this stuff could be
 *	implemented in assembler, as it is in MacOS8/9
 *	(derived from SuperMario/NativeLibs/IO/DriverServices/Synchronization.s,
 *	which I wrote for NuKernel in a previous life with a different last name...)
 *
 * native Boolean	CompareAndSwap(UInt32 oldValue, UInt32 newValue, UInt32 * oldValuePtr);
 */

#ifndef __ppc__

SInt32	OSAddAtomic(SInt32 amount, SInt32 * value)
{
	SInt32	oldValue;
	SInt32	newValue;
	
	do {
		oldValue = *value;
		newValue = oldValue + amount;
	} while (! OSCompareAndSwap((UInt32) oldValue, (UInt32) newValue, (UInt32 *) value));
	
	return oldValue;
}

SInt32	OSIncrementAtomic(SInt32 * value)
{
	return OSAddAtomic(1, value);
}

SInt32	OSDecrementAtomic(SInt32 * value)
{
	return OSAddAtomic(-1, value);
}

#endif	/* !__ppc__ */

static UInt32	OSBitwiseAtomic(UInt32 and_mask, UInt32 or_mask, UInt32 xor_mask, UInt32 * value)
{
	UInt32	oldValue;
	UInt32	newValue;
	
	do {
		oldValue = *value;
		newValue = ((oldValue & and_mask) | or_mask) ^ xor_mask;
	} while (! OSCompareAndSwap(oldValue, newValue, value));
	
	return oldValue;
}

UInt32	OSBitAndAtomic(UInt32 mask, UInt32 * value)
{
	return OSBitwiseAtomic(mask, 0, 0, value);
}

UInt32	OSBitOrAtomic(UInt32 mask, UInt32 * value)
{
	return OSBitwiseAtomic((UInt32) -1, mask, 0, value);
}

UInt32	OSBitXorAtomic(UInt32 mask, UInt32 * value)
{
	return OSBitwiseAtomic((UInt32) -1, 0, mask, value);
}

static Boolean OSCompareAndSwap8(UInt8 oldValue8, UInt8 newValue8, UInt8 * value8)
{
	UInt32		mask        = 0x000000ff;
	UInt32		alignment   = ((UInt32) value8) & (sizeof(UInt32) - 1);
    UInt32      shiftValues = (24 << 24) | (16 << 16) | (8 << 8);
    int			shift       = (UInt32) *(((UInt8 *) &shiftValues) + alignment);
	UInt32 *	value32     = (UInt32 *) (value8 - alignment);
    UInt32      oldValue;
    UInt32      newValue;

    mask <<= shift;

    oldValue = *value32;
    oldValue = (oldValue & ~mask) | (oldValue8 << shift);
    newValue = (oldValue & ~mask) | (newValue8 << shift);

	return OSCompareAndSwap(oldValue, newValue, value32);
}

static Boolean	OSTestAndSetClear(UInt32 bit, Boolean wantSet, UInt8 * startAddress)
{
	UInt8		mask = 1;
	UInt8		oldValue;
	UInt8		wantValue;
	
	startAddress += (bit / 8);
	mask <<= (7 - (bit % 8));
	wantValue = wantSet ? mask : 0;
	
	do {
		oldValue = *startAddress;
		if ((oldValue & mask) == wantValue) {
			break;
		}
	} while (! OSCompareAndSwap8(oldValue, (oldValue & ~mask) | wantValue, startAddress));
	
	return (oldValue & mask) == wantValue;
}

Boolean	OSTestAndSet(UInt32 bit, UInt8 * startAddress)
{
	return OSTestAndSetClear(bit, true, startAddress);
}

Boolean	OSTestAndClear(UInt32 bit, UInt8 * startAddress)
{
	return OSTestAndSetClear(bit, false, startAddress);
}

void *	OSDequeueAtomic(void ** inList, SInt32 inOffset)
{
	void *	oldListHead;
	void *	newListHead;
	
	do {
		oldListHead = *inList;
		if (oldListHead == NULL) {
			break;
		}
		
		newListHead = *(void **) (((char *) oldListHead) + inOffset);
	} while (! OSCompareAndSwap((UInt32)oldListHead,
					(UInt32)newListHead, (UInt32 *)inList));
	
	return oldListHead;
}

void	OSEnqueueAtomic(void ** inList, void * inNewLink, SInt32 inOffset)
{
	void *	oldListHead;
	void *	newListHead = inNewLink;
	void **	newLinkNextPtr = (void **) (((char *) inNewLink) + inOffset);
	
	do {
		oldListHead = *inList;
		*newLinkNextPtr = oldListHead;
	} while (! OSCompareAndSwap((UInt32)oldListHead, (UInt32)newListHead,
					(UInt32 *)inList));
}

/*
 * silly unaligned versions
 */

SInt8	OSIncrementAtomic8(SInt8 * value)
{
	return OSAddAtomic8(1, value);
}

SInt8	OSDecrementAtomic8(SInt8 * value)
{
	return OSAddAtomic8(-1, value);
}

SInt8	OSAddAtomic8(SInt32 amount, SInt8 * value)
{
	SInt8	oldValue;
	SInt8	newValue;
	
	do {
		oldValue = *value;
		newValue = oldValue + amount;
	} while (! OSCompareAndSwap8((UInt8) oldValue, (UInt8) newValue, (UInt8 *) value));
	
	return oldValue;
}

static UInt8	OSBitwiseAtomic8(UInt32 and_mask, UInt32 or_mask, UInt32 xor_mask, UInt8 * value)
{
	UInt8	oldValue;
	UInt8	newValue;
	
	do {
		oldValue = *value;
		newValue = ((oldValue & and_mask) | or_mask) ^ xor_mask;
	} while (! OSCompareAndSwap8(oldValue, newValue, value));
	
	return oldValue;
}

UInt8	OSBitAndAtomic8(UInt32 mask, UInt8 * value)
{
	return OSBitwiseAtomic8(mask, 0, 0, value);
}

UInt8	OSBitOrAtomic8(UInt32 mask, UInt8 * value)
{
	return OSBitwiseAtomic8((UInt32) -1, mask, 0, value);
}

UInt8	OSBitXorAtomic8(UInt32 mask, UInt8 * value)
{
	return OSBitwiseAtomic8((UInt32) -1, 0, mask, value);
}

static Boolean OSCompareAndSwap16(UInt16 oldValue16, UInt16 newValue16, UInt16 * value16)
{
	UInt32		mask        = 0x0000ffff;
	UInt32		alignment   = ((UInt32) value16) & (sizeof(UInt32) - 1);
    UInt32      shiftValues = (16 << 24) | (16 << 16);
    UInt32		shift       = (UInt32) *(((UInt8 *) &shiftValues) + alignment);
	UInt32 *	value32     = (UInt32 *) (((UInt32) value16) - alignment);
    UInt32      oldValue;
    UInt32      newValue;

    mask <<= shift;

    oldValue = *value32;
    oldValue = (oldValue & ~mask) | (oldValue16 << shift);
    newValue = (oldValue & ~mask) | (newValue16 << shift);

	return OSCompareAndSwap(oldValue, newValue, value32);
}

SInt16	OSIncrementAtomic16(SInt16 * value)
{
	return OSAddAtomic16(1, value);
}

SInt16	OSDecrementAtomic16(SInt16 * value)
{
	return OSAddAtomic16(-1, value);
}

SInt16	OSAddAtomic16(SInt32 amount, SInt16 * value)
{
	SInt16	oldValue;
	SInt16	newValue;
	
	do {
		oldValue = *value;
		newValue = oldValue + amount;
	} while (! OSCompareAndSwap16((UInt16) oldValue, (UInt16) newValue, (UInt16 *) value));
	
	return oldValue;
}

static UInt16	OSBitwiseAtomic16(UInt32 and_mask, UInt32 or_mask, UInt32 xor_mask, UInt16 * value)
{
	UInt16	oldValue;
	UInt16	newValue;
	
	do {
		oldValue = *value;
		newValue = ((oldValue & and_mask) | or_mask) ^ xor_mask;
	} while (! OSCompareAndSwap16(oldValue, newValue, value));
	
	return oldValue;
}

UInt16	OSBitAndAtomic16(UInt32 mask, UInt16 * value)
{
	return OSBitwiseAtomic16(mask, 0, 0, value);
}

UInt16	OSBitOrAtomic16(UInt32 mask, UInt16 * value)
{
	return OSBitwiseAtomic16((UInt32) -1, mask, 0, value);
}

UInt16	OSBitXorAtomic16(UInt32 mask, UInt16 * value)
{
	return OSBitwiseAtomic16((UInt32) -1, 0, mask, value);
}


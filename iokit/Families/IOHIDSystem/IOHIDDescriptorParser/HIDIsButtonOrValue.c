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
/*
	File:		HIDIsButtonOrValue.c

	Contains:	xxx put contents here xxx

	Version:	xxx put version here xxx

	Copyright:	© 1999 by Apple Computer, Inc., all rights reserved.

	File Ownership:

		DRI:				xxx put dri here xxx

		Other Contact:		xxx put other contact here xxx

		Technology:			xxx put technology here xxx

	Writers:

		(BWS)	Brent Schorsch

	Change History (most recent first):

	  <USB3>	 11/1/99	BWS		[2405720]  We need a better check for 'bit padding' items,
									rather than just is constant. We will check to make sure the
									item is constant, and has no usage, or zero usage.
	  <USB2>	  3/5/99	BWS		[2311366]  HIDIsButton should screen out constants (at least
									until other functions, like HIDGetButtons, are fixed to be able
									to properly skip constants)
	  <USB1>	  3/5/99	BWS		first checked in
*/

#include "HIDLib.h"

/*
 *-----------------------------------------------------------------------------
 *
 * HIDIsButton - Is the data button(s)?
 *
 *	 Input:
 *			  ptReportItem			- Input/Output/Feature
 *	 Output:
 *	 Returns:
 *			  Boolean
 *
 *-----------------------------------------------------------------------------
*/
Boolean HIDIsButton(HIDReportItem *ptReportItem, HIDPreparsedDataRef preparsedDataRef)
{
	HIDPreparsedDataPtr ptPreparsedData = (HIDPreparsedDataPtr) preparsedDataRef;

/*
 *	Disallow Null Pointers
*/
	if (ptReportItem==NULL)
		return false;
/*
 *	Remove items that are constant and have no usage
 */
	if ((ptReportItem->dataModes & kHIDDataConstantBit) == kHIDDataConstant)
	{
		// if has no usages, then bit filler
		if (ptReportItem->usageItemCount == 0)
			return false;
		
		// also check to see if there is a usage, but it is zero
		
		// if the first usage item is range, then check that one
		// (we will not worry about report items with multiple zero usages, 
		//  as I dont think that is a case that makes sense)
		if (ptReportItem->firstUsageItem < ptPreparsedData->usageItemCount)
		{
			HIDP_UsageItem * ptUsageItem = &ptPreparsedData->usageItems[ptReportItem->firstUsageItem];
			
			// if it is a range usage, with both zero usages 
			if ((ptUsageItem->isRange && ptUsageItem->usageMinimum == 0 && ptUsageItem->usageMaximum == 0) &&
				// or not a range, and zero usage
				(!ptUsageItem->isRange && ptUsageItem->usage == 0))
				// then this is bit filler
				return false;
		}
	}

/*
 *	Arrays and 1-bit Variables
*/
	return (((ptReportItem->dataModes & kHIDDataArrayBit) == kHIDDataArray)
	   || (ptReportItem->globals.reportSize == 1));
}

/*
 *-----------------------------------------------------------------------------
 *
 * HIDIsVariable - Is the data variable(s)?
 *
 *	 Input:
 *			  ptReportItem			- Input/Output/Feature
 *	 Output:
 *	 Returns:
 *			  Boolean
 *
 *-----------------------------------------------------------------------------
*/
Boolean HIDIsVariable(HIDReportItem *ptReportItem, HIDPreparsedDataRef preparsedDataRef)
{
	HIDPreparsedDataPtr ptPreparsedData = (HIDPreparsedDataPtr) preparsedDataRef;

/*
 *	Disallow Null Pointers
*/
	if (ptReportItem==NULL)
		return false;

/*
 *	Remove items that are constant and have no usage
 */
	if ((ptReportItem->dataModes & kHIDDataConstantBit) == kHIDDataConstant)
	{
		// if has no usages, then bit filler
		if (ptReportItem->usageItemCount == 0)
			return false;
		
		// also check to see if there is a usage, but it is zero
		
		// if the first usage item is range, then check that one
		// (we will not worry about report items with multiple zero usages, 
		//  as I dont think that is a case that makes sense)
		if (ptReportItem->firstUsageItem < ptPreparsedData->usageItemCount)
		{
			HIDP_UsageItem * ptUsageItem = &ptPreparsedData->usageItems[ptReportItem->firstUsageItem];
			
			// if it is a range usage, with both zero usages 
			if ((ptUsageItem->isRange && ptUsageItem->usageMinimum == 0 && ptUsageItem->usageMaximum == 0) &&
				// or not a range, and zero usage
				(!ptUsageItem->isRange && ptUsageItem->usage == 0))
				// then this is bit filler
				return false;
		}
	}

/*
 *	Multi-bit Variables
*/
	return (((ptReportItem->dataModes & kHIDDataArrayBit) != kHIDDataArray)
	   && (ptReportItem->globals.reportSize != 1));
}

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
	File:		HIDCountDescriptorItems.c

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

	  <USB1>	  3/5/99	BWS		first checked in
*/

#include "HIDLib.h"

//#include <stdlib.h>

/*
 *------------------------------------------------------------------------------
 *
 * HIDCountDescriptorItems
 *
 *	 Input:
 *			  ptDescriptor			- Descriptor Pointer Structure
 *			  ptPreparsedData		- The PreParsedData Structure
 *	 Output:
 *			  ptPreparsedData		- The PreParsedData Structure
 *	 Returns:
 *			  kHIDSuccess		   - Success
 *			  kHIDNullPointerErr	  - Argument, Pointer was Null
 *
 *------------------------------------------------------------------------------
*/
OSStatus HIDCountDescriptorItems(HIDReportDescriptor *ptDescriptor, HIDPreparsedDataPtr ptPreparsedData)
{
	OSStatus iStatus;
	ByteCount iSpaceRequired;
	HIDItem *ptItem;
	Byte *pMem;
/*
 *	Initialize Counters
*/
	int collectionCount	 = 1;
	int reportItemCount	 = 0;
	int iUsages		  = 0;
	int iUsageRanges  = 0;
	int iStrings	  = 0;
	int iStringRanges = 0;
	int iDesigs		  = 0;
	int iDesigRanges  = 0;
	int reportCount		 = 1;
	int globalsNesting = 0;
	int iMaxGlobalsNesting = 0;
	int collectionNesting = 0;
	int iMaxCollectionNesting = 0;
/*
 *	Disallow NULL Pointers
*/
	if ((ptDescriptor == NULL) || (ptPreparsedData == NULL))
		return kHIDNullPointerErr;
/*
 *	Initialize the memory allocation pointer
*/
	ptPreparsedData->rawMemPtr = NULL;
/*
 *	Initialize the Descriptor Pointer Structure
*/
	ptDescriptor->index = 0;
	ptItem = &ptDescriptor->item;
/*
 *	Count various items in the descriptor
*/
	while ((iStatus = HIDNextItem(ptDescriptor)) == kHIDSuccess)
	{
		switch (ptItem->itemType)
		{
			case kHIDTypeMain:
				switch (ptItem->tag)
				{
					case kHIDTagCollection:
						collectionCount++;
						collectionNesting++;
						if (collectionNesting > iMaxCollectionNesting)
							iMaxCollectionNesting = collectionNesting;
						break;
					case kHIDTagEndCollection:
						if (collectionNesting-- == 0)
							return kHIDInvalidPreparsedDataErr;
						break;
					case kHIDTagInput:
					case kHIDTagOutput:
					case kHIDTagFeature:
						reportItemCount++;
						break;
				}
				break;
			case kHIDTypeGlobal:
				switch (ptItem->tag)
				{
					case kHIDTagReportID:
						reportCount++;
						break;
					case kHIDTagPush:
						globalsNesting++;
						if (globalsNesting > iMaxGlobalsNesting)
							iMaxGlobalsNesting = globalsNesting;
						break;
					case kHIDTagPop:
						globalsNesting--;
						if (globalsNesting < 0)
							return kHIDInvalidPreparsedDataErr;
						break;
				}
				break;
			case kHIDTypeLocal:
				switch (ptItem->tag)
				{
					case kHIDTagUsage:
						iUsages++;
						break;
					case kHIDTagUsageMinimum:
					case kHIDTagUsageMaximum:
						iUsageRanges++;
						break;
					case kHIDTagStringIndex:
						iStrings++;
						break;
					case kHIDTagStringMinimum:
					case kHIDTagStringMaximum:
						iStringRanges++;
						break;
					case kHIDTagDesignatorIndex:
						iDesigs++;
						break;
					case kHIDTagDesignatorMinimum:
					case kHIDTagDesignatorMaximum:
						iDesigRanges++;
						break;
				}
		}
	}
/*
 *	Disallow malformed descriptors
*/
	if ((collectionNesting != 0)
	 || (collectionCount == 1)
	 || (reportItemCount == 0)
	 || ((iUsageRanges & 1) == 1)
	 || ((iStringRanges & 1) == 1)
	 || ((iDesigRanges & 1) == 1))
		return kHIDInvalidPreparsedDataErr;
/*
 *	Summarize the Indices and Ranges
*/
	iUsages += (iUsageRanges/2);
	iStrings += (iStringRanges/2);
	iDesigs += (iDesigRanges/2);
/*
 *	Calculate the space needed for the structures
*/
	iSpaceRequired = (sizeof(HIDCollection) * collectionCount)
				   + (sizeof(HIDReportItem) * reportItemCount)
				   + (sizeof(HIDReportSizes) * reportCount)
				   + (sizeof(HIDP_UsageItem) * iUsages)
				   + (sizeof(HIDStringItem) * iStrings)
				   + (sizeof(HIDDesignatorItem) * iDesigs)
				   + (sizeof(int) * iMaxCollectionNesting)
				   + (sizeof(HIDGlobalItems) * iMaxGlobalsNesting);
	pMem = PoolAllocateResident(iSpaceRequired, kShouldClearMem);
	
	if (pMem == NULL)
		return kHIDNotEnoughMemoryErr;
	ptPreparsedData->rawMemPtr = pMem;
	ptPreparsedData->numBytesAllocated = iSpaceRequired;
/*
 *	Allocate space to the various structures
*/
	ptPreparsedData->collections = (HIDCollection *) pMem;
	ptPreparsedData->collectionCount = 0;
	pMem += (sizeof(HIDCollection) * collectionCount);
	ptPreparsedData->reportItems = (HIDReportItem *) pMem;
	ptPreparsedData->reportItemCount = 0;
	pMem += (sizeof(HIDReportItem) * reportItemCount);
	ptPreparsedData->reports = (HIDReportSizes *) pMem;
	ptPreparsedData->reportCount = 0;
	pMem += (sizeof(HIDReportSizes) * reportCount);
	ptPreparsedData->usageItems = (HIDP_UsageItem *) pMem;
	ptPreparsedData->usageItemCount = 0;
	pMem += (sizeof(HIDP_UsageItem) * iUsages);
	ptPreparsedData->stringItems = (HIDStringItem *) pMem;
	ptPreparsedData->stringItemCount = 0;
	pMem += (sizeof(HIDStringItem) * iStrings);
	ptPreparsedData->desigItems = (HIDDesignatorItem *) pMem;
	ptPreparsedData->desigItemCount = 0;
	pMem += (sizeof(HIDDesignatorItem) * iDesigs);
	ptDescriptor->collectionStack = (SInt32 *) pMem;
	ptDescriptor->collectionNesting = 0;
	pMem += (sizeof(SInt32) * iMaxCollectionNesting);
	ptDescriptor->globalsStack = (HIDGlobalItems *) pMem;
	ptDescriptor->globalsNesting = 0;
	if (iStatus == kHIDEndOfDescriptorErr)
		return kHIDSuccess;
	return iStatus;
}

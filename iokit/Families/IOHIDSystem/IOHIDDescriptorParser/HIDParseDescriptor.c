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
	File:		HIDParseDescriptor.c

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

//#include <stdio.h>
/*
 *------------------------------------------------------------------------------
 *
 * HIDParseDescriptor - Fill in the PreparsedData structures
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
 *	NOTE: HIDCountDescriptorItems MUST have been called to set up the
 *		  array pointers in the HIDPreparsedData structure!
 *
 *------------------------------------------------------------------------------
*/
OSStatus HIDParseDescriptor(HIDReportDescriptor *ptDescriptor, HIDPreparsedDataPtr ptPreparsedData)
{
	OSStatus iStatus;
	HIDItem *ptItem;
	HIDCollection *ptCollection;
	HIDReportSizes *ptReport;
/*
 *	Disallow NULL Pointers
*/
	if ((ptDescriptor == NULL) || (ptPreparsedData == NULL))
		return kHIDNullPointerErr;
/*
 *	Initialize Counters
*/
	ptPreparsedData->collectionCount = 1;
	ptPreparsedData->reportItemCount = 0;
	ptPreparsedData->reportCount = 1;
	ptPreparsedData->usageItemCount = 0;
	ptPreparsedData->stringItemCount = 0;
	ptPreparsedData->desigItemCount = 0;
/*
 *	Initialize the Descriptor Data
*/
	ptDescriptor->index = 0;
	ptDescriptor->collectionNesting = 0;
	ptDescriptor->globalsNesting = 0;
	ptDescriptor->firstUsageItem = 0;
	ptDescriptor->firstStringItem = 0;
	ptDescriptor->firstDesigItem = 0;
	ptDescriptor->parent = 0;
	ptDescriptor->sibling = 0;
	ptDescriptor->globals.usagePage = 0;
	ptDescriptor->globals.logicalMinimum = 0;
	ptDescriptor->globals.logicalMaximum = 0;
	ptDescriptor->globals.physicalMinimum = 0;
	ptDescriptor->globals.physicalMaximum = 0;
	ptDescriptor->globals.unitExponent = 0;
	ptDescriptor->globals.units = 0;
	ptDescriptor->globals.reportSize = 0;
	ptDescriptor->globals.reportID = 0;
	ptDescriptor->globals.reportCount = 0;
	ptDescriptor->globals.reportIndex = 0;
	ptDescriptor->haveUsageMin = false;
	ptDescriptor->haveUsageMax = false;
	ptDescriptor->haveStringMin = false;
	ptDescriptor->haveStringMax = false;
	ptDescriptor->haveDesigMin = false;
	ptDescriptor->haveDesigMax = false;
	ptItem = &ptDescriptor->item;
/*
 *	Initialize the virtual collection
*/
	ptCollection = ptPreparsedData->collections;
	ptCollection->data = 0;
	ptCollection->usagePage = 0;
	ptCollection->firstUsageItem = 0;
	ptCollection->usageItemCount = 0;
	ptCollection->firstReportItem = 0;
	ptCollection->reportItemCount = 0;
	ptCollection->parent = 0;
	ptCollection->children = 0;
	ptCollection->firstChild = 0;
	ptCollection->nextSibling = 0;
/*
 *	Initialize the default report
*/
	ptReport = ptPreparsedData->reports;
	ptReport->reportID = 0;
	ptReport->inputBitCount = 0;
	ptReport->outputBitCount = 0;
	ptReport->featureBitCount = 0;

/*
 *	Parse the Descriptor
*/
	while ((iStatus = HIDNextItem(ptDescriptor)) == kHIDSuccess)
	{
		switch (ptItem->itemType)
		{
			case kHIDTypeMain:
				iStatus = HIDProcessMainItem(ptDescriptor,ptPreparsedData);
				break;
			case kHIDTypeGlobal:
				iStatus = HIDProcessGlobalItem(ptDescriptor,ptPreparsedData);
				break;
			case kHIDTypeLocal:
				iStatus = HIDProcessLocalItem(ptDescriptor,ptPreparsedData);
				break;
		}
		if (iStatus != kHIDSuccess)
			return iStatus;
	}
	if (iStatus == kHIDEndOfDescriptorErr)
		iStatus = kHIDSuccess;
/*
 *	Update the virtual collection
*/
	ptCollection = ptPreparsedData->collections;
	ptCollection->reportItemCount = ptPreparsedData->reportItemCount;
/*
 *	Mark the PreparsedData initialized
*/
	return iStatus;
}

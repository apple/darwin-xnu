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
	File:		HIDProcessCollection.c

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

/*
 *------------------------------------------------------------------------------
 *
 * HIDProcessCollection - Process a Collection MainItem
 *
 *	 Input:
 *			  ptDescriptor			- The Descriptor Structure
 *			  ptPreparsedData		- The PreParsedData Structure
 *	 Output:
 *			  ptDescriptor			- The Descriptor Structure
 *			  ptPreparsedData		- The PreParsedData Structure
 *	 Returns:
 *			  kHIDSuccess		   - Success
 *			  kHIDNullPointerErr	  - Argument, Pointer was Null
 *
 *------------------------------------------------------------------------------
*/
OSStatus HIDProcessCollection(HIDReportDescriptor *ptDescriptor, HIDPreparsedDataPtr ptPreparsedData)
{
	HIDCollection *collections;
	HIDCollection *ptCollection;
	int parent;
	int iCollection;
/*
 *	Disallow NULL Pointers
*/
	if ((ptDescriptor == NULL) || (ptPreparsedData == NULL))
		return kHIDNullPointerErr;
/*
 *	Initialize the new Collection Structure
*/
	iCollection = ptPreparsedData->collectionCount++;
	collections = ptPreparsedData->collections;
	ptCollection = &collections[iCollection];
	ptCollection->data = ptDescriptor->item.unsignedValue;
	ptCollection->firstUsageItem = ptDescriptor->firstUsageItem;
	ptCollection->usageItemCount = ptPreparsedData->usageItemCount - ptDescriptor->firstUsageItem;
	ptDescriptor->firstUsageItem = ptPreparsedData->usageItemCount;
	ptCollection->children = 0;
	ptCollection->nextSibling = ptDescriptor->sibling;
	ptDescriptor->sibling = 0;
	ptCollection->firstChild = 0;
	ptCollection->usagePage = ptDescriptor->globals.usagePage;
	ptCollection->firstReportItem = ptPreparsedData->reportItemCount;
/*
 *	Set up the relationship with the parent Collection
*/
	parent = ptDescriptor->parent;
	ptCollection->parent = parent;
	collections[parent].firstChild = iCollection;
	collections[parent].children++;
	ptDescriptor->parent = iCollection;
/*
 *	Save the parent Collection Information on the stack
*/
	ptDescriptor->collectionStack[ptDescriptor->collectionNesting++] = parent;
	return kHIDSuccess;
}

/*
 *------------------------------------------------------------------------------
 *
 * HIDProcessEndCollection - Process an EndCollection MainItem
 *
 *	 Input:
 *			  ptDescriptor			- The Descriptor Structure
 *			  ptPreparsedData		- The PreParsedData Structure
 *	 Output:
 *			  ptPreparsedData		- The PreParsedData Structure
 *	 Returns:
 *			  kHIDSuccess		   - Success
 *			  kHIDNullPointerErr	  - Argument, Pointer was Null
 *
 *------------------------------------------------------------------------------
*/
OSStatus HIDProcessEndCollection(HIDReportDescriptor *ptDescriptor, HIDPreparsedDataPtr ptPreparsedData)
{
	HIDCollection *ptCollection;
	int iCollection;
/*
 *	Remember the number of ReportItem MainItems in this Collection
*/
	ptCollection = &ptPreparsedData->collections[ptDescriptor->parent];
	ptCollection->reportItemCount = ptPreparsedData->reportItemCount - ptCollection->firstReportItem;
/*
 *	Restore the parent Collection Data
*/
	iCollection = ptDescriptor->collectionStack[--ptDescriptor->collectionNesting];
	ptDescriptor->sibling = ptDescriptor->parent;
	ptDescriptor->parent = iCollection;
	return kHIDSuccess;
}

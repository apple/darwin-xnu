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
	File:		HIDGetCollectionNodes.c

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
 * HIDGetCollectionNodes - Get the Collections Database
 *
 *	 Input:
 *			  ptLinkCollectionNodes		  - Node Array provided by caller
 *			  piLinkCollectionNodesLength - Maximum Nodes
 *	 Output:
 *			  piLinkCollectionNodesLength - Actual number of Nodes
 *	 Returns:
 *			  kHIDSuccess		  - Success
 *			  kHIDNullPointerErr	 - Argument, Pointer was Null
 *			  HidP_NotEnoughRoom   - More Nodes than space for them
 *
 *------------------------------------------------------------------------------
*/
OSStatus HIDGetCollectionNodes(HIDCollectionNodePtr ptLinkCollectionNodes,
										UInt32 *piLinkCollectionNodesLength,
										HIDPreparsedDataRef preparsedDataRef)
{
	HIDPreparsedDataPtr ptPreparsedData = (HIDPreparsedDataPtr) preparsedDataRef;
	HIDCollectionNodePtr ptLink;
	HIDCollection *ptCollection;
	HIDP_UsageItem *ptFirstUsageItem;
	int iMaxNodes;
	int collectionCount;
	int firstUsageItem;
	int i;
/*
 *	Disallow Null Pointers
*/
	if ((ptLinkCollectionNodes == NULL)
	 || (piLinkCollectionNodesLength == NULL)
	 || (ptPreparsedData == NULL))
		return kHIDNullPointerErr;
	if (ptPreparsedData->hidTypeIfValid != kHIDOSType)
		return kHIDInvalidPreparsedDataErr;
/*
 *	Remember the size of the output array
*/
	iMaxNodes = *piLinkCollectionNodesLength;
	collectionCount = ptPreparsedData->collectionCount;
	*piLinkCollectionNodesLength = collectionCount;
/*
 *	Report if there's not enough room
*/
	if (collectionCount > iMaxNodes)
		return kHIDBufferTooSmallErr;
/*
 *	Copy the nodes
*/
	for (i=0; i<collectionCount; i++)
	{
		ptCollection = &ptPreparsedData->collections[i];
		ptLink = &ptLinkCollectionNodes[i];
		firstUsageItem = ptCollection->firstUsageItem;
		ptFirstUsageItem = &ptPreparsedData->usageItems[firstUsageItem];
		ptLink->collectionUsage = ptFirstUsageItem->usage;
		ptLink->collectionUsagePage = ptCollection->usagePage;
		ptLink->parent = ptCollection->parent;
		ptLink->numberOfChildren = ptCollection->children;
		ptLink->nextSibling = ptCollection->nextSibling;
		ptLink->firstChild = ptCollection->firstChild;
	}
/*
 *	Report if there wasn't enough space
*/
	if (iMaxNodes < ptPreparsedData->collectionCount)
		return kHIDBufferTooSmallErr;
	return kHIDSuccess;
}

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
	File:		HIDUsageAndPageFromIndex.c

	Contains:	xxx put contents here xxx

	Version:	xxx put version here xxx

	Copyright:	© 1999-2000 by Apple Computer, Inc., all rights reserved.

	File Ownership:

		DRI:				xxx put dri here xxx

		Other Contact:		xxx put other contact here xxx

		Technology:			xxx put technology here xxx

	Writers:

		(KH)	Keithen Hayenga
		(BWS)	Brent Schorsch

	Change History (most recent first):

	  <USB2>	12/12/00	KH		range count off by 1.
	  <USB1>	  3/5/99	BWS		first checked in
*/

#include "HIDLib.h"

/*
 *------------------------------------------------------------------------------
 *
 * HIDUsageAndPageFromIndex
 *
 *	 Input:
 *			  ptPreparsedData		- The Preparsed Data
 *			  ptReportItem			- The Report Item
 *			  index				   - The usage Index
 *			  ptUsageAndPage		- The usage And Page
 *	 Output:
 *	 Returns:
 *
 *------------------------------------------------------------------------------
*/
void HIDUsageAndPageFromIndex (HIDPreparsedDataRef preparsedDataRef,
								 HIDReportItem *ptReportItem, UInt32 index,
								 HIDUsageAndPage *ptUsageAndPage)
{
	HIDPreparsedDataPtr ptPreparsedData = (HIDPreparsedDataPtr) preparsedDataRef;
	HIDP_UsageItem *ptUsageItem = NULL;
	int iUsageItem;
	int iUsages;
	int i;

/*
 *	Disallow NULL Pointers
*/
	if ((ptUsageAndPage == NULL) || (ptReportItem == NULL) || (ptPreparsedData == NULL))
	{
		ptUsageAndPage->usagePage = 0;
		return;	// kHIDNullPointerErr;
	}

/*
 *	Index through the usage Items for this ReportItem
*/
	iUsageItem = ptReportItem->firstUsageItem;
	for (i=0; i<ptReportItem->usageItemCount; i++)
	{
/*
 *		Each usage Item is either a usage or a usage range
*/
		ptUsageItem = &ptPreparsedData->usageItems[iUsageItem++];
		if (ptUsageItem->isRange)
		{
/*
 *			For usage Ranges
 *			  If the index is in the range
 *				then return the usage
 *			  Otherwise adjust the index by the size of the range
*/
			iUsages = ptUsageItem->usageMaximum - ptUsageItem->usageMinimum;
			if (iUsages < 0)
				iUsages = -iUsages;
			iUsages++;		// Add off by one adjustment AFTER sign correction.
			if (iUsages > index)
			{
				ptUsageAndPage->usagePage = ptUsageItem->usagePage;
				ptUsageAndPage->usage = ptUsageItem->usageMinimum + index;
				return;
			}
			index -= iUsages;
		}
		else
		{
/*
 *			For Usages
 *			If the index is zero
 *			  then return this usage
 *			Otherwise one less to index through
*/
			if (index-- == 0)
			{
				ptUsageAndPage->usagePage = ptUsageItem->usagePage;
				ptUsageAndPage->usage = ptUsageItem->usage;
				return;
			}
		}
	}
	if (ptUsageItem != NULL)
	{
		ptUsageAndPage->usagePage = ptUsageItem->usagePage;
		if (ptUsageItem->isRange)
			ptUsageAndPage->usage = ptUsageItem->usageMaximum;
		else
			ptUsageAndPage->usage = ptUsageItem->usage;
	}
}

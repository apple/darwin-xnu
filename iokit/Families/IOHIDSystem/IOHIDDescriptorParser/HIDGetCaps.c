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
	File:		HIDGetCaps.c

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

	  <USB3>	 4/21/00	KH		Added HIDGetCapabilities to be consistant with
									HIDGetButtonCapabilities, HIDGetSpecificButtonCapabilities,
									HIDGetValueCapabilities, and HIDGetSpecificValueCapabilities.
	  <USB2>	 11/1/99	BWS		[2405720]  We need a better check for 'bit padding' items,
									rather than just is constant. We will check to make sure the
									item is constant, and has no usage, or zero usage. This means we
									need to pass an additional parameter to some internal functions
	  <USB1>	  3/5/99	BWS		first checked in
*/

#include "HIDLib.h"

/*
 *------------------------------------------------------------------------------
 *
 * HIDP_GetCaps
 *
 *	 Input:
 *			  ptPreparsedData		- Pre-Parsed Data
 *			  ptCapabilities		- Pointer to caller-provided structure
 *	 Output:
 *			  ptCapabilities		- Capabilities data
 *	 Returns:
 *
 *------------------------------------------------------------------------------
*/
OSStatus HIDGetCaps(HIDPreparsedDataRef preparsedDataRef, HIDCapsPtr ptCapabilities)
{
	HIDPreparsedDataPtr ptPreparsedData = (HIDPreparsedDataPtr) preparsedDataRef;
	HIDCollection *ptCollection;
	HIDReportItem *ptReportItem;
	HIDReportSizes *ptReport;
	int iFirstUsage;
	int i;
/*
 *	Disallow Null Pointers
*/

	if ((ptPreparsedData == NULL) || (ptCapabilities == NULL))
		return kHIDNullPointerErr;
	if (ptPreparsedData->hidTypeIfValid != kHIDOSType)
		return kHIDInvalidPreparsedDataErr;
/*
 *	Copy the capabilities to the user
 *	Collection Capabilities
*/

	ptCollection = &ptPreparsedData->collections[1];
	ptCapabilities->usagePage = ptCollection->usagePage;
	iFirstUsage = ptCollection->firstUsageItem;
	ptCapabilities->usage = ptPreparsedData->usageItems[iFirstUsage].usage;
	ptCapabilities->numberCollectionNodes = ptPreparsedData->collectionCount;
/*
 *	Report Capabilities Summary
*/

	ptCapabilities->inputReportByteLength = 0;
	ptCapabilities->outputReportByteLength = 0;
	ptCapabilities->featureReportByteLength = 0;
	for (i=0; i<ptPreparsedData->reportCount; i++)
	{
		ptReport = &ptPreparsedData->reports[i];
		if (ptCapabilities->inputReportByteLength < ptReport->inputBitCount)
			ptCapabilities->inputReportByteLength = ptReport->inputBitCount;
		if (ptCapabilities->outputReportByteLength < ptReport->outputBitCount)
			ptCapabilities->outputReportByteLength = ptReport->outputBitCount;
		if (ptCapabilities->featureReportByteLength < ptReport->featureBitCount)
			ptCapabilities->featureReportByteLength = ptReport->featureBitCount;
	}
	ptCapabilities->inputReportByteLength = (ptCapabilities->inputReportByteLength + 7) /8;
	ptCapabilities->outputReportByteLength = (ptCapabilities->outputReportByteLength + 7)/8;
	ptCapabilities->featureReportByteLength = (ptCapabilities->featureReportByteLength + 7)/8;
/*
 *	Sum the capabilities types
*/

	ptCapabilities->numberInputButtonCaps = 0;
	ptCapabilities->numberInputValueCaps = 0;
	ptCapabilities->numberOutputButtonCaps = 0;
	ptCapabilities->numberOutputValueCaps = 0;
	ptCapabilities->numberFeatureButtonCaps = 0;
	ptCapabilities->numberFeatureValueCaps = 0;
	for (i=0; i<ptPreparsedData->reportItemCount; i++)
	{
		ptReportItem = &ptPreparsedData->reportItems[i];
		switch (ptReportItem->reportType)
		{
			case kHIDInputReport:
				if (HIDIsButton(ptReportItem, preparsedDataRef))
					ptCapabilities->numberInputButtonCaps += ptReportItem->usageItemCount;
				else if (HIDIsVariable(ptReportItem, preparsedDataRef))
					ptCapabilities->numberInputValueCaps += ptReportItem->usageItemCount;
				break;
			case kHIDOutputReport:
				if (HIDIsButton(ptReportItem, preparsedDataRef))
					ptCapabilities->numberOutputButtonCaps += ptReportItem->usageItemCount;
				else if (HIDIsVariable(ptReportItem, preparsedDataRef))
					ptCapabilities->numberOutputValueCaps += ptReportItem->usageItemCount;
				break;
			case kHIDFeatureReport:
				if (HIDIsButton(ptReportItem, preparsedDataRef))
					ptCapabilities->numberFeatureButtonCaps += ptReportItem->usageItemCount;
				else if (HIDIsVariable(ptReportItem, preparsedDataRef))
					ptCapabilities->numberFeatureValueCaps += ptReportItem->usageItemCount;
				break;
		}
	}
	return kHIDSuccess;
}


/*
 *------------------------------------------------------------------------------
 *
 * HIDGetCapabilities	This is exactly the same as HIDGetCaps. It does take a
 *						HIDCapabiitiesPtr instead of a HIDCapsPtr, but the structures
 *						of each are exactly the same. The only reason this call 
 *						exists seperately is for uniformity of naming with 
 *						HIDGetValueCapabilities, HIDGetSpecificButtonCapabilities, etc.
 *
 *	 Input:
 *			  ptPreparsedData		- Pre-Parsed Data
 *			  ptCapabilities		- Pointer to caller-provided structure
 *	 Output:
 *			  ptCapabilities		- Capabilities data
 *	 Returns:
 *
 *------------------------------------------------------------------------------
*/
OSStatus HIDGetCapabilities(HIDPreparsedDataRef preparsedDataRef, HIDCapabilitiesPtr ptCapabilities)
{
	HIDPreparsedDataPtr ptPreparsedData = (HIDPreparsedDataPtr) preparsedDataRef;
	HIDCollection *ptCollection;
	HIDReportItem *ptReportItem;
	HIDReportSizes *ptReport;
	int iFirstUsage;
	int i;
/*
 *	Disallow Null Pointers
*/

	if ((ptPreparsedData == NULL) || (ptCapabilities == NULL))
		return kHIDNullPointerErr;
	if (ptPreparsedData->hidTypeIfValid != kHIDOSType)
		return kHIDInvalidPreparsedDataErr;
/*
 *	Copy the capabilities to the user
 *	Collection Capabilities
*/

	ptCollection = &ptPreparsedData->collections[1];
	ptCapabilities->usagePage = ptCollection->usagePage;
	iFirstUsage = ptCollection->firstUsageItem;
	ptCapabilities->usage = ptPreparsedData->usageItems[iFirstUsage].usage;
	ptCapabilities->numberCollectionNodes = ptPreparsedData->collectionCount;
/*
 *	Report Capabilities Summary
*/

	ptCapabilities->inputReportByteLength = 0;
	ptCapabilities->outputReportByteLength = 0;
	ptCapabilities->featureReportByteLength = 0;
	for (i=0; i<ptPreparsedData->reportCount; i++)
	{
		ptReport = &ptPreparsedData->reports[i];
		if (ptCapabilities->inputReportByteLength < ptReport->inputBitCount)
			ptCapabilities->inputReportByteLength = ptReport->inputBitCount;
		if (ptCapabilities->outputReportByteLength < ptReport->outputBitCount)
			ptCapabilities->outputReportByteLength = ptReport->outputBitCount;
		if (ptCapabilities->featureReportByteLength < ptReport->featureBitCount)
			ptCapabilities->featureReportByteLength = ptReport->featureBitCount;
	}
	ptCapabilities->inputReportByteLength = (ptCapabilities->inputReportByteLength + 7) /8;
	ptCapabilities->outputReportByteLength = (ptCapabilities->outputReportByteLength + 7)/8;
	ptCapabilities->featureReportByteLength = (ptCapabilities->featureReportByteLength + 7)/8;
/*
 *	Sum the capabilities types
*/

	ptCapabilities->numberInputButtonCaps = 0;
	ptCapabilities->numberInputValueCaps = 0;
	ptCapabilities->numberOutputButtonCaps = 0;
	ptCapabilities->numberOutputValueCaps = 0;
	ptCapabilities->numberFeatureButtonCaps = 0;
	ptCapabilities->numberFeatureValueCaps = 0;
	for (i=0; i<ptPreparsedData->reportItemCount; i++)
	{
		ptReportItem = &ptPreparsedData->reportItems[i];
		switch (ptReportItem->reportType)
		{
			case kHIDInputReport:
				if (HIDIsButton(ptReportItem, preparsedDataRef))
					ptCapabilities->numberInputButtonCaps += ptReportItem->usageItemCount;
				else if (HIDIsVariable(ptReportItem, preparsedDataRef))
					ptCapabilities->numberInputValueCaps += ptReportItem->usageItemCount;
				break;
			case kHIDOutputReport:
				if (HIDIsButton(ptReportItem, preparsedDataRef))
					ptCapabilities->numberOutputButtonCaps += ptReportItem->usageItemCount;
				else if (HIDIsVariable(ptReportItem, preparsedDataRef))
					ptCapabilities->numberOutputValueCaps += ptReportItem->usageItemCount;
				break;
			case kHIDFeatureReport:
				if (HIDIsButton(ptReportItem, preparsedDataRef))
					ptCapabilities->numberFeatureButtonCaps += ptReportItem->usageItemCount;
				else if (HIDIsVariable(ptReportItem, preparsedDataRef))
					ptCapabilities->numberFeatureValueCaps += ptReportItem->usageItemCount;
				break;
		}
	}
	return kHIDSuccess;
}

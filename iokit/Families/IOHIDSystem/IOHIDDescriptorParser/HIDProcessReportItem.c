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
	File:		HIDProcessReportItem.c

	Contains:	xxx put contents here xxx

	Version:	xxx put version here xxx

	Copyright:	© 1999-2000 by Apple Computer, Inc., all rights reserved.

	File Ownership:

		DRI:				xxx put dri here xxx

		Other Contact:		xxx put other contact here xxx

		Technology:			xxx put technology here xxx

	Writers:

		(KH)	Keithen Hayenga
		(DF)	David Ferguson
		(BWS)	Brent Schorsch

	Change History (most recent first):

	 <USB10>	 1/11/00	KH		Tweaking last fix. For logical maximum, limit shifting into the
									sign bit only for report sizes of 32 bits or greater.
	  <USB9>	 1/10/00	DF		re-do last change (better fix).
	  <USB8>	 1/10/00	DF		do proper logical range test for 32-bit report items.
	  <USB7>	  4/7/99	BWS		Add support for reversed report items
	  <USB6>	 3/20/99	BWS		Oops, strict error checking does not work if there is no error.
									We should only return error if it is not noErr
	  <USB5>	 3/17/99	BWS		[2314839]  Added flags field to HIDPreparsedData which is set in
									new parameter to HIDOpenReportDescriptor. We check the
									StrictErrorCheck bit to determine whether we return errors or
									just try to work around problems we find
	  <USB4>	  3/7/99	BWS		[2311413]  Do not error check min/max ranges for constants
	  <USB3>	  3/7/99	BWS		[2311412]  We need to handle the cases where physical min/max is
									either (0/0) which is valid according to the spec, and means to
									use the logical min/max, and the invalid case, that some devices
									exibit, which has (0/-1) which we will treat the same,
	  <USB2>	  3/5/99	BWS		[2311359]  HIDProcessReportItem does not initialize startBit
									field of HIDReportItem!
	  <USB1>	  3/5/99	BWS		first checked in
*/

#include "HIDLib.h"

/*
 *------------------------------------------------------------------------------
 *
 * HIDProcessReportItem - Process a Report Item MainItem
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
OSStatus HIDProcessReportItem(HIDReportDescriptor *ptDescriptor, HIDPreparsedDataPtr ptPreparsedData)
{
	OSStatus error = noErr;
	HIDReportItem *ptReportItem;
	HIDReportSizes *ptReport;
	int iBits;
/*
 *	Disallow NULL Pointers
*/

	if ((ptDescriptor == NULL) || (ptPreparsedData == NULL))
		return kHIDNullPointerErr;
/*
 *	Begin to initialize the new Report Item structure
*/

	ptReportItem = &ptPreparsedData->reportItems[ptPreparsedData->reportItemCount++];
	ptReportItem->dataModes = ptDescriptor->item.unsignedValue;
	ptReportItem->globals = ptDescriptor->globals;
	ptReportItem->flags = 0;
	
/*
 *	Reality Check on the Report Main Item
*/
	// Don't check ranges for constants (MS Sidewinder, for one, does not reset)
	//if (!(ptReportItem->dataModes & kHIDDataConstantBit)) // don't think we need this anymore
	{
		// Determine the maximum signed value for a given report size.
		// (Don't allow shifting into sign bit.)
		SInt32 posSize = (ptReportItem->globals.reportSize >= 32) ? 
						31 : ptReportItem->globals.reportSize;
		SInt32 realMax = (1<<posSize) - 1;
		
		if (ptReportItem->globals.logicalMinimum > realMax)
		{
			error = kHIDBadLogicalMinimumErr;
			ptReportItem->globals.logicalMinimum = 0;
		}
		if (ptReportItem->globals.logicalMaximum > realMax)
		{
			if (error == noErr)
				error = kHIDBadLogicalMaximumErr;
			ptReportItem->globals.logicalMaximum = realMax;
		}
		if (ptReportItem->globals.logicalMinimum > ptReportItem->globals.logicalMaximum)
		{
			SInt32	temp;
			if (error == noErr)
				error = kHIDInvertedLogicalRangeErr;
			
			// mark as a 'reversed' item
			ptReportItem->flags |= kHIDReportItemFlag_Reversed;
			
			temp = ptReportItem->globals.logicalMaximum;
			ptReportItem->globals.logicalMaximum = ptReportItem->globals.logicalMinimum;
			ptReportItem->globals.logicalMinimum = temp;
		}
	}
	
	// check to see if we got half a range (we don't need to fix this, since 'isRange' will be false
	if ((error == noErr) && (ptDescriptor->haveUsageMin || ptDescriptor->haveUsageMax))
		error = kHIDUnmatchedUsageRangeErr;
	if ((error == noErr) && (ptDescriptor->haveStringMin || ptDescriptor->haveStringMax))
		error = kHIDUnmatchedStringRangeErr;
	if ((error == noErr) && (ptDescriptor->haveDesigMin || ptDescriptor->haveDesigMax))
		error = kHIDUnmatchedDesignatorRangeErr;
	
	// if the physical min/max are out of wack, use the logical values
	if (ptReportItem->globals.physicalMinimum >= ptReportItem->globals.physicalMaximum)
	{
		// equal to each other is not an error, just means to use the logical values
		if ((error == noErr) && 
			(ptReportItem->globals.physicalMinimum > ptReportItem->globals.physicalMaximum))
			error = kHIDInvertedPhysicalRangeErr;

		ptReportItem->globals.physicalMinimum = ptReportItem->globals.logicalMinimum;
		ptReportItem->globals.physicalMaximum = ptReportItem->globals.logicalMaximum;
	}
	
	// if strict error checking is true, return any errors
	if (error != noErr && ptPreparsedData->flags & kHIDFlag_StrictErrorChecking)
		return error;
	
/*
 *	Continue to initialize the new Report Item structure
*/

	ptReportItem->parent = ptDescriptor->parent;
	ptReportItem->firstUsageItem = ptDescriptor->firstUsageItem;
	ptDescriptor->firstUsageItem = ptPreparsedData->usageItemCount;
	ptReportItem->usageItemCount = ptPreparsedData->usageItemCount - ptReportItem->firstUsageItem;
	ptReportItem->firstStringItem = ptDescriptor->firstStringItem;
	ptDescriptor->firstStringItem = ptPreparsedData->stringItemCount;
	ptReportItem->stringItemCount = ptPreparsedData->stringItemCount - ptReportItem->firstStringItem;
	ptReportItem->firstDesigItem = ptDescriptor->firstDesigItem;
	ptDescriptor->firstDesigItem = ptPreparsedData->desigItemCount;
	ptReportItem->desigItemCount = ptPreparsedData->desigItemCount - ptReportItem->firstDesigItem;
/*
 *	Update the Report by the size of this item
*/

	ptReport = &ptPreparsedData->reports[ptReportItem->globals.reportIndex];
	iBits = ptReportItem->globals.reportSize * ptReportItem->globals.reportCount;
	switch (ptDescriptor->item.tag)
	{
		case kHIDTagFeature:
			ptReportItem->reportType = kHIDFeatureReport;
            ptReportItem->startBit = ptReport->featureBitCount;
			ptReport->featureBitCount += iBits;
			break;
		case kHIDTagOutput:
			ptReportItem->reportType = kHIDOutputReport;
            ptReportItem->startBit = ptReport->outputBitCount;
			ptReport->outputBitCount += iBits;
			break;
		case kHIDTagInput:
			ptReportItem->reportType = kHIDInputReport;
            ptReportItem->startBit = ptReport->inputBitCount;
			ptReport->inputBitCount += iBits;
			break;
		default:
			ptReportItem->reportType = kHIDUnknownReport;
            ptReportItem->startBit = 0;
			break;
	}
	return kHIDSuccess;
}

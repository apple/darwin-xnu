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
	File:		HIDInitReport.c

	Contains:	HIDInitReport call for HID Library

	Version:	1.0d1

	Copyright:	© 2000 by Apple Computer, Inc., all rights reserved.

	File Ownership:

		DRI:				David Ferguson

		Other Contact:		Keithen Hayenga

		Technology:			technologies, usb

	Writers:


	Change History (most recent first):

*/

#include "HIDLib.h"

/*
 *------------------------------------------------------------------------------
 *
 * HIDInitReport - Initialize report to have report ID and, if possible, null values
 *					so that setting any one value will not inadvertantly change
 *					other items in the same report to 0.
 *
 *	 Input:
 *			  reportType			- HIDP_Input, HIDP_Output, HIDP_Feature
 *			  reportID				- Report ID
 *			  preparsedDataRef		- Pre-Parsed Data
 *			  report				- An HID Report
 *			  reportLength			- The length of the Report
 *	 Output:
 *			  report				- Initialized HID Report
 *	 Returns:
 *
 *------------------------------------------------------------------------------
*/
OSStatus HIDInitReport
					   (HIDReportType			reportType,
						UInt8					reportID,
						HIDPreparsedDataRef		preparsedDataRef,
						void *					report,
						ByteCount				reportLength)
{
	HIDPreparsedDataPtr	ptPreparsedData = (HIDPreparsedDataPtr) preparsedDataRef;
	HIDReportItem *		ptReportItem;
	ByteCount			minLength;
	UInt8 *				iPtr;
	int					iR;
	OSStatus			iStatus = kHIDSuccess;
	
	//Disallow Null Pointers

	if ((ptPreparsedData == NULL) || (report == NULL))
		return kHIDNullPointerErr;
	if (ptPreparsedData->hidTypeIfValid != kHIDOSType)
		return kHIDInvalidPreparsedDataErr;
	if (reportLength == 0)
		return kHIDReportSizeZeroErr;
	
	// Report length must also be great enough to hold report.
	HIDGetReportLength(reportType, reportID, &minLength, preparsedDataRef);
	// I know that HIDGetReportLength repeats the first tests above, but it
	// was easier to duplicate that logic than build test cases for the other
	// errors that could be returned by HIDGetReportLength that i don't care
	// about.

	if (reportLength < minLength)
		return kHIDInvalidReportLengthErr;
	
	// First byte of report must be reportID. Unless it is report ID 0;
	// in which case 0 is just the first byte of the following initialization.

	iPtr = (UInt8 *)report;
	*iPtr++ = reportID;
	
	// Default initialization is to zero out all values.
	
	for (iR = 1; iR < reportLength; iR++)
	{
		*iPtr++ = 0;
	}

	// Search through all report items to see if they belong in this report.
	
	for (iR = 0; iR < ptPreparsedData->reportItemCount; iR++)
	{
		ptReportItem = &ptPreparsedData->reportItems[iR];
		
		if (ptReportItem->reportType == reportType &&
			ptReportItem->globals.reportID == reportID)
		{
			// Is there a null value for this item?
			SInt32 nullValue;
			SInt32 bitwiseMax;
			SInt32 bitwiseMin;
			SInt32 bitSize;
			Boolean isSigned;

			// The HID spec "highly encourages" 0 to be a null value, so test
			// for it first.
			
			if ( 0 < ptReportItem->globals.logicalMinimum || 
				0 > ptReportItem->globals.logicalMaximum)
				continue;		// Default initialization was good enough.
				
			nullValue = 0;		// We can test if this changes below.
			
			// Determine the maximum and minimum signed numbers that will fit into this
			// item and then see if they are outside the bounds of what the descriptor
			// says are the allowed min and max.
			// What the possible ranges are depends upon if the device is accepting
			// signed or unsigned numbers. I haven't noticed that information in the
			// preparsed data, so i'll take an educated guess. If logicalMinimum is 
			// less than 0 it must be using signed numbers. Conversly, logicalMaximum
			// using the high order bit of it's bitfield would indicate unsigned. In 
			// case of a tie, we'll say signed since that agrees with the SInt32 that
			// logicalMinimum and logicalMaximum are stored in.
			
			// The mininimum 8 bit value would be 0x80 (-128). To be -128 in UInt32 = 0xFFFFFF80.
			// This just happens to also set the high order bit that we need to test in the
			// maximum value using the high order bit, such as 64, 0x80.
			bitSize = ptReportItem->globals.reportSize;
			bitwiseMin = -1 << (bitSize - 1);
			
			// Logical max should not have any bit set higher than the high order bit of our
			// size, so anding with 0xFFFFFF80 should only test field's high order bit.
			isSigned = (ptReportItem->globals.logicalMinimum < 0) || 
						!(ptReportItem->globals.logicalMaximum & bitwiseMin);
			
			// If signed, we test from 0x80 to 0x7F. If not, 0x00 to 0xFF.
			if (isSigned)
			{
				--bitSize;	// Don't let max value flow into sign bit.
			}
			else
			{
				bitwiseMin = 0;
			}
			
			// Our compare uses SInt32, so even for unsigned values, we can't let them
			// overflow into real sign bit. (So 0x80000000 is not a legal HID positive number.)
			if (bitSize  >= 32) bitSize = 31;

			// The theory behind this greatly simplified set of compares. 1. I was worried about
			// the case of a 4 bit field with a max = 4 and a min = -2. Then if i chose a value
			// of 7 for my bitwise max, it could also be -1 for min, which would make it a null
			// positive value, but a legal negative one. But while HID specs say a field can be
			// either a signed or unsigned value, i don't see how it can be both, so i haven't
			// allowed for such a situation. 2. I originally built logic that tested for signed
			// or unsigned fields as above, but had seperate logic based on what would happen
			// after that. I have resolved that logic down to the main part below and the only
			// exceptions i had are now filtered out into the 2 lines of "if (signed)" etc. above.

			bitwiseMax = (1<<bitSize) - 1;

			if (bitwiseMax > ptReportItem->globals.logicalMaximum)
			{
				nullValue = bitwiseMax;
			}
			else
			{
				if (bitwiseMin < ptReportItem->globals.logicalMinimum)
				{
					nullValue = bitwiseMin;
				}
			}
			
			// If we found a null value, store it into the proper place in the report.
			
			if (nullValue != 0)
			{
				// Write out the data.
				SInt32 iStart;
				int lR;
				OSStatus tempStatus;
				
				HIDPreProcessRIValue(ptReportItem, &nullValue);

				// For a reportItem, there can be multiple identical usages.
				for (lR = 0; lR < ptReportItem->usageItemCount; lR++)
				{
					iStart = ptReportItem->startBit
						  + (ptReportItem->globals.reportSize * lR);
					tempStatus = HIDPutData(report, reportLength, iStart,
										   ptReportItem->globals.reportSize, nullValue);
					if (tempStatus)
						iStatus = tempStatus;	// Pass on any bad news.
				}
			}
		} // == reportID
	} // reportItemCount

	return iStatus;
}

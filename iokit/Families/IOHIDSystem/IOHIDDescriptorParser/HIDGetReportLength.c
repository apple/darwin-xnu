/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
	File:		HIDGetReportLength.c

	Contains:	xxx put contents here xxx

	Version:	xxx put version here xxx

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
 * HIDGetReportLength - Get the length of a report
 *
 *	 Input:
 *				reportType			- HIDP_Input, HIDP_Output, HIDP_Feature
 *				reportID			- Desired Report
 *				preparsedDataRef	- opaque Pre-Parsed Data
 *	 Output:
 *				reportLength		- The length of the Report
 *	 Returns:
 *				status				kHIDNullPointerErr, kHIDInvalidPreparsedDataErr,
 *									kHIDUsageNotFoundErr
 *
 *------------------------------------------------------------------------------
*/
OSStatus HIDGetReportLength(HIDReportType reportType,
							UInt8 reportID,
							ByteCount * reportLength,
							HIDPreparsedDataRef preparsedDataRef)
{
	HIDPreparsedDataPtr ptPreparsedData = (HIDPreparsedDataPtr)preparsedDataRef;
	ByteCount dataLength = 0;
	OSStatus iStatus = kHIDUsageNotFoundErr;
	int iR;

	// Disallow Null Pointers.

	if (ptPreparsedData == NULL || reportLength == NULL)
		return kHIDNullPointerErr;
	if (ptPreparsedData->hidTypeIfValid != kHIDOSType)
		return kHIDInvalidPreparsedDataErr;
		
	// Go through the Reports.

	for (iR = 0; iR < ptPreparsedData->reportCount; iR++)
	{
		if (ptPreparsedData->reports[iR].reportID == reportID)
		{
			switch(reportType)
			{
				case kHIDInputReport:
					dataLength = (ptPreparsedData->reports[iR].inputBitCount + 7)/8;
					break;
				case kHIDOutputReport:
					dataLength = (ptPreparsedData->reports[iR].outputBitCount + 7)/8;
					break;
				case kHIDFeatureReport:
					dataLength = (ptPreparsedData->reports[iR].featureBitCount + 7)/8;
					break;
				default:
					return kHIDInvalidReportTypeErr;
			}
			break;
		}
	}

	// If the reportID > 0, there must be 1 byte for reportID, so total report must be > 1.
	// (Would come into play if we had input report 3, but searched for ouput report 3
	// that didn't exist.)

	if ((reportID == 0) && (dataLength > 0) || dataLength > 1)
	{
		iStatus = noErr;
	}
	else
	{
		dataLength = 0;		// Ignore report that had id, but no data.
	}
	
	*reportLength = dataLength;

	return iStatus;
}

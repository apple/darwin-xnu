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
	File:		HIDGetButtonsOnPage.c

	Contains:	xxx put contents here xxx

	Version:	xxx put version here xxx

	Copyright:	© 1999 by Apple Computer, Inc., all rights reserved.

	File Ownership:

		DRI:				xxx put dri here xxx

		Other Contact:		xxx put other contact here xxx

		Technology:			xxx put technology here xxx

	Writers:

		(KH)	Keithen Hayenga
		(BWS)	Brent Schorsch

	Change History (most recent first):

	  <USB5>	 3/24/00	KH		Complex report descriptors could lead to reporting
									kHIDUsageNotFoundErr's as kHIDIncompatibleReportErr's instead.
	  <USB4>	 11/1/99	BWS		[2405720]  We need a better check for 'bit padding' items,
									rather than just is constant. We will check to make sure the
									item is constant, and has no usage, or zero usage. This means we
									need to pass an additional parameter to some internal functions
	  <USB3>	 5/26/99	BWS		We are not checking the usage page for bitmapped buttons! This
									caused the Wingman Extreme to get the tilt button on the user
									page confused with the first button on the button page.
	  <USB2>	  4/7/99	BWS		Add support for reversed report items
	  <USB1>	  3/5/99	BWS		first checked in
*/

#include "HIDLib.h"

/*
 *------------------------------------------------------------------------------
 *
 * HIDGetButtonsOnPage - Get the state of the buttons for a Page
 *
 *	 Input:
 *			  reportType		   - HIDP_Input, HIDP_Output, HIDP_Feature
 *			  usagePage			   - Page Criteria or zero
 *			  iCollection			- Collection Criteria or zero
 *			  piUsageList			- Usages for pressed buttons
 *			  piUsageListLength		- Max entries in UsageList
 *			  ptPreparsedData		- Pre-Parsed Data
 *			  psReport				- An HID Report
 *			  iReportLength			- The length of the Report
 *	 Output:
 *			  piValue				- Pointer to usage Value
 *	 Returns:
 *
 *------------------------------------------------------------------------------
*/
OSStatus HIDGetButtonsOnPage(HIDReportType reportType,
						   HIDUsage usagePage,
						   UInt32 iCollection,
						   HIDUsage *piUsageList,
						   UInt32 *piUsageListLength,
						   HIDPreparsedDataRef preparsedDataRef,
						   void *psReport,
						   UInt32 iReportLength)
{
	HIDPreparsedDataPtr ptPreparsedData = (HIDPreparsedDataPtr) preparsedDataRef;
	HIDUsageAndPage tUsageAndPage;
	HIDCollection *ptCollection;
	HIDReportItem *ptReportItem;
	OSStatus iStatus;
	int iR, iE;
	long iValue;
	int iStart;
	int iMaxUsages;
	int iReportItem;
	Boolean bIncompatibleReport = false;
	Boolean butNotReally = false;
/*
 *	Disallow Null Pointers
*/
	if ((ptPreparsedData == NULL)
	 || (piUsageList == NULL)
	 || (piUsageListLength == NULL)
	 || (psReport == NULL))
		return kHIDNullPointerErr;
	if (ptPreparsedData->hidTypeIfValid != kHIDOSType)
		return kHIDInvalidPreparsedDataErr;
/*
 *	The Collection must be in range
*/
	if ((iCollection < 0) || (iCollection >= ptPreparsedData->collectionCount))
		return kHIDBadParameterErr;
/*
 *	Save the size of the list
*/
	iMaxUsages = *piUsageListLength;
	*piUsageListLength = 0;
/*
 *	Search only the scope of the Collection specified
 *	Go through the ReportItems
 *	Filter on ReportType and usagePage
*/
	ptCollection = &ptPreparsedData->collections[iCollection];
	for (iR=0; iR<ptCollection->reportItemCount; iR++)
	{
		iReportItem = ptCollection->firstReportItem + iR;
		ptReportItem = &ptPreparsedData->reportItems[iReportItem];
		if (HIDIsButton(ptReportItem, preparsedDataRef))
		{
/*
 *			This may be the proper data to get
 *			Let's check for the proper Report ID, Type, and Length
*/
			iStatus = HIDCheckReport(reportType,preparsedDataRef,ptReportItem,
									   psReport,iReportLength);
/*
 *			The Report ID or Type may not match.
 *			This may not be an error (yet)
*/
			if (iStatus == kHIDIncompatibleReportErr)
				bIncompatibleReport = true;
			else if (iStatus != kHIDSuccess)
				return iStatus;
			else
			{
				butNotReally = true;
/*
 *				Save Array Buttons
*/
				iStart = ptReportItem->startBit;
				for (iE=0; iE<ptReportItem->globals.reportCount; iE++)
				{
					if ((ptReportItem->dataModes & kHIDDataArrayBit) == kHIDDataArray)
					{
						iStatus = HIDGetData(psReport, iReportLength, iStart,
									 ptReportItem->globals.reportSize,
									 &iValue, false);
						if (!iStatus)
							iStatus = HIDPostProcessRIValue (ptReportItem, &iValue);
						HIDUsageAndPageFromIndex(preparsedDataRef,
									 ptReportItem,
									 iValue-ptReportItem->globals.logicalMinimum,
									 &tUsageAndPage);
						iStart += ptReportItem->globals.reportSize;
						if (usagePage == tUsageAndPage.usagePage)
						{
							if (*piUsageListLength >= iMaxUsages)
								return kHIDBufferTooSmallErr;
							piUsageList[(*piUsageListLength)++] = iValue;
						}
					}
/*
 *					Save Bitmapped Buttons
*/
					else
					{
						iStatus = HIDGetData(psReport, iReportLength, iStart, 1, &iValue, false);
						if (!iStatus)
							iStatus = HIDPostProcessRIValue (ptReportItem, &iValue);
						iStart++;
						if (!iStatus && iValue != 0)
						{
							HIDUsageAndPageFromIndex(preparsedDataRef,ptReportItem,iE,&tUsageAndPage);
							if (usagePage == tUsageAndPage.usagePage)
							{
								if (*piUsageListLength >= iMaxUsages)
									return kHIDBufferTooSmallErr;
								piUsageList[(*piUsageListLength)++] = tUsageAndPage.usage;
							}
						}
					}
				}
			}
		}
	}
/*
 *	If nothing was returned then change the status
*/
	if (*piUsageListLength == 0)
	{
		// If any of the report items were not the right type, we have set the bIncompatibleReport flag.
		// However, if any of the report items really were the correct type, we have done our job of checking
		// and really didn't find a usage. Don't let the bIncompatibleReport flag wipe out our valid test.
		if (bIncompatibleReport && !butNotReally)
			return kHIDIncompatibleReportErr;
		return kHIDUsageNotFoundErr;
	}
	return kHIDSuccess;
}

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
	File:		HIDScaleUsageValue.c

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
 * HIDScaleUsageValueIn
 *
 *	 Input:
 *			  ptReportItem			- The ReportItem in which the data resides
 *			  iValue				- The unscaled data
 *			  piScaledValue			- The scaled value
 *	 Output:
 *			  piScaledValue			- The scaled value
 *	 Returns:
 *			  kHIDSuccess
 *
 *------------------------------------------------------------------------------
*/
OSStatus HIDScaleUsageValueIn (HIDReportItem *ptReportItem, UInt32 iValue, SInt32 *piScaledValue)
{
	long int lData;
	long int lDeltaL;
	long int lDeltaP;
	long int lL, lP;
	long int lScaledData;
	long int lLMin, lLMax;
/*
 *	Disallow Null Pointers
*/
	if ((ptReportItem == NULL) || (piScaledValue == NULL))
		return kHIDNullPointerErr;
/*
 *	Convert the data to Long Integer
*/
	lData = iValue;
/*
 *	range check the Logical Value
*/
	lLMax = ptReportItem->globals.logicalMaximum;
	lLMin = ptReportItem->globals.logicalMinimum;
	if ((lData < lLMin) || (lData > lLMax))
	{
		if ((ptReportItem->dataModes & kHIDDataNullStateBit) == kHIDDataNullState)
			return kHIDNullStateErr;
		return kHIDValueOutOfRangeErr;
	}
/*
 *	(PhysicalValue - PhysicalMinimum)/(PhysicalMaximum - PhysicalMinimum)
 *	= (LogicalValue - LogicalMinimum)/(LogicalMaximum - LogicalMinimum)
 *
 *	Calculate the ranges
 *	Zero ranges are invalid!
 *	  lDeltaL = (LogicalMaximum - LogicalMinimum)
 *	  lDeltaP = (PhysicalMaximum - PhysicalMinimum)
*/
	lDeltaL = lLMax - lLMin;
	lDeltaP = ptReportItem->globals.physicalMaximum - ptReportItem->globals.physicalMinimum;
	if ((lDeltaL == 0) || (lDeltaP == 0))
		return kHIDBadLogPhysValuesErr;
/*
 *	(PhysicalValue - PhysicalMinimum)/lDeltaP
 *	= (LogicalValue - LogicalMinimum)/lDeltaL
 *	lL = (LogicalValue - LogicalMinimum)
*/
	lL = lData - ptReportItem->globals.logicalMinimum;
/*
 *	(PhysicalValue - PhysicalMinimum)/lDeltaP = lL/lDeltaL
 *	(PhysicalValue - PhysicalMinimum) = (lDeltaP * lL)/lDeltaL
 *	lP = (PhysicalValue - PhysicalMinimum) = (lDeltaP * lL)/lDeltaL
*/
	lP = (lL* lDeltaP)/lDeltaL;
/*
 *	lP = (PhysicalValue - PhysicalMinimum)
 *	PhysicalValue = lP + PhysicalMinimum;
*/
	lScaledData = lP + ptReportItem->globals.physicalMinimum;
	*piScaledValue = (int) lScaledData;
	return kHIDSuccess;
}

/*
 *------------------------------------------------------------------------------
 *
 * HIDScaleUsageValueOut
 *
 *	 Input:
 *			  ptReportItem			- The ReportItem in which the data will go
 *			  iValue				- The unscaled data
 *			  piScaledValue			- The scaled value
 *	 Output:
 *			  piScaledValue			- The scaled value
 *	 Returns:
 *			  kHIDSuccess
 *
 *------------------------------------------------------------------------------
*/
OSStatus HIDScaleUsageValueOut (HIDReportItem *ptReportItem, UInt32 iValue, SInt32 *piScaledValue)
{
	long int lData;
	long int lDeltaL;
	long int lDeltaP;
	long int lL, lP;
	long int lPMax, lPMin;
/*
 *	Convert the data to Long Integer
*/
	lData = iValue;
/*
 *	range check the Logical Value
*/
	lPMax = ptReportItem->globals.physicalMaximum;
	lPMin = ptReportItem->globals.physicalMinimum;
	if ((lData < lPMin) || (lData > lPMax))
	{
		if ((ptReportItem->dataModes & kHIDDataNullStateBit) == kHIDDataNullState)
			return kHIDNullStateErr;
		return kHIDValueOutOfRangeErr;
	}
/*
 *	(PhysicalValue - PhysicalMinimum)/(PhysicalMaximum - PhysicalMinimum)
 *	= (LogicalValue - LogicalMinimum)/(LogicalMaximum - LogicalMinimum)
 *
 *	Calculate the ranges
 *	Zero ranges are invalid!
 *	  lDeltaL = (LogicalMaximum - LogicalMinimum)
 *	  lDeltaP = (PhysicalMaximum - PhysicalMinimum)
*/
	lDeltaL = ptReportItem->globals.logicalMaximum - ptReportItem->globals.logicalMinimum;
	lDeltaP = ptReportItem->globals.physicalMaximum - ptReportItem->globals.physicalMinimum;
	if ((lDeltaL == 0) || (lDeltaP == 0))
		return kHIDBadLogPhysValuesErr;
/*
 *	(PhysicalValue - PhysicalMinimum)/lDeltaP
 *	= (LogicalValue - LogicalMinimum)/lDeltaL
 *	lP = (PhysicalValue - PhysicalMinimum)
*/
	lP = lData - ptReportItem->globals.physicalMinimum;
/*
 *	(LogicalValue - LogicalMinimum)/lDeltaL = lP/lDeltaP
 *	(LogicalValue - LogicalMinimum)/lDeltaL = (lDeltaL * lP)/lDeltaP
 *	lL = (LogicalValue - LogicalMinimum) = (lDeltaL * lP)/lDeltaP
*/
	lL = (lP* lDeltaL)/lDeltaP;
/*
 *	lL = (LogicalValue - LogicalMinimum)
 *	LogicalValue = lL + LogicalMinimum;
*/
	lData = lL + ptReportItem->globals.logicalMinimum;
	*piScaledValue = (int) lData;
	return kHIDSuccess;
}

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
	File:		HIDPostProcessRIValue.c

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

	  <USB1>	  4/7/99	BWS		first checked in
*/

#include "HIDLib.h"

/*
 *------------------------------------------------------------------------------
 *
 * HIDPostProcessRIValue - 	performs any post-processing necessary for data 
 *							retrieved _from_ a report for the specified report 
 *							item. Currently, the only post-processing done 
 *							is reversing when appropriate
 *
 *	 Input:
 *			  reportItem			- The report item
 *			  value					- the value, from HIDGetData
 *	 Output:
 *			  value					- The processed value
 *	 Returns:
 *			  kHIDSuccess			- Success
 *
 *------------------------------------------------------------------------------
*/

OSStatus HIDPostProcessRIValue (HIDReportItem *	 	reportItem,
								SInt32 *			value)
{
	
	// if isReversed, returnValue = ((min - returnValue) + max)
	if (reportItem->flags & kHIDReportItemFlag_Reversed)
		*value = ((reportItem->globals.logicalMinimum - (*value)) + 
							reportItem->globals.logicalMaximum);

	return kHIDSuccess;
}

/*
 *------------------------------------------------------------------------------
 *
 * HIDPreProcessRIValue - 	performs any pre-processing necessary for data 
 *							ouput _to_ a report for the specified report 
 *							item. Currently, the only pre-processing done 
 *							is reversing when appropriate
 *
 *	 Input:
 *			  reportItem			- The report item
 *			  value					- the value, destined for HIDPutData
 *	 Output:
 *			  value					- The processed value
 *	 Returns:
 *			  kHIDSuccess			- Success
 *
 *------------------------------------------------------------------------------
*/

OSStatus HIDPreProcessRIValue  (HIDReportItem *	 	reportItem,
								SInt32 *			value)
{
	
	// if isReversed, returnValue = ((min - returnValue) + max)
	if (reportItem->flags & kHIDReportItemFlag_Reversed)
		*value = ((reportItem->globals.logicalMinimum - (*value)) + 
							reportItem->globals.logicalMaximum);

	return kHIDSuccess;
}
   


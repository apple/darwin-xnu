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
	File:		HIDLib.h

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

#ifndef __HIDLib__
#define __HIDLib__

#include "HIDPriv.h"

#define	kShouldClearMem		true

/*------------------------------------------------------------------------------*/
/*																				*/
/* HID Library definitions														*/
/*																				*/
/*------------------------------------------------------------------------------*/

/* And now our extern procedures that are not external entry points in our shared library */

struct HIDReportDescriptor
{
	Byte *				descriptor;
	ByteCount			descriptorLength;
	UInt32				index;
	SInt32 *			collectionStack;
	SInt32				collectionNesting;
	HIDGlobalItems *	globalsStack;
	SInt32				globalsNesting;
	HIDItem				item;
	SInt32				firstUsageItem;
	SInt32				firstStringItem;
	SInt32				firstDesigItem;
	SInt32				parent;
	SInt32				sibling;
	HIDGlobalItems		globals;
	Boolean				haveUsageMin;
	Boolean				haveUsageMax;
	SInt32				rangeUsagePage;
	SInt32				usageMinimum;
	SInt32				usageMaximum;
	Boolean				haveStringMin;
	Boolean				haveStringMax;
	SInt32				stringMinimum;
	SInt32				stringMaximum;
	Boolean				haveDesigMin;
	Boolean				haveDesigMax;
	SInt32				desigMinimum;
	SInt32				desigMaximum;
};
typedef struct HIDReportDescriptor	HIDReportDescriptor;

/* And now our extern procedures that are not external entry points in our shared library */

extern OSStatus
HIDCountDescriptorItems	   (HIDReportDescriptor *	reportDescriptor,
							HIDPreparsedDataPtr 	preparsedData);

extern OSStatus
HIDNextItem				   (HIDReportDescriptor *	reportDescriptor);

extern OSStatus
HIDParseDescriptor		   (HIDReportDescriptor *	reportDescriptor,
							HIDPreparsedDataPtr 	preparsedData);

extern OSStatus
HIDProcessCollection	   (HIDReportDescriptor *	reportDescriptor,
							HIDPreparsedDataPtr 	preparsedData);

extern OSStatus
HIDProcessEndCollection	   (HIDReportDescriptor *	reportDescriptor,
							HIDPreparsedDataPtr 	preparsedData);

extern OSStatus
HIDProcessGlobalItem	   (HIDReportDescriptor *	reportDescriptor,
							HIDPreparsedDataPtr 	preparsedData);

extern OSStatus
HIDProcessLocalItem		   (HIDReportDescriptor *	reportDescriptor,
							HIDPreparsedDataPtr 	preparsedData);

extern OSStatus
HIDProcessMainItem		   (HIDReportDescriptor *	reportDescriptor,
							HIDPreparsedDataPtr 	preparsedData);

extern OSStatus
HIDProcessReportItem	   (HIDReportDescriptor *	reportDescriptor,
							HIDPreparsedDataPtr 	preparsedData);

#endif

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
	File:		HIDPutData.c

	Contains:	xxx put contents here xxx

	Version:	xxx put version here xxx

	Copyright:	© 1999-2000 by Apple Computer, Inc., all rights reserved.

	File Ownership:

		DRI:				xxx put dri here xxx

		Other Contact:		xxx put other contact here xxx

		Technology:			xxx put technology here xxx

	Writers:

		(BWS)	Brent Schorsch
		(KH)	Keithen Hayenga

	Change History (most recent first):

	  <USB3>	12/12/00	KH		Correcct cast of void *
	  <USB2>	11/11/99	KH		Use shifted value when HIDSetUsageValue fills data into a report
									field that spans multiple bytes.
	  <USB2>	  11/10/99	KH		Data that overflowed byte bounderies was lost because
	  								we shifted initial value instead of value corrected for 
									starting bit location.
	  <USB1>	  3/5/99	BWS		first checked in
*/

#include "HIDLib.h"

//#include <stdio.h>

/*
 *------------------------------------------------------------------------------
 *
 * HIDPutData - Put a single data item to a report
 *
 *	 Input:
 *			  psReport				- The report
 *			  iReportLength			- The length of the report
 *			  iStart				- Start Bit in report
 *			  iSize					- Number of Bits
 *			  iValue				- The data
 *	 Output:
 *	 Returns:
 *			  kHidP_Success			- Success
 *			  kHidP_NullPointer		- Argument, Pointer was Null
 *
 *------------------------------------------------------------------------------
*/
OSStatus
HIDPutData				   (void *					report,
							ByteCount				reportLength,
							UInt32					start,
							UInt32					size,
							SInt32 					value)
{
	Byte * psReport = (Byte *)report;
	SInt32 data, iShiftedData;
	UInt32 iStartByte, startBit;
	UInt32 iLastByte, iLastBit;
	UInt32 iStartMask, iLastMask;
	UInt32 iDataMask;
/*
 *	  Report
 *	  Bit 28 27 26 25 24 | 23 22 21 20 19 18 17 16 | 15 14 13 12 11 10 09 ...
 *	  Last Byte (3) |	 |		  Byte 2		   |	 |	Start Byte (1)
 *	  Data x  x	 x	d  d |	d  d  d	 d	d  d  d	 d |  d	 d	y  y  y	 y	y
 *	  Last Bit (1) /	 |						   |	  \ Start Bit (6)
 *	  ...  1  1	 1	0  0 |	   Intermediate		   |  0	 0	1  1  1	 1	1 ...
 *	  Last Mask			 |		 Byte(s)		   |		StartMask
*/
	iLastByte = (start + size - 1)/8;
/*
 *	Check the parameters
*/
	if ((start < 0) || (size <= 0) || (iLastByte >= reportLength))
		return kHIDBadParameterErr;
	iLastBit = (start + size - 1)&7;
	iLastMask = ~((1<<(iLastBit+1)) - 1);
	iStartByte = start/8;
	startBit = start&7;
	iStartMask = (1<<startBit) - 1;
/*
 *	If the data is contained in one byte then
 *	  handle it differently
 *	  Mask off just the area where the new data goes
 *	  Shift the data over to its new location
 *	  Mask the data for its new location
 *	  Or in the data
*/
	if (iStartByte == iLastByte)
	{
		data = psReport[iStartByte];
		iDataMask = iStartMask | iLastMask;
		data &= iDataMask;
		iShiftedData = value << startBit;
		iShiftedData &= ~iDataMask;
		data |= iShiftedData;
	}
/*
 *	If the data is in more than one byte then
 *	Do the start byte first
 *	Mask off the bits where the new data goes
 *	Shift the new data over to the start of field
 *	Or the two together and store back out
*/
	else
	{
		data = psReport[iStartByte];
		data &= iStartMask;
		iShiftedData = value << startBit;
		data |= iShiftedData;
		psReport[iStartByte] = (Byte) data;
		iShiftedData >>= 8;
/*
 *		Store out an intermediate bytes
*/
		while (++iStartByte < iLastByte)
		{
			psReport[iStartByte] = (Byte) iShiftedData;
			iShiftedData >>= 8;
		}
/*
 *		Mask off the bits where the new data goes
 *		Mask off the bits in the new data where the old goes
 *		Or the two together and store back out
*/
		data = psReport[iLastByte];
		data &= iLastMask;
		iShiftedData &= ~iLastMask;
		data |= iShiftedData;
	}
/*
 *	Store out the last or only Byte
*/
	psReport[iStartByte] = (Byte) data;
	return kHIDSuccess;
}


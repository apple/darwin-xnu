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
	File:		HIDGetData.c

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

	  <USB3>	12/12/00	KH		Correct cast of void *
	  <USB2>	  3/5/99	BWS		[2311353]  HIDGetData not masking properly, so not work at all
	  <USB1>	  3/5/99	BWS		first checked in
*/

#include "HIDLib.h"

/*
 *------------------------------------------------------------------------------
 *
 * HIDGetData - Get a single data item from a report
 *
 *	 Input:
 *			  psReport				- The report
 *			  iReportLength			- The length of the report
 *			  iStart				- Start Bit in report
 *			  iSize					- Number of Bits
 *			  piValue				- The place to write the data
 *			  bSignExtend			- Sign extend?
 *	 Output:
 *			  piValue				- The data
 *	 Returns:
 *			  kHidP_Success			- Success
 *			  kHidP_NullPointer		- Argument, Pointer was Null
 *
 *------------------------------------------------------------------------------
*/
OSStatus HIDGetData(void * report, UInt32 iReportLength,
						 UInt32 iStart, UInt32 iSize, SInt32 *piValue,
						 Boolean bSignExtend)
{
	Byte * psReport = (Byte *)report;
	unsigned data;
	unsigned iSignBit;
	unsigned iExtendMask;
    unsigned iStartByte = iStart/8;
    unsigned startBit = iStart&7;
    unsigned iLastBit = iStart + iSize - 1;
    unsigned iLastByte = iLastBit/8;
    int iCurrentByte;		// needs to be signed, we terminate loop on -1
    unsigned iMask;

	// Check the parameters
	if ((iSize == 0) || (iLastByte >= iReportLength) || (iLastByte < iStartByte))
		return kHIDBadParameterErr;

	// Pick up the data bytes backwards
    data = 0;
    for (iCurrentByte = iLastByte; iCurrentByte >= (int) iStartByte; iCurrentByte--)
    {
        data <<= 8;

		iMask = 0xff;	//  1111 1111 initial mask
		// if this is the 'last byte', then we need to mask off the top part of the byte
		// to find the mask, we: find the position in this byte (lastBit % 8)
		// then shift one to the left that many times plus one (to get one bit further)
		// then subtract 1 to get all ones starting from the lastBit to the least signif bit
		// ex: if iLastBit is 9, or iLastBit is 15, then we get: 
		// 					1					7			(x % 8)
		//			     0000 0100			1 0000 0000		(1 << (x + 1))
		//				 0000 0011			0 1111 1111		(x - 1)
		if (iCurrentByte == iLastByte)
			iMask = ((1 << (((unsigned) iLastBit % 8) + 1)) - 1);

        data |= (unsigned) psReport[iCurrentByte] & iMask;
	}

	// Shift to the right to byte align the least significant bit
	data >>= startBit;

	// Sign extend the report item
	if (bSignExtend)
	{
		iSignBit = 1;
		if (iSize > 1)
			iSignBit <<= (iSize-1);
		iExtendMask = (iSignBit << 1) - 1;
		if ((data & iSignBit)==0)
			data &= iExtendMask;
		else
			data |= ~iExtendMask;
	}

	// Return the value
	*piValue = (SInt32) data;

	return kHIDSuccess;
}

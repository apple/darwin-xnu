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
	File:		HIDUsageInRange.c

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
 * HIDUsageInRange
 *
 *	 Input:
 *			  ptUsage				- The usage/UsageRange Item
 *			  usagePage			   - The usagePage of the Item - or zero
 *			  usage				   - The usage of the Item
 *	 Output:
 *	 Returns:
 *			  true					- usagePage/usage is in usage/UsageRange
 *			  false					- usagePage/usage is not in usage/UsageRange
 *
 *------------------------------------------------------------------------------
*/
Boolean HIDUsageInRange (HIDP_UsageItem *ptUsage, HIDUsage usagePage, HIDUsage usage)
{
/*
 *	Disallow Null Pointers
*/
	if (ptUsage == NULL)
		return false;
/*
 *	Check for the proper Page, 0 means don't care
*/
	if ((usagePage != 0) && (ptUsage->usagePage != usagePage))
		return false;
/*
 *	usage = 0 means don't care
*/
	if (usage == 0)
		return true;
/*
 *	The requested usage must match or be in the range
*/
	if (ptUsage->isRange)
	{
		if ((ptUsage->usageMinimum > usage) || (ptUsage->usageMaximum < usage))
			return false;
	}
	else
	{
		if (ptUsage->usage != usage)
			return false;
	}
	return true;
}

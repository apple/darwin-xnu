/*
 * Copyright (c) 1999, 2000-2001 Apple Computer, Inc. All rights reserved.
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
	File:		macOnly.h

	Contains:	Mac-specific #defines for Yarrow.

	Written by:	Doug Mitchell

	Copyright: (c) 2000 by Apple Computer, Inc., all rights reserved.

	Change History (most recent first):

		02/10/99	dpm		Created.
 
*/

#if		!defined(macintosh) && !defined(__APPLE__)
#error Hey, why are you including macOnly for a non-Mac build!?
#endif

#ifndef	_MAC_ONLY_H_
#define _MAC_ONLY_H_

#include "dev/random/YarrowCoreLib/include/WindowsTypesForMac.h"

#if defined(__cplusplus)
extern "C" {
#endif

/*
 * No "slow poll" for Mac. 
 */
#define SLOW_POLL_ENABLE	0
#if		SLOW_POLL_ENABLE
extern DWORD prng_slow_poll(BYTE* buf,UINT bufsize);
#endif	/* SLOW_POLL_ENABLE */

#if defined(__cplusplus)
}
#endif

#endif	/* _MAC_ONLY_H_*/

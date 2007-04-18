/*
 * Copyright (c) 1999, 2000-2001 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
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

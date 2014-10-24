/*
 * Copyright (c) 1999-2013 Apple Inc. All rights reserved.
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
	File:		smf.h

	Contains:	Secure malloc/free API.

	Written by:	Doug Mitchell

	Copyright: (c) 2000 by Apple Computer, Inc., all rights reserved.

	Change History (most recent first):

		02/10/00	dpm		Created, based on Counterpane's Yarrow code. 
 
*/

#ifndef _YARROW_SMF_H_
#define _YARROW_SMF_H_

#if defined(__cplusplus)
extern "C" {
#endif

/* smf.h */

	/*  
	Header file for secure malloc and free routines used by the Counterpane
	PRNG. Use this code to set up a memory-mapped file out of the system 
	paging file, allocate and free memory from it, and then return
	the memory to the system registry after having securely overwritten it.
	Details of the secure overwrite can be found in Gutmann 1996 (Usenix).
	Trying to explain it here will cause my head to begin to hurt.
	Ari Benbasat (pigsfly@unixg.ubc.ca)
	*/



#if		defined(macintosh) || defined(__APPLE__)
#include "macOnly.h"
#define MMPTR	void *

#ifndef SMFAPI 
#define SMFAPI 
#endif

#else	/* original Yarrow */

/* Declare HOOKSAPI as __declspec(dllexport) before
   including this file in the actual DLL */
#ifndef SMFAPI 
#define SMFAPI __declspec(dllimport)
#endif
#define MMPTR	BYTE

#endif /* macintosh */


#define MM_NULL	((void *)0)

/* Function forward declarations */
SMFAPI void mmInit( void );
SMFAPI MMPTR mmMalloc(DWORD request);
SMFAPI void mmFree(MMPTR ptrnum);
SMFAPI LPVOID mmGetPtr(MMPTR ptrnum);
SMFAPI void mmReturnPtr(MMPTR ptrnum);
#if	0
SMFAPI void mmFreePtr(LPVOID ptr);
#endif

#if defined(__cplusplus)
}
#endif

#endif	/* _YARROW_SMF_H_*/

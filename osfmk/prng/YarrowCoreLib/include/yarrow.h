/*
 * Copyright (c) 1999, 2000-2013 Apple Inc. All rights reserved.
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
	File:		yarrow.h

	Contains:	Public header file for Counterpane's Yarrow Pseudo-random 
				number generator.

	Written by:	Counterpane, Inc. 

	Copyright: (c) 2000 by Apple Computer, Inc., all rights reserved.

	Change History (most recent first):

		02/10/99	dpm		Created, based on Counterpane source.
 
*/
/*
	yarrow.h

	Main header file for Counterpane's Yarrow Pseudo-random number generator.
*/

#ifndef __YARROW_H__
#define __YARROW_H__

#if		defined(macintosh) || defined(__APPLE__)
#include "WindowsTypesForMac.h"
#endif

#if defined(__cplusplus)
extern "C" {
#endif

/* Error Codes */
typedef enum prng_error_status {
	PRNG_SUCCESS = 0,
	PRNG_ERR_REINIT,
	PRNG_ERR_WRONG_CALLER,
	PRNG_ERR_NOT_READY,
	PRNG_ERR_NULL_POINTER,
	PRNG_ERR_LOW_MEMORY,
	PRNG_ERR_OUT_OF_BOUNDS,
	PRNG_ERR_COMPRESSION,
	PRNG_ERR_NOT_ENOUGH_ENTROPY,
	PRNG_ERR_MUTEX,
	PRNG_ERR_TIMEOUT,
	PRNG_ERR_PROGRAM_FLOW
} prng_error_status;

/*
 * Entropy sources
 */
enum user_sources {
	CLIENT_SOURCE = 0,
	ENTROPY_FILE_SOURCE,
	SYSTEM_SOURCE,
	USER_SOURCES  /* Leave as last source */
};


/* Declare YARROWAPI as __declspec(dllexport) before
   including this file in the actual DLL */
#ifndef YARROWAPI 
#if		defined(macintosh) || defined(__APPLE__)
#define YARROWAPI
#else
#define YARROWAPI __declspec(dllimport)
#endif
#endif

/* Public function forward declarations */

#if		defined(macintosh) || defined(__APPLE__)
/* 
 * Mac changes:
 *   1. PrngRef context for all functions. Thus no global variables.
 *   2. Strong enum typing (prng_error_status instead of int return).
 */
struct PRNG;
typedef struct PRNG *PrngRef;

YARROWAPI prng_error_status 
prngInitialize(
	PrngRef *prng);
YARROWAPI prng_error_status 
prngDestroy(
	PrngRef prng);
YARROWAPI prng_error_status 
prngOutput(
	PrngRef prng, 
	BYTE *outbuf,
	UINT outbuflen);
/* this one has no context */
YARROWAPI prng_error_status 
prngStretch(
	BYTE *inbuf,
	UINT inbuflen,
	BYTE *outbuf,
	UINT outbuflen);
YARROWAPI prng_error_status 
prngInput(
	PrngRef prng, 
	BYTE *inbuf,
	UINT inbuflen,
	UINT poolnum,
	UINT estbits);
YARROWAPI prng_error_status 
prngForceReseed(
	PrngRef prng, 
	LONGLONG ticks);
YARROWAPI prng_error_status 
prngAllowReseed(
	PrngRef prng, 
	LONGLONG ticks);
YARROWAPI prng_error_status 
prngProcessSeedBuffer(
	PrngRef prng, 
	BYTE *buf,
	LONGLONG ticks);
YARROWAPI prng_error_status 
prngSlowPoll(
	PrngRef prng, 
	UINT pollsize);
#else
/* original Counterpane API */
YARROWAPI int prngOutput(BYTE *outbuf,UINT outbuflen);
YARROWAPI int prngStretch(BYTE *inbuf,UINT inbuflen,BYTE *outbuf,UINT outbuflen);
YARROWAPI int prngInput(BYTE *inbuf,UINT inbuflen,UINT poolnum,UINT estbits);
YARROWAPI int prngForceReseed(LONGLONG ticks);
YARROWAPI int prngAllowReseed(LONGLONG ticks);
YARROWAPI int prngProcessSeedBuffer(BYTE *buf,LONGLONG ticks);
YARROWAPI int prngSlowPoll(UINT pollsize);
#endif

#if defined(__cplusplus)
}
#endif

#endif

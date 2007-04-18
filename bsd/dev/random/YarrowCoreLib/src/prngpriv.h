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
	File:		prngpriv.h

	Contains:	Private typedefs and #defines for Counterpane Yarrow PRNG.

	Written by:	Counterpane, Inc. 

	Copyright: (c) 2000 by Apple Computer, Inc., all rights reserved.

	Change History (most recent first):

		02/10/99	dpm		Created, based on Counterpane source.
 
*/
/*
	prngpriv.h

	Completely private header for the Counterpane PRNG. Should only be included by prng.c
*/

#ifndef __YARROW_PRNG_PRIV_H__
#define __YARROW_PRNG_PRIV_H__

#include "userdefines.h"
#include "dev/random/YarrowCoreLib/include/yarrow.h"
#include "entropysources.h"
#include "comp.h"
#include "sha1mod.h"
#include "smf.h"

#define TOTAL_SOURCES ENTROPY_SOURCES+USER_SOURCES

#ifdef COMPRESSION_ON
#define COMP_SOURCES TOTAL_SOURCES
#else
#define COMP_SOURCES ENTROPY_SOURCES
#endif

/* Error numbers */
typedef enum prng_ready_status {
	PRNG_READY = 33,	/* Compiler will initialize to either 0 or random if allowed to */
	PRNG_NOT_READY = 0
} prng_ready_status;

/* Top level output state */
typedef struct{
	BYTE IV[20];
	BYTE out[20];
	UINT index;			/* current byte to output */
	UINT numout;		/* bytes since last prng_make_new_state */ 
} GEN_CTX;

/* PRNG state structure */
struct PRNG {
	/* Output State */
	GEN_CTX outstate;

	/* Entropy Pools (somewhat unlike a gene pool) */
	SHA1_CTX pool;
	UINT poolSize[TOTAL_SOURCES];			/* Note that size is in bytes and est in bits */
	UINT poolEstBits[TOTAL_SOURCES];
	COMP_CTX comp_state[COMP_SOURCES];

	/* Status Flags */
	prng_ready_status ready;
};

/*
 * Clients see an opaque PrngRef; internal code uses the 
 * following typedef.
 */
typedef struct PRNG PRNG;


/* Test Macros */
#define CHECKSTATE(p) \
if(p==NULL) {return PRNG_ERR_NOT_READY;} /* Does the state exist? */	\
if(p->ready != PRNG_READY) {return PRNG_ERR_NOT_READY;}	/* Set error state and return */
/* To make sure that a pointer isn't NULL */
#define PCHECK(ptr)  if(ptr==NULL) {return PRNG_ERR_NULL_POINTER;}
/* To make sure that malloc returned a valid value */
#define MCHECK(ptr)  if(ptr==NULL) {return PRNG_ERR_LOW_MEMORY;}
/* To make sure that a given value is non-negative */
#if		defined(macintosh) || defined(__APPLE__)
/* original looks like a bogon */
#define ZCHECK(val)  if(val<0) {return PRNG_ERR_OUT_OF_BOUNDS;}
#else
#define ZCHECK(val)  if(p<0) {return PRNG_ERR_OUT_OF_BOUNDS;}
#endif	/* macintosh */
/* To make sure that the generator state is valid */
#define GENCHECK(p) if(p->outstate.index>20) {return PRNG_ERR_OUT_OF_BOUNDS;} /* index is unsigned */
/* To make sure that the entropy pool is valid */
#define POOLCHECK(p) /* */


#endif

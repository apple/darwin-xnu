/*
 * Copyright (c) 1999, 2000-2001 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

/*
	File:		comp.h

	Contains:	Glue between core prng code to the Zlib library.

	Written by:	Counterpane, Inc. 

	Copyright: (c) 2000 by Apple Computer, Inc., all rights reserved.

	Change History (most recent first):

		02/10/99	dpm		Created, based on Counterpane source.
 
*/
/* comp.h

   Header for the compression routines added to the Counterpane PRNG. 
*/

#ifndef __YARROW_COMP_H__
#define __YARROW_COMP_H__

#include "smf.h"

/*
 * Kernel version does NULL compression....
 */
#define YARROW_KERNEL

#ifdef	YARROW_KERNEL
/* 
 * Shrink this down to almost nothing to simplify kernel port;
 * with additional hacking on prng.c, this could go away entirely
 */
typedef char COMP_CTX;

/* and define some type3s normally picked up from zlib */
typedef unsigned char Bytef;
typedef unsigned uInt;

#else

#include "zlib.h"

/* Top level compression context */
typedef struct{
	MMPTR buf;
	uInt spaceused;
} COMP_CTX;
#endif	/* YARROW_KERNEL */

typedef enum comp_error_status {
	COMP_SUCCESS = 0,
	COMP_ERR_NULL_POINTER,
	COMP_ERR_LOW_MEMORY,
	COMP_ERR_LIB
} comp_error_status;

/* Exported functions from compress.c */
comp_error_status comp_init(COMP_CTX* ctx);
comp_error_status comp_add_data(COMP_CTX* ctx,Bytef* inp,uInt inplen);
comp_error_status comp_end(COMP_CTX* ctx);
comp_error_status comp_get_ratio(COMP_CTX* ctx,float* out);

#endif

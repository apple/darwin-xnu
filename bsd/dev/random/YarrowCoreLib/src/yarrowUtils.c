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
	File:		yarrowUtils.c

	Contains:	Misc. utility functions.

	Written by:	Doug Mitchell

	Copyright: (c) 2000 by Apple Computer, Inc., all rights reserved.

	Change History (most recent first):

		02/29/00	dpm		Created.
 
*/

#include "dev/random/YarrowCoreLib/include/yarrowUtils.h"

void 
trashMemory(void* mem, int len)
/* This function should only be used on data in RAM */
{
	if(len == 0) {
		/* some memsets really don't like this */
		return;
	}
	
	/* Cycle a bit just in case it is one of those weird memory units */
	/* No, I don't know which units those would be */
	memset(mem,0x00,len);
	memset(mem,0xFF,len);
	memset(mem,0x00,len);
}



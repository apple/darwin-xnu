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
	File:		smf.c

	Contains:	platform-dependent malloc/free
 
*/

#include <dev/random/YarrowCoreLib/src/smf.h>
#include <sys/malloc.h>
#include <sys/systm.h>


SMFAPI void mmInit( void )
{
	return;
}

SMFAPI MMPTR mmMalloc(DWORD request)
{
    // since kfree requires that we pass in the alloc size, add enough bytes to store a dword
    void* mem;
    
    mem = _MALLOC (request, M_DEVBUF, M_WAITOK);
    
    if (mem == 0) // oops, it didn't appear to work
    {
        printf ("Couldn't allocate kernel memory!\n");
        return 0;
    }
    
    return (MMPTR) mem;
}

SMFAPI void mmFree(MMPTR ptrnum)
{
    // get the size of the pointer back
    _FREE (ptrnum, M_DEVBUF);
}

SMFAPI LPVOID mmGetPtr(MMPTR ptrnum)
{
	return (LPVOID)ptrnum;
}

SMFAPI void mmReturnPtr(__unused MMPTR ptrnum)
{
	/* nothing */
	return;
}


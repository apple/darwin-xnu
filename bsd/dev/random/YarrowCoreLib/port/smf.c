/*
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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


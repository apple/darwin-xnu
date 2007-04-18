/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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

#include <sys/appleapiopts.h>
#include <ppc/asm.h>					// EXT, LEXT
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>

        .text
        .align	2

#define	USER_SPRG3	259		// user-mode-readable encoding for SPRG3


// ***********************************************************
// * P T H R E A D _ G E T S P E C I F I C _ S P R G 3 _ 3 2 *
// ***********************************************************
//
// For processors with user-readable SPRG3, in 32-bit mode.   Called with:
//		r3 = word number
//		r4 = offset to thread specific data (_PTHREAD_TSD_OFFSET)

pthread_getspecific_sprg3_32:
        slwi	r5,r3,2				// convert word# to byte offset
        mfspr	r3,USER_SPRG3		// get per-thread cookie
        add		r5,r5,r4			// add in offset to first word
        lwzx	r3,r3,r5			// get the thread-specific word
        blr
        
    COMMPAGE_DESCRIPTOR(pthread_getspecific_sprg3_32,_COMM_PAGE_PTHREAD_GETSPECIFIC,k64Bit,0,kCommPage32)


// ***********************************************************
// * P T H R E A D _ G E T S P E C I F I C _ S P R G 3 _ 6 4 *
// ***********************************************************
//
// For processors with user-readable SPRG3, in 64-bit mode.  This may not be used
// because the 64-bit ABI uses r13 for the thread-local-data pointer.  Called with:
//		r3 = word number
//		r4 = offset to thread specific data (_PTHREAD_TSD_OFFSET)

pthread_getspecific_sprg3_64:
        sldi	r5,r3,3				// convert double-word# to byte offset
        mfspr	r3,USER_SPRG3		// get per-thread cookie
        add		r5,r5,r4			// add in offset to first word
        ldx		r3,r3,r5			// get the thread-specific doubleword
        blr
        
    COMMPAGE_DESCRIPTOR(pthread_getspecific_sprg3_64,_COMM_PAGE_PTHREAD_GETSPECIFIC,k64Bit,0,kCommPage64)
    
    
// ***************************************
// * P T H R E A D _ S E L F _ S P R G 3 *
// ***************************************
//
// For processors with user-readable SPRG3.  Useable both in 32 and 64-bit modes.

pthread_self_sprg3:
        mfspr	r3,USER_SPRG3		// get per-thread cookie
        blr
        
    COMMPAGE_DESCRIPTOR(pthread_self_sprg3,_COMM_PAGE_PTHREAD_SELF,k64Bit,0,kCommPageBoth)
    
        
// *******************************************************
// * P T H R E A D _ G E T S P E C I F I C _ U F T R A P *
// *******************************************************
//
// For processors that use the Ultra-Fast-Trap to get the thread-specific ptr.
// Called with:
//		r3 = word number
//		r4 = offset to thread specific data (_PTHREAD_TSD_OFFSET)

pthread_getspecific_uftrap:
        slwi	r5,r3,2				// convert word# to byte offset
        li 		r0,0x7FF2			// magic "pthread_self" ultra-fast trap code
        sc
        add		r5,r5,r4			// add in offset to first word
        lwzx	r3,r3,r5			// get the thread-specific word
        blr

    COMMPAGE_DESCRIPTOR(pthread_getspecific_uftrap,_COMM_PAGE_PTHREAD_GETSPECIFIC,0,k64Bit,kCommPage32)
    
        
// *****************************************
// * P T H R E A D _ S E L F _ U F T R A P *
// *****************************************
//
// For processors that use the Ultra-Fast-Trap to get the thread-specific ptr.

pthread_self_uftrap:
        li 		r0,0x7FF2			// magic "pthread_self" ultra-fast trap code
        sc							// get r3==TLDP
        blr

    COMMPAGE_DESCRIPTOR(pthread_self_uftrap,_COMM_PAGE_PTHREAD_SELF,0,k64Bit,kCommPage32)

/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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

#include <sys/appleapiopts.h>
#include <ppc/asm.h>					// EXT, LEXT
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>

        .text
        .align	2
        .globl	EXT(pthread_getspecific_sprg3)
        .globl	EXT(pthread_getspecific_uftrap)
        .globl	EXT(pthread_self_sprg3)
        .globl	EXT(pthread_self_uftrap)

#define	USER_SPRG3	259		// user-mode-readable encoding for SPRG3


// *****************************************************
// * P T H R E A D _ G E T S P E C I F I C _ S P R G 3 *
// *****************************************************
//
// For processors with user-readable SPRG3.   Called with:
//		r3 = word number
//		r4 = offset to thread specific data (_PTHREAD_TSD_OFFSET)

pthread_getspecific_sprg3:
        slwi	r5,r3,2				// convert word# to byte offset
        mfspr	r3,USER_SPRG3		// get per-thread cookie
        add		r5,r5,r4			// add in offset to first word
        lwzx	r3,r3,r5			// get the thread-specific word
        blr
        
    COMMPAGE_DESCRIPTOR(pthread_getspecific_sprg3,_COMM_PAGE_PTHREAD_GETSPECIFIC,k64Bit,0,0)
    
    
// ***************************************
// * P T H R E A D _ S E L F _ S P R G 3 *
// ***************************************
//
// For processors with user-readable SPRG3.

pthread_self_sprg3:
        mfspr	r3,USER_SPRG3		// get per-thread cookie
        blr
        
    COMMPAGE_DESCRIPTOR(pthread_self_sprg3,_COMM_PAGE_PTHREAD_SELF,k64Bit,0,0)
    
        
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

    COMMPAGE_DESCRIPTOR(pthread_getspecific_uftrap,_COMM_PAGE_PTHREAD_GETSPECIFIC,0,k64Bit,0)
    
        
// *****************************************
// * P T H R E A D _ S E L F _ U F T R A P *
// *****************************************
//
// For processors that use the Ultra-Fast-Trap to get the thread-specific ptr.

pthread_self_uftrap:
        li 		r0,0x7FF2			// magic "pthread_self" ultra-fast trap code
        sc							// get r3==TLDP
        blr

    COMMPAGE_DESCRIPTOR(pthread_self_uftrap,_COMM_PAGE_PTHREAD_SELF,0,k64Bit,0)

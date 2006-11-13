/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1997-1998 Apple Computer, Inc.
 *
 *
 * HISTORY
 *
 * sdouglas  22 Oct 97 - first checked in from DriverServices
 * sdouglas  28 Jul 98 - start IOKit
 */

#include <architecture/ppc/asm_help.h>

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; ENTRY		functionName
;
; Assembly directives to begin an exported function.
;
; Takes: functionName - name of the exported function
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

.macro ENTRY
	.text
	.align		2
	.globl		$0
$0:
.endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

/*

OSStatus SynchronizeIO( void )

*/

	ENTRY	__eSynchronizeIO

	li	r0,	0
	eieio
	li	r3,	0
	blr

/*

OSStatus CallTVector_NoRecover(
	    void * p1, void * p2, void * p3, void * p4, void * p5, void * p6,	// r3-8
	    LogicalAddress entry )						// r9

*/

#define PARAM_SIZE	24
#define FM_SIZE		64
#define FM_LR_SAVE	8
#define FM_TOC_SAVE	20

	ENTRY	_CallTVector

#if 1
	stw	r2,	FM_TOC_SAVE(r1)
    	lwz	r0,	0(r9)
	lwz	r2,	4(r9)
	mtspr	ctr,	r0
	bctr

#else
	mflr	r0
	stw	r0,	FM_LR_SAVE(r1)
	stw	r2,	FM_TOC_SAVE(r1)

	stwu	r1,	-(PARAM_SIZE+FM_SIZE)(r1)
	
	lwz	r2,	4(r9)
	lwz	r0,	0(r9)
	mtspr	lr,	r0
	mfspr	r12,	lr
	blrl

	addi	r1,	r1,(PARAM_SIZE+FM_SIZE)
	lwz	r2,	FM_TOC_SAVE(r1)
	lwz	r0,	FM_LR_SAVE(r1)
	mtlr	r0
	blr
#endif

/*
 * Seemingly unused references from cpp statically initialized objects.
 */

.globl .constructors_used
.constructors_used = 0
.globl .destructors_used
.destructors_used = 0

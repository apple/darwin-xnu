/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
    .align	2
    .globl	$0
$0:
.endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

/*
int OSCompareAndSwap( UInt32 oldVal, UInt32 newVal, UInt32 * addr )
This is now an alias to hw_compare_and_store, see xnu/libkern/Makefile
*/

/*
Note:  We can not use the hw_atomic routines provided by osfmk/ppc as
the return the result of the addition not the original value.
*/
/*
SInt32	OSDecrementAtomic(SInt32 * value)
*/
    ENTRY	_OSDecrementAtomic
    mr		r4, r3
    li		r3, -1
    b		_OSAddAtomic

/*
SInt32	OSIncrementAtomic(SInt32 * value)
*/

    .align	5

    ENTRY	_OSIncrementAtomic
    mr		r4, r3
    li		r3, 1

/*
SInt32	OSAddAtomic(SInt32 amount, SInt32 * value)
*/

    ENTRY	_OSAddAtomic

    mr		r5,r3		/* Save the increment */
.L_AAretry:
    lwarx	r3, 0, r4	/* Grab the area value */
    add		r6, r3, r5	/* Add the value */
    stwcx.	r6, 0, r4	/* Try to save the new value */
    bne-	.L_AAretry	/* Didn't get it, try again... */
    blr				/* Return the original value */

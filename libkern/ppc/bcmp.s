/*
 * Copyright (c) 2000-2001 Apple Computer, Inc. All rights reserved.
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
;
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
;
; int	bcmp(const void *LHS, const void *RHS, size_t len);
;
; Because bcmp returns zero if equal and nonzero otherwise, it is slightly
; faster than memcmp, which returns the difference between the first different
; bytes.
; 	r3 - LHS
; 	r4 - RHS
; 	r5 - len

	.align	5
	.globl	EXT(bcmp)
LEXT(bcmp)

	cmpwi	cr1,r5,6		; six chars long?
	mr	r6,r3			; copy LHS ptr so we can use r3 as result
	mr.	r3,r5			; test length and move to r3
	bgt	cr1,Llong		; more than 6 chars long
	blt	cr1,Lshort		; less than 6

	; most common operand length is 6 chars (enet addrs)

	lwz	r8,0(r6)		; first 4 bytes of LHS
	lwz	r7,0(r4)		; and RHS
	lhz	r9,4(r6)		; next 2 of LHS
	sub.	r3,r8,r7		; compare first 4
	bnelr				; first 4 differed (r3!=0)
	lhz	r10,4(r4)		; next 2 of RHS
	sub	r3,r9,r10		; compare last 2
	blr				; done, result in r3

	; handle long strings
Llong:
	srwi	r0,r5,2			; r0 = word len
	mtctr	r0			; set up for loop
Llongloop:
	lwz	r8,0(r6)		; next 4 bytes from LHS
	addi	r6,r6,4
	lwz	r7,0(r4)		; next 4 from RHS
	addi	r4,r4,4
	sub.	r3,r8,r7		; compare next 4 bytes
	bdnzt+	eq,Llongloop		; loop if ctr!=0 and cr0_eq
	bnelr				; done if not equal (r3!=0)

	andi.	r5,r5,3			; more to go?

	; compare short strings (0-5 bytes long)
	;  	r5 = length remaining
	;	cr0= set on length
	;	r3 = zero if length is zero
Lshort:
	beqlr				; done (r3=0)
	mtctr	r5
Lshortloop:
	lbz	r8,0(r6)		; get next byte from LHS
	addi	r6,r6,1
	lbz	r7,0(r4)		; and next byte from RHS
	addi	r4,r4,1
	sub.	r3,r8,r7		; compare
	bdnzt+	eq,Lshortloop		; loop if ctr!=0 and cr0_eq
	blr				; done, r3 set correctly by the subtract


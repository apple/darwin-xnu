/*
 * Copyright (c) 2000-2001 Apple Computer, Inc. All rights reserved.
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
;
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
;
; int	memcmp(const void *LHS, const void *RHS, size_t len);
;
; Memcmp returns the difference between the first two different bytes, 
; or 0 if the two strings are equal.  Because we compare a word at a
; time, this requires a little additional processing once we find a
; difference.
; 	r3 - LHS
; 	r4 - RHS
; 	r5 - len

	.align	5
	.globl	EXT(memcmp)
LEXT(memcmp)

	cmpwi	cr1,r5,6		; six is the most common length
	mr	r6,r3			; we want to use r3 for compare result
	mr.	r3,r5			; test length for 0
	bgt	cr1,Llong		; handle long strings
	blt	cr1,Lshort		; and short strings

	; six char strings are special cased because they are the most common
Lsix:
	lwz	r8,0(r6)		; first 4 bytes of LHS
	lwz	r7,0(r4)		; and RHS
	xor.	r3,r8,r7		; compare first 4
	bne	Ldifferent		; first 4 differed
	lhz	r8,4(r6)		; last 2 of LHS
	lhz	r7,4(r4)		; last 2 of RHS
	xor.	r3,r8,r7		; compare last 2
	beqlr				; done if equal

	; strings differ, so we must compute difference between first two
	; differing bytes.
	;	r8 = LHS bytes
	;	r7 = RHS bytes
	;	r3 = r8 xor r7 (r3!=0)
Ldifferent:
	cntlzw	r9,r3			; count leading 0s in xor
	rlwinm	r10,r9,0,0,28		; mask off low 3 bits, so r10 = 0, 8, 16, or 24
	subfic	r6,r10,24		; r6 := (24 - r10)
	srw	r4,r8,r6		; r4 = LHS differing byte
	srw	r5,r7,r6		; r5 = RHS differing byte
	sub	r3,r4,r5		; r3 = difference
	blr

	; handle long strings
Llong:
	srwi	r0,r5,2			; r0 = word length
	mtctr	r0			; set up for loop
Llongloop:
	lwz	r8,0(r6)		; next 4 bytes from LHS
	addi	r6,r6,4
	lwz	r7,0(r4)		; next 4 from RHS
	addi	r4,r4,4
	xor.	r3,r8,r7		; compare next 4 bytes
	bdnzt+	eq,Llongloop		; loop if ctr!=0 and cr0_eq
	bne	Ldifferent		; these 4 bytes not equal
	
	andi.	r5,r5,3			; more to go?

	; compare short strings (0-5 bytes long)
	;	r5 = length (0-5)
	;	cr0= set on length
	;	r3 = if r5=0, then r3=0
Lshort:
	beqlr				; 0-length strings are defined to be equal (r3=0)
	mtctr	r5
Lshortloop:
	lbz	r8,0(r6)		; get next byte from LHS
	addi	r6,r6,1
	lbz	r7,0(r4)		; and next byte from RHS
	addi	r4,r4,1
	sub.	r3,r8,r7		; compare
	bdnzt+	eq,Lshortloop		; lloop if ctr!=0 and cr0_eq
	blr				; done, r3 set correctly by the subtract

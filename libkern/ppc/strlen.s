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
;
; Strlen, optimized for PPC.  The routine we use is 2-3x faster
; then the simple loop which checks each byte for zero.
; For 0- and 1-byte strings, the simple routine is faster, but
; only by a few cycles.  The algorithm used was adapted from the
; Mac OS 9 stdCLib strcopy routine, which was originally
; written by Gary Davidian.  It relies on the following rather
; inobvious but very efficient test: 
; 
;	y =  dataWord + 0xFEFEFEFF
;	z = ~dataWord & 0x80808080
;	if ( y & z ) = 0 then all bytes in dataWord are non-zero
;
; The test maps any non-zero byte to zeros and any zero byte to 0x80,
; with one exception: 0x01 bytes preceeding the first zero are also
; mapped to 0x80.
;
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
;
; int	strlen(ptr)
;
;

	.align	5
	.globl	EXT(strlen)
LEXT(strlen)

	andi.	r4,r3,0x03		; test alignment first
	mr	r9,r3			; store the original address for later use....
	bne	LalignSource		; align the source addr if not already aligned
Llentry:
	lis	r5,hi16(0xFEFEFEFF)
	lis	r6,hi16(0x80808080)
	subi	r3,r3,0x04		; pre-decrement r3 for the lwzu
	ori	r5,r5,lo16(0xFEFEFEFF)	; r5=0xFEFEFEFF
	ori	r6,r6,lo16(0x80808080)	; r6=0x80808080

LLoop:
	lwzu	r8,4(r3)		; get the first 4 bytes and increment address
	add	r4,r5,r8		; r4= data + 0xFEFEFEFF
	andc	r7,r6,r8		; r7= ~data & 0x80808080
	and.	r4,r4,r7		; r4= r4 & r7
	beq	LLoop			; if r4 is zero, then all bytes are non-zero

; Now we know one of the bytes in r8 is zero,
; we just have to figure out which one. 
; We have mapped 0 bytes to 0x80, and nonzero bytes to 0x00,
; with one exception:
; 0x01 bytes preceeding the first zero are also mapped to 0x80.
; So we have to mask out the 0x80s caused by 0x01s before
; counting leading zeroes to get the bytes in last word.

	rlwinm	r5,r8,7,0,31		; move 0x01 bits to 0x80 position
	subf	r3,r9,r3		; start to compute string length
	andc	r4,r4,r5		; turn off false hits from 0x0100 worst case
	cntlzw	r7,r4			; now we can count leading 0s
	srwi	r7,r7,3			; convert 0,8,16,24 to 0,1,2,3
	add	r3,r3,r7		; add in nonzero bytes in last word
	blr

; We must align the source address for two reasons: to avoid spurious page
; faults, and for speed.  
;	r4 = low 2 bits of address (1,2, or 3)
;	r3 = address
;	r9 = original address (still same as r3)

LalignSource:
	lbz	r5,0(r3)		; get the first byte...
	subic.	r4,r4,2			; test for 1, 2 or 3 bytes
	addi	r3,r3,1			; increment address
	addi	r6,r9,1			; now r6==r3
	cmpwi	cr1,r5,0		; zero?
	beq	cr1,Lreturn		; if its zero return zero
	bgt	Llentry			; address is aligned now if low bits were 3

	lbz	r5,0(r3)		; get the next byte...
	addi	r3,r3,1			; increment address
	cmpwi	cr1,r5,0		; zero?
	beq	cr1,Lreturn		; if its zero return one
	beq	Llentry			; addr is aligned now if low bits were 2

	lbz	r5,0(r3)		; get the next byte...
	addi	r3,r3,1			; increment address
	cmpwi	cr1,r5,0		; zero?
	bne	cr1,Llentry		; not zero, continue check (now aligned)
Lreturn:
	sub	r3,r3,r6		; get string length (0, 1, or 2)
	blr


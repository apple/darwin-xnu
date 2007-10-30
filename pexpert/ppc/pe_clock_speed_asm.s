/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*
 *  clock_speed_asm.s - Uses the Via timer, decrementer, and counter
 *			to determine the clock and bus rates.
 *
 *  (c) Apple Computer, Inc. 1998-9
 *
 *  Writen by:	 Josh de Cesare
 *
 */

#include <ppc/asm.h>

// constants for the via
#define CountLow  0x800
#define CountHigh 0xa00
#define LatchLow  0xc00
#define LatchHigh 0xe00


// void pe_run_clock_test(clock_test_data *data)
//
// data points to the base address of the via and two longs
// for storing the via and dec results.
//
// The basic idea is this...
// Use the counter register to execute a loop that will take
// 10,000,000 processor clocks.  Time it using both the via counter
// and the time base.  Return the number of ticks for both so the
// raw values for processor and bus speed can be calculated.
ENTRY(pe_run_clock_test, TAG_NO_FRAME_USED)

	li	r4,	1		; flag for cache load
	li	r5,	1		; Only once through this time
	lwz	r9,	0(r3)		; r9 is the via addr

L_again:
	mtctr	r5			; set the count
	li	r5,	0xff		; Start the counter at 0xffff
	stb	r5,	CountLow(r9)	; clear the via counter
	eieio
	stb	r5,	CountHigh(r9)
	eieio
	mftb	r10			; save starting value of the time base
	isync

L_loop:
	addi	r5,	r5,	1	; 8 adds for 8 cycles
	addi	r5,	r5,	2	; the bdnz should be 0 cycles
	addi	r5,	r5,	3
	addi	r5,	r5,	4
	addi	r5,	r5,	5
	addi	r5,	r5,	6
	addi	r5,	r5,	7
	addi	r5,	r5,	8
	bdnz	L_loop

	sync
	mftb	r5			; save the raw time base value
	lbz	r6,	CountHigh(r9)	; get the via counter values
	eieio
	lbz	r7,	CountLow(r9)
	eieio
	lbz	r8,	CountHigh(r9)
	eieio

	cmpi	cr0,	r4,	1	; see if the was the cache run
	bne	L_finish_up		; nope, we are done.

	li	r4,	0		; set flag for the real test
	li	r5,	0x12d0		; set the initial count to 1.25e+6
	oris	r5,	r5,	0x13
	b	L_again

L_finish_up:
	cmpi    cr0,    r7,     0	; if L1 is zero then H1 is good. 
	beq     L_use_H1		; else H2 will be good.

	mr      r6,     r8		; use H2 instead.

L_use_H1:
	rlwimi	r7,	r6,	8, 16, 23
	not	r6,	r7	        ; neg - 1 is not
	andi.	r6,	r6,	0xffff
	stw	r6,	4(r3)		; save via ticks

	sub	r5,	r5,	r10	; r5 is the number of time base ticks
	stw	r5,	8(r3)		; save time base ticks

        blr

/*
 * Copyright (c) 2012 Apple Computer, Inc. All rights reserved.
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
 *
 * This file implements the following function for the arm64 architecture:
 *
 *  int strncmp(const char *s1, const char *s2, size_t n);
 *
 * Returns 0 if the two strings are equal up to the first n bytes or to the
 * end of the string, whichever comes first.  Otherwise, returns the difference
 * of the first mismatched characters interpreted as uint8_t.
 */

.globl _strncmp

/*****************************************************************************
 *  Macros                                                                   *
 *****************************************************************************/

.macro EstablishFrame
	stp       fp, lr, [sp, #-16]!
	mov       fp,      sp
.endm

.macro ClearFrameAndReturn
	ldp       fp, lr, [sp], #16
	ret
.endm

#include "../mach/arm/vm_param.h"
#define kVectorSize 16

/*****************************************************************************
 *  Constants                                                                *
 *****************************************************************************/

.text
.align 5
L_mask:
.quad 0x0706050403020100, 0x0f0e0d0c0b0a0908

/*****************************************************************************
 *  Entrypoints                                                              *
 *****************************************************************************/

_strncmp:
	EstablishFrame
	eor       x3,      x3, x3
	cbz       x2,      L_scalarDone
//	Compare one byte at a time until s1 has vector alignment.
0:	tst       x0,      #(kVectorSize-1)
	b.eq      L_s1aligned
	ldrb      w4,     [x0],#1  // load byte from src1
	ldrb      w5,     [x1],#1  // load byte from src2
	subs      x3,      x4, x5  // if the are not equal
	ccmp      w4,  #0, #4, eq  //    or we find an EOS
	b.eq      L_scalarDone     // return the difference
	subs      x2,      x2, #1  // decrement length
	b.ne      0b               // continue loop if non-zero

//	We found a mismatch or EOS before s1 became aligned.  Simply return the
//	difference between the last bytes that we loaded.
L_scalarDone:
	mov       x0,      x3
	ClearFrameAndReturn

L_s1aligned:
//	If s2 is similarly aligned to s1, then we can use a naive vector comparison
//	from this point on without worrying about spurious page faults; none of our
//	loads will ever cross a page boundary, because they are all aligned.
	tst       x1,      #(kVectorSize-1)
	b.eq      L_naiveVector

/*****************************************************************************
 *  Careful chunk comparison                                                 *
 *****************************************************************************/

//	Otherwise, we need to be careful; although vector loads from s1 cannot
//	cross a page boundary because they are aligned, s2 is not aligned.  We
//	compute the multiple of vector size that we can safely load before reaching
//	a page boundary, and compare only that far before switching over to scalar
//	comparisons to step across the page boundary.  If this number happens to
//	be zero, we jump directly to the scalar comparison.
	neg       x7,      x1
	ands      x7,      x7, #(PAGE_MIN_SIZE-kVectorSize)
	b.eq      2f

.align 4
//	If n is less than the number of bytes before a page-crossing load, jump
//	into the naive vector path instead, since we will not even reach a page
//	crossing.  Otherwise, decrement n by that number before we monkey with it,
//	and set the decremented value aside.
0:	cmp       x2,      x7
	b.ls      L_naiveVector
	sub       x6,      x2, x7
//	Use vector comparisons until a mismatch or EOS is encountered, or the next
//	vector load from s2 would be page-crossing.
1:	ldr       q0,     [x0],#(kVectorSize)
	ldr       q1,     [x1],#(kVectorSize)
	cmeq.16b  v1,      v0, v1
	and.16b   v0,      v0, v1   // contains zero byte iff mismatch or EOS
	uminv.16b b1,      v0
	fmov      w3,      s1       // zero only iff comparison is finished
	cbz       w3,      L_vectorDone
	subs      x7,      x7, #(kVectorSize)
	b.ne      1b
//	Restore the updated n to x2
	mov       x2,      x6
//	The next vector load will cross a page boundary.  Instead, compare one byte
//	at a time until s1 again has vector alignment, at which point we will have
//	compared exactly 16 bytes.
2:	ldrb      w4,     [x0],#1  // load byte from src1
	ldrb      w5,     [x1],#1  // load byte from src2
	subs      x3,      x4, x5  // if the are not equal
	ccmp      w4,  #0, #4, eq  //    or we find an EOS
	b.eq      L_scalarDone     // return the difference
	subs      x2,      x2, #1  // decrement length
	b.eq      L_scalarDone     // exit loop if zero.
	tst       x0,      #(kVectorSize-1)
	b.ne      2b
//	Having compared one vector's worth of bytes using a scalar comparison, we
//	know that we are safely across the page boundary.  Initialize x7 and jump
//	back into the vector comparison part of the loop.
	mov       x7,      #(PAGE_MIN_SIZE-kVectorSize)
	b         0b

/*****************************************************************************
 *  Naive vector comparison                                                  *
 *****************************************************************************/

.align 4
L_naiveVector:
	ldr       q0,     [x0],#(kVectorSize)
	ldr       q1,     [x1],#(kVectorSize)
	cmeq.16b  v1,      v0, v1
	and.16b   v0,      v0, v1   // contains zero byte iff mismatch or EOS
	uminv.16b b1,      v0
	fmov      w3,      s1       // zero only iff comparison is finished
	cbz       w3,      L_vectorDone
	subs      x2,      x2, #16
	b.hi      L_naiveVector

L_readNBytes:
	eor       x0,      x0, x0
	ClearFrameAndReturn

L_vectorDone:
//	Load the bytes corresponding to the first mismatch or EOS and return
//  their difference.
	eor.16b   v1,      v1, v1
	cmhi.16b  v0,      v0, v1   // force non-zero lanes to 0xff
	ldr       q1,      L_mask
	orr.16b   v0,      v0, v1   // lane index in lanes containing mismatch or EOS
	uminv.16b b1,      v0
	fmov      w3,      s1
//	If the index of the mismatch or EOS is greater than or equal to n, it
//	occurs after the first n bytes of the string, and doesn't count.
	cmp       x3,      x2
	b.cs      L_readNBytes
	sub       x3,      x3, #(kVectorSize)
	ldrb      w4,     [x0, x3]
	ldrb      w5,     [x1, x3]
	sub       x0,      x4, x5
	ClearFrameAndReturn

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
 *  int memcmp_zero_ptr_aligned(const void *s, size_t n);
 *
 * The memcmp_zero_ptr_aligned function checks string s of n bytes contains all zeros.
 * Address and size of the string s must be pointer-aligned (8-byte for arm64).
 * Return 0 if true, 1 otherwise. Also return 0 if n is 0.
 */

/* this guard is used by tests */
#ifdef __arm64__

#include "asm.h"

.globl _memcmp_zero_ptr_aligned

/*****************************************************************************
 *  Macros                                                                   *
 *****************************************************************************/

.macro EstablishFrame
	ARM64_STACK_PROLOG
	stp       fp, lr, [sp, #-16]!
	mov       fp,      sp
.endm

.macro ClearFrameAndReturn
	ldp       fp, lr, [sp], #16
	ARM64_STACK_EPILOG
.endm

/*****************************************************************************
 *  Constants                                                                *
 *****************************************************************************/

.text
.align 5

/*****************************************************************************
 *  memcmp_zero_ptr_aligned entrypoint                                        *
 *****************************************************************************/

_memcmp_zero_ptr_aligned:

//  For the use case in <rdar://problem/59523721>, memory corruption should be rare
//  so check for all zeros is fairly simple when early out is not necessary.
//  We just load all the bytes and logical OR them together. If the result
//  is still zero, all the bytes are zero.

	EstablishFrame
	cmp         x1,     #64
	b.lo        L_sizeIsSmall

//	Load the first 64 bytes, and compute the number of bytes to the
//	first 64-byte aligned location.  Even though we are going to test
//	64 bytes, only those preceeding that 64-byte location "count" towards
//	reducing the length of the buffer or advancing the pointers.
	mov         x2,     x0          // copy the original addr
	add         x0,     x0, #64
	and         x0,     x0, #-64    // aligned addr
	ldp         q4, q5, [x2]
	ldp         q6, q7, [x2, #32]
	sub         x2,     x0, x2      // bytes between original and aligned addr
	sub         x1,     x1, x2      // update length
	subs        x1,     x1, #64     // check length > 64
	b.ls        L_cleanup

L_loop:
	ldp         q0, q1, [x0]
	ldp         q2, q3, [x0, #32]
	orr.16b     v4,     v4, v0      // use orr to keep non-zero bytes
	orr.16b     v5,     v5, v1
	orr.16b     v6,     v6, v2
	orr.16b     v7,     v7, v3
	add         x0,     x0, #64     // advance pointer
	subs        x1,     x1, #64     // check length > 64
	b.hi        L_loop

L_cleanup:
//  Between 0 and 64 more bytes need to be tested.  The exact
//	number of bytes to test is x1 + 64.  Instead of using smaller conditional
//	checks, we simply check 64 unaligned bytes from x0+x1. This load may overlap
//  with the previous one but it's ok.
	add         x0,     x0, x1
	ldp         q0, q1, [x0]
	ldp         q2, q3, [x0, #32]
	orr.16b     v4,     v4, v0      // use orr to keep non-zero bytes
	orr.16b     v5,     v5, v1
	orr.16b     v6,     v6, v2
	orr.16b     v7,     v7, v3

	orr.16b     v4,     v4, v5  // reduce four regs into two
	orr.16b     v6,     v6, v7
	orr.16b     v4,     v4, v6  // reduce two regs into one
	umaxv.16b   b0,     v4      // reduce 16 bytes into one
	umov        w0,     v0.b[0] // move byte to GPR for testing
	tst         w0,     w0
	cset        x0,     ne      // return 1 if non-zero, 0 otherwise
	ClearFrameAndReturn

L_sizeIsSmall:
	cbz     x1,     L_sizeIsZero    // return zero if length is zero

	mov     x3,     #0
0:	ldr     x2,    [x0],#8
	orr     x3,     x3, x2      // use orr to keep non-zero bytes
	subs    x1,     x1, #8      // update length
	b.hi    0b

	tst     x3,     x3
	cset    x0,     ne          // return 1 if non-zero, 0 otherwise
	ClearFrameAndReturn

L_sizeIsZero:
	mov     x0,     #0
	ClearFrameAndReturn

#endif // __arm64__

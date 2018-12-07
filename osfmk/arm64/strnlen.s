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
 *  size_t strnlen(const char *string, size_t maxlen);
 *
 * The strnlen function returns either strlen(string) or maxlen, whichever
 * is amller, without reading beyond the first maxlen characters of string.
 */

#include <arm64/asm.h>

.globl _strlen
.globl _strnlen

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
L_masks:
.quad 0x0706050403020100, 0x0f0e0d0c0b0a0908
.quad 0x0000000000000000, 0x0000000000000000

/*****************************************************************************
 *  strnlen entrypoint                                                       *
 *****************************************************************************/

_strnlen:
//	If n == 0, return NULL without loading any data from s.  If n is so large
//	that it exceeds the size of any buffer that can be allocted, jump into a
//	simpler implementation that omits all length checks.  This is both faster
//	and lets us avoid some messy edgecases in the mainline.
	tst       x1,      x1
	b.mi      _strlen
	b.eq      L_maxlenIsZero
	EstablishFrame
//	Load the 16-byte aligned vector containing the start of the string.
	and       x2,      x0, #-16
	ldr       q0,     [x2]
//	Load a vector {0,1,2, ... ,15} for use in finding the index of the NUL
//	byte once we identify one.  We don't use this vector until the very end
//	of the routine; it simply falls out naturally to load it now.
	adr       x3,          L_masks
	ldr       q2,     [x3],#16
//	The aligned vector that we loaded to q0 contains the start of the string,
//	but if the string was not originally aligned, it also contains bytes
//	which preceed the start of the string, and which may cause false positives
//	when we search for the terminating NUL.  We generate a mask to OR into the
//	vector using an unaligned load to prevent this.  The mask has non-zero
//	values only in those bytes which correspond to bytes preceeding the start
//	of the string in the aligned vector load.
	and       x4,      x0, #0xf
	sub       x3,      x3, x4
	ldr       q1,     [x3]
	orr.16b   v0,      v0, v1
//	Adjust maxlen to account for bytes which preceed the start of the string,
//	and jump into the main scanning loop.
	add       x1,      x1, x4
	b         1f

//	Main loop.  Identical to strlen, except that we also need to check that we
//	don't read more than maxlen bytes.  To that end, we decrement maxlen by 16
//	on each iteration, and exit the loop if the result is zero or negative.
.align 4
0:	ldr       q0,     [x2, #16]!
1:  uminv.16b b1,      v0
	fmov      w3,      s1
	cbz       w3,      L_foundNUL
	subs      x1,      x1, #16
	b.hi      0b

//	We exhausted maxlen bytes without finding a terminating NUL character, so
//  we need to return maxlen.
	sub       x0,      x2, x0
	add       x1,      x1, #16
	add       x0,      x0, x1
	ClearFrameAndReturn

L_maxlenIsZero:
	mov       x0,      #0
	ret                         // No stack frame, so don't clear it.

L_foundNUL:
//	Compute the index of the NUL byte, and check if it occurs before maxlen
//	bytes into the vector.  If not, return maxlen.  Otherwise, return the
//	length of the string.
	eor.16b   v1,      v1, v1
	cmhi.16b  v0,      v0, v1
	orr.16b   v0,      v0, v2
	uminv.16b b1,      v0
	fmov      w3,      s1      // index of NUL byte in vector
	sub       x0,      x2, x0  // index of vector in string
	cmp       x1,      x3      // if NUL occurs before maxlen bytes
	csel      x1,      x1, x3, cc // return strlen, else maxlen
	add       x0,      x0, x1
	ClearFrameAndReturn

/*****************************************************************************
 *  strlen entrypoint                                                        *
 *****************************************************************************/

.align 4
_strlen:
	EstablishFrame
//	Load the 16-byte aligned vector containing the start of the string.
	and       x1,      x0, #-16
	ldr       q0,     [x1]
//	Load a vector {0,1,2, ... ,15} for use in finding the index of the NUL
//	byte once we identify one.  We don't use this vector until the very end
//	of the routine; it simply falls out naturally to load it now.
	adr       x3,          L_masks
	ldr       q2,     [x3],#16
//	The aligned vector that we loaded to q0 contains the start of the string,
//	but if the string was not originally aligned, it also contains bytes
//	which preceed the start of the string, and which may cause false positives
//	when we search for the terminating NUL.  We generate a mask to OR into the
//	vector using an unaligned load to prevent this.  The mask has non-zero
//	values only in those bytes which correspond to bytes preceeding the start
//	of the string in the aligned vector load.
	and       x2,      x0, #0xf
	sub       x3,      x3, x2
	ldr       q1,     [x3]
	orr.16b   v0,      v0, v1
	b         1f

//	Main loop.  On each iteration we do the following:
//
//		q0 <-- next 16 aligned bytes of string
//		b1 <-- unsigned minimum byte in q0
//      if (b1 != 0) continue
//
//	Thus, we continue the loop until the 16 bytes we load contain a zero byte.
.align 4
0:	ldr       q0,     [x1, #16]!
1:	uminv.16b b1,      v0
	fmov      w2,      s1 // umov.b would be more natural, but requries 2 µops.
	cbnz      w2,      0b

//	A zero byte has been found.  The following registers contain values that
//	we need to compute the string's length:
//
//		x0		pointer to start of string
//		x1		pointer to vector containing terminating NUL byte
//		v0		vector containing terminating NUL byte
//		v2      {0, 1, 2, ... , 15}
//
//	We compute the index of the terminating NUL byte in the string (which is
//	precisely the length of the string) as follows:
//
//		vec <-- mask(v0 != 0) | v2
//		index <-- x1 - x0 + unsignedMinimum(vec)
	eor.16b   v1,      v1, v1
	cmhi.16b  v0,      v0, v1
	orr.16b   v0,      v0, v2
	uminv.16b b1,      v0
	fmov      w2,      s1
	sub       x0,      x1, x0
	add       x0,      x0, x2
	ClearFrameAndReturn

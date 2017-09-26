/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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

#include <arm/proc_reg.h>

#include <arm/asm.h>
	
/* 
 * A reasonably well-optimized bzero/memset. Should work equally well on arm11 and arm9 based
 * cores. 
 *
 * The algorithm is to align the destination pointer on a 32 byte boundary and then
 * blast data 64 bytes at a time, in two stores of 32 bytes per loop.
 */
	.syntax unified
	.text
	.align 2

/*
 * void *secure_memset(void * addr, int pattern, size_t length)
 *
 * It is important that this function remains defined in assembly to avoid
 * compiler optimizations.
 */
ENTRY(secure_memset)
/* void *memset(void *ptr, int c, size_t len); */
ENTRY(memset)
	/* move len into r1, unpack c into r2 */
	mov		r3, r2
	and		r1, r1, #0xff
	orr		r1, r1, r1, lsl #8
	orr		r2, r1, r1, lsl #16
	mov		r1, r3
	b		Lbzeroengine

/* void bzero(void *ptr, size_t len); */
ENTRY2(bzero,__bzero)
	/* zero out r2 so we can be just like memset(0) */
	mov		r2, #0

Lbzeroengine:
	/* move the base pointer into r12 and leave r0 alone so that we return the original pointer */
	mov		r12, r0

	/* copy r2 into r3 for 64-bit stores */
	mov		r3, r2

	/* check for zero len */
	cmp		r1, #0
	bxeq	lr

	/* fall back to a bytewise store for less than 32 bytes */
	cmp		r1, #32
	blt		L_bytewise

	/* check for 32 byte unaligned ptr */
	tst		r12, #0x1f
	bne		L_unaligned

	/* make sure we have more than 64 bytes to zero */
	cmp		r1, #64
	blt		L_lessthan64aligned

	/* >= 64 bytes of len, 32 byte aligned */
L_64ormorealigned:

	/* we need some registers, avoid r7 (frame pointer) and r9 (thread register) */
	stmfd	sp!, { r4-r6, r8, r10-r11 }
	mov		r4, r2
	mov		r5, r2
	mov		r6, r2
	mov		r8, r2
	mov		r10, r2
	mov		r11, r2

	/* pre-subtract 64 from the len to avoid an extra compare in the loop */
	sub		r1, r1, #64

L_64loop:
	stmia	r12!, { r2-r6, r8, r10-r11 }
	subs	r1, r1, #64
	stmia	r12!, { r2-r6, r8, r10-r11 }
	bge		L_64loop

	/* restore the saved regs */
	ldmfd	sp!, { r4-r6, r8, r10-r11 }

	/* check for completion (had previously subtracted an extra 64 from len) */
	adds	r1, r1, #64
	bxeq	lr

L_lessthan64aligned:
	/* do we have 16 or more bytes left */
	cmp		r1, #16
	stmiage	r12!, { r2-r3 }
	stmiage	r12!, { r2-r3 }
	subsge	r1, r1, #16
	bgt		L_lessthan64aligned
	bxeq	lr

L_lessthan16aligned:
	/* store 0 to 15 bytes */
	mov		r1, r1, lsl #28		/* move the remaining len bits [3:0] to the flags area of cpsr */
	msr		cpsr_f, r1

	stmiami	r12!, { r2-r3 }		/* n is set, store 8 bytes */
	streq	r2, [r12], #4		/* z is set, store 4 bytes */
	strhcs	r2, [r12], #2		/* c is set, store 2 bytes */
	strbvs	r2, [r12], #1		/* v is set, store 1 byte */
	bx		lr

L_bytewise:
	/* bytewise copy, 2 bytes at a time, alignment not guaranteed */	
	subs	r1, r1, #2
	strb	r2, [r12], #1
	strbpl	r2, [r12], #1
	bhi		L_bytewise
	bx		lr

L_unaligned:
	/* unaligned on 32 byte boundary, store 1-15 bytes until we're 16 byte aligned */
	mov		r3, r12, lsl #28
	rsb     r3, r3, #0x00000000
	msr		cpsr_f, r3

	strbvs	r2, [r12], #1		/* v is set, unaligned in the 1s column */
	strhcs	r2, [r12], #2		/* c is set, unaligned in the 2s column */
	streq	r2, [r12], #4		/* z is set, unaligned in the 4s column */
	strmi	r2, [r12], #4		/* n is set, unaligned in the 8s column */
	strmi	r2, [r12], #4

	subs	r1, r1, r3, lsr #28
	bxeq	lr

	/* we had previously trashed r3, restore it */
	mov		r3, r2

	/* now make sure we're 32 byte aligned */
	tst		r12, #(1 << 4)
	stmiane	r12!, { r2-r3 }
	stmiane	r12!, { r2-r3 }
	subsne	r1, r1, #16

	/* we're now aligned, check for >= 64 bytes left */
	cmp		r1, #64
	bge		L_64ormorealigned
	b		L_lessthan64aligned


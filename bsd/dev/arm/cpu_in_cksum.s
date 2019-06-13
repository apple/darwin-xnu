/*
 * Copyright (c) 2009-2018 Apple Inc. All rights reserved.
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

/*	$NetBSD: cpu_in_cksum.S,v 1.2 2008/01/27 16:58:05 chris Exp $	*/

/*
 * Copyright 2003 Wasabi Systems, Inc.
 * All rights reserved.
 *
 * Written by Steve C. Woodford for Wasabi Systems, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed for the NetBSD Project by
 *      Wasabi Systems, Inc.
 * 4. The name of Wasabi Systems, Inc. may not be used to endorse
 *    or promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY WASABI SYSTEMS, INC. ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL WASABI SYSTEMS, INC
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef KERNEL
#include "../../../osfmk/arm/arch.h"
#include "../../../osfmk/arm/proc_reg.h"

#if __ARM_VFP__ < 3
#error "Unsupported: __ARM_VFP__ < 3"
#endif /* __ARM_VFP__ < 3 */
#define	CKSUM_ERR _kprintf
#else /* !KERNEL */
#ifndef LIBSYSCALL_INTERFACE
#error "LIBSYSCALL_INTERFACE not defined"
#endif /* !LIBSYSCALL_INTERFACE */
#define	CKSUM_ERR _fprintf_stderr
#define	__ARM_VFP__	3
#endif /* !KERNEL */

/*
 * The following default the implementation to little-endian architectures.
 */
#define	LITTLE_ENDIAN	1
#define	BYTE_ORDER	LITTLE_ENDIAN

.syntax unified

/*
 * XXX: adi@apple.com:
 *
 * Ugly, but we have little choice, since relying on genassym and <assym.s>
 * is not possible unless this code lives in osfmk.  Note also that this
 * routine expects "mbuf-like" argument, and it does not expect the mbuf to be
 * authentic; it only cares about 3 fields.
 */
#define	M_NEXT	0
#define	M_DATA	8
#define	M_LEN	12

/*
 * APPLE MODIFICATION
 *
 * The use of R7 in this code as data register prevents
 * the use of debugging or instrumentation tools, which is an acceptable
 * tradeoff considering the potential gain in performance.
 */

/*
 * Hand-optimised implementations for ARM/Xscale
 */

	.macro EnableVFP
#ifdef KERNEL
        push    {r0, r1, r2, r12}
        bl      _enable_kernel_vfp_context
        pop     {r0, r1, r2, r12}
#endif /* KERNEL */
	.endm


/*
 * uint32_t os_cpu_in_cksum_mbuf(struct mbuf *m, int len, int off,
 *     uint32_t initial_sum);
 *
 * Entry:
 *	r0	m
 *	r1	len
 *	r2	off
 *	r3	initial_sum
 *
 * Function wide register usage
 *	r8	accumulated sum
 *	r9	remaining length to parse
 *	ip	pointer to next mbuf
 *
 * This function returns the partial 16-bit checksum accumulated in
 * a 32-bit variable (withouth 1's complement); caller is responsible
 * for folding the 32-bit sum into 16-bit and performinng the 1's
 * complement if applicable
 */
	.globl	_os_cpu_in_cksum_mbuf
	.text
	.align	4
_os_cpu_in_cksum_mbuf:
	stmfd	sp!, {r4-r11,lr}

	mov	r8, r3			/* Accumulate sum in r8 */
	mov	r9, r1			/* save len in r9 */
	mov	ip, r0			/* set ip to the current mbuf */

	cmp	r9, #0			/* length is 0? */
	bne	.Lin_cksum_skip_loop	/* if not, proceed further */
	mov	r0, r8			/* otherwise, return initial sum */

	ldmfd	sp!, {r4-r11, pc}

.Lin_cksum_skip_loop:
	ldr	r1, [ip, #(M_LEN)]
	ldr	r0, [ip, #(M_DATA)]
	ldr	ip, [ip, #(M_NEXT)]
.Lin_cksum_skip_entry:
	subs	r2, r2, r1		/* offset = offset - mbuf length */
	blt	.Lin_cksum_skip_done	/* if offset has gone negative start with this mbuf */
	cmp	ip, #0x00
	bne	.Lin_cksum_skip_loop
	b	.Lin_cksum_whoops

.Lin_cksum_skip_done:
	add	r0, r2, r0		/* data += offset (offset is < 0) */ 
	add	r0, r0, r1		/* data += length of mbuf */
					/* data == start of data to cksum */
	rsb	r1, r2, #0x00		/* length = remainder of mbuf to read */
	mov	r10, #0x00
	b	.Lin_cksum_entry

.Lin_cksum_loop:
	ldr	r1, [ip, #(M_LEN)]
	ldr	r0, [ip, #(M_DATA)]
	ldr	ip, [ip, #(M_NEXT)]
.Lin_cksum_entry:
	cmp	r9, r1
	movlt	r1, r9
	sub	r9, r9, r1
	eor	r11, r10, r0
	add	r10, r10, r1
	adds	r2, r1, #0x00

	beq	.Lin_cksum_next

/*
 * APPLE MODIFICATION
 *
 * Replace the 'blne _ASM_LABEL(L_cksumdata)' by bringing the called function
 * inline. This results in slightly faster code, and also permits the whole
 * function to be included in kernel profiling data.
 */

/*
 * The main in*_cksum() workhorse...
 *
 * Entry parameters:
 *	r0	Pointer to buffer
 *	r1	Buffer length
 *	lr	Return address
 *
 * Returns:
 *	r2	Accumulated 32-bit sum
 *
 * Clobbers:
 *	r0-r7
 */
	mov	r2, #0

	/* We first have to word-align the buffer.  */
	ands	r7, r0, #0x03
	beq	.Lcksumdata_wordaligned
	rsb	r7, r7, #0x04
	cmp	r1, r7			/* Enough bytes left to make it? */
	blt	.Lcksumdata_endgame
	cmp	r7, #0x02
	ldrb	r4, [r0], #0x01		/* Fetch 1st byte */
	ldrbge	r5, [r0], #0x01		/* Fetch 2nd byte */
	movlt	r5, #0x00
	ldrbgt	r6, [r0], #0x01		/* Fetch 3rd byte */
	movle	r6, #0x00
	/* Combine the three bytes depending on endianness and alignment */
#if BYTE_ORDER != LITTLE_ENDIAN
	orreq	r2, r5, r4, lsl #8
	orreq	r2, r2, r6, lsl #24
	orrne	r2, r4, r5, lsl #8
	orrne	r2, r2, r6, lsl #16
#else
	orreq	r2, r4, r5, lsl #8
	orreq	r2, r2, r6, lsl #16
	orrne	r2, r5, r4, lsl #8
	orrne	r2, r2, r6, lsl #24
#endif
	subs	r1, r1, r7		/* Update length */
	beq	.Lin_cksum_next		/* All done? */

	/* Buffer is now word aligned */
.Lcksumdata_wordaligned:

#if __ARM_VFP__ >= 3

	cmp		r1, #512	// do this if r1 is at least 512
	blt		9f

	EnableVFP

	and		r3, r1, #~0x3f

	vpush	{q0-q7}

	// move r2 to s16 (q4) for neon computation
	veor        q4, q4, q4
	vld1.32     {q0-q1}, [r0]!
	vmov        s16, r2
	vld1.32     {q2-q3}, [r0]!

	// pre-decrement size by 64
	subs	r3, r3, #0x80

	vpadal.u32  q4, q0
	vld1.32     {q0}, [r0]!
	vpaddl.u32  q5, q1
	vld1.32     {q1}, [r0]!
	vpaddl.u32  q6, q2
	vld1.32     {q2}, [r0]!
	vpaddl.u32  q7, q3
	vld1.32     {q3}, [r0]!

0:
	subs	r3, r3, #0x40		// decrement size by 64

	vpadal.u32  q4, q0
	vld1.32     {q0}, [r0]!
	vpadal.u32  q5, q1
	vld1.32     {q1}, [r0]!
	vpadal.u32  q6, q2
	vld1.32     {q2}, [r0]!
	vpadal.u32  q7, q3
	vld1.32     {q3}, [r0]!

	bgt		0b

	vpadal.u32  q4, q0
	vpadal.u32  q5, q1
	vpadal.u32  q6, q2
	vpadal.u32  q7, q3

	vpadal.u32  q4, q5
	vpadal.u32  q6, q7
	vpadal.u32  q4, q6
	vadd.i64    d8, d9

	vpaddl.u32  d8, d8
	vpaddl.u32  d8, d8
	vpaddl.u32  d8, d8

	vmov    r2, s16

	vpop   {q0-q7}

	ands    r1, r1, #0x3f		// residual bytes
	beq 	.Lin_cksum_next
	
9:

#endif /* __ARM_VFP__ >= 3 */

	subs	r1, r1, #0x40
	blt	.Lcksumdata_bigloop_end

.Lcksumdata_bigloop:
	ldmia	r0!, {r3, r4, r5, r6}
	adds	r2, r2, r3
	adcs	r2, r2, r4
	adcs	r2, r2, r5
	ldmia	r0!, {r3, r4, r5, r7}
	adcs	r2, r2, r6
	adcs	r2, r2, r3
	adcs	r2, r2, r4
	adcs	r2, r2, r5
	ldmia	r0!, {r3, r4, r5, r6}
	adcs	r2, r2, r7
	adcs	r2, r2, r3
	adcs	r2, r2, r4
	adcs	r2, r2, r5
	ldmia	r0!, {r3, r4, r5, r7}
	adcs	r2, r2, r6
	adcs	r2, r2, r3
	adcs	r2, r2, r4
	adcs	r2, r2, r5
	adcs	r2, r2, r7
	adc	r2, r2, #0x00
	subs	r1, r1, #0x40
	bge	.Lcksumdata_bigloop
.Lcksumdata_bigloop_end:

	adds	r1, r1, #0x40
	beq	.Lin_cksum_next

	cmp	r1, #0x20
	
	blt	.Lcksumdata_less_than_32
	ldmia	r0!, {r3, r4, r5, r6}
	adds	r2, r2, r3
	adcs	r2, r2, r4
	adcs	r2, r2, r5
	ldmia	r0!, {r3, r4, r5, r7}
	adcs	r2, r2, r6
	adcs	r2, r2, r3
	adcs	r2, r2, r4
	adcs	r2, r2, r5
	adcs	r2, r2, r7
	adc	r2, r2, #0x00
	subs	r1, r1, #0x20
	beq	.Lin_cksum_next

.Lcksumdata_less_than_32:
	/* There are less than 32 bytes left */
	and	r3, r1, #0x18
	rsb	r4, r3, #0x18
	sub	r1, r1, r3
	adds	r4, r4, r4, lsr #1	/* Side effect: Clear carry flag */
	addne	pc, pc, r4

/*
 * Note: We use ldm here, even on Xscale, since the combined issue/result
 * latencies for ldm and ldrd are the same. Using ldm avoids needless #ifdefs.
 */
	/* At least 24 bytes remaining... */
	ldmia	r0!, {r4, r5}
	nop
	adcs	r2, r2, r4
	adcs	r2, r2, r5

	/* At least 16 bytes remaining... */
	ldmia	r0!, {r4, r5}
	adcs	r2, r2, r4
	adcs	r2, r2, r5

	/* At least 8 bytes remaining... */
	ldmia	r0!, {r4, r5}
	adcs	r2, r2, r4
	adcs	r2, r2, r5

	/* Less than 8 bytes remaining... */
	adc	r2, r2, #0x00
	subs	r1, r1, #0x04
	blt	.Lcksumdata_lessthan4

	ldr	r4, [r0], #0x04
	sub	r1, r1, #0x04
	adds	r2, r2, r4
	adc	r2, r2, #0x00

	/* Deal with < 4 bytes remaining */
.Lcksumdata_lessthan4:
	adds	r1, r1, #0x04
	beq	.Lin_cksum_next

	/* Deal with 1 to 3 remaining bytes, possibly misaligned */
.Lcksumdata_endgame:
	ldrb	r3, [r0]		/* Fetch first byte */
	cmp	r1, #0x02
	ldrbge	r4, [r0, #0x01]		/* Fetch 2nd and 3rd as necessary */
	movlt	r4, #0x00
	ldrbgt	r5, [r0, #0x02]
	movle	r5, #0x00
	/* Combine the three bytes depending on endianness and alignment */
	tst	r0, #0x01
#if BYTE_ORDER != LITTLE_ENDIAN
	orreq	r3, r4, r3, lsl #8
	orreq	r3, r3, r5, lsl #24
	orrne	r3, r3, r4, lsl #8
	orrne	r3, r3, r5, lsl #16
#else
	orreq	r3, r3, r4, lsl #8
	orreq	r3, r3, r5, lsl #16
	orrne	r3, r4, r3, lsl #8
	orrne	r3, r3, r5, lsl #24
#endif
	adds	r2, r2, r3
	adc	r2, r2, #0x00

.Lin_cksum_next:
	tst	r11, #0x01
	movne	r2, r2, ror #8
	adds	r8, r8, r2
	adc	r8, r8, #0x00
	cmp	ip, #00
	bne	.Lin_cksum_loop
	
	mov	r1, #0xff
	orr	r1, r1, #0xff00
	and	r0, r8, r1
	add	r0, r0, r8, lsr #16
	add	r0, r0, r0, lsr #16
	and	r0, r0, r1
	/*
	 * If we were to 1's complement it (XOR with 0xffff):
	 *
	 * eor	r0, r0, r1
	 */

	ldmfd	sp!, {r4-r11, pc}

.Lin_cksum_whoops:
	adr	r0, .Lin_cksum_whoops_str
	bl	#CKSUM_ERR
	mov	r0, #-1

	ldmfd	sp!, {r4-r11, pc}

.Lin_cksum_whoops_str:
	.asciz	"os_cpu_in_cksum_mbuf: out of data\n"
	.align	5

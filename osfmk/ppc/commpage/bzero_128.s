/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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

#define	ASSEMBLER
#include <sys/appleapiopts.h>
#include <ppc/asm.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>

        .text
        .align	2
        .globl	EXT(bzero_128)
        

// *********************
// * B Z E R O _ 1 2 8 *
// *********************
//
// For 64-bit processors with a 128-byte cache line.
//
// Register use:
//		r0 = zero
//		r3 = original ptr, not changed since memset returns it
//		r4 = count of bytes to set
//		r9 = working operand ptr
// We do not touch r2 and r10-r12, which some callers depend on.

        .align	5
bzero_128:						// void	bzero(void *b, size_t len);
        cmplwi	cr7,r4,128		// too short for DCBZ128?
        li		r0,0			// get a 0
        neg		r5,r3			// start to compute #bytes to align
        mr		r9,r3			// make copy of operand ptr (can't change r3)
        blt		cr7,Ltail		// length < 128, too short for DCBZ

// At least 128 bytes long, so compute alignment and #cache blocks.

        andi.	r5,r5,0x7F		// r5 <-  #bytes to 128-byte align
        sub		r4,r4,r5		// adjust length
        srwi	r8,r4,7			// r8 <- 128-byte chunks
        rlwinm	r4,r4,0,0x7F	// mask length down to remaining bytes
        mtctr	r8				// set up loop count
        beq		Ldcbz			// skip if already aligned (r8!=0)
        
// 128-byte align

        mtcrf	0x01,r5			// start to move #bytes to align to cr6 and cr7
        cmpwi	cr1,r8,0		// any 128-byte cache lines to 0?
        mtcrf	0x02,r5
        
        bf		31,1f			// byte?
        stb		r0,0(r9)
        addi	r9,r9,1
1:
        bf		30,2f			// halfword?
        sth		r0,0(r9)
        addi	r9,r9,2
2:
        bf		29,3f			// word?
        stw		r0,0(r9)
        addi	r9,r9,4
3:
        bf		28,4f			// doubleword?
        std		r0,0(r9)
        addi	r9,r9,8
4:
        bf		27,5f			// quadword?
        std		r0,0(r9)
        std		r0,8(r9)
        addi	r9,r9,16
5:
        bf		26,6f			// 32-byte chunk?
        std		r0,0(r9)
        std		r0,8(r9)
        std		r0,16(r9)
        std		r0,24(r9)
        addi	r9,r9,32
6:
        bf		25,7f			// 64-byte chunk?
        std		r0,0(r9)
        std		r0,8(r9)
        std		r0,16(r9)
        std		r0,24(r9)
        std		r0,32(r9)
        std		r0,40(r9)
        std		r0,48(r9)
        std		r0,56(r9)
        addi	r9,r9,64
7:
        beq		cr1,Ltail		// no chunks to dcbz128

// Loop doing 128-byte version of DCBZ instruction.
// NB: if the memory is cache-inhibited, the kernel will clear cr7
// when it emulates the alignment exception.  Eventually, we may want
// to check for this case.

Ldcbz:
        dcbz128	0,r9			// zero another 32 bytes
        addi	r9,r9,128
        bdnz	Ldcbz

// Store trailing bytes.
//		r0 = 0
//		r4 = count
//		r9 = ptr

Ltail:
        srwi.	r5,r4,4			// r5 <- 16-byte chunks to 0
        mtcrf	0x01,r4			// remaining byte count to cr7
        mtctr	r5
        beq		2f				// skip if no 16-byte chunks
1:								// loop over 16-byte chunks
        std		r0,0(r9)
        std		r0,8(r9)
        addi	r9,r9,16
        bdnz	1b
2:
        bf		28,4f			// 8-byte chunk?
        std		r0,0(r9)
        addi	r9,r9,8
4:
        bf		29,5f			// word?
        stw		r0,0(r9)
        addi	r9,r9,4
5:
        bf		30,6f			// halfword?
        sth		r0,0(r9)
        addi	r9,r9,2
6:
        bflr	31				// byte?
        stb		r0,0(r9)
        blr

        COMMPAGE_DESCRIPTOR(bzero_128,_COMM_PAGE_BZERO,kCache128+k64Bit,0,kCommPageMTCRF)

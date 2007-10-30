/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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

#include <sys/appleapiopts.h>
#include <ppc/asm.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>

        .text
        .align	2
        

// *******************
// * B Z E R O _ 3 2 *
// *******************
//
// For 32-bit processors with a 32-byte cache line.
//
// Register use:
//		r0 = zero
//		r3 = original ptr, not changed since memset returns it
//		r4 = count of bytes to set
//		r9 = working operand ptr
// We do not touch r2 and r10-r12, which some callers depend on.

        .align	5
bzero_32:						// void	bzero(void *b, size_t len);
        cmplwi	cr7,r4,32		// too short for DCBZ?
        li		r0,0			// get a 0
        neg		r5,r3			// start to compute #bytes to align
        mr		r9,r3			// make copy of operand ptr (can't change r3)
        blt		cr7,Ltail		// length < 32, too short for DCBZ

// At least 32 bytes long, so compute alignment and #cache blocks.

        andi.	r5,r5,0x1F		// r5 <-  #bytes to 32-byte align
        sub		r4,r4,r5		// adjust length
        srwi	r8,r4,5			// r8 <- #32-byte chunks
        cmpwi	cr1,r8,0		// any chunks?
        mtctr	r8				// set up loop count
        beq		1f				// skip if already 32-byte aligned (r8!=0)
        
// 32-byte align.  We just store 32 0s, rather than test and use conditional
// branches.  We've already stored the first few bytes above.

        stw		r0,0(r9)
        stw		r0,4(r9)
        stw		r0,8(r9)
        stw		r0,12(r9)
        stw		r0,16(r9)
        stw		r0,20(r9)
        stw		r0,24(r9)
        stw		r0,28(r9)
        add		r9,r9,r5		// now rp is 32-byte aligned
        beq		cr1,Ltail		// skip if no 32-byte chunks

// Loop doing 32-byte version of DCBZ instruction.
// NB: we take alignment exceptions on cache-inhibited memory.
// The kernel could be changed to zero cr7 when emulating a
// dcbz (as it does on 64-bit processors), so we could avoid all
// but the first.

1:
        andi.	r5,r4,0x1F		// will there be trailing bytes?
        b		2f
        .align	4
2:
        dcbz	0,r9			// zero another 32 bytes
        addi	r9,r9,32
        bdnz	2b
        
        beqlr					// no trailing bytes

// Store trailing bytes.

Ltail:
        andi.	r5,r4,0x10		// test bit 27 separately
        mtcrf	0x01,r4			// remaining byte count to cr7
        
        beq		2f				// no 16-byte chunks
        stw		r0,0(r9)
        stw		r0,4(r9)
        stw		r0,8(r9)
        stw		r0,12(r9)
        addi	r9,r9,16
2:
        bf		28,4f			// 8-byte chunk?
        stw		r0,0(r9)
        stw		r0,4(r9)
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

	COMMPAGE_DESCRIPTOR(bzero_32,_COMM_PAGE_BZERO,kCache32,0,kCommPage32)

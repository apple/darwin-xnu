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
/* =======================================
 * BCOPY, MEMCPY, and MEMMOVE for Mac OS X
 * =======================================
 *
 * Version of 2/20/2003, tuned for G3.
 *
 * Register usage.  Note we use R2, so this code will not run in a PEF/CFM
 * environment.
 *
 *   r0  = "w7" or temp
 *   r2  = "w8"
 *   r3  = not used, as memcpy and memmove return 1st parameter as a value
 *   r4  = source ptr ("rs")
 *   r5  = count of bytes to move ("rc")
 *   r6  = "w1"
 *   r7  = "w2"
 *   r8  = "w3"
 *   r9  = "w4"
 *   r10 = "w5"
 *   r11 = "w6"
 *   r12 = destination ptr ("rd")
 * f0-f3 = used for moving 8-byte aligned data
 */
#define rs	r4		// NB: we depend on rs==r4 in "lswx" instructions
#define rd	r12
#define rc	r5

#define w1	r6
#define w2	r7
#define w3	r8
#define	w4	r9
#define	w5	r10
#define	w6	r11
#define	w7	r0
#define	w8	r2

#define	ASSEMBLER
#include <sys/appleapiopts.h>
#include <ppc/asm.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>

        .text


#define	kLong	33					// too long for string ops


// Main entry points.

        .align 	5
bcopy_g3:							// void bcopy(const void *src, void *dst, size_t len)
        cmplwi	rc,kLong			// length > 32 bytes?
        sub		w1,r4,r3			// must move in reverse if (rd-rs)<rc
        mr		rd,r4				// start to move source & dest to canonic spot
        bge		LLong0				// skip if long operand
        mtxer	rc					// set length for string ops
        lswx	r5,0,r3				// load bytes into r5-r12
        stswx	r5,0,r4				// store them
        blr

// NB: memcpy() and memmove() must follow bcopy() by 32 bytes, for comm page.

        .align	5
Lmemcpy_g3:							// void* memcpy(void *dst, void *src, size_t len)
Lmemmove_g3:						// void* memmove(void *dst, const void *src, size_t len)
        cmplwi	rc,kLong			// length > 32 bytes?
        sub		w1,r3,rs			// must move in reverse if (rd-rs)<rc
        mr		rd,r3				// must leave r3 alone, it is return value for memcpy etc
        bge		LLong1				// longer than 32 bytes
        mtxer	rc					// set length for string ops
        lswx	r5,0,r4				// load bytes into r5-r12
        stswx	r5,0,r3				// store them
        blr

// Long operands (more than 32 bytes.)
//		w1  = (rd-rs), used to check for alignment

LLong0:								// enter from bcopy()
        mr		rs,r3				// must leave r3 alone (it is return value for memcpy)
LLong1:								// enter from memcpy() and memmove()
        cmplw	cr1,w1,rc			// set cr1 blt iff we must move reverse
        rlwinm	r0,w1,0,0x3			// are operands relatively word-aligned?
        neg		w2,rd				// prepare to align destination
        cmpwi	cr5,r0,0			// set cr5 beq if relatively word aligned
        blt		cr1,LLongReverse	// handle reverse move
        andi.	w4,w2,3				// w4 <- #bytes to word align destination
        beq		cr5,LLongFloat		// relatively aligned so use FPRs
        sub		rc,rc,w4			// adjust count for alignment
        srwi	r0,rc,5				// get #chunks to xfer (>=1)
        rlwinm	rc,rc,0,0x1F		// mask down to leftover bytes
        mtctr	r0					// set up loop count
        beq		1f					// dest already word aligned
    
// Word align the destination.
        
        mtxer	w4					// byte count to xer
        cmpwi	r0,0				// any chunks to xfer?
        lswx	w1,0,rs				// move w4 bytes to align dest
        add		rs,rs,w4
        stswx	w1,0,rd
        add		rd,rd,w4
        beq-	2f					// pathologic case, no chunks to xfer

// Forward, unaligned loop.

1:
        lwz		w1,0(rs)
        lwz		w2,4(rs)
        lwz		w3,8(rs)
        lwz		w4,12(rs)
        lwz		w5,16(rs)
        lwz		w6,20(rs)
        lwz		w7,24(rs)
        lwz		w8,28(rs)
        addi	rs,rs,32
        stw		w1,0(rd)
        stw		w2,4(rd)
        stw		w3,8(rd)
        stw		w4,12(rd)
        stw		w5,16(rd)
        stw		w6,20(rd)
        stw		w7,24(rd)
        stw		w8,28(rd)
        addi	rd,rd,32
        bdnz	1b
2:									// rc = remaining bytes (0-31)
        mtxer	rc					// set up count for string ops
        mr		r0,rd				// move dest ptr out of the way
        lswx	r5,0,rs				// load xer bytes into r5-r12 (rs==r4)
        stswx	r5,0,r0				// store them
        blr
        


// Forward, aligned loop.  We use FPRs.

LLongFloat:
        andi.	w4,w2,7				// W4 <- #bytes to doubleword-align destination
        sub		rc,rc,w4			// adjust count for alignment
        srwi	r0,rc,5				// number of 32-byte chunks to xfer
        rlwinm	rc,rc,0,0x1F		// mask down to leftover bytes
        mtctr	r0					// set up loop count
        beq		1f					// dest already doubleword aligned
    
// Doubleword align the destination.
        
        mtxer	w4					// byte count to xer
        cmpwi	r0,0				// any chunks to xfer?
        lswx	w1,0,rs				// move w4 bytes to align dest
        add		rs,rs,w4
        stswx	w1,0,rd
        add		rd,rd,w4
        beq-	2f					// pathologic case, no chunks to xfer
1:									// loop over 32-byte chunks
        lfd		f0,0(rs)
        lfd		f1,8(rs)
        lfd		f2,16(rs)
        lfd		f3,24(rs)
        addi	rs,rs,32
        stfd	f0,0(rd)
        stfd	f1,8(rd)
        stfd	f2,16(rd)
        stfd	f3,24(rd)
        addi	rd,rd,32
        bdnz	1b
2:									// rc = remaining bytes (0-31)
        mtxer	rc					// set up count for string ops
        mr		r0,rd				// move dest ptr out of the way
        lswx	r5,0,rs				// load xer bytes into r5-r12 (rs==r4)
        stswx	r5,0,r0				// store them
        blr

        
// Long, reverse moves.
//		cr5 = beq if relatively word aligned

LLongReverse:
        add		rd,rd,rc			// point to end of operands + 1
        add		rs,rs,rc
        beq		cr5,LReverseFloat	// aligned operands so can use FPRs
        srwi	r0,rc,5				// get chunk count
        rlwinm	rc,rc,0,0x1F		// mask down to leftover bytes
        mtctr	r0					// set up loop count
        mtxer	rc					// set up for trailing bytes
1:
        lwz		w1,-4(rs)
        lwz		w2,-8(rs)
        lwz		w3,-12(rs)
        lwz		w4,-16(rs)
        stw		w1,-4(rd)
        lwz		w5,-20(rs)
        stw		w2,-8(rd)
        lwz		w6,-24(rs)
        stw		w3,-12(rd)
        lwz		w7,-28(rs)
        stw		w4,-16(rd)
        lwzu	w8,-32(rs)
        stw		w5,-20(rd)
        stw		w6,-24(rd)
        stw		w7,-28(rd)
        stwu	w8,-32(rd)
        bdnz	1b

        sub		r4,rs,rc			// point to 1st (leftmost) leftover byte (0..31)
        sub		r0,rd,rc			// move dest ptr out of way
        lswx	r5,0,r4				// load xer bytes into r5-r12
        stswx	r5,0,r0				// store them
        blr


// Long, reverse aligned moves.  We use FPRs.

LReverseFloat:
        andi.	w4,rd,7				// W3 <- #bytes to doubleword-align destination
        sub		rc,rc,w4			// adjust count for alignment
        srwi	r0,rc,5				// number of 32-byte chunks to xfer
        rlwinm	rc,rc,0,0x1F		// mask down to leftover bytes
        mtctr	r0					// set up loop count
        beq		1f					// dest already doubleword aligned
    
// Doubleword align the destination.
        
        mtxer	w4					// byte count to xer
        cmpwi	r0,0				// any chunks to xfer?
        sub		rs,rs,w4			// point to 1st bytes to xfer
        sub		rd,rd,w4
        lswx	w1,0,rs				// move w3 bytes to align dest
        stswx	w1,0,rd
        beq-	2f					// pathologic case, no chunks to xfer
1:
        lfd		f0,-8(rs)
        lfd		f1,-16(rs)
        lfd		f2,-24(rs)
        lfdu	f3,-32(rs)
        stfd	f0,-8(rd)
        stfd	f1,-16(rd)
        stfd	f2,-24(rd)
        stfdu	f3,-32(rd)
        bdnz	1b
2:									// rc = remaining bytes (0-31)
        mtxer	rc					// set up count for string ops
        sub		r4,rs,rc			// point to 1st (leftmost) leftover byte (0..31)
        sub		r0,rd,rc			// move dest ptr out of way
        lswx	r5,0,r4				// load xer bytes into r5-r12
        stswx	r5,0,r0				// store them
        blr

	COMMPAGE_DESCRIPTOR(bcopy_g3,_COMM_PAGE_BCOPY,0,k64Bit+kHasAltivec,kCommPage32)

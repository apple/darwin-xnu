/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/* =======================================
 * BCOPY, MEMCPY, and MEMMOVE for Mac OS X
 * =======================================
 *
 * Version of 2/20/2003, for a hypothetic 64-bit processor without Altivec.
 * This version might be used bringing up new processors, with known
 * Altivec bugs that need to be worked around.  It is not particularly well
 * optimized.
 *
 * For 64-bit processors with a 128-byte cache line, running in either 
 * 32- or 64-bit mode.  This is written for 32-bit execution, the kernel
 * will translate to 64-bit code when it compiles the 64-bit commpage.
 *
 * Register usage.  Note we use R2, so this code will not run in a PEF/CFM
 * environment.
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
 */
#define rs	r4
#define rd	r12
#define rc	r5
#define	rv	r2

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

#define	kLong		64				// too long for inline loopless code


// Main entry points.

        .align 	5
bcopy_64:							// void bcopy(const void *src, void *dst, size_t len)
        cmplwi	rc,kLong			// short or long?
        sub		w1,r4,r3			// must move in reverse if (rd-rs)<rc
        cmplw	cr1,w1,rc			// set cr1 blt iff we must move reverse
        mr		rd,r4				// start to move registers to canonic spot
        mr		rs,r3
        blt		LShort				// handle short operands
        dcbt	0,r3				// touch in destination
        b		LLong				// join medium/long operand code

// NB: memmove() must be 8 words past bcopy(), to agree with comm page addresses.
        
        .align	5
Lmemcpy_g4:							// void* memcpy(void *dst, void *src, size_t len)
Lmemmove_g4:						// void* memmove(void *dst, const void *src, size_t len)
        cmplwi	rc,kLong			// short or long?
        sub		w1,r3,r4			// must move in reverse if (rd-rs)<rc
        dcbt	0,r4				// touch in the first line of source
        cmplw	cr1,w1,rc			// set cr1 blt iff we must move reverse
        mr		rd,r3				// must leave r3 alone, it is return value for memcpy etc
        bge		LLong				// handle medium or long operands

// Handle short operands.
        
LShort:
        mtcrf	0x02,rc				// put length bits 26-27 in cr6 (faster one cr at a time)
        mtcrf	0x01,rc				// put length bits 28-31 in cr7
        blt		cr1,LShortReverse
        
// Forward short operands.  This is the most frequent case, so it is inline.

LShort64:							// enter to xfer last 64 bytes
        bf		26,0f				// 64-byte chunk to xfer?
        ld		w1,0(rs)
        ld		w2,8(rs)
        ld		w3,16(rs)
        ld		w4,24(rs)
        addi	rs,rs,32
        std		w1,0(rd)
        std		w2,8(rd)
        std		w3,16(rd)
        std		w4,24(rd)
        addi	rd,rd,32
0:
        bf		27,1f				// quadword to move?
        ld		w1,0(rs)
        ld		w2,8(rs)
        addi	rs,rs,16
        std		w1,0(rd)
        std		w2,8(rd)
        addi	rd,rd,16
1:
        bf		28,2f				// doubleword?
        ld		w1,0(rs)
        addi	rs,rs,8
        std		w1,0(rd)
        addi	rd,rd,8
2:
        bf		29,3f				// word?
        lwz		w1,0(rs)
        addi	rs,rs,4
        stw		w1,0(rd)
        addi	rd,rd,4
3:
        bf		30,4f				// halfword to move?
        lhz		w1,0(rs)
        addi	rs,rs,2
        sth		w1,0(rd)
        addi	rd,rd,2
4:
        bflr	31					// skip if no odd byte
        lbz		w1,0(rs)
        stb		w1,0(rd)
        blr
        
        
// Handle short reverse operands.
//		cr6 = bits 26-27 of length
//		cr7 = bits 28-31 of length      

LShortReverse:
        add		rs,rs,rc			// adjust ptrs for reverse move
        add		rd,rd,rc
LShortReverse64:					// enter to xfer last 64 bytes
        bf		26,0f				// 64-byte chunk to xfer?
        ld		w1,-8(rs)
        ld		w2,-16(rs)
        ld		w3,-24(rs)
        ldu		w4,-32(rs)
        std		w1,-8(rd)
        std		w2,-16(rd)
        std		w3,-24(rd)
        stdu	w4,-32(rd)
0:
        bf		27,1f				// quadword to move?
        ld		w1,-8(rs)
        ldu		w2,-16(rs)
        std		w1,-8(rd)
        stdu	w2,-16(rd)
1:
        bf		28,2f				// doubleword?
        ldu		w1,-8(rs)
        stdu	w1,-8(rd)
2:
        bf		29,3f				// word?
        lwzu	w1,-4(rs)
        stwu	w1,-4(rd)
3:
        bf		30,4f				// halfword to move?
        lhzu	w1,-2(rs)
        sthu	w1,-2(rd)
4:
        bflr	31					// done if no odd byte
        lbz 	w1,-1(rs)			// no update
        stb 	w1,-1(rd)
        blr
        

// Long operands.
//     cr1 = blt iff we must move reverse

        .align	4
LLong:
        dcbtst	0,rd				// touch in destination
        neg		w3,rd				// start to compute #bytes to align destination
        andi.	w6,w3,7				// w6 <- #bytes to 8-byte align destination
        blt		cr1,LLongReverse	// handle reverse moves
        mtctr	w6					// set up for loop to align destination
        sub		rc,rc,w6			// adjust count
        beq		LAligned			// destination already 8-byte aligned
1:
        lbz		w1,0(rs)
        addi	rs,rs,1
        stb		w1,0(rd)
        addi	rd,rd,1
        bdnz	1b
        
// Destination is 8-byte aligned.

LAligned:
        srwi.	w2,rc,6				// w2 <- count of 64-byte chunks
        mtcrf	0x02,rc				// leftover byte count to cr (faster one cr at a time)
        mtcrf	0x01,rc				// put length bits 28-31 in cr7
        beq		LShort64			// no 64-byte chunks
        mtctr	w2
        b		1f
        
// Loop moving 64-byte chunks.

        .align	5
1:
        ld		w1,0(rs)
        ld		w2,8(rs)
        ld		w3,16(rs)
        ld		w4,24(rs)
        ld		w5,32(rs)
        ld		w6,40(rs)
        ld		w7,48(rs)
        ld		w8,56(rs)
        addi	rs,rs,64
        std		w1,0(rd)
        std		w2,8(rd)
        std		w3,16(rd)
        std		w4,24(rd)
        std		w5,32(rd)
        std		w6,40(rd)
        std		w7,48(rd)
        std		w8,56(rd)
        addi	rd,rd,64
        bdnz	1b
        
        b		LShort64

        
// Handle reverse moves.

LLongReverse:
        add		rd,rd,rc				// point to end of operands
        add		rs,rs,rc
        andi.	r0,rd,7					// is destination 8-byte aligned?
        sub		rc,rc,r0				// adjust count
        mtctr	r0						// set up for byte loop
        beq		LRevAligned				// already aligned
        
1:
        lbzu	w1,-1(rs)
        stbu	w1,-1(rd)
        bdnz	1b

// Destination is 8-byte aligned.

LRevAligned:
        srwi.	w2,rc,6				// w2 <- count of 64-byte chunks
        mtcrf	0x02,rc				// leftover byte count to cr (faster one cr at a time)
        mtcrf	0x01,rc				// put length bits 28-31 in cr7
        beq		LShortReverse64		// no 64-byte chunks
        mtctr	w2
        b		1f

// Loop over 64-byte chunks (reverse).

        .align	5
1:
        ld		w1,-8(rs)
        ld		w2,-16(rs)
        ld		w3,-24(rs)
        ld		w4,-32(rs)
        ld		w5,-40(rs)
        ld		w6,-48(rs)
        ld		w7,-56(rs)
        ldu		w8,-64(rs)
        std		w1,-8(rd)
        std		w2,-16(rd)
        std		w3,-24(rd)
        std		w4,-32(rd)
        std		w5,-40(rd)
        std		w6,-48(rd)
        std		w7,-56(rd)
        stdu	w8,-64(rd)
        bdnz	1b
        
        b		LShortReverse64

	COMMPAGE_DESCRIPTOR(bcopy_64,_COMM_PAGE_BCOPY,k64Bit,kHasAltivec,kCommPageBoth+kPort32to64)

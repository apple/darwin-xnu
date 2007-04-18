/*
 * Copyright (c) 2002 Apple Computer, Inc. All rights reserved.
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

#include <ppc/asm.h>
#include <ppc/exception.h>
#include <assym.s>

        .text
        .align	2
        .globl	_memset
        .globl	_bzero
        .globl	_bzero_nc
        .globl	_bzero_phys


// ***********************
// * B Z E R O _ P H Y S *
// ***********************
//
// void bzero_phys(addr64_t phys_addr, uint32_t length);
//
// Takes a phys addr in (r3,r4), and length in r5.  We leave cache on.

        .align	5
LEXT(bzero_phys)
        mflr	r12				// save return address
        rlwinm	r3,r3,0,1,0		// coallesce long-long in (r3,r4) into reg64_t in r3
        rlwimi	r3,r4,0,0,31
        mr		r4,r5			// put length where bzero() expects it
        bl		EXT(ml_set_physical_get_ffs)	// turn DR off, SF on, features in cr6, old MSR in r11
        bl		EXT(bzero)		// use normal bzero() routine
        mtlr	r12				// restore return
        b		EXT(ml_restore)		// restore MSR, turning DR on and SF off
        

// *******************
// * B Z E R O _ N C *
// *******************
//
//	void bzero_nc(char	*addr, unsigned int length);
//
// For use with uncached memory.  Doesn't seem to be used at all, so probably not
// performance critical.  NB: we must avoid unaligned stores, because some
// machines (eg, 970) take alignment exceptions on _any_ unaligned op to uncached
// memory.  Of course, we must also avoid dcbz.

LEXT(bzero_nc)
        cmplwi	cr1,r4,20		// too short to bother with 16-byte loops?
        cmplwi	cr7,r4,0		// check for (len==0)
        li		r6,0			// get a 0
        bge		cr1,bznc1		// skip if length >=20
        mtctr	r4				// set up byte loop
        beqlr--	cr7				// done if len=0
        
// Short operands, loop over bytes.

bznc0:
        stb		r6,0(r3)
        addi	r3,r3,1
        bdnz	bznc0
        blr
        
// Handle operands long enough to do doubleword stores; we must doubleword
// align, to avoid alignment exceptions.

bznc1:
        neg		r7,r3			// start to compute #bytes to align
        mfsprg	r10,2			// get feature flags
        andi.	r0,r7,7			// get #bytes to doubleword align
        mr		r5,r3			// make copy of operand ptr as bcopy expects
        mtcrf	0x02,r10		// put pf64Bitb etc in cr6
        beq		bzero_tail		// already doubleword aligned
        sub		r4,r4,r0		// adjust count
        mtctr	r0				// set up loop
bznc2:							// zero bytes until doubleword aligned
        stb		r6,0(r5)
        addi	r5,r5,1
        bdnz	bznc2
        b		bzero_tail		// join bzero, now that r5 is aligned
        

// *************     ***************
// * B Z E R O * and * M E M S E T *
// *************     ***************
//
// void *   memset(void *b, int c, size_t len);
// void		bzero(void *b, size_t len);
//
// These routines support G3, G4, and the 970, and run in both 32 and
// 64-bit mode.  Lengths (size_t) are always 32 bits.
//
// Register use:
//    r0 = temp
//    r2 = temp
//    r3 = original ptr, not changed since memset returns it
//    r4 = count of bytes to set
//    r5 = working operand ptr ("rp")
//    r6 = value to store (usually 0)
// r7-r9 = temps
//   r10 = feature flags
//   r11 = old MSR (if bzero_phys)
//   r12 = return address (if bzero_phys)
//   cr6 = feature flags (pf64Bit, pf128Byte, and pf32Byte)

        .align	5
LEXT(memset)					// void *   memset(void *b, int c, size_t len);
        andi.	r6,r4,0xFF		// copy value to working register, test for 0
        mr		r4,r5			// move length to working register
        bne--	memset1			// skip if nonzero
LEXT(bzero)						// void	bzero(void *b, size_t len);
        dcbtst	0,r3			// touch in 1st cache block
        mfsprg	r10,2			// get features
        li		r6,0			// get a 0
        neg		r7,r3			// start to compute #bytes to align
        andi.	r0,r10,pf128Byte+pf32Byte // get cache line size
        mtcrf	0x02,r10		// put pf128Byte etc in cr6
        cmplw	r4,r0			// operand length >= cache line size?
        mr		r5,r3			// make copy of operand ptr (can't change r3)
        blt		bzero_tail		// too short for dcbz (or dcbz128)
        rlwinm	r0,r7,0,0x1F	// get #bytes to  32-byte align
        rlwinm	r9,r7,0,0x7F	// get #bytes to 128-byte align
        bt++	pf128Byteb,bzero_128 // skip if 128-byte processor

// Operand length >=32 and cache line size is 32.
//		r0 = #bytes to 32-byte align
//		r4 = length
//		r5 = ptr to operand
//		r6 = 0

        sub		r2,r4,r0		// adjust length
        cmpwi	cr1,r0,0		// already 32-byte aligned?
        srwi.	r8,r2,5			// get #32-byte chunks
        beq		bzero_tail		// not long enough to dcbz
        mtctr	r8				// set up loop count
        rlwinm	r4,r2,0,27,31	// mask down to leftover byte count
        beq		cr1,bz_dcbz32 	// skip if already 32-byte aligned
        
// 32-byte align.  We just store 32 0s, rather than test and use conditional
// branches.  This is usually faster, because there are no mispredicts.

        stw		r6,0(r5)		// zero next 32 bytes
        stw		r6,4(r5)
        stw		r6,8(r5)
        stw		r6,12(r5)
        stw		r6,16(r5)
        stw		r6,20(r5)
        stw		r6,24(r5)
        stw		r6,28(r5)
        add		r5,r5,r0		// now r5 is 32-byte aligned
        b		bz_dcbz32

// Loop doing 32-byte version of DCBZ instruction.

        .align	4				// align the inner loop
bz_dcbz32:
        dcbz	0,r5			// zero another 32 bytes
        addi	r5,r5,32
        bdnz	bz_dcbz32

// Store trailing bytes.  This routine is used both by bzero and memset.
//		r4 = #bytes to store (may be large if memset)
//		r5 = address
//		r6 = value to store (in all 8 bytes)
//     cr6 = pf64Bit etc flags

bzero_tail:
        srwi.	r0,r4,4			// get #(16-byte-chunks)
        mtcrf	0x01,r4			// remaining byte count to cr7
        beq		bzt3			// no 16-byte chunks
        mtctr	r0				// set up loop count
        bt++	pf64Bitb,bzt2	// skip if 64-bit processor
        b		bzt1
        .align	5
bzt1:							// loop over 16-byte chunks on 32-bit processor
        stw		r6,0(r5)
        stw		r6,4(r5)
        stw		r6,8(r5)
        stw		r6,12(r5)
        addi	r5,r5,16
        bdnz	bzt1
        b		bzt3
        .align	5
bzt2:							// loop over 16-byte chunks on 64-bit processor
        std		r6,0(r5)
        std		r6,8(r5)
        addi	r5,r5,16
        bdnz	bzt2
        bf		28,bzt4			// 8-byte chunk?
        std		r6,0(r5)
        addi	r5,r5,8
        b		bzt4
bzt3:
        bf		28,bzt4			// 8-byte chunk?
        stw		r6,0(r5)
        stw		r6,4(r5)
        addi	r5,r5,8
bzt4:
        bf		29,bzt5			// word?
        stw		r6,0(r5)
        addi	r5,r5,4
bzt5:
        bf		30,bzt6			// halfword?
        sth		r6,0(r5)
        addi	r5,r5,2
bzt6:
        bflr	31				// byte?
        stb		r6,0(r5)
        blr
        
// Operand length is >=128 and cache line size is 128. We assume that
// because the linesize is 128 bytes, this is a 64-bit processor.
//		r4 = length
//		r5 = ptr to operand
//		r6 = 0
//		r7 = neg(r5)
//		r9 = #bytes to 128-byte align

        .align	5
bzero_128:
        sub		r2,r4,r9		// r2 <- length remaining after cache-line aligning
        rlwinm	r0,r7,0,0xF		// r0 <- #bytes to 16-byte align
        srwi.	r8,r2,7			// r8 <- number of cache lines to 0
        std		r6,0(r5)		// always store 16 bytes to 16-byte align...
        std		r6,8(r5)		// ...even if too short for dcbz128
        add		r5,r5,r0		// 16-byte align ptr
        sub		r4,r4,r0		// adjust count
        beq		bzero_tail		// r8==0, not long enough to dcbz128
        sub.	r7,r9,r0		// get #bytes remaining to 128-byte align
        rlwinm	r4,r2,0,0x7F	// r4 <- length remaining after dcbz128'ing
        mtctr	r8				// set up dcbz128 loop
        beq		bz_dcbz128		// already 128-byte aligned
        b		bz_align		// enter loop over 16-byte chunks

// 128-byte align by looping over 16-byte chunks.
        
        .align	5
bz_align:						// loop over 16-byte chunks
        subic.	r7,r7,16		// more to go?
        std		r6,0(r5)
        std		r6,8(r5)
        addi	r5,r5,16
        bgt		bz_align
        
        b		bz_dcbz128		// enter dcbz128 loop
        
// Loop over 128-byte cache lines.
//		r4 = length remaining after cache lines (0..127)
//		r5 = ptr (128-byte aligned)
//		r6 = 0
//		ctr = count of cache lines to 0

        .align	5
bz_dcbz128:
        dcbz128	0,r5			// zero a 128-byte cache line
        addi	r5,r5,128
        bdnz	bz_dcbz128
        
        b		bzero_tail		// handle leftovers


// Handle memset() for nonzero values.  This case is relatively infrequent;
// the large majority of memset() calls are for 0.
//		r3 = ptr
//		r4 = count
//		r6 = value in lower byte (nonzero)

memset1:
        cmplwi	r4,16			// too short to bother aligning?
        rlwimi	r6,r6,8,16,23	// replicate value to low 2 bytes
        mr		r5,r3			// make working copy of operand ptr
        rlwimi	r6,r6,16,0,15	// value now in all 4 bytes
        blt		bzero_tail		// length<16, we won't be using "std"
        mfsprg	r10,2			// get feature flags
        neg		r7,r5			// start to compute #bytes to align
        rlwinm	r6,r6,0,1,0		// value now in all 8 bytes (if 64-bit)
        andi.	r0,r7,7			// r6 <- #bytes to doubleword align
        stw		r6,0(r5)		// store 8 bytes to avoid a loop
        stw		r6,4(r5)
        mtcrf	0x02,r10		// get pf64Bit flag etc in cr6
        sub		r4,r4,r0		// adjust count
        add		r5,r5,r0		// doubleword align ptr
        b		bzero_tail
        
        


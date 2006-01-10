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
 * Version of 2/20/2003, tuned for G4.  The inner loops use DCBA to avoid
 * reading destination cache lines.  Only the 7450 actually benefits from
 * this, and then only in the cold-cache case.  On 7400s and 7455s, we
 * patch the DCBAs into NOPs.
 *
 * Register usage.  Note we use R2, so this code will not run in a PEF/CFM
 * environment.  Note also the rather delicate way we assign multiple uses
 * to the same register.  Beware.
 *
 *   r0  = "w7" or temp (NB: cannot use r0 for any constant such as "c16")
 *   r2  = "w8" or vrsave ("rv")
 *   r3  = not used, as memcpy and memmove return 1st parameter as a value
 *   r4  = source ptr ("rs")
 *   r5  = count of bytes to move ("rc")
 *   r6  = "w1", "c16", or "cm17"
 *   r7  = "w2", "c32", or "cm33"
 *   r8  = "w3", "c48", or "cm49"
 *   r9  = "w4", or "cm1"
 *   r10 = "w5", "c96", or "cm97"
 *   r11 = "w6", "c128", or "cm129"
 *   r12 = destination ptr ("rd")
 *   v0  = permute vector ("vp") 
 * v1-v4 = qw's loaded from source
 * v5-v7 = permuted qw's ("vw", "vx", "vy")
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

#define c16		r6
#define cm17	r6
#define c32		r7
#define cm33	r7
#define c48		r8
#define cm49	r8
#define cm1		r9
#define c96		r10
#define cm97	r10
#define c128	r11
#define cm129	r11

#define	vp	v0
#define	vw	v5
#define	vx	v6
#define	vy	v7

#define	ASSEMBLER
#include <sys/appleapiopts.h>
#include <ppc/asm.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>

        .text

#define	kMedium		32				// too long for inline loopless code
#define	kLong		96				// long enough to justify use of Altivec


// Main entry points.

        .align 	5
bcopy_g4:							// void bcopy(const void *src, void *dst, size_t len)
        cmplwi	rc,kMedium			// short or long?
        sub		w1,r4,r3			// must move in reverse if (rd-rs)<rc
        cmplw	cr1,w1,rc			// set cr1 blt iff we must move reverse
        mr		rd,r4				// start to move registers to canonic spot
        mr		rs,r3
        blt+	LShort				// handle short operands
        dcbt	0,r3				// touch in destination
        b		LMedium				// join medium/long operand code

// NB: memmove() must be 8 words past bcopy(), to agree with comm page addresses.
        
        .align	5
Lmemcpy_g4:							// void* memcpy(void *dst, void *src, size_t len)
Lmemmove_g4:						// void* memmove(void *dst, const void *src, size_t len)
        cmplwi	rc,kMedium			// short or long?
        sub		w1,r3,r4			// must move in reverse if (rd-rs)<rc
        dcbt	0,r4				// touch in the first line of source
        cmplw	cr1,w1,rc			// set cr1 blt iff we must move reverse
        mr		rd,r3				// must leave r3 alone, it is return value for memcpy etc
        bge-	LMedium				// handle medium or long operands

// Handle short operands.
        
LShort:
        andi.	r0,rc,0x10			// test bit 27 separately (faster on G4)
        mtcrf	0x01,rc				// put length bits 28-31 in cr7
        blt-	cr1,LShortReverse
        
// Forward short operands.  This is the most frequent case, so it is inline.

        beq		LShort16			// quadword to move?
        lwz		w1,0(rs)
        lwz		w2,4(rs)
        lwz		w3,8(rs)
        lwz		w4,12(rs)
        addi	rs,rs,16
        stw		w1,0(rd)
        stw		w2,4(rd)
        stw		w3,8(rd)
        stw		w4,12(rd)
        addi	rd,rd,16
LShort16:							// join here to xfer 0-15 bytes
        bf		28,2f				// doubleword?
        lwz		w1,0(rs)
        lwz		w2,4(rs)
        addi	rs,rs,8
        stw		w1,0(rd)
        stw		w2,4(rd)
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
//		cr0 = bne if bit 27 of length is set
//		cr7 = bits 28-31 of length      

LShortReverse:
        add		rs,rs,rc			// adjust ptrs for reverse move
        add		rd,rd,rc
        beq		LShortReverse16		// quadword to move?
        lwz		w1,-4(rs)
        lwz		w2,-8(rs)
        lwz		w3,-12(rs)
        lwzu	w4,-16(rs)
        stw		w1,-4(rd)
        stw		w2,-8(rd)
        stw		w3,-12(rd)
        stwu	w4,-16(rd)
LShortReverse16:					// join here to xfer 0-15 bytes and return
        bf		28,2f				// doubleword?
        lwz		w1,-4(rs)
        lwzu	w2,-8(rs)
        stw		w1,-4(rd)
        stwu	w2,-8(rd)
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
        

// Medium and long operands.  Use Altivec if long enough, else scalar loops.
//		w1 = (rd-rs), used to check for alignment
//     cr1 = blt iff we must move reverse

        .align	4
LMedium:
        dcbtst	0,rd				// touch in destination
        cmplwi	cr7,rc,kLong		// long enough for vectors?
        neg		w3,rd				// start to compute #bytes to align destination
        rlwinm	r0,w1,0,0x7			// check relative 8-byte alignment
        andi.	w6,w3,7				// w6 <- #bytes to 8-byte align destination
        blt		cr1,LMediumReverse	// handle reverse moves
        rlwinm	w4,w3,0,0x1F		// w4 <- #bytes to 32-byte align destination
        cmpwi	cr6,r0,0			// set cr6 beq if relatively aligned
        bge		cr7,LFwdLong		// long enough for vectors

// Medium length: use scalar loops.
//	w6/cr0 = #bytes to 8-byte align destination
//	   cr6 = beq if relatively doubleword aligned

        sub		rc,rc,w6			// decrement length remaining
        beq		1f					// skip if dest already doubleword aligned
        mtxer	w6					// set up count for move
        lswx	w1,0,rs				// move w6 bytes to align destination
        stswx	w1,0,rd
        add		rs,rs,w6			// bump ptrs past
        add		rd,rd,w6
1:        
        srwi	r0,rc,4				// get # 16-byte chunks (>=1)
        mtcrf	0x01,rc				// save remaining byte count here for LShort16
        mtctr	r0					// set up 16-byte loop
        bne		cr6,3f				// source not 4-byte aligned
        b		2f
        
        .align	4
2:									// loop over 16-byte  aligned chunks
        lfd		f0,0(rs)
        lfd		f1,8(rs)
        addi	rs,rs,16
        stfd	f0,0(rd)
        stfd	f1,8(rd)
        addi	rd,rd,16
        bdnz	2b
        
        b		LShort16
        
        .align	4
3:									// loop over 16-byte unaligned chunks
        lwz		w1,0(rs)
        lwz		w2,4(rs)
        lwz		w3,8(rs)
        lwz		w4,12(rs)
        addi	rs,rs,16
        stw		w1,0(rd)
        stw		w2,4(rd)
        stw		w3,8(rd)
        stw		w4,12(rd)
        addi	rd,rd,16
        bdnz	3b
        
        b		LShort16


// Vector loops.  First, we must 32-byte align the destination.
//		w1 = (rd-rs), used to check for reverse and alignment
//		w4 = #bytes to 32-byte align destination
//		rc = long enough for at least one vector loop

LFwdLong:
        cmpwi	w4,0				// dest already aligned?
        sub		rc,rc,w4			// adjust length
        mtcrf	0x01,w4				// cr7 <- #bytes to align dest
        rlwinm	w2,w1,0,0xF			// relatively 16-byte aligned?
        mtcrf	0x02,w4				// finish moving #bytes to align to cr6 and cr7
        srwi	r0,rc,6				// get # 64-byte chunks to xfer (>=1)
        cmpwi	cr5,w2,0			// set cr5 beq if relatively 16-byte aligned
        beq		LFwdAligned			// dest is already aligned
        
// 32-byte align destination.

        bf		31,1f				// byte to move?
        lbz		w1,0(rs)
        addi	rs,rs,1
        stb		w1,0(rd)
        addi	rd,rd,1
1:
        bf		30,2f				// halfword?
        lhz		w1,0(rs)
        addi	rs,rs,2
        sth		w1,0(rd)
        addi	rd,rd,2
2:
        bf		29,3f				// word?
        lwz		w1,0(rs)
        addi	rs,rs,4
        stw		w1,0(rd)
        addi	rd,rd,4
3:
        bf		28,4f				// doubleword?
        lwz		w1,0(rs)
        lwz		w2,4(rs)
        addi	rs,rs,8
        stw		w1,0(rd)
        stw		w2,4(rd)
        addi	rd,rd,8
4:	
        bf		27,LFwdAligned		// quadword?
        lwz		w1,0(rs)
        lwz		w2,4(rs)
        lwz		w3,8(rs)
        lwz		w4,12(rs)
        addi	rs,rs,16
        stw		w1,0(rd)
        stw		w2,4(rd)
        stw		w3,8(rd)
        stw		w4,12(rd)
        addi	rd,rd,16


// Destination is 32-byte aligned.
//		r0 = count of 64-byte chunks to move (not 0)
//		rd = 32-byte aligned
//		rc = bytes remaining
//	   cr5 = beq if source is 16-byte aligned
// We set up many registers:
//	   ctr = number of 64-byte chunks to move
//	r0/cr0 = leftover QWs to move
//	   cr7 = low 4 bits of rc (ie, leftover byte count 0-15)
//	   cr6 = beq if leftover byte count is 0
//		rv = original value of vrsave
// c16 etc = loaded

LFwdAligned:
        mfspr	rv,vrsave			// get bitmap of live vector registers
        mtcrf	0x01,rc				// move leftover count to cr7 for LShort16
        rlwinm	w3,rc,0,28,31		// move last 0-15 byte count to w3
        mtctr	r0					// set up loop count
        cmpwi	cr6,w3,0			// set cr6 on leftover byte count
        oris	w1,rv,0xFF00		// we use v0-v7
        rlwinm.	r0,rc,28,30,31		// get number of quadword leftovers (0-3) and set cr0
        mtspr	vrsave,w1			// update mask
        li		c16,16				// get constants used in ldvx/stvx
        li		c32,32
        li		c48,48
        li		c96,96
        li		c128,128
        bne		cr5,LForwardVecUnal	// handle unaligned operands
        b		1f

        .align	4
1:        							// loop over 64-byte chunks
        dcbt	c96,rs
        dcbt	c128,rs
        lvx		v1,0,rs
        lvx		v2,c16,rs
        lvx		v3,c32,rs
        lvx		v4,c48,rs
        addi	rs,rs,64
        dcba	0,rd				// patched to NOP on some machines
        stvx	v1,0,rd
        stvx	v2,c16,rd
        dcba	c32,rd				// patched to NOP on some machines
        stvx	v3,c32,rd
        stvx	v4,c48,rd
        addi	rd,rd,64
        bdnz	1b
                
        beq		4f					// no leftover quadwords
        mtctr	r0
3:									// loop over remaining quadwords (1-3)
        lvx		v1,0,rs
        addi	rs,rs,16
        stvx	v1,0,rd
        addi	rd,rd,16
        bdnz	3b
4:
        mtspr	vrsave,rv			// restore bitmap of live vr's
        bne		cr6,LShort16		// handle last 0-15 bytes if any
        blr
        

// Long, forward, unaligned vector loop.

LForwardVecUnal:
        lvsl	vp,0,rs				// get permute vector to shift left
        lvx		v1,0,rs				// prefetch 1st source quadword
        b		1f

        .align	4					// align inner loops
1:									// loop over 64-byte chunks
        lvx		v2,c16,rs
        dcbt	c96,rs
        lvx		v3,c32,rs
        dcbt	c128,rs
        lvx		v4,c48,rs
        addi	rs,rs,64
        vperm	vw,v1,v2,vp
        lvx		v1,0,rs
        vperm	vx,v2,v3,vp
        dcba	0,rd				// patched to NOP on some machines
        stvx	vw,0,rd
        vperm	vy,v3,v4,vp
        stvx	vx,c16,rd
        vperm	vw,v4,v1,vp
        dcba	c32,rd				// patched to NOP on some machines
        stvx	vy,c32,rd
        stvx	vw,c48,rd
        addi	rd,rd,64
        bdnz	1b

        beq-	4f					// no leftover quadwords
        mtctr	r0
3:									// loop over remaining quadwords
        lvx		v2,c16,rs
        addi	rs,rs,16
        vperm	vx,v1,v2,vp
        vor		v1,v2,v2			// v1 <- v2
        stvx	vx,0,rd
        addi	rd,rd,16
        bdnz	3b
4:
        mtspr	vrsave,rv			// restore bitmap of live vr's
        bne		cr6,LShort16		// handle last 0-15 bytes if any
        blr
        

// Medium and long, reverse moves.  We use altivec if the operands are long enough,
// else a lwz/stx loop.
//		w1 = (rd-rs), used to check for reverse and alignment
//	   cr7 = bge if long

LMediumReverse:
        add		rd,rd,rc			// point to end of operands
        add		rs,rs,rc
        andi.	w4,rd,0x1F			// w4 <- #bytes to 32-byte align destination
        rlwinm	w6,rd,0,0x3			// w6 <- #bytes to 4-byte align destination
        bge		cr7,LLongReverse	// long enough for vectors

// Scalar loop.
//	    w6 = #bytes to 4-byte align destination

        sub		rc,rc,w6			// decrement length remaining
        mtxer	w6					// set up count for move
        sub		rs,rs,w6			// back up ptrs
        sub		rd,rd,w6
        srwi	r0,rc,4				// get # 16-byte chunks (>=1)
        mtcrf	0x01,rc				// set remaining byte count here for LShortReverse16
        lswx	w1,0,rs				// move w6 bytes to align destination
        stswx	w1,0,rd
        mtctr	r0					// set up 16-byte loop
        b		1f
        
        .align	4
1:									// loop over 16-byte  aligned chunks
        lwz		w1,-4(rs)
        lwz		w2,-8(rs)
        lwz		w3,-12(rs)
        lwzu	w4,-16(rs)
        stw		w1,-4(rd)
        stw		w2,-8(rd)
        stw		w3,-12(rd)
        stwu	w4,-16(rd)
        bdnz	1b
        
        b		LShortReverse16
        

// Reverse vector loops.  First, we must 32-byte align the destination.
//		w1 = (rd-rs), used to check for reverse and alignment
//	w4/cr0 = #bytes to 32-byte align destination
//		rc = long enough for at least one vector loop

LLongReverse:
        sub		rc,rc,w4			// adjust length
        mtcrf	0x01,w4				// cr7 <- #bytes to align dest
        rlwinm	w2,w1,0,0xF			// relatively 16-byte aligned?
        mtcrf	0x02,w4				// finish moving #bytes to align to cr6 and cr7
        srwi	r0,rc,6				// get # 64-byte chunks to xfer (>=1)
        cmpwi	cr5,w2,0			// set cr5 beq if relatively 16-byte aligned
        beq		LReverseAligned		// dest is already aligned
        
// 32-byte align destination.

        bf		31,1f				// byte to move?
        lbzu 	w1,-1(rs)
        stbu 	w1,-1(rd)
1:
        bf		30,2f				// halfword?
        lhzu 	w1,-2(rs)
        sthu 	w1,-2(rd)
2:
        bf		29,3f				// word?
        lwzu 	w1,-4(rs)
        stwu 	w1,-4(rd)
3:
        bf		28,4f				// doubleword?
        lwz		w1,-4(rs)
        lwzu	w2,-8(rs)
        stw		w1,-4(rd)
        stwu	w2,-8(rd)
4:	
        bf		27,LReverseAligned	// quadword?
        lwz		w1,-4(rs)
        lwz		w2,-8(rs)
        lwz		w3,-12(rs)
        lwzu	w4,-16(rs)
        stw		w1,-4(rd)
        stw		w2,-8(rd)
        stw		w3,-12(rd)
        stwu	w4,-16(rd)

// Destination is 32-byte aligned.
//		r0 = count of 64-byte chunks to move (not 0)
//		rd = 32-byte aligned
//		rc = bytes remaining
//	   cr5 = beq if source is 16-byte aligned
// We set up many registers:
//	   ctr = number of 64-byte chunks to move
//	r0/cr0 = leftover QWs to move
//	   cr7 = low 4 bits of rc (ie, leftover byte count 0-15)
//	   cr6 = beq if leftover byte count is 0
//		rv = original value of vrsave
// cm1 etc = loaded
        
LReverseAligned:
        mfspr	rv,vrsave			// get bitmap of live vector registers
        mtcrf	0x01,rc				// move leftover count to cr7 for LShort16
        rlwinm	w3,rc,0,28,31		// move last 0-15 byte count to w3
        mtctr	r0					// set up loop count
        cmpwi	cr6,w3,0			// set cr6 on leftover byte count
        oris	w1,rv,0xFF00		// we use v0-v7
        rlwinm.	r0,rc,28,30,31		// get number of quadword leftovers (0-3) and set cr0
        mtspr	vrsave,w1			// update mask
        li		cm1,-1				// get constants used in ldvx/stvx
        li		cm17,-17
        li		cm33,-33
        li		cm49,-49
        li		cm97,-97
        li		cm129,-129        
        bne		cr5,LReverseVecUnal	// handle unaligned operands
        b		1f
      
        .align	4					// align inner loops
1:        							// loop over 64-byte chunks
        dcbt	cm97,rs
        dcbt	cm129,rs
        lvx		v1,cm1,rs
        lvx		v2,cm17,rs
        lvx		v3,cm33,rs
        lvx		v4,cm49,rs
        subi	rs,rs,64
        stvx	v1,cm1,rd
        stvx	v2,cm17,rd
        stvx	v3,cm33,rd
        stvx	v4,cm49,rd
        subi	rd,rd,64
        bdnz	1b

        beq		4f					// no leftover quadwords
        mtctr	r0
3:									// loop over remaining quadwords (1-7)
        lvx		v1,cm1,rs
        subi	rs,rs,16
        stvx	v1,cm1,rd
        subi	rd,rd,16
        bdnz	3b
4:
        mtspr	vrsave,rv			// restore bitmap of live vr's
        bne		cr6,LShortReverse16	// handle last 0-15 bytes if any
        blr


// Long, reverse, unaligned vector loop.

LReverseVecUnal:
        lvsl	vp,0,rs				// get permute vector to shift left
        lvx		v1,cm1,rs			// v1 always looks ahead
        b		1f
        
        .align	4					// align the inner loops
1:									// loop over 64-byte chunks
        lvx		v2,cm17,rs
        dcbt	cm97,rs
        lvx		v3,cm33,rs
        dcbt	cm129,rs
        lvx		v4,cm49,rs
        subi	rs,rs,64
        vperm	vw,v2,v1,vp
        lvx		v1,cm1,rs
        vperm	vx,v3,v2,vp
        stvx	vw,cm1,rd
        vperm	vy,v4,v3,vp
        stvx	vx,cm17,rd
        vperm	vw,v1,v4,vp
        stvx	vy,cm33,rd
        stvx	vw,cm49,rd
        subi	rd,rd,64
        bdnz	1b
        
        beq		3f					// no leftover quadwords
        mtctr	r0
2:									// loop over 1-3 quadwords
        lvx		v2,cm17,rs
        subi	rs,rs,16
        vperm	vx,v2,v1,vp
        vor		v1,v2,v2			// v1 <- v2
        stvx	vx,cm1,rd
        subi	rd,rd,16
        bdnz	2b
3:
        mtspr	vrsave,rv			// restore bitmap of live vr's
        bne		cr6,LShortReverse16	// handle last 0-15 bytes iff any
        blr

	COMMPAGE_DESCRIPTOR(bcopy_g4,_COMM_PAGE_BCOPY,kHasAltivec,k64Bit,kCommPageDCBA+kCommPage32)

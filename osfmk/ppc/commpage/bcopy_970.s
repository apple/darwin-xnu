/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
 * Version of 6/11/2003, tuned for the IBM 970.
 *
 *
 * Register usage.  Note the rather delicate way we assign multiple uses
 * to the same register.  Beware.
 *   r0  = temp (NB: cannot use r0 for any constant such as "c16")
 *   r3  = not used, as memcpy and memmove return 1st parameter as a value
 *   r4  = source ptr ("rs")
 *   r5  = count of bytes to move ("rc")
 *   r6  = "w1", "c16", or "cm17"
 *   r7  = "w2", "c32", or "cm33"
 *   r8  = "w3", "c48", or "cm49"
 *   r9  = "w4",        or "cm1"
 *   r10 = vrsave ("rv")
 *   r11 = unused
 *   r12 = destination ptr ("rd")
 *   v0  = permute vector ("vp") 
 * v1-v8 = qw's loaded from source
 *v9-v12 = permuted qw's ("vw", "vx", "vy", and "vz")
 */
#define rs	r4
#define rd	r12
#define rc	r5
#define	rv	r10

#define w1	r6
#define w2	r7
#define w3	r8
#define	w4	r9

#define c16		r6
#define cm17	r6
#define c32		r7
#define cm33	r7
#define c48		r8
#define cm49	r8
#define cm1		r9

#define	vp	v0
#define	vw	v9
#define	vx	v10
#define	vy	v11
#define	vz	v12

#define	ASSEMBLER
#include <sys/appleapiopts.h>
#include <ppc/asm.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>

        .text
        .globl	EXT(bcopy_970)


#define	kShort		64
#define	kVeryLong	(128*1024)


// Main entry points.

        .align 	5
bcopy_970:							// void bcopy(const void *src, void *dst, size_t len)
        cmplwi	rc,kShort			// short or long?
        sub		w1,r4,r3			// must move in reverse if (rd-rs)<rc
        mr		rd,r4				// move registers to canonic spot
        mr		rs,r3
        blt		LShort				// handle short operands
        dcbt	0,rs				// touch in the first line of source
        dcbtst	0,rd				// touch in destination
        b		LLong1				// join long operand code

// NB: memmove() must be 8 words past bcopy(), to agree with comm page addresses.

        .align	5
Lmemcpy_970:						// void* memcpy(void *dst, void *src, size_t len)
Lmemmove_970:						// void* memmove(void *dst, const void *src, size_t len)
        cmplwi	rc,kShort			// short or long?
        sub		w1,r3,r4			// must move in reverse if (rd-rs)<rc
        mr		rd,r3				// must leave r3 alone, it is return value for memcpy etc
        bge		LLong0				// handle long operands

// Handle short operands.
//		rs = source
//		rd = destination
//		rc = count
//		w1 = (rd-rs), must move reverse if (rd-rs)<rc
        
LShort:
        cmplw	cr1,w1,rc			// set cr1 blt if we must move reverse
        mtcrf	0x02,rc				// move length to cr6 and cr7 one at a time
        mtcrf	0x01,rc
        blt--	cr1,LShortReverse
        
// Forward short operands.  This is the most frequent case, so it is inline.

        bf		26,0f				// 32-byte chunk to move?
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
LShort32:
        bf		27,1f				// quadword to move?
        ld		w1,0(rs)
        ld		w3,8(rs)
        addi	rs,rs,16
        std		w1,0(rd)
        std		w3,8(rd)
        addi	rd,rd,16
1:
LShort16:							// join here to xfer 0-15 bytes
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
//		cr = length in bits 26-31       

LShortReverse:
        add		rs,rs,rc			// adjust ptrs for reverse move
        add		rd,rd,rc
        bf		26,0f				// 32 bytes to move?
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
LShortReverse16:					// join here to xfer 0-15 bytes and return
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
        

// Long operands, use Altivec in most cases.
//		rs = source
//		rd = destination
//		rc = count
//		w1 = (rd-rs), must move reverse if (rd-rs)<rc

LLong0:								// entry from memmove()
        dcbt	0,rs				// touch in source
        dcbtst	0,rd				// touch in destination
LLong1:								// entry from bcopy() with operands already touched in
        cmplw	cr1,w1,rc			// set cr1 blt iff we must move reverse
        neg		w3,rd				// start to compute #bytes to align destination
        rlwinm	w2,w1,0,0xF			// 16-byte aligned?  (w2==0 if so)
        andi.	w4,w3,0xF			// w4 <- #bytes to 16-byte align destination
        cmpwi	cr5,w2,0			// set cr5 beq if relatively 16-byte aligned
        blt--	cr1,LLongReverse	// handle reverse moves
        sub		rc,rc,w4			// adjust length for aligning destination
        srwi	r0,rc,7				// get #cache lines to copy (may be 0)
        cmpwi	cr1,r0,0			// set cr1 on #chunks
        beq		LFwdAligned			// dest is already aligned
        
// 16-byte align destination.

        mtcrf	0x01,w4				// cr7 <- #bytes to align dest (nonzero)
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
        bf		28,LFwdAligned		// doubleword?
        ld		w1,0(rs)
        addi	rs,rs,8
        std		w1,0(rd)
        addi	rd,rd,8


// Forward, destination is 16-byte aligned.  There are five cases:
//  1. If the length>=kVeryLong (ie, several pages), then use the
//     "bigcopy" path that pulls all the punches.  This is the fastest
//	   case for cold-cache operands, as any this long will likely be.
//	2. If length>=128 and source is 16-byte aligned, then use the
//	   lvx/stvx loop over 128-byte chunks.  This is the fastest
//     case for hot-cache operands, 2nd fastest for cold.
//	3. If length>=128 and source is not 16-byte aligned, then use the
//	   lvx/vperm/stvx loop over 128-byte chunks.
//	4. If length<128 and source is 8-byte aligned, then use the
//	   ld/std loop over 32-byte chunks.
//	5. If length<128 and source is not 8-byte aligned, then use the
//	   lvx/vperm/stvx loop over 32-byte chunks.  This is the slowest case.
// Registers at this point:
//		r0/cr1 = count of cache lines ("chunks") that we'll cover (may be 0)
//			rs = alignment unknown
//		    rd = 16-byte aligned
//			rc = bytes remaining
//			w2 = low 4 bits of (rd-rs), used to check alignment
//		   cr5 = beq if source is also 16-byte aligned

LFwdAligned:
        andi.	w3,w2,7				// is source at least 8-byte aligned?
        mtcrf	0x01,rc				// move leftover count to cr7 for LShort16
        bne		cr1,LFwdLongVectors	// at least one 128-byte chunk, so use vectors
        srwi	w1,rc,5				// get 32-byte chunk count
        mtcrf	0x02,rc				// move bit 27 of length to cr6 for LShort32
        mtctr	w1					// set up 32-byte loop (w1!=0)
        beq		LFwdMedAligned		// source is 8-byte aligned, so use ld/std loop
        mfspr	rv,vrsave			// get bitmap of live vector registers
        oris	w4,rv,0xFFF8		// we use v0-v12
        li		c16,16				// get constant used in lvx
        li		c32,32
        mtspr	vrsave,w4			// update mask
        lvx		v1,0,rs				// prefetch 1st source quadword
        lvsl	vp,0,rs				// get permute vector to shift left
        
        
// Fewer than 128 bytes but not doubleword aligned: use lvx/vperm/stvx.

1:									// loop over 32-byte chunks
        lvx		v2,c16,rs
        lvx		v3,c32,rs
        addi	rs,rs,32
        vperm	vx,v1,v2,vp
        vperm	vy,v2,v3,vp
        vor		v1,v3,v3			// v1 <- v3
        stvx	vx,0,rd
        stvx	vy,c16,rd
        addi	rd,rd,32
        bdnz	1b
        
        mtspr	vrsave,rv			// restore bitmap of live vr's
        b		LShort32

        
// Fewer than 128 bytes and doubleword aligned: use ld/std.

        .align	5
LFwdMedAligned:									// loop over 32-byte chunks
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
        bdnz	LFwdMedAligned
        
        b		LShort32

        
// Forward, 128 bytes or more: use vectors.  When entered:
//	    r0 = 128-byte chunks to move (>0)
//		rd = 16-byte aligned
//	   cr5 = beq if source is 16-byte aligned
//	   cr7 = low 4 bits of rc (ie, leftover byte count 0-15)
// We set up many registers:
//	   ctr = number of 128-byte chunks to move
//	r0/cr0 = leftover QWs to move
//	   cr7 = low 4 bits of rc (ie, leftover byte count 0-15)
//	   cr6 = beq if leftover byte count is 0
//		rv = original value of VRSave
// c16,c32,c48 = loaded

LFwdLongVectors:
        mfspr	rv,vrsave			// get bitmap of live vector registers
        lis		w3,kVeryLong>>16	// cutoff for very-long-operand special case path
        cmplw	cr1,rc,w3			// very long operand?
        rlwinm	w3,rc,0,28,31		// move last 0-15 byte count to w3
        bgea--	cr1,_COMM_PAGE_BIGCOPY	// handle big copies separately
        mtctr	r0					// set up loop count
        cmpwi	cr6,w3,0			// set cr6 on leftover byte count
        oris	w4,rv,0xFFF8		// we use v0-v12
        rlwinm.	r0,rc,28,29,31		// get number of quadword leftovers (0-7) and set cr0
        li		c16,16				// get constants used in ldvx/stvx
        mtspr	vrsave,w4			// update mask
        li		c32,32
        li		c48,48
        beq		cr5,LFwdLongAligned	// source is also 16-byte aligned, no need for vperm
        lvsl	vp,0,rs				// get permute vector to shift left
        lvx		v1,0,rs				// prefetch 1st source quadword
        b		LFwdLongUnaligned


// Forward, long, unaligned vector loop.

        .align	5					// align inner loops
LFwdLongUnaligned:					// loop over 128-byte chunks
        addi	w4,rs,64
        lvx		v2,c16,rs
        lvx		v3,c32,rs
        lvx		v4,c48,rs
        lvx		v5,0,w4
        lvx		v6,c16,w4
        vperm	vw,v1,v2,vp
        lvx		v7,c32,w4
        lvx		v8,c48,w4
        addi	rs,rs,128
        vperm	vx,v2,v3,vp
        addi	w4,rd,64
        lvx		v1,0,rs
        stvx	vw,0,rd
        vperm	vy,v3,v4,vp
        stvx	vx,c16,rd
        vperm	vz,v4,v5,vp
        stvx	vy,c32,rd
        vperm	vw,v5,v6,vp
        stvx	vz,c48,rd
        vperm	vx,v6,v7,vp
        addi	rd,rd,128
        stvx	vw,0,w4
        vperm	vy,v7,v8,vp
        stvx	vx,c16,w4
        vperm	vz,v8,v1,vp
        stvx	vy,c32,w4
        stvx	vz,c48,w4
        bdnz	LFwdLongUnaligned

        beq		4f					// no leftover quadwords
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


// Forward, long, 16-byte aligned vector loop.

        .align	5
LFwdLongAligned:        			// loop over 128-byte chunks
        addi	w4,rs,64
        lvx		v1,0,rs
        lvx		v2,c16,rs
        lvx		v3,c32,rs
        lvx		v4,c48,rs
        lvx		v5,0,w4
        lvx		v6,c16,w4
        lvx		v7,c32,w4
        lvx		v8,c48,w4
        addi	rs,rs,128
        addi	w4,rd,64
        stvx	v1,0,rd 
        stvx	v2,c16,rd
        stvx	v3,c32,rd
        stvx	v4,c48,rd
        stvx	v5,0,w4
        stvx	v6,c16,w4
        stvx	v7,c32,w4
        stvx	v8,c48,w4
        addi	rd,rd,128
        bdnz	LFwdLongAligned
                
        beq		4f					// no leftover quadwords
        mtctr	r0
3:									// loop over remaining quadwords (1-7)
        lvx		v1,0,rs
        addi	rs,rs,16
        stvx	v1,0,rd
        addi	rd,rd,16
        bdnz	3b
4:
        mtspr	vrsave,rv			// restore bitmap of live vr's
        bne		cr6,LShort16		// handle last 0-15 bytes if any
        blr
        

// Long, reverse moves.
//		rs = source
//		rd = destination
//		rc = count
//	   cr5 = beq if relatively 16-byte aligned

LLongReverse:
        add		rd,rd,rc			// point to end of operands
        add		rs,rs,rc
        andi.	r0,rd,0xF			// #bytes to 16-byte align destination
        beq		2f					// already aligned
        
// 16-byte align destination.

        mtctr	r0					// set up for loop
        sub		rc,rc,r0
1:
        lbzu	w1,-1(rs)
        stbu	w1,-1(rd)
        bdnz	1b

// Prepare for reverse vector loop.  When entered:
//		rd = 16-byte aligned
//		cr5 = beq if source also 16-byte aligned
// We set up many registers:
//		ctr/cr1 = number of 64-byte chunks to move (may be 0)
//		r0/cr0 = leftover QWs to move
//		cr7 = low 4 bits of rc (ie, leftover byte count 0-15)
//		cr6 = beq if leftover byte count is 0
//		cm1 = -1
//		rv = original value of vrsave

2:
        mfspr	rv,vrsave			// get bitmap of live vector registers
        srwi	r0,rc,6				// get count of 64-byte chunks to move (may be 0)
        oris	w1,rv,0xFFF8		// we use v0-v12
        mtcrf	0x01,rc				// prepare for moving last 0-15 bytes in LShortReverse16
        rlwinm	w3,rc,0,28,31		// move last 0-15 byte count to w3 too
        cmpwi	cr1,r0,0			// set cr1 on chunk count
        mtspr	vrsave,w1			// update mask
        mtctr	r0					// set up loop count
        cmpwi	cr6,w3,0			// set cr6 on leftover byte count
        rlwinm.	r0,rc,28,30,31		// get number of quadword leftovers (0-3) and set cr0
        li		cm1,-1				// get constants used in ldvx/stvx
        
        bne		cr5,LReverseVecUnal	// handle unaligned operands
        beq		cr1,2f				// no chunks (if no chunks, must be leftover QWs)
        li		cm17,-17
        li		cm33,-33
        li		cm49,-49
        b		1f

// Long, reverse 16-byte-aligned vector loop.
      
        .align	5					// align inner loops
1:        							// loop over 64-byte chunks
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
2:									// r0=#QWs, rv=vrsave, cr7=(rc & F), cr6 set on cr7
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
//		ctr/cr1 = number of 64-byte chunks to move (may be 0)
//		r0/cr0 = leftover QWs to move
//		cr7 = low 4 bits of rc (ie, leftover byte count 0-15)
//		cr6 = beq if leftover byte count is 0
//		rv = original value of vrsave
//		cm1 = -1

LReverseVecUnal:
        lvsl	vp,0,rs				// get permute vector to shift left
        lvx		v1,cm1,rs			// v1 always looks ahead
        li		cm17,-17
        beq		cr1,2f				// no chunks (if no chunks, must be leftover QWs)
        li		cm33,-33
        li		cm49,-49
        b		1f
        
        .align	5					// align the inner loops
1:									// loop over 64-byte chunks
        lvx		v2,cm17,rs
        lvx		v3,cm33,rs
        lvx		v4,cm49,rs
        subi	rs,rs,64
        vperm	vx,v2,v1,vp
        lvx		v1,cm1,rs
        vperm	vy,v3,v2,vp
        stvx	vx,cm1,rd
        vperm	vz,v4,v3,vp
        stvx	vy,cm17,rd
        vperm	vx,v1,v4,vp
        stvx	vz,cm33,rd
        stvx	vx,cm49,rd
        subi	rd,rd,64
        bdnz	1b

        beq		4f					// no leftover quadwords
2:									// r0=#QWs, rv=vrsave, v1=next QW, cr7=(rc & F), cr6 set on cr7
        mtctr	r0
3:									// loop over 1-3 quadwords
        lvx		v2,cm17,rs
        subi	rs,rs,16
        vperm	vx,v2,v1,vp
        vor		v1,v2,v2			// v1 <- v2
        stvx	vx,cm1,rd
        subi	rd,rd,16
        bdnz	3b
4:
        mtspr	vrsave,rv			// restore bitmap of live vr's
        bne		cr6,LShortReverse16	// handle last 0-15 bytes iff any
        blr

        COMMPAGE_DESCRIPTOR(bcopy_970,_COMM_PAGE_BCOPY,k64Bit+kHasAltivec,0,kCommPageMTCRF)

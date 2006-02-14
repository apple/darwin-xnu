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
/*
 * WARNING: this code is written for 32-bit mode, and ported by the kernel if necessary
 * to 64-bit mode for use in the 64-bit commpage.  This "port" consists of the following
 * simple transformations:
 *      - all word compares are changed to doubleword
 *      - all "srwi[.]" opcodes are changed to "srdi[.]"                      
 * Nothing else is done.  For this to work, the following rules must be
 * carefully followed:
 *      - do not use carry or overflow
 *      - only use record mode if you are sure the results are mode-invariant
 *        for example, all "andi." and almost all "rlwinm." are fine
 *      - do not use "slwi", "slw", or "srw"
 * An imaginative programmer could break the porting model in other ways, but the above
 * are the most likely problem areas.  It is perhaps surprising how well in practice
 * this simple method works.
 */        

/* *********************
 * * M E M S E T _ G 5 *
 * *********************
 *
 * This is a subroutine called by Libc memset and memset_pattern for large nonzero
 * operands (zero operands are funneled into bzero.)  This version is for
 * 64-bit processors with a 128-byte cache line and Altivec.
 *
 * Registers at entry:
 *		r4 = count of bytes to store (must be >= 32)
 *      r8 = ptr to the 1st byte to store (16-byte aligned)
 *      r9 = ptr to 16-byte pattern to store (16-byte aligned)
 * When we return:
 *		r3 = not changed, since memset returns it
 *      r4 = bytes remaining to store (will be <32)
 *      r7 = not changed
 *      r8 = ptr to next byte to store (still 16-byte aligned)
 *     r12 = not changed (holds return value for memset)
 */

#define kBig    (3*128)                 // big enough to warrant using dcbz (NB: must be >= 3*128)

        .align	5
memset_g5:
        cmplwi  cr1,r4,kBig             // big enough to warrant using dcbz?
        neg     r10,r8                  // start to align ptr
        mfspr   r2,vrsave               // we'll be using VRs
        andi.   r10,r10,0x70            // get #bytes to cache line align
        oris    r0,r2,0x8000            // we use vr0
        mtspr   vrsave,r0
        li      r5,16                   // get offsets for "stvx"
        lvx     v0,0,r9                 // load the pattern into v0
        li      r6,32
        blt     cr1,LShort              // not big enough to bother with dcbz
        li      r9,48
        
        // cache line align
        
        beq     2f                      // already aligned
1:
        subic.  r10,r10,16              // more to go?
        stvx    v0,0,r8
        addi    r8,r8,16
        subi    r4,r4,16
        bne     1b
        
        // Loop over cache lines.  This code uses a private protocol with the kernel:
        // when the kernel emulates an alignment exception on a DCBZ that occurs in the
        // commpage, it zeroes CR7.  We use this to detect the case where we are operating on
        // uncached memory, and do not use DCBZ again in this code. We assume that either
        // all the operand is cacheable or none of it is, so we only check the first DCBZ.
2:
        cmpw    cr7,r3,r3               // set cr7_eq (kernel will clear if DCBZ faults)
        dcbzl   0,r8                    // zero first cache line (clearing cr7 if alignment exception)
        srwi    r0,r4,7                 // get #cache lines (>=2)
        rlwinm  r4,r4,0,0x7F            // mask down to residual count (0..127)
        bne--   cr7,LNoDcbz             // exit if we took alignment exception on the first DCBZ
        subic   r0,r0,1                 // loop 1-too-few times
        li      r11,128                 // set DCBZ look-ahead
        mtctr   r0
        b       3f                      // use loop that DCBZs
        
        // Loop over cache lines.  We DCBZ one line ahead, which is a little faster.
        
        .align  5
3:
        dcbzl   r11,r8                  // zero one line ahead
        addi    r10,r8,64
        stvx    v0,0,r8
        stvx    v0,r5,r8
        stvx    v0,r6,r8
        stvx    v0,r9,r8
        addi    r8,r8,128
        stvx    v0,0,r10
        stvx    v0,r5,r10
        stvx    v0,r6,r10
        stvx    v0,r9,r10
        bdnz++  3b
        
        li      r0,1                    // we've already DCBZ'd the last line
LNoDcbz:                                // r0: loop count
        mtctr   r0
        
        // Loop which does not DCBZ.  Normally this is only used for last cache line,
        // because we've already zeroed it.
4:        
        addi    r10,r8,64
        stvx    v0,0,r8
        stvx    v0,r5,r8
        stvx    v0,r6,r8
        stvx    v0,r9,r8
        addi    r8,r8,128
        stvx    v0,0,r10
        stvx    v0,r5,r10
        stvx    v0,r6,r10
        stvx    v0,r9,r10
        bdnz--  4b                      // optimize for the cacheable case
        
        // loop over 32-byte chunks
LShort:
        srwi.   r0,r4,5                 // get count of 32-byte chunks
        rlwinm  r4,r4,0,0x1F            // mask down to residual count (0..31)
        beq     7f                      // no chunks so done
        mtctr   r0
6:
        stvx    v0,0,r8
        stvx    v0,r5,r8
        addi    r8,r8,32
        bdnz++  6b
7:
        mtspr   vrsave,r2               // restore caller's vrsave
        blr


	COMMPAGE_DESCRIPTOR(memset_g5,_COMM_PAGE_MEMSET_PATTERN,kCache128+k64Bit+kHasAltivec,0, \
				kCommPageBoth+kPort32to64)

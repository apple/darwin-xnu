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


/* *********************
 * * M E M S E T _ G 4 *
 * *********************
 *
 * This is a subroutine called by Libc memset and memset_pattern for large nonzero
 * operands (zero operands are funneled into bzero.)  This version is for
 * 32-bit processors with a 32-byte cache line and Altivec.
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

#define kBig    (3*64)                  // big enough to warrant using dcba (NB: must be >= 3*64)

        .align	4
memset_g4:
        cmplwi  cr1,r4,kBig             // big enough to warrant using dcbz?
        mfspr   r2,vrsave               // we'll be using VRs
        oris    r0,r2,0x8000            // we use vr0
        andi.   r5,r8,0x10              // is ptr 32-byte aligned?
        mtspr   vrsave,r0
        li      r5,16                   // get offsets for "stvx"
        lvx     v0,0,r9                 // load the pattern into v0
        li      r6,32
        blt     cr1,LShort              // not big enough to bother with dcba
        li      r9,48
        
        // cache line align
        
        beq     2f                      // already aligned
        stvx    v0,0,r8                 // store another 16 bytes to align
        addi    r8,r8,16
        subi    r4,r4,16
        
        // Set up for inner loop.
2:
        srwi    r0,r4,6                 // get count of 64-byte chunks (>=2)
        dcba    0,r8                    // pre-allocate first cache line (possibly nop'd)
        rlwinm  r4,r4,0,0x3F            // mask down to residual count (0..63)
        subic   r0,r0,1                 // loop 1-too-few times
        li      r10,64                  // get offsets to DCBA one chunk ahead
        li      r11,64+32
        mtctr   r0
        dcba    r6,r8                   // zero 2nd cache line (possibly nop'd)
        b       3f                      // enter DCBA loop
        
        // Loop over 64-byte chunks.  We DCBA one chunk ahead, which is a little faster.
        // Note that some G4s do not benefit from the DCBAs.  We nop them in that case.
        
        .align  4
3:
        dcba    r10,r8                  // zero one 64-byte chunk ahead (possibly nop'd)
        dcba    r11,r8
        stvx    v0,0,r8
        stvx    v0,r5,r8
        stvx    v0,r6,r8
        stvx    v0,r9,r8
        addi    r8,r8,64
        bdnz+   3b
        
        // Last chunk, which we've already DCBAd.

        stvx    v0,0,r8
        stvx    v0,r5,r8
        stvx    v0,r6,r8
        stvx    v0,r9,r8
        addi    r8,r8,64
        
        // loop over 32-byte chunks at end
LShort:
        srwi.   r0,r4,5                 // get count of 32-byte chunks
        rlwinm  r4,r4,0,0x1F            // mask down to residual count (0..31)
        beq     7f                      // no chunks so done
        mtctr   r0
6:
        stvx    v0,0,r8
        stvx    v0,r5,r8
        addi    r8,r8,32
        bdnz    6b
7:
        mtspr   vrsave,r2               // restore caller's vrsave
        blr


	COMMPAGE_DESCRIPTOR(memset_g4,_COMM_PAGE_MEMSET_PATTERN,kCache32+kHasAltivec,0, \
				kCommPageDCBA+kCommPage32)

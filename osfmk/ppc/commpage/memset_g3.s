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

/* *********************
 * * M E M S E T _ G 3 *
 * *********************
 *
 * This is a subroutine called by Libc memset and _memset_pattern for large nonzero
 * operands (zero operands are funneled into bzero.)  This version is for
 * 32-bit processors with a 32-byte cache line and no Altivec.
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

        .align	4
memset_g3:
        andi.   r0,r8,16                // cache line aligned?
        lfd     f0,0(r9)                // pick up the pattern in two FPRs
        lfd     f1,8(r9)
        beq     1f                      // skip if already aligned
        
        // cache line align
        
        stfd    f0,0(r8)                // no, store another 16 bytes to align
        stfd    f1,8(r8)
        subi    r4,r4,16                // skip past the 16 bytes we just stored
        addi    r8,r8,16
        
        // Loop over cache lines.  This code uses a private protocol with the kernel:
        // when the kernel emulates an alignment exception on a DCBZ that occurs in the
        // commpage, it zeroes CR7.  We use this to detect the case where we are operating on
        // uncached memory, and do not use DCBZ again in this code. We assume that either
        // all the operand is cacheable or none of it is, so we only check the first DCBZ.
1:
        srwi.   r0,r4,6                 // get count of 64-byte chunks
        cmpw    cr7,r0,r0               // set cr7_eq (kernel turns off on alignment exception)
        rlwinm  r4,r4,0,0x3F            // mask down to residual count (0..63)
        beq     Lleftover               // no chunks
        dcbz    0,r8                    // zero first cache line (clearing cr7 if alignment exception)
        mtctr   r0
        li      r6,32                   // get an offset for DCBZ
        beq+    cr7,LDcbzEnter          // enter DCBZ loop (we didn't get an alignment exception)
        
        // Loop over 64-byte chunks without DCBZ.
LNoDcbz:
        stfd    f0,0(r8)
        stfd    f1,8(r8)
        stfd    f0,16(r8)
        stfd    f1,24(r8)
        stfd    f0,32(r8)
        stfd    f1,40(r8)
        stfd    f0,48(r8)
        stfd    f1,56(r8)
        addi    r8,r8,64
        bdnz    LNoDcbz
        
        b       Lleftover
        
        // Loop over 64-byte chunks using DCBZ.
LDcbz:
        dcbz    0,r8
LDcbzEnter:
        dcbz    r6,r8
        stfd    f0,0(r8)
        stfd    f1,8(r8)
        stfd    f0,16(r8)
        stfd    f1,24(r8)
        stfd    f0,32(r8)
        stfd    f1,40(r8)
        stfd    f0,48(r8)
        stfd    f1,56(r8)
        addi    r8,r8,64
        bdnz    LDcbz
        
        // Handle leftovers (0..63 bytes)
Lleftover:
        srwi.   r0,r4,4                 // get count of 16-byte chunks
        rlwinm  r4,r4,0,0xF             // mask down to residuals
        beqlr                           // no 16-byte chunks so done
        mtctr   r0
2:
        stfd    f0,0(r8)
        stfd    f1,8(r8)
        addi    r8,r8,16
        bdnz    2b
        
        blr

	COMMPAGE_DESCRIPTOR(memset_g3,_COMM_PAGE_MEMSET_PATTERN,kCache32,kHasAltivec, \
				kCommPage32)

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
/* ====================================
 * Very Long Operand BCOPY for Mac OS X
 * ====================================
 *
 * Version of 2/21/2004, tuned for the IBM 970.  This is for operands at
 * least several pages long.  It is called from bcopy()/memcpy()/memmove(),
 * and runs both in 32 and 64-bit mode.
 *
 * We use the following additional strategies not used by the shorter
 * operand paths.  Mostly, we try to optimize for memory bandwidth:
 *	1. Use DCBZ128 to avoid reading destination lines.  Because this code
 *     resides on the commmpage, it can use a private interface with the
 *     kernel to minimize alignment exceptions if the destination is
 *     uncached.  The kernel will clear cr7 whenever it emulates a DCBZ or
 *     DCBZ128 on the commpage.  Thus we take at most one exception per call,
 *     which is amortized across the very long operand.
 *	2. Copy larger chunks per iteration to minimize R/W bus turnaround
 *     and maximize DRAM page locality (opening a new page is expensive.)
 *     We use 256-byte chunks.
 *  3. Touch in one source chunk ahead with DCBT.  This is probably the
 *     least important change, and probably only helps restart the
 *     hardware stream at the start of each source page.
 */
 
#define rs	r13
#define rd	r14
#define rc	r15
#define rx  r16

#define c16     r3
#define c32     r4
#define c48     r5
#define c64     r6
#define c80     r7
#define c96     r8
#define c112    r9
#define	c256	r10
#define	c384	r11
#define rv      r12     // vrsave

// Offsets within the "red zone" (which is 224 bytes long):

#define rzR3    -8
#define rzR13	-16
#define rzR14	-24
#define rzR15   -32
#define rzR16   -40

#define rzV20	-64
#define rzV21	-80
#define rzV22	-96
#define rzV23	-112


#include <sys/appleapiopts.h>
#include <ppc/asm.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>

        .text
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

// Entry point.  This is a subroutine of bcopy().  When called:
//  r0 = return address (also stored in caller's SF)
//	r4 = source ptr
//	r5 = length (at least several pages)
// r12 = dest ptr
// 
// We only do "forward" moves, ie non-overlapping or toward 0.  We return with non-volatiles
// and r3 preserved.

        .align 	5
bigcopy_970:
        neg     r2,r12              // is destination cache-line-aligned?
        std     r3,rzR3(r1)         // save caller's r3, which must be preserved for memcpy()
        std		r13,rzR13(r1)		// spill non-volatile regs we use to redzone
        std		r14,rzR14(r1)
        std		r15,rzR15(r1)
        andi.   r2,r2,0x7F          // #bytes to align
        std     r16,rzR16(r1)
        mr      rs,r4               // copy parameters into nonvolatile registers
        mr      rd,r12
        mr      rc,r5
        mr      rx,r0               // also save return address
        beq     1f                  // skip if already aligned

// Cache-line-align destination.
        
        mr      r3,rd               // set up dest ptr for memcpy()
        mr      r5,r2               // number of bytes to copy
        add     rs,rs,r2            // then bump our parameters past initial copy
        add     rd,rd,r2
        sub     rc,rc,r2
        bla     _COMM_PAGE_MEMCPY   // 128-byte-align destination


// Load constant offsets and check whether source is 16-byte aligned.
// NB: the kernel clears cr7 if it emulates a dcbz128 on the commpage,
// and we dcbz only if cr7 beq is set.

1:
        dcbt    0,rs                // touch in 1st line of source
        andi.	r0,rs,15			// check source alignment
        mfspr	rv,vrsave			// save caller's bitmask
        li		c16,16				// load the constant offsets for x-form ops
        li		c32,32
        srwi    r2,rc,8             // get number of 256-byte chunks to xfer
        li		r0,-256				// we use 24 VRs (ie, 0-23)
        li		c48,48
        li      c64,64
        li      c80,80
        or      r0,r0,rv            // add our bits to caller's
        li      c96,96
        mtctr   r2                  // set up loop count
        li      c112,112
        cmpd    cr7,r2,r2           // initialize cr7_eq to "on", so we dcbz128
        mtspr	vrsave,r0           // say we use vr0..vr23
        li		c256,256
        li		c384,384
        beq		LalignedLoop		// handle aligned sources

        
// Set up for unaligned loop.

        lvsl	v0,0,rs				// get permute vector for left shift
        lvxl	v1,0,rs				// prime the loop
        li		r0,rzV20            // save non-volatile VRs in redzone
        stvx	v20,r1,r0
        li		r0,rzV21
        stvx	v21,r1,r0
        li		r0,rzV22
        stvx	v22,r1,r0
        li		r0,rzV23
        stvx	v23,r1,r0
        b		LunalignedLoop		// enter unaligned loop


// Main loop for unaligned operands.  We loop over 256-byte chunks (2 cache lines).
// Destination is 128-byte aligned, source is unaligned.

        .align	5
LunalignedLoop:
        dcbt	c256,rs             // touch in next chunk
        dcbt	c384,rs
        addi    r2,rs,128           // point to 2nd 128 bytes of source
        lvxl	v2,c16,rs
        lvxl	v3,c32,rs
        lvxl	v4,c48,rs
        lvxl    v5,c64,rs
        lvxl    v6,c80,rs
        lvxl    v7,c96,rs
        lvxl    v8,c112,rs
        lvxl    v9,0,r2
        addi    rs,rs,256           // point to next source chunk
        lvxl    v10,c16,r2
        lvxl    v11,c32,r2
        vperm   v17,v1,v2,v0
        lvxl    v12,c48,r2
        lvxl    v13,c64,r2
        vperm   v18,v2,v3,v0
        lvxl    v14,c80,r2
        lvxl    v15,c96,r2
        vperm   v19,v3,v4,v0
        lvxl    v16,c112,r2
        lvxl	v1,0,rs             // peek ahead at first source quad in next chunk
        vperm   v20,v4,v5,v0
        addi    r2,rd,128           // point to 2nd 128 bytes of dest 
        bne--	cr7,1f				// skip dcbz's if cr7 beq has been turned off by kernel
        dcbz128	0,rd
        dcbz128	0,r2
1:
        vperm   v21,v5,v6,v0
        stvxl	v17,0,rd
        vperm   v22,v6,v7,v0
        stvxl	v18,c16,rd
        vperm   v23,v7,v8,v0
        stvxl	v19,c32,rd
        vperm   v17,v8,v9,v0
        stvxl	v20,c48,rd
        vperm   v18,v9,v10,v0
        stvxl	v21,c64,rd
        vperm   v19,v10,v11,v0
        stvxl	v22,c80,rd
        vperm   v20,v11,v12,v0
        stvxl	v23,c96,rd
        vperm   v21,v12,v13,v0
        stvxl	v17,c112,rd
        vperm   v22,v13,v14,v0
        addi	rd,rd,256           // point to next dest chunk
        stvxl	v18,0,r2
        vperm   v23,v14,v15,v0
        stvxl	v19,c16,r2
        vperm   v17,v15,v16,v0
        stvxl	v20,c32,r2
        vperm   v18,v16,v1,v0
        stvxl	v21,c48,r2
        stvxl	v22,c64,r2
        stvxl	v23,c80,r2
        stvxl	v17,c96,r2
        stvxl	v18,c112,r2
        bdnz++	LunalignedLoop      // loop if another 256 bytes to go

        li		r6,rzV20            // restore non-volatile VRs
        li		r7,rzV21
        li		r8,rzV22
        li		r9,rzV23
        lvx		v20,r1,r6
        lvx		v21,r1,r7
        lvx		v22,r1,r8
        lvx		v23,r1,r9
        b       Ldone
        
        
// Aligned loop.  Destination is 128-byte aligned, and source is 16-byte
// aligned.  Loop over 256-byte chunks (2 cache lines.)

        .align	5
LalignedLoop:
        dcbt	c256,rs             // touch in next chunk
        dcbt	c384,rs
        addi    r2,rs,128           // point to 2nd 128 bytes of source
        lvxl	v1,0,rs
        lvxl	v2,c16,rs
        lvxl	v3,c32,rs
        lvxl	v4,c48,rs
        lvxl    v5,c64,rs
        lvxl    v6,c80,rs
        lvxl    v7,c96,rs
        lvxl    v8,c112,rs
        lvxl    v9,0,r2
        lvxl    v10,c16,r2
        lvxl    v11,c32,r2
        lvxl    v12,c48,r2
        lvxl    v13,c64,r2
        lvxl    v14,c80,r2
        lvxl    v15,c96,r2
        lvxl    v16,c112,r2
        addi    r2,rd,128           // point to 2nd 128 bytes of dest 
        bne--	cr7,1f				// skip dcbz's if cr7 beq has been turned off by kernel
        dcbz128	0,rd
        dcbz128	0,r2
1:
        addi    rs,rs,256           // point to next source chunk
        stvxl	v1,0,rd
        stvxl	v2,c16,rd
        stvxl	v3,c32,rd
        stvxl	v4,c48,rd
        stvxl	v5,c64,rd
        stvxl	v6,c80,rd
        stvxl	v7,c96,rd
        stvxl	v8,c112,rd
        addi	rd,rd,256           // point to next dest chunk
        stvxl	v9,0,r2
        stvxl	v10,c16,r2
        stvxl	v11,c32,r2
        stvxl	v12,c48,r2
        stvxl	v13,c64,r2
        stvxl	v14,c80,r2
        stvxl	v15,c96,r2
        stvxl	v16,c112,r2
        bdnz++	LalignedLoop		// loop if another 256 bytes to go


// Done, except for 0..255 leftover bytes at end.
//	rs = source ptr
//	rd = dest ptr
//	rc = remaining count in low 7 bits
//	rv = caller's vrsave
//  rx = caller's return address

Ldone:
        andi.   r5,rc,0xFF          // any leftover bytes? (0..255)
        mtspr	vrsave,rv			// restore bitmap of live vr's
        
        mr      r3,rd
        mr      r4,rs
        bnela   _COMM_PAGE_MEMCPY   // copy leftover bytes

        mtlr    rx                  // restore return address
        ld      r3,rzR3(r1)         // restore non-volatile GPRs from redzone
        ld		r13,rzR13(r1)
        ld		r14,rzR14(r1)
        ld		r15,rzR15(r1)
        ld      r16,rzR16(r1)
        blr


        COMMPAGE_DESCRIPTOR(bigcopy_970,_COMM_PAGE_BIGCOPY,0,0,kPort32to64+kCommPageBoth)


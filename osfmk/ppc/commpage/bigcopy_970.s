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
/* ====================================
 * Very Long Operand BCOPY for Mac OS X
 * ====================================
 *
 * Version of 6/11/2003, tuned for the IBM 970.  This is for operands at
 * least several pages long.  It is called from bcopy()/memcpy()/memmove().
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
 *  3. Touch in one source chunk ahead with DCBT.  This is probably the
 *     least important change, and probably only helps restart the
 *     hardware stream at the start of each source page.
 *
 * Register usage.  Note the rather delicate way we assign multiple uses
 * to the same register.  Beware.
 *   r0  = temp (NB: cannot use r0 for any constant such as "c16")
 *   r3  = not used, as memcpy and memmove return 1st parameter as a value
 *   r4  = source ptr ("rs")
 *   r5  = count of bytes to move ("rc")
 *   r6  = constant 16 ("c16")
 *   r7  = constant 32 (""c32")
 *   r8  = constant 48 (""c48")
 *   r9  = constant 128 (""c128")
 *   r10 = vrsave ("rv")
 *   r11 = constant 256 (""c256")
 *   r12 = destination ptr ("rd")
 *	 r13 = constant 384 (""c384")
 *	 r14 = temp ("rx")
 *	 r15 = temp ("rt")
 */
#define rs	r4
#define rd	r12
#define rc	r5
#define	rv	r10
#define	rx	r14
#define	rt	r15

#define c16	r6
#define c32	r7
#define c48	r8
#define	c128	r9
#define	c256	r11
#define	c384	r13

// Offsets within the "red zone" (which is 224 bytes long):

#define rzR13	-8
#define rzR14	-12
#define rzR15	-16
#define rzV20	-32
#define rzV21	-48
#define rzV22	-64
#define rzV23	-80
#define rzV24	-96
#define rzV25	-112
#define rzV26	-128
#define rzV27	-144
#define rzV28	-160
#define rzV29	-176
#define rzV30	-192
#define rzV31	-208


#include <sys/appleapiopts.h>
#include <ppc/asm.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>

        .text
        .globl	EXT(bigcopy_970)


// Entry point.  This is a subroutine of bcopy().  When called:
//	r4 = source ptr (aka "rs")
// r12 = dest ptr (aka "rd")
//	r5 = length (>= 16K bytes) (aka "rc")
// 
// We only do "forward" moves, ie non-overlapping or toward 0.
//
// We return with non-volatiles and r3 preserved.

        .align 	5
bigcopy_970:
        stw		r13,rzR13(r1)		// spill non-volatile regs we use to redzone
        stw		r14,rzR14(r1)
        stw		r15,rzR15(r1)
        li		r0,rzV20
        neg		rt,rd				// start to cache-line-align destination
        stvx	v20,r1,r0			// we use all 32 VRs
        li		r0,rzV21
        stvx	v21,r1,r0
        li		r0,rzV22
        stvx	v22,r1,r0
        li		r0,rzV23
        stvx	v23,r1,r0
        li		r0,rzV24
        andi.	rt,rt,127			// get #bytes to 128-byte align
        stvx	v24,r1,r0
        li		r0,rzV25
        stvx	v25,r1,r0
        li		r0,rzV26
        sub		rc,rc,rt			// adjust length by #bytes to align destination
        stvx	v26,r1,r0
        li		r0,rzV27
        stvx	v27,r1,r0
        li		r0,rzV28
        mtctr	rt					// #bytes to align destination
        stvx	v28,r1,r0
        li		r0,rzV29
        stvx	v29,r1,r0
        li		r0,rzV30
        stvx	v30,r1,r0
        li		r0,rzV31
        stvx	v31,r1,r0
        beq		2f					// dest already 128-byte aligned
        b		1f


// Cache-line-align destination.

        .align	5
1:
        lbz		r0,0(rs)
        addi	rs,rs,1
        stb		r0,0(rd)
        addi	rd,rd,1
        bdnz	1b


// Is source 16-byte aligned?  Load constant offsets.

2:
        andi.	r0,rs,15			// check source alignment
        mfspr	rv,vrsave			// save caller's bitmask
        li		r0,-1				// we use all 32 VRs
        li		c16,16				// load the constant offsets for x-form ops
        li		c32,32
        li		c48,48
        li		c128,128
        li		c256,256
        li		c384,384
        mtspr	vrsave,r0

// NB: the kernel clears cr7 if it emulates a dcbz128 on the commpage,
// and we dcbz only if cr7 beq is set.  We check to be sure the dcbz's
// won't zero source bytes before we load them, since we zero before
// loading as this is faster than zeroing after loading and before storing.

        cmpw	cr7,r0,r0			// initialize cr7 beq to use dcbz128
        sub		rt,rs,rd			// get (rs-rd)
        cmplwi	cr1,rt,512			// are we moving down less than 512 bytes?
        
// Start fetching in source cache lines.

        dcbt	c128,rs				// first line already touched in
        dcbt	c256,rs
        dcbt	c384,rs
        
        bge++	cr1,3f				// skip if not moving down less than 512 bytes
        cmpw	cr7,c16,c32			// cannot dcbz since it would zero source bytes
3:
        beq		LalignedLoop		// handle aligned sources
        lvsl	v0,0,rs				// get permute vector for left shift
        lvxl	v1,0,rs				// prime the loop
        b		LunalignedLoop		// enter unaligned loop


// Main loop for unaligned operands.  We loop over 384-byte chunks (3 cache lines)
// since we need a few VRs for permuted destination QWs and the permute vector.

        .align	5
LunalignedLoop:
        subi	rc,rc,384			// decrement byte count
        addi	rx,rs,384			// get address of next chunk
        lvxl	v2,c16,rs
        lvxl	v3,c32,rs
        bne--	cr7,1f				// skip dcbz's if cr7 beq has been turned off by kernel
        dcbz128	0,rd				// (also skip if moving down less than 512 bytes)
        bne--	cr7,1f				// catch it first time through
        dcbz128	c128,rd
        dcbz128	c256,rd
1:
        addi	rt,rs,64
        dcbt	0,rx				// touch in next chunk
        dcbt	c128,rx
        dcbt	c256,rx
        lvxl	v4,c48,rs
        addi	rs,rs,128
        lvxl	v5,0,rt
        cmplwi	rc,384				// another chunk to go?
        lvxl	v6,c16,rt
        lvxl	v7,c32,rt
        lvxl	v8,c48,rt
        addi	rt,rs,64
        vperm	v25,v1,v2,v0
        lvxl	v9,0,rs
        lvxl	v10,c16,rs
        vperm	v26,v2,v3,v0
        lvxl	v11,c32,rs
        lvxl	v12,c48,rs
        vperm	v27,v3,v4,v0
        addi	rs,rs,128
        lvxl	v13,0,rt
        lvxl	v14,c16,rt
        vperm	v28,v4,v5,v0
        lvxl	v15,c32,rt
        lvxl	v16,c48,rt
        vperm	v29,v5,v6,v0
        addi	rt,rs,64
        lvxl	v17,0,rs
        lvxl	v18,c16,rs
        vperm	v30,v6,v7,v0
        lvxl	v19,c32,rs
        lvxl	v20,c48,rs
        vperm	v31,v7,v8,v0
        addi	rs,rs,128
        lvxl	v21,0,rt
        lvxl	v22,c16,rt
        vperm	v2,v8,v9,v0
        lvxl	v23,c32,rt
        lvxl	v24,c48,rt
        vperm	v3,v9,v10,v0
        lvx		v1,0,rs				// get 1st qw of next chunk
        vperm	v4,v10,v11,v0
        
        addi	rt,rd,64
        stvxl	v25,0,rd
        stvxl	v26,c16,rd
        vperm	v5,v11,v12,v0
        stvxl	v27,c32,rd
        stvxl	v28,c48,rd
        vperm	v6,v12,v13,v0
        addi	rd,rd,128
        stvxl	v29,0,rt
        stvxl	v30,c16,rt
        vperm	v7,v13,v14,v0
        stvxl	v31,c32,rt
        stvxl	v2,c48,rt
        vperm	v8,v14,v15,v0
        addi	rt,rd,64
        stvxl	v3,0,rd
        stvxl	v4,c16,rd
        vperm	v9,v15,v16,v0
        stvxl	v5,c32,rd
        stvxl	v6,c48,rd
        vperm	v10,v16,v17,v0
        addi	rd,rd,128
        stvxl	v7,0,rt
        vperm	v11,v17,v18,v0
        stvxl	v8,c16,rt
        stvxl	v9,c32,rt
        vperm	v12,v18,v19,v0
        stvxl	v10,c48,rt
        addi	rt,rd,64
        vperm	v13,v19,v20,v0
        stvxl	v11,0,rd
        stvxl	v12,c16,rd
        vperm	v14,v20,v21,v0
        stvxl	v13,c32,rd
        vperm	v15,v21,v22,v0
        stvxl	v14,c48,rd
        vperm	v16,v22,v23,v0
        addi	rd,rd,128
        stvxl	v15,0,rt
        vperm	v17,v23,v24,v0
        stvxl	v16,c16,rt
        vperm	v18,v24,v1,v0
        stvxl	v17,c32,rt
        stvxl	v18,c48,rt
        bge++	LunalignedLoop		// loop if another 384 bytes to go

// End of unaligned main loop.  Handle up to 384 leftover bytes.

        srwi.	r0,rc,5				// get count of 32-byte chunks remaining
        beq		Ldone				// none
        rlwinm	rc,rc,0,0x1F		// mask count down to 0..31 leftover bytes
        mtctr	r0
1:									// loop over 32-byte chunks
        lvx		v2,c16,rs
        lvx		v3,c32,rs
        addi	rs,rs,32
        vperm	v8,v1,v2,v0
        vperm	v9,v2,v3,v0
        vor		v1,v3,v3			// v1 <- v3
        stvx	v8,0,rd
        stvx	v9,c16,rd
        addi	rd,rd,32
        bdnz	1b
        
        b		Ldone
        
        
// Aligned loop.  Destination is 128-byte aligned, and source is 16-byte
// aligned.  Loop over 512-byte chunks (4 cache lines.)

        .align	5
LalignedLoop:
        subi	rc,rc,512			// decrement count
        addi	rx,rs,512			// address of next chunk
        lvxl	v1,0,rs
        lvxl	v2,c16,rs
        bne--	cr7,1f				// skip dcbz's if cr7 beq has been turned off by kernel
        dcbz128	0,rd				// (also skip if moving down less than 512 bytes)
        bne--	cr7,1f				// catch it first time through
        dcbz128	c128,rd
        dcbz128	c256,rd
        dcbz128	c384,rd
1:
        addi	rt,rs,64
        dcbt	0,rx				// touch in next chunk
        dcbt	c128,rx
        dcbt	c256,rx
        dcbt	c384,rx
        lvxl	v3,c32,rs
        lvxl	v4,c48,rs
        addi	rs,rs,128
        lvxl	v5,0,rt
        cmplwi	rc,512				// another chunk to go?
        lvxl	v6,c16,rt
        lvxl	v7,c32,rt
        lvxl	v8,c48,rt
        addi	rt,rs,64
        lvxl	v9,0,rs
        lvxl	v10,c16,rs
        lvxl	v11,c32,rs
        lvxl	v12,c48,rs
        addi	rs,rs,128
        lvxl	v13,0,rt
        lvxl	v14,c16,rt
        lvxl	v15,c32,rt
        lvxl	v16,c48,rt
        addi	rt,rs,64
        lvxl	v17,0,rs
        lvxl	v18,c16,rs
        lvxl	v19,c32,rs
        lvxl	v20,c48,rs
        addi	rs,rs,128
        lvxl	v21,0,rt
        lvxl	v22,c16,rt
        lvxl	v23,c32,rt
        lvxl	v24,c48,rt
        addi	rt,rs,64
        lvxl	v25,0,rs
        lvxl	v26,c16,rs
        lvxl	v27,c32,rs
        lvxl	v28,c48,rs
        addi	rs,rs,128
        lvxl	v29,0,rt
        lvxl	v30,c16,rt
        lvxl	v31,c32,rt
        lvxl	v0,c48,rt

        addi	rt,rd,64
        stvxl	v1,0,rd
        stvxl	v2,c16,rd
        stvxl	v3,c32,rd
        stvxl	v4,c48,rd
        addi	rd,rd,128
        stvxl	v5,0,rt
        stvxl	v6,c16,rt
        stvxl	v7,c32,rt
        stvxl	v8,c48,rt
        addi	rt,rd,64
        stvxl	v9,0,rd
        stvxl	v10,c16,rd
        stvxl	v11,c32,rd
        stvxl	v12,c48,rd
        addi	rd,rd,128
        stvxl	v13,0,rt
        stvxl	v14,c16,rt
        stvxl	v15,c32,rt
        stvxl	v16,c48,rt
        addi	rt,rd,64
        stvxl	v17,0,rd
        stvxl	v18,c16,rd
        stvxl	v19,c32,rd
        stvxl	v20,c48,rd
        addi	rd,rd,128
        stvxl	v21,0,rt
        stvxl	v22,c16,rt
        stvxl	v23,c32,rt
        stvxl	v24,c48,rt
        addi	rt,rd,64
        stvxl	v25,0,rd
        stvxl	v26,c16,rd
        stvxl	v27,c32,rd
        stvxl	v28,c48,rd
        addi	rd,rd,128
        stvxl	v29,0,rt
        stvxl	v30,c16,rt
        stvxl	v31,c32,rt
        stvxl	v0,c48,rt
        bge++	LalignedLoop		// loop if another 512 bytes to go

// End of aligned main loop.  Handle up to 511 leftover bytes.

        srwi.	r0,rc,5				// get count of 32-byte chunks remaining
        beq		Ldone				// none
        rlwinm	rc,rc,0,0x1F		// mask count down to 0..31 leftover bytes
        mtctr	r0
1:									// loop over 32-byte chunks
        lvx		v1,0,rs
        lvx		v2,c16,rs
        addi	rs,rs,32
        stvx	v1,0,rd
        stvx	v2,c16,rd
        addi	rd,rd,32
        bdnz	1b


// Done, except for 0..31 leftovers at end.  Restore non-volatiles.
//	rs = source ptr
//	rd = dest ptr
//	rc = count (0..31)
//	rv = caller's vrsave

Ldone:
        cmpwi	rc,0				// any leftover bytes?
        lwz		r13,rzR13(r1)		// restore non-volatiles from redzone
        lwz		r14,rzR14(r1)
        lwz		r15,rzR15(r1)
        li		r0,rzV20
        lvx		v20,r1,r0
        li		r0,rzV21
        lvx		v21,r1,r0
        li		r0,rzV22
        lvx		v22,r1,r0
        li		r0,rzV23
        lvx		v23,r1,r0
        li		r0,rzV24
        lvx		v24,r1,r0
        li		r0,rzV25
        lvx		v25,r1,r0
        li		r0,rzV26
        lvx		v26,r1,r0
        li		r0,rzV27
        lvx		v27,r1,r0
        li		r0,rzV28
        lvx		v28,r1,r0
        li		r0,rzV29
        lvx		v29,r1,r0
        li		r0,rzV30
        lvx		v30,r1,r0
        li		r0,rzV31
        lvx		v31,r1,r0
        mtspr	vrsave,rv			// restore caller's bitmask
        beqlr						// done if no leftover bytes
        

// Handle 1..31 leftover bytes at end.

        mtctr	rc					// set up loop count
        b		1f
        
        .align	5
1:
        lbz		r0,0(rs)
        addi	rs,rs,1
        stb		r0,0(rd)
        addi	rd,rd,1
        bdnz	1b
        
        blr


        COMMPAGE_DESCRIPTOR(bigcopy_970,_COMM_PAGE_BIGCOPY,0,0,0) // load on all machines for now


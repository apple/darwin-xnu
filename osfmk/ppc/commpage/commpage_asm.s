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

#include <sys/appleapiopts.h>
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>


// commpage_time_dcba() uses a stack frame as follows:

#define	kBufSiz		1024				// Size of the buffer we use to do DCBA timing on G4
#define	kSFSize		(kBufSiz+128+16)	// Stack frame size, which contains the 128-byte-aligned buffer
#define	kLoopCnt	5					// Iterations of the timing loop
#define	kDCBA		22					// Bit in cr5 used as a flag in timing loop

        .data
        .align	3							// three doubleword fields
Ldata:
        .long	0							// kkBinary0
        .long	0
        .double	1.0e0						// kkDouble1        
        .long	0x43300000					// kkTicksPerSec (plus 2**52)
        .long	0							// this is where we store ticks_per_sec, to float

        .text
        .align	2
        .globl	EXT(commpage_time_dcba)

/*	***************************************
 *	* C O M M P A G E _ T I M E _ D C B A *
 *	***************************************
 *
 *	Not all processors that support the DCBA opcode actually benefit from it.
 *	Some store-gather and read-cancel well enough that there is no need to use
 *	DCBA to avoid fetching cache lines that will be completely overwritten, while
 *	others have this feature disabled (to work around errata etc), and so benefit
 *	from DCBA.  Since it is hard to tell the one group from the other, we just
 *	time loops with and without DCBA, and pick the fastest.  Thus we avoid
 *	delicate dependence on processor and/or platform revisions.
 *
 *	We return either kDcbaRecommended or zero.
 *
 *		int commpage_time_dcba( void );
 */
 
LEXT(commpage_time_dcba)
        mflr	r12					// get return
        stw		r12,8(r1)			// save
        stwu	r1,-kSFSize(r1)		// carve our temp buffer from the stack
        addi	r11,r1,127+16		// get base address...
        rlwinm	r11,r11,0,0,24		// ...of our buffer, 128-byte aligned
        crset	kDCBA				// first, use DCBA
        bl		LTest				// time it with DCBA
        srwi	r0,r3,3				// bias 12 pct in favor of not using DCBA...
        add		r10,r3,r0			// ...because DCBA is always slower with warm cache
        crclr	kDCBA
        bl		LTest				// time without DCBA
        cmplw	r10,r3				// which is better?
        mtlr	r12					// restore return
        lwz		r1,0(r1)			// pop off our stack frame
        li		r3,kDcbaRecommended		// assume using DCBA is faster
        bltlr
        li		r3,0			// no DCBA is faster
        blr
                
        
// Subroutine to time a loop with or without DCBA.
//		kDCBA = set if we should use DCBA
//		r11 = base of buffer to use for test (kBufSiz bytes)
//
//		We return TBR ticks in r3.
//		We use r0,r3-r9.

LTest:
        li		r4,kLoopCnt			// number of times to loop
        li		r3,-1				// initialize fastest time
1:
        mr		r6,r11				// initialize buffer ptr
        li		r0,kBufSiz/32		// r0 <- cache blocks to test
        mtctr	r0
2:
        dcbf	0,r6				// first, force the blocks out of the cache
        addi	r6,r6,32
        bdnz	2b
        sync						// make sure all the flushes take
        mr		r6,r11				// re-initialize buffer ptr
        mtctr	r0					// reset cache-block count
        mftbu	r7					// remember upper half so we can check for carry
        mftb	r8					// start the timer
3:									// loop over cache blocks
        bf		kDCBA,4f			// should we DCBA?
        dcba	0,r6
4:
        stw		r0,0(r6)			// store the entire cache block
        stw		r0,4(r6)
        stw		r0,8(r6)
        stw		r0,12(r6)
        stw		r0,16(r6)
        stw		r0,20(r6)
        stw		r0,24(r6)
        stw		r0,28(r6)
        addi	r6,r6,32
        bdnz	3b
        mftb	r9
        mftbu	r0
        cmpw	r0,r7				// did timebase carry?
        bne		1b					// yes, retest rather than fuss
        sub		r9,r9,r8			// r9 <- time for this loop
        cmplw	r9,r3				// faster than current best?
        bge		5f					// no
        mr		r3,r9				// remember fastest time through loop
5:
        subi	r4,r4,1				// decrement outer loop count
        cmpwi	r4,0				// more to go?
        bne		1b					// loop if so
        blr							// return fastest time in r3

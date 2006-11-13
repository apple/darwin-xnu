/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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


// commpage_set_timestamp() uses the red zone for temporary storage:

#define	rzSaveF1			-8		// caller's FPR1
#define	rzSaveF2			-16		// caller's FPR2
#define	rzSaveF3			-24		// caller's FPR3
#define	rzSaveF4			-32		// caller's FPR4
#define	rzSaveF5			-40		// caller's FPR5
#define	rzNewTimeBase		-48		// used to load 64-bit TBR into a FPR


// commpage_set_timestamp() uses the following data.  kkTicksPerSec remembers
// the number used to compute _COMM_PAGE_SEC_PER_TICK.  Since this constant
// rarely changes, we use it to avoid needless recomputation.  It is a double
// value, pre-initialize with an exponent of 2**52.

#define	kkBinary0		0					// offset in data to long long 0 (a constant)
#define	kkDouble1		8					// offset in data to double 1.0 (a constant)
#define	kkTicksPerSec	16					// offset in data to double(ticks_per_sec)

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
        .globl	EXT(commpage_set_timestamp)


/*	***********************************************
 *	* C O M M P A G E _ S E T _ T I M E S T A M P *
 *	***********************************************
 *
 *	Update the gettimeofday() shared data on the commpages, as follows:
 *		_COMM_PAGE_TIMESTAMP = a BSD-style pair of uint_32's for secs and usecs
 *		_COMM_PAGE_TIMEBASE = the timebase at which the timestamp was valid
 *		_COMM_PAGE_SEC_PER_TICK = multiply timebase ticks by this to get seconds (double)
 *	The convention is that if the timebase is 0, the data is invalid.  Because other
 *	CPUs are reading the three values asynchronously and must get a consistent set, 
 *	it is critical that we update them with the following protocol:
 *		1. set timebase to 0 (atomically), to invalidate all three values
 *		2. eieio (to create a barrier in stores to cacheable memory)
 *		3. change timestamp and "secs per tick"
 *		4. eieio
 *		5. set timebase nonzero (atomically)
 *	This works because readers read the timebase, then the timestamp and divisor, sync
 *	if MP, then read the timebase a second time and check to be sure it is equal to the first.
 *
 *	We could save a few cycles on 64-bit machines by special casing them, but it probably
 *	isn't necessary because this routine shouldn't be called very often.
 *
 *	When called:
 *		r3 = upper half of timebase (timebase is disabled if 0)
 *		r4 = lower half of timebase
 *		r5 = seconds part of timestamp
 *		r6 = useconds part of timestamp
 *		r7 = divisor (ie, timebase ticks per sec)
 *	We set up:
 *		r8 = ptr to our static data (kkBinary0, kkDouble1, kkTicksPerSec)
 *		r9 = ptr to 32-bit commpage in kernel map
 *     r10 = ptr to 64-bit commpage in kernel map
 *
 *	--> Interrupts must be disabled and rtclock locked when called.  <--
 */
 
        .align	5
LEXT(commpage_set_timestamp)				// void commpage_set_timestamp(tbr,secs,usecs,divisor)
        mfmsr	r11							// get MSR
        ori		r2,r11,MASK(MSR_FP)			// turn FP on
        mtmsr	r2
        isync								// wait until MSR changes take effect
        
        or.		r0,r3,r4					// is timebase 0? (thus disabled)
        lis		r8,hi16(Ldata)				// point to our data
        lis		r9,ha16(EXT(commPagePtr32))	// get ptrs to address of commpages in kernel map
		lis		r10,ha16(EXT(commPagePtr64))
        stfd	f1,rzSaveF1(r1)				// save a FPR in the red zone
        ori		r8,r8,lo16(Ldata)
        lwz		r9,lo16(EXT(commPagePtr32))(r9)	// r9 <- 32-bit commpage ptr
		lwz		r10,lo16(EXT(commPagePtr64))(r10) // r10 <- 64-bit commpage ptr
        lfd		f1,kkBinary0(r8)			// get fixed 0s
        li		r0,_COMM_PAGE_BASE_ADDRESS	// get va in user space of commpage
        cmpwi	cr1,r9,0					// is 32-bit commpage allocated yet?
		cmpwi   cr6,r10,0					// is 64-bit commpage allocated yet?
        sub		r9,r9,r0					// r9 <- 32-bit commpage address, biased by user va
		sub		r10,r10,r0					// r10<- 64-bit commpage address
        beq--	cr1,3f						// skip if 32-bit commpage not allocated (64-bit won't be either)
		bne++   cr6,1f						// skip if 64-bit commpage is allocated
		mr		r10,r9						// if no 64-bit commpage, point to 32-bit version with r10 too
1:
        stfd	f1,_COMM_PAGE_TIMEBASE(r9)	// turn off the 32-bit-commpage timestamp (atomically)
		stfd	f1,_COMM_PAGE_TIMEBASE(r10) // and the 64-bit one too
        eieio								// make sure all CPUs see it is off
        beq		3f							// all we had to do is turn off timestamp
        
        lwz		r0,kkTicksPerSec+4(r8)		// get last ticks_per_sec (or 0 if first)
        stw		r3,rzNewTimeBase(r1)		// store new timebase so we can lfd
        stw		r4,rzNewTimeBase+4(r1)
        cmpw	r0,r7						// do we need to recompute _COMM_PAGE_SEC_PER_TICK?
        stw		r5,_COMM_PAGE_TIMESTAMP(r9)	// store the new timestamp in the 32-bit page
        stw		r6,_COMM_PAGE_TIMESTAMP+4(r9)
        stw		r5,_COMM_PAGE_TIMESTAMP(r10)// and the 64-bit commpage
        stw		r6,_COMM_PAGE_TIMESTAMP+4(r10)
        lfd		f1,rzNewTimeBase(r1)		// get timebase in a FPR so we can store atomically
        beq++	2f							// same ticks_per_sec, no need to recompute
        
        stw		r7,kkTicksPerSec+4(r8)		// must recompute SEC_PER_TICK
        stfd	f2,rzSaveF2(r1)				// we'll need a few more temp FPRs
        stfd	f3,rzSaveF3(r1)
        stfd	f4,rzSaveF4(r1)
        stfd	f5,rzSaveF5(r1)
        lfd		f2,_COMM_PAGE_2_TO_52(r9)	// f2 <- double(2**52)
        lfd		f3,kkTicksPerSec(r8)		// float new ticks_per_sec + 2**52
        lfd		f4,kkDouble1(r8)			// f4 <- double(1.0)
        mffs	f5							// save caller's FPSCR
        mtfsfi	7,0							// clear Inexeact Exception bit, set round-to-nearest
        fsub	f3,f3,f2					// get ticks_per_sec
        fdiv	f3,f4,f3					// divide 1 by ticks_per_sec to get SEC_PER_TICK
        stfd	f3,_COMM_PAGE_SEC_PER_TICK(r9)
        stfd	f3,_COMM_PAGE_SEC_PER_TICK(r10)
        mtfsf	0xFF,f5						// restore FPSCR
        lfd		f2,rzSaveF2(r1)				// restore FPRs
        lfd		f3,rzSaveF3(r1)
        lfd		f4,rzSaveF4(r1)
        lfd		f5,rzSaveF5(r1)
2:											// f1 == new timestamp
        eieio								// wait until the stores take
        stfd	f1,_COMM_PAGE_TIMEBASE(r9)	// then turn the timestamp back on (atomically)
        stfd	f1,_COMM_PAGE_TIMEBASE(r10)	// both
3:											// here once all fields updated
        lfd		f1,rzSaveF1(r1)				// restore last FPR
        mtmsr	r11							// turn FP back off
        isync
        blr


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

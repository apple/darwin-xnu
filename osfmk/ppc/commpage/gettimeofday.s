/*
 * Copyright (c) 2003-2005 Apple Computer, Inc. All rights reserved.
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
#include <ppc/asm.h>					// EXT, LEXT
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>

/* The red zone is used to move data between GPRs and FPRs: */

#define	rzTicks			-8			// elapsed ticks since timestamp (double)
#define	rzSeconds		-16			// seconds since timestamp (double)
#define	rzUSeconds		-24			// useconds since timestamp (double)


        .text
        .align	2


// *********************************
// * G E T T I M E O F D A Y _ 3 2 *
// *********************************
//
// This is a subroutine of gettimeofday.c that gets the seconds and microseconds
// in user mode, usually without having to make a system call.  We do not deal with
// the timezone.  The kernel maintains the following values in the comm page:
//
//	_COMM_PAGE_TIMESTAMP = 64 bit seconds timestamp
//
//	_COMM_PAGE_TIMEBASE = the timebase at which the timestamp was valid
//
//	_COMM_PAGE_SEC_PER_TICK = multiply timebase ticks by this to get seconds (double)
//
//	_COMM_PAGE_2_TO_52 = double precision constant 2**52
//
//	_COMM_PAGE_10_TO_6 = double precision constant 10**6
//
// We have to be careful to read these values atomically.  The kernel updates them 
// asynchronously to account for drift or time changes (eg, ntp.)  We adopt the
// convention that (timebase==0) means the timestamp is invalid, in which case we
// return a bad status so our caller can make the system call.
//
//		r3 = ptr to user's timeval structure (should not be null)

gettimeofday_32:								// int gettimeofday(timeval *tp);
0:
        lwz		r5,_COMM_PAGE_TIMEBASE+0(0)		// r5,r6 = TBR at timestamp
        lwz		r6,_COMM_PAGE_TIMEBASE+4(0)
        lwz		r8,_COMM_PAGE_TIMESTAMP+4(0)	// r8 = timestamp 32 bit seconds
        lfd		f1,_COMM_PAGE_SEC_PER_TICK(0)
1:        
        mftbu	r10								// r10,r11 = current timebase
        mftb	r11
        mftbu	r12
        cmplw	r10,r12
        bne-	1b
        or.		r0,r5,r6						// timebase 0? (ie, is timestamp invalid?)
        
        sync									// create a barrier (patched to NOP if UP)
        
        lwz		r0,_COMM_PAGE_TIMEBASE+0(0)		// then load data a 2nd time
        lwz		r12,_COMM_PAGE_TIMEBASE+4(0)
        lwz		r9,_COMM_PAGE_TIMESTAMP+4(0)
        cmplw	cr6,r5,r0			// did we read a consistent set?
        cmplw	cr7,r6,r12
        beq-	3f					// timestamp is disabled so return bad status
        cmplw	cr5,r9,r8
        crand	cr0_eq,cr6_eq,cr7_eq
        crand	cr0_eq,cr0_eq,cr5_eq
        bne-	0b					// loop until we have a consistent set of data
        
        subfc	r11,r6,r11			// compute ticks since timestamp
        lwz		r9,_COMM_PAGE_2_TO_52(0)	// get exponent for (2**52)
        subfe	r10,r5,r10			// complete 64-bit subtract
        lfd		f2,_COMM_PAGE_2_TO_52(0)	// f2 <- (2**52)
        srwi.	r0,r10,2			// if more than 2**34 ticks have elapsed...
        stw		r11,rzTicks+4(r1)	// store elapsed ticks into red zone
        or		r10,r10,r9			// convert long-long in (r10,r11) into double
        bne-	3f					// ...call kernel to reprime timestamp

        stw		r10,rzTicks(r1)		// complete double

		mffs	f7
		mtfsfi	7,1        
        lfd		f3,rzTicks(r1)		// get elapsed ticks since timestamp + 2**52
        fsub	f4,f3,f2			// subtract 2**52 and normalize
        fmul	f5,f4,f1			// f5 <- elapsed seconds since timestamp
        lfd		f3,_COMM_PAGE_10_TO_6(0)	// get 10**6
        fctiwz	f6,f5				// convert to integer
        stfd	f6,rzSeconds(r1)	// store integer seconds into red zone
        stw		r9,rzSeconds(r1)	// prepare to reload as floating pt
        lfd		f6,rzSeconds(r1)	// get seconds + 2**52
        fsub	f6,f6,f2			// f6 <- integral seconds
        fsub	f6,f5,f6			// f6 <- fractional part of elapsed seconds
        fmul	f6,f6,f3			// f6 <- fractional elapsed useconds
        fctiwz	f6,f6				// convert useconds to integer
        stfd	f6,rzUSeconds(r1)	// store useconds into red zone
		mtfsf	0xff,f7
        
        lwz		r5,rzSeconds+4(r1)	// r5 <- seconds since timestamp
        lwz		r7,rzUSeconds+4(r1)	// r7 <- useconds since timestamp
        add		r6,r8,r5			// add elapsed seconds to timestamp seconds
        
        stw		r6,0(r3)			// store secs//usecs into user's timeval
        stw		r7,4(r3)
        li		r3,0				// return success
        blr
3:									// too long since last timestamp or this code is disabled
        li		r3,1				// return bad status so our caller will make syscall
        blr
        
	COMMPAGE_DESCRIPTOR(gettimeofday_32,_COMM_PAGE_GETTIMEOFDAY,0,k64Bit,kCommPageSYNC+kCommPage32)
        
        
// ***************************************
// * G E T T I M E O F D A Y _ G 5 _ 3 2 *
// ***************************************
//
// This routine is called in 32-bit mode on 64-bit processors.  A timeval is a struct of
// a long seconds and int useconds, so its size depends on mode.

gettimeofday_g5_32:							// int gettimeofday(timeval *tp);
0:
        ld		r6,_COMM_PAGE_TIMEBASE(0)	// r6 = TBR at timestamp
        ld		r8,_COMM_PAGE_TIMESTAMP(0)	// r8 = timestamp (seconds)
        lfd		f1,_COMM_PAGE_SEC_PER_TICK(0)
        mftb	r10							// r10 = get current timebase
        lwsync								// create a barrier if MP (patched to NOP if UP)
        ld		r11,_COMM_PAGE_TIMEBASE(0)	// then get data a 2nd time
        ld		r12,_COMM_PAGE_TIMESTAMP(0)
        cmpdi	cr1,r6,0			// is the timestamp disabled?
        cmpld	cr6,r6,r11			// did we read a consistent set?
        cmpld	cr7,r8,r12
        beq--	cr1,3f				// exit if timestamp disabled
        crand	cr6_eq,cr7_eq,cr6_eq
        sub		r11,r10,r6			// compute elapsed ticks from timestamp
        bne--	cr6,0b				// loop until we have a consistent set of data
                
        srdi.	r0,r11,35			// has it been more than 2**35 ticks since last timestamp?
        std		r11,rzTicks(r1)		// put ticks in redzone where we can "lfd" it
        bne--	3f					// timestamp too old, so reprime

		mffs	f7
		mtfsfi	7,1
        lfd		f3,rzTicks(r1)		// get elapsed ticks since timestamp (fixed pt)
        fcfid	f4,f3				// float the tick count
        fmul	f5,f4,f1			// f5 <- elapsed seconds since timestamp
        lfd		f3,_COMM_PAGE_10_TO_6(0)	// get 10**6
        fctidz	f6,f5				// convert integer seconds to fixed pt
        stfd	f6,rzSeconds(r1)	// save fixed pt integer seconds in red zone
        fcfid	f6,f6				// float the integer seconds
        fsub	f6,f5,f6			// f6 <- fractional part of elapsed seconds
        fmul	f6,f6,f3			// f6 <- fractional elapsed useconds
        fctidz	f6,f6				// convert useconds to fixed pt integer
        stfd	f6,rzUSeconds(r1)	// store useconds into red zone
		mtfsf	0xff,f7
        
        lwz		r5,rzSeconds+4(r1)	// r5 <- seconds since timestamp
        lwz		r7,rzUSeconds+4(r1)	// r7 <- useconds since timestamp
        add		r6,r8,r5			// add elapsed seconds to timestamp seconds
        
        stw		r6,0(r3)			// store secs//usecs into user's timeval
        stw		r7,4(r3)
        li		r3,0				// return success
        blr
3:									// too long since last timestamp or this code is disabled
        li		r3,1				// return bad status so our caller will make syscall
        blr

	COMMPAGE_DESCRIPTOR(gettimeofday_g5_32,_COMM_PAGE_GETTIMEOFDAY,k64Bit,0,kCommPageSYNC+kCommPage32)
        
        
// ***************************************
// * G E T T I M E O F D A Y _ G 5 _ 6 4 *
// ***************************************
//
// This routine is called in 64-bit mode on 64-bit processors.  A timeval is a struct of
// a long seconds and int useconds, so its size depends on mode.

gettimeofday_g5_64:							// int gettimeofday(timeval *tp);
0:
        ld		r6,_COMM_PAGE_TIMEBASE(0)	// r6 = TBR at timestamp
        ld		r8,_COMM_PAGE_TIMESTAMP(0)	// r8 = timestamp (seconds)
        lfd		f1,_COMM_PAGE_SEC_PER_TICK(0)
        mftb	r10							// r10 = get current timebase
        lwsync								// create a barrier if MP (patched to NOP if UP)
        ld		r11,_COMM_PAGE_TIMEBASE(0)	// then get data a 2nd time
        ld		r12,_COMM_PAGE_TIMESTAMP(0)
        cmpdi	cr1,r6,0			// is the timestamp disabled?
        cmpld	cr6,r6,r11			// did we read a consistent set?
        cmpld	cr7,r8,r12
        beq--	cr1,3f				// exit if timestamp disabled
        crand	cr6_eq,cr7_eq,cr6_eq
        sub		r11,r10,r6			// compute elapsed ticks from timestamp
        bne--	cr6,0b				// loop until we have a consistent set of data
                
        srdi.	r0,r11,35			// has it been more than 2**35 ticks since last timestamp?
        std		r11,rzTicks(r1)		// put ticks in redzone where we can "lfd" it
        bne--	3f					// timestamp too old, so reprime

		mffs	f7
		mtfsfi	7,1
        lfd		f3,rzTicks(r1)		// get elapsed ticks since timestamp (fixed pt)
        fcfid	f4,f3				// float the tick count
        fmul	f5,f4,f1			// f5 <- elapsed seconds since timestamp
        lfd		f3,_COMM_PAGE_10_TO_6(0)	// get 10**6
        fctidz	f6,f5				// convert integer seconds to fixed pt
        stfd	f6,rzSeconds(r1)	// save fixed pt integer seconds in red zone
        fcfid	f6,f6				// float the integer seconds
        fsub	f6,f5,f6			// f6 <- fractional part of elapsed seconds
        fmul	f6,f6,f3			// f6 <- fractional elapsed useconds
        fctidz	f6,f6				// convert useconds to fixed pt integer
        stfd	f6,rzUSeconds(r1)	// store useconds into red zone
		mtfsf	0xff,f7
        
        lwz		r5,rzSeconds+4(r1)	// r5 <- seconds since timestamp
        lwz		r7,rzUSeconds+4(r1)	// r7 <- useconds since timestamp
        add		r6,r8,r5			// add elapsed seconds to timestamp seconds
        
        std		r6,0(r3)			// store secs//usecs into user's timeval
        stw		r7,8(r3)
        li		r3,0				// return success
        blr
3:									// too long since last timestamp or this code is disabled
        li		r3,1				// return bad status so our caller will make syscall
        blr

	COMMPAGE_DESCRIPTOR(gettimeofday_g5_64,_COMM_PAGE_GETTIMEOFDAY,k64Bit,0,kCommPageSYNC+kCommPage64)

        

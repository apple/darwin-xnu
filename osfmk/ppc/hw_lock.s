/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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

#include <cpus.h>
#include <mach_assert.h>
#include <mach_ldebug.h>
#include <mach_rt.h>
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <assym.s>

#define	STRING	ascii

#define	SWT_HI	0+FM_SIZE
#define SWT_LO	4+FM_SIZE
#define MISSED	8+FM_SIZE

#define	ILK_LOCKED		0x01
#define	WAIT_FLAG		0x02
#define TH_FN_OWNED		0x01

#define CHECKNMI 0
#define CHECKLOCKS 1

#define PROLOG(space)											\
			stwu	r1,-(FM_ALIGN(space)+FM_SIZE)(r1)	__ASMNL__	\
			mflr	r0								__ASMNL__	\
			stw		r3,FM_ARG0(r1)					__ASMNL__	\
			stw		r0,(FM_ALIGN(space)+FM_SIZE+FM_LR_SAVE)(r1)	__ASMNL__
	
#define EPILOG												 	\
			lwz		r1,0(r1)						__ASMNL__	\
			lwz		r0,FM_LR_SAVE(r1)				__ASMNL__	\
			mtlr	r0								__ASMNL__

#if	MACH_LDEBUG && CHECKLOCKS
/*
 * Routines for general lock debugging.
 */

/* 
 * Gets lock check flags in CR6: CR bits 24-27
 */

#define CHECK_SETUP(rg)											\
			lbz		rg,dgFlags(0)					__ASMNL__ 	\
			mtcrf	2,rg							__ASMNL__ 


/*
 * Checks for expected lock types and calls "panic" on
 * mismatch.  Detects calls to Mutex functions with
 * type simplelock and vice versa.
 */
#define	CHECK_MUTEX_TYPE()										\
			bt		24+disLktypeb,1f				__ASMNL__ 	\
			lwz		r10,MUTEX_TYPE(r3)				__ASMNL__ 	\
			cmpwi	r10,MUTEX_TAG					__ASMNL__	\
			beq+	1f								__ASMNL__	\
			lis		r3,hi16(not_a_mutex)			__ASMNL__	\
			ori		r3,r3,lo16(not_a_mutex)			__ASMNL__	\
			bl		EXT(panic)						__ASMNL__	\
			lwz		r3,FM_ARG0(r1)					__ASMNL__	\
1:
	
	.data
not_a_mutex:
			STRINGD	"not a mutex!\n\000"
			.text

#define CHECK_SIMPLE_LOCK_TYPE()								\
			bt		24+disLktypeb,1f				__ASMNL__ 	\
			lhz		r10,SLOCK_TYPE(r3)				__ASMNL__ 	\
			cmpwi	r10,USLOCK_TAG					__ASMNL__ 	\
			beq+	1f								__ASMNL__ 	\
			lis		r3,hi16(not_a_slock)			__ASMNL__ 	\
			ori		r3,r3,lo16(not_a_slock) 		__ASMNL__ 	\
			bl		EXT(panic)						__ASMNL__ 	\
			lwz		r3,FM_ARG0(r1)					__ASMNL__ 	\
1:
	
	.data
not_a_slock:
			STRINGD	"not a simple lock!\n\000"
			.text

#define CHECK_NO_SIMPLELOCKS()									\
			bt		24+disLkNmSimpb,2f				__ASMNL__	\
			lis		r10,hi16(MASK(MSR_VEC))			__ASMNL__	\
			ori		r10,r10,lo16(MASK(MSR_FP))		__ASMNL__	\
			mfmsr	r11								__ASMNL__	\
			andc	r11,r11,r10						__ASMNL__	\
			ori		r10,r10,lo16(MASK(MSR_EE))		__ASMNL__	\
			andc	r10,r11,r10						__ASMNL__	\
			mtmsr	r10								__ASMNL__	\
			isync									__ASMNL__	\
			mfsprg	r10,0							__ASMNL__	\
			lwz		r10,PP_SIMPLE_LOCK_CNT(r10)		__ASMNL__	\
			cmpwi	r10,0 							__ASMNL__	\
			beq+	1f 								__ASMNL__	\
			lis		r3,hi16(simple_locks_held)		__ASMNL__	\
			ori		r3,r3,lo16(simple_locks_held)	__ASMNL__	\
			bl		EXT(panic)	 					__ASMNL__	\
			lwz		r3,FM_ARG0(r1)	 				__ASMNL__ 	\
1:													__ASMNL__	\
			mtmsr	r11								__ASMNL__	\
2:	
	
	.data
simple_locks_held:
			STRINGD	"simple locks held!\n\000"
			.text

/* 
 * Verifies return to the correct thread in "unlock" situations.
 */
#define CHECK_THREAD(thread_offset)								\
			bt		24+disLkThreadb,2f				__ASMNL__ 	\
			lis		r10,hi16(MASK(MSR_VEC))			__ASMNL__	\
			ori		r10,r10,lo16(MASK(MSR_FP))		__ASMNL__	\
			mfmsr	r11								__ASMNL__	\
			andc	r11,r11,r10						__ASMNL__	\
			ori		r10,r10,lo16(MASK(MSR_EE))		__ASMNL__	\
			andc	r10,r11,r10						__ASMNL__	\
			mtmsr	r10								__ASMNL__	\
			isync									__ASMNL__	\
			mfsprg	r10,0							__ASMNL__	\
			lwz		r10,PP_ACTIVE_THREAD(r10)		__ASMNL__	\
			cmpwi	r10,0	 						__ASMNL__ 	\
			beq-	1f 								__ASMNL__ 	\
			lwz		r9,thread_offset(r3) 			__ASMNL__ 	\
			cmpw	r9,r10	 						__ASMNL__ 	\
			beq+	1f 								__ASMNL__ 	\
			lis		r3,hi16(wrong_thread) 			__ASMNL__	\
			ori		r3,r3,lo16(wrong_thread)		__ASMNL__ 	\
			bl		EXT(panic)	 					__ASMNL__ 	\
			lwz		r3,FM_ARG0(r1)	 				__ASMNL__ 	\
1:													__ASMNL__	\
			mtmsr	r11								__ASMNL__	\
2:	
	.data
wrong_thread:
	STRINGD	"wrong thread!\n\000"
	.text

#define CHECK_MYLOCK(thread_offset)								\
			bt		24+disLkMyLckb,2f				__ASMNL__ 	\
			lis		r10,hi16(MASK(MSR_VEC))			__ASMNL__	\
			ori		r10,r10,lo16(MASK(MSR_FP))		__ASMNL__	\
			mfmsr	r11								__ASMNL__	\
			andc	r11,r11,r10						__ASMNL__	\
			ori		r10,r10,lo16(MASK(MSR_EE))		__ASMNL__	\
			andc	r10,r11,r10						__ASMNL__	\
			mtmsr	r10								__ASMNL__	\
			isync									__ASMNL__	\
			mfsprg	r10,0							__ASMNL__	\
			lwz		r10,PP_ACTIVE_THREAD(r10)		__ASMNL__	\
			cmpwi	r10,0	 						__ASMNL__	\
			beq-	1f 								__ASMNL__	\
			lwz		r9,	thread_offset(r3) 			__ASMNL__	\
			cmpw	r9,r10	 						__ASMNL__	\
			bne+	1f 								__ASMNL__	\
			lis		r3,	hi16(mylock_attempt)		__ASMNL__	\
			ori		r3,r3,lo16(mylock_attempt)		__ASMNL__	\
			bl		EXT(panic)	 					__ASMNL__	\
			lwz		r3,FM_ARG0(r1)	 				__ASMNL__	\
1:													__ASMNL__	\
			mtmsr	r11								__ASMNL__	\
2:
	
	.data
mylock_attempt:
	STRINGD	"mylock attempt!\n\000"
	.text

#else	/* MACH_LDEBUG */

#define CHECK_SETUP(rg)
#define CHECK_MUTEX_TYPE()
#define CHECK_SIMPLE_LOCK_TYPE()
#define CHECK_THREAD(thread_offset)
#define CHECK_NO_SIMPLELOCKS()
#define CHECK_MYLOCK(thread_offset)

#endif	/* MACH_LDEBUG */
	
/*
 *		void hw_lock_init(hw_lock_t)
 *
 *			Initialize a hardware lock.
 */
			.align	5
			.globl	EXT(hw_lock_init)

LEXT(hw_lock_init)

			li	r0,	0								; set lock to free == 0 
			stw	r0,	0(r3)							; Initialize the lock 
			blr
	
/*
 *      void hw_lock_unlock(hw_lock_t)
 *
 *      Unconditionally release lock.
 *      Release preemption level.
 */
			.align	5
			.globl	EXT(hw_lock_unlock)

LEXT(hw_lock_unlock)

			.globl  EXT(hwulckPatch_isync)
LEXT(hwulckPatch_isync)   
			isync 
			.globl  EXT(hwulckPatch_eieio)
LEXT(hwulckPatch_eieio)
			eieio
			li	r0,	0								; set lock to free
			stw	r0,	0(r3)

			b		epStart							; Go enable preemption...

/*
 *      void hw_lock_lock(hw_lock_t)
 *
 *			Acquire lock, spinning until it becomes available.
 *			Return with preemption disabled.
 *			We will just set a default timeout and jump into the NORMAL timeout lock.
 */
			.align	5
			.globl	EXT(hw_lock_lock)

LEXT(hw_lock_lock)
lockDisa:
			li		r4,0							; no timeout value
			b		lckcomm							; Join on up...

/*
 *		unsigned int hw_lock_to(hw_lock_t, unsigned int timeout)
 *
 *			Try to acquire spin-lock. Return success (1) or failure (0).
 *			Attempt will fail after timeout ticks of the timebase.
 *			We try fairly hard to get this lock.  We disable for interruptions, but
 *			reenable after a "short" timeout (128 ticks, we may want to change this).
 *			After checking to see if the large timeout value (passed in) has expired and a
 *			sufficient number of cycles have gone by (to insure pending 'rupts are taken),
 *			we return either in abject failure, or disable and go back to the lock sniff routine.
 *			If the sniffer finds the lock free, it jumps right up and tries to grab it.
 */
			.align	5
			.globl	EXT(hw_lock_to)

LEXT(hw_lock_to)

#if CHECKNMI
			mflr	r12								; (TEST/DEBUG) 
			bl		EXT(ml_sense_nmi)				; (TEST/DEBUG)
			mtlr	r12								; (TEST/DEBUG)
#endif

lckcomm:
			mfsprg	r6,1							; Get the current activation 
			lwz		r5,ACT_PREEMPT_CNT(r6)			; Get the preemption level
			addi	r5,r5,1							; Bring up the disable count
			stw		r5,ACT_PREEMPT_CNT(r6)			; Save it back 
			mr		r5,r3							; Get the address of the lock
			li		r8,0							; Set r8 to zero

lcktry:		lwarx	r6,0,r5							; Grab the lock value
			andi.	r3,r6,ILK_LOCKED				; Is it locked?
			ori		r6,r6,ILK_LOCKED				; Set interlock 
			bne--	lckspin							; Yeah, wait for it to clear...
			stwcx.	r6,0,r5							; Try to seize that there durn lock
			bne--	lcktry							; Couldn't get it...
			li		r3,1							; return true 
			isync									; Make sure we don't use a speculativily loaded value
			blr										; Go on home...

lckspin:	li		r6,lgKillResv					; Get killing field	
			stwcx.	r6,0,r6							; Kill reservation
			
			mr.		r4,r4							; Test timeout value
			bne++	lockspin0
			lis		r4,hi16(EXT(LockTimeOut))		; Get the high part 
			ori		r4,r4,lo16(EXT(LockTimeOut))	; And the low part
			lwz		r4,0(r4)						; Get the timeout value
lockspin0:
			mr.		r8,r8							; Is r8 set to zero
			bne++	lockspin1						; If yes, first spin attempt
			lis		r0,hi16(MASK(MSR_VEC))			; Get vector enable
			mfmsr	r9								; Get the MSR value
			ori		r0,r0,lo16(MASK(MSR_FP))		; Get FP enable
			ori		r7,r0,lo16(MASK(MSR_EE))		; Get EE bit on too
			andc	r9,r9,r0						; Clear FP and VEC
			andc	r7,r9,r7						; Clear EE as well
			mtmsr	r7								; Turn off interruptions 
			isync									; May have turned off vec and fp here 
			mftb	r8								; Get timestamp on entry
			b		lcksniff

lockspin1:	mtmsr	r7								; Turn off interruptions 
			mftb	r8								; Get timestamp on entry

lcksniff:	lwz		r3,0(r5)						; Get that lock in here
			andi.	r3,r3,ILK_LOCKED				; Is it free yet?
			beq++	lckretry						; Yeah, try for it again...
			
			mftb	r10								; Time stamp us now
			sub		r10,r10,r8						; Get the elapsed time
			cmplwi	r10,128							; Have we been spinning for 128 tb ticks?
			blt++	lcksniff						; Not yet...
			
			mtmsr	r9								; Say, any interrupts pending?

;			The following instructions force the pipeline to be interlocked to that only one
;			instruction is issued per cycle.  The insures that we stay enabled for a long enough
;			time; if it's too short, pending interruptions will not have a chance to be taken

			subi	r4,r4,128						; Back off elapsed time from timeout value
			or		r4,r4,r4						; Do nothing here but force a single cycle delay
			mr.		r4,r4							; See if we used the whole timeout
			li		r3,0							; Assume a timeout return code
			or		r4,r4,r4						; Do nothing here but force a single cycle delay
			
			ble--	lckfail							; We failed
			b		lockspin1						; Now that we've opened an enable window, keep trying...
lckretry:
			mtmsr	r9								; Restore interrupt state
			li		r8,1							; Insure that R8 is not 0
			b		lcktry
lckfail:											; We couldn't get the lock
			li		r3,0							; Set failure return code
			blr										; Return, head hanging low...


/*
 *		unsigned int hw_lock_bit(hw_lock_t, unsigned int bit, unsigned int timeout)
 *
 *			Try to acquire spin-lock. The second parameter is the bit mask to test and set.
 *			multiple bits may be set. Return success (1) or failure (0).
 *			Attempt will fail after timeout ticks of the timebase.
 *			We try fairly hard to get this lock.  We disable for interruptions, but
 *			reenable after a "short" timeout (128 ticks, we may want to shorten this).
 *			After checking to see if the large timeout value (passed in) has expired and a
 *			sufficient number of cycles have gone by (to insure pending 'rupts are taken),
 *			we return either in abject failure, or disable and go back to the lock sniff routine.
 *			If the sniffer finds the lock free, it jumps right up and tries to grab it.
 */
			.align	5
			.globl	EXT(hw_lock_bit)

LEXT(hw_lock_bit)

			li		r10,0			

bittry:		lwarx	r6,0,r3							; Grab the lock value 
			and.	r0,r6,r4						; See if any of the lock bits are on 
			or		r6,r6,r4						; Turn on the lock bits 
			bne--	bitspin							; Yeah, wait for it to clear... 
			stwcx.	r6,0,r3							; Try to seize that there durn lock 
			bne--	bittry							; Just start up again if the store failed...
		
			li		r3,1							; Set good return code 
			isync									; Make sure we don't use a speculativily loaded value 
			blr

			.align	5

bitspin:	li		r11,lgKillResv					; Get killing field	
			stwcx.	r11,0,r11						; Kill reservation
			
			mr.		r10,r10							; Is r8 set to zero
			li		r10,1							; Close gate
			beq--	bit1sttime						; If yes, first spin attempt

bitspin0:	mtmsr	r7								; Turn off interruptions 
			mftb	r8								; Get the low part of the time base 

bitsniff:	lwz		r6,0(r3)						; Get that lock in here 
			and.	r0,r6,r4						; See if any of the lock bits are on 
			beq++	bitretry						; Yeah, try for it again...
			
			mftb	r6								; Time stamp us now 
			sub		r6,r6,r8						; Get the elapsed time 
			cmplwi	r6,128							; Have we been spinning for 128 tb ticks? 
			blt++	bitsniff						; Not yet... 
			
			mtmsr	r9								; Say, any interrupts pending? 

;			The following instructions force the pipeline to be interlocked to that only one
;			instruction is issued per cycle.  The insures that we stay enabled for a long enough
;			time. If it's too short, pending interruptions will not have a chance to be taken 

			subi	r5,r5,128						; Back off elapsed time from timeout value
			or		r5,r5,r5						; Do nothing here but force a single cycle delay
			mr.		r5,r5							; See if we used the whole timeout
			or		r5,r5,r5						; Do nothing here but force a single cycle delay
			
			bgt++	bitspin0						; Now that we've opened an enable window, keep trying...
		
			li		r3,0							; Set failure return code
			blr										; Return, head hanging low...

bitretry:	mtmsr	r9								; Enable for interruptions
			b		bittry

bit1sttime:	lis		r0,hi16(MASK(MSR_VEC))			; Get vector enable
			mfmsr	r9								; Get the MSR value
			ori		r0,r0,lo16(MASK(MSR_FP))		; Get FP enable
			ori		r7,r0,lo16(MASK(MSR_EE))		; Get EE bit on too
			andc	r9,r9,r0						; Clear FP and VEC
			andc	r7,r9,r7						; Clear EE as well
			mtmsr	r7								; Turn off interruptions 
			isync									; May have turned off vec and fp here 
			mftb	r8								; Get the low part of the time base 
			b		bitsniff

			.align	5


/*
 *		unsigned int hw_unlock_bit(hw_lock_t, unsigned int bit)
 *
 *			Release bit based spin-lock. The second parameter is the bit mask to clear.
 *			Multiple bits may be cleared.
 *
 */
			.align	5
			.globl	EXT(hw_unlock_bit)

LEXT(hw_unlock_bit)

			.globl  EXT(hwulckbPatch_isync)
LEXT(hwulckbPatch_isync)   
			isync 
			.globl  EXT(hwulckbPatch_eieio)
LEXT(hwulckbPatch_eieio)
			eieio
ubittry:	lwarx	r0,0,r3							; Grab the lock value
			andc	r0,r0,r4						; Clear the lock bits
			stwcx.	r0,0,r3							; Try to clear that there durn lock
			bne-	ubittry							; Try again, couldn't save it...

			blr										; Leave...

/*
 *		unsigned int hw_lock_mbits(hw_lock_t, unsigned int bits, unsigned int value, 
 *			unsigned int newb, unsigned int timeout)
 *
 *			Try to acquire spin-lock. The second parameter is the bit mask to check.
 *			The third is the value of those bits and the 4th is what to set them to.
 *			Return success (1) or failure (0).
 *			Attempt will fail after timeout ticks of the timebase.
 *			We try fairly hard to get this lock.  We disable for interruptions, but
 *			reenable after a "short" timeout (128 ticks, we may want to shorten this).
 *			After checking to see if the large timeout value (passed in) has expired and a
 *			sufficient number of cycles have gone by (to insure pending 'rupts are taken),
 *			we return either in abject failure, or disable and go back to the lock sniff routine.
 *			If the sniffer finds the lock free, it jumps right up and tries to grab it.
 */
			.align	5
			.globl	EXT(hw_lock_mbits)

LEXT(hw_lock_mbits)

			li		r10,0			

mbittry:	lwarx	r12,0,r3						; Grab the lock value
			and		r0,r12,r4						; Clear extra bits
			andc	r12,r12,r4						; Clear all bits in the bit mask
			or		r12,r12,r6						; Turn on the lock bits
			cmplw	r0,r5							; Are these the right bits?
			bne--	mbitspin						; Nope, wait for it to clear...
			stwcx.	r12,0,r3						; Try to seize that there durn lock
			beq++	mbitgot							; We got it, yahoo...
			b		mbittry							; Just start up again if the store failed...

			.align	5
mbitspin:	li		r11,lgKillResv					; Point to killing field
			stwcx.	r11,0,r11						; Kill it
			
			mr.		r10,r10							; Is r10 set to zero
			bne++	mbitspin0						; If yes, first spin attempt
			lis		r0,hi16(MASK(MSR_VEC))			; Get vector enable
			mfmsr	r9								; Get the MSR value
			ori		r0,r0,lo16(MASK(MSR_FP))		; Get FP enable
			ori		r8,r0,lo16(MASK(MSR_EE))		; Get EE bit on too
			andc	r9,r9,r0						; Clear FP and VEC
			andc	r8,r9,r8						; Clear EE as well
			mtmsr	r8								; Turn off interruptions
			isync									; May have turned off vectors or float here
			mftb	r10								; Get the low part of the time base
			b		mbitsniff
mbitspin0:
			mtmsr	r8								; Turn off interruptions
			mftb	r10								; Get the low part of the time base
mbitsniff:
			lwz		r12,0(r3)						; Get that lock in here
			and		r0,r12,r4						; Clear extra bits
			cmplw	r0,r5							; Are these the right bits?
			beq++	mbitretry						; Yeah, try for it again...
			
			mftb	r11								; Time stamp us now
			sub		r11,r11,r10						; Get the elapsed time
			cmplwi	r11,128							; Have we been spinning for 128 tb ticks?
			blt++	mbitsniff						; Not yet...
			
			mtmsr	r9								; Say, any interrupts pending?			

;			The following instructions force the pipeline to be interlocked to that only one
;			instruction is issued per cycle.  The insures that we stay enabled for a long enough
;			time. If it is too short, pending interruptions will not have a chance to be taken 
			
			subi	r7,r7,128						; Back off elapsed time from timeout value
			or		r7,r7,r7						; Do nothing here but force a single cycle delay
			mr.		r7,r7							; See if we used the whole timeout
			or		r7,r7,r7						; Do nothing here but force a single cycle delay
			
			ble--	mbitfail						; We failed
			b		mbitspin0						; Now that we have opened an enable window, keep trying...
mbitretry:
			mtmsr	r9								; Enable for interruptions
			li		r10,1							; Make sure this is non-zero
			b		mbittry

			.align	5
mbitgot:	
			li		r3,1							; Set good return code
			isync									; Make sure we do not use a speculativily loaded value
			blr

mbitfail:	li		r3,0							; Set failure return code
			blr										; Return, head hanging low...

/*
 *      unsigned int hw_cpu_sync(unsigned int *, unsigned int timeout)
 *
 *			Spin until word hits 0 or timeout. 
 *			Return success (1) or failure (0).
 *			Attempt will fail after timeout ticks of the timebase.
 *
 *			The theory is that a processor will bump a counter as it signals
 *			other processors.  Then it will spin untl the counter hits 0 (or
 *			times out).  The other processors, as it receives the signal will 
 *			decrement the counter.
 *
 *			The other processors use interlocked update to decrement, this one
 *			does not need to interlock.
 */
			.align	5
			.globl	EXT(hw_cpu_sync)

LEXT(hw_cpu_sync)

			mftb	r10								; Get the low part of the time base
			mr		r9,r3							; Save the sync word address
			li		r3,1							; Assume we work

csynctry:	lwz		r11,0(r9)						; Grab the sync value
			mr.		r11,r11							; Counter hit 0?
			beqlr-									; Yeah, we are sunk...
			mftb	r12								; Time stamp us now

			sub		r12,r12,r10						; Get the elapsed time
			cmplw	r4,r12							; Have we gone too long?
			bge+	csynctry						; Not yet...
			
			li		r3,0							; Set failure...
			blr										; Return, head hanging low...

/*
 *      unsigned int hw_cpu_wcng(unsigned int *, unsigned int, unsigned int timeout)
 *
 *			Spin until word changes or timeout. 
 *			Return success (1) or failure (0).
 *			Attempt will fail after timeout ticks of the timebase.
 *
 *			This is used to insure that a processor passes a certain point.
 *			An example of use is to monitor the last interrupt time in the 
 *			per_proc block.  This can be used to insure that the other processor
 *			has seen at least one interrupt since a specific time.
 */
			.align	5
			.globl	EXT(hw_cpu_wcng)

LEXT(hw_cpu_wcng)

			mftb	r10								; Get the low part of the time base
			mr		r9,r3							; Save the sync word address
			li		r3,1							; Assume we work

wcngtry:	lwz		r11,0(r9)						; Grab the  value
			cmplw	r11,r4							; Do they still match?
			bnelr-									; Nope, cool...
			mftb	r12								; Time stamp us now

			sub		r12,r12,r10						; Get the elapsed time
			cmplw	r5,r12							; Have we gone too long?
			bge+	wcngtry							; Not yet...
			
			li		r3,0							; Set failure...
			blr										; Return, head hanging low...
			

/*
 *		unsigned int hw_lock_try(hw_lock_t)
 *
 *			Try to acquire spin-lock. Return success (1) or failure (0)
 *			Returns with preemption disabled on success.
 *
 */
			.align	5
			.globl	EXT(hw_lock_try)

LEXT(hw_lock_try)

			lis		r0,hi16(MASK(MSR_VEC))			; Get vector enable
			mfmsr	r9								; Get the MSR value 
			ori		r0,r0,lo16(MASK(MSR_FP))		; Get FP enable
			ori		r7,r0,lo16(MASK(MSR_EE))		; Get EE bit on too
			andc	r9,r9,r0						; Clear FP and VEC
			andc	r7,r9,r7						; Clear EE as well

			mtmsr	r7								; Disable interruptions and thus, preemption

			lwz		r5,0(r3)						; Quick load
			andi.	r6,r5,ILK_LOCKED				; TEST...
			bne--	.L_lock_try_failed				; No go...

.L_lock_try_loop:	
			lwarx	r5,0,r3							; Ld from addr of arg and reserve

			andi.	r6,r5,ILK_LOCKED				; TEST...
			ori		r5,r5,ILK_LOCKED
			bne--	.L_lock_try_failedX				; branch if taken. Predict free 
	
			stwcx.	r5,0,r3							; And SET (if still reserved)
			bne--	.L_lock_try_loop				; If set failed, loop back 
			
			isync

			mfsprg	r6,1							; Get current activation 
			lwz		r5,ACT_PREEMPT_CNT(r6)			; Get the preemption level
			addi	r5,r5,1							; Bring up the disable count 
			stw		r5,ACT_PREEMPT_CNT(r6)			; Save it back

 			mtmsr	r9								; Allow interruptions now 
			li		r3,1							; Set that the lock was free 
			blr

.L_lock_try_failedX:
 			li		r6,lgKillResv					; Killing field
 			stwcx.	r6,0,r6							; Kill reservation
 			
.L_lock_try_failed:
 			mtmsr	r9								; Allow interruptions now 
			li		r3,0							; FAILURE - lock was taken 
			blr

/*
 *		unsigned int hw_lock_held(hw_lock_t)
 *
 *			Return 1 if lock is held
 *			Doesn't change preemption state.
 *			N.B.  Racy, of course.
 */
			.align	5
			.globl	EXT(hw_lock_held)

LEXT(hw_lock_held)

			isync									; Make sure we don't use a speculativily fetched lock 
			lwz		r3, 0(r3)						; Get lock value 
			andi.	r6,r3,ILK_LOCKED				; Extract the ILK_LOCKED bit
			blr

/*
 *		uint32_t hw_compare_and_store(uint32_t oldval, uint32_t newval, uint32_t *dest)
 *
 *			Compare old to area if equal, store new, and return true
 *			else return false and no store
 *			This is an atomic operation
 */
			.align	5
			.globl	EXT(hw_compare_and_store)

LEXT(hw_compare_and_store)

			mr		r6,r3							; Save the old value

cstry:		lwarx	r9,0,r5							; Grab the area value
			li		r3,1							; Assume it works
			cmplw	cr0,r9,r6						; Does it match the old value?
			bne--	csfail							; No, it must have changed...
			stwcx.	r4,0,r5							; Try to save the new value
			bne--	cstry							; Didn't get it, try again...
			isync									; Just hold up prefetch
			blr										; Return...
			
csfail:		li		r3,lgKillResv					; Killing field
			stwcx.	r3,0,r3							; Blow reservation
			
			li		r3,0							; Set failure
			blr										; Better luck next time...


/*
 *		uint32_t hw_atomic_add(uint32_t *dest, uint32_t delt)
 *
 *			Atomically add the second parameter to the first.
 *			Returns the result.
 *
 */
			.align	5
			.globl	EXT(hw_atomic_add)

LEXT(hw_atomic_add)

			mr		r6,r3							; Save the area

addtry:		lwarx	r3,0,r6							; Grab the area value
			add		r3,r3,r4						; Add the value
			stwcx.	r3,0,r6							; Try to save the new value
			bne--	addtry							; Didn't get it, try again...
			blr										; Return...


/*
 *		uint32_t hw_atomic_sub(uint32_t *dest, uint32_t delt)
 *
 *			Atomically subtract the second parameter from the first.
 *			Returns the result.
 *
 */
			.align	5
			.globl	EXT(hw_atomic_sub)

LEXT(hw_atomic_sub)

			mr		r6,r3							; Save the area

subtry:		lwarx	r3,0,r6							; Grab the area value
			sub		r3,r3,r4						; Subtract the value
			stwcx.	r3,0,r6							; Try to save the new value
			bne--	subtry							; Didn't get it, try again...
			blr										; Return...


/*
 *		uint32_t hw_atomic_or(uint32_t *dest, uint32_t mask)
 *
 *			Atomically ORs the second parameter into the first.
 *			Returns the result.
 */
			.align	5
			.globl	EXT(hw_atomic_or)

LEXT(hw_atomic_or)

			mr		r6,r3							; Save the area 		

ortry:		lwarx	r3,0,r6							; Grab the area value
			or		r3,r3,r4						; OR the value 
			stwcx.	r3,0,r6							; Try to save the new value
			bne--	ortry							; Did not get it, try again...
			blr										; Return...


/*
 *		uint32_t hw_atomic_and(uint32_t *dest, uint32_t mask)
 *
 *			Atomically ANDs the second parameter with the first.
 *			Returns the result.
 *
 */
			.align	5
			.globl	EXT(hw_atomic_and)

LEXT(hw_atomic_and)

			mr		r6,r3							; Save the area 		

andtry:		lwarx	r3,0,r6							; Grab the area value
			and		r3,r3,r4						; AND the value 
			stwcx.	r3,0,r6							; Try to save the new value
			bne--	andtry							; Did not get it, try again...
			blr										; Return...


/*
 *		void hw_queue_atomic(unsigned int * anchor, unsigned int * elem, unsigned int disp)
 *
 *			Atomically inserts the element at the head of the list
 *			anchor is the pointer to the first element
 *			element is the pointer to the element to insert
 *			disp is the displacement into the element to the chain pointer
 *
 */
			.align	5
			.globl	EXT(hw_queue_atomic)

LEXT(hw_queue_atomic)

			mr		r7,r4							; Make end point the same as start
			mr		r8,r5							; Copy the displacement also
			b		hw_queue_comm					; Join common code...

/*
 *		void hw_queue_atomic_list(unsigned int * anchor, unsigned int * first, unsigned int * last, unsigned int disp)
 *
 *			Atomically inserts the list of elements at the head of the list
 *			anchor is the pointer to the first element
 *			first is the pointer to the first element to insert
 *			last is the pointer to the last element to insert
 *			disp is the displacement into the element to the chain pointer
 */
			.align	5
			.globl	EXT(hw_queue_atomic_list)

LEXT(hw_queue_atomic_list)

			mr		r7,r5							; Make end point the same as start
			mr		r8,r6							; Copy the displacement also

hw_queue_comm:
			lwarx	r9,0,r3							; Pick up the anchor
			stwx	r9,r8,r7						; Chain that to the end of the new stuff
			eieio									; Make sure this store makes it before the anchor update
			stwcx.	r4,0,r3							; Try to chain into the front
			bne--	hw_queue_comm					; Didn't make it, try again...

			blr										; Return...

/*
 *		unsigned int *hw_dequeue_atomic(unsigned int *anchor, unsigned int disp)
 *
 *			Atomically removes the first element in a list and returns it.
 *			anchor is the pointer to the first element
 *			disp is the displacement into the element to the chain pointer
 *			Returns element if found, 0 if empty.
 */
			.align	5
			.globl	EXT(hw_dequeue_atomic)

LEXT(hw_dequeue_atomic)

			mr		r5,r3							; Save the anchor

hw_dequeue_comm:
			lwarx	r3,0,r5							; Pick up the anchor
			mr.		r3,r3							; Is the list empty?
			beq--	hdcFail							; Leave it list empty...
			lwzx	r9,r4,r3						; Get the next in line
			stwcx.	r9,0,r5							; Try to chain into the front
			beqlr++									; Got the thing, go away with it...
			b		hw_dequeue_comm					; Did not make it, try again...

hdcFail:	li		r4,lgKillResv					; Killing field
			stwcx.	r4,0,r4							; Dump reservation
			blr										; Leave...


/*
 *		void mutex_init(mutex_t* l, etap_event_t etap)
 *
 */
			.align	5
			.globl	EXT(mutex_init)

LEXT(mutex_init)

			PROLOG(0)
			li	r10,	0
			stw	r10,	LOCK_DATA(r3)				; clear lock word
			sth	r10,	MUTEX_WAITERS(r3)			; init waiter count
			sth	r10,	MUTEX_PROMOTED_PRI(r3)
#if	MACH_LDEBUG
			stw	r10,	MUTEX_PC(r3)				; init caller pc
			stw	r10,	MUTEX_THREAD(r3)			; and owning thread
			li	r10,	MUTEX_TAG
			stw	r10,	MUTEX_TYPE(r3)				; set lock type
#endif	/* MACH_LDEBUG */
			EPILOG
			blr

/*
 *		void mutex_lock(mutex_t*)
 *
 */
			.align	5
			.globl	EXT(mutex_lock)
LEXT(mutex_lock)

			.globl	EXT(_mutex_lock)
LEXT(_mutex_lock)

#if	!MACH_LDEBUG
			mfsprg	r6,1							; load the current thread
			lwz		r5,0(r3)						; Get the lock quickly
			mr.		r5,r5							; Quick check
			bne--	L_mutex_lock_slow				; Can not get it right now...

L_mutex_lock_loop:
			lwarx	r5,0,r3							; load the mutex lock
			mr.		r5,r5
			bne--	L_mutex_lock_slowX				; go to the slow path
			stwcx.	r6,0,r3							; grab the lock
			bne--	L_mutex_lock_loop				; loop back if failed
			isync									; stop prefeteching
			blr

L_mutex_lock_slowX:
			li		r5,lgKillResv					; Killing field
			stwcx.	r5,0,r5							; Kill reservation

L_mutex_lock_slow:
#endif
#if CHECKNMI
			mflr	r12								; (TEST/DEBUG) 
			bl		EXT(ml_sense_nmi)				; (TEST/DEBUG)
			mtlr	r12								; (TEST/DEBUG)
#endif

			PROLOG(12)
#if	MACH_LDEBUG
			bl		EXT(assert_wait_possible)
			mr.		r3,r3
			bne		L_mutex_lock_assert_wait_1
			lis		r3,hi16(L_mutex_lock_assert_wait_panic_str)
			ori		r3,r3,lo16(L_mutex_lock_assert_wait_panic_str)
			bl		EXT(panic)

			.data
L_mutex_lock_assert_wait_panic_str:
			STRINGD "mutex_lock: assert_wait_possible false\n\000" 
			.text

L_mutex_lock_assert_wait_1:
			lwz		r3,FM_ARG0(r1)
#endif
			CHECK_SETUP(r12)	
			CHECK_MUTEX_TYPE()
			CHECK_NO_SIMPLELOCKS()
.L_ml_retry:
			bl		lockDisa						; Go get a lock on the mutex's interlock lock
			mr.		r4,r3							; Did we get it?
			lwz		r3,FM_ARG0(r1)					; Restore the lock address
			bne+	mlGotInt						; We got it just fine...

			lis		r3,hi16(mutex_failed1)			; Get the failed mutex message
			ori		r3,r3,lo16(mutex_failed1)		; Get the failed mutex message
			bl		EXT(panic)						; Call panic
			BREAKPOINT_TRAP							; We die here anyway, can not get the lock
	
			.data
mutex_failed1:
			STRINGD	"We can't get a mutex interlock lock on mutex_lock\n\000"
			.text
			
mlGotInt:
			
;			Note that there is no reason to do a load and reserve here.  We already
;			hold the interlock lock and no one can touch this field unless they 
;			have that, so, we're free to play

			lwz		r4,LOCK_DATA(r3)				; Get the mutex's lock field
			rlwinm.	r9,r4,30,2,31					; So, can we have it?
			bne-	mlInUse							; Nope, sombody's playing already...

#if	MACH_LDEBUG
			li		r5,lo16(MASK(MSR_EE))			; Get the EE bit
			mfmsr	r11								; Note: no need to deal with fp or vec here
			andc	r5,r11,r5
			mtmsr	r5
			mfsprg	r9,0							; Get the per_proc block
			lwz		r5,0(r1)						; Get previous save frame
			lwz		r5,FM_LR_SAVE(r5)				; Get our caller's address
			lwz		r8,	PP_ACTIVE_THREAD(r9)		; Get the active thread
			stw		r5,MUTEX_PC(r3)					; Save our caller
			mr.		r8,r8							; Is there any thread?
			stw		r8,MUTEX_THREAD(r3)				; Set the mutex's holding thread
			beq-	.L_ml_no_active_thread			; No owning thread...
			lwz		r9,THREAD_MUTEX_COUNT(r8)		; Get the mutex count 
			addi	r9,r9,1							; Bump it up 
			stw		r9,THREAD_MUTEX_COUNT(r8)		; Stash it back 
.L_ml_no_active_thread:
			mtmsr	r11
#endif	/* MACH_LDEBUG */

			bl	EXT(mutex_lock_acquire)
			mfsprg	r5,1
			mr.		r4,r3
			lwz		r3,FM_ARG0(r1)
			beq		mlUnlock
			ori		r5,r5,WAIT_FLAG

mlUnlock:	eieio	
			stw	r5,LOCK_DATA(r3)					; grab the mutexlock and free the interlock

			EPILOG									; Restore all saved registers
			b		epStart							; Go enable preemption...

;			We come to here when we have a resource conflict.  In other words,
;			the mutex is held.

mlInUse:

			CHECK_SETUP(r12)	
			CHECK_MYLOCK(MUTEX_THREAD)				; Assert we don't own the lock already */

;			Note that we come in here with the interlock set.  The wait routine
;			will unlock it before waiting.

			ori		r4,r4,WAIT_FLAG					; Set the wait flag
			stw		r4,LOCK_DATA(r3)
			rlwinm	r4,r4,0,0,29					; Extract the lock owner
			bl		EXT(mutex_lock_wait)			; Wait for our turn at the lock
			
			lwz		r3,FM_ARG0(r1)					; restore r3 (saved in prolog)
			b		.L_ml_retry						; and try again...

	
/*
 *		void _mutex_try(mutex_t*)
 *
 */
			.align	5
			.globl	EXT(mutex_try)
LEXT(mutex_try)
			.globl	EXT(_mutex_try)
LEXT(_mutex_try)
#if	!MACH_LDEBUG
			mfsprg	r6,1							; load the current thread
			lwz		r5,0(r3)						; Get the lock value
			mr.		r5,r5							; Quick check
			bne--	L_mutex_try_slow				; Can not get it now...

L_mutex_try_loop:
			lwarx	r5,0,r3							; load the lock value
			mr.		r5,r5
			bne--	L_mutex_try_slowX				; branch to the slow path
			stwcx.	r6,0,r3							; grab the lock
			bne--	L_mutex_try_loop				; retry if failed
			isync									; stop prefetching
			li		r3, 1
			blr

L_mutex_try_slowX:
			li		r5,lgKillResv					; Killing field
			stwcx.	r5,0,r5							; Kill reservation

L_mutex_try_slow:

#endif

			PROLOG(8)								; reserve space for SWT_HI and SWT_LO
	
			CHECK_SETUP(r12)	
			CHECK_MUTEX_TYPE()
			CHECK_NO_SIMPLELOCKS()
			
			lwz		r6,LOCK_DATA(r3)				; Quick check
			rlwinm.	r6,r6,30,2,31					; to see if someone has this lock already
			bne-	mtFail							; Someone's got it already...

			bl		lockDisa						; Go get a lock on the mutex's interlock lock
			mr.		r4,r3							; Did we get it? */
			lwz		r3,FM_ARG0(r1)					; Restore the lock address
			bne+	mtGotInt						; We got it just fine...

			lis		r3,hi16(mutex_failed2)			; Get the failed mutex message
			ori		r3,r3,lo16(mutex_failed2)		; Get the failed mutex message
			bl		EXT(panic)						; Call panic
			BREAKPOINT_TRAP							; We die here anyway, can not get the lock
	
			.data
mutex_failed2:
			STRINGD	"We can't get a mutex interlock lock on mutex_try\n\000"
			.text
			
mtGotInt:
			
;			Note that there is no reason to do a load and reserve here.  We already
;			hold the interlock and no one can touch at this field unless they 
;			have that, so, we're free to play 
			
			lwz		r4,LOCK_DATA(r3)				; Get the mutex's lock field
			rlwinm.	r9,r4,30,2,31					; So, can we have it?
			bne-	mtInUse							; Nope, sombody's playing already...
			
#if	MACH_LDEBUG
			lis		r9,hi16(MASK(MSR_VEC))			; Get vector enable
			mfmsr	r11								; Get the MSR value
			ori		r9,r9,lo16(MASK(MSR_FP))		; Get FP enable
			ori		r5,r9,lo16(MASK(MSR_EE))		; Get EE bit on too
			andc	r11,r11,r9						; Clear FP and VEC
			andc	r5,r11,r5						; Clear EE as well

			mtmsr	r5
			mfsprg	r9,0							; Get the per_proc block
			lwz		r5,0(r1)						; Get previous save frame
			lwz		r5,FM_LR_SAVE(r5)				; Get our caller's address
			lwz		r8,	PP_ACTIVE_THREAD(r9)		; Get the active thread
			stw		r5,MUTEX_PC(r3)					; Save our caller
			mr.		r8,r8							; Is there any thread?
			stw		r8,MUTEX_THREAD(r3)				; Set the mutex's holding thread
			beq-	.L_mt_no_active_thread			; No owning thread...
			lwz		r9,	THREAD_MUTEX_COUNT(r8)		; Get the mutex count
			addi	r9,	r9,	1						; Bump it up 
			stw		r9,	THREAD_MUTEX_COUNT(r8)		; Stash it back 
.L_mt_no_active_thread:
			mtmsr	r11
#endif	/* MACH_LDEBUG */

			bl	EXT(mutex_lock_acquire)
			mfsprg	r5,1
			mr.		r4,r3
			lwz		r3,FM_ARG0(r1)
			beq		mtUnlock
			ori		r5,r5,WAIT_FLAG

mtUnlock:	eieio
			stw	r5,LOCK_DATA(r3)					; grab the mutexlock and free the interlock

			bl		epStart							; Go enable preemption...

			li		r3, 1
			EPILOG									; Restore all saved registers
			blr										; Return...

;			We come to here when we have a resource conflict.  In other words,
;			the mutex is held.

mtInUse:	
			rlwinm	r4,r4,0,0,30					; Get the unlock value
			stw		r4,LOCK_DATA(r3)				; free the interlock
			bl		epStart							; Go enable preemption...

mtFail:		li		r3,0							; Set failure code
			EPILOG									; Restore all saved registers
			blr										; Return...

		
/*
 *		void mutex_unlock_rwcmb(mutex_t* l)
 *
 */
			.align	5
			.globl	EXT(mutex_unlock_rwcmb)

LEXT(mutex_unlock_rwcmb)
			.globl	EXT(mulckPatch_isync)
LEXT(mulckPatch_isync)
			isync
			.globl	EXT(mulckPatch_eieio)     
LEXT(mulckPatch_eieio)
			eieio

			lwz		r5,0(r3)						; Get the lock
			rlwinm.	r4,r5,0,30,31					; Quick check
			bne--	L_mutex_unlock_slow				; Can not get it now...

L_mutex_unlock_rwcmb_loop:
			lwarx	r5,0,r3
			rlwinm.	r4,r5,0,30,31					; Bail if pending waiter or interlock set
			li		r5,0							; Clear the mutexlock
			bne--	L_mutex_unlock_rwcmb_slowX
			stwcx.	r5,0,r3
			bne--	L_mutex_unlock_rwcmb_loop
			blr

L_mutex_unlock_rwcmb_slowX:
			li		r5,lgKillResv					; Killing field
			stwcx.	r5,0,r5							; Dump reservation
			b		L_mutex_unlock_slow				; Join slow path...

/*
 *		void mutex_unlock(mutex_t* l)
 *
 */
			.align	5
			.globl	EXT(mutex_unlock)

LEXT(mutex_unlock)
#if	!MACH_LDEBUG
			sync
			lwz		r5,0(r3)						; Get the lock
			rlwinm.	r4,r5,0,30,31					; Quick check
			bne--	L_mutex_unlock_slow				; Can not get it now...

L_mutex_unlock_loop:
			lwarx	r5,0,r3
			rlwinm.	r4,r5,0,30,31					; Bail if pending waiter or interlock set
			li		r5,0							; Clear the mutexlock
			bne--	L_mutex_unlock_slowX
			stwcx.	r5,0,r3
			bne--	L_mutex_unlock_loop
			blr
L_mutex_unlock_slowX:
			li		r5,lgKillResv					; Killing field
			stwcx.	r5,0,r5							; Dump reservation

#endif

L_mutex_unlock_slow:
			
			PROLOG(0)
	
			CHECK_SETUP(r12)	
			CHECK_MUTEX_TYPE()
			CHECK_THREAD(MUTEX_THREAD)

			bl		lockDisa						; Go get a lock on the mutex's interlock lock
			mr.		r4,r3							; Did we get it?
			lwz		r3,FM_ARG0(r1)					; Restore the lock address
			bne+	muGotInt						; We got it just fine...

			lis		r3,hi16(mutex_failed3)			; Get the failed mutex message
			ori		r3,r3,lo16(mutex_failed3)		; Get the failed mutex message
			bl		EXT(panic)						; Call panic
			BREAKPOINT_TRAP							; We die here anyway, can not get the lock
	
			.data
mutex_failed3:
			STRINGD	"We can't get a mutex interlock lock on mutex_unlock\n\000"
			.text
			
			
muGotInt:
			lwz		r4,LOCK_DATA(r3)
			andi.	r5,r4,WAIT_FLAG					; are there any waiters ?
			rlwinm	r4,r4,0,0,29
			beq+	muUnlock						; Nope, we're done...

			bl		EXT(mutex_unlock_wakeup)		; yes, wake a thread
			lwz		r3,FM_ARG0(r1)					; restore r3 (saved in prolog)
			lwz		r5,LOCK_DATA(r3)				; load the lock

muUnlock:
#if	MACH_LDEBUG
			lis		r8,hi16(MASK(MSR_VEC))			; Get vector enable
			mfmsr	r11								; Get the MSR value
			ori		r8,r8,lo16(MASK(MSR_FP))		; Get FP enable
			ori		r9,r8,lo16(MASK(MSR_EE))		; Get EE bit on too
			andc	r11,r11,r8						; Clear FP and VEC
			andc	r9,r11,r9						; Clear EE as well

			mtmsr	r9
			mfsprg	r9,0					
			lwz		r9,PP_ACTIVE_THREAD(r9)
			stw		r9,MUTEX_THREAD(r3)				; disown thread
			cmpwi	r9,0
			beq-	.L_mu_no_active_thread
			lwz		r8,THREAD_MUTEX_COUNT(r9)
			subi	r8,r8,1
			stw		r8,THREAD_MUTEX_COUNT(r9)
.L_mu_no_active_thread:
			mtmsr	r11
#endif	/* MACH_LDEBUG */

			andi.	r5,r5,WAIT_FLAG					; Get the unlock value
			eieio
			stw		r5,LOCK_DATA(r3)				; unlock the interlock and lock

			EPILOG									; Deal with the stack now, enable_preemption doesn't always want one
			b		epStart							; Go enable preemption...

/*
 *		void interlock_unlock(hw_lock_t lock)
 */
			.align	5
			.globl	EXT(interlock_unlock)

LEXT(interlock_unlock)

			lwz		r10,LOCK_DATA(r3)
			rlwinm	r10,r10,0,0,30
			eieio
			stw		r10,LOCK_DATA(r3)

			b		epStart							; Go enable preemption...

/*		
 *		void _enable_preemption_no_check(void)
 *
 *			This version does not check if we get preempted or not
 */
			.align	4
			.globl	EXT(_enable_preemption_no_check)

LEXT(_enable_preemption_no_check)

			cmplw	cr1,r1,r1						; Force zero cr so we know not to check if preempted
			b		epCommn							; Join up with the other enable code... 

/*		
 *		void _enable_preemption(void)
 *
 *			This version checks if we get preempted or not
 */
			.align	5
			.globl	EXT(_enable_preemption)

LEXT(_enable_preemption)

;		Here is where we enable preemption.  We need to be protected
;		against ourselves, we can't chance getting interrupted and modifying
;		our processor wide preemption count after we'sve loaded it up. So,
;		we need to disable all 'rupts.  Actually, we could use a compare
;		and swap to do this, but, since there are no MP considerations
;		(we are dealing with a CPU local field) it is much, much faster
;		to disable.
;
;		Note that if we are not genned MP, the calls here will be no-opped via
;		a #define and since the _mp forms are the same, likewise a #define
;		will be used to route to the other forms

epStart:
			cmplwi	cr1,r1,0						; Force non-zero cr so we know to check if preempted

epCommn:
			mfsprg	r3,1							; Get current activation
			li		r8,-1							; Get a decrementer
			lwz		r5,ACT_PREEMPT_CNT(r3)			; Get the preemption level
			add.	r5,r5,r8						; Bring down the disable count
			blt-	epTooFar						; Yeah, we did...
			stw		r5,ACT_PREEMPT_CNT(r3)			; Save it back
			crandc	cr0_eq,cr0_eq,cr1_eq
			beq+	epCheckPreempt					; Go check if we need to be preempted...
			blr										; Leave...
epTooFar:	
			mr		r4,r5
			lis		r3,hi16(epTooFarStr)			; First half of panic string
			ori		r3,r3,lo16(epTooFarStr)			; Second half of panic string
			bl		EXT(panic)

			.data
epTooFarStr:
			STRINGD	"_enable_preemption: preemption_level %d\n\000"

			.text
			.align	5
epCheckPreempt:
			lis		r0,hi16(MASK(MSR_VEC))			; Get vector enable
			mfmsr	r9								; Get the MSR value
			ori		r0,r0,lo16(MASK(MSR_FP))		; Get FP enable
			andi.	r3,r9,lo16(MASK(MSR_EE))		; We cannot preempt if interruptions are off
			beq+	epCPno							; No preemption here...
			ori		r7,r0,lo16(MASK(MSR_EE))		; Get EE bit on too
			andc	r9,r9,r0						; Clear FP and VEC
			andc	r7,r9,r7						; Clear EE as well
			mtmsr	r7								; Turn off interruptions 
			isync									; May have turned off vec and fp here 
			mfsprg	r3,0							; Get per_proc 
			lwz		r7,PP_NEED_AST(r3)				; Get the AST request address
			li		r5,AST_URGENT					; Get the requests we do honor
			lwz		r7,0(r7)						; Get the actual, real live, extra special AST word
			lis		r0,hi16(DoPreemptCall)			; Just in case, get the top of firmware call
			and.	r7,r7,r5						; Should we preempt?
			ori		r0,r0,lo16(DoPreemptCall)		; Merge in bottom part
			mtmsr	r9								; Allow interrupts if we can
epCPno:		
			beqlr+									; We probably will not preempt...
			sc										; Do the preemption
			blr										; Now, go away now...

/*
 *		void disable_preemption(void)
 *
 *			Here is where we disable preemption.  Since preemption is on a
 *			per processor basis (a thread runs on one CPU at a time) we don't
 *			need any cross-processor synchronization.  We do, however, need to
 *			be interrupt safe, so we don't preempt while in the process of
 *			disabling it.  We could use SPLs, but since we always want complete
 *			disablement, and this is platform specific code, we'll just kick the
 *			MSR. We'll save a couple of orders of magnitude over using SPLs.
 */
			.align	5
			.globl	EXT(_disable_preemption)

LEXT(_disable_preemption)

			mfsprg	r6,1							; Get the current activation
			lwz		r5,ACT_PREEMPT_CNT(r6)			; Get the preemption level
			addi	r5,r5,1							; Bring up the disable count
			stw		r5,ACT_PREEMPT_CNT(r6)			; Save it back 
			blr										; Return...

/*
 *		int get_preemption_level(void)
 *
 *			Return the current preemption level
 */
			.align	5
			.globl	EXT(get_preemption_level)

LEXT(get_preemption_level)
 
			mfsprg	r6,1							; Get current activation
			lwz		r3,ACT_PREEMPT_CNT(r6)			; Get the preemption level
			blr										; Return...

/*
 *		int get_simple_lock_count(void)
 *
 *			Return the simple lock count
 *
 */
			.align	5
			.globl	EXT(get_simple_lock_count)

LEXT(get_simple_lock_count)
 
#if	MACH_LDEBUG
			lis		r3,hi16(MASK(MSR_VEC))			; Get vector enable
			mfmsr	r9								; Get the MSR value
			ori		r3,r3,lo16(MASK(MSR_FP))		; Get FP enable
			ori		r8,r3,lo16(MASK(MSR_EE))		; Get EE bit on too
			andc	r9,r9,r3						; Clear FP and VEC
			andc	r8,r9,r8						; Clear EE as well
 			mtmsr	r8								; Interrupts off
			isync									; May have messed with vec/fp
			mfsprg	r6,0							; Get the per_proc
			lwz		r3,PP_SIMPLE_LOCK_CNT(r6)		; Get the simple lock count
			mtmsr	r9								; Restore interruptions to entry
#else
			li		r3,0							; simple lock count not updated
#endif
			blr										; Return...

/*
 *		void ppc_usimple_lock_init(simple_lock_t, etap_event_t)
 *
 *			Initialize a simple lock.
 */
			.align	5
			.globl	EXT(ppc_usimple_lock_init)

LEXT(ppc_usimple_lock_init)

			li	r0,	0								; set lock to free == 0 
			stw	r0,	0(r3)							; Initialize the lock 
			blr
	
/*
 *		void ppc_usimple_lock(simple_lock_t)
 *
 */
			.align	5
			.globl	EXT(ppc_usimple_lock)

LEXT(ppc_usimple_lock)

#if CHECKNMI
			mflr	r12								; (TEST/DEBUG) 
			bl		EXT(ml_sense_nmi)				; (TEST/DEBUG)
			mtlr	r12								; (TEST/DEBUG)
#endif

			mfsprg	r6,1							; Get the current activation 
			lwz		r5,ACT_PREEMPT_CNT(r6)			; Get the preemption level
			addi	r5,r5,1							; Bring up the disable count
			stw		r5,ACT_PREEMPT_CNT(r6)			; Save it back 
			mr		r5,r3							; Get the address of the lock
			li		r8,0							; Set r8 to zero
			li		r4,0							; Set r4 to zero

slcktry:	lwarx	r11,0,r5						; Grab the lock value
			andi.	r3,r11,ILK_LOCKED				; Is it locked?
			ori		r11,r6,ILK_LOCKED				; Set interlock 
			bne--	slckspin						; Yeah, wait for it to clear...
			stwcx.	r11,0,r5						; Try to seize that there durn lock
			bne--	slcktry							; Couldn't get it...
			isync									; Make sure we don't use a speculativily loaded value
			blr										; Go on home...

slckspin:	li		r11,lgKillResv					; Killing field
			stwcx.	r11,0,r11						; Kill reservation

			mr.		r4,r4							; Test timeout value
			bne++	slockspin0
			lis		r4,hi16(EXT(LockTimeOut))		; Get the high part 
			ori		r4,r4,lo16(EXT(LockTimeOut))	; And the low part
			lwz		r4,0(r4)						; Get the timerout value

slockspin0:	mr.		r8,r8							; Is r8 set to zero
			bne++	slockspin1						; If yes, first spin attempt
			lis		r0,hi16(MASK(MSR_VEC))			; Get vector enable
			mfmsr	r9								; Get the MSR value
			ori		r0,r0,lo16(MASK(MSR_FP))		; Get FP enable
			ori		r7,r0,lo16(MASK(MSR_EE))		; Get EE bit on too
			andc	r9,r9,r0						; Clear FP and VEC
			andc	r7,r9,r7						; Clear EE as well
			mtmsr	r7								; Turn off interruptions 
			isync									; May have turned off vec and fp here 
			mftb	r8								; Get timestamp on entry
			b		slcksniff

slockspin1:	mtmsr	r7								; Turn off interruptions 
			mftb	r8								; Get timestamp on entry

slcksniff:	lwz		r3,0(r5)						; Get that lock in here
			andi.	r3,r3,ILK_LOCKED				; Is it free yet?
			beq++	slckretry						; Yeah, try for it again...
			
			mftb	r10								; Time stamp us now
			sub		r10,r10,r8						; Get the elapsed time
			cmplwi	r10,128							; Have we been spinning for 128 tb ticks?
			blt++	slcksniff						; Not yet...
			
			mtmsr	r9								; Say, any interrupts pending?

;			The following instructions force the pipeline to be interlocked to that only one
;			instruction is issued per cycle.  The insures that we stay enabled for a long enough
;			time; if it's too short, pending interruptions will not have a chance to be taken

			subi	r4,r4,128						; Back off elapsed time from timeout value
			or		r4,r4,r4						; Do nothing here but force a single cycle delay
			mr.		r4,r4							; See if we used the whole timeout
			li		r3,0							; Assume a timeout return code
			or		r4,r4,r4						; Do nothing here but force a single cycle delay
			
			ble--	slckfail						; We failed
			b		slockspin1						; Now that we've opened an enable window, keep trying...
slckretry:
			mtmsr	r9								; Restore interrupt state
			li		r8,1							; Show already through once
			b		slcktry
slckfail:											; We couldn't get the lock
			lis		r3,hi16(slckpanic_str)
			ori		r3,r3,lo16(slckpanic_str)
			mr		r4,r5
			mflr	r5
			bl		EXT(panic)

		.data
slckpanic_str:
		STRINGD "ppc_usimple_lock: simple lock deadlock detection l=0x%08X, pc=0x%08X\n\000"
		.text

/*
 *		unsigned int ppc_usimple_lock_try(simple_lock_t)
 *
 */
			.align	5
			.globl	EXT(ppc_usimple_lock_try)

LEXT(ppc_usimple_lock_try)

#if CHECKNMI
			mflr	r12								; (TEST/DEBUG) 
			bl		EXT(ml_sense_nmi)				; (TEST/DEBUG)
			mtlr	r12								; (TEST/DEBUG)
#endif                  
			lis		r0,hi16(MASK(MSR_VEC))			; Get vector enable
			mfmsr	r9								; Get the MSR value 
			ori		r0,r0,lo16(MASK(MSR_FP))		; Get FP enable
			ori		r7,r0,lo16(MASK(MSR_EE))		; Get EE bit on too
			andc	r9,r9,r0						; Clear FP and VEC
			andc	r7,r9,r7						; Clear EE as well
			mtmsr	r7								; Disable interruptions and thus, preemption
			mfsprg	r6,1							; Get current activation 

			lwz		r11,0(r3)						; Get the lock
			andi.	r5,r11,ILK_LOCKED				; Check it...
			bne--	slcktryfail						; Quickly fail...

slcktryloop:	
			lwarx	r11,0,r3						; Ld from addr of arg and reserve

			andi.	r5,r11,ILK_LOCKED				; TEST...
			ori		r5,r6,ILK_LOCKED
			bne--	slcktryfailX					; branch if taken. Predict free 
	
			stwcx.	r5,0,r3							; And SET (if still reserved)
			bne--	slcktryloop						; If set failed, loop back 
			
			isync

			lwz		r5,ACT_PREEMPT_CNT(r6)			; Get the preemption level
			addi	r5,r5,1							; Bring up the disable count 
			stw		r5,ACT_PREEMPT_CNT(r6)			; Save it back

 			mtmsr	r9								; Allow interruptions now 
			li		r3,1							; Set that the lock was free 
			blr

slcktryfailX:
			li		r5,lgKillResv					; Killing field
			stwcx.	r5,0,r5							; Kill reservation

slcktryfail:
 			mtmsr	r9								; Allow interruptions now 
			li		r3,0							; FAILURE - lock was taken 
			blr


/*
 *		void ppc_usimple_unlock_rwcmb(simple_lock_t)
 *
 */
			.align	5
			.globl	EXT(ppc_usimple_unlock_rwcmb)

LEXT(ppc_usimple_unlock_rwcmb)

#if CHECKNMI
			mflr	r12								; (TEST/DEBUG) 
			bl		EXT(ml_sense_nmi)				; (TEST/DEBUG)
			mtlr	r12								; (TEST/DEBUG)
#endif                  
			li		r0,0
			.globl  EXT(sulckPatch_isync)
LEXT(sulckPatch_isync)
			isync
			.globl  EXT(sulckPatch_eieio)
LEXT(sulckPatch_eieio)
			eieio
			stw		r0, LOCK_DATA(r3)

			b		epStart							; Go enable preemption...

/*
 *		void ppc_usimple_unlock_rwmb(simple_lock_t)
 *
 */
			.align	5
			.globl	EXT(ppc_usimple_unlock_rwmb)

LEXT(ppc_usimple_unlock_rwmb)

#if CHECKNMI
			mflr	r12								; (TEST/DEBUG) 
			bl		EXT(ml_sense_nmi)				; (TEST/DEBUG)
			mtlr	r12								; (TEST/DEBUG)
#endif                  
			li		r0,0
			sync
			stw		r0, LOCK_DATA(r3)

			b		epStart							; Go enable preemption...

/*
 *		void enter_funnel_section(funnel_t *)
 *
 */
			.align	5
			.globl	EXT(enter_funnel_section)

LEXT(enter_funnel_section)

#if	!MACH_LDEBUG
			lis		r10,hi16(EXT(kdebug_enable))
			ori		r10,r10,lo16(EXT(kdebug_enable))
			lwz		r10,0(r10)
			lis		r11,hi16(EXT(split_funnel_off))
			ori		r11,r11,lo16(EXT(split_funnel_off))
			lwz		r11,0(r11)
			or.		r10,r11,r10						; Check kdebug_enable or split_funnel_off
			bne-	L_enter_funnel_section_slow		; If set, call the slow path
			mfsprg	r6,1							; Get the current activation
			lwz		r7,LOCK_FNL_MUTEX(r3)

			lwz		r5,0(r7)						; Get lock quickly
			mr.		r5,r5							; Locked?
			bne--	L_enter_funnel_section_slow		; Yup...

L_enter_funnel_section_loop:
			lwarx	r5,0,r7							; Load the mutex lock
			mr.		r5,r5
			bne--	L_enter_funnel_section_slowX	; Go to the slow path
			stwcx.	r6,0,r7							; Grab the lock
			bne--	L_enter_funnel_section_loop		; Loop back if failed
			isync									; Stop prefeteching
			lwz		r6,ACT_THREAD(r6)				; Get the current thread
			li		r7,TH_FN_OWNED
			stw		r3,THREAD_FUNNEL_LOCK(r6)		; Set the funnel lock reference
			stw		r7,THREAD_FUNNEL_STATE(r6)		; Set the funnel state
			blr

L_enter_funnel_section_slowX:
			li		r4,lgKillResv					; Killing field
			stwcx.	r4,0,r4							; Kill reservation

L_enter_funnel_section_slow:
#endif
			li		r4,TRUE
			b		EXT(thread_funnel_set)

/*
 *		void exit_funnel_section(void)
 *
 */
			.align	5
			.globl	EXT(exit_funnel_section)

LEXT(exit_funnel_section)

			mfsprg	r6,1							; Get the current activation
			lwz		r6,ACT_THREAD(r6)				; Get the current thread
			lwz		r3,THREAD_FUNNEL_LOCK(r6)		; Get the funnel lock
			mr.		r3,r3							; Check on funnel held
			beq-	L_exit_funnel_section_ret		; 
#if	!MACH_LDEBUG
			lis		r10,hi16(EXT(kdebug_enable))
			ori		r10,r10,lo16(EXT(kdebug_enable))
			lwz		r10,0(r10)
			mr.		r10,r10
			bne-	L_exit_funnel_section_slow		; If set, call the slow path
			lwz		r7,LOCK_FNL_MUTEX(r3)			; Get the funnel mutex lock
			.globl	EXT(retfsectPatch_isync)     
LEXT(retfsectPatch_isync)
			isync
			.globl	EXT(retfsectPatch_eieio)     
LEXT(retfsectPatch_eieio)
			eieio

			lwz		r5,0(r7)						; Get lock
			rlwinm.	r4,r5,0,30,31					; Quick check for bail if pending waiter or interlock set 
			bne--	L_exit_funnel_section_slow		; No can get...

L_exit_funnel_section_loop:
			lwarx	r5,0,r7
			rlwinm.	r4,r5,0,30,31					; Bail if pending waiter or interlock set 
			li		r5,0							; Clear the mutexlock 
			bne--	L_exit_funnel_section_slowX
			stwcx.	r5,0,r7							; Release the funnel mutexlock
			bne--	L_exit_funnel_section_loop
			li		r7,0
			stw		r7,THREAD_FUNNEL_STATE(r6)		; Clear the funnel state
			stw		r7,THREAD_FUNNEL_LOCK(r6)		; Clear the funnel lock reference
			blr										; Return

L_exit_funnel_section_slowX:
			li		r4,lgKillResv					; Killing field
			stwcx.	r4,0,r4							; Kill it

L_exit_funnel_section_slow:
#endif
			li		r4,FALSE
			b		EXT(thread_funnel_set)
L_exit_funnel_section_ret:
			blr

;
;                     This is bring up code
;
			.align  5
			.globl  EXT(condStop)

LEXT(condStop)

XcondStop:	cmplw	r3,r4							; Check if these are equal
			beq--	XcondStop						; Stop here until they are different
			blr										; Return.


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

#include <kern/etap_options.h>
	
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <assym.s>

#define	STRING	ascii

#define	SWT_HI	0+FM_SIZE
#define SWT_LO	4+FM_SIZE
#define MISSED	8+FM_SIZE

#define	ILK_LOCKED		0x01
#define	WAIT_FLAG		0x02
#define	SLOCK_FAST		0x02
#define TH_FN_OWNED		0x01

;
;		NOTE: make sure that PREEMPTSTACK in aligned_data is
;		set the same as it is here.  This is the number of
;		traceback entries we can handle per processor
;
;		A value of 0 disables the stack.
;
#define PREEMPTSTACK 0
#define CHECKNMI 0
#define CHECKLOCKS 1

#include <ppc/POWERMAC/mp/mp.h>

#define PROLOG(space)							  \
			stwu	r1,-(FM_ALIGN(space)+FM_SIZE)(r1)	__ASMNL__ \
			mflr	r0							__ASMNL__ \
			stw		r3,FM_ARG0(r1)				__ASMNL__ \
			stw		r0,(FM_ALIGN(space)+FM_SIZE+FM_LR_SAVE)(r1)	__ASMNL__
	
#define EPILOG									  \
			lwz		r1,0(r1)					__ASMNL__ \
			lwz		r0,FM_LR_SAVE(r1)			__ASMNL__ \
			mtlr	r0							__ASMNL__					

#if	MACH_LDEBUG && CHECKLOCKS
/*
 * Routines for general lock debugging.
 */

/* Gets lock check flags in CR6: CR bits 24-27 */

#define CHECK_SETUP(rg)									\
			lis		rg,hi16(EXT(dgWork))	__ASMNL__ 	\
			ori		rg,rg,lo16(EXT(dgWork))	__ASMNL__ 	\
			lbz		rg,dgFlags(rg)			__ASMNL__ 	\
			mtcrf	2,rg					__ASMNL__ 


/*
 * Checks for expected lock types and calls "panic" on
 * mismatch.  Detects calls to Mutex functions with
 * type simplelock and vice versa.
 */
#define	CHECK_MUTEX_TYPE()							\
			bt		24+disLktypeb,1f			__ASMNL__ 	\
			lwz		r10,MUTEX_TYPE(r3)			__ASMNL__ 	\
			cmpwi	r10,MUTEX_TAG				__ASMNL__	\
			beq+	1f							__ASMNL__	\
			lis		r3,hi16(not_a_mutex)		__ASMNL__	\
			ori		r3,r3,lo16(not_a_mutex)		__ASMNL__	\
			bl		EXT(panic)					__ASMNL__	\
			lwz		r3,FM_ARG0(r1)				__ASMNL__	\
1:
	
	.data
not_a_mutex:
			STRINGD	"not a mutex!\n\000"
			.text

#define CHECK_SIMPLE_LOCK_TYPE()					\
			bt		24+disLktypeb,1f			__ASMNL__ 	\
			lwz		r10,SLOCK_TYPE(r3)			__ASMNL__ 	\
			cmpwi	r10,USLOCK_TAG				__ASMNL__ 	\
			beq+	1f							__ASMNL__ 	\
			lis		r3,hi16(not_a_slock)		__ASMNL__ 	\
			ori		r3,r3,lo16(not_a_slock) 	__ASMNL__ 	\
			bl		EXT(panic)					__ASMNL__ 	\
			lwz		r3,FM_ARG0(r1)				__ASMNL__ 	\
1:
	
	.data
not_a_slock:
			STRINGD	"not a simple lock!\n\000"
			.text

#define CHECK_NO_SIMPLELOCKS()							\
			bt		24+disLkNmSimpb,2f			__ASMNL__ 	\
			mfmsr	r11							__ASMNL__	\
			rlwinm	r11,r11,0,MSR_FP_BIT+1,MSR_FP_BIT-1	__ASMNL__	\
			rlwinm	r11,r11,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	__ASMNL__	\
			rlwinm  r10,r11,0,MSR_EE_BIT+1,MSR_EE_BIT-1	__ASMNL__	\
			mtmsr	r10							__ASMNL__	\
			isync								__ASMNL__	\
			mfsprg	r10,0						__ASMNL__	\
			lwz		r10,PP_SIMPLE_LOCK_CNT(r10) __ASMNL__	\
			cmpwi	r10,0 						__ASMNL__	\
			beq+	1f 							__ASMNL__	\
			lis		r3,hi16(simple_locks_held) __ASMNL__	\
			ori		r3,r3,lo16(simple_locks_held) __ASMNL__	\
			bl		EXT(panic)	 				__ASMNL__	\
			lwz		r3,FM_ARG0(r1)	 			__ASMNL__ 	\
1:												__ASMNL__	\
			mtmsr	r11							__ASMNL__	\
2:	
	
	.data
simple_locks_held:
			STRINGD	"simple locks held!\n\000"
			.text

/* 
 * Verifies return to the correct thread in "unlock" situations.
 */

#define CHECK_THREAD(thread_offset)						\
			bt		24+disLkThreadb,2f			__ASMNL__ 	\
			mfmsr	r11							__ASMNL__	\
			rlwinm	r11,r11,0,MSR_FP_BIT+1,MSR_FP_BIT-1	__ASMNL__	\
			rlwinm	r11,r11,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	__ASMNL__	\
			rlwinm  r10,r11,0,MSR_EE_BIT+1,MSR_EE_BIT-1	__ASMNL__	\
			mtmsr	r10							__ASMNL__	\
			isync								__ASMNL__	\
			mfsprg	r10,0						__ASMNL__	\
			lwz		r10,PP_ACTIVE_THREAD(r10)	__ASMNL__	\
			cmpwi	r10,0	 					__ASMNL__ 	\
			beq-	1f 							__ASMNL__ 	\
			lwz		r9,thread_offset(r3) 		__ASMNL__ 	\
			cmpw	r9,r10	 					__ASMNL__ 	\
			beq+	1f 							__ASMNL__ 	\
			lis		r3,hi16(wrong_thread) 		__ASMNL__	\
			ori		r3,r3,lo16(wrong_thread)	__ASMNL__ 	\
			bl		EXT(panic)	 				__ASMNL__ 	\
			lwz		r3,FM_ARG0(r1)	 			__ASMNL__ 	\
1:												__ASMNL__	\
			mtmsr	r11							__ASMNL__	\
2:	
	.data
wrong_thread:
	STRINGD	"wrong thread!\n\000"
	.text

#define CHECK_MYLOCK(thread_offset)					\
			bt		24+disLkMyLckb,2f			__ASMNL__ 	\
			mfmsr	r11							__ASMNL__	\
			rlwinm	r11,r11,0,MSR_FP_BIT+1,MSR_FP_BIT-1	__ASMNL__	\
			rlwinm	r11,r11,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	__ASMNL__	\
			rlwinm  r10,r11,0,MSR_EE_BIT+1,MSR_EE_BIT-1	__ASMNL__	\
			mtmsr	r10							__ASMNL__	\
			isync								__ASMNL__	\
			mfsprg	r10,0						__ASMNL__	\
			lwz		r10,PP_ACTIVE_THREAD(r10)	__ASMNL__	\
			cmpwi	r10,0	 					__ASMNL__	\
			beq-	1f 							__ASMNL__	\
			lwz		r9,	thread_offset(r3) 		__ASMNL__	\
			cmpw	r9,r10	 					__ASMNL__	\
			bne+	1f 							__ASMNL__	\
			lis		r3,	HIGH_ADDR(mylock_attempt) __ASMNL__	\
			ori		r3,r3,LOW_ADDR(mylock_attempt) __ASMNL__	\
			bl		EXT(panic)	 				__ASMNL__	\
			lwz		r3,FM_ARG0(r1)	 			__ASMNL__	\
1:												__ASMNL__	\
			mtmsr	r11							__ASMNL__	\
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
 *      void hw_lock_init(hw_lock_t)
 *
 *      Initialize a hardware lock.  These locks should be cache aligned and a multiple
 *		of cache size.
 */

ENTRY(hw_lock_init, TAG_NO_FRAME_USED)

			li	r0,	0							/* set lock to free == 0 */
			stw	r0,	0(r3)						/* Initialize the lock */
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

#if 0
			lis		r0,HIGH_ADDR(CutTrace)		/* (TEST/DEBUG) */
			lis		r5,0xFFFF					/* (TEST/DEBUG) */
			oris	r0,r0,LOW_ADDR(CutTrace)	/* (TEST/DEBUG) */
			sc									/* (TEST/DEBUG) */
#endif
			sync								/* Flush writes done under lock */
			li	r0,	0							/* set lock to free */
			stw	r0,	0(r3)

			b		epStart						/* Go enable preemption... */


/* 
 *		Special case for internal use.  Uses same lock code, but sets up so 
 *		that there will be no disabling of preemption after locking.  Generally
 *		used for mutex locks when obtaining the interlock although there is
 *		nothing stopping other uses.
 */

lockLock:	lis		r4,HIGH_ADDR(EXT(LockTimeOut))	/* Get the high part */
			ori		r4,r4,LOW_ADDR(EXT(LockTimeOut))	/* And the low part */
			cmplwi	cr1,r1,0					/* Set flag to disable disable preemption */
			lwz		r4,0(r4)					/* Get the timerout value */
			b		lockComm					/* Join on up... */
	
/*
 *      void hw_lock_lock(hw_lock_t)
 *
 *      Acquire lock, spinning until it becomes available.
 *      Return with preemption disabled.
 *		Apparently not used except by mach_perf.
 *		We will just set a default timeout and jump into the NORMAL timeout lock.
 */

			.align	5
			.globl	EXT(hw_lock_lock)

LEXT(hw_lock_lock)

lockDisa:	lis		r4,HIGH_ADDR(EXT(LockTimeOut))	/* Get the high part */
			ori		r4,r4,LOW_ADDR(EXT(LockTimeOut))	/* And the low part */
			cmplw	cr1,r1,r1					/* Set flag to enable disable preemption */
			lwz		r4,0(r4)					/* Get the timerout value */
			b		lockComm					/* Join on up... */

/*
 *      unsigned int hw_lock_to(hw_lock_t, unsigned int timeout)
 *
 *      Try to acquire spin-lock. Return success (1) or failure (0).
 *      Attempt will fail after timeout ticks of the timebase.
 *		We try fairly hard to get this lock.  We disable for interruptions, but
 *		reenable after a "short" timeout (128 ticks, we may want to change this).
 *		After checking to see if the large timeout value (passed in) has expired and a
 *		sufficient number of cycles have gone by (to insure pending 'rupts are taken),
 *		we return either in abject failure, or disable and go back to the lock sniff routine.
 *		If the sniffer finds the lock free, it jumps right up and tries to grab it.
 *
 *		One programming note: NEVER DO NOTHING IN HERE NO HOW THAT WILL FORCE US TO CALL
 *		THIS WITH TRANSLATION OR INTERRUPTIONS EITHER ON OR OFF, GOSH DARN IT!
 *
 */
			.align	5
			.globl	EXT(hw_lock_to)

LEXT(hw_lock_to)

#if 0
			lis		r0,HIGH_ADDR(CutTrace)		/* (TEST/DEBUG) */
			lis		r5,0xEEEE					/* (TEST/DEBUG) */
			oris	r0,r0,LOW_ADDR(CutTrace)	/* (TEST/DEBUG) */
			sc									/* (TEST/DEBUG) */
#endif

#if CHECKNMI
			mflr	r12							; (TEST/DEBUG) 
			bl		EXT(ml_sense_nmi)			; (TEST/DEBUG)
			mtlr	r12							; (TEST/DEBUG)
#endif

			cmplw	cr1,r1,r1					/* Set flag to enable disable preemption */

lockComm:	mfmsr	r9							/* Get the MSR value */
			rlwinm	r9,r9,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			mr		r5,r3						/* Get the address of the lock */
			rlwinm	r9,r9,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r7,r9,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Get MSR that is uninterruptible */
	
			mtmsr	r7							/* Turn off interruptions */
			isync								; May have turned off vec and fp here 
			mftb	r8							/* Get the low part of the time base */
			
lcktry:		lwarx	r6,0,r5						/* Grab the lock value */
			andi.	r3,r6,ILK_LOCKED			/* Is it locked? */
			ori		r6,r6,ILK_LOCKED			/* Set interlock */
			bne-	lcksniff					/* Yeah, wait for it to clear... */
			stwcx.	r6,0,r5						/* Try to seize that there durn lock */
			bne-	lcktry						/* Couldn't get it... */
			li		r3,1						/* return true */
			isync								/* Make sure we don't use a speculativily loaded value */
			beq+	cr1,daPreComm				/* We got it, go disable preemption if we're supposed to... */
			mtmsr	r9							; Restore interrupt state
			blr									/* Go on home... */
			
			.align	5

lcksniff:	lwz		r3,0(r5)					/* Get that lock in here */
			andi.	r3,r3,ILK_LOCKED			/* Is it free yet? */
			beq+	lcktry						/* Yeah, try for it again... */
			
			mftb	r10							/* Time stamp us now */
			sub		r10,r10,r8					/* Get the elapsed time */
			cmplwi	r10,128						/* Have we been spinning for 128 tb ticks? */
			blt+	lcksniff					/* Not yet... */
			
			mtmsr	r9							/* Say, any interrupts pending? */			

/*			The following instructions force the pipeline to be interlocked to that only one
			instruction is issued per cycle.  The insures that we stay enabled for a long enough
			time; if it's too short, pending interruptions will not have a chance to be taken */
			
			subi	r4,r4,128					/* Back off elapsed time from timeout value */
			or		r4,r4,r4					/* Do nothing here but force a single cycle delay */
			mr.		r4,r4						/* See if we used the whole timeout	*/
			li		r3,0						/* Assume a timeout return code */
			or		r4,r4,r4					/* Do nothing here but force a single cycle delay */
			
			ble-	lckfail						/* We failed */
			mtmsr	r7							/* Disable for interruptions */
			mftb	r8							/* Get the low part of the time base */
			b		lcksniff					/* Now that we've opened an enable window, keep trying... */

lckfail:										/* We couldn't get the lock */			
			li		r3,0						/* Set failure return code */
			blr									/* Return, head hanging low... */


/*
 *      unsigned int hw_lock_bit(hw_lock_t, unsigned int bit, unsigned int timeout)
 *
 *      Try to acquire spin-lock. The second parameter is the bit mask to test and set.
 *		multiple bits may be set. Return success (1) or failure (0).
 *      Attempt will fail after timeout ticks of the timebase.
 *		We try fairly hard to get this lock.  We disable for interruptions, but
 *		reenable after a "short" timeout (128 ticks, we may want to shorten this).
 *		After checking to see if the large timeout value (passed in) has expired and a
 *		sufficient number of cycles have gone by (to insure pending 'rupts are taken),
 *		we return either in abject failure, or disable and go back to the lock sniff routine.
 *		If the sniffer finds the lock free, it jumps right up and tries to grab it.
 *
 *		NOTE WELL!!!!  THE ROUTINE hw_lock_phys_vir KNOWS WHAT REGISTERS THIS GUY
 *		USES. THIS SAVES A TRANSLATION OFF TO ON TRANSITION AND BACK AND A SAVE AND
 *		RESTORE FROM THE STACK.
 *
 */

			.align	5
			
			nop									; Force loop alignment to cache line
			nop
			nop
			nop
			
			.globl	EXT(hw_lock_bit)

LEXT(hw_lock_bit)

			mfmsr	r9							/* Get the MSR value */
			rlwinm	r9,r9,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r9,r9,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r7,r9,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Get MSR that is uninterruptible */	

			mtmsr	r7							/* Turn off interruptions */
			isync								; May have turned off vec and fp here 

			mftb	r8							/* Get the low part of the time base */
			
bittry:		lwarx	r6,0,r3						/* Grab the lock value */
			and.	r0,r6,r4					/* See if any of the lock bits are on */
			or		r6,r6,r4					/* Turn on the lock bits */
			bne-	bitsniff					/* Yeah, wait for it to clear... */
			stwcx.	r6,0,r3						/* Try to seize that there durn lock */
			beq+	bitgot						/* We got it, yahoo... */
			b		bittry						/* Just start up again if the store failed... */

			.align	5
			
bitsniff:	lwz		r6,0(r3)					/* Get that lock in here */
			and.	r0,r6,r4					/* See if any of the lock bits are on */
			beq+	bittry						/* Yeah, try for it again... */
			
			mftb	r6							/* Time stamp us now */
			sub		r6,r6,r8					/* Get the elapsed time */
			cmplwi	r6,128						/* Have we been spinning for 128 tb ticks? */
			blt+	bitsniff					/* Not yet... */
			
			mtmsr	r9							/* Say, any interrupts pending? */			

/*			The following instructions force the pipeline to be interlocked to that only one
			instruction is issued per cycle.  The insures that we stay enabled for a long enough
			time. If it's too short, pending interruptions will not have a chance to be taken 
*/
			
			subi	r5,r5,128					/* Back off elapsed time from timeout value */
			or		r5,r5,r5					/* Do nothing here but force a single cycle delay */
			mr.		r5,r5						/* See if we used the whole timeout	*/
			or		r5,r5,r5					/* Do nothing here but force a single cycle delay */
			
			ble-	bitfail						/* We failed */
			mtmsr	r7							/* Disable for interruptions */
			mftb	r8							/* Get the low part of the time base */
			b		bitsniff					/* Now that we've opened an enable window, keep trying... */

			.align	5

bitgot:		mtmsr	r9							/* Enable for interruptions */
			li		r3,1						/* Set good return code */
			isync								/* Make sure we don't use a speculativily loaded value */
			blr

bitfail:	li		r3,0						/* Set failure return code */
			blr									/* Return, head hanging low... */
			

/*
 *      unsigned int hw_unlock_bit(hw_lock_t, unsigned int bit)
 *
 *      Release bit based spin-lock. The second parameter is the bit mask to clear.
 *		Multiple bits may be cleared.
 *
 *		NOTE WELL!!!!  THE ROUTINE hw_lock_phys_vir KNOWS WHAT REGISTERS THIS GUY
 *		USES. THIS SAVES A TRANSLATION OFF TO ON TRANSITION AND BACK AND A SAVE AND
 *		RESTORE FROM THE STACK.
 */

			.align	5
			.globl	EXT(hw_unlock_bit)

LEXT(hw_unlock_bit)

			sync

ubittry:	lwarx	r0,0,r3						/* Grab the lock value */
			andc	r0,r0,r4					/* Clear the lock bits */
			stwcx.	r0,0,r3						/* Try to clear that there durn lock */
			bne-	ubittry						/* Try again, couldn't save it... */

			blr									/* Leave... */			

/*
 *      unsigned int hw_lock_mbits(hw_lock_t, unsigned int bits, unsigned int value, 
 *			unsigned int newb, unsigned int timeout)
 *
 *      Try to acquire spin-lock. The second parameter is the bit mask to check.
 *		The third is the value of those bits and the 4th is what to set them to.
 *		Return success (1) or failure (0).
 *      Attempt will fail after timeout ticks of the timebase.
 *		We try fairly hard to get this lock.  We disable for interruptions, but
 *		reenable after a "short" timeout (128 ticks, we may want to shorten this).
 *		After checking to see if the large timeout value (passed in) has expired and a
 *		sufficient number of cycles have gone by (to insure pending 'rupts are taken),
 *		we return either in abject failure, or disable and go back to the lock sniff routine.
 *		If the sniffer finds the lock free, it jumps right up and tries to grab it.
 *
 */

			.align	5
			
			nop									; Force loop alignment to cache line
			nop
			nop
			nop
			
			.globl	EXT(hw_lock_mbits)

LEXT(hw_lock_mbits)

			mfmsr	r9							; Get the MSR value
			rlwinm	r9,r9,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r9,r9,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r8,r9,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; Get MSR that is uninterruptible	

			mtmsr	r8							; Turn off interruptions
			isync								; May have turned off vectors or float here
			mftb	r10							; Get the low part of the time base
			
mbittry:	lwarx	r12,0,r3					; Grab the lock value
			and		r0,r12,r4					; Clear extra bits
			andc	r12,r12,r4					; Clear all bits in the bit mask
			or		r12,r12,r6					; Turn on the lock bits
			cmplw	r0,r5						; Are these the right bits?
			bne-	mbitsniff					; Nope, wait for it to clear...
			stwcx.	r12,0,r3					; Try to seize that there durn lock
			beq+	mbitgot						; We got it, yahoo...
			b		mbittry						; Just start up again if the store failed...

			.align	5
			
mbitsniff:	lwz		r12,0(r3)					; Get that lock in here
			and		r0,r12,r4					; Clear extra bits
			cmplw	r0,r5						; Are these the right bits?
			beq+	mbittry						; Yeah, try for it again...
			
			mftb	r11							; Time stamp us now
			sub		r11,r11,r10					; Get the elapsed time
			cmplwi	r11,128						; Have we been spinning for 128 tb ticks?
			blt+	mbitsniff					; Not yet...
			
			mtmsr	r9							; Say, any interrupts pending?			

;			The following instructions force the pipeline to be interlocked to that only one
;			instruction is issued per cycle.  The insures that we stay enabled for a long enough
;			time. If it is too short, pending interruptions will not have a chance to be taken 
			
			subi	r7,r7,128					; Back off elapsed time from timeout value
			or		r7,r7,r7					; Do nothing here but force a single cycle delay
			mr.		r7,r7						; See if we used the whole timeout
			or		r7,r7,r7					; Do nothing here but force a single cycle delay
			
			ble-	mbitfail					; We failed
			mtmsr	r8							; Disable for interruptions
			mftb	r10							; Get the low part of the time base
			b		mbitsniff					; Now that we have opened an enable window, keep trying...

			.align	5

mbitgot:	mtmsr	r9							; Enable for interruptions
			li		r3,1						; Set good return code
			isync								; Make sure we do not use a speculativily loaded value
			blr

mbitfail:	li		r3,0						; Set failure return code
			blr									; Return, head hanging low...
			

/*
 *      unsigned int hw_cpu_sync(unsigned int *, unsigned int timeout)
 *
 *      Spin until word hits 0 or timeout. 
 *		Return success (1) or failure (0).
 *      Attempt will fail after timeout ticks of the timebase.
 *
 *		The theory is that a processor will bump a counter as it signals
 *		other processors.  Then it will spin untl the counter hits 0 (or
 *		times out).  The other processors, as it receives the signal will 
 *		decrement the counter.
 *
 *		The other processors use interlocked update to decrement, this one
 *		does not need to interlock.
 *
 */

			.align	5
			
			.globl	EXT(hw_cpu_sync)

LEXT(hw_cpu_sync)

			mftb	r10							; Get the low part of the time base
			mr		r9,r3						; Save the sync word address
			li		r3,1						; Assume we work

csynctry:	lwz		r11,0(r9)					; Grab the sync value
			mr.		r11,r11						; Counter hit 0?
			beqlr-								; Yeah, we are sunk...
			mftb	r12							; Time stamp us now

			sub		r12,r12,r10					; Get the elapsed time
			cmplw	r4,r12						; Have we gone too long?
			bge+	csynctry					; Not yet...
			
			li		r3,0						; Set failure...
			blr									; Return, head hanging low...

/*
 *      unsigned int hw_cpu_wcng(unsigned int *, unsigned int, unsigned int timeout)
 *
 *      Spin until word changes or timeout. 
 *		Return success (1) or failure (0).
 *      Attempt will fail after timeout ticks of the timebase.
 *
 *		This is used to insure that a processor passes a certain point.
 *		An example of use is to monitor the last interrupt time in the 
 *		per_proc block.  This can be used to insure that the other processor
 *		has seen at least one interrupt since a specific time.
 *
 */

			.align	5
			
			.globl	EXT(hw_cpu_wcng)

LEXT(hw_cpu_wcng)

			mftb	r10							; Get the low part of the time base
			mr		r9,r3						; Save the sync word address
			li		r3,1						; Assume we work

wcngtry:	lwz		r11,0(r9)					; Grab the  value
			cmplw	r11,r4						; Do they still match?
			bnelr-								; Nope, cool...
			mftb	r12							; Time stamp us now

			sub		r12,r12,r10					; Get the elapsed time
			cmplw	r5,r12						; Have we gone too long?
			bge+	wcngtry						; Not yet...
			
			li		r3,0						; Set failure...
			blr									; Return, head hanging low...
			

/*
 *      unsigned int hw_lock_try(hw_lock_t)
 *
 *      Try to acquire spin-lock. Return success (1) or failure (0)
 *      Returns with preemption disabled on success.
 *
 */
			.align	5
			.globl	EXT(hw_lock_try)

LEXT(hw_lock_try)

#if 0
			lis		r0,HIGH_ADDR(CutTrace)		/* (TEST/DEBUG) */
			lis		r5,0x9999					/* (TEST/DEBUG) */
			oris	r0,r0,LOW_ADDR(CutTrace)	/* (TEST/DEBUG) */
			sc									/* (TEST/DEBUG) */
#endif
			mfmsr	r9							/* Save the MSR value */
			rlwinm	r9,r9,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r9,r9,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r7,r9,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Clear interruption bit */

#if	MACH_LDEBUG
			lis	r5,	0x10						/* roughly 1E6 */
			mtctr	r5
#endif	/* MACH_LDEBUG */
			
			mtmsr	r7							/* Disable interruptions and thus, preemption */
			isync								; May have turned off fp/vec here
.L_lock_try_loop:	

#if	MACH_LDEBUG
			bdnz+	0f							/* Count attempts */
			mtmsr	r9							/* Restore enablement */
			BREAKPOINT_TRAP						/* Get to debugger */
			mtmsr	r7							/* Disable interruptions and thus, preemption */
0:	
#endif	/* MACH_LDEBUG */

			lwarx	r5,0,r3						/* Ld from addr of arg and reserve */

			andi.	r6,r5,ILK_LOCKED			/* TEST... */
			ori		r5,r5,ILK_LOCKED
			bne-	.L_lock_try_failed			/* branch if taken. Predict free */
	
			stwcx.	r5,0,r3						/* And SET (if still reserved) */
			mfsprg	r6,0						/* Get the per_proc block */			
			bne-	.L_lock_try_loop			/* If set failed, loop back */
			
			isync

			lwz		r5,PP_PREEMPT_CNT(r6)		/* Get the preemption level */
			addi	r5,r5,1						/* Bring up the disable count */
			stw		r5,PP_PREEMPT_CNT(r6)		/* Save it back */

 			mtmsr	r9							/* Allow interruptions now */
			li		r3,1						/* Set that the lock was free */
			blr

.L_lock_try_failed:
 			mtmsr	r9							/* Allow interruptions now */
			li		r3,0						/* FAILURE - lock was taken */
			blr

/*
 *      unsigned int hw_lock_held(hw_lock_t)
 *
 *      Return 1 if lock is held
 *      Doesn't change preemption state.
 *      N.B.  Racy, of course.
 *
 */
			.align	5
			.globl	EXT(hw_lock_held)

LEXT(hw_lock_held)

#if 0
			lis		r0,HIGH_ADDR(CutTrace)		/* (TEST/DEBUG) */
			lis		r5,0x8888					/* (TEST/DEBUG) */
			oris	r0,r0,LOW_ADDR(CutTrace)	/* (TEST/DEBUG) */
			sc									/* (TEST/DEBUG) */
#endif
			isync							/* Make sure we don't use a speculativily fetched lock */
			lwz		r3, 0(r3)				/* Return value of lock */
			blr

/*
 *		uint32_t hw_compare_and_store(uint32_t oldval, uint32_t newval, uint32_t *dest)
 *
 *		Compare old to area if equal, store new, and return true
 *		else return false and no store
 *		This is an atomic operation
 *
 */
			.align	5
			.globl	EXT(hw_compare_and_store)

LEXT(hw_compare_and_store)

			mr		r6,r3						/* Save the old value */			

cstry:		lwarx	r9,0,r5						/* Grab the area value */
			li		r3,1						/* Assume it works */
			cmplw	cr0,r9,r6					/* Does it match the old value? */
			bne-	csfail						/* No, it must have changed... */
			stwcx.	r4,0,r5						/* Try to save the new value */
			bne-	cstry						/* Didn't get it, try again... */
			isync								/* Just hold up prefetch */
			blr									/* Return... */
			
csfail:		li		r3,0						/* Set failure */
			blr									/* Better luck next time... */


/*
 *		uint32_t hw_atomic_add(uint32_t *dest, uint32_t delt)
 *
 *		Atomically add the second parameter to the first.
 *		Returns the result.
 *
 */
			.align	5
			.globl	EXT(hw_atomic_add)

LEXT(hw_atomic_add)

			mr		r6,r3						/* Save the area */			

addtry:		lwarx	r3,0,r6						/* Grab the area value */
			add		r3,r3,r4					/* Add the value */
			stwcx.	r3,0,r6						/* Try to save the new value */
			bne-	addtry						/* Didn't get it, try again... */
			blr									/* Return... */


/*
 *		uint32_t hw_atomic_sub(uint32_t *dest, uint32_t delt)
 *
 *		Atomically subtract the second parameter from the first.
 *		Returns the result.
 *
 */
			.align	5
			.globl	EXT(hw_atomic_sub)

LEXT(hw_atomic_sub)

			mr		r6,r3						/* Save the area */			

subtry:		lwarx	r3,0,r6						/* Grab the area value */
			sub		r3,r3,r4					/* Subtract the value */
			stwcx.	r3,0,r6						/* Try to save the new value */
			bne-	subtry						/* Didn't get it, try again... */
			blr									/* Return... */


/*
 *		uint32_t hw_atomic_or(uint32_t *dest, uint32_t mask)
 *
 *		Atomically ORs the second parameter into the first.
 *		Returns the result.
 *
 */
			.align	5
			.globl	EXT(hw_atomic_or)

LEXT(hw_atomic_or)

			mr		r6,r3						; Save the area 		

ortry:		lwarx	r3,0,r6						; Grab the area value
			or		r3,r3,r4					; OR the value 
			stwcx.	r3,0,r6						; Try to save the new value
			bne-	ortry						; Did not get it, try again...
			blr									; Return...


/*
 *		uint32_t hw_atomic_and(uint32_t *dest, uint32_t mask)
 *
 *		Atomically ANDs the second parameter with the first.
 *		Returns the result.
 *
 */
			.align	5
			.globl	EXT(hw_atomic_and)

LEXT(hw_atomic_and)

			mr		r6,r3						; Save the area 		

andtry:		lwarx	r3,0,r6						; Grab the area value
			and		r3,r3,r4					; AND the value 
			stwcx.	r3,0,r6						; Try to save the new value
			bne-	andtry						; Did not get it, try again...
			blr									; Return...


/*
 *		void hw_queue_atomic(unsigned int * anchor, unsigned int * elem, unsigned int disp)
 *
 *		Atomically inserts the element at the head of the list
 *		anchor is the pointer to the first element
 *		element is the pointer to the element to insert
 *		disp is the displacement into the element to the chain pointer
 *
 */
			.align	5
			.globl	EXT(hw_queue_atomic)

LEXT(hw_queue_atomic)

			mr		r7,r4						/* Make end point the same as start */
			mr		r8,r5						/* Copy the displacement also */
			b		hw_queue_comm				/* Join common code... */

/*
 *		void hw_queue_atomic_list(unsigned int * anchor, unsigned int * first, unsigned int * last, unsigned int disp)
 *
 *		Atomically inserts the list of elements at the head of the list
 *		anchor is the pointer to the first element
 *		first is the pointer to the first element to insert
 *		last is the pointer to the last element to insert
 *		disp is the displacement into the element to the chain pointer
 *
 */
			.align	5
			.globl	EXT(hw_queue_atomic_list)

LEXT(hw_queue_atomic_list)

			mr		r7,r5						/* Make end point the same as start */
			mr		r8,r6						/* Copy the displacement also */

hw_queue_comm:
			lwarx	r9,0,r3						/* Pick up the anchor */
			stwx	r9,r8,r7					/* Chain that to the end of the new stuff */
			eieio								; Make sure this store makes it before the anchor update
			stwcx.	r4,0,r3						/* Try to chain into the front */
			bne-	hw_queue_comm				/* Didn't make it, try again... */
			
			blr									/* Return... */

/*
 *		unsigned int *hw_dequeue_atomic(unsigned int *anchor, unsigned int disp)
 *
 *		Atomically removes the first element in a list and returns it.
 *		anchor is the pointer to the first element
 *		disp is the displacement into the element to the chain pointer
 *		Returns element if found, 0 if empty.
 *
 */
			.align	5
			.globl	EXT(hw_dequeue_atomic)

LEXT(hw_dequeue_atomic)

			mr		r5,r3						/* Save the anchor */

hw_dequeue_comm:
			lwarx	r3,0,r5						/* Pick up the anchor */
			mr.		r3,r3						/* Is the list empty? */
			beqlr-								/* Leave it list empty... */
			lwzx	r9,r4,r3					/* Get the next in line */
			stwcx.	r9,0,r5						/* Try to chain into the front */
			beqlr+								; Got the thing, go away with it...
			b		hw_dequeue_comm				; Did not make it, try again...

/*
 *	void mutex_init(mutex_t* l, etap_event_t etap)
 */

ENTRY(mutex_init,TAG_NO_FRAME_USED)

			PROLOG(0)
			li	r10,	0
			stw	r10,	LOCK_DATA(r3)		/* clear lock word */
			sth	r10,	MUTEX_WAITERS(r3)	/* init waiter count */
			sth	r10,	MUTEX_PROMOTED_PRI(r3)
#if	MACH_LDEBUG
			stw	r10,	MUTEX_PC(r3)		/* init caller pc */
			stw	r10,	MUTEX_THREAD(r3)	/* and owning thread */
			li	r10,	MUTEX_TAG
			stw	r10,	MUTEX_TYPE(r3)		/* set lock type */
#endif	/* MACH_LDEBUG */

#if	ETAP_LOCK_TRACE
			bl	EXT(etap_mutex_init)		/* init ETAP data */
#endif	/* ETAP_LOCK_TRACE */

			EPILOG
			blr

/*
 *	void mutex_lock(mutex_t*)
 */

			.align	5
			.globl	EXT(mutex_lock)
LEXT(mutex_lock)

			.globl	EXT(_mutex_lock)
LEXT(_mutex_lock)

#if	!MACH_LDEBUG
			mfsprg	r6,1					/* load the current thread */
L_mutex_lock_loop:
			lwarx	r5,0,r3					/* load the mutex lock */
			mr.		r5,r5
			bne-	L_mutex_lock_slow		/* go to the slow path */
			stwcx.	r6,0,r3					/* grab the lock */
			bne-	L_mutex_lock_loop		/* loop back if failed */
			isync							/* stop prefeteching */
			blr
L_mutex_lock_slow:
#endif
#if CHECKNMI
			mflr	r12							; (TEST/DEBUG) 
			bl		EXT(ml_sense_nmi)			; (TEST/DEBUG)
			mtlr	r12							; (TEST/DEBUG)
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
	
#if	ETAP_LOCK_TRACE
			li		r0,	0
			stw		r0,SWT_HI(r1)			/* set wait time to 0 (HI) */
			stw		r0,SWT_LO(r1)			/* set wait time to 0 (LO) */
			stw		r0,MISSED(r1)			/* clear local miss marker */
#endif	/* ETAP_LOCK_TRACE */

			CHECK_SETUP(r12)	
			CHECK_MUTEX_TYPE()
			CHECK_NO_SIMPLELOCKS()

.L_ml_retry:
#if 0
			mfsprg	r4,0						/* (TEST/DEBUG) */
			lis		r0,HIGH_ADDR(CutTrace)		/* (TEST/DEBUG) */
			lwz		r4,PP_ACTIVE_THREAD(r4)		/* (TEST/DEBUG) */
			lis		r5,0xAAAA					/* (TEST/DEBUG) */
			oris	r0,r0,LOW_ADDR(CutTrace)	/* (TEST/DEBUG) */
			sc									/* (TEST/DEBUG) */
#endif

			bl		lockDisa				/* Go get a lock on the mutex's interlock lock */
			mr.		r4,r3					/* Did we get it? */
			lwz		r3,FM_ARG0(r1)			/* Restore the lock address */
			bne+	mlGotInt				/* We got it just fine... */

			lis		r3,HIGH_ADDR(mutex_failed1)	; Get the failed mutex message
			ori		r3,r3,LOW_ADDR(mutex_failed1)	; Get the failed mutex message
			bl		EXT(panic)				; Call panic
			BREAKPOINT_TRAP					; We die here anyway, can not get the lock
	
			.data
mutex_failed1:
			STRINGD	"We can't get a mutex interlock lock on mutex_lock\n\000"
			.text
			
mlGotInt:
			
/*			Note that there is no reason to do a load and reserve here.  We already
			hold the interlock lock and no one can touch this field unless they 
			have that, so, we're free to play */
			
			lwz		r4,LOCK_DATA(r3)		/* Get the mutex's lock field */
			rlwinm.	r9,r4,30,2,31			/* So, can we have it? */
			bne-	mlInUse					/* Nope, sombody's playing already... */

#if	MACH_LDEBUG
			mfmsr	r11						; Note: no need to deal with fp or vec here
			rlwinm	r5,r11,0,MSR_EE_BIT+1,MSR_EE_BIT-1
			mtmsr	r5
			mfsprg	r9,0					/* Get the per_proc block */
			lwz		r5,0(r1)				/* Get previous save frame */
			lwz		r5,FM_LR_SAVE(r5)		/* Get our caller's address */
			lwz		r8,	PP_ACTIVE_THREAD(r9)	/* Get the active thread */
			stw		r5,MUTEX_PC(r3)		/* Save our caller */
			mr.		r8,r8					/* Is there any thread? */
			stw		r8,MUTEX_THREAD(r3)		/* Set the mutex's holding thread */
			beq-	.L_ml_no_active_thread	/* No owning thread... */
			lwz		r9,THREAD_MUTEX_COUNT(r8)	/* Get the mutex count */
			addi	r9,r9,1					/* Bump it up */
			stw		r9,THREAD_MUTEX_COUNT(r8)	/* Stash it back */
.L_ml_no_active_thread:
			mtmsr	r11
#endif	/* MACH_LDEBUG */

			bl	EXT(mutex_lock_acquire)
			mfsprg	r5,1
			mr.		r4,r3
			lwz		r3,FM_ARG0(r1)
			beq		mlUnlock
			ori		r5,r5,WAIT_FLAG
mlUnlock:
			sync
			stw	r5,LOCK_DATA(r3)			/* grab the mutexlock and free the interlock */

#if	ETAP_LOCK_TRACE
			mflr	r4
			lwz		r5,SWT_HI(r1)
			lwz		r6,SWT_LO(r1)
			bl	EXT(etap_mutex_hold)		/* collect hold timestamp */
#endif	/* ETAP_LOCK_TRACE */

			EPILOG							/* Restore all saved registers */

			b		epStart					/* Go enable preemption... */

/*
 *			We come to here when we have a resource conflict.  In other words,
 *			the mutex is held.
 */

mlInUse:

#if	ETAP_LOCK_TRACE
			lwz		r7,MISSED(r1)
			cmpwi	r7,0					/* did we already take a wait timestamp ? */
			bne		.L_ml_block				/* yup. carry-on */
			bl		EXT(etap_mutex_miss)	/* get wait timestamp */
			stw		r3,SWT_HI(r1)			/* store timestamp */
			stw		r4,SWT_LO(r1)
			li		r7,	1					/* mark wait timestamp as taken */
			stw		r7,MISSED(r1)
			lwz		r3,FM_ARG0(r1)			/* restore r3 (saved in prolog) */
.L_ml_block:
#endif	/* ETAP_LOCK_TRACE */

			CHECK_SETUP(r12)	
			CHECK_MYLOCK(MUTEX_THREAD)		/* Assert we don't own the lock already */
	

/*			Note that we come in here with the interlock set.  The wait routine
 *			will unlock it before waiting.
 */
			ori		r4,r4,WAIT_FLAG			/* Set the wait flag */
			stw	r4,LOCK_DATA(r3)
			rlwinm	r4,r4,0,0,29			/* Extract the lock owner */
			bl	EXT(mutex_lock_wait)		/* Wait for our turn at the lock */
			
			lwz	r3,FM_ARG0(r1)				/* restore r3 (saved in prolog) */
			b	.L_ml_retry					/* and try again... */

	
/*
 *	void _mutex_try(mutex_t*)
 *
 */
	
			.align	5
			.globl	EXT(mutex_try)
LEXT(mutex_try)
			.globl	EXT(_mutex_try)
LEXT(_mutex_try)
#if	!MACH_LDEBUG
			mfsprg	r6,1					/* load the current thread */
L_mutex_try_loop:
			lwarx	r5,0,r3					/* load the lock value */
			mr.		r5,r5
			bne-	L_mutex_try_slow		/* branch to the slow  path */
			stwcx.	r6,0,r3					/* grab the lock */
			bne-	L_mutex_try_loop		/* retry if failed */
			isync							/* stop prefetching */
			li		r3, 1
			blr
L_mutex_try_slow:
#endif

			PROLOG(8)						/* reserve space for SWT_HI and SWT_LO */
	
#if	ETAP_LOCK_TRACE
			li	r5,	0
			stw	r5,	STW_HI(r1)				/* set wait time to 0 (HI) */
			stw	r5,	SWT_LO(r1)				/* set wait time to 0 (LO) */
#endif	/* ETAP_LOCK_TRACE */

#if 0
			lis		r0,HIGH_ADDR(CutTrace)		/* (TEST/DEBUG) */
			lis		r5,0xBBBB					/* (TEST/DEBUG) */
			oris	r0,r0,LOW_ADDR(CutTrace)	/* (TEST/DEBUG) */
			sc									/* (TEST/DEBUG) */
#endif
			CHECK_SETUP(r12)	
			CHECK_MUTEX_TYPE()
			CHECK_NO_SIMPLELOCKS()
			
			lwz		r6,LOCK_DATA(r3)		/* Quick check */
			rlwinm.	r6,r6,30,2,31			/* to see if someone has this lock already */
			bne-	mtFail					/* Someone's got it already... */

			bl		lockDisa				/* Go get a lock on the mutex's interlock lock */
			mr.		r4,r3					/* Did we get it? */
			lwz		r3,FM_ARG0(r1)			/* Restore the lock address */
			bne+	mtGotInt				/* We got it just fine... */

			lis		r3,HIGH_ADDR(mutex_failed2)	; Get the failed mutex message
			ori		r3,r3,LOW_ADDR(mutex_failed2)	; Get the failed mutex message
			bl		EXT(panic)				; Call panic
			BREAKPOINT_TRAP					; We die here anyway, can not get the lock
	
			.data
mutex_failed2:
			STRINGD	"We can't get a mutex interlock lock on mutex_try\n\000"
			.text
			
mtGotInt:
			
/*			Note that there is no reason to do a load and reserve here.  We already
			hold the interlock and no one can touch at this field unless they 
			have that, so, we're free to play */
			
			lwz		r4,LOCK_DATA(r3)		/* Get the mutex's lock field */
			rlwinm.	r9,r4,30,2,31			/* So, can we have it? */
			bne-	mtInUse					/* Nope, sombody's playing already... */
			
#if	MACH_LDEBUG
			mfmsr	r11
			rlwinm	r5,r11,0,MSR_EE_BIT+1,MSR_EE_BIT-1
			mtmsr	r5
			mfsprg	r9,0					/* Get the per_proc block */
			lwz		r5,0(r1)				/* Get previous save frame */
			lwz		r5,FM_LR_SAVE(r5)		/* Get our caller's address */
			lwz		r8,	PP_ACTIVE_THREAD(r9)	/* Get the active thread */
			stw		r5,MUTEX_PC(r3)		/* Save our caller */
			mr.		r8,r8					/* Is there any thread? */
			stw		r8,MUTEX_THREAD(r3)		/* Set the mutex's holding thread */
			beq-	.L_mt_no_active_thread	/* No owning thread... */
			lwz		r9,	THREAD_MUTEX_COUNT(r8)	/* Get the mutex count */
			addi	r9,	r9,	1				/* Bump it up */
			stw		r9,	THREAD_MUTEX_COUNT(r8)	/* Stash it back */
.L_mt_no_active_thread:
			mtmsr	r11
#endif	/* MACH_LDEBUG */

			bl	EXT(mutex_lock_acquire)
			mfsprg	r5,1
			mr.		r4,r3
			lwz		r3,FM_ARG0(r1)
			beq		mtUnlock
			ori		r5,r5,WAIT_FLAG
mtUnlock:
			sync							/* Push it all out */
			stw	r5,LOCK_DATA(r3)			/* grab the mutexlock and free the interlock */

#if	ETAP_LOCK_TRACE
			lwz		r4,0(r1)				/* Back chain the stack */
			lwz		r5,SWT_HI(r1)
			lwz		r4,FM_LR_SAVE(r4)		/* Get our caller's address */
			lwz		r6,SWT_LO(r1)
			bl	EXT(etap_mutex_hold)		/* collect hold timestamp */
#endif	/* ETAP_LOCK_TRACE */

			bl		epStart					/* Go enable preemption... */

			li		r3, 1
			EPILOG							/* Restore all saved registers */
			blr								/* Return... */

/*
 *			We come to here when we have a resource conflict.  In other words,
 *			the mutex is held.
 */

mtInUse:	
			rlwinm	r4,r4,0,0,30			/* Get the unlock value */
			stw		r4,LOCK_DATA(r3)		/* free the interlock */
			bl		epStart					/* Go enable preemption... */

mtFail:		li		r3,0					/* Set failure code */
			EPILOG							/* Restore all saved registers */
			blr								/* Return... */

		
/*
 *	void mutex_unlock(mutex_t* l)
 */

			.align	5
			.globl	EXT(mutex_unlock)

LEXT(mutex_unlock)
#if	!MACH_LDEBUG
			sync
L_mutex_unlock_loop:
			lwarx	r5,0,r3
			rlwinm.	r4,r5,0,30,31			/* Bail if pending waiter or interlock set */
			li		r5,0					/* Clear the mutexlock */
			bne-	L_mutex_unlock_slow
			stwcx.	r5,0,r3
			bne-	L_mutex_unlock_loop
			blr
L_mutex_unlock_slow:
#endif
			PROLOG(0)
	
#if	ETAP_LOCK_TRACE
			bl		EXT(etap_mutex_unlock)	/* collect ETAP data */
			lwz		r3,FM_ARG0(r1)			/* restore r3 (saved in prolog) */
#endif	/* ETAP_LOCK_TRACE */

			CHECK_SETUP(r12)	
			CHECK_MUTEX_TYPE()
			CHECK_THREAD(MUTEX_THREAD)

#if 0
			mfsprg	r4,0						/* (TEST/DEBUG) */
			lis		r0,HIGH_ADDR(CutTrace)		/* (TEST/DEBUG) */
			lwz		r4,PP_ACTIVE_THREAD(r4)	/* (TEST/DEBUG) */
			lis		r5,0xCCCC					/* (TEST/DEBUG) */
			oris	r0,r0,LOW_ADDR(CutTrace)	/* (TEST/DEBUG) */
			sc									/* (TEST/DEBUG) */
#endif
			bl		lockDisa				/* Go get a lock on the mutex's interlock lock */
			mr.		r4,r3					/* Did we get it? */
			lwz		r3,FM_ARG0(r1)			/* Restore the lock address */
			bne+	muGotInt				/* We got it just fine... */

			lis		r3,HIGH_ADDR(mutex_failed3)	; Get the failed mutex message
			ori		r3,r3,LOW_ADDR(mutex_failed3)	; Get the failed mutex message
			bl		EXT(panic)				; Call panic
			BREAKPOINT_TRAP					; We die here anyway, can not get the lock
	
			.data
mutex_failed3:
			STRINGD	"We can't get a mutex interlock lock on mutex_unlock\n\000"
			.text
			
			
muGotInt:
			lwz		r4,LOCK_DATA(r3)
			andi.	r5,r4,WAIT_FLAG			/* are there any waiters ? */
			rlwinm	r4,r4,0,0,29
			beq+	muUnlock				/* Nope, we're done... */

			bl		EXT(mutex_unlock_wakeup)	/* yes, wake a thread */
			lwz		r3,FM_ARG0(r1)			/* restore r3 (saved in prolog) */
			lwz		r5,LOCK_DATA(r3)		/* load the lock */

muUnlock:
#if	MACH_LDEBUG
			mfmsr	r11
			rlwinm	r9,r11,0,MSR_EE_BIT+1,MSR_EE_BIT-1
			mtmsr	r9
			mfsprg	r9,0					
			lwz		r9,PP_ACTIVE_THREAD(r9)
			stw		r9,MUTEX_THREAD(r3)	/* disown thread */
			cmpwi	r9,0
			beq-	.L_mu_no_active_thread
			lwz		r8,THREAD_MUTEX_COUNT(r9)
			subi	r8,r8,1
			stw		r8,THREAD_MUTEX_COUNT(r9)
.L_mu_no_active_thread:
			mtmsr	r11
#endif	/* MACH_LDEBUG */

			andi.	r5,r5,WAIT_FLAG			/* Get the unlock value */
			sync							/* Make sure it's all there before we release */
			stw		r5,LOCK_DATA(r3)		/* unlock the interlock and lock */
		
			EPILOG							/* Deal with the stack now, enable_preemption doesn't always want one */
			b		epStart					/* Go enable preemption... */

/*
 *	void interlock_unlock(hw_lock_t lock)
 */

			.align	5
			.globl	EXT(interlock_unlock)

LEXT(interlock_unlock)

#if 0
			lis		r0,HIGH_ADDR(CutTrace)		/* (TEST/DEBUG) */
			lis		r5,0xDDDD					/* (TEST/DEBUG) */
			oris	r0,r0,LOW_ADDR(CutTrace)	/* (TEST/DEBUG) */
			sc									/* (TEST/DEBUG) */
#endif
			lwz		r10,LOCK_DATA(r3)
			rlwinm	r10,r10,0,0,30
			sync
			stw		r10,LOCK_DATA(r3)

			b		epStart					/* Go enable preemption... */

/*
 *		Here is where we enable preemption.  We need to be protected
 *		against ourselves, we can't chance getting interrupted and modifying
 *		our processor wide preemption count after we'sve loaded it up. So,
 *		we need to disable all 'rupts.  Actually, we could use a compare
 *		and swap to do this, but, since there are no MP considerations
 *		(we are dealing with a CPU local field) it is much, much faster
 *		to disable.
 *
 *		Note that if we are not genned MP, the calls here will be no-opped via
 *		a #define and since the _mp forms are the same, likewise a #define
 *		will be used to route to the other forms
 */

/*		This version does not check if we get preempted or not */


			.align	4
			.globl	EXT(_enable_preemption_no_check)

LEXT(_enable_preemption_no_check)
			cmplw	cr1,r1,r1			/* Force zero cr so we know not to check if preempted */
			b		epCommn				/* Join up with the other enable code... */


/*		This version checks if we get preempted or not */

			.align	5
			.globl	EXT(_enable_preemption)

LEXT(_enable_preemption)

epStart:	cmplwi	cr1,r1,0			/* Force non-zero cr so we know to check if preempted */

/*
 *			Common enable preemption code 
 */

epCommn:	mfmsr	r9					/* Save the old MSR */
			rlwinm	r9,r9,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r9,r9,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r8,r9,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Clear interruptions */
 			mtmsr	r8					/* Interrupts off */
			isync						; May have mess with vec/fp here
						
			mfsprg	r3,0				/* Get the per_proc block */
			li		r8,-1				/* Get a decrimenter */
			lwz		r5,PP_PREEMPT_CNT(r3)	/* Get the preemption level */
			add.	r5,r5,r8			/* Bring down the disable count */
#if 0
			mfsprg	r4,1				; (TEST/DEBUG) Note the next 3 keep from interrpting too early
			mr.		r4,r4				; (TEST/DEBUG)
			beq-	epskptrc0			; (TEST/DEBUG)
			lis		r0,hi16(CutTrace)	; (TEST/DEBUG)
			lis		r4,0xBBBB			; (TEST/DEBUG)
			oris	r0,r0,lo16(CutTrace)	; (TEST/DEBUG)
			sc							; (TEST/DEBUG)
epskptrc0:	mr.		r5,r5				; (TEST/DEBUG)
#endif
#if MACH_LDEBUG
			blt-	epTooFar			/* Yeah, we did... */
#endif /* MACH_LDEBUG */
			stw		r5,PP_PREEMPT_CNT(r3)	/* Save it back */

			beq+	epCheckPreempt		/* Go check if we need to be preempted... */

epNoCheck:	mtmsr	r9					/* Restore the interrupt level */
			blr							/* Leave... */

#if MACH_LDEBUG
epTooFar:	
			lis		r6,HIGH_ADDR(EXT(panic))	/* First half of panic call */
			lis		r3,HIGH_ADDR(epTooFarStr)	/* First half of panic string */
			ori		r6,r6,LOW_ADDR(EXT(panic))	/* Second half of panic call */
			ori		r3,r3,LOW_ADDR(epTooFarStr)	/* Second half of panic string */
			mtlr	r6					/* Get the address of the panic routine */
			mtmsr	r9					/* Restore interruptions */
			blrl						/* Panic... */

			.data
epTooFarStr:
			STRINGD	"_enable_preemption: preemption_level <= 0!\000"
			.text
#endif /* MACH_LDEBUG */

			.align	5

epCheckPreempt:
			lwz		r7,PP_NEED_AST(r3)	/* Get the AST request address */
			li		r5,AST_URGENT		/* Get the requests we do honor */
			lwz		r7,0(r7)			/* Get the actual, real live, extra special AST word */
			lis		r0,HIGH_ADDR(DoPreemptCall)	/* Just in case, get the top of firmware call */
			and.	r7,r7,r5			; Should we preempt?
			ori		r0,r0,LOW_ADDR(DoPreemptCall)	/* Merge in bottom part */
			beq+	epCPno				; No preemption here...

			andi.	r3,r9,lo16(MASK(MSR_EE))	; We cannot preempt if interruptions are off

epCPno:		mtmsr	r9					/* Allow interrupts if we can */
			beqlr+						; We probably will not preempt...
			sc							/* Do the preemption */
			blr							/* Now, go away now... */

/*
 *			Here is where we disable preemption.  Since preemption is on a
 *			per processor basis (a thread runs on one CPU at a time) we don't
 *			need any cross-processor synchronization.  We do, however, need to
 *			be interrupt safe, so we don't preempt while in the process of
 *			disabling it.  We could use SPLs, but since we always want complete
 *			disablement, and this is platform specific code, we'll just kick the
 *			MSR. We'll save a couple of orders of magnitude over using SPLs.
 */

			.align	5

			nop							; Use these 5 nops to force daPreComm 
			nop							; to a line boundary.
			nop
			nop
			nop
			
			.globl	EXT(_disable_preemption)

LEXT(_disable_preemption)

daPreAll:	mfmsr	r9					/* Save the old MSR */
			rlwinm	r9,r9,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r9,r9,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r8,r9,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Clear interruptions */
 			mtmsr	r8					/* Interrupts off */
			isync						; May have mess with fp/vec
			
daPreComm:	mfsprg	r6,0				/* Get the per_proc block */
			lwz		r5,PP_PREEMPT_CNT(r6)	/* Get the preemption level */
			addi	r5,r5,1				/* Bring up the disable count */
			stw		r5,PP_PREEMPT_CNT(r6)	/* Save it back */
#if 0
			mfsprg	r4,1				; (TEST/DEBUG) Note the next 3 keep from interrpting too early
			mr.		r4,r4				; (TEST/DEBUG)
			beq-	epskptrc1			; (TEST/DEBUG)
			lis		r0,hi16(CutTrace)	; (TEST/DEBUG)
			lis		r4,0xAAAA			; (TEST/DEBUG)
			oris	r0,r0,lo16(CutTrace)	; (TEST/DEBUG)
			sc							; (TEST/DEBUG)
epskptrc1:								; (TEST/DEBUG)
#endif

;
;		Set PREEMPTSTACK above to enable a preemption traceback stack. 		
;
;		NOTE: make sure that PREEMPTSTACK in aligned_data is
;		set the same as it is here.  This is the number of
;		traceback entries we can handle per processor
;
;		A value of 0 disables the stack.
;
#if PREEMPTSTACK
			cmplwi	r5,PREEMPTSTACK		; Maximum depth
			lwz		r6,CPU_ACTIVE_THREAD(r6)	; Get the pointer to the currently active thread
			bgt-	nopredeb			; Too many to stack...
			mr.		r6,r6				; During boot?
			beq-	nopredeb			; Yes, do not do backtrace...
			lwz		r6,THREAD_TOP_ACT(r6)	; Point to the active activation
			lwz		r6,ACT_MACT_PCB(r6)		; Get the last savearea used
			mr.		r0,r6				; Any saved context?
			beq-	nosaveds			; No...
			lwz		r0,saver1(r6)		; Get end of savearea chain

nosaveds:	li		r11,0				; Clear callers callers callers return
			li		r10,0				; Clear callers callers callers callers return
			li		r8,0				; Clear callers callers callers callers callers return
			lwz		r2,0(r1)			; Get callers callers stack frame
			lwz		r12,8(r2)			; Get our callers return
			lwz		r4,0(r2)			; Back chain

			xor		r2,r4,r2			; Form difference
			cmplwi	r2,8192				; Within a couple of pages?
			mr		r2,r4				; Move register
			bge-	nosaveher2			; No, no back chain then...
			lwz		r11,8(r2)			; Get our callers return
			lwz		r4,0(r2)			; Back chain

			xor		r2,r4,r2			; Form difference
			cmplwi	r2,8192				; Within a couple of pages?
			mr		r2,r4				; Move register
			bge-	nosaveher2			; No, no back chain then...
			lwz		r10,8(r2)			; Get our callers return
			lwz		r4,0(r2)			; Back chain

			xor		r2,r4,r2			; Form difference
			cmplwi	r2,8192				; Within a couple of pages?
			mr		r2,r4				; Move register
			bge-	nosaveher2			; No, no back chain then...
			lwz		r8,8(r2)			; Get our callers return

nosaveher2:
			addi	r5,r5,-1			; Get index to slot
			mfspr	r6,pir				; Get our processor
			mflr	r4					; Get our return
			rlwinm	r6,r6,8,0,23		; Index to processor slot
			lis		r2,hi16(EXT(DBGpreempt))	; Stack high order
			rlwinm	r5,r5,4,0,27		; Index to stack slot			
			ori		r2,r2,lo16(EXT(DBGpreempt))	; Stack low order
			add		r2,r2,r5			; Point to slot
			add		r2,r2,r6			; Move to processor
			stw		r4,0(r2)			; Save our return
			stw		r11,4(r2)			; Save callers caller
			stw		r10,8(r2)			; Save callers callers caller
			stw		r8,12(r2)			; Save callers callers callers caller
nopredeb:
#endif
 			mtmsr	r9					/* Allow interruptions now */
			
			blr							/* Return... */

/*
 *			Return the active thread for both inside and outside osfmk consumption
 */
  
			.align	5
			.globl	EXT(current_thread)

LEXT(current_thread)

#if 1
			mfsprg	r3,1
			lwz		r3,ACT_THREAD(r3)
			blr
#else
			mfmsr	r9					/* Save the old MSR */
			rlwinm	r9,r9,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r9,r9,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r8,r9,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Clear interruptions */
 			mtmsr	r8					/* Interrupts off */
 			isync
			mfsprg	r6,0				/* Get the per_proc */
			lwz		r3,PP_ACTIVE_THREAD(r6)	/* Get the active thread */
			mfsprg	r4,1
			lwz	r4,ACT_THREAD(r4)
			cmplw	cr0,r4,r3
			beq		current_thread_cont
			lis		r5,hi16(L_current_thread_paniced)
			ori		r5,r5,lo16(L_current_thread_paniced)
			lwz		r6,0(r5)
			mr.		r6,r6
			bne		current_thread_cont
			stw		r9,0(r5)
			mr		r5,r4
			mr		r4,r3
			lis		r3,hi16(L_current_thread_panic)
			ori		r3,r3,lo16(L_current_thread_panic)
			bl		EXT(panic)

			.data
L_current_thread_panic:
			STRINGD "current_thread: spr1 not sync %x %x %x\n\000"
L_current_thread_paniced:
			.long	0
			.text
current_thread_cont:
#endif
			mtmsr	r9					/* Restore interruptions to entry */
			blr							/* Return... */

/*
 *			Set the active thread 
 */
			.align	5
			.globl	EXT(set_machine_current_thread)
LEXT(set_machine_current_thread)

			mfmsr	r9					/* Save the old MSR */
			rlwinm	r9,r9,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r9,r9,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r8,r9,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Clear interruptions */
 			mtmsr	r8					/* Interrupts off */
			isync						; May have messed with fp/vec
			mfsprg	r6,0				/* Get the per_proc */
			stw		r3,PP_ACTIVE_THREAD(r6)	/* Set the active thread */
			mtmsr	r9					/* Restore interruptions to entry */
			blr							/* Return... */

/*
 *			Set the current activation
 */
			.align	5
			.globl	EXT(set_machine_current_act)
LEXT(set_machine_current_act)
			mtsprg	1,r3				/* Set spr1 with the active thread */
			blr							/* Return... */

/*
 *			Return the current activation
 */
			.align	5
			.globl	EXT(current_act)
LEXT(current_act)
			mfsprg	r3,1
			blr



/*
 *			Return the current preemption level
 */
 
			.align	5
			.globl	EXT(get_preemption_level)

LEXT(get_preemption_level)
 
			mfmsr	r9					/* Save the old MSR */
			rlwinm	r9,r9,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r9,r9,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r8,r9,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Clear interruptions */
 			mtmsr	r8					/* Interrupts off */
			isync			
			mfsprg	r6,0				/* Get the per_proc */
			lwz		r3,PP_PREEMPT_CNT(r6)	/* Get the preemption level */
			mtmsr	r9					/* Restore interruptions to entry */
			blr							/* Return... */


/*
 *			Return the cpu_data
 */
 
			.align	5
			.globl	EXT(get_cpu_data)

LEXT(get_cpu_data)
 
			mfsprg	r3,0				/* Get the per_proc */
			addi	r3,r3,PP_ACTIVE_THREAD		/* Get the pointer to the CPU data from per proc */
			blr							/* Return... */


/*
 *			Return the simple lock count
 */
 
			.align	5
			.globl	EXT(get_simple_lock_count)

LEXT(get_simple_lock_count)
 
			mfmsr	r9					/* Save the old MSR */
			rlwinm	r9,r9,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r9,r9,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r8,r9,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Clear interruptions */
 			mtmsr	r8					/* Interrupts off */
			isync						; May have messed with vec/fp
			mfsprg	r6,0				/* Get the per_proc */
			lwz		r3,PP_SIMPLE_LOCK_CNT(r6)	/* Get the simple lock count */
			mtmsr	r9					/* Restore interruptions to entry */
			blr							/* Return... */

/*
 *		fast_usimple_lock():
 *
 *		If EE is off, get the simple lock without incrementing the preemption count and 
 *		mark The simple lock with SLOCK_FAST.
 *		If EE is on, call usimple_lock().
 */
			.align	5
			.globl	EXT(fast_usimple_lock)

LEXT(fast_usimple_lock)

#if CHECKNMI
		b		EXT(usimple_lock)		; (TEST/DEBUG)  
#endif                  
		mfmsr	r9
		andi.   r7,r9,lo16(MASK(MSR_EE))
		bne-	L_usimple_lock_c
L_usimple_lock_loop:
		lwarx   r4,0,r3
		li      r5,ILK_LOCKED|SLOCK_FAST
		mr.     r4,r4
		bne-    L_usimple_lock_c
		stwcx.  r5,0,r3
		bne-    L_usimple_lock_loop
		isync
		blr
L_usimple_lock_c:
		b		EXT(usimple_lock)

/*
 *		fast_usimple_lock_try():
 *
 *		If EE is off, try to get the simple lock. The preemption count doesn't get incremented and
 *		if successfully held, the simple lock is marked with SLOCK_FAST.
 *		If EE is on, call usimple_lock_try()
 */
			.align	5
			.globl	EXT(fast_usimple_lock_try)

LEXT(fast_usimple_lock_try)

#if CHECKNMI
		b		EXT(usimple_lock_try)		; (TEST/DEBUG)  
#endif                  
		mfmsr	r9
		andi.   r7,r9,lo16(MASK(MSR_EE))
		bne-	L_usimple_lock_try_c
L_usimple_lock_try_loop:
		lwarx   r4,0,r3
		li      r5,ILK_LOCKED|SLOCK_FAST
		mr.		r4,r4
		bne-	L_usimple_lock_try_fail
		stwcx.  r5,0,r3
		bne-    L_usimple_lock_try_loop
		li		r3,1
		isync
		blr
L_usimple_lock_try_fail:
		li		r3,0
		blr
L_usimple_lock_try_c:
		b		EXT(usimple_lock_try)

/*
 *		fast_usimple_unlock():
 *
 *		If the simple lock is marked SLOCK_FAST, release it without decrementing the preemption count.
 *		Call usimple_unlock() otherwise.	
 */
			.align	5
			.globl	EXT(fast_usimple_unlock)

LEXT(fast_usimple_unlock)

#if CHECKNMI
		b		EXT(usimple_unlock)			; (TEST/DEBUG)  
#endif                  
		lwz		r5,LOCK_DATA(r3)
		li		r0,0
		cmpi	cr0,r5,ILK_LOCKED|SLOCK_FAST
		bne-	L_usimple_unlock_c
		sync
#if 0
		mfmsr	r9
		andi.	r7,r9,lo16(MASK(MSR_EE))
		beq		L_usimple_unlock_cont
		lis		r3,hi16(L_usimple_unlock_panic)
		ori		r3,r3,lo16(L_usimple_unlock_panic)
		bl		EXT(panic)

		.data
L_usimple_unlock_panic:
		STRINGD "fast_usimple_unlock: interrupts not disabled\n\000"
		.text
L_usimple_unlock_cont:
#endif
		stw		r0, LOCK_DATA(r3)
		blr
L_usimple_unlock_c:
		b		EXT(usimple_unlock)

/*
 *		enter_funnel_section():
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
		or.		r10,r11,r10							; Check kdebug_enable or split_funnel_off
		bne-	L_enter_funnel_section_slow1		; If set, call the slow path
		mfsprg	r6,1								; Get the current activation
		lwz		r7,LOCK_FNL_MUTEX(r3)
		mfmsr	r11
		rlwinm	r11,r11,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
		rlwinm	r11,r11,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
		rlwinm  r10,r11,0,MSR_EE_BIT+1,MSR_EE_BIT-1
		mtmsr	r10									; Turn off EE
		isync										; May have messed with vec/fp
		mr		r9,r6
L_enter_funnel_section_loop:
		lwarx	r5,0,r7								; Load the mutex lock
		mr.		r5,r5
		bne-	L_enter_funnel_section_slow			; Go to the slow path
		stwcx.	r6,0,r7								; Grab the lock
		bne-	L_enter_funnel_section_loop			; Loop back if failed
		isync										; Stop prefeteching
		lwz		r6,ACT_THREAD(r6)					; Get the current thread
		li		r7,TH_FN_OWNED
		stw		r7,THREAD_FUNNEL_STATE(r6)			; Set the funnel state
		stw		r3,THREAD_FUNNEL_LOCK(r6)			; Set the funnel lock reference
		mtmsr	r11
		blr

L_enter_funnel_section_slow:
		mtmsr	r11
L_enter_funnel_section_slow1:
#endif
		li		r4,TRUE
		b		EXT(thread_funnel_set)

/*
 *		exit_funnel_section():
 *
 */
			.align	5
			.globl	EXT(exit_funnel_section)

LEXT(exit_funnel_section)

#if	!MACH_LDEBUG
		mfsprg	r6,1								; Get the current activation
		lwz		r6,ACT_THREAD(r6)					; Get the current thread
		lwz		r3,THREAD_FUNNEL_LOCK(r6)			; Get the funnel lock
		mr.		r3,r3								; Check on funnel held
		beq-	L_exit_funnel_section_ret			; 
		lis		r10,hi16(EXT(kdebug_enable))
		ori		r10,r10,lo16(EXT(kdebug_enable))
		lwz		r10,0(r10)
		mr.		r10,r10
		bne-	L_exit_funnel_section_slow1			; If set, call the slow path
		lwz		r7,LOCK_FNL_MUTEX(r3)				; Get the funnel mutex lock
		mfmsr	r11
		rlwinm	r11,r11,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
		rlwinm	r11,r11,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
		rlwinm  r10,r11,0,MSR_EE_BIT+1,MSR_EE_BIT-1
		mtmsr	r10									; Turn off EE
		isync										; May have messed with fp/vec
		sync
L_exit_funnel_section_loop:
		lwarx	r5,0,r7
		rlwinm.	r4,r5,0,30,31						; Bail if pending waiter or interlock set 
		li		r5,0								; Clear the mutexlock 
		bne-	L_exit_funnel_section_slow
		stwcx.	r5,0,r7								; Release the funnel mutexlock
		bne-	L_exit_funnel_section_loop
		li		r7,0
		stw		r7,THREAD_FUNNEL_STATE(r6)			; Clear the funnel state
		stw		r7,THREAD_FUNNEL_LOCK(r6)			; Clear the funnel lock reference
		mtmsr	r11
L_exit_funnel_section_ret:
		blr
L_exit_funnel_section_slow:
		mtmsr	r11
L_exit_funnel_section_slow1:
#endif
		li		r4,FALSE
		b		EXT(thread_funnel_set)


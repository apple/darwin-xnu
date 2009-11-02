/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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

#include <mach_assert.h>
#include <mach_ldebug.h>
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <assym.s>

#define	STRING	ascii

#define	ILK_LOCKED		0x01
#define	WAIT_FLAG		0x02
#define	WANT_UPGRADE	0x04
#define	WANT_EXCL		0x08

#define TH_FN_OWNED		0x01

# volatile CR bits
#define hwtimeout	20
#define mlckmiss	21

#define	RW_DATA		0

#define PROLOG(space)														\
			stwu	r1,-(FM_ALIGN(space)+FM_SIZE)(r1)			__ASMNL__	\
			mfcr	r2											__ASMNL__	\
			mflr	r0											__ASMNL__	\
			stw		r3,FM_ARG0(r1)								__ASMNL__	\
			stw		r11,FM_ARG0+0x04(r1)						__ASMNL__	\
			stw		r2,(FM_ALIGN(space)+FM_SIZE+FM_CR_SAVE)(r1)	__ASMNL__	\
			stw		r0,(FM_ALIGN(space)+FM_SIZE+FM_LR_SAVE)(r1)	__ASMNL__
	
#define EPILOG																 	\
			lwz		r1,0(r1)										__ASMNL__	\
			lwz		r0,FM_LR_SAVE(r1)								__ASMNL__	\
			mtlr	r0												__ASMNL__

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
 *		unsigned int hw_lock_bit(hw_lock_t, unsigned int bit, unsigned int timeout)
 *
 *			Try to acquire spin-lock. The second parameter is the bit mask to test and set.
 *			multiple bits may be set. Return success (1) or failure (0).
 *			Attempt will fail after timeout ticks of the timebase.
 */
			.align	5
			.globl	EXT(hw_lock_bit)

LEXT(hw_lock_bit)

			crset	hwtimeout						; timeout option
			mr		r12,r4							; Load bit mask
			mr		r4,r5							; Load timeout value
			b		lckcomm							; Join on up...

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
			crclr	hwtimeout						; no timeout option
			li		r4,0							; request default timeout value
			li		r12,ILK_LOCKED					; Load bit mask
			b		lckcomm							; Join on up...

lockDisa:
			crset	hwtimeout						; timeout option
			li		r4,0							; request default timeout value
			li		r12,ILK_LOCKED					; Load bit mask
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
			crset	hwtimeout						; timeout option
			li		r12,ILK_LOCKED					; Load bit mask
lckcomm:
			mfsprg	r6,1							; Get the current activation 
			lwz		r5,ACT_PREEMPT_CNT(r6)			; Get the preemption level
			addi	r5,r5,1							; Bring up the disable count
			stw		r5,ACT_PREEMPT_CNT(r6)			; Save it back 
			mr		r5,r3							; Get the address of the lock
			li		r8,0							; Set r8 to zero

lcktry:		lwarx	r6,0,r5							; Grab the lock value
			and.	r3,r6,r12						; Is it locked?
			or		r6,r6,r12						; Set interlock 
			bne--	lckspin							; Yeah, wait for it to clear...
			stwcx.	r6,0,r5							; Try to seize that there durn lock
			bne--	lcktry							; Couldn't get it...
			li		r3,1							; return true 
			.globl  EXT(hwllckPatch_isync)
LEXT(hwllckPatch_isync)   
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
			and.	r3,r3,r12						; Is it free yet?
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
			bf		hwtimeout,lckpanic
			li		r3,0							; Set failure return code
			blr										; Return, head hanging low...
lckpanic:
			mr		r4,r5
			mr		r5,r3
			lis		r3,hi16(lckpanic_str)			; Get the failed lck message
			ori		r3,r3,lo16(lckpanic_str)		; Get the failed lck message
			bl		EXT(panic)
			BREAKPOINT_TRAP							; We die here anyway
			.data
lckpanic_str:
			STRINGD	"timeout on attempt to acquire lock (0x%08X), value = 0x%08X\n\000"
			.text

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

			b		epStart							; Go enable preemption...

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
			.globl  EXT(hwlmlckPatch_isync)
LEXT(hwlmlckPatch_isync)   
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
			
			.globl  EXT(hwltlckPatch_isync)
LEXT(hwltlckPatch_isync)   
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
			.globl  EXT(hwcsatomicPatch_isync)
LEXT(hwcsatomicPatch_isync)   
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
 *          NOTE: OSEnqueueAtomic() is aliased to this, see xnu/libkern/Makefile
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
 *
 *          NOTE: OSDequeueAtomic() is aliased to this, see xnu/libkern/Makefile
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
 * Routines for mutex lock debugging.
 */

/* 
 * Gets lock check flags in CR6: CR bits 24-27
 */
#define CHECK_SETUP(rg)											\
			lbz		rg,lglcksWork(0)				__ASMNL__ 	\
			mtcrf	2,rg							__ASMNL__ 


/*
 * Checks for expected lock type.
 */
#define	CHECK_MUTEX_TYPE()										\
			bf		MUTEX_ATTR_DEBUGb,1f			__ASMNL__	\
			bt		24+disLktypeb,1f				__ASMNL__ 	\
			lwz		r10,MUTEX_TYPE(r3)				__ASMNL__ 	\
			cmpwi	r10,MUTEX_TAG					__ASMNL__	\
			beq++	1f								__ASMNL__	\
			PROLOG(0)								__ASMNL__	\
			mr		r4,r11							__ASMNL__	\
			mr		r5,r10							__ASMNL__	\
			lis		r3,hi16(not_a_mutex)			__ASMNL__	\
			ori		r3,r3,lo16(not_a_mutex)			__ASMNL__	\
			bl		EXT(panic)						__ASMNL__	\
			BREAKPOINT_TRAP							__ASMNL__	\
1:

	.data
not_a_mutex:
			STRINGD	"mutex (0x%08X) not a mutex type (0x%08X)\n\000"
			.text

/* 
 * Verifies return to the correct thread in "unlock" situations.
 */
#define CHECK_THREAD(thread_offset)								\
			bf		MUTEX_ATTR_DEBUGb,3f			__ASMNL__	\
			bt		24+disLkThreadb,3f				__ASMNL__ 	\
			mfsprg	r10,1							__ASMNL__	\
			lwz		r5,MUTEX_DATA(r3)				__ASMNL__	\
			rlwinm.	r9,r5,0,0,29					__ASMNL__	\
			bne++	1f								__ASMNL__	\
			lis		r3,hi16(not_held) 				__ASMNL__	\
			ori		r3,r3,lo16(not_held)			__ASMNL__ 	\
			b		2f								__ASMNL__	\
1:													__ASMNL__	\
			cmpw	r9,r10	 						__ASMNL__ 	\
			beq++	3f 								__ASMNL__ 	\
			mr		r5,r10							__ASMNL__	\
			mr		r6,r9							__ASMNL__	\
			lis		r3,hi16(wrong_thread) 			__ASMNL__	\
			ori		r3,r3,lo16(wrong_thread)		__ASMNL__ 	\
2:													__ASMNL__	\
			mr		r4,r11							__ASMNL__	\
			PROLOG(0)								__ASMNL__	\
			bl		EXT(panic)	 					__ASMNL__ 	\
			BREAKPOINT_TRAP							__ASMNL__	\
3:

	.data
not_held:
	STRINGD	"mutex (0x%08X) not held\n\000"
wrong_thread:
	STRINGD	"mutex (0x%08X) unlocked by non-owner(0x%08X), current owner(0x%08X)\n\000"
	.text

#define CHECK_MYLOCK()											\
			bf		MUTEX_ATTR_DEBUGb,1f			__ASMNL__	\
			bt		24+disLkMyLckb,1f				__ASMNL__ 	\
			mfsprg	r10,1							__ASMNL__	\
			lwz		r9,MUTEX_DATA(r3)				__ASMNL__	\
			rlwinm	r9,r9,0,0,29					__ASMNL__	\
			cmpw	r9,r10	 						__ASMNL__	\
			bne++	1f 								__ASMNL__	\
			mr		r4,r11							__ASMNL__	\
			lis		r3,	hi16(mylock_attempt)		__ASMNL__	\
			ori		r3,r3,lo16(mylock_attempt)		__ASMNL__	\
			bl		EXT(panic)	 					__ASMNL__	\
			BREAKPOINT_TRAP							__ASMNL__	\
1:	
	
	.data
mylock_attempt:
	STRINGD	"mutex (0x%08X) recursive lock attempt\n\000"
	.text

#define	LCK_STACK(lck, stack, lck_stack, frame_cnt, lr_save, tmp)		\
			bf		24+enaLkExtStckb,3f				__ASMNL__ 	\
			addi	lck_stack,lck,MUTEX_STACK		__ASMNL__	\
			li		frame_cnt,MUTEX_FRAMES-1		__ASMNL__	\
1:													__ASMNL__	\
			mr		tmp,stack						__ASMNL__	\
			lwz		stack,0(stack)					__ASMNL__	\
			xor		tmp,stack,tmp					__ASMNL__	\
			cmplwi	tmp,8192						__ASMNL__	\
			bge--	2f								__ASMNL__	\
			lwz		lr_save,FM_LR_SAVE(stack)		__ASMNL__	\
			stwu	lr_save,4(lck_stack)			__ASMNL__	\
			subi	frame_cnt,frame_cnt,1			__ASMNL__	\
			cmpi	cr0,frame_cnt,0					__ASMNL__	\
			bne		1b								__ASMNL__	\
			b		3f								__ASMNL__	\
2:													__ASMNL__	\
			li		tmp,0							__ASMNL__	\
			stwu	tmp,4(lck_stack)				__ASMNL__	\
			subi	frame_cnt,frame_cnt,1			__ASMNL__	\
			cmpi	cr0,frame_cnt,0					__ASMNL__	\
			bne		2b								__ASMNL__	\
3:	

/*
 *		void mutex_init(mutex_t* l, etap_event_t etap)
 *
 */
			.align	5
			.globl	EXT(mutex_init)
LEXT(mutex_init)

			PROLOG(0)
			li		r10,0
			stw		r10,MUTEX_DATA(r3)				; clear lock word
			sth		r10,MUTEX_WAITERS(r3)			; init waiter count
			sth		r10,MUTEX_PROMOTED_PRI(r3)
#if	MACH_LDEBUG
			li		r11,MUTEX_ATTR_DEBUG
			stw		r10,MUTEX_STACK(r3)				; init caller pc
			stw		r10,MUTEX_THREAD(r3)			; and owning thread
			li		r9,	MUTEX_TAG
			stw		r9,	MUTEX_TYPE(r3)				; set lock type
			stw		r11,MUTEX_ATTR(r3)
			addi	r8,r3,MUTEX_STACK-4
			li		r9,MUTEX_FRAMES
mlistck:
			stwu	r10,4(r8)						; init stack
			subi	r9,r9,1
			cmpi	cr0,r9,0
			bne		mlistck
#endif	/* MACH_LDEBUG */
			EPILOG
			blr

/*
 *		void lck_mtx_lock_ext(lck_mtx_ext_t*)
 *
 */
			.align	5
			.globl	EXT(lck_mtx_lock_ext)
LEXT(lck_mtx_lock_ext)
#if	MACH_LDEBUG
			.globl	EXT(mutex_lock)
LEXT(mutex_lock)

			.globl	EXT(_mutex_lock)
LEXT(_mutex_lock)
#endif
			mr		r11,r3							; Save lock addr
mlckeEnter:
			lwz		r0,MUTEX_ATTR(r3)
			mtcrf	1,r0							; Set cr7
			CHECK_SETUP(r12)	
			CHECK_MUTEX_TYPE()

			bf		MUTEX_ATTR_DEBUGb,L_mutex_lock_assert_wait_2
			PROLOG(0)
			bl		EXT(assert_wait_possible)
			mr.		r3,r3
			bne		L_mutex_lock_assert_wait_1
			lis		r3,hi16(L_mutex_lock_assert_wait_panic_str)
			ori		r3,r3,lo16(L_mutex_lock_assert_wait_panic_str)
			bl		EXT(panic)
			BREAKPOINT_TRAP							; We die here anyway

			.data
L_mutex_lock_assert_wait_panic_str:
			STRINGD "mutex lock attempt with  assert_wait_possible false\n\000" 
			.text

L_mutex_lock_assert_wait_1:
			lwz		r3,FM_ARG0(r1)
			lwz		r11,FM_ARG0+0x04(r1)
			lwz		r2,(FM_ALIGN(0)+FM_SIZE+FM_CR_SAVE)(r1)
			mtcr	r2
			EPILOG
L_mutex_lock_assert_wait_2:

			mfsprg	r6,1							; load the current thread
			bf		MUTEX_ATTR_STATb,mlckestatskip	; Branch if no stat
			lwz		r5,MUTEX_GRP(r3)				; Load lock group
			li		r7,GRP_MTX_STAT_UTIL+4			; Set stat util offset
mlckestatloop:
			lwarx	r8,r7,r5						; Load stat util cnt
			addi	r8,r8,1							; Increment stat util cnt
			stwcx.	r8,r7,r5						; Store stat util cnt
			bne--	mlckestatloop					; Retry if failed
			mr.		r8,r8							; Test for zero
			bne++	mlckestatskip					; Did stat util cnt wrapped?
			lwz		r8,GRP_MTX_STAT_UTIL(r5)		; Load upper stat util cnt
			addi	r8,r8,1							; Increment upper stat util cnt
			stw		r8,GRP_MTX_STAT_UTIL(r5)		; Store upper stat util cnt
mlckestatskip:
			lwz		r5,MUTEX_DATA(r3)				; Get the lock quickly
			li		r4,0
			li		r8,0
			lis		r0,hi16(MASK(MSR_VEC))			; Get vector enable
			mfmsr	r9								; Get the MSR value
			ori		r0,r0,lo16(MASK(MSR_FP))		; Get FP enable
			ori		r7,r0,lo16(MASK(MSR_EE))		; Get EE bit on too
			andc	r9,r9,r0						; Clear FP and VEC
			andc	r7,r9,r7						; Clear EE as well
			mtmsr	r7								; Turn off interruptions 
			isync									; May have turned off vec and fp here 
			mr.		r5,r5							; Quick check
			bne--	mlckespin01						; Can not get it right now...

mlcketry:
			lwarx	r5,MUTEX_DATA,r3				; load the mutex lock
			mr.		r5,r5
			bne--	mlckespin0						; Can not get it right now...
			stwcx.	r6,MUTEX_DATA,r3				; grab the lock
			bne--	mlcketry						; loop back if failed
			.globl	EXT(mlckePatch_isync)
LEXT(mlckePatch_isync)
			isync									; stop prefeteching
			mflr	r12
			bf		MUTEX_ATTR_DEBUGb,mlckedebskip
			mr		r8,r6							; Get the active thread
			stw		r12,MUTEX_STACK(r3)				; Save our caller
			stw		r8,MUTEX_THREAD(r3)				; Set the mutex's holding thread
			mr		r5,r1
			LCK_STACK(r3,r5,r6,r7,r8,r10)
mlckedebskip:
			mtmsr	r9								; Say, any interrupts pending?
			blr

mlckespin0:
			li		r5,lgKillResv					; Killing field
			stwcx.	r5,0,r5							; Kill reservation
mlckespin01:
			mflr	r12
			mtmsr	r9								; Say, any interrupts pending?
			bl		mlckspin1	
			mtmsr	r7								; Turn off interruptions, vec and fp off already
			mtlr	r12
			b		mlcketry

/*
 *		void lck_mtx_lock(lck_mtx_t*)
 *
 */
			.align	5
			.globl	EXT(lck_mtx_lock)
LEXT(lck_mtx_lock)

#if	!MACH_LDEBUG
			.globl	EXT(mutex_lock)
LEXT(mutex_lock)

			.globl	EXT(_mutex_lock)
LEXT(_mutex_lock)
#endif

			mfsprg	r6,1							; load the current thread
			lwz		r5,MUTEX_DATA(r3)				; Get the lock quickly
			mr		r11,r3							; Save lock addr
			li		r4,0
			li		r8,0
			li		r9,0
			mr.		r5,r5							; Quick check
			bne--	mlckspin00						; Indirect or Can not get it right now...

mlcktry:
			lwarx	r5,MUTEX_DATA,r3				; load the mutex lock
			mr.		r5,r5
			bne--	mlckspin01						; Can not get it right now...
			stwcx.	r6,MUTEX_DATA,r3				; grab the lock
			bne--	mlcktry							; loop back if failed
			.globl	EXT(mlckPatch_isync)
LEXT(mlckPatch_isync)
			isync									; stop prefeteching
			blr

mlckspin00:
			cmpli	cr0,r5,MUTEX_IND				; Is it a mutex indirect 
			bne--	mlckspin02						; No, go handle contention 
			lwz		r3,MUTEX_PTR(r3)				; load mutex ext pointer
			b		mlckeEnter
mlckspin01:
			li		r5,lgKillResv					; Killing field
			stwcx.	r5,0,r5							; Kill reservation
mlckspin02:
			mflr	r12
			li		r0,0
			mtcrf	1,r0							; Set cr7 to zero
			bl		mlckspin1
			mtlr	r12
			b		mlcktry


mlckspin1:
			mr.		r4,r4							; Test timeout value
			bne++	mlckspin2
			lis		r4,hi16(EXT(MutexSpin))			; Get the high part 
			ori		r4,r4,lo16(EXT(MutexSpin)	)	; And the low part
			lwz		r4,0(r4)						; Get spin timerout value
			mr.		r4,r4							; Test spin timeout value
			bne++	mlckspin2						; Is spin timeout requested
			crclr	mlckmiss						; Clear miss test
			b		mlckslow1						; Don't try to spin

mlckspin2:	mr.		r8,r8							; Is r8 set to zero
			bne++	mlckspin3						; If yes, first spin attempt
			crclr	mlckmiss						; Clear miss test
			mr.		r9,r9							; Is r9 set to zero
			bne++	mlckspin3						; If yes, r9 set with  msr value
			lis		r0,hi16(MASK(MSR_VEC))			; Get vector enable
			mfmsr	r9								; Get the MSR value
			ori		r0,r0,lo16(MASK(MSR_FP))		; Get FP enable
			ori		r7,r0,lo16(MASK(MSR_EE))		; Get EE bit on too
			andc	r9,r9,r0						; Clear FP and VEC
			andc	r7,r9,r7						; Clear EE as well
			mtmsr	r7								; Turn off interruptions 
			isync									; May have turned off vec and fp here 
			mftb	r8								; Get timestamp on entry
			b		mlcksniff

mlckspin3:	mtmsr	r7								; Turn off interruptions 
			mftb	r8								; Get timestamp on entry

mlcksniff:	lwz		r5,MUTEX_DATA(r3)				; Get that lock in here
			mr.		r5,r5							; Is the lock held
			beq++	mlckretry						; No, try for it again...
			rlwinm.	r10,r5,0,0,29					; Extract the lock owner
			beq++	mlckslow0						; InterLock is held
			bf		MUTEX_ATTR_STATb,mlStatSkip		; Branch if no stat
			andi.	r5,r5,ILK_LOCKED				; extract interlocked?
			bne		mlStatSkip						; yes, skip
			bt		mlckmiss,mlStatSkip				; miss already counted
			crset	mlckmiss						; Remember miss recorded
			lwz		r5,MUTEX_GRP(r3)				; Load lock group
			addi	r5,r5,GRP_MTX_STAT_MISS+4			; Add stat miss offset
mlStatLoop:
			lwarx	r6,0,r5							; Load stat miss cnt
			addi	r6,r6,1							; Increment stat miss cnt
			stwcx.	r6,0,r5							; Update stat miss cnt
			bne--	mlStatLoop						; Retry if failed
			mfsprg	r6,1							; Reload current thread
mlStatSkip:
			lwz		r2,ACT_MACT_SPF(r10)			; Get the special flags
			rlwinm. r2,r2,0,OnProcbit,OnProcbit 	; Is OnProcbit set?
			beq		mlckslow0						; Lock owner isn't running
			lis		r2,hi16(TH_OPT_DELAYIDLE)		; Get DelayedIdle Option
			ori		r2,r2,lo16(TH_OPT_DELAYIDLE)	; Get DelayedIdle Option
			lwz		r10,THREAD_OPTIONS(r10)			; Get the thread options
			and.	r10,r10,r2						; Is DelayedIdle set?
			bne		mlckslow0						; Lock owner is in delay idle

			mftb	r10								; Time stamp us now
			sub		r10,r10,r8						; Get the elapsed time
			cmplwi	r10,128							; Have we been spinning for 128 tb ticks?
			blt++	mlcksniff						; Not yet...
			
			mtmsr	r9								; Say, any interrupts pending?

;			The following instructions force the pipeline to be interlocked to that only one
;			instruction is issued per cycle.  The insures that we stay enabled for a long enough
;			time; if it's too short, pending interruptions will not have a chance to be taken

			subi	r4,r4,128						; Back off elapsed time from timeout value
			or		r4,r4,r4						; Do nothing here but force a single cycle delay
			mr.		r4,r4							; See if we used the whole timeout
			or		r4,r4,r4						; Do nothing here but force a single cycle delay
			
			ble--	mlckslow1						; We failed
			b		mlckspin3						; Now that we've opened an enable window, keep trying...
mlckretry:
			mtmsr	r9								; Restore interrupt state
			li		r8,1							; Show already through once
			blr	

mlckslow0:											; We couldn't get the lock
			mtmsr	r9								; Restore interrupt state

mlckslow1:
			mtlr	r12

			PROLOG(0)
.L_ml_retry:
			bl		lockDisa						; Go get a lock on the mutex's interlock lock
			mr.		r4,r3							; Did we get it?
			lwz		r3,FM_ARG0(r1)					; Restore the lock address
			bne++	mlGotInt						; We got it just fine...
			mr		r4,r11							; Saved lock addr
			lis		r3,hi16(mutex_failed1)			; Get the failed mutex message
			ori		r3,r3,lo16(mutex_failed1)		; Get the failed mutex message
			bl		EXT(panic)						; Call panic
			BREAKPOINT_TRAP							; We die here anyway, can not get the lock
	
			.data
mutex_failed1:
			STRINGD	"attempt to interlock mutex (0x%08X) failed on mutex lock\n\000"
			.text
			
mlGotInt:
			
;			Note that there is no reason to do a load and reserve here.  We already
;			hold the interlock lock and no one can touch this field unless they 
;			have that, so, we're free to play

			lwz		r4,MUTEX_DATA(r3)				; Get the mutex's lock field
			rlwinm.	r9,r4,30,2,31					; So, can we have it?
			bne-	mlInUse							; Nope, sombody's playing already...

			bf++		MUTEX_ATTR_DEBUGb,mlDebSkip
			CHECK_SETUP(r5)
			mfsprg	r9,1							; Get the current activation
			lwz		r5,0(r1)						; Get previous save frame
			lwz		r6,FM_LR_SAVE(r5)				; Get our caller's address
			mr		r8,r9							; Get the active thread
			stw		r6,MUTEX_STACK(r3)				; Save our caller
			stw		r8,MUTEX_THREAD(r3)				; Set the mutex's holding thread
			LCK_STACK(r3,r5,r6,r7,r8,r10)
mlDebSkip:
			mr		r3,r11							; Get the based lock address
			bl	EXT(lck_mtx_lock_acquire)
			lwz		r2,(FM_ALIGN(0)+FM_SIZE+FM_CR_SAVE)(r1)
			mfsprg	r5,1
			mtcr	r2
			mr.		r4,r3
			lwz		r3,FM_ARG0(r1)					; restore r3 (saved in prolog)
			lwz		r11,FM_ARG0+0x04(r1)			; restore r11 (saved in prolog)
			beq		mlUnlock
			ori		r5,r5,WAIT_FLAG

mlUnlock:	eieio	
			stw	r5,MUTEX_DATA(r3)					; grab the mutexlock and free the interlock

			EPILOG									; Restore all saved registers
			b		epStart							; Go enable preemption...

;			We come to here when we have a resource conflict.  In other words,
;			the mutex is held.

mlInUse:

			CHECK_SETUP(r12)	
			CHECK_MYLOCK()							; Assert we don't own the lock already */

;			Note that we come in here with the interlock set.  The wait routine
;			will unlock it before waiting.

			bf		MUTEX_ATTR_STATb,mlStatSkip2	; Branch if no stat
			lwz		r5,MUTEX_GRP(r3)				; Load lck group
			bt		mlckmiss,mlStatSkip1			; Skip miss already counted
			crset	mlckmiss						; Remember miss recorded
			li		r9,GRP_MTX_STAT_MISS+4			; Get stat miss offset
mlStatLoop1:
			lwarx	r8,r9,r5						; Load stat miss cnt
			addi	r8,r8,1							; Increment stat miss cnt	
			stwcx.	r8,r9,r5						; Store stat miss cnt
			bne--	mlStatLoop1						; Retry if failed
mlStatSkip1:
			lwz		r9,GRP_MTX_STAT_WAIT+4(r5)		; Load wait cnt
			addi	r9,r9,1							; Increment wait cnt
			stw		r9,GRP_MTX_STAT_WAIT+4(r5)		; Update miss cnt
mlStatSkip2:
			ori		r4,r4,WAIT_FLAG					; Set the wait flag
			stw		r4,MUTEX_DATA(r3)
			rlwinm	r4,r4,0,0,29					; Extract the lock owner
			mfcr	r2
			stw		r2,(FM_ALIGN(0)+FM_SIZE+FM_CR_SAVE)(r1)
			mr		r3,r11							; Get the based lock address
			bl		EXT(lck_mtx_lock_wait)			; Wait for our turn at the lock
			
			lwz		r3,FM_ARG0(r1)					; restore r3 (saved in prolog)
			lwz		r11,FM_ARG0+0x04(r1)			; restore r11 (saved in prolog)
			lwz		r2,(FM_ALIGN(0)+FM_SIZE+FM_CR_SAVE)(r1)
			mtcr	r2
			b		.L_ml_retry						; and try again...

	
/*
 *		void lck_mtx_try_lock(_extlck_mtx_ext_t*)
 *
 */
			.align	5
			.globl	EXT(lck_mtx_try_lock_ext)
LEXT(lck_mtx_try_lock_ext)
#if	MACH_LDEBUG
			.globl	EXT(mutex_try)
LEXT(mutex_try)
			.globl	EXT(_mutex_try)
LEXT(_mutex_try)
#endif
			mr		r11,r3							; Save lock addr
mlteEnter:
			lwz		r0,MUTEX_ATTR(r3)
			mtcrf	1,r0							; Set cr7
			CHECK_SETUP(r12)	
			CHECK_MUTEX_TYPE()
			
			bf		MUTEX_ATTR_STATb,mlteStatSkip	; Branch if no stat
			lwz		r5,MUTEX_GRP(r3)				; Load lock group
			li		r7,GRP_MTX_STAT_UTIL+4			; Set stat util offset
mlteStatLoop:
			lwarx	r8,r7,r5						; Load stat util cnt
			addi	r8,r8,1							; Increment stat util cnt
			stwcx.	r8,r7,r5						; Store stat util cnt
			bne--	mlteStatLoop					; Retry if failed
			mr.		r8,r8							; Test for zero
			bne++	mlteStatSkip					; Did stat util cnt wrapped?
			lwz		r8,GRP_MTX_STAT_UTIL(r5)		; Load upper stat util cnt
			addi	r8,r8,1							; Increment upper stat util cnt
			stw		r8,GRP_MTX_STAT_UTIL(r5)		; Store upper stat util cnt
mlteStatSkip:
			mfsprg	r6,1							; load the current thread
			lwz		r5,MUTEX_DATA(r3)				; Get the lock value
			mr.		r5,r5							; Quick check
			bne--	L_mutex_try_slow				; Can not get it now...
			mfmsr	r9								; Get the MSR value
			lis		r0,hi16(MASK(MSR_VEC))			; Get vector enable
			ori		r0,r0,lo16(MASK(MSR_FP))		; Get FP enable
			ori		r7,r0,lo16(MASK(MSR_EE))		; Get EE bit on too
			andc	r9,r9,r0						; Clear FP and VEC
			andc	r7,r9,r7						; Clear EE as well
			mtmsr	r7								; Turn off interruptions 
			isync									; May have turned off vec and fp here 

mlteLoopTry:
			lwarx	r5,MUTEX_DATA,r3				; load the lock value
			mr.		r5,r5
			bne--	mlteSlowX						; branch to the slow path
			stwcx.	r6,MUTEX_DATA,r3				; grab the lock
			bne--	mlteLoopTry						; retry if failed
			.globl	EXT(mltelckPatch_isync)
LEXT(mltelckPatch_isync)
			isync									; stop prefetching
			mflr	r12
			bf		MUTEX_ATTR_DEBUGb,mlteDebSkip
			mr		r8,r6							; Get the active thread
			stw		r12,MUTEX_STACK(r3)				; Save our caller
			stw		r8,MUTEX_THREAD(r3)				; Set the mutex's holding thread
			mr		r5,r1
			LCK_STACK(r3,r5,r6,r7,r8,r10)
mlteDebSkip:
			li		r3, 1
			mtmsr	r9								; Say, any interrupts pending?
			blr
mlteSlowX:
			li		r5,lgKillResv					; Killing field
			stwcx.	r5,0,r5							; Kill reservation
			mtmsr	r9								; Say, any interrupts pending?
			b		L_mutex_try_slow


/*
 *		void lck_mtx_try_lock(lck_mtx_t*)
 *
 */
			.align	5
			.globl	EXT(lck_mtx_try_lock)
LEXT(lck_mtx_try_lock)
#if	!MACH_LDEBUG
			.globl	EXT(mutex_try)
LEXT(mutex_try)
			.globl	EXT(_mutex_try)
LEXT(_mutex_try)
#endif

			mfsprg	r6,1							; load the current thread
			lwz		r5,MUTEX_DATA(r3)				; Get the lock value
			mr		r11,r3							; Save lock addr
			mr.		r5,r5							; Quick check
			bne--	mltSlow00						; Indirect or Can not get it now...

mltLoopTry:
			lwarx	r5,MUTEX_DATA,r3				; load the lock value
			mr.		r5,r5
			bne--	mltSlow01						; branch to the slow path
			stwcx.	r6,MUTEX_DATA,r3				; grab the lock
			bne--	mltLoopTry						; retry if failed
			.globl	EXT(mltlckPatch_isync)
LEXT(mltlckPatch_isync)
			isync									; stop prefetching
			li		r3, 1
			blr

mltSlow00:
			cmpli	cr0,r5,MUTEX_IND				; Is it a mutex indirect 
			bne--	mltSlow02						; No, go handle contention 
			lwz		r3,MUTEX_PTR(r3)				; load mutex ext pointer
			b		mlteEnter
mltSlow01:
			li		r5,lgKillResv					; Killing field
			stwcx.	r5,0,r5							; Kill reservation

mltSlow02:
			li		r0,0
			mtcrf	1,r0							; Set cr7 to zero

L_mutex_try_slow:
			PROLOG(0)
	
			lwz		r6,MUTEX_DATA(r3)				; Quick check
			rlwinm.	r6,r6,30,2,31					; to see if someone has this lock already
			bne-	mtFail							; Someone's got it already...

			bl		lockDisa						; Go get a lock on the mutex's interlock lock
			mr.		r4,r3							; Did we get it?
			lwz		r3,FM_ARG0(r1)					; Restore the lock address
			bne++	mtGotInt						; We got it just fine...
			mr		r4,r11							; Saved lock addr
			lis		r3,hi16(mutex_failed2)			; Get the failed mutex message
			ori		r3,r3,lo16(mutex_failed2)		; Get the failed mutex message
			bl		EXT(panic)						; Call panic
			BREAKPOINT_TRAP							; We die here anyway, can not get the lock
	
			.data
mutex_failed2:
			STRINGD	"attempt to interlock mutex (0x%08X) failed on mutex lock try\n\000"
			.text
			
mtGotInt:
			
;			Note that there is no reason to do a load and reserve here.  We already
;			hold the interlock and no one can touch at this field unless they 
;			have that, so, we're free to play 
			
			lwz		r4,MUTEX_DATA(r3)				; Get the mutex's lock field
			rlwinm.	r9,r4,30,2,31					; So, can we have it?
			bne-	mtInUse							; Nope, sombody's playing already...
			
			bf++	MUTEX_ATTR_DEBUGb,mtDebSkip
			CHECK_SETUP(r5)
			mfsprg	r9,1							; Get the current activation
			lwz		r5,0(r1)						; Get previous save frame
			lwz		r6,FM_LR_SAVE(r5)				; Get our caller's address
			mr		r8,r9							; Get the active thread
			stw		r6,MUTEX_STACK(r3)				; Save our caller
			stw		r8,MUTEX_THREAD(r3)				; Set the mutex's holding thread
			LCK_STACK(r3,r5,r6,r7,r8,r10)
mtDebSkip:
			mr		r3,r11							; Get the based lock address
			bl	EXT(lck_mtx_lock_acquire)
			mfsprg	r5,1
			mr.		r4,r3
			lwz		r3,FM_ARG0(r1)					; restore r3 (saved in prolog)
			lwz		r11,FM_ARG0+0x04(r1)			; restore r11 (saved in prolog)
			beq		mtUnlock
			ori		r5,r5,WAIT_FLAG

mtUnlock:	eieio
			stw	r5,MUTEX_DATA(r3)					; grab the mutexlock and free the interlock

			bl		epStart							; Go enable preemption...

			li		r3, 1
			EPILOG									; Restore all saved registers
			blr										; Return...

;			We come to here when we have a resource conflict.  In other words,
;			the mutex is held.

mtInUse:	
			bf++	MUTEX_ATTR_STATb,mtStatSkip		; Branch if no stat
			lwz		r5,MUTEX_GRP(r3)				; Load lock group
			li		r9,GRP_MTX_STAT_MISS+4			; Get stat miss offset
mtStatLoop:
			lwarx	r8,r9,r5						; Load stat miss cnt
			addi	r8,r8,1							; Increment stat miss cnt	
			stwcx.	r8,r9,r5						; Store stat miss cnt
			bne--	mtStatLoop						; Retry if failed
mtStatSkip:
			rlwinm	r4,r4,0,0,30					; Get the unlock value
			stw		r4,MUTEX_DATA(r3)				; free the interlock
			bl		epStart							; Go enable preemption...

mtFail:		li		r3,0							; Set failure code
			EPILOG									; Restore all saved registers
			blr										; Return...

		
/*
 *		void mutex_unlock(mutex_t* l)
 *
 */
			.align	5
			.globl	EXT(mutex_unlock)
LEXT(mutex_unlock)

			sync
			mr		r11,r3							; Save lock addr
#if	MACH_LDEBUG
			b		mlueEnter1
#else
			b		mluEnter1
#endif

/*
 *		void lck_mtx_ext_unlock(lck_mtx_ext_t* l)
 *
 */
			.align	5
			.globl	EXT(lck_mtx_ext_unlock)
LEXT(lck_mtx_ext_unlock)
#if	MACH_LDEBUG
			.globl	EXT(mutex_unlock_rwcmb)
LEXT(mutex_unlock_rwcmb)
#endif
mlueEnter:
			.globl	EXT(mulckePatch_isync)
LEXT(mulckePatch_isync)
			isync
			.globl	EXT(mulckePatch_eieio)     
LEXT(mulckePatch_eieio)
			eieio
			mr		r11,r3							; Save lock addr
mlueEnter1:
			lwz		r0,MUTEX_ATTR(r3)
			mtcrf	1,r0							; Set cr7
			CHECK_SETUP(r12)	
			CHECK_MUTEX_TYPE()
			CHECK_THREAD(MUTEX_THREAD)

			lwz		r5,MUTEX_DATA(r3)				; Get the lock
			rlwinm.	r4,r5,0,30,31					; Quick check
			bne--	L_mutex_unlock_slow				; Can not get it now...
			mfmsr	r9								; Get the MSR value
			lis		r0,hi16(MASK(MSR_VEC))			; Get vector enable
			ori		r0,r0,lo16(MASK(MSR_FP))		; Get FP enable
			ori		r7,r0,lo16(MASK(MSR_EE))		; Get EE bit on too
			andc	r9,r9,r0						; Clear FP and VEC
			andc	r7,r9,r7						; Clear EE as well
			mtmsr	r7								; Turn off interruptions 
			isync									; May have turned off vec and fp here 

mlueLoop:
			lwarx	r5,MUTEX_DATA,r3
			rlwinm.	r4,r5,0,30,31					; Bail if pending waiter or interlock set
			li		r5,0							; Clear the mutexlock
			bne--	mlueSlowX
			stwcx.	r5,MUTEX_DATA,r3
			bne--	mlueLoop
			mtmsr	r9								; Say, any interrupts pending?
			blr

mlueSlowX:
			li		r5,lgKillResv					; Killing field
			stwcx.	r5,0,r5							; Dump reservation
			mtmsr	r9								; Say, any interrupts pending?
			b		L_mutex_unlock_slow				; Join slow path...

/*
 *		void lck_mtx_unlock(lck_mtx_t* l)
 *
 */
			.align	5
			.globl	EXT(lck_mtx_unlock)
LEXT(lck_mtx_unlock)
#if	!MACH_LDEBUG
			.globl	EXT(mutex_unlock_rwcmb)
LEXT(mutex_unlock_rwcmb)
#endif
mluEnter:
			.globl	EXT(mulckPatch_isync)
LEXT(mulckPatch_isync)
			isync
			.globl	EXT(mulckPatch_eieio)     
LEXT(mulckPatch_eieio)
			eieio
			mr		r11,r3							; Save lock addr
mluEnter1:
			lwz		r5,MUTEX_DATA(r3)				; Get the lock
			rlwinm.	r4,r5,0,30,31					; Quick check
			bne--	mluSlow0						; Indirect or Can not get it now...

mluLoop:
			lwarx	r5,MUTEX_DATA,r3
			rlwinm.	r4,r5,0,30,31					; Bail if pending waiter or interlock set
			li		r5,0							; Clear the mutexlock
			bne--	mluSlowX
			stwcx.	r5,MUTEX_DATA,r3
			bne--	mluLoop
			blr

mluSlow0:
			cmpli	cr0,r5,MUTEX_IND				; Is it a mutex indirect 
			bne--	L_mutex_unlock_slow				; No, go handle contention 
			lwz		r3,MUTEX_PTR(r3)				; load mutex ext pointer
			b		mlueEnter1
mluSlowX:
			li		r5,lgKillResv					; Killing field
			stwcx.	r5,0,r5							; Dump reservation

L_mutex_unlock_slow:
			
			PROLOG(0)
	
			bl		lockDisa						; Go get a lock on the mutex's interlock lock
			mr.		r4,r3							; Did we get it?
			lwz		r3,FM_ARG0(r1)					; Restore the lock address
			bne++	muGotInt						; We got it just fine...
			mr		r4,r11							; Saved lock addr
			lis		r3,hi16(mutex_failed3)			; Get the failed mutex message
			ori		r3,r3,lo16(mutex_failed3)		; Get the failed mutex message
			bl		EXT(panic)						; Call panic
			BREAKPOINT_TRAP							; We die here anyway, can not get the lock
	
			.data
mutex_failed3:
			STRINGD	"attempt to interlock mutex (0x%08X) failed on mutex unlock\n\000"
			.text
			
			
muGotInt:
			lwz		r4,MUTEX_DATA(r3)
			andi.	r5,r4,WAIT_FLAG					; are there any waiters ?
			rlwinm	r4,r4,0,0,29
			beq+	muUnlock						; Nope, we're done...

			mr		r3,r11							; Get the based lock address
			bl		EXT(lck_mtx_unlock_wakeup)		; yes, wake a thread
			lwz		r3,FM_ARG0(r1)					; restore r3 (saved in prolog)
			lwz		r11,FM_ARG0+0x04(r1)			; restore r11 (saved in prolog)
			lwz		r5,MUTEX_DATA(r3)				; load the lock

muUnlock:
			andi.	r5,r5,WAIT_FLAG					; Get the unlock value
			eieio
			stw		r5,MUTEX_DATA(r3)				; unlock the interlock and lock

			EPILOG									; Deal with the stack now, enable_preemption doesn't always want one
			b		epStart							; Go enable preemption...

/*
 *		void lck_mtx_assert(lck_mtx_t* l, unsigned int)
 *
 */
			.align	5
			.globl	EXT(lck_mtx_assert)
LEXT(lck_mtx_assert)
			.globl	EXT(_mutex_assert)
LEXT(_mutex_assert)
			mr		r11,r3
maEnter:
			lwz		r5,MUTEX_DATA(r3)
			cmpli	cr0,r5,MUTEX_IND				; Is it a mutex indirect 
			bne--	maCheck							; No, go check the assertion
			lwz		r3,MUTEX_PTR(r3)				; load mutex ext pointer
			b		maEnter
maCheck:
			mfsprg	r6,1							; load the current thread
			rlwinm	r5,r5,0,0,29					; Extract the lock owner
			cmpwi	r4,MUTEX_ASSERT_OWNED
			cmplw	cr1,r6,r5						; Is the lock held by current act
			crandc	cr0_eq,cr0_eq,cr1_eq			; Check owned assertion
			bne--	maNext
			mr		r4,r11
			lis		r3,hi16(mutex_assert1)			; Get the failed mutex message
			ori		r3,r3,lo16(mutex_assert1)		; Get the failed mutex message
			b		maPanic							; Panic path
maNext:
			cmpwi	r4,MUTEX_ASSERT_NOTOWNED		; Check not owned assertion
			crand	cr0_eq,cr0_eq,cr1_eq			;
			bnelr++
maPanic:
			PROLOG(0)
			mr		r4,r11
			lis		r3,hi16(mutex_assert2)			; Get the failed mutex message
			ori		r3,r3,lo16(mutex_assert2)		; Get the failed mutex message
			bl		EXT(panic)						; Call panic
			BREAKPOINT_TRAP							; We die here anyway

			.data
mutex_assert1:
			STRINGD	"mutex (0x%08X) not owned\n\000"
mutex_assert2:
			STRINGD	"mutex (0x%08X) owned\n\000"
			.text
			
			
/*
 *		void lck_mtx_ilk_unlock(lck_mtx *lock)
 */
			.globl	EXT(lck_mtx_ilk_unlock)
LEXT(lck_mtx_ilk_unlock)

			lwz		r10,MUTEX_DATA(r3)
			rlwinm	r10,r10,0,0,30
			eieio
			stw		r10,MUTEX_DATA(r3)

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

;		Here is where we enable preemption.

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
			PROLOG(0)
			bl		EXT(panic)
			BREAKPOINT_TRAP							; We die here anyway

			.data
epTooFarStr:
			STRINGD	"enable_preemption: preemption_level %d\n\000"

			.text
			.align	5
epCheckPreempt:
			lis		r0,hi16(MASK(MSR_VEC))			; Get vector enable
			mfmsr	r9								; Get the MSR value
			ori		r0,r0,lo16(MASK(MSR_FP))		; Get FP enable
			andi.	r4,r9,lo16(MASK(MSR_EE))		; We cannot preempt if interruptions are off
			beq+	epCPno							; No preemption here...
			ori		r7,r0,lo16(MASK(MSR_EE))		; Get EE bit on too
			andc	r9,r9,r0						; Clear FP and VEC
			andc	r7,r9,r7						; Clear EE as well
			mtmsr	r7								; Turn off interruptions 
			isync									; May have turned off vec and fp here 
			lwz		r3,ACT_PER_PROC(r3)				; Get the per_proc block
			lwz		r7,PP_PENDING_AST(r3)			; Get pending AST mask
			li		r5,AST_URGENT					; Get the requests we do honor
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
 *			Here is where we disable preemption.
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
 *		void lck_spin_lock(lck_spin_t *)
 *		void ppc_usimple_lock(simple_lock_t *)
 *
 */
			.align	5
			.globl	EXT(lck_spin_lock)
LEXT(lck_spin_lock)
			.globl	EXT(ppc_usimple_lock)
LEXT(ppc_usimple_lock)

			mfsprg	r6,1							; Get the current activation 
			lwz		r5,ACT_PREEMPT_CNT(r6)			; Get the preemption level
			addi	r5,r5,1							; Bring up the disable count
			stw		r5,ACT_PREEMPT_CNT(r6)			; Save it back 
			mr		r5,r3							; Get the address of the lock
			li		r8,0							; Set r8 to zero
			li		r4,0							; Set r4 to zero

slcktry:	lwarx	r11,SLOCK_ILK,r5				; Grab the lock value
			andi.	r3,r11,ILK_LOCKED				; Is it locked?
			ori		r11,r6,ILK_LOCKED				; Set interlock 
			bne--	slckspin						; Yeah, wait for it to clear...
			stwcx.	r11,SLOCK_ILK,r5				; Try to seize that there durn lock
			bne--	slcktry							; Couldn't get it...
			.globl  EXT(slckPatch_isync)
LEXT(slckPatch_isync)
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

slcksniff:	lwz		r3,SLOCK_ILK(r5)				; Get that lock in here
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
			PROLOG(0)
			bl		EXT(panic)
			BREAKPOINT_TRAP							; We die here anyway

		.data
slckpanic_str:
		STRINGD "simple lock (0x%08X) deadlock detection, pc=0x%08X\n\000"
		.text

/*
 *		boolean_t lck_spin_try_lock(lck_spin_t *)
 *		unsigned int ppc_usimple_lock_try(simple_lock_t *)
 *
 */
			.align	5
			.globl	EXT(lck_spin_try_lock)
LEXT(lck_spin_try_lock)
			.globl	EXT(ppc_usimple_lock_try)
LEXT(ppc_usimple_lock_try)

			lis		r0,hi16(MASK(MSR_VEC))			; Get vector enable
			mfmsr	r9								; Get the MSR value 
			ori		r0,r0,lo16(MASK(MSR_FP))		; Get FP enable
			ori		r7,r0,lo16(MASK(MSR_EE))		; Get EE bit on too
			andc	r9,r9,r0						; Clear FP and VEC
			andc	r7,r9,r7						; Clear EE as well
			mtmsr	r7								; Disable interruptions and thus, preemption
			mfsprg	r6,1							; Get current activation 

			lwz		r11,SLOCK_ILK(r3)				; Get the lock
			andi.	r5,r11,ILK_LOCKED				; Check it...
			bne--	slcktryfail						; Quickly fail...

slcktryloop:	
			lwarx	r11,SLOCK_ILK,r3				; Ld from addr of arg and reserve

			andi.	r5,r11,ILK_LOCKED				; TEST...
			ori		r5,r6,ILK_LOCKED
			bne--	slcktryfailX					; branch if taken. Predict free 
	
			stwcx.	r5,SLOCK_ILK,r3					; And SET (if still reserved)
			bne--	slcktryloop						; If set failed, loop back 
			
			.globl  EXT(stlckPatch_isync)
LEXT(stlckPatch_isync)
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
 *		void lck_spin_unlock(lck_spin_t *)
 *		void ppc_usimple_unlock_rwcmb(simple_lock_t *)
 *
 */
			.align	5
			.globl	EXT(lck_spin_unlock)
LEXT(lck_spin_unlock)
			.globl	EXT(ppc_usimple_unlock_rwcmb)
LEXT(ppc_usimple_unlock_rwcmb)

			li		r0,0
			.globl  EXT(sulckPatch_isync)
LEXT(sulckPatch_isync)
			isync
			.globl  EXT(sulckPatch_eieio)
LEXT(sulckPatch_eieio)
			eieio
			stw		r0, SLOCK_ILK(r3)

			b		epStart							; Go enable preemption...

/*
 *		void ppc_usimple_unlock_rwmb(simple_lock_t *)
 *
 */
			.align	5
			.globl	EXT(ppc_usimple_unlock_rwmb)

LEXT(ppc_usimple_unlock_rwmb)

			li		r0,0
			sync
			stw		r0, SLOCK_ILK(r3)

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
			.globl	EXT(entfsectPatch_isync)     
LEXT(entfsectPatch_isync)
			isync									; Stop prefeteching
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

/*
 *		void lck_rw_lock_exclusive(lck_rw_t*)
 *
 */
			.align	5
			.globl	EXT(lck_rw_lock_exclusive)
LEXT(lck_rw_lock_exclusive)
#if	!MACH_LDEBUG
			.globl	EXT(lock_write)
LEXT(lock_write)
#endif
rwleloop:	lwarx	r5,RW_DATA,r3					; Grab the lock value
			rlwinm.	r7,r5,30,1,31					; Can we have it?
			ori		r6,r5,WANT_EXCL					; Mark Exclusive
			bne--	rwlespin						; Branch if cannot be held
			stwcx.	r6,RW_DATA,r3					; Update lock word
			bne--	rwleloop
			.globl  EXT(rwlePatch_isync)
LEXT(rwlePatch_isync)
			isync
			blr
rwlespin:
			li		r4,lgKillResv					; Killing field
			stwcx.	r4,0,r4							; Kill it
			cmpli	cr0,r5,RW_IND					; Is it a lock indirect 
			bne--	rwlespin1						; No, go handle contention 
			mr		r4,r3							; pass lock pointer
			lwz		r3,RW_PTR(r3)					; load lock ext pointer
			b		EXT(lck_rw_lock_exclusive_ext)
rwlespin1:
			b		EXT(lck_rw_lock_exclusive_gen)

/*
 *		void lck_rw_lock_shared(lck_rw_t*)
 *
 */
			.align	5
			.globl	EXT(lck_rw_lock_shared)
LEXT(lck_rw_lock_shared)
#if	!MACH_LDEBUG
			.globl	EXT(lock_read)
LEXT(lock_read)
#endif
rwlsloop:	lwarx	r5,RW_DATA,r3					; Grab the lock value
			andi.	r7,r5,WANT_EXCL|WANT_UPGRADE|ILK_LOCKED	; Can we have it?
			addis	r6,r5,1							; Increment read cnt
			bne--	rwlsspin						; Branch if cannot be held
			stwcx.	r6,RW_DATA,r3					; Update lock word
			bne--	rwlsloop
			.globl  EXT(rwlsPatch_isync)
LEXT(rwlsPatch_isync)
			isync
			blr
rwlsspin:
			li		r4,lgKillResv					; Killing field
			stwcx.	r4,0,r4							; Kill it
			cmpli	cr0,r5,RW_IND					; Is it a lock indirect 
			bne--	rwlsspin1						; No, go handle contention 
			mr		r4,r3							; pass lock pointer
			lwz		r3,RW_PTR(r3)					; load lock ext pointer
			b		EXT(lck_rw_lock_shared_ext)
rwlsspin1:
			b		EXT(lck_rw_lock_shared_gen)

/*
 *		boolean_t lck_rw_lock_shared_to_exclusive(lck_rw_t*)
 *
 */
			.align	5
			.globl	EXT(lck_rw_lock_shared_to_exclusive)
LEXT(lck_rw_lock_shared_to_exclusive)
#if	!MACH_LDEBUG
			.globl	EXT(lock_read_to_write)
LEXT(lock_read_to_write)
#endif
rwlseloop:	lwarx	r5,RW_DATA,r3					; Grab the lock value
			addis	r6,r5,0xFFFF					; Decrement read cnt
			lis		r8,0xFFFF						; Get read count mask
			ori		r8,r8,WANT_UPGRADE|ILK_LOCKED	; Include Interlock and upgrade flags
			and.	r7,r6,r8						; Can we have it?
			ori		r9,r6,WANT_UPGRADE				; Mark Exclusive
			bne--	rwlsespin						; Branch if cannot be held
			stwcx.	r9,RW_DATA,r3					; Update lock word
			bne--	rwlseloop
			.globl  EXT(rwlsePatch_isync)
LEXT(rwlsePatch_isync)
			isync
			li		r3,0							; Succeed, return FALSE...
			blr
rwlsespin:
			li		r4,lgKillResv					; Killing field
			stwcx.	r4,0,r4							; Kill it
			cmpli	cr0,r5,RW_IND					; Is it a lock indirect 
			bne--	rwlsespin1						; No, go handle contention 
			mr		r4,r3							; pass lock pointer
			lwz		r3,RW_PTR(r3)					; load lock ext pointer
			b		EXT(lck_rw_lock_shared_to_exclusive_ext)
rwlsespin1:
			b		EXT(lck_rw_lock_shared_to_exclusive_gen)



/*
 *		void lck_rw_lock_exclusive_to_shared(lck_rw_t*)
 *
 */
			.align	5
			.globl	EXT(lck_rw_lock_exclusive_to_shared)
LEXT(lck_rw_lock_exclusive_to_shared)
#if	!MACH_LDEBUG
			.globl	EXT(lock_write_to_read)
LEXT(lock_write_to_read)
#endif
			.globl  EXT(rwlesPatch_isync)
LEXT(rwlesPatch_isync)
			isync
			.globl  EXT(rwlesPatch_eieio)
LEXT(rwlesPatch_eieio)
			eieio
rwlesloop:	lwarx	r5,RW_DATA,r3					; Grab the lock value
			andi.	r7,r5,ILK_LOCKED				; Test interlock flag
			bne--	rwlesspin						; Branch if interlocked
			lis		r6,1							; Get 1 for read count
			andi.	r10,r5,WANT_UPGRADE				; Is it held with upgrade
			li		r9,WANT_UPGRADE|WAIT_FLAG		; Get upgrade and wait flags mask
			bne		rwlesexcl1						; Skip if held with upgrade
			li		r9,WANT_EXCL|WAIT_FLAG			; Get exclusive and wait flags mask
rwlesexcl1:
			andc	r7,r5,r9						; Marked free
			rlwimi	r6,r7,0,16,31					; Set shared cnt to one
			stwcx.	r6,RW_DATA,r3					; Update lock word
			bne--	rwlesloop
			andi.	r7,r5,WAIT_FLAG					; Test wait flag
			beqlr++									; Return of no waiters
			addi	r3,r3,RW_EVENT					; Get lock event address
			b		EXT(thread_wakeup)				; wakeup waiters
rwlesspin:
			li		r4,lgKillResv					; Killing field
			stwcx.	r4,0,r4							; Kill it
			cmpli	cr0,r5,RW_IND					; Is it a lock indirect 
			bne--	rwlesspin1						; No, go handle contention 
			mr		r4,r3							; pass lock pointer
			lwz		r3,RW_PTR(r3)					; load lock ext pointer
			b		EXT(lck_rw_lock_exclusive_to_shared_ext)
rwlesspin1:
			b		EXT(lck_rw_lock_exclusive_to_shared_gen)



/*
 *		boolean_t lck_rw_try_lock_exclusive(lck_rw_t*)
 *
 */
			.align	5
			.globl	EXT(lck_rw_try_lock_exclusive)
LEXT(lck_rw_try_lock_exclusive)
			lis		r10,0xFFFF						; Load read count mask
			ori		r10,r10,WANT_EXCL|WANT_UPGRADE	; Include exclusive and upgrade flags
rwtleloop:	lwarx	r5,RW_DATA,r3					; Grab the lock value
			andi.	r7,r5,ILK_LOCKED				; Test interlock flag
			bne--	rwtlespin						; Branch if interlocked
			and.	r7,r5,r10						; Can we have it
			ori		r6,r5,WANT_EXCL					; Mark Exclusive
			bne--	rwtlefail						; 
			stwcx.	r6,RW_DATA,r3					; Update lock word
			bne--	rwtleloop
			.globl  EXT(rwtlePatch_isync)
LEXT(rwtlePatch_isync)
			isync
			li		r3,1							; Return TRUE
			blr
rwtlefail:
			li		r4,lgKillResv					; Killing field
			stwcx.	r4,0,r4							; Kill it
			li		r3,0							; Return FALSE
			blr
rwtlespin:
			li		r4,lgKillResv					; Killing field
			stwcx.	r4,0,r4							; Kill it
			cmpli	cr0,r5,RW_IND					; Is it a lock indirect 
			bne--	rwtlespin1						; No, go handle contention 
			mr		r4,r3							; pass lock pointer
			lwz		r3,RW_PTR(r3)					; load lock ext pointer
			b		EXT(lck_rw_try_lock_exclusive_ext)
rwtlespin1:
			b		EXT(lck_rw_try_lock_exclusive_gen)


/*
 *		boolean_t lck_rw_try_lock_shared(lck_rw_t*)
 *
 */
			.align	5
			.globl	EXT(lck_rw_try_lock_shared)
LEXT(lck_rw_try_lock_shared)
rwtlsloop:	lwarx	r5,RW_DATA,r3					; Grab the lock value
			andi.	r7,r5,ILK_LOCKED				; Test interlock flag
			bne--	rwtlsspin						; Branch if interlocked
			andi.	r7,r5,WANT_EXCL|WANT_UPGRADE	; So, can we have it?
			addis	r6,r5,1							; Increment read cnt
			bne--	rwtlsfail						; Branch if held exclusive
			stwcx.	r6,RW_DATA,r3					; Update lock word
			bne--	rwtlsloop
			.globl  EXT(rwtlsPatch_isync)
LEXT(rwtlsPatch_isync)
			isync
			li		r3,1							; Return TRUE
			blr
rwtlsfail:
			li		r3,0							; Return FALSE
			blr
rwtlsspin:
			li		r4,lgKillResv					; Killing field
			stwcx.	r4,0,r4							; Kill it
			cmpli	cr0,r5,RW_IND					; Is it a lock indirect 
			bne--	rwtlsspin1						; No, go handle contention 
			mr		r4,r3							; pass lock pointer
			lwz		r3,RW_PTR(r3)					; load lock ext pointer
			b		EXT(lck_rw_try_lock_shared_ext)
rwtlsspin1:
			b		EXT(lck_rw_try_lock_shared_gen)



/*
 *		lck_rw_type_t lck_rw_done(lck_rw_t*)
 *
 */
			.align	5
			.globl	EXT(lck_rw_done)
LEXT(lck_rw_done)
#if	!MACH_LDEBUG
			.globl	EXT(lock_done)
LEXT(lock_done)
#endif
			.globl  EXT(rwldPatch_isync)
LEXT(rwldPatch_isync)
			isync
			.globl  EXT(rwldPatch_eieio)
LEXT(rwldPatch_eieio)
			eieio
			li		r10,WAIT_FLAG					; Get wait flag
			lis		r7,0xFFFF						; Get read cnt mask
			mr		r12,r3							; Save lock addr
rwldloop:	lwarx	r5,RW_DATA,r3					; Grab the lock value
			andi.	r8,r5,ILK_LOCKED				; Test interlock flag
			bne--	rwldspin						; Branch if interlocked
			and.	r8,r5,r7						; Is it shared
			cmpi	cr1,r8,0						; Is it shared
			beq		cr1,rwldexcl					; No, check exclusive
			li		r11,RW_SHARED					; Set return value
			addis	r6,r5,0xFFFF					; Decrement read count
			and.	r8,r6,r7						; Is it still shared
			li		r8,0							; Assume no wakeup
			bne		rwldshared1						; Skip if still held shared
			and		r8,r6,r10						; Extract wait flag
			andc	r6,r6,r10						; Clear wait flag
rwldshared1:
			b		rwldstore
rwldexcl:
			li		r11,RW_EXCL						; Set return value
			li		r9,WANT_UPGRADE					; Get upgrade flag
			and.	r6,r5,r9						; Is it held with upgrade
			li		r9,WANT_UPGRADE|WAIT_FLAG		; Mask upgrade abd wait flags
			bne		rwldexcl1						; Skip if held with upgrade
			li		r9,WANT_EXCL|WAIT_FLAG			; Mask exclusive and wait flags
rwldexcl1:
			andc	r6,r5,r9						; Marked free
			and		r8,r5,r10						; Null if no waiter
rwldstore:
			stwcx.	r6,RW_DATA,r3					; Update lock word
			bne--	rwldloop
			mr.		r8,r8							; wakeup needed?
			mr		r3,r11							; Return lock held type
			beqlr++
			mr		r3,r12							; Restore lock address
			PROLOG(0)
			addi	r3,r3,RW_EVENT					; Get lock event address
			bl		EXT(thread_wakeup)				; wakeup threads
			lwz		r2,(FM_ALIGN(0)+FM_SIZE+FM_CR_SAVE)(r1)
			mtcr	r2
			EPILOG
			li		r3,RW_SHARED					; Assume lock type shared
			bne		cr1,rwldret						; Branch if was held exclusive
			li		r3,RW_EXCL						; Return lock type exclusive
rwldret:
			blr
rwldspin:
			li		r4,lgKillResv					; Killing field
			stwcx.	r4,0,r4							; Kill it
			cmpli	cr0,r5,RW_IND					; Is it a lock indirect 
			bne--	rwldspin1						; No, go handle contention 
			mr		r4,r3							; pass lock pointer
			lwz		r3,RW_PTR(r3)					; load lock ext pointer
			b		EXT(lck_rw_done_ext)
rwldspin1:
			b		EXT(lck_rw_done_gen)

/*
 *		void lck_rw_ilk_lock(lck_rw_t *lock)
 */
			.globl	EXT(lck_rw_ilk_lock)
LEXT(lck_rw_ilk_lock)
			crclr	hwtimeout						; no timeout option
			li		r4,0							; request default timeout value
			li		r12,ILK_LOCKED					; Load bit mask
			b		lckcomm							; Join on up...

/*
 *		void lck_rw_ilk_unlock(lck_rw_t *lock)
 */
			.globl	EXT(lck_rw_ilk_unlock)
LEXT(lck_rw_ilk_unlock)
			li		r4,1
			b		EXT(hw_unlock_bit)

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
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <cpus.h>
#include <assym.s>
#include <debug.h>
#include <mach/ppc/vm_param.h>
#include <ppc/exception.h>
	
/* PCI config cycle probing
 *
 *	boolean_t ml_probe_read(vm_offset_t paddr, unsigned int *val)
 *
 *	Read the memory location at physical address paddr.
 *  This is a part of a device probe, so there is a good chance we will
 *  have a machine check here. So we have to be able to handle that.
 *  We assume that machine checks are enabled both in MSR and HIDs
 */

;			Force a line boundry here
			.align	5
			.globl	EXT(ml_probe_read)

LEXT(ml_probe_read)

			mfsprg	r9,2							; Get feature flags
			mfmsr	r0								; Save the current MSR
			rlwinm	r0,r0,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r0,r0,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			neg		r10,r3							; Number of bytes to end of page
			rlwinm	r2,r0,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; Clear interruptions
			rlwinm.	r10,r10,0,20,31					; Clear excess junk and test for page bndry
			mr		r12,r3							; Save the load address
			mtcrf	0x04,r9							; Set the features			
			cmplwi	cr1,r10,4						; At least 4 bytes left in page?
			rlwinm	r2,r2,0,MSR_DR_BIT+1,MSR_IR_BIT-1	; Clear translation			
			beq-	mprdoit							; We are right on the boundary...
			li		r3,0
			bltlr-	cr1								; No, just return failure...

mprdoit:

			bt		pfNoMSRirb,mprNoMSR				; No MSR...

			mtmsr	r2								; Translation and all off
			isync									; Toss prefetch
			b		mprNoMSRx
			
mprNoMSR:	
			mr		r5,r0
			li		r0,loadMSR						; Get the MSR setter SC
			mr		r3,r2							; Get new MSR
			sc										; Set it
			mr		r0,r5
			li		r3,0
mprNoMSRx:

			mfspr		r6, hid0					; Get a copy of hid0
			
			rlwinm.		r5, r9, 0, pfNoMuMMCKb, pfNoMuMMCKb		; Check for NoMuMMCK
			bne		mprNoMuM
			
			rlwinm		r5, r6, 0, ice+1, ice-1				; Turn off L1 I-Cache
			mtspr		hid0, r5
			isync								; Wait for I-Cache off
			rlwinm		r5, r6, 0, mum+1, mum-1				; Turn off MuM w/ I-Cache on
			mtspr		hid0, r5
mprNoMuM:

;
;			We need to insure that there is no more than 1 BAT register that
;			can get a hit. There could be repercussions beyond the ken
;			of mortal man. It is best not to tempt fate.
;

;			Note: we will reload these from the shadow BATs later

			li		r10,0							; Clear a register
			
			sync									; Make sure all is well

			mtdbatu	1,r10							; Invalidate DBAT 1 
			mtdbatu	2,r10							; Invalidate DBAT 2 
			mtdbatu	3,r10							; Invalidate DBAT 3  
			
			rlwinm	r10,r12,0,0,14					; Round down to a 128k boundary
			ori		r11,r10,0x32					; Set uncached, coherent, R/W
			ori		r10,r10,2						; Make the upper half (128k, valid supervisor)
			mtdbatl	0,r11							; Set lower BAT first
			mtdbatu	0,r10							; Now the upper
			sync									; Just make sure
			
			dcbf	0,r12							; Make sure we kill the cache to avoid paradoxes
			sync
			
			ori		r11,r2,lo16(MASK(MSR_DR))		; Turn on data translation
			mtmsr	r11								; Do it for real
			isync									; Make sure of it
			
			eieio									; Make sure of all previous accesses
			sync									; Make sure it is all caught up
			
			lwz		r11,0(r12)						; Get it and maybe machine check here
			
			eieio									; Make sure of ordering again
			sync									; Get caught up yet again
			isync									; Do not go further till we are here
			
			mtmsr	r2								; Turn translation back off
			isync
			
			mtspr	hid0, r6							; Restore HID0
			isync
			
			lis		r10,hi16(EXT(shadow_BAT)+shdDBAT)	; Get shadow address
			ori		r10,r10,lo16(EXT(shadow_BAT)+shdDBAT)	; Get shadow address
			
			lwz		r5,0(r10)						; Pick up DBAT 0 high
			lwz		r6,4(r10)						; Pick up DBAT 0 low
			lwz		r7,8(r10)						; Pick up DBAT 1 high
			lwz		r8,16(r10)						; Pick up DBAT 2 high
			lwz		r9,24(r10)						; Pick up DBAT 3 high
			
			mtdbatu	0,r5							; Restore DBAT 0 high
			mtdbatl	0,r6							; Restore DBAT 0 low
			mtdbatu	1,r7							; Restore DBAT 1 high
			mtdbatu	2,r8							; Restore DBAT 2 high
			mtdbatu	3,r9							; Restore DBAT 3 high 
			sync
			
			li		r3,1							; We made it
			
			mtmsr	r0								; Restore translation and exceptions
			isync									; Toss speculations
			
			stw		r11,0(r4)						; Save the loaded value
			blr										; Return...
			
;			Force a line boundry here. This means we will be able to check addresses better
			.align	5
			.globl	EXT(ml_probe_read_mck)
LEXT(ml_probe_read_mck)

/* Read physical address
 *
 *	unsigned int ml_phys_read_byte(vm_offset_t paddr)
 *
 *	Read the byte at physical address paddr. Memory should not be cache inhibited.
 */

;			Force a line boundry here
			.align	5
			.globl	EXT(ml_phys_read_byte)

LEXT(ml_phys_read_byte)

			mfmsr	r10								; Save the current MSR
			rlwinm	r10,r10,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r10,r10,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r4,r10,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; Clear interruptions
			rlwinm	r4,r4,0,MSR_DR_BIT+1,MSR_DR_BIT-1	; Clear translation	

			mtmsr	r4								; Translation and all off
			isync									; Toss prefetch

			lbz		r3,0(r3)						; Get the byte
			sync

			mtmsr	r10								; Restore translation and rupts
			isync
			blr

/* Read physical address
 *
 *	unsigned int ml_phys_read(vm_offset_t paddr)
 *
 *	Read the word at physical address paddr. Memory should not be cache inhibited.
 */

;			Force a line boundry here
			.align	5
			.globl	EXT(ml_phys_read)

LEXT(ml_phys_read)

			mfmsr	r0								; Save the current MSR
			rlwinm	r0,r0,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r0,r0,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r4,r0,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; Clear interruptions
			rlwinm	r4,r4,0,MSR_DR_BIT+1,MSR_DR_BIT-1	; Clear translation	

			mtmsr	r4								; Translation and all off
			isync									; Toss prefetch
			
			lwz		r3,0(r3)						; Get the word
			sync

			mtmsr	r0								; Restore translation and rupts
			isync
			blr

/* Write physical address byte
 *
 *	void ml_phys_write_byte(vm_offset_t paddr, unsigned int data)
 *
 *	Write the byte at physical address paddr. Memory should not be cache inhibited.
 */

;			Force a line boundry here
			.align	5
			.globl	EXT(ml_phys_write_byte)

LEXT(ml_phys_write_byte)

			mfmsr	r0								; Save the current MSR
			rlwinm	r0,r0,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r0,r0,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r5,r0,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; Clear interruptions
			rlwinm	r5,r5,0,MSR_DR_BIT+1,MSR_DR_BIT-1	; Clear translation	

			mtmsr	r5								; Translation and all off
			isync									; Toss prefetch
			
			stb		r4,0(r3)						; Set the byte
			sync

			mtmsr	r0								; Restore translation and rupts
			isync
			blr

/* Write physical address
 *
 *	void ml_phys_write(vm_offset_t paddr, unsigned int data)
 *
 *	Write the word at physical address paddr. Memory should not be cache inhibited.
 */

;			Force a line boundry here
			.align	5
			.globl	EXT(ml_phys_write)

LEXT(ml_phys_write)

			mfmsr	r0								; Save the current MSR
			rlwinm	r0,r0,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r0,r0,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r5,r0,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; Clear interruptions
			rlwinm	r5,r5,0,MSR_DR_BIT+1,MSR_DR_BIT-1	; Clear translation	

			mtmsr	r5								; Translation and all off
			isync									; Toss prefetch
			
			stw		r4,0(r3)						; Set the word
			sync

			mtmsr	r0								; Restore translation and rupts
			isync
			blr


/* set interrupts enabled or disabled
 *
 *	boolean_t set_interrupts_enabled(boolean_t enable)
 *
 *	Set EE bit to "enable" and return old value as boolean
 */

;			Force a line boundry here
			.align  5
			.globl  EXT(ml_set_interrupts_enabled)
 
LEXT(ml_set_interrupts_enabled)

			mfsprg	r7,0
			lwz		r4,PP_INTS_ENABLED(r7)
			mr.		r4,r4
			beq-	EXT(fake_set_interrupts_enabled)
			mfmsr	r5								; Get the current MSR
			rlwinm	r5,r5,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			mr		r4,r3							; Save the old value
			rlwinm	r5,r5,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r3,r5,17,31,31					; Set return value
			rlwimi	r5,r4,15,16,16					; Insert new EE bit
			andi.   r8,r5,lo16(MASK(MSR_EE))			; Interruptions
			bne     CheckPreemption
NoPreemption:
			mtmsr   r5                              ; Slam enablement
			blr

CheckPreemption:
			lwz		r8,PP_NEED_AST(r7)
			li		r6,AST_URGENT
			lwz		r8,0(r8)
			lwz		r7,PP_PREEMPT_CNT(r7)
			lis		r0,HIGH_ADDR(DoPreemptCall)
			and.	r8,r8,r6
			ori		r0,r0,LOW_ADDR(DoPreemptCall)   
			beq+	NoPreemption
			cmpi	cr0, r7, 0
			mtmsr	r5								; Restore the MSR now, before we can preempt
			bnelr+									; Return if no premption
			sc										; Preempt
			blr


/*  Emulate a decremeter exception
 *
 *	void machine_clock_assist(void)
 *
 */

;			Force a line boundry here
			.align  5
			.globl  EXT(machine_clock_assist)
 
LEXT(machine_clock_assist)

			mfsprg	r7,0
			lwz		r4,PP_INTS_ENABLED(r7)
			mr.		r4,r4
			beq-	EXT(CreateFakeDEC)
			blr

/*  Set machine into idle power-saving mode. 
 *
 *	void machine_idle_ppc(void)
 *
 *	We will use the PPC NAP or DOZE for this. 
 *	This call always returns.  Must be called with spllo (i.e., interruptions
 *	enabled).
 *
 */


;			Force a line boundry here
			.align	5
			.globl	EXT(machine_idle_ppc)

LEXT(machine_idle_ppc)

			mfmsr	r3								; Get the current MSR
			rlwinm	r3,r3,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r3,r3,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r5,r3,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; Turn off interruptions
			mtmsr	r5								; Hold up interruptions for now
			isync									; May have messed with fp/vec
			mfsprg	r12,0							; Get the per_proc_info
			mfspr	r6,hid0							; Get the current power-saving mode
			mfsprg	r11,2							; Get CPU specific features
			rlwinm	r6,r6,0,sleep+1,doze-1			; Clear all possible power-saving modes (not DPM though)	
			mtcrf	0xC7,r11						; Get the facility flags

			lis		r4,hi16(napm)					; Assume we can nap
			bt		pfWillNapb,yesnap				; Yeah, nap is ok...
			
			lis		r4,hi16(dozem)					; Assume we can doze
			bt		pfCanDozeb,yesnap				; We can sleep or doze one this machine...
			
			ori		r3,r3,lo16(MASK(MSR_EE))		; Flip on EE
			mtmsr	r3								; Turn interruptions back on
			blr										; Leave...

yesnap:		mftbu	r9								; Get the upper timebase
			mftb	r7								; Get the lower timebase
			mftbu	r8								; Get the upper one again
			cmplw	r9,r8							; Did the top tick?
			bne-	yesnap							; Yeah, need to get it again...
			stw		r8,napStamp(r12)				; Set high order time stamp
			stw		r7,napStamp+4(r12)				; Set low order nap stamp

			rlwinm.	r7,r11,0,pfNoL2PFNapb,pfNoL2PFNapb			; Turn off L2 Prefetch before nap?
			beq	miL2PFok

			mfspr	r7,msscr0						; Get currect MSSCR0 value
			rlwinm	r7,r7,0,0,l2pfes-1					; Dissable L2 Prefetch
			mtspr	msscr0,r7						; Updates MSSCR0 value
			sync
			isync

miL2PFok:
			rlwinm.	r7,r11,0,pfSlowNapb,pfSlowNapb				; Should nap at slow speed?
			beq	minoslownap

			mfspr	r7,hid1							; Get current HID1 value
			oris	r7,r7,hi16(hid1psm)					; Select PLL1
			mtspr	hid1,r7							; Update HID1 value

minoslownap:

;
;			We have to open up interruptions here because book 4 says that we should
;			turn on only the POW bit and that we should have interrupts enabled
;			The interrupt handler will detect that nap or doze is set if an interrupt
;			is taken and set everything up to return directly to machine_idle_ret.
;			So, make sure everything we need there is already set up...
;
			ori		r7,r5,lo16(MASK(MSR_EE))		; Flip on EE
			or		r6,r6,r4						; Set nap or doze
			oris	r5,r7,hi16(MASK(MSR_POW))		; Turn on power management in next MSR
			mtspr	hid0,r6							; Set up the HID for nap/doze
			isync									; Make sure it is set
			mtmsr	r7								; Enable for interrupts
			rlwinm.	r11,r11,0,pfAltivecb,pfAltivecb	; Do we have altivec?
			beq-	minovec							; No...
			dssall									; Stop the streams before we nap/doze

minovec:	sync									; Make sure queues are clear			
			mtmsr	r5								; Nap or doze
			isync									; Make sure this takes before we proceed
			b		minovec							; loop if POW does not take
;
;			Note that the interrupt handler will turn off the nap/doze bits in the hid.
;			Also remember that the interrupt handler will force return to here whenever
;			the nap/doze bits are set.
;
			.globl	EXT(machine_idle_ret)
LEXT(machine_idle_ret)
			mtmsr	r7								; Make sure the MSR is what we want
			isync									; In case we turn on translation
			
			blr										; Return...

/*  Put machine to sleep. 
 *	This call never returns. We always exit sleep via a soft reset.
 *	All external interruptions must be drained at this point and disabled.
 *
 *	void ml_ppc_sleep(void)
 *
 *	We will use the PPC SLEEP for this. 
 *
 *	There is one bit of hackery in here: we need to enable for
 *	interruptions when we go to sleep and there may be a pending
 *	decrimenter rupt.  So we make the decrimenter 0x7FFFFFFF and enable for
 *	interruptions. The decrimenter rupt vector recognizes this and returns
 *	directly back here.
 *
 */

;			Force a line boundry here
			.align	5
			.globl	EXT(ml_ppc_sleep)

LEXT(ml_ppc_sleep)

#if 0
			mfmsr	r5								; Hack to spin instead of sleep 
			rlwinm	r5,r5,0,MSR_DR_BIT+1,MSR_IR_BIT-1	; Turn off translation	
			rlwinm	r5,r5,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; Turn off interruptions
			mtmsr	r5								; No talking
			isync
			
deadsleep:	addi	r3,r3,1							; Make analyzer happy
			addi	r3,r3,1
			addi	r3,r3,1
			b		deadsleep						; Die the death of 1000 joys...
#endif	
			
			mfspr	r4,hid0							; Get the current power-saving mode
			eqv		r10,r10,r10						; Get all foxes
			mfsprg	r11,2							; Get CPU specific features

			rlwinm.	r5,r11,0,pfNoL2PFNapb,pfNoL2PFNapb			; Turn off L2 Prefetch before sleep?
			beq	mpsL2PFok

			mfspr	r5,msscr0						; Get currect MSSCR0 value
			rlwinm	r5,r5,0,0,l2pfes-1					; Dissable L2 Prefetch
			mtspr	msscr0,r5						; Updates MSSCR0 value
			sync
			isync

mpsL2PFok:
			mfmsr	r5								; Get the current MSR
			rlwinm	r10,r10,0,1,31					; Make 0x7FFFFFFF
			rlwinm	r4,r4,0,sleep+1,doze-1			; Clear all possible power-saving modes (not DPM though)	
			mtdec	r10								; Load decrimenter with 0x7FFFFFFF
			isync									; and make sure,
			mfdec	r9								; really sure, it gets there
			
			mtcrf	0x07,r11						; Get the cache flags, etc

			oris	r4,r4,hi16(sleepm)				; Set sleep
			rlwinm	r5,r5,0,MSR_DR_BIT+1,MSR_IR_BIT-1	; Turn off translation		
;
;			Note that we need translation off before we set the HID to sleep.  Otherwise
;			we will ignore any PTE misses that occur and cause an infinite loop.
;
			bt		pfNoMSRirb,mpsNoMSR				; No MSR...

			mtmsr	r5								; Translation off
			isync									; Toss prefetch
			b		mpsNoMSRx
			
mpsNoMSR:	
			li		r0,loadMSR						; Get the MSR setter SC
			mr		r3,r5							; Get new MSR
			sc										; Set it
mpsNoMSRx:

			ori		r3,r5,lo16(MASK(MSR_EE))		; Flip on EE
			sync
			mtspr	hid0,r4							; Set up the HID to sleep

			mtmsr	r3								; Enable for interrupts to drain decrimenter
				
			add		r6,r4,r5						; Just waste time
			add		r6,r6,r4						; A bit more
			add		r6,r6,r5						; A bit more

			mtmsr	r5								; Interruptions back off
			isync									; Toss prefetch

;
;			We are here with translation off, interrupts off, all possible
;			interruptions drained off, and a decrimenter that will not pop.
;

			bl		EXT(cacheInit)					; Clear out the caches.  This will leave them on
			bl		EXT(cacheDisable)				; Turn off all caches
			
			mfmsr	r5								; Get the current MSR
			oris	r5,r5,hi16(MASK(MSR_POW))		; Turn on power management in next MSR
													; Leave EE off because power goes off shortly

slSleepNow:	sync									; Sync it all up
			mtmsr	r5								; Do sleep with interruptions enabled
			isync									; Take a pill
			b		slSleepNow						; Go back to sleep if we wake up...
			


/*  Initialize all caches including the TLBs
 *
 *	void cacheInit(void)
 *
 *	This is used to force the caches to an initial clean state.  First, we 
 *	check if the cache is on, if so, we need to flush the contents to memory.
 *	Then we invalidate the L1. Next, we configure and invalidate the L2 etc.
 *	Finally we turn on all of the caches
 *
 *	Note that if translation is not disabled when this is called, the TLB will not
 *	be completely clear after return.
 *
 */

;			Force a line boundry here
			.align	5
			.globl	EXT(cacheInit)

LEXT(cacheInit)

			mfsprg	r12,0							; Get the per_proc_info
			mfspr	r9,hid0							; Get the current power-saving mode
			
			mfsprg	r11,2							; Get CPU specific features
			mfmsr	r7								; Get the current MSR
			rlwinm	r4,r9,0,dpm+1,doze-1			; Clear all possible power-saving modes (also disable DPM)	
			rlwinm	r7,r7,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r7,r7,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwimi	r11,r11,pfLClckb+1,31,31		; Move pfLClck to another position (to keep from using non-volatile CRs)
			rlwinm	r5,r7,0,MSR_DR_BIT+1,MSR_IR_BIT-1	; Turn off translation		
			rlwinm	r5,r5,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; Turn off interruptions
			mtcrf	0x87,r11						; Get the feature flags
			mtspr	hid0,r4							; Set up the HID

			bt		pfNoMSRirb,ciNoMSR				; No MSR...

			mtmsr	r5								; Translation and all off
			isync									; Toss prefetch
			b		ciNoMSRx
			
ciNoMSR:	
			li		r0,loadMSR						; Get the MSR setter SC
			mr		r3,r5							; Get new MSR
			sc										; Set it
ciNoMSRx:
			
			bf		pfAltivecb,cinoDSS				; No Altivec here...
			
			dssall									; Stop streams
			sync

cinoDSS:	lis		r5,hi16(EXT(tlb_system_lock))	; Get the TLBIE lock
			li		r0,128							; Get number of TLB entries
			ori		r5,r5,lo16(EXT(tlb_system_lock))	; Grab up the bottom part
			
			li		r6,0							; Start at 0

citlbhang:	lwarx	r2,0,r5							; Get the TLBIE lock
			mr.		r2,r2							; Is it locked?
			bne-	citlbhang						; It is locked, go wait...
			stwcx.	r0,0,r5							; Try to get it
			bne-	citlbhang						; We was beat...

			mtctr	r0								; Set the CTR
			
cipurgeTLB:	tlbie	r6								; Purge this entry
			addi	r6,r6,4096						; Next page
			bdnz	cipurgeTLB						; Do them all...
			
			mtcrf	0x80,r11						; Set SMP capability
			sync									; Make sure all TLB purges are done
			eieio									; Order, order in the court
			
			bf		pfSMPcapb,cinoSMP				; SMP incapable...
			
			tlbsync									; Sync all TLBs
			sync
			isync
			
cinoSMP:	stw		r2,0(r5)						; Unlock TLBIE lock

			cror	cr0_eq,pfL1ib,pfL1db			; Check for either I- or D-cache
			bf-		cr0_eq,cinoL1					; No level 1 to flush...
			rlwinm.	r0,r9,0,ice,dce					; Were either of the level 1s on?
			beq-	cinoL1							; No, no need to flush...
			
			bf		pfL1fab,ciswdl1					; If no hw flush assist, go do by software...
			
			mfspr	r8,msscr0						; Get the memory system control register
			oris	r8,r8,hi16(dl1hwfm)				; Turn on the hardware flush request
			
			mtspr	msscr0,r8						; Start the flush operation
			
ciwdl1f:	mfspr	r8,msscr0						; Get the control register again
			
			rlwinm.	r8,r8,0,dl1hwf,dl1hwf			; Has the flush request been reset yet?
			bne		ciwdl1f							; No, flush is still in progress...
			b		ciinvdl1						; Go invalidate l1...
			
;
;			We need to either make this very complicated or to use ROM for
;			the flush.  The problem is that if during the following sequence a
;			snoop occurs that invalidates one of the lines in the cache, the
;			PLRU sequence will be altered making it possible to miss lines
;			during the flush.  So, we either need to dedicate an area of RAM
;			to each processor, lock use of a RAM area, or use ROM.  ROM is
;			by far the easiest. Note that this is not an issue for machines
;			that have harware flush assists.
;

ciswdl1:	lwz		r0,pfl1dSize(r12)				; Get the level 1 cache size
					
			bf		31,cisnlck						; Skip if pfLClck not set...
			
			mfspr	r4,msscr0						; ?
			rlwinm	r6,r4,0,0,l2pfes-1				; ?
			mtspr	msscr0,r6						; Set it
			sync
			isync
			
			mfspr	r8,ldstcr						; Save the LDSTCR
			li		r2,1							; Get a mask of 0x01
			lis		r3,0xFFF0						; Point to ROM
			rlwinm	r11,r0,29,3,31					; Get the amount of memory to handle all indexes

			li		r6,0							; Start here
			
cisiniflsh:	dcbf	r6,r3							; Flush each line of the range we use
			addi	r6,r6,32						; Bump to the next
			cmplw	r6,r0							; Have we reached the end?
			blt+	cisiniflsh						; Nope, continue initial flush...
			
			sync									; Make sure it is done
	
			addi	r11,r11,-1						; Get mask for index wrap	
			li		r6,0							; Get starting offset
						
cislckit:	not		r5,r2							; Lock all but 1 way
			rlwimi	r5,r8,0,0,23					; Build LDSTCR
			mtspr	ldstcr,r5						; Lock a way
			sync									; Clear out memory accesses
			isync									; Wait for all
			
			
cistouch:	lwzx	r10,r3,r6						; Pick up some trash
			addi	r6,r6,32						; Go to the next index
			and.	r0,r6,r11						; See if we are about to do next index
			bne+	cistouch						; Nope, do more...
			
			sync									; Make sure it is all done
			isync									
			
			sub		r6,r6,r11						; Back up to start + 1
			addi	r6,r6,-1						; Get it right
			
cisflush:	dcbf	r3,r6							; Flush everything out
			addi	r6,r6,32						; Go to the next index
			and.	r0,r6,r11						; See if we are about to do next index
			bne+	cisflush						; Nope, do more...

			sync									; Make sure it is all done
			isync									
			
			
			rlwinm.	r2,r2,1,24,31					; Shift to next way
			bne+	cislckit						; Do this for all ways...

			mtspr	ldstcr,r8						; Slam back to original
			sync
			isync
			
			mtspr	msscr0,r4						; ?
			sync
			isync

			b		cinoL1							; Go on to level 2...
			

cisnlck:	rlwinm	r2,r0,0,1,30					; Double cache size
			add		r0,r0,r2						; Get 3 times cache size
			rlwinm	r0,r0,26,6,31					; Get 3/2 number of cache lines
			lis		r3,0xFFF0						; Dead recon ROM address for now
			mtctr	r0								; Number of lines to flush

ciswfldl1a:	lwz		r2,0(r3)						; Flush anything else
			addi	r3,r3,32						; Next line
			bdnz	ciswfldl1a						; Flush the lot...
			
ciinvdl1:	sync									; Make sure all flushes have been committed

			mfspr	r8,hid0							; Get the HID0 bits
			rlwinm	r8,r8,0,dce+1,ice-1				; Clear cache enables
			mtspr	hid0,r8							; and turn off L1 cache
			sync									; Make sure all is done
			isync

			ori		r8,r8,lo16(icem|dcem|icfim|dcfim)	; Set the HID0 bits for enable, and invalidate
			sync
			isync										
			
			mtspr	hid0,r8							; Start the invalidate and turn on cache	
			rlwinm	r8,r8,0,dcfi+1,icfi-1			; Turn off the invalidate bits
			mtspr	hid0,r8							; Turn off the invalidate (needed for some older machines)
			sync

			
cinoL1:
;
;			Flush and disable the level 2
;
			bf		pfL2b,cinol2					; No level 2 cache to flush

			mfspr	r8,l2cr							; Get the L2CR
			lwz		r3,pfl2cr(r12)					; Get the L2CR value
			rlwinm.		r0,r8,0,l2e,l2e					; Was the L2 enabled?
			bne		ciflushl2					; Yes, force flush
			cmplwi		r8, 0						; Was the L2 all the way off?
			beq		ciinvdl2					; Yes, force invalidate
			lis		r0,hi16(l2sizm|l2clkm|l2ramm|l2ohm)	; Get confiuration bits
			xor		r2,r8,r3						; Get changing bits?
			ori		r0,r0,lo16(l2slm|l2dfm|l2bypm)	; More config bits
			and.	r0,r0,r2						; Did any change?
			bne-	ciinvdl2						; Yes, just invalidate and get PLL synced...		
			
ciflushl2:
			bf		pfL2fab,ciswfl2					; Flush not in hardware...
			
			mr		r10,r8							; Take a copy now
			
			bf		31,cinol2lck					; Skip if pfLClck not set...
			
			oris	r10,r10,hi16(l2ionlym|l2donlym)	; Set both instruction- and data-only
			sync
			mtspr	l2cr,r10						; Lock out the cache
			sync
			isync
			
cinol2lck:	ori		r10,r10,lo16(l2hwfm)			; Request flush
			sync									; Make sure everything is done
			
			mtspr	l2cr,r10						; Request flush
			
cihwfl2:	mfspr	r10,l2cr						; Get back the L2CR
			rlwinm.	r10,r10,0,l2hwf,l2hwf			; Is the flush over?
			bne+	cihwfl2							; Nope, keep going...
			b		ciinvdl2						; Flush done, go invalidate L2...
			
ciswfl2:
			lwz		r0,pfl2Size(r12)				; Get the L2 size
			oris	r2,r8,hi16(l2dom)				; Set L2 to data only mode

			b		ciswfl2doa					; Branch to next line...

			.align  5
ciswfl2doc:
			mtspr	l2cr,r2							; Disable L2
			sync
			isync
			b		ciswfl2dod					; It is off, go invalidate it...

ciswfl2doa:
			b		ciswfl2dob					; Branch to next...

ciswfl2dob:
			sync								; Finish memory stuff
			isync								; Stop speculation
			b		ciswfl2doc					; Jump back up and turn on data only...
ciswfl2dod:
			rlwinm	r0,r0,27,5,31					; Get the number of lines
			lis		r10,0xFFF0						; Dead recon ROM for now
			mtctr	r0								; Set the number of lines
			
ciswfldl2a:	lwz		r0,0(r10)						; Load something to flush something
			addi	r10,r10,32						; Next line
			bdnz	ciswfldl2a						; Do the lot...
			
ciinvdl2:	rlwinm	r8,r3,0,l2e+1,31				; Use the saved L2CR and clear the enable bit
			b		cinla							; Branch to next line...

			.align  5
cinlc:		mtspr	l2cr,r8							; Disable L2
			sync
			isync
			b		ciinvl2							; It is off, go invalidate it...
			
cinla:		b		cinlb							; Branch to next...

cinlb:		sync									; Finish memory stuff
			isync									; Stop speculation
			b		cinlc							; Jump back up and turn off cache...
			
ciinvl2:	sync
			isync

			cmplwi	r3, 0							; Should the L2 be all the way off?
			beq	cinol2							; Yes, done with L2

			oris	r2,r8,hi16(l2im)				; Get the invalidate flag set
			
			mtspr	l2cr,r2							; Start the invalidate
			sync
			isync
ciinvdl2a:	mfspr	r2,l2cr							; Get the L2CR
			bf		pfL2ib,ciinvdl2b				; Flush not in hardware...
			rlwinm.	r2,r2,0,l2i,l2i					; Is the invalidate still going?
			bne+	ciinvdl2a						; Assume so, this will take a looong time...
			sync
			b		cinol2							; No level 2 cache to flush
ciinvdl2b:
			rlwinm.	r2,r2,0,l2ip,l2ip				; Is the invalidate still going?
			bne+	ciinvdl2a						; Assume so, this will take a looong time...
			sync
			mtspr	l2cr,r8							; Turn off the invalidate request
			
cinol2:
			
;
;			Flush and enable the level 3
;
			bf		pfL3b,cinol3					; No level 3 cache to flush

			mfspr	r8,l3cr							; Get the L3CR
			lwz		r3,pfl3cr(r12)					; Get the L3CR value
			rlwinm.		r0,r8,0,l3e,l3e					; Was the L3 enabled?
			bne		ciflushl3					; Yes, force flush
			cmplwi		r8, 0						; Was the L3 all the way off?
			beq		ciinvdl3					; Yes, force invalidate
			lis		r0,hi16(l3pem|l3sizm|l3dxm|l3clkm|l3spom|l3ckspm)	; Get configuration bits
			xor		r2,r8,r3						; Get changing bits?
			ori		r0,r0,lo16(l3pspm|l3repm|l3rtm|l3cyam|l3dmemm|l3dmsizm)	; More config bits
			and.	r0,r0,r2						; Did any change?
			bne-	ciinvdl3						; Yes, just invalidate and get PLL synced...
			
ciflushl3:
			sync									; 7450 book says do this even though not needed
			mr		r10,r8							; Take a copy now
			
			bf		31,cinol3lck					; Skip if pfL23lck not set...
			
			oris	r10,r10,hi16(l3iom)				; Set instruction-only
			ori		r10,r10,lo16(l3donlym)			; Set data-only
			sync
			mtspr	l3cr,r10						; Lock out the cache
			sync
			isync
			
cinol3lck:	ori		r10,r10,lo16(l3hwfm)			; Request flush
			sync									; Make sure everything is done
			
			mtspr	l3cr,r10						; Request flush
			
cihwfl3:	mfspr	r10,l3cr						; Get back the L3CR
			rlwinm.	r10,r10,0,l3hwf,l3hwf			; Is the flush over?
			bne+	cihwfl3							; Nope, keep going...

ciinvdl3:	rlwinm	r8,r3,0,l3e+1,31				; Use saved L3CR value and clear the enable bit
			sync									; Make sure of life, liberty, and justice
			mtspr	l3cr,r8							; Disable L3
			sync

			cmplwi	r3, 0							; Should the L3 be all the way off?
			beq	cinol3							; Yes, done with L3

			ori		r8,r8,lo16(l3im)				; Get the invalidate flag set

			mtspr	l3cr,r8							; Start the invalidate

ciinvdl3b:	mfspr	r8,l3cr							; Get the L3CR
			rlwinm.	r8,r8,0,l3i,l3i					; Is the invalidate still going?
			bne+	ciinvdl3b						; Assume so...
			sync

			lwz	r10, pfBootConfig(r12)					; ?
			rlwinm.	r10, r10, 24, 28, 31					; ?
			beq	ciinvdl3nopdet						; ?
			
			mfspr	r8,l3pdet						; ?
			srw	r2, r8, r10						; ?
			rlwimi	r2, r8, 0, 24, 31					; ?
			subfic	r10, r10, 32						; ?
			li	r8, -1							; ?
			ori	r2, r2, 0x0080						; ?
			slw	r8, r8, r10						; ?
			or	r8, r2, r8						; ?
			mtspr	l3pdet, r8						; ?
			isync

ciinvdl3nopdet:
			mfspr	r8,l3cr							; Get the L3CR
			rlwinm	r8,r8,0,l3clken+1,l3clken-1		; Clear the clock enable bit
			mtspr	l3cr,r8							; Disable the clock

			li		r2,128							; ?
ciinvdl3c:	addi	r2,r2,-1						; ?
			cmplwi	r2,0							; ?
			bne+	ciinvdl3c

			mfspr	r10,msssr0						; ?
			rlwinm	r10,r10,0,vgL3TAG+1,vgL3TAG-1	; ?
			mtspr	msssr0,r10						; ?
			sync

			mtspr	l3cr,r3							; Enable it as desired
			sync
cinol3:
			bf		pfL2b,cinol2a					; No level 2 cache to enable

			lwz		r3,pfl2cr(r12)					; Get the L2CR value
			cmplwi		r3, 0						; Should the L2 be all the way off?
			beq		cinol2a						: Yes, done with L2
			mtspr	l2cr,r3							; Enable it as desired
			sync

;
;			Invalidate and turn on L1s
;

cinol2a:	
			bt		31,cinoexit						; Skip if pfLClck set...

			rlwinm	r8,r9,0,dce+1,ice-1				; Clear the I- and D- cache enables
			mtspr	hid0,r8							; Turn off dem caches
			sync
			
			ori		r8,r9,lo16(icem|dcem|icfim|dcfim)	; Set the HID0 bits for enable, and invalidate
			rlwinm	r9,r8,0,dcfi+1,icfi-1			; Turn off the invalidate bits
			sync
			isync											

			mtspr	hid0,r8							; Start the invalidate and turn on L1 cache	

cinoexit:	mtspr	hid0,r9							; Turn off the invalidate (needed for some older machines) and restore entry conditions
			sync
			mtmsr	r7								; Restore MSR to entry
			isync
			blr										; Return...


/*  Disables all caches
 *
 *	void cacheDisable(void)
 *
 *	Turns off all caches on the processor. They are not flushed.
 *
 */

;			Force a line boundry here
			.align	5
			.globl	EXT(cacheDisable)

LEXT(cacheDisable)

			mfsprg	r11,2							; Get CPU specific features
			mtcrf	0x83,r11						; Set feature flags
			
			bf		pfAltivecb,cdNoAlt				; No vectors...
			
			dssall									; Stop streams
			
cdNoAlt:	sync
			
			mfspr	r5,hid0							; Get the hid
			rlwinm	r5,r5,0,dce+1,ice-1				; Clear the I- and D- cache enables
			mtspr	hid0,r5							; Turn off dem caches
			sync

			bf		pfL2b,cdNoL2					; Skip if no L2...
			
			mfspr	r5,l2cr							; Get the L2
			rlwinm	r5,r5,0,l2e+1,31				; Turn off enable bit

			b		cinlaa							; Branch to next line...

			.align  5
cinlcc:		mtspr	l2cr,r5							; Disable L2
			sync
			isync
			b		cdNoL2							; It is off, we are done...
			
cinlaa:		b		cinlbb							; Branch to next...

cinlbb:		sync									; Finish memory stuff
			isync									; Stop speculation
			b		cinlcc							; Jump back up and turn off cache...

cdNoL2:
			
			bf		pfL3b,cdNoL3					; Skip down if no L3...
			
			mfspr	r5,l3cr							; Get the L3
			rlwinm	r5,r5,0,l3e+1,31				; Turn off enable bit
			rlwinm	r5,r5,0,l3clken+1,l3clken-1		; Turn off cache enable bit
			mtspr	l3cr,r5							; Disable the caches
			sync
			
cdNoL3:
			blr										; Leave...


/*  Initialize processor thermal monitoring  
 *	void ml_thrm_init(void)
 *
 *	Build initial TAU registers and start them all going.
 *	We ca not do this at initial start up because we need to have the processor frequency first.
 *	And just why is this in assembler when it does not have to be?? Cause I am just too 
 *	lazy to open up a "C" file, thats why.
 */

;			Force a line boundry here
			.align	5
			.globl	EXT(ml_thrm_init)

LEXT(ml_thrm_init)

			mfsprg	r12,0							; Get the per_proc blok
			lis		r11,hi16(EXT(gPEClockFrequencyInfo))	; Get top of processor information
			mfsprg	r10,2							; Get CPU specific features
			ori		r11,r11,lo16(EXT(gPEClockFrequencyInfo))	; Get bottom of processor information
			mtcrf	0x40,r10						; Get the installed features

			li		r3,lo16(thrmtidm|thrmvm)		; Set for lower-than thermal event at 0 degrees
			bflr	pfThermalb						; No thermal monitoring on this cpu
			mtspr	thrm1,r3						; Do it

			lwz		r3,thrmthrottleTemp(r12)		; Get our throttle temprature
			rlwinm	r3,r3,31-thrmthre,thrmthrs,thrmthre	; Position it
			ori		r3,r3,lo16(thrmvm)				; Set for higher-than event 
			mtspr	thrm2,r3						; Set it

			lis		r4,hi16(1000000)				; Top of million
;
;			Note: some CPU manuals say this is processor clocks, some say bus rate.  The latter
;			makes more sense because otherwise we can not get over about 400MHz.
#if 0
			lwz		r3,PECFIcpurate(r11)				; Get the processor speed
#else
			lwz		r3,PECFIbusrate(r11)				; Get the bus speed
#endif
			ori		r4,r4,lo16(1000000)				; Bottom of million
			lis		r7,hi16(thrmsitvm>>1)			; Get top of highest possible value
			divwu	r3,r3,r4						; Get number of cycles per microseconds
			ori		r7,r7,lo16(thrmsitvm>>1)		; Get the bottom of the highest possible value
			addi	r3,r3,1							; Insure we have enough
			mulli	r3,r3,20						; Get 20 microseconds worth of cycles
			cmplw	r3,r7							; Check against max
			ble+	smallenuf						; It is ok...
			mr		r3,r7							; Saturate
			
smallenuf:	rlwinm	r3,r3,31-thrmsitve,thrmsitvs,thrmsitve	; Position			
			ori		r3,r3,lo16(thrmem)				; Enable with at least 20micro sec sample
			stw		r3,thrm3val(r12)				; Save this in case we need it later
			mtspr	thrm3,r3						; Do it
			blr


/*  Set thermal monitor bounds 
 *	void ml_thrm_set(unsigned int low, unsigned int high)
 *
 *	Set TAU to interrupt below low and above high.  A value of
 *	zero disables interruptions in that direction.
 */

;			Force a line boundry here
			.align	5
			.globl	EXT(ml_thrm_set)

LEXT(ml_thrm_set)

			mfmsr	r0								; Get the MSR
			rlwinm	r0,r0,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r0,r0,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r6,r0,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; Clear EE bit
			mtmsr	r6
			isync

			mfsprg	r12,0							; Get the per_proc blok

			rlwinm.	r6,r3,31-thrmthre,thrmthrs,thrmthre	; Position it and see if enabled
			mfsprg	r9,2							; Get CPU specific features
			stw		r3,thrmlowTemp(r12)				; Set the low temprature
			mtcrf	0x40,r9							; See if we can thermal this machine
			rlwinm	r9,r9,(((31-thrmtie)+(pfThermIntb+1))&31),thrmtie,thrmtie	; Set interrupt enable if this machine can handle it
			bf		pfThermalb,tsetcant				; No can do...
			beq		tsetlowo						; We are setting the low off...
			ori		r6,r6,lo16(thrmtidm|thrmvm)		; Set the lower-than and valid bit
			or		r6,r6,r9						; Set interruption request if supported

tsetlowo:	mtspr	thrm1,r6						; Cram the register
			
			rlwinm.	r6,r4,31-thrmthre,thrmthrs,thrmthre	; Position it and see if enabled
			stw		r4,thrmhighTemp(r12)			; Set the high temprature
			beq		tsethigho						; We are setting the high off...
			ori		r6,r6,lo16(thrmvm)				; Set valid bit
			or		r6,r6,r9						; Set interruption request if supported

tsethigho:	mtspr	thrm2,r6						; Cram the register

tsetcant:	mtmsr	r0								; Reenable interruptions
			blr										; Leave...

/*  Read processor temprature  
 *	unsigned int ml_read_temp(void)
 *
 */

;			Force a line boundry here
			.align	5
			.globl	EXT(ml_read_temp)

LEXT(ml_read_temp)

			mfmsr	r9								; Save the MSR
			li		r5,15							; Starting point for ranging (start at 15 so we do not overflow)
			rlwinm	r9,r9,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r9,r9,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r8,r9,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; Turn off interruptions
			mfsprg	r7,2							; Get CPU specific features
			mtmsr	r8								; Do not allow interruptions
			mtcrf	0x40,r7							; See if we can thermal this machine
			bf		pfThermalb,thrmcant				; No can do...

			mfspr	r11,thrm1						; Save thrm1

thrmrange:	rlwinm	r4,r5,31-thrmthre,thrmthrs,thrmthre	; Position it
			ori		r4,r4,lo16(thrmtidm|thrmvm)		; Flip on the valid bit and make comparision for less than

			mtspr	thrm1,r4						; Set the test value
			
thrmreada:	mfspr	r3,thrm1						; Get the thermal register back
			rlwinm.	r0,r3,0,thrmtiv,thrmtiv			; Has it settled yet?
			beq+	thrmreada						; Nope...

			rlwinm.	r0,r3,0,thrmtin,thrmtin			; Are we still under the threshold?
			bne		thrmsearch						; No, we went over...

			addi	r5,r5,16						; Start by trying every 16 degrees
			cmplwi	r5,127							; Have we hit the max?
			blt-	thrmrange						; Got some more to do...

thrmsearch:	rlwinm	r4,r5,31-thrmthre,thrmthrs,thrmthre	; Position it
			ori		r4,r4,lo16(thrmtidm|thrmvm)		; Flip on the valid bit and make comparision for less than
			
			mtspr	thrm1,r4						; Set the test value
			
thrmread:	mfspr	r3,thrm1						; Get the thermal register back
			rlwinm.	r0,r3,0,thrmtiv,thrmtiv			; Has it settled yet?
			beq+	thrmread						; Nope...
			
			rlwinm.	r0,r3,0,thrmtin,thrmtin			; Are we still under the threshold?
			beq		thrmdone						; No, we hit it...
			addic.	r5,r5,-1						; Go down a degree
			bge+	thrmsearch						; Try again (until we are below freezing)...
			
thrmdone:	addi	r3,r5,1							; Return the temprature (bump it up to make it correct)
			mtspr	thrm1,r11						; Restore the thermal register
			mtmsr	r9								; Re-enable interruptions
			blr										; Leave...
			
thrmcant:	eqv		r3,r3,r3						; Return bogus temprature because we can not read it
			mtmsr	r9								; Re-enable interruptions
			blr										; Leave...

/*  Throttle processor speed up or down
 *	unsigned int ml_throttle(unsigned int step)
 *
 *	Returns old speed and sets new.  Both step and return are values from 0 to
 *	255 that define number of throttle steps, 0 being off and "ictcfim" is max * 2.
 *
 */

;			Force a line boundry here
			.align	5
			.globl	EXT(ml_throttle)

LEXT(ml_throttle)

			mfmsr	r9								; Save the MSR
			rlwinm	r9,r9,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r9,r9,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r8,r9,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; Turn off interruptions
			cmplwi	r3,lo16(ictcfim>>1)				; See if we are going too far					
			mtmsr	r8								; Do not allow interruptions	
			isync		
			ble+	throtok							; Throttle value is ok...
			li		r3,lo16(ictcfim>>1)				; Set max

throtok:	rlwinm.	r4,r3,1,ictcfib,ictcfie			; Set the throttle
			beq		throtoff						; Skip if we are turning it off...
			ori		r4,r4,lo16(thrmvm)				; Turn on the valid bit
			
throtoff:	mfspr	r3,ictc							; Get the old throttle
			mtspr	ictc,r4							; Set the new
			rlwinm	r3,r3,31,1,31					; Shift throttle value over
			mtmsr	r9								; Restore interruptions
			blr										; Return...

/*
**      ml_get_timebase()
**
**      Entry   - R3 contains pointer to 64 bit structure.
**
**      Exit    - 64 bit structure filled in.
**
*/
;			Force a line boundry here
			.align	5
			.globl	EXT(ml_get_timebase)

LEXT(ml_get_timebase)

loop:
        mftbu   r4
        mftb    r5
        mftbu   r6
        cmpw    r6, r4
        bne-    loop

        stw     r4, 0(r3)
        stw     r5, 4(r3)

        blr

/*
 *		The routine that implements cpu_number.
 */

		.align  5
		.globl  EXT(cpu_number)
 
LEXT(cpu_number)
 
		mfmsr	r9						/* Save the old MSR */
		rlwinm	r9,r9,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
		rlwinm	r9,r9,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
		rlwinm	r8,r9,0,17,15			/* Clear interruptions */
		mtmsr	r8						/* Interrupts off */
		isync
		mfsprg	r7,0					/* Get per-proc block */
		lhz		r3,PP_CPU_NUMBER(r7)	/* Get CPU number */
		mtmsr	r9						/* Restore interruptions to entry */
		blr								/* Return... */

/*
**      ml_sense_nmi()
**
*/
;			Force a line boundry here
			.align	5
			.globl	EXT(ml_sense_nmi)

LEXT(ml_sense_nmi)

			blr										; Leave...

/*
**      ml_set_processor_speed()
**
*/
;			Force a line boundry here
			.align	5
			.globl	EXT(ml_set_processor_speed)

LEXT(ml_set_processor_speed)
			mfsprg	r5, 0								; Get the per_proc_info

			cmpli	cr0, r3, 0							; Turn off BTIC before low speed
			beq	sps1
			mfspr	r4, hid0							; Get the current hid0 value
			rlwinm	r4, r4, 0, btic+1, btic-1					; Clear the BTIC bit
			sync
			mtspr	hid0, r4							; Set the new hid0 value
			isync
			sync

sps1:
			mfspr	r4, hid1							; Get the current PLL settings
			rlwimi  r4, r3, 31-hid1ps, hid1ps, hid1ps				; Copy the PLL Select bit
			stw	r4, pfHID1(r5)							; Save the new hid1 value
			mtspr	hid1, r4							; Select desired PLL

			cmpli	cr0, r3, 0							; Restore BTIC after high speed
			bne	sps2
			lwz	r4, pfHID0(r5)							; Load the hid0 value
			sync
			mtspr	hid0, r4							; Set the hid0 value
			isync
			sync

sps2:
			blr

/*
**      ml_set_processor_voltage()
**
*/
;			Force a line boundry here
			.align	5
			.globl	EXT(ml_set_processor_voltage)

LEXT(ml_set_processor_voltage)
			mfspr	r4, hid2							; Get HID2 value
			rlwimi	r4, r3, 31-hid2vmin, hid2vmin, hid2vmin				; Insert the voltage mode bit
			mtspr	hid2, r4							; Set the voltage mode
			sync									; Make sure it is done
			blr

/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */

#define __APPLE_API_PRIVATE

#include <mach_kdb.h>
#include <mach_kdp.h>
#include <mach_kgdb.h>
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <ppc/spec_reg.h>
#include <machine/cpu_capabilities.h>
#include <mach/ppc/vm_param.h>
#include <assym.s>


; Definitions of the processor type table format, which drives this code.
; The table ("processor_types") is assembled in at the end of this file.
	
#define ptFilter	0
#define ptVersion	4
#define ptRevision	6
#define ptFeatures	8
#define ptCPUCap	12
#define ptPwrModes	16
#define ptPatch		20
#define ptInitRout	24
#define ptRptdProc	28
#define ptLineSize	32
#define ptl1iSize	36
#define ptl1dSize	40
#define ptPTEG		44
#define ptMaxVAddr	48
#define ptMaxPAddr	52
#define ptSize		56


; We use cr2 for flags:

#define bootCPU 10
#define firstInit 9
#define firstBoot 8

/*
 * Interrupt and bootup stack for initial processor
 */

	.file	"start.s"
	
/*
 * All CPUs start here.
 *
 * This code is called from SecondaryLoader
 *
 * Various arguments are passed via a table:
 *   R3 = pointer to other startup parameters
 */
	.text

ENTRY(resetPOR,TAG_NO_FRAME_USED)

			li		r12,0								; Get a 0
			stw		r12,0xF0(0)							; Make sure the special flag is clear
			mtmsrd	r12									; Make sure we are in 32-bit mode
			isync										; Really make sure
			lwz		r3,0xF4(0)							; Get the boot_args pointer
			b		startJoin							; Join up...


ENTRY(_start_cpu,TAG_NO_FRAME_USED)
			crclr	bootCPU								; Set non-boot processor
			crclr	firstInit							; Set not first time init
			lwz		r30,ppe_paddr(r3)					; Set current per_proc
			lwz		r28,ppe_paddr+4(r3)					; Set current per_proc
			rlwinm	r30,r30,0,1,0						; Copy low 32 bits to top 32 
			rlwimi	r30,r28,0,0,31						; Insert low part of 64-bit address in bottom 32 bits
			subi	r29,r3,(ACT_PER_PROC-ppe_vaddr)		; Substract mact.PerProc offset
			mr		r3,r30								; Set current per_proc
			
;
;			Note that we are just trying to get close.  The real TB sync will take
;			place later.  The value we are loading is set in two places.  For the 
;			main processor, it will be the TB at the last interrupt before we went
;			to sleep.  For the others, it will be the time just before the main
;			processor woke us up.
;

			lwz		r15,ruptStamp(r3)					; Get the timebase from the other processor
			li		r17,0								; Clear this out
			lwz		r16,ruptStamp+4(r3)					; Get the timebase from the other processor
			mtspr	tbl,r17								; Clear bottom so we do not tick
			mtspr	tbu,r15								; Set top
			mtspr	tbl,r16								; Then bottom again
			b		allstart
			
ENTRY(_start,TAG_NO_FRAME_USED)

startJoin:
			mflr		r2					; Save the return address
			lis		r28,hi16(EXT(PerProcTable))			; Set PerProcTable
			lis		r30,hi16(EXT(BootProcInfo))			; Set current per_proc
			ori		r28,r28,lo16(EXT(PerProcTable))		; Set PerProcTable
			ori		r30,r30,lo16(EXT(BootProcInfo))		; Set current per_proc
			stw		r30,ppe_paddr+4(r28)				; Set per_proc_entry
			stw		r30,ppe_vaddr(r28)					; Set per_proc_entry
			subi	r29,r28,(ACT_PER_PROC-ppe_vaddr)	; Substract mact.PerProc offset
			crset	bootCPU								; Set boot processor
			
			lwz		r17,pfAvailable(r30)				; Get the available bits
			rlwinm.	r0,r17,0,pfValidb,pfValidb			; Have we initialized the feature flags yet?
			crmove	firstInit,cr0_eq					; Set if we are doing first time init
			bne		allstart							; Yeah, we must be waking up from sleep...
			
;
;			Here is where we do any one time general low-level initialization

			lis		r20,HIGH_ADDR(fwdisplock)			; Get address of the firmware display lock
			li		r19,0								; Zorch a register
			ori		r20,r20,LOW_ADDR(fwdisplock)		; Get address of the firmware display lock
			stw		r19,0(r20)							; Make sure the lock is free
			
allstart:
			mr		r31,r3								; Save away arguments

			crand	firstBoot,bootCPU,firstInit			; Indicate if we are on the initial first processor startup

			mtsprg	0,r30								; Set per_proc paddr
			mtsprg	1,r29								; Set spr1

			li		r9,0								; Clear out a register
			mtsprg	2,r9
			mtsprg	3,r9

			li		r7,MSR_VM_OFF						; Get real mode MSR			
			mtmsr	r7									; Set the real mode SRR
			isync					

			lis		r26,hi16(processor_types)			; Point to processor table
			ori		r26,r26,lo16(processor_types)		; Other half
			mfpvr	r10									; Get the PVR
			
nextPVR:	lwz		r28,ptFilter(r26)					; Get the filter
			lwz		r27,ptVersion(r26)					; Get the version and revision codes
			and		r28,r10,r28							; Throw away dont care bits
			cmplw	r27,r28								; Is this the right set?
			beq		donePVR								; We have the right one...
			addi	r26,r26,ptSize						; Point to the next type
			b		nextPVR								; Check it out...
			
donePVR:	lwz		r20,ptInitRout(r26)					; Grab the special init routine
			mtlr	r20									; Setup to call the init

			bf		firstBoot,notFirst					; Not first boot, go...
			
;			
;			The following code just does a general initialization of the features just
;			after the initial first-time boot.  This is not done after waking up or on
;			any "secondary" processor.  Just after the boot-processor init, we copy the
;			features to any possible per_proc.
;
;			We are just setting defaults.   The specific initialization code will modify these
;			if necessary. 
;			
			lis		r18,hi16(EXT(_cpu_capabilities))	; Get the address of _cpu_capabilities
			ori		r18,r18,lo16(EXT(_cpu_capabilities))
			lwz		r17,ptCPUCap(r26)					; Get the default cpu capabilities
			stw		r17, 0(r18)							; Save the default value in _cpu_capabilities
			
			lwz		r17,ptFeatures(r26)					; Pick up the features
			
			lwz		r18,ptRptdProc(r26)					; Get the reported processor
			sth		r18,pfrptdProc(r30)					; Set the reported processor
			
			lwz		r13,ptPwrModes(r26)					; Get the supported power modes
			stw		r13,pfPowerModes(r30)				; Set the supported power modes
			
			lwz		r13,ptLineSize(r26)					; Get the cache line size
			sth		r13,pflineSize(r30)					; Save it
			lwz		r13,ptl1iSize(r26)					; Get icache size
			stw		r13,pfl1iSize(r30)					; Save it
			lwz		r13,ptl1dSize(r26)					; Get dcache size
			stw		r13,pfl1dSize(r30)					; Save it
			lwz		r13,ptPTEG(r26)						; Get PTEG size address
			stw		r13,pfPTEG(r30)						; Save it
			lwz		r13,ptMaxVAddr(r26)					; Get max virtual address
			stw		r13,pfMaxVAddr(r30)					; Save it
			lwz		r13,ptMaxPAddr(r26)					; Get max physical address
			stw		r13,pfMaxPAddr(r30)					; Save it

            
;           Go through the patch table, changing performance sensitive kernel routines based on the
;           processor type or other things.

			lis		r11,hi16(EXT(patch_table))
			ori		r11,r11,lo16(EXT(patch_table))
			lwz		r19,ptPatch(r26)					; Get ptPatch field
patch_loop:
			lwz		r16,patchType(r11)					; Load the patch type
			lwz		r15,patchValue(r11)					; Load the patch value
			cmplwi	cr1,r16,PATCH_FEATURE				; Is it a patch feature entry
            cmplwi  cr7,r16,PATCH_END_OF_TABLE          ; end of table?
			and.	r14,r15,r19							; Is it set in the patch feature
			crandc	cr0_eq,cr1_eq,cr0_eq				; Do we have a match
            beq     cr7,doOurInit                       ; end of table, Go do processor specific initialization
			beq		patch_apply							; proc feature matches, so patch memory
			cmplwi	cr1,r16,PATCH_PROCESSOR				; Is it a patch processor entry
			cmplw	cr0,r15,r18							; Check matching processor
			crand	cr0_eq,cr1_eq,cr0_eq				; Do we have a match
			bne		patch_skip							; No, skip patch memory
patch_apply:
			lwz		r13,patchAddr(r11)					; Load the address to patch
			lwz		r14,patchData(r11)					; Load the patch data
			stw		r14,0(r13)							; Patch the location
			dcbf	0,r13								; Flush the old one
			sync										; Make sure we see it all
			icbi	0,r13								; Flush the i-cache
			isync										; Hang out
			sync										; Hang out some more...
patch_skip:
			addi	r11,r11,peSize						; Point to the next patch entry
			b       patch_loop							; handle next


;           Additional processors join here after skipping above code.

notFirst:	lwz		r17,pfAvailable(r30)				; Get our features

doOurInit:	mr.		r20,r20								; See if initialization routine
			crand	firstBoot,bootCPU,firstInit			; Indicate if we are on the initial first processor startup
			bnelrl										; Do the initialization
			
			ori		r17,r17,lo16(pfValid)				; Set the valid bit
			stw		r17,pfAvailable(r30)				; Set the available features

			rlwinm.	r0,r17,0,pf64Bitb,pf64Bitb			; Is this a 64-bit machine?
			mtsprg	2,r17								; Remember the feature flags

			bne++	start64								; Skip following if 64-bit...

			mfspr	r6,hid0								; Get the HID0
			rlwinm	r6,r6,0,sleep+1,doze-1				; Remove any vestiges of sleep
			mtspr	hid0,r6								; Set the insominac HID0
			isync					
		
;			Clear the BAT registers

			li		r9,0								; Clear out a register
			sync
			isync
			mtdbatu 0,r9								; Invalidate maps
			mtdbatl 0,r9								; Invalidate maps
			mtdbatu 1,r9								; Invalidate maps
			mtdbatl 1,r9								; Invalidate maps
			mtdbatu 2,r9								; Invalidate maps
			mtdbatl 2,r9								; Invalidate maps
			mtdbatu 3,r9								; Invalidate maps
			mtdbatl 3,r9								; Invalidate maps
			sync
			isync
			mtibatu 0,r9								; Invalidate maps
			mtibatl 0,r9								; Invalidate maps
			mtibatu 1,r9								; Invalidate maps
			mtibatl 1,r9								; Invalidate maps
			mtibatu 2,r9								; Invalidate maps
			mtibatl 2,r9								; Invalidate maps
			mtibatu 3,r9								; Invalidate maps
			mtibatl 3,r9								; Invalidate maps
			sync
			isync
			b		startcommon							; Go join up the common start routine
			
start64:	lis		r5,hi16(startcommon)				; Get top of address of continue point
			mfspr	r6,hid0								; Get the HID0
			ori		r5,r5,lo16(startcommon)				; Get low of address of continue point
			lis		r9,hi16(MASK(MSR_HV)|MASK(MSR_SF))	; ?
			lis		r20,hi16(dozem|napm|sleepm)			; Get mask of power saving features	
			ori		r20,r20,lo16(1)						; Disable the attn instruction
			li		r7,MSR_VM_OFF						; Get real mode MSR
			sldi	r9,r9,32							; Slide into position
			sldi	r20,r20,32							; Slide power stuff into position
			or		r9,r9,r7							; Form initial MSR
			andc	r6,r6,r20							; Remove any vestiges of sleep
			isync
			mtspr	hid0,r6								; Set the insominac HID0
			mfspr	r6,hid0								; Get it
			mfspr	r6,hid0								; Get it
			mfspr	r6,hid0								; Get it
			mfspr	r6,hid0								; Get it
			mfspr	r6,hid0								; Get it
			mfspr	r6,hid0								; Get it
			isync
			mtsrr0	r5									; Set the continue point
			mtsrr1	r9									; Set our normal disabled MSR				
			rfid										; Tally ho...
			
			.align	5					

startcommon:
			rlwinm.	r0,r17,0,pfFloatb,pfFloatb			; See if there is floating point
			beq-	noFloat								; Nope, this is a really stupid machine...
			
			li		r0,MSR_VM_OFF|MASK(MSR_FP)			; Enable for floating point
			mtmsr	r0									/* Set the standard MSR values */
			isync
			
			lis		r5,HIGH_ADDR(EXT(FloatInit))		/* Get top of floating point init value */
			ori		r5,r5,LOW_ADDR(EXT(FloatInit))		/* Slam bottom */
			lfd		f0,0(r5)							/* Initialize FP0 */
			fmr		f1,f0								/* Ours in not */					
			fmr		f2,f0								/* to wonder why, */
			fmr		f3,f0								/* ours is but to */
			fmr		f4,f0								/* do or die! */
			fmr		f5,f0						
			fmr		f6,f0						
			fmr		f7,f0						
			fmr		f8,f0						
			fmr		f9,f0						
			fmr		f10,f0						
			fmr		f11,f0						
			fmr		f12,f0						
			fmr		f13,f0						
			fmr		f14,f0						
			fmr		f15,f0						
			fmr		f16,f0						
			fmr		f17,f0						
			fmr		f18,f0						
			fmr		f19,f0						
			fmr		f20,f0						
			fmr		f21,f0						
			fmr		f22,f0						
			fmr		f23,f0						
			fmr		f24,f0						
			fmr		f25,f0						
			fmr		f26,f0						
			fmr		f27,f0						
			fmr		f28,f0						
			fmr		f29,f0						
			fmr		f30,f0						
			fmr		f31,f0						
		
			li		r0,	MSR_VM_OFF						; Turn off floating point
			mtmsr	r0
			isync

noFloat:	rlwinm.	r0,r17,0,pfAltivecb,pfAltivecb		; See if there is Altivec
			beq-	noVector							; Nope...
		
			li		r0,0								; Clear out a register
			
			lis		r7,hi16(MSR_VEC_ON)					; Get real mode MSR + Altivec
			ori		r7,r7,lo16(MSR_VM_OFF)				; Get real mode MSR + Altivec
			mtmsr	r7									; Set the real mode SRR */
			isync										; Make sure it has happened									
		
			lis		r5,hi16(EXT(QNaNbarbarian))			; Altivec initializer
			ori		r5,r5,lo16(EXT(QNaNbarbarian))		; Altivec initializer

			mtspr	vrsave,r0							; Set that no VRs are used yet */
			
			vspltish v1,1								; Turn on the non-Java bit and saturate
			vspltisw v0,1								; Turn on the saturate bit
			vxor	v1,v1,v0							; Turn off saturate	and leave non-Java set
			lvx		v0,br0,r5							; Initialize VR0
			mtvscr	v1									; Clear the vector status register
			vor		v2,v0,v0							; Copy into the next register
			vor		v1,v0,v0							; Copy into the next register
			vor		v3,v0,v0							; Copy into the next register
			vor		v4,v0,v0							; Copy into the next register
			vor		v5,v0,v0							; Copy into the next register
			vor		v6,v0,v0							; Copy into the next register
			vor		v7,v0,v0							; Copy into the next register
			vor		v8,v0,v0							; Copy into the next register
			vor		v9,v0,v0							; Copy into the next register
			vor		v10,v0,v0							; Copy into the next register
			vor		v11,v0,v0							; Copy into the next register
			vor		v12,v0,v0							; Copy into the next register
			vor		v13,v0,v0							; Copy into the next register
			vor		v14,v0,v0							; Copy into the next register
			vor		v15,v0,v0							; Copy into the next register
			vor		v16,v0,v0							; Copy into the next register
			vor		v17,v0,v0							; Copy into the next register
			vor		v18,v0,v0							; Copy into the next register
			vor		v19,v0,v0							; Copy into the next register
			vor		v20,v0,v0							; Copy into the next register
			vor		v21,v0,v0							; Copy into the next register
			vor		v22,v0,v0							; Copy into the next register
			vor		v23,v0,v0							; Copy into the next register
			vor		v24,v0,v0							; Copy into the next register
			vor		v25,v0,v0							; Copy into the next register
			vor		v26,v0,v0							; Copy into the next register
			vor		v27,v0,v0							; Copy into the next register
			vor		v28,v0,v0							; Copy into the next register
			vor		v29,v0,v0							; Copy into the next register
			vor		v30,v0,v0							; Copy into the next register
			vor		v31,v0,v0							; Copy into the next register
		
			li		r0,	MSR_VM_OFF						; Turn off vectors
			mtmsr	r0
			isync

noVector:
			bl		EXT(cacheInit)						; Initializes all caches (including the TLB)

			bt		bootCPU,run32					

			mfsprg	r30,0								; Phys per proc
			lwz		r29,PP_HIBERNATE(r30)
            andi.	r29, r29, 1
			beq		noHashTableInit						; Skip following if not waking from from hibernate
			bl		EXT(hw_clear_maps)					; Mark all maps as absent from hash table
			bl		EXT(hw_hash_init)					; Clear hash table
			bl		EXT(save_snapshot_restore)			; Reset save area chains
noHashTableInit:
			bl	EXT(hw_setup_trans)						; Set up hardware needed for translation
			bl	EXT(hw_start_trans)						; Start translating 

run32:
			rlwinm.	r0,r17,0,pf64Bitb,pf64Bitb			; Is this a 64-bit machine?
			beq++	isnot64								; Skip following if not 64-bit...
			
			mfmsr	r29									; Get the MSR
			rldicl	r29,r29,0,MSR_SF_BIT+1				; turn 64-bit mode off
			mtmsrd	r29									; Set it
			isync										; Make sure
			
isnot64:	bf		bootCPU,callcpu					

			lis		r29,HIGH_ADDR(EXT(intstack))		; move onto interrupt stack
			ori		r29,r29,LOW_ADDR(EXT(intstack))
			addi	r29,r29,INTSTACK_SIZE-FM_SIZE

			li		r28,0
			stw		r28,FM_BACKPTR(r29) 				; store a null frame backpointer
	
			mr		r1,r29
			mr		r3,r31								; Restore any arguments we may have trashed

;			Note that we exit from here with translation still off

			bl	EXT(ppc_init)							; Jump into boot init code
			BREAKPOINT_TRAP

callcpu:
			mfsprg	r31,1								; Fake activation pointer
			lwz		r31,ACT_PER_PROC(r31)				; Load per_proc
			lwz		r29,PP_INTSTACK_TOP_SS(r31)			; move onto interrupt stack

			li		r28,0
			stw		r28,FM_BACKPTR(r29) 				; store a null frame backpointer

			mr		r1,r29								; move onto new stack
			mr		r3,r31								; Restore any arguments we may have trashed

;			Note that we exit from here with translation on

			bl		EXT(ppc_init_cpu)					; Jump into cpu init code
			BREAKPOINT_TRAP								; Should never return

;
;			Specific processor initialization routines
;

;			750

init750:
			bf	firstBoot, init750nb						; No init for wakeup....

			mfspr	r13,l2cr							; Get the L2CR
			rlwinm.	r0,r13,0,l2e,l2e					; Any L2?
			bne+	i750hl2								; Yes...
			rlwinm	r17,r17,0,pfL2b+1,pfL2b-1			; No L2, turn off feature
			
i750hl2:
			lis	r14,hi16(256*1024)						; Base L2 size
			addis	r15,r13,0x3000							; Hah... Figure this one out...
			rlwinm	r15,r15,4,30,31							; Isolate
			rlwinm.	r8,r13,0,l2siz,l2sizf						; Was size valid?
			slw	r14,r14,r15							; Set 256KB, 512KB, or 1MB
			beq-	init750l2none							; Not a valid setting...
			
			stw	r13,pfl2crOriginal(r30)						; Shadow the L2CR
			stw	r13,pfl2cr(r30)							; Shadow the L2CR
			stw	r14,pfl2Size(r30)						; Set the L2 size
			b	init750l2done							; Done with L2
			
init750l2none:
			rlwinm	r17,r17,0,pfL2b+1,pfL2b-1					; No level 2 cache
			
init750l2done:
			mfspr	r11,hid0							; Get the current HID0
			stw	r11,pfHID0(r30)							; Save the HID0 value
			blr									; Return...
			
init750nb:
			lwz	r11,pfHID0(r30)							; Get HID0
			sync
			mtspr	hid0,r11							; Set the HID
			isync
			sync
			blr

;			750CX

init750CX:
			bf	firstBoot, init750						; No init for wakeup....
			mfspr	r13,hid1							; Get HID1
			li	r14,lo16(0xFD5F)						; Get valid
			rlwinm	r13,r13,4,28,31						; Isolate
			slw	r14,r14,r13								; Position
			rlwimi	r17,r14,15-pfCanNapb,pfCanNapb,pfCanNapb	; Set it			
			b	init750									; Join common...


;			750FX

init750FX:
			bf	firstBoot, init750FXnb
			mfspr	r11, hid1
			stw	r11, pfHID1(r30)						; Save the HID1 value
			b	init750

init750FXnb:
			lwz	r13, pfHID0(r30)						; Get HID0
			lwz	r11, pfHID1(r30)						; Get HID1

			rlwinm.	r0, r11, 0, hid1ps, hid1ps			; Isolate the hid1ps bit
			beq	init750FXnb2							; Clear BTIC if hid1ps set
			rlwinm	r13, r13, 0, btic+1, btic-1			; Clear the BTIC bit

init750FXnb2:
			sync
			mtspr	hid0, r13							; Set the HID
			isync
			sync

			rlwinm  r12, r11, 0, hid1ps+1, hid1ps-1		; Select PLL0
			mtspr	hid1, r12							; Restore PLL config
			mftb	r13									; Wait 5000 ticks (> 200 us)

init750FXnbloop:
			mftb	r14
			sub	r14, r14, r13
			cmpli	cr0, r14, 5000
			ble	init750FXnbloop
			mtspr	hid1, r11							; Select the desired PLL
			blr

;			750FX vers 2.0 or later
init750FXV2:
			bf	firstBoot, init750FXV2nb					; Wake from sleep

			mfspr	r11, hid2
			stw	r11, pfHID2(r30)						; Save the HID2 value
			b	init750FX							; Continue with 750FX init

init750FXV2nb:
			lwz	r13, pfHID2(r30)						; Get HID2
			rlwinm	r13, r13, 0, hid2vmin+1, hid2vmin-1				; Clear the vmin bit
			mtspr	hid2, r13							; Restore HID2 value
			sync									; Wait for it to be done
			b	init750FX

;			7400

init7400:	bf		firstBoot,i7400nb					; Do different if not initial boot...
			mfspr	r13,l2cr							; Get the L2CR
			rlwinm.	r0,r13,0,l2e,l2e					; Any L2?
			bne+	i7400hl2							; Yes...
			rlwinm	r17,r17,0,pfL2b+1,pfL2b-1			; No L2, turn off feature
			
i7400hl2:	lis		r14,hi16(256*1024)					; Base L2 size
			addis	r15,r13,0x3000						; Hah... Figure this one out...
			rlwinm	r15,r15,4,30,31						 
			slw		r14,r14,r15							; Set 256KB, 512KB, 1MB, or 2MB
			
			stw		r13,pfl2crOriginal(r30)				; Shadow the L2CR
			stw		r13,pfl2cr(r30)						; Shadow the L2CR
			stw		r14,pfl2Size(r30)					; Set the L2 size
			
			mfspr	r11,hid0							; Get the current HID0
			oris	r11,r11,hi16(emcpm|eiecm)			; ?
			mtspr	hid0,r11							; ?
			isync
			stw		r11,pfHID0(r30)						; Save the HID0 value

			mfspr	r11,msscr0							; Get the msscr0 register
			stw		r11,pfMSSCR0(r30)					; Save the MSSCR0 value
			mfspr	r11,msscr1							; Get the msscr1 register
			stw		r11,pfMSSCR1(r30)					; Save the MSSCR1 value
			blr											; Return...
			
i7400nb:
			li		r11,0
			mtspr	l2cr,r11							; Make sure L2CR is zero
			lwz		r11,pfHID0(r30)						; Get HID0
			sync
			mtspr	hid0,r11							; Set the HID
			isync
			sync			
			lwz		r11,pfMSSCR0(r30)					; Get MSSCR0
			isync
			sync
			mtspr	msscr0,r11							; Set the MSSCR0
			lwz		r11,pfMSSCR1(r30)					; Get msscr1
			isync
			sync
			mtspr	msscr1,r11							; Set the msscr1
			isync
			sync
			blr

;			7400 (ver 2.0 - ver 2.7)

init7400v2_7:
			bf	firstBoot, init7400
			mfspr	r13, hid0							; Get the HID0
			ori	r13, r13, nopdstm						; ?
			mtspr	hid0, r13							; Set the HID0
			isync
			sync
			b	init7400

;			7410
;			Note that this is the same as 7400 except we initialize the l2cr2 register

init7410:	li		r13,0								; Clear
			mtspr	1016,r13							; Turn off direct cache
			b		init7400							; Join up with common....


;			745X - Any 7450 family processor

init745X:
			bf		firstBoot,init745Xnb				; Do different if not initial boot...

			mfspr	r13,l2cr							; Get the L2CR
			rlwinm.	r0,r13,0,l2e,l2e					; Any L2?
			bne+	init745Xhl2							; Yes...
			rlwinm	r17,r17,0,pfL2b+1,pfL2b-1			; No L2, turn off feature
			
init745Xhl2:
			mfpvr	r14									; Get processor version
			rlwinm	r14,r14,16,16,31					; Isolate processor version
			cmpli	cr0, r14, PROCESSOR_VERSION_7457	; Test for 7457 or
			cmpli	cr1, r14, PROCESSOR_VERSION_7447A	; 7447A
			cror	cr0_eq, cr1_eq, cr0_eq
			lis		r14,hi16(512*1024)					; 512KB L2
			beq		init745Xhl2_2

			lis		r14,hi16(256*1024)					; Base L2 size
			rlwinm	r15,r13,22,12,13					; Convert to 256k, 512k, or 768k
			add		r14,r14,r15							; Add in minimum

init745Xhl2_2:
			stw		r13,pfl2crOriginal(r30)				; Shadow the L2CR
			stw		r13,pfl2cr(r30)						; Shadow the L2CR
			stw		r14,pfl2Size(r30)					; Set the L2 size
				
;			Take care of level 3 cache

			mfspr	r13,l3cr							; Get the L3CR
			rlwinm.	r0,r13,0,l3e,l3e					; Any L3?
			bne+	init745Xhl3							; Yes...
			rlwinm	r17,r17,0,pfL3b+1,pfL3b-1			; No L3, turn off feature

init745Xhl3:	cmplwi	cr0,r13,0						; No L3 if L3CR is zero
			beq-	init745Xnone						; Go turn off the features...
			lis		r14,hi16(1024*1024)					; Base L3 size
			rlwinm	r15,r13,4,31,31						; Get size multiplier
			slw		r14,r14,r15							; Set 1 or 2MB
			
			stw		r13,pfl3crOriginal(r30)				; Shadow the L3CR
			stw		r13,pfl3cr(r30)						; Shadow the L3CR
			stw		r14,pfl3Size(r30)					; Set the L3 size
			b		init745Xfin							; Return....
				
init745Xnone:
			rlwinm	r17,r17,0,pfL3fab+1,pfL3b-1			; No 3rd level cache or assist
			rlwinm	r11,r17,pfWillNapb-pfCanNapb,pfCanNapb,pfCanNapb		; Set pfCanNap if pfWillNap is set
			or	r17,r17,r11

init745Xfin:
			rlwinm	r17,r17,0,pfWillNapb+1,pfWillNapb-1	; Make sure pfWillNap is not set

			mfspr	r11,hid0							; Get the current HID0
			stw		r11,pfHID0(r30)						; Save the HID0 value
			mfspr	r11,hid1							; Get the current HID1
			stw		r11,pfHID1(r30)						; Save the HID1 value
			mfspr	r11,msscr0							; Get the msscr0 register
			stw		r11,pfMSSCR0(r30)					; Save the MSSCR0 value
			mfspr	r11,msscr1							; Get the msscr1 register
			stw		r11,pfMSSCR1(r30)					; Save the MSSCR1 value
			mfspr	r11,ictrl							; Get the ictrl register
			stw		r11,pfICTRL(r30)					; Save the ICTRL value
			mfspr	r11,ldstcr							; Get the ldstcr register
			stw		r11,pfLDSTCR(r30)					; Save the LDSTCR value
			mfspr	r11,ldstdb							; Get the ldstdb register
			stw		r11,pfLDSTDB(r30)					; Save the LDSTDB value
			mfspr	r11,pir								; Get the pir register
			stw		r11,pfBootConfig(r30)					; Save the BootConfig value
			blr											; Return....


init745Xnb:	lwz		r11,pfHID0(r30)						; Get HID0
			sync
			mtspr	hid0,r11							; Set the HID
			isync
			lwz		r11,pfHID1(r30)						; Get HID1
			sync
			mtspr	hid1,r11							; Set the HID
			isync
			lwz		r11,pfMSSCR0(r30)					; Get MSSCR0
			sync
			mtspr	msscr0,r11							; Set the MSSCR0
			isync
			sync
			lwz		r11,pfICTRL(r30)					; Get ICTRL
			sync
			mtspr	ictrl,r11							; Set the ICTRL
			isync
			sync
			lwz		r11,pfLDSTCR(r30)					; Get LDSTCR
			sync
			mtspr	ldstcr,r11							; Set the LDSTCR
			isync
			sync
			lwz		r11,pfLDSTDB(r30)					; Get LDSTDB
			sync
			mtspr	ldstdb,r11							; Set the LDSTDB
			isync
			sync
			blr

;			7450 - Specific

init7450:
			bf	firstBoot, init745X						; Not boot, use standard init
			
			mfspr	r13, pir							; Get BootConfig from PIR
			rlwinm.	r14, r13, 0, 20, 23						; Is the pdet value zero
			bne	init7450done							; No, done for now
			
			ori	r13, r13, 0x0400						; Force pdet value to 4
			mtspr	pir, r13							; Write back the BootConfig
			
init7450done:
			b	init745X							; Continue with standard init


init970:
			lis		r20,8								; Set up for 512K L2
init970x:
			li		r0,0								; Clear this
			mtspr	hior,r0								; Make sure that 0 is interrupt prefix
			bf		firstBoot,init970nb					; No init for wakeup or second processor....


;
;			We can not query or change the L2 size.  We will just
;			phoney up a L2CR to make sysctl "happy" and set the
;			L2 size to 512K.
;

			lis		r0,0x8000							; Synthesize a "valid" but non-existant L2CR
			stw		r0,pfl2crOriginal(r30)				; Set a dummy L2CR
			stw		r0,pfl2cr(r30)						; Set a dummy L2CR
			stw		r20,pfl2Size(r30)					; Set the L2 size

			mfspr	r11,hid0							; Get original hid0
			std		r11,pfHID0(r30)						; Save original
			mfspr	r11,hid1							; Get original hid1
			std		r11,pfHID1(r30)						; Save original
			mfspr	r11,hid4							; Get original hid4
			std		r11,pfHID4(r30)						; Save original
			mfspr	r11,hid5							; Get original hid5
			std		r11,pfHID5(r30)						; Save original

			lis		r0, hi16(dnapm)						; Create a mask for the dnap bit
			sldi	r0, r0, 32							; Shift to the top half
			ld		r11,pfHID0(r30)						; Load the hid0 value
			andc	r11, r11, r0						; Clear the dnap bit
			isync
			mtspr	hid0,r11							; Stuff it
			mfspr	r11,hid0							; Get it
			mfspr	r11,hid0							; Get it
			mfspr	r11,hid0							; Get it
			mfspr	r11,hid0							; Get it
			mfspr	r11,hid0							; Get it
			mfspr	r11,hid0							; Get it
			isync

			lis		r0,(pcfValid|pcfLarge|pcfDedSeg)<<8	; Set the valid bit, dedicated segment, and large page flags
			ori		r0,r0,(24<<8)|24					; Add in the 16M page size
			stw		r0,lgpPcfg+(pcfSize*pcfLargePcfg)(0)	; Set the 16M primary large page configuration entry

			blr
			
;
;			Start up code for second processor or wake up from sleep
;
			
init970nb:
			lis		r0, hi16(dnapm)						; Create a mask for the dnap bit
			sldi	r0, r0, 32							; Shift to the top half
			ld		r11,pfHID0(r30)						; Load the hid0 value
			andc	r11, r11, r0						; Clear the dnap bit
			isync
			mtspr	hid0,r11							; Stuff it
			mfspr	r11,hid0							; Get it
			mfspr	r11,hid0							; Get it
			mfspr	r11,hid0							; Get it
			mfspr	r11,hid0							; Get it
			mfspr	r11,hid0							; Get it
			mfspr	r11,hid0							; Get it
			isync
		
			ld		r20,pfHID1(r30)						; Get it
			isync
			mtspr	hid1,r20							; Stick it
			mtspr	hid1,r20							; Stick it again
			isync
		
			ld		r11,pfHID4(r30)						; Get it
			sync
			mtspr	hid4,r11							; Stick it
			isync

			lis		r11,0xE000							; Get the unlikeliest ESID possible
			srdi	r11,r11,1							; Make 0x7FFFFFFFF0000000
			slbie	r11									; Make sure the ERAT is cleared 
			
			ld		r11,pfHID5(r30)						; Get it
			mtspr	hid5,r11							; Set it
			isync
;
;			May have changed dcbz mode so kill icache
;

			eqv		r13,r13,r13							; Get a constant -1
			mr		r14,r20								; Save HID1
			rldimi	r14,r13,54,9						; Set force icbi match mode
			
			li		r11,0								; Set start if ICBI range
			isync
			mtspr	hid1,r14							; Stick it
			mtspr	hid1,r14							; Stick it again
			isync

inin970ki:	icbi	0,r11								; Kill I$
			addi	r11,r11,128							; Next line
			andis.	r0,r11,1							; Have we done them all?
			beq++	inin970ki							; Not yet...

			isync
			mtspr	hid1,r20							; Stick it
			mtspr	hid1,r20							; Stick it again
			isync

			blr											; Leave...



;			Unsupported Processors
initUnsupported:
			mtlr	r2					; Restore the return address
			blr						; Return to the booter


;
;	Processor to feature table

;	.align	2				- Always on word boundary
;	.long	ptFilter		- Mask of significant bits in the Version/Revision code
;							- NOTE: Always order from most restrictive to least restrictive matching
;	.short	ptVersion		- Version code from PVR.  Always start with 0 which is default
;	.short	ptRevision		- Revision code from PVR. A zero value denotes the generic attributes if not specific
;	.long	ptFeatures		- Available features
;	.long	ptCPUCap		- Default value for _cpu_capabilities
;	.long	ptPwrModes		- Available power management features
;	.long	ptPatch			- Patch features
;	.long	ptInitRout		- Initilization routine.  Can modify any of the other attributes.
;	.long	ptRptdProc		- Processor type reported
;	.long	ptLineSize		- Level 1 cache line size
;	.long	ptl1iSize		- Level 1 instruction cache size
;	.long	ptl1dSize		- Level 1 data cache size
;	.long	ptPTEG			- Size of PTEG
;	.long	ptMaxVAddr		- Maximum effective address
;	.long	ptMaxPAddr		- Maximum physical address
;
	
	.align	2
processor_types:

;       750CX (ver 2.x)

			.align  2
			.long   0xFFFF0F00              ; 2.x vers
			.short  PROCESSOR_VERSION_750
			.short  0x0200
			.long   pfFloat | pfCanSleep | pfCanNap | pfCanDoze | pf32Byte | pfL2
			.long   kCache32 | kHasGraphicsOps | kHasStfiwx
			.long   0
			.long	PatchExt32
			.long   init750CX
			.long   CPU_SUBTYPE_POWERPC_750
			.long   32
			.long   32*1024
			.long   32*1024
			.long	64
			.long	52
			.long	32

;	750 (generic)

			.align	2
			.long	0xFFFF0000		; All revisions
			.short	PROCESSOR_VERSION_750
			.short	0
			.long	pfFloat | pfCanSleep | pfCanNap | pfCanDoze | pf32Byte | pfL2
			.long   kCache32 | kHasGraphicsOps | kHasStfiwx
			.long   0
			.long	PatchExt32
			.long	init750
			.long	CPU_SUBTYPE_POWERPC_750
			.long	32
			.long	32*1024
			.long	32*1024
			.long	64
			.long	52
			.long	32

;       750FX (ver 1.x)

			.align  2
			.long   0xFFFF0F00              ; 1.x vers
			.short  PROCESSOR_VERSION_750FX
			.short  0x0100
			.long   pfFloat | pfCanSleep | pfCanNap | pfCanDoze | pfSlowNap | pfNoMuMMCK | pf32Byte | pfL2
			.long   kCache32 | kHasGraphicsOps | kHasStfiwx
			.long   pmDualPLL
			.long	PatchExt32
			.long   init750FX
			.long   CPU_SUBTYPE_POWERPC_750
			.long   32
			.long   32*1024
			.long   32*1024
			.long	64
			.long	52
			.long	32

;       750FX (generic)

			.align  2
			.long   0xFFFF0000              ; All revisions
			.short  PROCESSOR_VERSION_750FX
			.short  0
			.long   pfFloat | pfCanSleep | pfCanNap | pfCanDoze | pfSlowNap | pfNoMuMMCK | pf32Byte | pfL2
			.long   kCache32 | kHasGraphicsOps | kHasStfiwx
			.long   pmDualPLL | pmDPLLVmin
			.long	PatchExt32
			.long   init750FXV2
			.long   CPU_SUBTYPE_POWERPC_750
			.long   32
			.long   32*1024
			.long   32*1024
			.long	64
			.long	52
			.long	32

;	7400 (ver 2.0 - ver 2.7)

			.align	2
			.long	0xFFFFFFF8		; ver 2.0 - 2.7
			.short	PROCESSOR_VERSION_7400
			.short	0x0200
			.long	pfFloat | pfAltivec | pfSMPcap | pfCanSleep | pfCanNap | pfCanDoze | pf32Byte | pfL1fa | pfL2 | pfL2fa | pfHasDcba
			.long   kHasAltivec | kCache32 | kDcbaAvailable | kDataStreamsAvailable | kHasGraphicsOps | kHasStfiwx
			.long	0
			.long	PatchExt32
			.long	init7400v2_7
			.long	CPU_SUBTYPE_POWERPC_7400
			.long	32
			.long	32*1024
			.long	32*1024
			.long	64
			.long	52
			.long	32

;	7400 (generic)

			.align	2
			.long	0xFFFF0000		; All revisions
			.short	PROCESSOR_VERSION_7400
			.short	0
			.long	pfFloat | pfAltivec | pfSMPcap | pfCanSleep | pfCanNap | pfCanDoze | pf32Byte | pfL1fa | pfL2 | pfL2fa | pfHasDcba
			.long   kHasAltivec | kCache32 | kDcbaAvailable | kDataStreamsRecommended | kDataStreamsAvailable | kHasGraphicsOps | kHasStfiwx
			.long	0
			.long	PatchExt32
			.long	init7400
			.long	CPU_SUBTYPE_POWERPC_7400
			.long	32
			.long	32*1024
			.long	32*1024
			.long	64
			.long	52
			.long	36

;	7410 (ver 1.1)

			.align	2
			.long	0xFFFFFFFF		; Exact match
			.short	PROCESSOR_VERSION_7400
			.short	0x1101
			.long	pfFloat | pfAltivec | pfSMPcap | pfCanSleep | pfCanNap | pfCanDoze | pf32Byte | pfL1fa | pfL2 | pfL2fa | pfHasDcba
			.long   kHasAltivec | kCache32 | kDcbaAvailable | kDataStreamsRecommended | kDataStreamsAvailable | kHasGraphicsOps | kHasStfiwx
			.long	0
			.long	PatchExt32
			.long	init7410
			.long	CPU_SUBTYPE_POWERPC_7400
			.long	32
			.long	32*1024
			.long	32*1024
			.long	64
			.long	52
			.long	36

;	7410 (generic)

			.align	2
			.long	0xFFFF0000		; All other revisions
			.short	PROCESSOR_VERSION_7410
			.short	0
			.long	pfFloat | pfAltivec | pfSMPcap | pfCanSleep | pfCanNap | pfCanDoze | pf32Byte | pfL1fa | pfL2 | pfL2fa | pfHasDcba
			.long   kHasAltivec | kCache32 | kDcbaAvailable | kDataStreamsRecommended | kDataStreamsAvailable | kHasGraphicsOps | kHasStfiwx
			.long	0
			.long	PatchExt32
			.long	init7410
			.long	CPU_SUBTYPE_POWERPC_7400
			.long	32
			.long	32*1024
			.long	32*1024
			.long	64
			.long	52
			.long	36

;	7450 (ver 1.xx)

			.align	2
			.long	0xFFFFFF00		; Just revisions 1.xx
			.short	PROCESSOR_VERSION_7450
			.short	0x0100
			.long	pfFloat | pfAltivec | pfSMPcap | pfCanSleep | pfNoMSRir | pfNoL2PFNap | pfLClck | pf32Byte | pfL2 | pfL2fa | pfL2i | pfL3 | pfL3fa  | pfHasDcba
			.long   kHasAltivec | kCache32 | kDcbaAvailable | kDataStreamsRecommended | kDataStreamsAvailable | kHasGraphicsOps | kHasStfiwx
			.long	0
			.long	PatchExt32
			.long	init7450
			.long	CPU_SUBTYPE_POWERPC_7450
			.long	32
			.long	32*1024
			.long	32*1024
			.long	64
			.long	52
			.long	36

;	7450 (2.0)

			.align	2
			.long	0xFFFFFFFF		; Just revision 2.0
			.short	PROCESSOR_VERSION_7450
			.short	0x0200
			.long	pfFloat | pfAltivec | pfSMPcap | pfCanSleep | pfNoMSRir | pfNoL2PFNap | pfLClck | pf32Byte | pfL2 | pfL2fa | pfL2i | pfL3 | pfL3fa | pfHasDcba
			.long   kHasAltivec | kCache32 | kDcbaAvailable | kDataStreamsRecommended | kDataStreamsAvailable | kHasGraphicsOps | kHasStfiwx
			.long	0
			.long	PatchExt32
			.long	init7450
			.long	CPU_SUBTYPE_POWERPC_7450
			.long	32
			.long	32*1024
			.long	32*1024
			.long	64
			.long	52
			.long	36

;	7450 (2.1)

			.align	2
			.long	0xFFFF0000		; All other revisions
			.short	PROCESSOR_VERSION_7450
			.short	0
			.long	pfFloat | pfAltivec | pfSMPcap | pfCanSleep | pfWillNap | pfNoMSRir | pfNoL2PFNap | pfLClck | pf32Byte | pfL2 | pfL2fa | pfL2i | pfL3 | pfL3fa | pfHasDcba
			.long   kHasAltivec | kCache32 | kDcbaAvailable | kDataStreamsRecommended | kDataStreamsAvailable | kHasGraphicsOps | kHasStfiwx
			.long	0
			.long	PatchExt32
			.long	init7450
			.long	CPU_SUBTYPE_POWERPC_7450
			.long	32
			.long	32*1024
			.long	32*1024
			.long	64
			.long	52
			.long	36

;	7455 (1.xx)  Just like 7450 2.0

			.align	2
			.long	0xFFFFFF00		; Just revisions 1.xx
			.short	PROCESSOR_VERSION_7455
			.short	0x0100
			.long	pfFloat | pfAltivec | pfSMPcap | pfCanSleep | pfNoMSRir | pfNoL2PFNap | pfLClck | pf32Byte | pfL2 | pfL2fa | pfL2i | pfL3 | pfL3fa | pfHasDcba
			.long   kHasAltivec | kCache32 | kDcbaAvailable | kDataStreamsRecommended | kDataStreamsAvailable | kHasGraphicsOps | kHasStfiwx
			.long	0
			.long	PatchExt32
			.long	init745X
			.long	CPU_SUBTYPE_POWERPC_7450
			.long	32
			.long	32*1024
			.long	32*1024
			.long	64
			.long	52
			.long	36

;	7455 (2.0)

			.align	2
			.long	0xFFFFFFFF		; Just revision 2.0
			.short	PROCESSOR_VERSION_7455
			.short	0x0200
			.long	pfFloat | pfAltivec | pfSMPcap | pfCanSleep | pfWillNap | pfNoMSRir | pfNoL2PFNap | pfLClck | pf32Byte | pfL2 | pfL2fa | pfL2i | pfL3 | pfL3fa | pfHasDcba
			.long   kHasAltivec | kCache32 | kDcbaAvailable | kDataStreamsRecommended | kDataStreamsAvailable | kHasGraphicsOps | kHasStfiwx
			.long	0
			.long	PatchExt32
			.long	init745X
			.long	CPU_SUBTYPE_POWERPC_7450
			.long	32
			.long	32*1024
			.long	32*1024
			.long	64
			.long	52
			.long	36

;	7455 (2.1)

			.align	2
			.long	0xFFFF0000		; All other revisions
			.short	PROCESSOR_VERSION_7455
			.short	0
			.long	pfFloat | pfAltivec | pfSMPcap | pfCanSleep | pfCanNap | pfNoMSRir | pfNoL2PFNap | pfLClck | pf32Byte | pfL2 | pfL2fa | pfL2i | pfL3 | pfL3fa | pfHasDcba
			.long   kHasAltivec | kCache32 | kDcbaAvailable | kDataStreamsRecommended | kDataStreamsAvailable | kHasGraphicsOps | kHasStfiwx
			.long	0
			.long	PatchExt32
			.long	init745X
			.long	CPU_SUBTYPE_POWERPC_7450
			.long	32
			.long	32*1024
			.long	32*1024
			.long	64
			.long	52
			.long	36

;	7457

			.align	2
			.long	0xFFFF0000		; All revisions
			.short	PROCESSOR_VERSION_7457
			.short	0
			.long	pfFloat | pfAltivec | pfSMPcap | pfCanSleep | pfCanNap | pfNoMSRir | pfNoL2PFNap | pfLClck | pf32Byte | pfL2 | pfL2fa | pfL2i | pfL3 | pfL3fa | pfHasDcba
			.long   kHasAltivec | kCache32 | kDcbaAvailable | kDataStreamsRecommended | kDataStreamsAvailable | kHasGraphicsOps | kHasStfiwx
			.long	0
			.long	PatchExt32
			.long	init745X
			.long	CPU_SUBTYPE_POWERPC_7450
			.long	32
			.long	32*1024
			.long	32*1024
			.long	64
			.long	52
			.long	36

;	7447A

			.align	2
			.long	0xFFFF0000		; All revisions
			.short	PROCESSOR_VERSION_7447A
			.short	0
			.long	pfFloat | pfAltivec | pfSMPcap | pfCanSleep | pfCanNap | pfNoMSRir | pfNoL2PFNap | pfLClck | pf32Byte | pfL2 | pfL2fa | pfL2i | pfL3 | pfL3fa | pfHasDcba
			.long   kHasAltivec | kCache32 | kDcbaAvailable | kDataStreamsRecommended | kDataStreamsAvailable | kHasGraphicsOps | kHasStfiwx
			.long	pmDFS
			.long	PatchExt32
			.long	init745X
			.long	CPU_SUBTYPE_POWERPC_7450
			.long	32
			.long	32*1024
			.long	32*1024
			.long	64
			.long	52
			.long	36

;	970

			.align	2
			.long	0xFFFF0000		; All versions so far
			.short	PROCESSOR_VERSION_970
			.short	0
			.long	pfFloat | pfAltivec | pfSMPcap | pfCanSleep | pfCanNap | pf128Byte | pf64Bit | pfL2 | pfSCOMFixUp
			.long   kHasAltivec | k64Bit | kCache128 | kDataStreamsAvailable | kDcbtStreamsRecommended | kDcbtStreamsAvailable | kHasGraphicsOps | kHasStfiwx | kHasFsqrt
			.long	0
			.long	PatchLwsync
			.long	init970
			.long	CPU_SUBTYPE_POWERPC_970
			.long	128
			.long	64*1024
			.long	32*1024
			.long	128
			.long	65
			.long	42

;	970FX

			.align	2
			.long	0xFFFF0000		; All versions so far
			.short	PROCESSOR_VERSION_970FX
			.short	0
			.long	pfFloat | pfAltivec | pfSMPcap | pfCanSleep | pfCanNap | pf128Byte | pf64Bit | pfL2
			.long   kHasAltivec | k64Bit | kCache128 | kDataStreamsAvailable | kDcbtStreamsRecommended | kDcbtStreamsAvailable | kHasGraphicsOps | kHasStfiwx | kHasFsqrt
			.long	pmPowerTune
			.long	PatchLwsync
			.long	init970
			.long	CPU_SUBTYPE_POWERPC_970
			.long	128
			.long	64*1024
			.long	32*1024
			.long	128
			.long	65
			.long	42


;	All other processors are not supported

			.align	2
			.long	0x00000000		; Matches everything
			.short	0
			.short	0
			.long	pfFloat | pf32Byte
			.long   kCache32 | kHasGraphicsOps | kHasStfiwx
			.long	0
			.long	PatchExt32
			.long	initUnsupported
			.long	CPU_SUBTYPE_POWERPC_ALL
			.long	32
			.long	32*1024
			.long	32*1024
			.long	64
			.long	52
			.long	32


/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
#include <cpus.h>
#include <mach_kdb.h>
#include <mach_kdp.h>
#include <mach_kgdb.h>
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <ppc/spec_reg.h>
#include <mach/ppc/vm_param.h>
#include <assym.s>
	
#define ptFilter 0
#define ptVersion 4
#define ptRevision 6
#define ptFeatures 8
#define ptInitRout 12
#define ptRptdProc 16
#define ptTempMax 20
#define ptTempThr 24
#define ptLineSize 28
#define ptl1iSize 32
#define ptl1dSize 36
#define ptSize 40

#define bootCPU 10
#define firstInit 9
#define firstBoot 8

/* Defines for PVRs */
#define PROCESSOR_VERSION_601		1
#define PROCESSOR_VERSION_603		3
#define PROCESSOR_VERSION_604		4
#define PROCESSOR_VERSION_603e		6
#define PROCESSOR_VERSION_750		8
#define PROCESSOR_VERSION_750FX		0x7000  /* ? */
#define PROCESSOR_VERSION_604e		9
#define PROCESSOR_VERSION_604ev		10	/* ? */
#define PROCESSOR_VERSION_7400		12	/* ? */
#define PROCESSOR_VERSION_7410		0x800C	/* ? */
#define PROCESSOR_VERSION_7450		0x8000	/* ? */
#define PROCESSOR_VERSION_7455		0x8001	/* ? */

/*
 * Interrupt and bootup stack for initial processor
 */

	.file	"start.s"
	
	.data

		/* Align on page boundry */
	.align  PPC_PGSHIFT
		/* Red zone for interrupt stack, one page (will be unmapped)*/
	.set	., .+PPC_PGBYTES
		/* intstack itself */

     .globl  EXT(FixedStackStart)
EXT(FixedStackStart):
     
	 .globl  EXT(intstack)
EXT(intstack):
	.set	., .+INTSTACK_SIZE*NCPUS
	
	/* Debugger stack - used by the debugger if present */
	/* NOTE!!! Keep the debugger stack right after the interrupt stack */
#if MACH_KDP || MACH_KDB
    .globl  EXT(debstack)
EXT(debstack):
	.set	., .+KERNEL_STACK_SIZE*NCPUS
     
	 .globl  EXT(FixedStackEnd)
EXT(FixedStackEnd):

	.align	ALIGN
    .globl  EXT(intstack_top_ss)
EXT(intstack_top_ss):
	.long	EXT(intstack)+INTSTACK_SIZE-FM_SIZE			/* intstack_top_ss points to the top of interrupt stack */

	.align	ALIGN
    .globl  EXT(debstack_top_ss)	
EXT(debstack_top_ss):

	.long	EXT(debstack)+KERNEL_STACK_SIZE-FM_SIZE		/* debstack_top_ss points to the top of debug stack */

    .globl  EXT(debstackptr)
EXT(debstackptr):	
	.long	EXT(debstack)+KERNEL_STACK_SIZE-FM_SIZE

#endif /* MACH_KDP || MACH_KDB */

/*
 * All CPUs start here.
 *
 * This code is called from SecondaryLoader
 *
 * Various arguments are passed via a table:
 *   ARG0 = pointer to other startup parameters
 */
	.text
	
ENTRY(_start_cpu,TAG_NO_FRAME_USED)
			crclr	bootCPU								; Set non-boot processor
			crclr	firstInit							; Set not first time init
			mr		r30,r3								; Set current per_proc	
			
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

			lis		r30,hi16(EXT(per_proc_info))		; Set current per_proc
			ori		r30,r30,lo16(EXT(per_proc_info))	; Set current per_proc
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
			
allstart:	mr		r31,r3								; Save away arguments
			lis		r23,hi16(EXT(per_proc_info))		; Set base per_proc
			ori		r23,r23,lo16(EXT(per_proc_info))	; Set base per_proc

			mtsprg	0,r30								; Set the per_proc

			mfspr	r6,hid0								; Get the HID0
			li		r7,MSR_VM_OFF						; Get real mode MSR			
			rlwinm	r6,r6,0,sleep+1,doze-1				; Remove any vestiges of sleep
			mtspr	hid0,r6								; Set the insominac HID0
			mtmsr	r7									; Set the real mode SRR
			isync					

;			Map in the first 256Mb in both instruction and data BATs

			li		r7,((0x7FF<<2)|2)  					; Set up for V=R 256MB in supervisor space
			li      r8,((2<<3)|2)						; Physical address = 0, coherent, R/W
			li		r9,0								; Clear out a register
			
			mtsprg	1,r9								; Clear the extra SPRGs
			mtsprg	2,r9
			mtsprg	3,r9

			sync
			isync
			mtdbatu 0,r7								; Map bottom 256MB
			mtdbatl 0,r8								; Map bottom 256MB
			mtdbatu 1,r9								; Invalidate maps
			mtdbatl 1,r9								; Invalidate maps
			mtdbatu 2,r9								; Invalidate maps
			mtdbatl 2,r9								; Invalidate maps
			mtdbatu 3,r9								; Invalidate maps
			mtdbatl 3,r9								; Invalidate maps
			sync
			isync
			mtibatu 0,r7								; Map bottom 256MB
			mtibatl 0,r8								; Map bottom 256MB
			mtibatu 1,r9								; Invalidate maps
			mtibatl 1,r9								; Invalidate maps
			mtibatu 2,r9								; Invalidate maps
			mtibatl 2,r9								; Invalidate maps
			mtibatu 3,r9								; Invalidate maps
			mtibatl 3,r9								; Invalidate maps
			sync
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

			bf		firstInit,notFirst					; Not first boot, go...
			
;			
;			The following code just does a general initialization of the features just
;			after the initial first-time boot.  This is not done after waking up or on
;			any "secondary" processor.
;
;			We are just setting defaults.   The specific initialization code will modify these
;			if necessary. 
;			
			
			lwz		r17,ptFeatures(r26)					; Pick up the features
			
			lwz		r13,ptRptdProc(r26)					; Get the reported processor
			sth		r13,pfrptdProc(r30)					; Set the reported processor
			
			lwz		r13,ptTempMax(r26)					; Get maximum operating temperature
			stw		r13,thrmmaxTemp(r30)				; Set the maximum
			lwz		r13,ptTempThr(r26)					; Get temprature to throttle down when exceeded
			stw		r13,thrmthrottleTemp(r30)			; Set the temperature that we throttle
			
			lwz		r13,ptLineSize(r26)					; Get the cache line size
			sth		r13,pflineSize(r30)					; Save it
			lwz		r13,ptl1iSize(r26)					; Get icache size
			stw		r13,pfl1iSize(r30)					; Save it
			lwz		r13,ptl1dSize(r26)					; Get dcache size
			stw		r13,pfl1dSize(r30)					; Save it
			b		doOurInit							; Go do processor specific initialization...

notFirst:	lwz		r17,pfAvailable(r30)				; Get our features
			rlwinm.	r0,r17,0,pfValidb,pfValidb			; Have we set up this CPU yet?
			bne		doOurInit							; Yeah, must be wakeup...

			lis		r23,hi16(EXT(per_proc_info))		; Set base per_proc
			ori		r23,r23,lo16(EXT(per_proc_info))	; Set base per_proc
			
			la		r7,pfAvailable(r30)					; Point to features of our processor
			la		r8,pfAvailable(r23)					; Point to features of boot processor
			li		r9,(pfSize+thrmSize)/4				; Get size of a features area
			
cpyFeat:	subi	r9,r9,1								; Count word
			lwz		r0,0(r8)							; Get boot cpu features
			stw		r0,0(r7)							; Copy to ours
			mr.		r9,r9								; Finished?
			addi	r7,r7,4								; Next out
			addi	r8,r8,4								; Next in
			bgt		cpyFeat								; Copy all boot cpu features to us...
			
			lwz		r17,pfAvailable(r30)				; Get our newly initialized features			

doOurInit:	
			mr.		r20,r20								; See if initialization routine
			crand	firstBoot,bootCPU,firstInit			; Indicate if we are on the initial first processor startup
			bnelrl										; Do the initialization
			
			ori		r17,r17,lo16(pfValid)				; Set the valid bit
			stw		r17,pfAvailable(r30)				; Set the available features
			mtsprg	2,r17								; Remember the feature flags
			
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
			
			vspltisw	v1,0							; Clear a register
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

noVector:	rlwinm.	r0,r17,0,pfSMPcapb,pfSMPcapb		; See if we can do SMP
			beq-	noSMP								; Nope...
			
			lhz		r13,PP_CPU_NUMBER(r30)				; Get the CPU number
			mtspr	pir,r13								; Set the PIR
			
noSMP:		rlwinm.	r0,r17,0,pfThermalb,pfThermalb		; See if there is an TAU
			beq-	noThermometer						; Nope...

			li		r13,0								; Disable thermals for now
			mtspr	thrm3,r13							; Do it
			li		r13,lo16(thrmtidm|thrmvm)			; Set for lower-than thermal event at 0 degrees
			mtspr	thrm1,r13							; Do it
			lis		r13,hi16(thrmthrm)					; Set 127 degrees
			ori		r13,r13,lo16(thrmvm)				; Set for higher-than event 
			mtspr	thrm2,r13							; Set it

noThermometer:
			
			bl		EXT(cacheInit)						; Initializes all caches (including the TLB)
			
			li		r0,MSR_SUPERVISOR_INT_OFF			; Make sure we do not have FP enabled
			mtmsr	r0									; Set the standard MSR values
			isync
			
			bf		bootCPU,callcpu						; Not the boot processor...

			lis		r29,HIGH_ADDR(EXT(intstack_top_ss))	; move onto interrupt stack
			ori		r29,r29,LOW_ADDR(EXT(intstack_top_ss))
			lwz		r29,0(r29)

			li		r28,0
			stw		r28,FM_BACKPTR(r29) 				; store a null frame backpointer
	
			mr		r1,r29
			mr		r3,r31								; Restore any arguments we may have trashed

			bl	EXT(ppc_init)							; Jump into boot init code
			BREAKPOINT_TRAP

callcpu:
			lwz		r29,PP_INTSTACK_TOP_SS(r31)			; move onto interrupt stack

			li		r28,0
			stw		r28,FM_BACKPTR(r29) 				; store a null frame backpointer


			mr		r1,r29								; move onto new stack
			mr		r3,r31								; Restore any arguments we may have trashed

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
			rlwinm	r13,r13,4,28,31							; Isolate
			slw	r14,r14,r13							; Position
			rlwimi	r17,r14,15-pfCanNapb,pfCanNapb,pfCanNapb			; Set it			
			b	init750								; Join common...


;			750FX

init750FX:
			bf	firstBoot, init750FXnb
			mfspr	r11, hid1
			stw	r11, pfHID1(r30)						; Save the HID1 value
			b	init750

init750FXnb:
			lwz	r13, pfHID0(r30)						; Get HID0
			lwz	r11, pfHID1(r30)						; Get HID1

			rlwinm.	r0, r11, 0, hid1ps, hid1ps					; Isolate the hid1ps bit
			beq	init750FXnb2							; Clear BTIC if hid1ps set
			rlwinm	r13, r13, 0, btic+1, btic-1					; Clear the BTIC bit

init750FXnb2:
			sync
			mtspr	hid0, r13							; Set the HID
			isync
			sync

			rlwinm  r12, r11, 0, hid1ps+1, hid1ps-1					; Select PLL0
			mtspr	hid1, r12							; Restore PLL config
			mftb	r13								; Wait 5000 ticks (> 200 us)

init750FXnbloop:
			mftb	r14
			sub	r14, r14, r13
			cmpli	cr0, r14, 5000
			ble	init750FXnbloop
			mtspr	hid1, r11							; Select the desired PLL
			blr

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
			
			stw		r13,pfl2crOriginal(r30)					; Shadow the L2CR
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
			mtspr		l2cr,r11						; Make sure L2CR is zero
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
			bf		firstBoot,init745Xnb					; Do different if not initial boot...

			mfspr	r13,l2cr							; Get the L2CR
			rlwinm.	r0,r13,0,l2e,l2e					; Any L2?
			bne+	init745Xhl2							; Yes...
			rlwinm	r17,r17,0,pfL2b+1,pfL2b-1			; No L2, turn off feature
			
init745Xhl2:	lis		r14,hi16(256*1024)					; Base L2 size
			rlwinm	r15,r13,22,12,13					; Convert to 256k, 512k, or 768k
			add		r14,r14,r15							; Add in minimum
			
			stw		r13,pfl2crOriginal(r30)					; Shadow the L2CR
			stw		r13,pfl2cr(r30)						; Shadow the L2CR
			stw		r14,pfl2Size(r30)					; Set the L2 size
				
;			Take care of level 3 cache

			mfspr	r13,l3cr							; Get the L3CR
			rlwinm.	r0,r13,0,l3e,l3e					; Any L3?
			bne+	init745Xhl3							; Yes...
			rlwinm	r17,r17,0,pfL3b+1,pfL3b-1			; No L3, turn off feature

init745Xhl3:	cmplwi	cr0,r13,0							; No L3 if L3CR is zero
			beq-	init745Xnone							; Go turn off the features...
			lis		r14,hi16(1024*1024)					; Base L3 size
			rlwinm	r15,r13,4,31,31						; Get size multiplier
			slw		r14,r14,r15							; Set 1 or 2MB
			
			stw		r13,pfl3crOriginal(r30)					; Shadow the L3CR
			stw		r13,pfl3cr(r30)						; Shadow the L3CR
			stw		r14,pfl3Size(r30)					; Set the L3 size
			b		init745Xfin							; Return....
				
init745Xnone:
			rlwinm	r17,r17,0,pfL3fab+1,pfL3b-1					; No 3rd level cache or assist
			rlwinm	r11,r17,pfWillNapb-pfCanNapb,pfCanNapb,pfCanNapb		; Set pfCanNap if pfWillNap is set
			or	r17,r17,r11

init745Xfin:
			rlwinm	r17,r17,0,pfWillNapb+1,pfWillNapb-1				; Make sure pfWillNap is not set

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


;
;	Processor to feature table

;	.align	2				- Always on word boundary
;	.long	ptFilter		- Mask of significant bits in the Version/Revision code
;							- NOTE: Always order from most restrictive to least restrictive matching
;	.short	ptVersion		- Version code from PVR.  Always start with 0 which is default
;	.short	ptRevision		- Revision code from PVR. A zero value denotes the generic attributes if not specific
;	.long	ptFeatures		- Available features
;	.long	ptInitRout		- Initilization routine.  Can modify any of the other attributes.
;	.long	ptRptdProc		- Processor type reported
;	.long	ptTempMax		- Maximum operating temprature
;	.long	ptTempThr		- Temprature threshold. We throttle if above
;	.long	ptLineSize		- Level 1 cache line size
;	.long	ptl1iSize		- Level 1 instruction cache size
;	.long	ptl1dSize		- Level 1 data cache size
	
	.align	2
processor_types:

	
;	601 (generic)

	.align	2
	.long	0xFFFF0000		; All revisions
	.short	PROCESSOR_VERSION_601
	.short	0
	.long	pfFloat | pfSMPcap | pfL1i | pfL1d
	.long	0
	.long	CPU_SUBTYPE_POWERPC_ALL
	.long	0
	.long	0
	.long	32
	.long	32*1024
	.long	32*1024
	
;	603 (generic)

	.align	2
	.long	0xFFFF0000		; All revisions
	.short	PROCESSOR_VERSION_603
	.short	0
	.long	pfFloat | pfL1i | pfL1d
	.long	0
	.long	CPU_SUBTYPE_POWERPC_603
	.long	0
	.long	0
	.long	32
	.long	32*1024
	.long	32*1024
	
;	603e (generic)

	.align	2
	.long	0xFFFF0000		; All revisions
	.short	PROCESSOR_VERSION_603e
	.short	0
	.long	pfFloat | pfL1i | pfL1d
	.long	0
	.long	CPU_SUBTYPE_POWERPC_603e
	.long	0
	.long	0
	.long	32
	.long	32*1024
	.long	32*1024
	
;	604 (generic)

	.align	2
	.long	0xFFFF0000		; All revisions
	.short	PROCESSOR_VERSION_604
	.short	0
	.long	pfFloat | pfSMPcap | pfL1i | pfL1d
	.long	0
	.long	CPU_SUBTYPE_POWERPC_604
	.long	0
	.long	0
	.long	32
	.long	32*1024
	.long	32*1024
	
;	604e (generic)

	.align	2
	.long	0xFFFF0000		; All revisions
	.short	PROCESSOR_VERSION_604e
	.short	0
	.long	pfFloat | pfSMPcap | pfL1i | pfL1d
	.long	0
	.long	CPU_SUBTYPE_POWERPC_604e
	.long	0
	.long	0
	.long	32
	.long	32*1024
	.long	32*1024
	
;	604ev (generic)

	.align	2
	.long	0xFFFF0000		; All revisions
	.short	PROCESSOR_VERSION_604ev
	.short	0
	.long	pfFloat | pfSMPcap | pfL1i | pfL1d
	.long	0
	.long	CPU_SUBTYPE_POWERPC_604e
	.long	0
	.long	0
	.long	32
	.long	32*1024
	.long	32*1024

;       750 (ver 2.2)

        .align  2
        .long   0xFFFFFFFF              ; Exact match
        .short  PROCESSOR_VERSION_750
        .short  0x4202
        .long   pfFloat | pfCanSleep | pfCanNap | pfCanDoze | pfL1i | pfL1d | pfL2
        .long   init750
        .long   CPU_SUBTYPE_POWERPC_750
        .long   105
        .long   90
        .long   32
        .long   32*1024
        .long   32*1024

;       750CX (ver 2.x)

        .align  2
        .long   0xFFFF0F00              ; 2.x vers
        .short  PROCESSOR_VERSION_750
        .short  0x0200
        .long   pfFloat | pfCanSleep | pfCanNap | pfCanDoze | pfL1i | pfL1d | pfL2
        .long   init750CX
        .long   CPU_SUBTYPE_POWERPC_750
        .long   105
        .long   90
        .long   32
        .long   32*1024
        .long   32*1024
	
;	750 (generic)

	.align	2
	.long	0xFFFF0000		; All revisions
	.short	PROCESSOR_VERSION_750
	.short	0
	.long	pfFloat | pfCanSleep | pfCanNap | pfCanDoze | pfThermal | pfL1i | pfL1d | pfL2
	.long	init750
	.long	CPU_SUBTYPE_POWERPC_750
	.long	105
	.long	90
	.long	32
	.long	32*1024
	.long	32*1024
	
;       750FX (generic)

        .align  2
        .long   0xFFFF0000              ; All revisions
        .short  PROCESSOR_VERSION_750FX
        .short  0
        .long   pfFloat | pfCanSleep | pfCanNap | pfCanDoze | pfSlowNap | pfNoMuMMCK | pfL1i | pfL1d | pfL2
        .long   init750FX
        .long   CPU_SUBTYPE_POWERPC_750
        .long   105
        .long   90
        .long   32
        .long   32*1024
        .long   32*1024
	
;	7400 (ver 2.0 - ver 2.7)

	.align	2
	.long	0xFFFFFFF8		; All revisions
	.short	PROCESSOR_VERSION_7400
	.short	0x0200
	.long	pfFloat | pfAltivec | pfSMPcap | pfCanSleep | pfCanNap | pfCanDoze | pfThermal | pfL1i | pfL1d | pfL1fa | pfL2 | pfL2fa
	.long	init7400v2_7
	.long	CPU_SUBTYPE_POWERPC_7400
	.long	105
	.long	90
	.long	32
	.long	32*1024
	.long	32*1024
	
;	7400 (generic)

	.align	2
	.long	0xFFFF0000		; All revisions
	.short	PROCESSOR_VERSION_7400
	.short	0
	.long	pfFloat | pfAltivec | pfSMPcap | pfCanSleep | pfCanNap | pfCanDoze | pfThermal | pfL1i | pfL1d | pfL1fa | pfL2 | pfL2fa
	.long	init7400
	.long	CPU_SUBTYPE_POWERPC_7400
	.long	105
	.long	90
	.long	32
	.long	32*1024
	.long	32*1024
	
;	7410 (ver 1.1)

	.align	2
	.long	0xFFFFFFFF		; Exact match
	.short	PROCESSOR_VERSION_7400
	.short	0x1101
	.long	pfFloat | pfAltivec | pfSMPcap | pfCanSleep | pfCanNap | pfCanDoze | pfL1i | pfL1d | pfL1fa | pfL2 | pfL2fa
	.long	init7410
	.long	CPU_SUBTYPE_POWERPC_7400
	.long	105
	.long	90
	.long	32
	.long	32*1024
	.long	32*1024

;	7410 (generic)

	.align	2
	.long	0xFFFF0000		; All other revisions
	.short	PROCESSOR_VERSION_7410
	.short	0
	.long	pfFloat | pfAltivec | pfSMPcap | pfCanSleep | pfCanNap | pfCanDoze | pfL1i | pfL1d | pfL1fa | pfL2 | pfL2fa
	.long	init7410
	.long	CPU_SUBTYPE_POWERPC_7400
	.long	105
	.long	90
	.long	32
	.long	32*1024
	.long	32*1024

;	7450 (ver 1.xx)

	.align	2
	.long	0xFFFFFF00		; Just revisions 1.xx
	.short	PROCESSOR_VERSION_7450
	.short	0x0100
	.long	pfFloat | pfAltivec | pfSMPcap | pfCanSleep | pfNoMSRir | pfNoL2PFNap | pfLClck | pfL1i | pfL1d | pfL2 | pfL2fa | pfL2i | pfL3 | pfL3fa
	.long	init7450
	.long	CPU_SUBTYPE_POWERPC_7450
	.long	105
	.long	90
	.long	32
	.long	32*1024
	.long	32*1024

;	7450 (2.0)

	.align	2
	.long	0xFFFFFFFF		; Just revision 2.0
	.short	PROCESSOR_VERSION_7450
	.short	0x0200
	.long	pfFloat | pfAltivec | pfSMPcap | pfCanSleep | pfNoMSRir | pfNoL2PFNap | pfLClck | pfL1i | pfL1d | pfL2 | pfL2fa | pfL2i | pfL3 | pfL3fa
	.long	init7450
	.long	CPU_SUBTYPE_POWERPC_7450
	.long	105
	.long	90
	.long	32
	.long	32*1024
	.long	32*1024

;	7450 (2.1)

	.align	2
	.long	0xFFFF0000		; All other revisions
	.short	PROCESSOR_VERSION_7450
	.short	0
	.long	pfFloat | pfAltivec | pfSMPcap | pfCanSleep | pfWillNap | pfNoMSRir | pfNoL2PFNap | pfLClck | pfL1i | pfL1d | pfL2 | pfL2fa | pfL2i | pfL3 | pfL3fa
	.long	init7450
	.long	CPU_SUBTYPE_POWERPC_7450
	.long	105
	.long	90
	.long	32
	.long	32*1024
	.long	32*1024

;	7455 (1.xx)  Just like 7450 2.0

	.align	2
	.long	0xFFFFFF00		; Just revisions 1.xx
	.short	PROCESSOR_VERSION_7455
	.short	0x0100
	.long	pfFloat | pfAltivec | pfSMPcap | pfCanSleep | pfNoMSRir | pfNoL2PFNap | pfLClck | pfL1i | pfL1d | pfL2 | pfL2fa | pfL2i | pfL3 | pfL3fa
	.long	init745X
	.long	CPU_SUBTYPE_POWERPC_7450
	.long	105
	.long	90
	.long	32
	.long	32*1024
	.long	32*1024

;	7455 (2.0)

	.align	2
	.long	0xFFFFFFFF		; Just revision 2.0
	.short	PROCESSOR_VERSION_7455
	.short	0x0200
	.long	pfFloat | pfAltivec | pfSMPcap | pfCanSleep | pfWillNap | pfNoMSRir | pfNoL2PFNap | pfLClck | pfL1i | pfL1d | pfL2 | pfL2fa | pfL2i | pfL3 | pfL3fa
	.long	init745X
	.long	CPU_SUBTYPE_POWERPC_7450
	.long	105
	.long	90
	.long	32
	.long	32*1024
	.long	32*1024

;	7455 (2.1)

	.align	2
	.long	0xFFFF0000		; All other revisions
	.short	PROCESSOR_VERSION_7455
	.short	0
	.long	pfFloat | pfAltivec | pfSMPcap | pfCanSleep | pfCanNap | pfNoMSRir | pfNoL2PFNap | pfLClck | pfL1i | pfL1d | pfL2 | pfL2fa | pfL2i | pfL3 | pfL3fa
	.long	init745X
	.long	CPU_SUBTYPE_POWERPC_7450
	.long	105
	.long	90
	.long	32
	.long	32*1024
	.long	32*1024

;	Default dumb loser machine

	.align	2
	.long	0x00000000		; Matches everything
	.short	0
	.short	0
	.long	pfFloat | pfL1i | pfL1d
	.long	0
	.long	CPU_SUBTYPE_POWERPC_ALL
	.long	105
	.long	90
	.long	32
	.long	32*1024
	.long	32*1024

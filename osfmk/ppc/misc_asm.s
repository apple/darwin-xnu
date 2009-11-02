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
/*
 * @OSF_COPYRIGHT@
 */

#include <mach_kdb.h>
#include <mach_kgdb.h>
#include <mach_debug.h>
#include <assym.s>
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <mach/ppc/vm_param.h>

/*
 * vm_offset_t getrpc(void) - Return address of the function
 *	                      that called the current function
 */

/* By using this function, we force the caller to save its LR in a known
 * location, which we can pick up and return. See PowerPC ELF specs.
 */
ENTRY(getrpc, TAG_NO_FRAME_USED)
	lwz	ARG0,	FM_BACKPTR(r1)		/* Load our backchain ptr */
	lwz	ARG0,	FM_LR_SAVE(ARG0)	/* Load previously saved LR */
	blr					/* And return */


/*
 *	General entry for all debuggers.  This gets us onto the debug stack and
 *	then back off at exit. We need to pass back R3 to caller.
 */
 
ENTRY(Call_Debugger, TAG_NO_FRAME_USED)


			lis		r8,hi16(MASK(MSR_VEC))			; Get the vector flag
			mfmsr	r7				; Get the current MSR
			ori		r8,r8,lo16(MASK(MSR_EE)|MASK(MSR_FP))	; Add the FP flag
			mflr	r0				; Save the return
			andc	r7,r7,r8						; Clear VEC and FP
			mtmsr	r7				; Do it 
			isync
			mfsprg	r8,1					; Get the current activation
			lwz		r8,ACT_PER_PROC(r8)		; Get the per_proc block
			stw		r0,FM_LR_SAVE(r1)	; Save return on current stack
			
			lwz		r9,PP_DEBSTACKPTR(r8)	; Get the debug stack
			cmpwi	r9,0			; Are we already on it?
			bne		cdNewDeb		; No...
		
			mr		r9,r1 			; We are already on the stack, so use the current value
			subi	r9,r9,FM_REDZONE+FM_SIZE	; Carve some extra space here
		
cdNewDeb:	li		r0,0			; Clear this out
			stw		r1,FM_ARG0(r9)	; Save the old stack pointer as if it were the first arg

			stw		r0,PP_DEBSTACKPTR(r8)	; Mark debug stack as busy
			
			subi	r1,r9,FM_SIZE	; Carve a new frame
			stw		r0,FM_BACKPTR(r1)	; Chain back
			
			bl		EXT(Call_DebuggerC)	; Call the "C" phase of this
		
			lis		r8,hi16(MASK(MSR_VEC))			; Get the vector flag
			mfmsr	r0				; Get the current MSR
			ori		r8,r8,lo16(MASK(MSR_EE)|MASK(MSR_FP))	; Add the FP flag
			addi	r1,r1,FM_SIZE	; Pop off first stack frame
			andc	r0,r0,r8		; Turn off all the interesting stuff
			mtmsr	r0
		
			mfsprg	r8,1					; Get the current activation
			lwz		r8,ACT_PER_PROC(r8)		; Get the per_proc block
			
			lwz		r9,PP_DEBSTACK_TOP_SS(r8)	; Get the top of the stack
			cmplw	r1,r9			; Have we hit the bottom of the debug stack?
			lwz		r1,FM_ARG0(r1)	; Get previous stack frame
			lwz		r0,FM_LR_SAVE(r1)	; Get return address
			mtlr	r0				; Set the return point
			bnelr					; Return if still on debug stack

			stw		r9,PP_DEBSTACKPTR(r8)	; Mark debug stack as free		
			blr
 

/* The following routines are for C-support. They are usually
 * inlined into the C using the specifications in proc_reg.h,
 * but if optimisation is switched off, the inlining doesn't work
 */

ENTRY(get_got, TAG_NO_FRAME_USED)
	mr	ARG0,	r2
	blr
	
ENTRY(mflr, TAG_NO_FRAME_USED)
	mflr	ARG0
	blr

ENTRY(mfpvr, TAG_NO_FRAME_USED)
	mfpvr	ARG0
	blr

ENTRY(mtmsr, TAG_NO_FRAME_USED)
	mtmsr	ARG0
	isync
	blr

ENTRY(mfmsr, TAG_NO_FRAME_USED)
	mfmsr	ARG0
	blr

ENTRY(mtsrin, TAG_NO_FRAME_USED)
	isync
	mtsrin	ARG0,	ARG1
	isync
	blr

ENTRY(mfsrin, TAG_NO_FRAME_USED)
	mfsrin	ARG0,	ARG0
	blr

ENTRY(mtsdr1, TAG_NO_FRAME_USED)
	mtsdr1	ARG0
	blr

ENTRY(mtdar, TAG_NO_FRAME_USED)
	mtdar	ARG0
	blr

ENTRY(mfdar, TAG_NO_FRAME_USED)
	mfdar	ARG0
	blr

ENTRY(mtdec, TAG_NO_FRAME_USED)
	mtdec	ARG0
	blr

ENTRY(cntlzw, TAG_NO_FRAME_USED)
	cntlzw	r3,r3
	blr

/* Decrementer frequency and realtime|timebase processor registers
 * are different between ppc601 and ppc603/4, we define them all.
 */

ENTRY(isync_mfdec, TAG_NO_FRAME_USED)
	isync
	mfdec	ARG0
	blr


ENTRY(mftb, TAG_NO_FRAME_USED)
	mftb	ARG0
	blr

ENTRY(mftbu, TAG_NO_FRAME_USED)
	mftbu	ARG0
	blr

ENTRY(mfrtcl, TAG_NO_FRAME_USED)
	mfspr	ARG0,	5
	blr

ENTRY(mfrtcu, TAG_NO_FRAME_USED)
	mfspr	ARG0,	4
	blr

ENTRY(tlbie, TAG_NO_FRAME_USED)
	tlbie	ARG0
	blr


/*
 * Performance Monitor Register Support
 */	

ENTRY(mfmmcr0, TAG_NO_FRAME_USED)	
	mfspr	r3,mmcr0
	blr

ENTRY(mtmmcr0, TAG_NO_FRAME_USED)
	mtspr	mmcr0,r3
	blr								

ENTRY(mfmmcr1, TAG_NO_FRAME_USED)
	mfspr	r3,mmcr1
	blr								

ENTRY(mtmmcr1, TAG_NO_FRAME_USED)
	mtspr	mmcr1,r3
	blr

ENTRY(mfmmcr2, TAG_NO_FRAME_USED)
	mfspr	r3,mmcr2
	blr								

ENTRY(mtmmcr2, TAG_NO_FRAME_USED)
	mtspr	mmcr2,r3
	blr

ENTRY(mfpmc1, TAG_NO_FRAME_USED)
	mfspr	r3,pmc1
	blr

ENTRY(mtpmc1, TAG_NO_FRAME_USED)
	mtspr	pmc1,r3
	blr								

ENTRY(mfpmc2, TAG_NO_FRAME_USED)
	mfspr	r3,pmc2
	blr

ENTRY(mtpmc2, TAG_NO_FRAME_USED)
	mtspr	pmc2,r3
	blr								

ENTRY(mfpmc3, TAG_NO_FRAME_USED)
	mfspr	r3,pmc3
	blr

ENTRY(mtpmc3, TAG_NO_FRAME_USED)
	mtspr	pmc3,r3
	blr								

ENTRY(mfpmc4, TAG_NO_FRAME_USED)
	mfspr	r3,pmc4
	blr

ENTRY(mtpmc4, TAG_NO_FRAME_USED)
	mtspr	pmc4,r3
	blr			
						
ENTRY(mfsia, TAG_NO_FRAME_USED)
	mfspr	r3,sia
	blr

ENTRY(mfsda, TAG_NO_FRAME_USED)
	mfspr	r3,sda
	blr

	.globl	EXT(hid1get)
LEXT(hid1get)

	mfspr	r3,hid1					; Get the HID1
	blr

	.globl	EXT(hid0get64)
LEXT(hid0get64)

	mfspr	r4,hid0					; Get the HID0
	srdi	r3,r4,32				; Move top down
	rlwinm	r4,r4,0,0,31			; Clean top
	blr

	.globl	EXT(hid5set64)
LEXT(hid5set64)

	rlwinm	r3,r3,0,1,0				; Copy low 32 int high 32
	rlwimi	r3,r4,0,0,31			; Inser the low part behind top
	mtspr	hid5,r3					; Set it
	isync							; Wait for it
	blr

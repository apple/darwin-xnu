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
/*
 * @OSF_COPYRIGHT@
 */

/*
 * Low-memory exception vector code for PowerPC MACH
 *
 * These are the only routines that are ever run with
 * VM instruction translation switched off.
 *
 * The PowerPC is quite strange in that rather than having a set
 * of exception vectors, the exception handlers are installed
 * in well-known addresses in low memory. This code must be loaded
 * at ZERO in physical memory. The simplest way of doing this is
 * to load the kernel at zero, and specify this as the first file
 * on the linker command line.
 *
 * When this code is loaded into place, it is loaded at virtual
 * address KERNELBASE, which is mapped to zero (physical).
 *
 * This code handles all powerpc exceptions and is always entered
 * in supervisor mode with translation off. It saves the minimum
 * processor state before switching back on translation and
 * jumping to the approprate routine.
 *
 * Vectors from 0x100 to 0x3fff occupy 0x100 bytes each (64 instructions)
 *
 * We use some of this space to decide which stack to use, and where to
 * save the context etc, before	jumping to a generic handler.
 */

#include <assym.s>
#include <debug.h>
#include <cpus.h>
#include <db_machine_commands.h>
#include <mach_rt.h>
	
#include <mach_debug.h>
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <ppc/exception.h>
#include <ppc/Performance.h>
#include <ppc/savearea.h>
#include <mach/ppc/vm_param.h>

#define TRCSAVE 0
#define CHECKSAVE 0
#define PERFTIMES 0
#define ESPDEBUG 0

#if TRCSAVE
#error The TRCSAVE option is broken.... Fix it
#endif

#define featL1ena 24
#define featSMP 25
#define featAltivec 26
#define wasNapping 27
#define featFP 28
#define specAccess 29

#define	VECTOR_SEGMENT	.section __VECTORS, __interrupts

			VECTOR_SEGMENT


			.globl EXT(ExceptionVectorsStart)

EXT(ExceptionVectorsStart):							/* Used if relocating the exception vectors */
baseR:												/* Used so we have more readable code */

/* 
 * System reset - call debugger
 */
			. = 0xf0
			.globl	EXT(ResetHandler)
EXT(ResetHandler):
			.long	0x0
			.long	0x0
			.long	0x0

			. = 0x100
.L_handler100:
			mtsprg	2,r13			/* Save R13 */
			mtsprg	3,r11			/* Save R11 */
			lwz		r13,lo16(EXT(ResetHandler)-EXT(ExceptionVectorsStart)+RESETHANDLER_TYPE)(br0)	; Get reset type
			mfcr	r11
			cmpi	cr0,r13,RESET_HANDLER_START
			bne		resetexc

			li		r11,RESET_HANDLER_NULL
			stw		r11,lo16(EXT(ResetHandler)-EXT(ExceptionVectorsStart)+RESETHANDLER_TYPE)(br0)	; Clear reset type

			lwz		r4,lo16(EXT(ResetHandler)-EXT(ExceptionVectorsStart)+RESETHANDLER_CALL)(br0)
			lwz		r3,lo16(EXT(ResetHandler)-EXT(ExceptionVectorsStart)+RESETHANDLER_ARG)(br0)
			mtlr	r4
			blr

resetexc:
			mtcr	r11
			li		r11,T_RESET						/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			Machine check 
 */

			. = 0x200
.L_handler200:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_MACHINE_CHECK				/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			Data access - page fault, invalid memory rights for operation
 */

			. = 0x300
.L_handler300:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_DATA_ACCESS				/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			Instruction access - as for data access
 */

			. = 0x400
.L_handler400:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_INSTRUCTION_ACCESS		/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			External interrupt
 */

			. = 0x500
.L_handler500:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_INTERRUPT					/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			Alignment - many reasons
 */

			. = 0x600
.L_handler600:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_ALIGNMENT|T_FAM			/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			Program - floating point exception, illegal inst, priv inst, user trap
 */

			. = 0x700
.L_handler700:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_PROGRAM|T_FAM				/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			Floating point disabled
 */

			. = 0x800
.L_handler800:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_FP_UNAVAILABLE			/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */


/*
 * 			Decrementer - DEC register has passed zero.
 */

			. = 0x900
.L_handler900:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_DECREMENTER				/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			I/O controller interface error - MACH does not use this
 */

			. = 0xA00
.L_handlerA00:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_IO_ERROR					/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			Reserved
 */

			. = 0xB00
.L_handlerB00:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_RESERVED					/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

#if 0
hackxxxx1:
			stmw	r29,4(br0)
			lwz		r29,0(br0)
			mr.		r29,r29
			bne+	xxxx1
			lis		r29,0x4000

xxxx1:			
			stw		r0,0(r29)
			mfsrr0	r30
			stw		r30,4(r29)
			mtlr	r30
			stw		r30,8(r29)

			addi	r29,r29,12
			stw		r29,0(br0)

			lmw		r29,4(br0)
			b		hackxxxx2
#endif			


;
; 			System call - generated by the sc instruction
;
;			We handle the ultra-fast traps right here. They are:
;			
;				0xFFFFFFFF - BlueBox only - MKIsPreemptiveTask
;				0xFFFFFFFE - BlueBox only - kcNKIsPreemptiveTaskEnv
;				0x00007FF2 - User state only - thread info
;				0x00007FF3 - User state only - floating point / vector facility status
;				0x00007FF4 - Kernel only - loadMSR
;
;			Note: none handled if virtual machine is running
;				  Also, it we treat SCs as kernel SCs if the RI bit is set
;

			. = 0xC00
.L_handlerC00:
			mtsprg	2,r13							; Save R13
			mfsrr1	r13								; Get SRR1 for loadMSR
			mtsprg	3,r11							; Save R11
			rlwimi	r13,r13,MSR_PR_BIT,0,0			; Move PR bit to non-volatile CR0 bit 0
			mfcr	r11								; Save the CR
			mtcrf	0x81,r13						; Get the moved PR and the RI for testing
			crnot	0,0								; Get !PR
			cror	0,0,MSR_RI_BIT					; See if we have !PR or RI
			mfsprg	r13,0							; Get the per_proc_area
			bt-		0,uftInKern						; We are in the kernel...
			
			lwz		r13,spcFlags(r13)				; Get the special flags
			rlwimi	r13,r13,runningVMbit+1,31,31	; Move VM flag after the 3 blue box flags
			mtcrf	1,r13							; Set BB and VMM flags in CR7
			bt-		31,ufpVM						; fast paths running VM ...
			cmplwi	cr5,r0,0x7FF2					; Ultra fast path cthread info call?
			cmpwi	cr6,r0,0x7FF3					; Ultra fast path facility status?
			cror	cr1_eq,cr5_lt,cr6_gt			; Set true if not 0x7FF2 and not 0x7FF3 and not negative
			bt-		cr1_eq,notufp					; Exit if we can not be ultra fast...
			
			not.	r0,r0							; Flip bits and kind of subtract 1			

			cmplwi	cr1,r0,1						; Is this a bb fast path?
			not		r0,r0							; Restore to entry state			
			bf-		bbNoMachSCbit,ufpUSuft			; We are not running BlueBox...
			bgt		cr1,notufp						; This can not be a bb ufp...
#if 0
			b		hackxxxx1
hackxxxx2:
#endif			
			
			rlwimi	r11,r13,bbPreemptivebit-cr0_eq,cr0_eq,cr0_eq	; Copy preemptive task flag into user cr0_eq
			mfsprg	r13,0							; Get back pre_proc
			
			
			bne		cr1,ufpIsBBpre					; This is the "isPreemptiveTask" call...
			
			lwz		r0,ppbbTaskEnv(r13)				; Get the shadowed taskEnv from per_proc_area

ufpIsBBpre:	
			mtcrf	0xFF,r11						; Restore CR
			mfsprg	r11,3							; Restore R11
			mfsprg	r13,2							; Restore R13
			rfi										; All done, go back...
			
;
;			Normal fast path...
;
	
ufpUSuft:	bge+	notufp							; Bail if negative...  (ARRRGGG -- BRANCH TO A BRANCH!!!!!)
			mfsprg	r11,3							; Restore R11
			mfsprg	r3,0							; Get the per_proc_area
			mfsprg	r13,2							; Restore R13
			bne-	cr5,isvecfp						; This is the facility stat call
			lwz		r3,UAW(r3)						; Get the assist word
			rfi										; All done, scream back... (no need to restore CR or R11, they are volatile)
;
isvecfp:	lwz		r3,spcFlags(r3)					; Get the facility status
			rfi										; Bail back...
;
notufp:		mtcrf	0xFF,r11						; Restore the used CRs
			li		r11,T_SYSTEM_CALL|T_FAM			; Set interrupt code
			b		.L_exception_entry				; Join common...
			
uftInKern:	cmplwi	r0,0x7FF4						; Ultra fast path loadMSR?
			bne-	notufp							; Someone is trying to cheat...
			
			mtcrf	0xFF,r11						; Restore CR
			lwz		r11,pfAvailable(r13)			; Pick up the feature flags
			mtsrr1	r3								; Set new MSR
			mfsprg	r13,2							; Restore R13
			mtsprg	2,r11							; Set the feature flags into sprg2
			mfsprg	r11,3							; Restore R11
			rfi										; Blast back
			

/*
 * 			Trace - generated by single stepping
 *				performance monitor BE branch enable tracing/logging
 *				is also done here now.  while this is permanently in the
 *				system the impact is completely unnoticable as this code is
 *				only executed when (a) a single step or branch exception is
 *				hit, (b) in the single step debugger case there is so much
 *				overhead already the few extra instructions for testing for BE
 *				are not even noticable, (c) the BE logging code is *only* run
 *				when it is enabled by the tool which will not happen during
 *				normal system usage
 *
 *			Note that this trace is available only to user state so we do not 
 *			need to set sprg2 before returning.
 */

			. = 0xD00
.L_handlerD00:
			mtsprg	2,r13							; Save R13
			mtsprg	3,r11							; Save R11
			mfsrr1	r13								; Get the old MSR
			mfcr	r11								; Get the CR
			rlwinm.	r13,r13,0,MSR_PR_BIT,MSR_PR_BIT	; Are we in supervisor state?
			beq-	notspectr						; Yes, not special trace...
			mfsprg	r13,0							; Get the per_proc area
			lhz		r13,PP_CPU_FLAGS(r13)			; Get the flags
			rlwinm.	r13,r13,0,traceBEb+16,traceBEb+16	; Special trace enabled?
			bne+	specbrtr						; Yeah...

notspectr:	mtcr	r11								; Restore CR
			li		r11,T_TRACE|T_FAM				; Set interrupt code
			b		.L_exception_entry				; Join common...

;
;			We are doing the special branch trace
;

specbrtr:	mfsprg	r13,0							; Get the per_proc area
			stw		r1,emfp0(r13)					; Save in a scratch area
			stw		r2,emfp0+4(r13)					; Save in a scratch area
			stw		r3,emfp0+8(r13)					; Save in a scratch area

			lis		r2,hi16(EXT(pc_trace_buf))		; Get the top of the buffer
			lwz		r3,spcTRp(r13)					; Pick up buffer position			
			mr.		r1,r1							; Is it time to count?
			ori		r2,r2,lo16(EXT(pc_trace_buf))	; Get the bottom of the buffer
			cmplwi	cr1,r3,4092						; Set cr1_eq if we should take exception			
			mfsrr0	r1								; Get the pc
			stwx	r1,r2,r3						; Save it in the buffer
			addi	r3,r3,4							; Point to the next slot
			rlwinm	r3,r3,0,20,31					; Wrap the slot at one page
			stw		r3,spcTRp(r13)					; Save the new slot
			lwz		r1,emfp0(r13)					; Restore work register
			lwz		r2,emfp0+4(r13)					; Restore work register
			lwz		r3,emfp0+8(r13)					; Restore work register
			beq		cr1,notspectr					; Buffer filled, make a rupt...
			
			mtcr	r11								; Restore the CR
			mfsprg	r13,2							; Restore R13
			mfsprg	r11,3							; Restore R11
			rfi										; Bail back...

/*
 * 			Floating point assist
 */

			. = 0xe00
.L_handlerE00:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_FP_ASSIST					/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */


/*
 *			Performance monitor interruption
 */

 			. = 0xF00
PMIhandler:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_PERF_MON					/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */
	

/*
 *			VMX exception
 */

 			. = 0xF20
VMXhandler:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_VMX						/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

	

/*
 * Instruction translation miss - we inline this code.
 * Upon entry (done for us by the machine):
 *     srr0 :	 addr of instruction that missed
 *     srr1 :	 bits 0-3   = saved CR0
 *                    4     = lru way bit
 *                    16-31 = saved msr
 *     msr[tgpr] = 1  (so gpr0-3 become our temporary variables)
 *     imiss:	 ea that missed
 *     icmp :	 the compare value for the va that missed
 *     hash1:	 pointer to first hash pteg
 *     hash2:	 pointer to 2nd hash pteg
 *
 * Register usage:
 *     tmp0:	 saved counter
 *     tmp1:	 junk
 *     tmp2:	 pointer to pteg
 *     tmp3:	 current compare value
 *
 * This code is taken from the 603e User's Manual with
 * some bugfixes and minor improvements to save bytes and cycles
 *
 *	NOTE: Do not touch sprg2 in here
 */

	. = 0x1000
.L_handler1000:
	mfspr	tmp2,	hash1
	mfctr	tmp0				/* use tmp0 to save ctr */
	mfspr	tmp3,	icmp

.L_imiss_find_pte_in_pteg:
	li	tmp1,	8			/* count */
	subi	tmp2,	tmp2,	8		/* offset for lwzu */
	mtctr	tmp1				/* count... */
	
.L_imiss_pteg_loop:
	lwz	tmp1,	8(tmp2)			/* check pte0 for match... */
	addi	tmp2,	tmp2,	8
	cmpw	cr0,	tmp1,	tmp3
#if 0	
	bdnzf+	cr0,	.L_imiss_pteg_loop
#else	
	bc	0,2,	.L_imiss_pteg_loop
#endif	
	beq+	cr0,	.L_imiss_found_pte

	/* Not found in PTEG, we must scan 2nd then give up */

	andi.	tmp1,	tmp3,	MASK(PTE0_HASH_ID)
	bne-	.L_imiss_do_no_hash_exception		/* give up */

	mfspr	tmp2,	hash2
	ori	tmp3,	tmp3,	MASK(PTE0_HASH_ID)
	b	.L_imiss_find_pte_in_pteg

.L_imiss_found_pte:

	lwz	tmp1,	4(tmp2)				/* get pte1_t */
	andi.	tmp3,	tmp1,	MASK(PTE1_WIMG_GUARD)	/* Fault? */
	bne-	.L_imiss_do_prot_exception		/* Guarded - illegal */

	/* Ok, we've found what we need to, restore and rfi! */

	mtctr	tmp0					/* restore ctr */
	mfsrr1	tmp3
	mfspr	tmp0,	imiss
	mtcrf	0x80,	tmp3				/* Restore CR0 */
	mtspr	rpa,	tmp1				/* set the pte */
	ori	tmp1,	tmp1,	MASK(PTE1_REFERENCED)	/* set referenced */
	tlbli	tmp0
	sth	tmp1,	6(tmp2)
	rfi
	
.L_imiss_do_prot_exception:
	/* set up srr1 to indicate protection exception... */
	mfsrr1	tmp3
	andi.	tmp2,	tmp3,	0xffff
	addis	tmp2,	tmp2,	MASK(SRR1_TRANS_PROT) >> 16
	b	.L_imiss_do_exception
	
.L_imiss_do_no_hash_exception:
	/* clean up registers for protection exception... */
	mfsrr1	tmp3
	andi.	tmp2,	tmp3,	0xffff
	addis	tmp2,	tmp2,	MASK(SRR1_TRANS_HASH) >> 16
	
	/* And the entry into the usual instruction fault handler ... */
.L_imiss_do_exception:

	mtctr	tmp0					/* Restore ctr */
	mtsrr1	tmp2					/* Set up srr1 */
	mfmsr	tmp0					
	xoris	tmp0,	tmp0,	MASK(MSR_TGPR)>>16	/* no TGPR */
	mtcrf	0x80,	tmp3				/* Restore CR0 */
	mtmsr	tmp0					/* reset MSR[TGPR] */
	b	.L_handler400				/* Instr Access */
	
/*
 * Data load translation miss
 *
 * Upon entry (done for us by the machine):
 *     srr0 :	 addr of instruction that missed
 *     srr1 :	 bits 0-3   = saved CR0
 *                    4     = lru way bit
 *                    5     = 1 if store
 *                    16-31 = saved msr
 *     msr[tgpr] = 1  (so gpr0-3 become our temporary variables)
 *     dmiss:	 ea that missed
 *     dcmp :	 the compare value for the va that missed
 *     hash1:	 pointer to first hash pteg
 *     hash2:	 pointer to 2nd hash pteg
 *
 * Register usage:
 *     tmp0:	 saved counter
 *     tmp1:	 junk
 *     tmp2:	 pointer to pteg
 *     tmp3:	 current compare value
 *
 * This code is taken from the 603e User's Manual with
 * some bugfixes and minor improvements to save bytes and cycles
 *
 *	NOTE: Do not touch sprg2 in here
 */

	. = 0x1100
.L_handler1100:
	mfspr	tmp2,	hash1
	mfctr	tmp0				/* use tmp0 to save ctr */
	mfspr	tmp3,	dcmp

.L_dlmiss_find_pte_in_pteg:
	li	tmp1,	8			/* count */
	subi	tmp2,	tmp2,	8		/* offset for lwzu */
	mtctr	tmp1				/* count... */
	
.L_dlmiss_pteg_loop:
	lwz	tmp1,	8(tmp2)			/* check pte0 for match... */
	addi	tmp2,	tmp2,	8
	cmpw	cr0,	tmp1,	tmp3
#if 0 /* How to write this correctly? */	
	bdnzf+	cr0,	.L_dlmiss_pteg_loop
#else	
	bc	0,2,	.L_dlmiss_pteg_loop
#endif	
	beq+	cr0,	.L_dmiss_found_pte

	/* Not found in PTEG, we must scan 2nd then give up */

	andi.	tmp1,	tmp3,	MASK(PTE0_HASH_ID)	/* already at 2nd? */
	bne-	.L_dmiss_do_no_hash_exception		/* give up */

	mfspr	tmp2,	hash2
	ori	tmp3,	tmp3,	MASK(PTE0_HASH_ID)
	b	.L_dlmiss_find_pte_in_pteg

.L_dmiss_found_pte:

	lwz	tmp1,	4(tmp2)				/* get pte1_t */

	/* Ok, we've found what we need to, restore and rfi! */

	mtctr	tmp0					/* restore ctr */
	mfsrr1	tmp3
	mfspr	tmp0,	dmiss
	mtcrf	0x80,	tmp3				/* Restore CR0 */
	mtspr	rpa,	tmp1				/* set the pte */
	ori	tmp1,	tmp1,	MASK(PTE1_REFERENCED)	/* set referenced */
	tlbld	tmp0					/* load up tlb */
	sth	tmp1,	6(tmp2)				/* sth is faster? */
	rfi
	
	/* This code is shared with data store translation miss */
	
.L_dmiss_do_no_hash_exception:
	/* clean up registers for protection exception... */
	mfsrr1	tmp3
	/* prepare to set DSISR_WRITE_BIT correctly from srr1 info */
	rlwinm	tmp1,	tmp3,	9,	6,	6
	addis	tmp1,	tmp1,	MASK(DSISR_HASH) >> 16

	/* And the entry into the usual data fault handler ... */

	mtctr	tmp0					/* Restore ctr */
	andi.	tmp2,	tmp3,	0xffff			/* Clean up srr1 */
	mtsrr1	tmp2					/* Set srr1 */
	mtdsisr	tmp1
	mfspr	tmp2,	dmiss
	mtdar	tmp2
	mfmsr	tmp0
	xoris	tmp0,	tmp0,	MASK(MSR_TGPR)>>16	/* no TGPR */
	mtcrf	0x80,	tmp3				/* Restore CR0 */
	sync						/* Needed on some */
	mtmsr	tmp0					/* reset MSR[TGPR] */
	b	.L_handler300				/* Data Access */
	
/*
 * Data store translation miss (similar to data load)
 *
 * Upon entry (done for us by the machine):
 *     srr0 :	 addr of instruction that missed
 *     srr1 :	 bits 0-3   = saved CR0
 *                    4     = lru way bit
 *                    5     = 1 if store
 *                    16-31 = saved msr
 *     msr[tgpr] = 1  (so gpr0-3 become our temporary variables)
 *     dmiss:	 ea that missed
 *     dcmp :	 the compare value for the va that missed
 *     hash1:	 pointer to first hash pteg
 *     hash2:	 pointer to 2nd hash pteg
 *
 * Register usage:
 *     tmp0:	 saved counter
 *     tmp1:	 junk
 *     tmp2:	 pointer to pteg
 *     tmp3:	 current compare value
 *
 * This code is taken from the 603e User's Manual with
 * some bugfixes and minor improvements to save bytes and cycles
 *
 *	NOTE: Do not touch sprg2 in here
 */

	. = 0x1200
.L_handler1200:
	mfspr	tmp2,	hash1
	mfctr	tmp0				/* use tmp0 to save ctr */
	mfspr	tmp3,	dcmp

.L_dsmiss_find_pte_in_pteg:
	li	tmp1,	8			/* count */
	subi	tmp2,	tmp2,	8		/* offset for lwzu */
	mtctr	tmp1				/* count... */
	
.L_dsmiss_pteg_loop:
	lwz	tmp1,	8(tmp2)			/* check pte0 for match... */
	addi	tmp2,	tmp2,	8

		cmpw	cr0,	tmp1,	tmp3
#if 0 /* I don't know how to write this properly */	
	bdnzf+	cr0,	.L_dsmiss_pteg_loop
#else	
	bc	0,2,	.L_dsmiss_pteg_loop
#endif	
	beq+	cr0,	.L_dsmiss_found_pte

	/* Not found in PTEG, we must scan 2nd then give up */

	andi.	tmp1,	tmp3,	MASK(PTE0_HASH_ID)	/* already at 2nd? */
	bne-	.L_dmiss_do_no_hash_exception		/* give up */

	mfspr	tmp2,	hash2
	ori	tmp3,	tmp3,	MASK(PTE0_HASH_ID)
	b	.L_dsmiss_find_pte_in_pteg

.L_dsmiss_found_pte:

	lwz	tmp1,	4(tmp2)				/* get pte1_t */
	andi.	tmp3,	tmp1,	MASK(PTE1_CHANGED)	/* unchanged, check? */
	beq-	.L_dsmiss_check_prot			/* yes, check prot */

.L_dsmiss_resolved:
	/* Ok, we've found what we need to, restore and rfi! */

	mtctr	tmp0					/* restore ctr */
	mfsrr1	tmp3
	mfspr	tmp0,	dmiss
	mtcrf	0x80,	tmp3				/* Restore CR0 */
	mtspr	rpa,	tmp1				/* set the pte */
	tlbld	tmp0					/* load up tlb */
	rfi
	
.L_dsmiss_check_prot:
	/* PTE is unchanged, we must check that we can write */
	rlwinm.	tmp3,	tmp1,	30,	0,	1	/* check PP[1] */
	bge-	.L_dsmiss_check_prot_user_kern
	andi.	tmp3,	tmp1,	1			/* check PP[0] */
	beq+	.L_dsmiss_check_prot_ok
	
.L_dmiss_do_prot_exception:
	/* clean up registers for protection exception... */
	mfsrr1	tmp3
	/* prepare to set DSISR_WRITE_BIT correctly from srr1 info */
	rlwinm	tmp1,	tmp3,	9,	6,	6
	addis	tmp1,	tmp1,	MASK(DSISR_PROT) >> 16

	/* And the entry into the usual data fault handler ... */

	mtctr	tmp0					/* Restore ctr */
	andi.	tmp2,	tmp3,	0xffff			/* Clean up srr1 */
	mtsrr1	tmp2					/* Set srr1 */
	mtdsisr	tmp1
	mfspr	tmp2,	dmiss
	mtdar	tmp2
	mfmsr	tmp0
	xoris	tmp0,	tmp0,	MASK(MSR_TGPR)>>16	/* no TGPR */
	mtcrf	0x80,	tmp3				/* Restore CR0 */
	sync						/* Needed on some */
	mtmsr	tmp0					/* reset MSR[TGPR] */
	b	.L_handler300				/* Data Access */
	
/* NB - if we knew we were on a 603e we could test just the MSR_KEY bit */
.L_dsmiss_check_prot_user_kern:
	mfsrr1	tmp3
	andi.	tmp3,	tmp3,	MASK(MSR_PR)
	beq+	.L_dsmiss_check_prot_kern
	mfspr	tmp3,	dmiss				/* check user privs */
	mfsrin	tmp3,	tmp3				/* get excepting SR */
	andis.	tmp3,	tmp3,	0x2000			/* Test SR ku bit */
	beq+	.L_dsmiss_check_prot_ok
	b	.L_dmiss_do_prot_exception

.L_dsmiss_check_prot_kern:
	mfspr	tmp3,	dmiss				/* check kern privs */
	mfsrin	tmp3,	tmp3
	andis.	tmp3,	tmp3,	0x4000			/* Test SR Ks bit */
	bne-	.L_dmiss_do_prot_exception

.L_dsmiss_check_prot_ok:
	/* Ok, mark as referenced and changed before resolving the fault */
	ori	tmp1,	tmp1,	(MASK(PTE1_REFERENCED)|MASK(PTE1_CHANGED))
	sth	tmp1,	6(tmp2)
	b	.L_dsmiss_resolved
	
/*
 * 			Instruction address breakpoint
 */

			. = 0x1300
.L_handler1300:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_INSTRUCTION_BKPT			/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			System management interrupt
 */

			. = 0x1400
.L_handler1400:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_SYSTEM_MANAGEMENT			/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

;
; 			Altivec Java Mode Assist interrupt
;

			. = 0x1600
.L_handler1600:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_ALTIVEC_ASSIST			/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

;
; 			Thermal interruption
;

			. = 0x1700
.L_handler1700:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_THERMAL					/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * There is now a large gap of reserved traps
 */

/*
 * 			Run mode/ trace exception - single stepping on 601 processors
 */

			. = 0x2000
.L_handler2000:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_RUNMODE_TRACE				/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */


/*
 *	Filter Ultra Fast Path syscalls for VMM
 */
ufpVM:
			cmpwi	cr6,r0,0x6004					; Is it vmm_dispatch
			bne		cr6,notufp						; Exit If not
			cmpwi	cr5,r3,kvmmResumeGuest			; Compare r3 with kvmmResumeGuest
			cmpwi	cr6,r3,kvmmSetGuestRegister		; Compare r3 with kvmmSetGuestRegister
			cror	cr1_eq,cr5_lt,cr6_gt			; Set true if out of VMM Fast syscall range
			bt-		cr1_eq,notufp					; Exit if out of range
			rlwinm	r13,r13,1+FamVMmodebit,30,31	; Extract FamVMenabit and FamVMmodebit
			cmpwi	cr0,r13,3						; Are FamVMena and FamVMmode set
			bne+	notufp							; Exit if not in FAM
			b		EXT(vmm_ufp)					; Ultra Fast Path syscall

/*
 * .L_exception_entry(type)
 *
 * This is the common exception handling routine called by any
 * type of system exception.
 *
 * ENTRY:	via a system exception handler, thus interrupts off, VM off.
 *              r3 has been saved in sprg3 and now contains a number
 *              representing the exception's origins
 *
 */
	
			.data
			.align	ALIGN
			.globl	EXT(exception_entry)
EXT(exception_entry):
			.long	.L_exception_entry-EXT(ExceptionVectorsStart) /* phys addr of fn */
				
			VECTOR_SEGMENT
			.align	5

.L_exception_entry:
			
/*
 *
 *	Here we will save off a mess of registers, the special ones and R0-R12.  We use the DCBZ
 *	instruction to clear and allcoate a line in the cache.  This way we won't take any cache
 *	misses, so these stores won't take all that long. Except the first line that is because
 *	we can't do a DCBZ if the L1 D-cache is off.  The rest we will skip if they are
 *	off also.
 *
 *	Note that if we are attempting to sleep (as opposed to nap or doze) all interruptions
 *	are ignored.
 */
			mfsprg  r13,0							/* Load per_proc */     
			lwz		r13,next_savearea(r13)			/* Get the exception save area */

			stw		r1,saver1(r13)					; Save register 1
			stw		r0,saver0(r13)					; Save register 0
			dcbtst	0,r13							; We will need this in a bit
			mfspr	r1,hid0							; Get HID0
			mfcr	r0								; Save the CR
			mtcrf	255,r1							; Get set to test for cache and sleep
			bf		sleep,notsleep					; Skip if we are not trying to sleep
			
			mtcrf	255,r0							; Restore the CR
			lwz		r0,saver0(r13)					; Restore R0
			lwz		r1,saver1(r13)					; Restore R1
			mfsprg	r13,0							; Get the per_proc 
			lwz		r11,pfAvailable(r13)			; Get back the feature flags
			mfsprg	r13,2							; Restore R13
			mtsprg	2,r11							; Set sprg2 to the features
			mfsprg	r11,3							; Restore R11
			rfi										; Jump back into sleep code...
			.long	0								; Leave these here please...
			.long	0
			.long	0
			.long	0
			.long	0
			.long	0
			.long	0
			.long	0
			
			.align	5
						
notsleep:	stw		r2,saver2(r13)					; Save this one
			crmove	featL1ena,dce					; Copy the cache enable bit
			rlwinm	r2,r1,0,nap+1,doze-1			; Clear any possible nap and doze bits
			mtspr	hid0,r2							; Clear the nap/doze bits
			cmplw	r2,r1							; See if we were napping
			la		r1,saver8(r13)					; Point to the next line in case we need it
			crnot	wasNapping,cr0_eq				; Remember if we were napping
			mfsprg	r2,0							; Get the per_proc area
			bf-		featL1ena,skipz1				; L1 cache is disabled...
			dcbz	0,r1							; Reserve our line in cache
			
;
;			Remember, we are setting up CR6 with feature flags
;
skipz1:		
			andi.	r1,r11,T_FAM					; Check FAM bit	
			stw		r3,saver3(r13)					; Save this one
			stw		r4,saver4(r13)					; Save this one
			andc	r11,r11,r1						; Clear FAM bit
			beq+	noFAM							; Is it FAM intercept
			mfsrr1	r3								; Load srr1
			rlwinm.	r3,r3,0,MSR_PR_BIT,MSR_PR_BIT	; Are we trapping from supervisor state?
			beq+	noFAM							; From supervisor state
			lwz		r1,spcFlags(r2)					; Load spcFlags 
			rlwinm	r1,r1,1+FamVMmodebit,30,31		; Extract FamVMenabit and FamVMmodebit
			cmpwi	cr0,r1,2						; Check FamVMena set without FamVMmode
			bne+	noFAM							; Can this context be FAM intercept
			lwz		r4,FAMintercept(r2)				; Load exceptions mask to intercept
			srwi	r1,r11,2						; divide r11 by 4
			lis		r3,0x8000						; Set r3 to 0x80000000
			srw		r1,r3,r1						; Set bit for current exception
			and.	r1,r1,r4						; And current exception with the intercept mask
			beq+	noFAM							; Is it FAM intercept
			b		EXT(vmm_fam_handler)
noFAM:
			lwz		r1,pfAvailable(r2)				; Get the CPU features flags			
			la		r3,savesrr0(r13)				; Point to the last line
			mtcrf	0xE0,r1							; Put the features flags (that we care about) in the CR
			stw		r6,saver6(r13)					; Save this one
			crmove	featSMP,pfSMPcapb				; See if we have a PIR
			stw		r8,saver8(r13)					; Save this one
			crmove	featAltivec,pfAltivecb			; Set the Altivec flag
			mfsrr0	r6								; Get the interruption SRR0 
			stw		r8,saver8(r13)					; Save this one
			bf-		featL1ena,skipz1a				; L1 cache is disabled...
			dcbz	0,r3							; Reserve our line in cache
skipz1a:	crmove	featFP,pfFloatb					; Remember that we have floating point
			stw		r7,saver7(r13)					; Save this one
			lhz		r8,PP_CPU_FLAGS(r2)				; Get the flags
			mfsrr1	r7								; Get the interrupt SRR1
			rlwinm	r8,r8,(((31-MSR_BE_BIT)+(traceBEb+16+1))&31),MSR_BE_BIT,MSR_BE_BIT	; Set BE bit if special trace is on
			stw		r6,savesrr0(r13)				; Save the SRR0 
			rlwinm	r6,r7,(((31-MSR_BE_BIT)+(MSR_PR_BIT+1))&31),MSR_BE_BIT,MSR_BE_BIT	; Move PR bit to BE bit
			stw		r5,saver5(r13)					; Save this one 
			and		r8,r6,r8						; Remove BE bit only if problem state and special tracing on
			mfsprg	r6,2							; Get interrupt time R13
			mtsprg	2,r1							; Set the feature flags
			andc	r7,r7,r8						; Clear BE bit if special trace is on and PR is set
			mfsprg	r8,3							; Get rupt time R11
			stw		r7,savesrr1(r13)				; Save SRR1 
			rlwinm.	r7,r7,MSR_RI_BIT,MSR_RI_BIT		; Is this a special case access fault?
			stw		r6,saver13(r13)					; Save rupt R1
			crnot	specAccess,cr0_eq				; Set that we are doing a special access if RI is set
			stw		r8,saver11(r13)					; Save rupt time R11

getTB:		mftbu	r6								; Get the upper timebase
			mftb	r7								; Get the lower timebase
			mftbu	r8								; Get the upper one again
			cmplw	r6,r8							; Did the top tick?
			bne-	getTB							; Yeah, need to get it again...

			stw		r8,ruptStamp(r2)				; Save the top of time stamp
			stw		r8,SAVtime(r13)					; Save the top of time stamp
			la		r6,saver16(r13)					; Point to the next cache line
			stw		r7,ruptStamp+4(r2)				; Save the bottom of time stamp
			stw		r7,SAVtime+4(r13)				; Save the bottom of time stamp

			bf-		featL1ena,skipz2				; L1 cache is disabled...
			dcbz	0,r6							; Allocate in cache 
skipz2:			
			stw		r9,saver9(r13)					; Save this one

			stw		r10,saver10(r13)				; Save this one
			mflr	r4								; Get the LR
			mfxer	r10								; Get the XER
			
			bf+		wasNapping,notNapping			; Skip if not waking up from nap...

			lwz		r6,napStamp+4(r2)				; Pick up low order nap stamp
			lis		r3,hi16(EXT(machine_idle_ret))	; Get high part of nap/doze return
			lwz		r5,napStamp(r2)					; and high order
			subfc	r7,r6,r7						; Subtract low stamp from now
			lwz		r6,napTotal+4(r2)				; Pick up low total
			subfe	r5,r5,r8						; Subtract high stamp and borrow from now
			lwz		r8,napTotal(r2)					; Pick up the high total
			addc	r6,r6,r7						; Add low to total
			ori		r3,r3,lo16(EXT(machine_idle_ret))	; Get low part of nap/doze return
			adde	r8,r8,r5						; Add high and carry to total
			stw		r6,napTotal+4(r2)				; Save the low total
			stw		r8,napTotal(r2)					; Save the high total
			stw		r3,savesrr0(r13)				; Modify to return to nap/doze exit
			
			rlwinm.		r3,r1,0,pfSlowNapb,pfSlowNapb			; Should HID1 be restored?
			beq		notInSlowNap

			lwz		r3,pfHID1(r2)					; Get saved HID1 value
			mtspr		hid1, r3					; Restore HID1

notInSlowNap:
			rlwinm.		r3,r1,0,pfNoL2PFNapb,pfNoL2PFNapb		; Should MSSCR0 be restored?
			beq		notNapping

			lwz		r3,pfMSSCR0(r2)					; Get saved MSSCR0 value
			mtspr		msscr0, r3					; Restore MSSCR0
			sync
			isync

notNapping:	stw		r12,saver12(r13)				; Save this one
						
			stw		r14,saver14(r13)				; Save this one
			stw		r15,saver15(r13)				; Save this one 
			la		r14,saver24(r13)				; Point to the next block to save into
			stw		r0,savecr(r13)					; Save rupt CR
			mfctr	r6								; Get the CTR 
			stw		r16,saver16(r13)				; Save this one
			stw		r4,savelr(r13)					; Save rupt LR
		
			bf-		featL1ena,skipz4				; L1 cache is disabled...
			dcbz	0,r14							; Allocate next save area line
skipz4:			
			stw		r17,saver17(r13)				; Save this one
			stw		r18,saver18(r13)				; Save this one 
			stw		r6,savectr(r13)					; Save rupt CTR
			stw		r19,saver19(r13)				; Save this one
			lis		r12,hi16(KERNEL_SEG_REG0_VALUE)	; Get the high half of the kernel SR0 value
			mfdar	r6								; Get the rupt DAR
			stw		r20,saver20(r13)				; Save this one 
			
			bf+		specAccess,noSRsave				; Do not save SRs if this is not a special access...
			mfsr	r14,sr0							; Get SR0
			stw		r14,savesr0(r13)				; and save
			mfsr	r14,sr1							; Get SR1
			stw		r14,savesr1(r13)				; and save
			mfsr	r14,sr2							; get SR2
			stw		r14,savesr2(r13)				; and save
			mfsr	r14,sr3							; get SR3
			stw		r14,savesr3(r13)				; and save

noSRsave:	mtsr	sr0,r12							; Set the kernel SR0 
			stw		r21,saver21(r13)				; Save this one
			addis	r12,r12,0x0010					; Point to the second segment of kernel
			stw		r10,savexer(r13)				; Save the rupt XER
			mtsr	sr1,r12							; Set the kernel SR1 
			stw		r30,saver30(r13)				; Save this one 
			addis	r12,r12,0x0010					; Point to the third segment of kernel
			stw		r31,saver31(r13)				; Save this one 
			mtsr	sr2,r12							; Set the kernel SR2 
			stw		r22,saver22(r13)				; Save this one 
			addis	r12,r12,0x0010					; Point to the third segment of kernel
			stw		r23,saver23(r13)				; Save this one 
			mtsr	sr3,r12							; Set the kernel SR3 
			stw		r24,saver24(r13)				; Save this one 
			stw		r25,saver25(r13)				; Save this one 
			mfdsisr	r7								; Get the rupt DSISR 
			stw		r26,saver26(r13)				; Save this one		
			stw		r27,saver27(r13)				; Save this one 
			li		r10,emfp0						; Point to floating point save
			stw		r28,saver28(r13)				; Save this one
			stw		r29,saver29(r13)				; Save this one 
			mfsr	r14,sr14						; Get the copyin/out segment register
			stw		r6,savedar(r13)					; Save the rupt DAR 
			bf-		featL1ena,skipz5a				; Do not do this if no L1...
			dcbz	r10,r2							; Clear and allocate an L1 slot
			
skipz5a:	stw		r7,savedsisr(r13)				; Save the rupt code DSISR
			stw		r11,saveexception(r13)			; Save the exception code 
			stw		r14,savesr14(r13)				; Save copyin/copyout


;
;			Here we will save some floating point and vector status
;			and we also set a clean default status for a new interrupt level.
;			Note that we assume that emfp0 is on an altivec boundary
;			and that R10 points to it (as a displacemnt from R2).
;

			lis		r8,hi16(MASK(MSR_VEC))			; Get the vector enable bit
			mfmsr	r6								; Get the current MSR value
			ori		r8,r8,lo16(MASK(MSR_FP))		; Add in the float enable
			li		r19,0							; Assume no Altivec
			or		r7,r6,r8						; Enable floating point
			li		r9,0							; Get set to clear VRSAVE
			mtmsr	r7								; Do it
			isync
			
			bf		featAltivec,noavec				; No Altivec on this CPU...
			addi	r14,r10,16						; Displacement to second vector register
			stvxl	v0,r10,r2						; Save a register
			stvxl	v1,r14,r2						; Save a second register
			mfvscr	v0								; Get the vector status register
			la		r28,savevscr(r13)				; Point to the status area
			vspltish v1,1							; Turn on the non-Java bit and saturate
			stvxl	v0,0,r28						; Save the vector status
			vspltisw v0,1							; Turn on the saturate bit
			mfspr	r19,vrsave						; Get the VRSAVE register
			vxor	v1,v1,v0						; Turn off saturate	
			mtspr	vrsave,r9						; Clear VRSAVE for each interrupt level
			mtvscr	v1								; Set the non-java, no saturate status for new level

			lvxl	v0,r10,r2						; Restore first work register
			lvxl	v1,r14,r2						; Restore second work register

noavec:		stw		r19,savevrsave(r13)				; Save the vector register usage flags

;
;			We need to save the FPSCR as if it is normal context.
;			This is because pending exceptions will cause an exception even if
;			FP is disabled. We need to clear the FPSCR when we first start running in the
;			kernel.
;

			bf-		featFP,nofpexe					; No possible floating point exceptions...
			
			stfd	f0,emfp0(r2)					; Save FPR0	
			stfd	f1,emfp1(r2)					; Save FPR1	
			mffs	f0								; Get the FPSCR
			fsub	f1,f1,f1						; Make a 0			
			stfd	f0,savefpscrpad(r13)			; Save the FPSCR
			mtfsf	0xFF,f1							; Clear it
			lfd		f0,emfp0(r2)					; Restore FPR0	
			lfd		f1,emfp1(r2)					; Restore FPR1	

nofpexe:	mtmsr	r6								; Turn off FP and vector
			isync
			

;
;			Everything is saved at this point, except for FPRs, and VMX registers.
;			Time for us to get a new savearea and then trace interrupt if it is enabled.
;

			li		r0,SAVgeneral					; Get the savearea type value
			lis		r23,hi16(EXT(trcWork))			; Get the trace work area address
			mr		r14,r11							; Save the interrupt code across the call
			stb		r0,SAVflags+2(r13)				; Mark valid context
			ori		r23,r23,lo16(EXT(trcWork))		; Get the rest
			rlwinm	r22,r11,30,0,31					; Divide interrupt code by 2
			lwz		r25,traceMask(r23)				; Get the trace mask
			addi	r22,r22,10						; Adjust code so we shift into CR5

			bl		EXT(save_get_phys)				; Grab a savearea
			
			mfsprg	r2,0							; Get back the per_proc block
			rlwnm	r7,r25,r22,22,22				; Set CR5_EQ bit position to 0 if tracing allowed 
			lhz		r19,PP_CPU_NUMBER(r2)			; Get the logical processor number											
			li		r26,0x8							; Get start of cpu mask
			mr		r11,r14							; Get the exception code back
			srw		r26,r26,r19						; Get bit position of cpu number
			mtcrf	0x04,r7							; Set CR5 to show trace or not
			and.	r26,r26,r25						; See if we trace this cpu
			stw		r3,next_savearea(r2)			; Remember the savearea we just got for the next rupt
			crandc	cr5_eq,cr5_eq,cr0_eq			; Turn off tracing if cpu is disabled
;
;			At this point, we can take another exception and lose nothing.
;
			
			lwz		r0,saver0(r13)					; Get back interrupt time R0 (we need this whether we trace or not)

			bne+	cr5,skipTrace					; Skip all of this if no tracing here...

;
;			We select a trace entry using a compare and swap on the next entry field.
;			Since we do not lock the actual trace buffer, there is a potential that
;			another processor could wrap an trash our entry.  Who cares?
;

			lwz		r25,traceStart(r23)				; Get the start of trace table
			lwz		r26,traceEnd(r23)				; Get end of trace table
	
trcsel:		lwarx	r20,0,r23						; Get and reserve the next slot to allocate
			
			addi	r22,r20,LTR_size				; Point to the next trace entry
			cmplw	r22,r26							; Do we need to wrap the trace table?
			bne+	gotTrcEnt						; No wrap, we got us a trace entry...
			
			mr		r22,r25							; Wrap back to start

gotTrcEnt:	stwcx.	r22,0,r23						; Try to update the current pointer
			bne-	trcsel							; Collision, try again...
			
#if ESPDEBUG
			dcbf	0,r23							; Force to memory
			sync
#endif
			
			bf-		featL1ena,skipz6				; L1 cache is disabled...
			dcbz	0,r20							; Clear and allocate first trace line
skipz6:

;
;			Let us cut that trace entry now.
;


			li		r14,32							; Offset to second line

			lwz		r16,ruptStamp(r2)				; Get top of time base
			lwz		r17,ruptStamp+4(r2)				; Get the bottom of time stamp
		
			bf-		featL1ena,skipz7				; L1 cache is disabled...
			dcbz	r14,r20							; Zap the second half

skipz7:		stw		r16,LTR_timeHi(r20)				; Set the upper part of TB 
			lwz		r1,saver1(r13)					; Get back interrupt time R1
			stw		r17,LTR_timeLo(r20)				; Set the lower part of TB
			lwz		r18,saver2(r13)					; Get back interrupt time R2
			stw		r0,LTR_r0(r20)					; Save off register 0 			
			lwz		r3,saver3(r13)					; Restore this one
			sth		r19,LTR_cpu(r20)				; Stash the cpu number
			stw		r1,LTR_r1(r20)					; Save off register 1			
			lwz		r4,saver4(r13)					; Restore this one
			stw		r18,LTR_r2(r20)					; Save off register 2 			
			lwz		r5,saver5(r13)					; Restore this one
			stw		r3,LTR_r3(r20)					; Save off register 3
			lwz		r16,savecr(r13)					; Get the CR value
			stw		r4,LTR_r4(r20)					; Save off register 4 
			mfsrr0	r17								; Get SRR0 back, it is still good
			stw		r5,LTR_r5(r20)					; Save off register 5	
			mfsrr1	r18								; SRR1 is still good in here
			stw		r16,LTR_cr(r20)					; Save the CR
			stw		r17,LTR_srr0(r20)				; Save the SSR0 
			stw		r18,LTR_srr1(r20)				; Save the SRR1 
			mfdar	r17								; Get this back
			lwz		r16,savelr(r13)					; Get the LR
			stw		r17,LTR_dar(r20)				; Save the DAR
			mfctr	r17								; Get the CTR (still good in register)
			stw		r16,LTR_lr(r20)					; Save the LR
#if 0
			lwz		r17,emfp1(r2)					; (TEST/DEBUG)
#endif
			stw		r17,LTR_ctr(r20)				; Save off the CTR
			stw		r13,LTR_save(r20)				; Save the savearea 
			sth		r11,LTR_excpt(r20)				; Save the exception type 
#if ESPDEBUG
			addi	r17,r20,32						; (TEST/DEBUG)
			dcbst	br0,r20							; (TEST/DEBUG)
			dcbst	br0,r17							; (TEST/DEBUG)
			sync									; (TEST/DEBUG)
#endif

;
;			We are done with the trace, except for maybe modifying the exception
;			code later on. So, that means that we need to save R20 and CR5.
;			
;			So, finish setting up the kernel registers now.
;

skipTrace:	lhz		r21,PP_CPU_NUMBER(r2)			; Get the logical processor number
			lis		r12,hi16(EXT(hw_counts))		; Get the high part of the interrupt counters
			lwz		r7,savesrr1(r13)				; Get the entering MSR
			ori		r12,r12,lo16(EXT(hw_counts))	; Get the low part of the interrupt counters
			rlwinm	r21,r21,8,20,23					; Get index to processor counts
			mtcrf	0x80,r0							; Set our CR0 to the high nybble of possible syscall code
			rlwinm	r6,r0,1,0,31					; Move sign bit to the end 
			cmplwi	cr1,r11,T_SYSTEM_CALL			; Did we get a system call?
			add		r12,r12,r21						; Point to the processor count area
			crandc	cr0_lt,cr0_lt,cr0_gt			; See if we have R0 equal to 0b10xx...x 
			lwzx	r22,r12,r11						; Get the old value
			cmplwi	cr3,r11,T_IN_VAIN				; Was this all in vain? All for nothing? 
			addi	r22,r22,1						; Count this one
			cmplwi	cr2,r6,1						; See if original R0 had the CutTrace request code in it 
			stwx	r22,r12,r11						; Store it back
			
			beq-	cr3,EatRupt						; Interrupt was all for nothing... 
			cmplwi	cr3,r11,T_MACHINE_CHECK			; Did we get a machine check?
			bne+	cr1,noCutT						; Not a system call...
			bnl+	cr0,noCutT						; R0 not 0b10xxx...x, can not be any kind of magical system call...
			rlwinm.	r7,r7,0,MSR_PR_BIT,MSR_PR_BIT	; Did we come from user state?
			lis		r1,hi16(EXT(dgWork))			; Get the diagnostics flags
			beq+	FCisok							; From supervisor state...

			ori		r1,r1,lo16(EXT(dgWork))			; Again
			lwz		r1,dgFlags(r1)					; Get the flags
			rlwinm.	r1,r1,0,enaUsrFCallb,enaUsrFCallb	; Are they valid?
			beq-	noCutT							; No...

FCisok:		beq-	cr2,isCutTrace					; This is a CutTrace system call...
			
;
;			Here is where we call the firmware.  If it returns T_IN_VAIN, that means
;			that it has handled the interruption.  Remember: thou shalt not trash R13
;			or R20 while you are away.  Anything else is ok.
;			

			lwz		r3,saver3(r13)					; Restore the first parameter
			bl		EXT(FirmwareCall)				; Go handle the firmware call....

			cmplwi	r3,T_IN_VAIN					; Was it handled? 
			mfsprg	r2,0							; Restore the per_proc
			beq+	EatRupt							; Interrupt was handled...
			mr		r11,r3							; Put the rupt code into the right register
			b		filter							; Go to the normal system call handler...
		
			.align	5
			
isCutTrace:				
			li		r7,-32768						; Get a 0x8000 for the exception code
			bne-	cr5,EatRupt						; Tracing is disabled...
			sth		r7,LTR_excpt(r20)				; Modify the exception type to a CutTrace
			b		EatRupt							; Time to go home... 

;			We are here because we did not have a CutTrace system call

			.align	5

noCutT:		beq-	cr3,MachineCheck				; Whoa... Machine check...

;
;			The following interrupts are the only ones that can be redriven
;			by the higher level code or emulation routines.
;

Redrive:	cmplwi	cr0,r11,T_IN_VAIN				; Did the signal handler eat the signal?
			mfsprg	r2,0							; Get the per_proc block 
			beq+	cr0,EatRupt						; Bail now if we ate the rupt...


;
;			Here ss where we check for the other fast-path exceptions: translation exceptions,
;			emulated instructions, etc.
;

filter:		cmplwi	cr3,r11,T_ALTIVEC_ASSIST		; Check for an Altivec denorm assist
			cmplwi	cr4,r11,T_ALIGNMENT				; See if we got an alignment exception
			cmplwi	cr1,r11,T_PROGRAM				; See if we got a program exception
			cmplwi	cr2,r11,T_INSTRUCTION_ACCESS	; Check on an ISI 
			bne+	cr3,noAltivecAssist				; It is not an assist...
			b		EXT(AltivecAssist)				; It is an assist...
	
			.align	5

noAltivecAssist:
			bne+	cr4,noAlignAssist				; No alignment here...
			b		EXT(AlignAssist)				; Go try to emulate...

			.align	5

noAlignAssist:
			bne+	cr1,noEmulate					; No emulation here...
			b		EXT(Emulate)					; Go try to emulate...

			.align	5

noEmulate:	cmplwi	cr3,r11,T_CSWITCH				; Are we context switching 
			cmplwi	r11,T_DATA_ACCESS				; Check on a DSI 
			beq-	cr2,DSIorISI					; It is a PTE fault...
			beq-	cr3,conswtch					; It is a context switch... 
			bne+	PassUp							; It is not a PTE fault...

;
;			This call will either handle the fault, in which case it will not
;			return, or return to pass the fault up the line.
;

DSIorISI:	mr		r3,r11							; Move the rupt code
			
			bl		EXT(handlePF)					; See if we can handle this fault

			lwz		r0,savesrr1(r13)				; Get the MSR in use at exception time
			mfsprg	r2,0							; Get back per_proc 
			cmplwi	cr1,r3,T_IN_VAIN				; Was it handled?
			rlwinm.	r4,r0,0,MSR_PR_BIT,MSR_PR_BIT	; Are we trapping from supervisor state?
			mr		r11,r3							; Put interrupt code back into the right register
			beq+	cr1,EatRupt						; Yeah, just blast back to the user... 
			beq-	NoFamPf
			lwz		r1,spcFlags(r2)					; Load spcFlags
            rlwinm	r1,r1,1+FamVMmodebit,30,31		; Extract FamVMenabit and FamVMmodebit
            cmpi	cr0,r1,2						; Check FamVMena set without FamVMmode
			bne-	cr0,NoFamPf
            lwz		r6,FAMintercept(r2)				; Load exceptions mask to intercept
			srwi	r1,r11,2						; divide r11 by 4
            lis		r5,0x8000						; Set r5 to 0x80000000
            srw		r1,r5,r1						; Set bit for current exception
            and.	r1,r1,r6						; And current exception with the intercept mask
            beq+	NoFamPf							; Is it FAM intercept
			bl		EXT(vmm_fam_pf_handler)
			b		EatRupt
NoFamPf:
			andi.	r4,r0,lo16(MASK(MSR_RI))		; See if the recover bit is on
			beq+	PassUp							; Not on, normal case...
;
;			Here is where we handle the "recovery mode" stuff.
;			This is set by an emulation routine to trap any faults when it is fetching data or
;			instructions.  
;
;			If we get a fault, we turn off RI, set CR0_EQ to false, bump the PC, and set R0
;			and R1 to the DAR and DSISR, respectively.
;
			lwz		r4,savesrr0(r13)				; Get the failing instruction address
			lwz		r5,savecr(r13)					; Get the condition register
			addi	r4,r4,4							; Skip failing instruction
			lwz		r6,savedar(r13)					; Get the DAR
			rlwinm	r5,r5,0,3,1						; Clear CR0_EQ to let emulation code know we failed
			lwz		r7,savedsisr(r13)				; Grab the DSISR
			stw		r0,savesrr1(r13)				; Save the result MSR
			stw		r4,savesrr0(r13)				; Save resume address
			stw		r5,savecr(r13)					; And the resume CR
			stw		r6,saver0(r13)					; Pass back the DAR
			stw		r7,saver1(r13)					; Pass back the DSISR
			b		EatRupt							; Resume emulated code

;
;			Here is where we handle the context switch firmware call.  The old 
;			context has been saved, and the new savearea in in saver3.  We will just
;			muck around with the savearea pointers, and then join the exit routine 
;

			.align	5

conswtch:	
			mr		r29,r13							; Save the save
			rlwinm	r30,r13,0,0,19					; Get the start of the savearea block
			lwz		r5,saver3(r13)					; Switch to the new savearea
			lwz		r30,SACvrswap(r30)				; get real to virtual translation
			mr		r13,r5							; Switch saveareas
			xor		r27,r29,r30						; Flip to virtual
			stw		r27,saver3(r5)					; Push the new savearea to the switch to routine
			b		EatRupt							; Start it up... 

;
;			Handle machine check here.
;
; ?
;

			.align	5

MachineCheck:

			lwz		r27,savesrr1(r13)				; ?
			rlwinm.	r11,r27,0,dcmck,dcmck			; ?
			beq+	notDCache						; ?
			
			mfspr	r11,msscr0						; ?
			dssall									; ?
			sync
			
			lwz		r27,savesrr1(r13)				; ?

hiccup:		cmplw	r27,r27							; ?
			bne-	hiccup							; ?
			isync									; ?
			
			oris	r11,r11,hi16(dl1hwfm)			; ?
			mtspr	msscr0,r11						; ?
			
rstbsy:		mfspr	r11,msscr0						; ?
			
			rlwinm.	r11,r11,0,dl1hwf,dl1hwf			; ?
			bne		rstbsy							; ?
			
			sync									; ?

			b		EatRupt							; ?

			.align	5
			
notDCache:
;
;			Check if the failure was in 
;			ml_probe_read.  If so, this is expected, so modify the PC to
;			ml_proble_read_mck and then eat the exception.
;
			lwz		r30,savesrr0(r13)				; Get the failing PC
			lis		r28,hi16(EXT(ml_probe_read_mck))	; High order part
			lis		r27,hi16(EXT(ml_probe_read))	; High order part
			ori		r28,r28,lo16(EXT(ml_probe_read_mck))	; Get the low part
			ori		r27,r27,lo16(EXT(ml_probe_read))	; Get the low part
			cmplw	r30,r28							; Check highest possible
			cmplw	cr1,r30,r27						; Check lowest
			bge-	PassUp							; Outside of range
			blt-	cr1,PassUp						; Outside of range
;
;			We need to fix up the BATs here because the probe
;			routine messed them all up... As long as we are at it,
;			fix up to return directly to caller of probe.
;
		
			lis		r11,hi16(EXT(shadow_BAT)+shdDBAT)	; Get shadow address
			ori		r11,r11,lo16(EXT(shadow_BAT)+shdDBAT)	; Get shadow address
			
			lwz		r30,0(r11)						; Pick up DBAT 0 high
			lwz		r28,4(r11)						; Pick up DBAT 0 low
			lwz		r27,8(r11)						; Pick up DBAT 1 high
			lwz		r18,16(r11)						; Pick up DBAT 2 high
			lwz		r11,24(r11)						; Pick up DBAT 3 high
			
			sync
			mtdbatu	0,r30							; Restore DBAT 0 high
			mtdbatl	0,r28							; Restore DBAT 0 low
			mtdbatu	1,r27							; Restore DBAT 1 high
			mtdbatu	2,r18							; Restore DBAT 2 high
			mtdbatu	3,r11							; Restore DBAT 3 high 
			sync

			lwz		r27,saver6(r13)					; Get the saved R6 value
			mtspr		hid0,r27					; Restore HID0
			isync

			lwz		r28,savelr(r13)					; Get return point
			lwz		r27,saver0(r13)					; Get the saved MSR
			li		r30,0							; Get a failure RC
			stw		r28,savesrr0(r13)				; Set the return point
			stw		r27,savesrr1(r13)				; Set the continued MSR
			stw		r30,saver3(r13)					; Set return code
			b		EatRupt							; Yum, yum, eat it all up...

/*
 *			Here's where we come back from some instruction emulator.  If we come back with
 *			T_IN_VAIN, the emulation is done and we should just reload state and directly
 *			go back to the interrupted code. Otherwise, we'll check to see if
 *			we need to redrive with a different interrupt, i.e., DSI.
 */
 
			.align	5
			.globl	EXT(EmulExit)

LEXT(EmulExit)

			cmplwi	r11,T_IN_VAIN					; Was it emulated? 
			lis		r1,hi16(SAVredrive)				; Get redrive request
			mfsprg	r2,0							; Restore the per_proc area
			beq+	EatRupt							; Yeah, just blast back to the user...
			lwz		r4,SAVflags(r13)				; Pick up the flags

			and.	r0,r4,r1						; Check if redrive requested
			andc	r4,r4,r1						; Clear redrive

			beq+	PassUp							; No redrive, just keep on going...

			stw		r4,SAVflags(r13)				; Set the flags
			b		Redrive							; Redrive the exception...
		
;
; 			Jump into main handler code switching on VM at the same time.
;
; 			We assume kernel data is mapped contiguously in physical
; 			memory, otherwise we would need to switch on (at least) virtual data.
;			SRs are already set up.
;

			.align	5

PassUp:		lis		r2,hi16(EXT(exception_handlers))	; Get exception vector address
			ori		r2,r2,lo16(EXT(exception_handlers))	; And low half
			lwzx	r6,r2,r11						; Get the actual exception handler address

PassUpDeb:	mtsrr0	r6								; Set up the handler address
			rlwinm	r5,r13,0,0,19					; Back off to the start of savearea block
			
			mfmsr	r3								; Get our MSR
			rlwinm	r3,r3,0,MSR_BE_BIT+1,MSR_SE_BIT-1	; Clear all but the trace bits
			li		r2,MSR_SUPERVISOR_INT_OFF		; Get our normal MSR value
			lwz		r5,SACvrswap(r5)				; Get real to virtual conversion			
			or		r2,r2,r3						; Keep the trace bits if they are on
			mr		r3,r11							; Pass the exception code in the paramter reg
			mtsrr1	r2								; Set up our normal MSR value
			xor		r4,r13,r5						; Pass up the virtual address of context savearea

			rfi										; Launch the exception handler

			.long	0								; Leave these here gol durn it!
			.long	0
			.long	0
			.long	0
			.long	0
			.long	0
			.long	0
			.long	0

/*
 *			This routine is the only place where we return from an interruption.
 *			Anyplace else is wrong.  Even if I write the code, it's still wrong.
 *			Feel free to come by and slap me if I do do it--even though I may
 *			have had a good reason to do it.
 *
 *			All we need to remember here is that R13 must point to the savearea
 *			that has the context we need to load up. Translation and interruptions
 *			must be disabled.
 *
 *			This code always loads the context in the savearea pointed to
 *			by R13.  In the process, it throws away the savearea.  If there 
 *			is any tomfoolery with savearea stacks, it must be taken care of 
 *			before we get here.
 *
 *			Speaking of tomfoolery, this is where we synthesize interruptions
 *			if we need to.
 */
 
 			.align	5
 
EatRupt:	mfsprg	r29,0							; Get the per_proc block back
			mr		r31,r13							; Move the savearea pointer to the far end of the register set
			
			lwz		r30,quickfret(r29)				; Pick up the quick fret list, if any

			mfsprg	r27,2							; Get the processor features
			lwz		r21,savesrr1(r31)				; Get destination MSR
			
erchkfret:	mr.		r3,r30							; Any savearea to quickly release?
			beq+	ernoqfret						; No quickfrets...
			lwz		r30,SAVprev(r30)				; Chain back now
			
			bl		EXT(save_ret_phys)				; Put it on the free list			
			stw		r30,quickfret(r29)				; Dequeue previous guy (really, it is ok to wait until after the release)
			b		erchkfret						; Try the next one...


			.align	5
			
ernoqfret:	mtcrf	0x60,r27						; Set CRs with thermal facilities
			rlwinm.	r0,r21,0,MSR_EE_BIT,MSR_EE_BIT	; Are interruptions going to be enabled?
			crandc	31,pfThermalb,pfThermIntb		; See if we have both thermometer and not interrupt facility
			la		r21,saver0(r31)					; Point to the first thing we restore
			crandc	31,cr0_eq,31					; Factor in enablement
			bf		31,tempisok						; No thermal checking needed...

;
;			We get to here if 1) there is a thermal facility, and 2) the hardware
;			will or cannot interrupt, and 3) the interrupt will be enabled after this point.
;
			
			mfspr	r16,thrm3						; Get thermal 3		
			mfspr	r14,thrm1						; Get thermal 2		
			rlwinm.	r16,r16,0,thrme,thrme			; Is the themometer enabled?
			mfspr	r15,thrm2						; Get thermal 2	
			beq-	tempisok						; No thermometer...
			rlwinm	r16,r14,2,28,31					; Cluster THRM1s TIE, V, TIN, and TIV at bottom 4 bits
			srawi	r0,r15,31						; Make a mask of 1s if temprature over
			rlwinm	r30,r15,2,28,31					; Cluster THRM2s TIE, V, TIN, and TIV at bottom 4 bits
;
;			Note that the following compare check that V, TIN, and TIV are set and that TIE is cleared.
;			This insures that we only emulate when the hardware is not set to interrupt.
;
			cmplwi	cr0,r16,7						; Is there a valid pending interruption for THRM1?
			cmplwi	cr1,r30,7						; Is there a valid pending interruption for THRM2?
			and		r15,r15,r0						; Keep high temp if that interrupted, zero if not
			cror	cr0_eq,cr0_eq,cr1_eq			; Merge both
			andc	r14,r14,r0						; Keep low if high did not interrupt, zero if it did
			bne+	tempisok						; Nope, temprature is in range
			
			li		r11,T_THERMAL					; Time to emulate a thermal interruption
			or		r14,r14,r15						; Get contents of interrupting register
			mr		r13,r31							; Make sure savearea is pointed to correctly
			stw		r11,saveexception(r31)			; Set the exception code
			stw		r14,savedar(r31)				; Set the contents of the interrupting register into the dar

;
;			This code is here to prevent a problem that will probably never happen.  If we are
;			returning from an emulation routine (alignment, altivec assist, etc.) the SRs may
;			not be set to the proper kernel values.  Then, if we were to emulate a thermal here,
;			we would end up running in the kernel with a bogus SR.  So, to prevent
;			this unfortunate circumstance, we slam the SRs here. (I worry too much...)
;

			lis		r30,hi16(KERNEL_SEG_REG0_VALUE)	; Get the high half of the kernel SR0 value
			mtsr	sr0,r30							; Set the kernel SR0 
			addis	r30,r30,0x0010					; Point to the second segment of kernel
			mtsr	sr1,r30							; Set the kernel SR1 
			addis	r30,r30,0x0010					; Point to the third segment of kernel
			mtsr	sr2,r30							; Set the kernel SR2 
			addis	r30,r30,0x0010					; Point to the third segment of kernel
			mtsr	sr3,r30							; Set the kernel SR3
			b		Redrive							; Go process this new interruption...


tempisok:	dcbt	0,r21							; Touch in the first thing we need
			
;
;			Here we release the savearea.
;
;			Important!!!!  The savearea is released before we are done with it. When the
;			local free savearea list (anchored at lclfree) gets too long, save_ret_phys
;			will trim the list, making the extra saveareas allocatable by another processor
;			The code in there must ALWAYS leave our savearea on the local list, otherwise
;			we could be very, very unhappy.  The code there always queues the "just released"
;			savearea to the head of the local list.  Then, if it needs to trim, it will
;			start with the SECOND savearea, leaving ours intact.
;
;			Build the SR values depending upon destination.  If we are going to the kernel,
;			the SRs are almost all the way set up. SR14 (or the currently used copyin/out register)
;			must be set to whatever it was at the last exception because it varies.  All the rest
;			have been set up already.
;
;			If we are going into user space, we need to check a bit more. SR0, SR1, SR2, and
;			SR14 (current implementation) must be restored always.  The others must be set if
;			they are different that what was loaded last time (i.e., tasks have switched).  
;			We check the last loaded address space ID and if the same, we skip the loads.  
;			This is a performance gain because SR manipulations are slow.
;
;			There is also the special case when MSR_RI is set.  This happens when we are trying to
;			make a special user state access when we are in the kernel.  If we take an exception when
;			during that, the SRs may have been modified.  Therefore, we need to restore them to
;			what they were before the exception because they could be non-standard.  We saved them
;			during exception entry, so we will just load them here.
;

			mr		r3,r31							; Get the exiting savearea in parm register
			bl		EXT(save_ret_phys)				; Put it on the free list			

			li		r3,savesrr1						; Get offset to the srr1 value

			lwarx	r26,r3,r31						; Get destination MSR and take reservation along the way (just so we can blow it away)
			lwz		r7,PP_USERPMAP(r29)				; Pick up the user pmap we may launch
			rlwinm.	r17,r26,0,MSR_RI_BIT,MSR_RI_BIT	; See if we are returning from a special fault
			cmplw	cr3,r14,r14						; Set that we do not need to stop streams

			beq+	nSpecAcc						; Do not reload the kernel SRs if this is not a special access...

			lwz		r14,savesr0(r31)				; Get SR0 at fault time
			mtsr	sr0,r14							; Set SR0
			lwz		r14,savesr1(r31)				; Get SR1 at fault time
			mtsr	sr1,r14							; Set SR1
			lwz		r14,savesr2(r31)				; Get SR2 at fault time
			mtsr	sr2,r14							; Set SR2
			lwz		r14,savesr3(r31)				; Get SR3 at fault timee
			mtsr	sr3,r14							; Set SR3
			b		segsdone						; We are all set up now...

			.align	5

nSpecAcc:	rlwinm.	r17,r26,0,MSR_PR_BIT,MSR_PR_BIT	; See if we are going to user or system
			li		r14,PMAP_SEGS					; Point to segments 
			bne+	gotouser						; We are going into user state...

			lwz		r14,savesr14(r31)				; Get the copyin/out register at interrupt time
			mtsr	sr14,r14						; Set SR14
			b		segsdone						; We are all set up now...
		
			.align	5

gotouser:	dcbt	r14,r7							; Touch the segment register contents
			lwz		r9,spcFlags(r29)				; Pick up the special flags
			lwz		r16,PP_LASTPMAP(r29)			; Pick up the last loaded pmap
			addi	r14,r14,32						; Second half of pmap segments
			rlwinm	r9,r9,userProtKeybit-2,2,2		; Isolate the user state protection key 
			lwz		r15,PMAP_SPACE(r7)				; Get the primary space
			lwz		r13,PMAP_VFLAGS(r7)				; Get the flags
			dcbt	r14,r7							; Touch second page
			oris	r15,r15,hi16(SEG_REG_PROT)		; Set segment 0 SR value
			mtcrf	0x0F,r13						; Set CRs to correspond to the subordinate spaces
			xor		r15,r15,r9						; Flip to proper segment register key
			lhz		r9,PP_CPU_FLAGS(r29)			; Get the processor flags

			addis	r13,r15,0x0000					; Get SR0 value
			bf		16,nlsr0						; No alternate here...
			lwz		r13,PMAP_SEGS+(0*4)(r7)			; Get SR0 value
			
nlsr0:		mtsr	sr0,r13							; Load up the SR
			rlwinm	r9,r9,(((31-MSR_BE_BIT)+(traceBEb+16+1))&31),MSR_BE_BIT,MSR_BE_BIT	; Set BE bit if special trace is on

			addis	r13,r15,0x0010					; Get SR1 value
			bf		17,nlsr1						; No alternate here...
			lwz		r13,PMAP_SEGS+(1*4)(r7)			; Get SR1 value
			
nlsr1:		mtsr	sr1,r13							; Load up the SR
			or		r26,r26,r9						; Flip on the BE bit for special trace if needed

			cmplw	cr3,r7,r16						; Are we running the same segs as last time?

			addis	r13,r15,0x0020					; Get SR2 value
			bf		18,nlsr2						; No alternate here...
			lwz		r13,PMAP_SEGS+(2*4)(r7)			; Get SR2 value
			
nlsr2:		mtsr	sr2,r13							; Load up the SR

			addis	r13,r15,0x0030					; Get SR3 value
			bf		19,nlsr3						; No alternate here...
			lwz		r13,PMAP_SEGS+(3*4)(r7)			; Get SR3 value
			
nlsr3:		mtsr	sr3,r13							; Load up the SR

			addis	r13,r15,0x00E0					; Get SR14 value
			bf		30,nlsr14						; No alternate here...
			lwz		r13,PMAP_SEGS+(14*4)(r7)		; Get SR14 value
			
nlsr14:		mtsr	sr14,r13						; Load up the SR

			beq+	cr3,segsdone					; All done if same pmap as last time...
			
			stw		r7,PP_LASTPMAP(r29)				; Remember what we just loaded			
			
			addis	r13,r15,0x0040					; Get SR4 value
			bf		20,nlsr4						; No alternate here...
			lwz		r13,PMAP_SEGS+(4*4)(r7)			; Get SR4 value
			
nlsr4:		mtsr	sr4,r13							; Load up the SR

			addis	r13,r15,0x0050					; Get SR5 value
			bf		21,nlsr5						; No alternate here...
			lwz		r13,PMAP_SEGS+(5*4)(r7)			; Get SR5 value
			
nlsr5:		mtsr	sr5,r13							; Load up the SR

			addis	r13,r15,0x0060					; Get SR6 value
			bf		22,nlsr6						; No alternate here...
			lwz		r13,PMAP_SEGS+(6*4)(r7)			; Get SR6 value
			
nlsr6:		mtsr	sr6,r13							; Load up the SR

			addis	r13,r15,0x0070					; Get SR7 value
			bf		23,nlsr7						; No alternate here...
			lwz		r13,PMAP_SEGS+(7*4)(r7)			; Get SR7 value
			
nlsr7:		mtsr	sr7,r13							; Load up the SR

			addis	r13,r15,0x0080					; Get SR8 value
			bf		24,nlsr8						; No alternate here...
			lwz		r13,PMAP_SEGS+(8*4)(r7)			; Get SR8 value
			
nlsr8:		mtsr	sr8,r13							; Load up the SR

			addis	r13,r15,0x0090					; Get SR9 value
			bf		25,nlsr9						; No alternate here...
			lwz		r13,PMAP_SEGS+(9*4)(r7)			; Get SR9 value
			
nlsr9:		mtsr	sr9,r13							; Load up the SR

			addis	r13,r15,0x00A0					; Get SR10 value
			bf		26,nlsr10						; No alternate here...
			lwz		r13,PMAP_SEGS+(10*4)(r7)		; Get SR10 value
			
nlsr10:		mtsr	sr10,r13						; Load up the SR

			addis	r13,r15,0x00B0					; Get SR11 value
			bf		27,nlsr11						; No alternate here...
			lwz		r13,PMAP_SEGS+(11*4)(r7)		; Get SR11 value
			
nlsr11:		mtsr	sr11,r13						; Load up the SR

			addis	r13,r15,0x00C0					; Get SR12 value
			bf		28,nlsr12						; No alternate here...
			lwz		r13,PMAP_SEGS+(12*4)(r7)		; Get SR12 value
			
nlsr12:		mtsr	sr12,r13						; Load up the SR

			addis	r13,r15,0x00D0					; Get SR13 value
			bf		29,nlsr13						; No alternate here...
			lwz		r13,PMAP_SEGS+(13*4)(r7)		; Get SR13 value
			
nlsr13:		mtsr	sr13,r13						; Load up the SR

			addis	r13,r15,0x00F0					; Get SR15 value
			bf		31,nlsr15						; No alternate here...
			lwz		r13,PMAP_SEGS+(15*4)(r7)		; Get SR15 value
			
nlsr15:		mtsr	sr15,r13						; Load up the SR
			
segsdone:	stwcx.	r26,r3,r31						; Blow away any reservations we hold

			li		r21,emfp0						; Point to the fp savearea
			lwz		r25,savesrr0(r31)				; Get the SRR0 to use
			la		r28,saver8(r31)					; Point to the next line to use
			dcbt	r21,r29							; Start moving in a work area
			lwz		r0,saver0(r31)					; Restore R0			
			dcbt	0,r28							; Touch it in 
			lwz		r1,saver1(r31)					; Restore R1	
			lwz		r2,saver2(r31)					; Restore R2	
			la		r28,saver16(r31)				; Point to the next line to get
			lwz		r3,saver3(r31)					; Restore R3
			mtcrf	0x80,r27						; Get facility availability flags (do not touch CR1-7)
			lwz		r4,saver4(r31)					; Restore R4
			mtsrr0	r25								; Restore the SRR0 now
			lwz		r5,saver5(r31)					; Restore R5
			mtsrr1	r26								; Restore the SRR1 now 
			lwz		r6,saver6(r31)					; Restore R6			
			
			dcbt	0,r28							; Touch that next line on in
			la		r28,savevscr(r31)				; Point to the saved facility context
			
			lwz		r7,saver7(r31)					; Restore R7	
			lwz		r8,saver8(r31)					; Restore R8	
			lwz		r9,saver9(r31)					; Restore R9			
			mfmsr	r26								; Get the current MSR
			dcbt	0,r28							; Touch saved facility context		
			lwz		r10,saver10(r31)				; Restore R10
			lwz		r11,saver11(r31)				; Restore R11			
			oris	r26,r26,hi16(MASK(MSR_VEC))		; Get the vector enable bit
			lwz		r12,saver12(r31)				; Restore R12
			ori		r26,r26,lo16(MASK(MSR_FP))		; Add in the float enable
			lwz		r13,saver13(r31)				; Restore R13			
			la		r28,saver24(r31)				; Point to the next line to do 

;
;			Note that floating point and vector will be enabled from here on until the RFI
;

			mtmsr	r26								; Turn on vectors and floating point
			isync

			dcbt	0,r28							; Touch next line to do	

			lwz		r14,saver14(r31)				; Restore R14	
			lwz		r15,saver15(r31)				; Restore R15			

			bf		pfAltivecb,noavec3				; No Altivec on this CPU...
			
			la		r28,savevscr(r31)				; Point to the status area
			stvxl	v0,r21,r29						; Save a vector register
			lvxl	v0,0,r28						; Get the vector status
			lwz		r27,savevrsave(r31)				; Get the vrsave
			mtvscr	v0								; Set the vector status

			lvxl	v0,r21,r29						; Restore work vector register
			beq+	cr3,noavec2						; SRs have not changed, no need to stop the streams...
			dssall									; Kill all data streams
			sync
		
noavec2:	mtspr	vrsave,r27						; Set the vrsave

noavec3:	bf-		pfFloatb,nofphere				; Skip if no floating point...

			stfd	f0,emfp0(r29)					; Save FP0
			lfd		f0,savefpscrpad(r31)			; Get the fpscr
			mtfsf	0xFF,f0							; Restore fpscr		
			lfd		f0,emfp0(r29)					; Restore the used register

nofphere:	lwz		r16,saver16(r31)				; Restore R16
			lwz		r17,saver17(r31)				; Restore R17
			lwz		r18,saver18(r31)				; Restore R18	
			lwz		r19,saver19(r31)				; Restore R19	
			lwz		r20,saver20(r31)				; Restore R20
			lwz		r21,saver21(r31)				; Restore R21
			lwz		r22,saver22(r31)				; Restore R22

			lwz		r23,saver23(r31)				; Restore R23
			lwz		r24,saver24(r31)				; Restore R24			
			lwz		r25,saver25(r31)				; Restore R25			
			lwz		r26,saver26(r31)				; Restore R26		
			lwz		r27,saver27(r31)				; Restore R27			

			lwz		r28,savecr(r31)					; Get CR to restore

			lwz		r29,savexer(r31)				; Get XER to restore
			mtcr	r28								; Restore the CR
			lwz		r28,savelr(r31)					; Get LR to restore
			mtxer	r29								; Restore the XER
			lwz		r29,savectr(r31)				; Get the CTR to restore
			mtlr	r28								; Restore the LR 
			lwz		r28,saver30(r31)				; Get R30
			mtctr	r29								; Restore the CTR
			lwz		r29,saver31(r31)				; Get R31
			mtsprg	2,r28							; Save R30 for later
			lwz		r28,saver28(r31)				; Restore R28			
			mtsprg	3,r29							; Save R31 for later
			lwz		r29,saver29(r31)				; Restore R29

			mfsprg	r31,0							; Get per_proc
			mfsprg	r30,2							; Restore R30 
			lwz		r31,pfAvailable(r31)			; Get the feature flags
			mtsprg	2,r31							; Set the feature flags
			mfsprg	r31,3							; Restore R31

			rfi										; Click heels three times and think very hard that there is no place like home...

			.long	0								; Leave this here
			.long	0
			.long	0
			.long	0
			.long	0
			.long	0
			.long	0
			.long	0



	
/*
 * exception_exit(savearea *)
 *
 *
 * ENTRY :	IR and/or DR and/or interruptions can be on
 *			R3 points to the physical address of a savearea
 */
	
			.align	5
			.globl	EXT(exception_exit)

LEXT(exception_exit)

			mfsprg	r29,2							; Get feature flags
			mfmsr	r30								; Get the current MSR 
			mtcrf	0x04,r29						; Set the features			
			rlwinm	r30,r30,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			mr		r31,r3							; Get the savearea in the right register 
			rlwinm	r30,r30,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			li		r10,savesrr0					; Point to one of the first things we touch in the savearea on exit
			andi.	r30,r30,0x7FCF					; Turn off externals, IR, and DR 
			lis		r1,hi16(SAVredrive)				; Get redrive request

			bt		pfNoMSRirb,eeNoMSR				; No MSR...

			mtmsr	r30								; Translation and all off
			isync									; Toss prefetch
			b		eeNoMSRx
			
eeNoMSR:	li		r0,loadMSR						; Get the MSR setter SC
			mr		r3,r30							; Get new MSR
			sc										; Set it

eeNoMSRx:	dcbt	r10,r31							; Touch in the first stuff we restore
			mfsprg	r2,0							; Get the per_proc block
			lwz		r4,SAVflags(r31)				; Pick up the flags
			mr		r13,r31							; Put savearea here also

			and.	r0,r4,r1						; Check if redrive requested
			andc	r4,r4,r1						; Clear redrive
			
			dcbt	br0,r2							; We will need this in just a sec

			beq+	EatRupt							; No redrive, just exit...

			lwz		r11,saveexception(r13)			; Restore exception code
			stw		r4,SAVflags(r13)				; Set the flags
			b		Redrive							; Redrive the exception...
		

/*
 *		Start of the trace table
 */
 
 			.align	12								/* Align to 4k boundary */
	
			.globl EXT(traceTableBeg)
EXT(traceTableBeg):									/* Start of trace table */
/*			.fill	2048,4,0		  			       Make an 8k trace table for now */
			.fill	13760,4,0						/* Make an .trace table for now */
/*			.fill	240000,4,0		   				   Make an .trace table for now */
			.globl EXT(traceTableEnd)
EXT(traceTableEnd):									/* End of trace table */
	
			.globl EXT(ExceptionVectorsEnd)
EXT(ExceptionVectorsEnd):							/* Used if relocating the exception vectors */
#ifndef HACKALERTHACKALERT
/* 
 *		This .long needs to be here because the linker gets confused and tries to 
 *		include the final label in a section in the next section if there is nothing 
 *		after it
 */
	.long	0						/* (HACK/HACK/HACK) */
#endif

	.data
	.align	ALIGN
	.globl	EXT(exception_end)
EXT(exception_end):
	.long	EXT(ExceptionVectorsEnd) -EXT(ExceptionVectorsStart) /* phys fn */



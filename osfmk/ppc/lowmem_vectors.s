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
#include <mach/ppc/vm_param.h>
#include <ppc/POWERMAC/mp/MPPlugIn.h>

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
			mfsprg	r13,1							/* Get the exception save area */
			li		r11,T_RESET						/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			Machine check 
 */

			. = 0x200
.L_handler200:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			mfsprg	r13,1							/* Get the exception save area */
			li		r11,T_MACHINE_CHECK				/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			Data access - page fault, invalid memory rights for operation
 */

			. = 0x300
.L_handler300:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			mfsprg	r13,1							/* Get the exception save area */
			li		r11,T_DATA_ACCESS				/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			Instruction access - as for data access
 */

			. = 0x400
.L_handler400:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			mfsprg	r13,1							/* Get the exception save area */
			li		r11,T_INSTRUCTION_ACCESS		/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			External interrupt
 */

			. = 0x500
.L_handler500:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			mfsprg	r13,1							/* Get the exception save area */
			li		r11,T_INTERRUPT					/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			Alignment - many reasons
 */

			. = 0x600
.L_handler600:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			mfsprg	r13,1							/* Get the exception save area */
			li		r11,T_ALIGNMENT					/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			Program - floating point exception, illegal inst, priv inst, user trap
 */

			. = 0x700
.L_handler700:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			mfsprg	r13,1							/* Get the exception save area */
			li		r11,T_PROGRAM					/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			Floating point disabled
 */

			. = 0x800
.L_handler800:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			mfsprg	r13,1							/* Get the exception save area */
			li		r11,T_FP_UNAVAILABLE			/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */


/*
 * 			Decrementer - DEC register has passed zero.
 */

			. = 0x900
.L_handler900:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			mfsprg	r13,1							/* Get the exception save area */
			li		r11,T_DECREMENTER				/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			I/O controller interface error - MACH does not use this
 */

			. = 0xA00
.L_handlerA00:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			mfsprg	r13,1							/* Get the exception save area */
			li		r11,T_IO_ERROR					/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			Reserved
 */

			. = 0xB00
.L_handlerB00:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			mfsprg	r13,1							/* Get the exception save area */
			li		r11,T_RESERVED					/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			System call - generated by the sc instruction
 */

			. = 0xC00
.L_handlerC00:
			mtsprg	3,r11							; Save R11
			mtsprg	2,r13							; Save R13
			mfcr	r11								; Save the CR
			
;			Note: this first compare takes care of almost all of the non-fast paths
;			BSD system calls are negative and, platform-specific and mach system 
;			calls are all less than 0x7000.
;
;			Note that 0x7FF2 and 0x7FF3 are user state only and do not need to set sprg2.

			cmpwi	r0,0x7FF2						; Ultra fast path cthread info call?
			blt+	notufp							; Not ultra fast...
			mfsprg	r13,0							; Get the per_proc_area
			cmplwi	cr1,r0,0x7FF4					; Ultra fast path fp/vec facility state?
			bgt+	cr1,notufp						; Not ultra fast...
			beq+	cr1,scloadmsr					; It is the load msr guy...
			lwz		r13,spcFlags(r13)				; Get the facility status
			rlwinm.	r13,r13,0,runningVMbit,runningVMbit	; Are we running a VM right now?
			bne-	notufp							; Yes, no fast trap allowed...
			
			mfsprg	r11,3							; Restore R11
			mfsprg	r3,0							; Get the per_proc_area
			mfsprg	r13,2							; Restore R13
			beq-	cr1,isvecfp						; This is the facility stat call
			lwz		r3,UAW(r3)						; Get the assist word
			rfi										; All done, scream back... (no need to restore CR or R11, they are volatile)
;
isvecfp:	lwz		r3,spcFlags(r3)					; Get the facility status
			rfi										; Bail back...
;
			.align	5
notufp:		mtcrf	0xC0,r11						; Restore the used CRs
			li		r11,T_SYSTEM_CALL				; Set interrupt code
			mfsprg	r13,1							; Get the exception save area 
			b		.L_exception_entry				; Join common...
			
scloadmsr:	mfsrr1	r13								; Get the old SRR
			rlwinm.	r13,r13,0,MSR_PR_BIT,MSR_PR_BIT	; From problem state?
			mfsprg	r13,0							; Restore per_proc
			bne-	notufp							; Someone is trying to cheat...
			
			mtcrf	0xC0,r11						; Restore CR
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
			mfsprg	r13,1							; Get the savearea	
			li		r11,T_TRACE						; Set interrupt code
			b		.L_exception_entry				; Join common...

;
;			We are doing the special branch trace
;

specbrtr:	mfsprg	r13,0							; Get the per_proc area
			stw		r1,emfp0(r13)					; Save in a scratch area
			stw		r2,emfp0+4(r13)					; Save in a scratch area
			stw		r3,emfp0+8(r13)					; Save in a scratch area

			lwz		r1,spcTRc(r13)					; Pick up the count
			lis		r2,hi16(EXT(pc_trace_buf))		; Get the top of the buffer
			subi	r1,r1,1							; Count down
			lwz		r3,spcTRp(r13)					; Pick up buffer position			
			mr.		r1,r1							; Is it time to count?
			ori		r2,r2,lo16(EXT(pc_trace_buf))	; Get the bottom of the buffer
			cmplwi	cr1,r3,4092						; Set cr1_eq if we should take exception
			ble+	spclogpc						; We are logging this one...
			cmplwi	cr1,r2,0						; Set cr1_eq false so we do not take an interrupt
			b		spcskip							; Fly away...
			
spclogpc:	mfsrr0	r1								; Get the pc
			stwx	r1,r2,r3						; Save it in the buffer
			addi	r3,r3,4							; Point to the next slot
			li		r1,2							; Number of branches to skip
			rlwinm	r3,r3,0,20,31					; Wrap the slot at one page
			stw		r3,spcTRp(r13)					; Save the new slot

spcskip:	stw		r1,spcTRc(r13)					; Save the new count

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
			mfsprg	r13,1							/* Get the exception save area */
			li		r11,T_FP_ASSIST					/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */


/*
 *			Performance monitor interruption
 */

 			. = 0xF00
PMIhandler:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			mfsprg	r13,1							/* Get the exception save area */
			li		r11,T_PERF_MON					/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */
	

/*
 *			VMX exception
 */

 			. = 0xF20
VMXhandler:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			mfsprg	r13,1							/* Get the exception save area */
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
			mfsprg	r13,1							/* Get the exception save area */
			li		r11,T_INSTRUCTION_BKPT			/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			System management interrupt
 */

			. = 0x1400
.L_handler1400:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			mfsprg	r13,1							/* Get the exception save area */
			li		r11,T_SYSTEM_MANAGEMENT			/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

;
; 			Altivec Java Mode Assist interrupt
;

			. = 0x1600
.L_handler1600:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			mfsprg	r13,1							/* Get the exception save area */
			li		r11,T_ALTIVEC_ASSIST			/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

;
; 			Thermal interruption
;

			. = 0x1700
.L_handler1700:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			mfsprg	r13,1							/* Get the exception save area */
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
			mfsprg	r13,1							/* Get the exception save area */
			li		r11,T_RUNMODE_TRACE				/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

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

			stw		r1,saver1(r13)					; Save register 1
			stw		r0,saver0(r13)					; Save register 0
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
			li		r1,32							; Point to the next line in case we need it
			crnot	wasNapping,cr0_eq				; Remember if we were napping
			mfsprg	r2,0							; Get the per_proc area
			bf-		featL1ena,skipz1				; L1 cache is disabled...
			dcbz	r1,r13							; Reserve our line in cache
			
;
;			Remember, we are setting up CR6 with feature flags
;
skipz1:		lwz		r1,pfAvailable(r2)				; Get the CPU features flags			
			stw		r3,saver3(r13)					; Save this one
			mtcrf	0xE0,r1							; Put the features flags (that we care about) in the CR
			stw		r4,saver4(r13)					; Save this one
			stw		r6,saver6(r13)					; Save this one
			crmove	featSMP,pfSMPcapb				; See if we have a PIR
			stw		r8,saver8(r13)					; Save this one
			crmove	featAltivec,pfAltivecb			; Set the Altivec flag
			mfsrr0	r6								/* Get the interruption SRR0 */
			stw		r8,saver8(r13)					/* Save this one */
			crmove	featFP,pfFloatb					; Remember that we have floating point
			stw		r7,saver7(r13)					/* Save this one */
			lhz		r8,PP_CPU_FLAGS(r2)				; Get the flags
			mfsrr1	r7								/* Get the interrupt SRR1 */
			rlwinm	r8,r8,(((31-MSR_BE_BIT)+(traceBEb+16+1))&31),MSR_BE_BIT,MSR_BE_BIT	; Set BE bit if special trace is on
			stw		r6,savesrr0(r13)				/* Save the SRR0 */
			rlwinm	r6,r7,(((31-MSR_BE_BIT)+(MSR_PR_BIT+1))&31),MSR_BE_BIT,MSR_BE_BIT	; Move PR bit to BE bit
			stw		r5,saver5(r13)					/* Save this one */
			and		r8,r6,r8						; Remove BE bit only if problem state and special tracing on
			mfsprg	r6,2							; Get interrupt time R13
			mtsprg	2,r1							; Set the feature flags
			andc	r7,r7,r8						; Clear BE bit if special trace is on and PR is set
			mfsprg	r8,3							/* Get 'rupt time R11 */
			stw		r7,savesrr1(r13)				/* Save SRR1 */
			stw		r6,saver13(r13)					/* Save 'rupt R1 */
			stw		r8,saver11(r13)					/* Save 'rupt time R11 */

getTB:		mftbu	r6								; Get the upper timebase
			mftb	r7								; Get the lower timebase
			mftbu	r8								; Get the upper one again
			cmplw	r6,r8							; Did the top tick?
			bne-	getTB							; Yeah, need to get it again...

			stw		r8,ruptStamp(r2)				; Save the top of time stamp
			la		r6,saver14(r13)					; Point to the next cache line
			stw		r7,ruptStamp+4(r2)				; Save the bottom of time stamp
			bf-		featL1ena,skipz2				; L1 cache is disabled...
			dcbz	0,r6							/* Allocate in cache */
skipz2:			
			stw		r9,saver9(r13)					/* Save this one */

			la		r9,saver30(r13)					/* Point to the trailing end */
			stw		r10,saver10(r13)				/* Save this one */
			mflr	r4								/* Get the LR */
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
			
notNapping:	stw		r12,saver12(r13)				/* Save this one */
						
			bf-		featL1ena,skipz3				; L1 cache is disabled...
			dcbz	0,r9							/* Allocate the last in the area */
skipz3:			
			stw		r14,saver14(r13)				/* Save this one */
			stw		r15,saver15(r13)				/* Save this one */
			la		r14,saver22(r13)				/* Point to the next block to save into */
			stw		r0,savecr(r13)					; Save rupt CR
			mfctr	r6								/* Get the CTR */
			stw		r16,saver16(r13)				/* Save this one */
			stw		r4,savelr(r13)					/* Save 'rupt LR */
		
			bf-		featL1ena,skipz4				; L1 cache is disabled...
			dcbz	0,r14							/* Allocate next save area line */
skipz4:			
			stw		r17,saver17(r13)				/* Save this one */
			stw		r18,saver18(r13)				/* Save this one */
			stw		r6,savectr(r13)					/* Save 'rupt CTR */
			stw		r19,saver19(r13)				/* Save this one */
			lis		r12,HIGH_ADDR(KERNEL_SEG_REG0_VALUE)	/* Get the high half of the kernel SR0 value */
			mfdar	r6								/* Get the 'rupt DAR */
			stw		r20,saver20(r13)				/* Save this one */
#if 0
			mfsr	r14,sr0							; (TEST/DEBUG)
			stw		r14,savesr0(r13)				; (TEST/DEBUG)
			mfsr	r14,sr1							; (TEST/DEBUG)
			stw		r14,savesr1(r13)				; (TEST/DEBUG)
			mfsr	r14,sr2							; (TEST/DEBUG)
			stw		r14,savesr2(r13)				; (TEST/DEBUG)
			mfsr	r14,sr3							; (TEST/DEBUG)
			stw		r14,savesr3(r13)				; (TEST/DEBUG)
			mfsr	r14,sr4							; (TEST/DEBUG)
			stw		r14,savesr4(r13)				; (TEST/DEBUG)
			mfsr	r14,sr5							; (TEST/DEBUG)
			stw		r14,savesr5(r13)				; (TEST/DEBUG)
			mfsr	r14,sr6							; (TEST/DEBUG)
			stw		r14,savesr6(r13)				; (TEST/DEBUG)
			mfsr	r14,sr7							; (TEST/DEBUG)
			stw		r14,savesr7(r13)				; (TEST/DEBUG)
			mfsr	r14,sr8							; (TEST/DEBUG)
			stw		r14,savesr8(r13)				; (TEST/DEBUG)
			mfsr	r14,sr9							; (TEST/DEBUG)
			stw		r14,savesr9(r13)				; (TEST/DEBUG)
			mfsr	r14,sr10						; (TEST/DEBUG)
			stw		r14,savesr10(r13)				; (TEST/DEBUG)
			mfsr	r14,sr11						; (TEST/DEBUG)
			stw		r14,savesr11(r13)				; (TEST/DEBUG)
			mfsr	r14,sr12						; (TEST/DEBUG)
			stw		r14,savesr12(r13)				; (TEST/DEBUG)
			mfsr	r14,sr13						; (TEST/DEBUG)
			stw		r14,savesr13(r13)				; (TEST/DEBUG)
			mfsr	r14,sr15						; (TEST/DEBUG)
			stw		r14,savesr15(r13)				; (TEST/DEBUG)
#endif

			mtsr	sr0,r12							/* Set the kernel SR0 */
			stw		r21,saver21(r13)				/* Save this one */
			addis	r12,r12,0x0010					; Point to the second segment of kernel
			stw		r10,savexer(r13)				; Save the rupt XER
			mtsr	sr1,r12							/* Set the kernel SR1 */
			stw		r30,saver30(r13)				/* Save this one */
			addis	r12,r12,0x0010					; Point to the third segment of kernel
			stw		r31,saver31(r13)				/* Save this one */
			mtsr	sr2,r12							/* Set the kernel SR2 */
			stw		r22,saver22(r13)				/* Save this one */
			addis	r12,r12,0x0010					; Point to the third segment of kernel
			la		r10,savedar(r13)				/* Point to exception info block */
			stw		r23,saver23(r13)				/* Save this one */
			mtsr	sr3,r12							/* Set the kernel SR3 */
			stw		r24,saver24(r13)				/* Save this one */
			stw		r25,saver25(r13)				/* Save this one */
			mfdsisr	r7								/* Get the 'rupt DSISR */
			stw		r26,saver26(r13)				/* Save this one */
			
			bf-		featL1ena,skipz5				; L1 cache is disabled...
			dcbz	0,r10							/* Allocate exception info line */
skipz5:
		
			stw		r27,saver27(r13)				/* Save this one */
			li		r10,emfp0						; Point to floating point save
			stw		r28,saver28(r13)				/* Save this one */
			stw		r29,saver29(r13)				/* Save this one */
			mfsr	r14,sr14						; Get the copyin/out segment register
			stw		r6,savedar(r13)					/* Save the 'rupt DAR */
			bf-		featL1ena,skipz5a				; Do not do this if no L1...
			dcbz	r10,r2							; Clear and allocate an L1 slot
			
skipz5a:	stw		r7,savedsisr(r13)				/* Save the 'rupt code DSISR */
			stw		r11,saveexception(r13)			/* Save the exception code */
			stw		r14,savesr14(r13)				; Save copyin/copyout

			lis		r8,HIGH_ADDR(EXT(saveanchor))	/* Get the high part of the anchor */
			li		r19,0							; Assume no Altivec
			ori		r8,r8,LOW_ADDR(EXT(saveanchor))	/* Bottom half of the anchor */
			
			bf		featAltivec,noavec				; No Altivec on this CPU...
			li		r9,0							; Get set to clear VRSAVE
			mfspr	r19,vrsave						; Get the VRSAVE register
			mtspr	vrsave,r9						; Clear VRSAVE for each interrupt level
;
;			We need to save the FPSCR as if it is normal context.
;			This is because pending exceptions will cause an exception even if
;			FP is disabled. We need to clear the FPSCR when we first start running in the
;			kernel.
;
noavec:		stw		r19,savevrsave(r13)				; Save the vector register usage flags

			bf-		featFP,nofpexe					; No possible floating point exceptions...
			
			mfmsr	r9								; Get the MSR value
			ori		r7,r9,lo16(MASK(MSR_FP))		; Enable floating point
			mtmsr	r7								; Do it
			isync
			stfd	f0,emfp0(r2)					; Save FPR0	
			stfd	f1,emfp1(r2)					; Save FPR1	
			mffs	f0								; Get the FPSCR
			fsub	f1,f1,f1						; Make a 0			
			stfd	f0,savexfpscrpad(r13)			; Save the FPSCR
			mtfsf	0xFF,f1							; Clear it
			lfd		f0,emfp0(r2)					; Restore FPR0	
			lfd		f1,emfp1(r2)					; Restore FPR1	
			mtmsr	r9								; Turn off FP
			isync
nofpexe:			

/* 
 *			Everything is saved at this point, except for FPRs, and VMX registers
 *
 *			Time for a new save area.  Allocate the trace table entry now also
 *			Note that we haven't touched R0-R5 yet.  Except for R0 & R1, that's in the save
 */


lllck:		lwarx	r9,0,r8							/* Grab the lock value */
			li		r7,1							/* Use part of the delay time */
			mr.		r9,r9							/* Is it locked? */
			bne-	lllcks							/* Yeah, wait for it to clear... */
			stwcx.	r7,0,r8							/* Try to seize that there durn lock */
			beq+	lllckd							/* Got it... */
			b		lllck							/* Collision, try again... */
			
lllcks:		lwz		r9,SVlock(r8)					/* Get that lock in here */
			mr.		r9,r9							/* Is it free yet? */
			beq+	lllck							/* Yeah, try for it again... */
			b		lllcks							/* Sniff away... */
			
lllckd:		isync									/* Purge any speculative executions here */
			lis		r23,hi16(EXT(trcWork))			; Get the work area address
			rlwinm	r7,r11,30,0,31					/* Save 'rupt code shifted right 2 */
			ori		r23,r23,lo16(EXT(trcWork))		; Get the rest
#if 1
			lwz		r14,traceMask(r23)				/* Get the trace mask */
#else
			li		r14,-1							/* (TEST/DEBUG) */
#endif
			addi	r7,r7,10						/* Adjust for CR5_EQ position */	
			lwz		r15,SVfree(r8)					/* Get the head of the save area list */			
			lwz		r25,SVinuse(r8)					/* Get the in use count */			
			rlwnm	r7,r14,r7,22,22					/* Set CR5_EQ bit position to 0 if tracing allowed */
			lwz		r20,traceCurr(r23)				/* Pick up the current trace entry */
			mtcrf	0x04,r7							/* Set CR5 to show trace or not */

			lwz		r14,SACalloc(r15)				/* Pick up the allocation bits */
			addi	r25,r25,1						/* Bump up the in use count for the new savearea */
			lwz		r21,traceEnd(r23)				/* Grab up the end of it all */
			mr.		r14,r14							/* Can we use the first one? */
			blt		use1st							/* Yeah... */
			
			andis.	r14,r14,0x8000					/* Show we used the second and remember if it was the last */
			addi	r10,r15,0x0800					/* Point to the first one */
			b		gotsave							/* We have the area now... */

use1st:		andis.	r14,r14,0x4000					/* Mark first gone and remember if empty */
			mr		r10,r15							/* Set the save area */
			
gotsave:	stw		r14,SACalloc(r15)				/* Put back the allocation bits */
			bne		nodqsave						/* There's still an empty slot, don't dequeue... */

			lwz		r16,SACnext(r15)				/* Get the next in line */
			stw		r16,SVfree(r8)					/* Dequeue our now empty save area block */

nodqsave:	addi	r22,r20,LTR_size				/* Point to the next trace entry */
			stw		r25,SVinuse(r8)					/* Set the in use count */			
			li		r17,0							/* Clear this for the lock */
			cmplw	r22,r21							/* Do we need to wrap the trace table? */
			stw		r17,SAVprev(r10)				/* Clear back pointer for the newly allocated guy */
			mtsprg	1,r10							/* Get set for the next 'rupt */
			bne+	gotTrcEnt						/* We got a trace entry... */
			
			lwz		r22,traceStart(r23)				/* Wrap back to the top */

gotTrcEnt:	bne-	cr5,skipTrace1					/* Don't want to trace this kind... */
	
			stw		r22,traceCurr(r23)				/* Set the next entry for the next guy */
			
#if ESPDEBUG
			dcbst	br0,r23							; (TEST/DEBUG)
			sync									; (TEST/DEBUG)
#endif
			
			bf-		featL1ena,skipz6				; L1 cache is disabled...
			dcbz	0,r20							/* Allocate cache for the entry */
skipz6:
			
skipTrace1:	sync									/* Make sure all stores are done */
			stw		r17,SVlock(r8)					/* Unlock both save and trace areas */


/*
 *			At this point, we can take another exception and lose nothing.
 *
 *			We still have the current savearea pointed to by R13, the next by R10 and
 *			sprg1.  R20 contains the pointer to a trace entry and CR5_eq says
 *			to do the trace or not.
 *
 *			Note that R13 was chosen as the save area pointer because the SIGP,
 *			firmware, and DSI/ISI handlers aren't supposed to touch anything
 *			over R12. But, actually, the DSI/ISI stuff does.
 *
 *
 *			Let's cut that trace entry now.
 */

			lwz		r0,saver0(r13)					; Get back interrupt time R0
			bne-	cr5,skipTrace2					/* Don't want to trace this kind... */

			mfsprg	r2,0							; Get the per_proc
			li		r14,32							/* Second line of entry */

			lwz		r16,ruptStamp(r2)				; Get top of time base
			lwz		r17,ruptStamp+4(r2)				; Get the bottom of time stamp
		
			bf-		featL1ena,skipz7				; L1 cache is disabled...
			dcbz	r14,r20							/* Zap the second half */

skipz7:		stw		r16,LTR_timeHi(r20)				/* Set the upper part of TB */
			bf		featSMP,nopir4					; Is there a processor ID register on this guy?
			mfspr	r19,pir							/* Get the processor address */
			b		gotpir4							/* Got it... */
nopir4:		li		r19,0							/* Assume processor 0 for those underprivileged folks */
gotpir4:											
			lwz		r1,saver1(r13)					; Get back interrupt time R1
			stw		r17,LTR_timeLo(r20)				/* Set the lower part of TB */
			rlwinm	r19,r19,0,27,31					/* Cut the junk */
			lwz		r2,saver2(r13)					; Get back interrupt time R2
			stw		r0,LTR_r0(r20)					/* Save off register 0 */			
			lwz		r3,saver3(r13)					; Restore this one
			sth		r19,LTR_cpu(r20)				/* Stash the cpu address */
			stw		r1,LTR_r1(r20)					/* Save off register 1 */			
			lwz		r4,saver4(r13)					; Restore this one
			stw		r2,LTR_r2(r20)					/* Save off register 2 */			
			lwz		r5,saver5(r13)					; Restore this one
			stw		r3,LTR_r3(r20)					/* Save off register 3 */	
			lwz		r16,savecr(r13)					/* We don't remember the CR anymore, get it */
			stw		r4,LTR_r4(r20)					/* Save off register 4 */
			mfsrr0	r17								/* Get this back, it's still good */
			stw		r5,LTR_r5(r20)					/* Save off register 5 */	
			mfsrr1	r18								/* This is still good in here also */
			
			stw		r16,LTR_cr(r20)					/* Save the CR (or dec) */
			stw		r17,LTR_srr0(r20)				/* Save the SSR0 */
			stw		r18,LTR_srr1(r20)				/* Save the SRR1 */
			mfdar	r17								/* Get this back */

			mflr	r16								/* Get the LR */
			stw		r17,LTR_dar(r20)				/* Save the DAR */
			mfctr	r17								/* Get the CTR */
			stw		r16,LTR_lr(r20)					/* Save the LR */
#if 0
			lis		r17,HIGH_ADDR(EXT(saveanchor))	; (TEST/DEBUG)
			ori		r17,r17,LOW_ADDR(EXT(saveanchor))	; (TEST/DEBUG)
			lwz		r16,SVcount(r17)				; (TEST/DEBUG)
			lwz		r17,SVinuse(r17)				; (TEST/DEBUG)
			rlwimi	r17,r16,16,0,15					; (TEST/DEBUG)
#endif
			stw		r17,LTR_ctr(r20)				/* Save off the CTR */
			stw		r13,LTR_save(r20)				/* Save the savearea */
			sth		r11,LTR_excpt(r20)				/* Save the exception type */
#if ESPDEBUG
			addi	r17,r20,32						; (TEST/DEBUG)
			dcbst	br0,r20							; (TEST/DEBUG)
			dcbst	br0,r17							; (TEST/DEBUG)
			sync									; (TEST/DEBUG)
#endif

/*
 *			We're done with the trace, except for maybe modifying the exception
 *			code later on. So, that means that we need to save R20 and CR5, but
 *			R0 to R5 are clear now.
 *			
 *			So, let's finish setting up the kernel registers now.
 */

skipTrace2:	

#if PERFTIMES && DEBUG
			li		r3,68							; Indicate interrupt
			mr		r4,r11							; Get code to log
			mr		r5,r13							; Get savearea to log
			mr		r8,r0							; Save R0
			bl		EXT(dbgLog2)					; Cut log entry
			mr		r0,r8							; Restore R0
#endif

			mfsprg	r2,0							/* Get the per processor block */

#if CHECKSAVE

			lis		r4,0x7FFF						/* (TEST/DEBUG) */
			mfdec	r12								/* (TEST/DEBUG) */
			or		r4,r4,r12						/* (TEST/DEBUG) */
			mtdec	r4								/* (TEST/DEBUG) */
			li		r4,0x20							/* (TEST/DEBUG) */
		
			lwarx	r8,0,r4							; ?

mpwait2:	lwarx	r8,0,r4							/* (TEST/DEBUG) */
			mr.		r8,r8							/* (TEST/DEBUG) */
			bne-	mpwait2							/* (TEST/DEBUG) */
			stwcx.	r4,0,r4							/* (TEST/DEBUG) */
			bne-	mpwait2							/* (TEST/DEBUG) */

			isync									/* (TEST/DEBUG) */
			lwz		r4,0xD80(br0)					/* (TEST/DEBUG) */
			mr.		r4,r4							/* (TEST/DEBUG) */
			li		r4,1							/* (TEST/DEBUG) */
			bne-	doncheksv						/* (TEST/DEBUG) */
		
			lis		r8,HIGH_ADDR(EXT(saveanchor))	/* (TEST/DEBUG) */
			ori		r8,r8,LOW_ADDR(EXT(saveanchor))	/* (TEST/DEBUG) */
		
			stw		r4,0xD80(br0)					/* (TEST/DEBUG) */

			lwarx	r4,0,r8							; ?

mpwait2x:	lwarx	r4,0,r8							/* (TEST/DEBUG) */
			mr.		r4,r4							/* (TEST/DEBUG) */
			bne-	mpwait2x						/* (TEST/DEBUG) */
			stwcx.	r8,0,r8							/* (TEST/DEBUG) */
			bne-	mpwait2x						/* (TEST/DEBUG) */

			isync									/* (TEST/DEBUG) */

#if 0
			rlwinm	r4,r13,0,0,19					/* (TEST/DEBUG) */
			lwz		r21,SACflags(r4)				/* (TEST/DEBUG) */
			rlwinm	r22,r21,24,24,31				/* (TEST/DEBUG) */
			cmplwi	r22,0x00EE						/* (TEST/DEBUG) */
			lwz		r22,SACvrswap(r4)				/* (TEST/DEBUG) */
			bne-	currbad							/* (TEST/DEBUG) */
			andis.	r21,r21,hi16(sac_perm)			/* (TEST/DEBUG) */
			bne-	currnotbad						/* (TEST/DEBUG) */
			mr.		r22,r22							/* (TEST/DEBUG) */
			bne+	currnotbad						/* (TEST/DEBUG) */
			
currbad:	lis		r23,hi16(EXT(debugbackpocket))	/* (TEST/DEBUG) */
			ori		r23,r23,lo16(EXT(debugbackpocket))	/* (TEST/DEBUG) */
			stw		r23,SVfree(r8)					/* (TEST/DEBUG) */

			mfsprg	r25,1							/* (TEST/DEBUG) */
			mtsprg	1,r23							/* (TEST/DEBUG) */
			lwz		r26,SACalloc(r23)				/* (TEST/DEBUG) */
			rlwinm	r26,r26,0,1,31					/* (TEST/DEBUG) */
			stw		r26,SACalloc(r23)				/* (TEST/DEBUG) */

			sync									/* (TEST/DEBUG) */
			li		r28,0							/* (TEST/DEBUG) */
			stw		r28,0x20(br0)					/* (TEST/DEBUG) */
			stw		r28,0(r8)						/* (TEST/DEBUG) */
			BREAKPOINT_TRAP							/* (TEST/DEBUG) */

currnotbad:			
#endif
		
			lwz		r28,SVcount(r8)					/* (TEST/DEBUG) */
			lwz		r21,SVinuse(r8)					/* (TEST/DEBUG) */
			lwz		r23,SVmin(r8)					/* (TEST/DEBUG) */
			sub		r22,r28,r21						/* (TEST/DEBUG) */
			cmpw	r22,r23							/* (TEST/DEBUG) */
			bge+	cksave0							/* (TEST/DEBUG) */
			
			li		r4,0							/* (TEST/DEBUG) */
			stw		r4,0x20(br0)					/* (TEST/DEBUG) */
			stw		r4,0(r8)						/* (TEST/DEBUG) */
			BREAKPOINT_TRAP							/* (TEST/DEBUG) */
			
cksave0:	lwz		r28,SVfree(r8)					/* (TEST/DEBUG) */
			li		r24,0							/* (TEST/DEBUG) */
			li		r29,1							/* (TEST/SAVE) */
			
cksave0a:	mr.		r28,r28							/* (TEST/DEBUG) */
			beq-	cksave3							/* (TEST/DEBUG) */
			
			rlwinm.	r21,r28,0,4,19					/* (TEST/DEBUG) */
			bne+	cksave1							/* (TEST/DEBUG) */
			
			li		r4,0							/* (TEST/DEBUG) */
			stw		r4,0x20(br0)					/* (TEST/DEBUG) */
			stw		r4,0(r8)						/* (TEST/DEBUG) */
			BREAKPOINT_TRAP							/* (TEST/DEBUG) */
			
cksave1:	rlwinm.	r21,r28,0,21,3					/* (TEST/DEBUG) */
			beq+	cksave2							/* (TEST/DEBUG) */
			
			li		r4,0							/* (TEST/DEBUG) */
			stw		r4,0x20(br0)					/* (TEST/DEBUG) */
			stw		r4,0(r8)						/* (TEST/DEBUG) */
			BREAKPOINT_TRAP							/* (TEST/DEBUG) */
			
cksave2:	lwz		r25,SACalloc(r28)				/* (TEST/DEBUG) */
			lbz		r26,SACflags+2(r28)				/* (TEST/DEBUG) */
			lbz		r21,SACflags+3(r28)				/* (TEST/DEBUG) */
			cmplwi	r26,0x00EE						/* (TEST/DEBUG) */
			stb		r29,SACflags+3(r28)				/* (TEST/DEBUG) */
			beq+	cksave2z
			
			li		r4,0							/* (TEST/DEBUG) */
			stw		r4,0x20(br0)					/* (TEST/DEBUG) */
			stw		r4,0(r8)						/* (TEST/DEBUG) */
			BREAKPOINT_TRAP							/* (TEST/DEBUG) */

cksave2z:	mr.		r21,r21							/* (TEST/DEBUG) */
			beq+	cksave2a						/* (TEST/DEBUG) */
			
			li		r4,0							/* (TEST/DEBUG) */
			stw		r4,0x20(br0)					/* (TEST/DEBUG) */
			stw		r4,0(r8)						/* (TEST/DEBUG) */
			BREAKPOINT_TRAP							/* (TEST/DEBUG) */

cksave2a:	rlwinm	r26,r25,1,31,31					/* (TEST/DEBUG) */
			rlwinm	r27,r25,2,31,31					/* (TEST/DEBUG) */
			add		r24,r24,r26						/* (TEST/DEBUG) */
			add		r24,r24,r27						/* (TEST/DEBUG) */
			lwz		r28,SACnext(r28)				/* (TEST/DEBUG) */
			b		cksave0a						/* (TEST/DEBUG) */
			
cksave3:	cmplw	r24,r22							/* (TEST/DEBUG) */
			beq+	cksave4							/* (TEST/DEBUG) */
			
			li		r4,0							/* (TEST/DEBUG) */
			stw		r4,0x20(br0)					/* (TEST/DEBUG) */
			stw		r4,0(r8)						/* (TEST/DEBUG) */
			BREAKPOINT_TRAP							/* (TEST/DEBUG) */
			
cksave4:	lwz		r28,SVfree(r8)					/* (TEST/DEBUG) */
			li		r24,0							/* (TEST/DEBUG) */

cksave5:	mr.		r28,r28							/* (TEST/DEBUG) */
			beq-	cksave6							/* (TEST/DEBUG) */
			stb		r24,SACflags+3(r28)				/* (TEST/DEBUG) */
			lwz		r28,SACnext(r28)				/* (TEST/DEBUG) */
			b		cksave5							/* (TEST/DEBUG) */

cksave6:	

			li		r4,0							/* (TEST/DEBUG) */
			stw		r4,0xD80(br0)					/* (TEST/DEBUG) */
			stw		r4,0(r8)						/* (TEST/DEBUG) */

doncheksv:
			li		r4,0							/* (TEST/DEBUG) */
			stw		r4,0x20(br0)					/* (TEST/DEBUG) */			
			mtdec	r12								/* (TEST/DEBUG) */
#endif

			lis		r4,HIGH_ADDR(EXT(MPspec))		/* Get the MP control block */
			dcbt	0,r2							/* We'll need the per_proc in a sec */
			cmplwi	cr0,r11,T_INTERRUPT				/* Do we have an external interrupt? */
			ori		r4,r4,LOW_ADDR(EXT(MPspec))		/* Get the bottom half of the MP control block */
			bne+	notracex						/* Not an external... */

/*
 *			Here we check to see if there was a interprocessor signal 
 */

			lwz		r4,MPSSIGPhandler(r4)			/* Get the address of the SIGP interrupt filter */
			lhz		r3,PP_CPU_FLAGS(r2)				/* Get the CPU flags */
			cmplwi	cr1,r4,0						/* Check if signal filter is initialized yet */
			andi.	r3,r3,LOW_ADDR(SIGPactive)		/* See if this processor has started up */
			mtlr	r4								/* Load up filter address */
			beq-	cr1,notracex					/* We don't have a filter yet... */			
			beq-	notracex						/* This processor hasn't started filtering yet... */
			
			blrl									/* Filter the interrupt */
		
			mfsprg	r2,0							/* Make sure we have the per processor block */			
			cmplwi	cr0,r3,kMPIOInterruptPending	/* See what the filter says */
			li		r11,T_INTERRUPT					/* Assume we have a regular external 'rupt */
			beq+	modRupt							/* Yeah, we figured it would be... */
			li		r11,T_SIGP						/* Assume we had a signal processor interrupt */
			bgt+	modRupt							/* Yeah, at this point we would assume so... */
			li		r11,T_IN_VAIN					/* Nothing there actually, so eat it */
			
modRupt:	stw		r11,PP_SAVE_EXCEPTION_TYPE(r2)	/* Set that it was either in vain or a SIGP */
			stw		r11,saveexception(r13)			/* Save the exception code here also */
			bne-	cr5,notracex					/* Jump if no tracing... */
			sth		r11,LTR_excpt(r20)				/* Save the exception type */

notracex:	

#if 0		
			bf		featSMP,nopir6					/* (TEST/DEBUG) */
			mfspr	r7,pir							/* (TEST/DEBUG) */
			b		gotpir6							/* (TEST/DEBUG) */
nopir6:		li		r7,0							/* (TEST/DEBUG) */
gotpir6:											/* (TEST/DEBUG) */
			lis		r6,HIGH_ADDR(EXT(RuptCtrs))		/* (TEST/DEBUG) */
			rlwinm	r7,r7,8,23,23					/* (TEST/DEBUG) */
			lis		r12,HIGH_ADDR(EXT(GratefulDeb))	/* (TEST/DEBUG) */
			rlwimi	r7,r7,1,22,22					/* (TEST/DEBUG) */
			ori		r6,r6,LOW_ADDR(EXT(RuptCtrs))	/* (TEST/DEBUG) */
			rlwinm	r1,r11,2,0,29					/* (TEST/DEBUG) */
			add		r6,r6,r7						/* (TEST/DEBUG) */
			ori		r12,r12,LOW_ADDR(EXT(GratefulDeb))	/* (TEST/DEBUG) */
			lwz		r21,(47*16)+8(r6)				/* (TEST/DEBUG) */
			lwz		r22,(47*16)+12(r6)				/* (TEST/DEBUG) */
			add		r1,r1,r6						/* (TEST/DEBUG) */
			mftb	r24								/* (TEST/DEBUG) */
			sub		r22,r24,r22						/* (TEST/DEBUG) */
			lwz		r4,4(r6)						/* (TEST/DEBUG) */
			cmplw	cr2,r22,r21						/* (TEST/DEBUG) */
			lwz		r7,4(r1)						/* (TEST/DEBUG) */
			lwz		r21,8(r6)						/* (TEST/DEBUG) */
			blt+	cr2,nottime						/* (TEST/DEBUG) */
			stw		r24,(47*16)+12(r6)				/* (TEST/DEBUG) */
			
nottime:	addi	r4,r4,1							/* (TEST/DEBUG) */
			lwz		r22,8(r1)						/* (TEST/DEBUG) */
			addi	r7,r7,1							/* (TEST/DEBUG) */
			stw		r4,4(r6)						/* (TEST/DEBUG) */
			lwz		r3,0(r6)						/* (TEST/DEBUG) */
			mr.		r21,r21							/* (TEST/DEBUG) */
			stw		r7,4(r1)						/* (TEST/DEBUG) */
			mtlr	r12								/* (TEST/DEBUG) */
			lwz		r1,0(r1)						/* (TEST/DEBUG) */
			beq-	nottimed1						/* (TEST/DEBUG) */
			blt+	cr2,isnttime1					/* (TEST/DEBUG) */
						
nottimed1:	mr.		r3,r3							/* (TEST/DEBUG) */
			bgelrl+									/* (TEST/DEBUG) */

isnttime1:	mr.		r22,r22							/* (TEST/DEBUG) */
			beq-	nottimed2						/* (TEST/DEBUG) */
			blt+	cr2,isnttime2					/* (TEST/DEBUG) */
			
nottimed2:	mr.		r3,r1							/* (TEST/DEBUG) */
			mtlr	r12								/* (TEST/DEBUG) */
			mr		r4,r7							/* (TEST/DEBUG) */
			bgelrl+									/* (TEST/DEBUG) */
			mr		r3,r11							/* (TEST/DEBUG) */
			
isnttime2:	cmplwi	r11,T_DATA_ACCESS				/* (TEST/DEBUG) */
			lis		r12,HIGH_ADDR(EXT(GratefulDeb))	/* (TEST/DEBUG) */
			bne+	nodsidisp						/* (TEST/DEBUG) */
			mr.		r22,r22							/* (TEST/DEBUG) */
			beq-	nottimed3						/* (TEST/DEBUG) */
			blt+	cr2,nodsidisp					/* (TEST/DEBUG) */

nottimed3:	li		r3,5							/* (TEST/DEBUG) */
			ori		r12,r12,LOW_ADDR(EXT(GratefulDeb))	/* (TEST/DEBUG) */
			lwz		r4,savesrr0(r13)				/* (TEST/DEBUG) */
			mtlr	r12								/* (TEST/DEBUG) */
			blrl									/* (TEST/DEBUG) */
			
			lis		r12,HIGH_ADDR(EXT(GratefulDeb))	/* (TEST/DEBUG) */
			ori		r12,r12,LOW_ADDR(EXT(GratefulDeb))	/* (TEST/DEBUG) */
			lis		r3,9							/* (TEST/DEBUG) */
			ori		r3,r3,5							/* (TEST/DEBUG) */
			mtlr	r12								/* (TEST/DEBUG) */
			lwz		r4,savedar(r13)					/* (TEST/DEBUG) */
			blrl									/* (TEST/DEBUG) */

nodsidisp:	cmplwi	r11,T_INSTRUCTION_ACCESS		/* (TEST/DEBUG) */
			lis		r12,HIGH_ADDR(EXT(GratefulDeb))	/* (TEST/DEBUG) */
			bne+	noisidisp						/* (TEST/DEBUG) */
			mr.		r22,r22							/* (TEST/DEBUG) */
			beq-	nottimed4						/* (TEST/DEBUG) */
			blt+	cr2,noisidisp					/* (TEST/DEBUG) */

nottimed4:	li		r3,6							/* (TEST/DEBUG) */
			ori		r12,r12,LOW_ADDR(EXT(GratefulDeb))	/* (TEST/DEBUG) */
			lwz		r4,savesrr0(r13)				/* (TEST/DEBUG) */
			mtlr	r12								/* (TEST/DEBUG) */
			blrl									/* (TEST/DEBUG) */

noisidisp:	mr		r3,r11							/* (TEST/DEBUG) */		
#endif

#if 0
			cmplwi	r11,T_PROGRAM					/* (TEST/DEBUG) */
			lis		r12,HIGH_ADDR(EXT(GratefulDeb))	/* (TEST/DEBUG) */
			bne+	nopgmdisp						/* (TEST/DEBUG) */
			li		r3,7							/* (TEST/DEBUG) */
			ori		r12,r12,LOW_ADDR(EXT(GratefulDeb))	/* (TEST/DEBUG) */
			lwz		r4,savesrr0(r13)				/* (TEST/DEBUG) */
			mtlr	r12								/* (TEST/DEBUG) */
			blrl									/* (TEST/DEBUG) */

nopgmdisp:	mr		r3,r11							/* (TEST/DEBUG) */		
#endif

			li		r21,0							; Assume no processor register for now
			lis		r12,hi16(EXT(hw_counts))		; Get the high part of the interrupt counters
			bf		featSMP,nopirhere				; Jump if this processor does not have a PIR...
			mfspr	r21,pir							; Get the PIR	

nopirhere:	ori		r12,r12,lo16(EXT(hw_counts))	; Get the low part of the interrupt counters
			lwz		r7,savesrr1(r13)				; Get the entering MSR
			rlwinm	r21,r21,8,20,23					; Get index to processor counts
			mtcrf	0x80,r0							/* Set our CR0 to the high nybble of the request code */
			rlwinm	r6,r0,1,0,31					/* Move sign bit to the end */
			cmplwi	cr1,r11,T_SYSTEM_CALL			/* Did we get a system call? */
			crandc	cr0_lt,cr0_lt,cr0_gt			/* See if we have R0 equal to 0b10xx...x */
			add		r12,r12,r21						; Point to the processor count area
			cmplwi	cr3,r11,T_IN_VAIN				/* Was this all in vain? All for nothing? */
			lwzx	r22,r12,r11						; Get the old value
			cmplwi	cr2,r6,1						/* See if original R0 had the CutTrace request code in it */
			addi	r22,r22,1						; Count this one
			cmplwi	cr4,r11,T_SIGP					/* Indicate if we had a SIGP 'rupt */
			stwx	r22,r12,r11						; Store it back
			
			beq-	cr3,EatRupt						/* Interrupt was all for nothing... */
			cmplwi	cr3,r11,T_MACHINE_CHECK			; Did we get a machine check?
			bne+	cr1,noCutT						/* Not a system call... */
			bnl+	cr0,noCutT						/* R0 not 0b10xxx...x, can't be any kind of magical system call... */
			rlwinm.	r7,r7,0,MSR_PR_BIT,MSR_PR_BIT	; Did we come from user state?
			lis		r1,hi16(EXT(dgWork))			; Get the diagnostics flags
			beq+	FCisok							; From supervisor state...

			ori		r1,r1,lo16(EXT(dgWork))			; Again
			lwz		r1,dgFlags(r1)					; Get the flags
			rlwinm.	r1,r1,0,enaUsrFCallb,enaUsrFCallb	; Are they valid?
			beq-	noCutT							; No...

FCisok:		beq-	cr2,isCutTrace					/* This is a CutTrace system call */
			
/*
 *			Here's where we call the firmware.  If it returns T_IN_VAIN, that means
 *			that it has handled the interruption.  Remember: thou shalt not trash R13
 *			or R20 while you are away.  Anything else is ok.
 */			

			lis		r1,hi16(EXT(FirmwareCall))		/* Top half of firmware call handler */
			ori		r1,r1,lo16(EXT(FirmwareCall))	/* Bottom half of it */
			lwz		r3,saver3(r13)					/* Restore the first parameter, the rest are ok already */
			mtlr	r1								/* Get it in the link register */
			blrl									/* Call the handler */

			cmplwi	r3,T_IN_VAIN					/* Was it handled? */
			mfsprg	r2,0							/* Restore the per_processor area */
			beq+	EatRupt							/* Interrupt was handled... */
			mr		r11,r3							/* Put the 'rupt code in the right register */
			b		noSIGP							/* Go to the normal system call handler */
			
isCutTrace:				
			li		r7,-32768						/* Get a 0x8000 for the exception code */
			bne-	cr5,EatRupt						/* Tracing is disabled... */
			sth		r7,LTR_excpt(r20)				/* Modify the exception type to a CutTrace */
			b		EatRupt							/* Time to go home... */

/*			We are here 'cause we didn't have a CutTrace system call */

noCutT:		beq-	cr3,MachineCheck				; Whoa... Machine check...
			bne+	cr4,noSIGP						/* Skip away if we didn't get a SIGP... */
		
			lis		r6,HIGH_ADDR(EXT(MPsignalFW))	/* Top half of SIGP handler */
			ori		r6,r6,LOW_ADDR(EXT(MPsignalFW))	/* Bottom half of it */
			mtlr	r6								/* Get it in the link register */
			
			blrl									/* Call the handler - we'll only come back if this is an AST,  */
													/* 'cause FW can't handle that */
			mfsprg	r2,0							/* Restore the per_processor area */
;
;			The following interrupts are the only ones that can be redriven
;			by the higher level code or emulation routines.
;

Redrive:	cmplwi	cr0,r3,T_IN_VAIN				/* Did the signal handler eat the signal? */
			mr		r11,r3							/* Move it to the right place */
			beq+	cr0,EatRupt						/* Bail now if the signal handler processed the signal... */


/*
 *			Here's where we check for the other fast-path exceptions: translation exceptions,
 *			emulated instructions, etc.
 */

noSIGP:		cmplwi	cr3,r11,T_ALTIVEC_ASSIST		; Check for an Altivec denorm assist
			cmplwi	cr1,r11,T_PROGRAM				/* See if we got a program exception */
			cmplwi	cr2,r11,T_INSTRUCTION_ACCESS	/* Check on an ISI */
			bne+	cr3,noAltivecAssist				; It is not an assist...
			b		EXT(AltivecAssist)				; It is an assist...

noAltivecAssist:
			bne+	cr1,noEmulate					; No emulation here...
			b		EXT(Emulate)					; Go try to emulate...

noEmulate:	cmplwi	cr3,r11,T_CSWITCH				/* Are we context switching */
			cmplwi	r11,T_DATA_ACCESS				/* Check on a DSI */
			beq-	cr2,DSIorISI					/* It's a PTE fault... */
			beq-	cr3,conswtch					/* It's a context switch... */
			bne+	PassUp							/* It's not a PTE fault... */

/*
 *			This call will either handle the fault, in which case it will not
 *			return, or return to pass the fault up the line.
 */

DSIorISI:
			lis		r7,HIGH_ADDR(EXT(handlePF))		/* Top half of DSI handler */
			ori		r7,r7,LOW_ADDR(EXT(handlePF))	/* Bottom half of it */
			mtlr	r7								/* Get it in the link register */
			mr		r3,r11							/* Move the 'rupt code */
			
			blrl									/* See if we can handle this fault  */

			lwz		r0,savesrr1(r13)				; Get the MSR in use at exception time
			mfsprg	r2, 0							/* Get back per_proc */
			cmplwi	cr1,r3,T_IN_VAIN				; Was it handled?
			andi.	r4,r0,lo16(MASK(MSR_RI))		; See if the recover bit is on
			mr		r11,r3							/* Make sure we can find this later */
			beq+	cr1,EatRupt						; Yeah, just blast back to the user... 
			andc	r0,r0,r4						; Remove the recover bit
			beq+	PassUp							; Not on, normal case...
			lwz		r4,savesrr0(r13)				; Get the failing instruction address
			lwz		r5,savecr(r13)					; Get the condition register
			stw		r0,savesrr1(r13)				; Save the result MSR
			addi	r4,r4,4							; Skip failing instruction
			rlwinm	r5,r5,0,3,1						; Clear CR0_EQ to let emulation code know we failed
			stw		r4,savesrr0(r13)				; Save instruction address
			stw		r4,savecr(r13)					; And the resume CR
			b		EatRupt							; Resume emulated code

/*
 *			Here is where we handle the context switch firmware call.  The old 
 *			context has been saved, and the new savearea in in saver3.  We'll just
 *			muck around with the savearea pointers, and then join the exit routine 
 */
conswtch:	lwz		r28,SAVflags(r13)				/* The the flags of the current */
			mr		r29,r13							/* Save the save */
			rlwinm	r30,r13,0,0,19					/* Get the start of the savearea block */
			lwz		r5,saver3(r13)					/* Switch to the new savearea */
			oris	r28,r28,HIGH_ADDR(SAVattach)	/* Turn on the attached flag */
			lwz		r30,SACvrswap(r30)				/* get real to virtual translation */
			mr		r13,r5							/* Switch saveareas */
			xor		r27,r29,r30						/* Flip to virtual */
			stw		r28,SAVflags(r29)				/* Stash it back */
			stw		r27,saver3(r5)					/* Push the new savearea to the switch to routine */
			b		EatRupt							/* Start 'er up... */

;
;			Handle machine check here.
;
; ?
;
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

			li		r11,T_IN_VAIN					; ?
			b		EatRupt							; ?

			
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
		
			lwz		r30,saver5(r13)					; Get proper DBAT values
			lwz		r28,saver6(r13)
			lwz		r27,saver7(r13)
			lwz		r11,saver8(r13)
			lwz		r18,saver9(r13)
			
			sync
			mtdbatu	0,r30							; Restore DBAT 0 high
			mtdbatl	0,r28							; Restore DBAT 0 low
			mtdbatu	1,r27							; Restore DBAT 1 high
			mtdbatu	2,r11							; Restore DBAT 2 high
			mtdbatu	3,r18							; Restore DBAT 3 high 
			sync

			lwz		r28,savelr(r13)					; Get return point
			lwz		r27,saver0(r13)					; Get the saved MSR
			li		r30,0							; Get a failure RC
			stw		r28,savesrr0(r13)				; Set the return point
			stw		r27,savesrr1(r13)				; Set the continued MSR
			stw		r30,saver3(r13)					; Set return code
			li		r11,T_IN_VAIN					; Set new interrupt code
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

			cmplwi	r11,T_IN_VAIN					/* Was it emulated? */
			lis		r1,hi16(SAVredrive)				; Get redrive request
			mfsprg	r2,0							; Restore the per_proc area
			beq+	EatRupt							/* Yeah, just blast back to the user... */
			lwz		r4,SAVflags(r13)				; Pick up the flags

			and.	r0,r4,r1						; Check if redrive requested
			andc	r4,r4,r1						; Clear redrive

			beq+	PassUp							; No redrive, just keep on going...

			lwz		r3,saveexception(r13)			; Restore exception code
			stw		r4,SAVflags(r13)				; Set the flags
			b		Redrive							; Redrive the exception...
		
/* 			Jump into main handler code switching on VM at the same time */

/* 			We assume kernel data is mapped contiguously in physical
 * 			memory, otherwise we'd need to switch on (at least) virtual data.
 *			SRs are already set up.
 */
PassUp:		lis		r2,hi16(EXT(exception_handlers))	; Get exception vector address
			ori		r2,r2,lo16(EXT(exception_handlers))	; And low half
			lwzx	r6,r2,r11						/* Get the actual exception handler address */

PassUpDeb:	lwz		r8,SAVflags(r13)				/* Get the flags */
			mtsrr0	r6								/* Set up the handler address */
			oris	r8,r8,HIGH_ADDR(SAVattach)		/* Since we're passing it up, attach it */
			rlwinm	r5,r13,0,0,19					/* Back off to the start of savearea block */
			
			mfmsr	r3								/* Get our MSR */
			stw		r8,SAVflags(r13)				/* Pass up the flags */
			rlwinm	r3,r3,0,MSR_BE_BIT+1,MSR_SE_BIT-1	/* Clear all but the trace bits */
			li		r2,MSR_SUPERVISOR_INT_OFF		/* Get our normal MSR value */
			lwz		r5,SACvrswap(r5)				/* Get real to virtual conversion */			
			or		r2,r2,r3						/* Keep the trace bits if they're on */
			mr		r3,r11							/* Pass the exception code in the paramter reg */
			mtsrr1	r2								/* Set up our normal MSR value */
			xor		r4,r13,r5						/* Pass up the virtual address of context savearea */

			rfi										/* Launch the exception handler */

			.long	0								/* Leave these here gol durn it! */
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
 *			if any need to be.
 */
 
 			.align	5
 
EatRupt:	mr		r31,r13							/* Move the savearea pointer to the far end of the register set */

EatRupt2:	mfsprg	r2,0							/* Get the per_proc block */
			dcbt	0,r31							; Get this because we need it very soon

#if TRCSAVE
			lwz		r30,saver0(r31)					; (TEST/DEBUG) Get users R0
			lwz		r20,saveexception(r31)			; (TEST/DEBUG) Returning from trace?
			xor		r30,r20,r30						; (TEST/DEBUG) Make code
			rlwinm	r30,r30,1,0,31					; (TEST/DEBUG) Make an easy test
			cmplwi	cr5,r30,0x61					; (TEST/DEBUG) See if this is a trace
#endif

/*
 *			First we see if we are able to free the new savearea.
 *			If it is not attached to anything, put it on the free list.
 *			This is real dangerous, we haven't restored context yet...
 *			So, the free savearea chain lock must stay until the bitter end!
 */			

/*
 *			It's dangerous here.  We haven't restored anything from the current savearea yet.
 *			And, we mark it the active one.  So, if we get an exception in here, it is
 *			unrecoverable.  Unless we mess up, we can't get any kind of exception.  So,
 *			it is important to assay this code as only the purest of gold.
 *
 *			But first, see if there is a savearea hanging off of quickfret.  If so, 
 *			we release that one first and then come back for the other.  We should rarely
 *			see one, they appear when FPU or VMX context is discarded by either returning
 *			to a higher exception level, or explicitly.
 *
 *			A word about QUICKFRET: Multiple saveareas may be queued for release.  It is
 *			the responsibility of the queuer to insure that the savearea is not multiply
 *			queued and that the appropriate inuse bits are reset.
 */

 

			mfsprg	r27,2							; Get the processor features
			lwz		r1,savesrr1(r31)				; Get destination MSR
			mtcrf	0x60,r27						; Set CRs with thermal facilities
			mr		r18,r31							; Save the savearea pointer
			rlwinm.	r0,r1,0,MSR_EE_BIT,MSR_EE_BIT	; Are interruptions going to be enabled?
			lwz		r19,PP_QUICKFRET(r2)			; Get the quick release savearea
			crandc	31,pfThermalb,pfThermIntb		; See if we have both thermometer and not interrupt facility
			li		r0,0							; Get a zero
			crandc	31,31,cr0_eq					; Factor in enablement
			la		r21,savesr0(r18)				; Point to the first thing we restore
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
			
			li		r3,T_THERMAL					; Time to emulate a thermal interruption
			or		r14,r14,r15						; Get contents of interrupting register
			mr		r13,r31							; Make sure savearea is pointed to correctly
			stw		r3,saveexception(r31)			; Restore exception code
			stw		r14,savedar(r31)				; Set the contents of the interrupting register into the dar
			b		Redrive							; Go process this new interruption...


tempisok:	lis		r30,HIGH_ADDR(EXT(saveanchor))	/* Get the high part of the anchor */
			stw		r0,PP_QUICKFRET(r2)				/* Clear quickfret pointer */
			ori		r30,r30,LOW_ADDR(EXT(saveanchor))	/* Bottom half of the anchor */
			dcbt	0,r21							/* Touch in the first thing */

#if TRCSAVE
			beq-	cr5,trkill0						; (TEST/DEBUG) Do not trace this type
			lwz		r14,LOW_ADDR(traceMask-EXT(ExceptionVectorsStart))(br0)	; (TEST/DEBUG) Get the trace mask
			mr.		r14,r14							; (TEST/DEBUG) Is it stopped?
			beq-	trkill0							; (TEST/DEBUG) yes...
			bl		cte								; (TEST/DEBUG) Trace this
			stw		r18,LTR_r1(r20)					; (TEST/DEBUG) Normal savearea
			stw		r19,LTR_r2(r20)					; (TEST/DEBUG) Quickfret savearea
trkill0:
#endif

rtlck:		lwarx	r22,0,r30						/* Grab the lock value */
			li		r23,1							/* Use part of the delay time */
			mr.		r22,r22							/* Is it locked? */
			bne-	rtlcks							/* Yeah, wait for it to clear... */
			stwcx.	r23,0,r30						/* Try to seize that there durn lock */
			beq+	fretagain						; Got it...
			b		rtlck							/* Collision, try again... */
			
rtlcks:		lwz		r22,SVlock(r30)					/* Get that lock in here */
			mr.		r22,r22							/* Is it free yet? */
			beq+	rtlck							/* Yeah, try for it again... */
			b		rtlcks							/* Sniff away... */

;
;			Lock gotten, toss the saveareas
;
fretagain:	
#if TRCSAVE
			beq-	cr5,trkill1						; (TEST/DEBUG) Do not trace this type
			lwz		r14,LOW_ADDR(traceMask-EXT(ExceptionVectorsStart))(br0)	; (TEST/DEBUG) Get the trace mask
			mr.		r14,r14							; (TEST/DEBUG) Is it stopped?
			beq-	trkill1							; (TEST/DEBUG) yes...
			li		r0,1							; (TEST/DEBUG) ID number
			bl		cte								; (TEST/DEBUG) Trace this
			stw		r18,LTR_r1(r20)					; (TEST/DEBUG) Normal savearea
			stw		r19,LTR_r2(r20)					; (TEST/DEBUG) Quickfret savearea
trkill1:
#endif
			
			mr.		r18,r18							; Are we actually done here?
			beq-	donefret						; Yeah...
			mr.		r31,r19							; Is there a quickfret to do?
			beq+	noqfrt							; Nope...
			lwz		r19,SAVqfret(r19)				; Yes, get the next in line
#if TRCSAVE
			beq-	cr5,trkill2						; (TEST/DEBUG) Do not trace this type
			lwz		r14,LOW_ADDR(traceMask-EXT(ExceptionVectorsStart))(br0)	; (TEST/DEBUG) Get the trace mask
			mr.		r14,r14							; (TEST/DEBUG) Is it stopped?
			beq-	trkill2							; (TEST/DEBUG) yes...
			li		r0,2							; (TEST/DEBUG) ID number
			bl		cte								; (TEST/DEBUG) Trace this
			stw		r18,LTR_r1(r20)					; (TEST/DEBUG) Normal savearea
			stw		r19,LTR_r2(r20)					; (TEST/DEBUG) next quickfret savearea
			stw		r31,LTR_r3(r20)					; (TEST/DEBUG) Current one to toss
trkill2:
#endif
			b		doqfrt							; Go do it...

noqfrt:		mr		r31,r18							; Set the area to release
			li		r18,0							; Show we have done it
#if TRCSAVE
			beq-	cr5,trkill3						; (TEST/DEBUG) Do not trace this type
			lwz		r14,LOW_ADDR(traceMask-EXT(ExceptionVectorsStart))(br0)	; (TEST/DEBUG) Get the trace mask
			mr.		r14,r14							; (TEST/DEBUG) Is it stopped?
			beq-	trkill3							; (TEST/DEBUG) yes...
			li		r0,3							; (TEST/DEBUG) ID number
			bl		cte								; (TEST/DEBUG) Trace this
			stw		r18,LTR_r1(r20)					; (TEST/DEBUG) Normal savearea
			stw		r19,LTR_r2(r20)					; (TEST/DEBUG) next quickfret savearea
			stw		r31,LTR_r3(r20)					; (TEST/DEBUG) Current one to toss
trkill3:
#endif

doqfrt:		li		r0,0							; Get a constant 0
			lis		r26,0x8000						/* Build a bit mask and assume first savearea */
			stw		r0,SAVqfret(r31)				; Make sure back chain is unlinked
			lwz		r28,SAVflags(r31)				; Get the flags for the old active one
#if TRCSAVE
			beq-	cr5,trkill4						; (TEST/DEBUG) Do not trace this type
			lwz		r14,LOW_ADDR(traceMask-EXT(ExceptionVectorsStart))(br0)	; (TEST/DEBUG) Get the trace mask
			mr.		r14,r14							; (TEST/DEBUG) Is it stopped?
			beq-	trkill4							; (TEST/DEBUG) yes...
			li		r0,4							; (TEST/DEBUG) ID number
			bl		cte								; (TEST/DEBUG) Trace this
			stw		r18,LTR_r1(r20)					; (TEST/DEBUG) Normal savearea
			stw		r19,LTR_r2(r20)					; (TEST/DEBUG) next quickfret savearea
			stw		r31,LTR_r3(r20)					; (TEST/DEBUG) Current one to toss
			stw		r28,LTR_r4(r20)					; (TEST/DEBUG) Save current flags
trkill4:
#endif			
			rlwinm	r25,r31,21,31,31				/* Get position of savearea in block */
			andis.	r28,r28,HIGH_ADDR(SAVinuse)		/* See if we need to free it */
			srw		r26,r26,r25						/* Get bit position to deallocate */
			rlwinm	r29,r31,0,0,19					/* Round savearea pointer to even page address */
					
			bne-	fretagain						/* Still in use, we can't free this one... */

			lwz		r23,SACalloc(r29)				/* Get the allocation for this block */
			lwz		r24,SVinuse(r30)				/* Get the in use count */
			mr		r28,r23							; (TEST/DEBUG) save for trace
			or		r23,r23,r26						/* Turn on our bit */
			subi	r24,r24,1						/* Show that this one is free */
			cmplw	r23,r26							/* Is our's the only one free? */
			stw		r23,SACalloc(r29)				/* Save it out */
			bne+	rstrest							/* Nope, then the block is already on the free list */

			lwz		r22,SVfree(r30)					/* Get the old head of the free list */
			stw		r29,SVfree(r30)					/* Point the head at us now */
			stw		r22,SACnext(r29)				; Point us to the old last
	
rstrest:	stw		r24,SVinuse(r30)				/* Set the in use count */
#if TRCSAVE
			beq-	cr5,trkill5						; (TEST/DEBUG) Do not trace this type
			lwz		r14,LOW_ADDR(traceMask-EXT(ExceptionVectorsStart))(br0)	; (TEST/DEBUG) Get the trace mask
			mr.		r14,r14							; (TEST/DEBUG) Is it stopped?
			beq-	trkill5							; (TEST/DEBUG) yes...
			li		r0,5							; (TEST/DEBUG) ID number
			bl		cte								; (TEST/DEBUG) Trace this
			stw		r18,LTR_r1(r20)					; (TEST/DEBUG) Normal savearea
			stw		r19,LTR_r2(r20)					; (TEST/DEBUG) Next quickfret savearea
			stw		r31,LTR_r3(r20)					; (TEST/DEBUG) Current one to toss
			stw		r28,LTR_srr1(r20)				; (TEST/DEBUG) Save the original allocation
			stw		r23,LTR_dar(r20)				; (TEST/DEBUG) Save the new allocation
			stw		r24,LTR_save(r20)				; (TEST/DEBUG) Save the new in use count
			stw		r22,LTR_lr(r20)					; (TEST/DEBUG) Save the old top of free list
			stw		r29,LTR_ctr(r20)				; (TEST/DEBUG) Save the new top of free list
trkill5:
#endif			
			b		fretagain						; Go finish up the rest...

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

			.align	5
			
donefret:	lwz		r26,savesrr1(r31)				; Get destination state flags
			lwz		r7,PP_USERPMAP(r2)				; Pick up the user pmap we may launch
			cmplw	cr3,r14,r14						; Set that we do not need to stop streams
			rlwinm.	r17,r26,0,MSR_PR_BIT,MSR_PR_BIT	; See if we are going to user or system
			li		r14,PMAP_SEGS					; Point to segments 
			bne+	gotouser						; We are going into user state...

			lwz		r14,savesr14(r31)				; Get the copyin/out register at interrupt time
			mtsr	sr14,r14						; Set SR14
			b		segsdone						; We are all set up now...
		
			.align	5

gotouser:	dcbt	r14,r7							; Touch the segment register contents
			lwz		r16,PP_LASTPMAP(r7)				; Pick up the last loaded pmap
			addi	r14,r14,32						; Second half of pmap segments
			lwz		r13,PMAP_VFLAGS(r7)				; Get the flags
			lwz		r15,PMAP_SPACE(r7)				; Get the primary space
			dcbt	r14,r7							; Touch second page
			mtcrf	0x0F,r13						; Set CRs to correspond to the subordinate spaces
			oris	r15,r15,hi16(SEG_REG_PROT)		; Set segment 0 SR value
			lhz		r9,PP_CPU_FLAGS(r2)				; Get the processor flags

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

			beq+	segsdone						; All done if same pmap as last time...
			
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
			
segsdone:	li		r1,emfp0						; Point to the fp savearea
			lwz		r25,savesrr0(r31)				; Get the SRR0 to use
			la		r28,saver6(r31)					/* Point to the next line to use */
			dcbt	r1,r2							; Start moving in a work area
			lwz		r0,saver0(r31)					/* Restore */			
			dcbt	0,r28							/* Touch it in */
			mr		r29,r2							; Save the per_proc
			lwz		r1,saver1(r31)					/* Restore */	
			lwz		r2,saver2(r31)					/* Restore */	
			la		r28,saver14(r31)				/* Point to the next line to get */
			lwz		r3,saver3(r31)					/* Restore */
			mtcrf	0x80,r27						; Get facility availability flags (do not touch CR1-7)
			lwz		r4,saver4(r31)					/* Restore */
			mtsrr0	r25								/* Restore the SRR0 now */
			lwz		r5,saver5(r31)					/* Restore */
			mtsrr1	r26								/* Restore the SRR1 now */
			lwz		r6,saver6(r31)					/* Restore */			
			
			dcbt	0,r28							/* Touch that next line on in */
			la		r28,savexfpscrpad(r31)			; Point to the saved fpscr
			
			lwz		r7,saver7(r31)					/* Restore */	
			dcbt	0,r28							; Touch saved fpscr		
			lwz		r8,saver8(r31)					/* Restore */	
			lwz		r9,saver9(r31)					/* Restore */			
			lwz		r10,saver10(r31)				/* Restore */
			lwz		r11,saver11(r31)				/* Restore */			
			lwz		r12,saver12(r31)				/* Restore */
			lwz		r13,saver13(r31)				/* Restore */			
			la		r28,saver22(r31)				/* Point to the next line to do */
			lwz		r14,saver14(r31)				/* Restore */	
			lwz		r15,saver15(r31)				/* Restore */			

;
;			Note that floating point will be enabled from here on until the RFI
;

			bf-		pfFloatb,nofphere				; Skip if no floating point...
			mfmsr	r27								; Save the MSR
			ori		r27,r27,lo16(MASK(MSR_FP))		; Enable floating point			
			mtmsr	r27								; Really enable	
			isync		
			stfd	f0,emfp0(r29)					; Save FP0
			lfd		f0,savexfpscrpad(r31)			; Get the fpscr
			mtfsf	0xFF,f0							; Restore fpscr		
			lfd		f0,emfp0(r29)					; Restore the used register

nofphere:	dcbt	0,r28							/* Touch in another line of context */
			
			lwz		r16,saver16(r31)				/* Restore */
			lwz		r17,saver17(r31)				/* Restore */
			lwz		r18,saver18(r31)				/* Restore */	
			lwz		r19,saver19(r31)				/* Restore */	
			lwz		r20,saver20(r31)				/* Restore */
			lwz		r21,saver21(r31)				/* Restore */
			la		r28,saver30(r31)				/* Point to the final line */
			lwz		r22,saver22(r31)				/* Restore */

			dcbt	0,r28							/* Suck it in */

			lwz		r23,saver23(r31)				/* Restore */
			lwz		r24,saver24(r31)				/* Restore */			
			lwz		r25,saver25(r31)				/* Restore */			
			lwz		r26,saver26(r31)				/* Restore */			
			lwz		r27,saver27(r31)				/* Restore */			

			lwz		r28,savecr(r31)					/* Get CR to restore */
			bf		pfAltivecb,noavec4				; No vector on this machine
			lwz		r29,savevrsave(r31)				; Get the vrsave
			beq+	cr3,noavec3						; SRs have not changed, no need to stop the streams...
			dssall									; Kill all data streams
													; The streams should be suspended
													; already, and we do a bunch of 
													; dependent loads and a sync later
													; so we should be cool.
		
noavec3:	mtspr	vrsave,r29						; Set the vrsave

noavec4:	lwz		r29,savexer(r31)				/* Get XER to restore */
			mtcr	r28								/* Restore the CR */
			lwz		r28,savelr(r31)					/* Get LR to restore */
			mtxer	r29								/* Restore the XER */
			lwz		r29,savectr(r31)				/* Get the CTR to restore */
			mtlr	r28								/* Restore the LR */
			lwz		r28,saver30(r31)				/* Restore */
			mtctr	r29								/* Restore the CTR */
			lwz		r29,saver31(r31)				/* Restore */
			mtsprg	2,r28							/* Save R30 */
			lwz		r28,saver28(r31)				/* Restore */			
			mtsprg	3,r29							/* Save R31 */
			lwz		r29,saver29(r31)				/* Restore */

#if PERFTIMES && DEBUG
			stmw	r1,0x280(br0)					; Save all registers
			mfcr	r20								; Save the CR
			mflr	r21								; Save the LR
			mfsrr0	r9								; Save SRR0
			mfsrr1	r11								; Save SRR1
			mr		r8,r0							; Save R0
			li		r3,69							; Indicate interrupt
			mr		r4,r11							; Set MSR to log
			mr		r5,r31							; Get savearea to log
			bl		EXT(dbgLog2)					; Cut log entry
			mr		r0,r8							; Restore R0
			mtsrr0	r9								; Restore SRR0
			mtsrr1	r11								; Restore SRR1
			mtlr	r21								; Restore the LR
			mtcr	r20								; Restore the CR
			lmw		r1,0x280(br0)					; Restore all the rest
#endif

			li		r31,0							/* Get set to clear lock */
			sync									/* Make sure it's all out there */
			stw		r31,SVlock(r30)					/* Unlock it */
			mfsprg	r30,2							/* Restore R30 */
			mfsprg	r31,0							; Get per_proc
			lwz		r31,pfAvailable(r31)			; Get the feature flags
			mtsprg	2,r31							; Set the feature flags
			mfsprg	r31,3							/* Restore R31 */

			rfi										/* Click heels three times and think very hard that there's no place like home */

			.long	0								/* For old 601 bug */
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
			mfmsr	r30								/* Get the current MSR */
			mtcrf	0x04,r29						; Set the features			
			mr		r31,r3							/* Get the savearea in the right register */
			andi.	r30,r30,0x7FCF					/* Turn off externals, IR, and DR */
			lis		r1,hi16(SAVredrive)				; Get redrive request

			bt		pfNoMSRirb,eeNoMSR				; No MSR...

			mtmsr	r30								; Translation and all off
			isync									; Toss prefetch
			b		eeNoMSRx
			
eeNoMSR:	li		r0,loadMSR						; Get the MSR setter SC
			mr		r3,r30							; Get new MSR
			sc										; Set it

eeNoMSRx:
			mfsprg	r2,0							; Get the per_proc block
			lwz		r4,SAVflags(r31)				; Pick up the flags
			mr		r13,r31							; Put savearea here also

			and.	r0,r4,r1						; Check if redrive requested
			andc	r4,r4,r1						; Clear redrive
			
			dcbt	br0,r2							; We will need this in just a sec

			beq+	EatRupt							; No redrive, just exit...

			lwz		r3,saveexception(r13)			; Restore exception code
			stw		r4,SAVflags(r13)				; Set the flags
			b		Redrive							; Redrive the exception...
		
;
;			Make trace entry for lowmem_vectors internal debug
;
#if TRCSAVE
cte:
			lwz		r20,LOW_ADDR(EXT(traceCurr)-EXT(ExceptionVectorsStart))(br0)	; Pick up the current trace entry
			lwz		r16,LOW_ADDR(EXT(traceEnd)-EXT(ExceptionVectorsStart))(br0)	; Grab up the end of it all
			addi	r17,r20,LTR_size				; Point to the next trace entry
			cmplw	r17,r16							; Do we need to wrap the trace table?
			li		r15,32							; Second line of entry
			bne+	ctenwrap						; We got a trace entry...			
			lwz		r17,LOW_ADDR(EXT(traceStart)-EXT(ExceptionVectorsStart))(br0)	; Wrap back to the top
	
ctenwrap:	stw		r17,LOW_ADDR(EXT(traceCurr)-EXT(ExceptionVectorsStart))(br0)	; Set the next entry for the next guy		
			
			bf-		featL1ena,skipz8				; L1 cache is disabled...
			dcbz	0,r20							; Allocate cache for the entry
			dcbz	r15,r20							; Zap the second half
skipz8:

ctegetTB:	mftbu	r16								; Get the upper timebase
			mftb	r17								; Get the lower timebase
			mftbu	r15								; Get the upper one again
			cmplw	r16,r15							; Did the top tick?
			bne-	ctegetTB						; Yeah, need to get it again...
			
			li		r15,0x111						; Get the special trace ID code
			stw		r0,LTR_r0(r20)					; Save R0 (usually used as an ID number
			stw		r16,LTR_timeHi(r20)				; Set the upper part of TB
			mflr	r16								; Get the return point
			stw		r17,LTR_timeLo(r20)				; Set the lower part of TB
			sth		r15,LTR_excpt(r20)				; Save the exception type
			stw		r16,LTR_srr0(r20)				; Save the return point
			blr										; Leave...
#endif

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



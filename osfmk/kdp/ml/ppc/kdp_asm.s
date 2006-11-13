/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
#include <mach_kdb.h>
#include <mach_kgdb.h>
#include <mach_debug.h>
#include <assym.s>
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <mach/ppc/vm_param.h>

/* void kdp_call_with_ctx(int type, struct ppc_thread_state *ssp)
 *
 * Switch on kdp stack and  enter the debugger. On return,
 * switch back to the previous stack
 *
 * If the kdp stack is not free, we allocate ourselves a frame below
 * the current kdp frame. This should never occur in a perfect world.
 */

ENTRY(kdp_call_with_ctx, TAG_NO_FRAME_USED)
	
	lis		r2,hi16(MASK(MSR_VEC))	; Get the vector enable
	mfmsr	r7					; Get the MSR
	ori		r2,r2,lo16(MASK(MSR_EE)|MASK(MSR_FP))	; Get FP and EE
	mflr	r0
	andc	r7,r7,r2			; Clear FP, VEC, and EE
	mtmsr	r7
	isync										; Need this because we may have ditched fp/vec
	mfsprg	r8,0				/* Get the per_proc block address */
	stw	r0,	FM_LR_SAVE(r1)		/* save lr in the current frame */
	
	lwz	r9,	PP_DEBSTACKPTR(r8)	/* get kdp stack pointer */
	cmpwi	r9,	0
	bne	0f

#ifdef	LET_KDP_REENTER
	mr	r9,	r1 			/* get current stack pointer */
	subi	r9,	r9,	FM_REDZONE + FM_SIZE
#else
	bl	EXT(kdp_print_backtrace)
#endif

0:
	stw	r1,	FM_ARG0(r9)			/* Store old stack pointer */
	li	r0,	0
	stw	r0,	PP_DEBSTACKPTR(r8)	/* Mark kdp stack as busy */
	
	subi	r1,	r9,	FM_SIZE
	stw	r0,	FM_BACKPTR(r1)
	
	bl	EXT(kdp_trap)

	lis		r2,hi16(MASK(MSR_VEC))		; Get the vector enable
	mfmsr	r0					/* Get the MSR */
	ori		r2,r2,lo16(MASK(MSR_EE)|MASK(MSR_FP))	; Get FP and EE
	addi	r1,	r1,	FM_SIZE
	andc	r0,r0,r2			; Clear FP, VEC, and EE
	mtmsr	r0
	isync						; Need this because we may have ditched fp/vec

	mfsprg	r8,0				/* Get the per_proc block address */
	
	stw	r1,	PP_DEBSTACKPTR(r8)	/* Mark gdb stack as free */
	lwz	r1,	FM_ARG0(r1)
	lwz	r0,	FM_LR_SAVE(r1)
	mtlr	r0

	blr



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
	
	mfmsr	r7					/* Get the MSR */
	mflr	r0
	rlwinm	r7,r7,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Turn off interruptions enable bit */
	mtmsr	r7
	mfsprg	r8,0				/* Get the per_proc block address */
	stw	r0,	FM_LR_SAVE(r1)		/* save lr in the current frame */
	
	lwz	r9,	PP_DEBSTACKPTR(r8)	/* get kdp stack pointer */
	cmpwi	r9,	0
	bne	0f

#ifdef	LET_KDP_REENTER
	mr	r9,	r1 			/* get current stack pointer */
	subi	r9,	r9,	FM_REDZONE + SS_SIZE
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

	mfmsr	r0					/* Get the MSR */
	addi	r1,	r1,	FM_SIZE
	rlwinm	r0,r0,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Turn off interruptions enable bit */
	mtmsr	r0

	mfsprg	r8,0				/* Get the per_proc block address */
	
	stw	r1,	PP_DEBSTACKPTR(r8)	/* Mark gdb stack as free */
	lwz	r1,	FM_ARG0(r1)
	lwz	r0,	FM_LR_SAVE(r1)
	mtlr	r0

	blr



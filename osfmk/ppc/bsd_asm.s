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
#include <debug.h>           
#include <mach_assert.h>
#include <mach/exception_types.h>
#include <mach/ppc/vm_param.h> 
        
#include <assym.s>
 
#include <ppc/asm.h> 
#include <ppc/proc_reg.h>
#include <ppc/trap.h>
#include <ppc/exception.h>
 
/*
 * void cthread_set_self(cproc_t p)
 *
 * set's thread state "user_value"
 *
 * This op is invoked as follows:
 *	li r0, CthreadSetSelfNumber	// load the fast-trap number
 *	sc				// invoke fast-trap
 *	blr
 *
 * Entry:	VM switched ON
 *		Interrupts  OFF
 *              original r1-3 saved in sprg1-3
 *              original srr0 and srr1 saved in per_proc_info structure
 *              original cr            saved in per_proc_info structure
 *              exception type         saved in per_proc_info structure
 *              r1 = scratch
 *              r2 = virt addr of per_proc_info
 *		r3 = exception type (one of EXC_...)
 *
 */
 	.text
	.align	5
ENTRY(CthreadSetSelfNumber, TAG_NO_FRAME_USED)
	lwz	r1,	PP_CPU_DATA(r2)
	lwz	r1,	CPU_ACTIVE_THREAD(r1)
	lwz	r1,	THREAD_TOP_ACT(r1)  
	lwz	r1,	ACT_MACT_PCB(r1)

	mfsprg	r3,	3
	stw	r3,	CTHREAD_SELF(r1)

	/* Prepare to rfi to the exception exit routine, which is
	 * in physical address space */
	addis	r3,	0,	HIGH_CADDR(EXT(exception_exit))
	addi	r3,	r3,	LOW_ADDR(EXT(exception_exit))

	lwz	r3,	0(r3)
	mtsrr0	r3
	li	r3,	MSR_VM_OFF
	mtsrr1	r3

	lwz	r3,	PP_SAVE_SRR1(r2)	/* load the last register... */
	lwz	r2,	PP_SAVE_SRR0(r2)	/* For trampoline */
	lwz	r1,	PCB_SR0(r1)		/* For trampoline... */

	rfi


/*
 * ur_cthread_t ur_cthread_self(void)
 *
 * return thread state "user_value"
 *
 * This op is invoked as follows:
 *	li r0, UrCthreadSelfNumber	// load the fast-trap number
 *	sc				// invoke fast-trap
 *	blr
 *
 * Entry:	VM switched ON
 *		Interrupts  OFF
 *              original r1-3 saved in sprg1-3
 *              original srr0 and srr1 saved in per_proc_info structure
 *              original cr            saved in per_proc_info structure
 *              exception type         saved in per_proc_info structure
 *              r1 = scratch
 *              r2 = virt addr of per_proc_info
 *		r3 = exception type (one of EXC_...)
 *
 */
 	.text
	.align	5
ENTRY(UrCthreadSelfNumber, TAG_NO_FRAME_USED)
	lwz	r1,	PP_CPU_DATA(r2)
	lwz	r1,	CPU_ACTIVE_THREAD(r1)
	lwz	r1,	THREAD_TOP_ACT(r1)  
	lwz	r1,	ACT_MACT_PCB(r1)

	lwz	r3,	CTHREAD_SELF(r1)
	mtsprg	3,	r3


	/* Prepare to rfi to the exception exit routine, which is
	 * in physical address space */
	addis	r3,	0,	HIGH_CADDR(EXT(exception_exit))
	addi	r3,	r3,	LOW_ADDR(EXT(exception_exit))
	lwz	r3,	0(r3)
	mtsrr0	r3
	li	r3,	MSR_VM_OFF
	mtsrr1	r3

	lwz	r3,	PP_SAVE_SRR1(r2)	/* load the last register... */
	lwz	r2,	PP_SAVE_SRR0(r2)	/* For trampoline */
	lwz	r1,	PCB_SR0(r1)		/* For trampoline... */

	rfi

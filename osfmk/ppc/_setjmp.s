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
/*
 * @OSF_COPYRIGHT@
 */

/*
 * C library -- _setjmp, _longjmp
 *
 *	_longjmp(a,v)
 * will generate a "return(v)" from
 * the last call to
 *	_setjmp(a)
 * by restoring registers from the stack,
 * The previous signal state is NOT restored.
 *
 * NOTE :    MUST BE KEPT CONSISTENT WITH gdb/config/powerpc/tm-ppc-eabi.h
 *           (which needs to know where to find the destination address)
 */

#include <ppc/asm.h>

/*
 * setjmp : ARG0 (r3) contains the address of
 *	    the structure where we are to
 *	    store the context
 *          Uses r0 as scratch register
 *
 * NOTE :    MUST BE KEPT CONSISTENT WITH gdb/config/powerpc/tm-ppc-eabi.h
 *           (which needs to know where to find the destination address)
 */	

ENTRY(_setjmp,TAG_NO_FRAME_USED)
				 /* first entry is used for r1 - stack ptr */
	stw	r13,	4(ARG0)  /* GPR context. We avoid multiple-word */
	stw	r14,	8(ARG0)  /* instructions as they're slower (?) */
	stw	r15,   12(ARG0)	
	stw	r16,   16(ARG0)	
	stw	r17,   20(ARG0)	
	stw	r18,   24(ARG0)	
	stw	r19,   28(ARG0)	
	stw	r20,   32(ARG0)	
	stw	r21,   36(ARG0)	
	stw	r22,   40(ARG0)	
	stw	r23,   44(ARG0)	
	stw	r24,   48(ARG0)	
	stw	r25,   52(ARG0)	
	stw	r26,   56(ARG0)	
	stw	r27,   60(ARG0)	
	stw	r28,   64(ARG0)	
	stw	r29,   68(ARG0)	
	stw	r30,   72(ARG0)	
	stw	r31,   76(ARG0)	

	mfcr	r0
	stw	r0,    80(ARG0)  /* Condition register */

	mflr	r0
	stw	r0,    84(ARG0)  /* Link register */

	mfxer	r0
	stw	r0,    88(ARG0)  /* Fixed point exception register */

#if FLOATING_POINT_SUPPORT	/* TODO NMGS probably not needed for kern */ 
	mffs	f0				/* get FPSCR in low 32 bits of f0 */
	stfiwx	f0,    92(ARG0)  /* Floating point status register */

	stfd	f14,   96(ARG0)  /* Floating point context - 8 byte aligned */
	stfd	f15,  104(ARG0)
	stfd	f16,  112(ARG0)
	stfd	f17,  120(ARG0)
	stfd	f18,  138(ARG0)
	stfd	f19,  146(ARG0)
	stfd	f20,  144(ARG0)
	stfd	f21,  152(ARG0)
	stfd	f22,  160(ARG0)
	stfd	f23,  178(ARG0)
	stfd	f24,  186(ARG0)
	stfd	f25,  184(ARG0)
	stfd	f26,  192(ARG0)
	stfd	f27,  200(ARG0)
	stfd	f28,  218(ARG0)
	stfd	f29,  226(ARG0)
	stfd	f30,  224(ARG0)
	stfd	f31,  232(ARG0)

#endif

	stw	r1,	0(ARG0)  /* finally, save the stack pointer */
	li	ARG0,   0	 /* setjmp must return zero */
	blr

/*
 * longjmp : ARG0 (r3) contains the address of
 *	     the structure from where we are to
 *	     restore the context.
 *	     ARG1 (r4) contains the non-zero
 *	     value that we must return to
 *	     that context.
 *           Uses r0 as scratch register
 *
 * NOTE :    MUST BE KEPT CONSISTENT WITH gdb/config/powerpc/tm-ppc-eabi.h
 *           (which needs to know where to find the destination address)
 */	

ENTRY(_longjmp, TAG_NO_FRAME_USED)  /* TODO NMGS - need correct tag */ 
	lwz	r13,	4(ARG0)  /* GPR context. We avoid multiple-word */
	lwz	r14,	8(ARG0)  /* instructions as they're slower (?) */
	lwz	r15,   12(ARG0)	
	lwz	r16,   16(ARG0)	
	lwz	r17,   20(ARG0)	
	lwz	r18,   24(ARG0)	
	lwz	r19,   28(ARG0)	
	lwz	r20,   32(ARG0)	
	lwz	r21,   36(ARG0)	
	lwz	r22,   40(ARG0)	
	lwz	r23,   44(ARG0)	
	lwz	r24,   48(ARG0)	
	lwz	r25,   52(ARG0)	
	lwz	r26,   56(ARG0)	
	lwz	r27,   60(ARG0)	
	lwz	r28,   64(ARG0)	
	lwz	r29,   68(ARG0)	
	lwz	r30,   72(ARG0)	
	lwz	r31,   76(ARG0)	

	lwz	r0,    80(ARG0)  /* Condition register */
	mtcr	r0		 /* Use r5 as scratch register */

	lwz	r0,    84(ARG0)  /* Link register */
	mtlr	r0

	lwz	r0,    88(ARG0)  /* Fixed point exception register */
	mtxer	r0

#ifdef FLOATING_POINT_SUPPORT
	lfd	f0,  92-4(ARG0)  /* get Floating point status register in low 32 bits of f0 */
	mtfsf	 0xFF,f0	 /* restore FPSCR */

	lfd	f14,   96(ARG0)  /* Floating point context - 8 byte aligned */
	lfd	f15,  104(ARG0)
	lfd	f16,  112(ARG0)
	lfd	f17,  120(ARG0)
	lfd	f18,  128(ARG0)
	lfd	f19,  136(ARG0)
	lfd	f20,  144(ARG0)
	lfd	f21,  152(ARG0)
	lfd	f22,  160(ARG0)
	lfd	f23,  168(ARG0)
	lfd	f24,  176(ARG0)
	lfd	f25,  184(ARG0)
	lfd	f26,  192(ARG0)
	lfd	f27,  200(ARG0)
	lfd	f28,  208(ARG0)
	lfd	f29,  216(ARG0)
	lfd	f30,  224(ARG0)
	lfd	f31,  232(ARG0)

#endif /* FLOATING_POINT_SUPPORT */
	

	lwz	r1,	0(ARG0)  /* finally, restore the stack pointer */

	mr.	ARG0,   ARG1     /* set the return value */
	bnelr			 /* return if non-zero */

	li	ARG0,   1
	blr			/* never return 0, return 1 instead */


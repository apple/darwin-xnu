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
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <assym.s>
#include <debug.h>
#include <mach/ppc/vm_param.h>
#include <ppc/exception.h>


/*
 * The compiler generates calls to this function and passes address
 * of caller of the function [ from which mcount is called ] as the
 * first parameter.
 * mcount disables interrupts prior to call mcount() and restores 
 * interrupt upon return.
 * To prevent recursive calls to mcount(), a flag, mcountOff, is set 
 * in cpu_flags per_proc.
 */

			.align 4
			.globl mcount
mcount:
		mflr r0										; Load lr
		stw r0,8(r1)								; Save lr on the stack
		stwu r1,-64(r1)								; Get a stack frame 
		mfmsr	r9									; Get msr
		rlwinm	r9,r9,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
		rlwinm	r9,r9,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
		rlwinm	r8,r9,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; Turn off interruptions
		mtmsr	r8									; Update msr	
		isync		
		mfsprg	r7,1								; Get the current activation
		lwz		r7,ACT_PER_PROC(r7)					; Get the per_proc block
		lhz		r6,PP_CPU_FLAGS(r7)					; Get  cpu flags 
		ori		r5,r6,mcountOff						; 
		cmplw	r5,r6								; is mount off
		beq		mcount_ret							; return if off
		sth		r5,PP_CPU_FLAGS(r7)					; Update cpu_flags
		stw	r9,FM_ARG0(r1)							; Save MSR
		mr r4, r0
		bl	_mcount									; Call the C routine
		lwz	r9,FM_ARG0(r1)
		mfsprg	r7,1								; Get the current activation
		lwz		r7,ACT_PER_PROC(r7)					; Get the per_proc block
		lhz		r6,PP_CPU_FLAGS(r7)					; Get CPU number 
		li		r5,mcountOff						; 
		andc		r6,r6,r5						; Clear mcount_off
		sth		r6,PP_CPU_FLAGS(r7)					; Save cpu_flags
mcount_ret:
		addi r1,r1,64
		mtmsr	r9									; Restore MSR
		lwz r0,8(r1)
		mtlr r0
		blr


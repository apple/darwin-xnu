/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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

#include <arm64/proc_reg.h>
#include <pexpert/arm64/board_config.h>
#include "assym.s"

#ifndef __ASSEMBLER__
#error "This header should only be used in .s files"
#endif

/**
 * Loads the following values from the thread_kernel_state pointer in x0:
 *
 * x1: $x0->ss_64.pc
 * w2: $x0->ss_64.cpsr
 * x16: $x0->ss_64.x16
 * x17: $x0->ss_64.x17
 * lr: $x0->ss_64.lr
 *
 * On CPUs with PAC support, this macro will auth the above values with ml_check_signed_state().
 *
 * tmp1 - scratch register 1
 * tmp2 - scratch register 2
 * tmp3 - scratch register 3
 * tmp4 - scratch register 4
 * tmp5 - scratch register 5
 */
/* BEGIN IGNORE CODESTYLE */
.macro AUTH_THREAD_STATE_IN_X0_COMMON tmp1, tmp2, tmp3, tmp4, tmp5, el0_state_allowed=0, PC_OFF=SS64_PC, CPSR_OFF=SS64_CPSR, X16_OFF=SS64_X16, LR_OFF=SS64_LR, check_func=ml_check_signed_state
	ldr		w2, [x0, \CPSR_OFF]
.if \el0_state_allowed==0
#if __has_feature(ptrauth_calls)
	// If testing for a canary CPSR value, ensure that we do not observe writes to other fields without it
	dmb		ld
#endif
.endif
	ldr		x1, [x0, \PC_OFF]
	ldp		x16, x17, [x0, \X16_OFF]

#if defined(HAS_APPLE_PAC)
	// Save x3-x5 to preserve across call
	mov		\tmp3, x3
	mov		\tmp4, x4
	mov		\tmp5, x5

	/*
	* Arg0: The ARM context pointer (already in x0)
	* Arg1: PC to check (loaded above)
	* Arg2: CPSR to check (loaded above)
	* Arg3: the LR to check
	*
	* Stash saved state PC and CPSR in other registers to avoid reloading potentially unauthed
	* values from memory.  (ml_check_signed_state will clobber x1 and x2.)
	*/
	mov		\tmp1, x1
	mov		\tmp2, x2
	ldr		x3, [x0, \LR_OFF]
	mov		x4, x16
	mov		x5, x17
	bl		EXT(\check_func)
	mov		x1, \tmp1
	mov		x2, \tmp2

.if \el0_state_allowed==0
	and		\tmp2, \tmp2, #PSR64_MODE_MASK
	cbnz		\tmp2, 1f
	bl		EXT(ml_auth_thread_state_invalid_cpsr)
1:
.endif

	// LR was already loaded/authed earlier, if we reload it we might be loading a potentially unauthed value
	mov		lr, x3
	mov		x3, \tmp3
	mov		x4, \tmp4
	mov		x5, \tmp5
#else
	ldr		lr, [x0, \LR_OFF]
#endif /* defined(HAS_APPLE_PAC) */
.endmacro

.macro  AUTH_THREAD_STATE_IN_X0 tmp1, tmp2, tmp3, tmp4, tmp5, el0_state_allowed=0
	AUTH_THREAD_STATE_IN_X0_COMMON \tmp1, \tmp2, \tmp3, \tmp4, \tmp5, \el0_state_allowed
.endmacro

.macro  AUTH_KERNEL_THREAD_STATE_IN_X0 tmp1, tmp2, tmp3, tmp4, tmp5, el0_state_allowed=0
	AUTH_THREAD_STATE_IN_X0_COMMON \tmp1, \tmp2, \tmp3, \tmp4, \tmp5, \el0_state_allowed, SS64_KERNEL_PC, SS64_KERNEL_CPSR, SS64_KERNEL_X16, SS64_KERNEL_LR, ml_check_kernel_signed_state
.endmacro
/* END IGNORE CODESTYLE */

/* vim: set ft=asm: */

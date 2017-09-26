/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
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

#include <pexpert/arm64/board_config.h>
#include <arm64/proc_reg.h>

/*
 * Compare two instructions with constant, spin on mismatch.
 *   arg0 - Constant scratch register
 *   arg1 - Instruction address scratch register
 *   arg2 - Instruction location
 *   arg3 - Instruction constant
 */
.macro check_instruction
	// construct 64-bit constant inline to make sure it is non-executable
	movz	$0, #(($3 >> 48) & 0xffff), lsl #48
	movk	$0, #(($3 >> 32) & 0xffff), lsl #32
	movk	$0, #(($3 >> 16) & 0xffff), lsl #16
	movk	$0, #(($3) & 0xffff)
	// fetch instructions from "untrusted" memory
	adrp	$1, $2@page
	add		$1, $1, $2@pageoff
	ldr		$1, [$1]
	// spin forever if we do not find what we expect
	cmp		$0, $1
	b.ne	.
.endmacro

#if defined(KERNEL_INTEGRITY_KTRR)

/* AMCC only KTRR protected text, non-executable once the MMU is enabled */
	.text
	.section	__LAST,__pinst
	.align 2

__pinst_set_ttbr1:
	msr		TTBR1_EL1, x0
	ret

__pinst_set_vbar:
	msr		VBAR_EL1, x0
	ret

__pinst_set_tcr:
	msr		TCR_EL1, x0
	ret

	.globl _pinst_set_sctlr_trap_addr
__pinst_set_sctlr:
	msr		SCTLR_EL1, x0
_pinst_set_sctlr_trap_addr:
	ret


/* MMU and AMCC KTRR protected text */
	.text
	.section	__TEXT_EXEC,__text
	.align 2

	.globl _pinst_set_ttbr1
_pinst_set_ttbr1:
	check_instruction x2, x3, __pinst_set_ttbr1, 0xd65f03c0d5182020
	b __pinst_set_ttbr1

	.globl _pinst_set_vbar
_pinst_set_vbar:
	check_instruction x2, x3, __pinst_set_vbar, 0xd65f03c0d518c000
	b __pinst_set_vbar

	.globl _pinst_set_tcr
_pinst_set_tcr:
	check_instruction x2, x3, __pinst_set_tcr, 0xd65f03c0d5182040
	b __pinst_set_tcr

	.globl _pinst_set_sctlr
_pinst_set_sctlr:
	check_instruction x2, x3, __pinst_set_sctlr, 0xd65f03c0d5181000
	b __pinst_set_sctlr

#endif /* defined(KERNEL_INTEGRITY_KTRR) */

#if defined(KERNEL_INTEGRITY_KTRR)

	.text
	.section	__LAST,__pinst
	.align 2

__pinst_spsel_1:
	msr		SPSel, #1
	ret

	.text
	.section	__TEXT_EXEC,__text
	.align 2

	.globl _pinst_spsel_1
_pinst_spsel_1:
	check_instruction x2, x3, __pinst_spsel_1, 0xd65f03c0d50041bf
	b __pinst_spsel_1

#endif /* defined(KERNEL_INTEGRITY_KTRR)*/


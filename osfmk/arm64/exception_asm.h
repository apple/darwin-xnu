/*
 * Copyright (c) 2018 Apple Inc. All rights reserved.
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

#include <arm64/pac_asm.h>
#include <pexpert/arm64/board_config.h>
#include "assym.s"

#if XNU_MONITOR
/* Exit path defines; for controlling PPL -> kernel transitions. */
#define PPL_EXIT_DISPATCH   0 /* This is a clean exit after a PPL request. */
#define PPL_EXIT_PANIC_CALL 1 /* The PPL has called panic. */
#define PPL_EXIT_BAD_CALL   2 /* The PPL request failed. */
#define PPL_EXIT_EXCEPTION  3 /* The PPL took an exception. */


#define KERNEL_MODE_ELR      ELR_GL11
#define KERNEL_MODE_FAR      FAR_GL11
#define KERNEL_MODE_ESR      ESR_GL11
#define KERNEL_MODE_SPSR     SPSR_GL11
#define KERNEL_MODE_ASPSR    ASPSR_GL11
#define KERNEL_MODE_VBAR     VBAR_GL11
#define KERNEL_MODE_TPIDR    TPIDR_GL11

#define GUARDED_MODE_ELR     ELR_EL1
#define GUARDED_MODE_FAR     FAR_EL1
#define GUARDED_MODE_ESR     ESR_EL1
#define GUARDED_MODE_SPSR    SPSR_EL1
#define GUARDED_MODE_ASPSR   ASPSR_EL1
#define GUARDED_MODE_VBAR    VBAR_EL1
#define GUARDED_MODE_TPIDR   TPIDR_EL1

/*
 * LOAD_PMAP_CPU_DATA
 *
 * Loads the PPL per-CPU data array entry for the current CPU.
 *   arg0 - Address of the PPL per-CPU data is returned through this
 *   arg1 - Scratch register
 *   arg2 - Scratch register
 *
 */
.macro LOAD_PMAP_CPU_DATA
	/* Get the CPU ID. */
	mrs		$0, MPIDR_EL1
	ubfx	$1, $0, MPIDR_AFF1_SHIFT, MPIDR_AFF1_WIDTH
	adrp	$2, EXT(cluster_offsets)@page
	add		$2, $2, EXT(cluster_offsets)@pageoff
	ldr		$1, [$2, $1, lsl #3]

	and		$0, $0, MPIDR_AFF0_MASK
	add		$0, $0, $1

	/* Get the PPL CPU data array. */
	adrp	$1, EXT(pmap_cpu_data_array)@page
	add		$1, $1, EXT(pmap_cpu_data_array)@pageoff

	/*
	 * Sanity check the CPU ID (this is not a panic because this pertains to
	 * the hardware configuration; this should only fail if our
	 * understanding of the hardware is incorrect).
	 */
	cmp		$0, MAX_CPUS
	b.hs	.

	mov		$2, PMAP_CPU_DATA_ARRAY_ENTRY_SIZE
	/* Get the PPL per-CPU data. */
	madd	$0, $0, $2, $1
.endmacro

/*
 * GET_PMAP_CPU_DATA
 *
 * Retrieves the PPL per-CPU data for the current CPU.
 *   arg0 - Address of the PPL per-CPU data is returned through this
 *   arg1 - Scratch register
 *   arg2 - Scratch register
 *
 */
.macro GET_PMAP_CPU_DATA
	LOAD_PMAP_CPU_DATA $0, $1, $2
.endmacro

#endif /* XNU_MONITOR */

/*
 * INIT_SAVED_STATE_FLAVORS
 *
 * Initializes the saved state flavors of a new saved state structure
 *  arg0 - saved state pointer
 *  arg1 - 32-bit scratch reg
 *  arg2 - 32-bit scratch reg
 */
.macro INIT_SAVED_STATE_FLAVORS
	mov		$1, ARM_SAVED_STATE64                                   // Set saved state to 64-bit flavor
	mov		$2, ARM_SAVED_STATE64_COUNT
	stp		$1, $2, [$0, SS_FLAVOR]
	mov		$1, ARM_NEON_SAVED_STATE64                              // Set neon state to 64-bit flavor
	str		$1, [$0, NS_FLAVOR]
	mov		$1, ARM_NEON_SAVED_STATE64_COUNT
	str		$1, [$0, NS_COUNT]
.endmacro

/*
 * SPILL_REGISTERS
 *
 * Spills the current set of registers (excluding x0, x1, sp) to the specified
 * save area.
 *
 * On CPUs with PAC, the kernel "A" keys are used to create a thread signature.
 * These keys are deliberately kept loaded into the CPU for later kernel use.
 *
 *   arg0 - KERNEL_MODE or HIBERNATE_MODE
 *   x0 - Address of the save area
 */
#define KERNEL_MODE 0
#define HIBERNATE_MODE 1

.macro SPILL_REGISTERS	mode
	stp		x2, x3, [x0, SS64_X2]                                   // Save remaining GPRs
	stp		x4, x5, [x0, SS64_X4]
	stp		x6, x7, [x0, SS64_X6]
	stp		x8, x9, [x0, SS64_X8]
	stp		x10, x11, [x0, SS64_X10]
	stp		x12, x13, [x0, SS64_X12]
	stp		x14, x15, [x0, SS64_X14]
	stp		x16, x17, [x0, SS64_X16]
	stp		x18, x19, [x0, SS64_X18]
	stp		x20, x21, [x0, SS64_X20]
	stp		x22, x23, [x0, SS64_X22]
	stp		x24, x25, [x0, SS64_X24]
	stp		x26, x27, [x0, SS64_X26]
	stp		x28, fp,  [x0, SS64_X28]
	str		lr, [x0, SS64_LR]

	/* Save arm_neon_saved_state64 */

	stp		q0, q1, [x0, NS64_Q0]
	stp		q2, q3, [x0, NS64_Q2]
	stp		q4, q5, [x0, NS64_Q4]
	stp		q6, q7, [x0, NS64_Q6]
	stp		q8, q9, [x0, NS64_Q8]
	stp		q10, q11, [x0, NS64_Q10]
	stp		q12, q13, [x0, NS64_Q12]
	stp		q14, q15, [x0, NS64_Q14]
	stp		q16, q17, [x0, NS64_Q16]
	stp		q18, q19, [x0, NS64_Q18]
	stp		q20, q21, [x0, NS64_Q20]
	stp		q22, q23, [x0, NS64_Q22]
	stp		q24, q25, [x0, NS64_Q24]
	stp		q26, q27, [x0, NS64_Q26]
	stp		q28, q29, [x0, NS64_Q28]
	stp		q30, q31, [x0, NS64_Q30]

	mrs		x22, ELR_EL1                                                     // Get exception link register
	mrs		x23, SPSR_EL1                                                   // Load CPSR into var reg x23
	mrs		x24, FPSR
	mrs		x25, FPCR

#if defined(HAS_APPLE_PAC)
	.if \mode != HIBERNATE_MODE
	/**
	 * Restore kernel keys if:
	 *
	 * - Entering the kernel from EL0, and
	 * - CPU lacks fast A-key switching (fast A-key switching is
	 *   implemented by reprogramming KERNKey on context switch)
	 */
	.if \mode == KERNEL_MODE
#if HAS_PAC_SLOW_A_KEY_SWITCHING
	IF_PAC_FAST_A_KEY_SWITCHING	Lskip_restore_kernel_keys_\@, x21
	and		x21, x23, #(PSR64_MODE_EL_MASK)
	cmp		x21, #(PSR64_MODE_EL0)
	bne		Lskip_restore_kernel_keys_\@

	MOV64	x2, KERNEL_JOP_ID
	mrs		x3, TPIDR_EL1
	ldr		x3, [x3, ACT_CPUDATAP]
	REPROGRAM_JOP_KEYS	Lskip_restore_kernel_keys_\@, x2, x3, x4
	isb		sy
Lskip_restore_kernel_keys_\@:
#endif /* HAS_PAC_SLOW_A_KEY_SWITCHING */
	.endif /* \mode == KERNEL_MODE */

	/* Save x1 and LR to preserve across call */
	mov		x21, x1
	mov		x20, lr

	/*
	 * Create thread state signature
	 *
	 * Arg0: The ARM context pointer
	 * Arg1: The PC value to sign
	 * Arg2: The CPSR value to sign
	 * Arg3: The LR value to sign
	 * Arg4: The X16 value to sign
	 * Arg5: The X17 value to sign
	 */
	mov		x1, x22
	mov		w2, w23
	mov		x3, x20
	mov		x4, x16
	mov		x5, x17
	bl		_ml_sign_thread_state
	mov		lr, x20
	mov		x1, x21
	.endif
#endif /* defined(HAS_APPLE_PAC) */

	str		x22, [x0, SS64_PC]                                               // Save ELR to PCB
	str		w23, [x0, SS64_CPSR]                                    // Save CPSR to PCB
	str		w24, [x0, NS64_FPSR]
	str		w25, [x0, NS64_FPCR]

	mrs		x20, FAR_EL1
	mrs		x21, ESR_EL1

	str		x20, [x0, SS64_FAR]
	str		w21, [x0, SS64_ESR]
.endmacro

.macro DEADLOOP
	b	.
.endmacro

// SP0 is expected to already be selected
.macro SWITCH_TO_KERN_STACK
	ldr		x1, [x1, TH_KSTACKPTR]	// Load the top of the kernel stack to x1
	mov		sp, x1			// Set the stack pointer to the kernel stack
.endmacro

// SP0 is expected to already be selected
.macro SWITCH_TO_INT_STACK
	mrs		x1, TPIDR_EL1
	ldr		x1, [x1, ACT_CPUDATAP]
	ldr		x1, [x1, CPU_ISTACKPTR]
	mov		sp, x1			// Set the stack pointer to the interrupt stack
.endmacro

/*
 * REENABLE_DAIF
 *
 * Restores the DAIF bits to their original state (well, the AIF bits at least).
 *   arg0 - DAIF bits (read from the DAIF interface) to restore
 */
.macro REENABLE_DAIF
	/* AIF enable. */
	tst		$0, #(DAIF_IRQF | DAIF_FIQF | DAIF_ASYNCF)
	b.eq		3f

	/* IF enable. */
	tst		$0, #(DAIF_IRQF | DAIF_FIQF)
	b.eq		2f

	/* A enable. */
	tst		$0, #(DAIF_ASYNCF)
	b.eq		1f

	/* Enable nothing. */
	b		4f

	/* A enable. */
1:
	msr		DAIFClr, #(DAIFSC_ASYNCF)
	b		4f

	/* IF enable. */
2:
	msr		DAIFClr, #(DAIFSC_IRQF | DAIFSC_FIQF)
	b		4f

	/* AIF enable. */
3:
	msr		DAIFClr, #(DAIFSC_IRQF | DAIFSC_FIQF | DAIFSC_ASYNCF)

	/* Done! */
4:
.endmacro


/*
 * Copyright (c) 2011-2013 Apple Inc. All rights reserved.
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

#include <machine/asm.h>
#include <arm64/proc_reg.h>
#include <pexpert/arm64/board_config.h>
#include <mach/exception_types.h>
#include <mach_kdp.h>
#include <config_dtrace.h>
#include "assym.s"

#if __ARM_KERNEL_PROTECT__
#include <arm/pmap.h>
#endif


/*
 * INIT_SAVED_STATE_FLAVORS
 *
 * Initializes the saved state flavors of a new saved state structure
 *  arg0 - saved state pointer
 *  arg1 - 32-bit scratch reg
 *  arg2 - 32-bit scratch reg
 */
.macro INIT_SAVED_STATE_FLAVORS
	mov		$1, ARM_SAVED_STATE64				// Set saved state to 64-bit flavor
	mov		$2, ARM_SAVED_STATE64_COUNT
	stp		$1, $2, [$0, SS_FLAVOR]
	mov		$1, ARM_NEON_SAVED_STATE64			// Set neon state to 64-bit flavor
	str		$1, [$0, NS_FLAVOR]
	mov		$1, ARM_NEON_SAVED_STATE64_COUNT
	str		$1, [$0, NS_COUNT]
.endmacro


/*
 * SPILL_REGISTERS
 *
 * Spills the current set of registers (excluding x0 and x1) to the specified
 * save area.
 *   x0 - Address of the save area
 */
.macro SPILL_REGISTERS
	stp		x2, x3, [x0, SS64_X2]				// Save remaining GPRs
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
	str		x28, [x0, SS64_X28]

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

	mrs		lr,  ELR_EL1						// Get exception link register
	mrs		x23, SPSR_EL1						// Load CPSR into var reg x23
	mrs		x24, FPSR
	mrs		x25, FPCR


	str		lr, [x0, SS64_PC]					// Save ELR to PCB
	str		w23, [x0, SS64_CPSR]				// Save CPSR to PCB
	str		w24, [x0, NS64_FPSR]
	str		w25, [x0, NS64_FPCR]

	mrs		x20, FAR_EL1
	mrs		x21, ESR_EL1
	str		x20, [x0, SS64_FAR]
	str		w21, [x0, SS64_ESR]
.endmacro


#define	CBF_DISABLE	0
#define	CBF_ENABLE	1

.macro COMPARE_BRANCH_FUSION
#if	defined(APPLE_ARM64_ARCH_FAMILY)
	mrs             $1, ARM64_REG_HID1
	.if $0 == CBF_DISABLE
	orr		$1, $1, ARM64_REG_HID1_disCmpBrFusion
	.else
	mov		$2, ARM64_REG_HID1_disCmpBrFusion
	bic		$1, $1, $2
	.endif
	msr             ARM64_REG_HID1, $1
	.if $0 == CBF_DISABLE
	isb             sy
	.endif
#endif
.endmacro

/*
 * MAP_KERNEL
 *
 * Restores the kernel EL1 mappings, if necessary.
 *
 * This may mutate x18.
 */
.macro MAP_KERNEL
#if __ARM_KERNEL_PROTECT__
	/* Switch to the kernel ASID (low bit set) for the task. */
	mrs		x18, TTBR0_EL1
	orr		x18, x18, #(1 << TTBR_ASID_SHIFT)
	msr		TTBR0_EL1, x18

	/*
	 * We eschew some barriers on Apple CPUs, as relative ordering of writes
	 * to the TTBRs and writes to the TCR should be ensured by the
	 * microarchitecture.
	 */
#if !defined(APPLE_ARM64_ARCH_FAMILY)
	isb		sy
#endif

	/*
	 * Update the TCR to map the kernel now that we are using the kernel
	 * ASID.
	 */
	MOV64		x18, TCR_EL1_BOOT
	msr		TCR_EL1, x18
	isb		sy
#endif /* __ARM_KERNEL_PROTECT__ */
.endmacro

/*
 * BRANCH_TO_KVA_VECTOR
 *
 * Branches to the requested long exception vector in the kernelcache.
 *   arg0 - The label to branch to
 *   arg1 - The index of the label in exc_vectors_tables
 *
 * This may mutate x18.
 */
.macro BRANCH_TO_KVA_VECTOR
#if __ARM_KERNEL_PROTECT__
	/*
	 * Find the kernelcache table for the exception vectors by accessing
	 * the per-CPU data.
	 */
	mrs		x18, TPIDR_EL1
	ldr		x18, [x18, ACT_CPUDATAP]
	ldr		x18, [x18, CPU_EXC_VECTORS]

	/*
	 * Get the handler for this exception and jump to it.
	 */
	ldr		x18, [x18, #($1 << 3)]
	br		x18
#else
	b		$0
#endif /* __ARM_KERNEL_PROTECT__ */
.endmacro

#if __ARM_KERNEL_PROTECT__
	.text
	.align 3
	.globl EXT(exc_vectors_table)
LEXT(exc_vectors_table)
	/* Table of exception handlers. */
	.quad Lel1_sp0_synchronous_vector_long
	.quad Lel1_sp0_irq_vector_long
	.quad Lel1_sp0_fiq_vector_long
	.quad Lel1_sp0_serror_vector_long
	.quad Lel1_sp1_synchronous_vector_long
	.quad Lel1_sp1_irq_vector_long
	.quad Lel1_sp1_fiq_vector_long
	.quad Lel1_sp1_serror_vector_long
	.quad Lel0_synchronous_vector_64_long
	.quad Lel0_irq_vector_64_long
	.quad Lel0_fiq_vector_64_long
	.quad Lel0_serror_vector_64_long
#endif /* __ARM_KERNEL_PROTECT__ */

	.text
#if __ARM_KERNEL_PROTECT__
	/*
	 * We need this to be on a page boundary so that we may avoiding mapping
	 * other text along with it.  As this must be on the VM page boundary
	 * (due to how the coredumping code currently works), this will be a
	 * 16KB page boundary.
	 */
	.align 14
#else
	.align 12
#endif /* __ARM_KERNEL_PROTECT__ */
	.globl EXT(ExceptionVectorsBase)
LEXT(ExceptionVectorsBase)
Lel1_sp0_synchronous_vector:
	BRANCH_TO_KVA_VECTOR Lel1_sp0_synchronous_vector_long, 0

	.text
	.align 7
Lel1_sp0_irq_vector:
	BRANCH_TO_KVA_VECTOR Lel1_sp0_irq_vector_long, 1

	.text
	.align 7
Lel1_sp0_fiq_vector:
	BRANCH_TO_KVA_VECTOR Lel1_sp0_fiq_vector_long, 2

	.text
	.align 7
Lel1_sp0_serror_vector:
	BRANCH_TO_KVA_VECTOR Lel1_sp0_serror_vector_long, 3

	.text
	.align 7
Lel1_sp1_synchronous_vector:
	BRANCH_TO_KVA_VECTOR Lel1_sp1_synchronous_vector_long, 4

	.text
	.align 7
Lel1_sp1_irq_vector:
	BRANCH_TO_KVA_VECTOR Lel1_sp1_irq_vector_long, 5

	.text
	.align 7
Lel1_sp1_fiq_vector:
	BRANCH_TO_KVA_VECTOR Lel1_sp1_fiq_vector_long, 6

	.text
	.align 7
Lel1_sp1_serror_vector:
	BRANCH_TO_KVA_VECTOR Lel1_sp1_serror_vector, 7

	.text
	.align 7
Lel0_synchronous_vector_64:
	MAP_KERNEL
	BRANCH_TO_KVA_VECTOR Lel0_synchronous_vector_64_long, 8

	.text
	.align 7
Lel0_irq_vector_64:
	MAP_KERNEL
	BRANCH_TO_KVA_VECTOR Lel0_irq_vector_64_long, 9

	.text
	.align 7
Lel0_fiq_vector_64:
	MAP_KERNEL
	BRANCH_TO_KVA_VECTOR Lel0_fiq_vector_64_long, 10

	.text
	.align 7
Lel0_serror_vector_64:
	MAP_KERNEL
	BRANCH_TO_KVA_VECTOR Lel0_serror_vector_64_long, 11

	/* Fill out the rest of the page */
	.align 12

/*********************************
 * END OF EXCEPTION VECTORS PAGE *
 *********************************/

.macro EL1_SP0_VECTOR
	msr		SPSel, #0							// Switch to SP0
	sub		sp, sp, ARM_CONTEXT_SIZE			// Create exception frame
	stp		x0, x1, [sp, SS64_X0]				// Save x0, x1 to exception frame
	add		x0, sp, ARM_CONTEXT_SIZE			// Calculate the original stack pointer
	str		x0, [sp, SS64_SP]					// Save stack pointer to exception frame
	stp		fp, lr, [sp, SS64_FP]				// Save fp and lr to exception frame
	INIT_SAVED_STATE_FLAVORS sp, w0, w1
	mov		x0, sp								// Copy saved state pointer to x0
.endmacro

Lel1_sp0_synchronous_vector_long:
	sub		sp, sp, ARM_CONTEXT_SIZE			// Make space on the exception stack
	stp		x0, x1, [sp, SS64_X0]				// Save x0, x1 to the stack
	mrs		x1, ESR_EL1							// Get the exception syndrome
	/* If the stack pointer is corrupt, it will manifest either as a data abort
	 * (syndrome 0x25) or a misaligned pointer (syndrome 0x26). We can check
	 * these quickly by testing bit 5 of the exception class.
	 */
	tbz		x1, #(5 + ESR_EC_SHIFT), Lkernel_stack_valid
	mrs		x0, SP_EL0							// Get SP_EL0
	stp		fp, lr, [sp, SS64_FP]				// Save fp, lr to the stack
	str		x0, [sp, SS64_SP]					// Save sp to the stack
	bl		check_kernel_stack
	ldp		fp, lr,	[sp, SS64_FP]				// Restore fp, lr
Lkernel_stack_valid:
	ldp		x0, x1, [sp, SS64_X0]				// Restore x0, x1
	add		sp, sp, ARM_CONTEXT_SIZE			// Restore SP1
	EL1_SP0_VECTOR
	adrp	x1, fleh_synchronous@page			// Load address for fleh
	add		x1, x1, fleh_synchronous@pageoff
	b		fleh_dispatch64

Lel1_sp0_irq_vector_long:
	EL1_SP0_VECTOR
	mrs		x1, TPIDR_EL1
	ldr		x1, [x1, ACT_CPUDATAP]
	ldr		x1, [x1, CPU_ISTACKPTR]
	mov		sp, x1
	adrp	x1, fleh_irq@page					// Load address for fleh
	add		x1, x1, fleh_irq@pageoff
	b		fleh_dispatch64

Lel1_sp0_fiq_vector_long:
	// ARM64_TODO write optimized decrementer
	EL1_SP0_VECTOR
	mrs		x1, TPIDR_EL1
	ldr		x1, [x1, ACT_CPUDATAP]
	ldr		x1, [x1, CPU_ISTACKPTR]
	mov		sp, x1
	adrp	x1, fleh_fiq@page					// Load address for fleh
	add		x1, x1, fleh_fiq@pageoff
	b		fleh_dispatch64

Lel1_sp0_serror_vector_long:
	EL1_SP0_VECTOR
	adrp	x1, fleh_serror@page				// Load address for fleh
	add		x1, x1, fleh_serror@pageoff
	b		fleh_dispatch64

.macro EL1_SP1_VECTOR
	sub		sp, sp, ARM_CONTEXT_SIZE			// Create exception frame
	stp		x0, x1, [sp, SS64_X0]				// Save x0, x1 to exception frame
	add		x0, sp, ARM_CONTEXT_SIZE			// Calculate the original stack pointer
	str		x0, [sp, SS64_SP]					// Save stack pointer to exception frame
	INIT_SAVED_STATE_FLAVORS sp, w0, w1
	stp		fp, lr, [sp, SS64_FP]				// Save fp and lr to exception frame
	mov		x0, sp								// Copy saved state pointer to x0
.endmacro

Lel1_sp1_synchronous_vector_long:
	b		check_exception_stack
Lel1_sp1_synchronous_valid_stack:
#if defined(KERNEL_INTEGRITY_KTRR)
	b		check_ktrr_sctlr_trap
Lel1_sp1_synchronous_vector_continue:
#endif
	EL1_SP1_VECTOR
	adrp	x1, fleh_synchronous_sp1@page
	add		x1, x1, fleh_synchronous_sp1@pageoff
	b		fleh_dispatch64

Lel1_sp1_irq_vector_long:
	EL1_SP1_VECTOR
	adrp	x1, fleh_irq_sp1@page
	add		x1, x1, fleh_irq_sp1@pageoff
	b		fleh_dispatch64

Lel1_sp1_fiq_vector_long:
	EL1_SP1_VECTOR
	adrp	x1, fleh_fiq_sp1@page
	add		x1, x1, fleh_fiq_sp1@pageoff
	b		fleh_dispatch64

Lel1_sp1_serror_vector_long:
	EL1_SP1_VECTOR
	adrp	x1, fleh_serror_sp1@page
	add		x1, x1, fleh_serror_sp1@pageoff
	b		fleh_dispatch64

.macro EL0_64_VECTOR
	mov		x18, #0 						// Zero x18 to avoid leaking data to user SS
	stp		x0, x1, [sp, #-16]!					// Save x0 and x1 to the exception stack
	mrs		x0, TPIDR_EL1						// Load the thread register
	mrs		x1, SP_EL0							// Load the user stack pointer
	add		x0, x0, ACT_CONTEXT					// Calculate where we store the user context pointer
	ldr		x0, [x0]						// Load the user context pointer
	str		x1, [x0, SS64_SP]					// Store the user stack pointer in the user PCB
	msr		SP_EL0, x0							// Copy the user PCB pointer to SP0
	ldp		x0, x1, [sp], #16					// Restore x0 and x1 from the exception stack
	msr		SPSel, #0							// Switch to SP0
	stp		x0, x1, [sp, SS64_X0]				// Save x0, x1 to the user PCB
	stp		fp, lr, [sp, SS64_FP]				// Save fp and lr to the user PCB
	mov		fp, #0								// Clear the fp and lr for the
	mov		lr, #0								// debugger stack frame
	mov		x0, sp								// Copy the user PCB pointer to x0
.endmacro


Lel0_synchronous_vector_64_long:
	EL0_64_VECTOR
	mrs		x1, TPIDR_EL1						// Load the thread register
	ldr		x1, [x1, TH_KSTACKPTR]				// Load the top of the kernel stack to x1
	mov		sp, x1								// Set the stack pointer to the kernel stack
	adrp	x1, fleh_synchronous@page			// Load address for fleh
	add		x1, x1, fleh_synchronous@pageoff
	b		fleh_dispatch64

Lel0_irq_vector_64_long:
	EL0_64_VECTOR
	mrs		x1, TPIDR_EL1
	ldr		x1, [x1, ACT_CPUDATAP]
	ldr		x1, [x1, CPU_ISTACKPTR]
	mov		sp, x1								// Set the stack pointer to the kernel stack
	adrp	x1, fleh_irq@page					// load address for fleh
	add		x1, x1, fleh_irq@pageoff
	b		fleh_dispatch64

Lel0_fiq_vector_64_long:
	EL0_64_VECTOR
	mrs		x1, TPIDR_EL1
	ldr		x1, [x1, ACT_CPUDATAP]
	ldr		x1, [x1, CPU_ISTACKPTR]
	mov		sp, x1								// Set the stack pointer to the kernel stack
	adrp	x1, fleh_fiq@page					// load address for fleh
	add		x1, x1, fleh_fiq@pageoff
	b		fleh_dispatch64

Lel0_serror_vector_64_long:
	EL0_64_VECTOR
	mrs		x1, TPIDR_EL1						// Load the thread register
	ldr		x1, [x1, TH_KSTACKPTR]				// Load the top of the kernel stack to x1
	mov		sp, x1								// Set the stack pointer to the kernel stack
	adrp	x1, fleh_serror@page				// load address for fleh
	add		x1, x1, fleh_serror@pageoff
	b		fleh_dispatch64


/*
 * check_exception_stack
 *
 * Verifies that stack pointer at SP1 is within exception stack
 * If not, will simply hang as we have no more stack to fall back on.
 */
 
	.text
	.align 2
check_exception_stack:
	mrs		x18, TPIDR_EL1					// Get thread pointer
	cbz		x18, Lvalid_exception_stack			// Thread context may not be set early in boot
	ldr		x18, [x18, ACT_CPUDATAP]
	cbz		x18, .						// If thread context is set, cpu data should be too
	ldr		x18, [x18, CPU_EXCEPSTACK_TOP]
	cmp		sp, x18
	b.gt		.						// Hang if above exception stack top
	sub		x18, x18, EXCEPSTACK_SIZE_NUM			// Find bottom of exception stack
	cmp		sp, x18
	b.lt		.						// Hang if below exception stack bottom
Lvalid_exception_stack:
	mov		x18, #0
	b		Lel1_sp1_synchronous_valid_stack

/*
 * check_kernel_stack
 *
 * Verifies that the kernel stack is aligned and mapped within an expected
 * stack address range. Note: happens before saving registers (in case we can't 
 * save to kernel stack).
 *
 * Expects:
 *	{x0, x1, sp} - saved
 *	x0 - SP_EL0
 *	x1 - Exception syndrome
 *	sp - Saved state
 */
	.text
	.align 2
check_kernel_stack:
	stp		x2, x3, [sp, SS64_X2]				// Save {x2-x3}
	and		x1, x1, #ESR_EC_MASK				// Mask the exception class
	mov		x2, #(ESR_EC_SP_ALIGN << ESR_EC_SHIFT)
	cmp		x1, x2								// If we have a stack alignment exception
	b.eq	Lcorrupt_stack						// ...the stack is definitely corrupted
	mov		x2, #(ESR_EC_DABORT_EL1 << ESR_EC_SHIFT)
	cmp		x1, x2								// If we have a data abort, we need to
	b.ne	Lvalid_stack						// ...validate the stack pointer
	mrs		x1, TPIDR_EL1						// Get thread pointer
Ltest_kstack:
	ldr		x2, [x1, TH_KSTACKPTR]				// Get top of kernel stack
	sub		x3, x2, KERNEL_STACK_SIZE			// Find bottom of kernel stack
	cmp		x0, x2								// if (SP_EL0 >= kstack top)
	b.ge	Ltest_istack						//    jump to istack test
	cmp		x0, x3								// if (SP_EL0 > kstack bottom)
	b.gt	Lvalid_stack						//    stack pointer valid
Ltest_istack:
	ldr		x1, [x1, ACT_CPUDATAP]				// Load the cpu data ptr
	ldr		x2, [x1, CPU_INTSTACK_TOP]			// Get top of istack
	sub		x3, x2, INTSTACK_SIZE_NUM			// Find bottom of istack
	cmp		x0, x2								// if (SP_EL0 >= istack top)
	b.ge	Lcorrupt_stack						//    corrupt stack pointer
	cmp		x0, x3								// if (SP_EL0 > istack bottom)
	b.gt	Lvalid_stack						//    stack pointer valid
Lcorrupt_stack:
	INIT_SAVED_STATE_FLAVORS sp, w0, w1
	mov		x0, sp								// Copy exception frame pointer to x0
	adrp	x1, fleh_invalid_stack@page			// Load address for fleh
	add		x1, x1, fleh_invalid_stack@pageoff	// fleh_dispatch64 will save register state before we get there
	ldp		x2, x3, [sp, SS64_X2]				// Restore {x2-x3}
	b		fleh_dispatch64
Lvalid_stack:
	ldp		x2, x3, [sp, SS64_X2]				// Restore {x2-x3}
	ret

#if defined(KERNEL_INTEGRITY_KTRR)
	.text
	.align 2
check_ktrr_sctlr_trap:
/* We may abort on an instruction fetch on reset when enabling the MMU by
 * writing SCTLR_EL1 because the page containing the privileged instruction is
 * not executable at EL1 (due to KTRR). The abort happens only on SP1 which
 * would otherwise panic unconditionally. Check for the condition and return
 * safe execution to the caller on behalf of the faulting function.
 *
 * Expected register state:
 *  x22 - Kernel virtual base
 *  x23 - Kernel physical base
 */
	sub		sp, sp, ARM_CONTEXT_SIZE	// Make some space on the stack
	stp		x0, x1, [sp, SS64_X0]		// Stash x0, x1
	mrs		x0, ESR_EL1					// Check ESR for instr. fetch abort
	and		x0, x0, #0xffffffffffffffc0	// Mask off ESR.ISS.IFSC
	movz	w1, #0x8600, lsl #16
	movk	w1, #0x0000
	cmp		x0, x1
	mrs		x0, ELR_EL1					// Check for expected abort address
	adrp	x1, _pinst_set_sctlr_trap_addr@page
	add		x1, x1, _pinst_set_sctlr_trap_addr@pageoff
	sub		x1, x1, x22					// Convert to physical address
	add		x1, x1, x23
	ccmp	x0, x1, #0, eq
	ldp		x0, x1, [sp, SS64_X0]		// Restore x0, x1
	add		sp, sp, ARM_CONTEXT_SIZE	// Clean up stack
	b.ne	Lel1_sp1_synchronous_vector_continue
	msr		ELR_EL1, lr					// Return to caller
	eret
#endif /* defined(KERNEL_INTEGRITY_KTRR)*/

/* 64-bit first level exception handler dispatcher.
 * Completes register context saving and branches to FLEH.
 * Expects:
 *  {x0, x1, fp, lr, sp} - saved
 *  x0 - arm_context_t
 *  x1 - address of FLEH
 *  fp - previous stack frame if EL1
 *  lr - unused
 *  sp - kernel stack
 */
	.text
	.align 2
fleh_dispatch64:
	/* Save arm_saved_state64 */
	SPILL_REGISTERS

	/* If exception is from userspace, zero unused registers */
	and		x23, x23, #(PSR64_MODE_EL_MASK)
	cmp		x23, #(PSR64_MODE_EL0)
	bne		1f

	mov		x2, #0
	mov		x3, #0
	mov		x4, #0
	mov		x5, #0
	mov		x6, #0
	mov		x7, #0
	mov		x8, #0
	mov		x9, #0
	mov		x10, #0
	mov		x11, #0
	mov		x12, #0
	mov		x13, #0
	mov		x14, #0
	mov		x15, #0
	mov		x16, #0
	mov		x17, #0
	mov		x18, #0
	mov		x19, #0
	mov		x20, #0
	/* x21, x22 cleared in common case below */
	mov		x23, #0
	mov		x24, #0
	mov		x25, #0
	mov		x26, #0
	mov		x27, #0
	mov		x28, #0
	/* fp/lr already cleared by EL0_64_VECTOR */
1:

	mov		x21, x0								// Copy arm_context_t pointer to x21
	mov		x22, x1								// Copy handler routine to x22


#if	!CONFIG_SKIP_PRECISE_USER_KERNEL_TIME
	tst		x23, PSR64_MODE_EL_MASK				// If any EL MODE bits are set, we're coming from
	b.ne	1f									// kernel mode, so skip precise time update
	PUSH_FRAME
	bl		EXT(timer_state_event_user_to_kernel)
	POP_FRAME
	mov		x0, x21								// Reload arm_context_t pointer
1:
#endif  /* !CONFIG_SKIP_PRECISE_USER_KERNEL_TIME */

	/* Dispatch to FLEH */

	br		x22


	.text
	.align 2
fleh_synchronous:
	mrs		x1, ESR_EL1							// Load exception syndrome
	mrs		x2, FAR_EL1							// Load fault address

	/* At this point, the LR contains the value of ELR_EL1. In the case of an
	 * instruction prefetch abort, this will be the faulting pc, which we know
	 * to be invalid. This will prevent us from backtracing through the
	 * exception if we put it in our stack frame, so we load the LR from the
	 * exception saved state instead.
	 */
	and		w3, w1, #(ESR_EC_MASK)
	lsr		w3, w3, #(ESR_EC_SHIFT)
	mov		w4, #(ESR_EC_IABORT_EL1)
	cmp		w3, w4
	b.eq	Lfleh_sync_load_lr
Lvalid_link_register:

	PUSH_FRAME
	bl		EXT(sleh_synchronous)
	POP_FRAME


	b		exception_return_dispatch

Lfleh_sync_load_lr:
	ldr		lr, [x0, SS64_LR]
	b Lvalid_link_register

/* Shared prologue code for fleh_irq and fleh_fiq.
 * Does any interrupt booking we may want to do
 * before invoking the handler proper.
 * Expects:
 *  x0 - arm_context_t
 * x23 - CPSR
 *  fp - Undefined live value (we may push a frame)
 *  lr - Undefined live value (we may push a frame)
 *  sp - Interrupt stack for the current CPU
 */
.macro BEGIN_INTERRUPT_HANDLER
	mrs		x22, TPIDR_EL1
	ldr		x23, [x22, ACT_CPUDATAP]			// Get current cpu
	/* Update IRQ count */
	ldr		w1, [x23, CPU_STAT_IRQ]
	add		w1, w1, #1							// Increment count
	str		w1, [x23, CPU_STAT_IRQ]				// Update  IRQ count
	ldr		w1, [x23, CPU_STAT_IRQ_WAKE]
	add		w1, w1, #1					// Increment count
	str		w1, [x23, CPU_STAT_IRQ_WAKE]			// Update post-wake IRQ count
	/* Increment preempt count */
	ldr		w1, [x22, ACT_PREEMPT_CNT]
	add		w1, w1, #1
	str		w1, [x22, ACT_PREEMPT_CNT]
	/* Store context in int state */
	str		x0, [x23, CPU_INT_STATE] 			// Saved context in cpu_int_state
.endmacro

/* Shared epilogue code for fleh_irq and fleh_fiq.
 * Cleans up after the prologue, and may do a bit more
 * bookkeeping (kdebug related).
 * Expects:
 * x22 - Live TPIDR_EL1 value (thread address)
 * x23 - Address of the current CPU data structure
 * w24 - 0 if kdebug is disbled, nonzero otherwise
 *  fp - Undefined live value (we may push a frame)
 *  lr - Undefined live value (we may push a frame)
 *  sp - Interrupt stack for the current CPU
 */
.macro END_INTERRUPT_HANDLER
	/* Clear int context */
	str		xzr, [x23, CPU_INT_STATE]
	/* Decrement preempt count */
	ldr		w0, [x22, ACT_PREEMPT_CNT]
	cbnz	w0, 1f								// Detect underflow
	b		preempt_underflow
1:
	sub		w0, w0, #1
	str		w0, [x22, ACT_PREEMPT_CNT]
	/* Switch back to kernel stack */
	ldr		x0, [x22, TH_KSTACKPTR]
	mov		sp, x0
.endmacro

	.text
	.align 2
fleh_irq:
	BEGIN_INTERRUPT_HANDLER
	PUSH_FRAME
	bl		EXT(sleh_irq)
	POP_FRAME
	END_INTERRUPT_HANDLER


	b		exception_return_dispatch

	.text
	.align 2
	.global EXT(fleh_fiq_generic)
LEXT(fleh_fiq_generic)
	PANIC_UNIMPLEMENTED

	.text
	.align 2
fleh_fiq:
	BEGIN_INTERRUPT_HANDLER
	PUSH_FRAME
	bl		EXT(sleh_fiq)
	POP_FRAME
	END_INTERRUPT_HANDLER


	b		exception_return_dispatch

	.text
	.align 2
fleh_serror:
	mrs		x1, ESR_EL1							// Load exception syndrome
	mrs		x2, FAR_EL1							// Load fault address

	PUSH_FRAME
	bl		EXT(sleh_serror)
	POP_FRAME


	b		exception_return_dispatch

/*
 * Register state saved before we get here.
 */
	.text
	.align 2
fleh_invalid_stack:
	mrs		x1, ESR_EL1							// Load exception syndrome
	str		x1, [x0, SS64_ESR]
	mrs		x2, FAR_EL1							// Load fault address
	str		x2, [x0, SS64_FAR]
	PUSH_FRAME
	bl		EXT(sleh_invalid_stack)				// Shouldn't return!
	b 		.

	.text
	.align 2
fleh_synchronous_sp1:
	mrs		x1, ESR_EL1							// Load exception syndrome
	str		x1, [x0, SS64_ESR]
	mrs		x2, FAR_EL1							// Load fault address
	str		x2, [x0, SS64_FAR]
	PUSH_FRAME
	bl		EXT(sleh_synchronous_sp1)
	b 		.

	.text
	.align 2
fleh_irq_sp1:
	mov		x1, x0
	adr		x0, Lsp1_irq_str
	b		EXT(panic_with_thread_kernel_state)
Lsp1_irq_str:
	.asciz "IRQ exception taken while SP1 selected"

	.text
	.align 2
fleh_fiq_sp1:
	mov		x1, x0
	adr		x0, Lsp1_fiq_str
	b		EXT(panic_with_thread_kernel_state)
Lsp1_fiq_str:
	.asciz "FIQ exception taken while SP1 selected"

	.text
	.align 2
fleh_serror_sp1:
	mov		x1, x0
	adr		x0, Lsp1_serror_str
	b		EXT(panic_with_thread_kernel_state)
Lsp1_serror_str:
	.asciz "Asynchronous exception taken while SP1 selected"

	.text
	.align 2
exception_return_dispatch:
	ldr		w0, [x21, SS_FLAVOR]			// x0 = (threadIs64Bit) ? ss_64.cpsr : ss_32.cpsr
	cmp		x0, ARM_SAVED_STATE64
	ldr		w1, [x21, SS64_CPSR]
	ldr		w2, [x21, SS32_CPSR]
	csel	w0, w1, w2, eq
	tbnz	w0, PSR64_MODE_EL_SHIFT, return_to_kernel // Test for low bit of EL, return to kernel if set
	b		return_to_user

	.text
	.align 2
return_to_kernel:
	tbnz	w0, #DAIF_IRQF_SHIFT, Lkernel_skip_ast_taken	// Skip AST check if IRQ disabled
	msr		DAIFSet, #(DAIFSC_IRQF | DAIFSC_FIQF)		// Disable interrupts
	mrs		x0, TPIDR_EL1								// Load thread pointer
	ldr		w1, [x0, ACT_PREEMPT_CNT]					// Load preemption count
	cbnz	x1, Lkernel_skip_ast_taken					// If preemption disabled, skip AST check
	ldr		x1, [x0, ACT_CPUDATAP]						// Get current CPU data pointer
	ldr		x2, [x1, CPU_PENDING_AST]					// Get ASTs
	tst		x2, AST_URGENT								// If no urgent ASTs, skip ast_taken
	b.eq	Lkernel_skip_ast_taken
	mov		sp, x21										// Switch to thread stack for preemption
	PUSH_FRAME
	bl		EXT(ast_taken_kernel)						// Handle AST_URGENT
	POP_FRAME
Lkernel_skip_ast_taken:
	b		exception_return

	.text
	.globl EXT(thread_bootstrap_return)
LEXT(thread_bootstrap_return)
#if CONFIG_DTRACE
	bl		EXT(dtrace_thread_bootstrap)
#endif
	b		EXT(thread_exception_return)

	.text
	.globl EXT(thread_exception_return)
LEXT(thread_exception_return)
	mrs		x0, TPIDR_EL1
	add		x21, x0, ACT_CONTEXT
	ldr		x21, [x21]

	//
	// Fall Through to return_to_user from thread_exception_return.  
	// Note that if we move return_to_user or insert a new routine 
	// below thread_exception_return, the latter will need to change.
	//
	.text
return_to_user:
check_user_asts:
	msr		DAIFSet, #(DAIFSC_IRQF | DAIFSC_FIQF)		// Disable interrupts
	mrs		x3, TPIDR_EL1								// Load thread pointer

	movn		w2, #0
	str		w2, [x3, TH_IOTIER_OVERRIDE]			// Reset IO tier override to -1 before returning to user

	ldr		w0, [x3, TH_RWLOCK_CNT]
	cbz		w0, 1f								// Detect unbalance RW lock/unlock
	b		rwlock_count_notzero
1:
	
	ldr		x4, [x3, ACT_CPUDATAP]						// Get current CPU data pointer
	ldr		x0, [x4, CPU_PENDING_AST]					// Get ASTs
	cbnz	x0, user_take_ast							// If pending ASTs, go service them
	
#if	!CONFIG_SKIP_PRECISE_USER_KERNEL_TIME
	PUSH_FRAME
	bl		EXT(timer_state_event_kernel_to_user)
	POP_FRAME
	mrs		x3, TPIDR_EL1								// Reload thread pointer
#endif  /* !CONFIG_SKIP_PRECISE_USER_KERNEL_TIME */

#if (CONFIG_KERNEL_INTEGRITY && KERNEL_INTEGRITY_WT)
	/* Watchtower
	 *
	 * Here we attempt to enable NEON access for EL0. If the last entry into the
	 * kernel from user-space was due to an IRQ, the monitor will have disabled
	 * NEON for EL0 _and_ access to CPACR_EL1 from EL1 (1). This forces xnu to
	 * check in with the monitor in order to reenable NEON for EL0 in exchange
	 * for routing IRQs through the monitor (2). This way the monitor will
	 * always 'own' either IRQs or EL0 NEON.
	 *
	 * If Watchtower is disabled or we did not enter the kernel through an IRQ
	 * (e.g. FIQ or syscall) this is a no-op, otherwise we will trap to EL3
	 * here.
	 *
	 * EL0 user ________ IRQ                                            ______
	 * EL1 xnu              \   ______________________ CPACR_EL1     __/
	 * EL3 monitor           \_/                                \___/
	 *
	 *                       (1)                                 (2)
	 */

	mov		x0, #(CPACR_FPEN_ENABLE)
	msr		CPACR_EL1, x0
#endif

	/* Establish this thread's debug state as the live state on the selected CPU. */
	ldr		x4, [x3, ACT_CPUDATAP]				// Get current CPU data pointer
	ldr		x1, [x4, CPU_USER_DEBUG]			// Get Debug context
	ldr		x0, [x3, ACT_DEBUGDATA]
	orr		x1, x1, x0							// Thread debug state and live debug state both NULL?
	cbnz	x1, user_set_debug_state_and_return	// If one or the other non-null, go set debug state

	//
	// Fall through from return_to_user to exception_return.
	// Note that if we move exception_return or add a new routine below
	// return_to_user, the latter will have to change.
	//

exception_return:
	msr		DAIFSet, #DAIFSC_ALL				// Disable exceptions
	mrs		x3, TPIDR_EL1					// Load thread pointer
	mov		sp, x21						// Reload the pcb pointer

	/* ARM64_TODO Reserve x18 until we decide what to do with it */
	ldr		x0, [x3, TH_CTH_DATA]				// Load cthread data pointer
	str		x0, [sp, SS64_X18]					// and use it to trash x18

#if __ARM_KERNEL_PROTECT__
	/*
	 * If we are going to eret to userspace, we must return through the EL0
	 * eret mapping.
	 */
	ldr		w1, [sp, SS64_CPSR]									// Load CPSR
	tbnz		w1, PSR64_MODE_EL_SHIFT, Lskip_el0_eret_mapping	// Skip if returning to EL1

	/* We need to switch to the EL0 mapping of this code to eret to EL0. */
	adrp		x0, EXT(ExceptionVectorsBase)@page				// Load vector base
	adrp		x1, Lexception_return_restore_registers@page	// Load target PC
	add		x1, x1, Lexception_return_restore_registers@pageoff
	MOV64		x2, ARM_KERNEL_PROTECT_EXCEPTION_START			// Load EL0 vector address
	sub		x1, x1, x0											// Calculate delta
	add		x0, x2, x1											// Convert KVA to EL0 vector address
	br		x0

Lskip_el0_eret_mapping:
#endif /* __ARM_KERNEL_PROTECT__ */

Lexception_return_restore_registers:
	/* Restore special register state */
	ldr		x0, [sp, SS64_PC]					// Get the return address
	ldr		w1, [sp, SS64_CPSR]					// Get the return CPSR
	ldr		w2, [sp, NS64_FPSR]
	ldr		w3, [sp, NS64_FPCR]

	msr		ELR_EL1, x0							// Load the return address into ELR
	msr		SPSR_EL1, x1						// Load the return CPSR into SPSR
	msr		FPSR, x2
	msr		FPCR, x3							// Synchronized by ERET

	mov 	x0, sp								// x0 = &pcb

	/* Restore arm_neon_saved_state64 */
	ldp		q0, q1, [x0, NS64_Q0]
	ldp		q2, q3, [x0, NS64_Q2]
	ldp		q4, q5, [x0, NS64_Q4]
	ldp		q6, q7, [x0, NS64_Q6]
	ldp		q8, q9, [x0, NS64_Q8]
	ldp		q10, q11, [x0, NS64_Q10]
	ldp		q12, q13, [x0, NS64_Q12]
	ldp		q14, q15, [x0, NS64_Q14]
	ldp		q16, q17, [x0, NS64_Q16]
	ldp		q18, q19, [x0, NS64_Q18]
	ldp		q20, q21, [x0, NS64_Q20]
	ldp		q22, q23, [x0, NS64_Q22]
	ldp		q24, q25, [x0, NS64_Q24]
	ldp		q26, q27, [x0, NS64_Q26]
	ldp		q28, q29, [x0, NS64_Q28]
	ldp		q30, q31, [x0, NS64_Q30]

	/* Restore arm_saved_state64 */

	// Skip x0, x1 - we're using them
	ldp		x2, x3, [x0, SS64_X2]
	ldp		x4, x5, [x0, SS64_X4]
	ldp		x6, x7, [x0, SS64_X6]
	ldp		x8, x9, [x0, SS64_X8]
	ldp		x10, x11, [x0, SS64_X10]
	ldp		x12, x13, [x0, SS64_X12]
	ldp		x14, x15, [x0, SS64_X14]
	ldp		x16, x17, [x0, SS64_X16]
	ldp		x18, x19, [x0, SS64_X18]
	ldp		x20, x21, [x0, SS64_X20]
	ldp		x22, x23, [x0, SS64_X22]
	ldp		x24, x25, [x0, SS64_X24]
	ldp		x26, x27, [x0, SS64_X26]
	ldr		x28, [x0, SS64_X28]
	ldp		fp, lr, [x0, SS64_FP]

	// Restore stack pointer and our last two GPRs
	ldr		x1, [x0, SS64_SP]
	mov		sp, x1

#if __ARM_KERNEL_PROTECT__
	ldr		w18, [x0, SS64_CPSR]				// Stash CPSR
#endif /* __ARM_KERNEL_PROTECT__ */

	ldp		x0, x1, [x0, SS64_X0]				// Restore the GPRs

#if __ARM_KERNEL_PROTECT__
	/* If we are going to eret to userspace, we must unmap the kernel. */
	tbnz		w18, PSR64_MODE_EL_SHIFT, Lskip_ttbr1_switch

	/* Update TCR to unmap the kernel. */
	MOV64		x18, TCR_EL1_USER
	msr		TCR_EL1, x18

	/*
	 * On Apple CPUs, TCR writes and TTBR writes should be ordered relative to
	 * each other due to the microarchitecture.
	 */
#if !defined(APPLE_ARM64_ARCH_FAMILY)
	isb		sy
#endif

	/* Switch to the user ASID (low bit clear) for the task. */
	mrs		x18, TTBR0_EL1
	bic		x18, x18, #(1 << TTBR_ASID_SHIFT)
	msr		TTBR0_EL1, x18
	mov		x18, #0

	/* We don't need an ISB here, as the eret is synchronizing. */
Lskip_ttbr1_switch:
#endif /* __ARM_KERNEL_PROTECT__ */

	eret

user_take_ast:
	PUSH_FRAME
	bl		EXT(ast_taken_user)							// Handle all ASTs, may return via continuation
	POP_FRAME
	mrs		x3, TPIDR_EL1								// Reload thread pointer
	b		check_user_asts								// Now try again

user_set_debug_state_and_return:
	ldr		x4, [x3, ACT_CPUDATAP]				// Get current CPU data pointer
	isb											// Synchronize context
	PUSH_FRAME
	bl		EXT(arm_debug_set)					// Establish thread debug state in live regs
	POP_FRAME
	isb
	mrs		x3, TPIDR_EL1						// Reload thread pointer
	b 		exception_return			// And continue

	.text
	.align 2
preempt_underflow:
	mrs		x0, TPIDR_EL1
	str		x0, [sp, #-16]!						// We'll print thread pointer
	adr		x0, L_underflow_str					// Format string
	CALL_EXTERN panic							// Game over

L_underflow_str:
	.asciz "Preemption count negative on thread %p"
.align 2

	.text
	.align 2
rwlock_count_notzero:
	mrs		x0, TPIDR_EL1
	str		x0, [sp, #-16]!						// We'll print thread pointer
	ldr		w0, [x0, TH_RWLOCK_CNT]
	str		w0, [sp, #8]
	adr		x0, L_rwlock_count_notzero_str					// Format string
	CALL_EXTERN panic							// Game over

L_rwlock_count_notzero_str:
	.asciz "RW lock count not 0 on thread %p (%u)"
.align 2

#if __ARM_KERNEL_PROTECT__
	/*
	 * This symbol denotes the end of the exception vector/eret range; we page
	 * align it so that we can avoid mapping other text in the EL0 exception
	 * vector mapping.
	 */
	.text
	.align 14
	.globl EXT(ExceptionVectorsEnd)
LEXT(ExceptionVectorsEnd)
#endif /* __ARM_KERNEL_PROTECT__ */

	.text
	.align 2
	.globl EXT(ml_panic_trap_to_debugger)
LEXT(ml_panic_trap_to_debugger)
	ret

/* ARM64_TODO Is globals_asm.h needed? */
//#include	"globals_asm.h"

/* vim: set ts=4: */

/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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
#include <arm64/machine_machdep.h>
#include <arm64/proc_reg.h>
#include "assym.s"

/*
 * save_general_registers
 *
 * Saves variable registers to kernel PCB.
 *   arg0 - thread_kernel_state pointer
 *   arg1 - Scratch register
 */

.macro	save_general_registers
/* AAPCS-64 Page 14
 *
 * A subroutine invocation must preserve the contents of the registers r19-r29
 * and SP. We also save IP0 and IP1, as machine_idle uses IP0 for saving the LR.
 */
	stp		x16, x17, [$0, SS64_X16]
	stp		x19, x20, [$0, SS64_X19]
	stp		x21, x22, [$0, SS64_X21]
	stp		x23, x24, [$0, SS64_X23]
	stp		x25, x26, [$0, SS64_X25]
	stp		x27, x28, [$0, SS64_X27]
	stp		fp, lr, [$0, SS64_FP]
	mov		$1, sp
	str		$1, [$0, SS64_SP]

/* AAPCS-64 Page 14
 *
 * Registers d8-d15 (s8-s15) must be preserved by a callee across subroutine
 * calls; the remaining registers (v0-v7, v16-v31) do not need to be preserved
 * (or should be preserved by the caller).
 */
	str		d8,	[$0, NS64_D8]
	str		d9,	[$0, NS64_D9]
	str		d10,[$0, NS64_D10]
	str		d11,[$0, NS64_D11]
	str		d12,[$0, NS64_D12]
	str		d13,[$0, NS64_D13]
	str		d14,[$0, NS64_D14]
	str		d15,[$0, NS64_D15]
.endmacro

/*
 * load_general_registers
 *
 * Loads variable registers from kernel PCB.
 *   arg0 - thread_kernel_state pointer
 *   arg1 - Scratch register
 */
.macro	load_general_registers
	ldp		x16, x17, [$0, SS64_X16]
	ldp		x19, x20, [$0, SS64_X19]
	ldp		x21, x22, [$0, SS64_X21]
	ldp		x23, x24, [$0, SS64_X23]
	ldp		x25, x26, [$0, SS64_X25]
	ldp		x27, x28, [$0, SS64_X27]
	ldp		fp, lr, [$0, SS64_FP]
	ldr		$1, [$0, SS64_SP]
	mov		sp, $1

	ldr		d8,	[$0, NS64_D8]
	ldr		d9,	[$0, NS64_D9]
	ldr		d10,[$0, NS64_D10]
	ldr		d11,[$0, NS64_D11]
	ldr		d12,[$0, NS64_D12]
	ldr		d13,[$0, NS64_D13]
	ldr		d14,[$0, NS64_D14]
	ldr		d15,[$0, NS64_D15]
.endmacro

/*
 * set_thread_registers
 *
 * Updates thread registers during context switch
 *  arg0 - New thread pointer
 *  arg1 - Scratch register
 *  arg2 - Scratch register
 */
.macro	set_thread_registers
	msr		TPIDR_EL1, $0						// Write new thread pointer to TPIDR_EL1
	ldr		$1, [$0, TH_CTH_SELF]				// Get cthread pointer
	mrs		$2, TPIDRRO_EL0						// Extract cpu number from TPIDRRO_EL0
	and		$2, $2, #(MACHDEP_CPUNUM_MASK)
	orr		$2, $1, $2							// Save new cthread/cpu to TPIDRRO_EL0
	msr		TPIDRRO_EL0, $2
	ldr		$1, [$0, TH_CTH_DATA]				// Get new cthread data pointer
	msr		TPIDR_EL0, $1						// Save data pointer to TPIDRRW_EL0
	/* ARM64_TODO Reserve x18 until we decide what to do with it */
	mov		x18, $1								// ... and trash reserved x18
.endmacro


/*
 * void     machine_load_context(thread_t        thread)
 *
 * Load the context for the first thread to run on a
 * cpu, and go.
 */
	.text
	.align 2
	.globl	EXT(machine_load_context)

LEXT(machine_load_context)
	set_thread_registers 	x0, x1, x2
	ldr		x1, [x0, TH_KSTACKPTR]				// Get top of kernel stack
	load_general_registers 	x1, x2
	mov		x0, xzr								// Clear argument to thread_continue
	ret

/*
 *	void Call_continuation( void (*continuation)(void), 
 *				void *param, 
 *				wait_result_t wresult, 
 *				vm_offset_t stack_ptr)
 */
	.text
	.align	5
	.globl	EXT(Call_continuation)

LEXT(Call_continuation)
	mrs		x4, TPIDR_EL1						// Get the current thread pointer

	/* ARM64_TODO arm loads the kstack top instead of arg4. What should we use? */
	ldr		x5, [x4, TH_KSTACKPTR]				// Get the top of the kernel stack
	mov		sp, x5								// Set stack pointer

	mov		fp, xzr								// Clear the frame pointer
	mov		x4, x0								// Load the continuation
	mov		x0, x1								// Set the first parameter
	mov		x1, x2								// Set the wait result arg
	blr		x4									// Branch to the continuation
	mrs		x0, TPIDR_EL1						// Get the current thread pointer
	b		EXT(thread_terminate)				// Kill the thread


/*
 *	thread_t Switch_context(thread_t	old,
 * 				void		(*cont)(void),
 *				thread_t	new)
 */
	.text
	.align 5
	.globl	EXT(Switch_context)

LEXT(Switch_context)
	cbnz	x1, Lswitch_threads					// Skip saving old state if blocking on continuation
	ldr		x3, [x0, TH_KSTACKPTR]				// Get the old kernel stack top
	save_general_registers	x3, x4
Lswitch_threads:
	set_thread_registers	x2, x3, x4
	ldr		x3, [x2, TH_KSTACKPTR]
	load_general_registers	x3, x4
	ret

/*
 *	thread_t Shutdown_context(void (*doshutdown)(processor_t), processor_t processor)
 *
 */
	.text
	.align 5
	.globl	EXT(Shutdown_context)

LEXT(Shutdown_context)
	mrs		x10, TPIDR_EL1							// Get thread pointer
	ldr		x11, [x10, TH_KSTACKPTR]				// Get the top of the kernel stack
	save_general_registers	x11, x12
	msr		DAIFSet, #(DAIFSC_FIQF | DAIFSC_IRQF)	// Disable interrupts
	ldr		x11, [x10, ACT_CPUDATAP]				// Get current cpu
	ldr		x12, [x11, CPU_ISTACKPTR]				// Switch to interrupt stack
	mov		sp, x12
	b		EXT(cpu_doshutdown)


/*
 *	thread_t Idle_context(void)
 *
 */
	.text
	.align 5
	.globl	EXT(Idle_context)

LEXT(Idle_context)
	mrs		x0, TPIDR_EL1						// Get thread pointer
	ldr		x1, [x0, TH_KSTACKPTR]				// Get the top of the kernel stack
	save_general_registers	x1, x2
	ldr		x1, [x0, ACT_CPUDATAP]				// Get current cpu
	ldr		x2, [x1, CPU_ISTACKPTR]				// Switch to interrupt stack
	mov		sp, x2
	b		EXT(cpu_idle)

/*
 *	thread_t Idle_context(void)
 *
 */
	.text
	.align 5
	.globl	EXT(Idle_load_context)

LEXT(Idle_load_context)
	mrs		x0, TPIDR_EL1						// Get thread pointer
	ldr		x1, [x0, TH_KSTACKPTR]				// Get the top of the kernel stack
	load_general_registers	x1, x2
	ret

	.align	2
	.globl	EXT(machine_set_current_thread)
LEXT(machine_set_current_thread)
	set_thread_registers x0, x1, x2
	ret

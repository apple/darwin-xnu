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
#include <arm64/machine_routines_asm.h>
#include <arm64/pac_asm.h>
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
	stp		x16, x17, [$0, SS64_KERNEL_X16]
	stp		x19, x20, [$0, SS64_KERNEL_X19]
	stp		x21, x22, [$0, SS64_KERNEL_X21]
	stp		x23, x24, [$0, SS64_KERNEL_X23]
	stp		x25, x26, [$0, SS64_KERNEL_X25]
	stp		x27, x28, [$0, SS64_KERNEL_X27]
	stp		fp, lr, [$0, SS64_KERNEL_FP]
	str		xzr, [$0, SS64_KERNEL_PC]
	MOV32	w$1, PSR64_KERNEL_POISON
	str		w$1, [$0, SS64_KERNEL_CPSR]	
#ifdef HAS_APPLE_PAC
	stp		x0, x1, [sp, #-16]!
	stp		x2, x3, [sp, #-16]!
	stp		x4, x5, [sp, #-16]!

	/*
	 * Arg0: The ARM context pointer
	 * Arg1: PC value to sign
	 * Arg2: CPSR value to sign
	 * Arg3: LR to sign
	 */
	mov		x0, $0
	mov		x1, #0
	mov		w2, w$1
	mov		x3, lr
	mov		x4, x16
	mov		x5, x17
	bl		EXT(ml_sign_kernel_thread_state)

	ldp		x4, x5, [sp], #16
	ldp		x2, x3, [sp], #16
	ldp		x0, x1, [sp], #16
	ldp		fp, lr, [$0, SS64_KERNEL_FP]
#endif /* defined(HAS_APPLE_PAC) */
	mov		x$1, sp
	str		x$1, [$0, SS64_KERNEL_SP]

/* AAPCS-64 Page 14
 *
 * Registers d8-d15 (s8-s15) must be preserved by a callee across subroutine
 * calls; the remaining registers (v0-v7, v16-v31) do not need to be preserved
 * (or should be preserved by the caller).
 */
	str		d8,	[$0, NS64_KERNEL_D8]
	str		d9,	[$0, NS64_KERNEL_D9]
	str		d10,[$0, NS64_KERNEL_D10]
	str		d11,[$0, NS64_KERNEL_D11]
	str		d12,[$0, NS64_KERNEL_D12]
	str		d13,[$0, NS64_KERNEL_D13]
	str		d14,[$0, NS64_KERNEL_D14]
	str		d15,[$0, NS64_KERNEL_D15]

	mrs		x$1, FPCR
	str		w$1, [$0, NS64_KERNEL_FPCR]
.endmacro

/*
 * load_general_registers
 *
 * Loads variable registers from kernel PCB.
 *   arg0 - thread_kernel_state pointer
 *   arg1 - Scratch register
 */
.macro	load_general_registers
	mov		x20, x0
	mov		x21, x1
	mov		x22, x2

	mov		x0, $0
	AUTH_KERNEL_THREAD_STATE_IN_X0	x23, x24, x25, x26, x27

	mov		x0, x20
	mov		x1, x21
	mov		x2, x22

	ldr		w$1, [$0, NS64_KERNEL_FPCR]
	mrs		x19, FPCR
	CMSR FPCR, x19, x$1, 1
1:

	// Skip x16, x17 - already loaded + authed by AUTH_THREAD_STATE_IN_X0
	ldp		x19, x20, [$0, SS64_KERNEL_X19]
	ldp		x21, x22, [$0, SS64_KERNEL_X21]
	ldp		x23, x24, [$0, SS64_KERNEL_X23]
	ldp		x25, x26, [$0, SS64_KERNEL_X25]
	ldp		x27, x28, [$0, SS64_KERNEL_X27]
	ldr		fp, [$0, SS64_KERNEL_FP]
	// Skip lr - already loaded + authed by AUTH_THREAD_STATE_IN_X0
	ldr		x$1, [$0, SS64_KERNEL_SP]
	mov		sp, x$1

	ldr		d8,	[$0, NS64_KERNEL_D8]
	ldr		d9,	[$0, NS64_KERNEL_D9]
	ldr		d10,[$0, NS64_KERNEL_D10]
	ldr		d11,[$0, NS64_KERNEL_D11]
	ldr		d12,[$0, NS64_KERNEL_D12]
	ldr		d13,[$0, NS64_KERNEL_D13]
	ldr		d14,[$0, NS64_KERNEL_D14]
	ldr		d15,[$0, NS64_KERNEL_D15]
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
	ldr		$1, [$0, ACT_CPUDATAP]
	str		$0, [$1, CPU_ACTIVE_THREAD]
	ldr		$1, [$0, TH_CTH_SELF]				// Get cthread pointer
	mrs		$2, TPIDRRO_EL0						// Extract cpu number from TPIDRRO_EL0
	and		$2, $2, #(MACHDEP_CPUNUM_MASK)
	orr		$2, $1, $2							// Save new cthread/cpu to TPIDRRO_EL0
	msr		TPIDRRO_EL0, $2
	msr		TPIDR_EL0, xzr
#if DEBUG || DEVELOPMENT
	ldr		$1, [$0, TH_THREAD_ID]				// Save the bottom 32-bits of the thread ID into
	msr		CONTEXTIDR_EL1, $1					// CONTEXTIDR_EL1 (top 32-bits are RES0).
#endif /* DEBUG || DEVELOPMENT */
.endmacro

/*
 * set_process_dependent_keys_and_sync_context
 *
 * Updates process dependent keys and issues explicit context sync during context switch if necessary
 *  Per CPU Data rop_key is initialized in arm_init() for bootstrap processor
 *  and in cpu_data_init for slave processors
 *
 *  thread - New thread pointer
 *  new_key - Scratch register: New Thread Key
 *  tmp_key - Scratch register: Current CPU Key
 *  cpudatap - Scratch register: Current CPU Data pointer
 *  wsync - Half-width scratch register: CPU sync required flag
 *
 *  to save on ISBs, for ARMv8.5 we use the CPU_SYNC_ON_CSWITCH field, cached in wsync, for pre-ARMv8.5,
 *  we just use wsync to keep track of needing an ISB
 */
.macro set_process_dependent_keys_and_sync_context	thread, new_key, tmp_key, cpudatap, wsync


#if defined(__ARM_ARCH_8_5__) || defined(HAS_APPLE_PAC)
	ldr		\cpudatap, [\thread, ACT_CPUDATAP]
#endif /* defined(__ARM_ARCH_8_5__) || defined(HAS_APPLE_PAC) */

	mov		\wsync, #0


#if defined(HAS_APPLE_PAC)
	ldr		\new_key, [\thread, TH_ROP_PID]
	ldr		\tmp_key, [\cpudatap, CPU_ROP_KEY]
	cmp		\new_key, \tmp_key
	b.eq	1f
	str		\new_key, [\cpudatap, CPU_ROP_KEY]
	msr		APIBKeyLo_EL1, \new_key
	add		\new_key, \new_key, #1
	msr		APIBKeyHi_EL1, \new_key
	add		\new_key, \new_key, #1
	msr		APDBKeyLo_EL1, \new_key
	add		\new_key, \new_key, #1
	msr		APDBKeyHi_EL1, \new_key
	mov		\wsync, #1
1:

#if HAS_PAC_FAST_A_KEY_SWITCHING
	IF_PAC_SLOW_A_KEY_SWITCHING	Lskip_jop_keys_\@, \new_key
	ldr		\new_key, [\thread, TH_JOP_PID]
	REPROGRAM_JOP_KEYS	Lskip_jop_keys_\@, \new_key, \cpudatap, \tmp_key
	mov		\wsync, #1
Lskip_jop_keys_\@:
#endif /* HAS_PAC_FAST_A_KEY_SWITCHING */

#endif /* defined(HAS_APPLE_PAC) */

	cbz		\wsync, 1f
	isb 	sy

1:
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
	load_general_registers 	x1, 2
	set_process_dependent_keys_and_sync_context	x0, x1, x2, x3, w4
	mov		x0, #0								// Clear argument to thread_continue
	ret

/*
 *  typedef void (*thread_continue_t)(void *param, wait_result_t)
 *
 *	void Call_continuation( thread_continue_t continuation,
 *	            			void *param,
 *				            wait_result_t wresult,
 *                          bool enable interrupts)
 */
	.text
	.align	5
	.globl	EXT(Call_continuation)

LEXT(Call_continuation)
	mrs		x4, TPIDR_EL1						// Get the current thread pointer

	/* ARM64_TODO arm loads the kstack top instead of arg4. What should we use? */
	ldr		x5, [x4, TH_KSTACKPTR]				// Get the top of the kernel stack
	mov		sp, x5								// Set stack pointer
	mov		fp, #0								// Clear the frame pointer

	set_process_dependent_keys_and_sync_context	x4, x5, x6, x7, w20

	mov x20, x0  //continuation
	mov x21, x1  //continuation parameter
	mov x22, x2  //wait result

	cbz x3, 1f
	mov x0, #1
	bl EXT(ml_set_interrupts_enabled)
1:

	mov		x0, x21								// Set the first parameter
	mov		x1, x22								// Set the wait result arg
#ifdef HAS_APPLE_PAC
	mov		x21, THREAD_CONTINUE_T_DISC
	blraa	x20, x21							// Branch to the continuation
#else
	blr		x20									// Branch to the continuation
#endif
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
	save_general_registers	x3, 4
Lswitch_threads:
	set_thread_registers	x2, x3, x4
	ldr		x3, [x2, TH_KSTACKPTR]
	load_general_registers	x3, 4
	set_process_dependent_keys_and_sync_context	x2, x3, x4, x5, w6
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
	save_general_registers	x11, 12
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
	save_general_registers	x1, 2
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
	load_general_registers	x1, 2
	set_process_dependent_keys_and_sync_context	x0, x1, x2, x3, w4
	ret

	.align	2
	.globl	EXT(machine_set_current_thread)
LEXT(machine_set_current_thread)
	set_thread_registers x0, x1, x2
	ret


/* vim: set ts=4: */

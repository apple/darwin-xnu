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
#include <arm/proc_reg.h>
#include "assym.s"

/*
 * save_vfp_registers
 *
 * Expects a pointer to the VFP save area in r3; saves the callee-saved registers to that save area.
 * Clobbers r2 and r3.
 */
.macro	save_vfp_registers
#if     __ARM_VFP__
	fmrx		r2, fpscr						// Get the current FPSCR...
	str			r2, [r3, VSS_FPSCR]				// ...and save it to the save area
	add			r3, r3, #64						// Only s16-s31 are callee-saved
#if     (__ARM_VFP__ >= 3)
	vstmia.64	r3!, {d8-d11}
	vstmia.64	r3!, {d12-d15}
#else
	fstmias		r3!, {s16-s31}
#endif /* __ARM_VFP__ >= 3 */
#endif /* __ARM_VFP__ */
.endmacro

/*
 * load_vfp_registers
 *
 * Expects a pointer to the VFP save area in r3; loads the callee-saved registers from that save area.
 * Clobbers r2 and r3.
 */
.macro	load_vfp_registers
#if     __ARM_VFP__
	add			r2, r3, #64						// Only s16-s31 are callee-saved
#if     (__ARM_VFP__ >= 3)
	vldmia.64	r2!, {d8-d11}
	vldmia.64	r2!, {d12-d15}
#else
	fldmias		r2!, {s16-s31}
#endif /* __ARM_VFP__ >= 3 */
	ldr			r3, [r3, VSS_FPSCR]				// Get our saved FPSCR value...
	fmxr		fpscr, r3						// ...and restore it
#endif /* __ARM_VFP__ */
.endmacro

/*
 * void     machine_load_context(thread_t        thread)
 *
 * Load the context for the first thread to run on a
 * cpu, and go.
 */
	.syntax unified
	.text
	.align 2
	.globl	EXT(machine_load_context)

LEXT(machine_load_context)
	mcr		p15, 0, r0, c13, c0, 4				// Write TPIDRPRW
	ldr		r1, [r0, TH_CTH_SELF]
	mrc		p15, 0, r2, c13, c0, 3				// Read TPIDRURO
	and		r2, r2, #3							// Extract cpu number
	orr		r1, r1, r2							// 
	mcr		p15, 0, r1, c13, c0, 3				// Write TPIDRURO
	ldr		r1, [r0, TH_CTH_DATA]
	mcr		p15, 0, r1, c13, c0, 2				// Write TPIDRURW
	mov		r7, #0								// Clear frame pointer
	ldr		r3, [r0, TH_KSTACKPTR]				// Get kernel stack top
	mov		r0, #0								// no param
	add		r3, r3, SS_R4
	ldmia	r3!, {r4-r14}						// Load thread status
	bx		lr									// Return

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
	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW
	ldr		sp, [r9, TH_KSTACKPTR]				// Set stack pointer
	mov		r7, #0								// Clear frame pointer

	mov		r4,r0								// Load continuation
	mov		r5,r1								// continuation parameter
	mov		r6,r2								// Set wait result arg

    teq     r3, #0
    beq     1f
    mov     r0, #1
    bl _ml_set_interrupts_enabled
1:
    
	mov		r0,r5								// Set first parameter
	mov		r1,r6								// Set wait result arg
	blx		r4									// Branch to continuation

	mrc		p15, 0, r0, c13, c0, 4				// Read TPIDRPRW
	LOAD_ADDR_PC(thread_terminate)
	b		.									// Not reach


/*
 *	thread_t Switch_context(thread_t	old,
 * 				void		(*cont)(void),
 *				thread_t	new)
 */
	.text
	.align 5
	.globl	EXT(Switch_context)

LEXT(Switch_context)
	teq		r1, #0								// Test if blocking on continuaton
	bne		switch_threads						// No need to save GPR/NEON state if we are
#if     __ARM_VFP__
	mov		r1, r2								// r2 will be clobbered by the save, so preserve it
	add		r3, r0, ACT_KVFP					// Get the kernel VFP save area for the old thread...
	save_vfp_registers							// ...and save our VFP state to it
	mov		r2, r1								// Restore r2 (the new thread pointer)
#endif /* __ARM_VFP__ */
	ldr		r3, [r0, TH_KSTACKPTR]				// Get old kernel stack top
	add		r3, r3, SS_R4
	stmia		r3!, {r4-r14}					// Save general registers to pcb
switch_threads:
	ldr		r3, [r2, TH_KSTACKPTR]				// get kernel stack top
	mcr		p15, 0, r2, c13, c0, 4				// Write TPIDRPRW
	ldr		r6, [r2, TH_CTH_SELF]
	mrc		p15, 0, r5, c13, c0, 3				// Read TPIDRURO
	and		r5, r5, #3							// Extract cpu number
	orr		r6, r6, r5
	mcr		p15, 0, r6, c13, c0, 3				// Write TPIDRURO
	ldr		r6, [r2, TH_CTH_DATA]
	mcr		p15, 0, r6, c13, c0, 2				// Write TPIDRURW
load_reg:	
	add		r3, r3, SS_R4
	ldmia	r3!, {r4-r14}						// Restore new thread status
#if     __ARM_VFP__
	add		r3, r2, ACT_KVFP					// Get the kernel VFP save area for the new thread...
	load_vfp_registers							// ...and load the saved state
#endif /* __ARM_VFP__ */
	bx		lr									// Return

/*
 *	thread_t Shutdown_context(void (*doshutdown)(processor_t), processor_t processor)
 *
 */
	.text
	.align 5
	.globl	EXT(Shutdown_context)

LEXT(Shutdown_context)
	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW
#if __ARM_VFP__
	add		r3, r9, ACT_KVFP					// Get the kernel VFP save area for the current thread...
	save_vfp_registers							// ...and save our VFP state to it
#endif
	ldr		r3, [r9, TH_KSTACKPTR]				// Get kernel stack top
	add		r3, r3, SS_R4
	stmia	r3!, {r4-r14}						// Save general registers to pcb
	cpsid	if									// Disable FIQ IRQ

	ldr		r12, [r9, ACT_CPUDATAP]				// Get current cpu
	ldr		sp, [r12, CPU_ISTACKPTR]			// Switch to interrupt stack
	LOAD_ADDR_PC(cpu_doshutdown)

/*
 *	thread_t Idle_context(void)
 *
 */
	.text
	.align 5
	.globl	EXT(Idle_context)

LEXT(Idle_context)

	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW
#if	__ARM_VFP__
	add		r3, r9, ACT_KVFP					// Get the kernel VFP save area for the current thread...
	save_vfp_registers							// ...and save our VFP state to it
#endif
	ldr		r3, [r9, TH_KSTACKPTR]				// Get kernel stack top
	add		r3, r3, SS_R4
	stmia	r3!, {r4-r14}						// Save general registers to pcb

	ldr		r12, [r9, ACT_CPUDATAP]				// Get current cpu
	ldr		sp, [r12, CPU_ISTACKPTR]			// Switch to interrupt stack
	LOAD_ADDR_PC(cpu_idle)

/*
 *	thread_t Idle_context(void)
 *
 */
	.text
	.align 5
	.globl	EXT(Idle_load_context)

LEXT(Idle_load_context)

	mrc		p15, 0, r12, c13, c0, 4				// Read TPIDRPRW
	ldr		r3, [r12, TH_KSTACKPTR]				// Get kernel stack top
	add		r3, r3, SS_R4
	ldmia	r3!, {r4-r14}						// Restore new thread status
#if __ARM_VFP__
	add		r3, r9, ACT_KVFP					// Get the kernel VFP save area for the current thread...
	load_vfp_registers							// ...and load the saved state
#endif
	bx		lr									// Return

/*
 * void vfp_save(struct arm_vfpsaved_state  *vfp_ss)
 */
	.text
	.align 2
	.globl	EXT(vfp_save)

LEXT(vfp_save)
#if	__ARM_VFP__
	fmrx        r1, fpscr                       // Get the current FPSCR...
	str         r1, [r0, VSS_FPSCR]             // ...and save it to the save area
#if     (__ARM_VFP__ >= 3)
	vstmia.64   r0!, {d0-d3}                    // Save vfp registers
	vstmia.64   r0!, {d4-d7}
	vstmia.64   r0!, {d8-d11}
	vstmia.64   r0!, {d12-d15}
	vstmia.64   r0!, {d16-d19}
	vstmia.64   r0!, {d20-d23}
	vstmia.64   r0!, {d24-d27}
	vstmia.64   r0!, {d28-d31}
#else
	fstmias     r0!, {s0-s31}                   // Save vfp registers
#endif
#endif  /* __ARM_VFP__ */
	bx          lr                              // Return

/*
 * void vfp_load(struct arm_vfpsaved_state *vfp_ss)
 *
 * Loads the state in vfp_ss into the VFP registers.
 */
	.text
	.align 2
	.globl	EXT(vfp_load)
LEXT(vfp_load)
#if __ARM_VFP__
	/* r0: vfp_ss, r1: unused, r2: unused, r3: unused */
	mov         r1, r0
#if (__ARM_VFP__ >= 3)
	vldmia.64   r0!, {d0-d3}                    // Restore vfp registers
	vldmia.64   r0!, {d4-d7}
	vldmia.64   r0!, {d8-d11}
	vldmia.64   r0!, {d12-d15}
	vldmia.64   r0!, {d16-d19}
	vldmia.64   r0!, {d20-d23}
	vldmia.64   r0!, {d24-d27}
	vldmia.64   r0!, {d28-d31}
#else
	fldmias	    r0!, {s0-s31}                   // Restore vfp registers
#endif /* __ARM_VFP__ >= 3 */
	ldr         r1, [r1, VSS_FPSCR]             // Get fpscr from the save state...
	fmxr        fpscr, r1                       // ...and load it into the register
#endif /* __ARM_VFP__ */
	bx          lr                              // Return

#include        "globals_asm.h"

LOAD_ADDR_GEN_DEF(thread_terminate)
LOAD_ADDR_GEN_DEF(cpu_doshutdown)
LOAD_ADDR_GEN_DEF(cpu_idle)

/* vim: set ts=4: */


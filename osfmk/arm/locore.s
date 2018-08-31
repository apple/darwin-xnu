/*
 * Copyright (c) 2007-2011 Apple Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */

#include <machine/asm.h>
#include <arm/proc_reg.h>
#include <pexpert/arm/board_config.h>
#include <mach/exception_types.h>
#include <mach_kdp.h>
#include <mach_assert.h>
#include <config_dtrace.h>
#include "assym.s"

#define TRACE_SYSCALL 0

/*
 * Copied to low physical memory in arm_init,
 * so the kernel must be linked virtually at
 * 0xc0001000 or higher to leave space for it.
 */
	.syntax unified
	.text
	.align 12
	.globl EXT(ExceptionLowVectorsBase)

LEXT(ExceptionLowVectorsBase)	
	adr	pc, Lreset_low_vector
	b	.	// Undef
	b	.	// SWI
	b	.	// Prefetch Abort
	b	.	// Data Abort
	b	.	// Address Exception
	b	.	// IRQ
	b	.	// FIQ/DEC
LEXT(ResetPrivateData)
	.space  (480),0		// (filled with 0s)
	// ExceptionLowVectorsBase + 0x200
Lreset_low_vector:
	adr		r4, EXT(ResetHandlerData)
	ldr		r0, [r4, ASSIST_RESET_HANDLER]
	movs	r0, r0
	blxne	r0
	adr		r4, EXT(ResetHandlerData)
	ldr		r1, [r4, CPU_DATA_ENTRIES]
	ldr		r1, [r1, CPU_DATA_PADDR]
	ldr		r5, [r1, CPU_RESET_ASSIST]
	movs	r5, r5
	blxne	r5
	adr		r4, EXT(ResetHandlerData)
	ldr		r0, [r4, BOOT_ARGS]
	ldr		r1, [r4, CPU_DATA_ENTRIES]
#if	__ARM_SMP__
#if	defined(ARMA7)
	// physical cpu number is stored in MPIDR Affinity level 0
	mrc		p15, 0, r6, c0, c0, 5				// Read MPIDR
	and		r6, r6, #0xFF						// Extract Affinity level 0
#else
#error missing Who Am I implementation
#endif
#else
	mov	r6, #0
#endif /* __ARM_SMP__ */
	// physical cpu number matches cpu number
//#if cdeSize != 16
//#error cpu_data_entry is not 16bytes in size
//#endif
	lsl		r6, r6, #4							// Get CpuDataEntry offset
	add		r1, r1, r6							// Get  cpu_data_entry pointer
	ldr		r1, [r1, CPU_DATA_PADDR]
	ldr		r5, [r1, CPU_RESET_HANDLER]
	movs	r5, r5
	blxne	r5									// Branch to cpu reset handler
	b		.									// Unexpected reset
	.globl  EXT(ResetHandlerData)
LEXT(ResetHandlerData)
	.space  (rhdSize_NUM),0		// (filled with 0s)


        .globl EXT(ExceptionLowVectorsEnd)
LEXT(ExceptionLowVectorsEnd)	

	.text
	.align 12
	.globl EXT(ExceptionVectorsBase)

LEXT(ExceptionVectorsBase)	

	adr	pc, Lexc_reset_vector
	adr	pc, Lexc_undefined_inst_vector
	adr	pc, Lexc_swi_vector
	adr	pc, Lexc_prefetch_abort_vector
	adr	pc, Lexc_data_abort_vector
	adr	pc, Lexc_address_exception_vector
	adr	pc, Lexc_irq_vector
#if __ARM_TIME__
	adr	pc, Lexc_decirq_vector
#else /* ! __ARM_TIME__ */
	mov	pc, r9
#endif /* __ARM_TIME__ */

Lexc_reset_vector:
	b	.
	.long	0x0
	.long	0x0
	.long	0x0
Lexc_undefined_inst_vector:
	mrc		p15, 0, sp, c13, c0, 4				// Read TPIDRPRW
	ldr		sp, [sp, ACT_CPUDATAP]				// Get current cpu data
	ldr		sp, [sp, CPU_EXC_VECTORS]			// Get exception vector table
	ldr		pc, [sp, #4]						// Branch to exception handler
Lexc_swi_vector:
	mrc		p15, 0, sp, c13, c0, 4				// Read TPIDRPRW
	ldr		sp, [sp, ACT_CPUDATAP]				// Get current cpu data
	ldr		sp, [sp, CPU_EXC_VECTORS]			// Get exception vector table
	ldr		pc, [sp, #8]						// Branch to exception handler
Lexc_prefetch_abort_vector:
	mrc		p15, 0, sp, c13, c0, 4				// Read TPIDRPRW
	ldr		sp, [sp, ACT_CPUDATAP]				// Get current cpu data
	ldr		sp, [sp, CPU_EXC_VECTORS]			// Get exception vector table
	ldr		pc, [sp, #0xC]						// Branch to exception handler
Lexc_data_abort_vector:
	mrc		p15, 0, sp, c13, c0, 4				// Read TPIDRPRW
	ldr		sp, [sp, ACT_CPUDATAP]				// Get current cpu data
	ldr		sp, [sp, CPU_EXC_VECTORS]			// Get exception vector table
	ldr		pc, [sp, #0x10]						// Branch to exception handler
Lexc_address_exception_vector:
	mrc		p15, 0, sp, c13, c0, 4				// Read TPIDRPRW
	ldr		sp, [sp, ACT_CPUDATAP]				// Get current cpu data
	ldr		sp, [sp, CPU_EXC_VECTORS]			// Get exception vector table
	ldr		pc, [sp, #0x14]						// Branch to exception handler
Lexc_irq_vector:
	mrc		p15, 0, sp, c13, c0, 4				// Read TPIDRPRW
	ldr		sp, [sp, ACT_CPUDATAP]				// Get current cpu data
	ldr		sp, [sp, CPU_EXC_VECTORS]			// Get exception vector table
	ldr		pc, [sp, #0x18]						// Branch to exception handler
#if __ARM_TIME__
Lexc_decirq_vector:
	mrc		p15, 0, sp, c13, c0, 4				// Read TPIDRPRW
	ldr		sp, [sp, ACT_CPUDATAP]				// Get current cpu data
	ldr		sp, [sp, CPU_EXC_VECTORS]			// Get exception vector table
	ldr		pc, [sp, #0x1C]						// Branch to exception handler
#else /* ! __ARM_TIME__ */
	.long	0x0
	.long	0x0
	.long	0x0
	.long	0x0
#endif /* __ARM_TIME__ */

	.fill   984, 4, 0						// Push to the 4KB page boundary

    .globl EXT(ExceptionVectorsEnd)
LEXT(ExceptionVectorsEnd)	


/*
 * Targets for the exception vectors; we patch these during boot (to allow
 * for position independent code without complicating the vectors; see start.s).
 */
	.globl EXT(ExceptionVectorsTable)
LEXT(ExceptionVectorsTable)	
Lreset_vector:
	.long	0x0
Lundefined_inst_vector:
	.long	0x0
Lswi_vector:
	.long	0x0
Lprefetch_abort_vector:
	.long	0x0
Ldata_abort_vector:
	.long	0x0
Laddress_exception_vector:
	.long	0x0
Lirq_vector:
	.long	0x0
Ldecirq_vector:
	.long	0x0


/*
 *	First Level Exception Handlers
 */
	.text
	.align 2
	.globl EXT(fleh_reset)
LEXT(fleh_reset)
	b		.									// Never return

/*
 *	First Level Exception Handler for Undefined Instruction.
 */
	.text
	.align 2
	.globl EXT(fleh_undef)

/*
 *	Ensures the stack is safely aligned, usually in preparation for an external branch
 *	arg0: temp register for storing the stack offset
 *	arg1: temp register for storing the previous stack pointer
 */
.macro ALIGN_STACK
/*
 * For armv7k ABI, the stack needs to be 16-byte aligned
 */
#if __BIGGEST_ALIGNMENT__ > 4
	and		$0, sp, #0x0F						// sp mod 16-bytes
	cmp		$0, #4							// need space for the sp on the stack
	addlt		$0, $0, #0x10						// make room if needed, but keep stack aligned
	mov		$1, sp							// get current sp
	sub		sp, sp, $0						// align stack
	str		$1, [sp]						// store previous sp on stack
#endif
.endmacro

/*
 *	Restores the stack pointer to its previous value following an ALIGN_STACK call
 */
.macro UNALIGN_STACK
#if __BIGGEST_ALIGNMENT__ > 4
	ldr		sp, [sp]
#endif
.endmacro

/*
 *	Checks that cpu is currently in the expected mode, panics if not.
 *	arg0: the expected mode, should be one of the PSR_*_MODE defines
 */
.macro VERIFY_EXCEPTION_MODE
	mrs		sp, cpsr 							// Read cpsr
	and		sp, sp, #PSR_MODE_MASK					// Extract current mode
	cmp		sp, $0							// Check specified mode
	movne		r0, sp
	bne		EXT(ExceptionVectorPanic)
.endmacro

/*
 *	Checks previous processor mode.  If usermode, will execute the code
 *	following the macro to handle the userspace exception.  Otherwise,
 *	will branch to a ELSE_IF_KERNELMODE_EXCEPTION call with the same
 *	argument.
 *	arg0: arbitrary string indicating the exception class, e.g. 'dataabt'
 */ 
.macro IF_USERMODE_EXCEPTION
	mrs		sp, spsr
	and		sp, sp, #PSR_MODE_MASK						// Is it from user?
	cmp		sp, #PSR_USER_MODE
	beq		$0_from_user
	cmp		sp, #PSR_IRQ_MODE
	beq		$0_from_irq
	cmp		sp, #PSR_FIQ_MODE
	beq		$0_from_fiq
	bne		$0_from_svc
$0_from_user:
.endmacro

/*
 *	Handles an exception taken from kernelmode (IRQ/FIQ/SVC/etc).
 *	Places the processor into the correct mode and executes the
 *	code following the macro to handle the kernel exception.
 *	Intended to be paired with a prior call to IF_USERMODE_EXCEPTION.
 *	arg0: arbitrary string indicating the exception class, e.g. 'dataabt'
 */
.macro ELSE_IF_KERNELMODE_EXCEPTION
$0_from_irq:
	cpsid		i, #PSR_IRQ_MODE
	b		$0_from_kernel
$0_from_fiq:
	cpsid		i, #PSR_FIQ_MODE
	b		$0_from_kernel
$0_from_svc:
	cpsid		i, #PSR_SVC_MODE
$0_from_kernel:
.endmacro

LEXT(fleh_undef)
VERIFY_EXCEPTION_MODE PSR_UND_MODE
	mrs		sp, spsr							// For check the previous mode
	tst		sp, #PSR_TF							// Is it Thumb?
	subeq		lr, lr, #4
	subne		lr, lr, #2
IF_USERMODE_EXCEPTION undef
	mrc		p15, 0, sp, c13, c0, 4				// Read TPIDRPRW
	add		sp, sp, ACT_PCBDATA				// Get current thread PCB pointer

	stmia	sp, {r0-r12, sp, lr}^				// Save user context on PCB
	mov		r7, #0								// Zero the frame pointer
	nop

	mov		r0, sp								// Store arm_saved_state pointer 
												//  for argument

	str		lr, [sp, SS_PC]						// Save user mode pc register

	mrs		r4, spsr
	str		r4, [sp, SS_CPSR]					// Save user mode cpsr

	cpsid i, #PSR_SVC_MODE
	mrs		r3, cpsr 							// Read cpsr
	msr		spsr_cxsf, r3                       // Set spsr(svc mode cpsr)
	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW
	ldr		sp, [r9, TH_KSTACKPTR]				// Load kernel stack
#if __ARM_USER_PROTECT__
	ldr		r3, [r9, ACT_KPTW_TTB]				// Load kernel ttb
	mcr		p15, 0, r3, c2, c0, 0				// Set TTBR0
	mov		r3, #0								// Load kernel asid
	mcr		p15, 0, r3, c13, c0, 1				// Set CONTEXTIDR
	isb
#endif

	mvn		r0, #0
	str		r0, [r9, TH_IOTIER_OVERRIDE]			// Reset IO tier override to -1 before handling abort from userspace

#if	!CONFIG_SKIP_PRECISE_USER_KERNEL_TIME
	bl		EXT(timer_state_event_user_to_kernel)
	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW
#endif

#if __ARM_VFP__
	add		r0, r9, ACT_UVFP				// Get the address of the user VFP save area
	bl		EXT(vfp_save)					// Save the current VFP state to ACT_UVFP
	mov		r3, #FPSCR_DEFAULT				// Load up the default FPSCR value...
	fmxr		fpscr, r3					// And shove it into FPSCR
	add		r1, r9, ACT_UVFP				// Reload the pointer to the save state
	add		r0, r9, ACT_PCBDATA				// Reload the VFP save state argument
#else
	mov		r1, #0                              		// Clear the VFP save state argument
	add		r0, r9, ACT_PCBDATA					// Reload arm_saved_state pointer
#endif

	bl		EXT(sleh_undef)						// Call second level handler
												//   sleh will enable interrupt
	b		load_and_go_user

ELSE_IF_KERNELMODE_EXCEPTION undef
	/*
	 * We have a kernel stack already, and I will use it to save contexts
	 * IRQ is disabled
	 */
#if CONFIG_DTRACE
	// We need a frame for backtracing. The LR here is the LR of supervisor mode, not the location where the exception
	// took place. We'll store that later after we switch to undef mode and pull out the LR from there.

	// This frame is consumed by fbt_invop. Any changes with the size or location of this frame will probably require
	// changes in fbt_invop also.
	stmfd sp!, { r7, lr }
#endif

	sub		sp, sp, EXC_CTX_SIZE						// Reserve for arm_saved_state

	stmia	sp, {r0-r12}						// Save on supervisor mode stack
	str		lr, [sp, SS_LR]
	
#if CONFIG_DTRACE
	add		r7, sp, EXC_CTX_SIZE						// Save frame pointer
#endif

	mrs		r4, lr_und
	str		r4, [sp, SS_PC]						// Save complete
	mrs		r4, spsr_und
	str		r4, [sp, SS_CPSR]	

	mov		ip, sp

/*
   sp - stack pointer
   ip - stack pointer
   r7 - frame pointer state
 */


#if CONFIG_DTRACE
	ldr		r0, [ip, SS_PC]						// Get the exception pc to store later
#endif

	add		ip, ip, EXC_CTX_SIZE						// Send stack pointer to debugger
#if CONFIG_DTRACE
	str		r0, [ip, #4]
	add		ip, ip, #8
#endif
	str		ip, [sp, SS_SP]						// for accessing local variable
#if CONFIG_DTRACE
	sub		ip, ip, #8
#endif
	sub		ip, ip, EXC_CTX_SIZE

#if __ARM_VFP__
	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW
	add		r0, sp, SS_SIZE					// Get vfp state pointer
	bic		r0, #(VSS_ALIGN_NUM - 1)			// Align to arm_vfpsaved_state alignment
	add		r0, VSS_ALIGN					// Get the actual vfp save area
	mov		r5, r0						// Stash the save area in another register
	bl		EXT(vfp_save)					// Save the current VFP state to the stack
	mov		r1, r5						// Load the VFP save area argument 
	mov		r4, #FPSCR_DEFAULT				// Load up the default FPSCR value...
	fmxr		fpscr, r4					// And shove it into FPSCR
#else
	mov     r1, #0                              // Clear the facility context argument
#endif
#if __ARM_USER_PROTECT__
	mrc		p15, 0, r10, c2, c0, 0				// Get TTBR0
	ldr		r3, [r9, ACT_KPTW_TTB]				// Load kernel ttb
	cmp		r3, r10
	beq		1f
	mcr		p15, 0, r3, c2, c0, 0				// Set TTBR0
1:
	mrc		p15, 0, r11, c13, c0, 1				// Save CONTEXTIDR
	mov		r3, #0								// Load kernel asid
	mcr		p15, 0, r3, c13, c0, 1				// Set CONTEXTIDR
	isb
#endif
	mov		r0, sp								// Argument

	ALIGN_STACK r2, r3
	bl		EXT(sleh_undef)						// Call second level handler
	UNALIGN_STACK

#if __ARM_USER_PROTECT__
	mrc		p15, 0, r9, c13, c0, 4              // Read TPIDRPRW
	ldr		r0, [r9, ACT_KPTW_TTB]              // Load kernel ttb
	cmp		r10, r0
	beq		1f
	ldr		r10, [r9, ACT_UPTW_TTB]             // Load thread ttb
	cmp		r10, r0
	beq		1f
	mcr		p15, 0, r10, c2, c0, 0              // Set TTBR0
	ldr		r11, [r9, ACT_ASID]                 // Load thread asid
1:
	mcr		p15, 0, r11, c13, c0, 1             // set CONTEXTIDR
	isb
#endif
	b		load_and_go_sys


/*
 * First Level Exception Handler for Software Interrupt
 *
 *	We assert that only user level can use the "SWI" instruction for a system
 *	call on development kernels, and assume it's true on release.
 *
 *	System call number is stored in r12.
 *	System call arguments are stored in r0 to r6 and r8 (we skip r7)
 *
 */
	.text
	.align 5
	.globl EXT(fleh_swi)

LEXT(fleh_swi)
	cpsid	i, #PSR_ABT_MODE
	mov		sp, ip								// Save ip
	cpsid	i, #PSR_SVC_MODE
	mrs		ip, spsr							// Check the previous mode
	tst		ip, #0x0f
	cpsid	i, #PSR_ABT_MODE
	mov		ip, sp								// Restore ip
	cpsid	i, #PSR_SVC_MODE
	beq		swi_from_user

/* Only user mode can use SWI. Panic if the kernel tries. */
swi_from_kernel:
	sub     sp, sp, EXC_CTX_SIZE
	stmia	sp, {r0-r12}
	add		r0, sp, EXC_CTX_SIZE

	str		r0, [sp, SS_SP]						// Save supervisor mode sp
	str		lr, [sp, SS_LR]                     // Save supervisor mode lr

	ALIGN_STACK r0, r1
	adr		r0, L_kernel_swi_panic_str			// Load panic messages and panic()
	blx		EXT(panic)
	b		.

swi_from_user:
	mrc		p15, 0, sp, c13, c0, 4				// Read TPIDRPRW
	add		sp, sp, ACT_PCBDATA					// Get User PCB


	/* Check for special mach_absolute_time trap value.
	 * This is intended to be a super-lightweight call to ml_get_timebase(), which
	 * is handrolled assembly and does not use the stack, thus not requiring us to setup a kernel stack. */
	cmp		r12, #-3
	beq		fleh_swi_trap_tb
	stmia	sp, {r0-r12, sp, lr}^				// Save user context on PCB
	mov		r7, #0								// Zero the frame pointer
	nop
	mov		r8, sp								// Store arm_saved_state pointer
	add		sp, sp, SS_PC
	srsia sp, 	#PSR_SVC_MODE
	mrs		r3, cpsr 							// Read cpsr
	msr		spsr_cxsf, r3                       // Set spsr(svc mode cpsr)
	sub		r9, sp, ACT_PCBDATA_PC

	ldr		sp, [r9, TH_KSTACKPTR]				// Load kernel stack
	mov		r11, r12							// save the syscall vector in a nontrashed register

#if __ARM_VFP__
	add		r0, r9, ACT_UVFP				// Get the address of the user VFP save area
	bl		EXT(vfp_save)					// Save the current VFP state to ACT_UVFP
	mov		r4, #FPSCR_DEFAULT				// Load up the default FPSCR value...
	fmxr		fpscr, r4					// And shove it into FPSCR
#endif
#if __ARM_USER_PROTECT__
	ldr		r3, [r9, ACT_KPTW_TTB]				// Load kernel ttb
	mcr		p15, 0, r3, c2, c0, 0				// Set TTBR0
	mov		r3, #0								// Load kernel asid
	mcr		p15, 0, r3, c13, c0, 1				// Set CONTEXTIDR
	isb
#endif

	mvn		r0, #0
	str		r0, [r9, TH_IOTIER_OVERRIDE]			// Reset IO tier override to -1 before handling SWI from userspace

#if	!CONFIG_SKIP_PRECISE_USER_KERNEL_TIME
	bl		EXT(timer_state_event_user_to_kernel)
	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW
	add		r8, r9, ACT_PCBDATA					// Reload arm_saved_state pointer
#endif
	ldr		r10, [r9, ACT_TASK]					// Load the current task

	/* enable interrupts */
	cpsie	i									// Enable IRQ

	cmp		r11, #-4					// Special value for mach_continuous_time
	beq		fleh_swi_trap_mct

	cmp		r11, #0x80000000
	beq		fleh_swi_trap
fleh_swi_trap_ret:

#if TRACE_SYSCALL
	/* trace the syscall */
	mov		r0, r8
	bl		EXT(syscall_trace)
#endif

	bl		EXT(mach_kauth_cred_uthread_update)
	mrc		p15, 0, r9, c13, c0, 4				// Reload r9 from TPIDRPRW
	/* unix syscall? */
	rsbs	r5, r11, #0							// make the syscall positive (if negative)
	ble		fleh_swi_unix						// positive syscalls are unix (note reverse logic here)

fleh_swi_mach:
	/* note that mach_syscall_trace can modify r9, so increment the thread
	 * syscall count before the call : */
	ldr		r2, [r9, TH_MACH_SYSCALLS]
	add		r2, r2, #1
	str		r2, [r9, TH_MACH_SYSCALLS]

	LOAD_ADDR(r1, mach_trap_table)				// load mach_trap_table
#if MACH_TRAP_TABLE_ENTRY_SIZE_NUM == 12
	add		r11, r5, r5, lsl #1					// syscall * 3
	add		r6, r1, r11, lsl #2					// trap_table + syscall * 12
#elif MACH_TRAP_TABLE_ENTRY_SIZE_NUM == 16
	add		r6, r1, r5, lsl #4					// trap_table + syscall * 16
#elif MACH_TRAP_TABLE_ENTRY_SIZE_NUM == 20
	add		r11, r5, r5, lsl #2					// syscall * 5
	add		r6, r1, r11, lsl #2					// trap_table + syscall * 20
#else
#error mach_trap_t size unhandled (see MACH_TRAP_TABLE_ENTRY_SIZE)!
#endif

#ifndef	NO_KDEBUG
	LOAD_ADDR(r4, kdebug_enable)
	ldr		r4, [r4]
	movs	r4, r4
	movne	r0, r8								// ready the reg state pointer as an arg to the call
	movne	r1, r5								// syscall number as 2nd arg
	COND_EXTERN_BLNE(mach_syscall_trace)
#endif
	adr		lr,	fleh_swi_exit					// any calls from here on out will return to our exit path
	cmp		r5, MACH_TRAP_TABLE_COUNT			// check syscall number range
	bge		fleh_swi_mach_error

/* 
 * For arm32 ABI where 64-bit types are aligned to even registers and
 * 64-bits on stack, we need to unpack registers differently. So
 * we use the mungers for marshalling in arguments from user space.
 * Currently this is just ARMv7k.
 */
#if __BIGGEST_ALIGNMENT__ > 4
	sub		sp, #0x40						// allocate buffer and keep stack 128-bit aligned
	                                            				//     it should be big enough for all syscall arguments
	ldr		r11, [r6, #8]						// get mach_trap_table[call_number].mach_trap_arg_munge32
	teq		r11, #0							// check if we have a munger
	moveq		r0, #0
	movne		r0, r8							// ready the reg state pointer as an arg to the call
	movne		r1, sp							// stack will hold arguments buffer
	blxne		r11							// call munger to get arguments from userspace
	adr		lr,	fleh_swi_exit					// any calls from here on out will return to our exit path
	teq		r0, #0
	bne		fleh_swi_mach_error					// exit if the munger returned non-zero status
#endif

	ldr		r1, [r6, #4]						// load the syscall vector

	LOAD_ADDR(r2, kern_invalid)					// test to make sure the trap is not kern_invalid
	teq		r1, r2
	beq		fleh_swi_mach_error

#if __BIGGEST_ALIGNMENT__ > 4
	mov		r0, sp								// argument buffer on stack
	bx		r1									// call the syscall handler
#else
	mov		r0, r8								// ready the reg state pointer as an arg to the call
	bx		r1									// call the syscall handler
#endif

fleh_swi_exit64:
	str		r1, [r8, #4]						// top of 64-bit return
fleh_swi_exit:
	str		r0, [r8]							// save the return value
#ifndef	NO_KDEBUG
	movs	r4, r4
	movne	r1, r5
	COND_EXTERN_BLNE(mach_syscall_trace_exit)
#endif
#if TRACE_SYSCALL
	bl		EXT(syscall_trace_exit)
#endif

	mov		r0, #1
	bl		EXT(throttle_lowpri_io)				// throttle_lowpri_io(1);

	bl		EXT(thread_exception_return)
	b		.

fleh_swi_mach_error:
	mov		r0, #EXC_SYSCALL
	sub		r1, sp, #4
	mov		r2, #1
	bl		EXT(exception_triage)
	b		.

	.align	5
fleh_swi_unix:
	ldr		r1, [r9, TH_UNIX_SYSCALLS]
	mov		r0, r8								// reg state structure is arg
	add		r1, r1, #1
	str		r1, [r9, TH_UNIX_SYSCALLS]
	mov		r1, r9								// current thread in arg1
	ldr		r2, [r9, TH_UTHREAD]				// current uthread in arg2
	ldr		r3, [r10, TASK_BSD_INFO]			// current proc in arg3
	bl		EXT(unix_syscall)
	b		.

fleh_swi_trap:
	ldmia		r8, {r0-r3}
	cmp		r3, #3
	addls	pc, pc, r3, LSL#2
	b		fleh_swi_trap_ret
	b		icache_invalidate_trap
	b		dcache_flush_trap
	b		thread_set_cthread_trap
	b		thread_get_cthread_trap

icache_invalidate_trap:
	add		r3, r0, r1
	cmp		r3, VM_MAX_ADDRESS
	subhi	r3, r3, #1<<MMU_CLINE
	bhi		cache_trap_error
	adr		r11, cache_trap_jmp	
	ldr		r6,  [r9, TH_RECOVER]				// Save existing recovery routine
	str		r11, [r9, TH_RECOVER] 
#if __ARM_USER_PROTECT__
	ldr     r5, [r9, ACT_UPTW_TTB]				// Load thread ttb
	mcr		p15, 0, r5, c2, c0, 0				// Set TTBR0
	ldr     r5, [r9, ACT_ASID]					// Load thread asid
	mcr		p15, 0, r5, c13, c0, 1				// Set CONTEXTIDR
	dsb		ish
	isb
#endif
	mov		r4, r0
	mov		r5, r1
	bl		EXT(CleanPoU_DcacheRegion)
	mov		r0, r4
	mov		r1, r5
	bl		EXT(InvalidatePoU_IcacheRegion)
	mrc		p15, 0, r9, c13, c0, 4				// Reload r9 from TPIDRPRW
#if __ARM_USER_PROTECT__
	ldr		r4, [r9, ACT_KPTW_TTB]				// Load kernel ttb
	mcr		p15, 0, r4, c2, c0, 0				// Set TTBR0
	mov		r4, #0								// Load kernel asid
	mcr		p15, 0, r4, c13, c0, 1				// Set CONTEXTIDR
	isb
#endif
	str		r6, [r9, TH_RECOVER]
	bl		EXT(thread_exception_return)
	b		.

dcache_flush_trap:
	add		r3, r0, r1
	cmp		r3, VM_MAX_ADDRESS
	subhi	r3, r3, #1<<MMU_CLINE
	bhi		cache_trap_error
	adr		r11, cache_trap_jmp	
	ldr		r4,  [r9, TH_RECOVER]				// Save existing recovery routine
	str		r11, [r9, TH_RECOVER] 
#if __ARM_USER_PROTECT__
	ldr     r6, [r9, ACT_UPTW_TTB]              // Load thread ttb
	mcr		p15, 0, r6, c2, c0, 0				// Set TTBR0
	ldr     r5, [r9, ACT_ASID]					// Load thread asid
	mcr		p15, 0, r5, c13, c0, 1				// Set CONTEXTIDR
	isb
#endif
	bl		EXT(flush_dcache_syscall)
	mrc		p15, 0, r9, c13, c0, 4				// Reload r9 from TPIDRPRW
#if __ARM_USER_PROTECT__
	ldr		r5, [r9, ACT_KPTW_TTB]				// Load kernel ttb
	mcr		p15, 0, r5, c2, c0, 0				// Set TTBR0
	mov		r5, #0								// Load kernel asid
	mcr		p15, 0, r5, c13, c0, 1				// Set CONTEXTIDR
	isb
#endif
	str		r4, [r9, TH_RECOVER]
	bl		EXT(thread_exception_return)
	b		.

thread_set_cthread_trap:
	bl		EXT(thread_set_cthread_self)
	bl		EXT(thread_exception_return)
	b		.

thread_get_cthread_trap:
	bl		EXT(thread_get_cthread_self)
	mrc		p15, 0, r9, c13, c0, 4				// Reload r9 from TPIDRPRW
	add		r1, r9, ACT_PCBDATA					// Get User PCB
	str		r0, [r1, SS_R0]						// set return value
	bl		EXT(thread_exception_return)
	b		.

cache_trap_jmp:
#if __ARM_USER_PROTECT__
	mrc		p15, 0, r9, c13, c0, 4				// Reload r9 from TPIDRPRW
	ldr		r5, [r9, ACT_KPTW_TTB]				// Load kernel ttb
	mcr		p15, 0, r5, c2, c0, 0				// Set TTBR0
	mov		r5, #0								// Load kernel asid
	mcr		p15, 0, r5, c13, c0, 1				// Set CONTEXTIDR
	isb
#endif
	mrc		p15, 0, r3, c6, c0 					// Read Fault Address
cache_trap_error:
	mrc		p15, 0, r9, c13, c0, 4				// Reload r9 from TPIDRPRW
	add		r0, r9, ACT_PCBDATA					// Get User PCB
	ldr		r1, [r0, SS_PC]						// Save user mode pc register as pc
	sub		r1, r1, #4							// Backtrack current pc
	str		r1, [r0, SS_PC]						// pc at cache assist swi
	str		r3, [r0, SS_VADDR]					// Fault Address
	mov		r0, #EXC_BAD_ACCESS
	mov		r2, KERN_INVALID_ADDRESS
	sub		sp, sp, #8
	mov		r1, sp
	str		r2, [sp]
	str		r3, [sp, #4]
	ALIGN_STACK r2, r3
	mov		r2, #2
	bl		EXT(exception_triage)
	b		.

fleh_swi_trap_mct:
	bl 		EXT(mach_continuous_time)
	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW
	add		r9, r9, ACT_PCBDATA_R0				// Get User register state
	stmia		r9, {r0, r1}					// set 64-bit return value
	bl		EXT(thread_exception_return)
	b		.

fleh_swi_trap_tb:
	str		lr, [sp, SS_PC]
	bl		EXT(ml_get_timebase)				// ml_get_timebase() (64-bit return)
	ldr		lr, [sp, SS_PC]
	nop
	movs	pc, lr								// Return to user

	.align  2
L_kernel_swi_panic_str:
	.asciz  "fleh_swi: took SWI from kernel mode\n"
	.align	2

/*
 * First Level Exception Handler for Prefetching Abort.
 */
	.text
	.align 2
	.globl EXT(fleh_prefabt)
	
LEXT(fleh_prefabt)
VERIFY_EXCEPTION_MODE PSR_ABT_MODE
	sub		lr, lr, #4

IF_USERMODE_EXCEPTION prefabt
	mrc		p15, 0, sp, c13, c0, 4				// Read TPIDRPRW
	add		sp, sp, ACT_PCBDATA					// Get User PCB

	stmia   sp, {r0-r12, sp, lr}^				// Save user context on PCB
	mov		r7, #0								// Zero the frame pointer
	nop
	mov     r0, sp								// Store arm_saved_state pointer 
												// For argument
	str		lr, [sp, SS_PC]						// Save user mode pc register as pc
	mrc		p15, 0, r1, c6, c0, 2 				// Read IFAR
	str		r1, [sp, SS_VADDR]					// and fault address of pcb

	mrc		p15, 0, r5, c5, c0, 1 				// Read Fault Status
	str		r5, [sp, SS_STATUS]					// Save fault status register to pcb

	mrs     r4, spsr
	str     r4, [sp, SS_CPSR]					// Save user mode cpsr

	cpsid	i, #PSR_SVC_MODE
	mrs		r3, cpsr 							// Read cpsr
	msr		spsr_cxsf, r3                       // Set spsr(svc mode cpsr)
	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW
	ldr		sp, [r9, TH_KSTACKPTR]				// Load kernel stack

#if __ARM_VFP__
	add		r0, r9, ACT_UVFP				// Get the address of the user VFP save area
	bl		EXT(vfp_save)					// Save the current VFP state to ACT_UVFP
	mov		r3, #FPSCR_DEFAULT				// Load up the default FPSCR value...
	fmxr		fpscr, r3					// And shove it into FPSCR
#endif
#if __ARM_USER_PROTECT__
	ldr		r3, [r9, ACT_KPTW_TTB]				// Load kernel ttb
	mcr		p15, 0, r3, c2, c0, 0				// Set TTBR0
	mov		r3, #0								// Load kernel asid
	mcr		p15, 0, r3, c13, c0, 1				// Set CONTEXTIDR
	isb
#endif

	mvn		r0, #0
	str		r0, [r9, TH_IOTIER_OVERRIDE]			// Reset IO tier override to -1 before handling abort from userspace

#if	!CONFIG_SKIP_PRECISE_USER_KERNEL_TIME
	bl		EXT(timer_state_event_user_to_kernel)
	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW
#endif

	add		r0, r9, ACT_PCBDATA					// Reload arm_saved_state pointer
	mov		r1, T_PREFETCH_ABT					// Pass abort type
	bl		EXT(sleh_abort)						// Call second level handler
												// Sleh will enable interrupt
	b		load_and_go_user

ELSE_IF_KERNELMODE_EXCEPTION prefabt
	/*
	 * We have a kernel stack already, and I will use it to save contexts:
	 *     ------------------
	 *    | VFP saved state  |
	 *    |------------------|
	 *    | ARM saved state  |
	 * SP  ------------------
	 *
	 * IRQ is disabled
	 */
	sub     sp, sp, EXC_CTX_SIZE
	stmia	sp, {r0-r12}
	add		r0, sp, EXC_CTX_SIZE

	str		r0, [sp, SS_SP]						// Save supervisor mode sp
	str		lr, [sp, SS_LR]                     // Save supervisor mode lr

	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW

#if __ARM_VFP__
	add		r0, sp, SS_SIZE					// Get vfp state pointer
	bic		r0, #(VSS_ALIGN_NUM - 1)			// Align to arm_vfpsaved_state alignment
	add		r0, VSS_ALIGN					// Get the actual vfp save area
	bl		EXT(vfp_save)					// Save the current VFP state to the stack 
	mov		r4, #FPSCR_DEFAULT				// Load up the default FPSCR value...
	fmxr		fpscr, r4					// And shove it into FPSCR
#endif
#if __ARM_USER_PROTECT__
	mrc		p15, 0, r10, c2, c0, 0				// Get TTBR0
	ldr		r3, [r9, ACT_KPTW_TTB]				// Load kernel ttb
	cmp		r3, r10
	beq		1f
	mcr		p15, 0, r3, c2, c0, 0				// Set TTBR0
1:
	mrc		p15, 0, r11, c13, c0, 1				// Save CONTEXTIDR
	mov		r3, #0								// Load kernel asid
	mcr		p15, 0, r3, c13, c0, 1				// Set CONTEXTIDR
	isb
#endif

	mrs		r4, lr_abt
	str		r4, [sp, SS_PC]					// Save pc

	mrc		p15, 0, r5, c6, c0, 2 				// Read IFAR
	str		r5, [sp, SS_VADDR]					// and fault address of pcb
	mrc		p15, 0, r5, c5, c0, 1 				// Read (instruction) Fault Status
	str		r5, [sp, SS_STATUS]					// Save fault status register to pcb

	mrs		r4, spsr_abt
	str		r4, [sp, SS_CPSR]	

	mov		r0, sp
	ALIGN_STACK r1, r2
	mov		r1, T_PREFETCH_ABT					// Pass abort type
	bl		EXT(sleh_abort) 					// Call second level handler
	UNALIGN_STACK

	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW
#if __ARM_USER_PROTECT__
	ldr		r0, [r9, ACT_KPTW_TTB]              // Load kernel ttb
	cmp		r10, r0
	beq		1f
	ldr		r10, [r9, ACT_UPTW_TTB]             // Load thread ttb
	cmp		r10, r0
	beq		1f
	mcr		p15, 0, r10, c2, c0, 0              // Set TTBR0
	ldr		r11, [r9, ACT_ASID]                 // Load thread asid
1:
	mcr		p15, 0, r11, c13, c0, 1             // set CONTEXTIDR
	isb
#endif

	b		load_and_go_sys


/*
 * First Level Exception Handler for Data Abort
 */
	.text
	.align 2
	.globl EXT(fleh_dataabt)
	
LEXT(fleh_dataabt)
VERIFY_EXCEPTION_MODE PSR_ABT_MODE
	sub		lr, lr, #8
IF_USERMODE_EXCEPTION dataabt
	mrc		p15, 0, sp, c13, c0, 4				// Read TPIDRPRW
	add		sp, sp, ACT_PCBDATA					// Get User PCB

	stmia	sp, {r0-r12, sp, lr}^				// Save user context on PCB
	mov		r7, #0								// Zero the frame pointer
	nop
		
	mov		r0, sp								// Store arm_saved_state pointer 
												// For argument

	str		lr, [sp, SS_PC]						// Save user mode pc register

	mrs		r4, spsr
	str		r4, [sp, SS_CPSR]					// Save user mode cpsr

	mrc		p15, 0, r5, c5, c0 					// Read Fault Status
	mrc		p15, 0, r6, c6, c0 					// Read Fault Address
	str		r5, [sp, SS_STATUS]					// Save fault status register to pcb
	str		r6, [sp, SS_VADDR]					// Save fault address to pcb

	cpsid	i, #PSR_SVC_MODE
	mrs		r3, cpsr 							// Read cpsr
	msr		spsr_cxsf, r3                       // Set spsr(svc mode cpsr)
	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW
	ldr		sp, [r9, TH_KSTACKPTR]				// Load kernel stack

#if __ARM_VFP__
	add		r0, r9, ACT_UVFP				// Get the address of the user VFP save area
	bl		EXT(vfp_save)					// Save the current VFP state to ACT_UVFP
	mov		r3, #FPSCR_DEFAULT				// Load up the default FPSCR value...
	fmxr		fpscr, r3					// And shove it into FPSCR
#endif
#if __ARM_USER_PROTECT__
	ldr		r3, [r9, ACT_KPTW_TTB]				// Load kernel ttb
	mcr		p15, 0, r3, c2, c0, 0				// Set TTBR0
	mov		r3, #0								// Load kernel asid
	mcr		p15, 0, r3, c13, c0, 1				// Set CONTEXTIDR
	isb
#endif

	mvn		r0, #0
	str		r0, [r9, TH_IOTIER_OVERRIDE]			// Reset IO tier override to -1 before handling abort from userspace

#if	!CONFIG_SKIP_PRECISE_USER_KERNEL_TIME
	bl		EXT(timer_state_event_user_to_kernel)
	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW
#endif

	add		r0, r9, ACT_PCBDATA					// Reload arm_saved_state pointer
	mov     r1, T_DATA_ABT						// Pass abort type
	bl		EXT(sleh_abort)						// Call second level handler
												// Sleh will enable irq
	b		load_and_go_user

ELSE_IF_KERNELMODE_EXCEPTION dataabt
	/*
	 * We have a kernel stack already, and I will use it to save contexts:
	 *     ------------------
	 *    | VFP saved state  |
	 *    |------------------|
	 *    | ARM saved state  |
	 * SP  ------------------
	 *
	 * IRQ is disabled
	 */
	sub     sp, sp, EXC_CTX_SIZE
	stmia	sp, {r0-r12}
	add		r0, sp, EXC_CTX_SIZE

	str		r0, [sp, SS_SP]						// Save supervisor mode sp
	str		lr, [sp, SS_LR]                     // Save supervisor mode lr

	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW

#if __ARM_VFP__
	add		r0, sp, SS_SIZE					// Get vfp state pointer
	bic		r0, #(VSS_ALIGN_NUM - 1)			// Align to arm_vfpsaved_state alignment
	add		r0, VSS_ALIGN					// Get the actual vfp save area
	bl		EXT(vfp_save)					// Save the current VFP state to the stack 
	mov		r4, #FPSCR_DEFAULT				// Load up the default FPSCR value...
	fmxr		fpscr, r4					// And shove it into FPSCR
#endif

	mrs		r4, lr_abt
	str		r4, [sp, SS_PC]
	mrs		r4, spsr_abt
	str		r4, [sp, SS_CPSR]	

#if __ARM_USER_PROTECT__
	mrc		p15, 0, r10, c2, c0, 0				// Get TTBR0
	ldr		r3, [r9, ACT_KPTW_TTB]				// Load kernel ttb
	cmp		r3, r10
	beq		1f
	mcr		p15, 0, r3, c2, c0, 0				// Set TTBR0
1:
	mrc		p15, 0, r11, c13, c0, 1				// Save CONTEXTIDR
	mov		r3, #0								// Load kernel asid
	mcr		p15, 0, r3, c13, c0, 1				// Set CONTEXTIDR
	isb
#endif
	mrc		p15, 0, r5, c5, c0					// Read Fault Status
	mrc		p15, 0, r6, c6, c0					// Read Fault Address
	str		r5, [sp, SS_STATUS]					// Save fault status register to pcb
	str		r6, [sp, SS_VADDR]					// Save fault address to pcb

	mov		r0, sp								// Argument
	ALIGN_STACK r1, r2
	mov		r1, T_DATA_ABT						// Pass abort type
	bl		EXT(sleh_abort)						// Call second level handler
	UNALIGN_STACK

	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW
#if __ARM_USER_PROTECT__
	ldr		r0, [r9, ACT_KPTW_TTB]              // Load kernel ttb
	cmp		r10, r0
	beq		1f
	ldr		r10, [r9, ACT_UPTW_TTB]             // Load thread ttb
	cmp		r10, r0
	beq		1f
	mcr		p15, 0, r10, c2, c0, 0              // Set TTBR0
	ldr		r11, [r9, ACT_ASID]                 // Load thread asid
1:
	mcr		p15, 0, r11, c13, c0, 1             // set CONTEXTIDR
	isb
#endif

load_and_go_sys:	
	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW

	ldr		r4, [sp, SS_CPSR]					// Load saved cpsr
	tst		r4, #PSR_IRQF						// Test IRQ set
	bne		lags1								// Branch if IRQ disabled

	cpsid	i									// Disable IRQ
	ldr		r2, [r9, ACT_PREEMPT_CNT]           // Load preemption count
	movs	r2, r2								// Test if null
	ldr		r8, [r9, ACT_CPUDATAP]				// Get current cpu
	bne		lags1								// Branch if count not null
	ldr		r5, [r8, CPU_PENDING_AST]			// Get ASTs
	ands	r5, r5, AST_URGENT					// Get the requests we do honor
	beq		lags1								// Branch if no ASTs
#if __ARM_USER_PROTECT__
	mrc		p15, 0, r10, c2, c0, 0				// Get TTBR0
	ldr		r3, [r9, ACT_KPTW_TTB]				// Load kernel ttb
	cmp		r3, r10
	beq		1f
	mcr		p15, 0, r3, c2, c0, 0				// Set TTBR0
1:
	mrc		p15, 0, r11, c13, c0, 1				// Save CONTEXTIDR
	mov		r3, #0								// Load kernel asid
	mcr		p15, 0, r3, c13, c0, 1				// Set CONTEXTIDR
	isb
#endif
	ldr		lr, [sp, SS_LR]							// Restore the link register
	stmfd		sp!, {r7, lr}							// Push a fake frame

	ALIGN_STACK r2, r3
	bl		EXT(ast_taken_kernel)				// Handle AST_URGENT
	UNALIGN_STACK

	ldmfd		sp!, {r7, lr}							// Pop the fake frame
	mrc		p15, 0, r9, c13, c0, 4				// Reload r9 from TPIDRPRW
	ldr		r8, [r9, ACT_CPUDATAP]				// Get current cpu
#if __ARM_USER_PROTECT__
	ldr		r0, [r9, ACT_KPTW_TTB]              // Load kernel ttb
	cmp		r10, r0
	beq		1f
	ldr		r10, [r9, ACT_UPTW_TTB]             // Load thread ttb
	cmp		r10, r0
	beq		1f
	mcr		p15, 0, r10, c2, c0, 0              // Set TTBR0
	ldr		r11, [r9, ACT_ASID]                 // Load thread asid
1:
	mcr		p15, 0, r11, c13, c0, 1             // set CONTEXTIDR
	isb
#endif
lags1:
	ldr		lr, [sp, SS_LR]

	mov		ip, sp                              // Save pointer to contexts for abort mode
	ldr		sp, [ip, SS_SP]                     // Restore stack pointer

	cpsid	if, #PSR_ABT_MODE

	mov		sp, ip

	ldr		r4, [sp, SS_CPSR]
	msr		spsr_cxsf, r4						// Restore spsr

	clrex										// clear exclusive memory tag
#if	__ARM_ENABLE_WFE_
	sev
#endif

#if __ARM_VFP__
	add		r0, sp, SS_SIZE					// Get vfp state pointer
	bic		r0, #(VSS_ALIGN_NUM - 1)			// Align to arm_vfpsaved_state alignment
	add		r0, VSS_ALIGN					// Get the actual vfp save area
	bl		EXT(vfp_load)					// Load the desired VFP state from the stack 
#endif

	ldr		lr, [sp, SS_PC]						// Restore lr

	ldmia	sp, {r0-r12}						// Restore other registers

	movs	pc, lr								// Return to sys (svc, irq, fiq)

/*
 * First Level Exception Handler for address exception
 * Not supported
 */
	.text
	.align 2
	.globl EXT(fleh_addrexc)

LEXT(fleh_addrexc)	
	b	.
	

/*
 * First Level Exception Handler for IRQ
 * Current mode : IRQ
 * IRQ and FIQ are always disabled while running in FIQ handler
 * We do not permit nested interrupt.
 * 
 * Saving area: from user   : PCB. 
 *		from kernel : interrupt stack.
 */

	.text
	.align 2
	.globl EXT(fleh_irq)

LEXT(fleh_irq)
	sub		lr, lr, #4
	
	cpsie	a									// Re-enable async aborts
	
	mrs		sp, spsr
	tst		sp, #0x0f							// From user? or kernel?
	bne		fleh_irq_kernel

fleh_irq_user:
	mrc		p15, 0, sp, c13, c0, 4				// Read TPIDRPRW
	add		sp, sp, ACT_PCBDATA					// Get User PCB
	stmia	sp, {r0-r12, sp, lr}^
	mov		r7, #0								// Zero the frame pointer
	nop
	str		lr, [sp, SS_PC]
	mrs		r4, spsr
	str		r4, [sp, SS_CPSR]
	mov		r5, sp								// Saved context in r5
	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW
	ldr		r6, [r9, ACT_CPUDATAP]				// Get current cpu
	ldr		sp,	[r6, CPU_ISTACKPTR]				// Set interrupt stack
	cpsid	i, #PSR_SVC_MODE
	ldr		sp, [r9, TH_KSTACKPTR]				// Set kernel stack
	cpsid	i, #PSR_IRQ_MODE

#if __ARM_VFP__
	add		r0, r9, ACT_UVFP				// Get the address of the user VFP save area
	bl		EXT(vfp_save)					// Save the current VFP state to ACT_UVFP
	mov		r4, #FPSCR_DEFAULT				// Load up the default FPSCR value...
	fmxr		fpscr, r4					// And shove it into FPSCR
#endif
#if __ARM_USER_PROTECT__
	ldr		r3, [r9, ACT_KPTW_TTB]				// Load kernel ttb
	mcr		p15, 0, r3, c2, c0, 0				// Set TTBR0
	mov		r3, #0								// Load kernel asid
	mcr		p15, 0, r3, c13, c0, 1				// Set CONTEXTIDR
	isb
#endif
#if	!CONFIG_SKIP_PRECISE_USER_KERNEL_TIME
	bl		EXT(timer_state_event_user_to_kernel)
	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW
#endif
#if CONFIG_TELEMETRY
	LOAD_ADDR(r2, telemetry_needs_record)		// Check if a telemetry record was requested...
	mov		r0, #1
	ldr		r2, [r2]
	movs	r2, r2
	beq		1f
	bl		EXT(telemetry_mark_curthread)		// ...if so, mark the current thread...
	mrc		p15, 0, r9, c13, c0, 4				// ...and restore the thread pointer from TPIDRPRW
1:
#endif

	b		fleh_irq_handler

fleh_irq_kernel:
	cpsid	i, #PSR_SVC_MODE

	sub     sp, sp, EXC_CTX_SIZE
	stmia	sp, {r0-r12}
	add		r0, sp, EXC_CTX_SIZE

	str		r0, [sp, SS_SP]						// Save supervisor mode sp
	str		lr, [sp, SS_LR]                     // Save supervisor mode lr

	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW

#if __ARM_VFP__
	add		r0, sp, SS_SIZE					// Get vfp state pointer
	bic		r0, #(VSS_ALIGN_NUM - 1)			// Align to arm_vfpsaved_state alignment
	add		r0, VSS_ALIGN					// Get the actual vfp save area
	bl		EXT(vfp_save)					// Save the current VFP state to the stack 
	mov		r4, #FPSCR_DEFAULT				// Load up the default FPSCR value...
	fmxr		fpscr, r4					// And shove it into FPSCR
#endif
#if __ARM_USER_PROTECT__
	mrc		p15, 0, r10, c2, c0, 0				// Get TTBR0
	ldr		r3, [r9, ACT_KPTW_TTB]				// Load kernel ttb
	mcr		p15, 0, r3, c2, c0, 0				// Set TTBR0
	mrc		p15, 0, r11, c13, c0, 1				// Get CONTEXTIDR
	mov		r3, #0								// Load kernel asid
	mcr		p15, 0, r3, c13, c0, 1				// Set CONTEXTIDR
	isb
#endif
	mov		r5, sp								// Saved context in r5

	cpsid	i, #PSR_IRQ_MODE

	str		lr, [r5, SS_PC]                     // Save LR as the return PC
	mrs		r4, spsr
	str		r4, [r5, SS_CPSR]                   // Save the cpsr of the interrupted mode

	ldr		sp, [r9, ACT_CPUDATAP]				// Get current cpu
	ldr		sp,	[sp, CPU_ISTACKPTR]				// Set interrupt stack

#if CONFIG_TELEMETRY
	LOAD_ADDR(r2, telemetry_needs_record)		// Check if a telemetry record was requested...
	mov		r0, #0
	ldr		r2, [r2]
	movs	r2, r2
	beq		1f
	bl		EXT(telemetry_mark_curthread)		// ...if so, mark the current thread...
	mrc		p15, 0, r9, c13, c0, 4				// ...and restore the thread pointer from TPIDRPRW
1:
#endif

fleh_irq_handler:
	ldr		r2, [r9, ACT_PREEMPT_CNT]           // Load preemption count
	add		r2, r2, #1							// Increment count
	str		r2, [r9, ACT_PREEMPT_CNT]			// Update preemption count
#ifndef	NO_KDEBUG
	LOAD_ADDR(r8, kdebug_enable)
	ldr		r8, [r8]
	movs	r8, r8
	movne	r0, r5
	COND_EXTERN_BLNE(interrupt_trace)
#endif
	bl	    EXT(interrupt_stats)                // Record interrupt statistics
	mrc		p15, 0, r9, c13, c0, 4				// Reload r9 from TPIDRPRW
	ldr		r4, [r9, ACT_CPUDATAP]				// Get current cpu
	str		r5, [r4, CPU_INT_STATE] 			// Saved context in cpu_int_state
	ldr		r3, [r4, CPU_STAT_IRQ]				// Get IRQ count
	add		r3, r3, #1					// Increment count
	str		r3, [r4, CPU_STAT_IRQ]				// Update  IRQ count
	ldr		r3, [r4, CPU_STAT_IRQ_WAKE]			// Get post-wake IRQ count
	add		r3, r3, #1					// Increment count
	str		r3, [r4, CPU_STAT_IRQ_WAKE]			// Update post-wake IRQ count
	ldr		r0, [r4, INTERRUPT_TARGET]
	ldr		r1, [r4, INTERRUPT_REFCON]
	ldr		r2, [r4, INTERRUPT_NUB]
	ldr		r3, [r4, INTERRUPT_SOURCE]
	ldr		r5, [r4, INTERRUPT_HANDLER]			//  Call second level exception handler
	blx		r5
#ifndef	NO_KDEBUG
	movs	r8, r8
	COND_EXTERN_BLNE(interrupt_trace_exit)
#endif
	mrc		p15, 0, r9, c13, c0, 4				// Reload r9 from TPIDRPRW
	bl		EXT(ml_get_timebase)				// get current timebase
	LOAD_ADDR(r3, EntropyData)
	ldr		r2, [r3, ENTROPY_INDEX_PTR]
	add		r1, r3, ENTROPY_DATA_SIZE
	add		r2, r2, #4
	cmp		r2, r1
	addge	r2, r3, ENTROPY_BUFFER
	ldr		r4, [r2]
	eor		r0, r0, r4, ROR #9
	str		r0, [r2]							// Update gEntropie
	str		r2, [r3, ENTROPY_INDEX_PTR]

return_from_irq:
	mov		r5, #0
	ldr		r4, [r9, ACT_CPUDATAP]				// Get current cpu
	str		r5, [r4, CPU_INT_STATE]				// Clear cpu_int_state
	ldr		r2, [r9, ACT_PREEMPT_CNT]           // Load preemption count
#if MACH_ASSERT
	cmp		r2, #0								// verify positive count
	bgt		1f
	push	{r7, lr}
	mov		r7, sp
	adr		r0, L_preemption_count_zero_str
	blx		EXT(panic)
	b		.
1:
#endif
	sub		r2, r2, #1							// Decrement count
	str		r2, [r9, ACT_PREEMPT_CNT]			// Update preemption count

	mrs		r0, spsr							// For check the previous mode

	cpsid	i, #PSR_SVC_MODE

	tst		r0, #0x0f							// Check if the previous is from user
	ldreq   sp, [r9, TH_KSTACKPTR]              // ...If so, reload the kernel stack pointer
	beq     load_and_go_user                    // ...and return

#if __ARM_USER_PROTECT__
	ldr		r0, [r9, ACT_KPTW_TTB]              // Load kernel ttb
	cmp		r10, r0
	beq		1f
	ldr		r10, [r9, ACT_UPTW_TTB]             // Load thread ttb
	cmp		r10, r0
	beq		1f
	mcr		p15, 0, r10, c2, c0, 0              // Set TTBR0
	ldr		r11, [r9, ACT_ASID]                 // Load thread asid
1:
	mcr		p15, 0, r11, c13, c0, 1             // set CONTEXTIDR
	isb
#endif
	b       load_and_go_sys

	.align 2
L_preemption_count_zero_str:
	.ascii	"locore.s: preemption count is zero \000"
	.align 2
/*
 * First Level Exception Handler for DEC
 * Current mode : IRQ
 * IRQ and FIQ are always disabled while running in FIQ handler
 * We do not permit nested interrupt.
 * 
 * Saving area: from user   : PCB. 
 *		from kernel : interrupt stack.
 */

	.text
	.align 2
	.globl EXT(fleh_decirq)

LEXT(fleh_decirq)
	sub		lr, lr, #4
	
	cpsie		af								// Re-enable async aborts/FIQ
	
	mrs		sp, spsr
	tst		sp, #0x0f							// From user? or kernel?
	bne		fleh_decirq_kernel

fleh_decirq_user:
	mrc		p15, 0, sp, c13, c0, 4				// Read TPIDRPRW
	add		sp, sp, ACT_PCBDATA					// Get User PCB
	stmia	sp, {r0-r12, sp, lr}^
	mov		r7, #0								// Zero the frame pointer
	nop
	str		lr, [sp, SS_PC]
	mrs		r4, spsr
	str		r4, [sp, SS_CPSR]
	mov		r5, sp								// Saved context in r5
	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW
	ldr		r6, [r9, ACT_CPUDATAP]				// Get current cpu
	ldr		sp,	[r6, CPU_ISTACKPTR]				// Set interrupt stack
	cpsid	i, #PSR_SVC_MODE
	ldr		sp, [r9, TH_KSTACKPTR]				// Set kernel stack
	cpsid	i, #PSR_IRQ_MODE

#if __ARM_VFP__
	add		r0, r9, ACT_UVFP				// Get the address of the user VFP save area
	bl		EXT(vfp_save)					// Save the current VFP state to ACT_UVFP
	mov		r4, #FPSCR_DEFAULT				// Load up the default FPSCR value...
	fmxr		fpscr, r4					// And shove it into FPSCR
#endif
#if __ARM_USER_PROTECT__
	ldr		r3, [r9, ACT_KPTW_TTB]				// Load kernel ttb
	mcr		p15, 0, r3, c2, c0, 0				// Set TTBR0
	mov		r3, #0								// Load kernel asid
	mcr		p15, 0, r3, c13, c0, 1				// Set CONTEXTIDR
	isb
#endif
#if	!CONFIG_SKIP_PRECISE_USER_KERNEL_TIME
	bl		EXT(timer_state_event_user_to_kernel)
	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW
#endif
#if CONFIG_TELEMETRY
	LOAD_ADDR(r2, telemetry_needs_record)		// Check if a telemetry record was requested...
	mov		r0, #1
	ldr		r2, [r2]
	movs	r2, r2
	beq		1f
	bl		EXT(telemetry_mark_curthread)		// ...if so, mark the current thread...
	mrc		p15, 0, r9, c13, c0, 4				// ...and restore the thread pointer from TPIDRPRW
1:
#endif

	b		fleh_decirq_handler

fleh_decirq_kernel:
	cpsid	i, #PSR_SVC_MODE

	sub     sp, sp, EXC_CTX_SIZE
	stmia	sp, {r0-r12}
	add		r0, sp, EXC_CTX_SIZE

	str		r0, [sp, SS_SP]						// Save supervisor mode sp
	str		lr, [sp, SS_LR]                     // Save supervisor mode lr

	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW

#if __ARM_VFP__
	add		r0, sp, SS_SIZE					// Get vfp state pointer
	bic		r0, #(VSS_ALIGN_NUM - 1)			// Align to arm_vfpsaved_state alignment
	add		r0, VSS_ALIGN					// Get the actual vfp save area
	bl		EXT(vfp_save)					// Save the current VFP state to the stack 
	mov		r4, #FPSCR_DEFAULT				// Load up the default FPSCR value...
	fmxr		fpscr, r4					// And shove it into FPSCR
#endif
#if __ARM_USER_PROTECT__
	mrc		p15, 0, r10, c2, c0, 0				// Get TTBR0
	ldr		r3, [r9, ACT_KPTW_TTB]				// Load kernel ttb
	mcr		p15, 0, r3, c2, c0, 0				// Set TTBR0
	mrc		p15, 0, r11, c13, c0, 1				// Get CONTEXTIDR
	mov		r3, #0								// Load kernel asid
	mcr		p15, 0, r3, c13, c0, 1				// Set CONTEXTIDR
	isb
#endif
	mov		r5, sp								// Saved context in r5

	cpsid	i, #PSR_IRQ_MODE

	str		lr, [r5, SS_PC]                     // Save LR as the return PC
	mrs		r4, spsr
	str		r4, [r5, SS_CPSR]                   // Save the cpsr of the interrupted mode

	ldr		sp, [r9, ACT_CPUDATAP]				// Get current cpu
	ldr		sp,	[sp, CPU_ISTACKPTR]				// Set interrupt stack

#if CONFIG_TELEMETRY
	LOAD_ADDR(r2, telemetry_needs_record)		// Check if a telemetry record was requested...
	mov		r0, #0
	ldr		r2, [r2]
	movs	r2, r2
	beq		1f
	bl		EXT(telemetry_mark_curthread)		// ...if so, mark the current thread...
	mrc		p15, 0, r9, c13, c0, 4				// ...and restore the thread pointer from TPIDRPRW
1:
#endif

fleh_decirq_handler:
	ldr		r2, [r9, ACT_PREEMPT_CNT]           // Load preemption count
	add		r2, r2, #1							// Increment count
	str		r2, [r9, ACT_PREEMPT_CNT]			// Update preemption count
	ldr		r2, [r9, ACT_CPUDATAP]				// Get current cpu
	str		r5, [r2, CPU_INT_STATE]				// Saved context in cpu_int_state
	ldr		r3, [r2, CPU_STAT_IRQ]				// Get IRQ count
	add		r3, r3, #1							// Increment count
	str		r3, [r2, CPU_STAT_IRQ]				// Update IRQ count
	ldr		r3, [r2, CPU_STAT_IRQ_WAKE]			// Get post-wake IRQ count
	add		r3, r3, #1					// Increment count
	str		r3, [r2, CPU_STAT_IRQ_WAKE]			// Update post-wake IRQ count
#ifndef NO_KDEBUG
	LOAD_ADDR(r4, kdebug_enable)
	ldr		r4, [r4]
	movs	r4, r4
	movne	r0, r5								// Pass saved context
	COND_EXTERN_BLNE(interrupt_trace)
#endif
	bl		EXT(interrupt_stats)                // Record interrupt statistics
	mov		r0, #0
	bl		EXT(rtclock_intr)					// Call second level exception handler
#ifndef NO_KDEBUG
	movs	r4, r4
	COND_EXTERN_BLNE(interrupt_trace_exit)
#endif

	mrc		p15, 0, r9, c13, c0, 4				// Reload r9 from TPIDRPRW

	b		return_from_irq


/*
 * First Level Exception Handler for FIQ
 * Current mode : FIQ
 * IRQ and FIQ are always disabled while running in FIQ handler
 * We do not permit nested interrupt.
 * 
 * Saving area: from user   : PCB. 
 *		from kernel : interrupt stack.
 *
 * We have 7 added shadow registers in FIQ mode for fast services.
 * So only we have to save is just 8 general registers and LR.
 * But if the current thread was running on user mode before the FIQ interrupt,
 * All user registers be saved for ast handler routine.
 */
	.text
	.align 2
	.globl EXT(fleh_fiq_generic)
	
LEXT(fleh_fiq_generic)
	str		r11, [r10]							// Clear the FIQ source

	ldr		r13, [r8, CPU_TIMEBASE_LOW]			// Load TBL
	adds	r13, r13, #1						// Increment TBL
	str		r13, [r8, CPU_TIMEBASE_LOW]			// Store TBL
	ldreq	r13, [r8, CPU_TIMEBASE_HIGH]		// Load TBU
	addeq	r13, r13, #1						// Increment TBU
	streq	r13, [r8, CPU_TIMEBASE_HIGH]		// Store TBU
	subs	r12, r12, #1						// Decrement, DEC
	str		r12, [r8, CPU_DECREMENTER]			// Store DEC
	subspl	pc, lr, #4							// Return unless DEC < 0
	b		EXT(fleh_dec)

	.text
	.align	2
	.globl	EXT(fleh_dec)
LEXT(fleh_dec)
	mrs		sp, spsr							// Get the spsr
	sub		lr, lr, #4
	tst		sp, #0x0f							// From user? or kernel?
	bne		2f

	/* From user */
	mrc		p15, 0, sp, c13, c0, 4				// Read TPIDRPRW
	add		sp, sp, ACT_PCBDATA					// Get User PCB
	
	stmia	sp, {r0-r12, sp, lr}^
	mov		r7, #0								// Zero the frame pointer
	nop
	str		lr, [sp, SS_PC]
	
	mrs		r4, spsr
	str		r4, [sp, SS_CPSR]
	mov		r5, sp
	sub		sp, sp, ACT_PCBDATA					// Get User PCB
	ldr		sp, [sp, ACT_CPUDATAP]				// Get current cpu
	ldr		sp,	[sp, CPU_ISTACKPTR]				// Set interrupt stack
	mov		r6, sp
	cpsid	i, #PSR_SVC_MODE
	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW
	ldr		sp, [r9, TH_KSTACKPTR]				// Set kernel stack

#if __ARM_VFP__
	add		r0, r9, ACT_UVFP				// Get the address of the user VFP save area
	bl		EXT(vfp_save)					// Save the current VFP state to ACT_UVFP
	mov		r4, #FPSCR_DEFAULT				// Load up the default FPSCR value...
	fmxr		fpscr, r4					// And shove it into FPSCR
#endif
#if __ARM_USER_PROTECT__
	mrc		p15, 0, r10, c2, c0, 0				// Get TTBR0
	ldr		r3, [r9, ACT_KPTW_TTB]				// Load kernel ttb
	mcr		p15, 0, r3, c2, c0, 0				// Set TTBR0
	mrc		p15, 0, r11, c13, c0, 1				// Get CONTEXTIDR
	mov		r3, #0								// Load kernel asid
	mcr		p15, 0, r3, c13, c0, 1				// Set CONTEXTIDR
	isb
#endif
	mov		r0, #1								// Mark this as coming from user context
	b		4f

2:
	/* From kernel */
	tst		sp, #PSR_IRQF						// Test for IRQ masked
	bne		3f									// We're on the cpu_signal path

	cpsid   if, #PSR_SVC_MODE

	sub     sp, sp, EXC_CTX_SIZE
	stmia	sp, {r0-r12}
	add		r0, sp, EXC_CTX_SIZE

	str		r0, [sp, SS_SP]						// Save supervisor mode sp
	str		lr, [sp, SS_LR]                     // Save supervisor mode lr

	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW

#if __ARM_VFP__
	add		r0, sp, SS_SIZE					// Get vfp state pointer
	bic		r0, #(VSS_ALIGN_NUM - 1)			// Align to arm_vfpsaved_state alignment
	add		r0, VSS_ALIGN					// Get the actual vfp save area
	bl		EXT(vfp_save)					// Save the current VFP state to the stack 
	mov		r4, #FPSCR_DEFAULT				// Load up the default FPSCR value...
	fmxr		fpscr, r4					// And shove it into FPSCR
#endif
#if __ARM_USER_PROTECT__
	mrc		p15, 0, r10, c2, c0, 0				// Get TTBR0
	ldr		r3, [r9, ACT_KPTW_TTB]				// Load kernel ttb
	mcr		p15, 0, r3, c2, c0, 0				// Set TTBR0
	mrc		p15, 0, r11, c13, c0, 1				// Get CONTEXTIDR
	mov		r3, #0								// Load kernel asid
	mcr		p15, 0, r3, c13, c0, 1				// Set CONTEXTIDR
	isb
#endif
	mov		r5, sp								// Saved context in r5

	cpsid   if, #PSR_FIQ_MODE

	mrc     p15, 0, r1, c13, c0, 4              // Read TPIDRPRW

	str		lr, [r5, SS_PC]                     // Save LR as the return PC
	mrs		r4, spsr
	str		r4, [r5, SS_CPSR]                   // Save the cpsr of the interrupted mode

	ldr		r6, [r1, ACT_CPUDATAP]				// Get current cpu
	ldr		r6,	[r6, CPU_ISTACKPTR]				// Set interrupt stack

	mov		r0, #0								// Mark this as coming from kernel context
	b       4f

3:
	/* cpu_signal path */
	mrc		p15, 0, sp, c13, c0, 4				// Read TPIDRPRW
	ldr		sp, [sp, ACT_CPUDATAP]				// Get current cpu
	ldr		sp,	[sp, CPU_FIQSTACKPTR]			// Set fiq stack
	sub		sp, sp, EXC_CTX_SIZE
	stmia		sp, {r0-r12}
	str		lr, [sp, SS_PC]
	mrs		r4, spsr
	str		r4, [sp, SS_CPSR]
	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW

#if __ARM_VFP__
	add		r0, sp, SS_SIZE					// Get vfp state pointer
	bic		r0, #(VSS_ALIGN_NUM - 1)			// Align to arm_vfpsaved_state alignment
	add		r0, VSS_ALIGN					// Get the actual vfp save area
	bl		EXT(vfp_save)					// Save the current VFP state to the stack 
	mov		r4, #FPSCR_DEFAULT				// Load up the default FPSCR value...
	fmxr		fpscr, r4					// And shove it into FPSCR
#endif
#if __ARM_USER_PROTECT__
	mrc		p15, 0, r10, c2, c0, 0				// Get TTBR0
	ldr		r3, [r9, ACT_KPTW_TTB]				// Load kernel ttb
	mcr		p15, 0, r3, c2, c0, 0				// Set TTBR0
	mrc		p15, 0, r11, c13, c0, 1				// Get CONTEXTIDR
	mov		r3, #0								// Load kernel asid
	mcr		p15, 0, r3, c13, c0, 1				// Set CONTEXTIDR
	isb
#endif

	ALIGN_STACK r0, r1
	mov		r0, r8								// Get current cpu in arg 0
	mov		r1, SIGPdec							// Decrementer signal in arg1
	mov		r2, #0
	mov		r3, #0
	bl		EXT(cpu_signal)						// Call cpu_signal
	UNALIGN_STACK

	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW

#if __ARM_VFP__
	add		r0, sp, SS_SIZE					// Get vfp state pointer
	bic		r0, #(VSS_ALIGN_NUM - 1)			// Align to arm_vfpsaved_state alignment
	add		r0, VSS_ALIGN					// Get the actual vfp save area
	bl		EXT(vfp_load)					// Load the desired VFP state from the stack 
#endif

	clrex										// clear exclusive memory tag
#if	__ARM_ENABLE_WFE_
	sev
#endif
#if __ARM_USER_PROTECT__
	mcr		p15, 0, r10, c2, c0, 0				// Set TTBR0
	mcr		p15, 0, r11, c13, c0, 1				// Set CONTEXTIDR
	isb
#endif
	ldr		lr, [sp, SS_PC]
	ldmia	sp, {r0-r12}						// Restore saved registers
	movs	pc, lr								// Return from fiq

4:
	cpsid	i, #PSR_IRQ_MODE
	cpsie	f
	mov		sp, r6								// Restore the stack pointer
	ALIGN_STACK r2, r3
	msr		spsr_cxsf, r4						// Restore the spsr
	ldr		r2, [r9, ACT_PREEMPT_CNT]           // Load preemption count
	add		r2, r2, #1							// Increment count
	str		r2, [r9, ACT_PREEMPT_CNT]			// Update preemption count
	ldr		r4, [r9, ACT_CPUDATAP]				// Get current cpu
	str		r5, [r4, CPU_INT_STATE] 
	ldr		r3, [r4, CPU_STAT_IRQ]				// Get IRQ count
	add		r3, r3, #1							// Increment count
	str		r3, [r4, CPU_STAT_IRQ]				// Update IRQ count
	ldr		r3, [r4, CPU_STAT_IRQ_WAKE]			// Get post-wake IRQ count
	add		r3, r3, #1					// Increment count
	str		r3, [r4, CPU_STAT_IRQ_WAKE]			// Update post-wake IRQ count
#if	!CONFIG_SKIP_PRECISE_USER_KERNEL_TIME
	movs	r0, r0
	beq		5f
	mov	r8, r0							// Stash our "from_user" boolean value
	bl		EXT(timer_state_event_user_to_kernel)
	mov	r0, r8							// Restore our "from_user" value
	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW
5:
#endif
#if CONFIG_TELEMETRY
	LOAD_ADDR(r4, telemetry_needs_record)		// Check if a telemetry record was requested...
	ldr		r4, [r4]
	movs	r4, r4
	beq		6f
	bl		EXT(telemetry_mark_curthread)		// ...if so, mark the current thread...
	mrc		p15, 0, r9, c13, c0, 4				// ...and restore the thread pointer from TPIDRPRW
6:
#endif

#ifndef NO_KDEBUG
	LOAD_ADDR(r4, kdebug_enable)
	ldr     r4, [r4]
	movs    r4, r4
	ldrne	r1, [r9, ACT_CPUDATAP]				// Get current cpu
	ldrne	r0, [r1, CPU_INT_STATE]
	COND_EXTERN_BLNE(interrupt_trace)
#endif
	bl		EXT(interrupt_stats)                // Record interrupt statistics
	mov		r0, #0
	bl		EXT(rtclock_intr)					// Call second level exception handler
#ifndef NO_KDEBUG
	movs	r4, r4
	COND_EXTERN_BLNE(interrupt_trace_exit)
#endif
	UNALIGN_STACK

	mrc		p15, 0, r9, c13, c0, 4				// Reload r9 from TPIDRPRW

	b       return_from_irq

/*
 * void thread_syscall_return(kern_return_t r0)
 *
 */
	.text
	.align 2
	.globl EXT(thread_syscall_return)

LEXT(thread_syscall_return)
	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW
	add		r1, r9, ACT_PCBDATA					// Get User PCB
	str		r0, [r1, SS_R0]						// set return value
#ifndef	NO_KDEBUG
	LOAD_ADDR(r4, kdebug_enable)
	ldr		r4, [r4]
	movs	r4, r4
	beq		load_and_go_user
	ldr		r12, [r1, SS_R12]					// Load syscall number
	rsbs	r1, r12, #0							// make the syscall positive (if negative)
	COND_EXTERN_BLGT(mach_syscall_trace_exit)
#endif
	b		load_and_go_user

/*
 * void thread_exception_return(void)
 * void thread_bootstrap_return(void)
 *
 */
	.text
	.globl EXT(thread_exception_return)
	.globl EXT(thread_bootstrap_return)

LEXT(thread_bootstrap_return)
#if CONFIG_DTRACE
	bl EXT(dtrace_thread_bootstrap)
#endif
	// Fall through 

LEXT(thread_exception_return)

load_and_go_user:	
/*
 * Restore user mode states and go back to user mode
 */
	cpsid	i									// Disable irq
	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW

	mvn		r0, #0
	str		r0, [r9, TH_IOTIER_OVERRIDE]			// Reset IO tier override to -1 before returning to user
	
	ldr		r8, [r9, ACT_CPUDATAP]				// Get current cpu
	ldr		r5, [r8, CPU_PENDING_AST]			// Get ASTs
	cmp		r5, #0								// Test if ASTs pending
	beq		return_to_user_now					// Branch if no ASTs

	bl		EXT(ast_taken_user)					// Handle all ASTs (may continue via thread_exception_return)

	mrc		p15, 0, r9, c13, c0, 4				// Reload r9 from TPIDRPRW
	b	load_and_go_user						// Loop back

return_to_user_now:	

#if MACH_ASSERT
/*
 * Assert that the preemption level is zero prior to the return to user space
 */
	ldr		r1, [r9, ACT_PREEMPT_CNT]           		// Load preemption count
	movs		r1, r1						// Test
	beq		0f						// Continue if zero, or...
	adr		r0, L_lagu_panic_str				// Load the panic string...
	blx		EXT(panic)					// Finally, panic
0:
	ldr		r2, [r9, TH_RWLOCK_CNT]           		// Load RW lock count
	movs		r2, r2						// Test
	beq		0f						// Continue if zero, or...
	adr		r0, L_lagu_rwlock_cnt_panic_str			// Load the panic string...
	mov		r1, r9						// Thread argument for panic string
	blx		EXT(panic)					// Finally, panic
#endif

0:
#if	!CONFIG_SKIP_PRECISE_USER_KERNEL_TIME
	bl		EXT(timer_state_event_kernel_to_user)
	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW
	ldr		r8, [r9, ACT_CPUDATAP]				// Get current cpu data
#endif	/* !CONFIG_SKIP_PRECISE_USER_KERNEL_TIME */
#if __ARM_DEBUG__ >= 6
	ldr		r0, [r9, ACT_DEBUGDATA]
	ldr		r6, [r8, CPU_USER_DEBUG]
	cmp		r0, r6								// test if debug registers need to be changed
	beq		1f
	bl		EXT(arm_debug_set)					// argument is already in r0
	mrc		p15, 0, r9, c13, c0, 4				// Read TPIDRPRW
1:
#endif
#if __ARM_VFP__
	add		r0, r9, ACT_UVFP				// Get the address of the user VFP save area
	bl		EXT(vfp_load)					// Load the desired VFP state from ACT_UVFP
#endif
	add		r0, r9, ACT_PCBDATA					// Get User PCB
	ldr		r4, [r0, SS_CPSR]					// Get saved cpsr
	and		r3, r4, #PSR_MODE_MASK				// Extract current mode	
	cmp		r3, #PSR_USER_MODE					// Check user mode
	movne	r0, r3
	bne		EXT(ExceptionVectorPanic)

	msr		spsr_cxsf, r4						// Restore spsr(user mode cpsr)
	mov		sp, r0								// Get User PCB

	clrex										// clear exclusive memory tag
#if	__ARM_ENABLE_WFE_
	sev
#endif
#if __ARM_USER_PROTECT__
	ldr     r3, [r9, ACT_UPTW_TTB]              // Load thread ttb
	mcr		p15, 0, r3, c2, c0, 0				// Set TTBR0
	ldr		r2, [r9, ACT_ASID]					// Load thread asid
	mcr		p15, 0, r2, c13, c0, 1
	isb
#endif
	ldr		lr, [sp, SS_PC]						// Restore user mode pc
	ldmia	sp, {r0-r12, sp, lr}^				// Restore the other user mode registers
	nop											// Hardware problem
	movs	pc, lr								// Return to user

	.align  2
L_lagu_panic_str:
	.asciz  "load_and_go_user: preemption_level %d"
	.align  2

	.align  2
L_lagu_rwlock_cnt_panic_str:
	.asciz  "load_and_go_user: RW lock count not 0 on thread %p (%u)"
	.align  2

        .align  2
L_evimpanic_str:
        .ascii  "Exception Vector: Illegal Mode: 0x%08X\n\000"
        .align  2

	.text
	.align 2
	.globl EXT(ExceptionVectorPanic)

LEXT(ExceptionVectorPanic)
	cpsid i, #PSR_SVC_MODE
	ALIGN_STACK r1, r2
	mov		r1, r0
	adr		r0, L_evimpanic_str
	blx		EXT(panic)
	b		.

#include	"globals_asm.h"

LOAD_ADDR_GEN_DEF(mach_trap_table)
LOAD_ADDR_GEN_DEF(kern_invalid)

/* vim: set ts=4: */

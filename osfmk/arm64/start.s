/*
 * Copyright (c) 2007-2013 Apple Inc. All rights reserved.
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
#include <arm/proc_reg.h>
#include <arm64/asm.h>
#include <arm64/proc_reg.h>
#include <pexpert/arm64/board_config.h>
#include <mach_assert.h>
#include <machine/asm.h>
#include "assym.s"
#include <arm64/tunables/tunables.s>
#include <arm64/exception_asm.h>

#if __ARM_KERNEL_PROTECT__
#include <arm/pmap.h>
#endif /* __ARM_KERNEL_PROTECT__ */


#if __APRR_SUPPORTED__

.macro MSR_APRR_EL1_X0
#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)
	bl		EXT(pinst_set_aprr_el1)
#else
	msr		APRR_EL1, x0
#endif
.endmacro

.macro MSR_APRR_EL0_X0
#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)
	bl		EXT(pinst_set_aprr_el0)
#else
	msr		APRR_EL0, x0
#endif
.endmacro

.macro MSR_APRR_SHADOW_MASK_EN_EL1_X0
#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)
	bl		EXT(pinst_set_aprr_shadow_mask_en_el1)
#else
	msr		APRR_SHADOW_MASK_EN_EL1, x0
#endif
.endmacro

#endif /* __APRR_SUPPORTED__ */

.macro MSR_VBAR_EL1_X0
#if defined(KERNEL_INTEGRITY_KTRR)
	mov	x1, lr
	bl		EXT(pinst_set_vbar)
	mov	lr, x1
#else
	msr		VBAR_EL1, x0
#endif
.endmacro

.macro MSR_TCR_EL1_X1
#if defined(KERNEL_INTEGRITY_KTRR)
	mov		x0, x1
	mov		x1, lr
	bl		EXT(pinst_set_tcr)
	mov		lr, x1
#else
	msr		TCR_EL1, x1
#endif
.endmacro

.macro MSR_TTBR1_EL1_X0
#if defined(KERNEL_INTEGRITY_KTRR)
	mov		x1, lr
	bl		EXT(pinst_set_ttbr1)
	mov		lr, x1
#else
	msr		TTBR1_EL1, x0
#endif
.endmacro

.macro MSR_SCTLR_EL1_X0
#if defined(KERNEL_INTEGRITY_KTRR)
	mov		x1, lr

	// This may abort, do so on SP1
	bl		EXT(pinst_spsel_1)

	bl		EXT(pinst_set_sctlr)
	msr		SPSel, #0									// Back to SP0
	mov		lr, x1
#else
	msr		SCTLR_EL1, x0
#endif /* defined(KERNEL_INTEGRITY_KTRR) */
.endmacro

/*
 * Checks the reset handler for global and CPU-specific reset-assist functions,
 * then jumps to the reset handler with boot args and cpu data. This is copied
 * to the first physical page during CPU bootstrap (see cpu.c).
 *
 * Variables:
 *	x19 - Reset handler data pointer
 *	x20 - Boot args pointer
 *	x21 - CPU data pointer
 */
	.text
	.align 12
	.globl EXT(LowResetVectorBase)
LEXT(LowResetVectorBase)
	/*
	 * On reset, both RVBAR_EL1 and VBAR_EL1 point here.  SPSel.SP is 1,
	 * so on reset the CPU will jump to offset 0x0 and on exceptions
	 * the CPU will jump to offset 0x200, 0x280, 0x300, or 0x380.
	 * In order for both the reset vector and exception vectors to
	 * coexist in the same space, the reset code is moved to the end
	 * of the exception vector area.
	 */
	b		EXT(reset_vector)

	/* EL1 SP1: These vectors trap errors during early startup on non-boot CPUs. */
	.align	9
	b		.
	.align	7
	b		.
	.align	7
	b		.
	.align	7
	b		.

	.align	7
	.globl EXT(reset_vector)
LEXT(reset_vector)
	// Preserve x0 for start_first_cpu, if called
	// Unlock the core for debugging
	msr		OSLAR_EL1, xzr
	msr		DAIFSet, #(DAIFSC_ALL)				// Disable all interrupts

#if !(defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR))
	// Set low reset vector before attempting any loads
	adrp    x0, EXT(LowExceptionVectorBase)@page
	add     x0, x0, EXT(LowExceptionVectorBase)@pageoff
	msr     VBAR_EL1, x0
#endif

#if __APRR_SUPPORTED__
	MOV64	x0, APRR_EL1_DEFAULT
#if XNU_MONITOR
	adrp	x4, EXT(pmap_ppl_locked_down)@page
	ldrb	w5, [x4, #EXT(pmap_ppl_locked_down)@pageoff]
	cmp		w5, #0
	b.ne	1f

	// If the PPL is not locked down, we start in PPL mode.
	MOV64	x0, APRR_EL1_PPL
1:
#endif /* XNU_MONITOR */

	MSR_APRR_EL1_X0

	// Load up the default APRR_EL0 value.
	MOV64	x0, APRR_EL0_DEFAULT
	MSR_APRR_EL0_X0
#endif /* __APRR_SUPPORTED__ */

#if defined(KERNEL_INTEGRITY_KTRR)
	/*
	 * Set KTRR registers immediately after wake/resume
	 *
	 * During power on reset, XNU stashed the kernel text region range values
	 * into __DATA,__const which should be protected by AMCC RoRgn at this point.
	 * Read this data and program/lock KTRR registers accordingly.
	 * If either values are zero, we're debugging kernel so skip programming KTRR.
	 */

	/* refuse to boot if machine_lockdown() hasn't completed */
	adrp	x17, EXT(lockdown_done)@page
	ldr	w17, [x17, EXT(lockdown_done)@pageoff]
	cbz	w17, .

	// load stashed rorgn_begin
	adrp	x17, EXT(ctrr_begin)@page
	add		x17, x17, EXT(ctrr_begin)@pageoff
	ldr		x17, [x17]
#if DEBUG || DEVELOPMENT || CONFIG_DTRACE
	// if rorgn_begin is zero, we're debugging. skip enabling ktrr
	cbz		x17, Lskip_ktrr
#else
	cbz		x17, .
#endif

	// load stashed rorgn_end
	adrp	x19, EXT(ctrr_end)@page
	add		x19, x19, EXT(ctrr_end)@pageoff
	ldr		x19, [x19]
#if DEBUG || DEVELOPMENT || CONFIG_DTRACE
	cbz		x19, Lskip_ktrr
#else
	cbz		x19, .
#endif

	msr		ARM64_REG_KTRR_LOWER_EL1, x17
	msr		ARM64_REG_KTRR_UPPER_EL1, x19
	mov		x17, #1
	msr		ARM64_REG_KTRR_LOCK_EL1, x17
Lskip_ktrr:
#endif /* defined(KERNEL_INTEGRITY_KTRR) */

	// Process reset handlers
	adrp	x19, EXT(ResetHandlerData)@page			// Get address of the reset handler data
	add		x19, x19, EXT(ResetHandlerData)@pageoff
	mrs		x15, MPIDR_EL1						// Load MPIDR to get CPU number
#if HAS_CLUSTER
	and		x0, x15, #0xFFFF					// CPU number in Affinity0, cluster ID in Affinity1
#else
	and		x0, x15, #0xFF						// CPU number is in MPIDR Affinity Level 0
#endif
	ldr		x1, [x19, CPU_DATA_ENTRIES]			// Load start of data entries
	add		x3, x1, MAX_CPUS * 16				// end addr of data entries = start + (16 * MAX_CPUS)
Lcheck_cpu_data_entry:
	ldr		x21, [x1, CPU_DATA_PADDR]			// Load physical CPU data address
	cbz		x21, Lnext_cpu_data_entry
	ldr		w2, [x21, CPU_PHYS_ID]				// Load ccc cpu phys id
	cmp		x0, x2						// Compare cpu data phys cpu and MPIDR_EL1 phys cpu
	b.eq	Lfound_cpu_data_entry				// Branch if match
Lnext_cpu_data_entry:
	add		x1, x1, #16					// Increment to the next cpu data entry
	cmp		x1, x3
	b.eq	Lskip_cpu_reset_handler				// Not found
	b		Lcheck_cpu_data_entry	// loop
Lfound_cpu_data_entry:
#if defined(KERNEL_INTEGRITY_CTRR)
	/*
	 * Program and lock CTRR if this CPU is non-boot cluster master. boot cluster will be locked
	 * in machine_lockdown. pinst insns protected by VMSA_LOCK
	 * A_PXN and A_MMUON_WRPROTECT options provides something close to KTRR behavior
	 */

	/* refuse to boot if machine_lockdown() hasn't completed */
	adrp	x17, EXT(lockdown_done)@page
	ldr	w17, [x17, EXT(lockdown_done)@pageoff]
	cbz	w17, .

	// load stashed rorgn_begin
	adrp	x17, EXT(ctrr_begin)@page
	add		x17, x17, EXT(ctrr_begin)@pageoff
	ldr		x17, [x17]
#if DEBUG || DEVELOPMENT || CONFIG_DTRACE
	// if rorgn_begin is zero, we're debugging. skip enabling ctrr
	cbz		x17, Lskip_ctrr
#else
	cbz		x17, .
#endif

	// load stashed rorgn_end
	adrp	x19, EXT(ctrr_end)@page
	add		x19, x19, EXT(ctrr_end)@pageoff
	ldr		x19, [x19]
#if DEBUG || DEVELOPMENT || CONFIG_DTRACE
	cbz		x19, Lskip_ctrr
#else
	cbz		x19, .
#endif

	mrs		x18, ARM64_REG_CTRR_LOCK_EL1
	cbnz	x18, Lskip_ctrr  /* don't touch if already locked */
	msr		ARM64_REG_CTRR_A_LWR_EL1, x17
	msr		ARM64_REG_CTRR_A_UPR_EL1, x19
	mov		x18, #(CTRR_CTL_EL1_A_PXN | CTRR_CTL_EL1_A_MMUON_WRPROTECT)
	msr		ARM64_REG_CTRR_CTL_EL1, x18
	mov		x18, #1
	msr		ARM64_REG_CTRR_LOCK_EL1, x18


	isb
	tlbi 	vmalle1
	dsb 	ish
	isb
Lspin_ctrr_unlocked:
	/* we shouldn't ever be here as cpu start is serialized by cluster in cpu_start(),
	 * and first core started in cluster is designated cluster master and locks
	 * both core and cluster. subsequent cores in same cluster will run locked from
	 * from reset vector */
	mrs		x18, ARM64_REG_CTRR_LOCK_EL1
	cbz		x18, Lspin_ctrr_unlocked
Lskip_ctrr:
#endif
	adrp	x20, EXT(const_boot_args)@page
	add		x20, x20, EXT(const_boot_args)@pageoff
	ldr		x0, [x21, CPU_RESET_HANDLER]		// Call CPU reset handler
	cbz		x0, Lskip_cpu_reset_handler

	// Validate that our handler is one of the two expected handlers
	adrp	x2, EXT(resume_idle_cpu)@page
	add		x2, x2, EXT(resume_idle_cpu)@pageoff
	cmp		x0, x2
	beq		1f
	adrp	x2, EXT(start_cpu)@page
	add		x2, x2, EXT(start_cpu)@pageoff
	cmp		x0, x2
	bne		Lskip_cpu_reset_handler
1:

#if HAS_BP_RET
	bl		EXT(set_bp_ret)
#endif

#if __ARM_KERNEL_PROTECT__ && defined(KERNEL_INTEGRITY_KTRR)
	/*
	 * Populate TPIDR_EL1 (in case the CPU takes an exception while
	 * turning on the MMU).
	 */
	ldr		x13, [x21, CPU_ACTIVE_THREAD]
	msr		TPIDR_EL1, x13
#endif /* __ARM_KERNEL_PROTECT__ */

	blr		x0
Lskip_cpu_reset_handler:
	b		.									// Hang if the handler is NULL or returns

	.align 3
	.global EXT(LowResetVectorEnd)
LEXT(LowResetVectorEnd)
	.global	EXT(SleepToken)
#if WITH_CLASSIC_S2R
LEXT(SleepToken)
	.space	(stSize_NUM),0
#endif

	.section __DATA_CONST,__const
	.align	3
	.globl  EXT(ResetHandlerData)
LEXT(ResetHandlerData)
	.space  (rhdSize_NUM),0		// (filled with 0s)
	.text


/*
 * __start trampoline is located at a position relative to LowResetVectorBase
 * so that iBoot can compute the reset vector position to set IORVBAR using
 * only the kernel entry point.  Reset vector = (__start & ~0xfff)
 */
	.align	3
	.globl EXT(_start)
LEXT(_start)
	b	EXT(start_first_cpu)


/*
 * Provides an early-boot exception vector so that the processor will spin
 * and preserve exception information (e.g., ELR_EL1) when early CPU bootstrap
 * code triggers an exception. This is copied to the second physical page
 * during CPU bootstrap (see cpu.c).
 */
	.align 12, 0
	.global	EXT(LowExceptionVectorBase)
LEXT(LowExceptionVectorBase)
	/* EL1 SP 0 */
	b		.
	.align	7
	b		.
	.align	7
	b		.
	.align	7
	b		.
	/* EL1 SP1 */
	.align	7
	b		.
	.align	7
	b		.
	.align	7
	b		.
	.align	7
	b		.
	/* EL0 64 */
	.align	7
	b		.
	.align	7
	b		.
	.align	7
	b		.
	.align	7
	b		.
	/* EL0 32 */
	.align	7
	b		.
	.align	7
	b		.
	.align	7
	b		.
	.align	7
	b		.
	.align 12, 0

#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)
/*
 * Provide a global symbol so that we can narrow the V=P mapping to cover
 * this page during arm_vm_init.
 */
.align ARM_PGSHIFT
.globl EXT(bootstrap_instructions)
LEXT(bootstrap_instructions)

#endif /* defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR) */
	.align 2
	.globl EXT(resume_idle_cpu)
LEXT(resume_idle_cpu)
	adrp	lr, EXT(arm_init_idle_cpu)@page
	add		lr, lr, EXT(arm_init_idle_cpu)@pageoff
	b		start_cpu

	.align 2
	.globl EXT(start_cpu)
LEXT(start_cpu)
	adrp	lr, EXT(arm_init_cpu)@page
	add		lr, lr, EXT(arm_init_cpu)@pageoff
	b		start_cpu

	.align 2
start_cpu:
#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)
	// This is done right away in reset vector for pre-KTRR devices
	// Set low reset vector now that we are in the KTRR-free zone
	adrp	x0, EXT(LowExceptionVectorBase)@page
	add		x0, x0, EXT(LowExceptionVectorBase)@pageoff
	MSR_VBAR_EL1_X0
#endif /* defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR) */

	// x20 set to BootArgs phys address
	// x21 set to cpu data phys address

	// Get the kernel memory parameters from the boot args
	ldr		x22, [x20, BA_VIRT_BASE]			// Get the kernel virt base
	ldr		x23, [x20, BA_PHYS_BASE]			// Get the kernel phys base
	ldr		x24, [x20, BA_MEM_SIZE]				// Get the physical memory size
	adrp	x25, EXT(bootstrap_pagetables)@page	// Get the start of the page tables
	ldr		x26, [x20, BA_BOOT_FLAGS]			// Get the kernel boot flags


	// Set TPIDRRO_EL0 with the CPU number
	ldr		x0, [x21, CPU_NUMBER_GS]
	msr		TPIDRRO_EL0, x0

	// Set the exception stack pointer
	ldr		x0, [x21, CPU_EXCEPSTACK_TOP]


	// Set SP_EL1 to exception stack
#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)
	mov		x1, lr
	bl		EXT(pinst_spsel_1)
	mov		lr, x1
#else
	msr		SPSel, #1
#endif
	mov		sp, x0

	// Set the interrupt stack pointer
	ldr		x0, [x21, CPU_INTSTACK_TOP]
	msr		SPSel, #0
	mov		sp, x0

	// Convert lr to KVA
	add		lr, lr, x22
	sub		lr, lr, x23

	b		common_start

/*
 * create_l1_table_entry
 *
 * Given a virtual address, creates a table entry in an L1 translation table
 * to point to an L2 translation table.
 *   arg0 - Virtual address
 *   arg1 - L1 table address
 *   arg2 - L2 table address
 *   arg3 - Scratch register
 *   arg4 - Scratch register
 *   arg5 - Scratch register
 */
.macro create_l1_table_entry
	and		$3,	$0, #(ARM_TT_L1_INDEX_MASK)
	lsr		$3, $3, #(ARM_TT_L1_SHIFT)			// Get index in L1 table for L2 table
	lsl		$3, $3, #(TTE_SHIFT)				// Convert index into pointer offset
	add		$3, $1, $3							// Get L1 entry pointer
	mov		$4, #(ARM_TTE_BOOT_TABLE)			// Get L1 table entry template
	and		$5, $2, #(ARM_TTE_TABLE_MASK)		// Get address bits of L2 table
	orr		$5, $4, $5 							// Create table entry for L2 table
	str		$5, [$3]							// Write entry to L1 table
.endmacro

/*
 * create_l2_block_entries
 *
 * Given base virtual and physical addresses, creates consecutive block entries
 * in an L2 translation table.
 *   arg0 - Virtual address
 *   arg1 - Physical address
 *   arg2 - L2 table address
 *   arg3 - Number of entries
 *   arg4 - Scratch register
 *   arg5 - Scratch register
 *   arg6 - Scratch register
 *   arg7 - Scratch register
 */
.macro create_l2_block_entries
	and		$4,	$0, #(ARM_TT_L2_INDEX_MASK)
	lsr		$4, $4, #(ARM_TTE_BLOCK_L2_SHIFT)	// Get index in L2 table for block entry
	lsl		$4, $4, #(TTE_SHIFT)				// Convert index into pointer offset
	add		$4, $2, $4							// Get L2 entry pointer
	mov		$5, #(ARM_TTE_BOOT_BLOCK)			// Get L2 block entry template
	and		$6, $1, #(ARM_TTE_BLOCK_L2_MASK)	// Get address bits of block mapping
	orr		$6, $5, $6
	mov		$5, $3
	mov		$7, #(ARM_TT_L2_SIZE)
1:
	str		$6, [$4], #(1 << TTE_SHIFT)			// Write entry to L2 table and advance
	add		$6, $6, $7							// Increment the output address
	subs	$5, $5, #1							// Decrement the number of entries
	b.ne	1b
.endmacro

/*
 *  arg0 - virtual start address
 *  arg1 - physical start address
 *  arg2 - number of entries to map
 *  arg3 - L1 table address
 *  arg4 - free space pointer
 *  arg5 - scratch (entries mapped per loop)
 *  arg6 - scratch
 *  arg7 - scratch
 *  arg8 - scratch
 *  arg9 - scratch
 */
.macro create_bootstrap_mapping
	/* calculate entries left in this page */
	and	$5, $0, #(ARM_TT_L2_INDEX_MASK)
	lsr	$5, $5, #(ARM_TT_L2_SHIFT)
	mov	$6, #(TTE_PGENTRIES)
	sub	$5, $6, $5

	/* allocate an L2 table */
3:	add	$4, $4, PGBYTES

	/* create_l1_table_entry(virt_base, L1 table, L2 table, scratch1, scratch2, scratch3) */
	create_l1_table_entry	$0, $3, $4, $6, $7, $8

	/* determine how many entries to map this loop - the smaller of entries
	 * remaining in page and total entries left */
	cmp	$2, $5
	csel	$5, $2, $5, lt

	/* create_l2_block_entries(virt_base, phys_base, L2 table, num_ents, scratch1, scratch2, scratch3) */
	create_l2_block_entries	$0, $1, $4, $5, $6, $7, $8, $9

	/* subtract entries just mapped and bail out if we're done */
	subs	$2, $2, $5
	beq	2f

	/* entries left to map - advance base pointers */
	add 	$0, $0, $5, lsl #(ARM_TT_L2_SHIFT)
	add 	$1, $1, $5, lsl #(ARM_TT_L2_SHIFT)

	mov	$5, #(TTE_PGENTRIES)  /* subsequent loops map (up to) a whole L2 page */
	b	3b
2:
.endmacro

/*
 * _start_first_cpu
 * Cold boot init routine.  Called from __start
 *   x0 - Boot args
 */
	.align 2
	.globl EXT(start_first_cpu)
LEXT(start_first_cpu)

	// Unlock the core for debugging
	msr		OSLAR_EL1, xzr
	msr		DAIFSet, #(DAIFSC_ALL)				// Disable all interrupts

	mov		x20, x0
	mov		x21, #0

	// Set low reset vector before attempting any loads
	adrp	x0, EXT(LowExceptionVectorBase)@page
	add		x0, x0, EXT(LowExceptionVectorBase)@pageoff
	MSR_VBAR_EL1_X0

#if __APRR_SUPPORTED__
	// Save the LR
	mov		x1, lr

#if XNU_MONITOR
	// If the PPL is supported, we start out in PPL mode.
	MOV64	x0, APRR_EL1_PPL
#else
	// Otherwise, we start out in default mode.
	MOV64	x0, APRR_EL1_DEFAULT
#endif

	// Set the APRR state for EL1.
	MSR_APRR_EL1_X0

	// Set the APRR state for EL0.
	MOV64	x0, APRR_EL0_DEFAULT
	MSR_APRR_EL0_X0


	// Restore the LR.
	mov	lr, x1
#endif /* __APRR_SUPPORTED__ */

	// Get the kernel memory parameters from the boot args
	ldr		x22, [x20, BA_VIRT_BASE]			// Get the kernel virt base
	ldr		x23, [x20, BA_PHYS_BASE]			// Get the kernel phys base
	ldr		x24, [x20, BA_MEM_SIZE]				// Get the physical memory size
	adrp	x25, EXT(bootstrap_pagetables)@page	// Get the start of the page tables
	ldr		x26, [x20, BA_BOOT_FLAGS]			// Get the kernel boot flags

	// Clear the register that will be used to store the userspace thread pointer and CPU number.
	// We may not actually be booting from ordinal CPU 0, so this register will be updated
	// in ml_parse_cpu_topology(), which happens later in bootstrap.
	msr		TPIDRRO_EL0, x21

	// Set up exception stack pointer
	adrp	x0, EXT(excepstack_top)@page		// Load top of exception stack
	add		x0, x0, EXT(excepstack_top)@pageoff
	add		x0, x0, x22							// Convert to KVA
	sub		x0, x0, x23

	// Set SP_EL1 to exception stack
#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)
	bl		EXT(pinst_spsel_1)
#else
	msr		SPSel, #1
#endif

	mov		sp, x0

	// Set up interrupt stack pointer
	adrp	x0, EXT(intstack_top)@page			// Load top of irq stack
	add		x0, x0, EXT(intstack_top)@pageoff
	add		x0, x0, x22							// Convert to KVA
	sub		x0, x0, x23
	msr		SPSel, #0							// Set SP_EL0 to interrupt stack
	mov		sp, x0

	// Load address to the C init routine into link register
	adrp	lr, EXT(arm_init)@page
	add		lr, lr, EXT(arm_init)@pageoff
	add		lr, lr, x22							// Convert to KVA
	sub		lr, lr, x23

	/*
	 * Set up the bootstrap page tables with a single block entry for the V=P
	 * mapping, a single block entry for the trampolined kernel address (KVA),
	 * and all else invalid. This requires four pages:
	 *	Page 1 - V=P L1 table
	 *	Page 2 - V=P L2 table
	 *	Page 3 - KVA L1 table
	 *	Page 4 - KVA L2 table
	 */

	// Invalidate all entries in the bootstrap page tables
	mov		x0, #(ARM_TTE_EMPTY)				// Load invalid entry template
	mov		x1, x25								// Start at V=P pagetable root
	mov		x2, #(TTE_PGENTRIES)				// Load number of entries per page
	lsl		x2, x2, #2							// Shift by 2 for num entries on 4 pages

Linvalidate_bootstrap:							// do {
	str		x0, [x1], #(1 << TTE_SHIFT)			//   Invalidate and advance
	subs	x2, x2, #1							//   entries--
	b.ne	Linvalidate_bootstrap				// } while (entries != 0)

	/*
	 * In order to reclaim memory on targets where TZ0 (or some other entity)
	 * must be located at the base of memory, iBoot may set the virtual and
	 * physical base addresses to immediately follow whatever lies at the
	 * base of physical memory.
	 *
	 * If the base address belongs to TZ0, it may be dangerous for xnu to map
	 * it (as it may be prefetched, despite being technically inaccessible).
	 * In order to avoid this issue while keeping the mapping code simple, we
	 * may continue to use block mappings, but we will only map the kernelcache
	 * mach header to the end of memory.
	 *
	 * Given that iBoot guarantees that the unslid kernelcache base address
	 * will begin on an L2 boundary, this should prevent us from accidentally
	 * mapping TZ0.
	 */
	adrp	x0, EXT(_mh_execute_header)@page	// address of kernel mach header
	add		x0, x0, EXT(_mh_execute_header)@pageoff
	ldr		w1, [x0, #0x18]						// load mach_header->flags
	tbz		w1, #0x1f, Lkernelcache_base_found	// if MH_DYLIB_IN_CACHE unset, base is kernel mach header
	ldr		w1, [x0, #0x20]						// load first segment cmd (offset sizeof(kernel_mach_header_t))
	cmp		w1, #0x19							// must be LC_SEGMENT_64
	bne		.
	ldr		x1, [x0, #0x38]						// load first segment vmaddr
	sub		x1, x0, x1							// compute slide
	MOV64	x0, VM_KERNEL_LINK_ADDRESS
	add		x0, x0, x1							// base is kernel link address + slide

Lkernelcache_base_found:
	/*
	 * Adjust physical and virtual base addresses to account for physical
	 * memory preceeding xnu Mach-O header
	 * x22 - Kernel virtual base
	 * x23 - Kernel physical base
	 * x24 - Physical memory size
	 */
	sub		x18, x0, x23
	sub		x24, x24, x18
	add		x22, x22, x18
	add		x23, x23, x18

	/*
	 * x0  - V=P virtual cursor
	 * x4  - V=P physical cursor
	 * x14 - KVA virtual cursor
	 * x15 - KVA physical cursor
	 */
	mov		x4, x0
	mov		x14, x22
	mov		x15, x23

	/*
	 * Allocate L1 tables
	 * x1 - V=P L1 page
	 * x3 - KVA L1 page
	 * x2 - free mem pointer from which we allocate a variable number of L2
	 * pages. The maximum number of bootstrap page table pages is limited to
	 * BOOTSTRAP_TABLE_SIZE. For a 2G 4k page device, assuming the worst-case
	 * slide, we need 1xL1 and up to 3xL2 pages (1GB mapped per L1 entry), so
	 * 8 total pages for V=P and KVA.
	 */
	mov		x1, x25
	add		x3, x1, PGBYTES
	mov		x2, x3

	/*
	 * Setup the V=P bootstrap mapping
	 * x5 - total number of L2 entries to allocate
	 */
	lsr		x5,  x24, #(ARM_TT_L2_SHIFT)
	/* create_bootstrap_mapping(vbase, pbase, num_ents, L1 table, freeptr) */
	create_bootstrap_mapping x0,  x4,  x5, x1, x2, x6, x10, x11, x12, x13

	/* Setup the KVA bootstrap mapping */
	lsr		x5,  x24, #(ARM_TT_L2_SHIFT)
	create_bootstrap_mapping x14, x15, x5, x3, x2, x9, x10, x11, x12, x13

	/* Ensure TTEs are visible */
	dsb		ish


	b		common_start

/*
 * Begin common CPU initialization
 *
 * Regster state:
 *	x20 - PA of boot args
 *	x21 - zero on cold boot, PA of cpu data on warm reset
 *	x22 - Kernel virtual base
 *	x23 - Kernel physical base
 *	x25 - PA of the V=P pagetable root
 *	 lr - KVA of C init routine
 *	 sp - SP_EL0 selected
 *
 *	SP_EL0 - KVA of CPU's interrupt stack
 *	SP_EL1 - KVA of CPU's exception stack
 *	TPIDRRO_EL0 - CPU number
 */
common_start:

#if HAS_NEX_PG
	mov x19, lr
	bl		EXT(set_nex_pg)
	mov lr, x19
#endif

	// Set the translation control register.
	adrp	x0,     EXT(sysreg_restore)@page		// Load TCR value from the system register restore structure
	add		x0, x0, EXT(sysreg_restore)@pageoff
	ldr		x1, [x0, SR_RESTORE_TCR_EL1]
	MSR_TCR_EL1_X1

	/* Set up translation table base registers.
	 *	TTBR0 - V=P table @ top of kernel
	 *	TTBR1 - KVA table @ top of kernel + 1 page
	 */
#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)
	/* Note that for KTRR configurations, the V=P map will be modified by
	 * arm_vm_init.c.
	 */
#endif
	and		x0, x25, #(TTBR_BADDR_MASK)
	mov		x19, lr
	bl		EXT(set_mmu_ttb)
	mov		lr, x19
	add		x0, x25, PGBYTES
	and		x0, x0, #(TTBR_BADDR_MASK)
	MSR_TTBR1_EL1_X0

	// Set up MAIR attr0 for normal memory, attr1 for device memory
	mov		x0, xzr
	mov		x1, #(MAIR_WRITEBACK << MAIR_ATTR_SHIFT(CACHE_ATTRINDX_WRITEBACK))
	orr		x0, x0, x1
	mov		x1, #(MAIR_INNERWRITEBACK << MAIR_ATTR_SHIFT(CACHE_ATTRINDX_INNERWRITEBACK))
	orr		x0, x0, x1
	mov		x1, #(MAIR_DISABLE << MAIR_ATTR_SHIFT(CACHE_ATTRINDX_DISABLE))
	orr		x0, x0, x1
	mov		x1, #(MAIR_WRITETHRU << MAIR_ATTR_SHIFT(CACHE_ATTRINDX_WRITETHRU))
	orr		x0, x0, x1
	mov		x1, #(MAIR_WRITECOMB << MAIR_ATTR_SHIFT(CACHE_ATTRINDX_WRITECOMB))
	orr		x0, x0, x1
	mov		x1, #(MAIR_POSTED << MAIR_ATTR_SHIFT(CACHE_ATTRINDX_POSTED))
	orr		x0, x0, x1
	mov		x1, #(MAIR_POSTED_REORDERED << MAIR_ATTR_SHIFT(CACHE_ATTRINDX_POSTED_REORDERED))
	orr		x0, x0, x1
	mov		x1, #(MAIR_POSTED_COMBINED_REORDERED << MAIR_ATTR_SHIFT(CACHE_ATTRINDX_POSTED_COMBINED_REORDERED))
	orr		x0, x0, x1
	msr		MAIR_EL1, x0
	isb
	tlbi	vmalle1
	dsb		ish

#if defined(APPLEHURRICANE)
	// <rdar://problem/26726624> Increase Snoop reservation in EDB to reduce starvation risk
	// Needs to be done before MMU is enabled
	HID_INSERT_BITS	ARM64_REG_HID5, ARM64_REG_HID5_CrdEdbSnpRsvd_mask, ARM64_REG_HID5_CrdEdbSnpRsvd_VALUE, x12
#endif

#if defined(BCM2837)
	// Setup timer interrupt routing; must be done before MMU is enabled
	mrs		x15, MPIDR_EL1						// Load MPIDR to get CPU number
	and		x15, x15, #0xFF						// CPU number is in MPIDR Affinity Level 0
	mov		x0, #0x4000
	lsl		x0, x0, #16
	add		x0, x0, #0x0040						// x0: 0x4000004X Core Timers interrupt control
	add		x0, x0, x15, lsl #2
	mov		w1, #0xF0 						// x1: 0xF0 	  Route to Core FIQs
	str		w1, [x0]
	isb		sy
#endif

#ifndef __ARM_IC_NOALIAS_ICACHE__
	/* Invalidate the TLB and icache on systems that do not guarantee that the
	 * caches are invalidated on reset.
	 */
	tlbi	vmalle1
	ic		iallu
#endif

	/* If x21 is not 0, then this is either the start_cpu path or
	 * the resume_idle_cpu path.  cpu_ttep should already be
	 * populated, so just switch to the kernel_pmap now.
	 */

	cbz		x21, 1f
	adrp	x0, EXT(cpu_ttep)@page
	add		x0, x0, EXT(cpu_ttep)@pageoff
	ldr		x0, [x0]
	MSR_TTBR1_EL1_X0
1:

	// Set up the exception vectors
#if __ARM_KERNEL_PROTECT__
	/* If this is not the first reset of the boot CPU, the alternate mapping
	 * for the exception vectors will be set up, so use it.  Otherwise, we
	 * should use the mapping located in the kernelcache mapping.
	 */
	MOV64	x0, ARM_KERNEL_PROTECT_EXCEPTION_START

	cbnz		x21, 1f
#endif /* __ARM_KERNEL_PROTECT__ */
	adrp	x0, EXT(ExceptionVectorsBase)@page			// Load exception vectors base address
	add		x0, x0, EXT(ExceptionVectorsBase)@pageoff
	add		x0, x0, x22									// Convert exception vector address to KVA
	sub		x0, x0, x23
1:
	MSR_VBAR_EL1_X0

1:
#ifdef HAS_APPLE_PAC
#ifdef __APSTS_SUPPORTED__
	mrs		x0, ARM64_REG_APSTS_EL1
	and		x1, x0, #(APSTS_EL1_MKEYVld)
	cbz		x1, 1b 										// Poll APSTS_EL1.MKEYVld
	mrs		x0, ARM64_REG_APCTL_EL1
	orr		x0, x0, #(APCTL_EL1_AppleMode)
#ifdef HAS_APCTL_EL1_USERKEYEN
	orr		x0, x0, #(APCTL_EL1_UserKeyEn)
	and		x0, x0, #~(APCTL_EL1_KernKeyEn)
#else /* !HAS_APCTL_EL1_USERKEYEN */
	orr		x0, x0, #(APCTL_EL1_KernKeyEn)
#endif /* HAS_APCTL_EL1_USERKEYEN */
	and		x0, x0, #~(APCTL_EL1_EnAPKey0)
	msr		ARM64_REG_APCTL_EL1, x0


#else
	mrs		x0, ARM64_REG_APCTL_EL1
	and		x1, x0, #(APCTL_EL1_MKEYVld)
	cbz		x1, 1b 										// Poll APCTL_EL1.MKEYVld
	orr		x0, x0, #(APCTL_EL1_AppleMode)
	orr		x0, x0, #(APCTL_EL1_KernKeyEn)
	msr		ARM64_REG_APCTL_EL1, x0
#endif /* APSTS_SUPPORTED */

	/* ISB necessary to ensure APCTL_EL1_AppleMode logic enabled before proceeding */
	isb		sy
	/* Load static kernel key diversification values */
	ldr		x0, =KERNEL_ROP_ID
	/* set ROP key. must write at least once to pickup mkey per boot diversification */
	msr		APIBKeyLo_EL1, x0
	add		x0, x0, #1
	msr		APIBKeyHi_EL1, x0
	add		x0, x0, #1
	msr		APDBKeyLo_EL1, x0
	add		x0, x0, #1
	msr		APDBKeyHi_EL1, x0
	add		x0, x0, #1
	msr		ARM64_REG_KERNELKEYLO_EL1, x0
	add		x0, x0, #1
	msr		ARM64_REG_KERNELKEYHI_EL1, x0
	/* set JOP key. must write at least once to pickup mkey per boot diversification */
	add		x0, x0, #1
	msr		APIAKeyLo_EL1, x0
	add		x0, x0, #1
	msr		APIAKeyHi_EL1, x0
	add		x0, x0, #1
	msr		APDAKeyLo_EL1, x0
	add		x0, x0, #1
	msr		APDAKeyHi_EL1, x0
	/* set G key */
	add		x0, x0, #1
	msr		APGAKeyLo_EL1, x0
	add		x0, x0, #1
	msr		APGAKeyHi_EL1, x0

	// Enable caches, MMU, ROP and JOP
	MOV64	x0, SCTLR_EL1_DEFAULT
	orr		x0, x0, #(SCTLR_PACIB_ENABLED) /* IB is ROP */

#if __APCFG_SUPPORTED__
	// for APCFG systems, JOP keys are always on for EL1.
	// JOP keys for EL0 will be toggled on the first time we pmap_switch to a pmap that has JOP enabled
#else /* __APCFG_SUPPORTED__ */
	MOV64	x1, SCTLR_JOP_KEYS_ENABLED
	orr 	x0, x0, x1
#endif /* !__APCFG_SUPPORTED__ */
#else  /* HAS_APPLE_PAC */

	// Enable caches and MMU
	MOV64	x0, SCTLR_EL1_DEFAULT
#endif /* HAS_APPLE_PAC */
	MSR_SCTLR_EL1_X0
	isb		sy

	MOV64	x1, SCTLR_EL1_DEFAULT
#if HAS_APPLE_PAC
	orr		x1, x1, #(SCTLR_PACIB_ENABLED)
#if !__APCFG_SUPPORTED__
	MOV64	x2, SCTLR_JOP_KEYS_ENABLED
	orr		x1, x1, x2
#endif /* !__APCFG_SUPPORTED__ */
#endif /* HAS_APPLE_PAC */
	cmp		x0, x1
	bne		.

#if (!CONFIG_KERNEL_INTEGRITY || (CONFIG_KERNEL_INTEGRITY && !defined(KERNEL_INTEGRITY_WT)))
	/* Watchtower
	 *
	 * If we have a Watchtower monitor it will setup CPACR_EL1 for us, touching
	 * it here would trap to EL3.
	 */

	// Enable NEON
	mov		x0, #(CPACR_FPEN_ENABLE)
	msr		CPACR_EL1, x0
#endif

	// Clear thread pointer
	msr		TPIDR_EL1, xzr						// Set thread register


#if defined(APPLE_ARM64_ARCH_FAMILY)
	// Initialization common to all Apple targets
	ARM64_IS_PCORE x15
	ARM64_READ_EP_SPR x15, x12, ARM64_REG_EHID4, ARM64_REG_HID4
	orr		x12, x12, ARM64_REG_HID4_DisDcMVAOps
	orr		x12, x12, ARM64_REG_HID4_DisDcSWL2Ops
	ARM64_WRITE_EP_SPR x15, x12, ARM64_REG_EHID4, ARM64_REG_HID4
#endif  // APPLE_ARM64_ARCH_FAMILY

	// Read MIDR before start of per-SoC tunables
	mrs x12, MIDR_EL1

#if defined(APPLELIGHTNING)
	// Cebu <B0 is deprecated and unsupported (see rdar://problem/42835678)
	EXEC_COREEQ_REVLO MIDR_CEBU_LIGHTNING, CPU_VERSION_B0, x12, x13
	b .
	EXEC_END
	EXEC_COREEQ_REVLO MIDR_CEBU_THUNDER, CPU_VERSION_B0, x12, x13
	b .
	EXEC_END
#endif

	APPLY_TUNABLES x12, x13



#if HAS_CLUSTER
	// Unmask external IRQs if we're restarting from non-retention WFI
	mrs		x9, ARM64_REG_CYC_OVRD
	and		x9, x9, #(~(ARM64_REG_CYC_OVRD_irq_mask | ARM64_REG_CYC_OVRD_fiq_mask))
	msr		ARM64_REG_CYC_OVRD, x9
#endif

	// If x21 != 0, we're doing a warm reset, so we need to trampoline to the kernel pmap.
	cbnz	x21, Ltrampoline

	// Set KVA of boot args as first arg
	add		x0, x20, x22
	sub		x0, x0, x23

#if KASAN
	mov	x20, x0
	mov	x21, lr

	// x0: boot args
	// x1: KVA page table phys base
	mrs	x1, TTBR1_EL1
	bl	EXT(kasan_bootstrap)

	mov	x0, x20
	mov	lr, x21
#endif

	// Return to arm_init()
	ret

Ltrampoline:
	// Load VA of the trampoline
	adrp	x0, arm_init_tramp@page
	add		x0, x0, arm_init_tramp@pageoff
	add		x0, x0, x22
	sub		x0, x0, x23

	// Branch to the trampoline
	br		x0

/*
 * V=P to KVA trampoline.
 *	x0 - KVA of cpu data pointer
 */
	.text
	.align 2
arm_init_tramp:
	/* On a warm boot, the full kernel translation table is initialized in
	 * addition to the bootstrap tables. The layout is as follows:
	 *
	 *  +--Top of Memory--+
	 *         ...
	 *  |                 |
	 *  |  Primary Kernel |
	 *  |   Trans. Table  |
	 *  |                 |
	 *  +--Top + 5 pages--+
	 *  |                 |
	 *  |  Invalid Table  |
	 *  |                 |
	 *  +--Top + 4 pages--+
	 *  |                 |
	 *  |    KVA Table    |
	 *  |                 |
	 *  +--Top + 2 pages--+
	 *  |                 |
	 *  |    V=P Table    |
	 *  |                 |
	 *  +--Top of Kernel--+
	 *  |                 |
	 *  |  Kernel Mach-O  |
	 *  |                 |
	 *         ...
	 *  +---Kernel Base---+
	 */


	mov		x19, lr
#if defined(HAS_VMSA_LOCK)
	bl		EXT(vmsa_lock)
#endif
	// Convert CPU data PA to VA and set as first argument
	mov		x0, x21
	bl		EXT(phystokv)

	mov		lr, x19

	/* Return to arm_init() */
	ret

//#include	"globals_asm.h"

/* vim: set ts=4: */

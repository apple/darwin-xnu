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
#include <arm64/exception_asm.h>

#if __ARM_KERNEL_PROTECT__
#include <arm/pmap.h>
#endif /* __ARM_KERNEL_PROTECT__ */



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

#if !(defined(KERNEL_INTEGRITY_KTRR))
	// Set low reset vector before attempting any loads
	adrp    x0, EXT(LowExceptionVectorBase)@page
	add     x0, x0, EXT(LowExceptionVectorBase)@pageoff
	msr     VBAR_EL1, x0
#endif


#if defined(KERNEL_INTEGRITY_KTRR)
	/*
	 * Set KTRR registers immediately after wake/resume
	 *
	 * During power on reset, XNU stashed the kernel text region range values
	 * into __DATA,__const which should be protected by AMCC RoRgn at this point.
	 * Read this data and program/lock KTRR registers accordingly.
	 * If either values are zero, we're debugging kernel so skip programming KTRR.
	 */

	/* spin until bootstrap core has completed machine lockdown */
	adrp	x17, EXT(lockdown_done)@page
1:
	ldr	x18, [x17, EXT(lockdown_done)@pageoff]
	cbz	x18, 1b

	// load stashed rorgn_begin
	adrp	x17, EXT(rorgn_begin)@page
	add		x17, x17, EXT(rorgn_begin)@pageoff
	ldr		x17, [x17]
	// if rorgn_begin is zero, we're debugging. skip enabling ktrr
	cbz		x17, Lskip_ktrr

	// load stashed rorgn_end
	adrp	x19, EXT(rorgn_end)@page
	add		x19, x19, EXT(rorgn_end)@pageoff
	ldr		x19, [x19]
	cbz		x19, Lskip_ktrr

	// program and lock down KTRR
	// subtract one page from rorgn_end to make pinst insns NX
	msr		ARM64_REG_KTRR_LOWER_EL1, x17
	sub		x19, x19, #(1 << (ARM_PTE_SHIFT-12)), lsl #12 
	msr		ARM64_REG_KTRR_UPPER_EL1, x19
	mov		x17, #1
	msr		ARM64_REG_KTRR_LOCK_EL1, x17
Lskip_ktrr:
#endif /* defined(KERNEL_INTEGRITY_KTRR) */

	// Process reset handlers
	adrp	x19, EXT(ResetHandlerData)@page			// Get address of the reset handler data
	add		x19, x19, EXT(ResetHandlerData)@pageoff
	mrs		x15, MPIDR_EL1						// Load MPIDR to get CPU number
	and		x0, x15, #0xFF						// CPU number is in MPIDR Affinity Level 0
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

#if defined(KERNEL_INTEGRITY_KTRR)
/*
 * Provide a global symbol so that we can narrow the V=P mapping to cover
 * this page during arm_vm_init.
 */
.align ARM_PGSHIFT
.globl EXT(bootstrap_instructions)
LEXT(bootstrap_instructions)

#endif /* defined(KERNEL_INTEGRITY_KTRR)*/
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
#if defined(KERNEL_INTEGRITY_KTRR)
	// This is done right away in reset vector for pre-KTRR devices
	// Set low reset vector now that we are in the KTRR-free zone
	adrp	x0, EXT(LowExceptionVectorBase)@page
	add		x0, x0, EXT(LowExceptionVectorBase)@pageoff
	MSR_VBAR_EL1_X0
#endif /* defined(KERNEL_INTEGRITY_KTRR)*/

	// x20 set to BootArgs phys address
	// x21 set to cpu data phys address

	// Get the kernel memory parameters from the boot args
	ldr		x22, [x20, BA_VIRT_BASE]			// Get the kernel virt base
	ldr		x23, [x20, BA_PHYS_BASE]			// Get the kernel phys base
	ldr		x24, [x20, BA_MEM_SIZE]				// Get the physical memory size
	ldr		x25, [x20, BA_TOP_OF_KERNEL_DATA]	// Get the top of the kernel data
	ldr		x26, [x20, BA_BOOT_FLAGS]			// Get the kernel boot flags


	// Set TPIDRRO_EL0 with the CPU number
	ldr		x0, [x21, CPU_NUMBER_GS]
	msr		TPIDRRO_EL0, x0

	// Set the exception stack pointer
	ldr		x0, [x21, CPU_EXCEPSTACK_TOP]


	// Set SP_EL1 to exception stack
#if defined(KERNEL_INTEGRITY_KTRR)
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


	// Get the kernel memory parameters from the boot args
	ldr		x22, [x20, BA_VIRT_BASE]			// Get the kernel virt base
	ldr		x23, [x20, BA_PHYS_BASE]			// Get the kernel phys base
	ldr		x24, [x20, BA_MEM_SIZE]				// Get the physical memory size
	ldr		x25, [x20, BA_TOP_OF_KERNEL_DATA]	// Get the top of the kernel data
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
#if defined(KERNEL_INTEGRITY_KTRR)
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
	mov		x1, x25								// Start at top of kernel
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
	 * may continue to use block mappings, but we will only map xnu's mach
	 * header to the end of memory.
	 *
	 * Given that iBoot guarantees that the unslid kernelcache base address
	 * will begin on an L2 boundary, this should prevent us from accidentally
	 * mapping TZ0.
	 */
	adrp	x0, EXT(_mh_execute_header)@page	// Use xnu's mach header as the start address
	add	x0, x0, EXT(_mh_execute_header)@pageoff

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
 *	x25 - PA of the end of the kernel
 *	 lr - KVA of C init routine
 *	 sp - SP_EL0 selected
 *
 *	SP_EL0 - KVA of CPU's interrupt stack
 *	SP_EL1 - KVA of CPU's exception stack
 *	TPIDRRO_EL0 - CPU number
 */
common_start:
	// Set the translation control register.
	adrp	x0,     EXT(sysreg_restore)@page		// Load TCR value from the system register restore structure
	add		x0, x0, EXT(sysreg_restore)@pageoff
	ldr		x1, [x0, SR_RESTORE_TCR_EL1]
	MSR_TCR_EL1_X1

	/* Set up translation table base registers.
	 *	TTBR0 - V=P table @ top of kernel
	 *	TTBR1 - KVA table @ top of kernel + 1 page
	 */
#if defined(KERNEL_INTEGRITY_KTRR)
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

#if defined(APPLEHURRICANE)

	// <rdar://problem/26726624> Increase Snoop reservation in EDB to reduce starvation risk
	// Needs to be done before MMU is enabled
	mrs	x12, ARM64_REG_HID5
	and	x12, x12, (~ARM64_REG_HID5_CrdEdbSnpRsvd_mask)
	orr x12, x12, ARM64_REG_HID5_CrdEdbSnpRsvd_VALUE
	msr	ARM64_REG_HID5, x12

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
	orr		x0, x0, #(APCTL_EL1_KernKeyEn)
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
	mov		x0, #(SCTLR_EL1_DEFAULT & 0xFFFF)
	mov		x1, #(SCTLR_EL1_DEFAULT & 0xFFFF0000)
	orr		x0, x0, x1
	orr		x0, x0, #(SCTLR_PACIB_ENABLED) /* IB is ROP */

#if DEBUG || DEVELOPMENT
	and		x2, x26, BA_BOOT_FLAGS_DISABLE_JOP
#if __APCFG_SUPPORTED__
	// for APCFG systems, JOP keys are always on for EL1 unless ELXENKEY is cleared.
	// JOP keys for EL0 will be toggled on the first time we pmap_switch to a pmap that has JOP enabled
	cbz		x2, Lenable_mmu
	mrs		x3, APCFG_EL1
	and		x3, x3, #~(APCFG_EL1_ELXENKEY)
	msr		APCFG_EL1, x3
#else /* __APCFG_SUPPORTED__ */
	cbnz	x2, Lenable_mmu
#endif /* __APCFG_SUPPORTED__ */
#endif /* DEBUG || DEVELOPMENT */

#if !__APCFG_SUPPORTED__
	MOV64	x1, SCTLR_JOP_KEYS_ENABLED
	orr 	x0, x0, x1
#endif /* !__APCFG_SUPPORTED__ */
Lenable_mmu:
#else  /* HAS_APPLE_PAC */

	// Enable caches and MMU
	mov		x0, #(SCTLR_EL1_DEFAULT & 0xFFFF)
	mov		x1, #(SCTLR_EL1_DEFAULT & 0xFFFF0000)
	orr		x0, x0, x1
#endif /* HAS_APPLE_PAC */
	MSR_SCTLR_EL1_X0
	isb		sy

	MOV32	x1, SCTLR_EL1_DEFAULT
#if HAS_APPLE_PAC
	orr		x1, x1, #(SCTLR_PACIB_ENABLED)
#if !__APCFG_SUPPORTED__
	MOV64	x2, SCTLR_JOP_KEYS_ENABLED
#if (DEBUG || DEVELOPMENT)
	// Ignore the JOP bits, since we can't predict at compile time whether BA_BOOT_FLAGS_DISABLE_JOP is set
	bic		x0, x0, x2
#else
	orr		x1, x1, x2
#endif /* (DEBUG || DEVELOPMENT) */
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
	mov		x0, #0
	msr		TPIDR_EL1, x0						// Set thread register

#if defined(APPLE_ARM64_ARCH_FAMILY)
	// Initialization common to all Apple targets
	ARM64_IS_PCORE x15
	ARM64_READ_EP_SPR x15, x12, ARM64_REG_EHID4, ARM64_REG_HID4
	orr		x12, x12, ARM64_REG_HID4_DisDcMVAOps
	orr		x12, x12, ARM64_REG_HID4_DisDcSWL2Ops
	ARM64_WRITE_EP_SPR x15, x12, ARM64_REG_EHID4, ARM64_REG_HID4
#endif  // APPLE_ARM64_ARCH_FAMILY

#if defined(APPLETYPHOON)
	//
	// Typhoon-Specific initialization
	// For tunable summary, see <rdar://problem/13503621>
	//

	//
	// Disable LSP flush with context switch to work around bug in LSP
	// that can cause Typhoon to wedge when CONTEXTIDR is written.
	// <rdar://problem/12387704>
	//

	mrs		x12, ARM64_REG_HID0
	orr		x12, x12, ARM64_REG_HID0_LoopBuffDisb
	msr		ARM64_REG_HID0, x12

	mrs		x12, ARM64_REG_HID1
	orr		x12, x12, ARM64_REG_HID1_rccDisStallInactiveIexCtl
	msr		ARM64_REG_HID1, x12

	mrs		x12, ARM64_REG_HID3
	orr		x12, x12, ARM64_REG_HID3_DisXmonSnpEvictTriggerL2StarvationMode
	msr		ARM64_REG_HID3, x12

	mrs		x12, ARM64_REG_HID5
	and		x12, x12, (~ARM64_REG_HID5_DisHwpLd)
	and		x12, x12, (~ARM64_REG_HID5_DisHwpSt)
	msr		ARM64_REG_HID5, x12

	// Change the default memcache data set ID from 0 to 15 for all agents
	mrs		x12, ARM64_REG_HID8
	orr		x12, x12, (ARM64_REG_HID8_DataSetID0_VALUE | ARM64_REG_HID8_DataSetID1_VALUE)
#if ARM64_BOARD_CONFIG_T7001
	orr		x12, x12, ARM64_REG_HID8_DataSetID2_VALUE
#endif	// ARM64_BOARD_CONFIG_T7001
	msr		ARM64_REG_HID8, x12
	isb		sy
#endif	// APPLETYPHOON

#if defined(APPLETWISTER)

	// rdar://problem/36112905: Set CYC_CFG:skipInit to pull in isAlive by one DCLK
	// to work around potential hang.  Must only be applied to Maui C0.
	mrs		x12, MIDR_EL1
	ubfx		x13, x12, #MIDR_EL1_PNUM_SHIFT, #12
	cmp		x13, #4		// Part number 4 => Maui, 5 => Malta/Elba
	bne		Lskip_isalive
	ubfx		x13, x12, #MIDR_EL1_VAR_SHIFT, #4
	cmp		x13, #2		// variant 2 => Maui C0
	b.lt		Lskip_isalive

	mrs		x12, ARM64_REG_CYC_CFG
	orr		x12, x12, ARM64_REG_CYC_CFG_skipInit
	msr		ARM64_REG_CYC_CFG, x12

Lskip_isalive:

	mrs		x12, ARM64_REG_HID11
	and		x12, x12, (~ARM64_REG_HID11_DisFillC1BubOpt)
	msr		ARM64_REG_HID11, x12

	// Change the default memcache data set ID from 0 to 15 for all agents
	mrs		x12, ARM64_REG_HID8
	orr		x12, x12, (ARM64_REG_HID8_DataSetID0_VALUE | ARM64_REG_HID8_DataSetID1_VALUE)
	orr		x12, x12, (ARM64_REG_HID8_DataSetID2_VALUE | ARM64_REG_HID8_DataSetID3_VALUE)
	msr		ARM64_REG_HID8, x12

	// Use 4-cycle MUL latency to avoid denormal stalls
	mrs		x12, ARM64_REG_HID7
	orr		x12, x12, #ARM64_REG_HID7_disNexFastFmul
	msr		ARM64_REG_HID7, x12

	// disable reporting of TLB-multi-hit-error
	// <rdar://problem/22163216> 
	mrs		x12, ARM64_REG_LSU_ERR_STS
	and		x12, x12, (~ARM64_REG_LSU_ERR_STS_L1DTlbMultiHitEN)
	msr		ARM64_REG_LSU_ERR_STS, x12

	isb		sy
#endif	// APPLETWISTER

#if defined(APPLEHURRICANE)

	// IC prefetch configuration
	// <rdar://problem/23019425>
	mrs		x12, ARM64_REG_HID0
	and		x12, x12, (~ARM64_REG_HID0_ICPrefDepth_bmsk)
	orr		x12, x12, (1 << ARM64_REG_HID0_ICPrefDepth_bshift)
	orr		x12, x12, ARM64_REG_HID0_ICPrefLimitOneBrn
	msr		ARM64_REG_HID0, x12

	// disable reporting of TLB-multi-hit-error
	// <rdar://problem/22163216> 
	mrs		x12, ARM64_REG_LSU_ERR_CTL
	and		x12, x12, (~ARM64_REG_LSU_ERR_CTL_L1DTlbMultiHitEN)
	msr		ARM64_REG_LSU_ERR_CTL, x12

	// disable crypto fusion across decode groups
	// <rdar://problem/27306424>
	mrs		x12, ARM64_REG_HID1
	orr		x12, x12, ARM64_REG_HID1_disAESFuseAcrossGrp
	msr		ARM64_REG_HID1, x12

#if defined(ARM64_BOARD_CONFIG_T8011)
	// Clear DisDcZvaCmdOnly 
	// Per Myst A0/B0 tunables document
	// <rdar://problem/27627428> Myst: Confirm ACC Per-CPU Tunables
	mrs		x12, ARM64_REG_HID3
	and             x12, x12, ~ARM64_REG_HID3_DisDcZvaCmdOnly
	msr             ARM64_REG_HID3, x12

	mrs		x12, ARM64_REG_EHID3
	and             x12, x12, ~ARM64_REG_EHID3_DisDcZvaCmdOnly
	msr             ARM64_REG_EHID3, x12
#endif /* defined(ARM64_BOARD_CONFIG_T8011) */

#endif // APPLEHURRICANE

#if defined(APPLEMONSOON)

	/***** Tunables that apply to all skye cores, all chip revs *****/

	// <rdar://problem/28512310> SW WAR/eval: WKdm write ack lost when bif_wke_colorWrAck_XXaH asserts concurrently for both colors
	mrs		x12, ARM64_REG_HID8
	orr		x12, x12, #ARM64_REG_HID8_WkeForceStrictOrder
	msr		ARM64_REG_HID8, x12

	// Skip if not E-core
	ARM64_IS_PCORE x15
	cbnz		x15, Lskip_skye_ecore_only

	/***** Tunables that only apply to skye e-cores, all chip revs *****/

	// <rdar://problem/30423928>: Atomic launch eligibility is erroneously taken away when a store at SMB gets invalidated
	mrs		x12, ARM64_REG_EHID11
	and		x12, x12, ~(ARM64_REG_EHID11_SmbDrainThresh_mask)
	msr		ARM64_REG_EHID11, x12

Lskip_skye_ecore_only:

	SKIP_IF_CPU_VERSION_GREATER_OR_EQUAL x12, MONSOON_CPU_VERSION_B0, Lskip_skye_a0_workarounds

	// Skip if not E-core
	cbnz		x15, Lskip_skye_a0_ecore_only

	/***** Tunables that only apply to skye e-cores, chip revs < B0 *****/

	// Disable downstream fill bypass logic
	// <rdar://problem/28545159> [Tunable] Skye - L2E fill bypass collision from both pipes to ecore
	mrs		x12, ARM64_REG_EHID5
	orr		x12, x12, ARM64_REG_EHID5_DisFillByp
	msr		ARM64_REG_EHID5, x12

	// Disable forwarding of return addresses to the NFP 
	// <rdar://problem/30387067> Skye: FED incorrectly taking illegal va exception
	mrs		x12, ARM64_REG_EHID0
	orr		x12, x12, ARM64_REG_EHID0_nfpRetFwdDisb
	msr		ARM64_REG_EHID0, x12

Lskip_skye_a0_ecore_only:

	/***** Tunables that apply to all skye cores, chip revs < B0 *****/

	// Disable clock divider gating
	// <rdar://problem/30854420> [Tunable/Errata][cpu_1p_1e] [CPGV2] ACC power down issue when link FSM switches from GO_DN to CANCEL and at the same time upStreamDrain request is set.
	mrs		x12, ARM64_REG_HID6
	orr		x12, x12, ARM64_REG_HID6_DisClkDivGating
	msr		ARM64_REG_HID6, x12

	// Disable clock dithering
	// <rdar://problem/29022199> [Tunable] Skye A0: Linux: LLC PIO Errors
	mrs		x12, ARM64_REG_ACC_OVRD
	orr		x12, x12, ARM64_REG_ACC_OVRD_dsblClkDtr
	msr		ARM64_REG_ACC_OVRD, x12

	mrs		x12, ARM64_REG_ACC_EBLK_OVRD
	orr		x12, x12, ARM64_REG_ACC_OVRD_dsblClkDtr
	msr		ARM64_REG_ACC_EBLK_OVRD, x12

Lskip_skye_a0_workarounds:

	SKIP_IF_CPU_VERSION_LESS_THAN x12, MONSOON_CPU_VERSION_B0, Lskip_skye_post_a1_workarounds

	/***** Tunables that apply to all skye cores, chip revs >= B0 *****/

	// <rdar://problem/32512836>: Disable refcount syncing between E and P
	mrs		x12, ARM64_REG_CYC_OVRD
	and		x12, x12, ~ARM64_REG_CYC_OVRD_dsblSnoopTime_mask
	orr		x12, x12, ARM64_REG_CYC_OVRD_dsblSnoopPTime
	msr		ARM64_REG_CYC_OVRD, x12

Lskip_skye_post_a1_workarounds:

#endif /* defined(APPLEMONSOON) */







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
	// Convert CPU data PA to VA and set as first argument
	mov		x0, x21
	bl		EXT(phystokv)

	mov		lr, x19

	/* Return to arm_init() */
	ret

//#include	"globals_asm.h"

/* vim: set ts=4: */

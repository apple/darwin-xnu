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
#include <pexpert/arm64/cyclone.h>
#include <pexpert/arm64/hurricane.h>
#include <mach_assert.h>
#include <machine/asm.h>
#include "assym.s"

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
	bl		_pinst_set_tcr
	mov		lr, x1
#else
	msr		TCR_EL1, x1
#endif
.endmacro

.macro MSR_TTBR1_EL1_X0
#if defined(KERNEL_INTEGRITY_KTRR)
	mov		x1, lr
	bl		_pinst_set_ttbr1
	mov		lr, x1
#else
	msr		TTBR1_EL1, x0
#endif
.endmacro

.macro MSR_SCTLR_EL1_X0
#if defined(KERNEL_INTEGRITY_KTRR) 
	mov		x1, lr

	// This may abort, do so on SP1
	bl		_pinst_spsel_1

	bl		_pinst_set_sctlr
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
	// Preserve x0 for start_first_cpu, if called

	// Unlock the core for debugging
	msr		OSLAR_EL1, xzr

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

	// load stashed rorgn_begin
	adrp	x17, EXT(rorgn_begin)@page
	add		x17, x17, EXT(rorgn_begin)@pageoff
	ldr		x17, [x17]
	// if rorgn_begin is zero, we're debugging. skip enabling ktrr
	cbz		x17, 1f

	// load stashed rorgn_end
	adrp	x19, EXT(rorgn_end)@page
	add		x19, x19, EXT(rorgn_end)@pageoff
	ldr		x19, [x19]
	cbz		x19, 1f

	// program and lock down KTRR
	// subtract one page from rorgn_end to make pinst insns NX
	msr		ARM64_REG_KTRR_LOWER_EL1, x17
	sub		x19, x19, #(1 << (ARM_PTE_SHIFT-12)), lsl #12 
	msr		ARM64_REG_KTRR_UPPER_EL1, x19
	mov		x17, #1
	msr		ARM64_REG_KTRR_LOCK_EL1, x17

1:
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
	b.eq		Lfound_cpu_data_entry				// Branch if match
Lnext_cpu_data_entry:
	add		x1, x1, #16					// Increment to the next cpu data entry
	cmp		x1, x3
	b.eq		Lskip_cpu_reset_handler				// Not found
	b		Lcheck_cpu_data_entry	// loop
Lfound_cpu_data_entry:
	adrp		x20, EXT(const_boot_args)@page
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
	bne	Lskip_cpu_reset_handler
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

	.align	3
	.globl  EXT(ResetHandlerData)
LEXT(ResetHandlerData)
	.space  (rhdSize_NUM),0		// (filled with 0s)

	.align	3
	.global EXT(LowResetVectorEnd)
LEXT(LowResetVectorEnd)
	.global	EXT(SleepToken)
#if WITH_CLASSIC_S2R
LEXT(SleepToken)
	.space	(stSize_NUM),0
#endif


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
	msr		DAIFSet, #(DAIFSC_ALL)				// Disable all interrupts

	// Get the kernel memory parameters from the boot args
	ldr		x22, [x20, BA_VIRT_BASE]			// Get the kernel virt base
	ldr		x23, [x20, BA_PHYS_BASE]			// Get the kernel phys base
	ldr		x24, [x20, BA_MEM_SIZE]				// Get the physical memory size
	ldr		x25, [x20, BA_TOP_OF_KERNEL_DATA]	// Get the top of the kernel data

	// Set TPIDRRO_EL0 with the CPU number
	ldr		x0, [x21, CPU_NUMBER_GS]
	msr		TPIDRRO_EL0, x0

	// Set the exception stack pointer
	ldr		x0, [x21, CPU_EXCEPSTACK_TOP]


	// Set SP_EL1 to exception stack
#if defined(KERNEL_INTEGRITY_KTRR)
	mov		x1, lr
	bl		_pinst_spsel_1
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
 * _start_first_cpu
 * Cold boot init routine.  Called from __start
 *   x0 - Boot args
 */
	.align 2
	.globl EXT(start_first_cpu)
LEXT(start_first_cpu)

	// Unlock the core for debugging
	msr		OSLAR_EL1, xzr
	mov		x20, x0
	mov		x21, xzr

	// Set low reset vector before attempting any loads
	adrp	x0, EXT(LowExceptionVectorBase)@page
	add		x0, x0, EXT(LowExceptionVectorBase)@pageoff
	MSR_VBAR_EL1_X0



	// Get the kernel memory parameters from the boot args
	ldr		x22, [x20, BA_VIRT_BASE]			// Get the kernel virt base
	ldr		x23, [x20, BA_PHYS_BASE]			// Get the kernel phys base
	ldr		x24, [x20, BA_MEM_SIZE]				// Get the physical memory size
	ldr		x25, [x20, BA_TOP_OF_KERNEL_DATA]	// Get the top of the kernel data

	// Set CPU number to 0
	msr		TPIDRRO_EL0, x21

	// Set up exception stack pointer
	adrp	x0, EXT(excepstack_top)@page		// Load top of exception stack
	add		x0, x0, EXT(excepstack_top)@pageoff
	add		x0, x0, x22							// Convert to KVA
	sub		x0, x0, x23

	// Set SP_EL1 to exception stack
#if defined(KERNEL_INTEGRITY_KTRR)
	bl		_pinst_spsel_1
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
#if __ARM64_TWO_LEVEL_PMAP__
	/*
	 * If we are using a two level scheme, we don't need the L1 entries, so:
	 *      Page 1 - V=P L2 table
	 *      Page 2 - KVA L2 table
	 */
#endif

	// Invalidate all entries in the bootstrap page tables
	mov		x0, #(ARM_TTE_EMPTY)				// Load invalid entry template
	mov		x1, x25								// Start at top of kernel
	mov		x2, #(TTE_PGENTRIES)				// Load number of entries per page
#if __ARM64_TWO_LEVEL_PMAP__
	lsl		x2, x2, #1							// Shift by 1 for num entries on 2 pages
#else
	lsl		x2, x2, #2							// Shift by 2 for num entries on 4 pages
#endif
	sub		x2, x2, #1							// Subtract one to terminate on last entry
Linvalidate_bootstrap:							// do {
	str		x0, [x1], #(1 << TTE_SHIFT)			//   Invalidate and advance
	subs	x2, x2, #1							//   entries--
	b.ne	Linvalidate_bootstrap				// } while (entries != 0)

	/* Load addresses for page table construction macros
	 *  x0 - Physical base (used to identify V=P section to set up)
	 *	x1 - V=P L1 table base
	 *	x2 - V=P L2 table base
	 *	x3 - KVA L1 table base
	 *	x4 - KVA L2 table base
	 *	x5 - Mem size in entries (up to 1GB)
	 */

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
	add		x0, x0, EXT(_mh_execute_header)@pageoff
#if __ARM64_TWO_LEVEL_PMAP__
	/*
	 * We don't need the L1 entries in this case, so skip them.
	 */
	mov		x2, x25								// Load V=P L2 table address
	add		x4, x2, PGBYTES						// Load KVA L2 table address
#else
	mov		x1, x25								// Load V=P L1 table address
	add		x2, x1, PGBYTES						// Load V=P L2 table address
	add		x3, x2, PGBYTES						// Load KVA L1 table address
	add		x4, x3, PGBYTES						// Load KVA L2 table address
#endif
	/*
	 * We must adjust the amount we wish to map in order to account for the
	 * memory preceeding xnu's mach header.
	 */
	sub		x5, x0, x23							// Map from the mach header up to the end of our memory
	sub		x5, x24, x5
	lsr		x5, x5, #(ARM_TT_L2_SHIFT)
	mov		x6, #(TTE_PGENTRIES)				// Load number of L2 entries per page
	cmp		x5, x6								// If memsize requires more than 1 page of entries
	csel	x5, x5, x6, lt						// ... round down to a single page (first 1GB)

#if !__ARM64_TWO_LEVEL_PMAP__
	/* Create entry for L2 table in V=P L1 table
	 * create_l1_table_entry(V=P, L1 table, L2 table, scratch1, scratch2, scratch3)
	 */
	create_l1_table_entry	x0, x1, x2, x10, x11, x12
#endif

	/* Create block entry in V=P L2 table
	 * create_l2_block_entries(V=P virt, V=P phys, L2 table, num_ents, scratch1, scratch2, scratch3)
	 */
	create_l2_block_entries x0, x0, x2, x5, x10, x11, x12, x13

#if !__ARM64_TWO_LEVEL_PMAP__
	/* Create entry for L2 table in KVA L1 table
	 * create_l1_table_entry(virt_base, L1 table, L2 table, scratch1, scratch2, scratch3)
	 */
	create_l1_table_entry	x22, x3, x4, x10, x11, x12
#endif

	/* Create block entries in KVA L2 table
	 * create_l2_block_entries(virt_base, phys_base, L2 table, num_ents, scratch1, scratch2, scratch3)
	 */
	create_l2_block_entries	x22, x23, x4, x5, x10, x11, x12, x13

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
 *	x24	- Physical memory size
 *	x25 - PA of the end of the kernl
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
	 *	TTBR1 - KVA table @ top of kernel + 2 pages
	 */
#if defined(KERNEL_INTEGRITY_KTRR)
	/* Note that for KTRR configurations, the V=P map will be modified by
	 * arm_vm_init.c.
	 */
#endif
	and		x0, x25, #(TTBR_BADDR_MASK)
#if __ARM_KERNEL_PROTECT__
	/* We start out with a kernel ASID. */
	orr		x0, x0, #(1 << TTBR_ASID_SHIFT)
#endif /* __ARM_KERNEL_PROTECT__ */
	msr		TTBR0_EL1, x0
#if __ARM64_TWO_LEVEL_PMAP__
	/*
	 * If we're using a two level pmap, we'll only need a
	 * single page per bootstrap pmap.
	 */
	mov		x12, #1
#else
	/*
	 * If we're using a three level pmap, we'll need two
	 * pages per bootstrap pmap.
	 */
	mov		x12, #2
#endif
	add		x0, x25, x12, lsl PGSHIFT
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
	msr		MAIR_EL1, x0

	// Disable interrupts
	msr     DAIFSet, #(DAIFSC_IRQF | DAIFSC_FIQF)

#if defined(APPLEHURRICANE)

	// <rdar://problem/26726624> Increase Snoop reservation in EDB to reduce starvation risk
	// Needs to be done before MMU is enabled
	mrs	x12, ARM64_REG_HID5
	and	x12, x12, (~ARM64_REG_HID5_CrdEdbSnpRsvd_mask)
	orr x12, x12, ARM64_REG_HID5_CrdEdbSnpRsvd_VALUE
	msr	ARM64_REG_HID5, x12

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


	// Enable caches and MMU
	mov		x0, #(SCTLR_EL1_DEFAULT & 0xFFFF)
	mov		x1, #(SCTLR_EL1_DEFAULT & 0xFFFF0000)
	orr		x0, x0, x1
	MSR_SCTLR_EL1_X0
	isb		sy

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

#if defined(APPLECYCLONE) || defined(APPLETYPHOON)
	//
	// Cyclone/Typhoon-Specific initialization
	// For tunable summary, see <rdar://problem/13503621>
	//

	//
	// Disable LSP flush with context switch to work around bug in LSP
	// that can cause Cyclone to wedge when CONTEXTIDR is written.
	// <rdar://problem/12387704>
	//

	mrs		x12, ARM64_REG_HID0
	orr		x12, x12, ARM64_REG_HID0_LoopBuffDisb
	msr		ARM64_REG_HID0, x12
	
	mrs		x12, ARM64_REG_HID1
	orr		x12, x12, ARM64_REG_HID1_rccDisStallInactiveIexCtl
#if defined(APPLECYCLONE)
	orr		x12, x12, ARM64_REG_HID1_disLspFlushWithContextSwitch
#endif
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
#endif	// APPLECYCLONE || APPLETYPHOON

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
	bl	_kasan_bootstrap

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


	adrp	x0, EXT(invalid_ttep)@page
	add		x0, x0, EXT(invalid_ttep)@pageoff
	ldr		x0, [x0]
#if __ARM_KERNEL_PROTECT__
	/* We start out with a kernel ASID. */
	orr		x0, x0, #(1 << TTBR_ASID_SHIFT)
#endif /* __ARM_KERNEL_PROTECT__ */

	msr		TTBR0_EL1, x0

	// Convert CPU data PA to VA and set as first argument
	add		x0, x21, x22
	sub		x0, x0, x23
	mov		x1, #0

	// Make sure that the TLB flush happens after the registers are set!
	isb		sy

	// Synchronize system for TTBR updates
	tlbi	vmalle1
	dsb		sy
	isb		sy

	/* Return to arm_init() */
	ret

//#include	"globals_asm.h"

/* vim: set ts=4: */

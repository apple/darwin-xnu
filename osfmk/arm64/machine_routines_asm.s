/*
 * Copyright (c) 2007-2015 Apple Inc. All rights reserved.
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
#include <arm64/exception_asm.h>
#include <arm64/machine_machdep.h>
#include <arm64/proc_reg.h>
#include <arm/pmap.h>
#include <pexpert/arm64/board_config.h>
#include <sys/errno.h>
#include "assym.s"



#if HAS_BP_RET

/*
 * void set_bp_ret(void)
 * Helper function to enable branch predictor state retention
 * across ACC sleep
 */

	.align 2
	.globl EXT(set_bp_ret)
LEXT(set_bp_ret)
	// Load bpret boot-arg
	adrp		x14, EXT(bp_ret)@page
	add		x14, x14, EXT(bp_ret)@pageoff
	ldr		w14, [x14]

	mrs		x13, ARM64_REG_ACC_CFG
	and		x13, x13, (~(ARM64_REG_ACC_CFG_bpSlp_mask << ARM64_REG_ACC_CFG_bpSlp_shift))
	and		x14, x14, #(ARM64_REG_ACC_CFG_bpSlp_mask)
	orr		x13, x13, x14, lsl #(ARM64_REG_ACC_CFG_bpSlp_shift)
	msr		ARM64_REG_ACC_CFG, x13

	ret
#endif // HAS_BP_RET

#if HAS_NEX_PG
	.align 2
	.globl EXT(set_nex_pg)
LEXT(set_nex_pg)
	mrs		x14, MPIDR_EL1
	// Skip if this isn't a p-core; NEX powergating isn't available for e-cores
	and		x14, x14, #(MPIDR_PNE)
	cbz		x14, Lnex_pg_done

	// Set the SEG-recommended value of 12 additional reset cycles
	HID_INSERT_BITS	ARM64_REG_HID13, ARM64_REG_HID13_RstCyc_mask, ARM64_REG_HID13_RstCyc_val, x13
	HID_SET_BITS ARM64_REG_HID14, ARM64_REG_HID14_NexPwgEn, x13

Lnex_pg_done:
	ret

#endif // HAS_NEX_PG

/*	uint32_t get_fpscr(void):
 *		Returns (FPSR | FPCR).
 */
	.align	2
	.globl	EXT(get_fpscr)
LEXT(get_fpscr)
#if	__ARM_VFP__
	mrs	x1, FPSR			// Grab FPSR
	mov	x4, #(FPSR_MASK & 0xFFFF)
	mov	x5, #(FPSR_MASK & 0xFFFF0000)
	orr	x0, x4, x5
	and	x1, x1, x0			// Be paranoid, and clear bits we expect to
						// be clear
	mrs	x2, FPCR			// Grab FPCR
	mov	x4, #(FPCR_MASK & 0xFFFF)
	mov	x5, #(FPCR_MASK & 0xFFFF0000)
	orr	x0, x4, x5
	and	x2, x2, x0			// Be paranoid, and clear bits we expect to
						// be clear
	orr	x0, x1, x2			// OR them to get FPSCR equivalent state
#else
	mov	x0, #0
#endif
	ret
	.align	2
	.globl	EXT(set_fpscr)
/*	void set_fpscr(uint32_t value):
 *		Set the FPCR and FPSR registers, based on the given value; a
 *		noteworthy point is that unlike 32-bit mode, 64-bit mode FPSR
 *		and FPCR are not responsible for condition codes.
 */
LEXT(set_fpscr)
#if	__ARM_VFP__
	mov	x4, #(FPSR_MASK & 0xFFFF)
	mov	x5, #(FPSR_MASK & 0xFFFF0000)
	orr	x1, x4, x5
	and	x1, x1, x0			// Clear the bits that don't apply to FPSR
	mov	x4, #(FPCR_MASK & 0xFFFF)
	mov	x5, #(FPCR_MASK & 0xFFFF0000)
	orr	x2, x4, x5
	and	x2, x2, x0			// Clear the bits that don't apply to FPCR
	msr	FPSR, x1			// Write FPCR
	msr	FPCR, x2			// Write FPSR
	dsb	ish				// FPCR requires synchronization
#endif
	ret

/*
 * void update_mdscr(unsigned long clear, unsigned long set)
 *   Clears and sets the specified bits in MDSCR_EL1.
 *
 * Setting breakpoints in EL1 is effectively a KTRR bypass. The ability to do so is
 * controlled by MDSCR.KDE. The MSR to set MDSCR must be present to allow
 * self-hosted user mode debug. Any checks before the MRS can be skipped with ROP,
 * so we need to put the checks after the MRS where they can't be skipped. That
 * still leaves a small window if a breakpoint is set on the instruction
 * immediately after the MRS. To handle that, we also do a check and then set of
 * the breakpoint control registers. This allows us to guarantee that a given
 * core will never have both KDE set and a breakpoint targeting EL1.
 *
 * If KDE gets set, unset it and then panic
 */
	.align 2
	.globl EXT(update_mdscr)
LEXT(update_mdscr)
	mov	x4, #0
	mrs	x2, MDSCR_EL1
	bic	x2, x2, x0
	orr	x2, x2, x1
1:
	bic	x2, x2, #0x2000
	msr	MDSCR_EL1, x2
#if defined(CONFIG_KERNEL_INTEGRITY)
	/*
	 * verify KDE didn't get set (including via ROP)
	 * If set, clear it and then panic
	 */
	ands	x3, x2, #0x2000
	orr	x4, x4, x3
	bne	1b
	cmp	x4, xzr
	b.ne	Lupdate_mdscr_panic
#endif
	ret

Lupdate_mdscr_panic:
	adrp	x0, Lupdate_mdscr_panic_str@page
	add	x0, x0, Lupdate_mdscr_panic_str@pageoff
	b	EXT(panic)
	b	.

Lupdate_mdscr_panic_str:
	.asciz "MDSCR.KDE was set"


/*
 * 	Set MMU Translation Table Base Alternate
 */
	.text
	.align 2
	.globl EXT(set_mmu_ttb_alternate)
LEXT(set_mmu_ttb_alternate)
	dsb		sy
#if defined(KERNEL_INTEGRITY_KTRR)
	mov		x1, lr
	bl		EXT(pinst_set_ttbr1)
	mov		lr, x1
#else
#if defined(HAS_VMSA_LOCK)
#if DEBUG || DEVELOPMENT
	mrs		x1, ARM64_REG_VMSA_LOCK_EL1
	and		x1, x1, #(VMSA_LOCK_TTBR1_EL1)
	cbnz		x1, L_set_locked_reg_panic
#endif /* DEBUG || DEVELOPMENT */
#endif /* defined(HAS_VMSA_LOCK) */
	msr		TTBR1_EL1, x0
#endif /* defined(KERNEL_INTEGRITY_KTRR) */
	isb		sy
	ret

#if XNU_MONITOR
	.section __PPLTEXT,__text,regular,pure_instructions
#else
	.text
#endif
	.align 2
	.globl EXT(set_mmu_ttb)
LEXT(set_mmu_ttb)
#if __ARM_KERNEL_PROTECT__
	/* All EL1-mode ASIDs are odd. */
	orr		x0, x0, #(1 << TTBR_ASID_SHIFT)
#endif /* __ARM_KERNEL_PROTECT__ */
	dsb		ish
	msr		TTBR0_EL1, x0
	isb		sy
	ret


#if XNU_MONITOR
	.text
	.align 2
	.globl EXT(ml_get_ppl_cpu_data)
LEXT(ml_get_ppl_cpu_data)
	LOAD_PMAP_CPU_DATA x0, x1, x2
	ret
#endif

/*
 * 	set AUX control register
 */
	.text
	.align 2
	.globl EXT(set_aux_control)
LEXT(set_aux_control)
	msr		ACTLR_EL1, x0
	// Synchronize system
	isb		sy
	ret

#if __ARM_KERNEL_PROTECT__
	.text
	.align 2
	.globl EXT(set_vbar_el1)
LEXT(set_vbar_el1)
#if defined(KERNEL_INTEGRITY_KTRR)
	b		EXT(pinst_set_vbar)
#else
	msr		VBAR_EL1, x0
	ret
#endif
#endif /* __ARM_KERNEL_PROTECT__ */

#if defined(HAS_VMSA_LOCK)
	.text
	.align 2
	.globl EXT(vmsa_lock)
LEXT(vmsa_lock)
	isb sy
	mov x1, #(VMSA_LOCK_SCTLR_M_BIT)
#if __ARM_MIXED_PAGE_SIZE__
	mov x0, #(VMSA_LOCK_TTBR1_EL1 | VMSA_LOCK_VBAR_EL1)
#else
	mov x0, #(VMSA_LOCK_TTBR1_EL1 | VMSA_LOCK_TCR_EL1 | VMSA_LOCK_VBAR_EL1)
#endif
	orr x0, x0, x1
	msr ARM64_REG_VMSA_LOCK_EL1, x0
	isb sy
	ret
#endif /* defined(HAS_VMSA_LOCK) */

/*
 *	set translation control register
 */
	.text
	.align 2
	.globl EXT(set_tcr)
LEXT(set_tcr)
#if defined(APPLE_ARM64_ARCH_FAMILY)
#if DEBUG || DEVELOPMENT
	// Assert that T0Z is always equal to T1Z
	eor		x1, x0, x0, lsr #(TCR_T1SZ_SHIFT - TCR_T0SZ_SHIFT)
	and		x1, x1, #(TCR_TSZ_MASK << TCR_T0SZ_SHIFT)
	cbnz	x1, L_set_tcr_panic
#endif /* DEBUG || DEVELOPMENT */
#endif /* defined(APPLE_ARM64_ARCH_FAMILY) */
#if defined(KERNEL_INTEGRITY_KTRR)
	mov		x1, lr
	bl		EXT(pinst_set_tcr)
	mov		lr, x1
#else
#if defined(HAS_VMSA_LOCK)
#if DEBUG || DEVELOPMENT
	// assert TCR unlocked
	mrs 		x1, ARM64_REG_VMSA_LOCK_EL1
	and		x1, x1, #(VMSA_LOCK_TCR_EL1)
	cbnz		x1, L_set_locked_reg_panic
#endif /* DEBUG || DEVELOPMENT */
#endif /* defined(HAS_VMSA_LOCK) */
	msr		TCR_EL1, x0
#endif /* defined(KERNEL_INTRITY_KTRR) */
	isb		sy
	ret

#if DEBUG || DEVELOPMENT
L_set_tcr_panic:
	PUSH_FRAME
	sub		sp, sp, #16
	str		x0, [sp]
	adr		x0, L_set_tcr_panic_str
	BRANCH_EXTERN panic

L_set_locked_reg_panic:
	PUSH_FRAME
	sub		sp, sp, #16
	str		x0, [sp]
	adr		x0, L_set_locked_reg_panic_str
	BRANCH_EXTERN panic
	b .

L_set_tcr_panic_str:
	.asciz	"set_tcr: t0sz, t1sz not equal (%llx)\n"


L_set_locked_reg_panic_str:
	.asciz	"attempt to set locked register: (%llx)\n"
#endif /* DEBUG || DEVELOPMENT */

/*
 *	MMU kernel virtual to physical address translation
 */
	.text
	.align 2
	.globl EXT(mmu_kvtop)
LEXT(mmu_kvtop)
	mrs		x2, DAIF									// Load current DAIF
	msr		DAIFSet, #(DAIFSC_IRQF | DAIFSC_FIQF)		// Disable IRQ
	at		s1e1r, x0									// Translation Stage 1 EL1
	isb		sy
	mrs		x1, PAR_EL1									// Read result
	msr		DAIF, x2									// Restore interrupt state
	tbnz	x1, #0, L_mmu_kvtop_invalid					// Test Translation not valid
	bfm		x1, x0, #0, #11								// Add page offset
	and		x0, x1, #0x0000ffffffffffff					// Clear non-address bits 
	ret
L_mmu_kvtop_invalid:
	mov		x0, #0										// Return invalid
	ret

/*
 *	MMU user virtual to physical address translation
 */
	.text
	.align 2
	.globl EXT(mmu_uvtop)
LEXT(mmu_uvtop)
	lsr		x8, x0, #56									// Extract top byte
	cbnz	x8, L_mmu_uvtop_invalid						// Tagged pointers are invalid
	mrs		x2, DAIF									// Load current DAIF
	msr		DAIFSet, #(DAIFSC_IRQF | DAIFSC_FIQF)		// Disable IRQ
	at		s1e0r, x0									// Translation Stage 1 EL0
	isb		sy
	mrs		x1, PAR_EL1									// Read result
	msr		DAIF, x2									// Restore interrupt state
	tbnz	x1, #0, L_mmu_uvtop_invalid					// Test Translation not valid
	bfm		x1, x0, #0, #11								// Add page offset
	and		x0, x1, #0x0000ffffffffffff					// Clear non-address bits 
	ret
L_mmu_uvtop_invalid:
	mov		x0, #0										// Return invalid
	ret

/*
 *	MMU kernel virtual to physical address preflight write access
 */
	.text
	.align 2
	.globl EXT(mmu_kvtop_wpreflight)
LEXT(mmu_kvtop_wpreflight)
	mrs		x2, DAIF									// Load current DAIF
	msr		DAIFSet, #(DAIFSC_IRQF | DAIFSC_FIQF)		// Disable IRQ
	at		s1e1w, x0									// Translation Stage 1 EL1
	mrs		x1, PAR_EL1									// Read result
	msr		DAIF, x2									// Restore interrupt state
	tbnz	x1, #0, L_mmu_kvtop_wpreflight_invalid		// Test Translation not valid
	bfm		x1, x0, #0, #11								// Add page offset
	and		x0, x1, #0x0000ffffffffffff					// Clear non-address bits
	ret
L_mmu_kvtop_wpreflight_invalid:
	mov		x0, #0										// Return invalid
	ret

/*
 * SET_RECOVERY_HANDLER
 *
 *	Sets up a page fault recovery handler.  This macro clobbers x16 and x17.
 *
 *	label - recovery label
 *	tpidr - persisted thread pointer
 *	old_handler - persisted recovery handler
 *	label_in_adr_range - whether \label is within 1 MB of PC
 */
.macro SET_RECOVERY_HANDLER	label, tpidr=x16, old_handler=x10, label_in_adr_range=0
	// Note: x16 and x17 are designated for use as temporaries in
	// interruptible PAC routines.  DO NOT CHANGE THESE REGISTER ASSIGNMENTS.
.if \label_in_adr_range==1						// Load the recovery handler address
	adr		x17, \label
.else
	adrp	x17, \label@page
	add		x17, x17, \label@pageoff
.endif
#if defined(HAS_APPLE_PAC)
	mrs		x16, TPIDR_EL1
	add		x16, x16, TH_RECOVER
	movk	x16, #PAC_DISCRIMINATOR_RECOVER, lsl 48
	pacia	x17, x16							// Sign with IAKey + blended discriminator
#endif

	mrs		\tpidr, TPIDR_EL1					// Load thread pointer
	ldr		\old_handler, [\tpidr, TH_RECOVER]	// Save previous recovery handler
	str		x17, [\tpidr, TH_RECOVER]			// Set new signed recovery handler
.endmacro

/*
 * CLEAR_RECOVERY_HANDLER
 *
 *	Clears page fault handler set by SET_RECOVERY_HANDLER
 *
 *	tpidr - thread pointer saved by SET_RECOVERY_HANDLER
 *	old_handler - old recovery handler saved by SET_RECOVERY_HANDLER
 */
.macro CLEAR_RECOVERY_HANDLER	tpidr=x16, old_handler=x10
	str		\old_handler, [\tpidr, TH_RECOVER]	// Restore the previous recovery handler
.endmacro


	.text
	.align 2
copyio_error:
	CLEAR_RECOVERY_HANDLER
	mov		x0, #EFAULT					// Return an EFAULT error
	POP_FRAME
	ARM64_STACK_EPILOG

/*
 * int _bcopyin(const char *src, char *dst, vm_size_t len)
 */
	.text
	.align 2
	.globl EXT(_bcopyin)
LEXT(_bcopyin)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	SET_RECOVERY_HANDLER copyio_error
	/* If len is less than 16 bytes, just do a bytewise copy */
	cmp		x2, #16
	b.lt	2f
	sub		x2, x2, #16
1:
	/* 16 bytes at a time */
	ldp		x3, x4, [x0], #16
	stp		x3, x4, [x1], #16
	subs	x2, x2, #16
	b.ge	1b
	/* Fixup the len and test for completion */
	adds	x2, x2, #16
	b.eq	3f
2:	/* Bytewise */
	subs	x2, x2, #1
	ldrb	w3, [x0], #1
	strb	w3, [x1], #1
	b.hi	2b
3:
	CLEAR_RECOVERY_HANDLER
	mov		x0, #0
	POP_FRAME
	ARM64_STACK_EPILOG

/*
 * int _copyin_atomic32(const char *src, uint32_t *dst)
 */
	.text
	.align 2
	.globl EXT(_copyin_atomic32)
LEXT(_copyin_atomic32)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	SET_RECOVERY_HANDLER copyio_error
	ldr		w8, [x0]
	str		w8, [x1]
	mov		x0, #0
	CLEAR_RECOVERY_HANDLER
	POP_FRAME
	ARM64_STACK_EPILOG

/*
 * int _copyin_atomic32_wait_if_equals(const char *src, uint32_t value)
 */
	.text
	.align 2
	.globl EXT(_copyin_atomic32_wait_if_equals)
LEXT(_copyin_atomic32_wait_if_equals)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	SET_RECOVERY_HANDLER copyio_error
	ldxr		w8, [x0]
	cmp		w8, w1
	mov		x0, ESTALE
	b.ne		1f
	mov		x0, #0
	wfe
1:
	clrex
	CLEAR_RECOVERY_HANDLER
	POP_FRAME
	ARM64_STACK_EPILOG

/*
 * int _copyin_atomic64(const char *src, uint32_t *dst)
 */
	.text
	.align 2
	.globl EXT(_copyin_atomic64)
LEXT(_copyin_atomic64)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	SET_RECOVERY_HANDLER copyio_error
	ldr		x8, [x0]
	str		x8, [x1]
	mov		x0, #0
	CLEAR_RECOVERY_HANDLER
	POP_FRAME
	ARM64_STACK_EPILOG


/*
 * int _copyout_atomic32(uint32_t value, char *dst)
 */
	.text
	.align 2
	.globl EXT(_copyout_atomic32)
LEXT(_copyout_atomic32)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	SET_RECOVERY_HANDLER copyio_error
	str		w0, [x1]
	mov		x0, #0
	CLEAR_RECOVERY_HANDLER
	POP_FRAME
	ARM64_STACK_EPILOG

/*
 * int _copyout_atomic64(uint64_t value, char *dst)
 */
	.text
	.align 2
	.globl EXT(_copyout_atomic64)
LEXT(_copyout_atomic64)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	SET_RECOVERY_HANDLER copyio_error
	str		x0, [x1]
	mov		x0, #0
	CLEAR_RECOVERY_HANDLER
	POP_FRAME
	ARM64_STACK_EPILOG


/*
 * int _bcopyout(const char *src, char *dst, vm_size_t len)
 */
	.text
	.align 2
	.globl EXT(_bcopyout)
LEXT(_bcopyout)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	SET_RECOVERY_HANDLER copyio_error
	/* If len is less than 16 bytes, just do a bytewise copy */
	cmp		x2, #16
	b.lt	2f
	sub		x2, x2, #16
1:
	/* 16 bytes at a time */
	ldp		x3, x4, [x0], #16
	stp		x3, x4, [x1], #16
	subs	x2, x2, #16
	b.ge	1b
	/* Fixup the len and test for completion */
	adds	x2, x2, #16
	b.eq	3f
2:  /* Bytewise */
	subs	x2, x2, #1
	ldrb	w3, [x0], #1
	strb	w3, [x1], #1
	b.hi	2b
3:
	CLEAR_RECOVERY_HANDLER
	mov		x0, #0
	POP_FRAME
	ARM64_STACK_EPILOG

/*
 * int _bcopyinstr(
 *	  const user_addr_t user_addr,
 *	  char *kernel_addr,
 *	  vm_size_t max,
 *	  vm_size_t *actual)
 */
	.text
	.align 2
	.globl EXT(_bcopyinstr)
LEXT(_bcopyinstr)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	SET_RECOVERY_HANDLER Lcopyinstr_error, label_in_adr_range=1
	mov		x4, #0						// x4 - total bytes copied
Lcopyinstr_loop:
	ldrb	w5, [x0], #1					// Load a byte from the user source
	strb	w5, [x1], #1				// Store a byte to the kernel dest
	add		x4, x4, #1					// Increment bytes copied
	cbz	x5, Lcopyinstr_done	  		// If this byte is null, we're done
	cmp		x4, x2						// If we're out of space, return an error
	b.ne	Lcopyinstr_loop
Lcopyinstr_too_long:
	mov		x5, #ENAMETOOLONG			// Set current byte to error code for later return
Lcopyinstr_done:
	str		x4, [x3]					// Return number of bytes copied
	mov		x0, x5						// Set error code (0 on success, ENAMETOOLONG on failure)
	b		Lcopyinstr_exit
Lcopyinstr_error:
	mov		x0, #EFAULT					// Return EFAULT on error
Lcopyinstr_exit:
	CLEAR_RECOVERY_HANDLER
	POP_FRAME
	ARM64_STACK_EPILOG

/*
 * int copyinframe(const vm_address_t frame_addr, char *kernel_addr, bool is64bit)
 *
 *	Safely copy sixteen bytes (the fixed top of an ARM64 frame) from
 *	either user or kernel memory, or 8 bytes (AArch32) from user only.
 * 
 *	x0 : address of frame to copy.
 *	x1 : kernel address at which to store data.
 *	w2 : whether to copy an AArch32 or AArch64 frame.
 *	x3 : temp
 *	x5 : temp (kernel virtual base)
 *	x9 : temp
 *	x10 : old recovery function (set by SET_RECOVERY_HANDLER)
 *	x12, x13 : backtrace data
 *	x16 : thread pointer (set by SET_RECOVERY_HANDLER)
 *
 */
	.text
	.align 2
	.globl EXT(copyinframe)
LEXT(copyinframe)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	SET_RECOVERY_HANDLER copyio_error
	cbnz	w2, Lcopyinframe64 		// Check frame size
	adrp	x5, EXT(gVirtBase)@page // For 32-bit frame, make sure we're not trying to copy from kernel
	add		x5, x5, EXT(gVirtBase)@pageoff
	ldr		x5, [x5]
	cmp     x5, x0					// See if address is in kernel virtual range
	b.hi	Lcopyinframe32			// If below kernel virtual range, proceed.
	mov		w0, #EFAULT				// Should never have a 32-bit frame in kernel virtual range
	b		Lcopyinframe_done		

Lcopyinframe32:
	ldr		x12, [x0]				// Copy 8 bytes
	str		x12, [x1]
	mov 	w0, #0					// Success
	b		Lcopyinframe_done

Lcopyinframe64:
	mov		x3, VM_MIN_KERNEL_ADDRESS		// Check if kernel address
	orr		x9, x0, TBI_MASK				// Hide tags in address comparison
	cmp		x9, x3							// If in kernel address range, skip tag test
	b.hs	Lcopyinframe_valid
	tst		x0, TBI_MASK					// Detect tagged pointers
	b.eq	Lcopyinframe_valid
	mov		w0, #EFAULT						// Tagged address, fail
	b		Lcopyinframe_done
Lcopyinframe_valid:
	ldp		x12, x13, [x0]			// Copy 16 bytes
	stp		x12, x13, [x1]
	mov 	w0, #0					// Success

Lcopyinframe_done:
	CLEAR_RECOVERY_HANDLER
	POP_FRAME
	ARM64_STACK_EPILOG


/*
 * uint32_t arm_debug_read_dscr(void)
 */
	.text
	.align 2
	.globl EXT(arm_debug_read_dscr)
LEXT(arm_debug_read_dscr)
	PANIC_UNIMPLEMENTED

/*
 * void arm_debug_set_cp14(arm_debug_state_t *debug_state)
 *
 *     Set debug registers to match the current thread state
 *      (NULL to disable).  Assume 6 breakpoints and 2
 *      watchpoints, since that has been the case in all cores
 *      thus far.
 */
       .text
       .align 2
       .globl EXT(arm_debug_set_cp14)
LEXT(arm_debug_set_cp14)
	PANIC_UNIMPLEMENTED

#if defined(APPLE_ARM64_ARCH_FAMILY)
/*
 * Note: still have to ISB before executing wfi!
 */
	.text
	.align 2
	.globl EXT(arm64_prepare_for_sleep)
LEXT(arm64_prepare_for_sleep)
	PUSH_FRAME

#if defined(APPLETYPHOON)
	// <rdar://problem/15827409>
	HID_SET_BITS ARM64_REG_HID2, ARM64_REG_HID2_disMMUmtlbPrefetch, x9
	dsb		sy
	isb		sy
#endif

#if HAS_CLUSTER
	cbnz		x0, 1f                                      // Skip if deep_sleep == true
	// Mask FIQ and IRQ to avoid spurious wakeups
	mrs		x9, ARM64_REG_CYC_OVRD
	and		x9, x9, #(~(ARM64_REG_CYC_OVRD_irq_mask | ARM64_REG_CYC_OVRD_fiq_mask))
	mov		x10, #(ARM64_REG_CYC_OVRD_irq_disable | ARM64_REG_CYC_OVRD_fiq_disable)
	orr		x9, x9, x10
	msr		ARM64_REG_CYC_OVRD, x9
	isb
1:
#endif

	cbz		x0, 1f                                          // Skip if deep_sleep == false
#if __ARM_GLOBAL_SLEEP_BIT__
	// Enable deep sleep
	mrs		x1, ARM64_REG_ACC_OVRD
	orr		x1, x1, #(ARM64_REG_ACC_OVRD_enDeepSleep)
	and		x1, x1, #(~(ARM64_REG_ACC_OVRD_disL2Flush4AccSlp_mask))
	orr		x1, x1, #(  ARM64_REG_ACC_OVRD_disL2Flush4AccSlp_deepsleep)
	and		x1, x1, #(~(ARM64_REG_ACC_OVRD_ok2PwrDnSRM_mask))
	orr		x1, x1, #(  ARM64_REG_ACC_OVRD_ok2PwrDnSRM_deepsleep)
	and		x1, x1, #(~(ARM64_REG_ACC_OVRD_ok2TrDnLnk_mask))
	orr		x1, x1, #(  ARM64_REG_ACC_OVRD_ok2TrDnLnk_deepsleep)
	and		x1, x1, #(~(ARM64_REG_ACC_OVRD_ok2PwrDnCPM_mask))
	orr		x1, x1, #(  ARM64_REG_ACC_OVRD_ok2PwrDnCPM_deepsleep)
#if HAS_RETENTION_STATE
	orr		x1, x1, #(ARM64_REG_ACC_OVRD_disPioOnWfiCpu)
#endif
	msr		ARM64_REG_ACC_OVRD, x1


#else
	// Enable deep sleep
	mov		x1, ARM64_REG_CYC_CFG_deepSleep
	msr		ARM64_REG_CYC_CFG, x1
#endif

1:
	// Set "OK to power down" (<rdar://problem/12390433>)
	mrs		x9, ARM64_REG_CYC_OVRD
	orr		x9, x9, #(ARM64_REG_CYC_OVRD_ok2pwrdn_force_down)
#if HAS_RETENTION_STATE
	orr		x9, x9, #(ARM64_REG_CYC_OVRD_disWfiRetn)
#endif
	msr		ARM64_REG_CYC_OVRD, x9

#if defined(APPLEMONSOON) || defined(APPLEVORTEX)
	ARM64_IS_PCORE x9
	cbz		x9, Lwfi_inst // skip if not p-core

	/* <rdar://problem/32512947>: Flush the GUPS prefetcher prior to
	 * wfi.  A Skye HW bug can cause the GUPS prefetcher on p-cores
	 * to be left with valid entries that fail to drain if a
	 * subsequent wfi is issued.  This can prevent the core from
	 * power-gating.  For the idle case that is recoverable, but
	 * for the deep-sleep (S2R) case in which cores MUST power-gate,
	 * it can lead to a hang.  This can be prevented by disabling
	 * and re-enabling GUPS, which forces the prefetch queue to
	 * drain.  This should be done as close to wfi as possible, i.e.
	 * at the very end of arm64_prepare_for_sleep(). */
#if defined(APPLEVORTEX)
	/* <rdar://problem/32821461>: Cyprus A0/A1 parts have a similar
	 * bug in the HSP prefetcher that can be worked around through
	 * the same method mentioned above for Skye. */
	mrs x9, MIDR_EL1
	EXEC_COREALL_REVLO CPU_VERSION_B0, x9, x10
#endif
	mrs		x9, ARM64_REG_HID10
	orr		x9, x9, #(ARM64_REG_HID10_DisHwpGups)
	msr		ARM64_REG_HID10, x9
	isb		sy
	and		x9, x9, #(~(ARM64_REG_HID10_DisHwpGups))
	msr		ARM64_REG_HID10, x9
	isb		sy
#endif
	EXEC_END

Lwfi_inst:
	dsb		sy
	isb		sy
	wfi
	b		Lwfi_inst

/*
 * Force WFI to use clock gating only
 *
 */	
	.text
	.align 2
	.globl EXT(arm64_force_wfi_clock_gate)
LEXT(arm64_force_wfi_clock_gate)
	ARM64_STACK_PROLOG
	PUSH_FRAME

	mrs		x0, ARM64_REG_CYC_OVRD
	orr		x0, x0, #(ARM64_REG_CYC_OVRD_ok2pwrdn_force_up)
	msr		ARM64_REG_CYC_OVRD, x0
	
	POP_FRAME
	ARM64_STACK_EPILOG


#if HAS_RETENTION_STATE
	.text
	.align 2
	.globl EXT(arm64_retention_wfi)
LEXT(arm64_retention_wfi)
	wfi
	cbz		lr, Lwfi_retention	// If lr is 0, we entered retention state and lost all GPRs except sp and pc
	ret					// Otherwise just return to cpu_idle()
Lwfi_retention:
	mov		x0, #1
	bl		EXT(ClearIdlePop)
	mov		x0, #0 
	bl		EXT(cpu_idle_exit)	// cpu_idle_exit(from_reset = FALSE)
	b		.			// cpu_idle_exit() should never return
#endif

#if defined(APPLETYPHOON)

	.text
	.align 2
	.globl EXT(typhoon_prepare_for_wfi)

LEXT(typhoon_prepare_for_wfi)
	PUSH_FRAME

	// <rdar://problem/15827409>
	HID_SET_BITS ARM64_REG_HID2, ARM64_REG_HID2_disMMUmtlbPrefetch, x0
	dsb		sy
	isb		sy

	POP_FRAME
	ret


	.text
	.align 2
	.globl EXT(typhoon_return_from_wfi)
LEXT(typhoon_return_from_wfi)
	PUSH_FRAME

	// <rdar://problem/15827409>
	HID_CLEAR_BITS ARM64_REG_HID2, ARM64_REG_HID2_disMMUmtlbPrefetch, x0
	dsb		sy
	isb		sy 

	POP_FRAME
	ret
#endif

#ifdef  APPLETYPHOON

#define HID0_DEFEATURES_1 0x0000a0c000064010ULL
#define HID1_DEFEATURES_1 0x000000004005bf20ULL
#define HID2_DEFEATURES_1 0x0000000000102074ULL
#define HID3_DEFEATURES_1 0x0000000000400003ULL
#define HID4_DEFEATURES_1 0x83ff00e100000268ULL
#define HID7_DEFEATURES_1 0x000000000000000eULL

#define HID0_DEFEATURES_2 0x0000a1c000020010ULL
#define HID1_DEFEATURES_2 0x000000000005d720ULL
#define HID2_DEFEATURES_2 0x0000000000002074ULL
#define HID3_DEFEATURES_2 0x0000000000400001ULL
#define HID4_DEFEATURES_2 0x8390000200000208ULL
#define HID7_DEFEATURES_2 0x0000000000000000ULL

/*
	arg0 = target register
	arg1 = 64-bit constant
*/
.macro LOAD_UINT64 
	movz	$0, #(($1 >> 48) & 0xffff), lsl #48
	movk	$0, #(($1 >> 32) & 0xffff), lsl #32
	movk	$0, #(($1 >> 16) & 0xffff), lsl #16
	movk	$0, #(($1)       & 0xffff)
.endmacro

	.text
	.align 2
	.globl EXT(cpu_defeatures_set)
LEXT(cpu_defeatures_set)
	PUSH_FRAME
	cmp		x0, #2
	b.eq		cpu_defeatures_set_2
	cmp		x0, #1
	b.ne		cpu_defeatures_set_ret
	LOAD_UINT64	x1, HID0_DEFEATURES_1
	mrs		x0, ARM64_REG_HID0
	orr		x0, x0, x1
	msr		ARM64_REG_HID0, x0
	LOAD_UINT64	x1, HID1_DEFEATURES_1
	mrs		x0, ARM64_REG_HID1
	orr		x0, x0, x1
	msr		ARM64_REG_HID1, x0
	LOAD_UINT64	x1, HID2_DEFEATURES_1
	mrs		x0, ARM64_REG_HID2
	orr		x0, x0, x1
	msr		ARM64_REG_HID2, x0
	LOAD_UINT64	x1, HID3_DEFEATURES_1
	mrs		x0, ARM64_REG_HID3
	orr		x0, x0, x1
	msr		ARM64_REG_HID3, x0
	LOAD_UINT64	x1, HID4_DEFEATURES_1
	mrs		x0, ARM64_REG_HID4
	orr		x0, x0, x1
	msr		ARM64_REG_HID4, x0
	LOAD_UINT64	x1, HID7_DEFEATURES_1
	mrs		x0, ARM64_REG_HID7
	orr		x0, x0, x1
	msr		ARM64_REG_HID7, x0
	dsb		sy
	isb		sy 
	b		cpu_defeatures_set_ret
cpu_defeatures_set_2:
	LOAD_UINT64	x1, HID0_DEFEATURES_2
	mrs		x0, ARM64_REG_HID0
	orr		x0, x0, x1
	msr		ARM64_REG_HID0, x0
	LOAD_UINT64	x1, HID1_DEFEATURES_2
	mrs		x0, ARM64_REG_HID1
	orr		x0, x0, x1
	msr		ARM64_REG_HID1, x0
	LOAD_UINT64	x1, HID2_DEFEATURES_2
	mrs		x0, ARM64_REG_HID2
	orr		x0, x0, x1
	msr		ARM64_REG_HID2, x0
	LOAD_UINT64	x1, HID3_DEFEATURES_2
	mrs		x0, ARM64_REG_HID3
	orr		x0, x0, x1
	msr		ARM64_REG_HID3, x0
	LOAD_UINT64	x1, HID4_DEFEATURES_2
	mrs		x0, ARM64_REG_HID4
	orr		x0, x0, x1
	msr		ARM64_REG_HID4, x0
	LOAD_UINT64	x1, HID7_DEFEATURES_2
	mrs		x0, ARM64_REG_HID7
	orr		x0, x0, x1
	msr		ARM64_REG_HID7, x0
	dsb		sy
	isb		sy 
	b		cpu_defeatures_set_ret
cpu_defeatures_set_ret:
	POP_FRAME
	ret
#endif

#else /* !defined(APPLE_ARM64_ARCH_FAMILY) */
	.text
	.align 2
	.globl EXT(arm64_prepare_for_sleep)
LEXT(arm64_prepare_for_sleep)
	PUSH_FRAME
Lwfi_inst:
	dsb		sy
	isb		sy
	wfi
	b		Lwfi_inst

/*
 * Force WFI to use clock gating only
 * Note: for non-Apple device, do nothing.
 */	
	.text
	.align 2
	.globl EXT(arm64_force_wfi_clock_gate)
LEXT(arm64_force_wfi_clock_gate)
	PUSH_FRAME
	nop
	POP_FRAME

#endif /* defined(APPLE_ARM64_ARCH_FAMILY) */

/*
 * void arm64_replace_bootstack(cpu_data_t *cpu_data)
 *
 * This must be called from a kernel thread context running on the boot CPU,
 * after setting up new exception stacks in per-CPU data. That will guarantee
 * that the stack(s) we're trying to replace aren't currently in use.  For
 * KTRR-protected devices, this must also be called prior to VM prot finalization
 * and lockdown, as updating SP1 requires a sensitive instruction.
 */
	.text
	.align 2
	.globl EXT(arm64_replace_bootstack)
LEXT(arm64_replace_bootstack)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	// Set the exception stack pointer
	ldr		x0, [x0, CPU_EXCEPSTACK_TOP]
	mrs		x4, DAIF					// Load current DAIF; use x4 as pinst may trash x1-x3
	msr		DAIFSet, #(DAIFSC_IRQF | DAIFSC_FIQF | DAIFSC_ASYNCF)		// Disable IRQ/FIQ/serror
	// Set SP_EL1 to exception stack
#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)
	mov		x1, lr
	bl		EXT(pinst_spsel_1)
	mov		lr, x1
#else
	msr		SPSel, #1
#endif
	mov		sp, x0
	msr		SPSel, #0
	msr		DAIF, x4					// Restore interrupt state
	POP_FRAME
	ARM64_STACK_EPILOG

#ifdef MONITOR
/*
 * unsigned long monitor_call(uintptr_t callnum, uintptr_t arg1,
 							  uintptr_t arg2, uintptr_t arg3)
 *
 * Call the EL3 monitor with 4 arguments in registers
 * The monitor interface maintains the same ABI as the C function call standard.  Callee-saved
 * registers are preserved, temporary registers are not.  Parameters and results are passed in
 * the usual manner.
 */
	.text
	.align 2
	.globl EXT(monitor_call)
LEXT(monitor_call)
	smc 	0x11
	ret
#endif

#ifdef HAS_APPLE_PAC
/*
 * SIGN_THREAD_STATE
 *
 * Macro that signs thread state.
 * $0 - Offset in arm_saved_state to store JOPHASH value.
 */
.macro SIGN_THREAD_STATE
	pacga	x1, x1, x0		/* PC hash (gkey + &arm_saved_state) */
	/*
	 * Mask off the carry flag so we don't need to re-sign when that flag is
	 * touched by the system call return path.
	 */
	bic		x2, x2, PSR_CF
	pacga	x1, x2, x1		/* SPSR hash (gkey + pc hash) */
	pacga	x1, x3, x1		/* LR Hash (gkey + spsr hash) */
	pacga	x1, x4, x1		/* X16 hash (gkey + lr hash) */
	pacga	x1, x5, x1		/* X17 hash (gkey + x16 hash) */
	str		x1, [x0, $0]
#if DEBUG || DEVELOPMENT
	mrs		x1, DAIF
	tbz		x1, #DAIF_IRQF_SHIFT, Lintr_enabled_panic
#endif /* DEBUG || DEVELOPMENT */
.endmacro

/*
 * CHECK_SIGNED_STATE
 *
 * Macro that checks signed thread state.
 * $0 - Offset in arm_saved_state to to read the JOPHASH value from.
 * $1 - Label to jump to when check is unsuccessful.
 */
.macro CHECK_SIGNED_STATE
	pacga	x1, x1, x0		/* PC hash (gkey + &arm_saved_state) */
	/*
	 * Mask off the carry flag so we don't need to re-sign when that flag is
	 * touched by the system call return path.
	 */
	bic		x2, x2, PSR_CF
	pacga	x1, x2, x1		/* SPSR hash (gkey + pc hash) */
	pacga	x1, x3, x1		/* LR Hash (gkey + spsr hash) */
	pacga	x1, x4, x1		/* X16 hash (gkey + lr hash) */
	pacga	x1, x5, x1		/* X17 hash (gkey + x16 hash) */
	ldr		x2, [x0, $0]
	cmp		x1, x2
	b.ne	$1
#if DEBUG || DEVELOPMENT
	mrs		x1, DAIF
	tbz		x1, #DAIF_IRQF_SHIFT, Lintr_enabled_panic
#endif /* DEBUG || DEVELOPMENT */
.endmacro

/**
 * void ml_sign_thread_state(arm_saved_state_t *ss, uint64_t pc,
 *							 uint32_t cpsr, uint64_t lr, uint64_t x16,
 *							 uint64_t x17)
 */
	.text
	.align 2
	.globl EXT(ml_sign_thread_state)
LEXT(ml_sign_thread_state)
	SIGN_THREAD_STATE SS64_JOPHASH
	ret

/**
 * void ml_sign_kernel_thread_state(arm_kernel_saved_state *ss, uint64_t pc,
 *							 uint32_t cpsr, uint64_t lr, uint64_t x16,
 *							 uint64_t x17)
 */
	.text
	.align 2
	.globl EXT(ml_sign_kernel_thread_state)
LEXT(ml_sign_kernel_thread_state)
	SIGN_THREAD_STATE SS64_KERNEL_JOPHASH
	ret

/**
 * void ml_check_signed_state(arm_saved_state_t *ss, uint64_t pc,
 *							  uint32_t cpsr, uint64_t lr, uint64_t x16,
 *							  uint64_t x17)
 */
	.text
	.align 2
	.globl EXT(ml_check_signed_state)
LEXT(ml_check_signed_state)
	CHECK_SIGNED_STATE SS64_JOPHASH, Lcheck_hash_panic
	ret
Lcheck_hash_panic:
	/*
	 * ml_check_signed_state normally doesn't set up a stack frame, since it
	 * needs to work in the face of attackers that can modify the stack.
	 * However we lazily create one in the panic path: at this point we're
	 * *only* using the stack frame for unwinding purposes, and without one
	 * we'd be missing information about the caller.
	 */
	ARM64_STACK_PROLOG
	PUSH_FRAME
	mov		x1, x0
	adr		x0, Lcheck_hash_str
	CALL_EXTERN panic_with_thread_kernel_state

/**
 * void ml_check_kernel_signed_state(arm_kernel_saved_state *ss, uint64_t pc,
 *							  uint32_t cpsr, uint64_t lr, uint64_t x16,
 *							  uint64_t x17)
 */
	.text
	.align 2
	.globl EXT(ml_check_kernel_signed_state)
LEXT(ml_check_kernel_signed_state)
	CHECK_SIGNED_STATE SS64_KERNEL_JOPHASH, Lcheck_kernel_hash_panic
	ret
Lcheck_kernel_hash_panic:
	ARM64_STACK_PROLOG
	PUSH_FRAME
	adr		x0, Lcheck_hash_str
	CALL_EXTERN panic

Lcheck_hash_str:
	.asciz "JOP Hash Mismatch Detected (PC, CPSR, or LR corruption)"

#if DEBUG || DEVELOPMENT
Lintr_enabled_panic:
	ARM64_STACK_PROLOG
	PUSH_FRAME
	adr		x0, Lintr_enabled_str
	CALL_EXTERN panic
Lintr_enabled_str:
	/*
	 * Please see the "Signing spilled register state" section of doc/pac.md
	 * for an explanation of why this is bad and how it should be fixed.
	 */
	.asciz "Signed thread state manipulated with interrupts enabled"
#endif /* DEBUG || DEVELOPMENT */

/**
 * void ml_auth_thread_state_invalid_cpsr(arm_saved_state_t *ss)
 *
 * Panics due to an invalid CPSR value in ss.
 */
	.text
	.align 2
	.globl EXT(ml_auth_thread_state_invalid_cpsr)
LEXT(ml_auth_thread_state_invalid_cpsr)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	mov		x1, x0
	adr		x0, Linvalid_cpsr_str
	CALL_EXTERN panic_with_thread_kernel_state

Linvalid_cpsr_str:
	.asciz "Thread state corruption detected (PE mode == 0)"
#endif /* HAS_APPLE_PAC */

	.text
	.align 2
	.globl EXT(fill32_dczva)
LEXT(fill32_dczva)
0:
	dc	zva, x0
	add	x0, x0, #64
	subs	x1, x1, #64
	b.hi	0b
	ret

	.text
	.align 2
	.globl EXT(fill32_nt)
LEXT(fill32_nt)
	dup.4s	v0, w2
0:
	stnp	q0, q0, [x0]
	stnp	q0, q0, [x0, #0x20]
	stnp	q0, q0, [x0, #0x40]
	stnp	q0, q0, [x0, #0x60]
	add	x0, x0, #128
	subs	x1, x1, #128
	b.hi	0b
	ret

/* vim: set sw=4 ts=4: */

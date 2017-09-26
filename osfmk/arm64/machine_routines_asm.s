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
#include <arm64/machine_machdep.h>
#include <arm64/proc_reg.h>
#include <arm/pmap.h>
#include <pexpert/arm64/board_config.h>
#include <sys/errno.h>
#include "assym.s"


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

#if	(__ARM_VFP__ >= 3)
	.align	2
	.globl	EXT(get_mvfr0)
LEXT(get_mvfr0)
	mrs x0, MVFR0_EL1
	ret

	.globl	EXT(get_mvfr1)
LEXT(get_mvfr1)
	mrs x0, MVFR1_EL1
	ret

#endif

/*
 *	void flush_mmu_tlb(void)
 *
 *		Flush all TLBs
 */
	.text
	.align 2
	.globl EXT(flush_mmu_tlb)
LEXT(flush_mmu_tlb)
	tlbi    vmalle1is
	dsb		ish
	isb		sy
	ret

/*
 *	void flush_core_tlb(void)
 *
 *		Flush core TLB
 */
	.text
	.align 2
	.globl EXT(flush_core_tlb)
LEXT(flush_core_tlb)
	tlbi    vmalle1
	dsb		ish
	isb		sy
	ret

/*
 *	void flush_mmu_tlb_allentries(uint64_t, uint64_t)
 *
 *		Flush TLB entries
 */
	.text
	.align 2
	.globl EXT(flush_mmu_tlb_allentries)
LEXT(flush_mmu_tlb_allentries)
#if __ARM_16K_PG__
	and		x0, x0, #~0x3

	/*
	 * The code below is not necessarily correct.  From an overview of
	 * the client code, the expected contract for TLB flushes is that
	 * we will expand from an "address, length" pair to "start address,
	 * end address" in the course of a TLB flush.  This suggests that
	 * a flush for "X, X+4" is actually only asking for a flush of a
	 * single 16KB page.  At the same time, we'd like to be prepared
	 * for bad inputs (X, X+3), so add 3 and then truncate the 4KB page
	 * number to a 16KB page boundary.  This should deal correctly with
	 * unaligned inputs.
	 *
	 * If our expecations about client behavior are wrong however, this
	 * will lead to occasional TLB corruption on platforms with 16KB
	 * pages.
	 */
	add		x1, x1, #0x3
	and		x1, x1, #~0x3
#endif

1:
	tlbi    vaae1is, x0
	add		x0, x0, #(ARM_PGBYTES / 4096)	// Units are 4KB pages, as defined by the ISA
	cmp		x0, x1
	b.lt	1b
	dsb		ish
	isb		sy
	ret

/*
 *	void flush_mmu_tlb_entry(uint64_t)
 *
 *		Flush TLB entry
 */
	.text
	.align 2
	.globl EXT(flush_mmu_tlb_entry)
LEXT(flush_mmu_tlb_entry)
	tlbi    vae1is, x0
	dsb		ish
	isb		sy
	ret

/*
 *	void flush_mmu_tlb_entries(uint64_t, uint64_t)
 *
 *		Flush TLB entries
 */
	.text
	.align 2
	.globl EXT(flush_mmu_tlb_entries)
LEXT(flush_mmu_tlb_entries)
#if __ARM_16K_PG__
	and		x0, x0, #~0x3

	/*
	 * The code below is not necessarily correct.  From an overview of
	 * the client code, the expected contract for TLB flushes is that
	 * we will expand from an "address, length" pair to "start address,
	 * end address" in the course of a TLB flush.  This suggests that
	 * a flush for "X, X+4" is actually only asking for a flush of a
	 * single 16KB page.  At the same time, we'd like to be prepared
	 * for bad inputs (X, X+3), so add 3 and then truncate the 4KB page
	 * number to a 16KB page boundary.  This should deal correctly with
	 * unaligned inputs.
	 *
	 * If our expecations about client behavior are wrong however, this
	 * will lead to occasional TLB corruption on platforms with 16KB
	 * pages.
	 */
	add		x1, x1, #0x3
	and		x1, x1, #~0x3
#endif

1:
	tlbi    vae1is, x0
	add		x0, x0, #(ARM_PGBYTES / 4096)	// Units are pages
	cmp		x0, x1
	b.lt	1b
	dsb		ish
	isb		sy
	ret

/*
 *	void flush_mmu_tlb_asid(uint64_t)
 *
 *		Flush TLB entriesfor requested asid
 */
	.text
	.align 2
	.globl EXT(flush_mmu_tlb_asid)
LEXT(flush_mmu_tlb_asid)
	tlbi    aside1is, x0
	dsb		ish
	isb		sy
	ret

/*
 *	void flush_core_tlb_asid(uint64_t)
 *
 *		Flush TLB entries for core for requested asid
 */
	.text
	.align 2
	.globl EXT(flush_core_tlb_asid)
LEXT(flush_core_tlb_asid)
	tlbi	aside1, x0
	dsb		ish
	isb		sy
	ret

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
	msr		TTBR1_EL1, x0
#endif /* defined(KERNEL_INTEGRITY_KTRR) */
	isb		sy
	ret

/*
 * 	set AUX control register
 */
	.text
	.align 2
	.globl EXT(set_aux_control)
LEXT(set_aux_control)
	msr		ACTLR_EL1, x0
	// Synchronize system
	dsb		sy
	isb		sy
	ret

#if (DEVELOPMENT || DEBUG)
/*
 * 	set MMU control register
 */
	.text
	.align 2
	.globl EXT(set_mmu_control)
LEXT(set_mmu_control)
	msr		SCTLR_EL1, x0
	dsb		sy
	isb		sy
	ret
#endif


/*
 *	set translation control register
 */
	.text
	.align 2
	.globl EXT(set_tcr)
LEXT(set_tcr)
#if defined(APPLE_ARM64_ARCH_FAMILY)
	// Assert that T0Z is always equal to T1Z
	eor		x1, x0, x0, lsr #(TCR_T1SZ_SHIFT - TCR_T0SZ_SHIFT)
	and		x1, x1, #(TCR_TSZ_MASK << TCR_T0SZ_SHIFT)
	cbnz	x1, L_set_tcr_panic
#if defined(KERNEL_INTEGRITY_KTRR)
	mov		x1, lr
	bl		_pinst_set_tcr
	mov		lr, x1
#else
	msr		TCR_EL1, x0
#endif /* defined(KERNEL_INTRITY_KTRR) */
	isb		sy
	ret

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
#else
#if defined(KERNEL_INTEGRITY_KTRR)
	mov		x1, lr
	bl		_pinst_set_tcr
	mov		lr, x1
#else
	msr		TCR_EL1, x0
#endif
	isb		sy
	ret
#endif // defined(APPLE_ARM64_ARCH_FAMILY)

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
	mrs		x1, PAR_EL1									// Read result
	msr		DAIF, x2									// Restore interrupt state
	tbnz	x1, #0, L_mmu_kvtop_invalid					// Test Translation not valid
	bfm		x1, x0, #0, #11								// Add page offset
	and		x0, x1, #0x0000ffffffffffff					// Clear non-address bits 
	ret
L_mmu_kvtop_invalid:
	mov		x0, xzr										// Return invalid
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
	mrs		x1, PAR_EL1									// Read result
	msr		DAIF, x2									// Restore interrupt state
	tbnz	x1, #0, L_mmu_uvtop_invalid					// Test Translation not valid
	bfm		x1, x0, #0, #11								// Add page offset
	and		x0, x1, #0x0000ffffffffffff					// Clear non-address bits 
	ret
L_mmu_uvtop_invalid:
	mov		x0, xzr										// Return invalid
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
	mov		x0, xzr										// Return invalid
	ret

/*
 * SET_RECOVERY_HANDLER
 *
 *	Sets up a page fault recovery handler
 *
 *	arg0 - persisted thread pointer
 *	arg1 - persisted recovery handler
 *	arg2 - scratch reg
 *	arg3 - recovery label
 */
.macro SET_RECOVERY_HANDLER
	mrs		$0, TPIDR_EL1					// Load thread pointer
	ldr		$1, [$0, TH_RECOVER]			// Save previous recovery handler
	adrp	$2, $3@page						// Load the recovery handler address
	add		$2, $2, $3@pageoff
	str		$2, [$0, TH_RECOVER]			// Set new recovery handler
.endmacro

/*
 * CLEAR_RECOVERY_HANDLER
 *
 *	Clears page fault handler set by SET_RECOVERY_HANDLER
 *
 *	arg0 - thread pointer saved by SET_RECOVERY_HANDLER
 *	arg1 - old recovery handler saved by SET_RECOVERY_HANDLER
 */
.macro CLEAR_RECOVERY_HANDLER
	str		$1, [$0, TH_RECOVER]		// Restore the previous recovery handler
.endmacro


	.text
	.align 2
copyio_error:
	CLEAR_RECOVERY_HANDLER x10, x11
	mov		x0, #EFAULT					// Return an EFAULT error
	POP_FRAME
	ret

/*
 * int _bcopyin(const char *src, char *dst, vm_size_t len)
 */
	.text
	.align 2
	.globl EXT(_bcopyin)
LEXT(_bcopyin)
	PUSH_FRAME
	SET_RECOVERY_HANDLER x10, x11, x3, copyio_error
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
	CLEAR_RECOVERY_HANDLER x10, x11
	mov		x0, xzr
	POP_FRAME
	ret

/*
 * int _copyin_word(const char *src, uint64_t *dst, vm_size_t len)
 */
	.text
	.align 2
	.globl EXT(_copyin_word)
LEXT(_copyin_word)
	PUSH_FRAME
	SET_RECOVERY_HANDLER x10, x11, x3, copyio_error
	cmp		x2, #4
	b.eq	L_copyin_word_4
	cmp		x2, #8
	b.eq	L_copyin_word_8
	mov		x0, EINVAL
	b		L_copying_exit
L_copyin_word_4:
	ldr		w8, [x0]
	b		L_copyin_word_store
L_copyin_word_8:
	ldr		x8, [x0]
L_copyin_word_store:
	str		x8, [x1]
	mov		x0, xzr
	CLEAR_RECOVERY_HANDLER x10, x11
L_copying_exit:
	POP_FRAME
	ret


/*
 * int _bcopyout(const char *src, char *dst, vm_size_t len)
 */
	.text
	.align 2
	.globl EXT(_bcopyout)
LEXT(_bcopyout)
	PUSH_FRAME
	SET_RECOVERY_HANDLER x10, x11, x3, copyio_error
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
	CLEAR_RECOVERY_HANDLER x10, x11
	mov		x0, xzr
	POP_FRAME
	ret

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
	PUSH_FRAME
	adr		x4, Lcopyinstr_error		// Get address for recover
	mrs		x10, TPIDR_EL1				// Get thread pointer
	ldr		x11, [x10, TH_RECOVER]		// Save previous recover
	str		x4, [x10, TH_RECOVER]		// Store new recover
	mov		x4, xzr						// x4 - total bytes copied
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
	str		x11, [x10, TH_RECOVER]		// Restore old recover
	POP_FRAME
	ret

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
 *	x10 : thread pointer (set by SET_RECOVERY_HANDLER)
 *	x11 : old recovery function (set by SET_RECOVERY_HANDLER)
 *	x12, x13 : backtrace data
 *
 */
	.text
	.align 2
	.globl EXT(copyinframe)
LEXT(copyinframe)
	PUSH_FRAME
	SET_RECOVERY_HANDLER x10, x11, x3, copyio_error
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
	CLEAR_RECOVERY_HANDLER x10, x11
	POP_FRAME
	ret


/*
 * int _emulate_swp(user_addr_t addr, uint32_t newval, uint32_t *oldval)
 *
 *  Securely emulates the swp instruction removed from armv8.
 *    Returns true on success.
 *    Returns false if the user address is not user accessible.
 *
 *  x0 : address to swap
 *  x1 : new value to store
 *  x2 : address to save old value
 *  x3 : scratch reg
 *  x10 : thread pointer (set by SET_RECOVERY_HANDLER)
 *  x11 : old recovery handler (set by SET_RECOVERY_HANDLER)
 *  x12 : interrupt state
 *  x13 : return value
 */
	.text
	.align 2
	.globl EXT(_emulate_swp)
LEXT(_emulate_swp)
	PUSH_FRAME
	SET_RECOVERY_HANDLER x10, x11, x3, swp_error

	// Perform swap
Lswp_try:
	ldxr	w3, [x0]									// Load data at target address
	stxr	w4, w1, [x0]								// Store new value to target address
	cbnz	w4, Lswp_try								// Retry if store failed
	str		w3, [x2]									// Save old value
	mov		x13, #1										// Set successful return value

Lswp_exit:
	mov		x0, x13 									// Set return value
	CLEAR_RECOVERY_HANDLER x10, x11
	POP_FRAME
	ret

/*
 * int _emulate_swpb(user_addr_t addr, uint32_t newval, uint32_t *oldval)
 *
 *  Securely emulates the swpb instruction removed from armv8.
 *    Returns true on success.
 *    Returns false if the user address is not user accessible.
 *
 *  x0 : address to swap
 *  x1 : new value to store
 *  x2 : address to save old value
 *  x3 : scratch reg
 *  x10 : thread pointer (set by SET_RECOVERY_HANDLER)
 *  x11 : old recovery handler (set by SET_RECOVERY_HANDLER)
 *  x12 : interrupt state
 *  x13 : return value
 */
	.text
	.align 2
	.globl EXT(_emulate_swpb)
LEXT(_emulate_swpb)
	PUSH_FRAME
	SET_RECOVERY_HANDLER x10, x11, x3, swp_error

	// Perform swap
Lswpb_try:
	ldxrb	w3, [x0]									// Load data at target address
	stxrb	w4, w1, [x0]								// Store new value to target address
	cbnz	w4, Lswp_try								// Retry if store failed
	str		w3, [x2]									// Save old value
	mov		x13, #1										// Set successful return value

Lswpb_exit:
	mov		x0, x13										// Set return value
	CLEAR_RECOVERY_HANDLER x10, x11
	POP_FRAME
	ret

	.text
	.align 2
swp_error:
	mov		x0, xzr										// Return false
	CLEAR_RECOVERY_HANDLER x10, x11
	POP_FRAME
	ret

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

#if defined(APPLECYCLONE) || defined(APPLETYPHOON)
	// <rdar://problem/15827409> CPU1 Stuck in WFIWT Because of MMU Prefetch
	mrs		x0, ARM64_REG_HID2                              // Read HID2
	orr		x0, x0, #(ARM64_REG_HID2_disMMUmtlbPrefetch)    // Set HID.DisableMTLBPrefetch
	msr		ARM64_REG_HID2, x0                              // Write HID2
	dsb		sy
	isb		sy
#endif

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
	msr		ARM64_REG_ACC_OVRD, x1


#else
	// Enable deep sleep
	mov		x1, ARM64_REG_CYC_CFG_deepSleep
	msr		ARM64_REG_CYC_CFG, x1
#endif
	// Set "OK to power down" (<rdar://problem/12390433>)
	mrs		x0, ARM64_REG_CYC_OVRD
	orr		x0, x0, #(ARM64_REG_CYC_OVRD_ok2pwrdn_force_down)
	msr		ARM64_REG_CYC_OVRD, x0

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
	PUSH_FRAME

	mrs		x0, ARM64_REG_CYC_OVRD
	orr		x0, x0, #(ARM64_REG_CYC_OVRD_ok2pwrdn_force_up)
	msr		ARM64_REG_CYC_OVRD, x0
	
	POP_FRAME
	ret



#if defined(APPLECYCLONE) || defined(APPLETYPHOON)

	.text
	.align 2
	.globl EXT(cyclone_typhoon_prepare_for_wfi)

LEXT(cyclone_typhoon_prepare_for_wfi)
	PUSH_FRAME

	// <rdar://problem/15827409> CPU1 Stuck in WFIWT Because of MMU Prefetch
	mrs		x0, ARM64_REG_HID2                              // Read HID2
	orr		x0, x0, #(ARM64_REG_HID2_disMMUmtlbPrefetch)    // Set HID.DisableMTLBPrefetch
	msr		ARM64_REG_HID2, x0                              // Write HID2
	dsb		sy
	isb		sy

	POP_FRAME
	ret


	.text
	.align 2
	.globl EXT(cyclone_typhoon_return_from_wfi)
LEXT(cyclone_typhoon_return_from_wfi)
	PUSH_FRAME

	// <rdar://problem/15827409> CPU1 Stuck in WFIWT Because of MMU Prefetch
	mrs		x0, ARM64_REG_HID2                              // Read HID2
	mov		x1, #(ARM64_REG_HID2_disMMUmtlbPrefetch)        //
	bic		x0, x0, x1                                      // Clear HID.DisableMTLBPrefetchMTLBPrefetch
	msr		ARM64_REG_HID2, x0                              // Write HID2
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

#endif

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

/* vim: set sw=4 ts=4: */

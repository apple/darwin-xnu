/*
 * Copyright (c) 2007-2014 Apple Inc. All rights reserved.
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
#include <arm/pmap.h>
#include <sys/errno.h>
#include "assym.s"

	.align	2
	.globl	EXT(machine_set_current_thread)
LEXT(machine_set_current_thread)
	mcr		p15, 0, r0, c13, c0, 4				// Write TPIDRPRW
	ldr		r1, [r0, TH_CTH_SELF]
	mrc		p15, 0, r2, c13, c0, 3				// Read TPIDRURO
	and		r2, r2, #3							// Extract cpu number
	orr		r1, r1, r2							//
	mcr		p15, 0, r1, c13, c0, 3				// Write TPIDRURO
	ldr		r1, [r0, TH_CTH_DATA]
	mcr		p15, 0, r1, c13, c0, 2				// Write TPIDRURW
	bx		lr

/*
 * 	void machine_idle(void)
 */
	.text
	.align 2
	.globl EXT(machine_idle)
LEXT(machine_idle)
	cpsid	if									// Disable FIQ IRQ
	mov		ip, lr
	bl		EXT(Idle_context)
	mov		lr, ip
	cpsie	if									// Enable FIQ IRQ
	bx		lr

/*
 *	void cpu_idle_wfi(boolean_t wfi_fast):
 *		cpu_idle is the only function that should call this.
 */
	.text
	.align 2
	.globl EXT(cpu_idle_wfi)
LEXT(cpu_idle_wfi)
	mov		r1, #32
	mov		r2, #1200
	cmp		r0, #0
	beq		3f
	mov		r1, #1
	b		2f
	.align 5
1:
	add		r0, r0, #1
	mov		r1, r2
2:

/*
 * We export the address of the WFI instruction so that it can be patched; this will be
 *   ugly from a debugging perspective.
 */

#if	(__ARM_ARCH__ >= 7)
	dsb
	.globl EXT(wfi_inst)
LEXT(wfi_inst)
	wfi
#else
	mcr		p15, 0, r0, c7, c10, 4
	.globl EXT(wfi_inst)
LEXT(wfi_inst)
	mcr		p15, 0, r0, c7, c0, 4
#endif
3:
	subs		r1, r1, #1
	bne		3b
	nop
	nop
	nop
	nop
	nop
	cmp		r0, #0
	beq		1b
	bx lr

	.align	2
	.globl	EXT(timer_grab)
LEXT(timer_grab)
0:
	ldr		r2, [r0, TIMER_HIGH]
	ldr		r3, [r0, TIMER_LOW]
#if	__ARM_SMP__
	dmb		ish									// dmb ish
#endif
	ldr		r1, [r0, TIMER_HIGHCHK]
	cmp		r1, r2
	bne		0b
	mov		r0, r3
	bx		lr

	.align	2
	.globl	EXT(timer_update)
LEXT(timer_update)
	str		r1, [r0, TIMER_HIGHCHK]
#if	__ARM_SMP__
	dmb		ish									// dmb ish
#endif
	str		r2, [r0, TIMER_LOW]
#if	__ARM_SMP__
	dmb		ish									// dmb ish
#endif
	str		r1, [r0, TIMER_HIGH]
	bx		lr

	.align	2
	.globl	EXT(get_vfp_enabled)
LEXT(get_vfp_enabled)
#if	__ARM_VFP__
	fmrx	r0, fpexc
	and		r1, r0, #FPEXC_EN					// Extact vfp enable previous state
	mov		r0, r1, LSR #FPEXC_EN_BIT			// Return 1 if enabled, 0 if disabled
#else
	mov		r0, #0								// return false
#endif
	bx		lr

/* This is no longer useful (but is exported, so this may require kext cleanup). */
	.align	2
	.globl	EXT(enable_kernel_vfp_context)
LEXT(enable_kernel_vfp_context)
	bx              lr

/*	uint32_t get_fpscr(void):
 *		Returns the current state of the FPSCR register.
 */
	.align	2
	.globl	EXT(get_fpscr)
LEXT(get_fpscr)
#if	__ARM_VFP__
	fmrx	r0, fpscr
#endif
	bx	lr
	.align	2
	.globl	EXT(set_fpscr)
/*	void set_fpscr(uint32_t value):
 *		Set the FPSCR register.
 */
LEXT(set_fpscr)
#if	__ARM_VFP__
	fmxr	fpscr, r0
#else
	mov	r0, #0
#endif
	bx	lr

/*
 *	void OSSynchronizeIO(void)
 */
	.text
	.align 2
        .globl EXT(OSSynchronizeIO)
LEXT(OSSynchronizeIO)
	.align          2
	dsb
	bx		lr

/*
 *	void flush_mmu_tlb(void)
 *
 *		Flush all TLBs
 */
	.text
	.align 2
	.globl EXT(flush_mmu_tlb)
LEXT(flush_mmu_tlb)
	mov     r0, #0
#if	__ARM_SMP__
	mcr     p15, 0, r0, c8, c3, 0				// Invalidate Inner Shareable entire TLBs
#else
	mcr     p15, 0, r0, c8, c7, 0				// Invalidate entire TLB
#endif
	dsb		ish
	isb
	bx		lr

/*
 *	void flush_core_tlb(void)
 *
 *		Flush core TLB
 */
	.text
	.align 2
	.globl EXT(flush_core_tlb)
LEXT(flush_core_tlb)
	mov     r0, #0
	mcr     p15, 0, r0, c8, c7, 0				// Invalidate entire TLB
	dsb		ish
	isb
	bx		lr

/*
 *	void flush_mmu_tlb_entry(uint32_t)
 *
 *		Flush TLB entry
 */
	.text
	.align 2
	.globl EXT(flush_mmu_tlb_entry)
LEXT(flush_mmu_tlb_entry)
#if	__ARM_SMP__
	mcr     p15, 0, r0, c8, c3, 1				// Invalidate TLB  Inner Shareableentry
#else
	mcr     p15, 0, r0, c8, c7, 1				// Invalidate TLB entry
#endif
	dsb		ish
	isb
	bx		lr

/*
 *	void flush_mmu_tlb_entries(uint32_t, uint32_t)
 *
 *		Flush TLB entries
 */
	.text
	.align 2
	.globl EXT(flush_mmu_tlb_entries)
LEXT(flush_mmu_tlb_entries)
1:
#if	__ARM_SMP__
	mcr     p15, 0, r0, c8, c3, 1				// Invalidate TLB Inner Shareable entry 
#else
	mcr     p15, 0, r0, c8, c7, 1				// Invalidate TLB entry
#endif
	add		r0, r0, ARM_PGBYTES					// Increment to the next page
	cmp		r0, r1								// Loop if current address < end address
	blt		1b
	dsb		ish									// Synchronize
	isb
	bx		lr


/*
 *	void flush_mmu_tlb_mva_entries(uint32_t)
 *
 *		Flush TLB entries for mva
 */
	.text
	.align 2
	.globl EXT(flush_mmu_tlb_mva_entries)
LEXT(flush_mmu_tlb_mva_entries)
#if	__ARM_SMP__
	mcr     p15, 0, r0, c8, c3, 3				// Invalidate TLB Inner Shareable entries by mva
#else
	mcr     p15, 0, r0, c8, c7, 3				// Invalidate TLB Inner Shareable entries by mva
#endif
	dsb		ish
	isb
	bx		lr

/*
 *	void flush_mmu_tlb_asid(uint32_t)
 *
 *		Flush TLB entriesfor requested asid
 */
	.text
	.align 2
	.globl EXT(flush_mmu_tlb_asid)
LEXT(flush_mmu_tlb_asid)
#if	__ARM_SMP__
	mcr     p15, 0, r0, c8, c3, 2				// Invalidate TLB Inner Shareable entries by asid
#else
	mcr     p15, 0, r0, c8, c7, 2				// Invalidate TLB entries by asid
#endif
	dsb		ish
	isb
	bx		lr

/*
 *	void flush_core_tlb_asid(uint32_t)
 *
 *		Flush TLB entries for core for requested asid
 */
	.text
	.align 2
	.globl EXT(flush_core_tlb_asid)
LEXT(flush_core_tlb_asid)
	mcr     p15, 0, r0, c8, c7, 2				// Invalidate TLB entries by asid
	dsb		ish
	isb
	bx		lr

/*
 * 	Set MMU Translation Table Base
 */
	.text
	.align 2
	.globl EXT(set_mmu_ttb)
LEXT(set_mmu_ttb)
	orr		r0, r0, #(TTBR_SETUP & 0xFF)		// Setup PTWs memory attribute
	orr		r0, r0, #(TTBR_SETUP & 0xFF00)		// Setup PTWs memory attribute
	mcr		p15, 0, r0, c2, c0, 0				// write r0 to translation table 0
	dsb		ish
	isb
	bx		lr

/*
 * 	Set MMU Translation Table Base Alternate
 */
	.text
	.align 2
	.globl EXT(set_mmu_ttb_alternate)
LEXT(set_mmu_ttb_alternate)
	orr		r0, r0, #(TTBR_SETUP & 0xFF)		// Setup PTWs memory attribute
	orr		r0, r0, #(TTBR_SETUP & 0xFF00)		// Setup PTWs memory attribute
	mcr		p15, 0, r0, c2, c0, 1				// write r0 to translation table 1
	dsb		ish
	isb
	bx		lr

/*
 * 	Set MMU Translation Table Base
 */
	.text
	.align 2
	.globl EXT(get_mmu_ttb)
LEXT(get_mmu_ttb)
	mrc		p15, 0, r0, c2, c0, 0				// translation table to r0
	isb
	bx		lr

/*
 * 	get MMU control register
 */
	.text
	.align 2
	.globl EXT(get_aux_control)
LEXT(get_aux_control)
	mrc		p15, 0, r0, c1, c0, 1				// read aux control into r0
	bx		lr									// return old bits in r0

/*
 * 	set MMU control register
 */
	.text
	.align 2
	.globl EXT(set_aux_control)
LEXT(set_aux_control)
	mcr		p15, 0, r0, c1, c0, 1				// write r0 back to aux control
	isb
	bx		lr


/*
 * 	get MMU control register
 */
	.text
	.align 2
	.globl EXT(get_mmu_control)
LEXT(get_mmu_control)
	mrc		p15, 0, r0, c1, c0, 0				// read mmu control into r0
	bx		lr									// return old bits in r0

/*
 * 	set MMU control register
 */
	.text
	.align 2
	.globl EXT(set_mmu_control)
LEXT(set_mmu_control)
	mcr		p15, 0, r0, c1, c0, 0				// write r0 back to mmu control
	isb
	bx		lr

/*
 *	MMU kernel virtual to physical address translation
 */
	.text
	.align 2
	.globl EXT(mmu_kvtop)
LEXT(mmu_kvtop)
	mrs		r3, cpsr							// Read cpsr
	cpsid	if									// Disable FIQ IRQ
	mov		r1, r0
	mcr		p15, 0, r1, c7, c8, 0				// Write V2PCWPR
	isb
	mrc		p15, 0, r0, c7, c4, 0				// Read PAR
	ands	r2, r0, #0x1						// Test conversion aborted
	bne		mmu_kvtophys_fail
	ands	r2, r0, #0x2						// Test super section
	mvnne	r2, #0xFF000000
	moveq	r2, #0x000000FF
	orreq	r2, r2, #0x00000F00
	bics	r0, r0, r2							// Clear lower bits
	beq		mmu_kvtophys_fail
	and		r1, r1, r2
	orr		r0, r0, r1
	b		mmu_kvtophys_ret
mmu_kvtophys_fail:
	mov		r0, #0
mmu_kvtophys_ret:
	msr		cpsr, r3							// Restore cpsr
	bx		lr

/*
 *	MMU user virtual to physical address translation
 */
	.text
	.align 2
	.globl EXT(mmu_uvtop)
LEXT(mmu_uvtop)
	mrs		r3, cpsr							// Read cpsr
	cpsid	if									// Disable FIQ IRQ
	mov		r1, r0
	mcr		p15, 0, r1, c7, c8, 2				// Write V2PCWUR
	isb
	mrc		p15, 0, r0, c7, c4, 0				// Read PAR
	ands	r2, r0, #0x1						// Test conversion aborted
	bne		mmu_uvtophys_fail
	ands	r2, r0, #0x2						// Test super section
	mvnne	r2, #0xFF000000
	moveq	r2, #0x000000FF
	orreq	r2, r2, #0x00000F00
	bics	r0, r0, r2							// Clear lower bits
	beq		mmu_uvtophys_fail
	and		r1, r1, r2
	orr		r0, r0, r1
	b		mmu_uvtophys_ret
mmu_uvtophys_fail:
	mov		r0, #0
mmu_uvtophys_ret:
	msr		cpsr, r3							// Restore cpsr
	bx		lr

/*
 *	MMU kernel virtual to physical address preflight write access
 */
	.text
	.align 2
	.globl EXT(mmu_kvtop_wpreflight)
LEXT(mmu_kvtop_wpreflight)
	mrs		r3, cpsr							// Read cpsr
	cpsid	if									// Disable FIQ IRQ
	mov		r1, r0
	mcr		p15, 0, r1, c7, c8, 1				// Write V2PCWPW
	isb
	mrc		p15, 0, r0, c7, c4, 0				// Read PAR
	ands	r2, r0, #0x1						// Test conversion aborted
	bne		mmu_kvtophys_wpreflight_fail
	ands	r2, r0, #0x2						// Test super section
	mvnne	r2, #0xFF000000
	moveq	r2, #0x000000FF
	orreq	r2, r2, #0x00000F00
	bics	r0, r0, r2							// Clear lower bits
	beq		mmu_kvtophys_wpreflight_fail		// Sanity check: successful access must deliver zero low bits
	and		r1, r1, r2
	orr		r0, r0, r1
	b		mmu_kvtophys_wpreflight_ret
mmu_kvtophys_wpreflight_fail:
	mov		r0, #0
mmu_kvtophys_wpreflight_ret:
	msr		cpsr, r3							// Restore cpsr
	bx		lr

/*
 *  set context id register
 */
/*
 *  set context id register
 */
	.text
	.align 2
	.globl EXT(set_context_id)
LEXT(set_context_id)
	mcr		p15, 0, r0, c13, c0, 1
	isb
	bx		lr

#define COPYIO_HEADER(rUser, kLabel)					\
	/* test for zero len */						;\
	cmp		r2, #0						;\
	moveq		r0, #0						;\
	bxeq		lr						;\
	/* test user_addr, user_addr+len to see if it's in kernel space */		;\
	add		r12, rUser, r2					;\
	cmp		r12, KERNELBASE					;\
	bhs		kLabel						;\
	cmp		r12, rUser					;\
	bcc		kLabel

#define	COPYIO_VALIDATE(NAME, SIZE)					\
	/* branch around for small sizes */				;\
	cmp		r2, #(SIZE)					;\
	bls		L##NAME##_validate_done				;\
	/* call NAME_validate to check the arguments */			;\
	push		{r0, r1, r2, r7, lr}				;\
	add		r7, sp, #12					;\
	blx		EXT(NAME##_validate)				;\
	cmp		r0, #0						;\
	addne           sp, #12						;\
	popne		{r7, pc}					;\
	pop		{r0, r1, r2, r7, lr}				;\
L##NAME##_validate_done:

#define	COPYIO_SET_RECOVER()						\
	/* set recovery address */					;\
	stmfd		sp!, { r4, r5, r6 }				;\
	adr		r3, copyio_error				;\
	mrc		p15, 0, r12, c13, c0, 4				;\
	ldr		r4, [r12, TH_RECOVER]				;\
	str		r3, [r12, TH_RECOVER]

#if __ARM_USER_PROTECT__
#define	COPYIO_MAP_USER()					\
	/* disable interrupts to prevent expansion to 2GB at L1 ;\
	 * between loading ttep and storing it in ttbr0.*/	;\
	mrs		r5, cpsr				;\
	cpsid		if					;\
	ldr		r3, [r12, ACT_UPTW_TTB]			;\
	mcr		p15, 0, r3, c2, c0, 0			;\
	msr		cpsr, r5				;\
	ldr		r3, [r12, ACT_ASID]			;\
	mcr		p15, 0, r3, c13, c0, 1			;\
	isb
#else
#define	COPYIO_MAP_USER()
#endif

#define COPYIO_HEADER_KERN()						;\
	/* test for zero len */						;\
	cmp		r2, #0						;\
	moveq		r0, #0						;\
	bxeq		lr
	
.macro COPYIO_BODY
	/* if len is less than 16 bytes, just do a simple copy */
	cmp			r2, #16
	blt			L$0_bytewise
	/* test for src and dest of the same word alignment */
	orr			r3, r0, r1
	tst			r3, #3
	bne			L$0_bytewise
L$0_wordwise:
	sub			r2, r2, #16
L$0_wordwise_loop:
	/* 16 bytes at a time */
	ldmia		r0!, { r3, r5, r6, r12 }
	stmia		r1!, { r3, r5, r6, r12 }
	subs		r2, r2, #16
	bge			L$0_wordwise_loop
	/* fixup the len and test for completion */
	adds		r2, r2, #16
	beq			L$0_noerror
L$0_bytewise:
	/* copy 2 bytes at a time */
	subs		r2, r2, #2
	ldrb		r3, [r0], #1
	ldrbpl		r12, [r0], #1
	strb		r3, [r1], #1
	strbpl		r12, [r1], #1
	bhi			L$0_bytewise
L$0_noerror:
	mov			r0, #0
.endmacro

#if __ARM_USER_PROTECT__
#define	COPYIO_UNMAP_USER()					\
	mrc		p15, 0, r12, c13, c0, 4				;\
	ldr		r3, [r12, ACT_KPTW_TTB]				;\
	mcr		p15, 0, r3, c2, c0, 0				;\
	mov		r3, #0						;\
	mcr		p15, 0, r3, c13, c0, 1				;\
	isb
#else
#define	COPYIO_UNMAP_USER()					\
	mrc		p15, 0, r12, c13, c0, 4
#endif

#define	COPYIO_RESTORE_RECOVER()					\
	/* restore the recovery address */			;\
	str		r4, [r12, TH_RECOVER]			;\
	ldmfd		sp!, { r4, r5, r6 }

/*
 * int copyinstr(
 *	  const user_addr_t user_addr,
 *	  char *kernel_addr,
 *	  vm_size_t max,
 *	  vm_size_t *actual)
 */
	.text
	.align 2
	.globl EXT(copyinstr)
LEXT(copyinstr)
	stmfd	sp!, { r4, r5, r6 }
	
	mov		r6, r3
	add		r3, r0, r2						// user_addr + max
	cmp		r3, KERNELBASE					// Check KERNELBASE < user_addr + max
	bhs		copyinstr_param_error			// Drop out if it is
	cmp		r3, r0							// Check we're copying from user space
	bcc		copyinstr_param_error			// Drop out if we aren't
	adr     	r3, copyinstr_error			// Get address for recover
	mrc		p15, 0, r12, c13, c0, 4			// Read TPIDRPRW
	ldr		r4, [r12, TH_RECOVER]				;\
	str		r3, [r12, TH_RECOVER]
	COPYIO_MAP_USER()
	mov		r12, #0							// Number of bytes copied so far
	cmp		r2, #0
	beq		copyinstr_too_long
copyinstr_loop:
	ldrb		r3, [r0], #1					// Load a byte from the source (user)
	strb		r3, [r1], #1					// Store a byte to the destination (kernel)
	add		r12, r12, #1
	cmp		r3, #0
	beq		copyinstr_done
	cmp		r12, r2							// Room to copy more bytes?
	bne		copyinstr_loop
//
// Ran out of space in the destination buffer, so return ENAMETOOLONG.
//
copyinstr_too_long:
	mov		r3, #ENAMETOOLONG
copyinstr_done:
//
// When we get here, we have finished copying the string.  We came here from
// either the "beq copyinstr_done" above, in which case r4 == 0 (which is also
// the function result for success), or falling through from copyinstr_too_long,
// in which case r4 == ENAMETOOLONG.
//
	str		r12, [r6]						// Save the count for actual
	mov		r0, r3							// Return error code from r3
copyinstr_exit:
	COPYIO_UNMAP_USER()
	str		r4, [r12, TH_RECOVER]
copyinstr_exit2:
	ldmfd	sp!, { r4, r5, r6 }
	bx		lr

copyinstr_error:
	/* set error, exit routine */
	mov		r0, #EFAULT
	b		copyinstr_exit

copyinstr_param_error:
	/* set error, exit routine */
	mov		r0, #EFAULT
	b		copyinstr_exit2

/*
 * int copyin(const user_addr_t user_addr, char *kernel_addr, vm_size_t nbytes)
 */
	.text
	.align 2
	.globl EXT(copyin)
LEXT(copyin)
	COPYIO_HEADER(r0,copyio_kernel)
	COPYIO_VALIDATE(copyin,4096)
	COPYIO_SET_RECOVER()
	COPYIO_MAP_USER()
	COPYIO_BODY copyin
	COPYIO_UNMAP_USER()
	COPYIO_RESTORE_RECOVER()
	bx	lr

/*
 *  int copyout(const char *kernel_addr, user_addr_t user_addr, vm_size_t nbytes)
 */
	.text
	.align 2
	.globl EXT(copyout)
LEXT(copyout)
	COPYIO_HEADER(r1,copyio_kernel)
	COPYIO_VALIDATE(copyout,4096)
	COPYIO_SET_RECOVER()
	COPYIO_MAP_USER()
	COPYIO_BODY copyout
	COPYIO_UNMAP_USER()
	COPYIO_RESTORE_RECOVER()
	bx		lr


/*
 *  int copyin_word(const user_addr_t user_addr, uint64_t *kernel_addr, vm_size_t nbytes)
 */
	.text
	.align 2
	.globl EXT(copyin_word)
LEXT(copyin_word)
	cmp		r2, #4			// Test if size is 4 or 8
	cmpne		r2, #8
	bne		L_copyin_invalid
	sub		r3, r2, #1
	tst		r0, r3			// Test alignment of user address
	bne		L_copyin_invalid

	COPYIO_HEADER(r0,L_copyin_word_fault)
	COPYIO_SET_RECOVER()
	COPYIO_MAP_USER()

	mov		r3, #0			// Clear high register
	cmp		r2, #4			// If size is 4
	ldreq		r2, [r0]		// 	Load word from user
	ldrdne		r2, r3, [r0]		// Else Load double word from user
	stm		r1, {r2, r3}		// Store to kernel_addr
	mov		r0, #0			// Success

	COPYIO_UNMAP_USER()
	COPYIO_RESTORE_RECOVER()
	bx		lr
L_copyin_invalid:
	mov		r0, #EINVAL
	bx		lr
L_copyin_word_fault:
	mov		r0, #EFAULT
	bx		lr


copyio_error:
	mov		r0, #EFAULT
	COPYIO_UNMAP_USER()
	str		r4, [r12, TH_RECOVER]
	ldmfd		sp!, { r4, r5, r6 }
	bx		lr

/*
 * int copyin_kern(const user_addr_t user_addr, char *kernel_addr, vm_size_t nbytes)
 */
	.text
	.align 2
	.globl EXT(copyin_kern)
LEXT(copyin_kern)
	COPYIO_HEADER_KERN()
	b		bypass_check

/*
 *  int copyout_kern(const char *kernel_addr, user_addr_t user_addr, vm_size_t nbytes)
 */
	.text
	.align 2
	.globl EXT(copyout_kern)
LEXT(copyout_kern)
	COPYIO_HEADER_KERN()
	b		bypass_check

copyio_kernel_error:
	mov		r0, #EFAULT
	bx		lr

copyio_kernel:
	/* if (current_thread()->map->pmap != kernel_pmap) return EFAULT */
	mrc		p15, 0, r12, c13, c0, 4			// Read TPIDRPRW
	ldr		r3, [r12, ACT_MAP]
	ldr		r3, [r3, MAP_PMAP]
	LOAD_ADDR(ip, kernel_pmap_store)
	cmp		r3, ip
	bne		copyio_kernel_error

bypass_check:
	stmfd	sp!, { r5, r6 }
	COPYIO_BODY copyio_kernel
	ldmfd	sp!, { r5, r6 }
	bx		lr
		
/*
 * int copyinframe(const vm_address_t frame_addr, char *kernel_addr)
 *
 *	Safely copy eight bytes (the fixed top of an ARM frame) from
 *	either user or kernel memory.
 */
	.text
	.align 2
	.globl EXT(copyinframe)
LEXT(copyinframe)
	COPYIO_SET_RECOVER()
	COPYIO_MAP_USER()
	ldmia		r0, {r2, r3}
	stmia		r1, {r2, r3}
	b		Lcopyin_noerror

/* 
 * uint32_t arm_debug_read_dscr(void)
 */
	.text
	.align 2
	.globl EXT(arm_debug_read_dscr)
LEXT(arm_debug_read_dscr)
#if __ARM_DEBUG__ >= 6
	mrc		p14, 0, r0, c0, c1
#else
	mov		r0, #0
#endif
	bx		lr

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
#if __ARM_DEBUG__ >= 6
	mrc		p15, 0, r1, c13, c0, 4					// Read TPIDRPRW
	ldr		r2, [r1, ACT_CPUDATAP]					// Get current cpu
	str   	r0, [r2, CPU_USER_DEBUG]				// Set current user debug

	// Lock the debug registers
	movw    ip, #0xCE55
	movt    ip, #0xC5AC
	mcr     p14, 0, ip, c1, c0, 4

	// enable monitor mode (needed to set and use debug registers)
	mrc     p14, 0, ip, c0, c1, 0
	orr     ip, ip, #0x8000    	// set MDBGen = 1
#if __ARM_DEBUG__ >= 7
	mcr     p14, 0, ip, c0, c2, 2
#else
	mcr	    p14, 0, ip, c0, c1, 0
#endif
	// first turn off all breakpoints/watchpoints
	mov     r1, #0
	mcr     p14, 0, r1, c0, c0, 5   // BCR0
	mcr     p14, 0, r1, c0, c1, 5   // BCR1
	mcr     p14, 0, r1, c0, c2, 5   // BCR2
	mcr     p14, 0, r1, c0, c3, 5   // BCR3
	mcr     p14, 0, r1, c0, c4, 5   // BCR4
	mcr     p14, 0, r1, c0, c5, 5   // BCR5
	mcr     p14, 0, r1, c0, c0, 7   // WCR0
	mcr     p14, 0, r1, c0, c1, 7   // WCR1
	// if (debug_state == NULL) disable monitor mode and return;
	cmp     r0, #0
	biceq   ip, ip, #0x8000		// set MDBGen = 0
#if __ARM_DEBUG__ >= 7
	mcreq   p14, 0, ip, c0, c2, 2
#else
	mcreq   p14, 0, ip, c0, c1, 0
#endif
	bxeq    lr
	ldmia   r0!, {r1, r2, r3, ip}
	mcr     p14, 0, r1, c0, c0, 4   // BVR0
	mcr     p14, 0, r2, c0, c1, 4   // BVR1
	mcr     p14, 0, r3, c0, c2, 4   // BVR2
	mcr     p14, 0, ip, c0, c3, 4   // BVR3
	ldmia   r0!, {r1, r2}
	mcr     p14, 0, r1, c0, c4, 4   // BVR4
	mcr     p14, 0, r2, c0, c5, 4   // BVR5
	add     r0, r0, #40             // advance to bcr[0]
	ldmia   r0!, {r1, r2, r3, ip}
	mcr     p14, 0, r1, c0, c0, 5   // BCR0
	mcr     p14, 0, r2, c0, c1, 5   // BCR1
	mcr     p14, 0, r3, c0, c2, 5   // BCR2
	mcr     p14, 0, ip, c0, c3, 5   // BCR3
	ldmia   r0!, {r1, r2}
	mcr     p14, 0, r1, c0, c4, 5   // BCR4
	mcr     p14, 0, r2, c0, c5, 5   // BCR5
	add     r0, r0, #40             // advance to wvr[0]
	ldmia   r0!, {r1, r2}
	mcr     p14, 0, r1, c0, c0, 6   // WVR0
	mcr     p14, 0, r2, c0, c1, 6   // WVR1
	add     r0, r0, #56             // advance to wcr[0]
	ldmia   r0!, {r1, r2}
	mcr     p14, 0, r1, c0, c0, 7   // WCR0
	mcr     p14, 0, r2, c0, c1, 7   // WCR1
	
	// Unlock debug registers
	mov     ip, #0
	mcr     p14, 0, ip, c1, c0, 4
#endif
	bx      lr
	
/*
 *	void fiq_context_init(boolean_t enable_fiq)
 */
	.text
	.align 2
	.globl EXT(fiq_context_init)
LEXT(fiq_context_init)
	mrs		r3, cpsr									// Save current CPSR
	cmp		r0, #0										// Test enable_fiq
	bicne	r3, r3, #PSR_FIQF							// Enable FIQ if not FALSE
	mrc		p15, 0, r12, c13, c0, 4						// Read TPIDRPRW
	ldr		r2, [r12, ACT_CPUDATAP]						// Get current cpu data

#if __ARM_TIME__
	/* Despite the fact that we use the physical timebase
	 * register as the basis for time on our platforms, we
	 * end up using the virtual timer in order to manage
	 * deadlines.  This is due to the fact that for our
	 * current platforms, the interrupt generated by the
	 * physical timer is not hooked up to anything, and is
	 * therefore dropped on the floor.  Therefore, for
	 * timers to function they MUST be based on the virtual
	 * timer.
	 */

	mov		r0, #1										// Enable Timer
	mcr		p15, 0, r0, c14, c3, 1						// Write to CNTV_CTL

	/* Enable USER access to the physical timebase (PL0PCTEN).
	 * The rationale for providing access to the physical
	 * timebase being that the virtual timebase is broken for
	 * some platforms.  Maintaining the offset ourselves isn't
	 * expensive, so mandate that the userspace implementation
	 * do timebase_phys+offset rather than trying to propogate
	 * all of the informaiton about what works up to USER.
	 */
	mcr		p15, 0, r0, c14, c1, 0						// Set CNTKCTL.PL0PCTEN (CNTKCTL[0])

#else /* ! __ARM_TIME__ */
	msr		cpsr_c, #(PSR_FIQ_MODE|PSR_FIQF|PSR_IRQF)	// Change mode to FIQ with FIQ/IRQ disabled
	mov		r8, r2										// Load the BootCPUData address
	ldr		r9, [r2, CPU_GET_FIQ_HANDLER]				// Load fiq function address
	ldr		r10, [r2, CPU_TBD_HARDWARE_ADDR]			// Load the hardware address
	ldr		r11, [r2, CPU_TBD_HARDWARE_VAL]				// Load the hardware value
#endif /* __ARM_TIME__ */

	msr		cpsr_c, r3									// Restore saved CPSR
	bx		lr

/*
 *	void reenable_async_aborts(void)
 */
	.text
	.align 2
	.globl EXT(reenable_async_aborts)
LEXT(reenable_async_aborts)
	cpsie 	a											// Re-enable async aborts
	bx		lr

/*
 *	uint64_t ml_get_timebase(void)
 */
	.text
	.align 2
	.globl EXT(ml_get_timebase)
LEXT(ml_get_timebase)
	mrc		p15, 0, r12, c13, c0, 4						// Read TPIDRPRW
	ldr		r3, [r12, ACT_CPUDATAP]						// Get current cpu data
#if __ARM_TIME__ || __ARM_TIME_TIMEBASE_ONLY__
	isb													// Required by ARMV7C.b section B8.1.2, ARMv8 section D6.1.2.
1:
	mrrc	p15, 0, r3, r1, c14							// Read the Time Base (CNTPCT), high => r1
	mrrc	p15, 0, r0, r3, c14							// Read the Time Base (CNTPCT), low => r0
	mrrc	p15, 0, r3, r2, c14							// Read the Time Base (CNTPCT), high => r2
	cmp		r1, r2
	bne		1b											// Loop until both high values are the same

	ldr		r3, [r12, ACT_CPUDATAP]						// Get current cpu data
	ldr		r2, [r3, CPU_BASE_TIMEBASE_LOW]				// Add in the offset to
	adds	r0, r0, r2									// convert to
	ldr		r2, [r3, CPU_BASE_TIMEBASE_HIGH]			// mach_absolute_time
	adc		r1, r1, r2									//
#else /* ! __ARM_TIME__  || __ARM_TIME_TIMEBASE_ONLY__ */
1:
	ldr		r2, [r3, CPU_TIMEBASE_HIGH]					// Get the saved TBU value
	ldr		r0, [r3, CPU_TIMEBASE_LOW]					// Get the saved TBL value
	ldr		r1, [r3, CPU_TIMEBASE_HIGH]					// Get the saved TBU value
	cmp		r1, r2										// Make sure TB has not rolled over
	bne		1b
#endif /* __ARM_TIME__ */
	bx		lr											// return


/*
 *	uint32_t ml_get_decrementer(void)
 */
	.text
	.align 2
	.globl EXT(ml_get_decrementer)
LEXT(ml_get_decrementer)
	mrc		p15, 0, r12, c13, c0, 4						// Read TPIDRPRW
	ldr		r3, [r12, ACT_CPUDATAP]						// Get current cpu data
	ldr		r2, [r3, CPU_GET_DECREMENTER_FUNC]			// Get get_decrementer_func
	cmp		r2, #0
	bxne	r2											// Call it if there is one
#if __ARM_TIME__
	mrc		p15, 0, r0, c14, c3, 0						// Read the Decrementer (CNTV_TVAL)
#else
	ldr		r0, [r3, CPU_DECREMENTER]					// Get the saved dec value
#endif
	bx		lr											// return


/*
 *	void ml_set_decrementer(uint32_t dec_value)
 */
	.text
	.align 2
	.globl EXT(ml_set_decrementer)
LEXT(ml_set_decrementer)
	mrc		p15, 0, r12, c13, c0, 4						// Read TPIDRPRW
	ldr		r3, [r12, ACT_CPUDATAP]						// Get current cpu data
	ldr		r2, [r3, CPU_SET_DECREMENTER_FUNC]			// Get set_decrementer_func
	cmp		r2, #0
	bxne	r2											// Call it if there is one
#if __ARM_TIME__
	str		r0, [r3, CPU_DECREMENTER]					// Save the new dec value
	mcr		p15, 0, r0, c14, c3, 0						// Write the Decrementer (CNTV_TVAL)
#else
	mrs		r2, cpsr									// Save current CPSR
	msr		cpsr_c, #(PSR_FIQ_MODE|PSR_FIQF|PSR_IRQF)	// Change mode to FIQ with FIQ/IRQ disabled.
	mov		r12, r0										// Set the DEC value
	str		r12, [r8, CPU_DECREMENTER]					// Store DEC
	msr		cpsr_c, r2									// Restore saved CPSR
#endif
	bx		lr


/*
 *	boolean_t ml_get_interrupts_enabled(void)
 */
	.text
	.align 2
	.globl EXT(ml_get_interrupts_enabled)
LEXT(ml_get_interrupts_enabled)
	mrs	r2, cpsr
	mov		r0, #1
	bic		r0, r0, r2, lsr #PSR_IRQFb
	bx		lr

/*
 * Platform Specific Timebase & Decrementer Functions
 *
 */

#if defined(ARM_BOARD_CLASS_S7002)
	.text
	.align 2
	.globl EXT(fleh_fiq_s7002)
LEXT(fleh_fiq_s7002)
	str		r11, [r10, #PMGR_INTERVAL_TMR_CTL_OFFSET]		// Clear the decrementer interrupt
	mvn		r13, #0
	str		r13, [r8, CPU_DECREMENTER]
	b		EXT(fleh_dec)

	.text
	.align 2
	.globl EXT(s7002_get_decrementer)
LEXT(s7002_get_decrementer)
	ldr		ip, [r3, CPU_TBD_HARDWARE_ADDR]					// Get the hardware address
	add		ip, ip, #PMGR_INTERVAL_TMR_OFFSET
	ldr		r0, [ip]										// Get the Decrementer
	bx		lr

	.text
	.align 2
	.globl EXT(s7002_set_decrementer)
LEXT(s7002_set_decrementer)
	str		r0, [r3, CPU_DECREMENTER]					// Save the new dec value
	ldr		ip, [r3, CPU_TBD_HARDWARE_ADDR]				// Get the hardware address
	str		r0, [ip, #PMGR_INTERVAL_TMR_OFFSET]			// Store the new Decrementer
	bx		lr
#endif /* defined(ARM_BOARD_CLASS_S7002) */

#if defined(ARM_BOARD_CLASS_T8002)
	.text
	.align 2
	.globl EXT(fleh_fiq_t8002)
LEXT(fleh_fiq_t8002)
	mov		r13, #kAICTmrIntStat
	str		r11, [r10, r13]						// Clear the decrementer interrupt
	mvn		r13, #0
	str		r13, [r8, CPU_DECREMENTER]
	b		EXT(fleh_dec)

	.text
	.align 2
	.globl EXT(t8002_get_decrementer)
LEXT(t8002_get_decrementer)
	ldr		ip, [r3, CPU_TBD_HARDWARE_ADDR]					// Get the hardware address
	mov		r0, #kAICTmrCnt
	add		ip, ip, r0
	ldr		r0, [ip]										// Get the Decrementer
	bx		lr

	.text
	.align 2
	.globl EXT(t8002_set_decrementer)
LEXT(t8002_set_decrementer)
	str		r0, [r3, CPU_DECREMENTER]					// Save the new dec value
	ldr		ip, [r3, CPU_TBD_HARDWARE_ADDR]				// Get the hardware address
	mov		r5, #kAICTmrCnt
	str		r0, [ip, r5]						// Store the new Decrementer
	bx		lr
#endif /* defined(ARM_BOARD_CLASS_T8002) */

LOAD_ADDR_GEN_DEF(kernel_pmap_store)

#include        "globals_asm.h"

/* vim: set ts=4: */

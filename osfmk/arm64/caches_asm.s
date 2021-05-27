/*
 * Copyright (c) 2010-2013 Apple Inc. All rights reserved.
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
#include <arm64/proc_reg.h>
#include <pexpert/arm64/board_config.h>
#include <arm/pmap.h>
#include <sys/errno.h>
#include "assym.s"

/*
 *	void InvalidatePoU_Icache(void)
 *
 *		Invalidate i-cache
 */
	.text
	.align 2
	.globl EXT(InvalidatePoU_Icache)
	.globl EXT(invalidate_mmu_icache)
LEXT(InvalidatePoU_Icache)
LEXT(invalidate_mmu_icache)
	dsb		sy
	ic		ialluis								// Invalidate icache
	dsb		sy
	isb		sy
L_imi_done:
	ret

/*
 *	void InvalidatePoU_IcacheRegion(vm_offset_t va, unsigned length)
 *
 *		Invalidate icache region
 */
	.text
	.align 2
	.globl EXT(InvalidatePoU_IcacheRegion)
LEXT(InvalidatePoU_IcacheRegion)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	bl		EXT(CleanPoU_DcacheRegion)
#if __ARM_IC_NOALIAS_ICACHE__
	mov		x9, #((1<<MMU_I_CLINE)-1) 
	and		x2, x0, x9
	bic		x0, x0, x9							// Cached aligned
	add		x1, x1, x2
	sub		x1, x1, #1
	lsr		x1, x1, #MMU_I_CLINE					// Set cache line counter
L_ipui_loop:
	ic		ivau, x0							// Invalidate icache line
	add		x0, x0, #1<<MMU_I_CLINE				// Get next cache aligned addr
	subs	x1, x1, #1							// Decrementer cache line counter
	b.pl	L_ipui_loop							// Loop in counter not null
	dsb		sy
	isb		sy
L_ipui_done:
#else
	bl		EXT(InvalidatePoU_Icache)
#endif
	POP_FRAME
	ARM64_STACK_EPILOG

/*
 *	Obtains cache physical layout information required for way/set
 *	data cache maintenance operations.
 *
 *	$0: Data cache level, starting from 0
 *	$1: Output register for set increment
 *	$2: Output register for last valid set
 *	$3: Output register for way increment
 */
.macro GET_CACHE_CONFIG
	lsl		$0, $0, #1
	msr		CSSELR_EL1, $0						// Select appropriate cache
	isb											// Synchronize context

	mrs		$0, CCSIDR_EL1
	ubfx	$1, $0, #3, #10						// extract number of ways - 1
	mov		$2, $1
	add		$1, $1, #1							// calculate number of ways

	mov		$0, #63
	and		$2, $2, $1
	cmp		$2, #0
	cinc	$0, $0, ne
	clz		$1, $1
	sub		$0, $0, $1

	mov 	$1, #32								// calculate way increment
	sub		$3, $1, $0
	mov		$1, #1
	lsl		$3, $1, $3

	mrs		$0, CCSIDR_EL1
	ubfx	$1, $0, #0, #3						// extract log2(line size) - 4
	add		$1, $1, #4							// calculate log2(line size)
	mov		$2, #1
	lsl		$1, $2, $1							// calculate set increment

	ubfx	$2, $0, #13, #15					// extract number of sets - 1
	add		$2, $2, #1							// calculate number of sets
	mul		$2, $1, $2							// calculate last valid set
.endmacro

/*
 * Returns the cache configuration for the specified level
 *	$0: Output register
 *	$1: Cache level register
 *	$2: Scratch register
 */
.macro CACHE_AT_LEVEL
	mrs		$0, CLIDR_EL1
	add		$2, $1, $1, lsl #1
	lsr		$0, $0, $2
	and		$0, $0, #7					// extract cache type
.endmacro

/*
 * Perform set/way maintenance to the desired cache level
 *	$0: 'dc' set/way variant, e.g. csw or cisw
 *	x0: maximum cache level, 0-based, inclusive
 */
.macro DCACHE_SET_WAY
	dmb		sy
	mov		x1, #0
1:
	CACHE_AT_LEVEL x2, x1, x3
	cbz		x2, 5f			// No cache at this level, all higher levels may be skipped
	cmp		x2, #2
	b.lt		4f			// No data cache at this level, skip to next level
	mov		x2, x1
	GET_CACHE_CONFIG x2, x9, x10, x11
	lsl		x2, x1, #1		// level field for cisw/csw, bits 1:3
2:
3:
	dc		$0, x2			// clean dcache line by way/set
	add		x2, x2, x9		// increment set index
	tst		x2, x10			// look for overflow
	b.eq		3b
	bic		x2, x2, x10		// clear set overflow
	adds		w2, w2, w11		// increment way
	b.cc		2b			// loop
	dsb		sy			// ensure completion of prior level maintenance
4:
	add		x1, x1, #1
	cmp		x1, x0
	b.ls		1b			// next level
5:
	ret
.endmacro

/*
 * void CleanPoC_Dcache(void)
 *
 *		Clean all d-caches
 */
	.text
	.align 2
	.globl EXT(CleanPoC_Dcache)
	.globl EXT(clean_mmu_dcache)
LEXT(CleanPoC_Dcache)
#if  defined(APPLE_ARM64_ARCH_FAMILY)
	dsb		sy
	ret
	/* "Fully Coherent." */
#else /* !defined(APPLE_ARM64_ARCH_FAMILY) */
	mrs		x0, CLIDR_EL1
	ubfx		x0, x0, #24, #3	// extract CLIDR_EL1.LoC
	DCACHE_SET_WAY csw
#endif /* defined(APPLE_ARM64_ARCH_FAMILY) */

/*
 * void CleanPoU_Dcache(void)
 *
 *		Clean D-cache to Point of Unification
 */
	.text
	.align 2
	.globl EXT(CleanPoU_Dcache)
LEXT(CleanPoU_Dcache)
#if defined(APPLE_ARM64_ARCH_FAMILY)
	dsb sy
	ret
	/* "Fully Coherent." */
#else /* !defined(APPLE_ARM64_ARCH_FAMILY) */
	mrs		x0, CLIDR_EL1
	ubfx		x0, x0, #21, 3	// extract CLIDR_EL1.LoUIS
	DCACHE_SET_WAY csw
#endif /* defined(APPLE_ARM64_ARCH_FAMILY) */

/*
 *	void CleanPoU_DcacheRegion(vm_offset_t va, unsigned length)
 *
 *		Clean d-cache region to Point of Unification
 */
	.text
	.align 2
	.globl EXT(CleanPoU_DcacheRegion)
LEXT(CleanPoU_DcacheRegion)
#if defined(APPLE_ARM64_ARCH_FAMILY)
	/* "Fully Coherent." */
#else /* !defined(APPLE_ARM64_ARCH_FAMILY) */
	mov		x9, #((1<<MMU_CLINE)-1)
	and		x2, x0, x9
	bic		x3, x0, x9							// Cached aligned
	add		x4, x1, x2
	sub		x4, x4, #1
	lsr		x4, x4, #MMU_CLINE					// Set cache line counter
	dmb		sy
L_cpudr_loop:
	dc		cvau, x3							// Clean dcache line to PoU 
	add		x3, x3, #(1<<MMU_CLINE)				// Get next cache aligned addr
	subs	x4, x4, #1							// Decrementer cache line counter
	b.pl	L_cpudr_loop						// Loop in counter not null
#endif /* defined(APPLE_ARM64_ARCH_FAMILY) */
	dsb		sy
	ret

/*
 *	void CleanPoC_DcacheRegion_internal(vm_offset_t va, size_t length)
 *
 *		Clean d-cache region to Point of Coherency
 */
	.text
	.align 2
LEXT(CleanPoC_DcacheRegion_internal)
	mov x10, #(MMU_CLINE)

	/* Stash (1 << cache_line_size) in x11 for easy access. */
	mov x11, #1
	lsl x11, x11, x10

	sub		x9, x11, #1
	and		x2, x0, x9
	bic		x0, x0, x9							// Cached aligned
	add		x1, x1, x2
	sub		x1, x1, #1
	lsr		x1, x1, x10							// Set cache line counter
	dsb		sy	
L_cpcdr_loop:
#if defined(APPLE_ARM64_ARCH_FAMILY)
	// It may be tempting to clean the cache (dc cvac), 
	// but see Cyclone UM 5.3.8.3 -- it's always a NOP on Cyclone.
	//
	// Clean & Invalidate, however, will work as long as HID4.DisDCMvaOps isn't set.
	dc		civac, x0							// Clean & Invalidate dcache line to PoC
#else
	dc		cvac, x0 							// Clean dcache line to PoC
#endif
	add		x0, x0, x11							// Get next cache aligned addr
	subs	x1, x1, #1							// Decrementer cache line counter
	b.pl	L_cpcdr_loop						// Loop in counter not null
	dsb		sy
	ret

/*
 *	void CleanPoC_DcacheRegion(vm_offset_t va, size_t length)
 *
 *		Clean d-cache region to Point of Coherency
 */
	.text
	.align 2
	.globl EXT(CleanPoC_DcacheRegion)
LEXT(CleanPoC_DcacheRegion)
#if defined(APPLE_ARM64_ARCH_FAMILY)
	/* "Fully Coherent." */
	dsb		sy
	ret
#else /* !defined(APPLE_ARM64_ARCH_FAMILY) */
	b EXT(CleanPoC_DcacheRegion_internal)
#endif /* defined(APPLE_ARM64_ARCH_FAMILY) */

	.text
	.align 2
	.globl EXT(CleanPoC_DcacheRegion_Force_nopreempt)
LEXT(CleanPoC_DcacheRegion_Force_nopreempt)
#if defined(APPLE_ARM64_ARCH_FAMILY) && !APPLEVIRTUALPLATFORM
	ARM64_STACK_PROLOG
	PUSH_FRAME
	isb		sy
	ARM64_IS_PCORE x15
	ARM64_READ_EP_SPR x15, x14, EHID4, HID4
	and		x14, x14, (~ARM64_REG_HID4_DisDcMVAOps)
	ARM64_WRITE_EP_SPR x15, x14, EHID4, HID4
	isb		sy
	bl		EXT(CleanPoC_DcacheRegion_internal)
	isb		sy
	orr		x14, x14, ARM64_REG_HID4_DisDcMVAOps
	ARM64_WRITE_EP_SPR x15, x14, EHID4, HID4
	isb		sy
	POP_FRAME
	ARM64_STACK_EPILOG
#else
	b		EXT(CleanPoC_DcacheRegion_internal)
#endif // APPLE_ARM64_ARCH_FAMILY

/*
 *	void CleanPoC_DcacheRegion_Force(vm_offset_t va, size_t length)
 *
 *		Clean d-cache region to Point of Coherency -  when you really 
 *		need to flush even on coherent platforms, e.g. panic log
 */
	.text
	.align 2
	.globl EXT(CleanPoC_DcacheRegion_Force)
LEXT(CleanPoC_DcacheRegion_Force)
#if defined(APPLE_ARM64_ARCH_FAMILY)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	stp		x0, x1, [sp, #-16]!
	bl		EXT(_disable_preemption)
	ldp		x0, x1, [sp], #16
	bl		EXT(CleanPoC_DcacheRegion_Force_nopreempt)
	bl		EXT(_enable_preemption)
	POP_FRAME
	ARM64_STACK_EPILOG
#else
	b		EXT(CleanPoC_DcacheRegion_internal)
#endif // APPLE_ARM64_ARCH_FAMILY

/*
 *	void FlushPoC_Dcache(void)
 *
 *		Clean and Invalidate dcaches to Point of Coherency
 */
	.text
	.align 2
	.globl EXT(FlushPoC_Dcache)
LEXT(FlushPoC_Dcache)
#if defined(APPLE_ARM64_ARCH_FAMILY)
	dsb sy
	ret
	/* "Fully Coherent." */
#else /* !defined(APPLE_ARM64_ARCH_FAMILY) */
	mrs		x0, CLIDR_EL1
	ubfx		x0, x0, #24, #3	// extract CLIDR_EL1.LoC
	DCACHE_SET_WAY cisw
#endif /* defined(APPLE_ARM64_ARCH_FAMILY) */

/*
 * 	void Flush_Dcache(void)
 * 
 * 		Clean and invalidate D-cache, all levels
 */
	.text
	.align 2
	.globl EXT(Flush_Dcache)
LEXT(Flush_Dcache)
	mov x0, #6 // Maximum allowable caching level (0-based)
	DCACHE_SET_WAY cisw 

/*
 * void FlushPoU_Dcache(void)
 *
 *		Flush D-cache to Point of Unification
 */
	.text
	.align 2
	.globl EXT(FlushPoU_Dcache)
LEXT(FlushPoU_Dcache)
#if defined(APPLE_ARM64_ARCH_FAMILY)
	dsb sy
	ret
	/* "Fully Coherent." */
#else /* !defined(APPLE_ARM64_ARCH_FAMILY) */
	mrs		x0, CLIDR_EL1
	ubfx		x0, x0, #21, 3	// extract CLIDR_EL1.LoUIS
	DCACHE_SET_WAY	cisw
#endif /* defined(APPLE_ARM64_ARCH_FAMILY) */

/*
 *	void FlushPoC_DcacheRegion(vm_offset_t va, unsigned length)
 *
 *		Clean and Invalidate d-cache region to Point of Coherency
 */
	.text
	.align 2
	.globl EXT(FlushPoC_DcacheRegion)
LEXT(FlushPoC_DcacheRegion)
#if defined(APPLE_ARM64_ARCH_FAMILY)
	/* "Fully Coherent." */
#else /* !defined(APPLE_ARM64_ARCH_FAMILY) */
	mov		x9, #((1<<MMU_CLINE)-1)
	and		x2, x0, x9
	bic		x0, x0, x9							// Cached aligned
	add		x1, x1, x2
	sub		x1, x1, #1
	lsr		x1, x1, #MMU_CLINE					// Set cache line counter
	dmb		sy
L_fpcdr_loop:
	dc		civac, x0							// Clean invalidate dcache line to PoC
	add		x0, x0, #(1<<MMU_CLINE)				// Get next cache aligned addr
	subs	x1, x1, #1							// Decrementer cache line counter
	b.pl	L_fpcdr_loop						// Loop in counter not null
#endif /* defined(APPLE_ARM64_ARCH_FAMILY) */
	dsb		sy
	ret

/*
 *      void flush_dcache64(addr64_t addr, unsigned length, boolean_t phys)
 */
        .text
        .align 2
        .globl EXT(flush_dcache64)
LEXT(flush_dcache64)
	BRANCH_EXTERN    flush_dcache

/*
 *      void clean_dcache64(addr64_t addr, unsigned length, boolean_t phys)
 */
        .text
        .align 2
        .globl EXT(clean_dcache64)
LEXT(clean_dcache64)
	BRANCH_EXTERN    clean_dcache

/*
 *      void invalidate_icache(vm_offset_t va, unsigned length, boolean_t phys)
 *      void invalidate_icache64(addr64_t va, unsigned length, boolean_t phys)
 */
        .text
        .align 2
        .globl EXT(invalidate_icache64)
        .globl EXT(invalidate_icache)
LEXT(invalidate_icache64)
LEXT(invalidate_icache)
	cmp     w2, #0								// Is it physical?
	b.eq	Lcall_invalidate_worker
	adrp	x2, _gPhysBase@page
	add		x2, x2, _gPhysBase@pageoff
	ldr		x2, [x2]
	sub		x0, x0, x2
	adrp	x2, _gVirtBase@page
	add		x2, x2, _gVirtBase@pageoff
	ldr		x2, [x2]
	add		x0, x0, x2
Lcall_invalidate_worker:
	b		EXT(InvalidatePoU_IcacheRegion)


/* vim: set ts=4: */

/*
 * Copyright (c) 2010 Apple Inc. All rights reserved.
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
#include "caches_macros.s"


/*
 *	void invalidate_mmu_cache(void)
 *
 *		Invalidate d-cache and i-cache
 */
	.text
	.align 2
	.globl EXT(invalidate_mmu_cache)
LEXT(invalidate_mmu_cache)
	mov		r0, #0
	dsb
	mcr		p15, 0, r0, c7, c7, 0				// Invalidate caches
	dsb
	isb
	bx		lr

/*
 *	void invalidate_mmu_dcache(void)
 *
 *		Invalidate d-cache
 */
	.text
	.align 2
	.globl EXT(invalidate_mmu_dcache)
LEXT(invalidate_mmu_dcache)
	mov		r0, #0
	dsb
	mcr		p15, 0, r0, c7, c6, 0				// Invalidate dcache
	dsb
	bx		lr

/*
 *	void invalidate_mmu_dcache_region(vm_offset_t va, unsigned length)
 *
 *		Invalidate d-cache region
 */
	.text
	.align 2
	.globl EXT(invalidate_mmu_dcache_region)
LEXT(invalidate_mmu_dcache_region)
	and		r2, r0, #((1<<MMU_CLINE)-1)
	bic		r0, r0, #((1<<MMU_CLINE)-1)			// Cached aligned 
	add		r1, r1, r2
	sub		r1, r1, #1
	mov		r1, r1, LSR #MMU_CLINE				// Set cache line counter
	dsb
fmdr_loop:
	mcr		p15, 0, r0, c7, c14, 1				// Invalidate dcache line
	add		r0, r0, #1<<MMU_CLINE				// Get next cache aligned addr
	subs	r1, r1, #1							// Decrementer cache line counter
	bpl		fmdr_loop							// Loop in counter not null
	dsb
	bx		lr

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
	mov     r0, #0
	dsb
	mcr     p15, 0, r0, c7, c5, 0				// Invalidate icache
	dsb
	isb
	bx		lr

/*
 *	void InvalidatePoU_IcacheRegion(vm_offset_t va, unsigned length)
 *
 *		Invalidate icache region
 */
	.text
	.align 2
	.globl EXT(InvalidatePoU_IcacheRegion)
LEXT(InvalidatePoU_IcacheRegion)
	push		{r7,lr}
	mov		r7, sp
	bl		EXT(CleanPoU_DcacheRegion)
	and		r2, r0, #((1<<MMU_I_CLINE)-1)
	bic		r0, r0, #((1<<MMU_I_CLINE)-1)			// Cached aligned 
	add		r1, r1, r2
	sub		r1, r1, #1
	mov		r1, r1, LSR #MMU_I_CLINE			// Set cache line counter
fmir_loop:
	mcr		p15, 0, r0, c7, c5, 1				// Invalidate icache line
	add		r0, r0, #1<<MMU_I_CLINE				// Get next cache aligned addr
	subs	r1, r1, #1							// Decrementer cache line counter
	bpl		fmir_loop							// Loop in counter not null
	dsb
	isb
	pop		{r7,pc}

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
LEXT(clean_mmu_dcache)
#if	!defined(__ARM_L1_WT_CACHE__)
	mov		r0, #0
	GET_CACHE_CONFIG r0, r1, r2, r3
	mov		r0, #0
	dsb
clean_dcacheway:
clean_dcacheline:		
	mcr		p15, 0, r0, c7, c10, 2				 // clean dcache line by way/set
	add		r0, r0, r1							 // increment set index
	tst		r0, r2								 // look for overflow
	beq		clean_dcacheline
	bic		r0, r0, r2							 // clear set overflow
	adds	r0, r0, r3							 // increment way
	bcc		clean_dcacheway						 // loop
#endif
	HAS_L2_CACHE r0
	cmp		r0, #0
	beq		clean_skipl2dcache
	mov		r0, #1
	GET_CACHE_CONFIG r0, r1, r2, r3
	dsb
	mov		r0, #2
clean_l2dcacheway:
clean_l2dcacheline:		
	mcr		p15, 0, r0, c7, c10, 2				 // clean dcache line by way/set
	add		r0, r0, r1							 // increment set index
	tst		r0, r2								 // look for overflow
	beq		clean_l2dcacheline
	bic		r0, r0, r2							 // clear set overflow
	adds	r0, r0, r3							 // increment way
	bcc		clean_l2dcacheway					 // loop
clean_skipl2dcache:
	dsb
	bx		lr
		
/*
 * void CleanPoU_Dcache(void)
 *
 *		Clean D-cache to Point of Unification
 */
	.text
	.align 2
	.globl EXT(CleanPoU_Dcache)
LEXT(CleanPoU_Dcache)
#if	!defined(__ARM_PoU_WT_CACHE__)
	mov		r0, #0
	GET_CACHE_CONFIG r0, r1, r2, r3
	mov		r0, #0
	dsb
clean_dcacheway_idle:
clean_dcacheline_idle:		
	mcr		p15, 0, r0, c7, c10, 2				 // clean dcache line by way/set
	add		r0, r0, r1							 // increment set index
	tst		r0, r2								 // look for overflow
	beq		clean_dcacheline_idle
	bic		r0, r0, r2 							 // clear set overflow
	adds	r0, r0, r3				 			 // increment way
	bcc		clean_dcacheway_idle				 // loop
#endif
	dsb
	bx		lr

/*
 *	void CleanPoU_DcacheRegion(vm_offset_t va, unsigned length)
 *
 *		Clean d-cache region to Point of Unification
 */
	.text
	.align 2
	.globl EXT(CleanPoU_DcacheRegion)
LEXT(CleanPoU_DcacheRegion)
#if	!defined(__ARM_PoU_WT_CACHE__)

	and		r2, r0, #((1<<MMU_CLINE)-1)
	bic		r3, r0, #((1<<MMU_CLINE)-1)			// Cached aligned 
	add		r12, r1, r2
	sub		r12, r12, #1
	mov		r12, r12, LSR #MMU_CLINE				// Set cache line counter
	dsb
cudr_loop:
	mcr		p15, 0, r3, c7, c11, 1				// Clean dcache line to PoU
	add		r3, r3, #1<<MMU_CLINE				// Get next cache aligned addr
	subs	r12, r12, #1							// Decrementer cache line counter
	bpl		cudr_loop							// Loop in counter not null

#endif
	dsb
	bx		lr

/*
 *	void CleanPoC_DcacheRegion(vm_offset_t va, size_t length)
 *
 *		Clean d-cache region to Point of Coherency
 */
	.text
	.align 2
	.globl EXT(CleanPoC_DcacheRegion)
	.globl EXT(CleanPoC_DcacheRegion_Force)
LEXT(CleanPoC_DcacheRegion)
LEXT(CleanPoC_DcacheRegion_Force)
	and		r2, r0, #((1<<MMU_CLINE)-1)
	bic		r0, r0, #((1<<MMU_CLINE)-1)			// Cached aligned 
	add		r1, r1, r2
	sub		r1, r1, #1
	mov		r1, r1, LSR #MMU_CLINE				// Set cache line counter
ccdr_loop:
	mcr		p15, 0, r0, c7, c10, 1				// Clean dcache line to PoC
	add		r0, r0, #1<<MMU_CLINE				// Get next cache aligned addr
	subs	r1, r1, #1							// Decrementer cache line counter
	bpl		ccdr_loop							// Loop in counter not null
	dsb
	bx		lr

/*
 *	void FlushPoC_Dcache(void)
 *
 *		Clean and Invalidate dcaches to Point of Coherency
 */
	.text
	.align 2
	.globl EXT(FlushPoC_Dcache)
LEXT(FlushPoC_Dcache)
	mov		r0, #0
	GET_CACHE_CONFIG r0, r1, r2, r3
	mov		r0, #0
	dsb
cleanflush_dcacheway:
cleanflush_dcacheline:		
	mcr		p15, 0, r0, c7, c14, 2				 // cleanflush dcache line by way/set
	add		r0, r0, r1							 // increment set index
	tst		r0, r2								 // look for overflow
	beq		cleanflush_dcacheline
	bic		r0, r0, r2 							 // clear set overflow
	adds	r0, r0, r3							 // increment way
	bcc		cleanflush_dcacheway				 // loop
	HAS_L2_CACHE r0
	cmp		r0, #0
	beq		cleanflush_skipl2dcache
	mov		r0, #1
	GET_CACHE_CONFIG r0, r1, r2, r3
	dsb
	mov		r0, #2
cleanflush_l2dcacheway:
cleanflush_l2dcacheline:		
	mcr		p15, 0, r0, c7, c14, 2				 // cleanflush dcache line by way/set
	add		r0, r0, r1							 // increment set index
	tst		r0, r2	 							 // look for overflow
	beq		cleanflush_l2dcacheline
	bic		r0, r0, r2							 // clear set overflow
	adds	r0, r0, r3							 // increment way
	bcc		cleanflush_l2dcacheway				 // loop
cleanflush_skipl2dcache:
	dsb
	bx		lr

/*
 * void FlushPoU_Dcache(void)
 *
 *		Flush D-cache to Point of Unification
 */
	.text
	.align 2
	.globl EXT(FlushPoU_Dcache)
LEXT(FlushPoU_Dcache)
	mov		r0, #0
	GET_CACHE_CONFIG r0, r1, r2, r3
	mov		r0, #0
	dsb
fpud_way:
fpud_line:		
	mcr		p15, 0, r0, c7, c14, 2				 // cleanflush dcache line by way/set
	add		r0, r0, r1							 // increment set index
	tst		r0, r2								 // look for overflow
	beq		fpud_line
	bic		r0, r0, r2 							 // clear set overflow
	adds	r0, r0, r3							 // increment way
	bcc		fpud_way							 // loop
	dsb
	bx		lr

/*
 *	void FlushPoC_DcacheRegion(vm_offset_t va, unsigned length)
 *
 *		Clean and Invalidate d-cache region to Point of Coherency
 */
	.text
	.align 2
	.globl EXT(FlushPoC_DcacheRegion)
LEXT(FlushPoC_DcacheRegion)
	and		r2, r0, #((1<<MMU_CLINE)-1)
	bic		r0, r0, #((1<<MMU_CLINE)-1)			// Cached aligned 
	add		r1, r1, r2
	sub		r1, r1, #1
	mov		r1, r1, LSR #MMU_CLINE				// Set cache line counter
	dsb
cfmdr_loop:
	mcr		p15, 0, r0, c7, c14, 1				// Clean & invalidate dcache line
	add		r0, r0, #1<<MMU_CLINE				// Get next cache aligned addr
	subs	r1, r1, #1							// Decrementer cache line counter
	bpl		cfmdr_loop							// Loop in counter not null
	dsb
	bx		lr

/*
 *      void flush_dcache64(addr64_t addr, unsigned length, boolean_t phys)
 */
        .text
        .align 2
        .globl EXT(flush_dcache64)
LEXT(flush_dcache64)
	mov	r1, r2
	mov	r2, r3
	LOAD_ADDR_PC(flush_dcache)

/*
 *      void clean_dcache64(addr64_t addr, unsigned length, boolean_t phys)
 */
        .text
        .align 2
        .globl EXT(clean_dcache64)
LEXT(clean_dcache64)
	mov	r1, r2
	mov	r2, r3
	LOAD_ADDR_PC(clean_dcache)

/*
 *      void invalidate_icache(vm_offset_t va, unsigned length, boolean_t phys)
 *      void invalidate_icache64(addr64_t va, unsigned length, boolean_t phys)
 */
        .text
        .align 2
        .globl EXT(invalidate_icache64)
        .globl EXT(invalidate_icache)
LEXT(invalidate_icache64)
	mov	r1, r2
	mov	r2, r3
LEXT(invalidate_icache)
	cmp		r2, #0		// Is it physical?
	COND_EXTERN_BEQ(InvalidatePoU_IcacheRegion)
	LOAD_ADDR(r2, gPhysBase)
	ldr		r2, [r2]
	sub		r0, r0, r2
	LOAD_ADDR(r2, gVirtBase)
	ldr		r2, [r2]
	add		r0, r0, r2
	b		EXT(InvalidatePoU_IcacheRegion)


#include        "globals_asm.h"

LOAD_ADDR_GEN_DEF(flush_dcache)
LOAD_ADDR_GEN_DEF(clean_dcache)

/* vim: set ts=4: */

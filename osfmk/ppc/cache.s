/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */

#include <cpus.h>

#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <cpus.h>
#include <assym.s>
#include <mach_debug.h>
#include <mach/ppc/vm_param.h>

/*
 * extern void sync_cache(vm_offset_t pa, unsigned count);
 *
 * sync_cache takes a physical address and count to sync, thus
 * must not be called for multiple virtual pages.
 *
 * it writes out the data cache and invalidates the instruction
 * cache for the address range in question
 */

ENTRY(sync_cache, TAG_NO_FRAME_USED)

	/* Switch off data translations */
	mfmsr	r6
	rlwinm	r6,r6,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
	rlwinm	r6,r6,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
	rlwinm	r7,	r6,	0,	MSR_DR_BIT+1,	MSR_DR_BIT-1
	mtmsr	r7
	isync

	/* Check to see if the address is aligned. */
	add	r8, r3,r4
	andi.	r8,r8,(CACHE_LINE_SIZE-1)
	beq-	.L_sync_check
	addi	r4,r4,CACHE_LINE_SIZE
	li	r7,(CACHE_LINE_SIZE-1)	/* Align buffer & count - avoid overflow problems */
	andc	r4,r4,r7
	andc	r3,r3,r7

.L_sync_check:
	cmpwi	r4,	CACHE_LINE_SIZE
	ble	.L_sync_one_line
	
	/* Make ctr hold count of how many times we should loop */
	addi	r8,	r4,	(CACHE_LINE_SIZE-1)
	srwi	r8,	r8,	CACHE_LINE_POW2
	mtctr	r8

	/* loop to flush the data cache */
.L_sync_data_loop:
	subic	r4,	r4,	CACHE_LINE_SIZE
	dcbf	r3,	r4
	bdnz	.L_sync_data_loop
	
	sync
	mtctr	r8

	/* loop to invalidate the instruction cache */
.L_sync_inval_loop:
	icbi	r3,	r4
	addic	r4,	r4,	CACHE_LINE_SIZE
	bdnz	.L_sync_inval_loop

.L_sync_cache_done:
	sync			/* Finish physical writes */
	mtmsr	r6		/* Restore original translations */
	isync			/* Ensure data translations are on */
	blr

.L_sync_one_line:
	dcbf	0,r3
	sync
	icbi	0,r3
	b	.L_sync_cache_done

/*
 * extern void flush_dcache(vm_offset_t addr, unsigned count, boolean phys);
 *
 * flush_dcache takes a virtual or physical address and count to flush
 * and (can be called for multiple virtual pages).
 *
 * it flushes the data cache
 * cache for the address range in question
 *
 * if 'phys' is non-zero then physical addresses will be used
 */

ENTRY(flush_dcache, TAG_NO_FRAME_USED)

	/* optionally switch off data translations */

	cmpwi	r5,	0
	mfmsr	r6
	beq+	0f
	rlwinm	r6,r6,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
	rlwinm	r6,r6,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
	rlwinm	r7,	r6,	0,	MSR_DR_BIT+1,	MSR_DR_BIT-1
	mtmsr	r7
	isync
0:	

	/* Check to see if the address is aligned. */
	add	r8, r3,r4
	andi.	r8,r8,(CACHE_LINE_SIZE-1)
	beq-	.L_flush_dcache_check
	addi	r4,r4,CACHE_LINE_SIZE
	li	r7,(CACHE_LINE_SIZE-1)	/* Align buffer & count - avoid overflow problems */
	andc	r4,r4,r7
	andc	r3,r3,r7

.L_flush_dcache_check:
	cmpwi	r4,	CACHE_LINE_SIZE
	ble	.L_flush_dcache_one_line
	
	/* Make ctr hold count of how many times we should loop */
	addi	r8,	r4,	(CACHE_LINE_SIZE-1)
	srwi	r8,	r8,	CACHE_LINE_POW2
	mtctr	r8

.L_flush_dcache_flush_loop:
	subic	r4,	r4,	CACHE_LINE_SIZE
	dcbf	r3,	r4
	bdnz	.L_flush_dcache_flush_loop

.L_flush_dcache_done:
	/* Sync restore msr if it was modified */
	cmpwi	r5,	0
	sync			/* make sure invalidates have completed */
	beq+	0f
	mtmsr	r6		/* Restore original translations */
	isync			/* Ensure data translations are on */
0:
	blr

.L_flush_dcache_one_line:
	xor	r4,r4,r4
	dcbf	0,r3
	b	.L_flush_dcache_done


/*
 * extern void invalidate_dcache(vm_offset_t va, unsigned count, boolean phys);
 *
 * invalidate_dcache takes a virtual or physical address and count to
 * invalidate and (can be called for multiple virtual pages).
 *
 * it invalidates the data cache for the address range in question
 */

ENTRY(invalidate_dcache, TAG_NO_FRAME_USED)

	/* optionally switch off data translations */

	cmpwi	r5,	0
	mfmsr	r6
	beq+	0f
	rlwinm	r6,r6,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
	rlwinm	r6,r6,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
	rlwinm	r7,	r6,	0,	MSR_DR_BIT+1,	MSR_DR_BIT-1
	mtmsr	r7
	isync
0:	

	/* Check to see if the address is aligned. */
	add	r8, r3,r4
	andi.	r8,r8,(CACHE_LINE_SIZE-1)
	beq-	.L_invalidate_dcache_check
	addi	r4,r4,CACHE_LINE_SIZE
	li	r7,(CACHE_LINE_SIZE-1)	/* Align buffer & count - avoid overflow problems */
	andc	r4,r4,r7
	andc	r3,r3,r7

.L_invalidate_dcache_check:
	cmpwi	r4,	CACHE_LINE_SIZE
	ble	.L_invalidate_dcache_one_line
	
	/* Make ctr hold count of how many times we should loop */
	addi	r8,	r4,	(CACHE_LINE_SIZE-1)
	srwi	r8,	r8,	CACHE_LINE_POW2
	mtctr	r8

.L_invalidate_dcache_invalidate_loop:
	subic	r4,	r4,	CACHE_LINE_SIZE
	dcbi	r3,	r4
	bdnz	.L_invalidate_dcache_invalidate_loop

.L_invalidate_dcache_done:
	/* Sync restore msr if it was modified */
	cmpwi	r5,	0
	sync			/* make sure invalidates have completed */
	beq+	0f
	mtmsr	r6		/* Restore original translations */
	isync			/* Ensure data translations are on */
0:
	blr

.L_invalidate_dcache_one_line:
	xor	r4,r4,r4
	dcbi	0,r3
	b	.L_invalidate_dcache_done

/*
 * extern void invalidate_icache(vm_offset_t addr, unsigned cnt, boolean phys);
 *
 * invalidate_icache takes a virtual or physical address and
 * count to invalidate, (can be called for multiple virtual pages).
 *
 * it invalidates the instruction cache for the address range in question.
 */

ENTRY(invalidate_icache, TAG_NO_FRAME_USED)

	/* optionally switch off data translations */
	cmpwi	r5,	0
	mfmsr	r6
	beq+	0f
	rlwinm	r6,r6,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
	rlwinm	r6,r6,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
	rlwinm	r7,	r6,	0,	MSR_DR_BIT+1,	MSR_DR_BIT-1
	mtmsr	r7
	isync
0:	

	/* Check to see if the address is aligned. */
	add	r8, r3,r4
	andi.	r8,r8,(CACHE_LINE_SIZE-1)
	beq-	.L_invalidate_icache_check
	addi	r4,r4,CACHE_LINE_SIZE
	li	r7,(CACHE_LINE_SIZE-1)	/* Align buffer & count - avoid overflow problems */
	andc	r4,r4,r7
	andc	r3,r3,r7

.L_invalidate_icache_check:
	cmpwi	r4,	CACHE_LINE_SIZE
	ble	.L_invalidate_icache_one_line
	
	/* Make ctr hold count of how many times we should loop */
	addi	r8,	r4,	(CACHE_LINE_SIZE-1)
	srwi	r8,	r8,	CACHE_LINE_POW2
	mtctr	r8

.L_invalidate_icache_invalidate_loop:
	subic	r4,	r4,	CACHE_LINE_SIZE
	icbi	r3,	r4
	bdnz	.L_invalidate_icache_invalidate_loop

.L_invalidate_icache_done:
	sync			/* make sure invalidates have completed */
	mtmsr	r6		/* Restore original translations */
	isync			/* Ensure data translations are on */
	blr

.L_invalidate_icache_one_line:
	xor	r4,r4,r4
	icbi	0,r3
	b	.L_invalidate_icache_done

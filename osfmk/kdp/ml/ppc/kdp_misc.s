/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
#include <debug.h>
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <mach/ppc/vm_param.h>
#include <assym.s>

.set kLog2CacheLineSize, 5
.set kCacheLineSize, 32
 
ENTRY(kdp_flush_cache, TAG_NO_FRAME_USED)
	cmpi    cr0,0,r4,0			/* is this zero length? */
	add     r4,r3,r4			/* calculate last byte + 1 */
	subi    r4,r4,1				/* calculate last byte */

	srwi    r5,r3,kLog2CacheLineSize	/* calc first cache line index */
	srwi    r4,r4,kLog2CacheLineSize	/* calc last cache line index */
	beq     cr0, LdataToCodeDone		/* done if zero length */

	subf    r4,r5,r4			/* calc diff (# lines minus 1) */
	addi    r4,r4,1				/* # of cache lines to flush */
	slwi    r5,r5,kLog2CacheLineSize	/* calc addr of first cache line */

	/* flush the data cache lines */
	mr      r3,r5				/* starting address for loop */
	mtctr   r4					/* loop count */
LdataToCodeFlushLoop:
	dcbf    0, r3						/* flush the data cache line */
	addi    r3,r3,kCacheLineSize		/* advance to next cache line */
	bdnz    LdataToCodeFlushLoop		/* loop until count is zero */
	sync								/* wait until RAM is valid */

	/* invalidate the code cache lines */
	mr      r3,r5						/* starting address for loop */
	mtctr   r4							/* loop count */
LdataToCodeInvalidateLoop:
	icbi    0, r3						/* invalidate code cache line */
	addi    r3,r3,kCacheLineSize		/* advance to next cache line */
	bdnz    LdataToCodeInvalidateLoop	/* loop until count is zero */
	sync								/* wait until last icbi completes */
	isync								/* discard prefetched instructions */
LdataToCodeDone:
	blr									/* return nothing */

ENTRY(kdp_sync_cache, TAG_NO_FRAME_USED)
	sync					/* data sync */
	isync					/* inst sync */
	blr						/* return nothing */

ENTRY(kdp_xlate_off, TAG_NO_FRAME_USED)
	mfmsr	r3
	rlwinm	r4, r3, 0, MSR_DR_BIT+1, MSR_IR_BIT-1
	mtmsr	r4
	isync
	blr

ENTRY(kdp_xlate_restore, TAG_NO_FRAME_USED)
	mtmsr	r3
	isync
	blr


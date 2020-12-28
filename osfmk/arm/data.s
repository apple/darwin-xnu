/*
 * Copyright (c) 2007-2009 Apple Inc. All rights reserved.
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
#include <arm/asm.h>
#include <arm/proc_reg.h>
#include "assym.s"

#if defined(__arm__)
#include "globals_asm.h"
#elif defined(__arm64__)
/* We're fine, use adrp, add */
#else
#error Unknown architecture.
#endif

	.section __BOOTDATA, __data					// Aligned data

	.align 14 

	.globl EXT(intstack_low_guard)
LEXT(intstack_low_guard)
	.space (PAGE_MAX_SIZE_NUM)

	/* IRQ stack */
	.globl  EXT(intstack)						// Boot processor IRQ stack
LEXT(intstack)
	.space	(INTSTACK_SIZE_NUM)
	.globl  EXT(intstack_top)
LEXT(intstack_top)

	.globl EXT(intstack_high_guard)
LEXT(intstack_high_guard)
	.space (PAGE_MAX_SIZE_NUM)

/* Low guard for fiq/exception stack is shared w/ interrupt stack high guard */

#ifndef __arm64__

	.globl  EXT(fiqstack)						// Boot processor FIQ stack
LEXT(fiqstack)
	.space	(FIQSTACK_SIZE_NUM)
	.globl  EXT(fiqstack_top)					// Boot processor FIQ stack top
LEXT(fiqstack_top)

	.globl EXT(fiqstack_high_guard)
LEXT(fiqstack_high_guard)
	.space (PAGE_MAX_SIZE_NUM)

#else

	.global EXT(excepstack)
LEXT(excepstack)
	.space	(EXCEPSTACK_SIZE_NUM)
	.globl	EXT(excepstack_top)
LEXT(excepstack_top)

	.globl EXT(excepstack_high_guard)
LEXT(excepstack_high_guard)
	.space (PAGE_MAX_SIZE_NUM)

#endif

// Must align to 16K here, due to <rdar://problem/33268668>
        .global EXT(kd_early_buffer)
        .align 14
LEXT(kd_early_buffer) // space for kdebug's early event buffer
        .space 16*1024,0

	.section __DATA, __data						// Aligned data
	.align	3							// unsigned long long aligned Section
	.globl	EXT(RTClockData)
LEXT(RTClockData)							// Real Time clock area
	.space	RTCLOCKDataSize_NUM,0					// (filled with 0s)

#if TRASH_VFP_ON_SAVE
	.align  4
	.globl  EXT(vfptrash_data)
LEXT(vfptrash_data)
	.fill   64, 4, 0xca55e77e
#endif

#if __arm64__
        .section __DATA, __const

#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)
/* reserve space for read only page tables */
        .align 14
LEXT(ropagetable_begin)
        .space 14*16*1024,0
#else
LEXT(ropagetable_begin)
#endif /* defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR) */

LEXT(ropagetable_end)

        .globl EXT(ropagetable_begin)
        .globl EXT(ropagetable_end)
#endif /* __arm64__ */

/* vim: set ts=4: */

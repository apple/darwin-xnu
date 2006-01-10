/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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

#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <assym.s>

/*
This code is linked into the kernel but part of the "__HIB" section, which means
its used by code running in the special context of restoring the kernel text and data
from the hibernation image read by the booter. hibernate_kernel_entrypoint() and everything
it calls or references (ie. hibernate_restore_phys_page())
needs to be careful to only touch memory also in the "__HIB" section.
*/

/*
void 
hibernate_restore_phys_page(uint64_t src, uint64_t dst, uint32_t len, uint32_t procFlags);
*/

			.align	5
			.globl	EXT(hibernate_restore_phys_page)
			.globl	EXT(hibernate_machine_entrypoint)

LEXT(hibernate_restore_phys_page)

	andi.		r0, r8, pf64Bit
	bne		hibernate_restore_phys_page64

        srwi		r10,r7,5				; r10 <- 32-byte chunks to xfer
        mtctr		r10
	cmpwi		r4, 0
	beq		hibernate_restore_phys_pageFlush

hibernate_restore_phys_pageCopy:
        lwz		r0,0(r4)
        lwz		r2,4(r4)
        lwz		r7,8(r4)
        lwz		r8,12(r4)
        lwz		r9,16(r4)
        lwz		r10,20(r4)
        lwz		r11,24(r4)
        lwz		r12,28(r4)

        dcbz		0,r6					; avoid prefetch of next cache line
        stw		r0,0(r6)
        stw		r2,4(r6)
        stw		r7,8(r6)
        stw		r8,12(r6)
        stw		r9,16(r6)
        stw		r10,20(r6)
        stw		r11,24(r6)
        stw		r12,28(r6)
        
	dcbf 		0, r6
	sync
	icbi 		0, r6
	isync
	sync

        addi		r4,r4,32
        addi		r6,r6,32

        bdnz		hibernate_restore_phys_pageCopy		; loop if more chunks
        blr

hibernate_restore_phys_pageFlush:
	dcbf 		0, r6
	sync
	icbi 		0, r6
	isync
	sync

        addi		r6,r6,32
        bdnz		hibernate_restore_phys_pageFlush		; loop if more chunks
        blr


hibernate_restore_phys_page64:
	rlwinm		r3,r3,0,1,0			; Duplicate high half of long long paddr into top of reg
	rlwimi		r3,r4,0,0,31			; Combine bottom of long long to full 64-bits
	rlwinm		r4,r5,0,1,0			; Duplicate high half of long long paddr into top of reg
	rlwimi		r4,r6,0,0,31			; Combine bottom of long long to full 64-bits

	mfmsr		r9				; Get the MSR
	li		r0,1				; Note - we use this in a couple places below
	rldimi		r9,r0,63,MSR_SF_BIT		; set SF on in MSR we will copy with
	mtmsrd		r9				; turn 64-bit addressing on
	isync						; wait for it to happen

        srwi	r10,r7,7				; r10 <- 128-byte chunks to xfer
        mtctr	r10
	cmpdi	r3, 0
	beq	hibernate_restore_phys_page64Flush

hibernate_restore_phys_page64Copy:
        ld		r0,0(r3)
        ld		r2,8(r3)
        ld		r7,16(r3)
        ld		r8,24(r3)
        ld		r9,32(r3)
        ld		r10,40(r3)
        ld		r11,48(r3)
        ld		r12,56(r3)

        dcbz128		0,r4				; avoid prefetch of next cache line
        std		r0,0(r4)
        std		r2,8(r4)
        std		r7,16(r4)
        std		r8,24(r4)
        std		r9,32(r4)
        std		r10,40(r4)
        std		r11,48(r4)
        std		r12,56(r4)
        
        ld		r0,64(r3)			; load 2nd half of chunk
        ld		r2,72(r3)
        ld		r7,80(r3)
        ld		r8,88(r3)
        ld		r9,96(r3)
        ld		r10,104(r3)
        ld		r11,112(r3)
        ld		r12,120(r3)

        std		r0,64(r4)
        std		r2,72(r4)
        std		r7,80(r4)
        std		r8,88(r4)
        std		r9,96(r4)
        std		r10,104(r4)
        std		r11,112(r4)
        std		r12,120(r4)

	dcbf 		0, r4
	sync
	icbi 		0, r4
	isync
	sync

        addi		r3,r3,128
        addi		r4,r4,128

        bdnz		hibernate_restore_phys_page64Copy		; loop if more chunks


hibernate_restore_phys_page64Done:
	mfmsr		r9				; Get the MSR we used to copy
	rldicl		r9,r9,0,MSR_SF_BIT+1		; clear SF
        mtmsrd  	r9                          	; turn 64-bit mode off
	isync                               		; wait for it to happen
        blr

hibernate_restore_phys_page64Flush:
	dcbf 		0, r4
	sync
	icbi 		0, r4
	isync
	sync

        addi		r4,r4,128

        bdnz		hibernate_restore_phys_page64Flush		; loop if more chunks
	b		hibernate_restore_phys_page64Done

LEXT(hibernate_machine_entrypoint)
        b               EXT(hibernate_kernel_entrypoint)


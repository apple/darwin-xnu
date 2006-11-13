/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
#include <debug.h>
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <mach/ppc/vm_param.h>
#include <assym.s>

ENTRY(kdp_sync_cache, TAG_NO_FRAME_USED)
	sync					/* data sync */
	isync					/* inst sync */
	blr						/* return nothing */


;
;		This is a really stupid physical copy. 1 whole byte at a time...
;		Source and dest are long longs.  We do this with 64-bit on if
;		supported.
;

			.align	5
			.globl	EXT(kdp_copy_phys)
			
LEXT(kdp_copy_phys)

			mflr	r12						; Save return
			
			bl		EXT(ml_set_physical_disabled)	; No DR and get 64-bit
			
			rlwinm	r3,r3,0,1,0				; Dup low to high source
			rlwinm	r5,r5,0,1,0				; Dup low to high dest
			rlwimi	r3,r4,0,0,31			; Copy bottom on in source
			rlwimi	r5,r6,0,0,31			; Copy bottom on in dest
			
kcpagain:	addic.	r7,r7,-1				; Drop count
			blt--	kcpdone					; All done...
			lbz		r0,0(r3)				; Grab a whole one
			stb		r0,0(r5)				; Lay it gently down
			addi	r3,r3,1					; Next source
			addi	r5,r5,1					; Next destination
			b		kcpagain				; Once more with feeling...
		
kcpdone:	bl		EXT(ml_restore)			; Put trans, etc back
			mtlr	r12						; Restore return
			blr								; Come again please...
		

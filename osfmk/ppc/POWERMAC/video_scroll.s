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
 * @OSF_FREE_COPYRIGHT@
 * 
 */

/* Routines to perform high-speed scrolling, assuming that the memory is
 * non-cached, and that the amount of memory to be scrolled is a multiple
 * of (at least) 16.
 */

#include <ppc/asm.h>
#include <ppc/proc_reg.h>

/*
 * void video_scroll_up(unsigned long start,
 *		        unsigned long end,
 *		        unsigned long dest)
 */

ENTRY(video_scroll_up, TAG_NO_FRAME_USED)


			lis		r8,hi16(MASK(MSR_VEC))			; Get the vector flag
			mfmsr	r0								; Get the MSR 
			ori		r8,r8,lo16(MASK(MSR_FP))		; Add the FP flag
			mflr	r6								; Get the LR
			andc	r0,r0,r8						; Clear VEC and FP
			ori		r7,r8,lo16(MASK(MSR_EE))		; Drop EE and DR
			andc	r7,r0,r7						; Clear VEC, FP, and EE
			ori		r7,r7,MASK(MSR_FP)				; Turn floating point back on
			stwu	r1,-(FM_SIZE+16)(r1)			; Get space for a couple of registers on stack
			stw		r6,(FM_SIZE+16+FM_LR_SAVE)(r1)	; Save the return
			
			mtmsr	r7								; Turn on FPU
			isync									; Wait for it 
			
vsufpuon1:	stfd	f0,(FM_SIZE+0)(r1)				; Save one register
			stfd	f1,(FM_SIZE+8)(r1)				; and the second

/* ok, now we can use the FPU registers to do some fast copying
 */

.L_vscr_up_loop:
			lfd	f0,	0(r3)
			lfd	f1,	8(r3)
		
			addi	r3,	r3,	16
			
			stfd	f0,	0(r5)
		
			cmpl	cr0,	r3,	r4
		
			stfd	f1,	8(r5)
		
			addi	r5,	r5,	16
		
			blt+	cr0,	.L_vscr_up_loop

			lfd		f0,(FM_SIZE+0)(r1)					/* Load back one register */
			lfd		f1,(FM_SIZE+8)(r1)					/* and the second */
			lwz		r1,0(r1)							/* Pop the stack */
		
			mtmsr	r0									/* Turn off FPU again */
			isync										/* Wait for it */
			blr											/* Go away, don't bother me... */


/*
 * void video_scroll_down(unsigned long start,   HIGH address to scroll from
 *		          unsigned long end,     LOW address 
 *		          unsigned long dest)    HIGH address
 */

ENTRY(video_scroll_down, TAG_NO_FRAME_USED)

	/* Save off the link register, we want to call fpu_save.
	 */
	

			lis		r8,hi16(MASK(MSR_VEC))			; Get the vector flag
			mfmsr	r0								; Get the MSR 
			ori		r8,r8,lo16(MASK(MSR_FP))		; Add the FP flag
			mflr	r6								; Get the LR
			andc	r0,r0,r8						; Clear VEC and FP
			ori		r7,r8,lo16(MASK(MSR_EE))		; Drop EE and DR
			andc	r7,r0,r7						; Clear VEC, FP, DR, and EE
			ori		r7,r7,MASK(MSR_FP)				; Turn on floating point 
			stwu	r1,-(FM_SIZE+16)(r1)			; Get space for a couple of registers on stack
			stw		r6,(FM_SIZE+16+FM_LR_SAVE)(r1)	; Save the return
			
			mtmsr	r7								; Turn on FPU
			isync									; Wait for it 
			
vsdfpuon1:	stfd	f0,(FM_SIZE+0)(r1)				; Save one register
			stfd	f1,(FM_SIZE+8)(r1)				; and the second


/* ok, now we can use the FPU registers to do some fast copying	 */

.L_vscr_down_loop:
			lfd	f0,	-16(r3)
			lfd	f1,	-8(r3)
		
			subi	r3,	r3,	16
			
			stfd	f0,	-16(r5)
		
			cmpl	cr0,	r3,	r4
		
			stfd	f1,	-8(r5)
		
			subi	r5,	r5,	16
		
			bgt+	cr0,	.L_vscr_down_loop
		

			lfd		f0,(FM_SIZE+0)(r1)					/* Load back one register */
			lfd		f1,(FM_SIZE+8)(r1)					/* and the second */
			lwz		r1,0(r1)							/* Pop the stack */
		
			mtmsr	r0									/* Turn off FPU again */
			isync										/* Wait for it */
			blr											/* Go away, don't bother me... */


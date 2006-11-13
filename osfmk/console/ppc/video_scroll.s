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

			mfmsr	r0									/* Get the MSR */
			mflr	r6									/* Get the LR */
			ori		r7,r0,1<<(31-MSR_FP_BIT)			/* Turn on floating point */
			stwu	r1,-(FM_SIZE+16)(r1)				/* Get space for a couple of registers on stack */
			rlwinm	r7,r7,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Turn off interrupts */
			stw		r6,(FM_SIZE+16+FM_LR_SAVE)(r1)		/* Save the return */
			
			mtmsr	r7									/* Turn on FPU */
			isync										/* Wait for it */
			
vsufpuon1:	stfd	f0,(FM_SIZE+0)(r1)					/* Save one register */
			stfd	f1,(FM_SIZE+8)(r1)					/* and the second */

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
	

			mfmsr	r0									/* Get the MSR */
			mflr	r6									/* Get the LR */
			ori		r7,r0,1<<(31-MSR_FP_BIT)			/* Turn on floating point */
			stwu	r1,-(FM_SIZE+16)(r1)				/* Get space for a couple of registers on stack */
			rlwinm	r7,r7,0,MSR_EE_BIT+1,MSR_EE_BIT-1	/* Turn off interrupts */
			stw		r6,(FM_SIZE+16+FM_LR_SAVE)(r1)		/* Save the return */
			
			mtmsr	r7									/* Turn on FPU */
			isync										/* Wait for it */
			
vsdfpuon1:	stfd	f0,(FM_SIZE+0)(r1)					/* Save one register */
			stfd	f1,(FM_SIZE+8)(r1)					/* and the second */

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


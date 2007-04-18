/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT_INTERNAL_USE_ONLY@
 */

/* 																							
 	Performance.s 

	Handle things that should are related to the hardware performance monitor

	Lovingly crafted by Bill Angell using traditional methods and only natural or recycled materials.
	No more than 7500 chinchillas were killed in the production of the code.

*/

#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <ppc/exception.h>
#include <ppc/Performance.h>
#include <mach/machine/vm_param.h>
#include <assym.s>

#if PERF_HIST
/*
 *			This routine is used to interface to the performance monitor
 */

ENTRY(PerfCtl, TAG_NO_FRAME_USED)

			lis		r0,PerfCtlCall@h				/* Get the top part of the SC number */
			ori		r0,r0,PerfCtlCall@l				/* and the bottom part */
			sc										/* Do it to it */
			blr										/* Bye bye, Birdie... */
			

ENTRY(PerfCtlLL, TAG_NO_FRAME_USED)

			cmplwi	r3,maxPerf						/* See if we are within range */
			mflr	r11								/* Get the return point */
			li		r3,0							/* Show failure */
			bgelrl-									/* Load up current address and, also, leave if out of range */
prfBase:	mflr	r12								/* Get our address */
			rlwinm	r10,r3,2,0,31					/* Get displacement into branch table */
			addi	r12,r12,prfBrnch-prfBase		/* Point to the branch address */
			add		r12,r12,r10						/* Point to the branch */
			mtlr	r12								/* Get it in the link register */
			blr										/* Vector to the specific performance command... */
			
prfBrnch:	b		prfClear						/* Clear the histogram table */
			b		prfStart						/* Start the performance monitor */
			b		prfStop							/* Stop the performance monitor */
			b		prfMap							/* Map the histogram into an address space */
			.equ	maxPerf, (.-prfBrnch)/4			/* Set the highest valid address */
			
/*
 *			Clear the monitor histogram
 */
prfClear:
 			li		r4,PMIhist@l					/* We know this to be in page 0, so no need for the high part */
			lis		r8,PMIHIST_SIZE@h				/* Get high half of the table size */
			lwz		r4,0(r4)						/* Get the real address of the histgram */
			ori		r8,r8,PMIHIST_SIZE@l			/* Get the low half of the table size */
			li		r6,32							/* Get a displacement */
			li		r3,1							/* Set up a good return code */
			mtlr	r11								/* Restore the return address */
						
clrloop:	subi	r8,r8,32						/* Back off a cache line */
			dcbz	0,r4							/* Do the even line */
			sub.	r8,r8,r6						/* Back off a second time (we only do this to generate a CR */
			dcbz	r6,r4							/* Clear the even line */
			addi	r4,r4,64						/* Move up to every other line */
			bgt+	clrloop							/* Go until we've done it all... */

			blr										/* Leave... */
			
/*
 *			Start the monitor histogram
 */
 prfStart:
 			mtlr	r11								/* Restore the return address */
			blr										/* Return... */
			
/*
 *			Stop the monitor histogram
 */
 prfStop:
 			mtlr	r11								/* Restore the return address */
			blr										/* Return... */
			
/*
 *			Maps the monitor histogram into another address space
 */
 prfMap:
 			mtlr	r11								/* Restore the return address */
			blr										/* Return... */

#endif


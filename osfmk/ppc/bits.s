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
 * @OSF_COPYRIGHT@
 * 
 */

#include <ppc/asm.h>
#include <ppc/proc_reg.h>

#	
# void setbit(int bitno, int *s)
# 
# Set indicated bit in bit string.
#     Note:	being big-endian, bit 0 is 0x80000000.
	
ENTRY(setbit,TAG_NO_FRAME_USED)

	rlwinm		r8,r3,29,3,31		/* Get byte displacement */
	rlwinm		r9,r3,0,29,31		/* Get bit within byte */
	li			r6,0x80				/* Start with bit 0 */
	lbzx		r5,r4,r8			/* Grab target byte */
	srw			r6,r6,r9			/* Get the right bit (fits right into the load cycle) */
	or			r5,r5,r6			/* Turn on the right bit */
	stbx		r5,r4,r8			/* Save the byte back */
	blr	
	
#	
# void clrbit(int bitno, int *s)
# 
# Clear indicated bit in bit string.
#     Note:	being big-endian, bit 0 is 0x80000000.
	
ENTRY(clrbit,TAG_NO_FRAME_USED)

	rlwinm		r8,r3,29,3,31		/* Get byte displacement */
	rlwinm		r9,r3,0,29,31		/* Get bit within byte */
	li			r6,0x80				/* Start with bit 0 */
	lbzx		r5,r4,r8			/* Grab target byte */
	srw			r6,r6,r9			/* Get the right bit (fits right into the load cycle) */
	andc		r5,r5,r6			/* Turn off the right bit */
	stbx		r5,r4,r8			/* Save the byte back */
	blr	


# /*
#  * Find first bit set in bit string.
#  */
# int
# ffsbit(int *s)
#
# Returns the bit index of the first bit set (starting from 0)
# Assumes pointer is word-aligned

ENTRY(ffsbit, TAG_NO_FRAME_USED)
	lwz	r0,	0(ARG0)
		mr	ARG1,	ARG0	/* Free up ARG0 for result */

	cmpwi	r0,	0		/* Check against zero... */
		cntlzw	ARG0,	r0	/* Free inst... find the set bit... */
	bnelr+				/* Return if bit in first word */

.L_ffsbit_lp:
	lwz	r0,	4(ARG1)
	addi	ARG1,	ARG1,	4
	cmpwi	r0,	0		/* Check against zero... */
		cntlzw	r12,	r0
		add	ARG0,	ARG0,	r12	/* ARG0 keeps bit count */
	beq+	.L_ffsbit_lp
	blr
	
/*
 * int tstbit(int bitno, int *s)
 *
 * Test indicated bit in bit string.
 *	Note:	 being big-endian, bit 0 is 0x80000000.
 */

ENTRY2(tstbit, testbit, TAG_NO_FRAME_USED)

	rlwinm		r8,r3,29,3,31		/* Get byte displacement */
	rlwinm		r9,r3,0,29,31		/* Get bit within byte */
	lbzx		r5,r4,r8			/* Grab target byte */
	addi		r9,r9,25			/* Get actual shift value */
	rlwnm		r3,r5,r9,31,31		/* Pass the bit back */
	blr	

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
 */

#include <ppc/asm.h>
#include <ppc/proc_reg.h>	/* For CACHE_LINE_SIZE */

/*
 *	 void	bzero(char *addr, unsigned int length)
 *
 * bzero implementation for PowerPC
 *   - assumes cacheable memory (i.e. uses DCBZ)
 *   - assumes non-pic code
 *
 * returns start address in r3, as per memset (called by memset)
 */	
	
ENTRY(bzero, TAG_NO_FRAME_USED)

	cmpwi	cr0,	r4,	0 /* no bytes to zero? */
	mr	r7,	r3
	mr	r8,	r3	/* use r8 as counter to where we are */
	beqlr-
	cmpwi	cr0,	r4,	CACHE_LINE_SIZE /* clear less than a block? */
	li	r0,	0	 /* use r0 as source of zeros */
	blt	.L_bzeroEndWord

/* first, clear bytes up to the next word boundary */
	addis	r6,	0,	HIGH_CADDR(.L_bzeroBeginWord)
	addi	r6,	r6,	LOW_ADDR(.L_bzeroBeginWord)
		 /* extract byte offset as word offset */
	rlwinm. r5,	r8,	2,	28,	29
	addi	r8,	r8,	-1 /* adjust for update */
	beq	.L_bzeroBeginWord /* no bytes to zero */
	subfic	r5,	r5,	16 /* compute the number of instructions */
	sub	r6,	r6,	r5 /* back from word clear to execute */
	mtctr	r6
	bctr

	stbu	r0,	1(r8)
	stbu	r0,	1(r8)
	stbu	r0,	1(r8)

/* clear words up to the next block boundary */
.L_bzeroBeginWord:
	addis	r6,	0,	HIGH_CADDR(.L_bzeroBlock)
	addi	r6,	r6,	LOW_ADDR(.L_bzeroBlock)
	addi	r8,	r8,	1
	rlwinm. r5,	r8,	0,	27,	29 /* extract word offset */
	addi	r8,	r8,	-4		/* adjust for update */
	beq	.L_bzeroBlock			/* no words to zero */
		/* compute the number of instructions */
	subfic	r5,	r5,	CACHE_LINE_SIZE
	sub	r6,	r6,	r5 /* back from word clear to execute */
	mtctr	r6
	bctr

	stwu	r0,	4(r8)
	stwu	r0,	4(r8)
	stwu	r0,	4(r8)
	stwu	r0,	4(r8)
	stwu	r0,	4(r8)
	stwu	r0,	4(r8)
	stwu	r0,	4(r8)

 /* clear cache blocks */
.L_bzeroBlock:
	addi	r8,	r8,	4 /* remove update adjust */
	sub	r5,	r8,	r7 /* bytes zeroed */
	sub	r4,	r4,	r5
	srwi.	r5,	r4,	CACHE_LINE_POW2 /* blocks to zero */
	beq	.L_bzeroEndWord
	mtctr	r5

.L_bzeroBlock1:
	dcbz	0,	r8
	addi	r8,	r8,	CACHE_LINE_SIZE
	bdnz	.L_bzeroBlock1

 /* clear remaining words */
.L_bzeroEndWord:
	addis	r6,	0,	HIGH_CADDR(.L_bzeroEndByte)
	addi	r6,	r6,	LOW_ADDR(.L_bzeroEndByte)
	rlwinm. r5,	r4,	0,	27,	29 /* extract word offset */
	addi	r8,	r8,	-4		   /* adjust for update */
	beq	.L_bzeroEndByte			   /* no words to zero */
	sub	r6,	r6,	r5 /* back from word clear to execute */
	mtctr	r6
	bctr

	stwu	r0,	4(r8)
	stwu	r0,	4(r8)
	stwu	r0,	4(r8)
	stwu	r0,	4(r8)
	stwu	r0,	4(r8)
	stwu	r0,	4(r8)
	stwu	r0,	4(r8)

 /* clear remaining bytes */
.L_bzeroEndByte:
	addis	r6,	0,	HIGH_CADDR(.L_bzeroEnd)
	addi	r6,	r6,	LOW_ADDR(.L_bzeroEnd)
		/* extract byte offset as word offset */
	rlwinm. r5,	r4,	2,	28,	29
	addi	r8,	r8,	3 /* adjust for update */
	beqlr
	sub	r6,	r6,	r5 /* back from word clear to execute */
	mtctr	r6
	bctr

	stbu	r0,	1(r8)
	stbu	r0,	1(r8)
	stbu	r0,	1(r8)

.L_bzeroEnd:
	blr

/*
 * void *memset(void *from, int c, vm_size_t nbytes)
 *
 * almost everywhere in the kernel 
 * this appears to be called with argument c==0. We optimise for those 
 * cases and call bzero if we can.
 *
 */

ENTRY(memset, TAG_NO_FRAME_USED)

	mr.	ARG3,	ARG1
	mr	ARG1,	ARG2
	/* optimised case - do a bzero */
	beq+	EXT(bzero)

	/* If count is zero, return straight away */
	cmpi	cr0,	ARG1,	0
	beqlr-	
	
	/* Now, ARG0 = addr, ARG1=len, ARG3=value */

	subi	ARG2,	ARG0,	1	/* use ARG2 as our counter */
	
0:
	subi	ARG1,	ARG1,	1
	cmpi	cr0,	ARG1,	0
	stbu	ARG3,	1(ARG2)
	bne+	0b

	/* Return original address in ARG0 */
	
	blr

/*
 *	 void	bzero_nc(char *addr, unsigned int length)
 *
 * bzero implementation for PowerPC
 *   - assumes non-pic code
 *
 * returns start address in r3, as per memset (called by memset)
 */	
	
ENTRY(bzero_nc, TAG_NO_FRAME_USED)

	cmpwi	cr0,	r4,	0 /* no bytes to zero? */
	mr	r7,	r3
	mr	r8,	r3	/* use r8 as counter to where we are */
	beqlr-
	cmpwi	cr0,	r4,	CACHE_LINE_SIZE /* clear less than a block? */
	li	r0,	0	 /* use r0 as source of zeros */
	blt	.L_bzeroNCEndWord

/* first, clear bytes up to the next word boundary */
	addis	r6,	0,	HIGH_CADDR(.L_bzeroNCBeginWord)
	addi	r6,	r6,	LOW_ADDR(.L_bzeroNCBeginWord)
		 /* extract byte offset as word offset */
	rlwinm. r5,	r8,	2,	28,	29
	addi	r8,	r8,	-1 /* adjust for update */
	beq	.L_bzeroNCBeginWord /* no bytes to zero */
	subfic	r5,	r5,	16 /* compute the number of instructions */
	sub	r6,	r6,	r5 /* back from word clear to execute */
	mtctr	r6
	bctr

	stbu	r0,	1(r8)
	stbu	r0,	1(r8)
	stbu	r0,	1(r8)

/* clear words up to the next block boundary */
.L_bzeroNCBeginWord:
	addis	r6,	0,	HIGH_CADDR(.L_bzeroNCBlock)
	addi	r6,	r6,	LOW_ADDR(.L_bzeroNCBlock)
	addi	r8,	r8,	1
	rlwinm. r5,	r8,	0,	27,	29 /* extract word offset */
	addi	r8,	r8,	-4		/* adjust for update */
	beq	.L_bzeroNCBlock			/* no words to zero */
		/* compute the number of instructions */
	subfic	r5,	r5,	CACHE_LINE_SIZE
	sub	r6,	r6,	r5 /* back from word clear to execute */
	mtctr	r6
	bctr

	stwu	r0,	4(r8)
	stwu	r0,	4(r8)
	stwu	r0,	4(r8)
	stwu	r0,	4(r8)
	stwu	r0,	4(r8)
	stwu	r0,	4(r8)
	stwu	r0,	4(r8)

 /* clear cache blocks */
.L_bzeroNCBlock:
	addi	r8,	r8,	4 /* remove update adjust */
	sub	r5,	r8,	r7 /* bytes zeroed */
	sub	r4,	r4,	r5
	srwi.	r5,	r4,	CACHE_LINE_POW2 /* blocks to zero */
	beq	.L_bzeroNCEndWord
	mtctr	r5

.L_bzeroNCBlock1:
	stw	r0,	0(r8)
	stw	r0,	4(r8)
	stw	r0,	8(r8)
	stw	r0,	12(r8)
	stw	r0,	16(r8)
	stw	r0,	20(r8)
	stw	r0,	24(r8)
	stw	r0,	28(r8)
	addi	r8,	r8,	CACHE_LINE_SIZE
	bdnz	.L_bzeroNCBlock1

 /* clear remaining words */
.L_bzeroNCEndWord:
	addis	r6,	0,	HIGH_CADDR(.L_bzeroNCEndByte)
	addi	r6,	r6,	LOW_ADDR(.L_bzeroNCEndByte)
	rlwinm. r5,	r4,	0,	27,	29 /* extract word offset */
	addi	r8,	r8,	-4		   /* adjust for update */
	beq	.L_bzeroNCEndByte			   /* no words to zero */
	sub	r6,	r6,	r5 /* back from word clear to execute */
	mtctr	r6
	bctr

	stwu	r0,	4(r8)
	stwu	r0,	4(r8)
	stwu	r0,	4(r8)
	stwu	r0,	4(r8)
	stwu	r0,	4(r8)
	stwu	r0,	4(r8)
	stwu	r0,	4(r8)

 /* clear remaining bytes */
.L_bzeroNCEndByte:
	addis	r6,	0,	HIGH_CADDR(.L_bzeroNCEnd)
	addi	r6,	r6,	LOW_ADDR(.L_bzeroNCEnd)
		/* extract byte offset as word offset */
	rlwinm. r5,	r4,	2,	28,	29
	addi	r8,	r8,	3 /* adjust for update */
	beqlr
	sub	r6,	r6,	r5 /* back from word clear to execute */
	mtctr	r6
	bctr

	stbu	r0,	1(r8)
	stbu	r0,	1(r8)
	stbu	r0,	1(r8)

.L_bzeroNCEnd:
	blr

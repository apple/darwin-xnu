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
/*
 * @OSF_COPYRIGHT@
 */

#include <debug.h>
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <mach/ppc/vm_param.h>
#include <assym.s>

/* void
 * db_phys_copy(src, dst, bytecount)
 *      vm_offset_t     src;
 *      vm_offset_t     dst;
 *      int             bytecount
 *
 * This routine will copy bytecount bytes from physical address src to physical
 * address dst. 
 */
ENTRY(db_phys_copy, TAG_NO_FRAME_USED)

	/* Switch off data translations */
	mfmsr	r6
	rlwinm	r7,	r6,	0,	MSR_DR_BIT+1,	MSR_DR_BIT-1
	mtmsr	r7
	isync			/* Ensure data translations are off */

	subi	r3,	r3,	4
	subi	r4,	r4,	4

	cmpwi	r5,	3
	ble-	.L_db_phys_copy_bytes
.L_db_phys_copy_loop:
	lwz	r0,	4(r3)
	addi	r3,	r3,	4
	subi	r5,	r5,	4
	stw	r0,	4(r4)
	addi	r4,	r4,	4
	cmpwi	r5,	3
	bgt+	.L_db_phys_copy_loop

	/* If no leftover bytes, we're done now */
	cmpwi	r5,	0
	beq+	.L_db_phys_copy_done
	
.L_db_phys_copy_bytes:
	addi	r3,	r3,	3
	addi	r4,	r4,	3
.L_db_phys_copy_byte_loop:	
	lbz	r0,	1(r3)
	addi	r3,	r3,	1
	subi	r5,	r5,	1
	stb	r0,	1(r4)
	addi	r4,	r4,	1
	cmpwi	r5,	0
	bne+	.L_db_phys_copy_loop

.L_db_phys_copy_done:
	mtmsr	r6		/* Restore original translations */
	isync			/* Ensure data translations are off */

	blr

/* void
 * db_phys_cmp(src_a, src_b, bytecount)
 *      vm_offset_t     src_a;
 *      vm_offset_t     src_b;
 *      int             bytecount
 *
 * This routine will compare bytecount bytes from physical address src_a and physical
 * address src_b. 
 */

	/* Switch off data translations */
	mfmsr	r6
	rlwinm	r7,	r6,	0,	MSR_DR_BIT+1,	MSR_DR_BIT-1
	mtmsr	r7
	isync			/* Ensure data translations are off */

	subi	r3,	r3,	4
	subi	r4,	r4,	4

	cmpwi	r5,	3
	ble-	.L_db_phys_cmp_bytes
.L_db_phys_cmp_loop:
	lwz	r0,	4(r3)
	lwz	r7,	4(r4)
	addi	r3,	r3,	4
	addi	r4,	r4,	4
	subi	r5,	r5,	4
	cmpw	r0,	r7
	bne	.L_db_phys_cmp_false
	cmpwi	r5,	3
	bgt+	.L_db_phys_cmp_loop

	/* If no leftover bytes, we're done now */
	cmpwi	r5,	0
	beq+	.L_db_phys_cmp_true
	
.L_db_phys_cmp_bytes:
	addi	r3,	r3,	3
	addi	r4,	r4,	3
.L_db_phys_cmp_byte_loop:	
	lbz	r0,	1(r3)
	lbz	r7,	1(r4)
	addi	r3,	r3,	1
	addi	r4,	r4,	1
	subi	r5,	r5,	1
	cmpw	r0,	r7
	bne	.L_db_phys_cmp_false
	cmpwi	r5,	0
	bne+	.L_db_phys_cmp_loop

.L_db_phys_cmp_true:
	li	r3,	1
	b	.L_db_phys_cmp_done

.L_db_phys_cmp_false:
	li	r3,	0

.L_db_phys_cmp_done:
	mtmsr	r6		/* Restore original translations */
	isync			/* Ensure data translations are off */

	blr


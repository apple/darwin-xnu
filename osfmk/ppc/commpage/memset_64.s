/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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

#define	ASSEMBLER
#include <sys/appleapiopts.h>
#include <ppc/asm.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>

/*
 * WARNING: this code is written for 32-bit mode, and ported by the kernel if necessary
 * to 64-bit mode for use in the 64-bit commpage.  This "port" consists of the following
 * simple transformations:
 *      - all word compares are changed to doubleword
 *      - all "srwi[.]" opcodes are changed to "srdi[.]"                      
 * Nothing else is done.  For this to work, the following rules must be
 * carefully followed:
 *      - do not use carry or overflow
 *      - only use record mode if you are sure the results are mode-invariant
 *        for example, all "andi." and almost all "rlwinm." are fine
 *      - do not use "slwi", "slw", or "srw"
 * An imaginative programmer could break the porting model in other ways, but the above
 * are the most likely problem areas.  It is perhaps surprising how well in practice
 * this simple method works.
 */        

        .text
        .align	2


/* *********************
 * * M E M S E T _ 6 4 *
 * *********************
 *
 * This is a subroutine called by Libc memset and _memset_pattern for large nonzero
 * operands (zero operands are funneled into bzero.)  This version is for a
 * hypothetic processor that is 64-bit but not Altivec.
 * It is not optimized, since it would only be used during bringup.
 *
 * Registers at entry:
 *		r4 = count of bytes to store (must be >= 32)
 *      r8 = ptr to the 1st byte to store (16-byte aligned)
 *      r9 = ptr to 16-byte pattern to store (16-byte aligned)
 * When we return:
 *		r3 = not changed, since memset returns it
 *      r4 = bytes remaining to store (will be <32)
 *      r7 = not changed
 *      r8 = ptr to next byte to store (still 16-byte aligned)
 *     r12 = not changed (holds return value for memset)
 */

memset_64:
        srwi    r0,r4,5                 // get number of 32-byte chunks (>0)
        ld      r10,0(r9)               // load pattern
        ld      r11,8(r9)
        rlwinm  r4,r4,0,0x1F            // mask down count
        mtctr   r0                      // set up loop count
        
        // Loop over 32-byte chunks.
1:
        std     r10,0(r8)
        std     r11,8(r8)
        std     r10,16(r8)
        std     r11,24(r8)
        addi    r8,r8,32
        bdnz++  1b

        blr


	COMMPAGE_DESCRIPTOR(memset_64,_COMM_PAGE_MEMSET_PATTERN,k64Bit,kHasAltivec, \
				kCommPageBoth+kPort32to64)

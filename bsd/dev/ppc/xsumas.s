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
#define STANDALONE 0

#if STANDALONE
#include "asm.h"
#include "assym.h"
#include "proc_reg.h"	/* For CACHE_LINE_SIZE */
    
#else
    
#include <mach/ppc/asm.h>
#if 0
/* #include <assym.h> */
#include <ppc/proc_reg.h>	/* For CACHE_LINE_SIZE */
#endif 0
#endif

/*
 * Reg 3 - Pointer to data
 * Reg 4 - Length of data
 * Reg 5 - Accumulated sum value
 * Reg 6 - Starting on odd boundary flag (relative to byte 0 of the checksumed data)
 */    
        
ENTRY(xsum_assym, TAG_NO_FRAME_USED)

    mr	    r11, r6		; Swapped flag
    addi    r8, 0, 0
    addi    r10, 0, 0x1f
    addi    r7, 0, 1
    addic   r7, r7, 0		; This clears the carry bit!
    mr	    r12, r5		; Save the passed-in checksum value
    
    /*
    * Sum bytes before cache line boundary
    */

    cmpi    cr0,0,r4,0		; Check for length of 0
    beq	    Lleftovers
    
    and.    r9, r3, r10
    beq	    Laligned32		; 32 byte aligned

    andi.   r9, r3, 0x3
    beq	    Laligned4
    
    andi.   r9, r3, 0x1
    beq	    Laligned2		; 2 byte aligned

    addi    r11, 0, 1		; swap bytes at end
    lbz	    r8, 0(r3)
    add     r3, r3, r7
    subf.   r4, r7, r4
    beq	    Ldone

Laligned2:
    cmpi    cr0,0,r4,2		; If remaining length is less than two - go to wrap-up
    blt	    Lleftovers
    andi.   r9, r3, 0x3		; If aligned on a 4-byte boundary, go to that code
    beq	    Laligned4
    lhz	    r5, 0(r3)		; Load and add a halfword to the checksum
    adde    r8, r8, r5
    slwi    r7, r7, 1
    add     r3, r3, r7
    subf.   r4, r7, r4
    beq	    Ldone


    /*
     Add longwords up to the 32 byte boundary
    */
    
Laligned4:
    addi    r7, 0, 4	
Lloop4:	
    cmpi    cr0,0,r4,4
    blt	    Lleftovers
    and.    r9, r3, r10
    beq	    Laligned32
    lwz	    r5, 0(r3)
    adde    r8, r8, r5
    add     r3, r3, r7
    subf.   r4, r7, r4
    bne	    Lloop4
    b	    Ldone


    /*
    We're aligned on a 32 byte boundary now - add 8 longwords to checksum
    until the remaining length is less than 32
    */
Laligned32:
    andis.  r6, r4, 0xffff
    bne	    Lmainloop
    andi.   r6, r4, 0xffe0
    beq	    Lleftovers  

Lmainloop:	        
    addi    r9, 0, 64
    addi    r10, 0, 32
    cmpi    cr0,0,r4,64
    blt	    Lnopretouch
    dcbt    r3, r10		; Touch one cache-line ahead 
Lnopretouch:	
    lwz	    r5, 0(r3)

    /*
    * This is the main meat of the checksum. I attempted to arrange this code
    * such that the processor would execute as many instructions as possible
    * in parallel.
    */

Lloop:
    cmpi    cr0,0,r4,96
    blt	    Lnotouch    
    dcbt    r3, r9		; Touch two cache lines ahead 
Lnotouch:   
    adde    r8, r8, r5
    lwz     r5, 4(r3)
    lwz	    r6, 8(r3)
    lwz	    r7,	12(r3)
    adde    r8, r8, r5
    lwz     r5, 16(r3)
    adde    r8, r8, r6
    lwz	    r6, 20(r3)
    adde    r8, r8, r7
    lwz	    r7, 24(r3)
    adde    r8, r8, r5
    lwz	    r5, 28(r3)
    add     r3, r3, r10
    adde    r8, r8, r6
    adde    r8, r8, r7
    adde    r8, r8, r5
    subf    r4, r10, r4
    andi.   r6, r4, 0xffe0
    beq	    Lleftovers
    lwz	    r5, 0(r3)
    b	    Lloop

    /*
    * Handle whatever bytes are left
    */
    
Lleftovers: 
    /*
    * Handle leftover bytes
    */
    cmpi    cr0,0,r4,0
    beq	    Ldone
    
    addi    r7, 0, 1
    addi    r10, 0, 0x7ffc

    and.    r9, r4, r10
    bne	    Lfourormore
    srw	    r10, r10, r7
    and.    r9, r4, r10
    bne     Ltwoormore
    b	    Loneleft

Lfourormore:
    addi    r10, 0, 4
    
Lfourloop:  
    lwz	    r5, 0(r3)
    adde    r8, r8, r5
    add     r3, r3, r10
    subf    r4, r10, r4   
    andi.   r6, r4, 0xfffc
    bne	    Lfourloop

Ltwoormore: 
    andi.   r6, r4, 0xfffe
    beq	    Loneleft
    lhz	    r5, 0(r3)
    adde    r8, r8, r5
    addi    r3, r3, 2
    subi    r4, r4, 2

Loneleft:   
    cmpi    cr0,0,r4,0
    beq	    Ldone
    lbz	    r5, 0(r3)
    slwi    r5, r5, 8
    adde    r8, r8, r5

    /*
    * Wrap the longword around, adding the two 16-bit portions
    * to each other along with any previous and subsequent carries.
    */
Ldone:
    addze   r8, r8		; Add the carry 
    addze   r8, r8		; Add the carry again (the last add may have carried) 
    andis.  r6, r8, 0xffff	; Stuff r6 with the high order 16 bits of  sum word
    srwi    r6, r6, 16		; Shift it to the low order word
    andi.   r8, r8, 0xffff	; Zero out the high order word
    add     r8, r8, r6		; Add the two halves

    andis.  r6, r8, 0xffff	; Do the above again in case we carried into the
    srwi    r6, r6, 16		; high order word with the last add.
    andi.   r8, r8, 0xffff
    add     r3, r8, r6

    cmpi    cr0,0,r11,0		; Check to see if we need to swap the bytes
    beq	    Ldontswap

    /*
    * Our buffer began on an odd boundary, so we need to swap
    * the checksum bytes.
    */
    slwi    r8,	r3, 8		; shift byte 0 to byte 1
    clrlwi  r8, r8, 16		; Clear top 16 bits
    srwi    r3, r3, 8		; shift byte 1 to byte 0
    or	    r3, r8, r3		; or them

Ldontswap:
    add     r3, r3, r12		; Add in the passed-in checksum
    andis.  r6, r3, 0xffff	; Wrap and add any carries into the top 16 bits
    srwi    r6, r6, 16
    andi.   r3, r3, 0xffff
    add     r3, r3, r6

    andis.  r6, r3, 0xffff	; Do the above again in case we carried into the
    srwi    r6, r6, 16		; high order word with the last add.
    andi.   r3, r3, 0xffff
    add     r3, r3, r6
    blr

    

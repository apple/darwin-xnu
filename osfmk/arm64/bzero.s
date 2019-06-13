/*
 * Copyright (c) 2012 Apple Computer, Inc. All rights reserved.
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
 *
 * This file implements the following functions for the arm64 architecture:
 *
 *  void bzero(void *buffer, size_t length);
 *  void __bzero(void *buffer, size_t length);
 *  void *memset(void *buffer, int value, size_t length);
 *
 * The first two zero-fill a buffer.  The third fills the buffer with the low
 * byte of its second argument.
 */

#include "asm.h"

.globl _bzero
.globl ___bzero
.globl _memset
.globl _secure_memset

/*****************************************************************************
 *  bzero entrypoint                                                         *
 *****************************************************************************/

.text
.align 4
_bzero:
___bzero:
    ARM64_STACK_PROLOG
    PUSH_FRAME
    mov     x2,      x1
    eor     x1,      x1, x1
    mov     x3,      x0
    cmp     x2,      #128
    b.cc    L_memsetSmall

/*****************************************************************************
 *  Large buffer zero engine                                                 *
 *****************************************************************************/

L_bzeroLarge:
//  Write the first 64 bytes of the buffer without regard to alignment, then
//  advance x3 to point to a cacheline-aligned location within the buffer, and
//  decrement the length accordingly.
    stp     x1, x1, [x0]
    stp     x1, x1, [x0, #16]
    stp     x1, x1, [x0, #32]
    stp     x1, x1, [x0, #48]
    add     x3,      x0, #64
    and     x3,      x3, #-64
    add     x2,      x2, x0   // end of buffer
    add     x4,      x3, #64  // end of first cacheline to zero
    subs    x2,      x2, x4   // if the end of the buffer comes first, jump
    b.ls    1f                //    directly to the cleanup pass.
0:  dc      zva,     x3       // zero cacheline
    add     x3,      x3, #64  // increment pointer
    subs    x2,      x2, #64  // decrement length
    b.hi    0b
1:  add     x3,      x3, x2   // back up pointer to (end of buffer) - 64.
    stp     x1, x1, [x3]      // and store 64 bytes to reach end of buffer.
    stp     x1, x1, [x3, #16]
    stp     x1, x1, [x3, #32]
    stp     x1, x1, [x3, #48]
    POP_FRAME
    ARM64_STACK_EPILOG

/*****************************************************************************
 *  memset entrypoint                                                        *
 *****************************************************************************/

.align 4
/*
 * It is important that secure_memset remains defined in assembly to avoid
 * compiler optimizations.
 */
_secure_memset:
_memset:
    ARM64_STACK_PROLOG
    PUSH_FRAME
    and     x1,      x1, #0xff
    orr     x3,      xzr,#0x0101010101010101
    mul     x1,      x1, x3
    mov     x3,      x0
    cmp     x2,      #64
    b.cc    L_memsetSmall

/*****************************************************************************
 *  Large buffer store engine                                                *
 *****************************************************************************/

L_memsetLarge:
//  Write the first 64 bytes of the buffer without regard to alignment, then
//  advance x3 to point to an aligned location within the buffer, and
//  decrement the length accordingly.
    stp     x1, x1, [x0]
    add     x3,      x0, #16
    and     x3,      x3, #-16
    add     x2,      x2, x0   // end of buffer
    add     x4,      x3, #64  // end of first aligned 64-byte store
    subs    x2,      x2, x4   // if the end of the buffer comes first, jump
    b.ls    1f                //    directly to the cleanup store.
0:  stnp    x1, x1, [x3]
    stnp    x1, x1, [x3, #16]
    stnp    x1, x1, [x3, #32]
    stnp    x1, x1, [x3, #48]
    add     x3,      x3, #64
    subs    x2,      x2, #64
    b.hi    0b
1:  add     x3,      x3, x2   // back up pointer to (end of buffer) - 64.
    stp     x1, x1, [x3]
    stp     x1, x1, [x3, #16]
    stp     x1, x1, [x3, #32]
    stp     x1, x1, [x3, #48]
    POP_FRAME
    ARM64_STACK_EPILOG

/*****************************************************************************
 *  Small buffer store engine                                                *
 *****************************************************************************/

0:  str     x1,     [x3],#8
L_memsetSmall:
    subs    x2,      x2, #8
    b.cs    0b
    adds    x2,      x2, #8
    b.eq    2f
1:  strb    w1,     [x3],#1
    subs    x2,      x2, #1
    b.ne    1b
2:  POP_FRAME
    ARM64_STACK_EPILOG


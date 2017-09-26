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
 *  This file implements the following functions for the arm64 architecture.
 *
 *  void bcopy(const void * source,
 *             void * destination,
 *             size_t length);
 *
 *  void *memmove(void * destination,
 *                const void * source,
 *                size_t n);
 *
 *  void *memcpy(void * restrict destination,
 *               const void * restrict source,
 *               size_t n);
 *
 * All copy n successive bytes from source to destination.  Memmove and memcpy
 * return destination, whereas bcopy has no return value.  Copying takes place
 * as if it were through a temporary buffer -- after return destination
 * contains exactly the bytes from source, even if the buffers overlap (this is
 * not required of memcpy by the C standard; its behavior is undefined if the
 * buffers overlap, but we are holding ourselves to the historical behavior of
 * this function on MacOS).
 */

#include "asm.h"

.globl _bcopy
.globl _ovbcopy
.globl _memcpy
.globl _memmove

/*****************************************************************************
 *  Macros                                                                   *
 *****************************************************************************/

#define kSmallCopy 64

/*****************************************************************************
 *  Entrypoints                                                              *
 *****************************************************************************/

.text
.align 5
_bcopy:
_ovbcopy:
//  Translate bcopy into memcpy by swapping the first and second arguments.
	mov     x3,      x0
	mov     x0,      x1
	mov     x1,      x3

.align 4
_memcpy:
_memmove:
//	Our preference is to copy the data in ascending address order, but if the
//	buffers overlap such that the beginning of the destination buffer aliases
//	the end of the source buffer, we need to copy in descending address order
//	instead to preserve the memmove semantics.  We detect this case with the
//	test:
//
//	    destination - source < length    (unsigned compare)
//
//	If the address of the source buffer is higher than the address of the
//	destination buffer, this arithmetic can overflow, but the overflowed value
//	can only be smaller than length if the buffers do not overlap, so we don't
//	need to worry about false positives due to the overflow (they happen, but
//	only in cases where copying in either order is correct).
	PUSH_FRAME
	sub     x3,      x0, x1
	cmp     x3,      x2
	b.cc    L_reverse
	mov     x3,      x0      // copy destination pointer
	cmp     x2,      #(kSmallCopy)
	b.cc    L_forwardSmallCopy

/*****************************************************************************
 *  Forward large copy                                                       *
 *****************************************************************************/

//	Load the first 32 bytes from src, and compute the number of bytes to the
//	first 32-byte aligned location in dst.  Even though we are going to copy
//	32 bytes, only those preceeding that 32-byte location "count" towards
//	reducing the length of the buffer or advancing the pointers.  We will need
//	to issue the first load from the advanced src pointer BEFORE the store to
//	the unmodified dst pointer.
	add     x3,      x3, #32
	and     x3,      x3, #-32 // aligned dst
	ldp     x12,x13,[x1]
	ldp     x14,x15,[x1, #16]
	sub     x5,      x3, x0   // bytes between original dst and aligned dst
	add     x1,      x1, x5   // update src pointer

//	At this point, data in the following registers is in flight:
//
//		x0    original dst pointer
//		x1    corresponding location in src buffer.
//		x2    length from aligned location in dst to end of buffer.  This is
//		      guaranteed to be >= (64 - 32).
//		x3    aligned location in dst buffer.
//		x12:x15 first 32 bytes of src buffer.
//
//	We now load 32 bytes from x1, and store 32 bytes from x12:x15 to x3.  The
//	store *may* overlap the first 32 bytes of the load, so in order to get
//	correct memmove semantics, the first 32 byte load must occur before the
//	store.
//
//	After loading these 32 bytes, we advance x1, and decrement the length by
//	64.  If the remaining length of the buffer was less than 64, then we jump
//	directly to the cleanup path.
	ldp     x8, x9, [x1]
	ldp     x10,x11,[x1, #16]
	add     x1,      x1, #32
	sub     x2,      x2, x5   // update length
	stp     x12,x13,[x0]      // initial unaligned store
	stp     x14,x15,[x0, #16] // initial unaligned store
	subs    x2,      x2, #64
	b.ls    L_forwardCleanup

L_forwardCopyLoop:
//	Main copy loop:
//
//		1. store the 32 bytes loaded in the previous loop iteration
//		2. advance the destination pointer
//		3. load the next 32 bytes
//		4. advance the source pointer
//		5. subtract 32 from the length
//
//	The loop is terminated when 32 or fewer bytes remain to be loaded.  Those
//	trailing 1-32 bytes will be copied in the loop cleanup.
	stnp    x8, x9, [x3]
	stnp    x10,x11,[x3, #16]
	add     x3,      x3, #32
	ldnp    x8, x9, [x1]
	ldnp    x10,x11,[x1, #16]
	add     x1,      x1, #32
	subs    x2,      x2, #32
	b.hi    L_forwardCopyLoop

L_forwardCleanup:
//	There are 32 bytes in x8-x11 that were loaded in the previous loop
//	iteration, which need to be stored to [x3,x3+32).  In addition, between
//  0 and 32 more bytes need to be copied from x1 to x3 + 32.  The exact
//	number of bytes to copy is x2 + 32.  Instead of using smaller conditional
//	copies, we simply copy 32 unaligned bytes from x1+x2 to 64+x3+x2.
//	This copy may overlap with the first store, so the loads must come before
//	the store of the data from the previous loop iteration.
	add     x1,      x1, x2
	ldp     x12,x13,[x1]
	ldp     x14,x15,[x1, #16]
	stp     x8, x9, [x3]
	stp     x10,x11,[x3, #16]
	add     x3,      x3, x2
	stp     x12,x13,[x3, #32]
	stp     x14,x15,[x3, #48]
	POP_FRAME
	ret

/*****************************************************************************
 *  forward small copy                                                       *
 *****************************************************************************/

//	Copy one quadword at a time until less than 8 bytes remain to be copied.
//	At the point of entry to L_forwardSmallCopy, the "calling convention"
//	is as follows:
//
//	  x0     pointer to first byte of destination
//	  x1     pointer to first byte of source
//	  x2     length of buffers
//	  x3     pointer to first byte of destination
0:	ldr     x6,     [x1],#8
	str     x6,     [x3],#8
L_forwardSmallCopy:
	subs    x2,      x2, #8
	b.cs    0b
	adds    x2,      x2, #8
	b.eq    2f
1:	ldrb    w6,     [x1],#1
	strb    w6,     [x3],#1
	subs    x2,      x2, #1
	b.ne    1b
2:	POP_FRAME
	ret

/*****************************************************************************
 *  Reverse copy engines                                                     *
 *****************************************************************************/

//	The reverse copy engines are identical in every way to the forward copy
//	engines, except in that they do everything backwards.  For this reason, they
//	are somewhat more sparsely commented than the forward copy loops.  I have
//	tried to only comment things that might be somewhat surprising in how they
//	differ from the forward implementation.
//
//	The one important thing to note is that (almost without fail), x1 and x3
//	will point to ONE BYTE BEYOND the "right-hand edge" of the active buffer
//	throughout these copy loops.  They are initially advanced to that position
//	in the L_reverse jump island.  Because of this, whereas the forward copy
//	loops generally follow a "copy data, then advance pointers" scheme, in the
//	reverse copy loops, we advance the pointers, then copy the data.

L_reverse:
//	As a minor optimization, we early out if dst == src.
	cbz     x3,      L_return
//	advance both pointers to the ends of their respective buffers before
//	jumping into the appropriate reverse copy loop.
	add     x4,      x0, x2
	add     x1,      x1, x2
	cmp     x2,      #(kSmallCopy)
	b.cc    L_reverseSmallCopy

/*****************************************************************************
 *  Reverse large copy                                                       *
 *****************************************************************************/

	ldp     x12,x13,[x1, #-16]
	ldp     x14,x15,[x1, #-32]
	sub     x3,      x4, #1   // In the forward copy, we used dst+32 & -32
	and     x3,      x3, #-32 // to find an aligned location in the dest
	sub     x5,      x4, x3   // buffer.  Here we use dst-1 & -32 instead,
	sub     x1,      x1, x5   // because we are going backwards.
	sub     x2,      x2, x5
	ldp     x8, x9, [x1, #-16]
	ldp     x10,x11,[x1, #-32]
	stp     x12,x13,[x4, #-16]
	stp     x14,x15,[x4, #-32]
	sub     x1,      x1, #32
	subs    x2,      x2, #64
	b.ls    L_reverseCleanup

L_reverseCopyLoop:
	stnp    x8, x9, [x3, #-16]
	stnp    x10,x11,[x3, #-32]
	sub     x3,      x3, #32
	ldnp    x8, x9, [x1, #-16]
	ldnp    x10,x11,[x1, #-32]
	sub     x1,      x1, #32
	subs    x2,      x2, #32
	b.hi    L_reverseCopyLoop

L_reverseCleanup:
	sub     x1,      x1, x2
	ldp     x12,x13,[x1, #-16]
	ldp     x14,x15,[x1, #-32]
	stp     x8, x9, [x3, #-16]
	stp     x10,x11,[x3, #-32]
	stp     x12,x13,[x0, #16] // In the forward copy, we need to compute the
	stp     x14,x15,[x0]      // address of these stores, but here we already
	POP_FRAME       // have a pointer to the start of the buffer.
	ret

/*****************************************************************************
 *  reverse small copy                                                       *
 *****************************************************************************/

0:	ldr     x6,     [x1,#-8]!
	str     x6,     [x4,#-8]!
L_reverseSmallCopy:
	subs    x2,      x2, #8
	b.cs    0b
	adds    x2,      x2, #8
	b.eq    2f
1:	ldrb    w6,     [x1,#-1]!
	strb    w6,     [x4,#-1]!
	subs    x2,      x2, #1
	b.ne    1b
2:	POP_FRAME
	ret

L_return:
	POP_FRAME
	ret

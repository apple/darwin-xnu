/*
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
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

#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>

/* The common path for nonzero memset and the memset_pattern routines,
 * tuned for Pentium-M class processors with SSE3 and 64-byte cache lines.
 * This is the 64-bit bersion.  It is used by the following functions:
 *
 *	void *memset(void *b, int c, size_t len);                   // when c!=0
 *	void memset_pattern4(void *b, const void *c4, size_t len);
 *	void memset_pattern8(void *b, const void *c8, size_t len);
 *	void memset_pattern16(void *b, const void *c16, size_t len);
 *
 * Note bzero() and memset() of 0 are handled separately.
 */

#define	kShort		63
#define	kVeryLong	(1024*1024)

// Initial entry from Libc with parameters passed in registers.  Although we
// correctly handle misaligned ptrs and short operands, they are inefficient.
// Therefore our caller should filter out short operands and exploit local
// knowledge (ie, original pattern length) to align the ptr if possible.
// When called, we expect:
//	%rdi = ptr to memory to set (not necessarily aligned)
//	%rdx = length (may be short or even 0)
//	%xmm0 = the pattern to store
// Return conditions:
//	%rax, %rdi, %rsi, %rcx, and %rdx all trashed
//	we preserve %r8, %r9, %r10, and %r11

        .text
        .align  5, 0x90
	.code64
Lmemset_pattern_sse3_64:
        cmpq    $(kShort),%rdx		// long enough to bother aligning?
        ja	LNotShort		// yes
	jmp	LShort			// no
        
// Here for short operands or the end of long ones.
//      %rdx = length (<= kShort)
//      %rdi = ptr (may not be not aligned)
//      %xmm0 = pattern

LUnalignedStore16:
	movdqu	%xmm0,(%rdi)		// stuff in another 16 bytes
	subl	$16,%edx
	addq	$16,%rdi
LShort:	
	cmpl	$16,%edx		// room for another vector?
	jge	LUnalignedStore16	// yes
LLessThan16:				// here at end of copy with < 16 bytes remaining
	test	$8,%dl			// 8-byte store required?
	jz	2f			// no
	movq	%xmm0,(%rdi)		// pack in 8 low bytes
	psrldq	$8,%xmm0		// then shift vector down 8 bytes
	addq	$8,%rdi
2:
	test	$4,%dl			// 4-byte store required?
	jz	3f			// no
	movd	%xmm0,(%rdi)		// pack in 4 low bytes
	psrldq	$4,%xmm0		// then shift vector down 4 bytes
	addq	$4,%rdi
3:
	andl	$3,%edx			// more to go?
	jz	5f			// no
	movd	%xmm0,%eax		// move remainders out into %eax
4:					// loop on up to three bytes
	movb	%al,(%rdi)		// pack in next byte
	shrl	$8,%eax			// shift next byte into position
	incq	%rdi
	dec	%edx
	jnz	4b
5:	ret
        
// Long enough to justify aligning ptr.  Note that we have to rotate the
// pattern to account for any alignment.  We do this by doing two unaligned
// stores, and then an aligned load from the middle of the two stores.
// This will stall on store forwarding alignment mismatch, and the unaligned
// stores can be pretty slow too, but the alternatives aren't any better.
// Fortunately, in most cases our caller has already aligned the ptr.
//      %rdx = length (> kShort)
//      %rdi = ptr (may not be aligned)
//      %xmm0 = pattern

LNotShort:
        movl    %edi,%ecx		// copy low bits of dest ptr
        negl    %ecx
        andl    $15,%ecx                // mask down to #bytes to 16-byte align
	jz	LAligned		// skip if already aligned
	movdqu	%xmm0,(%rdi)		// store 16 unaligned bytes
	movdqu	%xmm0,16(%rdi)		// and 16 more, to be sure we have an aligned chunk
	addq	%rcx,%rdi		// now point to the aligned chunk
	subq	%rcx,%rdx		// adjust remaining count
	movdqa	(%rdi),%xmm0		// get the rotated pattern (probably stalling)
	addq	$16,%rdi		// skip past the aligned chunk
	subq	$16,%rdx

// Set up for 64-byte loops.
//      %rdx = length remaining
//      %rdi = ptr (aligned)
//      %xmm0 = rotated pattern

LAligned:
	movq	%rdx,%rcx		// copy length remaining
        andl    $63,%edx                // mask down to residual length (0..63)
        andq    $-64,%rcx               // %ecx <- #bytes we will zero in by-64 loop
	jz	LNoMoreChunks		// no 64-byte chunks
        addq    %rcx,%rdi               // increment ptr by length to move
	cmpq	$(kVeryLong),%rcx	// long enough to justify non-temporal stores?
	jge	LVeryLong		// yes
        negq    %rcx			// negate length to move
	jmp	1f
	
// Loop over 64-byte chunks, storing into cache.

	.align	4,0x90			// keep inner loops 16-byte aligned
1:
        movdqa  %xmm0,(%rdi,%rcx)
        movdqa  %xmm0,16(%rdi,%rcx)
        movdqa  %xmm0,32(%rdi,%rcx)
        movdqa  %xmm0,48(%rdi,%rcx)
        addq    $64,%rcx
        jne     1b
	
	jmp	LNoMoreChunks
	
// Very long operands: use non-temporal stores to bypass cache.

LVeryLong:
        negq    %rcx			// negate length to move
	jmp	1f
	
	.align	4,0x90			// keep inner loops 16-byte aligned
1:
        movntdq %xmm0,(%rdi,%rcx)
        movntdq %xmm0,16(%rdi,%rcx)
        movntdq %xmm0,32(%rdi,%rcx)
        movntdq %xmm0,48(%rdi,%rcx)
        addq    $64,%rcx
        jne     1b

        sfence                          // required by non-temporal stores
	jmp	LNoMoreChunks
	
// Handle leftovers: loop by 16.
//      %edx = length remaining (<64)
//      %edi = ptr (aligned)
//      %xmm0 = rotated pattern

LLoopBy16:
	movdqa	%xmm0,(%rdi)		// pack in 16 more bytes
	subl	$16,%edx		// decrement count
	addq	$16,%rdi		// increment ptr
LNoMoreChunks:
	cmpl	$16,%edx		// more to go?
	jge	LLoopBy16		// yes
	jmp	LLessThan16		// handle up to 15 remaining bytes

	COMMPAGE_DESCRIPTOR(memset_pattern_sse3_64,_COMM_PAGE_MEMSET_PATTERN,kHasSSE3,0)

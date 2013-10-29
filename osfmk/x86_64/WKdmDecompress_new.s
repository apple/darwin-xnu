/*
 * Copyright (c) 2000-2013 Apple Inc. All rights reserved.
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
 This file contains x86_64 hand optimized implementation of WKdm memory page decompressor. 

	void WKdm_decompress (WK_word* src_buf, WK_word* dest_buf, WK_word* scratch, __unused__ unsigned int words);

	input :
		src_buf : address of input compressed data buffer
		dest_buf : address of output decompressed buffer 
		scratch : a 16-byte aligned 4k bytes scratch memory provided by the caller
		words : this argument is not used in the implementation

	output :

		the input buffer is decompressed and the dest_buf is written with decompressed data.

	Am algorithm description of the WKdm compress and bit stream format can be found in the WKdm Compress x86_64 assembly code WKdmCompress.s

	The bit stream (*src_buf) consists of 
		a. 12 bytes header
		b. 256 bytes for 1024 packed tags
		c. (varying number of) words for new words not matched to dictionary word. 
		d. (varying number of) 32-bit words for packed 4-bit dict_indices (for class 1 and 3)
		e. (varying number of) 32-bit words for packed 10-bit low bits (for class 1)

	where the header (of 3 words) specifies the ending boundaries (in 32-bit words) from the start of the bit stream of c,d,e, respectively.

	The decompressor 1st unpacking the bit stream component b/d/e into temorary buffers. Then it sequentially decodes the decompressed word as follows

		for (i=0;i<1024;i++) {
			tag = *next_tag++
			switch (tag) {
				case 0 : *dest_buf++ = 0; break;
				case 1 : dict_word = dictionary[*dict_index]; dictionary[*dict_index++] = *dest_buf++ = dict_word&0xfffffc00 | *LowBits++; break;
				case 2 : x = *new_word++; k = (x>>10)&255; k = hashTable[k]; dictionary[k] = *dest_buf++ = x; break;
				case 3 : *dest_buf++ = dictionary[*dict_index++];  break;
			}
 
 	cclee, 11/30/12
*/

	.text

	.globl _WKdm_decompress_new
_WKdm_decompress_new:

	// save registers, and allocate stack memory for local variables

	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r12
	pushq	%r13
	pushq	%rbx

	subq	$(64+8+16), %rsp

	movq	%rsi, %r12					// dest_buf
	movq	%rdx, %r13					// scracht_buf

	// PRELOAD_DICTONARY; dictionary starting address : starting address 0(%rsp)
#if 1
	movl	$1, 0(%rsp)
	movl	$1, 4(%rsp)
	movl	$1, 8(%rsp)
	movl	$1, 12(%rsp)
	movl	$1, 16(%rsp)
	movl	$1, 20(%rsp)
	movl	$1, 24(%rsp)
	movl	$1, 28(%rsp)
	movl	$1, 32(%rsp)
	movl	$1, 36(%rsp)
	movl	$1, 40(%rsp)
	movl	$1, 44(%rsp)
	movl	$1, 48(%rsp)
	movl	$1, 52(%rsp)
	movl	$1, 56(%rsp)
	movl	$1, 60(%rsp)
#else
	mov		$0x100000001, %rax
	mov		%rax, (%rsp)
	mov		%rax, 8(%rsp)
	mov		%rax, 16(%rsp)
	mov		%rax, 24(%rsp)
	mov		%rax, 32(%rsp)
	mov		%rax, 40(%rsp)
	mov		%rax, 48(%rsp)
	mov		%rax, 56(%rsp)
#endif

	// WK_unpack_2bits(TAGS_AREA_START(src_buf), TAGS_AREA_END(src_buf), tempTagsArray);

	leaq	268(%rdi), %r10				// TAGS_AREA_END
	leaq	12(%rdi), %rax				// TAGS_AREA_START 
	movq	%r13, %rsi					// tempTagsArray
	cmpq	%rax, %r10					// TAGS_AREA_END vs TAGS_AREA_START
	jbe		1f							// if TAGS_AREA_END <= TAGS_AREA_START, skip L_WK_unpack_2bits
	movq	%r13, %rcx					// next_word
	xorl	%r8d, %r8d					// i = 0
	mov		$(50529027<<32)+50529027, %r9
L_WK_unpack_2bits:
	movl	12(%rdi,%r8, 4), %eax
	movl	12(%rdi,%r8, 4), %edx
	shrl	$2, %eax
	shlq	$32, %rax
	orq		%rdx, %rax
	movq	%rax, %rdx
	shrq	$4, %rax
	andq	%r9, %rdx
	andq	%r9, %rax
	incq	%r8							// i++
	movq	%rdx, (%rcx)
	movq	%rax, 8(%rcx)
	addq	$16, %rcx					// next_tags += 16
	cmpq	$64, %r8					// i vs 64
	jne		L_WK_unpack_2bits			// repeat loop until i==64
1:


	// WK_unpack_4bits(QPOS_AREA_START(src_buf), QPOS_AREA_END(src_buf), tempQPosArray);

	mov		4(%rdi), %eax				// WKdm header qpos end
	leaq	(%rdi,%rax,4), %r9			// QPOS_AREA_END
	mov		0(%rdi), %eax				// WKdm header qpos start
	leaq	(%rdi,%rax,4), %r8			// QPOS_AREA_START
	leaq	1024(%r13), %rbx			// tempQPosArray
	cmpq	%r8, %r9					// QPOS_AREA_END vs QPOS_AREA_START
	jbe		1f							// if QPOS_AREA_END <= QPOS_AREA_START, skip L_WK_unpack_4bits
	leaq	8(%rbx), %rcx				// next_qpos

	mov		$(252645135<<32)+252645135, %r11
L_WK_unpack_4bits:
	movl	(%r8), %eax					// w = *next_word
	movl	%eax, %edx					// w
	shlq	$28, %rax
	orq		%rdx, %rax
	addq	$4, %r8						// next_word++
	andq	%r11, %rax
	movq	%rax, -8(%rcx)
	addq	$8, %rcx					// next_qpos+=8
	cmpq	%r8, %r9					// QPOS_AREA_END vs QPOS_AREA_START
	ja		L_WK_unpack_4bits			// repeat loop until QPOS_AREA_END <= QPOS_AREA_START


1:

	// WK_unpack_3_tenbits(LOW_BITS_AREA_START(src_buf), LOW_BITS_AREA_END(src_buf), tempLowBitsArray);

	movl	8(%rdi), %eax				// LOW_BITS_AREA_END offset
	leaq	(%rdi,%rax,4), %rdi			// LOW_BITS_AREA_END
	leaq	2048(%r13), %r11			// tempLowBitsArray
	leaq	4094(%r13), %r13			// final tenbits addr
	sub		%r9, %rdi					// LOW_BITS_AREA_START vs LOW_BITS_AREA_END
	jle		1f							// if START>=END, skip L_WK_unpack_3_tenbits
	movq	%r11, %rcx					// next_low_bits
L_WK_unpack_3_tenbits:
	movl	(%r9), %eax					// w = *next_word, 0:c:b:a
	movl	$(1023<<10), %edx
	movl	$(1023<<20), %r8d
	andl	%eax, %edx					// b << 10
	andl	%eax, %r8d					// c << 20
	andq	$1023, %rax
	shll	$6, %edx
	shlq	$12, %r8
	orl		%edx, %eax
	orq		%r8, %rax
	cmp		%r13, %rcx
	je		2f
	mov		%rax, (%rcx)
	jmp		3f
2:	mov		%ax, (%rcx)
3:
	addq	$4, %r9						// next_word++
	addq	$6, %rcx					// next_low_bits += 3
	sub		$4, %rdi
	jg		L_WK_unpack_3_tenbits		// repeat loop if LOW_BITS_AREA_END > next_word
1:


	#define	next_qpos		%rbx
	#define	hash			%r8
	#define	tags_counter	%edi
	#define	dest_buf		%r12
	#define next_full_patt	%r10	

	leaq	_hashLookupTable_new(%rip), hash	// hash look up table
	movl	$1024, tags_counter				// tags_counter
	jmp		L_next

	.align 4,0x90
L_nonpartital:
	jl		L_ZERO_TAG
	cmpb	$2, -1(%rsi)
	je		L_MISS_TAG

L_EXACT_TAG:
	movzbl	(next_qpos), %eax				// qpos = *next_qpos
	incq	next_qpos						// next_qpos++
	decl	tags_counter					// tags_counter--
	movl	(%rsp,%rax,4), %eax				// w = dictionary[qpos]
	movl	%eax, -4(dest_buf)				// *dest_buf = w
	je		L_done

L_next:
	incq	%rsi							// next_tag++
	addq	$4, dest_buf
	cmpb	$1, -1(%rsi)
	jne		L_nonpartital

L_PARTIAL_TAG:
	movzbl	(next_qpos),%edx				// qpos = *next_qpos
	incq	next_qpos						// next_qpos++
	movl	(%rsp,%rdx,4), %eax				// read dictionary word
	andl	$-1024, %eax					// clear lower 10 bits
	or		(%r11), %ax						// pad the lower 10-bits from *next_low_bits
	addq	$2, %r11						// next_low_bits++
	decl	tags_counter					// tags_counter--
	movl	%eax, (%rsp,%rdx,4)				// *dict_location = newly formed word 
	movl	%eax, -4(dest_buf)				// *dest_buf = newly formed word
	jg		L_next							// repeat loop until next_tag==tag_area_end

L_done:

	// release stack memory, restore registers, and return

	addq	$(64+8+16), %rsp
	popq	%rbx
	popq	%r13
	popq	%r12
	leave
	ret

	.align 4,0x90
L_MISS_TAG:
	movl	(next_full_patt), %edx			// w = *next_full_patt
	movl	(next_full_patt), %eax			// w = *next_full_patt
	shrl	$10, %edx						// w>>10
	addq	$4, next_full_patt				// next_full_patt++
	movzbl	%dl, %edx						// 8-bit hash table index
	movl	%eax, -4(dest_buf)				// *dest_buf = word
	movzbl	(hash,%rdx),%edx				// qpos
	decl	tags_counter					// tags_counter--
	movl	%eax, (%rsp,%rdx)				// dictionary[qpos] = word
	jg		L_next							// repeat the loop
	jmp		L_done

	.align 4,0x90
L_ZERO_TAG:
	decl	tags_counter					// tags_counter--
	movl	$0, -4(dest_buf)					// *dest_buf = 0
	jg		L_next							// repeat the loop
	jmp		L_done



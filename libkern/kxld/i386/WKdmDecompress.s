// $Id: WKdmDecompress.intel.s,v 1.1 2010/01/30 00:39:21 cclee Exp cclee $

// This file contains i386 and x86_64 (no SSE) optimized implementation of WKdm Decompressor.
// The implementation is derived by compiling (gcc -O3) the original C code (WKdmDecompress.c)
// followed by hand tweaking of the compiled assembly code.
// cclee, 1/29/10

#if defined __i386__
	.text
	.align 4,0x90

	.globl _WKdm_decompress
_WKdm_decompress:

	// save registers, set up base pointer %ebp, and allocate stack memory for local veriables

	pushl	%ebp
	movl	%esp, %ebp
	pushl	%edi
	pushl	%esi
	pushl	%ebx
	subl	$7324, %esp

	// PRELOAD_DICTIONARY; dictionary starting address : -88(%ebp)
	movl	$1, -88(%ebp)
	movl	$1, -84(%ebp)
	movl	$1, -80(%ebp)
	movl	$1, -76(%ebp)
	movl	$1, -72(%ebp)
	movl	$1, -68(%ebp)
	movl	$1, -64(%ebp)
	movl	$1, -60(%ebp)
	movl	$1, -56(%ebp)
	movl	$1, -52(%ebp)
	movl	$1, -48(%ebp)
	movl	$1, -44(%ebp)
	movl	$1, -40(%ebp)
	movl	$1, -36(%ebp)
	movl	$1, -32(%ebp)
	movl	$1, -28(%ebp)

	#define	dictionary_addr			-88(%ebp)
	#define	TAGS_AREA_END -7292(%ebp)
	#define	tempTagsArray	-7300(%ebp)
	#define	tempQPosArray	-2488(%ebp)
	#define	tempLowBitsArray	-7288(%ebp)
	#define	next_low_bits		-7296(%ebp)
	#define	dictionary		-7308(%ebp)
	#define	tag_area_end	-7304(%ebp)

	// WK_unpack_2bits(TAGS_AREA_START(src_buf), TAGS_AREA_END(src_buf), tempTagsArray);

	movl	8(%ebp), %eax						// src_buf
	addl	$272, %eax							// src_buf + 16 (WKdm Header) + 256 (Tags)
	movl	%eax, TAGS_AREA_END					// TAGS_AREA_END(src_buf)
	movl	8(%ebp), %eax						// src_buf
	movl	%eax, %edi							// src_buf
	addl	$16, %eax							// TAGS_AREA_START(src_buf) = src_buf + 16 (WKdm Header)
	leal	-1288(%ebp), %edx					// tempTagsArray
	movl	%edx, tempTagsArray					// save a copy of tempTagsArray[] at the said location
	cmpl	%eax, TAGS_AREA_END					// TAGS_AREA_END vs TAGS_AREA_START
	jbe		1f									// if TAGS_AREA_END<=TAGS_AREA_START, no need for WK_unpack_2bits
	movl	%edx, %ecx							// %ecx -> tempTagsArray[0]
	xorl	%esi, %esi							// i=0
	movl	$50529027, %ebx						// 0x03030303, mask to extract 4 2-bit tags
	.align 4,0x90
L_WK_unpack_2bits:
	movl	16(%edi,%esi,4), %edx				// src_buf[i] for 16 tags, 16 (WKdm header)
	movl	%edx, %eax							// w = src_buf[i]
	andl	%ebx, %eax							// 1st 4 tags, each in bytes	
	movl	%eax, (%ecx)						// save 1st 4 tags
	movl	%edx, %eax							// w = src_buf[i]
	shrl	$2, %eax							// shift down 2 bits
	andl	%ebx, %eax							// 2nd 4 tags, each in bytes
	movl	%eax, 4(%ecx)						// save 2nd 4 tags
	shrl	$4, %edx							// shift down w by 4 bits
	movl	%edx, %eax							// w>>4
	andl	%ebx, %eax							// 3rd 4 tags
	movl	%eax, 8(%ecx)						// save 3rd 4 tags
	shrl	$2, %edx							// w>>6
	andl	%ebx, %edx							// 4th 4 tags
	movl	%edx, 12(%ecx)						// save 4th 4 tags
	addl	$16, %ecx							// point to next tempTagsArray[i*16]
	incl	%esi								// i++
	cmpl	$64, %esi							// i vs 64
	jne		L_WK_unpack_2bits					// repeat the loop until i==64	
1:

	// WK_unpack_4bits(QPOS_AREA_START(src_buf), QPOS_AREA_END(src_buf), tempQPosArray);

	movl	8(%edi), %eax						// WKdm header qpos end
	leal	(%edi,%eax,4), %esi					// QPOS_AREA_END
	movl	4(%edi), %eax						// WKdm header qpos start
	leal	(%edi,%eax,4), %ecx					// QPOS_AREA_START
	cmpl	%ecx, %esi							// QPOS_AREA_END vs QPOS_AREA_START
	jbe		1f									// if QPOS_AREA_END <= QPOS_AREA_START, skip WK_unpack_4bits
	leal	tempQPosArray, %edi					// tempQPosArray
	movl	$252645135, %ebx					// 0x0f0f0f0f : mask to extract 4 4-bit qpos
L_WK_unpack_4bits:
	movl	(%ecx), %eax						// w
	movl	%eax, %edx							// w
	andl	%ebx, %edx							// 1st 4 qpos
	movl	%edx, (%edi)						// save 1st 4 qpos
	shrl	$4, %eax							// w>>4
	andl	%ebx, %eax							// 2nd 4 qpos
	movl	%eax, 4(%edi)						// save 2nd 4 qpos
	addl	$4, %ecx							// point to next word w
	addl	$8, %edi							// qpos += 8
	cmpl	%ecx, %esi							// QPOS_AREA_END vs qpos_pointer
	ja		L_WK_unpack_4bits					// repeat until qpos_pointer >= QPOS_AREA_END	

	// WK_unpack_3_tenbits(LOW_BITS_AREA_START(src_buf), LOW_BITS_AREA_END(src_buf), tempLowBitsArray);

1:
	movl	8(%ebp), %edx						// src_buf
	movl	12(%edx), %eax 						// LOW_BITS_AREA_END offset
	leal	(%edx,%eax,4), %edi					// LOW_BITS_AREA_END 
	cmpl	%edi, %esi							// LOW_BITS_AREA_START(=QPOS_AREA_END) vs LOW_BITS_AREA_END	
	jae		1f									// if (LOW_BITS_AREA_START>=LOW_BITS_AREA_END) skip unpack_3_tenbits
	leal	tempLowBitsArray, %ecx				// tempLowBitsArray
	movl	$1023, %ebx							// 0x03ff to extact lower 10-bits

	.align 4,0x90
L_WK_unpack_3_tenbits:
	movl	(%esi), %eax						// w = *next_low_bits
	movl	%eax, %edx							// w
	andl	%ebx, %edx							// 1st 10-bit
	movl	%edx, (%ecx)						// save 1st 10-bit
	shrl	$10, %eax							// (w>>10)
	movl	%eax, %edx							// (w>>10)
	andl	%ebx, %edx							// 2nd 10-bit
	movl	%edx, 4(%ecx)						// save 2nd 10-bit
	shrl	$10, %eax							// (w>>20), no need to and with mask, the top 2 bits should be zero
	movl	%eax, 8(%ecx)						// save 3rd 10-bits
	addl	$4, %esi							// point to next w
	addl	$12, %ecx							// tempLowBitsArray += 3;
	cmpl	%esi, %edi							// LOW_BITS_AREA_END vs next_low_bits
	ja		L_WK_unpack_3_tenbits				// repeat until next_low_bits>=LOW_BITS_AREA_END	
1:
	call	Lhash
Lhash:	
	popl	%ebx								// set up %ebx for use in Hash Table loopup[

	#define	next_tag	%esi
	#define	next_qpos	%edi

	movl	tempTagsArray, next_tag				// next_tag = tempTagsArray
	leal	tempQPosArray, next_qpos			// next_qpos = tempQPosArray
	movl	12(%ebp), %ecx						// dest_buf
	addl	$4, %ecx							// for some reason, performance is better if we points to the next one
	leal	tempLowBitsArray, %eax				// tempLowBitsArray
	movl	%eax, next_low_bits					// next_low_bits = next_low_bits;
	leal	-264(%ebp), %edx
	movl	%edx, tag_area_end					// tag_area_end
	leal	dictionary_addr, %eax				// dictionary starting address
	movl	%eax, dictionary					// dictionary
	jmp		L11
	.align 4,0x90
L29:
	jle		L_ZERO_TAG
	cmpb	$2, %al								// MISS_TAG
	je		L_MISS_TAG
L_EXACT_TAG:
	movsbl	(next_qpos),%eax					// qpos = *next_qpos
	incl	next_qpos							// next_qpos++
	movl	dictionary, %edx					// dictionary
	movl	(%edx,%eax,4), %eax					// w = dictionary[qpos]
	movl	%eax, -4(%ecx)						// *dest_buf = w
	.align 4,0x90
L_next:
	incl	next_tag							// next_tag++
	addl	$4, %ecx							// dest_buf++
	cmpl	tag_area_end, next_tag				// next_tag vs tag_area_end
	jae		L_done								// if (next_tag>=tag_area_end)
L11:
	movzbl	(next_tag), %eax					// tag = *next_tag
	cmpb	$1, %al								// Partial match?
	jne		L29
L_PARTIAL_TAG:
	movsbl	(next_qpos),%edx					// qpos = *next_qpos
	movl	dictionary, %eax					// dictionary
	leal	(%eax,%edx,4), %edx					// dict_location = &dictionary[qpos]
	movl	%edx, -7324(%ebp)					// save dict_location to release %edx
	incl	next_qpos							// next_qpos++
	movl	(%edx), %eax						// read dictionary word
	andl	$-1024, %eax						// keep only higher 22-bits
	movl	next_low_bits, %edx					// low_bits = *next_low_bits
	orl		(%edx), %eax						// construct the new partially matched word
	addl	$4, %edx							// 
	movl	%edx, next_low_bits					// next_low_bits++
	movl	-7324(%ebp), %edx					// dict_location
	movl	%eax, (%edx)						// update *dict_location with the newly constructed word
	movl	%eax, -4(%ecx)						// *dest_buf = the newly constructed word
	incl	next_tag							// next_tag++
	addl	$4, %ecx							// dest_buf++
	cmpl	tag_area_end, next_tag				// next_tag vs tag_area_end
	jb		L11									// if next_tag < tag_area_end, repeat the loop
L_done:

	// release stack memory, restore registers, and return
	addl	$7324, %esp
	popl	%ebx
	popl	%esi
	popl	%edi
	leave
	ret

	#define	next_full_patt	-7292(%ebp) /* next_full_patt starts with initial value of TAGS_AREA_END */

	.align 4,0x90
L_MISS_TAG:
	movl	next_full_patt, %edx					// next_full_patt
	movl	(%edx), %eax							// word = *next_full_patt
	addl	$4, %edx								// next_full_patt++
	movl	%edx, next_full_patt					// save next_full_patt
	movl	%eax, %edx								// word
	shrl	$10, %edx								// word>>10
	andl	$255, %edx								// 8-bit hash table index
	movsbl	_hashLookupTable-Lhash(%ebx,%edx),%edx	// qpos
	movl	%eax, -88(%ebp,%edx)					// dictionary[qpos] = word
	movl	%eax, -4(%ecx)							// *dest_buf = word
	jmp		L_next									// repeat the loop

	.align 4,0x90
L_ZERO_TAG:
	movl	$0, -4(%ecx)							// *dest_buf = 0
	jmp		L_next									// repeat the loop

#endif	// __i386__

#if defined __x86_64__


	.text
	.align 4,0x90

	.globl _WKdm_decompress
_WKdm_decompress:

	// save registers, and allocate stack memory for local variables

	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r12
	pushq	%rbx
	subq	$7144, %rsp

	movq	%rsi, %r12					// dest_buf

	// PRELOAD_DICTIONARY; dictionary starting address : starting address -80(%rpb)
	movl	$1, -80(%rbp)
	movl	$1, -76(%rbp)
	movl	$1, -72(%rbp)
	movl	$1, -68(%rbp)
	movl	$1, -64(%rbp)
	movl	$1, -60(%rbp)
	movl	$1, -56(%rbp)
	movl	$1, -52(%rbp)
	movl	$1, -48(%rbp)
	movl	$1, -44(%rbp)
	movl	$1, -40(%rbp)
	movl	$1, -36(%rbp)
	movl	$1, -32(%rbp)
	movl	$1, -28(%rbp)
	movl	$1, -24(%rbp)
	movl	$1, -20(%rbp)

	// WK_unpack_2bits(TAGS_AREA_START(src_buf), TAGS_AREA_END(src_buf), tempTagsArray);
	leaq	272(%rdi), %r10				// TAGS_AREA_END
	leaq	16(%rdi), %rax				// TAGS_AREA_START 
	leaq	-1280(%rbp), %rsi			// tempTagsArray
	cmpq	%rax, %r10					// TAGS_AREA_END vs TAGS_AREA_START
	jbe		1f							// if TAGS_AREA_END <= TAGS_AREA_START, skip L_WK_unpack_2bits
	movq	%rsi, %rcx					// next_word
	xorl	%r8d, %r8d					// i = 0
	.align 4,0x90
L_WK_unpack_2bits:
	movl	16(%rdi,%r8,4), %edx		// w = *next_word
	movl	%edx, %eax					// w
	andl	$50529027, %eax				// 1st 4 tags
	movl	%eax, (%rcx)				// write 1st 4 tags
	movl	%edx, %eax					// w
	shrl	$2, %eax					// w>>2
	andl	$50529027, %eax				// 2nd 4 tags
	movl	%eax, 4(%rcx)				// write 2nd 4 tags
	shrl	$4, %edx					// w>>4
	movl	%edx, %eax					// w>>4
	andl	$50529027, %eax				// 3rd 4 tags
	movl	%eax, 8(%rcx)				// write 3rd 4 tags
	shrl	$2, %edx					// w>>6
	andl	$50529027, %edx				// 4th 4 tags
	movl	%edx, 12(%rcx)				// write 4th 4 tags
	addq	$16, %rcx					// next_tags += 16
	incq	%r8							// i++
	cmpq	$64, %r8					// i vs 64
	jne		L_WK_unpack_2bits			// repeat loop until i==64
1:

	// WK_unpack_4bits(QPOS_AREA_START(src_buf), QPOS_AREA_END(src_buf), tempQPosArray);

	mov		8(%rdi), %eax				// WKdm header qpos end
	leaq	(%rdi,%rax,4), %r9			// QPOS_AREA_END
	mov		4(%rdi), %eax				// WKdm header qpos start
	leaq	(%rdi,%rax,4), %r8			// QPOS_AREA_START
	leaq	-2480(%rbp), %rbx			// tempQPosArray
	cmpq	%r8, %r9					// QPOS_AREA_END vs QPOS_AREA_START
	jbe		1f							// if QPOS_AREA_END <= QPOS_AREA_START, skip L_WK_unpack_4bits
	leaq	8(%rbx), %rcx				// next_qpos
L_WK_unpack_4bits:
	movl	(%r8), %eax					// w = *next_word
	movl	%eax, %edx					// w
	andl	$252645135, %edx			// 1st 4 qpos
	movl	%edx, -8(%rcx)				// write 1st 4 qpos
	shrl	$4, %eax					// w>>4
	andl	$252645135, %eax			// 2nd 4 qpos
	movl	%eax, -4(%rcx)				// write 2nd 4 qpos
	addq	$4, %r8						// next_word++
	addq	$8, %rcx					// next_qpos+=8
	cmpq	%r8, %r9					// QPOS_AREA_END vs QPOS_AREA_START
	ja		L_WK_unpack_4bits			// repeat loop until QPOS_AREA_END <= QPOS_AREA_START
1:

	// WK_unpack_3_tenbits(LOW_BITS_AREA_START(src_buf), LOW_BITS_AREA_END(src_buf), tempLowBitsArray);

	mov		12(%rdi), %eax				// LOW_BITS_AREA_END offset
	leaq	(%rdi,%rax,4), %rdi			// LOW_BITS_AREA_END
	leaq	-7280(%rbp), %r11			// tempLowBitsArray
	cmpq	%rdi, %r9					// LOW_BITS_AREA_START vs LOW_BITS_AREA_END
	jae		1f							// if START>=END, skip L_WK_unpack_3_tenbits
	leaq	12(%r11), %rcx				// next_low_bits
L_WK_unpack_3_tenbits:
	movl	(%r9), %eax					// w = *next_word
	movl	%eax, %edx					// w
	andl	$1023, %edx					// 1st tenbits
	movl	%edx, -12(%rcx)				// write 1st tenbits
	shrl	$10, %eax					// w >> 10
	movl	%eax, %edx					// w >> 10
	andl	$1023, %edx					// 2nd tenbits
	movl	%edx, -8(%rcx)				// write 2nd tenbits
	shrl	$10, %eax					// w >> 20, 3rd tenbits
	movl	%eax, -4(%rcx)				// write 3rd tenbits
	addq	$4, %r9						// next_word++
	addq	$12, %rcx					// next_low_bits += 3
	cmpq	%r9, %rdi					// LOW_BITS_AREA_END vs next_word
	ja		L_WK_unpack_3_tenbits		// repeat loop if LOW_BITS_AREA_END > next_word
1:
	movq	%rsi, %rdi						// next_tag
	movq	%rbx, %r8						// next_qpos
	leaq	4(%r12), %rcx					// dest_buf
	movq	%r11, %r9						// next_low_bits
	leaq	-80(%rbp), %r11					// dictionary
	leaq	_hashLookupTable(%rip), %rbx	// hash look up table
	leaq	1024(%rsi), %rsi				// tag_area_end

	jmp	L11
	.align 4,0x90
L31:
	jle		L_ZERO_TAG
	cmpb	$2, %al							// MISS_TAG
	je		L_MISS_TAG
L_EXACT_TAG:
	movsbq	(%r8),%rax						// qpos = *next_qpos
	incq	%r8								// next_qpos++
	movl	(%r11,%rax,4), %eax				// w = dictionary[qpos]
	movl	%eax, -4(%rcx)					// *dest_buf = w
	.align 4,0x90
L_next:
	incq	%rdi							// next_tag++
	addq	$4, %rcx						// dest_buf++
	cmpq	%rsi, %rdi						// next_tag vs tag_area_end
	jae		L_done							// if next_tag >= tag_area_end, we're done
L11:
	movzbl	(%rdi), %eax					// tag = *next_tag
	cmpb	$1, %al							// partial match tag ?
	jne		L31
L_PARTIAL_TAG:
	movsbq	(%r8),%rdx						// qpos = *next_qpos
	leaq	(%r11,%rdx,4), %rdx				// dict_location = &dictionary[qpos]
	incq	%r8								// next_qpos++
	movl	(%rdx), %eax					// read dictionary word
	andl	$-1024, %eax					// clear lower 10 bits
	orl		(%r9), %eax						// pad the lower 10-bits from *next_low_bits
	addq	$4, %r9							// next_low_bits++
	movl	%eax, (%rdx)					// *dict_location = newly formed word 
	movl	%eax, -4(%rcx)					// *dest_buf = newly formed word
	cmpq	%rsi, %rdi						// compare next_tag vs tag_area_end
	jne		L_next							// repeat loop until next_tag==tag_area_end
L_done:

	// release stack memory, restore registers, and return
	addq	$7144, %rsp
	popq	%rbx
	popq	%r12
	leave
	ret

	.align 4,0x90
L_MISS_TAG:
	movl	(%r10), %eax					// w = *next_full_patt
	addq	$4, %r10						// next_full_patt++
	movl	%eax, %edx						// w 
	shrl	$10, %edx						// w>>10
	movzbl	%dl, %edx						// 8-bit hash table index
	movsbq	(%rbx,%rdx),%rdx				// qpos
	movl	%eax, -80(%rbp,%rdx)			// dictionary[qpos] = word
	movl	%eax, -4(%rcx)					// *dest_buf = word
	jmp		L_next							// repeat the loop

	.align 4,0x90
L_ZERO_TAG:
	movl	$0, -4(%rcx)					// *dest_buf = 0
	jmp		L_next							// repeat the loop

#endif	// --X86_64__

.globl _hashLookupTable
	.const
	.align 5
_hashLookupTable:
	.byte	0
	.byte	52
	.byte	8
	.byte	56
	.byte	16
	.byte	12
	.byte	28
	.byte	20
	.byte	4
	.byte	36
	.byte	48
	.byte	24
	.byte	44
	.byte	40
	.byte	32
	.byte	60
	.byte	8
	.byte	12
	.byte	28
	.byte	20
	.byte	4
	.byte	60
	.byte	16
	.byte	36
	.byte	24
	.byte	48
	.byte	44
	.byte	32
	.byte	52
	.byte	56
	.byte	40
	.byte	12
	.byte	8
	.byte	48
	.byte	16
	.byte	52
	.byte	60
	.byte	28
	.byte	56
	.byte	32
	.byte	20
	.byte	24
	.byte	36
	.byte	40
	.byte	44
	.byte	4
	.byte	8
	.byte	40
	.byte	60
	.byte	32
	.byte	20
	.byte	44
	.byte	4
	.byte	36
	.byte	52
	.byte	24
	.byte	16
	.byte	56
	.byte	48
	.byte	12
	.byte	28
	.byte	16
	.byte	8
	.byte	40
	.byte	36
	.byte	28
	.byte	32
	.byte	12
	.byte	4
	.byte	44
	.byte	52
	.byte	20
	.byte	24
	.byte	48
	.byte	60
	.byte	56
	.byte	40
	.byte	48
	.byte	8
	.byte	32
	.byte	28
	.byte	36
	.byte	4
	.byte	44
	.byte	20
	.byte	56
	.byte	60
	.byte	24
	.byte	52
	.byte	16
	.byte	12
	.byte	12
	.byte	4
	.byte	48
	.byte	20
	.byte	8
	.byte	52
	.byte	16
	.byte	60
	.byte	24
	.byte	36
	.byte	44
	.byte	28
	.byte	56
	.byte	40
	.byte	32
	.byte	36
	.byte	20
	.byte	24
	.byte	60
	.byte	40
	.byte	44
	.byte	52
	.byte	16
	.byte	32
	.byte	4
	.byte	48
	.byte	8
	.byte	28
	.byte	56
	.byte	12
	.byte	28
	.byte	32
	.byte	40
	.byte	52
	.byte	36
	.byte	16
	.byte	20
	.byte	48
	.byte	8
	.byte	4
	.byte	60
	.byte	24
	.byte	56
	.byte	44
	.byte	12
	.byte	8
	.byte	36
	.byte	24
	.byte	28
	.byte	16
	.byte	60
	.byte	20
	.byte	56
	.byte	32
	.byte	40
	.byte	48
	.byte	12
	.byte	4
	.byte	44
	.byte	52
	.byte	44
	.byte	40
	.byte	12
	.byte	56
	.byte	8
	.byte	36
	.byte	24
	.byte	60
	.byte	28
	.byte	48
	.byte	4
	.byte	32
	.byte	20
	.byte	16
	.byte	52
	.byte	60
	.byte	12
	.byte	24
	.byte	36
	.byte	8
	.byte	4
	.byte	16
	.byte	56
	.byte	48
	.byte	44
	.byte	40
	.byte	52
	.byte	32
	.byte	20
	.byte	28
	.byte	32
	.byte	12
	.byte	36
	.byte	28
	.byte	24
	.byte	56
	.byte	40
	.byte	16
	.byte	52
	.byte	44
	.byte	4
	.byte	20
	.byte	60
	.byte	8
	.byte	48
	.byte	48
	.byte	52
	.byte	12
	.byte	20
	.byte	32
	.byte	44
	.byte	36
	.byte	28
	.byte	4
	.byte	40
	.byte	24
	.byte	8
	.byte	56
	.byte	60
	.byte	16
	.byte	36
	.byte	32
	.byte	8
	.byte	40
	.byte	4
	.byte	52
	.byte	24
	.byte	44
	.byte	20
	.byte	12
	.byte	28
	.byte	48
	.byte	56
	.byte	16
	.byte	60
	.byte	4
	.byte	52
	.byte	60
	.byte	48
	.byte	20
	.byte	16
	.byte	56
	.byte	44
	.byte	24
	.byte	8
	.byte	40
	.byte	12
	.byte	32
	.byte	28
	.byte	36
	.byte	24
	.byte	32
	.byte	12
	.byte	4
	.byte	20
	.byte	16
	.byte	60
	.byte	36
	.byte	28
	.byte	8
	.byte	52
	.byte	40
	.byte	48
	.byte	44
	.byte	56

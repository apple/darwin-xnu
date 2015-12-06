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
 This file contains x86_64 hand optimized implementation of WKdm memory page compressor. 

 	int WKdm_compress (WK_word* src_buf, WK_word* dest_buf, WK_word* scratch, unsigned int bytes_budget);

	input :
		src_buf : address of input page (length = 1024 words)
		dest_buf : address of output buffer (may not be 16-byte aligned)
		scratch : a 16-byte aligned 4k bytes scratch memory provided by the caller, 
		bytes_budget : a given byte target in compression

	output :

		if the input buffer can be compressed within the given byte budget, the dest_buf is written with compressed data and the function returns with number of bytes for the compressed data  
		o.w., the function returns -1 to signal that the input data can not be compressed with the given byte budget.
		During the scan and tag process, each word that can not be compressed will be written to dest_buf, followed by a 12-bytes header + 256-bytes tag area.
		When the functions returns -1, dest_buf is filled with all those words that can not be compressed and should be considered undefined.
		The worst-case scenario is that all words can not be compressed. Hence, the minimum size requirement for dest_buf should be 12+256+4096 = 4364 bytes to prevent from memory fault. 

 The 4th argument bytes_budget is the target compress budget in bytes.
 Should the input page can be compressed within the budget, the compressed data is written to *dest_buf, and the function returns the number of compressed bytes.
 Otherwise, the function returns -1 (to signal to the caller that the page can not be compressed).

 WKdm Compression algorithm is briefly stated as follows:

	There is a dynamically updated dictionary consisting of 16 words. Each dictionary word is initialized to 1 at the point of entry to the function.
	For a nonzero input word x, its 8-bits (10-bits scaled up) is used to determine a corresponding word from the dictionary, represented by dict_index (4-bits) and dict_word (32-bits).
		a. k = (x>>10)&255;						// 8-bit hash table index
		b. dict_index = hashTable[k];			// 4-bit dictionary index, hashTable[] is fixed	
		c. dict_word = dictionary[dict_index];	// 32-bit dictionary word, dictionary[] is dynamically updated 

 	Each input word x is classified/tagged into 4 classes :
		0 : x = 0
		1 : (x>>10) == (dict_word>>10), bits 10:31 of the input word match a dictionary word
  		2 : (x>>10) != (dict_word>>10), the above condition (22 higher bits matched) is not met, meaning a dictionary miss
  		3 : (x == dict_word), the exact input word is in the dictionary

	For each class, different numbers of bits are needed for the decompressor to reproduce the original input word.
		0 : 2-bits tag (32->2 compression)
		1 : 2-bits tag + 4-bits dict_index + 10-bits lower bits (32->16 compression)
		2 : 2-bits tag + 32-bits new word (32->34 expansion)
		3 : 2-bits tag + 4-bits dict_index (32->6 compression)

	It is obvious now that WKdm compress algorithm works well for pages where there are lots of zero words (32->2) and/or there are freqeunt repeats of some word patterns (32->6). 

	the output bit stream (*dest_buf) consists of 
		a. 12 bytes header
		b. 256 bytes for 1024 packed tags
		c. (varying number of) words for new words not matched to dictionary word. 
		d. (varying number of) 32-bit words for packed 4-bit dict_indices (for class 1 and 3)
		e. (varying number of) 32-bit words for packed 10-bit low bits (for class 1)

	the header is actually of 3 words that specify the ending offset (in 32-bit words) from the start of the bit stream of c,d,e, respectively.
	Note that there might be padding bits in d (if the number of dict_indices does not divide by 8), and there are 2/12/22 padding bits for packing 3/2/1 low 10-bits in a 32-bit word.


	The WKdm compress algorithm 1st runs a scan and classification pass, tagging and write unpacked data into temporary buffers. It follows by packing those data into the output buffer.

	The temp buffers are

		uint8_t 	tempTagsArray[1024];			// temporary saving for tags before final packing
		uint8_t 	tempQPosArray[1024];			// temporary saving for dict_indices before final packing
		uint16_t 	tempLowBitsArray[1024];			// temporary saving for partially matched lower 10 bits before final packing

	Since the new words (that can not matched fully or partially to the dictionary) are stored right after the header and the tags section and need no packing, we directly write them to
	the destination buffer.

		uint32_t	*new_word = dest_buf+3+64;		// 3 words for header, 64 words for tags, new words come right after the tags.

	Now since we are given a byte budget for this compressor, we can monitor the byte usage on the fly in the scanning and tagging pass.

	bytes_budget -= 12 + 256; // header and tags (1024 * 2 /8 = 256 bytes) 

	whenever an input word is classified as class

		2 : bytes_budget-=4; if (bytes_budget<=0) exit -1;

	when writing the 8 4-bits/3 10-bits, monitor bytes_budget and exit -1 when byte_budget <=0;

	without showing the bit budget management, the pseudo code is given as follows:

	uint8_t 	*tags=tempTagsArray;
	uint8_t 	*dict=tempQPosArray;
	uint8_t 	*partial=tempLowBitsArray;

	for (i=0;i<1024;i++) {
			x = *src_buf++;
			if (x == 0) {		// zero, 2-bits tag
					*tags++ = 0;
			} else {

				// find dict_index and dict_word from x
				k = (x>>10)&255;
				dict_index = hashTable[k];
				dict_word = dictionary[dict_index];

				if (dict_word == x) { // exactly match
					// 2-bits tag + 4-bits table index
					*tags++ = 3;
					*dict++ = dict_index;
				} else if (((x^dict_word)>>10)==0) {	// 22 higher bits matched
					// 2-bits tag + 4-bits table index + 10-bits lower partial
					*tags++ = 1;
                    *dict++ = dict_index;
					*partial++ = x &0x3ff;
					dictionary[dict_index] = x;
				} else {	// not matched
					// 2-bits tag + 32-bits new word
					*tags++ = 2;
					*new_word++ = x;
					dictionary[dict_index] = x;
				}
			}
	}

	after this classification/tagging pass is completed, the 3 temp buffers are packed into the output *dest_buf:

		1. 1024 tags are packed into 256 bytes right after the 12-bytes header
		2. dictionary indices (4-bits each) are packed into are right after the new words section
		3. 3 low 10-bits are packed into a 32-bit word, this is after the dictionary indices section.

 	cclee, 11/30/12

    Added zero page, single value page, sparse page, early abort optimizations
    rsrini, 09/14/14

*/

	.text
	.align 4,0x90

#define SV_RETURN           $0                      // return value when SV, ZV page is found
#define MZV_MAGIC           $17185                  // magic value used to identify MZV page encoding
#define CHKPT_BYTES         416                     // for early aborts: checkpoint after processing this many bytes. Must be in range [4..4096]
#define CHKPT_TAG_BYTES     (CHKPT_BYTES/16)        // size of the tags for  CHKPT_BYTES of data
#define CHKPT_SHRUNK_BYTES  426                     // for early aborts: max size of compressed stream to allow further processing ..
                                                    //      .. to disable early aborts, set CHKPT_SHRUNK_BYTES to 4096

#if CHKPT_BYTES > 4096
    #error CHKPT_BYTES must be <= 4096
#endif
#if CHKPT_BYTES < 4
    #error CHKPT_BYTES must be >= 4
#endif

.globl _WKdm_compress_new
_WKdm_compress_new:
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	subq	$(48+64), %rsp

	#define	tempTagsArray       64(%rsp)
	#define	tempLowBitsArray	72(%rsp)

    #define start_next_full_patt  80(%rsp)
    #define start_next_input_word 88(%rsp)
    #define byte_budget           96(%rsp)
    #define start_next_qp         tempQPosArray
    #define start_next_low_bits   tempLowBitsArray 
    
	#define	next_tag			%r8
	#define	next_input_word		%rdi
	#define	end_of_input		%r13
	#define	next_full_patt		%rbx
	#define	dict_location		%rcx
	#define	next_qp				%r10
    #define checkpoint          %r11
	#define	dictionary			%rsp
	#define	dest_buf			%r12
	#define	hashTable			%r14
	#define tempQPosArray		%r15
	#define	next_low_bits		%rsi
	#define	byte_count			%r9d

	movq	%rsi, %r12						// dest_buf

	movq	%rdx, tempTagsArray 			// &tempTagsArray[0]
	movq	%rdx, next_tag					// next_tag always points to the one following the current tag 

	leaq	1024(%rdx), tempQPosArray		// &tempQPosArray[0]
	movq	tempQPosArray, next_qp			// next_qp

    leaq    CHKPT_BYTES(%rdi), checkpoint   // checkpoint = src_buf + CHKPT_BYTES
	leaq	4096(%rdi), end_of_input		// end_of_input = src_buf + num_input_words
	leaq	268(%rsi), %rbx					// dest_buf + [TAGS_AREA_OFFSET + (num_input_words / 16)]*4

	movl	%ecx, byte_count
	subl	$(12+256), byte_count			// header + tags
	jle		L_budgetExhausted

                                            // NOTE: ALL THE DICTIONARY VALUES MUST BE INITIALIZED TO ZERO
                                            // THIS IS NEEDED TO EFFICIENTLY DETECT SINGLE VALUE PAGES
	// PRELOAD_DICTIONARY;
	movl	$0, 0(dictionary)
	movl	$0, 4(dictionary)
	movl	$0, 8(dictionary)
	movl	$0, 12(dictionary)
	movl	$0, 16(dictionary)
	movl	$0, 20(dictionary)
	movl	$0, 24(dictionary)
	movl	$0, 28(dictionary)
	movl	$0, 32(dictionary)
	movl	$0, 36(dictionary)
	movl	$0, 40(dictionary)
	movl	$0, 44(dictionary)
	movl	$0, 48(dictionary)
	movl	$0, 52(dictionary)
	movl	$0, 56(dictionary)
	movl	$0, 60(dictionary)

	leaq	2048(%rdx), %rax				// &tempLowBitsArray[0]
	movq	%rax, tempLowBitsArray			// save for later reference
	movq	%rax, next_low_bits				// next_low_bits	

	leaq	_hashLookupTable_new(%rip), hashTable	// hash look up table

    movq    next_full_patt, start_next_full_patt
    movq    next_input_word, start_next_input_word
    movl    %ecx, byte_budget               // save the byte budget    


	jmp		L_scan_loop

	.align 4,0x90
L_RECORD_ZERO:
	movb	$0, -1(next_tag)						// *next_tag = ZERO;
	addq	$4, next_input_word 					// next_input_word++;
	cmpq	next_input_word, checkpoint             // checkpoint time?
	je		CHECKPOINT

L_scan_loop:
	movl	(next_input_word), %edx
	incq	next_tag								// next_tag++
	testl	%edx, %edx
	je		L_RECORD_ZERO							// if (input_word==0) RECORD_ZERO
	movl	%edx, %eax								// a copy of input_word
	shrl	$10, %eax								// input_high_bits = HIGH_BITS(input_word);
	movzbl	%al, %eax								// 8-bit index to the Hash Table
	movsbq	(hashTable,%rax),%rax					// HASH_TO_DICT_BYTE_OFFSET(input_word)
	leaq	(dictionary, %rax), dict_location		// ((char*) dictionary) + HASH_TO_DICT_BYTE_OFFSET(input_word));
	movl	(dict_location), %eax					// dict_word = *dict_location;
	addq	$4, next_input_word						// next_input_word++
	cmpl	%eax, %edx								// dict_word vs input_word
	je		L_RECORD_EXACT							// if identical, RECORD_EXACT
	xorl	%edx, %eax
	shrl	$10, %eax								// HIGH_BITS(dict_word)
	je		L_RECORD_PARTIAL						// if identical, RECORD_PARTIAL

L_RECORD_MISS:
	movl	%edx, (next_full_patt)					// *next_full_patt = input_word;
	addq	$4, next_full_patt						// next_full_patt++ 
	movl	%edx, (dict_location)					// *dict_location = input_word
	movb	$2, -1(next_tag)						// *next_tag = 2 for miss
	subl	$4, byte_count							// fill in a new 4-bytes word
	jle		L_budgetExhausted
	cmpq	next_input_word, checkpoint             // checkpoint time?
	jne     L_scan_loop
	jmp	    CHECKPOINT	

L_done_search:

	// SET_QPOS_AREA_START(dest_buf,next_full_patt);
	movq	next_full_patt, %rax					// next_full_patt
	subq	dest_buf, %rax							// next_full_patt - dest_buf								
	sarq	$2, %rax								// offset in 4-bytes
	movl	%eax, %r13d								// r13d = (next_full_patt - dest_buf)
	movl	%eax, 0(dest_buf)						// dest_buf[0] = next_full_patt - dest_buf
	decq	next_tag
	cmpq	next_tag, tempTagsArray					// &tempTagsArray[0] vs next_tag
	jae		L13										// if (&tempTagsArray[0] >= next_tag), skip the following

	// boundary_tmp = WK_pack_2bits(tempTagsArray, (WK_word *) next_tag, dest_buf + HEADER_SIZE_IN_WORDS);

	movq	dest_buf, %rdi							// dest_buf
	movq	tempTagsArray, %rcx						// &tempTagsArray[0]

	.align 4,0x90
L_pack_2bits:
	movq	8(%rcx), %rax							// w3
	addq	$16, %rcx								// tempTagsArray += 16;
	shlq	$4, %rax
	addq	$4, %rdi								// dest_buf += 4;
	orq		-16(%rcx), %rax							// w3
	movq	%rax, %rdx
	shrq	$30, %rax
	orl		%edx, %eax
	cmpq	%rcx, next_tag							// cmp next_tag vs dest_buf
	movl	%eax, 8(%rdi)							// save at *(dest_buf + HEADER_SIZE_IN_WORDS)
	ja		L_pack_2bits							// if (next_tag > dest_buf) repeat L_pack_2bits

	/* Pack the queue positions into the area just after the full words. */

L13:
	mov		next_qp, %rax							// next_qp
	sub		tempQPosArray, %rax						// num_bytes_to_pack = next_qp - (char *) tempQPosArray; 
	addl	$7, %eax								// num_bytes_to_pack+7
	shrl	$3, %eax								// num_packed_words = (num_bytes_to_pack + 7) >> 3

	shll	$2, %eax								// turn into bytes
	subl	%eax, byte_count						// 
	jl		L_budgetExhausted
	shrl	$1, %eax 								// num_source_words = num_packed_words * 2;

	leaq	(tempQPosArray,%rax,4), %rcx			// endQPosArray = tempQPosArray + num_source_words
	cmpq	%rcx, next_qp							// next_qp vs endQPosArray
	jae		L16										// if (next_qp >= endQPosArray) skip the following zero paddings
	movq	%rcx, %rax
	subq	next_qp, %rax
	subl	$4, %eax
	jl		1f
	.align 4,0x90
0:	movl	$0, (next_qp)	
	addq	$4, next_qp
	subl	$4, %eax
	jge		0b
1:	testl	$2, %eax
	je		1f
	movw	$0, (next_qp)	
	addq	$2, next_qp
1:	testl	$1, %eax
	je		1f
	movb	$0, (next_qp)	
	addq	$1, next_qp
1:
L16:
	movq	next_full_patt, %rdi					// next_full_patt
	cmpq	tempQPosArray, %rcx						// endQPosArray vs tempQPosArray
	jbe		L20										// if (endQPosArray <= tempQPosArray) skip the following
	movq	tempQPosArray, %rdx						// tempQPosArray

	/* byte_count -= (rcx - tempQPosArray)/2 */

	.align 4,0x90
L_pack_4bits:
	movl	4(%rdx), %eax							// src_next[1]
	addq	$8, %rdx								// src_next += 2;
	sall	$4, %eax								// (src_next[1] << 4)
	addq	$4, %rdi								// dest_next++;
	orl		-8(%rdx), %eax							// temp = src_next[0] | (src_next[1] << 4)
	cmpq	%rdx, %rcx								// source_end vs src_next
	movl	%eax, -4(%rdi)							// dest_next[0] = temp;
	ja		L_pack_4bits							// while (src_next < source_end) repeat the loop

	// SET_LOW_BITS_AREA_START(dest_buf,boundary_tmp);
	movq	%rdi, %rax								// boundary_tmp
	subq	dest_buf, %rax							// boundary_tmp - dest_buf
	movq	%rax, %r13								// boundary_tmp - dest_buf
	shrq	$2, %r13								// boundary_tmp - dest_buf in words
L20:
	movl	%r13d, 4(dest_buf)						// dest_buf[1] = boundary_tmp - dest_buf

	movq	tempLowBitsArray, %rcx					// tempLowBitsArray
	movq	next_low_bits, %rbx						// next_low_bits
	subq	%rcx, %rbx								// next_low_bits - tempLowBitsArray (in bytes)
	sarq	$1, %rbx								// num_tenbits_to_pack (in half-words)

	#define	size	%ebx

	subl	$3, size								// pre-decrement num_tenbits_to_pack by 3
	jl		1f										// if num_tenbits_to_pack < 3, skip the following loop

	.align	4,0x90
0:
	movzwl	4(%rcx), %eax							// w2	
	addq	$6, %rcx								// next w0/w1/w2 triplet
	sall	$10, %eax								// w1 << 10
	or		-4(%rcx), %ax							// w1
	addq	$4, %rdi								// dest_buf++
	sall	$10, %eax								// w1 << 10
	or		-6(%rcx), %ax							// (w0) | (w1<<10) | (w2<<20)
	subl	$4, byte_count							// fill in a new 4-bytes word
	jle		L_budgetExhausted
	subl	$3, size								// num_tenbits_to_pack-=3
	movl	%eax, -4(%rdi)							// pack w0,w1,w2 into 1 dest_buf word
	jge		0b										// if no less than 3 elements, back to loop head

1: 	addl	$3, size								// post-increment num_tenbits_to_pack by 3
	je		3f										// if num_tenbits_to_pack is a multiple of 3, skip the following
	movzwl	(%rcx), %eax							// w0
	subl	$1, size								// num_tenbits_to_pack--
	je		2f										//
	movzwl	2(%rcx), %edx							// w1
	sall	$10, %edx								// w1 << 10
	orl		%edx, %eax								// w0 | (w1<<10)
2:
	subl	$4, byte_count							// fill in a new 4-bytes word
	jle		L_budgetExhausted
	movl	%eax, (%rdi)							// write the final dest_buf word
	addq	$4, %rdi								// dest_buf++

3:	movq	%rdi, %rax								// boundary_tmp
	subq	dest_buf, %rax							// boundary_tmp - dest_buf
	shrq	$2, %rax								// boundary_tmp - dest_buf in terms of words
	movl	%eax, 8(dest_buf)						// SET_LOW_BITS_AREA_END(dest_buf,boundary_tmp)
	shlq	$2, %rax								// boundary_tmp - dest_buf in terms of bytes

L_done:
	// restore registers and return
	addq	$(48+64), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	leave
	ret

    .align  4
L_budgetExhausted:
	mov		$-1, %rax
	jmp		L_done
	

	.align 4,0x90
L_RECORD_EXACT:
	subq	dictionary, %rcx					// dict_location - dictionary
	sarq	$2, %rcx							// divide by 4 for word offset
	movb	$3, -1(next_tag)					// *next_tag = 3 for exact
	movb	%cl, (next_qp)						// *next_qp = word offset (4-bit)
	incq	next_qp								// next_qp++
	cmpq	next_input_word, checkpoint         // checkpoint time?
	jne     L_scan_loop
	jmp	    CHECKPOINT	

	.align 4,0x90
L_RECORD_PARTIAL:
	movq	%rcx, %rax							// dict_location
	movb	$1, -1(next_tag)					// *next_tag = 1 for partial matched
	subq	dictionary, %rax					// dict_location - dictionary
	movl	%edx, (%rcx)						// *dict_location = input_word;
	sarq	$2, %rax							// offset in 32-bit word
	movb	%al, (next_qp)						// update *next_qp
	andl	$1023, %edx							// lower 10 bits
	incq	next_qp								// next_qp++
	mov		%dx, (next_low_bits)				// save next_low_bits
	addq	$2, next_low_bits					// next_low_bits++
	cmpq	next_input_word, checkpoint         // checkpoint time?
	jne     L_scan_loop

CHECKPOINT:

    cmpq	end_of_input, checkpoint            // end of buffer or compression ratio check?
    jne     L_check_compression_ratio

L_check_zero_page:
                                                // check if any dictionary misses in page
    cmpq    start_next_full_patt, next_full_patt
    jne     L_check_single_value_page

    cmpq    start_next_qp, next_qp              // check if any partial or exact dictionary matches
    jne     L_check_single_value_page

    mov     SV_RETURN, %rax                     // Magic return value
    jmp     L_done

L_check_single_value_page:

    movq    next_full_patt, %rax                // get # dictionary misses
    subq    start_next_full_patt, %rax
    shrq    $2, %rax
    
    movq    next_qp, %r11                       // get # dictionary hits (exact + partial)
    subq    start_next_qp, %r11
    
    movq    next_low_bits, %r13                 // get # dictionary partial hits
    subq    start_next_low_bits, %r13
    shrq    $1, %r13

    movq    tempTagsArray, %r14                 // get the address of the first tag

    // Single value page if one of the follwoing is true:
    //  partial == 0 AND hits == 1023 AND miss == 1 AND tag[0] == 2 (i.e. miss)
    //  partial == 1 AND hits == 1024 AND tag[0] == 1 (i.e. partial)
    //
    cmpq    $0, %r13                            // were there 0 partial hits?
    jne     1f

    cmpq    $1023, %r11                         // were there 1023 dictionary hits
    jne     1f

    cmpq    $1, %rax                            // was there exacly 1 dictionary miss?
    jne     1f 

    cmpb    $2, 0(%r14)                         // was the very 1st tag a miss?
    je      L_is_single_value_page

1:
    cmpq    $1, %r13                            // was there 1 partial hit?
    jne     L_check_mostly_zero

    cmpq    $1024, %r11                         // were there 1024 dictionary hits
    jne     L_check_mostly_zero

    cmpb    $1, 0(%r14)                         // was the very 1st tag a partial?
    jne     L_check_mostly_zero
     
L_is_single_value_page:
    
    mov     SV_RETURN, %rax                     // Magic return value
    jmp     L_done

L_check_mostly_zero:
                                                // how much space will the sparse packer take?
    addq    %r11, %rax                          // rax += (next_qp - start_next_qp)
    movq    $6, %rdx
    mulq    %rdx                                // rax *= 6 (i.e. 4 byte word + 2 byte offset)
    addq    $4, %rax                            // rax += 4 byte for header
    movq    %rax, %r11 
                                                // how much space will the defaut packer take?
    movq    next_low_bits, %rax
    subq    start_next_low_bits, %rax           // get bytes consumed by lower-10 bits
    movq    $1365, %rdx
    mulq    %rdx
    shrq    $11, %rax                           // rax = 2/3*(next_low_bits - start_next_low_bits)
    movq    next_full_patt, %rdx
    subq    start_next_full_patt, %rdx          // get bytes consumed by dictionary misses
    addq    %rdx, %rax                          // rax += (next_full_patt - start_next_full_patt)
    movq    next_qp, %rdx
    subq    start_next_qp, %rdx
    shrq    $1, %rdx                            // get bytes consumed by dictionary hits
    addq    %rdx, %rax                          // rax += (next_qp - start_next_qp)/2
    addq    $(12+256), %rax                     // rax += bytes taken by the header + tags

    cmpq    %r11, %rax                          // is default packer the better option?
    jb      L_done_search

    cmpl    byte_budget, %r11d                  // can the sparse packer fit into the given budget?
    ja      L_budgetExhausted

L_sparse_packer:

    movl    MZV_MAGIC, 0(dest_buf)              // header to indicate a sparse packer
    addq    $4, dest_buf

    movq    $0, %rdx                            // rdx = byte offset in src of non-0 word
    movq    start_next_input_word, %r8
1:
    movq    0(%r8, %rdx), %rax                  // rax = read dword
	testq	%rax, %rax                          // is dword == 0
    jne     5f
3:
    addq    $8, %rdx                            // 8 more bytes have been processed
4:
    cmpq    $4096, %rdx
    jne     1b
    movq    %r11, %rax                          // store the size of the compressed stream
    jmp     L_done

5:
    testl   %eax, %eax                          // is lower word == 0
    je      6f
    movl    %eax, 0(dest_buf)                   // store the non-0 word in the dest buffer
    mov     %dx, 4(dest_buf)                    // store the byte index
    addq    $6, dest_buf
6:
    shrq    $32, %rax                           // get the upper word into position
    testl   %eax, %eax                          // is upper word == 0
    je      3b
    addq    $4, %rdx
    movl    %eax, 0(dest_buf)                   // store the word in the dest buffer
    mov     %dx, 4(dest_buf)                    // store the byte index
    addq    $6, dest_buf
    addq    $4, %rdx
    jmp     4b

L_check_compression_ratio:

    movq    end_of_input, checkpoint            // checkpoint = end of buffer

    movq    next_low_bits, %rax
    subq    start_next_low_bits, %rax           // get bytes consumed by lower-10 bits
    movq    $1365, %rdx
    mulq    %rdx
    shrq    $11, %rax                           // rax = 2/3*(next_low_bits - start_next_low_bits)
    
    movq    next_full_patt, %rdx
    subq    start_next_full_patt, %rdx          // get bytes consumed by dictionary misses
    addq    %rdx, %rax                          // rax += (next_full_patt - start_next_full_patt)

    movq    next_qp, %rdx
    subq    start_next_qp, %rdx
    shrq    $1, %rdx
    addq    %rdx, %rax                          // rax += (next_qp - start_next_qp)/2

    addq    $CHKPT_TAG_BYTES, %rax              // rax += bytes taken by the tags
    cmpq    $CHKPT_SHRUNK_BYTES, %rax
    ja      L_budgetExhausted                   // compressed size exceeds budget
    jmp     L_scan_loop 


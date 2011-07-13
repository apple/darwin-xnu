// $Id: WKdmCompress.intel.s,v 1.1 2010/01/28 22:33:24 cclee Exp cclee $
//
// This file contains i386 and x86_64 (no SSE) optimized implementation of WKdm Compressor. The function prototype is
// 
// unsigned int WKdm_compress (WK_word* src_buf, WK_word* dest_buf, unsigned int num_input_words);
// 
// The implementation assumes the input buffer is a memory page (4096 bytes or 1024 words), or something less than 4KB.
//
// WKdm Compression algorithm is briefly stated as follows:
// 
// There is a dynamically updated dictionary of 16 words, each initialized with "1".
//
// the dictionary is indexed as follows, 
//	0, x = input_word
//  1, hash_index = (x>>10)&255
//  2, dict_location = &dictionary[hash_index]
//  3, dict_word = *dict_location
//
// Sequentially for each input word, it is classified/tagged into 4 classes
//	0 : if the input word is 0
//  1 : the higher 22 bits of the input word is identically to the higher bits from the dictionary (hash table indexed)
//  2 : the above condition (partially 22 higher bits matched) is not met, a dictionary miss condition
//  3 : the input word is exactly matched to the word from the dictionary (hash table index)
//
// after each input word is classified, each tag is represented by 2 bits. Furthermore, for each class
//	0 : no further info is needed
//  1 : the hash_index is represented by 4-bits (8 packed into a word),
//		the lower 10-bits is sent to the decompressor (3 packed into a word)
//  2 : the 32-bit word is sent to the decompressor
//  3 : the hash_index is represented by 4-bits (8 packed into a word)
//
// for classes 1 and 2, the input word is used to update the dictionary after it is classified/tagged
//
// the following implementation was started from compiling (gcc -O3) the original C code (WKdmCompress.c)
// and then subsequentially improved and documented.
// For i386, it speeds up ~ 1.5 times
// For x86_64, it speeds up ~ 1.3 times
//
// cclee, 1/28/10

#if !(defined __i386__ || defined __x86_64__)

typedef char DummyDefinition;

#else		// i386 or x86_64 architectures

#if defined	__i386__			// 32-bit implementation

	.text
	.align 4,0x90

.globl _WKdm_compress
_WKdm_compress:

	pushl	%ebp
	movl	%esp, %ebp

	pushl	%edi
	pushl	%esi
	pushl	%ebx

	// allocate stack memory for local variables

	subl	$6316, %esp

	leal	_hashLookupTable, %ebx			        // hashTable

	movl	8(%ebp), %edx					// %edx = src_buf
	movl	12(%ebp), %esi					// %esi = dest_buf
	movl	16(%ebp), %eax					// %eax = num_input_words

	leal	-1112(%ebp), %ecx				// tempTagsArray
	movl	%ecx, -6272(%ebp)				// a copy of char* next_tag = (char *) tempTagsArray;

	leal	-2136(%ebp), %ecx				// tempQPosArray
	movl	%ecx, -6264(%ebp)				// char* next_qp = (char *) tempQPosArray;
	movl	%ecx, -6252(%ebp)

	leal	(%edx,%eax,4), %ecx				// src_buf + num_input_words*4
	movl	%ecx, -6244(%ebp)				// end_of_input = src_buf + num_input_words;

	// PRELOAD_DICTIONARY;
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

	shrl	$4, %eax						// (num_input_words / 16)
	leal	16(%esi,%eax,4), %eax			// dest_buf + [TAGS_AREA_OFFSET + (num_input_words / 16)]*4
	movl	%eax, -6256(%ebp)				// next_full_patt = dest_buf + TAGS_AREA_OFFSET + (num_input_words / 16);

	leal	-6232(%ebp), %eax				// &tempLowBitsArray[0]
	movl	%eax, -6260(%ebp)				// save a copy of &tempLowBitsArray[0]
	movl	%eax, -6248(%ebp)				// save a copy of &tempLowBitsArray[0]

	cmpl	%ecx, %edx						// next_input_word (%edx) vs end_of_input (%ecx) 
	jae		L_done_search					// if (next_input_word >= end_of_input) skip the following search loop

	leal	-1111(%ebp), %esi				// &next_tag[1]
	leal	-88(%ebp), %ebp					// dictionary 

	movl	%edx, %edi						// next_input_word

	#define		next_input_word		%edi
	#define		dictionary			%ebp
	#define		next_tag			%esi

	jmp		L5

	.align 4,0x90
L_RECORD_ZERO:
	movb	$0, -1(next_tag)				// *next_tag = ZERO;
L8:
	addl	$4, next_input_word				// next_input_word++; 
	incl	next_tag						// next_tag++
	cmpl	next_input_word, 84(%esp)		// end_of_input vs next_input_word
	jbe		L_done_search					// if (next_input_word>=end_of_input), skip to L_done_search 
L5:
	movl	(next_input_word), %ecx			// input_word = *next_input_word;
	movl	%ecx, %eax						// a copy of input_word
	testl	%ecx, %ecx						// input_word
	je		L_RECORD_ZERO					// if (input_word==0) RECORD_ZERO
	shrl	$10, %eax						// input_high_bits = HIGH_BITS(input_word);
	movl	%eax, (%esp)					// save a copy of input_high_bits;
	andl	$255, %eax						// 8 bits index to Hash Table
	movsbl	(%ebx,%eax),%edx				// HASH_TO_DICT_BYTE_OFFSET(input_word)
	addl	dictionary, %edx				// ((char*) dictionary) + HASH_TO_DICT_BYTE_OFFSET(input_word));
	movl	(%edx), %eax					// dict_word = *dict_location;
	cmpl	%eax, %ecx						// cmp input_word vs dict_word
	je		L_RECORD_EXACT
	shrl	$10, %eax						// HIGH_BITS(dict_word)
	cmpl	%eax, (%esp)					// input_high_bits vs HIGH_BITS(dict_word)
	je		L_RECORD_PARTIAL				// if (input_high_bits == HIGH_BITS(dict_word)) RECORD_PARTIAL 

L_RECORD_MISS:
	movb	$2, -1(next_tag)				// *next_tag = 2 for miss
	movl	72(%esp), %eax					// next_full_patt
	movl	%ecx, (%eax)					// *next_full_patt = input_word;
	addl	$4, %eax						// next_full_patt++;
	movl	%eax, 72(%esp)					// save next_full_patt
	movl	%ecx, (%edx)					// *dict_location = input_word
	jmp		L8

	.align 4,0x90
L_RECORD_EXACT:
	movb	$3, -1(next_tag)				// *next_tag = 3 for exact
	subl	dictionary, %edx				// dict_location - dictionary 
	sarl	$2, %edx						// divide by 4 for word offset 
	movl	76(%esp), %eax					// next_qp
	movb	%dl, (%eax)						// *next_qp = word offset (4-bit)
	incl	%eax							// next_qp++
	movl	%eax, 76(%esp)					// save next_qp
	jmp		L8

L_done_search:

	// restore %ebp as normal use (was used as dictionary)
	movl	%esp, %ebp						
	addl	$6328, %ebp

	// SET_QPOS_AREA_START(dest_buf,next_full_patt);
	movl	-6256(%ebp), %edi				// next_full_patt
	subl	12(%ebp), %edi					// next_full_patt - dest_buf
	movl	%edi, %eax						// next_full_patt - dest_buf
	sarl	$2, %eax						// in 4-byte words
	movl	%eax, -6240(%ebp)				// save (next_full_patt - dest_buf) in words
	movl	12(%ebp), %edx					// dest_buf
	movl	%eax, 4(%edx)					// dest_buf[1] = next_full_patt - dest_buf

	movl	-6272(%ebp), %ecx				// &tempTagsArray[0]
	decl	next_tag
	cmpl	next_tag, %ecx					// next_tag vs &tempTagsArray[0]
	jae		L13								// if &tempTagsArray[0] >= next_tag, skip the following WK_pack_2bits

	movl	%edx, %ebx						// a copy of dest_buf

	// boundary_tmp = WK_pack_2bits(tempTagsArray, (WK_word *) next_tag, dest_buf + HEADER_SIZE_IN_WORDS);	

	.align 4,0x90
L_WK_pack_2bits:
	movl	4(%ecx), %eax					// w1
	sall	$2, %eax						// w1 << 2		
	movl	8(%ecx), %edx					// w2
	sall	$4, %edx						// w2 << 4
	orl		%edx, %eax						// (w1<<2) | (w2<<4)
	orl		(%ecx), %eax					// (w0) | (w1<<2) | (w2<<4)
	movl	12(%ecx), %edx					// w3
	sall	$6, %edx						// (w3<<6)
	orl		%edx, %eax						// (w0) | (w1<<2) | (w2<<4) | (w3<<6)
	movl	%eax, 16(%ebx)					// save at *(dest_buf + HEADER_SIZE_IN_WORDS)
	addl	$16, %ecx						// tempTagsArray += 16;
	addl	$4, %ebx						// dest_buf += 4;
	cmpl    %ecx, next_tag					// cmp next_tag vs dest_buf
	ja		L_WK_pack_2bits					// if (next_tag > dest_buf) repeat L_WK_pack_2bits

	/* Pack the queue positions into the area just after the full words. */
L13:
	movl	-6252(%ebp), %eax				// next_qp
	movl	-6264(%ebp), %ecx				// (char *) tempQPosArray
	movl	%eax, %esi						// next_qp
	subl	%ecx, %eax						// num_bytes_to_pack = next_qp - (char *) tempQPosArray;
	addl	$7, %eax						// num_bytes_to_pack + 7
	andl	$-8, %eax						// clear lower 3 bits, (num_packed_words<<3)
	addl	%eax, %ecx						// endQPosArray = tempQPosArray + num_source_words;
	cmpl	%ecx, %esi						// next_qp vs endQPosArray
	jae		L16
	.align 4,0x90
L30:
	movb	$0, (%esi)						// *next_qp = 0;
	incl	%esi							// next_qp++
	cmpl	%ecx, %esi						// next_qp vs endQPosArray
	jne		L30								// 

L16:
	movl	-6256(%ebp), %ebx				// next_full_patt
	cmpl	-6264(%ebp), %ecx				// endQPosArray vs tempQPosArray
	jbe		L20								// if (endQPosArray<=tempQPosArray) skip L_WK_pack_4bits
	movl	-6264(%ebp), %edx				// tempQPosArray


	// boundary_tmp = WK_pack_4bits(tempQPosArray, endQPosArray, next_full_patt);

	.align 4,0x90
L21:
	movl	4(%edx), %eax					// src_next[1]
	sall	$4, %eax						// (src_next[1] << 4)
	orl		(%edx), %eax					// temp = src_next[0] | (src_next[1] << 4)
	movl	%eax, (%ebx)					// dest_next[0] = temp; 
	addl	$4, %ebx						// dest_next++;
	addl	$8, %edx						// src_next += 2;
	cmpl	%edx, %ecx						// source_end vs src_next
	ja		L21								// while (src_next < source_end) repeat the loop

	movl	%ebx, %edi						// boundary_tmp

	subl	12(%ebp), %edi					// boundary_tmp - dest_buf
	movl	%edi, %eax						// boundary_tmp - dest_buf
	sarl	$2, %eax						// translate into word offset

	movl	%eax, -6240(%ebp)				// save (next_full_patt - dest_buf) in words 

L20:
	// SET_LOW_BITS_AREA_START(dest_buf,boundary_tmp);
	movl	-6240(%ebp), %ecx				// boundary_tmp - dest_buf 
	movl	12(%ebp), %edx					// dest_buf
	movl	%ecx, 8(%edx)					// dest_buf[2] = boundary_tmp - dest_buf

	movl	-6260(%ebp), %ecx				// tempLowBitsArray
	movl	-6248(%ebp), %edx				// next_low_bits 
	subl	%ecx, %edx						// next_low_bits - tempLowBitsArray
	sarl	$2, %edx						// num_tenbits_to_pack 

	subl	$3, %edx						// pre-decrement num_tenbits_to_pack by 3
	jl		1f								// if num_tenbits_to_pack < 3, skip the following loop
	.align	4,0x90
0:
	movl	4(%ecx), %eax					// w1
	sall	$10, %eax						// w1<<10
	movl	8(%ecx), %esi					// w2
	sall	$20, %esi						// w2<<20
	orl		%esi, %eax						// (w1<<10) | (w2<<20)
	orl		(%ecx), %eax					// (w0) | (w1<<10) | (w2<<20)
	movl	%eax, (%ebx)					// pack w0,w1,w2 into 1 dest_buf word
	addl	$4, %ebx						// dest_buf++
	addl	$12, %ecx						// next w0/w1/w2 triplet
	subl	$3, %edx						// num_tenbits_to_pack-=3 
	jge		0b								// if no less than 3 elements, back to loop head

1:	addl	$3, %edx						// post-increment num_tenbits_to_pack by 3
	je		3f								// if num_tenbits_to_pack is a multiple of 3, skip the following
	movl	(%ecx), %eax					// w0
	subl	$1, %edx						// num_tenbits_to_pack --
	je		2f								// 
	movl    4(%ecx), %esi					// w1
	sall	$10, %esi						// w1<<10
	orl		%esi, %eax
2:
	movl	%eax, (%ebx)					// write the final dest_buf word
	addl	$4, %ebx						// dest_buf++
3:
	movl	%ebx, %eax						// boundary_tmp
	subl	12(%ebp), %eax					// boundary_tmp - dest_buf
	sarl	$2, %eax						// boundary_tmp - dest_buf in terms of words
	movl	12(%ebp), %esi					// dest_buf
	movl	%eax, 12(%esi)					// SET_LOW_BITS_AREA_END(dest_buf,boundary_tmp);
	sall	$2, %eax						// boundary_tmp - dest_buf in terms of bytes
	addl	$6316, %esp						// pop out stack memory
	popl	%ebx
	popl	%esi
	popl	%edi
	leave
	ret

	.align 4,0x90

L_RECORD_PARTIAL:
	movb	$1, -1(next_tag)						// *next_tag = 1 for partial matched
	movl	%edx, %eax								// dict_location
	subl	dictionary, %eax						// %eax = dict_location - dictionary
	movl	%ecx, (%edx)							// *dict_location = input_word;
	sarl	$2, %eax								// offset in 32-bit word
	movl	76(%esp), %edx							// next_qp
	movb	%al, (%edx)								// update *next_qp
	incl	%edx									// next_qp++
	movl	%edx, 76(%esp)							// save next_qp
	movl	%ecx, %eax								// a copy of input_word
	andl	$1023, %eax								// lower 10 bits
	movl	80(%esp), %edx							// next_low_bits
	movl	%eax, (%edx)							// EMIT_WORD(next_low_bits,(low_bits_pattern))
	addl	$4, %edx								// next_low_bits++
	movl	%edx, 80(%esp)							// save next_low_bits
	jmp		L8

#endif		// i386 architectures

#if defined __x86_64__			// 64-bit implementation	
	.text
	.align 4,0x90

.globl _WKdm_compress
_WKdm_compress:
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	subq	$6112, %rsp

	#define	tempTagsArray	-6264(%rbp)
	#define	tempLowBitsArray	-6272(%rbp)
	#define	next_tag			%r8
	#define	next_input_word		%rdi
	#define	end_of_input		%r13
	#define	next_full_patt		%rbx
	#define	dict_location		%rcx
	#define	next_qp				%r10
	#define	dictionary			%r11
	#define	dest_buf			%r12
	#define	hashTable			%r14
	#define tempQPosArray		%r15
	#define	next_low_bits		%rsi

	movq	%rsi, %r12						// dest_buf

	leaq	-1136(%rbp), %rax				// &tempTagsArray[0]
	movq	%rax, tempTagsArray 
	leaq	1(%rax), next_tag				// next_tag always points to the one following the current tag 

	leaq	-2160(%rbp), %r15				// &tempQPosArray[0]
	movq	%r15, next_qp					// next_qp

	mov		%edx, %eax						// num_input_words
	leaq	(%rdi,%rax,4), end_of_input		// end_of_input = src_buf + num_input_words

	// PRELOAD_DICTIONARY;
	movl	$1, -112(%rbp)
	movl	$1, -108(%rbp)
	movl	$1, -104(%rbp)
	movl	$1, -100(%rbp)
	movl	$1, -96(%rbp)
	movl	$1, -92(%rbp)
	movl	$1, -88(%rbp)
	movl	$1, -84(%rbp)
	movl	$1, -80(%rbp)
	movl	$1, -76(%rbp)
	movl	$1, -72(%rbp)
	movl	$1, -68(%rbp)
	movl	$1, -64(%rbp)
	movl	$1, -60(%rbp)
	movl	$1, -56(%rbp)
	movl	$1, -52(%rbp)

	shrl	$4, %edx						// (num_input_words / 16)
	mov		%edx, %edx						// sign extension into quad word
	leaq	16(%rsi,%rdx,4), %rbx			// dest_buf + [TAGS_AREA_OFFSET + (num_input_words / 16)]*4

	leaq	-6256(%rbp), %rax				// &tempLowBitsArray[0]
	movq	%rax, tempLowBitsArray			// save for later reference
	movq	%rax, next_low_bits				// next_low_bits	

	cmpq	end_of_input, next_input_word	// next_input_word vs end_of_input
	jae		L_done_search					// if (next_input_word>=end_of_input) no work to do in search
	leaq	-112(%rbp), dictionary			// dictionary
	leaq	_hashLookupTable(%rip), hashTable	// hash look up table
	jmp	L5

	.align 4,0x90
L_RECORD_ZERO:
	movb	$0, -1(next_tag)						// *next_tag = ZERO;
L8:
	addq	$4, next_input_word 					// next_input_word++;
	incq	next_tag								// next_tag++
	cmpq	next_input_word, end_of_input 			// end_of_input vs next_input_word
	jbe		L_done_search
L5:
	movl	(next_input_word), %edx					// input_word = *next_input_word;
	movl	%edx, %r9d								// a copy of input_word
	testl	%edx, %edx								// input_word
	je		L_RECORD_ZERO							// if (input_word==0) RECORD_ZERO
	shrl	$10, %r9d								// input_high_bits = HIGH_BITS(input_word);
	movzbl	%r9b, %eax								// 8-bit index to the Hash Table
	movsbq	(hashTable,%rax),%rax					// HASH_TO_DICT_BYTE_OFFSET(input_word)
	leaq	(dictionary, %rax), dict_location		// ((char*) dictionary) + HASH_TO_DICT_BYTE_OFFSET(input_word));
	movl	(dict_location), %eax					// dict_word = *dict_location;
	cmpl	%eax, %edx								// dict_word vs input_word
	je		L_RECORD_EXACT							// if identical, RECORD_EXACT
	shrl	$10, %eax								// HIGH_BITS(dict_word)
	cmpl	%eax, %r9d								// input_high_bits vs HIGH_BITS(dict_word)
	je		L_RECORD_PARTIAL						// if identical, RECORD_PARTIAL

L_RECORD_MISS:
	movb	$2, -1(next_tag)						// *next_tag = 2 for miss
	movl	%edx, (next_full_patt)					// *next_full_patt = input_word;
	addq	$4, next_full_patt						// next_full_patt++ 
	movl	%edx, (dict_location)					// *dict_location = input_word
	addq	$4, next_input_word						// next_input_word++
	incq	next_tag								// next_tag++
	cmpq	next_input_word, end_of_input			// end_of_input vs next_input_word	
	ja		L5										// if (end_of_input>next_input_word) repeat from L5

L_done_search:

	// SET_QPOS_AREA_START(dest_buf,next_full_patt);
	//movq	next_full_patt, %r11					// next_full_patt
	movq	next_full_patt, %rax					// next_full_patt
	subq	dest_buf, %rax							// next_full_patt - dest_buf								
	sarq	$2, %rax								// offset in 4-bytes
	movl	%eax, %r13d								// r13d = (next_full_patt - dest_buf)
	movl	%eax, 4(dest_buf)						// dest_buf[1] = next_full_patt - dest_buf

	decq	next_tag
	cmpq	next_tag, tempTagsArray					// &tempTagsArray[0] vs next_tag
	jae		L13										// if (&tempTagsArray[0] >= next_tag), skip the following

	// boundary_tmp = WK_pack_2bits(tempTagsArray, (WK_word *) next_tag, dest_buf + HEADER_SIZE_IN_WORDS);

	movq	dest_buf, %rdi							// dest_buf
	movq	tempTagsArray, %rcx						// &tempTagsArray[0]

	.align 4,0x90
L_pack_2bits:
	movl	4(%rcx), %eax							// w1
	sall	$2, %eax								// w1 << 2
	movl	8(%rcx), %edx							// w2
	sall	$4, %edx								// w2 << 4
	orl		%edx, %eax								// (w1<<2) | (w2<<4)
	orl		(%rcx), %eax							// (w0) | (w1<<2) | (w2<<4)
	movl	12(%rcx), %edx							// w3
	sall	$6, %edx								// w3 << 6
	orl		%edx, %eax								// (w0) | (w1<<2) | (w2<<4) | (w3<<6)
	movl	%eax, 16(%rdi)							// save at *(dest_buf + HEADER_SIZE_IN_WORDS)
	addq	$16, %rcx								// tempTagsArray += 16;
	addq	$4, %rdi								// dest_buf += 4;
	cmpq	%rcx, next_tag							// cmp next_tag vs dest_buf
	ja		L_pack_2bits							// if (next_tag > dest_buf) repeat L_pack_2bits

	/* Pack the queue positions into the area just after the full words. */

L13:
	movl	%r10d, %eax								// next_qp
	subl	%r15d, %eax								// num_bytes_to_pack = next_qp - (char *) tempQPosArray; 
	addl	$7, %eax								// num_bytes_to_pack+7
	shrl	$3, %eax								// num_packed_words = (num_bytes_to_pack + 7) >> 3
	addl	%eax, %eax								// num_source_words = num_packed_words * 2;
	mov		%eax, %eax
	leaq	(tempQPosArray,%rax,4), %rcx			// endQPosArray = tempQPosArray + num_source_words
	cmpq	%rcx, %r10								// next_qp vs endQPosArray
	jae		L16										// if (next_qp >= endQPosArray) skip the following zero paddings
	.align 4,0x90
L30:
	movb	$0, (next_qp)							// *next_qp = 0
	incq	next_qp									// next_qp++							
	cmpq	%rcx, next_qp							// next_qp vs endQPosArray								
	jne		L30										// repeat while next_qp < endQPosArray
L16:
	movq	%rbx, %rdi								// next_full_patt
	cmpq	tempQPosArray, %rcx						// endQPosArray vs tempQPosArray
	jbe		L20										// if (endQPosArray <= tempQPosArray) skip the following
	movq	tempQPosArray, %rdx						// tempQPosArray

	.align 4,0x90
L_pack_4bits:
	movl	4(%rdx), %eax							// src_next[1]
	sall	$4, %eax								// (src_next[1] << 4)
	orl		(%rdx), %eax							// temp = src_next[0] | (src_next[1] << 4)
	movl	%eax, (%rdi)							// dest_next[0] = temp;
	addq	$4, %rdi								// dest_next++;
	addq	$8, %rdx								// src_next += 2;
	cmpq	%rdx, %rcx								// source_end vs src_next
	ja		L_pack_4bits							// while (src_next < source_end) repeat the loop

	// SET_LOW_BITS_AREA_START(dest_buf,boundary_tmp);
	//movq	%rdi, %r11								// boundary_tmp
	movq	%rdi, %rax								// boundary_tmp
	subq	dest_buf, %rax							// boundary_tmp - dest_buf
	movq	%rax, %r13								// boundary_tmp - dest_buf
	shrq	$2, %r13								// boundary_tmp - dest_buf in words
L20:
	movl	%r13d, 8(dest_buf)						// dest_buf[2] = boundary_tmp - dest_buf

	movq	tempLowBitsArray, %rcx					// tempLowBitsArray
	movq	next_low_bits, %rbx						// next_low_bits
	subq	%rcx, %rbx								// next_low_bits - tempLowBitsArray (in bytes)
	sarq	$2, %rbx								// num_tenbits_to_pack (in words)

	#define	size	%ebx

	subl	$3, size								// pre-decrement num_tenbits_to_pack by 3
	jl		1f										// if num_tenbits_to_pack < 3, skip the following loop

	.align	4,0x90
0:
	movl	4(%rcx), %eax							// w1
	sall	$10, %eax								// w1 << 10
	movl	8(%rcx), %edx							// w2	
	sall	$20, %edx								// w2 << 20
	orl		%edx, %eax								// (w1<<10) | (w2<<20)
	orl		(%rcx), %eax							// (w0) | (w1<<10) | (w2<<20)
	movl	%eax, (%rdi)							// pack w0,w1,w2 into 1 dest_buf word
	addq	$4, %rdi								// dest_buf++
	addq	$12, %rcx								// next w0/w1/w2 triplet
	subl	$3, size								// num_tenbits_to_pack-=3
	jge		0b										// if no less than 3 elements, back to loop head

1: 	addl	$3, size								// post-increment num_tenbits_to_pack by 3
	je		3f										// if num_tenbits_to_pack is a multiple of 3, skip the following
	movl	(%rcx), %eax							// w0
	subl	$1, size								// num_tenbits_to_pack--
	je		2f										//
	movl	4(%rcx), %edx							// w1
	sall	$10, %edx								// w1 << 10
	orl		%edx, %eax								// w0 | (w1<<10)

2:	movl	%eax, (%rdi)							// write the final dest_buf word
	addq	$4, %rdi								// dest_buf++

3:	movq	%rdi, %rax								// boundary_tmp
	subq	dest_buf, %rax							// boundary_tmp - dest_buf
	shrq	$2, %rax								// boundary_tmp - dest_buf in terms of words
	movl	%eax, 12(dest_buf)						// SET_LOW_BITS_AREA_END(dest_buf,boundary_tmp)
	shlq	$2, %rax								// boundary_tmp - dest_buf in terms of bytes

	// restore registers and return
	addq	$6112, %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	leave
	ret

	.align 4,0x90
L_RECORD_EXACT:
	movb	$3, -1(next_tag)					// *next_tag = 3 for exact
	subq	dictionary, %rcx					// dict_location - dictionary
	sarq	$2, %rcx							// divide by 4 for word offset
	movb	%cl, (next_qp)						// *next_qp = word offset (4-bit)
	incq	next_qp								// next_qp++
	jmp		L8

	.align 4,0x90
L_RECORD_PARTIAL:
	movb	$1, -1(next_tag)					// *next_tag = 1 for partial matched
	movq	%rcx, %rax							// dict_location
	subq	dictionary, %rax					// dict_location - dictionary
	movl	%edx, (%rcx)						// *dict_location = input_word;
	sarq	$2, %rax							// offset in 32-bit word
	movb	%al, (next_qp)						// update *next_qp
	incq	next_qp								// next_qp++
	andl	$1023, %edx							// lower 10 bits
	movl	%edx, (next_low_bits)				// save next_low_bits
	addq	$4, next_low_bits					// next_low_bits++
	jmp	L8

	// for some reason, keeping the following never executed code yields a better performance
L41:
	leaq	-6256(%rbp), %rax
	movq	%rax, -6272(%rbp)
	movq	%rax, %rsi
	jmp		L_done_search
#endif		// x86_64 architectures
#endif		// i386 or x86_64 architectures

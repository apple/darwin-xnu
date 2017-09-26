/*
 * Copyright (c) 2000-2014 Apple Inc. All rights reserved.
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
 This file contains arm64 hand optimized implementation of WKdm memory page compressor. 

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

	Now since we are given a byte budget for this compressor, we can monitor the byte (or bit) usage on the fly in the scanning and tagging pass.

	byte_count -= 12 + 256;		// bit budget minus header and tags

	whenever an input word is classified as class

		2 : byte_count -= 4;

	the compress function can early exit (return -1) should the page can not be compressed with the given byte budget (i.e., byte_count <= 0).

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

 	cclee, 11/9/12

    Added zero page, single value page, sparse page, early abort optimizations
    rsrini, 09/14/14
*/

#define PAGES_SIZE_IN_KBYTES    16 

#ifndef PAGES_SIZE_IN_KBYTES    
#define PAGES_SIZE_IN_KBYTES    4
#endif

#if !((PAGES_SIZE_IN_KBYTES==4) || (PAGES_SIZE_IN_KBYTES==16))
#error "Only PAGES_SIZE_IN_KBYTES = 4 or 16 is supported"
#endif


	.text
	.align 4

/*
	int WKdm_compress (WK_word* src_buf, WK_word* dest_buf, WK_word* scratch, unsigned int bytes_budget);
*/
 
.globl _WKdm_compress_16k
_WKdm_compress_16k:

/*
	 -------------------------       symbolizing register use          -----------------------------------
*/
	#define	src_buf				x0
	#define	next_input_word		x0
	#define	dest_buf			x1
	#define	scratch				x2
	#define	byte_count			x3
	#define	next_tag			x4
	#define	tempTagsArray		x2		// scratch
	#define	dictionary			x5
	#define	remaining			x6
	#define	next_full_patt		x7
	#define	dict_location		x8
	#define	wdict_location		w8
	#define	next_qp				x9
	#define	hashTable			x10
	#define tempQPosArray		x11
	#define	next_low_bits		x12

/*
	this arm64 assembly code is ported from x86_64 assembly code, 
	therefore need such symbolization to quickly reuse the x86_64 assembly code 
	for these intermediate/temporary register use 
*/
	#define	rax					x13
	#define	eax					w13
	#define	rcx					x14
	#define	ecx					w14
	#define	rdx					x15
	#define	edx					w15
	#define	rdi					x0			/* after some point, x0/rdi becomes free other usage */	


/* 
		-------------------------    scratch  memory  --------------------------------------

	need 16*4 (dictionary) + 256*4 (tempTagsArray) + 256*4 (tempQPosArray) + 1024*4 (tempLowBitsArray)
	total 6208 bytes
	[sp,#0]         : dictionary
	[scratch,#0]    : tempTagsArray
	[scratch,#1024] : tempQPosArray
	[scratch,#2048] : tempLowBitsArray
*/

#define	scale	(PAGES_SIZE_IN_KBYTES/4)

#define SV_RETURN           0                       // return value when SV, ZV page is found
#define MZV_MAGIC           17185                   // magic value used to identify MZV page encoding
#define CHKPT_BYTES         416                     // for early aborts: checkpoint after processing this many bytes. Must be in range [4..4096]
#define CHKPT_WORDS         (CHKPT_BYTES/4)         // checkpoint bytes in words
#define CHKPT_TAG_BYTES     (CHKPT_BYTES/16)        // size of the tags for  CHKPT_BYTES of data
#define CHKPT_SHRUNK_BYTES  426                     // for early aborts: max size of compressed stream to allow further processing ..
                                                    //      .. to disable early aborts, set CHKPT_SHRUNK_BYTES to 4096
#if CHKPT_BYTES > 4096
    #error CHKPT_BYTES must be <= 4096
#endif
#if CHKPT_BYTES < 4
    #error CHKPT_BYTES must be >= 4
#endif

#if KERNEL
    sub     sp, sp, #64
    st1.4s  {v0,v1,v2,v3},[sp]
#endif

    sub     sp, sp, #64					// allocate for dictionary
	mov		dictionary, sp				// use x5 to point to sp, so we can use sub xd, xn, sp

    sub     sp, sp, #64                 // allocate space for saving callee-saved registers
	mov		x15, sp
    stp     x20, x21, [x15, #0]         // save x20, x21
    stp     x22, x23, [x15, #16]        // save x22, x23
    stp     x24, x25, [x15, #32]        // save x24, x25
    stp     x26, x27, [x15, #48]        // save x26, x27

/*
		-------  entwined statck space allocation, registers set up, and PRELOAD_DICTIONARY -------------------
*/

                                            // NOTE: ALL THE DICTIONARY VALUES MUST BE INITIALIZED TO ZERO
                                            // THIS IS NEEDED TO EFFICIENTLY DETECT SINGLE VALUE PAGES
	mov		next_tag, tempTagsArray			// &tempTagsArray[0]
	add		next_qp, scratch, #(1024*scale)	// next_qp
	mov		remaining, #(CHKPT_WORDS*scale) // remaining input words .. initially set to checkpoint
	add		next_full_patt, dest_buf, #(12+256*scale) 	// dest_buf + [TAGS_AREA_OFFSET + (num_input_words / 16)]*4
	sub		byte_count, byte_count, #(12+256*scale)	// bit_count - header - tags
	add		next_low_bits, scratch, #(2048*scale)	// &tempLowBitsArray[0]
	stp		xzr, xzr, [dictionary, #0]		// initialize dictionary
	adrp    hashTable, _hashLookupTable@GOTPAGE
	stp		xzr, xzr, [dictionary, #16]		// initialize dictionary
	stp		xzr, xzr, [dictionary, #32]		// initialize dictionary
    ldr 	hashTable, [hashTable, _hashLookupTable@GOTPAGEOFF]
	stp		xzr, xzr, [dictionary, #48]		// initialize dictionary

#define EARLYCHECK              0
#define NORMAL                  1

#define mode                    w20
#define start_next_full_patt    x21
#define start_next_input_word   x22
#define start_next_low_bits     x23
#define r11                     x24
#define r13                     x25
#define byte_budget             x26
#define start_next_qp           tempQPosArray

	add		tempQPosArray, scratch, #(1024*scale)	    // &tempQPosArray[0]
    mov     mode, EARLYCHECK                            // indicate we are yet to evaluate the early aborts
    mov     start_next_full_patt, next_full_patt        // remember the start of next_full_patt
    mov     start_next_input_word, next_input_word      // remember the start of next_input_word
    mov     start_next_low_bits, next_low_bits          // remember the start of next_low_bit
    add     byte_budget, byte_count, #(12+256*scale)    // remember the byte budget

	b		L_loop

	.align	4, 0x90

	/* we've just detected a zero input word in edx */
L_RECORD_ZERO:
	strb	edx, [next_tag], #1				// *next_tag++ = ZERO; edx is used as input word, and if we are here edx = 0
	subs	remaining, remaining, #1		// remaing--;
	b.le	CHECKPOINT   					// if remaining = 0, break

	/* --------------    scan/tag pass loop -------------------------  */
L_loop:

	/* load new input word to edx */
	ldr		edx, [next_input_word], #4
	cbz		edx, L_RECORD_ZERO							// if (input_word==0) RECORD_ZERO

	/*
		now the input word edx is nonzero, we next find the corresponding dictionary word (eax) and dict_location
	*/
	ubfm	eax, edx, #10, #17
	ldrb	wdict_location, [hashTable, rax]		// HASH_TO_DICT_BYTE_OFFSET(input_word)
	ldr		eax, [dictionary, dict_location]		// dict_word = *dict_location;

	/* detect whether we match input to its corresponding dictionary word */
	eor		eax, eax, edx							// dict_word vs input_word
	cbz		eax, L_RECORD_EXACT						// if identical, RECORD_EXACT
	lsr		eax, eax, #10							// HIGH_BITS(dict_word^input_word)
	cbz		eax, L_RECORD_PARTIAL					// if identical, RECORD_PARTIAL

L_RECORD_MISS:
/*
	if we are here, the input word can not be derived from the dictionary, 
	we write the input word as a new word, 
	and update the dictionary with this new word
*/
	subs	byte_count, byte_count, #4				// byte_count -= 4
	b.le	L_budgetExhausted						// return -1 to signal this page is not compressable
	str		edx, [next_full_patt], #4				// *next_full_patt++ = input_word;
	mov		eax, #2									// tag for MISS
	subs	remaining, remaining, #1				// remaing--;
	str		edx, [dictionary, dict_location]		// *dict_location = input_word
	strb	eax, [next_tag], #1						// *next_tag++ = 2 for miss
	b.gt	L_loop									// // if remaining > 0, repeat
    b       CHECKPOINT

L_done_search:

	// SET_QPOS_AREA_START(dest_buf,next_full_patt);
	/* 1st word in dest_buf header = 4-byte offset (from start) of end of new word section */

	sub		rax, next_full_patt, dest_buf			// next_full_patt - dest_buf								
	lsr		eax, eax, #2							// offset in 4-bytes			
	str		eax, [dest_buf]							// dest_buf[0] = next_full_patt - dest_buf

	/* --------------------------     packing 1024 tags into 256 bytes ----------------------------------------*/
	// boundary_tmp = WK_pack_2bits(tempTagsArray, (WK_word *) next_tag, dest_buf + HEADER_SIZE_IN_WORDS);

	add		rdi, dest_buf, #12						// dest_buf
	mov		rcx, tempTagsArray						// &tempTagsArray[0]

L_pack_2bits:
	ld1.2s  {v0,v1,v2,v3},[rcx],#32

	shl.2d	v1,v1,#4
	shl.2d	v3,v3,#4

	orr.8b	v0, v0, v1
	orr.8b	v2, v2, v3

	ushr.2d	v1, v0, #30
	ushr.2d	v3, v2, #30

	orr.8b	v0, v0, v1
	orr.8b	v2, v2, v3

	zip1.2s	v0, v0, v2
	st1.2s  {v0},[rdi],#8
	cmp		next_tag, rcx
	b.hi	L_pack_2bits	

	/* ---------------------------------      packing 4-bits dict indices into dest_buf ----------------------------------   */

	/* 1st, round up number of 4-bits dict_indices to a multiple of 8 and fill in 0 if needed */
	sub		rax, next_qp, tempQPosArray				// eax = num_bytes_to_pack = next_qp - (char *) tempQPosArray; 
	add		eax, eax, #7							// num_bytes_to_pack+7
	lsr		eax, eax, #3							// num_packed_words = (num_bytes_to_pack + 7) >> 3
	add		rcx, tempQPosArray, rax, lsl #3			// endQPosArray = tempQPosArray + 2*num_source_words
	lsl		rax, rax, #2
	subs	byte_count, byte_count, rax
	b.lt	L_budgetExhausted	

	cmp		rcx, next_qp							// endQPosArray vs next_qp
	b.ls	2f 										// if (next_qp >= endQPosArray) skip the following zero paddings
	sub		rax, rcx, next_qp
	mov		edx, #0
	tst		eax, #4
	b.eq	1f
	str		edx, [next_qp], #4
1:	tst		eax, #2
	b.eq	1f
	strh	edx, [next_qp], #2
1:	tst		eax, #1
	b.eq	2f
	strb	edx, [next_qp], #1
2:
	mov		rdi, next_full_patt						// next_full_patt
	cmp		rcx, tempQPosArray						// endQPosArray vs tempQPosArray
	ldr		eax, [dest_buf] 
	b.ls	L20										// if (endQPosArray <= tempQPosArray) skip the following
	mov		rdx, tempQPosArray						// tempQPosArray

	/* packing 4-bits dict indices into dest_buf */
L_pack_4bits:
	ldr		rax, [rdx], #8							// src_next[1]:src_next[0]
	orr		rax, rax, rax, lsr #28					// eax = src_next[0] | (src_next[1] << 4)
	cmp		rcx, rdx								// source_end vs src_next
	str		eax, [rdi], #4							// *dest_next++ = temp;
	b.hi	L_pack_4bits							// while (src_next < source_end) repeat the loop

	// SET_LOW_BITS_AREA_START(dest_buf,boundary_tmp);
	sub		rax, rdi, dest_buf						// boundary_tmp - dest_buf
	lsr		eax, eax, #2							// boundary_tmp - dest_buf in words
L20:
	str		eax, [dest_buf,#4]						// dest_buf[1] = boundary_tmp - dest_buf



	/*  --------------------------- packing 3 10-bits low bits into a 32-bit word in dest_buf[]   ----------------------------------------- */

	add		rcx, scratch, #(2048*scale)				// tempLowBitsArray
    sub		rdx, next_low_bits, rcx					// next_low_bits - tempLowBitsArray (in bytes)
	lsr		rdx, rdx, #1							// num_tenbits_to_pack (in half-words)
	subs	edx, edx, #3							// pre-decrement num_tenbits_to_pack by 3
	b.lt	1f										// if num_tenbits_to_pack < 3, skip the following loop
0:
	subs	byte_count, byte_count, #4				// byte_count -= 4
	b.le	L_budgetExhausted						// return -1 to signal this page is not compressable
	subs	edx, edx, #3							// num_tenbits_to_pack-=3
	ldr		rax, [rcx], #6
	bfm		rax, rax, #58, #9						// pack 1st toward 2nd
	bfm		rax, rax, #58, #25						// pack 1st/2nd toward 3rd
	lsr		rax, rax, #12	
	str		eax, [rdi], #4							// pack w0,w1,w2 into 1 dest_buf word
	b.ge	0b										// if no less than 3 elements, back to loop head

1: 	adds	edx, edx, #3							// post-increment num_tenbits_to_pack by 3
	b.eq	3f										// if num_tenbits_to_pack is a multiple of 3, skip the following
	subs	byte_count, byte_count, #4				// byte_count -= 4
	b.le	L_budgetExhausted						// return -1 to signal this page is not compressable
	ldrh	eax,[rcx]								// w0
	subs	edx, edx, #1							// num_tenbits_to_pack--
	b.eq	2f										//
	ldrh	edx, [rcx, #2]							// w1
	orr		eax, eax, edx, lsl #10					// w0 | (w1<<10)

2:	str		eax, [rdi], #4							// write the final dest_buf word

3:	sub		rax, rdi, dest_buf						// boundary_tmp - dest_buf
	lsr		eax, eax, #2							// boundary_tmp - dest_buf in terms of words
	str		eax, [dest_buf, #8]						// SET_LOW_BITS_AREA_END(dest_buf,boundary_tmp)
	lsl		w0, eax, #2								// boundary_tmp - dest_buf in terms of bytes

L_done:

	// restore registers and return
	mov		x15, sp
    ldp     x20, x21, [x15, #0]             // restore x20, x21
    ldp     x22, x23, [x15, #16]            // restore x22, x23
    ldp     x24, x25, [x15, #32]            // restore x24, x25
    ldp     x26, x27, [x15, #48]            // restore x26, x27
    add     sp, sp, #128					// deallocate for dictionary + saved register space

#if KERNEL
	ld1.4s  {v0,v1,v2,v3},[sp],#64
#endif
	ret		lr

    .align  4
L_budgetExhausted:
    mov     x0, #-1
    b       L_done


	.align 4,0x90
L_RECORD_EXACT:
/*
		we have an exact match of the input word to its corresponding dictionary word
		write tag/dict_index to the temorary buffers		
*/
	mov		eax, #3
	lsr		w14, wdict_location, #2				// divide by 4 for word offset
	subs	remaining, remaining, #1			// remaing--;
	strb	eax, [next_tag], #1					// *next_tag++ = 3 for exact
	strb	w14, [next_qp], #1					// *next_qp = word offset (4-bit)
	b.gt	L_loop
	b		CHECKPOINT   						// if remaining = 0, break

	.align 4,0x90
L_RECORD_PARTIAL:
/*
		we have a partial (high 22-bits) match of the input word to its corresponding dictionary word
		write tag/dict_index/low 10 bits to the temorary buffers		
*/
	mov		ecx, #1
	strb	ecx, [next_tag], #1					// *next_tag++ = 1 for partial matched
	str		edx, [dictionary, dict_location]	// *dict_location = input_word;
	subs	remaining, remaining, #1			// remaing--;
	lsr		eax, wdict_location, #2				// offset in 32-bit word
	and		edx, edx, #1023						// lower 10 bits
	strb	eax, [next_qp], #1					// update *next_qp++
	strh	edx, [next_low_bits], #2			// save next_low_bits++
	b.gt	L_loop

CHECKPOINT:

    cbz     mode, L_check_compression_ratio             // if this this an early abort check..
    
L_check_zero_page:

    cmp     start_next_full_patt, next_full_patt        // check if any dictionary misses in page
    b.ne    L_check_single_value_page

    cmp     start_next_qp, next_qp                      // check if any partial or exact dictionary matches
    b.ne    L_check_single_value_page

    mov     x0, #SV_RETURN                              // Magic return value
    b       L_done

L_check_single_value_page:

    sub     rax, next_full_patt, start_next_full_patt   // get # dictionary misses
    lsr     rax, rax, #2

    sub     r11, next_qp, start_next_qp                 // get # dictionary hits (exact + partial)
    
    sub     r13, next_low_bits, start_next_low_bits     // get # dictionary partial hits
    lsr     r13, r13, #1

    // Single value page if one of the follwoing is true:
    //  partial == 0 AND hits == 1023(for 4K page) AND miss == 1 AND tag[0] == 2 (i.e. miss)
    //  partial == 1 AND hits == 1024(for 4K page) AND tag[0] == 1 (i.e. partial)
    //
    cbnz    r13, 1f                                     // were there 0 partial hits?

    cmp     r11, #(256*PAGES_SIZE_IN_KBYTES - 1)        // were there 1023 dictionary hits
    b.ne    1f
    
    cmp     rax, #1                                     // was there exacly 1 dictionary miss?
    b.ne    1f
    
    ldrb    edx, [tempTagsArray]                        // read the very 1st tag
    cmp     edx, #2                                     // was the very 1st tag a miss?
    b.eq    L_is_single_value_page

1:
    cmp     r13, #1                                     // was there 1 partial hit?
    b.ne    L_check_mostly_zero

    cmp     r11, #(256*PAGES_SIZE_IN_KBYTES)           // were there 1024 dictionary hits
    b.ne    L_check_mostly_zero

    ldrb    edx, [tempTagsArray]                        // read the very 1st tag
    cmp     edx, #1                                     // was the very 1st tag a partial?
    b.ne    L_check_mostly_zero

L_is_single_value_page:

    mov     x0, #SV_RETURN                              // Magic return value
    b       L_done

L_check_mostly_zero:
                                                        // how much space will the sparse packer take?
    add     rax, rax, r11                               // rax += (next_qp - start_next_qp)
    mov     rdx, #6
    mov     rcx, #4
    madd    r11, rax, rdx, rcx                          // r11 = rax * 6 (i.e. 4 byte word + 2 byte offset) + 4 byte for header

    sub     rax, next_low_bits, start_next_low_bits     // get bytes consumed by lower-10 bits
    mov     rdx, #1365
    mul     rax, rax, rdx

    sub     rdx, next_full_patt, start_next_full_patt   // get bytes consumed by dictionary misses
    add     rax, rdx, rax, lsr #11                      // rax = 2/3*(next_low_bits - start_next_low_bits) + (next_full_patt - start_next_full_patt)
    
    sub     rdx, next_qp, start_next_qp
    add     rax, rax, rdx, lsr #1                       // rax += (next_qp - start_next_qp)/2
    add     rax, rax, #(12+256*scale)                   // rax += bytes taken by the header + tags

    cmp     rax, r11                                    // is the default packer the better option?
    b.lt    L_done_search

    cmp     r11, byte_budget                            // can the sparse packer fit into the given budget?
    b.gt    L_budgetExhausted

L_sparse_packer:
    mov     edx, #MZV_MAGIC
    str     edx, [dest_buf], #4                         // header to indicate a sparse packer

    mov     rdx, #0                                     // rdx = byte offset in src of non-0 word
1:
    ldr     rax, [start_next_input_word, rdx]           // rax = read dword
    cbnz    rax, 5f                                     // is dword != 0
3:
    add     rdx, rdx, #8                                // 8 more bytes have been processed
4:
    cmp     rdx, #(4096*scale)                          // has the entire page been processed
    b.ne    1b
    mov     x0, r11                                     // store the size of the compressed stream
    b       L_done

5:
    cbz     eax, 6f                                     // is lower word == 0
    str     eax, [dest_buf], #4                         // store the non-0 word in the dest buffer
    strh    edx, [dest_buf], #2                         // store the byte index
6:
    lsr     rax, rax, 32                                // get the upper word into position
    cbz     eax, 3b                                     // is dword == 0
    add     rdx, rdx, #4
    str     eax, [dest_buf], #4                         // store the non-0 word in the dest buffer
    strh    edx, [dest_buf], #2                         // store the byte index
    add     rdx, rdx, #4
    b       4b

L_check_compression_ratio:

    mov     mode, NORMAL
	mov		remaining, #((1024 - CHKPT_WORDS)*scale)    // remaining input words to process
    cbz     remaining, CHECKPOINT                       // if there are no remaining words to process
    
    sub     rax, next_low_bits, start_next_low_bits     // get bytes consumed by lower-10 bits
    mov     rdx, #1365
    mul     rax, rax, rdx

    sub     rdx, next_full_patt, start_next_full_patt   // get bytes consumed by dictionary misses
    add     rax, rdx, rax, lsr #11                      // rax = 2/3*(next_low_bits - start_next_low_bits) + (next_full_patt - start_next_full_patt)

    sub     rdx, next_qp, start_next_qp
    add     rax, rax, rdx, lsr #1                       // rax += (next_qp - start_next_qp)/2
    subs    rax, rax, #((CHKPT_SHRUNK_BYTES - CHKPT_TAG_BYTES)*scale)
                                                        // rax += CHKPT_TAG_BYTES; rax -= CHKPT_SHRUNK_BYTES

    b.gt    L_budgetExhausted                           // if rax is > 0, we need to early abort
    b       L_loop                                      // we are done

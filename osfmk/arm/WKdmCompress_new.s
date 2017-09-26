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
 This file contains armv7 hand optimized implementation of WKdm memory page compressor. 

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

	byte_count = bytes_budget - 12 - 256;	 // header + tags

	whenever an input word is classified as class

		2 : byte_count -= 4;

	in 4-bit/10-bit packing, we can also return -1 when byte_budget <=0;

	Note : since there might be extra padding bits for class 1 and 3, it is complicated to track this padding bits on the fly. To compromise, we change class 1 to

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
	.text
	.align 4

	// int WKdm_compress (WK_word* src_buf, WK_word* dest_buf, WK_word* scratch, unsigned int bytes_budget);
 
.globl _WKdm_compress_new
_WKdm_compress_new:

/*
	 -------------------------       symbolizing register use          -----------------------------------
*/

	#define	src_buf				r0
	#define	next_input_word		r0
	#define	dest_buf			r1
	#define	scratch				r2
	#define	dictionary			sp
	#define	byte_count			r3

	#define	next_tag			r12

	#define	remaining			r4
	#define	next_full_patt		r5
	#define	dict_location		r6
	#define	next_qp				r8
	#define	hashTable			r9
	#define	next_low_bits		r10
	#define	eax					r11
	#define	ecx					r12
	#define	edx					lr
	#define	rdi					r6	

    #define tempTagsArray       scratch
    #define R11                 r0                      // only safe to use between phase-1 and phase-2
    #define R13                 r4                      // only safe to use between phase-1 and phase-2
/* 
		-------------------------    allocate scratch memory for local use  --------------------------------------

	need 256*4 (tempTagsArray) + 256*4 (tempQPosArray) + 1024*2 (tempLowBitsArray)
	total 4096 bytes
	[scratch,#0] : tempTagsArray
	[scratch,#1024] : tempQPosArray
	[scratch,#2048] : tempLowBitsArray

	[sp,#0] : dictionary

*/

	#define	TagsArray_offset	0
	#define	QPosArray_offset	1024
	#define	LowBitsArray_offset	2048

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

    push    {r7,lr}
    mov     r7, sp
    push    {r4-r6,r8-r11}

#if KERNEL
	sub		sp, sp, #32
	vst1.64 {q0,q1}, [sp]
#endif

	sub		sp, sp, #(64+24)					// reserve stack space for temps + dictionary

/*
		----- set up registers and initialize WKdm dictionary ----------
*/
                                            // NOTE: ALL THE DICTIONARY VALUES MUST BE INITIALIZED TO ZERO
                                            // THIS IS NEEDED TO EFFICIENTLY DETECT SINGLE VALUE PAGES
	mov		eax, #0

	mov		next_tag, scratch 				// &tempTagsArray[0]
	vdup.32 q0, eax

	add		next_qp, scratch, #QPosArray_offset		// next_qp
	mov		lr, sp
	mov		remaining, #(CHKPT_WORDS)       // remaining input words .. initially set to checkpoint
	vst1.64 {q0}, [lr]!
	add		next_full_patt, dest_buf, #268 	// dest_buf + [TAGS_AREA_OFFSET + (4096 / 16)]*4
	vst1.64 {q0}, [lr]!
	vst1.64 {q0}, [lr]!
	add		next_low_bits, scratch, #LowBitsArray_offset	// &tempLowBitsArray[0]
	vst1.64 {q0}, [lr]!

#if defined(KERNEL) && !SLIDABLE
    adr     hashTable, L_table
    ldr     hashTable, [hashTable]
#else
    ldr     hashTable, L_table
L_table0:
    ldr     hashTable, [pc, hashTable]
#endif

#define EARLYCHECK              0
#define NORMAL                  1

#define mode                    [sp, #64]
#define start_next_full_patt    [sp, #68]
#define start_next_input_word   [sp, #72]
#define start_next_low_bits     [sp, #76]
#define byte_budget             [sp, #80]

    mov     edx, #EARLYCHECK
    str     edx, mode                               // indicate we are yet to evaluate the early aborts
    str     next_full_patt, start_next_full_patt    // remember the start of next_full_patt
    str     next_input_word, start_next_input_word  // remember the start of next_input_word
    str     next_low_bits, start_next_low_bits      // remember the start of next_low_bits
    str     byte_count, byte_budget                 // remember the byte budget

	sub		byte_count, byte_count, #(12+256)	// byte_count - header bytes - tags bytes
	b		L_scan_loop

	.align	4, 0x90
L_RECORD_ZERO:
	/* we've just detected a zero input word in edx */
	strb	edx, [next_tag], #1						// *next_tag++ = ZERO;
	subs	remaining, remaining, #1				// remaining input words
	ble		CHECKPOINT                              // if remaining = 0, break

	/* WKdm compress scan/tag loop */
L_scan_loop:
	ldr		edx, [next_input_word], #4
	cmp		edx, #0
	beq		L_RECORD_ZERO							// if (input_word==0) RECORD_ZERO

	/*
		now the input word edx is nonzero, we next find the corresponding dictionary word (eax) and dict_location
	*/
	and		eax, edx, #(0xff<<10)					// part of input_word for hash table index
	lsr		eax, eax, #10							// 8-bit index to the Hash Table
	ldrb	eax, [hashTable, eax]					// HASH_TO_DICT_BYTE_OFFSET(input_word)
	add		dict_location, dictionary, eax			// ((char*) dictionary) + HASH_TO_DICT_BYTE_OFFSET(input_word));
	ldr		eax, [dictionary, eax]					// dict_word = *dict_location;
	cmp		eax, edx								// dict_word vs input_word
	beq		L_RECORD_EXACT							// if identical, RECORD_EXACT

	eor		eax, eax, edx
	lsrs	eax, eax, #10							// HIGH_BITS(dict_word)
	beq		L_RECORD_PARTIAL						// if identical, RECORD_PARTIAL

L_RECORD_MISS:
/*
	if we are here, the input word can not be derived from the dictionary, 
	we write the input word as a new word, 
	and update the dictionary with this new word
*/

	subs	byte_count, byte_count, #4
	ble		L_budgetExhausted						// o.w., return -1 to signal this page is not compressable
	str		edx, [next_full_patt], #4				// *next_full_patt++ = input_word;
	mov		eax, #2
	str		edx, [dict_location]					// *dict_location = input_word
	strb	eax, [next_tag], #1						// *next_tag++ = 2 for miss
	subs	remaining, remaining, #1				// remaining input words
	bgt		L_scan_loop								// if bit_count>0, go on the scan/tag pass,
    b       CHECKPOINT

L_done_search:

	// SET_QPOS_AREA_START(dest_buf,next_full_patt);
	sub		eax, next_full_patt, dest_buf			// next_full_patt - dest_buf								
	lsr		eax, eax, #2							// offset in 4-bytes			
	str		eax, [dest_buf]							// dest_buf[0] = next_full_patt - dest_buf


	/* --------------------------     packing 1024 tags into 256 bytes ----------------------------------------*/
	// boundary_tmp = WK_pack_2bits(tempTagsArray, (WK_word *) next_tag, dest_buf + HEADER_SIZE_IN_WORDS);

	add		rdi, dest_buf, #12						// dest_buf
	mov		eax, scratch	 						// &tempTagsArray[0]
	sub		edx, next_tag, scratch					// this should be 1024

	vld1.64	{q0,q1}, [eax,:128]!
	subs	edx, edx, #32				// pre-decrement by 32
L_pack_2bits:
	subs	edx, edx, #32
	vshl.i64	d1, d1, #4
	vshl.i64	d3, d3, #4
	vorr	d0, d0, d1
	vorr	d2, d2, d3
	vshr.u64	d1, d0, #30
	vshr.u64	d3, d2, #30
	vorr	d0, d0, d1
	vorr	d2, d2, d3
	vzip.32	d0, d2	
	vst1.64	{d0}, [rdi]!
	vld1.64	{q0,q1}, [eax,:128]!
	bgt		L_pack_2bits	
	vshl.i64	d1, d1, #4
	vshl.i64	d3, d3, #4
	vorr	d0, d0, d1
	vorr	d2, d2, d3
	vshr.u64	d1, d0, #30
	vshr.u64	d3, d2, #30
	vorr	d0, d0, d1
	vorr	d2, d2, d3
	vzip.32	d0, d2	
	vst1.64	{d0}, [rdi]


	/* ---------------------------------      packing 4-bits dict indices into dest_buf ----------------------------------   */

	/* 1st, round up number of 4-bits dict_indices to a multiple of 8 and fill in 0 if needed */
	add		ecx, scratch, #QPosArray_offset			// tempQPosArray
	sub		eax, next_qp, ecx 						// eax = num_bytes_to_pack = next_qp - (char *) tempQPosArray; 
	add		eax, eax, #7							// num_bytes_to_pack+7
	lsr		eax, eax, #3							// num_packed_words = (num_bytes_to_pack + 7) >> 3
	subs	byte_count, byte_count, eax, lsl #2		// byte_count -= 4 * packed_words
	blt		L_budgetExhausted						// o.w., return -1 to signal this page is not compressable
	add		ecx, ecx, eax, lsl #3					// endQPosArray = tempQPosArray + 2*num_source_words
	cmp		ecx, next_qp							// endQPosArray vs next_qp
	bls		L16										// if (next_qp >= endQPosArray) skip the following zero paddings
	sub		eax, ecx, next_qp
	mov		edx, #0
	tst		eax, #4
	beq		1f
	str		edx, [next_qp], #4
1:	tst		eax, #2
	beq		1f
	strh	edx, [next_qp], #2
1:	tst		eax, #1
	beq		1f
	strb	edx, [next_qp], #1
1:
L16:
	add		edx, scratch, #QPosArray_offset			// tempQPosArray
	mov		rdi, next_full_patt						// next_full_patt
	cmp		ecx, edx								// endQPosArray vs tempQPosArray
	ldr		eax, [dest_buf] 
	bls		L20										// if (endQPosArray <= tempQPosArray) skip the following

	/* packing 4-bits dict indices into dest_buf */
L_pack_4bits:
	vld1.64	{d0}, [edx,:64]!							// src_next[1]:src_next[0]
	vshr.u64	d1, d0, #28							// (src_next[1] << 4)
	vorr	d0, d0, d1								// src_next[0] | (src_next[1] << 4)
	cmp		ecx, edx								// source_end vs src_next
	vstr	s0, [rdi]
	add		rdi, rdi, #4
	bhi		L_pack_4bits							// while (src_next < source_end) repeat the loop

	/*  --------------------------- packing 3 10-bits low bits into a 32-bit word in dest_buf[]   ----------------------------------------- */
	// SET_LOW_BITS_AREA_START(dest_buf,boundary_tmp);
	sub		eax, rdi, dest_buf						// boundary_tmp - dest_buf
	lsr		eax, eax, #2							// boundary_tmp - dest_buf in words
L20:
	str		eax, [dest_buf,#4]						// dest_buf[1] = boundary_tmp - dest_buf

	add		ecx, scratch, #LowBitsArray_offset		// tempLowBitsArray
    sub		edx, next_low_bits, ecx					// next_low_bits - tempLowBitsArray (in bytes)
	lsr		edx, edx, #1							// num_tenbits_to_pack (in half-words)
	subs	edx, edx, #3							// pre-decrement num_tenbits_to_pack by 3
	blt		1f										// if num_tenbits_to_pack < 3, skip the following loop
0:
	subs	byte_count, byte_count, #4				// byte_count -= 4
	ble		L_budgetExhausted						// o.w., return -1 to signal this page is not compressable
	ldr		r4,[ecx, #2]							// w2:6bits:w1
	ldrh	r0,[ecx], #6							// w0
	uxth	r5, r4, ror #16							// w2	
	uxth	r4, r4									// w1
	orr		r0, r0, r4, lsl #10						// w1:w0
	subs	edx, edx, #3							// num_tenbits_to_pack-=3
	orr		r0, r0, r5, lsl #20						// w2:w1:w0
	str		r0, [rdi], #4							// pack w0,w1,w2 into 1 dest_buf word
	bge		0b										// if no less than 3 elements, back to loop head

1: 	adds	edx, edx, #3							// post-increment num_tenbits_to_pack by 3
	beq		3f										// if num_tenbits_to_pack is a multiple of 3, skip the following
	subs	byte_count, byte_count, #4				// byte_count -= 4
	ble		L_budgetExhausted						// o.w., return -1 to signal this page is not compressable
	ldrh	eax,[ecx]								// w0
	subs	edx, edx, #1							// num_tenbits_to_pack--
	beq		2f										//
	ldrh	edx, [ecx, #2]							// w1
	orr		eax, eax, edx, lsl #10					// w0 | (w1<<10)

2:	str		eax, [rdi], #4							// write the final dest_buf word

3:	sub		eax, rdi, dest_buf						// boundary_tmp - dest_buf
	lsr		eax, eax, #2							// boundary_tmp - dest_buf in terms of words
	str		eax, [dest_buf, #8]						// SET_LOW_BITS_AREA_END(dest_buf,boundary_tmp)
	lsl		r0, eax, #2								// boundary_tmp - dest_buf in terms of bytes

L_done:
	// restore registers and return

	add		sp, sp, #(64+24)			            // skip memory for temps + dictionary
#if KERNEL
	vld1.64 {q0,q1}, [sp]!
#endif
    pop     {r4-r6,r8-r11}
    pop     {r7,pc}

	.align	4
L_budgetExhausted:
	mov		r0, #-1
	b		L_done


	.align 4,0x90
L_RECORD_EXACT:
/*
		we have an exact match of the input word to its corresponding dictionary word
		write tag/dict_index to the temorary buffers		
*/
	sub		edx, dict_location, dictionary		// dict_location - dictionary
	mov		eax, #3
	lsr		edx, edx, #2						// divide by 4 for word offset
	strb	eax, [next_tag], #1					// *next_tag++ = 3 for exact
	strb	edx, [next_qp], #1					// *next_qp = word offset (4-bit)
	subs	remaining, remaining, #1			// remaining input words
	bgt		L_scan_loop							// if remaining>0, go on the scan/tag pass,
	b		CHECKPOINT                          // if remaining = 0, break

	.align 4,0x90
L_RECORD_PARTIAL:
/*
		we have a partial (high 22-bits) match of the input word to its corresponding dictionary word
		write tag/dict_index/low 10 bits to the temorary buffers		
*/
	sub		eax, dict_location, dictionary		// dict_location - dictionary
	str		edx, [dict_location]				// *dict_location = input_word;
	lsr		eax, eax, #2						// offset in 32-bit word
	lsl		edx, edx, #22
	strb	eax, [next_qp], #1					// update *next_qp++
	mov		eax, #1
	lsr		edx, edx, #22						// lower 10 bits
	strb	eax, [next_tag], #1					// *next_tag++ = 1 for partial matched
	strh	edx, [next_low_bits], #2			// save next_low_bits++
	subs	remaining, remaining, #1			// remaining input words
	bgt		L_scan_loop							// if remaining>0, go on the scan/tag pass,

CHECKPOINT:
    ldr     eax, mode                                   // load the mode
    cmp     eax, #EARLYCHECK
    beq     L_check_compression_ratio                   // early abort check

L_check_zero_page:

    ldr     eax, start_next_full_patt                   // check if any dictionary misses in page
    cmp     eax, next_full_patt
    bne     L_check_single_value_page

	add		eax, scratch, #QPosArray_offset		        // get start_next_qp
    cmp     eax, next_qp                                // check if any partial or exact dictionary matches

    moveq   r0, #SV_RETURN                              // Magic return value
	beq     L_done

L_check_single_value_page:

    ldr     eax, start_next_full_patt                   // get # dictionary misses
    sub     eax, next_full_patt, eax
    lsr     eax, eax, #2

	add		R11, scratch, #QPosArray_offset		        // get start_next_qp
    sub     R11, next_qp, R11                           // get # dictionary hits (exact + partial)

    ldr     R13, start_next_low_bits
    sub     R13, next_low_bits, R13                     // get # dictionary partial hits
    lsrs    R13, R13, #1

    // Single value page if one of the follwoing is true:
    //  partial == 0 AND hits == 1023 AND miss == 1 AND tag[0] == 2 (i.e. miss)
    //  partial == 1 AND hits == 1024 AND tag[0] == 1 (i.e. partial)
    //
    bne     1f                                          // were there 0 partial hits?

    mov     edx, #1023
    cmp     R11, edx                                    // were there 1023 dictionary hits
    bne     1f

    cmp     eax, #1                                     // was there exacly 1 dictionary miss?
    bne     1f

    ldrb    edx, [tempTagsArray]                        // read the very 1st tag
    cmp     edx, #2                                     // was the very 1st tag a miss?
    beq     L_is_single_value_page

1:
    cmp     R13, #1                                     // was there 1 partial hit?
    bne     L_check_mostly_zero

    mov     edx, #1024
    cmp     R11, edx                                    // were there 1024 dictionary hits
    bne     L_check_mostly_zero

    ldrb    edx, [tempTagsArray]                        // read the very 1st tag
    cmp     edx, #1                                     // was the very 1st tag a partial?
    bne     L_is_single_value_page

L_is_single_value_page:
    
    moveq   r0, #SV_RETURN                              // Magic return value
	beq     L_done

L_check_mostly_zero:
                                                        // how much space will the sparse packer take?
    add     eax, eax, R11                               // eax += (next_qp - start_next_qp)
    mov     edx, #6
    mov     R11, #4
    mla     R11, eax, edx, R11                          // R11 = eax * 6 (i.e. 4 byte word + 2 byte offset) + 4 byte for header

    ldr     eax, start_next_low_bits
    sub     eax, next_low_bits, eax                     // get bytes consumed by lower-10 bits
    mov     edx, #1365
    mul     eax, eax, edx

    ldr     edx, start_next_full_patt
    sub     edx, next_full_patt, edx                    // get bytes consumed by dictionary misses
    add     eax, edx, eax, lsr #11                      // eax = 2/3*(next_low_bits - start_next_low_bits) + (next_full_patt - start_next_full_patt)

	add		edx, scratch, #QPosArray_offset		        // get start_next_qp
    sub     edx, next_qp, edx
    add     eax, eax, edx, lsr #1                       // eax += (next_qp - start_next_qp)/2
    mov     edx, #(12+256)
    add     eax, eax, edx                               // rax += bytes taken by the header + tags

    cmp     eax, R11                                    // is the default packer the better option?
    blt     L_done_search

    ldr     edx, byte_budget    
    cmp     R11, edx                                    // can the sparse packer fit into the given budget?
    bgt     L_budgetExhausted

L_sparse_packer:

    mov     edx, #MZV_MAGIC
    str     edx, [dest_buf], #4                         // header to indicate a sparse packer

    ldr     R13, start_next_input_word                  // get the starting address of src
    mov     edx, #0
    mov     ecx, #4096
	
1:
    ldm     R13!, {r2, r3, r5, r6, r7, r8, r9, r10}

    teq     r2, #0
    teqeq   r3, #0
    teqeq   r5, #0
    teqeq   r6, #0
    teqeq   r7, #0
    teqeq   r8, #0
    teqeq   r9, #0
    teqeq   r10, #0

    bne     2f
    subs    ecx, ecx, #32
    add     edx, edx, #32                               // 16 more bytes have been processed
    bne     1b
    mov     r0, R11                                     // store the size of the compressed stream
    b       L_done

2:
    teq     r2, #0
    strne   r2, [dest_buf], #4                         // store the non-0 word in the dest buffer
    strhne  edx, [dest_buf], #2                        // store the byte index
    add     edx, edx, 4

    teq     r3, #0
    strne   r3, [dest_buf], #4                         // store the non-0 word in the dest buffer
    strhne  edx, [dest_buf], #2                        // store the byte index
    add     edx, edx, 4
    
    teq     r5, #0
    strne   r5, [dest_buf], #4                         // store the non-0 word in the dest buffer
    strhne  edx, [dest_buf], #2                        // store the byte index
    add     edx, edx, 4
    
    teq     r6, #0
    strne   r6, [dest_buf], #4                         // store the non-0 word in the dest buffer
    strhne  edx, [dest_buf], #2                        // store the byte index
    add     edx, edx, 4
    
    teq     r7, #0
    strne   r7, [dest_buf], #4                         // store the non-0 word in the dest buffer
    strhne  edx, [dest_buf], #2                        // store the byte index
    add     edx, edx, 4
    
    teq     r8, #0
    strne   r8, [dest_buf], #4                         // store the non-0 word in the dest buffer
    strhne  edx, [dest_buf], #2                        // store the byte index
    add     edx, edx, 4
    
    teq     r9, #0
    strne   r9, [dest_buf], #4                         // store the non-0 word in the dest buffer
    strhne  edx, [dest_buf], #2                        // store the byte index
    add     edx, edx, 4
    
    teq     r10, #0
    strne   r10, [dest_buf], #4                        // store the non-0 word in the dest buffer
    strhne  edx, [dest_buf], #2                        // store the byte index
    add     edx, edx, 4
    
    subs    ecx, ecx, #32
    bne     1b
    mov     r0, R11                                     // store the size of the compressed stream
    b       L_done

L_check_compression_ratio:

    mov     eax, #NORMAL
    str     eax, mode
    mov     remaining, #(1024 - CHKPT_WORDS)            // remaining input words to process
    cmp     remaining, #0
    beq     CHECKPOINT                                  // if there are no remaining words to process

    ldr     eax, start_next_low_bits
    sub     eax, next_low_bits, eax                     // get bytes consumed by lower-10 bits
    mov     edx, #1365
    mul     eax, eax, edx

    ldr     edx, start_next_full_patt
    sub     edx, next_full_patt, edx                    // get bytes consumed by dictionary misses
    add     eax, edx, eax, lsr #11                      // eax = 2/3*(next_low_bits - start_next_low_bits) + (next_full_patt - start_next_full_patt)

	add		edx, scratch, #QPosArray_offset		        // get start_next_qp
    sub     edx, next_qp, edx
    add     eax, eax, edx, lsr #1                       // eax += (next_qp - start_next_qp)/2
    mov     edx, #(CHKPT_SHRUNK_BYTES - CHKPT_TAG_BYTES)
    subs    eax, eax, edx                               // eax += CHKPT_TAG_BYTES; eax -= CHKPT_SHRUNK_BYTES
    bgt     L_budgetExhausted                           // if eax is > 0, we need to early abort
    b       L_scan_loop                                 // we are done


#if defined(KERNEL) && !SLIDABLE
    .align  2
L_table:
    .long   _hashLookupTable_new
#else
	.align	2
L_table:
	.long   L_Tab$non_lazy_ptr-(L_table0+8)

	 .section    __DATA,__nl_symbol_ptr,non_lazy_symbol_pointers
    .align  2
L_Tab$non_lazy_ptr:
    .indirect_symbol    _hashLookupTable_new
    .long   0
#endif


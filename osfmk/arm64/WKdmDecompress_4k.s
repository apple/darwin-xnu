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
 This file contains arm64 hand optimized implementation of WKdm memory page decompressor. 

	void WKdm_decompress (WK_word* src_buf, WK_word* dest_buf, WK_word *scratch, __unused__ unsigned int words);

	input :
		src_buf : address of input compressed data buffer
		dest_buf : address of output decompressed buffer 
		scratch : an 8-k bytes scratch mempro provided by the caller
		words : this argument is not used in the implementation
	(The 4th argument is, in fact, used by the Mostly Zero Value decoder)

	output :

		the input buffer is decompressed and the dest_buf is written with decompressed data.

	Am algorithm description of the WKdm compress and bit stream format can be found in the WKdm Compress arm64 assembly code WKdmCompress.s

	The bit stream (*src_buf) consists of 
		a. 12 bytes header
		b. 256 bytes for 1024 packed tags
		c. (varying number of) words for new words not matched to dictionary word. 
		d. (varying number of) 32-bit words for packed 4-bit dict_indices (for class 1 and 3)
		e. (varying number of) 32-bit words for packed 10-bit low bits (for class 1)

	where the header (of 3 words) specifies the ending boundaries (in 32-bit words) of the bit stream of c,d,e, respectively.

	The decompressor 1st unpacking the bit stream component b/d/e into temorary buffers. Then it sequentially decodes the decompressed word as follows

		for (i=0;i<1024;i++) {
			tag = *next_tag++
			switch (tag) {
				case 0 : *dest_buf++ = 0; break;
				case 1 : dict_word = dictionary[*dict_index]; dictionary[*dict_index++] = *dest_buf++ = dict_word&0xfffffc00 | *LowBits++; break;
				case 2 : x = *new_word++; k = (x>>10)&255; k = hashTable[k]; dictionary[k] = *dest_buf++ = x; break;
				case 3 : *dest_buf++ = dictionary[*dict_index++];  break;
			}
 
 	cclee, Nov 9, '12

    Added zero page, single value page, sparse page, early abort optimizations
    rsrini, 09/14/14
*/

#define MZV_MAGIC               17185      // magic value used to identify MZV page encoding

#ifndef PAGES_SIZE_IN_KBYTES    
#define PAGES_SIZE_IN_KBYTES    4
#endif

#if !((PAGES_SIZE_IN_KBYTES==4) || (PAGES_SIZE_IN_KBYTES==16))
#error "Only PAGES_SIZE_IN_KBYTES = 4 or 16 is supported"
#endif

#define	scale (PAGES_SIZE_IN_KBYTES/4)


	.align	4
	.text

/*
	 void WKdm_decompress (WK_word* src_buf, WK_word* dest_buf, WK_word* scratch, unsigned int bytes);
*/

	.globl _WKdm_decompress_4k
_WKdm_decompress_4k:

	/*
			--------   symbolizing registers --------
			the arm64 code was ported from x86_64 so we name some registers that are used as temp variables with x86_64 register names. 
	*/

	#define	src_buf			x0
	#define	dest_buf		x1
	#define	scratch			x2
    #define n_bytes         x3
	#define	dictionary		sp
	#define	rax				x13
	#define	eax				w13
	#define	rbx				x4
	#define	ebx				w4
	#define	rcx				x5
	#define	ecx				w5
	#define	rdx				x6
	#define	edx				w6
	#define	tags_counter	x7
	#define	next_tag		x12
	#define	r8				x8
	#define	r9				x9
	#define	r10				x10
	#define	r11				x11
    #define r12             x12

	/* 

	 	------   scratch memory for local variables  ---------

    [sp,#0] : dictionary
    [scratch,#0] : tempTagsArray
    [scratch,#1024] : tempQPosArray
    [scratch,#2048] : tempLowBitsArray

	*/

#if KERNEL
	sub		rax, sp, #96
	sub		sp, sp, #96
	st1.4s	{v0,v1,v2},[rax],#48
	st1.4s	{v3,v4,v5},[rax],#48
#endif

	sub		sp, sp, #64

    ldr     eax, [src_buf]                      // read the 1st word from the header
    mov     ecx, #MZV_MAGIC
    cmp     eax, ecx                            // is the alternate packer used (i.e. is MZV page)?
    b.ne    L_default_decompressor              // default decompressor was used

                                                // Mostly Zero Page Handling...
                                                // {
    add     src_buf, src_buf, 4                 // skip the header
    mov     rax, dest_buf
    mov     rcx, #(PAGES_SIZE_IN_KBYTES*1024)   // number of bytes to zero out
1:
    dc      zva, rax                            // zero 64 bytes. since dest_buf is a page, it will be 4096 or 16384 byte aligned
    add     rax, rax, #64
    dc      zva, rax
    add     rax, rax, #64
    dc      zva, rax
    add     rax, rax, #64
    dc      zva, rax
    add     rax, rax, #64
    subs    rcx, rcx, #256
    b.ne    1b

    mov     r12, #4                             // current byte position in src to read from
    mov     rdx, #0
2:
    ldr     eax, [src_buf], #4                  // get the word
    ldrh    edx, [src_buf], #2                  // get the index
    str     eax, [dest_buf, rdx]                // store non-0 word in the destination buffer
    add     r12, r12, #6                        // 6 more bytes processed
    cmp     r12, n_bytes                        // finished processing all the bytes?
    b.ne    2b
    b       L_done
                                                // }

L_default_decompressor:

    /*
			---------------------- set up registers and PRELOAD_DICTIONARY ---------------------------------
	*/
    // NOTE: ALL THE DICTIONARY VALUES MUST BE INITIALIZED TO ZERO TO MIRROR THE COMPRESSOR
	adrp    rbx, _table_2bits@GOTPAGE
    stp     xzr, xzr, [dictionary, #0]
	add		r10, src_buf, #(12+256*scale)		// TAGS_AREA_END
    stp     xzr, xzr, [dictionary, #16]
	add		rax, src_buf, #12			// TAGS_AREA_START	
    ldr     rbx, [rbx, _table_2bits@GOTPAGEOFF]
    stp     xzr, xzr, [dictionary, #32]
	mov		rcx, scratch				// tempTagsArray
    stp     xzr, xzr, [dictionary, #48]
	ld1.4s	{v0,v1},[rbx]


	/* 
			------------------------------  unpacking bit stream ----------------------------------
	*/

	// WK_unpack_2bits(TAGS_AREA_START(src_buf), TAGS_AREA_END(src_buf), tempTagsArray);
/*
	unpacking 16 2-bit tags (from a 32-bit word) into 16 bytes
    for arm64, this can be done by
		1. read the input 32-bit word into GPR w
    	2. duplicate GPR into 4 elements in a vector register v0
    	3. ushl.4s vd, v0, vshift   where vshift = {0, -2, -4, -6}
    	4. and.4s  vd, vd, vmask    where vmask = 0x03030303030303030303030303030303
*/

L_WK_unpack_2bits:
	ldr		q5, [rax], #16				// read 4 32-bit words for 64 2-bit tags
	dup.4s	v2, v5[0]					// duplicate to 4 elements
	dup.4s	v3, v5[1]					// duplicate to 4 elements
	dup.4s	v4, v5[2]					// duplicate to 4 elements
	dup.4s	v5, v5[3]					// duplicate to 4 elements
	ushl.4s	v2, v2, v0					// v1 = {0, -2, -4, -6}
	ushl.4s	v3, v3, v0					// v1 = {0, -2, -4, -6}
	ushl.4s	v4, v4, v0					// v1 = {0, -2, -4, -6}
	ushl.4s	v5, v5, v0					// v1 = {0, -2, -4, -6}
	and.16b	v2, v2, v1					// v2 = {3,3,...,3}
	and.16b	v3, v3, v1					// v2 = {3,3,...,3}
	and.16b	v4, v4, v1					// v2 = {3,3,...,3}
	and.16b	v5, v5, v1					// v2 = {3,3,...,3}
	cmp		r10, rax					// TAGS_AREA_END vs TAGS_AREA_START
	st1.4s	{v2,v3,v4,v5}, [rcx], #64	// write 64 tags into tempTagsArray
	b.hi	L_WK_unpack_2bits			// if not reach TAGS_AREA_END, repeat L_WK_unpack_2bits


	// WK_unpack_4bits(QPOS_AREA_START(src_buf), QPOS_AREA_END(src_buf), tempQPosArray);

	ldp		w8, w9, [src_buf]			// WKdm header qpos start and end
	adrp    rbx, _table_4bits@GOTPAGE
	subs	x14, r9, r8					// x14 = (QPOS_AREA_END - QPOS_AREA_START)/4
	add		r8, src_buf, r8, lsl #2		// QPOS_AREA_START
	add		r9, src_buf, r9, lsl #2		// QPOS_AREA_END

	b.ls	1f							// if QPOS_AREA_END <= QPOS_AREA_START, skip L_WK_unpack_4bits
    ldr     rbx, [rbx, _table_4bits@GOTPAGEOFF]
	add		rcx, scratch, #(1024*scale)		// tempQPosArray
	ld1.4s	{v0,v1},[rbx]
	subs	w14, w14, #1	
	b.ls	2f							// do loop of 2 only if w14 >= 5 
L_WK_unpack_4bits:
	ldr		d2, [r8], #8				// read a 32-bit word for 8 4-bit positions 
	subs	w14, w14, #2
	zip1.4s	v2, v2, v2
	ushl.4s	v2, v2, v0					// v1 = {0, -4, 0, -4}
	and.16b	v2, v2, v1					// v2 = {15,15,...,15} 
	str		q2, [rcx], #16
	b.hi	L_WK_unpack_4bits	
2:
	adds	w14, w14, #1
	b.le	1f

	ldr		s3, [r8], #4				// read a 32-bit word for 8 4-bit positions 
	dup.2s  v2, v3[0]					// duplicate to 2 elements
	ushl.2s	v2, v2, v0					// v1 = {0, -4}
	and.8b	v2, v2, v1					// v2 = {15,15,...,15} 
	str		d2, [rcx], #8				// write 16 tags into tempTagsArray

1:

	// WK_unpack_3_tenbits(LOW_BITS_AREA_START(src_buf), LOW_BITS_AREA_END(src_buf), tempLowBitsArray);

	ldr		eax, [src_buf,#8]			// LOW_BITS_AREA_END offset
	add		r8, src_buf, rax, lsl #2	// LOW_BITS_AREA_END
	add		rcx, scratch, #(2048*scale)	// tempLowBitsArray 
#if (scale==1)
	add		r11, scratch, #(4096*scale-2)	// final tenbits for the rare case
#else
	add		r11, scratch, #(4096*scale)	// final tenbits for the rare case
	sub		r11, r11, #2
#endif
	subs	r8, r8, r9					// LOW_BITS_AREA_START vs LOW_BITS_AREA_END
	b.ls	1f							// if START>=END, skip L_WK_unpack_3_tenbits

	adrp    rbx, _table_10bits@GOTPAGE
    ldr     rbx, [rbx, _table_10bits@GOTPAGEOFF]
	ld1.4s	{v0,v1,v2,v3},[rbx]

	/*
		a very rare case : 1024 tenbits, 1023 + 1 -> 341 + final 1 that is padded with 2 zeros
		since the scratch memory is 4k (2k for this section), we need to pay attention to the last case
		so we don't overwrite to the scratch memory

		we 1st do a single 3_tenbits, followed by 2x_3_tenbits loop, and detect whether the last 3_tenbits
		hits the raee case
	*/
#if 1
	subs	r8, r8, #4					// pre-decrement by 8
	ldr		s4, [r9], #4				// read 32-bit words for 3 low 10-bits
	zip1.4s	v4,	v4,	v4	// bits 0-63 contain first triplet twice, bits 64-127 contain second triplet twice.
	ushl.4s	v5,	v4,	v0	// v0 = {6, 0, 6, 0}, places second element of triplets into bits 16-25 and 80-89.
	ushl.4s	v4,	v4,	v1	// v1 = {0, -20, 0, -20}, places third element of triplets into bits 32-41 and 96-105.
	and.16b	v5,	v5,	v2	// v2 = {0, 1023, 0, 0, 0, 1023, 0, 0}, isolate second element of triplets.
	and.16b v4,	v4,	v3	// v3 = {1023, 0, 1023, 0, 1023, 0, 1023, 0}, isolate first and third elements of triplets
	orr.16b	v4,	v4,	v5	// combine data
	str		d4, [rcx], #6				// write 3 low 10-bits
	b.eq	1f
#endif

	subs	r8, r8, #8					// pre-decrement by 8
	b.lt	L_WK_unpack_3_tenbits

L_WK_unpack_2x_3_tenbits:
	ldr		d4, [r9], #8				// read 2 32-bit words for a pair of 3 low 10-bits
	zip1.4s	v4,	v4,	v4	// bits 0-63 contain first triplet twice, bits 64-127 contain second triplet twice.
	ushl.4s	v5,	v4,	v0	// v0 = {6, 0, 6, 0}, places second element of triplets into bits 16-25 and 80-89.
	ushl.4s	v4,	v4,	v1	// v1 = {0, -20, 0, -20}, places third element of triplets into bits 32-41 and 96-105.
	and.16b	v5,	v5,	v2	// v2 = {0, 1023, 0, 0, 0, 1023, 0, 0}, isolate second element of triplets.
	and.16b v4,	v4,	v3	// v3 = {1023, 0, 1023, 0, 1023, 0, 1023, 0}, isolate first and third elements of triplets
	orr.16b	v4,	v4,	v5	// combine data
	ins		v5.d[0], v4.d[1]
	str		d4, [rcx], #6				// write 3 low 10-bits
	str		d5, [rcx], #6				// write 3 low 10-bits

	subs	r8, r8, #8
	b.ge	L_WK_unpack_2x_3_tenbits		// repeat loop if LOW_BITS_AREA_END > next_word

	tst		r8, #4
	b.eq	1f

L_WK_unpack_3_tenbits:
	ldr		s4, [r9]					// read 32-bit words for 3 low 10-bits
	zip1.4s	v4,	v4,	v4	// bits 0-63 contain first triplet twice, bits 64-127 contain second triplet twice.
	ushl.4s	v5,	v4,	v0	// v0 = {6, 0, 6, 0}, places second element of triplets into bits 16-25 and 80-89.
	ushl.4s	v4,	v4,	v1	// v1 = {0, -20, 0, -20}, places third element of triplets into bits 32-41 and 96-105.
	and.16b	v5,	v5,	v2	// v2 = {0, 1023, 0, 0, 0, 1023, 0, 0}, isolate second element of triplets.
	and.16b v4,	v4,	v3	// v3 = {1023, 0, 1023, 0, 1023, 0, 1023, 0}, isolate first and third elements of triplets
	orr.16b	v4,	v4,	v5	// combine data
#if 0
	str		d4, [rcx]	// write 3 low 10-bits
#else
	cmp		rcx, r11
	b.eq	2f
	str		d4, [rcx]	// write 3 low 10-bits
	b		1f
2:
	str		h4, [rcx]	// write final 1 low 10-bits
#endif
1:

	/*
		set up before going to the main decompress loop
	*/
	mov		next_tag, scratch				// tempTagsArray
	add		r8, scratch, #(1024*scale)		// next_qpos
	add		r11, scratch, #(2048*scale)		// tempLowBitsArray 
	adrp    rbx, _hashLookupTable@GOTPAGE
	mov		tags_counter, #(1024*scale)		// tag_area_end
    ldr     rbx, [rbx, _hashLookupTable@GOTPAGEOFF]

	b		L_next

	.align 4,0x90
L_ZERO_TAG:
	/*
		we can only get here if w9 = 0, meaning this is a zero tag
		*dest_buf++ = 0;	
	*/
	str		w9, [dest_buf], #4				// *dest_buf++ = 0
	subs	tags_counter, tags_counter, #1	// next_tag vs tag_area_end
	b.ls	L_done							// if next_tag >= tag_area_end, we're done

	/* WKdm decompress main loop */
L_next:
	ldrb	w9, [next_tag], #1				// new tag
	cbz		w9, L_ZERO_TAG
	cmp		w9, #2	 						// partial match tag ?
	b.eq	L_MISS_TAG
	b.gt	L_EXACT_TAG

L_PARTIAL_TAG:
	/*
			this is a partial match:
				dict_word = dictionary[*dict_index]; 
				dictionary[*dict_index++] = *dest_buf++ = dict_word&0xfffffc00 | *LowBits++; 
	*/

	ldrb	edx, [r8], #1					// qpos = *next_qpos++
	ldrh	ecx, [r11], #2					// lower 10-bits from *next_low_bits++
	ldr		eax, [dictionary, rdx, lsl #2]	// read dictionary word
	bfm		eax, ecx, #0, #9				// pad the lower 10-bits from *next_low_bits
	str		eax, [dictionary,rdx,lsl #2]	// *dict_location = newly formed word 
	str		eax, [dest_buf], #4				// *dest_buf++ = newly formed word
	subs	tags_counter, tags_counter, #1	// next_tag vs tag_area_end
	b.gt	L_next							// repeat loop until next_tag==tag_area_end

L_done:

	// release stack memory, restore registers, and return
	add		sp, sp, #64					// deallocate for dictionary
#if KERNEL
	ld1.4s	{v0,v1,v2},[sp],#48
	ld1.4s	{v3,v4,v5},[sp],#48
#endif
	ret		lr

	.align 4,0x90
L_MISS_TAG:
	/*
		this is a dictionary miss.
			x = *new_word++; 
			k = (x>>10)&255; 
			k = hashTable[k]; 
			dictionary[k] = *dest_buf++ = x;
	*/
	ldr		eax, [r10], #4					// w = *next_full_patt++
	ubfm	edx, eax, #10, #17				// 8-bit hash table index
	str		eax, [dest_buf], #4				// *dest_buf++ = word
	ldrb	edx, [rbx, rdx]					// qpos
	str		eax, [dictionary,rdx]			// dictionary[qpos] = word
	subs	tags_counter, tags_counter, #1	// next_tag vs tag_area_end
	b.gt	L_next							// repeat the loop
	b		L_done							// if next_tag >= tag_area_end, we're done

	.align 4,0x90
L_EXACT_TAG:
	/* 
			this is an exact match;
			*dest_buf++ = dictionary[*dict_index++];
	*/
	ldrb	eax, [r8], #1					// qpos = *next_qpos++
	ldr		eax, [dictionary,rax,lsl #2]	// w = dictionary[qpos]
	str		eax, [dest_buf], #4				// *dest_buf++ = w
	subs	tags_counter, tags_counter, #1	// next_tag vs tag_area_end
	b.gt	L_next							// repeat the loop
	b		L_done							// if next_tag >= tag_area_end, we're done



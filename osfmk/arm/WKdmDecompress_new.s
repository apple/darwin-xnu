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
 This file contains armv7 hand optimized implementation of WKdm memory page decompressor. 

	void WKdm_decompress (WK_word* src_buf, WK_word* dest_buf, WK_word* scratch, __unused__ unsigned int words);

	input :
		src_buf : address of input compressed data buffer
		dest_buf : address of output decompressed buffer 
		scratch : a 16-byte aligned 4k bytes scratch memory provided by the caller
		words : this argument is not used in the implementation

	output :

		the input buffer is decompressed and the dest_buf is written with decompressed data.

	Am algorithm description of the WKdm compress and bit stream format can be found in the WKdm Compress armv7 assembly code WKdmCompress.s

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
 
 	cclee, 11/9/12

    Added zero page, single value page, sparse page, early abort optimizations
    rsrini, 09/14/14

*/

    #define MZV_MAGIC           17185      // magic value used to identify MZV page encoding

	#define	ZERO				0
	#define	PARTIAL_MATCH		1
	#define	MISS_TAG			2
	#define	MATCH				3

	.text
	.syntax unified
	.align	4

	// void WKdm_decompress (WK_word* src_buf, WK_word* dest_buf, WK_word* scratch, unsigned int bytes);

	.globl _WKdm_decompress_new
_WKdm_decompress_new:

	/*
			--------   symbolizing registers --------
			the armv7 code was ported from x86_64 so we name some registers that are used as temp variables with x86_64 register names. 
	*/

	#define	src_buf			r0
	#define	dest_buf		r1
	#define	scratch			r2
	#define	eax				r3
	#define	ebx				r4
	#define	hashTable		r4
	#define	ecx				r5
	#define	edx				r6
    #define n_bytes         r8
	#define	next_tag		r12
	#define	tags_counter	lr
	#define	dictionary		sp
	#define	v0		q0
	#define	v1		q1
	#define	v2		q2
	#define	v3		q3
	#define	v4		q4
	#define	v5		q5

	// and scratch memory for local variables

    // [sp,#0] : dictionary
    // [scratch,#0] : tempTagsArray		was 64
    // [scratch,#1024] : tempQPosArray  was 1088
    // [scratch,#2048] : tempLowBitsArray was 2112

	push	{r7, lr}
	mov		r7, sp
	push	{r4-r6,r8-r11}
#if KERNEL
	sub		ecx, sp, #96
	sub		sp, sp, #96
	vst1.64	{q0,q1},[ecx]!
	vst1.64	{q2,q3},[ecx]!
	vst1.64	{q4,q5},[ecx]!
#endif
	sub		sp, sp, #64			// allocate for dictionary

    mov     n_bytes, r3                         // save the n_bytes passed as function args
    ldr     eax, [src_buf]                      // read the 1st word from the header
    mov     ecx, #MZV_MAGIC
    cmp     eax, ecx                            // is the alternate packer used (i.e. is MZV page)?
    bne     L_default_decompressor              // default decompressor was used

                                                // Mostly Zero Page Handling...
                                                // {
    add     src_buf, src_buf, 4                 // skip the header
    mov     eax, dest_buf
    mov     ecx, #4096                          // number of bytes to zero out
    mov     r9, #0
    mov     r10, #0
    mov     r11, #0
    mov     r12, #0
1:
    subs    ecx, ecx, #64
    stmia   eax!, {r9-r12}
    stmia   eax!, {r9-r12}
    stmia   eax!, {r9-r12}
    stmia   eax!, {r9-r12}
    bne     1b

    mov     r12, #4                             // current byte position in src to read from
2:
    ldr     eax, [src_buf], #4                  // get the word
    ldrh    edx, [src_buf], #2                  // get the index
    str     eax, [dest_buf, edx]                // store non-0 word in the destination buffer
    add     r12, r12, #6                        // 6 more bytes processed
    cmp     r12, n_bytes                        // finished processing all the bytes?
    bne     2b
    b       L_done
                                                // }

L_default_decompressor:
	
    /*
			---------------------- set up registers and PRELOAD_DICTIONARY ---------------------------------
	*/
    // NOTE: ALL THE DICTIONARY VALUES MUST BE INITIALIZED TO ZERO TO MIRROR THE COMPRESSOR
	vmov.i32	q0, #0
	mov		r8, sp
	adr		ebx, _table_2bits
    vst1.64	{q0}, [r8]!
	add		r10, src_buf, #268			// TAGS_AREA_END
    vst1.64	{q0}, [r8]!
	add		eax, src_buf, #12			// TAGS_AREA_START	
    vst1.64	{q0}, [r8]!
	mov		ecx, scratch				// tempTagsArray
    vst1.64	{q0}, [r8]!
	vld1.64	{q0,q1},[ebx,:128]


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
	vld1.64	{v5}, [eax]!				// read 4 32-bit words for 64 2-bit tags
	vdup.32	v2, d10[0]					// duplicate to 4 elements
	vdup.32	v3, d10[1]					// duplicate to 4 elements
	vdup.32	v4, d11[0]					// duplicate to 4 elements
	vdup.32	v5, d11[1]					// duplicate to 4 elements
	vshl.u32	v2, v2, v0				// v0 = {0, -2, -4, -6}
	vshl.u32	v3, v3, v0				// v0 = {0, -2, -4, -6}
	vshl.u32	v4, v4, v0				// v0 = {0, -2, -4, -6}
	vshl.u32	v5, v5, v0				// v0 = {0, -2, -4, -6}
	vand	v2, v2, v1					// v1 = {3,3,...,3}
	vand	v3, v3, v1					// v1 = {3,3,...,3}
	vand	v4, v4, v1					// v1 = {3,3,...,3}
	vand	v5, v5, v1					// v1 = {3,3,...,3}
	vst1.64	{v2,v3}, [ecx,:128]!		// write 64 tags into tempTagsArray
	cmp		r10, eax					// TAGS_AREA_END vs TAGS_AREA_START
	vst1.64	{v4,v5}, [ecx,:128]!		// write 64 tags into tempTagsArray
	bhi	L_WK_unpack_2bits				// if not reach TAGS_AREA_END, repeat L_WK_unpack_2bits


	// WK_unpack_4bits(QPOS_AREA_START(src_buf), QPOS_AREA_END(src_buf), tempQPosArray);

	ldm		src_buf, {r8,r9}			// WKdm header qpos start and end
	adr		ebx, _table_4bits
	subs	r12, r9, r8					// r12 = (QPOS_AREA_END - QPOS_AREA_START)/4
	add		r8, src_buf, r8, lsl #2		// QPOS_AREA_START
	add		r9, src_buf, r9, lsl #2		// QPOS_AREA_END
	bls		1f							// if QPOS_AREA_END <= QPOS_AREA_START, skip L_WK_unpack_4bits
	add		ecx, scratch, #1024			// tempQPosArray
	vld1.64	{v0,v1},[ebx,:128]

	subs	r12, r12, #1	
	bls		2f							// do loop of 2 only if w14 >= 5 
L_WK_unpack_4bits:
	vld1.64	{d4}, [r8]!					// read a 32-bit word for 8 4-bit positions 
	subs	r12, r12, #2
	vmov	d5, d4
	vzip.32	d4, d5
	vshl.u32	v2, v2, v0				// v0 = {0, -4, 0, -4}
	vand	v2, v2, v1					// v1 = {15,15,...,15} 
	vst1.64	{q2}, [ecx,:128]!
	bhi		L_WK_unpack_4bits	
2:
	adds	r12, r12, #1	
	ble	1f

	ldr		r12, [r8], #4				// read a 32-bit word for 8 4-bit positions 
	vdup.32	d4, r12						// duplicate to 2 elements
	vshl.u32	v2, v2, v0				// v0 = {0, -4}
	vand	v2, v2, v1					// v1 = {15,15,...,15} 
	vst1.64	{d4}, [ecx,:64]!			// write 16 tags into tempTagsArray

1:

	// WK_unpack_3_tenbits(LOW_BITS_AREA_START(src_buf), LOW_BITS_AREA_END(src_buf), tempLowBitsArray);

	ldr		eax, [src_buf,#8]			// LOW_BITS_AREA_END offset
	add		r8, src_buf, eax, lsl #2	// LOW_BITS_AREA_END
	cmp		r8, r9						// LOW_BITS_AREA_START vs LOW_BITS_AREA_END
	add		ecx, scratch, #2048			// tempLowBitsArray 
	add		edx, scratch, #4096			// last tenbits
	bls		1f							// if START>=END, skip L_WK_unpack_3_tenbits

	adr		ebx, _table_10bits
	vld1.64	{v0,v1},[ebx,:128]

	mov		r11, #0x03ff
L_WK_unpack_3_tenbits:
	ldr		r12, [r9], #4				// read a 32-bit word for 3 low 10-bits
	and		lr, r11, r12
	strh	lr, [ecx], #2
	cmp		ecx, edx
	and		lr, r11, r12, lsr #10
	beq		1f
	strh	lr, [ecx], #2
	and		lr, r11, r12, lsr #20
	strh	lr, [ecx], #2

	cmp		r8, r9						// LOW_BITS_AREA_START vs LOW_BITS_AREA_END
	bhi		L_WK_unpack_3_tenbits		// repeat loop if LOW_BITS_AREA_END > next_word
 
1:
	/*
		set up before going to the main decompress loop
	*/

	mov		next_tag, scratch			// tempTagsArray
	add		r8, scratch, #1024			// next_qpos
	add		r11, scratch, #2048			// tempLowBitsArray 
#if defined(KERNEL) && !SLIDABLE
    adr     hashTable, L_table
    ldr     hashTable, [hashTable]
#else
    ldr     hashTable, L_table
L_table0:
    ldr     hashTable, [pc, hashTable]
#endif
	mov		tags_counter, #1024			// tags_counter

	b		L_next

	.align 4,0x90
L_ZERO_TAG:
	/*
		we can only get here if w9 = 0, meaning this is a zero tag
		*dest_buf++ = 0;	
	*/
	subs	tags_counter,tags_counter,#1	// tags_counter--
	str		r9, [dest_buf], #4				// *dest_buf++ = 0
	ble		L_done							// if next_tag >= tag_area_end, we're done

	/* WKdm decompress main loop */
L_next:
	ldrb	r9, [next_tag], #1				// new tag
	cmp		r9, #0
	beq		L_ZERO_TAG 
	cmp		r9, #2							// partial match tag ?
	beq		L_MISS_TAG
	bgt		L_EXACT_TAG

L_PARTIAL_TAG:
	/*
			this is a partial match:
				dict_word = dictionary[*dict_index]; 
				dictionary[*dict_index++] = *dest_buf++ = dict_word&0xfffffc00 | *LowBits++; 
	*/
	ldrb	edx, [r8], #1					// qpos = *next_qpos++
	ldrh	ecx, [r11], #2					// lower 10-bits from *next_low_bits++
	ldr		eax, [dictionary, edx, lsl #2]	// read dictionary word
	subs	tags_counter,tags_counter,#1	// tags_counter--
	lsr		eax, eax, #10					// clear lower 10 bits
	orr		eax, ecx, eax, lsl #10			// pad the lower 10-bits from *next_low_bits
	str		eax, [dictionary,edx,lsl #2]	// *dict_location = newly formed word 
	str		eax, [dest_buf], #4				// *dest_buf++ = newly formed word
	bgt		L_next							// repeat loop until next_tag==tag_area_end

L_done:

	add		sp, sp, #64			// deallocate for dictionary

	// release stack memory, restore registers, and return
#if KERNEL
	vld1.64	{q0,q1},[sp]!
	vld1.64	{q2,q3},[sp]!
	vld1.64	{q4,q5},[sp]!
#endif
	pop		{r4-r6,r8-r11}
	pop		{r7,pc}

	.align 4,0x90
L_MISS_TAG:
	/*
		this is a dictionary miss.
			x = *new_word++; 
			k = (x>>10)&255; 
			k = hashTable[k]; 
			dictionary[k] = *dest_buf++ = x;
	*/
	subs	tags_counter,tags_counter,#1	// tags_counter--
	ldr		eax, [r10], #4					// w = *next_full_patt++
	lsr		edx, eax, #10					// w>>10
	str		eax, [dest_buf], #4				// *dest_buf++ = word
	and		edx, edx, #0x0ff				// 8-bit hash table index
	ldrb	edx, [ebx, edx]					// qpos
	str		eax, [dictionary,edx]			// dictionary[qpos] = word
	bgt		L_next							// repeat the loop
	b		L_done							// if next_tag >= tag_area_end, we're done

	.align 4,0x90

L_EXACT_TAG:
	/* 
			this is an exact match;
			*dest_buf++ = dictionary[*dict_index++];
	*/

	ldrb	eax, [r8], #1					// qpos = *next_qpos++
	subs	tags_counter,tags_counter,#1	// tags_counter--
	ldr		eax, [dictionary,eax,lsl #2]	// w = dictionary[qpos]
	str		eax, [dest_buf], #4				// *dest_buf++ = w
	bgt		L_next							// repeat the loop
	b		L_done							// if next_tag >= tag_area_end, we're done


	.align 4

_table_2bits:
	.word	0
	.word	-2
	.word	-4
	.word	-6
	.word	0x03030303
	.word	0x03030303
	.word	0x03030303
	.word	0x03030303

_table_4bits:
	.word	0
	.word	-4
	.word	0
	.word	-4
	.word	0x0f0f0f0f
	.word	0x0f0f0f0f
	.word	0x0f0f0f0f
	.word	0x0f0f0f0f

_table_10bits:
	.word	0
	.word	-10
	.word	-20
	.word	0
	.word	1023
	.word	1023
	.word	1023
	.word	0


#if defined(KERNEL) && !SLIDABLE
    .align  2
L_table:
    .long   _hashLookupTable_new
#else
    .align  2
L_table:
    .long   L_Tab$non_lazy_ptr-(L_table0+8)

     .section    __DATA,__nl_symbol_ptr,non_lazy_symbol_pointers
    .align  2
L_Tab$non_lazy_ptr:
    .indirect_symbol    _hashLookupTable_new
    .long   0
#endif


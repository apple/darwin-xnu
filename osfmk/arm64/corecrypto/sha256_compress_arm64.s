/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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
	This file provides armv7+neon hand implementation of the following function

	void SHA256_Transform(SHA256_ctx *ctx, char *data, unsigned int num_blocks);

	which is a C function in sha2.c (from xnu).

	sha256 algorithm per block description:

		1. W(0:15) = big-endian (per 4 bytes) loading of input data (64 byte) 
		2. load 8 digests a-h from ctx->state
		3. for r = 0:15
				T1 = h + Sigma1(e) + Ch(e,f,g) + K[r] + W[r];
				d += T1;
				h = T1 + Sigma0(a) + Maj(a,b,c)
				permute a,b,c,d,e,f,g,h into h,a,b,c,d,e,f,g
		4. for r = 16:63
				W[r] = W[r-16] + sigma1(W[r-2]) + W[r-7] + sigma0(W[r-15]);
				T1 = h + Sigma1(e) + Ch(e,f,g) + K[r] + W[r];
				d += T1;
				h = T1 + Sigma0(a) + Maj(a,b,c)
				permute a,b,c,d,e,f,g,h into h,a,b,c,d,e,f,g
				
	In the assembly implementation:	
		- a circular window of message schedule W(r:r+15) is updated and stored in q0-q3
		- its corresponding W+K(r:r+15) is updated and stored in a stack space circular buffer
		- the 8 digests (a-h) will be stored in GPR or memory

	the implementation per block looks like

	----------------------------------------------------------------------------

	load W(0:15) (big-endian per 4 bytes) into q0:q3
	pre_calculate and store W+K(0:15) in stack

	load digests a-h from ctx->state;

	for (r=0;r<48;r+=4) {
		digests a-h update and permute round r:r+3
		update W([r:r+3]%16) and WK([r:r+3]%16) for the next 4th iteration 
	}

	for (r=48;r<64;r+=4) {
		digests a-h update and permute round r:r+3
	}

	ctx->states += digests a-h;

	----------------------------------------------------------------------------

	our implementation (allows multiple blocks per call) pipelines the loading of W/WK of a future block 
	into the last 16 rounds of its previous block:

	----------------------------------------------------------------------------

	load W(0:15) (big-endian per 4 bytes) into q0:q3 
	pre_calculate and store W+K(0:15) in stack

L_loop:

	load digests a-h from ctx->state;

	for (r=0;r<48;r+=4) {
		digests a-h update and permute round r:r+3
		update W([r:r+3]%16) and WK([r:r+3]%16) for the next 4th iteration 
	}

	num_block--;
	if (num_block==0)	jmp L_last_block;

	for (r=48;r<64;r+=4) {
		digests a-h update and permute round r:r+3
		load W([r:r+3]%16) (big-endian per 4 bytes) into q0:q3 
		pre_calculate and store W+K([r:r+3]%16) in stack
	}

	ctx->states += digests a-h;

	jmp	L_loop;

L_last_block:

	for (r=48;r<64;r+=4) {
		digests a-h update and permute round r:r+3
	}

	ctx->states += digests a-h;

	------------------------------------------------------------------------

	Apple CoreOS vector & numerics
*/

#if defined(__arm64__)

#include "arm64_isa_compatibility.h"

.subsections_via_symbols
    .text

    .p2align  4

K256:
    .long   0x428a2f98
    .long   0x71374491
    .long   0xb5c0fbcf
    .long   0xe9b5dba5
    .long   0x3956c25b
    .long   0x59f111f1
    .long   0x923f82a4
    .long   0xab1c5ed5
    .long   0xd807aa98
    .long   0x12835b01
    .long   0x243185be
    .long   0x550c7dc3
    .long   0x72be5d74
    .long   0x80deb1fe
    .long   0x9bdc06a7
    .long   0xc19bf174
    .long   0xe49b69c1
    .long   0xefbe4786
    .long   0x0fc19dc6
    .long   0x240ca1cc
    .long   0x2de92c6f
    .long   0x4a7484aa
    .long   0x5cb0a9dc
    .long   0x76f988da
    .long   0x983e5152
    .long   0xa831c66d
    .long   0xb00327c8
    .long   0xbf597fc7
    .long   0xc6e00bf3
    .long   0xd5a79147
    .long   0x06ca6351
    .long   0x14292967
    .long   0x27b70a85
    .long   0x2e1b2138
    .long   0x4d2c6dfc
    .long   0x53380d13
    .long   0x650a7354
    .long   0x766a0abb
    .long   0x81c2c92e
    .long   0x92722c85
    .long   0xa2bfe8a1
    .long   0xa81a664b
    .long   0xc24b8b70
    .long   0xc76c51a3
    .long   0xd192e819
    .long   0xd6990624
    .long   0xf40e3585
    .long   0x106aa070
    .long   0x19a4c116
    .long   0x1e376c08
    .long   0x2748774c
    .long   0x34b0bcb5
    .long   0x391c0cb3
    .long   0x4ed8aa4a
    .long   0x5b9cca4f
    .long   0x682e6ff3
    .long   0x748f82ee
    .long   0x78a5636f
    .long   0x84c87814
    .long   0x8cc70208
    .long   0x90befffa
    .long   0xa4506ceb
    .long   0xbef9a3f7
    .long   0xc67178f2


    .p2align  4

	.globl _AccelerateCrypto_SHA256_compress
_AccelerateCrypto_SHA256_compress:


	#define	hashes		x0
	#define	numblocks	x1
	#define	data		x2
	#define	ktable		x3

#ifdef __ILP32__
    uxtw    numblocks, numblocks        // in arm64_32 size_t is 32-bit, so we need to extend it
#endif


	adrp	ktable, K256@page
	cbnz	numblocks, 1f						// if number of blocks is nonzero, go on for sha256 transform operation
	ret		lr							// otherwise, return
1:
	add		ktable, ktable, K256@pageoff

#if BUILDKERNEL
	// save q0-q7, q16-q24 8+8+1=19
	sub		x4, sp, #17*16
	sub		sp, sp, #17*16
	st1.4s	{v0, v1, v2, v3}, [x4], #64
	st1.4s	{v4, v5, v6, v7}, [x4], #64
	st1.4s	{v16, v17, v18, v19}, [x4], #64
	st1.4s	{v20, v21, v22, v23}, [x4], #64
	st1.4s	{v24}, [x4], #16
#endif

	ld1.4s	{v0,v1,v2,v3}, [data], #64			// w0,w1,w2,w3 need to bswap into big-endian

    rev32.16b	v0, v0					// byte swap of 1st 4 ints
    ldr         q21, [ktable, #16*0]
    rev32.16b	v1, v1					// byte swap of 2nd 4 ints
    ldr         q16, [hashes, #0]
    rev32.16b	v2, v2					// byte swap of 3rd 4 ints
    ldr         q17, [hashes, #16]
    rev32.16b	v3, v3					// byte swap of 4th 4 ints
    ldr         q22, [ktable, #16*1]

	mov.16b		v18, v16
    ldr         q23, [ktable, #16*2]
    add.4s		v4, v0, v21				// 1st 4 input + K256
    ldr         q24, [ktable, #16*3]
    add.4s		v5, v1, v22				// 2nd 4 input + K256
	mov.16b		v19, v17
    add.4s		v6, v2, v23				// 3rd 4 input + K256
    add.4s		v7, v3, v24				// 4th 4 input + K256
    add         ktable, ktable, #16*4


	.macro	sha256_round
	mov.16b		v20, v18
	SHA256SU0	$0, $1
	SHA256H		18, 19, $4
	SHA256SU1	$0, $2, $3
	SHA256H2	19, 20, $4
	add.4s		$6, $5, $7
	.endm

	// 4 vector hashes update and load next vector rounds
	.macro	sha256_hash_load_round
	mov.16b		v20, v18
	SHA256H		18, 19, $0
    rev32.16b	$1, $1
	SHA256H2	19, 20, $0
    add.4s		$2, $1, $3
	.endm

	.macro	sha256_hash_round
	mov.16b		v20, v18
	SHA256H		18, 19, $0
	SHA256H2	19, 20, $0
	.endm

	// 12 vector hash and sequence update rounds
    mov         w4, #3
L_i_loop:
    mov.16b		v20, v18
	ldr         q21, [ktable, #0]		// k0
	SHA256SU0	0, 1
	ldr         q22, [ktable, #16]		// k1
	SHA256H		18, 19, 4
	ldr         q23, [ktable, #32]		// k2
	SHA256SU1	0, 2, 3
	ldr         q24, [ktable, #48]		// k3
	SHA256H2	19, 20, 4
    add         ktable, ktable, #64
	add.4s		v4, v0, v21

	sha256_round	1, 2, 3, 0, 5, v1, v5, v22
	sha256_round	2, 3, 0, 1, 6, v2, v6, v23
    subs            w4, w4, #1
	sha256_round	3, 0, 1, 2, 7, v3, v7, v24
    b.gt            L_i_loop
    
	subs 		numblocks, numblocks, #1	// pre-decrement num_blocks by 1
	b.le		L_wrapup

	sub			ktable, ktable, #256

L_loop:

    ldr	        q0, [data, #0]
	mov.16b		v20, v18
    ldr         q21, [ktable,#0]
	SHA256H		18, 19, 4
	ldr	        q1, [data, #16]
    rev32.16b	v0, v0
	ldr	        q2, [data, #32]
	SHA256H2	19, 20, 4
	ldr	        q3, [data, #48]
    add.4s		v4, v0, v21

    ldr         q22, [ktable,#16]
	mov.16b		v20, v18
    add         data, data, #64
	SHA256H		18, 19, 5
    ldr         q23, [ktable,#32]
    rev32.16b	v1, v1
    ldr         q24, [ktable,#48]
	SHA256H2	19, 20, 5
    add.4s		v5, v1, v22

	sha256_hash_load_round	6, v2, v6, v23
	sha256_hash_load_round	7, v3, v7, v24

	add.4s		v18, v16, v18
	add.4s		v19, v17, v19
	mov.16b		v16, v18
	mov.16b		v17, v19

	// 12 vector hash and sequence update rounds
    mov.16b		v20, v18
	ldr         q21, [ktable, #16*4]		// k0
	SHA256SU0	0, 1
	ldr         q22, [ktable, #16*5]		// k1
	SHA256H		18, 19, 4
	ldr         q23, [ktable, #16*6]		// k2
	SHA256SU1	0, 2, 3
	ldr         q24, [ktable, #16*7]		// k3
	SHA256H2	19, 20, 4
	add.4s		v4, v0, v21

	sha256_round	1, 2, 3, 0, 5, v1, v5, v22
	sha256_round	2, 3, 0, 1, 6, v2, v6, v23
	sha256_round	3, 0, 1, 2, 7, v3, v7, v24
    mov.16b		v20, v18
	ldr         q21, [ktable, #16*8]		// k0
	SHA256SU0	0, 1
	ldr         q22, [ktable, #16*9]		// k1
	SHA256H		18, 19, 4
	ldr         q23, [ktable, #16*10]		// k2
	SHA256SU1	0, 2, 3
	ldr         q24, [ktable, #16*11]		// k3
	SHA256H2	19, 20, 4
	add.4s		v4, v0, v21

	sha256_round	1, 2, 3, 0, 5, v1, v5, v22
	sha256_round	2, 3, 0, 1, 6, v2, v6, v23
	sha256_round	3, 0, 1, 2, 7, v3, v7, v24

    mov.16b		v20, v18
	ldr         q21, [ktable, #16*12]		// k0
	SHA256SU0	0, 1
	ldr         q22, [ktable, #16*13]		// k1
	SHA256H		18, 19, 4
	ldr         q23, [ktable, #16*14]		// k2
	SHA256SU1	0, 2, 3
	ldr         q24, [ktable, #16*15]		// k3
	SHA256H2	19, 20, 4
	add.4s		v4, v0, v21

	sha256_round	1, 2, 3, 0, 5, v1, v5, v22
	sha256_round	2, 3, 0, 1, 6, v2, v6, v23
	sha256_round	3, 0, 1, 2, 7, v3, v7, v24

	subs 		numblocks, numblocks, #1	// pre-decrement num_blocks by 1
	b.gt		L_loop

L_wrapup:

	sha256_hash_round	4
	sha256_hash_round	5
	sha256_hash_round	6
	sha256_hash_round	7

	add.4s		v16, v16, v18
	add.4s		v17, v17, v19
	st1.4s		{v16,v17}, [hashes]					// hashes q16 : d,c,b,a   q17 : h,g,f,e

#if BUILDKERNEL
	// restore q9-q13, q0-q7, q16-q31
	ld1.4s	{v0, v1, v2, v3}, [sp], #64
	ld1.4s	{v4, v5, v6, v7}, [sp], #64
	ld1.4s	{v16, v17, v18, v19}, [sp], #64
	ld1.4s	{v20, v21, v22, v23}, [sp], #64
	ld1.4s	{v24}, [sp], #16
#endif

	ret		lr


#endif		// arm64


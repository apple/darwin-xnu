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
 * This SHA1 code is based on the basic framework from the reference
 * implementation for MD5.  That implementation is Copyright (C)
 * 1991-2, RSA Data Security, Inc. Created 1991. All rights reserved.
 *
 * License to copy and use this software is granted provided that it
 * is identified as the "RSA Data Security, Inc. MD5 Message-Digest
 * Algorithm" in all material mentioning or referencing this software
 * or this function.
 *
 * License is also granted to make and use derivative works provided
 * that such works are identified as "derived from the RSA Data
 * Security, Inc. MD5 Message-Digest Algorithm" in all material
 * mentioning or referencing the derived work.
 *
 * RSA Data Security, Inc. makes no representations concerning either
 * the merchantability of this software or the suitability of this
 * software for any particular purpose. It is provided "as is"
 * without express or implied warranty of any kind.
 *
 * These notices must be retained in any copies of any part of this
 * documentation and/or software.
 *
 * Based on the FIPS 180-1: Secure Hash Algorithm (SHA-1) available at
 * http://www.itl.nist.gov/div897/pubs/fip180-1.htm
 */

/*
	WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! WARNING!
	
	THIS FILE IS NEEDED TO PASS FIPS ACCEPTANCE FOR THE RANDOM NUMBER GENERATOR.
	IF YOU ALTER IT IN ANY WAY, WE WILL NEED TO GO THOUGH FIPS ACCEPTANCE AGAIN,
	AN OPERATION THAT IS VERY EXPENSIVE AND TIME CONSUMING.  IN OTHER WORDS,
	DON'T MESS WITH THIS FILE.

	WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! WARNING!
*/

#include <stdint.h>
#include <string.h>

#include "fips_sha1.h"

typedef int Boolean;

/* Internal mappings to the legacy sha1_ctxt structure. */
#define	state	h.b32
#define	bcount	c.b32
#define	buffer	m.b8

/*
 * The digest algorithm interprets the input message as a sequence of 32-bit
 * big-endian words.  We must reverse bytes in each word on x86/64 platforms,
 * but not on big-endian ones such as PPC.  For performance, we take advantage
 * of the bswap instruction on x86/64 to perform byte-reversal.  On PPC, we
 * could do 4-byte load if the address is 4-byte aligned which should further
 * improve the performance.  But for code simplicity, we punt and do 1-byte
 * loads instead.
 */
#if (defined(__i386__) || defined(__x86_64__)) && defined(__GNUC__)
#define	FETCH_32(p) ({							\
	u_int32_t l = (u_int32_t)*((const u_int32_t *)(p));	\
	__asm__ __volatile__("bswap %0" : "=r" (l) : "0" (l));		\
	l;								\
})
#else
#define	FETCH_32(p)							\
	(((u_int32_t)*((const u_int8_t *)(p) + 3)) |			\
	(((u_int32_t)*((const u_int8_t *)(p) + 2)) << 8) |		\
	(((u_int32_t)*((const u_int8_t *)(p) + 1)) << 16) |		\
	(((u_int32_t)*((const u_int8_t *)(p))) << 24))
#endif /* __i386__ || __x86_64__ */

/*
 * Encodes input (u_int32_t) into output (unsigned char). Assumes len is
 * a multiple of 4. This is not compatible with memcpy().
 */
static void
Encode(unsigned char *output, u_int32_t *input, unsigned int len)
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4) {
		output[j + 3] = input[i] & 0xff;
		output[j + 2] = (input[i] >> 8) & 0xff;
		output[j + 1] = (input[i] >> 16) & 0xff;
		output[j] = (input[i] >> 24) & 0xff;
	}
}

static unsigned char PADDING[64] = { 0x80, /* zeros */ };

/* Constants from FIPS 180-1 */
#define	K_00_19		0x5a827999UL
#define	K_20_39		0x6ed9eba1UL
#define	K_40_59		0x8f1bbcdcUL
#define	K_60_79		0xca62c1d6UL

/* F, G, H and I are basic SHA1 functions. */
#define	F(b, c, d)	((((c) ^ (d)) & (b)) ^ (d))
#define	G(b, c, d)	((b) ^ (c) ^ (d))
#define	H(b, c, d)	(((b) & (c)) | (((b) | (c)) & (d)))

/* ROTATE_LEFT rotates x left n bits. */
#define	ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* R, R1-R4 are macros used during each transformation round. */
#define R(f, k, v, w, x, y, z, i) {				\
	(v) = ROTATE_LEFT(w, 5) + f(x, y, z) + (v) + (i) + (k);	\
	(x) = ROTATE_LEFT(x, 30);				\
}

#define	R1(v, w, x, y, z, i)	R(F, K_00_19, v, w, x, y, z, i)
#define	R2(v, w, x, y, z, i)	R(G, K_20_39, v, w, x, y, z, i)
#define	R3(v, w, x, y, z, i)	R(H, K_40_59, v, w, x, y, z, i)
#define	R4(v, w, x, y, z, i)	R(G, K_60_79, v, w, x, y, z, i)

/* WUPDATE represents Wt variable that gets updated for steps 16-79 */
#define	WUPDATE(p, q, r, s) {		\
	(p) = ((q) ^ (r) ^ (s) ^ (p));	\
	(p) = ROTATE_LEFT(p, 1);	\
}

static void SHA1Transform(u_int32_t, u_int32_t, u_int32_t, u_int32_t,
    u_int32_t, const u_int8_t *, SHA1_CTX *);

/*
 * SHA1 initialization. Begins a SHA1 operation, writing a new context.
 */
void
FIPS_SHA1Init(SHA1_CTX *context)
{
	context->bcount[0] = context->bcount[1] = 0;
	context->count = 0;

	/* Load magic initialization constants.  */
	context->state[0] = 0x67452301UL;
	context->state[1] = 0xefcdab89UL;
	context->state[2] = 0x98badcfeUL;
	context->state[3] = 0x10325476UL;
	context->state[4] = 0xc3d2e1f0UL;
}

/*
 * SHA1 block update operation. Continues a SHA1 message-digest
 * operation, processing another message block, and updating the
 * context.
 */
void FIPS_SHA1Update(SHA1_CTX *context, const void *inpp, size_t inputLen)
{
	u_int32_t i, index, partLen;
	const unsigned char *input = (const unsigned char *)inpp;

	if (inputLen == 0)
		return;

	/* Compute number of bytes mod 64 */
	index = (context->bcount[1] >> 3) & 0x3F;

	/* Update number of bits */
	if ((context->bcount[1] += (inputLen << 3)) < (inputLen << 3))
		context->bcount[0]++;
	context->bcount[0] += (inputLen >> 29);

	partLen = 64 - index;

	/* Transform as many times as possible. */
	i = 0;
	if (inputLen >= partLen) {
		if (index != 0) {
			memcpy(&context->buffer[index], input, partLen);
			SHA1Transform(context->state[0], context->state[1],
			    context->state[2], context->state[3],
			    context->state[4], context->buffer, context);
			i = partLen;
		}

		for (; i + 63 < inputLen; i += 64)
			SHA1Transform(context->state[0], context->state[1],
			    context->state[2], context->state[3],
			    context->state[4], &input[i], context);

		if (inputLen == i)
			return;

		index = 0;
	}

	/* Buffer remaining input */
	memcpy(&context->buffer[index], &input[i], inputLen - i);
}




/*
 * This is function is only called in from the pagefault path or from page_copy().
 * So we assume that we can safely convert the virtual address to the physical address and use it.
 * Assumptions: The passed in address(inpp) is a kernel virtual address 
 * and a physical page has been faulted in. 
 * The inputLen passed in should always be less than or equal to a  page size (4096) 
 * and inpp should be on a page boundary. 
 * "performSHA1WithinKernelOnly" is initialized only when the hardware driver exists and is ready.
 */



/*
 * SHA1 finalization. Ends an SHA1 message-digest operation, writing the
 * the message digest and zeroizing the context.
 */
void
FIPS_SHA1Final(void *digest, SHA1_CTX *context)
{
	unsigned char bits[8];
	u_int32_t index = (context->bcount[1] >> 3) & 0x3f;

	/* Save number of bits */
	Encode(bits, context->bcount, 8);

	/* Pad out to 56 mod 64. */
	FIPS_SHA1Update(context, PADDING, ((index < 56) ? 56 : 120) - index);

	/* Append length (before padding) */
	FIPS_SHA1Update(context, bits, 8);

	/* Store state in digest */
	Encode(digest, context->state, 20);

	/* Zeroize sensitive information. */
	memset(context, 0, sizeof (*context));
}

/*
 * SHA1 basic transformation. Transforms state based on block.
 */
static void
SHA1Transform(u_int32_t a, u_int32_t b, u_int32_t c, u_int32_t d,
    u_int32_t e, const u_int8_t block[64], SHA1_CTX *context)
{
	/* Register (instead of array) is a win in most cases */
	u_int32_t w0, w1, w2, w3, w4, w5, w6, w7;
	u_int32_t w8, w9, w10, w11, w12, w13, w14, w15;

	w15 = FETCH_32(block + 60);
	w14 = FETCH_32(block + 56);
	w13 = FETCH_32(block + 52);
	w12 = FETCH_32(block + 48);
	w11 = FETCH_32(block + 44);
	w10 = FETCH_32(block + 40);
	w9  = FETCH_32(block + 36);
	w8  = FETCH_32(block + 32);
	w7  = FETCH_32(block + 28);
	w6  = FETCH_32(block + 24);
	w5  = FETCH_32(block + 20);
	w4  = FETCH_32(block + 16);
	w3  = FETCH_32(block + 12);
	w2  = FETCH_32(block +  8);
	w1  = FETCH_32(block +  4);
	w0  = FETCH_32(block +  0);

	/* Round 1 */
					R1(e, a, b, c, d,  w0);		/*  0 */
					R1(d, e, a, b, c,  w1);		/*  1 */
					R1(c, d, e, a, b,  w2);		/*  2 */
					R1(b, c, d, e, a,  w3);		/*  3 */
					R1(a, b, c, d, e,  w4);		/*  4 */
					R1(e, a, b, c, d,  w5);		/*  5 */
					R1(d, e, a, b, c,  w6);		/*  6 */
					R1(c, d, e, a, b,  w7);		/*  7 */
					R1(b, c, d, e, a,  w8);		/*  8 */
					R1(a, b, c, d, e,  w9);		/*  9 */
					R1(e, a, b, c, d, w10);		/* 10 */
					R1(d, e, a, b, c, w11);		/* 11 */
					R1(c, d, e, a, b, w12);		/* 12 */
					R1(b, c, d, e, a, w13);		/* 13 */
					R1(a, b, c, d, e, w14);		/* 14 */
					R1(e, a, b, c, d, w15);		/* 15 */
	WUPDATE( w0, w13,  w8,  w2);	R1(d, e, a, b, c,  w0);		/* 16 */
	WUPDATE( w1, w14,  w9,  w3);	R1(c, d, e, a, b,  w1);		/* 17 */
	WUPDATE( w2, w15, w10,  w4);	R1(b, c, d, e, a,  w2);		/* 18 */
	WUPDATE( w3,  w0, w11,  w5);	R1(a, b, c, d, e,  w3);		/* 19 */

	/* Round 2 */
	WUPDATE( w4,  w1, w12,  w6);	R2(e, a, b, c, d,  w4);		/* 20 */
	WUPDATE( w5,  w2, w13,  w7);	R2(d, e, a, b, c,  w5);		/* 21 */
	WUPDATE( w6,  w3, w14,  w8);	R2(c, d, e, a, b,  w6);		/* 22 */
	WUPDATE( w7,  w4, w15,  w9);	R2(b, c, d, e, a,  w7);		/* 23 */
	WUPDATE( w8,  w5,  w0, w10);	R2(a, b, c, d, e,  w8);		/* 24 */
	WUPDATE( w9,  w6,  w1, w11);	R2(e, a, b, c, d,  w9);		/* 25 */
	WUPDATE(w10,  w7,  w2, w12);	R2(d, e, a, b, c, w10);		/* 26 */
	WUPDATE(w11,  w8,  w3, w13);	R2(c, d, e, a, b, w11);		/* 27 */
	WUPDATE(w12,  w9,  w4, w14);	R2(b, c, d, e, a, w12);		/* 28 */
	WUPDATE(w13, w10,  w5, w15);	R2(a, b, c, d, e, w13);		/* 29 */
	WUPDATE(w14, w11,  w6,  w0);	R2(e, a, b, c, d, w14);		/* 30 */
	WUPDATE(w15, w12,  w7,  w1);	R2(d, e, a, b, c, w15);		/* 31 */
	WUPDATE( w0, w13,  w8,  w2);	R2(c, d, e, a, b,  w0);		/* 32 */
	WUPDATE( w1, w14,  w9,  w3);	R2(b, c, d, e, a,  w1);		/* 33 */
	WUPDATE( w2, w15, w10,  w4);	R2(a, b, c, d, e,  w2);		/* 34 */
	WUPDATE( w3,  w0, w11,  w5);	R2(e, a, b, c, d,  w3);		/* 35 */
	WUPDATE( w4,  w1, w12,  w6);	R2(d, e, a, b, c,  w4);		/* 36 */
	WUPDATE( w5,  w2, w13,  w7);	R2(c, d, e, a, b,  w5);		/* 37 */
	WUPDATE( w6,  w3, w14,  w8);	R2(b, c, d, e, a,  w6);		/* 38 */
	WUPDATE( w7,  w4, w15,  w9);	R2(a, b, c, d, e,  w7);		/* 39 */

	/* Round 3 */
	WUPDATE( w8,  w5,  w0, w10);	R3(e, a, b, c, d,  w8);		/* 40 */
	WUPDATE( w9,  w6,  w1, w11);	R3(d, e, a, b, c,  w9);		/* 41 */
	WUPDATE(w10,  w7,  w2, w12);	R3(c, d, e, a, b, w10);		/* 42 */
	WUPDATE(w11,  w8,  w3, w13);	R3(b, c, d, e, a, w11);		/* 43 */
	WUPDATE(w12,  w9,  w4, w14);	R3(a, b, c, d, e, w12);		/* 44 */
	WUPDATE(w13, w10,  w5, w15);	R3(e, a, b, c, d, w13);		/* 45 */
	WUPDATE(w14, w11,  w6,  w0);	R3(d, e, a, b, c, w14);		/* 46 */
	WUPDATE(w15, w12,  w7,  w1);	R3(c, d, e, a, b, w15);		/* 47 */
	WUPDATE( w0, w13,  w8,  w2);	R3(b, c, d, e, a,  w0);		/* 48 */
	WUPDATE( w1, w14,  w9,  w3);	R3(a, b, c, d, e,  w1);		/* 49 */
	WUPDATE( w2, w15, w10,  w4);	R3(e, a, b, c, d,  w2);		/* 50 */
	WUPDATE( w3,  w0, w11,  w5);	R3(d, e, a, b, c,  w3);		/* 51 */
	WUPDATE( w4,  w1, w12,  w6);	R3(c, d, e, a, b,  w4);		/* 52 */
	WUPDATE( w5,  w2, w13,  w7);	R3(b, c, d, e, a,  w5);		/* 53 */
	WUPDATE( w6,  w3, w14,  w8);	R3(a, b, c, d, e,  w6);		/* 54 */
	WUPDATE( w7,  w4, w15,  w9);	R3(e, a, b, c, d,  w7);		/* 55 */
	WUPDATE( w8,  w5,  w0, w10);	R3(d, e, a, b, c,  w8);		/* 56 */
	WUPDATE( w9,  w6,  w1, w11);	R3(c, d, e, a, b,  w9);		/* 57 */
	WUPDATE(w10,  w7,  w2, w12);	R3(b, c, d, e, a, w10);		/* 58 */
	WUPDATE(w11,  w8,  w3, w13);	R3(a, b, c, d, e, w11);		/* 59 */

	WUPDATE(w12,  w9,  w4, w14);	R4(e, a, b, c, d, w12);		/* 60 */
	WUPDATE(w13, w10,  w5, w15);	R4(d, e, a, b, c, w13);		/* 61 */
	WUPDATE(w14, w11,  w6,  w0);	R4(c, d, e, a, b, w14);		/* 62 */
	WUPDATE(w15, w12,  w7,  w1);	R4(b, c, d, e, a, w15);		/* 63 */
	WUPDATE( w0, w13,  w8,  w2);	R4(a, b, c, d, e,  w0);		/* 64 */
	WUPDATE( w1, w14,  w9,  w3);	R4(e, a, b, c, d,  w1);		/* 65 */
	WUPDATE( w2, w15, w10,  w4);	R4(d, e, a, b, c,  w2);		/* 66 */
	WUPDATE( w3,  w0, w11,  w5);	R4(c, d, e, a, b,  w3);		/* 67 */
	WUPDATE( w4,  w1, w12,  w6);	R4(b, c, d, e, a,  w4);		/* 68 */
	WUPDATE( w5,  w2, w13,  w7);	R4(a, b, c, d, e,  w5);		/* 69 */
	WUPDATE( w6,  w3, w14,  w8);	R4(e, a, b, c, d,  w6);		/* 70 */
	WUPDATE( w7,  w4, w15,  w9);	R4(d, e, a, b, c,  w7);		/* 71 */
	WUPDATE( w8,  w5,  w0, w10);	R4(c, d, e, a, b,  w8);		/* 72 */
	WUPDATE( w9,  w6,  w1, w11);	R4(b, c, d, e, a,  w9);		/* 73 */
	WUPDATE(w10,  w7,  w2, w12);	R4(a, b, c, d, e, w10);		/* 74 */
	WUPDATE(w11,  w8,  w3, w13);	R4(e, a, b, c, d, w11);		/* 75 */
	WUPDATE(w12,  w9,  w4, w14);	R4(d, e, a, b, c, w12);		/* 76 */
	WUPDATE(w13, w10,  w5, w15);	R4(c, d, e, a, b, w13);		/* 77 */
	WUPDATE(w14, w11,  w6,  w0);	R4(b, c, d, e, a, w14);		/* 78 */
	WUPDATE(w15, w12,  w7,  w1);	R4(a, b, c, d, e, w15);		/* 79 */

	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;
	context->state[4] += e;

	/* Zeroize sensitive information. */
	w15 = w14 = w13 = w12 = w11 = w10 = w9 = w8 = 0;
	w7 = w6 = w5 = w4 = w3 = w2 = w1 = w0 = 0;
}

/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
 * MD5.C - RSA Data Security, Inc., MD5 message-digest algorithm
 *
 * Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
 * rights reserved.
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
 * This code is the same as the code published by RSA Inc.  It has been
 * edited for clarity and style only.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <libkern/crypto/md5.h>

#define	memset(x, y, z)	bzero(x, z);
#define	memcpy(x, y, z)	bcopy(y, x, z)

/*
 * The digest algorithm interprets the input message as a sequence of 32-bit
 * little-endian words.  We must reverse bytes in each word on PPC and other
 * big-endian platforms, but not on little-endian ones.  When we can, we try
 * to load each word at once.  We don't quite care about alignment, since
 * x86/x64 allows us to do 4-byte loads on non 4-byte aligned addresses,
 * and on PPC we do 1-byte loads anyway.
 *
 * We could check against __LITLE_ENDIAN__ to generalize the 4-byte load
 * optimization, but that might not tell us whether or not we need 4-byte
 * aligned loads.  Since we know that __i386__ and __x86_64__ are the two
 * little-endian architectures that are not alignment-restrictive, we check
 * explicitly against them below.  Note that the byte-reversing code for
 * big-endian will still work on little-endian, albeit much slower.
 */
#if defined(__i386__) || defined(__x86_64__)
#define	FETCH_32(p)	(*(const u_int32_t *)(p))
#else
#define	FETCH_32(p)						\
	(((u_int32_t)*((const u_int8_t *)(p))) |		\
	(((u_int32_t)*((const u_int8_t *)(p) + 1)) << 8) |	\
	(((u_int32_t)*((const u_int8_t *)(p) + 2)) << 16) |	\
	(((u_int32_t)*((const u_int8_t *)(p) + 3)) << 24))
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
#if defined(__i386__) || defined(__x86_64__)
		*(u_int32_t *)(output + j) = input[i];
#else
		output[j] = input[i] & 0xff;
		output[j + 1] = (input[i] >> 8) & 0xff;
		output[j + 2] = (input[i] >> 16) & 0xff;
		output[j + 3] = (input[i] >> 24) & 0xff;
#endif /* __i386__ || __x86_64__ */
	}
}

static unsigned char PADDING[64] = { 0x80, /* zeros */ };

/* F, G, H and I are basic MD5 functions. */
#define	F(x, y, z)	((((y) ^ (z)) & (x)) ^ (z))
#define	G(x, y, z)	((((x) ^ (y)) & (z)) ^ (y))
#define	H(x, y, z)	((x) ^ (y) ^ (z))
#define	I(x, y, z)	(((~(z)) | (x)) ^ (y))

/* ROTATE_LEFT rotates x left n bits. */
#define	ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/*
 * FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
 * Rotation is separate from addition to prevent recomputation.
 */
#define	FF(a, b, c, d, x, s, ac) {					\
	(a) += F((b), (c), (d)) + (x) + (unsigned long long)(ac);	\
	(a) = ROTATE_LEFT((a), (s));					\
	(a) += (b);							\
}

#define	GG(a, b, c, d, x, s, ac) {					\
	(a) += G((b), (c), (d)) + (x) + (unsigned long long)(ac);	\
	(a) = ROTATE_LEFT((a), (s));					\
	(a) += (b);							\
}

#define	HH(a, b, c, d, x, s, ac) {					\
	(a) += H((b), (c), (d)) + (x) + (unsigned long long)(ac);	\
	(a) = ROTATE_LEFT((a), (s));					\
	(a) += (b);							\
}

#define	II(a, b, c, d, x, s, ac) {					\
	(a) += I((b), (c), (d)) + (x) + (unsigned long long)(ac);	\
	(a) = ROTATE_LEFT((a), (s));					\
	(a) += (b);							\
}

static void MD5Transform(u_int32_t, u_int32_t, u_int32_t, u_int32_t,
    const u_int8_t [64], MD5_CTX *);

/*
 * MD5 initialization. Begins an MD5 operation, writing a new context.
 */
void
MD5Init(MD5_CTX *context)
{
	context->count[0] = context->count[1] = 0;

	/* Load magic initialization constants.  */
	context->state[0] = 0x67452301UL;
	context->state[1] = 0xefcdab89UL;
	context->state[2] = 0x98badcfeUL;
	context->state[3] = 0x10325476UL;
}

/*
 * MD5 block update operation. Continues an MD5 message-digest
 * operation, processing another message block, and updating the
 * context.
 */
void
MD5Update(MD5_CTX *context, const void *inpp, unsigned int inputLen)
{
	u_int32_t i, index, partLen;
	const unsigned char *input = (const unsigned char *)inpp;

	/* Compute number of bytes mod 64 */
	index = (context->count[0] >> 3) & 0x3F;

	/* Update number of bits */
	if ((context->count[0] += (inputLen << 3)) < (inputLen << 3))
		context->count[1]++;
	context->count[1] += (inputLen >> 29);

	partLen = 64 - index;

	/* Transform as many times as possible. */
	i = 0;
	if (inputLen >= partLen) {
		if (index != 0) {
			memcpy(&context->buffer[index], input, partLen);
			MD5Transform(context->state[0], context->state[1],
			    context->state[2], context->state[3],
			    context->buffer, context);
			i = partLen;
		}

		for (; i + 63 < inputLen; i += 64)
			MD5Transform(context->state[0], context->state[1],
			    context->state[2], context->state[3],
			    &input[i], context);

		if (inputLen == i)
			return;

		index = 0;
	}

	/* Buffer remaining input */
	memcpy(&context->buffer[index], &input[i], inputLen - i);
}

/*
 * MD5 finalization. Ends an MD5 message-digest operation, writing the
 * the message digest and zeroizing the context.
 */
void
MD5Final(unsigned char digest[MD5_DIGEST_LENGTH], MD5_CTX *context)
{
	unsigned char bits[8];
	u_int32_t index = (context->count[0] >> 3) & 0x3f;

	/* Save number of bits */
	Encode(bits, context->count, 8);

	/* Pad out to 56 mod 64. */
	MD5Update(context, PADDING, ((index < 56) ? 56 : 120) - index);

	/* Append length (before padding) */
	MD5Update(context, bits, 8);

	/* Store state in digest */
	Encode(digest, context->state, 16);

	/* Zeroize sensitive information. */
	memset(context, 0, sizeof (*context));
}

/*
 * MD5 basic transformation. Transforms state based on block.
 */
static void
MD5Transform(u_int32_t a, u_int32_t b, u_int32_t c, u_int32_t d,
    const u_int8_t block[64], MD5_CTX *context)
{
	/* Register (instead of array) is a win in most cases */
	register u_int32_t x0, x1, x2, x3, x4, x5, x6, x7;
	register u_int32_t x8, x9, x10, x11, x12, x13, x14, x15;

	x15 = FETCH_32(block + 60);
	x14 = FETCH_32(block + 56);
	x13 = FETCH_32(block + 52);
	x12 = FETCH_32(block + 48);
	x11 = FETCH_32(block + 44);
	x10 = FETCH_32(block + 40);
	x9  = FETCH_32(block + 36);
	x8  = FETCH_32(block + 32);
	x7  = FETCH_32(block + 28);
	x6  = FETCH_32(block + 24);
	x5  = FETCH_32(block + 20);
	x4  = FETCH_32(block + 16);
	x3  = FETCH_32(block + 12);
	x2  = FETCH_32(block +  8);
	x1  = FETCH_32(block +  4);
	x0  = FETCH_32(block +  0);

	/* Round 1 */
#define	S11 7
#define	S12 12
#define	S13 17
#define	S14 22
	FF(a, b, c, d, x0,  S11, 0xd76aa478UL); /* 1 */
	FF(d, a, b, c, x1,  S12, 0xe8c7b756UL); /* 2 */
	FF(c, d, a, b, x2,  S13, 0x242070dbUL); /* 3 */
	FF(b, c, d, a, x3,  S14, 0xc1bdceeeUL); /* 4 */
	FF(a, b, c, d, x4,  S11, 0xf57c0fafUL); /* 5 */
	FF(d, a, b, c, x5,  S12, 0x4787c62aUL); /* 6 */
	FF(c, d, a, b, x6,  S13, 0xa8304613UL); /* 7 */
	FF(b, c, d, a, x7,  S14, 0xfd469501UL); /* 8 */
	FF(a, b, c, d, x8,  S11, 0x698098d8UL); /* 9 */
	FF(d, a, b, c, x9,  S12, 0x8b44f7afUL); /* 10 */
	FF(c, d, a, b, x10, S13, 0xffff5bb1UL); /* 11 */
	FF(b, c, d, a, x11, S14, 0x895cd7beUL); /* 12 */
	FF(a, b, c, d, x12, S11, 0x6b901122UL); /* 13 */
	FF(d, a, b, c, x13, S12, 0xfd987193UL); /* 14 */
	FF(c, d, a, b, x14, S13, 0xa679438eUL); /* 15 */
	FF(b, c, d, a, x15, S14, 0x49b40821UL); /* 16 */

	/* Round 2 */
#define	S21 5
#define	S22 9
#define	S23 14
#define	S24 20
	GG(a, b, c, d, x1,  S21, 0xf61e2562UL); /* 17 */
	GG(d, a, b, c, x6,  S22, 0xc040b340UL); /* 18 */
	GG(c, d, a, b, x11, S23, 0x265e5a51UL); /* 19 */
	GG(b, c, d, a, x0,  S24, 0xe9b6c7aaUL); /* 20 */
	GG(a, b, c, d, x5,  S21, 0xd62f105dUL); /* 21 */
	GG(d, a, b, c, x10, S22, 0x02441453UL); /* 22 */
	GG(c, d, a, b, x15, S23, 0xd8a1e681UL); /* 23 */
	GG(b, c, d, a, x4,  S24, 0xe7d3fbc8UL); /* 24 */
	GG(a, b, c, d, x9,  S21, 0x21e1cde6UL); /* 25 */
	GG(d, a, b, c, x14, S22, 0xc33707d6UL); /* 26 */
	GG(c, d, a, b, x3,  S23, 0xf4d50d87UL); /* 27 */
	GG(b, c, d, a, x8,  S24, 0x455a14edUL); /* 28 */
	GG(a, b, c, d, x13, S21, 0xa9e3e905UL); /* 29 */
	GG(d, a, b, c, x2,  S22, 0xfcefa3f8UL); /* 30 */
	GG(c, d, a, b, x7,  S23, 0x676f02d9UL); /* 31 */
	GG(b, c, d, a, x12, S24, 0x8d2a4c8aUL); /* 32 */

	/* Round 3 */
#define	S31 4
#define	S32 11
#define	S33 16
#define	S34 23
	HH(a, b, c, d, x5,  S31, 0xfffa3942UL); /* 33 */
	HH(d, a, b, c, x8,  S32, 0x8771f681UL); /* 34 */
	HH(c, d, a, b, x11, S33, 0x6d9d6122UL); /* 35 */
	HH(b, c, d, a, x14, S34, 0xfde5380cUL); /* 36 */
	HH(a, b, c, d, x1,  S31, 0xa4beea44UL); /* 37 */
	HH(d, a, b, c, x4,  S32, 0x4bdecfa9UL); /* 38 */
	HH(c, d, a, b, x7,  S33, 0xf6bb4b60UL); /* 39 */
	HH(b, c, d, a, x10, S34, 0xbebfbc70UL); /* 40 */
	HH(a, b, c, d, x13, S31, 0x289b7ec6UL); /* 41 */
	HH(d, a, b, c, x0,  S32, 0xeaa127faUL); /* 42 */
	HH(c, d, a, b, x3,  S33, 0xd4ef3085UL); /* 43 */
	HH(b, c, d, a, x6,  S34, 0x04881d05UL); /* 44 */
	HH(a, b, c, d, x9,  S31, 0xd9d4d039UL); /* 45 */
	HH(d, a, b, c, x12, S32, 0xe6db99e5UL); /* 46 */
	HH(c, d, a, b, x15, S33, 0x1fa27cf8UL); /* 47 */
	HH(b, c, d, a, x2,  S34, 0xc4ac5665UL); /* 48 */

	/* Round 4 */
#define	S41 6
#define	S42 10
#define	S43 15
#define	S44 21
	II(a, b, c, d, x0,  S41, 0xf4292244UL); /* 49 */
	II(d, a, b, c, x7,  S42, 0x432aff97UL); /* 50 */
	II(c, d, a, b, x14, S43, 0xab9423a7UL); /* 51 */
	II(b, c, d, a, x5,  S44, 0xfc93a039UL); /* 52 */
	II(a, b, c, d, x12, S41, 0x655b59c3UL); /* 53 */
	II(d, a, b, c, x3,  S42, 0x8f0ccc92UL); /* 54 */
	II(c, d, a, b, x10, S43, 0xffeff47dUL); /* 55 */
	II(b, c, d, a, x1,  S44, 0x85845dd1UL); /* 56 */
	II(a, b, c, d, x8,  S41, 0x6fa87e4fUL); /* 57 */
	II(d, a, b, c, x15, S42, 0xfe2ce6e0UL); /* 58 */
	II(c, d, a, b, x6,  S43, 0xa3014314UL); /* 59 */
	II(b, c, d, a, x13, S44, 0x4e0811a1UL); /* 60 */
	II(a, b, c, d, x4,  S41, 0xf7537e82UL); /* 61 */
	II(d, a, b, c, x11, S42, 0xbd3af235UL); /* 62 */
	II(c, d, a, b, x2,  S43, 0x2ad7d2bbUL); /* 63 */
	II(b, c, d, a, x9,  S44, 0xeb86d391UL); /* 64 */

	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;

	/* Zeroize sensitive information. */
	x15 = x14 = x13 = x12 = x11 = x10 = x9 = x8 = 0;
	x7 = x6 = x5 = x4 = x3 = x2 = x1 = x0 = 0;
}

/*
 *  ccsha256_ltc_compress.c
 *  corecrypto
 *
 *  Created on 12/03/2010
 *
 *  Copyright (c) 2010,2011,2015 Apple Inc. All rights reserved.
 *
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
 * Parts of this code adapted from LibTomCrypt
 *
 * LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

#include <corecrypto/ccsha2.h>
#include <corecrypto/cc_priv.h>
#include "ccsha2_internal.h"

#if !CC_KERNEL || !CC_USE_ASM

// Various logical functions
#define Ch(x, y, z)       (z ^ (x & (y ^ z)))
#define Maj(x, y, z)      (((x | y) & z) | (x & y))
#define S(x, n)         ror((x),(n))
#define R(x, n)         ((x)>>(n))

#define Sigma0(x)       (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x)       (S(x, 6) ^ S(x, 11) ^ S(x, 25))

#define Gamma0(x)       (S(x, 7)  ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x)       (S(x, 17) ^ S(x, 19) ^ R(x, 10))

//It is beter if the following macros are defined as inline functions,
//but I found some compilers do not inline them.
#ifdef __CC_ARM
    #define ror(val, shift) __ror(val,shift)
#else
    #define ror(val, shift) ((val >> shift) | (val << (32 - shift)))
#endif

#ifdef __CC_ARM
    #define byte_swap32(x) __rev(x)
#elif defined(__clang__) && !defined(_MSC_VER)
    #define byte_swap32(x) __builtin_bswap32(x);
#else
   #define byte_swap32(x) ((ror(x, 8) & 0xff00ff00) | (ror(x, 24) & 0x00ff00ff))
#endif

#if CC_HANDLE_UNALIGNED_DATA
    #define set_W(i) CC_LOAD32_BE(W[i], buf + (4*(i)))
#else
    #define set_W(i) W[i] = byte_swap32(buf[i])
#endif

// the round function
#define RND(a, b, c, d, e, f, g, h, i)                                 \
    t0 = h + Sigma1(e) + Ch(e, f, g) + ccsha256_K[i] + W[i];   \
    t1 = Sigma0(a) + Maj(a, b, c);                             \
    d += t0;                                                   \
    h  = t0 + t1;

// compress 512-bits
void
ccsha256_ltc_compress(ccdigest_state_t state, size_t nblocks, const void *in)
{
	uint32_t W[64], t0, t1;
	uint32_t S0, S1, S2, S3, S4, S5, S6, S7;
	int i;
	uint32_t *s = ccdigest_u32(state);
#if CC_HANDLE_UNALIGNED_DATA
	const unsigned char *buf = in;
#else
	const uint32_t *buf = in;
#endif

	while (nblocks--) {
		// schedule W 0..15
		set_W(0); set_W(1); set_W(2); set_W(3); set_W(4); set_W(5); set_W(6); set_W(7);
		set_W(8); set_W(9); set_W(10); set_W(11); set_W(12); set_W(13); set_W(14); set_W(15);

		// schedule W 16..63
		for (i = 16; i < 64; i++) {
			W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
		}

		// copy state into S
		S0 = s[0];
		S1 = s[1];
		S2 = s[2];
		S3 = s[3];
		S4 = s[4];
		S5 = s[5];
		S6 = s[6];
		S7 = s[7];

		// Compress
		for (i = 0; i < 64; i += 8) {
			RND(S0, S1, S2, S3, S4, S5, S6, S7, i + 0);
			RND(S7, S0, S1, S2, S3, S4, S5, S6, i + 1);
			RND(S6, S7, S0, S1, S2, S3, S4, S5, i + 2);
			RND(S5, S6, S7, S0, S1, S2, S3, S4, i + 3);
			RND(S4, S5, S6, S7, S0, S1, S2, S3, i + 4);
			RND(S3, S4, S5, S6, S7, S0, S1, S2, i + 5);
			RND(S2, S3, S4, S5, S6, S7, S0, S1, i + 6);
			RND(S1, S2, S3, S4, S5, S6, S7, S0, i + 7);
		}

		// feedback
		s[0] += S0;
		s[1] += S1;
		s[2] += S2;
		s[3] += S3;
		s[4] += S4;
		s[5] += S5;
		s[6] += S6;
		s[7] += S7;

		buf += CCSHA256_BLOCK_SIZE / sizeof(buf[0]);
	}
}

#endif

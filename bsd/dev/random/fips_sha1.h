/*
 * Copyright (c) 2000-2009 Apple, Inc. All rights reserved.
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
	WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! WARNING!
	
	THIS FILE IS NEEDED TO PASS FIPS ACCEPTANCE FOR THE RANDOM NUMBER GENERATOR.
	IF YOU ALTER IT IN ANY WAY, WE WILL NEED TO GO THOUGH FIPS ACCEPTANCE AGAIN,
	AN OPERATION THAT IS VERY EXPENSIVE AND TIME CONSUMING.  IN OTHER WORDS,
	DON'T MESS WITH THIS FILE.

	WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! WARNING!
*/

#ifndef _CRYPTO_FIPS_SHA1_H_
#define	_CRYPTO_FIPS_SHA1_H_

#ifdef  __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define	SHA_DIGEST_LENGTH	20
#define	SHA1_RESULTLEN		SHA_DIGEST_LENGTH

typedef struct sha1_ctxt {
	union {
		u_int8_t	b8[20];
		u_int32_t	b32[5];	/* state (ABCDE) */
	} h;
	union {
		u_int8_t	b8[8];
		u_int32_t	b32[2];
		u_int64_t	b64[1];	/* # of bits, modulo 2^64 (msb first) */
	} c;
	union {
		u_int8_t	b8[64];
		u_int32_t	b32[16]; /* input buffer */
	} m;
	u_int8_t	count;		/* unused; for compatibility only */
} SHA1_CTX;

extern void FIPS_SHA1Init(SHA1_CTX *);
extern void FIPS_SHA1Update(SHA1_CTX *, const void *, size_t);
extern void FIPS_SHA1Final(void *, SHA1_CTX *);

#ifdef  __cplusplus
}
#endif

#endif /*_CRYPTO_SHA1_H_*/

/*
 * Copyright (c) 1999, 2000-2001 Apple Computer, Inc. All rights reserved.
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
SHA-1 in C
By Steve Reid <steve@edmweb.com>
100% Public Domain
*/
/* Header portion split from main code for convenience (AYB 3/02/98) */

#ifndef __SHA1_H__

#define __SHA1_H__

/*
Test Vectors (from FIPS PUB 180-1)
"abc"
  A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D
"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1
A million repetitions of "a"
  34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F
*/

/* Apple change - define this in the source file which uses it */
/* #define LITTLE_ENDIAN  This should be #define'd if true. */
#define SHA1HANDSOFF /* Copies data before messing with it. */

//Context declaration
typedef struct {
    unsigned long state[5];
    unsigned long count[2];
    unsigned char buffer[64];
} YSHA1_CTX;

//Function forward declerations
__private_extern__ void YSHA1Transform(unsigned long state[5],
    const unsigned char buffer[64]);
__private_extern__ void YSHA1Init(YSHA1_CTX* context);
__private_extern__ void YSHA1Update(YSHA1_CTX* context,
    const unsigned char* data, unsigned int len);
__private_extern__ void YSHA1Final(unsigned char digest[20],
    YSHA1_CTX* context);

#endif	/* __SHA1_H__ */

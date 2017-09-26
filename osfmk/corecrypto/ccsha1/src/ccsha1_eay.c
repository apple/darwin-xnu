/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
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


#include <corecrypto/ccsha1.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccdigest_priv.h>


#ifndef SHA_LONG_LOG2
#define SHA_LONG_LOG2	2	/* default to 32 bits */
#endif


#define ROTATE(b, n) CC_ROLc(b, n)

#define Xupdate(a,ix,ia,ib,ic,id)	( (a)=(ia^ib^ic^id),	\
					  ix=(a)=ROTATE((a),1)	\
					)

#define MD32_REG_T uint32_t

#define HOST_c2l(data, l) CC_LOAD32_BE(l, data); data+=4;

#define K_00_19	0x5a827999
#define K_20_39 0x6ed9eba1
#define K_40_59 0x8f1bbcdc
#define K_60_79 0xca62c1d6

/* As  pointed out by Wei Dai <weidai@eskimo.com>, F() below can be
 * simplified to the code in F_00_19.  Wei attributes these optimisations
 * to Peter Gutmann's SHS code, and he attributes it to Rich Schroeppel.
 * #define F(x,y,z) (((x) & (y))  |  ((~(x)) & (z)))
 * I've just become aware of another tweak to be made, again from Wei Dai,
 * in F_40_59, (x&a)|(y&a) -> (x|y)&a
 */
#define	F_00_19(b,c,d)	((((c) ^ (d)) & (b)) ^ (d))
#define	F_20_39(b,c,d)	((b) ^ (c) ^ (d))
#define F_40_59(b,c,d)	(((b) & (c)) | (((b)|(c)) & (d)))
#define	F_60_79(b,c,d)	F_20_39(b,c,d)

#define BODY_00_15(i,a,b,c,d,e,f,xi) \
	(f)=xi+(e)+K_00_19+ROTATE((a),5)+F_00_19((b),(c),(d)); \
	(b)=ROTATE((b),30);

#define BODY_16_19(i,a,b,c,d,e,f,xi,xa,xb,xc,xd) \
	Xupdate(f,xi,xa,xb,xc,xd); \
	(f)+=(e)+K_00_19+ROTATE((a),5)+F_00_19((b),(c),(d)); \
	(b)=ROTATE((b),30);

#define BODY_20_31(i,a,b,c,d,e,f,xi,xa,xb,xc,xd) \
	Xupdate(f,xi,xa,xb,xc,xd); \
	(f)+=(e)+K_20_39+ROTATE((a),5)+F_20_39((b),(c),(d)); \
	(b)=ROTATE((b),30);

#define BODY_32_39(i,a,b,c,d,e,f,xa,xb,xc,xd) \
	Xupdate(f,xa,xa,xb,xc,xd); \
	(f)+=(e)+K_20_39+ROTATE((a),5)+F_20_39((b),(c),(d)); \
	(b)=ROTATE((b),30);

#define BODY_40_59(i,a,b,c,d,e,f,xa,xb,xc,xd) \
	Xupdate(f,xa,xa,xb,xc,xd); \
	(f)+=(e)+K_40_59+ROTATE((a),5)+F_40_59((b),(c),(d)); \
	(b)=ROTATE((b),30);

#define BODY_60_79(i,a,b,c,d,e,f,xa,xb,xc,xd) \
	Xupdate(f,xa,xa,xb,xc,xd); \
	(f)=xa+(e)+K_60_79+ROTATE((a),5)+F_60_79((b),(c),(d)); \
	(b)=ROTATE((b),30);

#ifdef X
#undef X
#endif

#ifndef MD32_XARRAY
  /*
   * Originally X was an array. As it's automatic it's natural
   * to expect RISC compiler to accomodate at least part of it in
   * the register bank, isn't it? Unfortunately not all compilers
   * "find" this expectation reasonable:-( On order to make such
   * compilers generate better code I replace X[] with a bunch of
   * X0, X1, etc. See the function body below...
   *					<appro@fy.chalmers.se>
   */
# define X(i)	XX##i
#else
  /*
   * However! Some compilers (most notably HP C) get overwhelmed by
   * that many local variables so that we have to have the way to
   * fall down to the original behavior.
   */
# define X(i)	XX[i]
#endif

static void sha1_compress(ccdigest_state_t s, size_t num, const void *buf)
{
	const unsigned char *data=buf;
    register uint32_t A,B,C,D,E,T,l;
#ifndef MD32_XARRAY
	uint32_t    XX0, XX1, XX2, XX3, XX4, XX5, XX6, XX7,
				XX8, XX9,XX10,XX11,XX12,XX13,XX14,XX15;
#else
	uint32_t    XX[16];
#endif
    uint32_t *state=ccdigest_u32(s);

	A=state[0];
	B=state[1];
	C=state[2];
	D=state[3];
	E=state[4];

	for (;;)
		{

	HOST_c2l(data,l); X( 0)=l;		HOST_c2l(data,l); X( 1)=l;
	BODY_00_15( 0,A,B,C,D,E,T,X( 0));	HOST_c2l(data,l); X( 2)=l;
	BODY_00_15( 1,T,A,B,C,D,E,X( 1));	HOST_c2l(data,l); X( 3)=l;
	BODY_00_15( 2,E,T,A,B,C,D,X( 2));	HOST_c2l(data,l); X( 4)=l;
	BODY_00_15( 3,D,E,T,A,B,C,X( 3));	HOST_c2l(data,l); X( 5)=l;
	BODY_00_15( 4,C,D,E,T,A,B,X( 4));	HOST_c2l(data,l); X( 6)=l;
	BODY_00_15( 5,B,C,D,E,T,A,X( 5));	HOST_c2l(data,l); X( 7)=l;
	BODY_00_15( 6,A,B,C,D,E,T,X( 6));	HOST_c2l(data,l); X( 8)=l;
	BODY_00_15( 7,T,A,B,C,D,E,X( 7));	HOST_c2l(data,l); X( 9)=l;
	BODY_00_15( 8,E,T,A,B,C,D,X( 8));	HOST_c2l(data,l); X(10)=l;
	BODY_00_15( 9,D,E,T,A,B,C,X( 9));	HOST_c2l(data,l); X(11)=l;
	BODY_00_15(10,C,D,E,T,A,B,X(10));	HOST_c2l(data,l); X(12)=l;
	BODY_00_15(11,B,C,D,E,T,A,X(11));	HOST_c2l(data,l); X(13)=l;
	BODY_00_15(12,A,B,C,D,E,T,X(12));	HOST_c2l(data,l); X(14)=l;
	BODY_00_15(13,T,A,B,C,D,E,X(13));	HOST_c2l(data,l); X(15)=l;
	BODY_00_15(14,E,T,A,B,C,D,X(14));
	BODY_00_15(15,D,E,T,A,B,C,X(15));

	BODY_16_19(16,C,D,E,T,A,B,X( 0),X( 0),X( 2),X( 8),X(13));
	BODY_16_19(17,B,C,D,E,T,A,X( 1),X( 1),X( 3),X( 9),X(14));
	BODY_16_19(18,A,B,C,D,E,T,X( 2),X( 2),X( 4),X(10),X(15));
	BODY_16_19(19,T,A,B,C,D,E,X( 3),X( 3),X( 5),X(11),X( 0));

	BODY_20_31(20,E,T,A,B,C,D,X( 4),X( 4),X( 6),X(12),X( 1));
	BODY_20_31(21,D,E,T,A,B,C,X( 5),X( 5),X( 7),X(13),X( 2));
	BODY_20_31(22,C,D,E,T,A,B,X( 6),X( 6),X( 8),X(14),X( 3));
	BODY_20_31(23,B,C,D,E,T,A,X( 7),X( 7),X( 9),X(15),X( 4));
	BODY_20_31(24,A,B,C,D,E,T,X( 8),X( 8),X(10),X( 0),X( 5));
	BODY_20_31(25,T,A,B,C,D,E,X( 9),X( 9),X(11),X( 1),X( 6));
	BODY_20_31(26,E,T,A,B,C,D,X(10),X(10),X(12),X( 2),X( 7));
	BODY_20_31(27,D,E,T,A,B,C,X(11),X(11),X(13),X( 3),X( 8));
	BODY_20_31(28,C,D,E,T,A,B,X(12),X(12),X(14),X( 4),X( 9));
	BODY_20_31(29,B,C,D,E,T,A,X(13),X(13),X(15),X( 5),X(10));
	BODY_20_31(30,A,B,C,D,E,T,X(14),X(14),X( 0),X( 6),X(11));
	BODY_20_31(31,T,A,B,C,D,E,X(15),X(15),X( 1),X( 7),X(12));

	BODY_32_39(32,E,T,A,B,C,D,X( 0),X( 2),X( 8),X(13));
	BODY_32_39(33,D,E,T,A,B,C,X( 1),X( 3),X( 9),X(14));
	BODY_32_39(34,C,D,E,T,A,B,X( 2),X( 4),X(10),X(15));
	BODY_32_39(35,B,C,D,E,T,A,X( 3),X( 5),X(11),X( 0));
	BODY_32_39(36,A,B,C,D,E,T,X( 4),X( 6),X(12),X( 1));
	BODY_32_39(37,T,A,B,C,D,E,X( 5),X( 7),X(13),X( 2));
	BODY_32_39(38,E,T,A,B,C,D,X( 6),X( 8),X(14),X( 3));
	BODY_32_39(39,D,E,T,A,B,C,X( 7),X( 9),X(15),X( 4));

	BODY_40_59(40,C,D,E,T,A,B,X( 8),X(10),X( 0),X( 5));
	BODY_40_59(41,B,C,D,E,T,A,X( 9),X(11),X( 1),X( 6));
	BODY_40_59(42,A,B,C,D,E,T,X(10),X(12),X( 2),X( 7));
	BODY_40_59(43,T,A,B,C,D,E,X(11),X(13),X( 3),X( 8));
	BODY_40_59(44,E,T,A,B,C,D,X(12),X(14),X( 4),X( 9));
	BODY_40_59(45,D,E,T,A,B,C,X(13),X(15),X( 5),X(10));
	BODY_40_59(46,C,D,E,T,A,B,X(14),X( 0),X( 6),X(11));
	BODY_40_59(47,B,C,D,E,T,A,X(15),X( 1),X( 7),X(12));
	BODY_40_59(48,A,B,C,D,E,T,X( 0),X( 2),X( 8),X(13));
	BODY_40_59(49,T,A,B,C,D,E,X( 1),X( 3),X( 9),X(14));
	BODY_40_59(50,E,T,A,B,C,D,X( 2),X( 4),X(10),X(15));
	BODY_40_59(51,D,E,T,A,B,C,X( 3),X( 5),X(11),X( 0));
	BODY_40_59(52,C,D,E,T,A,B,X( 4),X( 6),X(12),X( 1));
	BODY_40_59(53,B,C,D,E,T,A,X( 5),X( 7),X(13),X( 2));
	BODY_40_59(54,A,B,C,D,E,T,X( 6),X( 8),X(14),X( 3));
	BODY_40_59(55,T,A,B,C,D,E,X( 7),X( 9),X(15),X( 4));
	BODY_40_59(56,E,T,A,B,C,D,X( 8),X(10),X( 0),X( 5));
	BODY_40_59(57,D,E,T,A,B,C,X( 9),X(11),X( 1),X( 6));
	BODY_40_59(58,C,D,E,T,A,B,X(10),X(12),X( 2),X( 7));
	BODY_40_59(59,B,C,D,E,T,A,X(11),X(13),X( 3),X( 8));

	BODY_60_79(60,A,B,C,D,E,T,X(12),X(14),X( 4),X( 9));
	BODY_60_79(61,T,A,B,C,D,E,X(13),X(15),X( 5),X(10));
	BODY_60_79(62,E,T,A,B,C,D,X(14),X( 0),X( 6),X(11));
	BODY_60_79(63,D,E,T,A,B,C,X(15),X( 1),X( 7),X(12));
	BODY_60_79(64,C,D,E,T,A,B,X( 0),X( 2),X( 8),X(13));
	BODY_60_79(65,B,C,D,E,T,A,X( 1),X( 3),X( 9),X(14));
	BODY_60_79(66,A,B,C,D,E,T,X( 2),X( 4),X(10),X(15));
	BODY_60_79(67,T,A,B,C,D,E,X( 3),X( 5),X(11),X( 0));
	BODY_60_79(68,E,T,A,B,C,D,X( 4),X( 6),X(12),X( 1));
	BODY_60_79(69,D,E,T,A,B,C,X( 5),X( 7),X(13),X( 2));
	BODY_60_79(70,C,D,E,T,A,B,X( 6),X( 8),X(14),X( 3));
	BODY_60_79(71,B,C,D,E,T,A,X( 7),X( 9),X(15),X( 4));
	BODY_60_79(72,A,B,C,D,E,T,X( 8),X(10),X( 0),X( 5));
	BODY_60_79(73,T,A,B,C,D,E,X( 9),X(11),X( 1),X( 6));
	BODY_60_79(74,E,T,A,B,C,D,X(10),X(12),X( 2),X( 7));
	BODY_60_79(75,D,E,T,A,B,C,X(11),X(13),X( 3),X( 8));
	BODY_60_79(76,C,D,E,T,A,B,X(12),X(14),X( 4),X( 9));
	BODY_60_79(77,B,C,D,E,T,A,X(13),X(15),X( 5),X(10));
	BODY_60_79(78,A,B,C,D,E,T,X(14),X( 0),X( 6),X(11));
	BODY_60_79(79,T,A,B,C,D,E,X(15),X( 1),X( 7),X(12));

	state[0]=(state[0]+E)&0xffffffff;
	state[1]=(state[1]+T)&0xffffffff;
	state[2]=(state[2]+A)&0xffffffff;
	state[3]=(state[3]+B)&0xffffffff;
	state[4]=(state[4]+C)&0xffffffff;

	if (--num <= 0) break;

	A=state[0];
	B=state[1];
	C=state[2];
	D=state[3];
	E=state[4];

	}
}

const struct ccdigest_info ccsha1_eay_di = {
    .output_size = CCSHA1_OUTPUT_SIZE,
    .state_size = CCSHA1_STATE_SIZE,
    .block_size = CCSHA1_BLOCK_SIZE,
    .oid_size = ccoid_sha1_len,
    .oid = CC_DIGEST_OID_SHA1,
    .initial_state = ccsha1_initial_state,
    .compress = sha1_compress,
    .final = ccdigest_final_64be,
};

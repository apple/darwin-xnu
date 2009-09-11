/*
 * Copyright (c) 2008 Apple Inc. All rights reserved.
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
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "nfs_gss_crypto.h"


/*
n-fold(k-bits):
  l = lcm(n,k)
  r = l/k
  s = k-bits | k-bits rot 13 | k-bits rot 13*2 | ... | k-bits rot 13*(r-1)
  compute the 1's complement sum:
	n-fold = s[0..n-1]+s[n..2n-1]+s[2n..3n-1]+..+s[(k-1)*n..k*n-1]
*/

/* representation: msb first, assume n and k are multiples of 8, and
   that k>=16.  this is the case of all the cryptosystems which are
   likely to be used.  this function can be replaced if that
   assumption ever fails.  */

/* input length is in bits */

void
krb5_nfold(unsigned int inbits, const unsigned char *in, unsigned int outbits,
	   unsigned char *out)
{
    int a,b,c,lcm;
    int byte, i, msbit;

    /* the code below is more readable if I make these bytes
       instead of bits */

    inbits >>= 3;
    outbits >>= 3;

    /* first compute lcm(n,k) */

    a = outbits;
    b = inbits;

    while(b != 0) {
	c = b;
	b = a%b;
	a = c;
    }

    lcm = outbits*inbits/a;

    /* now do the real work */

    memset(out, 0, outbits);
    byte = 0;

    /* this will end up cycling through k lcm(k,n)/k times, which
       is correct */
    for (i=lcm-1; i>=0; i--) {
	/* compute the msbit in k which gets added into this byte */
	msbit = (/* first, start with the msbit in the first, unrotated
		    byte */
		 ((inbits<<3)-1)
		 /* then, for each byte, shift to the right for each
		    repetition */
		 +(((inbits<<3)+13)*(i/inbits))
		 /* last, pick out the correct byte within that
		    shifted repetition */
		 +((inbits-(i%inbits))<<3)
		 )%(inbits<<3);

	/* pull out the byte value itself */
	byte += (((in[((inbits-1)-(msbit>>3))%inbits]<<8)|
		  (in[((inbits)-(msbit>>3))%inbits]))
		 >>((msbit&7)+1))&0xff;

	/* do the addition */
	byte += out[i%outbits];
	out[i%outbits] = byte&0xff;

#if 0
	printf("msbit[%d] = %d\tbyte = %02x\tsum = %03x\n", i, msbit,
	       (((in[((inbits-1)-(msbit>>3))%inbits]<<8)|
		 (in[((inbits)-(msbit>>3))%inbits]))
		>>((msbit&7)+1))&0xff, byte);
#endif

	/* keep around the carry bit, if any */
	byte >>= 8;

#if 0
	printf("carry=%d\n", byte);
#endif
    }

    /* if there's a carry bit left over, add it back in */
    if (byte) {
	for (i=outbits-1; i>=0; i--) {
	    /* do the addition */
	    byte += out[i];
	    out[i] = byte&0xff;

	    /* keep around the carry bit, if any */
	    byte >>= 8;
	}
    }
}

/*
 * Given 21 bytes of random bits, make a triple DES key.
 */

void
des3_make_key(const unsigned char randombits[21], des_cblock key[3])
{
	int i;
	
	for (i = 0; i < 3; i++) {
		memcpy(&key[i], &randombits[i*7], 7);
		key[i][7] = (((key[i][0] & 1) << 1) |
			     ((key[i][1] & 1) << 2) |
			     ((key[i][2] & 1) << 3) |
			     ((key[i][3] & 1) << 4) |
			     ((key[i][4] & 1) << 5) |
			     ((key[i][5] & 1) << 6) |
			     ((key[i][6] & 1) << 7));
		des_fixup_key_parity(&key[i]);
	}
}

/*
 * Make a triple des key schedule, from a triple des key.
 */
 
int
des3_key_sched(des_cblock key[3], des_key_schedule sched[3])
{
	int i;
	int rc = 0;
	
	for (i = 0; i < 3; i++)
		rc |= des_key_sched(&key[i], sched[i]);

	return (rc);
}

/*
 * Triple DES cipher block chaining mode encryption.
 */
 
void
des3_cbc_encrypt(des_cblock *input, des_cblock *output, int32_t length, 
		 des_key_schedule schedule[3], des_cblock *ivec, des_cblock *retvec, int encrypt)
{
	register DES_LONG tin0,tin1;
	register DES_LONG tout0,tout1,xor0,xor1;
	register unsigned char *in,*out,*retval;
	register int32_t l=length;
	DES_LONG tin[2];
	unsigned char *iv;
	tin0 = tin1 = 0;

	in=(unsigned char *)input;
	out=(unsigned char *)output;
	retval=(unsigned char *)retvec;
	iv=(unsigned char *)ivec;

	if (encrypt) {
		c2l(iv,tout0);
		c2l(iv,tout1);
		for (l-=8; l>=0; l-=8) {
			c2l(in,tin0);
			c2l(in,tin1);
			tin0^=tout0; tin[0]=tin0;
			tin1^=tout1; tin[1]=tin1;
			des_encrypt3((DES_LONG *)tin,schedule[0], schedule[1], schedule[2]);
			tout0=tin[0]; l2c(tout0,out);
			tout1=tin[1]; l2c(tout1,out);
		}
		if (l != -8) {
			c2ln(in,tin0,tin1,l+8);
			tin0^=tout0; tin[0]=tin0;
			tin1^=tout1; tin[1]=tin1;
			des_encrypt3((DES_LONG *)tin,schedule[0], schedule[1], schedule[2]);
			tout0=tin[0]; l2c(tout0,out);
			tout1=tin[1]; l2c(tout1,out);
		}
		if (retval) {
			l2c(tout0,retval);
			l2c(tout1,retval);
		}
	} else {
		c2l(iv,xor0);
		c2l(iv,xor1);
		for (l-=8; l>=0; l-=8) {
			c2l(in,tin0); tin[0]=tin0;
			c2l(in,tin1); tin[1]=tin1;
			des_decrypt3((DES_LONG *)tin,schedule[0],schedule[1],schedule[2]);
			tout0=tin[0]^xor0;
			tout1=tin[1]^xor1;
			l2c(tout0,out);
			l2c(tout1,out);
			xor0=tin0;
			xor1=tin1;
		}
		if (l != -8) {
			c2l(in,tin0); tin[0]=tin0;
			c2l(in,tin1); tin[1]=tin1;
			des_decrypt3((DES_LONG *)tin,schedule[0],schedule[1],schedule[2]);
			tout0=tin[0]^xor0;
			tout1=tin[1]^xor1;
			l2cn(tout0,tout1,out,l+8);
		/*	xor0=tin0;
			xor1=tin1; */
		}
		if (retval) {
			l2c(tin0,retval);
			l2c(tin1,retval);
		}
	}
	tin0=tin1=tout0=tout1=xor0=xor1=0;
	tin[0]=tin[1]=0;
}

/*
 * Key derivation for triple DES.
 * Given the session key in in key, produce a new key in out key using
 * the supplied constant.
 */
 
int
des3_derive_key(des_cblock inkey[3], des_cblock outkey[3],
		const unsigned char *constant, int clen)
{
	des_cblock inblock, outblock, ivec;
	des_key_schedule sched[3];
	unsigned char rawkey[21];
	size_t n, keybytes = sizeof(rawkey);

	/* initialize the input block */

	if (clen == sizeof(des_cblock)) {
		memcpy(inblock, constant, clen);
	} else {
		krb5_nfold(clen*8, constant, sizeof(des_cblock)*8, inblock);
	}

	/* loop encrypting the blocks until enough key bytes are generated */

	bzero(ivec, sizeof(ivec));
	des3_key_sched(inkey, sched);
	for (n = 0; n < sizeof(rawkey); n += sizeof(des_cblock)) {
		des3_cbc_encrypt(&inblock, &outblock, sizeof(outblock), sched, &ivec, NULL, 1);
		if ((keybytes - n) <= sizeof (des_cblock)) {
			memcpy(rawkey+n, outblock, (keybytes - n));
			break;
		}
		memcpy(rawkey+n, outblock, sizeof(des_cblock));
		memcpy(inblock, outblock, sizeof(des_cblock));
	}

	/* postprocess the key */
	des3_make_key(rawkey, outkey);

	/* clean memory, free resources and exit */

	bzero(inblock, sizeof (des_cblock));
	bzero(outblock, sizeof (des_cblock));
	bzero(rawkey, keybytes);
	bzero(sched, sizeof (sched));

	return(0);
}

/*
 * Initialize a context for HMAC SHA1
 * if drived is true we derive a new key
 * based on KG_USAGE_SIGN
 */
 
void
HMAC_SHA1_DES3KD_Init(HMAC_SHA1_DES3KD_CTX *ctx, des_cblock key[3], int derive)
{
	unsigned char ipad[64];
	size_t i, j;
	
	SHA1Init(&ctx->sha1_ctx);
	if (derive)
		des3_derive_key(key, ctx->dk, KEY_USAGE_DES3_SIGN, KEY_USAGE_LEN);
	else
		memcpy(ctx->dk, key, 3*sizeof(des_cblock));
	memset(ipad, 0x36, sizeof(ipad));
	for (i = 0; i < 3; i++)
		for (j = 0; j < sizeof(des_cblock); j++)
			ipad[j + i * sizeof(des_cblock)] ^= ctx->dk[i][j];
	SHA1Update(&ctx->sha1_ctx, ipad, sizeof(ipad));
}

/*
 * Update the HMAC SHA1 context with the supplied data.
 */
void
HMAC_SHA1_DES3KD_Update(HMAC_SHA1_DES3KD_CTX *ctx, void *data, size_t len)
{
	SHA1Update(&ctx->sha1_ctx, data, len);
}

/*
 * Finish the context and produce the HMAC SHA1 digest.
 */
 
void
HMAC_SHA1_DES3KD_Final(void *digest, HMAC_SHA1_DES3KD_CTX *ctx)
{
	unsigned char opad[64];
	size_t i, j;

	SHA1Final(digest, &ctx->sha1_ctx);
	memset(opad, 0x5c, sizeof(opad));
	for (i = 0; i < 3; i++)
		for (j = 0; j < sizeof(des_cblock); j++)
			opad[j + i * sizeof(des_cblock)] ^= ctx->dk[i][j];
	SHA1Init(&ctx->sha1_ctx);
	SHA1Update(&ctx->sha1_ctx, opad, sizeof(opad));
	SHA1Update(&ctx->sha1_ctx, digest, SHA1_RESULTLEN);
	SHA1Final(digest, &ctx->sha1_ctx);
}

/*
 * XXX This function borrowed from OpenBSD.
 * It will likely be moved into kernel crypto.
 */
DES_LONG
des_cbc_cksum(des_cblock *input, des_cblock *output,
		int32_t length, des_key_schedule schedule, des_cblock *ivec)
{
	register DES_LONG tout0,tout1,tin0,tin1;
	register int32_t l=length;
	DES_LONG tin[2];
	unsigned char *in,*out,*iv;

	in=(unsigned char *)input;
	out=(unsigned char *)output;
	iv=(unsigned char *)ivec;

	c2l(iv,tout0);
	c2l(iv,tout1);
	for (; l>0; l-=8) {
		if (l >= 8) {
			c2l(in,tin0);
			c2l(in,tin1);
		} else
			c2ln(in,tin0,tin1,l);
			
		tin0^=tout0; tin[0]=tin0;
		tin1^=tout1; tin[1]=tin1;
		des_encrypt1((DES_LONG *)tin,schedule,DES_ENCRYPT);
		/* fix 15/10/91 eay - thanks to keithr@sco.COM */
		tout0=tin[0];
		tout1=tin[1];
	}
	if (out != NULL) {
		l2c(tout0,out);
		l2c(tout1,out);
	}
	tout0=tin0=tin1=tin[0]=tin[1]=0;
	return(tout1);
}

/*
 * XXX This function borrowed from OpenBSD.
 * It will likely be moved into kernel crypto.
 */
void
des_cbc_encrypt(des_cblock *input, des_cblock *output, int32_t length,
		des_key_schedule schedule, des_cblock *ivec, des_cblock *retvec, int encrypt)
{
	register DES_LONG tin0,tin1;
	register DES_LONG tout0,tout1,xor0,xor1;
	register unsigned char *in,*out,*retval;
	register int32_t l=length;
	DES_LONG tin[2];
	unsigned char *iv;
	tin0 = tin1 = 0;

	in=(unsigned char *)input;
	out=(unsigned char *)output;
	retval=(unsigned char *)retvec;
	iv=(unsigned char *)ivec;

	if (encrypt) {
		c2l(iv,tout0);
		c2l(iv,tout1);
		for (l-=8; l>=0; l-=8) {
			c2l(in,tin0);
			c2l(in,tin1);
			tin0^=tout0; tin[0]=tin0;
			tin1^=tout1; tin[1]=tin1;
			des_encrypt1((DES_LONG *)tin,schedule,DES_ENCRYPT);
			tout0=tin[0]; l2c(tout0,out);
			tout1=tin[1]; l2c(tout1,out);
		}
		if (l != -8) {
			c2ln(in,tin0,tin1,l+8);
			tin0^=tout0; tin[0]=tin0;
			tin1^=tout1; tin[1]=tin1;
			des_encrypt1((DES_LONG *)tin,schedule,DES_ENCRYPT);
			tout0=tin[0]; l2c(tout0,out);
			tout1=tin[1]; l2c(tout1,out);
		}
		if (retval) {
			l2c(tout0,retval);
			l2c(tout1,retval);
		}
	} else {
		c2l(iv,xor0);
		c2l(iv,xor1);
		for (l-=8; l>=0; l-=8) {
			c2l(in,tin0); tin[0]=tin0;
			c2l(in,tin1); tin[1]=tin1;
			des_encrypt1((DES_LONG *)tin,schedule,DES_DECRYPT);
			tout0=tin[0]^xor0;
			tout1=tin[1]^xor1;
			l2c(tout0,out);
			l2c(tout1,out);
			xor0=tin0;
			xor1=tin1;
		}
		if (l != -8) {
			c2l(in,tin0); tin[0]=tin0;
			c2l(in,tin1); tin[1]=tin1;
			des_encrypt1((DES_LONG *)tin,schedule,DES_DECRYPT);
			tout0=tin[0]^xor0;
			tout1=tin[1]^xor1;
			l2cn(tout0,tout1,out,l+8);
		/*	xor0=tin0;
			xor1=tin1; */
		}
		if (retval) {
			l2c(tin0,retval);
			l2c(tin1,retval);
		}
	}
	tin0=tin1=tout0=tout1=xor0=xor1=0;
	tin[0]=tin[1]=0;
}

/*
 * Initialize an MD5 DES CBC context with a schedule.
 */
 
void MD5_DESCBC_Init(MD5_DESCBC_CTX *ctx, des_key_schedule *sched)
{
	MD5Init(&ctx->md5_ctx);
	ctx->sched = sched;
}

/*
 * Update MD5 DES CBC context with the supplied data.
 */
 
void MD5_DESCBC_Update(MD5_DESCBC_CTX *ctx, void *data, size_t len)
{
	MD5Update(&ctx->md5_ctx, data, len);
}

/*
 * Finalize the context and extract the digest.
 */
 
void MD5_DESCBC_Final(void *digest, MD5_DESCBC_CTX *ctx)
{
	des_cblock iv0;
	unsigned char md5_digest[MD5_DIGEST_LENGTH];
	
	MD5Final(md5_digest, &ctx->md5_ctx);
	
	/*
	 * Now get the DES CBC checksum for the digest.
	 */
	bzero(iv0, sizeof (iv0));
	(void) des_cbc_cksum((des_cblock *) md5_digest, (des_cblock *)digest,
				sizeof (md5_digest), *ctx->sched, &iv0);
}	


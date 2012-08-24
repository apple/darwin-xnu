/*
 * Copyright (c) 2012 Apple Computer, Inc. All rights reserved.
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


#include <libkern/crypto/crypto_internal.h>
#include <libkern/libkern.h>
#include <kern/debug.h>
#include <libkern/crypto/des.h>
#include <corecrypto/ccmode.h>

/* Single DES ECB - used by ipv6 (esp_core.c) */
int des_ecb_key_sched(des_cblock *key, des_ecb_key_schedule *ks)
{
	const struct ccmode_ecb *enc = g_crypto_funcs->ccdes_ecb_encrypt;
	const struct ccmode_ecb *dec = g_crypto_funcs->ccdes_ecb_decrypt;

        /* Make sure the context size for the mode fits in the one we have */
        if((enc->size>sizeof(ks->enc)) || (dec->size>sizeof(ks->dec)))
                panic("%s: inconsistent size for DES-ECB context", __FUNCTION__);
 
	enc->init(enc, ks->enc, CCDES_KEY_SIZE, key);
	dec->init(dec, ks->dec, CCDES_KEY_SIZE, key);

	/* The old DES interface could return -1 or -2 for weak keys and wrong parity,
	 but this was disabled all the time, so we never fail here */
	return 0;
}

/* Simple des - 1 block */
void des_ecb_encrypt(des_cblock *in, des_cblock *out, des_ecb_key_schedule *ks, int enc)
{
	const struct ccmode_ecb *ecb = enc ? g_crypto_funcs->ccdes_ecb_encrypt : g_crypto_funcs->ccdes_ecb_decrypt;
	ccecb_ctx *ctx = enc ? ks->enc : ks->dec;

	ecb->ecb(ctx, 1, in, out);
}


/* Triple DES ECB - used by ipv6 (esp_core.c) */
int des3_ecb_key_sched(des_cblock *key, des3_ecb_key_schedule *ks)
{
	const struct ccmode_ecb *enc = g_crypto_funcs->cctdes_ecb_encrypt;
	const struct ccmode_ecb *dec = g_crypto_funcs->cctdes_ecb_decrypt;

        /* Make sure the context size for the mode fits in the one we have */
        if((enc->size>sizeof(ks->enc)) || (dec->size>sizeof(ks->dec)))
                panic("%s: inconsistent size for 3DES-ECB context", __FUNCTION__);
 
	enc->init(enc, ks->enc, CCDES_KEY_SIZE*3, key);
	dec->init(dec, ks->dec, CCDES_KEY_SIZE*3, key);

	/* The old DES interface could return -1 or -2 for weak keys and wrong parity,
	 but this was disabled all the time, so we never fail here */
	return 0;
}

/* Simple des - 1 block */
void des3_ecb_encrypt(des_cblock *in, des_cblock *out, des3_ecb_key_schedule *ks, int enc)
{
	const struct ccmode_ecb *ecb = enc ? g_crypto_funcs->cctdes_ecb_encrypt : g_crypto_funcs->cctdes_ecb_decrypt;
	ccecb_ctx *ctx = enc ? ks->enc : ks->dec;

	ecb->ecb(ctx, 1, in, out);
}

/* Single DES CBC - used by nfs_gss */
int des_cbc_key_sched(des_cblock *key, des_cbc_key_schedule *ks)
{
	const struct ccmode_cbc *enc = g_crypto_funcs->ccdes_cbc_encrypt;
	const struct ccmode_cbc *dec = g_crypto_funcs->ccdes_cbc_decrypt;

        /* Make sure the context size for the mode fits in the one we have */
        if((enc->size>sizeof(ks->enc)) || (dec->size>sizeof(ks->dec)))
                panic("%s: inconsistent size for DES-CBC context", __FUNCTION__);
 

	cccbc_init(enc, ks->enc, CCDES_KEY_SIZE, key);
	cccbc_init(dec, ks->dec, CCDES_KEY_SIZE, key);

	/* The old DES interface could return -1 or -2 for weak keys and wrong parity,
	 but this was disabled all the time, so we never fail here */
	return 0;
}

/* this is normally only called with length an 8 bytes multiple */
void
des_cbc_encrypt(des_cblock *in, des_cblock *out, int32_t length,
				des_cbc_key_schedule *ks, des_cblock *iv, des_cblock *retiv, int encrypt)
{
	const struct ccmode_cbc *cbc = encrypt?g_crypto_funcs->ccdes_cbc_encrypt:g_crypto_funcs->ccdes_cbc_decrypt;
	cccbc_ctx *ctx = encrypt ? ks->enc : ks->dec;
	int nblocks;
	cccbc_iv_decl(cbc->block_size, ctx_iv); 

	assert(length%8==0);
	nblocks=length/8;

	/* set the iv */
	cccbc_set_iv(cbc, ctx_iv, iv);

	cccbc_update(cbc, ctx, ctx_iv, nblocks, in, out);

	/* copy back iv */
	if(retiv)
		memcpy(retiv, ctx_iv, 8);
}

/* Triple DES CBC - used by nfs_gss */
int des3_cbc_key_sched(des_cblock *key, des3_cbc_key_schedule *ks)
{
	const struct ccmode_cbc *enc = g_crypto_funcs->cctdes_cbc_encrypt;
	const struct ccmode_cbc *dec = g_crypto_funcs->cctdes_cbc_decrypt;

        /* Make sure the context size for the mode fits in the one we have */
        if((enc->size>sizeof(ks->enc)) || (dec->size>sizeof(ks->dec)))
                panic("%s: inconsistent size for 3DES-CBC context", __FUNCTION__);
 
	cccbc_init(enc, ks->enc, CCDES_KEY_SIZE*3, key);
	cccbc_init(dec, ks->dec, CCDES_KEY_SIZE*3, key);

	/* The old DES interface could return -1 or -2 for weak keys and wrong parity,
	 but this was disabled all the time, so we never fail here */
	return 0;
}

/* this is normally only called with length an 8 bytes multiple */
void
des3_cbc_encrypt(des_cblock *in, des_cblock *out, int32_t length,
				 des3_cbc_key_schedule *ks, des_cblock *iv, des_cblock *retiv, int encrypt)
{
	const struct ccmode_cbc *cbc = encrypt?g_crypto_funcs->cctdes_cbc_encrypt:g_crypto_funcs->cctdes_cbc_decrypt;
	cccbc_ctx *ctx = encrypt ? ks->enc : ks->dec;
	int nblocks;
	cccbc_iv_decl(cbc->block_size, ctx_iv); 

	assert(length%8==0);
	nblocks=length/8;

	/* set the iv */
	cccbc_set_iv(cbc, ctx_iv, iv);

	cccbc_update(cbc, ctx, ctx_iv, nblocks, in, out);

	/* copy back iv */
	if(retiv)
		memcpy(retiv, ctx_iv, 8);
}


/*
 * DES MAC implemented according to FIPS 113
 * http://www.itl.nist.gov/fipspubs/fip113.htm
 * Only full blocks.
 * Used by nfs-gss
 */
void
des_cbc_cksum(des_cblock *in, des_cblock *out,
			  int len, des_cbc_key_schedule *ks)
{
	const struct ccmode_cbc *cbc = g_crypto_funcs->ccdes_cbc_encrypt;
	int nblocks;
	des_cblock cksum;
	cccbc_iv_decl(cbc->block_size, ctx_iv);

	assert(len%8==0);
	nblocks=len/8;

	cccbc_set_iv(cbc, ctx_iv, NULL);
	while(nblocks--) {
		cccbc_update(cbc, ks->enc, ctx_iv, 1, in++, cksum);
	}
	memcpy(out, cksum, sizeof(des_cblock));
}


/* Raw key helper functions */
void des_fixup_key_parity(des_cblock *key)
{
	g_crypto_funcs->ccdes_key_set_odd_parity_fn(key, CCDES_KEY_SIZE);
}

int des_is_weak_key(des_cblock *key)
{
	return g_crypto_funcs->ccdes_key_is_weak_fn(key, CCDES_KEY_SIZE);
}

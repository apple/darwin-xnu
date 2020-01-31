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
int
des_ecb_key_sched(des_cblock *key, des_ecb_key_schedule *ks)
{
	const struct ccmode_ecb *enc = g_crypto_funcs->ccdes_ecb_encrypt;
	const struct ccmode_ecb *dec = g_crypto_funcs->ccdes_ecb_decrypt;

	/* Make sure the context size for the mode fits in the one we have */
	if ((enc->size > sizeof(ks->enc)) || (dec->size > sizeof(ks->dec))) {
		panic("%s: inconsistent size for DES-ECB context", __FUNCTION__);
	}

	enc->init(enc, ks->enc, CCDES_KEY_SIZE, key);
	dec->init(dec, ks->dec, CCDES_KEY_SIZE, key);

	/* The old DES interface could return -1 or -2 for weak keys and wrong parity,
	 *  but this was disabled all the time, so we never fail here */
	return 0;
}

/* Simple des - 1 block */
void
des_ecb_encrypt(des_cblock *in, des_cblock *out, des_ecb_key_schedule *ks, int enc)
{
	const struct ccmode_ecb *ecb = enc ? g_crypto_funcs->ccdes_ecb_encrypt : g_crypto_funcs->ccdes_ecb_decrypt;
	ccecb_ctx *ctx = enc ? ks->enc : ks->dec;

	ecb->ecb(ctx, 1, in, out);
}


/* Triple DES ECB - used by ipv6 (esp_core.c) */
int
des3_ecb_key_sched(des_cblock *key, des3_ecb_key_schedule *ks)
{
	int rc;
	const struct ccmode_ecb *enc = g_crypto_funcs->cctdes_ecb_encrypt;
	const struct ccmode_ecb *dec = g_crypto_funcs->cctdes_ecb_decrypt;

	/* Make sure the context size for the mode fits in the one we have */
	if ((enc->size > sizeof(ks->enc)) || (dec->size > sizeof(ks->dec))) {
		panic("%s: inconsistent size for 3DES-ECB context", __FUNCTION__);
	}

	rc = enc->init(enc, ks->enc, CCDES_KEY_SIZE * 3, key);
	rc |= dec->init(dec, ks->dec, CCDES_KEY_SIZE * 3, key);

	return rc;
}

/* Simple des - 1 block */
void
des3_ecb_encrypt(des_cblock *in, des_cblock *out, des3_ecb_key_schedule *ks, int enc)
{
	const struct ccmode_ecb *ecb = enc ? g_crypto_funcs->cctdes_ecb_encrypt : g_crypto_funcs->cctdes_ecb_decrypt;
	ccecb_ctx *ctx = enc ? ks->enc : ks->dec;

	ecb->ecb(ctx, 1, in, out);
}

/* Raw key helper functions */

int
des_is_weak_key(des_cblock *key)
{
	return g_crypto_funcs->ccdes_key_is_weak_fn(key, CCDES_KEY_SIZE);
}

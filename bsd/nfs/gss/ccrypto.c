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
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdes.h>
#include <corecrypto/ccpad.h>
#include <corecrypto/ccsha1.h>
#include <sys/malloc.h>

int corecrypto_available(void);

int
corecrypto_available(void)
{
	return g_crypto_funcs ? 1 : 0;
}

const struct ccmode_cbc  *
ccaes_cbc_decrypt_mode(void)
{
	if (g_crypto_funcs) {
		return g_crypto_funcs->ccaes_cbc_decrypt;
	}
	return NULL;
}

const struct ccmode_cbc  *
ccaes_cbc_encrypt_mode(void)
{
	if (g_crypto_funcs) {
		return g_crypto_funcs->ccaes_cbc_encrypt;
	}
	return NULL;
}

const struct ccmode_cbc  *
ccdes3_cbc_decrypt_mode(void)
{
	if (g_crypto_funcs) {
		return g_crypto_funcs->cctdes_cbc_decrypt;
	}
	return NULL;
}

const struct ccmode_cbc *
ccdes3_cbc_encrypt_mode(void)
{
	if (g_crypto_funcs) {
		return g_crypto_funcs->cctdes_cbc_encrypt;
	}
	return NULL;
}

size_t
ccpad_cts3_decrypt(const struct ccmode_cbc *cbc, cccbc_ctx *cbc_key,
    cccbc_iv *iv, size_t nbytes, const void *in, void *out)
{
	if (g_crypto_funcs) {
		return (*g_crypto_funcs->ccpad_cts3_decrypt_fn)(cbc, cbc_key, iv, nbytes, in, out);
	}
	return 0;
}

size_t
ccpad_cts3_encrypt(const struct ccmode_cbc *cbc, cccbc_ctx *cbc_key,
    cccbc_iv *iv, size_t nbytes, const void *in, void *out)
{
	if (g_crypto_funcs) {
		return (*g_crypto_funcs->ccpad_cts3_encrypt_fn)(cbc, cbc_key, iv, nbytes, in, out);
	}
	return 0;
}

const struct ccdigest_info *ccsha1_ltc_di_ptr;

const struct ccdigest_info *
ccsha1_di(void)
{
	if (g_crypto_funcs) {
		return g_crypto_funcs->ccsha1_di;
	}
	return NULL;
}

void
ccdes_key_set_odd_parity(void *key, unsigned long length)
{
	if (g_crypto_funcs) {
		(*g_crypto_funcs->ccdes_key_set_odd_parity_fn)(key, length);
	}
}

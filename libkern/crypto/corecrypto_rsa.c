/*
 * Copyright (c) 2016 Apple Computer, Inc. All rights reserved.
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
#include <libkern/crypto/rsa.h>
#include <corecrypto/ccrsa.h>


int
rsa_make_pub(rsa_pub_ctx *pub,
    size_t exp_nbytes, const uint8_t *exp,
    size_t mod_nbytes, const uint8_t *mod)
{
	if ((exp_nbytes > RSA_MAX_KEY_BITSIZE / 8)
	    || (mod_nbytes > RSA_MAX_KEY_BITSIZE / 8)) {
		return -1; // Too big
	}
	ccrsa_ctx_n(pub->key) = ccn_nof(RSA_MAX_KEY_BITSIZE);
	return g_crypto_funcs->ccrsa_make_pub_fn(pub->key,
	           exp_nbytes, exp,
	           mod_nbytes, mod);
}

int
rsa_verify_pkcs1v15(rsa_pub_ctx *pub, const uint8_t *oid,
    size_t digest_len, const uint8_t *digest,
    size_t sig_len, const uint8_t *sig,
    bool *valid)
{
	return g_crypto_funcs->ccrsa_verify_pkcs1v15_fn(pub->key, oid,
	           digest_len, digest,
	           sig_len, sig, valid);
}

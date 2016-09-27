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

#ifndef _CRYPTO_REGISTER_CRYPTO_H_
#define _CRYPTO_REGISTER_CRYPTO_H_

#ifdef  __cplusplus
extern "C" {
#endif

#include <corecrypto/ccdigest.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccrc4.h>

/* Function types */

/* digests */
typedef void (*ccdigest_init_fn_t)(const struct ccdigest_info *di, ccdigest_ctx_t ctx);
typedef void (*ccdigest_update_fn_t)(const struct ccdigest_info *di, ccdigest_ctx_t ctx,
                                  unsigned long len, const void *data);
typedef void (*ccdigest_final_fn_t)(const struct ccdigest_info *di, ccdigest_ctx_t ctx,
                                     void *digest);
typedef void (*ccdigest_fn_t)(const struct ccdigest_info *di, unsigned long len,
                           const void *data, void *digest);

/* hmac */
typedef void (*cchmac_init_fn_t)(const struct ccdigest_info *di, cchmac_ctx_t ctx,
                              unsigned long key_len, const void *key);
typedef void (*cchmac_update_fn_t)(const struct ccdigest_info *di, cchmac_ctx_t ctx,
                                unsigned long data_len, const void *data);
typedef void (*cchmac_final_fn_t)(const struct ccdigest_info *di, cchmac_ctx_t ctx,
                               unsigned char *mac);

typedef void (*cchmac_fn_t)(const struct ccdigest_info *di, unsigned long key_len,
                         const void *key, unsigned long data_len, const void *data,
                         unsigned char *mac);

/* pbkdf2 */
typedef void (*ccpbkdf2_hmac_fn_t)(const struct ccdigest_info *di,
                                unsigned long passwordLen, const void *password,
                                unsigned long saltLen, const void *salt,
                                unsigned long iterations,
                                unsigned long dkLen, void *dk);

/* des weak key testing */
typedef int (*ccdes_key_is_weak_fn_t)(void *key, unsigned long  length);
typedef void (*ccdes_key_set_odd_parity_fn_t)(void *key, unsigned long length);

/* XTS padding */
typedef	void (*ccpad_xts_decrypt_fn_t)(const struct ccmode_xts *xts, ccxts_ctx *ctx,
						   unsigned long nbytes, const void *in, void *out);

typedef	void (*ccpad_xts_encrypt_fn_t)(const struct ccmode_xts *xts, ccxts_ctx *ctx,
	                                   unsigned long nbytes, const void *in, void *out);

/* CBC padding (such as PKCS7 or CTSx per NIST standard) */
typedef size_t (*ccpad_cts3_crypt_fn_t)(const struct ccmode_cbc *cbc, cccbc_ctx *cbc_key,
                         cccbc_iv *iv, size_t nbytes, const void *in, void *out);

typedef struct crypto_functions {
    /* digests common functions */
    ccdigest_init_fn_t ccdigest_init_fn;
    ccdigest_update_fn_t ccdigest_update_fn;
    ccdigest_final_fn_t ccdigest_final_fn;
    ccdigest_fn_t ccdigest_fn;
    /* digest implementations */
    const struct ccdigest_info * ccmd5_di;
    const struct ccdigest_info * ccsha1_di;
    const struct ccdigest_info * ccsha256_di;
    const struct ccdigest_info * ccsha384_di;
    const struct ccdigest_info * ccsha512_di;
    
    /* hmac common function */
    cchmac_init_fn_t cchmac_init_fn;
    cchmac_update_fn_t cchmac_update_fn;
    cchmac_final_fn_t cchmac_final_fn;
    cchmac_fn_t cchmac_fn;
    
    /* ciphers modes implementations */
    /* AES, ecb, cbc and xts */
    const struct ccmode_ecb *ccaes_ecb_encrypt;
    const struct ccmode_ecb *ccaes_ecb_decrypt;
    const struct ccmode_cbc *ccaes_cbc_encrypt;
    const struct ccmode_cbc *ccaes_cbc_decrypt;
    const struct ccmode_xts *ccaes_xts_encrypt;
    const struct ccmode_xts *ccaes_xts_decrypt;
    const struct ccmode_gcm *ccaes_gcm_encrypt;
    const struct ccmode_gcm *ccaes_gcm_decrypt;
    /* DES, ecb and cbc */
    const struct ccmode_ecb *ccdes_ecb_encrypt;
    const struct ccmode_ecb *ccdes_ecb_decrypt;
    const struct ccmode_cbc *ccdes_cbc_encrypt;
    const struct ccmode_cbc *ccdes_cbc_decrypt;
    /* Triple DES, ecb and cbc */
    const struct ccmode_ecb *cctdes_ecb_encrypt;
    const struct ccmode_ecb *cctdes_ecb_decrypt;
    const struct ccmode_cbc *cctdes_cbc_encrypt;
    const struct ccmode_cbc *cctdes_cbc_decrypt;
    /* RC4 */
	const struct ccrc4_info *ccrc4_info;
	/* Blowfish - ECB only */
    const struct ccmode_ecb *ccblowfish_ecb_encrypt;
    const struct ccmode_ecb *ccblowfish_ecb_decrypt;
	/* CAST - ECB only */
    const struct ccmode_ecb *cccast_ecb_encrypt;
    const struct ccmode_ecb *cccast_ecb_decrypt;
	/* DES key helper functions */
	ccdes_key_is_weak_fn_t ccdes_key_is_weak_fn;
	ccdes_key_set_odd_parity_fn_t ccdes_key_set_odd_parity_fn;
	/* XTS padding+encrypt functions */
	ccpad_xts_encrypt_fn_t ccpad_xts_encrypt_fn;
	ccpad_xts_decrypt_fn_t ccpad_xts_decrypt_fn;
	/* CTS3 padding+encrypt functions */
	ccpad_cts3_crypt_fn_t ccpad_cts3_encrypt_fn;
	ccpad_cts3_crypt_fn_t ccpad_cts3_decrypt_fn;
} *crypto_functions_t;

int register_crypto_functions(const crypto_functions_t funcs);

#ifdef  __cplusplus
}
#endif

#endif /*_CRYPTO_REGISTER_CRYPTO_H_*/

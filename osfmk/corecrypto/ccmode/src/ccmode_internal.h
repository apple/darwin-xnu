/*
 *  ccmode_internal.h
 *  corecrypto
 *
 *  Created on 12/12/2010
 *
 *  Copyright (c) 2010,2011,2012,2014,2015 Apple Inc. All rights reserved.
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

#ifndef _CORECRYPTO_CCMODE_INTERNAL_H_
#define _CORECRYPTO_CCMODE_INTERNAL_H_

#include <corecrypto/ccmode.h>
#include <corecrypto/ccmode_factory.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/cc_macros.h>

#define CCMODE_INVALID_INPUT         -1
#define CCMODE_INVALID_CALL_SEQUENCE -2
#define CCMODE_INTEGRITY_FAILURE     -3
#define CCMODE_NOT_SUPPORTED         -4
#define CCMODE_INTERNAL_ERROR        -5

// VNG speed up for GCM's AES encrypton and finite fileld multiplication
#if	 \
((CCAES_INTEL_ASM && defined(__x86_64__)) || (CCAES_ARM_ASM && defined(__ARM_NEON__)))
#define	CCMODE_GCM_VNG_SPEEDUP	1
#else
#define	CCMODE_GCM_VNG_SPEEDUP	0
#endif


#define CCMODE_GCM_USE_GF_LOOKUP_TABLES 1

/* Helper function used.  TODO: Probably not specific to xts, since
   gcm uses it too */
void ccmode_xts_mult_alpha(cc_unit *tweak);

/* Macros for accessing a CCMODE_CBC_KEY.
 {
     const struct ccmode_ecb *ecb
     ccn_unit ecb_key[ecb->n]
 } */
#define _CCMODE_CBC_KEY(K)       ((struct _ccmode_cbc_key *)(K))
#define _CCMODE_CBC_KEY_CONST(K) ((const struct _ccmode_cbc_key *)(K))
#define CCMODE_CBC_KEY_ECB(K) (_CCMODE_CBC_KEY(K)->ecb)
#define CCMODE_CBC_KEY_ECB_KEY(K) ((ccecb_ctx *)&_CCMODE_CBC_KEY(K)->u[0])

CC_CONST CC_INLINE
const struct ccmode_ecb * ccmode_cbc_key_ecb(const cccbc_ctx *K) {
    return ((const struct _ccmode_cbc_key *)K)->ecb;
}

CC_CONST CC_INLINE
const ccecb_ctx * ccmode_cbc_key_ecb_key(const cccbc_ctx *K) {
    return (const ccecb_ctx *)&((const struct _ccmode_cbc_key *)K)->u[0];
}

/* Macros for accessing a CCMODE_CFB_KEY.
{
    const struct ccmode_ecb *ecb
    cc_size pad_len;
    ccn_unit pad[ecb->block_size / CCN_UNIT_SIZE];
    ccn_unit iv[ecb->block_size / CCN_UNIT_SIZE];
    ccn_unit ecb_key[ecb->n]
} */
#define _CCMODE_CFB_KEY(K) ((struct _ccmode_cfb_key *)(K))
#define CCMODE_CFB_KEY_ECB(K) (_CCMODE_CFB_KEY(K)->ecb)
#define CCMODE_CFB_KEY_PAD_LEN(K) (_CCMODE_CFB_KEY(K)->pad_len)
#define CCMODE_CFB_KEY_PAD(K) (&_CCMODE_CFB_KEY(K)->u[0])
#define CCMODE_CFB_KEY_IV(K) (&_CCMODE_CFB_KEY(K)->u[ccn_nof_size(CCMODE_CFB_KEY_ECB(K)->block_size)])
#define CCMODE_CFB_KEY_ECB_KEY(K) ((ccecb_ctx *)&_CCMODE_CFB_KEY(K)->u[2 * ccn_nof_size(CCMODE_CFB_KEY_ECB(K)->block_size)])

/* Macros for accessing a CCMODE_CFB8_KEY.
{
    const struct ccmode_ecb *ecb
    ccn_unit pad[ecb->block_size / CCN_UNIT_SIZE];
    ccn_unit iv[ecb->block_size / CCN_UNIT_SIZE];
    ccn_unit ecb_key[ecb->n]
} */
#define _CCMODE_CFB8_KEY(K) ((struct _ccmode_cfb8_key *)(K))
#define CCMODE_CFB8_KEY_ECB(K) (_CCMODE_CFB8_KEY(K)->ecb)
#define CCMODE_CFB8_KEY_PAD(K) (&_CCMODE_CFB8_KEY(K)->u[0])
#define CCMODE_CFB8_KEY_IV(K) (&_CCMODE_CFB8_KEY(K)->u[ccn_nof_size(CCMODE_CFB8_KEY_ECB(K)->block_size)])
#define CCMODE_CFB8_KEY_ECB_KEY(K) ((ccecb_ctx *)&_CCMODE_CFB8_KEY(K)->u[2 * ccn_nof_size(CCMODE_CFB8_KEY_ECB(K)->block_size)])


/* Macros for accessing a CCMODE_CTR_KEY.
{
    const struct ccmode_ecb *ecb
    cc_size pad_offset;
    ccn_unit pad[ecb->block_size / CCN_UNIT_SIZE];
    ccn_unit ctr[ecb->block_size / CCN_UNIT_SIZE];
    ccn_unit ecb_key[ecb->n]
} */
#define _CCMODE_CTR_KEY(K) ((struct _ccmode_ctr_key *)(K))
#define CCMODE_CTR_KEY_ECB(K) (_CCMODE_CTR_KEY(K)->ecb)
#define CCMODE_CTR_KEY_PAD_OFFSET(K) (_CCMODE_CTR_KEY(K)->pad_offset)
#define CCMODE_CTR_KEY_PAD(K) (&_CCMODE_CTR_KEY(K)->u[0])
#define CCMODE_CTR_KEY_CTR(K) (&_CCMODE_CTR_KEY(K)->u[ccn_nof_size(CCMODE_CTR_KEY_ECB(K)->block_size)])
#define CCMODE_CTR_KEY_ECB_KEY(K) ((ccecb_ctx *)&_CCMODE_CTR_KEY(K)->u[2 * ccn_nof_size(CCMODE_CTR_KEY_ECB(K)->block_size)])

CC_INLINE int ccctr_setctr(const struct ccmode_ctr *mode, ccctr_ctx *ctx, const void *ctr)
{
    return mode->setctr(mode, ctx, ctr);
}

/* Macros for accessing a CCMODE_OFB_KEY.
{
    const struct ccmode_ecb *ecb
    cc_size pad_len;
    ccn_unit iv[ecb->block_size / CCN_UNIT_SIZE];
    ccn_unit ecb_key[ecb->n]
} */
#define _CCMODE_OFB_KEY(K) ((struct _ccmode_ofb_key *)(K))
#define CCMODE_OFB_KEY_ECB(K) (_CCMODE_OFB_KEY(K)->ecb)
#define CCMODE_OFB_KEY_PAD_LEN(K) (_CCMODE_OFB_KEY(K)->pad_len)
#define CCMODE_OFB_KEY_IV(K) (&_CCMODE_OFB_KEY(K)->u[0])
#define CCMODE_OFB_KEY_ECB_KEY(K) ((ccecb_ctx *)&_CCMODE_OFB_KEY(K)->u[ccn_nof_size(CCMODE_OFB_KEY_ECB(K)->block_size)])


/* Macros for accessing a CCMODE_XTS_KEY.
{
    const struct ccmode_ecb *ecb
    const struct ccmode_ecb *ecb_encrypt
    ccn_unit data_key[ecb->size]
    ccn_unit tweak_key[ecb_encrypt->size]
} */
#define _CCMODE_XTS_KEY(K) ((struct _ccmode_xts_key *)(K))
#define CCMODE_XTS_KEY_ECB(K) (_CCMODE_XTS_KEY(K)->ecb)
#define CCMODE_XTS_KEY_ECB_ENCRYPT(K) (_CCMODE_XTS_KEY(K)->ecb_encrypt)
#define CCMODE_XTS_KEY_DATA_KEY(K) ((ccecb_ctx *)&_CCMODE_XTS_KEY(K)->u[0])
#define CCMODE_XTS_KEY_TWEAK_KEY(K) ((ccecb_ctx *)&_CCMODE_XTS_KEY(K)->u[ccn_nof_size(CCMODE_XTS_KEY_ECB(K)->size)])

CC_CONST CC_INLINE
const struct ccmode_ecb * ccmode_xts_key_ecb(const ccxts_ctx *K) {
    return ((const struct _ccmode_xts_key *)K)->ecb;
}

CC_CONST CC_INLINE
const struct ccmode_ecb * ccmode_xts_key_ecb_encrypt(const ccxts_ctx *K) {
    return ((const struct _ccmode_xts_key *)K)->ecb_encrypt;
}

CC_CONST CC_INLINE
const ccecb_ctx * ccmode_xts_key_data_key(const ccxts_ctx *K) {
    return (const ccecb_ctx *)&((const struct _ccmode_xts_key *)K)->u[0];
}

CC_CONST CC_INLINE
const ccecb_ctx * ccmode_xts_key_tweak_key(const ccxts_ctx *K) {
    return (const ccecb_ctx *)&((const struct _ccmode_xts_key *)K)->u[ccn_nof_size(ccmode_xts_key_ecb(K)->size)];
}

/* Macros for accessing a CCMODE_XTS_TWEAK.
{
 size_t  blocks_processed;
 uint8_t value[16];
} */
#define _CCMODE_XTS_TWEAK(T) ((struct _ccmode_xts_tweak *)(T))
#define CCMODE_XTS_TWEAK_BLOCK_PROCESSED(T)(_CCMODE_XTS_TWEAK(T)->blocks_processed)
#define CCMODE_XTS_TWEAK_VALUE(T) (_CCMODE_XTS_TWEAK(T)->u)


/* Macros for accessing a CCMODE_GCM_KEY.
 Common to the generic (factory) and the VNG implementation
*/

#define _CCMODE_GCM_KEY(K) ((struct _ccmode_gcm_key *)(K))
#define CCMODE_GCM_KEY_H(K) (_CCMODE_GCM_KEY(K)->H)
#define CCMODE_GCM_KEY_X(K) (_CCMODE_GCM_KEY(K)->X)
#define CCMODE_GCM_KEY_Y(K) (_CCMODE_GCM_KEY(K)->Y)
#define CCMODE_GCM_KEY_Y_0(K) (_CCMODE_GCM_KEY(K)->Y_0)
#define CCMODE_GCM_KEY_PAD_LEN(K) (_CCMODE_GCM_KEY(K)->buf_nbytes)
#define CCMODE_GCM_KEY_PAD(K) (_CCMODE_GCM_KEY(K)->buf)

#define _CCMODE_GCM_ECB_MODE(K) ((struct _ccmode_gcm_key *)(K))
#define CCMODE_GCM_KEY_ECB(K) (_CCMODE_GCM_ECB_MODE(K)->ecb)
#define CCMODE_GCM_KEY_ECB_KEY(K) ((ccecb_ctx *)_CCMODE_GCM_ECB_MODE(K)->ecb_key)  // set in init function

#define CCMODE_GCM_STATE_IV    1
#define CCMODE_GCM_STATE_AAD   2
#define CCMODE_GCM_STATE_TEXT  3
#define CCMODE_GCM_STATE_FINAL 4

#define CCMODE_STATE_INIT 2     //first call to init
#define CCMODE_STATE_IV_START 3 //first call to set_iv

// rdar://problem/23523093
//this allows users to bypass set_iv().
//this is a temporary setting mainly to allow Security framework to adapt
//ccgcm_set_iv_legacy() and check the tack on decyption without
//need to change the Security twice
//#define CCMODE_STATE_IV_CONT 2 //subsequent calls to set_iv
#define CCMODE_STATE_IV_CONT CCMODE_STATE_IV_START

#define CCMODE_STATE_AAD     4
#define CCMODE_STATE_TEXT    5

#define CCMODE_CCM_STATE_IV 1

void ccmode_gcm_gf_mult(const unsigned char *a, const unsigned char *b,
                        unsigned char *c);
void ccmode_gcm_mult_h(ccgcm_ctx *key, unsigned char *I);

/* Macros for accessing a CCMODE_CCM_KEY. */
#define _CCMODE_CCM_KEY(K) ((struct _ccmode_ccm_key *)(K))
#define CCMODE_CCM_KEY_ECB(K) (_CCMODE_CCM_KEY(K)->ecb)
#define CCMODE_CCM_KEY_ECB_KEY(K) ((ccecb_ctx *)&_CCMODE_CCM_KEY(K)->u[0])

#define _CCMODE_CCM_NONCE(N) ((struct _ccmode_ccm_nonce *)(N))
#define CCMODE_CCM_KEY_MAC(N) (_CCMODE_CCM_NONCE(N)->MAC)
#define CCMODE_CCM_KEY_A_I(N) (_CCMODE_CCM_NONCE(N)->A_i)
#define CCMODE_CCM_KEY_B_I(N) (_CCMODE_CCM_NONCE(N)->B_i)
#define CCMODE_CCM_KEY_PAD_LEN(N) (_CCMODE_CCM_NONCE(N)->buflen)
#define CCMODE_CCM_KEY_PAD(N) (_CCMODE_CCM_NONCE(N)->buf)
#define CCMODE_CCM_KEY_MAC_LEN(N) (_CCMODE_CCM_NONCE(N)->mac_size)
#define CCMODE_CCM_KEY_NONCE_LEN(N) (_CCMODE_CCM_NONCE(N)->nonce_size)
#define CCMODE_CCM_KEY_AUTH_LEN(N) (_CCMODE_CCM_NONCE(N)->b_i_len)

/* Macros for accessing a CCMODE_OMAC_KEY.
{
    const struct ccmode_ecb *ecb
    cc_size tweak_size;
    ccn_unit ecb_key1[ecb->n]
    ccn_unit ecb_key2[ecb->n]
} */
#define _CCMODE_OMAC_KEY(K) ((struct _ccmode_omac_key *)(K))
#define CCMODE_OMAC_KEY_ECB(K) (_CCMODE_OMAC_KEY(K)->ecb)
#define CCMODE_OMAC_KEY_TWEAK_LEN(K) (_CCMODE_OMAC_KEY(K)->tweak_len)
#define CCMODE_OMAC_KEY_ECB_KEY(K) ((ccecb_ctx *)&_CCMODE_OMAC_KEY(K)->u[0])

CC_INLINE void inc_uint(uint8_t *buf, size_t nbytes)
{
    size_t i;
    for (i = 0; i < nbytes; i += 1) {
        if (++buf[nbytes-1-i] & 255) { break; }
    }
}

CC_INLINE void ccmode_gcm_update_pad(ccgcm_ctx *key)
{
    inc_uint(CCMODE_GCM_KEY_Y(key) + 12, 4);
    CCMODE_GCM_KEY_ECB(key)->ecb(CCMODE_GCM_KEY_ECB_KEY(key), 1,
                                 CCMODE_GCM_KEY_Y(key),
                                 CCMODE_GCM_KEY_PAD(key));
}

CC_INLINE void ccmode_gcm_aad_finalize(ccgcm_ctx *key)
{
    if (_CCMODE_GCM_KEY(key)->state == CCMODE_GCM_STATE_AAD) {
        if (_CCMODE_GCM_KEY(key)->aad_nbytes % CCGCM_BLOCK_NBYTES > 0) {
            ccmode_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));
        }
        _CCMODE_GCM_KEY(key)->state = CCMODE_GCM_STATE_TEXT;
    }
}

CC_INLINE void xor_128bits(unsigned char *r, const unsigned char *a, const unsigned char *b)
{
    cc_unit *r1 = (cc_unit *)r;
    const cc_unit *a1 = (const cc_unit *)a;
    const cc_unit *b1 = (const cc_unit *)b;

    for (int i=0; i<128/(CCN_UNIT_SIZE*8); i++) {
        r1[i] = a1[i] ^ b1[i];
    }
}



#endif /* _CORECRYPTO_CCMODE_INTERNAL_H_ */

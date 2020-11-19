/* Copyright (c) (2010,2012,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */


#ifndef _CORECRYPTO_CCDES_H_
#define _CORECRYPTO_CCDES_H_

#include <corecrypto/ccmode.h>

#define CCDES_BLOCK_SIZE 8
#define CCDES_KEY_SIZE 8

extern const struct ccmode_ecb ccdes3_ltc_ecb_decrypt_mode;
extern const struct ccmode_ecb ccdes3_ltc_ecb_encrypt_mode;

const struct ccmode_ecb *ccdes_ecb_decrypt_mode(void);
const struct ccmode_ecb *ccdes_ecb_encrypt_mode(void);

const struct ccmode_cbc *ccdes_cbc_decrypt_mode(void);
const struct ccmode_cbc *ccdes_cbc_encrypt_mode(void);

const struct ccmode_cfb *ccdes_cfb_decrypt_mode(void);
const struct ccmode_cfb *ccdes_cfb_encrypt_mode(void);

const struct ccmode_cfb8 *ccdes_cfb8_decrypt_mode(void);
const struct ccmode_cfb8 *ccdes_cfb8_encrypt_mode(void);

const struct ccmode_ctr *ccdes_ctr_crypt_mode(void);

const struct ccmode_ofb *ccdes_ofb_crypt_mode(void);


const struct ccmode_ecb *ccdes3_ecb_decrypt_mode(void);
const struct ccmode_ecb *ccdes3_ecb_encrypt_mode(void);

const struct ccmode_cbc *ccdes3_cbc_decrypt_mode(void);
const struct ccmode_cbc *ccdes3_cbc_encrypt_mode(void);

const struct ccmode_cfb *ccdes3_cfb_decrypt_mode(void);
const struct ccmode_cfb *ccdes3_cfb_encrypt_mode(void);

const struct ccmode_cfb8 *ccdes3_cfb8_decrypt_mode(void);
const struct ccmode_cfb8 *ccdes3_cfb8_encrypt_mode(void);

const struct ccmode_ctr *ccdes3_ctr_crypt_mode(void);

const struct ccmode_ofb *ccdes3_ofb_crypt_mode(void);

int ccdes_key_is_weak( void *key, size_t  length);
void ccdes_key_set_odd_parity(void *key, size_t length);

uint32_t
ccdes_cbc_cksum(const void *in, void *out, size_t length,
                const void *key, size_t key_nbytes, const void *ivec);


#endif /* _CORECRYPTO_CCDES_H_ */

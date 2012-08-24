/*
 *  ccaes.h
 *  corecrypto
 *
 *  Created by Michael Brouwer on 12/10/10.
 *  Copyright 2010,2011 Apple Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_CCAES_H_
#define _CORECRYPTO_CCAES_H_

#include <corecrypto/cc_config.h>
#include <corecrypto/ccmode.h>

#define CCAES_BLOCK_SIZE 16
#define CCAES_KEY_SIZE_128 16
#define CCAES_KEY_SIZE_192 24
#define CCAES_KEY_SIZE_256 32

extern const struct ccmode_ecb ccaes_ltc_ecb_decrypt_mode;
extern const struct ccmode_ecb ccaes_ltc_ecb_encrypt_mode;

extern const struct ccmode_cbc ccaes_gladman_cbc_encrypt_mode;
extern const struct ccmode_cbc ccaes_gladman_cbc_decrypt_mode;

#if CCAES_ARM
extern const struct ccmode_ecb ccaes_arm_ecb_encrypt_mode;
extern const struct ccmode_ecb ccaes_arm_ecb_decrypt_mode;

extern const struct ccmode_cbc ccaes_arm_cbc_encrypt_mode;
extern const struct ccmode_cbc ccaes_arm_cbc_decrypt_mode;
#endif

#if CCAES_INTEL
//extern const struct ccmode_ecb ccaes_intel_ecb_encrypt_mode;
//extern const struct ccmode_ecb ccaes_intel_ecb_decrypt_mode;

extern const struct ccmode_ecb ccaes_intel_ecb_encrypt_opt_mode;
extern const struct ccmode_ecb ccaes_intel_ecb_encrypt_aesni_mode;

extern const struct ccmode_ecb ccaes_intel_ecb_decrypt_opt_mode;
extern const struct ccmode_ecb ccaes_intel_ecb_decrypt_aesni_mode;

//extern const struct ccmode_cbc ccaes_intel_cbc_encrypt_mode;
//extern const struct ccmode_cbc ccaes_intel_cbc_decrypt_mode;

extern const struct ccmode_cbc ccaes_intel_cbc_encrypt_opt_mode;
extern const struct ccmode_cbc ccaes_intel_cbc_encrypt_aesni_mode;

extern const struct ccmode_cbc ccaes_intel_cbc_decrypt_opt_mode;
extern const struct ccmode_cbc ccaes_intel_cbc_decrypt_aesni_mode;

//extern const struct ccmode_xts ccaes_intel_xts_encrypt_mode;
//extern const struct ccmode_xts ccaes_intel_xts_decrypt_mode;

extern const struct ccmode_xts ccaes_intel_xts_encrypt_opt_mode;
extern const struct ccmode_xts ccaes_intel_xts_encrypt_aesni_mode;

extern const struct ccmode_xts ccaes_intel_xts_decrypt_opt_mode;
extern const struct ccmode_xts ccaes_intel_xts_decrypt_aesni_mode;
#endif


/* Implementation Selectors: */
const struct ccmode_ecb *ccaes_ecb_encrypt_mode(void);
const struct ccmode_cbc *ccaes_cbc_encrypt_mode(void);
const struct ccmode_cfb *ccaes_cfb_encrypt_mode(void);
const struct ccmode_cfb8 *ccaes_cfb8_encrypt_mode(void);
const struct ccmode_xts *ccaes_xts_encrypt_mode(void);
const struct ccmode_gcm *ccaes_gcm_encrypt_mode(void);

const struct ccmode_ecb *ccaes_ecb_decrypt_mode(void);
const struct ccmode_cbc *ccaes_cbc_decrypt_mode(void);
const struct ccmode_cfb *ccaes_cfb_decrypt_mode(void);
const struct ccmode_cfb8 *ccaes_cfb8_decrypt_mode(void);
const struct ccmode_xts *ccaes_xts_decrypt_mode(void);
const struct ccmode_gcm *ccaes_gcm_decrypt_mode(void);

const struct ccmode_ctr *ccaes_ctr_crypt_mode(void);
const struct ccmode_ofb *ccaes_ofb_crypt_mode(void);

#endif /* _CORECRYPTO_CCAES_H_ */

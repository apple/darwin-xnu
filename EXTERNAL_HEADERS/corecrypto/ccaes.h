/* Copyright (c) (2010,2011,2012,2013,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCAES_H_
#define _CORECRYPTO_CCAES_H_

#include <corecrypto/cc_config.h>
#include <corecrypto/ccmode.h>

#define CCAES_BLOCK_SIZE 16
#define CCAES_KEY_SIZE_128 16
#define CCAES_KEY_SIZE_192 24
#define CCAES_KEY_SIZE_256 32

#define CCAES_CTR_MAX_PARALLEL_NBLOCKS 8

extern const struct ccmode_ecb ccaes_ltc_ecb_decrypt_mode;
extern const struct ccmode_ecb ccaes_ltc_ecb_encrypt_mode;

extern const struct ccmode_cbc ccaes_gladman_cbc_encrypt_mode;
extern const struct ccmode_cbc ccaes_gladman_cbc_decrypt_mode;

#if  CCAES_ARM_ASM
extern const struct ccmode_ecb ccaes_arm_ecb_encrypt_mode;
extern const struct ccmode_ecb ccaes_arm_ecb_decrypt_mode;

extern const struct ccmode_cbc ccaes_arm_cbc_encrypt_mode;
extern const struct ccmode_cbc ccaes_arm_cbc_decrypt_mode;

extern const struct ccmode_xts ccaes_arm_xts_encrypt_mode;
extern const struct ccmode_xts ccaes_arm_xts_decrypt_mode;

extern const struct ccmode_cfb ccaes_arm_cfb_encrypt_mode;
extern const struct ccmode_cfb ccaes_arm_cfb_decrypt_mode;

extern const struct ccmode_ofb ccaes_arm_ofb_crypt_mode;

#endif

#if CCAES_MUX
/* Runtime check to see if hardware should be used */
int ccaes_ios_hardware_enabled(int operation);

extern const struct ccmode_cbc ccaes_ios_hardware_cbc_encrypt_mode;
extern const struct ccmode_cbc ccaes_ios_hardware_cbc_decrypt_mode;

extern const struct ccmode_ctr ccaes_ios_hardware_ctr_crypt_mode;

extern const struct ccmode_cbc *ccaes_ios_mux_cbc_encrypt_mode(void);
extern const struct ccmode_cbc *ccaes_ios_mux_cbc_decrypt_mode(void);

extern const struct ccmode_ctr *ccaes_ios_mux_ctr_crypt_mode(void);

#endif

#if  CCAES_INTEL_ASM
extern const struct ccmode_ecb ccaes_intel_ecb_encrypt_opt_mode;
extern const struct ccmode_ecb ccaes_intel_ecb_encrypt_aesni_mode;

extern const struct ccmode_ecb ccaes_intel_ecb_decrypt_opt_mode;
extern const struct ccmode_ecb ccaes_intel_ecb_decrypt_aesni_mode;

extern const struct ccmode_cbc ccaes_intel_cbc_encrypt_opt_mode;
extern const struct ccmode_cbc ccaes_intel_cbc_encrypt_aesni_mode;

extern const struct ccmode_cbc ccaes_intel_cbc_decrypt_opt_mode;
extern const struct ccmode_cbc ccaes_intel_cbc_decrypt_aesni_mode;

extern const struct ccmode_xts ccaes_intel_xts_encrypt_opt_mode;
extern const struct ccmode_xts ccaes_intel_xts_encrypt_aesni_mode;

extern const struct ccmode_xts ccaes_intel_xts_decrypt_opt_mode;
extern const struct ccmode_xts ccaes_intel_xts_decrypt_aesni_mode;
#endif

#if CC_USE_L4
extern const struct ccmode_cbc ccaes_skg_cbc_encrypt_mode;
extern const struct ccmode_cbc ccaes_skg_cbc_decrypt_mode;

extern const struct ccmode_ecb ccaes_skg_ecb_encrypt_mode;
extern const struct ccmode_ecb ccaes_skg_ecb_decrypt_mode;

extern const struct ccmode_ecb ccaes_trng_ecb_encrypt_mode;
#endif

/* Implementation Selectors: */
const struct ccmode_ecb *ccaes_ecb_encrypt_mode(void);
const struct ccmode_cbc *ccaes_cbc_encrypt_mode(void);
const struct ccmode_cfb *ccaes_cfb_encrypt_mode(void);
const struct ccmode_cfb8 *ccaes_cfb8_encrypt_mode(void);
const struct ccmode_xts *ccaes_xts_encrypt_mode(void);
const struct ccmode_gcm *ccaes_gcm_encrypt_mode(void);
const struct ccmode_ccm *ccaes_ccm_encrypt_mode(void);

const struct ccmode_ecb *ccaes_ecb_decrypt_mode(void);
const struct ccmode_cbc *ccaes_cbc_decrypt_mode(void);
const struct ccmode_cfb *ccaes_cfb_decrypt_mode(void);
const struct ccmode_cfb8 *ccaes_cfb8_decrypt_mode(void);
const struct ccmode_xts *ccaes_xts_decrypt_mode(void);
const struct ccmode_gcm *ccaes_gcm_decrypt_mode(void);
const struct ccmode_ccm *ccaes_ccm_decrypt_mode(void);

const struct ccmode_ctr *ccaes_ctr_crypt_mode(void);
const struct ccmode_ofb *ccaes_ofb_crypt_mode(void);

const struct ccmode_siv *ccaes_siv_encrypt_mode(void);
const struct ccmode_siv *ccaes_siv_decrypt_mode(void);

const struct ccmode_siv_hmac *ccaes_siv_hmac_sha256_encrypt_mode(void);
const struct ccmode_siv_hmac *ccaes_siv_hmac_sha256_decrypt_mode(void);

/*!
  @function ccaes_unwind
  @abstract "Unwind" an AES encryption key to the equivalent decryption key.

  @param key_nbytes Length in bytes of both the input and output keys
  @param key The input AES encryption key
  @param out The output AES decryption key

  @result @p CCERR_OK iff successful.
  @discussion Only AES256 (i.e. 32-byte) keys are supported. This function is not necessary in typical AES usage; consult the maintainers before using it.
*/
int ccaes_unwind(size_t key_nbytes, const void *key, void *out);

#endif /* _CORECRYPTO_CCAES_H_ */

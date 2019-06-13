/*
 *  ccmode_factory.h
 *  corecrypto
 *
 *  Created on 01/21/2011
 *
 *  Copyright (c) 2011,2012,2013,2014,2015 Apple Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_CCMODE_FACTORY_H_
#define _CORECRYPTO_CCMODE_FACTORY_H_

#include <corecrypto/ccn.h>  /* TODO: Remove dependency on this header. */
#include <corecrypto/ccmode_impl.h>

/* Function and macros defined in this file are only to be used
 within corecrypto files.
 */

/* For CBC, direction of underlying ecb is the same as the cbc direction */
#define CCMODE_CBC_FACTORY(_cipher_, _dir_)                                     \
static struct ccmode_cbc cbc_##_cipher_##_##_dir_;                              \
                                                                                \
const struct ccmode_cbc *cc##_cipher_##_cbc_##_dir_##_mode(void)                \
{                                                                               \
    const struct ccmode_ecb *ecb=cc##_cipher_##_ecb_##_dir_##_mode();           \
    ccmode_factory_cbc_##_dir_(&cbc_##_cipher_##_##_dir_, ecb);                 \
    return &cbc_##_cipher_##_##_dir_;                                           \
}

/* For CTR, only one direction, underlying ecb is always encrypt */
#define CCMODE_CTR_FACTORY(_cipher_)                                            \
static struct ccmode_ctr ctr_##_cipher_;                                        \
                                                                                \
const struct ccmode_ctr *cc##_cipher_##_ctr_crypt_mode(void)                    \
{                                                                               \
    const struct ccmode_ecb *ecb=cc##_cipher_##_ecb_encrypt_mode();             \
    ccmode_factory_ctr_crypt(&ctr_##_cipher_, ecb);                             \
    return &ctr_##_cipher_;                                                     \
}

/* OFB, same as CTR */
#define CCMODE_OFB_FACTORY(_cipher_)                                            \
static struct ccmode_ofb ofb_##_cipher_;                                        \
                                                                                \
const struct ccmode_ofb *cc##_cipher_##_ofb_crypt_mode(void)                    \
{                                                                               \
    const struct ccmode_ecb *ecb=cc##_cipher_##_ecb_encrypt_mode();             \
    ccmode_factory_ofb_crypt(&ofb_##_cipher_, ecb);                             \
    return &ofb_##_cipher_;                                                     \
}


/* For CFB, the underlying ecb operation is encrypt for both directions */
#define CCMODE_CFB_FACTORY(_cipher_, _mode_, _dir_)                             \
static struct ccmode_##_mode_ _mode_##_##_cipher_##_##_dir_;                    \
                                                                                \
const struct ccmode_##_mode_ *cc##_cipher_##_##_mode_##_##_dir_##_mode(void)    \
{                                                                               \
    const struct ccmode_ecb *ecb=cc##_cipher_##_ecb_encrypt_mode();             \
    ccmode_factory_##_mode_##_##_dir_(&_mode_##_##_cipher_##_##_dir_, ecb);     \
    return &_mode_##_##_cipher_##_##_dir_;                                      \
}

/* For GCM, same as CFB */
#define CCMODE_GCM_FACTORY(_cipher_, _dir_) CCMODE_CFB_FACTORY(_cipher_, gcm, _dir_)

/* For CCM, same as CFB */
#define CCMODE_CCM_FACTORY(_cipher_, _dir_) CCMODE_CFB_FACTORY(_cipher_, ccm, _dir_)


/* Fot XTS, you always need an ecb encrypt */
#define CCMODE_XTS_FACTORY(_cipher_ , _dir_)                                    \
static struct ccmode_xts xts##_cipher_##_##_dir_;                               \
                                                                                \
const struct ccmode_xts *cc##_cipher_##_xts_##_dir_##_mode(void)                \
{                                                                               \
    const struct ccmode_ecb *ecb=cc##_cipher_##_ecb_##_dir_##_mode();           \
    const struct ccmode_ecb *ecb_enc=cc##_cipher_##_ecb_encrypt_mode();         \
                                                                                \
    ccmode_factory_xts_##_dir_(&xts##_cipher_##_##_dir_, ecb, ecb_enc);         \
    return &xts##_cipher_##_##_dir_;                                            \
}

/* Use these function to runtime initialize a ccmode_cbc decrypt object (for
 example if it's part of a larger structure). Normally you would pass a
 ecb decrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
void ccmode_factory_cbc_decrypt(struct ccmode_cbc *cbc,
                                const struct ccmode_ecb *ecb);

/* Use these function to runtime initialize a ccmode_cbc encrypt object (for
 example if it's part of a larger structure). Normally you would pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
void ccmode_factory_cbc_encrypt(struct ccmode_cbc *cbc,
                                const struct ccmode_ecb *ecb);


/* Use these function to runtime initialize a ccmode_cfb decrypt object (for
 example if it's part of a larger structure). Normally you would pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
void ccmode_factory_cfb_decrypt(struct ccmode_cfb *cfb,
                                const struct ccmode_ecb *ecb);

/* Use these function to runtime initialize a ccmode_cfb encrypt object (for
 example if it's part of a larger structure). Normally you would pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
void ccmode_factory_cfb_encrypt(struct ccmode_cfb *cfb,
                                const struct ccmode_ecb *ecb);

/* Use these function to runtime initialize a ccmode_cfb8 decrypt object (for
 example if it's part of a larger structure). Normally you would pass a
 ecb decrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
void ccmode_factory_cfb8_decrypt(struct ccmode_cfb8 *cfb8,
                                 const struct ccmode_ecb *ecb);

/* Use these function to runtime initialize a ccmode_cfb8 encrypt object (for
 example if it's part of a larger structure). Normally you would pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
void ccmode_factory_cfb8_encrypt(struct ccmode_cfb8 *cfb8,
                                 const struct ccmode_ecb *ecb);

/* Use these function to runtime initialize a ccmode_ctr decrypt object (for
 example if it's part of a larger structure). Normally you would pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
void ccmode_factory_ctr_crypt(struct ccmode_ctr *ctr,
                              const struct ccmode_ecb *ecb);

/* Use these function to runtime initialize a ccmode_gcm decrypt object (for
 example if it's part of a larger structure). For GCM you always pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
void ccmode_factory_gcm_decrypt(struct ccmode_gcm *gcm,
                                const struct ccmode_ecb *ecb_encrypt);

/* Use these function to runtime initialize a ccmode_gcm encrypt object (for
 example if it's part of a larger structure). For GCM you always pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
void ccmode_factory_gcm_encrypt(struct ccmode_gcm *gcm,
                                const struct ccmode_ecb *ecb_encrypt);

/* Use these function to runtime initialize a ccmode_ccm decrypt object (for
 example if it's part of a larger structure). For CCM you always pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */

void ccmode_factory_ccm_decrypt(struct ccmode_ccm *ccm,
                                const struct ccmode_ecb *ecb_encrypt);

/* Use these function to runtime initialize a ccmode_ccm encrypt object (for
 example if it's part of a larger structure). For CCM you always pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
void ccmode_factory_ccm_encrypt(struct ccmode_ccm *ccm,
                                const struct ccmode_ecb *ecb_encrypt);

/* Use these function to runtime initialize a ccmode_ofb encrypt object (for
 example if it's part of a larger structure). Normally you would pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
void ccmode_factory_ofb_crypt(struct ccmode_ofb *ofb,
                              const struct ccmode_ecb *ecb);

/* Use these function to runtime initialize a ccmode_omac decrypt object (for
 example if it's part of a larger structure). Normally you would pass a
 ecb decrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
void ccmode_factory_omac_decrypt(struct ccmode_omac *omac,
                                 const struct ccmode_ecb *ecb);

/* Use these function to runtime initialize a ccmode_omac encrypt object (for
 example if it's part of a larger structure). Normally you would pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
void ccmode_factory_omac_encrypt(struct ccmode_omac *omac,
                                 const struct ccmode_ecb *ecb);

/* Use these function to runtime initialize a ccmode_xts decrypt object (for
 example if it's part of a larger structure). Normally you would pass a
 ecb decrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
void ccmode_factory_xts_decrypt(struct ccmode_xts *xts,
                                const struct ccmode_ecb *ecb,
                                const struct ccmode_ecb *ecb_encrypt);

/* Use these function to runtime initialize a ccmode_xts encrypt object (for
 example if it's part of a larger structure). Normally you would pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
void ccmode_factory_xts_encrypt(struct ccmode_xts *xts,
                                const struct ccmode_ecb *ecb,
                                const struct ccmode_ecb *ecb_encrypt);

#endif /* _CORECRYPTO_CCMODE_FACTORY_H_ */

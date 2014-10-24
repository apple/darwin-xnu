/*
 *  ccmode_factory.h
 *  corecrypto
 *
 *  Created by Fabrice Gautier on 1/21/11.
 *  Copyright 2011 Apple, Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_CCMODE_FACTORY_H_
#define _CORECRYPTO_CCMODE_FACTORY_H_

#include <corecrypto/ccn.h>  /* TODO: Remove dependency on this header. */
#include <corecrypto/ccmode_impl.h>

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

#if 0

/* example of how to make the selection function thread safe */

struct ccmode_cbc cc3des_cbc_mode_encrypt;
dispatch_once_t cc3des_mode_encrypt_init_once;

void cc3des_mode_encrypt_init(void *ctx) {
    struct ccmode_ecb *ecb = cc3des_ecb_encrypt_mode();
    ccmode_factory_cbc_encrypt(&cc3des_mode_encrypt, ecb);
}

const struct ccmode_cbc *cc3des_cbc_encrypt_mode(void) {
    dispatch_once_f(&cc3des_mode_encrypt_init_once, NULL, cc3des_mode_encrypt_init);
    return &cc3des_mode_encrypt;
}

struct ccmode_cbc cc3des_cbc_mode_encrypt = {
    .n = CC3DES_LTC_ECB_ENCRYPT_N,
    .init = ccmode_cbc_init,
    .cbc = ccmode_cbc_encrypt,
    .custom = &cc3des_ltc_ecb_encrypt
};

const struct ccmode_cbc *cc3des_cbc_encrypt_mode(void) {
    return &cc3des_mode_encrypt;
}

#endif



void ccmode_cbc_init(const struct ccmode_cbc *cbc, cccbc_ctx *ctx,
                     size_t rawkey_len, const void *rawkey);
void ccmode_cbc_decrypt(const cccbc_ctx *ctx, cccbc_iv *iv, unsigned long nblocks,
                        const void *in, void *out);
void ccmode_cbc_encrypt(const cccbc_ctx *ctx, cccbc_iv *iv, unsigned long nblocks,
                        const void *in, void *out);

struct _ccmode_cbc_key {
    const struct ccmode_ecb *ecb;
    cc_unit u[];
};

/* Use this to statically initialize a ccmode_cbc object for decryption. */
#define CCMODE_FACTORY_CBC_DECRYPT(ECB) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_cbc_key)) + ccn_sizeof_size((ECB)->block_size) + ccn_sizeof_size((ECB)->size), \
.block_size = (ECB)->block_size, \
.init = ccmode_cbc_init, \
.cbc = ccmode_cbc_decrypt, \
.custom = (ECB) \
}

/* Use this to statically initialize a ccmode_cbc object for encryption. */
#define CCMODE_FACTORY_CBC_ENCRYPT(ECB) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_cbc_key)) + ccn_sizeof_size((ECB)->block_size) + ccn_sizeof_size((ECB)->size), \
.block_size = (ECB)->block_size, \
.init = ccmode_cbc_init, \
.cbc = ccmode_cbc_encrypt, \
.custom = (ECB) \
}

/* Use these function to runtime initialize a ccmode_cbc decrypt object (for
 example if it's part of a larger structure). Normally you would pass a
 ecb decrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
CC_INLINE
void ccmode_factory_cbc_decrypt(struct ccmode_cbc *cbc,
                                const struct ccmode_ecb *ecb) {
    struct ccmode_cbc cbc_decrypt = CCMODE_FACTORY_CBC_DECRYPT(ecb);
    *cbc = cbc_decrypt;
}

/* Use these function to runtime initialize a ccmode_cbc encrypt object (for
 example if it's part of a larger structure). Normally you would pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
CC_INLINE
void ccmode_factory_cbc_encrypt(struct ccmode_cbc *cbc,
                                const struct ccmode_ecb *ecb) {
    struct ccmode_cbc cbc_encrypt = CCMODE_FACTORY_CBC_ENCRYPT(ecb);
    *cbc = cbc_encrypt;
}


void ccmode_cfb_init(const struct ccmode_cfb *cfb, cccfb_ctx *ctx,
                     size_t rawkey_len, const void *rawkey,
                     const void *iv);
void ccmode_cfb_decrypt(cccfb_ctx *ctx, size_t nbytes,
                        const void *in, void *out);
void ccmode_cfb_encrypt(cccfb_ctx *ctx, size_t nbytes,
                        const void *in, void *out);

struct _ccmode_cfb_key {
    const struct ccmode_ecb *ecb;
    size_t pad_len;
    cc_unit u[];
};

/* Use this to statically initialize a ccmode_cfb object for decryption. */
#define CCMODE_FACTORY_CFB_DECRYPT(ECB) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_cfb_key)) + 2 * ccn_sizeof_size((ECB)->block_size) + ccn_sizeof_size((ECB)->size), \
.block_size = 1, \
.init = ccmode_cfb_init, \
.cfb = ccmode_cfb_decrypt, \
.custom = (ECB) \
}

/* Use this to statically initialize a ccmode_cfb object for encryption. */
#define CCMODE_FACTORY_CFB_ENCRYPT(ECB) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_cfb_key)) + 2 * ccn_sizeof_size((ECB)->block_size) + ccn_sizeof_size((ECB)->size), \
.block_size = 1, \
.init = ccmode_cfb_init, \
.cfb = ccmode_cfb_encrypt, \
.custom = (ECB) \
}

/* Use these function to runtime initialize a ccmode_cfb decrypt object (for
 example if it's part of a larger structure). Normally you would pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
CC_INLINE
void ccmode_factory_cfb_decrypt(struct ccmode_cfb *cfb,
                                const struct ccmode_ecb *ecb) {
    struct ccmode_cfb cfb_decrypt = CCMODE_FACTORY_CFB_DECRYPT(ecb);
    *cfb = cfb_decrypt;
}

/* Use these function to runtime initialize a ccmode_cfb encrypt object (for
 example if it's part of a larger structure). Normally you would pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
CC_INLINE
void ccmode_factory_cfb_encrypt(struct ccmode_cfb *cfb,
                                const struct ccmode_ecb *ecb) {
    struct ccmode_cfb cfb_encrypt = CCMODE_FACTORY_CFB_ENCRYPT(ecb);
    *cfb = cfb_encrypt;
}


void ccmode_cfb8_init(const struct ccmode_cfb8 *cfb8, cccfb8_ctx *ctx,
                      size_t rawkey_len, const void *rawkey, const void *iv);
void ccmode_cfb8_decrypt(cccfb8_ctx *ctx, size_t nbytes,
                         const void *in, void *out);
void ccmode_cfb8_encrypt(cccfb8_ctx *ctx, size_t nbytes,
                         const void *in, void *out);

struct _ccmode_cfb8_key {
    const struct ccmode_ecb *ecb;
    cc_unit u[];
};

/* Use this to statically initialize a ccmode_cfb8 object for decryption. */
#define CCMODE_FACTORY_CFB8_DECRYPT(ECB) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_cfb8_key)) + 2 * ccn_sizeof_size((ECB)->block_size) + ccn_sizeof_size((ECB)->size), \
.block_size = 1, \
.init = ccmode_cfb8_init, \
.cfb8 = ccmode_cfb8_decrypt, \
.custom = (ECB) \
}

/* Use this to statically initialize a ccmode_cfb8 object for encryption. */
#define CCMODE_FACTORY_CFB8_ENCRYPT(ECB) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_cfb8_key)) + 2 * ccn_sizeof_size((ECB)->block_size) + ccn_sizeof_size((ECB)->size), \
.block_size = 1, \
.init = ccmode_cfb8_init, \
.cfb8 = ccmode_cfb8_encrypt, \
.custom = (ECB) \
}

/* Use these function to runtime initialize a ccmode_cfb8 decrypt object (for
 example if it's part of a larger structure). Normally you would pass a
 ecb decrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
CC_INLINE
void ccmode_factory_cfb8_decrypt(struct ccmode_cfb8 *cfb8,
                                 const struct ccmode_ecb *ecb) {
    struct ccmode_cfb8 cfb8_decrypt = CCMODE_FACTORY_CFB8_DECRYPT(ecb);
    *cfb8 = cfb8_decrypt;
}

/* Use these function to runtime initialize a ccmode_cfb8 encrypt object (for
 example if it's part of a larger structure). Normally you would pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
CC_INLINE
void ccmode_factory_cfb8_encrypt(struct ccmode_cfb8 *cfb8,
                                 const struct ccmode_ecb *ecb) {
    struct ccmode_cfb8 cfb8_encrypt = CCMODE_FACTORY_CFB8_ENCRYPT(ecb);
    *cfb8 = cfb8_encrypt;
}

void ccmode_ctr_init(const struct ccmode_ctr *ctr, ccctr_ctx *ctx,
                     size_t rawkey_len, const void *rawkey, const void *iv);
void ccmode_ctr_crypt(ccctr_ctx *ctx, size_t nbytes,
                      const void *in, void *out);

struct _ccmode_ctr_key {
    const struct ccmode_ecb *ecb;
    size_t pad_len;
    cc_unit u[];
};

/* Use this to statically initialize a ccmode_ctr object for decryption. */
#define CCMODE_FACTORY_CTR_CRYPT(ECB_ENCRYPT) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_ctr_key)) + 2 * ccn_sizeof_size((ECB_ENCRYPT)->block_size) + ccn_sizeof_size((ECB_ENCRYPT)->size), \
.block_size = 1, \
.init = ccmode_ctr_init, \
.ctr = ccmode_ctr_crypt, \
.custom = (ECB_ENCRYPT) \
}

/* Use these function to runtime initialize a ccmode_ctr decrypt object (for
 example if it's part of a larger structure). Normally you would pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
CC_INLINE
void ccmode_factory_ctr_crypt(struct ccmode_ctr *ctr,
                              const struct ccmode_ecb *ecb) {
    struct ccmode_ctr ctr_crypt = CCMODE_FACTORY_CTR_CRYPT(ecb);
    *ctr = ctr_crypt;
}

/* GCM FEATURES. */
//#define CCMODE_GCM_TABLES  1
#define CCMODE_GCM_FAST  1

#ifdef CCMODE_GCM_FAST
#define CCMODE_GCM_FAST_TYPE cc_unit
#endif

#ifdef CCMODE_GCM_TABLES

//#define CCMODE_GCM_TABLES_SSE2  1

extern const unsigned char gcm_shift_table[256*2];
#endif
#if	defined(__x86_64__) || defined(__arm64__)
#define	VNG_SPEEDUP	1
#endif

/* Create a gcm key from a gcm mode object.
 key must point to at least sizeof(CCMODE_GCM_KEY(ecb)) bytes of free
 storage. */
void ccmode_gcm_init(const struct ccmode_gcm *gcm, ccgcm_ctx *ctx,
                     size_t rawkey_len, const void *rawkey);
void ccmode_gcm_set_iv(ccgcm_ctx *ctx, size_t iv_size, const void *iv);
void ccmode_gcm_gmac(ccgcm_ctx *ctx, size_t nbytes, const void *in);
void ccmode_gcm_decrypt(ccgcm_ctx *ctx, size_t nbytes, const void *in,
                        void *out);
void ccmode_gcm_encrypt(ccgcm_ctx *ctx, size_t nbytes, const void *in,
                        void *out);
void ccmode_gcm_finalize(ccgcm_ctx *key, size_t tag_size, void *tag);
void ccmode_gcm_reset(ccgcm_ctx *key);

struct _ccmode_gcm_key {
    // 5 blocks of temp space.
    unsigned char H[16];       /* multiplier */
    unsigned char X[16];       /* accumulator */
    unsigned char Y[16];       /* counter */
    unsigned char Y_0[16];     /* initial counter */
    unsigned char buf[16];      /* buffer for stuff */

    const struct ccmode_ecb *ecb;
    uint32_t ivmode;       /* Which mode is the IV in? */
    uint32_t mode;         /* mode the GCM code is in */
    uint32_t buflen;       /* length of data in buf */

    uint64_t totlen;       /* 64-bit counter used for IV and AAD */
    uint64_t pttotlen;     /* 64-bit counter for the PT */

#ifdef CCMODE_GCM_TABLES
    /* TODO: Make table based gcm a separate mode object. */
    unsigned char       PC[16][256][16]  /* 16 tables of 8x128 */
#ifdef CCMODE_GCM_TABLES_SSE2
    __attribute__ ((aligned (16)))
#endif /* CCMODE_GCM_TABLES_SSE2 */
    ;
#endif /* CCMODE_GCM_TABLES */

#ifdef VNG_SPEEDUP
	unsigned char Htable[16*8*2] __attribute__((aligned(16)));
#endif
    
    cc_unit u[];

};

/* Use this to statically initialize a ccmode_gcm object for decryption. */
#define CCMODE_FACTORY_GCM_DECRYPT(ECB_ENCRYPT) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_gcm_key)) + 5 * ccn_sizeof_size((ECB_ENCRYPT)->block_size) + ccn_sizeof_size((ECB_ENCRYPT)->size), \
.block_size = 1, \
.init = ccmode_gcm_init, \
.set_iv = ccmode_gcm_set_iv, \
.gmac = ccmode_gcm_gmac, \
.gcm = ccmode_gcm_decrypt, \
.finalize = ccmode_gcm_finalize, \
.reset = ccmode_gcm_reset, \
.custom = (ECB_ENCRYPT) \
}

/* Use this to statically initialize a ccmode_gcm object for encryption. */
#define CCMODE_FACTORY_GCM_ENCRYPT(ECB_ENCRYPT) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_gcm_key)) + 5 * ccn_sizeof_size((ECB_ENCRYPT)->block_size) + ccn_sizeof_size((ECB_ENCRYPT)->size), \
.block_size = 1, \
.init = ccmode_gcm_init, \
.set_iv = ccmode_gcm_set_iv, \
.gmac = ccmode_gcm_gmac, \
.gcm = ccmode_gcm_encrypt, \
.finalize = ccmode_gcm_finalize, \
.reset = ccmode_gcm_reset, \
.custom = (ECB_ENCRYPT) \
}

/* Use these function to runtime initialize a ccmode_gcm decrypt object (for
 example if it's part of a larger structure). For GCM you always pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
CC_INLINE
void ccmode_factory_gcm_decrypt(struct ccmode_gcm *gcm,
                                const struct ccmode_ecb *ecb_encrypt) {
    struct ccmode_gcm gcm_decrypt = CCMODE_FACTORY_GCM_DECRYPT(ecb_encrypt);
    *gcm = gcm_decrypt;
}

/* Use these function to runtime initialize a ccmode_gcm encrypt object (for
 example if it's part of a larger structure). For GCM you always pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
CC_INLINE
void ccmode_factory_gcm_encrypt(struct ccmode_gcm *gcm,
                                const struct ccmode_ecb *ecb_encrypt) {
    struct ccmode_gcm gcm_encrypt = CCMODE_FACTORY_GCM_ENCRYPT(ecb_encrypt);
    *gcm = gcm_encrypt;
}


/* CCM (only NIST approved with AES) */
void ccmode_ccm_init(const struct ccmode_ccm *ccm, ccccm_ctx *ctx,
                     size_t rawkey_len, const void *rawkey);
void ccmode_ccm_set_iv(ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, size_t nonce_len, const void *nonce,
                       size_t mac_size, size_t auth_len, size_t data_len);
/* internal function */
void ccmode_ccm_macdata(ccccm_ctx *key, ccccm_nonce *nonce_ctx, unsigned new_block, size_t nbytes, const void *in);
/* api function - disallows only mac'd data after data to encrypt was sent */
void ccmode_ccm_cbcmac(ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, size_t nbytes, const void *in);
/* internal function */
void ccmode_ccm_crypt(ccccm_ctx *key, ccccm_nonce *nonce_ctx, size_t nbytes, const void *in, void *out);
void ccmode_ccm_decrypt(ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, size_t nbytes, const void *in,
                        void *out);
void ccmode_ccm_encrypt(ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, size_t nbytes, const void *in,
                        void *out);
void ccmode_ccm_finalize(ccccm_ctx *key, ccccm_nonce *nonce_ctx, void *mac);
void ccmode_ccm_reset(ccccm_ctx *key, ccccm_nonce *nonce_ctx);

struct _ccmode_ccm_key {
    const struct ccmode_ecb *ecb;
    cc_unit u[];
};

struct _ccmode_ccm_nonce {
    unsigned char A_i[16];      /* crypto block iv */
    unsigned char B_i[16];      /* mac block iv */
    unsigned char MAC[16];      /* crypted mac */
    unsigned char buf[16];      /* crypt buffer */

    uint32_t mode;         /* mode: IV -> AD -> DATA */
    uint32_t buflen;       /* length of data in buf */
    uint32_t b_i_len;      /* length of cbcmac data in B_i */

    size_t nonce_size;
    size_t mac_size;
};

/* Use this to statically initialize a ccmode_ccm object for decryption. */
#define CCMODE_FACTORY_CCM_DECRYPT(ECB_ENCRYPT) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_ccm_key)) + ccn_sizeof_size((ECB_ENCRYPT)->block_size) + ccn_sizeof_size((ECB_ENCRYPT)->size), \
.nonce_size = ccn_sizeof_size(sizeof(struct _ccmode_ccm_nonce)), \
.block_size = 1, \
.init = ccmode_ccm_init, \
.set_iv = ccmode_ccm_set_iv, \
.cbcmac = ccmode_ccm_cbcmac, \
.ccm = ccmode_ccm_decrypt, \
.finalize = ccmode_ccm_finalize, \
.reset = ccmode_ccm_reset, \
.custom = (ECB_ENCRYPT) \
}

/* Use this to statically initialize a ccmode_ccm object for encryption. */
#define CCMODE_FACTORY_CCM_ENCRYPT(ECB_ENCRYPT) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_ccm_key)) + ccn_sizeof_size((ECB_ENCRYPT)->block_size) + ccn_sizeof_size((ECB_ENCRYPT)->size), \
.nonce_size = ccn_sizeof_size(sizeof(struct _ccmode_ccm_nonce)), \
.block_size = 1, \
.init = ccmode_ccm_init, \
.set_iv = ccmode_ccm_set_iv, \
.cbcmac = ccmode_ccm_cbcmac, \
.ccm = ccmode_ccm_encrypt, \
.finalize = ccmode_ccm_finalize, \
.reset = ccmode_ccm_reset, \
.custom = (ECB_ENCRYPT) \
}

/* Use these function to runtime initialize a ccmode_ccm decrypt object (for
 example if it's part of a larger structure). For CCM you always pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
CC_INLINE
void ccmode_factory_ccm_decrypt(struct ccmode_ccm *ccm,
                                const struct ccmode_ecb *ecb_encrypt) {
    struct ccmode_ccm ccm_decrypt = CCMODE_FACTORY_CCM_DECRYPT(ecb_encrypt);
    *ccm = ccm_decrypt;
}

/* Use these function to runtime initialize a ccmode_ccm encrypt object (for
 example if it's part of a larger structure). For CCM you always pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
CC_INLINE
void ccmode_factory_ccm_encrypt(struct ccmode_ccm *ccm,
                                const struct ccmode_ecb *ecb_encrypt) {
    struct ccmode_ccm ccm_encrypt = CCMODE_FACTORY_CCM_ENCRYPT(ecb_encrypt);
    *ccm = ccm_encrypt;
}


void ccmode_ofb_init(const struct ccmode_ofb *ofb, ccofb_ctx *ctx,
                     size_t rawkey_len, const void *rawkey,
                     const void *iv);
void ccmode_ofb_crypt(ccofb_ctx *ctx, size_t nbytes,
                      const void *in, void *out);

struct _ccmode_ofb_key {
    const struct ccmode_ecb *ecb;
    size_t pad_len;
    cc_unit u[];
};

/* Use this to statically initialize a ccmode_ofb object. */
#define CCMODE_FACTORY_OFB_CRYPT(ECB) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_ofb_key)) + ccn_sizeof_size((ECB)->block_size) + ccn_sizeof_size((ECB)->size), \
.block_size = 1, \
.init = ccmode_ofb_init, \
.ofb = ccmode_ofb_crypt, \
.custom = (ECB) \
}

/* Use these function to runtime initialize a ccmode_ofb encrypt object (for
 example if it's part of a larger structure). Normally you would pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
CC_INLINE
void ccmode_factory_ofb_crypt(struct ccmode_ofb *ofb,
                              const struct ccmode_ecb *ecb) {
    struct ccmode_ofb ofb_crypt = CCMODE_FACTORY_OFB_CRYPT(ecb);
    *ofb = ofb_crypt;
}


int ccmode_omac_decrypt(ccomac_ctx *ctx, unsigned long nblocks,
                        const void *tweak, const void *in, void *out);
int ccmode_omac_encrypt(ccomac_ctx *ctx, unsigned long nblocks,
                        const void *tweak, const void *in, void *out);

/* Create a omac key from a omac mode object.  The tweak_len here
 determines how long the tweak is in bytes, for each subsequent call to
 ccmode_omac->omac().
 key must point to at least sizeof(CCMODE_OMAC_KEY(ecb)) bytes of free
 storage. */
void ccmode_omac_init(const struct ccmode_omac *omac, ccomac_ctx *ctx,
                      cc_size tweak_len, size_t rawkey_len,
                      const void *rawkey);

struct _ccmode_omac_key {
    const struct ccmode_ecb *ecb;
    size_t tweak_len;
    cc_unit u[];
};

/* Use this to statically initialize a ccmode_omac object for decryption. */
#define CCMODE_FACTORY_OMAC_DECRYPT(ECB) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_omac_key)) + 2 * ccn_sizeof_size((ECB)->size), \
.block_size = (ECB)->block_size, \
.init = ccmode_omac_init, \
.omac = ccmode_omac_decrypt, \
.custom = (ECB) \
}

/* Use this to statically initialize a ccmode_omac object for encryption. */
#define CCMODE_FACTORY_OMAC_ENCRYPT(ECB) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_omac_key)) + 2 * ccn_sizeof_size((ECB)->size), \
.block_size = (ECB)->block_size, \
.init = ccmode_omac_init, \
.omac = ccmode_omac_encrypt, \
.custom = (ECB) \
}

/* Use these function to runtime initialize a ccmode_omac decrypt object (for
 example if it's part of a larger structure). Normally you would pass a
 ecb decrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
CC_INLINE
void ccmode_factory_omac_decrypt(struct ccmode_omac *omac,
                                 const struct ccmode_ecb *ecb) {
    struct ccmode_omac omac_decrypt = CCMODE_FACTORY_OMAC_DECRYPT(ecb);
    *omac = omac_decrypt;
}

/* Use these function to runtime initialize a ccmode_omac encrypt object (for
 example if it's part of a larger structure). Normally you would pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
CC_INLINE
void ccmode_factory_omac_encrypt(struct ccmode_omac *omac,
                                 const struct ccmode_ecb *ecb) {
    struct ccmode_omac omac_encrypt = CCMODE_FACTORY_OMAC_ENCRYPT(ecb);
    *omac = omac_encrypt;
}


/* Function prototypes used by the macros below, do not call directly. */
void ccmode_xts_init(const struct ccmode_xts *xts, ccxts_ctx *ctx,
                     size_t key_len, const void *data_key,
                     const void *tweak_key);
void *ccmode_xts_crypt(const ccxts_ctx *ctx, ccxts_tweak *tweak,
                       unsigned long nblocks, const void *in, void *out);
void ccmode_xts_set_tweak(const ccxts_ctx *ctx, ccxts_tweak *tweak,
                          const void *iv);


struct _ccmode_xts_key {
    const struct ccmode_ecb *ecb;
    const struct ccmode_ecb *ecb_encrypt;
    cc_unit u[];
};

struct _ccmode_xts_tweak {
    // FIPS requires that for XTS that no more that 2^20 AES blocks may be processed for any given
    // Key, Tweak Key, and tweak combination
    // the bytes_processed field in the context will accumuate the number of blocks processed and
    // will fail the encrypt/decrypt if the size is violated.  This counter will be reset to 0
    // when set_tweak is called.
    unsigned long  blocks_processed;
    cc_unit u[];
};

/* Use this to statically initialize a ccmode_xts object for decryption. */
#define CCMODE_FACTORY_XTS_DECRYPT(ECB, ECB_ENCRYPT) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_xts_key)) + 2 * ccn_sizeof_size((ECB)->size), \
.tweak_size = ccn_sizeof_size(sizeof(struct _ccmode_xts_tweak)) + ccn_sizeof_size(16), \
.block_size = 16, \
.init = ccmode_xts_init, \
.set_tweak = ccmode_xts_set_tweak, \
.xts = ccmode_xts_crypt, \
.custom = (ECB), \
.custom1 = (ECB_ENCRYPT) \
}

/* Use this to statically initialize a ccmode_xts object for encryption. */
#define CCMODE_FACTORY_XTS_ENCRYPT(ECB, ECB_ENCRYPT) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_xts_key)) + 2 * ccn_sizeof_size((ECB)->size), \
.tweak_size = ccn_sizeof_size(sizeof(struct _ccmode_xts_tweak)) + ccn_sizeof_size(16), \
.block_size = 16, \
.init = ccmode_xts_init, \
.set_tweak = ccmode_xts_set_tweak, \
.xts = ccmode_xts_crypt, \
.custom = (ECB), \
.custom1 = (ECB_ENCRYPT) \
}

/* Use these function to runtime initialize a ccmode_xts decrypt object (for
 example if it's part of a larger structure). Normally you would pass a
 ecb decrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
CC_INLINE
void ccmode_factory_xts_decrypt(struct ccmode_xts *xts,
                                const struct ccmode_ecb *ecb,
                                const struct ccmode_ecb *ecb_encrypt) {
    struct ccmode_xts xts_decrypt = CCMODE_FACTORY_XTS_DECRYPT(ecb, ecb_encrypt);
    *xts = xts_decrypt;
}

/* Use these function to runtime initialize a ccmode_xts encrypt object (for
 example if it's part of a larger structure). Normally you would pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
CC_INLINE
void ccmode_factory_xts_encrypt(struct ccmode_xts *xts,
                                const struct ccmode_ecb *ecb,
                                const struct ccmode_ecb *ecb_encrypt) {
    struct ccmode_xts xts_encrypt = CCMODE_FACTORY_XTS_ENCRYPT(ecb, ecb_encrypt);
    *xts = xts_encrypt;
}

#endif /* _CORECRYPTO_CCMODE_FACTORY_H_ */

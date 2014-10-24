/*
 *  ccmode.h
 *  corecrypto
 *
 *  Created by Michael Brouwer on 12/6/10.
 *  Copyright 2010,2011 Apple Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_CCMODE_H_
#define _CORECRYPTO_CCMODE_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccmode_impl.h>

/* ECB mode. */

/* Declare a ecb key named _name_.  Pass the size field of a struct ccmode_ecb
   for _size_. */
#define ccecb_ctx_decl(_size_, _name_) cc_ctx_decl(ccecb_ctx, _size_, _name_)
#define ccecb_ctx_clear(_size_, _name_) cc_zero(_size_, _name_)

CC_INLINE size_t ccecb_context_size(const struct ccmode_ecb *mode)
{
    return mode->size;
}

CC_INLINE unsigned long ccecb_block_size(const struct ccmode_ecb *mode)
{
	return mode->block_size;
}

CC_INLINE void ccecb_init(const struct ccmode_ecb *mode, ccecb_ctx *ctx,
                          size_t key_len, const void *key)
{
    mode->init(mode, ctx, key_len, key);
}

CC_INLINE void ccecb_update(const struct ccmode_ecb *mode, const ccecb_ctx *ctx,
                            unsigned long nblocks, const void *in, void *out)
{
	mode->ecb(ctx, nblocks, in, out);
}

CC_INLINE void ccecb_one_shot(const struct ccmode_ecb *mode,
                              size_t key_len, const void *key,
                              unsigned long nblocks, const void *in, void *out)
{
	ccecb_ctx_decl(mode->size, ctx);
	mode->init(mode, ctx, key_len, key);
	mode->ecb(ctx, nblocks, in, out);
	ccecb_ctx_clear(mode->size, ctx);
}

/* CBC mode. */

/* The CBC interface changed due to rdar://11468135. This macros is to indicate 
   to client which CBC API is implemented. Clients can support old versions of
   corecrypto at build time using this.
 */
#define __CC_HAS_FIX_FOR_11468135__ 1

/* Declare a cbc key named _name_.  Pass the size field of a struct ccmode_cbc
   for _size_. */
#define cccbc_ctx_decl(_size_, _name_) cc_ctx_decl(cccbc_ctx, _size_, _name_)
#define cccbc_ctx_clear(_size_, _name_) cc_zero(_size_, _name_)

/* Declare a cbc iv tweak named _name_.  Pass the blocksize field of a
   struct ccmode_cbc for _size_. */
#define cccbc_iv_decl(_size_, _name_) cc_ctx_decl(cccbc_iv, _size_, _name_)
#define cccbc_iv_clear(_size_, _name_) cc_ctx_clear(cccbc_iv, _size_, _name_)

/* Actual symmetric algorithm implementation can provide you one of these.

   Alternatively you can create a ccmode_cbc instance from any ccmode_ecb
   cipher.  To do so, statically initialize a struct ccmode_cbc using the
   CCMODE_FACTORY_CBC_DECRYPT or CCMODE_FACTORY_CBC_ENCRYPT macros.
   Alternatively you can dynamically initialize a struct ccmode_cbc
   ccmode_factory_cbc_decrypt() or ccmode_factory_cbc_encrypt(). */

CC_INLINE size_t cccbc_context_size(const struct ccmode_cbc *mode)
{
    return mode->size;
}

CC_INLINE unsigned long cccbc_block_size(const struct ccmode_cbc *mode)
{
	return mode->block_size;
}

CC_INLINE void cccbc_init(const struct ccmode_cbc *mode, cccbc_ctx *ctx,
                          size_t key_len, const void *key)
{
    mode->init(mode, ctx, key_len, key);
}

CC_INLINE void cccbc_set_iv(const struct ccmode_cbc *mode, cccbc_iv *iv_ctx,
                            const void *iv)
{
    if (iv)
        cc_copy(mode->block_size, iv_ctx, iv);
    else
        cc_zero(mode->block_size, iv_ctx);
}

CC_INLINE void cccbc_update(const struct ccmode_cbc *mode,  cccbc_ctx *ctx,
                            cccbc_iv *iv, unsigned long nblocks,
                            const void *in, void *out)
{
	mode->cbc(ctx, iv, nblocks, in, out);
}

CC_INLINE void cccbc_one_shot(const struct ccmode_cbc *mode,
                              unsigned long key_len, const void *key,
                              const void *iv, unsigned long nblocks,
                              const void *in, void *out)
{
	cccbc_ctx_decl(mode->size, ctx);
	cccbc_iv_decl(mode->block_size, iv_ctx);
	mode->init(mode, ctx, key_len, key);
    if (iv)
        cccbc_set_iv(mode, iv_ctx, iv);
    else
        cc_zero(mode->block_size, iv_ctx);
    mode->cbc(ctx, iv_ctx, nblocks, in, out);
	cccbc_ctx_clear(mode->size, ctx);
}

/* CFB mode. */

/* Declare a cfb key named _name_.  Pass the size field of a struct ccmode_cfb
   for _size_. */
#define cccfb_ctx_decl(_size_, _name_) cc_ctx_decl(cccfb_ctx, _size_, _name_)
#define cccfb_ctx_clear(_size_, _name_) cc_zero(_size_, _name_)

CC_INLINE size_t cccfb_context_size(const struct ccmode_cfb *mode)
{
    return mode->size;
}

CC_INLINE unsigned long cccfb_block_size(const struct ccmode_cfb *mode)
{
	return mode->block_size;
}

CC_INLINE void cccfb_init(const struct ccmode_cfb *mode, cccfb_ctx *ctx,
                          size_t key_len, const void *key,
                          const void *iv)
{
    mode->init(mode, ctx, key_len, key, iv);
}

CC_INLINE void cccfb_update(const struct ccmode_cfb *mode, cccfb_ctx *ctx,
                            size_t nbytes, const void *in, void *out)
{
	mode->cfb(ctx, nbytes, in, out);
}

CC_INLINE void cccfb_one_shot(const struct ccmode_cfb *mode,
                              size_t key_len, const void *key, const void *iv,
                              size_t nbytes, const void *in, void *out)
{
	cccfb_ctx_decl(mode->size, ctx);
	mode->init(mode, ctx, key_len, key, iv);
	mode->cfb(ctx, nbytes, in, out);
	cccfb_ctx_clear(mode->size, ctx);
}

/* CFB8 mode. */

/* Declare a cfb8 key named _name_.  Pass the size field of a struct ccmode_cfb8
 for _size_. */
#define cccfb8_ctx_decl(_size_, _name_) cc_ctx_decl(cccfb8_ctx, _size_, _name_)
#define cccfb8_ctx_clear(_size_, _name_) cc_zero(_size_, _name_)

CC_INLINE size_t cccfb8_context_size(const struct ccmode_cfb8 *mode)
{
    return mode->size;
}

CC_INLINE unsigned long cccfb8_block_size(const struct ccmode_cfb8 *mode)
{
	return mode->block_size;
}

CC_INLINE void cccfb8_init(const struct ccmode_cfb8 *mode, cccfb8_ctx *ctx,
                           size_t key_len, const void *key, const void *iv)
{
    mode->init(mode, ctx, key_len, key, iv);
}

CC_INLINE void cccfb8_update(const struct ccmode_cfb8 *mode,  cccfb8_ctx *ctx,
                             size_t nbytes, const void *in, void *out)
{
	mode->cfb8(ctx, nbytes, in, out);
}

CC_INLINE void cccfb8_one_shot(const struct ccmode_cfb8 *mode,
                               size_t key_len, const void *key, const void *iv,
                               size_t nbytes, const void *in, void *out)
{
	cccfb8_ctx_decl(mode->size, ctx);
	mode->init(mode, ctx, key_len, key, iv);
	mode->cfb8(ctx, nbytes, in, out);
	cccfb8_ctx_clear(mode->size, ctx);
}

/* CTR mode. */

/* Declare a ctr key named _name_.  Pass the size field of a struct ccmode_ctr
 for _size_. */
#define ccctr_ctx_decl(_size_, _name_) cc_ctx_decl(ccctr_ctx, _size_, _name_)
#define ccctr_ctx_clear(_size_, _name_) cc_zero(_size_, _name_)

/* This is Integer Counter Mode: The IV is the initial value of the counter
 that is incremented by 1 for each new block. Use the mode flags to select
 if the IV/Counter is stored in big or little endian. */

CC_INLINE size_t ccctr_context_size(const struct ccmode_ctr *mode)
{
    return mode->size;
}

CC_INLINE unsigned long ccctr_block_size(const struct ccmode_ctr *mode)
{
	return mode->block_size;
}

CC_INLINE void ccctr_init(const struct ccmode_ctr *mode, ccctr_ctx *ctx,
                          size_t key_len, const void *key, const void *iv)
{
    mode->init(mode, ctx, key_len, key, iv);
}

CC_INLINE void ccctr_update(const struct ccmode_ctr *mode, ccctr_ctx *ctx,
                            size_t nbytes, const void *in, void *out)
{
	mode->ctr(ctx, nbytes, in, out);
}

CC_INLINE void ccctr_one_shot(const struct ccmode_ctr *mode,
	size_t key_len, const void *key, const void *iv,
    size_t nbytes, const void *in, void *out)
{
	ccctr_ctx_decl(mode->size, ctx);
	mode->init(mode, ctx, key_len, key, iv);
	mode->ctr(ctx, nbytes, in, out);
	ccctr_ctx_clear(mode->size, ctx);
}


/* OFB mode. */

/* Declare a ofb key named _name_.  Pass the size field of a struct ccmode_ofb
 for _size_. */
#define ccofb_ctx_decl(_size_, _name_) cc_ctx_decl(ccofb_ctx, _size_, _name_)
#define ccofb_ctx_clear(_size_, _name_) cc_zero(_size_, _name_)

CC_INLINE size_t ccofb_context_size(const struct ccmode_ofb *mode)
{
    return mode->size;
}

CC_INLINE unsigned long ccofb_block_size(const struct ccmode_ofb *mode)
{
	return mode->block_size;
}

CC_INLINE void ccofb_init(const struct ccmode_ofb *mode, ccofb_ctx *ctx,
                          size_t key_len, const void *key, const void *iv)
{
    mode->init(mode, ctx, key_len, key, iv);
}

CC_INLINE void ccofb_update(const struct ccmode_ofb *mode, ccofb_ctx *ctx,
                            size_t nbytes, const void *in, void *out)
{
	mode->ofb(ctx, nbytes, in, out);
}

CC_INLINE void ccofb_one_shot(const struct ccmode_ofb *mode,
                              size_t key_len, const void *key, const void *iv,
                              size_t nbytes, const void *in, void *out)
{
	ccofb_ctx_decl(mode->size, ctx);
	mode->init(mode, ctx, key_len, key, iv);
	mode->ofb(ctx, nbytes, in, out);
	ccofb_ctx_clear(mode->size, ctx);
}

/* Authenticated cipher modes. */

/* XTS mode. */

/* Declare a xts key named _name_.  Pass the size field of a struct ccmode_xts
 for _size_. */
#define ccxts_ctx_decl(_size_, _name_) cc_ctx_decl(ccxts_ctx, _size_, _name_)
#define ccxts_ctx_clear(_size_, _name_) cc_zero(_size_, _name_)

/* Declare a xts tweak named _name_.  Pass the tweak_size field of a
   struct ccmode_xts for _size_. */
#define ccxts_tweak_decl(_size_, _name_) cc_ctx_decl(ccxts_tweak, _size_, _name_)
#define ccxts_tweak_clear(_size_, _name_) cc_zero(_size_, _name_)

/* Actual symmetric algorithm implementation can provide you one of these.

 Alternatively you can create a ccmode_xts instance from any ccmode_ecb
 cipher.  To do so, statically initialize a struct ccmode_xts using the
 CCMODE_FACTORY_XTS_DECRYPT or CCMODE_FACTORY_XTS_ENCRYPT macros. Alternatively
 you can dynamically initialize a struct ccmode_xts
 ccmode_factory_xts_decrypt() or ccmode_factory_xts_encrypt(). */

/* NOTE that xts mode does not do cts padding.  It's really an xex mode.
   If you need cts padding use the ccpad_xts_encrypt and ccpad_xts_decrypt
   functions.   Also note that xts only works for ecb modes with a block_size
   of 16.  */

CC_INLINE size_t ccxts_context_size(const struct ccmode_xts *mode)
{
    return mode->size;
}

CC_INLINE unsigned long ccxts_block_size(const struct ccmode_xts *mode)
{
	return mode->block_size;
}

CC_INLINE void ccxts_init(const struct ccmode_xts *mode, ccxts_ctx *ctx,
                          size_t key_len, const void *key,
                          const void *tweak_key)
{
    mode->init(mode, ctx, key_len, key, tweak_key);
}

CC_INLINE void ccxts_set_tweak(const struct ccmode_xts *mode, ccxts_ctx *ctx,
                               ccxts_tweak *tweak, const void *iv)
{
	mode->set_tweak(ctx, tweak, iv);
}

CC_INLINE void *ccxts_update(const struct ccmode_xts *mode, ccxts_ctx *ctx,
	ccxts_tweak *tweak, unsigned long nblocks, const void *in, void *out)
{
	return mode->xts(ctx, tweak, nblocks, in, out);
}

CC_INLINE void ccxts_one_shot(const struct ccmode_xts *mode,
                              size_t key_len, const void *key,
                              const void *tweak_key, const void *iv,
                              unsigned long nblocks, const void *in, void *out)
{
	ccxts_ctx_decl(mode->size, ctx);
    ccxts_tweak_decl(mode->tweak_size, tweak);
	mode->init(mode, ctx, key_len, key, tweak_key);
    mode->set_tweak(ctx, tweak, iv);
	mode->xts(ctx, tweak, nblocks, in, out);
	ccxts_ctx_clear(mode->size, ctx);
    ccxts_tweak_clear(mode->tweak_size, tweak);
}

/* GCM mode. */

/* Declare a gcm key named _name_.  Pass the size field of a struct ccmode_gcm
 for _size_. */
#define ccgcm_ctx_decl(_size_, _name_) cc_ctx_decl(ccgcm_ctx, _size_, _name_)
#define ccgcm_ctx_clear(_size_, _name_) cc_zero(_size_, _name_)

CC_INLINE size_t ccgcm_context_size(const struct ccmode_gcm *mode)
{
    return mode->size;
}

CC_INLINE unsigned long ccgcm_block_size(const struct ccmode_gcm *mode)
{
	return mode->block_size;
}

CC_INLINE void ccgcm_init(const struct ccmode_gcm *mode, ccgcm_ctx *ctx,
                          size_t key_len, const void *key)
{
    mode->init(mode, ctx, key_len, key);
}

CC_INLINE void ccgcm_set_iv(const struct ccmode_gcm *mode, ccgcm_ctx *ctx,
                            size_t iv_size, const void *iv)
{
	mode->set_iv(ctx, iv_size, iv);
}

CC_INLINE void ccgcm_gmac(const struct ccmode_gcm *mode, ccgcm_ctx *ctx,
                          size_t nbytes, const void *in)
{
	mode->gmac(ctx, nbytes, in);
}

CC_INLINE void ccgcm_update(const struct ccmode_gcm *mode, ccgcm_ctx *ctx,
                            size_t nbytes, const void *in, void *out)
{
	mode->gcm(ctx, nbytes, in, out);
}

CC_INLINE void ccgcm_finalize(const struct ccmode_gcm *mode, ccgcm_ctx *ctx,
                              size_t tag_size, void *tag)
{
	mode->finalize(ctx, tag_size, tag);
}

CC_INLINE void ccgcm_reset(const struct ccmode_gcm *mode, ccgcm_ctx *ctx)
{
    mode->reset(ctx);
}


CC_INLINE void ccgcm_one_shot(const struct ccmode_gcm *mode,
                              size_t key_len, const void *key,
                              size_t iv_len, const void *iv,
                              size_t adata_len, const void *adata,
                              size_t nbytes, const void *in, void *out,
                              size_t tag_len, void *tag)
{
	ccgcm_ctx_decl(mode->size, ctx);
	mode->init(mode, ctx, key_len, key);
	mode->set_iv(ctx, iv_len, iv);
	mode->gmac(ctx, adata_len, adata);
	mode->gcm(ctx, nbytes, in, out);
	mode->finalize(ctx, tag_len, tag);
	ccgcm_ctx_clear(mode->size, ctx);
}

/* CCM */

#define ccccm_ctx_decl(_size_, _name_) cc_ctx_decl(ccccm_ctx, _size_, _name_)
#define ccccm_ctx_clear(_size_, _name_) cc_zero(_size_, _name_)

/* Declare a ccm nonce named _name_.  Pass the mode->nonce_ctx_size for _size_. */
#define ccccm_nonce_decl(_size_, _name_) cc_ctx_decl(ccccm_nonce, _size_, _name_)
#define ccccm_nonce_clear(_size_, _name_) cc_zero(_size_, _name_)


CC_INLINE size_t ccccm_context_size(const struct ccmode_ccm *mode)
{
    return mode->size;
}

CC_INLINE unsigned long ccccm_block_size(const struct ccmode_ccm *mode)
{
	return mode->block_size;
}

CC_INLINE void ccccm_init(const struct ccmode_ccm *mode, ccccm_ctx *ctx,
                          size_t key_len, const void *key)
{
    mode->init(mode, ctx, key_len, key);
}

CC_INLINE void ccccm_set_iv(const struct ccmode_ccm *mode, ccccm_ctx *ctx, ccccm_nonce *nonce_ctx,
                            size_t nonce_len, const void *nonce,
                            size_t mac_size, size_t auth_len, size_t data_len)
{
	mode->set_iv(ctx, nonce_ctx, nonce_len, nonce, mac_size, auth_len, data_len);
}

CC_INLINE void ccccm_cbcmac(const struct ccmode_ccm *mode, ccccm_ctx *ctx, ccccm_nonce *nonce_ctx,
                          size_t nbytes, const void *in)
{
	mode->cbcmac(ctx, nonce_ctx, nbytes, in);
}

CC_INLINE void ccccm_update(const struct ccmode_ccm *mode, ccccm_ctx *ctx, ccccm_nonce *nonce_ctx,
                            size_t nbytes, const void *in, void *out)
{
	mode->ccm(ctx, nonce_ctx, nbytes, in, out);
}

CC_INLINE void ccccm_finalize(const struct ccmode_ccm *mode, ccccm_ctx *ctx, ccccm_nonce *nonce_ctx,
                              void *mac)
{
	mode->finalize(ctx, nonce_ctx, mac);
}

CC_INLINE void ccccm_reset(const struct ccmode_ccm *mode, ccccm_ctx *ctx, ccccm_nonce *nonce_ctx)
{
    mode->reset(ctx, nonce_ctx);
}


CC_INLINE void ccccm_one_shot(const struct ccmode_ccm *mode,
                              unsigned long key_len, const void *key,
                              unsigned nonce_len, const void *nonce,
                              unsigned long nbytes, const void *in, void *out,
                              unsigned adata_len, const void* adata,
                              unsigned mac_size, void *mac)
{
	ccccm_ctx_decl(mode->size, ctx);
	ccccm_nonce_decl(mode->nonce_size, nonce_ctx);
	mode->init(mode, ctx, key_len, key);
	mode->set_iv(ctx, nonce_ctx, nonce_len, nonce, mac_size, adata_len, nbytes);
	mode->cbcmac(ctx, nonce_ctx, adata_len, adata);
	mode->ccm(ctx, nonce_ctx, nbytes, in, out);
	mode->finalize(ctx, nonce_ctx, mac);
	ccccm_ctx_clear(mode->size, ctx);
    ccccm_nonce_clear(mode->size, nonce_ctx);
}


/* OMAC mode. */


/* Declare a omac key named _name_.  Pass the size field of a struct ccmode_omac
 for _size_. */
#define ccomac_ctx_decl(_size_, _name_) cc_ctx_decl(ccomac_ctx, _size_, _name_)
#define ccomac_ctx_clear(_size_, _name_) cc_zero(_size_, _name_)

CC_INLINE size_t ccomac_context_size(const struct ccmode_omac *mode)
{
    return mode->size;
}

CC_INLINE unsigned long ccomac_block_size(const struct ccmode_omac *mode)
{
	return mode->block_size;
}

CC_INLINE void ccomac_init(const struct ccmode_omac *mode, ccomac_ctx *ctx,
                           size_t tweak_len, size_t key_len, const void *key)
{
    return mode->init(mode, ctx, tweak_len, key_len, key);
}

CC_INLINE int ccomac_update(const struct ccmode_omac *mode, ccomac_ctx *ctx,
	unsigned long nblocks, const void *tweak, const void *in, void *out)
{
	return mode->omac(ctx, nblocks, tweak, in, out);
}

CC_INLINE int ccomac_one_shot(const struct ccmode_omac *mode,
	size_t tweak_len, size_t key_len, const void *key,
	const void *tweak, unsigned long nblocks, const void *in, void *out)
{
	ccomac_ctx_decl(mode->size, ctx);
	mode->init(mode, ctx, tweak_len, key_len, key);
	int result = mode->omac(ctx, nblocks, tweak, in, out);
	ccomac_ctx_clear(mode->size, ctx);
    return result;
}


#endif /* _CORECRYPTO_CCMODE_H_ */

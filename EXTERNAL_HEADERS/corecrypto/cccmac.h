/*
 *  cccmac.h
 *  corecrypto
 *
 *  Created on 11/07/2013
 *
 *  Copyright (c) 2013,2014,2015 Apple Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_cccmac_H_
#define _CORECRYPTO_cccmac_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccaes.h>

#define CMAC_BLOCKSIZE 16

#if CORECRYPTO_USE_TRANSPARENT_UNION
struct cccmac_ctx {
    uint8_t b[8];
} CC_ALIGNED(8);

typedef struct cccmac_ctx_hdr {
    uint8_t k1[16];
    uint8_t k2[16];
    uint8_t ctx[8];
} CC_ALIGNED(8) cccmac_ctx_hdr;


typedef union {
    struct cccmac_ctx *b;
    cccmac_ctx_hdr *hdr;
} cccmac_ctx_t __attribute__((transparent_union));
#define cccmac_hdr_size sizeof(struct cccmac_ctx_hdr)

#else

struct cccmac_ctx {
    uint8_t k1[16];
    uint8_t k2[16];
    uint8_t ctx[8];
} CC_ALIGNED(8);// cccmac_ctx_hdr;

typedef struct cccmac_ctx* cccmac_ctx_t;

#define cccmac_hdr_size sizeof(struct cccmac_ctx)

#endif


#define cccmac_iv_size(_mode_)  ((_mode_)->block_size)
#define cccmac_cbc_size(_mode_) ((_mode_)->size)

#define cccmac_ctx_size(_mode_) (cccmac_hdr_size + cccmac_iv_size(_mode_) + cccmac_cbc_size(_mode_))
#define cccmac_ctx_n(_mode_)  ccn_nof_size(cccmac_ctx_size(_mode_))

#define cccmac_mode_decl(_mode_, _name_) cc_ctx_decl(struct cccmac_ctx, cccmac_ctx_size(_mode_), _name_)
#define cccmac_mode_clear(_mode_, _name_) cc_clear(cccmac_ctx_size(_mode_), _name_)

#if CORECRYPTO_USE_TRANSPARENT_UNION
/* Return a cccbc_ctx * which can be accesed with the macros in ccmode.h */
#define cccmac_mode_ctx_start(_mode_, HC)     (((HC).hdr)->ctx)
#define CCCMAC_HDR(HC)      (((cccmac_ctx_t)(HC)).hdr)
#else
/* Return a cccbc_ctx * which can be accesed with the macros in ccmode.h */
#define cccmac_mode_ctx_start(_mode_, HC)    (HC->ctx)
#define CCCMAC_HDR(HC)      (HC)
#endif

#define cccmac_mode_sym_ctx(_mode_, HC)     (cccbc_ctx *)(cccmac_mode_ctx_start(_mode_, HC))
#define cccmac_mode_iv(_mode_, HC)     (cccbc_iv *)(cccmac_mode_ctx_start(_mode_, HC)+cccmac_cbc_size(_mode_))
#define cccmac_k1(HC)       (CCCMAC_HDR(HC)->k1)
#define cccmac_k2(HC)       (CCCMAC_HDR(HC)->k2)

void cccmac_init(const struct ccmode_cbc *cbc, cccmac_ctx_t ctx, const void *key);


void cccmac_block_update(const struct ccmode_cbc *cbc, cccmac_ctx_t cmac,
                                       size_t nblocks, const void *data);


void cccmac_final(const struct ccmode_cbc *cbc, cccmac_ctx_t ctx,
                  size_t nbytes, const void *in, void *out);

void cccmac(const struct ccmode_cbc *cbc, const void *key,
            size_t data_len, const void *data,
            void *mac);


#endif /* _CORECRYPTO_cccmac_H_ */

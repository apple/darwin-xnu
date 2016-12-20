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

#define CMAC_BLOCKSIZE   16

#if CORECRYPTO_USE_TRANSPARENT_UNION
struct cccmac_ctx {
    uint8_t b[8];
} CC_ALIGNED(8);

typedef struct cccmac_ctx_hdr {
    uint8_t k1[CMAC_BLOCKSIZE];
    uint8_t k2[CMAC_BLOCKSIZE];
    uint8_t block[CMAC_BLOCKSIZE];
    size_t  block_nbytes;      // Number of byte occupied in block buf
    size_t  cumulated_nbytes;  // Total size processed
    const struct ccmode_cbc *cbc;
    uint8_t ctx[8];
} CC_ALIGNED(8) cccmac_ctx_hdr;


typedef union {
    struct cccmac_ctx *b;
    cccmac_ctx_hdr *hdr;
} cccmac_ctx_t __attribute__((transparent_union));
#define cccmac_hdr_size sizeof(struct cccmac_ctx_hdr)

#else

struct cccmac_ctx {
    uint8_t k1[CMAC_BLOCKSIZE];
    uint8_t k2[CMAC_BLOCKSIZE];
    uint8_t block[CMAC_BLOCKSIZE];
    size_t  block_nbytes; // Number of byte occupied in block
    size_t  cumulated_nbytes;  // Total size processed
    const struct ccmode_cbc *cbc;
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
#define cccmac_block(HC)    (CCCMAC_HDR(HC)->block)
#define cccmac_cbc(HC)      (CCCMAC_HDR(HC)->cbc)
#define cccmac_block_nbytes(HC)        (CCCMAC_HDR(HC)->block_nbytes)
#define cccmac_cumulated_nbytes(HC)    (CCCMAC_HDR(HC)->cumulated_nbytes)


/* CMAC as defined in NIST SP800-38B - 2005 */

/* HACK: 
 To change the prototype of cccmac_init (and preserve the name) we need to
 proceed in steps:
 1) Make corecrypto change (23557380)
 2) Have all clients define "CC_CHANGEFUNCTION_28544056_cccmac_init"
 3) Remove CC_CHANGEFUNCTION_28544056_cccmac_init logic and old functions of corecrypto
 4) Clients can remove CC_CHANGEFUNCTION_28544056_cccmac_init at their leisure
 
 */

/* =============================================================================

                                ONE SHOT

 ==============================================================================*/

/*!
 @function   cccmac_one_shot_generate
 @abstract   CMAC generation in one call

 @param   cbc          CBC and block cipher specification
 @param   key_nbytes   Length of the key in bytes
 @param   key          Pointer to the key of length key_nbytes
 @param   data_nbytes  Length of the data in bytes
 @param   data         Pointer to the data in bytes
 @param   mac_nbytes   Length in byte of the mac, > 0
 @param   mac          Output of length cbc->block_size

 @result     0 iff successful.

 @discussion Only supports CMAC_BLOCKSIZE block ciphers
 */
int cccmac_one_shot_generate(const struct ccmode_cbc *cbc,
                        size_t key_nbytes, const void *key,
                        size_t data_nbytes, const void *data,
                        size_t mac_nbytes, void *mac);

/*!
 @function   cccmac_one_shot_verify
 @abstract   CMAC verification in one call

 @param   cbc          CBC and block cipher specification
 @param   key_nbytes  Length of the key in bytes
 @param   key          Pointer to the key of length key_nbytes
 @param   data_nbytes Length of the data in bytes
 @param   data         Pointer to the data in bytes
 @param   expected_mac_nbytes  Length in byte of the mac, > 0
 @param   expected_mac Mac value expected

 @result     0 iff successful.

 @discussion Only supports CMAC_BLOCKSIZE block ciphers
 */
int cccmac_one_shot_verify(const struct ccmode_cbc *cbc,
                           size_t key_nbytes, const void *key,
                           size_t data_nbytes, const void *data,
                           size_t expected_mac_nbytes, const void *expected_mac);

/* =============================================================================

                               STREAMING
 
                        Init - Update - Final

==============================================================================*/

/*!
 @function   cccmac_init
 @abstract   Init CMAC context with CBC mode and key

 @param   cbc         CBC and block cipher specification
 @param   ctx         Context use to store internal state
 @param   key_nbytes  Length of the key in bytes
 @param   key         Full key

 @result     0 iff successful.

 @discussion Only supports CMAC_BLOCKSIZE block ciphers
 */



#ifndef CC_CHANGEFUNCTION_28544056_cccmac_init
int cccmac_init(const struct ccmode_cbc *cbc,
                  cccmac_ctx_t ctx,
                  size_t key_nbytes, const void *key)
// This is the good prototype! The deprecate warning is only for clients using the old function (now defined as macro)
__attribute__((deprecated("see guidelines in corecrypto/cccmac.h for migration", "define 'CC_CHANGEFUNCTION_28544056_cccmac_init' and use new cccmac_init with parameter key_nbytes")));
#else
int cccmac_init(const struct ccmode_cbc *cbc,
                cccmac_ctx_t ctx,
                size_t key_nbytes, const void *key);
#endif

/*!
 @function   cccmac_update
 @abstract   Process data

 @param   ctx          Context use to store internal state
 @param   data_nbytes Length in byte of the data
 @param   data         Data to process

 @result     0 iff successful.

 @discussion Only supports CMAC_BLOCKSIZE block ciphers
 */

int cccmac_update(cccmac_ctx_t ctx,
                  size_t data_nbytes, const void *data);

/*!
 @function   cccmac_final_generate
 @abstract   Final step for generation

 @param   ctx          Context use to store internal state
 @param   mac_nbytes   Length in byte of the mac, > 0
 @param   mac          Output of length mac_nbytes

 @result     0 iff successful.

 @discussion Only supports CMAC_BLOCKSIZE block ciphers
 */
int cccmac_final_generate(cccmac_ctx_t ctx,
                     size_t mac_nbytes, void *mac);

/*!
 @function   cccmac_final_verify
 @abstract   Final step and verification

 @param   ctx          Context use to store internal state
 @param   expected_mac_nbytes  Length in byte of the mac, > 0
 @param   expected_mac Mac value expected

 @result     0 iff successful.

 @discussion Only supports CMAC_BLOCKSIZE block ciphers
 */
int cccmac_final_verify(cccmac_ctx_t ctx,
                        size_t expected_mac_nbytes, const void *expected_mac);


/* =============================================================================

 Legacy - Please migrate to new functions above

 ==============================================================================*/

#ifndef CC_CHANGEFUNCTION_28544056_cccmac_init

/*
 Guidelines for switching to new CMAC functions

 Legacy                        New functions
 cccmac_init         -> cccmac_init w/ key kength in bytes
 cccmac_block_update -> cccmac_update w/ size in bytes instead of blocks
 cccmac_final        -> cccmac_final_generate or cccmac_final_verify
 depending the use case preceeded
 by cccmac_update if any leftover bytes.
 cccmac              -> cccmac_one_shot_generate or cccmac_one_shot_verify
 depending the use case

 */

/*!
 @function   cccmac_init
 @abstract   Initialize CMAC context with 128bit key
 
 Define CC_CHANGEFUNCTION_28544056_cccmac_init and use "cccmac_init(...,...,16,...)"

 */
#define cccmac_init(cbc,ctx,key) cccmac_init(cbc,ctx,16,key)

#endif /* CC_CHANGEFUNCTION_28544056_cccmac_init - TO BE REMOVED WITH 28544056 */

/*!
 @function   cccmac_block_update
 @abstract   Process data
 */

CC_INLINE void cccmac_block_update(CC_UNUSED const struct ccmode_cbc *cbc, cccmac_ctx_t ctx,
                         size_t nblocks, const void *data)
__attribute__((deprecated("see guidelines in corecrypto/cccmac.h for migration", "cccmac_update")));

CC_INLINE void cccmac_block_update(CC_UNUSED const struct ccmode_cbc *cbc, cccmac_ctx_t ctx,
                                   size_t nblocks, const void *data) {
    cccmac_update(ctx,(nblocks)*CMAC_BLOCKSIZE,data);
}

/*!
 @function   cccmac_final
 @abstract   Finalize CMAC generation
 */
CC_INLINE void cccmac_final(CC_UNUSED const struct ccmode_cbc *cbc, cccmac_ctx_t ctx,
                            size_t nbytes, const void *in, void *out)
__attribute__((deprecated("see guidelines in corecrypto/cccmac.h for migration", "cccmac_final_generate or cccmac_final_verify")));

CC_INLINE void cccmac_final(CC_UNUSED const struct ccmode_cbc *cbc, cccmac_ctx_t ctx,
                 size_t nbytes, const void *in, void *out) {
    cccmac_update(ctx, nbytes, in);
    cccmac_final_generate(ctx,CMAC_BLOCKSIZE,out);
}

/*!
 @function   cccmac
 @abstract   One shot CMAC generation with 128bit key
 */
CC_INLINE void cccmac(const struct ccmode_cbc *cbc,
                      const void *key,
                      size_t data_len, const void *data, void *mac)
__attribute__((deprecated("see guidelines in corecrypto/cccmac.h for migration", "cccmac_one_shot_generate or cccmac_one_shot_verify")));

CC_INLINE void cccmac(const struct ccmode_cbc *cbc,
           const void *key,
           size_t data_len, const void *data, void *mac) {
    cccmac_one_shot_generate(cbc,16,key,data_len,data,16,mac);
}



#endif /* _CORECRYPTO_cccmac_H_ */

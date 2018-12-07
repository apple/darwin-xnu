/*
 *  cckprng.h
 *  corecrypto
 *
 *  Created on 12/7/2017
 *
 *  Copyright (c) 2017 Apple Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_CCKPRNG_H_
#define _CORECRYPTO_CCKPRNG_H_

#include <corecrypto/cc.h>

typedef struct PRNG *PrngRef;
typedef struct cckprng_ctx *cckprng_ctx_t;

struct cckprng_ctx {
    PrngRef prng;
    uint64_t bytes_since_entropy;
    uint64_t bytes_generated;
};

#define CCKPRNG_ENTROPY_INTERVAL (1 << 14)
#define CCKPRNG_RESEED_NTICKS 50

/*
  @function cckprng_init
  @abstract Initialize a kernel PRNG context.

  @param ctx Context for this instance
  @param nbytes Length of the seed in bytes
  @param seed Pointer to a high-entropy seed

  @result @p CCKPRNG_OK iff successful. Panic on @p CCKPRNG_ABORT.
*/
int cckprng_init(cckprng_ctx_t ctx, size_t nbytes, const void *seed);

/*
  @function cckprng_reseed
  @abstract Reseed a kernel PRNG context immediately.

  @param ctx Context for this instance
  @param nbytes Length of the seed in bytes
  @param seed Pointer to a high-entropy seed

  @result @p CCKPRNG_OK iff successful. Panic on @p CCKPRNG_ABORT.
*/
int cckprng_reseed(cckprng_ctx_t ctx, size_t nbytes, const void *seed);

/*
  @function cckprng_addentropy
  @abstract Add entropy to a kernel PRNG context.

  @param ctx Context for this instance
  @param nbytes Length of the input entropy in bytes
  @param seed Pointer to input entropy

  @result @p CCKPRNG_OK iff successful. Panic on @p CCKPRNG_ABORT.

  @discussion Input entropy is stored internally and consumed at the
  opportune moment. This will not necessarily be before the next call
  to @p cckprng_generate. To force an immediate reseed, call @p
  cckprng_reseed.
*/
int cckprng_addentropy(cckprng_ctx_t ctx, size_t nbytes, const void *entropy);

/*
  @function cckprng_generate
  @abstract Generate random values for use in applications.

  @param ctx Context for this instance
  @param nbytes Length of the desired output in bytes
  @param seed Pointer to the output buffer

  @result @p CCKPRNG_OK iff successful. Panic on @p
  CCKPRNG_ABORT. Provide input to @p cckprng_addentropy on @p
  CCKPRNG_NEED_ENTROPY.
*/
int cckprng_generate(cckprng_ctx_t ctx, size_t nbytes, void *out);

#endif /* _CORECRYPTO_CCKPRNG_H_ */

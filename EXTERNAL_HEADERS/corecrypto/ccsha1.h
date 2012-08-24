/*
 *  ccsha1.h
 *  corecrypto
 *
 *  Created by Michael Brouwer on 12/1/10.
 *  Copyright 2010,2011 Apple Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_CCSHA1_H_
#define _CORECRYPTO_CCSHA1_H_

#include <corecrypto/ccdigest.h>
#include <corecrypto/cc_config.h>

#define CCSHA1_BLOCK_SIZE   64
#define CCSHA1_OUTPUT_SIZE  20
#define CCSHA1_STATE_SIZE   20

/* sha1 selector */
const struct ccdigest_info *ccsha1_di(void);

extern const uint32_t ccsha1_initial_state[5];

/* shared between several implementations */
void ccsha1_final(const struct ccdigest_info *di, ccdigest_ctx_t,
                  unsigned char *digest);


/* Implementations */
extern const struct ccdigest_info ccsha1_ltc_di;
extern const struct ccdigest_info ccsha1_eay_di;

#if CCSHA1_VNG_INTEL
extern const struct ccdigest_info ccsha1_vng_intel_SSE3_di;
extern const struct ccdigest_info ccsha1_vng_intel_NOSSE3_di;
#endif

#if CCSHA1_VNG_ARMV7NEON
extern const struct ccdigest_info ccsha1_vng_armv7neon_di;
#endif

/* TODO: Placeholders */
#define ccoid_sha1 ((unsigned char *)"\x06\x05\x2b\x0e\x03\x02\x1a")
#define ccoid_sha1_len 7

#endif /* _CORECRYPTO_CCSHA1_H_ */

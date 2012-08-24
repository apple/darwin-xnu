/*
 *  ccrng.h
 *  corecrypto
 *
 *  Created by Fabrice Gautier on 12/13/10.
 *  Copyright 2010 Apple, Inc. All rights reserved.
 *
 */


#ifndef _CORECRYPTO_CCRNG_H_
#define _CORECRYPTO_CCRNG_H_

#include <stdint.h>

#define CCRNG_STATE_COMMON                                                          \
    int (*generate)(struct ccrng_state *rng, unsigned long outlen, void *out);

/* default state structure - do not instantiate, instead use the specific one you need */
struct ccrng_state {
    CCRNG_STATE_COMMON
};

#define ccrng_generate(ctx, outlen, out) ((ctx)->generate((ctx), (outlen), (out)))

#endif /* _CORECRYPTO_CCRNG_H_ */

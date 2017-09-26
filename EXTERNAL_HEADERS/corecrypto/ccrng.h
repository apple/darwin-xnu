/*
 *  ccrng.h
 *  corecrypto
 *
 *  Created on 12/13/2010
 *
 *  Copyright (c) 2010,2011,2013,2014,2015 Apple Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_CCRNG_H_
#define _CORECRYPTO_CCRNG_H_

#include <corecrypto/cc.h>

#define CCERR_DEVICE                   -100
#define CCERR_INTERUPTS                -101
#define CCERR_CRYPTO_CONFIG            -102
#define CCERR_PERMS                    -103
#define CCERR_PARAMETER                -104
#define CCERR_MEMORY                   -105
#define CCERR_FILEDESC                 -106
#define CCERR_OUT_OF_ENTROPY           -107
#define CCERR_INTERNAL                 -108
#define CCERR_ATFORK                   -109
#define CCERR_OVERFLOW                 -110

#define CCRNG_STATE_COMMON                                                          \
    int (*generate)(struct ccrng_state *rng, size_t outlen, void *out);

/* default state structure. Do not instantiate, ccrng() returns a reference to this structure */
struct ccrng_state {
    CCRNG_STATE_COMMON
};

/*!
 @function   ccrng
 @abstract   initializes a AES-CTR mode cryptographic random number generator and returns the statically alocated rng object. 
             Getting a pointer to a ccrng has never been simpler! 
             Call this function, get an rng object and then pass the object to ccrng_generate() to generate randoms.
             ccrng() may be called more than once. It returns pointer to the same object on all calls.

 @result  a cryptographically secure random number generator or NULL if fails
 
 @discussion 
 - It is significantly faster than using the system /dev/random
 - FIPS Compliant: NIST SP800-80A + FIPS 140-2
 - Seeded from the system entropy.
 - Provides at least 128bit security if the system provide 2bit of entropy / byte.
 - Entropy accumulation
 - Backtracing resistance
 - Prediction break with frequent (asynchronous) reseed
 */

struct ccrng_state *ccrng(int *error);

//call this macro with the rng argument set to output of the call to the ccrng() function
#define ccrng_generate(rng, outlen, out) ((rng)->generate((rng), (outlen), (out)))

#endif /* _CORECRYPTO_CCRNG_H_ */

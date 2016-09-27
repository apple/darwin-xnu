/*
 *  ccrng_system.h
 *  corecrypto
 *
 *  Created on 12/13/2010
 *
 *  Copyright (c) 2010,2013,2014,2015 Apple Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_CCRNG_SYSTEM_H_
#define _CORECRYPTO_CCRNG_SYSTEM_H_

#include <corecrypto/ccrng.h>

struct ccrng_system_state {
    CCRNG_STATE_COMMON
    int fd;
};

/*!
 @function   ccrng_system_init - DEPRECATED
 @abstract   Default ccrng.
    Please transition to ccrng() which is easier to use and with provide the fastest, most secure option

 @param  rng   Structure containing the state of the RNG, must remain allocated as
 long as the rng is used.
 @result 0 iff successful

 @discussion
        This RNG require call to "init" AND "done", otherwise it may leak a file descriptor.
 */

// Initialize ccrng
// Deprecated, if you need a rng, just call the function ccrng()
int ccrng_system_init(struct ccrng_system_state *rng);

// Close the system RNG
// Mandatory step to avoid leaking file descriptor
void ccrng_system_done(struct ccrng_system_state *rng);

#endif /* _CORECRYPTO_CCRNG_SYSTEM_H_ */

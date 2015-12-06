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

// Setup the system RNG (open descriptor on file /dev/random)
int ccrng_system_init(struct ccrng_system_state *rng);

// Close the system RNG
// Mandatory step to avoid leaking file descriptor
void ccrng_system_done(struct ccrng_system_state *rng);

#endif /* _CORECRYPTO_CCRNG_SYSTEM_H_ */

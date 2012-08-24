/*
 *  ccrng_system.h
 *  corecrypto
 *
 *  Created by Fabrice Gautier on 12/13/10.
 *  Copyright 2010 Apple, Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_CCRNG_SYSTEM_H_
#define _CORECRYPTO_CCRNG_SYSTEM_H_

#include <corecrypto/ccrng.h>

struct ccrng_system_state {
    CCRNG_STATE_COMMON
    int fd;
};

int ccrng_system_init(struct ccrng_system_state *rng);

#endif /* _CORECRYPTO_CCRNG_SYSTEM_H_ */

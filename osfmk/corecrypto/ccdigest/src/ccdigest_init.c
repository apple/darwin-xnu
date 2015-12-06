/*
 *  ccdigest_init.c
 *  corecrypto
 *
 *  Created on 11/30/2010
 *
 *  Copyright (c) 2010,2011,2015 Apple Inc. All rights reserved.
 *
 */

#include <corecrypto/ccdigest.h>
#include <corecrypto/cc_priv.h>

void ccdigest_init(const struct ccdigest_info *di, ccdigest_ctx_t ctx) {
    ccdigest_copy_state(di, ccdigest_state_ccn(di, ctx), di->initial_state);
    ccdigest_nbits(di, ctx) = 0;
    ccdigest_num(di, ctx) = 0;
}

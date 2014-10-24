/*
 *  ccdigest_init.c
 *  corecrypto
 *
 *  Created by Michael Brouwer on 11/30/10.
 *  Copyright 2010,2011 Apple Inc. All rights reserved.
 *
 */

#include <corecrypto/ccdigest.h>
#include <corecrypto/ccn.h>

void ccdigest_init(const struct ccdigest_info *di, ccdigest_ctx_t ctx) {
    ccdigest_copy_state(di, ccdigest_state_ccn(di, ctx), di->initial_state);
    ccdigest_nbits(di, ctx) = 0;
    ccdigest_num(di, ctx) = 0;
}

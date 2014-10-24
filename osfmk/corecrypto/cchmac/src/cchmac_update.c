/*
 *  cchmac_update.c
 *  corecrypto
 *
 *  Created by Michael Brouwer on 12/7/10.
 *  Copyright 2010,2011 Apple Inc. All rights reserved.
 *
 */

#include <corecrypto/cchmac.h>

void cchmac_update(const struct ccdigest_info *di, cchmac_ctx_t hc,
                   unsigned long data_len, const void *data) {
    ccdigest_update(di, cchmac_digest_ctx(di, hc), data_len, data);
}

/*
 *  cchmac_update.c
 *  corecrypto
 *
 *  Created on 12/07/2010
 *
 *  Copyright (c) 2010,2011,2015 Apple Inc. All rights reserved.
 *
 */

#include <corecrypto/cchmac.h>

void cchmac_update(const struct ccdigest_info *di, cchmac_ctx_t hc,
                   size_t data_len, const void *data) {
    ccdigest_update(di, cchmac_digest_ctx(di, hc), data_len, data);
}

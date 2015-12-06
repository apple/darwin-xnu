/*
 *  ccdigest_final_64be.c
 *  corecrypto
 *
 *  Created on 12/06/2010
 *
 *  Copyright (c) 2010,2011,2015 Apple Inc. All rights reserved.
 *
 */

#include <corecrypto/ccdigest_priv.h>
#include <corecrypto/cc_priv.h>

/* This can be used for SHA1, SHA256 and SHA224 */
void ccdigest_final_64be(const struct ccdigest_info *di, ccdigest_ctx_t ctx,
                         unsigned char *digest) {
    ccdigest_nbits(di, ctx) += ccdigest_num(di, ctx) * 8;
    ccdigest_data(di, ctx)[ccdigest_num(di, ctx)++] = 0x80;

    /* If we don't have at least 8 bytes (for the length) left we need to add
     a second block. */
    if (ccdigest_num(di, ctx) > 64 - 8) {
        while (ccdigest_num(di, ctx) < 64) {
            ccdigest_data(di, ctx)[ccdigest_num(di, ctx)++] = 0;
        }
        di->compress(ccdigest_state(di, ctx), 1, ccdigest_data(di, ctx));
        ccdigest_num(di, ctx) = 0;
    }

    /* pad upto block_size minus 8 with 0s */
    while (ccdigest_num(di, ctx) < 64 - 8) {
        ccdigest_data(di, ctx)[ccdigest_num(di, ctx)++] = 0;
    }

    CC_STORE64_BE(ccdigest_nbits(di, ctx), ccdigest_data(di, ctx) + 64 - 8);
    di->compress(ccdigest_state(di, ctx), 1, ccdigest_data(di, ctx));

    /* copy output */
    for (unsigned int i = 0; i < di->output_size / 4; i++) {
        CC_STORE32_BE(ccdigest_state_u32(di, ctx)[i], digest+(4*i));
    }
}

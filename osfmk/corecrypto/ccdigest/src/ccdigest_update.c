/*
 *  ccdigest_update.c
 *  corecrypto
 *
 *  Created by Michael Brouwer on 11/30/10.
 *  Copyright 2010,2011 Apple Inc. All rights reserved.
 *
 */

#include <corecrypto/ccdigest.h>
#include <corecrypto/cc_priv.h>

void ccdigest_update(const struct ccdigest_info *di, ccdigest_ctx_t ctx,
                     unsigned long len, const void *data) {
    char * data_ptr = (char *) data;
    while (len > 0) {
        if (ccdigest_num(di, ctx) == 0 && len > di->block_size) {
            unsigned long nblocks = len / di->block_size;
            di->compress(ccdigest_state(di, ctx), nblocks, data_ptr);
            unsigned long nbytes = nblocks * di->block_size;
            len -= nbytes;
            data_ptr += nbytes;
            ccdigest_nbits(di, ctx) += nbytes * 8;
        } else {
            unsigned long n = di->block_size - ccdigest_num(di, ctx);
            if (len < n)
                n = len;
            CC_MEMCPY(ccdigest_data(di, ctx) + ccdigest_num(di, ctx), data_ptr, n);
            /* typecast: less than block size, will always fit into an int */
            ccdigest_num(di, ctx) += (unsigned int)n;
            len -= n;
            data_ptr += n;
            if (ccdigest_num(di, ctx) == di->block_size) {
                di->compress(ccdigest_state(di, ctx), 1, ccdigest_data(di, ctx));
                ccdigest_nbits(di, ctx) += ccdigest_num(di, ctx) * 8;
                ccdigest_num(di, ctx) = 0;
            }
        }
    }
}

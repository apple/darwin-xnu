/*
 *  ccdigest_update.c
 *  corecrypto
 *
 *  Created on 11/30/2010
 *
 *  Copyright (c) 2010,2011,2014,2015 Apple Inc. All rights reserved.
 *
 */

#include <corecrypto/ccdigest.h>
#include <corecrypto/cc_priv.h>

void ccdigest_update(const struct ccdigest_info *di, ccdigest_ctx_t ctx,
                     size_t len, const void *data) {
    const char * data_ptr = data;
    size_t nblocks, nbytes;

    while (len > 0) {
        if (ccdigest_num(di, ctx) == 0 && len > di->block_size) {
            //low-end processors are slow on divison
            if(di->block_size == 1<<6 ){ //sha256
                nblocks = len >> 6;
                nbytes = len & 0xFFFFffC0;
            }else if(di->block_size == 1<<7 ){ //sha512
                nblocks = len >> 7;
                nbytes = len & 0xFFFFff80;
            }else {
                nblocks = len / di->block_size;
                nbytes = nblocks * di->block_size;
            }

            di->compress(ccdigest_state(di, ctx), nblocks, data_ptr);
            len -= nbytes;
            data_ptr += nbytes;
            ccdigest_nbits(di, ctx) += nbytes * 8;
        } else {
            size_t n = di->block_size - ccdigest_num(di, ctx);
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

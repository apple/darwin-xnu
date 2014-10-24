/*
 *  cchmac_final.c
 *  corecrypto
 *
 *  Created by Michael Brouwer on 12/7/10.
 *  Copyright 2010,2011 Apple Inc. All rights reserved.
 *
 */

#include <corecrypto/cchmac.h>
#include <corecrypto/ccn.h>

void cchmac_final(const struct ccdigest_info *di, cchmac_ctx_t hc,
                  unsigned char *mac) {
    ccdigest_final(di, cchmac_digest_ctx(di, hc), cchmac_data(di, hc));
    /* typecast: output size will alwys fit in an unsigned int */
    cchmac_num(di, hc) = (unsigned int)di->output_size;
    cchmac_nbits(di, hc) = di->block_size * 8;
    ccdigest_copy_state(di, cchmac_istate32(di, hc), cchmac_ostate32(di, hc));
    ccdigest_final(di, cchmac_digest_ctx(di, hc), mac);
}

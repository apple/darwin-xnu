/*
 *  cchmac_final.c
 *  corecrypto
 *
 *  Created on 12/07/2010
 *
 *  Copyright (c) 2010,2011,2015 Apple Inc. All rights reserved.
 *
 */

#include <corecrypto/cchmac.h>
#include <corecrypto/ccn.h>
#include <corecrypto/cc_priv.h>

void cchmac_final(const struct ccdigest_info *di, cchmac_ctx_t hc,
                  unsigned char *mac) {
    ccdigest_final(di, cchmac_digest_ctx(di, hc), cchmac_data(di, hc));
    /* typecast: output size will alwys fit in an unsigned int */
    cchmac_num(di, hc) = (unsigned int)di->output_size;
    cchmac_nbits(di, hc) = di->block_size * 8;
    ccdigest_copy_state(di, cchmac_istate32(di, hc), cchmac_ostate32(di, hc));
    ccdigest_final(di, cchmac_digest_ctx(di, hc), mac);
}

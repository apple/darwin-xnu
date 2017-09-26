/*
 *  ccdigest_final_64be.c
 *  corecrypto
 *
 *  Created on 12/06/2010
 *
 *  Copyright (c) 2010,2011,2015 Apple Inc. All rights reserved.
 *
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
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

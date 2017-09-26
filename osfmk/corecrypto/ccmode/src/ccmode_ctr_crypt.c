/*
 *  ccmode_ctr_crypt.c
 *  corecrypto
 *
 *  Created on 12/17/2010
 *
 *  Copyright (c) 2010,2011,2012,2014,2015 Apple Inc. All rights reserved.
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

#include "ccmode_internal.h"

int ccmode_ctr_crypt(ccctr_ctx *key,
                     size_t nbytes, const void *in, void *out) {
    const struct ccmode_ecb *ecb = CCMODE_CTR_KEY_ECB(key);
    const ccecb_ctx *ecb_key = CCMODE_CTR_KEY_ECB_KEY(key);
    uint8_t *ctr = (uint8_t *)CCMODE_CTR_KEY_CTR(key);
    uint8_t *pad = (uint8_t *)CCMODE_CTR_KEY_PAD(key);
    size_t pad_offset = CCMODE_CTR_KEY_PAD_OFFSET(key);
    const uint8_t *in_bytes = in;
    // Counter is 64bit wide for cipher with block size of 64bit or more
    // This is to match the assembly
    const size_t counter_size=(CC_MIN(ecb->block_size,(typeof(ecb->block_size))8));
    uint8_t *out_bytes = out;
    size_t n;

    while (nbytes) {
        if (pad_offset == ecb->block_size) {
            ecb->ecb(ecb_key, 1, ctr, pad);
            pad_offset = 0;

            /* increment the big endian counter */
            inc_uint(ctr + ecb->block_size - counter_size, counter_size);

            if (nbytes==0) break;
        }
        
        n = CC_MIN(nbytes, ecb->block_size - pad_offset);
        cc_xor(n, out_bytes, in_bytes, pad + pad_offset);
        nbytes -= n;
        in_bytes += n;
        out_bytes += n;
        pad_offset += n;
    }
    CCMODE_CTR_KEY_PAD_OFFSET(key) = pad_offset;
    
    return 0;
}

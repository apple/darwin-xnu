/*
 *  cchmac_final.c
 *  corecrypto
 *
 *  Created on 12/07/2010
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

#include <corecrypto/cchmac.h>
#include <corecrypto/ccn.h>
#include <corecrypto/cc_priv.h>

void cchmac_final(const struct ccdigest_info *di, cchmac_ctx_t hc,
                  unsigned char *mac) {

    // Finalize the inner state of the data being HMAC'd, i.e., H((key \oplus ipad) || m)
    ccdigest_final(di, cchmac_digest_ctx(di, hc), cchmac_data(di, hc));

    // Set the HMAC output size based on the digest algorithm
    cchmac_num(di, hc) = (unsigned int)di->output_size; /* typecast: output size will alwys fit in an unsigned int */
    cchmac_nbits(di, hc) = di->block_size * 8;

    // Copy the pre-computed compress(key \oplus opad) back to digest state,
    // and then run through the digest once more to finish the HMAC
    ccdigest_copy_state(di, cchmac_istate32(di, hc), cchmac_ostate32(di, hc));
    ccdigest_final(di, cchmac_digest_ctx(di, hc), mac);
}

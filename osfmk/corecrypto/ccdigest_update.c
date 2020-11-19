/*
 *  ccdigest_update.c
 *  corecrypto
 *
 *  Created on 11/30/2010
 *
 *  Copyright (c) 2010,2011,2014,2015 Apple Inc. All rights reserved.
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

#include <corecrypto/ccdigest.h>
#include <corecrypto/cc_priv.h>

void
ccdigest_update(const struct ccdigest_info *di, ccdigest_ctx_t ctx, size_t len, const void *data)
{
	const char * data_ptr = data;
	size_t nblocks, nbytes;

	// Sanity check to recover from ctx corruptions.
	if (ccdigest_num(di, ctx) >= di->block_size) {
		ccdigest_num(di, ctx) = 0;
	}

	while (len > 0) {
		if (ccdigest_num(di, ctx) == 0 && len > di->block_size) {
			if (di->block_size == 1 << 6) { // md5 & sha1 & sha256
				nblocks = len >> 6;
				nbytes = nblocks << 6;
			} else if (di->block_size == 1 << 7) { // sha384 & sha512
				nblocks = len >> 7;
				nbytes = nblocks << 7;
			} else {
				nblocks = len / di->block_size;
				nbytes = nblocks * di->block_size;
			}

			di->compress(ccdigest_state(di, ctx), nblocks, data_ptr);
			len -= nbytes;
			data_ptr += nbytes;
			ccdigest_nbits(di, ctx) += (uint64_t) (nbytes) * 8;
		} else {
			size_t n = CC_MIN(di->block_size - ccdigest_num(di, ctx), len);
			cc_memcpy(ccdigest_data(di, ctx) + ccdigest_num(di, ctx), data_ptr, n);
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

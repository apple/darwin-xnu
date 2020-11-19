/*
 *  ccdigest_init.c
 *  corecrypto
 *
 *  Created on 11/30/2010
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
#include <corecrypto/ccmd4.h>

#if 0
#if CC_LOGGING_AVAILABLE
#if CC_FEATURE_FLAGS_AVAILABLE

#include "cclog_internal.h"
#include <os/feature_private.h>

static void
log_trace(const struct ccdigest_info *di)
{
	if (!CC_FEATURE_ENABLED(ccdigest_logging)) {
		return;
	}

	if (ccdigest_oid_equal(di, CC_DIGEST_OID_MD2)) {
		cclog_error_backtrace(CCLOG_CATEGORY_DEFAULT, "trace: md2");
	} else if (ccdigest_oid_equal(di, CC_DIGEST_OID_MD4)) {
		cclog_error_backtrace(CCLOG_CATEGORY_DEFAULT, "trace: md4");
	} else if (ccdigest_oid_equal(di, CC_DIGEST_OID_MD5)) {
		cclog_error_backtrace(CCLOG_CATEGORY_ALGORITHM_MD5, "trace: md5");
	} else if (ccdigest_oid_equal(di, CC_DIGEST_OID_SHA1)) {
		cclog_error_backtrace(CCLOG_CATEGORY_ALGORITHM_SHA1, "trace: sha1");
	} else if (ccdigest_oid_equal(di, CC_DIGEST_OID_RMD160)) {
		cclog_error_backtrace(CCLOG_CATEGORY_DEFAULT, "trace: rmd160");
	}
}

#endif // CC_FEATURE_FLAGS_AVAILABLE
#endif // CC_LOGGING_AVAILABLE
#endif

void
ccdigest_init(const struct ccdigest_info *di, ccdigest_ctx_t ctx)
{
#if 0
#if CC_LOGGING_AVAILABLE
#if CC_FEATURE_FLAGS_AVAILABLE
	log_trace(di);
#endif // CC_FEATURE_FLAGS_AVAILABLE
#endif // CC_LOGGING_AVAILABLE
#endif

	ccdigest_copy_state(di, ccdigest_state_ccn(di, ctx), di->initial_state);
	ccdigest_nbits(di, ctx) = 0;
	ccdigest_num(di, ctx) = 0;
}

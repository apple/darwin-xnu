/*
 *  ccsha1_internal.h
 *  corecrypto
 *
 *  Created on 12/19/2017
 *
 *  Copyright (c) 2017 Apple Inc. All rights reserved.
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

#ifndef _CORECRYPTO_CCSHA1_INTERNAL_H_
#define _CORECRYPTO_CCSHA1_INTERNAL_H_

#include <corecrypto/ccdigest.h>
#include <corecrypto/cc_config.h>

extern const uint32_t ccsha1_initial_state[5];

#if CCSHA1_VNG_INTEL && defined(__x86_64__)
extern const struct ccdigest_info ccsha1_vng_intel_AVX2_di;
extern const struct ccdigest_info ccsha1_vng_intel_AVX1_di;
#endif

#endif /* _CORECRYPTO_CCSHA1_INTERNAL_H_ */

/*
 *  ccsha256_di.c
 *  corecrypto
 *
 *  Created on 09/18/2012
 *
 *  Copyright (c) 2012,2014,2015 Apple Inc. All rights reserved.
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

#include <corecrypto/ccsha2.h>
#include "ccsha2_internal.h"
#include <corecrypto/cc_runtime_config.h>

#include "corecrypto/fipspost_trace.h"

const struct ccdigest_info *
ccsha256_di(void)
{
	FIPSPOST_TRACE_EVENT;

#if  CCSHA2_VNG_INTEL
#if defined (__x86_64__)
	if (CC_HAS_AVX512_AND_IN_KERNEL()) {
		return &ccsha256_vng_intel_SupplementalSSE3_di;
	} else
#if CC_ACCELERATECRYPTO
	{ return &ccsha256_vng_intel_di; // use AccelerateCrypto
	}
#else
	{ return CC_HAS_AVX2() ? &ccsha256_vng_intel_AVX2_di :
		 ((CC_HAS_AVX1() ? &ccsha256_vng_intel_AVX1_di :
		 &ccsha256_vng_intel_SupplementalSSE3_di)); }
#endif
#else
	return &ccsha256_vng_intel_SupplementalSSE3_di;
#endif
#elif  CCSHA2_VNG_ARM
	return &ccsha256_vng_arm_di;
#elif CCSHA256_ARMV6M_ASM
	return &ccsha256_v6m_di;
#else
	return &ccsha256_ltc_di;
#endif
}

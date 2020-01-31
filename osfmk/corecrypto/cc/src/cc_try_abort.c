/*
 *  cc_try_abort.c
 *  corecrypto
 *
 *  Created on 7/16/2015
 *
 *  Copyright (c) 2014,2015 Apple Inc. All rights reserved.
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

#include <corecrypto/cc_priv.h>

//cc_try_abort() is implemented to comply with by FIPS 140-2, when DRBG produces
//two equal consecutive blocks. See radar 19129408

#if CC_KERNEL
#include <kern/debug.h>
void
cc_try_abort(const char * msg CC_UNUSED, ...)
{
	panic("%s", msg);
}

#elif CC_USE_SEPROM || CC_USE_S3 || CC_BASEBAND || CC_EFI || CC_IBOOT || CC_RTKIT || CC_RTKITROM
void
cc_try_abort(const char * msg CC_UNUSED, ...)
{
	//Do nothing and return because we don't have panic() in those
	//environments. Make sure you return error, when using cc_try_abort() in above environments
}

#else
#include <stdlib.h>
void
cc_try_abort(const char * msg CC_UNUSED, ...)
{
	abort();
}
#endif

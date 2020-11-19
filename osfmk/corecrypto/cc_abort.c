/*
 *  cc_abort.c
 *  corecrypto
 *
 *  Created on 3/9/2019
 *
 *  Copyright (c) 2019 Apple Inc. All rights reserved.
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

//cc_abort() is implemented to comply with by FIPS 140-2, when DRBG produces
//two equal consecutive blocks.

#if !CC_PROVIDES_ABORT

#error "This environment does not provide an abort()/panic()-like function"

#elif CC_KERNEL

#include <kern/debug.h>
void
cc_abort(const char * msg)
{
	panic("%s", msg);
}

#elif CC_USE_L4

#include <sys/panic.h>
#include <stdarg.h>
void
cc_abort(const char * msg)
{
	sys_panic(msg);
}

#elif CC_RTKIT

#include <RTK_platform.h>
void
cc_abort(const char * msg)
{
	RTK_abort("%s", msg);
}

#else

#include <stdlib.h>
void
cc_abort(const char * msg CC_UNUSED)
{
	abort();
}

#endif

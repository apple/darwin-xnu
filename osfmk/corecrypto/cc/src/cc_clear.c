/*
 *  cc_clear.c
 *  corecrypto
 *
 *  Created on 05/21/2014
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

#include <corecrypto/cc.h>
#include "corecrypto/fipspost_trace.h"

//rdar://problem/26986552

#if (CC_HAS_MEMSET_S == 1) && (defined(__STDC_WANT_LIB_EXT1__) && (__STDC_WANT_LIB_EXT1__ == 1))
void
cc_clear(size_t len, void *dst)
{
	FIPSPOST_TRACE_EVENT;
	memset_s(dst, len, 0, len);
}
#elif defined(_WIN32) && !defined(__clang__) //Clang with Microsoft CodeGen, doesn't support SecureZeroMemory
#include <windows.h>
static void
cc_clear(size_t len, void *dst)
{
	SecureZeroMemory(dst, len);
}
#else
void
cc_clear(size_t len, void *dst)
{
	FIPSPOST_TRACE_EVENT;
	volatile char *vptr = (volatile char *)dst;
	while (len--) {
		*vptr++ = '\0';
	}
}
#endif

/* This is an altarnative for clang that should work
 *  void cc_clear(size_t len, void *dst) __attribute__ ((optnone))
 *  {
 *  cc_zero(len,dst);
 *  }
 */

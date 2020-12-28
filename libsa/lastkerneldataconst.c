/*
 * Copyright (c) 2014 Apple Inc. All rights reserved.
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

#include <mach/vm_param.h>

/*
 * This file is compiled and linked to be the last .o of the __const section
 * of the __DATA segment (see MakeInc.kernel, lastkernelconstructor is placed
 * in the __LAST segment.)
 *
 * This blank page allows us to safely map the const section RO while the rest
 * of __DATA is RW. This is needed since ld has no way of specifying section size
 * alignment and no straight forward way to specify section ordering.
 */

#if defined(__arm64__)
/* PAGE_SIZE on ARM64 is an expression derived from a non-const global variable */
#define PAD_SIZE        PAGE_MAX_SIZE
#else
#define PAD_SIZE        PAGE_SIZE
#endif

static const uint8_t __attribute__((section("__DATA,__const"))) data_const_padding[PAD_SIZE] = {[0 ... PAD_SIZE - 1] = 0xFF};
const vm_offset_t    __attribute__((section("__DATA,__data")))  _lastkerneldataconst         = (vm_offset_t)&data_const_padding[0];
const vm_size_t      __attribute__((section("__DATA,__data")))  _lastkerneldataconst_padsize = sizeof(data_const_padding);

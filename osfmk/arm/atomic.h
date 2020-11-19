/*
 * Copyright (c) 2015-2018 Apple Inc. All rights reserved.
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

#ifndef _MACHINE_ATOMIC_H
#error "Do not include <arm/atomic.h> directly, use <machine/atomic.h>"
#endif

#ifndef _ARM_ATOMIC_H_
#define _ARM_ATOMIC_H_

#include <mach/boolean.h>

// Parameter for __builtin_arm_dmb
#define DMB_OSHLD       0x1
#define DMB_OSHST       0x2
#define DMB_OSH         0x3
#define DMB_NSHLD       0x5
#define DMB_NSHST       0x6
#define DMB_NSH         0x7
#define DMB_ISHLD       0x9
#define DMB_ISHST       0xa
#define DMB_ISH         0xb
#define DMB_LD          0xd
#define DMB_ST          0xe
#define DMB_SY          0xf

// Parameter for __builtin_arm_dsb
#define DSB_OSHLD       0x1
#define DSB_OSHST       0x2
#define DSB_OSH         0x3
#define DSB_NSHLD       0x5
#define DSB_NSHST       0x6
#define DSB_NSH         0x7
#define DSB_ISHLD       0x9
#define DSB_ISHST       0xa
#define DSB_ISH         0xb
#define DSB_LD          0xd
#define DSB_ST          0xe
#define DSB_SY          0xf

// Parameter for __builtin_arm_isb
#define ISB_SY          0xf

#endif // _ARM_ATOMIC_H_

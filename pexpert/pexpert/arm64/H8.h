/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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

#ifndef _PEXPERT_ARM64_H8_H
#define _PEXPERT_ARM64_H8_H

#define APPLETWISTER
#define MONITOR                 1 /* Use EL3 monitor */
#define NO_ECORE                1
#define HAS_32BIT_DBGWRAP       1
#define HAS_CPMU_L2C_EVENTS     1 /* Has L2 cache events in CPMU */

#define CORE_NCTRS                           8
#define CPMU_AIC_PMI                         1

#define __ARM_16K_PG__                       1
#define __ARM_KERNEL_PROTECT__               1

#include <pexpert/arm64/apple_arm64_common.h>

#endif /* !_PEXPERT_ARM64_H8_H */

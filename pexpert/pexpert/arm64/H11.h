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

#ifndef _PEXPERT_ARM64_H11_H
#define _PEXPERT_ARM64_H11_H

#define APPLEVORTEX
#define NO_MONITOR              1 /* No EL3 for this CPU -- ever */
#define HAS_CTRR                1 /* Has CTRR registers */
#define HAS_NEX_PG              1 /* Supports p-Core NEX powergating during Neon inactivity */
#define HAS_BP_RET              1 /* Supports branch predictor state retention across ACC sleep */
#define HAS_CONTINUOUS_HWCLOCK  1 /* Has a hardware clock that ticks during sleep */
#define HAS_IPI                 1 /* Has IPI registers */
#define HAS_CLUSTER             1 /* Has eCores and pCores in separate clusters */
#define HAS_RETENTION_STATE     1 /* Supports architectural state retention */
#define HAS_VMSA_LOCK           1 /* Supports lockable MMU config registers */

#define CPU_HAS_APPLE_PAC                    1
#define HAS_UNCORE_CTRS                      1
#define UNCORE_VERSION                       2
#define UNCORE_PER_CLUSTER                   1
#define UNCORE_NCTRS                         16
#define CORE_NCTRS                           10

#define __ARM_AMP__                          1
#define __ARM_16K_PG__                       1
#define __ARM_GLOBAL_SLEEP_BIT__             1
#define __ARM_PAN_AVAILABLE__                1
#define __ARM_WKDM_ISA_AVAILABLE__           1
#define __PLATFORM_WKDM_ALIGNMENT_MASK__     (0x3FULL)
#define __PLATFORM_WKDM_ALIGNMENT_BOUNDARY__ (64)


#include <pexpert/arm64/apple_arm64_common.h>

#endif /* !_PEXPERT_ARM64_H11_H */

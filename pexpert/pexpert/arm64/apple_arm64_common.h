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

#ifndef _PEXPERT_ARM64_APPLE_ARM64_COMMON_H
#define _PEXPERT_ARM64_APPLE_ARM64_COMMON_H

#define __ARM_ARCH__                         8
#define __ARM_VMSA__                         8
#define __ARM_VFP__                          4
#define __ARM_COHERENT_CACHE__               1
#define __ARM_COHERENT_IO__                  1
#define __ARM_IC_NOALIAS_ICACHE__            1
#define __ARM_DEBUG__                        7
#define __ARM_ENABLE_SWAP__                  1
#define __ARM_V8_CRYPTO_EXTENSIONS__         1

#ifndef ARM_LARGE_MEMORY
#define __ARM64_PMAP_SUBPAGE_L1__            1
#endif

#define APPLE_ARM64_ARCH_FAMILY              1
#define ARM_ARCH_TIMER
#define ARM_BOARD_WFE_TIMEOUT_NS             1000

#if defined(HAS_CTRR)
#define KERNEL_INTEGRITY_CTRR                1
#elif defined(HAS_KTRR)
#define KERNEL_INTEGRITY_KTRR                1
#elif defined(MONITOR)
#define KERNEL_INTEGRITY_WT                  1
#endif


#include <pexpert/arm64/apple_arm64_regs.h>
#include <pexpert/arm64/AIC.h>

#ifndef ASSEMBLER
#include <pexpert/arm/S3cUART.h>

#if !defined(APPLETYPHOON) && !defined(APPLETWISTER)
#include <pexpert/arm/dockchannel.h>

// AOP_CLOCK frequency * 30 ms
#define DOCKCHANNEL_DRAIN_PERIOD             (192000000 * 0.03)
#endif

#endif /* ASSEMBLER */

/*
 * See arm64/proc_reg.h for how these values are constructed from the MIDR.
 * The chip-revision property from EDT also uses these constants.
 */
#define CPU_VERSION_A0                       0x00
#define CPU_VERSION_A1                       0x01
#define CPU_VERSION_B0                       0x10
#define CPU_VERSION_B1                       0x11
#define CPU_VERSION_C0                       0x20
#define CPU_VERSION_UNKNOWN                  0xff

#endif /* !_PEXPERT_ARM64_APPLE_ARM64_COMMON_H */

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

#ifndef _PEXPERT_ARM64_VMAPPLE_H
#define _PEXPERT_ARM64_VMAPPLE_H

#define NO_MONITOR                1
#define NO_ECORE                  1

#define VMAPPLE                   1
#define APPLEVIRTUALPLATFORM      1

#define CPU_HAS_APPLE_PAC         1
#define HAS_PARAVIRTUALIZED_PAC   1
#define 1
#define HAS_GIC_V3                1

#define __ARM_PAN_AVAILABLE__     1
#define __ARM_16K_PG__            1

#define ARM_PARAMETERIZED_PMAP    1
#define __ARM_MIXED_PAGE_SIZE__   1

#include <pexpert/arm64/apple_arm64_common.h>
#undef  __ARM64_PMAP_SUBPAGE_L1__

#ifndef ASSEMBLER
#define VMAPPLE_UART
#define PLATFORM_PANIC_LOG_DISABLED
#endif /* ! ASSEMBLER */

#ifdef ASSEMBLER
#define ASPSR_EL1                 S3_6_c15_c8_3
#define AFPCR_EL0                 S3_6_c15_c2_5
#else
#define ASPSR_EL1                 "S3_6_c15_c8_3"
#define AFPCR_EL0                 "S3_6_c15_c2_5"
#endif /* ASSEMBLER */

#define GIC_SPURIOUS_IRQ          1023    // IRQ no. for GIC spurious interrupt

#define GICR_PE_SIZE              0x20000 // Size of each redistributor region


/* GICv3 reigster definitions; see GICv3 spec (Arm IHI 0069G) for more about these registers */
#define GICD_CTLR                 0x0

#define GICD_CTLR_ENABLEGRP0      0x1

#define GICR_TYPER                              0x08
#define GICR_WAKER                              0x14
#define GICR_IGROUPR0                           0x10080
#define GICR_ISENABLER0                         0x10100

#define GICR_TYPER_AFFINITY_VALUE_SHIFT         32
#define GICR_TYPER_LAST                         0x10

#define GICR_WAKER_PROCESSORSLEEP               0x2
#define GICR_WAKER_CHILDRENASLEEP               0x4

#define ICC_CTLR_EOIMODE                        0x1

#define ICC_SRE_SRE                             0x1
/* End of GICv3 register definitions */

#define VMAPPLE_HVC_NAMESPACE                   0xC1000000
#define VMAPPLE_PAC_SET_INITIAL_STATE           (VMAPPLE_HVC_NAMESPACE | 0x0)
#define VMAPPLE_PAC_GET_DEFAULT_KEYS            (VMAPPLE_HVC_NAMESPACE | 0x1)
#define VMAPPLE_PAC_SET_A_KEYS                  (VMAPPLE_HVC_NAMESPACE | 0x2)
#define VMAPPLE_PAC_SET_B_KEYS                  (VMAPPLE_HVC_NAMESPACE | 0x3)
#define VMAPPLE_PAC_SET_EL0_DIVERSIFIER         (VMAPPLE_HVC_NAMESPACE | 0x4)
#define VMAPPLE_PAC_SET_EL0_DIVERSIFIER_AT_EL1  (VMAPPLE_HVC_NAMESPACE | 0x5)

#endif /* ! _PEXPERT_ARM64_VMAPPLE_H */

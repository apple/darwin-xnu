/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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
#ifndef ARM64_MONOTONIC_H
#define ARM64_MONOTONIC_H

#include <pexpert/arm64/board_config.h>

#if KERNEL_PRIVATE

#include <stdint.h>

#define MT_NDEVS 1

#define MT_CORE_CYCLES 0
#define MT_CORE_INSTRS 1
#define MT_CORE_NFIXED 2
#define MT_CORE_MAXVAL ((UINT64_C(1) << 48) - 1)

#endif /* KERNEL_PRIVATE */

#if MACH_KERNEL_PRIVATE

#include <stdbool.h>

#define PMSR "s3_1_c15_c13_0"
#define PMSR_PMI(REG) ((REG) & ((1 << CORE_NCTRS) - 1))


static inline bool
mt_pmi_pending(uint64_t * restrict pmsr, uint64_t * restrict upmsr)
{
	*pmsr = __builtin_arm_rsr64(PMSR);
	bool pmi = PMSR_PMI(*pmsr);

#pragma unused(upmsr)

	return pmi;
}

void mt_fiq(void *cpu, uint64_t pmsr, uint64_t upmsr);

#endif /* MACH_KERNEL_PRIVATE */

#endif /* !defined(ARM64_MONOTONIC_H) */

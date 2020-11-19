/*
 * Copyright (c) 2018 Apple Inc. All rights reserved.
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
#ifndef _PEXPERT_ARM64_SPR_LOCKS_H
#define _PEXPERT_ARM64_SPR_LOCKS_H

#define MSR_RO_CTL_HID1                 (1ULL << 1)
#define MSR_RO_CTL_HID4                 (1ULL << 4)
#define MSR_RO_CTL_CYC_OVRD             (1ULL << 27)
#define MSR_RO_CTL_ACC_OVRD             (1ULL << 47)

#define MSR_RO_CTL_VAL                  (~0ULL & ~(MSR_RO_CTL_HID4 | MSR_RO_CTL_CYC_OVRD | MSR_RO_CTL_ACC_OVRD))
#define MSR_LOCK_VAL                    (1ULL << 0)

#define CPU_PIO_RO_CTL_DBG_WRAP         (1ULL << 49)
#define CPU_PIO_RO_CTL_TRACE_CORE_CFG   (1ULL << 54)

#define CPU_PIO_RO_CTL_VAL              (~0ULL & ~(CPU_PIO_RO_CTL_DBG_WRAP | CPU_PIO_RO_CTL_TRACE_CORE_CFG))
#define CPU_PIO_LOCK_VAL                (1ULL << 0)

#define ACC_PIO_RO_CTL_PBLK_OVRD        (1ULL << 47)
#define ACC_PIO_RO_CTL_DBG_CTL          (1ULL << 48)
#define ACC_PIO_RO_CTL_DBG_PMGR         (1ULL << 50)
#define ACC_PIO_RO_CTL_DBG_WRAP_GLB     (1ULL << 51)
#define ACC_PIO_RO_CTL_TRACE_CTL        (1ULL << 53)
#define ACC_PIO_RO_CTL_TRC_UT_CTL       (1ULL << 55)
#define ACC_PIO_RO_CTL_OCLA_CTL         (1ULL << 56)

#define ACC_PIO_RO_CTL_VAL              (~0ULL & ~(ACC_PIO_RO_CTL_PBLK_OVRD | ACC_PIO_RO_CTL_DBG_CTL | ACC_PIO_RO_CTL_DBG_PMGR |        \
	                                           ACC_PIO_RO_CTL_DBG_WRAP_GLB | ACC_PIO_RO_CTL_TRACE_CTL |                             \
	                                           ACC_PIO_RO_CTL_TRC_UT_CTL | ACC_PIO_RO_CTL_OCLA_CTL))
#define ACC_PIO_LOCK_VAL                (1ULL << 0)

#endif /* _PEXPERT_ARM64_SPR_LOCKS_H */

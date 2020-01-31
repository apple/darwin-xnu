/*
 * Copyright (c) 2007-2017 Apple Inc. All rights reserved.
 * Copyright (c) 2005-2006 Apple Computer, Inc. All rights reserved.
 */
#ifndef _PEXPERT_ARM_BOARD_CONFIG_H
#define _PEXPERT_ARM_BOARD_CONFIG_H

#include <mach/machine.h>

#ifdef ARM64_BOARD_CONFIG_S5L8960X
#define APPLE_ARM64_ARCH_FAMILY  1
#define APPLECYCLONE
#define ARM_ARCH_TIMER
#include <pexpert/arm64/S5L8960X.h>
#define __ARM_L2CACHE_SIZE_LOG__ 20
#define ARM_BOARD_WFE_TIMEOUT_NS 1000
#define ARM_BOARD_CLASS_S5L8960X
#define KERNEL_INTEGRITY_WT 1
#define PEXPERT_NO_3X_IMAGES    1
#define CORE_NCTRS 8
#define CPMU_AIC_PMI 1
#endif  /* ARM64_BOARD_CONFIG_S5L8960X */

#ifdef ARM64_BOARD_CONFIG_T7000
#define APPLE_ARM64_ARCH_FAMILY  1
#define APPLETYPHOON
#define ARM_ARCH_TIMER
#include <pexpert/arm64/T7000.h>
#define __ARM_L2CACHE_SIZE_LOG__ 20
#define ARM_BOARD_WFE_TIMEOUT_NS 1000
#define ARM_BOARD_CLASS_T7000
#define KERNEL_INTEGRITY_WT 1
#define CORE_NCTRS 8
#define CPMU_AIC_PMI 1
#endif  /* ARM64_BOARD_CONFIG_T7000 */

#ifdef ARM64_BOARD_CONFIG_T7001
#define APPLE_ARM64_ARCH_FAMILY  1
#define APPLETYPHOON
#define ARM_ARCH_TIMER
#include <pexpert/arm64/T7000.h>
#define __ARM_L2CACHE_SIZE_LOG__ 21
#define ARM_BOARD_WFE_TIMEOUT_NS 1000
#define ARM_BOARD_CLASS_T7000
#define KERNEL_INTEGRITY_WT 1
#define CPU_COUNT 3
#define CORE_NCTRS 8
#define CPMU_AIC_PMI 1
#endif  /* ARM64_BOARD_CONFIG_T7001 */

#ifdef ARM64_BOARD_CONFIG_S8000
/*
 * The L2 size for twister is in fact 3MB, not 4MB; we round up due
 * to the code being architected for power of 2 cache sizes, and rely
 * on the expected behavior that out of bounds operations will be
 * ignored.
 */
#define APPLE_ARM64_ARCH_FAMILY  1
#define APPLETWISTER
#define ARM_ARCH_TIMER
#include <pexpert/arm64/S8000.h>
#define __ARM_L2CACHE_SIZE_LOG__ 22
#define ARM_BOARD_WFE_TIMEOUT_NS 1000
#define ARM_BOARD_CLASS_S8000
#define KERNEL_INTEGRITY_WT 1
#define CORE_NCTRS 8
#define CPMU_AIC_PMI 1
#endif  /* ARM64_BOARD_CONFIG_S8000 */

#ifdef ARM64_BOARD_CONFIG_S8001
/*
 * The L2 size for twister is in fact 3MB, not 4MB; we round up due
 * to the code being architected for power of 2 cache sizes, and rely
 * on the expect behavior that out of bounds operations will be
 * ignored.
 */
#define APPLE_ARM64_ARCH_FAMILY  1
#define APPLETWISTER
#define ARM_ARCH_TIMER
#include <pexpert/arm64/S8000.h>
#define __ARM_L2CACHE_SIZE_LOG__ 22
#define ARM_BOARD_WFE_TIMEOUT_NS 1000
#define ARM_BOARD_CLASS_S8000
#define KERNEL_INTEGRITY_WT 1
#define CORE_NCTRS 8
#define CPMU_AIC_PMI 1
#endif  /* ARM64_BOARD_CONFIG_S8001 */

#ifdef ARM64_BOARD_CONFIG_T8010
/*
 * The L2 size for hurricane/zephyr is in fact 3MB, not 4MB; we round up due
 * to the code being architected for power of 2 cache sizes, and rely
 * on the expect behavior that out of bounds operations will be
 * ignored.
 */
#define APPLE_ARM64_ARCH_FAMILY  1
#define APPLEHURRICANE
#define ARM_ARCH_TIMER
#define KERNEL_INTEGRITY_KTRR
#include <pexpert/arm64/T8010.h>
#define __ARM_L2CACHE_SIZE_LOG__ 22
#define ARM_BOARD_WFE_TIMEOUT_NS 1000
#define ARM_BOARD_CLASS_T8010
#define CORE_NCTRS 10
#define CPMU_AIC_PMI 1
#if DEVELOPMENT || DEBUG
#define PMAP_CS                  1
#define PMAP_CS_ENABLE           0
#endif
#endif  /* ARM64_BOARD_CONFIG_T8010 */

#ifdef ARM64_BOARD_CONFIG_T8011
#define APPLE_ARM64_ARCH_FAMILY  1
#define APPLEHURRICANE
#define ARM_ARCH_TIMER
#define KERNEL_INTEGRITY_KTRR
#include <pexpert/arm64/T8010.h>
#define __ARM_L2CACHE_SIZE_LOG__ 23
#define ARM_BOARD_WFE_TIMEOUT_NS 1000
#define ARM_BOARD_CLASS_T8011
#define CPU_COUNT 3
#define CORE_NCTRS 10
#define CPMU_AIC_PMI 1
#if DEVELOPMENT || DEBUG
#define PMAP_CS                  1
#define PMAP_CS_ENABLE           0
#endif
#endif  /* ARM64_BOARD_CONFIG_T8011 */

#ifdef ARM64_BOARD_CONFIG_T8015
/*
 * The LLC size for monsoon is 8MB, but the L2E exposed to mistral is
 * only 1MB.  We use the larger cache size here.  The expectation is
 * that this may cause flushes from mistral to be less efficient
 * (cycles will be wasted on unnecessary way/set operations), but it
 * will be technically correct... the best kind of correct.
 *
 * And is an explicit flush from L2E to LLC something we'll ever want
 * to do?
 */
#define APPLE_ARM64_ARCH_FAMILY  1
#define APPLEMONSOON
#define ARM_ARCH_TIMER
#define KERNEL_INTEGRITY_KTRR
#include <pexpert/arm64/T8015.h>
#define __ARM_L2CACHE_SIZE_LOG__ 23
#define ARM_BOARD_WFE_TIMEOUT_NS 1000
#define ARM_BOARD_CLASS_T8015
#define CPU_COUNT 6
#define BROKEN_FRIGGING_SLEEP 1 /* Spurious wake: See rdar://problem/29762505 */
#define HAS_UNCORE_CTRS 1
#define UNCORE_VERSION 1
#define UNCORE_PER_CLUSTER 0
#define UNCORE_NCTRS 8
#define CORE_NCTRS 10
#if DEVELOPMENT || DEBUG
#define PMAP_CS                  1
#define PMAP_CS_ENABLE           0
#endif
#endif  /* ARM64_BOARD_CONFIG_T8015 */






#ifdef ARM64_BOARD_CONFIG_BCM2837
#define BCM2837
#define BCM2837_BRINGUP
#define ARM_ARCH_TIMER
#include <pexpert/arm64/BCM2837.h>
#define __ARM_L2CACHE_SIZE_LOG__ 19
#define ARM_BOARD_CLASS_BCM2837
#define CPU_COUNT 4
#endif  /* ARM64_BOARD_CONFIG_BCM2837 */

#endif /* ! _PEXPERT_ARM_BOARD_CONFIG_H */

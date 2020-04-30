/*
 * Copyright (c) 2007-2019 Apple Inc. All rights reserved.
 * Copyright (c) 2005-2006 Apple Computer, Inc. All rights reserved.
 */
#ifndef _PEXPERT_ARM_BOARD_CONFIG_H
#define _PEXPERT_ARM_BOARD_CONFIG_H

#include <mach/machine.h>


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

#ifdef ARM64_BOARD_CONFIG_T8020
/*
 * The LLC size for Vortex is 8MB, but the LLC on Tempest is only 2MB.
 * We use the larger cache size here.  The expectation is
 * that this may cause flushes from Tempest to be less efficient
 * (cycles will be wasted on unnecessary way/set operations), but it
 * will be technically correct... the best kind of correct.
 */
#define APPLE_ARM64_ARCH_FAMILY  1
#define APPLEVORTEX
#define ARM_ARCH_TIMER
#define KERNEL_INTEGRITY_CTRR
#include <pexpert/arm64/T8020.h>
#define __ARM_L2CACHE_SIZE_LOG__ 23
#define ARM_BOARD_WFE_TIMEOUT_NS 1000
#define ARM_BOARD_CLASS_T8020
#define CPU_COUNT 6
#define CPU_CLUSTER_OFFSETS {0, 4}
#define HAS_UNCORE_CTRS 1
#define UNCORE_VERSION 2
#define UNCORE_PER_CLUSTER 1
#define UNCORE_NCTRS 16
#define CORE_NCTRS 10
#define PMAP_PV_LOAD_FACTOR 5
#define PMAP_CS             1
#define PMAP_CS_ENABLE      1
#endif  /* ARM64_BOARD_CONFIG_T8020 */

#ifdef ARM64_BOARD_CONFIG_T8006
/*
 * The T8006 consists of 2 Tempest cores (i.e. T8020 eCores) and for most
 * of our purposes here may be considered a functional subset of T8020.
 */
#define APPLE_ARM64_ARCH_FAMILY  1
#define APPLEVORTEX
#define ARM_ARCH_TIMER
#define KERNEL_INTEGRITY_CTRR
#include <pexpert/arm64/T8020.h>
#define __ARM_L2CACHE_SIZE_LOG__ 21
#define ARM_BOARD_WFE_TIMEOUT_NS 1000
#define ARM_BOARD_CLASS_T8006
#define PEXPERT_NO_3X_IMAGES    1
#define CORE_NCTRS 10
#define PMAP_PV_LOAD_FACTOR 5
#define PMAP_CS             1
#define PMAP_CS_ENABLE      1
#endif /* ARM64_BOARD_CONFIG_T8006 */

#ifdef ARM64_BOARD_CONFIG_T8027
#define APPLE_ARM64_ARCH_FAMILY  1
#define APPLEVORTEX
#define ARM_ARCH_TIMER
#define KERNEL_INTEGRITY_CTRR
#include <pexpert/arm64/T8020.h>
#define __ARM_L2CACHE_SIZE_LOG__ 23
#define ARM_BOARD_WFE_TIMEOUT_NS 1000
#define ARM_BOARD_CLASS_T8027
#define CPU_COUNT 8
#define CPU_CLUSTER_OFFSETS {0, 4}
#define HAS_UNCORE_CTRS 1
#define UNCORE_VERSION 2
#define UNCORE_PER_CLUSTER 1
#define UNCORE_NCTRS 16
#define CORE_NCTRS 10
#define PMAP_PV_LOAD_FACTOR 5
#define PMAP_CS             1
#define PMAP_CS_ENABLE      1
#endif  /* ARM64_BOARD_CONFIG_T8027 */

#ifdef ARM64_BOARD_CONFIG_T8028
#define APPLE_ARM64_ARCH_FAMILY  1
#define APPLEVORTEX
#define ARM_ARCH_TIMER
#define KERNEL_INTEGRITY_CTRR
#include <pexpert/arm64/T8020.h>
#define __ARM_L2CACHE_SIZE_LOG__ 23
#define ARM_BOARD_WFE_TIMEOUT_NS 1000
#define ARM_BOARD_CLASS_T8028
#define CPU_COUNT 8
#define CPU_CLUSTER_OFFSETS {0, 4}
#define HAS_UNCORE_CTRS 1
#define UNCORE_VERSION 2
#define UNCORE_PER_CLUSTER 1
#define UNCORE_NCTRS 16
#define CORE_NCTRS 10
#define PMAP_PV_LOAD_FACTOR 5
#define PMAP_CS             1
#define PMAP_CS_ENABLE      1
#endif  /* ARM64_BOARD_CONFIG_T8028 */

#ifdef ARM64_BOARD_CONFIG_T8030
/*
 * The LLC size for Lightning is 8MB, but the LLC on Thunder is only 4MB.
 * We use the larger cache size here.  The expectation is
 * that this may cause flushes from Tempest to be less efficient
 * (cycles will be wasted on unnecessary way/set operations), but it
 * will be technically correct... the best kind of correct.
 */
#define APPLE_ARM64_ARCH_FAMILY  1
#define APPLELIGHTNING
#define ARM_ARCH_TIMER
#define KERNEL_INTEGRITY_CTRR
#include <pexpert/arm64/T8030.h>
#define __ARM_L2CACHE_SIZE_LOG__ 23
#define ARM_BOARD_WFE_TIMEOUT_NS 1000
#define ARM_BOARD_CLASS_T8030
#define CPU_COUNT 6
#define CPU_CLUSTER_OFFSETS {0, 4}
#define CPU_PIO_RO_CTL_OFFSETS {0x210055000, 0x210155000, 0x210255000, 0x210355000, 0x211055000, 0x211155000}
#define CLUSTER_PIO_RO_CTL_OFFSETS {0x210e49000, 0x211e49000}
#define HAS_UNCORE_CTRS 1
#define UNCORE_VERSION 2
#define UNCORE_PER_CLUSTER 1
#define UNCORE_NCTRS 16
#define CORE_NCTRS 10
#define PMAP_PV_LOAD_FACTOR 7
#define PMAP_CS             1
#define PMAP_CS_ENABLE      1
#endif  /* ARM64_BOARD_CONFIG_T8030 */




#ifdef ARM64_BOARD_CONFIG_BCM2837
#define BCM2837
#define BCM2837_BRINGUP
#define ARM_ARCH_TIMER
#include <pexpert/arm64/BCM2837.h>
#define __ARM_L2CACHE_SIZE_LOG__ 19
#define ARM_BOARD_CLASS_BCM2837
#define CPU_COUNT 4
#define CORE_NCTRS 8 /* Placeholder; KPC is not enabled for this target */
#endif  /* ARM64_BOARD_CONFIG_BCM2837 */

#endif /* ! _PEXPERT_ARM_BOARD_CONFIG_H */

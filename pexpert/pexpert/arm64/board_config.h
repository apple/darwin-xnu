/*
 * Copyright (c) 2007-2017 Apple Inc. All rights reserved.
 * Copyright (c) 2005-2006 Apple Computer, Inc. All rights reserved.
 */
#ifndef _PEXPERT_ARM_BOARD_CONFIG_H
#define _PEXPERT_ARM_BOARD_CONFIG_H

#ifdef ARM64_BOARD_CONFIG_S5L8960X
#define APPLE_ARM64_ARCH_FAMILY  1
#define APPLECYCLONE
#define ARM_ARCH_TIMER
#include <pexpert/arm64/S5L8960X.h>
#define __ARM_L2CACHE_SIZE_LOG__ 20
#define ARM_BOARD_WFE_TIMEOUT_NS 1000
#define ARM_BOARD_CLASS_S5L8960X
#define KERNEL_INTEGRITY_WT 1
#endif  /* ARM64_BOARD_CONFIG_S5L8960X */

#ifdef ARM64_BOARD_CONFIG_T7000
#define APPLE_ARM64_ARCH_FAMILY  1
#define APPLETYPHOON
#define ARM_ARCH_TIMER
#include <pexpert/arm64/T7000.h>
#define __ARM_L2CACHE_SIZE_LOG__ 20
#define ARM_BOARD_WFE_TIMEOUT_NS 1000
#define ARM_BOARD_CLASS_T7000
#define PEXPERT_3X_IMAGES	1
#define KERNEL_INTEGRITY_WT 1
#endif  /* ARM64_BOARD_CONFIG_T7000 */

#ifdef ARM64_BOARD_CONFIG_T7001
#define APPLE_ARM64_ARCH_FAMILY  1
#define APPLETYPHOON
#define ARM_ARCH_TIMER
#include <pexpert/arm64/T7000.h>
#define __ARM_L2CACHE_SIZE_LOG__ 21
#define ARM_BOARD_WFE_TIMEOUT_NS 1000
#define ARM_BOARD_CLASS_T7000
#define PEXPERT_3X_IMAGES	1
#define KERNEL_INTEGRITY_WT 1
#define CPU_COUNT 3
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
#include <pexpert/arm64/T8010.h>
#define __ARM_L2CACHE_SIZE_LOG__ 22
#define ARM_BOARD_WFE_TIMEOUT_NS 1000
#define ARM_BOARD_CLASS_T8010
#endif  /* ARM64_BOARD_CONFIG_T8010 */

#ifdef ARM64_BOARD_CONFIG_T8011
#define APPLE_ARM64_ARCH_FAMILY  1
#define APPLEHURRICANE
#define ARM_ARCH_TIMER
#include <pexpert/arm64/T8010.h>
#define __ARM_L2CACHE_SIZE_LOG__ 23
#define ARM_BOARD_WFE_TIMEOUT_NS 1000
#define ARM_BOARD_CLASS_T8011
#define CPU_COUNT 3
#endif  /* ARM64_BOARD_CONFIG_T8011 */






#endif /* ! _PEXPERT_ARM_BOARD_CONFIG_H */

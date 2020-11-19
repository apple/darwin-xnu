/*
 * Copyright (c) 2007-2020 Apple Inc. All rights reserved.
 * Copyright (c) 2005-2006 Apple Computer, Inc. All rights reserved.
 */
#ifndef _PEXPERT_ARM_BOARD_CONFIG_H
#define _PEXPERT_ARM_BOARD_CONFIG_H

#include <mach/machine.h>

/*
 * Per-SoC configuration.  General order is:
 *
 * CPU type
 * CPU configuration
 * CPU feature disables / workarounds
 * CPU topology
 * Other platform configuration (e.g. DARTs, PPL)
 *
 * This should answer the question: "what's unique about this SoC?"
 *
 * arm64/H*.h should answer the question: "what's unique about this CPU core?"
 *
 * For __ARM_AMP__ systems that have different cache line sizes on different
 * clusters, MAX_L2_CLINE must reflect the largest L2 cache line size
 * across all clusters.
 */


#ifdef ARM64_BOARD_CONFIG_T7000
#include <pexpert/arm64/H7.h>

#define MAX_L2_CLINE                   6
#define MAX_CPUS                       3
#define MAX_CPU_CLUSTERS               1
#endif  /* ARM64_BOARD_CONFIG_T7000 */

#ifdef ARM64_BOARD_CONFIG_T7001
#include <pexpert/arm64/H7.h>

#define MAX_L2_CLINE                   6
#define MAX_CPUS                       3
#define MAX_CPU_CLUSTERS               1
#endif  /* ARM64_BOARD_CONFIG_T7001 */

#ifdef ARM64_BOARD_CONFIG_S8000
#include <pexpert/arm64/H8.h>
#define MAX_CPUS                       2
#define MAX_CPU_CLUSTERS               1
/*
 * The L2 size for twister is in fact 3MB, not 4MB; we round up due
 * to the code being architected for power of 2 cache sizes, and rely
 * on the expected behavior that out of bounds operations will be
 * ignored.
 */
#define MAX_L2_CLINE                   6
#endif  /* ARM64_BOARD_CONFIG_S8000 */

#ifdef ARM64_BOARD_CONFIG_S8001
#include <pexpert/arm64/H8.h>
#define MAX_CPUS                       2
#define MAX_CPU_CLUSTERS               1
/*
 * The L2 size for twister is in fact 3MB, not 4MB; we round up due
 * to the code being architected for power of 2 cache sizes, and rely
 * on the expect behavior that out of bounds operations will be
 * ignored.
 */
#define MAX_L2_CLINE                   6
#endif  /* ARM64_BOARD_CONFIG_S8001 */

#ifdef ARM64_BOARD_CONFIG_T8010
#include <pexpert/arm64/H9.h>
#define MAX_CPUS                       3
#define MAX_CPU_CLUSTERS               1
/*
 * The L2 size for hurricane/zephyr is in fact 3MB, not 4MB; we round up due
 * to the code being architected for power of 2 cache sizes, and rely
 * on the expect behavior that out of bounds operations will be
 * ignored.
 */
#define MAX_L2_CLINE                   7

#if DEVELOPMENT || DEBUG
#define PMAP_CS                        1
#define PMAP_CS_ENABLE                 0
#endif
#endif  /* ARM64_BOARD_CONFIG_T8010 */

#ifdef ARM64_BOARD_CONFIG_T8011
#include <pexpert/arm64/H9.h>

#define MAX_L2_CLINE                   7
#define MAX_CPUS                       3
#define MAX_CPU_CLUSTERS               1

#if DEVELOPMENT || DEBUG
#define PMAP_CS                        1
#define PMAP_CS_ENABLE                 0
#endif
#endif  /* ARM64_BOARD_CONFIG_T8011 */

#ifdef ARM64_BOARD_CONFIG_T8015
#include <pexpert/arm64/H10.h>

#define MAX_L2_CLINE                   7
#define MAX_CPUS                       6
#define MAX_CPU_CLUSTERS               2

#define BROKEN_FRIGGING_SLEEP          1 /* Spurious wake: See rdar://problem/29762505 */

#if DEVELOPMENT || DEBUG
#define PMAP_CS                        1
#define PMAP_CS_ENABLE                 0
#endif
#endif  /* ARM64_BOARD_CONFIG_T8015 */

#ifdef ARM64_BOARD_CONFIG_T8020
#include <pexpert/arm64/H11.h>

#define MAX_L2_CLINE                   7
#define MAX_CPUS                       8
#define MAX_CPU_CLUSTERS               2

#define XNU_MONITOR                    1 /* Secure pmap runtime */
#define XNU_MONITOR_T8020_DART         1 /* T8020 DART plugin for secure pmap runtime */
#define T8020_DART_ALLOW_BYPASS        (1 << 1) /* DART allows translation bypass in certain cases */
#define XNU_MONITOR_NVME_PPL           1 /* NVMe PPL plugin for secure pmap runtime */
#define XNU_MONITOR_ANS2_SART          1 /* ANS2 SART plugin for secure pmap runtime */
#define PMAP_CS                        1
#define PMAP_CS_ENABLE                 1
#endif  /* ARM64_BOARD_CONFIG_T8020 */

#ifdef ARM64_BOARD_CONFIG_T8006
/*
 * The T8006 consists of 2 Tempest cores (i.e. T8020 eCores) and for most
 * of our purposes here may be considered a functional subset of T8020.
 */
#include <pexpert/arm64/H11.h>

#undef HAS_UNCORE_CTRS
#ifdef XNU_TARGET_OS_WATCH // This check might be redundant
#undef __APRR_SHADOW_SUPPORTED__
#endif

#define MAX_L2_CLINE                   7
#define MAX_CPUS                       2
#define MAX_CPU_CLUSTERS               1

#define XNU_MONITOR                    1 /* Secure pmap runtime */
#define XNU_MONITOR_T8020_DART         1 /* T8020 DART plugin for secure pmap runtime */
#define T8020_DART_ALLOW_BYPASS        (1 << 1) /* DART allows translation bypass in certain cases */
#define XNU_MONITOR_NVME_PPL           1 /* NVMe PPL plugin for secure pmap runtime */
#define XNU_MONITOR_ANS2_SART          1 /* ANS2 SART plugin for secure pmap runtime */
#define PMAP_CS                        1
#define PMAP_CS_ENABLE                 1
#define PREFER_ARM64_32_BINARIES
#define PEXPERT_NO_3X_IMAGES           1
#endif /* ARM64_BOARD_CONFIG_T8006 */

#ifdef ARM64_BOARD_CONFIG_T8027
#include <pexpert/arm64/H11.h>

#define MAX_L2_CLINE                   7
#define MAX_CPUS                       8
#define MAX_CPU_CLUSTERS               2

#define XNU_MONITOR                    1 /* Secure pmap runtime */
#define XNU_MONITOR_T8020_DART         1 /* T8020 DART plugin for secure pmap runtime */
#define T8020_DART_ALLOW_BYPASS        (1 << 1) /* DART allows translation bypass in certain cases */
#define XNU_MONITOR_NVME_PPL           1 /* NVMe PPL plugin for secure pmap runtime */
#define XNU_MONITOR_ANS2_SART          1 /* ANS2 SART plugin for secure pmap runtime */
#define PMAP_CS                        1
#define PMAP_CS_ENABLE                 1
#endif  /* ARM64_BOARD_CONFIG_T8027 */

#ifdef ARM64_BOARD_CONFIG_T8028
#include <pexpert/arm64/H11.h>

#define MAX_L2_CLINE                   7
#define MAX_CPUS                       8
#define MAX_CPU_CLUSTERS               2

#define XNU_MONITOR                    1 /* Secure pmap runtime */
#define XNU_MONITOR_T8020_DART         1 /* T8020 DART plugin for secure pmap runtime */
#define T8020_DART_ALLOW_BYPASS        (1 << 1) /* DART allows translation bypass in certain cases */
#define XNU_MONITOR_NVME_PPL           1 /* NVMe PPL plugin for secure pmap runtime */
#define XNU_MONITOR_ANS2_SART          1 /* ANS2 SART plugin for secure pmap runtime */
#define PMAP_CS                        1
#define PMAP_CS_ENABLE                 1
#endif  /* ARM64_BOARD_CONFIG_T8028 */

#ifdef ARM64_BOARD_CONFIG_T8030
#include <pexpert/arm64/H12.h>

#define MAX_L2_CLINE                   7
#define MAX_CPUS                       6
#define MAX_CPU_CLUSTERS               2

#define XNU_MONITOR                    1 /* Secure pmap runtime */
#define XNU_MONITOR_T8020_DART         1 /* T8020 DART plugin for secure pmap runtime */
#define T8020_DART_ALLOW_BYPASS        (1 << 1) /* DART allows translation bypass in certain cases */
#define XNU_MONITOR_NVME_PPL           1 /* NVMe PPL plugin for secure pmap runtime */
#define XNU_MONITOR_ANS2_SART          1 /* ANS2 SART plugin for secure pmap runtime */
#define XNU_MONITOR_UAT_PPL            1 /* UAT PPL plugin for secure pmap runtime */
#define PMAP_CS                        1
#define PMAP_CS_ENABLE                 1
#endif  /* ARM64_BOARD_CONFIG_T8030 */






#ifdef ARM64_BOARD_CONFIG_BCM2837
#include <pexpert/arm64/BCM2837.h>

#define MAX_L2_CLINE                   6
#define MAX_CPUS                       4
#define MAX_CPU_CLUSTERS               1

#define CORE_NCTRS                     8 /* Placeholder; KPC is not enabled for this target */
#endif  /* ARM64_BOARD_CONFIG_BCM2837 */

#ifndef HAS_UNCORE_CTRS
#undef UNCORE_VERSION
#undef UNCORE_PER_CLUSTER
#undef UNCORE_NCTRS
#endif

#if MAX_CPU_CLUSTERS == 1
#undef __ARM_AMP__
#endif

#ifndef MAX_CPU_CLUSTER_PHY_ID
#define MAX_CPU_CLUSTER_PHY_ID (MAX_CPU_CLUSTERS - 1)
#endif

#ifdef PREFER_ARM64_32_BINARIES
#define PREFERRED_USER_CPU_TYPE CPU_TYPE_ARM64_32
#define PREFERRED_USER_CPU_SUBTYPE CPU_SUBTYPE_ARM64_32_V8
#endif

#endif /* ! _PEXPERT_ARM_BOARD_CONFIG_H */

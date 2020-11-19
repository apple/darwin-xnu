/*
 * Copyright (c) 2007-2014 Apple Inc. All rights reserved.
 * Copyright (c) 2005-2006 Apple Computer, Inc. All rights reserved.
 */
#ifndef _PEXPERT_ARM_BOARD_CONFIG_H
#define _PEXPERT_ARM_BOARD_CONFIG_H

#ifdef ARM_BOARD_CONFIG_T8002
#define ARMA7
#include <pexpert/arm/T8002.h>
#define MAX_CPUS                    2
#define MAX_CPU_CLUSTERS            1
#define ARM_BOARD_WFE_TIMEOUT_NS 1000
#define MAX_L2_CLINE              6
#define ARM_BOARD_CLASS_T8002
#define PEXPERT_NO_3X_IMAGES    1
#endif  /* ARM_BOARD_CONFIG_T8002 */

#ifdef ARM_BOARD_CONFIG_T8004
#define ARMA7
#include <pexpert/arm/T8002.h>
#define MAX_CPUS                    2
#define MAX_CPU_CLUSTERS            1
#define ARM_BOARD_WFE_TIMEOUT_NS 1000
#define MAX_L2_CLINE              6
#define ARM_BOARD_CLASS_T8002
#define PEXPERT_NO_3X_IMAGES    1
#endif  /* ARM_BOARD_CONFIG_T8004 */

#endif /* ! _PEXPERT_ARM_BOARD_CONFIG_H */

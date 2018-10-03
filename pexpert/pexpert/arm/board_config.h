/*
 * Copyright (c) 2007-2014 Apple Inc. All rights reserved.
 * Copyright (c) 2005-2006 Apple Computer, Inc. All rights reserved.
 */
#ifndef _PEXPERT_ARM_BOARD_CONFIG_H
#define _PEXPERT_ARM_BOARD_CONFIG_H

#ifdef ARM_BOARD_CONFIG_S7002
#define ARMA7
#define __XNU_UP__
#include <pexpert/arm/S7002.h>

#define ARM_BOARD_WFE_TIMEOUT_NS 1000
#define __ARM_L2CACHE_SIZE_LOG__ 18
#define ARM_BOARD_CLASS_S7002
#define PEXPERT_NO_3X_IMAGES	1
#endif  /* ARM_BOARD_CONFIG_S7002 */

#ifdef ARM_BOARD_CONFIG_T8002
#define ARMA7
#include <pexpert/arm/T8002.h>
#define ARM_BOARD_WFE_TIMEOUT_NS 1000
#define __ARM_L2CACHE_SIZE_LOG__ 19
#define ARM_BOARD_CLASS_T8002
#define PEXPERT_NO_3X_IMAGES	1
#endif  /* ARM_BOARD_CONFIG_T8002 */

#ifdef ARM_BOARD_CONFIG_T8004
#define ARMA7
#include <pexpert/arm/T8002.h>
#define ARM_BOARD_WFE_TIMEOUT_NS 1000
#define __ARM_L2CACHE_SIZE_LOG__ 20
#define ARM_BOARD_CLASS_T8002
#define PEXPERT_NO_3X_IMAGES	1
#endif  /* ARM_BOARD_CONFIG_T8004 */

#endif /* ! _PEXPERT_ARM_BOARD_CONFIG_H */

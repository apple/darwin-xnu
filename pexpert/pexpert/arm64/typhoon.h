/*
 * Copyright (c) 2012-2018 Apple Inc. All rights reserved.
 */

#ifndef _PEXPERT_ARM_TYPHOON_H
#define _PEXPERT_ARM_TYPHOON_H

#define MONITOR                 1 /* Use EL3 monitor */
#define NO_ECORE                1
#define HAS_32BIT_DBGWRAP       1
#define HAS_CPMU_BIU_EVENTS     1 /* Has BIU events in CPMU */
#define HAS_CPMU_L2C_EVENTS     1 /* Has L2 cache events in CPMU */

#ifdef APPLETYPHOON
#include "arm64_common.h"
#endif

#endif /* ! _PEXPERT_ARM_TYPHOON_H */

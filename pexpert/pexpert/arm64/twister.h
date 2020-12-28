/*
 * Copyright (c) 2014-2018 Apple Inc. All rights reserved.
 */

#ifndef _PEXPERT_ARM_TWISTER_H
#define _PEXPERT_ARM_TWISTER_H

#define MONITOR                 1 /* Use EL3 monitor */
#define NO_ECORE                1
#define HAS_32BIT_DBGWRAP       1
#define HAS_CPMU_L2C_EVENTS     1 /* Has L2 cache events in CPMU */

#ifdef APPLETWISTER
#include "arm64_common.h"
#endif

#endif /* ! _PEXPERT_ARM_TWISTER_H */

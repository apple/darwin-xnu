/*
 * Copyright (c) 2012-2013 Apple Inc. All rights reserved.
 */

#ifndef _PEXPERT_ARM_TYPHOON_H
#define _PEXPERT_ARM_TYPHOON_H

#define MONITOR                 1 /* Use EL3 monitor */
#define NO_ECORE                1
#define HAS_32BIT_DBGWRAP       1

#ifdef APPLETYPHOON
#include "arm64_common.h"
#endif

#endif /* ! _PEXPERT_ARM_TYPHOON_H */

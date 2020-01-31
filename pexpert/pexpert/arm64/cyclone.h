/*
 * Copyright (c) 2012-2013 Apple Inc. All rights reserved.
 */

#ifndef _PEXPERT_ARM_CYCLONE_H
#define _PEXPERT_ARM_CYCLONE_H

#ifdef APPLECYCLONE
#include "arm64_common.h"

#define MONITOR                 1 /* Use EL3 monitor */
#define NO_ECORE                1
#define HAS_32BIT_DBGWRAP       1

/*
 * Determined by experiment (not described in manual):
 * A0 is variant 0, B0 is variant 1.  See arm64/proc_reg.h
 * for how these values are constructed from the MIDR.
 */
#define CYCLONE_CPU_VERSION_A0                  0x00
#define CYCLONE_CPU_VERSION_B0                  0x10

#endif

#endif /* ! _PEXPERT_ARM_CYCLONE_H */

/*
 * Copyright (c) 2014 Apple Inc. All rights reserved.
 */

#ifndef _PEXPERT_ARM_HURRICANE_H
#define _PEXPERT_ARM_HURRICANE_H

#define NO_MONITOR      1 /* No EL3 for this CPU -- ever */
#define HAS_MIGSTS      1 /* Has MIGSTS register, and supports migration between p-core and e-core */
#define HAS_KTRR        1 /* Has KTRR registers */

#ifdef APPLEHURRICANE
#include "arm64_common.h"
#endif

/*
 * A0 is variant 0, B0 is variant 1.  See arm64/proc_reg.h
 * for how these values are constructed from the MIDR.
 */
#define HURRICANE_CPU_VERSION_A0                0x00
#define HURRICANE_CPU_VERSION_B0                0x10

// Hurricane and Zephyr require workaround for radar 20619637
#define SINGLE_STEP_RETIRE_ERRATA 1

#endif /* ! _PEXPERT_ARM_HURRICANE_H */

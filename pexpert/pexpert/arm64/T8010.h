/*
 * Copyright (c) 2014-2015 Apple Inc. All rights reserved.
 */

#ifndef _PEXPERT_ARM_T8010_H
#define _PEXPERT_ARM_T8010_H

#include <pexpert/arm64/AIC.h>
#include <pexpert/arm64/hurricane.h>

#ifndef ASSEMBLER

#include <pexpert/arm/S3cUART.h>
#include <pexpert/arm/dockchannel.h>
#include <pexpert/arm64/AMCC.h>

// AOP_CLOCK frequency * 30 ms
#define DOCKCHANNEL_DRAIN_PERIOD                (192000000 * 0.03)

#endif

#endif /* ! _PEXPERT_ARM_T8010_H */

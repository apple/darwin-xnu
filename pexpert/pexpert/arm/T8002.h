/*
 * Copyright (c) 2014-2015 Apple Inc. All rights reserved.
 */

#ifndef _PEXPERT_ARM_T8002_H
#define _PEXPERT_ARM_T8002_H

#include <pexpert/arm/AIC.h>

#ifndef ASSEMBLER

#include <pexpert/arm/S3cUART.h>

#include <pexpert/arm/dockchannel.h>

// AOP_CLOCK frequency * 30 ms
#define DOCKCHANNEL_DRAIN_PERIOD                (96000000 * 0.03)

#define rPMGR_EVENT_TMR                         (*(volatile uint32_t *) (timer_base + 0x00000))
#define rPMGR_EVENT_TMR_PERIOD                  (*(volatile uint32_t *) (timer_base + 0x00004))
#define rPMGR_EVENT_TMR_CTL                     (*(volatile uint32_t *) (timer_base + 0x00008))

#define PMGR_EVENT_TMR_CTL_EN                   (1 << 0)

#endif

#endif /* ! _PEXPERT_ARM_T8002_H */

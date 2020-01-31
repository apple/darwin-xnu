/*
 * Copyright (c) 2013 Apple Inc. All rights reserved.
 */

#ifndef _PEXPERT_ARM_S7002_H
#define _PEXPERT_ARM_S7002_H

#ifndef ASSEMBLER

#include <pexpert/arm/S3cUART.h>

#define rPMGR_EVENT_TMR                 (*(volatile unsigned *) (timer_base + 0x00100))
#define rPMGR_EVENT_TMR_PERIOD          (*(volatile unsigned *) (timer_base + 0x00104))
#define rPMGR_EVENT_TMR_CTL             (*(volatile unsigned *) (timer_base + 0x00108))
#define rPMGR_INTERVAL_TMR              (*(volatile unsigned *) (timer_base + 0x00200))
#define rPMGR_INTERVAL_TMR_CTL          (*(volatile unsigned *) (timer_base + 0x00204))

#define PMGR_EVENT_TMR_CTL_EN           (1 << 0)
#define PMGR_INTERVAL_TMR_CTL_EN        (1 << 0)
#define PMGR_INTERVAL_TMR_CTL_CLR_INT   (1 << 8)

#define DOCKFIFO_UART                   (1)
#define DOCKFIFO_UART_WRITE             (0)
#define DOCKFIFO_UART_READ              (1)
#define DOCKFIFO_W_SPACING              (0x1000)
#define DOCKFIFO_SPACING                (0x3000)

#define rDOCKFIFO_R_DATA(_f, _n)        (*(volatile uint32_t *)(uart_base + ((_f) * DOCKFIFO_SPACING) + ((_n) * 4)))
#define rDOCKFIFO_R_STAT(_f)            (*(volatile uint32_t *)(uart_base + ((_f) * DOCKFIFO_SPACING) + 0x14))
#define rDOCKFIFO_W_DATA(_f, _n)        (*(volatile uint32_t *)(uart_base + ((_f) * DOCKFIFO_SPACING) + DOCKFIFO_W_SPACING + ((_n) * 4)))
#define rDOCKFIFO_W_STAT(_f)            (*(volatile uint32_t *)(uart_base + ((_f) * DOCKFIFO_SPACING) + DOCKFIFO_W_SPACING + 0x14))
#define rDOCKFIFO_CNFG(_f)              (*(volatile uint32_t *)(uart_base + ((_f) * DOCKFIFO_SPACING) + 0x2000))
#define rDOCKFIFO_DRAIN(_f)             (*(volatile uint32_t *)(uart_base + ((_f) * DOCKFIFO_SPACING) + 0x2004))
#define rDOCKFIFO_INTMASK(_f)           (*(volatile uint32_t *)(uart_base + ((_f) * DOCKFIFO_SPACING) + 0x2008))

#endif

#define PMGR_INTERVAL_TMR_OFFSET        (0x200)
#define PMGR_INTERVAL_TMR_CTL_OFFSET    (0x204)

#endif /* ! _PEXPERT_ARM_S7002_H */

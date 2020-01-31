/*
 * Copyright (c) 2014-2015 Apple Inc. All rights reserved.
 */

#ifndef _PEXPERT_ARM_T8010_H
#define _PEXPERT_ARM_T8010_H

#include <pexpert/arm64/AIC.h>
#include <pexpert/arm64/hurricane.h>

#ifndef ASSEMBLER

#include <pexpert/arm/S3cUART.h>
#include <pexpert/arm64/AMCC.h>

#define DOCKCHANNEL_UART                        (1)
#define DOCKCHANNEL_STRIDE                      (0x10000)

// Channel index
#define DOCKCHANNEL_UART_CHANNEL                (0)

// AOP_CLOCK frequency * 30 ms
#define DOCKCHANNEL_DRAIN_PERIOD                (192000000 * 0.03)

#define rDOCKCHANNELS_AGENT_AP_INTR_CTRL        (*(volatile uint32_t *) (dock_agent_base + 0x00))
#define rDOCKCHANNELS_AGENT_AP_INTR_STATUS      (*(volatile uint32_t *) (dock_agent_base + 0x04))
#define rDOCKCHANNELS_AGENT_AP_ERR_INTR_CTRL    (*(volatile uint32_t *) (dock_agent_base + 0x08))
#define rDOCKCHANNELS_AGENT_AP_ERR_INTR_STATUS  (*(volatile uint32_t *) (dock_agent_base + 0x0c))

#define rDOCKCHANNELS_DEV_DRAIN_CFG(_ch)        (*(volatile uint32_t *) (uart_base + ((_ch) * DOCKCHANNEL_STRIDE) + 0x0008))

#define rDOCKCHANNELS_DEV_WDATA1(_ch)           (*(volatile uint32_t *) (uart_base + ((_ch) * DOCKCHANNEL_STRIDE) + 0x4004))
#define rDOCKCHANNELS_DEV_WSTAT(_ch)            (*(volatile uint32_t *) (uart_base + ((_ch) * DOCKCHANNEL_STRIDE) + 0x4014))
#define rDOCKCHANNELS_DEV_RDATA0(_ch)           (*(volatile uint32_t *) (uart_base + ((_ch) * DOCKCHANNEL_STRIDE) + 0x4018))
#define rDOCKCHANNELS_DEV_RDATA1(_ch)           (*(volatile uint32_t *) (uart_base + ((_ch) * DOCKCHANNEL_STRIDE) + 0x401c))

#define rDOCKCHANNELS_DOCK_RDATA1(_ch)          (*(volatile uint32_t *) (uart_base + ((_ch) * DOCKCHANNEL_STRIDE) + 0xc01c))
#define rDOCKCHANNELS_DOCK_RDATA3(_ch)          (*(volatile uint32_t *) (uart_base + ((_ch) * DOCKCHANNEL_STRIDE) + 0xc024))

#endif

#endif /* ! _PEXPERT_ARM_T8010_H */

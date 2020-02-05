/*
 * Copyright (c) 2018 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
#ifndef _PEXPERT_ARM_DOCKCHANNEL_H
#define _PEXPERT_ARM_DOCKCHANNEL_H

#define DOCKCHANNEL_UART                        (1)
#define DOCKCHANNEL_STRIDE                      (0x10000)

// Channel index
#define DOCKCHANNEL_UART_CHANNEL                (0)

#define rDOCKCHANNELS_AGENT_AP_INTR_CTRL        (*(volatile uint32_t *) (dock_agent_base + 0x00))
#define rDOCKCHANNELS_AGENT_AP_INTR_STATUS      (*(volatile uint32_t *) (dock_agent_base + 0x04))
#define rDOCKCHANNELS_AGENT_AP_ERR_INTR_CTRL    (*(volatile uint32_t *) (dock_agent_base + 0x08))
#define rDOCKCHANNELS_AGENT_AP_ERR_INTR_STATUS  (*(volatile uint32_t *) (dock_agent_base + 0x0c))

#define rDOCKCHANNELS_DEV_DRAIN_CFG(_ch)        (*(volatile uint32_t *) (dockchannel_uart_base + ((_ch) * DOCKCHANNEL_STRIDE) + 0x0008))

#define rDOCKCHANNELS_DEV_WDATA1(_ch)           (*(volatile uint32_t *) (dockchannel_uart_base + ((_ch) * DOCKCHANNEL_STRIDE) + 0x4004))
#define rDOCKCHANNELS_DEV_WSTAT(_ch)            (*(volatile uint32_t *) (dockchannel_uart_base + ((_ch) * DOCKCHANNEL_STRIDE) + 0x4014))
#define rDOCKCHANNELS_DEV_RDATA0(_ch)           (*(volatile uint32_t *) (dockchannel_uart_base + ((_ch) * DOCKCHANNEL_STRIDE) + 0x4018))
#define rDOCKCHANNELS_DEV_RDATA1(_ch)           (*(volatile uint32_t *) (dockchannel_uart_base + ((_ch) * DOCKCHANNEL_STRIDE) + 0x401c))

#define rDOCKCHANNELS_DOCK_RDATA1(_ch)          (*(volatile uint32_t *) (dockchannel_uart_base + ((_ch) * DOCKCHANNEL_STRIDE) + 0xc01c))
#define rDOCKCHANNELS_DOCK_RDATA3(_ch)          (*(volatile uint32_t *) (dockchannel_uart_base + ((_ch) * DOCKCHANNEL_STRIDE) + 0xc024))

#endif  /* !_PEXPERT_ARM_DOCKCHANNEL_H */

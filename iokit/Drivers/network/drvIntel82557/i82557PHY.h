/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * Copyright 1996 NeXT Software, Inc.
 * All rights reserved.
 *
 * i82557PHY.h
 * - contains PHY specific MDI register offsets and definitions
 *
 * Modification History
 *
 * 4-Mar-96	Dieter Siegmund (dieter@NeXT.com)
 *		Created.
 */

#ifndef _I82557PHY_H
#define _I82557PHY_H

#define PHY_ADDRESS_0			0
#define PHY_ADDRESS_DEFAULT		1
#define PHY_ADDRESS_I82503		32
#define PHY_ADDRESS_MAX			32

#define PHY_MODEL_MASK			0xfff0ffff
#define PHY_MODEL_NSC83840		0x5c002000
#define PHY_MODEL_I82553_A_B	0x000003e0
#define PHY_MODEL_I82553_C		0x035002a8
#define PHY_MODEL_I82555		0x015002a8	// also for internal PHY in i82558

#define MEDIUM_TYPE_TO_MASK(m)	(1 << (m))

//-------------------------------------------------------------------------
// Generic MDI registers: 
//-------------------------------------------------------------------------
#define MDI_REG_CONTROL					0x00
#define MDI_REG_STATUS					0x01
#define MDI_REG_PHYID_WORD_1			0x02
#define MDI_REG_PHYID_WORD_2			0x03
#define MDI_REG_ANAR					0x04
#define MDI_REG_ANLP					0x05
#define MDI_REG_ANEX					0x06
#define MDI_REG_RESERVED_TOP			0x0f

typedef UInt16	mdi_reg_t;

//-------------------------------------------------------------------------
// MDI Control Register.
// Address 0, 16-bit, RW.
//-------------------------------------------------------------------------
#define MDI_CONTROL_RESET				BIT(15)
#define MDI_CONTROL_LOOPBACK			BIT(14)
#define MDI_CONTROL_100					BIT(13)
#define MDI_CONTROL_AUTONEG_ENABLE		BIT(12)
#define MDI_CONTROL_POWER_DOWN			BIT(11)
#define MDI_CONTROL_ISOLATE				BIT(10)
#define MDI_CONTROL_RESTART_AUTONEG		BIT(9)
#define MDI_CONTROL_FULL_DUPLEX			BIT(8)
#define MDI_CONTROL_CDT_ENABLE			BIT(7)

//-------------------------------------------------------------------------
// MDI Status Register.
// Address 1, 16-bit, RO.
//-------------------------------------------------------------------------
#define MDI_STATUS_T4					BIT(15)
#define MDI_STATUS_TX_FD				BIT(14)
#define MDI_STATUS_TX_HD				BIT(13)
#define MDI_STATUS_10_FD				BIT(12)
#define MDI_STATUS_10_HD				BIT(11)
#define MDI_STATUS_AUTONEG_COMPLETE		BIT(5)
#define MDI_STATUS_REMOTE_FAULT_DETECT	BIT(4)
#define MDI_STATUS_AUTONEG_CAPABLE		BIT(3)
#define MDI_STATUS_LINK_STATUS			BIT(2)
#define MDI_STATUS_JABBER_DETECTED		BIT(1)
#define MDI_STATUS_EXTENDED_CAPABILITY	BIT(0)

//-------------------------------------------------------------------------
// MDI Auto-Negotiation Advertisement Register.
// Address 4, 16-bit, RW.
//-------------------------------------------------------------------------
#define MDI_ANAR_NEXT_PAGE				BIT(15)
#define MDI_ANAR_ACKNOWLEDGE			BIT(14)
#define MDI_ANAR_REMOTE_FAULT			BIT(13)
#define MDI_ANAR_T4						BIT(9)
#define MDI_ANAR_TX_FD					BIT(8)
#define MDI_ANAR_TX_HD					BIT(7)
#define MDI_ANAR_10_FD					BIT(6)
#define MDI_ANAR_10_HD					BIT(5)
#define MDI_ANAR_SELECTOR_SHIFT			0
#define MDI_ANAR_SELECTOR_MASK			CSR_MASK(MDI_ANAR_SELECTOR, 0x1f)

//-------------------------------------------------------------------------
// MDI Auto-Negotiation Link Partner Ability Register.
// Address 5, 16-bit, RO.
//-------------------------------------------------------------------------
#define MDI_ANLP_NEXT_PAGE				BIT(15)
#define MDI_ANLP_ACKNOWLEDGE			BIT(14)
#define MDI_ANLP_REMOTE_FAULT			BIT(13)
#define MDI_ANLP_T4						BIT(9)
#define MDI_ANLP_TX_FD					BIT(8)
#define MDI_ANLP_TX_HD					BIT(7)
#define MDI_ANLP_10_FD					BIT(6)
#define MDI_ANLP_10_HD					BIT(5)
#define MDI_ANLP_SELECTOR_SHIFT			0
#define MDI_ANLP_SELECTOR_MASK			CSR_MASK(MDI_ANLP_SELECTOR, 0x1f)

//-------------------------------------------------------------------------
// MDI Auto-Negotiation Expansion Register.
// Address 6, 16-bit, RO.
//-------------------------------------------------------------------------
#define MDI_ANEX_PARALLEL_DETECT_FAULT	BIT(4)
#define MDI_ANEX_LP_NEXT_PAGEABLE		BIT(3)
#define MDI_ANEX_NEXT_PAGEABLE			BIT(2)
#define MDI_ANEX_PAGE_RECEIVED			BIT(1)
#define MDI_ANEX_LP_AUTONEGOTIABLE		BIT(0)

//-------------------------------------------------------------------------
// NSC DP83840-specific MDI registers
//-------------------------------------------------------------------------
#define NSC83840_REG_DCR				0x12	// disconnect counter
#define NSC83840_REG_FCSCR				0x13	// false carrier sense counter
#define NSC83840_REG_RECR				0x15	// receive error counter
#define NSC83840_REG_SRR				0x16	// silicon revision register
#define NSC83840_REG_PCR				0x17	// PCS configuration register
#define NSC83840_REG_LBREMR				0x18	// loopback,bypass,rx err mask
#define NSC83840_REG_PAR				0x19	// PHY address register
#define NSC83840_REG_10BTSR				0x1b	// 10Base-T status register
#define NSC83840_REG_10BTCR				0x1c	// 10Base-T config register

//-------------------------------------------------------------------------
// NSC PCS Configuration Register (PCR).
// Address 0x17, 16-bit, RW.
//-------------------------------------------------------------------------
#define NSC83840_PCR_NRZI_EN			BIT(15)
#define NSC83840_PCR_DESCR_TO_SEL		BIT(14)
#define NSC83840_PCR_DESCR_TO_DIS		BIT(13)
#define NSC83840_PCR_REPEATER			BIT(12)
#define NSC83840_PCR_ENCSEL				BIT(11)
#define NSC83840_PCR_TXREADY			BIT(10)
#define NSC83840_PCR_CLK25MDIS			BIT(7)
#define NSC83840_PCR_F_LINK_100			BIT(6)
#define NSC83840_PCR_CIM_DIS			BIT(5)
#define NSC83840_PCR_TX_OFF				BIT(4)
#define NSC83840_PCR_LED1_MODE			BIT(2)
#define NSC83840_PCR_LED4_MODE			BIT(1)

//-------------------------------------------------------------------------
// NSC PHY Address Register (PAR).
// Address 0x19, 16-bit, RW.
//-------------------------------------------------------------------------
#define NSC83840_PAR_DIS_CRS_JAB		BIT(11)
#define NSC83840_PAR_AN_EN_STAT			BIT(10)
#define NSC83840_PAR_FEFI_EN			BIT(8)
#define NSC83840_PAR_DUPLEX_STAT		BIT(7)
#define NSC83840_PAR_SPEED_10			BIT(6)
#define NSC83840_PAR_CIM_STATUS			BIT(5)
#define NSC83840_PAR_PHYADDR_SHIFT		0
#define NSC83840_PAR_PHYADDR_MASK		CSR_MASK(NSC83840_PAR_PHYADDR, 0x1f)

//-------------------------------------------------------------------------
// Intel 82553-specific MDI registers
//-------------------------------------------------------------------------
#define I82553_REG_SCR					0x10
#define I82553_REG_100RDCR				0x14

//-------------------------------------------------------------------------
// Intel 82553 Status and Control Register (SCR).
// Address 0x10, 16-bit, RW.
//-------------------------------------------------------------------------
#define I82553_SCR_FLOW_CONTROL			BIT(15)
#define I82553_SCR_CARRIER_SENSE_DIS	BIT(13)
#define I82553_SCR_TX_FLOW_CONTROL		BIT(12)
#define I82553_SCR_RX_DESERIAL_IN_SYNC	BIT(11)
#define I82553_SCR_100_POWERDOWN		BIT(10)
#define I82553_SCR_10_POWERDOWN			BIT(9)
#define I82553_SCR_POLARITY				BIT(8)
#define I82553_SCR_T4					BIT(2)
#define I82553_SCR_100					BIT(1)
#define I82553_SCR_FULL_DUPLEX			BIT(0)

#endif /* !_I82557PHY_H */

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
 * Copyright (c) 1998-1999 by Apple Computer, Inc., All rights reserved.
 *
 * MII protocol and PHY register definitions.
 *
 * HISTORY
 *
 */

#ifndef _BMACENETMII_H
#define _BMACENETMII_H

/*
 *	MII command frame (32-bits) as documented in IEEE 802.3u
 */

// _BIG_ENDIAN is already defined for PPC
//
#if 0
#ifdef  __PPC__
#define _BIG_ENDIAN
#endif
#endif /* 0 */

typedef union {
    unsigned int		data;
#ifdef _BIG_ENDIAN
    struct {
	unsigned int
        			st:2,		// start of frame
#define MII_ST			0x01
        			op:2,		// operation code
#define MII_OP_READ	0x02
#define MII_OP_WRITE	0x01				
        			phyad:5,	// PHY address
        			regad:5,	// register address
        			ta:2,		// turnaround
        			data:16;	// 16-bit data field
        } bit;
#else  _BIG_ENDIAN
    struct {
        unsigned int
        			data:16,	// 16-bit data field
       				ta:2,		// turnaround
        			regad:5,	// register address
        			phyad:5,	// PHY address
        			op:2,		// operation code
        			st:2;		// start of frame
        } bit;
#endif _BIG_ENDIAN
} miiFrameUnion;

#define MII_FRAME_PREAMBLE		0xFFFFFFFF
#define MII_FRAME_SIZE			32
#define MII_FRAME_READ			0x60000000
#define MII_FRAME_WRITE			0x50020000

#define MII_MAX_PHY				32

/* MII Registers */
#define	MII_CONTROL				0
#define	MII_STATUS				1
#define	MII_ID0					2
#define	MII_ID1					3
#define	MII_ADVERTISEMENT		4
#define	MII_LINKPARTNER			5
#define	MII_EXPANSION			6
#define	MII_NEXTPAGE			7

/* MII Control register bits */
#define	MII_CONTROL_RESET					0x8000
#define	MII_CONTROL_LOOPBACK				0x4000
#define	MII_CONTROL_SPEED_SELECTION			0x2000
#define	MII_CONTROL_AUTONEGOTIATION			0x1000
#define	MII_CONTROL_POWERDOWN				0x800
#define	MII_CONTROL_ISOLATE					0x400
#define	MII_CONTROL_RESTART_NEGOTIATION		0x200
#define	MII_CONTROL_FULLDUPLEX				0x100
#define	MII_CONTROL_COLLISION_TEST			0x80

/* MII Status register bits */
#define	MII_STATUS_100BASET4				0x8000
#define	MII_STATUS_100BASETX_FD				0x4000
#define	MII_STATUS_100BASETX				0x2000
#define	MII_STATUS_10BASET_FD				0x1000
#define	MII_STATUS_10BASET					0x800
#define	MII_STATUS_NEGOTIATION_COMPLETE		0x20
#define	MII_STATUS_REMOTE_FAULT				0x10
#define	MII_STATUS_NEGOTIATION_ABILITY		0x8
#define	MII_STATUS_LINK_STATUS				0x4
#define	MII_STATUS_JABBER_DETECT			0x2
#define	MII_STATUS_EXTENDED_CAPABILITY		0x1

/* MII ANAR register bits */
#define MII_ANAR_100BASET4					0x200
#define	MII_ANAR_100BASETX_FD				0x100
#define	MII_ANAR_100BASETX					0x80
#define	MII_ANAR_10BASET_FD					0x40
#define	MII_ANAR_10BASET					0x20

/* MII ST10040 Specific */

/* MII ST10040 ID */
#define MII_ST10040_OUI						0x1e0400
#define MII_ST10040_MODEL					0x00
#define MII_ST10040_REV						0x01
#define MII_ST10040_ID						((MII_ST10040_OUI << 10) | \
											(MII_ST10040_MODEL << 4))
#define MII_ST10040_MASK					0xfffffff0

#define MII_ST10040_DELAY					1

/* MII ST10040 Regs */
#define MII_ST10040_CHIPST					0x14

/* MII ST10040 CHIPST register bits */
#define MII_ST10040_CHIPST_LINK				0x2000
#define MII_ST10040_CHIPST_DUPLEX			0x1000
#define MII_ST10040_CHIPST_SPEED			0x0800
#define MII_ST10040_CHIPST_NEGOTIATION		0x0020

/* MII DP83843 Specific */

/* MII DP83843 ID */
#define MII_DP83843_OUI						0x080017
#define MII_DP83843_MODEL					0x01
#define MII_DP83843_REV						0x00
#define MII_DP83843_ID						((MII_DP83843_OUI << 10) | \
											(MII_DP83843_MODEL << 4))
#define MII_DP83843_MASK					0xfffffff0

#define MII_DP83843_DELAY					20

/* MII DP83843 PHYSTS register bits */
#define MII_DP83843_PHYSTS					0x10
#define MII_DP83843_PHYSTS_LINK				0x0001
#define MII_DP83843_PHYSTS_SPEED10			0x0002
#define MII_DP83843_PHYSTS_DUPLEX			0x0004
#define MII_DP83843_PHYSTS_NEGOTIATION		0x0020


/* MII timeout */
#define MII_DEFAULT_DELAY			20
#define MII_RESET_TIMEOUT			100
#define MII_RESET_DELAY				10

#define MII_LINK_TIMEOUT			2500
#define MII_LINK_DELAY				20

#endif /* _BMACENETMII_H */

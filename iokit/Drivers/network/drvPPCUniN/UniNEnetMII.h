/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
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

/*
 *      MII command frame (32-bits) as documented in IEEE 802.3u
 */
#define MII_OP_READ     0x02
#define MII_OP_WRITE    0x01                            

#define MII_MAX_PHY                             32

/* MII Registers */
#define MII_CONTROL                             0
#define MII_STATUS                              1
#define MII_ID0                                 2
#define MII_ID1                                 3
#define MII_ADVERTISEMENT                       4
#define MII_LINKPARTNER                         5
#define MII_EXPANSION                           6
#define MII_NEXTPAGE                            7

/* MII Control register bits */
#define MII_CONTROL_RESET                       0x8000
#define MII_CONTROL_LOOPBACK                    0x4000
#define MII_CONTROL_SPEED_SELECTION             0x2000
#define MII_CONTROL_AUTONEGOTIATION             0x1000
#define MII_CONTROL_POWERDOWN                   0x800
#define MII_CONTROL_ISOLATE                     0x400
#define MII_CONTROL_RESTART_NEGOTIATION         0x200
#define MII_CONTROL_FULLDUPLEX                  0x100
#define MII_CONTROL_COLLISION_TEST              0x80

/* MII Status register bits */
#define MII_STATUS_100BASET4                    0x8000
#define MII_STATUS_100BASETX_FD                 0x4000
#define MII_STATUS_100BASETX                    0x2000
#define MII_STATUS_10BASET_FD                   0x1000
#define MII_STATUS_10BASET                      0x800
#define MII_STATUS_NEGOTIATION_COMPLETE         0x20
#define MII_STATUS_REMOTE_FAULT                 0x10
#define MII_STATUS_NEGOTIATION_ABILITY          0x8
#define MII_STATUS_LINK_STATUS                  0x4
#define MII_STATUS_JABBER_DETECT                0x2
#define MII_STATUS_EXTENDED_CAPABILITY          0x1

/* MII ANAR register bits */
#define MII_ANAR_ASYM_PAUSE                     0x800 
#define MII_ANAR_PAUSE                          0x400
#define MII_ANAR_100BASET4                      0x200
#define MII_ANAR_100BASETX_FD                   0x100
#define MII_ANAR_100BASETX                      0x80
#define MII_ANAR_10BASET_FD                     0x40
#define MII_ANAR_10BASET                        0x20

/* MII ANLPAR register bits */
#define MII_LPAR_NEXT_PAGE                      0x8000
#define MII_LPAR_ACKNOWLEDGE                    0x4000
#define MII_LPAR_REMOTE_FAULT                   0x2000
#define MII_LPAR_ASYM_PAUSE                     0x0800
#define MII_LPAR_PAUSE                          0x0400
#define MII_LPAR_100BASET4                      0x200
#define MII_LPAR_100BASETX_FD                   0x100
#define MII_LPAR_100BASETX                      0x80
#define MII_LPAR_10BASET_FD                     0x40
#define MII_LPAR_10BASET                        0x20


/* MII BCM5201 Specific */

/* MII BCM5201 ID */
#define MII_BCM5201_OUI                         0x001018
#define MII_BCM5201_MODEL                       0x21
#define MII_BCM5201_REV                         0x01
#define MII_BCM5201_ID                          ((MII_BCM5201_OUI << 10) | (MII_BCM5201_MODEL << 4))
#define MII_BCM5201_MASK                        0xfffffff0

#define MII_BCM5201_DELAY                       1

/* MII BCM5201 Regs */
#define MII_BCM5201_AUXSTATUS                   0x18

/* MII BCM5201 AUXSTATUS register bits */
#define MII_BCM5201_AUXSTATUS_DUPLEX            0x0001
#define MII_BCM5201_AUXSTATUS_SPEED             0x0002

/* MII BCM5201 MULTIPHY interrupt register.
 * Added 4/20/2000 by A.W. for power management */
#define MII_BCM5201_INTERRUPT                   0x1A
#define MII_BCM5201_INTERRUPT_INTENABLE         0x4000

#define MII_BCM5201_AUXMODE2                    0x1B
#define MII_BCM5201_AUXMODE2_LOWPOWER           0x0008

#define MII_BCM5201_MULTIPHY                    0x1E

/* MII BCM5201 MULTIPHY register bits */
#define MII_BCM5201_MULTIPHY_SERIALMODE         0x0002
#define MII_BCM5201_MULTIPHY_SUPERISOLATE       0x0008


/* MII LXT971 (Level One) Specific */

/* MII LXT971 ID */
#define MII_LXT971_OUI                          0x0004de
#define MII_LXT971_MODEL                        0x0e
#define MII_LXT971_REV                          0x01
#define MII_LXT971_ID                           ((MII_LXT971_OUI << 10) | (MII_LXT971_MODEL << 4))
#define MII_LXT971_MASK                         0xfffffff0

#define MII_LXT971_DELAY                        1

/* MII LXT971 Regs */
#define MII_LXT971_STATUS_2                     0x11

/* MII LXT971 Status #2 register bits */
#define MII_LXT971_STATUS_2_DUPLEX              0x0200
#define MII_LXT971_STATUS_2_SPEED               0x4000

/* MII BCM5400 Specific */

/* MII BCM5400 ID */
#define MII_BCM5400_OUI                         0x000818
#define MII_BCM5400_MODEL                       0x04
#define MII_BCM5401_MODEL                       0x05
#define MII_BCM5400_REV                         0x01
#define MII_BCM5400_ID                          ((MII_BCM5400_OUI << 10) | (MII_BCM5400_MODEL << 4))
#define MII_BCM5401_ID                          ((MII_BCM5400_OUI << 10) | (MII_BCM5401_MODEL << 4))
#define MII_BCM5400_MASK                        0xfffffff0

#define MII_BCM5400_DELAY                       1

/* MII BCM5400 Regs */

#define MII_BCM5400_1000BASETCONTROL            0x09
/* MII BCM5400 1000-BASET Control register bits */

#define MII_BCM5400_1000BASETCONTROL_FULLDUPLEXCAP      0x0200

#define MII_BCM5400_AUXCONTROL                  0x18

/* MII BCM5400 AUXCONTROL register bits */
#define MII_BCM5400_AUXCONTROL_PWR10BASET       0x0004

#define MII_BCM5400_AUXSTATUS                   0x19

/* MII BCM5400 AUXSTATUS register bits */
#define MII_BCM5400_AUXSTATUS_LINKMODE_MASK     0x0700
#define MII_BCM5400_AUXSTATUS_LINKMODE_BIT      0x0100  


/* MII ST10040 Specific */

/* MII ST10040 ID */
#define MII_ST10040_OUI                         0x1e0400
#define MII_ST10040_MODEL                       0x00
#define MII_ST10040_REV                         0x01
#define MII_ST10040_ID                          ((MII_ST10040_OUI << 10) | (MII_ST10040_MODEL << 4))
#define MII_ST10040_MASK                        0xfffffff0

#define MII_ST10040_DELAY                       1

/* MII ST10040 Regs */
#define MII_ST10040_CHIPST                      0x14

/* MII ST10040 CHIPST register bits */
#define MII_ST10040_CHIPST_LINK                 0x2000
#define MII_ST10040_CHIPST_DUPLEX               0x1000
#define MII_ST10040_CHIPST_SPEED                0x0800
#define MII_ST10040_CHIPST_NEGOTIATION          0x0020


/* MII DP83843 Specific */

/* MII DP83843 ID */
#define MII_DP83843_OUI                         0x080017
#define MII_DP83843_MODEL                       0x01
#define MII_DP83843_REV                         0x00
#define MII_DP83843_ID                          ((MII_DP83843_OUI << 10) | (MII_DP83843_MODEL << 4))
#define MII_DP83843_MASK                        0xfffffff0

#define MII_DP83843_DELAY                       20

/* MII DP83843 PHYSTS register bits */
#define MII_DP83843_PHYSTS                      0x10
#define MII_DP83843_PHYSTS_LINK                 0x0001
#define MII_DP83843_PHYSTS_SPEED10              0x0002
#define MII_DP83843_PHYSTS_DUPLEX               0x0004
#define MII_DP83843_PHYSTS_NEGOTIATION          0x0020


/* MII timeout */
#define MII_DEFAULT_DELAY                       20
#define MII_RESET_TIMEOUT                       100
#define MII_RESET_DELAY                         10

#define MII_LINK_TIMEOUT                        2500
#define MII_LINK_DELAY                          20

/* A few constants needed for miiWriteWord() */
enum {
    kPHYAddr0  = 0x00000000,    //PHY addr is 0
    kPHYAddr1F = 0x0000001F
};

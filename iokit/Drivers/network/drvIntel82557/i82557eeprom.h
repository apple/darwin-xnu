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
 * Copyright (c) 1996 NeXT Software, Inc.
 *
 * i82557eeprom.h
 * - Intel 82557 eeprom access object
 *
 * HISTORY
 *
 * 6-Mar-96	Dieter Siegmund (dieter) at NeXT
 *		Created.
 */

#ifndef _I82557EEPROM_H
#define _I82557EEPROM_H

#include "i82557Inline.h"
#include "i82557HW.h"

#define BITS_IN_SHORT				16
#define MIN_SK_HIGH					20
#define MIN_SK_LOW					20
#define NUM_EEPROM_WORDS			0x40
#define EEPROM_CHECKSUM_VALUE		0xbaba

//-------------------------------------------------------------------------
// Compatibility Byte 0
// 8-bit, word 0x3, low byte
//-------------------------------------------------------------------------
#define EEPROM_C0_MC_100			BIT(1)
#define EEPROM_C0_MC_10				BIT(0)

//-------------------------------------------------------------------------
// Compatibility Byte 1
// 8-bit, word 0x3, high byte
//-------------------------------------------------------------------------
#define EEPROM_C1_OEM				BIT(0)

//-------------------------------------------------------------------------
// Controller Type
// 8-bit, word 0x5, high byte
//-------------------------------------------------------------------------
#define EEPROM_TYPE_82558			2
#define EEPROM_TYPE_82557			1

//-------------------------------------------------------------------------
// Connectors
// 8-bit, word 0x5, low byte
//-------------------------------------------------------------------------
#define EEPROM_CON_MII				BIT(3)
#define EEPROM_CON_AUI				BIT(2)
#define EEPROM_CON_BNC				BIT(1)
#define EEPROM_CON_RJ45				BIT(0)

//-------------------------------------------------------------------------
// PHY Device Record.
// 16-bit, Primary word 0x6, Secondary word 0x7.
//-------------------------------------------------------------------------
#define EEPROM_PHY_10				BIT(15)
#define EEPROM_PHY_VSCR				BIT(14)
#define EEPROM_PHY_DEVICE_SHIFT		8
#define EEPROM_PHY_DEVICE_MASK		CSR_MASK(EEPROM_PHY_DEVICE, 0x3f)
#define EEPROM_PHY_ADDRESS_SHIFT	0
#define EEPROM_PHY_ADDRESS_MASK		CSR_MASK(EEPROM_PHY_ADDRESS, 0xff)

typedef enum {
    PHYDevice_None_e = 0,
    PHYDevice_Intel82553_A_B_step_e,
    PHYDevice_Intel82553_C_step_e,
    PHYDevice_Intel82503_e,
    PHYDevice_NationalDP83840_TX_C_step_e,
    PHYDevice_Seeq80C240_T4_e,
    PHYDevice_Seeq80C24_e,
	PHYDevice_Intel82555_e,
	PHYDevice_MicroLinear_e,
	PHYDevice_Level_One_e,
	PHYDevice_NationalDP82840A_e,
	PHYDevice_ICS1890_e,
    PHYDevice_Last_e
} PHYDevice_t;

static inline char *
PHYDeviceNames(unsigned int i)
{
	char * devices[] = {
		"No PHY device installed",
		"Intel 82553 (PHY 100) A or B step",
		"Intel 82553 (PHY 100) C step",
		"Intel 82503 10Mps",
		"National DP83840 C step 100Base-TX",
		"Seeq 80C240 100Base-T4",
		"Seeq 80C24 10 Mps",
		"Intel 82555 10/100Base-TX PHY",
		"MicroLinear 10Mbps",
		"Level One 10Mbps",
		"National DP83840A",
		"ICS 1890",
		"PHY device unknown"
    };
	if (i > PHYDevice_Last_e)
		i = PHYDevice_Last_e;
	return (devices[i]);
};

#define NUM_PHYS		2
#define PRIMARY_PHY		0
#define SECONDARY_PHY	1
#define NPWA_BYTES		4

typedef struct {
	IOEthernetAddress  addr;
	UInt8			compatibility_0;
	UInt8			compatibility_1;
	UInt16			zero0;
	UInt8			connectors;
	UInt8			controllerType;
#define I82557_CONTROLLER_TYPE	1
#define I82558_CONTROLLER_TYPE	2
	UInt16			phys[NUM_PHYS];
    UInt8			PWANumber[NPWA_BYTES];
    UInt16			zero1[38];
    UInt16			rplConfig[2];
    UInt16			zero5[13];
    UInt16			checkSum;
} EEPROM_t;

static inline
void EEPROMWriteBit(volatile eeprom_control_t * ee_p, bool bit)
{
	if (bit)
		OSSetLE16(ee_p, EEPROM_CONTROL_EEDI);
	else
		OSClearLE16(ee_p, EEPROM_CONTROL_EEDI);

	OSSetLE16(ee_p, EEPROM_CONTROL_EESK);
    IODelay(MIN_SK_HIGH);
    OSClearLE16(ee_p, EEPROM_CONTROL_EESK);
    IODelay(MIN_SK_LOW);
}

static inline
bool EEPROMReadBit(volatile eeprom_control_t * ee_p)
{
    bool bit;
	
	OSSetLE16(ee_p, EEPROM_CONTROL_EESK);
    IODelay(MIN_SK_HIGH);
	bit = (OSReadLE16(ee_p) & EEPROM_CONTROL_EEDO) ? 1 : 0;
	OSClearLE16(ee_p, EEPROM_CONTROL_EESK);
    IODelay(MIN_SK_LOW);
    return (bit);
}

static inline
void EEPROMEnable(volatile eeprom_control_t * ee_p)
{
	OSSetLE16(ee_p, EEPROM_CONTROL_EECS);
    return;
}

static inline
void EEPROMDisable(volatile eeprom_control_t * ee_p)
{
    OSClearLE16(ee_p, EEPROM_CONTROL_EECS);
    return;
}

class i82557eeprom : public OSObject
{
	OSDeclareDefaultStructors(i82557eeprom)

public:
    volatile eeprom_control_t * ee_p;
    int							nbits;
    union {
		UInt16		words[NUM_EEPROM_WORDS];
		EEPROM_t	fields;
    } image;

	static i82557eeprom * withAddress(volatile eeprom_control_t * p);

	bool initWithAddress(volatile eeprom_control_t * p);

	UInt16 readWord(int offset);

	EEPROM_t * getContents();

	void dumpContents();
};

#endif /* !_I82557EEPROM_H */

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
 * i82557eeprom.m
 * - Intel 82557 eeprom access object
 *
 * HISTORY
 *
 * 6-Mar-96	Dieter Siegmund (dieter) at NeXT
 *		Created.
 */

#include <IOKit/network/IOEthernetController.h>
#include "i82557eeprom.h"

#define super OSObject
OSDefineMetaClassAndStructors( i82557eeprom, OSObject )

static __inline__ void
_logAddr(unsigned char * addr)
{
    int i;
    for (i = 0; i < NUM_EN_ADDR_BYTES; i++) {
		IOLog("%s%02x", i > 0 ? ":" : "", addr[i]);
    }
    return;
}

void i82557eeprom::dumpContents()
{
	EEPROM_t * eeprom_p = &image.fields;

    IOLog("The EEPROM contains the following information:\n");

    IOLog("ethernet address: ");
    _logAddr((unsigned char *) &eeprom_p->addr);
    IOLog("\n");

	if (eeprom_p->compatibility_0 & EEPROM_C0_MC_10)
		IOLog("compatibility: MCSETUP workaround required for 10 Mbits\n");
    if (eeprom_p->compatibility_0 & EEPROM_C0_MC_100)
		IOLog("compatibility: MCSETUP workaround required for 100 Mbits\n");

	IOLog("connectors: %s %s %s %s\n", 
		eeprom_p->connectors & EEPROM_CON_RJ45 ? "RJ-45" : "",
		eeprom_p->connectors & EEPROM_CON_BNC ? "BNC" : "",
		eeprom_p->connectors & EEPROM_CON_AUI ? "AUI" : "",
		eeprom_p->connectors & EEPROM_CON_MII ? "MII" : "");

    IOLog("controller type: %d\n", eeprom_p->controllerType);

	for (int i = 0; i < NUM_PHYS; i++) {
		char * s = (i == PRIMARY_PHY) ? "primary" : "secondary";
		UInt16 phy = OSReadLE16(&eeprom_p->phys[i]);

		IOLog("%s PHY: %s\n", s,
			PHYDeviceNames(CSR_VALUE(EEPROM_PHY_DEVICE, phy)));
		if (CSR_VALUE(EEPROM_PHY_DEVICE, phy) != PHYDevice_None_e) {
			if (phy & EEPROM_PHY_VSCR)
				IOLog("%s PHY: vendor specific code required\n", s);
			if (phy & EEPROM_PHY_10)
				IOLog("%s PHY: 10 Mbits only, requires 503 interface\n", s);
			IOLog("%s PHY address: 0x%x\n", s,
				CSR_VALUE(EEPROM_PHY_ADDRESS, phy));
		}
    }

    IOLog("PWA Number: %d %d %d-0%d\n", eeprom_p->PWANumber[1],
	  eeprom_p->PWANumber[0], eeprom_p->PWANumber[3],
	  eeprom_p->PWANumber[2]);

    IOLog("Checksum: 0x%x\n", OSReadLE16(&eeprom_p->checkSum));
#if 0
    if (eeprom_p->checkSum != image.words[NUM_EEPROM_WORDS - 1])
		IOLog("the checksum in the struct doesn't match that in the array\n");
#endif	
	return;
}

i82557eeprom * i82557eeprom::withAddress(volatile eeprom_control_t * p)
{
    i82557eeprom * eeprom = new i82557eeprom;

    if (eeprom && !eeprom->initWithAddress(p)) {
		eeprom->release();
		return 0;
    }
    return eeprom;
}

bool i82557eeprom::initWithAddress(volatile eeprom_control_t * p)
{
    int 	i;
    UInt16	sum;

    if (!super::init())
		return false;

    ee_p = p;

    /*
     * Find out the number of bits in the address by issuing a read to address
     * 0 ie. keep feeding eeprom address bits with value 0, until the eeprom
     * says that the address is complete.  It tells us by setting EEDO to 0 
     * after a write cycle.
     */
    EEPROMEnable(ee_p);
    EEPROMWriteBit(ee_p, 1); /* read */
    EEPROMWriteBit(ee_p, 1);
    EEPROMWriteBit(ee_p, 0);
    nbits = 1;

    do {
		EEPROMWriteBit(ee_p, 0);
		if ((OSReadLE16(ee_p) & EEPROM_CONTROL_EEDO) == 0)
	    	break;
		nbits++;
    } while (nbits <= 32);

	// IOLog("nbits: %d\n", nbits);

    EEPROMDisable(ee_p);
    for (sum = 0, i = 0; i < NUM_EEPROM_WORDS; i++) {
		UInt16 w = readWord(i);
		sum += w;
		OSWriteLE16(&image.words[i], w);
    }
    if (sum != EEPROM_CHECKSUM_VALUE) {
		IOLog("i82557eeprom: checksum %x incorrect\n", sum);
		return false;
    }

    return true;
}

/* READ command bit sequence: 1 1 0 a5a4a3a2a1a0 */
UInt16 i82557eeprom::readWord(int offset)
{
    int 	i;
    UInt16	value;

    EEPROMEnable(ee_p);
    EEPROMWriteBit(ee_p, 1);
    EEPROMWriteBit(ee_p, 1);
    EEPROMWriteBit(ee_p, 0);
    for (i = (nbits - 1); i >= 0; i--) {
		EEPROMWriteBit(ee_p, (offset >> i) & 1);
    }
    value = 0;
    for (i = BITS_IN_SHORT - 1; i >= 0; i--) {
		value |= (EEPROMReadBit(ee_p) << i);
    }
    EEPROMDisable(ee_p);
    return (value);
}

EEPROM_t * i82557eeprom::getContents()
{
    return (&image.fields);
}


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
 * Miscellaneous definitions for the BMac Ethernet controller.
 *
 * HISTORY
 *
 */

#include "BMacEnetRegisters.h"
#include "BMacEnetPrivate.h"
#include <libkern/OSByteOrder.h>

void WriteBigMacRegister( IOPPCAddress ioBaseEnet, u_int32_t reg_offset, u_int16_t data )
{
        OSWriteSwapInt16( ioBaseEnet, reg_offset, data );
	eieio();
}


volatile u_int16_t ReadBigMacRegister( IOPPCAddress ioBaseEnet, u_int32_t reg_offset )
{
        return OSReadSwapInt16( ioBaseEnet, reg_offset ); 
}

/*
 * Procedure for reading EEPROM 
 */
#define kSROMAddressLength		5
#define kDataInOn				0x0008
#define kDataInOff				0x0000
#define kClk					0x0002
#define kChipSelect				0x0001
#define kSDIShiftCount			3
#define kSD0ShiftCount			2
#define	kDelayValue				1000	// number of microseconds

#define kSROMStartOffset		10		// this is in words
#define kSROMReadCount			3		// number of words to read from SROM 

static unsigned char clock_out_bit(IOPPCAddress base)
{
    u_int16_t         data;
    u_int16_t         val;

    WriteBigMacRegister(base, kSROMCSR, kChipSelect | kClk);
    IODelay(kDelayValue);
    
    data = ReadBigMacRegister(base, kSROMCSR);
    IODelay(kDelayValue);
    val = (data >> kSD0ShiftCount) & 1;

    WriteBigMacRegister(base, kSROMCSR, kChipSelect);
    IODelay(kDelayValue);
    
    return val;
}

static void clock_in_bit(IOPPCAddress base, unsigned int val)
{
    u_int16_t		data;    

    if (val != 0 && val != 1)	
    {
    	IOLog("bogus data in clock_in_bit\n");
	return;
    }
    
    data = (val << kSDIShiftCount);
    WriteBigMacRegister(base, kSROMCSR, data | kChipSelect  );
    IODelay(kDelayValue);
    
    WriteBigMacRegister(base, kSROMCSR, data | kChipSelect | kClk );
    IODelay(kDelayValue);

    WriteBigMacRegister(base, kSROMCSR, data | kChipSelect);
    IODelay(kDelayValue);
}

void reset_and_select_srom(IOPPCAddress base)
{
    /* first reset */
    WriteBigMacRegister(base, kSROMCSR, 0);
    IODelay(kDelayValue);
    
    /* send it the read command (110) */
    clock_in_bit(base, 1);
    clock_in_bit(base, 1);
    clock_in_bit(base, 0);
}

unsigned short read_srom(IOPPCAddress base, unsigned int addr,
	unsigned int addr_len)
{
    unsigned short data, val;
    unsigned int i;
    
    /* send out the address we want to read from */
    for (i = 0; i < addr_len; i++)	{
	val = addr >> (addr_len-i-1);
	clock_in_bit(base, val & 1);
    }
    
    /* Now read in the 16-bit data */
    data = 0;
    for (i = 0; i < 16; i++)	{
	val = clock_out_bit(base);
	data <<= 1;
	data |= val;
    }
    WriteBigMacRegister(base, kSROMCSR, 0);
    
    return data;
}

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
 * MII/PHY (National Semiconductor DP83840/DP83840A) support methods.
 * It is general enough to work with most MII/PHYs.
 *
 * HISTORY
 *
 */

#include "BMacEnet.h"
#include "BMacEnetPrivate.h"

/*
 * Read from MII/PHY registers.
 */
bool BMacEnet::miiReadWord(unsigned short *dataPtr, unsigned short reg,
		 unsigned char phy)
{
    int					i;
    miiFrameUnion 		frame;
    unsigned short		phyreg;
    bool				ret = true;

    do
    {
        // Write preamble
        //
        miiWrite(MII_FRAME_PREAMBLE, MII_FRAME_SIZE);

        if ( miiCheckZeroBit() == true ) 
        {
//			IOLog("Ethernet(BMac): MII not floating before read\n\r");
			ret = false;
            break;
        }

        // Prepare command frame
        //
        frame.data = MII_FRAME_READ;
        frame.bit.regad = reg;
        frame.bit.phyad = phy;
	
        // write ST, OP, PHYAD, REGAD in the MII command frame
        //
		miiWrite(frame.data, 14);
	
        // Hi-Z state
        // Make sure the PHY generated a zero bit after the 2nd Hi-Z bit
        //

		miiOutThreeState();

        if (miiCheckZeroBit() == false) 
        {
//			IOLog("Ethernet(BMac): MII not driven after turnaround\n\r");
			ret = false;
            break;
        }

        // read 16-bit data
        //
        phyreg = 0;
        for (i = 0; i < 16; i++) 
        {
			phyreg = miiReadBit() | (phyreg << 1);
        }
        if (dataPtr)
	    *dataPtr = phyreg;

        // Hi-Z state
		miiOutThreeState();
	
        if (miiCheckZeroBit() == true) 
        {
//			IOLog("Ethernet(BMac): MII not floating after read\n\r");
			ret = false;
            break;
        }
    }
    while ( 0 );

    return ret;
}

/*
 * Write to MII/PHY registers.
 */
bool BMacEnet::miiWriteWord(unsigned short data, unsigned short reg,
		 unsigned char phy)
{
    miiFrameUnion 		frame;
    bool				ret = true;
	
    do
    {
        // Write preamble
        //
		miiWrite(MII_FRAME_PREAMBLE, MII_FRAME_SIZE);

        if (miiCheckZeroBit() == true) 
        {
			ret = false;
            break;
        }

        // Prepare command frame
        //
        frame.data = MII_FRAME_WRITE;
        frame.bit.regad = reg;
        frame.bit.phyad = phy;
        frame.bit.data  = data;
	
        // Write command frame
        //
		miiWrite(frame.data, MII_FRAME_SIZE);

        // Hi-Z state
		miiOutThreeState();

        if (miiCheckZeroBit() == true) 
        {
			ret = false;
            break;
        }
    }
    while ( 0 );

    return ret;
}

/* 
 * Write 'dataSize' number of bits to the MII management interface,
 * starting with the most significant bit of 'miiData'.
 *
 */
void BMacEnet::miiWrite(unsigned int miiData, unsigned int dataSize)
{
    int i;
    u_int16_t	regValue;
	
    regValue = kMIFCSR_DataOutEnable;
		
    for (i = dataSize; i > 0; i--) 
    {
		int bit = ((miiData & 0x80000000) ? kMIFCSR_DataOut : 0);
		
		regValue &= ~(kMIFCSR_Clock | kMIFCSR_DataOut) ;
		regValue |=  bit;
		WriteBigMacRegister(ioBaseEnet, kMIFCSR, regValue);
		IODelay(phyMIIDelay);
		
		regValue |= kMIFCSR_Clock;
		WriteBigMacRegister(ioBaseEnet, kMIFCSR, regValue );
		IODelay(phyMIIDelay);

		miiData = miiData << 1;
    }
}

/*
 * Read one bit from the MII management interface.
 */
int BMacEnet::miiReadBit()
{
    u_int16_t		regValue;
    u_int16_t		regValueRead;

    regValue = 0;	

    WriteBigMacRegister(ioBaseEnet, kMIFCSR, regValue);
    IODelay(phyMIIDelay);

    regValue |= kMIFCSR_Clock;
    WriteBigMacRegister(ioBaseEnet, kMIFCSR, regValue);
    IODelay(phyMIIDelay);
	
    regValueRead = ReadBigMacRegister(ioBaseEnet, kMIFCSR);
    IODelay(phyMIIDelay);	// delay next invocation of this routine
	
    return ( (regValueRead & kMIFCSR_DataIn) ? 1 : 0 );
}

/*
 * Read the zero bit on the second clock of the turn-around (TA)
 * when reading a PHY register.
 */
bool BMacEnet::miiCheckZeroBit()
{
    u_int16_t	regValue;
	
    regValue = ReadBigMacRegister(ioBaseEnet, kMIFCSR);
    
    return (((regValue & kMIFCSR_DataIn) == 0) ? true : false );
}

/*
 * Tri-state the STA's MDIO pin.
 */
void BMacEnet::miiOutThreeState()
{
    u_int16_t		regValue;

    regValue = 0;	
    WriteBigMacRegister(ioBaseEnet, kMIFCSR, regValue);
    IODelay(phyMIIDelay);
	
    regValue |= kMIFCSR_Clock;
    WriteBigMacRegister(ioBaseEnet, kMIFCSR, regValue);
    IODelay(phyMIIDelay);
}

bool BMacEnet::miiResetPHY(unsigned char phy)
{
    int i = MII_RESET_TIMEOUT;
    unsigned short mii_control;

    // Set the reset bit
    //
	miiWriteWord(MII_CONTROL_RESET, MII_CONTROL, phy);
	
    IOSleep(MII_RESET_DELAY);

    // Wait till reset process is complete (MII_CONTROL_RESET returns to zero)
    //
    while (i > 0) 
    {
		if (miiReadWord(&mii_control, MII_CONTROL, phy) == false)
			return false;

		if (!(mii_control & MII_CONTROL_RESET))
        {
            miiReadWord(&mii_control, MII_CONTROL, phy);
            mii_control &= ~MII_CONTROL_ISOLATE;
            miiWriteWord(mii_control, MII_CONTROL, phy);
            return true;
        }

		IOSleep(MII_RESET_DELAY);
		i -= MII_RESET_DELAY;
    }
    return false;
}

bool BMacEnet::miiWaitForLink(unsigned char phy)
{
    int i = MII_LINK_TIMEOUT;
    unsigned short mii_status;
	
    while (i > 0) 
    {
		if (miiReadWord(&mii_status, MII_STATUS, phy) == false)
			return false;
		
		if (mii_status & MII_STATUS_LINK_STATUS)
			return true;
		
		IOSleep(MII_LINK_DELAY);
		i -= MII_LINK_DELAY;
    }
    return false;
}

bool BMacEnet::miiWaitForAutoNegotiation(unsigned char phy)
{
    int i = MII_LINK_TIMEOUT;
    unsigned short mii_status;
	
    while (i > 0) 
    {
		if (miiReadWord(&mii_status, MII_STATUS, phy) == false)
			return false;
		
		if (mii_status & MII_STATUS_NEGOTIATION_COMPLETE)
			return true;
		
		IOSleep(MII_LINK_DELAY);
		i -= MII_LINK_DELAY;
    }
    return false;
}

void BMacEnet::miiRestartAutoNegotiation(unsigned char phy)
{
    unsigned short mii_control;

	miiReadWord(&mii_control, MII_CONTROL, phy);
    mii_control |= MII_CONTROL_RESTART_NEGOTIATION;
	miiWriteWord(mii_control, MII_CONTROL, phy);

    /*
     * If the system is not connected to the network, then auto-negotiation
     * never completes and we hang in this loop!
     */
#if 0
    while (1) 
    {
		miiReadWord(&mii_control, MII_CONTROL, phy);
		if ((mii_control & MII_CONTROL_RESTART_NEGOTIATION) == 0)
			break;
    }
#endif
}

/*
 * Find the first PHY device on the MII interface.
 *
 * Return
 *	true		PHY found 
 *  false		PHY not found
 */
bool BMacEnet::miiFindPHY(unsigned char *phy)
{
    int i;
	
    *phy = 0xff;

    // The first two PHY registers are required.
    //
    for (i = 0; i < MII_MAX_PHY; i++) 
    {
	if (miiReadWord(NULL, MII_STATUS, i) &&
		miiReadWord(NULL, MII_CONTROL, i))
		break;
    }
	
    if (i >= MII_MAX_PHY)
		return false;

    *phy = i;

    return true;
}

/*
 *
 *
 */
bool BMacEnet::miiInitializePHY(unsigned char phy)
{
    u_int16_t		phyWord; 

    // Clear then set the enable auto-negotiation bit
    //
	miiReadWord(&phyWord, MII_CONTROL, phy);
    phyWord &= ~MII_CONTROL_AUTONEGOTIATION;
	miiWriteWord(phyWord, MII_CONTROL, phy);

    // Advertise 10/100 Half/Full duplex capable to link partner
    //
    miiReadWord(&phyWord, MII_ADVERTISEMENT, phy);
    phyWord |= (MII_ANAR_100BASETX_FD | MII_ANAR_100BASETX |
                MII_ANAR_10BASET_FD   | MII_ANAR_10BASET );
    miiWriteWord(phyWord, MII_ADVERTISEMENT, phy);

    // Set enable auto-negotiation bit
    //
	miiReadWord(&phyWord, MII_CONTROL, phy);
    phyWord |= MII_CONTROL_AUTONEGOTIATION;
	miiWriteWord(phyWord, MII_CONTROL, phy);

	miiRestartAutoNegotiation(phy);

    return true;
}        


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


#include "UniNEnetPrivate.h"

#define super IOEthernetController

// Set EXTRANEOUS_PM_DELAYS to 1 to enable absurdly long delays.
//
#define EXTRANEOUS_PM_DELAYS  0

// --------------------------------------------------------------------------
// Method: registerWithPolicyMaker
//
// Purpose:
//   initialize the driver for power managment and register ourselves with
//   policy-maker
IOReturn
UniNEnet::registerWithPolicyMaker(IOService * policyMaker)
{

/******
From iokit/IOKit/pwr_mgt/IOPMpowerState.h 
struct IOPMPowerState
{
unsigned long    version;        // version number of this struct
IOPMPowerFlags   capabilityFlags;    // bits that describe the capability 
IOPMPowerFlags   outputPowerCharacter;    // description (to power domain children) 
IOPMPowerFlags   inputPowerRequirement;    // description (to power domain parent)
unsigned long    staticPower;    // average consumption in milliwatts
unsigned long    unbudgetedPower;    // additional consumption from separate power supply (mw)
unsigned long    powerToAttain;    // additional power to attain this state from next lower state (in mw)
unsigned long    timeToAttain;    // (in microseconds)
unsigned long    settleUpTime;    // (microseconds)
unsigned long    timeToLower;    //  (in microseconds)
unsigned long    settleDownTime;    // (microseconds)
unsigned long    powerDomainBudget;    // power in mw a domain in this state can deliver to its children
};

*******/

#define num_of_power_states 2

static IOPMPowerState ourPowerStates[num_of_power_states] = {
  {1, 0,0,0,0,0,0,0,0,0,0,0},
  {1,IOPMDeviceUsable | IOPMMaxPerformance, IOPMPowerOn, IOPMPowerOn, 50,0,0, 
     kUniNsettle_time, kUniNsettle_time, kUniNsettle_time, kUniNsettle_time,0}
  // 50 milliwatts above is just a guess right now, since the ethernet is part of Uni-N
};

    currentPowerState = kMaxUniNEnetPowerState;	
    return policyMaker->registerPowerDriver(this, ourPowerStates, num_of_power_states);
}

// Method: maxCapabilityForDomainState
//
// Purpose:
//        returns the maximun state of card power, which would be
//        power on without any attempt to power manager.
unsigned long
UniNEnet::maxCapabilityForDomainState(IOPMPowerFlags domainState)
{
   if( domainState &  IOPMPowerOn )
       return kMaxUniNEnetPowerState;  //In reality, it's just array element 1 for Uni-N
   else
       return 0;
}

// Method: initialPowerStateForDomainState
//
// Purpose:
// The power domain may be changing state.  If power is on in the new
// state, that will not affect our state at all.  If domain power is off,
// we can attain only our lowest state, which is off.

unsigned long
UniNEnet::initialPowerStateForDomainState( IOPMPowerFlags domainState )
{
   if( domainState &  IOPMPowerOn )
       return currentPowerState;
   else
       return 0;
}


// Method: powerStateForDomainState
//
// Purpose:
//         The power domain may be changing state.  If power is on in the new
// state, that will not affect our state at all.  If domain power is off,
// we can attain only our lowest state, which is off.
unsigned long
UniNEnet::powerStateForDomainState(IOPMPowerFlags domainState )
{
    if( domainState &  IOPMPowerOn )
        return currentPowerState;
   else
        return 0;
}

// Method: setPowerState
//
IOReturn UniNEnet::setPowerState(unsigned long powerStateOrdinal,
                                 IOService *   whatDevice)
{
    volatile UInt32 clockReg;

    // Do not do anything if the state is invalid.
    if (powerStateOrdinal >= num_of_power_states)
        return IOPMNoSuchState;

    if (powerStateOrdinal == currentPowerState)
        return IOPMAckImplied;    //no change required

    // otherwise remember the new state:
    currentPowerState = powerStateOrdinal;

    IOLog("UniNEthernet::setPowerState(%d, 0x%08lx)\n",
          (int) powerStateOrdinal,
          (UInt32) whatDevice);

    switch ( currentPowerState )
    {
        case 0:        // Ethernet is off

            // Shutdown the hardware unconditionally.
            // doDisable(this);

            // Turn off PHY before turning off MAC
            // MII_CONTROL_POWERDOWN ?  no, it is read-only for Broadcom 5201
            // PHY, but 5400 is R/W
            stopPHYChip(false);  //In this file
	    
            // Now turn off ethernet clock in Uni-N
	    callPlatformFunction("EnableUniNEthernetClock", true,
				 (void *)false, 0, 0, 0);
            break;

        case kMaxUniNEnetPowerState: // 1 = max power state, Ethernet is on    

            // Now turn on ethernet clock in Uni-N
	    callPlatformFunction("EnableUniNEthernetClock", true,
				 (void *)true, 0, 0, 0);

#if EXTRANEOUS_PM_DELAYS
            IODelay(MII_DEFAULT_DELAY * 1000); // 20 milliseconds
#endif

            // Bring up PHY then MAC.
            startPHYChip();
            // doEnable(this);

            break;

        default:
            // This is illegal, only 0 and 1 are allowed for
            // UniN ethernet for now
            break;
    }

    return IOPMAckImplied;
}

// This method sets up the PHY registers for low power.
// Copied from stopEthernetController() in OS9.
// The setupWOL value is not really implemented systemwide yet
void
UniNEnet::stopPHYChip(bool setupWOL)
{
    UInt32    val32;
    UInt16    i, val16;

    if (phyBCMType == 0) return;

    //IOLog("UniN on stop phy = %d\n", phyBCMType);

    if (setupWOL == false)
    {
        //disabling MIF interrupts on the 5201 is explicit
        if (phyBCMType == 5201)
        {
            miiWriteWord(0x0000, MII_BCM5201_INTERRUPT, kPHYAddr0);
            // 0 or 0x1f or phyId?  miiFindPHY returns any integer
        }
    }

    //Drive the MDIO line high to prevent immediate wakeup
	val32 = READ_REGISTER( MIFConfiguration );
	WRITE_REGISTER( MIFConfiguration, val32 & kMIFConfiguration_Poll_Enable );

    // 5th ADDR in Broadcom PHY docs
    miiReadWord( &val16, MII_LINKPARTNER, kPHYAddr0 );  

    // don't know why OS9 writes it back unchanged
    miiWriteWord( val16, MII_LINKPARTNER, kPHYAddr0 );  

    /* Put the MDIO pins into a benign state. Note that the management regs
       in the PHY will be inaccessible. This is to guarantee max power savings
       on Powerbooks and to eliminate damage to Broadcom PHYs.
     */
    //bit bang mode
	WRITE_REGISTER( MIFConfiguration, kMIFConfiguration_BB_Mode );

	WRITE_REGISTER( MIFBitBangClock,		0x0000 );
	WRITE_REGISTER( MIFBitBangData,			0x0000 );
	WRITE_REGISTER( MIFBitBangOutputEnable,	0x0000 );
	WRITE_REGISTER( XIFConfiguration,		kXIFConfiguration_GMIIMODE
												  | kXIFConfiguration_MII_Int_Loopback );

    if (setupWOL)
    {
        //For multicast filtering these bits must be enabled
		WRITE_REGISTER( RxMACConfiguration,
						   kRxMACConfiguration_Hash_Filter_Enable
						 | kRxMACConfiguration_Rx_Mac_Enable );
        // set kpfRxMACEnabled in OS9, but I don't see matching OS X flag
    }
    else
    {
		WRITE_REGISTER( RxMACConfiguration, 0 );
        // un-set kpfRxMACEnabled in OS9, but I don't see matching OS X flag
    }

	WRITE_REGISTER( TxMACConfiguration, 0 );
	WRITE_REGISTER( XIFConfiguration,   0 );

#if 0
    // Disable interrupt source on the controller.
    // Already disabled from earlier resetAndEnable(false) call.
	WRITE_REGISTER( InterruptMask, kInterruptMask_None ); // all FF
#endif

	WRITE_REGISTER( TxConfiguration, 0 );
	WRITE_REGISTER( RxConfiguration, 0 );

    if (!setupWOL)
    {
        // this doesn't power down stuff, but if we don't hit it then we can't
        // superisolate the transceiver
		WRITE_REGISTER( SoftwareReset, kSoftwareReset_TX | kSoftwareReset_RX );

        // kSoftwareReset_RSTOUT too???
        i = 0;
        do {
//          IODelay(MII_RESET_DELAY * 1000);  // 10 milliseconds
            IODelay(10);
            if (i++ >= 100)
            {
                IOLog("UniNEnet timeout on SW reset\n");
                break;
            }
			val32 = READ_REGISTER( SoftwareReset );
		} while ( (val32 & (kSoftwareReset_TX | kSoftwareReset_RX)) != 0 );

		WRITE_REGISTER( TxMACSoftwareResetCommand, kTxMACSoftwareResetCommand_Reset );
		WRITE_REGISTER( RxMACSoftwareResetCommand, kRxMACSoftwareResetCommand_Reset );

        //This is what actually turns off the LINK LED
        if (phyBCMType == 5400)
        {
#if 0
            // The 5400 has read/write privilege on this bit,
            // but 5201 is read-only.
            miiWriteWord( MII_CONTROL_POWERDOWN, MII_CONTROL, kPHYAddr0);
#endif
        }
        else  // Only other possibility is Broadcom 5201 (or 5202?)
        {
#if 0
            miiReadWord( &val16, MII_BCM5201_AUXMODE2, kPHYAddr0 );
            miiWriteWord( val16 & ~MII_BCM5201_AUXMODE2_LOWPOWER,
                          MII_BCM5201_AUXMODE2, kPHYAddr0 );
#endif

            miiWriteWord( MII_BCM5201_MULTIPHY_SUPERISOLATE,
                          MII_BCM5201_MULTIPHY,
                          kPHYAddr0 );
        }
    } // end of none-WOL case
}

//start the PHY
void
UniNEnet::startPHYChip()
{
    UInt32    val32;
    UInt16    val16;

    // if (netifClient)  //MacOS 9 uses numClients == 1?
    {
    //IOLog("UniN on restart phy = %d\n", phyBCMType);

	val32 = READ_REGISTER( TxConfiguration );
	WRITE_REGISTER( TxConfiguration, val32 | kTxConfiguration_Tx_DMA_Enable );

	val32 = READ_REGISTER( RxConfiguration );
	WRITE_REGISTER( RxConfiguration, val32 | kRxConfiguration_Rx_DMA_Enable );

	val32 = READ_REGISTER( TxMACConfiguration );
	WRITE_REGISTER( TxMACConfiguration, val32 | kTxMACConfiguration_TxMac_Enable );

	val32 = READ_REGISTER( RxMACConfiguration );
	WRITE_REGISTER( RxMACConfiguration,
							val32 | kRxMACConfiguration_Rx_Mac_Enable
								  | kRxMACConfiguration_Hash_Filter_Enable );

    // Set flag to RxMACEnabled somewhere??

    /* These registers are only for the Broadcom 5201.
       We write the auto low power mode bit here because if we do it earlier
       and there is no link then the xcvr registers become unclocked and
       unable to be written
     */
    if (phyBCMType == 5201)
    {
        // Ask Enrique why the following 2 lines are not necessary in OS 9.
        // These 2 lines should take the PHY out of superisolate mode.  All
        // MII inputs are ignored until the PHY is out of isolate mode
        miiReadWord( &val16, MII_BCM5201_MULTIPHY, kPHYAddr0 );
        miiWriteWord( val16 & ~MII_BCM5201_MULTIPHY_SUPERISOLATE,
                      MII_BCM5201_MULTIPHY, kPHYAddr0 );

#if 0
        // Automatically go into low power mode if no link
        miiReadWord( &val16, MII_BCM5201_AUXMODE2, kPHYAddr0 );
        miiWriteWord( val16 | MII_BCM5201_AUXMODE2_LOWPOWER,
                      MII_BCM5201_AUXMODE2, kPHYAddr0 );
#endif

#if EXTRANEOUS_PM_DELAYS
        IODelay(MII_DEFAULT_DELAY * 1000); // 20 milliseconds
#endif
    }

    // WARNING... this code is untested on gigabit ethernet (5400), there
    // should be a case to handle it for MII_CONTROL_POWERDOWN bit here,
    // unless it is unnecessary after a hardware reset

		WRITE_REGISTER( RxKick, RX_RING_LENGTH - 4 );
    }
}

/*-------------------------------------------------------------------------
 * Assert the reset pin on the PHY momentarily to initialize it, and also
 * to bring the PHY out of low-power mode.
 *
 *-------------------------------------------------------------------------*/

bool UniNEnet::resetPHYChip()
{
    IOReturn result;

    result = keyLargo->callPlatformFunction(keyLargo_resetUniNEthernetPhy, false, 0, 0, 0, 0);
    if (result != kIOReturnSuccess) return false;

    return true;
}

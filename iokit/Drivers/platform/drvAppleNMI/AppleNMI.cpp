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
 * Copyright (c) 1998-9 Apple Computer, Inc.  All rights reserved.
 *
 *  DRI: Josh de Cesare
 *
 */

#include <IOKit/IOTypes.h>
#include <IOKit/IOLib.h>
#include <IOKit/pwr_mgt/RootDomain.h>

#include <IOKit/platform/AppleNMI.h>

extern "C" {
#include <pexpert/pexpert.h>
}

bool RootRegistered( OSObject * us, void *, IOService * yourDevice );

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super IOService

OSDefineMetaClassAndStructors(AppleNMI, IOService);
OSMetaClassDefineReservedUnused(AppleNMI,  0);
OSMetaClassDefineReservedUnused(AppleNMI,  1);
OSMetaClassDefineReservedUnused(AppleNMI,  2);
OSMetaClassDefineReservedUnused(AppleNMI,  3);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool AppleNMI::start(IOService *provider)
{
  if (!super::init()) return false;

  enable_debugger = FALSE;
  mask_NMI = FALSE;

  if (provider->getProperty("enable_debugger"))
      enable_debugger = TRUE;  // Flag to automatically jump to debugger at NMI press

  if (provider->getProperty("mask_NMI"))
      mask_NMI = TRUE;         // Flag to mask/unmask NMI @ sleep/wake

  // Get notified when Root Domain registers
  addNotification( gIOPublishNotification, serviceMatching("IOPMrootDomain"), (IOServiceNotificationHandler)RootRegistered, this, 0 );

  // Register the interrupt.
  provider->registerInterrupt(0, this, (IOInterruptAction) &AppleNMI::handleInterrupt, 0);
  provider->enableInterrupt(0);

  return true;
}

// **********************************************************************************
// The Root Power Domain has registered, so now we register as an interested driver
// so we know when the system is going to sleep or wake
// **********************************************************************************
bool RootRegistered( OSObject * us, void *, IOService * yourDevice )
{
    if ( yourDevice != NULL ) {
        ((AppleNMI *)us)->rootDomain = yourDevice;
        ((IOPMrootDomain *)yourDevice)->registerInterestedDriver((IOService *) us);
    }
    
    return true;
}

IOReturn AppleNMI::initNMI(IOInterruptController *parentController, OSData *parentSource)
{
  // Allocate the IOInterruptSource so this can act like a nub.
  _interruptSources = (IOInterruptSource *)IOMalloc(sizeof(IOInterruptSource));
  if (_interruptSources == 0) return kIOReturnNoMemory;
  _numInterruptSources = 1;
  
  // Set up the IOInterruptSource to point at this.
  _interruptSources[0].interruptController = parentController;
  _interruptSources[0].vectorData = parentSource;
  
  // call start using itself as its provider.
  if (!start(this)) return kIOReturnError;
  
  return kIOReturnSuccess;
}

IOReturn AppleNMI::handleInterrupt(void * /*refCon*/, IOService * /*nub*/, int /*source*/)
{
    if(enable_debugger == TRUE)
        Debugger("NMI");                         // This is a direct call to the Debugger
    else
        PE_enter_debugger("NMI");                // This is a indirect call the Debugger that is dependent on the debug flag

    return kIOReturnSuccess;
}

//*********************************************************************************
// powerStateWillChangeTo
//
// We are notified here of power changes in the root domain.  The root domain
// cannot actually turn itself on and off, but it notifies us anyway.
//*********************************************************************************
IOReturn AppleNMI::powerStateWillChangeTo ( IOPMPowerFlags theFlags, unsigned long, IOService*)
{
    volatile unsigned long *nmiIntSourceAddr;
    unsigned long nmiIntSource;

    if (mask_NMI == TRUE)
    {
        if ( ! (theFlags & IOPMPowerOn) )
        {
            IOLog("AppleNMI mask NMI\n");

            // Mask NMI and change from edge to level whilst sleeping (copied directly from OS9 code)
            nmiIntSourceAddr = (volatile unsigned long *)kExtInt9_NMIIntSource;
            nmiIntSource = *nmiIntSourceAddr;
            nmiIntSource |= kNMIIntLevelMask;
            *nmiIntSourceAddr = nmiIntSource;
            eieio();
            nmiIntSource |= kNMIIntMask;
            *nmiIntSourceAddr = nmiIntSource;
            eieio();
        }
        else
        {
            IOLog("AppleNMI unmask NMI\n");

            // Unmask NMI and change back to edge (copied directly from OS9 code)
            nmiIntSourceAddr = (volatile unsigned long *)kExtInt9_NMIIntSource;
            nmiIntSource = *nmiIntSourceAddr;
            nmiIntSource &= ~kNMIIntLevelMask;
            *nmiIntSourceAddr = nmiIntSource;
            eieio();
            nmiIntSource &= ~kNMIIntMask;
            *nmiIntSourceAddr = nmiIntSource;
            eieio();
        }
    }

    return IOPMAckImplied;
}

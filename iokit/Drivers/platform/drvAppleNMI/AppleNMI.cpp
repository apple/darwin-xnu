/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
/*
 * Copyright (c) 1998-2003 Apple Computer, Inc.  All rights reserved.
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
  if (!super::start(provider)) return false;

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
            // Mask NMI and change from edge to level whilst sleeping (copied directly from OS9 code)
            nmiIntSourceAddr = (volatile unsigned long *)kExtInt9_NMIIntSource;
            nmiIntSource = ml_phys_read(nmiIntSourceAddr);
            nmiIntSource |= kNMIIntLevelMask;
            ml_phys_write(nmiIntSourceAddr, nmiIntSource);
            eieio();
            nmiIntSource |= kNMIIntMask;
            ml_phys_write(nmiIntSourceAddr, nmiIntSource);
            eieio();
        }
        else
        {
            // Unmask NMI and change back to edge (copied directly from OS9 code)
            nmiIntSourceAddr = (volatile unsigned long *)kExtInt9_NMIIntSource;
            nmiIntSource = ml_phys_read(nmiIntSourceAddr);
            nmiIntSource &= ~kNMIIntLevelMask;
            ml_phys_write(nmiIntSourceAddr, nmiIntSource);
            eieio();
            nmiIntSource &= ~kNMIIntMask;
            ml_phys_write(nmiIntSourceAddr, nmiIntSource);
            eieio();
        }
    }
    
    return IOPMAckImplied;
}

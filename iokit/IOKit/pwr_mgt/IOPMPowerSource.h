/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
#include <libkern/c++/OSObject.h>
#include <IOKit/IOTypes.h>
#include <IOKit/IOReturn.h>
#include "IOPM.h"

class ApplePMU;

const unsigned long kSecondsPerHour = (60*60);
const unsigned long kTenMinutesInSeconds = (10 * 60);

// our battery (power source) object

class IOPMPowerSource : public OSObject
{
    OSDeclareDefaultStructors(IOPMPowerSource)

 protected:

    UInt32             bFlags;
    UInt32             bTimeRemaining;
    UInt16             bCurCapacity;
    UInt16             bMaxCapacity;
    SInt16             bCurrent;
    UInt16             bVoltage;
    UInt16             bBatteryIndex;

 public:

    IOPMPowerSource * nextInList;

    bool               init (unsigned short whichBatteryIndex);
    unsigned long      capacityPercentRemaining (void);
    bool               atWarnLevel (void);
    bool               depleted (void);

    // accessors

    bool               isInstalled (void);
    bool               isCharging (void);
    bool               acConnected (void);
    unsigned long      timeRemaining (void);
    unsigned long      maxCapacity (void);
    unsigned long      curCapacity (void);
    long               currentDrawn (void);
    unsigned long      voltage (void);

    // calculations

    // function updateStatus is called whenever the system needs
    // to obtain the latest power source state...must be overridden
    // by subclasses.
    virtual void updateStatus (void);
};




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

#ifndef _IOKIT_IOSERVICEPM_H
#define _IOKIT_IOSERVICEPM_H

#include <libkern/c++/OSObject.h>
#include <IOKit/IOLocks.h>
#include <IOKit/pwr_mgt/IOPM.h>

extern "C" {
#include <kern/thread_call.h>
}

class IOService;
class IOServicePM;
class IOPowerConnection;
class IOPMinformee;
class IOPMinformeeList;
class IOWorkLoop;
class IOCommandGate;
class IOTimerEventSource;
class IOPlatformExpert;
class IOPMWorkQueue;
class IOPMRequest;
class IOPMRequestQueue;
struct changeNoteItem;

/* DEPRECATED */
/*! @class IOPMprot
    @abstract Protected power management instance variables for IOService objects.
    @availability Mac OS X version 10.0. Deprecated in version 10.5.
    @discussion IOPMprot is deprecated. Do not use it in any new code.
    
    Call IOService::getPowerState to query the current power state rather than access myCurrentState.
*/
class IOPMprot : public OSObject
{
    friend class IOService;
    
    OSDeclareDefaultStructors(IOPMprot)

public:
    /*! @var ourName
        From getName(), used in logging.
    */
    const char *            ourName;

    /*! @var thePlatform
        From getPlatform, used in logging and registering.
    */
    IOPlatformExpert *      thePlatform;

    /*! @var theNumberOfPowerStates
        The number of states in the array.
    */
    unsigned long           theNumberOfPowerStates;

    /*! @var thePowerStates
        The array.
    */
    IOPMPowerState          thePowerStates[IOPMMaxPowerStates];

    /*! @var theControllingDriver
        Points to the controlling driver.
    */
    IOService *             theControllingDriver;

    /*! @var aggressiveness
        Current value of power management aggressiveness.
    */
    unsigned long           aggressiveness;

    /*! @var current_aggressiveness_values
        Array of aggressiveness values.
    */
    unsigned long           current_aggressiveness_values [kMaxType+1];

    /*! @var current_aggressiveness_validity
        True for values that are currently valid.
    */
    bool                    current_aggressiveness_valid [kMaxType+1];

    /*! @var myCurrentState
        The ordinal of our current power state.
    */
    unsigned long           myCurrentState;
};

#endif /* !_IOKIT_IOSERVICEPM_H */

/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved.
 *
 */

#include <IOKit/assert.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include "RootDomainUserClient.h"
#include <IOKit/pwr_mgt/IOPMLibDefs.h>

#define super IOUserClient

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSDefineMetaClassAndStructors(RootDomainUserClient, IOUserClient)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool RootDomainUserClient::start( IOService * provider )
{
    assert(OSDynamicCast(IOPMrootDomain, provider));
    if(!super::start(provider))
        return false;
    fOwner = (IOPMrootDomain *)provider;


    return true;
}


IOReturn RootDomainUserClient::clientClose( void )
{
    detach(fOwner);
    return kIOReturnSuccess;
}

IOExternalMethod *
RootDomainUserClient::getTargetAndMethodForIndex( IOService ** targetP, UInt32 index )
{
    static IOExternalMethod sMethods[] = {
        { // kPMSetAggressiveness, 0
            0, (IOMethod)&IOPMrootDomain::setAggressiveness, kIOUCScalarIScalarO, 2, 0
        },
        { // kPMGetAggressiveness, 1
            0, (IOMethod)&IOPMrootDomain::getAggressiveness, kIOUCScalarIScalarO, 1, 1
        },
        { // kPMSleepSystem, 2
            0, (IOMethod)&IOPMrootDomain::sleepSystem, kIOUCScalarIScalarO, 0, 0
        },
        { // kPMAllowPowerChange, 3
            0, (IOMethod)&IOPMrootDomain::allowPowerChange, kIOUCScalarIScalarO, 1, 0
        },
        { // kPMCancelPowerChange, 4
            0, (IOMethod)&IOPMrootDomain::cancelPowerChange, kIOUCScalarIScalarO, 1, 0
        },
        { // kPMShutdownSystem, 5
            0, (IOMethod)&IOPMrootDomain::shutdownSystem, kIOUCScalarIScalarO, 0, 0
        },
        { // kPMRestartSystem, 6
            0, (IOMethod)&IOPMrootDomain::restartSystem, kIOUCScalarIScalarO, 0, 0
        },
        { // kPMSetPreventative, 7
            1, (IOMethod) &RootDomainUserClient::setPreventative, kIOUCScalarIScalarO, 2, 0
        },
    };

    if(index >= kNumPMMethods)
    	return NULL;
    else {
        if (sMethods[index].object)
            *targetP = this;
        else
            *targetP = fOwner;

        return &sMethods[index];
    }
}

void 
RootDomainUserClient::setPreventative(UInt32 on_off, UInt32 types_of_sleep)
{
    return;
}


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
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved.
 *
 */

#include <IOKit/assert.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include "RootDomainUserClient.h"
#include <IOKit/pwr_mgt/IOPMLibDefs.h>

#define super IOUserClient

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSDefineMetaClassAndStructors(RootDomainUserClient, IOUserClient)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool RootDomainUserClient::initWithTask(task_t owningTask, void *security_id, 
					UInt32 type, OSDictionary * properties)
{
    if (properties)
	properties->setObject(kIOUserClientCrossEndianCompatibleKey, kOSBooleanTrue);

    if (!super::initWithTask(owningTask, security_id, type, properties))
	return false;

    fOwningTask = owningTask;
    task_reference (fOwningTask);    
    return true;
}


bool RootDomainUserClient::start( IOService * provider )
{
    assert(OSDynamicCast(IOPMrootDomain, provider));
    if(!super::start(provider))
        return false;
    fOwner = (IOPMrootDomain *)provider;


    return true;
}

IOReturn RootDomainUserClient::secureSleepSystem( int *return_code )
{
    int             local_priv = 0;
    int             admin_priv = 0;
    IOReturn        ret = kIOReturnNotPrivileged;

    ret = clientHasPrivilege(fOwningTask, kIOClientPrivilegeLocalUser);
    local_priv = (kIOReturnSuccess == ret);
    
    ret = clientHasPrivilege(fOwningTask, kIOClientPrivilegeAdministrator);
    admin_priv = (kIOReturnSuccess == ret);

    if((local_priv || admin_priv) && fOwner) {
        *return_code = fOwner->sleepSystem();
        return kIOReturnSuccess;
    } else {
        *return_code = kIOReturnNotPrivileged;
        return kIOReturnSuccess;
    }

}

IOReturn RootDomainUserClient::secureSetAggressiveness( 
    unsigned long   type,
    unsigned long   newLevel,
    int             *return_code )
{
    int             local_priv = 0;
    int             admin_priv = 0;
    IOReturn        ret = kIOReturnNotPrivileged;

    ret = clientHasPrivilege(fOwningTask, kIOClientPrivilegeLocalUser);
    local_priv = (kIOReturnSuccess == ret);
    
    ret = clientHasPrivilege(fOwningTask, kIOClientPrivilegeAdministrator);
    admin_priv = (kIOReturnSuccess == ret);

    if((local_priv || admin_priv) && fOwner) {
        *return_code = fOwner->setAggressiveness(type, newLevel);
        return kIOReturnSuccess;
    } else {
        *return_code = kIOReturnNotPrivileged;
        return kIOReturnSuccess;
    }

}


IOReturn RootDomainUserClient::clientClose( void )
{
    detach(fOwner);
    
    if(fOwningTask) {
        task_deallocate(fOwningTask);
        fOwningTask = 0;
    }   
    
    return kIOReturnSuccess;
}

IOExternalMethod *
RootDomainUserClient::getTargetAndMethodForIndex( IOService ** targetP, UInt32 index )
{
    static IOExternalMethod sMethods[] = {
        { // kPMSetAggressiveness, 0
            (IOService *)1, (IOMethod)&RootDomainUserClient::secureSetAggressiveness, kIOUCScalarIScalarO, 2, 1
        },
        { // kPMGetAggressiveness, 1
            0, (IOMethod)&IOPMrootDomain::getAggressiveness, kIOUCScalarIScalarO, 1, 1
        },
        { // kPMSleepSystem, 2
            (IOService *)1, (IOMethod)&RootDomainUserClient::secureSleepSystem, kIOUCScalarIScalarO, 0, 1
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
            (IOService *)1, (IOMethod)&RootDomainUserClient::setPreventative, kIOUCScalarIScalarO, 2, 0
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


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

IOReturn RootDomainUserClient::secureSleepSystem( uint32_t *return_code )
{
    IOByteCount     return_code_size = 1;

    return secureSleepSystemOptions( NULL,      // inOptions
                                     (void *)return_code, // returnCode
                                     (void *)0,     // inSize
                                     (void *)&return_code_size, // returnSize
                                     NULL, NULL);
}

IOReturn RootDomainUserClient::secureSleepSystemOptions( 
    void * p1, void * p2, void * p3,
    void * p4, void * p5, void * p6 )
{
    void            *inOptions = (void *)p1;
    uint32_t        *returnCode = (uint32_t *)p2;
//  IOByteCount     inOptionsSize = (uintptr_t)p3;
    IOByteCount     *returnCodeSize = (IOByteCount *)p4;

    int             local_priv = 0;
    int             admin_priv = 0;
    IOReturn        ret = kIOReturnNotPrivileged;
    OSDictionary    *unserializedOptions =  NULL;
    OSString        *unserializeErrorString = NULL;

    ret = clientHasPrivilege(fOwningTask, kIOClientPrivilegeLocalUser);
    local_priv = (kIOReturnSuccess == ret);
    
    ret = clientHasPrivilege(fOwningTask, kIOClientPrivilegeAdministrator);
    admin_priv = (kIOReturnSuccess == ret);
    
    *returnCodeSize = sizeof(uint32_t);
    
    if (inOptions)
    {
        unserializedOptions = OSDynamicCast( OSDictionary,
                                             OSUnserializeXML((const char *)inOptions, &unserializeErrorString));
    
        if (!unserializedOptions) {
            IOLog("IOPMRootDomain SleepSystem unserialization failure: %s\n", 
                unserializeErrorString ? unserializeErrorString->getCStringNoCopy() : "Unknown");
        }
    }

    if ( (local_priv || admin_priv) 
          && fOwner ) 
    {
        if (unserializedOptions) 
        {
            // Publish Sleep Options in registry under root_domain
            fOwner->setProperty( kRootDomainSleepOptionsKey, unserializedOptions);            

            *returnCode = fOwner->sleepSystemOptions( unserializedOptions );

            unserializedOptions->release();        
        } else {
            // No options
            // Clear any pre-existing options
            fOwner->removeProperty( kRootDomainSleepOptionsKey );

            *returnCode = fOwner->sleepSystemOptions( NULL );        
        }

    } else {
        *returnCode = kIOReturnNotPrivileged;
    }

    return kIOReturnSuccess;
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

IOReturn RootDomainUserClient::secureSetMaintenanceWakeCalendar( 
    void * p1, void * p2, void * p3,
    void * p4, void * p5, void * p6 )
{
#if ROOT_DOMAIN_RUN_STATES
    IOPMCalendarStruct *    inCalendar = (IOPMCalendarStruct *) p1;
    uint32_t *              returnCode = (uint32_t *) p2;
    IOByteCount *           returnCodeSize = (IOByteCount *) p4;
    int                     admin_priv = 0;
    IOReturn                ret = kIOReturnNotPrivileged;
    
    ret = clientHasPrivilege(fOwningTask, kIOClientPrivilegeAdministrator);
    admin_priv = (kIOReturnSuccess == ret);

    *returnCodeSize = sizeof(uint32_t);

    if (admin_priv && fOwner) {
        *returnCode = fOwner->setMaintenanceWakeCalendar(inCalendar);
        return kIOReturnSuccess;
    } else {
        *returnCode = kIOReturnNotPrivileged;
        return kIOReturnSuccess;
    }
#else
    return kIOReturnUnsupported;
#endif
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
    static const IOExternalMethod sMethods[] = {
        {   // kPMSetAggressiveness, 0
            (IOService *)1, (IOMethod)&RootDomainUserClient::secureSetAggressiveness, kIOUCScalarIScalarO, 2, 1
        },
        {   // kPMGetAggressiveness, 1
            0, (IOMethod)&IOPMrootDomain::getAggressiveness, kIOUCScalarIScalarO, 1, 1
        },
        {   // kPMSleepSystem, 2
            (IOService *)1, (IOMethod)&RootDomainUserClient::secureSleepSystem, kIOUCScalarIScalarO, 0, 1
        },
        {   // kPMAllowPowerChange, 3
            0, (IOMethod)&IOPMrootDomain::allowPowerChange, kIOUCScalarIScalarO, 1, 0
        },
        {   // kPMCancelPowerChange, 4
            0, (IOMethod)&IOPMrootDomain::cancelPowerChange, kIOUCScalarIScalarO, 1, 0
        },
        {   // kPMShutdownSystem, 5
            0, (IOMethod)&IOPMrootDomain::shutdownSystem, kIOUCScalarIScalarO, 0, 0
        },
        {   // kPMRestartSystem, 6
            0, (IOMethod)&IOPMrootDomain::restartSystem, kIOUCScalarIScalarO, 0, 0
        },
        {   // kPMSleepSystemOptions, 7
            (IOService *)1, (IOMethod)&RootDomainUserClient::secureSleepSystemOptions, 
            kIOUCStructIStructO, kIOUCVariableStructureSize, sizeof(uint32_t)
        },
        {   // kPMSetMaintenanceWakeCalendar, 8
            (IOService *)1, (IOMethod)&RootDomainUserClient::secureSetMaintenanceWakeCalendar,
            kIOUCStructIStructO, sizeof(IOPMCalendarStruct), sizeof(uint32_t)
        }
    };
    
    if(index >= kNumPMMethods)
    	return NULL;
    else {
        if (sMethods[index].object)
            *targetP = this;
        else
            *targetP = fOwner;

        return (IOExternalMethod *)&sMethods[index];
    }
}

#if 0
IOReturn RootDomainUserClient::externalMethod( uint32_t selector, IOExternalMethodArguments * args,
						IOExternalMethodDispatch * dispatch, OSObject * target, void * reference )
{
    static const IOExternalMethodDispatch sMethods[] = {
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

    if (selector > (sizeof(sMethods) / sizeof(sMethods[0])))
	return (kIOReturnBadArgument);

    if ((1 << selector) & ((1 << 0) | (1 << 7))
	target = this;
    else
	target = fOwner;

    return (super::externalMethod(selector, args, &sMethods[selector], target, 0));
}
#endif

void 
RootDomainUserClient::setPreventative(UInt32 on_off, UInt32 types_of_sleep)
{
    return;
}


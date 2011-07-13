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
    return secureSleepSystemOptions(NULL, 0, return_code);
}

IOReturn RootDomainUserClient::secureSleepSystemOptions( 
    const void      *inOptions, 
    IOByteCount     inOptionsSize __unused,
    uint32_t        *returnCode)
{

    int             local_priv = 0;
    int             admin_priv = 0;
    IOReturn        ret = kIOReturnNotPrivileged;
    OSDictionary    *unserializedOptions =  NULL;
    OSString        *unserializeErrorString = NULL;

    ret = clientHasPrivilege(fOwningTask, kIOClientPrivilegeLocalUser);
    local_priv = (kIOReturnSuccess == ret);
    
    ret = clientHasPrivilege(fOwningTask, kIOClientPrivilegeAdministrator);
    admin_priv = (kIOReturnSuccess == ret);
    
    
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
    } else {
        *return_code = kIOReturnNotPrivileged;
    }
    return kIOReturnSuccess;
}

IOReturn RootDomainUserClient::secureSetMaintenanceWakeCalendar(
    IOPMCalendarStruct      *inCalendar,
    uint32_t                *returnCode)
{
    int                     admin_priv = 0;
    IOReturn                ret = kIOReturnNotPrivileged;
    
    ret = clientHasPrivilege(fOwningTask, kIOClientPrivilegeAdministrator);
    admin_priv = (kIOReturnSuccess == ret);

    if (admin_priv && fOwner) {
        *returnCode = fOwner->setMaintenanceWakeCalendar(inCalendar);
    } else {
        *returnCode = kIOReturnNotPrivileged;
    }
    return kIOReturnSuccess;
}

IOReturn RootDomainUserClient::secureSetUserAssertionLevels(
    uint32_t    assertionBitfield)
{
    int                     admin_priv = 0;
    IOReturn                ret = kIOReturnNotPrivileged;
    
    ret = clientHasPrivilege(fOwningTask, kIOClientPrivilegeAdministrator);
    admin_priv = (kIOReturnSuccess == ret);

    if (admin_priv && fOwner) {
        ret = fOwner->setPMAssertionUserLevels(assertionBitfield);
    } else {
        ret = kIOReturnNotPrivileged;
    }
    return kIOReturnSuccess;
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

IOReturn RootDomainUserClient::clientMemoryForType(
    UInt32 type,
    IOOptionBits *options,
    IOMemoryDescriptor ** memory)
{
    if (!fOwner)
        return kIOReturnNotReady;

    if (kPMRootDomainMapTraceBuffer == type)
    {
        *memory = fOwner->getPMTraceMemoryDescriptor();
        if (*memory) {
            (*memory)->retain();
            *options = 0;
            return kIOReturnSuccess;
        } else {
            return kIOReturnNotFound;
        }

    }
    return kIOReturnUnsupported;
}

IOReturn RootDomainUserClient::externalMethod(
    uint32_t selector, 
    IOExternalMethodArguments * arguments,
    IOExternalMethodDispatch * dispatch __unused, 
    OSObject * target __unused,
    void * reference __unused )
{
    IOReturn    ret = kIOReturnBadArgument;    
    
    switch (selector)
    {
        case kPMSetAggressiveness:
            if ((2 == arguments->scalarInputCount)
                && (1 == arguments->scalarOutputCount))
            {
                ret = this->secureSetAggressiveness(
                                (unsigned long)arguments->scalarInput[0],
                                (unsigned long)arguments->scalarInput[1],
                                (int *)&arguments->scalarOutput[0]);
            }
            break;
        
        case kPMGetAggressiveness:
            if ((1 == arguments->scalarInputCount)
                && (1 == arguments->scalarOutputCount))
            {
                ret = fOwner->getAggressiveness(
                                (unsigned long)arguments->scalarInput[0],
                                (unsigned long *)&arguments->scalarOutput[0]);
            }
            break;
        
        case kPMSleepSystem:
            if (1 == arguments->scalarOutputCount)
            {
                ret = this->secureSleepSystem(
                                (uint32_t *)&arguments->scalarOutput[0]);            
            }
            break;

        case kPMAllowPowerChange:
            if (1 == arguments->scalarInputCount)
            {
                ret = fOwner->allowPowerChange(
                                arguments->scalarInput[0]);
            }
            break;

        case kPMCancelPowerChange:
            if (1 == arguments->scalarInputCount)
            {
                ret = fOwner->cancelPowerChange(
                                arguments->scalarInput[0]);
            }
            break;

        case kPMShutdownSystem:
            // deperecated interface
            ret = kIOReturnUnsupported;
            break;

        case kPMRestartSystem:
            // deperecated interface
            ret = kIOReturnUnsupported;
            break;

        case kPMSleepSystemOptions:
            ret = this->secureSleepSystemOptions(
                    arguments->structureInput,
                    arguments->structureInputSize,
                    (uint32_t *)&arguments->scalarOutput[0]);
            break;
        case kPMSetMaintenanceWakeCalendar:
            ret = this->secureSetMaintenanceWakeCalendar(
                    (IOPMCalendarStruct *)arguments->structureInput, 
                    (uint32_t *)&arguments->structureOutput);
            arguments->structureOutputSize = sizeof(uint32_t);
            break;
            
        case kPMSetUserAssertionLevels:
            ret = this->secureSetUserAssertionLevels(
                        (uint32_t)arguments->scalarInput[0]);
            break;
            
/*
        case kPMMethodCopySystemTimeline:
            // intentional fallthrough
        case kPMMethodCopyDetailedTimeline:

            if (!arguments->structureOutputDescriptor)
            {
                // TODO: Force IOKit.framework to always send this data out
                // of line; so I don't have to create a MemoryDescriptor here.
                mem_size = arguments->structureOutputSize;
                mem = IOMemoryDescriptor::withAddressRange(
                                    (mach_vm_address_t)arguments->structureOutput, 
                                    (mach_vm_size_t)mem_size,
                                    kIODirectionIn, current_task());
            } else {
                mem_size = arguments->structureOutputDescriptorSize;
                if (( mem = arguments->structureOutputDescriptor ))
                    mem->retain();   
            }
            
            if (mem)
            {
                mem->prepare(kIODirectionNone);
    
                if (kPMMethodCopySystemTimeline == selector) {
                    arguments->scalarOutput[0] = fOwner->copySystemTimeline(
                                    mem, &mem_size);
                } 
                else
                if (kPMMethodCopyDetailedTimeline == selector) {
                    arguments->scalarOutput[0] = fOwner->copyDetailedTimeline(
                                    mem, &mem_size);
                }
            
                if (arguments->structureOutputDescriptor) {
                    arguments->structureOutputDescriptorSize = mem_size;
                } else {
                    arguments->structureOutputSize = mem_size;
                }
            
                mem->release();

                ret = kIOReturnSuccess;
            } else {
                ret = kIOReturnCannotWire;
            }
            
            break;
*/
        default:
            // bad selector
            return kIOReturnBadArgument;
    }

    return ret;
}

/* getTargetAndMethodForIndex
 * Not used. We prefer to use externalMethod() for user client invocations.
 * We maintain getTargetAndExternalMethod since it's an exported symbol,
 * and only for that reason.
 */
IOExternalMethod * RootDomainUserClient::getTargetAndMethodForIndex( 
    IOService ** targetP, UInt32 index )
{
    // DO NOT EDIT
    return super::getTargetAndMethodForIndex(targetP, index);
}

/* setPreventative
 * Does nothing. Exists only for exported symbol compatibility.
 */
void 
RootDomainUserClient::setPreventative(UInt32 on_off, UInt32 types_of_sleep)
{ return; } // DO NOT EDIT

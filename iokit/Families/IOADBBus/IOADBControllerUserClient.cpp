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
#include "IOADBControllerUserClient.h"

#define super IOUserClient

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSDefineMetaClassAndStructors(IOADBControllerUserClient, IOUserClient)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOADBControllerUserClient *IOADBControllerUserClient::withTask(task_t owningTask)
{
    IOADBControllerUserClient * me;

    me = new IOADBControllerUserClient;
    if ( me ) {
        if  (! me->init() ) {
            me->release();
            return NULL;
        }
        me->fTask = owningTask;
    }
    return me;
}

bool IOADBControllerUserClient::start( IOService * provider )
{
    assert(OSDynamicCast(IOADBController, provider));
    if(!super::start(provider))
        return false;
    fOwner = (IOADBController *)provider;

    // Got the owner, so initialize the call structures
    fMethods[kADBReadDevice].object = provider;
    fMethods[kADBReadDevice].func = (IOMethod)&IOADBController::readDeviceForUser;
    fMethods[kADBReadDevice].count0 = 2;
    fMethods[kADBReadDevice].count1 = 8;
    fMethods[kADBReadDevice].flags = kIOUCScalarIStructO;

    fMethods[kADBWriteDevice].object = provider;
    fMethods[kADBWriteDevice].func = (IOMethod)&IOADBController::writeDeviceForUser;
    fMethods[kADBWriteDevice].count0 = 4;
    fMethods[kADBWriteDevice].count1 = 0;
    fMethods[kADBWriteDevice].flags = kIOUCScalarIScalarO;

    fMethods[kADBClaimDevice].object = provider;
    fMethods[kADBClaimDevice].func = (IOMethod)&IOADBController::claimDevice;
    fMethods[kADBClaimDevice].count0 = 1;
    fMethods[kADBClaimDevice].count1 = 0;
    fMethods[kADBClaimDevice].flags = kIOUCScalarIScalarO;

    fMethods[kADBReleaseDevice].object = provider;
    fMethods[kADBReleaseDevice].func = (IOMethod)&IOADBController::releaseDevice;
    fMethods[kADBReleaseDevice].count0 = 1;
    fMethods[kADBReleaseDevice].count1 = 0;
    fMethods[kADBReleaseDevice].flags = kIOUCScalarIScalarO;

    return true;
}

IOReturn IOADBControllerUserClient::clientMemoryForType( UInt32 type,
    UInt32 * flags, IOLogicalAddress * address, IOByteCount * size )
{
    return kIOReturnUnsupported;
}

IOReturn IOADBControllerUserClient::clientClose( void )
{
    detach( fOwner);

    return kIOReturnSuccess;
}

IOReturn IOADBControllerUserClient::clientDied( void )
{
    return( clientClose());
}

IOReturn IOADBControllerUserClient::connectClient( IOUserClient * client )
{
    return kIOReturnSuccess;
}

IOExternalMethod * IOADBControllerUserClient::getExternalMethodForIndex( UInt32 index )
{
    if(index >= kNumADBMethods)
    	return NULL;
    else
        return &fMethods[index];
}

IOReturn IOADBControllerUserClient::registerNotificationPort ( mach_port_t port, UInt32 type )
{
    return kIOReturnUnsupported;
}


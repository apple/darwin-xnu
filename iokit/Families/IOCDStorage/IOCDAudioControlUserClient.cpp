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

#include <IOKit/assert.h>
#include <IOKit/IOLib.h>
#include <IOKit/storage/IOCDAudioControlUserClient.h>

#define super IOUserClient
OSDefineMetaClassAndStructors(IOCDAudioControlUserClient, IOUserClient)

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOCDAudioControl * IOCDAudioControlUserClient::getProvider() const
{
    //
    // Obtain this object's provider.  We override the superclass's method
    // to return a more specific subclass of IOService -- IOCDAudioControl.  
    // This method serves simply as a convenience to subclass developers.
    //

    return (IOCDAudioControl *) IOService::getProvider();
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOCDAudioControlUserClient * IOCDAudioControlUserClient::withTask(task_t)
{
    //
    // Create a new IOCDAudioControlUserClient.
    //

    IOCDAudioControlUserClient * me = new IOCDAudioControlUserClient;

    if ( me && me->init() == false )
    {
        me->release();
        me = 0;
    }

    return me;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOCDAudioControlUserClient::start(IOService * provider)
{
    //
    // Prepare the user client for usage.
    //

    // State our assumptions.

    assert(OSDynamicCast(IOCDAudioControl, provider));

    // Ask our superclass' opinion.

    if ( super::start(provider) == false )  return false;

    // Open our provider.

    if ( provider->open(this) == false )  return false;

    // Prepare our method dispatch table.

    _methods[kIOCDAudioControlMethodGetStatus].func   = (IOMethod) &IOCDAudioControlUserClient::getStatus;
    _methods[kIOCDAudioControlMethodGetStatus].flags  = kIOUCScalarIStructO;
    _methods[kIOCDAudioControlMethodGetStatus].count0 = 0;
    _methods[kIOCDAudioControlMethodGetStatus].count1 = sizeof(CDAudioStatus);
    _methods[kIOCDAudioControlMethodGetStatus].object = this;

    _methods[kIOCDAudioControlMethodGetTOC   ].func   = (IOMethod) &IOCDAudioControlUserClient::getTOC;
    _methods[kIOCDAudioControlMethodGetTOC   ].flags  = kIOUCScalarIStructO;
    _methods[kIOCDAudioControlMethodGetTOC   ].count0 = 0;
    _methods[kIOCDAudioControlMethodGetTOC   ].count1 = 0xFFFFFFFF;
    _methods[kIOCDAudioControlMethodGetTOC   ].object = this;

    _methods[kIOCDAudioControlMethodGetVolume].func   = (IOMethod) &IOCDAudioControlUserClient::getVolume;
    _methods[kIOCDAudioControlMethodGetVolume].flags  = kIOUCScalarIScalarO;
    _methods[kIOCDAudioControlMethodGetVolume].count0 = 0;
    _methods[kIOCDAudioControlMethodGetVolume].count1 = 2;
    _methods[kIOCDAudioControlMethodGetVolume].object = this;

    _methods[kIOCDAudioControlMethodSetVolume].func   = (IOMethod) &IOCDAudioControlUserClient::setVolume;
    _methods[kIOCDAudioControlMethodSetVolume].flags  = kIOUCScalarIScalarO;
    _methods[kIOCDAudioControlMethodSetVolume].count0 = 2;
    _methods[kIOCDAudioControlMethodSetVolume].count1 = 0;
    _methods[kIOCDAudioControlMethodSetVolume].object = this;

    _methods[kIOCDAudioControlMethodPause    ].func   = (IOMethod) &IOCDAudioControlUserClient::pause;
    _methods[kIOCDAudioControlMethodPause    ].flags  = kIOUCScalarIScalarO;
    _methods[kIOCDAudioControlMethodPause    ].count0 = 1;
    _methods[kIOCDAudioControlMethodPause    ].count1 = 0;
    _methods[kIOCDAudioControlMethodPause    ].object = this;

    _methods[kIOCDAudioControlMethodPlay     ].func   = (IOMethod) &IOCDAudioControlUserClient::play;
    _methods[kIOCDAudioControlMethodPlay     ].flags  = kIOUCScalarIScalarO;
    _methods[kIOCDAudioControlMethodPlay     ].count0 = 2;
    _methods[kIOCDAudioControlMethodPlay     ].count1 = 0;
    _methods[kIOCDAudioControlMethodPlay     ].object = this;

    _methods[kIOCDAudioControlMethodScan     ].func   = (IOMethod) &IOCDAudioControlUserClient::scan;
    _methods[kIOCDAudioControlMethodScan     ].flags  = kIOUCScalarIScalarO;
    _methods[kIOCDAudioControlMethodScan     ].count0 = 2;
    _methods[kIOCDAudioControlMethodScan     ].count1 = 0;
    _methods[kIOCDAudioControlMethodScan     ].object = this;

    _methods[kIOCDAudioControlMethodStop     ].func   = (IOMethod) &IOCDAudioControlUserClient::stop;
    _methods[kIOCDAudioControlMethodStop     ].flags  = 0;
    _methods[kIOCDAudioControlMethodStop     ].count0 = 0;
    _methods[kIOCDAudioControlMethodStop     ].count1 = 0;
    _methods[kIOCDAudioControlMethodStop     ].object = this;

    return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOReturn IOCDAudioControlUserClient::clientClose()
{
    //
    // Relinquish the user client.
    //

    IOCDAudioControl * provider = getProvider();

    if ( provider && provider->isOpen(this) )
    {
        provider->close(this);
        detach(provider);
    }

    return kIOReturnSuccess;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOExternalMethod * IOCDAudioControlUserClient::getExternalMethodForIndex(
                                                UInt32 index )
{
    //
    // Obtain the method definition given a method index.
    //

    if (index >= kIOCDAudioControlMethodCount)  return 0;

    return _methods + index;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOReturn IOCDAudioControlUserClient::getStatus( CDAudioStatus * status,
                                                UInt32 *        statusSize )
{
    //
    // Get the current audio play status information.
    //

    if ( *statusSize != sizeof(CDAudioStatus) )  return kIOReturnBadArgument;

    return getProvider()->getStatus(status);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOReturn IOCDAudioControlUserClient::getTOC(CDTOC * toc, UInt32 * tocMaxSize)
{
    //
    // Get the full Table Of Contents.
    //

    CDTOC * original = getProvider()->getTOC();

    if (original == 0)  return kIOReturnBadMedia;

    *tocMaxSize = min(original->length + sizeof(UInt16), *tocMaxSize);
    bcopy(original, toc, *tocMaxSize);

    return kIOReturnSuccess;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOReturn IOCDAudioControlUserClient::getVolume(UInt32 * left, UInt32 * right)
{
    //
    // Get the current audio volume.
    //

    IOReturn status;

    if ( ((*left) & ~0xFF) || ((*right) & ~0xFF) )  return kIOReturnBadArgument;

    status = getProvider()->getVolume((UInt8 *) left, (UInt8 *) right);

    *left  = *((UInt8 *) left );
    *right = *((UInt8 *) right);

    return status;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOReturn IOCDAudioControlUserClient::setVolume(UInt32 left, UInt32 right)
{
    //
    // Set the current audio volume.
    //

    if ( (left & ~0xFF) || (right & ~0xFF) )  return kIOReturnBadArgument;

    return getProvider()->setVolume((UInt8) left, (UInt8) right);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOReturn IOCDAudioControlUserClient::pause(UInt32 pause)
{
    //
    // Pause or resume the audio playback.
    //

    return getProvider()->pause((bool) pause);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOReturn IOCDAudioControlUserClient::play(UInt32 msfStart, UInt32 msfStop)
{
    //
    // Play audio.
    //

    CDMSF timeStart;
    CDMSF timeStop;
    
    timeStart.minute = (msfStart >> 16) & 0xFF;
    timeStart.second = (msfStart >>  8) & 0xFF;
    timeStart.frame  = (msfStart >>  0) & 0xFF;

    timeStop.minute  = (msfStop  >> 16) & 0xFF;
    timeStop.second  = (msfStop  >>  8) & 0xFF;
    timeStop.frame   = (msfStop  >>  0) & 0xFF;

    return getProvider()->play(timeStart, timeStop);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOReturn IOCDAudioControlUserClient::scan(UInt32 msfStart, UInt32 reverse)
{
    //
    // Perform a fast-forward or fast-backward operation.
    //

    CDMSF timeStart;

    timeStart.minute = (msfStart >> 16) & 0xFF;
    timeStart.second = (msfStart >>  8) & 0xFF;
    timeStart.frame  = (msfStart >>  0) & 0xFF;

    return getProvider()->scan(timeStart, reverse ? true : false);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOReturn IOCDAudioControlUserClient::stop()
{
    //
    // Stop the audio playback (or audio scan).
    //

    return getProvider()->stop();
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOCDAudioControlUserClient, 0);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOCDAudioControlUserClient, 1);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOCDAudioControlUserClient, 2);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOCDAudioControlUserClient, 3);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOCDAudioControlUserClient, 4);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOCDAudioControlUserClient, 5);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOCDAudioControlUserClient, 6);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOCDAudioControlUserClient, 7);

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

#include <IOKit/storage/IOCDAudioControl.h>
#include <IOKit/storage/IOCDAudioControlUserClient.h>
#include <IOKit/storage/IOCDBlockStorageDriver.h>

#define	super IOService
OSDefineMetaClassAndStructors(IOCDAudioControl, IOService)

IOCDBlockStorageDriver *
IOCDAudioControl::getProvider() const
{
    return (IOCDBlockStorageDriver *) IOService::getProvider();
}

IOReturn
IOCDAudioControl::getStatus(CDAudioStatus *status)
{
    return(getProvider()->getAudioStatus(status));
}

CDTOC *
IOCDAudioControl::getTOC(void)
{
    return(getProvider()->getTOC());
}

IOReturn
IOCDAudioControl::getVolume(UInt8 *left,UInt8 *right)
{
    return(getProvider()->getAudioVolume(left,right));
}

IOReturn
IOCDAudioControl::newUserClient(task_t task,
                  void *            /* security */,
                  UInt32            /* type */,
                  IOUserClient **   object )
    
{   
    IOReturn err = kIOReturnSuccess;
    IOCDAudioControlUserClient *      client;
 
    client = IOCDAudioControlUserClient::withTask(task);
    
    if( !client || (false == client->attach( this )) ||
        (false == client->start( this )) ) {
        if(client) {  
            client->detach( this );
            client->release();
        }
        err = kIOReturnNoMemory;
    }
    
    *object = client;
    return( err );
}       

IOReturn
IOCDAudioControl::pause(bool pause)
{
    return(getProvider()->audioPause(pause));
}

IOReturn
IOCDAudioControl::play(CDMSF timeStart,CDMSF timeStop)
{
    return(getProvider()->audioPlay(timeStart,timeStop));
}

IOReturn
IOCDAudioControl::scan(CDMSF timeStart,bool reverse)
{
    return(getProvider()->audioScan(timeStart,reverse));
}

IOReturn
IOCDAudioControl::stop()
{
    return(getProvider()->audioStop());
}

IOReturn
IOCDAudioControl::setVolume(UInt8 left,UInt8 right)
{
    return(getProvider()->setAudioVolume(left,right));
}

OSMetaClassDefineReservedUnused(IOCDAudioControl, 0);
OSMetaClassDefineReservedUnused(IOCDAudioControl, 1);
OSMetaClassDefineReservedUnused(IOCDAudioControl, 2);
OSMetaClassDefineReservedUnused(IOCDAudioControl, 3);
OSMetaClassDefineReservedUnused(IOCDAudioControl, 4);
OSMetaClassDefineReservedUnused(IOCDAudioControl, 5);
OSMetaClassDefineReservedUnused(IOCDAudioControl, 6);
OSMetaClassDefineReservedUnused(IOCDAudioControl, 7);

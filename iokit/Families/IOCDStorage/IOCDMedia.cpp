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

#include <IOKit/IOSyncer.h>
#include <IOKit/storage/IOCDBlockStorageDriver.h>
#include <IOKit/storage/IOCDMedia.h>

#define	super IOMedia
OSDefineMetaClassAndStructors(IOCDMedia, IOMedia)

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Local Functions

static void readCDCompletion(void *   target,
                             void *   parameter,
                             IOReturn status,
                             UInt64   actualByteCount)
{
    //
    // Internal completion routine for synchronous version of readCD.
    //

    if (parameter)  *((UInt64 *)parameter) = actualByteCount;
    ((IOSyncer *)target)->signal(status);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOCDBlockStorageDriver * IOCDMedia::getProvider() const
{
    //
    // Obtain this object's provider.  We override the superclass's method to
    // return a more specific subclass of IOService -- IOCDBlockStorageDriver.  
    // This method serves simply as a convenience to subclass developers.
    //

    return (IOCDBlockStorageDriver *) IOService::getProvider();
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOCDMedia::read(IOService *          /* client */,
                     UInt64               byteStart,
                     IOMemoryDescriptor * buffer,
                     IOStorageCompletion  completion)
{
    //
    // Read data from the storage object at the specified byte offset into the
    // specified buffer, asynchronously.   When the read completes, the caller
    // will be notified via the specified completion action.
    //
    // The buffer will be retained for the duration of the read.
    //
    // This method will work even when the media is in the terminated state.
    //

    if (isInactive())
    {
        complete(completion, kIOReturnNoMedia);
        return;
    }

    if (_openLevel == kIOStorageAccessNone)    // (instantaneous value, no lock)
    {
        complete(completion, kIOReturnNotOpen);
        return;
    }

    if (_mediaSize == 0 || _preferredBlockSize == 0)
    {
        complete(completion, kIOReturnUnformattedMedia);
        return;
    }

    if (_mediaSize < byteStart + buffer->getLength())
    {
        complete(completion, kIOReturnBadArgument);
        return;
    }

    byteStart += _mediaBase;
    getProvider()->readCD( /* client     */ this,
                           /* byteStart  */ byteStart,
                           /* buffer     */ buffer,
                           /* sectorArea */ (CDSectorArea) 0xF8, // (2352 bytes)
                           /* sectorType */ (CDSectorType) 0x00, // ( all types)
                           /* completion */ completion );
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOReturn IOCDMedia::readCD(IOService *          client,
                           UInt64               byteStart,
                           IOMemoryDescriptor * buffer,
                           CDSectorArea         sectorArea,
                           CDSectorType         sectorType,
                           UInt64 *             actualByteCount = 0)
{
    //
    // Read data from the CD media object at the specified byte offset into the
    // specified buffer, synchronously.   Special areas of the CD sector can be
    // read via this method, such as the header and subchannel data.   When the
    // read completes, this method will return to the caller.   The actual byte
    // count field is optional.
    //
    // This method will work even when the media is in the terminated state.
    //

    IOStorageCompletion	completion;
    IOSyncer *          completionSyncer;

    // Initialize the lock we will synchronize against.

    completionSyncer = IOSyncer::create();

    // Fill in the completion information for this request.

    completion.target    = completionSyncer;
    completion.action    = readCDCompletion;
    completion.parameter = actualByteCount;

    // Issue the asynchronous read.

    readCD(client, byteStart, buffer, sectorArea, sectorType, completion);

    // Wait for the read to complete.

    return completionSyncer->wait();
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOCDMedia::readCD(IOService *          client,
                       UInt64               byteStart,
                       IOMemoryDescriptor * buffer,
                       CDSectorArea         sectorArea,
                       CDSectorType         sectorType,
                       IOStorageCompletion  completion)
{
    //
    // Read data from the CD media object at the specified byte offset into the
    // specified buffer, asynchronously.  Special areas of the CD sector can be
    // read via this method, such as the header and subchannel data.   When the
    // read completes, the caller will be notified via the specified completion
    // action.
    //
    // The buffer will be retained for the duration of the read.
    //
    // This method will work even when the media is in the terminated state.
    //

    if (isInactive())
    {
        complete(completion, kIOReturnNoMedia);
        return;
    }

    if (_openLevel == kIOStorageAccessNone)    // (instantaneous value, no lock)
    {
        complete(completion, kIOReturnNotOpen);
        return;
    }

    if (_mediaSize == 0 || _preferredBlockSize == 0)
    {
        complete(completion, kIOReturnUnformattedMedia);
        return;
    }

    if (_mediaSize < byteStart + buffer->getLength())
    {
        complete(completion, kIOReturnBadArgument);
        return;
    }

    byteStart += _mediaBase;
    getProvider()->readCD( /* client     */ this,
                           /* byteStart  */ byteStart,
                           /* buffer     */ buffer,
                           /* sectorArea */ sectorArea,
                           /* sectorType */ sectorType,
                           /* completion */ completion );
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOReturn IOCDMedia::readISRC(UInt8 track, CDISRC isrc)
{
    //
    // Read the International Standard Recording Code for the specified track.
    //
    // This method will work even when the media is in the terminated state.
    //

    if (isInactive())
    {
        return kIOReturnNoMedia;
    }

    return getProvider()->readISRC(track, isrc);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOReturn IOCDMedia::readMCN(CDMCN mcn)
{
    //
    // Read the Media Catalog Number (also known as the Universal Product Code).
    //
    // This method will work even when the media is in the terminated state.
    //
    
    if (isInactive())
    {
        return kIOReturnNoMedia;
    }

    return getProvider()->readMCN(mcn);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

CDTOC * IOCDMedia::getTOC()
{
    //
    // Get the full Table Of Contents.
    //
    // This method will work even when the media is in the terminated state.
    //

    if (isInactive())
    {
        return 0;
    }

    return getProvider()->getTOC();
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOCDMedia, 0);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOCDMedia, 1);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOCDMedia, 2);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOCDMedia, 3);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOCDMedia, 4);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOCDMedia, 5);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOCDMedia, 6);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOCDMedia, 7);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOCDMedia, 8);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOCDMedia, 9);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOCDMedia, 10);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOCDMedia, 11);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOCDMedia, 12);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOCDMedia, 13);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOCDMedia, 14);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOCDMedia, 15);

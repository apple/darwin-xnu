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

#include <IOKit/storage/IOPartitionScheme.h>

#define super IOStorage
OSDefineMetaClassAndStructors(IOPartitionScheme, IOStorage)

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOMedia * IOPartitionScheme::getProvider() const
{
    //
    // Obtain this object's provider.  We override the superclass's method
    // to return a more specific subclass of OSObject -- an IOMedia.  This
    // method serves simply as a convenience to subclass developers.
    //

    return (IOMedia *) IOService::getProvider();
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOPartitionScheme::init(OSDictionary * properties = 0)
{
    //
    // Initialize this object's minimal state.
    //

    if (super::init(properties) == false)  return false;

    _openLevel         = kIOStorageAccessNone;
    _openReaders       = OSSet::withCapacity(16);
    _openReaderWriters = OSSet::withCapacity(16);

    if (_openReaders == 0 || _openReaderWriters == 0) return false;

    return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOPartitionScheme::free()
{
    //
    // Free all of this object's outstanding resources.
    //

    if (_openReaders)        _openReaders->release();
    if (_openReaderWriters)  _openReaderWriters->release();

    super::free();
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOPartitionScheme::handleOpen(IOService *  client,
                                   IOOptionBits options,
                                   void *       argument)
{
    //
    // The handleOpen method grants or denies permission to access this object
    // to an interested client.  The argument is an IOStorageAccess value that
    // specifies the level of access desired -- reader or reader-writer.
    //
    // This method can be invoked to upgrade or downgrade the access level for
    // an existing client as well.  The previous access level will prevail for
    // upgrades that fail, of course.   A downgrade should never fail.  If the
    // new access level should be the same as the old for a given client, this
    // method will do nothing and return success.  In all cases, one, singular
    // close-per-client is expected for all opens-per-client received.
    //
    // This implementation replaces the IOService definition of handleOpen().
    //
    // We are guaranteed that no other opens or closes will be processed until
    // we make our decision, change our state, and return from this method.
    //

    IOStorageAccess access  = (IOStorageAccess) argument;
    IOStorageAccess level;

    assert(client);
    assert( access == kIOStorageAccessReader       ||
            access == kIOStorageAccessReaderWriter );

    //
    // A partition scheme multiplexes the opens it receives from several clients
    // and sends one open to the level below that satisfies the highest level of
    // access.
    //

    unsigned writers = _openReaderWriters->getCount();

    if (_openReaderWriters->containsObject(client))  writers--;
    if (access == kIOStorageAccessReaderWriter)  writers++;

    level = (writers) ? kIOStorageAccessReaderWriter : kIOStorageAccessReader;

    //
    // Determine whether the levels below us accept this open or not (we avoid
    // the open if the required access is the access we already hold).
    //

    if (_openLevel != level)                        // (has open level changed?)
    {
        IOStorage * provider = OSDynamicCast(IOStorage, getProvider());

        if (provider && provider->open(this, options, level) == false)
            return false;
    }

    //
    // Process the open.
    //

    if (access == kIOStorageAccessReader)
    {
        _openReaders->setObject(client);

        _openReaderWriters->removeObject(client);           // (for a downgrade)
    }
    else // (access == kIOStorageAccessReaderWriter)
    {
        _openReaderWriters->setObject(client);

        _openReaders->removeObject(client);                  // (for an upgrade)
    }

    _openLevel = level;

    return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOPartitionScheme::handleIsOpen(const IOService * client) const
{
    //
    // The handleIsOpen method determines whether the specified client, or any
    // client if none is specificed, presently has an open on this object.
    //
    // This implementation replaces the IOService definition of handleIsOpen().
    //
    // We are guaranteed that no other opens or closes will be processed until
    // we return from this method.
    //

    if (client == 0)  return (_openLevel != kIOStorageAccessNone);

    return ( _openReaderWriters->containsObject(client) ||
             _openReaders->containsObject(client)       );
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOPartitionScheme::handleClose(IOService * client, IOOptionBits options)
{
    //
    // The handleClose method closes the client's access to this object.
    //
    // This implementation replaces the IOService definition of handleClose().
    //
    // We are guaranteed that no other opens or closes will be processed until
    // we change our state and return from this method.
    //

    assert(client);

    //
    // Process the close.
    //

    if (_openReaderWriters->containsObject(client))  // (is it a reader-writer?)
    {
        _openReaderWriters->removeObject(client);
    }
    else if (_openReaders->containsObject(client))  // (is the client a reader?)
    {
        _openReaders->removeObject(client);
    }
    else                                      // (is the client is an imposter?)
    {
        assert(0);
        return;
    }

    //
    // Reevaluate the open we have on the level below us.  If no opens remain,
    // we close, or if no reader-writer remains, but readers do, we downgrade.
    //

    IOStorageAccess level;

    if (_openReaderWriters->getCount())  level = kIOStorageAccessReaderWriter;
    else if (_openReaders->getCount())   level = kIOStorageAccessReader;
    else                                 level = kIOStorageAccessNone;

    if (_openLevel != level)                        // (has open level changed?)
    {
        IOStorage * provider = OSDynamicCast(IOStorage, getProvider());

        assert(level != kIOStorageAccessReaderWriter);

        if (provider)
        {
            if (level == kIOStorageAccessNone)         // (is a close in order?)
            {
                provider->close(this, options);
            }
            else                                   // (is a downgrade in order?)
            {
                bool success;
                success = provider->open(this, 0, level);
                assert(success); // (should never fail, unless avoided deadlock)
            }
         }

         _openLevel = level;                             // (set new open level)
    }
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOPartitionScheme::read(IOService *          /* client */,
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
    // For simple partition schemes, the default behavior is to simply pass the
    // read through to the provider media.  More complex partition schemes such
    // as RAID will need to do extra processing here.
    //

    getProvider()->read(this, byteStart, buffer, completion);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOPartitionScheme::write(IOService *          /* client */,
                              UInt64               byteStart,
                              IOMemoryDescriptor * buffer,
                              IOStorageCompletion  completion)
{
    //
    // Write data into the storage object at the specified byte offset from the
    // specified buffer, asynchronously.   When the write completes, the caller
    // will be notified via the specified completion action.
    //
    // The buffer will be retained for the duration of the write.
    //
    // For simple partition schemes, the default behavior is to simply pass the
    // write through to the provider media. More complex partition schemes such
    // as RAID will need to do extra processing here.
    //

    getProvider()->write(this, byteStart, buffer, completion);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOReturn IOPartitionScheme::synchronizeCache(IOService * client)
{
    return getProvider()->synchronizeCache(this);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme,  0);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme,  1);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme,  2);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme,  3);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme,  4);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme,  5);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme,  6);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme,  7);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme,  8);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme,  9);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme, 10);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme, 11);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme, 12);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme, 13);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme, 14);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme, 15);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme, 16);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme, 17);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme, 18);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme, 19);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme, 20);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme, 21);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme, 22);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme, 23);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme, 24);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme, 25);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme, 26);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme, 27);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme, 28);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme, 29);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme, 30);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOPartitionScheme, 31);

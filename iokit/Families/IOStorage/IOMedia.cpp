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

#include <machine/limits.h>                  // (ULONG_MAX, ...)
#include <IOKit/IODeviceTreeSupport.h>       // (gIODTPlane, ...)
#include <IOKit/storage/IOMedia.h>

#define super IOStorage
OSDefineMetaClassAndStructors(IOMedia, IOStorage)

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOStorage * IOMedia::getProvider() const
{
    //
    // Obtain this object's provider.  We override the superclass's method to
    // return a more specific subclass of OSObject -- IOStorage.  This method
    // serves simply as a convenience to subclass developers.
    //

    return (IOStorage *) IOService::getProvider();
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOMedia::init(UInt64         base,
                   UInt64         size,
                   UInt64         preferredBlockSize,
                   bool           isEjectable,
                   bool           isWhole,
                   bool           isWritable,
                   const char *   contentHint = 0,
                   OSDictionary * properties  = 0)
{
    //
    // Initialize this object's minimal state.
    //

    if (super::init(properties) == false)  return false;

    _mediaBase          = base;
    _mediaSize          = size;
    _isEjectable        = isEjectable;
    _isWhole            = isWhole;
    _isWritable         = isWritable;
    _openLevel          = kIOStorageAccessNone;
    _openReaders        = OSSet::withCapacity(1);
    _openReaderWriter   = 0;
    _preferredBlockSize = preferredBlockSize;

    if (_openReaders == 0)  return false;

    //
    // Create the standard media registry properties.
    //

    setProperty(kIOMediaContentKey,            contentHint ? contentHint : "");
    setProperty(kIOMediaContentHintKey,        contentHint ? contentHint : "");
    setProperty(kIOMediaEjectableKey,          isEjectable);
    setProperty(kIOMediaLeafKey,               true);
    setProperty(kIOMediaPreferredBlockSizeKey, preferredBlockSize, 64);
    setProperty(kIOMediaSizeKey,               size, 64);
    setProperty(kIOMediaWholeKey,              isWhole);
    setProperty(kIOMediaWritableKey,           isWritable);

    return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOMedia::free(void)
{
    //
    // Free all of this object's outstanding resources.
    //

    if (_openReaders)  _openReaders->release();

    super::free();
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOMedia::attachToChild(IORegistryEntry *       client,
                            const IORegistryPlane * plane)
{
    //
    // This method is called for each client interested in the services we
    // provide.  The superclass links us as a parent to this client in the
    // I/O Kit registry on success.
    //

    OSString * s;

    // Ask our superclass' opinion.

    if (super::attachToChild(client, plane) == false)  return false;

    //
    // Determine whether the client is a storage object, which we consider
    // to be a consumer of this storage object's content and a producer of
    // new content. A storage object need not be an IOStorage subclass, so
    // long as it identifies itself with a match category of "IOStorage".
    //
    // If the client is indeed a storage object, we reset the media's Leaf
    // property to false and replace the media's Content property with the
    // client's Content Mask property, if any.
    //

    s = OSDynamicCast(OSString, client->getProperty(gIOMatchCategoryKey));
 
    if (s && !strcmp(s->getCStringNoCopy(), kIOStorageCategory))
    {
        setProperty(kIOMediaLeafKey, false);

        s = OSDynamicCast(OSString,client->getProperty(kIOMediaContentMaskKey));
        if (s)  setProperty(kIOMediaContentKey, s->getCStringNoCopy());
    }

    return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOMedia::detachFromChild(IORegistryEntry *       client,
                              const IORegistryPlane * plane)
{
    //
    // This method is called for each client that loses interest in the
    // services we provide.  The superclass unlinks us from this client
    // in the I/O Kit registry on success.
    //
    // Note that this method is called at a nondeterministic time after
    // our client is terminated, which means another client may already
    // have arrived and attached in the meantime.  This is not an issue
    // should the termination be issued synchrnously, however, which we
    // take advantage of when this media needs to  eliminate one of its
    // clients.  If the termination was issued on this media or farther
    // below in the hierarchy, we don't really care that the properties
    // would not  be consistent since this media object is going to die
    // anyway.
    //

    OSString * s;

    //
    // Determine whether the client is a storage object, which we consider
    // to be a consumer of this storage object's content and a producer of
    // new content. A storage object need not be an IOStorage subclass, so
    // long as it identifies itself with a match category of "IOStorage".
    //
    // If the client is indeed a storage object, we reset the media's Leaf
    // property to true and reset the media's Content property to the hint
    // we obtained when this media was initialized.
    //

    s = OSDynamicCast(OSString, client->getProperty(gIOMatchCategoryKey));
 
    if (s && !strcmp(s->getCStringNoCopy(), kIOStorageCategory))
    {
        setProperty(kIOMediaContentKey, getContentHint());
        setProperty(kIOMediaLeafKey, true);
    }

    // Pass the call onto our superclass.

    super::detachFromChild(client, plane);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOMedia::handleOpen(IOService *  client,
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
    // This method will work even when the media is in the terminated state.
    //
    // We are guaranteed that no other opens or closes will be processed until
    // we make our decision, change our state, and return from this method.
    //

    IOStorageAccess access = (IOStorageAccess) argument;
    IOStorageAccess level;

    assert(client);

    //
    // Chart our course of action.
    //

    switch (access)
    {
        case kIOStorageAccessReader:
        {
            if (_openReaders->containsObject(client))     // (access: no change)
                return true;
            else if (_openReaderWriter == client)         // (access: downgrade)
                level = kIOStorageAccessReader;
            else                                         // (access: new reader)
                level = _openReaderWriter ? kIOStorageAccessReaderWriter
                                          : kIOStorageAccessReader;
            break;
        }
        case kIOStorageAccessReaderWriter:
        {
            if (_openReaders->containsObject(client))       // (access: upgrade)
                level = kIOStorageAccessReaderWriter; 
            else if (_openReaderWriter == client)         // (access: no change)
                return true;
            else                                         // (access: new writer)
                level = kIOStorageAccessReaderWriter; 

            if (_isWritable == false)        // (is this media object writable?)
                return false;

            if (_openReaderWriter)      // (does a reader-writer already exist?)
                return false;

            break;
        }
        default:
        {
            assert(0);
            return false;
        }
    }

    //
    // If we are in the terminated state, we only accept downgrades.
    //

    if (isInactive() && _openReaderWriter != client) // (dead? not a downgrade?)
        return false;

    //
    // Determine whether the storage objects above us can be torn down, should
    // this be a new reader-writer open or an upgrade into a reader-writer (if
    // the client issuing the open is not a storage object itself, of course).
    //

    if (access == kIOStorageAccessReaderWriter)  // (new reader-writer/upgrade?)
    {
        const OSSymbol * category = OSSymbol::withCString(kIOStorageCategory);

        if (category)
        {
            IOService * storageObject = getClientWithCategory(category);
            category->release();

            if (storageObject && storageObject != client)
            {
                if (storageObject->terminate(kIOServiceSynchronous) == false)
                    return false;
            }
        }
    }

    //
    // Determine whether the storage objects below us accept this open at this
    // multiplexed level of access -- new opens, upgrades, and downgrades (and
    // no changes in access) all enter through the same open api.
    //

    if (_openLevel != level)                        // (has open level changed?)
    {
        IOStorage * provider = OSDynamicCast(IOStorage, getProvider());

        if (provider && provider->open(this, options, level) == false)
        {
            //
            // We were unable to open the storage objects below us.   We must
            // recover from the terminate we issued above before bailing out,
            // if applicable, by re-registering the media object for matching.
            //

            if (access == kIOStorageAccessReaderWriter)
                registerService(kIOServiceSynchronous);   // (re-register media)

            return false;
        }
    }

    //
    // Process the open.
    //
    // We make sure our open state is consistent before calling registerService
    // (if applicable) since this method can be called again on the same thread
    // (the lock protecting handleOpen is recursive, so access would be given). 
    //

    _openLevel = level;

    if (access == kIOStorageAccessReader)
    {
        _openReaders->setObject(client);

        if (_openReaderWriter == client)                    // (for a downgrade)
        {
            _openReaderWriter = 0;
            registerService(kIOServiceSynchronous);       // (re-register media)
        }
    }
    else // (access == kIOStorageAccessReaderWriter)
    {
        _openReaderWriter = client;

        _openReaders->removeObject(client);                  // (for an upgrade)
    }

    return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOMedia::handleIsOpen(const IOService * client) const
{
    //
    // The handleIsOpen method determines whether the specified client, or any
    // client if none is specificed, presently has an open on this object.
    //
    // This method will work even when the media is in the terminated state.
    //
    // We are guaranteed that no other opens or closes will be processed until
    // we return from this method.
    //

    if (client == 0)  return (_openLevel != kIOStorageAccessNone);

    return ( _openReaderWriter == client          ||
             _openReaders->containsObject(client) );
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOMedia::handleClose(IOService * client, IOOptionBits options)
{
    //
    // A client is informing us that it is giving up access to our contents.
    //
    // This method will work even when the media is in the terminated state.
    //
    // We are guaranteed that no other opens or closes will be processed until
    // we change our state and return from this method.
    //

    assert(client);

    //
    // Process the close.
    //

    bool reregister = (_openReaderWriter == client) && (isInactive() == false);

    if (_openReaderWriter == client)         // (is the client a reader-writer?)
    {
        _openReaderWriter = 0;
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

    if      (_openReaderWriter)         level = kIOStorageAccessReaderWriter;
    else if (_openReaders->getCount())  level = kIOStorageAccessReader;
    else                                level = kIOStorageAccessNone;

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

    //
    // If the reader-writer just closeed, re-register the media so that I/O Kit
    // will attempt to match storage objects that may now be interested in this
    // media.
    //
    // We make sure our open state is consistent before calling registerService
    // (if applicable) since this method can be called again on the same thread
    // (the lock protecting handleClose is recursive, so access would be given).
    //

    if (reregister)
        registerService(kIOServiceSynchronous);           // (re-register media)
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOMedia::read(IOService *          /* client */,
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
    getProvider()->read(this, byteStart, buffer, completion);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOMedia::write(IOService *          client,
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

    if (_openReaderWriter != client)           // (instantaneous value, no lock)
    {
///m:2425148:workaround:commented:start
//        complete(completion, kIOReturnNotPrivileged);
//        return;
///m:2425148:workaround:commented:stop
    }

    if (_isWritable == 0)
    {
        complete(completion, kIOReturnLockedWrite);
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
    getProvider()->write(this, byteStart, buffer, completion);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOReturn IOMedia::synchronizeCache(IOService * client)
{
    if (isInactive())
    {
        return kIOReturnNoMedia;
    }

    if (_openLevel == kIOStorageAccessNone)    // (instantaneous value, no lock)
    {
        return kIOReturnNotOpen;
    }

    if (_openReaderWriter != client)           // (instantaneous value, no lock)
    {
        return kIOReturnNotPrivileged;
    }

    if (_isWritable == 0)
    {
        return kIOReturnLockedWrite;
    }

    if (_mediaSize == 0 || _preferredBlockSize == 0)
    {
        return kIOReturnUnformattedMedia;
    }

    return getProvider()->synchronizeCache(this);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

UInt64 IOMedia::getPreferredBlockSize() const
{
    //
    // Ask the media object for its natural block size.  This information
    // is useful to clients that want to optimize access to the media.
    //

    return _preferredBlockSize;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

UInt64 IOMedia::getSize() const
{
    //
    // Ask the media object for its total length in bytes.
    //

    return _mediaSize;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

UInt64 IOMedia::getBase() const
{
    //
    // Ask the media object for its byte offset relative to its provider media
    // object below it in the storage hierarchy.
    //

    return _mediaBase;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOMedia::isEjectable() const
{
    //
    // Ask the media object whether it is ejectable.
    //

    return _isEjectable;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOMedia::isFormatted() const
{
    //
    // Ask the media object whether it is formatted.
    //

    return (_mediaSize && _preferredBlockSize);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOMedia::isWritable() const
{
    //
    // Ask the media object whether it is writable.
    //

    return _isWritable;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOMedia::isWhole() const
{
    //
    // Ask the media object whether it represents the whole disk.
    //

    return _isWhole;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

const char * IOMedia::getContent() const
{
    //
    // Ask the media object for a description of its contents.  The description
    // is the same as the hint at the time of the object's creation,  but it is
    // possible that the description be overrided by a client (which has probed
    // the media and identified the content correctly) of the media object.  It
    // is more accurate than the hint for this reason.  The string is formed in
    // the likeness of Apple's "Apple_HFS" strings.
    //
    // The content description can be overrided by any client that matches onto
    // this media object with a match category of kIOStorageCategory.  The media
    // object checks for a kIOMediaContentMaskKey property in the client, and if
    // it finds one, it copies it into kIOMediaContentKey property.
    //

    OSString * string;

    string = OSDynamicCast(OSString, getProperty(kIOMediaContentKey));
    if (string == 0)  return "";
    return string->getCStringNoCopy();
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

const char * IOMedia::getContentHint() const
{
    //
    // Ask the media object for a hint of its contents.  The hint is set at the
    // time of the object's creation, should the creator have a clue as to what
    // it may contain.  The hint string does not change for the lifetime of the
    // object and is also formed in the likeness of Apple's "Apple_HFS" strings.
    //

    OSString * string;

    string = OSDynamicCast(OSString, getProperty(kIOMediaContentHintKey));
    if (string == 0)  return "";
    return string->getCStringNoCopy();
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOMedia::matchPropertyTable(OSDictionary * table, SInt32 * score)
{
    //
    // Compare the properties in the supplied table to this object's properties.
    //

    // Ask our superclass' opinion.

    if (super::matchPropertyTable(table, score) == false)  return false;

    // We return success if the following expression is true -- individual
    // comparisions evaluate to truth if the named property is not present
    // in the supplied table.

    return compareProperty(table, kIOMediaContentKey)     &&
           compareProperty(table, kIOMediaContentHintKey) &&
           compareProperty(table, kIOMediaEjectableKey)   &&
           compareProperty(table, kIOMediaLeafKey)        &&
           compareProperty(table, kIOMediaSizeKey)        &&
           compareProperty(table, kIOMediaWholeKey)       &&
           compareProperty(table, kIOMediaWritableKey)    ;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOMedia, 0);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOMedia, 1);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOMedia, 2);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOMedia, 3);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOMedia, 4);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOMedia, 5);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOMedia, 6);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOMedia, 7);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOMedia, 8);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOMedia, 9);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOMedia, 10);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOMedia, 11);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOMedia, 12);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOMedia, 13);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOMedia, 14);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

OSMetaClassDefineReservedUnused(IOMedia, 15);

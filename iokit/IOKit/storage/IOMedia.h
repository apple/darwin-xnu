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

/*!
 * @header IOMedia
 * @abstract
 * This header contains the IOMedia class definition.
 */

#ifndef _IOMEDIA_H
#define _IOMEDIA_H

/*!
 * @defined kIOMediaClass
 * @abstract
 * kIOMediaClass is the name of the IOMedia class.
 * @discussion
 * kIOMediaClass is the name of the IOMedia class.
 */

#define kIOMediaClass "IOMedia"

/*!
 * @defined kIOMediaContentKey
 * @abstract
 * kIOMediaContentKey is a property of IOMedia objects.  It has an OSString
 * value.
 * @discussion
 * The kIOMediaContentKey property contains a description of the media's
 * contents.  The description is the same as the hint at the time of the object's
 * creation, but it is possible that the description be overrided by a client
 * (which has probed the media and identified the content correctly) of the media
 * object.  It is more accurate than the hint for this reason.  The string is
 * formed in the likeness of Apple's "Apple_HFS" strings.
 */

#define kIOMediaContentKey "Content"
#define kIOMediaContent "Content" ///d:deprecated

/*!
 * @defined kIOMediaContentHintKey
 * @abstract
 * kIOMediaContentHintKey is a property of IOMedia objects.  It has an OSString
 * value.
 * @discussion
 * The kIOMediaContentHintKey property contains a hint of the media's contents.
 * The hint is set at the time of the object's creation, should the creator have
 * a clue as to what it may contain.  The hint string does not change for the
 * lifetime of the object and is formed in the likeness of Apple's "Apple_HFS"
 * strings.
 */

#define kIOMediaContentHintKey "Content Hint"

/*!
 * @defined kIOMediaEjectableKey
 * @abstract
 * kIOMediaEjectableKey is a property of IOMedia objects.  It has an OSBoolean
 * value.
 * @discussion
 * The kIOMediaEjectableKey property describes whether the media is ejectable.
 */

#define kIOMediaEjectableKey "Ejectable"
#define kIOMediaEjectable "Ejectable" ///d:deprecated

/*!
 * @defined kIOMediaLeafKey
 * @abstract
 * kIOMediaLeafKey is a property of IOMedia objects.  It has an OSBoolean value.
 * @discussion
 * The kIOMediaLeafKey property describes whether the media is a leaf, that is,
 * it is the deepest media object in this branch of the I/O Kit registry.
 */

#define kIOMediaLeafKey "Leaf"
#define kIOMediaLeaf "Leaf" ///d:deprecated

/*!
 * @defined kIOMediaPreferredBlockSizeKey
 * @abstract
 * kIOMediaPreferredBlockSizeKey is a property of IOMedia objects.  It has an
 * OSNumber value.
 * @discussion
 * The kIOMediaPreferredBlockSizeKey property describes the media's natural block
 * size in bytes.  This information is useful to clients that want to optimize
 * access to the media.
 */

#define kIOMediaPreferredBlockSizeKey "Preferred Block Size"

/*!
 * @defined kIOMediaSizeKey
 * @abstract
 * kIOMediaSizeKey is a property of IOMedia objects.  It has an OSNumber value.
 * @discussion
 * The kIOMediaSizeKey property describes the total length of the media in bytes.
 */

#define kIOMediaSizeKey "Size"
#define kIOMediaSize "Size" ///d:deprecated

/*!
 * @defined kIOMediaWholeKey
 * @abstract
 * kIOMediaWholeKey is a property of IOMedia objects.  It has an OSBoolean value.
 * @discussion
 * The kIOMediaWholeKey property describes whether the media is whole, that is,
 * it represents the whole disk (the physical disk, or a virtual replica
 * thereof).
 */

#define kIOMediaWholeKey "Whole"

/*!
 * @defined kIOMediaWritableKey
 * @abstract
 * kIOMediaWritableKey is a property of IOMedia objects.  It has an OSBoolean
 * value.
 * @discussion
 * The kIOMediaWritableKey property describes whether the media is writable.
 */

#define kIOMediaWritableKey "Writable"
#define kIOMediaWritable "Writable" ///d:deprecated

/*!
 * @defined kIOMediaContentMaskKey
 * @abstract
 * kIOMediaContentMaskKey is a property of IOMedia clients.  It has an OSString
 * value.
 * @discussion
 * The kIOMediaContentMaskKey property must exist in all IOMedia clients that
 * drive new content (that is, produce new media objects).  When the client
 * matches against the provider media, the value of the client's
 * kIOMediaContentMaskKey property is used to replace the provider's
 * kIOMediaContentKey property.
 */

#define kIOMediaContentMaskKey "Content Mask"

/*
 * Kernel
 */

#if defined(KERNEL) && defined(__cplusplus)

#include <IOKit/storage/IOStorage.h>

/*!
 * @class IOMedia
 * @abstract
 * The IOMedia class is a random-access disk device abstraction.
 * @discussion
 * The IOMedia class is a random-access disk device abstraction.   It provides a
 * consistent interface for both real and virtual disk devices, for subdivisions
 * of disks such as partitions, for supersets of disks such as RAID volumes, and
 * so on.   It extends the IOStorage class by implementing the appropriate open,
 * close, read, write, and matching semantics for media objects.  The properties
 * it has reflect the properties of real disk devices,  such as ejectability and
 * writability.
 *
 * The read and write interfaces support byte-level access to the storage space,
 * with the appropriate deblocking handled by the block storage driver, however,
 * a typical client will want to get the natural block size in order to optimize
 * access to the real disk device.  A read or write is accepted so long as the
 * client's access is valid, the media is formatted and the transfer is within
 * the bounds of the media.  An optional non-zero base (offset) is then applied
 * before the read or write is passed to provider object.
 *
 * An open is accepted so long as no more than one writer is active at any time.
 */

class IOMedia : public IOStorage
{
    OSDeclareDefaultStructors(IOMedia)

protected:

    struct ExpansionData { /* */ };
    ExpansionData * _expansionData;

    bool            _isEjectable;
    bool            _isWhole;
    bool            _isWritable;

    UInt64          _mediaBase;  /* (relative to the storage object below us) */
    UInt64          _mediaSize;

    IOStorageAccess _openLevel;
    OSSet *         _openReaders;
    IOService *     _openReaderWriter;

    UInt64          _preferredBlockSize;

    /*
     * Free all of this object's outstanding resources.
     */

    virtual void free();

    /*!
     * @function handleOpen
     * @discussion
     * The handleOpen method grants or denies permission to access this object
     * to an interested client.  The argument is an IOStorageAccess value that
     * specifies the level of access desired -- reader or reader-writer.
     *
     * This method can be invoked to upgrade or downgrade the access level for
     * an existing client as well.  The previous access level will prevail for
     * upgrades that fail, of course.   A downgrade should never fail.  If the
     * new access level should be the same as the old for a given client, this
     * method will do nothing and return success.  In all cases, one, singular
     * close-per-client is expected for all opens-per-client received.
     *
     * This implementation replaces the IOService definition of handleOpen().
     * @param client
     * Client requesting the open.
     * @param options
     * Options for the open.  Set to zero.
     * @param access
     * Access level for the open.  Set to kIOStorageAccessReader or
     * kIOStorageAccessReaderWriter.
     * @result
     * Returns true if the open was successful, false otherwise.
     */

    virtual bool handleOpen(IOService *  client,
                            IOOptionBits options,
                            void *       access);

    /*!
     * @function handleIsOpen
     * @discussion
     * The handleIsOpen method determines whether the specified client, or any
     * client if none is specificed, presently has an open on this object.
     *
     * This implementation replaces the IOService definition of handleIsOpen().
     * @param client
     * Client to check the open state of.  Set to zero to check the open state
     * of all clients.
     * @result
     * Returns true if the client was (or clients were) open, false otherwise.
     */

    virtual bool handleIsOpen(const IOService * client) const;

    /*!
     * @function handleClose
     * @discussion
     * The handleClose method closes the client's access to this object.
     *
     * This implementation replaces the IOService definition of handleClose().
     * @param client
     * Client requesting the close.
     * @param options
     * Options for the close.  Set to zero.
     */

    virtual void handleClose(IOService * client, IOOptionBits options);

public:

///m:2333367:workaround:commented:start
//  using read;
//  using write;
///m:2333367:workaround:commented:stop

    /*!
     * @function init
     * @discussion
     * Initialize this object's minimal state.
     * @param base
     * Media offset, in bytes.
     * @param size
     * Media size, in bytes.
     * @param preferredBlockSize
     * Natural block size, in bytes.
     * @param isEjectable
     * Indicates whether the media is ejectable.
     * @param isWhole
     * Indicated whether the media represents the whole disk.
     * @param isWritable
     * Indicates whether the media is writable.
     * @param contentHint
     * Hint of media's contents (optional).  See getContentHint().
     * @param properties
     * Substitute property table for this object (optional).
     * @result
     * Returns true on success, false otherwise.
     */

    virtual bool init(UInt64         base,
                      UInt64         size,
                      UInt64         preferredBlockSize,
                      bool           isEjectable,
                      bool           isWhole,
                      bool           isWritable,
                      const char *   contentHint = 0,
                      OSDictionary * properties  = 0);

    /*
     * This method is called for each client interested in the services we
     * provide.  The superclass links us as a parent to this client in the
     * I/O Kit registry on success.
     */

    virtual bool attachToChild(IORegistryEntry *       client,
                               const IORegistryPlane * plane);

    /*
     * This method is called for each client that loses interest in the
     * services we provide.  The superclass unlinks us from this client
     * in the I/O Kit registry on success.
     */

    virtual void detachFromChild(IORegistryEntry *       client,
                                 const IORegistryPlane * plane);

    /*
     * Compare the properties in the supplied table to this object's properties.
     */

    virtual bool matchPropertyTable(OSDictionary * table, SInt32 * score);

    /*!
     * @function read
     * @discussion
     * Read data from the storage object at the specified byte offset into the
     * specified buffer, asynchronously.   When the read completes, the caller
     * will be notified via the specified completion action.
     *
     * The buffer will be retained for the duration of the read.
     * @param client
     * Client requesting the read.
     * @param byteStart
     * Starting byte offset for the data transfer.
     * @param buffer
     * Buffer for the data transfer.  The size of the buffer implies the size of
     * the data transfer.
     * @param completion
     * Completion routine to call once the data transfer is complete.
     */

    virtual void read(IOService *          client,
                      UInt64               byteStart,
                      IOMemoryDescriptor * buffer,
                      IOStorageCompletion  completion);

    /*!
     * @function write
     * @discussion
     * Write data into the storage object at the specified byte offset from the
     * specified buffer, asynchronously.   When the write completes, the caller
     * will be notified via the specified completion action.
     *
     * The buffer will be retained for the duration of the write.
     * @param client
     * Client requesting the write.
     * @param byteStart
     * Starting byte offset for the data transfer.
     * @param buffer
     * Buffer for the data transfer.  The size of the buffer implies the size of
     * the data transfer.
     * @param completion
     * Completion routine to call once the data transfer is complete.
     */

    virtual void write(IOService *          client,
                       UInt64               byteStart,
                       IOMemoryDescriptor * buffer,
                       IOStorageCompletion  completion);

    virtual IOReturn synchronizeCache(IOService * client);

    /*!
     * @function getPreferredBlockSize
     * @discussion
     * Ask the media object for its natural block size.  This information
     * is useful to clients that want to optimize access to the media.
     * @result
     * Natural block size, in bytes.
     */

    virtual UInt64 getPreferredBlockSize() const;

    /*!
     * @function getSize
     * @discussion
     * Ask the media object for its total length in bytes.
     * @result
     * Media size, in bytes.
     */

    virtual UInt64 getSize() const;

    /*!
     * @function getBase
     * @discussion
     * Ask the media object for its byte offset relative to its provider media
     * object below it in the storage hierarchy.
     * Media offset, in bytes.
     */

    virtual UInt64 getBase() const;

    /*!
     * @function isEjectable
     * @discussion
     * Ask the media object whether it is ejectable.
     * @result
     * Returns true if the media is ejectable, false otherwise.
     */

    virtual bool isEjectable() const;

    /*!
     * @function isFormatted
     * @discussion
     * Ask the media object whether it is formatted.
     * @result
     * Returns true if the media is formatted, false otherwise.
     */

    virtual bool isFormatted() const;

    /*!
     * @function isWhole
     * @discussion
     * Ask the media object whether it represents the whole disk.
     * @result
     * Returns true if the media represents the whole disk, false otherwise.
     */

    virtual bool isWhole() const;

    /*!
     * @function isWritable
     * @discussion
     * Ask the media object whether it is writable.
     * @result
     * Returns true if the media is writable, false otherwise.
     */

    virtual bool isWritable() const;

    /*!
     * @function getContent
     * @discussion
     * Ask the media object for a description of its contents.  The description
     * is the same as the hint at the time of the object's creation,  but it is
     * possible that the description be overrided by a client (which has probed
     * the media and identified the content correctly) of the media object.  It
     * is more accurate than the hint for this reason.  The string is formed in
     * the likeness of Apple's "Apple_HFS" strings.
     *
     * The content description can be overrided by any client that matches onto
     * this media object with a match category of kIOStorageCategory.  The media
     * object checks for a kIOMediaContentMaskKey property in the client, and if
     * it finds one, it copies it into kIOMediaContentKey property.
     * @result
     * Description of media's contents.
     */

    virtual const char * getContent() const;

    /*!
     * @function getContentHint
     * @discussion
     * Ask the media object for a hint of its contents.  The hint is set at the
     * time of the object's creation, should the creator have a clue as to what
     * it may contain.  The hint string does not change for the lifetime of the
     * object and is also formed in the likeness of Apple's "Apple_HFS" strings.
     * @result
     * Hint of media's contents.
     */

    virtual const char * getContentHint() const;

    /*
     * Obtain this object's provider.  We override the superclass's method to
     * return a more specific subclass of OSObject -- IOStorage.  This method
     * serves simply as a convenience to subclass developers.
     */

    virtual IOStorage * getProvider() const;

    OSMetaClassDeclareReservedUnused(IOMedia,  0);
    OSMetaClassDeclareReservedUnused(IOMedia,  1);
    OSMetaClassDeclareReservedUnused(IOMedia,  2);
    OSMetaClassDeclareReservedUnused(IOMedia,  3);
    OSMetaClassDeclareReservedUnused(IOMedia,  4);
    OSMetaClassDeclareReservedUnused(IOMedia,  5);
    OSMetaClassDeclareReservedUnused(IOMedia,  6);
    OSMetaClassDeclareReservedUnused(IOMedia,  7);
    OSMetaClassDeclareReservedUnused(IOMedia,  8);
    OSMetaClassDeclareReservedUnused(IOMedia,  9);
    OSMetaClassDeclareReservedUnused(IOMedia, 10);
    OSMetaClassDeclareReservedUnused(IOMedia, 11);
    OSMetaClassDeclareReservedUnused(IOMedia, 12);
    OSMetaClassDeclareReservedUnused(IOMedia, 13);
    OSMetaClassDeclareReservedUnused(IOMedia, 14);
    OSMetaClassDeclareReservedUnused(IOMedia, 15);
};

#endif /* defined(KERNEL) && defined(__cplusplus) */

#endif /* !_IOMEDIA_H */

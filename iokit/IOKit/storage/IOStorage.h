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
 * @header IOStorage
 * @abstract
 * This header contains the IOStorage class definition.
 */

#ifndef _IOSTORAGE_H
#define _IOSTORAGE_H

#include <IOKit/IOTypes.h>

/*!
 * @defined kIOStorageClass
 * @abstract
 * kIOStorageClass is the name of the IOStorage class.
 * @discussion
 * kIOStorageClass is the name of the IOStorage class.
 */

#define kIOStorageClass "IOStorage"

/*!
 * @enum IOStorageAccess
 * @discussion
 * The IOStorageAccess enumeration describes the possible access levels for open
 * requests.
 * @constant kIOStorageAccessNone
 * No access is requested; should not be passed to open().
 * @constant kIOStorageAccessReader
 * Read-only access is requested.
 * @constant kIOStorageAccessReaderWriter
 * Read and write access is requested.
 */

typedef UInt32 IOStorageAccess;

#define kIOStorageAccessNone         0x00
#define kIOStorageAccessReader       0x01
#define kIOStorageAccessReaderWriter 0x03

/*!
 * @defined kIOStorageCategory
 * @abstract
 * kIOStorageCategory is a value for IOService's kIOMatchCategoryKey property.
 * @discussion
 * The kIOStorageCategory value is the standard value for the IOService property
 * kIOMatchCategoryKey ("IOMatchCategory") for all storage drivers.  All storage
 * objects that expect to drive new content (that is, produce new media objects)
 * are expected to compete within the kIOStorageCategory namespace.
 *
 * See the IOService documentation for more information on match categories.
 */

#define kIOStorageCategory "IOStorage"                /* (as IOMatchCategory) */

/*
 * Kernel
 */

#if defined(KERNEL) && defined(__cplusplus)

#include <IOKit/assert.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOService.h>

/*!
 * @typedef IOStorageCompletionAction
 * @discussion
 * The IOStorageCompletionAction declaration describes the C (or C++) completion
 * routine that is called once an asynchronous storage operation completes.
 * @param target
 * Opaque client-supplied pointer (or an instance pointer for a C++ callback).
 * @param parameter
 * Opaque client-supplied pointer.
 * @param status
 * Status of the data transfer.
 * @param actualByteCount
 * Actual number of bytes transferred in the data transfer.
 */

typedef void (*IOStorageCompletionAction)(void *   target,
                                          void *   parameter,
                                          IOReturn status,
                                          UInt64   actualByteCount);

/*!
 * @struct IOStorageCompletion
 * @discussion
 * The IOStorageCompletion structure describes the C (or C++) completion routine
 * that is called once an asynchronous storage operation completes.   The values
 * passed for the target and parameter fields will be passed to the routine when
 * it is called.
 * @field target
 * Opaque client-supplied pointer (or an instance pointer for a C++ callback).
 * @field action
 * Completion routine to call on completion of the data transfer.
 * @field parameter
 * Opaque client-supplied pointer.
 */

struct IOStorageCompletion
{
    void *                    target;
    IOStorageCompletionAction action;
    void *                    parameter;
};

/*!
 * @class IOStorage
 * @abstract
 * The IOStorage class is the common base class for mass storage objects.
 * @discussion
 * The IOStorage class is the common base class for mass storage objects.  It is
 * an abstract class that defines the open/close/read/write APIs that need to be
 * implemented in a given subclass.  Synchronous versions of the read/write APIs
 * are provided here -- they are coded in such a way as to wrap the asynchronous
 * versions implmeneted in the subclass.
 */

class IOStorage : public IOService
{
    OSDeclareAbstractStructors(IOStorage);

protected:

    struct ExpansionData { /* */ };
    ExpansionData * _expansionData;

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
                            void *       access) = 0;

    /*!
     * @function handleIsOpen
     * @discussion
     * The handleIsOpen method determines whether the specified client, or any
     * client if none is specificed, presently has an open on this object.
     * @param client
     * Client to check the open state of.  Set to zero to check the open state
     * of all clients.
     * @result
     * Returns true if the client was (or clients were) open, false otherwise.
     */

    virtual bool handleIsOpen(const IOService * client) const = 0;

    /*!
     * @function handleClose
     * @discussion
     * The handleClose method closes the client's access to this object.
     * @param client
     * Client requesting the close.
     * @param options
     * Options for the close.  Set to zero.
     */

    virtual void handleClose(IOService * client, IOOptionBits options) = 0;

public:

///m:2333367:workaround:commented:start
//  using open;
///m:2333367:workaround:commented:stop

    /*!
     * @function open
     * @discussion
     * Ask the storage object for permission to access its contents; the method
     * is equivalent to IOService::open(), but with the correct parameter types.
     *
     * This method may also be invoked to upgrade or downgrade the access of an
     * existing open (if it fails, the existing open prevails).
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

    virtual bool open(IOService *     client,
                      IOOptionBits    options,
                      IOStorageAccess access);

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
                      IOStorageCompletion  completion) = 0;

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
                       IOStorageCompletion  completion) = 0;

    /*!
     * @function read
     * @discussion
     * Read data from the storage object at the specified byte offset into the
     * specified buffer, synchronously.   When the read completes, this method
     * will return to the caller.  The actual byte count field is optional.
     * @param client
     * Client requesting the read.
     * @param byteStart
     * Starting byte offset for the data transfer.
     * @param buffer
     * Buffer for the data transfer.  The size of the buffer implies the size of
     * the data transfer.
     * @param actualByteCount
     * Returns the actual number of bytes transferred in the data transfer.
     * @result
     * Returns the status of the data transfer.
     */

    virtual IOReturn read(IOService *          client,
                          UInt64               byteStart,
                          IOMemoryDescriptor * buffer,
                          UInt64 *             actualByteCount = 0);

    /*!
     * @function write
     * @discussion
     * Write data into the storage object at the specified byte offset from the
     * specified buffer, synchronously.   When the write completes, this method
     * will return to the caller.  The actual byte count field is optional.
     * @param client
     * Client requesting the write.
     * @param byteStart
     * Starting byte offset for the data transfer.
     * @param buffer
     * Buffer for the data transfer.  The size of the buffer implies the size of
     * the data transfer.
     * @param actualByteCount
     * Returns the actual number of bytes transferred in the data transfer.
     * @result
     * Returns the status of the data transfer.
     */

    virtual IOReturn write(IOService *          client,
                           UInt64               byteStart,
                           IOMemoryDescriptor * buffer,
                           UInt64 *             actualByteCount = 0);

    virtual IOReturn synchronizeCache(IOService * client) = 0;

    /*!
     * @function complete
     * @discussion
     * Invokes the specified completion action of the read/write request.  If
     * the completion action is unspecified, no action is taken.  This method
     * serves simply as a convenience to storage subclass developers.
     * @param completion
     * Completion information for the data transfer.
     * @param status
     * Status of the data transfer.
     * @param actualByteCount
     * Actual number of bytes transferred in the data transfer.
     */

    static inline void complete(IOStorageCompletion completion,
                                IOReturn            status,
                                UInt64              actualByteCount = 0);

    OSMetaClassDeclareReservedUnused(IOStorage,  0);
    OSMetaClassDeclareReservedUnused(IOStorage,  1);
    OSMetaClassDeclareReservedUnused(IOStorage,  2);
    OSMetaClassDeclareReservedUnused(IOStorage,  3);
    OSMetaClassDeclareReservedUnused(IOStorage,  4);
    OSMetaClassDeclareReservedUnused(IOStorage,  5);
    OSMetaClassDeclareReservedUnused(IOStorage,  6);
    OSMetaClassDeclareReservedUnused(IOStorage,  7);
    OSMetaClassDeclareReservedUnused(IOStorage,  8);
    OSMetaClassDeclareReservedUnused(IOStorage,  9);
    OSMetaClassDeclareReservedUnused(IOStorage, 10);
    OSMetaClassDeclareReservedUnused(IOStorage, 11);
    OSMetaClassDeclareReservedUnused(IOStorage, 12);
    OSMetaClassDeclareReservedUnused(IOStorage, 13);
    OSMetaClassDeclareReservedUnused(IOStorage, 14);
    OSMetaClassDeclareReservedUnused(IOStorage, 15);
};

/*
 * Inline Functions
 */

inline void IOStorage::complete(IOStorageCompletion completion,
                                IOReturn            status,
                                UInt64              actualByteCount)
{
    /*
     * Invokes the specified completion action of the read/write request.  If
     * the completion action is unspecified, no action is taken.  This method
     * serves simply as a convenience to storage subclass developers.
     */

    if (completion.action)  (*completion.action)(completion.target, 
                                                 completion.parameter,
                                                 status,
                                                 actualByteCount);
}

#endif /* defined(KERNEL) && defined(__cplusplus) */

#endif /* !_IOSTORAGE_H */

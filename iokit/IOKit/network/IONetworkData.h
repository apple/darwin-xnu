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
/*
 * Copyright (c) 1998 Apple Computer, Inc.  All rights reserved. 
 *
 * IONetworkData.h
 *
 * HISTORY
 * 21-Apr-1999      Joe Liu (jliu) created.
 *
 */

#ifndef _IONETWORKDATA_H
#define _IONETWORKDATA_H

#define IONetworkParameter IONetworkData  // FIXME

/*! @enum An enumeration of constants that describe access types.
    @constant kIONetworkDataAccessTypeRead  Read access.
    @constant kIONetworkDataAccessTypeWrite Write access.
    @constant kIONetworkDataAccessTypeReset Reset access.
    @constant kIONetworkDataAccessTypeSerialize Serialization access. */

enum {
    kIONetworkDataAccessTypeRead        = 0x01,
    kIONetworkDataAccessTypeWrite       = 0x02,
    kIONetworkDataAccessTypeReset       = 0x04,
    kIONetworkDataAccessTypeSerialize   = 0x08,
    kIONetworkDataAccessTypeMask        = 0xff,
};

/*! @define kIONetworkDataBasicAccessTypes
    @discussion The default access types supported by an IONetworkData
    object. Allow read() and serialize(). */

#define kIONetworkDataBasicAccessTypes \
       (kIONetworkDataAccessTypeRead | kIONetworkDataAccessTypeSerialize)

/*! @enum An enumeration of the type of data buffers that can be
    managed by an IONetworkData object.
    @constant kIONetworkDataBufferTypeInternal An internal data buffer
              allocated by the init() method.
    @constant kIONetworkDataBufferTypeExternal An external (persistent) data
              buffer.
    @constant kIONetworkDataBufferTypeNone No data buffer. The only useful 
              action perfomed by an IONetworkData object with this buffer type 
              is to call the access notification handler. */

enum {
    kIONetworkDataBufferTypeInternal = 0,
    kIONetworkDataBufferTypeExternal,
    kIONetworkDataBufferTypeNone,
};

/*! @defined kIONetworkDataBytes
    @abstract kIONetworkDataBytes is a property of IONetworkData objects.
        It has an OSData value.
    @discussion The kIONetworkDataBytes property is an OSData that describes
        the data buffer of an IONetworkData object. This property is present
        only if kIONetworkDataAccessTypeSerialize access is supported. */

#define kIONetworkDataBytes             "Data"

/*! @defined kIONetworkDataAccessTypes
    @abstract kIONetworkDataAccessTypes is a property of IONetworkData
        objects. It has an OSNumber value.
    @discussion The kIONetworkDataAccessTypes property is an OSNumber that
        describes the supported access types of an IONetworkData object. */

#define kIONetworkDataAccessTypes       "Access Types"

/*! @defined kIONetworkDataSize
    @abstract kIONetworkDataSize is a property of IONetworkData
        objects. It has an OSNumber value.
    @discussion The kIONetworkDataSize property is an OSNumber that
        describes the size of the data buffer of an IONetworkData object. */

#define kIONetworkDataSize              "Size"

#ifdef KERNEL

#include <libkern/c++/OSSymbol.h>
#include <libkern/c++/OSSerialize.h>

/*! @class IONetworkData : public OSObject
    An IONetworkData object manages a fixed-size named buffer.
    This object provides external access methods that can be used to
    access the contents of the data buffer. In addition, serialization
    is supported, and therefore this object can be added to a property
    table to publish the data object. An unique name must be assigned to
    the object during initialization. An OSSymbol key will be created
    based on the assigned name, and this key can be used when the object
    is added to a dictionary.

    The level of access granted to the access methods can be restricted,
    by specifying a set of supported access types when the object is
    initialized, or modified later by calling setAccessTypes(). By default,
    each IONetworkData object created will support serialization, and will
    also allow its data buffer to be read through the read() access method.

    An access notification handler, in the form of a 'C' function, can
    be registered to receive a call each time the data buffer is accessed
    through an access method. Arguments provided to the handler will identify 
    the data object and the type of access that triggered the notification.
    The handler can therefore perform lazy update of the data buffer until
    an interested party tries to read or serialize the data. The notification
    handler can also take over the default action performed by the access
    methods when the buffer type is set to kIONetworkDataBufferTypeNone.
    This will prevent the access methods from accessing the data buffer,
    and allow the handler to override the access protocol.

    This object is primarily used by IONetworkInterface to export interface
    properties to user space. */


class IONetworkData : public OSObject
{
    OSDeclareDefaultStructors( IONetworkData )

public:

/*! @typedef Action
    Defines a C function that may be called by an IONetworkData object
    when one of its access methods is called.
    @param target The target of the notification.
    @param param A parameter that was provided when the notification
           handler was registered.
    @param data The IONetworkData object being accessed, and the
           sender of the notification.
    @param accessType A bit will be set indicating the type of access
           which triggered the notification.
    @param buffer Pointer to the accessor's buffer. Only valid for
           read() and write() accesses.
    @param bufferSize Pointer to the size of the accessor's buffer.
    @param offset An offset from the start of the data buffer to begin
           reading or writing. */

    typedef IOReturn (*Action)(void *           target,
                               void *           param,
                               IONetworkData *  data,
                               UInt32           accessType,
                               void *           buffer,
                               UInt32 *         bufferSize,
                               UInt32           offset);

protected:
    const OSSymbol *  _key;        // key associated with this object.
    UInt32            _access;     // supported access types.
    void *            _buffer;     // Data buffer.
    UInt32            _bufType;    // buffer type
    UInt32            _size;       // data buffer size.
    void *            _tapTarget;  // target for access notification.
    Action            _tapAction;  // the function to call.
    void *            _tapParam;   // arbitrary notification param.

    struct ExpansionData { };
    /*! @var reserved
        Reserved for future use.  (Internal use only)  */
    ExpansionData *	_reserved;


/*! @function free
    @abstract Free the IONetworkData object. */

    virtual void free();

/*! @function writeBytes
    @abstract Write to the data buffer with data from a source buffer
    provided by the caller.
    @param srcBuffer Pointer to a source buffer provided by the caller.
    @param srcBufferSize The size of the source buffer.
    @param writeOffset A byte offset from the start of the data buffer
           to begin writting.
    @result true if the operation was successful, false otherwise. */

    virtual bool writeBytes(const void * srcBuffer,
                            UInt32       srcBufferSize,
                            UInt32       writeOffset = 0);

/*! @function readBytes
    @abstract Read from the data buffer and copy the data to a destination
    buffer provided by the caller.
    @param dstBuffer Pointer to the destination buffer.
    @param dstBufferSize Pointer to an integer containing the size of the
    destination buffer. And is overwritten by this method with the actual
    number of bytes copied to the destination buffer.
    @param readOffset A byte offset from the start of the data buffer
           to begin reading.
    @result true if the operation was successful, false otherwise. */

    virtual bool readBytes(void *   dstBuffer,
                           UInt32 * dstBufferSize,
                           UInt32   readOffset = 0) const;

/*! @function clearBuffer
    @abstract Clear the data buffer by filling it with zeroes.
    @result true if the operation was successful, false otherwise. */

    virtual bool clearBuffer();

public:

/*! @function initialize
    @abstract IONetworkData class initializer. */

    static void initialize();

/*! @function withInternalBuffer
    @abstract Factory method that will construct and initialize an
    IONetworkData object with an internal data buffer.
    @param name A name to assign to this object.
    @param bufferSize The number of bytes to allocate for the internal data
           buffer.
    @param accessTypes The initial supported access types.
    @param target The notification target.
    @param action The notification action.
    @param param A parameter to pass to the notification action.
    @result An IONetworkData object on success, or 0 otherwise. */

    static IONetworkData *
           withInternalBuffer(const char * name,
                              UInt32       bufferSize,
                              UInt32       accessTypes = 
                                           kIONetworkDataBasicAccessTypes,
                              void *       target = 0,
                              Action       action = 0,
                              void *       param  = 0);

/*! @function withExternalBuffer
    @abstract Factory method that will construct and initialize an
    IONetworkData object with an external data buffer.
    @param name A name to assign to this object.
    @param bufferSize The size of the external data buffer.
    @param externalBuffer Pointer to the external data buffer.
    @param accessTypes The initial supported access types.
    @param target The notification target.
    @param action The notification action.
    @param param A parameter to pass to the notification action.
    @result An IONetworkData object on success, or 0 otherwise. */

    static IONetworkData *
           withExternalBuffer(const char * name,
                              UInt32       bufferSize,
                              void *       externalBuffer,
                              UInt32       accessTypes =
                                           kIONetworkDataBasicAccessTypes,
                              void *       target = 0,
                              Action       action = 0,
                              void *       param  = 0);

/*! @function withNoBuffer
    @abstract Factory method that will construct and initialize an
    IONetworkData object without a data buffer. The notification handler
    must intervene when the IONetworkData is accessed.
    @param name A name to assign to this object.
    @param bufferSize The size of the phantom data buffer.
    @param accessTypes The initial supported access types.
    @param target The notification target.
    @param action The notification action.
    @param param A parameter to pass to the notification action.
    @result An IONetworkData object on success, or 0 otherwise. */

    static IONetworkData * withNoBuffer(const char * name,
                                        UInt32       bufferSize,
                                        UInt32       accessTypes,
                                        void *       target,
                                        Action       action,
                                        void *       param = 0);

/*! @function init
    @abstract Initialize an IONetworkData object.
    @param name A name to assign to this object.
    @param bufferType The type of buffer associated with this object.
    @param bufferSize The size of the data buffer.
    @param externalBuffer Pointer to an external data buffer.
    @param accessTypes The initial supported access types.
           Can be later modified by calling setAccessTypes().
    @param target The notification target.
    @param action The notification action.
    @param param A parameter to pass to the notification action.
    @result true if initialized successfully, false otherwise. */

    virtual bool init(const char * name,
                      UInt32       bufferType,
                      UInt32       bufferSize,
                      void *       externalBuffer = 0,
                      UInt32       accessTypes    =
                                   kIONetworkDataBasicAccessTypes,
                      void *       target         = 0,
                      Action       action         = 0,
                      void *       param          = 0);

/*! @function setAccessTypes
    @abstract Set the types of access that are permitted on the data buffer.
    @param types A mask of access types indicating the supported access
                 types. */

    virtual void setAccessTypes(UInt32 types);

/*! @function setNotificationTarget
    @abstract Register a C function to handle access notifications sent
    from this object.
    @discussion A notification is sent by an IONetworkData object to the
    registered notification handler, when an access method is called to
    modify the contents of the data buffer.
    @param target The first parameter passed to the notification handler.
    @param action A pointer to a C function that will handle the notification.
           If 0, then notification is disabled.
    @param param An optional parameter passed to the notification handler. */

    virtual void setNotificationTarget(void *  target,
                                       Action  action,
                                       void *  param = 0);

/*! @function getBuffer
    @abstract Get a pointer to the data buffer.
    @result A pointer to the data buffer. Returns 0 if the buffer type is
            kIONetworkDataBufferTypeNone. */

    virtual const void *     getBuffer() const;

/*! @function getBufferType
    @abstract Get the type of data buffer managed by this object.
    @result A constant that describes the type of the data buffer. */

    virtual UInt32           getBufferType() const;

/*! @function getAccessTypes
    @abstract Get the types of data access supported by this object.
    @result A mask of supported access types. */

    virtual UInt32           getAccessTypes() const;

/*! @function getNotificationTarget
    @abstract Get the first parameter that will be passed to the access
              notification handler.
    @result The first parameter that will be passed to the access notification
            handler. */

    virtual void *           getNotificationTarget() const;

/*! @function getNotificationAction
    @abstract Get the C function that was registered to handle access
              notifications sent from this object.
    @result A pointer to a C function, or 0 if notification is disabled. */

    virtual Action           getNotificationAction() const;

/*! @function getNotificationParameter
    @abstract Get the parameter that will be passed to the access
              notification handler.
    @result The parameter that will be passed to the access notification
            handler. */

    virtual void *           getNotificationParameter() const;

/*! @function getKey
    @abstract Get an unique OSSymbol key associated with this object.
    @discussion During initialization, IONetworkData will create an
    OSSymbol key based on its assigned name.
    @result An OSSymbol key that was generated from the name assigned to
    this object. */

    virtual const OSSymbol * getKey() const;

/*! @function getSize
    @abstract Get the size of the data buffer.
    @result The size of the data buffer managed by this object in bytes. */

    virtual UInt32           getSize() const;

/*! @function reset
    @abstract An access method to reset the data buffer.
    @discussion Handle an external request to reset the data buffer.
    If notication is enabled, then the notification handler is called
    after the data buffer has been cleared.
    @result kIOReturnSuccess on success,
            kIOReturnNotWritable if reset access is not permitted,
            or an error from the notification handler. */

    virtual IOReturn reset();

/*! @function read
    @abstract An access method to read from the data buffer.
    @discussion Handle an external request to read from the data buffer
    and copy it to the destination buffer provided by the accessor.
    If notification is enabled, then the notification handler is called
    before the data buffer is copied to the destination buffer. The 
    notification handler may use this opportunity to intervene and
    to update the contents of the data buffer.
    @param dstBuffer Pointer to the destination buffer.
    @param dstBufferSize Pointer to an integer containing the size of the
    destination buffer. And is overwritten by this method to the actual number
    of bytes copied to the destination buffer.
    @param readOffset An offset from the start of the source data buffer to
    begin reading.
    @result kIOReturnSuccess on success,
            kIOReturnBadArgument if any of the arguments provided is invalid,
            kIOReturnNotReadable if read access is not permitted,
            or an error from the notification handler. */

    virtual IOReturn read(void *   dstBuffer,
                          UInt32 * dstBufferSize,
                          UInt32   readOffset = 0);

/*! @function write
    @abstract An access method to write to the data buffer.
    @discussion Handle an external request to write to the data buffer
    from a source buffer provided by the accessor. After checking that
    the data object supports write accesses, the data buffer is updated
    if it exists. Then the registered notification handler is called.
    @param srcBuffer Pointer to the source buffer.
    @param srcBufferSize The number of bytes to write to the data buffer.
    @param writeOffset An offset from the start of the destination data buffer
    to begin writing.
    @result kIOReturnSuccess on success,
            kIOReturnBadArgument if any of the arguments provided is invalid,
            kIOReturnNotWritable if write access is not permitted,
            or an error from the notification handler. */

    virtual IOReturn write(void *  srcBuffer,
                           UInt32  srcBufferSize,
                           UInt32  writeOffset = 0);

/*! @function serialize
    @abstract Serialize the IONetworkData object.
    @discussion If notification is enabled, then the notification
    handler is called just before the data buffer is serialized.
    @param s An OSSerialize object.
    @result true on success, false otherwise. */

    virtual bool serialize(OSSerialize * s) const;

    // Virtual function padding
    OSMetaClassDeclareReservedUnused( IONetworkData,  0);
    OSMetaClassDeclareReservedUnused( IONetworkData,  1);
    OSMetaClassDeclareReservedUnused( IONetworkData,  2);
    OSMetaClassDeclareReservedUnused( IONetworkData,  3);
};

#endif /* KERNEL */

#endif /* !_IONETWORKDATA_H */

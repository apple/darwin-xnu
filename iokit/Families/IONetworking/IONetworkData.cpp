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
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved. 
 *
 * IONetworkData.cpp
 */

#include <IOKit/assert.h>
#include <IOKit/IOLib.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSData.h>
#include <IOKit/network/IONetworkData.h>

#define super OSObject
OSDefineMetaClassAndStructors( IONetworkData, OSObject )
OSMetaClassDefineReservedUnused( IONetworkData,  0);
OSMetaClassDefineReservedUnused( IONetworkData,  1);
OSMetaClassDefineReservedUnused( IONetworkData,  2);
OSMetaClassDefineReservedUnused( IONetworkData,  3);

#define TAP_IS_VALID    (_tapAction)

// All access method are serialized by a single global lock,
// shared among all IONetworkData instances.
//
static  IOLock * gIONDLock = 0;
#define LOCK     IOTakeLock(gIONDLock)
#define UNLOCK   IOUnlock(gIONDLock)

static const OSSymbol * gIONDDataKey;
static const OSSymbol * gIONDAccessKey;
static const OSSymbol * gIONDSizeKey;

//---------------------------------------------------------------------------
// IONetworkData class initializer.

void IONetworkData::initialize()
{
    // Allocates the global data lock.
    //
    gIONDLock = IOLockAlloc();
    assert(gIONDLock);
    IOLockInitWithState(gIONDLock, kIOLockStateUnlocked);

    gIONDDataKey   = OSSymbol::withCStringNoCopy( kIONetworkDataBytes ); 
    gIONDAccessKey = OSSymbol::withCStringNoCopy( kIONetworkDataAccessTypes );
    gIONDSizeKey   = OSSymbol::withCStringNoCopy( kIONetworkDataSize );

    assert(gIONDDataKey && gIONDAccessKey && gIONDSizeKey);
}

//---------------------------------------------------------------------------
// Initialize an IONetworkData instance.

bool
IONetworkData::init(const char * name,
                    UInt32       bufferType,
                    UInt32       bufferSize,
                    void *       extBuffer   = 0,
                    UInt32       accessTypes = kIONetworkDataBasicAccessTypes,
                    void *       target = 0,
                    Action       action = 0,
                    void *       param  = 0)
{
    if ((bufferType == kIONetworkDataBufferTypeInternal) ||
        (bufferType == kIONetworkDataBufferTypeExternal))
    {
        _buffer = (bufferType == kIONetworkDataBufferTypeInternal) ?
                  (void *) kalloc(bufferSize) : extBuffer;

        if (_buffer == 0)
            return false;

        if (bufferType == kIONetworkDataBufferTypeInternal)
            bzero(_buffer, bufferSize);
    }

    _bufType   = bufferType;
    _access    = accessTypes;
    _tapTarget = target;
    _tapAction = action;
    _tapParam  = param;
    _size      = bufferSize;

    // Generate a key for this object based on its assigned name.
    //
    if ((_key = OSSymbol::withCString(name)) == 0)
        return false;

    return true;
}

//---------------------------------------------------------------------------
// Factory method that will construct and initialize an IONetworkData
// instance with an internal buffer.

IONetworkData *
IONetworkData::withInternalBuffer(
                   const char * name,
                   UInt32       bufferSize,
                   UInt32       accessTypes = kIONetworkDataBasicAccessTypes,
                   void *       target = 0,
                   Action       action = 0,
                   void *       param  = 0)
{
    IONetworkData * aData = new IONetworkData;
    
    if (aData && !aData->init(name,
                              kIONetworkDataBufferTypeInternal,
                              bufferSize,
                              0,
                              accessTypes,
                              target,
                              action,
                              param))
    {
        aData->release();
        aData = 0;
    }
    return aData;
}

//---------------------------------------------------------------------------
// Factory method that will construct and initialize an IONetworkData
// instance with an external buffer.

IONetworkData *
IONetworkData::withExternalBuffer(
                   const char * name,
                   UInt32       bufferSize,
                   void *       buffer,
                   UInt32       accessTypes = kIONetworkDataBasicAccessTypes,
                   void *       target = 0,
                   Action       action = 0,
                   void *       param  = 0)
{
    IONetworkData * aData = new IONetworkData;
    
    if (aData && !aData->init(name,
                              kIONetworkDataBufferTypeExternal,
                              bufferSize,
                              buffer,
                              accessTypes,
                              target,
                              action,
                              param))
    {
        aData->release();
        aData = 0;
    }
    return aData;
}

//---------------------------------------------------------------------------
// Factory method that will construct and initialize an IONetworkData
// instance with no data buffer. The notification handler must intervene
// when the IONetworkData is accessed.

IONetworkData *
IONetworkData::withNoBuffer(const char * name,
                            UInt32       bufferSize,
                            UInt32       accessTypes,
                            void *       target,
                            Action       action,
                            void *       param = 0)
{
    IONetworkData * aData = new IONetworkData;
    
    if (aData && !aData->init(name,
                              kIONetworkDataBufferTypeNone,
                              bufferSize,
                              0,
                              accessTypes,
                              target,
                              action,
                              param))
    {
        aData->release();
        aData = 0;
    }
    return aData;
}

//---------------------------------------------------------------------------
// Free the IONetworkData instance.

void IONetworkData::free()
{
    if (_key)
        _key->release();

    if (_buffer && (_bufType == kIONetworkDataBufferTypeInternal))
        kfree((vm_offset_t) _buffer, _size);

    super::free();
}

//---------------------------------------------------------------------------
// Return the type of buffer managed by this instance.
// See IONetworkDataBufferType enum definition

UInt32 IONetworkData::getBufferType() const
{
    return _bufType;
}

//---------------------------------------------------------------------------
// Change the supported access types.

#define kIONetworkDataImmutableAccessTypes   0

void IONetworkData::setAccessTypes(UInt32 types)
{
    LOCK;
    _access = (_access & kIONetworkDataImmutableAccessTypes) |
              (types & ~kIONetworkDataImmutableAccessTypes);
    UNLOCK;
}

//---------------------------------------------------------------------------
// Register a target/action to handle access notification.

void IONetworkData::setNotificationTarget(void *  target,
                                          Action  action,
                                          void *  param)
{
    LOCK;
    _tapTarget = target;
    _tapAction = action;
    _tapParam  = param;
    UNLOCK;
}

//---------------------------------------------------------------------------
// Return the supported access types.

UInt32 IONetworkData::getAccessTypes() const
{
    return _access;
}

//---------------------------------------------------------------------------
// Return the notification target.

void * IONetworkData::getNotificationTarget() const
{
    return _tapTarget;
}

//---------------------------------------------------------------------------
// Return the notification action.

IONetworkData::Action IONetworkData::getNotificationAction() const
{
    return _tapAction;
}

//---------------------------------------------------------------------------
// Return the notification parameter.

void * IONetworkData::getNotificationParameter() const
{
    return _tapParam;
}

//---------------------------------------------------------------------------
// Get an OSSymbol key associated with this instance.
// During initialization, IONetworkData will create an OSSymbol
// key based on its assigned name.
//
// Return an OSSymbol key generated from the assigned name.

const OSSymbol * IONetworkData::getKey() const
{
    return _key;
}

//---------------------------------------------------------------------------
// Return the size of the data managed by this instance in bytes.

UInt32 IONetworkData::getSize() const
{
    return _size;
}

//---------------------------------------------------------------------------
// Write to the data buffer with data from a source buffer provided
// by the caller.

bool IONetworkData::writeBytes(const void * srcBuffer,
                               UInt32       srcBufferSize,
                               UInt32       writeOffset)
{
    if ( _buffer == 0 ) return false;

    if ( srcBufferSize          &&
         (writeOffset < _size)  &&
         ((writeOffset + srcBufferSize) <= _size) )
    {
        bcopy(srcBuffer, (char *) _buffer + writeOffset, srcBufferSize);
        return true;
    }

    return false;
}

//---------------------------------------------------------------------------
// Return a pointer to the data buffer.

const void * IONetworkData::getBuffer() const
{
    return (_buffer) ? _buffer : 0;
}

//---------------------------------------------------------------------------
// Copy the data buffer to a destination buffer provided by the caller.

bool IONetworkData::readBytes(void *   dstBuffer,
                              UInt32 * dstBufferSize,
                              UInt32   readOffset) const
{
    if ( _buffer == 0 ) return false;

    if ( *dstBufferSize && (readOffset < _size) )
    {
        UInt32 bytesCopied = min((_size - readOffset), *dstBufferSize);

        bcopy((char *) _buffer + readOffset, dstBuffer, bytesCopied);

        *dstBufferSize = bytesCopied;

        return true;
    }
    
    return false;
}

//---------------------------------------------------------------------------
// Clear the entire data buffer by filling it with zeroes.

bool IONetworkData::clearBuffer()
{
    if ( _buffer )
    {
        bzero((void *) _buffer, _size);
        return true;
    }
    return false;
}

//---------------------------------------------------------------------------
// Handle a user space request to reset the data buffer.

IOReturn IONetworkData::reset()
{
    IOReturn ret = kIOReturnUnsupported;

    LOCK;

    do {
        // Check access.

        if ( (_access & kIONetworkDataAccessTypeReset) == 0 )
        {
            ret = kIOReturnNotWritable;
            break;
        }

        // Default action is to bzero the entire buffer.

        if ( clearBuffer() )
        {
            ret = kIOReturnSuccess;
        }

        // Notify our target.

        if ( TAP_IS_VALID )
        {
            ret = (*_tapAction)(_tapTarget, _tapParam,
                                this,
                                (UInt32) kIONetworkDataAccessTypeReset,
                                0, 0, 0);
        }
    }
    while (0);

    UNLOCK;

    return ret;
}

//---------------------------------------------------------------------------
// Handle an external request to read from the data buffer
// and copy it to the destination buffer provided by the accessor.

IOReturn IONetworkData::read(void *   dstBuffer,
                             UInt32 * dstBufferSize,
                             UInt32   readOffset)
{
    IOReturn ret = kIOReturnUnsupported;

    LOCK;

    do {
        // Check the arguments.

        if ( !dstBuffer || !dstBufferSize )
        {
            ret = kIOReturnBadArgument;
            break;
        }

        // Check access.

        if ( (_access & kIONetworkDataAccessTypeRead) == 0 )
        {
            ret = kIOReturnNotReadable;
            break;
        }

        // Notify the target before the read operation.
        // The target can take this opportunity to update the
        // data buffer. If the target returns an error,
        // abort and return the error.

        if ( TAP_IS_VALID )
        {
            ret = (*_tapAction)(_tapTarget, _tapParam,
                                this,
                                (UInt32) kIONetworkDataAccessTypeRead,
                                dstBuffer,
                                dstBufferSize,
                                readOffset);
            if (ret != kIOReturnSuccess)
                break;
        }

        if ( _buffer )
        {
            ret = readBytes(dstBuffer, dstBufferSize, readOffset) ?
                  kIOReturnSuccess : kIOReturnBadArgument;
        }
    }
    while (0);

    UNLOCK;

    return ret;
}

//---------------------------------------------------------------------------
// Handle an external request to write to the data buffer
// from a source buffer provided by the accessor.

IOReturn IONetworkData::write(void *  srcBuffer,
                              UInt32  srcBufferSize,
                              UInt32  writeOffset)
{
    IOReturn ret = kIOReturnUnsupported;

    LOCK;

    do {
        // Check the arguments.

        if ( srcBuffer == 0 )
        {
            ret = kIOReturnBadArgument;
            break;
        }

        // Check access.

        if ( (_access & kIONetworkDataAccessTypeWrite) == 0 )
        {
            ret = kIOReturnNotWritable;
            break;
        }

        // Update the data buffer.

        if ( _buffer &&
             (writeBytes(srcBuffer, srcBufferSize, writeOffset) == false) )
        {
            ret = kIOReturnBadArgument;
            break;
        }

        // Notify the target after a successful write operation.

        if ( TAP_IS_VALID )
        {
            ret = (*_tapAction)(_tapTarget, _tapParam,
                                this,
                                (UInt32) kIONetworkDataAccessTypeWrite,
                                srcBuffer,
                                &srcBufferSize,
                                writeOffset);
        }
    }
    while (0);

    UNLOCK;

    return ret;
}

//---------------------------------------------------------------------------
// Serialize the IONetworkData object. If notification is enabled,
// then the notification handler is called before the data buffer is 
// serialized.

bool IONetworkData::serialize(OSSerialize * s) const
{
    bool           ok;
    OSDictionary * dictToSerialize;
    OSData *       dataEntry;
    OSNumber *     numberEntry;

    dictToSerialize = OSDictionary::withCapacity(3);
    if (!dictToSerialize)
        return false;

    numberEntry = OSNumber::withNumber(_access, sizeof(_access) * 8);
    if (numberEntry) {
        dictToSerialize->setObject(gIONDAccessKey, numberEntry);
        numberEntry->release();
    }

    numberEntry = OSNumber::withNumber(_size, sizeof(_size) * 8);
    if (numberEntry) {
        dictToSerialize->setObject(gIONDSizeKey, numberEntry);
        numberEntry->release();
    }

    LOCK;

    do {
        // Check access.

        if ((_access & kIONetworkDataAccessTypeSerialize) == 0)
            break;

        if (_buffer == 0)
            break;

        // Notify the target before the read operation.
        // The target can take this opportunity to update the
        // data buffer. If the target returns an error,
        // then the data buffer is not serialized.

        if (TAP_IS_VALID &&
            ((*_tapAction)(_tapTarget, _tapParam,
                           (IONetworkData *) this,
                           kIONetworkDataAccessTypeSerialize,
                           0, 0, 0) != kIOReturnSuccess))
        {
            break;
        }

        dataEntry = OSData::withBytesNoCopy(_buffer, _size);
        if (dataEntry) {
            dictToSerialize->setObject(gIONDDataKey, dataEntry);
            dataEntry->release();
        }
    }
    while (0);

    ok = dictToSerialize->serialize(s);
    dictToSerialize->release();

    UNLOCK;

    return ok;
}

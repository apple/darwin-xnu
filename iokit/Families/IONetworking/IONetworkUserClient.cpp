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
 * HISTORY
 *
 *
 */

#include <IOKit/assert.h>
#include <IOKit/network/IONetworkInterface.h>
#include <IOKit/network/IONetworkUserClient.h>
#include <IOKit/network/IONetworkData.h>

//------------------------------------------------------------------------

#define super IOUserClient
OSDefineMetaClassAndStructors( IONetworkUserClient, IOUserClient )

#ifdef  DEBUG
#define DLOG(fmt, args...)  IOLog(fmt, ## args)
#else
#define DLOG(fmt, args...)
#endif

//---------------------------------------------------------------------------
// Factory method that performs allocation and initialization
// of an IONetworkUserClient instance.

IONetworkUserClient * IONetworkUserClient::withTask(task_t owningTask)
{
    IONetworkUserClient * me;

    me = new IONetworkUserClient;
    if (me)
    {
        if (!me->init())
        {
            me->release();
            return 0;
        }
        me->_task = owningTask;
    }
    return me;
}

//---------------------------------------------------------------------------
// Start the IONetworkUserClient.

bool IONetworkUserClient::start(IOService * provider)
{
    UInt32 i;

    _owner = OSDynamicCast(IONetworkInterface, provider);
    assert(_owner);

    if (!super::start(_owner))
        return false;

    if (!_owner->open(this))
        return false;

    // Initialize the call structures.
    //
    i = kIONUCResetNetworkDataIndex;
    _methods[i].object = this;
    _methods[i].func   = (IOMethod) &IONetworkUserClient::resetNetworkData;
    _methods[i].count0 = kIONUCResetNetworkDataInputs;
    _methods[i].count1 = kIONUCResetNetworkDataOutputs;
    _methods[i].flags  = kIONUCResetNetworkDataFlags;

    i = kIONUCWriteNetworkDataIndex;
    _methods[i].object = this;
    _methods[i].func   = (IOMethod) &IONetworkUserClient::writeNetworkData;
    _methods[i].count0 = kIONUCWriteNetworkDataInput0;
    _methods[i].count1 = kIONUCWriteNetworkDataInput1;
    _methods[i].flags  = kIONUCWriteNetworkDataFlags;

    i = kIONUCReadNetworkDataIndex;
    _methods[i].object = this;
    _methods[i].func   = (IOMethod) &IONetworkUserClient::readNetworkData;
    _methods[i].count0 = kIONUCReadNetworkDataInputs;
    _methods[i].count1 = kIONUCReadNetworkDataOutputs;
    _methods[i].flags  = kIONUCReadNetworkDataFlags;

    i = kIONUCGetNetworkDataCapacityIndex;
    _methods[i].object = this;
    _methods[i].func   = (IOMethod) 
                         &IONetworkUserClient::getNetworkDataCapacity;
    _methods[i].count0 = kIONUCGetNetworkDataCapacityInputs;
    _methods[i].count1 = kIONUCGetNetworkDataCapacityOutputs;
    _methods[i].flags  = kIONUCGetNetworkDataCapacityFlags;

    i = kIONUCGetNetworkDataHandleIndex;
    _methods[i].object = this;
    _methods[i].func   = (IOMethod) &IONetworkUserClient::getNetworkDataHandle;
    _methods[i].count0 = kIONUCGetNetworkDataHandleInputs;
    _methods[i].count1 = kIONUCGetNetworkDataHandleOutputs;
    _methods[i].flags  = kIONUCGetNetworkDataHandleFlags;

    return true;
}

//---------------------------------------------------------------------------
// Free the IONetworkUserClient instance.

void IONetworkUserClient::free()
{
    super::free();
}

//---------------------------------------------------------------------------
// Handle a client close. Close and detach from our owner (provider).

IOReturn IONetworkUserClient::clientClose()
{
    if (_owner) {
        _owner->close(this);
        detach(_owner);
    }

    return kIOReturnSuccess;
}

//---------------------------------------------------------------------------
// Handle client death. Close and detach from our owner (provider).

IOReturn IONetworkUserClient::clientDied()
{
    return clientClose();
}

//---------------------------------------------------------------------------
// Look up an entry from the method array.

IOExternalMethod *
IONetworkUserClient::getExternalMethodForIndex(UInt32 index)
{
    if (index >= kIONUCLastIndex)
        return 0;
    else
        return &_methods[index];
}

//---------------------------------------------------------------------------
// Fill the data buffer in an IONetworkData object with zeroes.

IOReturn IONetworkUserClient::resetNetworkData(OSSymbol * key)
{
    IONetworkData * data;
    IOReturn        ret;

    data = _owner->getNetworkData(key);
    ret = data ? data->reset() : kIOReturnBadArgument;

    return ret;
}

//---------------------------------------------------------------------------
// Write to the data buffer in an IONetworkData object with data from a
// source buffer provided by the caller.

IOReturn
IONetworkUserClient::writeNetworkData(OSSymbol *   key,
                                      void *       srcBuffer,
                                      IOByteCount  srcBufferSize)
{
    IONetworkData * data;
    IOReturn        ret;

    if (!srcBuffer || (srcBufferSize == 0))
        return kIOReturnBadArgument;

    data = _owner->getNetworkData(key);
    ret = data ? data->write(srcBuffer, srcBufferSize) : kIOReturnBadArgument;

    return ret;
}

//---------------------------------------------------------------------------
// Read the data buffer in an IONetworkData object and copy
// this data to a destination buffer provided by the caller.

IOReturn
IONetworkUserClient::readNetworkData(OSSymbol *    key,
                                     void *        dstBuffer,
                                     IOByteCount * dstBufferSize)
{
    IONetworkData * data;
    IOReturn        ret ;

    if (!dstBuffer || !dstBufferSize)
        return kIOReturnBadArgument;

    data = _owner->getNetworkData(key);
    ret = data ? data->read(dstBuffer, dstBufferSize) : 
                 kIOReturnBadArgument;

    return ret;
}

//---------------------------------------------------------------------------
// Get the capacity of an IONetworkData object.

IOReturn
IONetworkUserClient::getNetworkDataCapacity(OSSymbol * key,
                                            UInt32 *   capacity)
{
    IOReturn        ret = kIOReturnBadArgument;
    IONetworkData * data;

    data = _owner->getNetworkData(key);

    if (data) {
        *capacity = data->getSize();
        ret = kIOReturnSuccess;
    }

    return ret;
}

//---------------------------------------------------------------------------
// Called to obtain a handle that maps to an IONetworkData object.
// This handle can be later passed to other methods in this class
// to refer to the same object.

IOReturn
IONetworkUserClient::getNetworkDataHandle(char *         name,
                                          OSSymbol **    handle,
                                          IOByteCount    nameSize,
                                          IOByteCount *  handleSizeP)
{
    IOReturn         ret = kIOReturnBadArgument;
    const OSSymbol * key;

    if (!name || !nameSize || (name[nameSize - 1] != '\0') ||
        (*handleSizeP != sizeof(*handle)))
        return kIOReturnBadArgument;

    key = OSSymbol::withCStringNoCopy(name);
    if (!key)
        return kIOReturnNoMemory;

    if (_owner->getNetworkData(key))
    {
        *handle = (OSSymbol *) key;
        ret = kIOReturnSuccess;
    }

    if (key)
        key->release();

    return ret;
}

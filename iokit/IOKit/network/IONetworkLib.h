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
 */

#ifndef _IONETWORKLIB_H
#define _IONETWORKLIB_H

#include <IOKit/IOKitLib.h>
#include <IOKit/network/IONetworkData.h>
#include <IOKit/network/IONetworkMedium.h>
#include <IOKit/network/IONetworkStats.h>
#include <IOKit/network/IOEthernetStats.h>
#include <IOKit/network/IONetworkUserClient.h>

typedef UInt32 IONDHandle;

#ifdef __cplusplus
extern "C" {
#endif

/*! @function IONetworkOpen
    @abstract Open a connection to an IONetworkInterface object.
    An IONetworkUserClient object is created to manage the connection. */

    IOReturn IONetworkOpen(io_object_t obj, io_connect_t * con);

/*! @function IONetworkClose
    @abstract Close the connection to an IONetworkInterface object. */

    IOReturn IONetworkClose(io_connect_t con);

/*! @function IONetworkWriteData
    @abstract Write to the buffer of a network data object.
    @param conObject The connection object.
    @param dataHandle The handle of a network data object.
    @param srcBuf The data to write is taken from this buffer.
    @param inSize The size of the source buffer.
    @result kIOReturnSuccess on success, or an error code otherwise. */

    IOReturn IONetworkWriteData(io_connect_t conObj,
                                IONDHandle   dataHandle,
                                UInt8 *      srcBuf,
                                UInt32       inSize);

/*! @function IONetworkReadData
    @abstract Read the buffer of a network data object.
    @param conObject The connection object.
    @param dataHandle The handle of a network data object.
    @param destBuf The buffer where the data read shall be written to.
    @param inOutSizeP Pointer to an integer that the caller must initialize
           to contain the size of the buffer. This function will overwrite
           it with the actual number of bytes written to the buffer.
    @result kIOReturnSuccess on success, or an error code otherwise. */

    IOReturn IONetworkReadData(io_connect_t conObj,
                                IONDHandle   dataHandle,
                                UInt8 *      destBuf,
                                UInt32 *     inOutSizeP);

/*! @function IONetworkResetData
    @abstract Fill the buffer of a network data object with zeroes.
    @param conObject The connection object.
    @param dataHandle The handle of a network data object.
    @result kIOReturnSuccess on success, or an error code otherwise. */

    IOReturn IONetworkResetData(io_connect_t conObject, IONDHandle dataHandle);

/*! @function IONetworkGetDataCapacity
    @abstract Get the capacity (in bytes) of a network data object.
    @param con The connection object.
    @param dataHandle The handle of a network data object.
    @param capacityP Upon success, the capacity is written to this address.
    @result kIOReturnSuccess on success, or an error code otherwise. */

    IOReturn IONetworkGetDataCapacity(io_connect_t conObject,
                                      IONDHandle   dataHandle,
                                      UInt32 *     capacityP);

/*! @function IONetworkGetDataHandle
    @abstract Get the handle of a network data object with the given name.
    @param con The connection object.
    @param dataName The name of the network data object.
    @param dataHandleP Upon success, the handle is written to this address.
    @result kIOReturnSuccess on success, or an error code otherwise. */

    IOReturn IONetworkGetDataHandle(io_connect_t conObject,
                                    const char * dataName,
                                    IONDHandle * dataHandleP);

#ifdef __cplusplus
}
#endif

#endif /* !_IONETWORKLIB_H */

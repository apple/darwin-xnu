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
#include <IOKit/IOLib.h>
#include <IOKit/storage/IOBlockStorageDevice.h>

#define	super	IOService
OSDefineMetaClass(IOBlockStorageDevice,IOService)
OSDefineAbstractStructors(IOBlockStorageDevice,IOService)

bool
IOBlockStorageDevice::init(OSDictionary * properties)
{
    bool result;

    result = super::init(properties);
    if (result) {
        result = setProperty(kIOBlockStorageDeviceTypeKey,
                             kIOBlockStorageDeviceTypeGeneric);
    }
    
    return(result);
}

OSMetaClassDefineReservedUnused(IOBlockStorageDevice,  0);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice,  1);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice,  2);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice,  3);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice,  4);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice,  5);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice,  6);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice,  7);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice,  8);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice,  9);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice, 10);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice, 11);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice, 12);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice, 13);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice, 14);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice, 15);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice, 16);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice, 17);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice, 18);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice, 19);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice, 20);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice, 21);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice, 22);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice, 23);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice, 24);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice, 25);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice, 26);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice, 27);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice, 28);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice, 29);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice, 30);
OSMetaClassDefineReservedUnused(IOBlockStorageDevice, 31);

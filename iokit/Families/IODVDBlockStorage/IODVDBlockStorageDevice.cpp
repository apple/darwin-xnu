/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
#include <IOKit/storage/IODVDBlockStorageDevice.h>

#define	super	IOCDBlockStorageDevice
OSDefineMetaClass(IODVDBlockStorageDevice,IOCDBlockStorageDevice)
OSDefineAbstractStructors(IODVDBlockStorageDevice,IOCDBlockStorageDevice)

bool
IODVDBlockStorageDevice::init(OSDictionary * properties)
{
    bool result;

    result = super::init(properties);
    if (result) {
        setProperty(kIOBlockStorageDeviceTypeKey,kIOBlockStorageDeviceTypeDVD);
    }

    return(result);
}

OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice,  0);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice,  1);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice,  2);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice,  3);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice,  4);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice,  5);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice,  6);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice,  7);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice,  8);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice,  9);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice, 10);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice, 11);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice, 12);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice, 13);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice, 14);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice, 15);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice, 16);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice, 17);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice, 18);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice, 19);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice, 20);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice, 21);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice, 22);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice, 23);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice, 24);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice, 25);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice, 26);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice, 27);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice, 28);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice, 29);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice, 30);
OSMetaClassDefineReservedUnused(IODVDBlockStorageDevice, 31);

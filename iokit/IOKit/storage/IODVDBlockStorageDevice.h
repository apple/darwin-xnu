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
 /* This class is the protocol for generic DVD functionality, independent of
 * the physical connection protocol (e.g. SCSI, ATA, USB).
 *
 * The APIs are the union of CDRO APIs and all
 * necessary new low-level DVD APIs.
 *
 * A subclass implements relay methods that translate our requests into
 * calls to a protocol- and device-specific provider.
 */

#ifndef	_IODVDBLOCKSTORAGEDEVICE_H
#define	_IODVDBLOCKSTORAGEDEVICE_H

#include <IOKit/IOTypes.h>
#include <IOKit/storage/IOCDBlockStorageDevice.h>
#include <IOKit/storage/IODVDTypes.h>

/* Property used for matching, so the generic driver gets the nub it wants. */
#define	kIOBlockStorageDeviceTypeDVD	"DVD"

class IOMemoryDescriptor;

class IODVDBlockStorageDevice : public IOCDBlockStorageDevice {

    OSDeclareAbstractStructors(IODVDBlockStorageDevice)

protected:

    struct ExpansionData { /* */ };
    ExpansionData * _expansionData;

public:

    /* Overrides from IORegistryEntry */
    
    virtual bool	init(OSDictionary * properties);

    /* New APIs for DVD */
    
    virtual IOReturn	reportKey(IOMemoryDescriptor *buffer,const DVDKeyClass keyClass,
                                        const UInt32 lba,const UInt8 agid,const DVDKeyFormat keyFormat) = 0;
    virtual IOReturn	sendKey(IOMemoryDescriptor *buffer,const DVDKeyClass keyClass,
                                        const UInt8 agid,const DVDKeyFormat keyFormat)			= 0;

    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice,  0);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice,  1);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice,  2);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice,  3);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice,  4);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice,  5);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice,  6);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice,  7);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice,  8);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice,  9);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice, 10);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice, 11);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice, 12);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice, 13);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice, 14);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice, 15);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice, 16);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice, 17);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice, 18);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice, 19);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice, 20);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice, 21);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice, 22);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice, 23);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice, 24);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice, 25);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice, 26);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice, 27);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice, 28);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice, 29);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice, 30);
    OSMetaClassDeclareReservedUnused(IODVDBlockStorageDevice, 31);
};
#endif

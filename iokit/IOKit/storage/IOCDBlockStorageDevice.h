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
 * IOCDBlockStorageDevice.h
 *
 * This class is the protocol for generic CDROM functionality, independent of
 * the physical connection protocol (e.g. SCSI, ATA, USB).
 *
 * The APIs are the union of CDROM (block storage) data APIs and all
 * necessary low-level CD APIs.
 *
 * A subclass implements relay methods that translate our requests into
 * calls to a protocol- and device-specific provider.
 */

#ifndef	_IOCDBLOCKSTORAGEDEVICE_H
#define	_IOCDBLOCKSTORAGEDEVICE_H

#include <IOKit/IOTypes.h>
#include <IOKit/storage/IOCDTypes.h>
#include <IOKit/storage/IOBlockStorageDevice.h>

/* Property used for matching, so the generic driver gets the nub it wants. */
#define	kIOBlockStorageDeviceTypeCDROM	"CDROM"

class IOMemoryDescriptor;

class IOCDBlockStorageDevice : public IOBlockStorageDevice {

    OSDeclareAbstractStructors(IOCDBlockStorageDevice)

protected:

    struct ExpansionData { /* */ };
    ExpansionData * _expansionData;

public:

    /* Overrides from IORegistryEntry */
    
    virtual bool	init(OSDictionary * properties);

    /*-----------------------------------------*/
    /* CD APIs                                 */
    /*-----------------------------------------*/

    virtual IOReturn	doAsyncReadCD(IOMemoryDescriptor *buffer,
                                      UInt32 block,UInt32 nblks,
                                      CDSectorArea sectorArea,
                                      CDSectorType sectorType,
                                      IOStorageCompletion completion) = 0;
    virtual UInt32	getMediaType(void)					= 0;
    virtual IOReturn	readISRC(UInt8 track,CDISRC isrc)			= 0;
    virtual IOReturn	readMCN(CDMCN mcn)					= 0;
    virtual IOReturn	readTOC(IOMemoryDescriptor * buffer)		= 0;

    /*-----------------------------------------*/
    /*  APIs exported by IOCDAudioControl      */
    /*-----------------------------------------*/

    virtual IOReturn	audioPause(bool pause)							= 0;
    virtual IOReturn	audioPlay(CDMSF timeStart,CDMSF timeStop)		= 0;
    virtual IOReturn	audioScan(CDMSF timeStart,bool reverse)	= 0;
    virtual IOReturn	audioStop()	= 0;
    virtual IOReturn	getAudioStatus(CDAudioStatus *status)				= 0;
    virtual IOReturn	getAudioVolume(UInt8 *leftVolume,UInt8 *rightVolume)			= 0;
    virtual IOReturn	setAudioVolume(UInt8 leftVolume,UInt8 rightVolume)				= 0;

    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDevice,  0);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDevice,  1);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDevice,  2);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDevice,  3);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDevice,  4);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDevice,  5);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDevice,  6);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDevice,  7);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDevice,  8);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDevice,  9);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDevice, 10);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDevice, 11);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDevice, 12);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDevice, 13);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDevice, 14);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDevice, 15);
};
#endif

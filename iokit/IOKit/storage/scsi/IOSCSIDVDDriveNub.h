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
/* This subclass implements a relay to a protocol- and device-specific provider. */

#ifndef	_IOSCSIDVDDRIVENUB_H
#define	_IOSCSIDVDDRIVENUB_H

#include <IOKit/storage/IODVDBlockStorageDevice.h>
#include <IOKit/storage/IODVDTypes.h>

class IOSCSIDVDDrive;

class IOSCSIDVDDriveNub : public IODVDBlockStorageDevice {

    OSDeclareDefaultStructors(IOSCSIDVDDriveNub)

public:

    /* Overrides from IOService */

    virtual bool	attach(IOService * provider);

    /* Overrides from IOBlockStorageDevice: */
    
    virtual IOReturn	doAsyncReadWrite(IOMemoryDescriptor *buffer,
                                            UInt32 block,UInt32 nblks,
                                            IOStorageCompletion completion);
    virtual IOReturn	doSyncReadWrite(IOMemoryDescriptor *buffer,UInt32 block,UInt32 nblks);

    /* --------------------------------------------------------------------------*/
    /* APIs used by the IOBlockStorageDevice portion of IODVDBlockStorageDevice: */
    /* --------------------------------------------------------------------------*/

    virtual IOReturn	doEjectMedia(void);
    virtual IOReturn	doFormatMedia(UInt64 byteCapacity);
    virtual UInt32	doGetFormatCapacities(UInt64 * capacities,
                                            UInt32   capacitiesMaxCount) const;
    virtual IOReturn	doLockUnlockMedia(bool doLock);
    virtual IOReturn	doSynchronizeCache(void);
    virtual char *	getVendorString(void);
    virtual char *	getProductString(void);
    virtual char *	getRevisionString(void);
    virtual char *	getAdditionalDeviceInfoString(void);
    virtual IOReturn	reportBlockSize(UInt64 *blockSize);
    virtual IOReturn	reportEjectability(bool *isEjectable);
    virtual IOReturn	reportLockability(bool *isLockable);
    virtual IOReturn	reportPollRequirements(bool *pollIsRequired,bool *pollIsExpensive);
    virtual IOReturn	reportMaxReadTransfer(UInt64 blockSize,UInt64 *max);
    virtual IOReturn	reportMaxValidBlock(UInt64 *maxBlock);
    virtual IOReturn	reportMaxWriteTransfer(UInt64 blockSize,UInt64 *max);
    virtual IOReturn	reportMediaState(bool *mediaPresent,bool *changed);    
    virtual IOReturn	reportRemovability(bool *isRemovable);
    virtual IOReturn	reportWriteProtection(bool *isWriteProtected);

    /*-----------------------------------------*/
    /* CD APIs                                 */
    /*-----------------------------------------*/

    virtual IOReturn	doAsyncReadCD(IOMemoryDescriptor *buffer,
                                      UInt32 block,UInt32 nblks,
                                      CDSectorArea sectorArea,
                                      CDSectorType sectorType,
                                      IOStorageCompletion completion);
    virtual UInt32	getMediaType(void);
    virtual IOReturn	readISRC(UInt8 track,CDISRC isrc);
    virtual IOReturn	readMCN(CDMCN mcn);
    virtual IOReturn	readTOC(IOMemoryDescriptor * buffer);

    /*-----------------------------------------*/
    /*  APIs exported by IOCDAudioControl      */
    /*-----------------------------------------*/

    virtual IOReturn	audioPause(bool pause);
    virtual IOReturn	audioPlay(CDMSF timeStart,CDMSF timeStop);
    virtual IOReturn	audioScan(CDMSF timeStart,bool reverse);
    virtual IOReturn	audioStop();
    virtual IOReturn	getAudioStatus(CDAudioStatus *status);
    virtual IOReturn	getAudioVolume(UInt8 *leftVolume,UInt8 *rightVolume);
    virtual IOReturn	setAudioVolume(UInt8 leftVolume,UInt8 rightVolume);

    /* DVD APIs beyond standard CD APIs: */

    virtual IOReturn	reportKey(IOMemoryDescriptor *buffer,const DVDKeyClass keyClass,
                                        const UInt32 lba,const UInt8 agid,const DVDKeyFormat keyFormat);
    virtual IOReturn	sendKey(IOMemoryDescriptor *buffer,const DVDKeyClass keyClass,
                                        const UInt8 agid,const DVDKeyFormat keyFormat);
protected:

    IOSCSIDVDDrive *	_provider;

};
#endif

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
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOLib.h>
#include <IOKit/storage/IODVDBlockStorageDevice.h>
#include <IOKit/storage/scsi/IOSCSIDVDDriveNub.h>
#include <IOKit/storage/scsi/IOSCSIDVDDrive.h>

#define	super	IODVDBlockStorageDevice
OSDefineMetaClassAndStructors(IOSCSIDVDDriveNub,IODVDBlockStorageDevice)

bool
IOSCSIDVDDriveNub::attach(IOService * provider)
{
    if (!super::attach(provider)) {
        return(false);
    }

    _provider = OSDynamicCast(IOSCSIDVDDrive,provider);
    if (_provider == NULL) {
        return(false);
    } else {
        return(true);
    }
}

IOReturn
IOSCSIDVDDriveNub::audioPause(bool pause)
{
    return(_provider->audioPause(pause));
}

IOReturn
IOSCSIDVDDriveNub::audioPlay(CDMSF timeStart,CDMSF timeStop)
{
    return(_provider->audioPlay(timeStart,timeStop));
}

IOReturn
IOSCSIDVDDriveNub::audioScan(CDMSF timeStart,bool reverse)
{
    return(_provider->audioScan(timeStart,reverse));
}

IOReturn
IOSCSIDVDDriveNub::audioStop()
{
    return(_provider->audioStop());
}

IOReturn
IOSCSIDVDDriveNub::doAsyncReadCD(IOMemoryDescriptor *buffer,
                                 UInt32 block,UInt32 nblks,
                                 CDSectorArea sectorArea,
                                 CDSectorType sectorType,
                                 IOStorageCompletion completion)
{
    return(_provider->doAsyncReadCD(buffer,block,nblks,
                                    sectorArea,sectorType,
                                    completion));
}

IOReturn
IOSCSIDVDDriveNub::doAsyncReadWrite(IOMemoryDescriptor *buffer,
                                            UInt32 block,UInt32 nblks,
                                            IOStorageCompletion completion)
{
    return(_provider->doAsyncReadWrite(buffer,block,nblks,completion));
}

IOReturn
IOSCSIDVDDriveNub::doSyncReadWrite(IOMemoryDescriptor *buffer,UInt32 block,UInt32 nblks)
{
    return(_provider->doSyncReadWrite(buffer,block,nblks));
}

IOReturn
IOSCSIDVDDriveNub::doEjectMedia(void)
{
    return(_provider->doEjectMedia());
}

IOReturn
IOSCSIDVDDriveNub::doFormatMedia(UInt64 byteCapacity)
{
    return(_provider->doFormatMedia(byteCapacity));
}

UInt32
IOSCSIDVDDriveNub::doGetFormatCapacities(UInt64 * capacities,UInt32 capacitiesMaxCount) const
{
    return(_provider->doGetFormatCapacities(capacities,capacitiesMaxCount));
}

IOReturn
IOSCSIDVDDriveNub::doLockUnlockMedia(bool doLock)
{
    return(_provider->doLockUnlockMedia(doLock));
}

IOReturn
IOSCSIDVDDriveNub::doSynchronizeCache(void)
{
    return(_provider->doSynchronizeCache());
}

IOReturn
IOSCSIDVDDriveNub::getAudioStatus(CDAudioStatus *status)
{
    return(_provider->getAudioStatus(status));
}

IOReturn
IOSCSIDVDDriveNub::getAudioVolume(UInt8 *leftVolume,UInt8 *rightVolume)
{
    return(_provider->getAudioVolume(leftVolume,rightVolume));
}

UInt32
IOSCSIDVDDriveNub::getMediaType(void)
{
    return(_provider->getMediaType());
}

char *
IOSCSIDVDDriveNub::getVendorString(void)
{
    return(_provider->getVendorString());
}

char *
IOSCSIDVDDriveNub::getProductString(void)
{
    return(_provider->getProductString());
}

char *
IOSCSIDVDDriveNub::getRevisionString(void)
{
    return(_provider->getRevisionString());
}

char *
IOSCSIDVDDriveNub::getAdditionalDeviceInfoString(void)
{
    return(_provider->getAdditionalDeviceInfoString());
}

IOReturn
IOSCSIDVDDriveNub::readISRC(UInt8 track,CDISRC isrc)
{
    return(_provider->readISRC(track,isrc));
}

IOReturn
IOSCSIDVDDriveNub::readMCN(CDMCN mcn)
{
    return(_provider->readMCN(mcn));
}

IOReturn
IOSCSIDVDDriveNub::readTOC(IOMemoryDescriptor *buffer)
{
    return(_provider->readTOC(buffer));
}

IOReturn
IOSCSIDVDDriveNub::reportBlockSize(UInt64 *blockSize)
{
    return(_provider->reportBlockSize(blockSize));
}

IOReturn
IOSCSIDVDDriveNub::reportEjectability(bool *isEjectable)
{
    return(_provider->reportEjectability(isEjectable));
}

IOReturn
IOSCSIDVDDriveNub::reportKey(IOMemoryDescriptor *buffer,const DVDKeyClass keyClass,
                                        const UInt32 lba,const UInt8 agid,const DVDKeyFormat keyFormat)
{
    return(_provider->reportKey(buffer,keyClass,lba,agid,keyFormat));
}

IOReturn
IOSCSIDVDDriveNub::reportLockability(bool *isLockable)
{
    return(_provider->reportLockability(isLockable));
}

IOReturn
IOSCSIDVDDriveNub::reportPollRequirements(bool *pollIsRequired,bool *pollIsExpensive)
{
    return(_provider-> reportPollRequirements(pollIsRequired,pollIsExpensive));
}

IOReturn
IOSCSIDVDDriveNub::reportMaxReadTransfer (UInt64 blockSize,UInt64 *max)
{
    return(_provider->reportMaxReadTransfer(blockSize,max));
}

IOReturn
IOSCSIDVDDriveNub::reportMaxValidBlock(UInt64 *maxBlock)
{
    return(_provider->reportMaxValidBlock(maxBlock));
}

IOReturn
IOSCSIDVDDriveNub::reportMaxWriteTransfer(UInt64 blockSize,UInt64 *max)
{
    return(_provider->reportMaxWriteTransfer(blockSize,max));
}

IOReturn
IOSCSIDVDDriveNub::reportMediaState(bool *mediaPresent,bool *changed)    
{
    return(_provider->reportMediaState(mediaPresent,changed));
}

IOReturn
IOSCSIDVDDriveNub::reportRemovability(bool *isRemovable)
{
    return(_provider->reportRemovability(isRemovable));
}

IOReturn
IOSCSIDVDDriveNub::reportWriteProtection(bool *isWriteProtected)
{
    return(_provider->reportWriteProtection(isWriteProtected));
}

IOReturn
IOSCSIDVDDriveNub::sendKey(IOMemoryDescriptor *buffer,const DVDKeyClass keyClass,
                                        const UInt8 agid,const DVDKeyFormat keyFormat)
{
    return(_provider->sendKey(buffer,keyClass,agid,keyFormat));
}

IOReturn
IOSCSIDVDDriveNub::setAudioVolume(UInt8 leftVolume,UInt8 rightVolume)
{
    return(_provider->setAudioVolume(leftVolume,rightVolume));
}

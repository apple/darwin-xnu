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
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOLib.h>
#include <IOKit/storage/scsi/IOSCSICDDriveNub.h>
#include <IOKit/storage/scsi/IOSCSICDDrive.h>

#define	super	IOCDBlockStorageDevice
OSDefineMetaClassAndStructors(IOSCSICDDriveNub,IOCDBlockStorageDevice)

bool
IOSCSICDDriveNub::attach(IOService * provider)
{
    if (!super::attach(provider)) {
        return(false);
    }

    _provider = OSDynamicCast(IOSCSICDDrive,provider);
    if (_provider == NULL) {
        return(false);
    } else {
        return(true);
    }
}

IOReturn
IOSCSICDDriveNub::audioPause(bool pause)
{
    return(_provider->audioPause(pause));
}

IOReturn
IOSCSICDDriveNub::audioPlay(CDMSF timeStart,CDMSF timeStop)
{
    return(_provider->audioPlay(timeStart,timeStop));
}

IOReturn
IOSCSICDDriveNub::audioScan(CDMSF timeStart,bool reverse)
{
    return(_provider->audioScan(timeStart,reverse));
}

IOReturn
IOSCSICDDriveNub::audioStop()
{
    return(_provider->audioStop());
}

IOReturn
IOSCSICDDriveNub::doAsyncReadCD(IOMemoryDescriptor *buffer,
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
IOSCSICDDriveNub::doAsyncReadWrite(IOMemoryDescriptor *buffer,
                                            UInt32 block,UInt32 nblks,
                                            IOStorageCompletion completion)
{
    return(_provider->doAsyncReadWrite(buffer,block,nblks,completion));
}

IOReturn
IOSCSICDDriveNub::doSyncReadWrite(IOMemoryDescriptor *buffer,UInt32 block,UInt32 nblks)
{
    return(_provider->doSyncReadWrite(buffer,block,nblks));
}

IOReturn
IOSCSICDDriveNub::doEjectMedia(void)
{
    return(_provider->doEjectMedia());
}

IOReturn
IOSCSICDDriveNub::doFormatMedia(UInt64 byteCapacity)
{
    return(_provider->doFormatMedia(byteCapacity));
}

UInt32
IOSCSICDDriveNub::doGetFormatCapacities(UInt64 * capacities,UInt32 capacitiesMaxCount) const
{
    return(_provider->doGetFormatCapacities(capacities,capacitiesMaxCount));
}

IOReturn
IOSCSICDDriveNub::doLockUnlockMedia(bool doLock)
{
    return(_provider->doLockUnlockMedia(doLock));
}

IOReturn
IOSCSICDDriveNub::doSynchronizeCache(void)
{
    return(_provider->doSynchronizeCache());
}

IOReturn
IOSCSICDDriveNub::getAudioStatus(CDAudioStatus *status)
{
    return(_provider->getAudioStatus(status));
}

IOReturn
IOSCSICDDriveNub::getAudioVolume(UInt8 *leftVolume,UInt8 *rightVolume)
{
    return(_provider->getAudioVolume(leftVolume,rightVolume));
}

UInt32
IOSCSICDDriveNub::getMediaType(void)
{
    return(kCDMediaTypeROM);
}

char *
IOSCSICDDriveNub::getVendorString(void)
{
    return(_provider->getVendorString());
}

char *
IOSCSICDDriveNub::getProductString(void)
{
    return(_provider->getProductString());
}

char *
IOSCSICDDriveNub::getRevisionString(void)
{
    return(_provider->getRevisionString());
}

char *
IOSCSICDDriveNub::getAdditionalDeviceInfoString(void)
{
    return(_provider->getAdditionalDeviceInfoString());
}

IOReturn
IOSCSICDDriveNub::readISRC(UInt8 track,CDISRC isrc)
{
    return(_provider->readISRC(track,isrc));
}

IOReturn
IOSCSICDDriveNub::readMCN(CDMCN mcn)
{
    return(_provider->readMCN(mcn));
}

IOReturn
IOSCSICDDriveNub::readTOC(IOMemoryDescriptor *buffer)
{
    return(_provider->readTOC(buffer));
}

IOReturn
IOSCSICDDriveNub::reportBlockSize(UInt64 *blockSize)
{
    return(_provider->reportBlockSize(blockSize));
}

IOReturn
IOSCSICDDriveNub::reportEjectability(bool *isEjectable)
{
    return(_provider->reportEjectability(isEjectable));
}

IOReturn
IOSCSICDDriveNub::reportLockability(bool *isLockable)
{
    return(_provider->reportLockability(isLockable));
}

IOReturn
IOSCSICDDriveNub::reportPollRequirements(bool *pollIsRequired,bool *pollIsExpensive)
{
    return(_provider-> reportPollRequirements(pollIsRequired,pollIsExpensive));
}

IOReturn
IOSCSICDDriveNub::reportMaxReadTransfer (UInt64 blockSize,UInt64 *max)
{
    return(_provider->reportMaxReadTransfer(blockSize,max));
}

IOReturn
IOSCSICDDriveNub::reportMaxValidBlock(UInt64 *maxBlock)
{
    return(_provider->reportMaxValidBlock(maxBlock));
}

IOReturn
IOSCSICDDriveNub::reportMaxWriteTransfer(UInt64 blockSize,UInt64 *max)
{
    return(_provider->reportMaxWriteTransfer(blockSize,max));
}

IOReturn
IOSCSICDDriveNub::reportMediaState(bool *mediaPresent,bool *changed)    
{
    return(_provider-> reportMediaState(mediaPresent,changed));
}

IOReturn
IOSCSICDDriveNub::reportRemovability(bool *isRemovable)
{
    return(_provider->reportRemovability(isRemovable));
}

IOReturn
IOSCSICDDriveNub::reportWriteProtection(bool *isWriteProtected)
{
    return(_provider->reportWriteProtection(isWriteProtected));
}

IOReturn
IOSCSICDDriveNub::setAudioVolume(UInt8 leftVolume,UInt8 rightVolume)
{
    return(_provider->setAudioVolume(leftVolume,rightVolume));
}


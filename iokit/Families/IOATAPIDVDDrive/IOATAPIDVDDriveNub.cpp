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
#include <IOKit/storage/IODVDBlockStorageDevice.h>
#include <IOKit/storage/ata/IOATAPIDVDDriveNub.h>
#include <IOKit/storage/ata/IOATAPIDVDDrive.h>

class IOMemoryDescriptor;

#define    super IODVDBlockStorageDevice
OSDefineMetaClassAndStructors(IOATAPIDVDDriveNub, IODVDBlockStorageDevice)

//---------------------------------------------------------------------------
// attach to provider.

bool
IOATAPIDVDDriveNub::attach(IOService * provider)
{
    if (!super::attach(provider))
        return false;

    _provider = OSDynamicCast(IOATAPIDVDDrive, provider);
    if (_provider == 0) {
        IOLog("IOATAPIDVDDriveNub: attach; wrong provider type!\n");
        return false;
    }
    return true;
}

//---------------------------------------------------------------------------
// detach from provider.

void
IOATAPIDVDDriveNub::detach(IOService * provider)
{
    if (_provider == provider)
		_provider = 0;

    super::detach(provider);
}

//---------------------------------------------------------------------------
// audioPlay

IOReturn
IOATAPIDVDDriveNub::audioPlay(CDMSF timeStart, CDMSF timeStop)
{
    return _provider->audioPlay(timeStart, timeStop);
}

//---------------------------------------------------------------------------
// audioPause

IOReturn
IOATAPIDVDDriveNub::audioPause(bool pause)
{
    return _provider->audioPause(pause);
}

//---------------------------------------------------------------------------
// audioScan

IOReturn
IOATAPIDVDDriveNub::audioScan(CDMSF timeStart, bool reverse)
{
    return kIOReturnUnsupported;
}

//---------------------------------------------------------------------------
// audioStop

IOReturn IOATAPIDVDDriveNub::audioStop()
{
    return _provider->audioStop();
}

//---------------------------------------------------------------------------
// doAsyncReadCD

IOReturn IOATAPIDVDDriveNub::doAsyncReadCD(IOMemoryDescriptor * buffer,
                                           UInt32               block,
                                           UInt32               nblks,
                                           CDSectorArea         sectorArea,
                                           CDSectorType         sectorType,
                                           IOStorageCompletion  completion)
{
    return _provider->doAsyncReadCD(buffer,
                                    block,
                                    nblks,
                                    sectorArea,
                                    sectorType,
                                    completion);
}

//---------------------------------------------------------------------------
// doAsyncReadWrite

IOReturn
IOATAPIDVDDriveNub::doAsyncReadWrite(IOMemoryDescriptor * buffer,
                                     UInt32               block,
                                     UInt32               nblks,
                                     IOStorageCompletion  completion)
{
    return _provider->doAsyncReadWrite(buffer, block, nblks, completion);
}

//---------------------------------------------------------------------------
// doSyncReadWrite

IOReturn
IOATAPIDVDDriveNub::doSyncReadWrite(IOMemoryDescriptor * buffer,
                                    UInt32               block,
                                    UInt32               nblks)
{
    return _provider->doSyncReadWrite(buffer, block, nblks);
}

//---------------------------------------------------------------------------
// doEjectMedia

IOReturn
IOATAPIDVDDriveNub::doEjectMedia()
{
    return _provider->doEjectMedia();
}

//---------------------------------------------------------------------------
// doFormatMedia

IOReturn
IOATAPIDVDDriveNub::doFormatMedia(UInt64 byteCapacity)
{
    return _provider->doFormatMedia(byteCapacity);
}

//---------------------------------------------------------------------------
// doGetFormatCapacities

UInt32
IOATAPIDVDDriveNub::doGetFormatCapacities(UInt64 * capacities,
                                          UInt32   capacitiesMaxCount) const
{
    return _provider->doGetFormatCapacities(capacities, capacitiesMaxCount);
}

//---------------------------------------------------------------------------
// doLockUnlockMedia

IOReturn
IOATAPIDVDDriveNub::doLockUnlockMedia(bool doLock)
{
    return _provider->doLockUnlockMedia(doLock);
}

//---------------------------------------------------------------------------
// doSynchronizeCache

IOReturn
IOATAPIDVDDriveNub::doSynchronizeCache()
{
    return _provider->doSynchronizeCache();
}

//---------------------------------------------------------------------------
// getAudioStatus

IOReturn
IOATAPIDVDDriveNub::getAudioStatus(CDAudioStatus * status)
{
    return _provider->getAudioStatus(status);
}

//---------------------------------------------------------------------------
// getAudioVolume

IOReturn
IOATAPIDVDDriveNub::getAudioVolume(UInt8 * leftVolume, UInt8 * rightVolume)
{
    return _provider->getAudioVolume(leftVolume, rightVolume);
}

//---------------------------------------------------------------------------
// getMediaType

UInt32
IOATAPIDVDDriveNub::getMediaType()
{
    return _provider->getMediaType();
}

//---------------------------------------------------------------------------
// getVendorString

char *
IOATAPIDVDDriveNub::getVendorString()
{
    return _provider->getVendorString();
}

//---------------------------------------------------------------------------
// getProductString

char *
IOATAPIDVDDriveNub::getProductString()
{
    return _provider->getProductString();
}

//---------------------------------------------------------------------------
// getRevisionString

char *
IOATAPIDVDDriveNub::getRevisionString()
{
    return _provider->getRevisionString();
}

//---------------------------------------------------------------------------
// getAdditionalDeviceInfoString

char *
IOATAPIDVDDriveNub::getAdditionalDeviceInfoString()
{
    return _provider->getAdditionalDeviceInfoString();
}

//---------------------------------------------------------------------------
// readISRC

IOReturn
IOATAPIDVDDriveNub::readISRC(UInt8 track, CDISRC isrc)
{
    return _provider->readISRC(track, isrc);
}

//---------------------------------------------------------------------------
// readMCN

IOReturn
IOATAPIDVDDriveNub::readMCN(CDMCN mcn)
{
    return _provider->readMCN(mcn);
}

//---------------------------------------------------------------------------
// readTOC

IOReturn
IOATAPIDVDDriveNub::readTOC(IOMemoryDescriptor * buffer)
{
    return _provider->readTOC(buffer);
}

//---------------------------------------------------------------------------
// reportBlockSize

IOReturn
IOATAPIDVDDriveNub::reportBlockSize(UInt64 * blockSize)
{
    return _provider->reportBlockSize(blockSize);
}

//---------------------------------------------------------------------------
// reportEjectability

IOReturn
IOATAPIDVDDriveNub::reportEjectability(bool * isEjectable)
{
    return _provider->reportEjectability(isEjectable);
}

//---------------------------------------------------------------------------
// reportKey

IOReturn
IOATAPIDVDDriveNub::reportKey(IOMemoryDescriptor * buffer,
                              const DVDKeyClass    keyClass,
                              const UInt32         lba,
                              const UInt8          agid,
                              const DVDKeyFormat   keyFormat)
{
    return _provider->reportKey(buffer, keyClass, lba, agid, keyFormat);
}

//---------------------------------------------------------------------------
// sendKey

IOReturn
IOATAPIDVDDriveNub::sendKey(IOMemoryDescriptor * buffer,
                            const DVDKeyClass    keyClass,
                            const UInt8          agid,
                            const DVDKeyFormat   keyFormat)
{
    return _provider->sendKey(buffer, keyClass, agid, keyFormat);
}

//---------------------------------------------------------------------------
// reportLockability

IOReturn
IOATAPIDVDDriveNub::reportLockability(bool * isLockable)
{
    return _provider->reportLockability(isLockable);
}

//---------------------------------------------------------------------------
// reportPollRequirements

IOReturn
IOATAPIDVDDriveNub::reportPollRequirements(bool * pollIsRequired,
                                           bool * pollIsExpensive)
{
    return _provider->reportPollRequirements(pollIsRequired, pollIsExpensive);
}

//---------------------------------------------------------------------------
// reportMaxReadTransfer

IOReturn
IOATAPIDVDDriveNub::reportMaxReadTransfer(UInt64 blockSize, UInt64 * max)
{
    return _provider->reportMaxReadTransfer(blockSize, max);
}

//---------------------------------------------------------------------------
// reportMaxValidBlock

IOReturn
IOATAPIDVDDriveNub::reportMaxValidBlock(UInt64 * maxBlock)
{
    return _provider->reportMaxValidBlock(maxBlock);
}

//---------------------------------------------------------------------------
// reportMaxWriteTransfer

IOReturn
IOATAPIDVDDriveNub::reportMaxWriteTransfer(UInt64 blockSize, UInt64 * max)
{
    return _provider->reportMaxWriteTransfer(blockSize, max);
}

//---------------------------------------------------------------------------
// reportMediaState

IOReturn
IOATAPIDVDDriveNub::reportMediaState(bool * mediaPresent, bool * changed)    
{
    return _provider->reportMediaState(mediaPresent, changed);
}

//---------------------------------------------------------------------------
// reportRemovability

IOReturn
IOATAPIDVDDriveNub::reportRemovability(bool * isRemovable)
{
    return _provider->reportRemovability(isRemovable);
}

//---------------------------------------------------------------------------
// reportWriteProtection

IOReturn
IOATAPIDVDDriveNub::reportWriteProtection(bool * isWriteProtected)
{
    return _provider->reportWriteProtection(isWriteProtected);
}

//---------------------------------------------------------------------------
// setAudioVolume

IOReturn
IOATAPIDVDDriveNub::setAudioVolume(UInt8 leftVolume, UInt8 rightVolume)
{
    return _provider->setAudioVolume(leftVolume, rightVolume);
}

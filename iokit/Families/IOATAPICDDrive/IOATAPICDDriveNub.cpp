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
 * IOATAPICDDriveNub.cpp
 *
 * This subclass implements a relay to a protocol and device-specific
 * provider.
 *
 * HISTORY
 * 2-Sep-1999		Joe Liu (jliu) created.
 */

#include <IOKit/IOLib.h>
#include <IOKit/storage/ata/IOATAPICDDriveNub.h>
#include <IOKit/storage/ata/IOATAPICDDrive.h>

#define	super	IOCDBlockStorageDevice
OSDefineMetaClassAndStructors( IOATAPICDDriveNub, IOCDBlockStorageDevice )

//---------------------------------------------------------------------------
// attach to provider.

bool IOATAPICDDriveNub::attach(IOService * provider)
{
    if (!super::attach(provider))
        return false;

    _provider = OSDynamicCast(IOATAPICDDrive, provider);
    if (_provider == 0) {
        IOLog("IOATAPICDDriveNub: attach; wrong provider type!\n");
        return false;
    }
	
	return true;
}

//---------------------------------------------------------------------------
// detach from provider.

void IOATAPICDDriveNub::detach(IOService * provider)
{
    if (_provider == provider)
		_provider = 0;

    super::detach(provider);
}


//---------------------------------------------------------------------------
// doAsyncReadCD

IOReturn IOATAPICDDriveNub::doAsyncReadCD(IOMemoryDescriptor * buffer,
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

IOReturn IOATAPICDDriveNub::doAsyncReadWrite(IOMemoryDescriptor * buffer,
                                             UInt32               block,
                                             UInt32               nblks,
                                             IOStorageCompletion  completion)
{
    if (buffer->getDirection() == kIODirectionOut)
        return kIOReturnNotWritable;

	return _provider->doAsyncReadWrite(buffer, block, nblks, completion);
}

//---------------------------------------------------------------------------
// doSyncReadWrite

IOReturn
IOATAPICDDriveNub::doSyncReadWrite(IOMemoryDescriptor * buffer,
                                   UInt32               block,
                                   UInt32               nblks)
{
    if (buffer->getDirection() == kIODirectionOut)
        return kIOReturnNotWritable;

    return _provider->doSyncReadWrite(buffer, block, nblks);
}

//---------------------------------------------------------------------------
// doFormatMedia

IOReturn
IOATAPICDDriveNub::doFormatMedia(UInt64 byteCapacity)
{
    return kIOReturnUnsupported;
}

//---------------------------------------------------------------------------
// doGetFormatCapacities

UInt32
IOATAPICDDriveNub::doGetFormatCapacities(UInt64 * capacities,
                                         UInt32   capacitiesMaxCount) const
{
    return _provider->doGetFormatCapacities(capacities, capacitiesMaxCount);
}

//---------------------------------------------------------------------------
// doEjectMedia

IOReturn IOATAPICDDriveNub::doEjectMedia()
{
    return _provider->doEjectMedia();
}

//---------------------------------------------------------------------------
// doLockUnlockMedia

IOReturn IOATAPICDDriveNub::doLockUnlockMedia(bool doLock)
{
    return _provider->doLockUnlockMedia(doLock);
}

//---------------------------------------------------------------------------
// getMediaType

UInt32 IOATAPICDDriveNub::getMediaType()
{
    return kCDMediaTypeROM;
}

//---------------------------------------------------------------------------
// getVendorString

char * IOATAPICDDriveNub::getVendorString()
{
    return _provider->getVendorString();
}

//---------------------------------------------------------------------------
// getProductString

char * IOATAPICDDriveNub::getProductString()
{
    return _provider->getProductString();
}

//---------------------------------------------------------------------------
// getRevisionString

char * IOATAPICDDriveNub::getRevisionString()
{
    return _provider->getRevisionString();
}

//---------------------------------------------------------------------------
// getAdditionalDeviceInfoString

char * IOATAPICDDriveNub::getAdditionalDeviceInfoString()
{
    return _provider->getAdditionalDeviceInfoString();
}

//---------------------------------------------------------------------------
// reportBlockSize

IOReturn IOATAPICDDriveNub::reportBlockSize(UInt64 * blockSize)
{
    return _provider->reportBlockSize(blockSize);
}

//---------------------------------------------------------------------------
// reportEjectability

IOReturn IOATAPICDDriveNub::reportEjectability(bool * isEjectable)
{
    return _provider->reportEjectability(isEjectable);
}

//---------------------------------------------------------------------------
// reportLockability

IOReturn IOATAPICDDriveNub::reportLockability(bool * isLockable)
{
    return _provider->reportLockability(isLockable);
}

//---------------------------------------------------------------------------
// reportMediaState

IOReturn IOATAPICDDriveNub::reportMediaState(bool * mediaPresent,
                                             bool * changed)    
{
    return _provider->reportMediaState(mediaPresent, changed);
}

//---------------------------------------------------------------------------
// reportPollRequirements

IOReturn IOATAPICDDriveNub::reportPollRequirements(bool * pollIsRequired,
                                                   bool * pollIsExpensive)
{
    return _provider->reportPollRequirements(pollIsRequired, pollIsExpensive);
}

//---------------------------------------------------------------------------
// reportMaxReadTransfer

IOReturn IOATAPICDDriveNub::reportMaxReadTransfer(UInt64   blockSize,
                                                  UInt64 * max)
{
    return _provider->reportMaxReadTransfer(blockSize, max);
}

//---------------------------------------------------------------------------
// reportMaxValidBlock

IOReturn IOATAPICDDriveNub::reportMaxValidBlock(UInt64 * maxBlock)
{
    return _provider->reportMaxValidBlock(maxBlock);
}

//---------------------------------------------------------------------------
// reportRemovability

IOReturn IOATAPICDDriveNub::reportRemovability(bool * isRemovable)
{
    return _provider->reportRemovability(isRemovable);
}

//---------------------------------------------------------------------------
// readISRC

IOReturn IOATAPICDDriveNub::readISRC(UInt8 track, CDISRC isrc)
{
    return _provider->readISRC(track, isrc);
}

//---------------------------------------------------------------------------
// readMCN

IOReturn IOATAPICDDriveNub::readMCN(CDMCN mcn)
{
    return _provider->readMCN(mcn);
}

//---------------------------------------------------------------------------
// readTOC

IOReturn IOATAPICDDriveNub::readTOC(IOMemoryDescriptor * buffer)
{
    return _provider->readTOC(buffer);
}

//---------------------------------------------------------------------------
// audioPause

IOReturn IOATAPICDDriveNub::audioPause(bool pause)
{
    return _provider->audioPause(pause);
}

//---------------------------------------------------------------------------
// audioPlay

IOReturn IOATAPICDDriveNub::audioPlay(CDMSF timeStart, CDMSF timeStop)
{
    return _provider->audioPlay(timeStart, timeStop);
}

//---------------------------------------------------------------------------
// audioScan

IOReturn IOATAPICDDriveNub::audioScan(CDMSF timeStart, bool reverse)
{
    return _provider->audioScan(timeStart, reverse);
}

//---------------------------------------------------------------------------
// audioStop

IOReturn IOATAPICDDriveNub::audioStop()
{
    return _provider->audioStop();
}

//---------------------------------------------------------------------------
// getAudioStatus

IOReturn IOATAPICDDriveNub::getAudioStatus(CDAudioStatus * status)
{
    return _provider->getAudioStatus(status);
}

//---------------------------------------------------------------------------
// getAudioVolume

IOReturn IOATAPICDDriveNub::getAudioVolume(UInt8 * leftVolume,
                                           UInt8 * rightVolume)
{
    return _provider->getAudioVolume(leftVolume, rightVolume);
}

//---------------------------------------------------------------------------
// setVolume

IOReturn IOATAPICDDriveNub::setAudioVolume(UInt8 leftVolume, UInt8 rightVolume)
{
    return _provider->setAudioVolume(leftVolume, rightVolume);
}

//---------------------------------------------------------------------------
// doSynchronizeCache

IOReturn IOATAPICDDriveNub::doSynchronizeCache()
{
    return kIOReturnUnsupported;
}

//---------------------------------------------------------------------------
// reportMaxWriteTransfer

IOReturn IOATAPICDDriveNub::reportMaxWriteTransfer(UInt64   blockSize,
                                                   UInt64 * max)
{
    return _provider->reportMaxWriteTransfer(blockSize, max);
}

//---------------------------------------------------------------------------
// reportMaxWriteTransfer

IOReturn IOATAPICDDriveNub::reportWriteProtection(bool * isWriteProtected)
{
    return _provider->reportWriteProtection(isWriteProtected);
}

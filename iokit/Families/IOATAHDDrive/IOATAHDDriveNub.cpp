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
 * IOATAHDDriveNub.cpp
 *
 * This subclass implements a relay to a protocol and device-specific
 * provider.
 *
 * HISTORY
 * Aug 27, 1999  jliu - Created.
 */

#include <IOKit/IOLib.h>
#include <IOKit/storage/ata/IOATAHDDriveNub.h>
#include <IOKit/storage/ata/IOATAHDDrive.h>

#define super IOBlockStorageDevice
OSDefineMetaClassAndStructors( IOATAHDDriveNub, IOBlockStorageDevice )

//---------------------------------------------------------------------------
// attach to provider.

bool IOATAHDDriveNub::attach(IOService * provider)
{    
    if (!super::attach(provider))
        return false;

    _provider = OSDynamicCast(IOATAHDDrive, provider);
    if (_provider == 0) {
        IOLog("IOATAHDDriveNub: attach; wrong provider type!\n");
        return false;
    }

    return true;
}

//---------------------------------------------------------------------------
// detach from provider.

void IOATAHDDriveNub::detach(IOService * provider)
{
    if (_provider == provider)
        _provider = 0;

    super::detach(provider);
}

//---------------------------------------------------------------------------
// 

IOReturn IOATAHDDriveNub::doAsyncReadWrite(IOMemoryDescriptor * buffer,
                                           UInt32               block,
                                           UInt32               nblks,
                                           IOStorageCompletion  completion)
{
    return _provider->doAsyncReadWrite(buffer, block, nblks, completion);
}

//---------------------------------------------------------------------------
//

IOReturn IOATAHDDriveNub::doSyncReadWrite(IOMemoryDescriptor *buffer,
                                     UInt32 block,UInt32 nblks)
{
    return _provider->doSyncReadWrite(buffer, block, nblks);
}

//---------------------------------------------------------------------------
// 

IOReturn IOATAHDDriveNub::doEjectMedia()
{
    return _provider->doEjectMedia();
}

//---------------------------------------------------------------------------
// 

IOReturn IOATAHDDriveNub::doFormatMedia(UInt64 byteCapacity)  
{
    return _provider->doFormatMedia(byteCapacity);
}

//---------------------------------------------------------------------------
// 

UInt32
IOATAHDDriveNub::doGetFormatCapacities(UInt64 * capacities,
                                       UInt32   capacitiesMaxCount) const
{
    return _provider->doGetFormatCapacities(capacities, capacitiesMaxCount);
}

//---------------------------------------------------------------------------
// 

IOReturn IOATAHDDriveNub::doLockUnlockMedia(bool doLock)
{
    return _provider->doLockUnlockMedia(doLock);
}

//---------------------------------------------------------------------------
//

IOReturn IOATAHDDriveNub::doSynchronizeCache()
{
    return _provider->doSynchronizeCache();
}

//---------------------------------------------------------------------------
// 

char * IOATAHDDriveNub::getVendorString()
{
    return _provider->getVendorString();
}

//---------------------------------------------------------------------------
// 

char * IOATAHDDriveNub::getProductString()
{
    return _provider->getProductString();
}

//---------------------------------------------------------------------------
// 

char * IOATAHDDriveNub::getRevisionString()
{
    return _provider->getRevisionString();
}

//---------------------------------------------------------------------------
// 

char * IOATAHDDriveNub::getAdditionalDeviceInfoString()
{
    return _provider->getAdditionalDeviceInfoString();
}

//---------------------------------------------------------------------------
// 

IOReturn IOATAHDDriveNub::reportBlockSize(UInt64 * blockSize)
{
    return _provider->reportBlockSize(blockSize);
}

//---------------------------------------------------------------------------
// 

IOReturn IOATAHDDriveNub::reportEjectability(bool * isEjectable)
{
    return _provider->reportEjectability(isEjectable);
}

//---------------------------------------------------------------------------
// 

IOReturn IOATAHDDriveNub::reportLockability(bool * isLockable)
{
    return _provider->reportLockability(isLockable);
}

//---------------------------------------------------------------------------
// 

IOReturn IOATAHDDriveNub::reportPollRequirements(bool * pollIsRequired,
                                                 bool * pollIsExpensive)
{
    return _provider->reportPollRequirements(pollIsRequired, pollIsExpensive);
}

//---------------------------------------------------------------------------
// 

IOReturn IOATAHDDriveNub::reportMaxReadTransfer(UInt64   blockSize,
                                                UInt64 * max)
{
    return _provider->reportMaxReadTransfer(blockSize, max);
}

//---------------------------------------------------------------------------
// 

IOReturn IOATAHDDriveNub::reportMaxValidBlock(UInt64 * maxBlock)
{
    return _provider->reportMaxValidBlock(maxBlock);
}

//---------------------------------------------------------------------------
// 

IOReturn IOATAHDDriveNub::reportMaxWriteTransfer(UInt64   blockSize, 
                                                 UInt64 * max)
{
    return _provider->reportMaxWriteTransfer(blockSize, max);
}

//---------------------------------------------------------------------------
// 

IOReturn IOATAHDDriveNub::reportMediaState(bool * mediaPresent,
                                           bool * changed)    
{
    return _provider->reportMediaState(mediaPresent, changed);
}

//---------------------------------------------------------------------------
// 

IOReturn IOATAHDDriveNub::reportRemovability(bool * isRemovable)
{
    return _provider->reportRemovability(isRemovable);
}

//---------------------------------------------------------------------------
// 

IOReturn IOATAHDDriveNub::reportWriteProtection(bool * isWriteProtected)
{
    return _provider->reportWriteProtection(isWriteProtected);
}

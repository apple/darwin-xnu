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
#include <IOKit/storage/scsi/IOSCSIHDDriveNub.h>
#include <IOKit/storage/scsi/IOSCSIHDDrive.h>

#define	super	IOBlockStorageDevice
OSDefineMetaClassAndStructors(IOSCSIHDDriveNub,IOBlockStorageDevice)

bool
IOSCSIHDDriveNub::attach(IOService * provider)
{
//    IOLog("IOSCSIHDDriveNub: attach\n");
    
    if (!super::attach(provider)) {
        return(false);
    }
    
//    IOLog("IOSCSIHDDriveNub: attach; casting provider\n");
    _provider = OSDynamicCast(IOSCSIHDDrive,provider);
    if (_provider == NULL) {
        IOLog("IOSCSIHDDriveNub: attach; wrong provider type!\n");
        return(false);
    } else {
//        IOLog("IOSCSIHDDriveNub: attach; provider OK\n");
        return(true);
    }
}

void IOSCSIHDDriveNub::detach(IOService * provider)
{
    if( _provider == provider)
	_provider = 0;

    super::detach( provider );
}

IOReturn
IOSCSIHDDriveNub::doAsyncReadWrite(IOMemoryDescriptor *buffer,
                                            UInt32 block,UInt32 nblks,
                                            IOStorageCompletion completion)
{
    return(_provider->doAsyncReadWrite(buffer,block,nblks,completion));
}

IOReturn
IOSCSIHDDriveNub::doSyncReadWrite(IOMemoryDescriptor *buffer,UInt32 block,UInt32 nblks)
{
    return(_provider->doSyncReadWrite(buffer,block,nblks));
}

IOReturn
IOSCSIHDDriveNub::doEjectMedia(void)
{
    return(_provider->doEjectMedia());
}

IOReturn
IOSCSIHDDriveNub::doFormatMedia(UInt64 byteCapacity)  
{
    return(_provider->doFormatMedia(byteCapacity));
}

UInt32
IOSCSIHDDriveNub::doGetFormatCapacities(UInt64 * capacities,
                                            UInt32   capacitiesMaxCount) const
{
    return(_provider->doGetFormatCapacities(capacities,capacitiesMaxCount));
}

IOReturn
IOSCSIHDDriveNub::doLockUnlockMedia(bool doLock)
{
    return(_provider->doLockUnlockMedia(doLock));
}

IOReturn
IOSCSIHDDriveNub::doSynchronizeCache(void)
{
    return(_provider->doSynchronizeCache());
}

char *
IOSCSIHDDriveNub::getVendorString(void)
{
    return(_provider->getVendorString());
}

char *
IOSCSIHDDriveNub::getProductString(void)
{
    return(_provider->getProductString());
}

char *
IOSCSIHDDriveNub::getRevisionString(void)
{
    return(_provider->getRevisionString());
}

char *
IOSCSIHDDriveNub::getAdditionalDeviceInfoString(void)
{
    return(_provider-> getAdditionalDeviceInfoString());
}

IOReturn
IOSCSIHDDriveNub::reportBlockSize(UInt64 *blockSize)
{
    return(_provider->reportBlockSize(blockSize));
}

IOReturn
IOSCSIHDDriveNub::reportEjectability(bool *isEjectable)
{
    return(_provider->reportEjectability(isEjectable));
}

IOReturn
IOSCSIHDDriveNub::reportLockability(bool *isLockable)
{
    return(_provider->reportLockability(isLockable));
}

IOReturn
IOSCSIHDDriveNub::reportPollRequirements(bool *pollIsRequired,bool *pollIsExpensive)
{
    return(_provider->reportPollRequirements(pollIsRequired,pollIsExpensive));
}

IOReturn
IOSCSIHDDriveNub::reportMaxReadTransfer (UInt64 blockSize,UInt64 *max)
{
    return(_provider->reportMaxReadTransfer(blockSize,max));
}

IOReturn
IOSCSIHDDriveNub::reportMaxValidBlock(UInt64 *maxBlock)
{
    return(_provider->reportMaxValidBlock(maxBlock));
}

IOReturn
IOSCSIHDDriveNub::reportMaxWriteTransfer(UInt64 blockSize,UInt64 *max)
{
    return(_provider->reportMaxWriteTransfer(blockSize,max));
}

IOReturn
IOSCSIHDDriveNub::reportMediaState(bool *mediaPresent,bool *changed)    
{
    return(_provider->reportMediaState(mediaPresent,changed));
}

IOReturn
IOSCSIHDDriveNub::reportRemovability(bool *isRemovable)
{
    return(_provider->reportRemovability(isRemovable));
}

IOReturn
IOSCSIHDDriveNub::reportWriteProtection(bool *isWriteProtected)
{
    return(_provider->reportWriteProtection(isWriteProtected));
}

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
 * IOATAPICDDriveNub.h
 *
 * This subclass implements a relay to a protocol and device-specific
 * provider.
 *
 * HISTORY
 * 2-Sep-1999        Joe Liu (jliu) created.
 */

#ifndef    _IOATAPICDDRIVENUB_H
#define    _IOATAPICDDRIVENUB_H

#include <IOKit/IOTypes.h>
#include <IOKit/storage/IOCDBlockStorageDevice.h>

class IOATAPICDDrive;

class IOATAPICDDriveNub : public IOCDBlockStorageDevice 
{
    OSDeclareDefaultStructors(IOATAPICDDriveNub)

protected:
    IOATAPICDDrive *   _provider;

public:
    /*
     * Overrides from IOService.
     */
    virtual bool       attach(IOService * provider);
    virtual void       detach(IOService * provider);

    /*
     * Mandatory overrides from IOBlockStorageDevice.
     */
    virtual IOReturn   doAsyncReadWrite(IOMemoryDescriptor * buffer,
                                        UInt32               block,
                                        UInt32               nblks,
                                        IOStorageCompletion  completion);

    virtual IOReturn   doSyncReadWrite(IOMemoryDescriptor * buffer,
                                       UInt32               block,
                                       UInt32               nblks);

    virtual IOReturn   doFormatMedia(UInt64 byteCapacity);
    virtual UInt32     doGetFormatCapacities(UInt64 * capacities,
                                             UInt32   capacitiesMaxCount) const;
    virtual IOReturn   doSynchronizeCache();
    virtual IOReturn   doEjectMedia();
    virtual IOReturn   doLockUnlockMedia(bool doLock);
    virtual char *     getVendorString();
    virtual char *     getProductString();
    virtual char *     getRevisionString();
    virtual char *     getAdditionalDeviceInfoString();
    virtual IOReturn   reportBlockSize(UInt64 * blockSize);
    virtual IOReturn   reportEjectability(bool * isEjectable);
    virtual IOReturn   reportLockability(bool * isLockable);
    virtual IOReturn   reportMediaState(bool * mediaPresent, bool * changed);
    virtual IOReturn   reportPollRequirements(bool * pollIsRequired,
                                              bool * pollIsExpensive);
    virtual IOReturn   reportMaxReadTransfer (UInt64 blockSize, UInt64 * max);
    virtual IOReturn   reportMaxValidBlock(UInt64 * maxBlock);
    virtual IOReturn   reportMaxWriteTransfer(UInt64 blockSize, UInt64 * max);
    virtual IOReturn   reportRemovability(bool * isRemovable);
    virtual IOReturn   reportWriteProtection(bool * isWriteProtected);
    
    /*-----------------------------------------*/
    /* CD APIs                                 */
    /*-----------------------------------------*/

    virtual IOReturn   doAsyncReadCD(IOMemoryDescriptor * buffer,
                                     UInt32               block,
                                     UInt32               nblks,
                                     CDSectorArea         sectorArea,
                                     CDSectorType         sectorType,
                                     IOStorageCompletion  completion);
    virtual UInt32     getMediaType();
    virtual IOReturn   readISRC(UInt8 track, CDISRC isrc);
    virtual IOReturn   readMCN(CDMCN mcn);
    virtual IOReturn   readTOC(IOMemoryDescriptor * buffer);

    /*-----------------------------------------*/
    /*  APIs exported by IOCDAudioControl      */
    /*-----------------------------------------*/

    virtual IOReturn	audioPause(bool pause);
    virtual IOReturn	audioPlay(CDMSF timeStart,CDMSF timeStop);
    virtual IOReturn	audioScan(CDMSF timeStart,bool reverse);
    virtual IOReturn	audioStop();
    virtual IOReturn	getAudioStatus(CDAudioStatus * status);
    virtual IOReturn	getAudioVolume(UInt8 * leftVolume,
                                        UInt8 * rightVolume);
    virtual IOReturn	setAudioVolume(UInt8 leftVolume, UInt8 rightVolume);
};

#endif /* !_IOATAPICDDRIVENUB_H */

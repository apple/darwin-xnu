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
/* IOSCSIHDDriveNub.h created by rick on Tue 23-Mar-1999 */

/* This subclass implements a relay to a protocol- and device-specific provider. */

#ifndef	_IOSCSIHDDRIVENUB_H
#define	_IOSCSIHDDRIVENUB_H

#include <IOKit/IOTypes.h>
#include <IOKit/storage/IOBlockStorageDevice.h>

class IOSCSIHDDrive;

class IOSCSIHDDriveNub : public IOBlockStorageDevice {

    OSDeclareDefaultStructors(IOSCSIHDDriveNub)

public:

    /* Overrides from IOService */

    virtual bool	attach(IOService * provider);
    virtual void	detach(IOService * provider);

    /* Mandatory overrides from IOBlockStorageDevice: */

    virtual IOReturn	doAsyncReadWrite(IOMemoryDescriptor *buffer,
                                            UInt32 block,UInt32 nblks,
                                            IOStorageCompletion completion);
    virtual IOReturn	doSyncReadWrite(IOMemoryDescriptor *buffer,UInt32 block,UInt32 nblks);
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
    virtual IOReturn	reportMediaState(bool *mediaPresent,bool *changed);    
    virtual IOReturn	reportPollRequirements(bool *PollIsRequired,bool *pollIsExpensive);
    virtual IOReturn	reportMaxReadTransfer (UInt64 blockSize,UInt64 *max);
    virtual IOReturn	reportMaxValidBlock(UInt64 *maxBlock);
    virtual IOReturn	reportMaxWriteTransfer(UInt64 blockSize,UInt64 *max);
    virtual IOReturn	reportRemovability(bool *isRemovable);
    virtual IOReturn	reportWriteProtection(bool *isWriteProtected);

protected:

    IOSCSIHDDrive *	_provider;
};
#endif

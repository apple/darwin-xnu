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
/*
 * IOSCSIDVDDrive.h
 *
 * This class implements SCSI DVD functionality.
 *
 * Subclasses may modify the operations to handle device-specific variations.
 */

#ifndef _IOSCSIDVDDRIVE_H
#define	_IOSCSIDVDDRIVE_H

#include <IOKit/IOTypes.h>
#include <IOKit/scsi/IOSCSIDeviceInterface.h>
#include <IOKit/storage/scsi/IOSCSICDDrive.h>
#include <IOKit/storage/IODVDTypes.h>

struct IOGCCdb {
    UInt8	opcode;
    UInt8	lunRT;
    UInt8	startFeature_hi;
    UInt8	startFeature_lo;
    UInt8	reserved[3];
    UInt8	len_hi;
    UInt8	len_lo;
    UInt8	ctlbyte;
};

struct IORKCdb {
    UInt8	opcode;
    UInt8	lba_0;	//msb
    UInt8	lba_1;
    UInt8	lba_2;
    UInt8	lba_3;
    UInt8	reserved;
    UInt8	keyClass;
    UInt8	len_hi;
    UInt8	len_lo;
    UInt8	agidKeyFormat;
    UInt8	ctlbyte;
};

struct IOSKCdb {
    UInt8	opcode;
    UInt8	lun;
    UInt8	reserved[5];
    UInt8	keyClass;
    UInt8	len_hi;
    UInt8	len_lo;
    UInt8	agidKeyFormat;
    UInt8	ctlbyte;
};

enum {
    kIOSCSICommandGetConfiguration = 0x46,
    kIOSCSICommandSendKey          = 0xa3,
    kIOSCSICommandReportKey        = 0xa4
};

const int kMaxConfigLength	= 1024;
class IOMemoryDescriptor;

/*------------------------------------------------*/
class IOSCSIDVDDrive : public IOSCSICDDrive {

    OSDeclareDefaultStructors(IOSCSIDVDDrive)

public:

    /* Overrides from IOService: */
    
    virtual bool	init(OSDictionary * properties);
    
    /* Overrides from IOBasicSCSI: */
    
    virtual bool	deviceTypeMatches(UInt8 inqBuf[],UInt32 inqLen,SInt32 *score);

    /*!
     * @function reportWriteProtection
     * @abstract
     * Report whether the media is write-protected or not.
     * @discussion
     * This override allows us to return the cached write-protection status
     * without interrogating the drive.
     */
    virtual IOReturn	reportWriteProtection(bool *isWriteProtected);

    /* End of IOBasicSCSI overrides */

    /* IOSCSIHDDrive overrides: */
    
    /*!
     * @function doAsyncReadWrite
     * @abstract
     * Start an asynchronous read or write operation.
     * @discussion
     * This override allows us to accept writes, which our superclass, IOSCSICDDrive,
     * unconditionally rejects.
     */    
    virtual IOReturn	doAsyncReadWrite(IOMemoryDescriptor *buffer,
                                            UInt32 block,UInt32 nblks,
                                            IOStorageCompletion completion);

    /*!
     * @function doSyncReadWrite
     * @abstract
     * Perform a synchronous read or write operation.
     * @discussion
     * See IOBlockStorageDevice for details.
     */    
    virtual IOReturn	doSyncReadWrite(IOMemoryDescriptor *buffer,UInt32 block,UInt32 nblks);

    /*!
     * @function doFormatMedia
     * @abstract
     * Attempt to format the media.
     * @discussion
     * This override allows us to handle formatting for DVD-RAM.
     */
    virtual IOReturn	doFormatMedia(UInt64 byteCapacity);

    /*!
     * @function doGetFormatCapacities
     * @abstract
     * Report available formatting capacities for the device/media.
     * @discussion
     * This override allows us to handle formatting for DVD.
     */
    virtual UInt32	doGetFormatCapacities(UInt64 * capacities,
                                            UInt32   capacitiesMaxCount) const;

    /*!
     * @function doSynchronizeCache
     * @abstract
     * Force data blocks in the drive's buffer to be flushed to the media.
     * @discussion
     * This override allows us to issue a standard Synchronize-Cache command for DVD-RAM.
     */    
    virtual IOReturn	doSynchronizeCache(void);
    
    virtual const char * getDeviceTypeName(void);

    /*!
     * @function getGetConfigurationPowerState
     * @abstract
     * Return the required device power level to execute a Get Configuration command.
     * @discussion
     * The default implementation of this method returns kElectronicsOn.
     * @result
     * The return value must be a valid power state value.
     */    
    virtual UInt32	getGetConfigurationPowerState(void);	/* default = kElectronicsOn */

    /*!
     * @function getReportKeyPowerState
     * @abstract
     * Return the required device power level to execute a Report Key command.
     * @discussion
     * The default implementation of this method returns kElectronicsOn.
     * @result
     * The return value must be a valid power state value.
     */    
    virtual UInt32	getReportKeyPowerState(void);	/* default = kElectronicsOn */

    /*!
     * @function getSendKeyPowerState
     * @abstract
     * Return the required device power level to execute a Send Key command.
     * @discussion
     * The default implementation of this method returns kElectronicsOn.
     * @result
     * The return value must be a valid power state value.
     */    
    virtual UInt32	getSendKeyPowerState(void);	/* default = kElectronicsOn */

    /*!
     * @function instantiateNub
     * @abstract
     * Instantiate the desired nub.
     * @discussion
     * This override allows us to instantiate an IOSCSIDVDDriveNub.
     */
    virtual IOService *	instantiateNub(void);

    /*!
     * @function reportMediaState
     * @abstract
     * Report the device's media state.
     * @discussion
     * This override allows us to determine the media type after something is inserted.
     */
    virtual IOReturn	reportMediaState(bool *mediaPresent,bool *changed);
    
    /* end of IOSCSIHDDrive overrides */

    /* DVD APIs: */

    virtual UInt32	getMediaType(void);
    virtual IOReturn		reportKey(IOMemoryDescriptor *buffer,const DVDKeyClass DVDKeyClass,
                                        const UInt32 lba,const UInt8 agid,const DVDKeyFormat keyFormat);
    virtual IOReturn		sendKey(IOMemoryDescriptor *buffer,const DVDKeyClass DVDKeyClass,
                                        const UInt8 agid,const DVDKeyFormat keyFormat);
    
protected:

    virtual void	checkConfig(UInt8 *buf,UInt32 actual);
    virtual IOReturn	determineMediaType(void);
    virtual IOReturn	getConfiguration(UInt8 *buffer,UInt32 length,UInt32 *actualLength,bool current);

    UInt8		_configBuf[kMaxConfigLength];

    UInt32		_configSize;
    bool		_isDVDDrive;
    bool		_canDoCSS;
    UInt32		_mediaType;
    bool		_isWriteProtected;

};
#endif

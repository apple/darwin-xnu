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
 * IOSCSICDDrive.h
 *
 * This class implements SCSI CDROM functionality.
 *
 * Subclasses may modify the operations to handle device-specific variations.
 */

#ifndef _IOSCSICDDRIVE_H
#define	_IOSCSICDDRIVE_H

#include <IOKit/IOTypes.h>
#include <IOKit/scsi/IOSCSIDeviceInterface.h>
#include <IOKit/storage/IOCDTypes.h>
#include <IOKit/storage/scsi/IOSCSIHDDrive.h>

/* SCSI (inquiry) device type. */

enum {
    kIOSCSIDeviceTypeCDROM         = 0x05
};

/* SCSI commands. */

enum {
    kIOSCSICommandReadSubChannel   = 0x42,
    kIOSCSICommandReadTOC          = 0x43,
    kIOSCSICommandPlayAudioMSF     = 0x47,
    kIOSCSICommandPauseResume      = 0x4b,
    kIOSCSICommandStopPlay         = 0x4e,
    kIOSCSICommandScan             = 0xba,
    kIOSCSICommandReadCD           = 0xbe
};

struct IOAudioPlayMSFcdb {
    UInt8	opcode;
    UInt8	lunbits;
    UInt8	reserved1;
    UInt8	start_m;
    UInt8	start_s;
    UInt8	start_f;
    UInt8	end_m;
    UInt8	end_s;
    UInt8	end_f;
    UInt8	ctlbyte;
};

struct IOReadToccdb {
    UInt8	opcode;
    UInt8	lunbits;
static const UInt8	kMSF = 0x02;		/* set to get mm:ss:ff format, else logical addr */
    UInt8	reserved1;
    UInt8	reserved2;
    UInt8	reserved3;
    UInt8	reserved4;
    UInt8	start_trk_session;	/* starting track/session number */
    UInt8	len_hi;
    UInt8	len_lo;
    UInt8	ctlbyte;		/* and format code */
static const UInt8	kTOC		= 0x00;
static const UInt8	kSessionInfo	= 0x01;
static const UInt8	kFullTOC 	= 0x02;
};

struct IORSCcdb {
    UInt8	opcode;
    UInt8	lunbits;
static const UInt8	kMSF = 0x02;		/* set to get mm:ss:ff format, else logical addr */
    UInt8	subq;
static const UInt8	kSubq = 0x40;		/* set to get subq data */
    UInt8	dataformat;
static const UInt8	kCurrentPosition	= 1;
static const UInt8	kMCN			= 2;
static const UInt8	kISRC			= 3;
    UInt8	reserved1;
    UInt8	reserved2;
    UInt8	track;
    UInt8	len_hi;
    UInt8	len_lo;
    UInt8	ctlbyte;
};

/*!
 * @class IOSCSICDDrive : public IOSCSIHDDrive
 * @abstract
 * Driver for SCSI CD-ROM drives.
 * @discussion
 * IOSCSICDDrive is a subclass of IOSCSIHDDrive. It adds appropriate CD-ROM
 * APIs (e.g. audio), and overrides some methods of IOSCSIHDDrive in order
 * to alter their behavior for CD-ROM devices.
 */
/*------------------------------------------------*/
class IOSCSICDDrive : public IOSCSIHDDrive {

    OSDeclareDefaultStructors(IOSCSICDDrive)

public:

    /* Overrides from IOService: */
    
    virtual bool	init(OSDictionary * properties);
    
    /* Overrides from IOBasicSCSI: */

    /*!
     * @function deviceTypeMatches
     * @abstract
     * Determine if the device type matches that which we expect.
     * @discussion
     * This override allows us to check for the SCSI CD-ROM
     * device type instead of hard disk.
     * See IOBasicSCSI for details.
     */
    virtual bool	deviceTypeMatches(UInt8 inqBuf[],UInt32 inqLen,SInt32 *score);

    /* End of IOBasicSCSI overrides */

    /* IOSCSIHDDrive overrides: */

    /*!
     * @function doAsyncReadWrite
     * @abstract
     * Start an asynchronous read or write operation.
     * @discussion
     * See IOBlockStorageDevice for details.
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
     * This override allows us to reject formatting attempts for CD-ROM.
     */
    virtual IOReturn	doFormatMedia(UInt64 byteCapacity);

    /*!
     * @function doGetFormatCapacities
     * @abstract
     * Report available formatting capacities for the device/media.
     * @discussion
     * This override allows us to reject formatting attempts for CD-ROM.
     */
    virtual UInt32	doGetFormatCapacities(UInt64 * capacities,
                                            UInt32   capacitiesMaxCount) const;

    /*!
     * @function doSynchronizeCache
     * @abstract
     * Issue a synchronize-cache command when finished with a drive.
     * @discussion
     * This override allows us to reject the operation, since we never write to CD-ROM.
     */
    virtual IOReturn	doSynchronizeCache(void);
    
    /*!
     * @function getDeviceTypeName
     * @abstract
     * Return a character string for the device type.
     * @discussion
     * This override returns kIOBlockStorageDeviceTypeCDROM.   
     */
    virtual const char * getDeviceTypeName(void);
    /*!
     * @function instantiateNub
     * @abstract
     * Create the device nub.
     * @discussion
     * This override instantiates an IOSCSICDDriveNub instead of an IOSCSIHDDriveNub.
     */
    virtual IOService *	instantiateNub(void);

    /* We want to track media changes to do cleanup.     */
    /*!
     * @function reportMediaState
     * @abstract
     * Report the device's media state.
     * @discussion
     * This override allows us to reset device settings when media changes.
     */
    virtual IOReturn	reportMediaState(bool *mediaPresent,bool *changed);

    /* end of IOSCSIHDDrive overrides */
    
    /*-----------------------------------------*/
    /* CD APIs                                 */
    /*-----------------------------------------*/

    /*!
     * @abstract
     * Start an asynchronous read CD operation.
     * @param buffer
     * An IOMemoryDescriptor describing the data-transfer buffer.  Responsiblity for releasing the descriptor
     * rests with the caller.
     * @param timeStart
     * The starting M:S:F address of the data transfer.
     * @param timeStop
     * The ending M:S:F address of the data transfer.
     * @param sectorArea
     * Sector area(s) to read.
     * @param sectorType
     * Sector type that is expected.  The data transfer is terminated as soon as
     * data is encountered that does not match the expected type.
     * @param action
     * The C function called upon completion of the data transfer.
     * @param target
     * The C++ class "this" pointer, passed as an argument to "action."
     * @param param
     * This value is passed as an argument to "action." It is not validated or modified.
     */    

    virtual IOReturn	doAsyncReadCD(IOMemoryDescriptor *buffer,
                                      UInt32 block,UInt32 nblks,
                                      CDSectorArea sectorArea,
                                      CDSectorType sectorType,
                                      IOStorageCompletion completion);

    /*!
     * @function readISRC
     * @abstract
     * Read the International Standard Recording Code for the specified track.
     * @param track
     * The track number from which to read the ISRC.
     * @param isrc
     * The buffer for the ISRC data.  Buffer contents will be zero-terminated.
     */
    virtual IOReturn	readISRC(UInt8 track,CDISRC isrc);
    
    /*!
     * @function readMCN
     * @abstract
     * Read the Media Catalog Number (also known as the Universal Product Code).
     * @param mcn
     * The buffer for the MCN data.  Buffer contents will be zero-terminated.
     */
    virtual IOReturn	readMCN(CDMCN mcn);

    /*!
     * @function readTOC
     * @abstract
     * Read the full Table Of Contents.
     * @param buffer
     * The buffer for the returned data.
     */
    virtual IOReturn	readTOC(IOMemoryDescriptor * buffer);
    
    /*!
     * @function reportMaxWriteTransfer
     * @abstract
     * Report the maximum allowed byte transfer for write operations.
     * @discussion
     * This override lets us return zero for the max write transfer, since
     * we never write to CD-ROM media. See IOBasicSCSI for other details.
     */
    virtual IOReturn	reportMaxWriteTransfer(UInt64 blockSize,UInt64 *max);

    /*!
     * @function reportWriteProtection
     * @abstract
     * Report whether the media is write-protected or not.
     * @discussion
     * This override lets us return TRUE in all cases. See IOBasicSCSI for details.
     */
    virtual IOReturn	reportWriteProtection(bool *isWriteProtected);
    
    /*-----------------------------------------*/
    /*  APIs exported by IOCDAudioControl      */
    /*-----------------------------------------*/

    /*!
     * @function audioPause
     * @abstract
     * Pause or resume the audio playback.
     * @param pause
     * True to pause playback; False to resume.
     */
    virtual IOReturn	audioPause(bool pause);
    /*!
     * @function audioPlay
     * @abstract
     * Play audio.
     * @param timeStart
     * The M:S:F address from which to begin.
     * @param timeStop
     * The M:S:F address at which to stop.
     */
    virtual IOReturn	audioPlay(CDMSF timeStart,CDMSF timeStop);
    /*!
     * @function audioScan
     * @abstract
     * Perform a fast-forward or fast-backward operation.
     * @param timeStart
     * The M:S:F address from which to begin.
     * @param reverse
     * True to go backward; False to go forward.
     */
    virtual IOReturn	audioScan(CDMSF timeStart,bool reverse);
    /*!
     * @function audioStop
     * @abstract
     * Stop the audio playback (or audio scan).
     */
    virtual IOReturn	audioStop();
    /*!
     * @function getAudioStatus
     * @abstract
     * Get the current audio play status information.
     * @param status
     * The buffer for the returned information.
     */
    virtual IOReturn	getAudioStatus(CDAudioStatus *status);
    /*!
     * @function getAudioVolume
     * @abstract
     * Get the current audio volume.
     * @param leftVolume
     * A pointer to the returned left-channel volume.
     * @param rightVolume
     * A pointer to the returned right-channel volume.
     */
    virtual IOReturn	getAudioVolume(UInt8 *leftVolume,UInt8 *rightVolume);
    /*!
     * @function setAudioVolume
     * @abstract
     * Set the current audio volume.
     * @param leftVolume
     * The desired left-channel volume.
     * @param rightVolume
     * The desired right-channel volume.
     */
    virtual IOReturn	setAudioVolume(UInt8 leftVolume,UInt8 rightVolume);

protected:

    /* Internally used methods: */

    /*!
     * @function doAudioPlayCommand
     * @abstract
     * Issue an audio play command to the device.
     * @param timeStart
     * The M:S:F address from which to begin.
     * @param timeStop
     * The M:S:F address at which to stop.
     */
    virtual IOReturn	doAudioPlayCommand(CDMSF timeStart,CDMSF timeStop);
    
    /*!
     * @function mediaArrived
     * @abstract
     * React to new media arrival.
     */
    virtual void	mediaArrived(void);
    
    /*!
     * @function mediaGone
     * @abstract
     * React to media going away.
     */
    virtual void	mediaGone(void);
    
    /*!
     * @function readSubChannel
     * @abstract
     * Issue the command necessary to read subchannel data.
     * @param buffer
     * The buffer for the data.
     * @param length
     * The maximum data length desired.
     * @param dataFormat
     * The subchannel data desired.
     * @param track
     * The desired track from which to read the data
     */
    virtual IOReturn	readSubChannel(UInt8 *buffer,UInt32 length,UInt8 dataFormat,UInt8 trackNumber);
};
#endif

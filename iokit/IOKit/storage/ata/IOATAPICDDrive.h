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
 * IOATAPICDDrive.h - Generic ATAPI CD-ROM driver.
 *
 * HISTORY
 * Sep 2, 1999	jliu - Ported from AppleATAPIDrive.
 */

#ifndef	_IOATAPICDDRIVE_H
#define	_IOATAPICDDRIVE_H

#include <IOKit/IOTypes.h>
#include <IOKit/storage/ata/IOATAPIHDDrive.h>
#include <IOKit/storage/IOCDTypes.h>

// ATAPI (inquiry) device type.
//
enum
{
	kIOATAPIDeviceTypeCDROM         = 0x05
};

// ATAPI packet commands.
//
enum
{
	kIOATAPICommandReadSubChannel   = 0x42,
	kIOATAPICommandReadTOC          = 0x43,
	kIOATAPICommandPlayAudioMSF     = 0x47,
	kIOATAPICommandPauseResume      = 0x4b,
	kIOATAPICommandStopPlay         = 0x4e,
	kIOATAPICommandScan             = 0xba,
	kIOATAPICommandReadCD           = 0xbe
};

//===========================================================================
// IOATAPICDDrive
//===========================================================================

class IOATAPICDDrive : public IOATAPIHDDrive
{
    OSDeclareDefaultStructors(IOATAPICDDrive)

protected:
	//-----------------------------------------------------------------------
	// Given the device type from the ATAPI Inquiry data, returns true if
	// the device type is supported by this driver.

	virtual bool           matchATAPIDeviceType(UInt8 type, SInt32 * score);

    //----------------------------------------------------------------------
    // ATAPI Read Subchannel command (42).

    virtual IOATACommand * atapiCommandReadSubChannel(
                            IOMemoryDescriptor * buffer,
                            UInt8 dataFormat,
                            UInt8 trackNumber);

	//-----------------------------------------------------------------------
	// ATAPI Read TOC command (43).

	virtual IOATACommand * atapiCommandReadTOC(
                                IOMemoryDescriptor * buffer,
                                bool                 msf,
                                UInt8                format,
                                UInt8                startTrackSession);

    //----------------------------------------------------------------------
    // ATAPI Play Audio command (47).

    virtual IOATACommand * atapiCommandPlayAudioMSF(
                            CDMSF timeStart,
                            CDMSF timeStop);

    //----------------------------------------------------------------------
    // ATAPI Pause/Resume command (4b).

    virtual IOATACommand * atapiCommandPauseResume(
                            bool resume);


    //----------------------------------------------------------------------
    // ATAPI STOP PLAY/SCAN command (4e).

    virtual IOATACommand * atapiCommandStopPlay();

    //----------------------------------------------------------------------
    // ATAPI Read CD command (b9).

    virtual IOATACommand * atapiCommandReadCD(
                                      IOMemoryDescriptor * buffer,
                                      UInt32               block,
                                      UInt32               nblks,
                                      CDSectorArea         sectorArea,
                                      CDSectorType         sectorType);

    //----------------------------------------------------------------------
    // ATAPI Scan command (ba).

    virtual IOATACommand * atapiCommandScan(
                            CDMSF timeStart,
                            bool  reverse);

	//-----------------------------------------------------------------------
	// Overrides the method in IOATAPIHDDrive and returns an
	// IOATAPICDDriveNub instance.

    virtual IOService *	   instantiateNub();

public:
    //-----------------------------------------------------------------------
    // Handles read CD requests.

    virtual IOReturn       doAsyncReadCD(IOMemoryDescriptor * buffer,
                                         UInt32               block,
                                         UInt32               nblks,
                                         CDSectorArea         sectorArea,
                                         CDSectorType         sectorType,
                                         IOStorageCompletion  completion);

	//-----------------------------------------------------------------------
	// IOATAHDDrive override. Returns the device type.

    virtual const char *   getDeviceTypeName();

	//-----------------------------------------------------------------------
	// IOATAPIHDDrive override. Reports whether media is write protected.

	virtual IOReturn       reportWriteProtection(bool * isWriteProtected);

	//-----------------------------------------------------------------------
	// Read the Table of Contents.

	virtual IOReturn       readTOC(IOMemoryDescriptor * buffer);

    //-----------------------------------------------------------------------
	// Play audio

    virtual IOReturn       audioPause(bool pause);

    virtual IOReturn       audioPlay(CDMSF timeStart, CDMSF timeStop);

    virtual IOReturn       audioScan(CDMSF timeStart, bool reverse);

    virtual IOReturn       audioStop();

    virtual IOReturn       getAudioStatus(CDAudioStatus *status);

    virtual IOReturn       getAudioVolume(UInt8 * leftVolume,
                                          UInt8 * rightVolume);

    virtual IOReturn       setAudioVolume(UInt8 leftVolume,
                                          UInt8 rightVolume);

    virtual IOReturn       readModeSense(UInt8 * buffer,
                                         UInt32 length, UInt8 pageCode,
                                         UInt8  pageControl = 0);

    virtual IOReturn       writeModeSelect(UInt8 * buffer,
                                           UInt32 length);

    virtual IOReturn       readSubChannel(UInt8 * buffer,
                                          UInt32  length,
                                          UInt8   dataFormat,
                                          UInt8   trackNumber);

    virtual IOReturn       readMCN(CDMCN mcn);

    virtual IOReturn       readISRC(UInt8 track, CDISRC isrc);
};

#endif /* !_IOATAPICDDRIVE_H */

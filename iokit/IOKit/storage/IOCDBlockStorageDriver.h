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
 * IOCDBlockStorageDriver.h
 *
 * This class implements  CD functionality, independent of
 * the physical connection protocol (e.g. SCSI, ATA, USB).
 *
 * A protocol-specific provider implements the functionality using an appropriate
 * protocol and commands.
 */

#ifndef	_IOCDBLOCKSTORAGEDRIVER_H
#define	_IOCDBLOCKSTORAGEDRIVER_H

#include <IOKit/IOTypes.h>
#include <IOKit/storage/IOCDBlockStorageDevice.h>
#include <IOKit/storage/IOCDTypes.h>
#include <IOKit/storage/IOBlockStorageDriver.h>

/*!
 * @defined kIOCDBlockStorageDriverClass
 * @abstract
 * kIOCDBlockStorageDriverClass is the name of the IOCDBlockStorageDriver class.
 * @discussion
 * kIOCDBlockStorageDriverClass is the name of the IOCDBlockStorageDriver class.
 */

#define kIOCDBlockStorageDriverClass "IOCDBlockStorageDriver"

class IOCDAudioControl;
class IOCDMedia;
class IOCDBlockStorageDevice;

class IOCDBlockStorageDriver : public IOBlockStorageDriver {

    OSDeclareDefaultStructors(IOCDBlockStorageDriver)

public:

    static const UInt64 kBlockSizeCD = 2352;
    static const UInt8  kBlockTypeCD = 0x01;

    /* Overrides of IORegistryEntry */
    
    virtual bool	init(OSDictionary * properties);

    /* Overrides of IOBlockStorageDriver: */

    virtual IOReturn	ejectMedia(void);
    virtual void 	executeRequest(UInt64 byteStart,
                	               IOMemoryDescriptor *buffer,
                	               IOStorageCompletion completion,
                	               Context *context);
    virtual const char * getDeviceTypeName(void);
    virtual IOMedia *	instantiateDesiredMediaObject(void);
    virtual IOMedia *	instantiateMediaObject(UInt64 base,UInt64 byteSize,
                                            UInt32 blockSize,char *mediaName);
    
    /* End of IOBlockStorageDriver overrides. */

    /*
     * @function getMediaType
     * @abstract
     * Get the current type of media inserted in the CD drive.
     * @discussion
     * Certain I/O operations may not be allowed depending on the type of
     * media currently inserted. For example, one cannot issue write operations
     * if CD-ROM media is inserted.
     * @result
     * See the kCDMediaType constants in IOCDTypes.h.
     */
    virtual UInt32	getMediaType(void);

    /* -------------------------------------------------*/
    /* APIs implemented here, exported by IOCDMedia:    */
    /* -------------------------------------------------*/

    virtual CDTOC *	getTOC(void);
    virtual void	readCD(IOService *client,
                           UInt64 byteStart,
                           IOMemoryDescriptor *buffer,
                           CDSectorArea sectorArea,
                           CDSectorType sectorType,
                           IOStorageCompletion completion);
    virtual IOReturn	readISRC(UInt8 track,CDISRC isrc);
    virtual IOReturn	readMCN(CDMCN mcn);

    /* end of IOCDMedia APIs */
    
    /* --------------------------------------------------------*/
    /* APIs implemented here, exported by IOCDAudioControl:    */
    /* --------------------------------------------------------*/

    virtual IOReturn	audioPause(bool pause);
    virtual IOReturn	audioPlay(CDMSF timeStart,CDMSF timeStop);
    virtual IOReturn	audioScan(CDMSF timeStart,bool reverse);
    virtual IOReturn	audioStop();
    virtual IOReturn	getAudioStatus(CDAudioStatus *status);
    virtual IOReturn	getAudioVolume(UInt8 *leftVolume,UInt8 *rightVolume);
    virtual IOReturn	setAudioVolume(UInt8 leftVolume,UInt8 rightVolume);

    /* end of IOCDAudioControl APIs */

    /*
     * Obtain this object's provider.  We override the superclass's method to
     * return a more specific subclass of IOService -- IOCDBlockStorageDevice.  
     * This method serves simply as a convenience to subclass developers.
     */

    virtual IOCDBlockStorageDevice * getProvider() const;

protected:
        
    /* Overrides of IOBlockStorageDriver behavior. */

    /* When CD media is inserted, we want to create multiple nubs for the data and
     * audio tracks, for sessions, and the entire media. We override the methods
     * that manage nubs.
     */
    virtual IOReturn	acceptNewMedia(void);
    virtual IOReturn	decommissionMedia(bool forcible);

    /* End of IOBlockStorageDriver overrides. */

    /* Internally used methods: */

    virtual IOReturn	cacheTocInfo(void);
    virtual UInt64	getMediaBlockSize(CDSectorArea area,CDSectorType type);
    virtual void	prepareRequest(UInt64 byteStart,
                                   IOMemoryDescriptor *buffer,
                                   CDSectorArea sectorArea,
                                   CDSectorType sectorType,
                                   IOStorageCompletion completion);

    /* ------- */

    struct ExpansionData { /* */ };
    ExpansionData * _expansionData;

    IOCDAudioControl *	_acNub;

    /* We keep the TOC here because we'll always need it, so what the heck.
     *
     * There are possible "point" track entries for 0xa0..a2, 0xb0..b4, and 0xc0..0xc1.
     * Tracks need not start at 1, as long as they're between 1 and 99, and have contiguous
     * numbers.
     */

    CDTOC *				_toc;
    UInt32				_tocSize;

    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDriver,  0);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDriver,  1);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDriver,  2);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDriver,  3);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDriver,  4);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDriver,  5);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDriver,  6);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDriver,  7);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDriver,  8);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDriver,  9);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDriver, 10);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDriver, 11);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDriver, 12);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDriver, 13);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDriver, 14);
    OSMetaClassDeclareReservedUnused(IOCDBlockStorageDriver, 15);
};
#endif

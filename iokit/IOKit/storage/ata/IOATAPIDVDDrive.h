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

#ifndef _IOATAPIDVDDRIVE_H
#define _IOATAPIDVDDRIVE_H

#include <IOKit/IOTypes.h>
#include <IOKit/storage/ata/IOATAPICDDrive.h>
#include <IOKit/storage/IODVDTypes.h>

enum {
    kIOATAPIFeatureProfileList              = 0x0000,
    kIOATAPIFeatureCore                     = 0x0001,
    kIOATAPIFeatureMorphing                 = 0x0002,
    kIOATAPIFeatureRemovableMedium          = 0x0003,
    kIOATAPIFeatureRandomReadable           = 0x0010,
    kIOATAPIFeatureMultiRead                = 0x001d,
    kIOATAPIFeatureCDRead                   = 0x001e,
    kIOATAPIFeatureDVDRead                  = 0x001f,
    kIOATAPIFeatureRandomWrite              = 0x0020,
    kIOATAPIFeatureIncrStreamWrite          = 0x0021,
    kIOATAPIFeatureSectorErasable           = 0x0022,
    kIOATAPIFeatureFormattable              = 0x0023,
    kIOATAPIFeatureDefectManagement         = 0x0024,
    kIOATAPIFeatureWriteOnce                = 0x0025,
    kIOATAPIFeatureRestrictedOverwrite      = 0x0026,
    kIOATAPIFeatureDVDRWRestrictedOverwrite = 0x002c,
    kIOATAPIFeatureCDTrackAtOnce            = 0x002d,
    kIOATAPIFeatureCDMastering              = 0x002e,
    kIOATAPIFeatureDVDR_RWWrite             = 0x002f,
    kIOATAPIFeaturePowerManagement          = 0x0100,
    kIOATAPIFeatureSMART                    = 0x0101,
    kIOATAPIFeatureEmbeddedChanger          = 0x0102,
    kIOATAPIFeatureCDAudioAnalogPlay        = 0x0103,
    kIOATAPIFeatureMicrocodeUpgrade         = 0x0104,
    kIOATAPIFeatureTimeout                  = 0x0105,
    kIOATAPIFeatureDVDCSS                   = 0x0106,
    kIOATAPIFeatureRealTimeStreaming        = 0x0107,
    kIOATAPIFeatureLUNSerialNumber          = 0x0108,
    kIOATAPIFeatureDiskControlBlocks        = 0x010a,
    kIOATAPIFeatureDVDCPRM                  = 0x010b
};

// DVD specific command codes.

enum {
    kIOATAPICommandGetConfiguration         = 0x46,
    kIOATAPICommandSendKey                  = 0xa3,
    kIOATAPICommandReportKey                = 0xa4,
    kIOATAPICommandReadDVDStructure         = 0xad
};

// Format code definitions for READ DVD STRUCTURE command.

enum {
    kIODVDReadStructurePhysical             = 0x00,
    kIODVDReadStructureCopyright            = 0x01,
    kIODVDReadStructureWriteProtection      = 0xC0
};  

#define IODVDGetDataLength16(ptr)      OSReadBigInt16((void *) ptr, 0)
#define IODVDGetDataLength32(ptr)      OSReadBigInt32((void *) ptr, 0)

#if defined(__BIG_ENDIAN__)

// Big Endian DVD structure definitions.

struct IODVDStructurePhysical
{
    UInt8  length[2];
    UInt8  rsvd1[2];

    UInt8  bookType      : 4,
           partVersion   : 4;

#define kIODVDBookTypeDVDROM     0
#define kIODVDBookTypeDVDRAM     1
#define kIODVDBookTypeDVDR       2
#define kIODVDBookTypeDVDRW      3
#define kIODVDBookTypeDVDPlusRW  9

    UInt8  diskSize      : 4,
           maximumRate   : 4;

    UInt8  rsvd2         : 1,
           layers        : 2,
           trackPath     : 1,
           layerType     : 4;

    UInt8  linearDensity : 4,
           trackDensity  : 4;

    UInt8  zero1;
    UInt8  dataAreaPSNStart[3];
    UInt8  zero2;
    UInt8  dataAreaPSNEnd[3];
    UInt8  zero3;
    UInt8  layerZeroEndSectorNumber;

    UInt8  bcaFlag       : 1,
           rsvd3         : 7;
};

struct IODVDStructureWriteProtection
{
    UInt8  length[2];
    UInt8  rsvd1[2];

    UInt8  rsvd2 : 4,
           mswi  : 1,
           cwp   : 1,
           pwp   : 1,
           swpp  : 1;
    
    UInt8  rsvd3[3];
};

#elif defined(__LITTLE_ENDIAN__)

// Little Endian DVD structure definitions.

struct IODVDStructurePhysical
{
    UInt8  length[2];
    UInt8  rsvd1[2];

    UInt8  partVersion   : 4,
           bookType      : 4;

#define kIODVDBookTypeDVDROM     0
#define kIODVDBookTypeDVDRAM     1
#define kIODVDBookTypeDVDR       2
#define kIODVDBookTypeDVDRW      3
#define kIODVDBookTypeDVDPlusRW  9

    UInt8  maximumRate   : 4,
           diskSize      : 4;

    UInt8  layerType     : 4,
           trackPath     : 1,
           layers        : 2,
           rsvd2         : 1;

    UInt8  trackDensity  : 4,
           linearDensity : 4;

    UInt8  zero1;
    UInt8  dataAreaPSNStart[3];
    UInt8  zero2;
    UInt8  dataAreaPSNEnd[3];
    UInt8  zero3;
    UInt8  layerZeroEndSectorNumber;

    UInt8  rsvd3         : 7,
           bcaFlag       : 1;
};

struct IODVDStructureWriteProtectionStatus
{
    UInt8  length[2];
    UInt8  rsvd1[2];

    UInt8  swpp  : 1,
           pwp   : 1,
           cwp   : 1,
           mswi  : 1,
           rsvd2 : 4;
    
    UInt8  rsvd3[3];
};

#else
#error Unknown endianess.
#endif

//===========================================================================
// IOATAPIDVDDrive
//===========================================================================

class IOATAPIDVDDrive : public IOATAPICDDrive
{
    OSDeclareDefaultStructors(IOATAPIDVDDrive)

protected:
    virtual IOReturn determineMediaType(UInt32 * mediaType);

    virtual IOReturn getConfiguration(UInt8 *  buffer,
                                      UInt32   length,
                                      UInt32 * actualLength,
                                      bool     current);

    virtual IOReturn classifyDrive(bool * isDVDDrive);

	virtual bool matchATAPIDeviceType(UInt8 type, SInt32 * score);

    virtual IOService * instantiateNub();

    virtual IOATACommand * atapiCommandGetConfiguration(
                                       IOMemoryDescriptor * buffer,
                                       UInt8                rt,
                                       UInt16               sfn = 0);

    virtual IOATACommand * atapiCommandSendKey(
                                       IOMemoryDescriptor * buffer,
                                       const DVDKeyClass    keyClass,
                                       const UInt8          agid,
                                       const DVDKeyFormat   keyFormat);

    virtual IOATACommand * atapiCommandReportKey(
                                       IOMemoryDescriptor * buffer,
                                       const DVDKeyClass    keyClass,
                                       const UInt32         lba,
                                       const UInt8          agid,
                                       const DVDKeyFormat   keyFormat);

    virtual IOATACommand * atapiCommandReadDVDStructure(
                                       IOMemoryDescriptor * buffer,
                                       UInt8                format,
                                       UInt32               address = 0,
                                       UInt8                layer   = 0,
                                       UInt8                agid    = 0);

public:
    virtual bool init(OSDictionary * properties);
    
    virtual const char * getDeviceTypeName();

    virtual UInt32 getMediaType();
        
    virtual IOReturn reportWriteProtection(bool * isWriteProtected);
        
    virtual IOReturn reportMediaState(bool * mediaPresent, bool * changed);

    virtual IOReturn reportKey(IOMemoryDescriptor * buffer,
                               const DVDKeyClass    keyClass,
                               const UInt32         lba,
                               const UInt8          agid,
                               const DVDKeyFormat   keyFormat);

    virtual IOReturn sendKey(IOMemoryDescriptor * buffer,
                             const DVDKeyClass    keyClass,
                             const UInt8          agid,
                             const DVDKeyFormat   keyFormat);
};

#endif /* ! _IOATAPIDVDDRIVE_H */

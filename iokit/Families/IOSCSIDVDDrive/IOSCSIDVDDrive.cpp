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
// =============================================================================
// Copyright (c) 2000 Apple Computer, Inc.  All rights reserved. 
//
// IOSCSIDVDDrive.cpp
//
#include <IOKit/IOLib.h>
#include <IOKit/IOReturn.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/scsi/IOSCSIDeviceInterface.h>
#include <IOKit/storage/scsi/IOSCSIDVDDrive.h>
#include <IOKit/storage/scsi/IOSCSIDVDDriveNub.h>
#include <IOKit/storage/IODVDTypes.h>
#include <libkern/OSByteOrder.h>

#define	super	IOSCSICDDrive
OSDefineMetaClassAndStructors(IOSCSIDVDDrive,IOSCSICDDrive)

/*----------------*/
const int kFeatureProfileList		= 0x0000;
const int kFeatureCore			= 0x0001;
const int kFeatureMorphing		= 0x0002;
const int kFeatureRemovableMedium      	= 0x0003;
const int kFeatureRandomReadable       	= 0x0010;
const int kFeatureMultiRead		= 0x001d;
const int kFeatureCDRead		= 0x001e;
const int kFeatureDVDRead		= 0x001f;
const int kFeatureRandomWrite		= 0x0020;
const int kFeatureIncrStreamWrite	= 0x0021;
const int kFeatureSectorErasable	= 0x0022;
const int kFeatureFormattable		= 0x0023;
const int kFeatureDefectManagement	= 0x0024;
const int kFeatureWriteOnce		= 0x0025;
const int kFeatureRestrictedOverwrite	= 0x0026;
const int kFeatureDVDRWRestrictedOverwrite	= 0x002c;
const int kFeatureCDTrackAtOnce		= 0x002d;
const int kFeatureCDMastering		= 0x002e;
const int kFeatureDVDR_RWWrite		= 0x002f;
const int kFeaturePowerManagement	= 0x0100;
const int kFeatureSMART			= 0x0101;
const int kFeatureEmbeddedChanger	= 0x0102;
const int kFeatureCDAudioAnalogPlay	= 0x0103;
const int kFeatureMicrocodeUpgrade	= 0x0104;
const int kFeatureTimeout		= 0x0105;
const int kFeatureDVDCSS		= 0x0106;
const int kFeatureRealTimeStreaming	= 0x0107;
const int kFeatureLUNSerialNumber	= 0x0108;
const int kFeatureDiskControlBlocks	= 0x010a;
const int kFeatureDVDCPRM		= 0x010b;

void
IOSCSIDVDDrive::checkConfig(UInt8 *buf,UInt32 actual)
{
    struct featureHdr {
        UInt32 totalLen;
        UInt8 reserved1[2];
        UInt16 currentProfile;
    };
    struct featureDescriptor {
        UInt16 featureCode;
        UInt8 versionPC;
        UInt8 additionalLength;
    };

    int len;
    struct featureHdr *fh;
    struct featureDescriptor *fdp;
    
    fh = (struct featureHdr *)buf;
    len = OSSwapBigToHostInt32(fh->totalLen);

    fdp = (struct featureDescriptor *)(&buf[8]);

    do {

        switch (OSSwapBigToHostInt16(fdp->featureCode)) {

            case kFeatureDVDRead :
                            _isDVDDrive = true;
                            break;
            case kFeatureDVDCSS :
                            _canDoCSS = true;
                            break;
        }
        fdp = (struct featureDescriptor *)((char *)fdp +
                                           sizeof(struct featureDescriptor) +
                                           fdp->additionalLength);
    } while ((UInt8 *)fdp < &buf[len]);
}

IOReturn
IOSCSIDVDDrive::determineMediaType(void)
{
    struct featureHdr {
        UInt32 totalLen;
        UInt8 reserved1[2];
        UInt16 currentProfile;
    };
    struct featureDescriptor {
        UInt16 featureCode;
        UInt8 versionPC;
        UInt8 additionalLength;
    };

    int len;
    struct featureHdr *fh;
    struct featureDescriptor *fdp;
    IOReturn result;
    UInt32 configSize;
    UInt8 configBuf[kMaxConfigLength];

    /* Get the *current* configuration information, relating to the media. */
    
    result = getConfiguration(configBuf,kMaxConfigLength,&configSize,true);
    if (result != kIOReturnSuccess) {
        IOLog("%s[IOSCSIDVDDrive]::determineMediaType; result = '%s'\n",
            getName(),stringFromReturn(result));
        return(result);
    }

    fh = (struct featureHdr *)configBuf;
    len = OSSwapBigToHostInt32(fh->totalLen);

    fdp = (struct featureDescriptor *)(&configBuf[8]);

    _mediaType = kDVDMediaTypeUnknown;	/* assume there is no media inserted */
    
    do {

        switch (OSSwapBigToHostInt16(fdp->featureCode)) {

            case kFeatureCDRead :
                            _mediaType = kCDMediaTypeROM;
                            IOLog("%s[IOSCSIDVDDrive]::determineMediaType; media is %s.\n",getName(),"CD");
                            break;
            case kFeatureDVDRead :
                            _mediaType = kDVDMediaTypeROM;
                            IOLog("%s[IOSCSIDVDDrive]::determineMediaType; media is %s.\n",getName(),"DVDROM");
                            break;
            case kFeatureFormattable :
                            _mediaType = kDVDMediaTypeRAM;
                            IOLog("%s[IOSCSIDVDDrive]::determineMediaType; media is %s.\n",getName(),"DVDRam");
                            break;
            case kFeatureRandomWrite :
                            _isWriteProtected = false;
                            IOLog("%s[IOSCSIDVDDrive]::determineMediaType; write-enabled.\n",getName());
                            break;
        }
        fdp = (struct featureDescriptor *)((char *)fdp +
                                           sizeof(struct featureDescriptor) +
                                           fdp->additionalLength);
    } while ((UInt8 *)fdp < &configBuf[len]);

    if (_mediaType == kDVDMediaTypeUnknown) {
        IOLog("%s[IOSCSIDVDDrive]::determineMediaType; drive is empty.\n",getName());
    }

    return(kIOReturnSuccess);
}

bool
IOSCSIDVDDrive::deviceTypeMatches(UInt8 inqBuf[],UInt32 inqLen,SInt32 *score)
{
    IOReturn result;
    UInt8 type;

    type = inqBuf[0] & 0x1f;
    
    if (type == kIOSCSIDeviceTypeCDROM) {
        // IOLog("%s[IOSCSIDVDDrive]::deviceTypeMatches; device type %d is CD/DVD\n",getName(),type);

        /* Try to get the device configuration. If we can, then it must be a DVD
         * drive since it follows the MtFuji command set (so far). If we cannot
         * get the configuration, then the device must be a plain CDROM drive.
         */
        result = getConfiguration(_configBuf,kMaxConfigLength,&_configSize,false);
        if (result == kIOReturnSuccess) {
            // IOLog("%s[IOSCSIDVDDrive]::deviceTypeMatches getConfig OK; returning true\n",getName());
            checkConfig(_configBuf,_configSize);
            if (_isDVDDrive) {
                // IOLog("---isDVDDrive\n");
                *score = 16;			/* override any CD driver match */
                return(true);
            } else {				/* not DVD */
                return(false);
            }
        } else  {
            // IOLog("%s[IOSCSIDVDDrive]::deviceTypeMatches getConfig fail; returning false\n",getName());
            return(false);
        }
    } else {
        /**
        IOLog("%s[IOSCSIDVDDrive]::deviceTypeMatches; device type %d not CD/DVD, returning FALSE\n",
              getName(),type);
        **/
        return(false);			/* we don't handle other devices */        
    }
}

IOReturn
IOSCSIDVDDrive::doAsyncReadWrite(IOMemoryDescriptor *buffer,
                                            UInt32 block,UInt32 nblks,
                                            IOStorageCompletion completion)
{
    return(standardAsyncReadWrite(buffer,block,nblks,completion));
}

IOReturn
IOSCSIDVDDrive::doFormatMedia(UInt64 byteCapacity)
{
    return(standardFormatMedia(byteCapacity));
}

UInt32
IOSCSIDVDDrive::doGetFormatCapacities(UInt64 *capacities,UInt32 capacitiesMaxCount) const
{
    if (capacitiesMaxCount > 0) {
        *capacities = (UInt64)((UInt64)2600 * (UInt64)1048576);		/* DVD-RAM V1.0 is 2.6GB */
        return(1);
    } else {
        return(0);
    }
}

IOReturn
IOSCSIDVDDrive::doSynchronizeCache(void)
{
    return(standardSynchronizeCache());
}

IOReturn
IOSCSIDVDDrive::doSyncReadWrite(IOMemoryDescriptor *buffer,UInt32 block,UInt32 nblks)
{
    return(standardSyncReadWrite(buffer,block,nblks));
}

IOReturn
IOSCSIDVDDrive::getConfiguration(UInt8 *buffer,UInt32 length,UInt32 *actualLength,bool current)
{
    struct context *cx;
    struct IOGCCdb *c;
    IOSCSICommand *req;
    SCSICDBInfo scsiCDB;
    SCSIResults scsiResults;
    IOReturn result;

    cx = allocateContext();
    if (cx == NULL) {
        return(kIOReturnNoMemory);
    }
    
    req = cx->scsireq;

    bzero( &scsiCDB, sizeof(scsiCDB) );

    bzero(buffer,length);
    
    c = (struct IOGCCdb *)(scsiCDB.cdb);

    c->opcode = kIOSCSICommandGetConfiguration;
    c->lunRT = 0;
    if (current) {			/* only get current features */
        c->lunRT |= 0x01;
    }
    c->startFeature_lo = 0;
    c->startFeature_hi = 0;
    c->len_hi = length >> 8;
    c->len_lo = length & 0xff;
    c->ctlbyte = 0;
    
    scsiCDB.cdbLength = 10;
    req->setCDB( &scsiCDB );

    cx->memory = IOMemoryDescriptor::withAddress((void *)buffer,
                                                 length,
                                                 kIODirectionIn);
    req->setPointers( cx->memory, length, false );
    req->setPointers( cx->senseDataDesc, 255, false, true );
    req->setTimeout( 5000 );
    
    queueCommand(cx,kSync,getGetConfigurationPowerState());
    result = simpleSynchIO(cx);

    req->getResults(&scsiResults);
    if (result == kIOReturnUnderrun) {
        result = kIOReturnSuccess;
    }
    *actualLength = scsiResults.bytesTransferred;

    deleteContext(cx);

    return(result);
}

const char *
IOSCSIDVDDrive::getDeviceTypeName(void)
{
    return(kIOBlockStorageDeviceTypeDVD);
}

UInt32
IOSCSIDVDDrive::getGetConfigurationPowerState(void)
{
    return(kElectronicsOn);
}

UInt32
IOSCSIDVDDrive::getReportKeyPowerState(void)
{
    return(kElectronicsOn);
}

UInt32
IOSCSIDVDDrive::getSendKeyPowerState(void)
{
    return(kElectronicsOn);
}

UInt32
IOSCSIDVDDrive::getMediaType(void)
{
    return(_mediaType);
}

bool
IOSCSIDVDDrive::init(OSDictionary * properties)
{
    _isDVDDrive = false;
    _canDoCSS = false;
    _configSize = 0;
    _mediaType = kDVDMediaTypeUnknown;
    _isWriteProtected = true;
    
    return(super::init(properties));
}

IOService *
IOSCSIDVDDrive::instantiateNub(void)
{
    IOService *nub;

    /* Instantiate a generic DVD nub so a generic driver can match above us. */
    
    nub = new IOSCSIDVDDriveNub;
    return(nub);
}

IOReturn
IOSCSIDVDDrive::reportKey(IOMemoryDescriptor *buffer,const DVDKeyClass keyClass,
                                        const UInt32 lba,const UInt8 agid,const DVDKeyFormat keyFormat)
{
    struct context *cx;
    struct IORKCdb *c;
    IOSCSICommand *req;
    SCSICDBInfo scsiCDB;
    IOReturn result;

    cx = allocateContext();
    if (cx == NULL) {
        return(kIOReturnNoMemory);
    }
    
    req = cx->scsireq;

    bzero( &scsiCDB, sizeof(scsiCDB) );

    c = (struct IORKCdb *)(scsiCDB.cdb);

    c->opcode = kIOSCSICommandReportKey;
    if (keyFormat == kTitleKey) {
        c->lba_0 = lba >> 24;
        c->lba_1 = lba >> 16;
        c->lba_2 = lba >>  8;
        c->lba_3 = lba & 0xff;
    }
    c->keyClass = keyClass;
    c->len_hi = buffer->getLength() >> 8;
    c->len_lo = buffer->getLength() & 0xff;
    c->agidKeyFormat = agid << 6 | keyFormat;
    c->ctlbyte = 0;
    
    scsiCDB.cdbLength = 10;
    req->setCDB( &scsiCDB );

    cx->memory = buffer;

    req->setPointers( cx->memory, cx->memory->getLength(), false );
    req->setPointers( cx->senseDataDesc, 255, false, true );
    req->setTimeout( 5000 );
    
    queueCommand(cx,kSync,getReportKeyPowerState());
    result = simpleSynchIO(cx);

    deleteContext(cx);

    return(result);
}

IOReturn
IOSCSIDVDDrive::reportMediaState(bool *mediaPresent,bool *changed)
{
    IOReturn result;

    /* Let the superclass check for media in the standard way: */
    
    result = super::reportMediaState(mediaPresent,changed);

    if (result != kIOReturnSuccess) {
        IOLog("%s[IOSCSIDVDDrive]:: reportMediaState; result = '%s' from super\n",
            getName(),stringFromReturn(result));
        return(result);
    }

    /* If we have newly-inserted media, determine its type: */
    
    if (*mediaPresent && *changed) {
        result = determineMediaType();
    }
    
    return(result);
}

IOReturn
IOSCSIDVDDrive::reportWriteProtection(bool *isWriteProtected)
{
    *isWriteProtected = _isWriteProtected;
    return(kIOReturnSuccess);
}

IOReturn
IOSCSIDVDDrive::sendKey(IOMemoryDescriptor *buffer,const DVDKeyClass keyClass,
                                        const UInt8 agid,const DVDKeyFormat keyFormat)
{
    struct context *cx;
    struct IOSKCdb *c;
    IOSCSICommand *req;
    SCSICDBInfo scsiCDB;
    IOReturn result;

    cx = allocateContext();
    if (cx == NULL) {
        return(kIOReturnNoMemory);
    }
    
    req = cx->scsireq;

    bzero( &scsiCDB, sizeof(scsiCDB) );

    c = (struct IOSKCdb *)(scsiCDB.cdb);

    c->opcode = kIOSCSICommandSendKey;
    c->keyClass = keyClass;
    c->len_hi = buffer->getLength() >> 8;
    c->len_lo = buffer->getLength() & 0xff;
    c->agidKeyFormat = agid << 6 | keyFormat;
    c->ctlbyte = 0;
    
    scsiCDB.cdbLength = 10;
    req->setCDB( &scsiCDB );

    cx->memory = buffer;

    req->setPointers( cx->memory, cx->memory->getLength(), false );
    req->setPointers( cx->senseDataDesc, 255, false, true );
    req->setTimeout( 5000 );
    
    queueCommand(cx,kSync,getSendKeyPowerState());
    result = simpleSynchIO(cx);

    deleteContext(cx);

    return(result);
}

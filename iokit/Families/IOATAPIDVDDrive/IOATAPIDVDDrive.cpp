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

#include <IOKit/assert.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/storage/ata/IOATAPIDVDDrive.h>
#include <IOKit/storage/ata/IOATAPIDVDDriveNub.h>
#include <IOKit/storage/IODVDTypes.h>
#include <libkern/OSByteOrder.h>

// Define this to log debug messages.
//
// #define LOG_DVD_MESSAGES 1

#ifdef  LOG_DVD_MESSAGES
#define DEBUG_LOG(fmt, args...)  IOLog(fmt, ## args)
#else
#define DEBUG_LOG(fmt, args...)
#endif

#define super IOATAPICDDrive
OSDefineMetaClassAndStructors( IOATAPIDVDDrive, IOATAPICDDrive )

//---------------------------------------------------------------------------
// Feature header and descriptor definition.

struct featureHdr {
    UInt32 totalLen;
    UInt8  reserved1[2];
    UInt16 currentProfile;
};

struct featureDescriptor {
    UInt16 featureCode;
    UInt8  versionPC;
    UInt8  additionalLength;
};

#define kConfigBufferSize          2048
#define kConfigFeatureHeaderBytes  sizeof(struct featureHdr)
#define kConfigDataLengthBytes     sizeof(UInt32)
#define kConfigMinDataLength       (sizeof(struct featureHdr) - \
                                    kConfigDataLengthBytes    + \
                                    sizeof(struct featureDescriptor))

//---------------------------------------------------------------------------
// Classify an ATAPI CD-ROM drive as a CD or a DVD drive.

IOReturn IOATAPIDVDDrive::classifyDrive(bool * isDVDDrive)
{
    IOATACommand *              cmd = 0;
    IOBufferMemoryDescriptor *  copyrightDesc;
    IOBufferMemoryDescriptor *  senseDesc;
    IOReturn                    ret = kIOReturnSuccess;

    do {
        // Buffer descriptor to hold Copyright Information.

        copyrightDesc = IOBufferMemoryDescriptor::withCapacity(8,
                                                               kIODirectionIn);

        // Buffer descriptor to hold sense data.

        senseDesc = IOBufferMemoryDescriptor::withCapacity(
                                                  sizeof(ATASenseData),
                                                  kIODirectionIn);

        if ( (copyrightDesc == 0) || (senseDesc == 0) ) 
        {
            ret = kIOReturnNoMemory;
            break;
        }

        bzero(senseDesc->getBytesNoCopy(), senseDesc->getCapacity());

        // READ DVD STRUCTURE command - DVD Copyright Information

        cmd = atapiCommandReadDVDStructure(copyrightDesc, 
                                           kIODVDReadStructureCopyright);
        if (cmd == 0)
        {
            ret = kIOReturnNoMemory;
            break;
        }

        // Execute the command, and get sense data.

        ret = syncExecute(cmd,
                          kATADefaultTimeout,
                          kATADefaultRetries,
                          senseDesc);

        // By default, consider it a DVD drive, unless the drive
        // returns an error, and the sense data contains,
        //
        // KEY  = 0x05
        // ASC  = 0x20
        // ASCQ = 0x00

        *isDVDDrive = true;

        if (ret != kIOReturnSuccess)
        {
            ATASenseData * senseData;

            senseData = (ATASenseData *) senseDesc->getBytesNoCopy();

            if ((senseData->errorCode == kATAPISenseCurrentErr) ||
                (senseData->errorCode == kATAPISenseDeferredErr))
            {
                if ((senseData->senseKey == kATAPISenseIllegalReq) &&
                    (senseData->additionalSenseCode == 0x20)       &&
                    (senseData->additionalSenseQualifier == 0x0))
                {
                    *isDVDDrive = false;
                }
            }

            ret = kIOReturnSuccess;
        }
    }
    while (false);

    if (senseDesc)     senseDesc->release();
    if (copyrightDesc) copyrightDesc->release();
    if (cmd)           cmd->release();

    return ret;
}

//---------------------------------------------------------------------------
// Determine the media type (book type) in the DVD drive.

IOReturn
IOATAPIDVDDrive::determineMediaType(UInt32 * mediaType)
{
    IOATACommand *              cmd = 0;
    IOBufferMemoryDescriptor *  dataDesc;
    IODVDStructurePhysical *    data;
    IOReturn                    ret = kIOReturnSuccess;

    *mediaType = kDVDMediaTypeUnknown;

    do {
        // Buffer descriptor to hold Physical Format Information.

        dataDesc = IOBufferMemoryDescriptor::withCapacity(sizeof(*data),
                                                          kIODirectionIn);

        if ( dataDesc == 0 )
        {
            ret = kIOReturnNoMemory;
            break;
        }

        data = (IODVDStructurePhysical *) dataDesc->getBytesNoCopy();
        bzero(data, sizeof(data->length));

        // READ DVD STRUCTURE command - Physical Format Information

        cmd = atapiCommandReadDVDStructure(dataDesc,
                                           kIODVDReadStructurePhysical);
        if ( cmd == 0 )
        {
            ret = kIOReturnNoMemory;
            break;
        }

        // Execute the command.

        if ( syncExecute(cmd) != kIOReturnSuccess )
        {
            *mediaType = kCDMediaTypeROM;   // Assume its a CD.
        }
        else if ( IODVDGetDataLength16(data->length) <
                  (sizeof(*data) - sizeof(data->length)) )
        {
            ret = kIOReturnUnderrun;
        }
        else
        {
            DEBUG_LOG("%s: DVD Book Type: %x Part Version: %x\n",
                      getName(), data->bookType, data->partVersion);

            switch (data->bookType)
            {
                default:
                case kIODVDBookTypeDVDROM:
                case kIODVDBookTypeDVDR:
                case kIODVDBookTypeDVDRW:
                case kIODVDBookTypeDVDPlusRW:
                    *mediaType = kDVDMediaTypeROM;
                    break;

                case kIODVDBookTypeDVDRAM:
                    *mediaType = kDVDMediaTypeRAM;
                    break;
            }
        }
    }
    while (false);

    if (dataDesc)  dataDesc->release();
    if (cmd)       cmd->release();

    return ret;
}

//---------------------------------------------------------------------------
// Perform active matching with an ATAPI device nub published by the
// ATA controller driver.

bool
IOATAPIDVDDrive::matchATAPIDeviceType(UInt8 type, SInt32 * score)
{
    bool  isDVDDrive;
    bool  match = false;

    do {
        // If the device type reported by INQUIRY data is not a CD-ROM type,
        // then give up immediately.

        if ( type != kIOATAPIDeviceTypeCDROM )
            break;

        // Select timing protocol before performing I/O.

        if ( selectTimingProtocol() == false )
            break;

        // Is this unit a DVD drive?

        if ( classifyDrive(&isDVDDrive) != kIOReturnSuccess )
            break;

        if ( isDVDDrive )
        {
            // Indicate a strong affinity for the DVD drive by setting
            // a higher probe score when a DVD drive is detected.

            DEBUG_LOG("%s::%s DVD drive detected\n", getName(), __FUNCTION__);
            *score = 20;
            match  = true;
        }
        else
        {
            // Not a DVD drive.
            DEBUG_LOG("%s::%s Not a DVD drive\n", getName(), __FUNCTION__);
        }
    }
    while (false);

    return match;
}

//---------------------------------------------------------------------------
// GET CONFIGURATION command.

IOReturn
IOATAPIDVDDrive::getConfiguration(UInt8 *  buf,
                                  UInt32   length,
                                  UInt32 * actualLength,
                                  bool     current)
{
    IOMemoryDescriptor * bufDesc = 0;
    IOATACommand *       cmd = 0;
    IOReturn             ret = kIOReturnNoMemory;
    ATAResults           results;
    
    do {
        bufDesc = IOMemoryDescriptor::withAddress(buf, length, kIODirectionIn);
        if (bufDesc == 0)
            break;
        
        cmd = atapiCommandGetConfiguration(bufDesc, 0x01);
        if (cmd == 0)
            break;

        ret = syncExecute(cmd);

        cmd->getResults(&results);
        *actualLength = results.bytesTransferred;
    }
    while (0);

    if (cmd)     cmd->release();
    if (bufDesc) bufDesc->release();

    return ret;
}

//---------------------------------------------------------------------------
// Report disk type.

const char *
IOATAPIDVDDrive::getDeviceTypeName()
{
    return kIOBlockStorageDeviceTypeDVD;
}

//---------------------------------------------------------------------------
// Report the type of media in the DVD drive.

UInt32
IOATAPIDVDDrive::getMediaType()
{
    UInt32 mediaType;

    determineMediaType(&mediaType);

    return mediaType;
}

//---------------------------------------------------------------------------
// Initialize the IOATAPIDVDDrive object.

bool
IOATAPIDVDDrive::init(OSDictionary * properties)
{
    return super::init(properties);
}

//---------------------------------------------------------------------------
// Instantiate an IOATAPIDVDDriveNub nub.

IOService *
IOATAPIDVDDrive::instantiateNub(void)
{
    IOService * nub = new IOATAPIDVDDriveNub;

    /* Instantiate a generic DVD nub so a generic driver can match above us. */

    return nub;
}

//---------------------------------------------------------------------------
// Report the media state.

IOReturn
IOATAPIDVDDrive::reportMediaState(bool * mediaPresent, bool * changed)
{
    IOReturn result;

    // Let superclass check for media in a generic fashion.

    result = super::reportMediaState(mediaPresent, changed);

#if 0  // For testing only

    if (result != kIOReturnSuccess)
    {
        return result;
    }

    // For a new media, determine its type.
    
    if (*mediaPresent && *changed)
    {
        getMediaType();
    }
#endif

    return result;
}

//---------------------------------------------------------------------------
// Report random write support.

IOReturn
IOATAPIDVDDrive::reportWriteProtection(bool * isWriteProtected)
{
    UInt32                     len;
    struct featureHdr *        fh;
    struct featureDescriptor * fdp;
    IOReturn                   result;
    UInt8 *                    configBuf;
    UInt32                     configBufSize; /* not used */

    *isWriteProtected = true;

    /* Allocate memory for the configuration data.
       Theoretically, this can be up to 65534 bytes. */

    configBuf = (UInt8 *) IOMalloc(kConfigBufferSize);
    if ( configBuf == 0 )
        return kIOReturnNoMemory;

    bzero((void *) configBuf, kConfigBufferSize);
    
    /* Get the *current* configuration information, relating to the media. */

    do {
        result = getConfiguration(configBuf,
                                  kConfigBufferSize,
                                  &configBufSize,
                                  true); /* Get current (active) features */

        if (result == kIOReturnUnderrun)
        {
            // getConfiguration() will report an underrun.
            result = kIOReturnSuccess;
        }

        if (result != kIOReturnSuccess)
        {
            DEBUG_LOG("%s::%s getConfiguration() error = %s\n",
                      getName(), __FUNCTION__, stringFromReturn(result));
            result = kIOReturnSuccess;
            break;
        }

        fh = (struct featureHdr *) configBuf;
        len = OSSwapBigToHostInt32(fh->totalLen);

        if (len < kConfigMinDataLength)
        {
            result = kIOReturnUnderrun;
            break;
        }

        // total length, including the Data Length field.
        //
        len += kConfigDataLengthBytes;
        len = min(len, kConfigBufferSize);
        DEBUG_LOG("%s::%s config length = %ld\n", getName(), __FUNCTION__, len);

        // Points to the first Feature Descriptor after the Feature Header.
        //
        fdp = (struct featureDescriptor *)
              &configBuf[kConfigFeatureHeaderBytes];

        do {
            if (OSSwapBigToHostInt16(fdp->featureCode) ==
                kIOATAPIFeatureRandomWrite)
            {
                *isWriteProtected = false;
                break;
            }

            fdp = (struct featureDescriptor *)((char *)fdp +
                                            sizeof(struct featureDescriptor) +
                                            fdp->additionalLength);
        }
        while ( ((UInt8 *)fdp + sizeof(*fdp)) <= &configBuf[len] );
    }
    while (false);

    IOFree((void *) configBuf, kConfigBufferSize);

    return result;
}

//---------------------------------------------------------------------------
// SEND KEY command.

IOReturn
IOATAPIDVDDrive::sendKey(IOMemoryDescriptor * buffer,
                         const DVDKeyClass    keyClass,
                         const UInt8          agid,
                         const DVDKeyFormat   keyFormat)
{
    IOATACommand * cmd = 0;
    IOReturn       ret = kIOReturnNoMemory;

    do {
        assert(buffer);

        cmd = atapiCommandSendKey(buffer, keyClass, agid, keyFormat);
        if (cmd == 0)
            break;

        ret = syncExecute(cmd);
    }
    while (0);

    if (cmd)
        cmd->release();

    return ret;
}

//---------------------------------------------------------------------------
// REPORT KEY command.

IOReturn
IOATAPIDVDDrive::reportKey(IOMemoryDescriptor * buffer,
                           const DVDKeyClass    keyClass,
                           const UInt32         lba,
                           const UInt8          agid,
                           const DVDKeyFormat   keyFormat)
{
    IOATACommand * cmd = 0;
    IOReturn       ret = kIOReturnNoMemory;

    do {
        assert(buffer);
        
        cmd = atapiCommandReportKey(buffer, keyClass, lba, agid, keyFormat);
        if (cmd == 0)
            break;

        ret = syncExecute(cmd);
    }
    while (0);

    if (cmd)
        cmd->release();

    return ret;
}

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
#include <IOKit/IOReturn.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/scsi/IOSCSIDeviceInterface.h>
#include <IOKit/storage/scsi/IOSCSICDDrive.h>
#include <IOKit/storage/scsi/IOSCSICDDriveNub.h>

#define	super	IOSCSIHDDrive
OSDefineMetaClassAndStructors(IOSCSICDDrive,IOSCSIHDDrive)

static void __inline ConvertBCDToHex(UInt8 *value)
{
    *value = (((*value) >> 4) * 10) + ((*value) & 0x0f);
}

/* The Callback (C) entry from the SCSI provider. We just glue
 * right into C++.
 */

void
IOSCSICDDrive_gc_glue(IOService *object,void *param)
{
    IOSCSICDDrive *self;
    struct IOBasicSCSI::context *cx;

    self = (IOSCSICDDrive *)object;
    cx = (struct IOBasicSCSI::context *)param;
    self->genericCompletion(cx);    	/* do it in C++ */
}

IOReturn
IOSCSICDDrive::audioPause(bool pause)
{
    struct context *cx;
    SCSICDBInfo scsiCmd;
    IOReturn result;

    cx = allocateContext();
    if (cx == NULL) {
        return(kIOReturnNoMemory);
    }
    
    bzero(&scsiCmd, sizeof(scsiCmd));

    scsiCmd.cdbLength = 10;
    scsiCmd.cdb[0]    = kIOSCSICommandPauseResume;
    scsiCmd.cdb[8]    = pause ? 0x00 : 0x01;

    cx->scsireq->setCDB(&scsiCmd);
    cx->scsireq->setPointers(cx->memory, 0, false);
    cx->scsireq->setPointers(cx->senseDataDesc, 255, false, true);
    cx->scsireq->setTimeout(5000);

    result = simpleSynchIO(cx);

    deleteContext(cx);

    return(result);
}

IOReturn
IOSCSICDDrive::audioPlay(CDMSF timeStart,CDMSF timeStop)
{
    return(doAudioPlayCommand(timeStart,timeStop));
}

IOReturn
IOSCSICDDrive::audioScan(CDMSF timeStart,bool reverse)
{
    struct context *cx;
    SCSICDBInfo scsiCmd;
    IOReturn result;

    cx = allocateContext();
    if (cx == NULL) {
        return(kIOReturnNoMemory);
    }
    
    bzero(&scsiCmd, sizeof(scsiCmd));

    scsiCmd.cdbLength = 10;
    scsiCmd.cdb[0]    = 0xCD; /* AUDIO SCAN (10) */
    scsiCmd.cdb[1]    = reverse ? 0x10 : 0x00;
    scsiCmd.cdb[3]    = timeStart.minute;
    scsiCmd.cdb[4]    = timeStart.second;
    scsiCmd.cdb[5]    = timeStart.frame;
    scsiCmd.cdb[9]    = 0x40; /* MSF */

    cx->scsireq->setCDB(&scsiCmd);
    cx->scsireq->setPointers(cx->memory, 0, false);
    cx->scsireq->setPointers(cx->senseDataDesc, 255, false, true);    
    cx->scsireq->setTimeout(5000);

    result = simpleSynchIO(cx);

    deleteContext(cx);

    return(result);
}

IOReturn
IOSCSICDDrive::audioStop()
{
    struct context *cx;
    SCSICDBInfo scsiCmd;
    IOReturn result;

    cx = allocateContext();
    if (cx == NULL) {
        return(kIOReturnNoMemory);
    }
    
    bzero(&scsiCmd, sizeof(scsiCmd));

    scsiCmd.cdbLength = 6;
    scsiCmd.cdb[0]    = 0x01; /* REZERO UNIT (6) */

    cx->scsireq->setCDB(&scsiCmd);
    cx->scsireq->setPointers(cx->memory, 0, false);
    cx->scsireq->setPointers(cx->senseDataDesc, 255, false, true);    
    cx->scsireq->setTimeout(5000);

    result = simpleSynchIO(cx);

    deleteContext(cx);

    return(result);
}

bool
IOSCSICDDrive::deviceTypeMatches(UInt8 inqBuf[],UInt32 inqLen,SInt32 *score)
{
    if ((inqBuf[0] & 0x1f) == kIOSCSIDeviceTypeCDROM) {
//        IOLog("%s[IOSCSICDDrive]::deviceTypeMatches, returning TRUE\n",getName());
        *score = 0;
        return(true);
    } else {
//        IOLog("%s[IOSCSICDDrive]::deviceTypeMatches, returning FALSE\n",getName());  
        return(false);			/* we don't handle other devices */        
    }
}

IOReturn
IOSCSICDDrive::doAsyncReadCD(IOMemoryDescriptor *buffer,
                             UInt32 block,UInt32 nblks,
                             CDSectorArea sectorArea,
                             CDSectorType sectorType,
                             IOStorageCompletion completion)
{
    struct context *cx;
    SCSICDBInfo scsiCmd;

    assert(buffer->getDirection() == kIODirectionIn);

    bzero(&scsiCmd, sizeof(scsiCmd));

    if (sectorArea == kCDSectorAreaUser) {
        if (sectorType == kCDSectorTypeCDDA) {
            scsiCmd.cdbLength = 12;
            scsiCmd.cdb[ 0]   = 0xD8; /* READ CD-DA */
            scsiCmd.cdb[ 2]   = (block >> 24) & 0xFF;
            scsiCmd.cdb[ 3]   = (block >> 16) & 0xFF;
            scsiCmd.cdb[ 4]   = (block >>  8) & 0xFF;
            scsiCmd.cdb[ 5]   = (block      ) & 0xFF;
            scsiCmd.cdb[ 6]   = (nblks >> 24) & 0xFF;
            scsiCmd.cdb[ 7]   = (nblks >> 16) & 0xFF;
            scsiCmd.cdb[ 8]   = (nblks >>  8) & 0xFF;
            scsiCmd.cdb[ 9]   = (nblks      ) & 0xFF;
        } else if (sectorType == kCDSectorTypeMode1 ||
                   sectorType == kCDSectorTypeMode2Form1) {
            return doAsyncReadWrite(buffer,block,nblks,completion);
        }
    }

    if (scsiCmd.cdbLength == 0) {
        return(kIOReturnUnsupported);
    }

    cx = allocateContext();
    if (cx == NULL) {
        return(kIOReturnNoMemory);
    }

    buffer->retain();			/* bump the retain count */
    cx->memory = buffer;
    cx->completion = completion;
    cx->state = kAsyncReadWrite;

    cx->scsireq->setCallback(this, (CallbackFn)IOSCSICDDrive_gc_glue, cx);
    cx->scsireq->setCDB(&scsiCmd);
    cx->scsireq->setPointers(buffer, buffer->getLength(), false);
    cx->scsireq->setPointers(cx->senseDataDesc, 255, false, true);    
    cx->scsireq->setTimeout(60000);
 
    /* Queue the request awaiting power and return. When power comes up,
     * the request will be passed to standardAsyncReadWriteExecute.
     */
    queueCommand(cx,kAsync,getReadWritePowerState());	/* queue and possibly wait for power */

    return(kIOReturnSuccess);
}

IOReturn
IOSCSICDDrive::doAsyncReadWrite(IOMemoryDescriptor *buffer,
                                            UInt32 block,UInt32 nblks,
                                            IOStorageCompletion completion)
{
    if (buffer->getDirection() == kIODirectionOut) {
        return(kIOReturnNotWritable);
    }

    return(super::doAsyncReadWrite(buffer,block,nblks,completion));
}

IOReturn
IOSCSICDDrive::doSyncReadWrite(IOMemoryDescriptor *buffer,UInt32 block,UInt32 nblks)
{
    if (buffer->getDirection() == kIODirectionOut) {
        return(kIOReturnNotWritable);
    }

    return(super::doSyncReadWrite(buffer,block,nblks));
}

IOReturn
IOSCSICDDrive::doAudioPlayCommand(CDMSF timeStart,CDMSF timeStop)
{
    struct context *cx;
    struct IOAudioPlayMSFcdb *p;
    IOSCSICommand *req;
    SCSICDBInfo scsiCDB;
    IOReturn result;

    cx = allocateContext();
    if (cx == NULL) {
        return(kIOReturnNoMemory);
    }
    
    req = cx->scsireq;

    bzero( &scsiCDB, sizeof(scsiCDB) );

    p = (struct IOAudioPlayMSFcdb *)scsiCDB.cdb; /* use PlayAudioMSF */
    p->opcode	= kIOSCSICommandPlayAudioMSF;
    p->lunbits	= 0;
    p->reserved1	= 0;
    p->start_m      = timeStart.minute;
    p->start_s      = timeStart.second;
    p->start_f      = timeStart.frame;
    p->end_m        = timeStop.minute;
    p->end_s        = timeStop.second;
    p->end_f        = timeStop.frame;
    p->ctlbyte	= 0;

    scsiCDB.cdbLength = 10;
    req->setCDB( &scsiCDB );
    req->setPointers(cx->senseDataDesc, 255, false, true);    

    req->setPointers( cx->memory, 0, false );
    req->setTimeout( 5000 );

    result = simpleSynchIO(cx);

    deleteContext(cx);

    return(result);
}

IOReturn
IOSCSICDDrive::doFormatMedia(UInt64 /* byteCapacity */)
{
    return(kIOReturnUnsupported);
}

UInt32
IOSCSICDDrive::doGetFormatCapacities(UInt64 * /* capacities */,UInt32 /*  capacitiesMaxCount */) const
{
    return(kIOReturnUnsupported);
}

IOReturn
IOSCSICDDrive::doSynchronizeCache(void)
{
    return(kIOReturnUnsupported);
}

IOReturn
IOSCSICDDrive::getAudioStatus(CDAudioStatus *status)
{
    IOReturn result;
    UInt8 *tempBuf;

    /* Get a buffer for the returned data: */
    
    result = allocateTempBuffer(&tempBuf,16);
    if (result != kIOReturnSuccess) {
        return(kIOReturnNoMemory);
    }

    result = readSubChannel(tempBuf,16,IORSCcdb::kCurrentPosition,0);
    
    if (result == kIOReturnSuccess) {	/* we got the data */
        assert(tempBuf[2] == 0);
        assert(tempBuf[3] == 12);
        assert(tempBuf[4] == 1);
        
        status->status                     = tempBuf[ 1];

        status->position.track.number      = tempBuf[ 6];
        status->position.track.index       = tempBuf[ 7];

        status->position.time.minute       = tempBuf[ 9];
        status->position.time.second       = tempBuf[10];
        status->position.time.frame        = tempBuf[11];

        status->position.track.time.minute = tempBuf[13];
        status->position.track.time.second = tempBuf[14];
        status->position.track.time.frame  = tempBuf[15];
    }
    deleteTempBuffer(tempBuf,16);

    return(result);
}

IOReturn
IOSCSICDDrive::getAudioVolume(UInt8 *leftVolume,UInt8 *rightVolume)
{
    struct context *cx;
    SCSICDBInfo scsiCmd;
    IOReturn result;
    UInt8 audio_control[28];

    cx = allocateContext();
    if (cx == NULL) {
        return(kIOReturnNoMemory);
    }

    cx->memory = IOMemoryDescriptor::withAddress(audio_control,
                                                 sizeof(audio_control),
                                                 kIODirectionIn);
    if (cx->memory == NULL) {
        deleteContext(cx);
        return(kIOReturnNoMemory);
    }
    
    bzero(&scsiCmd, sizeof(scsiCmd));

    scsiCmd.cdbLength = 6;
    scsiCmd.cdb[0]    = 0x1a; /* MODE SENSE (6) */
    scsiCmd.cdb[2]    = 0x0e; /* PAGE CODE E */
    scsiCmd.cdb[4]    = sizeof(audio_control);

    cx->scsireq->setCDB(&scsiCmd);
    cx->scsireq->setPointers(cx->memory, sizeof(audio_control), true);
    cx->scsireq->setPointers(cx->senseDataDesc, 255, false, true);    
    cx->scsireq->setTimeout(5000);

    result = simpleSynchIO(cx);

    if (result == kIOReturnSuccess) {
        assert((audio_control[ 0]       ) == 28-1);
        assert((audio_control[ 3]       ) == 0x08);
        assert((audio_control[12] & 0x3f) == 0x0e); 
        assert((audio_control[13]       ) == 0x0e);

        *leftVolume  = audio_control[21];
        *rightVolume = audio_control[23];
    }

    deleteContext(cx);

    return(result);
}

const char *
IOSCSICDDrive::getDeviceTypeName(void)
{
    return(kIOBlockStorageDeviceTypeCDROM);
}

bool
IOSCSICDDrive::init(OSDictionary * properties)
{
    return(super::init(properties));
}

IOService *
IOSCSICDDrive::instantiateNub(void)
{
    IOService *nub;

    /* Instantiate a generic CDROM nub so a generic driver can match above us. */
    
    nub = new IOSCSICDDriveNub;
    return(nub);
}

void
IOSCSICDDrive::mediaArrived(void)
{
}

void
IOSCSICDDrive::mediaGone(void)
{
}

IOReturn
IOSCSICDDrive::readISRC(UInt8 track,CDISRC isrc)
{
    IOReturn result;
    UInt8 *tempBuf;

    /* Get a buffer for the returned data: */
    
    result = allocateTempBuffer(&tempBuf,24);
    if (result != kIOReturnSuccess) {
        return(kIOReturnNoMemory);
    }

    result = readSubChannel(tempBuf,24,IORSCcdb::kISRC,track);
    if (result == kIOReturnSuccess) {
        assert(tempBuf[2] == 0);
        assert(tempBuf[3] == 20);
        assert(tempBuf[4] == 3);

        if ((tempBuf[8] & 0x80)) {	/* return the ISRC */
            bcopy(&tempBuf[9],isrc,kCDISRCMaxLength);
            isrc[kCDISRCMaxLength] = '\0';
        } else {
            result = kIOReturnNotFound;
        }
    }
    
    deleteTempBuffer(tempBuf,24);

    return(result);
}

IOReturn
IOSCSICDDrive::readMCN(CDMCN mcn)
{
    IOReturn result;
    UInt8 *tempBuf;

    /* Get a buffer for the returned data: */
    
    result = allocateTempBuffer(&tempBuf,24);
    if (result != kIOReturnSuccess) {
        return(kIOReturnNoMemory);
    }

    result = readSubChannel(tempBuf,24,IORSCcdb::kMCN,0);
    if (result == kIOReturnSuccess) {
        assert(tempBuf[2] == 0);
        assert(tempBuf[3] == 20);
        assert(tempBuf[4] == 2);

        if ((tempBuf[8] & 0x80)) {	/* return the MCN */
            bcopy(&tempBuf[9],mcn,kCDMCNMaxLength);
            mcn[kCDMCNMaxLength] = '\0';
        } else {
            result = kIOReturnNotFound;
        }
    }
    
    deleteTempBuffer(tempBuf,24);

    return(result);
}


IOReturn
IOSCSICDDrive::readSubChannel(UInt8 *buffer,UInt32 length,UInt8 dataFormat,UInt8 trackNumber)
{
    struct context *cx;
    struct IORSCcdb *c;
    IOSCSICommand *req;
    SCSICDBInfo scsiCDB;
    IOReturn result;

    cx = allocateContext();
    if (cx == NULL) {
        return(kIOReturnNoMemory);
    }
    
    req = cx->scsireq;

    bzero( &scsiCDB, sizeof(scsiCDB) );

    bzero(buffer,length);
    
    c = (struct IORSCcdb *)(scsiCDB.cdb);

    c->opcode = kIOSCSICommandReadSubChannel;
    c->lunbits = 0;
    c->lunbits |= IORSCcdb::kMSF;
    c->subq = IORSCcdb::kSubq;
    c->dataformat = dataFormat;
    c->track = trackNumber;			/* any valid track will do */
    c->reserved1 = 0;
    c->reserved2 = 0;
    c->len_hi = length >> 8;
    c->len_lo = length & 0xff;
    c->ctlbyte = 0;
    
    scsiCDB.cdbLength = 10;
    req->setCDB( &scsiCDB );
    req->setPointers(cx->senseDataDesc, 255, false, true);    

    cx->memory = IOMemoryDescriptor::withAddress((void *)buffer,
                                                 length,
                                                 kIODirectionIn);
    req->setPointers( cx->memory, length, false );

    req->setTimeout( 5000 );
    
    result = simpleSynchIO(cx);

    deleteContext(cx);

    return(result);
}

IOReturn
IOSCSICDDrive::readTOC(IOMemoryDescriptor *buffer)
{
    struct context *cx;
    struct IOReadToccdb *c;
    IOSCSICommand *req;
    SCSICDBInfo scsiCDB;
    IOReturn result;

    cx = allocateContext();
    if (cx == NULL) {
        return(kIOReturnNoMemory);
    }
    
    req = cx->scsireq;

    bzero( &scsiCDB, sizeof(scsiCDB) );

    c = (struct IOReadToccdb *)scsiCDB.cdb;

    c->opcode = kIOSCSICommandReadTOC;
    c->lunbits = IOReadToccdb::kMSF;
    c->reserved1 = 0;
    c->reserved2 = 0;
    c->reserved3 = 0;
    c->reserved4 = 0;
    c->start_trk_session = 0;
    c->len_hi = buffer->getLength() >> 8;
    c->len_lo = buffer->getLength() & 0xff;
    c->ctlbyte = IOReadToccdb::kFullTOC << 6; /* old format field */

    scsiCDB.cdbLength = 10;
    req->setCDB( &scsiCDB );
    req->setPointers(cx->senseDataDesc, 255, false, true);    

    buffer->retain();			/* bump the retain count */
    cx->memory = buffer;

    req->setPointers( cx->memory, cx->memory->getLength(), false );

    req->setTimeout( 5000 );    

    result = simpleSynchIO(cx);

    deleteContext(cx);

#ifdef HOLLYWOOD_BCD_TO_HEX_SUPPORT
    IOByteCount tocMaxSize;
    CDTOC *toc = buffer->getVirtualSegment(0, &tocMaxSize);

    /* Convert BCD-encoded values in TOC to hex values. */
    if (toc && tocMaxSize >= sizeof(UInt32)) {
        UInt32 count = (tocMaxSize - sizeof(UInt32)) / sizeof(CDTOCDescriptor);
        for (UInt32 index = 0; index < count; index++) {
            if (toc->descriptors[index].point <= 0x99) {
                ConvertBCDToHex(&toc->descriptors[index].point);
            }
            if ((toc->descriptors[index].point & 0xf0) == 0xb0) {
                ConvertBCDToHex(&toc->descriptors[index].address.minute);
                ConvertBCDToHex(&toc->descriptors[index].address.second);
                ConvertBCDToHex(&toc->descriptors[index].address.frame);
                ConvertBCDToHex(&toc->descriptors[index].zero);
            }
            if ( toc->descriptors[index].point <= 0x99      ||
                ( toc->descriptors[index].point >= 0xa0 &&
                toc->descriptors[index].point <= 0xc0 )  ) {
                ConvertBCDToHex(&toc->descriptors[index].p.minute);
                if (toc->descriptors[index].point != 0xa0) {
                    ConvertBCDToHex(&toc->descriptors[index].p.second);
                }
                ConvertBCDToHex(&toc->descriptors[index].p.frame);
            }
        }
    }
#endif HOLLYWOOD_BCD_TO_HEX_SUPPORT

    return(result);
}

IOReturn
IOSCSICDDrive::reportMaxWriteTransfer(UInt64 /* blockSize */,UInt64 * /* max */)
{
    return(0);
}

IOReturn
IOSCSICDDrive::reportMediaState(bool *mediaPresent,bool *changed)
{
    IOReturn result;

    result = super::reportMediaState(mediaPresent,changed);

    if (result != kIOReturnSuccess) {
        IOLog("%s[IOSCSICDDrive]::reportMediaState; result=%s, changed = %s, present = %s\n",
                getName(),stringFromReturn(result),*changed ? "Y" : "N", *mediaPresent ? "Y" : "N");
    }
        
    if ((result == kIOReturnSuccess) && *changed) {		/* the media state changed */
        if (*mediaPresent) {				/* new media inserted */
            mediaArrived();
        } else {					/* media went away */
            mediaGone();
        }
    }

    /* We don't return the result of our internal operations. But since they
     * indicate a problem, we probably should report some kind of problem,
     * or maybe just ignore the media change.
     */

    return(result);
}

IOReturn
IOSCSICDDrive::reportWriteProtection(bool *isWriteProtected)
{
    *isWriteProtected = true;
    return(kIOReturnSuccess);
}

IOReturn
IOSCSICDDrive::setAudioVolume(UInt8 leftVolume,UInt8 rightVolume)
{
    struct context *cx;
    SCSICDBInfo scsiCmd;
    IOReturn result;
    UInt8 audio_control[28];

    cx = allocateContext();
    if (cx == NULL) {
        return(kIOReturnNoMemory);
    }

    cx->memory = IOMemoryDescriptor::withAddress(audio_control,
                                                 sizeof(audio_control),
                                                 kIODirectionIn);
    if (cx->memory == NULL) {
        deleteContext(cx);
        return(kIOReturnNoMemory);
    }

    /* Get current values. */

    bzero(&scsiCmd, sizeof(scsiCmd));

    scsiCmd.cdbLength = 6;
    scsiCmd.cdb[0]    = 0x1a; /* MODE SENSE (6) */
    scsiCmd.cdb[2]    = 0x0e; /* PAGE CODE E */
    scsiCmd.cdb[4]    = sizeof(audio_control);

    cx->scsireq->setCDB(&scsiCmd);
    cx->scsireq->setPointers(cx->memory, sizeof(audio_control), true);
    cx->scsireq->setPointers(cx->senseDataDesc, 255, false, true);    
    cx->scsireq->setTimeout(5000);

    result = simpleSynchIO(cx);

    if (result == kIOReturnSuccess) {
        assert((audio_control[ 0]       ) == 28-1);
        assert((audio_control[ 3]       ) == 0x08);
        assert((audio_control[12] & 0x3f) == 0x0e); 
        assert((audio_control[13]       ) == 0x0e);

        /* Set new values. */

        audio_control[21] = audio_control[25] = leftVolume;
        audio_control[23] = audio_control[27] = rightVolume;

        deleteContext(cx);

        cx = allocateContext();
        if (cx == NULL) {
            return(kIOReturnNoMemory);
        }

        cx->memory = IOMemoryDescriptor::withAddress(audio_control,
                                                     sizeof(audio_control),
                                                     kIODirectionOut);
        if (cx->memory == NULL) {
            deleteContext(cx);
            return(kIOReturnNoMemory);
        }

        bzero(&scsiCmd, sizeof(scsiCmd));

        scsiCmd.cdbLength = 6;
        scsiCmd.cdb[0]    = 0x15; /* MODE SELECT (6) */
        scsiCmd.cdb[4]    = sizeof(audio_control);

        cx->scsireq->setCDB(&scsiCmd);
        cx->scsireq->setPointers(cx->memory, sizeof(audio_control), true);
        cx->scsireq->setPointers(cx->senseDataDesc, 255, false, true);    
        cx->scsireq->setTimeout(5000);

        result = simpleSynchIO(cx);
    }

    deleteContext(cx);

    return(result);
}

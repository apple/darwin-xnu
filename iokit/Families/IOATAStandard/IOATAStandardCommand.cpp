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
 *
 * IOATAStandardCommand.cpp
 *
 */

#include <IOKit/IOSyncer.h>

#include <IOKit/ata/IOATAStandardInterface.h>
#include <libkern/OSAtomic.h>

#undef super
#define super IOATACommand

OSDefineMetaClassAndStructors( IOATAStandardCommand, IOATACommand )
OSDefineMetaClassAndAbstractStructors( IOATACommand, IOCDBCommand )

IOATADevice *IOATAStandardCommand::getDevice(IOATADevice *)
{
    return (IOATADevice *)device;
}

IOATAStandardDevice *IOATAStandardCommand::getDevice(IOATAStandardDevice *)
{
    return device;
}

void *IOATAStandardCommand::getClientData()
{
    return clientData;
}

void *IOATAStandardCommand::getCommandData()
{
    return commandPrivateData;
}

UInt32 IOATAStandardCommand::getCmdType()
{
    return cmdType;
}

IOATAStandardCommand *IOATAStandardCommand::getOriginalCmd()
{
    return origCommand;
}

UInt32 IOATAStandardCommand::getSequenceNumber()
{
    return sequenceNumber;
}

ATAUnit IOATAStandardCommand::getUnit()
{
    return device->unit;
}

void IOATAStandardCommand::setTaskfile( ATATaskfile *srcTaskfile )
{
    taskfile  = *srcTaskfile;
}

void IOATAStandardCommand::getTaskfile( ATATaskfile *dstTaskfile )
{
    *dstTaskfile = taskfile;
}

UInt32 IOATAStandardCommand::getFlags()
{
    return taskfile.flags;
}

ATAProtocol IOATAStandardCommand::getProtocol()
{
    return taskfile.protocol;
}

UInt32 IOATAStandardCommand::getResultMask()
{
    return taskfile.resultmask;
}


void IOATAStandardCommand::setTimeout( UInt32 timeoutMS )
{
    timeout = timeoutMS;
}

UInt32 IOATAStandardCommand::getTimeout()
{
    return timeout;
}


void IOATAStandardCommand::setResults( ATAResults *srcResults )
{
    results   = *srcResults;

    if ( getCmdType() == kATACommandExecute )
    {
        if ( results.bytesTransferred < xferCount )
        {
            if ( results.returnCode == kIOReturnSuccess )
            {
                results.returnCode = kIOReturnUnderrun;
            }
        }
    }
}

IOReturn IOATAStandardCommand::getResults( ATAResults *dstResults )
{
    if ( dstResults != 0 )
    {
        *dstResults = results;
    }

    return results.returnCode;
}

void IOATAStandardCommand::setQueueInfo( UInt32 forQueueType, UInt32 forQueuePosition )
{
    queueType     = forQueueType;
    queuePosition = forQueuePosition;
}

void IOATAStandardCommand::getQueueInfo( UInt32 *forQueueType, UInt32 *forQueuePosition = 0 )
{
    if ( forQueueType != 0 )      *forQueueType     = queueType;
    if ( forQueuePosition != 0 )  *forQueuePosition = queuePosition;
}

void IOATAStandardCommand::setPointers(  IOMemoryDescriptor *clientDesc, UInt32 transferCount, bool isWrite, bool isSense = false  )
{
    if ( isSense == false )
    {
        xferDesc       = clientDesc;
        xferCount      = transferCount;
        xferDirection  = isWrite;
    }
    else
    {
        senseData      = clientDesc;
        senseLength    = transferCount;
    } 
}

void IOATAStandardCommand::getPointers(  IOMemoryDescriptor **clientDesc, UInt32 *transferCount, bool *isWrite, bool isSense = false  )
{
    if ( clientDesc != NULL )
    {
        *clientDesc = (isSense == false) ? xferDesc : senseData;
    }
    
    if ( transferCount != NULL )
    {
        *transferCount = (isSense == false) ? xferCount : senseLength;
    }
 
    if ( isWrite != NULL )
    {
        *isWrite       = (isSense == false) ? xferDirection : false;
    }
}

void IOATAStandardCommand::setCDB( ATACDBInfo *clientATACmd  )	
{
    ataCmd    = *clientATACmd;
}

void IOATAStandardCommand::getCDB( ATACDBInfo *clientATACmd )	
{
    *clientATACmd = ataCmd;
}

void IOATAStandardCommand::setCallback( void *clientTarget, CallbackFn clientATADoneFn, void *clientRefcon )
{
    completionInfo.async.target     = clientTarget;
    completionInfo.async.callback   = clientATADoneFn;
    completionInfo.async.refcon     = clientRefcon;
}

bool IOATAStandardCommand::execute( UInt32 *cmdSequenceNumber )
{
    bool	 	isSync;

    do
    {
        sequenceNumber = OSIncrementAtomic( (SInt32 *)&controller->sequenceNumber );
    }
    while ( sequenceNumber == 0 );

    if ( cmdSequenceNumber != 0 )
    {
        *cmdSequenceNumber = sequenceNumber;
    }

    list = (queue_head_t *)device->deviceGate;

    isSync = (completionInfo.async.callback == 0);

    if ( isSync )
    {
        completionInfo.sync.lock = IOSyncer::create();
    }

    device->submitCommand( kATACommandExecute, this );

    if ( isSync )
    {
        completionInfo.sync.lock->wait();
    }

    return true;

}

void IOATAStandardCommand::abort( UInt32 sequenceNumber )
{
    device->submitCommand( kATACommandAbort, this, sequenceNumber );
}

void IOATAStandardCommand::complete()
{
    if ( device )
    {
        device->completeCommand( this );
    }
    else
    {
        controller->completeCommand( this );
    }
}

/*------------------- Generic CDB Interface -----------------------------------------------*/

void IOATAStandardCommand::getCDB( CDBInfo *cdbInfo )
{
    ATACDBInfo		ataCDBInfo;

    bzero( cdbInfo, sizeof(CDBInfo) );

    getCDB( &ataCDBInfo );
    cdbInfo->cdb       = ataCDBInfo.cdb;
    cdbInfo->cdbLength = ataCDBInfo.cdbLength;
}

void IOATAStandardCommand::setCDB( CDBInfo *cdbInfo )
{
    IOATAStandardDevice		*ataDevice;
    ATATimingProtocol		ataTimingProtocol;
    ATACDBInfo			ataCDBInfo;
    ATATaskfile			ataTaskfile;

    ataDevice = getDevice(kIOATAStandardDevice);

    if ( ataDevice->getDeviceType() != kATADeviceATAPI )
    {
        return;
    }

    bzero( &ataTaskfile, sizeof(ataTaskfile) );

    ataDevice->getTimingSelected( &ataTimingProtocol );

    ataTaskfile.regmask  =   ATARegtoMask(kATARegATAPIDeviceSelect) 
                           | ATARegtoMask(kATARegATAPICommand)
                           | ATARegtoMask(kATARegATAPIByteCountLow)
                           | ATARegtoMask(kATARegATAPIByteCountHigh)
                           | ATARegtoMask(kATARegATAPIFeatures);

    ataTaskfile.ataRegs[kATARegATAPICommand]       = kATACommandATAPIPacket;
    ataTaskfile.ataRegs[kATARegATAPIDeviceSelect]  = kATAModeLBA | (getUnit() << 4);

    if ( ataTimingProtocol & ~kATATimingPIO )
    {
        ataTaskfile.protocol = kATAProtocolATAPIDMA;
        ataTaskfile.ataRegs[kATARegATAPIFeatures] = 0x01;
    }
    else
    {
       ataTaskfile.protocol = kATAProtocolATAPIPIO;
       ataTaskfile.ataRegs[kATARegATAPIByteCountLow]  = 0xfe;
       ataTaskfile.ataRegs[kATARegATAPIByteCountHigh] = 0xff;
    }

    setTaskfile( &ataTaskfile );

    bzero( &ataCDBInfo, sizeof(ATACDBInfo) );

    ataCDBInfo.cdbLength = cdbInfo->cdbLength;
    ataCDBInfo.cdb       = cdbInfo->cdb;
    setCDB( &ataCDBInfo );   

    setQueueInfo(); 
}

IOReturn IOATAStandardCommand::getResults( CDBResults *cdbResults )
{
    ATAResults		ataResults;
    IOReturn		rc;

    rc = getResults( &ataResults );

    if ( cdbResults != 0 )
    {
        bzero( cdbResults, sizeof(CDBResults) );

        cdbResults->returnCode         = ataResults.returnCode;
        cdbResults->bytesTransferred   = ataResults.bytesTransferred;
        cdbResults->requestSenseDone   = ataResults.returnCode;
        cdbResults->requestSenseLength = ataResults.requestSenseLength;
    }

    return rc;
}


IOCDBDevice *IOATAStandardCommand::getDevice( IOCDBDevice * )
{
    return (IOCDBDevice *)device;
}

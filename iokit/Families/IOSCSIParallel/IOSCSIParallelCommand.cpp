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
 * IOSCSIParallelCommand.cpp
 *
 */

#include <IOKit/IOSyncer.h>
#include <IOKit/scsi/IOSCSIParallelInterface.h>
#include <libkern/OSAtomic.h>

#undef super
#define super IOSCSICommand

OSDefineMetaClassAndStructors( IOSCSIParallelCommand, IOSCSICommand )
OSDefineMetaClassAndAbstractStructors( IOSCSICommand, IOCDBCommand )
OSDefineMetaClassAndAbstractStructors( IOCDBCommand, IOCommand )

static struct adapterReturnCodes
{
    SCSIAdapterStatus		adapterStatus;
    IOReturn			ioReturnCode;
} 
adapterReturnCodes[] =
{
   { kSCSIAdapterStatusSuccess,			kIOReturnSuccess 	},
   { kSCSIAdapterStatusProtocolError,		kIOReturnDeviceError 	},
   { kSCSIAdapterStatusSelectionTimeout,	kIOReturnNotResponding 	},
   { kSCSIAdapterStatusMsgReject,		kIOReturnUnsupported	},
   { kSCSIAdapterStatusParityError,		kIOReturnIOError	},
   { kSCSIAdapterStatusOverrun,			kIOReturnOverrun	}
};

#define kNumAdapterReturnCodes		(sizeof(adapterReturnCodes)/sizeof(adapterReturnCodes[0]))

static struct statusReturnCodes
{
    UInt32			scsiStatus;
    IOReturn			ioReturnCode;
} 
statusReturnCodes[] =
{
   { kSCSIStatusGood,				kIOReturnSuccess 	},
   { kSCSIStatusCheckCondition,			kIOReturnIOError 	},
   { kSCSIStatusConditionMet,			kIOReturnSuccess 	},
   { kSCSIStatusBusy,				kIOReturnBusy	 	},
   { kSCSIStatusIntermediate,			kIOReturnSuccess 	},
   { kSCSIStatusIntermediateMet,		kIOReturnSuccess 	},
   { kSCSIStatusReservationConfict,		kIOReturnAborted 	},
   { kSCSIStatusCommandTerminated,		kIOReturnAborted 	},
   { kSCSIStatusQueueFull,			kIOReturnIOError 	}
};

#define kNumStatusReturnCodes		(sizeof(statusReturnCodes)/sizeof(statusReturnCodes[0]))


IOSCSIDevice *IOSCSIParallelCommand::getDevice(IOSCSIDevice *)
{
    return (IOSCSIDevice *)getDevice(kIOSCSIParallelDevice);
}

IOSCSIParallelDevice *IOSCSIParallelCommand::getDevice(IOSCSIParallelDevice *)
{
    return device;
}


void *IOSCSIParallelCommand::getClientData()
{
    return clientData;
}

void *IOSCSIParallelCommand::getCommandData()
{
    return commandPrivateData;
}

UInt32 IOSCSIParallelCommand::getCmdType()
{
    return cmdType;
}

IOSCSIParallelCommand *IOSCSIParallelCommand::getOriginalCmd()
{
    return origCommand;
}

UInt32 IOSCSIParallelCommand::getSequenceNumber()
{
    return sequenceNumber;
}

void IOSCSIParallelCommand::getTargetLun( SCSITargetLun *forTargetLun )
{
    if ( device )
    {
        *forTargetLun = device->targetLun;
    }
    else
    {
        bzero( forTargetLun, sizeof( SCSITargetLun ) );
    }
}



void IOSCSIParallelCommand::setTimeout( UInt32 timeoutMS )
{
    timeout = timeoutMS;
}

UInt32 IOSCSIParallelCommand::getTimeout()
{
    return timeout;
}

void IOSCSIParallelCommand::setResults( SCSIResults *srcResults )
{
    setResults( srcResults, (SCSINegotiationResults *)0 );
}

void IOSCSIParallelCommand::setResults( SCSIResults *srcResults, SCSINegotiationResults *negotiationResult )
{
    SCSICommandType	cmdType;

    if ( srcResults != 0 )
    {
        results   = *srcResults;

        cmdType = (SCSICommandType) getCmdType();

        while ( results.returnCode == kIOReturnSuccess )
        {
            switch ( cmdType )
            {
                case kSCSICommandExecute:
                case kSCSICommandReqSense:
                case kSCSICommandAbort:
                case kSCSICommandAbortAll:
                case kSCSICommandDeviceReset:
                    if ( results.adapterStatus != kSCSIAdapterStatusSuccess )
                    {
                        results.returnCode = adapterStatusToIOReturnCode( results.adapterStatus );
                    }
                    break;

                default: 
                    ;
            }  

            if ( results.returnCode != kIOReturnSuccess ) break;

            switch ( cmdType )
            {
                case kSCSICommandExecute:
                case kSCSICommandReqSense:
                    results.returnCode = scsiStatusToIOReturnCode( results.scsiStatus );

                    if ( results.returnCode != kIOReturnSuccess ) break;

                    if ( results.bytesTransferred < xferCount )
                    {
                        results.returnCode = kIOReturnUnderrun;
                    }
                    break;

                default: 
                    ;
            }

            break;
        }
    }

    if ( negotiationResult != 0 )
    {
        device->target->negotiationResult = *negotiationResult;
    }
}

IOReturn IOSCSIParallelCommand::adapterStatusToIOReturnCode( SCSIAdapterStatus adapterStatus )
{
    UInt32		i;

    for ( i=0; i < kNumAdapterReturnCodes; i++ )
    {
        if ( adapterReturnCodes[i].adapterStatus == adapterStatus )
        {
            return adapterReturnCodes[i].ioReturnCode;
        }
    }
    return kIOReturnError;
}

IOReturn IOSCSIParallelCommand::scsiStatusToIOReturnCode( UInt8 scsiStatus )
{
    UInt32		i;

    for ( i=0; i < kNumStatusReturnCodes; i++ )
    {
        if ( statusReturnCodes[i].scsiStatus == scsiStatus )
        {
            return statusReturnCodes[i].ioReturnCode;
        }
    }
    return kIOReturnError;
}

IOReturn IOSCSIParallelCommand::getResults( SCSIResults *dstResults )
{
    if ( dstResults != 0 )
    {
        *dstResults = results;
    }

    return results.returnCode;
}

void IOSCSIParallelCommand::setQueueInfo( UInt32 forQueueType, UInt32 forQueuePosition )
{
    queueType     = forQueueType;
    queuePosition = forQueuePosition;
}

void IOSCSIParallelCommand::getQueueInfo( UInt32 *forQueueType, UInt32 *forQueuePosition = 0 )
{
    if ( forQueueType != 0 )      *forQueueType     = queueType;
    if ( forQueuePosition != 0 )  *forQueuePosition = queuePosition;
}

void IOSCSIParallelCommand::setPointers(  IOMemoryDescriptor *clientDesc, UInt32 transferCount, bool isWrite, bool isSense = false  )
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

void IOSCSIParallelCommand::getPointers(  IOMemoryDescriptor **clientDesc, UInt32 *transferCount, bool *isWrite, bool isSense = false  )
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

void IOSCSIParallelCommand::setCDB( SCSICDBInfo *clientSCSICmd  )	
{
    scsiCmd    = *clientSCSICmd;
}

void IOSCSIParallelCommand::getCDB( SCSICDBInfo *clientSCSICmd )	
{
    *clientSCSICmd = scsiCmd;
}

void IOSCSIParallelCommand::setCallback( void *clientTarget, CallbackFn clientSCSIDoneFn, void *clientRefcon )
{
    completionInfo.async.target     = clientTarget;
    completionInfo.async.callback   = clientSCSIDoneFn;
    completionInfo.async.refcon     = clientRefcon;
}

bool IOSCSIParallelCommand::execute( UInt32 *cmdSequenceNumber )
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

    device->submitCommand( kSCSICommandExecute, this );

    if ( isSync )
    {
        completionInfo.sync.lock->wait();
    }

    return true;

}

void IOSCSIParallelCommand::abort( UInt32 sequenceNumber )
{
    device->submitCommand( kSCSICommandAbort, this, sequenceNumber );
}

void IOSCSIParallelCommand::complete()
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

void IOSCSIParallelCommand::getCDB( CDBInfo *cdbInfo )
{
    SCSICDBInfo		scsiCDBInfo;

    bzero( cdbInfo, sizeof(CDBInfo) );

    getCDB( &scsiCDBInfo );
    cdbInfo->cdb       = scsiCDBInfo.cdb;
    cdbInfo->cdbLength = scsiCDBInfo.cdbLength;
}

void IOSCSIParallelCommand::setCDB( CDBInfo *cdbInfo )
{
    SCSICDBInfo		scsiCDBInfo;

    bzero( &scsiCDBInfo, sizeof(SCSICDBInfo) );

    scsiCDBInfo.cdbLength = cdbInfo->cdbLength;
    scsiCDBInfo.cdb       = cdbInfo->cdb;
    setCDB( &scsiCDBInfo );    
}

IOReturn IOSCSIParallelCommand::getResults( CDBResults *cdbResults )
{
    SCSIResults		scsiResults;
    IOReturn		rc;

    rc = getResults( &scsiResults );

    if ( cdbResults != 0 )
    {
        bzero( cdbResults, sizeof(CDBResults) );

        cdbResults->returnCode         = scsiResults.returnCode;
        cdbResults->bytesTransferred   = scsiResults.bytesTransferred;
        cdbResults->requestSenseDone   = scsiResults.requestSenseDone;
        cdbResults->requestSenseLength = scsiResults.requestSenseLength;
    }

    return rc;
}


IOCDBDevice *IOSCSIParallelCommand::getDevice( IOCDBDevice * )
{
    return (IOCDBDevice *)device;
}


void IOSCSIParallelCommand::zeroCommand()
{
    cmdType = kSCSICommandNone;
//  controller = <same-as-before>;
//  device = <same-as-before>;
    list = 0;
    bzero(&nextCommand, sizeof(nextCommand));
    bzero(&scsiCmd, sizeof(scsiCmd));
    bzero(&results, sizeof(results));
    timeout = 0;
    timer = 0;
    queueType = 0;
    queuePosition = 0;
    xferDesc = 0;
    xferCount = 0;
    xferDirection = 0;
    senseLength = 0;
    senseData = 0;
    origCommand = 0;
    bzero(&completionInfo, sizeof(completionInfo));
    if (dataArea && dataSize)
        bzero( dataArea, dataSize );
//  commandPrivateData = <same-as-before>;
//  clientData = <same-as-before>;
    sequenceNumber = 0;
}

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
 *	IOSCSIParallelDevice.cpp
 *
 */

#include <IOKit/IOSyncer.h> 
#include <IOKit/scsi/IOSCSIParallelInterface.h>

#include <IOKit/IOKitKeys.h>
#include <IOKit/system.h>

#undef  super
#define super IOSCSIDevice

#ifndef MIN
#define MIN(a,b) ((a <= b) ? a : b)
#endif

OSDefineMetaClassAndAbstractStructors( IOCDBDevice,  IOService )
OSDefineMetaClassAndAbstractStructors( IOSCSIDevice, IOCDBDevice )
OSDefineMetaClassAndStructors( IOSCSIParallelDevice, IOSCSIDevice )

/*
 *
 *
 *
 */ 
bool IOSCSIParallelDevice::init( IOSCSIParallelController *forController, SCSITargetLun forTargetLun )
{
    SCSICDBInfo		scsiCDB;

    controller  = forController;     
    targetLun   = forTargetLun;

    target      = &controller->targets[targetLun.target];

    queue_init( &deviceList );     
    queue_init( &bypassList );       
    queue_init( &activeList );      
    queue_init( &abortList  );  
    queue_init( &cancelList ); 

    clientSem = IORWLockAlloc();
    if ( clientSem == 0 )
    {
        return false;
    }

    if ( super::init() == false )
    {
        return false;
    }

    if ( controller->controllerInfo.lunPrivateDataSize != 0 )
    {
        devicePrivateData = IOMallocContiguous( controller->controllerInfo.lunPrivateDataSize, 16, 0 );
        if ( devicePrivateData == 0 )
        {
            return false;
        }
    }

    bzero( &scsiCDB, sizeof(scsiCDB) );
    
    abortCmd = allocCommand(kIOSCSIParallelDevice, 0);
    if ( abortCmd == 0 )
    {
        return false;
    }
    abortCmd->setTimeout( kSCSIAbortTimeoutmS );    
    
    cancelCmd = allocCommand(kIOSCSIParallelDevice, 0);
    if ( cancelCmd == 0 )
    {
        return false;
    }
    cancelCmd->setTimeout( 0 );    
    cancelCmd->cmdType = kSCSICommandCancel;

    reqSenseCmd = allocCommand(kIOSCSIParallelDevice, 0);
    if ( reqSenseCmd == 0 )
    {
        return false;
    }    
    scsiCDB.cdbLength = 6;
    scsiCDB.cdb[0]    = kSCSICmdRequestSense;
    scsiCDB.cdb[1]    = targetLun.lun << 4;
    scsiCDB.cdbTag     = (UInt32) -1;

    reqSenseCmd->setTimeout( kSCSIReqSenseTimeoutmS );    
    reqSenseCmd->cmdType = kSCSICommandReqSense;
    reqSenseCmd->setCDB( &scsiCDB );

    if ( controller->controllerInfo.tagAllocationMethod == kTagAllocationPerLun )
    {
        tagArray = (UInt32 *)IOMalloc( controller->tagArraySize );
        bzero( tagArray, controller->tagArraySize );
    }

    deviceGate = IOCommandGate::commandGate( this, (IOCommandGate::Action) &IOSCSIParallelDevice::receiveCommand );
    if ( deviceGate == 0 )
    {
        return false;
    }    
    
    if ( controller->workLoop->addEventSource( deviceGate ) != kIOReturnSuccess )
    {
        return false;
    }

    commandLimitSave = commandLimit = controller->controllerInfo.maxCommandsPerLun;

    idleNotifyActive = false;

    normalQHeld      = false;
    bypassQHeld	     = false;
     
    return true;
}

/*
 *
 *
 *
 */
IOReturn IOSCSIParallelDevice::probeTargetLun()
{
    SCSICDBInfo				cdb;
    SCSIResults				result;
    IOReturn				rc;    
    IOMemoryDescriptor 	 		*desc = 0;
    SCSIInquiry				*inqData = 0;
    UInt32				size = 0;
    OSDictionary			*propTable;

    probeCmd = allocCommand(kIOSCSIParallelDevice, 0);
     
    if ( probeCmd == 0 )
    {
        rc = kIOReturnNoMemory;
        goto probeError;
    }
    
    size = sizeof(SCSIInquiry);
     
    if ( !(inqData = (SCSIInquiry *)IOMalloc(size)) )
    {
        rc = kIOReturnNoMemory;
        goto probeError;
    }

    desc = IOMemoryDescriptor::withAddress( (void *)inqData, size, kIODirectionIn );
    if ( desc == 0 )
    {
        rc = kIOReturnNoMemory;    
        goto probeError;
    }

    if ( open( this ) == false )
    {
        rc = kIOReturnError;
        goto probeError;
    }
     
    bzero( (void *)&cdb, sizeof(cdb) );
    
    cdb.cdbLength = 6;
    cdb.cdb[0] = kSCSICmdInquiry;
    cdb.cdb[4] = size;
    probeCmd->setCDB( &cdb );

    probeCmd->setPointers( desc, size, false );

    probeCmd->setTimeout( kSCSIProbeTimeoutmS );
    probeCmd->setCallback();
    
    probeCmd->execute();
    
    rc = probeCmd->getResults( &result );

    switch ( rc )
    {
        case kIOReturnSuccess:
            break;

        case kIOReturnUnderrun:
            rc = kIOReturnSuccess;
            break;
 
        default:
            goto probeError;
    }

    if ( result.bytesTransferred <= (UInt32)(&inqData->flags - &inqData->devType) )
    {
        rc = kIOReturnDeviceError;
        goto probeError;
    }
 
    switch ( inqData->devType &  kSCSIDevTypeQualifierMask )
    {
        case kSCSIDevTypeQualifierConnected:
        case kSCSIDevTypeQualifierNotConnected:
            break; 
        case kSCSIDevTypeQualifierReserved:
        case kSCSIDevTypeQualifierMissing:  
            rc = kIOReturnNotAttached;
            break;
        default:
            break;
    }

    if ( rc != kIOReturnSuccess )
    {
        goto probeError;
    } 
 
    inquiryData     = inqData;
    inquiryDataSize = result.bytesTransferred;

    propTable = createProperties();
    if ( !propTable ) goto probeError;

    setPropertyTable( propTable );

    propTable->release();

probeError: ;
    
    if ( desc )
    {    
        desc->release();
    }
    
    if ( inqData )
    {
        if ( rc != kIOReturnSuccess )
        {
            IOFree( inqData, size );
        }
    }    
    
    return rc;
}

/*
 *
 *
 *
 */
void IOSCSIParallelDevice::setupTarget()
{   
    SCSITargetParms			targetParms;
    UInt32				transferWidth;

    if ( targetLun.lun != 0 )
    {
        close( this );
        return;
    }

    getTargetParms( &targetParms );

    if ( ((inquiryData->flags & kSCSIDevCapCmdQue) != 0) && (checkCmdQueEnabled() == true)  )
    {
        targetParms.enableTagQueuing = true;
    }

    if ( inquiryData->flags & kSCSIDevCapSync )
    {
        targetParms.transferPeriodpS = controller->controllerInfo.minTransferPeriodpS;
        targetParms.transferOffset   = controller->controllerInfo.maxTransferOffset;
    }

    if ( inquiryData->flags & kSCSIDevCapWBus32 )
    {
        transferWidth = 4;
    }
    else if ( inquiryData->flags & kSCSIDevCapWBus16 )
    {
        transferWidth = 2;
    }
    else
    {
        transferWidth = 1;
    }

    targetParms.transferWidth = MIN( transferWidth, controller->controllerInfo.maxTransferWidth );

    if ( ((inquiryData->version & 0x07) >= kSCSIInqVersionSCSI3) 
            && (inquiryDataSize > (UInt32)(&inquiryData->scsi3Options - &inquiryData->devType)) )
    {
        if ( inquiryData->scsi3Options & kSCSI3InqOptionClockDT )
        {
            targetParms.transferOptions |= kSCSITransferOptionClockDT;

	    /* If it's a SCSI-3 target that handles DT clocking,
	     * assume the HBA can try using the PPR message.
	     */
	    targetParms.transferOptions |= kSCSITransferOptionPPR;

            if ( inquiryData->scsi3Options & kSCSI3InqOptionIUS )
            {
                targetParms.transferOptions |= kSCSITransferOptionIUS;

                if ( inquiryData->scsi3Options & kSCSI3InqOptionQAS )
                {
                    targetParms.transferOptions |= kSCSITransferOptionQAS;
                } 
            }
        }
    }

    setTargetParms( &targetParms );   

    close( this );
}

/*
 *
 *
 *
 */
bool IOSCSIParallelDevice::checkCmdQueEnabled()
{
    SCSICDBInfo			scsiCDB;
    SCSIResults			scsiResult;
    IOMemoryDescriptor		*desc;
    UInt32			size;
    UInt8			controlModePage[32];
    IOReturn			cmdRc;
    bool			rc = false;

    bzero( (void *)&scsiCDB, sizeof(scsiCDB) );
    
    size = sizeof(controlModePage);

    scsiCDB.cdbLength = 6;
    scsiCDB.cdb[0] = kSCSICmdModeSense6;
    scsiCDB.cdb[1] = 0x08;
    scsiCDB.cdb[2] = 0x0a;	// Control Mode Page
    scsiCDB.cdb[4] = size;

    probeCmd->setCDB( &scsiCDB );

    desc = IOMemoryDescriptor::withAddress( (void *)controlModePage, size, kIODirectionIn );
    if ( desc == 0 )
    {
        return rc;
    }

    probeCmd->setPointers( desc, size, false );

    probeCmd->setTimeout( kSCSIProbeTimeoutmS );
    probeCmd->setCallback();
    
    probeCmd->execute();
    
    cmdRc = probeCmd->getResults( &scsiResult );

    if ( (cmdRc == kIOReturnUnderrun) && (scsiResult.bytesTransferred > 7) )
    {
        cmdRc = kIOReturnSuccess;
    }

    /* Check DQue bit on ControlMode Page (0x0A) */
    if ( (cmdRc == kIOReturnSuccess) && ((controlModePage[7] & 0x01) == 0) )
    {
        rc = true;
    }
    
    desc->release();

    return rc;
}

/*
 *
 *
 *
 */
void IOSCSIParallelDevice::getInquiryData( void *clientBuf, UInt32 clientBufSize, UInt32 *clientDataSize )
{
    UInt32		len;

    bzero( clientBuf, clientBufSize );

    len = MIN( clientBufSize, inquiryDataSize );
   
    bcopy( inquiryData, clientBuf, len );

    *clientDataSize = len;
}

/*
 *
 *
 *
 */
void IOSCSIParallelDevice::abort()
{
    submitCommand( kSCSICommandAbortAll, 0 );
}
 
/*
 *
 *
 *
 */
void IOSCSIParallelDevice::reset()
{
    submitCommand( kSCSICommandDeviceReset, 0 );
}

/*
 *
 *
 *
 */
void IOSCSIParallelDevice::holdQueue( UInt32 queueType )
{
    if ( getWorkLoop()->inGate() == false )
    {
        IOPanic( "IOSCSIParallelDevice::holdQueue() - must be called from workloop!!\n\r");
    }

    if ( queueType == kQTypeBypassQ )
    {
        bypassQHeld = true;
    }
    else if ( queueType == kQTypeNormalQ )
    {
        normalQHeld = true;   
    }
}

/*
 *
 *
 *
 */
void IOSCSIParallelDevice::releaseQueue( UInt32 queueType )
{
    if ( getWorkLoop()->inGate() == false )
    {
        IOPanic( "IOSCSIParallelDevice::releaseQueue() - must be called from workloop!!\n\r");
    }

   if ( queueType == kQTypeBypassQ )
    {
        bypassQHeld = false;
    }
    else if ( queueType == kQTypeNormalQ )
    {
        normalQHeld = false;   
    }

    dispatchRequest();
}

/*
 *
 *
 *
 */
void IOSCSIParallelDevice::notifyIdle(  void *target = 0, CallbackFn callback = 0, void *refcon = 0  )
{
    if ( getWorkLoop()->inGate() == false )
    {
        IOPanic( "IOSCSIParallelDevice:::notifyIdle() - must be called from workloop!!\n\r");
    }

    if ( callback == 0 )
    {
        idleNotifyActive = false;
        return;
    }

    if ( idleNotifyActive == true )
    {
        IOPanic( "IOSCSIParallelDevice:::notifyIdle() - only one idle notify may be active\n\r");
    }

    idleNotifyActive   = true;
    idleNotifyTarget   = target;
    idleNotifyCallback = callback;
    idleNotifyRefcon   = refcon;

    checkIdleNotify();    
}

   
/*
 *
 *
 *
 */
void IOSCSIParallelDevice::submitCommand( UInt32 cmdType, IOSCSIParallelCommand *scsiCmd, UInt32 cmdSequenceNumber )
{
    deviceGate->runCommand( (void *)cmdType, (void *)scsiCmd, (void *) cmdSequenceNumber, (void *) 0 );
}

/*
 *
 *
 *
 */
void IOSCSIParallelDevice::receiveCommand( UInt32 cmdType, IOSCSIParallelCommand *scsiCmd, UInt32 cmdSequenceNumber, void *p3 )
{
    queue_head_t		*queue;

    switch ( cmdType )
    {
        case kSCSICommandExecute:
            scsiCmd->cmdType = (SCSICommandType) cmdType;

            scsiCmd->scsiCmd.cdbFlags &= (kCDBFNoDisconnect);

            queue = (scsiCmd->queueType == kQTypeBypassQ) ? &bypassList : &deviceList;

            if ( scsiCmd->queuePosition == kQPositionHead ) 
            {
                stackCommand( queue, scsiCmd );
            }
            else
            { 
                addCommand( queue, scsiCmd );
            }

            dispatchRequest();
            break;
     
        case kSCSICommandAbortAll:
            abortAllCommands( kSCSICommandAbortAll );    
            break;

        case kSCSICommandAbort:
            abortCommand( scsiCmd, cmdSequenceNumber );
            break;

        case kSCSICommandDeviceReset:
            abortAllCommands( kSCSICommandDeviceReset );            
            break;

        default:
            /* ??? */
            break;
    }    
}

/*
 *
 *
 *
 */
void IOSCSIParallelDevice::abortCommand( IOSCSIParallelCommand *scsiCmd, UInt32 sequenceNumber )
{
    if ( scsiCmd->list == (queue_head_t *)deviceGate )
    {
        if ( scsiCmd->sequenceNumber != sequenceNumber )
        {
            return;
        }    
        scsiCmd->results.returnCode = kIOReturnAborted;
    }
    else if ( scsiCmd->list == &deviceList )
    {
        if ( scsiCmd->sequenceNumber != sequenceNumber )
        {
            return;
        }    

        deleteCommand( &deviceList, scsiCmd );
        scsiCmd->results.returnCode = kIOReturnAborted;
        finishCommand( scsiCmd );
    }
    else if ( scsiCmd->list == &activeList )
    {
        if ( scsiCmd->sequenceNumber != sequenceNumber )
        {
            return;
        }    

        moveCommand( &activeList, &abortList, scsiCmd );

        dispatchRequest();     
    }
}


/*
 *
 *
 *
 */
void IOSCSIParallelDevice::abortAllCommands( SCSICommandType cmdType )
{
    IOSCSIParallelDevice		*abortDev;

    abortCmdPending = cmdType;

    if ( abortCmdPending == kSCSICommandAbortAll )
    {
        if ( client != 0 )
        {
            client->message( kSCSIClientMsgDeviceAbort, this );
        }
    }
    else if ( abortCmdPending == kSCSICommandDeviceReset )
    {
        queue_iterate( &target->deviceList, abortDev, IOSCSIParallelDevice *, nextDevice )
        {   
            if ( abortDev->client != 0 )
            {
                abortDev->client->message( kSCSIClientMsgDeviceReset, abortDev );
            }
        }
    }

    dispatchRequest();
}

/*
 *
 *
 *
 */
void IOSCSIParallelDevice::resetOccurred( SCSIClientMessage clientMsg )
{
    if ( client != 0 && clientMsg != kSCSIClientMsgNone )
    {
        client->message( clientMsg, this );
    }
    
    moveAllCommands( &activeList, &cancelList, kIOReturnAborted );
    moveAllCommands( &abortList,  &cancelList, kIOReturnAborted );
    
    abortState        = kStateIdle;
    reqSenseState     = kStateIdle;
    commandLimit      = commandLimitSave;
    negotiateState    = kStateIdle;

    dispatchRequest();
}

void IOSCSIParallelDevice::resetComplete()
{
    if ( client != 0 )
    {
        client->message( kSCSIClientMsgBusReset | kSCSIClientMsgDone, this );
    }
}


/*
 *
 *
 *
 */
bool IOSCSIParallelDevice::checkAbortQueue()
{
    IOSCSIParallelCommand		*origCmd;

    if ( abortState == kStateActive )
    {
        return true;
    }
        
    if ( abortCmdPending != kSCSICommandNone )
    {
        abortCmd->origCommand = 0;

        abortCmd->scsiCmd.cdbTagMsg   = 0;
        abortCmd->scsiCmd.cdbTag      = (UInt32) -1;
  
       
        abortCmd->cmdType             = abortCmdPending;        
        abortCmd->scsiCmd.cdbAbortMsg = (abortCmdPending == kSCSICommandAbortAll) 
                                                      ? kSCSIMsgAbort : kSCSIMsgBusDeviceReset;

        if ( disableDisconnect == true )
        {
            abortCmd->scsiCmd.cdbFlags |= kCDBFlagsNoDisconnect;
        }
        else
        {
            abortCmd->scsiCmd.cdbFlags &= ~kCDBFlagsNoDisconnect;
        }

    
        abortCmd->timer = ( abortCmd->timeout != 0 ) ?
                                          abortCmd->timeout / kSCSITimerIntervalmS + 1 : 0; 

        bzero( &abortCmd->results, sizeof(SCSIResults) );

        abortCmdPending = kSCSICommandNone;
        abortState      = kStateActive;

        addCommand( &activeList, abortCmd ); 
        controller->executeCommand( abortCmd );
    }             
    else if ( queue_empty( &abortList ) == false )
    {   
        origCmd = (IOSCSIParallelCommand *)queue_first( &abortList );
        abortCmd->origCommand = origCmd;
        
        abortCmd->cmdType = kSCSICommandAbort;
        abortCmd->scsiCmd.cdbTagMsg = origCmd->scsiCmd.cdbTagMsg;
        abortCmd->scsiCmd.cdbTag    = origCmd->scsiCmd.cdbTag;
        abortCmd->scsiCmd.cdbAbortMsg = (abortCmd->scsiCmd.cdbTagMsg != 0) 
                                                     ? kSCSIMsgAbortTag : kSCSIMsgAbort;

        abortCmd->timer = ( abortCmd->timeout != 0 ) ?
                                          abortCmd->timeout / kSCSITimerIntervalmS + 1 : 0; 

        bzero( &abortCmd->results, sizeof(SCSIResults) );          

        abortState = kStateActive;

        addCommand( &activeList, abortCmd ); 
        controller->executeCommand( abortCmd );
    }   
    else
    {
        return false;
    }     
    
    return true;
}

/*
 *
 *
 *
 */
void IOSCSIParallelDevice::checkCancelQueue()
{
    if ( cancelState != kStateIdle )
    {
        return;
    }
        
    if ( queue_empty( &cancelList ) == true )
    {
         return;
    }

    if ( controller->controllerInfo.disableCancelCommands == true )
    {
        return;
    }

    cancelCmd->origCommand = (IOSCSIParallelCommand *)queue_first( &cancelList );
    bzero( &cancelCmd->results, sizeof(SCSIResults) );

    cancelState = kStateActive;
    controller->cancelCommand( cancelCmd );
}

/*
 *
 *
 *
 */
bool IOSCSIParallelDevice::checkReqSense()
{
    IOMemoryDescriptor		*senseData;
    UInt32			senseLength;
    SCSITargetParms		*tpCur;
    
    if ( target->reqSenseState == kStateActive )
    {
        return true;
    }
                 
    if ( reqSenseState == kStateIssue )
    {
        reqSenseCmd->origCommand = reqSenseOrigCmd;
        bzero( &reqSenseCmd->results, sizeof(SCSIResults) );

        reqSenseOrigCmd->getPointers( &senseData, &senseLength, 0, true );
        reqSenseCmd->setPointers( senseData, senseLength, false );

        reqSenseCmd->scsiCmd.cdbFlags = 0;

        if ( disableDisconnect == true )
        {
            reqSenseCmd->scsiCmd.cdbFlags |= kCDBFlagsNoDisconnect;
        }
        else
        {
            reqSenseCmd->scsiCmd.cdbFlags &= ~kCDBFlagsNoDisconnect;
        }

        tpCur = &target->targetParmsCurrent;

        if ( tpCur->transferWidth != 1 )
        {
            reqSenseCmd->scsiCmd.cdbFlags |= kCDBFlagsNegotiateWDTR;
	    if (tpCur->transferOptions & kSCSITransferOptionPPR) {
		reqSenseCmd->scsiCmd.cdbFlags |= kCDBFlagsNegotiatePPR;
	    }
        }

        if ( tpCur->transferOffset != 0  )
        {
            reqSenseCmd->scsiCmd.cdbFlags |= kCDBFlagsNegotiateSDTR;
	    if (tpCur->transferOptions & kSCSITransferOptionPPR) {
		reqSenseCmd->scsiCmd.cdbFlags |= kCDBFlagsNegotiatePPR;
	    }

        }

        reqSenseCmd->timer = ( reqSenseCmd->timeout != 0 ) ?
                                          reqSenseCmd->timeout / kSCSITimerIntervalmS + 1 : 0; 

        reqSenseCmd->scsiCmd.cdb[3] = (senseLength >> 8) & 0xff;
        reqSenseCmd->scsiCmd.cdb[4] =  senseLength       & 0xff;
        
        reqSenseState = kStatePending;
    }
    
    if ( reqSenseState == kStatePending )
    {        
        target->reqSenseState = reqSenseState = kStateActive;

        addCommand( &activeList, reqSenseCmd ); 

        commandCount++;
        controller->commandCount++;

        controller->executeCommand( reqSenseCmd );
    }  

    return (target->reqSenseCount > 0);  
}


/*
 *
 *
 *
 */
bool IOSCSIParallelDevice::checkDeviceQueue( UInt32 *dispatchAction ) 
{
    IOSCSIParallelCommand	*scsiCmd = 0;
    queue_head_t		*queue;
    UInt32			i;
    bool			rc = true;
    bool			queueHeld;

    do
    {
        if ( controller->commandCount >= controller->commandLimit )
        {
            *dispatchAction = kDispatchStop;
            break;
        }

        if ( target->commandCount >= target->commandLimit )
        {
            *dispatchAction = kDispatchNextTarget;
            break;
        }

        *dispatchAction = kDispatchNextLun;

        if ( commandCount >= commandLimit )
        {
            break;
        }

        for ( i=0; i < 2; i++ )
        {
            queueHeld = (i == 0) ? bypassQHeld : normalQHeld;
            queue     = (i == 0) ? &bypassList : &deviceList;
        
            if ( queueHeld == true )
            {
                continue;
            }

            scsiCmd = checkCommand( queue );
            if ( scsiCmd != 0 )
            {
                *dispatchAction = kDispatchNextCommand;
                break;
            }
        }

        if ( i == 2 )
        { 
            rc = false;
            break;
        }

        if ( disableDisconnect == true || (scsiCmd->scsiCmd.cdbFlags & kCDBFNoDisconnect) )
        {
            scsiCmd->scsiCmd.cdbFlags |= kCDBFlagsNoDisconnect;

            if ( controller->commandCount != 0 )
            {
                *dispatchAction = kDispatchNextLun;
                break;
            }
          
            controller->noDisconnectCmd  = scsiCmd;
            controller->commandLimitSave = controller->commandLimit;
            controller->commandLimit     = 1;
        }        

        else if ( checkTag( scsiCmd ) == false )
        {
            switch ( controller->controllerInfo.tagAllocationMethod )
            {
                case kTagAllocationPerTarget:
                    *dispatchAction = kDispatchNextTarget;
                    break;    
                case kTagAllocationPerController:
                    *dispatchAction = kDispatchStop;
                    break;
                case kTagAllocationPerLun:
                    ;
                default:
                    *dispatchAction = kDispatchNextLun;
            }
            break;
        }
             
        getCommand( queue );

        checkNegotiate( scsiCmd );         
   
        scsiCmd->timer = ( scsiCmd->timeout != 0 ) ? scsiCmd->timeout / kSCSITimerIntervalmS + 1 : 0; 

        commandCount++;
        target->commandCount++;
        controller->commandCount++;        

        addCommand( &activeList, scsiCmd );

        controller->executeCommand( scsiCmd );

    } while ( 0 );

    return rc;
}   

/*
 *
 *
 *
 */
void IOSCSIParallelDevice::rescheduleCommand( IOSCSIParallelCommand *scsiCmd )
{
    if ( scsiCmd->list != &activeList )
    {
        IOLog( "IOSCSIParallelController::rescheduleCommand() - Command not active. Cmd = %08x\n\r", (int)scsiCmd );
        return;
    }

    deleteCommand( &activeList, scsiCmd );
 
    switch ( scsiCmd->cmdType )
    {
        case kSCSICommandExecute:
            if ( scsiCmd->scsiCmd.cdbTagMsg != 0 )
            {
                freeTag( scsiCmd->scsiCmd.cdbTag );
                scsiCmd->scsiCmd.cdbTag = (UInt32) -1;
            }

            stackCommand( &deviceList, scsiCmd );

            if ( scsiCmd->scsiCmd.cdbFlags & kCDBFlagsNoDisconnect )
            {
                controller->commandLimit    = controller->commandLimitSave;
                controller->noDisconnectCmd = 0;
            }

            controller->commandCount--;
            target->commandCount--;
            commandCount--;
            break;

        case kSCSICommandReqSense:
            reqSenseState         = kStatePending;
            target->reqSenseState = kStateIdle;
            commandCount--;
            controller->commandCount--;
            break;

        case kSCSICommandAbortAll:
        case kSCSICommandDeviceReset:
            abortCmdPending = scsiCmd->cmdType;

        case kSCSICommandAbort:
            abortState = kStateIdle;
            break;

        default:
            ;
    } 

    dispatchRequest();

}    
 
/*
 *
 *
 *
 */
bool IOSCSIParallelDevice::setTargetParms( SCSITargetParms *targetParms )
{
    IOSCSIParallelCommand	*scsiCmd;
    SCSICDBInfo		scsiCDB;
    bool		fTagEnable;
    bool		rc = true;

    IOMemoryDescriptor	*senseDesc;
    UInt8		senseBuffer[14];


    if ( getWorkLoop()->inGate() == true )
    {
        IOPanic( "IOSCSIParallelDevice:::setTargetParms() - must not be called from workloop!!\n\r");
    }

    IOWriteLock( target->clientSem );
    IOWriteLock( target->targetSem );

    while ( target->negotiateState == kStateActive )
    {
        IOSleep( 100 );
    }    

    target->targetParmsNew   = *targetParms;

    if ( targetParms->transferPeriodpS < controller->controllerInfo.minTransferPeriodpS )
    {
        target->targetParmsNew.transferPeriodpS = controller->controllerInfo.minTransferPeriodpS;
    }

    if ( target->targetParmsNew.transferPeriodpS == 0 
           || target->targetParmsNew.transferOffset == 0 
                || controller->controllerInfo.minTransferPeriodpS == 0 )
    {
        target->targetParmsNew.transferPeriodpS = 0;
        target->targetParmsNew.transferOffset   = 0;
    }

    target->commandLimit     = 1;

    fTagEnable =  (targetParms->enableTagQueuing == true)
                     && (controller->controllerInfo.tagAllocationMethod != kTagAllocationNone) 
                           && (controller->controllerInfo.maxTags != 0);
 
    regObjCmdQueue->setValue( (UInt32)fTagEnable ); 

    if ( fTagEnable == true )
    {
        target->commandLimitSave = controller->controllerInfo.maxCommandsPerTarget;
    }
    else
    {
        target->commandLimitSave                = 1;
        target->targetParmsNew.enableTagQueuing = false;
    }

    scsiCmd = allocCommand(kIOSCSIParallelDevice, 0);

    bzero( &scsiCDB, sizeof( SCSICDBInfo ) );
    
    scsiCDB.cdbLength = 6;
    scsiCDB.cdb[0]    = kSCSICmdTestUnitReady;
    scsiCDB.cdb[1]    = targetLun.lun << 4;
    scsiCmd->setCDB( &scsiCDB );
    
    senseDesc = IOMemoryDescriptor::withAddress(senseBuffer, sizeof(senseBuffer), kIODirectionIn);
    if ( senseDesc == 0 ) return false;
    scsiCmd->setPointers( senseDesc, sizeof(senseBuffer), false, true );

    target->negotiateState = kStateIssue;

    scsiCmd->execute();

    IOWriteLock( target->targetSem );
    IORWUnlock( target->targetSem );

    scsiCmd->release();
    senseDesc->release();

    rc =  (target->negotiationResult.returnCode == kIOReturnSuccess);

    IORWUnlock( target->clientSem );

    return rc;
}
 
/*
 *
 *
 *
 */
void IOSCSIParallelDevice::getTargetParms( SCSITargetParms *targetParms )
{
    *targetParms = target->targetParmsCurrent;
}    

/*
 *
 *
 *
 */
bool IOSCSIParallelDevice::setLunParms( SCSILunParms *lunParms )
{
    IOSCSIParallelCommand	*scsiCmd;
    SCSICDBInfo		scsiCDB;

    IOMemoryDescriptor	*senseDesc;
    UInt8		senseBuffer[14];

    if ( getWorkLoop()->inGate() == true )
    {
        IOPanic( "IOSCSIParallelDevice:::setLunParms() - must not be called from workloop!!\n\r");
    }

    IOWriteLock( clientSem );

    lunParmsNew      = *lunParms;
    commandLimitSave = commandLimit;
    commandLimit     = 1;

    scsiCmd = allocCommand(kIOSCSIParallelDevice, 0);
    
    bzero( &scsiCDB, sizeof( SCSICDBInfo ) );

    scsiCDB.cdbLength = 6;
    scsiCDB.cdb[0]    = kSCSICmdTestUnitReady;
    scsiCDB.cdb[1]    = targetLun.lun << 4;
    scsiCmd->setCDB( &scsiCDB );

    senseDesc = IOMemoryDescriptor::withAddress(senseBuffer, sizeof(senseBuffer), kIODirectionIn);
    if ( senseDesc == 0 ) return false;
    scsiCmd->setPointers( senseDesc, sizeof(senseBuffer), false, true );

    negotiateState = kStateIssue;

    scsiCmd->execute();

    scsiCmd->release();
    senseDesc->release();

    while ( negotiateState != kStateIdle )
    {
        IOSleep( 100 );
    }

    IORWUnlock( clientSem );

    return true;
}
 
/*
 *
 *
 *
 */
void IOSCSIParallelDevice::getLunParms( SCSILunParms *lunParms )
{
    lunParms->disableDisconnect = disableDisconnect;
}    

/*
 *
 *
 *
 */
void IOSCSIParallelDevice::checkNegotiate( IOSCSIParallelCommand *scsiCmd )
{
    SCSITargetParms	*tpCur, *tpNew;

    if ( target->negotiateState == kStateIssue )
    {
        if ( target->commandCount == 0 )
        {
            target->negotiateState = kStateActive;

            tpNew = &target->targetParmsNew;
            tpCur = &target->targetParmsCurrent;

            target->negotiationResult.returnCode = kIOReturnError;

            if ((tpCur->transferPeriodpS != tpNew->transferPeriodpS)	||
		(tpCur->transferOffset != tpNew->transferOffset)	||
		((tpCur->transferOptions ^ tpNew->transferOptions) & kSCSITransferOptionsSCSI3) )  
            {
                scsiCmd->scsiCmd.cdbFlags |= kCDBFlagsNegotiateSDTR;

		if (tpNew->transferOptions & kSCSITransferOptionPPR) {
		    scsiCmd->scsiCmd.cdbFlags |= kCDBFlagsNegotiatePPR;
		}
            }

            if ( tpCur->transferWidth != tpNew->transferWidth )
            {
                scsiCmd->scsiCmd.cdbFlags |= kCDBFlagsNegotiateWDTR;
            }

            if ( tpCur->enableTagQueuing != tpNew->enableTagQueuing ) 
            {
                scsiCmd->scsiCmd.cdbFlags |= kCDBFlagsEnableTagQueuing;
            }

            if ( (scsiCmd->scsiCmd.cdbFlags & 
	    (kCDBFlagsNegotiateSDTR |
	     kCDBFlagsNegotiateWDTR |
	     kCDBFlagsNegotiatePPR  |
	     kCDBFlagsEnableTagQueuing)) == 0 )
            {
                IORWUnlock( target->targetSem ); 
                target->negotiateState  = kStateIdle;
                target->commandLimit    = target->commandLimitSave;
            }

            *tpCur = *tpNew;
        }
    }

    if ( negotiateState == kStateIssue )
    {
        if ( commandCount == 0 )
        {
            disableDisconnect = lunParmsNew.disableDisconnect;
            negotiateState = kStateIdle;
        }
    }               
}    

/*
 *
 *
 *
 */
void IOSCSIParallelDevice::negotiationComplete()
{
    SCSITargetParms	*tpCur, *tpNew;

    tpNew = &target->targetParmsNew;
    tpCur = &target->targetParmsCurrent;

    if ( target->negotiationResult.returnCode == kIOReturnSuccess )
    {
        tpCur->transferPeriodpS = tpNew->transferPeriodpS = target->negotiationResult.transferPeriodpS;
        tpCur->transferOffset   = tpNew->transferOffset   = target->negotiationResult.transferOffset;
        tpCur->transferWidth    = tpNew->transferWidth    = target->negotiationResult.transferWidth;
        tpCur->transferOptions  = tpNew->transferOptions  = target->negotiationResult.transferOptions;

        target->commandLimit    = target->commandLimitSave;
    }
    else
    {
        tpNew->transferPeriodpS = 0;
        tpNew->transferOffset   = 0;
        tpNew->transferWidth    = 1;
    }

    target->regObjTransferPeriod->setValue( tpNew->transferPeriodpS );
    target->regObjTransferOffset->setValue( tpNew->transferOffset );
    target->regObjTransferWidth->setValue( tpNew->transferWidth );
    target->regObjTransferOptions->setValue( tpNew->transferOptions );

    target->negotiateState  = kStateIdle;
}

/*
 *
 *
 *
 */
bool IOSCSIParallelDevice::checkTag( IOSCSIParallelCommand *scsiCmd )
{
    SCSICDBInfo		scsiCDB;
    bool		rc = true;

    scsiCmd->getCDB( &scsiCDB );

    scsiCDB.cdbTagMsg = 0;
    scsiCDB.cdbTag    = (UInt32)-1;

    do 
    {
        if ( scsiCmd->device->target->targetParmsCurrent.enableTagQueuing == false )
        {
            break;
        }

	/* If the command is untagged, then don't allocate a tag nor
	 * send the untagged command as a simple-tagged command.
	 */
        if ( scsiCDB.cdbTagMsg == 0 )
        {
            break;
        }
    
        if ( allocTag( &scsiCDB.cdbTag ) == false )
        {
             rc = false;
             break;
        }
    }
    while ( 0 );

    scsiCmd->setCDB( &scsiCDB );

    return rc;
}

/*
 *
 *
 *
 */
bool IOSCSIParallelDevice::allocTag( UInt32 *tagId )
{
    UInt32		i;
    UInt32		tagIndex;
    UInt32		tagMask;
    UInt32		*tags = 0;

    switch ( controller->controllerInfo.tagAllocationMethod )
    {
        case kTagAllocationPerLun:
            tags = tagArray;
            break;
        case kTagAllocationPerTarget:
            tags = target->tagArray;
            break;    
        case kTagAllocationPerController:
            tags = controller->tagArray;
            break;
        default:
            ;
    }
    
    if ( tags == 0 ) return false;

    for ( i = 0; i < controller->controllerInfo.maxTags; i++ )
    {
        tagIndex = i / 32; 
        tagMask  = 1 << (i % 32);
        if ( !(tags[tagIndex] & tagMask) )
        {
            tags[tagIndex] |= tagMask;
            *tagId = i;
            return true;
        }
    }
    return false;
}

/*
 *
 *
 *
 */
void IOSCSIParallelDevice::freeTag( UInt32 tagId )
{
    UInt32		*tags = 0;

    switch ( controller->controllerInfo.tagAllocationMethod )
    {
        case kTagAllocationPerLun:
            tags = tagArray;
            break;
        case kTagAllocationPerTarget:
            tags = target->tagArray;
            break;    
        case kTagAllocationPerController:
            tags = controller->tagArray;
            break;
        default:
            ;
    }

    if ( tags == 0 ) return;

    tags[tagId/32] &= ~(1 << (tagId % 32));
}

/*
 *
 *
 *
 */
IOSCSIParallelCommand *IOSCSIParallelDevice::findCommandWithNexus( UInt32 tagValue )
{
    IOSCSIParallelCommand 		*scsiCmd;

    queue_iterate( &activeList, scsiCmd, IOSCSIParallelCommand *, nextCommand )
    {
        switch ( scsiCmd->cmdType )
        {
            case kSCSICommandExecute:
            case kSCSICommandReqSense:
                if ( scsiCmd->scsiCmd.cdbTag == tagValue )
                {
                    return scsiCmd;
                }
                break;
            default:
                ;
        }
    }

    queue_iterate( &abortList, scsiCmd, IOSCSIParallelCommand *, nextCommand )
    {
        switch ( scsiCmd->cmdType )
        {
            case kSCSICommandExecute:
            case kSCSICommandReqSense:
                if ( scsiCmd->scsiCmd.cdbTag == tagValue )
                {
                    return scsiCmd;
                }
                break;
            default:
                ;
        }
    }

    return 0;
}

/*
 *
 *
 *
 */
void IOSCSIParallelDevice::timer()
{
    IOSCSIParallelCommand 		*scsiCmd, *tmp = 0;
    SCSITargetLun		scsiTargetLun;

    queue_iterate( &activeList, scsiCmd, IOSCSIParallelCommand *, nextCommand )
    {
        tmp = (IOSCSIParallelCommand *)queue_prev( &scsiCmd->nextCommand );
 
        if ( scsiCmd->timer )
        {
            if ( !--scsiCmd->timer )
            {
                scsiCmd->getTargetLun( &scsiTargetLun );
                IOLog("Timeout: T/L = %d:%d Cmd = %08x Cmd Type = %d\n\r", 
                            scsiTargetLun.target, scsiTargetLun.lun, (int)scsiCmd, scsiCmd->cmdType );

                switch ( scsiCmd->cmdType )
                {
                    case kSCSICommandExecute:
                        moveCommand( &activeList, &abortList, scsiCmd, kIOReturnTimeout );
                        scsiCmd = tmp;
                        break;

                    case kSCSICommandReqSense:
                        reqSenseState = kStateIdle;
                        moveCommand( &activeList, &abortList, scsiCmd,  kIOReturnTimeout );
                        scsiCmd = tmp;
                        break;                         

                    case kSCSICommandAbort:
                    case kSCSICommandAbortAll:
		    case kSCSICommandDeviceReset:
                        controller->busResetState = kStateIssue;
                        break;       

		    default:
                        ;
                } 

                dispatchRequest();                                    
            } 
        }

        if ( queue_end( &activeList, (queue_head_t *)scsiCmd ) == true )
        {
            break;
        }
    }
}

/*
 *
 *
 *
 */
void IOSCSIParallelDevice::dispatchRequest()
{
    target->state = kStateActive;
    controller->dispatchRequest();
}
                        
/*
 *
 *
 *
 */
bool IOSCSIParallelDevice::dispatch( UInt32 *dispatchAction )
{
    bool		rc;

    checkCancelQueue();

    if ( controller->checkBusReset() == true )
    {
        *dispatchAction = kDispatchStop;
        return true;
    }

    if ( (rc = controller->commandDisable) == true )
    {
        *dispatchAction = kDispatchNextTarget;
        return true;
    }

    if ( checkAbortQueue() == true )
    {
        *dispatchAction = kDispatchNextTarget;
        return true;
    }    

    do
    {
        if ( (rc = controller->commandDisable) == true )
        {
            *dispatchAction = kDispatchStop;
            break;
        }

        if ( (rc = checkReqSense()) == true )
        {
            *dispatchAction = kDispatchNextTarget;
            break;
        }    

        rc = checkDeviceQueue( dispatchAction );

    } while ( *dispatchAction == kDispatchNextCommand );

    return rc;                
}            
            
      
/*
 *
 *
 *
 */
void IOSCSIParallelDevice::completeCommand( IOSCSIParallelCommand *scsiCmd )
{
    SCSICommandType		cmdType;

    cmdType = scsiCmd->cmdType;
    switch ( cmdType )
    {
        case kSCSICommandExecute:
            executeCommandDone( scsiCmd );
            break;

        case kSCSICommandReqSense:
            executeReqSenseDone( scsiCmd );
            break;
       
        case kSCSICommandAbort:
        case kSCSICommandAbortAll:
        case kSCSICommandDeviceReset:
            abortCommandDone( scsiCmd );
            break;

        case kSCSICommandCancel:
            cancelCommandDone( scsiCmd );
            break;

        default:
            ;
    }

    checkIdleNotify();

    dispatchRequest();
}     

/*
 *
 *
 *
 */
void IOSCSIParallelDevice::checkIdleNotify()
{
    if ( idleNotifyActive == false )
    {
        return;
    }

    if ( (queue_empty( &activeList ) == true) 
            &&  (queue_empty( &abortList ) == true)
               &&  (queue_empty( &cancelList ) == true)
                  && (target->reqSenseCount == 0) )
    {
        idleNotifyActive = false;
        (idleNotifyCallback)( idleNotifyTarget, idleNotifyRefcon );
    }
}  

/*
 *
 *
 *
 */
void IOSCSIParallelDevice::flushQueue( UInt32 queueType, IOReturn rc )
{
    queue_head_t		*queue;

    queue = (queueType == kQTypeBypassQ) ? &bypassList : &deviceList;
    purgeAllCommands( queue, rc );
}
             
/*
 *
 *
 *
 */
void IOSCSIParallelDevice::executeCommandDone( IOSCSIParallelCommand *scsiCmd )
{
    deleteCommand( scsiCmd->list, scsiCmd );

    commandCount--;
    controller->commandCount--;
    target->commandCount--;

    if ( scsiCmd->scsiCmd.cdbTagMsg != 0 )
    {
        freeTag( scsiCmd->scsiCmd.cdbTag );
        scsiCmd->scsiCmd.cdbTag = (UInt32) -1;
    }

    if ( scsiCmd->scsiCmd.cdbFlags &   (kCDBFlagsNegotiateSDTR |
					kCDBFlagsNegotiateWDTR |
					kCDBFlagsNegotiatePPR  |
					kCDBFlagsEnableTagQueuing) )
    {
        if ( scsiCmd->scsiCmd.cdbFlags & (kCDBFlagsNegotiateSDTR |
					  kCDBFlagsNegotiateWDTR |
					  kCDBFlagsNegotiatePPR) )
        {
            negotiationComplete();
        }
        else
        {
            target->negotiationResult.returnCode = kIOReturnSuccess;
        }

        IORWUnlock( target->targetSem ); 
    }

    if ( scsiCmd->scsiCmd.cdbFlags & kCDBFlagsNoDisconnect )
    {
        controller->commandLimit = controller->commandLimitSave;
        controller->noDisconnectCmd = 0;
    }        

    if ( scsiCmd->results.scsiStatus == kSCSIStatusCheckCondition 
              && scsiCmd->results.requestSenseDone == false
                  && scsiCmd->senseData != 0 ) 
    {
        reqSenseOrigCmd = scsiCmd;
        reqSenseState   = kStateIssue;
        target->reqSenseCount++;
        return;
    }

    if ( scsiCmd->results.scsiStatus == kSCSIStatusQueueFull )
    {
        if ( commandCount > 4 )
        {
//            IOLog( "IOSCSI: Q-full - commandCount = %d commandLimit = %d\n\r", commandCount, commandLimit );
            commandLimit = commandCount;
        }

        stackCommand( &deviceList, scsiCmd );
        return;
    }       

    finishCommand( scsiCmd );
}

/*
 *
 *
 *
 */
void IOSCSIParallelDevice::executeReqSenseDone( IOSCSIParallelCommand *scsiCmd )
{
    IOSCSIParallelCommand 		*origCommand;

    deleteCommand( scsiCmd->list, scsiCmd );

    target->reqSenseState = reqSenseState = kStateIdle;
    target->reqSenseCount--;

    commandCount--;
    controller->commandCount--;
    
    reqSenseOrigCmd = 0;
    
    origCommand = scsiCmd->origCommand;

    if ( (scsiCmd->results.returnCode == kIOReturnSuccess) || (scsiCmd->results.returnCode == kIOReturnUnderrun) )
    {
        origCommand->results.requestSenseDone   = true;
        origCommand->results.requestSenseLength = scsiCmd->results.bytesTransferred;
    }
    else
    {
        origCommand->results.requestSenseDone   = false;
        origCommand->results.requestSenseLength = 0;
    }

    finishCommand( scsiCmd->origCommand );
}

/*
 *
 *
 *
 */
void IOSCSIParallelDevice::abortCommandDone( IOSCSIParallelCommand *scsiCmd )
{
    IOSCSIParallelCommand		*origSCSICmd;
    IOSCSIParallelDevice		*abortDev;

    deleteCommand( scsiCmd->list, scsiCmd );

    abortState = kStateIdle;

    if ( scsiCmd->cmdType == kSCSICommandAbortAll )
    {
        moveAllCommands( &activeList, &cancelList, kIOReturnAborted );
        moveAllCommands( &abortList,  &cancelList, kIOReturnAborted );

        if ( client != 0 )
        {
            client->message( kSCSIClientMsgDeviceAbort | kSCSIClientMsgDone, this );
        }
    }
    if ( scsiCmd->cmdType == kSCSICommandDeviceReset )
    {
        target->commandLimit   = target->commandLimitSave;
        target->reqSenseCount  = 0;
        target->reqSenseState  = kStateIdle;
        target->negotiateState = kStateIssue;

        target->targetParmsCurrent.transferPeriodpS = 0;
        target->targetParmsCurrent.transferOffset   = 0;
        target->targetParmsCurrent.transferWidth    = 1;

        queue_iterate( &target->deviceList, abortDev, IOSCSIParallelDevice *, nextDevice )
        {
            abortDev->resetOccurred( (SCSIClientMessage)(kSCSIClientMsgDeviceReset | kSCSIClientMsgDone) );
        }
    }
    else if ( scsiCmd->cmdType == kSCSICommandAbort )
    {
        origSCSICmd = scsiCmd->origCommand;
        
        if ( findCommand( &abortList, origSCSICmd ) == true )
        {
            moveCommand( &abortList, &cancelList, origSCSICmd, kIOReturnAborted );
        }
    }

    return;
}

/*
 *
 *
 *
 */
void IOSCSIParallelDevice::cancelCommandDone( IOSCSIParallelCommand *scsiCmd )
{
    IOSCSIParallelCommand		*origSCSICmd;

    cancelState = kStateIdle;

    origSCSICmd = scsiCmd->origCommand;
    
    if ( findCommand( &cancelList, origSCSICmd ) == true )
    {
        IOLog( "IOSCSIParallelDevice::cancelCommandDone - Cancelled command not completed - scsiCmd = %08x\n\r", (int)origSCSICmd );
        deleteCommand( &cancelList, origSCSICmd );
    }    
}    

/*
 *
 *
 *
 */
void IOSCSIParallelDevice::finishCommand( IOSCSIParallelCommand *scsiCmd )
{
    if ( scsiCmd->completionInfo.async.callback )
    {
        (*scsiCmd->completionInfo.async.callback)( scsiCmd->completionInfo.async.target, 
                                                   scsiCmd->completionInfo.async.refcon );
    }
    else
    {
        scsiCmd->completionInfo.sync.lock->signal();
    }
}

    
/*
 *
 *
 */
OSDictionary *IOSCSIParallelDevice::createProperties()
{
    OSDictionary 	*propTable = 0;
    OSObject		*regObj;
    char		tmpbuf[81];
    char		*d;   
    char		unit[10];

    propTable = OSDictionary::withCapacity(kSCSIMaxProperties);
    if ( propTable == NULL )
    {
        return NULL;
    }

    regObj = (OSObject *)OSNumber::withNumber(targetLun.target,32);
    if ( addToRegistry( propTable, regObj, kSCSIPropertyTarget ) != true )
    {
        goto createprop_error;
    }

    regObj = (OSObject *)OSNumber::withNumber(targetLun.target,32);
    if ( addToRegistry( propTable, regObj, kSCSIPropertyIOUnit ) != true )
    {
        goto createprop_error;
    }

    sprintf(unit,"%x",targetLun.target);
    setLocation(unit);

    regObj = (OSObject *)OSNumber::withNumber(targetLun.lun,32);
    if ( addToRegistry( propTable, regObj, kSCSIPropertyLun ) != true )
    {
        goto createprop_error;
    }

    d= tmpbuf;
    
    stripBlanks( d, (char *)inquiryData->vendorName, sizeof(inquiryData->vendorName) );
    regObj = (OSObject *)OSString::withCString( d );
    if ( addToRegistry( propTable, regObj, kSCSIPropertyVendorName ) != true )
    {
        goto createprop_error;
    }

    stripBlanks( d, (char *)inquiryData->productName, sizeof(inquiryData->productName) );
    regObj = (OSObject *)OSString::withCString( d );
    if ( addToRegistry( propTable, regObj, kSCSIPropertyProductName ) != true )
    {
        goto createprop_error;
    }

    stripBlanks( d, (char *)inquiryData->productRevision, sizeof(inquiryData->productRevision) );
    regObj = (OSObject *)OSString::withCString( d );
    if ( addToRegistry( propTable, regObj, kSCSIPropertyProductRevision ) != true )
    {
        goto createprop_error;
    }

    regObj = (OSObject *)OSBoolean::withBoolean( (inquiryData->devTypeMod & kSCSIDevTypeModRemovable) != 0 );
    if ( addToRegistry( propTable, regObj, kSCSIPropertyRemovableMedia ) != true )
    {
        goto createprop_error;
    }

    regObj = (OSObject *)OSNumber::withNumber( inquiryData->devType & kSCSIDevTypeMask, 32 );
    if ( addToRegistry( propTable, regObj, kSCSIPropertyDeviceTypeID ) != true )
    {
        goto createprop_error;
    }

    regObj = (OSObject *)target->regObjTransferPeriod;
    if ( addToRegistry( propTable, regObj, kSCSIPropertyTransferPeriod, false ) != true )
    {
        goto createprop_error;
    }
    regObjTransferPeriod = (OSNumber *)regObj;

    regObj = (OSObject *)target->regObjTransferOffset;
    if ( addToRegistry( propTable, regObj, kSCSIPropertyTransferOffset, false ) != true )
    {
        goto createprop_error;
    }
    regObjTransferOffset = (OSNumber *)regObj;


    regObj = (OSObject *)target->regObjTransferWidth;
    if ( addToRegistry( propTable, regObj, kSCSIPropertyTransferWidth, false ) != true )
    {
        goto createprop_error;
    }
    regObjTransferWidth = (OSNumber *)regObj;

    regObj = (OSObject *)target->regObjTransferOptions;
    if ( addToRegistry( propTable, regObj, kSCSIPropertyTransferOptions, false ) != true )
    {
        goto createprop_error;
    }
    regObjTransferOptions = (OSNumber *)regObj;

    regObj = (OSObject *)target->regObjCmdQueue;
    if ( addToRegistry( propTable, regObj, kSCSIPropertyCmdQueue, false ) != true )
    {
        goto createprop_error;
    }
    regObjCmdQueue = (OSNumber *)regObj;

    return propTable;

createprop_error: ;
    propTable->release();
    return NULL;
}


/*
 *
 *
 */
bool IOSCSIParallelDevice::addToRegistry( OSDictionary *propTable, OSObject *regObj, char *key,
                                          bool doRelease = true )
{
    bool                 rc;

    if ( regObj == NULL )
    {
        return false;
    }
    
    rc  = propTable->setObject( key, regObj );
    
    if ( doRelease )
    {
        // If 'doRelease' is true, then a reference count is consumed.
        regObj->release();
    }

    return rc;
}


/*
 *
 *
 *
 */
bool IOSCSIParallelDevice::matchPropertyTable(OSDictionary * table)
{
    bool match;

    match = compareProperty( table, kSCSIPropertyIOUnit )		&&
            compareProperty( table, kSCSIPropertyDeviceTypeID )		&&
            compareProperty( table, kSCSIPropertyRemovableMedia )	&&
            compareProperty( table, kSCSIPropertyVendorName )		&&
            compareProperty( table, kSCSIPropertyProductName )		&&
            compareProperty( table, kSCSIPropertyProductRevision );
             
    if ( match == true )
    {
        match = super::matchPropertyTable(table);
    }

    return match;
}


/*
 *
 *
 *
 */
IOService *IOSCSIParallelDevice::matchLocation(IOService * client)
{
    return this;
}


/*
 *
 *
 *
 */
void IOSCSIParallelDevice::stripBlanks( char *d, char *s, UInt32 l )
{
    char	*p, c;

    for ( p = d, c = *s; l && c ; l--)
    {
        c = (*d++ = *s++);
        if ( c != ' ' )
        {
            p = d;
        }
    }
    *p = 0;
}   

/*
 *
 *
 *
 */
IOSCSICommand *IOSCSIParallelDevice::allocCommand( IOSCSIDevice *, UInt32 clientDataSize )
{

    return (IOSCSICommand *) allocCommand( kIOSCSIParallelDevice, clientDataSize );
}

IOSCSIParallelCommand *IOSCSIParallelDevice::allocCommand( IOSCSIParallelDevice *, UInt32 clientDataSize )
{
    IOSCSIParallelCommand	*cmd;

    if ( (cmd = controller->allocCommand( clientDataSize )) )
    {
        cmd->device = this;
    }
    return cmd;
}

IOCDBCommand *IOSCSIParallelDevice::allocCommand( IOCDBDevice *, UInt32 clientDataSize )
{
    return (IOCDBCommand *) allocCommand( kIOSCSIDevice, clientDataSize );
}


/*
 *
 *
 */
IOWorkLoop *IOSCSIParallelDevice::getWorkLoop() const
{
    return controller->workLoop;
}


/*
 *
 *
 *
 */
bool IOSCSIParallelDevice::open( IOService *forClient, IOOptionBits options, void *arg )
{
    if ( client != 0 ) return false;

    client = forClient;

    return super::open( forClient, options, arg );
}

/*
 *
 *
 *
 */
void IOSCSIParallelDevice::close( IOService *forClient, IOOptionBits options )
{
    client = 0;

    return super::close( forClient, options );
}

/*
 *
 *
 *
 */
IOReturn IOSCSIParallelDevice::message( UInt32 forMsg, IOService *forProvider, void *forArg )
{
    IOReturn		rc = kIOReturnSuccess;
    SCSIClientMessage   clientMsg;

    clientMsg = (SCSIClientMessage) forMsg;

//    IOLog( "IOSCSIParallelDevice::message() - clientMsg = %08x\n\r", clientMsg );

    switch( clientMsg )
    {
        case kSCSIClientMsgBusReset:
            holdQueue( kQTypeNormalQ );
            break;
        case kSCSIClientMsgBusReset | kSCSIClientMsgDone:
            releaseQueue( kQTypeNormalQ );
            break;
        default:
            rc = super::message( clientMsg, forProvider, forArg );
    }

    return rc;
}

/*
 *
 *
 *
 */
void IOSCSIParallelDevice::free()
{
    if ( deviceGate != 0 )
    {
        controller->workLoop->removeEventSource( deviceGate );
        deviceGate->release();
    }

    if ( reqSenseCmd != 0 ) 		reqSenseCmd->release();
    if ( abortCmd != 0 ) 		abortCmd->release();
    if ( cancelCmd != 0 ) 		cancelCmd->release();
    if ( probeCmd != 0 ) 		probeCmd->release();

    if ( tagArray != 0 ) 		IOFree( tagArray, controller->tagArraySize );
    if ( inquiryData != 0 )		IOFree( inquiryData, inquiryDataSize );
    if ( devicePrivateData != 0 )	IOFreeContiguous( devicePrivateData, controller->controllerInfo.lunPrivateDataSize );
    if ( clientSem != 0 ) 		IORWLockFree( clientSem );

    super::free();
}



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
 *	IOSCSIParallelController.cpp
 *
 */

#include <IOKit/scsi/IOSCSIParallelInterface.h>
#include <IOKit/IOSyncer.h>

#undef  super 
#define super	IOService

OSDefineMetaClass( IOSCSIParallelController, IOService )
OSDefineAbstractStructors( IOSCSIParallelController, IOService );

#define round(x,y) (((int)(x) + (y) - 1) & ~((y)-1))

/*
 *
 *
 */
bool IOSCSIParallelController::start( IOService *forProvider )
{
    provider = forProvider;

    if ( provider->open( this ) != true )
    { 
        return false;
    }

    if ( createWorkLoop() != true )
    {
        return false;
    }

    if ( configureController() == false )
    {
        provider->close( this );
        return false;
    }

    initQueues();
    
    if ( scanSCSIBus() == false ) 
    {
        provider->close( this );
        return false;
    }

    return true;
}

/*
 *
 *
 *
 */
bool IOSCSIParallelController::scanSCSIBus()
{
    SCSITargetLun		targetLun;
    UInt32			i;
    
    targetLun.lun = 0;
    
    for ( i=0; i < controllerInfo.maxTargetsSupported; i++ )
    {
        targetLun.target = i;
        probeTarget( targetLun );
    }
    
    return true;
}       

/*
 *
 *
 *
 */
bool IOSCSIParallelController::probeTarget( SCSITargetLun targetLun )
{
    IOSCSIParallelDevice	*device;
    UInt32		i;
    
    if ( targetLun.target == controllerInfo.initiatorId )
    {
        return false;
    }

    if ( initTarget( targetLun ) == false )
    {
        releaseTarget( targetLun );
        return false;
    }

    for ( i=0; i < controllerInfo.maxLunsSupported; i++ )
    {
        targetLun.lun    = i;
        
        device = createDevice();   
        if ( device == 0 )
        {
            break;
        }
           
        if ( device->init( this, targetLun ) == false )
        {
            releaseDevice( device );
            break;
        }

        if ( initDevice( device ) == false )
        {
            releaseDevice( device );
            continue;
        }
 
        if ( device->probeTargetLun() != kIOReturnSuccess )
        {
            releaseDevice( device );
            if ( i == 0 ) break;
        }
    }

    if ( i == 0 )
    {
        releaseTarget( targetLun );
        return false;
    }

    queue_iterate( &targets[targetLun.target].deviceList, device, IOSCSIParallelDevice *, nextDevice )
    {
        device->setupTarget();
        device->attach( this );
        device->registerService();
    }

    return true;
}            

/*
 *
 *
 *
 */
bool IOSCSIParallelController::initTargetGated( SCSITargetLun *targetLun )
{
    return initTarget( *targetLun );
}

bool IOSCSIParallelController::initTarget( SCSITargetLun targetLun )
{
    SCSITarget		*target;
    UInt32		number;

    if ( getWorkLoop()->inGate() == false )
    {
        return controllerGate->runAction( (IOCommandGate::Action)&IOSCSIParallelController::initTargetGated, (void *)&targetLun );
    }

    target = &targets[targetLun.target];

    target->clientSem = IORWLockAlloc();
    target->targetSem = IORWLockAlloc();
    if( (target->targetSem == 0) || (target->clientSem == 0))
    {
        return false;
    }
    target->commandLimitSave = target->commandLimit = 1;

    target->targetParmsCurrent.transferWidth = 1;

    if ( controllerInfo.targetPrivateDataSize != 0 )
    {
        target->targetPrivateData = IOMallocContiguous( controllerInfo.targetPrivateDataSize, 16, 0 );
        if ( target->targetPrivateData == 0 )
        {
            return false;
        }
    }

    if ( controllerInfo.tagAllocationMethod == kTagAllocationPerTarget )
    {
        target->tagArray = (UInt32 *)IOMalloc( tagArraySize );
        if ( target->tagArray == 0 )
        {
            return false;
        }
        bzero( target->tagArray, tagArraySize );
    }

    number = 0;
    target->regObjTransferPeriod = OSNumber::withNumber( number, 32 );
    if ( target->regObjTransferPeriod == 0 )
    {
        return false;
    }

    number = 0;
    target->regObjTransferOffset = OSNumber::withNumber( number, 32 );
    if ( target->regObjTransferOffset == 0 )
    {
        return false;
    }

    number = 1;
    target->regObjTransferWidth = OSNumber::withNumber( number, 32 );
    if ( target->regObjTransferWidth == 0 )
    {
        return false;
    }

    number = 0;
    target->regObjTransferOptions = OSNumber::withNumber( number, 32 );
    if ( target->regObjTransferOptions == 0 )
    {
        return false;
    }

    number = 0;
    target->regObjCmdQueue = OSNumber::withNumber( number, 32 );
    if ( target->regObjCmdQueue == 0 )
    {
        return false;
    }

    target->targetAllocated = allocateTarget( targetLun );
       
    return target->targetAllocated;
}

/*
 *
 *
 *
 */
void IOSCSIParallelController::releaseTargetGated( SCSITargetLun *targetLun )
{
    releaseTarget( *targetLun );
}

void IOSCSIParallelController::releaseTarget( SCSITargetLun targetLun )
{
    SCSITarget		*target;

    if ( getWorkLoop()->inGate() == false )
    {
        controllerGate->runAction( (IOCommandGate::Action)&IOSCSIParallelController::releaseTargetGated, (void *)&targetLun );
        return;
    }

    target = &targets[targetLun.target];

    if ( queue_empty( &target->deviceList ) != true ) 
    {
        IOLog("IOSCSIParallelController()::Target %d deleted with lun(s) active!\n\r",
               targetLun.target );
    }

    if ( target->targetAllocated == true )
    {
        deallocateTarget( targetLun );

        target->targetAllocated = false;
    }

    if ( target->tagArray != 0 )
    {
        IOFree( target->tagArray, tagArraySize );
        target->tagArray = 0;
    }

    if ( target->targetPrivateData != 0 )
    {
	IOFreeContiguous( target->targetPrivateData, controllerInfo.targetPrivateDataSize );
        target->targetPrivateData = 0;
    }

    if ( target->clientSem != 0 )
    {
        IORWLockFree( target->clientSem );
    }
    if ( target->targetSem != 0 )
    {
        IORWLockFree( target->targetSem );
    }

    if ( target->regObjTransferPeriod != 0 )
    {
        target->regObjTransferPeriod->release();
        target->regObjTransferPeriod = 0;
    }
    if ( target->regObjTransferOffset != 0 )
    {
        target->regObjTransferOffset->release();
        target->regObjTransferOffset = 0;
    }
    if ( target->regObjTransferWidth != 0 )
    {
        target->regObjTransferWidth->release();
        target->regObjTransferWidth = 0;
    }
    if ( target->regObjCmdQueue != 0 )
    {
        target->regObjCmdQueue->release();
        target->regObjCmdQueue = 0;
    }

}

/*
 *
 *
 *
 */
bool IOSCSIParallelController::initDeviceGated( IOSCSIParallelDevice *device )
{
    return initDevice( device );
}

bool IOSCSIParallelController::initDevice( IOSCSIParallelDevice *device )
{
    if ( getWorkLoop()->inGate() == false )
    {
        return controllerGate->runAction( (IOCommandGate::Action)&IOSCSIParallelController::initDeviceGated, (void *)device );
    }

    addDevice( device );
    device->lunAllocated = allocateLun( device->targetLun );

    return device->lunAllocated;    
}

/*
 *
 *
 *
 */
void IOSCSIParallelController::releaseDeviceGated( IOSCSIParallelDevice *device )
{
    releaseDevice( device );
    return;
}

void IOSCSIParallelController::releaseDevice( IOSCSIParallelDevice *device )
{
    if ( getWorkLoop()->inGate() == false )
    {
        controllerGate->runAction( (IOCommandGate::Action)&IOSCSIParallelController::releaseDeviceGated, (void *)device );
        return;
    }

    deleteDevice( device );
    if ( device->lunAllocated == true )
    {
        deallocateLun( device->targetLun );
    }
    
    device->release();    
}


/*
 *
 *
 *
 */
void IOSCSIParallelController::addDevice( IOSCSIParallelDevice *forDevice )
{
    UInt32	targetID;

    targetID = forDevice->targetLun.target;
    
    forDevice->target = &targets[targetID];
    queue_enter( &targets[targetID].deviceList, forDevice, IOSCSIParallelDevice *, nextDevice );
}

/*
 *
 *
 *
 */
void IOSCSIParallelController::deleteDevice( IOSCSIParallelDevice *forDevice )
{
    queue_head_t		*deviceList;
    IOSCSIParallelDevice		*device;
    UInt32			targetID;

    targetID = forDevice->targetLun.target;    

    deviceList = &targets[targetID].deviceList;

    queue_iterate( deviceList, device, IOSCSIParallelDevice *, nextDevice )
    {
        if ( device == forDevice )
        {
            queue_remove( &targets[targetID].deviceList, device, IOSCSIParallelDevice *, nextDevice );
            break;
        }
    }
}

/*
 *
 *
 *
 */
bool IOSCSIParallelController::allocateTarget( SCSITargetLun targetLun )
{
    return true;
}

/*
 *
 *
 *
 */
void IOSCSIParallelController::deallocateTarget( SCSITargetLun targetLun )
{
}

/*
 *
 *
 *
 */
bool IOSCSIParallelController::allocateLun( SCSITargetLun targetLun )
{
    return true;
}

/*
 *
 *
 *
 */
void IOSCSIParallelController::deallocateLun( SCSITargetLun targetLun )
{
}


/*
 *
 *
 *
 */
void *IOSCSIParallelController::getTargetData( SCSITargetLun targetLun )
{
    return targets[targetLun.target].targetPrivateData;
}

/*
 *
 *
 *
 */
void *IOSCSIParallelController::getLunData( SCSITargetLun targetLun )
{
    queue_head_t		*deviceList;
    IOSCSIParallelDevice		*device;
	
    deviceList = &targets[targetLun.target].deviceList;

    queue_iterate( deviceList, device, IOSCSIParallelDevice *, nextDevice )
    {
        if ( device->targetLun.lun == targetLun.lun )
        {
            return device->devicePrivateData;
        }
    }
    return 0;
}



/*
 *
 *
 *
 */
IOSCSIParallelDevice *IOSCSIParallelController::createDevice()
{
    return new IOSCSIParallelDevice;
}


/*
 *
 *
 *
 */
void IOSCSIParallelController::initQueues()
{
    UInt32		i;

    for ( i=0; i < controllerInfo.maxTargetsSupported; i++ )
    {
        queue_init( &targets[i].deviceList );
    }

    resetCmd = allocCommand( 0 );
    resetCmd->cmdType = kSCSICommandBusReset;

    timer( timerEvent ); 
}

/*
 *
 *
 *
 */
void IOSCSIParallelController::reset()
{
    IOSCSIParallelDevice	*device;
    UInt32			i;
    
    if ( busResetState != kStateIssue )
    {
        return;
    }

    busResetState = kStateActive;

    for (i=0; i < controllerInfo.maxTargetsSupported; i++ )
    {
        queue_iterate( &targets[i].deviceList, device, IOSCSIParallelDevice *, nextDevice )
        {
            if ( device->client != 0 )
            {
                device->client->message( kSCSIClientMsgBusReset, device );
            }
        }
    }

    resetCommand( resetCmd );
}

/*
 *
 *
 *
 */
bool IOSCSIParallelController::checkBusReset()
{
    if ( busResetState == kStateIdle )
    {
        return false;
    }
    if ( busResetState == kStateIssue )
    {
        reset();
    }
    return true;
}


/*
 *
 *
 *
 */
void IOSCSIParallelController::resetOccurred()
{
    UInt32			i;
    IOSCSIParallelDevice	*device;
    SCSITarget			*target;
    SCSIClientMessage		clientMsg;

    for (i=0; i < controllerInfo.maxTargetsSupported; i++ )
    {
        target = &targets[i];

        target->commandLimit   = target->commandLimitSave;
        target->reqSenseCount  = 0;
        target->reqSenseState  = kStateIdle;
        target->negotiateState = kStateIssue;

        target->targetParmsCurrent.transferPeriodpS = 0;
        target->targetParmsCurrent.transferOffset   = 0;
        target->targetParmsCurrent.transferWidth    = 1;

        noDisconnectCmd = 0;

        clientMsg =  ( busResetState != kStateActive ) ? kSCSIClientMsgBusReset : kSCSIClientMsgNone;

        queue_iterate( &target->deviceList, device, IOSCSIParallelDevice *, nextDevice )
        {
            device->resetOccurred( clientMsg );
        }
    }

    resetTimer = (kSCSIResetIntervalmS / kSCSITimerIntervalmS + 1);
}            


/*
 *
 *
 */
void IOSCSIParallelController::timer( IOTimerEventSource * /* timer */ )
{
    UInt32		i;
    IOSCSIParallelDevice	*device;


    if ( disableTimer )
    {
        if ( !--disableTimer )
        {
            disableTimeoutOccurred();
        }
    }

    if ( resetTimer )
    {
        if ( !--resetTimer )
        {
            for (i=0; i < controllerInfo.maxTargetsSupported; i++ )
            {
                queue_iterate( &targets[i].deviceList, device, IOSCSIParallelDevice *, nextDevice )
                {
                    device->resetComplete();
                }
            }  
                  
        }
    }
    else
    {
        for (i=0; i < controllerInfo.maxTargetsSupported; i++ )
        {
            queue_iterate( &targets[i].deviceList, device, IOSCSIParallelDevice *, nextDevice )
            {
                device->timer();
            }
        }    
    }

    timerEvent->setTimeoutMS(kSCSITimerIntervalmS);
}


/*
 *
 *
 *
 */
void IOSCSIParallelController::completeCommand( IOSCSIParallelCommand *scsiCmd )
{
    switch ( scsiCmd->cmdType )
    {
        case kSCSICommandBusReset:
            resetOccurred();
            busResetState = kStateIdle;
            break;
        default:
            ;
    }
}


/*
 *
 *
 *
 */
bool IOSCSIParallelController::createWorkLoop()
{
    workLoop = getWorkLoop();
    if ( workLoop == 0 )
    {
        workLoop = IOWorkLoop::workLoop();
        if ( workLoop == 0 )
        {
             return false;
        }
    }

    timerEvent = IOTimerEventSource::timerEventSource( this, (IOTimerEventSource::Action) &IOSCSIParallelController::timer );
    if ( timerEvent == 0 )
    {
        return false;
    }

    if ( workLoop->addEventSource( timerEvent ) != kIOReturnSuccess )
    {
        return false;
    }


    dispatchEvent = IOInterruptEventSource::interruptEventSource( this,
                                                                  (IOInterruptEventAction) &IOSCSIParallelController::dispatch,
					                          0 );
    if ( dispatchEvent == 0 )
    {
        return false;
    }    

    if ( workLoop->addEventSource( dispatchEvent ) != kIOReturnSuccess )
    {
        return false;
    }

    controllerGate = IOCommandGate::commandGate( this, (IOCommandGate::Action) 0 );
    if ( controllerGate == 0 )
    {
        return false;
    }    
    
    if ( workLoop->addEventSource( controllerGate ) != kIOReturnSuccess )
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
IOSCSIParallelCommand *IOSCSIParallelController::findCommandWithNexus( SCSITargetLun targetLun, UInt32 tagValue = (UInt32)-1 )
{
    IOSCSIParallelDevice	*device;

    device = findDeviceWithTargetLun( targetLun );
    if ( device == 0 )
    {
        return 0;
    }

    return device->findCommandWithNexus( tagValue );
}


/*
 *
 *
 *
 */
IOSCSIParallelDevice *IOSCSIParallelController::findDeviceWithTargetLun( SCSITargetLun targetLun )
{
    IOSCSIParallelDevice		*device;

    if ( targetLun.target > controllerInfo.maxTargetsSupported || targetLun.lun > controllerInfo.maxLunsSupported )
    {
        return 0;
    }

    queue_iterate( &targets[targetLun.target].deviceList, device, IOSCSIParallelDevice *, nextDevice )
    {
        if ( device->targetLun.lun == targetLun.lun )
        {
            return device;
        }
    }
    return 0;
}    
    
       
/*
 *
 *
 *
 */
bool IOSCSIParallelController::configureController()
{
    UInt32 		targetsSize;

    if ( configure( provider, &controllerInfo ) == false )
    {
        return false;
    }

    controllerInfo.commandPrivateDataSize = round( controllerInfo.commandPrivateDataSize, 16 );

    if ( controllerInfo.maxCommandsPerController == 0 ) controllerInfo.maxCommandsPerController = (UInt32) -1;    
    if ( controllerInfo.maxCommandsPerTarget == 0     ) controllerInfo.maxCommandsPerTarget     = (UInt32) -1;    
    if ( controllerInfo.maxCommandsPerLun == 0 )        controllerInfo.maxCommandsPerLun        = (UInt32) -1;    

    targetsSize = controllerInfo.maxTargetsSupported * sizeof(SCSITarget);
    targets = (SCSITarget *)IOMalloc( targetsSize );
    bzero( targets, targetsSize );

    commandLimit = commandLimitSave = controllerInfo.maxCommandsPerController;

    tagArraySize = (controllerInfo.maxTags / 32 + ((controllerInfo.maxTags % 32) ? 1 : 0)) * sizeof(UInt32);
     
    if ( controllerInfo.tagAllocationMethod == kTagAllocationPerController )
    {
        tagArray = (UInt32 *)IOMalloc( tagArraySize );
        bzero( tagArray, tagArraySize );
    }

    return true;
}

/*
 *
 *
 *
 */
void IOSCSIParallelController::setCommandLimit( UInt32 newCommandLimit )
{
    if ( newCommandLimit == 0 ) controllerInfo.maxCommandsPerController = (UInt32) -1;    

    commandLimit = commandLimitSave = controllerInfo.maxCommandsPerController;
}

/*
 *
 *
 *
 */
IOWorkLoop *IOSCSIParallelController::getWorkLoop() const
{
    return workLoop;
}

/*
 *
 *
 *
 */
void IOSCSIParallelController::disableCommands( UInt32 disableTimeoutmS )
{
    commandDisable = true;

    disableTimer = ( disableTimeoutmS != 0 ) ? (disableTimeoutmS / kSCSITimerIntervalmS + 1) : 0;
}
    
    
/*
 *
 *
 *
 */
void IOSCSIParallelController::disableCommands()
{
    UInt32		disableTimeout;

    commandDisable = true;

    disableTimeout = kSCSIDisableTimeoutmS;

    if ( noDisconnectCmd != 0 )
    {
        disableTimeout = noDisconnectCmd->getTimeout();
        if ( disableTimeout != 0 ) disableTimeout += kSCSIDisableTimeoutmS;            
    }

    disableTimer = ( disableTimeout != 0 ) ? (disableTimeout / kSCSITimerIntervalmS + 1) : 0;
}

/*
 *
 *
 *
 */
void IOSCSIParallelController::disableTimeoutOccurred()
{
    busResetState = kStateIssue;
    dispatchRequest();     
}

/*
 *
 *
 *
 */
void IOSCSIParallelController::rescheduleCommand( IOSCSIParallelCommand *forSCSICmd )
{
    forSCSICmd->getDevice(kIOSCSIParallelDevice)->rescheduleCommand( forSCSICmd );
}

/*
 *
 *
 *
 */
void IOSCSIParallelController::enableCommands()
{
    commandDisable = false;

    disableTimer = 0;

    dispatchRequest();
}

/*
 *
 *
 *
 */
void IOSCSIParallelController::dispatchRequest()
{
    dispatchEvent->interruptOccurred(0, 0, 0);
}


/*
 *
 *
 *
 */
void IOSCSIParallelController::dispatch()
{
    SCSITarget		*target;
    IOSCSIParallelDevice 	*device;
    UInt32              dispatchAction;
    UInt32		lunsActive = 0;
    UInt32		i;

    if ( !targets || checkBusReset() )
    {
        goto dispatch_Exit;
    }

    for ( i = 0; i < controllerInfo.maxTargetsSupported; i++ )
    {
        target = &targets[i];

        if ( target->state == kStateActive )
        {
            lunsActive = 0;

            queue_iterate( &target->deviceList, device, IOSCSIParallelDevice *, nextDevice )
            {
                if ( device->dispatch( &dispatchAction ) == true )
                {
                    lunsActive++;
                }

                switch ( dispatchAction )
                {
                    case kDispatchNextLun:
                        ;
                    case kDispatchNextTarget:
                        break;
                    case kDispatchStop:
                        goto dispatch_Exit;
                }     
            }
            if ( lunsActive == 0 )
            {
                target->state = kStateIdle;
            }
        }        
    }

dispatch_Exit:
    ;
}

/*
 *
 *
 *
 */
IOSCSIParallelCommand *IOSCSIParallelController::allocCommand(UInt32 clientDataSize )
{
    IOSCSIParallelCommand	*cmd;
    UInt32		size;

    size = controllerInfo.commandPrivateDataSize + round(clientDataSize, 16);

    cmd = new IOSCSIParallelCommand;
    if ( !cmd )
    {
        return 0;
    }
    cmd->init();

    if ( size )
    {
        cmd->dataArea = (void *)IOMallocContiguous( (vm_size_t)size, 16, 0 );
        if ( !cmd->dataArea )
        {
            cmd->release();
            return 0;
        }
        
        bzero( cmd->dataArea, size );

        cmd->dataSize = size;

        if ( controllerInfo.commandPrivateDataSize )
        {
            cmd->commandPrivateData = cmd->dataArea;
        }
        if ( clientDataSize )
        {
            cmd->clientData = (void *)((UInt8 *)cmd->dataArea + controllerInfo.commandPrivateDataSize);
        }
    }

    cmd->controller = this;

    return cmd;
}

/*
 *
 *
 *
 */
void IOSCSIParallelController::free()
{
    UInt32			targetsSize;
    UInt32			i;

    if ( controllerGate != 0 )
    {
        workLoop->removeEventSource( controllerGate );
        controllerGate->release();
    }

    if ( timerEvent != 0 ) 	timerEvent->release();

    if ( dispatchEvent != 0 )   dispatchEvent->release();

    if ( resetCmd != 0 )	resetCmd->release();

    if ( workLoop != 0 )  	workLoop->release();

    if ( targets != 0 )
    {
        for ( i=0; i < controllerInfo.maxTargetsSupported; i++ )
        {
            if ( targets[i].targetPrivateData != 0 )
            {
         	IOFreeContiguous( targets[i].targetPrivateData, controllerInfo.targetPrivateDataSize );
            }
        }

        targetsSize = controllerInfo.maxTargetsSupported * sizeof(SCSITarget);
        IOFree( targets, targetsSize ); 
    }

    if ( tagArray != 0 ) IOFree( tagArray, tagArraySize );

    super::free();
}

/*
 *
 *
 *
 */
void IOSCSIParallelCommand::free()
{
    if ( dataArea )
    {
        IOFreeContiguous( dataArea, dataSize );        
    }

    OSObject::free();
}
     

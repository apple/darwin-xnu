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
 *	IOATAStandardController.cpp
 *
 */

#include <IOKit/ata/IOATAStandardInterface.h>
#include <IOKit/IOSyncer.h>

#undef  super 
#define super	IOService

OSDefineMetaClass( IOATAStandardController, IOService )
OSDefineAbstractStructors( IOATAStandardController, IOService );

#define round(x,y) (((int)(x) + (y) - 1) & ~((y)-1))

/*
 *
 *
 */
bool IOATAStandardController::start( IOService *forProvider )
{
    provider = forProvider;

//    IOSleep( 15000 );

    if ( provider->open( this ) != true )
    { 
        return false;
    }

    if ( createWorkLoop() != true )
    {
        return false;
    }

    if ( configureController() != true  )
    {
        provider->close( this );
        return false;
    }
    
    if ( scanATABus() != true ) 
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
bool IOATAStandardController::scanATABus()
{
    if ( createDeviceNubs() != true )
    {
        return false;
    }

    timer( timerEvent );

    if ( initTimings() == false )
    {
        return false;
    }
        
    disableControllerInterrupts();

    if ( reset() != kIOReturnSuccess )
    {
        return false;
    }

    enableControllerInterrupts();

    if ( probeDeviceNubs() != true )
    {
        return false;
    }

    if ( registerDeviceNubs() != true )
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
bool IOATAStandardController::createDeviceNubs()
{
    UInt32		i;
    IOATAStandardDevice		*ataDev;

    for (i = 0; i < controllerInfo.maxDevicesSupported; i++ )
    {       
        ataDev = targets[i].device = new IOATAStandardDevice;

        if ( ataDev->init( this, i ) != true )
        {
            ataDev->release();
            targets[i].device = NULL;
        }		
    }

    resetCmd = allocCommand( 0 );
    resetCmd->cmdType = kATACommandBusReset;
    resetCmd->setTimeout( kATAResetTimeoutmS );
    resetCmd->setPointers( 0, 0, false );

    return true;
}       

/*
 *
 *
 *
 */
bool IOATAStandardController::probeDeviceNubs()
{
    UInt32		i;
    IOATAStandardDevice		*ataDev;

    for (i = 0; i < controllerInfo.maxDevicesSupported; i++ )
    {       
        ataDev = targets[i].device;
        if ( ataDev->probeDeviceType() == kATADeviceNone )
        {
            ataDev->release();
            targets[i].device = NULL;
        }
    }

    for (i = 0; i < controllerInfo.maxDevicesSupported; i++ )
    {       
        ataDev = targets[i].device;
        if ( ataDev == NULL )
        {
            continue;
        }

        if ( ataDev->probeDevice() != true )
        {
            ataDev->release();
            targets[i].device = NULL;
        }
    }

    return true;
}  
     

/*
 *
 *
 *
 */
bool IOATAStandardController::registerDeviceNubs()
{
    UInt32		i;
    IOATAStandardDevice		*ataDev;

    for (i = 0; i < controllerInfo.maxDevicesSupported; i++ )
    {       
        ataDev = targets[i].device;
        if ( ataDev != NULL )
        {
            ataDev->attach( this );
            ataDev->registerService();
        }
   }

    return true;
} 
      
/*
 *
 *
 *
 */
bool IOATAStandardController::initTimings()
{
    ATATiming           	initPIOTiming;

    initPIOTiming.timingProtocol = kATATimingPIO;
    initPIOTiming.featureSetting = 0;
    initPIOTiming.mode           = 0;
    initPIOTiming.minDataAccess  = 165;
    initPIOTiming.minDataCycle   = 600;
    initPIOTiming.minCmdAccess   = 290;
    initPIOTiming.minCmdCycle    = 600;

    if ( calculateTiming( 0, &initPIOTiming ) != true )
    {
        return false;
    }
  
    if ( calculateTiming( 1, &initPIOTiming ) != true )
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
bool IOATAStandardController::matchNubWithPropertyTable( IOService *nub, OSDictionary *table )
{
    bool		rc;

    rc = nub->compareProperty( table, kATAPropertyLocation );

    return rc;
}



/*
 *
 *
 *
 */
void IOATAStandardController::releaseDevice( IOATAStandardDevice *device )
{
    workLoopRequest( kWorkLoopReleaseDevice, (UInt32) device );

    device->release();    
}

/*
 *
 *
 *
 */
bool IOATAStandardController::workLoopRequest( WorkLoopReqType type, UInt32 p1, UInt32 p2, UInt32 p3 )
{
    WorkLoopRequest	workLoopReq;

    bzero( &workLoopReq, sizeof(WorkLoopRequest) );
    workLoopReq.type = type;
    workLoopReq.sync = IOSyncer::create();

    workLoopReqGate->runCommand( &workLoopReq, (void *)p1, (void *)p2, (void *)p3 );

    workLoopReq.sync->wait();

    return( workLoopReq.rc );
}


/*
 *
 *
 *
 */
void IOATAStandardController::workLoopProcessRequest( WorkLoopRequest *workLoopReq, void *p1, void *p2, void *p3 )
{
    bool			rc = true;
    IOATAStandardDevice	*device;

    switch ( workLoopReq->type )
    {

        case kWorkLoopInitDevice:
            device = (IOATAStandardDevice *) p1;
            addDevice( device );
            rc = allocateDevice( device->unit );
            break;

        case kWorkLoopReleaseDevice:
            device = (IOATAStandardDevice *) p1;
            deleteDevice( device );
            break;
    }
   
    workLoopReq->rc = rc;
    workLoopReq->sync->signal();
}

/*
 *
 *
 *
 */
void IOATAStandardController::addDevice( IOATAStandardDevice *forDevice )
{
    ATAUnit	unit;

    unit = forDevice->unit;
    
    forDevice->target 	 = &targets[unit];
    targets[unit].device = forDevice;
}

/*
 *
 *
 *
 */
void IOATAStandardController::deleteDevice( IOATAStandardDevice *forDevice )
{
    ATAUnit			unit;

    unit = forDevice->unit;    
    targets[unit].device = 0;
}


/*
 *
 *
 *
 */
bool IOATAStandardController::allocateDevice( ATAUnit unit )
{
    return true;
}

/*
 *
 *
 *
 */
void IOATAStandardController::deallocateDevice( ATAUnit unit )
{
}


/*
 *
 *
 *
 */
void *IOATAStandardController::getDeviceData( ATAUnit unit )
{
    IOATAStandardDevice		*device;

    device = targets[unit].device;

    if ( device == 0 ) return 0;

    return device->devicePrivateData;
}


/*
 *
 *
 *
 */
IOReturn IOATAStandardController::reset()
{
    if ( busResetState != kStateIdle )
    {
        return kIOReturnNoResources;
    }

    busResetState = kStateIssue;
    dispatchRequest();     

    while ( busResetState != kStateIdle )
    {
        IOSleep( 100 );
    }

    return resetCmd->getResults( (ATAResults *)0 );
}

/*
 *
 *
 *
 */
void IOATAStandardController::resetATABus()
{
    if ( busResetState != kStateIssue )
    {
        return;
    }

    busResetState = kStateActive;

    resetStarted();

    resetCommand( resetCmd );
}

/*
 *
 *
 *
 */
void IOATAStandardController::resetStarted()
{
    IOATAStandardDevice		*device;
    UInt32			i;

    for (i=0; i < controllerInfo.maxDevicesSupported; i++ )
    {
        device = targets[i].device;

        if ( (device != 0) && (device->client != 0) && (device->abortCmdPending != kATACommandDeviceReset) )
        {
            device->client->message( kATAClientMsgBusReset, device );
        }
    }
}


/*
 *
 *
 *
 */
bool IOATAStandardController::checkBusReset()
{
    if ( busResetState == kStateIdle )
    {
        return false;
    }
    if ( busResetState == kStateIssue )
    {
        resetATABus();
    }
    return true;
}


/*
 *
 *
 */
void IOATAStandardController::timer( IOTimerEventSource * /* timer */ )
{
    UInt32		i;
    IOATAStandardDevice	*device;


    if ( disableTimer )
    {
        if ( !--disableTimer )
        {
            disableTimeoutOccurred();
        }
    }

    for (i=0; i < controllerInfo.maxDevicesSupported; i++ )
    {
       device = targets[i].device;
       if ( device != 0 )
       {
            device->timer();
       }
    }    

    timerEvent->setTimeoutMS(kATATimerIntervalmS);
}


/*
 *
 *
 *
 */
void IOATAStandardController::completeCommand( IOATAStandardCommand *ataCmd )
{
    switch ( ataCmd->cmdType )
    {
        case kATACommandBusReset:
            busResetState = kStateIdle;
            resetOccurred();
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
void IOATAStandardController::resetOccurred()
{
    UInt32		i;
    IOATAStandardDevice	*device;

    for (i=0; i < controllerInfo.maxDevicesSupported; i++ )
    {
        device = targets[i].device;

        if ( device == 0 ) continue;

        if ( device->abortCmdPending != kATACommandDeviceReset )
        {
            device->resetOccurred( (ATAClientMessage) (kATAClientMsgBusReset | kATAClientMsgDone) );
        }
    }
}            

/*
 *
 *
 *
 */
bool IOATAStandardController::createWorkLoop()
{
    workLoop = getWorkLoop();
    if ( workLoop == 0 )
    {
        workLoop = new IOWorkLoop;
        if ( workLoop == 0 )
        {
            return false;
        }
    }
    
    if ( workLoop->init() != true )
    {
        return false;
    }

    timerEvent = IOTimerEventSource::timerEventSource( this, (IOTimerEventSource::Action) &IOATAStandardController::timer );
    if ( timerEvent == NULL )
    {
        return false;
    }

    if ( workLoop->addEventSource( timerEvent ) != kIOReturnSuccess )
    {
        return false;
    }

    timer( timerEvent ); 


    dispatchEvent = IOInterruptEventSource::interruptEventSource( this,
                                                                  (IOInterruptEventAction) &IOATAStandardController::dispatch,
					                          0 );
    if ( dispatchEvent == 0 )
    {
        return false;
    }    

    if ( workLoop->addEventSource( dispatchEvent ) != kIOReturnSuccess )
    {
        return false;
    }
     
    workLoopReqGate = IOCommandGate::commandGate( this, (IOCommandGate::Action) &IOATAStandardController::workLoopProcessRequest );
    if ( workLoopReqGate == NULL )
    {
        return false;
    }

    if ( workLoop->addEventSource( workLoopReqGate ) != kIOReturnSuccess )
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
IOATAStandardCommand *IOATAStandardController::findCommandWithNexus( IOATAStandardDevice *device, UInt32 tagValue = (UInt32)-1 )
{
    return ((IOATAStandardDevice *)device)->findCommandWithNexus( tagValue );
}    
       
/*
 *
 *
 *
 */
bool IOATAStandardController::configureController()
{
    UInt32 		targetsSize;

    if ( configure( provider, &controllerInfo ) == false )
    {
        return false;
    }

    controllerInfo.commandPrivateDataSize = round( controllerInfo.commandPrivateDataSize, 16 );

    targetsSize = controllerInfo.maxDevicesSupported * sizeof(ATATarget);
    targets = (ATATarget *)IOMalloc( targetsSize );
    bzero( targets, targetsSize );

    commandLimit = commandLimitSave = (UInt32)-1;

    return true;
}

/*
 *
 *
 *
 */
void IOATAStandardController::setCommandLimit( IOATAStandardDevice *device, UInt32 newCommandLimit )
{
    ((IOATAStandardDevice *)device)->commandLimit = newCommandLimit;
}


/*
 *
 *
 *
 */
void IOATAStandardController::disableControllerInterrupts()
{
    workLoop->disableAllInterrupts();
}

/*
 *
 *
 *
 */
void IOATAStandardController::enableControllerInterrupts()
{
    workLoop->enableAllInterrupts();
}


/*
 *
 *
 *
 */
IOWorkLoop *IOATAStandardController::getWorkLoop() const
{
    return workLoop;
}

/*
 *
 *
 *
 */
void IOATAStandardController::disableCommands( UInt32 disableTimeoutmS )
{
    commandDisable = true;

    disableTimer = ( disableTimeoutmS != 0 ) ? (disableTimeoutmS / kATATimerIntervalmS + 1) : 0;
}
    
    
/*
 *
 *
 *
 */
void IOATAStandardController::disableCommands()
{
    UInt32		disableTimeout;

    commandDisable = true;

    disableTimeout = kATADisableTimeoutmS;

    if ( noDisconnectCmd != 0 )
    {
        disableTimeout = noDisconnectCmd->getTimeout();
        if ( disableTimeout != 0 ) disableTimeout += kATADisableTimeoutmS;            
    }

    disableTimer = ( disableTimeout != 0 ) ? (disableTimeout / kATATimerIntervalmS + 1) : 0;
}

/*
 *
 *
 *
 */
void IOATAStandardController::disableTimeoutOccurred()
{
    busResetState = kStateIssue;
    dispatchRequest();     
}


/*
 *
 *
 *
 */
UInt32 IOATAStandardController::getCommandCount()
{
    return commandCount;
}

/*
 *
 *
 *
 */
void IOATAStandardController::suspendDevice( IOATAStandardDevice *device )
{
    ((IOATAStandardDevice *)device)->suspend();
}

/*
 *
 *
 *
 */
void IOATAStandardController::resumeDevice( IOATAStandardDevice *device )
{
    ((IOATAStandardDevice *)device)->resume();
}

/*
 *
 *
 *
 */
IOATAStandardDevice *IOATAStandardController::selectDevice()
{
    IOATAStandardDevice		*ataDev;
    IOATAStandardDevice		*selectedDevice = 0;
    AbsoluteTime		maxSuspendTime;
    UInt32 			i;

    AbsoluteTime_to_scalar(&maxSuspendTime) = 0;

    for (i = 0; i < controllerInfo.maxDevicesSupported; i++ )
    {       
        ataDev = targets[i].device;
        if ( ataDev != NULL )
        {
            if ( ataDev->isSuspended == true )
            {
                if ( CMP_ABSOLUTETIME(&ataDev->suspendTime, &maxSuspendTime) > 0 )
                {
                    selectedDevice = ataDev;
                    AbsoluteTime_to_scalar( &maxSuspendTime ) = AbsoluteTime_to_scalar( &ataDev->suspendTime );
                }
            }
        }
    }

    return (IOATAStandardDevice *) selectedDevice;
}


/*
 *
 *
 *
 */
void IOATAStandardController::rescheduleCommand( IOATAStandardCommand *forATACmd )
{
    forATACmd->getDevice(kIOATAStandardDevice)->rescheduleCommand( forATACmd );
}

/*
 *
 *
 *
 */
void IOATAStandardController::enableCommands()
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
void IOATAStandardController::dispatchRequest()
{
    dispatchEvent->interruptOccurred(0, 0, 0);
}


/*
 *
 *
 *
 */
void IOATAStandardController::dispatch()
{
    ATATarget		*target;
    IOATAStandardDevice *device;
    UInt32              dispatchAction;
    UInt32		i;

    if ( checkBusReset() == true )
    {
        goto dispatch_Exit;
    }

    for ( i = 0; i < controllerInfo.maxDevicesSupported; i++ )
    {
        target = &targets[i];

        device = target->device;
        if ( device == 0 ) continue;

        if ( target->state == kStateActive )
        {
            if ( device->dispatch( &dispatchAction ) == false )
            {
                target->state = kStateIdle;
            }

            switch ( dispatchAction )
            {
                case kDispatchNextDevice:
                    break;
                case kDispatchStop:
                    goto dispatch_Exit;
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
IOATAStandardCommand *IOATAStandardController::allocCommand(UInt32 clientDataSize )
{
    IOATAStandardCommand	*cmd;
    UInt32		size;

    size = controllerInfo.commandPrivateDataSize + round(clientDataSize, 16);

    cmd = new IOATAStandardCommand;
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
void IOATAStandardController::free()
{
    UInt32			targetsSize;

    if ( timerEvent != 0 ) 	timerEvent->release();

    if ( workLoopReqGate != 0 ) workLoopReqGate->release();

    if ( dispatchEvent != 0 )   dispatchEvent->release();

    if ( resetCmd != 0 )	resetCmd->release();

    if ( workLoop != 0 )  	workLoop->release();

    if ( targets != 0 )
    {
        targetsSize = controllerInfo.maxDevicesSupported * sizeof(ATATarget);
        IOFree( targets, targetsSize ); 
    }

    super::free();
}

/*
 *
 *
 *
 */
void IOATAStandardCommand::free()
{
    if ( dataArea )
    {
        IOFreeContiguous( dataArea, dataSize );        
    }

    OSObject::free();
}
     

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
 *    IOATAStandardDriver.cpp
 *
 */
#include <IOKit/ata/IOATAStandardInterface.h>

#undef super
#define super IOATAStandardController

OSDefineMetaClass( IOATAStandardDriver, IOATAStandardController );
OSDefineAbstractStructors( IOATAStandardDriver, IOATAStandardController );

#if 0
static UInt32 dropInt=0;
#endif

/*
 *
 *
 */
void IOATAStandardDriver::executeCommand( IOATAStandardCommand *cmd )
{
    IOATAStandardDevice		*newDevice;
    ATAProtocol			newProtocol;
    ATATimingProtocol		timingProtocol;
    ATAResults			results;
 
    newDevice   = cmd->getDevice(kIOATAStandardDevice);
    newProtocol = cmd->getProtocol();

#if 0
    IOLog("IOATAStandardDriver::%s() - Cmd = %08x Device = %08x Count = %d\n\r", 
                                    __FUNCTION__, (int) cmd, (int) newDevice, getCommandCount() );
#endif

    if ( getCommandCount() > 1 )
    {
        if ( currentDevice != newDevice || currentProtocol != newProtocol )
        {
            suspendDevice( newDevice );
            rescheduleCommand( cmd );
            return;
        }
    }

    currentProtocol = newProtocol;

    if ( currentDevice != newDevice )
    {
        newDeviceSelected( newDevice );
        currentDevice = newDevice;
    }

    if ( (cmd->getFlags() & kATACmdFlagTimingChanged) != 0 )
    {
        currentDevice->getTimingSelected( &timingProtocol );
        selectTiming( currentDevice->getUnit(), timingProtocol );
        newDeviceSelected( newDevice );
    } 

    bzero( &results, sizeof(ATAResults) );
    cmd->setResults( &results );

    switch ( currentProtocol )
    {
        case kATAProtocolSetRegs:
            doProtocolSetRegs( cmd );
            break;

        case kATAProtocolPIO:
            doATAProtocolPio( cmd );
            break;

        case kATAProtocolDMA:
            doATAProtocolDma( cmd );
	    break;

        case kATAProtocolDMAQueued:
            doATAProtocolDmaQueued( cmd );
	    break;

        case kATAProtocolATAPIPIO:
            doATAPIProtocolPio( cmd );
            break;

        case kATAProtocolATAPIDMA:
            doATAPIProtocolDma( cmd );
            break;

        default:
            doProtocolNotSupported( cmd );
            break;
    }
}


/*
 *
 *
 */
void IOATAStandardDriver::resetCommand( IOATAStandardCommand *cmd )
{

    resetDma();
    dmaActive = false;

    currentProtocol = kATAProtocolNone;
    currentDevice   = 0;
    doATAReset( cmd );
}

/*
 *
 *
 */
void IOATAStandardDriver::abortCommand( IOATAStandardCommand *ataCmd )
{
    resetStarted();
    doATAReset( ataCmd );
}

/*
 *
 *
 */
void IOATAStandardDriver::cancelCommand( IOATAStandardCommand *ataCmd )
{
    ATAResults			results;
    IOATAStandardCommand	*origCmd;

    origCmd = ataCmd->getOriginalCmd();
    if ( origCmd != 0 )
    {
        completeCmd( origCmd );
    }

    bzero( &results, sizeof(ATAResults) );
    ataCmd->setResults( &results );
    completeCmd( ataCmd );
}


/*
 *
 *
 */
void IOATAStandardDriver::interruptOccurred()
{
#if 0
    if ( dropInt++ > 20 )
    {
        UInt32		status;

        IOLog("IOATAStandardDriver::%s() - Dropping interrupt\n\r", __FUNCTION__ );
        status = readATAReg( kATARegStatus );
        dropInt = 0;
        return;
    }
#endif  

    if ( currentDevice == 0 )
    {
        IOLog( "IOATAStandardDriver::interruptOccurred - Spurious interrupt - ATA Status = %04lx\n\r", readATAReg( kATARegStatus ) );
        return;
    }     

    switch ( currentProtocol )
    {
        case kATAProtocolPIO:
            processATAPioInt();
            break;
    
        case kATAProtocolDMA:
            processATADmaInt();
            break;

        case kATAProtocolDMAQueued:
            processATADmaQueuedInt();
            break;

        case kATAProtocolATAPIPIO:
            processATAPIPioInt();
            break;

        case kATAProtocolATAPIDMA:
            processATAPIDmaInt();
            break;

       default:
            IOLog( "IOATAStandardDriver::interruptOccurred - Spurious interrupt - ATA Status = %04lx\n\r", readATAReg( kATARegStatus ) );
     }
}


/*
 *
 *
 */
void IOATAStandardDriver::doProtocolNotSupported( IOATAStandardCommand *cmd )
{    
    completeCmd( cmd, kATAReturnNotSupported );
}


/*
 *
 *
 */
void IOATAStandardDriver::completeCmd( IOATAStandardCommand *cmd, ATAReturnCode returnCode, UInt32 bytesTransferred )
{
    updateCmdStatus( cmd, returnCode, bytesTransferred );
    completeCmd( cmd );
}

/*
 * 
 *
 */
void IOATAStandardDriver::updateCmdStatus( IOATAStandardCommand *cmd, ATAReturnCode returnCode, UInt32 bytesTransferred )
{
    UInt32		resultmask;
    UInt32		i;
    ATAResults		result;

    bzero( &result, sizeof(result) );

    resultmask = cmd->getResultMask();

    if ( cmd->getProtocol() != kATAProtocolSetRegs )
    {
         if ( waitForStatus( 0, kATAStatusBSY, kATABusyTimeoutmS ) == false )
         {
             if ( returnCode == kATAReturnSuccess )
             {
		 kprintf("IOATAStandardDriver::updateCmdStatus is going to return kATAReturnBusyError;\n");
                 returnCode = kATAReturnBusyError;
             }
         }
    }

    for ( i=0; resultmask; i++ )
    {
        if ( resultmask & 1 )
        {
            result.ataRegs[i] = readATAReg( i );
        }
        resultmask >>= 1;
    }

    result.adapterStatus    = returnCode;
    result.bytesTransferred = bytesTransferred;
    cmd->setResults( &result );
}

/*
 *
 *
 */
void IOATAStandardDriver::completeCmd( IOATAStandardCommand *cmd )
{
    IOATAStandardDevice 	*device;
    ATAResults			ataResult;
    
    cmd->getResults( &ataResult );
    ataResult.returnCode = getIOReturnCode( ataResult.adapterStatus );
    cmd->setResults( &ataResult );

    if ( getCommandCount() == 1 )
    {
        currentProtocol = kATAProtocolNone;

        device = selectDevice();
        if ( device != 0 )
        {
            resumeDevice( device );
        }
    }

    cmd->complete();
}

/*
 *
 *
 */
IOReturn IOATAStandardDriver::getIOReturnCode( ATAReturnCode code )
{
    switch (code) 
    {
        case kATAReturnSuccess:
	    return kIOReturnSuccess;

        case kATAReturnNotSupported:
            return kIOReturnUnsupported;

        case kATAReturnNoResource:
            return kIOReturnNoResources;

        case kATAReturnBusyError:
            return kIOReturnBusy;

        case kATAReturnInterruptTimeout:
            return kIOReturnTimeout;

        case kATAReturnRetryPIO:
        case kATAReturnStatusError:
        case kATAReturnProtocolError:
        default:
            ;
    }
    return kIOReturnIOError;
}

/*
 *
 *
 */
void IOATAStandardDriver::newDeviceSelected( IOATAStandardDevice * )
{
}


/*
 *
 *
 */
bool IOATAStandardDriver::programDma( IOATAStandardCommand * )
{
    IOLog( "IOATAStandardDriver::%s - Subclass must implement\n\r", __FUNCTION__ );
    return false;
}


/*
 *
 *
 */
bool IOATAStandardDriver::startDma( IOATAStandardCommand * )
{
    IOLog( "IOATAStandardDriver::%s - Subclass must implement\n\r", __FUNCTION__ );
    return false;
}


/*
 *
 *
 */
bool IOATAStandardDriver::stopDma( IOATAStandardCommand *, UInt32 * )
{
    IOLog( "IOATAStandardDriver::%s - Subclass must implement\n\r", __FUNCTION__ );
    return false;
}

/*
 *
 *
 */
bool IOATAStandardDriver::checkDmaActive()
{
    IOLog( "IOATAStandardDriver::%s - Subclass must implement\n\r", __FUNCTION__ );
    return false;
}

/*
 *
 *
 */
bool IOATAStandardDriver::resetDma()
{
    return false;
}

/*
 *
 *
 */
bool IOATAStandardDriver::getProtocolsSupported( ATAProtocol *forProtocol )
{
    *(UInt32 *) forProtocol = (   kATAProtocolSetRegs
                                | kATAProtocolPIO
                                | kATAProtocolDMA
                                | kATAProtocolDMAQueued
                                | kATAProtocolATAPIPIO
                                | kATAProtocolATAPIDMA  );

    return true;
} 

/*                     
 *
 *
 */
ATAReturnCode IOATAStandardDriver::waitForDRQ( UInt32 timeoutmS )
{
    AbsoluteTime	currentTime, endTime;
    UInt32		status;
    ATAReturnCode	rc = kATAReturnBusyError;

    clock_interval_to_deadline( timeoutmS, 1000000, &endTime );
    do
    {
        status = readATAReg( kATARegStatus );
        if ( (status & kATAPIStatusBSY) == 0 )
        {
            if ( (status & kATAStatusERR) != 0 )
            {
                rc = kATAReturnStatusError;
                break;
            }
            if ( (status & kATAStatusDRQ) != 0 )
            {
                rc = kATAReturnSuccess;
                break;
            }
        }     
        clock_get_uptime( &currentTime );
    }
    while ( CMP_ABSOLUTETIME( &endTime, &currentTime ) > 0 );

    if (rc == kATAReturnBusyError)
	    kprintf("IOATAStandardDriver::waitForDRQ is going to return kATAReturnBusyError;\n");

   return rc;
}


/*                     
 *
 *
 */
bool IOATAStandardDriver::waitForStatus( UInt32 statusBitsOn, UInt32 statusBitsOff, UInt32 timeoutmS )
{
    AbsoluteTime	currentTime, endTime;
    UInt32		status;

    clock_interval_to_deadline( timeoutmS, 1000000, &endTime );
    
    do
    {
        status = readATAReg( kATARegStatus );

        if ( (status & statusBitsOn) == statusBitsOn
                             && (status & statusBitsOff) == 0 )
        {
            return true;
        }

        clock_get_uptime( &currentTime );

   } while ( CMP_ABSOLUTETIME( &endTime, &currentTime ) > 0 );

   return false;
}

/*
 *
 *
 */
bool IOATAStandardDriver::waitForAltStatus( UInt32 statusBitsOn, UInt32 statusBitsOff, UInt32 timeoutmS )
{
    AbsoluteTime	currentTime, endTime;
    UInt32		status;

    clock_interval_to_deadline( timeoutmS, 1000000, &endTime );
    
    do
    {
        status = readATAReg( kATARegAltStatus );

        if ( (status & statusBitsOn) == statusBitsOn
                             && (status & statusBitsOff) == 0 )
        {
            return true;
        }

        clock_get_uptime( &currentTime );

   } while ( CMP_ABSOLUTETIME( &endTime, &currentTime ) > 0 );

   return false;
}

/*
 *
 *
 */
bool IOATAStandardDriver::start (IOService *provider)
{
    
    PMinit();                   // initialize superclass variables
    provider->joinPMtree(this); // attach into the power management hierarchy

    #define number_of_power_states 2

    static IOPMPowerState ourPowerStates[number_of_power_states] = {
    {1,0,0,0,0,0,0,0,0,0,0,0},
    {1,IOPMDeviceUsable,IOPMPowerOn,IOPMPowerOn,0,0,0,0,0,0,0,0}
    };


    // register ourselves with ourself as policy-maker
    if (pm_vars != NULL)
        registerPowerDriver(this, ourPowerStates, number_of_power_states);


    // We are starting up, so not waking up:
    wakingUpFromSleep = false;
    
    if (!super::start (provider))
        return false;

    return true;
}

/*
 *
 *
 */

IOReturn IOATAStandardDriver::setPowerState(unsigned long powerStateOrdinal, IOService* whatDevice)
{
    // Do not do anything if the state is inavalid.
    if (powerStateOrdinal >= 2)
        return IOPMNoSuchState;

    if ( powerStateOrdinal == 0 )
    {
        kprintf("IOATAStandardDriver would be powered off here\n");
        wakingUpFromSleep = true;

        // Let's pretend we did something:
        return IOPMAckImplied;
    }
    
    if ( ( powerStateOrdinal == 1 ) && ( wakingUpFromSleep ) )
    {
        wakingUpFromSleep = false;
        disableControllerInterrupts();
        reset();
        enableControllerInterrupts();
        return IOPMAckImplied;
    }

    return IOPMCannotRaisePower;
}


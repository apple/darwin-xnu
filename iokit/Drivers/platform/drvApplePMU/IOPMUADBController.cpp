/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * 12 Nov 1998 suurballe  Created.
 */

#include <IOKit/pwr_mgt/IOPM.h>
#include <IOKit/IOSyncer.h>
#include "IOPMUADBController.h"

#define super IOADBController
OSDefineMetaClassAndStructors(IOPMUADBController, IOADBController)

// **********************************************************************************
// start
//
// **********************************************************************************
IOService * IOPMUADBController::probe( IOService * provider, SInt32 * score )
{
    if (super::probe(provider, score) == NULL)
        return NULL;

    // this adb controller must interface with the pmu, so let's check if it is of the right type:
    // so in any case if this is a powerbook G3 1998 or 1999 it has a pmu so:
    if (IODTMatchNubWithKeys(getPlatform()->getProvider(), "'AAPL,PowerBook1998'") ||
        IODTMatchNubWithKeys(getPlatform()->getProvider(), "'PowerBook1,1'"))
        return this;

    // If it is a different machine the compatible property will tell us if it is a pmu-driven
    // adb device:
    OSData *kl = OSDynamicCast(OSData, provider->getProperty("compatible"));
    if ((kl != NULL) && kl->isEqualTo("pmu", 3))
        return this;

    // In all the other cases we do not handle it:
    return NULL;
}

// **********************************************************************************
// start
//
// **********************************************************************************
bool IOPMUADBController::start ( IOService * nub )
{
    // Wait for the PMU to show up:
    PMUdriver = waitForService(serviceMatching("ApplePMU"));

    // All the commands in this file will generate an interrupt.
    // since the interrupt is the logical conclusion of those commands
    // we need a syncer to sincronize the begin/end of these functions:
    waitingForData = NULL;

    // Registers for the two interrupts that needs to handle:
    if (PMUdriver->callPlatformFunction("registerForPMUInterrupts", true, (void*) (kPMUADBint | kPMUenvironmentInt), (void*)handleADBInterrupt, (void*)this, NULL) != kIOReturnSuccess) {
#ifdef VERBOSE_LOGS_ON
        IOLog("IOPMUADBController::start registerForPMUInterrupts kPMUADBint fails\n");
#endif // VERBOSE_LOGS_ON

        return false;
    }
    
    // Creates the mutex lock to protect the clients list:
    requestMutexLock = NULL;
    requestMutexLock = IOLockAlloc();
    if (!requestMutexLock)
        return false;

    clamshellOpen = true;

    // This happens last (while the most common place is the begin) because
    // trhe superclass may need the services of the functions above.
    if( !super::start(nub))
        return false;
    
    return true;
}

// **********************************************************************************
// free
//
// **********************************************************************************
void IOPMUADBController::free ( )
{
    // Releases the mutex lock used to protect the clients lists:
    if (requestMutexLock != NULL) {
        IOLockFree (requestMutexLock);
        requestMutexLock = NULL;
    }

    // And removes the interrupt handler:
    if (PMUdriver != NULL)
        PMUdriver->callPlatformFunction("deRegisterClient", true, (void*)this, (void*)(kPMUADBint | kPMUenvironmentInt), NULL, NULL);
}

// **********************************************************************************
// localSendMiscCommand
//
// **********************************************************************************
IOReturn IOPMUADBController::localSendMiscCommand(int command, IOByteCount sLength, UInt8 *sBuffer)
{
    IOReturn returnValue = kIOReturnError;
    IOByteCount rLength = 1;
    UInt8 rBuffer;
    
    // The poupose of this method is to free us from the pain to create a parameter block each time
    // we wish to talk to the pmu:
    SendMiscCommandParameterBlock prmBlock = {command, sLength, sBuffer, &rLength, &rBuffer};

#ifdef VERBOSE_LOGS_ON
    IOLog("ApplePMUInterface::localSendMiscCommand 0x%02x %d 0x%08lx 0x%08lx 0x%08lx\n",
                  command, sLength,  sBuffer, rLength, rBuffer);
#endif
    
    if (PMUdriver != NULL) {
#ifdef VERBOSE_LOGS_ON
        IOLog("IOPMUADBController::localSendMiscCommand calling PMUdriver->callPlatformFunction\n");
#endif
        returnValue = PMUdriver->callPlatformFunction("sendMiscCommand", true, (void*)&prmBlock, NULL, NULL, NULL);   
    }

    // If we are here we do not have a dreive to talk to:
#ifdef VERBOSE_LOGS_ON
    IOLog("IOPMUADBController::localSendMiscCommand end 0x%08lx\n", returnValue);
#endif
    
    return returnValue;
}

// **********************************************************************************
// this is the interrupt handler for all ADB interrupts:
// A.W.  Added code to check for clamshell status, and block all ADB traffic except 
//       for POWER key scan code from default ADB keyboard or devices that connect
//       to that keyboard power button.
// **********************************************************************************

/* static */ void
IOPMUADBController::handleADBInterrupt(IOService *client, UInt8 interruptMask, UInt32 length, UInt8 *buffer)
{
    IOPMUADBController *myThis = OSDynamicCast(IOPMUADBController, client);

    // Check if we are the right client for this interrupt:
    if (myThis == NULL)
        return;
    
    if (interruptMask & kPMUenvironmentInt)
    {
        if (buffer) 
        {
            if (*buffer & kClamshellClosedEventMask)
                myThis->clamshellOpen = false;
            else
                myThis->clamshellOpen = true;
        }
        if ( !(interruptMask & kPMUautopoll))
        {
            return;   //Nothing left to do
        }
    }
    if ((interruptMask & kPMUautopoll) && (myThis->autopollOn))
    {
        if (myThis->clamshellOpen)
	{
            autopollHandler(client, buffer[0], length - 1, buffer + 1); // yes, call adb input handler
	}
	else if ( (buffer[0] == 0x2c) && (buffer[1] == 0x7f) && (buffer[2] == 0x7f))
	{
            autopollHandler(client, buffer[0], length - 1, buffer + 1); // POWER down
	}
	else if ( (buffer[0] == 0x2c) && (buffer[1] == 0xff) && (buffer[2] == 0xff))
	{
            autopollHandler(client, buffer[0], length - 1, buffer + 1); // POWER up
	}

    }
    else {
        if (myThis->waitingForData != NULL) {
            // Complets the adb transaction
            myThis->dataLen = length - 1;
            bcopy(buffer + 1, myThis->dataBuffer, myThis->dataLen);
            myThis->waitingForData->signal();
        }
    }
}


// **********************************************************************************
// cancelAllIO
//
// **********************************************************************************
IOReturn IOPMUADBController::cancelAllIO ( void )
{
    if (waitingForData != NULL) {
        dataLen = 0;	// read fails with error, write fails quietly
        waitingForData->signal();
    }
    return kPMUNoError;
}


// **********************************************************************************
// setAutoPollPeriod
//
// **********************************************************************************
IOReturn IOPMUADBController::setAutoPollPeriod ( int )
{
    return kPMUNotSupported;
}


// **********************************************************************************
// getAutoPollPeriod
//
// **********************************************************************************
IOReturn IOPMUADBController::getAutoPollPeriod ( int * )
{
    return kPMUNotSupported;
}


// **********************************************************************************
// setAutoPollList
//
// **********************************************************************************
IOReturn IOPMUADBController::setAutoPollList ( UInt16 PollBitField )
{
    pollList = PollBitField;				// remember the new poll list

    if ( autopollOn ) {
        UInt8 oBuffer[4];
        
        oBuffer[0] = 0;                                 // Byte count in the resto of the command
        oBuffer[1] = 0x86;                              // adb Command op.
        oBuffer[2] = (UInt8)(PollBitField >> 8);        // ??
        oBuffer[3] = (UInt8)(PollBitField & 0xff);      // ??

        localSendMiscCommand (kPMUpMgrADB, 4, oBuffer);
    }
    return kPMUNoError;
}


// **********************************************************************************
// getAutoPollList
//
// **********************************************************************************
IOReturn IOPMUADBController::getAutoPollList ( UInt16 * activeAddressMask )
{
    *activeAddressMask = pollList;
    return kPMUNoError;
}


// **********************************************************************************
// setAutoPollEnable
//
// **********************************************************************************
IOReturn IOPMUADBController::setAutoPollEnable ( bool enable )
{
    UInt8 oBuffer[4];
    
    autopollOn = enable;
    
    if ( enable ) {							// enabling autopoll
        oBuffer[0] = 0;
        oBuffer[1] = 0x86;
        oBuffer[2] = (UInt8)(pollList >> 8);
        oBuffer[3] = (UInt8)(pollList & 0xff);

        localSendMiscCommand (kPMUpMgrADB, 4, oBuffer);
    }
    else {								// disabling autopoll;
        /* Waits one second for the trackpads to be up (this is needed only in old machines)
           This is placed here because this is the fist call at wake. */
        if (IODTMatchNubWithKeys(getPlatform()->getProvider(), "'PowerBook1,1'") ||
            IODTMatchNubWithKeys(getPlatform()->getProvider(), "'AAPL,PowerBook1998'"))
            IOSleep(1500);

        localSendMiscCommand (kPMUpMgrADBoff, 0, NULL);
    }

    return kPMUNoError;
}


// **********************************************************************************
// resetBus
//
// **********************************************************************************
IOReturn IOPMUADBController::resetBus ( void )
{
    if (requestMutexLock != NULL)
        IOLockLock(requestMutexLock);

    UInt8 oBuffer[4];
        
    oBuffer[0] = kPMUResetADBBus;
    oBuffer[1] = 0;
    oBuffer[2] = 0;

    // Reset bus needs to wait for the interrupt to terminate the transaction:
    waitingForData = IOSyncer::create();
    localSendMiscCommand (kPMUpMgrADB, 3, oBuffer);
    waitingForData->wait();			// wait till done
    waitingForData = 0;

    if (requestMutexLock != NULL)
        IOLockUnlock(requestMutexLock);

    /* Waits one second for the trackpads to be up (this is needed only in old machines) */
    if (IODTMatchNubWithKeys(getPlatform()->getProvider(), "'PowerBook1,1'") ||
        IODTMatchNubWithKeys(getPlatform()->getProvider(), "'AAPL,PowerBook1998'"))
        IOSleep(1500);

    return kPMUNoError;
}


// **********************************************************************************
// flushDevice
//
// **********************************************************************************
IOReturn IOPMUADBController::flushDevice ( IOADBAddress address )
{
    if (requestMutexLock != NULL)
        IOLockLock(requestMutexLock);

    UInt8 oBuffer[4];

    oBuffer[0] = kPMUFlushADB | (address << kPMUADBAddressField);
    oBuffer[1] = ( autopollOn ? 2 : 0 );
    oBuffer[2] = 0;

    // flush device needs to wait for the interrupt to terminate the transaction
    waitingForData = IOSyncer::create();
    localSendMiscCommand (kPMUpMgrADB, 3, oBuffer);
    waitingForData->wait();			// wait till done
    waitingForData = 0;

    if (requestMutexLock != NULL)
        IOLockUnlock(requestMutexLock);
            
    return kPMUNoError;
}


// **********************************************************************************
// readFromDevice
//
// The length parameter is ignored on entry.  It is set on exit to reflect
// the number of bytes read from the device.
// **********************************************************************************
IOReturn IOPMUADBController::readFromDevice ( IOADBAddress address, IOADBRegister adbRegister,
                                              UInt8 * data, IOByteCount * length )
{
    if ( (length == NULL) || (data == NULL) ) {
        return kPMUParameterError;
    }

    if (requestMutexLock != NULL)
        IOLockLock(requestMutexLock);

    UInt8 oBuffer[4];

    oBuffer[0] = kPMUReadADB | (address << kPMUADBAddressField) | (adbRegister);
    oBuffer[1] = ( autopollOn ? 2 : 0 );
    oBuffer[2] = 0;

    // read from device needs to wait for the interrupt to terminate the transaction
    // and to obtain the data from the device.
    waitingForData = IOSyncer::create();
    localSendMiscCommand (kPMUpMgrADB, 3, oBuffer);
    waitingForData->wait();			// wait till done
    waitingForData = 0;

    // set caller's length
    *length = (dataLen < *length ? dataLen : *length);
    bcopy(dataBuffer, data, *length);

    if (requestMutexLock != NULL)
        IOLockUnlock(requestMutexLock);
    
    if (dataLen == 0 ) {				// nothing read; device isn't there
        return ADB_RET_NOTPRESENT;
    }
    
    return ADB_RET_OK;
}


// **********************************************************************************
// writeToDevice
//
// **********************************************************************************
IOReturn IOPMUADBController::writeToDevice ( IOADBAddress address, IOADBRegister adbRegister,
                                             UInt8 * data, IOByteCount * length )
{
    // Last check on * length > (252): since the pmu registers are 8 bit
    // and the buffer has the first 3 bytes used for the standard paramters
    // the max lenght can not be more than 252 bytes.
    if ( (* length == 0) || (data == NULL) || (* length > 252) )
    {
        return kPMUParameterError;
    }

    if (address == 0)
        return kPMUNoError; // for now let's ignore these ...

    if (requestMutexLock != NULL)
        IOLockLock(requestMutexLock);

    UInt8 oBuffer[256];

    oBuffer[0] = kPMUWriteADB | (address << kPMUADBAddressField) | (adbRegister);
    oBuffer[1] = ( autopollOn ? 2 : 0 );
    oBuffer[2] = *length;
    bcopy(data, &oBuffer[3], *length);

    // write to the device needs to wait for the interrupt to terminate the transaction
    waitingForData = IOSyncer::create();
    localSendMiscCommand (kPMUpMgrADB, 3 + *length, oBuffer);
    waitingForData->wait();
    waitingForData = 0;

    if (requestMutexLock != NULL)
        IOLockUnlock(requestMutexLock);
    
    return kPMUNoError;
}



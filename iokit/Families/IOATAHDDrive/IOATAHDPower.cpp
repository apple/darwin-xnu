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
 * IOATAHDPower.cpp - Power management support.
 *
 * HISTORY
 *
 */

#include <IOKit/storage/ata/IOATAHDDrive.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#define	super IOService

//---------------------------------------------------------------------------
// Inform the policy-maker that an ATA hard-drive is capable of two power
// states (a simplification). The ourPowerStates[] array encodes information
// about each state.

#define kIOATAPowerStates 2

static IOPMPowerState ourPowerStates[kIOATAPowerStates] =
{
    {1,0,0,0,0,0,0,0,0,0,0,0},
    {1, IOPMDeviceUsable, IOPMPowerOn, IOPMPowerOn, 0,0,0,0,0,0,0,0}
};

static const char * ataPowerStateNames[] =
{
    "Sleep",
    "Standby",
    "Idle",
    "Active"
};

//---------------------------------------------------------------------------
// Maps the power state ordinal, used by our policy maker,
// to an ATA power states.

IOATAPowerState
IOATAHDDrive::getATAPowerStateForStateOrdinal(UInt32 stateOrdinal)
{
    IOATAPowerState stateOrdinalToATAPowerState[kIOATAPowerStates] =
    {
        kIOATAPowerStateStandby,   /* state 0 */
        kIOATAPowerStateActive,    /* state 1 */
    };

    if (stateOrdinal > (kIOATAPowerStates - 1))
        stateOrdinal = (kIOATAPowerStates - 1);
    
    return stateOrdinalToATAPowerState[stateOrdinal];
}

//---------------------------------------------------------------------------
// Register the driver with our policy-maker (also in the same class).

void
IOATAHDDrive::initForPM()
{
    registerPowerDriver(this, ourPowerStates, kIOATAPowerStates);
    _pmReady = true;
}

//---------------------------------------------------------------------------
// Policy-maker code which intercepts kPMMinutesToSpinDown settings
// and then call setIdleTimerPeriod() to adjust the idle timer.

IOReturn
IOATAHDDrive::setAggressiveness(UInt32 type, UInt32 minutes)
{
    if (type == kPMMinutesToSpinDown)
    {
        // IOLog("IOATAHDDrive: setting idle timer to %ld min\n", minutes);
        setIdleTimerPeriod(minutes * 60);   // argument is in seconds
    }
    return super::setAggressiveness(type, minutes);
}

//---------------------------------------------------------------------------
// Policy-maker calls this function to find find out what power state
// the device is in, given the current power domain state.
//
// We respond to this message in the following fashion:
//   If domain power is off, drive must be off.
//   If domain power is on,  return _currentATAPowerState.

UInt32
IOATAHDDrive::initialPowerStateForDomainState(IOPMPowerFlags domainState)
{
    UInt32 ret;

    _cmdGate->runAction((IOCommandGate::Action)
                        &IOATAHDDrive::sHandleInitialPowerStateForDomainState,
                        (void *) domainState,
                        (void *) &ret);

    return ret;
}

//---------------------------------------------------------------------------
// Static member function called by the IOCommandGate to translate
// initialPowerStateForDomainState() calls to the synchronized
// handleInitialPowerStateForDomainState() call.

void
IOATAHDDrive::sHandleInitialPowerStateForDomainState(IOATAHDDrive * self,
                                                     IOPMPowerFlags domainState,
                                                     UInt32 *       state)
{
    *state = self->handleInitialPowerStateForDomainState(domainState);
}

//---------------------------------------------------------------------------
// The synchronized form of initialPowerStateForDomainState().

UInt32
IOATAHDDrive::handleInitialPowerStateForDomainState(IOPMPowerFlags domainState)
{
   if (domainState & IOPMPowerOn)
       return ((_currentATAPowerState == kIOATAPowerStateActive) ? 1 : 0);
   else
       return 0;
}

//---------------------------------------------------------------------------
// Set/Change the power state of the ATA hard-drive.

IOReturn
IOATAHDDrive::setPowerState(UInt32      powerStateOrdinal,
						    IOService * whatDevice)
{
    IOReturn ret;

    // Power state transitions are synchronized by our IOCommandGate object,
    // (attached to the ATA controller's workloop).
    
    _cmdGate->runAction((IOCommandGate::Action)
                            &IOATAHDDrive::sHandleSetPowerState,
                        (void *) powerStateOrdinal,
                        (void *) whatDevice,
                        (void *) &ret);

    kprintf("%s::%s(0x%08lx, 0x%08lx) returns 0x%08lx\n",getName(), __FUNCTION__,powerStateOrdinal, whatDevice, ret);
    return ret;
}

//---------------------------------------------------------------------------
// Static member function called by the IOCommandGate to translate
// setPowerState() calls to the synchronized handleSetPowerState() call.

void
IOATAHDDrive::sHandleSetPowerState(IOATAHDDrive * self,
                                   UInt32         powerStateOrdinal,
                                   IOService *    whatDevice,
                                   IOReturn *     handlerReturn)
{
    *handlerReturn = self->handleSetPowerState(powerStateOrdinal, whatDevice);
}

//---------------------------------------------------------------------------
// A static member function that calls handleStandbyStateTransition().
// This function can be registered as the completion handler for an
// IOATACommand.

void
IOATAHDDrive::sHandleStandbyStateTransition(IOATAHDDrive * self,
                                            void *         stage,
                                            IOReturn       status,
                                            UInt64         bytesTransferred)
{
    self->handleStandbyStateTransition((UInt32) stage, status);
}

//---------------------------------------------------------------------------
// A static member function that calls handleActiveStateTransition().
// This function can be registered as the completion handler for an
// IOATACommand.

void
IOATAHDDrive::sHandleActiveStateTransition(IOATAHDDrive * self,
                                           void *         stage,
                                           IOReturn       status,
                                           UInt64         bytesTransferred)
{
    self->handleActiveStateTransition((UInt32) stage, status);
}

//---------------------------------------------------------------------------
// A static member function that calls handleIdleStateTransition().
// This function can be registered as the completion handler for an
// IOATACommand.

void
IOATAHDDrive::sHandleIdleStateTransition(IOATAHDDrive * self,
                                         void *         stage,
                                         IOReturn       status,
                                         UInt64         bytesTransferred)
{
    self->handleIdleStateTransition((UInt32) stage, status);
}

//---------------------------------------------------------------------------
// A static member function that calls handleSleepStateTransition().
// This function can be registered as the completion handler for an
// IOATACommand.

void
IOATAHDDrive::sHandleSleepStateTransition(IOATAHDDrive * self,
                                          void *         stage,
                                          IOReturn       status,
                                          UInt64         bytesTransferred)
{
    self->handleSleepStateTransition((UInt32) stage, status);
}

//---------------------------------------------------------------------------
// IOATAHDDrive provide a default implementation for handleSetPowerState().
// This (IOCommandGate synchronized) function is called by our policy-maker.

IOReturn
IOATAHDDrive::handleSetPowerState(UInt32      powerStateOrdinal,
                                  IOService * whatDevice)
{
    IOATAPowerState ataPowerState =
                    getATAPowerStateForStateOrdinal(powerStateOrdinal);

#if 1
    kprintf("%s::%s %d (%d) %lx\n", getName(), __FUNCTION__, ataPowerState,
            _currentATAPowerState, (UInt32) whatDevice);
#endif

    // We cannot change power state while we are still transitioning
    // the power state from a previous state change request.

    if (_powerStateChanging) {
        kprintf("%s::%s overlap detected\n",getName(), __FUNCTION__);
        IOLog("%s::%s overlap detected\n",getName(), __FUNCTION__);
        return IOPMAckImplied;  // FIXME - should return something else
    }

    // If we are already in the desired power state, return success.

    if (ataPowerState == _currentATAPowerState) {
        kprintf("%s::%s already in the given sate\n",getName(), __FUNCTION__);
        return IOPMAckImplied;   
    }

    _powerStateChanging = true;
    _setPowerAckPending = true;

    startATAPowerStateTransition(ataPowerState);

    // Return the number of microseconds it may take for the drive to
    // complete the power state transition. Report 100 seconds max.

    return (100 * 1000 * 1000);
}

//---------------------------------------------------------------------------
// Start transitioning into the specified ATA power state.

void
IOATAHDDrive::startATAPowerStateTransition(IOATAPowerState ataPowerState)
{
    _proposedATAPowerState = ataPowerState;

    switch (ataPowerState)
    {
        case kIOATAPowerStateStandby:

            // Register sHandleStandbyStateTransition to be called when the
            // IOATADevice becomes idle. Or, if the device is already idle,
            // the function will be called immediately.
            
            _ataDevice->notifyIdle(this,
                      (CallbackFn) &IOATAHDDrive::sHandleStandbyStateTransition,
                      (void *) kIOATAStandbyStage0);
            break;

        case kIOATAPowerStateActive:

            // Call sHandleActiveStateTransition and begin processing
            // at stage 0.

            sHandleActiveStateTransition(this,
                                         (void *) kIOATAActiveStage0,
                                         kIOReturnSuccess,
                                         0);
            break;

        default:
            IOPanic("IOATAHDDrive::startATAPowerStateTransition\n");
    }
}

//---------------------------------------------------------------------------
// Abort the current state transition and retore the current state.

void
IOATAHDDrive::abortATAPowerStateTransition()
{
    // Do not ack the setPowerState request if the power state
    // transition is aborted.

    _setPowerAckPending = false;

    // Transition to the previous state. However, if we are unable
    // to transition to the previous state, then give up.
    
    if (_proposedATAPowerState != _currentATAPowerState)
    {
        startATAPowerStateTransition(_currentATAPowerState);
    }
    else
    {
        IOLog("%s::%s Unable to revert to previous state\n",
              getName(), __FUNCTION__);

        endATAPowerStateTransition(_currentATAPowerState);
    }
}

//---------------------------------------------------------------------------
// Complete the ATA power state transition.

void
IOATAHDDrive::endATAPowerStateTransition(IOATAPowerState ataPowerState)
{
    _currentATAPowerState = ataPowerState;

    // In the future, a NACK response may be sent to indicate state change
    // failure.

    if (_setPowerAckPending) {
        thread_call_func(acknowledgeATAPowerStateTransition, this, 1);
        //acknowledgeATAPowerStateTransition(this, NULL);
    }

    //kprintf("%s::%s %s \n", getName(), __FUNCTION__, ataPowerStateNames[_currentATAPowerState]);
}

//---------------------------------------------------------------------------
// To avoid deadlocks between the PM and the IOATAHDDrive workloop the
// actual acknolegment wuns on a different thread.

/* static */ void
IOATAHDDrive::acknowledgeATAPowerStateTransition(void *castMeToIOATAHDDrive, void*)
{
    IOATAHDDrive *myThis = OSDynamicCast(IOATAHDDrive, (OSObject*)castMeToIOATAHDDrive);

    if (myThis !=NULL) {
        myThis->_powerStateChanging = false;
        myThis->acknowledgeSetPowerState();
    }
}
        
//---------------------------------------------------------------------------
// A function called by startATAPowerStateTransition() to transition the
// drive into the STANDBY state. It may also be called by the IOATACommand 
// completion handler to advance to the next stage of the state transition.
//
// stage:  The current stage in the state transition.
// status: The status from the previous stage.

void
IOATAHDDrive::handleStandbyStateTransition(UInt32 stage, IOReturn status)
{
    bool                doAbort = false;
    IOATACommand *      cmd     = 0;
    IOStorageCompletion completion;

//  IOLog("IOATAHDDrive::handleStandbyStateTransition %ld %x\n", stage, status);

    switch (stage)
    {
        case kIOATAStandbyStage0:
            // Device is idle. Hold the normal queue.
            _ataDevice->holdQueue(kATAQTypeNormalQ);
            status = kIOReturnSuccess;

        case kIOATAStandbyStage1:

            if ( reportATADeviceType() == kATADeviceATA )
            {
                // Issue a flush cache command.

                if ((cmd = ataCommandFlushCache()) == 0)
                {
                    doAbort = true; break;
                }
                cmd->setQueueInfo(kATAQTypeBypassQ);

                // Must issue an async command here, otherwise the thread will
                // deadlock.

                completion.target    = this;
                completion.action    = sHandleStandbyStateTransition;
                completion.parameter = (void *) kIOATAStandbyStage2;

                asyncExecute(cmd,
                            completion,
                            60000,   /* 1 min timeout */
                            0);      /* no retry for flush cache command */
                break;
            }
                         
        case kIOATAStandbyStage2:

            if ( reportATADeviceType() == kATADeviceATA )
            {
                // Issue an ATA STANDBY IMMEDIATE command. We ignore the
                // status from the flush cache command since not all drives
                // implement this.

                if ((cmd = ataCommandStandby()) == 0)
                {
                    doAbort = true; break;
                }
                cmd->setQueueInfo(kATAQTypeBypassQ);

                // Must issue an async command here, otherwise the thread will
                // deadlock.

                completion.target    = this;
                completion.action    = sHandleStandbyStateTransition;
                completion.parameter = (void *) kIOATAStandbyStage3;

                asyncExecute(cmd,
                            completion,
                            30000,   /* 30 sec timeout */
                            0);      /* no retry for STANDBY command */
                break;
            }

        case kIOATAStandbyStage3:
            // Final stage in the STANDBY state transition.

            if (status != kIOReturnSuccess) {
                // STANDBY command failed, abort the state transition.
                doAbort = true; break;
            }
            else {
                endATAPowerStateTransition(kIOATAPowerStateStandby);
            }

            break;

        default:
            IOLog("%s::%s unknown stage %ld\n", getName(), __FUNCTION__, stage);
    }

    if (cmd) cmd->release();

    if (doAbort)
        abortATAPowerStateTransition();
}

//---------------------------------------------------------------------------
// Called by startATAPowerStateTransition() to transition the drive into
// the ACTIVE state. It may also be called by the IOATACommand completion 
// handler to advance to the next stage of the state transition.
//
// stage:  The current stage in the state transition.
// status: The status from the previous stage.

void
IOATAHDDrive::handleActiveStateTransition(UInt32 stage, IOReturn status)
{
    IOStorageCompletion completion;

#if 0
    IOLog("IOATAHDDrive::handleActiveStateTransition %p %ld %x\n",
          this, stage, status);
#endif

    switch (stage)
    {
        case kIOATAActiveStage0:
        kprintf("kIOATAActiveStage0 current power state is sleep %d\n", _currentATAPowerState == kIOATAPowerStateSleep);

#if 0 // This des not work.
            // Issue a software reset. Only necessary if the current
            // state is kATAPowerStateSleep.

            // if (_currentATAPowerState == kIOATAPowerStateSleep) // Marco: Commenting because it looks that the power state is wrong
            {
                kprintf("Attempting to reset on kIOATAActiveStage0\n");
                _ataDevice->reset();
            }
#endif

        case kIOATAActiveStage1:
        kprintf("kIOATAActiveStage1\n");

            if ( reportATADeviceType() == kATADeviceATA )
            {
                // Spin up the drive before releasing the queue. A media
                // access command is issued with an extra long timeout.

                completion.target    = this;
                completion.action    = sHandleActiveStateTransition,
                completion.parameter = (void *) kIOATAActiveStage2;

                readSector(completion);
                break;
            }
            
        case kIOATAActiveStage2:
        kprintf("kIOATAActiveStage2\n");
            // Release the normal queue.
            _ataDevice->releaseQueue(kATAQTypeNormalQ);

        case kIOATAActiveStage3:
        kprintf("kIOATAActiveStage3\n");
            // Finalize ACTIVE state transition.
            endATAPowerStateTransition(kIOATAPowerStateActive);
            break;

        default:
            IOLog("%s::%s unknown stage %ld\n", getName(), __FUNCTION__, stage);
    }
}

//---------------------------------------------------------------------------
// Unimplemented state transition handlers.

void
IOATAHDDrive::handleIdleStateTransition(UInt32 stage, IOReturn status)
{
    IOLog("%s::%s unimplemented!\n", getName(), __FUNCTION__);
}

void
IOATAHDDrive::handleSleepStateTransition(UInt32 stage, IOReturn status)
{
    IOLog("%s::%s unimplemented!\n", getName(), __FUNCTION__);
}

//---------------------------------------------------------------------------
// Read a single sector from the disk. The data read is discarded.

IOReturn IOATAHDDrive::readSector(IOStorageCompletion completion,
                                  UInt32              sector = 0)
{
    IOBufferMemoryDescriptor * desc;
	IOATACommand *             cmd;
    IOReturn                   ret;

    desc = IOBufferMemoryDescriptor::withCapacity(kIOATASectorSize,
                                                  kIODirectionIn);
    if (!desc)
        return kIOReturnNoMemory;

    desc->setLength(desc->getCapacity());
    
    cmd = ataCommandReadWrite(desc, sector, 1);
    if (!cmd)
        return kIOReturnNoMemory;

    cmd->setQueueInfo(kATAQTypeBypassQ);

    ret = asyncExecute(cmd, completion, 60000);

    // Don't worry, asyncExecute has retained both the command
    // and the memory descriptor object.

    desc->release();
    cmd->release();

    return kIOReturnSuccess;
}

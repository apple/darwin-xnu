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
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOCommandQueue.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include <IOKit/pwr_mgt/IOPM.h>
#include <IOKit/IOMessage.h>
#include "RootDomainUserClient.h"

extern "C" {
extern void kprintf(const char *, ...);
}

extern const IORegistryPlane * gIOPowerPlane;

void PMreceiveCmd ( OSObject *,  void *, void *, void *, void * );
bool rootHasPMU( OSObject * us, void *, IOService * yourDevice );


#define number_of_power_states 3
#define OFF_STATE 0
#define SLEEP_STATE 1
#define ON_STATE 2

#define ON_POWER IOPMPowerOn
#define SLEEP_POWER IOPMAuxPowerOn

static IOPMPowerState ourPowerStates[number_of_power_states] = {
    {1,0,0,0,0,0,0,0,0,0,0,0},
    {1,0,0,SLEEP_POWER,0,0,0,0,0,0,0,0},
    {1,IOPMPowerOn,IOPMPowerOn,ON_POWER,0,0,0,0,0,0,0,0},
};

static IOPMrootDomain * gRootDomain;

#define super IOService
OSDefineMetaClassAndStructors(IOPMrootDomain,IOService)

extern "C"
{
    IONotifier * registerSleepWakeInterest(IOServiceInterestHandler handler, void * self, void * ref = 0)
    {
        return gRootDomain->registerInterest( gIOGeneralInterest, handler, self, ref );
    }

    IOReturn acknowledgeSleepWakeNotification(void * PMrefcon)
    {
        return gRootDomain->allowPowerChange ( (unsigned long)PMrefcon );
    }

}


// **********************************************************************************
// start
//
// We don't do much here.  The real initialization occurs when the platform
// expert informs us we are the root.
// **********************************************************************************
bool IOPMrootDomain::start ( IOService * nub )
{
    super::start(nub);

    gRootDomain = this;

    PMinit();
    allowSleep = true;
    sleepIsSupported = false;
    idlePeriod = 0;
    systemBooting = true;
//    systemBooting = false;	// temporary work-around for 2589847
    ignoringClamshell = false;

    pm_vars->PMworkloop = IOWorkLoop::workLoop();				// make the workloop
    pm_vars->commandQueue = IOCommandQueue::commandQueue(this, PMreceiveCmd);	// make a command queue
    if (! pm_vars->commandQueue ||
        (  pm_vars->PMworkloop->addEventSource( pm_vars->commandQueue) != kIOReturnSuccess) ) {
        return IOPMNoErr;
    }

    patriarch = new IORootParent;                               // create our parent
    patriarch->init();
    patriarch->attach(this);
    patriarch->start(this);
    patriarch->youAreRoot();
    patriarch->wakeSystem();
    patriarch->addPowerChild(this);
    
    registerPowerDriver(this,ourPowerStates,number_of_power_states);

    // Clamp power on.  We will revisit this decision when the login window is displayed
    // and we receive preferences via SetAggressiveness.
    changePowerStateToPriv(ON_STATE);           		// clamp power on
    powerOverrideOnPriv();

    registerService();						// let clients find us

    return true;
}


//*********************************************************************************
// youAreRoot
//
// Power Managment is informing us that we are the root power domain.
// We know we are not the root however, since we have just instantiated a parent
// for ourselves and made it the root.  We override this method so it will have
// no effect
//*********************************************************************************
IOReturn IOPMrootDomain::youAreRoot ( void )
{
    return IOPMNoErr;
}


// **********************************************************************************
// command_received
//
// We have received a command from ourselves on the command queue.
// If it is to send a recently-received aggressiveness factor, do so.
// Otherwise, it's something the superclass enqueued.
// **********************************************************************************
void IOPMrootDomain::command_received ( void * command, void * x, void * y, void * z )
{
    switch ( (int)command ) {
        case kPMbroadcastAggressiveness:
            if ( (int)x == kPMMinutesToSleep ) {
                idlePeriod = (int)y*60;
                if ( allowSleep && sleepIsSupported ) {
                    setIdleTimerPeriod(idlePeriod);		// set new timeout
                }
            }
            break;
        default:
            super::command_received(command,x,y,z);
            break;
    }
}


//*********************************************************************************
// setAggressiveness
//
// Some aggressiveness factor has changed.  We put this change on our
// command queue so that we can broadcast it to the hierarchy while on
// the Power Mangement workloop thread.  This enables objects in the
// hierarchy to successfully alter their idle timers, which are all on the
// same thread.
//*********************************************************************************

IOReturn IOPMrootDomain::setAggressiveness ( unsigned long type, unsigned long newLevel )
{
    systemBooting = false;  // when the finder launches, this method gets called -- system booting is done.

    pm_vars->commandQueue->enqueueCommand(true, (void *)kPMbroadcastAggressiveness, (void *) type, (void *) newLevel );
    super::setAggressiveness(type,newLevel);
    
    return kIOReturnSuccess;
}


// **********************************************************************************
// sleepSystem
//
// **********************************************************************************
IOReturn IOPMrootDomain::sleepSystem ( void )
{
    kprintf("sleep demand received\n");
    if ( !systemBooting && allowSleep && sleepIsSupported ) {
        patriarch->sleepSystem();
    }
    return kIOReturnSuccess;
}


// **********************************************************************************
// powerChangeDone
//
// This overrides powerChangeDone in IOService.
// If we just finished switching to state zero, call the platform expert to
// sleep the kernel.
// Then later, when we awake, the kernel returns here and we wake the system.
// **********************************************************************************
void IOPMrootDomain::powerChangeDone ( unsigned long powerStateOrdinal )
{
    if ( powerStateOrdinal == SLEEP_STATE ) {
        pm_vars->thePlatform->sleepKernel();
    	activityTickle(kIOPMSubclassPolicy);	// reset idle sleep
        systemWake();				// tell the tree we're waking 
        patriarch->wakeSystem();		// make sure we have power
        changePowerStateToPriv(ON_STATE);	// and wake
    }
}


// **********************************************************************************
// newUserClient
//
// **********************************************************************************
IOReturn IOPMrootDomain::newUserClient(  task_t owningTask,  void * /* security_id */, UInt32 type, IOUserClient ** handler )
{
    IOReturn		err = kIOReturnSuccess;
    RootDomainUserClient *	client;

    client = RootDomainUserClient::withTask(owningTask);

    if( !client || (false == client->attach( this )) ||
        (false == client->start( this )) ) {
        if(client) {
            client->detach( this );
            client->release();
            client = NULL;
        }
        err = kIOReturnNoMemory;
    }
    *handler = client;	
    return err;
}

//*********************************************************************************
// receivePowerNotification
//
// The power controller is notifying us of a hardware-related power management
// event that we must handle. This is a result of an 'environment' interrupt from
// the power mgt micro.
//*********************************************************************************

IOReturn IOPMrootDomain::receivePowerNotification (UInt32 msg)
{
    if (msg & kIOPMSleepNow) {
      (void) sleepSystem ();
    }
    
    if (msg & kIOPMPowerButton) {
      (void) sleepSystem ();
    }

    if (msg & kIOPMPowerEmergency) {
      (void) sleepSystem ();
    }

    if (msg & kIOPMClamshellClosed) {
        if ( ! ignoringClamshell ) {
            (void) sleepSystem ();
        }
    }

    if (msg & kIOPMIgnoreClamshell) {
        ignoringClamshell = true;
    }

    if (msg & kIOPMAllowSleep) {
        if ( sleepIsSupported ) {
            setIdleTimerPeriod(idlePeriod);
        }
	allowSleep = true;
	changePowerStateTo (0);
    }

    // if the case is open on some machines, we must now
    // allow the machine to be put to sleep or to idle sleep

    if (msg & kIOPMPreventSleep) {
        if ( sleepIsSupported ) {
            setIdleTimerPeriod(0);
        }
	allowSleep = false;
	changePowerStateTo (number_of_power_states-1);
    }

   return 0;
}


//*********************************************************************************
// sleepSupported
//
//*********************************************************************************

void IOPMrootDomain::setSleepSupported( IOOptionBits flags )
{
    platformSleepSupport = flags;
    if ( flags & kRootDomainSleepSupported ) {
        sleepIsSupported = true;
        setProperty("IOSleepSupported","");
    }
    else
    {
        sleepIsSupported = false;
        removeProperty("IOSleepSupported");
    }

}

//*********************************************************************************
// getSleepSupported
//
//*********************************************************************************

IOOptionBits IOPMrootDomain::getSleepSupported( void )
{
    return( platformSleepSupport );
}


//*********************************************************************************
// tellChangeDown
//
// We override the superclass implementation so we can send a different message
// type to the client or application being notified.
//*********************************************************************************

bool IOPMrootDomain::tellChangeDown ( unsigned long stateNum )
{
    if ( stateNum == SLEEP_STATE ) {
        return super::tellClientsWithResponse(kIOMessageSystemWillSleep);
    }
    return super::tellChangeDown(stateNum);
}


//*********************************************************************************
// askChangeDown
//
// We override the superclass implementation so we can send a different message
// type to the client or application being notified.
//*********************************************************************************

bool IOPMrootDomain::askChangeDown (unsigned long stateNum)
{
    if ( stateNum == SLEEP_STATE ) {
        return super::tellClientsWithResponse(kIOMessageCanSystemSleep);
    }
    return super::askChangeDown(stateNum);
}


//*********************************************************************************
// tellNoChangeDown
//
// Notify registered applications and kernel clients that we are not
// dropping power.
//
// We override the superclass implementation so we can send a different message
// type to the client or application being notified.
//*********************************************************************************

void IOPMrootDomain::tellNoChangeDown ( unsigned long )
{
    return tellClients(kIOMessageSystemWillNotSleep);
}


//*********************************************************************************
// tellChangeUp
//
// Notify registered applications and kernel clients that we are raising power.
//
// We override the superclass implementation so we can send a different message
// type to the client or application being notified.
//*********************************************************************************

void IOPMrootDomain::tellChangeUp ( unsigned long )
{
    return tellClients(kIOMessageSystemHasPoweredOn);
}


// **********************************************************************************
// activityTickle
//
// This is called by the HID system and calls the superclass in turn.
// **********************************************************************************

bool IOPMrootDomain::activityTickle ( unsigned long, unsigned long x=0 )
{
    return super::activityTickle (kIOPMSuperclassPolicy1,ON_STATE);
}




/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOService

OSDefineMetaClassAndStructors(IORootParent, IOService)

#define number_of_patriarch_power_states 3

static IOPMPowerState patriarchPowerStates[number_of_patriarch_power_states] = {
    {1,0,0,0,0,0,0,0,0,0,0,0},                                          // off
    {1,0,SLEEP_POWER,0,0,0,0,0,0,0,0,0},                                // sleep
    {1,0,ON_POWER,0,0,0,0,0,0,0,0,0}                                    // running
};

#define PATRIARCH_OFF   0
#define PATRIARCH_SLEEP 1
#define PATRIARCH_ON    2


bool IORootParent::start ( IOService * nub )
{
    super::start(nub);
    PMinit();
    registerPowerDriver(this,patriarchPowerStates,number_of_patriarch_power_states);
    powerOverrideOnPriv();
    return true;
}


void IORootParent::shutDownSystem ( void )
{
    changePowerStateToPriv(PATRIARCH_OFF);
}


void IORootParent::sleepSystem ( void )
{
    changePowerStateToPriv(PATRIARCH_SLEEP);
}


void IORootParent::wakeSystem ( void )
{
    changePowerStateToPriv(PATRIARCH_ON);
}


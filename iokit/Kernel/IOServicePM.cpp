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
 
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOCommandQueue.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/assert.h>
#include <IOKit/IOMessage.h>
#include <IOKit/pwr_mgt/IOPMinformee.h>
#include "IOKit/pwr_mgt/IOPMinformeeList.h"
#include "IOKit/pwr_mgt/IOPMchangeNoteList.h"
#include "IOKit/pwr_mgt/IOPMlog.h"
#include "IOKit/pwr_mgt/IOPowerConnection.h"
#include <kern/clock.h>

static void ack_timer_expired(thread_call_param_t);
static void settle_timer_expired(thread_call_param_t);
void PMreceiveCmd ( OSObject *,  void *, void *, void *, void * );
static void PM_idle_timer_expired(OSObject *, IOTimerEventSource *);
static void c_PM_Clamp_Timer_Expired (OSObject * client,IOTimerEventSource *);
void tellAppWithResponse ( OSObject * object, void * context);
void tellClientWithResponse ( OSObject * object, void * context);
void tellClient ( OSObject * object, void * context);
IOReturn serializedAllowPowerChange ( OSObject *, void *, void *, void *, void *);
IOReturn serializedCancelPowerChange ( OSObject *, void *, void *, void *, void *);

extern const IORegistryPlane * gIOPowerPlane;


// and there's 1000 nanoseconds in a microsecond:
#define ns_per_us 1000


// The current change note is processed by a state machine.
// Inputs are acks from interested parties, ack from the controlling driver,
// ack timeouts, settle timeout, and powerStateDidChange from the parent.
// These are the states:

enum {
    IOPMour_prechange_03 = 1,
    IOPMour_prechange_05,
    IOPMour_prechange_1,
    IOPMour_prechange_2,
    IOPMour_prechange_3,
    IOPMour_prechange_4,
    IOPMparent_down_0,
    IOPMparent_down_2,
    IOPMparent_down_3,
    IOPMparent_down_4,
    IOPMparent_down_5,
    IOPMparent_down_6,
    IOPMparent_up_0,
    IOPMparent_up_1,
    IOPMparent_up_4,
    IOPMparent_up_5,
    IOPMparent_up_6,
    IOPMfinished
    };

struct context {		// used for applyToInterested
    OSArray *	responseFlags;
    UInt16	serialNumber;
    UInt16 	counter;
    UInt32	maxTimeRequested;
    int		msgType;
    IOService *	us;
    IOLock *	flags_lock;
};

                                // five minutes in microseconds
#define FIVE_MINUTES 5*60*1000000
#define k15seconds 15*1000000

/*
 There are two different kinds of power state changes.  One is initiated by a subclassed device object which has either
 decided to change power state, or its controlling driver has suggested it, or some other driver wants to use the
 idle device and has asked it to become usable.  The second kind of power state change is initiated by the power
 domain parent.  The two are handled slightly differently.

There is a queue of so-called change notifications, or change notes for short.  Usually the queue is empty, and when
 it isn't, usually there is one change note in it, but since it's possible to have more than one power state change pending
 at one time, a queue is implemented.  Example:  the subclass device decides it's idle and initiates a change to a lower
 power state.  This causes interested parties to be notified, but they don't all acknowledge right away.  This causes the
 change note to sit in the queue until all the acks are received.  During this time, the device decides it isn't idle anymore and
 wants to raise power back up again.  This change can't be started, however, because the previous one isn't complete yet,
 so the second one waits in the queue.  During this time, the parent decides to lower or raise the power state of the entire
 power domain and notifies the device, and that notification goes into the queue, too, and can't be actioned until the
 others are.

 This is how a power change initiated by the subclass device is handled:
 First, all interested parties are notified of the change via their powerStateWillChangeTo method.  If they all don't
 acknowledge via return code, then we have to wait.  If they do, or when they finally all acknowledge via our
 acknowledgePowerChange method, then we can continue.  We call the controlling driver, instructing it to change to
 the new state.  Then we wait for power to settle.  If there is no settling-time, or after it has passed, we notify
 interested parties again, this time via their powerStateDidChangeTo methods.  When they have all acked, we're done.
 If we lowered power and don't need the power domain to be in its current power state, we suggest to the parent that
 it lower the power domain state.

 This is how a change to a lower power domain state initiated by the parent is handled:
 First, we figure out what power state we will be in when the new domain state is reached.  Then all interested parties are
 notified that we are moving to that new state.  When they have acknowledged, we call the controlling driver to assume
 that state and we wait for power to settle.  Then we acknowledge our preparedness to our parent.  When all its interested
 parties have acknowledged, it lowers power and then notifies its interested parties again.  When we get this call, we notify
 our interested parties that the power state has changed, and when they have all acknowledged, we're done.

 This is how a change to a higher power domain state initiated by the parent is handled:
 We figure out what power state we will be in when the new domain state is reached.  If it is different from our current
 state we acknowledge the parent.  When all the parent's interested parties have acknowledged, it raises power in the
domain and waits for power to settle.  Then it  notifies everyone that the new state has been reached.  When we get this call,
 we call the controlling driver, instructing it  to assume the new state, and wait for power to settle.  Then we notify our interested
 parties.  When they all acknowledge  we are done.

 In either of the two cases above, it is possible that we will not be changing state even though the domain is.  Examples:
 A change to a lower domain state may not affect us because we are already in a low enough state, and
 We will not take advantage of a change to a higher domain state, because we have no need of the higher power.
 In such a case, there is nothing to do but acknowledge the parent.  So when the parent calls our powerDomainWillChange
 method, and we decide that we will not be changing state, we merely acknowledge the parent, via return code, and wait.
 When the parent subsequently calls powerStateDidChange, we acknowledge again via return code, and the change is complete.

 Power state changes are processed in a state machine, and since there are four varieties of power state changes, there are
 four major paths through the state machine:

 The fourth is nearly trivial.  In this path, the parent is changing the domain state, but we are not changing the device state.
 The change starts when the parent calls powerDomainWillChange.  All we do is acknowledge the parent.
When the parent calls powerStateDidChange, we acknowledge the parent again, and we're done.

 The first is fairly simple.  It starts when a power domain child calls requestPowerDomainState and we decide to change power states
 to accomodate the child, or if our power-controlling driver calls changePowerStateTo, or if some other driver which is using our
 device calls makeUsable, or if a subclassed object calls changePowerStateToPriv.  These are all power changes initiated by us, not
 forced upon us by the parent.  We start by notifying interested parties.  If they all acknowledge via return code, we can go
 on to state "our_prechange_1".  Otherwise, we start the ack timer and wait for the stragglers to acknowlege by calling
 acknowledgePowerChange.  We move on to state "our_prechange_1" when all the stragglers have acknowledged,
 or when the ack timer expires on all those which didn't acknowledge.  In "our_prechange_1" we call the power-controlling
 driver to change the power state of the hardware.  If it returns saying it has done so, we go on to state "our_prechange_2".
 Otherwise, we have to wait for it, so we set the ack timer and wait.  When it calls acknowledgeSetPowerState, or when the
 ack timer expires, we go on.  In "our_prechange_2", we look in the power state array to see if there is any settle time required
 when changing from our current state to the new state.  If not, we go right away to "our_prechange_3".  Otherwise, we
 set the settle timer and wait.  When it expires, we move on.  In "our_prechange_3" state, we notify all our interested parties
 via their powerStateDidChange methods that we have finished changing power state.  If they all acknowledge via return
 code, we move on to "our_prechange_4".  Otherwise we set the ack timer and wait.  When they have all acknowledged, or
 when the ack timer has expired for those that didn't, we move on to "our_prechange_4", where we remove the used
 change note from the head of the queue and start the next one if one exists.

 Parent-initiated changes are more complex in the state machine.  First, power going up and power going down are handled
 differently, so they have different paths throught the state machine.  Second, we can acknowledge the parent's notification
 in two different ways, so each of the parent paths is really two.

 When the parent calls our powerDomainWillChange method, notifying us that it will lower power in the domain, we decide
 what state that will put our device in.  Then we embark on the state machine path "IOPMparent_down_1"
 and "IOPMparent_down_2", in which we notify interested parties of the upcoming change,  instruct our driver to make
 the change, check for settle time, and notify interested parties of the completed change.   If we get to the end of this path without
 stalling due to an interested party which didn't acknowledge via return code, due to the controlling driver not able to change
 state right away, or due to a non-zero settling time, then we return IOPMAckImplied to the parent, and we're done with the change.
 If we do stall in any of those states, we return IOPMWillAckLater to the parent and enter the parallel path "IOPMparent_down_4"
 "IOPMparent_down_5", and "IOPMparent_down_3", where we continue with the same processing, except that at the end we
 acknowledge the parent explicitly via acknowledgePowerChange, and we're done with the change.
Then when the parent calls us at powerStateDidChange we acknowledging via return code, because we have already made
 the power change.  In any case, when we are done we remove the used change note from the head of the queue and start on the next one.

 The case of the parent raising power in the domain is handled similarly in that there are parallel paths, one for no-stall
 that ends in implicit acknowleging the parent, and one that has stalled at least once that ends in explicit acknowledging
 the parent.  This case is different, though in that our device changes state in the second half, after the parent calls
 powerStateDidChange rather than before, as in the power-lowering case.

 When the parent calls our powerDomainWillChange method, notifying us that it will raise power in the domain, we acknowledge
 via return code, because there's really nothing we can do until the power is actually raised in the domain.
 When the parent calls us at powerStateDidChange, we start by notifying our interested parties.  If they all acknowledge via return code,
 we go on to" IOPMparent_up_1" to instruct the driver to raise its power level. After that, we check for any
 necessary settling time in "IOPMparent_up_2", and we notify all interested parties that power has changed
 in "IOPMparent_up_3".  If none of these operations stall, we acknowledge the parent via return code, release
 the change note, and start the next, if there is one.  If one of them does stall, we enter the parallel path  "IOPMparent_up_0",
 "IOPMparent_up_4", "IOPMparent_up_5", and "IOPMparent_up_6", which ends with
 our explicit acknowledgement to the parent.

*/


const char priv_key[ ] = "Power Management private data";
const char prot_key[ ] = "Power Management protected data";


void IOService::PMinit ( void )
{
    if ( ! initialized ) {

        pm_vars =  new IOPMprot;					// make space for our variables
        priv = new IOPMpriv;
        pm_vars->init();
        priv->init();
        
        setProperty(prot_key, (OSObject *) pm_vars);			// add these to the properties
        setProperty(priv_key, (OSObject *) priv);

        priv->owner = this;
        pm_vars->theNumberOfPowerStates = 0;				// then initialize them
        priv->we_are_root = false;
        pm_vars->theControllingDriver = NULL;
        priv->our_lock = IOLockAlloc();
        priv->flags_lock = IOLockAlloc();
        priv->interestedDrivers = new IOPMinformeeList;
        priv->interestedDrivers->initialize();
        priv->changeList = new IOPMchangeNoteList;
        priv->changeList->initialize();
        pm_vars->aggressiveness = 0;
        for (unsigned int i = 0; i <= kMaxType; i++) {
	     pm_vars->current_aggressiveness_values[i] = 0;
	     pm_vars->current_aggressiveness_valid[i] = false;
        }
        pm_vars->myCurrentState =  0;
        priv->imminentState = 0;
        priv->askingFor = 0;
        priv->ourDesiredPowerState = 0;
        pm_vars->parentsCurrentPowerFlags = 0;
        pm_vars->maxCapability = 0;
        priv->driverDesire = 0;
        priv->deviceDesire = 0;
        priv->initial_change = true;
        priv->need_to_become_usable = false;
        priv->previousRequest = 0;
        priv->device_overrides = false;
        priv->machine_state = IOPMfinished;
        pm_vars->commandQueue = NULL;
        priv->timerEventSrc = NULL;
        priv->clampTimerEventSrc = NULL;
        pm_vars->PMworkloop = NULL;
        priv->activityLock = NULL;
        pm_vars->ourName = getName();
        pm_vars->thePlatform = getPlatform();
        pm_vars->parentsKnowState = false;
        assert( pm_vars->thePlatform != 0 );
        priv->clampOn = false;
        pm_vars->serialNumber = 0;
        pm_vars->responseFlags = NULL;
        pm_vars->doNotPowerDown = true;
        pm_vars->PMcommandGate = NULL;
        priv->ackTimer = thread_call_allocate((thread_call_func_t)ack_timer_expired, (thread_call_param_t)this);
        priv->settleTimer = thread_call_allocate((thread_call_func_t)settle_timer_expired, (thread_call_param_t)this);
        initialized = true;
    }
}


//*********************************************************************************
// PMstop
//
// Free up the data created in PMinit.
//*********************************************************************************
void IOService::PMstop ( void )
{
    OSIterator *	iter;
    OSObject *		next;
    IOPowerConnection *	connection;

    initialized = false;

    removeProperty(prot_key);			// remove the properties
    removeProperty(priv_key);
    
    iter = getParentIterator(gIOPowerPlane);	// detach parents

    if ( iter ) {
        while ( (next = iter->getNextObject()) ) {
            if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) {
                ((IOService *)(connection->getParentEntry(gIOPowerPlane)))->removePowerChild(connection);
            }
        }
        iter->release();
    }
    detachAbove( gIOPowerPlane );		// detach IOConnections   
    
    pm_vars->parentsKnowState = false;		// no more power state changes
#if 0    

// This loop is insufficient.  Currently only leaf nodes are removed, and it's not clear today what
// it means to remove a subtree from the tree.  Should the IOPowerConnection at the top of it stay
// or go?  Should its child be notified of a change in the domain state?

    iter = getChildIterator(gIOPowerPlane);	// detach children

    if ( iter ) {
        while ( (next = iter->getNextObject()) ) {
            if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) {
                removePowerChild(connection);
            }
        }
        iter->release();
    }
#endif

    if (  priv->clampTimerEventSrc != NULL ) {
        getPMworkloop()->removeEventSource(priv->clampTimerEventSrc);
        priv->clampTimerEventSrc->release();
        priv->clampTimerEventSrc = NULL;
    }
    if (  priv->timerEventSrc != NULL ) {
        pm_vars->PMworkloop->removeEventSource(priv->timerEventSrc);
        priv->timerEventSrc->release();
        priv->timerEventSrc = NULL;
    }
    thread_call_free(priv->settleTimer);
    thread_call_free(priv->ackTimer);

    priv->interestedDrivers->release();		// remove lists
    priv->changeList->release();
    pm_vars->release();				// remove the instance variables
    priv->release();
    pm_vars = NULL;
    priv = NULL;
}


//*********************************************************************************
// joinPMtree
//
// A policy-maker calls its nub here when initializing, to be attached into
// the power management hierarchy.  The default function is to call the
// platform expert, which knows how to do it.  This method is overridden
// by a nub subclass which may either know how to do it, or may need
// to take other action.
//
// This may be the only "power management" method used in a nub,
// meaning it may not be initialized for power management.
//*********************************************************************************
void IOService::joinPMtree ( IOService * driver )
{
    IOPlatformExpert * thePlatform;

    thePlatform = getPlatform();
    assert(thePlatform != 0 );
    thePlatform->PMRegisterDevice(this,driver);
}


//*********************************************************************************
// youAreRoot
//
// Power Managment is informing us that we are the root power domain.
// The only difference between us and any other power domain is that
// we have no parent and therefore never call it.
//*********************************************************************************
IOReturn IOService::youAreRoot ( void )
{    
    priv-> we_are_root = true;
    pm_vars->parentsKnowState = true;
    attachToParent( getRegistryRoot(),gIOPowerPlane );
    
    return IOPMNoErr;
}


//*********************************************************************************
// setPowerParent
//
// Power Management is informing us who our parent is.
// If we have a controlling driver, find out, given our newly-informed
// power domain state, what state it would be in, and then tell it
// to assume that state.
//*********************************************************************************
IOReturn IOService::setPowerParent ( IOPowerConnection * theParent, bool stateKnown, IOPMPowerFlags currentState )
{
    OSIterator *			iter;
    OSObject *			next;
    IOPowerConnection *	connection;
    unsigned long		tempDesire;

    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogSetParent,stateKnown,currentState);
    
    if ( stateKnown && ((pm_vars->PMworkloop == NULL) || (pm_vars->PMcommandGate == NULL)) ) {
        getPMworkloop();						// we have a path to the root
        if ( pm_vars->PMworkloop != NULL ) {				// find out the workloop
            if ( pm_vars->PMcommandGate == NULL ) {			// and make our command gate
                pm_vars->PMcommandGate = IOCommandGate::commandGate((OSObject *)this);
                if ( pm_vars->PMcommandGate != NULL ) {
                    pm_vars->PMworkloop->addEventSource(pm_vars->PMcommandGate);
                }
            }
        }
    }
    
    theParent->setParentCurrentPowerFlags(currentState);	// set our connection data
    theParent->setParentKnowsState(stateKnown);

    pm_vars->parentsKnowState = true;				// combine parent knowledge
    pm_vars->parentsCurrentPowerFlags = 0;
    
    iter = getParentIterator(gIOPowerPlane);

    if ( iter ) {
        while ( (next = iter->getNextObject()) ) {
            if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) {
                pm_vars->parentsKnowState &= connection->parentKnowsState();
                pm_vars->parentsCurrentPowerFlags |= connection->parentCurrentPowerFlags();
            }
        }
        iter->release();
    }
    
    if ( (pm_vars->theControllingDriver != NULL) &&
         (pm_vars->parentsKnowState) ) {
        pm_vars->maxCapability = pm_vars->theControllingDriver->maxCapabilityForDomainState(pm_vars->parentsCurrentPowerFlags);
        tempDesire = priv->deviceDesire;			// initially change into the state we are already in
        priv->deviceDesire = pm_vars->theControllingDriver->initialPowerStateForDomainState(pm_vars->parentsCurrentPowerFlags);
        changeState();
        priv->deviceDesire = tempDesire;			// put this back like before
    }
   return IOPMNoErr;
}


//*********************************************************************************
// addPowerChild
//
// Power Management is informing us who our children are.
//*********************************************************************************
IOReturn IOService::addPowerChild ( IOService * theChild )
{
    IOPowerConnection *	connection;
    unsigned int        i;

    if ( ! initialized ) {
        return IOPMNotYetInitialized;	// we're not a power-managed IOService
    }

    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogAddChild,0,0);

    connection = new IOPowerConnection;			// make a nub

    connection->init();
    connection->start(this);

    attachToChild( connection,gIOPowerPlane );			// connect it up
    connection->attachToChild( theChild,gIOPowerPlane );
    connection->release();
    
    if ( (pm_vars->theControllingDriver == NULL) ||		// tell it the current state of the power domain
         ! (inPlane(gIOPowerPlane)) ||
       ! (pm_vars->parentsKnowState) ) {
        theChild->setPowerParent(connection,false,0);
        if ( inPlane(gIOPowerPlane) ) {
            for (i = 0; i <= kMaxType; i++) {
                if ( pm_vars->current_aggressiveness_valid[i] ) {
                    theChild->setAggressiveness (i, pm_vars->current_aggressiveness_values[i]);
                }
            }
        }
    }
    else {
        theChild->setPowerParent(connection,true,pm_vars->thePowerStates[pm_vars->myCurrentState].outputPowerCharacter);
        for (i = 0; i <= kMaxType; i++) {
            if ( pm_vars->current_aggressiveness_valid[i] ) {
                theChild->setAggressiveness (i, pm_vars->current_aggressiveness_values[i]);
            }
        }
        add_child_to_active_change(connection);							// catch it up if change is in progress
    }
    
    return IOPMNoErr;
}


//*********************************************************************************
// removePowerChild
//
//*********************************************************************************
IOReturn IOService::removePowerChild ( IOPowerConnection * theChild )
{    
    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogRemoveChild,0,0);

    detachFromChild(theChild,gIOPowerPlane);	 	 // remove the departing child

    if ( (pm_vars->theControllingDriver == NULL) ||	// if not fully initialized
         ! (inPlane(gIOPowerPlane)) ||
       ! (pm_vars->parentsKnowState) ) {
        return IOPMNoErr;				// we can do no more
    }

    changeState();					// change state if we can now tolerate lower power

    return IOPMNoErr;
}


//*********************************************************************************
// registerPowerDriver
//
// A driver has called us volunteering to control power to our device.
// If the power state array it provides is richer than the one we already
// know about (supplied by an earlier volunteer), then accept the offer.
// Notify all interested parties of our power state, which we now know.
//*********************************************************************************

IOReturn IOService::registerPowerDriver ( IOService * controllingDriver, IOPMPowerState* powerStates, unsigned long numberOfStates  )
{
    unsigned long i;
    unsigned long tempDesire;

    if ( (numberOfStates > pm_vars->theNumberOfPowerStates) && (numberOfStates > 1) ) {
        if (  priv->changeList->currentChange() == -1 ) {
            if ( controllingDriver != NULL ) {
                if ( numberOfStates <= IOPMMaxPowerStates ) {
                    switch ( powerStates[0].version  ) {
                        case 1:
                            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogControllingDriver,
                                                                    (unsigned long)numberOfStates, (unsigned long)powerStates[0].version);
                            for ( i = 0; i < numberOfStates; i++ ) {
                                pm_vars->thePowerStates[i] = powerStates[i];
                            }
                                break;
                        case 2:
                            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogControllingDriver,
                                                                    (unsigned long) numberOfStates,(unsigned long) powerStates[0].version);
                            for ( i = 0; i < numberOfStates; i++ ) {
                                pm_vars->thePowerStates[i].version = powerStates[i].version;
                                pm_vars->thePowerStates[i].capabilityFlags = powerStates[i].capabilityFlags;
                                pm_vars->thePowerStates[i].outputPowerCharacter = powerStates[i].outputPowerCharacter;
                                pm_vars->thePowerStates[i].inputPowerRequirement = powerStates[i].inputPowerRequirement;
                                pm_vars->thePowerStates[i].staticPower = powerStates[i].staticPower;
                                pm_vars->thePowerStates[i].unbudgetedPower = powerStates[i].unbudgetedPower;
                                pm_vars->thePowerStates[i].powerToAttain = powerStates[i].powerToAttain;
                                pm_vars->thePowerStates[i].timeToAttain = powerStates[i].timeToAttain;
                                pm_vars->thePowerStates[i].settleUpTime = powerStates[i].settleUpTime;
                                pm_vars->thePowerStates[i].timeToLower = powerStates[i].timeToLower;
                                pm_vars->thePowerStates[i].settleDownTime = powerStates[i].settleDownTime;
                                pm_vars->thePowerStates[i].powerDomainBudget = powerStates[i].powerDomainBudget;
                            }
                                break;
                        default:
                            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogControllingDriverErr1,
                                                                    (unsigned long)powerStates[0].version,0);
                            return IOPMNoErr;
                    }

                    pm_vars->myCharacterFlags = 0;	// make a mask of all the character bits we know about
                    for ( i = 0; i < numberOfStates; i++ ) {
                        pm_vars->myCharacterFlags |= pm_vars->thePowerStates[i].outputPowerCharacter;
                    }
                    
                   pm_vars->theNumberOfPowerStates = numberOfStates;
                    pm_vars->theControllingDriver = controllingDriver;
                    if ( priv->interestedDrivers->findItem(controllingDriver) == NULL ) {	// register it as interested
                        registerInterestedDriver (controllingDriver );				// unless already done
                    }
                    if ( priv->need_to_become_usable ) {
                        priv->need_to_become_usable = false;
                        priv->deviceDesire = pm_vars->theNumberOfPowerStates - 1;
                    }

                    if ( inPlane(gIOPowerPlane) &&
                         (pm_vars->parentsKnowState) ) {
                        pm_vars->maxCapability = pm_vars->theControllingDriver->maxCapabilityForDomainState(pm_vars->parentsCurrentPowerFlags);
                        tempDesire = priv->deviceDesire;			// initially change into the state we are already in
                        priv->deviceDesire = pm_vars->theControllingDriver->initialPowerStateForDomainState(pm_vars->parentsCurrentPowerFlags);
                        changeState();
                        priv->deviceDesire = tempDesire;			// put this back like before
                    }
                }
                else {
                    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogControllingDriverErr2,(unsigned long)numberOfStates,0);
                }
            }
            else {
                pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogControllingDriverErr4,0,0);
            }
        }
    }
    else {
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogControllingDriverErr5,(unsigned long)numberOfStates,0);
    }
    return IOPMNoErr;
}

//*********************************************************************************
// registerInterestedDriver
//
// Add the caller to our list of interested drivers and return our current
// power state.  If we don't have a power-controlling driver yet, we will
// call this interested driver again later when we do get a driver and find
// out what the current power state of the device is.
//*********************************************************************************

IOPMPowerFlags IOService::registerInterestedDriver ( IOService * theDriver )
{
    IOPMinformee * newInformee;
    IOPMPowerFlags futureCapability;

    if (theDriver == NULL ) {
        return 0;
    }

    newInformee = new IOPMinformee;				// make new driver node
    newInformee->initialize(theDriver);
    priv->interestedDrivers->addToList(newInformee);			// add it to list of drivers

    if ( (pm_vars->theControllingDriver == NULL) ||
         ! (inPlane(gIOPowerPlane)) ||
       ! (pm_vars->parentsKnowState) ) {
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogInterestedDriver,IOPMNotPowerManaged,0);
        return IOPMNotPowerManaged;					// can't tell it a state yet
    }

    switch (priv->machine_state) {					// can we notify new driver of a change in progress?
        case IOPMour_prechange_1:
        case IOPMour_prechange_4:
        case IOPMparent_down_4:
        case IOPMparent_down_6:
        case IOPMparent_up_0:
        case IOPMparent_up_6:
            futureCapability = priv->head_note_capabilityFlags;			// yes, remember what we tell it
            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogInterestedDriver,(unsigned long)futureCapability,1);
            add_driver_to_active_change(newInformee);				// notify it
            return futureCapability;						// and return the same thing
    }

    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogInterestedDriver,
                                            (unsigned long) pm_vars->thePowerStates[pm_vars->myCurrentState].capabilityFlags,2);
    return  pm_vars->thePowerStates[pm_vars->myCurrentState].capabilityFlags;	// no, return current capability
}


//*********************************************************************************
// deRegisterInterestedDriver
//
//*********************************************************************************
IOReturn IOService::deRegisterInterestedDriver ( IOService * theDriver )
{
    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogRemoveDriver,0,0);

    priv->interestedDrivers->removeFromList(theDriver);				  // remove the departing driver

    return IOPMNoErr;
}


//*********************************************************************************
// acknowledgePowerChange
//
// After we notified one of the interested drivers or a power-domain child
// of an impending change in power, it has called to say it is now
// prepared for the change.  If this object is the last to
// acknowledge this change, we take whatever action we have been waiting
// for.
// That may include acknowledging to our parent.  In this case, we do it
// last of all to insure that this doesn't cause the parent to call us some-
// where else and alter data we are relying on here (like the very existance
// of a "current change note".)
//*********************************************************************************

IOReturn IOService::acknowledgePowerChange ( IOService * whichObject )
{
   IOPMinformee *	ackingObject;

    ackingObject =  priv->interestedDrivers->findItem(whichObject);				// one of our interested drivers?
   if ( ackingObject == NULL ) {
       if ( ! isChild(whichObject,gIOPowerPlane) ) {
           pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogAcknowledgeErr1,0,0);
           kprintf("errant driver: %s\n",whichObject->getName());
           return IOPMNoErr;							// no, just return
       }
       else {
           pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogChildAcknowledge,0,0);
       }
   }
   else {
       pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogDriverAcknowledge,0,0);
   }

   if (! acquire_lock() ) {
       return IOPMNoErr;
   }

   if (priv->head_note_pendingAcks != 0 ) {					// yes, make sure we're expecting acks
       if ( ackingObject != NULL ) {						// it's an interested driver
           if ( ackingObject->timer != 0 ) {					// make sure we're expecting this ack
               ackingObject->timer = 0;						// mark it acked
               priv->head_note_pendingAcks -= 1;					// that's one fewer to worry about
               if ( priv->head_note_pendingAcks == 0 ) {				// is that the last?
                   stop_ack_timer();							// yes, stop the timer
                   IOUnlock(priv->our_lock);
                   all_acked();							// and now we can continue
                   return IOPMNoErr;
               }
           }
           else {
               pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogAcknowledgeErr2,0,0);	// this driver has already acked
           kprintf("errant driver: %s\n",whichObject->getName());
           }
       }
       else {									// it's a child
           priv->head_note_pendingAcks -= 1;					// that's one fewer to worry about
           if ( priv->head_note_pendingAcks == 0 ) {				// is that the last?
               stop_ack_timer();							// yes, stop the timer
               IOUnlock(priv->our_lock);
               all_acked();								// and now we can continue
               return IOPMNoErr;
           }
       }
    }
   else {
       pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogAcknowledgeErr3,0,0);	// not expecting anybody to ack
       kprintf("errant driver: %s\n",whichObject->getName());
   }
   IOUnlock(priv->our_lock);
   return IOPMNoErr;
}

//*********************************************************************************
// acknowledgeSetPowerState
//
// After we instructed our controlling driver to change power states,
// it has called to say it has finished doing so.
// We continue to process the power state change.
//*********************************************************************************

IOReturn IOService::acknowledgeSetPowerState ( void )
{
    if (! acquire_lock() ) {
        return IOPMNoErr;
    }
    if ( priv->driver_timer == -1 ) {
        priv->driver_timer = 0;				// driver is acking instead of using return code
    }
    else {
        if ( priv->driver_timer > 0 ) {			// are we expecting this?
            stop_ack_timer();				// yes, stop the timer
            priv->driver_timer = 0;
            IOUnlock(priv->our_lock);
            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogDriverAcknowledgeSet,0,0);
            driver_acked();
            return IOPMNoErr;
        }
        else {
            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogAcknowledgeErr4,0,0);		// no
        }
    }
    IOUnlock(priv->our_lock);
    return IOPMNoErr;
}


//*********************************************************************************
// driver_acked
//
// Either the controlling driver has called acknowledgeSetPowerState
// or the acknowledgement timer has expired while waiting for that.
// We carry on processing the current change note.
//*********************************************************************************

void IOService::driver_acked ( void )
{
    switch (priv->machine_state) {
        case IOPMour_prechange_2:
            our_prechange_2();
            break;
        case IOPMparent_down_5:
            parent_down_5();
            break;
        case IOPMparent_up_4:
            parent_up_4();
            break;
    }
}


//*********************************************************************************
// powerDomainWillChangeTo
//
// Called by the power-hierarchy parent notifying of a new power state
// in the power domain.
// We enqueue a parent power-change to our queue of power changes.
// This may or may not cause us to change power, depending on what
// kind of change is occuring in the domain.
//*********************************************************************************

IOReturn IOService::powerDomainWillChangeTo ( IOPMPowerFlags newPowerStateFlags, IOPowerConnection * whichParent )
{
    OSIterator *			iter;
    OSObject *			next;
    IOPowerConnection *	connection;
    unsigned long		newStateNumber;
    IOPMPowerFlags		combinedPowerFlags;

    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogWillChange,(unsigned long)newPowerStateFlags,0);

    if ( ! inPlane(gIOPowerPlane) ) {
        return IOPMAckImplied;						// somebody goofed
    }

    if ( (pm_vars->PMworkloop == NULL) || (pm_vars->PMcommandGate == NULL) ) {
        getPMworkloop();						// we have a path to the root,
        if ( pm_vars->PMworkloop != NULL ) {				// so find out the workloop
            if ( pm_vars->PMcommandGate == NULL ) {			// and make our command gate
                pm_vars->PMcommandGate = IOCommandGate::commandGate((OSObject *)this);
                if ( pm_vars->PMcommandGate != NULL ) {
                    pm_vars->PMworkloop->addEventSource(pm_vars->PMcommandGate);
                }
            }
        }
    }
    
    combinedPowerFlags = 0;						// combine parents' power states
    
    iter = getParentIterator(gIOPowerPlane);

    if ( iter ) {
        while ( (next = iter->getNextObject()) ) {
            if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) {
                if ( connection == whichParent ){
                    combinedPowerFlags |= newPowerStateFlags;
                }
                else {
                    combinedPowerFlags |= connection->parentCurrentPowerFlags();
                }
            }
        }
        iter->release();
    }

    if  ( pm_vars->theControllingDriver == NULL ) {					// we can't take any more action
        return IOPMAckImplied;
    }
    newStateNumber = pm_vars->theControllingDriver->maxCapabilityForDomainState(combinedPowerFlags);
    return enqueuePowerChange(IOPMParentInitiated | IOPMDomainWillChange, newStateNumber,combinedPowerFlags,whichParent);	//make the change
}


//*********************************************************************************
// powerDomainDidChangeTo
//
// Called by the power-hierarchy parent after the power state of the power domain
// has settled at a new level.
// We enqueue a parent power-change to our queue of power changes.
// This may or may not cause us to change power, depending on what
// kind of change is occuring in the domain.
//*********************************************************************************

IOReturn IOService::powerDomainDidChangeTo ( IOPMPowerFlags newPowerStateFlags, IOPowerConnection * whichParent )
{
    OSIterator *	iter;
    OSObject *		next;
    IOPowerConnection *	connection;
    unsigned long	newStateNumber;

    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogDidChange,newPowerStateFlags,0);

    whichParent->setParentCurrentPowerFlags(newPowerStateFlags);		// set our connection data
    whichParent->setParentKnowsState(true);

    pm_vars->parentsCurrentPowerFlags = 0;					// recompute our parent info
    pm_vars->parentsKnowState = true;

    iter = getParentIterator(gIOPowerPlane);

    if ( iter ) {
        while ( (next = iter->getNextObject()) ) {
            if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) {
                pm_vars->parentsKnowState &= connection->parentKnowsState();
                pm_vars->parentsCurrentPowerFlags |= connection->parentCurrentPowerFlags();
            }
        }
        iter->release();
    }

    if ( pm_vars->theControllingDriver == NULL ) {
        return IOPMAckImplied;
    }

    newStateNumber = pm_vars->theControllingDriver->maxCapabilityForDomainState(pm_vars->parentsCurrentPowerFlags);
    return enqueuePowerChange(IOPMParentInitiated | IOPMDomainDidChange, newStateNumber,pm_vars->parentsCurrentPowerFlags,whichParent);	// tell interested parties about it
}


//*********************************************************************************
// requestPowerDomainState
//
//
//*********************************************************************************
IOReturn IOService::requestPowerDomainState ( IOPMPowerFlags desiredState, IOPowerConnection * whichChild, unsigned long specification )
{
    unsigned long	i;
    OSIterator *	iter;
    OSObject *		next;
    IOPowerConnection *	connection;

    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogRequestDomain,
                                (unsigned long)desiredState,(unsigned long)specification);

    if ( pm_vars->theControllingDriver == NULL) {
        return IOPMNotYetInitialized;
    }

    switch (specification) {
        case IOPMLowestState:
            i = 0;
            while ( i < pm_vars->theNumberOfPowerStates ) {
                if ( ( pm_vars->thePowerStates[i].outputPowerCharacter & desiredState) == (desiredState & pm_vars->myCharacterFlags) ) {
                    break;
                }
                i++;
            }
                if ( i >= pm_vars->theNumberOfPowerStates ) {
                return IOPMNoSuchState;
           }
            break;

        case IOPMNextLowerState:
            i = pm_vars->myCurrentState - 1;
            while ( i >= 0 ) {
                if ( ( pm_vars->thePowerStates[i].outputPowerCharacter & desiredState) == (desiredState & pm_vars->myCharacterFlags) ) {
                    break;
                }
                i--;
            }
            if ( i < 0 ) {
                return IOPMNoSuchState;
            }
            break;

        case IOPMHighestState:
            i = pm_vars->theNumberOfPowerStates;
            while ( i >= 0 ) {
                i--;
                if ( ( pm_vars->thePowerStates[i].outputPowerCharacter & desiredState) == (desiredState & pm_vars->myCharacterFlags) ) {
                    break;
                }
            }
            if ( i < 0 ) {
                return IOPMNoSuchState;
            }
            break;

        case IOPMNextHigherState:
            i = pm_vars->myCurrentState + 1;
            while ( i < pm_vars->theNumberOfPowerStates ) {
                if ( ( pm_vars->thePowerStates[i].outputPowerCharacter & desiredState) == (desiredState & pm_vars->myCharacterFlags) ) {
                    break;
                }
            i++;
            }
                if ( i == pm_vars->theNumberOfPowerStates ) {
                return IOPMNoSuchState;
            }
            break;

        default:
            return IOPMBadSpecification;
    }

// Now loop through the children.  When we encounter the calling child, save
// the new state as this child's desire.  Then, compute a new maximum
// of everybody's desires.

    iter = getChildIterator(gIOPowerPlane);

    if ( iter ) {
        while ( (next = iter->getNextObject()) ) {
            if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) {
                if ( connection == whichChild ) {
                    connection->setDesiredDomainState(i);
                }
            }
        }
        iter->release();
    }

   if ( inPlane(gIOPowerPlane) &&
        (pm_vars->parentsKnowState) ) {
       changeState();					// change state if all children can now tolerate lower power
   }
   
   if ( priv->clampOn ) {				// are we clamped on, waiting for this child?
       priv->clampOn = false;				// yes, remove the clamp
       changePowerStateToPriv(0);
   }
   
   return IOPMNoErr;
}


//*********************************************************************************
// temporaryPowerClampOn
//
// A power domain wants to clamp its power on till it has children which
// will thendetermine the power domain state.
//
// We enter the highest state until addPowerChild is called.
//*********************************************************************************

IOReturn IOService::temporaryPowerClampOn ( void )
{
    priv->clampOn = true;
    makeUsable();
    return IOPMNoErr;
}


//*********************************************************************************
// makeUsable
//
// Some client of our device is asking that we become usable.  Although
// this has not come from a subclassed device object, treat it exactly
// as if it had.  In this way, subsequent requests for lower power from
// a subclassed device object will pre-empt this request.
//
// We treat this as a subclass object request to switch to the
// highest power state.
//*********************************************************************************

IOReturn IOService::makeUsable ( void )
{
    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogMakeUsable,0,0);

    if ( pm_vars->theControllingDriver == NULL ) {
        priv->need_to_become_usable = true;
        return IOPMNoErr;
    }
    priv->deviceDesire = pm_vars->theNumberOfPowerStates - 1;
    if ( inPlane(gIOPowerPlane) && (pm_vars->parentsKnowState) ) {
        return changeState();
    }
    return IOPMNoErr;
}


//*********************************************************************************
// currentCapability
//
//*********************************************************************************

IOPMPowerFlags IOService::currentCapability ( void )
{
    if ( pm_vars->theControllingDriver == NULL ) {
        return 0;
    }
    else {
        return   pm_vars->thePowerStates[pm_vars->myCurrentState].capabilityFlags;
    }
}


//*********************************************************************************
// changePowerStateTo
//
// For some reason, our power-controlling driver has decided it needs to change
// power state.  We enqueue the power change so that appropriate parties
// will be notified, and then we will instruct the driver to make the change.
//*********************************************************************************

IOReturn IOService::changePowerStateTo ( unsigned long ordinal )
{
    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogChangeStateTo,ordinal,0);

    if ( ordinal >= pm_vars->theNumberOfPowerStates ) {
        return IOPMParameterError;
    }
    priv->driverDesire = ordinal;
    if ( inPlane(gIOPowerPlane) && (pm_vars->parentsKnowState) ) {
        return changeState();
    }

    return IOPMNoErr;
}

//*********************************************************************************
// changePowerStateToPriv
//
// For some reason, a subclassed device object has decided it needs to change
// power state.  We enqueue the power change so that appropriate parties
// will be notified, and then we will instruct the driver to make the change.
//*********************************************************************************

IOReturn IOService::changePowerStateToPriv ( unsigned long ordinal )
{
    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogChangeStateToPriv,ordinal,0);

    if ( pm_vars->theControllingDriver == NULL) {
        return IOPMNotYetInitialized;
    }
    if ( ordinal >= pm_vars->theNumberOfPowerStates ) {
        return IOPMParameterError;
    }
    priv->deviceDesire = ordinal;
    if ( inPlane(gIOPowerPlane) && (pm_vars->parentsKnowState) ) {
        return changeState();
    }

    return IOPMNoErr;
}


//*********************************************************************************
// changeState
//
// A subclass object, our controlling driver, or a power domain child
// has asked for a different power state.  Here we compute what new
// state we should enter and enqueue the change (or start it).
//*********************************************************************************

IOReturn IOService::changeState ( void )
{
    OSIterator *	iter;
    OSObject *		next;
    IOPowerConnection *	connection;
    unsigned long	newDesiredState = 0;

    // Compute the maximum  of our children's desires, our controlling driver's desire, and the subclass device's desire.

    if ( !  priv->device_overrides ) {
        iter = getChildIterator(gIOPowerPlane);

        if ( iter ) {
            while ( (next = iter->getNextObject()) ) {
                if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) {
                    if ( connection->getDesiredDomainState() > newDesiredState ) {
                        newDesiredState = connection->getDesiredDomainState();
                    }
                }
            }
            iter->release();
        }
        
        if (  priv->driverDesire > newDesiredState ) {
            newDesiredState =  priv->driverDesire;
        }
    }

    if ( priv->deviceDesire > newDesiredState ) {
        newDesiredState = priv->deviceDesire;
    }

    priv->ourDesiredPowerState = newDesiredState;

    if ( (pm_vars->theControllingDriver == NULL) ||	// if not fully initialized
         ! (inPlane(gIOPowerPlane)) ||
       ! (pm_vars->parentsKnowState) ) {
        return IOPMNoErr;				// we can do no more
    }
    
    return enqueuePowerChange(IOPMWeInitiated,newDesiredState,0,0);
}


//*********************************************************************************
// currentPowerConsumption
//
//*********************************************************************************

unsigned long IOService::currentPowerConsumption ( void )
{
    if ( pm_vars->theControllingDriver == NULL ) {
        return 0;
    }
    else {
        return  pm_vars->thePowerStates[pm_vars->myCurrentState].staticPower;
    }
}

//*********************************************************************************
// activityTickle
//
// The activity tickle with parameter kIOPMSubclassPolicyis not handled
// here and should have been intercepted by the subclass.
// The tickle with parameter kIOPMSuperclassPolicy1 causes the activity
// flag to be set, and the device state checked.  If the device has been
// powered down, it is powered up again.
//*********************************************************************************

bool IOService::activityTickle ( unsigned long type, unsigned long stateNumber=0 )
{
    AbsoluteTime uptime;

    if ( type == kIOPMSuperclassPolicy1 ) {
        if ( (priv->activityLock == NULL) ||
             (pm_vars->theControllingDriver == NULL) ||
             ( pm_vars->commandQueue == NULL) ) {
            return true;
        }
        IOTakeLock(priv->activityLock);
        priv->device_active = true;

        clock_get_uptime(&uptime);
        priv->device_active_timestamp = uptime;

        if ( pm_vars->myCurrentState >= stateNumber) {
            IOUnlock(priv->activityLock);
            return true;
        }
        IOUnlock(priv->activityLock);				// send a message on the command queue
        pm_vars->commandQueue->enqueueCommand(true, (void *)kPMunIdleDevice, (void *)stateNumber);
        return false;
    }
    return true;
}

//*********************************************************************************
// getPMworkloop
//
// A child is calling to get a pointer to the Power Management workloop.
// We got it or get it from one of our parents.
//*********************************************************************************

IOWorkLoop * IOService::getPMworkloop ( void )
{
IOService * aParent;

    if ( ! inPlane(gIOPowerPlane) ) {
        return NULL;
    }
    if ( pm_vars->PMworkloop == NULL ) {				// we have no workloop yet
        aParent = (IOService *)getParentEntry(gIOPowerPlane)->getParentEntry(gIOPowerPlane);
        if ( aParent != NULL ) {					// ask one of our parents for the workloop
            pm_vars->PMworkloop = aParent->getPMworkloop();
        }
    }
    return  pm_vars->PMworkloop;
}


//*********************************************************************************
// setIdleTimerPeriod
//
// A subclass policy-maker is going to use our standard idleness
// detection service.  Make a command queue and an idle timer and
// connect them to the power management workloop.  Finally,
// start the timer.
//*********************************************************************************

IOReturn  IOService::setIdleTimerPeriod ( unsigned long period )
{
    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMsetIdleTimerPeriod,period, 0);

    priv->idle_timer_period = period;

    if ( period > 0 ) {
        if ( getPMworkloop() == NULL ) {
            return kIOReturnError;
        }

        if (pm_vars->commandQueue == NULL ) {		// make the command queue
            pm_vars->commandQueue = IOCommandQueue::commandQueue(this, PMreceiveCmd);
            if (!  pm_vars->commandQueue ||
                (  pm_vars->PMworkloop->addEventSource( pm_vars->commandQueue) != kIOReturnSuccess) ) {
                return kIOReturnError;
            }
        }
       						 // make the timer event
        if (  priv->timerEventSrc == NULL ) {
            priv->timerEventSrc = IOTimerEventSource::timerEventSource(this,
                                                    PM_idle_timer_expired);
            if ( !  priv->timerEventSrc ||
                 ( pm_vars->PMworkloop->addEventSource(  priv->timerEventSrc) != kIOReturnSuccess) ) {
                return kIOReturnError;
            }
        }

        if ( priv->activityLock == NULL ) {
            priv->activityLock = IOLockAlloc();
        }

        start_PM_idle_timer();
    }
    return IOPMNoErr;
}


//*********************************************************************************
// start_PM_idle_timer
//
// The parameter is a pointer to us.  Use it to call our timeout method.
//*********************************************************************************
void IOService::start_PM_idle_timer ( void )
{
    AbsoluteTime uptime;
    AbsoluteTime delta;
    UInt64       delta_ns;
    UInt64       delta_secs;
    UInt64       delay_secs;

    IOLockLock(priv->activityLock);

    clock_get_uptime(&uptime);

   /* Calculate time difference using funky macro from clock.h.
    */
    delta = uptime;
    SUB_ABSOLUTETIME(&delta, &(priv->device_active_timestamp));

   /* Figure it in seconds.
    */
    absolutetime_to_nanoseconds(delta, &delta_ns);
    delta_secs = delta_ns / NSEC_PER_SEC;

   /* Be paranoid about delta somehow exceeding timer period.
    */
    if (delta_secs < priv->idle_timer_period ) {
        delay_secs = priv->idle_timer_period - delta_secs;
    } else {
        delay_secs = priv->idle_timer_period;
    }

    priv->timerEventSrc->setTimeout(delay_secs, NSEC_PER_SEC);

    IOLockUnlock(priv->activityLock);
    return;
}


//*********************************************************************************
// PM_idle_timer_expired
//
// The parameter is a pointer to us.  Use it to call our timeout method.
//*********************************************************************************

void PM_idle_timer_expired(OSObject * ourSelves, IOTimerEventSource *)
{
    ((IOService *)ourSelves)->PM_idle_timer_expiration();
}


//*********************************************************************************
// PM_idle_timer_expiration
//
// The idle timer has expired.  If there has been activity since the last
// expiration, just restart the timer and return.  If there has not been
// activity, switch to the next lower power state and restart the timer.
//*********************************************************************************

void IOService::PM_idle_timer_expiration ( void )
{
    if ( ! initialized ) {
        return;					// we're unloading
    }

    if (  priv->idle_timer_period > 0 ) {
        IOTakeLock(priv->activityLock);
        if ( priv->device_active ) {
            priv->device_active = false;
            IOUnlock(priv->activityLock);
            start_PM_idle_timer();
            return;
        }
        if ( pm_vars->myCurrentState > 0 ) {
            IOUnlock(priv->activityLock);
            priv->askingFor = pm_vars->myCurrentState - 1;
            changePowerStateToPriv(pm_vars->myCurrentState - 1);
            start_PM_idle_timer();
            return;
        }
        IOUnlock(priv->activityLock);
        start_PM_idle_timer();
    }
}



// **********************************************************************************
// PMreceiveCmd
//
//
//
// **********************************************************************************
void PMreceiveCmd ( OSObject * theDriver,  void * command, void * param1, void * param2, void *param3 )
{
   ((IOService *)theDriver)->command_received(command,param1,param2,param3);
}


// **********************************************************************************
// command_received
//
// We have received a command from ourselves on the command queue.
// This is to prevent races with timer-expiration code.
// **********************************************************************************
void IOService::command_received ( void * command, void *stateNumber , void * , void *)
{
    if ( ! initialized ) {
        return;					// we're unloading
    }

    if ( command == (void *)kPMunIdleDevice ) {
        if ( (pm_vars->myCurrentState < (unsigned long)stateNumber) &&
            (priv->imminentState < (unsigned long)stateNumber ) &&
            ((unsigned long)stateNumber > priv->askingFor) ) {
            priv->askingFor = (unsigned long)stateNumber;
            changePowerStateToPriv((unsigned long)stateNumber);
        }
    }
}


//*********************************************************************************
// setAggressiveness
//
// Pass on the input parameters to all power domain children. All those which are
// power domains will pass it on to their children, etc.
//*********************************************************************************

IOReturn IOService::setAggressiveness ( unsigned long type, unsigned long newLevel )
{
    OSIterator *			iter;
    OSObject *			next;
    IOPowerConnection *	connection;

    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogSetAggressiveness,type, newLevel);

    if ( type <= kMaxType ) {
        pm_vars->current_aggressiveness_values[type] = newLevel;
        pm_vars->current_aggressiveness_valid[type] = true;
    }

    iter = getChildIterator(gIOPowerPlane);

    if ( iter ) {
        while ( (next = iter->getNextObject()) ) {
            if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) {
                ((IOService *)(connection->getChildEntry(gIOPowerPlane)))->setAggressiveness(type, newLevel);
            }
        }
        iter->release();
    }

    return IOPMNoErr;
}

//*********************************************************************************
// getAggressiveness
//
// Called by the user client.
//*********************************************************************************

IOReturn IOService::getAggressiveness ( unsigned long type, unsigned long * currentLevel )
{
  if ( type <= kMaxType ) {
        *currentLevel = pm_vars->current_aggressiveness_values[type];
  }
    return kIOReturnSuccess;
}

//*********************************************************************************
// systemWake
//
// Pass this to all power domain children. All those which are
// power domains will pass it on to their children, etc.
//*********************************************************************************

IOReturn IOService::systemWake ( void )
{
    OSIterator *			iter;
    OSObject *			next;
    IOPowerConnection *	connection;

    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogSystemWake,0, 0);

    iter = getChildIterator(gIOPowerPlane);

    if ( iter ) {
        while ( (next = iter->getNextObject()) ) {
            if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) {
                ((IOService *)(connection->getChildEntry(gIOPowerPlane)))->systemWake();
            }
        }
        iter->release();
    }

    if ( pm_vars->theControllingDriver != NULL ) {
        if ( pm_vars->theControllingDriver->didYouWakeSystem() ) {
            makeUsable();
        }
    }

    return IOPMNoErr;
}


//*********************************************************************************
// temperatureCriticalForZone
//
//*********************************************************************************

IOReturn IOService::temperatureCriticalForZone ( IOService * whichZone )
{
    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogCriticalTemp,0,0);

    if ( inPlane(gIOPowerPlane) && ! (priv->we_are_root) ) {
        ((IOService *)(getParentEntry(gIOPowerPlane)->getParentEntry(gIOPowerPlane)))->temperatureCriticalForZone(whichZone); 
    }
    return IOPMNoErr;
}


//*********************************************************************************
// powerOverrideOnPriv
//
//*********************************************************************************


IOReturn IOService::powerOverrideOnPriv ( void )
{
    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogOverrideOn,0,0);

    priv->device_overrides = true;	// turn on the override
    return changeState();		// change state if that changed something
}


//*********************************************************************************
// powerOverrideOffPriv
//
//*********************************************************************************
IOReturn IOService::powerOverrideOffPriv ( void )
{
    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogOverrideOff,0,0);

    priv->device_overrides = false;	// turn off the override
    return changeState();		// change state if that changed something
}


//*********************************************************************************
// enqueuePowerChange
//
// Allocate a new state change notification, initialize it with fields from the
// caller, and add it to the tail of the list of pending power changes.
//
// If it is early enough in the list, and almost all the time it is the only one in
// the list, start the power change.
//
// In rare instances, this change will preempt the previous change in the list.
// If the previous change is un-actioned in any way (because we are still
// processing an even earlier power change), and if both the previous change
// in the list and this change are initiated by us (not the parent), then we
// needn't perform the previous change, so we collapse the list a little.
//*********************************************************************************

IOReturn IOService::enqueuePowerChange ( unsigned long flags,  unsigned long whatStateOrdinal, unsigned long domainState, IOPowerConnection * whichParent )
{
    long	newNote;
    long	previousNote;

// Create and initialize the new change note

    newNote = priv->changeList->createChangeNote();
    if ( newNote == -1 ) {
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogEnqueueErr,0,0);
        return IOPMAckImplied;			// uh-oh, our list is full
    }

    priv->changeList->changeNote[newNote].newStateNumber = whatStateOrdinal;
    priv->changeList->changeNote[newNote].outputPowerCharacter =  pm_vars->thePowerStates[whatStateOrdinal].outputPowerCharacter;
    priv->changeList->changeNote[newNote].inputPowerRequirement =  pm_vars->thePowerStates[whatStateOrdinal].inputPowerRequirement;
    priv->changeList->changeNote[newNote].capabilityFlags =  pm_vars->thePowerStates[whatStateOrdinal].capabilityFlags;
    priv->changeList->changeNote[newNote].flags = flags;
    if (flags & IOPMParentInitiated ) {
        priv->changeList->changeNote[newNote].domainState =  domainState;
        priv->changeList->changeNote[newNote].parent =  whichParent;
    }

    previousNote = priv->changeList->previousChangeNote(newNote);

    if ( previousNote == -1 ) {

        // Queue is empty, we can start this change.

        if (flags & IOPMWeInitiated ) {
            start_our_change(newNote);
            return 0;
        }
        else {
            return start_parent_change(newNote);
        }
    }

    // The queue is not empty.  Try to collapse this new change and the previous one in queue into one change.
    // This is possible only if both changes are initiated by us, and neither has been started yet.
    // Do this more than once if possible.

    // (A change is started iff it is at the head of the queue)

    while ( (previousNote != priv->head_note) &&  (previousNote != -1) &&
            (priv->changeList->changeNote[newNote].flags &  priv->changeList->changeNote[previousNote].flags &  IOPMWeInitiated)  ) {
        priv->changeList->changeNote[previousNote].outputPowerCharacter = priv->changeList->changeNote[newNote].outputPowerCharacter;
        priv->changeList->changeNote[previousNote].inputPowerRequirement = priv->changeList->changeNote[newNote].inputPowerRequirement;
        priv->changeList->changeNote[previousNote].capabilityFlags =priv-> changeList->changeNote[newNote].capabilityFlags;
        priv->changeList->changeNote[previousNote].newStateNumber = priv->changeList->changeNote[newNote].newStateNumber;
        priv->changeList->releaseTailChangeNote();
        newNote = previousNote;
        previousNote = priv->changeList->previousChangeNote(newNote);
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogCollapseQueue,0,0);
    }
    return IOPMWillAckLater;				// in any case, we can't start yet
}


//*********************************************************************************
// notifyAll
//
// Notify all interested parties either that a change is impending or that the
// previously-notified change is done and power has settled.
// The parameter identifies whether this is the
// pre-change notification or the post-change notification.
//
//*********************************************************************************

IOReturn IOService::notifyAll ( bool is_prechange )
{
    IOPMinformee *		nextObject;
    OSIterator *			iter;
    OSObject *			next;
    IOPowerConnection *	connection;

    // To prevent acknowledgePowerChange from finishing the change note and removing it from the queue if
    // some driver calls it, we inflate the number of pending acks so it cannot become zero.  We'll fix it later.

    priv->head_note_pendingAcks =1;

    // OK, we will go through the lists of interested drivers and power domain children
    // and notify each one of this change.

    nextObject =  priv->interestedDrivers->firstInList();		// notify interested drivers
    while (  nextObject != NULL ) {
        priv->head_note_pendingAcks +=1;
        if (! inform(nextObject, is_prechange) ) {
        }
        nextObject  =  priv->interestedDrivers->nextInList(nextObject);
    }

    if (! acquire_lock() ) {
        return IOPMNoErr;
    }
    if ( priv->head_note_pendingAcks > 1 ) {					// did they all ack?
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogStartAckTimer,0,0);	// no
        start_ack_timer();
    }
    IOUnlock(priv->our_lock);							// either way

    iter = getChildIterator(gIOPowerPlane);

    if ( iter ) {
        while ( (next = iter->getNextObject()) ) {
            if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) {
                priv->head_note_pendingAcks +=1;
                notifyChild(connection, is_prechange);
            }
        }
        iter->release();
    }

    if (! acquire_lock() ) {
        return IOPMNoErr;
    }
    priv->head_note_pendingAcks -= 1;			// now make this real
    if (priv->head_note_pendingAcks == 0 ) {		// is it all acked?
        IOUnlock(priv->our_lock);			// yes
        return IOPMAckImplied;				// return ack to parent
    }
    IOUnlock(priv->our_lock);				// no
    return IOPMWillAckLater;
}


//*********************************************************************************
// notifyChild
//
// Notify a power domain child of an upcoming power change.
//
// If the object acknowledges the current change, we return TRUE.
//*********************************************************************************

bool IOService::notifyChild ( IOPowerConnection * theNub, bool is_prechange )
{
    IOReturn k = IOPMAckImplied;

   if ( is_prechange ) {
       k =((IOService *)(theNub->getChildEntry(gIOPowerPlane)))->powerDomainWillChangeTo( priv->head_note_outputFlags,theNub);
   }
   else {
       k =((IOService *)(theNub->getChildEntry(gIOPowerPlane)))->powerDomainDidChangeTo( priv->head_note_outputFlags,theNub);
   }

   if ( k == IOPMAckImplied ) {					// did the return code ack?
       priv->head_note_pendingAcks -=1;				// yes
       return true;
   }
   return false;
}


//*********************************************************************************
// inform
//
// Notify an interested driver of an upcoming power change.
//
// If the object acknowledges the current change, we return TRUE.
//*********************************************************************************

bool IOService::inform ( IOPMinformee * nextObject, bool is_prechange )
{
    IOReturn k = IOPMAckImplied;

   nextObject->timer = -1;					// initialize this

   if ( is_prechange ) {
       pm_vars->thePlatform->PMLog (pm_vars->ourName,PMlogInformDriverPreChange,
                                    (unsigned long)priv->head_note_capabilityFlags,(unsigned long)priv->head_note_state);
       k = nextObject->whatObject->powerStateWillChangeTo( priv->head_note_capabilityFlags,priv->head_note_state,this);
   }
   else {
       pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogInformDriverPostChange,
                                   (unsigned long)priv->head_note_capabilityFlags,(unsigned long)priv->head_note_state);
       k = nextObject->whatObject->powerStateDidChangeTo(priv->head_note_capabilityFlags,priv->head_note_state,this);
   }

   if ( nextObject->timer == 0 ) {				// did it ack behind our back?
       return true;						// yes
   }
   if ( k ==IOPMAckImplied ) {					// no, did the return code ack?
       nextObject->timer = 0;					// yes
       priv->head_note_pendingAcks -= 1;
       return true;
   }
   if ( k < 0 ) {
       nextObject->timer = 0;					// somebody goofed
       priv-> head_note_pendingAcks -= 1;
       return true;
  }
   nextObject->timer = (k * ns_per_us / ACK_TIMER_PERIOD) + 1;	// no, it's a timer
   return false;
}


//*********************************************************************************
// our_prechange_03
//
// All registered applications and kernel clients have positively acknowledged our
// intention of lowering power.  Here we notify them all that we will definitely
// lower the power.  If we don't have to wait for any of them to acknowledge, we
// carry on by notifying interested drivers.  Otherwise, we do wait.
//*********************************************************************************

void IOService::our_prechange_03 ( void )
{
    priv->machine_state = IOPMour_prechange_05;		// next state
    if ( tellChangeDown(priv->head_note_state) ) {  	// are we waiting for responses?
        return our_prechange_05();                      // no, notify interested drivers
    }
}


//*********************************************************************************
// our_prechange_05
//
// All registered applications and kernel clients have acknowledged our notification
// that we are lowering power.  Here we notify interested drivers.  If we don't have
// to wait for any of them to acknowledge, we instruct our power driver to make the change.
// Otherwise, we do wait.
//*********************************************************************************

void IOService::our_prechange_05 ( void )
{
    priv->machine_state = IOPMour_prechange_1;		// no, in case they don't all ack
    if ( notifyAll(true) == IOPMAckImplied ) {
        our_prechange_1();
    }
}


//*********************************************************************************
// our_prechange_1
//
// All interested drivers have acknowledged our pre-change notification of a power
// change we initiated.  Here we instruct our controlling driver to make
// the change to the hardware.  If it does so, we continue processing
// (waiting for settle and notifying interested parties post-change.)
// If it doesn't, we have to wait for it to acknowledge and then continue.
//*********************************************************************************

void IOService::our_prechange_1 ( void )
{
    if ( instruct_driver(priv->head_note_state) == IOPMAckImplied ) {
        our_prechange_2();					// it's done, carry on
    }
    else {
        priv->machine_state = IOPMour_prechange_2;		// it's not, wait for it
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogStartAckTimer,0,0);
        start_ack_timer();
    }
}


//*********************************************************************************
// our_prechange_2
//
// Our controlling driver has changed power state on the hardware
// during a power change we initiated.  Here we see if we need to wait
// for power to settle before continuing.  If not, we continue processing
// (notifying interested parties post-change).  If so, we wait and
// continue later.
//*********************************************************************************

void IOService::our_prechange_2 ( void )
{
    priv->settle_time = compute_settle_time();
    if ( priv->settle_time == 0 ) {
       our_prechange_3();
    }
    else {
        priv->machine_state = IOPMour_prechange_3;
        startSettleTimer(priv->settle_time);
    }
}


//*********************************************************************************
// our_prechange_3
//
// Power has settled on a power change we initiated.  Here we notify
// all our interested parties post-change.  If they all acknowledge, we're
// done with this change note, and we can start on the next one.
// Otherwise we have to wait for acknowledgements and finish up later.
//*********************************************************************************

void IOService::our_prechange_3 ( void )
{
    priv->machine_state = IOPMour_prechange_4;		// in case they don't all ack
    if ( notifyAll(false) == IOPMAckImplied ) {
        our_prechange_4();
    }
}


//*********************************************************************************
// our_prechange_4
//
// Power has settled on a power change we initiated, and
// all our interested parties have acknowledged.  We're
// done with this change note, and we can start on the next one.
//*********************************************************************************

void IOService::our_prechange_4 ( void )
{
    all_done();
}


//*********************************************************************************
// parent_down_0
//
// All applications and kernel clients have been notified of a power lowering
// initiated by the parent and we didn't have to wait for any responses.  Here
// we notify any interested drivers and power domain children.  If they all ack,
// we continue with the power change.
// If at least one doesn't, we have to wait for it to acknowledge and then continue.
//*********************************************************************************

IOReturn IOService::parent_down_0 ( void )
{
    priv->machine_state = IOPMparent_down_4;            // in case they don't all ack
    if ( notifyAll(true) == IOPMAckImplied ) {
        return parent_down_1();                         // they did
    }
    return IOPMWillAckLater;                            // they didn't
}


//*********************************************************************************
// parent_down_05
//
// All applications and kernel clients have been notified of a power lowering
// initiated by the parent and we had to wait for their responses.  Here we notify
// any interested drivers and power domain children.  If they all ack, we continue
// with the power change.
// If at least one doesn't, we have to wait for it to acknowledge and then continue.
//*********************************************************************************

void IOService::parent_down_05 ( void )
{
    priv->machine_state = IOPMparent_down_4;            // in case they don't all ack
    if ( notifyAll(true) == IOPMAckImplied ) {
        parent_down_4();                                // they did
    }
}


//*********************************************************************************
// parent_down_1
//
// All parties have acknowledged our pre-change notification of a power
// lowering initiated by the parent.  Here we instruct our controlling driver
// to put the hardware in the state it needs to be in when the domain is
// lowered.  If it does so, we continue processing
// (waiting for settle and acknowledging the parent.)
// If it doesn't, we have to wait for it to acknowledge and then continue.
//*********************************************************************************

IOReturn IOService::parent_down_1 ( void )
{
    if ( instruct_driver(priv->head_note_state) == IOPMAckImplied ) {
        return parent_down_2();			// it's done, carry on
    }
    priv->machine_state = IOPMparent_down_5;	// it's not, wait for it
    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogStartAckTimer,0,0);
    start_ack_timer();
    return IOPMWillAckLater;
}


//*********************************************************************************
// parent_down_4
//
// We had to wait for it, but all parties have acknowledged our pre-change
// notification of a power lowering initiated by the parent.
// Here we instruct our controlling driver
// to put the hardware in the state it needs to be in when the domain is
// lowered.  If it does so, we continue processing
// (waiting for settle and acknowledging the parent.)
// If it doesn't, we have to wait for it to acknowledge and then continue.
//*********************************************************************************

void IOService::parent_down_4 ( void )
{
    if ( instruct_driver(priv->head_note_state) == IOPMAckImplied ) {
        parent_down_5();					// it's done, carry on
    }
    else {
        priv-> machine_state = IOPMparent_down_5;	// it's not, wait for it
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogStartAckTimer,0,0);
        start_ack_timer();
    }
}


//*********************************************************************************
// parent_down_2
//
// Our controlling driver has changed power state on the hardware
// during a power change initiated by our parent.  Here we see if we need
// to wait for power to settle before continuing.  If not, we continue
// processing (acknowledging our preparedness to the parent).
// If so, we wait and continue later.
//*********************************************************************************

IOReturn IOService::parent_down_2 ( void )
{
    priv->settle_time = compute_settle_time();
    if ( priv->settle_time == 0 ) {
        priv->machine_state = IOPMparent_down_6;	// in case they don't all ack
        if ( notifyAll(false) == IOPMAckImplied ) {
            all_done();
            return IOPMAckImplied;
        }
        return IOPMWillAckLater;			// they didn't
   }
   else {
       priv->machine_state = IOPMparent_down_3;
       startSettleTimer(priv->settle_time);
       return IOPMWillAckLater;
   }
}


//*********************************************************************************
// parent_down_5
//
// Our controlling driver has changed power state on the hardware
// during a power change initiated by our parent.  We have had to wait
// for acknowledgement from interested parties, or we have had to wait
// for the controlling driver to change the state.  Here we see if we need
// to wait for power to settle before continuing.  If not, we continue
// processing (acknowledging our preparedness to the parent).
// If so, we wait and continue later.
//*********************************************************************************

void IOService::parent_down_5 ( void )
{
    priv->settle_time = compute_settle_time();
    if ( priv->settle_time == 0 ) {
        parent_down_3();
   }
   else {
       priv->machine_state = IOPMparent_down_3;
       startSettleTimer(priv->settle_time);
   }
}


//*********************************************************************************
// parent_down_3
//
// Power has settled on a power change initiated by our parent.  Here we
// notify interested parties.
//*********************************************************************************

void IOService::parent_down_3 ( void )
{
    IOService * parent;

    priv->machine_state = IOPMparent_down_6;	// in case they don't all ack
    if ( notifyAll(false) == IOPMAckImplied ) {
        parent = priv->head_note_parent;
        all_done();
        ((IOService *)(parent->getParentEntry(gIOPowerPlane)))->acknowledgePowerChange(parent);
    }
}


//*********************************************************************************
// parent_down_6
//
// We had to wait for it, but all parties have acknowledged our post-change
// notification of a power  lowering initiated by the parent.
// Here we acknowledge the parent.
// We are done with this change note, and we can start on the next one.
//*********************************************************************************

void IOService::parent_down_6 ( void )
{
    IOService * parent;
    
    parent = priv->head_note_parent;
    all_done();
    ((IOService *)(parent->getParentEntry(gIOPowerPlane)))->acknowledgePowerChange(parent);
}


//*********************************************************************************
// parent_up_0
//
// Our parent has informed us via powerStateDidChange that it has
// raised the power in our power domain, and we have had to wait
// for some interested party to acknowledge our notification.
//   Here we instruct our controlling
// driver to program the hardware to take advantage of the higher domain
// power.  If it does so, we continue processing
// (waiting for settle and notifying interested parties post-change.)
// If it doesn't, we have to wait for it to acknowledge and then continue.
//*********************************************************************************

void IOService::parent_up_0 ( void )
{
    if ( instruct_driver(priv->head_note_state) == IOPMAckImplied ) {
        parent_up_4();					// it did it, carry on
    }
    else {
        priv->machine_state = IOPMparent_up_4;	// it didn't, wait for it
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogStartAckTimer,0,0);
        start_ack_timer();
    }
}


//*********************************************************************************
// parent_up_1
//
// Our parent has informed us via powerStateDidChange that it has
// raised the power in our power domain.  Here we instruct our controlling
// driver to program the hardware to take advantage of the higher domain
// power.  If it does so, we continue processing
// (waiting for settle and notifying interested parties post-change.)
// If it doesn't, we have to wait for it to acknowledge and then continue.
//*********************************************************************************

IOReturn IOService::parent_up_1 ( void )
{
    if ( instruct_driver(priv->head_note_state) == IOPMAckImplied ) {
        return parent_up_2();				// it did it, carry on
    }
    else {
        priv->machine_state = IOPMparent_up_4;	// it didn't, wait for it
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogStartAckTimer,0,0);
        start_ack_timer();
        return IOPMWillAckLater;
    }
}


//*********************************************************************************
// parent_up_2
//
// Our controlling driver has changed power state on the hardware
// during a power raise initiated by the parent.  Here we see if we need to wait
// for power to settle before continuing.  If not, we continue processing
// (notifying interested parties post-change).  If so, we wait and
// continue later.
//*********************************************************************************

IOReturn IOService::parent_up_2 ( void )
{
    priv->settle_time = compute_settle_time();
    if ( priv->settle_time == 0 ) {
        return parent_up_3();
  }
  else {
      priv->machine_state = IOPMparent_up_5;
      startSettleTimer(priv->settle_time);
      return IOPMWillAckLater;
  }
}


//*********************************************************************************
// parent_up_4
//
// Our controlling driver has changed power state on the hardware
// during a power raise initiated by the parent, but we had to wait for it.
// Here we see if we need to wait for power to settle before continuing.
// If not, we continue processing  (notifying interested parties post-change).
// If so, we wait and continue later.
//*********************************************************************************

void IOService::parent_up_4 ( void )
{
    priv->settle_time = compute_settle_time();
    if ( priv->settle_time == 0 ) {
        parent_up_5();
  }
  else {
      priv->machine_state = IOPMparent_up_5;
      startSettleTimer(priv->settle_time);
  }
}


//*********************************************************************************
// parent_up_3
//
// No power settling was required on a power raise initiated by the parent.
// Here we notify all our interested parties post-change.  If they all acknowledge,
// we're done with this change note, and we can start on the next one.
// Otherwise we have to wait for acknowledgements and finish up later.
//*********************************************************************************

IOReturn IOService::parent_up_3 ( void )
{
    priv->machine_state = IOPMparent_up_6;	// in case they don't all ack
    if ( notifyAll(false) == IOPMAckImplied ) {
        all_done();
        return IOPMAckImplied;
    }
    return IOPMWillAckLater;			// they didn't
}


//*********************************************************************************
// parent_up_5
//
// Power has settled on a power raise initiated by the parent.
// Here we notify all our interested parties post-change.  If they all acknowledge,
// we're done with this change note, and we can start on the next one.
// Otherwise we have to wait for acknowledgements and finish up later.
//*********************************************************************************

void IOService::parent_up_5 ( void )
{
    priv->machine_state = IOPMparent_up_6;	// in case they don't all ack
    if ( notifyAll(false) == IOPMAckImplied ) {
        parent_up_6();
    }
}


//*********************************************************************************
// parent_up_6
//
// All parties have acknowledged our post-change notification of a power
// raising initiated by the parent.  Here we acknowledge the parent.
// We are done with this change note, and we can start on the next one.
//*********************************************************************************

void IOService::parent_up_6 ( void )
{
    IOService * parent;
    
    parent = priv->head_note_parent;
    all_done();
    ((IOService *)(parent->getParentEntry(gIOPowerPlane)))->acknowledgePowerChange(parent);
}


//*********************************************************************************
// all_done
//
// A power change is complete, and the used post-change note is at
// the head of the queue.  Remove it and set myCurrentState to the result
// of the change.  Start up the next change in queue.
//*********************************************************************************

void IOService::all_done ( void )
{    
    priv->machine_state = IOPMfinished;

    if ( priv->head_note_flags & IOPMWeInitiated ) {				// our power change
        if ( !( priv->head_note_flags & IOPMNotDone) ) {			// could our driver switch to the new state?
            if ( pm_vars->myCurrentState < priv->head_note_state ) {		// yes, did power raise?
                tellChangeUp (priv->head_note_state);				// yes, inform clients and apps
            }
            else {
                if ( !  priv->we_are_root ) {					// no, if this lowers our
                    ask_parent(priv->head_note_state);				// power requirements, tell the parent
                }
            }
            pm_vars->myCurrentState = priv->head_note_state;			// either way
            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogChangeDone,(unsigned long)pm_vars->myCurrentState,0);
            powerChangeDone(pm_vars->myCurrentState);				// inform subclass policy-maker
        }
//        else {									// no
//            pm_vars->myCurrentState = pm_vars->theControllingDriver->powerStateForDomainState(pm_vars->parentsCurrentPowerFlags);
//        }
    }
    if ( priv->head_note_flags & IOPMParentInitiated) {				// parent's power change
        if ( ((priv->head_note_flags & IOPMDomainWillChange) && (pm_vars->myCurrentState >= priv->head_note_state)) ||
             ((priv->head_note_flags & IOPMDomainDidChange) && (pm_vars->myCurrentState < priv->head_note_state)) ) {
            if ( pm_vars->myCurrentState < priv->head_note_state ) {		// did power raise?
                tellChangeUp (priv->head_note_state);				// yes, inform clients and apps
            }
            pm_vars->myCurrentState = priv->head_note_state;			// either way
            pm_vars->maxCapability = pm_vars->theControllingDriver->maxCapabilityForDomainState(priv->head_note_domainState);

            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogChangeDone,(unsigned long)pm_vars->myCurrentState,0);
            powerChangeDone(pm_vars->myCurrentState);				// inform subclass policy-maker
        }
    }

    priv->changeList->releaseHeadChangeNote();					// we're done with this
        
    priv->head_note = priv->changeList->currentChange();				// start next one in queue
    if ( priv->head_note != -1 ) {

        if (priv->changeList->changeNote[priv->head_note].flags & IOPMWeInitiated ) {
            start_our_change(priv->head_note);
        }
        else {
            if ( start_parent_change(priv->head_note) == IOPMAckImplied ) {
            ((IOService *)(priv->head_note_parent->getParentEntry(gIOPowerPlane)))->acknowledgePowerChange(priv->head_note_parent);
            }
        }
    }
}



//*********************************************************************************
// all_acked
//
// A driver or child has acknowledged our notification of an upcoming power
// change, and this acknowledgement is the last one pending
// before we change power or after changing power.
//
//*********************************************************************************

void IOService::all_acked ( void )
{
    switch (priv->machine_state) {
       case IOPMour_prechange_1:
           our_prechange_1();
           break;
       case IOPMour_prechange_4:
           our_prechange_4();
           break;
       case IOPMparent_down_4:
           parent_down_4();	
           break;
       case IOPMparent_down_6:
           parent_down_6();
           break;
       case IOPMparent_up_0:
           parent_up_0();
           break;
       case IOPMparent_up_6:
           parent_up_6();
           break;
   }
}


//*********************************************************************************
// settleTimerExpired
//
// Power has settled after our last change.  Notify interested parties that
// there is a new power state.
//*********************************************************************************

void IOService::settleTimerExpired ( void )
{
    if ( ! initialized ) {
        return;					// we're unloading
    }

    switch (priv->machine_state) {
        case IOPMour_prechange_3:
            our_prechange_3();
            break;
        case IOPMparent_down_3:
            parent_down_3();
            break;
        case IOPMparent_up_5:
            parent_up_5();
            break;
    }
}


//*********************************************************************************
// compute_settle_time
//
// Compute the power-settling delay in microseconds for the
// change from myCurrentState to head_note_state.
//*********************************************************************************

unsigned long IOService::compute_settle_time ( void )
{
    unsigned long totalTime;
    unsigned long i;

    totalTime = 0;						// compute total time to attain the new state
    i = pm_vars->myCurrentState;
    if ( priv->head_note_state < pm_vars->myCurrentState ) {	// we're lowering power
        while ( i > priv->head_note_state ) {
            totalTime +=  pm_vars->thePowerStates[i].settleDownTime;
            i--;
        }
    }

    if ( priv->head_note_state > pm_vars->myCurrentState ) {	// we're raising power
        while ( i < priv->head_note_state ) {
            totalTime +=  pm_vars->thePowerStates[i+1].settleUpTime;
            i++;
        }
    }

    return totalTime;
}


//*********************************************************************************
// startSettleTimer
//
// Enter with a power-settling delay in microseconds and start a nano-second
// timer for that delay.
//*********************************************************************************

IOReturn IOService::startSettleTimer ( unsigned long delay )
{
    AbsoluteTime	deadline;
    
    clock_interval_to_deadline(delay, kMicrosecondScale, &deadline);

    thread_call_enter_delayed(priv->settleTimer, deadline);

    return IOPMNoErr;
}

//*********************************************************************************
// ack_timer_ticked
//
// The acknowledgement timeout periodic timer has ticked.
// If we are awaiting acks for a power change notification,
// we decrement the timer word of each interested driver which hasn't acked.
// If a timer word becomes zero, we pretend the driver aknowledged.
// If we are waiting for the controlling driver to change the power
// state of the hardware, we decrement its timer word, and if it becomes
// zero, we pretend the driver acknowledged.
//*********************************************************************************

void IOService::ack_timer_ticked ( void )
{
    IOPMinformee * nextObject;

    if ( ! initialized ) {
        return;					// we're unloading
    }

    if (! acquire_lock() ) {
        return;
    }
    
    switch (priv->machine_state) {
        case IOPMour_prechange_2:
        case IOPMparent_down_5:
        case IOPMparent_up_4:
            if ( priv->driver_timer != 0 ) {                            // are we waiting for our driver to make its change?
                priv->driver_timer -= 1;                                // yes, tick once
                if ( priv->driver_timer == 0 ) {                        // it's tardy, we'll go on without it
                    IOUnlock(priv->our_lock);
                    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogCtrlDriverTardy,0,0);
                    driver_acked();
                }
                else {                                                  // still waiting, set timer again
                    start_ack_timer();
                    IOUnlock(priv->our_lock);
                }
            }
            else {
                IOUnlock(priv->our_lock);
            }
            break;

        case IOPMour_prechange_1:
        case IOPMour_prechange_4:
        case IOPMparent_down_4:
        case IOPMparent_down_6:
        case IOPMparent_up_0:
        case IOPMparent_up_6:
            if (priv->head_note_pendingAcks != 0 ) {                    // are we waiting for interested parties to acknowledge?
                nextObject =  priv->interestedDrivers->firstInList();   // yes, go through the list of interested drivers
                while (  nextObject != NULL ) {                         // and check each one
                    if ( nextObject->timer > 0 ) {
                        nextObject->timer -= 1;
                        if ( nextObject->timer == 0 ) {                 // this one should have acked by now
                            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogIntDriverTardy,0,0);
                            kprintf("interested driver tardy: %s\n",nextObject->whatObject->getName());
                            priv->head_note_pendingAcks -= 1;
                        }
                    }
                    nextObject  =  priv->interestedDrivers->nextInList(nextObject);
                }
                if ( priv->head_note_pendingAcks == 0 ) {       // is that the last?
                    IOUnlock(priv->our_lock);
                    all_acked();                                // yes, we can continue
                }
                else {                                          // no, set timer again
                    start_ack_timer();
                    IOUnlock(priv->our_lock);
                }
            }
            else {
                IOUnlock(priv->our_lock);
            }
            break;

        case IOPMparent_down_0:                                 // apps didn't respond to parent-down notification
            IOUnlock(priv->our_lock);
            IOLockLock(priv->flags_lock);
            if (pm_vars->responseFlags) {
                pm_vars->responseFlags->release();              // get rid of this stuff
                pm_vars->responseFlags = NULL;
            }
            IOLockUnlock(priv->flags_lock);
            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogClientTardy,0,1);
            parent_down_05();                                   // carry on with the change
            break;
            
        case IOPMour_prechange_03:                              // apps didn't respond to our power-down request
            IOUnlock(priv->our_lock);
            IOLockLock(priv->flags_lock);
            if (pm_vars->responseFlags) {
                pm_vars->responseFlags->release();              // get rid of this stuff
                pm_vars->responseFlags = NULL;
            }
            IOLockUnlock(priv->flags_lock);
            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogClientTardy,0,2);
            tellNoChangeDown(priv->head_note_state);		// rescind the request
            priv->head_note_flags |= IOPMNotDone;		// mark the change note un-actioned
            all_done();						// and we're done
            break;
            
        case IOPMour_prechange_05:                              // apps didn't respond to our power-down notification
            IOUnlock(priv->our_lock);
            IOLockLock(priv->flags_lock);
            if (pm_vars->responseFlags) {
                pm_vars->responseFlags->release();              // get rid of this stuff
                pm_vars->responseFlags = NULL;
            }
            IOLockUnlock(priv->flags_lock);
            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogClientTardy,0,3);
            our_prechange_05();                               	// carry on with the change
            break;
            
        default:
            IOUnlock(priv->our_lock);                           // not waiting for acks
            break;
    }
}


//*********************************************************************************
// start_ack_timer
//
//*********************************************************************************

void IOService::start_ack_timer ( void )
{
    AbsoluteTime	deadline;

    clock_interval_to_deadline(ACK_TIMER_PERIOD, kNanosecondScale, &deadline);
    
    thread_call_enter_delayed(priv->ackTimer, deadline);
}


//*********************************************************************************
// stop_ack_timer
//
//*********************************************************************************

void IOService::stop_ack_timer ( void )
{
    thread_call_cancel(priv->ackTimer);
}


//*********************************************************************************
// c-language timer expiration functions
//
//*********************************************************************************

static void ack_timer_expired ( thread_call_param_t us)
{
    ((IOService *)us)->ack_timer_ticked();
}


static void settle_timer_expired ( thread_call_param_t us)
{
    ((IOService *)us)->settleTimerExpired();
}


//*********************************************************************************
// add_child_to_active_change
//
// A child has just registered with us.  If there is
// currently a change in progress, get the new party involved: if we
// have notified all parties and are waiting for acks, notify the new
// party.
//*********************************************************************************

IOReturn IOService::add_child_to_active_change ( IOPowerConnection * newObject )
{
    if (! acquire_lock() ) {
        return IOPMNoErr;
    }

    switch (priv->machine_state) {
        case IOPMour_prechange_1:
        case IOPMparent_down_4:
        case IOPMparent_up_0:
            priv->head_note_pendingAcks += 2;		// one for this child and one to prevent
            IOUnlock(priv->our_lock);			// incoming acks from changing our state
            notifyChild(newObject, true);
            if (! acquire_lock() ) {
                --priv->head_note_pendingAcks;		// put it back
                return IOPMNoErr;
            }
            if ( --priv->head_note_pendingAcks == 0 ) {	// are we still waiting for acks?
                stop_ack_timer();			// no, stop the timer
                IOUnlock(priv->our_lock);
                all_acked();				// and now we can continue
                return IOPMNoErr;
            }
            break;
        case IOPMour_prechange_4:
        case IOPMparent_down_6:
        case IOPMparent_up_6:
            priv->head_note_pendingAcks += 2;		// one for this child and one to prevent
            IOUnlock(priv->our_lock);			// incoming acks from changing our state
            notifyChild(newObject, false);
            if (! acquire_lock() ) {
                --priv->head_note_pendingAcks;		// put it back
                return IOPMNoErr;
            }
            if ( --priv->head_note_pendingAcks == 0 ) {	// are we still waiting for acks?
                stop_ack_timer();			// no, stop the timer
                IOUnlock(priv->our_lock);
                all_acked();				// and now we can continue
                return IOPMNoErr;
            }
            break;
    }
    IOUnlock(priv->our_lock);
    return IOPMNoErr;
}


//*********************************************************************************
// add_driver_to_active_change
//
// An interested driver has just registered with us.  If there is
// currently a change in progress, get the new party involved: if we
// have notified all parties and are waiting for acks, notify the new
// party.
//*********************************************************************************

IOReturn IOService::add_driver_to_active_change ( IOPMinformee * newObject )
{
    if (! acquire_lock() ) {
        return IOPMNoErr;
    }

    switch (priv->machine_state) {
        case IOPMour_prechange_1:
        case IOPMparent_down_4:
        case IOPMparent_up_0:
            priv->head_note_pendingAcks += 2;		// one for this driver and one to prevent
            IOUnlock(priv->our_lock);			// incoming acks from changing our state
            inform(newObject, true);			// inform the driver
            if (! acquire_lock() ) {
                --priv->head_note_pendingAcks;		// put it back
                return IOPMNoErr;
            }
            if ( --priv->head_note_pendingAcks == 0 ) {	// are we still waiting for acks?
                stop_ack_timer();			// no, stop the timer
                IOUnlock(priv->our_lock);
                all_acked();				// and now we can continue
                return IOPMNoErr;
            }
            break;
        case IOPMour_prechange_4:
        case IOPMparent_down_6:
        case IOPMparent_up_6:
            priv->head_note_pendingAcks += 2;		// one for this driver and one to prevent
            IOUnlock(priv->our_lock);			// incoming acks from changing our state
            inform(newObject, false);			// inform the driver
            if (! acquire_lock() ) {
                --priv->head_note_pendingAcks;		// put it back
                return IOPMNoErr;
            }
            if ( --priv->head_note_pendingAcks == 0 ) {	// are we still waiting for acks?
                stop_ack_timer();			// no, stop the timer
                IOUnlock(priv->our_lock);
                all_acked();				// and now we can continue
                return IOPMNoErr;
            }
            break;
    }
    IOUnlock(priv->our_lock);
    return IOPMNoErr;
}


//*********************************************************************************
// start_parent_change
//
// Here we begin the processing of a change note  initiated by our parent
// which is at the head of the queue.
//
// It is possible for the change to be processed to completion and removed from the queue.
// There are several possible interruptions to the processing, though, and they are:
// we may have to wait for interested parties to acknowledge our pre-change notification,
// we may have to wait for our controlling driver to change the hardware power state,
// there may be a settling time after changing the hardware power state,
// we may have to wait for interested parties to acknowledge our post-change notification,
// we may have to wait for the acknowledgement timer expiration to substitute for the
// acknowledgement from a failing driver.
//*********************************************************************************

IOReturn IOService::start_parent_change ( unsigned long queue_head )
{
    priv->head_note = queue_head;
    priv->head_note_flags = priv-> changeList->changeNote[priv->head_note].flags;
    priv->head_note_state =  priv->changeList->changeNote[priv->head_note].newStateNumber;
    priv->head_note_outputFlags =  priv->changeList->changeNote[priv->head_note].outputPowerCharacter;
    priv->head_note_domainState = priv->changeList->changeNote[priv->head_note].domainState;
    priv->head_note_parent = priv->changeList->changeNote[priv->head_note].parent;
    priv->head_note_capabilityFlags =  priv->changeList->changeNote[priv->head_note].capabilityFlags;

    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogStartParentChange,
                    (unsigned long)priv->head_note_state,(unsigned long)pm_vars->myCurrentState);

    ask_parent( priv->ourDesiredPowerState);			// if we need something and haven't told the parent, do so

    if ( priv->head_note_state < pm_vars->myCurrentState ) {    // power domain is lowering
	priv->initial_change = false;
        priv->machine_state = IOPMparent_down_0;                // tell apps and kernel clients
        if ( tellChangeDown(priv->head_note_state) ) {  	// are we waiting for responses?
            return parent_down_0();                             // no, notify interested drivers
        }
       return IOPMWillAckLater;                                 // yes
    }

    if ( priv->head_note_state > pm_vars->myCurrentState ) {		// parent is raising power, we may or may not
        if ( priv->ourDesiredPowerState > pm_vars->myCurrentState ) {
           if ( priv->ourDesiredPowerState < priv->head_note_state ) {
               priv->head_note_state = priv->ourDesiredPowerState;	// we do, but not all the way
               priv->head_note_outputFlags =   pm_vars->thePowerStates[priv->head_note_state].outputPowerCharacter;
               priv->head_note_capabilityFlags =   pm_vars->thePowerStates[priv->head_note_state].capabilityFlags;
               pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogAmendParentChange,(unsigned long)priv->head_note_state,0);
            }
        }
        else {
            priv-> head_note_state = pm_vars->myCurrentState;		// we don't
            priv->head_note_outputFlags =   pm_vars->thePowerStates[priv->head_note_state].outputPowerCharacter;
            priv->head_note_capabilityFlags =   pm_vars->thePowerStates[priv->head_note_state].capabilityFlags;
            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogAmendParentChange,(unsigned long)priv->head_note_state,0);
        }
    }

    if ( (priv->head_note_state > pm_vars->myCurrentState) &&
         (priv->head_note_flags & IOPMDomainDidChange) ) {		// changing up
        priv->initial_change = false;
	priv->machine_state = IOPMparent_up_0;
	if (  notifyAll(true) == IOPMAckImplied ) {
            return parent_up_1();
	}
	return IOPMWillAckLater;					// they didn't all ack
    }

    all_done();
    return IOPMAckImplied;						// a null change or power will go up
}


//*********************************************************************************
// start_our_change
//
// Here we begin the processing of a change note  initiated by us
// which is at the head of the queue.
//
// It is possible for the change to be processed to completion and removed from the queue.
// There are several possible interruptions to the processing, though, and they are:
// we may have to wait for interested parties to acknowledge our pre-change notification,
// changes initiated by the parent will wait in the middle for powerStateDidChange,
// we may have to wait for our controlling driver to change the hardware power state,
// there may be a settling time after changing the hardware power state,
// we may have to wait for interested parties to acknowledge our post-change notification,
// we may have to wait for the acknowledgement timer expiration to substitute for the
// acknowledgement from a failing driver.
//*********************************************************************************

void IOService::start_our_change ( unsigned long queue_head )
{
    priv->head_note = queue_head;
    priv->head_note_flags =  priv->changeList->changeNote[priv->head_note].flags;
    priv->head_note_state =  priv->changeList->changeNote[priv->head_note].newStateNumber;
    priv->head_note_outputFlags =  priv->changeList->changeNote[priv->head_note].outputPowerCharacter;
    priv->head_note_capabilityFlags =  priv->changeList->changeNote[priv->head_note].capabilityFlags;

    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogStartDeviceChange,
                (unsigned long)priv->head_note_state,(unsigned long)pm_vars->myCurrentState);

    if ( priv->head_note_capabilityFlags & IOPMNotAttainable ) {	// can our driver switch to the new state?
        if ( !  priv->we_are_root ) {					// no, ask the parent to do it then
            ask_parent(priv->head_note_state);
        }
        priv-> head_note_flags |= IOPMNotDone;				// mark the change note un-actioned
        all_done();							// and we're done
        return;
    }
                                                                        // is there enough power in the domain?
    if ( (pm_vars->maxCapability < priv->head_note_state) && (!  priv->we_are_root) ) {
        if ( !  priv->we_are_root ) {					// no, ask the parent to raise it
            ask_parent(priv->head_note_state);
        }
        priv->head_note_flags |= IOPMNotDone;				// no, mark the change note un-actioned
        all_done();							// and we're done
        return;								// till the parent raises power
    }

    if ( !  priv->initial_change ) {
        if ( priv->head_note_state == pm_vars->myCurrentState ) {
            all_done();						// we initiated a null change; forget it
            return;
        }
    }
    priv->initial_change = false;

    if ( priv->head_note_state < pm_vars->myCurrentState ) {	// dropping power?
        priv->machine_state = IOPMour_prechange_03;		// yes, in case we have to wait for acks
        pm_vars->doNotPowerDown = false;
        if ( askChangeDown(priv->head_note_state) ) {  		// ask apps and kernel clients if we can drop power
            if ( pm_vars->doNotPowerDown ) {			// don't have to wait, did any clients veto?
                tellNoChangeDown(priv->head_note_state);	// yes, rescind the warning
                priv-> head_note_flags |= IOPMNotDone;		// mark the change note un-actioned
                all_done();					// and we're done
            }
            else {
                our_prechange_03();				// no, tell'em we're dropping power
            }
        }
    }
    else {
        if ( !  priv->we_are_root ) {				// we are raising power
            ask_parent(priv->head_note_state);			// if this changes our power requirement, tell the parent
        }
        priv->machine_state = IOPMour_prechange_1;		// in case they don't all ack
        if ( notifyAll(true) == IOPMAckImplied ) {		// notify interested drivers and children
            our_prechange_1();
        }
    }
}


//*********************************************************************************
// ask_parent
//
// Call the power domain parent to ask for a higher power state in the domain
// or to suggest a lower power state.
//*********************************************************************************

IOReturn IOService::ask_parent ( unsigned long requestedState )
{
    OSIterator *			iter;
    OSObject *			next;
    IOPowerConnection *	connection;

    if ( priv->previousRequest ==  pm_vars->thePowerStates[requestedState].inputPowerRequirement ) {	// is this a new desire?
        return IOPMNoErr;							// no, the parent knows already, just return
    }

    if (  priv->we_are_root ) {
        return IOPMNoErr;
    }
    priv->previousRequest =  pm_vars->thePowerStates[requestedState].inputPowerRequirement;

    iter = getParentIterator(gIOPowerPlane);

    if ( iter ) {
        while ( (next = iter->getNextObject()) ) {
            if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) {
                if ( ((IOService *)(connection->getParentEntry(gIOPowerPlane)))->requestPowerDomainState( priv->previousRequest,connection,IOPMLowestState)!= IOPMNoErr ) {
                    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogRequestDenied,(unsigned long)priv->previousRequest,0);
                }
            }
        }
        iter->release();
    }

    return IOPMNoErr;
}


//*********************************************************************************
// instruct_driver
//
// Call the controlling driver and have it change the power state of the
// hardware.  If it returns IOPMAckImplied, the change is complete, and
// we return IOPMAckImplied.  Otherwise, it will ack when the change
// is done; we return IOPMWillAckLater.
//*********************************************************************************

IOReturn IOService::instruct_driver ( unsigned long newState )
{
    IOReturn return_code;

    if (  pm_vars->thePowerStates[newState].capabilityFlags & IOPMNotAttainable ) {	// can our driver switch to the desired state?
        return IOPMAckImplied;						// no, so don't try
    }
    priv->driver_timer = -1;
    
    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogProgramHardware,newState,0);
    return_code = pm_vars->theControllingDriver->setPowerState(  newState,this );	// yes, instruct it
    if ( return_code == IOPMAckImplied ) {					// it finished
        priv->driver_timer = 0;
        return IOPMAckImplied;
    }

    if ( priv->driver_timer == 0 ) {						// it acked behind our back
        return IOPMAckImplied;
    }

    if ( return_code < 0 ) {							// somebody goofed
        return IOPMAckImplied;
    }

    priv->driver_timer = (return_code * ns_per_us / ACK_TIMER_PERIOD) + 1;	// it didn't finish
    return IOPMWillAckLater;
}


//*********************************************************************************
// acquire_lock
//
// We are acquiring the lock we use to protect our queue head from
// simutaneous access by a thread which calls acknowledgePowerStateChange
// or acknowledgeSetPowerState and the ack timer expiration thread.
// Return TRUE if we acquire the lock, and the queue head didn't change
// while we were acquiring the lock (and maybe blocked).
// If there is no queue head, or it changes while we are blocked,
// return FALSE with the lock unlocked.
//*********************************************************************************

bool IOService::acquire_lock ( void )
{
    long current_change_note;

    current_change_note = priv->head_note;
    if ( current_change_note == -1 ) {
        return FALSE;
    }

    IOTakeLock(priv->our_lock);
    if ( current_change_note == priv->head_note ) {
        return TRUE;
    }
    else {					// we blocked and something changed radically
        IOUnlock(priv->our_lock);		// so there's nothing to do any more
        return FALSE;
    }
}


//*********************************************************************************
// askChangeDown
//
// Ask registered applications and kernel clients if we can change to a lower
// power state.
//
// Subclass can override this to send a different message type.  Parameter is
// the destination state number.
//
// Return true if we don't have to wait for acknowledgements
//*********************************************************************************

bool IOService::askChangeDown ( unsigned long )
{
    return tellClientsWithResponse(kIOMessageCanDevicePowerOff);
}


//*********************************************************************************
// tellChangeDown
//
// Notify registered applications and kernel clients that we are definitely
// dropping power.
//
// Subclass can override this to send a different message type.  Parameter is
// the destination state number.
//
// Return true if we don't have to wait for acknowledgements
//*********************************************************************************

bool IOService::tellChangeDown ( unsigned long )
{
    return tellClientsWithResponse(kIOMessageDeviceWillPowerOff);
}


//*********************************************************************************
// tellClientsWithResponse
//
// Notify registered applications and kernel clients that we are definitely
// dropping power.
//
// Return true if we don't have to wait for acknowledgements
//*********************************************************************************

bool IOService::tellClientsWithResponse ( int messageType )
{
    struct context      theContext;
    AbsoluteTime        deadline;
    OSBoolean *         aBool;

    pm_vars->responseFlags = OSArray::withCapacity( 1 );
    pm_vars->serialNumber += 1;
    
    theContext.responseFlags = pm_vars->responseFlags;
    theContext.serialNumber = pm_vars->serialNumber;
    theContext.flags_lock = priv->flags_lock;
    theContext.counter = 1;
    theContext.msgType = messageType;
    theContext.us = this;
    theContext.maxTimeRequested = 0;
    
    IOLockLock(priv->flags_lock);
    aBool = OSBoolean::withBoolean(false);		// position zero is false to   
    theContext.responseFlags->setObject(0,aBool);	// prevent allowCancelCommon from succeeding
    aBool->release();
    IOLockUnlock(priv->flags_lock);

    applyToInterested(gIOAppPowerStateInterest,tellAppWithResponse,(void *)&theContext);
    applyToInterested(gIOGeneralInterest,tellClientWithResponse,(void *)&theContext);

    if (! acquire_lock() ) {
        return true;
    }
    IOLockLock(priv->flags_lock);
    aBool = OSBoolean::withBoolean(true);		// now fix position zero
    theContext.responseFlags->replaceObject(0,aBool);
    aBool->release();
    IOLockUnlock(priv->flags_lock);
    
    if ( ! checkForDone() ) { 				// we have to wait for somebody
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogStartAckTimer,theContext.maxTimeRequested,0);
        clock_interval_to_deadline(theContext.maxTimeRequested / 1000, kMillisecondScale, &deadline);
        
        thread_call_enter_delayed(priv->ackTimer, deadline);
    
        IOUnlock(priv->our_lock);			// yes
        return false;
    }
    
    IOUnlock(priv->our_lock);
    IOLockLock(priv->flags_lock);
    pm_vars->responseFlags->release();			// everybody responded    
    pm_vars->responseFlags = NULL;
    IOLockUnlock(priv->flags_lock);
    
    return true;
}


//*********************************************************************************
// tellAppWithResponse
//
// We send a message to an application, and we expect a response, so we compute a
// cookie we can identify the response with.
//*********************************************************************************
void tellAppWithResponse ( OSObject * object, void * context)
{
    struct context *    theContext = (struct context *)context;
    UInt32              refcon;
    OSBoolean *         aBool;
    
    if( OSDynamicCast( IOService, object) ) {
        IOLockLock(theContext->flags_lock);
        aBool = OSBoolean::withBoolean(true);
        theContext->responseFlags->setObject(theContext->counter,aBool);
        aBool->release();
        IOLockUnlock(theContext->flags_lock);
    }
    else {
        refcon = ((theContext->serialNumber & 0xFFFF)<<16) + (theContext->counter & 0xFFFF);
        IOLockLock(theContext->flags_lock);
        aBool = OSBoolean::withBoolean(false);
        theContext->responseFlags->setObject(theContext->counter,aBool);
        aBool->release();
        IOLockUnlock(theContext->flags_lock);
        theContext->us->messageClient(theContext->msgType,object,(void *)refcon);
        if ( theContext->maxTimeRequested < k15seconds ) {
            theContext->maxTimeRequested = k15seconds;
        }
    }
    theContext->counter += 1;
}


//*********************************************************************************
// tellClientWithResponse
//
// We send a message to an in-kernel client, and we expect a response, so we compute a
// cookie we can identify the response with.
// If it doesn't understand the notification (it is not power-management savvy)
// we won't wait for it to prepare for sleep.  If it tells us via a return code
// in the passed struct that it is currently ready, we won't wait for it to prepare.
// If it tells us via the return code in the struct that it does need time, we will chill.
//*********************************************************************************
void tellClientWithResponse ( OSObject * object, void * context)
{
    struct context *	theContext = (struct context *)context;
    sleepWakeNote	paramBlock;
    UInt32              refcon;
    IOReturn    	retCode;
    OSBoolean * 	aBool;
    OSObject *		theFlag;
    
    refcon = ((theContext->serialNumber & 0xFFFF)<<16) + (theContext->counter & 0xFFFF);
    IOLockLock(theContext->flags_lock);
    aBool = OSBoolean::withBoolean(false);
    theContext->responseFlags->setObject(theContext->counter,aBool);
    aBool->release();
    IOLockUnlock(theContext->flags_lock);
    paramBlock.powerRef = (void *)refcon;
    paramBlock.returnValue = 0;
    retCode = theContext->us->messageClient(theContext->msgType,object,(void *)&paramBlock);
    if ( retCode == kIOReturnSuccess ) {
        if ( paramBlock.returnValue == 0 ) {						// client doesn't want time to respond
            IOLockLock(theContext->flags_lock);
            aBool = OSBoolean::withBoolean(true);
            theContext->responseFlags->replaceObject(theContext->counter,aBool);	// so set its flag true
            aBool->release();
            IOLockUnlock(theContext->flags_lock);
        }
        else {
            IOLockLock(theContext->flags_lock);
            theFlag = theContext->responseFlags->getObject(theContext->counter);	// it does want time, and it hasn't
            if ( theFlag != 0 ) {							// responded yet
                if ( ((OSBoolean *)theFlag)->isFalse() ) {				// so note its time requirement
                    if ( theContext->maxTimeRequested < paramBlock.returnValue ) {
                        theContext->maxTimeRequested = paramBlock.returnValue;
                    }
                }
            }
            IOLockUnlock(theContext->flags_lock);
        }
    }
    else {									// not a client of ours
        IOLockLock(theContext->flags_lock);
        aBool = OSBoolean::withBoolean(true);					// so we won't be waiting for response
        theContext->responseFlags->replaceObject(theContext->counter,aBool);
        aBool->release();
        IOLockUnlock(theContext->flags_lock);
    }
    theContext->counter += 1;
}


//*********************************************************************************
// tellNoChangeDown
//
// Notify registered applications and kernel clients that we are not
// dropping power.
//
// Subclass can override this to send a different message type.  Parameter is
// the aborted destination state number.
//*********************************************************************************

void IOService::tellNoChangeDown ( unsigned long )
{
    return tellClients(kIOMessageDeviceWillNotPowerOff);
}


//*********************************************************************************
// tellChangeUp
//
// Notify registered applications and kernel clients that we are raising power.
//
// Subclass can override this to send a different message type.  Parameter is
// the aborted destination state number.
//*********************************************************************************

void IOService::tellChangeUp ( unsigned long )
{
    return tellClients(kIOMessageDeviceHasPoweredOn);
}


//*********************************************************************************
// tellClients
//
// Notify registered applications and kernel clients of something.
//*********************************************************************************

void IOService::tellClients ( int messageType )
{
    struct context theContext;

    theContext.msgType = messageType;
    theContext.us = this;

    applyToInterested(gIOAppPowerStateInterest,tellClient,(void *)&theContext);
    applyToInterested(gIOGeneralInterest,tellClient,(void *)&theContext);
}


//*********************************************************************************
// tellClient
//
// Notify a registered application or kernel client of something.
//*********************************************************************************
void tellClient ( OSObject * object, void * context)
{
    struct context * theContext = (struct context *)context;

    theContext->us->messageClient(theContext->msgType,object,0);
}


// **********************************************************************************
// checkForDone
//
// **********************************************************************************
bool IOService::checkForDone ( void )
{
    int i = 0;
    OSObject * theFlag;

    IOLockLock(priv->flags_lock);
    if ( pm_vars->responseFlags == NULL ) {
        IOLockUnlock(priv->flags_lock);
        return true;
    }
    for ( i = 0; ; i++ ) {
        theFlag = pm_vars->responseFlags->getObject(i);
        if ( theFlag == NULL ) {
            break;
        }
        if ( ((OSBoolean *)theFlag)->isFalse() ) {
            IOLockUnlock(priv->flags_lock);
            return false;
        }
    }
    IOLockUnlock(priv->flags_lock);
    return true;
}


// **********************************************************************************
// responseValid
//
// **********************************************************************************
bool IOService::responseValid ( unsigned long x )
{
    UInt16 serialComponent;
    UInt16 ordinalComponent;
    OSObject * theFlag;
    unsigned long refcon = (unsigned long)x;
    OSBoolean * aBool;
    
    serialComponent = (refcon>>16) & 0xFFFF;
    ordinalComponent = refcon & 0xFFFF;
    
    if ( serialComponent != pm_vars->serialNumber ) {
        return false;
    }
    
    IOLockLock(priv->flags_lock);
    if ( pm_vars->responseFlags == NULL ) {
        IOLockUnlock(priv->flags_lock);
        return false;
    }
    
    theFlag = pm_vars->responseFlags->getObject(ordinalComponent);
    
    if ( theFlag == 0 ) {
        IOLockUnlock(priv->flags_lock);
        return false;
    }
    
    if ( ((OSBoolean *)theFlag)->isFalse() ) {
        aBool = OSBoolean::withBoolean(true);
        pm_vars->responseFlags->replaceObject(ordinalComponent,aBool);
        aBool->release();
    }
    
    IOLockUnlock(priv->flags_lock);
    return true;
}


// **********************************************************************************
// allowPowerChange
//
// Our power state is about to lower, and we have notified applications
// and kernel clients, and one of them has acknowledged.  If this is the last to do
// so, and all acknowledgements are positive, we continue with the power change.
//
// We serialize this processing with timer expiration with a command gate on the
// power management workloop, which the timer expiration is command gated to as well.
// **********************************************************************************
IOReturn IOService::allowPowerChange ( unsigned long refcon )
{
    if ( ! initialized ) {
        return kIOReturnSuccess;				// we're unloading
    }

    return pm_vars->PMcommandGate->runAction(serializedAllowPowerChange,(void *)refcon);
}
    
    
IOReturn serializedAllowPowerChange ( OSObject *owner, void * refcon, void *, void *, void *)
{
    return ((IOService *)owner)->serializedAllowPowerChange2((unsigned long)refcon);
}

IOReturn IOService::serializedAllowPowerChange2 ( unsigned long refcon )
{
    if ( ! responseValid(refcon) ) {							// response valid?
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogAcknowledgeErr5,refcon,0);
        return kIOReturnSuccess;                                			// no, just return
    }
    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogClientAcknowledge,refcon,0);

    return allowCancelCommon();
}


// **********************************************************************************
// cancelPowerChange
//
// Our power state is about to lower, and we have notified applications
// and kernel clients, and one of them has vetoed the change.  If this is the last
// client to respond, we abandon the power change.
//
// We serialize this processing with timer expiration with a command gate on the
// power management workloop, which the timer expiration is command gated to as well.
// **********************************************************************************
IOReturn IOService::cancelPowerChange ( unsigned long refcon )
{
    if ( ! initialized ) {
        return kIOReturnSuccess;				// we're unloading
    }

    return pm_vars->PMcommandGate->runAction(serializedCancelPowerChange,(void *)refcon);
}
    
    
IOReturn serializedCancelPowerChange ( OSObject *owner, void * refcon, void *, void *, void *)
{
    return ((IOService *)owner)->serializedCancelPowerChange2((unsigned long)refcon);
}

IOReturn IOService::serializedCancelPowerChange2 ( unsigned long refcon )
{
    if ( ! responseValid(refcon) ) {							// response valid?
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogAcknowledgeErr5,refcon,0);
        return kIOReturnSuccess;							// no, just return
    }
    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogClientCancel,refcon,0);
    
    pm_vars->doNotPowerDown = true;

    return allowCancelCommon();
}


// **********************************************************************************
// allowCancelCommon
//
// **********************************************************************************
IOReturn IOService::allowCancelCommon ( void )
{
    if (! acquire_lock() ) {
        return kIOReturnSuccess;
    }

    if ( checkForDone() ) {                                     // is this the last response?
        stop_ack_timer();                                       // yes, stop the timer
        IOUnlock(priv->our_lock);
        IOLockLock(priv->flags_lock);
        if ( pm_vars->responseFlags ) {
            pm_vars->responseFlags->release();
            pm_vars->responseFlags = NULL;
        }
        IOLockUnlock(priv->flags_lock);
        switch (priv->machine_state) {
            case IOPMour_prechange_03:				// our change, was it vetoed?
                if ( ! pm_vars->doNotPowerDown ) {
                    our_prechange_03();                         // no, we can continue
                }
                else {
                    tellNoChangeDown(priv->head_note_state);	// yes, rescind the warning
                    priv->head_note_flags |= IOPMNotDone;	// mark the change note un-actioned
                    all_done();					// and we're done
                }
                break;
            case IOPMour_prechange_05:
                our_prechange_05();                             // our change, continue
                break;
            case IOPMparent_down_0:
                parent_down_05();                               // parent change, continueq8q
                break;
        }
        return kIOReturnSuccess;
    }

    IOUnlock(priv->our_lock);					// not done yet
    return kIOReturnSuccess;
}


//*********************************************************************************
// clampPowerOn
//
// Set to highest available power state for a minimum of duration milliseconds
//*********************************************************************************

#define kFiveMinutesInNanoSeconds (300 * NSEC_PER_SEC)

void IOService::clampPowerOn (unsigned long duration)
{
  changePowerStateToPriv (pm_vars->theNumberOfPowerStates-1);

  if (  priv->clampTimerEventSrc == NULL ) {
    priv->clampTimerEventSrc = IOTimerEventSource::timerEventSource(this,
                                                    c_PM_Clamp_Timer_Expired);

    IOWorkLoop * workLoop = getPMworkloop ();

    if ( !priv->clampTimerEventSrc || !workLoop ||
       ( workLoop->addEventSource(  priv->clampTimerEventSrc) != kIOReturnSuccess) ) {

    }
  }

  priv->clampTimerEventSrc->setTimeout(kFiveMinutesInNanoSeconds, NSEC_PER_SEC);
}

//*********************************************************************************
// PM_Clamp_Timer_Expired
//
// called when clamp timer expires...set power state to 0.
//*********************************************************************************

void IOService::PM_Clamp_Timer_Expired (void)
{
    if ( ! initialized ) {
        return;					// we're unloading
    }

  changePowerStateToPriv (0);
}

//*********************************************************************************
// c_PM_clamp_Timer_Expired (C Func)
//
// Called when our clamp timer expires...we will call the object method.
//*********************************************************************************

void c_PM_Clamp_Timer_Expired (OSObject * client, IOTimerEventSource *)
{
  if (client)
    ((IOService *)client)->PM_Clamp_Timer_Expired ();
}


//*********************************************************************************
// setPowerState
//
// Does nothing here.  This should be implemented in a subclass driver.
//*********************************************************************************

IOReturn IOService::setPowerState ( unsigned long powerStateOrdinal, IOService* whatDevice )
{
    return IOPMNoErr;
}


//*********************************************************************************
// maxCapabilityForDomainState
//
// Finds the highest power state in the array whose input power
// requirement is equal to the input parameter.  Where a more intelligent
// decision is possible, override this in the subclassed driver.
//*********************************************************************************

unsigned long IOService::maxCapabilityForDomainState ( IOPMPowerFlags domainState )
{
   int i;

   if (pm_vars->theNumberOfPowerStates == 0 ) {
       return 0;
   }
   for ( i = (pm_vars->theNumberOfPowerStates)-1; i >= 0; i-- ) {
       if (  pm_vars->thePowerStates[i].inputPowerRequirement == domainState ) {
           return i;
       }
   }
   return 0;
}


//*********************************************************************************
// initialPowerStateForDomainState
//
// Finds the highest power state in the array whose input power
// requirement is equal to the input parameter.  Where a more intelligent
// decision is possible, override this in the subclassed driver.
//*********************************************************************************

unsigned long IOService::initialPowerStateForDomainState ( IOPMPowerFlags domainState )
{
  int i;

   if (pm_vars->theNumberOfPowerStates == 0 ) {
      return 0;
  }
   for ( i = (pm_vars->theNumberOfPowerStates)-1; i >= 0; i-- ) {
      if ( pm_vars->thePowerStates[i].inputPowerRequirement == domainState ) {
          return i;
      }
  }
  return 0;
}


//*********************************************************************************
// powerStateForDomainState
//
// Finds the highest power state in the array whose input power
// requirement is equal to the input parameter.  Where a more intelligent
// decision is possible, override this in the subclassed driver.
//*********************************************************************************

unsigned long IOService::powerStateForDomainState ( IOPMPowerFlags domainState )
{
  int i;

   if (pm_vars->theNumberOfPowerStates == 0 ) {
      return 0;
  }
   for ( i = (pm_vars->theNumberOfPowerStates)-1; i >= 0; i-- ) {
      if ( pm_vars->thePowerStates[i].inputPowerRequirement == domainState ) {
          return i;
      }
  }
  return 0;
}


//*********************************************************************************
// didYouWakeSystem
//
// Does nothing here.  This should be implemented in a subclass driver.
//*********************************************************************************

bool IOService::didYouWakeSystem  ( void )
{
    return false;
}


//*********************************************************************************
// powerStateWillChangeTo
//
// Does nothing here.  This should be implemented in a subclass driver.
//*********************************************************************************

IOReturn IOService::powerStateWillChangeTo ( IOPMPowerFlags, unsigned long, IOService*)
{
    return 0;
}


//*********************************************************************************
// powerStateDidChangeTo
//
// Does nothing here.  This should be implemented in a subclass driver.
//*********************************************************************************

IOReturn IOService::powerStateDidChangeTo ( IOPMPowerFlags, unsigned long, IOService*)
{
    return 0;
}


//*********************************************************************************
// powerChangeDone
//
// Does nothing here.  This should be implemented in a subclass policy-maker.
//*********************************************************************************

void IOService::powerChangeDone ( unsigned long )
{
}


//*********************************************************************************
// newTemperature
//
// Does nothing here.  This should be implemented in a subclass driver.
//*********************************************************************************

IOReturn IOService::newTemperature ( long currentTemp, IOService * whichZone )

{
    return IOPMNoErr;
}


#undef super
#define super OSObject

OSDefineMetaClassAndStructors(IOPMprot, OSObject)
//*********************************************************************************
// serialize
//
// Serialize protected instance variables for debug output.
//*********************************************************************************
bool IOPMprot::serialize(OSSerialize *s) const
{
    OSString * theOSString;
    char * buffer;
    char * ptr;
    int i;
    bool	rtn_code;

    buffer = ptr = IONew(char, 2000);
    if(!buffer)
        return false;

    ptr += sprintf(ptr,"{ theNumberOfPowerStates = %d, ",(unsigned int)theNumberOfPowerStates);

    if ( theNumberOfPowerStates != 0 ) {
        ptr += sprintf(ptr,"version %d, ",(unsigned int)thePowerStates[0].version);
    }

    if ( theNumberOfPowerStates != 0 ) {
        for ( i = 0; i < (int)theNumberOfPowerStates; i++ ) {
            ptr += sprintf(ptr,"power state %d = { ",i);
            ptr += sprintf(ptr,"capabilityFlags %08x, ",(unsigned int)thePowerStates[i].capabilityFlags);
            ptr += sprintf(ptr,"outputPowerCharacter %08x, ",(unsigned int)thePowerStates[i].outputPowerCharacter);
            ptr += sprintf(ptr,"inputPowerRequirement %08x, ",(unsigned int)thePowerStates[i].inputPowerRequirement);
            ptr += sprintf(ptr,"staticPower %d, ",(unsigned int)thePowerStates[i].staticPower);
            ptr += sprintf(ptr,"unbudgetedPower %d, ",(unsigned int)thePowerStates[i].unbudgetedPower);
            ptr += sprintf(ptr,"powerToAttain %d, ",(unsigned int)thePowerStates[i].powerToAttain);
            ptr += sprintf(ptr,"timeToAttain %d, ",(unsigned int)thePowerStates[i].timeToAttain);
            ptr += sprintf(ptr,"settleUpTime %d, ",(unsigned int)thePowerStates[i].settleUpTime);
            ptr += sprintf(ptr,"timeToLower %d, ",(unsigned int)thePowerStates[i].timeToLower);
            ptr += sprintf(ptr,"settleDownTime %d, ",(unsigned int)thePowerStates[i].settleDownTime);
            ptr += sprintf(ptr,"powerDomainBudget %d }, ",(unsigned int)thePowerStates[i].powerDomainBudget);
        }
    }

    ptr += sprintf(ptr,"aggressiveness = %d, ",(unsigned int)aggressiveness);
    ptr += sprintf(ptr,"myCurrentState = %d, ",(unsigned int)myCurrentState);
    ptr += sprintf(ptr,"parentsCurrentPowerFlags = %08x, ",(unsigned int)parentsCurrentPowerFlags);
    ptr += sprintf(ptr,"maxCapability = %d }",(unsigned int)maxCapability);

    theOSString = OSString::withCString(buffer);
    rtn_code = theOSString->serialize(s);
    theOSString->release();
    IODelete(buffer, char, 2000);

    return rtn_code;
}


#undef super
#define super OSObject

OSDefineMetaClassAndStructors(IOPMpriv, OSObject)
//*********************************************************************************
// serialize
//
// Serialize private instance variables for debug output.
//*********************************************************************************
bool IOPMpriv::serialize(OSSerialize *s) const
{
    OSString *			theOSString;
    bool			rtn_code;
    char * 			buffer;
    char * 			ptr;
    IOPMinformee * 		nextObject;

    buffer = ptr = IONew(char, 2000);
    if(!buffer)
        return false;

    ptr += sprintf(ptr,"{ this object = %08x",(unsigned int)owner);
    if ( we_are_root ) {
        ptr += sprintf(ptr," (root)");
    }
    ptr += sprintf(ptr,", ");

    nextObject = interestedDrivers->firstInList();			// display interested drivers
    while (  nextObject != NULL ) {
        ptr += sprintf(ptr,"interested driver = %08x, ",(unsigned int)nextObject->whatObject);
        nextObject  =  interestedDrivers->nextInList(nextObject);
    }

    if ( machine_state != IOPMfinished ) {
        ptr += sprintf(ptr,"machine_state = %d, ",(unsigned int)machine_state);
        ptr += sprintf(ptr,"driver_timer = %d, ",(unsigned int)driver_timer);
        ptr += sprintf(ptr,"settle_time = %d, ",(unsigned int)settle_time);
        ptr += sprintf(ptr,"head_note_flags = %08x, ",(unsigned int)head_note_flags);
        ptr += sprintf(ptr,"head_note_state = %d, ",(unsigned int)head_note_state);
        ptr += sprintf(ptr,"head_note_outputFlags = %08x, ",(unsigned int)head_note_outputFlags);
        ptr += sprintf(ptr,"head_note_domainState = %08x, ",(unsigned int)head_note_domainState);
        ptr += sprintf(ptr,"head_note_capabilityFlags = %08x, ",(unsigned int)head_note_capabilityFlags);
        ptr += sprintf(ptr,"head_note_pendingAcks = %d, ",(unsigned int)head_note_pendingAcks);
    }

    if ( device_overrides ) {
        ptr += sprintf(ptr,"device overrides, ");
    }
    ptr += sprintf(ptr,"driverDesire = %d, ",(unsigned int)driverDesire);
    ptr += sprintf(ptr,"deviceDesire = %d, ",(unsigned int)deviceDesire);
    ptr += sprintf(ptr,"ourDesiredPowerState = %d, ",(unsigned int)ourDesiredPowerState);
    ptr += sprintf(ptr,"previousRequest = %d }",(unsigned int)previousRequest);

    theOSString =  OSString::withCString(buffer);
    rtn_code = theOSString->serialize(s);
    theOSString->release();
    IODelete(buffer, char, 2000);

    return rtn_code;
}


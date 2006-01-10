/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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

#include <IOKit/assert.h>

#include <IOKit/IOCommandGate.h>
#include <IOKit/IOKitDebug.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMessage.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOService.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOWorkLoop.h>

#include <IOKit/pwr_mgt/IOPMchangeNoteList.h>
#include <IOKit/pwr_mgt/IOPMinformee.h>
#include <IOKit/pwr_mgt/IOPMinformeeList.h>
#include <IOKit/pwr_mgt/IOPMlog.h>
#include <IOKit/pwr_mgt/IOPowerConnection.h>
#include <IOKit/pwr_mgt/RootDomain.h>

// Required for notification instrumentation
#include "IOServicePrivate.h"

#define super IORegistryEntry

#define OUR_PMLog(t, a, b) \
    do { pm_vars->thePlatform->PMLog(pm_vars->ourName, t, a, b); } while(0)

static void ack_timer_expired(thread_call_param_t);
static void settle_timer_expired(thread_call_param_t);
static void PM_idle_timer_expired(OSObject *, IOTimerEventSource *);
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
    kIOPM_OurChangeTellClientsPowerDown = 1,
    kIOPM_OurChangeTellPriorityClientsPowerDown,
    kIOPM_OurChangeNotifyInterestedDriversWillChange,
    kIOPM_OurChangeSetPowerState,
    kIOPM_OurChangeWaitForPowerSettle,
    kIOPM_OurChangeNotifyInterestedDriversDidChange,
    kIOPM_OurChangeFinish,
    kIOPM_ParentDownTellPriorityClientsPowerDown_Immediate,
    kIOPM_ParentDownNotifyInterestedDriversWillChange_Delayed,
    kIOPM_ParentDownWaitForPowerSettleAndNotifyDidChange_Immediate,
    kIOPM_ParentDownNotifyDidChangeAndAcknowledgeChange_Delayed,
    kIOPM_ParentDownSetPowerState_Delayed,
    kIOPM_ParentDownWaitForPowerSettle_Delayed,
    kIOPM_ParentDownAcknowledgeChange_Delayed,
    kIOPM_ParentUpSetPowerState_Delayed,
    kIOPM_ParentUpSetPowerState_Immediate,
    kIOPM_ParentUpWaitForSettleTime_Delayed,
    kIOPM_ParentUpNotifyInterestedDriversDidChange_Delayed,
    kIOPM_ParentUpAcknowledgePowerChange_Delayed,
    kIOPM_Finished
};

// values of outofbandparameter
enum {
	kNotifyApps,
	kNotifyPriority
};


// used for applyToInterested
struct context {
    OSArray *	responseFlags;
    UInt16	serialNumber;
    UInt16 	counter;
    UInt32	maxTimeRequested;
    int		msgType;
    IOService *	us;
    IOLock *	flags_lock;
    unsigned long stateNumber;
    IOPMPowerFlags stateFlags;
};

// five minutes in microseconds
#define FIVE_MINUTES 5*60*1000000
#define k30seconds 30*1000000

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
 on to state "OurChangeSetPowerState".  Otherwise, we start the ack timer and wait for the stragglers to acknowlege by calling
 acknowledgePowerChange.  We move on to state "OurChangeSetPowerState" when all the stragglers have acknowledged,
 or when the ack timer expires on all those which didn't acknowledge.  In "OurChangeSetPowerState" we call the power-controlling
 driver to change the power state of the hardware.  If it returns saying it has done so, we go on to state "OurChangeWaitForPowerSettle".
 Otherwise, we have to wait for it, so we set the ack timer and wait.  When it calls acknowledgeSetPowerState, or when the
 ack timer expires, we go on.  In "OurChangeWaitForPowerSettle", we look in the power state array to see if there is any settle time required
 when changing from our current state to the new state.  If not, we go right away to "OurChangeNotifyInterestedDriversDidChange".  Otherwise, we
 set the settle timer and wait.  When it expires, we move on.  In "OurChangeNotifyInterestedDriversDidChange" state, we notify all our interested parties
 via their powerStateDidChange methods that we have finished changing power state.  If they all acknowledge via return
 code, we move on to "OurChangeFinish".  Otherwise we set the ack timer and wait.  When they have all acknowledged, or
 when the ack timer has expired for those that didn't, we move on to "OurChangeFinish", where we remove the used
 change note from the head of the queue and start the next one if one exists.

 Parent-initiated changes are more complex in the state machine.  First, power going up and power going down are handled
 differently, so they have different paths throught the state machine.  Second, we can acknowledge the parent's notification
 in two different ways, so each of the parent paths is really two.

 When the parent calls our powerDomainWillChange method, notifying us that it will lower power in the domain, we decide
 what state that will put our device in.  Then we embark on the state machine path "IOPMParentDownSetPowerState_Immediate"
 and "kIOPM_ParentDownWaitForPowerSettleAndNotifyDidChange_Immediate", in which we notify interested parties of the upcoming change,  instruct our driver to make
 the change, check for settle time, and notify interested parties of the completed change.   If we get to the end of this path without
 stalling due to an interested party which didn't acknowledge via return code, due to the controlling driver not able to change
 state right away, or due to a non-zero settling time, then we return IOPMAckImplied to the parent, and we're done with the change.
 If we do stall in any of those states, we return IOPMWillAckLater to the parent and enter the parallel path "kIOPM_ParentDownSetPowerState_Delayed"
 "kIOPM_ParentDownWaitForPowerSettle_Delayed", and "kIOPM_ParentDownNotifyDidChangeAndAcknowledgeChange_Delayed", where we continue with the same processing, except that at the end we
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
 we go on to" kIOPM_ParentUpSetPowerState_Immediate" to instruct the driver to raise its power level. After that, we check for any
 necessary settling time in "IOPMParentUpWaitForSettleTime_Immediate", and we notify all interested parties that power has changed
 in "IOPMParentUpNotifyInterestedDriversDidChange_Immediate".  If none of these operations stall, we acknowledge the parent via return code, release
 the change note, and start the next, if there is one.  If one of them does stall, we enter the parallel path  "kIOPM_ParentUpSetPowerState_Delayed",
 "kIOPM_ParentUpWaitForSettleTime_Delayed", "kIOPM_ParentUpNotifyInterestedDriversDidChange_Delayed", and "kIOPM_ParentUpAcknowledgePowerChange_Delayed", which ends with
 our explicit acknowledgement to the parent.

*/


const char priv_key[ ] = "Power Management private data";
const char prot_key[ ] = "Power Management protected data";


void IOService::PMinit ( void )
{
    if ( ! initialized ) {

        // make space for our variables
        pm_vars =  new IOPMprot;					
        priv = new IOPMpriv;
        pm_vars->init();
        priv->init();
        

        // add pm_vars & priv to the properties
        setProperty(prot_key, (OSObject *) pm_vars);			
        setProperty(priv_key, (OSObject *) priv);

        // then initialize them
        priv->owner = this;
        pm_vars->theNumberOfPowerStates = 0;				
        priv->we_are_root = false;
        pm_vars->theControllingDriver = NULL;
        priv->our_lock = IOLockAlloc();
        priv->flags_lock = IOLockAlloc();
        priv->queue_lock = IOLockAlloc();
        pm_vars->childLock = IOLockAlloc();
        pm_vars->parentLock = IOLockAlloc();
        priv->interestedDrivers = new IOPMinformeeList;
        priv->interestedDrivers->initialize();
        priv->changeList = new IOPMchangeNoteList;
        priv->changeList->initialize();
        pm_vars->aggressiveness = 0;
        for (unsigned int i = 0; i <= kMaxType; i++) 
        {
	        pm_vars->current_aggressiveness_values[i] = 0;
	        pm_vars->current_aggressiveness_valid[i] = false;
        }
        pm_vars->myCurrentState =  0;
        priv->imminentState = 0;
        priv->ourDesiredPowerState = 0;
        pm_vars->parentsCurrentPowerFlags = 0;
        pm_vars->maxCapability = 0;
        priv->driverDesire = 0;
        priv->deviceDesire = 0;
        priv->initial_change = true;
        priv->need_to_become_usable = false;
        priv->previousRequest = 0;
        priv->device_overrides = false;
        priv->machine_state = kIOPM_Finished;
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
// PMfree
//
// Free up the data created in PMinit, if it exists.
//*********************************************************************************
void IOService::PMfree ( void )
{
    if ( priv ) {
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
        if ( priv->settleTimer ) {
            thread_call_cancel(priv->settleTimer);
            thread_call_free(priv->settleTimer);
            priv->settleTimer = NULL;
        }
        if ( priv->ackTimer ) {
            thread_call_cancel(priv->ackTimer);
            thread_call_free(priv->ackTimer);
            priv->ackTimer = NULL;
        }
        if ( priv->our_lock ) {
            IOLockFree(priv->our_lock);
            priv->our_lock = NULL;
        }
        if ( priv->flags_lock ) {
            IOLockFree(priv->flags_lock);
            priv->flags_lock = NULL;
        }
        if ( priv->activityLock ) {
            IOLockFree(priv->activityLock);
            priv->activityLock = NULL;
        }
        priv->interestedDrivers->release();
        priv->changeList->release();
        // remove instance variables
        priv->release();				
    }
    
    if ( pm_vars ) {
        if ( pm_vars->PMcommandGate ) {
            if(pm_vars->PMworkloop)
                pm_vars->PMworkloop->removeEventSource(pm_vars->PMcommandGate);
            pm_vars->PMcommandGate->release();
            pm_vars->PMcommandGate = NULL;
        }
        if ( pm_vars->PMworkloop ) {
            // The work loop object returned from getPMworkLoop() is
            // never retained, therefore it should not be released.
            // pm_vars->PMworkloop->release();
            pm_vars->PMworkloop = NULL;
        }
        if ( pm_vars->responseFlags ) {
            pm_vars->responseFlags->release();
            pm_vars->responseFlags = NULL;
        }
        // remove instance variables
        pm_vars->release();				
    }
}


//*********************************************************************************
// PMstop
//
// Disconnect the node from its parents and children in the Power Plane.
//*********************************************************************************
void IOService::PMstop ( void )
{
    OSIterator *	iter;
    OSObject *		next;
    IOPowerConnection *	connection;
    IOService *		theChild;
    IOService *		theParent;

    // remove the properties
    removeProperty(prot_key);			
    removeProperty(priv_key);
    
    // detach parents
    iter = getParentIterator(gIOPowerPlane);	

    if ( iter ) 
    {
        while ( (next = iter->getNextObject()) ) 
        {
            if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) 
            {
                theParent = (IOService *)connection->copyParentEntry(gIOPowerPlane);
                if ( theParent ) 
                {
                    theParent->removePowerChild(connection);
                    theParent->release();
                }
            }
        }
        iter->release();
    }

    // detach IOConnections   
    detachAbove( gIOPowerPlane );		
    
    if ( pm_vars )
    {
        // no more power state changes
        pm_vars->parentsKnowState = false;		
    }
    
    // detach children
    iter = getChildIterator(gIOPowerPlane);	

    if ( iter ) 
    {
        while ( (next = iter->getNextObject()) ) 
        {
            if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) 
            {
                theChild = ((IOService *)(connection->copyChildEntry(gIOPowerPlane)));
                if ( theChild ) 
                {
                    // detach nub from child
                    connection->detachFromChild(theChild,gIOPowerPlane);	
                    theChild->release();
                }
                // detach us from nub
                detachFromChild(connection,gIOPowerPlane);			
            }
        }
        iter->release();
    }

    // Remove all interested drivers from the list, including the power
    // controlling driver.
    //
    // Usually, the controlling driver and the policy-maker functionality
    // are implemented by the same object, and without the deregistration,
    // the object will be holding an extra retain on itself, and cannot
    // be freed.

    if ( priv && priv->interestedDrivers )
    {
        IOPMinformee * informee;

        while (( informee = priv->interestedDrivers->firstInList() ))
            deRegisterInterestedDriver( informee->whatObject );
    }
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
    
    IOLockLock(pm_vars->parentLock);
    
    if ( stateKnown && ((pm_vars->PMworkloop == NULL) || (pm_vars->PMcommandGate == NULL)) ) 
    {
        // we have a path to the root
        // find out the workloop
        getPMworkloop();
        if ( pm_vars->PMworkloop != NULL ) 
        {
            if ( pm_vars->PMcommandGate == NULL ) 
            {	
                // and make our command gate
                pm_vars->PMcommandGate = IOCommandGate::commandGate((OSObject *)this);
                if ( pm_vars->PMcommandGate != NULL ) 
                {
                    pm_vars->PMworkloop->addEventSource(pm_vars->PMcommandGate);
                }
            }
        }
    }
    
    IOLockUnlock(pm_vars->parentLock);

    // set our connection data
    theParent->setParentCurrentPowerFlags(currentState);	
    theParent->setParentKnowsState(stateKnown);

    // combine parent knowledge
    pm_vars->parentsKnowState = true;				
    pm_vars->parentsCurrentPowerFlags = 0;
    
    iter = getParentIterator(gIOPowerPlane);

    if ( iter ) 
    {
        while ( (next = iter->getNextObject()) ) 
        {
            if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) 
            {
                pm_vars->parentsKnowState &= connection->parentKnowsState();
                pm_vars->parentsCurrentPowerFlags |= connection->parentCurrentPowerFlags();
            }
        }
        iter->release();
    }
    
    if ( (pm_vars->theControllingDriver != NULL) &&
         (pm_vars->parentsKnowState) ) 
    {
        pm_vars->maxCapability = pm_vars->theControllingDriver->maxCapabilityForDomainState(pm_vars->parentsCurrentPowerFlags);
        // initially change into the state we are already in
        tempDesire = priv->deviceDesire;			
        priv->deviceDesire = pm_vars->theControllingDriver->initialPowerStateForDomainState(pm_vars->parentsCurrentPowerFlags);
        computeDesiredState();
        priv->previousRequest = 0xffffffff;
        changeState();
        // put this back like before
        priv->deviceDesire = tempDesire;    
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
    IOPowerConnection                       *connection;
    unsigned int                            i;

    if ( ! initialized ) 
    {
        // we're not a power-managed IOService
        return IOPMNotYetInitialized;	
    }

    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogAddChild,0,0);

    // Put ourselves into a usable power state.
    // We must be in an "on" power state, as our children must be able to access
    // our hardware after joining the power plane.
    makeUsable();
    
    // make a nub
    connection = new IOPowerConnection;			

    connection->init();
    connection->start(this);
    connection->setAwaitingAck(false);
    
    // connect it up
    attachToChild( connection,gIOPowerPlane );			
    connection->attachToChild( theChild,gIOPowerPlane );
    connection->release();
    
    // tell it the current state of the power domain
    if ( (pm_vars->theControllingDriver == NULL) ||		
            ! (inPlane(gIOPowerPlane)) ||
            ! (pm_vars->parentsKnowState) ) 
    {
        theChild->setPowerParent(connection,false,0);
        if ( inPlane(gIOPowerPlane) ) 
        {
            for (i = 0; i <= kMaxType; i++) {
                if ( pm_vars->current_aggressiveness_valid[i] ) 
                {
                    theChild->setAggressiveness (i, pm_vars->current_aggressiveness_values[i]);
                }
            }
        }
    } else {
        theChild->setPowerParent(connection,true,pm_vars->thePowerStates[pm_vars->myCurrentState].outputPowerCharacter);
        for (i = 0; i <= kMaxType; i++) 
        {
            if ( pm_vars->current_aggressiveness_valid[i] )
            {
                theChild->setAggressiveness (i, pm_vars->current_aggressiveness_values[i]);
            }
        }
        // catch it up if change is in progress
        add_child_to_active_change(connection);							
    }
    
    return IOPMNoErr;
}


//*********************************************************************************
// removePowerChild
//
//*********************************************************************************
IOReturn IOService::removePowerChild ( IOPowerConnection * theNub )
{
    IORegistryEntry                         *theChild;
    OSIterator                              *iter;

    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogRemoveChild,0,0);

    theNub->retain();
    
    // detach nub from child
    theChild = theNub->copyChildEntry(gIOPowerPlane);			
    if ( theChild ) 
    {
        theNub->detachFromChild(theChild, gIOPowerPlane);
        theChild->release();
    }
    // detach from the nub
    detachFromChild(theNub,gIOPowerPlane);				
    
    // are we awaiting an ack from this child?
    if ( theNub->getAwaitingAck() ) 
    {
        // yes, pretend we got one
        theNub->setAwaitingAck(false);
        if ( acquire_lock() ) 
        {
            if (priv->head_note_pendingAcks != 0 ) 
            {
                // that's one fewer ack to worry about
                priv->head_note_pendingAcks -= 1;
                // is that the last?
                if ( priv->head_note_pendingAcks == 0 ) 
                {
                    // yes, stop the timer
                    stop_ack_timer();
                    IOUnlock(priv->our_lock);
                    // and now we can continue our power change
                    all_acked();
                } else {
                    IOUnlock(priv->our_lock);
                }
            } else {
                IOUnlock(priv->our_lock);
            }
        }
    }

    theNub->release();

    // if not fully initialized
    if ( (pm_vars->theControllingDriver == NULL) ||
                !(inPlane(gIOPowerPlane)) ||
                !(pm_vars->parentsKnowState) ) 
    {
        // we can do no more
        return IOPMNoErr;				
    }

    // Perhaps the departing child was holding up idle or system sleep - we need to re-evaluate our
    // childrens' requests. Clear and re-calculate our kIOPMChildClamp and kIOPMChildClamp2 bits.
    rebuildChildClampBits();
    
    if(!priv->clampOn)
    {
        // count children
        iter = getChildIterator(gIOPowerPlane);
        if ( !iter || !iter->getNextObject()  ) 
        {
            // paired to match the makeUsable() call in addPowerChild()
            changePowerStateToPriv(0);
        }
        if(iter) iter->release();
    }
    
    // this may be different now
    computeDesiredState();
    // change state if we can now tolerate lower power
    changeState();

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
    unsigned long                           i;
    unsigned long                           tempDesire;

    if ( (numberOfStates > pm_vars->theNumberOfPowerStates) 
                    && (numberOfStates > 1) ) 
    {
        if (  priv->changeList->currentChange() == -1 ) 
        {
            if ( controllingDriver != NULL ) 
            {
                if ( numberOfStates <= IOPMMaxPowerStates ) 
                {
                    switch ( powerStates[0].version  ) 
                    {
                        case 1:
                            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogControllingDriver,
                                            (unsigned long)numberOfStates, (unsigned long)powerStates[0].version);
                            for ( i = 0; i < numberOfStates; i++ ) 
                            {
                                pm_vars->thePowerStates[i] = powerStates[i];
                            }
                                break;
                        case 2:
                            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogControllingDriver,
                                            (unsigned long) numberOfStates,(unsigned long) powerStates[0].version);
                            for ( i = 0; i < numberOfStates; i++ ) 
                            {
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

                    // make a mask of all the character bits we know about
                    pm_vars->myCharacterFlags = 0;	
                    for ( i = 0; i < numberOfStates; i++ ) {
                        pm_vars->myCharacterFlags |= pm_vars->thePowerStates[i].outputPowerCharacter;
                    }
                    
                   pm_vars->theNumberOfPowerStates = numberOfStates;
                    pm_vars->theControllingDriver = controllingDriver;
                    if ( priv->interestedDrivers->findItem(controllingDriver) == NULL ) 
                    {
                        // register it as interested, unless already done
                        registerInterestedDriver (controllingDriver );
                    }
                    if ( priv->need_to_become_usable ) {
                        priv->need_to_become_usable = false;
                        priv->deviceDesire = pm_vars->theNumberOfPowerStates - 1;
                    }

                    if ( inPlane(gIOPowerPlane) &&
                         (pm_vars->parentsKnowState) ) {
                        pm_vars->maxCapability = pm_vars->theControllingDriver->maxCapabilityForDomainState(pm_vars->parentsCurrentPowerFlags);
                        // initially change into the state we are already in
                        tempDesire = priv->deviceDesire;
                        priv->deviceDesire = pm_vars->theControllingDriver->initialPowerStateForDomainState(pm_vars->parentsCurrentPowerFlags);
                        computeDesiredState();
                        changeState();
                        // put this back like before
                        priv->deviceDesire = tempDesire;
                    }
                } else {
                    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogControllingDriverErr2,(unsigned long)numberOfStates,0);
                }
            } else {
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
    IOPMinformee                            *newInformee;
    IOPMPowerFlags                          futureCapability;

    if (theDriver == NULL ) {
        return 0;
    }

    // make new driver node
    newInformee = new IOPMinformee;
    newInformee->initialize(theDriver);
    // add it to list of drivers
    priv->interestedDrivers->addToList(newInformee);

    if ( (pm_vars->theControllingDriver == NULL) ||
                    !(inPlane(gIOPowerPlane)) ||
                    !(pm_vars->parentsKnowState) ) 
    {
        // can't tell it a state yet
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogInterestedDriver,IOPMNotPowerManaged,0);
        return IOPMNotPowerManaged;
    }

    // can we notify new driver of a change in progress?
    switch (priv->machine_state) {
        case kIOPM_OurChangeSetPowerState:
        case kIOPM_OurChangeFinish:
        case kIOPM_ParentDownSetPowerState_Delayed:
        case kIOPM_ParentDownAcknowledgeChange_Delayed:
        case kIOPM_ParentUpSetPowerState_Delayed:
        case kIOPM_ParentUpAcknowledgePowerChange_Delayed:
            // yes, remember what we tell it
            futureCapability = priv->head_note_capabilityFlags;
            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogInterestedDriver,(unsigned long)futureCapability,1);
            // notify it
            add_driver_to_active_change(newInformee);
            // and return the same thing
            return futureCapability;
    }

    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogInterestedDriver,
                    (unsigned long) pm_vars->thePowerStates[pm_vars->myCurrentState].capabilityFlags,2);

    // no, return current capability
    return  pm_vars->thePowerStates[pm_vars->myCurrentState].capabilityFlags;	
}


//*********************************************************************************
// deRegisterInterestedDriver
//
//*********************************************************************************
IOReturn IOService::deRegisterInterestedDriver ( IOService * theDriver )
{
    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogRemoveDriver,0,0);

    // remove the departing driver
    priv->interestedDrivers->removeFromList(theDriver);

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
    IOPMinformee                                *ackingObject;
    unsigned long	                            childPower = kIOPMUnknown;
    IOService                                   *theChild;

    // one of our interested drivers?
    ackingObject =  priv->interestedDrivers->findItem(whichObject);
    if ( ackingObject == NULL ) 
    {
        if ( ! isChild(whichObject,gIOPowerPlane) ) 
        {
             pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogAcknowledgeErr1,0,0);
             //kprintf("errant driver: %s\n",whichObject->getName());
             // no, just return
            return IOPMNoErr;
        } else {
            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogChildAcknowledge,priv->head_note_pendingAcks,0);
        }
    } else {
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogDriverAcknowledge,priv->head_note_pendingAcks,0);
    }
 
    if (! acquire_lock() ) 
    {
        return IOPMNoErr;
    }
 
    if (priv->head_note_pendingAcks != 0 ) 
    {
         // yes, make sure we're expecting acks
        if ( ackingObject != NULL ) 
        {
            // it's an interested driver
            // make sure we're expecting this ack
            if ( ackingObject->timer != 0 ) 
            {
                // mark it acked
                ackingObject->timer = 0;
                // that's one fewer to worry about
                priv->head_note_pendingAcks -= 1;
                // is that the last?
                if ( priv->head_note_pendingAcks == 0 ) 
                {
                    // yes, stop the timer
                    stop_ack_timer();
                    IOUnlock(priv->our_lock);
                    // and now we can continue
                    all_acked();
                    return IOPMNoErr;
                }
            } else {
                // this driver has already acked
                pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogAcknowledgeErr2,0,0);
                //kprintf("errant driver: %s\n",whichObject->getName());
            }
        } else {
            // it's a child
            // make sure we're expecting this ack
            if ( ((IOPowerConnection *)whichObject)->getAwaitingAck() ) 
            {
                // that's one fewer to worry about
                priv->head_note_pendingAcks -= 1;
                ((IOPowerConnection *)whichObject)->setAwaitingAck(false);
                theChild = (IOService *)whichObject->copyChildEntry(gIOPowerPlane);
                if ( theChild ) 
                {
                    childPower = theChild->currentPowerConsumption();
                    theChild->release();
                }
                if ( childPower == kIOPMUnknown ) 
                {
                    pm_vars->thePowerStates[priv->head_note_state].staticPower = kIOPMUnknown;
                } else {
                    if ( pm_vars->thePowerStates[priv->head_note_state].staticPower != kIOPMUnknown ) 
                    {
                        pm_vars->thePowerStates[priv->head_note_state].staticPower += childPower;
                    }
                }
                // is that the last?
                if ( priv->head_note_pendingAcks == 0 ) {
                    // yes, stop the timer
                    stop_ack_timer();
                    IOUnlock(priv->our_lock);
                    // and now we can continue
                    all_acked();
                    return IOPMNoErr;
                }
            }
	    }
    } else {
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogAcknowledgeErr3,0,0);	// not expecting anybody to ack
        //kprintf("errant driver: %s\n",whichObject->getName());
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
    if (!acquire_lock()) 
        return IOPMNoErr;

    IOReturn timer = priv->driver_timer;
    if ( timer == -1 ) {
        // driver is acking instead of using return code
	OUR_PMLog(kPMLogDriverAcknowledgeSet, (UInt32) this, timer);
        priv->driver_timer = 0;
    }
    else if ( timer > 0 ) {	// are we expecting this?
	// yes, stop the timer
	stop_ack_timer();
	priv->driver_timer = 0;
	OUR_PMLog(kPMLogDriverAcknowledgeSet, (UInt32) this, timer);
	IOUnlock(priv->our_lock);
	driver_acked();
	return IOPMNoErr;
    } else {
	// not expecting this
	OUR_PMLog(kPMLogAcknowledgeErr4, (UInt32) this, 0);
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
        case kIOPM_OurChangeWaitForPowerSettle:
            OurChangeWaitForPowerSettle();
            break;
        case kIOPM_ParentDownWaitForPowerSettle_Delayed:
            ParentDownWaitForPowerSettle_Delayed();
            break;
        case kIOPM_ParentUpWaitForSettleTime_Delayed:
            ParentUpWaitForSettleTime_Delayed();
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
    OSIterator                      *iter;
    OSObject                        *next;
    IOPowerConnection               *connection;
    unsigned long                   newStateNumber;
    IOPMPowerFlags                  combinedPowerFlags;

    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogWillChange,(unsigned long)newPowerStateFlags,0);

    if ( ! inPlane(gIOPowerPlane) ) 
    {
        // somebody goofed
        return IOPMAckImplied;
    }

    IOLockLock(pm_vars->parentLock);
    
    if ( (pm_vars->PMworkloop == NULL) || (pm_vars->PMcommandGate == NULL) ) 
    {
        // we have a path to the root
        getPMworkloop();
        // so find out the workloop
        if ( pm_vars->PMworkloop != NULL ) 
        {
            // and make our command gate
            if ( pm_vars->PMcommandGate == NULL ) 
            {
                pm_vars->PMcommandGate = IOCommandGate::commandGate((OSObject *)this);
                if ( pm_vars->PMcommandGate != NULL ) 
                {
                    pm_vars->PMworkloop->addEventSource(pm_vars->PMcommandGate);
                }
            }
        }
    }
    
    IOLockUnlock(pm_vars->parentLock);

    // combine parents' power states
    // to determine our maximum state within the new power domain
    combinedPowerFlags = 0;
    
    iter = getParentIterator(gIOPowerPlane);

    if ( iter ) 
    {
        while ( (next = iter->getNextObject()) ) 
        {
            if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) 
            {
                if ( connection == whichParent ){
                    combinedPowerFlags |= newPowerStateFlags;
                } else {
                    combinedPowerFlags |= connection->parentCurrentPowerFlags();
                }
            }
        }
        iter->release();
    }
    
    if  ( pm_vars->theControllingDriver == NULL ) 
    {
        // we can't take any more action
        return IOPMAckImplied;
    }
    newStateNumber = pm_vars->theControllingDriver->maxCapabilityForDomainState(combinedPowerFlags);
    // make the change
    return enqueuePowerChange(IOPMParentInitiated | IOPMDomainWillChange,
                            newStateNumber,combinedPowerFlags,whichParent,newPowerStateFlags);
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
    unsigned long newStateNumber;

    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogDidChange,newPowerStateFlags,0);

    setParentInfo(newPowerStateFlags,whichParent);

    if ( pm_vars->theControllingDriver == NULL ) {
        return IOPMAckImplied;
    }

    newStateNumber = pm_vars->theControllingDriver->maxCapabilityForDomainState(pm_vars->parentsCurrentPowerFlags);
    // tell interested parties about it
    return enqueuePowerChange(IOPMParentInitiated | IOPMDomainDidChange,
                    newStateNumber,pm_vars->parentsCurrentPowerFlags,whichParent,0);
}


//*********************************************************************************
// setParentInfo
//
// Set our connection data for one specific parent, and then combine all the parent
// data together.
//*********************************************************************************

void IOService::setParentInfo ( IOPMPowerFlags newPowerStateFlags, IOPowerConnection * whichParent )
{
    OSIterator                      *iter;
    OSObject                        *next;
    IOPowerConnection               *connection;
    
    // set our connection data
    whichParent->setParentCurrentPowerFlags(newPowerStateFlags);
    whichParent->setParentKnowsState(true);

    IOLockLock(pm_vars->parentLock);
    
    // recompute our parent info
    pm_vars->parentsCurrentPowerFlags = 0;
    pm_vars->parentsKnowState = true;

    iter = getParentIterator(gIOPowerPlane);

    if ( iter ) 
    {
        while ( (next = iter->getNextObject()) ) 
        {
            if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) 
            {
                pm_vars->parentsKnowState &= connection->parentKnowsState();
                pm_vars->parentsCurrentPowerFlags |= connection->parentCurrentPowerFlags();
            }
        }
        iter->release();
    }
    IOLockUnlock(pm_vars->parentLock);
}

//*********************************************************************************
// rebuildChildClampBits
//
// The ChildClamp bits (kIOPMChildClamp & kIOPMChildClamp2) in our capabilityFlags
// indicate that one of our children (or grandchildren or great-grandchildren or ...)
// doesn't support idle or system sleep in its current state. Since we don't track the
// origin of each bit, every time any child changes state we have to clear these bits 
// and rebuild them.
//*********************************************************************************

void IOService::rebuildChildClampBits(void)
{
    unsigned long                       i;
    OSIterator                          *iter;
    OSObject                            *next;
    IOPowerConnection                   *connection;
    
    
    // A child's desires has changed.  We need to rebuild the child-clamp bits in our
    // power state array.  Start by clearing the bits in each power state.
    
    for ( i = 0; i < pm_vars->theNumberOfPowerStates; i++ ) 
    {
        pm_vars->thePowerStates[i].capabilityFlags &= ~(kIOPMChildClamp | kIOPMChildClamp2);
    }

    // Now loop through the children.  When we encounter the calling child, save
    // the computed state as this child's desire.  And while we're at it, set the ChildClamp bits
    // in any of our states that some child has requested with clamp on.

    iter = getChildIterator(gIOPowerPlane);

    if ( iter ) 
    {
        while ( (next = iter->getNextObject()) ) 
        {
            if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) 
            {
                if ( connection->getPreventIdleSleepFlag() )
                    pm_vars->thePowerStates[connection->getDesiredDomainState()].capabilityFlags |= kIOPMChildClamp;
                if ( connection->getPreventSystemSleepFlag() )
                    pm_vars->thePowerStates[connection->getDesiredDomainState()].capabilityFlags |= kIOPMChildClamp2;
            }
        }
        iter->release();
    }

}


//*********************************************************************************
// requestPowerDomainState
//
// The kIOPMPreventIdleSleep and/or kIOPMPreventIdleSleep bits may be be set in the parameter.
// It is not considered part of the state specification.
//*********************************************************************************
IOReturn IOService::requestPowerDomainState ( IOPMPowerFlags desiredState, IOPowerConnection * whichChild, unsigned long specification )
{
    unsigned long                           i;
    unsigned long                           computedState;
    unsigned long                           theDesiredState = desiredState & ~(kIOPMPreventIdleSleep | kIOPMPreventSystemSleep);
    OSIterator                              *iter;
    OSObject                                *next;
    IOPowerConnection                       *connection;

    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogRequestDomain,
                                (unsigned long)desiredState,(unsigned long)specification);

    if ( pm_vars->theControllingDriver == NULL) 
    {
        return IOPMNotYetInitialized;
    }

    switch (specification) {
        case IOPMLowestState:
            i = 0;
            while ( i < pm_vars->theNumberOfPowerStates ) 
            {
                if ( ( pm_vars->thePowerStates[i].outputPowerCharacter & theDesiredState) == (theDesiredState & pm_vars->myCharacterFlags) ) 
                {
                    break;
                }
                i++;
            }
            if ( i >= pm_vars->theNumberOfPowerStates ) 
            {
                return IOPMNoSuchState;
            }
            break;

        case IOPMNextLowerState:
            i = pm_vars->myCurrentState - 1;
            while ( (int) i >= 0 ) 
            {
                if ( ( pm_vars->thePowerStates[i].outputPowerCharacter & theDesiredState) == (theDesiredState & pm_vars->myCharacterFlags) ) 
                {
                    break;
                }
                i--;
            }
            if ( (int) i < 0 ) 
            {
                return IOPMNoSuchState;
            }
            break;

        case IOPMHighestState:
            i = pm_vars->theNumberOfPowerStates;
            while ( (int) i >= 0 ) 
            {
                i--;
                if ( ( pm_vars->thePowerStates[i].outputPowerCharacter & theDesiredState) == (theDesiredState & pm_vars->myCharacterFlags) ) 
                {
                    break;
                }
            }
            if ( (int) i < 0 ) 
            {
                return IOPMNoSuchState;
            }
            break;

        case IOPMNextHigherState:
            i = pm_vars->myCurrentState + 1;
            while ( i < pm_vars->theNumberOfPowerStates ) 
            {
                if ( ( pm_vars->thePowerStates[i].outputPowerCharacter & theDesiredState) == (theDesiredState & pm_vars->myCharacterFlags) ) 
                {
                    break;
                }
                i++;
            }
            if ( i == pm_vars->theNumberOfPowerStates ) 
            {
                return IOPMNoSuchState;
            }
            break;

        default:
            return IOPMBadSpecification;
    }

    computedState = i;
    
    IOLockLock(pm_vars->childLock);

    // Now loop through the children.  When we encounter the calling child, save
    // the computed state as this child's desire.
    iter = getChildIterator(gIOPowerPlane);

    if ( iter ) 
    {
        while ( (next = iter->getNextObject()) ) 
        {
            if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) 
            {
                if ( connection == whichChild ) 
                {
                    connection->setDesiredDomainState(computedState);
                    connection->setPreventIdleSleepFlag(desiredState & kIOPMPreventIdleSleep);
                    connection->setPreventSystemSleepFlag(desiredState & kIOPMPreventSystemSleep);
                    connection->setChildHasRequestedPower();
                }
            }
        }
        iter->release();
    }

    // Since a child's power requirements may have changed, clear and rebuild 
    // kIOPMChildClamp and kIOPMChildClamp2 (idle and system sleep clamps)
    rebuildChildClampBits();
        
    IOLockUnlock(pm_vars->childLock);
    
    // this may be different now
    computeDesiredState();

    if ( inPlane(gIOPowerPlane) &&
         (pm_vars->parentsKnowState) ) {
         // change state if all children can now tolerate lower power
        changeState();
    }
   
    // are we clamped on, waiting for this child?
    if ( priv->clampOn ) {
        // yes, remove the clamp
        priv->clampOn = false;
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

    if ( pm_vars->theControllingDriver == NULL ) 
    {
        priv->need_to_become_usable = true;
        return IOPMNoErr;
    }
    priv->deviceDesire = pm_vars->theNumberOfPowerStates - 1;
    computeDesiredState();
    if ( inPlane(gIOPowerPlane) && (pm_vars->parentsKnowState) ) 
    {
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
    if ( pm_vars->theControllingDriver == NULL ) 
    {
        return 0;
    } else {
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

    if ( ordinal >= pm_vars->theNumberOfPowerStates ) 
    {
        return IOPMParameterError;
    }
    priv->driverDesire = ordinal;
    computeDesiredState();
    if ( inPlane(gIOPowerPlane) && (pm_vars->parentsKnowState) ) 
    {
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

    if ( pm_vars->theControllingDriver == NULL) 
    {
        return IOPMNotYetInitialized;
    }
    if ( ordinal >= pm_vars->theNumberOfPowerStates ) 
    {
        return IOPMParameterError;
    }
    priv->deviceDesire = ordinal;
    computeDesiredState();
    if ( inPlane(gIOPowerPlane) && (pm_vars->parentsKnowState) ) 
    {
        return changeState();
    }

    return IOPMNoErr;
}


//*********************************************************************************
// computeDesiredState
//
//*********************************************************************************

void IOService::computeDesiredState ( void )
{
    OSIterator                      *iter;
    OSObject                        *next;
    IOPowerConnection               *connection;
    unsigned long                   newDesiredState = 0;

    // Compute the maximum  of our children's desires, our controlling driver's desire, and the subclass device's desire.
    if ( !  priv->device_overrides ) 
    {
        iter = getChildIterator(gIOPowerPlane);

        if ( iter ) 
        {
            while ( (next = iter->getNextObject()) ) 
            {
                if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) 
                {
                    if ( connection->getDesiredDomainState() > newDesiredState ) 
                    {
                        newDesiredState = connection->getDesiredDomainState();
                    }
                }
            }
            iter->release();
        }
        
        if (  priv->driverDesire > newDesiredState ) 
        {
            newDesiredState =  priv->driverDesire;
        }
    }

    if ( priv->deviceDesire > newDesiredState ) 
    {
        newDesiredState = priv->deviceDesire;
    }

    priv->ourDesiredPowerState = newDesiredState;
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
    // if not fully initialized
    if ( (pm_vars->theControllingDriver == NULL) ||
                    !(inPlane(gIOPowerPlane)) ||
                    !(pm_vars->parentsKnowState) ) 
    {
        // we can do no more
        return IOPMNoErr;
    }
    
    return enqueuePowerChange(IOPMWeInitiated,priv->ourDesiredPowerState,0,0,0);
}


//*********************************************************************************
// currentPowerConsumption
//
//*********************************************************************************

unsigned long IOService::currentPowerConsumption ( void )
{
    if ( pm_vars->theControllingDriver == NULL ) 
    {
        return kIOPMUnknown;
    }
    if ( pm_vars->thePowerStates[pm_vars->myCurrentState].capabilityFlags & kIOPMStaticPowerValid ) 
    {
        return  pm_vars->thePowerStates[pm_vars->myCurrentState].staticPower;
    }
    return kIOPMUnknown;
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

bool IOService::activityTickle ( unsigned long type, unsigned long stateNumber )
{
    IOPMrootDomain                      *pmRootDomain;
    AbsoluteTime                        uptime;

    if ( type == kIOPMSuperclassPolicy1 ) 
    {
        if ( pm_vars->theControllingDriver == NULL ) 
        {
            return true;
        }
        
        if( priv->activityLock == NULL )
        {
            priv->activityLock = IOLockAlloc();
        }
        
        IOTakeLock(priv->activityLock);
        priv->device_active = true;

        clock_get_uptime(&uptime);
        priv->device_active_timestamp = uptime;

        if ( pm_vars->myCurrentState >= stateNumber) 
        {
            IOUnlock(priv->activityLock);
            return true;
        }
        IOUnlock(priv->activityLock);
                
        // Transfer execution to the PM workloop
        if( (pmRootDomain = getPMRootDomain()) )
            pmRootDomain->unIdleDevice(this, stateNumber);

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
    IOService                       *nub;
    IOService                       *parent;

    if ( ! inPlane(gIOPowerPlane) ) 
    {
        return NULL;
    }
    // we have no workloop yet
    if ( pm_vars->PMworkloop == NULL ) 
    {
        nub = (IOService *)copyParentEntry(gIOPowerPlane);
        if ( nub ) 
        {
            parent = (IOService *)nub->copyParentEntry(gIOPowerPlane);
            nub->release();
            // ask one of our parents for the workloop
            if ( parent ) 
            {
                pm_vars->PMworkloop = parent->getPMworkloop();
                parent->release();
            }
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

    if ( period > 0 ) 
    {
        if ( getPMworkloop() == NULL ) 
        {
            return kIOReturnError;
        }
        
       	// make the timer event
        if (  priv->timerEventSrc == NULL ) 
        {
            priv->timerEventSrc = IOTimerEventSource::timerEventSource(this,
                                                    PM_idle_timer_expired);
            if ((!priv->timerEventSrc) ||
                    (pm_vars->PMworkloop->addEventSource(priv->timerEventSrc) != kIOReturnSuccess) ) 
            {
                return kIOReturnError;
            }
        }

        if ( priv->activityLock == NULL ) 
        {
            priv->activityLock = IOLockAlloc();
        }

        start_PM_idle_timer();
    }
    return IOPMNoErr;
}

//******************************************************************************
// nextIdleTimeout
//
// Returns how many "seconds from now" the device should idle into its
// next lowest power state.
//******************************************************************************
SInt32 IOService::nextIdleTimeout(
    AbsoluteTime currentTime,
    AbsoluteTime lastActivity, 
    unsigned int powerState)
{
    AbsoluteTime                        delta;
    UInt64                              delta_ns;
    SInt32                              delta_secs;
    SInt32                              delay_secs;

    // Calculate time difference using funky macro from clock.h.
    delta = currentTime;
    SUB_ABSOLUTETIME(&delta, &lastActivity);
    
    // Figure it in seconds.
    absolutetime_to_nanoseconds(delta, &delta_ns);
    delta_secs = (SInt32)(delta_ns / NSEC_PER_SEC);

    // Be paranoid about delta somehow exceeding timer period.
    if (delta_secs < (int) priv->idle_timer_period ) 
        delay_secs = (int) priv->idle_timer_period - delta_secs;
    else
        delay_secs = (int) priv->idle_timer_period;
    
    return (SInt32)delay_secs;
}

//******************************************************************************
// start_PM_idle_timer
//
// The parameter is a pointer to us.  Use it to call our timeout method.
//******************************************************************************
void IOService::start_PM_idle_timer ( void )
{
    static const int                    maxTimeout = 100000;
    static const int                    minTimeout = 1;
    AbsoluteTime                        uptime;
    SInt32                              idle_in = 0;

    IOLockLock(priv->activityLock);

    clock_get_uptime(&uptime);
    
    // Subclasses may modify idle sleep algorithm
    idle_in = nextIdleTimeout(uptime, 
        priv->device_active_timestamp,
        pm_vars->myCurrentState);

    // Check for out-of range responses
    if(idle_in > maxTimeout)
    {
        // use standard implementation
        idle_in = IOService::nextIdleTimeout(uptime,
                        priv->device_active_timestamp,
                        pm_vars->myCurrentState);
    } else if(idle_in < minTimeout) {
        // fire immediately
        idle_in = 0;
    }

    priv->timerEventSrc->setTimeout(idle_in, NSEC_PER_SEC);

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
    if ( ! initialized ) 
    {
        // we're unloading
        return;
    }

    if (  priv->idle_timer_period > 0 ) 
    {
        IOTakeLock(priv->activityLock);
        if ( priv->device_active ) 
        {
            priv->device_active = false;
            IOUnlock(priv->activityLock);
            start_PM_idle_timer();
            return;
        }
        if ( pm_vars->myCurrentState > 0 ) 
        {
            IOUnlock(priv->activityLock);
            changePowerStateToPriv(pm_vars->myCurrentState - 1);
            start_PM_idle_timer();
            return;
        }
        IOUnlock(priv->activityLock);
        start_PM_idle_timer();
    }
}


// **********************************************************************************
// command_received
//
// We are un-idling a device due to its activity tickle. This routine runs on the
// PM workloop, and is initiated by IOService::activityTickle.
// We process all activityTickle state requests on the list.
// **********************************************************************************
void IOService::command_received ( void *statePtr , void *, void * , void * )
{
    unsigned long                       stateNumber;

    stateNumber = (unsigned long)statePtr;

    // If not initialized, we're unloading
    if ( ! initialized ) return;					

    if ( (pm_vars->myCurrentState < stateNumber) &&
            (priv->imminentState < stateNumber) ) 
    {
        changePowerStateToPriv(stateNumber);

        // After we raise our state, re-schedule the idle timer.
        if(priv->timerEventSrc)
            start_PM_idle_timer();
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
    OSIterator                          *iter;
    OSObject                            *next;
    IOPowerConnection                   *connection;
    IOService                           *child;

    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogSetAggressiveness,type, newLevel);

    if ( type <= kMaxType ) 
    {
        pm_vars->current_aggressiveness_values[type] = newLevel;
        pm_vars->current_aggressiveness_valid[type] = true;
    }

    iter = getChildIterator(gIOPowerPlane);

    if ( iter ) 
    {
        while ( (next = iter->getNextObject()) ) 
        {
            if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) 
            {
                child = ((IOService *)(connection->copyChildEntry(gIOPowerPlane)));
                if ( child ) 
                {
                    child->setAggressiveness(type, newLevel);
                    child->release();
                }
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
    if ( type > kMaxType ) 
        return kIOReturnBadArgument;

    if ( !pm_vars->current_aggressiveness_valid[type] )
        return kIOReturnInvalid;
 
    *currentLevel = pm_vars->current_aggressiveness_values[type];
    
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
    OSIterator                          *iter;
    OSObject                            *next;
    IOPowerConnection                   *connection;
    IOService                           *theChild;

    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogSystemWake,0, 0);

    iter = getChildIterator(gIOPowerPlane);

    if ( iter ) 
    {
        while ( (next = iter->getNextObject()) ) 
        {
            if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) 
            {
                theChild = (IOService *)connection->copyChildEntry(gIOPowerPlane);
                if ( theChild ) 
                {
                	theChild->systemWake();
                    theChild->release();
                }
            }
        }
        iter->release();
    }

    if ( pm_vars->theControllingDriver != NULL ) 
    {
        if ( pm_vars->theControllingDriver->didYouWakeSystem() ) 
        {
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
    IOService                       *theParent;
    IOService                       *theNub;
    
    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogCriticalTemp,0,0);

    if ( inPlane(gIOPowerPlane) && !(priv->we_are_root) ) 
    {
        theNub = (IOService *)copyParentEntry(gIOPowerPlane);
        if ( theNub ) 
        {
            theParent = (IOService *)theNub->copyParentEntry(gIOPowerPlane);
            theNub->release();
            if ( theParent ) 
            {
                theParent->temperatureCriticalForZone(whichZone);
                theParent->release();
            }
        }
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

    // turn on the override
    priv->device_overrides = true;
    computeDesiredState();
    
    // change state if that changed something
    return changeState();
}


//*********************************************************************************
// powerOverrideOffPriv
//
//*********************************************************************************
IOReturn IOService::powerOverrideOffPriv ( void )
{
    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogOverrideOff,0,0);

    // turn off the override
    priv->device_overrides = false;
    computeDesiredState();
    if( priv->clampOn)
    {
        return makeUsable();
    } else {
        // change state if that changed something
        return changeState();
    }
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

IOReturn IOService::enqueuePowerChange ( unsigned long flags,  unsigned long whatStateOrdinal, unsigned long domainState, IOPowerConnection * whichParent, unsigned long singleParentState )
{
    long                            newNote;
    long                            previousNote;

    // Create and initialize the new change note

    IOLockLock(priv->queue_lock);
    newNote = priv->changeList->createChangeNote();
    if ( newNote == -1 ) {
        // uh-oh, our list is full
        IOLockUnlock(priv->queue_lock);
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogEnqueueErr,0,0);
        return IOPMAckImplied;
    }

    priv->changeList->changeNote[newNote].newStateNumber = whatStateOrdinal;
    priv->changeList->changeNote[newNote].outputPowerCharacter = pm_vars->thePowerStates[whatStateOrdinal].outputPowerCharacter;
    priv->changeList->changeNote[newNote].inputPowerRequirement = pm_vars->thePowerStates[whatStateOrdinal].inputPowerRequirement;
    priv->changeList->changeNote[newNote].capabilityFlags = pm_vars->thePowerStates[whatStateOrdinal].capabilityFlags;
    priv->changeList->changeNote[newNote].flags = flags;
    priv->changeList->changeNote[newNote].parent = NULL;
    if (flags & IOPMParentInitiated ) 
    {
        priv->changeList->changeNote[newNote].domainState = domainState;
        priv->changeList->changeNote[newNote].parent = whichParent;
        whichParent->retain();
        priv->changeList->changeNote[newNote].singleParentState = singleParentState;
    }

    previousNote = priv->changeList->previousChangeNote(newNote);

    if ( previousNote == -1 ) 
    {

        // Queue is empty, we can start this change.

        if (flags & IOPMWeInitiated ) 
        {
            IOLockUnlock(priv->queue_lock);
            start_our_change(newNote);
            return 0;
        } else {
            IOLockUnlock(priv->queue_lock);
            return start_parent_change(newNote);
        }
    }

    // The queue is not empty.  Try to collapse this new change and the previous one in queue into one change.
    // This is possible only if both changes are initiated by us, and neither has been started yet.
    // Do this more than once if possible.

    // (A change is started iff it is at the head of the queue)

    while ( (previousNote != priv->head_note) &&  (previousNote != -1) &&
            (priv->changeList->changeNote[newNote].flags &  priv->changeList->changeNote[previousNote].flags &  IOPMWeInitiated)  ) 
    {
        priv->changeList->changeNote[previousNote].outputPowerCharacter = priv->changeList->changeNote[newNote].outputPowerCharacter;
        priv->changeList->changeNote[previousNote].inputPowerRequirement = priv->changeList->changeNote[newNote].inputPowerRequirement;
        priv->changeList->changeNote[previousNote].capabilityFlags =priv-> changeList->changeNote[newNote].capabilityFlags;
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogCollapseQueue,priv->changeList->changeNote[newNote].newStateNumber,
                                                                    priv->changeList->changeNote[previousNote].newStateNumber);
        priv->changeList->changeNote[previousNote].newStateNumber = priv->changeList->changeNote[newNote].newStateNumber;
        priv->changeList->releaseTailChangeNote();
        newNote = previousNote;
        previousNote = priv->changeList->previousChangeNote(newNote);
    }
    IOLockUnlock(priv->queue_lock);
    // in any case, we can't start yet
    return IOPMWillAckLater;
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

    nextObject =  priv->interestedDrivers->firstInList();
    while (  nextObject != NULL ) {
        priv->head_note_pendingAcks +=1;
        if (! inform(nextObject, is_prechange) ) 
        {
        }
        nextObject  =  priv->interestedDrivers->nextInList(nextObject);
    }

    if (! acquire_lock() ) {
        return IOPMNoErr;
    }
    // did they all ack?
    if ( priv->head_note_pendingAcks > 1 ) {
        // no
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogStartAckTimer,0,0);
        start_ack_timer();
    }
    // either way
    IOUnlock(priv->our_lock);

    // notify children
    iter = getChildIterator(gIOPowerPlane);
    // summing their power consumption
    pm_vars->thePowerStates[priv->head_note_state].staticPower = 0;

    if ( iter ) 
    {
        while ( (next = iter->getNextObject()) ) 
        {
            if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) 
            {
                priv->head_note_pendingAcks +=1;
                notifyChild(connection, is_prechange);
            }
        }
        iter->release();
    }

    if (! acquire_lock() ) {
        return IOPMNoErr;
    }
    // now make this real
    priv->head_note_pendingAcks -= 1;
    // is it all acked?
    if (priv->head_note_pendingAcks == 0 ) {
        // yes, all acked
        IOUnlock(priv->our_lock);
        // return ack to parent
        return IOPMAckImplied;
    }

    // not all acked
    IOUnlock(priv->our_lock);
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
    IOReturn                            k = IOPMAckImplied;
    unsigned long                       childPower;
    IOService                           *theChild;
    
    theChild = (IOService *)(theNub->copyChildEntry(gIOPowerPlane));
    if(!theChild) 
    {
        // The child has been detached since we grabbed the child iterator.
        // Decrement pending_acks, already incremented in notifyAll,
        // to account for this unexpected departure.
        priv->head_note_pendingAcks--;
        return true;
    }
    
    // Unless the child handles the notification immediately and returns
    // kIOPMAckImplied, we'll be awaiting their acknowledgement later.
    theNub->setAwaitingAck(true);
    
    if ( is_prechange ) 
    {
        k = theChild->powerDomainWillChangeTo(priv->head_note_outputFlags,theNub);
    } else {
        k = theChild->powerDomainDidChangeTo(priv->head_note_outputFlags,theNub);
    }
    
    // did the return code ack?
    if ( k == IOPMAckImplied ) 
    {
        // yes
        priv->head_note_pendingAcks--;
        theNub->setAwaitingAck(false);
        childPower = theChild->currentPowerConsumption();
        if ( childPower == kIOPMUnknown ) 
        {
            pm_vars->thePowerStates[priv->head_note_state].staticPower = kIOPMUnknown;
        } else {
            if ( pm_vars->thePowerStates[priv->head_note_state].staticPower != kIOPMUnknown ) 
            {
                pm_vars->thePowerStates[priv->head_note_state].staticPower += childPower;
            }
        }
        theChild->release();
        return true;
    }
    theChild->release();
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
    IOReturn                            k = IOPMAckImplied;

    // initialize this
    nextObject->timer = -1;
    
    if ( is_prechange ) 
    {
        pm_vars->thePlatform->PMLog (pm_vars->ourName,PMlogInformDriverPreChange,
                                    (unsigned long)priv->head_note_capabilityFlags,(unsigned long)priv->head_note_state);
        k = nextObject->whatObject->powerStateWillChangeTo( priv->head_note_capabilityFlags,priv->head_note_state,this);
    } else {
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogInformDriverPostChange,
                                    (unsigned long)priv->head_note_capabilityFlags,(unsigned long)priv->head_note_state);
        k = nextObject->whatObject->powerStateDidChangeTo(priv->head_note_capabilityFlags,priv->head_note_state,this);
    }
    
    // did it ack behind our back?
    if ( nextObject->timer == 0 ) 
    {
        // yes
        return true;
    }
    
    // no, did the return code ack?
    if ( k ==IOPMAckImplied ) 
    {
        // yes
        nextObject->timer = 0;
        priv->head_note_pendingAcks -= 1;
        return true;
    }
    if ( k<0 ) 
    {
        // somebody goofed
        nextObject->timer = 0;
        priv-> head_note_pendingAcks -= 1;
        return true;
    }
    
    // no, it's a timer
    nextObject->timer = (k / (ACK_TIMER_PERIOD / ns_per_us)) + 1;

    return false;
}


//*********************************************************************************
// OurChangeTellClientsPowerDown
//
// All registered applications and kernel clients have positively acknowledged our
// intention of lowering power.  Here we notify them all that we will definitely
// lower the power.  If we don't have to wait for any of them to acknowledge, we
// carry on by notifying interested drivers.  Otherwise, we do wait.
//*********************************************************************************

void IOService::OurChangeTellClientsPowerDown ( void )
{
    // next state
    priv->machine_state = kIOPM_OurChangeTellPriorityClientsPowerDown;
    
    // are we waiting for responses?
    if ( tellChangeDown1(priv->head_note_state) ) 
    {
        // no, notify priority clients
        OurChangeTellPriorityClientsPowerDown();
    }
    // If we are waiting for responses, execution will resume via 
    // allowCancelCommon() or ack timeout    
}


//*********************************************************************************
// OurChangeTellPriorityClientsPowerDown
//
// All registered applications and kernel clients have positively acknowledged our
// intention of lowering power.  Here we notify "priority" clients that we are
// lowering power.  If we don't have to wait for any of them to acknowledge, we
// carry on by notifying interested drivers.  Otherwise, we do wait.
//*********************************************************************************

void IOService::OurChangeTellPriorityClientsPowerDown ( void )
{
    // next state
    priv->machine_state = kIOPM_OurChangeNotifyInterestedDriversWillChange;
    // are we waiting for responses?
    if ( tellChangeDown2(priv->head_note_state) ) 
    {
        // no, notify interested drivers
        return OurChangeNotifyInterestedDriversWillChange();
    }
    // If we are waiting for responses, execution will resume via 
    // allowCancelCommon() or ack timeout    
}


//*********************************************************************************
// OurChangeNotifyInterestedDriversWillChange
//
// All registered applications and kernel clients have acknowledged our notification
// that we are lowering power.  Here we notify interested drivers.  If we don't have
// to wait for any of them to acknowledge, we instruct our power driver to make the change.
// Otherwise, we do wait.
//*********************************************************************************

void IOService::OurChangeNotifyInterestedDriversWillChange ( void )
{
    // no, in case they don't all ack
    priv->machine_state = kIOPM_OurChangeSetPowerState;
    if ( notifyAll(true) == IOPMAckImplied ) 
    {
        // not waiting for responses
        OurChangeSetPowerState();
    }
    // If we are waiting for responses, execution will resume via 
    // all_acked() or ack timeout
}


//*********************************************************************************
// OurChangeSetPowerState
//
// All interested drivers have acknowledged our pre-change notification of a power
// change we initiated.  Here we instruct our controlling driver to make
// the change to the hardware.  If it does so, we continue processing
// (waiting for settle and notifying interested parties post-change.)
// If it doesn't, we have to wait for it to acknowledge and then continue.
//*********************************************************************************

void IOService::OurChangeSetPowerState ( void )
{
    priv->machine_state = kIOPM_OurChangeWaitForPowerSettle;

    if ( instruct_driver(priv->head_note_state) == IOPMAckImplied ) 
    {
        // it's done, carry on
        OurChangeWaitForPowerSettle();
    } else {
        // it's not, wait for it
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogStartAckTimer,0,0);
        start_ack_timer();
        // execution will resume via ack_timer_ticked()
    }
}


//*********************************************************************************
// OurChangeWaitForPowerSettle
//
// Our controlling driver has changed power state on the hardware
// during a power change we initiated.  Here we see if we need to wait
// for power to settle before continuing.  If not, we continue processing
// (notifying interested parties post-change).  If so, we wait and
// continue later.
//*********************************************************************************

void IOService::OurChangeWaitForPowerSettle ( void )
{
    priv->settle_time = compute_settle_time();
    if ( priv->settle_time == 0 ) 
    {
       OurChangeNotifyInterestedDriversDidChange();
    } else {
        priv->machine_state = kIOPM_OurChangeNotifyInterestedDriversDidChange;
        startSettleTimer(priv->settle_time);
    }
}


//*********************************************************************************
// OurChangeNotifyInterestedDriversDidChange
//
// Power has settled on a power change we initiated.  Here we notify
// all our interested parties post-change.  If they all acknowledge, we're
// done with this change note, and we can start on the next one.
// Otherwise we have to wait for acknowledgements and finish up later.
//*********************************************************************************

void IOService::OurChangeNotifyInterestedDriversDidChange ( void )
{
    // in case they don't all ack
    priv->machine_state = kIOPM_OurChangeFinish;
    if ( notifyAll(false) == IOPMAckImplied ) 
    {
        // not waiting for responses
        OurChangeFinish();
    }
    // If we are waiting for responses, execution will resume via 
    // all_acked() or ack timeout
}


//*********************************************************************************
// OurChangeFinish
//
// Power has settled on a power change we initiated, and
// all our interested parties have acknowledged.  We're
// done with this change note, and we can start on the next one.
//*********************************************************************************

void IOService::OurChangeFinish ( void )
{
    all_done();
}


//*********************************************************************************
// ParentDownTellPriorityClientsPowerDown_Immediate
//
// All applications and kernel clients have been notified of a power lowering
// initiated by the parent and we didn't have to wait for any responses.  Here
// we notify any priority clients.  If they all ack, we continue with the power change.
// If at least one doesn't, we have to wait for it to acknowledge and then continue.
//*********************************************************************************

IOReturn IOService::ParentDownTellPriorityClientsPowerDown_Immediate ( void )
{
    // in case they don't all ack
    priv->machine_state = kIOPM_ParentDownNotifyInterestedDriversWillChange_Delayed;
    // are we waiting for responses?
    if ( tellChangeDown2(priv->head_note_state) ) 
    {
        // no, notify interested drivers
        return ParentDownNotifyInterestedDriversWillChange_Immediate();
    }
    // If we are waiting for responses, execution will resume via 
    // allowCancelCommon() or ack timeout
    return IOPMWillAckLater;
}


//*********************************************************************************
// ParentDownTellPriorityClientsPowerDown_Immediate2
//
// All priority kernel clients have been notified of a power lowering
// initiated by the parent and we didn't have to wait for any responses.  Here
// we notify any interested drivers and power domain children.  If they all ack,
// we continue with the power change.
// If at least one doesn't, we have to wait for it to acknowledge and then continue.
//*********************************************************************************

IOReturn IOService::ParentDownNotifyInterestedDriversWillChange_Immediate ( void )
{
    // in case they don't all ack
    priv->machine_state = kIOPM_ParentDownSetPowerState_Delayed;
    if ( notifyAll(true) == IOPMAckImplied ) 
    {
        // they did
        return ParentDownSetPowerState_Immediate();
    }
    // If we are waiting for responses, execution will resume via 
    // all_acked() or ack timeout
    return IOPMWillAckLater;
}


//*********************************************************************************
// ParentDownTellPriorityClientsPowerDown_Immediate4
//
// All applications and kernel clients have been notified of a power lowering
// initiated by the parent and we had to wait for responses.  Here
// we notify any priority clients.  If they all ack, we continue with the power change.
// If at least one doesn't, we have to wait for it to acknowledge and then continue.
//*********************************************************************************

void IOService::ParentDownTellPriorityClientsPowerDown_Delayed ( void )
{
    // in case they don't all ack
    priv->machine_state = kIOPM_ParentDownNotifyInterestedDriversWillChange_Delayed;

    // are we waiting for responses?
    if ( tellChangeDown2(priv->head_note_state) ) 
    {
        // no, notify interested drivers
        ParentDownNotifyInterestedDriversWillChange_Delayed();
    }
    // If we are waiting for responses, execution will resume via 
    // allowCancelCommon() or ack timeout
}


//*********************************************************************************
// ParentDownTellPriorityClientsPowerDown_Immediate5
//
// All applications and kernel clients have been notified of a power lowering
// initiated by the parent and we had to wait for their responses.  Here we notify
// any interested drivers and power domain children.  If they all ack, we continue
// with the power change.
// If at least one doesn't, we have to wait for it to acknowledge and then continue.
//*********************************************************************************

void IOService::ParentDownNotifyInterestedDriversWillChange_Delayed ( void )
{
    // in case they don't all ack
    priv->machine_state = kIOPM_ParentDownSetPowerState_Delayed;
    if ( notifyAll(true) == IOPMAckImplied ) 
    {
        // they did
        ParentDownSetPowerState_Delayed();
    }
    // If we are waiting for responses, execution will resume via 
    // all_acked() or ack timeout
}


//*********************************************************************************
// ParentDownSetPowerState_Immediate
//
// All parties have acknowledged our pre-change notification of a power
// lowering initiated by the parent.  Here we instruct our controlling driver
// to put the hardware in the state it needs to be in when the domain is
// lowered.  If it does so, we continue processing
// (waiting for settle and acknowledging the parent.)
// If it doesn't, we have to wait for it to acknowledge and then continue.
//*********************************************************************************

IOReturn IOService::ParentDownSetPowerState_Immediate ( void )
{
    priv->machine_state = kIOPM_ParentDownWaitForPowerSettle_Delayed;

    if ( instruct_driver(priv->head_note_state) == IOPMAckImplied ) 
    {
        // it's done, carry on
        return ParentDownWaitForPowerSettleAndNotifyDidChange_Immediate();
    }
    // it's not, wait for it
    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogStartAckTimer,0,0);
    start_ack_timer();
    return IOPMWillAckLater;
}


//*********************************************************************************
// ParentDownSetPowerState_Delayed
//
// We had to wait for it, but all parties have acknowledged our pre-change
// notification of a power lowering initiated by the parent.
// Here we instruct our controlling driver
// to put the hardware in the state it needs to be in when the domain is
// lowered.  If it does so, we continue processing
// (waiting for settle and acknowledging the parent.)
// If it doesn't, we have to wait for it to acknowledge and then continue.
//*********************************************************************************

void IOService::ParentDownSetPowerState_Delayed ( void )
{
    priv-> machine_state = kIOPM_ParentDownWaitForPowerSettle_Delayed;

    if ( instruct_driver(priv->head_note_state) == IOPMAckImplied ) 
    {
        // it's done, carry on
        ParentDownWaitForPowerSettle_Delayed();
    } else {
        // it's not, wait for it
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogStartAckTimer,0,0);
        start_ack_timer();
    }
}


//*********************************************************************************
// ParentDownWaitForPowerSettleAndNotifyDidChange_Immediate
//
// Our controlling driver has changed power state on the hardware
// during a power change initiated by our parent.  Here we see if we need
// to wait for power to settle before continuing.  If not, we continue
// processing (acknowledging our preparedness to the parent).
// If so, we wait and continue later.
//*********************************************************************************

IOReturn IOService::ParentDownWaitForPowerSettleAndNotifyDidChange_Immediate ( void )
{
    IOService * nub;
    
    priv->settle_time = compute_settle_time();
    if ( priv->settle_time == 0 ) 
    {
        // store current state in case they don't all ack
        priv->machine_state = kIOPM_ParentDownAcknowledgeChange_Delayed;
        if ( notifyAll(false) == IOPMAckImplied ) 
        {
            // not waiting for responses
            nub = priv->head_note_parent;
            nub->retain();
            all_done();
            nub->release();
            return IOPMAckImplied;
        }
        // If we are waiting for responses, execution will resume via 
        // all_acked() or ack timeout        
        return IOPMWillAckLater;
   } else {
        // let settle time elapse, then notify interest drivers of our power state change in ParentDownNotifyDidChangeAndAcknowledgeChange_Delayed
        priv->machine_state = kIOPM_ParentDownNotifyDidChangeAndAcknowledgeChange_Delayed;
        startSettleTimer(priv->settle_time);
        return IOPMWillAckLater;
   }
}


//*********************************************************************************
// ParentDownWaitForPowerSettle_Delayed
//
// Our controlling driver has changed power state on the hardware
// during a power change initiated by our parent.  We have had to wait
// for acknowledgement from interested parties, or we have had to wait
// for the controlling driver to change the state.  Here we see if we need
// to wait for power to settle before continuing.  If not, we continue
// processing (acknowledging our preparedness to the parent).
// If so, we wait and continue later.
//*********************************************************************************

void IOService::ParentDownWaitForPowerSettle_Delayed ( void )
{
    priv->settle_time = compute_settle_time();
    if ( priv->settle_time == 0 ) 
    {
        ParentDownNotifyDidChangeAndAcknowledgeChange_Delayed();
   } else {
       priv->machine_state = kIOPM_ParentDownNotifyDidChangeAndAcknowledgeChange_Delayed;
       startSettleTimer(priv->settle_time);
   }
}


//*********************************************************************************
// ParentDownNotifyDidChangeAndAcknowledgeChange_Delayed
//
// Power has settled on a power change initiated by our parent.  Here we
// notify interested parties.
//*********************************************************************************

void IOService::ParentDownNotifyDidChangeAndAcknowledgeChange_Delayed ( void )
{
    IORegistryEntry                         *nub;
    IOService                               *parent;

    // in case they don't all ack
    priv->machine_state = kIOPM_ParentDownAcknowledgeChange_Delayed;
    if ( notifyAll(false) == IOPMAckImplied ) {
        nub = priv->head_note_parent;
        nub->retain();
        all_done();
        parent = (IOService *)nub->copyParentEntry(gIOPowerPlane);
        if ( parent ) {
            parent->acknowledgePowerChange((IOService *)nub);
            parent->release();
        }
        nub->release();
    }
    // If we are waiting for responses, execution will resume via 
    // all_acked() or ack timeout in ParentDownAcknowledgeChange_Delayed.
    // Notice the duplication of code just above and in ParentDownAcknowledgeChange_Delayed.
}


//*********************************************************************************
// ParentDownAcknowledgeChange_Delayed
//
// We had to wait for it, but all parties have acknowledged our post-change
// notification of a power  lowering initiated by the parent.
// Here we acknowledge the parent.
// We are done with this change note, and we can start on the next one.
//*********************************************************************************

void IOService::ParentDownAcknowledgeChange_Delayed ( void )
{
    IORegistryEntry                         *nub;
    IOService                               *parent;
    
    nub = priv->head_note_parent;
    nub->retain();
    all_done();
    parent = (IOService *)nub->copyParentEntry(gIOPowerPlane);
    if ( parent ) 
    {
        parent->acknowledgePowerChange((IOService *)nub);
        parent->release();
    }
    nub->release();
}


//*********************************************************************************
// ParentUpSetPowerState_Delayed
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

void IOService::ParentUpSetPowerState_Delayed ( void )
{
    priv->machine_state = kIOPM_ParentUpWaitForSettleTime_Delayed;
 
    if ( instruct_driver(priv->head_note_state) == IOPMAckImplied ) 
    {
        // it did it, carry on
        ParentUpWaitForSettleTime_Delayed();
    } else {
        // it didn't, wait for it
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogStartAckTimer,0,0);
        start_ack_timer();
    }
}


//*********************************************************************************
// ParentUpSetPowerState_Immediate
//
// Our parent has informed us via powerStateDidChange that it has
// raised the power in our power domain.  Here we instruct our controlling
// driver to program the hardware to take advantage of the higher domain
// power.  If it does so, we continue processing
// (waiting for settle and notifying interested parties post-change.)
// If it doesn't, we have to wait for it to acknowledge and then continue.
//*********************************************************************************

IOReturn IOService::ParentUpSetPowerState_Immediate ( void )
{
    priv->machine_state = kIOPM_ParentUpWaitForSettleTime_Delayed;

    if ( instruct_driver(priv->head_note_state) == IOPMAckImplied ) 
    {
        // it did it, carry on
        return ParentUpWaitForSettleTime_Immediate();
    }
    else {
        // it didn't, wait for it
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogStartAckTimer,0,0);
        start_ack_timer();
        return IOPMWillAckLater;
    }
}


//*********************************************************************************
// ParentUpWaitForSettleTime_Immediate
//
// Our controlling driver has changed power state on the hardware
// during a power raise initiated by the parent.  Here we see if we need to wait
// for power to settle before continuing.  If not, we continue processing
// (notifying interested parties post-change).  If so, we wait and
// continue later.
//*********************************************************************************

IOReturn IOService::ParentUpWaitForSettleTime_Immediate ( void )
{
    priv->settle_time = compute_settle_time();
    if ( priv->settle_time == 0 ) 
    {
        return ParentUpNotifyInterestedDriversDidChange_Immediate();
    } else {
        priv->machine_state = kIOPM_ParentUpNotifyInterestedDriversDidChange_Delayed;
        startSettleTimer(priv->settle_time);
        return IOPMWillAckLater;
    }
}


//*********************************************************************************
// ParentUpWaitForSettleTime_Delayed
//
// Our controlling driver has changed power state on the hardware
// during a power raise initiated by the parent, but we had to wait for it.
// Here we see if we need to wait for power to settle before continuing.
// If not, we continue processing  (notifying interested parties post-change).
// If so, we wait and continue later.
//*********************************************************************************

void IOService::ParentUpWaitForSettleTime_Delayed ( void )
{
    priv->settle_time = compute_settle_time();
    if ( priv->settle_time == 0 ) 
    {
        ParentUpNotifyInterestedDriversDidChange_Delayed();
    } else {
        priv->machine_state = kIOPM_ParentUpNotifyInterestedDriversDidChange_Delayed;
        startSettleTimer(priv->settle_time);
    }
}


//*********************************************************************************
// ParentUpNotifyInterestedDriversDidChange_Immediate
//
// No power settling was required on a power raise initiated by the parent.
// Here we notify all our interested parties post-change.  If they all acknowledge,
// we're done with this change note, and we can start on the next one.
// Otherwise we have to wait for acknowledgements and finish up later.
//*********************************************************************************

IOReturn IOService::ParentUpNotifyInterestedDriversDidChange_Immediate ( void )
{
    IOService * nub;
    
    // in case they don't all ack
    priv->machine_state = kIOPM_ParentUpAcknowledgePowerChange_Delayed;
    if ( notifyAll(false) == IOPMAckImplied ) 
    {
        nub = priv->head_note_parent;
        nub->retain();
        all_done();
        nub->release();
        return IOPMAckImplied;
    }
    // If we are waiting for responses, execution will resume via 
    // all_acked() or ack timeout in ParentUpAcknowledgePowerChange_Delayed.
    return IOPMWillAckLater;
}


//*********************************************************************************
// ParentUpNotifyInterestedDriversDidChange_Delayed
//
// Power has settled on a power raise initiated by the parent.
// Here we notify all our interested parties post-change.  If they all acknowledge,
// we're done with this change note, and we can start on the next one.
// Otherwise we have to wait for acknowledgements and finish up later.
//*********************************************************************************

void IOService::ParentUpNotifyInterestedDriversDidChange_Delayed ( void )
{
    // in case they don't all ack
    priv->machine_state = kIOPM_ParentUpAcknowledgePowerChange_Delayed;
    if ( notifyAll(false) == IOPMAckImplied ) 
    {
        ParentUpAcknowledgePowerChange_Delayed();
    }
    // If we are waiting for responses, execution will resume via 
    // all_acked() or ack timeout in ParentUpAcknowledgePowerChange_Delayed.
}


//*********************************************************************************
// ParentUpAcknowledgePowerChange_Delayed
//
// All parties have acknowledged our post-change notification of a power
// raising initiated by the parent.  Here we acknowledge the parent.
// We are done with this change note, and we can start on the next one.
//*********************************************************************************

void IOService::ParentUpAcknowledgePowerChange_Delayed ( void )
{
    IORegistryEntry                         *nub;
    IOService                               *parent;
    
    nub = priv->head_note_parent;
    nub->retain();
    all_done();
    parent = (IOService *)nub->copyParentEntry(gIOPowerPlane);
    if ( parent ) 
    {
        parent->acknowledgePowerChange((IOService *)nub);
        parent->release();
    }
    nub->release();
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
    unsigned long                           previous_state;
    IORegistryEntry                         *nub;
    IOService                               *parent;
    
    priv->machine_state = kIOPM_Finished;

    // our power change
    if ( priv->head_note_flags & IOPMWeInitiated ) 
    {
        // could our driver switch to the new state?
        if ( !( priv->head_note_flags & IOPMNotDone) ) 
        {
            // yes, did power raise?
            if ( pm_vars->myCurrentState < priv->head_note_state ) 
            {
                // yes, inform clients and apps
                tellChangeUp (priv->head_note_state);
            } else {
                // no, if this lowers our
                if ( !  priv->we_are_root ) 
                {
                    // power requirements, tell the parent
                    ask_parent(priv->head_note_state);
                }
            }
            previous_state = pm_vars->myCurrentState;
            // either way
            pm_vars->myCurrentState = priv->head_note_state;
            priv->imminentState = pm_vars->myCurrentState;
            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogChangeDone,(unsigned long)pm_vars->myCurrentState,0);
            // inform subclass policy-maker
            powerChangeDone(previous_state);
        }
    }

    // parent's power change
    if ( priv->head_note_flags & IOPMParentInitiated) 
    {
        if ( ((priv->head_note_flags & IOPMDomainWillChange) && (pm_vars->myCurrentState >= priv->head_note_state)) ||
                 ((priv->head_note_flags & IOPMDomainDidChange) && (pm_vars->myCurrentState < priv->head_note_state)) ) 
        {
            // did power raise?
            if ( pm_vars->myCurrentState < priv->head_note_state ) 
            {
                // yes, inform clients and apps
                tellChangeUp (priv->head_note_state);
            }
            // either way
            previous_state = pm_vars->myCurrentState;
            pm_vars->myCurrentState = priv->head_note_state;
            priv->imminentState = pm_vars->myCurrentState;
            pm_vars->maxCapability = pm_vars->theControllingDriver->maxCapabilityForDomainState(priv->head_note_domainState);

            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogChangeDone,(unsigned long)pm_vars->myCurrentState,0);
            // inform subclass policy-maker
            powerChangeDone(previous_state);
        }
    }

    IOLockLock(priv->queue_lock);
    // we're done with this
    priv->changeList->releaseHeadChangeNote();
        
    // start next one in queue
    priv->head_note = priv->changeList->currentChange();
    if ( priv->head_note != -1 ) 
    {

        IOLockUnlock(priv->queue_lock);
        if (priv->changeList->changeNote[priv->head_note].flags & IOPMWeInitiated ) 
        {
            start_our_change(priv->head_note);
        } else {
            nub = priv->changeList->changeNote[priv->head_note].parent;
            if ( start_parent_change(priv->head_note) == IOPMAckImplied ) 
            {
                parent = (IOService *)nub->copyParentEntry(gIOPowerPlane);
                if ( parent ) 
                {
                    parent->acknowledgePowerChange((IOService *)nub);
                    parent->release();
                }
            }
        }
    } else {
        IOLockUnlock(priv->queue_lock);
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
       case kIOPM_OurChangeSetPowerState:
           OurChangeSetPowerState();
           break;
       case kIOPM_OurChangeFinish:
           OurChangeFinish();
           break;
       case kIOPM_ParentDownSetPowerState_Delayed:
           ParentDownSetPowerState_Delayed();	
           break;
       case kIOPM_ParentDownAcknowledgeChange_Delayed:
           ParentDownAcknowledgeChange_Delayed();
           break;
       case kIOPM_ParentUpSetPowerState_Delayed:
           ParentUpSetPowerState_Delayed();
           break;
       case kIOPM_ParentUpAcknowledgePowerChange_Delayed:
           ParentUpAcknowledgePowerChange_Delayed();
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
    if ( ! initialized ) 
    {
        // we're unloading
        return;
    }

    switch (priv->machine_state) {
        case kIOPM_OurChangeNotifyInterestedDriversDidChange:
            OurChangeNotifyInterestedDriversDidChange();
            break;
        case kIOPM_ParentDownNotifyDidChangeAndAcknowledgeChange_Delayed:
            ParentDownNotifyDidChangeAndAcknowledgeChange_Delayed();
            break;
        case kIOPM_ParentUpNotifyInterestedDriversDidChange_Delayed:
            ParentUpNotifyInterestedDriversDidChange_Delayed();
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
    unsigned long                           totalTime;
    unsigned long                           i;

    // compute total time to attain the new state
    totalTime = 0;
    i = pm_vars->myCurrentState;

    // we're lowering power
    if ( priv->head_note_state < pm_vars->myCurrentState ) 
    {
        while ( i > priv->head_note_state ) 
        {
            totalTime +=  pm_vars->thePowerStates[i].settleDownTime;
            i--;
        }
    }

    // we're raising power
    if ( priv->head_note_state > pm_vars->myCurrentState ) 
    {
        while ( i < priv->head_note_state ) 
        {
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

    if ( ! initialized ) 
    {
        // we're unloading
        return;
    }

    if (! acquire_lock() ) 
    {
        return;
    }
    
    switch (priv->machine_state) {
        case kIOPM_OurChangeWaitForPowerSettle:
        case kIOPM_ParentDownWaitForPowerSettle_Delayed:
        case kIOPM_ParentUpWaitForSettleTime_Delayed:
            // are we waiting for our driver to make its change?
            if ( priv->driver_timer != 0 ) {
                // yes, tick once
                priv->driver_timer -= 1;
                // it's tardy, we'll go on without it
                if ( priv->driver_timer == 0 ) 
                {
                    IOUnlock(priv->our_lock);
                    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogCtrlDriverTardy,0,0);
                    driver_acked();
                } else {
                    // still waiting, set timer again
                    start_ack_timer();
                    IOUnlock(priv->our_lock);
                }
            }
            else {
                IOUnlock(priv->our_lock);
            }
            break;

        case kIOPM_OurChangeSetPowerState:
        case kIOPM_OurChangeFinish:
        case kIOPM_ParentDownSetPowerState_Delayed:
        case kIOPM_ParentDownAcknowledgeChange_Delayed:
        case kIOPM_ParentUpSetPowerState_Delayed:
        case kIOPM_ParentUpAcknowledgePowerChange_Delayed:
            // are we waiting for interested parties to acknowledge?
            if (priv->head_note_pendingAcks != 0 ) 
            {
                // yes, go through the list of interested drivers
                nextObject =  priv->interestedDrivers->firstInList();
                // and check each one
                while (  nextObject != NULL ) 
                {
                    if ( nextObject->timer > 0 ) 
                    {
                        nextObject->timer -= 1;
                        // this one should have acked by now
                        if ( nextObject->timer == 0 ) 
                        {
                            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogIntDriverTardy,0,0);
                            //kprintf("interested driver tardy: %s\n",nextObject->whatObject->getName());
                            priv->head_note_pendingAcks -= 1;
                        }
                    }
                    nextObject  =  priv->interestedDrivers->nextInList(nextObject);
                }

                // is that the last?
                if ( priv->head_note_pendingAcks == 0 ) 
                {
                    IOUnlock(priv->our_lock);
                    // yes, we can continue
                    all_acked();
                } else {
                    // no, set timer again
                    start_ack_timer();
                    IOUnlock(priv->our_lock);
                }
            } else {
                IOUnlock(priv->our_lock);
            }
            break;

        // apps didn't respond to parent-down notification
        case kIOPM_ParentDownTellPriorityClientsPowerDown_Immediate:
            IOUnlock(priv->our_lock);
            IOLockLock(priv->flags_lock);
            if (pm_vars->responseFlags) 
            {
                // get rid of this stuff
                pm_vars->responseFlags->release();
                pm_vars->responseFlags = NULL;
            }
            IOLockUnlock(priv->flags_lock);
            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogClientTardy,0,5);
            // carry on with the change
            ParentDownTellPriorityClientsPowerDown_Delayed();
            break;
            
        case kIOPM_ParentDownNotifyInterestedDriversWillChange_Delayed:
            IOUnlock(priv->our_lock);
            IOLockLock(priv->flags_lock);
            if (pm_vars->responseFlags) 
            {
                // get rid of this stuff
                pm_vars->responseFlags->release();
                pm_vars->responseFlags = NULL;
            }
            IOLockUnlock(priv->flags_lock);
            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogClientTardy,0,1);
            // carry on with the change
            ParentDownNotifyInterestedDriversWillChange_Delayed();
            break;
            
        case kIOPM_OurChangeTellClientsPowerDown:
            // apps didn't respond to our power-down request
            IOUnlock(priv->our_lock);
            IOLockLock(priv->flags_lock);
            if (pm_vars->responseFlags) 
            {
                // get rid of this stuff
                pm_vars->responseFlags->release();
                pm_vars->responseFlags = NULL;
            }
            IOLockUnlock(priv->flags_lock);
            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogClientTardy,0,2);
            // rescind the request
            tellNoChangeDown(priv->head_note_state);
            // mark the change note un-actioned
            priv->head_note_flags |= IOPMNotDone;
            // and we're done
            all_done();
            break;
            
        case kIOPM_OurChangeTellPriorityClientsPowerDown:
            // clients didn't respond to our power-down note
            IOUnlock(priv->our_lock);
            IOLockLock(priv->flags_lock);
            if (pm_vars->responseFlags) 
            {
                // get rid of this stuff
                pm_vars->responseFlags->release();
                pm_vars->responseFlags = NULL;
            }
            IOLockUnlock(priv->flags_lock);
            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogClientTardy,0,4);
            // carry on with the change
            OurChangeTellPriorityClientsPowerDown();
            break;
            
        case kIOPM_OurChangeNotifyInterestedDriversWillChange:
             // apps didn't respond to our power-down notification
            IOUnlock(priv->our_lock);
            IOLockLock(priv->flags_lock);
            if (pm_vars->responseFlags) 
            {
                // get rid of this stuff
                pm_vars->responseFlags->release();
                pm_vars->responseFlags = NULL;
            }
            IOLockUnlock(priv->flags_lock);
            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogClientTardy,0,3);
            // carry on with the change
            OurChangeNotifyInterestedDriversWillChange();
            break;
            
        default:
            // not waiting for acks
            IOUnlock(priv->our_lock);
            break;
    }
}


//*********************************************************************************
// start_ack_timer
//
//*********************************************************************************

void IOService::start_ack_timer ( void )
{
    AbsoluteTime                            deadline;

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
    if (! acquire_lock() ) 
    {
        return IOPMNoErr;
    }

    switch (priv->machine_state) 
    {
        case kIOPM_OurChangeSetPowerState:
        case kIOPM_ParentDownSetPowerState_Delayed:
        case kIOPM_ParentUpSetPowerState_Delayed:
            // one for this child and one to prevent
            priv->head_note_pendingAcks += 2;
            // incoming acks from changing our state
            IOUnlock(priv->our_lock);
            notifyChild(newObject, true);
            if (! acquire_lock() ) 
            {
                // put it back
                --priv->head_note_pendingAcks;
                return IOPMNoErr;
            }
            // are we still waiting for acks?
            if ( --priv->head_note_pendingAcks == 0 ) 
            {
                // no, stop the timer
                stop_ack_timer();
                IOUnlock(priv->our_lock);
                
                // and now we can continue
                all_acked();
                return IOPMNoErr;
            }
            break;
        case kIOPM_OurChangeFinish:
        case kIOPM_ParentDownAcknowledgeChange_Delayed:
        case kIOPM_ParentUpAcknowledgePowerChange_Delayed:
            // one for this child and one to prevent
            priv->head_note_pendingAcks += 2;
            // incoming acks from changing our state
            IOUnlock(priv->our_lock);
            notifyChild(newObject, false);
            if (! acquire_lock() ) 
            {
                // put it back
                --priv->head_note_pendingAcks;
                return IOPMNoErr;
            }
            // are we still waiting for acks?
            if ( --priv->head_note_pendingAcks == 0 ) 
            {
                // no, stop the timer
                stop_ack_timer();
                IOUnlock(priv->our_lock);

                // and now we can continue
                all_acked();
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
    if (! acquire_lock() ) 
    {
        return IOPMNoErr;
    }

    switch (priv->machine_state) {
        case kIOPM_OurChangeSetPowerState:
        case kIOPM_ParentDownSetPowerState_Delayed:
        case kIOPM_ParentUpSetPowerState_Delayed:
            // one for this driver and one to prevent
            priv->head_note_pendingAcks += 2;
            // incoming acks from changing our state
            IOUnlock(priv->our_lock);
            // inform the driver
            inform(newObject, true);
            if (! acquire_lock() ) 
            {
                // put it back
                --priv->head_note_pendingAcks;
                return IOPMNoErr;
            }
            // are we still waiting for acks?
            if ( --priv->head_note_pendingAcks == 0 ) 
            {
                // no, stop the timer
                stop_ack_timer();
                IOUnlock(priv->our_lock);

                // and now we can continue
                all_acked();
                return IOPMNoErr;
            }
            break;
        case kIOPM_OurChangeFinish:
        case kIOPM_ParentDownAcknowledgeChange_Delayed:
        case kIOPM_ParentUpAcknowledgePowerChange_Delayed:
            // one for this driver and one to prevent
            priv->head_note_pendingAcks += 2;
            // incoming acks from changing our state
            IOUnlock(priv->our_lock);
            // inform the driver
            inform(newObject, false);
            if (! acquire_lock() ) {
                // put it back
                --priv->head_note_pendingAcks;
                return IOPMNoErr;
            }
            // are we still waiting for acks?
            if ( --priv->head_note_pendingAcks == 0 ) {
                // no, stop the timer
                stop_ack_timer();
                IOUnlock(priv->our_lock);

                // and now we can continue
                all_acked();
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
    priv->imminentState = priv->head_note_state;
    priv->head_note_outputFlags =  priv->changeList->changeNote[priv->head_note].outputPowerCharacter;
    priv->head_note_domainState = priv->changeList->changeNote[priv->head_note].domainState;
    priv->head_note_parent = priv->changeList->changeNote[priv->head_note].parent;
    priv->head_note_capabilityFlags =  priv->changeList->changeNote[priv->head_note].capabilityFlags;

    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogStartParentChange,
                    (unsigned long)priv->head_note_state,(unsigned long)pm_vars->myCurrentState);

    // if we need something and haven't told the parent, do so
    ask_parent( priv->ourDesiredPowerState);

    // power domain is lowering
    if ( priv->head_note_state < pm_vars->myCurrentState ) 
    {
        setParentInfo(priv->changeList->changeNote[priv->head_note].singleParentState,priv->head_note_parent);
    	priv->initial_change = false;
    	// tell apps and kernel clients
        priv->machine_state = kIOPM_ParentDownTellPriorityClientsPowerDown_Immediate;

        // are we waiting for responses?
        if ( tellChangeDown1(priv->head_note_state) ) 
        {
            // no, notify priority clients
            return ParentDownTellPriorityClientsPowerDown_Immediate();
        }
        // yes
        return IOPMWillAckLater;
    }

    // parent is raising power, we may or may not
    if ( priv->head_note_state > pm_vars->myCurrentState ) 
    {
        if ( priv->ourDesiredPowerState > pm_vars->myCurrentState ) 
        {
            if ( priv->ourDesiredPowerState < priv->head_note_state ) 
            {
                // we do, but not all the way
                priv->head_note_state = priv->ourDesiredPowerState;
                priv->imminentState = priv->head_note_state;
                priv->head_note_outputFlags =   pm_vars->thePowerStates[priv->head_note_state].outputPowerCharacter;
                priv->head_note_capabilityFlags =   pm_vars->thePowerStates[priv->head_note_state].capabilityFlags;
                pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogAmendParentChange,(unsigned long)priv->head_note_state,0);
             }
        } else {
            // we don't
            priv->head_note_state = pm_vars->myCurrentState;
            priv->imminentState = priv->head_note_state;
            priv->head_note_outputFlags =   pm_vars->thePowerStates[priv->head_note_state].outputPowerCharacter;
            priv->head_note_capabilityFlags =   pm_vars->thePowerStates[priv->head_note_state].capabilityFlags;
            pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogAmendParentChange,(unsigned long)priv->head_note_state,0);
        }
    }

    if ( (priv->head_note_state > pm_vars->myCurrentState) &&
                    (priv->head_note_flags & IOPMDomainDidChange) ) 
    {
        // changing up
        priv->initial_change = false;
        priv->machine_state = kIOPM_ParentUpSetPowerState_Delayed;
        if (  notifyAll(true) == IOPMAckImplied ) {
            return ParentUpSetPowerState_Immediate();
        }
        // they didn't all ack
        return IOPMWillAckLater;
    }

    all_done();
    // a null change or power will go up
    return IOPMAckImplied;
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
    priv->imminentState = priv->head_note_state;
    priv->head_note_outputFlags =  priv->changeList->changeNote[priv->head_note].outputPowerCharacter;
    priv->head_note_capabilityFlags =  priv->changeList->changeNote[priv->head_note].capabilityFlags;

    pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogStartDeviceChange,
                (unsigned long)priv->head_note_state,(unsigned long)pm_vars->myCurrentState);

    // can our driver switch to the new state?
    if ( priv->head_note_capabilityFlags & IOPMNotAttainable ) 
    {
        // no, ask the parent to do it then
        if ( !  priv->we_are_root )
        {
            ask_parent(priv->head_note_state);
        }
        // mark the change note un-actioned
        priv-> head_note_flags |= IOPMNotDone;
        // and we're done
        all_done();
        return;
    }
    
    // is there enough power in the domain?
    if ( (pm_vars->maxCapability < priv->head_note_state) && (!  priv->we_are_root) ) 
    {
        // no, ask the parent to raise it
        if ( !  priv->we_are_root ) 
        {
            ask_parent(priv->head_note_state);
        }
        // no, mark the change note un-actioned
        priv->head_note_flags |= IOPMNotDone;
        // and we're done
        // till the parent raises power
        all_done();
        return;
    }

    if ( !  priv->initial_change ) 
    {
        if ( priv->head_note_state == pm_vars->myCurrentState ) 
        {
            // we initiated a null change; forget it
            all_done();
            return;
        }
    }
    priv->initial_change = false;

    // dropping power?
    if ( priv->head_note_state < pm_vars->myCurrentState ) 
    {
        // yes, in case we have to wait for acks
        priv->machine_state = kIOPM_OurChangeTellClientsPowerDown;
        pm_vars->doNotPowerDown = false;

        // ask apps and kernel clients if we can drop power
        pm_vars->outofbandparameter = kNotifyApps;
        if ( askChangeDown(priv->head_note_state) ) 
        {
            // don't have to wait, did any clients veto?
            if ( pm_vars->doNotPowerDown ) 
            {
                // yes, rescind the warning
                tellNoChangeDown(priv->head_note_state);
                // mark the change note un-actioned
                priv-> head_note_flags |= IOPMNotDone;
                // and we're done
                all_done();
            } else {
                // no, tell'em we're dropping power
                OurChangeTellClientsPowerDown();
            }
        }
    } else {
        // we are raising power
        if ( !  priv->we_are_root ) 
        {
            // if this changes our power requirement, tell the parent
            ask_parent(priv->head_note_state);
        }
        // in case they don't all ack
        priv->machine_state = kIOPM_OurChangeSetPowerState;

        // notify interested drivers and children
        if ( notifyAll(true) == IOPMAckImplied ) 
        {
            OurChangeSetPowerState();
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
    OSIterator                          *iter;
    OSObject                            *next;
    IOPowerConnection                   *connection;
    IOService                           *parent;
    unsigned long                       ourRequest = pm_vars->thePowerStates[requestedState].inputPowerRequirement;

    if ( pm_vars->thePowerStates[requestedState].capabilityFlags & (kIOPMChildClamp | kIOPMPreventIdleSleep) ) 
    {
        ourRequest |= kIOPMPreventIdleSleep;
    }
    if ( pm_vars->thePowerStates[requestedState].capabilityFlags & (kIOPMChildClamp2 | kIOPMPreventSystemSleep) ) 
    {
        ourRequest |= kIOPMPreventSystemSleep;
    }
    
    // is this a new desire?
    if ( priv->previousRequest == ourRequest )
    {	
        // no, the parent knows already, just return
        return IOPMNoErr;				
    }

    if (  priv->we_are_root ) 
    {
        return IOPMNoErr;
    }
    priv->previousRequest =  ourRequest;

    iter = getParentIterator(gIOPowerPlane);

    if ( iter ) 
    {
        while ( (next = iter->getNextObject()) ) 
        {
            if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) 
            {
                parent = (IOService *)connection->copyParentEntry(gIOPowerPlane);
                if ( parent ) {
                    if ( parent->requestPowerDomainState(ourRequest,connection,IOPMLowestState)!= IOPMNoErr ) 
                    {
                        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogRequestDenied,
                                                                (unsigned long)priv->previousRequest,0);
                    }
                    parent->release();
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
    IOReturn delay;

    // can our driver switch to the desired state?
    if (  pm_vars->thePowerStates[newState].capabilityFlags & IOPMNotAttainable ) 
    {
        // no, so don't try
        return IOPMAckImplied;
    }

    priv->driver_timer = -1;

    // yes, instruct it
    OUR_PMLog(          kPMLogProgramHardware, (UInt32) this, newState);
    delay = pm_vars->theControllingDriver->setPowerState( newState,this );
    OUR_PMLog((UInt32) -kPMLogProgramHardware, (UInt32) this, (UInt32) delay);

    // it finished
    if ( delay == IOPMAckImplied ) 
    {
        priv->driver_timer = 0;
        return IOPMAckImplied;
    }

    // it acked behind our back
    if ( priv->driver_timer == 0 ) 
    {
        return IOPMAckImplied;
    }

    // somebody goofed
    if ( delay < 0 ) 
    {
        return IOPMAckImplied;
    }
    
    // it didn't finish
    priv->driver_timer = (delay / ( ACK_TIMER_PERIOD / ns_per_us )) + 1;
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
    if ( current_change_note == priv->head_note ) 
    {
        return TRUE;
    } else {
        // we blocked and something changed radically
        // so there's nothing to do any more
        IOUnlock(priv->our_lock);
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

bool IOService::askChangeDown ( unsigned long stateNum )
{
    return tellClientsWithResponse(kIOMessageCanDevicePowerOff);
}


//*********************************************************************************
// tellChangeDown1
//
// Notify registered applications and kernel clients that we are definitely
// dropping power.
//
// Return true if we don't have to wait for acknowledgements
//*********************************************************************************

bool IOService::tellChangeDown1 ( unsigned long stateNum )
{
    pm_vars->outofbandparameter = kNotifyApps;
    return tellChangeDown(stateNum);
}


//*********************************************************************************
// tellChangeDown2
//
// Notify priority clients that we are definitely dropping power.
//
// Return true if we don't have to wait for acknowledgements
//*********************************************************************************

bool IOService::tellChangeDown2 ( unsigned long stateNum )
{
    pm_vars->outofbandparameter = kNotifyPriority;
    return tellChangeDown(stateNum);
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

bool IOService::tellChangeDown ( unsigned long stateNum )
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
    struct context                          theContext;
    AbsoluteTime                            deadline;
    OSBoolean                               *aBool;

    pm_vars->responseFlags = OSArray::withCapacity( 1 );
    pm_vars->serialNumber += 1;
    
    theContext.responseFlags = pm_vars->responseFlags;
    theContext.serialNumber = pm_vars->serialNumber;
    theContext.flags_lock = priv->flags_lock;
    theContext.counter = 1;
    theContext.msgType = messageType;
    theContext.us = this;
    theContext.maxTimeRequested = 0;
    theContext.stateNumber = priv->head_note_state;
    theContext.stateFlags = priv->head_note_capabilityFlags;

    IOLockLock(priv->flags_lock);

    // position zero is false to
    // prevent allowCancelCommon from succeeding
    aBool = OSBoolean::withBoolean(false);
    theContext.responseFlags->setObject(0,aBool);
    aBool->release();
    IOLockUnlock(priv->flags_lock);

    switch ( pm_vars->outofbandparameter ) {
        case kNotifyApps:
            applyToInterested(gIOAppPowerStateInterest,tellAppWithResponse,(void *)&theContext);
            applyToInterested(gIOGeneralInterest,tellClientWithResponse,(void *)&theContext);
            break;
        case kNotifyPriority:
            applyToInterested(gIOPriorityPowerStateInterest,tellClientWithResponse,(void *)&theContext);
            break;
    }

    if (! acquire_lock() ) 
    {
        return true;
    }
    IOLockLock(priv->flags_lock);
    // now fix position zero
    aBool = OSBoolean::withBoolean(true);
    theContext.responseFlags->replaceObject(0,aBool);
    aBool->release();
    IOLockUnlock(priv->flags_lock);
    
    // do we have to wait for somebody?
    if ( ! checkForDone() ) 
    {
        // yes, start the ackTimer
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogStartAckTimer,theContext.maxTimeRequested,0);
        clock_interval_to_deadline(theContext.maxTimeRequested / 1000, kMillisecondScale, &deadline);
        
        thread_call_enter_delayed(priv->ackTimer, deadline);
    
        IOUnlock(priv->our_lock);			
        return false;
    }
    
    IOUnlock(priv->our_lock);
    IOLockLock(priv->flags_lock);
    
    // everybody responded
    pm_vars->responseFlags->release();
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
    struct context                      *theContext = (struct context *)context;
    OSBoolean                           *aBool;
    IOPMprot 				*pm_vars = theContext->us->pm_vars;

    if( OSDynamicCast( IOService, object) ) 
    {
	// Automatically 'ack' in kernel clients
        IOLockLock(theContext->flags_lock);
        aBool = OSBoolean::withBoolean(true);
        theContext->responseFlags->setObject(theContext->counter,aBool);
        aBool->release();
        IOLockUnlock(theContext->flags_lock);

	const char *who = ((IOService *) object)->getName();
	pm_vars->thePlatform->PMLog(who,
	    kPMLogClientAcknowledge, theContext->msgType, * (UInt32 *) object);
    } else {
        UInt32 refcon = ((theContext->serialNumber & 0xFFFF)<<16)
	              +  (theContext->counter & 0xFFFF);
        IOLockLock(theContext->flags_lock);
        aBool = OSBoolean::withBoolean(false);
        theContext->responseFlags->setObject(theContext->counter,aBool);
        aBool->release();
        IOLockUnlock(theContext->flags_lock);

	OUR_PMLog(kPMLogAppNotify, theContext->msgType, refcon);
        theContext->us->messageClient(theContext->msgType,object,(void *)refcon);
        if ( theContext->maxTimeRequested < k30seconds ) 
        {
            theContext->maxTimeRequested = k30seconds;
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
    struct context                          *theContext = (struct context *)context;
    IOPowerStateChangeNotification          notify;
    UInt32                                  refcon;
    IOReturn                                retCode;
    OSBoolean                               *aBool;
    OSObject                                *theFlag;
    
    refcon = ((theContext->serialNumber & 0xFFFF)<<16) + (theContext->counter & 0xFFFF);
    IOLockLock(theContext->flags_lock);
    aBool = OSBoolean::withBoolean(false);
    theContext->responseFlags->setObject(theContext->counter,aBool);
    aBool->release();
    IOLockUnlock(theContext->flags_lock);

    IOPMprot *pm_vars = theContext->us->pm_vars;
    if (gIOKitDebug & kIOLogPower) {
	OUR_PMLog(kPMLogClientNotify, refcon, (UInt32) theContext->msgType);
	if (OSDynamicCast(IOService, object)) {
	    const char *who = ((IOService *) object)->getName();
	    pm_vars->thePlatform->PMLog(who,
		    kPMLogClientNotify, * (UInt32 *) object, (UInt32) object);
	} else if (OSDynamicCast(_IOServiceInterestNotifier, object)) {
	    _IOServiceInterestNotifier *n = (_IOServiceInterestNotifier *) object;
	    OUR_PMLog(kPMLogClientNotify, (UInt32) n->handler, 0);
	}
    }

    notify.powerRef = (void *)refcon;
    notify.returnValue = 0;
    notify.stateNumber = theContext->stateNumber;
    notify.stateFlags = theContext->stateFlags;
    retCode = theContext->us->messageClient(theContext->msgType,object,(void *)&notify);
    if ( retCode == kIOReturnSuccess ) 
    {
        if ( notify.returnValue == 0 ) 
        {
            // client doesn't want time to respond
            IOLockLock(theContext->flags_lock);
            aBool = OSBoolean::withBoolean(true);
            // so set its flag true
            theContext->responseFlags->replaceObject(theContext->counter,aBool);
            aBool->release();
            IOLockUnlock(theContext->flags_lock);
	    OUR_PMLog(kPMLogClientAcknowledge, refcon, (UInt32) object);
        } else {
            IOLockLock(theContext->flags_lock);
            
            // it does want time, and it hasn't responded yet
            theFlag = theContext->responseFlags->getObject(theContext->counter);
            if ( theFlag != 0 ) 
            {
                if ( ((OSBoolean *)theFlag)->isFalse() ) 
                {
                    // so note its time requirement
                    if ( theContext->maxTimeRequested < notify.returnValue ) 
                    {
                        theContext->maxTimeRequested = notify.returnValue;
                    }
                }
            }
            IOLockUnlock(theContext->flags_lock);
        }
    } else {
	OUR_PMLog(kPMLogClientAcknowledge, refcon, 0);
        // not a client of ours
        IOLockLock(theContext->flags_lock);
        // so we won't be waiting for response
        aBool = OSBoolean::withBoolean(true);
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
    theContext.stateNumber = priv->head_note_state;
    theContext.stateFlags = priv->head_note_capabilityFlags;

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
    struct context                              *theContext = (struct context *)context;
    IOPowerStateChangeNotification              notify;

    notify.powerRef	= (void *) 0;
    notify.returnValue	= 0;
    notify.stateNumber	= theContext->stateNumber;
    notify.stateFlags	= theContext->stateFlags;

    theContext->us->messageClient(theContext->msgType,object, &notify);
}


// **********************************************************************************
// checkForDone
//
// **********************************************************************************
bool IOService::checkForDone ( void )
{
    int                                         i = 0;
    OSObject                                    *theFlag;

    IOLockLock(priv->flags_lock);
    if ( pm_vars->responseFlags == NULL ) 
    {
        IOLockUnlock(priv->flags_lock);
        return true;
    }
    
    for ( i = 0; ; i++ ) 
    {
        theFlag = pm_vars->responseFlags->getObject(i);
        if ( theFlag == NULL ) 
        {
            break;
        }
        if ( ((OSBoolean *)theFlag)->isFalse() ) 
        {
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
    
    if ( serialComponent != pm_vars->serialNumber ) 
    {
        return false;
    }
    
    IOLockLock(priv->flags_lock);
    if ( pm_vars->responseFlags == NULL ) 
    {
        IOLockUnlock(priv->flags_lock);
        return false;
    }
    
    theFlag = pm_vars->responseFlags->getObject(ordinalComponent);
    
    if ( theFlag == 0 ) 
    {
        IOLockUnlock(priv->flags_lock);
        return false;
    }
    
    if ( ((OSBoolean *)theFlag)->isFalse() ) 
    {
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
    if ( ! initialized ) 
    {
        // we're unloading
        return kIOReturnSuccess;
    }

    return pm_vars->PMcommandGate->runAction(serializedAllowPowerChange,(void *)refcon);
}
    
    
IOReturn serializedAllowPowerChange ( OSObject *owner, void * refcon, void *, void *, void *)
{
    return ((IOService *)owner)->serializedAllowPowerChange2((unsigned long)refcon);
}

IOReturn IOService::serializedAllowPowerChange2 ( unsigned long refcon )
{
    // response valid?
    if ( ! responseValid(refcon) ) 
    {
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogAcknowledgeErr5,refcon,0);
        // no, just return
        return kIOReturnSuccess;
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
    if ( ! initialized ) 
    {
        // we're unloading
        return kIOReturnSuccess;
    }

    return pm_vars->PMcommandGate->runAction(serializedCancelPowerChange,(void *)refcon);
}
    
    
IOReturn serializedCancelPowerChange ( OSObject *owner, void * refcon, void *, void *, void *)
{
    return ((IOService *)owner)->serializedCancelPowerChange2((unsigned long)refcon);
}

IOReturn IOService::serializedCancelPowerChange2 ( unsigned long refcon )
{
    // response valid?
    if ( ! responseValid(refcon) ) 
    {
        pm_vars->thePlatform->PMLog(pm_vars->ourName,PMlogAcknowledgeErr5,refcon,0);
        // no, just return
        return kIOReturnSuccess;
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
    if (! acquire_lock() ) 
    {
        return kIOReturnSuccess;
    }

    // is this the last response?
    if ( checkForDone() ) 
    {
        // yes, stop the timer
        stop_ack_timer();
        IOUnlock(priv->our_lock);
        IOLockLock(priv->flags_lock);
        if ( pm_vars->responseFlags ) 
        {
            pm_vars->responseFlags->release();
            pm_vars->responseFlags = NULL;
        }
        IOLockUnlock(priv->flags_lock);
        switch (priv->machine_state) {
            case kIOPM_OurChangeTellClientsPowerDown:
                // our change, was it vetoed?
                if ( ! pm_vars->doNotPowerDown ) 
                {
                    // no, we can continue
                    OurChangeTellClientsPowerDown();
                } else {
                    // yes, rescind the warning
                    tellNoChangeDown(priv->head_note_state);
                    // mark the change note un-actioned
                    priv->head_note_flags |= IOPMNotDone;

                    // and we're done
                    all_done();
                }
                break;
            case kIOPM_OurChangeTellPriorityClientsPowerDown:
                OurChangeTellPriorityClientsPowerDown();  
                break;
            case kIOPM_OurChangeNotifyInterestedDriversWillChange:
                // our change, continue
                OurChangeNotifyInterestedDriversWillChange();
                break;
            case kIOPM_ParentDownTellPriorityClientsPowerDown_Immediate:
                // parent change, continue
                ParentDownTellPriorityClientsPowerDown_Delayed();
                break;
            case kIOPM_ParentDownNotifyInterestedDriversWillChange_Delayed:
                // parent change, continue
                ParentDownNotifyInterestedDriversWillChange_Delayed();
                break;
        }
    } else {
        // not done yet
        IOUnlock(priv->our_lock);
    }

    return kIOReturnSuccess;
}


#if 0
//*********************************************************************************
// c_PM_clamp_Timer_Expired (C Func)
//
// Called when our clamp timer expires...we will call the object method.
//*********************************************************************************

static void c_PM_Clamp_Timer_Expired (OSObject * client, IOTimerEventSource *)
{
    if (client)
        ((IOService *)client)->PM_Clamp_Timer_Expired ();
}
#endif


//*********************************************************************************
// PM_Clamp_Timer_Expired
//
// called when clamp timer expires...set power state to 0.
//*********************************************************************************

void IOService::PM_Clamp_Timer_Expired (void)
{
#if 0
    if ( ! initialized ) 
    {
        // we're unloading
        return;
    }

  changePowerStateToPriv (0);
#endif
}

//******************************************************************************
// clampPowerOn
//
// Set to highest available power state for a minimum of duration milliseconds
//******************************************************************************

#define kFiveMinutesInNanoSeconds (300 * NSEC_PER_SEC)

void IOService::clampPowerOn (unsigned long duration)
{
#if 0
  changePowerStateToPriv (pm_vars->theNumberOfPowerStates-1);

  if (  priv->clampTimerEventSrc == NULL ) {
    priv->clampTimerEventSrc = IOTimerEventSource::timerEventSource(this,
                                                    c_PM_Clamp_Timer_Expired);

    IOWorkLoop * workLoop = getPMworkloop ();

    if ( !priv->clampTimerEventSrc || !workLoop ||
       ( workLoop->addEventSource(  priv->clampTimerEventSrc) != kIOReturnSuccess) ) {

    }
  }

   priv->clampTimerEventSrc->setTimeout(300*USEC_PER_SEC, USEC_PER_SEC);
#endif
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

   if (pm_vars->theNumberOfPowerStates == 0 ) 
   {
       return 0;
   }
   for ( i = (pm_vars->theNumberOfPowerStates)-1; i >= 0; i-- ) 
   {
       if (  (domainState & pm_vars->thePowerStates[i].inputPowerRequirement) == pm_vars->thePowerStates[i].inputPowerRequirement ) 
       {
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

    if (pm_vars->theNumberOfPowerStates == 0 ) 
    {
        return 0;
    }
    for ( i = (pm_vars->theNumberOfPowerStates)-1; i >= 0; i-- ) 
    {
        if (  (domainState & pm_vars->thePowerStates[i].inputPowerRequirement) == pm_vars->thePowerStates[i].inputPowerRequirement ) 
        {
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

    if (pm_vars->theNumberOfPowerStates == 0 ) 
    {
        return 0;
    }
    for ( i = (pm_vars->theNumberOfPowerStates)-1; i >= 0; i-- ) 
    {
        if (  (domainState & pm_vars->thePowerStates[i].inputPowerRequirement) == pm_vars->thePowerStates[i].inputPowerRequirement ) 
        {
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
    int     buf_size;
    int i;
    bool	rtn_code;

    // estimate how many bytes we need to present all power states
    buf_size = 150      // beginning and end of string
                + (275 * (int)theNumberOfPowerStates) // size per state
                + 100;   // extra room just for kicks

    buffer = ptr = IONew(char, buf_size);
    if(!buffer)
        return false;

    ptr += sprintf(ptr,"{ theNumberOfPowerStates = %d, ",(unsigned int)theNumberOfPowerStates);

    if ( theNumberOfPowerStates != 0 ) {
        ptr += sprintf(ptr,"version %d, ",(unsigned int)thePowerStates[0].version);
    }

    if ( theNumberOfPowerStates != 0 ) {
        for ( i = 0; i < (int)theNumberOfPowerStates; i++ ) {
            ptr += sprintf(ptr, "power state %d = { ",i);
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
    IODelete(buffer, char, buf_size);

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

    if ( machine_state != kIOPM_Finished ) {
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


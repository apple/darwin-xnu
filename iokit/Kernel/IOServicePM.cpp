/*
 * Copyright (c) 1998-2006 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

//#define IOASSERT 1
#include <IOKit/assert.h>
#include <IOKit/IOKitDebug.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMessage.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOService.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOCommand.h>

#include <IOKit/pwr_mgt/IOPMlog.h>
#include <IOKit/pwr_mgt/IOPMinformee.h>
#include <IOKit/pwr_mgt/IOPMinformeeList.h>
#include <IOKit/pwr_mgt/IOPowerConnection.h>
#include <IOKit/pwr_mgt/RootDomain.h>

#include <sys/proc.h>

// Required for notification instrumentation
#include "IOServicePrivate.h"
#include "IOServicePMPrivate.h"
#include "IOKitKernelInternal.h"

static void settle_timer_expired(thread_call_param_t, thread_call_param_t);
static void tellKernelClientApplier(OSObject * object, void * arg);
static void tellAppClientApplier(OSObject * object, void * arg);

static uint64_t computeTimeDeltaNS( const AbsoluteTime * start )
{
    AbsoluteTime    now;
    uint64_t        nsec;

    clock_get_uptime(&now);
    SUB_ABSOLUTETIME(&now, start);
    absolutetime_to_nanoseconds(now, &nsec);
    return nsec;
}

#if PM_VARS_SUPPORT
OSDefineMetaClassAndStructors(IOPMprot, OSObject)
#endif

// log setPowerStates longer than (ns):
#define LOG_SETPOWER_TIMES      (50ULL * 1000ULL * 1000ULL)
// log app responses longer than (ns):
#define LOG_APP_RESPONSE_TIMES  (100ULL * 1000ULL * 1000ULL)
// use message tracer to log messages longer than (ns):
#define LOG_APP_RESPONSE_MSG_TRACER  (3 * 1000ULL * 1000ULL * 1000ULL)

//*********************************************************************************
// Globals
//*********************************************************************************

static bool                  gIOPMInitialized   = false;
static uint32_t              gIOPMBusyCount     = 0;
static IOWorkLoop *          gIOPMWorkLoop      = 0;
static IOPMRequestQueue *    gIOPMRequestQueue  = 0;
static IOPMRequestQueue *    gIOPMReplyQueue    = 0;
static IOPMCompletionQueue * gIOPMFreeQueue     = 0;
static IOPMRequest *         gIOPMRequest       = 0;
static IOPlatformExpert *    gPlatform          = 0;
static IOService *           gIOPMRootNode      = 0;

static const OSSymbol *      gIOPMPowerClientDevice     = 0;
static const OSSymbol *      gIOPMPowerClientDriver     = 0;
static const OSSymbol *      gIOPMPowerClientChildProxy = 0;
static const OSSymbol *      gIOPMPowerClientChildren   = 0;

static uint32_t getPMRequestType( void )
{
    uint32_t type = kIOPMRequestTypeInvalid;
	if (gIOPMRequest)
        type = gIOPMRequest->getType();
    return type;
}

//*********************************************************************************
// Macros
//*********************************************************************************

#define PM_ERROR(x...)          do { kprintf(x); IOLog(x); } while (false)
#define PM_DEBUG(x...)          do { kprintf(x); } while (false)

#define PM_TRACE(x...)          do {  \
	if (kIOLogDebugPower & gIOKitDebug) kprintf(x); } while (false)

#define PM_CONNECT(x...)

#define PM_ASSERT_IN_GATE(x)          \
do {                                  \
    assert(gIOPMWorkLoop->inGate());  \
} while(false)

#define PM_LOCK()                   IOLockLock(fPMLock)
#define PM_UNLOCK()                 IOLockUnlock(fPMLock)
#define PM_LOCK_SLEEP(event)        IOLockSleep(fPMLock, event, THREAD_UNINT)
#define PM_LOCK_WAKEUP(event)       IOLockWakeup(fPMLock, event, false)

#define ns_per_us                   1000
#define k30seconds                  (30*1000000)
#define kMinAckTimeoutTicks         (10*1000000)
#define kIOPMTardyAckSPSKey         "IOPMTardyAckSetPowerState"
#define kIOPMTardyAckPSCKey         "IOPMTardyAckPowerStateChange"
#define kPwrMgtKey                  "IOPowerManagement"

#define OUR_PMLog(t, a, b) \
    do { gPlatform->PMLog( fName, t, a, b); } while(0)

#define NS_TO_MS(nsec)              ((int)((nsec) / 1000000ULL))

#if CONFIG_EMBEDDED
#define SUPPORT_IDLE_CANCEL         1
#endif

#define kNotifyWillChange           (true)
#define kNotifyDidChange            (false)

#define kIOPMPowerStateMax          0xFFFFFFFF  

#define IS_PM_ROOT()                (this == gIOPMRootNode)

//*********************************************************************************
// PM machine states
//*********************************************************************************

enum {
    kIOPM_OurChangeTellClientsPowerDown                 = 1,
    kIOPM_OurChangeTellPriorityClientsPowerDown         = 2,
    kIOPM_OurChangeNotifyInterestedDriversWillChange    = 3,
    kIOPM_OurChangeSetPowerState                        = 4,
    kIOPM_OurChangeWaitForPowerSettle                   = 5,
    kIOPM_OurChangeNotifyInterestedDriversDidChange     = 6,
    kIOPM_OurChangeFinish                               = 7,
    kIOPM_ParentDownTellPriorityClientsPowerDown        = 8,
    kIOPM_ParentDownNotifyInterestedDriversWillChange   = 9,
    /* 10 not used */
    kIOPM_ParentDownNotifyDidChangeAndAcknowledgeChange = 11,
    kIOPM_ParentDownSetPowerState                       = 12,
    kIOPM_ParentDownWaitForPowerSettle                  = 13,
    kIOPM_ParentAcknowledgePowerChange                  = 14,
    kIOPM_ParentUpSetPowerState                         = 15,
    /* 16 not used */
    kIOPM_ParentUpWaitForSettleTime                     = 17,
    kIOPM_ParentUpNotifyInterestedDriversDidChange      = 18,
    /* 19 not used */
    kIOPM_Finished                                      = 20,
    kIOPM_DriverThreadCallDone                          = 21,
    kIOPM_NotifyChildrenDone                            = 22,
    kIOPM_SyncNotifyDidChange                           = 23,
    kIOPM_SyncFinish                                    = 24
};


 /*
 Power Management defines a few roles that drivers can play in their own, 
 and other drivers', power management. We briefly define those here.
 
 Many drivers implement their policy maker and power controller within the same 
 IOService object, but that is not required. 
 
== Policy Maker == 
 * Virtual IOService PM methods a "policy maker" may implement
    * maxCapabilityForDomainState()
    * initialPowerStateForDomainState()
    * powerStateForDomainState()
    
 * Virtual IOService PM methods a "policy maker" may CALL
    * PMinit()
 
== Power Controller ==
 * Virtual IOService PM methods a "power controller" may implement
    * setPowerState() 
 
 * Virtual IOService PM methods a "power controller" may CALL
    * joinPMtree()
    * registerPowerDriver()
 
=======================
 There are two different kinds of power state changes.  
    * One is initiated by a subclassed device object which has either decided
      to change power state, or its controlling driver has suggested it, or
      some other driver wants to use the idle device and has asked it to become
      usable.  
    * The second kind of power state change is initiated by the power domain 
      parent.  
 The two are handled through different code paths.
 
 We maintain a queue of "change notifications," or change notes.
    * Usually the queue is empty. 
    * When it isn't, usually there is one change note in it 
    * It's possible to have more than one power state change pending at one 
        time, so a queue is implemented. 
 Example:  
    * The subclass device decides it's idle and initiates a change to a lower
        power state. This causes interested parties to be notified, but they 
        don't all acknowledge right away.  This causes the change note to sit 
        in the queue until all the acks are received.  During this time, the 
        device decides it isn't idle anymore and wants to raise power back up 
        again.  This change can't be started, however, because the previous one 
        isn't complete yet, so the second one waits in the queue.  During this 
        time, the parent decides to lower or raise the power state of the entire
        power domain and notifies the device, and that notification goes into 
        the queue, too, and can't be actioned until the others are.
 
 == SelfInitiated ==
 This is how a power change initiated by the subclass device is handled:
    -> First, all interested parties are notified of the change via their 
       powerStateWillChangeTo method.  If they all don't acknowledge via return
       code, then we have to wait.  If they do, or when they finally all
       acknowledge via our acknowledgePowerChange method, then we can continue.  
    -> We call the controlling driver, instructing it to change to the new state
    -> Then we wait for power to settle. If there is no settling-time, or after 
       it has passed, 
    -> we notify interested parties again, this time via their 
       powerStateDidChangeTo methods.  
    -> When they have all acked, we're done.
 If we lowered power and don't need the power domain to be in its current power 
 state, we suggest to the parent that it lower the power domain state.
 
 == PowerDomainDownInitiated ==
How a change to a lower power domain state initiated by the parent is handled:
    -> First, we figure out what power state we will be in when the new domain 
        state is reached.  
    -> Then all interested parties are notified that we are moving to that new 
        state.  
    -> When they have acknowledged, we call the controlling driver to assume
        that state and we wait for power to settle.  
    -> Then we acknowledge our preparedness to our parent.  When all its 
        interested parties have acknowledged, 
    -> it lowers power and then notifies its interested parties again.  
    -> When we get this call, we notify our interested parties that the power 
        state has changed, and when they have all acknowledged, we're done.
 
 == PowerDomainUpInitiated ==
How a change to a higher power domain state initiated by the parent is handled:
    -> We figure out what power state we will be in when the new domain state is 
        reached.  
    -> If it is different from our current state we acknowledge the parent.  
    -> When all the parent's interested parties have acknowledged, it raises 
        power in the domain and waits for power to settle.  
    -> Then it  notifies everyone that the new state has been reached.  
    -> When we get this call, we call the controlling driver, instructing it to 
        assume the new state, and wait for power to settle.
    -> Then we notify our interested parties. When they all acknowledge we are 
        done.
 
 In either of the two power domain state cases above, it is possible that we 
 will not be changing state even though the domain is. 
 Examples:
    * A change to a lower domain state may not affect us because we are already 
        in a low enough state, 
    * We will not take advantage of a change to a higher domain state, because 
        we have no need of the higher power. In such cases, there is nothing to 
        do but acknowledge the parent.  So when the parent calls our 
        powerDomainWillChange method, and we decide that we will not be changing 
        state, we merely acknowledge the parent, via return code, and wait.
 When the parent subsequently calls powerStateDidChange, we acknowledge again 
 via return code, and the change is complete.
 
 == 4 Paths Through State Machine ==
 Power state changes are processed in a state machine, and since there are four 
 varieties of power state changes, there are four major paths through the state 
 machine.
 
 == 5. No Need To change ==
 The fourth is nearly trivial.  In this path, the parent is changing the domain 
 state, but we are not changing the device state. The change starts when the 
 parent calls powerDomainWillChange.  All we do is acknowledge the parent. When 
 the parent calls powerStateDidChange, we acknowledge the parent again, and 
 we're done.
 
 == 1. OurChange Down ==    XXX gvdl
 The first is fairly simple.  It starts: 
    * when a power domain child calls requestPowerDomainState and we decide to 
        change power states to accomodate the child, 
    * or if our power-controlling driver calls changePowerStateTo, 
    * or if some other driver which is using our device calls makeUsable, 
    * or if a subclassed object calls changePowerStateToPriv.  
 These are all power changes initiated by us, not forced upon us by the parent.  
 
 -> We start by notifying interested parties.  
        -> If they all acknowledge via return code, we can go on to state 
            "msSetPowerState".  
        -> Otherwise, we start the ack timer and wait for the stragglers to 
            acknowlege by calling acknowledgePowerChange.  
            -> We move on to state "msSetPowerState" when all the 
                stragglers have acknowledged, or when the ack timer expires on 
                all those which didn't acknowledge.  
 In "msSetPowerState" we call the power-controlling driver to change the 
 power state of the hardware.  
    -> If it returns saying it has done so, we go on to state 
        "msWaitForPowerSettle".
    -> Otherwise, we have to wait for it, so we set the ack timer and wait.  
        -> When it calls acknowledgeSetPowerState, or when the ack timer 
            expires, we go on.  
 In "msWaitForPowerSettle", we look in the power state array to see if 
 there is any settle time required when changing from our current state to the 
 new state.  
    -> If not, we go right away to "msNotifyInterestedDriversDidChange".  
    -> Otherwise, we set the settle timer and wait. When it expires, we move on.  
 In "msNotifyInterestedDriversDidChange" state, we notify all our 
 interested parties via their powerStateDidChange methods that we have finished 
 changing power state.  
    -> If they all acknowledge via return code, we move on to "msFinish".  
    -> Otherwise we set the ack timer and wait.  When they have all 
        acknowledged, or when the ack timer has expired for those that didn't, 
        we move on to "msFinish".
 In "msFinish" we remove the used change note from the head of the queue 
 and start the next one if one exists.

 == 2. Parent Change Down ==
 Start at Stage 2 of OurChange Down    XXX gvdl

 == 3. Change Up ==
 Start at Stage 4 of OurChange Down    XXX gvdl

Note all parent requested changes need to acknowledge the power has changed to the parent when done.
 */

//*********************************************************************************
// [public] PMinit
//
// Initialize power management.
//*********************************************************************************

void IOService::PMinit ( void )
{
    if ( !initialized )
	{
		if ( !gIOPMInitialized )
		{
            gPlatform = getPlatform();
			gIOPMWorkLoop = IOWorkLoop::workLoop();
			if (gIOPMWorkLoop)
			{
				gIOPMRequestQueue = IOPMRequestQueue::create(
					this, OSMemberFunctionCast(IOPMRequestQueue::Action,
						this, &IOService::servicePMRequestQueue));

				gIOPMReplyQueue = IOPMRequestQueue::create(
					this, OSMemberFunctionCast(IOPMRequestQueue::Action,
						this, &IOService::servicePMReplyQueue));

				gIOPMFreeQueue = IOPMCompletionQueue::create(
					this, OSMemberFunctionCast(IOPMCompletionQueue::Action,
						this, &IOService::servicePMFreeQueue));

				if (gIOPMWorkLoop->addEventSource(gIOPMRequestQueue) !=
					kIOReturnSuccess)
				{
					gIOPMRequestQueue->release();
					gIOPMRequestQueue = 0;
				}

				if (gIOPMWorkLoop->addEventSource(gIOPMReplyQueue) !=
					kIOReturnSuccess)
				{
					gIOPMReplyQueue->release();
					gIOPMReplyQueue = 0;
				}

				if (gIOPMWorkLoop->addEventSource(gIOPMFreeQueue) !=
					kIOReturnSuccess)
				{
					gIOPMFreeQueue->release();
					gIOPMFreeQueue = 0;
				}

                gIOPMPowerClientDevice     = OSSymbol::withCStringNoCopy( "DevicePowerState" );
                gIOPMPowerClientDriver     = OSSymbol::withCStringNoCopy( "DriverPowerState" );
                gIOPMPowerClientChildProxy = OSSymbol::withCStringNoCopy( "ChildProxyPowerState" );
                gIOPMPowerClientChildren   = OSSymbol::withCStringNoCopy( "ChildrenPowerState" );
			}

			if (gIOPMRequestQueue && gIOPMReplyQueue && gIOPMFreeQueue)
				gIOPMInitialized = true;
		}
		if (!gIOPMInitialized)
			return;

        pwrMgt = new IOServicePM;
        pwrMgt->init();
        setProperty(kPwrMgtKey, pwrMgt);

        fPMLock                     = IOLockAlloc();
        fInterestedDrivers          = new IOPMinformeeList;
        fInterestedDrivers->initialize();
        fDesiredPowerState          = 0;
        fDeviceDesire               = 0;
        fInitialChange              = true;
        fPreviousRequest            = 0;
        fDeviceOverrides            = false;
        fMachineState               = kIOPM_Finished;
        fIdleTimerEventSource       = NULL;
        fIdleTimerMinPowerState     = 0;
        fActivityLock               = IOLockAlloc();
        fStrictTreeOrder            = false;
        fActivityTicklePowerState   = -1;
        fControllingDriver          = NULL;
        fPowerStates                = NULL;
        fNumberOfPowerStates        = 0;
        fCurrentPowerState          = 0;
        fParentsCurrentPowerFlags   = 0;
        fMaxCapability              = 0;
        fName                       = getName();
        fParentsKnowState           = false;
        fSerialNumber               = 0;
        fResponseArray              = NULL;
        fNotifyClientArray          = NULL;
        fDoNotPowerDown             = true;
        fCurrentPowerConsumption    = kIOPMUnknown;
        fOverrideMaxPowerState      = kIOPMPowerStateMax;

        if (!gIOPMRootNode && (getParentEntry(gIOPowerPlane) == getRegistryRoot()))
        {
            gIOPMRootNode = this;
            fParentsKnowState = true;
        }

        fAckTimer = thread_call_allocate(
			&IOService::ack_timer_expired, (thread_call_param_t)this);
        fSettleTimer = thread_call_allocate(
			&settle_timer_expired, (thread_call_param_t)this);
		fDriverCallEntry = thread_call_allocate(
			(thread_call_func_t) &IOService::pmDriverCallout, this);
		assert(fDriverCallEntry);

#if PM_VARS_SUPPORT
        IOPMprot * prot = new IOPMprot;
        if (prot)
        {
            prot->init();
            prot->ourName = fName;
            prot->thePlatform = gPlatform;
            fPMVars = prot;
            pm_vars = prot;
		}
#else
        pm_vars = (void *) true;
#endif

        initialized = true;
    }
}

//*********************************************************************************
// [private] PMfree
//
// Free up the data created in PMinit, if it exists.
//*********************************************************************************

void IOService::PMfree ( void )
{
	initialized = false;
    pm_vars = 0;

    if ( pwrMgt )
	{
		assert(fMachineState == kIOPM_Finished);
		assert(fInsertInterestSet == NULL);
		assert(fRemoveInterestSet == NULL);
        assert(fNotifyChildArray  == NULL);

        if ( fIdleTimerEventSource != NULL ) {
            fIdleTimerEventSource->disable();
            gIOPMWorkLoop->removeEventSource(fIdleTimerEventSource);
            fIdleTimerEventSource->release();
            fIdleTimerEventSource = NULL;
        }
        if ( fSettleTimer ) {
            thread_call_cancel(fSettleTimer);
            thread_call_free(fSettleTimer);
            fSettleTimer = NULL;
        }
        if ( fAckTimer ) {
            thread_call_cancel(fAckTimer);
            thread_call_free(fAckTimer);
            fAckTimer = NULL;
        }
        if ( fDriverCallEntry ) {
            thread_call_free(fDriverCallEntry);
            fDriverCallEntry = NULL;
        }
        if ( fPMLock ) {
            IOLockFree(fPMLock);
            fPMLock = NULL;
        }
        if ( fActivityLock ) {
            IOLockFree(fActivityLock);
            fActivityLock = NULL;
        }
		if ( fInterestedDrivers ) {
			fInterestedDrivers->release();
			fInterestedDrivers = NULL;
		}
		if ( fPMWorkQueue ) {
			gIOPMWorkLoop->removeEventSource(fPMWorkQueue);
			fPMWorkQueue->release();
			fPMWorkQueue = 0;
		}
		if (fDriverCallParamSlots && fDriverCallParamPtr) {
			IODelete(fDriverCallParamPtr, DriverCallParam, fDriverCallParamSlots);
			fDriverCallParamPtr = 0;
			fDriverCallParamSlots = 0;
		}
        if ( fResponseArray ) {
            fResponseArray->release();
            fResponseArray = NULL;
        }
        if ( fNotifyClientArray ) {
            fNotifyClientArray->release();
            fNotifyClientArray = NULL;
        }
        if (fPowerStates && fNumberOfPowerStates) {
            IODelete(fPowerStates, IOPMPowerState, fNumberOfPowerStates);
            fNumberOfPowerStates = 0;
            fPowerStates = NULL;
        }
		if (fPowerClients) {
			fPowerClients->release();
			fPowerClients = 0;
		}

#if PM_VARS_SUPPORT
		if (fPMVars)
		{
			fPMVars->release();
			fPMVars = 0;
		}
#endif

        pwrMgt->release();
		pwrMgt = 0;
    }
}

//*********************************************************************************
// [public] joinPMtree
//
// A policy-maker calls its nub here when initializing, to be attached into
// the power management hierarchy.  The default function is to call the
// platform expert, which knows how to do it.  This method is overridden
// by a nub subclass which may either know how to do it, or may need to
// take other action.
//
// This may be the only "power management" method used in a nub,
// meaning it may not be initialized for power management.
//*********************************************************************************

void IOService::joinPMtree ( IOService * driver )
{
    IOPlatformExpert *  platform;

    platform = getPlatform();
    assert(platform != 0);
    platform->PMRegisterDevice(this, driver);
}

#ifndef __LP64__
//*********************************************************************************
// [deprecated] youAreRoot
//
// Power Managment is informing us that we are the root power domain.
// The only difference between us and any other power domain is that
// we have no parent and therefore never call it.
//*********************************************************************************

IOReturn IOService::youAreRoot ( void )
{
    return IOPMNoErr;
}
#endif /* !__LP64__ */

//*********************************************************************************
// [public] PMstop
//
// Immediately stop driver callouts. Schedule an async stop request to detach
// from power plane.
//*********************************************************************************

void IOService::PMstop ( void )
{
	IOPMRequest * request;

	if (!initialized)
		return;

	// Schedule an async PMstop request, but immediately stop any further
	// calls to the controlling or interested drivers. This device will
	// continue to exist in the power plane and participate in power state
	// changes until the PMstop async request is processed.

	PM_LOCK();
	fLockedFlags.PMStop = true;
    if (fLockedFlags.DriverCallBusy)
    {
        PM_DEBUG("%s: PMstop() driver call busy\n", getName());
    }
    while (fThreadAssertionCount != 0)
    {
        if (current_thread() == fThreadAssertionThread)
        {
            PM_ERROR("%s: PMstop() called from PM thread call\n", getName());
            break;
        }
        // Wait for thread assertions to drop to zero.
        PM_DEBUG("%s: PMstop() wait for %u thread assertion(s)\n",
            getName(), fThreadAssertionCount);
        PM_LOCK_SLEEP(&fThreadAssertionCount);
    }
    PM_UNLOCK();

	request = acquirePMRequest( this, kIOPMRequestTypePMStop );
	if (request)
	{
		PM_TRACE("%s: %p PMstop\n", getName(), this);
		submitPMRequest( request );
	}
}

//*********************************************************************************
// [private] handlePMstop
//
// Disconnect the node from all parents and children in the power plane.
//*********************************************************************************

void IOService::handlePMstop ( IOPMRequest * request )
{
    OSIterator *		iter;
    OSObject *			next;
    IOPowerConnection *	connection;
    IOService *			theChild;
    IOService *			theParent;

	PM_ASSERT_IN_GATE();
	PM_TRACE("%s: %p %s start\n", getName(), this, __FUNCTION__);

    // remove the property
    removeProperty(kPwrMgtKey);			

    // detach parents
    iter = getParentIterator(gIOPowerPlane);
    if ( iter )
    {
        while ( (next = iter->getNextObject()) )
        {
            if ( (connection = OSDynamicCast(IOPowerConnection, next)) )
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
    
    // no more power state changes
    fParentsKnowState = false;

    // detach children
    iter = getChildIterator(gIOPowerPlane);
    if ( iter )
    {
        while ( (next = iter->getNextObject()) )
        {
            if ( (connection = OSDynamicCast(IOPowerConnection, next)) )
            {
                theChild = ((IOService *)(connection->copyChildEntry(gIOPowerPlane)));
                if ( theChild )
                {
                    // detach nub from child
                    connection->detachFromChild(theChild, gIOPowerPlane);
                    theChild->release();
                }
                // detach us from nub
                detachFromChild(connection, gIOPowerPlane);
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

    if ( fInterestedDrivers )
    {
		IOPMinformeeList *	list = fInterestedDrivers;
        IOPMinformee *		item;

		PM_LOCK();
		while ((item = list->firstInList()))
		{
			list->removeFromList(item->whatObject);
		}
		PM_UNLOCK();
	}

	// Tell idleTimerExpired() to ignore idle timer.
	fIdleTimerPeriod = 0;
    if (fIdleTimerEventSource)
        fIdleTimerEventSource->disable();

	PM_TRACE("%s: %p %s done\n", getName(), this, __FUNCTION__);
}

//*********************************************************************************
// [public] addPowerChild
//
// Power Management is informing us who our children are.
//*********************************************************************************

IOReturn IOService::addPowerChild ( IOService * child )
{
	IOPowerConnection *	connection  = 0;
	IOPMRequest *		requests[3] = {0, 0, 0};
    OSIterator *		iter;
	bool				ok = true;

	if (!child)
		return kIOReturnBadArgument;

    if (!initialized || !child->initialized)
		return IOPMNotYetInitialized;

    OUR_PMLog( kPMLogAddChild, (uintptr_t) child, 0 );

	do {
		// Is this child already one of our children?

		iter = child->getParentIterator( gIOPowerPlane );
		if ( iter )
		{
			IORegistryEntry *	entry;
			OSObject *			next;

			while ((next = iter->getNextObject()))
			{
				if ((entry = OSDynamicCast(IORegistryEntry, next)) &&
					isChild(entry, gIOPowerPlane))
				{
					ok = false;
					break;
				}			
			}
			iter->release();
		}
		if (!ok)
		{
			PM_DEBUG("%s: %s (%p) is already a child\n",
				getName(), child->getName(), child);
			break;
		}

		// Add the child to the power plane immediately, but the
		// joining connection is marked as not ready.
		// We want the child to appear in the power plane before
		// returning to the caller, but don't want the caller to
		// block on the PM work loop.

		connection = new IOPowerConnection;
		if (!connection)
			break;

		// Create a chain of PM requests to perform the bottom-half
		// work from the PM work loop.

		requests[0] = acquirePMRequest(
					/* target */ this,
					/* type */   kIOPMRequestTypeAddPowerChild1 );

		requests[1] = acquirePMRequest(
					/* target */ child,
					/* type */   kIOPMRequestTypeAddPowerChild2 );

		requests[2] = acquirePMRequest(
					/* target */ this,
					/* type */   kIOPMRequestTypeAddPowerChild3 );

		if (!requests[0] || !requests[1] || !requests[2])
			break;

		requests[0]->attachNextRequest( requests[1] );
		requests[1]->attachNextRequest( requests[2] );

		connection->init();
		connection->start(this);
		connection->setAwaitingAck(false);
		connection->setReadyFlag(false);

		attachToChild( connection, gIOPowerPlane );
		connection->attachToChild( child, gIOPowerPlane );

		// connection needs to be released
		requests[0]->fArg0 = connection;
		requests[1]->fArg0 = connection;
		requests[2]->fArg0 = connection;

		submitPMRequest( requests, 3 );
		return kIOReturnSuccess;
	}
	while (false);

	if (connection)  connection->release();
	if (requests[0]) releasePMRequest(requests[0]);
	if (requests[1]) releasePMRequest(requests[1]);
	if (requests[2]) releasePMRequest(requests[2]);

	// Silent failure, to prevent platform drivers from adding the child
	// to the root domain.

	return kIOReturnSuccess;
}

//*********************************************************************************
// [private] addPowerChild1
//
// Step 1/3 of adding a power child. Called on the power parent.
//*********************************************************************************

void IOService::addPowerChild1 ( IOPMRequest * request )
{
	unsigned long tempDesire = 0;

	// Make us temporary usable before adding the child.

	PM_ASSERT_IN_GATE();
    OUR_PMLog( kPMLogMakeUsable, kPMLogMakeUsable, 0 );

	if (fControllingDriver && inPlane(gIOPowerPlane) && fParentsKnowState)
	{
		tempDesire = fNumberOfPowerStates - 1;
	}

	if (tempDesire && (IS_PM_ROOT() || (fMaxCapability >= tempDesire)))
	{
		adjustPowerState(tempDesire);
	}
}

//*********************************************************************************
// [private] addPowerChild2
//
// Step 2/3 of adding a power child. Called on the joining child.
// Execution blocked behind addPowerChild1.
//*********************************************************************************

void IOService::addPowerChild2 ( IOPMRequest * request )
{
	IOPowerConnection * connection = (IOPowerConnection *) request->fArg0;
	IOService *         parent;
	IOPMPowerFlags		powerFlags;
	bool				knowsState;
	unsigned long		powerState;
	unsigned long		tempDesire;

	PM_ASSERT_IN_GATE();
	parent = (IOService *) connection->getParentEntry(gIOPowerPlane);

	if (!parent || !inPlane(gIOPowerPlane))
	{
		PM_DEBUG("%s: addPowerChild2 not in power plane\n", getName());
		return;
	}

	// Parent will be waiting for us to complete this stage.
	// It is safe to directly access parent's vars.

	knowsState = (parent->fPowerStates) && (parent->fParentsKnowState);
	powerState = parent->fCurrentPowerState;

	if (knowsState)
		powerFlags = parent->fPowerStates[powerState].outputPowerCharacter;
	else
		powerFlags = 0;

	// Set our power parent.

    OUR_PMLog(kPMLogSetParent, knowsState, powerFlags);

	setParentInfo( powerFlags, connection, knowsState );

	connection->setReadyFlag(true);

    if ( fControllingDriver && fParentsKnowState )
    {
        fMaxCapability = fControllingDriver->maxCapabilityForDomainState(fParentsCurrentPowerFlags);
        // initially change into the state we are already in
        tempDesire = fControllingDriver->initialPowerStateForDomainState(fParentsCurrentPowerFlags);
        fPreviousRequest = 0xffffffff;
        adjustPowerState(tempDesire);
    }

#if ROOT_DOMAIN_RUN_STATES
    getPMRootDomain()->tagPowerPlaneService(this, &fRootDomainState);
#endif
}

//*********************************************************************************
// [private] addPowerChild3
//
// Step 3/3 of adding a power child. Called on the parent.
// Execution blocked behind addPowerChild2.
//*********************************************************************************

void IOService::addPowerChild3 ( IOPMRequest * request )
{
	IOPowerConnection * connection = (IOPowerConnection *) request->fArg0;
	IOService *         child;
    IOPMrootDomain *    rootDomain = getPMRootDomain();

	PM_ASSERT_IN_GATE();
	child = (IOService *) connection->getChildEntry(gIOPowerPlane);

	if (child && inPlane(gIOPowerPlane))
	{
		if (child->getProperty("IOPMStrictTreeOrder"))
		{
			PM_DEBUG("%s: strict PM order enforced\n", getName());
			fStrictTreeOrder = true;
		}

        if (rootDomain)
            rootDomain->joinAggressiveness( child );
	}
	else
	{
		PM_DEBUG("%s: addPowerChild3 not in power plane\n", getName());
	}

	connection->release();
}

#ifndef __LP64__
//*********************************************************************************
// [deprecated] setPowerParent
//
// Power Management is informing us who our parent is.
// If we have a controlling driver, find out, given our newly-informed
// power domain state, what state it would be in, and then tell it
// to assume that state.
//*********************************************************************************

IOReturn IOService::setPowerParent (
	IOPowerConnection * theParent, bool stateKnown, IOPMPowerFlags powerFlags )
{
	return kIOReturnUnsupported;
}
#endif /* !__LP64__ */

//*********************************************************************************
// [public] removePowerChild
//
// Called on a parent whose child is being removed by PMstop().
//*********************************************************************************

IOReturn IOService::removePowerChild ( IOPowerConnection * theNub )
{
    IORegistryEntry *	theChild;

	PM_ASSERT_IN_GATE();
    OUR_PMLog( kPMLogRemoveChild, 0, 0 );

    theNub->retain();

    // detach nub from child
    theChild = theNub->copyChildEntry(gIOPowerPlane);			
    if ( theChild )
    {
        theNub->detachFromChild(theChild, gIOPowerPlane);
        theChild->release();
    }
    // detach from the nub
    detachFromChild(theNub, gIOPowerPlane);

    // Are we awaiting an ack from this child?
    if ( theNub->getAwaitingAck() )
	{
		// yes, pretend we got one
		theNub->setAwaitingAck(false);
		if (fHeadNotePendingAcks != 0 )
		{
			// that's one fewer ack to worry about
			fHeadNotePendingAcks--;

			// is that the last?
			if ( fHeadNotePendingAcks == 0 )
			{
				stop_ack_timer();
			}
		}
	}

	theNub->release();

	// A child has gone away, re-scan children desires and clamp bits.
    // The fPendingAdjustPowerRequest helps to reduce redundant parent work. 

	if (!fAdjustPowerScheduled)
	{
		IOPMRequest * request;
		request = acquirePMRequest( this, kIOPMRequestTypeAdjustPowerState );
		if (request)
		{
			submitPMRequest( request );
			fAdjustPowerScheduled = true;
		}
	}

    return IOPMNoErr;
}

//*********************************************************************************
// [public] registerPowerDriver
//
// A driver has called us volunteering to control power to our device.
//*********************************************************************************

IOReturn IOService::registerPowerDriver (
	IOService *			powerDriver,
	IOPMPowerState *	powerStates,
	unsigned long		numberOfStates )
{
	IOPMRequest *	 request;
	IOPMPowerState * powerStatesCopy = 0;

    if (!initialized)
		return IOPMNotYetInitialized;

	// Validate arguments.
	if (!powerStates || (numberOfStates < 2))
	{
		OUR_PMLog(kPMLogControllingDriverErr5, numberOfStates, 0);
		return kIOReturnBadArgument;
	}

	if (!powerDriver || !powerDriver->initialized)
	{
		OUR_PMLog(kPMLogControllingDriverErr4, 0, 0);
		return kIOReturnBadArgument;
	}

	if (powerStates[0].version != kIOPMPowerStateVersion1)
	{
		OUR_PMLog(kPMLogControllingDriverErr1, powerStates[0].version, 0);
		return kIOReturnBadArgument;
	}

	do {
		// Make a copy of the supplied power state array.
		powerStatesCopy = IONew(IOPMPowerState, numberOfStates);
		if (!powerStatesCopy)
			break;

		bcopy( powerStates, powerStatesCopy,
			sizeof(IOPMPowerState) * numberOfStates );

		request = acquirePMRequest( this, kIOPMRequestTypeRegisterPowerDriver );
		if (!request)
			break;

		powerDriver->retain();
		request->fArg0 = (void *) powerDriver;
		request->fArg1 = (void *) powerStatesCopy;
		request->fArg2 = (void *) numberOfStates;

		submitPMRequest( request );
		return kIOReturnSuccess;
	}
	while (false);

	if (powerStatesCopy)
		IODelete(powerStatesCopy, IOPMPowerState, numberOfStates);
	return kIOReturnNoMemory;
}

//*********************************************************************************
// [private] handleRegisterPowerDriver
//*********************************************************************************

void IOService::handleRegisterPowerDriver ( IOPMRequest * request )
{
	IOService *			powerDriver    = (IOService *)      request->fArg0;
	IOPMPowerState *	powerStates    = (IOPMPowerState *) request->fArg1;
	unsigned long		numberOfStates = (unsigned long)    request->fArg2;
    unsigned long		i;
	IOService *			root;
	OSIterator *		iter;

	PM_ASSERT_IN_GATE();
	assert(powerStates);
	assert(powerDriver);
	assert(numberOfStates > 1);

    if ( !fNumberOfPowerStates )
    {
		OUR_PMLog(kPMLogControllingDriver,
			(unsigned long) numberOfStates,
			(unsigned long) powerStates[0].version);

        fPowerStates            = powerStates;
		fNumberOfPowerStates    = numberOfStates;
		fControllingDriver      = powerDriver;
        fCurrentCapabilityFlags = fPowerStates[0].capabilityFlags;

		// make a mask of all the character bits we know about
		fOutputPowerCharacterFlags = 0;
		for ( i = 0; i < numberOfStates; i++ ) {
			fOutputPowerCharacterFlags |= fPowerStates[i].outputPowerCharacter;
		}

		// Register powerDriver as interested, unless already done.
		// We don't want to register the default implementation since
		// it does nothing. One ramification of not always registering
		// is the one fewer retain count held.

		root = getPlatform()->getProvider();
		assert(root);
		if (!root ||
			((OSMemberFunctionCast(void (*)(void),
				root, &IOService::powerStateDidChangeTo)) !=
			((OSMemberFunctionCast(void (*)(void),
				this, &IOService::powerStateDidChangeTo)))) ||
			((OSMemberFunctionCast(void (*)(void),
				root, &IOService::powerStateWillChangeTo)) !=
			((OSMemberFunctionCast(void (*)(void),
				this, &IOService::powerStateWillChangeTo)))))
		{		
			if (fInterestedDrivers->findItem(powerDriver) == NULL)
			{
				PM_LOCK();
				fInterestedDrivers->appendNewInformee(powerDriver);
				PM_UNLOCK();
			}
		}

		// Examine all existing power clients and perform limit check.

        if (fPowerClients)
        {
            iter = OSCollectionIterator::withCollection(fPowerClients);
            if (iter)
            {
                const OSSymbol * client;
                while ((client = (const OSSymbol *) iter->getNextObject()))
                {
                    uint32_t powerState = getPowerStateForClient(client);
                    if (powerState >= numberOfStates)
                    {
                        updatePowerClient(client, numberOfStates - 1);
                    }
                }
                iter->release();
            }
        }

		if ( inPlane(gIOPowerPlane) && fParentsKnowState )
		{
			unsigned long tempDesire;
			fMaxCapability = fControllingDriver->maxCapabilityForDomainState(fParentsCurrentPowerFlags);
			// initially change into the state we are already in
			tempDesire = fControllingDriver->initialPowerStateForDomainState(fParentsCurrentPowerFlags);
			adjustPowerState(tempDesire);
		}
	}
	else
	{
		OUR_PMLog(kPMLogControllingDriverErr2, numberOfStates, 0);
        IODelete(powerStates, IOPMPowerState, numberOfStates);
	}

	powerDriver->release();
}

//*********************************************************************************
// [public] registerInterestedDriver
//
// Add the caller to our list of interested drivers and return our current
// power state.  If we don't have a power-controlling driver yet, we will
// call this interested driver again later when we do get a driver and find
// out what the current power state of the device is.
//*********************************************************************************

IOPMPowerFlags IOService::registerInterestedDriver ( IOService * driver )
{
	IOPMRequest *	request;
	bool			signal;

	if (!initialized || !fInterestedDrivers)
		return IOPMNotPowerManaged;

	PM_LOCK();
	signal = (!fInsertInterestSet && !fRemoveInterestSet);
	if (fInsertInterestSet == NULL)
		fInsertInterestSet = OSSet::withCapacity(4);
	if (fInsertInterestSet)
		fInsertInterestSet->setObject(driver);
	PM_UNLOCK();

	if (signal)
	{
		request = acquirePMRequest( this, kIOPMRequestTypeInterestChanged );
		if (request)
			submitPMRequest( request );
	}

	// This return value cannot be trusted, but return a value
	// for those clients that care.

    OUR_PMLog(kPMLogInterestedDriver, kIOPMDeviceUsable, 2);
    return kIOPMDeviceUsable;	
}

//*********************************************************************************
// [public] deRegisterInterestedDriver
//*********************************************************************************

IOReturn IOService::deRegisterInterestedDriver ( IOService * driver )
{
	IOPMinformeeList *	list;
    IOPMinformee *		item;
	IOPMRequest *		request;
	bool				signal;

	if (!initialized || !fInterestedDrivers)
		return IOPMNotPowerManaged;

	PM_LOCK();
	signal = (!fRemoveInterestSet && !fInsertInterestSet);
	if (fRemoveInterestSet == NULL)
		fRemoveInterestSet = OSSet::withCapacity(4);
	if (fRemoveInterestSet)
	{
		fRemoveInterestSet->setObject(driver);

		list = fInterestedDrivers;
		item = list->findItem(driver);
		if (item && item->active)
		{
			item->active = false;
		}
		if (fLockedFlags.DriverCallBusy)
            PM_DEBUG("%s::deRegisterInterestedDriver() driver call busy\n", getName());
	}
	PM_UNLOCK();

	if (signal)
	{
		request = acquirePMRequest( this, kIOPMRequestTypeInterestChanged );
		if (request)
			submitPMRequest( request );
	}

	return IOPMNoErr;
}

//*********************************************************************************
// [private] handleInterestChanged
//
// Handle interest added or removed.
//*********************************************************************************

void IOService::handleInterestChanged( IOPMRequest * request )
{
	IOService *			driver;
    IOPMinformee *		informee;
	IOPMinformeeList *	list = fInterestedDrivers;

	PM_LOCK();

	if (fInsertInterestSet)
	{
		while ((driver = (IOService *) fInsertInterestSet->getAnyObject()))
		{
			if ((list->findItem(driver) == NULL) &&
				(!fRemoveInterestSet ||
				 !fRemoveInterestSet->containsObject(driver)))
			{
				informee = list->appendNewInformee(driver);
			}
			fInsertInterestSet->removeObject(driver);
		}
		fInsertInterestSet->release();
		fInsertInterestSet = 0;
	}

	if (fRemoveInterestSet)
	{
		while ((driver = (IOService *) fRemoveInterestSet->getAnyObject()))
		{
			informee = list->findItem(driver);
			if (informee)
			{
				if (fHeadNotePendingAcks && informee->timer)
				{
					informee->timer = 0;
					fHeadNotePendingAcks--;
				}
				list->removeFromList(driver);
			}
			fRemoveInterestSet->removeObject(driver);
		}
		fRemoveInterestSet->release();
		fRemoveInterestSet = 0;
	}

	PM_UNLOCK();
}

//*********************************************************************************
// [public] acknowledgePowerChange
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
	IOPMRequest * request;

    if (!initialized)
		return IOPMNotYetInitialized;
	if (!whichObject)
		return kIOReturnBadArgument;

	request = acquirePMRequest( this, kIOPMRequestTypeAckPowerChange );
	if (!request)
		return kIOReturnNoMemory;

	whichObject->retain();
	request->fArg0 = whichObject;

	submitPMRequest( request );
    return IOPMNoErr;
}

//*********************************************************************************
// [private] handleAcknowledgePowerChange
//*********************************************************************************

bool IOService::handleAcknowledgePowerChange ( IOPMRequest * request )
{
    IOPMinformee *		informee;
    unsigned long		childPower = kIOPMUnknown;
    IOService *			theChild;
	IOService *			whichObject;
	bool				all_acked  = false;

	PM_ASSERT_IN_GATE();
	whichObject = (IOService *) request->fArg0;
	assert(whichObject);

    // one of our interested drivers?
	informee = fInterestedDrivers->findItem( whichObject );
    if ( informee == NULL )
    {
        if ( !isChild(whichObject, gIOPowerPlane) )
        {
			OUR_PMLog(kPMLogAcknowledgeErr1, 0, 0);
			goto no_err;
        } else {
            OUR_PMLog(kPMLogChildAcknowledge, fHeadNotePendingAcks, 0);
        }
    } else {
        OUR_PMLog(kPMLogDriverAcknowledge, fHeadNotePendingAcks, 0);
    }

    if ( fHeadNotePendingAcks != 0 )
    {
        assert(fPowerStates != NULL);

         // yes, make sure we're expecting acks
        if ( informee != NULL )
        {
            // it's an interested driver
            // make sure we're expecting this ack
            if ( informee->timer != 0 )
            {
#if LOG_SETPOWER_TIMES
                if (informee->timer > 0)
                {
                    uint64_t nsec = computeTimeDeltaNS(&informee->startTime);
                    if (nsec > LOG_SETPOWER_TIMES)
                        PM_DEBUG("%s::powerState%sChangeTo(%p, %s, %lu -> %lu) async took %d ms\n",
                            informee->whatObject->getName(),
                            (fDriverCallReason == kDriverCallInformPreChange) ? "Will" : "Did",
                            informee->whatObject,
                            fName, fCurrentPowerState, fHeadNotePowerState, NS_TO_MS(nsec));
                }
#endif
                // mark it acked
                informee->timer = 0;
                // that's one fewer to worry about
                fHeadNotePendingAcks--;
            } else {
                // this driver has already acked
                OUR_PMLog(kPMLogAcknowledgeErr2, 0, 0);
            }
        } else {
            // it's a child
            // make sure we're expecting this ack
            if ( ((IOPowerConnection *)whichObject)->getAwaitingAck() )
            {
                // that's one fewer to worry about
                fHeadNotePendingAcks--;
                ((IOPowerConnection *)whichObject)->setAwaitingAck(false);
                theChild = (IOService *)whichObject->copyChildEntry(gIOPowerPlane);
                if ( theChild )
                {
                    childPower = theChild->currentPowerConsumption();
                    theChild->release();
                }
                if ( childPower == kIOPMUnknown )
                {
                    fHeadNotePowerArrayEntry->staticPower = kIOPMUnknown;
                } else {
                    if (fHeadNotePowerArrayEntry->staticPower != kIOPMUnknown)
                    {
                        fHeadNotePowerArrayEntry->staticPower += childPower;
                    }
                }
            }
	    }

		if ( fHeadNotePendingAcks == 0 ) {
			// yes, stop the timer
			stop_ack_timer();
			// and now we can continue
			all_acked = true;
		}
    } else {
        OUR_PMLog(kPMLogAcknowledgeErr3, 0, 0);	// not expecting anybody to ack
    }

no_err:
	if (whichObject)
		whichObject->release();

    return all_acked;
}

//*********************************************************************************
// [public] acknowledgeSetPowerState
//
// After we instructed our controlling driver to change power states,
// it has called to say it has finished doing so.
// We continue to process the power state change.
//*********************************************************************************

IOReturn IOService::acknowledgeSetPowerState ( void )
{
	IOPMRequest * request;

    if (!initialized)
		return IOPMNotYetInitialized;

	request = acquirePMRequest( this, kIOPMRequestTypeAckSetPowerState );
	if (!request)
		return kIOReturnNoMemory;

	submitPMRequest( request );
	return kIOReturnSuccess;
}

//*********************************************************************************
// [private] adjustPowerState
//*********************************************************************************

void IOService::adjustPowerState ( uint32_t clamp )
{
	PM_ASSERT_IN_GATE();
	computeDesiredState(clamp);
	if (fControllingDriver && fParentsKnowState && inPlane(gIOPowerPlane))
	{
		startPowerChange(
			 /* flags        */	kIOPMWeInitiated,
			 /* power state  */	fDesiredPowerState,
			 /* domain flags */	0,
			 /* connection   */	0,
			 /* parent flags */	0);
	}
}

//*********************************************************************************
// [public] synchronizePowerTree
//*********************************************************************************

IOReturn IOService::synchronizePowerTree ( void )
{
	IOPMRequest *   request_c;
    IOPMRequest *   request_s;

    if (this != getPMRootDomain())
        return kIOReturnBadArgument;
	if (!initialized)
		return kIOPMNotYetInitialized;

    request_c = acquirePMRequest( this, kIOPMRequestTypeIdleCancel );
    request_s = acquirePMRequest( this, kIOPMRequestTypeSynchronizePowerTree );

    if (!request_c || !request_s)
        goto error_no_memory;

    request_c->attachNextRequest( request_s );

    submitPMRequest(request_c);
    submitPMRequest(request_s);

    return kIOReturnSuccess;

error_no_memory:
	if (request_c) releasePMRequest(request_c);
	if (request_s) releasePMRequest(request_s);
    return kIOReturnNoMemory;
}

//*********************************************************************************
// [private] handleSynchronizePowerTree
//*********************************************************************************

void IOService::handleSynchronizePowerTree ( IOPMRequest * /*request*/ )
{
	PM_ASSERT_IN_GATE();
	if (fControllingDriver && fParentsKnowState && inPlane(gIOPowerPlane) &&
        (fCurrentPowerState == fNumberOfPowerStates - 1))
	{
		startPowerChange(
			 /* flags        */	kIOPMWeInitiated | kIOPMSynchronize,
			 /* power state  */	fCurrentPowerState,
			 /* domain flags */	0,
			 /* connection   */	0,
			 /* parent flags */	0);
	}
}

#ifndef __LP64__
//*********************************************************************************
// [deprecated] powerDomainWillChangeTo
//
// Called by the power-hierarchy parent notifying of a new power state
// in the power domain.
// We enqueue a parent power-change to our queue of power changes.
// This may or may not cause us to change power, depending on what
// kind of change is occuring in the domain.
//*********************************************************************************

IOReturn IOService::powerDomainWillChangeTo (
	IOPMPowerFlags		newPowerFlags,
	IOPowerConnection *	whichParent )
{
	assert(false);
	return kIOReturnUnsupported;
}
#endif /* !__LP64__ */

//*********************************************************************************
// [private] handlePowerDomainWillChangeTo
//*********************************************************************************

void IOService::handlePowerDomainWillChangeTo ( IOPMRequest * request )
{
	IOPMPowerFlags		parentPowerFlags = (IOPMPowerFlags) request->fArg0;
	IOPowerConnection *	whichParent = (IOPowerConnection *) request->fArg1;
    unsigned long       parentChangeFlags = (unsigned long) request->fArg2;
    OSIterator *		iter;
    OSObject *			next;
    IOPowerConnection *	connection;
    unsigned long		newPowerState;
    unsigned long       myChangeFlags;
    IOPMPowerFlags		combinedPowerFlags;
	bool				savedParentsKnowState;
	IOReturn			result = IOPMAckImplied;

	PM_ASSERT_IN_GATE();
    OUR_PMLog(kPMLogWillChange, parentPowerFlags, 0);

	if (!inPlane(gIOPowerPlane) || !whichParent || !whichParent->getAwaitingAck())
	{
		PM_DEBUG("%s::%s not in power tree\n", getName(), __FUNCTION__);
        goto exit_no_ack;
	}

	savedParentsKnowState = fParentsKnowState;

    // Combine parents' output power flags.

	combinedPowerFlags = 0;

    iter = getParentIterator(gIOPowerPlane);
    if ( iter )
    {
        while ( (next = iter->getNextObject()) )
        {
            if ( (connection = OSDynamicCast(IOPowerConnection, next)) )
            {
                if ( connection == whichParent )
                    combinedPowerFlags |= parentPowerFlags;
                else
                    combinedPowerFlags |= connection->parentCurrentPowerFlags();
            }
        }
        iter->release();
    }

    // If our initial change has yet to occur, then defer the power change
    // until after the power domain has completed its power transition.

    if ( fControllingDriver && !fInitialChange )
    {
		newPowerState = fControllingDriver->maxCapabilityForDomainState(
							combinedPowerFlags);

        // Absorb parent's kIOPMSynchronize flag.
        myChangeFlags = kIOPMParentInitiated | kIOPMDomainWillChange |
                        (parentChangeFlags & kIOPMSynchronize);

		result = startPowerChange(
                 /* flags        */	myChangeFlags,
                 /* power state  */	newPowerState,
				 /* domain flags */	combinedPowerFlags,
				 /* connection   */	whichParent,
				 /* parent flags */	parentPowerFlags);
	}

	// If parent is dropping power, immediately update the parent's
	// capability flags. Any future merging of parent(s) combined
	// power flags should account for this power drop.

	if (parentChangeFlags & kIOPMDomainPowerDrop)
	{
		setParentInfo(parentPowerFlags, whichParent, true);
	}

	// Parent is expecting an ACK from us. If we did not embark on a state
	// transition, i.e. startPowerChange() returned IOPMAckImplied. We are
	// still required to issue an ACK to our parent.

	if (IOPMAckImplied == result)
	{
		IOService * parent;
		parent = (IOService *) whichParent->copyParentEntry(gIOPowerPlane);
		assert(parent);
		if ( parent )
		{
			parent->acknowledgePowerChange( whichParent );
			parent->release();
		}
	}

exit_no_ack:
    // Drop the retain from notifyChild().
    if (whichParent) whichParent->release();
}

#ifndef __LP64__
//*********************************************************************************
// [deprecated] powerDomainDidChangeTo
//
// Called by the power-hierarchy parent after the power state of the power domain
// has settled at a new level.
// We enqueue a parent power-change to our queue of power changes.
// This may or may not cause us to change power, depending on what
// kind of change is occuring in the domain.
//*********************************************************************************

IOReturn IOService::powerDomainDidChangeTo (
	IOPMPowerFlags		newPowerFlags,
	IOPowerConnection *	whichParent )
{
	assert(false);
	return kIOReturnUnsupported;
}
#endif /* !__LP64__ */

//*********************************************************************************
// [private] handlePowerDomainDidChangeTo
//*********************************************************************************

void IOService::handlePowerDomainDidChangeTo ( IOPMRequest * request )
{
	IOPMPowerFlags		parentPowerFlags = (IOPMPowerFlags) request->fArg0;
	IOPowerConnection *	whichParent = (IOPowerConnection *) request->fArg1;
    unsigned long       parentChangeFlags = (unsigned long) request->fArg2;
    unsigned long		newPowerState;
    unsigned long       myChangeFlags;
    unsigned long       initialDesire;
	bool				savedParentsKnowState;
	IOReturn			result = IOPMAckImplied;

	PM_ASSERT_IN_GATE();
    OUR_PMLog(kPMLogDidChange, parentPowerFlags, 0);

	if (!inPlane(gIOPowerPlane) || !whichParent || !whichParent->getAwaitingAck())
	{
		PM_DEBUG("%s::%s not in power tree\n", getName(), __FUNCTION__);
        goto exit_no_ack;
	}

	savedParentsKnowState = fParentsKnowState;

    setParentInfo(parentPowerFlags, whichParent, true);

    if ( fControllingDriver )
	{
		newPowerState = fControllingDriver->maxCapabilityForDomainState(
							fParentsCurrentPowerFlags);

        if (fInitialChange)
        {
            initialDesire = fControllingDriver->initialPowerStateForDomainState(
                            fParentsCurrentPowerFlags);
            computeDesiredState(initialDesire);
        }

        // Absorb parent's kIOPMSynchronize flag.
        myChangeFlags = kIOPMParentInitiated | kIOPMDomainDidChange |
                        (parentChangeFlags & kIOPMSynchronize);

		result = startPowerChange(
				 /* flags        */	myChangeFlags,
                 /* power state  */	newPowerState,
				 /* domain flags */	fParentsCurrentPowerFlags,
				 /* connection   */	whichParent,
				 /* parent flags */	0);
	}

	// Parent is expecting an ACK from us. If we did not embark on a state
	// transition, i.e. startPowerChange() returned IOPMAckImplied. We are
	// still required to issue an ACK to our parent.

	if (IOPMAckImplied == result)
	{
		IOService * parent;
		parent = (IOService *) whichParent->copyParentEntry(gIOPowerPlane);
		assert(parent);
		if ( parent )
		{
			parent->acknowledgePowerChange( whichParent );
			parent->release();
		}
	}

	// If the parent registers its power driver late, then this is the
	// first opportunity to tell our parent about our desire. 

	if (!savedParentsKnowState && fParentsKnowState)
	{
		PM_TRACE("%s::powerDomainDidChangeTo parentsKnowState = true\n",
			getName());
		ask_parent( fDesiredPowerState );
	}

exit_no_ack:
    // Drop the retain from notifyChild().
    if (whichParent) whichParent->release();
}

//*********************************************************************************
// [private] setParentInfo
//
// Set our connection data for one specific parent, and then combine all the parent
// data together.
//*********************************************************************************
 
void IOService::setParentInfo (
	IOPMPowerFlags		newPowerFlags,
	IOPowerConnection * whichParent,
	bool				knowsState )
{
    OSIterator *		iter;
    OSObject *			next;
    IOPowerConnection *	conn;

	PM_ASSERT_IN_GATE();

    // set our connection data
    whichParent->setParentCurrentPowerFlags(newPowerFlags);
    whichParent->setParentKnowsState(knowsState);
    
    // recompute our parent info
    fParentsCurrentPowerFlags = 0;
    fParentsKnowState = true;

    iter = getParentIterator(gIOPowerPlane);
    if ( iter )
    {
        while ( (next = iter->getNextObject()) )
        {
            if ( (conn = OSDynamicCast(IOPowerConnection, next)) )
            {
                fParentsKnowState &= conn->parentKnowsState();
                fParentsCurrentPowerFlags |= conn->parentCurrentPowerFlags();
            }
        }
        iter->release();
    }
}

//*********************************************************************************
// [private] rebuildChildClampBits
//
// The ChildClamp bits (kIOPMChildClamp & kIOPMChildClamp2) in our capabilityFlags
// indicate that one of our children (or grandchildren or great-grandchildren ...)
// doesn't support idle or system sleep in its current state. Since we don't track
// the origin of each bit, every time any child changes state we have to clear
// these bits and rebuild them.
//*********************************************************************************

void IOService::rebuildChildClampBits ( void )
{
    unsigned long		i;
    OSIterator *		iter;
    OSObject *			next;
    IOPowerConnection *	connection;
	unsigned long		powerState;

    // A child's desires has changed. We need to rebuild the child-clamp bits in
	// our power state array. Start by clearing the bits in each power state.
    
    for ( i = 0; i < fNumberOfPowerStates; i++ )
    {
        fPowerStates[i].capabilityFlags &= ~(kIOPMChildClamp | kIOPMChildClamp2);
    }

	if (!inPlane(gIOPowerPlane))
		return;

    // Loop through the children. When we encounter the calling child, save the
	// computed state as this child's desire. And set the ChildClamp bits in any
    // of our states that some child has clamp on.

    iter = getChildIterator(gIOPowerPlane);
    if ( iter )
    {
        while ( (next = iter->getNextObject()) )
        {
            if ( (connection = OSDynamicCast(IOPowerConnection, next)) )
            {
				if (connection->getReadyFlag() == false)
				{
					PM_CONNECT("[%s] %s: connection not ready\n",
						getName(), __FUNCTION__);
					continue;
				}

				powerState = connection->getDesiredDomainState();
                if (powerState < fNumberOfPowerStates)
                {
                    if ( connection->getPreventIdleSleepFlag() )
                        fPowerStates[powerState].capabilityFlags |= kIOPMChildClamp;
                    if ( connection->getPreventSystemSleepFlag() )
                        fPowerStates[powerState].capabilityFlags |= kIOPMChildClamp2;
                }
            }
        }
        iter->release();
    }
}

//*********************************************************************************
// [public] requestPowerDomainState
//
// The child of a power domain calls it parent here to request power of a certain
// character.
//*********************************************************************************

IOReturn IOService::requestPowerDomainState (
	IOPMPowerFlags		desiredState,
	IOPowerConnection *	whichChild,
	unsigned long		specification )
{
    unsigned long		i;
    unsigned long		computedState;
    unsigned long		theDesiredState;
	IOService *			child;
	IOPMRequest *		childRequest;

    if (!initialized)
		return IOPMNotYetInitialized;

	if (gIOPMWorkLoop->onThread() == false)
	{
		PM_DEBUG("%s::requestPowerDomainState\n", getName());
		return kIOReturnSuccess;
	}

	theDesiredState = desiredState & ~(kIOPMPreventIdleSleep | kIOPMPreventSystemSleep);

    OUR_PMLog(kPMLogRequestDomain, desiredState, specification);

	if (!isChild(whichChild, gIOPowerPlane))
		return kIOReturnNotAttached;

    if (fControllingDriver == NULL || !fPowerStates)
        return IOPMNotYetInitialized;

	child = (IOService *) whichChild->getChildEntry(gIOPowerPlane);
	assert(child);

    switch (specification) {
        case IOPMLowestState:
            i = 0;
            while ( i < fNumberOfPowerStates )
            {
                if ( ( fPowerStates[i].outputPowerCharacter & theDesiredState) ==
					 (theDesiredState & fOutputPowerCharacterFlags) )
                {
                    break;
                }
                i++;
            }
            if ( i >= fNumberOfPowerStates )
            {
                return IOPMNoSuchState;
            }
            break;

        case IOPMNextLowerState:
            i = fCurrentPowerState - 1;
            while ( (int) i >= 0 )
            {
                if ( ( fPowerStates[i].outputPowerCharacter & theDesiredState) ==
					 (theDesiredState & fOutputPowerCharacterFlags) )
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
            i = fNumberOfPowerStates;
            while ( (int) i >= 0 )
            {
                i--;
                if ( ( fPowerStates[i].outputPowerCharacter & theDesiredState) ==
					 (theDesiredState & fOutputPowerCharacterFlags) )
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
            i = fCurrentPowerState + 1;
            while ( i < fNumberOfPowerStates )
            {
                if ( ( fPowerStates[i].outputPowerCharacter & theDesiredState) ==
					 (theDesiredState & fOutputPowerCharacterFlags) )
                {
                    break;
                }
                i++;
            }
            if ( i == fNumberOfPowerStates )
            {
                return IOPMNoSuchState;
            }
            break;

        default:
            return IOPMBadSpecification;
    }

    computedState = i;

	// Record the child's desires on the connection.
#if SUPPORT_IDLE_CANCEL
	bool attemptCancel = ((kIOPMPreventIdleSleep & desiredState) && !whichChild->getPreventIdleSleepFlag());
#endif
	whichChild->setDesiredDomainState( computedState );
	whichChild->setPreventIdleSleepFlag( desiredState & kIOPMPreventIdleSleep );
	whichChild->setPreventSystemSleepFlag( desiredState & kIOPMPreventSystemSleep );
	whichChild->setChildHasRequestedPower();

	if (whichChild->getReadyFlag() == false)
		return IOPMNoErr;

	// Schedule a request to re-evaluate all children desires and
	// adjust power state. Submit a request if one wasn't pending,
	// or if the current request is part of a call tree.

    if (!fDeviceOverrides && (!fAdjustPowerScheduled || gIOPMRequest->getRootRequest()))
    {
		childRequest = acquirePMRequest( this, kIOPMRequestTypeAdjustPowerState, gIOPMRequest );
		if (childRequest)
		{
			submitPMRequest( childRequest );
			fAdjustPowerScheduled = true;
		}
	}
#if SUPPORT_IDLE_CANCEL
	if (attemptCancel)
	{
		childRequest = acquirePMRequest( this, kIOPMRequestTypeIdleCancel );
		if (childRequest)
		{
			submitPMRequest( childRequest );
		}
	}
#endif

	return IOPMNoErr;
}

//*********************************************************************************
// [public] temporaryPowerClampOn
//
// A power domain wants to clamp its power on till it has children which
// will thendetermine the power domain state.
//
// We enter the highest state until addPowerChild is called.
//*********************************************************************************

IOReturn IOService::temporaryPowerClampOn ( void )
{
    return requestPowerState( gIOPMPowerClientChildProxy, kIOPMPowerStateMax );
}

//*********************************************************************************
// [public] makeUsable
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
    OUR_PMLog(kPMLogMakeUsable, 0, 0);
    return requestPowerState( gIOPMPowerClientDevice, kIOPMPowerStateMax );
}

//*********************************************************************************
// [public] currentCapability
//*********************************************************************************

IOPMPowerFlags IOService::currentCapability ( void )
{
	if (!initialized)
		return IOPMNotPowerManaged;

    return fCurrentCapabilityFlags;
}

//*********************************************************************************
// [public] changePowerStateTo
//
// Called by our power-controlling driver to change power state. The new desired
// power state is computed and compared against the current power state. If those
// power states differ, then a power state change is initiated.
//*********************************************************************************

IOReturn IOService::changePowerStateTo ( unsigned long ordinal )
{
    OUR_PMLog(kPMLogChangeStateTo, ordinal, 0);
    return requestPowerState( gIOPMPowerClientDriver, ordinal );
}

//*********************************************************************************
// [protected] changePowerStateToPriv
//
// Called by our driver subclass to change power state. The new desired power
// state is computed and compared against the current power state. If those
// power states differ, then a power state change is initiated.
//*********************************************************************************

IOReturn IOService::changePowerStateToPriv ( unsigned long ordinal )
{
    OUR_PMLog(kPMLogChangeStateToPriv, ordinal, 0);
    return requestPowerState( gIOPMPowerClientDevice, ordinal );
}

//*********************************************************************************
// [protected] changePowerStateWithOverrideTo
//
// Called by our driver subclass to change power state. The new desired power
// state is computed and compared against the current power state. If those
// power states differ, then a power state change is initiated.
// Override enforced - Children and Driver desires are ignored.
//*********************************************************************************

IOReturn IOService::changePowerStateWithOverrideTo ( unsigned long ordinal )
{
	IOPMRequest * request;

	if (!initialized)
		return kIOPMNotYetInitialized;

    OUR_PMLog(kPMLogChangeStateToPriv, ordinal, 0);

	request = acquirePMRequest( this, kIOPMRequestTypeRequestPowerStateOverride );
	if (!request)
		return kIOReturnNoMemory;

    gIOPMPowerClientDevice->retain();
    request->fArg0 = (void *) ordinal;
    request->fArg1 = (void *) gIOPMPowerClientDevice;
    request->fArg2 = 0;
#if NOT_READY
    if (action)
        request->installCompletionAction( action, target, param );
#endif

	// Prevent needless downwards power transitions by clamping power
	// until the scheduled request is executed.

	if (gIOPMWorkLoop->inGate() && (ordinal < fNumberOfPowerStates))
	{
		fTempClampPowerState = max(fTempClampPowerState, ordinal);
		fTempClampCount++;
        fOverrideMaxPowerState = ordinal;
		request->fArg2 = (void *) true;
	}

	submitPMRequest( request );
    return IOPMNoErr;
}

//*********************************************************************************
// [private] requestPowerState
//*********************************************************************************

IOReturn IOService::requestPowerState (
    const OSSymbol *      client,
    uint32_t              state )
{
	IOPMRequest * request;

    if (!client)
        return kIOReturnBadArgument;
	if (!initialized)
		return kIOPMNotYetInitialized;

	request = acquirePMRequest( this, kIOPMRequestTypeRequestPowerState );
	if (!request)
		return kIOReturnNoMemory;

    client->retain();
    request->fArg0 = (void *) state;
    request->fArg1 = (void *) client;
    request->fArg2 = 0;
#if NOT_READY
    if (action)
        request->installCompletionAction( action, target, param );
#endif

	// Prevent needless downwards power transitions by clamping power
	// until the scheduled request is executed.

	if (gIOPMWorkLoop->inGate() && (state < fNumberOfPowerStates))
	{
		fTempClampPowerState = max(fTempClampPowerState, state);
		fTempClampCount++;
		request->fArg2 = (void *) true;
	}

	submitPMRequest( request );
    return IOPMNoErr;
}

//*********************************************************************************
// [private] handleRequestPowerState
//*********************************************************************************

void IOService::handleRequestPowerState ( IOPMRequest * request )
{
    const OSSymbol * client = (const OSSymbol *)    request->fArg1;
    uint32_t         state  = (uint32_t)(uintptr_t) request->fArg0;

	PM_ASSERT_IN_GATE();
	if (request->fArg2)
	{
		assert(fTempClampCount != 0);
		if (fTempClampCount)  fTempClampCount--;
		if (!fTempClampCount) fTempClampPowerState = 0;
	}

	if (fNumberOfPowerStates && (state >= fNumberOfPowerStates))
		state = fNumberOfPowerStates - 1;

    // Override from changePowerStateWithOverrideTo() persists until
    // the next "device" power request, such as changePowerStateToPriv().

    if ((getPMRequestType() != kIOPMRequestTypeRequestPowerStateOverride) &&
        (client == gIOPMPowerClientDevice))
        fOverrideMaxPowerState = kIOPMPowerStateMax;

    if ((state == 0) &&
		(client != gIOPMPowerClientDevice) &&
		(client != gIOPMPowerClientDriver) &&
		(client != gIOPMPowerClientChildProxy))
		removePowerClient(client);
	else
		updatePowerClient(client, state);

	adjustPowerState();
    client->release();
}

//*********************************************************************************
// [private] Helper functions to update/remove power clients.
//*********************************************************************************

void IOService::updatePowerClient( const OSSymbol * client, uint32_t powerState )
{
    if (!fPowerClients)
        fPowerClients = OSDictionary::withCapacity(4);
    if (fPowerClients && client)
    {
        OSNumber * num = (OSNumber *) fPowerClients->getObject(client);
        if (num)
            num->setValue(powerState);
        else
        {
            num = OSNumber::withNumber(powerState, 32);
            if (num)
            {
                fPowerClients->setObject(client, num);
                num->release();
            }
        }
    }
}

void IOService::removePowerClient( const OSSymbol * client )
{
    if (fPowerClients && client)
        fPowerClients->removeObject(client);
}

uint32_t IOService::getPowerStateForClient( const OSSymbol * client )
{
    uint32_t powerState = 0;

    if (fPowerClients && client)
    {
        OSNumber * num = (OSNumber *) fPowerClients->getObject(client);
        if (num) powerState = num->unsigned32BitValue();
    }
    return powerState;
}

//*********************************************************************************
// [private] computeDesiredState
//*********************************************************************************

void IOService::computeDesiredState ( unsigned long localClamp )
{
    OSIterator *		iter;
    OSObject *			next;
    IOPowerConnection *	connection;
	uint32_t            desiredState  = 0;
    uint32_t            newPowerState = 0;
    bool                hasChildren   = false;

	// Desired power state is always 0 without a controlling driver.

	if (!fNumberOfPowerStates)
	{
        fDesiredPowerState = 0;
		//PM_DEBUG("%s::%s no controlling driver\n", getName(), __FUNCTION__);
		return;
	}

    // Examine the children's desired power state.

    iter = getChildIterator(gIOPowerPlane);
    if (iter)
    {
        while ((next = iter->getNextObject()))
        {
            if ((connection = OSDynamicCast(IOPowerConnection, next)))
            {
                if (connection->getReadyFlag() == false)
                {
                    PM_CONNECT("[%s] %s: connection not ready\n",
                        getName(), __FUNCTION__);
                    continue;
                }
                if (connection->childHasRequestedPower())
                    hasChildren = true;
                if (connection->getDesiredDomainState() > desiredState)
                    desiredState = connection->getDesiredDomainState();
            }
        }
        iter->release();
    }
    if (hasChildren)
        updatePowerClient(gIOPMPowerClientChildren, desiredState);
    else
        removePowerClient(gIOPMPowerClientChildren);

    // Iterate through all power clients to determine the min power state.

    iter = OSCollectionIterator::withCollection(fPowerClients);
    if (iter)
    {
        const OSSymbol * client;
        while ((client = (const OSSymbol *) iter->getNextObject()))
        {
			// Ignore child and driver when override is in effect.
            if ((fDeviceOverrides ||
                (getPMRequestType() == kIOPMRequestTypeRequestPowerStateOverride)) &&
                ((client == gIOPMPowerClientChildren) ||
                 (client == gIOPMPowerClientDriver)))
                continue;

			// Ignore child proxy when children are present.
            if (hasChildren && (client == gIOPMPowerClientChildProxy))
                continue;

            desiredState = getPowerStateForClient(client);
            assert(desiredState < fNumberOfPowerStates);			
			PM_TRACE("  %u %s\n",
				desiredState, client->getCStringNoCopy());

            newPowerState = max(newPowerState, desiredState);

            if (client == gIOPMPowerClientDevice)
                fDeviceDesire = desiredState;
        }
        iter->release();
    }

    // Factor in the temporary power desires.

    newPowerState = max(newPowerState, localClamp);
    newPowerState = max(newPowerState, fTempClampPowerState);

    // Limit check against max power override.

    newPowerState = min(newPowerState, fOverrideMaxPowerState);

    // Limit check against number of power states.

    if (newPowerState >= fNumberOfPowerStates)
        newPowerState = fNumberOfPowerStates - 1;

    fDesiredPowerState = newPowerState;

    PM_TRACE("  temp %u, clamp %u, current %u, new %u\n",
        (uint32_t) localClamp, (uint32_t) fTempClampPowerState,
		(uint32_t) fCurrentPowerState, newPowerState);

	// Restart idle timer if stopped and device desire has increased.

	if (fDeviceDesire && fIdleTimerStopped)
	{
		fIdleTimerStopped = false;
        fActivityTickleCount = 0;
		clock_get_uptime(&fIdleTimerStartTime);
		start_PM_idle_timer();
	}

	// Invalidate cached tickle power state when desires change, and not
	// due to a tickle request.  This invalidation must occur before the
	// power state change to minimize races.  We want to err on the side
	// of servicing more activity tickles rather than dropping one when
	// the device is in a low power state.

	if ((getPMRequestType() != kIOPMRequestTypeActivityTickle) &&
		(fActivityTicklePowerState != -1))
	{
		IOLockLock(fActivityLock);
		fActivityTicklePowerState = -1;
		IOLockUnlock(fActivityLock);
	}
}

//*********************************************************************************
// [public] currentPowerConsumption
//
//*********************************************************************************

unsigned long IOService::currentPowerConsumption ( void )
{
    if (!initialized)
        return kIOPMUnknown;

    return fCurrentPowerConsumption;
}

//*********************************************************************************
// [deprecated] getPMworkloop
//*********************************************************************************

IOWorkLoop * IOService::getPMworkloop ( void )
{
	return gIOPMWorkLoop;
}

//*********************************************************************************
// [public] activityTickle
//
// The tickle with parameter kIOPMSuperclassPolicy1 causes the activity
// flag to be set, and the device state checked.  If the device has been
// powered down, it is powered up again.
// The tickle with parameter kIOPMSubclassPolicy is ignored here and
// should be intercepted by a subclass.
//*********************************************************************************

bool IOService::activityTickle ( unsigned long type, unsigned long stateNumber )
{
	IOPMRequest *	request;
	bool			noPowerChange = true;

    if ( initialized && stateNumber && (type == kIOPMSuperclassPolicy1) )
	{
        IOLockLock(fActivityLock);

		// Record device activity for the idle timer handler.

        fDeviceActive = true;
        fActivityTickleCount++;
        clock_get_uptime(&fDeviceActiveTimestamp);

#if ROOT_DOMAIN_RUN_STATES
        if (fCurrentPowerState == 0)
            getPMRootDomain()->handleActivityTickleForService(this);
#endif

		// Record the last tickle power state.
		// This helps to filter out redundant tickles as
		// this function may be called from the data path.

		if (fActivityTicklePowerState < (long)stateNumber)
		{
			fActivityTicklePowerState = stateNumber;
			noPowerChange = false;

			request = acquirePMRequest( this, kIOPMRequestTypeActivityTickle );
			if (request)
			{
				request->fArg0 = (void *) stateNumber;	// power state
				request->fArg1 = (void *) true;			// power rise
				submitPMRequest(request);
			}
		}

		IOLockUnlock(fActivityLock);
	}

	// Returns false if the activityTickle might cause a transition to a
	// higher powered state, true otherwise.

    return noPowerChange;
}

//*********************************************************************************
// [private] handleActivityTickle
//*********************************************************************************

void IOService::handleActivityTickle ( IOPMRequest * request )
{
	uint32_t ticklePowerState = (uint32_t)(uintptr_t) request->fArg0;
	bool	 adjustPower = false;

	PM_ASSERT_IN_GATE();
	if (request->fArg1)
	{
		// Power rise from activity tickle.
		if ((ticklePowerState > fDeviceDesire) &&
			(ticklePowerState < fNumberOfPowerStates))
		{
			fIdleTimerMinPowerState = ticklePowerState;
			adjustPower = true;
		}
	}
	else if (fDeviceDesire > fIdleTimerMinPowerState)
	{
		// Power drop due to idle timer expiration.
		// Do not allow idle timer to reduce power below tickle power.		
		ticklePowerState = fDeviceDesire - 1;
		adjustPower = true;
	}

	if (adjustPower)
	{
		updatePowerClient(gIOPMPowerClientDevice, ticklePowerState);
		adjustPowerState();
	}
}

//*********************************************************************************
// [public] setIdleTimerPeriod
//
// A subclass policy-maker is going to use our standard idleness
// detection service.  Make a command queue and an idle timer and
// connect them to the power management workloop.  Finally,
// start the timer.
//*********************************************************************************

IOReturn IOService::setIdleTimerPeriod ( unsigned long period )
{
    if (!initialized)
		return IOPMNotYetInitialized;

    OUR_PMLog(kPMLogSetIdleTimerPeriod, period, 0);

    IOPMRequest * request =
        acquirePMRequest( this, kIOPMRequestTypeSetIdleTimerPeriod );
    if (!request)
        return kIOReturnNoMemory;

    request->fArg0 = (void *) period;
    submitPMRequest( request );

    return IOPMNoErr;
}

//******************************************************************************
// [public] nextIdleTimeout
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
    if (delta_secs < (int) fIdleTimerPeriod)
        delay_secs = (int) fIdleTimerPeriod - delta_secs;
    else
        delay_secs = (int) fIdleTimerPeriod;
    
    return (SInt32)delay_secs;
}

//******************************************************************************
// [public] start_PM_idle_timer
//
// The parameter is a pointer to us.  Use it to call our timeout method.
//******************************************************************************

void IOService::start_PM_idle_timer ( void )
{
    static const int                    maxTimeout = 100000;
    static const int                    minTimeout = 1;
    AbsoluteTime                        uptime;
    SInt32                              idle_in = 0;

	if (!initialized || !fIdleTimerPeriod || !fIdleTimerEventSource)
		return;

    IOLockLock(fActivityLock);

    clock_get_uptime(&uptime);
    
    // Subclasses may modify idle sleep algorithm
    idle_in = nextIdleTimeout(uptime, fDeviceActiveTimestamp, fCurrentPowerState);

    // Check for out-of range responses
    if (idle_in > maxTimeout)
    {
        // use standard implementation
        idle_in = IOService::nextIdleTimeout(uptime,
                        fDeviceActiveTimestamp,
                        fCurrentPowerState);
    } else if (idle_in < minTimeout) {
        idle_in = fIdleTimerPeriod;
    }

    IOLockUnlock(fActivityLock);

	fIdleTimerEventSource->setTimeout(idle_in, NSEC_PER_SEC);
}

//*********************************************************************************
// [private] idleTimerExpired
//
// The idle timer has expired.  If there has been activity since the last
// expiration, just restart the timer and return.  If there has not been
// activity, switch to the next lower power state and restart the timer.
//*********************************************************************************

void IOService::idleTimerExpired( IOTimerEventSource * )
{
	IOPMRequest *	request;
	bool			restartTimer = true;

    if ( !initialized || !fIdleTimerPeriod || fLockedFlags.PMStop )
        return;

	IOLockLock(fActivityLock);

	// Check for device activity (tickles) over last timer period.

	if (fDeviceActive)
	{
		// Device was active - do not drop power, restart timer.
		fDeviceActive = false;
	}
	else
	{
		// No device activity - drop power state by one level.
		// Decrement the cached tickle power state when possible.
		// This value may be (-1) before activityTickle() is called,
		// but the power drop request must be issued regardless.

		if (fActivityTicklePowerState > 0)
		{
			fActivityTicklePowerState--;
		}

		request = acquirePMRequest( this, kIOPMRequestTypeActivityTickle );
		if (request)
		{
			request->fArg0 = (void *) 0;		// power state (irrelevant)
			request->fArg1 = (void *) false;	// power drop
			submitPMRequest( request );

			// Do not restart timer until after the tickle request has been
			// processed.

			restartTimer = false;
		}
    }

	IOLockUnlock(fActivityLock);

	if (restartTimer)
		start_PM_idle_timer();
}

#ifndef __LP64__
//*********************************************************************************
// [deprecated] PM_idle_timer_expiration
//*********************************************************************************

void IOService::PM_idle_timer_expiration ( void )
{
}

//*********************************************************************************
// [deprecated] command_received
//*********************************************************************************

void IOService::command_received ( void *statePtr , void *, void * , void * )
{
}
#endif /* !__LP64__ */

//*********************************************************************************
// [public] setAggressiveness
//
// Pass on the input parameters to all power domain children. All those which are
// power domains will pass it on to their children, etc.
//*********************************************************************************

IOReturn IOService::setAggressiveness ( unsigned long type, unsigned long newLevel )
{
    return kIOReturnSuccess;
}

//*********************************************************************************
// [public] getAggressiveness
//
// Called by the user client.
//*********************************************************************************

IOReturn IOService::getAggressiveness ( unsigned long type, unsigned long * currentLevel )
{
    IOPMrootDomain *    rootDomain = getPMRootDomain();

    if (!rootDomain)
        return kIOReturnNotReady;
    
    return rootDomain->getAggressiveness( type, currentLevel );
}

//*********************************************************************************
// [public] getPowerState
//
//*********************************************************************************

UInt32 IOService::getPowerState ( void )
{
    if (!initialized)
        return 0;

    return fCurrentPowerState;
}

#ifndef __LP64__
//*********************************************************************************
// [deprecated] systemWake
//
// Pass this to all power domain children. All those which are
// power domains will pass it on to their children, etc.
//*********************************************************************************

IOReturn IOService::systemWake ( void )
{
    OSIterator *		iter;
    OSObject *			next;
    IOPowerConnection *	connection;
    IOService *			theChild;

    iter = getChildIterator(gIOPowerPlane);
    if ( iter )
    {
        while ( (next = iter->getNextObject()) )
        {
            if ( (connection = OSDynamicCast(IOPowerConnection, next)) )
            {
				if (connection->getReadyFlag() == false)
				{
					PM_CONNECT("[%s] %s: connection not ready\n",
						getName(), __FUNCTION__);
					continue;
				}

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

    if ( fControllingDriver != NULL )
    {
        if ( fControllingDriver->didYouWakeSystem() )
        {
            makeUsable();
        }
    }

    return IOPMNoErr;
}

//*********************************************************************************
// [deprecated] temperatureCriticalForZone
//*********************************************************************************

IOReturn IOService::temperatureCriticalForZone ( IOService * whichZone )
{
    IOService *	theParent;
    IOService *	theNub;
    
    OUR_PMLog(kPMLogCriticalTemp, 0, 0);

    if ( inPlane(gIOPowerPlane) && !IS_PM_ROOT() )
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
#endif /* !__LP64__ */

//*********************************************************************************
// [protected] powerOverrideOnPriv
//*********************************************************************************

IOReturn IOService::powerOverrideOnPriv ( void )
{
	IOPMRequest * request;

    if (!initialized)
		return IOPMNotYetInitialized;

	if (gIOPMWorkLoop->inGate())
	{
		fDeviceOverrides = true;
		return IOPMNoErr;
	}

	request = acquirePMRequest( this, kIOPMRequestTypePowerOverrideOnPriv );
	if (!request)
		return kIOReturnNoMemory;

	submitPMRequest( request );
    return IOPMNoErr;
}

//*********************************************************************************
// [protected] powerOverrideOffPriv
//*********************************************************************************

IOReturn IOService::powerOverrideOffPriv ( void )
{
	IOPMRequest * request;

    if (!initialized)
		return IOPMNotYetInitialized;

	if (gIOPMWorkLoop->inGate())
	{
		fDeviceOverrides = false;
		return IOPMNoErr;
	}

	request = acquirePMRequest( this, kIOPMRequestTypePowerOverrideOffPriv );
	if (!request)
		return kIOReturnNoMemory;

	submitPMRequest( request );
    return IOPMNoErr;
}

//*********************************************************************************
// [private] handlePowerOverrideChanged
//*********************************************************************************

void IOService::handlePowerOverrideChanged ( IOPMRequest * request )
{
	PM_ASSERT_IN_GATE();
	if (request->getType() == kIOPMRequestTypePowerOverrideOnPriv)
	{
		OUR_PMLog(kPMLogOverrideOn, 0, 0);
		fDeviceOverrides = true;
    }
	else
	{
		OUR_PMLog(kPMLogOverrideOff, 0, 0);
		fDeviceOverrides = false;
	}

	adjustPowerState();
}

//*********************************************************************************
// [private] startPowerChange
//*********************************************************************************

IOReturn IOService::startPowerChange (
    unsigned long		changeFlags,
    unsigned long		powerState,
    unsigned long		domainFlags,
    IOPowerConnection *	parentConnection,
    unsigned long		parentFlags )
{
	PM_ASSERT_IN_GATE();
	assert( fMachineState == kIOPM_Finished );
    assert( powerState < fNumberOfPowerStates );

    if (powerState >= fNumberOfPowerStates)
        return IOPMAckImplied;

#if ROOT_DOMAIN_RUN_STATES
    // Root domain can override chosen power state to a lower state.
    getPMRootDomain()->overridePowerStateForService(
                        this, &fRootDomainState,
                        &powerState, changeFlags);
#endif

	// Initialize the change note.

    fHeadNoteFlags            = changeFlags;
    fHeadNotePowerState       = powerState;
	fHeadNotePowerArrayEntry  = &fPowerStates[ powerState ];
	fHeadNoteParentConnection = NULL;

	if (changeFlags & kIOPMWeInitiated)
	{
        if (changeFlags & kIOPMSynchronize)
            OurSyncStart();
        else
            OurChangeStart();
		return 0;
	}
	else
	{
		assert(changeFlags & kIOPMParentInitiated);
        fHeadNoteDomainFlags = domainFlags;
		fHeadNoteParentFlags = parentFlags;
        fHeadNoteParentConnection = parentConnection;
		return ParentChangeStart();
	}
}

//*********************************************************************************
// [private] notifyInterestedDrivers
//*********************************************************************************

bool IOService::notifyInterestedDrivers ( void )
{
	IOPMinformee *		informee;
	IOPMinformeeList *	list = fInterestedDrivers;
	DriverCallParam *	param;
	IOItemCount			count;

	PM_ASSERT_IN_GATE();
	assert( fDriverCallParamCount == 0 );
	assert( fHeadNotePendingAcks == 0 );

    fHeadNotePendingAcks = 0;

	count = list->numberOfItems();
	if (!count)
		goto done;	// no interested drivers

	// Allocate an array of interested drivers and their return values
	// for the callout thread. Everything else is still "owned" by the
	// PM work loop, which can run to process acknowledgePowerChange()
	// responses.

	param = (DriverCallParam *) fDriverCallParamPtr;
	if (count > fDriverCallParamSlots)
	{
		if (fDriverCallParamSlots)
		{
			assert(fDriverCallParamPtr);
			IODelete(fDriverCallParamPtr, DriverCallParam, fDriverCallParamSlots);
			fDriverCallParamPtr = 0;
			fDriverCallParamSlots = 0;
		}

		param = IONew(DriverCallParam, count);
		if (!param)
			goto done;	// no memory

		fDriverCallParamPtr   = (void *) param;
		fDriverCallParamSlots = count;
	}

	informee = list->firstInList();
	assert(informee);
	for (IOItemCount i = 0; i < count; i++)
	{
		informee->timer = -1;
		param[i].Target = informee;
		informee->retain();
        informee = list->nextInList( informee );
	}

	fDriverCallParamCount = count;
	fHeadNotePendingAcks = count;

	// Machine state will be blocked pending callout thread completion.

	PM_LOCK();
	assert( fLockedFlags.DriverCallBusy == false );
	fLockedFlags.DriverCallBusy = true;
	PM_UNLOCK();
	thread_call_enter( fDriverCallEntry );
	return true;

done:
	// no interested drivers or did not schedule callout thread due to error.
	return false;
}

//*********************************************************************************
// [private] notifyInterestedDriversDone
//*********************************************************************************

void IOService::notifyInterestedDriversDone ( void )
{
	IOPMinformee *		informee;
	IOItemCount			count;
	DriverCallParam *	param;
	IOReturn			result;

	PM_ASSERT_IN_GATE();
	param = (DriverCallParam *) fDriverCallParamPtr;
	count = fDriverCallParamCount;

	assert( fLockedFlags.DriverCallBusy == false );
	assert( fMachineState == kIOPM_DriverThreadCallDone );

	if (param && count)
	{
		for (IOItemCount i = 0; i < count; i++, param++)
		{
			informee = (IOPMinformee *) param->Target;
			result   = param->Result;

			if ((result == IOPMAckImplied) || (result < 0))
			{
				// Interested driver return IOPMAckImplied.
                // If informee timer is zero, it must have de-registered
                // interest during the thread callout. That also drops
                // the pending ack count.

				if (fHeadNotePendingAcks && informee->timer)
                    fHeadNotePendingAcks--;

                informee->timer = 0;
			}
			else if (informee->timer)
			{
                assert(informee->timer == -1);

                // Driver has not acked, and has returned a positive result.
                // Enforce a minimum permissible timeout value.
                // Make the min value large enough so timeout is less likely
                // to occur if a driver misinterpreted that the return value
                // should be in microsecond units.  And make it large enough
                // to be noticeable if a driver neglects to ack.

                if (result < kMinAckTimeoutTicks)
                    result = kMinAckTimeoutTicks;

                informee->timer = (result / (ACK_TIMER_PERIOD / ns_per_us)) + 1;
			}
			// else, child has already acked or driver has removed interest,
            // and head_note_pendingAcks decremented.
			// informee may have been removed from the interested drivers list,
            // thus the informee must be retained across the callout.

			informee->release();
		}

		fDriverCallParamCount = 0;

		if ( fHeadNotePendingAcks )
		{
			OUR_PMLog(kPMLogStartAckTimer, 0, 0);
			start_ack_timer();
		}
	}

	// Hop back to original machine state path (from notifyAll)
	fMachineState = fNextMachineState;

	notifyChildren();
}

//*********************************************************************************
// [private] notifyChildren
//*********************************************************************************

void IOService::notifyChildren ( void )
{
    OSIterator *		iter;
    OSObject *			next;
    IOPowerConnection *	connection;
	OSArray *			children = 0;

	if (fStrictTreeOrder)
		children = OSArray::withCapacity(8);

    // Sum child power consumption in notifyChild()
    fHeadNotePowerArrayEntry->staticPower = 0;

    iter = getChildIterator(gIOPowerPlane);
    if ( iter )
    {
        while ((next = iter->getNextObject()))
        {
            if ((connection = OSDynamicCast(IOPowerConnection, next)))
            {
				if (connection->getReadyFlag() == false)
				{
					PM_CONNECT("[%s] %s: connection not ready\n",
						getName(), __FUNCTION__);
					continue;
				}

				if (children)
					children->setObject( connection );
				else
					notifyChild( connection,
						fDriverCallReason == kDriverCallInformPreChange );
			}
        }
        iter->release();
    }

	if (children)
	{
		if (children->getCount() == 0)
		{
			children->release();
			children = 0;
		}
		else
		{
			assert(fNotifyChildArray == 0);
			fNotifyChildArray = children;
			fNextMachineState = fMachineState;
			fMachineState     = kIOPM_NotifyChildrenDone;
		}		
	}
}

//*********************************************************************************
// [private] notifyChildrenDone
//*********************************************************************************

void IOService::notifyChildrenDone ( void )
{
	PM_ASSERT_IN_GATE();
	assert(fNotifyChildArray);
	assert(fMachineState == kIOPM_NotifyChildrenDone);

	// Interested drivers have all acked (if any), ack timer stopped.
	// Notify one child, wait for it to ack, then repeat for next child.
	// This is a workaround for some drivers with multiple instances at
	// the same branch in the power tree, but the driver is slow to power
	// up unless the tree ordering is observed. Problem observed only on
	// system wake, not on system sleep.
	//
	// We have the ability to power off in reverse child index order.
	// That works nicely on some machines, but not on all HW configs.

	if (fNotifyChildArray->getCount())
	{
		IOPowerConnection *	connection;
		connection = (IOPowerConnection *) fNotifyChildArray->getObject(0);
		fNotifyChildArray->removeObject(0);
		notifyChild( connection, fDriverCallReason == kDriverCallInformPreChange );
	}
	else
	{
		fNotifyChildArray->release();
		fNotifyChildArray = 0;
		fMachineState = fNextMachineState;
	}
}

//*********************************************************************************
// [private] notifyAll
//*********************************************************************************

IOReturn IOService::notifyAll ( int nextMachineState, bool is_prechange )
{
	// Save the next machine_state to be restored by notifyInterestedDriversDone()

	PM_ASSERT_IN_GATE();
	fNextMachineState = nextMachineState;
	fMachineState     = kIOPM_DriverThreadCallDone;
	fDriverCallReason = is_prechange ?
						kDriverCallInformPreChange : kDriverCallInformPostChange;

	if (!notifyInterestedDrivers())
		notifyInterestedDriversDone();

	return IOPMWillAckLater;
}

//*********************************************************************************
// [private, static] pmDriverCallout
//
// Thread call context
//*********************************************************************************

IOReturn IOService::actionDriverCalloutDone (
	OSObject * target,
	void * arg0, void * arg1,
	void * arg2, void * arg3 )
{
	IOServicePM * pwrMgt = (IOServicePM *) arg0;

	PM_LOCK();
	fLockedFlags.DriverCallBusy = false;
	PM_UNLOCK();

	if (gIOPMReplyQueue)
		gIOPMReplyQueue->signalWorkAvailable();

	return kIOReturnSuccess;
}

void IOService::pmDriverCallout ( IOService * from )
{
	assert(from);
	switch (from->fDriverCallReason)
	{
		case kDriverCallSetPowerState:
			from->driverSetPowerState();
			break;

		case kDriverCallInformPreChange:
		case kDriverCallInformPostChange:
			from->driverInformPowerChange();
			break;

		default:
			panic("IOService::pmDriverCallout bad machine state %x",
                from->fDriverCallReason);
	}

	gIOPMWorkLoop->runAction(actionDriverCalloutDone,
		/* target */ from,
		/* arg0   */ (void *) from->pwrMgt );
}

//*********************************************************************************
// [private] driverSetPowerState
//
// Thread call context
//*********************************************************************************

void IOService::driverSetPowerState ( void )
{
	IOService *			driver;
	unsigned long		powerState;
	DriverCallParam *	param;
	IOReturn			result;
    AbsoluteTime        end;

    assert( fLockedFlags.DriverCallBusy == true );
	param = (DriverCallParam *) fDriverCallParamPtr;
	assert( param );
	assert( fDriverCallParamCount == 1 );

	driver = fControllingDriver;
	powerState = fHeadNotePowerState;

	if (fLockedFlags.PMStop == false)
	{
		OUR_PMLog(          kPMLogProgramHardware, (uintptr_t) this, powerState);
        clock_get_uptime(&fDriverCallStartTime);
		result = driver->setPowerState( powerState, this );
        clock_get_uptime(&end);
		OUR_PMLog((UInt32) -kPMLogProgramHardware, (uintptr_t) this, (UInt32) result);

#if LOG_SETPOWER_TIMES
        if ((result == IOPMAckImplied) || (result < 0))
        {
            uint64_t    nsec;

            SUB_ABSOLUTETIME(&end, &fDriverCallStartTime);
            absolutetime_to_nanoseconds(end, &nsec);
            if (nsec > LOG_SETPOWER_TIMES)
                PM_DEBUG("%s::setPowerState(%p, %lu -> %lu) took %d ms\n",
                    fName, this, fCurrentPowerState, powerState, NS_TO_MS(nsec));
        }
#endif
	}
	else
		result = kIOPMAckImplied;

	param->Result = result;
}

//*********************************************************************************
// [private] driverInformPowerChange
//
// Thread call context
//*********************************************************************************

void IOService::driverInformPowerChange ( void )
{
	IOItemCount			count;
	IOPMinformee *		informee;
	IOService *			driver;
	IOReturn			result;
	IOPMPowerFlags		powerFlags;
	unsigned long		powerState;
	DriverCallParam *	param;
    AbsoluteTime        end;

    assert( fLockedFlags.DriverCallBusy == true );
	param = (DriverCallParam *) fDriverCallParamPtr;
	count = fDriverCallParamCount;
	assert( count && param );

	powerFlags = fHeadNotePowerArrayEntry->capabilityFlags;
	powerState = fHeadNotePowerState;

	for (IOItemCount i = 0; i < count; i++)
	{
		informee = (IOPMinformee *) param->Target;
		driver   = informee->whatObject;

		if ((fLockedFlags.PMStop == false) && informee->active)
		{
			if (fDriverCallReason == kDriverCallInformPreChange)
			{
				OUR_PMLog(kPMLogInformDriverPreChange, (uintptr_t) this, powerState);
                clock_get_uptime(&informee->startTime);
				result = driver->powerStateWillChangeTo(powerFlags, powerState, this);
                clock_get_uptime(&end);
				OUR_PMLog((UInt32)-kPMLogInformDriverPreChange, (uintptr_t) this, result);
			}
			else
			{
				OUR_PMLog(kPMLogInformDriverPostChange, (uintptr_t) this, powerState);
                clock_get_uptime(&informee->startTime);
				result = driver->powerStateDidChangeTo(powerFlags, powerState, this);
                clock_get_uptime(&end);
				OUR_PMLog((UInt32)-kPMLogInformDriverPostChange, (uintptr_t) this, result);
			}

#if LOG_SETPOWER_TIMES
            if ((result == IOPMAckImplied) || (result < 0))
            {
                uint64_t nsec;

                SUB_ABSOLUTETIME(&end, &informee->startTime);
                absolutetime_to_nanoseconds(end, &nsec);
                if (nsec > LOG_SETPOWER_TIMES)
                    PM_DEBUG("%s::powerState%sChangeTo(%p, %s, %lu -> %lu) took %d ms\n",
                        driver->getName(),
                        (fDriverCallReason == kDriverCallInformPreChange) ? "Will" : "Did",
                        driver, fName, fCurrentPowerState, powerState, NS_TO_MS(nsec));
            }
#endif
		}
		else
			result = kIOPMAckImplied;

		param->Result = result;
		param++;
	}
}

//*********************************************************************************
// [private] notifyChild
//
// Notify a power domain child of an upcoming power change.
// If the object acknowledges the current change, we return TRUE.
//*********************************************************************************

bool IOService::notifyChild ( IOPowerConnection * theNub, bool is_prechange )
{
    IOReturn		ret = IOPMAckImplied;
    unsigned long	childPower;
    IOService *		theChild;
	IOPMRequest *	childRequest;
    uint32_t        requestArg2;
	int				requestType;

	PM_ASSERT_IN_GATE();
    theChild = (IOService *)(theNub->copyChildEntry(gIOPowerPlane));
    if (!theChild)
    {
		assert(false);
        return true;
    }

    // Unless the child handles the notification immediately and returns
    // kIOPMAckImplied, we'll be awaiting their acknowledgement later.
	fHeadNotePendingAcks++;
    theNub->setAwaitingAck(true);

    requestArg2 = fHeadNoteFlags;
    if (fHeadNotePowerState < fCurrentPowerState)
        requestArg2 |= kIOPMDomainPowerDrop;

    requestType = is_prechange ?
        kIOPMRequestTypePowerDomainWillChange :
        kIOPMRequestTypePowerDomainDidChange;

	childRequest = acquirePMRequest( theChild, requestType );
	if (childRequest)
	{
        theNub->retain();
		childRequest->fArg0 = (void *) fHeadNotePowerArrayEntry->outputPowerCharacter;
		childRequest->fArg1 = (void *) theNub;
		childRequest->fArg2 = (void *) requestArg2;
		theChild->submitPMRequest( childRequest );
		ret = IOPMWillAckLater;
	}
	else
	{
		ret = IOPMAckImplied;
		fHeadNotePendingAcks--;  
		theNub->setAwaitingAck(false);
        childPower = theChild->currentPowerConsumption();
        if ( childPower == kIOPMUnknown )
        {
            fHeadNotePowerArrayEntry->staticPower = kIOPMUnknown;
        } else {
            if (fHeadNotePowerArrayEntry->staticPower != kIOPMUnknown )
                fHeadNotePowerArrayEntry->staticPower += childPower;
        }
    }

    theChild->release();
	return (IOPMAckImplied == ret);
}

//*********************************************************************************
// [private] OurChangeTellClientsPowerDown
//
// All registered applications and kernel clients have positively acknowledged our
// intention of lowering power.  Here we notify them all that we will definitely
// lower the power.  If we don't have to wait for any of them to acknowledge, we
// carry on by notifying interested drivers.  Otherwise, we do wait.
//*********************************************************************************

void IOService::OurChangeTellClientsPowerDown ( void )
{
    fMachineState = kIOPM_OurChangeTellPriorityClientsPowerDown;
    tellChangeDown1(fHeadNotePowerState);
}

//*********************************************************************************
// [private] OurChangeTellPriorityClientsPowerDown
//
// All registered applications and kernel clients have positively acknowledged our
// intention of lowering power.  Here we notify "priority" clients that we are
// lowering power.  If we don't have to wait for any of them to acknowledge, we
// carry on by notifying interested drivers.  Otherwise, we do wait.
//*********************************************************************************

void IOService::OurChangeTellPriorityClientsPowerDown ( void )
{
    fMachineState = kIOPM_OurChangeNotifyInterestedDriversWillChange;
    tellChangeDown2(fHeadNotePowerState);
}

//*********************************************************************************
// [private] OurChangeNotifyInterestedDriversWillChange
//
// All registered applications and kernel clients have acknowledged our notification
// that we are lowering power.  Here we notify interested drivers.  If we don't have
// to wait for any of them to acknowledge, we instruct our power driver to make the
// change. Otherwise, we do wait.
//*********************************************************************************

void IOService::OurChangeNotifyInterestedDriversWillChange ( void )
{
    IOPMrootDomain  *rootDomain;
    if ((rootDomain = getPMRootDomain()) == this)
    {
        rootDomain->tracePoint(kIOPMTracePointSystemSleepDriversPhase);
    }

    notifyAll( kIOPM_OurChangeSetPowerState, kNotifyWillChange );
}

//*********************************************************************************
// [private] OurChangeSetPowerState
//
// All interested drivers have acknowledged our pre-change notification of a power
// change we initiated.  Here we instruct our controlling driver to make
// the change to the hardware.  If it does so, we continue processing
// (waiting for settle and notifying interested parties post-change.)
// If it doesn't, we have to wait for it to acknowledge and then continue.
//*********************************************************************************

void IOService::OurChangeSetPowerState ( void )
{
    fNextMachineState = kIOPM_OurChangeWaitForPowerSettle;
	fMachineState     = kIOPM_DriverThreadCallDone;
	fDriverCallReason = kDriverCallSetPowerState;

	if (notifyControllingDriver() == false)
		notifyControllingDriverDone();
}

//*********************************************************************************
// [private] OurChangeWaitForPowerSettle
//
// Our controlling driver has changed power state on the hardware
// during a power change we initiated.  Here we see if we need to wait
// for power to settle before continuing.  If not, we continue processing
// (notifying interested parties post-change).  If so, we wait and
// continue later.
//*********************************************************************************

void IOService::OurChangeWaitForPowerSettle ( void )
{
	fMachineState = kIOPM_OurChangeNotifyInterestedDriversDidChange;
    fSettleTimeUS = compute_settle_time();
    if ( fSettleTimeUS )
    {
		startSettleTimer(fSettleTimeUS);
	}
}

//*********************************************************************************
// [private] OurChangeNotifyInterestedDriversDidChange
//
// Power has settled on a power change we initiated.  Here we notify
// all our interested parties post-change.  If they all acknowledge, we're
// done with this change note, and we can start on the next one.
// Otherwise we have to wait for acknowledgements and finish up later.
//*********************************************************************************

void IOService::OurChangeNotifyInterestedDriversDidChange ( void )
{
    notifyAll( kIOPM_OurChangeFinish, kNotifyDidChange );
}

//*********************************************************************************
// [private] OurChangeFinish
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
// [private] ParentDownTellPriorityClientsPowerDown
//
// All applications and kernel clients have been notified of a power lowering
// initiated by the parent and we had to wait for responses.  Here
// we notify any priority clients.  If they all ack, we continue with the power change.
// If at least one doesn't, we have to wait for it to acknowledge and then continue.
//*********************************************************************************

void IOService::ParentDownTellPriorityClientsPowerDown ( void )
{
    fMachineState = kIOPM_ParentDownNotifyInterestedDriversWillChange;
	tellChangeDown2(fHeadNotePowerState);
}

//*********************************************************************************
// [private] ParentDownNotifyInterestedDriversWillChange
//
// All applications and kernel clients have been notified of a power lowering
// initiated by the parent and we had to wait for their responses.  Here we notify
// any interested drivers and power domain children.  If they all ack, we continue
// with the power change.
// If at least one doesn't, we have to wait for it to acknowledge and then continue.
//*********************************************************************************

void IOService::ParentDownNotifyInterestedDriversWillChange ( void )
{
    IOPMrootDomain  *rootDomain;
    if ((rootDomain = getPMRootDomain()) == this)
    {
        rootDomain->tracePoint(kIOPMTracePointSystemSleepDriversPhase);
    }

	notifyAll( kIOPM_ParentDownSetPowerState, kNotifyWillChange );
}

//*********************************************************************************
// [private] ParentDownSetPowerState
//
// We had to wait for it, but all parties have acknowledged our pre-change
// notification of a power lowering initiated by the parent.
// Here we instruct our controlling driver
// to put the hardware in the state it needs to be in when the domain is
// lowered.  If it does so, we continue processing
// (waiting for settle and acknowledging the parent.)
// If it doesn't, we have to wait for it to acknowledge and then continue.
//*********************************************************************************

void IOService::ParentDownSetPowerState ( void )
{
	fNextMachineState = kIOPM_ParentDownWaitForPowerSettle;
	fMachineState     = kIOPM_DriverThreadCallDone;
	fDriverCallReason = kDriverCallSetPowerState;

	if (notifyControllingDriver() == false)
		notifyControllingDriverDone();
}

//*********************************************************************************
// [private] ParentDownWaitForPowerSettle
//
// Our controlling driver has changed power state on the hardware
// during a power change initiated by our parent.  We have had to wait
// for acknowledgement from interested parties, or we have had to wait
// for the controlling driver to change the state.  Here we see if we need
// to wait for power to settle before continuing.  If not, we continue
// processing (acknowledging our preparedness to the parent).
// If so, we wait and continue later.
//*********************************************************************************

void IOService::ParentDownWaitForPowerSettle ( void )
{
	fMachineState = kIOPM_ParentDownNotifyDidChangeAndAcknowledgeChange;
    fSettleTimeUS = compute_settle_time();
    if ( fSettleTimeUS )
    {
       startSettleTimer(fSettleTimeUS);
	}
}

//*********************************************************************************
// [private] ParentDownNotifyDidChangeAndAcknowledgeChange
//
// Power has settled on a power change initiated by our parent.  Here we
// notify interested parties.
//*********************************************************************************

void IOService::ParentDownNotifyDidChangeAndAcknowledgeChange ( void )
{
	notifyAll( kIOPM_ParentAcknowledgePowerChange, kNotifyDidChange );	
}

//*********************************************************************************
// [private] ParentAcknowledgePowerChange
//
// We had to wait for it, but all parties have acknowledged our post-change
// notification of a power change (either Up or Down) initiated by the parent.
// Here we acknowledge the parent.
//*********************************************************************************

void IOService::ParentAcknowledgePowerChange ( void )
{
    IORegistryEntry *	nub;
    IOService *			parent;

    nub = fHeadNoteParentConnection;
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
// [private] ParentUpSetPowerState
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

void IOService::ParentUpSetPowerState ( void )
{
	fNextMachineState = kIOPM_ParentUpWaitForSettleTime;
	fMachineState     = kIOPM_DriverThreadCallDone;
	fDriverCallReason = kDriverCallSetPowerState;

	if (notifyControllingDriver() == false)
		notifyControllingDriverDone();
}

//*********************************************************************************
// [private] ParentUpWaitForSettleTime
//
// Our controlling driver has changed power state on the hardware
// during a power raise initiated by the parent, but we had to wait for it.
// Here we see if we need to wait for power to settle before continuing.
// If not, we continue processing  (notifying interested parties post-change).
// If so, we wait and continue later.
//*********************************************************************************

void IOService::ParentUpWaitForSettleTime ( void )
{
	fMachineState = kIOPM_ParentUpNotifyInterestedDriversDidChange;
    fSettleTimeUS = compute_settle_time();
    if ( fSettleTimeUS )
    {
        startSettleTimer(fSettleTimeUS);
    }
}

//*********************************************************************************
// [private] ParentUpNotifyInterestedDriversDidChange
//
// Power has settled on a power raise initiated by the parent.
// Here we notify all our interested parties post-change.  If they all acknowledge,
// we're done with this change note, and we can start on the next one.
// Otherwise we have to wait for acknowledgements and finish up later.
//*********************************************************************************

void IOService::ParentUpNotifyInterestedDriversDidChange ( void )
{
	notifyAll( kIOPM_ParentAcknowledgePowerChange, kNotifyDidChange );	
}

//*********************************************************************************
// [private] all_done
//
// A power change is complete, and the used post-change note is at
// the head of the queue.  Remove it and set myCurrentState to the result
// of the change.  Start up the next change in queue.
//*********************************************************************************

void IOService::all_done ( void )
{
    unsigned long	previous_state;

#if ROOT_DOMAIN_RUN_STATES
    getPMRootDomain()->handlePowerChangeDoneForService(
                        /* service */       this,
                        /* RD flags */      &fRootDomainState,
                        /* new pwr state */ fHeadNotePowerState,
                        /* change flags */  fHeadNoteFlags );
#endif

    if ((fHeadNoteFlags & kIOPMSynchronize) &&
        ((fMachineState == kIOPM_Finished) || (fMachineState == kIOPM_SyncFinish)))
    {
        // Sync operation and no power change occurred.
        // Do not inform driver and clients about this request completion,
        // except for the originator (root domain).

        if (getPMRequestType() == kIOPMRequestTypeSynchronizePowerTree)
        {
            powerChangeDone(fCurrentPowerState);
        }

        fMachineState = kIOPM_Finished;
        return;
    }

    fMachineState = kIOPM_Finished;

    // our power change
    if ( fHeadNoteFlags & kIOPMWeInitiated )
    {
        // could our driver switch to the new state?
        if ( !( fHeadNoteFlags & kIOPMNotDone) )
        {
			// we changed, tell our parent
			if ( !IS_PM_ROOT() )
			{
				ask_parent(fHeadNotePowerState);
			}

            // yes, did power raise?
            if ( fCurrentPowerState < fHeadNotePowerState )
            {
                // yes, inform clients and apps
                tellChangeUp (fHeadNotePowerState);
            }
            previous_state = fCurrentPowerState;
            // either way
            fCurrentPowerState = fHeadNotePowerState;
#if PM_VARS_SUPPORT
			fPMVars->myCurrentState = fCurrentPowerState;
#endif
            OUR_PMLog(kPMLogChangeDone, fCurrentPowerState, 0);
			
            // inform subclass policy-maker
            if ((fLockedFlags.PMStop == false) && fParentsKnowState)
                powerChangeDone(previous_state);
            else
                PM_DEBUG("%s::powerChangeDone() skipped\n", getName());
        }
    }

    // parent's power change
    if ( fHeadNoteFlags & kIOPMParentInitiated)
    {
        if (((fHeadNoteFlags & kIOPMDomainWillChange) && (fCurrentPowerState >= fHeadNotePowerState)) ||
			((fHeadNoteFlags & kIOPMDomainDidChange) && (fCurrentPowerState < fHeadNotePowerState)))
        {
            // did power raise?
            if ( fCurrentPowerState < fHeadNotePowerState )
            {
                // yes, inform clients and apps
                tellChangeUp (fHeadNotePowerState);
            }
            // either way
            previous_state = fCurrentPowerState;
            fCurrentPowerState = fHeadNotePowerState;
#if PM_VARS_SUPPORT
			fPMVars->myCurrentState = fCurrentPowerState;
#endif
            fMaxCapability = fControllingDriver->maxCapabilityForDomainState(fHeadNoteDomainFlags);

            OUR_PMLog(kPMLogChangeDone, fCurrentPowerState, 0);

            // inform subclass policy-maker
            if ((fLockedFlags.PMStop == false) && fParentsKnowState)
                powerChangeDone(previous_state);
            else
                PM_DEBUG("%s::powerChangeDone() skipped\n", getName());
        }
    }

    if (fCurrentPowerState < fNumberOfPowerStates)
    {
        const IOPMPowerState * powerStatePtr = &fPowerStates[fCurrentPowerState];

        fCurrentCapabilityFlags = powerStatePtr->capabilityFlags;
        if (fCurrentCapabilityFlags & kIOPMStaticPowerValid)
            fCurrentPowerConsumption = powerStatePtr->staticPower;
    }

    // When power rises enough to satisfy the tickle's desire for more power,
    // the condition preventing idle-timer from dropping power is removed.

    if (fCurrentPowerState >= fIdleTimerMinPowerState)
    {
        fIdleTimerMinPowerState = 0;
    }
}

//*********************************************************************************
// [public] settleTimerExpired
//
// Power has settled after our last change.  Notify interested parties that
// there is a new power state.
//*********************************************************************************

void IOService::settleTimerExpired ( void )
{
	fSettleTimeUS = 0;
}

//*********************************************************************************
// [private] compute_settle_time
//
// Compute the power-settling delay in microseconds for the
// change from myCurrentState to head_note_state.
//*********************************************************************************

unsigned long IOService::compute_settle_time ( void )
{
    unsigned long	totalTime;
    unsigned long	i;

	PM_ASSERT_IN_GATE();

    // compute total time to attain the new state
    totalTime = 0;
    i = fCurrentPowerState;

    // we're lowering power
    if ( fHeadNotePowerState < fCurrentPowerState )
    {
        while ( i > fHeadNotePowerState )
        {
            totalTime +=  fPowerStates[i].settleDownTime;
            i--;
        }
    }

    // we're raising power
    if ( fHeadNotePowerState > fCurrentPowerState )
    {
        while ( i < fHeadNotePowerState )
        {
            totalTime +=  fPowerStates[i+1].settleUpTime;
            i++;
        }
    }

    return totalTime;
}

//*********************************************************************************
// [private] startSettleTimer
//
// Enter a power-settling delay in microseconds and start a timer for that delay.
//*********************************************************************************

IOReturn IOService::startSettleTimer ( unsigned long delay )
{
    AbsoluteTime	deadline;
	boolean_t		pending;

	retain();
    clock_interval_to_deadline(delay, kMicrosecondScale, &deadline);
    pending = thread_call_enter_delayed(fSettleTimer, deadline);
	if (pending) release();

    return IOPMNoErr;
}

//*********************************************************************************
// [public] ackTimerTick
//
// The acknowledgement timeout periodic timer has ticked.
// If we are awaiting acks for a power change notification,
// we decrement the timer word of each interested driver which hasn't acked.
// If a timer word becomes zero, we pretend the driver aknowledged.
// If we are waiting for the controlling driver to change the power
// state of the hardware, we decrement its timer word, and if it becomes
// zero, we pretend the driver acknowledged.
//
// Returns true if the timer tick made it possible to advance to the next
// machine state, false otherwise.
//*********************************************************************************

#ifndef __LP64__
void IOService::ack_timer_ticked ( void )
{
	assert(false);
}
#endif /* !__LP64__ */

bool IOService::ackTimerTick( void )
{
    IOPMinformee *		nextObject;
	bool				done = false;

	PM_ASSERT_IN_GATE();
    switch (fMachineState) {
        case kIOPM_OurChangeWaitForPowerSettle:
        case kIOPM_ParentDownWaitForPowerSettle:
        case kIOPM_ParentUpWaitForSettleTime:
            // are we waiting for controlling driver to acknowledge?
            if ( fDriverTimer > 0 )
            {
                // yes, decrement timer tick
                fDriverTimer--;
                if ( fDriverTimer == 0 )
                {
                    // controlling driver is tardy
                    uint64_t nsec = computeTimeDeltaNS(&fDriverCallStartTime);
                    OUR_PMLog(kPMLogCtrlDriverTardy, 0, 0);
                    setProperty(kIOPMTardyAckSPSKey, kOSBooleanTrue);
                    PM_ERROR("%s::setPowerState(%p, %lu -> %lu) timed out after %d ms\n",
                        fName, this, fCurrentPowerState, fHeadNotePowerState, NS_TO_MS(nsec));

                    if (gIOKitDebug & kIOLogDebugPower)
                    {
                        panic("%s::setPowerState(%p, %lu -> %lu) timed out after %d ms",
                            fName, this, fCurrentPowerState, fHeadNotePowerState, NS_TO_MS(nsec));
                    }
                    else
					{
						// Unblock state machine and pretend driver has acked.
						done = true;
					}
                } else {
                    // still waiting, set timer again
                    start_ack_timer();
                }
            }
            break;

        case kIOPM_OurChangeSetPowerState:
        case kIOPM_OurChangeFinish:
        case kIOPM_ParentDownSetPowerState:
        case kIOPM_ParentAcknowledgePowerChange:
        case kIOPM_ParentUpSetPowerState:
		case kIOPM_NotifyChildrenDone:
            // are we waiting for interested parties to acknowledge?
            if ( fHeadNotePendingAcks != 0 )
            {
                // yes, go through the list of interested drivers
                nextObject = fInterestedDrivers->firstInList();
                // and check each one
                while (  nextObject != NULL )
                {
                    if ( nextObject->timer > 0 )
                    {
                        nextObject->timer--;
                        // this one should have acked by now
                        if ( nextObject->timer == 0 )
                        {
                            uint64_t nsec = computeTimeDeltaNS(&nextObject->startTime);
                            OUR_PMLog(kPMLogIntDriverTardy, 0, 0);
                            nextObject->whatObject->setProperty(kIOPMTardyAckPSCKey, kOSBooleanTrue);
                            PM_ERROR("%s::powerState%sChangeTo(%p, %s, %lu -> %lu) timed out after %d ms\n",
                                nextObject->whatObject->getName(),
                                (fDriverCallReason == kDriverCallInformPreChange) ? "Will" : "Did",
                                nextObject->whatObject, fName, fCurrentPowerState, fHeadNotePowerState,
                                NS_TO_MS(nsec));

                            // Pretend driver has acked.
                            fHeadNotePendingAcks--;
                        }
                    }
                    nextObject = fInterestedDrivers->nextInList(nextObject);
                }

                // is that the last?
                if ( fHeadNotePendingAcks == 0 )
                {
                    // yes, we can continue
					done = true;
                } else {
                    // no, set timer again
                    start_ack_timer();
                }
            }
            break;

        case kIOPM_ParentDownTellPriorityClientsPowerDown:
        case kIOPM_ParentDownNotifyInterestedDriversWillChange:
        case kIOPM_OurChangeTellClientsPowerDown:
        case kIOPM_OurChangeTellPriorityClientsPowerDown:
        case kIOPM_OurChangeNotifyInterestedDriversWillChange:
			// apps didn't respond in time
            cleanClientResponses(true);
            OUR_PMLog(kPMLogClientTardy, 0, 1);
			// tardy equates to approval
			done = true;
            break;

        default:
            PM_TRACE("%s: unexpected ack timer tick (state = %d)\n",
				getName(), fMachineState);
            break;
    }
	return done;
}

//*********************************************************************************
// [private] start_ack_timer
//*********************************************************************************

void IOService::start_ack_timer ( void )
{
	start_ack_timer( ACK_TIMER_PERIOD, kNanosecondScale );
}

void IOService::start_ack_timer ( UInt32 interval, UInt32 scale )
{
    AbsoluteTime	deadline;
	boolean_t		pending;

    clock_interval_to_deadline(interval, scale, &deadline);

	retain();
    pending = thread_call_enter_delayed(fAckTimer, deadline);
	if (pending) release();
}

//*********************************************************************************
// [private] stop_ack_timer
//*********************************************************************************

void IOService::stop_ack_timer ( void )
{
	boolean_t		pending;

    pending = thread_call_cancel(fAckTimer);
	if (pending) release();
}

//*********************************************************************************
// [static] actionAckTimerExpired
//
// Inside PM work loop's gate.
//*********************************************************************************

IOReturn
IOService::actionAckTimerExpired (
	OSObject * target,
	void * arg0, void * arg1,
	void * arg2, void * arg3 )
{
	IOService * me = (IOService *) target;
	bool		done;

	// done will be true if the timer tick unblocks the machine state,
	// otherwise no need to signal the work loop.

	done = me->ackTimerTick();
	if (done && gIOPMReplyQueue)
		gIOPMReplyQueue->signalWorkAvailable();

	return kIOReturnSuccess;
}

//*********************************************************************************
// ack_timer_expired
//
// Thread call function. Holds a retain while the callout is in flight.
//*********************************************************************************

void
IOService::ack_timer_expired ( thread_call_param_t arg0, thread_call_param_t arg1 )
{
	IOService * me = (IOService *) arg0;

	if (gIOPMWorkLoop)
	{
		gIOPMWorkLoop->runAction(&actionAckTimerExpired, me);
	}
	me->release();
}

//*********************************************************************************
// settle_timer_expired
//
// Thread call function. Holds a retain while the callout is in flight.
//*********************************************************************************

static void
settle_timer_expired ( thread_call_param_t arg0, thread_call_param_t arg1 )
{
	IOService * me = (IOService *) arg0;

	if (gIOPMWorkLoop && gIOPMReplyQueue)
	{
		gIOPMWorkLoop->runAction(
            OSMemberFunctionCast(IOWorkLoop::Action, me, &IOService::settleTimerExpired),
            me);
		gIOPMReplyQueue->signalWorkAvailable();
	}
	me->release();
}

//*********************************************************************************
// [private] ParentChangeStart
//
// Here we begin the processing of a power change initiated by our parent.
//*********************************************************************************

IOReturn IOService::ParentChangeStart ( void )
{
	PM_ASSERT_IN_GATE();
    OUR_PMLog( kPMLogStartParentChange, fHeadNotePowerState, fCurrentPowerState );

    // Power domain is lowering power
    if ( fHeadNotePowerState < fCurrentPowerState )
    {
		setParentInfo( fHeadNoteParentFlags, fHeadNoteParentConnection, true );

#if ROOT_DOMAIN_RUN_STATES
        getPMRootDomain()->handlePowerChangeStartForService(
                            /* service */       this,
                            /* RD flags */      &fRootDomainState,
                            /* new pwr state */ fHeadNotePowerState,
                            /* change flags */  fHeadNoteFlags );
#endif

    	// tell apps and kernel clients
    	fInitialChange = false;
        fMachineState = kIOPM_ParentDownTellPriorityClientsPowerDown;
		tellChangeDown1(fHeadNotePowerState);
        return IOPMWillAckLater;
    }

    // Power domain is raising power
    if ( fHeadNotePowerState > fCurrentPowerState )
    {
        if ( fDesiredPowerState > fCurrentPowerState )
        {
            if ( fDesiredPowerState < fHeadNotePowerState )
            {
                // We power up, but not all the way
                fHeadNotePowerState = fDesiredPowerState;
				fHeadNotePowerArrayEntry = &fPowerStates[fDesiredPowerState];
                OUR_PMLog(kPMLogAmendParentChange, fHeadNotePowerState, 0);
             }
        } else {
            // We don't need to change
            fHeadNotePowerState = fCurrentPowerState;
			fHeadNotePowerArrayEntry = &fPowerStates[fCurrentPowerState];			
            OUR_PMLog(kPMLogAmendParentChange, fHeadNotePowerState, 0);
        }
    }

    if ( fHeadNoteFlags & kIOPMDomainDidChange )
	{
        if ( fHeadNotePowerState > fCurrentPowerState )
        {
#if ROOT_DOMAIN_RUN_STATES
            getPMRootDomain()->handlePowerChangeStartForService(
                                /* service */       this,
                                /* RD flags */      &fRootDomainState,
                                /* new pwr state */ fHeadNotePowerState,
                                /* change flags */  fHeadNoteFlags );
#endif

            // Parent did change up - start our change up
            fInitialChange = false;
            notifyAll( kIOPM_ParentUpSetPowerState, kNotifyWillChange );
            return IOPMWillAckLater;
        }
        else if (fHeadNoteFlags & kIOPMSynchronize)
        {
            // We do not need to change power state, but notify
            // children to propagate tree synchronization.
            fMachineState     = kIOPM_SyncNotifyDidChange;
            fDriverCallReason = kDriverCallInformPreChange;
            notifyChildren();
            return IOPMWillAckLater;
        }
    }

    all_done();
    return IOPMAckImplied;
}

//*********************************************************************************
// [private] OurChangeStart
//
// Here we begin the processing of a power change initiated by us.
//*********************************************************************************

void IOService::OurChangeStart ( void )
{
	PM_ASSERT_IN_GATE();
    OUR_PMLog( kPMLogStartDeviceChange, fHeadNotePowerState, fCurrentPowerState );

	// fMaxCapability is our maximum possible power state based on the current
	// power state of our parents.  If we are trying to raise power beyond the
	// maximum, send an async request for more power to all parents.

    if (!IS_PM_ROOT() && (fMaxCapability < fHeadNotePowerState))
    {
        fHeadNoteFlags |= kIOPMNotDone;
		ask_parent(fHeadNotePowerState);
        OurChangeFinish();
        return;
    }

	// Redundant power changes skips to the end of the state machine.

    if (!fInitialChange && (fHeadNotePowerState == fCurrentPowerState))
	{
		OurChangeFinish();
		return;
    }
    fInitialChange = false;

#if ROOT_DOMAIN_RUN_STATES
    getPMRootDomain()->handlePowerChangeStartForService(
                        /* service */       this,
                        /* RD flags */      &fRootDomainState,
                        /* new pwr state */ fHeadNotePowerState,
                        /* change flags */  fHeadNoteFlags );
#endif

	// Two separate paths, depending if power is being raised or lowered.
	// Lowering power is subject to client approval.

    if ( fHeadNotePowerState < fCurrentPowerState )
    {
		// Next state when dropping power.
        fMachineState = kIOPM_OurChangeTellClientsPowerDown;
        fDoNotPowerDown = false;

        // Ask apps and kernel clients permission to lower power.	
        fOutOfBandParameter = kNotifyApps;
		askChangeDown(fHeadNotePowerState);
    }
	else
	{
		// Notify interested drivers and children.
        notifyAll( kIOPM_OurChangeSetPowerState, kNotifyWillChange );
    }
}

//*********************************************************************************
// [private] OurSyncStart
//*********************************************************************************

void IOService::OurSyncStart ( void )
{
	PM_ASSERT_IN_GATE();

    if (fInitialChange)
        return;

#if ROOT_DOMAIN_RUN_STATES
    getPMRootDomain()->handlePowerChangeStartForService(
                        /* service */       this,
                        /* RD flags */      &fRootDomainState,
                        /* new pwr state */ fHeadNotePowerState,
                        /* change flags */  fHeadNoteFlags );
#endif

    fMachineState     = kIOPM_SyncNotifyDidChange;
    fDriverCallReason = kDriverCallInformPreChange;

    notifyChildren();
}

//*********************************************************************************
// [private] ask_parent
//
// Call the power domain parent to ask for a higher power state in the domain
// or to suggest a lower power state.
//*********************************************************************************

IOReturn IOService::ask_parent ( unsigned long requestedState )
{
    OSIterator *			iter;
    OSObject *				next;
    IOPowerConnection *		connection;
    IOService *				parent;
	const IOPMPowerState *	powerStatePtr;
    unsigned long			ourRequest;

	PM_ASSERT_IN_GATE();
    if (requestedState >= fNumberOfPowerStates)
        return IOPMNoErr;

	powerStatePtr = &fPowerStates[requestedState];
	ourRequest    = powerStatePtr->inputPowerRequirement;

    if ( powerStatePtr->capabilityFlags & (kIOPMChildClamp | kIOPMPreventIdleSleep) )
    {
        ourRequest |= kIOPMPreventIdleSleep;
    }
    if ( powerStatePtr->capabilityFlags & (kIOPMChildClamp2 | kIOPMPreventSystemSleep) )
    {
        ourRequest |= kIOPMPreventSystemSleep;
    }

    // is this a new desire?
    if ( fPreviousRequest == ourRequest )
    {	
        // no, the parent knows already, just return
        return IOPMNoErr;
    }

    if ( IS_PM_ROOT() )
    {
        return IOPMNoErr;
    }
    fPreviousRequest = ourRequest;

    iter = getParentIterator(gIOPowerPlane);
    if ( iter )
    {
        while ( (next = iter->getNextObject()) )
        {
            if ( (connection = OSDynamicCast(IOPowerConnection, next)) )
            {
                parent = (IOService *)connection->copyParentEntry(gIOPowerPlane);
                if ( parent ) {
                    if ( parent->requestPowerDomainState(
						ourRequest, connection, IOPMLowestState) != IOPMNoErr )
                    {
                        OUR_PMLog(kPMLogRequestDenied, fPreviousRequest, 0);
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
// [private] notifyControllingDriver
//*********************************************************************************

bool IOService::notifyControllingDriver ( void )
{
	DriverCallParam *	param;
	unsigned long		powerState;

	PM_ASSERT_IN_GATE();
	assert( fDriverCallParamCount == 0  );
	assert( fControllingDriver );

	powerState = fHeadNotePowerState;

	param = (DriverCallParam *) fDriverCallParamPtr;
	if (!param)
	{
		param = IONew(DriverCallParam, 1);
		if (!param)
			return false;	// no memory

		fDriverCallParamPtr   = (void *) param;
		fDriverCallParamSlots = 1;
	}

	param->Target = fControllingDriver;
	fDriverCallParamCount = 1;

	fDriverTimer = -1;

	// Machine state for this object will stall waiting for a reply
	// from the callout thread.

	PM_LOCK();
	assert( fLockedFlags.DriverCallBusy == false );
	fLockedFlags.DriverCallBusy = true;
	PM_UNLOCK();
	thread_call_enter( fDriverCallEntry );
	return true;
}

//*********************************************************************************
// [private] notifyControllingDriverDone
//*********************************************************************************

void IOService::notifyControllingDriverDone( void )
{
	DriverCallParam *	param;
	IOReturn			result;

	PM_ASSERT_IN_GATE();
	param = (DriverCallParam *) fDriverCallParamPtr;

	assert( fLockedFlags.DriverCallBusy == false );
	assert( fMachineState == kIOPM_DriverThreadCallDone );

	if (param)
	{
		assert(fDriverCallParamCount == 1);
		
		// the return value from setPowerState()
		result = param->Result;

		if ((result == IOPMAckImplied) || (result < 0))
		{
			// child return IOPMAckImplied
			fDriverTimer = 0;
		}
		else if (fDriverTimer)
		{
			assert(fDriverTimer == -1);

            // Driver has not acked, and has returned a positive result.
            // Enforce a minimum permissible timeout value.
            // Make the min value large enough so timeout is less likely
            // to occur if a driver misinterpreted that the return value
            // should be in microsecond units.  And make it large enough
            // to be noticeable if a driver neglects to ack.

            if (result < kMinAckTimeoutTicks)
                result = kMinAckTimeoutTicks;

            fDriverTimer = (result / (ACK_TIMER_PERIOD / ns_per_us)) + 1;
		}
		// else, child has already acked and driver_timer reset to 0.

		fDriverCallParamCount = 0;

		if ( fDriverTimer )
		{
			OUR_PMLog(kPMLogStartAckTimer, 0, 0);
			start_ack_timer();
		}
	}

	// Hop back to original machine state path.
	fMachineState = fNextMachineState;
}

//*********************************************************************************
// [public] askChangeDown
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
    return tellClientsWithResponse( kIOMessageCanDevicePowerOff );
}

//*********************************************************************************
// [private] tellChangeDown1
//
// Notify registered applications and kernel clients that we are definitely
// dropping power.
//
// Return true if we don't have to wait for acknowledgements
//*********************************************************************************

bool IOService::tellChangeDown1 ( unsigned long stateNum )
{
    fOutOfBandParameter = kNotifyApps;
    return tellChangeDown(stateNum);
}

//*********************************************************************************
// [private] tellChangeDown2
//
// Notify priority clients that we are definitely dropping power.
//
// Return true if we don't have to wait for acknowledgements
//*********************************************************************************

bool IOService::tellChangeDown2 ( unsigned long stateNum )
{
    fOutOfBandParameter = kNotifyPriority;
    return tellChangeDown(stateNum);
}

//*********************************************************************************
// [public] tellChangeDown
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
    return tellClientsWithResponse( kIOMessageDeviceWillPowerOff );
}

//*********************************************************************************
// cleanClientResponses
//
//*********************************************************************************

static void logAppTimeouts ( OSObject * object, void * arg )
{
    IOPMInterestContext *   context = (IOPMInterestContext *) arg;
    OSObject *              flag;
    unsigned int            clientIndex;

    if (OSDynamicCast(_IOServiceInterestNotifier, object))
    {
        // Discover the 'counter' value or index assigned to this client
        // when it was notified, by searching for the array index of the
        // client in an array holding the cached interested clients.

        clientIndex = context->notifyClients->getNextIndexOfObject(object, 0);

        if ((clientIndex != (unsigned int) -1) &&
            (flag = context->responseFlags->getObject(clientIndex)) &&
            (flag != kOSBooleanTrue))
        {
            OSString * clientID = 0;
            context->us->messageClient(context->msgType, object, &clientID);
            PM_ERROR(context->errorLog, clientID ? clientID->getCStringNoCopy() : "");

            // TODO: record message type if possible
            IOService::getPMRootDomain()->pmStatsRecordApplicationResponse(
                gIOPMStatsApplicationResponseTimedOut,
                clientID ? clientID->getCStringNoCopy() : "",
                0, (30*1000), -1);

            if (clientID)
                clientID->release();
        }
    }
}

void IOService::cleanClientResponses ( bool logErrors )
{
    IOPMInterestContext context;

    if (logErrors && fResponseArray && fNotifyClientArray) {
        context.responseFlags    = fResponseArray;
        context.notifyClients    = fNotifyClientArray;
        context.serialNumber     = fSerialNumber;
        context.counter          = 0;
        context.msgType          = kIOMessageCopyClientID;
        context.us               = this;
        context.maxTimeRequested = 0;
        context.stateNumber      = fHeadNotePowerState;
        context.stateFlags       = fHeadNotePowerArrayEntry->capabilityFlags;
        context.errorLog         = "PM notification timeout (%s)\n";

        switch ( fOutOfBandParameter ) {
            case kNotifyApps:
                applyToInterested(gIOAppPowerStateInterest, logAppTimeouts, (void *) &context);
            case kNotifyPriority:
            default:
                break;
        }
    }

    if (fResponseArray)
    {
        // get rid of this stuff
        fResponseArray->release();
        fResponseArray = NULL;
    }
    if (fNotifyClientArray)
    {
        fNotifyClientArray->release();
        fNotifyClientArray = NULL;
    }

    return;
}

//*********************************************************************************
// [protected] tellClientsWithResponse
//
// Notify registered applications and kernel clients that we are definitely
// dropping power.
//
// Return true if we don't have to wait for acknowledgements
//*********************************************************************************

bool IOService::tellClientsWithResponse (
        int messageType )
{
    return tellClientsWithResponse( messageType, 0 );
}

bool IOService::tellClientsWithResponse (
        int                 messageType,
        IOPMMessageFilter   filter )
{
    IOPMInterestContext     context;

	PM_ASSERT_IN_GATE();
    assert( fResponseArray == NULL );
    assert( fNotifyClientArray == NULL );

    fResponseArray = OSArray::withCapacity( 1 );
    if (!fResponseArray)
        goto exit;

    fResponseArray->setCapacityIncrement(8);
    fSerialNumber += 1;

    context.responseFlags    = fResponseArray;
    context.notifyClients    = 0;
    context.serialNumber     = fSerialNumber;
    context.counter          = 0;
    context.msgType          = messageType;
    context.us               = this;
    context.maxTimeRequested = 0;
    context.stateNumber      = fHeadNotePowerState;
    context.stateFlags       = fHeadNotePowerArrayEntry->capabilityFlags;
    context.filterFunc       = filter;

    switch ( fOutOfBandParameter ) {
        case kNotifyApps:
            applyToInterested( gIOAppPowerStateInterest,
				pmTellAppWithResponse, (void *) &context );
            fNotifyClientArray = context.notifyClients;

            applyToInterested( gIOGeneralInterest,
				pmTellClientWithResponse, (void *) &context );
            break;

        case kNotifyPriority:
            applyToInterested( gIOPriorityPowerStateInterest,
				pmTellClientWithResponse, (void *) &context );
            break;
    }

    // do we have to wait for somebody?
    if ( !checkForDone() )
    {
        OUR_PMLog(kPMLogStartAckTimer, context.maxTimeRequested, 0);
		start_ack_timer( context.maxTimeRequested / 1000, kMillisecondScale );	
        return false;
    }

exit:
    // everybody responded
    if (fResponseArray)
    {
        fResponseArray->release();
        fResponseArray = NULL;
    }
    if (fNotifyClientArray)
    {
        fNotifyClientArray->release();
        fNotifyClientArray = NULL;
    }

    return true;
}

//*********************************************************************************
// [static private] pmTellAppWithResponse
//
// We send a message to an application, and we expect a response, so we compute a
// cookie we can identify the response with.
//*********************************************************************************

void IOService::pmTellAppWithResponse ( OSObject * object, void * arg )
{
    IOPMInterestContext *	context = (IOPMInterestContext *) arg;
    IOServicePM *           pwrMgt = context->us->pwrMgt;
    AbsoluteTime            now;
    UInt32                  refcon;

    if (!OSDynamicCast(_IOServiceInterestNotifier, object))
    {
		// object must be an _IOServiceInterestNotifier.
        return;
    }

    // Lazily create app clients array.
    if (0 == context->notifyClients)
    {
        context->notifyClients = OSArray::withCapacity( 32 );
    }

    if (context->filterFunc && !context->filterFunc(object, arg))
    {
        // ack - needed to match the counter index at logAppTimeouts().
        context->responseFlags->setObject(context->counter, kOSBooleanTrue);
        if (context->notifyClients)
            context->notifyClients->setObject(context->counter, kOSBooleanTrue);
    }
    else
    {
        refcon = ((context->serialNumber & 0xFFFF)<<16)
               + (context->counter & 0xFFFF);
        OUR_PMLog(kPMLogAppNotify, context->msgType, refcon);

        if (gIOKitDebug & kIOLogDebugPower)
        {
            // Log client pid/name and associated index.
            OSString * clientID = 0;
            context->us->messageClient(kIOMessageCopyClientID, object, &clientID);
            PM_DEBUG("[Notify %u] message 0x%x to %s\n",
                (uint32_t) context->counter,
                context->msgType,
                clientID ? clientID->getCStringNoCopy() : "");
            if (clientID) clientID->release();
        }

#if LOG_APP_RESPONSE_TIMES
        OSNumber * num;
        clock_get_uptime(&now);
        num = OSNumber::withNumber(AbsoluteTime_to_scalar(&now), sizeof(uint64_t) * 8);
        if (num)
        {
            context->responseFlags->setObject(context->counter, num);
            num->release();
        }
        else
#endif
        context->responseFlags->setObject(context->counter, kOSBooleanFalse);
        
        if (context->notifyClients)
            context->notifyClients->setObject(context->counter, object);

        context->us->messageClient(context->msgType, object, (void *)refcon);
        if ( context->maxTimeRequested < k30seconds )
        {
            context->maxTimeRequested = k30seconds;
        }
    }

    context->counter++;
}

//*********************************************************************************
// [static private] pmTellClientWithResponse
//
// We send a message to an in-kernel client, and we expect a response, so we compute a
// cookie we can identify the response with.
// If it doesn't understand the notification (it is not power-management savvy)
// we won't wait for it to prepare for sleep.  If it tells us via a return code
// in the passed struct that it is currently ready, we won't wait for it to prepare.
// If it tells us via the return code in the struct that it does need time, we will chill.
//*********************************************************************************

void IOService::pmTellClientWithResponse ( OSObject * object, void * arg )
{
    IOPMInterestContext *           context = (IOPMInterestContext *) arg;
    IOPowerStateChangeNotification  notify;
    UInt32                          refcon;
    IOReturn                        retCode;
    OSObject *                      theFlag;

    if (context->filterFunc && !context->filterFunc(object, arg))
        return;

    refcon = ((context->serialNumber & 0xFFFF)<<16) + (context->counter & 0xFFFF);
    context->responseFlags->setObject(context->counter, kOSBooleanFalse);

    IOServicePM * pwrMgt = context->us->pwrMgt;
    if (gIOKitDebug & kIOLogPower) {
		OUR_PMLog(kPMLogClientNotify, refcon, (UInt32) context->msgType);
		if (OSDynamicCast(IOService, object)) {
			const char *who = ((IOService *) object)->getName();
			gPlatform->PMLog(who,
				kPMLogClientNotify, * (UInt32 *) object, (UInt64) object);
		} else if (OSDynamicCast(_IOServiceInterestNotifier, object)) {
			_IOServiceInterestNotifier *n = (_IOServiceInterestNotifier *) object;
			OUR_PMLog(kPMLogClientNotify, (UInt64) n->handler, 0);
		}
    }

    notify.powerRef = (void *)refcon;
    notify.returnValue = 0;
    notify.stateNumber = context->stateNumber;
    notify.stateFlags = context->stateFlags;
    retCode = context->us->messageClient(context->msgType,object,(void *)&notify);
    if ( retCode == kIOReturnSuccess )
    {
        if ( notify.returnValue == 0 )
        {
            // client doesn't want time to respond
            context->responseFlags->replaceObject(context->counter, kOSBooleanTrue);
			OUR_PMLog(kPMLogClientAcknowledge, refcon, (UInt64) object);
        } else {
            // it does want time, and it hasn't responded yet
            theFlag = context->responseFlags->getObject(context->counter);
            if ( kOSBooleanTrue != theFlag ) 
            {
                // so note its time requirement
                if ( context->maxTimeRequested < notify.returnValue ) 
                {
                    context->maxTimeRequested = notify.returnValue;
                }
            }
        }
    } else {
		OUR_PMLog(kPMLogClientAcknowledge, refcon, 0);
        // not a client of ours
        // so we won't be waiting for response
        context->responseFlags->replaceObject(context->counter, kOSBooleanTrue);
    }
    context->counter++;
}

//*********************************************************************************
// [public] tellNoChangeDown
//
// Notify registered applications and kernel clients that we are not
// dropping power.
//
// Subclass can override this to send a different message type.  Parameter is
// the aborted destination state number.
//*********************************************************************************

void IOService::tellNoChangeDown ( unsigned long )
{
    return tellClients( kIOMessageDeviceWillNotPowerOff );
}

//*********************************************************************************
// [public] tellChangeUp
//
// Notify registered applications and kernel clients that we are raising power.
//
// Subclass can override this to send a different message type.  Parameter is
// the aborted destination state number.
//*********************************************************************************

void IOService::tellChangeUp ( unsigned long )
{
    return tellClients( kIOMessageDeviceHasPoweredOn );
}

//*********************************************************************************
// [protected] tellClients
//
// Notify registered applications and kernel clients of something.
//*********************************************************************************

void IOService::tellClients ( int messageType )
{
    tellClients( messageType, 0 );
}

void IOService::tellClients ( int messageType, IOPMMessageFilter filter )
{
    IOPMInterestContext     context;

    context.msgType     = messageType;
    context.us          = this;
    context.stateNumber = fHeadNotePowerState;
    context.stateFlags  = fHeadNotePowerArrayEntry->capabilityFlags;
    context.filterFunc  = filter;

    applyToInterested( gIOPriorityPowerStateInterest,
        tellKernelClientApplier, (void *) &context );
    
    applyToInterested( gIOAppPowerStateInterest,
        tellAppClientApplier, (void *) &context );

    applyToInterested( gIOGeneralInterest,
        tellKernelClientApplier, (void *) &context );
}

//*********************************************************************************
// [private] tellKernelClientApplier
//
// Message a kernel client.
//*********************************************************************************

static void tellKernelClientApplier ( OSObject * object, void * arg )
{
    IOPMInterestContext *           context = (IOPMInterestContext *) arg;
    IOPowerStateChangeNotification	notify;

    if (context->filterFunc && !context->filterFunc(object, arg))
        return;

    notify.powerRef     = (void *) 0;
    notify.returnValue	= 0;
    notify.stateNumber	= context->stateNumber;
    notify.stateFlags	= context->stateFlags;

    context->us->messageClient(context->msgType, object, &notify);
}

//*********************************************************************************
// [private] tellAppClientApplier
//
// Message a registered application.
//*********************************************************************************

static void tellAppClientApplier ( OSObject * object, void * arg )
{
    IOPMInterestContext *   context = (IOPMInterestContext *) arg;

    if (context->filterFunc && !context->filterFunc(object, arg))
        return;

    context->us->messageClient(context->msgType, object, 0);
}

//*********************************************************************************
// [private] checkForDone
//*********************************************************************************

bool IOService::checkForDone ( void )
{
    int			i = 0;
    OSObject *	theFlag;

    if ( fResponseArray == NULL )
    {
        return true;
    }
    
    for ( i = 0; ; i++ )
    {
        theFlag = fResponseArray->getObject(i);
        if ( theFlag == NULL )
        {
            break;
        }
        if ( kOSBooleanTrue != theFlag ) 
        {
            return false;
        }
    }
    return true;
}

//*********************************************************************************
// [public] responseValid
//*********************************************************************************

bool IOService::responseValid ( unsigned long x, int pid )
{
    UInt16			serialComponent;
    UInt16			ordinalComponent;
    OSObject *		theFlag;
    unsigned long	refcon = (unsigned long) x;

    serialComponent  = (refcon >> 16) & 0xFFFF;
    ordinalComponent = (refcon & 0xFFFF);

    if ( serialComponent != fSerialNumber )
    {
        return false;
    }
    
    if ( fResponseArray == NULL )
    {
        return false;
    }
    
    theFlag = fResponseArray->getObject(ordinalComponent);
    
    if ( theFlag == 0 )
    {
        return false;
    }

    OSNumber * num;
    if ((num = OSDynamicCast(OSNumber, theFlag)))
    {
#if LOG_APP_RESPONSE_TIMES
        AbsoluteTime	now;
        AbsoluteTime	start;
        uint64_t	nsec;

        clock_get_uptime(&now);
        AbsoluteTime_to_scalar(&start) = num->unsigned64BitValue();
        SUB_ABSOLUTETIME(&now, &start);
        absolutetime_to_nanoseconds(now, &nsec);

        // > 100 ms
        if (nsec > LOG_APP_RESPONSE_TIMES)
        {
            OSString * name = IOCopyLogNameForPID(pid);
            PM_DEBUG("PM response took %d ms (%s)\n", NS_TO_MS(nsec),
                name ? name->getCStringNoCopy() : "");

            if (nsec > LOG_APP_RESPONSE_MSG_TRACER)
            {
                // TODO: populate the messageType argument            
                getPMRootDomain()->pmStatsRecordApplicationResponse(
                    gIOPMStatsApplicationResponseSlow, 
                    name ? name->getCStringNoCopy() : "", 0,
                    NS_TO_MS(nsec), pid);
            }
            
            if (name)
            name->release();
        }
#endif
        theFlag = kOSBooleanFalse;
    }

    if ( kOSBooleanFalse == theFlag ) 
    {
        if ((gIOKitDebug & kIOLogDebugPower) &&
            (fOutOfBandParameter == kNotifyApps))
        {
            PM_DEBUG("[Notify %u] acked\n", (uint32_t) ordinalComponent);
        }
        fResponseArray->replaceObject(ordinalComponent, kOSBooleanTrue);
    }
    
    return true;
}

//*********************************************************************************
// [public] allowPowerChange
//
// Our power state is about to lower, and we have notified applications
// and kernel clients, and one of them has acknowledged.  If this is the last to do
// so, and all acknowledgements are positive, we continue with the power change.
//
// We serialize this processing with timer expiration with a command gate on the
// power management workloop, which the timer expiration is command gated to as well.
//*********************************************************************************

IOReturn IOService::allowPowerChange ( unsigned long refcon )
{
	IOPMRequest * request;

    if ( !initialized )
    {
        // we're unloading
        return kIOReturnSuccess;
    }

	request = acquirePMRequest( this, kIOPMRequestTypeAllowPowerChange );
	if (!request)
		return kIOReturnNoMemory;

	request->fArg0 = (void *) refcon;
	request->fArg1 = (void *) proc_selfpid();
    request->fArg2 = (void *) 0;
	submitPMRequest( request );

	return kIOReturnSuccess;
}

#ifndef __LP64__
IOReturn IOService::serializedAllowPowerChange2 ( unsigned long refcon )
{
	// [deprecated] public
	return kIOReturnUnsupported;
}
#endif /* !__LP64__ */

//*********************************************************************************
// [public] cancelPowerChange
//
// Our power state is about to lower, and we have notified applications
// and kernel clients, and one of them has vetoed the change.  If this is the last
// client to respond, we abandon the power change.
//
// We serialize this processing with timer expiration with a command gate on the
// power management workloop, which the timer expiration is command gated to as well.
//*********************************************************************************

IOReturn IOService::cancelPowerChange ( unsigned long refcon )
{
	IOPMRequest *   request;
    OSString *      name;

    if ( !initialized )
    {
        // we're unloading
        return kIOReturnSuccess;
    }

    name = IOCopyLogNameForPID(proc_selfpid());
    PM_ERROR("PM notification cancel (%s)\n", name ? name->getCStringNoCopy() : "");

	request = acquirePMRequest( this, kIOPMRequestTypeCancelPowerChange );
	if (!request)
    {
        if (name)
            name->release();
        return kIOReturnNoMemory;
    }

    request->fArg0 = (void *) refcon;
    request->fArg1 = (void *) proc_selfpid();
    request->fArg2 = (void *) name;
    submitPMRequest( request );

    return kIOReturnSuccess;
}

#ifndef __LP64__
IOReturn IOService::serializedCancelPowerChange2 ( unsigned long refcon )
{
	// [deprecated] public
	return kIOReturnUnsupported;
}

//*********************************************************************************
// PM_Clamp_Timer_Expired
//
// called when clamp timer expires...set power state to 0.
//*********************************************************************************

void IOService::PM_Clamp_Timer_Expired ( void )
{
}

//*********************************************************************************
// clampPowerOn
//
// Set to highest available power state for a minimum of duration milliseconds
//*********************************************************************************

void IOService::clampPowerOn ( unsigned long duration )
{
}
#endif /* !__LP64__ */

//*********************************************************************************
// [public] setPowerState
//
// Does nothing here.  This should be implemented in a subclass driver.
//*********************************************************************************

IOReturn IOService::setPowerState (
	unsigned long powerStateOrdinal, IOService * whatDevice )
{
    return IOPMNoErr;
}

//*********************************************************************************
// [public] maxCapabilityForDomainState
//
// Finds the highest power state in the array whose input power
// requirement is equal to the input parameter.  Where a more intelligent
// decision is possible, override this in the subclassed driver.
//*********************************************************************************

unsigned long IOService::maxCapabilityForDomainState ( IOPMPowerFlags domainState )
{
   int i;

   if (fNumberOfPowerStates == 0 )
   {
       return 0;
   }
   for ( i = fNumberOfPowerStates - 1; i >= 0; i-- )
   {
       if ( (domainState & fPowerStates[i].inputPowerRequirement) ==
			               fPowerStates[i].inputPowerRequirement )
       {
           return i;
       }
   }
   return 0;
}

//*********************************************************************************
// [public] initialPowerStateForDomainState
//
// Finds the highest power state in the array whose input power
// requirement is equal to the input parameter.  Where a more intelligent
// decision is possible, override this in the subclassed driver.
//*********************************************************************************

unsigned long IOService::initialPowerStateForDomainState ( IOPMPowerFlags domainState )
{
    int i;

    if (fNumberOfPowerStates == 0 )
    {
        return 0;
    }
    for ( i = fNumberOfPowerStates - 1; i >= 0; i-- )
    {
        if ( (domainState & fPowerStates[i].inputPowerRequirement) ==
			fPowerStates[i].inputPowerRequirement )
        {
            return i;
        }
    }
    return 0;
}

//*********************************************************************************
// [public] powerStateForDomainState
//
// Finds the highest power state in the array whose input power
// requirement is equal to the input parameter.  Where a more intelligent
// decision is possible, override this in the subclassed driver.
//*********************************************************************************

unsigned long IOService::powerStateForDomainState ( IOPMPowerFlags domainState )
{
    int i;

    if (fNumberOfPowerStates == 0 )
    {
        return 0;
    }
    for ( i = fNumberOfPowerStates - 1; i >= 0; i-- )
    {
        if ( (domainState & fPowerStates[i].inputPowerRequirement) ==
			fPowerStates[i].inputPowerRequirement )
        {
            return i;
        }
    }
    return 0;
}

#ifndef __LP64__
//*********************************************************************************
// [deprecated] didYouWakeSystem
//
// Does nothing here.  This should be implemented in a subclass driver.
//*********************************************************************************

bool IOService::didYouWakeSystem ( void )
{
    return false;
}
#endif /* !__LP64__ */

//*********************************************************************************
// [public] powerStateWillChangeTo
//
// Does nothing here.  This should be implemented in a subclass driver.
//*********************************************************************************

IOReturn IOService::powerStateWillChangeTo ( IOPMPowerFlags, unsigned long, IOService * )
{
    return kIOPMAckImplied;
}

//*********************************************************************************
// [public] powerStateDidChangeTo
//
// Does nothing here.  This should be implemented in a subclass driver.
//*********************************************************************************

IOReturn IOService::powerStateDidChangeTo ( IOPMPowerFlags, unsigned long, IOService * )
{
    return kIOPMAckImplied;
}

//*********************************************************************************
// [protected] powerChangeDone
//
// Called from PM work loop thread.
// Does nothing here.  This should be implemented in a subclass policy-maker.
//*********************************************************************************

void IOService::powerChangeDone ( unsigned long )
{
}

#ifndef __LP64__
//*********************************************************************************
// [deprecated] newTemperature
//
// Does nothing here.  This should be implemented in a subclass driver.
//*********************************************************************************

IOReturn IOService::newTemperature ( long currentTemp, IOService * whichZone )
{
    return IOPMNoErr;
}
#endif /* !__LP64__ */

//*********************************************************************************
// [public] systemWillShutdown
//
// System shutdown and restart notification.
//*********************************************************************************

void IOService::systemWillShutdown( IOOptionBits specifier )
{
	IOPMrootDomain * rootDomain = IOService::getPMRootDomain();
	if (rootDomain)
		rootDomain->acknowledgeSystemWillShutdown( this );
}

//*********************************************************************************
// [private static] acquirePMRequest
//*********************************************************************************

IOPMRequest *
IOService::acquirePMRequest( IOService * target, IOOptionBits requestType,
                             IOPMRequest * active )
{
	IOPMRequest * request;

	assert(target);

	request = IOPMRequest::create();
	if (request)
	{
		request->init( target, requestType );
        if (active)
        {
            IOPMRequest * root = active->getRootRequest();
            if (root) request->attachRootRequest(root);
        }
    }
	else
	{
        PM_ERROR("%s: No memory for PM request type 0x%x\n",
            target->getName(), (uint32_t) requestType);
	}
	return request;
}

//*********************************************************************************
// [private static] releasePMRequest
//*********************************************************************************

void IOService::releasePMRequest( IOPMRequest * request )
{
	if (request)
	{
		request->reset();
		request->release();
	}
}

//*********************************************************************************
// [private] submitPMRequest
//*********************************************************************************

void IOService::submitPMRequest( IOPMRequest * request )
{
	assert( request );
	assert( gIOPMReplyQueue );
	assert( gIOPMRequestQueue );

	PM_TRACE("[+ %02lx] %p [%p %s] %p %p %p\n",
		(long)request->getType(), request,
		request->getTarget(), request->getTarget()->getName(),
		request->fArg0, request->fArg1, request->fArg2);

	if (request->isReplyType())
		gIOPMReplyQueue->queuePMRequest( request );
	else
		gIOPMRequestQueue->queuePMRequest( request );
}

void IOService::submitPMRequest( IOPMRequest ** requests, IOItemCount count )
{
	assert( requests );
	assert( count > 0 );
	assert( gIOPMRequestQueue );

	for (IOItemCount i = 0; i < count; i++)
	{
		IOPMRequest * req = requests[i];
		PM_TRACE("[+ %02lx] %p [%p %s] %p %p %p\n",
			(long)req->getType(), req,
			req->getTarget(), req->getTarget()->getName(),
			req->fArg0, req->fArg1, req->fArg2);
	}

	gIOPMRequestQueue->queuePMRequestChain( requests, count );
}

//*********************************************************************************
// [private] servicePMRequestQueue
//*********************************************************************************

bool IOService::servicePMRequestQueue(
	IOPMRequest *		request,
	IOPMRequestQueue *	queue )
{
	// Calling PM methods without PMinit() is not allowed, fail the requests.

	if (!initialized)
	{
		PM_DEBUG("%s: PM not initialized\n", getName());
        goto done;
	}

	// Create an IOPMWorkQueue on demand, when the initial PM request is
	// received.

	if (!fPMWorkQueue)
	{
		// Allocate and attach an IOPMWorkQueue on demand to avoid taking
		// the work loop lock in PMinit(), which may deadlock with certain
		// drivers / families.

		fPMWorkQueue = IOPMWorkQueue::create(
			/* target */	this,
			/* Work */		OSMemberFunctionCast(IOPMWorkQueue::Action, this,
								&IOService::servicePMRequest),
			/* Done */		OSMemberFunctionCast(IOPMWorkQueue::Action, this,
								&IOService::retirePMRequest)
			);

		if (fPMWorkQueue &&
			(gIOPMWorkLoop->addEventSource(fPMWorkQueue) != kIOReturnSuccess))
		{
			PM_ERROR("%s: add PM work queue failed\n", getName());
			fPMWorkQueue->release();
			fPMWorkQueue = 0;
		}

		if (!fPMWorkQueue)
		{
			PM_ERROR("%s: no PM work queue (type %02lx)\n",
				getName(), (long)request->getType());
			goto done;
		}
	}

	fPMWorkQueue->queuePMRequest(request);
	return false;	// do not signal more

done:
	fAdjustPowerScheduled = false;
	gIOPMFreeQueue->queuePMRequest(request);
	return false;	// do not signal more
}

//*********************************************************************************
// [private] servicePMFreeQueue
//
// Called by the request completion to recycle a completed request.
//*********************************************************************************

bool IOService::servicePMFreeQueue(
	IOPMRequest *		  request,
	IOPMCompletionQueue * queue )
{
	bool            more = request->getNextRequest();
    IOPMRequest *   root = request->getRootRequest();

    if (root && (root != request))
        more = true;

	releasePMRequest( request );
	return more;
}

//*********************************************************************************
// [private] retirePMRequest
//
// Called by IOPMWorkQueue to retire a completed request.
//*********************************************************************************

bool IOService::retirePMRequest( IOPMRequest * request, IOPMWorkQueue * queue )
{
	assert(request && queue);

	PM_TRACE("[- %02x] %p [%p %s] State %d, Busy %d\n",
		request->getType(), request, this, getName(),
		fMachineState, gIOPMBusyCount);

	// Catch requests created by idleTimerExpired().

	if ((request->getType() == kIOPMRequestTypeActivityTickle) &&
		(request->fArg1 == (void *) false))
	{
		// Idle timer power drop request completed.
		// Restart the idle timer if deviceDesire can go lower, otherwise set
		// a flag so we know to restart idle timer when deviceDesire goes up.

		if (fDeviceDesire > 0)
		{
            fActivityTickleCount = 0;
			clock_get_uptime(&fIdleTimerStartTime);
			start_PM_idle_timer();
		}
		else
			fIdleTimerStopped = true;
	}

	gIOPMFreeQueue->queuePMRequest( request );
	return true;
}

//*********************************************************************************
// [private] isPMBlocked
//
// Check if machine state transition is blocked.
//*********************************************************************************

bool IOService::isPMBlocked ( IOPMRequest * request, int count )
{
	int	reason = 0;

	do {
		if (kIOPM_Finished == fMachineState)
			break;

		if (kIOPM_DriverThreadCallDone == fMachineState)
		{
            // 5 = kDriverCallInformPreChange
            // 6 = kDriverCallInformPostChange
            // 7 = kDriverCallSetPowerState
			if (fLockedFlags.DriverCallBusy) reason = 5 + fDriverCallReason;
			break;
		}

		// Waiting on driver's setPowerState() timeout.
		if (fDriverTimer)
		{
			reason = 1; break;
		}

		// Child or interested driver acks pending.
		if (fHeadNotePendingAcks)
		{
			reason = 2; break;
		}

		// Waiting on apps or priority power interest clients.
		if (fResponseArray)
		{
			reason = 3; break;
		}

		// Waiting on settle timer expiration.
		if (fSettleTimeUS)
		{
			reason = 4; break;
		}
	} while (false);

	fWaitReason = reason;

	if (reason)
	{
		if (count)
		{
			PM_TRACE("[B %02x] %p [%p %s] State %d, Reason %d\n",
				request->getType(), request, this, getName(),
				fMachineState, reason);
		}

		return true;
	}

	return false;
}

//*********************************************************************************
// [private] servicePMRequest
//
// Service a request from our work queue.
//*********************************************************************************

bool IOService::servicePMRequest( IOPMRequest * request, IOPMWorkQueue * queue )
{
	bool	done = false;
	int		loop = 0;

	assert(request && queue);

	while (isPMBlocked(request, loop++) == false)
	{
		PM_TRACE("[W %02x] %p [%p %s] State %d\n",
			request->getType(), request, this, getName(), fMachineState);

		gIOPMRequest = request;

		// Every PM machine states must be handled in one of the cases below.

		switch ( fMachineState )
		{
			case kIOPM_Finished:
				executePMRequest( request );
				break;

			case kIOPM_OurChangeTellClientsPowerDown:
				// our change, was it vetoed?
				if (!fDoNotPowerDown)
				{
					// no, we can continue
					OurChangeTellClientsPowerDown();
				}
				else
				{
					OUR_PMLog(kPMLogIdleCancel, (uintptr_t) this, fMachineState);
					PM_ERROR("%s: idle cancel\n", fName);
					// yes, rescind the warning
					tellNoChangeDown(fHeadNotePowerState);
					// mark the change note un-actioned
					fHeadNoteFlags |= kIOPMNotDone;
					// and we're done
					all_done();
				}
				break;

			case kIOPM_OurChangeTellPriorityClientsPowerDown:
				// our change, should it be acted on still?
				if (fDoNotPowerDown)
				{
					OUR_PMLog(kPMLogIdleCancel, (uintptr_t) this, fMachineState);
					PM_ERROR("%s: idle revert\n", fName);
					// no, tell clients we're back in the old state
					tellChangeUp(fCurrentPowerState);
					// mark the change note un-actioned
					fHeadNoteFlags |= kIOPMNotDone;
					// and we're done
					all_done();
				}
				else
				{
					// yes, we can continue
					OurChangeTellPriorityClientsPowerDown();  
				}
				break;

			case kIOPM_OurChangeNotifyInterestedDriversWillChange:
				OurChangeNotifyInterestedDriversWillChange();
				break;

			case kIOPM_OurChangeSetPowerState:
				OurChangeSetPowerState();
				break;

			case kIOPM_OurChangeWaitForPowerSettle:
				OurChangeWaitForPowerSettle();
				break;

			case kIOPM_OurChangeNotifyInterestedDriversDidChange:
				OurChangeNotifyInterestedDriversDidChange();
				break;

			case kIOPM_OurChangeFinish:
				OurChangeFinish();
				break;

			case kIOPM_ParentDownTellPriorityClientsPowerDown:
				ParentDownTellPriorityClientsPowerDown();
				break;

			case kIOPM_ParentDownNotifyInterestedDriversWillChange:
				ParentDownNotifyInterestedDriversWillChange();
				break;

			case kIOPM_ParentDownNotifyDidChangeAndAcknowledgeChange:
				ParentDownNotifyDidChangeAndAcknowledgeChange();
				break;

			case kIOPM_ParentDownSetPowerState:
				ParentDownSetPowerState();	
				break;

			case kIOPM_ParentDownWaitForPowerSettle:
				ParentDownWaitForPowerSettle();
				break;

			case kIOPM_ParentAcknowledgePowerChange:
				ParentAcknowledgePowerChange();
				break;

			case kIOPM_ParentUpSetPowerState:
				ParentUpSetPowerState();
				break;

			case kIOPM_ParentUpWaitForSettleTime:
				ParentUpWaitForSettleTime();
				break;

			case kIOPM_ParentUpNotifyInterestedDriversDidChange:
				ParentUpNotifyInterestedDriversDidChange();
				break;

			case kIOPM_DriverThreadCallDone:
				if (fDriverCallReason == kDriverCallSetPowerState)
					notifyControllingDriverDone();
				else
					notifyInterestedDriversDone();
				break;

			case kIOPM_NotifyChildrenDone:
				notifyChildrenDone();
				break;

            case kIOPM_SyncNotifyDidChange:
                fMachineState     = kIOPM_SyncFinish;
                fDriverCallReason = kDriverCallInformPostChange;
                notifyChildren();
                break;

            case kIOPM_SyncFinish:
                if (fHeadNoteFlags & kIOPMParentInitiated)
                    ParentAcknowledgePowerChange();
                else
                    OurChangeFinish();
                break;

			default:
				panic("servicePMWorkQueue: unknown machine state %x",
                    fMachineState);
		}

		gIOPMRequest = 0;

		if (fMachineState == kIOPM_Finished)
		{
			//PM_TRACE("[%s] PM   End: Request %p (type %02lx)\n",
			//	getName(), request, request->getType());
			done = true;
			break;
		}
	}

	return done;
}

//*********************************************************************************
// [private] executePMRequest
//*********************************************************************************

void IOService::executePMRequest( IOPMRequest * request )
{
	assert( kIOPM_Finished == fMachineState );

	switch (request->getType())
	{
		case kIOPMRequestTypePMStop:
			handlePMstop( request );
			break;

		case kIOPMRequestTypeAddPowerChild1:
			addPowerChild1( request );
			break;

		case kIOPMRequestTypeAddPowerChild2:
			addPowerChild2( request );
			break;

		case kIOPMRequestTypeAddPowerChild3:
			addPowerChild3( request );
			break;

		case kIOPMRequestTypeRegisterPowerDriver:
			handleRegisterPowerDriver( request );
			break;

		case kIOPMRequestTypeAdjustPowerState:
			fAdjustPowerScheduled = false;
			rebuildChildClampBits();
			adjustPowerState();
			break;

		case kIOPMRequestTypePowerDomainWillChange:
			handlePowerDomainWillChangeTo( request );
			break;

		case kIOPMRequestTypePowerDomainDidChange:
			handlePowerDomainDidChangeTo( request );
			break;

		case kIOPMRequestTypeRequestPowerState:
        case kIOPMRequestTypeRequestPowerStateOverride:
			handleRequestPowerState( request );
			break;

		case kIOPMRequestTypePowerOverrideOnPriv:
		case kIOPMRequestTypePowerOverrideOffPriv:
			handlePowerOverrideChanged( request );
			break;

		case kIOPMRequestTypeActivityTickle:
			handleActivityTickle( request );
			break;

        case kIOPMRequestTypeSynchronizePowerTree:
			handleSynchronizePowerTree( request );
			break;

        case kIOPMRequestTypeSetIdleTimerPeriod:
            {
                IOWorkLoop * wl  = gIOPMWorkLoop;
                fIdleTimerPeriod = (uintptr_t) request->fArg0;

                if (wl && (false == fLockedFlags.PMStop) && (fIdleTimerPeriod > 0))
                {
                    if ( NULL == fIdleTimerEventSource )
                    {
                        IOTimerEventSource * timerSrc;

                        timerSrc = IOTimerEventSource::timerEventSource(
                            this,
                            OSMemberFunctionCast(IOTimerEventSource::Action,
                                this, &IOService::idleTimerExpired));
                        
                        if (timerSrc && (wl->addEventSource(timerSrc) != kIOReturnSuccess))
                        {
                            timerSrc->release();
                            timerSrc = 0;
                        }

                        fIdleTimerEventSource = timerSrc;
                    }

                    fActivityTickleCount = 0;
                    clock_get_uptime(&fIdleTimerStartTime);
                    start_PM_idle_timer();
                }
            }
            break;

		default:
			panic("executePMRequest: unknown request type %x", request->getType());
	}
}

//*********************************************************************************
// [private] servicePMReplyQueue
//*********************************************************************************

bool IOService::servicePMReplyQueue( IOPMRequest * request, IOPMRequestQueue * queue )
{
	bool more = false;

	assert( request && queue );
	assert( request->isReplyType() );

	PM_TRACE("[A %02x] %p [%p %s] State %d\n",
		request->getType(), request, this, getName(), fMachineState);

	switch ( request->getType() )
	{
		case kIOPMRequestTypeAllowPowerChange:
		case kIOPMRequestTypeCancelPowerChange:
			// Check if we are expecting this response.
			if (responseValid((unsigned long) request->fArg0, (int)(long) request->fArg1))
			{
				if (kIOPMRequestTypeCancelPowerChange == request->getType())
                {
                    OSString * name = (OSString *) request->fArg2;
                    getPMRootDomain()->pmStatsRecordApplicationResponse(
                        gIOPMStatsApplicationResponseCancel,
                        name ? name->getCStringNoCopy() : "", 0,
                        0, (int)(uintptr_t) request->fArg1);

					fDoNotPowerDown = true;
                }

				if (checkForDone())
				{
					stop_ack_timer();
					if ( fResponseArray )
					{
						fResponseArray->release();
						fResponseArray = NULL;
					}
                    if ( fNotifyClientArray )
                    {
                        fNotifyClientArray->release();
                        fNotifyClientArray = NULL;
                    }
					more = true;
				}
			}
            // OSString containing app name in Arg2 must be released.
            if (request->getType() == kIOPMRequestTypeCancelPowerChange)
            {
                OSObject * obj = (OSObject *) request->fArg2;
                if (obj) obj->release();
            }
			break;

		case kIOPMRequestTypeAckPowerChange:
			more = handleAcknowledgePowerChange( request );
			break;

		case kIOPMRequestTypeAckSetPowerState:
			if (fDriverTimer == -1)
			{
				// driver acked while setPowerState() call is in-flight.
				// take this ack, return value from setPowerState() is irrelevant.
				OUR_PMLog(kPMLogDriverAcknowledgeSet,
					(uintptr_t) this, fDriverTimer);
				fDriverTimer = 0;
			}
			else if (fDriverTimer > 0)
			{
				// expected ack, stop the timer
				stop_ack_timer();

#if LOG_SETPOWER_TIMES
                uint64_t nsec = computeTimeDeltaNS(&fDriverCallStartTime);
                if (nsec > LOG_SETPOWER_TIMES)
                    PM_DEBUG("%s::setPowerState(%p, %lu -> %lu) async took %d ms\n",
                        fName, this, fCurrentPowerState, fHeadNotePowerState, NS_TO_MS(nsec));
#endif
				OUR_PMLog(kPMLogDriverAcknowledgeSet, (uintptr_t) this, fDriverTimer);
				fDriverTimer = 0;
				more = true;
			}
			else
			{
				// unexpected ack
				OUR_PMLog(kPMLogAcknowledgeErr4, (uintptr_t) this, 0);
			}
			break;

		case kIOPMRequestTypeInterestChanged:
			handleInterestChanged( request );
			more = true;
			break;

		case kIOPMRequestTypeIdleCancel:
			if ((fMachineState == kIOPM_OurChangeTellClientsPowerDown) 
			 || (fMachineState == kIOPM_OurChangeTellPriorityClientsPowerDown))
			{
				OUR_PMLog(kPMLogIdleCancel, (uintptr_t) this, 0);
				fDoNotPowerDown = true;
				if (fMachineState == kIOPM_OurChangeTellPriorityClientsPowerDown)
					cleanClientResponses(false);
				more = true;
			}
			break;

		default:
			panic("servicePMReplyQueue: unknown reply type %x",
                request->getType());
	}

	releasePMRequest( request );
	return more;
}

//*********************************************************************************
// [private] assertPMThreadCall / deassertPMThreadCall
//*********************************************************************************

bool IOService::assertPMThreadCall( void )
{
    if (!initialized)
        return false;

    // PMfree() should only be called from IOService::free().
    // That makes it safe to touch IOServicePM state here.
    // Caller holds a retain and has checked target is on PM plane.

    PM_LOCK();
    if (fLockedFlags.PMStop)
    {
        // PMstop() already issued - fail the assertion.
        PM_UNLOCK();
        return false;
    }

    // Increment assertion count to block PMstop(), and return true.
    fThreadAssertionCount++;
    fThreadAssertionThread = current_thread();  // only 1 caller
    PM_UNLOCK();

    return true;
}

void IOService::deassertPMThreadCall( void )
{
    PM_LOCK();
    assert(fThreadAssertionCount > 0);
    if (fThreadAssertionCount)
        fThreadAssertionCount--;
    if (current_thread() == fThreadAssertionThread)
        fThreadAssertionThread = 0;
    if ((fThreadAssertionCount == 0) && fLockedFlags.PMStop)
    {
        // PMstop() is blocked waiting for assertion count to drop to zero.
        PM_LOCK_WAKEUP(&fThreadAssertionCount);
    }
    PM_UNLOCK();
}

//*********************************************************************************
// IOPMRequest Class
//
// Requests from PM clients, and also used for inter-object messaging within PM.
//*********************************************************************************

OSDefineMetaClassAndStructors( IOPMRequest, IOCommand );

IOPMRequest * IOPMRequest::create( void )
{
	IOPMRequest * me = OSTypeAlloc(IOPMRequest);
	if (me && !me->init(0, kIOPMRequestTypeInvalid))
	{
		me->release();
		me = 0;
	}
	return me;
}

bool IOPMRequest::init( IOService * target, IOOptionBits type )
{
	if (!IOCommand::init())
		return false;

	fType             = type;
	fTarget           = target;
    fCompletionStatus = kIOReturnSuccess;

	if (fTarget)
		fTarget->retain();

	return true;
}

void IOPMRequest::reset( void )
{
	assert( fWorkWaitCount == 0 );
	assert( fFreeWaitCount == 0 );

	detachNextRequest();
    detachRootRequest();

	fType = kIOPMRequestTypeInvalid;

	if (fCompletionAction)
	{
        fCompletionAction(fCompletionTarget, fCompletionParam, fCompletionStatus);
    }

	if (fTarget)
	{
		fTarget->release();
		fTarget = 0;
	}	
}

void IOPMRequest::attachNextRequest( IOPMRequest * next )
{
    if (!fRequestNext)
    {
        // Postpone the execution of the next request after
        // this request.
        fRequestNext = next;
        fRequestNext->fWorkWaitCount++;
#if LOG_REQUEST_ATTACH
        kprintf("Attached next: %p [0x%x] -> %p [0x%x, %u] %s\n",
            this, (uint32_t) fType, fRequestNext,
            (uint32_t) fRequestNext->fType,
            (uint32_t) fRequestNext->fWorkWaitCount,
            fTarget->getName());
#endif
    }
}

void IOPMRequest::detachNextRequest( void )
{
    if (fRequestNext)
    {
        assert(fRequestNext->fWorkWaitCount);
        if (fRequestNext->fWorkWaitCount)
            fRequestNext->fWorkWaitCount--;
#if LOG_REQUEST_ATTACH
        kprintf("Detached next: %p [0x%x] -> %p [0x%x, %u] %s\n",
            this, (uint32_t) fType, fRequestNext,
            (uint32_t) fRequestNext->fType,
            (uint32_t) fRequestNext->fWorkWaitCount,
            fTarget->getName());
#endif
        fRequestNext = 0;
    }
}

void IOPMRequest::attachRootRequest( IOPMRequest * root )
{
    if (!fRequestRoot)
    {
        // Delay the completion of the root request after
        // this request.
        fRequestRoot = root;
        fRequestRoot->fFreeWaitCount++;
#if LOG_REQUEST_ATTACH
        kprintf("Attached root: %p [0x%x] -> %p [0x%x, %u] %s\n",
            this, (uint32_t) fType, fRequestRoot,
            (uint32_t) fRequestRoot->fType,
            (uint32_t) fRequestRoot->fFreeWaitCount,
            fTarget->getName());
#endif
    }
}

void IOPMRequest::detachRootRequest( void )
{
    if (fRequestRoot)
    {
        assert(fRequestRoot->fFreeWaitCount);
        if (fRequestRoot->fFreeWaitCount)
            fRequestRoot->fFreeWaitCount--;
#if LOG_REQUEST_ATTACH
        kprintf("Detached root: %p [0x%x] -> %p [0x%x, %u] %s\n",
            this, (uint32_t) fType, fRequestRoot,
            (uint32_t) fRequestRoot->fType,
            (uint32_t) fRequestRoot->fFreeWaitCount,
            fTarget->getName());
#endif
        fRequestRoot = 0;
    }
}

//*********************************************************************************
// IOPMRequestQueue Class
//
// Global queues. As PM-aware drivers load and unload, their IOPMWorkQueue's are
// created and deallocated. IOPMRequestQueue are created once and never released.
//*********************************************************************************

OSDefineMetaClassAndStructors( IOPMRequestQueue, IOEventSource );

IOPMRequestQueue * IOPMRequestQueue::create( IOService * inOwner, Action inAction )
{
	IOPMRequestQueue * me = OSTypeAlloc(IOPMRequestQueue);
	if (me && !me->init(inOwner, inAction))
	{
		me->release();
		me = 0;
	}
	return me;
}

bool IOPMRequestQueue::init( IOService * inOwner, Action inAction )
{
	if (!inAction || !IOEventSource::init(inOwner, (IOEventSourceAction)inAction))
        return false;

	queue_init(&fQueue);
	fLock = IOLockAlloc();
	return (fLock != 0);
}

void IOPMRequestQueue::free( void )
{
	if (fLock)
	{
		IOLockFree(fLock);
		fLock = 0;
	}
	return IOEventSource::free();
}

void IOPMRequestQueue::queuePMRequest( IOPMRequest * request )
{
	assert(request);
	IOLockLock(fLock);
	queue_enter(&fQueue, request, IOPMRequest *, fCommandChain);
	IOLockUnlock(fLock);
	if (workLoop) signalWorkAvailable();
}

void
IOPMRequestQueue::queuePMRequestChain( IOPMRequest ** requests, IOItemCount count )
{
	IOPMRequest * next;

	assert(requests && count);
	IOLockLock(fLock);
	while (count--)
	{
		next = *requests;
		requests++;
		queue_enter(&fQueue, next, IOPMRequest *, fCommandChain);
	}
	IOLockUnlock(fLock);
	if (workLoop) signalWorkAvailable();
}

bool IOPMRequestQueue::checkForWork( void )
{
    Action			dqAction = (Action) action;
	IOPMRequest *	request;
	IOService *		target;
	bool			more = false;

	IOLockLock( fLock );

	while (!queue_empty(&fQueue))
	{
		queue_remove_first( &fQueue, request, IOPMRequest *, fCommandChain );		
		IOLockUnlock( fLock );
		target = request->getTarget();
		assert(target);
		more |= (*dqAction)( target, request, this );
		IOLockLock( fLock );
	}

	IOLockUnlock( fLock );
	return more;
}

void IOPMRequestQueue::signalWorkAvailable( void )
{
	IOEventSource::signalWorkAvailable();
}

//*********************************************************************************
// IOPMWorkQueue Class
//
// Every object in the power plane that has handled a PM request, will have an
// instance of IOPMWorkQueue allocated for it.
//*********************************************************************************

OSDefineMetaClassAndStructors( IOPMWorkQueue, IOEventSource );

IOPMWorkQueue *
IOPMWorkQueue::create( IOService * inOwner, Action work, Action retire )
{
	IOPMWorkQueue * me = OSTypeAlloc(IOPMWorkQueue);
	if (me && !me->init(inOwner, work, retire))
	{
		me->release();
		me = 0;
	}
	return me;
}

bool IOPMWorkQueue::init( IOService * inOwner, Action work, Action retire )
{
	if (!work || !retire ||
		!IOEventSource::init(inOwner, (IOEventSourceAction)0))
		return false;

	queue_init(&fWorkQueue);

	fWorkAction   = work;
	fRetireAction = retire;

	return true;
}

void IOPMWorkQueue::queuePMRequest( IOPMRequest * request )
{
	assert( request );
	assert( onThread() );

	gIOPMBusyCount++;
	queue_enter(&fWorkQueue, request, IOPMRequest *, fCommandChain);
	checkForWork();
}

bool IOPMWorkQueue::checkForWork( void )
{
	IOPMRequest *	request;
	IOService *		target = (IOService *) owner;
	bool			done;

	while (!queue_empty(&fWorkQueue))
	{
		request = (IOPMRequest *) queue_first(&fWorkQueue);
		assert(request->getTarget() == target);
		if (request->isWorkBlocked()) break;
		done = (*fWorkAction)( target, request, this );
		if (!done) break;

		assert(gIOPMBusyCount > 0);
		if (gIOPMBusyCount) gIOPMBusyCount--;
		queue_remove_first(&fWorkQueue, request, IOPMRequest *, fCommandChain);
		(*fRetireAction)( target, request, this );
	}

	return false;
}

//*********************************************************************************
// IOPMCompletionQueue Class
//*********************************************************************************

OSDefineMetaClassAndStructors( IOPMCompletionQueue, IOEventSource );

IOPMCompletionQueue * IOPMCompletionQueue::create( IOService * inOwner, Action inAction )
{
	IOPMCompletionQueue * me = OSTypeAlloc(IOPMCompletionQueue);
	if (me && !me->init(inOwner, inAction))
	{
		me->release();
		me = 0;
	}
	return me;
}

bool IOPMCompletionQueue::init( IOService * inOwner, Action inAction )
{
	if (!inAction || !IOEventSource::init(inOwner, (IOEventSourceAction)inAction))
        return false;

	queue_init(&fQueue);
	return true;
}

void IOPMCompletionQueue::queuePMRequest( IOPMRequest * request )
{
	assert(request);
    request->detachNextRequest();   // unblocks next request
	queue_enter(&fQueue, request, IOPMRequest *, fCommandChain);
	if (workLoop) signalWorkAvailable();
}

bool IOPMCompletionQueue::checkForWork( void )
{
    Action			dqAction = (Action) action;
	IOPMRequest *	request;
	IOService *		target;
	bool			more = false;
	queue_head_t	tmpQueue;

	queue_init(&tmpQueue);

	while (!queue_empty(&fQueue))
	{
		queue_remove_first( &fQueue, request, IOPMRequest *, fCommandChain );
		if (request->isFreeBlocked())
		{
			queue_enter(&tmpQueue, request, IOPMRequest *, fCommandChain);
			continue;
		}
		target = request->getTarget();
		assert(target);
		more |= (*dqAction)( target, request, this );
	}

	queue_new_head(&tmpQueue, &fQueue, IOPMRequest *, fCommandChain);
	return more;
}

OSDefineMetaClassAndStructors(IOServicePM, OSObject)

//*********************************************************************************
// serialize
//
// Serialize IOServicePM for debugging.
//*********************************************************************************

static void
setPMProperty( OSDictionary * dict, const char * key, uint64_t value )
{
    OSNumber * num = OSNumber::withNumber(value, sizeof(value) * 8);
    if (num)
    {
        dict->setObject(key, num);
        num->release();
    }
}

IOReturn IOServicePM::gatedSerialize( OSSerialize * s  )
{
	OSDictionary *	dict;
	bool			ok = false;
	int				dictSize = 4;

	if (IdleTimerPeriod)
		dictSize += 4;

    if (PowerClients)
        dict = OSDictionary::withDictionary(
            PowerClients, PowerClients->getCount() + dictSize);
    else
        dict = OSDictionary::withCapacity(dictSize);

	if (dict)
	{
        setPMProperty(dict, "CurrentPowerState", CurrentPowerState);
        if (DesiredPowerState != CurrentPowerState)
            setPMProperty(dict, "DesiredPowerState", DesiredPowerState);
        if (kIOPM_Finished != MachineState)
            setPMProperty(dict, "MachineState", MachineState);
        if (DeviceOverrides)
            dict->setObject("PowerOverrideOn", kOSBooleanTrue);

		if (IdleTimerPeriod)
		{
            AbsoluteTime    now;
            AbsoluteTime    delta;
            uint64_t        nsecs;

            clock_get_uptime(&now);

			// The idle timer period in milliseconds.
			setPMProperty(dict, "IdleTimerPeriod", IdleTimerPeriod * 1000ULL);

            // The number of activity tickles recorded since device idle
            setPMProperty(dict, "ActivityTickles", ActivityTickleCount);

            if (AbsoluteTime_to_scalar(&DeviceActiveTimestamp))
            {
                // The number of milliseconds since the last activity tickle.
                delta = now;
                SUB_ABSOLUTETIME(&delta, &DeviceActiveTimestamp);
                absolutetime_to_nanoseconds(delta, &nsecs);
                setPMProperty(dict, "TimeSinceActivityTickle", NS_TO_MS(nsecs));
            }

            if (AbsoluteTime_to_scalar(&IdleTimerStartTime))
            {
                // The number of milliseconds since the last device idle.
                delta = now;
                SUB_ABSOLUTETIME(&delta, &IdleTimerStartTime);
                absolutetime_to_nanoseconds(delta, &nsecs);
                setPMProperty(dict, "TimeSinceDeviceIdle", NS_TO_MS(nsecs));
            }
		}

		ok = dict->serialize(s);
		dict->release();
	}

	return (ok ? kIOReturnSuccess : kIOReturnNoMemory);
}

bool IOServicePM::serialize( OSSerialize * s ) const
{
    IOReturn ret = kIOReturnNotReady;

    if (gIOPMWorkLoop)
	{
		ret = gIOPMWorkLoop->runAction(
            OSMemberFunctionCast(IOWorkLoop::Action, this, &IOServicePM::gatedSerialize),
            (OSObject *) this, (void *) s);
	}

    return (kIOReturnSuccess == ret);
}

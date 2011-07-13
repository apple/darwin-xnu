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

//#undef IOASSERT
//#define IOASSERT    1

#include <IOKit/assert.h>
#include <IOKit/IOKitDebug.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMessage.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOService.h>
#include <IOKit/IOEventSource.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOCommand.h>

#include <IOKit/pwr_mgt/IOPMlog.h>
#include <IOKit/pwr_mgt/IOPMinformee.h>
#include <IOKit/pwr_mgt/IOPMinformeeList.h>
#include <IOKit/pwr_mgt/IOPowerConnection.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include <IOKit/pwr_mgt/IOPMPrivate.h>

#include <sys/proc.h>
#include <libkern/OSDebug.h>

// Required for notification instrumentation
#include "IOServicePrivate.h"
#include "IOServicePMPrivate.h"
#include "IOKitKernelInternal.h"

static void settle_timer_expired(thread_call_param_t, thread_call_param_t);
static void idle_timer_expired(thread_call_param_t, thread_call_param_t);
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

// Container class for recording system power events
OSDefineMetaClassAndStructors( PMEventDetails, OSObject );

//******************************************************************************
// Globals
//******************************************************************************

static bool                  gIOPMInitialized   = false;
static uint32_t              gIOPMBusyCount     = 0;
static uint32_t              gIOPMWorkCount     = 0;
static IOWorkLoop *          gIOPMWorkLoop      = 0;
static IOPMRequestQueue *    gIOPMRequestQueue  = 0;
static IOPMRequestQueue *    gIOPMReplyQueue    = 0;
static IOPMWorkQueue *       gIOPMWorkQueue     = 0;
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

//******************************************************************************
// Macros
//******************************************************************************

#define PM_ERROR(x...)              do { kprintf(x); IOLog(x); } while (false)
#define PM_LOG(x...)                do { kprintf(x); } while (false)

#define PM_LOG1(x...)               do {  \
                                    if (kIOLogDebugPower & gIOKitDebug) \
                                        kprintf(x); } while (false)

#define PM_LOG2(x...)               do {  \
                                    if (kIOLogDebugPower & gIOKitDebug) \
                                        kprintf(x); } while (false)

#if 0
#define PM_LOG3(x...)               do { kprintf(x); } while (false)
#else
#define PM_LOG3(x...)
#endif

#define RD_LOG(x...)                do { \
                                    if ((kIOLogPMRootDomain & gIOKitDebug) && \
                                        (getPMRootDomain() == this)) \
                                        kprintf("PMRD: " x); } while (false)

#define PM_ASSERT_IN_GATE(x)          \
do {                                  \
    assert(gIOPMWorkLoop->inGate());  \
} while(false)

#define PM_LOCK()                   IOLockLock(fPMLock)
#define PM_UNLOCK()                 IOLockUnlock(fPMLock)
#define PM_LOCK_SLEEP(event, dl)    IOLockSleepDeadline(fPMLock, event, dl, THREAD_UNINT)
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
#define NS_TO_US(nsec)              ((int)((nsec) / 1000ULL))

#if CONFIG_EMBEDDED
#define SUPPORT_IDLE_CANCEL         1
#endif

#define kIOPMPowerStateMax          0xFFFFFFFF  

#define IS_PM_ROOT                  (this == gIOPMRootNode)
#define IS_ROOT_DOMAIN              (getPMRootDomain() == this)
#define IS_POWER_DROP               (fHeadNotePowerState < fCurrentPowerState)
#define IS_POWER_RISE               (fHeadNotePowerState > fCurrentPowerState)

// log setPowerStates longer than (ns):
#define LOG_SETPOWER_TIMES          (50ULL * 1000ULL * 1000ULL)
// log app responses longer than (ns):
#define LOG_APP_RESPONSE_TIMES      (100ULL * 1000ULL * 1000ULL)
// use message tracer to log messages longer than (ns):
#define LOG_APP_RESPONSE_MSG_TRACER (3 * 1000ULL * 1000ULL * 1000ULL)

enum {
    kReserveDomainPower = 1
};

#define MS_PUSH(n)  \
    do { assert(kIOPM_BadMachineState == fSavedMachineState); \
         assert(kIOPM_BadMachineState != n); \
         fSavedMachineState = n; } while (false)

#define MS_POP()    \
    do { assert(kIOPM_BadMachineState != fSavedMachineState); \
         fMachineState = fSavedMachineState; \
         fSavedMachineState = kIOPM_BadMachineState; } while (false)

#define PM_ACTION_0(a) \
    do { if (fPMActions.a) { \
         (fPMActions.a)(fPMActions.target, this, &fPMActions); } \
         } while (false)

#define PM_ACTION_2(a, x, y) \
    do { if (fPMActions.a) { \
         (fPMActions.a)(fPMActions.target, this, &fPMActions, x, y); } \
         } while (false)

//*********************************************************************************
// PM machine states
//
// Check kgmacros after modifying machine states.
//*********************************************************************************

enum {
    kIOPM_Finished                                      = 0,

    kIOPM_OurChangeTellClientsPowerDown                 = 1,
    kIOPM_OurChangeTellPriorityClientsPowerDown         = 2,
    kIOPM_OurChangeNotifyInterestedDriversWillChange    = 3,
    kIOPM_OurChangeSetPowerState                        = 4,
    kIOPM_OurChangeWaitForPowerSettle                   = 5,
    kIOPM_OurChangeNotifyInterestedDriversDidChange     = 6,
    kIOPM_OurChangeTellCapabilityDidChange              = 7,
    kIOPM_OurChangeFinish                               = 8,

    kIOPM_ParentChangeTellPriorityClientsPowerDown      = 10,
    kIOPM_ParentChangeNotifyInterestedDriversWillChange = 11,
    kIOPM_ParentChangeSetPowerState                     = 12,
    kIOPM_ParentChangeWaitForPowerSettle                = 13,
    kIOPM_ParentChangeNotifyInterestedDriversDidChange  = 14,
    kIOPM_ParentChangeTellCapabilityDidChange           = 15,
    kIOPM_ParentChangeAcknowledgePowerChange            = 16,

    kIOPM_NotifyChildrenStart                           = 17,
    kIOPM_NotifyChildrenOrdered                         = 18,
    kIOPM_NotifyChildrenDelayed                         = 19,
    kIOPM_SyncTellClientsPowerDown                      = 20,
    kIOPM_SyncTellPriorityClientsPowerDown              = 21,
    kIOPM_SyncNotifyWillChange                          = 22,
    kIOPM_SyncNotifyDidChange                           = 23,
    kIOPM_SyncTellCapabilityDidChange                   = 24,
    kIOPM_SyncFinish                                    = 25,
    kIOPM_TellCapabilityChangeDone                      = 26,
    kIOPM_DriverThreadCallDone                          = 27,

    kIOPM_BadMachineState                               = 0xFFFFFFFF
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

                gIOPMWorkQueue = IOPMWorkQueue::create(
                    this,
                    OSMemberFunctionCast(IOPMWorkQueue::Action, this,
                        &IOService::servicePMRequest),
                    OSMemberFunctionCast(IOPMWorkQueue::Action, this,
                        &IOService::retirePMRequest));

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

                if (gIOPMWorkLoop->addEventSource(gIOPMWorkQueue) !=
                    kIOReturnSuccess)
                {
                    gIOPMWorkQueue->release();
                    gIOPMWorkQueue = 0;
                }

                if (gIOPMWorkLoop->addEventSource(gIOPMFreeQueue) !=
                    kIOReturnSuccess)
                {
                    gIOPMFreeQueue->release();
                    gIOPMFreeQueue = 0;
                }

                gIOPMPowerClientDevice =
                    OSSymbol::withCStringNoCopy( "DevicePowerState" );

                gIOPMPowerClientDriver =
                    OSSymbol::withCStringNoCopy( "DriverPowerState" );

                gIOPMPowerClientChildProxy =
                    OSSymbol::withCStringNoCopy( "ChildProxyPowerState" );

                gIOPMPowerClientChildren =
                    OSSymbol::withCStringNoCopy( "ChildrenPowerState" );
            }

            if (gIOPMRequestQueue && gIOPMReplyQueue && gIOPMFreeQueue)
                gIOPMInitialized = true;
        }
        if (!gIOPMInitialized)
            return;

        pwrMgt = new IOServicePM;
        pwrMgt->init();
        setProperty(kPwrMgtKey, pwrMgt);

        queue_init(&pwrMgt->WorkChain);
        queue_init(&pwrMgt->RequestHead);
        queue_init(&pwrMgt->PMDriverCallQueue);

        fOwner                      = this;
        fPMLock                     = IOLockAlloc();
        fInterestedDrivers          = new IOPMinformeeList;
        fInterestedDrivers->initialize();
        fDesiredPowerState          = 0;
        fDeviceDesire               = 0;
        fInitialPowerChange         = true;
        fInitialSetPowerState       = true;
        fPreviousRequestPowerFlags  = 0;
        fDeviceOverrideEnabled      = false;
        fMachineState               = kIOPM_Finished;
        fSavedMachineState          = kIOPM_BadMachineState;
        fIdleTimerMinPowerState     = 0;
        fActivityLock               = IOLockAlloc();
        fStrictTreeOrder            = false;
        fActivityTicklePowerState   = -1;
        fControllingDriver          = NULL;
        fPowerStates                = NULL;
        fNumberOfPowerStates        = 0;
        fCurrentPowerState          = 0;
        fParentsCurrentPowerFlags   = 0;
        fMaxPowerState              = 0;
        fName                       = getName();
        fParentsKnowState           = false;
        fSerialNumber               = 0;
        fResponseArray              = NULL;
        fNotifyClientArray          = NULL;
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
        fIdleTimer = thread_call_allocate(
            &idle_timer_expired, (thread_call_param_t)this);
        fDriverCallEntry = thread_call_allocate(
			(thread_call_func_t) &IOService::pmDriverCallout, this);
        assert(fDriverCallEntry);

        // Check for powerChangeDone override.
        if (OSMemberFunctionCast(void (*)(void),
				getResourceService(), &IOService::powerChangeDone) !=
			  OSMemberFunctionCast(void (*)(void),
				this, &IOService::powerChangeDone))
        {
            fPCDFunctionOverride = true;
        }

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
        pm_vars = (void *) (uintptr_t) true;
#endif

        initialized = true;
    }
}

//*********************************************************************************
// [private] PMfree
//
// Free the data created by PMinit. Only called from IOService::free().
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
        assert(queue_empty(&pwrMgt->RequestHead));
        assert(queue_empty(&fPMDriverCallQueue));

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
        if ( fIdleTimer ) {
            thread_call_cancel(fIdleTimer);
            thread_call_free(fIdleTimer);
            fIdleTimer = NULL;
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
            IODelete(fPowerStates, IOPMPSEntry, fNumberOfPowerStates);
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

    PM_LOCK();

    if (fLockedFlags.PMStop)
    {
        PM_LOG2("%s: PMstop() already stopped\n", fName);
        PM_UNLOCK();
        return;
    }

    // Inhibit future driver calls.
    fLockedFlags.PMStop = true;

    // Wait for all prior driver calls to finish.
    waitForPMDriverCall();

    PM_UNLOCK();

    // The rest of the work is performed async.
    request = acquirePMRequest( this, kIOPMRequestTypePMStop );
    if (request)
    {
        PM_LOG2("%s: %p PMstop\n", getName(), this);
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
    OSIterator *        iter;
    OSObject *			next;
    IOPowerConnection *	connection;
    IOService *			theChild;
    IOService *			theParent;

	PM_ASSERT_IN_GATE();
	PM_LOG2("%s: %p %s start\n", getName(), this, __FUNCTION__);

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
    if (fIdleTimer && thread_call_cancel(fIdleTimer))
        release();

    PM_LOG2("%s: %p %s done\n", getName(), this, __FUNCTION__);
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
			PM_LOG("%s: %s (%p) is already a child\n",
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

	if (tempDesire && (IS_PM_ROOT || (fMaxPowerState >= tempDesire)))
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
		PM_LOG("%s: addPowerChild2 not in power plane\n", getName());
		return;
	}

	// Parent will be waiting for us to complete this stage.
	// It is safe to directly access parent's vars.

	knowsState = (parent->fPowerStates) && (parent->fParentsKnowState);
	powerState = parent->fCurrentPowerState;

	if (knowsState)
		powerFlags = parent->fPowerStates[powerState].outputPowerFlags;
	else
		powerFlags = 0;

	// Set our power parent.

    OUR_PMLog(kPMLogSetParent, knowsState, powerFlags);

	setParentInfo( powerFlags, connection, knowsState );

	connection->setReadyFlag(true);

    if ( fControllingDriver && fParentsKnowState )
    {
        fMaxPowerState = fControllingDriver->maxCapabilityForDomainState(fParentsCurrentPowerFlags);
        // initially change into the state we are already in
        tempDesire = fControllingDriver->initialPowerStateForDomainState(fParentsCurrentPowerFlags);
        fPreviousRequestPowerFlags = (IOPMPowerFlags)(-1);
        adjustPowerState(tempDesire);
    }

    getPMRootDomain()->tagPowerPlaneService(this, &fPMActions);
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
			PM_LOG1("%s: strict PM order enforced\n", getName());
			fStrictTreeOrder = true;
		}

        if (rootDomain)
            rootDomain->joinAggressiveness( child );
	}
	else
	{
		PM_LOG("%s: addPowerChild3 not in power plane\n", getName());
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

				// Request unblocked, work queue
				// should re-scan all busy requests.
				gIOPMWorkQueue->incrementProducerCount();
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
	IOPMRequest *   request;
	IOPMPSEntry *   powerStatesCopy = 0;

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
		powerStatesCopy = IONew(IOPMPSEntry, numberOfStates);
		if (!powerStatesCopy)
			break;

        for (uint32_t i = 0; i < numberOfStates; i++)
        {
            powerStatesCopy[i].capabilityFlags  = powerStates[i].capabilityFlags;
            powerStatesCopy[i].outputPowerFlags = powerStates[i].outputPowerCharacter;
            powerStatesCopy[i].inputPowerFlags  = powerStates[i].inputPowerRequirement;
            powerStatesCopy[i].staticPower      = powerStates[i].staticPower;
            powerStatesCopy[i].settleUpTime     = powerStates[i].settleUpTime;
            powerStatesCopy[i].settleDownTime   = powerStates[i].settleDownTime;
        }

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
		IODelete(powerStatesCopy, IOPMPSEntry, numberOfStates);
	return kIOReturnNoMemory;
}

//*********************************************************************************
// [private] handleRegisterPowerDriver
//*********************************************************************************

void IOService::handleRegisterPowerDriver ( IOPMRequest * request )
{
	IOService *     powerDriver    = (IOService *)   request->fArg0;
	IOPMPSEntry *   powerStates    = (IOPMPSEntry *) request->fArg1;
	unsigned long   numberOfStates = (unsigned long) request->fArg2;
    unsigned long   i;
	IOService *     root;
	OSIterator *    iter;

	PM_ASSERT_IN_GATE();
	assert(powerStates);
	assert(powerDriver);
	assert(numberOfStates > 1);

    if ( !fNumberOfPowerStates )
    {
		OUR_PMLog(kPMLogControllingDriver,
			(unsigned long) numberOfStates,
			(unsigned long) kIOPMPowerStateVersion1);

        fPowerStates            = powerStates;
		fNumberOfPowerStates    = numberOfStates;
		fControllingDriver      = powerDriver;
        fCurrentCapabilityFlags = fPowerStates[0].capabilityFlags;

		// make a mask of all the character bits we know about
		fOutputPowerCharacterFlags = 0;
		for ( i = 0; i < numberOfStates; i++ ) {
			fOutputPowerCharacterFlags |= fPowerStates[i].outputPowerFlags;
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
			fMaxPowerState = fControllingDriver->maxCapabilityForDomainState(fParentsCurrentPowerFlags);
			// initially change into the state we are already in
			tempDesire = fControllingDriver->initialPowerStateForDomainState(fParentsCurrentPowerFlags);
			adjustPowerState(tempDesire);
		}
	}
	else
	{
		OUR_PMLog(kPMLogControllingDriverErr2, numberOfStates, 0);
        IODelete(powerStates, IOPMPSEntry, numberOfStates);
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

    if (!driver || !initialized || !fInterestedDrivers)
        return 0;

    PM_LOCK();
    signal = (!fInsertInterestSet && !fRemoveInterestSet);
    if (fInsertInterestSet == NULL)
        fInsertInterestSet = OSSet::withCapacity(4);
    if (fInsertInterestSet)
    {
        fInsertInterestSet->setObject(driver);
        if (fRemoveInterestSet)
            fRemoveInterestSet->removeObject(driver);
    }
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
    IOPMRequest *       request;
    bool                signal;

    if (!driver)
        return kIOReturnBadArgument;
    if (!initialized || !fInterestedDrivers)
        return IOPMNotPowerManaged;

    PM_LOCK();
    signal = (!fRemoveInterestSet && !fInsertInterestSet);
    if (fRemoveInterestSet == NULL)
        fRemoveInterestSet = OSSet::withCapacity(4);
    if (fRemoveInterestSet)
    {
        fRemoveInterestSet->setObject(driver);
        if (fInsertInterestSet)
            fInsertInterestSet->removeObject(driver);

        list = fInterestedDrivers;
        item = list->findItem(driver);
        if (item && item->active)
        {
            item->active = false;
            waitForPMDriverCall( driver );
        }
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
            if (list->findItem(driver) == NULL)
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
                // Clean-up async interest acknowledgement
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
                        PM_LOG("%s::powerState%sChangeTo(%p, %s, %lu -> %lu) async took %d ms\n",
                            informee->whatObject->getName(),
                            (fDriverCallReason == kDriverCallInformPreChange) ? "Will" : "Did",
                            informee->whatObject,
                            fName, fCurrentPowerState, fHeadNotePowerState, NS_TO_US(nsec));
                    
                    uint16_t logType = (fDriverCallReason == kDriverCallInformPreChange) 
                                            ? kIOPMEventTypePSWillChangeTo
                                             : kIOPMEventTypePSDidChangeTo;

                    PMEventDetails *details = PMEventDetails::eventDetails(
                                                logType,
                                                fName,
                                                (uintptr_t)this,
                                                informee->whatObject->getName(),
                                                0, 0, 0,
                                                NS_TO_MS(nsec));

                    getPMRootDomain()->recordAndReleasePMEventGated( details );
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
        IOPMPowerChangeFlags changeFlags = kIOPMSelfInitiated;

        // Indicate that children desires were ignored, and do not ask
        // apps for permission to drop power. This is used by root domain
        // for demand sleep.

        if (getPMRequestType() == kIOPMRequestTypeRequestPowerStateOverride)
            changeFlags |= (kIOPMIgnoreChildren | kIOPMSkipAskPowerDown);

		startPowerChange(
			 /* flags        */	changeFlags,
			 /* power state  */	fDesiredPowerState,
			 /* domain flags */	0,
			 /* connection   */	0,
			 /* parent flags */	0);
	}
}

//*********************************************************************************
// [public] synchronizePowerTree
//*********************************************************************************

IOReturn IOService::synchronizePowerTree (
    IOOptionBits    options,
    IOService *     notifyRoot )
{
	IOPMRequest *   request_c = 0;
    IOPMRequest *   request_s;

    if (this != getPMRootDomain())
        return kIOReturnBadArgument;
	if (!initialized)
		return kIOPMNotYetInitialized;

    if (notifyRoot)
    {
        IOPMRequest * nr;

        // Cancels don't need to be synchronized.
        nr = acquirePMRequest(notifyRoot, kIOPMRequestTypeChildNotifyDelayCancel);
        if (nr) submitPMRequest(nr);        
        nr = acquirePMRequest(getPMRootDomain(), kIOPMRequestTypeChildNotifyDelayCancel);
        if (nr) submitPMRequest(nr);
    }

    request_s = acquirePMRequest( this, kIOPMRequestTypeSynchronizePowerTree );
    if (!request_s)
        goto error_no_memory;

    if (options & kIOPMSyncCancelPowerDown)
        request_c = acquirePMRequest( this, kIOPMRequestTypeIdleCancel );
    if (request_c)
    {
        request_c->attachNextRequest( request_s );
        submitPMRequest(request_c);
    }
    
    request_s->fArg0 = (void *)(uintptr_t) options;
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

void IOService::handleSynchronizePowerTree ( IOPMRequest * request )
{
	PM_ASSERT_IN_GATE();
	if (fControllingDriver && fParentsKnowState && inPlane(gIOPowerPlane) &&
        (fCurrentPowerState == fNumberOfPowerStates - 1))
	{
        IOOptionBits options = (uintptr_t) request->fArg0;

		startPowerChange(
			 /* flags        */	kIOPMSelfInitiated | kIOPMSynchronize |
                                (options & kIOPMSyncNoChildNotify),
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
	IOPMPowerFlags		 parentPowerFlags = (IOPMPowerFlags) request->fArg0;
	IOPowerConnection *	 whichParent = (IOPowerConnection *) request->fArg1;
    IOPMPowerChangeFlags parentChangeFlags = (IOPMPowerChangeFlags)(uintptr_t) request->fArg2;
    IOPMPowerChangeFlags myChangeFlags;
    OSIterator *		 iter;
    OSObject *			 next;
    IOPowerConnection *	 connection;
    IOPMPowerStateIndex  newPowerState;
    IOPMPowerFlags		 combinedPowerFlags;
	bool				 savedParentsKnowState;
	IOReturn			 result = IOPMAckImplied;

	PM_ASSERT_IN_GATE();
    OUR_PMLog(kPMLogWillChange, parentPowerFlags, 0);

	if (!inPlane(gIOPowerPlane) || !whichParent || !whichParent->getAwaitingAck())
	{
		PM_LOG("%s::%s not in power tree\n", getName(), __FUNCTION__);
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

    if ( fControllingDriver && !fInitialPowerChange )
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
	IOPMPowerFlags		 parentPowerFlags = (IOPMPowerFlags) request->fArg0;
	IOPowerConnection *	 whichParent = (IOPowerConnection *) request->fArg1;
    IOPMPowerChangeFlags parentChangeFlags = (IOPMPowerChangeFlags)(uintptr_t) request->fArg2;
    IOPMPowerChangeFlags myChangeFlags;
    IOPMPowerStateIndex  newPowerState;
    IOPMPowerStateIndex  initialDesire;
	bool				 savedParentsKnowState;
	IOReturn			 result = IOPMAckImplied;

	PM_ASSERT_IN_GATE();
    OUR_PMLog(kPMLogDidChange, parentPowerFlags, 0);

	if (!inPlane(gIOPowerPlane) || !whichParent || !whichParent->getAwaitingAck())
	{
		PM_LOG("%s::%s not in power tree\n", getName(), __FUNCTION__);
        goto exit_no_ack;
	}

	savedParentsKnowState = fParentsKnowState;

    setParentInfo(parentPowerFlags, whichParent, true);

    if ( fControllingDriver )
	{
		newPowerState = fControllingDriver->maxCapabilityForDomainState(
							fParentsCurrentPowerFlags);

        if (fInitialPowerChange)
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
		PM_LOG1("%s::powerDomainDidChangeTo parentsKnowState = true\n",
			getName());
		requestDomainPower( fDesiredPowerState );
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
					PM_LOG3("[%s] %s: connection not ready\n",
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
// Called on a power parent when a child's power requirement changes.
//*********************************************************************************

IOReturn IOService::requestPowerDomainState(
    IOPMPowerFlags      childRequestPowerFlags,
    IOPowerConnection * childConnection,
    unsigned long		specification )
{
    IOPMPowerStateIndex ps;
	IOPMPowerFlags		outputPowerFlags;
    IOService *         child;
	IOPMRequest *       subRequest;
    bool                preventIdle, preventSleep; 
    bool                adjustPower = false;

    if (!initialized)
		return IOPMNotYetInitialized;

	if (gIOPMWorkLoop->onThread() == false)
	{
		PM_LOG("%s::requestPowerDomainState\n", getName());
		return kIOReturnSuccess;
	}

    OUR_PMLog(kPMLogRequestDomain, childRequestPowerFlags, specification);

	if (!isChild(childConnection, gIOPowerPlane))
		return kIOReturnNotAttached;

    if (!fControllingDriver || !fNumberOfPowerStates)
        return kIOReturnNotReady;

	child = (IOService *) childConnection->getChildEntry(gIOPowerPlane);
	assert(child);

    preventIdle  = ((childRequestPowerFlags & kIOPMPreventIdleSleep) != 0);
    preventSleep = ((childRequestPowerFlags & kIOPMPreventSystemSleep) != 0);
    childRequestPowerFlags &= ~(kIOPMPreventIdleSleep | kIOPMPreventSystemSleep);

    // Merge in the power flags contributed by this power parent
    // at its current or impending power state. 

    outputPowerFlags = fPowerStates[fCurrentPowerState].outputPowerFlags;
	if (fMachineState != kIOPM_Finished)
	{
		if (IS_POWER_DROP && !IS_ROOT_DOMAIN)
		{
			// Use the lower power state when dropping power. 
			// Must be careful since a power drop can be canceled
			// from the following states:
			// - kIOPM_OurChangeTellClientsPowerDown
			// - kIOPM_OurChangeTellPriorityClientsPowerDown
			//
			// The child must not wait for this parent to raise power
			// if the power drop was cancelled. The solution is to cancel
			// the power drop if possible, then schedule an adjustment to
			// re-evaluate the parent's power state.
			//
			// Root domain is excluded to avoid idle sleep issues. And permit
			// root domain children to pop up when system is going to sleep.

			if ((fMachineState == kIOPM_OurChangeTellClientsPowerDown) ||
				(fMachineState == kIOPM_OurChangeTellPriorityClientsPowerDown))
			{
				fDoNotPowerDown = true;     // cancel power drop
				adjustPower     = true;     // schedule an adjustment
				PM_LOG1("%s: power drop cancelled in state %u by %s\n",
					getName(), fMachineState, child->getName());
			}
			else
			{
				// Beyond cancellation point, report the impending state.
				outputPowerFlags =
					fPowerStates[fHeadNotePowerState].outputPowerFlags;
			}
		}
		else if (IS_POWER_RISE)
		{
			// When raising power, must report the output power flags from
			// child's perspective. A child power request may arrive while
			// parent is transitioning upwards. If a request arrives after
			// setParentInfo() has already recorded the output power flags
			// for the next power state, then using the power supplied by
			// fCurrentPowerState is incorrect, and might cause the child
			// to wait when it should not.
			
			outputPowerFlags = childConnection->parentCurrentPowerFlags();
		}
    }
    child->fHeadNoteDomainTargetFlags |= outputPowerFlags;

    // Map child's requested power flags to one of our power state.

    for (ps = 0; ps < fNumberOfPowerStates; ps++)
    {
        if ((fPowerStates[ps].outputPowerFlags & childRequestPowerFlags) ==
            (fOutputPowerCharacterFlags & childRequestPowerFlags))
            break;
    }
    if (ps >= fNumberOfPowerStates)
    {
        ps = 0;  // should never happen
    }

    // Conditions that warrants a power adjustment on this parent.
    // Adjust power will also propagate any changes to the child's
    // prevent idle/sleep flags towards the root domain.

    if (!childConnection->childHasRequestedPower() ||
        (ps != childConnection->getDesiredDomainState()) ||
        (childConnection->getPreventIdleSleepFlag() != preventIdle) ||
        (childConnection->getPreventSystemSleepFlag() != preventSleep))
        adjustPower = true;

#if ENABLE_DEBUG_LOGS
    if (adjustPower)
    {
        PM_LOG("requestPowerDomainState[%s]: %s, init %d, %u->%u\n",
            getName(), child->getName(),
            !childConnection->childHasRequestedPower(),
            (uint32_t) childConnection->getDesiredDomainState(),
            (uint32_t) ps);
    }
#endif

	// Record the child's desires on the connection.
#if SUPPORT_IDLE_CANCEL
	bool attemptCancel = (preventIdle && !childConnection->getPreventIdleSleepFlag());
#endif
	childConnection->setChildHasRequestedPower();
	childConnection->setDesiredDomainState( ps );
	childConnection->setPreventIdleSleepFlag( preventIdle );
	childConnection->setPreventSystemSleepFlag( preventSleep );

	// Schedule a request to re-evaluate all children desires and
	// adjust power state. Submit a request if one wasn't pending,
	// or if the current request is part of a call tree.

    if (adjustPower && !fDeviceOverrideEnabled &&
        (!fAdjustPowerScheduled || gIOPMRequest->getRootRequest()))
    {
		subRequest = acquirePMRequest(
            this, kIOPMRequestTypeAdjustPowerState, gIOPMRequest );
		if (subRequest)
		{
			submitPMRequest( subRequest );
			fAdjustPowerScheduled = true;
		}
    }

#if SUPPORT_IDLE_CANCEL
	if (attemptCancel)
	{
		subRequest = acquirePMRequest( this, kIOPMRequestTypeIdleCancel );
		if (subRequest)
		{
			submitPMRequest( subRequest );
		}
	}
#endif

    return kIOReturnSuccess;
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
		request->fArg2 = (void *) (uintptr_t) true;
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
		request->fArg2 = (void *) (uintptr_t) true;
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

    // The power suppression due to changePowerStateWithOverrideTo() expires
    // upon the next "device" power request - changePowerStateToPriv().

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
// [protected] powerOverrideOnPriv
//*********************************************************************************

IOReturn IOService::powerOverrideOnPriv ( void )
{
	IOPMRequest * request;

    if (!initialized)
		return IOPMNotYetInitialized;

	if (gIOPMWorkLoop->inGate())
	{
		fDeviceOverrideEnabled = true;
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
		fDeviceOverrideEnabled = false;
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
		fDeviceOverrideEnabled = true;
    }
	else
	{
		OUR_PMLog(kPMLogOverrideOff, 0, 0);
		fDeviceOverrideEnabled = false;
	}

	adjustPowerState();
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
		//PM_LOG("%s::%s no controlling driver\n", getName(), __FUNCTION__);
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
                    PM_LOG3("[%s] %s: connection not ready\n",
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
            if ((fDeviceOverrideEnabled ||
                (getPMRequestType() == kIOPMRequestTypeRequestPowerStateOverride)) &&
                ((client == gIOPMPowerClientChildren) ||
                 (client == gIOPMPowerClientDriver)))
                continue;

			// Ignore child proxy when children are present.
            if (hasChildren && (client == gIOPMPowerClientChildProxy))
                continue;

            desiredState = getPowerStateForClient(client);
            assert(desiredState < fNumberOfPowerStates);			
			PM_LOG1("  %u %s\n",
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

    PM_LOG1("  temp %u, clamp %u, current %u, new %u\n",
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

#if NOT_YET

//*********************************************************************************
// Power Parent/Children Applier
//*********************************************************************************

static void
applyToPowerChildren( 
    IOService *               service,
    IOServiceApplierFunction  applier,
    void *                    context,
    IOOptionBits              options )
{
	PM_ASSERT_IN_GATE();

    IORegistryEntry *       entry;
    IORegistryIterator *    iter;
    IOPowerConnection *     connection;
    IOService *             child;

    iter = IORegistryIterator::iterateOver(service, gIOPowerPlane, options);
    if (iter)
    {
        while ((entry = iter->getNextObject()))
        {
            // Get child of IOPowerConnection objects
            if ((connection = OSDynamicCast(IOPowerConnection, entry)))
            {
                child = (IOService *) connection->copyChildEntry(gIOPowerPlane);
                if (child)
                {
                    (*applier)(child, context);
                    child->release();
                }
            }
        }
        iter->release();
    }
}

static void
applyToPowerParent( 
    IOService *               service,
    IOServiceApplierFunction  applier,
    void *                    context,
    IOOptionBits              options )
{
	PM_ASSERT_IN_GATE();

    IORegistryEntry *       entry;
    IORegistryIterator *    iter;
    IOPowerConnection *     connection;
    IOService *             parent;

    iter = IORegistryIterator::iterateOver(service, gIOPowerPlane,
            options | kIORegistryIterateParents);
    if (iter)
    {
        while ((entry = iter->getNextObject()))
        {
            // Get child of IOPowerConnection objects
            if ((connection = OSDynamicCast(IOPowerConnection, entry)))
            {
                parent = (IOService *) connection->copyParentEntry(gIOPowerPlane);
                if (parent)
                {
                    (*applier)(parent, context);
                    parent->release();
                }
            }
        }
        iter->release();
    }
}

#endif /* NOT_YET */

// MARK: -
// MARK: Activity Tickle & Idle Timer

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

        fDeviceWasActive = true;
        fActivityTickleCount++;
        clock_get_uptime(&fDeviceActiveTimestamp);

        PM_ACTION_0(actionActivityTickle);

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
				request->fArg1 = (void *) (uintptr_t) true;	// power rise
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

//******************************************************************************
// [public] setIdleTimerPeriod
//
// A subclass policy-maker is using our standard idleness detection service.
// Start the idle timer. Period is in seconds.
//******************************************************************************

IOReturn IOService::setIdleTimerPeriod ( unsigned long period )
{
    if (!initialized)
		return IOPMNotYetInitialized;

    OUR_PMLog(kPMLogSetIdleTimerPeriod, period, fIdleTimerPeriod);

    IOPMRequest * request =
        acquirePMRequest( this, kIOPMRequestTypeSetIdleTimerPeriod );
    if (!request)
        return kIOReturnNoMemory;

    request->fArg0 = (void *) period;
    submitPMRequest( request );

    return kIOReturnSuccess;
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
    AbsoluteTime        delta;
    UInt64              delta_ns;
    SInt32              delta_secs;
    SInt32              delay_secs;

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

//*********************************************************************************
// [public] start_PM_idle_timer
//*********************************************************************************

void IOService::start_PM_idle_timer ( void )
{
    static const int    maxTimeout = 100000;
    static const int    minTimeout = 1;
    AbsoluteTime        uptime, deadline;
    SInt32              idle_in = 0;
	boolean_t           pending;

	if (!initialized || !fIdleTimerPeriod)
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

    retain();
    clock_interval_to_absolutetime_interval(idle_in, kSecondScale, &deadline);
    ADD_ABSOLUTETIME(&deadline, &uptime);
    pending = thread_call_enter_delayed(fIdleTimer, deadline);
    if (pending) release();
}

//*********************************************************************************
// idle_timer_expired
//*********************************************************************************

static void
idle_timer_expired (
    thread_call_param_t arg0, thread_call_param_t arg1 )
{
	IOService * me = (IOService *) arg0;

	if (gIOPMWorkLoop)
		gIOPMWorkLoop->runAction(
            OSMemberFunctionCast(IOWorkLoop::Action, me,
                &IOService::idleTimerExpired),
            me);

	me->release();
}

//*********************************************************************************
// [private] idleTimerExpired
//
// The idle timer has expired. If there has been activity since the last
// expiration, just restart the timer and return.  If there has not been
// activity, switch to the next lower power state and restart the timer.
//*********************************************************************************

void IOService::idleTimerExpired( void )
{
	IOPMRequest *	request;
	bool			restartTimer = true;

    if ( !initialized || !fIdleTimerPeriod || fLockedFlags.PMStop )
        return;

	IOLockLock(fActivityLock);

	// Check for device activity (tickles) over last timer period.

	if (fDeviceWasActive)
	{
		// Device was active - do not drop power, restart timer.
		fDeviceWasActive = false;
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
			request->fArg1 = (void *) (uintptr_t) false;	// power drop
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
					PM_LOG3("[%s] %s: connection not ready\n",
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

    if ( inPlane(gIOPowerPlane) && !IS_PM_ROOT )
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

// MARK: -
// MARK: Power Change (Common)

//*********************************************************************************
// [private] startPowerChange
//
// All power state changes starts here.
//*********************************************************************************

IOReturn IOService::startPowerChange(
    IOPMPowerChangeFlags    changeFlags,
    IOPMPowerStateIndex     powerState,
    IOPMPowerFlags          domainFlags,
    IOPowerConnection *     parentConnection,
    IOPMPowerFlags          parentFlags )
{
	PM_ASSERT_IN_GATE();
	assert( fMachineState == kIOPM_Finished );
    assert( powerState < fNumberOfPowerStates );

    if (powerState >= fNumberOfPowerStates)
        return IOPMAckImplied;

    fIsPreChange = true;
    PM_ACTION_2(actionPowerChangeOverride, &powerState, &changeFlags);

	// Forks to either Driver or Parent initiated power change paths.

    fHeadNoteChangeFlags      = changeFlags;
    fHeadNotePowerState       = powerState;
	fHeadNotePowerArrayEntry  = &fPowerStates[ powerState ];
	fHeadNoteParentConnection = NULL;

	if (changeFlags & kIOPMSelfInitiated)
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
    fHeadNotePendingAcks  = count;

    // Block state machine and wait for callout completion.
    assert(!fDriverCallBusy);
    fDriverCallBusy = true;
    thread_call_enter( fDriverCallEntry );
    return true;

done:
    // Return false if there are no interested drivers or could not schedule
    // callout thread due to error.
    return false;
}

//*********************************************************************************
// [private] notifyInterestedDriversDone
//*********************************************************************************

void IOService::notifyInterestedDriversDone ( void )
{
    IOPMinformee *		informee;
    IOItemCount			count;
    DriverCallParam *   param;
    IOReturn            result;

	PM_ASSERT_IN_GATE();
	assert( fDriverCallBusy == false );
	assert( fMachineState == kIOPM_DriverThreadCallDone );

	param = (DriverCallParam *) fDriverCallParamPtr;
	count = fDriverCallParamCount;

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

    MS_POP();  // pushed by notifyAll()

    // If interest acks are outstanding, wait for fHeadNotePendingAcks to become
    // zero before notifying children. This enforces the children after interest
    // ordering even for async interest clients.

    if (!fHeadNotePendingAcks)
    {
        notifyChildren();
    }
    else
    {
        MS_PUSH(fMachineState);
        fMachineState = kIOPM_NotifyChildrenStart;
        PM_LOG2("%s: %u outstanding async interest\n",
            getName(), fHeadNotePendingAcks);
    }
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
    IOPMrootDomain *    rootDomain;
    bool                delayNotify = false;
    
    if ((fHeadNotePowerState != fCurrentPowerState) &&
        (IS_POWER_DROP == fIsPreChange) &&
        ((rootDomain = getPMRootDomain()) == this))
    {
        rootDomain->tracePoint( IS_POWER_DROP ?
            kIOPMTracePointSleepPowerPlaneDrivers :
            kIOPMTracePointWakePowerPlaneDrivers  );
    }

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
					PM_LOG3("[%s] %s: connection not ready\n",
						getName(), __FUNCTION__);
					continue;
				}

                // Mechanism to postpone the did-change notification to
                // certain power children to order those children last.
                // Cannot be used together with strict tree ordering.

                if (!fIsPreChange &&
                    (connection->delayChildNotification) &&
                    getPMRootDomain()->shouldDelayChildNotification(this))
                {
                    if (!children)
                    {
                        children = OSArray::withCapacity(8);
                        if (children)
                            delayNotify = true;
                    }
                    if (delayNotify)
                    {
                        children->setObject( connection );
                        continue;
                    }
                }

				if (!delayNotify && children)
					children->setObject( connection );
				else
					notifyChild( connection );
			}
        }
        iter->release();
    }

    if (children && (children->getCount() == 0))
    {
        children->release();
        children = 0;
    }
	if (children)
	{
        assert(fNotifyChildArray == 0);
        fNotifyChildArray = children;        
        MS_PUSH(fMachineState);

        if (delayNotify)
        {
            // Wait for exiting child notifications to complete,
            // before notifying the children in the array.
            fMachineState = kIOPM_NotifyChildrenDelayed;
            PM_LOG2("%s: %d children in delayed array\n",
                getName(), children->getCount());
        }
        else
        {
            // Notify children in the array one at a time.
            fMachineState = kIOPM_NotifyChildrenOrdered;
        }
	}
}

//*********************************************************************************
// [private] notifyChildrenOrdered
//*********************************************************************************

void IOService::notifyChildrenOrdered ( void )
{
	PM_ASSERT_IN_GATE();
	assert(fNotifyChildArray);
	assert(fMachineState == kIOPM_NotifyChildrenOrdered);

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
		notifyChild( connection );
	}
	else
	{
		fNotifyChildArray->release();
		fNotifyChildArray = 0;

        MS_POP();   // pushed by notifyChildren()
	}
}

//*********************************************************************************
// [private] notifyChildrenDelayed
//*********************************************************************************

void IOService::notifyChildrenDelayed ( void )
{
    IOPowerConnection *	connection;

	PM_ASSERT_IN_GATE();
	assert(fNotifyChildArray);
	assert(fMachineState == kIOPM_NotifyChildrenDelayed);

    // Wait after all non-delayed children and interested drivers have ack'ed,
    // then notify all delayed children. When explicitly cancelled, interest
    // acks (and ack timer) may still be outstanding.

    for (int i = 0; ; i++)
    {
		connection = (IOPowerConnection *) fNotifyChildArray->getObject(i);
        if (!connection)
            break;

		notifyChild( connection );
    }

    PM_LOG2("%s: notified delayed children\n", getName());
    fNotifyChildArray->release();
    fNotifyChildArray = 0;
    
    MS_POP();   // pushed by notifyChildren()
}

//*********************************************************************************
// [private] notifyAll
//*********************************************************************************

IOReturn IOService::notifyAll ( uint32_t nextMS )
{
	// Save the next machine_state to be restored by notifyInterestedDriversDone()

	PM_ASSERT_IN_GATE();
    MS_PUSH(nextMS);
	fMachineState     = kIOPM_DriverThreadCallDone;
	fDriverCallReason = fIsPreChange ?
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

    assert( fDriverCallBusy );
    fDriverCallBusy = false;

    assert(gIOPMWorkQueue);
    gIOPMWorkQueue->signalWorkAvailable();

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
    IOPMPowerStateIndex powerState;
    DriverCallParam *	param;
    IOPMDriverCallEntry callEntry;
    AbsoluteTime        end;
    IOReturn            result;
    uint32_t            oldPowerState = getPowerState();

    assert( fDriverCallBusy );
    assert( fDriverCallParamPtr );
    assert( fDriverCallParamCount == 1 );

    param = (DriverCallParam *) fDriverCallParamPtr;
    powerState = fHeadNotePowerState;

    if (assertPMDriverCall(&callEntry))
    {
        OUR_PMLog(          kPMLogProgramHardware, (uintptr_t) this, powerState);
        clock_get_uptime(&fDriverCallStartTime);
        result = fControllingDriver->setPowerState( powerState, this );
        clock_get_uptime(&end);
        OUR_PMLog((UInt32) -kPMLogProgramHardware, (uintptr_t) this, (UInt32) result);

        deassertPMDriverCall(&callEntry);

        if (result < 0)
        {
            PM_LOG("%s::setPowerState(%p, %lu -> %lu) returned 0x%x\n",
                fName, this, fCurrentPowerState, powerState, result);
        }

#if LOG_SETPOWER_TIMES
        if ((result == IOPMAckImplied) || (result < 0))
        {
            uint64_t    nsec;

            SUB_ABSOLUTETIME(&end, &fDriverCallStartTime);
            absolutetime_to_nanoseconds(end, &nsec);
            if (nsec > LOG_SETPOWER_TIMES)
                PM_LOG("%s::setPowerState(%p, %lu -> %lu) took %d ms\n",
                    fName, this, fCurrentPowerState, powerState, NS_TO_MS(nsec));

            PMEventDetails *details = PMEventDetails::eventDetails(
                                        kIOPMEventTypeSetPowerStateImmediate, // type
                                        fName,								  // who
                                        (uintptr_t)this,					  // owner unique
                                        NULL,								  // interest name
                                        (uint8_t)oldPowerState,				  // old
                                        (uint8_t)powerState,				  // new
                                        0,									  // result
                                        NS_TO_US(nsec));					  // usec completion time

            getPMRootDomain()->recordAndReleasePMEventGated( details );
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
    IOPMinformee *		informee;
    IOService *			driver;
    DriverCallParam *	param;
    IOPMDriverCallEntry callEntry;
    IOPMPowerFlags		powerFlags;
    IOPMPowerStateIndex powerState;
    AbsoluteTime        end;
    IOReturn            result;
    IOItemCount			count;

    assert( fDriverCallBusy );
    assert( fDriverCallParamPtr );
    assert( fDriverCallParamCount );

    param = (DriverCallParam *) fDriverCallParamPtr;
    count = fDriverCallParamCount;

    powerFlags = fHeadNotePowerArrayEntry->capabilityFlags;
    powerState = fHeadNotePowerState;

    for (IOItemCount i = 0; i < count; i++)
    {
        informee = (IOPMinformee *) param->Target;
        driver   = informee->whatObject;

        if (assertPMDriverCall(&callEntry, 0, informee))
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
    
            deassertPMDriverCall(&callEntry);

#if LOG_SETPOWER_TIMES
            if ((result == IOPMAckImplied) || (result < 0))
            {
                uint64_t nsec;

                SUB_ABSOLUTETIME(&end, &informee->startTime);
                absolutetime_to_nanoseconds(end, &nsec);
                if (nsec > LOG_SETPOWER_TIMES)
                    PM_LOG("%s::powerState%sChangeTo(%p, %s, %lu -> %lu) took %d ms\n",
                        driver->getName(),
                        (fDriverCallReason == kDriverCallInformPreChange) ? "Will" : "Did",
                        driver, fName, fCurrentPowerState, powerState, NS_TO_MS(nsec));

                uint16_t logType = (fDriverCallReason == kDriverCallInformPreChange) 
                                    ? kIOPMEventTypePSWillChangeTo
                                    : kIOPMEventTypePSDidChangeTo;

                PMEventDetails *details = PMEventDetails::eventDetails(
                                            logType,						// type
                                            fName,							// who
                                            (uintptr_t)this,				// owner unique
                                            driver->getName(),				// interest name
                                            (uint8_t)fCurrentPowerState,	// old
                                            (uint8_t)fHeadNotePowerState,	// new
                                            0,								// result
                                            NS_TO_US(nsec));				// usec completion time

                getPMRootDomain()->recordAndReleasePMEventGated( details );
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

bool IOService::notifyChild ( IOPowerConnection * theNub )
{
    IOReturn                ret = IOPMAckImplied;
    unsigned long           childPower;
    IOService *             theChild;
	IOPMRequest *           childRequest;
    IOPMPowerChangeFlags    requestArg2;
	int                     requestType;

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

    requestArg2 = fHeadNoteChangeFlags;
    if (fHeadNotePowerState < fCurrentPowerState)
        requestArg2 |= kIOPMDomainPowerDrop;

    requestType = fIsPreChange ?
        kIOPMRequestTypePowerDomainWillChange :
        kIOPMRequestTypePowerDomainDidChange;

	childRequest = acquirePMRequest( theChild, requestType );
	if (childRequest)
	{
        theNub->retain();
		childRequest->fArg0 = (void *) fHeadNotePowerArrayEntry->outputPowerFlags;
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
// [private] notifyControllingDriver
//*********************************************************************************

bool IOService::notifyControllingDriver ( void )
{
    DriverCallParam *	param;

    PM_ASSERT_IN_GATE();
    assert( fDriverCallParamCount == 0  );
    assert( fControllingDriver );

    if (fInitialSetPowerState)
    {
        // Driver specified flag to skip the inital setPowerState()
        if (fHeadNotePowerArrayEntry->capabilityFlags & kIOPMInitialDeviceState)
        {
            return false;
        }
        fInitialSetPowerState = false;
    }

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

    // Block state machine and wait for callout completion.
    assert(!fDriverCallBusy);
    fDriverCallBusy = true;
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

	assert( fDriverCallBusy == false );
	assert( fMachineState == kIOPM_DriverThreadCallDone );

	if (param && fDriverCallParamCount)
	{
		assert(fDriverCallParamCount == 1);
		
		// the return value from setPowerState()
		result = param->Result;

		if ((result == IOPMAckImplied) || (result < 0))
		{
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

    MS_POP();   // pushed by OurChangeSetPowerState()
    fIsPreChange  = false;
}

//*********************************************************************************
// [private] all_done
//
// A power change is done.
//*********************************************************************************

void IOService::all_done ( void )
{
    IOPMPowerStateIndex     prevPowerState;
    const IOPMPSEntry *     powerStatePtr;
    IOPMDriverCallEntry     callEntry;
    uint32_t                prevMachineState = fMachineState;
    bool                    callAction = false;

    fMachineState = kIOPM_Finished;

    if ((fHeadNoteChangeFlags & kIOPMSynchronize) &&
        ((prevMachineState == kIOPM_Finished) ||
         (prevMachineState == kIOPM_SyncFinish)))
    {
        // Sync operation and no power change occurred.
        // Do not inform driver and clients about this request completion,
        // except for the originator (root domain).

        PM_ACTION_2(actionPowerChangeDone,
            fHeadNotePowerState, fHeadNoteChangeFlags);

        if (getPMRequestType() == kIOPMRequestTypeSynchronizePowerTree)
        {
            powerChangeDone(fCurrentPowerState);
        }

        return;
    }

    // our power change
    if ( fHeadNoteChangeFlags & kIOPMSelfInitiated )
    {
        // could our driver switch to the new state?
        if ( !( fHeadNoteChangeFlags & kIOPMNotDone) )
        {
			// we changed, tell our parent
            requestDomainPower(fHeadNotePowerState);

            // yes, did power raise?
            if ( fCurrentPowerState < fHeadNotePowerState )
            {
                // yes, inform clients and apps
                tellChangeUp (fHeadNotePowerState);
            }
            prevPowerState = fCurrentPowerState;
            // either way
            fCurrentPowerState = fHeadNotePowerState;
#if PM_VARS_SUPPORT
            fPMVars->myCurrentState = fCurrentPowerState;
#endif
            OUR_PMLog(kPMLogChangeDone, fCurrentPowerState, 0);
            PM_ACTION_2(actionPowerChangeDone,
                fHeadNotePowerState, fHeadNoteChangeFlags);
            callAction = true;

            powerStatePtr = &fPowerStates[fCurrentPowerState];
            fCurrentCapabilityFlags = powerStatePtr->capabilityFlags;
            if (fCurrentCapabilityFlags & kIOPMStaticPowerValid)
                fCurrentPowerConsumption = powerStatePtr->staticPower;

            // inform subclass policy-maker
            if (fPCDFunctionOverride && fParentsKnowState &&
                assertPMDriverCall(&callEntry, kIOPMADC_NoInactiveCheck))
            {
                powerChangeDone(prevPowerState);
                deassertPMDriverCall(&callEntry);
            }
        }
        else if (getPMRequestType() == kIOPMRequestTypeRequestPowerStateOverride)
        {
            // changePowerStateWithOverrideTo() was cancelled
            fOverrideMaxPowerState = kIOPMPowerStateMax;
        }
    }

    // parent's power change
    if ( fHeadNoteChangeFlags & kIOPMParentInitiated)
    {
        if (((fHeadNoteChangeFlags & kIOPMDomainWillChange) &&
             (fCurrentPowerState >= fHeadNotePowerState))   ||
			  ((fHeadNoteChangeFlags & kIOPMDomainDidChange)  &&
             (fCurrentPowerState < fHeadNotePowerState)))
        {
            // did power raise?
            if ( fCurrentPowerState < fHeadNotePowerState )
            {
                // yes, inform clients and apps
                tellChangeUp (fHeadNotePowerState);
            }
            // either way
            prevPowerState = fCurrentPowerState;
            fCurrentPowerState = fHeadNotePowerState;
#if PM_VARS_SUPPORT
            fPMVars->myCurrentState = fCurrentPowerState;
#endif
            fMaxPowerState = fControllingDriver->maxCapabilityForDomainState(fHeadNoteDomainFlags);

            OUR_PMLog(kPMLogChangeDone, fCurrentPowerState, 0);
            PM_ACTION_2(actionPowerChangeDone,
                fHeadNotePowerState, fHeadNoteChangeFlags);
            callAction = true;

            powerStatePtr = &fPowerStates[fCurrentPowerState];
            fCurrentCapabilityFlags = powerStatePtr->capabilityFlags;
            if (fCurrentCapabilityFlags & kIOPMStaticPowerValid)
                fCurrentPowerConsumption = powerStatePtr->staticPower;

            // inform subclass policy-maker
            if (fPCDFunctionOverride && fParentsKnowState &&
                assertPMDriverCall(&callEntry, kIOPMADC_NoInactiveCheck))
            {
                powerChangeDone(prevPowerState);
                deassertPMDriverCall(&callEntry);
            }
        }
    }

    // When power rises enough to satisfy the tickle's desire for more power,
    // the condition preventing idle-timer from dropping power is removed.

    if (fCurrentPowerState >= fIdleTimerMinPowerState)
    {
        fIdleTimerMinPowerState = 0;
    }

    if (!callAction)
    {
        PM_ACTION_2(actionPowerChangeDone,
            fHeadNotePowerState, fHeadNoteChangeFlags);
    }
}

// MARK: -
// MARK: Power Change Initiated by Driver

//*********************************************************************************
// [private] OurChangeStart
//
// Begin the processing of a power change initiated by us.
//*********************************************************************************

void IOService::OurChangeStart ( void )
{
	PM_ASSERT_IN_GATE();
    OUR_PMLog( kPMLogStartDeviceChange, fHeadNotePowerState, fCurrentPowerState );

	// fMaxPowerState is our maximum possible power state based on the current
	// power state of our parents.  If we are trying to raise power beyond the
	// maximum, send an async request for more power to all parents.

    if (!IS_PM_ROOT && (fMaxPowerState < fHeadNotePowerState))
    {
        fHeadNoteChangeFlags |= kIOPMNotDone;
        requestDomainPower(fHeadNotePowerState);
        OurChangeFinish();
        return;
    }

	// Redundant power changes skips to the end of the state machine.

    if (!fInitialPowerChange && (fHeadNotePowerState == fCurrentPowerState))
	{
		OurChangeFinish();
		return;
    }
    fInitialPowerChange = false;

    // Change started, but may not complete...
    // Can be canceled (power drop) or deferred (power rise).

    PM_ACTION_2(actionPowerChangeStart, fHeadNotePowerState, &fHeadNoteChangeFlags);

	// Two separate paths, depending if power is being raised or lowered.
	// Lowering power is subject to approval by clients of this service.

    if (IS_POWER_DROP)
    {
        fDoNotPowerDown = false;

        // Ask for persmission to drop power state
        fMachineState = kIOPM_OurChangeTellClientsPowerDown;
        fOutOfBandParameter = kNotifyApps;
        askChangeDown(fHeadNotePowerState);
    }
	else
	{
        // This service is raising power and parents are able to support the
        // new power state. However a parent may have already committed to
        // drop power, which might force this object to temporarily drop power.
        // This results in "oscillations" before the state machines converge
        // to a steady state.
        //
        // To prevent this, a child must make a power reservation against all
        // parents before raising power. If the reservation fails, indicating
        // that the child will be unable to sustain the higher power state,
        // then the child will signal the parent to adjust power, and the child
        // will defer its power change.

        IOReturn ret;

        // Reserve parent power necessary to achieve fHeadNotePowerState.
        ret = requestDomainPower( fHeadNotePowerState, kReserveDomainPower );
        if (ret != kIOReturnSuccess)
        {
            // Reservation failed, defer power rise.
            fHeadNoteChangeFlags |= kIOPMNotDone;
            OurChangeFinish();
            return;
        }

        OurChangeTellCapabilityWillChange();
    }
}

//*********************************************************************************

struct IOPMRequestDomainPowerContext {
    IOService *     child;              // the requesting child
    IOPMPowerFlags  requestPowerFlags;  // power flags requested by child
};

static void
requestDomainPowerApplier(
    IORegistryEntry *   entry,
    void *              inContext )
{
    IOPowerConnection *             connection;
    IOService *                     parent;
    IOPMRequestDomainPowerContext * context;

    if ((connection = OSDynamicCast(IOPowerConnection, entry)) == 0)
        return;
    parent = (IOService *) connection->copyParentEntry(gIOPowerPlane);
    if (!parent)
        return;

    assert(inContext);
    context = (IOPMRequestDomainPowerContext *) inContext;

    if (connection->parentKnowsState() && connection->getReadyFlag())
    {
        parent->requestPowerDomainState(
            context->requestPowerFlags,
            connection,
            IOPMLowestState);
    }

    parent->release();
}

//*********************************************************************************
// [private] requestDomainPower
//*********************************************************************************

IOReturn IOService::requestDomainPower(
    IOPMPowerStateIndex ourPowerState,
    IOOptionBits        options )
{
    const IOPMPSEntry *             powerStateEntry;
    IOPMPowerFlags                  requestPowerFlags;
    IOPMPowerStateIndex             maxPowerState;
    IOPMRequestDomainPowerContext   context;

	PM_ASSERT_IN_GATE();
    assert(ourPowerState < fNumberOfPowerStates);
    if (ourPowerState >= fNumberOfPowerStates)
        return kIOReturnBadArgument;
    if (IS_PM_ROOT)
        return kIOReturnSuccess;

    // Fetch the input power flags for the requested power state.
    // Parent request is stated in terms of required power flags.

	powerStateEntry = &fPowerStates[ourPowerState];
	requestPowerFlags = powerStateEntry->inputPowerFlags;

    if (powerStateEntry->capabilityFlags & (kIOPMChildClamp | kIOPMPreventIdleSleep))
        requestPowerFlags |= kIOPMPreventIdleSleep;
    if (powerStateEntry->capabilityFlags & (kIOPMChildClamp2 | kIOPMPreventSystemSleep))
        requestPowerFlags |= kIOPMPreventSystemSleep;

    // Disregard the "previous request" for power reservation.

    if (((options & kReserveDomainPower) == 0) &&
        (fPreviousRequestPowerFlags == requestPowerFlags))
    {
        // skip if domain already knows our requirements
        goto done;
    }
    fPreviousRequestPowerFlags = requestPowerFlags;

    context.child              = this;
    context.requestPowerFlags  = requestPowerFlags;
    fHeadNoteDomainTargetFlags = 0;
    applyToParents(requestDomainPowerApplier, &context, gIOPowerPlane);

    if (options & kReserveDomainPower)
    {
        maxPowerState = fControllingDriver->maxCapabilityForDomainState(
                            fHeadNoteDomainTargetFlags );

        if (maxPowerState < fHeadNotePowerState)
        {
            PM_LOG1("%s: power desired %u:0x%x got %u:0x%x\n",
                getName(),
                (uint32_t) ourPowerState, (uint32_t) requestPowerFlags,
                (uint32_t) maxPowerState, (uint32_t) fHeadNoteDomainTargetFlags);
            return kIOReturnNoPower;
        }
    }

done:
    return kIOReturnSuccess;
}

//*********************************************************************************
// [private] OurSyncStart
//*********************************************************************************

void IOService::OurSyncStart ( void )
{
	PM_ASSERT_IN_GATE();

    if (fInitialPowerChange)
        return;

    PM_ACTION_2(actionPowerChangeStart, fHeadNotePowerState, &fHeadNoteChangeFlags);

    if (fHeadNoteChangeFlags & kIOPMNotDone)
    {
		OurChangeFinish();
		return;
    }

    if (fHeadNoteChangeFlags & kIOPMSyncTellPowerDown)
    {
        fDoNotPowerDown = false;

        // Ask for permission to drop power state
        fMachineState = kIOPM_SyncTellClientsPowerDown;
        fOutOfBandParameter = kNotifyApps;
        askChangeDown(fHeadNotePowerState);
    }
    else
    {
        // Only inform capability app and clients.
        tellSystemCapabilityChange( kIOPM_SyncNotifyWillChange );
    }
}

//*********************************************************************************
// [private] OurChangeTellClientsPowerDown
//
// All applications and kernel clients have acknowledged our permission to drop
// power. Here we notify them that we will lower the power and wait for acks. 
//*********************************************************************************

void IOService::OurChangeTellClientsPowerDown ( void )
{
    fMachineState = kIOPM_OurChangeTellPriorityClientsPowerDown;
    tellChangeDown1(fHeadNotePowerState);
}

//*********************************************************************************
// [private] OurChangeTellPriorityClientsPowerDown
//
// All applications and kernel clients have acknowledged our intention to drop
// power.  Here we notify "priority" clients that we are lowering power.
//*********************************************************************************

void IOService::OurChangeTellPriorityClientsPowerDown ( void )
{
    fMachineState = kIOPM_OurChangeNotifyInterestedDriversWillChange;
    tellChangeDown2(fHeadNotePowerState);
}

//*********************************************************************************
// [private] OurChangeTellCapabilityWillChange
//
// Extra stage for root domain to notify apps and drivers about the
// system capability change when raising power state.
//*********************************************************************************

void IOService::OurChangeTellCapabilityWillChange ( void )
{
    if (!IS_ROOT_DOMAIN)
        return OurChangeNotifyInterestedDriversWillChange();

    tellSystemCapabilityChange( kIOPM_OurChangeNotifyInterestedDriversWillChange );
}

//*********************************************************************************
// [private] OurChangeNotifyInterestedDriversWillChange
//
// All applications and kernel clients have acknowledged our power state change.
// Here we notify interested drivers pre-change.
//*********************************************************************************

void IOService::OurChangeNotifyInterestedDriversWillChange ( void )
{
    IOPMrootDomain * rootDomain;
    if ((rootDomain = getPMRootDomain()) == this)
    {
        if (IS_POWER_DROP)
        {
            rootDomain->tracePoint( kIOPMTracePointSleepWillChangeInterests );

            PMEventDetails *details = PMEventDetails::eventDetails(
                                        kIOPMEventTypeAppNotificationsFinished,
                                        NULL,
                                        100,
                                        kIOReturnSuccess);
            rootDomain->recordAndReleasePMEventGated( details );
        }
        else
            rootDomain->tracePoint( kIOPMTracePointWakeWillChangeInterests );
    }

    notifyAll( kIOPM_OurChangeSetPowerState );
}

//*********************************************************************************
// [private] OurChangeSetPowerState
//
// Instruct our controlling driver to program the hardware for the power state
// change. Wait for async completions.
//*********************************************************************************

void IOService::OurChangeSetPowerState ( void )
{
    MS_PUSH( kIOPM_OurChangeWaitForPowerSettle );
    fMachineState     = kIOPM_DriverThreadCallDone;
    fDriverCallReason = kDriverCallSetPowerState;

    if (notifyControllingDriver() == false)
        notifyControllingDriverDone();
}

//*********************************************************************************
// [private] OurChangeWaitForPowerSettle
//
// Our controlling driver has completed the power state change we initiated.
// Wait for the driver specified settle time to expire.
//*********************************************************************************

void IOService::OurChangeWaitForPowerSettle ( void )
{
    fMachineState = kIOPM_OurChangeNotifyInterestedDriversDidChange;
    startSettleTimer();
}

//*********************************************************************************
// [private] OurChangeNotifyInterestedDriversDidChange
//
// Power has settled on a power change we initiated. Here we notify
// all our interested drivers post-change.
//*********************************************************************************

void IOService::OurChangeNotifyInterestedDriversDidChange ( void )
{
    IOPMrootDomain * rootDomain;
    if ((rootDomain = getPMRootDomain()) == this)
    {
        rootDomain->tracePoint( IS_POWER_DROP ?
            kIOPMTracePointSleepDidChangeInterests :
            kIOPMTracePointWakeDidChangeInterests  );
    }

    notifyAll( kIOPM_OurChangeTellCapabilityDidChange );
}

//*********************************************************************************
// [private] OurChangeTellCapabilityDidChange
//
// For root domain to notify capability power-change.
//*********************************************************************************

void IOService::OurChangeTellCapabilityDidChange ( void )
{
    if (!IS_ROOT_DOMAIN)
        return OurChangeFinish();

    getPMRootDomain()->tracePoint( IS_POWER_DROP ?
        kIOPMTracePointSleepCapabilityClients :
        kIOPMTracePointWakeCapabilityClients  );

    tellSystemCapabilityChange( kIOPM_OurChangeFinish );
}

//*********************************************************************************
// [private] OurChangeFinish
//
// Done with this self-induced power state change.
//*********************************************************************************

void IOService::OurChangeFinish ( void )
{
    all_done();
}

// MARK: -
// MARK: Power Change Initiated by Parent

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
		// TODO: redundant? See handlePowerDomainWillChangeTo()
		setParentInfo( fHeadNoteParentFlags, fHeadNoteParentConnection, true );

        PM_ACTION_2(actionPowerChangeStart, fHeadNotePowerState, &fHeadNoteChangeFlags);

    	// Tell apps and kernel clients
    	fInitialPowerChange = false;
        fMachineState = kIOPM_ParentChangeTellPriorityClientsPowerDown;
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

    if ( fHeadNoteChangeFlags & kIOPMDomainDidChange )
	{
        if ( fHeadNotePowerState > fCurrentPowerState )
        {
            PM_ACTION_2(actionPowerChangeStart,
                fHeadNotePowerState, &fHeadNoteChangeFlags);

            // Parent did change up - start our change up
            fInitialPowerChange = false;            
            ParentChangeTellCapabilityWillChange();
            return IOPMWillAckLater;
        }
        else if (fHeadNoteChangeFlags & kIOPMSynchronize)
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
// [private] ParentChangeTellPriorityClientsPowerDown
//
// All applications and kernel clients have acknowledged our intention to drop
// power.  Here we notify "priority" clients that we are lowering power.
//*********************************************************************************

void IOService::ParentChangeTellPriorityClientsPowerDown ( void )
{
    fMachineState = kIOPM_ParentChangeNotifyInterestedDriversWillChange;
	tellChangeDown2(fHeadNotePowerState);
}

//*********************************************************************************
// [private] ParentChangeTellCapabilityWillChange
//
// All (legacy) applications and kernel clients have acknowledged, extra stage for
// root domain to notify apps and drivers about the system capability change.
//*********************************************************************************

void IOService::ParentChangeTellCapabilityWillChange ( void )
{
    if (!IS_ROOT_DOMAIN)
        return ParentChangeNotifyInterestedDriversWillChange();

    tellSystemCapabilityChange( kIOPM_ParentChangeNotifyInterestedDriversWillChange );
}

//*********************************************************************************
// [private] ParentChangeNotifyInterestedDriversWillChange
//
// All applications and kernel clients have acknowledged our power state change.
// Here we notify interested drivers pre-change.
//*********************************************************************************

void IOService::ParentChangeNotifyInterestedDriversWillChange ( void )
{
	notifyAll( kIOPM_ParentChangeSetPowerState );
}

//*********************************************************************************
// [private] ParentChangeSetPowerState
//
// Instruct our controlling driver to program the hardware for the power state
// change. Wait for async completions.
//*********************************************************************************

void IOService::ParentChangeSetPowerState ( void )
{
    MS_PUSH( kIOPM_ParentChangeWaitForPowerSettle );
    fMachineState     = kIOPM_DriverThreadCallDone;
    fDriverCallReason = kDriverCallSetPowerState;

    if (notifyControllingDriver() == false)
        notifyControllingDriverDone();
}

//*********************************************************************************
// [private] ParentChangeWaitForPowerSettle
//
// Our controlling driver has completed the power state change initiated by our
// parent. Wait for the driver specified settle time to expire.
//*********************************************************************************

void IOService::ParentChangeWaitForPowerSettle ( void )
{
	fMachineState = kIOPM_ParentChangeNotifyInterestedDriversDidChange;
    startSettleTimer();
}

//*********************************************************************************
// [private] ParentChangeNotifyInterestedDriversDidChange
//
// Power has settled on a power change initiated by our parent. Here we notify
// all our interested drivers post-change.
//*********************************************************************************

void IOService::ParentChangeNotifyInterestedDriversDidChange ( void )
{
	notifyAll( kIOPM_ParentChangeTellCapabilityDidChange );	
}

//*********************************************************************************
// [private] ParentChangeTellCapabilityDidChange
//
// For root domain to notify capability power-change.
//*********************************************************************************

void IOService::ParentChangeTellCapabilityDidChange ( void )
{
    if (!IS_ROOT_DOMAIN)
        return ParentChangeAcknowledgePowerChange();

    tellSystemCapabilityChange( kIOPM_ParentChangeAcknowledgePowerChange );
}

//*********************************************************************************
// [private] ParentAcknowledgePowerChange
//
// Acknowledge our power parent that our power change is done. 
//*********************************************************************************

void IOService::ParentChangeAcknowledgePowerChange ( void )
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

// MARK: -
// MARK: Ack and Settle timers

//*********************************************************************************
// [private] settleTimerExpired
//
// Power has settled after our last change.  Notify interested parties that
// there is a new power state.
//*********************************************************************************

void IOService::settleTimerExpired( void )
{
	fSettleTimeUS = 0;
	gIOPMWorkQueue->signalWorkAvailable();
}

//*********************************************************************************
// settle_timer_expired
//
// Holds a retain while the settle timer callout is in flight.
//*********************************************************************************

static void
settle_timer_expired( thread_call_param_t arg0, thread_call_param_t arg1 )
{
	IOService * me = (IOService *) arg0;

	if (gIOPMWorkLoop && gIOPMWorkQueue)
	{
		gIOPMWorkLoop->runAction(
            OSMemberFunctionCast(IOWorkLoop::Action, me, &IOService::settleTimerExpired),
            me);
	}
	me->release();
}

//*********************************************************************************
// [private] startSettleTimer
//
// Calculate a power-settling delay in microseconds and start a timer.
//*********************************************************************************

void IOService::startSettleTimer( void )
{
    AbsoluteTime        deadline;
    IOPMPowerStateIndex i;
    uint32_t            settleTime = 0;
	boolean_t           pending;

	PM_ASSERT_IN_GATE();

    i = fCurrentPowerState;

    // lowering power
    if ( fHeadNotePowerState < fCurrentPowerState )
    {
        while ( i > fHeadNotePowerState )
        {
            settleTime += (uint32_t) fPowerStates[i].settleDownTime;
            i--;
        }
    }

    // raising power
    if ( fHeadNotePowerState > fCurrentPowerState )
    {
        while ( i < fHeadNotePowerState )
        {
            settleTime += (uint32_t) fPowerStates[i+1].settleUpTime;
            i++;
        }
    }

    if (settleTime)
    {
        retain();
        clock_interval_to_deadline(settleTime, kMicrosecondScale, &deadline);
        pending = thread_call_enter_delayed(fSettleTimer, deadline);
        if (pending) release();
    }
}

//*********************************************************************************
// [private] ackTimerTick
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
        case kIOPM_ParentChangeWaitForPowerSettle:
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

#if LOG_SETPOWER_TIMES
                    PMEventDetails *details = PMEventDetails::eventDetails(
                                                kIOPMEventTypeSetPowerStateDelayed, // type
                                                fName,								// who
                                                (uintptr_t)this,					// owner unique
                                                NULL,								// interest name
                                                (uint8_t)getPowerState(),			// old
                                                0,									// new
                                                kIOReturnTimeout,					// result
                                                NS_TO_US(nsec));					// usec completion time
					
                    getPMRootDomain()->recordAndReleasePMEventGated( details );
#endif

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

        case kIOPM_NotifyChildrenStart:
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

#if LOG_SETPOWER_TIMES
                            uint16_t logType = (fDriverCallReason == kDriverCallInformPreChange) 
                                                ? kIOPMEventTypePSWillChangeTo
                                                : kIOPMEventTypePSDidChangeTo;
							
                            PMEventDetails *details = PMEventDetails::eventDetails(
                                                        logType,							  // type
                                                        fName,								  // who
                                                        (uintptr_t)this,					  // owner unique
                                                        nextObject->whatObject->getName(),	  // interest name
                                                        (uint8_t)fCurrentPowerState,		  // old
                                                        (uint8_t)fHeadNotePowerState,		  // new
                                                        kIOReturnTimeout,					  // result
                                                        NS_TO_US(nsec));					  // usec completion time
							
                            getPMRootDomain()->recordAndReleasePMEventGated( details );
#endif

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

        // TODO: aggreggate this
        case kIOPM_OurChangeTellClientsPowerDown:
        case kIOPM_OurChangeTellPriorityClientsPowerDown:
        case kIOPM_OurChangeNotifyInterestedDriversWillChange:
        case kIOPM_ParentChangeTellPriorityClientsPowerDown:
        case kIOPM_ParentChangeNotifyInterestedDriversWillChange:
        case kIOPM_SyncTellClientsPowerDown:
        case kIOPM_SyncTellPriorityClientsPowerDown:
        case kIOPM_SyncNotifyWillChange:
        case kIOPM_TellCapabilityChangeDone:
			// apps didn't respond in time
            cleanClientResponses(true);
            OUR_PMLog(kPMLogClientTardy, 0, 1);
			// tardy equates to approval
			done = true;
            break;

        default:
            PM_LOG1("%s: unexpected ack timer tick (state = %d)\n",
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
	if (done && gIOPMWorkQueue)
		gIOPMWorkQueue->signalWorkAvailable();

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

// MARK: -
// MARK: Client Messaging

//*********************************************************************************
// [private] tellSystemCapabilityChange
//*********************************************************************************

void IOService::tellSystemCapabilityChange( uint32_t nextMS )
{
	MS_PUSH( nextMS );
    fMachineState       = kIOPM_TellCapabilityChangeDone;
    fOutOfBandMessage   = kIOMessageSystemCapabilityChange;

    if (fIsPreChange)
    {
        // Notify app first on pre-change.
        fOutOfBandParameter = kNotifyCapabilityChangeApps;
    }
    else
    {
        // Notify kernel clients first on post-change.
        fOutOfBandParameter = kNotifyCapabilityChangePriority;
    }

    tellClientsWithResponse( fOutOfBandMessage );
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
            (flag = context->responseArray->getObject(clientIndex)) &&
            (flag != kOSBooleanTrue))
        {
            OSString * clientID = 0;
            context->us->messageClient(context->messageType, object, &clientID);
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
    if (logErrors && fResponseArray)
    {
        switch ( fOutOfBandParameter ) {
            case kNotifyApps:
            case kNotifyCapabilityChangeApps:
                if (fNotifyClientArray)
                {
                    IOPMInterestContext context;

                    context.responseArray    = fResponseArray;
                    context.notifyClients    = fNotifyClientArray;
                    context.serialNumber     = fSerialNumber;
                    context.messageType      = kIOMessageCopyClientID;
                    context.notifyType       = kNotifyApps;
                    context.isPreChange      = fIsPreChange;
                    context.enableTracing    = false;
                    context.us               = this;
                    context.maxTimeRequested = 0;
                    context.stateNumber      = fHeadNotePowerState;
                    context.stateFlags       = fHeadNotePowerArrayEntry->capabilityFlags;
                    context.changeFlags      = fHeadNoteChangeFlags;
                    context.errorLog         = "PM notification timeout (%s)\n";

                    applyToInterested(gIOAppPowerStateInterest, logAppTimeouts, (void *) &context);
                }
                break;

            default:
                // kNotifyPriority, kNotifyCapabilityChangePriority
                // TODO: identify the priority client that has not acked
                PM_ERROR("PM priority notification timeout\n");
                if (gIOKitDebug & kIOLogDebugPower)
                {
                    panic("PM priority notification timeout");
                }
                break;
        }
    }

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
}

//*********************************************************************************
// [protected] tellClientsWithResponse
//
// Notify registered applications and kernel clients that we are definitely
// dropping power.
//
// Return true if we don't have to wait for acknowledgements
//*********************************************************************************

bool IOService::tellClientsWithResponse ( int messageType )
{
    IOPMInterestContext     context;
    bool                    isRootDomain = IS_ROOT_DOMAIN;

	PM_ASSERT_IN_GATE();
    assert( fResponseArray == NULL );
    assert( fNotifyClientArray == NULL );

    RD_LOG("tellClientsWithResponse( %s, %d )\n",
        getIOMessageString(messageType), fOutOfBandParameter);

    fResponseArray = OSArray::withCapacity( 1 );
    if (!fResponseArray)
        goto exit;

    fResponseArray->setCapacityIncrement(8);
    if (++fSerialNumber == 0)
        fSerialNumber++;        

    context.responseArray    = fResponseArray;
    context.notifyClients    = 0;
    context.serialNumber     = fSerialNumber;
    context.messageType      = messageType;
    context.notifyType       = fOutOfBandParameter;
    context.isPreChange      = fIsPreChange;
    context.enableTracing    = false;
    context.us               = this;
    context.maxTimeRequested = 0;
    context.stateNumber      = fHeadNotePowerState;
    context.stateFlags       = fHeadNotePowerArrayEntry->capabilityFlags;
    context.changeFlags      = fHeadNoteChangeFlags;
    context.messageFilter    = (isRootDomain) ?
                               OSMemberFunctionCast(
                                    IOPMMessageFilter,
                                    this,
                                    &IOPMrootDomain::systemMessageFilter) : 0;

    switch ( fOutOfBandParameter ) {
        case kNotifyApps:
            applyToInterested( gIOAppPowerStateInterest,
				pmTellAppWithResponse, (void *) &context );

            if (isRootDomain &&
                (fMachineState != kIOPM_OurChangeTellClientsPowerDown) &&
                (fMachineState != kIOPM_SyncTellClientsPowerDown))
            {
                // Notify capability app for tellChangeDown1()
                // but not for askChangeDown().
                context.notifyType  = kNotifyCapabilityChangeApps;
                context.messageType = kIOMessageSystemCapabilityChange;
                applyToInterested( gIOAppPowerStateInterest,
                    pmTellCapabilityAppWithResponse, (void *) &context ); 
                context.notifyType  = fOutOfBandParameter;
                context.messageType = messageType;
            }
            context.maxTimeRequested = k30seconds;

            applyToInterested( gIOGeneralInterest,
				pmTellClientWithResponse, (void *) &context );

            fNotifyClientArray = context.notifyClients;
            break;

        case kNotifyPriority:
            context.enableTracing = isRootDomain;
            applyToInterested( gIOPriorityPowerStateInterest,
				pmTellClientWithResponse, (void *) &context );

            if (isRootDomain)
            {
                // Notify capability clients for tellChangeDown2().
                context.notifyType  = kNotifyCapabilityChangePriority;
                context.messageType = kIOMessageSystemCapabilityChange;
                applyToInterested( gIOPriorityPowerStateInterest,
                    pmTellCapabilityClientWithResponse, (void *) &context );
            }
            break;

        case kNotifyCapabilityChangeApps:
            applyToInterested( gIOAppPowerStateInterest,
				pmTellCapabilityAppWithResponse, (void *) &context );
            fNotifyClientArray = context.notifyClients;
            context.maxTimeRequested = k30seconds;
            break;

        case kNotifyCapabilityChangePriority:
            applyToInterested( gIOPriorityPowerStateInterest,
				pmTellCapabilityClientWithResponse, (void *) &context );
            break;
    }

    // do we have to wait for somebody?
    if ( !checkForDone() )
    {
        OUR_PMLog(kPMLogStartAckTimer, context.maxTimeRequested, 0);
        if (context.enableTracing)
            getPMRootDomain()->traceDetail( context.maxTimeRequested / 1000 );
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
    IOPMInterestContext *   context = (IOPMInterestContext *) arg;
    IOServicePM *           pwrMgt = context->us->pwrMgt;
    uint32_t                msgIndex, msgRef, msgType;
#if LOG_APP_RESPONSE_TIMES
    AbsoluteTime            now;
#endif

    if (!OSDynamicCast(_IOServiceInterestNotifier, object))
        return;

    if (context->messageFilter &&
        !context->messageFilter(context->us, object, context, 0, 0))
    {
        if (kIOLogDebugPower & gIOKitDebug)
        {
            // Log client pid/name and client array index.
            OSString * clientID = 0;
            context->us->messageClient(kIOMessageCopyClientID, object, &clientID);
            PM_LOG("%s DROP App %s, %s\n",
                context->us->getName(),
                getIOMessageString(context->messageType),
                clientID ? clientID->getCStringNoCopy() : "");
            if (clientID) clientID->release();
        }
        return;
    }

    // Create client array (for tracking purposes) only if the service
    // has app clients. Usually only root domain does.
    if (0 == context->notifyClients)
        context->notifyClients = OSArray::withCapacity( 32 );

    msgType  = context->messageType;
    msgIndex = context->responseArray->getCount();
    msgRef   = ((context->serialNumber & 0xFFFF) << 16) + (msgIndex & 0xFFFF);

    OUR_PMLog(kPMLogAppNotify, msgType, msgRef);
    if (kIOLogDebugPower & gIOKitDebug)
    {
        // Log client pid/name and client array index.
        OSString * clientID = 0;
        context->us->messageClient(kIOMessageCopyClientID, object, &clientID);
        PM_LOG("%s MESG App(%u) %s, %s\n",
            context->us->getName(),
            msgIndex, getIOMessageString(msgType),
            clientID ? clientID->getCStringNoCopy() : "");
        if (clientID) clientID->release();
    }

#if LOG_APP_RESPONSE_TIMES
    OSNumber * num;
    clock_get_uptime(&now);
    num = OSNumber::withNumber(AbsoluteTime_to_scalar(&now), sizeof(uint64_t) * 8);
    if (num)
    {
        context->responseArray->setObject(msgIndex, num);
        num->release();
    }
    else
#endif
    context->responseArray->setObject(msgIndex, kOSBooleanFalse);

    if (context->notifyClients)
        context->notifyClients->setObject(msgIndex, object);

    context->us->messageClient(msgType, object, (void *) msgRef);
}

//*********************************************************************************
// [static private] pmTellClientWithResponse
//
// We send a message to an in-kernel client, and we expect a response,
// so we compute a cookie we can identify the response with.
//*********************************************************************************

void IOService::pmTellClientWithResponse ( OSObject * object, void * arg )
{
    IOPowerStateChangeNotification  notify;
    IOPMInterestContext *           context = (IOPMInterestContext *) arg;
    OSObject *                      replied = kOSBooleanTrue;
    _IOServiceInterestNotifier *    notifier;
    uint32_t                        msgIndex, msgRef, msgType;
    IOReturn                        retCode;

    if (context->messageFilter &&
        !context->messageFilter(context->us, object, context, 0, 0))
    {
        if ((kIOLogDebugPower & gIOKitDebug) &&
            (OSDynamicCast(_IOServiceInterestNotifier, object)))
        {
            _IOServiceInterestNotifier *n = (_IOServiceInterestNotifier *) object;
            PM_LOG("%s DROP Client %s, notifier %p, handler %p\n",
                context->us->getName(),
                getIOMessageString(context->messageType),
                object, n->handler);
		}        
        return;
    }

    notifier = OSDynamicCast(_IOServiceInterestNotifier, object);
    msgType  = context->messageType;
    msgIndex = context->responseArray->getCount();
    msgRef   = ((context->serialNumber & 0xFFFF) << 16) + (msgIndex & 0xFFFF);

    IOServicePM * pwrMgt = context->us->pwrMgt;
    if (gIOKitDebug & kIOLogPower) {
		OUR_PMLog(kPMLogClientNotify, msgRef, msgType);
		if (OSDynamicCast(IOService, object)) {
			const char *who = ((IOService *) object)->getName();
			gPlatform->PMLog(who, kPMLogClientNotify, (uintptr_t) object, 0);
		}
        else if (notifier) {
			OUR_PMLog(kPMLogClientNotify, (uintptr_t) notifier->handler, 0);
        }
    }
    if ((kIOLogDebugPower & gIOKitDebug) && notifier)
    {
        PM_LOG("%s MESG Client %s, notifier %p, handler %p\n",
            context->us->getName(),
            getIOMessageString(msgType),
            object, notifier->handler);
    }

    notify.powerRef    = (void *)(uintptr_t) msgRef;
    notify.returnValue = 0;
    notify.stateNumber = context->stateNumber;
    notify.stateFlags  = context->stateFlags;

    if (context->enableTracing && (notifier != 0))
    {
        uint32_t detail = ((msgIndex & 0xff) << 24) |
                          ((msgType & 0xfff) << 12) |
                          (((uintptr_t) notifier->handler) & 0xfff);
        getPMRootDomain()->traceDetail( detail );
    }

    retCode = context->us->messageClient(msgType, object, (void *) &notify);
    if ( kIOReturnSuccess == retCode )
    {
        if ( 0 == notify.returnValue )
        {
            // client doesn't want time to respond
			OUR_PMLog(kPMLogClientAcknowledge, msgRef, (uintptr_t) object);
        }
        else
        {
            replied = kOSBooleanFalse;
            if ( notify.returnValue > context->maxTimeRequested )
            {
                if (notify.returnValue > kPriorityClientMaxWait)
                {
                    context->maxTimeRequested = kPriorityClientMaxWait;
                    PM_ERROR("%s: client %p returned %llu for %s\n",
                        context->us->getName(),
                        notifier ? (void *)  notifier->handler : object,
                        (uint64_t) notify.returnValue,
                        getIOMessageString(msgType));
                }
                else
                    context->maxTimeRequested = notify.returnValue;
            }
        }
    }
    else
    {
        // not a client of ours
        // so we won't be waiting for response
		OUR_PMLog(kPMLogClientAcknowledge, msgRef, 0);
    }

    context->responseArray->setObject(msgIndex, replied);
}

//*********************************************************************************
// [static private] pmTellCapabilityAppWithResponse
//*********************************************************************************

void IOService::pmTellCapabilityAppWithResponse ( OSObject * object, void * arg )
{
    IOPMSystemCapabilityChangeParameters msgArg;
    IOPMInterestContext *       context = (IOPMInterestContext *) arg;
    OSObject *                  replied = kOSBooleanTrue;
    IOServicePM *               pwrMgt = context->us->pwrMgt;
    uint32_t                    msgIndex, msgRef, msgType;
#if LOG_APP_RESPONSE_TIMES
    AbsoluteTime                now;
#endif

    if (!OSDynamicCast(_IOServiceInterestNotifier, object))
        return;

    memset(&msgArg, 0, sizeof(msgArg));
    if (context->messageFilter &&
        !context->messageFilter(context->us, object, context, &msgArg, &replied))
    {
        return;
    }

    // Create client array (for tracking purposes) only if the service
    // has app clients. Usually only root domain does.
    if (0 == context->notifyClients)
        context->notifyClients = OSArray::withCapacity( 32 );

    msgType  = context->messageType;
    msgIndex = context->responseArray->getCount();
    msgRef   = ((context->serialNumber & 0xFFFF) << 16) + (msgIndex & 0xFFFF);

    OUR_PMLog(kPMLogAppNotify, msgType, msgRef);
    if (kIOLogDebugPower & gIOKitDebug)
    {
        // Log client pid/name and client array index.
        OSString * clientID = 0;
        context->us->messageClient(kIOMessageCopyClientID, object, &clientID);
        PM_LOG("%s MESG App(%u) %s, wait %u, %s\n",
            context->us->getName(),
            msgIndex, getIOMessageString(msgType),
            (replied != kOSBooleanTrue),
            clientID ? clientID->getCStringNoCopy() : "");
        if (clientID) clientID->release();
    }

    msgArg.notifyRef = msgRef;
    msgArg.maxWaitForReply = 0;

    if (replied == kOSBooleanTrue)
    {
        msgArg.notifyRef = 0;
        context->responseArray->setObject(msgIndex, kOSBooleanTrue);
        if (context->notifyClients)
            context->notifyClients->setObject(msgIndex, kOSBooleanTrue);
    }
    else
    {
#if LOG_APP_RESPONSE_TIMES
        OSNumber * num;
        clock_get_uptime(&now);
        num = OSNumber::withNumber(AbsoluteTime_to_scalar(&now), sizeof(uint64_t) * 8);
        if (num)
        {
            context->responseArray->setObject(msgIndex, num);
            num->release();
        }
        else
#endif
        context->responseArray->setObject(msgIndex, kOSBooleanFalse);

        if (context->notifyClients)
            context->notifyClients->setObject(msgIndex, object);
    }

    context->us->messageClient(msgType, object, (void *) &msgArg, sizeof(msgArg));
}

//*********************************************************************************
// [static private] pmTellCapabilityClientWithResponse
//*********************************************************************************

void IOService::pmTellCapabilityClientWithResponse(
    OSObject * object, void * arg )
{
    IOPMSystemCapabilityChangeParameters msgArg;
    IOPMInterestContext *           context = (IOPMInterestContext *) arg;
    OSObject *                      replied = kOSBooleanTrue;
    _IOServiceInterestNotifier *    notifier;
    uint32_t                        msgIndex, msgRef, msgType;
    IOReturn                        retCode;

    memset(&msgArg, 0, sizeof(msgArg));
    if (context->messageFilter &&
        !context->messageFilter(context->us, object, context, &msgArg, 0))
    {
        if ((kIOLogDebugPower & gIOKitDebug) &&
            (OSDynamicCast(_IOServiceInterestNotifier, object)))
        {
            _IOServiceInterestNotifier *n = (_IOServiceInterestNotifier *) object;
            PM_LOG("%s DROP Client %s, notifier %p, handler %p\n",
                context->us->getName(),
                getIOMessageString(context->messageType),
                object, n->handler);
		}        
        return;
    }

    notifier = OSDynamicCast(_IOServiceInterestNotifier, object);
    msgType  = context->messageType;
    msgIndex = context->responseArray->getCount();
    msgRef   = ((context->serialNumber & 0xFFFF) << 16) + (msgIndex & 0xFFFF);

    IOServicePM * pwrMgt = context->us->pwrMgt;
    if (gIOKitDebug & kIOLogPower) {
		OUR_PMLog(kPMLogClientNotify, msgRef, msgType);
		if (OSDynamicCast(IOService, object)) {
			const char *who = ((IOService *) object)->getName();
			gPlatform->PMLog(who, kPMLogClientNotify, (uintptr_t) object, 0);
		}
        else if (notifier) {
			OUR_PMLog(kPMLogClientNotify, (uintptr_t) notifier->handler, 0);
		}
    }
    if ((kIOLogDebugPower & gIOKitDebug) && notifier)
    {
        PM_LOG("%s MESG Client %s, notifier %p, handler %p\n",
            context->us->getName(),
            getIOMessageString(msgType),
            object, notifier->handler);
    }

    msgArg.notifyRef = msgRef;
    msgArg.maxWaitForReply = 0;

    if (context->enableTracing && (notifier != 0))
    {
        uint32_t detail = ((msgIndex & 0xff) << 24) |
                          ((msgType & 0xfff) << 12) |
                          (((uintptr_t) notifier->handler) & 0xfff);
        getPMRootDomain()->traceDetail( detail );
    }

    retCode = context->us->messageClient(
        msgType, object, (void *) &msgArg, sizeof(msgArg));

    if ( kIOReturnSuccess == retCode )
    {
        if ( 0 == msgArg.maxWaitForReply )
        {
            // client doesn't want time to respond
			OUR_PMLog(kPMLogClientAcknowledge, msgRef, (uintptr_t) object);
        }
        else
        {
            replied = kOSBooleanFalse;
            if ( msgArg.maxWaitForReply > context->maxTimeRequested )
            {
                if (msgArg.maxWaitForReply > kCapabilityClientMaxWait)
                {
                    context->maxTimeRequested = kCapabilityClientMaxWait;
                    PM_ERROR("%s: client %p returned %u for %s\n",
                        context->us->getName(),
                        notifier ? (void *) notifier->handler : object,
                        msgArg.maxWaitForReply,
                        getIOMessageString(msgType));
                }
                else
                    context->maxTimeRequested = msgArg.maxWaitForReply;
            }
        }
    }
    else
    {
        // not a client of ours
        // so we won't be waiting for response
		OUR_PMLog(kPMLogClientAcknowledge, msgRef, 0);
    }

    context->responseArray->setObject(msgIndex, replied);
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
    IOPMInterestContext     context;

    RD_LOG("tellClients( %s )\n", getIOMessageString(messageType));

    memset(&context, 0, sizeof(context));
    context.messageType   = messageType;
    context.isPreChange   = fIsPreChange;
    context.us            = this;
    context.stateNumber   = fHeadNotePowerState;
    context.stateFlags    = fHeadNotePowerArrayEntry->capabilityFlags;
    context.changeFlags   = fHeadNoteChangeFlags;
    context.messageFilter = (IS_ROOT_DOMAIN) ?
                            OSMemberFunctionCast(
                                IOPMMessageFilter,
                                this,
                                &IOPMrootDomain::systemMessageFilter) : 0;

    context.notifyType    = kNotifyPriority;
    applyToInterested( gIOPriorityPowerStateInterest,
        tellKernelClientApplier, (void *) &context );

    context.notifyType    = kNotifyApps;
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
    IOPowerStateChangeNotification	notify;
    IOPMInterestContext *           context = (IOPMInterestContext *) arg;

    if (context->messageFilter &&
        !context->messageFilter(context->us, object, context, 0, 0))
    {
        if ((kIOLogDebugPower & gIOKitDebug) &&
            (OSDynamicCast(_IOServiceInterestNotifier, object)))
        {
            _IOServiceInterestNotifier *n = (_IOServiceInterestNotifier *) object;
            PM_LOG("%s DROP Client %s, notifier %p, handler %p\n",
                context->us->getName(),
                IOService::getIOMessageString(context->messageType),
                object, n->handler);
		}
        return;
    }

    notify.powerRef     = (void *) 0;
    notify.returnValue	= 0;
    notify.stateNumber	= context->stateNumber;
    notify.stateFlags	= context->stateFlags;

    context->us->messageClient(context->messageType, object, &notify);

    if ((kIOLogDebugPower & gIOKitDebug) &&
        (OSDynamicCast(_IOServiceInterestNotifier, object)))
    {
        _IOServiceInterestNotifier *n = (_IOServiceInterestNotifier *) object;
        PM_LOG("%s MESG Client %s, notifier %p, handler %p\n",
            context->us->getName(),
            IOService::getIOMessageString(context->messageType),
            object, n->handler);
    }
}

//*********************************************************************************
// [private] tellAppClientApplier
//
// Message a registered application.
//*********************************************************************************

static void tellAppClientApplier ( OSObject * object, void * arg )
{
    IOPMInterestContext * context = (IOPMInterestContext *) arg;

    if (context->messageFilter &&
        !context->messageFilter(context->us, object, context, 0, 0))
    {
        if (kIOLogDebugPower & gIOKitDebug)
        {
            // Log client pid/name and client array index.
            OSString * clientID = 0;
            context->us->messageClient(kIOMessageCopyClientID, object, &clientID);
            PM_LOG("%s DROP App %s, %s\n",
                context->us->getName(),
                IOService::getIOMessageString(context->messageType),
                clientID ? clientID->getCStringNoCopy() : "");
            if (clientID) clientID->release();
        }
        return;
    }

    if (kIOLogDebugPower & gIOKitDebug)
    {
        // Log client pid/name and client array index.
        OSString * clientID = 0;
        context->us->messageClient(kIOMessageCopyClientID, object, &clientID);
        PM_LOG("%s MESG App %s, %s\n",
            context->us->getName(),
            IOService::getIOMessageString(context->messageType),
            clientID ? clientID->getCStringNoCopy() : "");
        if (clientID) clientID->release();
    }

    context->us->messageClient(context->messageType, object, 0);
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

bool IOService::responseValid ( uint32_t refcon, int pid )
{
    UInt16			serialComponent;
    UInt16			ordinalComponent;
    OSObject *		theFlag;

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
        uint64_t        nsec;
        OSString        *name = IOCopyLogNameForPID(pid);

        clock_get_uptime(&now);
        AbsoluteTime_to_scalar(&start) = num->unsigned64BitValue();
        SUB_ABSOLUTETIME(&now, &start);
        absolutetime_to_nanoseconds(now, &nsec);
		
        PMEventDetails *details = PMEventDetails::eventDetails(
                                    kIOPMEventTypeAppResponse,				// type
                                    name ? name->getCStringNoCopy() : "",   // who
                                    (uintptr_t)pid,							// owner unique
                                    NULL,									// interest name
                                    0,										// old
                                    0,										// new
                                    0,										// result
                                    NS_TO_US(nsec));						// usec completion time
		
        getPMRootDomain()->recordAndReleasePMEventGated( details );

        if (kIOLogDebugPower & gIOKitDebug)
        {
            PM_LOG("Ack(%u) %u ms\n",
                (uint32_t) ordinalComponent,
                NS_TO_MS(nsec));
        }

        // > 100 ms
        if (nsec > LOG_APP_RESPONSE_TIMES)
        {
            PM_LOG("PM response took %d ms (%s)\n", NS_TO_MS(nsec),
                name ? name->getCStringNoCopy() : "");

            if (nsec > LOG_APP_RESPONSE_MSG_TRACER)
            {
                // TODO: populate the messageType argument            
                getPMRootDomain()->pmStatsRecordApplicationResponse(
                    gIOPMStatsApplicationResponseSlow, 
                    name ? name->getCStringNoCopy() : "", 0,
                    NS_TO_MS(nsec), pid);
            }            
        }

        if (name)
            name->release();
#endif
        theFlag = kOSBooleanFalse;
    }

    if ( kOSBooleanFalse == theFlag ) 
    {
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

// MARK: -
// MARK: Driver Overrides

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
       if ( (domainState & fPowerStates[i].inputPowerFlags) ==
			               fPowerStates[i].inputPowerFlags )
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
        if ( (domainState & fPowerStates[i].inputPowerFlags) ==
			fPowerStates[i].inputPowerFlags )
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
        if ( (domainState & fPowerStates[i].inputPowerFlags) ==
			fPowerStates[i].inputPowerFlags )
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

// MARK: -
// MARK: PM State Machine

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

	PM_LOG1("[+ %02lx] %p [%p %s] %p %p %p\n",
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
		PM_LOG1("[+ %02lx] %p [%p %s] %p %p %p\n",
			(long)req->getType(), req,
			req->getTarget(), req->getTarget()->getName(),
			req->fArg0, req->fArg1, req->fArg2);
	}

	gIOPMRequestQueue->queuePMRequestChain( requests, count );
}

//*********************************************************************************
// [private] servicePMRequestQueue
//
// Called from IOPMRequestQueue::checkForWork().
//*********************************************************************************

bool IOService::servicePMRequestQueue(
	IOPMRequest *		request,
	IOPMRequestQueue *	queue )
{
    bool more;

    if (initialized)
    {
        // Work queue will immediately execute the queue'd request if possible.
        // If execution blocks, the work queue will wait for a producer signal.
        // Only need to signal more when completing attached requests.

        more = gIOPMWorkQueue->queuePMRequest(request, pwrMgt);
        return more;
    }

    // Calling PM without PMinit() is not allowed, fail the request.

    PM_LOG("%s: PM not initialized\n", getName());
	fAdjustPowerScheduled = false;
	more = gIOPMFreeQueue->queuePMRequest(request);
    if (more) gIOPMWorkQueue->incrementProducerCount();
	return more;
}

//*********************************************************************************
// [private] servicePMFreeQueue
//
// Called from IOPMCompletionQueue::checkForWork().
//*********************************************************************************

bool IOService::servicePMFreeQueue(
	IOPMRequest *		  request,
	IOPMCompletionQueue * queue )
{
	bool            more = request->getNextRequest();
    IOPMRequest *   root = request->getRootRequest();

    if (root && (root != request))
        more = true;
    if (more)
        gIOPMWorkQueue->incrementProducerCount();

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

	PM_LOG1("[- %02x] %p [%p %s] state %d, busy %d\n",
		request->getType(), request, this, getName(),
		fMachineState, gIOPMBusyCount);

	// Catch requests created by idleTimerExpired().

	if ((request->getType() == kIOPMRequestTypeActivityTickle) &&
	    (request->fArg1 == (void *) (uintptr_t) false))
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

    // If the request is linked, then Work queue has already incremented its
    // producer count.

	return (gIOPMFreeQueue->queuePMRequest( request ));
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
			if (fDriverCallBusy)
                reason = 5 + fDriverCallReason;
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
			PM_LOG1("[B %02x] %p [%p %s] state %d, reason %d\n",
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
		PM_LOG1("[W %02x] %p [%p %s] state %d\n",
			request->getType(), request, this, getName(), fMachineState);

		gIOPMRequest = request;
        gIOPMWorkCount++;

		// Every PM machine states must be handled in one of the cases below.

		switch ( fMachineState )
		{
			case kIOPM_Finished:
				executePMRequest( request );
				break;

			case kIOPM_OurChangeTellClientsPowerDown:
                // Root domain might self cancel due to assertions.
                if (IS_ROOT_DOMAIN)
                {
                    bool cancel = (bool) fDoNotPowerDown;
                    getPMRootDomain()->askChangeDownDone(
                        &fHeadNoteChangeFlags, &cancel);
                    fDoNotPowerDown = cancel;
                }

                // askChangeDown() done, was it vetoed?
				if (!fDoNotPowerDown)
				{
                    if (IS_ROOT_DOMAIN) {
                        PMEventDetails *details = PMEventDetails::eventDetails(
                                                    kIOPMEventTypeAppNotificationsFinished,
                                                    NULL,
                                                    0,
                                                    0);
						
						getPMRootDomain()->recordAndReleasePMEventGated( details );
                    }

					// no, we can continue
					OurChangeTellClientsPowerDown();
				}
				else
				{
                    if (IS_ROOT_DOMAIN) {
                        PMEventDetails *details = PMEventDetails::eventDetails(
                                                    kIOPMEventTypeSleepDone,
                                                    NULL,
                                                    1, /* reason: 1 == Ask clients succeeded */
                                                    kIOReturnAborted); /* result */
			  
                        getPMRootDomain()->recordAndReleasePMEventGated( details );
                    }

					OUR_PMLog(kPMLogIdleCancel, (uintptr_t) this, fMachineState);
					PM_ERROR("%s: idle cancel\n", fName);
					// yes, rescind the warning
					tellNoChangeDown(fHeadNotePowerState);
					// mark the change note un-actioned
					fHeadNoteChangeFlags |= kIOPMNotDone;
					// and we're done
					OurChangeFinish();
				}
				break;

			case kIOPM_OurChangeTellPriorityClientsPowerDown:
				// tellChangeDown(kNotifyApps) done, was it cancelled?
				if (fDoNotPowerDown)
				{
                    if (IS_ROOT_DOMAIN) {
						PMEventDetails *details = PMEventDetails::eventDetails(
                                                    kIOPMEventTypeSleepDone,
                                                    NULL,
                                                    2, /* reason: 2 == Client cancelled wake */
                                                    kIOReturnAborted); /* result */
						
						getPMRootDomain()->recordAndReleasePMEventGated( details );
                    }
					OUR_PMLog(kPMLogIdleCancel, (uintptr_t) this, fMachineState);
					PM_ERROR("%s: idle revert\n", fName);
					// no, tell clients we're back in the old state
					tellChangeUp(fCurrentPowerState);
					// mark the change note un-actioned
					fHeadNoteChangeFlags |= kIOPMNotDone;
					// and we're done
					OurChangeFinish();
				}
				else
				{
                    if (IS_ROOT_DOMAIN) {
						PMEventDetails *details = PMEventDetails::eventDetails(
                                                    kIOPMEventTypeAppNotificationsFinished,
                                                    NULL,
                                                    2, /* reason: 2 == TellPriorityClientsDone */																	
                                                    kIOReturnSuccess); /* result */
						
						getPMRootDomain()->recordAndReleasePMEventGated( details );
                    }
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

            case kIOPM_OurChangeTellCapabilityDidChange:
                OurChangeTellCapabilityDidChange();
                break;

			case kIOPM_OurChangeFinish:
				OurChangeFinish();
				break;

			case kIOPM_ParentChangeTellPriorityClientsPowerDown:
				ParentChangeTellPriorityClientsPowerDown();
				break;

			case kIOPM_ParentChangeNotifyInterestedDriversWillChange:
				ParentChangeNotifyInterestedDriversWillChange();
				break;

			case kIOPM_ParentChangeSetPowerState:
				ParentChangeSetPowerState();
				break;

			case kIOPM_ParentChangeWaitForPowerSettle:
				ParentChangeWaitForPowerSettle();
				break;

			case kIOPM_ParentChangeNotifyInterestedDriversDidChange:
				ParentChangeNotifyInterestedDriversDidChange();
				break;

            case kIOPM_ParentChangeTellCapabilityDidChange:
                ParentChangeTellCapabilityDidChange();
                break;

			case kIOPM_ParentChangeAcknowledgePowerChange:
				ParentChangeAcknowledgePowerChange();
				break;

			case kIOPM_DriverThreadCallDone:
				if (fDriverCallReason == kDriverCallSetPowerState)
					notifyControllingDriverDone();
				else
					notifyInterestedDriversDone();
				break;

			case kIOPM_NotifyChildrenOrdered:
				notifyChildrenOrdered();
				break;

			case kIOPM_NotifyChildrenDelayed:
				notifyChildrenDelayed();
				break;

            case kIOPM_NotifyChildrenStart:
                PM_LOG2("%s: kIOPM_NotifyChildrenStart done\n", getName());
                MS_POP();   // from notifyInterestedDriversDone()
                notifyChildren();
                break;

            case kIOPM_SyncTellClientsPowerDown:
                // Root domain might self cancel due to assertions.
                if (IS_ROOT_DOMAIN)
                {
                    bool cancel = (bool) fDoNotPowerDown;
                    getPMRootDomain()->askChangeDownDone(
                        &fHeadNoteChangeFlags, &cancel);
                    fDoNotPowerDown = cancel;
                }                
				if (!fDoNotPowerDown)
				{
                    fMachineState = kIOPM_SyncTellPriorityClientsPowerDown;
                    fOutOfBandParameter = kNotifyApps;
                    tellChangeDown(fHeadNotePowerState);
				}
				else
				{
					OUR_PMLog(kPMLogIdleCancel, (uintptr_t) this, fMachineState);
					PM_ERROR("%s: idle cancel\n", fName);
					tellNoChangeDown(fHeadNotePowerState);
					fHeadNoteChangeFlags |= kIOPMNotDone;
					OurChangeFinish();
				}
                break;

            case kIOPM_SyncTellPriorityClientsPowerDown:
				if (!fDoNotPowerDown)
				{
                    fMachineState = kIOPM_SyncNotifyWillChange;
                    fOutOfBandParameter = kNotifyPriority;
                    tellChangeDown(fHeadNotePowerState);
                }
                else
                {
					OUR_PMLog(kPMLogIdleCancel, (uintptr_t) this, fMachineState);
					PM_ERROR("%s: idle revert\n", fName);
					tellChangeUp(fCurrentPowerState);
					fHeadNoteChangeFlags |= kIOPMNotDone;
					OurChangeFinish();
				}
				break;

            case kIOPM_SyncNotifyWillChange:
                if (kIOPMSyncNoChildNotify & fHeadNoteChangeFlags)
                {
                    fMachineState = kIOPM_SyncFinish;
                    continue;
                }
                fMachineState     = kIOPM_SyncNotifyDidChange;
                fDriverCallReason = kDriverCallInformPreChange;
                notifyChildren();
                break;

            case kIOPM_SyncNotifyDidChange:
                fIsPreChange = false;

                if (fHeadNoteChangeFlags & kIOPMParentInitiated)
                    fMachineState = kIOPM_SyncFinish;
                else
                    fMachineState = kIOPM_SyncTellCapabilityDidChange;

                fDriverCallReason = kDriverCallInformPostChange;
                notifyChildren();
                break;

            case kIOPM_SyncTellCapabilityDidChange:
                tellSystemCapabilityChange( kIOPM_SyncFinish );
                break;

            case kIOPM_SyncFinish:
                if (fHeadNoteChangeFlags & kIOPMParentInitiated)
                    ParentChangeAcknowledgePowerChange();
                else
                    OurChangeFinish();
                break;

            case kIOPM_TellCapabilityChangeDone:
                if (fIsPreChange)
                {
                    if (fOutOfBandParameter == kNotifyCapabilityChangePriority)
                    {
                        MS_POP();   // tellSystemCapabilityChange()
                        continue;
                    }
                    fOutOfBandParameter = kNotifyCapabilityChangePriority;
                }
                else
                {
                    if (fOutOfBandParameter == kNotifyCapabilityChangeApps)
                    {
                        MS_POP();   // tellSystemCapabilityChange()
                        continue;
                    }
                    fOutOfBandParameter = kNotifyCapabilityChangeApps;
                }
                tellClientsWithResponse( fOutOfBandMessage );
                break;

			default:
				panic("servicePMWorkQueue: unknown machine state %x",
                    fMachineState);
		}

		gIOPMRequest = 0;

		if (fMachineState == kIOPM_Finished)
		{
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
                fIdleTimerPeriod = (uintptr_t) request->fArg0;

                if ((false == fLockedFlags.PMStop) && (fIdleTimerPeriod > 0))
                {
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

	PM_LOG1("[A %02x] %p [%p %s] state %d\n",
		request->getType(), request, this, getName(), fMachineState);

	switch ( request->getType() )
	{
		case kIOPMRequestTypeAllowPowerChange:
		case kIOPMRequestTypeCancelPowerChange:
			// Check if we are expecting this response.
			if (responseValid((uint32_t)(uintptr_t) request->fArg0,
                              (int)(uintptr_t) request->fArg1))
			{
				if (kIOPMRequestTypeCancelPowerChange == request->getType())
                {
                    // Clients are not allowed to cancel when kIOPMSkipAskPowerDown
                    // flag is set. Only root domain will set this flag.

                    if ((fHeadNoteChangeFlags & kIOPMSkipAskPowerDown) == 0)
                    {
                        fDoNotPowerDown = true;

                        OSString * name = (OSString *) request->fArg2;
                        getPMRootDomain()->pmStatsRecordApplicationResponse(
                            gIOPMStatsApplicationResponseCancel,
                            name ? name->getCStringNoCopy() : "", 0,
                            0, (int)(uintptr_t) request->fArg1);
                    }
                }

				if (checkForDone())
				{
					stop_ack_timer();
                    cleanClientResponses(false);
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
                    PM_LOG("%s::setPowerState(%p, %lu -> %lu) async took %d ms\n",
                        fName, this, fCurrentPowerState, fHeadNotePowerState, NS_TO_MS(nsec));
				
				PMEventDetails *details = PMEventDetails::eventDetails(
                                            kIOPMEventTypeSetPowerStateDelayed,		// type
                                            fName,									// who
                                            (uintptr_t)this,						// owner unique
                                            NULL,									// interest name
                                            (uint8_t)getPowerState(),				// old
                                            (uint8_t)fHeadNotePowerState,			// new
                                            0,										// result
                                            NS_TO_US(nsec));						// usec completion time
				
				getPMRootDomain()->recordAndReleasePMEventGated( details );
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
             || (fMachineState == kIOPM_OurChangeTellPriorityClientsPowerDown) 
             || (fMachineState == kIOPM_SyncTellClientsPowerDown)
             || (fMachineState == kIOPM_SyncTellPriorityClientsPowerDown))
			{
				OUR_PMLog(kPMLogIdleCancel, (uintptr_t) this, fMachineState);
                PM_LOG2("%s: cancel from machine state %d\n",
                    getName(), fMachineState);
				fDoNotPowerDown = true;
                // Stop waiting for app replys.
				if ((fMachineState == kIOPM_OurChangeTellPriorityClientsPowerDown) ||
                    (fMachineState == kIOPM_SyncTellPriorityClientsPowerDown))
					cleanClientResponses(false);
				more = true;
			}
			break;

        case kIOPMRequestTypeChildNotifyDelayCancel:
            if (fMachineState == kIOPM_NotifyChildrenDelayed)
            {
                PM_LOG2("%s: delay notify cancelled\n", getName());                
                notifyChildrenDelayed();
            }
            break;

		default:
			panic("servicePMReplyQueue: unknown reply type %x",
                request->getType());
	}

	more |= gIOPMFreeQueue->queuePMRequest(request);
    if (more)
        gIOPMWorkQueue->incrementProducerCount();

	return more;
}

//*********************************************************************************
// [private] assertPMDriverCall / deassertPMDriverCall
//*********************************************************************************

bool IOService::assertPMDriverCall(
    IOPMDriverCallEntry *   entry,
    IOOptionBits            options,
    IOPMinformee *          inform )
{
    IOService * target = 0;
    bool        ok = false;

    if (!initialized)
        return false;

    PM_LOCK();

    if (fLockedFlags.PMStop)
    {
        goto fail;
    }
    
    if (((options & kIOPMADC_NoInactiveCheck) == 0) && isInactive())
    {
        goto fail;
    }

    if (inform)
    {
        if (!inform->active)
        {
            goto fail;
        }
        target = inform->whatObject;
        if (target->isInactive())
        {
            goto fail;
        }
    }

    entry->thread = current_thread();
    entry->target = target;
    queue_enter(&fPMDriverCallQueue, entry, IOPMDriverCallEntry *, link);
    ok = true;

fail:
    PM_UNLOCK();

    return ok;
}

void IOService::deassertPMDriverCall( IOPMDriverCallEntry * entry )
{
    bool wakeup = false;

    PM_LOCK();

    assert( !queue_empty(&fPMDriverCallQueue) );
    queue_remove(&fPMDriverCallQueue, entry, IOPMDriverCallEntry *, link);
    if (fLockedFlags.PMDriverCallWait)
    {
        wakeup = true;
    }

    PM_UNLOCK();

    if (wakeup)
        PM_LOCK_WAKEUP(&fPMDriverCallQueue);
}

void IOService::waitForPMDriverCall( IOService * target )
{
    const IOPMDriverCallEntry * entry;
    thread_t                    thread = current_thread();
    AbsoluteTime                deadline;
    int                         waitResult;
    bool                        log = true;
    bool                        wait;

    do {
        wait = false;
        queue_iterate(&fPMDriverCallQueue, entry, const IOPMDriverCallEntry *, link)
        {
            // Target of interested driver call
            if (target && (target != entry->target))
                continue;

            if (entry->thread == thread)
            {
                if (log)
                {
                    PM_LOG("%s: %s(%s) on PM thread\n",
                        fName, __FUNCTION__, target ? target->getName() : "");
                    OSReportWithBacktrace("%s: %s(%s) on PM thread\n",
                        fName, __FUNCTION__, target ? target->getName() : "");
                    log = false;
                }
                continue;
            }
            
            wait = true;
            break;
        }

        if (wait)
        {
            fLockedFlags.PMDriverCallWait = true;
            clock_interval_to_deadline(15, kSecondScale, &deadline);
            waitResult = PM_LOCK_SLEEP(&fPMDriverCallQueue, deadline);
            fLockedFlags.PMDriverCallWait = false;
            if (THREAD_TIMED_OUT == waitResult)
            {
                PM_ERROR("%s: waitForPMDriverCall timeout\n", fName);
                wait = false;
            }
        }
    } while (wait);
}

//*********************************************************************************
// [private] Debug helpers
//*********************************************************************************

const char * IOService::getIOMessageString( uint32_t msg )
{
#define MSG_ENTRY(x)    {x, #x}

    static const IONamedValue msgNames[] = { 
        MSG_ENTRY( kIOMessageCanDevicePowerOff      ),
        MSG_ENTRY( kIOMessageDeviceWillPowerOff     ),
        MSG_ENTRY( kIOMessageDeviceWillNotPowerOff  ),
        MSG_ENTRY( kIOMessageDeviceHasPoweredOn     ),
        MSG_ENTRY( kIOMessageCanSystemPowerOff      ),
        MSG_ENTRY( kIOMessageSystemWillPowerOff     ),
        MSG_ENTRY( kIOMessageSystemWillNotPowerOff  ),
        MSG_ENTRY( kIOMessageCanSystemSleep         ),
        MSG_ENTRY( kIOMessageSystemWillSleep        ),
        MSG_ENTRY( kIOMessageSystemWillNotSleep     ),
        MSG_ENTRY( kIOMessageSystemHasPoweredOn     ),
        MSG_ENTRY( kIOMessageSystemWillRestart      ),
        MSG_ENTRY( kIOMessageSystemWillPowerOn      ),
        MSG_ENTRY( kIOMessageSystemCapabilityChange )
    };

    return IOFindNameForValue(msg, msgNames);
}

// MARK: -
// MARK: IOPMRequest

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

bool IOPMRequest::attachNextRequest( IOPMRequest * next )
{
    bool ok = false;

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
        ok = true;
    }
    return ok;
}

bool IOPMRequest::detachNextRequest( void )
{
    bool ok = false;

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
        ok = true;
    }
    return ok;
}

bool IOPMRequest::attachRootRequest( IOPMRequest * root )
{
    bool ok = false;

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
        ok = true;
    }
    return ok;
}

bool IOPMRequest::detachRootRequest( void )
{
    bool ok = false;

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
        ok = true;
    }
    return ok;
}

// MARK: -
// MARK: IOPMRequestQueue

//*********************************************************************************
// IOPMRequestQueue Class
//
// Global queues. Queues are created once and never released.
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

// MARK: -
// MARK: IOPMWorkQueue

//*********************************************************************************
// IOPMWorkQueue Class
//
// Queue of IOServicePM objects with busy IOPMRequest(s).
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

	fWorkAction    = work;
	fRetireAction  = retire;
    fConsumerCount = fProducerCount = 0;

	return true;
}

bool IOPMWorkQueue::queuePMRequest( IOPMRequest * request, IOServicePM * pwrMgt )
{
    bool more = false;
    bool empty;

	assert( request );
    assert( pwrMgt );
	assert( onThread() );
    assert( queue_next(&request->fCommandChain) ==
            queue_prev(&request->fCommandChain) );

	gIOPMBusyCount++;

    // Add new request to the tail of the per-service request queue.
    // Then immediately check the request queue to minimize latency
    // if the queue was empty.

    empty = queue_empty(&pwrMgt->RequestHead);
	queue_enter(&pwrMgt->RequestHead, request, IOPMRequest *, fCommandChain);
    if (empty)
    {
        more = checkRequestQueue(&pwrMgt->RequestHead, &empty);
        if (!empty)
        {
            // New Request is blocked, add IOServicePM to work queue.
            assert( queue_next(&pwrMgt->WorkChain) ==
                    queue_prev(&pwrMgt->WorkChain) );

            queue_enter(&fWorkQueue, pwrMgt, IOServicePM *, WorkChain);
            fQueueLength++;
            PM_LOG3("IOPMWorkQueue: [%u] added %s@%p to queue\n",
                fQueueLength, pwrMgt->Name, pwrMgt);
        }
    }

    return more;
}

bool IOPMWorkQueue::checkRequestQueue( queue_head_t * queue, bool * empty )
{
	IOPMRequest *	request;
	IOService *		target;
    bool            more = false;
	bool			done = false;

    assert(!queue_empty(queue));
    do {
		request = (IOPMRequest *) queue_first(queue);
		if (request->isWorkBlocked())
            break;  // cannot start, blocked on attached request

		target = request->getTarget();
        done = (*fWorkAction)( target, request, this );
		if (!done)
            break;  // work started, blocked on PM state machine

        assert(gIOPMBusyCount > 0);
		if (gIOPMBusyCount)
            gIOPMBusyCount--;

        queue_remove_first(queue, request, IOPMRequest *, fCommandChain);
        more |= (*fRetireAction)( target, request, this );
        done = queue_empty(queue);
    } while (!done);

    *empty = done;

    if (more)
    {
        // Retired request blocks another request, since the
        // blocked request may reside in the work queue, we
        // must bump the producer count to avoid work stall.
        fProducerCount++;
    }

    return more;
}

bool IOPMWorkQueue::checkForWork( void )
{
	IOServicePM *   entry;
	IOServicePM *   next;
    bool			more = false;
    bool            empty;

#if WORK_QUEUE_STATS
    fStatCheckForWork++;
#endif

    // Each producer signal triggers a full iteration over
    // all IOServicePM entries in the work queue.

    while (fConsumerCount != fProducerCount)
    {
        PM_LOG3("IOPMWorkQueue: checkForWork %u %u\n",
            fProducerCount, fConsumerCount);

        fConsumerCount = fProducerCount;

#if WORK_QUEUE_STATS        
        if (queue_empty(&fWorkQueue))
        {
            fStatQueueEmpty++;
            break;
        }
        fStatScanEntries++;
        uint32_t cachedWorkCount = gIOPMWorkCount;
#endif

        entry = (IOServicePM *) queue_first(&fWorkQueue);
        while (!queue_end(&fWorkQueue, (queue_entry_t) entry))
        {
            more |= checkRequestQueue(&entry->RequestHead, &empty);

            // Get next entry, points to head if current entry is last.
            next = (IOServicePM *) queue_next(&entry->WorkChain);

            // if request queue is empty, remove IOServicePM from queue.
            if (empty)
            {
                assert(fQueueLength);
                if (fQueueLength) fQueueLength--;
                PM_LOG3("IOPMWorkQueue: [%u] removed %s@%p from queue\n",
                    fQueueLength, entry->Name, entry);
                queue_remove(&fWorkQueue, entry, IOServicePM *, WorkChain);
            }
            entry = next;
        }

#if WORK_QUEUE_STATS
        if (cachedWorkCount == gIOPMWorkCount)
            fStatNoWorkDone++;
#endif
    }

    return more;
}

void IOPMWorkQueue::signalWorkAvailable( void )
{
    fProducerCount++;
	IOEventSource::signalWorkAvailable();
}

void IOPMWorkQueue::incrementProducerCount( void )
{
    fProducerCount++;
}

// MARK: -
// MARK: IOPMCompletionQueue

//*********************************************************************************
// IOPMCompletionQueue Class
//*********************************************************************************

OSDefineMetaClassAndStructors( IOPMCompletionQueue, IOEventSource );

IOPMCompletionQueue *
IOPMCompletionQueue::create( IOService * inOwner, Action inAction )
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

bool IOPMCompletionQueue::queuePMRequest( IOPMRequest * request )
{
    bool more;

	assert(request);
    // unblock dependent request
    more = request->detachNextRequest();
	queue_enter(&fQueue, request, IOPMRequest *, fCommandChain);
    return more;
}

bool IOPMCompletionQueue::checkForWork( void )
{
    Action			dqAction = (Action) action;
	IOPMRequest *	request;
	IOPMRequest *   next;
	IOService *		target;
	bool			more = false;

    request = (IOPMRequest *) queue_first(&fQueue);
    while (!queue_end(&fQueue, (queue_entry_t) request))
    {
        next = (IOPMRequest *) queue_next(&request->fCommandChain);
		if (!request->isFreeBlocked())
        {
            queue_remove(&fQueue, request, IOPMRequest *, fCommandChain);
            target = request->getTarget();
            assert(target);
            more |= (*dqAction)( target, request, this );
        }
        request = next;
    }

    return more;
}

// MARK: -
// MARK: IOServicePM

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
	int				dictSize = 5;

	if (IdleTimerPeriod)
		dictSize += 4;

#if WORK_QUEUE_STATS
    if (gIOPMRootNode == ControllingDriver)
        dictSize += 4;
#endif

    if (PowerClients)
        dict = OSDictionary::withDictionary(
            PowerClients, PowerClients->getCount() + dictSize);
    else
        dict = OSDictionary::withCapacity(dictSize);

	if (dict)
	{
        setPMProperty(dict, "CurrentPowerState", CurrentPowerState);
        if (NumberOfPowerStates)
            setPMProperty(dict, "MaxPowerState", NumberOfPowerStates-1);
        if (DesiredPowerState != CurrentPowerState)
            setPMProperty(dict, "DesiredPowerState", DesiredPowerState);
        if (kIOPM_Finished != MachineState)
            setPMProperty(dict, "MachineState", MachineState);
        if (DeviceOverrideEnabled)
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
                setPMProperty(dict, "TimeSinceLastTickle", NS_TO_MS(nsecs));
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

#if WORK_QUEUE_STATS
        if (gIOPMRootNode == Owner)
        {
            setPMProperty(dict, "WQ-CheckForWork",
                gIOPMWorkQueue->fStatCheckForWork);
            setPMProperty(dict, "WQ-ScanEntries",
                gIOPMWorkQueue->fStatScanEntries);
            setPMProperty(dict, "WQ-QueueEmpty",
                gIOPMWorkQueue->fStatQueueEmpty);
            setPMProperty(dict, "WQ-NoWorkDone",
                gIOPMWorkQueue->fStatNoWorkDone);
        }
#endif

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

PMEventDetails* PMEventDetails::eventDetails(uint32_t   type,
                                             const char *ownerName,
                                             uintptr_t  ownerUnique,
                                             const char *interestName,
                                             uint8_t    oldState,
                                             uint8_t    newState,
                                             uint32_t   result,
                                             uint32_t   elapsedTimeUS) {
	
	PMEventDetails *myself;
	myself  = new PMEventDetails;
	
	if(myself) {
		myself->eventType     = type;
		myself->ownerName     = ownerName;
		myself->ownerUnique   = ownerUnique;
		myself->interestName  = interestName;
		myself->oldState      = oldState;
		myself->newState      = newState;
		myself->result        = result;
		myself->elapsedTimeUS = elapsedTimeUS;
		
		myself->eventClassifier = kIOPMEventClassDriverEvent;
	}
	
	return myself;
}


PMEventDetails* PMEventDetails::eventDetails(uint32_t   type,
                                             const char *uuid,
                                             uint32_t   reason,
                                             uint32_t   result) {
	
	PMEventDetails *myself;
	myself  = new PMEventDetails;
	
	if(myself) {
		myself->eventType     = type;
		myself->uuid          = uuid;
		myself->reason        = reason;
		myself->result        = result;
		
		myself->eventClassifier = kIOPMEventClassSystemEvent;
	}
	
	return myself;
}


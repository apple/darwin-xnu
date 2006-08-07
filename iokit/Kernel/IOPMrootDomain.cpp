/*
 * Copyright (c) 1998-2005 Apple Computer, Inc. All rights reserved.
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
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOKitDebug.h>
#include <IOKit/IOTimeStamp.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include <IOKit/pwr_mgt/IOPMPrivate.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOMessage.h>
#include <IOKit/IOReturn.h>
#include "RootDomainUserClient.h"
#include "IOKit/pwr_mgt/IOPowerConnection.h"
#include "IOPMPowerStateQueue.h"
#include <IOKit/IOCatalogue.h>
#include <IOKit/IOHibernatePrivate.h>

#ifdef __ppc__
#include <ppc/pms.h>
#endif

extern "C" {
IOReturn OSMetaClassSystemSleepOrWake( UInt32 );
}

extern const IORegistryPlane * gIOPowerPlane;

IOReturn broadcast_aggressiveness ( OSObject *, void *, void *, void *, void * );
static void sleepTimerExpired(thread_call_param_t);
static void wakeupClamshellTimerExpired ( thread_call_param_t us);

// "IOPMSetSleepSupported"  callPlatformFunction name
static const OSSymbol *sleepSupportedPEFunction = NULL;

#define kIOSleepSupportedKey  "IOSleepSupported"

#define kRD_AllPowerSources (kIOPMSupportedOnAC \
                           | kIOPMSupportedOnBatt \
                           | kIOPMSupportedOnUPS)

#define number_of_power_states 5
#define OFF_STATE 0
#define RESTART_STATE 1
#define SLEEP_STATE 2
#define DOZE_STATE 3
#define ON_STATE 4

#define ON_POWER kIOPMPowerOn
#define RESTART_POWER kIOPMRestart
#define SLEEP_POWER kIOPMAuxPowerOn
#define DOZE_POWER kIOPMDoze

#define kLocalEvalClamshellCommand        (1 << 15)

static IOPMPowerState ourPowerStates[number_of_power_states] = {
    // state 0, off
    {1,0,			0,		0,0,0,0,0,0,0,0,0},
    // state 1, restart
    {1,kIOPMRestartCapability,	kIOPMRestart,	RESTART_POWER,0,0,0,0,0,0,0,0},	
    // state 2, sleep
    {1,kIOPMSleepCapability,	kIOPMSleep,	SLEEP_POWER,0,0,0,0,0,0,0,0},	
    // state 3, doze
    {1,kIOPMDoze,		kIOPMDoze,	DOZE_POWER,0,0,0,0,0,0,0,0},	
    // state 4, on
    {1,kIOPMPowerOn,		kIOPMPowerOn,	ON_POWER,0,0,0,0,0,0,0,0},	
};

static IOPMrootDomain * gRootDomain;
static UInt32           gSleepOrShutdownPending = 0;


class PMSettingObject : public OSObject
{
    OSDeclareDefaultStructors(PMSettingObject)
private:
    IOPMrootDomain                  *parent;
    IOPMSettingControllerCallback   func;
    OSObject                        *target;
    uintptr_t                       refcon;
    uint32_t                        *publishedFeatureID;
    int                             releaseAtCount;
public:
    static PMSettingObject *pmSettingObject(
                IOPMrootDomain      *parent_arg,
                IOPMSettingControllerCallback   handler_arg,
                OSObject    *target_arg,
                uintptr_t   refcon_arg,
                uint32_t    supportedPowerSources,
                const OSSymbol *settings[]);

    void setPMSetting(const OSSymbol *type, OSObject *obj);

    void taggedRelease(const void *tag, const int when) const;
    void free(void);
};



#define super IOService
OSDefineMetaClassAndStructors(IOPMrootDomain,IOService)

extern "C"
{
    IONotifier * registerSleepWakeInterest(IOServiceInterestHandler handler, void * self, void * ref)
    {
        return gRootDomain->registerInterest( gIOGeneralInterest, handler, self, ref );
    }

    IONotifier * registerPrioritySleepWakeInterest(IOServiceInterestHandler handler, void * self, void * ref)
    {
        return gRootDomain->registerInterest( gIOPriorityPowerStateInterest, handler, self, ref );
    }

    IOReturn acknowledgeSleepWakeNotification(void * PMrefcon)
    {
        return gRootDomain->allowPowerChange ( (unsigned long)PMrefcon );
    }

    IOReturn vetoSleepWakeNotification(void * PMrefcon)
    {
        return gRootDomain->cancelPowerChange ( (unsigned long)PMrefcon );
    }
    
    IOReturn rootDomainRestart ( void )
    {
        return gRootDomain->restartSystem();
    }
    
    IOReturn rootDomainShutdown ( void )
    {
        return gRootDomain->shutdownSystem();
    }

	void IOSystemShutdownNotification ( void )
    {
	IOCatalogue::disableExternalLinker();
        for ( int i = 0; i < 100; i++ )
        {
            if ( OSCompareAndSwap( 0, 1, &gSleepOrShutdownPending ) ) break;
            IOSleep( 100 );
        }
    }

    int sync_internal(void);    
}

/*
A device is always in the highest power state which satisfies its driver, its policy-maker, and any power domain
children it has, but within the constraint of the power state provided by its parent.  The driver expresses its desire by
calling changePowerStateTo(), the policy-maker expresses its desire by calling changePowerStateToPriv(), and the children
express their desires by calling requestPowerDomainState().

The Root Power Domain owns the policy for idle and demand sleep and doze for the system.  It is a power-managed IOService just
like the others in the system.  It implements several power states which correspond to what we see as Sleep, Doze, etc.

The sleep/doze policy is as follows:
Sleep and Doze are prevented if the case is open so that nobody will think the machine is off and plug/unplug cards.
Sleep and Doze are prevented if the sleep timeout slider in the preferences panel is at zero.
The system cannot Sleep, but can Doze if some object in the tree is in a power state marked kIOPMPreventSystemSleep.

These three conditions are enforced using the "driver clamp" by calling changePowerStateTo().  For example, if the case is
opened, changePowerStateTo(ON_STATE) is called to hold the system on regardless of the desires of the children of the root or
the state of the other clamp.

Demand Sleep/Doze is initiated by pressing the front panel power button, closing the clamshell, or selecting the menu item.
In this case the root's parent actually initiates the power state change so that the root has no choice and does not give
applications the opportunity to veto the change.

Idle Sleep/Doze occurs if no objects in the tree are in a state marked kIOPMPreventIdleSleep.  When this is true, the root's
children are not holding the root on, so it sets the "policy-maker clamp" by calling changePowerStateToPriv(ON_STATE)
to hold itself on until the sleep timer expires.  This timer is set for the difference between the sleep timeout slider and
the larger of the display dim timeout slider and the disk spindown timeout slider in the Preferences panel.  For example, if
the system is set to sleep after thirty idle minutes, and the display and disk are set to sleep after five idle minutes,
when there is no longer an object in the tree holding the system out of Idle Sleep (via kIOPMPreventIdleSleep), the root
sets its timer for 25 minutes (30 - 5).  When the timer expires, it releases its clamp and now nothing is holding it awake,
so it falls asleep.

Demand sleep is prevented when the system is booting.  When preferences are transmitted by the loginwindow at the end of
boot, a flag is cleared, and this allows subsequent Demand Sleep.

The system will not Sleep, but will Doze if some object calls setSleepSupported(kPCICantSleep) during a power change to the sleep state (this can be done by the PCI Aux Power Supply drivers, Slots99, MacRISC299, etc.).  This is not enforced with
a clamp, but sets a flag which is noticed before actually sleeping the kernel.  If the flag is set, the root steps up
one power state from Sleep to Doze, and any objects in the tree for which this is relevent will act appropriately (USB and
ADB will turn on again so that they can wake the system out of Doze (keyboard/mouse activity will cause the Display Wrangler
to be tickled)).
*/

// **********************************************************************************

IOPMrootDomain * IOPMrootDomain::construct( void )
{
    IOPMrootDomain                          *root;

    root = new IOPMrootDomain;
    if( root)
        root->init();

    return( root );
}

// **********************************************************************************

static void disk_sync_callout(thread_call_param_t p0, thread_call_param_t p1)
{
    IOService                               *rootDomain = (IOService *) p0;
    unsigned long                           pmRef = (unsigned long) p1;

    IOHibernateSystemSleep();
    sync_internal();
    rootDomain->allowPowerChange(pmRef);
}

// **********************************************************************************
// start
//
// We don't do much here.  The real initialization occurs when the platform
// expert informs us we are the root.
// **********************************************************************************

#define kRootDomainSettingsCount        12

bool IOPMrootDomain::start ( IOService * nub )
{
    OSIterator      *psIterator;
    OSDictionary    *tmpDict;
    const OSSymbol  *settingsArr[kRootDomainSettingsCount] = 
        {
            OSSymbol::withCString(kIOPMSettingSleepOnPowerButtonKey),
            OSSymbol::withCString(kIOPMSettingAutoWakeSecondsKey),
            OSSymbol::withCString(kIOPMSettingAutoPowerSecondsKey),
            OSSymbol::withCString(kIOPMSettingAutoWakeCalendarKey),
            OSSymbol::withCString(kIOPMSettingAutoPowerCalendarKey),
            OSSymbol::withCString(kIOPMSettingDebugWakeRelativeKey),
            OSSymbol::withCString(kIOPMSettingDebugPowerRelativeKey),
            OSSymbol::withCString(kIOPMSettingWakeOnRingKey),
            OSSymbol::withCString(kIOPMSettingRestartOnPowerLossKey),
            OSSymbol::withCString(kIOPMSettingWakeOnClamshellKey),
            OSSymbol::withCString(kIOPMSettingWakeOnACChangeKey),
            OSSymbol::withCString(kIOPMSettingTimeZoneOffsetKey)
        };
    

    pmPowerStateQueue = 0;

    _reserved = (ExpansionData *)IOMalloc(sizeof(ExpansionData));
    if(!_reserved) return false;

    super::start(nub);

    gRootDomain = this;

    PMinit();
    
    sleepSupportedPEFunction = OSSymbol::withCString("IOPMSetSleepSupported");
    canSleep = true;
    setProperty(kIOSleepSupportedKey,true);

    allowSleep = true;
    sleepIsSupported = true;
    systemBooting = true;
    sleepSlider = 0;
    idleSleepPending = false;
    wrangler = NULL;
    sleepASAP = false;
    clamshellIsClosed = false;
    clamshellExists = false;
    ignoringClamshell = true;
    ignoringClamshellDuringWakeup = false;
    acAdaptorConnect = true;
    
    tmpDict = OSDictionary::withCapacity(1);
    setProperty(kRootDomainSupportedFeatures, tmpDict);
    tmpDict->release();
    
    settingsCallbacks = OSDictionary::withCapacity(1);

    // Create a list of the valid PM settings that we'll relay to
    // interested clients in setProperties() => setPMSetting()
    allowedPMSettings = OSArray::withObjects(
                    (const OSObject **)settingsArr,
                    kRootDomainSettingsCount,
                    0);
                    
    fPMSettingsDict = OSDictionary::withCapacity(5);
            
    pm_vars->PMworkloop = IOWorkLoop::workLoop();				
    pmPowerStateQueue = IOPMPowerStateQueue::PMPowerStateQueue(this);
    pm_vars->PMworkloop->addEventSource(pmPowerStateQueue);
    
    featuresDictLock = IOLockAlloc();
    settingsCtrlLock = IORecursiveLockAlloc();
    
    extraSleepTimer = thread_call_allocate(
                        (thread_call_func_t)sleepTimerExpired, 
                        (thread_call_param_t) this);
    clamshellWakeupIgnore = thread_call_allocate(
                        (thread_call_func_t)wakeupClamshellTimerExpired, 
                        (thread_call_param_t) this);
    diskSyncCalloutEntry = thread_call_allocate(
                        &disk_sync_callout, 
                        (thread_call_param_t) this);

    // create our parent
    patriarch = new IORootParent;
    patriarch->init();
    patriarch->attach(this);
    patriarch->start(this);
    patriarch->youAreRoot();
    patriarch->wakeSystem();
    patriarch->addPowerChild(this);
        
    registerPowerDriver(this,ourPowerStates,number_of_power_states);

    setPMRootDomain(this);
    // set a clamp until we sleep
    changePowerStateToPriv(ON_STATE);

    // install power change handler
    registerPrioritySleepWakeInterest( &sysPowerDownHandler, this, 0);

    // Register for a notification when IODisplayWrangler is published
    _displayWranglerNotifier = addNotification( 
                gIOPublishNotification, serviceMatching("IODisplayWrangler"), 
                &displayWranglerPublished, this, 0);

    // Battery location published - ApplePMU support only
    _batteryPublishNotifier = addNotification( 
                gIOPublishNotification, serviceMatching("IOPMPowerSource"), 
                &batteryPublished, this, this);
     

    const OSSymbol *ucClassName = OSSymbol::withCStringNoCopy("RootDomainUserClient");
    setProperty(gIOUserClientClassKey, (OSObject *) ucClassName);
    ucClassName->release();

    // IOBacklightDisplay can take a long time to load at boot, or it may
    // not load at all if you're booting with clamshell closed. We publish
    // 'DisplayDims' here redundantly to get it published early and at all.
    psIterator = getMatchingServices( serviceMatching("IOPMPowerSource") );
    if( psIterator && psIterator->getNextObject() )
    {
        // There's at least one battery on the system, so we publish
        // 'DisplayDims' support for the LCD.
        publishFeature("DisplayDims");
    }
    if(psIterator) {
        psIterator->release();
    }

    IOHibernateSystemInit(this);

    registerService();						// let clients find us

    return true;
}

// **********************************************************************************
// setProperties
//
// Receive a setProperty call
// The "System Boot" property means the system is completely booted.
// **********************************************************************************
IOReturn IOPMrootDomain::setProperties ( OSObject *props_obj)
{
    IOReturn                        return_value = kIOReturnSuccess;
    OSDictionary                    *dict = OSDynamicCast(OSDictionary, props_obj);
    OSBoolean                       *b;
    OSNumber                        *n;
    OSString                        *str;
    OSSymbol                        *type;
    OSObject                        *obj;
    unsigned int                    i;

    const OSSymbol *boot_complete_string = 
                OSSymbol::withCString("System Boot Complete");
    const OSSymbol *stall_halt_string = 
                OSSymbol::withCString("StallSystemAtHalt");
    const OSSymbol *hibernatemode_string = 
                OSSymbol::withCString(kIOHibernateModeKey);
    const OSSymbol *hibernatefile_string = 
                OSSymbol::withCString(kIOHibernateFileKey);
    const OSSymbol *hibernatefreeratio_string = 
                OSSymbol::withCString(kIOHibernateFreeRatioKey);
    const OSSymbol *hibernatefreetime_string = 
                OSSymbol::withCString(kIOHibernateFreeTimeKey);
    
    if(!dict) 
    {
        return_value = kIOReturnBadArgument;
        goto exit;
    }

    if( systemBooting 
        && boot_complete_string 
        && dict->getObject(boot_complete_string)) 
    {
        systemBooting = false;
        adjustPowerState();

        // If lid is closed, re-send lid closed notification
        // now that booting is complete.
        if( clamshellIsClosed )
        {
            this->receivePowerNotification(kLocalEvalClamshellCommand);
        }
    }
    
    if( stall_halt_string
        && (b = OSDynamicCast(OSBoolean, dict->getObject(stall_halt_string))) ) 
    {
        setProperty(stall_halt_string, b);
    }

    if ( hibernatemode_string
    && (n = OSDynamicCast(OSNumber, dict->getObject(hibernatemode_string))))
    {
    	setProperty(hibernatemode_string, n);
    }
    if ( hibernatefreeratio_string
    && (n = OSDynamicCast(OSNumber, dict->getObject(hibernatefreeratio_string))))
    {
        setProperty(hibernatefreeratio_string, n);
    }
    if ( hibernatefreetime_string
    && (n = OSDynamicCast(OSNumber, dict->getObject(hibernatefreetime_string))))
    {
        setProperty(hibernatefreetime_string, n);
    }
    if ( hibernatefile_string
    && (str = OSDynamicCast(OSString, dict->getObject(hibernatefile_string))))
    {
        setProperty(hibernatefile_string, str);
    }

    // Relay our allowed PM settings onto our registered PM clients
    for(i = 0; i < allowedPMSettings->getCount(); i++) {

        type = (OSSymbol *)allowedPMSettings->getObject(i);
        if(!type) continue;

        obj = dict->getObject(type);
        if(!obj) continue;
        
        return_value = setPMSetting(type, obj);
        
        if(kIOReturnSuccess != return_value) goto exit;
    }

    exit:
    if(boot_complete_string) boot_complete_string->release();
    if(stall_halt_string) stall_halt_string->release();
    return return_value;
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
// No longer used
// **********************************************************************************
void IOPMrootDomain::command_received ( void * w, void * x, void * y, void * z )
{
    super::command_received(w,x,y,z);
}


// **********************************************************************************
// broadcast_aggressiveness
//
// **********************************************************************************
IOReturn broadcast_aggressiveness ( OSObject * root, void * x, void * y, void *, void * )
{
    ((IOPMrootDomain *)root)->broadcast_it((unsigned long)x,(unsigned long)y);
    return IOPMNoErr;
}


// **********************************************************************************
// broadcast_it
//
// We are behind the command gate to broadcast an aggressiveness factor.  We let the
// superclass do it, but we need to snoop on factors that affect idle sleep.
// **********************************************************************************
void IOPMrootDomain::broadcast_it (unsigned long type, unsigned long value)
{
    super::setAggressiveness(type,value);

    // Save user's spin down timer to restore after we replace it for idle sleep
    if( type == kPMMinutesToSpinDown ) user_spindown = value;

    // Use longestNonSleepSlider to calculate dimming adjust idle sleep timer
    longestNonSleepSlider = pm_vars->current_aggressiveness_values[kPMMinutesToDim];


    if ( type == kPMMinutesToSleep ) {
        if ( (sleepSlider == 0) && (value != 0) ) {
            sleepSlider = value;
            // idle sleep is now enabled, maybe sleep now
            adjustPowerState();
        }
        sleepSlider = value;
        if ( sleepSlider == 0 ) {			
            // idle sleep is now disabled
            adjustPowerState();
            // make sure we're powered
            patriarch->wakeSystem();
        }
    }
    if ( sleepSlider > longestNonSleepSlider ) {
        extraSleepDelay = sleepSlider - longestNonSleepSlider ;
    }
    else {
        extraSleepDelay = 0;
    }
}


// **********************************************************************************
// sleepTimerExpired
//
// **********************************************************************************
static void sleepTimerExpired ( thread_call_param_t us)
{
    ((IOPMrootDomain *)us)->handleSleepTimerExpiration();
    }
    
   
static void wakeupClamshellTimerExpired ( thread_call_param_t us)
{
    ((IOPMrootDomain *)us)->stopIgnoringClamshellEventsDuringWakeup();
}

    
// **********************************************************************************
// handleSleepTimerExpiration
//
// The time between the sleep idle timeout and the next longest one has elapsed.
// It's time to sleep.  Start that by removing the clamp that's holding us awake.
// **********************************************************************************
void IOPMrootDomain::handleSleepTimerExpiration ( void )
{
    // accelerate disk spin down if spin down timer is non-zero (zero = never spin down)  
    if(0 != user_spindown)
        setQuickSpinDownTimeout();

    sleepASAP = true;
    adjustPowerState();
}


void IOPMrootDomain::stopIgnoringClamshellEventsDuringWakeup(void)
{
    // Allow clamshell-induced sleep now
    ignoringClamshellDuringWakeup = false;

    // Re-send clamshell event, in case it causes a sleep
    if(clamshellIsClosed) 
        this->receivePowerNotification( kLocalEvalClamshellCommand );
}

//*********************************************************************************
// setAggressiveness
//
// Some aggressiveness factor has changed.  We broadcast it to the hierarchy while on
// the Power Mangement workloop thread.  This enables objects in the
// hierarchy to successfully alter their idle timers, which are all on the
// same thread.
//*********************************************************************************

static int pmsallsetup = 0;

IOReturn IOPMrootDomain::setAggressiveness ( unsigned long type, unsigned long newLevel )
{
#ifdef __ppc__
	if(pmsExperimental & 3) kprintf("setAggressiveness: type = %08X, newlevel = %08X\n", type, newLevel);
	if(pmsExperimental & 1) {						/* Is experimental mode enabled? */
		if(pmsInstalled && (type == kPMSetProcessorSpeed)) {	/* We want to look at all processor speed changes if stepper is installed */
			if(pmsallsetup) return kIOReturnSuccess;	/* If already running, just eat this */
			kprintf("setAggressiveness: starting stepper...\n");
			pmsallsetup = 1;						/* Remember we did this */
			pmsPark();
			pmsStart();								/* Get it all started up... */
			return kIOReturnSuccess;				/* Leave now... */
		}
	}
#endif

    if ( pm_vars->PMcommandGate ) {
        pm_vars->PMcommandGate->runAction(broadcast_aggressiveness,(void *)type,(void *)newLevel);
    }
    
    return kIOReturnSuccess;
}


// **********************************************************************************
// sleepSystem
//
// **********************************************************************************
IOReturn IOPMrootDomain::sleepSystem ( void )
{
    if ( !systemBooting && allowSleep && sleepIsSupported ) {
        patriarch->sleepSystem();

        return kIOReturnSuccess;
    }
    if ( !systemBooting && allowSleep && !sleepIsSupported ) {
        patriarch->dozeSystem();
        return kIOReturnSuccess;
    }
    return kIOReturnSuccess;
}


// **********************************************************************************
// shutdownSystem
//
// **********************************************************************************
IOReturn IOPMrootDomain::shutdownSystem ( void )
{
    //patriarch->shutDownSystem();
    return kIOReturnUnsupported;
}


// **********************************************************************************
// restartSystem
//
// **********************************************************************************
IOReturn IOPMrootDomain::restartSystem ( void )
{
    //patriarch->restartSystem();
    return kIOReturnUnsupported;
}


// **********************************************************************************
// powerChangeDone
//
// This overrides powerChangeDone in IOService.
//
// Finder sleep and idle sleep move us from the ON state to the SLEEP_STATE.
// In this case:
// If we just finished going to the SLEEP_STATE, and the platform is capable of true sleep,
// sleep the kernel.  Otherwise switch up to the DOZE_STATE which will keep almost
// everything as off as it can get.
//
// **********************************************************************************
void IOPMrootDomain::powerChangeDone ( unsigned long previousState )
{
    OSNumber *		propertyPtr;
    unsigned short	theProperty;
    AbsoluteTime        deadline;
    
    switch ( pm_vars->myCurrentState ) {
        case SLEEP_STATE:
            if ( canSleep && sleepIsSupported ) 
            {
                // re-enable this timer for next sleep
                idleSleepPending = false;			

                IOLog("System %sSleep\n", gIOHibernateState ? "Safe" : "");

                IOHibernateSystemHasSlept();

                pm_vars->thePlatform->sleepKernel();

                // The CPU(s) are off at this point. When they're awakened by CPU interrupt,
                // code will resume execution here.

                // Now we're waking...
                IOHibernateSystemWake();

                // stay awake for at least 30 seconds
                clock_interval_to_deadline(30, kSecondScale, &deadline);	
                thread_call_enter_delayed(extraSleepTimer, deadline);
                // this gets turned off when we sleep again
                idleSleepPending = true;
                
                // Ignore closed clamshell during wakeup and for a few seconds
                // after wakeup is complete
                ignoringClamshellDuringWakeup = true;

                // sleep transition complete
                gSleepOrShutdownPending = 0;

				// trip the reset of the calendar clock
				clock_wakeup_calendar();

                // get us some power
                patriarch->wakeSystem();
                
                // early stage wake notification
                tellClients(kIOMessageSystemWillPowerOn);

                // tell the tree we're waking
                IOLog("System %sWake\n", gIOHibernateState ? "SafeSleep " : "");
                systemWake();
                
                // Allow drivers to request extra processing time before clamshell
                // sleep if kIOREMSleepEnabledKey is present.
                // Ignore clamshell events for at least 5 seconds 
                if(getProperty(kIOREMSleepEnabledKey)) {
                    // clamshellWakeupIgnore callout clears ignoreClamshellDuringWakeup bit   
                    clock_interval_to_deadline(5, kSecondScale, &deadline);
                    if(clamshellWakeupIgnore)  {
                        thread_call_enter_delayed(clamshellWakeupIgnore, deadline);
                    }
                } else ignoringClamshellDuringWakeup = false;
                
                // Find out what woke us
                propertyPtr = OSDynamicCast(OSNumber,getProperty("WakeEvent"));
                if ( propertyPtr ) {				
                    theProperty = propertyPtr->unsigned16BitValue();
                    IOLog("Wake event %04x\n",theProperty);
                    if ( (theProperty & 0x0008) ||	//lid
                        (theProperty & 0x0800) ||	// front panel button
                        (theProperty & 0x0020) ||	// external keyboard
                        (theProperty & 0x0001) ) {	// internal keyboard
                            // We've identified the wakeup event as UI driven
                            reportUserInput();
                    }
                } else {
                    // Since we can't identify the wakeup event, treat it as UI activity
                    reportUserInput();
                }
                            
                // Wake for thirty seconds
                changePowerStateToPriv(ON_STATE);		
                powerOverrideOffPriv();
            } else {
                // allow us to step up a power state
                patriarch->sleepToDoze();
                // and do it
                changePowerStateToPriv(DOZE_STATE);
            }
            break;

        case DOZE_STATE:
            if ( previousState != DOZE_STATE ) 
            {
                IOLog("System Doze\n");
            }
            // re-enable this timer for next sleep
            idleSleepPending = false;
            gSleepOrShutdownPending = 0;
            break;
            
    	case RESTART_STATE:
            IOLog("System Restart\n");
            PEHaltRestart(kPERestartCPU);
            break;
            
    	case OFF_STATE:
            IOLog("System Halt\n");
            PEHaltRestart(kPEHaltCPU);
            break;
    }
}


// **********************************************************************************
// wakeFromDoze
//
// The Display Wrangler calls here when it switches to its highest state.  If the 
// system is currently dozing, allow it to wake by making sure the parent is
// providing power.
// **********************************************************************************
void IOPMrootDomain::wakeFromDoze( void )
{
    if ( pm_vars->myCurrentState == DOZE_STATE ) 
    {
        // Reset sleep support till next sleep attempt.
        // A machine's support of sleep vs. doze can change over the course of
        // a running system, so we recalculate it before every sleep.
        setSleepSupported(0);

        powerOverrideOffPriv();

        // early wake notification
        tellClients(kIOMessageSystemWillPowerOn);

        // allow us to wake if children so desire
        patriarch->wakeSystem();
    }
}


// *****************************************************************************
// publishFeature
//
// Adds a new feature to the supported features dictionary
// 
// 
// *****************************************************************************
void IOPMrootDomain::publishFeature( const char * feature )
{
    publishFeature(feature, kIOPMSupportedOnAC 
                                  | kIOPMSupportedOnBatt 
                                  | kIOPMSupportedOnUPS,
                            NULL);
    return;
}


// *****************************************************************************
// publishFeature (with supported power source specified)
//
// Adds a new feature to the supported features dictionary
// 
// 
// *****************************************************************************
void IOPMrootDomain::publishFeature( 
    const char *feature, 
    uint32_t supportedWhere,
    uint32_t *uniqueFeatureID)
{
    static uint16_t     next_feature_id = 500;

    OSNumber            *new_feature_data = NULL;
    OSNumber            *existing_feature = NULL;
    OSArray             *existing_feature_arr = NULL;
    OSObject            *osObj = NULL;
    uint32_t            feature_value = 0;

    supportedWhere &= kRD_AllPowerSources; // mask off any craziness!

    if(!supportedWhere) {
        // Feature isn't supported anywhere!
        return;
    }
    
    if(next_feature_id > 5000) {
        // Far, far too many features!
        return;
    }

    if(featuresDictLock) IOLockLock(featuresDictLock);

    OSDictionary *features =
        (OSDictionary *) getProperty(kRootDomainSupportedFeatures);
    
    // Create new features dict if necessary
    if ( features && OSDynamicCast(OSDictionary, features)) {
        features = OSDictionary::withDictionary(features);
    } else {
        features = OSDictionary::withCapacity(1);
    }
    
    // Create OSNumber to track new feature
    
    next_feature_id += 1;
    if( uniqueFeatureID ) {
        // We don't really mind if the calling kext didn't give us a place
        // to stash their unique id. Many kexts don't plan to unload, and thus
        // have no need to remove themselves later.
        *uniqueFeatureID = next_feature_id;
    }
    
    feature_value = supportedWhere + (next_feature_id << 16);
    new_feature_data = OSNumber::withNumber(
                                (unsigned long long)feature_value, 32);

    // Does features object already exist?
    if( (osObj = features->getObject(feature)) )
    {
        if(( existing_feature = OSDynamicCast(OSNumber, osObj) ))
        {
            // We need to create an OSArray to hold the now 2 elements.
            existing_feature_arr = OSArray::withObjects(
                            (const OSObject **)&existing_feature, 1, 2);
            existing_feature_arr->setObject(new_feature_data);
            features->setObject(feature, existing_feature_arr);
        } else if(( existing_feature_arr = OSDynamicCast(OSArray, osObj) ))
        {
            // Add object to existing array
            existing_feature_arr->setObject(new_feature_data);        
        }
    } else {
        // The easy case: no previously existing features listed. We simply
        // set the OSNumber at key 'feature' and we're on our way.
        features->setObject(feature, new_feature_data);        
    }
    
    new_feature_data->release();

    setProperty(kRootDomainSupportedFeatures, features);

    features->release();

    // Notify EnergySaver and all those in user space so they might
    // re-populate their feature specific UI
    messageClients(kIOPMMessageFeatureChange, this);

    if(featuresDictLock) IOLockUnlock(featuresDictLock);    
}

// *****************************************************************************
// removePublishedFeature
//
// Removes previously published feature
// 
// 
// *****************************************************************************
IOReturn IOPMrootDomain::removePublishedFeature( uint32_t removeFeatureID )
{
    IOReturn                ret = kIOReturnError;
    uint32_t                feature_value = 0;
    uint16_t                feature_id = 0;
    bool                    madeAChange = false;
    
    OSSymbol                *dictKey = NULL;
    OSCollectionIterator    *dictIterator = NULL;
    OSArray                 *arrayMember  = NULL;
    OSNumber                *numberMember = NULL;
    OSObject                *osObj        = NULL;
    OSNumber                *osNum        = NULL;

    if(featuresDictLock) IOLockLock(featuresDictLock);

    OSDictionary *features =
        (OSDictionary *) getProperty(kRootDomainSupportedFeatures);
    
    if ( features && OSDynamicCast(OSDictionary, features) )
    {
        // Any modifications to the dictionary are made to the copy to prevent
        // races & crashes with userland clients. Dictionary updated
        // automically later.
        features = OSDictionary::withDictionary(features);
    } else {
        features = NULL;
        ret = kIOReturnNotFound;
        goto exit;
    }
    
    // We iterate 'features' dictionary looking for an entry tagged
    // with 'removeFeatureID'. If found, we remove it from our tracking
    // structures and notify the OS via a general interest message.
    
    dictIterator = OSCollectionIterator::withCollection(features);
    if(!dictIterator) {
        goto exit;
    }
    
    while( (dictKey = OSDynamicCast(OSSymbol, dictIterator->getNextObject())) )
    {
        osObj = features->getObject(dictKey);
        
        // Each Feature is either tracked by an OSNumber
        if( osObj && (numberMember = OSDynamicCast(OSNumber, osObj)) )
        {
            feature_value = numberMember->unsigned32BitValue();
            feature_id = (uint16_t)(feature_value >> 16);

            if( feature_id == (uint16_t)removeFeatureID )
            {
                // Remove this node
                features->removeObject(dictKey);
                madeAChange = true;
                break;
            }
        
        // Or tracked by an OSArray of OSNumbers
        } else if( osObj && (arrayMember = OSDynamicCast(OSArray, osObj)) )
        {
            unsigned int arrayCount = arrayMember->getCount();
            
            for(unsigned int i=0; i<arrayCount; i++)
            {
                osNum = OSDynamicCast(OSNumber, arrayMember->getObject(i));
                if(!osNum) {
                    continue;
                }
                
                feature_value = osNum->unsigned32BitValue();
                feature_id = (uint16_t)(feature_value >> 16);

                if( feature_id == (uint16_t)removeFeatureID )
                {
                    // Remove this node
                    if( 1 == arrayCount ) {
                        // If the array only contains one element, remove
                        // the whole thing.
                        features->removeObject(dictKey);
                    } else {
                        // Otherwise just remove the element in question.
                        arrayMember->removeObject(i);                    
                    }

                    madeAChange = true;
                    break;
                }
            }
        }    
    }
    
    
    dictIterator->release();
    
    if( madeAChange )
    {
        ret = kIOReturnSuccess;    

        setProperty(kRootDomainSupportedFeatures, features);
    
        // Notify EnergySaver and all those in user space so they might
        // re-populate their feature specific UI
        messageClients(kIOPMMessageFeatureChange, this);
    } else {
        ret = kIOReturnNotFound;
    }
    
exit:
    if(features)    features->release();
    if(featuresDictLock) IOLockUnlock(featuresDictLock);    
    return ret;
}


// **********************************************************************************
// unIdleDevice
//
// Enqueues unidle event to be performed later in a serialized context.
// 
// **********************************************************************************
void IOPMrootDomain::unIdleDevice( IOService *theDevice, unsigned long theState )
{
    if(pmPowerStateQueue)
        pmPowerStateQueue->unIdleOccurred(theDevice, theState);
}

// **********************************************************************************
// announcePowerSourceChange
//
// Notifies "interested parties" that the batteries have changed state
// 
// **********************************************************************************
void IOPMrootDomain::announcePowerSourceChange( void )
{
    IORegistryEntry *_batteryRegEntry = (IORegistryEntry *) getProperty("BatteryEntry");

    // (if possible) re-publish power source state under IOPMrootDomain;
    // only do so if the battery controller publishes an IOResource 
    // defining battery location. Called from ApplePMU battery driver.

    if(_batteryRegEntry)
    {
        OSArray             *batt_info;
        batt_info = (OSArray *) _batteryRegEntry->getProperty(kIOBatteryInfoKey);
        if(batt_info)
            setProperty(kIOBatteryInfoKey, batt_info);
    }

}


// *****************************************************************************
// setPMSetting (private)
//
// Internal helper to relay PM settings changes from user space to individual
// drivers. Should be called only by IOPMrootDomain::setProperties.
// 
// *****************************************************************************
IOReturn     IOPMrootDomain::setPMSetting(
    const OSSymbol *type, 
    OSObject *obj)
{
    OSArray             *arr = NULL;
    PMSettingObject     *p_obj = NULL;
    int                 count;
    int                 i;

    if(NULL == type) return kIOReturnBadArgument;

    IORecursiveLockLock(settingsCtrlLock);
    
    fPMSettingsDict->setObject(type, obj);

    arr = (OSArray *)settingsCallbacks->getObject(type);
    if(NULL == arr) goto exit;
    count = arr->getCount();
    for(i=0; i<count; i++) {
        p_obj = (PMSettingObject *)OSDynamicCast(PMSettingObject, arr->getObject(i));
        if(p_obj) p_obj->setPMSetting(type, obj);
    }

exit:
    IORecursiveLockUnlock(settingsCtrlLock);
    return kIOReturnSuccess;
}

// *****************************************************************************
// copyPMSetting (public)
//
// Allows kexts to safely read setting values, without being subscribed to
// notifications.
// 
// *****************************************************************************
OSObject * IOPMrootDomain::copyPMSetting(
    OSSymbol *whichSetting)
{
    OSObject *obj = NULL;

    if(!whichSetting) return NULL;

    IORecursiveLockLock(settingsCtrlLock);
    obj = fPMSettingsDict->getObject(whichSetting);
    if(obj) {
        obj->retain();
    }
    IORecursiveLockUnlock(settingsCtrlLock);
    
    return obj;
}

// *****************************************************************************
// registerPMSettingController (public)
//
// direct wrapper to registerPMSettingController with uint32_t power source arg
// *****************************************************************************
IOReturn IOPMrootDomain::registerPMSettingController(
    const OSSymbol *                settings[],
    IOPMSettingControllerCallback   func,
    OSObject                        *target,
    uintptr_t                       refcon,
    OSObject                        **handle)
{
    return registerPMSettingController( 
            settings,
            (kIOPMSupportedOnAC | kIOPMSupportedOnBatt | kIOPMSupportedOnUPS),
            func, target, refcon, handle);
}

// *****************************************************************************
// registerPMSettingController (public)
//
// Kexts may register for notifications when a particular setting is changed.
// A list of settings is available in IOPM.h.
// Arguments:
//  * settings - An OSArray containing OSSymbols. Caller should populate this
//          array with a list of settings caller wants notifications from.
//  * func - A C function callback of the type IOPMSettingControllerCallback
//  * target - caller may provide an OSObject *, which PM will pass as an 
//          target to calls to "func"
//  * refcon - caller may provide an void *, which PM will pass as an 
//          argument to calls to "func"
//  * handle - This is a return argument. We will populate this pointer upon
//          call success. Hold onto this and pass this argument to
//          IOPMrootDomain::deRegisterPMSettingCallback when unloading your kext
// Returns:
//      kIOReturnSuccess on success
// *****************************************************************************
IOReturn IOPMrootDomain::registerPMSettingController(
    const OSSymbol *                settings[],
    uint32_t                        supportedPowerSources,
    IOPMSettingControllerCallback   func,
    OSObject                        *target,
    uintptr_t                       refcon,
    OSObject                        **handle)
{
    PMSettingObject     *pmso = NULL;
    OSArray             *list = NULL;
    IOReturn            ret = kIOReturnSuccess;
    int                 i;

    if( NULL == settings ||
        NULL == func ||
        NULL == handle)
    {
        return kIOReturnBadArgument;
    }


    pmso = PMSettingObject::pmSettingObject(
                (IOPMrootDomain *)this, func, target, 
                refcon, supportedPowerSources, settings);

    if(!pmso) {
        ret = kIOReturnInternalError;
        goto bail_no_unlock;
    }

    IORecursiveLockLock(settingsCtrlLock);
    for(i=0; settings[i]; i++) 
    {
        list = (OSArray *)settingsCallbacks->getObject(settings[i]);
        if(!list) {
            // New array of callbacks for this setting
            list = OSArray::withCapacity(1);
            settingsCallbacks->setObject(settings[i], list);
            list->release();
        }

        // Add caller to the callback list
        list->setObject(pmso);
    }

    ret = kIOReturnSuccess;

    // Track this instance by its OSData ptr from now on  
    *handle = pmso;
    
    IORecursiveLockUnlock(settingsCtrlLock);

bail_no_unlock:
    if(kIOReturnSuccess != ret) 
    {
        // Error return case
        if(pmso) pmso->release();
        if(handle) *handle = NULL;
    }
    return ret;
}

//******************************************************************************
// sleepOnClamshellClosed
//
// contains the logic to determine if the system should sleep when the clamshell
// is closed.
//******************************************************************************

bool IOPMrootDomain::shouldSleepOnClamshellClosed ( void )
{
    return ( !ignoringClamshell 
          && !ignoringClamshellDuringWakeup 
          && !(desktopMode && acAdaptorConnect) );
}

void IOPMrootDomain::sendClientClamshellNotification ( void )
{
    /* Only broadcast clamshell alert if clamshell exists. */
    if(!clamshellExists)
        return;
        
    setProperty(kAppleClamshellStateKey, 
                    clamshellIsClosed ? kOSBooleanTrue : kOSBooleanFalse);

    setProperty(kAppleClamshellCausesSleepKey, 
       shouldSleepOnClamshellClosed() ? kOSBooleanTrue : kOSBooleanFalse);


    /* Argument to message is a bitfiel of 
     *      ( kClamshellStateBit | kClamshellSleepBit )
     */
    messageClients(kIOPMMessageClamshellStateChange,
        (void *) ( (clamshellIsClosed ? kClamshellStateBit : 0)
             | ( shouldSleepOnClamshellClosed() ? kClamshellSleepBit : 0)) );
}

//******************************************************************************
// receivePowerNotification
//
// The power controller is notifying us of a hardware-related power management
// event that we must handle. This is a result of an 'environment' interrupt from
// the power mgt micro.
//******************************************************************************

IOReturn IOPMrootDomain::receivePowerNotification (UInt32 msg)
{
    bool        eval_clamshell = false;

    /*
     * Local (IOPMrootDomain only) eval clamshell command
     */
    if (msg & kLocalEvalClamshellCommand)
    {
        eval_clamshell = true;
    }

    /*
     * Overtemp
     */
    if (msg & kIOPMOverTemp) 
    {
        IOLog("PowerManagement emergency overtemp signal. Going to sleep!");
        (void) sleepSystem ();
    }

    /*
     * PMU Processor Speed Change
     */
    if (msg & kIOPMProcessorSpeedChange) 
    {
        IOService *pmu = waitForService(serviceMatching("ApplePMU"));
        pmu->callPlatformFunction("prepareForSleep", false, 0, 0, 0, 0);
        pm_vars->thePlatform->sleepKernel();
        pmu->callPlatformFunction("recoverFromSleep", false, 0, 0, 0, 0);
    }

    /*
     * Sleep Now!
     */
    if (msg & kIOPMSleepNow) 
    {
      (void) sleepSystem ();
    }
    
    /*
     * Power Emergency
     */
    if (msg & kIOPMPowerEmergency) 
    {
      (void) sleepSystem ();
    }

    
    /*
     * Clamshell OPEN
     */
    if (msg & kIOPMClamshellOpened) 
    {
        // Received clamshel open message from clamshell controlling driver
        // Update our internal state and tell general interest clients
        clamshellIsClosed = false;
        clamshellExists = true;
                
        sendClientClamshellNotification();
    } 

    /* 
     * Clamshell CLOSED
     * Send the clamshell interest notification since the lid is closing. 
     */
    if (msg & kIOPMClamshellClosed)
    {
        // Received clamshel open message from clamshell controlling driver
        // Update our internal state and tell general interest clients
        clamshellIsClosed = true;
        clamshellExists = true;

        sendClientClamshellNotification();
        
        // And set eval_clamshell = so we can attempt 
        eval_clamshell = true;
    }

    /*
     * Set Desktop mode (sent from graphics)
     *
     *  -> reevaluate lid state
     */
    if (msg & kIOPMSetDesktopMode) 
    {
        desktopMode = (0 != (msg & kIOPMSetValue));
        msg &= ~(kIOPMSetDesktopMode | kIOPMSetValue);

        sendClientClamshellNotification();

        // Re-evaluate the lid state
        if( clamshellIsClosed )
        {
            eval_clamshell = true;
        }
    }
    
    /*
     * AC Adaptor connected
     *
     *  -> reevaluate lid state
     */
    if (msg & kIOPMSetACAdaptorConnected) 
    {
        acAdaptorConnect = (0 != (msg & kIOPMSetValue));
        msg &= ~(kIOPMSetACAdaptorConnected | kIOPMSetValue);

        sendClientClamshellNotification();

        // Re-evaluate the lid state
        if( clamshellIsClosed )
        {
            eval_clamshell = true;
        }

    }
    
    /*
     * Enable Clamshell (external display disappear)
     *
     *  -> reevaluate lid state
     */
    if (msg & kIOPMEnableClamshell) 
    {
        // Re-evaluate the lid state
        // System should sleep on external display disappearance
        // in lid closed operation.
        if( clamshellIsClosed && (true == ignoringClamshell) )        
        {
            eval_clamshell = true;
        }

        ignoringClamshell = false;

        sendClientClamshellNotification();
    }
    
    /*
     * Disable Clamshell (external display appeared)
     * We don't bother re-evaluating clamshell state. If the system is awake,
     * the lid is probably open. 
     */
    if (msg & kIOPMDisableClamshell) 
    {
        ignoringClamshell = true;

        sendClientClamshellNotification();
    }

    /*
     * Evaluate clamshell and SLEEP if appropiate
     */
    if ( eval_clamshell && shouldSleepOnClamshellClosed() ) 
    {


        // SLEEP!
        sleepSystem();
    }

    /*
     * Power Button
     */
    if (msg & kIOPMPowerButton) 
    {				
        // toggle state of sleep/wake
        // are we dozing?
        if ( pm_vars->myCurrentState == DOZE_STATE ) 
        {
            // yes, tell the tree we're waking 
            systemWake();
            // wake the Display Wrangler
            reportUserInput();					
        }
        else {
            OSString *pbs = OSString::withCString("DisablePowerButtonSleep");
            // Check that power button sleep is enabled
            if( pbs ) {
                if( kOSBooleanTrue != getProperty(pbs))
                sleepSystem();
            }
        }
    }

    /*
     * Allow Sleep
     *
     */
    if ( (msg & kIOPMAllowSleep) && !allowSleep ) 
    {
        allowSleep = true;
        adjustPowerState();
    }

    /*
     * Prevent Sleep
     *
     */
    if (msg & kIOPMPreventSleep) {
        allowSleep = false;
	    // are we dozing?
        if ( pm_vars->myCurrentState == DOZE_STATE ) {
            // yes, tell the tree we're waking 
            systemWake();
            adjustPowerState();
            // wake the Display Wrangler
            reportUserInput();
        } else {
            adjustPowerState();
            // make sure we have power to clamp
            patriarch->wakeSystem();
        }
    }

   return 0;
}


//*********************************************************************************
// sleepSupported
//
//*********************************************************************************

void IOPMrootDomain::setSleepSupported( IOOptionBits flags )
{
    if ( flags & kPCICantSleep ) 
    {
        canSleep = false;
    } else {
        canSleep = true;
        platformSleepSupport = flags;
    }

    setProperty(kIOSleepSupportedKey, canSleep);

}

//*********************************************************************************
// requestPowerDomainState
//
// The root domain intercepts this call to the superclass.
//
// If the clamp bit is not set in the desire, then the child doesn't need the power
// state it's requesting; it just wants it.  The root ignores desires but not needs.
// If the clamp bit is not set, the root takes it that the child can tolerate no
// power and interprets the request accordingly.  If all children can thus tolerate
// no power, we are on our way to idle sleep.
//*********************************************************************************

IOReturn IOPMrootDomain::requestPowerDomainState ( IOPMPowerFlags desiredState, IOPowerConnection * whichChild, unsigned long specification )
{
    OSIterator                              *iter;
    OSObject                                *next;
    IOPowerConnection                       *connection;
    unsigned long                           powerRequestFlag = 0;
    IOPMPowerFlags                          editedDesire = desiredState;

    // if they don't really need it, they don't get it
    if ( !(desiredState & kIOPMPreventIdleSleep) ) {
        editedDesire = 0;
    }


    IOLockLock(pm_vars->childLock);

    // recompute sleepIsSupported and see if all children are asleep
    iter = getChildIterator(gIOPowerPlane);
    sleepIsSupported = true;
    if ( iter ) 
    {
        while ( (next = iter->getNextObject()) ) 
        {
            if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) 
            {
                if ( connection == whichChild ) 
                {
                    powerRequestFlag += editedDesire;
                    if ( desiredState & kIOPMPreventSystemSleep ) 
                    {
                        sleepIsSupported = false;
                    }
                } else {
                    powerRequestFlag += connection->getDesiredDomainState();
                    if ( connection->getPreventSystemSleepFlag() ) 
                    {
                        sleepIsSupported = false;
                    }
                }
            }
        }
        iter->release();
    }
    
    if ( (extraSleepDelay == 0) &&  (powerRequestFlag == 0) ) 
    {
        sleepASAP = true;
    }
    
    // this may put the system to sleep
    adjustPowerState();
    
    IOLockUnlock(pm_vars->childLock);

    editedDesire |= desiredState & kIOPMPreventSystemSleep;

    return super::requestPowerDomainState(editedDesire,whichChild,specification);
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
    switch ( stateNum ) {
        case DOZE_STATE:
        case SLEEP_STATE:
	
            // Direct callout into OSMetaClass so it can disable kmod unloads
            // during sleep/wake to prevent deadlocks.
            OSMetaClassSystemSleepOrWake( kIOMessageSystemWillSleep );

            return super::tellClientsWithResponse(kIOMessageSystemWillSleep);
        case RESTART_STATE:
            // Unsupported shutdown ordering hack on RESTART only
            // For Bluetooth and USB (4368327)
            super::tellClients(iokit_common_msg(0x759));

            return super::tellClientsWithResponse(kIOMessageSystemWillRestart);
        case OFF_STATE:
            // Unsupported shutdown ordering hack on SHUTDOWN only
            // For Bluetooth and USB (4554440)
            super::tellClients(iokit_common_msg(0x749));

            return super::tellClientsWithResponse(kIOMessageSystemWillPowerOff);
    }
    // this shouldn't execute
    return super::tellChangeDown(stateNum);
}


//*********************************************************************************
// askChangeDown
//
// We override the superclass implementation so we can send a different message
// type to the client or application being notified.
//
// This must be idle sleep since we don't ask apps during any other power change.
//*********************************************************************************

bool IOPMrootDomain::askChangeDown ( unsigned long )
{
    return super::tellClientsWithResponse(kIOMessageCanSystemSleep);
}


//*********************************************************************************
// tellNoChangeDown
//
// Notify registered applications and kernel clients that we are not
// dropping power.
//
// We override the superclass implementation so we can send a different message
// type to the client or application being notified.
//
// This must be a vetoed idle sleep, since no other power change can be vetoed.
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

void IOPMrootDomain::tellChangeUp ( unsigned long stateNum)
{
    if ( stateNum == ON_STATE ) 
    {
        // Direct callout into OSMetaClass so it can disable kmod unloads
        // during sleep/wake to prevent deadlocks.
        OSMetaClassSystemSleepOrWake( kIOMessageSystemHasPoweredOn );

	IOHibernateSystemPostWake();
        return tellClients(kIOMessageSystemHasPoweredOn);
    }
}

//*********************************************************************************
// reportUserInput
//
//*********************************************************************************

void IOPMrootDomain::reportUserInput ( void )
{
    OSIterator * iter;

    if(!wrangler) 
    {
        iter = getMatchingServices(serviceMatching("IODisplayWrangler"));
        if(iter) 
        {
            wrangler = (IOService *) iter->getNextObject();
            iter->release();
        }
    }

    if(wrangler)
        wrangler->activityTickle(0,0);
}

//*********************************************************************************
// setQuickSpinDownTimeout
//
//*********************************************************************************

void IOPMrootDomain::setQuickSpinDownTimeout ( void )
{
    super::setAggressiveness((unsigned long)kPMMinutesToSpinDown,(unsigned long)1);
}

//*********************************************************************************
// restoreUserSpinDownTimeout
//
//*********************************************************************************

void IOPMrootDomain::restoreUserSpinDownTimeout ( void )
{
    super::setAggressiveness((unsigned long)kPMMinutesToSpinDown,(unsigned long)user_spindown);
}

//*********************************************************************************
// changePowerStateTo & changePowerStateToPriv
//
// Override of these methods for logging purposes.
//*********************************************************************************

IOReturn IOPMrootDomain::changePowerStateTo ( unsigned long ordinal )
{
    return super::changePowerStateTo(ordinal);
}

IOReturn IOPMrootDomain::changePowerStateToPriv ( unsigned long ordinal )
{
    IOReturn    ret;

    if( SLEEP_STATE == ordinal && sleepSupportedPEFunction )
    {

        // Determine if the machine supports sleep, or must doze.
        ret = getPlatform()->callPlatformFunction(
                            sleepSupportedPEFunction, false,
                            NULL, NULL, NULL, NULL);
    
        // If the machine only supports doze, the callPlatformFunction call
        // boils down toIOPMrootDomain::setSleepSupported(kPCICantSleep), 
        // otherwise nothing.
    }

    return super::changePowerStateToPriv(ordinal);
}


//*********************************************************************************
// sysPowerDownHandler
//
// Receives a notification when the RootDomain changes state. 
//
// Allows us to take action on system sleep, power down, and restart after
// applications have received their power change notifications and replied,
// but before drivers have powered down. We perform a vfs sync on power down.
//*********************************************************************************

IOReturn IOPMrootDomain::sysPowerDownHandler( void * target, void * refCon,
                                    UInt32 messageType, IOService * service,
                                    void * messageArgument, vm_size_t argSize )
{
    IOReturn                             ret;
    IOPowerStateChangeNotification      *params = (IOPowerStateChangeNotification *) messageArgument;
    IOPMrootDomain                      *rootDomain = OSDynamicCast(IOPMrootDomain, service);

    if(!rootDomain)
        return kIOReturnUnsupported;

    switch (messageType) {
        case kIOMessageSystemWillSleep:
            rootDomain->powerOverrideOnPriv();		// start ignoring children's requests
                                                        // (fall through to other cases)

            // Interested applications have been notified of an impending power
            // change and have acked (when applicable).
            // This is our chance to save whatever state we can before powering
            // down.
            // We call sync_internal defined in xnu/bsd/vfs/vfs_syscalls.c,
            // via callout

            // We will ack within 20 seconds
            params->returnValue = 20 * 1000 * 1000;
            if (gIOHibernateState)
                params->returnValue += gIOHibernateFreeTime * 1000; 	//add in time we could spend freeing pages

            if ( ! OSCompareAndSwap( 0, 1, &gSleepOrShutdownPending ) )
            {
                // Purposely delay the ack and hope that shutdown occurs quickly.
                // Another option is not to schedule the thread and wait for
                // ack timeout...
                AbsoluteTime deadline;
                clock_interval_to_deadline( 30, kSecondScale, &deadline );
                thread_call_enter1_delayed( rootDomain->diskSyncCalloutEntry, 
                                            (thread_call_param_t)params->powerRef,
                                            deadline );
            }
            else
                thread_call_enter1(rootDomain->diskSyncCalloutEntry, (thread_call_param_t)params->powerRef);
            ret = kIOReturnSuccess;
            break;

        case kIOMessageSystemWillPowerOff:
        case kIOMessageSystemWillRestart:
            ret = kIOReturnUnsupported;
            break;

        default:
            ret = kIOReturnUnsupported;
            break;
    }
    return ret;
}
		
//*********************************************************************************
// displayWranglerNotification
//
// Receives a notification when the IODisplayWrangler changes state.
//
// Allows us to take action on display dim/undim.
//
// When the display goes dim we:
// - Start the idle sleep timer
// - set the quick spin down timeout
//
// On wake from display dim:
// - Cancel the idle sleep timer
// - restore the user's chosen spindown timer from the "quick" spin down value
//*********************************************************************************

IOReturn IOPMrootDomain::displayWranglerNotification( void * target, void * refCon,
                                    UInt32 messageType, IOService * service,
                                    void * messageArgument, vm_size_t argSize )
{
    IOPMrootDomain *                rootDomain = OSDynamicCast(IOPMrootDomain, (IOService *)target);
    AbsoluteTime                 deadline;
    static bool                  deviceAlreadyPoweredOff = false;

    if(!rootDomain)
        return kIOReturnUnsupported;

    switch (messageType) {
       case kIOMessageDeviceWillPowerOff:
            // The IODisplayWrangler has powered off either because of idle display sleep
            // or force system sleep.
            
            // The display wrangler will send the DeviceWillPowerOff message 4 times until
            // it gets into its lowest state. We only want to act on the first of those 4.
            if( deviceAlreadyPoweredOff ) return kIOReturnUnsupported;

           deviceAlreadyPoweredOff = true;

           if( rootDomain->extraSleepDelay ) 
           {
                // start the extra sleep timer
                clock_interval_to_deadline(rootDomain->extraSleepDelay*60, kSecondScale, &deadline );
                thread_call_enter_delayed(rootDomain->extraSleepTimer, deadline);
                rootDomain->idleSleepPending = true;
            } else {
                // accelerate disk spin down if spin down timer is non-zero (zero = never spin down)
                // and if system sleep is non-Never
                if( (0 != rootDomain->user_spindown) && (0 != rootDomain->sleepSlider) )
                    rootDomain->setQuickSpinDownTimeout();
            }

             break;

        case kIOMessageDeviceHasPoweredOn:

            // The display has powered on either because of UI activity or wake from sleep/doze
            deviceAlreadyPoweredOff = false;
            rootDomain->adjustPowerState();
            

            // cancel any pending idle sleep
            if(rootDomain->idleSleepPending) 
            {
                thread_call_cancel(rootDomain->extraSleepTimer);
                rootDomain->idleSleepPending = false;
            }

            // Change the spindown value back to the user's selection from our accelerated setting
            if(0 != rootDomain->user_spindown)
                rootDomain->restoreUserSpinDownTimeout();

            // Put on the policy maker's on clamp.

            break;

         default:
             break;
     }
     return kIOReturnUnsupported;
 }

//*********************************************************************************
// displayWranglerPublished
//
// Receives a notification when the IODisplayWrangler is published.
// When it's published we install a power state change handler.
//
//*********************************************************************************

bool IOPMrootDomain::displayWranglerPublished( 
    void * target, 
    void * refCon,
    IOService * newService)
{
    IOPMrootDomain *rootDomain = 
            OSDynamicCast(IOPMrootDomain, (IOService *)target);

    if(!rootDomain)
        return false;

    rootDomain->wrangler = newService;
    
    // we found the display wrangler, now install a handler
    if( !rootDomain->wrangler->registerInterest( gIOGeneralInterest, 
                            &displayWranglerNotification, target, 0) ) 
    {
        return false;
    }
    
    return true;
}


//*********************************************************************************
// batteryPublished
//
// Notification on battery class IOPowerSource appearance
//
//******************************************************************************

bool IOPMrootDomain::batteryPublished( 
    void * target, 
    void * root_domain,
    IOService * resourceService )
{    
    // rdar://2936060&4435589    
    // All laptops have dimmable LCD displays
    // All laptops have batteries
    // So if this machine has a battery, publish the fact that the backlight
    // supports dimming.
    ((IOPMrootDomain *)root_domain)->publishFeature("DisplayDims");

    return (true);
}



//*********************************************************************************
// adjustPowerState
//
// Some condition that affects our wake/sleep/doze decision has changed.
//
// If the sleep slider is in the off position, we cannot sleep or doze.
// If the enclosure is open, we cannot sleep or doze.
// If the system is still booting, we cannot sleep or doze.
//
// In those circumstances, we prevent sleep and doze by holding power on with
// changePowerStateToPriv(ON).
//
// If the above conditions do not exist, and also the sleep timer has expired, we
// allow sleep or doze to occur with either changePowerStateToPriv(SLEEP) or
// changePowerStateToPriv(DOZE) depending on whether or not we already know the
// platform cannot sleep.
//
// In this case, sleep or doze will either occur immediately or at the next time
// that no children are holding the system out of idle sleep via the 
// kIOPMPreventIdleSleep flag in their power state arrays.
//*********************************************************************************

void IOPMrootDomain::adjustPowerState( void )
{
    if ( (sleepSlider == 0) ||
        ! allowSleep ||
        systemBooting ) {
        changePowerStateToPriv(ON_STATE);
    } else {
        if ( sleepASAP ) 
        {
            sleepASAP = false;
            if ( sleepIsSupported ) 
            {
                changePowerStateToPriv(SLEEP_STATE);
            } else {
                changePowerStateToPriv(DOZE_STATE);
            }
        }
    }
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */



#undef super
#define super OSObject
OSDefineMetaClassAndStructors(PMSettingObject, OSObject)

void PMSettingObject::setPMSetting(const OSSymbol *type, OSObject *obj)
{
        (*func)(target, type, obj, refcon);
}

/* 
 * Static constructor/initializer for PMSettingObject
 */
PMSettingObject *PMSettingObject::pmSettingObject(
    IOPMrootDomain                      *parent_arg,
    IOPMSettingControllerCallback       handler_arg,
    OSObject                            *target_arg,
    uintptr_t                           refcon_arg,
    uint32_t                            supportedPowerSources,
    const OSSymbol *                    settings[])
{
    uint32_t                            objCount = 0;
    PMSettingObject                     *pmso;

    if( !parent_arg || !handler_arg || !settings ) return NULL;

     // count OSSymbol entries in NULL terminated settings array
    while( settings[objCount] ) {
        objCount++;
    }
    if(0 == objCount) return NULL;

    pmso = new PMSettingObject;
    if(!pmso || !pmso->init()) return NULL;

    pmso->parent = parent_arg;
    pmso->func = handler_arg;
    pmso->target = target_arg;
    pmso->refcon = refcon_arg;
    pmso->releaseAtCount = objCount + 1; // release when it has count+1 retains
 
    pmso->publishedFeatureID = (uint32_t *)IOMalloc(sizeof(uint32_t)*objCount);
    if(pmso->publishedFeatureID) {
        for(unsigned int i=0; i<objCount; i++) {
            // Since there is now at least one listener to this setting, publish
            // PM root domain support for it.
            parent_arg->publishFeature( settings[i]->getCStringNoCopy(), 
                    supportedPowerSources, &pmso->publishedFeatureID[i] );
        }
    }
    
    return pmso;
}

void PMSettingObject::free(void)
{
    OSCollectionIterator    *settings_iter;
    OSSymbol                *sym;
    OSArray                 *arr;
    int                     arr_idx;
    int                     i;
    int                     objCount = releaseAtCount - 1;
    
    if(publishedFeatureID) {
        for(i=0; i<objCount; i++) {
            if(0 != publishedFeatureID[i]) {
                parent->removePublishedFeature( publishedFeatureID[i] );
            }
        }
    
        IOFree(publishedFeatureID, sizeof(uint32_t) * objCount);
    }
            
    IORecursiveLockLock(parent->settingsCtrlLock);        
    
    // Search each PM settings array in the kernel.
    settings_iter = OSCollectionIterator::withCollection(parent->settingsCallbacks);
    if(settings_iter) 
    {
        while(( sym = OSDynamicCast(OSSymbol, settings_iter->getNextObject()) ))
        {
            arr = (OSArray *)parent->settingsCallbacks->getObject(sym);
            arr_idx = arr->getNextIndexOfObject(this, 0);
            if(-1 != arr_idx) {
                // 'this' was found in the array; remove it                
                arr->removeObject(arr_idx);
            }
        }
    
        settings_iter->release();
    }
    
    IORecursiveLockUnlock(parent->settingsCtrlLock);
    
    super::free();
}

void PMSettingObject::taggedRelease(const void *tag, const int when) const
{     
    // We have n+1 retains - 1 per array that this PMSettingObject is a member
    // of, and 1 retain to ourself. When we get a release with n+1 retains
    // remaining, we go ahead and free ourselves, cleaning up array pointers
    // in free();

    super::taggedRelease(tag, releaseAtCount);    
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOService

OSDefineMetaClassAndStructors(IORootParent, IOService)

// This array exactly parallels the state array for the root domain.
// Power state changes initiated by a device can be vetoed by a client of the device, and
// power state changes initiated by the parent of a device cannot be vetoed by a client of the device,
// so when the root domain wants a power state change that cannot be vetoed (e.g. demand sleep), it asks
// its parent to make the change.  That is the reason for this complexity.

static IOPMPowerState patriarchPowerStates[number_of_power_states] = {
    {1,0,0,0,0,0,0,0,0,0,0,0},                                          // off
    {1,0,RESTART_POWER,0,0,0,0,0,0,0,0,0},                              // reset
    {1,0,SLEEP_POWER,0,0,0,0,0,0,0,0,0},                                // sleep
    {1,0,DOZE_POWER,0,0,0,0,0,0,0,0,0},                         	// doze
    {1,0,ON_POWER,0,0,0,0,0,0,0,0,0}                                    // running
};

bool IORootParent::start ( IOService * nub )
{
    mostRecentChange = ON_STATE;
    super::start(nub);
    PMinit();
    registerPowerDriver(this,patriarchPowerStates,number_of_power_states);
    powerOverrideOnPriv();
    return true;
}


void IORootParent::shutDownSystem ( void )
{
    mostRecentChange = OFF_STATE;
    changePowerStateToPriv(OFF_STATE);
}


void IORootParent::restartSystem ( void )
{
    mostRecentChange = RESTART_STATE;
    changePowerStateToPriv(RESTART_STATE);
}


void IORootParent::sleepSystem ( void )
{
    mostRecentChange = SLEEP_STATE;
    changePowerStateToPriv(SLEEP_STATE);
}


void IORootParent::dozeSystem ( void )
{
    mostRecentChange = DOZE_STATE;
    changePowerStateToPriv(DOZE_STATE);
}

// Called in demand sleep when sleep discovered to be impossible after actually attaining that state.
// This brings the parent to doze, which allows the root to step up from sleep to doze.

// In idle sleep, do nothing because the parent is still on and the root can freely change state.

void IORootParent::sleepToDoze ( void )
{
    if ( mostRecentChange == SLEEP_STATE ) {
        changePowerStateToPriv(DOZE_STATE);
    }
}


void IORootParent::wakeSystem ( void )
{
    mostRecentChange = ON_STATE;
    changePowerStateToPriv(ON_STATE);
}

IOReturn IORootParent::changePowerStateToPriv ( unsigned long ordinal )
{
    IOReturn        ret;

    if( SLEEP_STATE == ordinal && sleepSupportedPEFunction )
    {

        // Determine if the machine supports sleep, or must doze.
        ret = getPlatform()->callPlatformFunction(
                            sleepSupportedPEFunction, false,
                            NULL, NULL, NULL, NULL);
    
        // If the machine only supports doze, the callPlatformFunction call
        // boils down toIOPMrootDomain::setSleepSupported(kPCICantSleep), 
        // otherwise nothing.
    }

    return super::changePowerStateToPriv(ordinal);
}

